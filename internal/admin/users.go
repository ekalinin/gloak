package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
)

// userRepresentation is Keycloak's UserRepresentation, in the field order
// measured 2026-08-23 on a user carrying every one of them.
//
// Five fields are pointers, and none of that is style. briefRepresentation=true
// drops totp, disableableCredentialTypes, requiredActions and notBefore, whose
// natural values are false, [], [] and 0 - all of which omitempty would drop
// unconditionally. A pointer makes "absent" and "present and empty" different
// things, which is what the two shapes need. access is the same problem twice
// over: absent on the service-account read, one key on a listing, six on a
// single read.
//
// attributes sits between emailVerified and enabled, which is not where anyone
// would put it. The bootstrapped administrator is the only user that has any.
type userRepresentation struct {
	ID                         string              `json:"id"`
	Username                   string              `json:"username"`
	FirstName                  string              `json:"firstName,omitempty"`
	LastName                   string              `json:"lastName,omitempty"`
	Email                      string              `json:"email,omitempty"`
	EmailVerified              bool                `json:"emailVerified"`
	Attributes                 map[string][]string `json:"attributes,omitempty"`
	Enabled                    bool                `json:"enabled"`
	CreatedTimestamp           int64               `json:"createdTimestamp"`
	TOTP                       *bool               `json:"totp,omitempty"`
	DisableableCredentialTypes *[]string           `json:"disableableCredentialTypes,omitempty"`
	RequiredActions            *[]string           `json:"requiredActions,omitempty"`
	NotBefore                  *int                `json:"notBefore,omitempty"`
	Access                     any                 `json:"access,omitempty"`
	// Credentials is write-only. Nothing that serialises a user ever sets it -
	// a credential is read through .../credentials, which carries a different
	// shape and no secret - so omitempty keeps it out of every response, and
	// it is here so that POST and PUT can read the array Keycloak honours on
	// both. See credentialRequest for what an entry means.
	Credentials []credentialRequest `json:"credentials,omitempty"`
}

// userAccess is the permissions block a single read carries, in the measured
// key order - a Java Map's hash order, deterministic for this key set.
//
// Every flag is computed from the **caller's** roles, never from anything
// about the user being read. Each was measured by giving a user exactly one
// master-realm role and reading the administrator through it:
//
//	manageGroupMembership, resetPassword, mapRoles, manage  manage-users
//	view                                                    view-users or manage-users
//	impersonate                                             impersonation
type userAccess struct {
	ManageGroupMembership bool `json:"manageGroupMembership"`
	ResetPassword         bool `json:"resetPassword"`
	View                  bool `json:"view"`
	MapRoles              bool `json:"mapRoles"`
	Impersonate           bool `json:"impersonate"`
	Manage                bool `json:"manage"`
}

// userListAccess is the one-key block a listing carries instead of the six.
// Measured on both a full administrator and a caller holding only view-users,
// which gets {"manage":false} rather than an omitted block.
type userListAccess struct {
	Manage bool `json:"manage"`
}

func userAccessFor(c *caller) userAccess {
	manage := c.has("manage-users")
	return userAccess{
		ManageGroupMembership: manage,
		ResetPassword:         manage,
		View:                  manage || c.has("view-users"),
		MapRoles:              manage,
		Impersonate:           c.has("impersonation"),
		Manage:                manage,
	}
}

// listUsers serves GET /admin/realms/{realm}/users.
//
// Everything a caller can narrow the list with is a query parameter, and the
// two families do not behave the same way. username, email, firstName and
// lastName are case-insensitive **substrings**, which exact=true turns into
// equality. search is a case-insensitive **prefix** across all four fields,
// takes * as a wildcard and "quotes" as equality, and ignores exact
// altogether. See matches and matchesSearch, which carry the recordings.
//
// A filter matching nothing answers 200 with [], never 404.
func (h *handler) listUsers(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	users, err := h.matchingUsers(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	users = page(users, r.URL.Query())

	// **The listing is filtered by what the caller may view; the count is
	// not.** Measured 2026-08-28 on one caller per role: query-users gets 200
	// and `[]` from this route and 200 and the full count from the route next
	// door, while view-users and manage-users get everybody from both. So
	// query-users opens the route and sees nothing - a filter, not a guard:
	// the route stays open and the body empties.
	//
	// The predicate is caller-wide rather than per user, which is what
	// userAccessFor expresses and what a default 26.7.1 does. Keycloak's
	// fine-grained admin permissions can make it per user; they are off by
	// default, nothing here measures them, and this must not be read as
	// modelling them.
	if !userAccessFor(rc.caller).View {
		users = nil
	}

	brief := r.URL.Query().Get("briefRepresentation") == "true"
	out := make([]userRepresentation, 0, len(users))
	for _, u := range users {
		rep := userRepresentationOf(u, brief)
		rep.Access = userListAccess{Manage: rc.caller.has("manage-users")}
		out = append(out, rep)
	}
	writeAdminJSON(w, out)
}

// countUsers serves GET /admin/realms/{realm}/users/count.
//
// The body is a bare JSON number, not an object, and it carries the same
// charset Content-Type and Cache-Control the listing does.
//
// It applies the same filters as the listing but **not** the same visibility:
// a caller holding only query-users was measured getting [] from the listing
// and 7 from the count, on the same realm at the same moment. Re-measured
// 2026-08-28 across nine callers and it still holds, so the two endpoints
// disagreeing is the contract and not an artefact of one reading.
//
// This used to note that Gloak did not filter the listing either, so the two
// agreed here for a different reason than Keycloak's. The listing filters now,
// and this one deliberately still does not.
func (h *handler) countUsers(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	users, err := h.matchingUsers(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, len(users))
}

// userFromPath resolves the {user-id} segment into a user, writing the
// measured 404 and returning false when there is none.
//
// Every endpoint that takes a user ID goes through this - the credential
// endpoints in credentials.go already did, and readUser and updateUser below
// did too until each carried its own copy of the same eight lines. The
// role-mapping endpoints are about to add eleven more callers; a second
// spelling of "User not found" would have been indistinguishable from a real
// divergence, which is why there is exactly one.
func (h *handler) userFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.User, bool) {
	// guardUserSubject resolves the subject before the route's own role check,
	// because Keycloak answers 404 for a missing user to any caller inside the
	// users family whether or not it may use the route. Every handler in the
	// family still asks for the subject here, so this hands back what the
	// guard already found rather than reading the store twice.
	if rc.subject != nil {
		return rc.subject, true
	}
	user, err := h.store.Users().ByID(r.Context(), rc.realm.ID, r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeUserNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return user, true
}

// readUser serves GET /admin/realms/{realm}/users/{user-id}.
//
// The 404 message is "User not found", where a missing client answers "Could
// not find client" and a missing realm "Realm not found." - three endpoints,
// three spellings, one of them with a full stop.
func (h *handler) readUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	rep := userRepresentationOf(user, false)
	rep.Access = userAccessFor(rc.caller)
	writeAdminJSON(w, rep)
}

// createUser serves POST /admin/realms/{realm}/users.
//
// Measured: 201 with an empty body, the new object's absolute URL in Location
// and content-length 0 - unlike the client create, which sends no
// Content-Length header at all.
//
// **The username is lowercased.** A create naming Probe-UPPER answers 201 and
// the user reads back as probe-upper.
//
// **An inline credentials array is honoured**, which is follow-up F84 and was
// the whole of what this handler was missing: a user created with
// {"username":"x","credentials":[{"type":"password","value":"..."}]} can use
// the password grant immediately. See applyCredentials for what an entry means
// and credentialRequest for the five fields that are read and dropped.
func (h *handler) createUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeUser(w, r)
	if !ok {
		return
	}
	if rep.Username == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "User name is missing")
		return
	}

	m := &model.User{
		ID:               model.NewID(),
		RealmID:          rc.realm.ID,
		Username:         strings.ToLower(rep.Username),
		Email:            rep.Email,
		EmailVerified:    rep.EmailVerified,
		Enabled:          rep.Enabled,
		FirstName:        rep.FirstName,
		LastName:         rep.LastName,
		CreatedTimestamp: time.Now().UnixMilli(),
		// Attributes are deliberately dropped. Measured: a create carrying
		// {"dept":["eng"]} answers 201 and the user reads back with no
		// attributes at all, because unmanaged attributes are off by default
		// in the declarative user profile. Storing them would make Gloak
		// remember what Keycloak forgets.
	}
	if err := h.store.Users().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeUsernameConflict(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **The credentials are checked after the username, and a bad one takes the
	// user with it.** Measured on both cells: a create naming a username
	// somebody already holds and carrying a valueless credential answers the
	// 409, so the conflict is decided first; the same credential on a free
	// username answers 500 and leaves no user behind at all. Keycloak rolls a
	// transaction back where this deletes what it just made, which is the same
	// observable and the only one available without transactions in the store.
	if credentialsMissingValue(rep.Credentials) {
		_ = h.store.Users().Delete(r.Context(), rc.realm.ID, m.ID)
		writeUserUnknownError(w)
		return
	}
	// Measured: a user created here holds default-roles-master and nothing
	// else. Without it the user exists but every token it is issued carries no
	// aud, no realm_access and no resource_access.
	if err := roles.AssignDefaults(r.Context(), h.store.Roles(), rc.realm.ID, rc.realm.Name, m.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.applyCredentials(r.Context(), m, rep.Credentials); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/users/"+m.ID)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// updateUser serves PUT /admin/realms/{realm}/users/{user-id}.
//
// Measured: 204 with no body and no Cache-Control, and the body **merges** -
// a request carrying only firstName leaves lastName and email alone.
//
// **The username does not change.** A PUT naming a free username answers 204
// and leaves the stored one as it was, because the master realm has username
// editing switched off. A PUT naming a username somebody else holds still
// answers 409, so the conflict check runs before the change is discarded -
// which is why this reads the request's username even though it never applies
// it.
//
// **It honours an inline credentials array too.** F84 was filed against
// POST /users and is a defect on both routes: a PUT carrying
// {"credentials":[{"type":"password","value":"..."}]} answers 204 and the user
// logs in with it. The two routes disagree about the failures rather than about
// the success - see decodeInto and writeUserUpdateFailed.
func (h *handler) updateUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	current, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}

	merged := userRepresentationOf(current, true)
	if !decodeInto(w, r, &merged, writeUserUpdateFailed) {
		return
	}

	if wanted := strings.ToLower(merged.Username); wanted != current.Username {
		taken, err := h.store.Users().ByUsername(r.Context(), rc.realm.ID, wanted)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if taken != nil {
			writeUsernameConflict(w)
			return
		}
	}

	// The same order the create was measured in - the username conflict above
	// decides first, and a valueless credential only then. What differs is the
	// answer: 400 "Could not update user!" here where the create answers the
	// 500 unknown_error body.
	if credentialsMissingValue(merged.Credentials) {
		writeUserUpdateFailed(w)
		return
	}

	updated := *current
	updated.Email = merged.Email
	updated.EmailVerified = merged.EmailVerified
	updated.Enabled = merged.Enabled
	updated.FirstName = merged.FirstName
	updated.LastName = merged.LastName
	if err := h.store.Users().Update(r.Context(), &updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.applyCredentials(r.Context(), &updated, merged.Credentials); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteUser serves DELETE /admin/realms/{realm}/users/{user-id}.
//
// Measured: 204 carrying Cache-Control: no-cache and omitting X-Frame-Options,
// the same pair the client delete has and the same one every successful DELETE
// was measured with.
func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	err := h.store.Users().Delete(r.Context(), rc.realm.ID, r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeUserNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// decodeUser reads a UserRepresentation from the request body.
func decodeUser(w http.ResponseWriter, r *http.Request) (userRepresentation, bool) {
	var rep userRepresentation
	ok := decodeInto(w, r, &rep, writeUserUnknownError)
	return rep, ok
}

// decodeInto reads the body over an existing representation, which is what
// makes PUT a merge, and writes the four measured failures.
//
// The empty-body case is the odd one and it is copied on purpose: Keycloak
// answers 500 with the unknown_error body for a POST whose body is empty or the
// literal null, where a body that is merely malformed gets a 400. Same class of
// defect as DELETE .../client-secret/rotated, and reproduced for the same
// reason. **The PUT next door answers that body 400
// {"errorMessage":"Could not update user!"} instead**, measured 2026-08-30, so
// the answer arrives as an argument rather than being decided here - the fifth
// time this API has punished one decoder shared by two routes.
//
// The other three rows are the same shape rule decodeMapperBody records, with
// one more measurement under it. A **binding** failure is unknown_error and a
// **syntax** failure is invalid_request:
//
//	{                              invalid_request   syntax, right shape
//	[                              unknown_error     wrong shape
//	{"credentials":"nonsense"}     unknown_error     right shape, wrong type
//	{"enabled":"yes"}              unknown_error     right shape, wrong type
//
// The two type-mismatch rows are new. Every earlier probe of this endpoint sent
// a truncated document, so invalid_request looked like the answer to "malformed
// body" when it is the answer to "malformed JSON"; a well-formed document whose
// field will not bind is the other family. Gloak served invalid_request for all
// four until the credentials array made the difference reachable from a body a
// caller would really send.
func decodeInto(w http.ResponseWriter, r *http.Request, rep *userRepresentation,
	empty func(http.ResponseWriter)) bool {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		empty(w)
		return false
	}
	if trimmed[0] != '{' {
		writeUserCannotParse(w, "unknown_error")
		return false
	}
	if err := json.Unmarshal(raw, rep); err != nil {
		var mismatch *json.UnmarshalTypeError
		if errors.As(err, &mismatch) {
			writeUserCannotParse(w, "unknown_error")
			return false
		}
		writeUserCannotParse(w, "invalid_request")
		return false
	}
	return true
}

// writeUserCannotParse is the 400 both parse families answer, differing only in
// the code. The description is identical, which is why the code is the argument.
func writeUserCannotParse(w http.ResponseWriter, code string) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, code, "Cannot parse the JSON")
}

// writeUserUnknownError is the 500 POST /users answers for an empty body and
// for a credential carrying no value - Keycloak's own defect on both, and one
// body for the two.
func writeUserUnknownError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// writeUserUpdateFailed is PUT /users/{id}'s answer to the two bodies the
// create answers with a 500: an empty or null body, and a credential with no
// value. Same two inputs, same endpoint family, a different status and a
// different error shape.
func writeUserUpdateFailed(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusBadRequest, "Could not update user!")
}

// writeUsernameConflict emits the measured 409. The message names no username,
// unlike the client conflict's "Client <id> already exists".
func writeUsernameConflict(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusConflict, "User exists with same username")
}

func writeUserNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "User not found")
}

// matchingUsers reads the realm's users and applies the request's filters.
//
// Filtering happens here rather than in SQL because the parameters are the
// admin API's vocabulary, not the store's, and because the two drivers would
// otherwise have to agree on case-insensitive matching - which is exactly the
// kind of divergence AGENTS.md warns about.
func (h *handler) matchingUsers(r *http.Request, rc *reqContext) ([]*model.User, error) {
	users, err := h.store.Users().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	exact := q.Get("exact") == "true"

	out := make([]*model.User, 0, len(users))
	for _, u := range users {
		if matchesFilters(u, q, exact) {
			out = append(out, u)
		}
	}
	return out, nil
}

func matchesFilters(u *model.User, q map[string][]string, exact bool) bool {
	get := func(name string) string {
		if v := q[name]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	fields := []struct{ param, value string }{
		{"username", u.Username},
		{"email", u.Email},
		{"firstName", u.FirstName},
		{"lastName", u.LastName},
	}
	for _, f := range fields {
		if want := get(f.param); want != "" && !matches(f.value, want, exact) {
			return false
		}
	}
	// search is the loose one: any of the four fields matching is enough. It
	// is also the one exact does not apply to - measured,
	// search=full&exact=true still finds full-user by prefix.
	if term := get("search"); term != "" {
		any := false
		for _, f := range fields {
			if matchesSearch(f.value, term) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	return true
}

// matches is how the four named filters compare: case-insensitive, and a
// substring unless exact was asked for.
//
// Measured: username=ull finds full-user, so it really is a substring and not
// a prefix; username=FULL-USER finds it too; username=full&exact=true finds
// nothing while username=FULL-USER&exact=true does. A * here is a literal -
// username=*user finds nothing.
func matches(value, want string, exact bool) bool {
	if exact {
		return strings.EqualFold(value, want)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(want))
}

// matchesSearch is how search compares, and it is **not** how the named
// filters do.
//
// Measured 2026-08-23, correcting what Task 13 recorded as a substring:
//
//	search=full      matches full-user        a bare term is a prefix
//	search=user      matches nothing          which is why it is not a substring
//	search=ovelace   matches nothing          nor a suffix
//	search=user*     matches nothing          an explicit * is the whole pattern
//	search=*user     matches full-user
//	search=*ull*     matches full-user
//	search="full-user" matches full-user      quotes mean equality
//
// The rule those six agree on was written down as "a term containing * is that
// pattern with * standing for any run of characters, anchored at both ends",
// **and it is wrong at the tail.** Corrected 2026-09-01 by a seventh probe the
// six could not distinguish: with a user named `xabbcx`,
//
//	search=*bbc      matches xabbcx      an anchored glob says it must *end* in bbc
//
// The rule that fits all seven is Keycloak's LIKE: replace every `*` with `%`,
// **append a `%` when the pattern does not already end in one**, and compare
// case-insensitively. The six original probes are all still explained by it -
// `user*` becomes `user%`, a prefix, which is why it matches nothing - and only
// a pattern whose last literal run is neither at the end of the value nor
// followed by a `*` can tell the two apart. That is why this stood for a week.
//
// That is Keycloak's rule and it is the reason this function has the shape it
// has; it is **not** a description of the steps below. The body expresses the
// trailing `%` by anchoring the head and not the tail rather than by appending
// anything - see the comment on the walk.
//
// **The role listing does not share it.** The same `search=*bbc` against a role
// named `xabbcx` answers `[]`, and so do `xa*`, `*abbcx`, `*abb*` and `x*x`
// while the bare `xabbcx` matches - so `*` is a literal there and a wildcard
// here. The identity provider listing **does** share it, measured on the same
// probe on the same container, which is what earns filterIdentityProviders the
// right to call this rather than copying it. The **group** listing was measured
// sharing it too and does not implement it; that is filed rather than fixed,
// because a search-semantics change in a third chapter is not this one's to
// make.
//
// Whether a term with spaces splits into several is not measured, so a term is
// taken whole.
func matchesSearch(value, term string) bool {
	value = strings.ToLower(value)
	term = strings.ToLower(term)

	if len(term) >= 2 && strings.HasPrefix(term, `"`) && strings.HasSuffix(term, `"`) {
		return value == strings.Trim(term, `"`)
	}
	// Walk the literal runs between the wildcards in order. **The head is
	// anchored and the tail deliberately is not**, and that asymmetry is the
	// whole of the implied trailing `%`: the first run must sit at the start
	// unless the term opens with `*`, and every later run is found by a forward
	// scan that does not care what follows it. So `bbc` is a prefix and `*bbc`
	// is a substring.
	//
	// There was a `term += "*"` here until 2026-09-01, with a comment claiming
	// it was what made `*bbc` a substring match. **It was a no-op.** Appending a
	// `*` only adds a trailing empty run, which the loop below skips, so every
	// term - `bbc`, `*bbc`, `a*b`, one already ending in `*`, the empty one -
	// took the identical path with and without it; deleting the three lines
	// changed no test. The tail anchor removed in the same commit is what
	// carried the rule, and the comment named the wrong half.
	//
	// **The two blocks also masked each other**, which is how this survived a
	// mutation pass. With the append present the last run is always empty, so a
	// restored tail anchor is unreachable and looks harmless; with the append
	// gone the anchor is what the `*bbc` probe fails on.
	//
	// The empty run is skipped rather than matched, which is what lets `a**b`
	// and a term ending in `*` through.
	parts := strings.Split(term, "*")
	if head := parts[0]; head != "" {
		if !strings.HasPrefix(value, head) {
			return false
		}
		value = value[len(head):]
	}
	for _, part := range parts[1:] {
		if part == "" {
			continue
		}
		i := strings.Index(value, part)
		if i < 0 {
			return false
		}
		value = value[i+len(part):]
	}
	return true
}

// page applies first and max. Both are ignored when absent or unparseable,
// which is what a listing with neither has to do.
func page(users []*model.User, q map[string][]string) []*model.User {
	first := 0
	if v := q["first"]; len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n > 0 {
			first = n
		}
	}
	if first >= len(users) {
		return nil
	}
	users = users[first:]

	if v := q["max"]; len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n >= 0 && n < len(users) {
			users = users[:n]
		}
	}
	return users
}

// userRepresentationOf converts a stored user for the wire. brief drops the
// four legacy fields briefRepresentation=true was measured dropping; access is
// the caller's business and is set by each handler.
func userRepresentationOf(u *model.User, brief bool) userRepresentation {
	rep := userRepresentation{
		ID:               u.ID,
		Username:         u.Username,
		FirstName:        u.FirstName,
		LastName:         u.LastName,
		Email:            u.Email,
		EmailVerified:    u.EmailVerified,
		Attributes:       u.Attributes,
		Enabled:          u.Enabled,
		CreatedTimestamp: u.CreatedTimestamp,
	}
	if brief {
		return rep
	}
	totp := false
	notBefore := u.NotBefore
	// Both must marshal as [] rather than null, so the slices are empty and
	// non-nil. Nothing populates them yet: disableableCredentialTypes needs
	// the credential model's notion of which types can be disabled, and
	// requiredActions needs required actions, neither of which P2 has.
	credentialTypes := []string{}
	requiredActions := nonNilActions(u.RequiredActions)
	rep.TOTP = &totp
	rep.DisableableCredentialTypes = &credentialTypes
	rep.RequiredActions = &requiredActions
	rep.NotBefore = &notBefore
	return rep
}

// readServiceAccountUser serves GET .../clients/{client-uuid}/service-account-user.
//
// A client without service accounts answers 400, not 404, and the message
// names the clientId in single quotes rather than the UUID the request used.
func (h *handler) readServiceAccountUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	if !client.ServiceAccountsEnabled {
		httpx.WriteMessageError(w, http.StatusBadRequest,
			"Service account not enabled for the client '"+client.ClientID+"'")
		return
	}
	user, err := h.ensureServiceAccount(r.Context(), rc.realm, client)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **No access block**, and that is measured rather than an omission: the
	// same user through GET /users/{id} carries six keys and through
	// GET /users one. Three serialisations of one object, so a single shared
	// user serialiser would be wrong twice.
	writeAdminJSON(w, userRepresentationOf(user, false))
}

// ensureServiceAccount returns the account a service-account client acts as,
// creating it if it is not there yet.
//
// Measured: the account exists as soon as the client does. A GET on
// service-account-user immediately after a create answers 200 with no token
// grant in between, and switching serviceAccountsEnabled on through PUT
// creates it too. That is why createClient and updateClient call this rather
// than leaving it to the first client_credentials grant.
//
// internal/oidc creates the same account on demand during that grant, and both
// paths stay. This one is what the admin API observes; that one covers every
// client that never went through the admin API - the six bootstrap makes, and
// every client a test builds straight through the store.
func (h *handler) ensureServiceAccount(ctx context.Context, realm *model.Realm, c *model.Client) (*model.User, error) {
	username := model.ServiceAccountUsername(c.ClientID)
	user, err := h.store.Users().ByUsername(ctx, realm.ID, username)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	user = &model.User{
		ID:               model.NewID(),
		RealmID:          realm.ID,
		Username:         username,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := h.store.Users().Create(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return h.store.Users().ByUsername(ctx, realm.ID, username)
		}
		return nil, err
	}
	// A service account is a user and gets the same default roles, measured:
	// a client_credentials token carries default-roles-master, offline_access,
	// uma_authorization and the three account roles, exactly as a person's
	// does.
	if err := roles.AssignDefaults(ctx, h.store.Roles(), realm.ID, realm.Name, user.ID); err != nil {
		return nil, err
	}
	return user, nil
}

// nonNilActions keeps requiredActions marshalling as [] rather than null. The
// measured representation carries an empty array for a user with none.
func nonNilActions(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
