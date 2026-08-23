package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
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
// Everything a caller can narrow the list with is a query parameter, and their
// semantics are measured rather than guessed: search matches username,
// firstName, lastName and email as a case-insensitive substring; username,
// email, firstName and lastName each match their own field the same way; and
// exact=true turns those four into equality. A filter matching nothing answers
// 200 with [], never 404.
func (h *handler) listUsers(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	users, err := h.matchingUsers(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	users = page(users, r.URL.Query())

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
// and 7 from the count, on the same realm at the same moment. Gloak does not
// filter the listing by visibility either - see follow-up F17 - so the two
// agree here for a different reason than Keycloak's.
func (h *handler) countUsers(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	users, err := h.matchingUsers(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, len(users))
}

// readUser serves GET /admin/realms/{realm}/users/{user-id}.
//
// The 404 message is "User not found", where a missing client answers "Could
// not find client" and a missing realm "Realm not found." - three endpoints,
// three spellings, one of them with a full stop.
func (h *handler) readUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, err := h.store.Users().ByID(r.Context(), rc.realm.ID, r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "User not found")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	rep := userRepresentationOf(user, false)
	rep.Access = userAccessFor(rc.caller)
	writeAdminJSON(w, rep)
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
	// search is the loose one: any of the four fields matching is enough, and
	// exact does not apply to it.
	if term := get("search"); term != "" {
		any := false
		for _, f := range fields {
			if matches(f.value, term, false) {
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

// matches is case-insensitive, and a substring unless exact was asked for.
// Measured: username=full finds full-user, username=FULL-USER finds it too,
// and username=full&exact=true finds nothing.
func matches(value, want string, exact bool) bool {
	if exact {
		return strings.EqualFold(value, want)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(want))
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
	notBefore := 0
	// Both must marshal as [] rather than null, so the slices are empty and
	// non-nil. Nothing populates them yet: disableableCredentialTypes needs
	// the credential model's notion of which types can be disabled, and
	// requiredActions needs required actions, neither of which P2 has.
	credentialTypes := []string{}
	requiredActions := []string{}
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
	user, err := h.ensureServiceAccount(r.Context(), rc.realm.ID, client)
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
func (h *handler) ensureServiceAccount(ctx context.Context, realmID string, c *model.Client) (*model.User, error) {
	username := model.ServiceAccountUsername(c.ClientID)
	user, err := h.store.Users().ByUsername(ctx, realmID, username)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	user = &model.User{
		ID:               model.NewID(),
		RealmID:          realmID,
		Username:         username,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := h.store.Users().Create(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return h.store.Users().ByUsername(ctx, realmID, username)
		}
		return nil, err
	}
	return user, nil
}
