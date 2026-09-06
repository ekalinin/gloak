package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
)

// partialImport is POST /admin/realms/{realm}/partialImport.
//
// The vendored description declares its request body as
// `{"format":"binary","type":"string"}` with no schema at all and its answers as
// 200, 403 and 409, so everything below was measured on a live 26.7.1 on
// 2026-09-06, in a realm created for it.
//
// The answer is a per-resource result rather than a status:
//
//	{"overwritten":0,"added":1,"skipped":0,
//	 "results":[{"action":"ADDED","resourceType":"USER","resourceName":"u1",
//	             "id":"ba3d3d6a-..."}]}
//
// **The success carries `;charset=UTF-8`, which the export beside it does
// not.** Two operations on one tag, opposite sides of AGENTS.md's charset rule.
//
// `results` has **no reproducible order**. Five runs of one identical body
// against identical state, under SKIP so every id was fixed, came back in five
// different orders - not input order, not grouped by type, the two users landing
// apart every time. Keycloak collects them in a HashSet whose element has no
// hashCode. Gloak emits a deterministic order because its own goldens have to
// be reproducible, and the conformance case carries Unordered on `/results`
// because Keycloak's is not.

// partialImportPolicy is `ifResourceExists`. The field is spelled that way and
// **`policy` is not read**: a body naming `policy` behaved exactly as one naming
// nothing.
type partialImportPolicy string

const (
	// policyFail is the default. A body with no ifResourceExists answers the
	// same 409 as one naming FAIL, measured on both.
	policyFail      partialImportPolicy = "FAIL"
	policySkip      partialImportPolicy = "SKIP"
	policyOverwrite partialImportPolicy = "OVERWRITE"

	// policyNull is an **explicit** `"ifResourceExists":null`, which is not the
	// same as an absent field and not the same as an unknown string.
	//
	// It binds to a Java null and is dereferenced only when a resource turns
	// out to exist, so it is a 200 `ADDED` on a resource that does not and a
	// 500 on one that does - measured on a user and on a group, in both
	// directions. The first hand probe of this cell sent it only against a
	// resource that already existed and wrote the 500 down as the whole answer;
	// the recorded golden refuted that, which is what a two-condition rule
	// looks like when a probe supplies one condition.
	policyNull partialImportPolicy = "\x00null"
)

// partialImportBody is what the endpoint decodes. Unknown top-level keys are
// ignored - `{"nosuchkey":[1,2,3]}` answered 200 with an empty result set - so
// this is a plain decode rather than the strict one most of this package uses.
type partialImportBody struct {
	IfResourceExists  json.RawMessage        `json:"ifResourceExists"`
	Users             []partialImportUser    `json:"users"`
	Groups            []partialImportGroup   `json:"groups"`
	Clients           []clientRepresentation `json:"clients"`
	Roles             *partialImportRoles    `json:"roles"`
	IdentityProviders []identityProviderBody `json:"identityProviders"`
}

type partialImportRoles struct {
	Realm  []partialImportRole            `json:"realm"`
	Client map[string][]partialImportRole `json:"client"`
}

type partialImportRole struct {
	ID          string              `json:"id"`
	Name        jsonScalarString    `json:"name"`
	Description string              `json:"description"`
	Attributes  map[string][]string `json:"attributes"`
}

type partialImportUser struct {
	ID            string           `json:"id"`
	Username      jsonScalarString `json:"username"`
	Email         string           `json:"email"`
	EmailVerified bool             `json:"emailVerified"`
	Enabled       bool             `json:"enabled"`
	FirstName     string           `json:"firstName"`
	LastName      string           `json:"lastName"`
}

type partialImportGroup struct {
	ID   string           `json:"id"`
	Name jsonScalarString `json:"name"`
	Path string           `json:"path"`
}

// jsonScalarString is a string that also accepts a JSON number, because Jackson
// coerces one: `{"users":[{"username":7}]}` answered 200 and created a user
// whose name is the string "7". Refusing it would be a 500 where Keycloak
// answers 200.
//
// **Only the number was measured.** What a boolean or a null in the same
// position does is not, so both are left to fail the bind rather than guessed
// at - which is the answer this file gives everywhere the measurement stops.
type jsonScalarString string

func (s *jsonScalarString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = jsonScalarString(v)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = jsonScalarString(n.String())
	return nil
}

// partialImportResults is the answer. Four keys in this order, three counts and
// an array.
type partialImportResults struct {
	Overwritten int                   `json:"overwritten"`
	Added       int                   `json:"added"`
	Skipped     int                   `json:"skipped"`
	Results     []partialImportResult `json:"results"`
}

// partialImportResult is one row. `resourceType` is USER, GROUP, CLIENT,
// REALM_ROLE, CLIENT_ROLE or **IDP** - the last is not spelled
// IDENTITY_PROVIDER, which is the abbreviation nothing in this repository would
// have guessed.
type partialImportResult struct {
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	ResourceName string `json:"resourceName"`
	ID           string `json:"id"`
}

const (
	actionAdded       = "ADDED"
	actionSkipped     = "SKIPPED"
	actionOverwritten = "OVERWRITTEN"
)

// partialImport serves the endpoint.
//
// The order is the realm, then manage-realm, then the body - measured: an
// unknown realm is 404 to a caller holding no admin role, a malformed body is
// 403 to that caller and to a view-realm caller alike, and a manage-realm
// caller sending a malformed body against an unknown realm gets the 404. The
// guard supplies the first two steps.
//
// **The guard does not follow the body.** manage-realm alone answered 200 for a
// user, a client and a group, so a caller holding no manage-users creates users
// through it. That is the opposite of the export next door, whose guard does
// grow with its query.
func (h *handler) partialImport(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, err := readRequestBody(r)
	if err != nil {
		writePartialImportBindError(w)
		return
	}
	var in partialImportBody
	if refusal := decodePartialImportBody(body, &in); refusal != nil {
		refusal(w)
		return
	}
	policy, refused := partialImportPolicyOf(in.IfResourceExists)
	if refused != nil {
		refused(w)
		return
	}

	results, refusal, err := h.applyPartialImport(r.Context(), rc, &in, policy)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if refusal != nil {
		refusal(w)
		return
	}
	// **No Cache-Control**, on the 200 and on every refusal alike, so this is
	// not writeAdminJSON. The 200 does carry the charset, which makes this
	// response the export's twin on one of the two headers and its opposite on
	// the other. Measured with GET /admin/realms/master as the control, which
	// carries both - and the first hand probe of this endpoint never looked at
	// Cache-Control at all. The recorded golden is what said so.
	httpx.WriteJSONCharset(w, http.StatusOK, results)
}

// partialImportPolicyOf reads the field, and it takes the raw bytes because
// **absent and `null` are two different answers** that a *string cannot tell
// apart:
//
//	absent       FAIL       - a body with no ifResourceExists answered the 409
//	                          a FAIL body answers
//	"FAIL"       FAIL
//	"SKIP"       SKIP
//	"OVERWRITE"  OVERWRITE
//	"skip"       500 unknown_error  Cannot parse the JSON  - case-sensitive
//	""           500 unknown_error  Cannot parse the JSON
//	"BOGUS"      500 unknown_error  Cannot parse the JSON
//	5            500 unknown_error  Cannot parse the JSON
//	null         200 on a resource that does not exist,
//	             500 unknown_error / consult the server log on one that does
//
// **The unknown string and the explicit null are two different mechanisms**, and
// the difference is which condition they need. An unknown string fails to bind
// and is rejected **before any resource is looked at** - `BOGUS` against a
// resource that does not exist answers the same 500 as one that does. A `null`
// binds and is dereferenced only when the resource turns out to exist, so it
// needs the second condition and this function cannot answer it.
func partialImportPolicyOf(raw json.RawMessage) (partialImportPolicy, func(http.ResponseWriter)) {
	if len(raw) == 0 {
		return policyFail, nil
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return policyNull, nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", writePartialImportBindError
	}
	switch partialImportPolicy(v) {
	case policyFail, policySkip, policyOverwrite:
		return partialImportPolicy(v), nil
	}
	return "", writePartialImportBindError
}

// decodePartialImportBody separates Keycloak's two failure families, which this
// one endpoint answers with two different codes on one route:
//
//	{             500  invalid_request  Cannot parse the JSON   a syntax error
//	{"users":[],} 500  invalid_request  Cannot parse the JSON
//	{users:[]}    500  invalid_request  Cannot parse the JSON
//	nul           500  invalid_request  Cannot parse the JSON
//	[             500  unknown_error    Cannot parse the JSON   a value that will not bind
//	[]            500  unknown_error    Cannot parse the JSON
//	"x" true 7    500  unknown_error    Cannot parse the JSON
//	(empty)       500  unknown_error    Cannot parse the JSON
//	{"users":"x"} 500  unknown_error    Cannot parse the JSON
//
// **A JSON syntax error answers invalid_request; syntactically valid JSON that
// will not bind answers unknown_error**, and both are 500 where every other
// `Cannot parse the JSON` in this repository is a 400. That is F163's
// discriminating request - a body of the right shape carrying a value of the
// wrong type - and it is answered here rather than in writeCannotParseJSON,
// which fourteen other decoders share and whose leading-bracket rule agrees
// with every body measured before this cut. Changing that shared writer on one
// endpoint's evidence is what the follow-up warns against; see the handover.
//
// The discriminator is the **first token**, because that is what Jackson's is.
// A body opening with a complete JSON value that is not an object has already
// failed to bind by the time truncation could be noticed, which is why a bare
// `[` is unknown_error and a bare `{` is invalid_request.
func decodePartialImportBody(body []byte, out *partialImportBody) func(http.ResponseWriter) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return writePartialImportBindError
	}
	switch trimmed[0] {
	case '{':
		// A trailing second document is ignored: `{} {}` answered 200 with an
		// empty result set, so this decodes one value rather than requiring the
		// body to be exactly one.
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(out); err != nil {
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) || errors.Is(err, io.ErrUnexpectedEOF) {
				return writePartialImportParseError
			}
			return writePartialImportBindError
		}
		return nil
	case '[', '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return writePartialImportBindError
	}
	// A bare word: `true`, `false` and `null` are complete tokens the binder
	// rejects, and anything else - `nul` was the probe - is the parser's.
	word := string(bytes.TrimRight(trimmed, " \t\r\n"))
	if word == "true" || word == "false" || word == "null" {
		return writePartialImportBindError
	}
	return writePartialImportParseError
}

// writePartialImportParseError is the syntax half.
func writePartialImportParseError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "invalid_request", "Cannot parse the JSON")
}

// writePartialImportBindError is the binding half.
func writePartialImportBindError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error", "Cannot parse the JSON")
}

// writePartialImportServerError is Keycloak's own defect surfacing: an
// uncaught exception inside the import, answered with the generic description
// rather than a parse one. Two bodies reach it - an explicit
// `"ifResourceExists":null`, and a group carrying no `path`.
func writePartialImportServerError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// applyPartialImport runs the whole body.
//
// **A refusal rolls everything back.** Measured: a body naming a new user and
// then an existing one under FAIL answered the 409 and left the new user
// uncreated. Gloak has no transaction across repositories, so this collects the
// creations and undoes them, which is the same observable.
func (h *handler) applyPartialImport(ctx context.Context, rc *reqContext, in *partialImportBody,
	policy partialImportPolicy) (partialImportResults, func(http.ResponseWriter), error) {

	imp := &partialImporter{h: h, rc: rc, policy: policy}
	refusal, err := imp.run(ctx, in)
	if err != nil || refusal != nil {
		imp.rollback(ctx)
		return partialImportResults{}, refusal, err
	}
	return imp.results, nil, nil
}

// partialImporter carries the state one import needs: the results so far and
// what to undo if it does not finish.
type partialImporter struct {
	h       *handler
	rc      *reqContext
	policy  partialImportPolicy
	results partialImportResults
	undo    []func(context.Context)
	touched []string
}

func (p *partialImporter) rollback(ctx context.Context) {
	for i := len(p.undo) - 1; i >= 0; i-- {
		p.undo[i](ctx)
	}
}

func (p *partialImporter) record(action, resourceType, name, id string) {
	switch action {
	case actionAdded:
		p.results.Added++
	case actionSkipped:
		p.results.Skipped++
	case actionOverwritten:
		p.results.Overwritten++
	}
	p.results.Results = append(p.results.Results, partialImportResult{
		Action: action, ResourceType: resourceType, ResourceName: name, ID: id,
	})
}

// run walks the five resource families.
//
// The order here is Gloak's own and is **not** observable: Keycloak's results
// come back in a HashSet's order, so no ordering of this loop can be right or
// wrong against it. Clients come before client roles because a client role
// needs its container, which a body creating both in one request relies on -
// measured working.
func (p *partialImporter) run(ctx context.Context, in *partialImportBody) (func(http.ResponseWriter), error) {
	p.results.Results = []partialImportResult{}

	for _, u := range in.Users {
		if refusal, err := p.importUser(ctx, u); refusal != nil || err != nil {
			return refusal, err
		}
	}
	for _, g := range in.Groups {
		if refusal, err := p.importGroup(ctx, g); refusal != nil || err != nil {
			return refusal, err
		}
	}
	for i := range in.Clients {
		if refusal, err := p.importClient(ctx, &in.Clients[i]); refusal != nil || err != nil {
			return refusal, err
		}
	}
	if in.Roles != nil {
		for _, role := range in.Roles.Realm {
			if refusal, err := p.importRole(ctx, role, nil); refusal != nil || err != nil {
				return refusal, err
			}
		}
		for _, clientID := range sortedKeys(in.Roles.Client) {
			client, err := p.h.store.Clients().ByClientID(ctx, p.rc.realm.ID, clientID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					// Not measured. A client role named against a container
					// that does not exist is left as an internal error rather
					// than given an invented body.
					return writePartialImportServerError, nil
				}
				return nil, err
			}
			for _, role := range in.Roles.Client[clientID] {
				if refusal, err := p.importRole(ctx, role, client); refusal != nil || err != nil {
					return refusal, err
				}
			}
		}
	}
	for i := range in.IdentityProviders {
		if refusal, err := p.importIdentityProvider(ctx, &in.IdentityProviders[i]); refusal != nil || err != nil {
			return refusal, err
		}
	}
	return nil, nil
}

// alreadyExists is the FAIL refusal. Six spellings were measured, one per
// resource type, and **three of them have a full stop where the other three do
// not** - the same punctuation split AGENTS.md tracks on the not-found list,
// met again on a different verb.
//
//	User with user name u1 already exists.
//	Group '/g4' already exists
//	Client id 'pi-client-a' already exists
//	Realm role 'pi-role-a' already exists.
//	Client role 'pi-crole-a' for client 'pi-client-a' already exists.
//	Identity Provider 'idp-a' already exists.
func alreadyExists(message string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		httpx.WriteAdminError(w, http.StatusConflict, message)
	}
}

// refuseExisting is what a resource that already exists earns under a policy
// that is neither SKIP nor OVERWRITE.
//
// **It is two answers, not one.** FAIL and an absent field give the 409;
// an explicit `"ifResourceExists":null` gives the 500, because that is the
// branch where Keycloak dereferences the null it bound. A body naming null
// against a resource that does **not** exist never reaches here and answers
// 200 ADDED, which is the condition the first hand probe of this cell did not
// supply.
func (p *partialImporter) refuseExisting(message string) func(http.ResponseWriter) {
	if p.policy == policyNull {
		return writePartialImportServerError
	}
	return alreadyExists(message)
}

// duplicateResource is what a body naming one resource **twice** answers, and
// it answers it under SKIP as well as FAIL: the policy is about resources that
// existed before the import, not about the body's own repeats. It is the
// `Duplicate resource error` family AGENTS.md records elsewhere.
func duplicateResource(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusConflict, "Duplicate resource error")
}

func (p *partialImporter) importUser(ctx context.Context, u partialImportUser) (func(http.ResponseWriter), error) {
	name := strings.ToLower(string(u.Username))
	existing, err := p.h.store.Users().ByUsername(ctx, p.rc.realm.ID, name)
	switch {
	case err == nil:
		if p.seen("USER", name) {
			return duplicateResource, nil
		}
		switch p.policy {
		case policySkip:
			p.record(actionSkipped, "USER", string(u.Username), existing.ID)
			return nil, nil
		case policyOverwrite:
			if err := p.h.store.Users().Delete(ctx, p.rc.realm.ID, existing.ID); err != nil {
				return nil, err
			}
		default:
			return p.refuseExisting("User with user name " + string(u.Username) + " already exists."), nil
		}
	case errors.Is(err, store.ErrNotFound):
		if p.seen("USER", name) {
			return duplicateResource, nil
		}
	default:
		return nil, err
	}

	// **OVERWRITE mints a new id.** Measured on a user, a group and a client:
	// the row that comes back is not the row that went in, so this is a delete
	// and a create rather than an update.
	m := &model.User{
		ID:               idOrNew(u.ID),
		RealmID:          p.rc.realm.ID,
		Username:         name,
		Email:            u.Email,
		EmailVerified:    u.EmailVerified,
		Enabled:          u.Enabled,
		FirstName:        u.FirstName,
		LastName:         u.LastName,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := p.h.store.Users().Create(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return duplicateResource, nil
		}
		return nil, err
	}
	p.undo = append(p.undo, func(ctx context.Context) {
		_ = p.h.store.Users().Delete(ctx, p.rc.realm.ID, m.ID)
	})
	if err := roles.AssignDefaults(ctx, p.h.store.Roles(), p.rc.realm.ID, p.rc.realm.Name, m.ID); err != nil {
		return nil, err
	}
	p.record(p.actionFor(err), "USER", string(u.Username), m.ID)
	return nil, nil
}

func (p *partialImporter) importGroup(ctx context.Context, g partialImportGroup) (func(http.ResponseWriter), error) {
	// **A group with no `path` is a 500**, on every policy value, and it leaves
	// nothing behind. Keycloak's GroupsPartialImport creates the group and then
	// looks it up by a path the representation never carried, and
	// findGroupModel returning null is an uncaught NullPointerException. The
	// realm was `[]` afterwards on three such bodies, so the answer here is the
	// 500 and no group.
	if g.Path == "" {
		return writePartialImportServerError, nil
	}
	existing, err := p.h.groupAtPath(ctx, p.rc.realm.ID, groupByPathSegments(g.Path))
	switch {
	case err == nil:
		if p.seen("GROUP", g.Path) {
			return duplicateResource, nil
		}
		switch p.policy {
		case policySkip:
			p.record(actionSkipped, "GROUP", string(g.Name), existing.ID)
			return nil, nil
		case policyOverwrite:
			if err := p.h.store.Groups().Delete(ctx, p.rc.realm.ID, existing.ID); err != nil {
				return nil, err
			}
		default:
			return p.refuseExisting("Group '" + g.Path + "' already exists"), nil
		}
	case errors.Is(err, store.ErrNotFound):
		if p.seen("GROUP", g.Path) {
			return duplicateResource, nil
		}
	default:
		return nil, err
	}

	// **The body's id wins**, which is the same rule POST /client-scopes and
	// POST /clients follow and a third endpoint on that side of it: a group
	// imported with "id":"1111...1111" came back with exactly that id and holds
	// it in the realm.
	m := &model.Group{
		ID:      idOrNew(g.ID),
		RealmID: p.rc.realm.ID,
		Name:    string(g.Name),
	}
	if err := p.h.store.Groups().Create(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return duplicateResource, nil
		}
		return nil, err
	}
	p.undo = append(p.undo, func(ctx context.Context) {
		_ = p.h.store.Groups().Delete(ctx, p.rc.realm.ID, m.ID)
	})
	p.record(p.actionFor(err), "GROUP", string(g.Name), m.ID)
	return nil, nil
}

func (p *partialImporter) importClient(ctx context.Context, rep *clientRepresentation) (func(http.ResponseWriter), error) {
	existing, err := p.h.store.Clients().ByClientID(ctx, p.rc.realm.ID, rep.ClientID)
	switch {
	case err == nil:
		if p.seen("CLIENT", rep.ClientID) {
			return duplicateResource, nil
		}
		switch p.policy {
		case policySkip:
			p.record(actionSkipped, "CLIENT", rep.ClientID, existing.ID)
			return nil, nil
		case policyOverwrite:
			if err := p.h.store.Clients().Delete(ctx, p.rc.realm.ID, existing.ID); err != nil {
				return nil, err
			}
		default:
			return p.refuseExisting("Client id '" + rep.ClientID + "' already exists"), nil
		}
	case errors.Is(err, store.ErrNotFound):
		if p.seen("CLIENT", rep.ClientID) {
			return duplicateResource, nil
		}
	default:
		return nil, err
	}

	m := newClientFrom(*rep, p.rc.realm.ID)
	if rep.ID != "" {
		m.ID = rep.ID
	}
	m.Attributes["realm_client"] = "false"
	if !m.PublicClient {
		m.Attributes["client.secret.creation.time"] = strconv.FormatInt(time.Now().Unix(), 10)
		if m.Secret == "" {
			m.Secret = model.NewSecret()
		}
	}
	if err := bootstrap.InheritClientScopes(ctx, p.h.store, p.rc.realm.ID, m); err != nil {
		return nil, err
	}
	if err := p.h.store.Clients().Create(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return duplicateResource, nil
		}
		return nil, err
	}
	p.undo = append(p.undo, func(ctx context.Context) {
		_ = p.h.store.Clients().Delete(ctx, p.rc.realm.ID, m.ID)
	})
	if m.ServiceAccountsEnabled {
		if _, err := p.h.ensureServiceAccount(ctx, p.rc.realm, m); err != nil {
			return nil, err
		}
	}
	p.record(p.actionFor(err), "CLIENT", rep.ClientID, m.ID)
	return nil, nil
}

// importRole covers both halves of the `roles` object. `container` is nil for a
// realm role.
//
// **A client role's result row is not shaped like the others**: its
// `resourceName` is `<clientId>-->[roleName]` without the brackets, and its `id`
// is the **client's** uuid rather than the role's. Both measured twice, on two
// different clients.
func (p *partialImporter) importRole(ctx context.Context, role partialImportRole,
	container *model.Client) (func(http.ResponseWriter), error) {

	containerID := ""
	resourceType := "REALM_ROLE"
	name := string(role.Name)
	if container != nil {
		containerID = container.ID
		resourceType = "CLIENT_ROLE"
		name = container.ClientID + "-->" + string(role.Name)
	}

	existing, err := p.h.store.Roles().ByName(ctx, p.rc.realm.ID, containerID, string(role.Name))
	reportedID := func(roleID string) string {
		if container != nil {
			return container.ID
		}
		return roleID
	}
	switch {
	case err == nil:
		if p.seen(resourceType, name) {
			return duplicateResource, nil
		}
		switch p.policy {
		case policySkip:
			p.record(actionSkipped, resourceType, name, reportedID(existing.ID))
			return nil, nil
		case policyOverwrite:
			if err := p.h.store.Roles().Delete(ctx, p.rc.realm.ID, existing.ID); err != nil {
				return nil, err
			}
		default:
			if container != nil {
				return p.refuseExisting("Client role '" + string(role.Name) + "' for client '" +
					container.ClientID + "' already exists."), nil
			}
			return p.refuseExisting("Realm role '" + string(role.Name) + "' already exists."), nil
		}
	case errors.Is(err, store.ErrNotFound):
		if p.seen(resourceType, name) {
			return duplicateResource, nil
		}
	default:
		return nil, err
	}

	m := &model.Role{
		ID:          idOrNew(role.ID),
		RealmID:     p.rc.realm.ID,
		ClientID:    containerID,
		Name:        string(role.Name),
		Description: role.Description,
		Attributes:  role.Attributes,
	}
	if err := p.h.store.Roles().Create(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return duplicateResource, nil
		}
		return nil, err
	}
	p.undo = append(p.undo, func(ctx context.Context) {
		_ = p.h.store.Roles().Delete(ctx, p.rc.realm.ID, m.ID)
	})
	p.record(p.actionFor(err), resourceType, name, reportedID(m.ID))
	return nil, nil
}

func (p *partialImporter) importIdentityProvider(ctx context.Context, body *identityProviderBody) (func(http.ResponseWriter), error) {
	alias := ""
	if body.Alias != nil {
		alias = *body.Alias
	}
	existing, err := p.h.store.IdentityProviders().ByAlias(ctx, p.rc.realm.ID, alias)
	switch {
	case err == nil:
		if p.seen("IDP", alias) {
			return duplicateResource, nil
		}
		switch p.policy {
		case policySkip:
			p.record(actionSkipped, "IDP", alias, existing.InternalID)
			return nil, nil
		case policyOverwrite:
			if err := p.h.store.IdentityProviders().Delete(ctx, p.rc.realm.ID, alias); err != nil {
				return nil, err
			}
		default:
			return p.refuseExisting("Identity Provider '" + alias + "' already exists."), nil
		}
	case errors.Is(err, store.ErrNotFound):
		if p.seen("IDP", alias) {
			return duplicateResource, nil
		}
	default:
		return nil, err
	}

	m := identityProviderOf(p.rc.realm.ID, body)
	if err := p.h.store.IdentityProviders().Create(ctx, m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return duplicateResource, nil
		}
		return nil, err
	}
	p.undo = append(p.undo, func(ctx context.Context) {
		_ = p.h.store.IdentityProviders().Delete(ctx, p.rc.realm.ID, alias)
	})
	p.record(p.actionFor(err), "IDP", alias, m.InternalID)
	return nil, nil
}

// actionFor says whether the row that was just written replaced one. It reads
// the lookup's error rather than the policy, because OVERWRITE on a resource
// that does not exist is `ADDED` - measured on all three policy values against
// a new resource, which answered the identical 200.
func (p *partialImporter) actionFor(lookup error) string {
	if lookup == nil {
		return actionOverwritten
	}
	return actionAdded
}

// seen reports whether this import has already touched a resource, which is
// what turns a body naming one twice into the `Duplicate resource error` 409
// rather than a second create.
func (p *partialImporter) seen(resourceType, key string) bool {
	k := resourceType + "\x00" + key
	for _, s := range p.touched {
		if s == k {
			return true
		}
	}
	p.touched = append(p.touched, k)
	return false
}

func idOrNew(id string) string {
	if id != "" {
		return id
	}
	return model.NewID()
}

// sortedKeys puts the client-role containers in a fixed order. Keycloak's own
// order here is a Java map's and is unobservable in the answer, whose result
// array is unordered anyway; sorting is what makes Gloak's own golden
// reproducible.
func sortedKeys(m map[string][]partialImportRole) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
