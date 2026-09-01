package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// resourceServerRepresentation is Keycloak's ResourceServerRepresentation, in
// the field order measured 2026-08-31:
//
//	id clientId name allowRemoteResourceManagement policyEnforcementMode
//	resources policies scopes decisionStrategy
//
// **Neither `id` nor `clientId` is what its name says.** Both are the client's
// internal UUID - the same value twice - and `name` is the client's `clientId`
// string. So the representation's `clientId` is not the client's `clientId`,
// and a serialiser that filled it from `model.Client.ClientID` would produce a
// body that reads correctly and is wrong.
//
// **The three arrays are always empty on this read.** Measured against a
// resource server holding four scopes: `GET .../authz/resource-server` still
// answered `"scopes":[]`. They are not a view over anything, which is why
// nothing fills them here. `GET .../settings` is the read that populates them
// and it is a different body - see settingsRepresentation.
type resourceServerRepresentation struct {
	ID                            string                     `json:"id"`
	ClientID                      string                     `json:"clientId"`
	Name                          string                     `json:"name"`
	AllowRemoteResourceManagement bool                       `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string                     `json:"policyEnforcementMode"`
	Resources                     []struct{}                 `json:"resources"`
	Policies                      []struct{}                 `json:"policies"`
	Scopes                        []authzScopeRepresentation `json:"scopes"`
	DecisionStrategy              string                     `json:"decisionStrategy"`
}

// settingsRepresentation is what GET .../authz/resource-server/settings answers.
//
// **It is not the same body as the read beside it**, and the difference is not
// cosmetic: it omits `id`, `clientId` and `name`, and its `scopes` is populated
// where the other read's is always empty. It is the export shape, and the
// scopes inside it carry no `id`.
//
// It is a separate struct rather than the same one with omitempty because two
// of the three omissions are strings that a client could legitimately hold
// empty, so omitempty would be a guess. Measured on a resource server holding
// four scopes, where the two bodies differ in both directions at once.
//
// **`resources` was `[]struct{}` until P10's third cut and that was wrong.**
// Nothing had caught it because no fixture had a resource to put in it: the
// first two cuts served no route that could create one, so the only value the
// key ever took was the empty array. It carries the export view of every
// resource - the representation minus `_id` and `owner`, with each inline scope
// reduced to its name - in **creation order**, which is the same order the
// scopes beside it come back in. `policies` is still `[]struct{}` for the
// reason `resources` used to be, and that reason is now load-bearing rather
// than accidental: this cut serves no route that creates a policy, so the
// empty array is a fact about the store and not a placeholder.
type settingsRepresentation struct {
	AllowRemoteResourceManagement bool                          `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string                        `json:"policyEnforcementMode"`
	Resources                     []authzResourceRepresentation `json:"resources"`
	Policies                      []struct{}                    `json:"policies"`
	Scopes                        []authzScopeRepresentation    `json:"scopes"`
	DecisionStrategy              string                        `json:"decisionStrategy"`
}

// authzScopeRepresentation is a scope as the read, the listing, the search and
// the settings export all serve it.
//
// The measured field order is `id name iconUri displayName`, from a create
// that sent name, displayName and iconUri in that order. **The export is this
// same body with the id left empty** rather than a type of its own, which is
// measured rather than assumed: a scope carrying an iconUri and a displayName
// comes back from GET .../settings with both and without the id, so exactly
// one key differs between the two views.
//
// It is *not* what the create's 201 answers. That body echoes the request's
// `policies` and `resources` back and no other view of a scope carries them -
// see authzScopeCreated.
type authzScopeRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	IconURI     string `json:"iconUri,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// policyProvider is one entry of the two provider catalogues.
type policyProvider struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

// policyProviders is what both GET .../policy/providers and
// GET .../permission/providers answer, and they answer it **byte for byte
// alike** - 588 bytes each, compared with cmp on 2026-08-31. The permission
// catalogue is not filtered to the two providers whose group is "Permission";
// it carries regex, role, time and the rest, which is why one variable serves
// both routes rather than one being a subset of the other.
//
// Ten entries where the `policy` SPI registers eleven: `uma` is registered and
// is not offered here, and `js` is absent from both because SCRIPTS is a
// disabled feature.
//
// **The order is a Java map's and is written out rather than computed.**
// `javamap.KeyOrder` gets it wrong - it places client-scope before user and
// aggregate before group - while `javamap.SizedKeyOrder(n, ...)` for any n up
// to 9 reproduces it exactly. So the list is a measured key set for the sized
// constructor, and it is a constant here for the reason the argon2 keys are a
// constant: the values are fixed by the server's provider registry, and
// computing them would be a second implementation of something with one
// possible answer.
var policyProviders = []policyProvider{
	{Type: "regex", Name: "Regex", Group: "Identity Based"},
	{Type: "role", Name: "Role", Group: "Identity Based"},
	{Type: "resource", Name: "Resource-Based", Group: "Permission"},
	{Type: "scope", Name: "Scope-Based", Group: "Permission"},
	{Type: "client", Name: "Client", Group: "Identity Based"},
	{Type: "time", Name: "Time", Group: "Time Based"},
	{Type: "user", Name: "User", Group: "Identity Based"},
	{Type: "client-scope", Name: "Client Scope", Group: "Identity Based"},
	{Type: "group", Name: "Group", Group: "Identity Based"},
	{Type: "aggregate", Name: "Aggregated", Group: "Others"},
}

// readResourceServer serves GET .../clients/{client-uuid}/authz/resource-server.
//
// **No Cache-Control**, where every sub-resource read on this family carries
// `no-cache`. Measured on this route and on settings beside it, both of which
// omit it, against the four listings and the four searches, all of which send
// it. So it is not "the authz family sends no-cache" and not "reads send it":
// it is the two reads of the resource server itself that do not.
func (h *handler) readResourceServer(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	httpx.WriteJSONCharset(w, http.StatusOK, resourceServerRepresentation{
		// Both the client's internal UUID, deliberately. See the type.
		ID:                            a.client.ID,
		ClientID:                      a.client.ID,
		Name:                          a.client.ClientID,
		AllowRemoteResourceManagement: a.rs.AllowRemoteResourceManagement,
		PolicyEnforcementMode:         a.rs.PolicyEnforcementMode,
		Resources:                     []struct{}{},
		Policies:                      []struct{}{},
		Scopes:                        []authzScopeRepresentation{},
		DecisionStrategy:              a.rs.DecisionStrategy,
	})
}

// readResourceServerSettings serves GET .../authz/resource-server/settings.
//
// It needs **manage-authorization**, where the read beside it takes
// view-authorization or view-clients. Measured one role at a time on four
// callers: view-authorization and view-clients both read
// `.../authz/resource-server` and are 403 here. A read that refuses the view
// role is the opposite of AGENTS.md's "reads accept the manage role, not just
// the view role", and the role list is in the router rather than here.
// **The scopes come back in creation order, where the listing beside them is
// sorted by name.** Measured 2026-09-01: four scopes created zulu, yankee,
// xray, whiskey - the reverse of name order - came back that way here and the
// other way from GET .../scope, and deleting xray and recreating it moved it
// to the **end**. The first cut recorded this order as "neither name order nor
// insertion order and not pinned"; it is insertion order, and store.ListScopes
// returns it so that one set of rows can serve both reads.
//
// Each entry is stripped of its `id` and keeps its `iconUri` and
// `displayName`, measured on scopes carrying both.
func (h *handler) readResourceServerSettings(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	scopes, err := h.store.Authz().ListScopes(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	exported := []authzScopeRepresentation{}
	byID := make(map[string]*model.AuthzScope, len(scopes))
	for _, s := range scopes {
		byID[s.ID] = s
		e := scopeRepresentationOf(s)
		// The one difference from every other view of a scope.
		e.ID = ""
		exported = append(exported, e)
	}
	// The resources come back in creation order too, which is what
	// store.ListResources returns - the listing beside it is the one that
	// sorts. Their export view drops `_id` and `owner` and keeps `type`,
	// `displayName` and `icon_uri`, all four halves measured on one resource
	// carrying all of them.
	resources, err := h.store.Authz().ListResources(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	exportedResources := []authzResourceRepresentation{}
	for _, res := range resources {
		exportedResources = append(exportedResources, authzResourceRepresentationOf(
			res, a.client.ID, a.client.ClientID, byID, authzResourceExported))
	}
	httpx.WriteJSONCharset(w, http.StatusOK, settingsRepresentation{
		AllowRemoteResourceManagement: a.rs.AllowRemoteResourceManagement,
		PolicyEnforcementMode:         a.rs.PolicyEnforcementMode,
		Resources:                     exportedResources,
		Policies:                      []struct{}{},
		Scopes:                        exported,
		DecisionStrategy:              a.rs.DecisionStrategy,
	})
}

// listPolicyProviders serves both GET .../policy/providers and
// GET .../permission/providers, which are byte-identical. It carries
// Cache-Control, unlike the two resource-server reads.
func (h *handler) listPolicyProviders(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	writeAdminJSON(w, policyProviders)
}

// resourceServerBody is what PUT .../authz/resource-server decodes.
//
// Decoded with decodeStrict: an unknown field answers
// `Invalid json representation for ResourceServerRepresentation. Unrecognized
// field "zzz" at line 1 column 9.` These are the fifth and sixth strict
// endpoints after the two required-action PUTs and the two organization writes.
//
// The field set is what the server accepts and no more. `id`, `clientId` and
// `name` are declared because a body carrying them is not the unknown-field
// 400, and they are unused because the write ignores them - the three values
// are derived from the client on every read.
// **Every field is a pointer that needs to tell absent from zero**, because an
// absent field is neither kept nor zeroed - see updateResourceServer.
type resourceServerBody struct {
	ID                            string  `json:"id"`
	ClientID                      string  `json:"clientId"`
	Name                          string  `json:"name"`
	AllowRemoteResourceManagement *bool   `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string  `json:"policyEnforcementMode"`
	DecisionStrategy              *string `json:"decisionStrategy"`
}

// The accepted enum values, and neither list is the one the OpenAPI description
// declares.
//
// **CONSENSUS is a documented decisionStrategy and a 500 on this endpoint**:
// `{"decisionStrategy":"CONSENSUS"}` answers
// `{"error":"unknown_error","error_description":"For more on this error consult
// the server log."}`, where AFFIRMATIVE and UNANIMOUS answer 204. Measured
// three times in one sweep. It is Keycloak's own defect and it is reproduced,
// the same way POST /users with an empty body is reproduced as a 500.
//
// An unknown policyEnforcementMode is **not** a validation error either: it is
// `400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
// a parse failure for a body that parses, because Jackson rejects the token
// while binding the enum. Measured with `{"policyEnforcementMode":"NOPE"}`
// beside a good decisionStrategy, so the two checks are independent.
var (
	authzPolicyEnforcementModes = []string{"ENFORCING", "PERMISSIVE", "DISABLED"}
	// The two that work. CONSENSUS is handled separately because its answer is
	// a 500 rather than the 400 an unknown value gets, and folding it into
	// either list loses that.
	authzDecisionStrategies = []string{"AFFIRMATIVE", "UNANIMOUS"}
)

// updateResourceServer serves PUT .../clients/{client-uuid}/authz/resource-server.
//
// Measured: 204, no body, no Cache-Control and no Content-Type.
//
// **`decisionStrategy` is the gate, and nothing else is.** A body that does not
// carry it - or carries it as `null` - answers
// `409 {"error":"conflict","error_description":"Duplicate resource error"}` and
// changes nothing, whatever else it holds. Measured across ten bodies:
// `{}`, `{"name":"x"}`, `{"allowRemoteResourceManagement":false}`,
// `{"policyEnforcementMode":"PERMISSIVE"}`, `{"id":...}` and `{"clientId":...}`
// are all 409, and `{"decisionStrategy":"AFFIRMATIVE"}` **alone** is 204.
//
// That last pair is the whole finding. The first reading of this endpoint was
// "a body with no name is a 409", from `{}` and `{"name":"x"}`... and the
// second of those is a 409 *with* a name. `{"name":"x"}` is the probe that
// tells the two rules apart, and it was only sent because a role sweep happened
// to use it.
//
// **The write replaces, and the values an absent field takes are not the zero
// values.** `{"decisionStrategy":"UNANIMOUS"}` against a stored
// `false / PERMISSIVE / AFFIRMATIVE` produced `true / ENFORCING / UNANIMOUS`:
// the two absent fields went to Keycloak's ResourceServerRepresentation field
// initialisers, not to `false` and not to what was stored. Measured twice, from
// `PERMISSIVE` and from `DISABLED`. So this is model.DefaultAuthzResourceServer
// overwritten by what the body named - which is neither a merge nor a Go
// zero-value replace, and both of those are wrong on
// allowRemoteResourceManagement in opposite directions.
func (h *handler) updateResourceServer(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	var body resourceServerBody
	if !decodeStrict(w, r, "ResourceServerRepresentation", &body) {
		return
	}
	// The gate. It runs after the strict decode - `{"zzz":1}` carries no
	// decisionStrategy and answers the unknown-field 400 rather than this 409 -
	// and before both enum checks: `{"policyEnforcementMode":"NOPE"}` with no
	// decisionStrategy is a 409, not the 400 the same value gets beside a good
	// strategy.
	if body.DecisionStrategy == nil {
		// The protocol mappers' helper, reused rather than copied: **this 409
		// drops the five security headers too**, measured on both endpoints.
		// The three other refusals on this same route - the strict 400, the
		// bad-enum 400 and the CONSENSUS 500 - all carry the five, so the
		// omission belongs to the `Duplicate resource error` shape and not to
		// the endpoint or to the status class. That is a second instance of an
		// exception AGENTS.md's security-header bullet does not list.
		writeDuplicateResource(w)
		return
	}
	if *body.DecisionStrategy == "CONSENSUS" {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"For more on this error consult the server log.")
		return
	}
	if !containsString(authzDecisionStrategies, *body.DecisionStrategy) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unknown_error", "Cannot parse the JSON")
		return
	}
	if body.PolicyEnforcementMode != "" &&
		!containsString(authzPolicyEnforcementModes, body.PolicyEnforcementMode) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unknown_error", "Cannot parse the JSON")
		return
	}

	// Start from the defaults rather than from what is stored: an absent field
	// is reset to the representation's own initialiser, measured.
	updated := model.DefaultAuthzResourceServer(a.client.ID)
	if body.AllowRemoteResourceManagement != nil {
		updated.AllowRemoteResourceManagement = *body.AllowRemoteResourceManagement
	}
	if body.PolicyEnforcementMode != "" {
		updated.PolicyEnforcementMode = body.PolicyEnforcementMode
	}
	updated.DecisionStrategy = *body.DecisionStrategy
	if err := h.store.Authz().Upsert(r.Context(), updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// authzContext is what every handler on this family needs: the client the path
// named and its resource server. Both are resolved by guardAuthz, because the
// second is the gate.
type authzContext struct {
	client *model.Client
	rs     *model.AuthzResourceServer
}

// guardAuthz is the guard every route under authz/resource-server takes.
//
// **The order is measured and it is a fourth shape**, sharing an implementation
// with neither client-types nor organizations:
//
//	no Authorization header             401 {"error":"HTTP 401 Unauthorized"}
//	unknown realm                       404 {"error":"Realm not found."}
//	unknown client, may list clients    404 {"error":"Could not find client"}
//	unknown client, may not             403 {"error":"HTTP 403 Forbidden"}
//	client without the flag, any caller 404 {"error":"HTTP 404 Not Found"}
//	client with it, caller without the role  403 {"error":"HTTP 403 Forbidden"}
//
// Two things in that table are easy to get wrong and both are measured.
//
// **The gate runs before the roles.** A caller holding no admin role at all
// gets the 404 for a client without authorization services, exactly as
// client-types' 501 precedes its authorization check and unlike organizations'
// realm flag, which follows it. Putting the role check first would answer 403
// where Keycloak answers 404.
//
// **The unknown client is Keycloak's id-phishing branch**, and it is the one
// place in this package where a 404 depends on the caller: `view-clients` sees
// `Could not find client` and `view-authorization` - which reads the resource
// server of a client that does exist - sees 403. That is not the role-mapping
// routes' rule, which was re-measured on the same container as a control and
// still answers `Client not found` to a caller holding nothing.
//
// The gate's own 404 body is `{"error":"HTTP 404 Not Found"}`, which is the
// body AGENTS.md attributes to a wrong method on a known path. Here it is a
// correct method on a correct path whose resource is switched off, so that
// bullet's two producers are three.
func (h *handler) guardAuthz(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext, *authzContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		rc := &reqContext{realm: realm, caller: c}
		client, err := h.store.Clients().ByID(r.Context(), realm.ID, r.PathValue("clientUUID"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// The phishing branch: the message only goes to a caller who
				// may enumerate clients anyway.
				if c.hasAny(clientsReadRoles) {
					writeClientNotFound(w)
					return
				}
				writeForbidden(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		rs, err := h.store.Authz().ByClientID(r.Context(), client.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAuthzNotEnabled(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !c.hasAny(roles) {
			writeForbidden(w)
			return
		}
		next(w, r, rc, &authzContext{client: client, rs: rs})
	}
}

// writeAuthzNotEnabled is what a client without authorizationServicesEnabled
// answers on every path under authz/resource-server.
//
// Measured on eight of them - the resource server, settings, the four listings,
// policy/providers and a search - and on four callers including one holding no
// admin role, all alike. The body carries a plain `application/json` with no
// charset and no Cache-Control, which is the ordinary error shape.
func writeAuthzNotEnabled(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}
