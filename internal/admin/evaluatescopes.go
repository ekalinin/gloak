package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// The scope evaluator: what the admin console shows when it asks "what would
// this client's tokens look like for this user".
//
// **It is not the scope-mapping family with a prefix**, and that was measured
// rather than assumed - which is the check the neighbouring-family shortcut
// exists to fail. On a client with fullScopeAllowed off, one realm role mapped
// directly and composite over a second, and a linked client scope carrying a
// scope mapping to a third:
//
//	evaluate-scopes/scope-mappings/{realm}/granted   r1, r2, r3
//	scope-mappings/realm/composite                   r1, r2
//	scope-mappings/realm                             r1
//
// The third role arrives through the **linked client scope's own scope
// mappings**, which the neighbour does not read, and a `scope` query parameter
// naming an optional client scope adds a fourth. So the evaluated scope has two
// inputs hasScope has none of, and pointing compositeRealmScopeMappings at this
// route would be wrong on both of them.
//
// Two of the seven operations of this family are deliberately not served, both
// for boundary reasons rather than for effort:
//
//   - generate-example-userinfo's body is the userinfo document, whose one
//     truth is internal/oidc's userinfoDocument. Declaring that shape a second
//     time here is exactly the duplication follow-up F148 exists to prevent.
//   - generate-example-saml-response is a SAML assertion, and Gloak serves no
//     SAML at all. It is also unrecordable: two ID_<uuid> attributes, four
//     timestamps and a Java set's role order move between two identical
//     requests, inside a JSON **string**, which no mask in the harness reaches.
//
// Both are in the catalogue as Pending with those reasons.

// protocolMapperEvaluationRepresentation is one row of
// GET .../evaluate-scopes/protocol-mappers, in the measured key order.
//
// containerName is the surprise: it is the **client scope's** name, and a
// client's own mapper carries `""` even when the client has a name. Measured by
// putting a name on a client carrying a direct mapper and re-reading - the
// field stayed empty, so it is not "the container's display name" and a
// fallback to the clientId would be wrong.
type protocolMapperEvaluationRepresentation struct {
	MapperID       string `json:"mapperId"`
	MapperName     string `json:"mapperName"`
	ContainerID    string `json:"containerId"`
	ContainerName  string `json:"containerName"`
	ContainerType  string `json:"containerType"`
	ProtocolMapper string `json:"protocolMapper"`
}

// The two containerType spellings, measured. There is no third: a client scope
// and the client itself are the only two places a mapper can live.
const (
	containerTypeClientScope = "client-scope"
	containerTypeClient      = "client"
)

// evaluatedScopes is the client scopes a request evaluates against: the
// client's default scopes plus the optional ones the `scope` parameter names.
//
// An optional scope the request does not name contributes nothing, and a
// `scope` naming something that is not one of this client's optional scopes is
// **silently ignored** - measured, `scope=nosuchscope` is a 200 that changes no
// byte of the answer, not a 400. The same is true of a `scope` naming one of
// the client's own *default* scopes: it is already in, and naming it adds
// nothing.
func (h *handler) evaluatedScopes(ctx context.Context, c *model.Client, requested string) ([]*model.ClientScope, error) {
	defaults, err := h.store.ClientScopes().ListClientScopes(ctx, c.ID, true)
	if err != nil {
		return nil, err
	}
	optional, err := h.store.ClientScopes().ListClientScopes(ctx, c.ID, false)
	if err != nil {
		return nil, err
	}
	asked := strings.Fields(requested)
	out := make([]*model.ClientScope, 0, len(defaults)+len(optional))
	out = append(out, defaults...)
	for _, s := range optional {
		if slices.Contains(asked, s.Name) {
			out = append(out, s)
		}
	}
	return out, nil
}

// listEvaluatedProtocolMappers serves
// GET .../evaluate-scopes/protocol-mappers.
//
// Every mapper of every evaluated client scope, then the client's own. The
// client's come last, measured on a client carrying one.
//
// The array's order is the client's own scope list order, which is measured
// **not reproducible across container starts** - see the client-scope chapter's
// note that a client's two lists swapped two names between two clients created
// minutes apart. The case compares it unordered for that reason and not because
// nothing was measured.
func (h *handler) listEvaluatedProtocolMappers(w http.ResponseWriter, r *http.Request, rc *reqContext, c *model.Client) {
	scopes, err := h.evaluatedScopes(r.Context(), c, r.URL.Query().Get("scope"))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]protocolMapperEvaluationRepresentation, 0)
	for _, s := range scopes {
		for _, m := range s.ProtocolMappers {
			out = append(out, protocolMapperEvaluationRepresentation{
				MapperID: m.ID, MapperName: m.Name,
				ContainerID: s.ID, ContainerName: s.Name,
				ContainerType: containerTypeClientScope, ProtocolMapper: m.ProtocolMapper,
			})
		}
	}
	for _, m := range c.ProtocolMappers {
		out = append(out, protocolMapperEvaluationRepresentation{
			MapperID: m.ID, MapperName: m.Name,
			ContainerID: c.ID, ContainerName: "",
			ContainerType: containerTypeClient, ProtocolMapper: m.ProtocolMapper,
		})
	}
	writeAdminJSON(w, out)
}

// roleContainer resolves the {roleContainerId} segment of the two scope-mapping
// reads: the realm's **name**, or a client's **UUID**.
//
// Both halves are measured, and both are narrower than a reader would guess.
// The realm's own **id** is a 404 although every realm role's containerId is
// that id, and a client's **clientId** is a 404 although every other route in
// this API that takes a client name takes it there. So the two spellings that
// work are the two a reader would not pick.
func (h *handler) roleContainer(ctx context.Context, rc *reqContext, id string) ([]*model.Role, bool, error) {
	if id == rc.realm.Name {
		out, err := h.store.Roles().ListRealmRoles(ctx, rc.realm.ID)
		return out, true, err
	}
	c, err := h.store.Clients().ByID(ctx, rc.realm.ID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	out, err := h.store.Roles().ListClientRoles(ctx, rc.realm.ID, c.ID)
	return out, true, err
}

// evaluatedScopePredicate is what `granted` keeps and `not-granted` drops.
//
// It is hasScope's three clauses plus a fourth, and the fourth is this family's
// whole difference from the scope-mapping one: **the evaluated client scopes'
// own scope mappings are in the client's scope**. A client scope has no
// fullScopeAllowed and owns no roles, so it contributes its mappings and
// nothing else.
//
// fullScopeAllowed short-circuits the rest, measured: a SAML client created
// with the flag on answered every realm role from `granted` and `[]` from
// `not-granted`, where `account` with the flag off answered the reverse.
func (h *handler) evaluatedScopePredicate(ctx context.Context, c *model.Client,
	scopes []*model.ClientScope) (func(*model.Role) bool, error) {
	if c.FullScopeAllowed {
		return func(*model.Role) bool { return true }, nil
	}
	direct, err := h.store.Roles().ListClientScopeMappings(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	own, err := h.store.Roles().ListClientRoles(ctx, c.RealmID, c.ID)
	if err != nil {
		return nil, err
	}
	direct = append(direct, own...)
	for _, s := range scopes {
		mapped, err := h.store.Roles().ListClientScopeScopeMappings(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		direct = append(direct, mapped...)
	}
	reachable, err := roles.ExpandFrom(ctx, h.store.Roles(), direct)
	if err != nil {
		return nil, err
	}
	in := make(map[string]bool, len(reachable))
	for _, role := range reachable {
		in[role.ID] = true
	}
	return func(role *model.Role) bool { return in[role.ID] }, nil
}

// evaluatedScopeMappings serves both
// .../evaluate-scopes/scope-mappings/{roleContainerId}/granted and its
// not-granted sibling. `granted` reports true.
//
// The two are exact complements over the container's roles, measured on both
// containers of a client whose scope holds some of each. Neither honours
// briefRepresentation - the description declares no such parameter and the
// brief shape is what both answer.
func (h *handler) evaluatedScopeMappings(granted bool) func(http.ResponseWriter, *http.Request, *reqContext, *model.Client) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext, c *model.Client) {
		all, ok, err := h.roleContainer(r.Context(), rc, r.PathValue("roleContainerID"))
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !ok {
			writeRoleContainerNotFound(w)
			return
		}
		scopes, err := h.evaluatedScopes(r.Context(), c, r.URL.Query().Get("scope"))
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		inScope, err := h.evaluatedScopePredicate(r.Context(), c, scopes)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		writeMappingList(w, keep(all, func(role *model.Role) bool {
			return inScope(role) == granted
		}), rc.realm.ID, true)
	}
}

// writeRoleContainerNotFound is the 404 an unknown {roleContainerId} gets.
//
// `Role Container not found` is a spelling this API did not have - the
// twenty-ninth in AGENTS.md's list, with a capital C in the middle and no full
// stop - so it gets a helper of its own rather than a shared not-found.
func writeRoleContainerNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Role Container not found")
}

// exampleTokenScope is the `scope` claim of both example tokens: the evaluated
// client scopes that ask to be in it, in the client's own list order.
//
// `include.in.token.scope` is read as "anything but the string false", which is
// how the six bootstrapped default scopes split - profile and email are in,
// web-origins, acr, roles and basic are out - and which is why `account`'s
// example answers `email profile` and not the six names it is attached to.
//
// The **order** is the client's list order and is not reproducible across
// container starts, for the same reason the client's own two scope lists are
// not. The cases compare it with UnorderedWords, which is what
// oidc/introspection/active-refresh-token already does to the same claim.
func exampleTokenScope(scopes []*model.ClientScope) string {
	words := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if v, _ := s.Attributes.Get("include.in.token.scope"); v != "false" {
			words = append(words, s.Name)
		}
	}
	return strings.Join(words, " ")
}

// exampleTokenRequest builds the issuance request the two example bodies are
// rendered from.
//
// The session is a throwaway and is never stored: Keycloak mints a fresh sid
// per request for a session that does not exist, measured by issuing the same
// request twice and finding four values moved - exp, iat, jti and sid - and
// nothing else.
//
// The roles are the user's effective roles **filtered by the evaluated scope**,
// which is the whole point of the endpoint and the reason `account` previews a
// token with no realm_access although the administrator holds five realm roles.
func (h *handler) exampleTokenRequest(ctx context.Context, rc *reqContext, c *model.Client,
	user *model.User, requested string) (token.Request, error) {
	scopes, err := h.evaluatedScopes(ctx, c, requested)
	if err != nil {
		return token.Request{}, err
	}
	inScope, err := h.evaluatedScopePredicate(ctx, c, scopes)
	if err != nil {
		return token.Request{}, err
	}
	held, err := roles.Effective(ctx, h.store.Roles(), user.ID)
	if err != nil {
		return token.Request{}, err
	}
	var realmRoles []string
	clientRoles := make(map[string][]string)
	for _, role := range keep(held, inScope) {
		if role.ClientID == "" {
			realmRoles = append(realmRoles, role.Name)
			continue
		}
		owner, err := h.store.Clients().ByID(ctx, rc.realm.ID, role.ClientID)
		if err != nil {
			return token.Request{}, err
		}
		clientRoles[owner.ClientID] = append(clientRoles[owner.ClientID], role.Name)
	}
	return token.Request{
		Client: c,
		User:   user,
		UserSession: &model.UserSession{
			ID: model.NewID(), RealmID: rc.realm.ID,
			UserID: user.ID, Username: user.Username,
		},
		Scope:       exampleTokenScope(scopes),
		RealmRoles:  realmRoles,
		ClientRoles: clientRoles,
		AccessLife:  rc.realm.AccessTokenLifespan,
	}, nil
}

// generateExampleAccessToken and generateExampleIDToken serve the two token
// previews. Both delegate the claim set to internal/token; neither builds one.
func (h *handler) generateExampleAccessToken(w http.ResponseWriter, r *http.Request, rc *reqContext,
	c *model.Client, user *model.User) {
	h.writeExampleToken(w, r, rc, c, user, func(i *token.Issuer, req token.Request) any {
		return i.ExampleAccessClaims(req)
	})
}

func (h *handler) generateExampleIDToken(w http.ResponseWriter, r *http.Request, rc *reqContext,
	c *model.Client, user *model.User) {
	h.writeExampleToken(w, r, rc, c, user, func(i *token.Issuer, req token.Request) any {
		return i.ExampleIDClaims(req)
	})
}

// writeExampleToken is what the two previews share: resolve the inputs, ask
// internal/token for the claim set, send it.
//
// The Issuer carries no keys, and that is not an oversight. Nothing here is
// signed - the endpoint answers a claim set as an ordinary JSON body - so
// handing it a signer would be declaring a capability this path does not use.
func (h *handler) writeExampleToken(w http.ResponseWriter, r *http.Request, rc *reqContext,
	c *model.Client, user *model.User, claims func(*token.Issuer, token.Request) any) {
	req, err := h.exampleTokenRequest(r.Context(), rc, c, user, r.URL.Query().Get("scope"))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	want := r.URL.Query().Get("audience")
	available, err := h.exampleAudienceAvailable(r.Context(), rc, c, req, want)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !available {
		writeAudienceNotAvailable(w, want)
		return
	}
	issuer := &token.Issuer{Issuer: h.realmIssuer(rc.realm.Name)}
	writeAdminJSON(w, claims(issuer, req))
}

// exampleAudienceAvailable is the `audience` parameter's refusal, and the two
// halves of it are the opposite way round from what a reader expects.
//
// Measured on four values against `account`:
//
//	audience=master-realm    404 Requested audience not available: master-realm
//	audience=account         404 - a client is never its own audience
//	audience=admin-cli       404
//	audience=nosuchclient    **200**, silently ignored
//
// So an audience naming a client that **does not exist** is dropped, and one
// naming a client that does but is out of scope is a 404. Refusing the unknown
// one "because it cannot be resolved" is the obvious implementation and it is
// wrong on the only value that succeeds.
//
// The available set is **computed, not assumed to be empty.** The positive case
// was measured rather than inferred from the three refusals: a second client
// whose role the user holds and whose role is mapped into this client's scope
// answers 200 for `audience=<that client>`, and it is exactly the value the
// token's own `aud` already carries. So the set is token.Audience's - the
// clients the user holds roles on, in scope, minus the issuing client - and
// the answer follows the claim rather than being a second rule beside it.
func (h *handler) exampleAudienceAvailable(ctx context.Context, rc *reqContext,
	c *model.Client, req token.Request, want string) (bool, error) {
	if want == "" {
		return true, nil
	}
	if _, err := h.store.Clients().ByClientID(ctx, rc.realm.ID, want); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Not a client of this realm at all: dropped rather than refused.
			return true, nil
		}
		return false, err
	}
	return slices.Contains(token.Audience(c.ClientID, req.ClientRoles), want), nil
}

// writeAudienceNotAvailable spells the 404 that refusal sends. The requested
// value is echoed into the sentence, which is why this takes an argument.
func writeAudienceNotAvailable(w http.ResponseWriter, audience string) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Requested audience not available: "+audience)
}

// guardEvaluateScopes is the three reads' guard: the protocol-mapper family's
// coarse gate and fine check, reused after being measured on **these** routes
// rather than carried over.
//
// The order, from a sweep varying which id is bad against four callers:
//
//	no clients role   403, even for a client that does not exist
//	query-clients     404 for a client that does not exist, 403 for one that does
//	view-clients      404 for a bad client, 404 for a bad role container, 200 otherwise
//
// So the client is resolved inside the coarse gate and before the fine check,
// and the role container after both - which is why a query-clients caller gets
// `Could not find client` for a bad client and a plain 403 for a bad container.
func (h *handler) guardEvaluateScopes(
	next func(http.ResponseWriter, *http.Request, *reqContext, *model.Client)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			client, ok := h.clientFromPath(w, r, rc)
			if !ok {
				return
			}
			if !mayUseClientMappers(rc.caller, false) {
				writeForbidden(w)
				return
			}
			next(w, r, rc, client)
		})
}

// guardExampleToken is the two generators' guard, and it is **not** the one
// above with a user lookup appended.
//
// The four generate-example-* routes refuse every single admin role there is -
// swept over eleven of them one at a time, with GET /admin/realms/{realm}/
// clients as a control that answers 200 to three of the same callers. They need
// a **conjunction**: a client-read role and a user-read role held together.
//
//	view-clients   + view-users    200      manage-clients + view-users    200
//	view-clients   + manage-users  200      manage-clients + manage-users  200
//	view-clients   + query-users   403      query-clients  + view-users    403
//	view-clients   + impersonation 403      view-clients   + view-realm    403
//
// So neither half's `query-` role opens it, and the two halves are userReadRoles
// and mayUseClientMappers' read pair. This is the second family in this API with
// /roles/{name}/users' shape, which AGENTS.md records as the only one.
//
// Three things happen after the client and before the user, in this order,
// measured against a view-clients caller holding no user role:
//
//	no userId at all   404 {"error":"No userId provided"}   - before the user role
//	user role missing  403 {"error":"You have no access to this user"}
//	userId unknown     404 {"error":"No user found"}
//
// The 403 is its own sentence rather than the generic `HTTP 403 Forbidden`, and
// the presence check running ahead of it is what makes a caller with no user
// role able to see the parameter is missing.
func (h *handler) guardExampleToken(
	next func(http.ResponseWriter, *http.Request, *reqContext, *model.Client, *model.User)) http.HandlerFunc {
	return h.guardEvaluateScopes(func(w http.ResponseWriter, r *http.Request, rc *reqContext, c *model.Client) {
		id := r.URL.Query().Get("userId")
		if id == "" {
			httpx.WriteMessageError(w, http.StatusNotFound, "No userId provided")
			return
		}
		if !rc.caller.hasAny(userReadRoles) {
			httpx.WriteMessageError(w, http.StatusForbidden, "You have no access to this user")
			return
		}
		user, err := h.store.Users().ByID(r.Context(), rc.realm.ID, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				httpx.WriteMessageError(w, http.StatusNotFound, "No user found")
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		next(w, r, rc, c, user)
	})
}
