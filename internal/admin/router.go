package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

type handler struct {
	store      store.Store
	keys       *keys.Manager
	issuerBase string
}

// Register adds the Admin REST API to an existing mux.
//
// It registers onto a caller's mux rather than building its own, and does no
// wrapping. The security headers and the two measured fallback 404 shapes
// belong to the whole server, not to this API: with a mux of its own, an
// unmatched admin path would produce a third 404 shape, and only two are
// measured. internal/oidc.WithKeycloakFallbacks wraps the composed result
// once.
func Register(mux *http.ServeMux, s store.Store, k *keys.Manager, issuerBase string) {
	h := &handler{store: s, keys: k, issuerBase: issuerBase}
	h.register(mux)
}

// register declares every route. Routes are added through h.guard so that a
// route with no required role cannot be written by accident: guard takes the
// role as a parameter, so omitting it does not compile.
func (h *handler) register(mux *http.ServeMux) {
	// Listing and counting accept query-users as well as view-users, measured:
	// a caller holding only query-users gets 200 on both. Reading one user
	// does not - it answers 403.
	mux.HandleFunc("GET /admin/realms/{realm}/users", h.guardAny(usersReadRoles, h.listUsers))
	mux.HandleFunc("GET /admin/realms/{realm}/users/count", h.guardAny(usersReadRoles, h.countUsers))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}", h.guard("view-users", h.readUser))
	mux.HandleFunc("POST /admin/realms/{realm}/users", h.guard("manage-users", h.createUser))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}", h.guard("manage-users", h.updateUser))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}", h.guard("manage-users", h.deleteUser))
	// Reading a credential list needs only view-users: the body carries no
	// secret. Everything that changes one needs manage-users.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/credentials", h.guard("view-users", h.listCredentials))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/reset-password", h.guard("manage-users", h.resetPassword))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/credentials/{credentialID}", h.guard("manage-users", h.deleteCredential))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/userLabel", h.guard("manage-users", h.setCredentialLabel))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/moveToFirst", h.guard("manage-users", h.moveCredentialToFirst))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/credentials/{credentialID}/moveAfter/{previousID}", h.guard("manage-users", h.moveCredentialAfter))
	mux.HandleFunc("PUT /admin/realms/{realm}/users/{userID}/disable-credential-types", h.guard("manage-users", h.disableCredentialTypes))
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/logout", h.guard("manage-users", h.logoutUser))

	// The combined view: both halves of a user's **direct** mappings in one
	// object. Same guard as the six listings below, and measured on this route
	// rather than inherited - the same seven single-role callers, a fresh token
	// minted immediately before each call. view-clients was the plausible one
	// on a body keyed by clientId, and it is 403 here like the other four.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings",
		h.guardAny(userMappingsReadRoles, h.allMappings))

	// A user's realm role mappings: three reads that answer three different
	// questions. All three take view-users or manage-users - measured against a
	// live 26.7.1 with one user per role, a fresh token minted immediately
	// before each call, and two different subjects.
	//
	// Not usersReadRoles, which is one role wider: query-users opens the user
	// listing and the count and is 403 on all three of these. And not
	// view-users alone, which the plan predicted: manage-users has no
	// composites at all - it is not composite over view-users - and still opens
	// every one of them, so refusing it would be the too-restrictive direction
	// this cut has already reverted twice.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guardAny(userMappingsReadRoles, h.listRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/available",
		h.guardAny(userMappingsReadRoles, h.availableRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/composite",
		h.guardAny(userMappingsReadRoles, h.compositeRealmMappings))

	// The two writes take manage-users **alone**, which is narrower than the
	// reads above - measured on both verbs across the same seven single-role
	// callers, with a fresh token minted immediately before each call.
	// view-users opens all three reads and neither write, so
	// userMappingsReadRoles must not be reused here; extending a rule measured
	// on one verb to its neighbour is what this cut has already had to revert
	// twice.
	//
	// The guard follows the **subject**, not the role: a caller holding
	// manage-realm and nothing else is refused even for a realm role, which is
	// the opposite of roles-by-id.
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guard(userMappingsWriteRole, h.assignRealmMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guard(userMappingsWriteRole, h.removeRealmMappings))

	// The same three reads for one client's roles. The guard is the realm
	// triple's, and that is measured on these routes rather than inherited:
	// the same seven single-role callers were swept against all three, on two
	// subjects and two containers, with a fresh token minted immediately
	// before each call. A client-scoped route plausibly wants view-clients,
	// and it does not - view-clients and manage-clients are 403 on all three,
	// like every other role outside the users family.
	//
	// The guard follows the **subject** here too: which client's roles are
	// being read makes no difference to it, which is why the {clientUUID}
	// segment is the handler's business and not the guard's.
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guardAny(userMappingsReadRoles, h.listClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}/available",
		h.guardAny(userMappingsReadRoles, h.availableClientMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}/composite",
		h.guardAny(userMappingsReadRoles, h.compositeClientMappings))

	// The two client writes take manage-users **alone** - the realm writes'
	// guard, and narrower than the client reads directly above, which
	// view-users opens. Measured on these routes across the same seven
	// single-role callers, on both verbs, on an ordinary client and on the
	// realm's own, with a fresh token minted immediately before each call.
	//
	// A client-scoped **write** is where manage-clients was most plausible -
	// the reads refusing it is evidence about reads only - and it is 403 here
	// too. The guard follows the subject on this pair as on every other one in
	// the family, so the {clientUUID} segment stays the handler's business.
	mux.HandleFunc("POST /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guard(userMappingsWriteRole, h.assignClientMappings))
	mux.HandleFunc("DELETE /admin/realms/{realm}/users/{userID}/role-mappings/clients/{clientUUID}",
		h.guard(userMappingsWriteRole, h.removeClientMappings))

	mux.HandleFunc("GET /admin/realms/{realm}/clients", h.guard("view-clients", h.listClients))
	// {clientUUID}, not {client-uuid}: net/http requires a wildcard name to be
	// a Go identifier and panics on the hyphen. The OpenAPI description spells
	// it with one, and Case.Operation keeps that spelling - the route pattern
	// is ours, the operation key is Keycloak's, and they are not the same
	// string.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}", h.guard("view-clients", h.readClient))
	mux.HandleFunc("POST /admin/realms/{realm}/clients", h.guard("manage-clients", h.createClient))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}", h.guard("manage-clients", h.updateClient))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}", h.guard("manage-clients", h.deleteClient))

	// Reading a secret needs view-clients and regenerating one needs
	// manage-clients. That split is measured, not read off the names: three
	// users were given exactly one master-realm role each and every operation
	// called with a token for them.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/client-secret", h.guard("view-clients", h.readClientSecret))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/client-secret", h.guard("manage-clients", h.regenerateClientSecret))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/client-secret/rotated", h.guard("view-clients", h.readRotatedSecret))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/client-secret/rotated",
		h.guardRejecting("manage-clients", deleteRotatedSecretRejection, h.deleteRotatedSecret))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/service-account-user", h.guard("view-clients", h.readServiceAccountUser))

	// Realm roles: reading admits view-realm or manage-realm and writing needs
	// manage-realm - measured across eight single-role callers, none of the
	// users or clients roles opens any of them. manage-realm reading too is
	// not a composite - it is its own role with no children - so it has to be
	// admitted here rather than reached through view-realm.
	mux.HandleFunc("GET /admin/realms/{realm}/roles", h.guardAny(realmRolesReadRoles, h.listRealmRoles))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}", h.guardAny(realmRolesReadRoles, h.readRealmRole))
	mux.HandleFunc("POST /admin/realms/{realm}/roles", h.guard("manage-realm", h.createRealmRole))
	mux.HandleFunc("PUT /admin/realms/{realm}/roles/{roleName}", h.guard("manage-realm", h.updateRealmRole))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles/{roleName}", h.guard("manage-realm", h.deleteRealmRole))

	// Client roles: the same split as the realm roles above - reading admits
	// view-clients or manage-clients, and writing needs manage-clients alone.
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles", h.guardAny(clientRolesReadRoles, h.listClientRoles))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guardAny(clientRolesReadRoles, h.readClientRole))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/roles", h.guard("manage-clients", h.createClientRole))
	mux.HandleFunc("PUT /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guard("manage-clients", h.updateClientRole))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}", h.guard("manage-clients", h.deleteClientRole))

	// Composites, for both realm roles and client roles. The five shapes are
	// the same either side; only the locator differs. Reads take the same
	// guardAny pair as the plain role reads next door - measured directly
	// rather than assumed from that sibling, since two earlier tasks had to
	// correct exactly this assumption: a caller holding only view-realm and
	// one holding only manage-realm both get 200 on GET .../composites, and
	// the client side mirrors it with view-clients/manage-clients. Writes
	// (POST and DELETE) admit only the manage role on either side - measured
	// the same way, with the view role and the other side's manage role both
	// 403.
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites/realm",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/composites/clients/{targetClientUUID}",
		h.guardAny(realmRolesReadRoles, h.listComposites(h.realmRole, onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/roles/{roleName}/composites",
		h.guard("manage-realm", h.addComposites(h.realmRole)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles/{roleName}/composites",
		h.guard("manage-realm", h.removeComposites(h.realmRole)))

	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites/realm",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites/clients/{targetClientUUID}",
		h.guardAny(clientRolesReadRoles, h.listComposites(h.clientRoleLocator, onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guard("manage-clients", h.addComposites(h.clientRoleLocator)))
	mux.HandleFunc("DELETE /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/composites",
		h.guard("manage-clients", h.removeComposites(h.clientRoleLocator)))

	// The holders of a role. .../groups takes the same view/manage pair as the
	// plain role reads and the composites above it - measured the same way, not
	// assumed from that sibling.
	//
	// .../users does not: measured against a live 26.7.1 with every single
	// master-realm role tried alone and in combination, it 403s a caller
	// holding only view-realm/manage-realm/view-clients/manage-clients *and*
	// one holding only view-users/manage-users/query-users, and 200s only a
	// caller holding one of each pair together. That is a conjunction of two
	// role families neither guard nor guardAny expresses, so it gets its own
	// combinator rather than a third slice bolted onto guardAny's contract.
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/users",
		h.guardAnyAndAny(realmRolesReadRoles, usersReadRoles, h.roleUsers(h.realmRole)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles/{roleName}/groups",
		h.guardAny(realmRolesReadRoles, h.roleGroups(h.realmRole)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/users",
		h.guardAnyAndAny(clientRolesReadRoles, usersReadRoles, h.roleUsers(h.clientRoleLocator)))
	mux.HandleFunc("GET /admin/realms/{realm}/clients/{clientUUID}/roles/{roleName}/groups",
		h.guardAny(clientRolesReadRoles, h.roleGroups(h.clientRoleLocator)))

	// roles-by-id: the same eight operations, addressed by the role's own id
	// rather than by name/container path. The required role is decided by the
	// role's own container once it is resolved, not by the route - measured
	// against a live 26.7.1 for both a realm role and a client role id, across
	// every plain master-realm role. Reads take the same view/manage pair as
	// the by-name reads next door (a single measurement of view-realm and
	// view-clients alone had this wrong as a single role; manage-realm and
	// manage-clients were checked too and both open it). Writes - PUT, DELETE
	// and POST/DELETE .../composites - take only the manage role on the
	// resolved role's own side, measured the same way. See
	// guardByRoleContainer and the "roles-by-id" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.readRoleByID))
	mux.HandleFunc("PUT /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.updateRoleByID))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles-by-id/{roleID}",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.deleteRoleByID))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(nil)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites/realm",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(onlyRealmRoles)))
	mux.HandleFunc("GET /admin/realms/{realm}/roles-by-id/{roleID}/composites/clients/{targetClientUUID}",
		h.guardByRoleContainer(realmRolesReadRoles, clientRolesReadRoles, h.compositesByID(onlyThisClientsRoles)))
	mux.HandleFunc("POST /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.addCompositesByID))
	mux.HandleFunc("DELETE /admin/realms/{realm}/roles-by-id/{roleID}/composites",
		h.guardByRoleContainer([]string{"manage-realm"}, []string{"manage-clients"}, h.removeCompositesByID))
}

// guard is the authorization filter every admin route goes through: resolve
// the realm, resolve the caller from its session, then check the one role this
// operation requires.
//
// The role is per operation rather than a blanket "is an admin" check, because
// that is what was measured: a caller holding view-users and nothing else gets
// 200 listing users and 403 creating one.
func (h *handler) guard(role string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardRejecting(role, writeForbidden, next)
}

// guardAny is guard for a route that more than one role opens. The user
// listing and count take view-users, query-users or manage-users; reading one
// user takes only the first and third.
func (h *handler) guardAny(roles []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting(roles, writeForbidden, next)
}

// guardRejecting is guard with the rejection spelled out, for the one route
// that does not answer 403.
//
// DELETE .../client-secret/rotated answers 500 to a caller lacking its role -
// Keycloak's own error handler raises a NullPointerException while formatting
// the ForbiddenException. Measured, reproducible, and copied on purpose. A
// route with a different rejection has to say so at the call site rather than
// hiding it in the handler, because the rejection happens before the handler
// runs.
func (h *handler) guardRejecting(role string, reject func(http.ResponseWriter), next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting([]string{role}, reject, next)
}

// guardAnyAndAny is guard for the one route in this file that needs a role
// from each of two families rather than any of one: .../roles/{name}/users
// needs a role-management role (a: realmRolesReadRoles or
// clientRolesReadRoles) together with a user-read role (b: usersReadRoles) -
// measured, not assumed from guardAny's single-family siblings. It is built
// from guardAnyRejecting rather than duplicated: that call resolves the
// realm and the caller and checks the first family, and the wrapped next
// adds the second check before running the handler.
func (h *handler) guardAnyAndAny(a, b []string, next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return h.guardAnyRejecting(a, writeForbidden, func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !rc.caller.hasAny(b) {
			writeForbidden(w)
			return
		}
		next(w, r, rc)
	})
}

// guardByRoleContainer is guard for the roles-by-id routes, whose required
// role is decided by the **data** rather than by the route: the role has to
// be resolved before the caller can be judged, because the same path takes
// realmRoles for a realm role and clientRoles for a client role. Both take a
// slice rather than a single role, mirroring guardAny's contract - measured
// directly rather than assumed from the by-name reads next door: a single
// earlier measurement of view-realm and view-clients alone made this look
// like a lone role, and manage-realm/manage-clients opening it too was found
// on the second pass.
//
// The order matters and is measured too: the role is resolved first, so a
// missing role answers 404 whatever the caller holds. That is Keycloak's own
// behaviour, not a defensive choice - and it is not a safe one. Answering the
// existence question before the authorization question means an
// unauthorized caller can tell a missing id (404) apart from one that exists
// but it may not touch (403), which is exactly the ordering an access-control
// design would normally avoid. It is kept here because it is what was
// measured, not because it is the safer order.
func (h *handler) guardByRoleContainer(realmRoles, clientRoles []string, next func(http.ResponseWriter, *http.Request, *reqContext, *model.Role)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		role, err := h.store.Roles().ByID(r.Context(), realm.ID, r.PathValue("roleID"))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeRoleIDNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		required := realmRoles
		if role.ClientID != "" {
			required = clientRoles
		}
		if !c.hasAny(required) {
			writeForbidden(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c}, role)
	}
}

// guardAnyRejecting is the one implementation the three wrappers share:
// resolve the realm, resolve the caller, admit it if it holds any of the
// roles.
func (h *handler) guardAnyRejecting(roles []string, reject func(http.ResponseWriter), next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if !c.hasAny(roles) {
			reject(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}

// reqContext is what a handler needs that the request itself does not carry:
// the resolved realm and the authenticated caller.
type reqContext struct {
	realm  *model.Realm
	caller *caller
}

// realmIssuer is the iss claim a token from this realm carries, and therefore
// the value ParseAccess checks against.
func (h *handler) realmIssuer(realm string) string {
	return h.issuerBase + "/realms/" + realm
}

// usersReadRoles is what the user listing and the count accept. Reading one
// user by ID is not on this list: query-users was measured getting 403 there
// and 200 on the other two.
var usersReadRoles = []string{"view-users", "query-users", "manage-users"}

// userMappingsReadRoles is what the seven role-mapping reads accept - the three
// realm ones, the three client ones and the combined view, swept separately and
// agreeing. Six until the combined view joined them.
// It is usersReadRoles minus query-users, and the two lists are kept separate
// because they were measured separately and disagree: the same caller that
// gets 200 on GET /users gets 403 on GET /users/{id}/role-mappings/realm.
var userMappingsReadRoles = []string{"view-users", "manage-users"}

// userMappingsWriteRole is what all four role-mapping writes take, and it is a
// single role rather than a slice: view-users opens every read above and
// neither verb of either write.
//
// It is named because the two available reads need it too. Their own guard is
// the looser pair above, and the list they answer is measurably the set the
// caller could POST - a view-users caller gets 200 and `[]` - so grantable
// re-applies this before judging any individual role. Spelling it once is what
// stops that filter and this guard from drifting apart.
const userMappingsWriteRole = "manage-users"

// realmRolesReadRoles is what both realm-role reads accept: view-realm or
// manage-realm, measured across eight single-role callers.
var realmRolesReadRoles = []string{"view-realm", "manage-realm"}

// clientRolesReadRoles is what both client-role reads accept: view-clients or
// manage-clients - measured the same way as the realm-role pair above, on an
// ordinary client. GET .../roles answered 200 for both roles.
var clientRolesReadRoles = []string{"view-clients", "manage-clients"}
