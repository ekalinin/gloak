package admin

import (
	"net/http"

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

// realmRolesReadRoles is what both realm-role reads accept: view-realm or
// manage-realm, measured across eight single-role callers.
var realmRolesReadRoles = []string{"view-realm", "manage-realm"}
