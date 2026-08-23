package admin

import (
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
	mux.HandleFunc("GET /admin/realms/{realm}/users", h.guard("view-users", h.listUsers))
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
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if !c.has(role) {
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

// listUsers is a placeholder until Task 13 records the representation. It
// exists so the authentication and authorization cases have a route to reach;
// returning a body nobody measured would be worse than returning none.
func (h *handler) listUsers(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteJSON(w, http.StatusOK, []struct{}{})
}
