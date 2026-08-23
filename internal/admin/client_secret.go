package admin

import (
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// clientSecret is Keycloak's CredentialRepresentation as the client-secret
// endpoints emit it: two keys, and value absent when there is nothing to show.
//
// Measured 2026-08-23. Every one of the six clients the master realm
// bootstraps answers {"type":"secret"} with no value, which is why the client
// representation recorded in P2 never carried a secret and why an absent value
// has to be a normal 200 rather than a 404.
type clientSecret struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// readClientSecret serves GET /admin/realms/{realm}/clients/{client-uuid}/client-secret.
//
// Measured: 200 with Cache-Control: no-cache, and view-clients is enough -
// reading a secret needs no more than reading the client it belongs to.
func (h *handler) readClientSecret(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	writeAdminJSON(w, clientSecret{Type: "secret", Value: client.Secret})
}

// regenerateClientSecret serves POST .../client-secret.
//
// Measured: 200 carrying the new secret and, unlike the GET on the same path,
// **no Cache-Control** - which is why this does not go through writeAdminJSON.
//
// Also measured: a public client is not refused. It gets a secret, and its own
// representation goes on hiding it, so the two endpoints disagree about the
// same client on purpose. Refusing here would be the tidier API and the wrong
// one.
//
// Unmeasured: whether Keycloak refreshes the client.secret.creation.time
// attribute here. It is left alone rather than guessed at.
func (h *handler) regenerateClientSecret(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	client.Secret = model.NewSecret()
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, clientSecret{Type: "secret", Value: client.Secret})
}

// readRotatedSecret serves GET .../client-secret/rotated.
//
// The constant 404 is the whole contract, not a stub. Measured on a default
// 26.7.1: CLIENT_SECRET_ROTATION is reported by /admin/serverinfo as a preview
// feature with enabled false, and secret-rotation is not among the 35
// registered client-policy-executor providers - a client profile naming it is
// rejected. No client on this distribution can hold a rotated secret, so the
// 200 shape is not merely unmeasured but unmeasurable.
//
// The client lookup still runs. An unknown UUID answers a different 404,
// "Could not find client", and collapsing the two would lose the distinction.
func (h *handler) readRotatedSecret(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.clientFromPath(w, r, rc); !ok {
		return
	}
	httpx.WriteMessageError(w, http.StatusNotFound, "Client does not have a rotated secret")
}

// deleteRotatedSecret serves DELETE .../client-secret/rotated.
//
// Measured: 204 whether or not anything was rotated - it is idempotent - with
// no Cache-Control, unlike the client delete beside it.
//
// The 500 this route answers a caller lacking manage-clients is not here; see
// deleteRotatedSecretRejection and where register wires it.
func (h *handler) deleteRotatedSecret(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.clientFromPath(w, r, rc); !ok {
		return
	}
	httpx.WriteNoContentAfterDelete(w)
}

// deleteRotatedSecretRejection is what this one route answers a caller who
// lacks its role, in place of the 403 every other admin route answers.
//
// This is a Keycloak defect and it is reproduced deliberately. Measured
// 2026-08-23 with two different callers, three times: the response is 500 with
// {"error":"unknown_error","error_description":"For more on this error consult
// the server log."} and the server log shows a NullPointerException in
// Keycloak's own error handler, raised while formatting the ForbiddenException
// it had just caught.
//
// Answering 403 here would be the correct HTTP and an observable difference
// from Keycloak, which is the one thing this project cannot afford. It carries
// X-Frame-Options, unlike the 204 on the same path.
func deleteRotatedSecretRejection(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}
