package oidc

import (
	"errors"
	"net/http"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// revoke serves POST /realms/{realm}/protocol/openid-connect/revoke.
//
// Three measured behaviours, all in
// internal/conformance/testdata/golden/oidc/revocation/:
//
//   - a public client may revoke. admin-cli does, successfully. This is the
//     opposite of introspection, which refuses public clients outright.
//   - an unparseable token answers **200** with an error body, not 400. A 200
//     carrying {"error":"invalid_token"} is not a mistake in the golden.
//   - the success answers 200 with an empty body, no Content-Type, and a
//     Content-Security-Policy header that no other recorded response carries.
func (h *handler) revoke(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}

	client, authErr := h.authenticateClient(r.Context(), realm, r.PostForm, r.Header)
	if authErr != nil {
		authErr.write(w)
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	session := h.sessionBehindToken(r, realm, client, k)
	if session == nil {
		// Measured: 200, not 400. The client asked for the token to stop
		// working and it does not work, so the request succeeded even though
		// the token was never valid.
		httpx.WriteJSON(w, http.StatusOK, oauthErrorBody{
			Error:            "invalid_token",
			ErrorDescription: "Invalid token",
		})
		return
	}

	if err := h.store.Sessions().DeleteUserSession(r.Context(), realm.ID, session.ID); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.SetContentSecurityPolicy(w)
	w.WriteHeader(http.StatusOK)
}

// oauthErrorBody is the RFC 6749 error shape emitted with a 200 status, which
// httpx.WriteOAuthError cannot express: it writes the body and the status
// together, and every other caller pairs this body with a 4xx.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// sessionBehindToken resolves the session a revocation request names, trying
// the token as a refresh token and then as an access token. It returns nil
// when the token is not this realm's, has expired, belongs to another client,
// or names a session that is already gone - all of which the caller answers
// the same way.
//
// token_type_hint is only a hint: RFC 7009 requires the endpoint to fall back
// to the other type, and the measured access-token case sends the hint while
// the refresh-token case does not.
func (h *handler) sessionBehindToken(r *http.Request, realm *model.Realm, client *model.Client, k *keys.RealmKeys) *model.UserSession {
	raw := r.PostForm.Get("token")
	if raw == "" {
		return nil
	}
	issuer := h.realmIssuer(realm.Name)
	now := time.Now()

	parsed, err := token.ParseRefresh(k, issuer, raw, now)
	if err != nil {
		if parsed, err = token.ParseAccess(k, issuer, raw, now); err != nil {
			return nil
		}
	}
	if parsed.ClientID != client.ClientID {
		return nil
	}
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		return nil
	}
	return session
}
