package oidc

import (
	"net/http"
	"slices"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/token"
)

// inactive is the whole of the negative body: `{"active":false}` and nothing
// else. Measured, and the same bytes for a token that never was one, one whose
// session has ended, and one whose audience excludes the caller.
type inactive struct {
	Active bool `json:"active"`
}

// introspect serves POST /realms/{realm}/protocol/openid-connect/token/introspect.
//
// Two behaviours are measured about the request. A request with no client
// credentials answers 401 invalid_client, with **no** Cache-Control and no
// Pragma - unlike the token endpoint, which sends both on every response. And
// a *public* client is refused outright with 403 "Client not allowed.", the
// mirror image of revocation, which accepts one. See
// internal/conformance/testdata/golden/oidc/introspection/unauthenticated-client.http
// and the "Revocation accepts a public client; introspection does not" section
// of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func (h *handler) introspect(w http.ResponseWriter, r *http.Request) {
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
	if client.PublicClient {
		httpx.WriteOAuthError(w, http.StatusForbidden, "invalid_request", "Client not allowed.")
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	raw := r.PostForm.Get("token")
	issuer := h.realmIssuer(realm.Name)
	now := time.Now()
	parsed, err := token.ParseAccess(k, issuer, raw, now)
	if err != nil {
		if parsed, err = token.ParseRefresh(k, issuer, raw, now); err != nil {
			// RFC 7662: a token the server cannot validate is reported as
			// inactive rather than as an error.
			httpx.WriteJSON(w, http.StatusOK, inactive{})
			return
		}
	} else if !slices.Contains(parsed.Audience, client.ClientID) {
		// **An access token is refused when the caller is outside its aud**,
		// and a refresh token is not - measured 2026-08-23, and the check
		// applies only on the branch that parsed an access token for exactly
		// that reason.
		//
		// Since an access token's aud never names the client that asked for it
		// (see token.Audience), this makes introspecting one's own token
		// impossible, which is the contract rather than an accident of it.
		// Keycloak logs `reason="Client '...' is not in the token audience"`
		// and answers the ordinary inactive body, so the caller cannot tell
		// this apart from a token that expired.
		httpx.WriteJSON(w, http.StatusOK, inactive{})
		return
	}

	// A token whose session has been revoked is inactive even though it still
	// verifies: revocation deletes the session, not the signature.
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, inactive{})
		return
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, session.UserID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, inactive{})
		return
	}
	// The roles are resolved now rather than read out of the token. That is
	// what lets a refresh token - which carries none - introspect into the
	// access token's full claim set, and it is measured: the body reflects a
	// role assigned after the token was minted.
	realmRoles, clientRoles, err := h.tokenRoles(r.Context(), realm, user)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, token.Introspect(token.IntrospectionRequest{
		Parsed:      parsed,
		Issuer:      issuer,
		Username:    session.Username,
		Realm:       realmRoles,
		Clients:     clientRoles,
		EmailVerify: user.EmailVerified,
	}))
}
