package oidc

import (
	"net/http"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/token"
)

// introspectionDocument is the RFC 7662 response.
//
// The inactive body is measured and matches: `{"active":false}` alone. **The
// active body does not.** Keycloak was measured rebuilding the *access* token's
// whole claim set - realm_access, resource_access, acr, preferred_username -
// and appending client_id, username, token_type and active, nineteen keys with
// active last. This is nine keys with active first.
//
// Gloak cannot produce the measured shape until roles are resolved at
// issuance, which is follow-up F18; oidc/introspection/active-refresh-token is
// Recorded so the contract sits in the repository and the alarm fires when it
// starts matching.
//
// Also unimplemented and measured: Keycloak answers `{"active":false}` for an
// access token whose aud excludes the caller, which is every token a client
// asked for itself. Same follow-up.
type introspectionDocument struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Sid       string `json:"sid,omitempty"`
}

// introspect serves POST /realms/{realm}/protocol/openid-connect/token/introspect.
//
// Two behaviours are measured. A request with no client credentials answers
// 401 invalid_client, with **no** Cache-Control and no Pragma - unlike the
// token endpoint, which sends both on every response. And a *public* client is
// refused outright with 403 "Client not allowed.", the mirror image of
// revocation, which accepts one. See
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
			httpx.WriteJSON(w, http.StatusOK, introspectionDocument{Active: false})
			return
		}
	}
	// A token whose session has been revoked is inactive even though it still
	// verifies: revocation deletes the session, not the signature.
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, introspectionDocument{Active: false})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, introspectionDocument{
		Active:    true,
		Scope:     parsed.Scope,
		ClientID:  parsed.ClientID,
		Username:  session.Username,
		TokenType: parsed.Type,
		Exp:       parsed.ExpiresAt.Unix(),
		Iat:       parsed.IssuedAt.Unix(),
		Sub:       session.UserID,
		Iss:       issuer,
		Sid:       parsed.SessionID,
	})
}
