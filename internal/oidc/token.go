package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/auth"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// Grant types this endpoint dispatches on.
const (
	grantPassword = "password"
)

// defaultClientScopes is what a client grants when the request asks for no
// scope. Measured on the admin-cli password grant, whose response carries
// scope "profile email" - see
// internal/conformance/testdata/golden/oidc/token/password-grant-admin-cli.http.
//
// It is a constant because client scopes are not modelled until P5. That
// sub-project replaces this with the realm's actual default scopes.
var defaultClientScopes = []string{"profile", "email"}

// passwordCredentialType is Keycloak's CredentialRepresentation.type for a
// password.
const passwordCredentialType = "password"

// tokenResponse is the token endpoint's success body, in the order Keycloak
// emits it - see the "Token endpoint response" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md and the
// password-grant-admin-cli golden.
//
// not-before-policy is spelled with hyphens. IDToken is omitted rather than
// emitted empty when the openid scope was not granted: the measured admin-cli
// password grant has no id_token key at all.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// token serves POST /realms/{realm}/protocol/openid-connect/token.
//
// The validation order is measured, not chosen. A request with a valid
// client_id but no grant_type answers "Missing form parameter: grant_type",
// and one with a valid client_id and an unrecognised grant_type answers
// "Unsupported grant_type" - so both checks run *before* client
// authentication. See the missing-grant-type and unknown-grant-type goldens.
func (h *handler) token(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}

	// Measured on every token endpoint response, success and failure alike.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	grantType := r.PostForm.Get("grant_type")
	if grantType == "" {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			"invalid_request", "Missing form parameter: grant_type")
		return
	}
	if grantType != grantPassword {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			"unsupported_grant_type", "Unsupported grant_type")
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
	h.passwordGrant(w, r, realm, client, k)
}

// passwordGrant is the Resource Owner Password Credentials grant.
//
// A missing user, a missing password credential and a wrong password all
// produce the identical measured 400 invalid_grant "Invalid user credentials".
// Reporting them differently would turn the endpoint into an
// account-enumeration oracle.
func (h *handler) passwordGrant(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	if !client.DirectAccessGrantsEnabled {
		// Unmeasured: no bootstrapped client reaches this branch, since
		// admin-cli is the only one with direct access grants and it has them
		// enabled. The RFC 6749 code for "this client may not use this grant"
		// is unauthorized_client; correct it when it is first recorded.
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			"unauthorized_client", "Client not allowed for direct access grants")
		return
	}

	user, err := h.store.Users().ByUsername(r.Context(), realm.ID, r.PostForm.Get("username"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvalidUserCredentials(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !user.Enabled {
		writeInvalidUserCredentials(w)
		return
	}
	cred, err := h.store.Users().CredentialByUser(r.Context(), user.ID, passwordCredentialType)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvalidUserCredentials(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := auth.VerifyPassword(cred, r.PostForm.Get("password")); err != nil {
		if errors.Is(err, auth.ErrInvalidCredential) {
			writeInvalidUserCredentials(w)
			return
		}
		// A credential this build cannot evaluate is a server problem, not a
		// failed login.
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	scope := grantedScope(r.PostForm.Get("scope"))
	session, err := h.startSession(r.Context(), realm, client, user, scope)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeTokens(w, realm, client, user, session, scope, k)
}

func writeInvalidUserCredentials(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid user credentials")
}

// startSession creates the SSO session and the client's participation in it.
// The session ID becomes both the token's sid and the response's
// session_state.
func (h *handler) startSession(ctx context.Context, realm *model.Realm, client *model.Client, user *model.User, scope string) (*model.UserSession, error) {
	now := time.Now().UnixMilli()
	session := &model.UserSession{
		ID:          model.NewID(),
		RealmID:     realm.ID,
		UserID:      user.ID,
		Username:    user.Username,
		StartedAt:   now,
		LastRefresh: now,
		ExpiresAt:   now + realm.RefreshTokenLifespan.Milliseconds(),
	}
	if err := h.store.Sessions().CreateUserSession(ctx, session); err != nil {
		return nil, err
	}
	clientSession := &model.ClientSession{
		ID:            model.NewID(),
		UserSessionID: session.ID,
		ClientID:      client.ID,
		Scope:         scope,
		StartedAt:     now,
	}
	if err := h.store.Sessions().CreateClientSession(ctx, clientSession); err != nil {
		return nil, err
	}
	return session, nil
}

// writeTokens issues a set for an established session and writes the measured
// response body.
func (h *handler) writeTokens(w http.ResponseWriter, realm *model.Realm, client *model.Client, user *model.User, session *model.UserSession, scope string, k *keys.RealmKeys) {
	issuer := &token.Issuer{Keys: k, Issuer: h.realmIssuer(realm.Name)}
	set, err := issuer.Issue(token.Request{
		Client:         client,
		User:           user,
		UserSession:    session,
		Scope:          scope,
		AccessLife:     realm.AccessTokenLifespan,
		RefreshLife:    realm.RefreshTokenLifespan,
		IncludeIDToken: hasScope(scope, "openid"),
	})
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tokenResponse{
		AccessToken:      set.AccessToken,
		ExpiresIn:        int64(realm.AccessTokenLifespan.Seconds()),
		RefreshExpiresIn: int64(realm.RefreshTokenLifespan.Seconds()),
		RefreshToken:     set.RefreshToken,
		TokenType:        "Bearer",
		IDToken:          set.IDToken,
		NotBeforePolicy:  0,
		SessionState:     session.ID,
		Scope:            scope,
	})
}

// realmIssuer is the iss claim and the audience of a refresh token.
func (h *handler) realmIssuer(realm string) string {
	return h.issuerBase + "/realms/" + realm
}

// grantedScope is what the client actually gets: the default client scopes,
// plus openid when it was asked for. Anything else a request names is dropped,
// since there is no client-scope model to check it against until P5.
func grantedScope(requested string) string {
	granted := make([]string, 0, len(defaultClientScopes)+1)
	if hasScope(requested, "openid") {
		granted = append(granted, "openid")
	}
	granted = append(granted, defaultClientScopes...)
	return strings.Join(granted, " ")
}

func hasScope(scope, want string) bool {
	for s := range strings.FieldsSeq(scope) {
		if s == want {
			return true
		}
	}
	return false
}
