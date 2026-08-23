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

// Grant types this endpoint dispatches on. Anything else is answered
// unsupported_grant_type; the authorization_code grant arrives with P3, which
// is what mints a code.
const (
	grantPassword          = "password"
	grantRefreshToken      = "refresh_token"
	grantClientCredentials = "client_credentials"
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
	switch grantType {
	case grantPassword, grantRefreshToken, grantClientCredentials:
	default:
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
	switch grantType {
	case grantPassword:
		h.passwordGrant(w, r, realm, client, k)
	case grantRefreshToken:
		h.refreshTokenGrant(w, r, realm, client, k)
	case grantClientCredentials:
		h.clientCredentialsGrant(w, r, realm, client, k)
	}
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

// refreshTokenGrant exchanges a refresh token for a fresh set.
//
// Every way this can fail - rubbish input, another realm's token, an expired
// one, a session that has since been revoked, a token minted for a different
// client - answers the same measured 400 invalid_grant "Invalid refresh
// token". See internal/conformance/testdata/golden/oidc/token/invalid-refresh-token.http.
func (h *handler) refreshTokenGrant(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	parsed, err := token.ParseRefresh(k, h.realmIssuer(realm.Name), r.PostForm.Get("refresh_token"), time.Now())
	if err != nil {
		writeInvalidRefreshToken(w)
		return
	}
	if parsed.ClientID != client.ClientID {
		writeInvalidRefreshToken(w)
		return
	}

	ctx := r.Context()
	session, err := h.store.Sessions().UserSessionByID(ctx, realm.ID, parsed.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvalidRefreshToken(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// The scope comes from the stored client session rather than from the
	// token: the refresh token's own scope claim is Keycloak's longer internal
	// list, not what this client was granted.
	clientSession, err := h.store.Sessions().ClientSession(ctx, session.ID, client.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvalidRefreshToken(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	user, err := h.store.Users().ByID(ctx, realm.ID, session.UserID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.store.Sessions().TouchUserSession(ctx, session.ID, time.Now().UnixMilli()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeInvalidRefreshToken(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// refresh_expires_in on a refresh response is bounded by the remaining SSO
	// session lifetime rather than purely by the configured lifespan - noted in
	// the "Token endpoint response" section of the observed-behaviour document
	// as the weakest of the unmasked duration values. The recorded golden
	// agrees with the configured 1800 because the session is seconds old there.
	h.writeTokens(w, realm, client, user, session, clientSession.Scope, k)
}

func writeInvalidRefreshToken(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
}

// clientCredentialsGrant issues a token for a client acting on its own behalf.
//
// **The response shape here is unmeasured.** No client on a bootstrapped
// master realm has a service account, so oidc/token/client-credentials-grant
// has no golden and stays Pending; whoever first creates such a client -
// which is P2, where client management lives - has to record it and correct
// this. What is asserted today is only who may use the grant, in
// internal/oidc/token_test.go.
func (h *handler) clientCredentialsGrant(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	if client.PublicClient || !client.ServiceAccountsEnabled {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			"unauthorized_client", "Client not enabled to retrieve service account")
		return
	}
	user, err := h.serviceAccountUser(r.Context(), realm, client)
	if err != nil {
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

// serviceAccountUser returns the account a client acts as, creating it on
// first use.
//
// The username was P1's guess and P2 measured it - see
// model.ServiceAccountUsername - so the convention is now contract rather than
// convention. What P2 also measured is that Keycloak provisions the account
// when the client is created, not when the first grant arrives, so
// internal/admin does that eagerly.
//
// This path stays because it covers every client that was never created
// through the admin API: the six bootstrap makes, and every client a test
// builds straight through the store.
func (h *handler) serviceAccountUser(ctx context.Context, realm *model.Realm, client *model.Client) (*model.User, error) {
	username := model.ServiceAccountUsername(client.ClientID)
	user, err := h.store.Users().ByUsername(ctx, realm.ID, username)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	user = &model.User{
		ID:               model.NewID(),
		RealmID:          realm.ID,
		Username:         username,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := h.store.Users().Create(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return h.store.Users().ByUsername(ctx, realm.ID, username)
		}
		return nil, err
	}
	return user, nil
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
