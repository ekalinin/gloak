package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
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
// unsupported_grant_type.
const (
	grantPassword          = "password"
	grantRefreshToken      = "refresh_token"
	grantClientCredentials = "client_credentials"
	grantAuthorizationCode = "authorization_code"
)

// The authorization_code grant's measured answers, in the order they are
// reached. Measured 2026-08-30 against a live 26.7.1 by driving two faults at
// once, one pair per adjacency:
//
//  1. grant_type absent      Missing form parameter: grant_type   (above)
//  2. grant_type unknown     Unsupported grant_type               (above)
//  3. client authentication  401, and it does **not** spend the code
//  4. a duplicated form key  duplicated parameter
//  5. code absent            Missing parameter: code
//  6. code not redeemable    Code not valid
//  7. redirect_uri           Incorrect redirect_uri
//  8. the code's own client  Auth error: Found different client_id in clientSession
//  9. PKCE, four answers
//
// Two of those are not where they look. **The redirect URI is compared before
// the client is**: another client redeeming a code with a wrong redirect_uri
// answers about the redirect_uri, so step 7 cannot be folded into step 8 as "is
// this caller allowed this code". And **the duplicated-parameter check is
// fourth**, after client authentication - zz twice with an unknown client_id is
// the 401, and zz twice with a valid client and no code is the duplicate.
//
// Everything from step 6 onwards spends the code; step 3 does not, because the
// code has not been looked at yet. See docs/superpowers/plans/2026-08-30-p3-code-grant.md
// section 1.
const (
	descMissingCode        = "Missing parameter: code"
	descCodeNotValid       = "Code not valid"
	descIncorrectRedirect  = "Incorrect redirect_uri"
	descDifferentClient    = "Auth error: Found different client_id in clientSession"
	descVerifierMissing    = "PKCE code verifier not specified"
	descVerifierUnexpected = "PKCE code verifier specified but challenge not present in authorization"
	descVerifierMalformed  = "PKCE verification failed: Invalid code verifier"
	descVerifierMismatch   = "PKCE verification failed: Code mismatch"
)

// The direct grant's two refusals of an account that authenticated correctly.
// Both are invalid_grant with a 400, both are measured after the password, and
// descAccountDisabled outranks descAccountNotSetUp on a user that is both.
const (
	descAccountDisabled = "Account disabled"
	descAccountNotSetUp = "Account is not fully set up"
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
//
// refresh_token and session_state carry omitempty for the same reason, added
// once the client_credentials grant was measured: that grant's body has
// neither key. **refresh_expires_in does not**, because that grant sends it
// as 0 rather than dropping it - two absences and a zero, in one body.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state,omitempty"`
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
	case grantPassword, grantRefreshToken, grantClientCredentials, grantAuthorizationCode,
		grantDeviceCode, grantCIBA:
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
	// A repeated form key is this endpoint's error too, with the authorization
	// endpoint's lower-case spelling and its "any key, even one nobody reads"
	// rule - zz twice is enough and so is grant_type twice.
	//
	// Two things about it are this endpoint's own. It reads the **body** and not
	// the query: zz twice on the query of a valid password grant is a 200, one
	// in each is a 200, and both in the body is this 400. And it runs **after**
	// client authentication, where /auth's runs seventh: zz twice with an
	// unknown client_id is the 401, and zz twice with a valid client and a wrong
	// password is this. Measured 2026-08-30 on all six pairs.
	if hasDuplicate(r.PostForm) {
		httpx.WriteOAuthError(w, http.StatusBadRequest,
			authErrInvalidRequest, descDuplicatedParameter)
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
	case grantAuthorizationCode:
		h.authorizationCodeGrant(w, r, realm, client, k)
	case grantDeviceCode:
		h.deviceCodeGrant(w, r, realm, client, k)
	case grantCIBA:
		// No keys are needed: every answer a default deployment can give to
		// this grant is a refusal. See internal/oidc/ciba.go.
		h.cibaGrant(w, r, client)
	}
}

// authorizationCodeGrant redeems a code the browser flow minted.
//
// The check order is the measured one and the two surprises in it are recorded
// on the constant block above. What is worth repeating here is that
// **spendCode is called before any of the code's contents are judged**: a
// failed exchange spends the code, measured on four different failures, so the
// retry after a wrong redirect_uri, a wrong client, a missing verifier or a
// mismatched one all answer "Code not valid" rather than repeating themselves.
// The one failure that does not spend it is client authentication, and that
// falls out of it happening in token() above rather than being a special case.
func (h *handler) authorizationCodeGrant(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, client *model.Client, k *keys.RealmKeys) {
	// Presence, not value. An empty code= answers "Code not valid" - it reaches
	// the lookup - where an absent one answers about the parameter.
	if _, present := r.PostForm["code"]; !present {
		httpx.WriteOAuthError(w, http.StatusBadRequest, authErrInvalidRequest, descMissingCode)
		return
	}
	code, ok := h.auth.spendCode(realm.Name, r.PostForm.Get("code"))
	if !ok {
		writeCodeNotValid(w)
		return
	}
	// The redirect URI is compared against what the authorization request
	// stored, never against the client's registered patterns: a code minted for
	// one registered URI and redeemed naming another registered one is refused.
	// An absent redirect_uri compares unequal rather than being caught by a
	// presence check, which is why this is not "Missing parameter".
	if r.PostForm.Get("redirect_uri") != code.RedirectURI {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descIncorrectRedirect)
		return
	}
	if code.ClientUUID != client.ID {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descDifferentClient)
		return
	}
	if desc, bad := checkCodeVerifier(code, r.PostForm); bad {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", desc)
		return
	}

	ctx := r.Context()
	session, err := h.store.Sessions().UserSessionByID(ctx, realm.ID, code.SessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Measured: deleting the user session between the login and the
			// exchange makes the code answer "Code not valid", not a session
			// error. The code is only redeemable while its session lives.
			writeCodeNotValid(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	user, err := h.store.Users().ByID(ctx, realm.ID, code.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeCodeNotValid(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// auth_time is when the user authenticated, which for this grant is when the
	// session started - measured as iat - auth_time == 6 on a login left six
	// seconds before the exchange, so issuing time is the wrong value.
	authTime := time.UnixMilli(session.StartedAt)
	h.writeTokens(w, r, realm, client, user, session, code.Scope, k, false, authTime, code.Nonce)
}

func writeCodeNotValid(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descCodeNotValid)
}

// checkCodeVerifier is the PKCE half of the redemption, and it is four answers
// rather than one.
//
// Measured 2026-08-30 over the whole grid. An absent verifier against a stored
// challenge and a present verifier against no challenge are two different
// errors, and both are different from a mismatch. **An empty code_verifier= is
// "Invalid code verifier", not "not specified"** - so the absence check is on
// the parameter and the shape check catches the empty string.
//
// The shape is RFC 7636's code_verifier production, measured at both bounds and
// on the alphabet: 42 characters and 129 characters are both "Invalid code
// verifier", 128 reaches the comparison and answers "Code mismatch", and 43 "!"
// characters are invalid.
//
// A stored method of "" means the request sent a challenge and no method, which
// is measured to default to plain - the same default checkPKCE records at the
// authorization endpoint.
func checkCodeVerifier(code *authCode, form url.Values) (string, bool) {
	verifier, present := form["code_verifier"]
	if code.CodeChallenge == "" {
		if present {
			return descVerifierUnexpected, true
		}
		return "", false
	}
	if !present {
		return descVerifierMissing, true
	}
	// RFC 7636 gives the verifier and the challenge the same production, and
	// both halves are measured to enforce it, so validCodeChallenge is reused
	// rather than copied.
	if !validCodeChallenge(verifier[0]) {
		return descVerifierMalformed, true
	}
	if codeChallengeFor(verifier[0], code.CodeChallengeMethod) != code.CodeChallenge {
		return descVerifierMismatch, true
	}
	return "", false
}

// codeChallengeFor is what a verifier hashes to under a method. S256 is the
// unpadded base64url of its SHA-256; plain, and an absent method, are the
// verifier itself.
func codeChallengeFor(verifier, method string) string {
	if method != "S256" {
		return verifier
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// passwordGrant is the Resource Owner Password Credentials grant.
//
// A missing user, a missing password credential and a wrong password all
// produce the identical measured 400 invalid_grant "Invalid user credentials".
// Reporting them differently would turn the endpoint into an
// account-enumeration oracle.
//
// **Two checks run after the password and neither did until 2026-08-31.**
// Measured on one container, one user at a time:
//
//	disabled user, right password        Account disabled
//	disabled user, wrong password        Invalid user credentials
//	requiredActions non-empty            Account is not fully set up
//	disabled and requiredActions both    Account disabled
//
// So `enabled` is not an early gate - it is checked after the credential, the
// same way the browser flow's "Account is disabled, contact your administrator."
// is - and Gloak answered "Invalid user credentials" for a disabled user until
// this was measured, from a check that ran before the password.
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
	if !user.Enabled {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descAccountDisabled)
		return
	}
	// **The direct grant reads requiredActions raw, where the browser flow
	// filters them.** It applies no enabled filter and asks no provider whether
	// there is anything to do: measured, a user carrying only the *disabled*
	// TERMS_AND_CONDITIONS completes the browser login and is refused here, and
	// so are delete_account, UPDATE_EMAIL, delete_credential, idp_link and
	// update_user_locale - seven aliases on which the two endpoints disagree
	// about one user. Sharing nextRequiredAction between them is the obvious
	// saving and it is wrong on every one of the seven.
	if len(user.RequiredActions) > 0 {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descAccountNotSetUp)
		return
	}

	scope := grantedScope(r.PostForm.Get("scope"))
	session, err := h.startSession(r.Context(), realm, client, user, scope)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeTokens(w, r, realm, client, user, session, scope, k, false, time.Time{}, "")
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
			// Measured 2026-08-23: a token that verifies but whose session is
			// gone answers "Session not active", not "Invalid refresh token".
			// Both an admin logout and a revocation produce it, and the
			// garbage-token case recorded in P1 still produces the other. Two
			// causes, two messages, one status.
			writeSessionNotActive(w)
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
	h.writeTokens(w, r, realm, client, user, session, clientSession.Scope, k, false, time.Time{}, "")
}

func writeInvalidRefreshToken(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
}

// writeSessionNotActive is what a *valid* refresh token whose session has been
// ended answers, as against writeInvalidRefreshToken for a token that never
// was one.
//
// Unmeasured, and left on the other message rather than guessed at: a token
// that has expired, and one minted for a different client.
func writeSessionNotActive(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Session not active")
}

// clientCredentialsGrant issues a token for a client acting on its own behalf.
//
// Measured 2026-08-23, once client management made a service-account client
// creatable: the response is three keys short of the other grants - no
// refresh_token, no session_state, no id_token - while refresh_expires_in is
// present and 0. See writeTokens, and the client-credentials-grant golden.
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
	h.writeTokens(w, r, realm, client, user, session, scope, k, true, time.Time{}, "")
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
//
// serviceAccount selects the client_credentials shape, which is measurably
// different in three places: no refresh_token, no session_state, and
// refresh_expires_in 0 rather than the realm's lifespan. The refresh token is
// not merely left out of the body - none is issued, so a service account
// session cannot be refreshed.
//
// authTime and nonce are the browser flow's and are the zero value for every
// other grant, which is what makes their claims absent there. **The refresh
// grant passes the zero auth time and Keycloak does not**: measured, refreshing
// a browser-login session keeps the original auth_time and refreshing a
// password-grant session has none, so auth_time belongs to the user session and
// Gloak has nowhere to keep it - model.UserSession is internal/model's. Filed
// rather than guessed.
func (h *handler) writeTokens(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, user *model.User, session *model.UserSession, scope string, k *keys.RealmKeys, serviceAccount bool, authTime time.Time, nonce string) {
	realmRoles, clientRoles, err := h.tokenRoles(r.Context(), realm, user)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	accessLife := accessLifespan(realm, client)
	issuer := &token.Issuer{Keys: k, Issuer: h.realmIssuer(realm.Name)}
	set, err := issuer.Issue(token.Request{
		Client:         client,
		User:           user,
		UserSession:    session,
		Scope:          scope,
		RealmRoles:     realmRoles,
		ClientRoles:    clientRoles,
		AccessLife:     accessLife,
		RefreshLife:    realm.RefreshTokenLifespan,
		IncludeIDToken: hasScope(scope, "openid"),
		AuthTime:       authTime,
		Nonce:          nonce,
	})
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	body := tokenResponse{
		AccessToken:      set.AccessToken,
		ExpiresIn:        int64(accessLife.Seconds()),
		RefreshExpiresIn: int64(realm.RefreshTokenLifespan.Seconds()),
		RefreshToken:     set.RefreshToken,
		TokenType:        "Bearer",
		IDToken:          set.IDToken,
		NotBeforePolicy:  0,
		SessionState:     session.ID,
		Scope:            scope,
	}
	if serviceAccount {
		body.RefreshToken = ""
		body.RefreshExpiresIn = 0
		body.SessionState = ""
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

// accessLifespan is the realm's access token lifespan unless the client
// shortens it.
//
// Measured 2026-08-23: setting the client attribute access.token.lifespan to
// "1" makes expires_in 1 and the token verifiably rejected a second later.
// Two neighbouring values were measured too and neither is reproduced here,
// because neither is a lifespan: "0" yields expires_in 0 with a token the
// server still accepts, and "-1" falls back to 36000 rather than to this
// realm's 60. See follow-up F19.
func accessLifespan(realm *model.Realm, c *model.Client) time.Duration {
	seconds, err := strconv.Atoi(c.Attributes["access.token.lifespan"])
	if err != nil || seconds <= 0 {
		return realm.AccessTokenLifespan
	}
	return time.Duration(seconds) * time.Second
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
