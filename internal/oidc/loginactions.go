package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/auth"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/token"
)

// The messages the re-served login page carries. All three are measured; the
// bodies Gloak serves are still placeholders, so these decide the branch rather
// than the bytes - the same arrangement F67 records for the logout pages.
const (
	// msgInvalidCredentials is the answer to every credential failure: a wrong
	// password, an unknown username, an empty username, an empty password, and a
	// POST with no form fields at all. Measured on all six - reporting them
	// differently would turn the login form into an account-enumeration oracle,
	// and Keycloak does not.
	msgInvalidCredentials = "Invalid username or password."
	// msgAccountDisabled is the one credential outcome that differs, and it is
	// only reached once the password has already verified.
	msgAccountDisabled = "Account is disabled, contact your administrator."
)

// loginActionCacheControl is what every response from this endpoint carries -
// the 302s, the re-served login page, the "Page has expired" page and all three
// 400 pages alike.
//
// It is the **third** value the theme error page has been measured with, and
// the three were taken side by side on one container on 2026-08-30:
//
//	GET  /auth                        400 and 403 pages   no Cache-Control at all
//	GET  /logout                      400 page            no-cache
//	POST /login-actions/authenticate  400 pages           no-store, must-revalidate, max-age=0
//
// One page, three endpoints, three answers. That is why WriteThemeErrorPage
// takes the value as an argument instead of choosing one.
const loginActionCacheControl = "no-store, must-revalidate, max-age=0"

// loginActions serves GET and POST /realms/{realm}/login-actions/authenticate.
//
// **It reads its five parameters from the query string and its credentials from
// the request body**, and that is measured rather than conventional: putting all
// five parameters in the body with an empty query answers the 400 client page,
// and putting only session_code in the body answers as though none had been
// sent. It is the exact mirror of /auth, which on a POST reads the body and
// ignores the query. One flow, two endpoints, opposite rules - so r.Form, which
// merges the two, is never consulted here.
//
// GET is registered because Keycloak answers it, and it answers it by
// *attempting the login*: a GET with the right parameters and no body re-serves
// the page with "Invalid username or password." and a rotated session_code,
// exactly as a POST with empty credentials does. It is not a read. That falls
// out of reading the credentials from PostForm, which a GET leaves empty.
//
// The check order below is measured with paired faults, one pair per adjacency;
// see section 1.5 of docs/superpowers/plans/2026-08-30-p13-login.md.
func (h *handler) loginActions(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	q := r.URL.Query()

	// Step 1. client_data is parsed before anything else, including before the
	// cookies and before the client. Measured: "no client_id + bad client_data"
	// and "bad client_data + no cookies" both answer about client_data.
	if !validClientData(q.Get("client_data")) {
		h.writeLoginActionErrorPage(w)
		return
	}

	// Step 2. The authentication session. A request that cannot reach one takes
	// the three-way branch rather than being told what was wrong with it.
	tab, sess, ok := h.resolveAuthTab(r, realm, q)
	if !ok {
		h.writeUnusableSession(w, r, realm, q)
		return
	}

	// Step 3. The client has to resolve **and be the tab's own**. Measured: a
	// request naming a different real client answers the same 400 page an
	// unknown one does, so this is not only a lookup.
	client, ok := h.resolveAuthClient(r, realm, q.Get("client_id"))
	if !ok || client.ClientID != tab.ClientID {
		h.writeLoginActionErrorPage(w)
		return
	}

	// A tab with no session code has not been asked for credentials yet: this is
	// the restart landing and the "no session_code" case, both measured 200 with
	// the login page. It is checked after the client so that a landing naming
	// the wrong client is still the client page.
	if q.Get("session_code") == "" {
		h.serveLoginPage(w, realm, sess, tab, tab.Username, "")
		return
	}

	// Step 4. The execution. An absent or unknown one is a 200 "Page has
	// expired" - not a 400, and not the login page. Measured after the session
	// code and before the credentials: a bad execution with a wrong password
	// answers about the execution.
	if q.Get("execution") != executionID(realm.ID) {
		httpx.WriteThemePage(w, http.StatusOK, loginActionCacheControl, httpx.ExpiredPageTitle)
		return
	}

	// Step 5. The credentials, from the body alone.
	h.attemptLogin(w, r, realm, client, sess, tab)
}

// resolveAuthTab finds the tab a request names, insisting on the cookie, the
// tab id and - when one was sent - the session code.
//
// A **missing** session code is not a failure here: it is the restart landing,
// which the caller serves as a login page. A **wrong or expired** one is,
// because an expired session code and a replayed one are measured to take the
// identical branch.
func (h *handler) resolveAuthTab(r *http.Request, realm *model.Realm, q url.Values) (*authTab, *authSession, bool) {
	cookie, err := r.Cookie(authSessionCookie)
	if err != nil {
		return nil, nil, false
	}
	sess, ok := h.auth.sessionByCookie(realm.Name, cookie.Value)
	if !ok {
		return nil, nil, false
	}
	tabID := q.Get("tab_id")
	if code := q.Get("session_code"); code != "" {
		tab, ok := h.auth.tabByCode(sess, tabID, code)
		return tab, sess, ok
	}
	tab, ok := h.auth.tabByID(sess, tabID)
	return tab, sess, ok
}

// writeUnusableSession is the three-way branch a request takes when its
// authentication session cannot be used - a spent session code, an expired one,
// a tab that is not there, or no cookie at all.
//
// Measured 2026-08-30 as a clean grid: the code was spent by completing a login
// and the three cookies were then varied independently, eight combinations,
// and the answer depends on exactly two of them.
//
//	KC_RESTART present            -> 302 restart, whatever else is sent
//	else KEYCLOAK_IDENTITY present -> 302 to the client, temporarily_unavailable
//	else                          -> 400 page, "Restart login cookie not found"
//
// **An empty KC_RESTART counts as absent**, and that is what makes the middle
// branch reachable in practice: the successful login clears the cookie with
// Max-Age=0, so the browser that replays sends `KC_RESTART=` and gets the
// client redirect. The observed document records only that middle branch, and
// records it unconditioned; a client that still holds its KC_RESTART restarts
// and does re-serve the login page.
func (h *handler) writeUnusableSession(w http.ResponseWriter, r *http.Request, realm *model.Realm, q url.Values) {
	if rec, ok := h.restartRecord(r, realm); ok {
		h.writeRestartRedirect(w, r, realm, rec, q)
		return
	}
	if _, err := r.Cookie(identityCookie); err == nil {
		if h.writeExpiredAuthentication(w, r, realm, q) {
			return
		}
	}
	// Nothing to restart from and nobody to tell. Measured: 400, the theme error
	// page, "Restart login cookie not found. It may have expired; ...".
	h.writeLoginActionErrorPage(w)
}

// restartRecord reads KC_RESTART and resolves what it points at.
func (h *handler) restartRecord(r *http.Request, realm *model.Realm) (*restartRecord, bool) {
	cookie, err := r.Cookie(restartCookie)
	if err != nil {
		return nil, false
	}
	return h.auth.restartByCookie(realm.Name, cookie.Value)
}

// writeRestartRedirect starts the login again from the KC_RESTART record.
//
// Measured, the 302 goes to this endpoint's own path carrying client_id, a
// **freshly minted tab_id** and client_data, with no session_code - and
// following it serves the login page. So the restart is a real round trip
// rather than an internal jump, and the new tab has to exist before the
// redirect is written or the landing request would find nothing.
//
// The client is resolved from the **query**, not from the record, and that is
// measured: a spent session code with no client_id answers the 400 client page
// where the same request with no cookies at all answers the restart-cookie
// page. So the restart needs the client_id the request carried.
func (h *handler) writeRestartRedirect(w http.ResponseWriter, r *http.Request, realm *model.Realm, rec *restartRecord, q url.Values) {
	client, ok := h.resolveAuthClient(r, realm, q.Get("client_id"))
	if !ok {
		h.writeLoginActionErrorPage(w)
		return
	}
	tab := &authTab{
		ClientID:            client.ClientID,
		ClientUUID:          client.ID,
		RedirectURI:         rec.RedirectURI,
		ResponseMode:        rec.ResponseMode,
		State:               rec.State,
		HasState:            rec.HasState,
		Scope:               rec.Scope,
		Nonce:               rec.Nonce,
		CodeChallenge:       rec.CodeChallenge,
		CodeChallengeMethod: rec.CodeChallengeMethod,
		DeviceUserCode:      rec.DeviceUserCode,
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	sess, err := h.beginAuthSession(w, r, realm, k, tab, nil)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data, err := encodeClientData(rec.RedirectURI, responseTypeCode, rec.ResponseMode, rec.State, rec.HasState)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	_ = sess
	// The measured key order is client_id, tab_id, client_data, and there is no
	// session_code: the landing request is what mints one.
	location := h.realmBase(realm.Name) + "/login-actions/authenticate?" + strings.Join([]string{
		"client_id=" + url.QueryEscape(client.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&")
	httpx.WriteLoginActionRedirect(w, location)
}

// writeExpiredAuthentication tells the client its login expired, which is what a
// browser holding a live KEYCLOAK_IDENTITY and no KC_RESTART is answered.
//
// The parameters are measured: error=temporarily_unavailable,
// error_description=authentication_expired, then state when one was sent, then
// iss - the same four keys and the same order /auth's rejections use. It
// reports false when it cannot address the client, so the caller falls through
// to the page rather than inventing a redirect.
func (h *handler) writeExpiredAuthentication(w http.ResponseWriter, r *http.Request, realm *model.Realm, q url.Values) bool {
	client, ok := h.resolveAuthClient(r, realm, q.Get("client_id"))
	if !ok {
		return false
	}
	redirectURI, state, hasState, ok := clientDataTarget(q.Get("client_data"), client)
	if !ok {
		return false
	}
	httpx.WriteLoginActionRedirect(w, h.authorizationErrorLocation(realm.Name, redirectURI,
		defaultResponseMode(q, responseTypeCode), authErrTemporarilyUnavailable,
		descAuthenticationExpired, state, hasState))
	return true
}

// clientDataTarget is the one place client_data is read for anything, and it is
// read only after the authentication session is already gone.
//
// Everywhere else client_data is measured to be **parsed and ignored**: one
// naming another redirect URI still redirects to the registered one, one naming
// another state still echoes the original, and one adding rm=fragment still
// puts the parameters in the query. Here the authentication session that held
// those values has been destroyed, so the browser's own copy is all there is -
// and it is still checked against the client's registered patterns before
// anything is sent to it, so a forged client_data cannot redirect a user
// anywhere the client could not have asked for itself.
func clientDataTarget(raw string, client *model.Client) (redirectURI, state string, hasState, ok bool) {
	cd, err := decodeClientData(raw)
	if err != nil {
		return "", "", false, false
	}
	if !matchRedirectURI(client.RedirectURIs, cd.RedirectURI) {
		return "", "", false, false
	}
	if cd.State != nil {
		return cd.RedirectURI, *cd.State, true, true
	}
	return cd.RedirectURI, "", false, true
}

// attemptLogin is the credential check and everything a success sets in motion.
func (h *handler) attemptLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab) {
	if err := r.ParseForm(); err != nil {
		h.writeLoginActionErrorPage(w)
		return
	}
	// PostForm, not Form: a GET's parameters must not become its credentials,
	// and a POST's query must not either.
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	user, message := h.verifyLoginCredentials(r, realm, username, password)
	if user == nil {
		// Measured: a failed credential re-serves the login page with a rotated
		// session_code while execution, tab_id and client_data stay the same,
		// and the retry with the rotated code succeeds.
		h.serveLoginPage(w, realm, sess, tab, username, message)
		return
	}

	// The user goes on the tab before anything is established, because the
	// consent page is a second request and the session does not exist until it
	// comes back. Measured: the 302 to the consent page sets no cookies at all.
	tab.UserID = user.ID
	if h.consentNeeded(realm, client, user, parsePrompt(tab.Prompt)) {
		h.writeRequiredActionRedirect(w, realm, client, tab)
		return
	}

	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	if err := h.finishFlow(w, r, realm, client, sess, tab, user, k); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
	}
}

// verifyLoginCredentials returns the user, or nil and the message the re-served
// page carries.
//
// Every way of failing to present a password answers the same measured
// "Invalid username or password.": a wrong password, an unknown username, an
// empty or absent username, an empty or absent password, and a request with no
// form fields at all. Only a **disabled** user differs, and only after the
// password has verified - so the disabled message is not an enumeration oracle
// either.
//
// The username is folded to lower case before the lookup. Measured: `ADMIN`
// logs in, and Gloak already lowercases a username on create.
func (h *handler) verifyLoginCredentials(r *http.Request, realm *model.Realm, username, password string) (*model.User, string) {
	if username == "" || password == "" {
		return nil, msgInvalidCredentials
	}
	user, err := h.store.Users().ByUsername(r.Context(), realm.ID, strings.ToLower(username))
	if err != nil {
		return nil, msgInvalidCredentials
	}
	cred, err := h.store.Users().CredentialByUser(r.Context(), user.ID, passwordCredentialType)
	if err != nil {
		return nil, msgInvalidCredentials
	}
	// A credential this build cannot evaluate is answered as a failed login
	// rather than as the 500 passwordGrant gives it, and the difference is
	// deliberate: this endpoint's login failure is measured and its 500 page is
	// not. Guessing a server-error page here would be inventing a response.
	if err := auth.VerifyPassword(cred, password); err != nil {
		return nil, msgInvalidCredentials
	}
	if !user.Enabled {
		return nil, msgAccountDisabled
	}
	return user, ""
}

// completeLogin establishes the session, mints the code and writes the redirect.
//
// **The user session takes the authentication session's root id**, which is the
// single most load-bearing measurement in this flow. On a live login the same
// 24-character value appears in four places at once: inside AUTH_SESSION_ID,
// as the redirect's session_state, as KEYCLOAK_IDENTITY's sid, and as the
// authorization code's second part. Minting a fresh id here would get all four
// wrong together.
func (h *handler) completeLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User, k *keys.RealmKeys) error {
	// The granted scope follows the authorization request, not a constant.
	// Measured: a login asking scope=openid produces a token response whose
	// scope is "openid profile email" and which carries an id_token, and one
	// asking for none produces neither the word nor the token.
	scope := grantedScope(tab.Scope)
	session, err := h.startSessionWithID(r.Context(), sess.RootID, realm, client, user, scope)
	if err != nil {
		return err
	}
	code, err := h.auth.newCode(&authCode{
		Realm:               realm.Name,
		ClientUUID:          client.ID,
		RedirectURI:         tab.RedirectURI,
		UserID:              user.ID,
		SessionID:           session.ID,
		Scope:               scope,
		Nonce:               tab.Nonce,
		CodeChallenge:       tab.CodeChallenge,
		CodeChallengeMethod: tab.CodeChallengeMethod,
	})
	if err != nil {
		return err
	}
	// The authentication session is gone the moment the login completes, which
	// is what makes a replayed session_code unusable: there is nothing left to
	// replay it against.
	h.auth.endSession(sess.RootID)

	clearRestartCookie(w, realm)
	if err := h.setLoginCookies(w, realm, k, session.ID, user); err != nil {
		return err
	}
	httpx.WriteLoginActionRedirect(w, h.authorizationCodeLocation(realm.Name, tab, session.ID, code))
	return nil
}

// clearRestartCookie is the Max-Age=0 KC_RESTART an **interactive** login ends
// with, and it is separate from setLoginCookies because the SSO redirect does
// not send it.
//
// Measured on three endings side by side. The credential POST and the consent
// accept both send KC_RESTART cleared, KEYCLOAK_IDENTITY, KEYCLOAK_SESSION; the
// SSO redirect sends KC_RESTART with a **real value** and the same two after it.
// Folding the clear into setLoginCookies is the saving that makes the SSO
// redirect set KC_RESTART twice, once each way.
//
// The clear carries neither Secure nor HttpOnly where the cookie it clears
// carries both - measured, and the sort of asymmetry that looks like an
// oversight and is the contract.
func clearRestartCookie(w http.ResponseWriter, realm *model.Realm) {
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: restartCookie, Path: realmCookiePath(realm.Name), MaxAge: 0, SetMaxAge: true,
	})
}

// setLoginCookies writes KEYCLOAK_IDENTITY and then KEYCLOAK_SESSION, the pair
// that makes a browser recognisable afterwards.
//
// It takes the **session id** rather than the authentication session, because
// three callers write this pair and only one of them has an authentication
// session to hand: the credential POST, the consent accept and the SSO
// redirect. All three were measured writing the identical two.
func (h *handler) setLoginCookies(w http.ResponseWriter, realm *model.Realm, k *keys.RealmKeys,
	sessionID string, user *model.User) error {
	path := realmCookiePath(realm.Name)
	stateChecker, err := randomBase64URL(rootIDBytes)
	if err != nil {
		return err
	}
	identity, err := token.IssueIdentityCookie(k, h.realmIssuer(realm.Name), user.ID,
		sessionID, model.NewID(), stateChecker, time.Now())
	if err != nil {
		return err
	}
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: identityCookie, Value: identity, Path: path,
		Secure: true, HTTPOnly: true, SameSite: "None",
	})
	// KEYCLOAK_SESSION is KC_AUTH_SESSION_HASH's value in the other base64
	// alphabet, measured byte for byte on the pair of responses carrying both -
	// and it is derived from the session id rather than remembered, which is what
	// makes an SSO redirect re-emit the value the original login set.
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: sessionCookie, Value: keycloakSessionValue(sessionHash(k, sessionID)), Path: path,
		MaxAge: int(keycloakSessionMaxAge.Seconds()), SetMaxAge: true,
		Secure: true, SameSite: "None",
	})
	return nil
}

// authorizationCodeLocation builds the redirect that carries the code.
//
// The query key order is measured: state, session_state, iss, code - which is
// **not** the order the same four parameters take inside a form_post response,
// where they are code, iss, state, session_state. One response, two orderings,
// decided by the response mode. state is emitted only when the authorization
// request sent one, the same rule /auth's rejections follow.
//
// url.Values.Encode sorts by key, which is none of those orders, so the query
// is joined by hand here as it is in authorizationErrorLocation.
func (h *handler) authorizationCodeLocation(realm string, tab *authTab, sessionState, code string) string {
	parts := make([]string, 0, 4)
	if tab.HasState {
		parts = append(parts, "state="+url.QueryEscape(tab.State))
	}
	parts = append(parts,
		"session_state="+url.QueryEscape(sessionState),
		"iss="+url.QueryEscape(h.realmIssuer(realm)),
		"code="+url.QueryEscape(code))

	separator := "?"
	if tab.ResponseMode == "fragment" || tab.ResponseMode == "fragment.jwt" {
		separator = "#"
	}
	return tab.RedirectURI + separator + strings.Join(parts, "&")
}

// serveLoginPage renders the form, minting the tab a fresh session code.
//
// Every render mints one, which is what makes the measured rotation fall out
// rather than being a special case: the first render after /auth and the
// re-render after a wrong password both get a new code, and the old one stops
// working either way.
func (h *handler) serveLoginPage(w http.ResponseWriter, realm *model.Realm, sess *authSession,
	tab *authTab, username, message string) {
	code, err := h.auth.rotateSessionCode(sess, tab, username)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	action, err := h.loginActionURL(realm, tab, code)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteThemeLoginPage(w, action, username, message)
}

// loginActionURL is the form's action, and its five parameters are in the
// measured order: session_code, execution, client_id, tab_id, client_data.
func (h *handler) loginActionURL(realm *model.Realm, tab *authTab, sessionCode string) (string, error) {
	data, err := encodeClientData(tab.RedirectURI, responseTypeCode, tab.ResponseMode, tab.State, tab.HasState)
	if err != nil {
		return "", err
	}
	return h.realmBase(realm.Name) + "/login-actions/authenticate?" + strings.Join([]string{
		"session_code=" + url.QueryEscape(sessionCode),
		"execution=" + url.QueryEscape(executionID(realm.ID)),
		"client_id=" + url.QueryEscape(tab.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&"), nil
}

// writeLoginActionErrorPage is this endpoint's 400.
//
// All three of its measured spellings share one envelope and differ only in
// prose Gloak does not serve yet: "Invalid Request" for an unparseable
// client_data, "An error occurred, please login again through your
// application." for a client that does not resolve, and "Restart login cookie
// not found. ..." when there is nothing to restart from. The branch that was
// taken is guarded by internal/oidc's own tests; the prose is P13's later work,
// the same arrangement F67 records for the logout pages.
func (h *handler) writeLoginActionErrorPage(w http.ResponseWriter) {
	httpx.WriteThemeErrorPage(w, http.StatusBadRequest, loginActionCacheControl)
}

// startSessionWithID is startSession with the session id supplied rather than
// minted, which the browser login needs because its id was decided at GET /auth
// and is already in the browser's AUTH_SESSION_ID cookie.
func (h *handler) startSessionWithID(ctx context.Context, id string, realm *model.Realm,
	client *model.Client, user *model.User, scope string) (*model.UserSession, error) {
	now := time.Now().UnixMilli()
	session := &model.UserSession{
		ID:          id,
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
