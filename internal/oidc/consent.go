package oidc

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
)

// The OAUTH_GRANT consent page and the endpoint its two buttons post to.
//
// Measured on 2026-08-30 against a live 26.7.1, container kc-browser on 8112,
// on two flows that reach the identical page: a `consentRequired` browser client
// and the device authorization grant. See section 1 of
// docs/superpowers/plans/2026-08-30-p13-sso-and-consent.md.

// executionOAuthGrant is the consent's `execution`, and it is the **last**
// member of the queue /login-actions/required-action serves rather than the only
// value it knows. Measured: a consentRequired client whose user carries
// UPDATE_PASSWORD is sent to execution=UPDATE_PASSWORD first, and the consent
// page follows the action rather than replacing it.
const executionOAuthGrant = "OAUTH_GRANT"

// requiredAction serves GET and POST /realms/{realm}/login-actions/required-action.
//
// **The session_code decides what the request is, and the verb decides
// nothing.** Measured 2026-08-31 as a twelve-cell grid on a live UPDATE_PASSWORD
// tab, GET and POST for each of six combinations, and the two verbs agree on
// every row:
//
//	session_code  execution   answer
//	present       matches     the action runs
//	present       mismatched  302 -> required-action?execution=<the tab's own>
//	present       absent      302 -> required-action?execution=<the tab's own>
//	absent        matches     200, the step's page
//	absent        mismatched  200, "Page has expired"
//	absent        absent      200, the step's page
//
// A GET carrying a session code therefore **submits**, with whatever the body
// holds - nothing, for a GET - which is the same rule
// GET /login-actions/authenticate already follows. A matrix that varied the verb
// alone would have found the two agreeing and concluded the verb was the
// variable.
//
// This replaces what this function did until 2026-08-31, which was to answer the
// 400 error page to any execution that was not exactly OAUTH_GRANT. Re-measured
// on a consent-only tab, `execution=BOGUS` is 200 "Page has expired" and an
// **absent** execution serves the consent page, so the old comment's "400, the
// theme error page, invalid_request" was wrong on five of the six rows. It is
// the reachable-in-one-request shape of the same mistake CIBA's parameter order
// caught: every probe behind it broke one thing at a time.
func (h *handler) requiredAction(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	// The body is decoded before anything this endpoint decides, so that a
	// submission whose form will not parse answers the measured 500 rather than
	// this endpoint's page. See decodeLoginActionBody.
	if !decodeLoginActionBody(w, r) {
		return
	}
	q := r.URL.Query()
	if !validClientData(q.Get("client_data")) {
		h.writeLoginActionErrorPage(w, h.loginActionChrome(r, realm, q), pageInvalidRequest)
		return
	}
	// The tab is resolved by its id alone, never by the session code, because a
	// stale code here is measured to re-issue the landing rather than to take
	// the restart branch. resolveAuthTab would consume the code and report the
	// tab missing.
	sess, tab, ok := h.resolveActionTab(r, realm, q)
	if !ok {
		h.writeUnusableSession(w, r, realm, q)
		return
	}
	client, ok := h.authClient(r, realm, q.Get("client_id"))
	if !ok || client.ClientID != tab.ClientID {
		h.writeLoginActionErrorPage(w, h.loginActionChrome(r, realm, q), pageLoginActionError)
		return
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, tab.UserID)
	if err != nil {
		// The tab reached this endpoint without a user on it, which only a
		// hand-made request can produce.
		h.writeUnusableSession(w, r, realm, q)
		return
	}
	step, err := h.tabStep(r.Context(), realm, client, user, tab)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	execution := q.Get("execution")
	code := q.Get("session_code")
	if code == "" {
		// A landing. An execution naming something this tab is not at is the
		// expired page; an absent one is served the step, which is why this is
		// not a presence check.
		if step == "" || (execution != "" && execution != step) {
			httpx.WriteThemePage(w, http.StatusOK, loginActionCacheControl, httpx.ExpiredPageTitle)
			return
		}
		h.serveStep(w, realm, sess, tab, client, user, step, "")
		return
	}
	if step == "" || execution != step || code != tab.SessionCode {
		// A submission that does not match what the tab is waiting for is sent
		// back to the landing for what it is waiting for - not refused, and not
		// answered the expired page, which is the landing's answer and not this
		// one's.
		h.writeRequiredActionRedirect(w, realm, client, tab, step)
		return
	}
	if step == executionOAuthGrant {
		// The consent has its own endpoint for its submission, and this one is
		// measured not to take it: the page's form posts to
		// /login-actions/consent.
		h.serveStep(w, realm, sess, tab, client, user, step, "")
		return
	}
	if !h.runStep(w, r, realm, client, sess, tab, user, step) {
		return
	}
	h.continueAfterStep(w, r, realm, client, sess, tab, user)
}

// resolveActionTab finds the tab by its id, without spending or checking the
// session code.
func (h *handler) resolveActionTab(r *http.Request, realm *model.Realm, q url.Values) (*authSession, *authTab, bool) {
	cookie, err := r.Cookie(authSessionCookie)
	if err != nil {
		return nil, nil, false
	}
	sess, ok := h.auth.sessionByCookie(realm.Name, cookie.Value)
	if !ok {
		return nil, nil, false
	}
	tab, ok := h.auth.tabByID(sess, q.Get("tab_id"))
	return sess, tab, ok
}

// continueAfterStep is what a completed required action answers, and it is two
// answers rather than one.
//
// Measured on a user carrying UPDATE_PROFILE and UPDATE_PASSWORD: submitting the
// profile answered **200 with the password page**, not a redirect to it. So the
// chain between two actions is served in place, and only the end of the queue
// redirects. A handler that answered a 302 for both would send a browser through
// an extra round trip Keycloak does not make.
func (h *handler) continueAfterStep(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User) {
	next, err := h.tabStep(r.Context(), realm, client, user, tab)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if next != "" {
		h.serveStep(w, realm, sess, tab, client, user, next, "")
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

// serveConsentPage renders the OAUTH_GRANT page, minting the tab a fresh
// session code the way every other render in this flow does.
//
// The `code` it renders is that session code, and the endpoint it posts to is
// measured **not to check it**. It is rendered anyway because Keycloak renders
// it, and because a page that omitted it would look like a page whose endpoint
// wanted one.
func (h *handler) serveConsentPage(w http.ResponseWriter, realm *model.Realm,
	sess *authSession, tab *authTab, client *model.Client) {
	code, err := h.auth.rotateSessionCode(sess, tab, tab.Username)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	data, err := tab.clientData()
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// Measured key order: client_id, tab_id, client_data - the required-action
	// redirect's own three minus the execution.
	action := h.realmBase(realm.Name) + "/login-actions/consent?" + strings.Join([]string{
		"client_id=" + url.QueryEscape(client.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&")
	httpx.WriteThemeConsentPage(w, action, client.ClientID, code)
}

// consent serves POST /realms/{realm}/login-actions/consent, the page's two
// buttons.
//
// **`cancel` decides and everything else is an approval**, which is measured
// rather than inferred and is the shape a reader would get backwards:
//
//	cancel alone              denied
//	accept and cancel both    denied - cancel wins
//	accept alone              granted
//	neither                   granted
//	accept with a wrong code  granted - the code is not checked
//	accept with no code       granted
//
// So the endpoint tests for `cancel` and treats the rest as consent. Requiring
// `accept` would refuse two requests Keycloak measurably accepts, and checking
// the `code` would refuse two more.
//
// **GET on this path is a 404**, not the page - measured
// `{"error":"HTTP 404 Not Found"}`, which is WithKeycloakFallbacks' own answer
// for a known path hit with the wrong method, so only POST is registered.
func (h *handler) consent(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	if !decodeLoginActionBody(w, r) {
		return
	}
	q := r.URL.Query()
	if !validClientData(q.Get("client_data")) {
		h.writeLoginActionErrorPage(w, h.loginActionChrome(r, realm, q), pageInvalidRequest)
		return
	}
	tab, sess, ok := h.resolveAuthTab(r, realm, q)
	if !ok {
		// Measured: a POST with no cookies at all answers the 400 page whose
		// instruction is "Restart login cookie not found. …", which is the same
		// three-way branch /login-actions/authenticate takes - and a replayed
		// accept takes its restart arm, a 302 back to the login action.
		h.writeUnusableSession(w, r, realm, q)
		return
	}
	client, ok := h.authClient(r, realm, q.Get("client_id"))
	if !ok || client.ClientID != tab.ClientID {
		h.writeLoginActionErrorPage(w, h.loginActionChrome(r, realm, q), pageLoginActionError)
		return
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, tab.UserID)
	if err != nil {
		// The tab reached the consent page without a user on it, which only a
		// hand-made request can produce. It is answered as an unusable session
		// rather than invented as a new page.
		h.writeUnusableSession(w, r, realm, q)
		return
	}

	if _, denied := r.PostForm["cancel"]; denied {
		h.denyConsent(w, r, realm, client, sess, tab)
		return
	}
	h.consents.grant(realm.ID, user.ID, client.ID)
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	if err := h.finishFlow(w, r, realm, client, sess, tab, user, k); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
	}
}

// denyConsent is the cancel button, and the two flows differ in where it sends
// the browser and agree on setting no cookies at all.
//
//	device      302 /realms/{realm}/device/status?error=access_denied
//	browser     302 <redirect_uri>?error=access_denied&state=…&iss=…
//
// The browser one carries **three keys and no error_description**, where the
// device grant's poll answers the same code with a sentence attached. One code,
// two endpoints, and only one of them explains itself.
//
// The authentication session is ended either way: measured, the request after a
// consent decision takes the restart branch, so there is nothing left to submit
// the page against.
func (h *handler) denyConsent(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab) {
	h.auth.endSession(sess.RootID)
	if tab.DeviceUserCode != "" {
		h.device.denyDeviceCode(tab.DeviceUserCode)
		httpx.WriteLoginActionRedirect(w, h.deviceStatusLocation(realm.Name, deviceErrAccessDenied))
		return
	}
	httpx.WriteLoginActionRedirect(w, h.authorizationErrorLocation(realm.Name, tab.RedirectURI,
		tab.ResponseMode, authErrAccessDenied, "", tab.State, tab.HasState))
}

// finishFlow is what a login that has cleared both the credentials and the
// consent does, and it is two endings rather than one.
//
// The device flow ends at /realms/{realm}/device/status with the device code
// approved; the browser flow ends at the client with an authorization code.
// Both set the identical three cookies - KC_RESTART cleared, KEYCLOAK_IDENTITY,
// KEYCLOAK_SESSION - which is measured on both and is why the cookie writer is
// shared and the redirect is not.
func (h *handler) finishFlow(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User, k *keys.RealmKeys) error {
	if tab.DeviceUserCode != "" {
		return h.completeDeviceApproval(w, r, realm, client, sess, tab, user, k)
	}
	return h.completeLogin(w, r, realm, client, sess, tab, user, k)
}

// writeRequiredActionRedirect is the 302 a login answers when the flow still
// wants something from the user - a required action or a consent.
//
// Measured on both flows and on both kinds of step: the key order is execution,
// client_id, tab_id, client_data, the location is **absolute**, and the response
// sets **no cookies at all** - the session cookies come later, from whatever
// finishes the flow. A handler that established the session here would set them
// one request early and would leave a signed-in browser behind an action that
// was never done.
//
// The alias is a parameter rather than the constant it was until 2026-08-31:
// UPDATE_PASSWORD, UPDATE_PROFILE and OAUTH_GRANT all travel through this one
// redirect, byte for byte alike apart from the value.
func (h *handler) writeRequiredActionRedirect(w http.ResponseWriter, realm *model.Realm,
	client *model.Client, tab *authTab, step string) {
	data, err := tab.clientData()
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteLoginActionRedirect(w, h.realmBase(realm.Name)+"/login-actions/required-action?"+strings.Join([]string{
		"execution=" + url.QueryEscape(step),
		"client_id=" + url.QueryEscape(client.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&"))
}
