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

// executionOAuthGrant is the one `execution` /login-actions/required-action is
// measured to answer. Anything else is a 400 page whose instruction is
// `invalid_request` - the same envelope the endpoint's other rejections use, and
// a value spelled in the OAuth style where every other instruction on these
// pages is prose.
const executionOAuthGrant = "OAUTH_GRANT"

// requiredAction serves GET /realms/{realm}/login-actions/required-action.
//
// It is reached by the 302 a completed login answers when the client still wants
// a consent, and its query is client_id, tab_id and client_data plus the
// execution - **with no session_code**, which is what makes it a landing rather
// than a form submission. The page it serves is the one place the browser flow
// and the device flow become the same request.
func (h *handler) requiredAction(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	q := r.URL.Query()
	if !validClientData(q.Get("client_data")) {
		h.writeLoginActionErrorPage(w)
		return
	}
	// The execution is checked before the cookies. Measured with a bogus
	// execution on a jar holding a live authentication session: 400, the theme
	// error page, `invalid_request`, and Cache-Control present - so it is this
	// endpoint's own page family rather than the restart branch.
	if q.Get("execution") != executionOAuthGrant {
		h.writeLoginActionErrorPage(w)
		return
	}
	tab, sess, ok := h.resolveAuthTab(r, realm, q)
	if !ok {
		h.writeUnusableSession(w, r, realm, q)
		return
	}
	client, ok := h.resolveAuthClient(r, realm, q.Get("client_id"))
	if !ok || client.ClientID != tab.ClientID {
		h.writeLoginActionErrorPage(w)
		return
	}
	h.serveConsentPage(w, realm, sess, tab, client)
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
	q := r.URL.Query()
	if !validClientData(q.Get("client_data")) {
		h.writeLoginActionErrorPage(w)
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
	client, ok := h.resolveAuthClient(r, realm, q.Get("client_id"))
	if !ok || client.ClientID != tab.ClientID {
		h.writeLoginActionErrorPage(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.writeLoginActionErrorPage(w)
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

// writeRequiredActionRedirect is the 302 a login answers when the client still
// wants a consent.
//
// Measured on both flows: the key order is execution, client_id, tab_id,
// client_data, the location is **absolute**, and the response sets **no cookies
// at all** - the session cookies come later, from the consent accept. A handler
// that established the session here would set them one request early and would
// leave a signed-in browser behind a consent that was never given.
func (h *handler) writeRequiredActionRedirect(w http.ResponseWriter, realm *model.Realm,
	client *model.Client, tab *authTab) {
	data, err := tab.clientData()
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteLoginActionRedirect(w, h.realmBase(realm.Name)+"/login-actions/required-action?"+strings.Join([]string{
		"execution=" + executionOAuthGrant,
		"client_id=" + url.QueryEscape(client.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + url.QueryEscape(data),
	}, "&"))
}
