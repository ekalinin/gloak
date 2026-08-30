package oidc

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
)

// The device grant's browser half: the page a person types a user code into,
// and the page they land on when it is over.
//
// Measured on 2026-08-30 against a live 26.7.1, container kc-browser on 8112.
// See section 1 of docs/superpowers/plans/2026-08-30-p13-sso-and-consent.md.

// msgInvalidUserCode is the feedback the verification page carries for a code it
// cannot use. Measured identical for a well-formed unknown code (AAAA-AAAA) and
// for a malformed one (zzzz); an **empty** user_code is the plain first render
// with no feedback at all, so absent and wrong are two answers rather than one.
const msgInvalidUserCode = "Invalid code, please try again."

// deviceClientData is the client_data the verification redirect carries: `e30`,
// which is base64url of `{}`.
//
// The device flow has no redirect URI, no response type and no state, so the
// browser's restart hint is an **empty object** rather than an absent parameter.
// That is measured on the redirect itself, and it is why encodeClientData is not
// used here: it would emit `{"ru":"","rt":"code"}`.
const deviceClientData = "e30"

// deviceVerification serves GET on **both** paths the device endpoint answers.
//
// `/realms/{realm}/device` and `/realms/{realm}/protocol/openid-connect/auth/device`
// are one endpoint mounted twice, which is measured in both directions and on
// both verbs: the POST on either mints a device code, and the GET on either
// serves this page. Four probes per path, identical answers. It is not two
// endpoints that resemble each other.
//
// Three answers, decided by the user_code:
//
//	absent or empty        200 page, no feedback
//	present and unusable   200 page, "Invalid code, please try again."
//	present and live       302 to /login-actions/authenticate, three cookies
func (h *handler) deviceVerification(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		h.serveDeviceCodePage(w, realm, "")
		return
	}
	dc, ok := h.device.deviceCodeByUserCode(realm.Name, userCode)
	if !ok {
		h.serveDeviceCodePage(w, realm, msgInvalidUserCode)
		return
	}
	client, err := h.store.Clients().ByID(r.Context(), realm.ID, dc.ClientUUID)
	if err != nil {
		h.serveDeviceCodePage(w, realm, msgInvalidUserCode)
		return
	}
	h.beginDeviceLogin(w, r, realm, client, dc)
}

// serveDeviceCodePage renders the verification form. Its action is the path this
// request arrived on, so the copy served under /protocol/openid-connect/auth/device
// posts there and the copy served under /device posts to /device - which is what
// Keycloak does, both being the same handler.
func (h *handler) serveDeviceCodePage(w http.ResponseWriter, realm *model.Realm, message string) {
	httpx.WriteThemeDeviceCodePage(w, h.realmBase(realm.Name)+"/device", message)
}

// beginDeviceLogin is the 302 a live user code answers: an authentication
// session carrying the device code, and the ordinary login action to follow.
//
// Measured: the redirect is absolute, its keys are client_id, tab_id,
// client_data in that order, there is **no session_code** - the landing request
// is what mints one, exactly as the restart redirect works - and it sets
// AUTH_SESSION_ID, KC_AUTH_SESSION_HASH and KC_RESTART. It omits X-Frame-Options
// and Content-Security-Policy, which is /auth's redirect header set and not the
// login action's.
//
// The tab carries the **user code** rather than the device code, because that is
// the only identifier this side of the flow ever sees: the device code never
// leaves the device.
func (h *handler) beginDeviceLogin(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, dc *deviceCode) {
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	tab := &authTab{
		ClientID:       client.ClientID,
		ClientUUID:     client.ID,
		Scope:          dc.Scope,
		DeviceUserCode: dc.UserCode,
	}
	if _, err := h.beginAuthSession(w, r, realm, k, tab, &restartRecord{
		Realm:          realm.Name,
		ClientID:       client.ClientID,
		Scope:          dc.Scope,
		DeviceUserCode: dc.UserCode,
	}); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteAuthorizationRedirect(w, h.realmBase(realm.Name)+"/login-actions/authenticate?"+strings.Join([]string{
		"client_id=" + url.QueryEscape(client.ClientID),
		"tab_id=" + url.QueryEscape(tab.TabID),
		"client_data=" + deviceClientData,
	}, "&"))
}

// completeDeviceApproval is the device flow's ending: the code approved against
// a real user session, and the browser sent to the status page.
//
// The user session is established here rather than at the credential POST,
// which is measured: the login's own 302 to the consent page sets **no cookies
// at all**, and the consent accept sets the three. So a device login that stops
// at the consent page has authenticated nobody.
func (h *handler) completeDeviceApproval(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, sess *authSession, tab *authTab, user *model.User, k *keys.RealmKeys) error {
	scope := grantedScope(tab.Scope)
	session, err := h.startSessionWithID(r.Context(), sess.RootID, realm, client, user, scope)
	if err != nil {
		return err
	}
	if !h.device.approveDeviceCode(tab.DeviceUserCode, user.ID, session.ID) {
		// The code expired while the person was typing their password. Measured
		// nowhere - a ten-minute lifespan makes it hard to reach on purpose - so
		// it takes the failure page rather than an invented one.
		h.auth.endSession(sess.RootID)
		httpx.WriteLoginActionRedirect(w, h.deviceStatusLocation(realm.Name, deviceErrExpiredToken))
		return nil
	}
	h.auth.endSession(sess.RootID)
	clearRestartCookie(w, realm)
	if err := h.setLoginCookies(w, realm, k, session.ID, user); err != nil {
		return err
	}
	httpx.WriteLoginActionRedirect(w, h.deviceStatusLocation(realm.Name, ""))
	return nil
}

// deviceStatusLocation is where a finished device authorization sends the
// browser: the status page, absolute, with the error on the query when there was
// one.
func (h *handler) deviceStatusLocation(realm, errCode string) string {
	location := h.realmBase(realm) + "/device/status"
	if errCode != "" {
		location += "?error=" + url.QueryEscape(errCode)
	}
	return location
}

// deviceStatus serves GET /realms/{realm}/device/status, the page a person is
// left on.
//
// It is 200 whatever it is given, it carries **no Cache-Control at all** - the
// only page in this flow that does not - and it has two headings and three
// bodies. The split is not the one the query suggests: `?error=` with an empty
// value is the success heading, and **any** non-empty value is the failure one,
// including a code Keycloak does not recognise. It asks for no session and no
// cookies; a browser that never started a device login sees the success page.
func (h *handler) deviceStatus(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	title := httpx.DeviceStatusPageTitle
	if r.URL.Query().Get("error") != "" {
		title = httpx.DeviceStatusFailedTitle
	}
	httpx.WriteThemePage(w, http.StatusOK, "", title)
}
