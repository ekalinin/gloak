package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The consent page and the device grant's browser half.
//
// Every claim here was measured on a live 26.7.1 on 2026-08-30, and none of it
// is reachable from a golden: each of these is three or four requests carrying
// state in cookies a conformance case masks as volatile.

// deviceLogin drives a device authorization all the way to the consent page and
// returns the page's form action and its hidden `code`, along with the
// device_code the "device" is polling with.
func deviceLogin(t *testing.T, b *browser) (action, code, deviceCode string) {
	t.Helper()
	w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/auth/device", url.Values{
		"client_id": {"probe-device"},
		"scope":     {"openid"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("the device authorization request: want 200, got %d\n%s", w.Code, w.Body)
	}
	var minted struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &minted); err != nil {
		t.Fatalf("decode the device response: %v", err)
	}

	w = b.do(http.MethodGet, "/realms/master/device?user_code="+minted.UserCode, nil)
	if w.Code != http.StatusFound {
		t.Fatalf("the verification landing: want 302, got %d\n%s", w.Code, w.Body)
	}
	w = b.do(http.MethodGet, w.Header().Get("Location"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the login page: want 200, got %d", w.Code)
	}
	target, _ := actionParams(t, formAction(t, w.Body.String()))
	w = b.do(http.MethodPost, target, credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("the credentials: want 302, got %d\n%s", w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login-actions/required-action?execution=OAUTH_GRANT") {
		t.Fatalf("want the consent redirect, got %s", location)
	}
	w = b.do(http.MethodGet, location, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("the consent page: want 200, got %d", w.Code)
	}
	return formAction(t, w.Body.String()), hiddenCode(t, w.Body.String()), minted.DeviceCode
}

var hiddenCodeRe = regexp.MustCompile(`name="code"[^>]*value="([^"]*)"`)

func hiddenCode(t *testing.T, body string) string {
	t.Helper()
	m := hiddenCodeRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no hidden code input in the consent page (%d bytes)", len(body))
	}
	return m[1]
}

// poll issues one device-grant poll and returns the response.
func (b *browser) poll(deviceCode string) *http.Response {
	b.t.Helper()
	w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {"probe-device"},
		"device_code": {deviceCode},
	})
	return w.Result()
}

// TestADeviceLoginCanBeCompleted is the one this cut exists for.
//
// It runs the whole browser half - the verification landing, the login page, the
// credentials, the consent page, accept - and then polls, which is what F101
// said could not be done.
func TestADeviceLoginCanBeCompleted(t *testing.T) {
	b := newBrowser(t)
	action, code, deviceCode := deviceLogin(t, b)

	// Only one poll, and it is after the consent. Two polls inside the client's
	// five-second interval are a slow_down, which is the measured behaviour
	// TestSlowDownDoesNotMoveThePollClock already pins - so a test that polled
	// before and after would be asserting the interval by accident.
	w := b.do(http.MethodPost, action, url.Values{"code": {code}, "accept": {"Yes"}})
	if w.Code != http.StatusFound {
		t.Fatalf("accept: want 302, got %d\n%s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); !strings.HasSuffix(got, "/realms/master/device/status") {
		t.Errorf("accept redirect: want the status page, got %s", got)
	}
	if w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {"probe-device"},
		"device_code": {deviceCode},
	}); w.Code != http.StatusOK {
		t.Fatalf("polling an approved device code: want 200, got %d\n%s", w.Code, w.Body)
	}
}

// TestConsentCancelDeniesTheDeviceCode is `oidc/device/poll-access-denied`'s
// mechanism, and it is what that case was Pending on.
func TestConsentCancelDeniesTheDeviceCode(t *testing.T) {
	b := newBrowser(t)
	action, code, deviceCode := deviceLogin(t, b)

	w := b.do(http.MethodPost, action, url.Values{"code": {code}, "cancel": {"No"}})
	if w.Code != http.StatusFound {
		t.Fatalf("cancel: want 302, got %d\n%s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); !strings.HasSuffix(got, "/device/status?error=access_denied") {
		t.Errorf("cancel redirect: want the denied status page, got %s", got)
	}
	// Measured: cancel sets no cookies at all, where accept sets three.
	for _, raw := range w.Header().Values("Set-Cookie") {
		t.Errorf("cancel set a cookie: %s", raw)
	}
	// One poll only: a second inside the client's five-second interval is a
	// slow_down. That a denied code survives the poll reporting it is
	// TestADeniedCodeIsNotConsumed's claim, which reaches the store directly and
	// so can move the clock.
	assertPollError(t, b, deviceCode, "access_denied")
}

func assertPollError(t *testing.T, b *browser, deviceCode, want string) {
	t.Helper()
	w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {"probe-device"},
		"device_code": {deviceCode},
	})
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode the poll response: %v", err)
	}
	if body.Error != want {
		t.Errorf("poll: want %s, got %s (%s)", want, body.Error, w.Body)
	}
}

// TestCancelDecidesAndEverythingElseIsAnApproval is the shape a reader gets
// backwards, and every row of it was measured on a live 26.7.1.
//
// The endpoint tests for `cancel` and treats the rest as consent: requiring
// `accept` would refuse two requests Keycloak accepts, and checking the `code`
// would refuse two more.
func TestCancelDecidesAndEverythingElseIsAnApproval(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   url.Values
		denied bool
	}{
		{"accept alone", url.Values{"accept": {"Yes"}}, false},
		{"cancel alone", url.Values{"cancel": {"No"}}, true},
		{"both, cancel wins", url.Values{"accept": {"Yes"}, "cancel": {"No"}}, true},
		{"neither is an approval", url.Values{}, false},
		{"a wrong code still approves", url.Values{"code": {"BOGUS"}, "accept": {"Yes"}}, false},
		{"a wrong code still denies", url.Values{"code": {"BOGUS"}, "cancel": {"No"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			action, code, deviceCode := deviceLogin(t, b)
			form := url.Values{}
			for k, v := range tc.form {
				form[k] = v
			}
			if _, sent := form["code"]; !sent && tc.name != "neither is an approval" {
				form.Set("code", code)
			}
			w := b.do(http.MethodPost, action, form)
			if w.Code != http.StatusFound {
				t.Fatalf("want 302, got %d\n%s", w.Code, w.Body)
			}
			denied := strings.Contains(w.Header().Get("Location"), "error=access_denied")
			if denied != tc.denied {
				t.Errorf("denied: want %v, got %v (%s)", tc.denied, denied, w.Header().Get("Location"))
			}
			want := "authorization_pending"
			if tc.denied {
				want = "access_denied"
			} else {
				// An approved code redeems rather than reporting a state.
				if w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/token", url.Values{
					"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
					"client_id":   {"probe-device"},
					"device_code": {deviceCode},
				}); w.Code != http.StatusOK {
					t.Errorf("an approved code did not redeem: %d %s", w.Code, w.Body)
				}
				return
			}
			assertPollError(t, b, deviceCode, want)
		})
	}
}

// TestTheDeviceGrantAsksEveryTime, on a client whose consentRequired is false
// and for a user who has approved it before.
//
// Measured three device logins in a row on one user: all three served the
// OAUTH_GRANT page. Reusing the authorization endpoint's consent predicate here
// is the obvious saving and it skips the only page the device grant has.
func TestTheDeviceGrantAsksEveryTime(t *testing.T) {
	b := newBrowser(t)
	for i := range 3 {
		action, code, _ := deviceLogin(t, b)
		if w := b.do(http.MethodPost, action, url.Values{"code": {code}, "accept": {"Yes"}}); w.Code != http.StatusFound {
			t.Fatalf("run %d: accept want 302, got %d", i, w.Code)
		}
	}
}

// TestABrowserConsentIsRemembered, which is the device grant's opposite.
//
// Measured: after one accept at a consentRequired client, later logins there go
// straight to the client. So one consent store, two endpoints, and only one of
// them reads it.
func TestABrowserConsentIsRemembered(t *testing.T) {
	b := newBrowser(t)
	action := b.login(map[string]string{"client_id": "probe-consent"})
	target, _ := actionParams(t, action)
	w := b.do(http.MethodPost, target, credentials("admin", "admin"))
	if !strings.Contains(w.Header().Get("Location"), "execution=OAUTH_GRANT") {
		t.Fatalf("the first login did not ask for consent: %s", w.Header().Get("Location"))
	}
	w = b.do(http.MethodGet, w.Header().Get("Location"), nil)
	consentAction, code := formAction(t, w.Body.String()), hiddenCode(t, w.Body.String())
	w = b.do(http.MethodPost, consentAction, url.Values{"code": {code}, "accept": {"Yes"}})
	if !strings.HasPrefix(w.Header().Get("Location"), probeRedirectURI) {
		t.Fatalf("accept did not redirect to the client: %s", w.Header().Get("Location"))
	}
	first, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	session := first.Query().Get("session_state")

	// A second authorization request on the same browser: signed in, consent
	// remembered, so it is an ordinary SSO code.
	w = b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
		baseQuery(map[string]string{"client_id": "probe-consent"}), nil)
	if w.Code != http.StatusFound {
		t.Fatalf("the second request asked again: %d", w.Code)
	}
	if strings.Contains(w.Header().Get("Location"), "OAUTH_GRANT") {
		t.Errorf("the consent was not remembered: %s", w.Header().Get("Location"))
	}

	// prompt=consent re-asks, and accepting keeps the **original** session.
	w = b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
		baseQuery(map[string]string{"client_id": "probe-consent", "prompt": "consent"}), nil)
	if !strings.Contains(w.Header().Get("Location"), "execution=OAUTH_GRANT") {
		t.Fatalf("prompt=consent did not re-ask: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = b.do(http.MethodGet, w.Header().Get("Location"), nil)
	consentAction, code = formAction(t, w.Body.String()), hiddenCode(t, w.Body.String())
	w = b.do(http.MethodPost, consentAction, url.Values{"code": {code}, "accept": {"Yes"}})
	again, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := again.Query().Get("session_state"); got != session {
		t.Errorf("prompt=consent minted a new session: want %q, got %q", session, got)
	}
}

// TestTheDeviceVerificationPageAndItsAlias.
//
// /realms/{realm}/device and /realms/{realm}/protocol/openid-connect/auth/device
// are one endpoint mounted twice, measured on both verbs on both paths. The POST
// with a user code and no client_id is the theme's own form, and it answers 401
// invalid_client - so the page Keycloak renders cannot be submitted, and
// verification_uri_complete is the only route through.
func TestTheDeviceVerificationPageAndItsAlias(t *testing.T) {
	for _, path := range []string{
		"/realms/master/device",
		"/realms/master/protocol/openid-connect/auth/device",
	} {
		t.Run("GET "+path, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet, path, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("want the verification page, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), `name="device_user_code"`) {
				t.Errorf("the page has no device_user_code input")
			}
		})
		t.Run("POST "+path+" mints a code", func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodPost, path, url.Values{"client_id": {"probe-device"}})
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"device_code"`) {
				t.Fatalf("want a device authorization response, got %d %s", w.Code, w.Body)
			}
		})
		t.Run("POST "+path+" with the theme's own form", func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodPost, path, url.Values{"device_user_code": {"AAAA-AAAA"}})
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), "invalid_client") {
				t.Errorf("want invalid_client, got %s", w.Body)
			}
		})
	}
}

// TestTheDeviceStatusPage has two headings and three bodies, and the split is
// not the one the query suggests: an empty error= is the success heading and any
// non-empty value is the failure one. It carries no Cache-Control at all.
func TestTheDeviceStatusPage(t *testing.T) {
	for _, tc := range []struct{ query, want string }{
		{"", "Device Login Successful"},
		{"?error=", "Device Login Successful"},
		{"?error=access_denied", "Device Login Failed"},
		{"?error=bogus", "Device Login Failed"},
	} {
		t.Run("status"+tc.query, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet, "/realms/master/device/status"+tc.query, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("want the heading %q, got %s", tc.want, w.Body)
			}
			if got := w.Header().Get("Cache-Control"); got != "" {
				t.Errorf("Cache-Control: want none, got %q", got)
			}
		})
	}
}

// TestTheConsentEndpointNeedsItsCookies. A POST with no cookies at all is the
// 400 page whose instruction is "Restart login cookie not found. …", and a
// replayed accept - on a browser that still holds its KC_RESTART - takes the
// restart branch. Both measured, and both the same three-way branch
// /login-actions/authenticate takes.
//
// The replay is driven with the pre-accept jar because that is how it was
// measured: the accept clears KC_RESTART, and a browser that has already
// expired it sends `KC_RESTART=`. What a device flow answers in **that** state
// was not measured - the browser flow's middle branch needs a redirect URI to
// tell the client about, and a device tab has none - so it is not asserted here.
func TestTheConsentEndpointNeedsItsCookies(t *testing.T) {
	b := newBrowser(t)
	action, code, _ := deviceLogin(t, b)

	bare := newBrowser(t)
	bare.h = b.h
	if w := bare.do(http.MethodPost, action, url.Values{"code": {code}, "accept": {"Yes"}}); w.Code != http.StatusBadRequest {
		t.Errorf("no cookies: want the 400 page, got %d", w.Code)
	}
	before := map[string]string{}
	for k, v := range b.jar {
		before[k] = v
	}
	if w := b.do(http.MethodPost, action, url.Values{"code": {code}, "accept": {"Yes"}}); w.Code != http.StatusFound {
		t.Fatalf("the real accept: want 302, got %d", w.Code)
	}
	b.jar = before
	w := b.do(http.MethodPost, action, url.Values{"code": {code}, "accept": {"Yes"}})
	if w.Code != http.StatusFound ||
		!strings.Contains(w.Header().Get("Location"), "/login-actions/authenticate?") {
		t.Errorf("the replay: want the restart 302, got %d %s", w.Code, w.Header().Get("Location"))
	}
}

// TestRequiredActionRefusesAnUnknownExecution. Measured 400, the theme error
// page, with Cache-Control present - so it is this endpoint's own page family
// rather than the restart branch, and the execution is checked before the
// cookies.
//
// **It is driven on a browser that is mid-flow**, and that is the correction
// mutation testing forced. The first version sent the request with no cookies
// and asserted a 400; deleting the execution check entirely still answered a
// 400, because a request with no authentication session lands on the identical
// page by the other route. Only a browser that *would* have been served the
// consent page can tell the two apart.
func TestRequiredActionRefusesAnUnknownExecution(t *testing.T) {
	b := newBrowser(t)
	action, _, _ := deviceLogin(t, b)
	// deviceLogin leaves the browser on the consent page, so the same query with
	// the right execution is a 200. Take the tab id out of the form's action.
	u, err := url.Parse(action)
	if err != nil {
		t.Fatalf("parse the consent action: %v", err)
	}
	q := u.Query()
	base := "/realms/master/login-actions/required-action?client_id=" + q.Get("client_id") +
		"&tab_id=" + q.Get("tab_id") + "&client_data=" + q.Get("client_data")

	if w := b.do(http.MethodGet, base+"&execution=OAUTH_GRANT", nil); w.Code != http.StatusOK {
		t.Fatalf("the control: OAUTH_GRANT should serve the consent page, got %d", w.Code)
	}
	w := b.do(http.MethodGet, base+"&execution=BOGUS", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store, must-revalidate, max-age=0" {
		t.Errorf("Cache-Control: got %q", got)
	}
}

// TestGETOnTheConsentPathIsA404, which is the fallback's own answer for a known
// path hit with the wrong method - so registering POST alone is the measured
// behaviour rather than an omission.
func TestGETOnTheConsentPathIsA404(t *testing.T) {
	b := newBrowser(t)
	w := b.do(http.MethodGet, "/realms/master/login-actions/consent", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "HTTP 404 Not Found") {
		t.Errorf("want the wrong-method 404 body, got %s", w.Body)
	}
}
