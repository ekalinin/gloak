package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The login theme's pages, and the three things about them the conformance
// goldens cannot reach.
//
// Seven theme pages are compared byte for byte by internal/conformance. What is
// *not* covered there is every rejection those seven happen not to be: the
// bearer-only 403, an empty client_id, a disabled client, the logout page's
// eight-cell grid and the device status page's two failure bodies have no
// golden, so a wrong sentence in any of them would ship silently. These are the
// guard.
//
// Every string below was read off a live Keycloak 26.7.1 on 2026-09-01,
// container kc-theme on port 8152. See
// docs/superpowers/plans/2026-09-01-p13-theme-markup.md.

// instructionOf returns the page's one <p class="instruction">.
func instructionOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := regexp.MustCompile(`<p class="instruction">([^<]*)</p>`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no instruction in the page:\n%s", w.Body.String())
	}
	return m[1]
}

// restartQueryOf returns the query of the URL startSessionPolling is called
// with, which is where the page says which client it is about.
func restartQueryOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := regexp.MustCompile(`login-actions/restart\?([^"]*)"`).FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("no restart URL in the page:\n%s", w.Body.String())
	}
	return m[1]
}

// TestAuthorizePageInstructions is the sweep the page family's four
// client rejections needed, and the answer is **three** sentences rather than
// the four the endpoint's own comment claimed until 2026-09-01.
//
// The pair that matters is the first two rows: an absent client_id and an empty
// one part company, so a handler reading the value through url.Values.Get -
// which cannot tell them apart - gets one of them wrong.
func TestAuthorizePageInstructions(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		name      string
		overrides map[string]string
		status    int
		want      string
	}{
		{"an absent client_id", map[string]string{"client_id": absent},
			http.StatusBadRequest, "Invalid Request"},
		{"an empty client_id", map[string]string{"client_id": ""},
			http.StatusBadRequest, "Client not found."},
		{"an unknown client", map[string]string{"client_id": "nosuchclient"},
			http.StatusBadRequest, "Client not found."},
		{"a disabled client", map[string]string{"client_id": "probe-disabled"},
			http.StatusBadRequest, "Client disabled."},
		{"a bearer-only client", map[string]string{"client_id": "probe-bearer"},
			http.StatusForbidden,
			"Bearer-only applications are not allowed to initiate browser login"},
		{"a non-numeric max_age", map[string]string{"max_age": "abc"},
			http.StatusBadRequest, "Invalid Request"},
		{"an unregistered redirect_uri", map[string]string{"redirect_uri": "https://evil.example/cb"},
			http.StatusBadRequest, "Invalid parameter: redirect_uri"},
		{"an absent redirect_uri", map[string]string{"redirect_uri": absent},
			http.StatusBadRequest, "Invalid parameter: redirect_uri"},
		{"prompt=create", map[string]string{"prompt": "create"},
			http.StatusBadRequest, "Registration not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrides := map[string]string{}
			for k, v := range tc.overrides {
				overrides[k] = v
			}
			// prompt=create is the one row that has to survive every earlier
			// check, so it keeps its response_type; the rest drop it for
			// TestAuthorizePageFamily's reason.
			if _, ok := overrides["prompt"]; !ok {
				overrides["response_type"] = absent
			}
			w := authorize(t, h, baseQuery(overrides))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if got := instructionOf(t, w); got != tc.want {
				t.Errorf("instruction = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAuthorizePageNamesTheClientOrNothing pins the other half of the page: the
// restart URL's client_id and the "Back to Application" link.
//
// **The bearer-only row is the one nobody would guess.** Its client resolves -
// it has to, or the 403 could not be decided - and the page still names no
// client and offers no link, so "the request named a client" is not what the
// chrome is about. Measured on master-realm, which carries a baseUrl.
func TestAuthorizePageNamesTheClientOrNothing(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		name        string
		overrides   map[string]string
		wantRestart string
		wantLink    bool
	}{
		{"an unknown client names nothing", map[string]string{"client_id": "nosuchclient"},
			"skip_logout=true", false},
		{"an absent client_id names nothing", map[string]string{"client_id": absent},
			"skip_logout=true", false},
		{"a disabled client names nothing", map[string]string{"client_id": "probe-disabled"},
			"skip_logout=true", false},
		{"a bearer-only client names nothing", map[string]string{"client_id": "probe-bearer"},
			"skip_logout=true", false},
		{"a bad redirect_uri names the client", map[string]string{"redirect_uri": "https://evil.example/cb"},
			"client_id=probe&skip_logout=true", false},
		{"max_age names the client", map[string]string{"max_age": "abc"},
			"client_id=probe&skip_logout=true", false},
		{"a client with a baseUrl gets the link",
			map[string]string{"client_id": "probe-home", "redirect_uri": "https://evil.example/cb"},
			"client_id=probe-home&skip_logout=true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrides := map[string]string{"response_type": absent}
			for k, v := range tc.overrides {
				overrides[k] = v
			}
			w := authorize(t, h, baseQuery(overrides))
			if got := restartQueryOf(t, w); got != tc.wantRestart {
				t.Errorf("restart query = %q, want %q", got, tc.wantRestart)
			}
			hasLink := strings.Contains(w.Body.String(), `id="backToApplication"`)
			if hasLink != tc.wantLink {
				t.Errorf("Back to Application link present = %v, want %v", hasLink, tc.wantLink)
			}
		})
	}
}

// TestBackToApplicationFollowsTheBaseURL is the five-client sweep behind the
// link's href, and its fourth row is the one an implementation gets wrong: a
// client whose only URL is a rootUrl has **no link at all**, although the admin
// console presents rootUrl and baseUrl together as one "Home URL".
func TestBackToApplicationFollowsTheBaseURL(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		clientID string
		want     string // "" means no link
	}{
		{"probe-home", "http://abs.example/home"},
		{"probe-relhome", testIssuerBase + "/rel/home"},
		{"probe-roothome", "http://root.example/rel/home"},
		{"probe-rootonly", ""},
		{"probe", ""},
	} {
		t.Run(tc.clientID, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{
				"client_id": tc.clientID, "response_type": absent,
				"redirect_uri": "https://evil.example/cb",
			}))
			m := regexp.MustCompile(`id="backToApplication" href="([^"]*)"`).
				FindStringSubmatch(w.Body.String())
			got := ""
			if m != nil {
				got = m[1]
			}
			if got != tc.want {
				t.Errorf("href = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLogoutPageInstructions is F67: three sentences that were one placeholder.
//
// The grid is eight cells because the variable is **not** whether a client was
// found. An unknown client_id and a real one answer the same sentence; an
// absent client_id and an empty one answer the other. So `client_id=` counts as
// absent here and as present at /auth, which is one parameter read two ways by
// two endpoints in the same flow.
func TestLogoutPageInstructions(t *testing.T) {
	h := authServer(t)
	const registered = probeRedirectURI
	const unregistered = "https://evil.example/cb"
	for _, tc := range []struct {
		name        string
		query       string
		want        string
		wantRestart string
	}{
		{"no client_id, a registered target", "post_logout_redirect_uri=" + registered,
			"Missing parameters: id_token_hint", "skip_logout=true"},
		{"no client_id, an unregistered target", "post_logout_redirect_uri=" + unregistered,
			"Missing parameters: id_token_hint", "skip_logout=true"},
		{"an empty client_id", "client_id=&post_logout_redirect_uri=" + unregistered,
			"Missing parameters: id_token_hint", "skip_logout=true"},
		{"an unknown client_id, a registered target",
			"client_id=nosuchclient&post_logout_redirect_uri=" + registered,
			"Invalid redirect uri", "skip_logout=true"},
		{"an unknown client_id, an unregistered target",
			"client_id=nosuchclient&post_logout_redirect_uri=" + unregistered,
			"Invalid redirect uri", "skip_logout=true"},
		{"a known client, an unregistered target",
			"client_id=probe&post_logout_redirect_uri=" + unregistered,
			"Invalid redirect uri", "client_id=probe&skip_logout=true"},
		{"a disabled client, an unregistered target",
			"client_id=probe-disabled&post_logout_redirect_uri=" + unregistered,
			"Invalid redirect uri", "client_id=probe-disabled&skip_logout=true"},
		{"an unusable id_token_hint",
			"id_token_hint=not-a-jwt&client_id=probe&post_logout_redirect_uri=" + unregistered,
			"Invalid parameter: id_token_hint", "skip_logout=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/realms/master/protocol/openid-connect/logout?"+tc.query, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400\n%s", w.Code, w.Body)
			}
			if got := instructionOf(t, w); got != tc.want {
				t.Errorf("instruction = %q, want %q", got, tc.want)
			}
			if got := restartQueryOf(t, w); got != tc.wantRestart {
				t.Errorf("restart query = %q, want %q", got, tc.wantRestart)
			}
		})
	}
}

// TestDeviceStatusPageHasThreeBodies. Only the success page has a golden, so
// the two failure sentences are guarded here or nowhere.
//
// The split is measured and is not the one the query suggests: `error=` with an
// empty value is the **success** page, and every non-empty value is a failure
// page under one of two sentences.
func TestDeviceStatusPageHasThreeBodies(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct{ query, title, instruction string }{
		{"", "Device Login Successful",
			"You may close this browser window and go back to your device."},
		{"?error=", "Device Login Successful",
			"You may close this browser window and go back to your device."},
		{"?error=access_denied", "Device Login Failed",
			"Consent denied for connecting the device."},
		{"?error=expired_token", "Device Login Failed",
			"You may close this browser window and go back to your device and try connecting again."},
		{"?error=zzz", "Device Login Failed",
			"You may close this browser window and go back to your device and try connecting again."},
	} {
		t.Run("query"+tc.query, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/realms/master/device/status"+tc.query, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if !strings.Contains(w.Body.String(), tc.title) {
				t.Errorf("page has no heading %q", tc.title)
			}
			if got := instructionOf(t, w); got != tc.instruction {
				t.Errorf("instruction = %q, want %q", got, tc.instruction)
			}
			if !strings.Contains(w.Body.String(), `data-page-id="login-info"`) {
				t.Error("page is not the login-info template")
			}
		})
	}
}

// TestDeviceVerifyFormActionIsTheSameOnBothPaths.
//
// The handler's own doc comment said the action echoed the path the request
// arrived on, and it was never measured. On 2026-09-01 the two paths produced
// byte-identical 4692-byte pages, both naming /realms/master/device, and the
// action is **relative**. Serving the absolute form is what Gloak did.
func TestDeviceVerifyFormActionIsTheSameOnBothPaths(t *testing.T) {
	h := authServer(t)
	var bodies []string
	for _, path := range []string{
		"/realms/master/device",
		"/realms/master/protocol/openid-connect/auth/device",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), `action="/realms/master/device"`) {
			t.Errorf("%s: form action is not /realms/master/device", path)
		}
		bodies = append(bodies, w.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Error("the two paths serve different pages; measured byte-identical")
	}
}

// TestUnparseableBodyIsA500 pins the answer that is **not** a page.
//
// Measured 2026-09-01 on POST /auth and POST /logout with a body holding a bad
// percent escape: 500, application/json, and the same nine-word description on
// both. Gloak answered the 400 error page on both until this cut, which is the
// wrong status, the wrong Content-Type and the wrong family.
func TestUnparseableBodyIsA500(t *testing.T) {
	h := authServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect/auth",
		"/realms/master/protocol/openid-connect/logout",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path,
				strings.NewReader("client_id=probe&%zz=1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500\n%s", w.Code, w.Body)
			}
			if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			want := `{"error":"unknown_error","error_description":` +
				`"For more on this error consult the server log."}`
			if got := w.Body.String(); got != want {
				t.Errorf("body = %s, want %s", got, want)
			}
		})
	}
}
