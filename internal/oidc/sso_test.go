package oidc_test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The SSO tests drive the real router with the real cookie jar, for the reason
// the login tests give: every claim here is about what carries state from one
// request to the next, and a test that reached into the handler's maps would
// pass while the cookie that makes it work was misspelled.
//
// They are also the only guard on most of it. Every conformance case in this
// flow masks Location and Set-Cookie as volatile, so the session_state, the
// cookie set and the auth_time are invisible to a golden.

// signIn runs a whole browser login and returns the jar, ready for a second
// authorization request.
func signIn(t *testing.T) *browser {
	t.Helper()
	b := newBrowser(t)
	action := b.login(nil)
	target, _ := actionParams(t, action)
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("login: want 302, got %d\n%s", w.Code, w.Body)
	}
	return b
}

// authorize issues a second GET /auth on an existing jar.
func (b *browser) authorize(overrides map[string]string) *url.Values {
	b.t.Helper()
	w := b.do(http.MethodGet,
		"/realms/master/protocol/openid-connect/auth?"+baseQuery(overrides), nil)
	if w.Code != http.StatusFound {
		return nil
	}
	q, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		b.t.Fatalf("parse Location: %v", err)
	}
	values := q.Query()
	return &values
}

// TestSSOReusesTheOriginalSession is the load-bearing one, and it asserts the
// three things a live 26.7.1 carries out of the first login into the second
// authorization request.
//
// Measured on one browser: the SSO redirect's session_state is the **original**
// user session id, the token minted from its code carries the **original**
// auth_time with a later iat, and the sid is unchanged - so no second user
// session exists. Minting a session here is the obvious implementation and gets
// all three wrong at once.
func TestSSOReusesTheOriginalSession(t *testing.T) {
	b := signIn(t)
	first, err := url.Parse(b.last.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse the login redirect: %v", err)
	}
	firstSession := first.Query().Get("session_state")

	second := b.authorize(map[string]string{"state": "second"})
	if second == nil {
		t.Fatalf("the second GET /auth did not redirect: %d\n%s", b.last.Code, b.last.Body)
	}
	if got := second.Get("session_state"); got != firstSession {
		t.Errorf("session_state: want the original %q, got %q", firstSession, got)
	}
	if got := second.Get("code"); !strings.Contains(got, "."+firstSession+".") {
		t.Errorf("the code's second part is not the original session_state: %q", got)
	}
	if second.Get("error") != "" {
		t.Errorf("the SSO redirect carries an error: %v", second.Get("error"))
	}
	// The fresh AUTH_SESSION_ID carries the **original** session id and a new
	// opaque half, measured by base64url-decoding the cookie on a live 26.7.1.
	decoded, err := base64.RawURLEncoding.DecodeString(b.jar["AUTH_SESSION_ID"])
	if err != nil {
		t.Fatalf("AUTH_SESSION_ID is not base64url: %v", err)
	}
	root, secret, ok := strings.Cut(string(decoded), ".")
	if !ok || root != firstSession {
		t.Errorf("AUTH_SESSION_ID root: want the original session %q, got %q", firstSession, root)
	}
	if len(secret) != 86 {
		t.Errorf("AUTH_SESSION_ID secret: want 86 characters, got %d", len(secret))
	}
	if claims := identityClaims(t, b.jar["KEYCLOAK_IDENTITY"]); claims["sid"] != firstSession {
		t.Errorf("KEYCLOAK_IDENTITY sid moved: want %q, got %v", firstSession, claims["sid"])
	}
}

// TestSSOCodeIsRedeemable is what says the SSO branch produced a real code
// rather than a well-shaped string.
//
// It is a separate test from the one above because the two fail for different
// reasons: that one fails when the session is not reused, this one when the
// code is minted against something the token endpoint cannot resolve.
func TestSSOCodeIsRedeemable(t *testing.T) {
	b := signIn(t)
	second := b.authorize(map[string]string{"state": "second"})
	if second == nil {
		t.Fatalf("the second GET /auth did not redirect: %d", b.last.Code)
	}
	w := b.do(http.MethodPost, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {second.Get("code")},
		"client_id":    {"probe"},
		"redirect_uri": {probeRedirectURI},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("redeeming the SSO code: want 200, got %d\n%s", w.Code, w.Body)
	}
}

// TestOnlyTheIdentityCookieDecidesSSO is the measurement a reader would get
// wrong.
//
// Replaying GET /auth with each subset of the four cookies a completed login
// leaves: KEYCLOAK_IDENTITY alone is a code, and KEYCLOAK_SESSION,
// AUTH_SESSION_ID and KC_AUTH_SESSION_HASH in any combination without it are the
// login page. AUTH_SESSION_ID is the one that names the authentication session
// and it decides nothing here.
func TestOnlyTheIdentityCookieDecidesSSO(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keep    []string
		wantSSO bool
	}{
		{"all four", []string{"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION", "AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH"}, true},
		{"KEYCLOAK_IDENTITY alone", []string{"KEYCLOAK_IDENTITY"}, true},
		{"KEYCLOAK_IDENTITY and AUTH_SESSION_ID", []string{"KEYCLOAK_IDENTITY", "AUTH_SESSION_ID"}, true},
		{"KEYCLOAK_SESSION alone", []string{"KEYCLOAK_SESSION"}, false},
		{"AUTH_SESSION_ID alone", []string{"AUTH_SESSION_ID"}, false},
		{"KC_AUTH_SESSION_HASH alone", []string{"KC_AUTH_SESSION_HASH"}, false},
		{"everything but the identity cookie", []string{"KEYCLOAK_SESSION", "AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH"}, false},
		{"nothing", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := signIn(t)
			full := b.jar
			b.jar = map[string]string{}
			for _, name := range tc.keep {
				if full[name] == "" {
					t.Fatalf("the login left no %s to keep", name)
				}
				b.jar[name] = full[name]
			}
			w := b.do(http.MethodGet,
				"/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil)
			if tc.wantSSO && w.Code != http.StatusFound {
				t.Fatalf("want the SSO redirect, got %d", w.Code)
			}
			if !tc.wantSSO && w.Code != http.StatusOK {
				t.Fatalf("want the login page, got %d (%s)", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// TestPromptOnASignedInBrowser walks every measured value of the parameter that
// makes SSO observable.
//
// Four of these are the ones a reader gets wrong. An unrecognised value is
// **ignored** rather than refused, so prompt=bogus is a code; the comparison is
// case-sensitive, so prompt=NONE is a code too; `none login` is login_required
// where `none` alone is a code, so "none must be the only value" is not the
// rule; and `none consent` is a code, which is what says so.
func TestPromptOnASignedInBrowser(t *testing.T) {
	const (
		wantCode  = "code"
		wantPage  = "page"
		wantLogin = "login_required"
		want400   = "400"
	)
	for _, tc := range []struct{ prompt, signedIn, anonymous string }{
		{"", wantCode, wantPage},
		{"none", wantCode, wantLogin},
		{"login", wantPage, wantPage},
		{"consent", wantCode, wantPage},
		{"select_account", wantCode, wantPage},
		{"bogus", wantCode, wantPage},
		{"NONE", wantCode, wantPage},
		{"create", want400, want400},
		{"none login", wantLogin, wantLogin},
		{"none consent", wantCode, wantLogin},
		{"login consent", wantPage, wantPage},
		{"none create", wantCode, wantLogin},
		{"create login", wantPage, wantPage},
	} {
		t.Run("signed-in prompt="+tc.prompt, func(t *testing.T) {
			b := signIn(t)
			assertPromptOutcome(t, b, tc.prompt, tc.signedIn)
		})
		t.Run("anonymous prompt="+tc.prompt, func(t *testing.T) {
			assertPromptOutcome(t, newBrowser(t), tc.prompt, tc.anonymous)
		})
	}
}

func assertPromptOutcome(t *testing.T, b *browser, prompt, want string) {
	t.Helper()
	w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
		baseQuery(map[string]string{"prompt": prompt}), nil)
	got := outcome(t, w.Code, w.Header().Get("Location"))
	if got != want {
		t.Errorf("prompt=%q: want %s, got %s (%d %s)", prompt, want, got, w.Code, w.Header().Get("Location"))
	}
}

// outcome names which of the four measured answers a response is.
func outcome(t *testing.T, status int, location string) string {
	t.Helper()
	switch status {
	case http.StatusOK:
		return "page"
	case http.StatusBadRequest:
		return "400"
	case http.StatusFound:
		u, err := url.Parse(location)
		if err != nil {
			t.Fatalf("parse Location %q: %v", location, err)
		}
		if e := u.Query().Get("error"); e != "" {
			return e
		}
		return "code"
	}
	return "unexpected status"
}

// TestMaxAgeOnASignedInBrowser. The comparison is `now - auth_time > max_age`
// and it is **strict**: max_age=0 on a session created in the same second is a
// code, which is what a browser signed in a moment ago is here.
//
// max_age=abc and an empty max_age= are both the page family, and that is the
// opposite of prompt=, where an empty value is an absent one - two parameters on
// one endpoint, opposite answers to the same emptiness.
func TestMaxAgeOnASignedInBrowser(t *testing.T) {
	for _, tc := range []struct{ maxAge, signedIn, anonymous string }{
		{"3600", "code", "page"},
		{"0", "code", "page"},
		{"abc", "400", "400"},
		{"", "400", "400"},
		{"-1", "page", "page"},
	} {
		t.Run("signed-in max_age="+tc.maxAge, func(t *testing.T) {
			b := signIn(t)
			w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(map[string]string{"max_age": tc.maxAge}), nil)
			if got := outcome(t, w.Code, w.Header().Get("Location")); got != tc.signedIn {
				t.Errorf("max_age=%q: want %s, got %s", tc.maxAge, tc.signedIn, got)
			}
		})
		t.Run("anonymous max_age="+tc.maxAge, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(map[string]string{"max_age": tc.maxAge}), nil)
			if got := outcome(t, w.Code, w.Header().Get("Location")); got != tc.anonymous {
				t.Errorf("max_age=%q: want %s, got %s", tc.maxAge, tc.anonymous, got)
			}
		})
	}
}

// TestMaxAgeIsRefusedBeforeTheRedirectURI places the new check.
//
// It is a **page** rejection sitting between two other page rejections, which
// is why it cannot be folded into either: it loses to an unknown client_id and
// to a bearer-only client, and beats the redirect URI and everything after it.
// Six pairs, each driving two faults at once.
func TestMaxAgeIsRefusedBeforeTheRedirectURI(t *testing.T) {
	for _, tc := range []struct {
		name      string
		overrides map[string]string
		want      int
	}{
		{"an unknown client wins", map[string]string{"client_id": "nope", "max_age": "abc"}, http.StatusBadRequest},
		{"a bearer-only client wins", map[string]string{"client_id": "probe-bearer", "max_age": "abc"}, http.StatusForbidden},
		{"max_age beats the redirect URI", map[string]string{"redirect_uri": "http://evil/cb", "max_age": "abc"}, http.StatusBadRequest},
		{"max_age beats a missing response_type", map[string]string{"response_type": "", "max_age": "abc"}, http.StatusBadRequest},
		{"max_age beats a bad scope", map[string]string{"scope": "bogus", "max_age": "abc"}, http.StatusBadRequest},
		{"max_age beats prompt=none", map[string]string{"prompt": "none", "max_age": "abc"}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet,
				"/realms/master/protocol/openid-connect/auth?"+baseQuery(tc.overrides), nil)
			if w.Code != tc.want {
				t.Fatalf("want %d, got %d (%s)", tc.want, w.Code, w.Header().Get("Location"))
			}
			// Every one of these is the page family, so none of them may be a
			// redirect - which is what "before the redirect URI" means.
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("want a page, got a redirect to %s", loc)
			}
		})
	}
}

// TestTheTwoNewPagesDisagreeAboutCacheControl is the finding that refutes a line
// in AGENTS.md.
//
// That file records /auth's page family as sending no Cache-Control at all,
// which is true of the six rejections it was measured on and false of
// prompt=create's. Measured side by side on one container. The predictor is not
// the endpoint but how far the request got: max_age fails while the parameters
// are being read, prompt=create fails inside the authentication flow.
func TestTheTwoNewPagesDisagreeAboutCacheControl(t *testing.T) {
	for _, tc := range []struct{ name, override, value, want string }{
		{"max_age sends none", "max_age", "abc", ""},
		{"prompt=create sends one", "prompt", "create", "no-store, must-revalidate, max-age=0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(map[string]string{tc.override: tc.value}), nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", w.Code)
			}
			if got := w.Header().Get("Cache-Control"); got != tc.want {
				t.Errorf("Cache-Control: want %q, got %q", tc.want, got)
			}
		})
	}
}

// TestTheSSORedirectSetsFiveCookies, and prompt=none's four.
//
// Measured on a jar holding all four cookies, on one holding KEYCLOAK_IDENTITY
// alone and on three consecutive requests: the SSO success always sets all five.
// **prompt=none sets no KC_RESTART** of its own.
//
// **The jar must not present a KC_RESTART**, and saying so is the correction
// this test needed. A browser that has one gets a sixth Set-Cookie clearing it -
// see TestAPresentedRestartCookieIsClearedOnTheWayOut - and this test passed
// while that was unimplemented because the harness keeps a cleared cookie as an
// empty value, so the jar a login leaves behind still presents one. It was
// measuring a condition it had not stated.
func TestTheSSORedirectSetsFiveCookies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prompt string
		want   []string
	}{
		{"no prompt", "", []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART",
			"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}},
		{"prompt=none", "none", []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH",
			"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := signIn(t)
			delete(b.jar, "KC_RESTART")
			b.raw = nil
			w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(map[string]string{"prompt": tc.prompt}), nil)
			if w.Code != http.StatusFound {
				t.Fatalf("want the SSO redirect, got %d", w.Code)
			}
			if got := cookieNames(b.raw); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("cookies: want %v, got %v", tc.want, got)
			}
		})
	}
}

// TestAPresentedRestartCookieIsClearedOnTheWayOut is the strangest measured
// thing in the cut, and it is invisible to a golden: Set-Cookie is masked whole
// on every case in this family, and a masked header is asserted on presence
// alone, so the **count** is never compared.
//
// A response can set KC_RESTART twice, in opposite directions. The clear is
// last, so a browser that arrives holding one leaves without it and a browser
// that arrives without one leaves holding a fresh one. Six branches were
// measured with the same cookie present and three of them clear it.
func TestAPresentedRestartCookieIsClearedOnTheWayOut(t *testing.T) {
	for _, tc := range []struct {
		name      string
		signedIn  bool
		overrides map[string]string
		want      []string
	}{
		{"the SSO code sets one and clears it", true, nil, []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART", "KC_RESTART",
			"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}},
		{"prompt=none clears it and sets none", true, map[string]string{"prompt": "none"}, []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART",
			"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}},
		{"login_required clears it", false, map[string]string{"prompt": "none"}, []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART"}},
		{"prompt=create does not", false, map[string]string{"prompt": "create"}, []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH"}},
		{"the login page does not", false, nil, []string{
			"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH", "KC_RESTART"}},
		{"max_age's page sets nothing", false, map[string]string{"max_age": "abc"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			if tc.signedIn {
				b = signIn(t)
			}
			// The cookie is put in by hand so that every row starts from the
			// same request, whatever the jar happened to hold.
			b.jar["KC_RESTART"] = "junk"
			b.raw = nil
			b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(tc.overrides), nil)
			if got := cookieNames(b.raw); strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("cookies: want %v, got %v", tc.want, got)
			}
			// The clear has to be the **last** KC_RESTART, or a browser would
			// end up holding the fresh one where Keycloak leaves it with none.
			cleared := 0
			last := ""
			for _, raw := range b.raw {
				if strings.HasPrefix(raw, "KC_RESTART=") {
					last = raw
					if strings.Contains(raw, "Max-Age=0") {
						cleared++
					}
				}
			}
			wantCleared := strings.Contains(tc.name, "clears it")
			if (cleared == 1) != wantCleared {
				t.Errorf("cleared KC_RESTART %d times, want %v", cleared, wantCleared)
			}
			if wantCleared && !strings.Contains(last, "Max-Age=0") {
				t.Errorf("the clear is not the last KC_RESTART: %s", last)
			}
		})
	}
}

// TestTheSilentRejectionsStillOpenASession is the part of the two rejections at
// step 10 that a reader would leave out.
//
// **login_required and prompt=create's page both set AUTH_SESSION_ID and
// KC_AUTH_SESSION_HASH**, and no KC_RESTART of their own. Four rows, each on its
// own fresh login. max_age's rejection at step 2c is the only one that sends
// none at all, which is what says the two checks are in different places.
//
// The jar is emptied of KC_RESTART for the reason
// TestTheSSORedirectSetsFiveCookies gives: login_required clears a presented
// one, so a jar that still holds the login's emptied cookie would see a third
// Set-Cookie here that this test is not about.
func TestTheSilentRejectionsStillOpenASession(t *testing.T) {
	pair := []string{"AUTH_SESSION_ID", "KC_AUTH_SESSION_HASH"}
	for _, tc := range []struct {
		name      string
		signedIn  bool
		overrides map[string]string
		want      []string
	}{
		{"prompt=none anonymous", false, map[string]string{"prompt": "none"}, pair},
		{"prompt=none login signed in", true, map[string]string{"prompt": "none login"}, pair},
		{"prompt=create anonymous", false, map[string]string{"prompt": "create"}, pair},
		{"prompt=create signed in", true, map[string]string{"prompt": "create"}, pair},
		{"max_age=abc anonymous", false, map[string]string{"max_age": "abc"}, nil},
		{"max_age=abc signed in", true, map[string]string{"max_age": "abc"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			if tc.signedIn {
				b = signIn(t)
			}
			delete(b.jar, "KC_RESTART")
			b.raw = nil
			b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+
				baseQuery(tc.overrides), nil)
			got := cookieNames(b.raw)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("cookies: want %v, got %v", tc.want, got)
			}
		})
	}
}

// TestAnUnusableIdentityCookieIsCleared, together with KEYCLOAK_SESSION.
//
// **Both go, not just the one that failed.** Measured on three ways an identity
// cookie can be unusable: a value that is not a JWT, a valid one with its
// signature rewritten, and a correctly signed one naming a session that has been
// ended. All three answer the same pair of Max-Age=0 cookies and then serve the
// request as an anonymous one.
func TestAnUnusableIdentityCookieIsCleared(t *testing.T) {
	t.Run("not a JWT", func(t *testing.T) {
		b := signIn(t)
		b.jar["KEYCLOAK_IDENTITY"] = "garbage"
		assertIdentityCleared(t, b)
	})
	t.Run("a rewritten signature", func(t *testing.T) {
		b := signIn(t)
		raw := b.jar["KEYCLOAK_IDENTITY"]
		b.jar["KEYCLOAK_IDENTITY"] = raw[:len(raw)-3] + "AAA"
		assertIdentityCleared(t, b)
	})
	t.Run("another realm's signature", func(t *testing.T) {
		b := signIn(t)
		// A cookie minted by a different server for the same session id: the
		// second browser's realm is a different sqlite file, so its HMAC key is
		// a different one.
		other := signIn(t)
		b.jar["KEYCLOAK_IDENTITY"] = other.jar["KEYCLOAK_IDENTITY"]
		assertIdentityCleared(t, b)
	})
}

func assertIdentityCleared(t *testing.T, b *browser) {
	t.Helper()
	b.raw = nil
	w := b.do(http.MethodGet, "/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want the login page, got %d (%s)", w.Code, w.Header().Get("Location"))
	}
	cleared := map[string]bool{}
	for _, raw := range b.raw {
		name, rest, _ := strings.Cut(raw, "=")
		if strings.Contains(rest, "Max-Age=0") {
			cleared[name] = true
		}
	}
	for _, name := range []string{"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"} {
		if !cleared[name] {
			t.Errorf("%s was not cleared; got %v", name, b.raw)
		}
	}
}

// TestALiveBrowserSessionChangesOneLogoutCell is F65, and one cell is the whole
// of it.
//
// The grid was measured with each row on its own fresh login. Six of the seven
// rows are what Gloak already answered; the seventh - a live browser session, no
// id_token_hint, and a registered target - is the confirmation page where Gloak
// sent a 302. A valid hint still redirects on a signed-in browser, which is what
// says this is not "a live session means the page".
//
// The page **ends nothing**: GET /auth immediately afterwards still answers a
// code.
func TestALiveBrowserSessionChangesOneLogoutCell(t *testing.T) {
	target := url.QueryEscape(probeRedirectURI)
	for _, tc := range []struct {
		name     string
		signedIn bool
		query    string
		want     int
	}{
		{"live, no hint, no target", true, "client_id=probe", http.StatusOK},
		{"live, no hint, a target", true, "client_id=probe&post_logout_redirect_uri=" + target, http.StatusOK},
		{"none, no hint, no target", false, "client_id=probe", http.StatusOK},
		{"none, no hint, a target", false, "client_id=probe&post_logout_redirect_uri=" + target, http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			if tc.signedIn {
				b = signIn(t)
			}
			w := b.do(http.MethodGet,
				"/realms/master/protocol/openid-connect/logout?"+tc.query, nil)
			if w.Code != tc.want {
				t.Fatalf("want %d, got %d (%s)", tc.want, w.Code, w.Header().Get("Location"))
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), "Logging out") {
				t.Errorf("want the confirmation page, got %s", w.Body)
			}
		})
	}

	t.Run("the confirmation page ends nothing", func(t *testing.T) {
		b := signIn(t)
		if w := b.do(http.MethodGet,
			"/realms/master/protocol/openid-connect/logout?client_id=probe", nil); w.Code != http.StatusOK {
			t.Fatalf("want the confirmation page, got %d", w.Code)
		}
		if w := b.do(http.MethodGet,
			"/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil); w.Code != http.StatusFound {
			t.Errorf("the confirmation page ended the session: GET /auth answered %d", w.Code)
		}
	})
}

// cookieNames lists the cookies a response set, in order.
func cookieNames(raw []string) []string {
	var names []string
	for _, c := range raw {
		name, _, _ := strings.Cut(c, "=")
		names = append(names, name)
	}
	return names
}
