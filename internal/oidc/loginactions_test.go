package oidc_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// The browser flow's tests drive the real router with a real cookie jar,
// because every claim in this file is about what carries state from one request
// to the next. A test that reached into the handler's maps would pass while the
// cookie that makes it work was misspelled.

// browser is a cookie jar and the handler it talks to.
type browser struct {
	h    http.Handler
	t    *testing.T
	jar  map[string]string
	raw  []string
	last *httptest.ResponseRecorder
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	return &browser{h: authServer(t), t: t, jar: map[string]string{}}
}

// do sends one request with the jar applied and folds the response's cookies
// back in.
//
// A cookie cleared with Max-Age=0 is stored as an empty value rather than
// deleted, which is what internal/conformance's jar does and what a browser
// that has not yet expired it sends. It is also what makes the KC_RESTART
// branch in writeUnusableSession reachable from a test at all.
func (b *browser) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	if form != nil {
		return b.doRaw(method, target, form.Encode())
	}
	return b.send(httptest.NewRequest(method, target, strings.NewReader("")))
}

// doRaw is do with the body written verbatim, which is the only way to send one
// that will not form-decode. url.Values cannot express a bad percent escape.
func (b *browser) doRaw(method, target, body string) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.send(req)
}

func (b *browser) send(req *http.Request) *httptest.ResponseRecorder {
	b.t.Helper()
	if len(b.jar) > 0 {
		pairs := make([]string, 0, len(b.jar))
		for name, value := range b.jar {
			pairs = append(pairs, name+"="+value)
		}
		req.Header.Set("Cookie", strings.Join(pairs, "; "))
	}
	w := httptest.NewRecorder()
	b.h.ServeHTTP(w, req)
	for _, raw := range w.Header().Values("Set-Cookie") {
		b.raw = append(b.raw, raw)
		name, rest, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		value, _, _ := strings.Cut(rest, ";")
		b.jar[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	b.last = w
	return w
}

// login runs GET /auth and returns the login form's action.
func (b *browser) login(overrides map[string]string) string {
	b.t.Helper()
	w := b.do(http.MethodGet,
		"/realms/master/protocol/openid-connect/auth?"+baseQuery(overrides), nil)
	if w.Code != http.StatusOK {
		b.t.Fatalf("GET /auth: want 200, got %d", w.Code)
	}
	return formAction(b.t, w.Body.String())
}

// credentials is the three fields the measured login page carries.
func credentials(username, password string) url.Values {
	return url.Values{"username": {username}, "password": {password}, "credentialId": {""}}
}

var actionRe = regexp.MustCompile(`<form[^>]*\baction="([^"]*)"`)

// formAction pulls the first form's action out of a page and unescapes it, the
// way internal/conformance's tokeniser does.
func formAction(t *testing.T, body string) string {
	t.Helper()
	m := actionRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no <form action=> in the page (%d bytes)", len(body))
	}
	return strings.NewReplacer("&amp;", "&", "&quot;", `"`).Replace(m[1])
}

// actionParams splits an action URL into its target path-with-query and its
// parsed parameters.
func actionParams(t *testing.T, action string) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(action)
	if err != nil {
		t.Fatalf("parse action %q: %v", action, err)
	}
	return u.Path + "?" + u.RawQuery, u.Query()
}

// TestBrowserLoginMintsACode is the whole flow, and it asserts the four places
// one measured value has to appear.
//
// **The root authentication session id is the session_state.** On a live
// 26.7.1 login the same 24-character string is inside AUTH_SESSION_ID, is the
// redirect's session_state, is KEYCLOAK_IDENTITY's sid and is the
// authorization code's second part. A design that minted session_state at
// login time rather than at GET /auth would get all four wrong together, and
// no conformance case would see it: every one of them masks Location and
// Set-Cookie as volatile.
func TestBrowserLoginMintsACode(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)

	// The action's five parameters, in the measured order.
	if got := strings.Join(paramOrder(t, action), ","); got != "session_code,execution,client_id,tab_id,client_data" {
		t.Errorf("action parameter order: got %s", got)
	}
	for name, want := range map[string]int{"session_code": 43, "tab_id": 11} {
		if got := len(params.Get(name)); got != want {
			t.Errorf("%s: want %d characters, got %d (%q)", name, want, got, params.Get(name))
		}
	}

	w := b.do(http.MethodPost, target, credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("login: want 302, got %d\n%s", w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	rawQuery := strings.TrimPrefix(location, probeRedirectURI+"?")
	if rawQuery == location {
		t.Fatalf("login did not redirect to the registered URI: %s", location)
	}
	// Measured: state, session_state, iss, code - which is **not** the order the
	// same four parameters take inside a form_post body.
	var keys []string
	for _, pair := range strings.Split(rawQuery, "&") {
		k, _, _ := strings.Cut(pair, "=")
		keys = append(keys, k)
	}
	if got := strings.Join(keys, ","); got != "state,session_state,iss,code" {
		t.Errorf("redirect key order: got %s", got)
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("parse redirect query: %v", err)
	}
	sessionState := q.Get("session_state")
	parts := strings.Split(q.Get("code"), ".")
	if len(parts) != 3 {
		t.Fatalf("code has %d parts, want 3: %q", len(parts), q.Get("code"))
	}
	if parts[1] != sessionState {
		t.Errorf("code part 2: want the session_state %q, got %q", sessionState, parts[1])
	}
	// Part 1 is laid out like a UUID and is not one, so its shape is asserted
	// and its version and variant nibbles deliberately are not.
	if !regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`).MatchString(parts[0]) {
		t.Errorf("code part 1 is not UUID-shaped: %q", parts[0])
	}

	// AUTH_SESSION_ID decodes to "<session_state>.<opaque>".
	decoded, err := base64.RawURLEncoding.DecodeString(b.jar["AUTH_SESSION_ID"])
	if err != nil {
		t.Fatalf("AUTH_SESSION_ID is not base64url: %v", err)
	}
	root, secret, ok := strings.Cut(string(decoded), ".")
	if !ok {
		t.Fatalf("AUTH_SESSION_ID does not decode to <root>.<secret>: %q", decoded)
	}
	if root != sessionState {
		t.Errorf("AUTH_SESSION_ID root: want the session_state %q, got %q", sessionState, root)
	}
	if len(secret) != 86 {
		t.Errorf("AUTH_SESSION_ID secret: want 86 characters, got %d", len(secret))
	}

	// KEYCLOAK_IDENTITY's sid is the same value again, and its typ is measured.
	claims := identityClaims(t, b.jar["KEYCLOAK_IDENTITY"])
	if claims["sid"] != sessionState {
		t.Errorf("KEYCLOAK_IDENTITY sid: want %q, got %v", sessionState, claims["sid"])
	}
	if claims["typ"] != "Serialized-ID" {
		t.Errorf("KEYCLOAK_IDENTITY typ: want Serialized-ID, got %v", claims["typ"])
	}
}

// paramOrder returns an action's query keys in the order they were written,
// which url.Values cannot report.
func paramOrder(t *testing.T, action string) []string {
	t.Helper()
	_, raw, ok := strings.Cut(action, "?")
	if !ok {
		t.Fatalf("action carries no query: %q", action)
	}
	var out []string
	for _, pair := range strings.Split(raw, "&") {
		k, _, _ := strings.Cut(pair, "=")
		out = append(out, k)
	}
	return out
}

func identityClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("KEYCLOAK_IDENTITY is not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode identity payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("parse identity payload: %v", err)
	}
	return claims
}

// TestLoginCookiesCarryKeycloaksSpelling pins the attribute spelling, which
// net/http's own http.SetCookie cannot produce: no space after the semicolon,
// a leading Version=1, and KC_AUTH_SESSION_HASH's value in double quotes.
//
// The conformance suite cannot catch any of this. Every case in the flow masks
// Set-Cookie as volatile, so a cookie whose attributes were all wrong would
// still be "present" and still pass.
func TestLoginCookiesCarryKeycloaksSpelling(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)

	authCookies := b.last.Header().Values("Set-Cookie")
	want := []string{
		`AUTH_SESSION_ID=`,
		`KC_AUTH_SESSION_HASH="`,
		`KC_RESTART=`,
	}
	if len(authCookies) != 3 {
		t.Fatalf("GET /auth set %d cookies, want 3: %q", len(authCookies), authCookies)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(authCookies[i], prefix) {
			t.Errorf("cookie %d: want a %s, got %q", i, prefix, authCookies[i])
		}
	}
	for _, c := range authCookies {
		if strings.Contains(c, "; ") {
			t.Errorf("cookie has a space after a semicolon, Keycloak sends none: %q", c)
		}
		if !strings.Contains(c, ";Version=1;") {
			t.Errorf("cookie is missing Version=1: %q", c)
		}
		if !strings.Contains(c, ";Path=/realms/master/;") &&
			!strings.HasSuffix(c, ";Path=/realms/master/") {
			t.Errorf("cookie Path is not /realms/master/ with its trailing slash: %q", c)
		}
	}
	// KC_AUTH_SESSION_HASH is the one cookie whose value is quoted, the one that
	// omits HttpOnly, and the one carrying Max-Age=60.
	hash := authCookies[1]
	if !strings.Contains(hash, ";Max-Age=60;") {
		t.Errorf("KC_AUTH_SESSION_HASH: want Max-Age=60, got %q", hash)
	}
	if strings.Contains(hash, "HttpOnly") {
		t.Errorf("KC_AUTH_SESSION_HASH: measured without HttpOnly, got %q", hash)
	}
	if !strings.Contains(authCookies[0], ";HttpOnly;") {
		t.Errorf("AUTH_SESSION_ID: measured with HttpOnly, got %q", authCookies[0])
	}

	target, _ := actionParams(t, action)
	b.do(http.MethodPost, target, credentials("admin", "admin"))
	loginCookies := b.last.Header().Values("Set-Cookie")
	if len(loginCookies) != 3 {
		t.Fatalf("the login set %d cookies, want 3: %q", len(loginCookies), loginCookies)
	}
	// Measured order, and the clear comes first.
	if got := strings.TrimSpace(loginCookies[0]); got != "KC_RESTART=;Version=1;Path=/realms/master/;Max-Age=0" {
		t.Errorf("KC_RESTART clear: got %q", got)
	}
	if !strings.HasPrefix(loginCookies[1], "KEYCLOAK_IDENTITY=") {
		t.Errorf("cookie 1: want KEYCLOAK_IDENTITY, got %q", loginCookies[1])
	}
	if !strings.Contains(loginCookies[2], ";Max-Age=36000;") {
		t.Errorf("KEYCLOAK_SESSION: want Max-Age=36000, got %q", loginCookies[2])
	}

	// KEYCLOAK_SESSION is KC_AUTH_SESSION_HASH's value in the other base64
	// alphabet. Measured byte for byte; minting a second random value is the
	// obvious implementation and it breaks a client that compares the two.
	hashValue := strings.Trim(strings.SplitN(strings.SplitN(hash, "=", 2)[1], ";", 2)[0], `"`)
	sessionValue := strings.SplitN(strings.SplitN(loginCookies[2], "=", 2)[1], ";", 2)[0]
	if want := strings.NewReplacer("+", "-", "/", "_").Replace(hashValue); sessionValue != want {
		t.Errorf("KEYCLOAK_SESSION: want %q (the hash in base64url), got %q", want, sessionValue)
	}
}

// TestLoginRedirectKeepsTheHeadersAuthDrops is the difference this cut's
// conformance cases now assert and nothing asserted before.
//
// Two 302s, to the same URI, in the same flow, with the same status: /auth's
// omits X-Frame-Options and Content-Security-Policy and this one carries both.
// It is not "errors omit them" and not "302s omit them" - it is per endpoint.
func TestLoginRedirectKeepsTheHeadersAuthDrops(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, _ := actionParams(t, action)
	login := b.do(http.MethodPost, target, credentials("admin", "admin"))

	for _, h := range []string{"X-Frame-Options", "Content-Security-Policy"} {
		if login.Header().Get(h) == "" {
			t.Errorf("the login redirect is missing %s", h)
		}
	}
	if got := login.Header().Get("Cache-Control"); got != "no-store, must-revalidate, max-age=0" {
		t.Errorf("login redirect Cache-Control: got %q", got)
	}
	if login.Body.Len() != 0 {
		t.Errorf("the login redirect has a body: %q", login.Body)
	}

	// The control, on the same handler: /auth's own redirect drops both.
	rejected := authorize(t, b.h, baseQuery(map[string]string{"response_type": absent}))
	if rejected.Code != http.StatusFound {
		t.Fatalf("control: want a 302 from /auth, got %d", rejected.Code)
	}
	for _, h := range []string{"X-Frame-Options", "Content-Security-Policy"} {
		if rejected.Header().Get(h) != "" {
			t.Errorf("/auth's redirect sends %s, which is measured absent", h)
		}
	}
}

// TestLoginPageEnvelope pins the 200's headers, including the Cache-Control
// that /auth's own page family measurably does **not** send.
func TestLoginPageEnvelope(t *testing.T) {
	b := newBrowser(t)
	b.login(nil)
	w := b.last
	for header, want := range map[string]string{
		"Content-Type":            "text/html;charset=utf-8",
		"Content-Language":        "en",
		"Cache-Control":           "no-store, must-revalidate, max-age=0",
		"Content-Security-Policy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
		"X-Frame-Options":         "SAMEORIGIN",
	} {
		if got := w.Header().Get(header); got != want {
			t.Errorf("login page %s: want %q, got %q", header, want, got)
		}
	}
	// The three inputs the measured page carries, and no others.
	body := w.Body.String()
	for _, name := range []string{`name="username"`, `name="password"`, `name="credentialId"`} {
		if !strings.Contains(body, name) {
			t.Errorf("login page is missing an input %s", name)
		}
	}
	if n := strings.Count(body, "<form"); n != 1 {
		t.Errorf("login page has %d forms, the measured one has 1", n)
	}
}

// TestThemeErrorPageCacheControlIsPerEndpoint is the third value this page has
// been measured with, and all three were taken side by side on one container.
//
// It is the reason WriteThemeErrorPage takes the value as an argument. A writer
// that hard-coded any one of the three would be wrong on the other two.
func TestThemeErrorPageCacheControlIsPerEndpoint(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)

	// /login-actions: no-store, must-revalidate, max-age=0.
	broken := replaceParam(target, params, "client_data", "!!!!")
	w := b.do(http.MethodPost, broken, credentials("admin", "admin"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad client_data: want 400, got %d", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store, must-revalidate, max-age=0" {
		t.Errorf("/login-actions 400 page Cache-Control: got %q", got)
	}

	// /auth: none at all.
	page := authorize(t, b.h, baseQuery(map[string]string{"client_id": "nosuch"}))
	if page.Code != http.StatusBadRequest {
		t.Fatalf("control: want 400 from /auth, got %d", page.Code)
	}
	if got := page.Header().Get("Cache-Control"); got != "" {
		t.Errorf("/auth's 400 page sends Cache-Control %q, measured to send none", got)
	}
}

// replaceParam rewrites one query parameter of an action URL, keeping the rest
// in their measured order.
func replaceParam(target string, params url.Values, name, value string) string {
	path, _, _ := strings.Cut(target, "?")
	out := make([]string, 0, len(params))
	for _, key := range []string{"session_code", "execution", "client_id", "tab_id", "client_data"} {
		v, ok := params[key]
		if key == name {
			if value == absent {
				continue
			}
			out = append(out, key+"="+url.QueryEscape(value))
			continue
		}
		if !ok {
			continue
		}
		out = append(out, key+"="+url.QueryEscape(v[0]))
	}
	return path + "?" + strings.Join(out, "&")
}

// TestLoginActionRejectionOrder drives two faults at once, the way
// TestAuthorizeRejectionOrder does, and asserts the earlier check wins.
//
// Each row is measured against a live 26.7.1; see section 1.5 of
// docs/superpowers/plans/2026-08-30-p13-login.md. The outcomes are spelled as
// the status and the branch, since the prose Gloak serves is still a
// placeholder.
func TestLoginActionRejectionOrder(t *testing.T) {
	const badCode = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	const badExec = "11111111-1111-1111-1111-111111111111"

	tests := []struct {
		name    string
		params  map[string]string
		cookies []string // cookie names to drop
		want    int
		branch  string
	}{
		{"bad client_data alone", map[string]string{"client_data": "!!!!"}, nil, 400, "page"},
		{"bad client_data beats a missing client_id",
			map[string]string{"client_data": "!!!!", "client_id": absent}, nil, 400, "page"},
		{"bad client_data beats missing cookies",
			map[string]string{"client_data": "!!!!"}, []string{"AUTH_SESSION_ID", "KC_RESTART"}, 400, "page"},
		{"bad client_data beats a bad session_code",
			map[string]string{"client_data": "!!!!", "session_code": badCode}, nil, 400, "page"},
		{"no cookies at all is the page, not a restart",
			nil, []string{"AUTH_SESSION_ID", "KC_RESTART"}, 400, "page"},
		{"no cookies beats an unknown client_id",
			map[string]string{"client_id": "nosuch"}, []string{"AUTH_SESSION_ID", "KC_RESTART"}, 400, "page"},
		{"a missing client_id beats a bad session_code",
			map[string]string{"client_id": absent, "session_code": badCode}, nil, 400, "page"},
		{"a bad session_code restarts when KC_RESTART is there",
			map[string]string{"session_code": badCode}, nil, 302, "restart"},
		{"a bad session_code beats a wrong password",
			map[string]string{"session_code": badCode}, nil, 302, "restart"},
		{"a bad execution is a 200 page, not a 400",
			map[string]string{"execution": badExec}, nil, 200, "expired"},
		{"a bad execution beats a wrong password",
			map[string]string{"execution": badExec}, nil, 200, "expired"},
		{"a client that is not this tab's is the page",
			map[string]string{"client_id": "probe-implicit"}, nil, 400, "page"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			action := b.login(nil)
			target, params := actionParams(t, action)
			for name, value := range tc.params {
				target = replaceParam(target, params, name, value)
				_, params = actionParams(t, "http://x"+target)
			}
			for _, name := range tc.cookies {
				delete(b.jar, name)
			}
			password := "admin"
			if strings.Contains(tc.name, "wrong password") {
				password = "nope"
			}
			w := b.do(http.MethodPost, target, credentials("admin", password))
			if w.Code != tc.want {
				t.Fatalf("want %d, got %d\n%s", tc.want, w.Code, w.Body)
			}
			switch tc.branch {
			case "restart":
				loc := w.Header().Get("Location")
				if !strings.Contains(loc, "/login-actions/authenticate?") {
					t.Errorf("want a restart redirect, got %q", loc)
				}
				if strings.Contains(loc, "session_code=") {
					t.Errorf("the restart redirect carries a session_code, measured to carry none: %q", loc)
				}
			case "expired":
				if !strings.Contains(w.Body.String(), "Page has expired") {
					t.Errorf("want the expired page, got %q", w.Body)
				}
			case "page":
				if !strings.Contains(w.Body.String(), "We are sorry...") {
					t.Errorf("want the theme error page, got %q", w.Body)
				}
			}
		})
	}
}

// TestUnusableAuthSessionHasThreeAnswers is the grid measured 2026-08-30: the
// code is spent by completing a login, then the three cookies are varied
// independently.
//
// The two rules it pins are the ones a reader would assume away. **KC_RESTART
// wins over everything**, so a browser that still holds one restarts rather
// than being told anything; and **an empty KC_RESTART counts as absent**,
// which is the state the successful login itself leaves behind.
func TestUnusableAuthSessionHasThreeAnswers(t *testing.T) {
	tests := []struct {
		name    string
		keep    []string
		want    int
		wantLoc string
	}{
		{"KC_RESTART restarts", []string{"AUTH_SESSION_ID", "KC_RESTART", "KEYCLOAK_IDENTITY"},
			302, "/login-actions/authenticate?"},
		{"KC_RESTART restarts without an identity", []string{"KC_RESTART"},
			302, "/login-actions/authenticate?"},
		{"an identity alone tells the client", []string{"KEYCLOAK_IDENTITY"},
			302, "error=temporarily_unavailable&error_description=authentication_expired"},
		{"an identity with a spent auth cookie tells the client",
			[]string{"AUTH_SESSION_ID", "KEYCLOAK_IDENTITY"},
			302, "error=temporarily_unavailable&error_description=authentication_expired"},
		{"neither is the page", []string{"AUTH_SESSION_ID"}, 400, ""},
		{"nothing at all is the page", nil, 400, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			action := b.login(nil)
			target, _ := actionParams(t, action)
			// Keep a copy of the pre-login jar: the login clears KC_RESTART, and
			// the branch under test needs the un-cleared value.
			before := map[string]string{}
			for k, v := range b.jar {
				before[k] = v
			}
			if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
				t.Fatalf("setup login: want 302, got %d", w.Code)
			}
			full := map[string]string{}
			for k, v := range before {
				full[k] = v
			}
			for k, v := range b.jar {
				if v != "" {
					full[k] = v
				}
			}
			b.jar = map[string]string{}
			for _, name := range tc.keep {
				if v, ok := full[name]; ok {
					b.jar[name] = v
				}
			}
			w := b.do(http.MethodPost, target, credentials("admin", "admin"))
			if w.Code != tc.want {
				t.Fatalf("want %d, got %d\n%s", tc.want, w.Code, w.Body)
			}
			if tc.wantLoc != "" && !strings.Contains(w.Header().Get("Location"), tc.wantLoc) {
				t.Errorf("Location: want it to contain %q, got %q", tc.wantLoc, w.Header().Get("Location"))
			}
		})
	}
}

// TestEmptyRestartCookieCountsAsAbsent is the measurement the grid above rests
// on, isolated so that it fails on its own.
//
// The successful login clears KC_RESTART with Max-Age=0. A browser that has not
// yet expired it sends `KC_RESTART=`, and Keycloak answers such a request the
// **client** redirect rather than a restart - which is why the observed
// document's unconditioned "a replayed session_code redirects" is right for a
// browser and wrong in general.
func TestEmptyRestartCookieCountsAsAbsent(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, _ := actionParams(t, action)
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("setup login: want 302, got %d", w.Code)
	}
	if b.jar["KC_RESTART"] != "" {
		t.Fatalf("the login did not clear KC_RESTART: %q", b.jar["KC_RESTART"])
	}
	w := b.do(http.MethodPost, target, credentials("admin", "admin"))
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=temporarily_unavailable") {
		t.Errorf("a replay with a cleared KC_RESTART: want the client redirect, got %q", loc)
	}
	if !strings.HasPrefix(loc, probeRedirectURI+"?") {
		t.Errorf("the expiry redirect did not go to the registered URI: %q", loc)
	}
	// The measured key order, the same four keys /auth's own rejections use.
	rawQuery := strings.TrimPrefix(loc, probeRedirectURI+"?")
	var keys []string
	for _, pair := range strings.Split(rawQuery, "&") {
		k, _, _ := strings.Cut(pair, "=")
		keys = append(keys, k)
	}
	if got := strings.Join(keys, ","); got != "error,error_description,state,iss" {
		t.Errorf("expiry redirect key order: got %s", got)
	}
}

// TestWrongPasswordRotatesTheSessionCode is measured: the page comes back with
// a new session_code while execution, tab_id and client_data stay the same, the
// username is echoed, and the retry with the rotated code succeeds while the
// old one does not.
func TestWrongPasswordRotatesTheSessionCode(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)

	w := b.do(http.MethodPost, target, credentials("admin", "nope"))
	if w.Code != http.StatusOK {
		t.Fatalf("wrong password: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid username or password.") {
		t.Errorf("wrong password: the page carries no feedback message")
	}
	if !strings.Contains(w.Body.String(), `value="admin"`) {
		t.Errorf("wrong password: the username is not echoed back into the form")
	}

	retryTarget, retry := actionParams(t, formAction(t, w.Body.String()))
	if retry.Get("session_code") == params.Get("session_code") {
		t.Errorf("the session_code was not rotated")
	}
	for _, name := range []string{"execution", "tab_id", "client_data"} {
		if retry.Get(name) != params.Get(name) {
			t.Errorf("%s changed across the failed attempt: %q then %q",
				name, params.Get(name), retry.Get(name))
		}
	}
	// The new code works.
	ok := b.do(http.MethodPost, retryTarget, credentials("admin", "admin"))
	if ok.Code != http.StatusFound || !strings.Contains(ok.Header().Get("Location"), "code=") {
		t.Fatalf("the retry with the rotated code did not log in: %d %q",
			ok.Code, ok.Header().Get("Location"))
	}

	// And the rotated-away one does not - checked on a second browser, because
	// spending a stale code takes the restart branch, which mints the jar a new
	// authentication session and would invalidate the retry above.
	b2 := newBrowser(t)
	stale, _ := actionParams(t, b2.login(nil))
	b2.do(http.MethodPost, stale, credentials("admin", "nope"))
	old := b2.do(http.MethodPost, stale, credentials("admin", "admin"))
	if old.Code == http.StatusFound &&
		strings.HasPrefix(old.Header().Get("Location"), probeRedirectURI) {
		t.Errorf("the rotated-away session_code still logged in")
	}
}

// TestCredentialFailuresAllSayTheSameThing guards the property that keeps this
// endpoint from being an account-enumeration oracle, and which is measured on
// six different requests.
func TestCredentialFailuresAllSayTheSameThing(t *testing.T) {
	for name, form := range map[string]url.Values{
		"wrong password":   credentials("admin", "nope"),
		"unknown username": credentials("nosuchuser", "admin"),
		"empty username":   credentials("", "admin"),
		"empty password":   credentials("admin", ""),
		"no fields at all": {},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBrowser(t)
			target, _ := actionParams(t, b.login(nil))
			w := b.do(http.MethodPost, target, form)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), "Invalid username or password.") {
				t.Errorf("want the shared message, got %q", w.Body)
			}
		})
	}
}

// TestUsernameIsCaseInsensitive is measured: ADMIN logs in.
func TestUsernameIsCaseInsensitive(t *testing.T) {
	b := newBrowser(t)
	target, _ := actionParams(t, b.login(nil))
	w := b.do(http.MethodPost, target, credentials("ADMIN", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("ADMIN: want 302, got %d\n%s", w.Code, w.Body)
	}
}

// TestClientDataIsParsedAndIgnored is the security-relevant measurement in this
// flow, and it is measured three ways.
//
// A client_data naming another redirect URI still redirects to the registered
// one; one naming another state still echoes the original; one adding
// rm=fragment still puts the parameters in the query. The authentication
// session is the authority and the browser's copy is not - so a handler that
// read the redirect URI out of client_data would let a forged one redirect a
// user anywhere.
func TestClientDataIsParsedAndIgnored(t *testing.T) {
	encode := func(t *testing.T, v map[string]string) string {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	tests := []struct {
		name string
		data map[string]string
	}{
		{"another redirect URI", map[string]string{
			"ru": "http://evil.example/cb", "rt": "code", "st": "xyz123"}},
		{"another state", map[string]string{
			"ru": probeRedirectURI, "rt": "code", "st": "TAMPERED"}},
		{"an added response mode", map[string]string{
			"ru": probeRedirectURI, "rt": "code", "rm": "fragment", "st": "xyz123"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			action := b.login(nil)
			target, params := actionParams(t, action)
			target = replaceParam(target, params, "client_data", encode(t, tc.data))
			w := b.do(http.MethodPost, target, credentials("admin", "admin"))
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, probeRedirectURI+"?") {
				t.Fatalf("client_data moved the redirect: %q", loc)
			}
			if !strings.Contains(loc, "state=xyz123") {
				t.Errorf("client_data changed the echoed state: %q", loc)
			}
		})
	}
}

// TestForgedClientDataCannotRedirectAnywhere guards the one branch where
// client_data is read for something.
//
// On the expiry branch the authentication session that held the redirect URI
// has been destroyed, so the browser's own copy is the only record of where the
// request came from. That makes it the one place a forged client_data could
// steer a redirect - so the value it names is still checked against the
// client's registered patterns, and a target the client could not have asked
// for itself falls through to the page instead.
func TestForgedClientDataCannotRedirectAnywhere(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("setup login: want 302, got %d", w.Code)
	}
	forged, err := json.Marshal(map[string]string{
		"ru": "http://attacker.example/steal", "rt": "code", "st": "xyz123"})
	if err != nil {
		t.Fatal(err)
	}
	w := b.do(http.MethodPost,
		replaceParam(target, params, "client_data", base64.RawURLEncoding.EncodeToString(forged)),
		credentials("admin", "admin"))
	if loc := w.Header().Get("Location"); strings.Contains(loc, "attacker.example") {
		t.Fatalf("a forged client_data redirected the browser to %q", loc)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("want the page when the forged target does not validate, got %d", w.Code)
	}
}

// TestClientDataIsOptionalButMustParse is the pair of measurements that says
// client_data is a hint rather than an input: dropping it succeeds, and
// corrupting it is a 400.
func TestClientDataIsOptionalButMustParse(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)
	w := b.do(http.MethodPost, replaceParam(target, params, "client_data", absent),
		credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("client_data dropped: want 302, got %d\n%s", w.Code, w.Body)
	}

	b2 := newBrowser(t)
	action2 := b2.login(nil)
	target2, params2 := actionParams(t, action2)
	bad := b2.do(http.MethodPost, replaceParam(target2, params2, "client_data", "!!!!"),
		credentials("admin", "admin"))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("client_data corrupted: want 400, got %d", bad.Code)
	}
}

// TestParametersComeFromTheQueryAndCredentialsFromTheBody is the mirror of
// /auth, which on a POST reads the body and ignores the query.
//
// r.Form merges the two and would hide both halves of this.
func TestParametersComeFromTheQueryAndCredentialsFromTheBody(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	_, params := actionParams(t, action)

	// Everything in the body, nothing in the query: the parameters are not read.
	form := credentials("admin", "admin")
	for key, values := range params {
		form.Set(key, values[0])
	}
	w := b.do(http.MethodPost, "/realms/master/login-actions/authenticate", form)
	if w.Code == http.StatusFound && strings.HasPrefix(w.Header().Get("Location"), probeRedirectURI) {
		t.Errorf("the parameters were read from the body; measured, they are query-only")
	}

	// The credentials in the query, nothing in the body: they are not read.
	b2 := newBrowser(t)
	target2, _ := actionParams(t, b2.login(nil))
	w2 := b2.do(http.MethodPost, target2+"&username=admin&password=admin", nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("credentials in the query: want the re-served page, got %d", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), "Invalid username or password.") {
		t.Errorf("credentials in the query were accepted; measured, they are body-only")
	}
}

// TestGetAttemptsTheLogin is the measurement that a GET here is not a read: it
// answers exactly as a POST with empty credentials does, page and all.
func TestGetAttemptsTheLogin(t *testing.T) {
	b := newBrowser(t)
	target, params := actionParams(t, b.login(nil))
	w := b.do(http.MethodGet, target, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid username or password.") {
		t.Errorf("GET did not attempt the login: %q", w.Body)
	}
	// And it spent the code, the way the POST would have.
	after := actionParamsOf(t, w.Body.String())
	if after.Get("session_code") == params.Get("session_code") {
		t.Errorf("the GET did not rotate the session_code")
	}
}

func actionParamsOf(t *testing.T, body string) url.Values {
	t.Helper()
	_, params := actionParams(t, formAction(t, body))
	return params
}

// TestRepeatedQueryParameterIsNotAnErrorHere is the opposite of /auth, where
// any key sent twice - including one the endpoint never reads - answers
// `duplicated parameter`. Measured on three keys here, all of which succeed.
func TestRepeatedQueryParameterIsNotAnErrorHere(t *testing.T) {
	for _, extra := range []string{"&zz=1&zz=2", "&tab_id=other", "&session_code=nonsense"} {
		t.Run(extra, func(t *testing.T) {
			b := newBrowser(t)
			target, _ := actionParams(t, b.login(nil))
			w := b.do(http.MethodPost, target+extra, credentials("admin", "admin"))
			if w.Code != http.StatusFound ||
				!strings.HasPrefix(w.Header().Get("Location"), probeRedirectURI) {
				t.Fatalf("a repeated parameter refused the login: %d %q",
					w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// TestResponseModeFragmentSurvivesTheLogin: the mode is carried on the
// authentication session, so the code lands where the authorization request
// asked for it and not where client_data claims.
func TestResponseModeFragmentSurvivesTheLogin(t *testing.T) {
	b := newBrowser(t)
	target, _ := actionParams(t, b.login(map[string]string{"response_mode": "fragment"}))
	w := b.do(http.MethodPost, target, credentials("admin", "admin"))
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, probeRedirectURI+"#") {
		t.Fatalf("response_mode=fragment: want the code in the fragment, got %q", loc)
	}
}

// TestTwoTabsShareOneSession is measured: a second GET /auth on one jar does
// not move AUTH_SESSION_ID, both tabs get their own tab_id and session_code,
// and both logins succeed reporting the same session_state.
func TestTwoTabsShareOneSession(t *testing.T) {
	b := newBrowser(t)
	first := b.login(map[string]string{"state": "A"})
	cookie := b.jar["AUTH_SESSION_ID"]
	second := b.login(map[string]string{"state": "B"})
	if b.jar["AUTH_SESSION_ID"] != cookie {
		t.Errorf("the second authorization request moved AUTH_SESSION_ID")
	}
	// Measured: the first GET /auth sets three cookies and a second one on the
	// same jar sets **only KC_RESTART**, because the authentication session is
	// reused and only the record of the latest authorization request moves.
	repeat := b.last.Header().Values("Set-Cookie")
	if len(repeat) != 1 || !strings.HasPrefix(repeat[0], "KC_RESTART=") {
		t.Errorf("the second GET /auth set %q, want KC_RESTART alone", repeat)
	}
	_, p1 := actionParams(t, first)
	_, p2 := actionParams(t, second)
	if p1.Get("tab_id") == p2.Get("tab_id") {
		t.Errorf("two tabs share a tab_id")
	}
	if p1.Get("session_code") == p2.Get("session_code") {
		t.Errorf("two tabs share a session_code")
	}

	t1, _ := actionParams(t, first)
	w1 := b.do(http.MethodPost, t1, credentials("admin", "admin"))
	if w1.Code != http.StatusFound {
		t.Fatalf("tab A: want 302, got %d", w1.Code)
	}
	if !strings.Contains(w1.Header().Get("Location"), "state=A") {
		t.Errorf("tab A got the wrong state: %q", w1.Header().Get("Location"))
	}
}

// TestUnknownRealmIsTheProtocolSpelling: this endpoint is on the protocol side,
// so a missing realm is `Realm does not exist` with no full stop, not the admin
// API's `Realm not found.`.
func TestUnknownRealmIsTheProtocolSpelling(t *testing.T) {
	b := newBrowser(t)
	w := b.do(http.MethodPost, "/realms/nosuch/login-actions/authenticate", credentials("admin", "admin"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"Realm does not exist"}` {
		t.Errorf("body: got %s", got)
	}
}

// TestRestartRedirectLandsOnALoginPage: the restart is a real round trip, so
// following it has to serve a form. A redirect to a tab that does not exist
// would loop.
func TestRestartRedirectLandsOnALoginPage(t *testing.T) {
	b := newBrowser(t)
	action := b.login(nil)
	target, params := actionParams(t, action)
	w := b.do(http.MethodPost, replaceParam(target, params, "session_code", "nonsense"),
		credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("want a restart 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse %q: %v", loc, err)
	}
	landing := b.do(http.MethodGet, u.Path+"?"+u.RawQuery, nil)
	if landing.Code != http.StatusOK {
		t.Fatalf("following the restart: want 200, got %d\n%s", landing.Code, landing.Body)
	}
	// And the form it serves works.
	retryTarget, _ := actionParams(t, formAction(t, landing.Body.String()))
	ok := b.do(http.MethodPost, retryTarget, credentials("admin", "admin"))
	if ok.Code != http.StatusFound || !strings.Contains(ok.Header().Get("Location"), "code=") {
		t.Fatalf("the restarted login did not complete: %d %q",
			ok.Code, ok.Header().Get("Location"))
	}
}

// TestClientDataKeyOrderAndStateRule pins what the login form hands the browser.
//
// The key order is ru, rt, rm, st; `rm` appears only when the authorization
// request named a response_mode; and `st` follows /auth's own state rule -
// absent when no state was sent, present and empty when `state=` was. A
// `json:",omitempty"` on the state would emit three keys where Keycloak emits
// four.
func TestClientDataKeyOrderAndStateRule(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]string
		want      string
	}{
		{"plain", nil, `{"ru":"` + probeRedirectURI + `","rt":"code","st":"xyz123"}`},
		{"with a response mode", map[string]string{"response_mode": "fragment"},
			`{"ru":"` + probeRedirectURI + `","rt":"code","rm":"fragment","st":"xyz123"}`},
		{"no state", map[string]string{"state": absent},
			`{"ru":"` + probeRedirectURI + `","rt":"code"}`},
		{"an empty state", map[string]string{"state": ""},
			`{"ru":"` + probeRedirectURI + `","rt":"code","st":""}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			_, params := actionParams(t, b.login(tc.overrides))
			raw, err := base64.RawURLEncoding.DecodeString(params.Get("client_data"))
			if err != nil {
				t.Fatalf("client_data is not unpadded base64url: %v", err)
			}
			if string(raw) != tc.want {
				t.Errorf("client_data:\nwant %s\ngot  %s", tc.want, raw)
			}
		})
	}
}

// TestExecutionIsStableAcrossLogins is measured: `execution` is the same value
// on every login in one container while the other four action parameters vary
// per request. A per-request execution would look right in one transcript.
func TestExecutionIsStableAcrossLogins(t *testing.T) {
	b := newBrowser(t)
	_, first := actionParams(t, b.login(nil))
	b2 := newBrowser(t)
	_, alien := actionParams(t, b2.login(nil))
	_, second := actionParams(t, b.login(nil))

	if first.Get("execution") != second.Get("execution") {
		t.Errorf("execution moved between two logins in one realm: %q then %q",
			first.Get("execution"), second.Get("execution"))
	}
	if first.Get("tab_id") == second.Get("tab_id") {
		t.Errorf("tab_id did not move between two logins")
	}
	// A different realm - here, a different bootstrapped store - gets its own.
	if alien.Get("execution") == first.Get("execution") {
		t.Errorf("two realms share an execution id")
	}
}

// The three instructions the /login-actions family's 400 page carries, measured
// 2026-09-02 across all twelve call sites that reach it. They are spelled here
// rather than imported so that a change to the constant fails a test that says
// what the sentence is.
const (
	instrInvalidRequest = "Invalid Request"
	instrClientFailed   = "An error occurred, please login again through your application."
	instrNoRestart      = "Restart login cookie not found. It may have expired; it may have been " +
		"deleted or cookies are disabled in your browser. If cookies are disabled then enable them. " +
		"Click Back to Application to login again."
)

// TestLoginActionErrorPageInstructions is F109's twelve, one branch at a time.
//
// **Twelve call sites, three sentences.** The mapping is the whole of what F109
// asked for and it is not the one a reader would guess: the four ways a client
// can fail - unknown, absent, empty, and a real client that is not the tab's -
// collapse into **one** sentence here, where GET /auth splits the same four into
// three. Guessing would have produced three sentences on this endpoint too.
func TestLoginActionErrorPageInstructions(t *testing.T) {
	const la = "/realms/master/login-actions/authenticate"
	const ra = "/realms/master/login-actions/required-action"
	const co = "/realms/master/login-actions/consent"

	tests := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"authenticate, unparseable client_data", http.MethodGet,
			la + "?client_id=probe&tab_id=zz&client_data=%21%21%21%21", instrInvalidRequest},
		{"required-action, unparseable client_data", http.MethodGet,
			ra + "?client_id=probe&tab_id=zz&client_data=%21%21%21%21", instrInvalidRequest},
		{"consent, unparseable client_data", http.MethodPost,
			co + "?client_id=probe&tab_id=zz&client_data=%21%21%21%21", instrInvalidRequest},
		{"authenticate, nothing to restart from", http.MethodGet,
			la + "?client_id=probe&tab_id=zz&client_data=e30", instrNoRestart},
		{"required-action, nothing to restart from", http.MethodGet,
			ra + "?client_id=probe&tab_id=zz&client_data=e30", instrNoRestart},
		// An unknown client_id does not reach the client check: the session is
		// judged first and answers about the cookie. Measured on both.
		{"authenticate, an unknown client is still the cookie", http.MethodGet,
			la + "?client_id=nosuch&tab_id=zz&client_data=e30", instrNoRestart},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(tc.method, tc.target, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d\n%s", w.Code, w.Body)
			}
			assertInstruction(t, w.Body.String(), tc.want)
		})
	}

	// The client branch needs a live tab, because the only way to reach it is to
	// get past the session check with a client that is not this tab's.
	t.Run("authenticate, a real client that is not the tab's", func(t *testing.T) {
		b := newBrowser(t)
		target, params := actionParams(t, b.login(nil))
		w := b.do(http.MethodPost, replaceParam(target, params, "client_id", "probe-home"),
			credentials("admin", "admin"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d\n%s", w.Code, w.Body)
		}
		assertInstruction(t, w.Body.String(), instrClientFailed)
	})
	t.Run("required-action, a real client that is not the tab's", func(t *testing.T) {
		h, s := authServerAndStore(t)
		b := &browser{h: h, t: t, jar: map[string]string{}}
		setActions(t, s, "UPDATE_PASSWORD")
		landing := b.browserAt(t, "")
		u, err := url.Parse(landing)
		if err != nil {
			t.Fatalf("parse landing %q: %v", landing, err)
		}
		q := u.Query()
		q.Set("client_id", "probe-home")
		w := b.do(http.MethodGet, u.Path+"?"+q.Encode(), nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d\n%s", w.Code, w.Body)
		}
		assertInstruction(t, w.Body.String(), instrClientFailed)
	})
}

var instructionRe = regexp.MustCompile(`<p class="instruction">([^<]*)</p>`)

// assertInstruction reads the login-error template's one instruction paragraph.
func assertInstruction(t *testing.T, body, want string) {
	t.Helper()
	m := instructionRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no <p class=\"instruction\"> in the page (%d bytes)", len(body))
	}
	if m[1] != want {
		t.Errorf("instruction:\n got %q\nwant %q", m[1], want)
	}
}

// TestLoginActionErrorPageNamesTheRequestsClient is the half of F109 nothing had
// measured: which client the page's restart URL names.
//
// **It is the request's own client_id, not the tab's**, and the branch that
// makes that visible is the one whose sentence says the client failed. A page
// that read the chrome off the tab would name the right client on five of the
// six cells and the wrong one on the sixth, which is the cell nobody would build
// a fixture for.
func TestLoginActionErrorPageNamesTheRequestsClient(t *testing.T) {
	const la = "/realms/master/login-actions/authenticate"
	tests := []struct {
		name     string
		clientID string
		want     string // the restart URL's query, before skip_logout
		link     string
	}{
		{"a client with a baseUrl", "probe-home", "client_id=probe-home&", "http://abs.example/home"},
		{"a client without one", "probe", "client_id=probe&", ""},
		{"a client carrying a rootUrl alone", "probe-rootonly", "client_id=probe-rootonly&", ""},
		{"an unknown client", "nosuch", "", ""},
		{"an empty client_id", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			w := b.do(http.MethodGet,
				la+"?client_id="+url.QueryEscape(tc.clientID)+"&tab_id=zz&client_data=e30", nil)
			assertChrome(t, w.Body.String(), tc.want, tc.link)
		})
	}
	t.Run("an absent client_id", func(t *testing.T) {
		b := newBrowser(t)
		w := b.do(http.MethodGet, la+"?tab_id=zz&client_data=e30", nil)
		assertChrome(t, w.Body.String(), "", "")
	})
	// The cell that separates "the request's client" from "the tab's client".
	t.Run("a real client that is not the tab's", func(t *testing.T) {
		b := newBrowser(t)
		target, params := actionParams(t, b.login(nil))
		w := b.do(http.MethodPost, replaceParam(target, params, "client_id", "probe-home"),
			credentials("admin", "admin"))
		assertChrome(t, w.Body.String(), "client_id=probe-home&", "http://abs.example/home")
	})
}

// assertChrome checks the restart URL's parameters and the Back to Application
// link, which are the two things the page's chrome is.
func assertChrome(t *testing.T, body, wantParams, wantLink string) {
	t.Helper()
	want := `"/realms/master/login-actions/restart?` + wantParams + `skip_logout=true"`
	if !strings.Contains(body, want) {
		t.Errorf("restart URL: want the page to contain %s", want)
	}
	link := strings.Contains(body, `id="backToApplication" href="`+wantLink+`"`)
	if wantLink == "" {
		if strings.Contains(body, "backToApplication") {
			t.Errorf("want no Back to Application link, got one")
		}
		return
	}
	if !link {
		t.Errorf("Back to Application: want href %q", wantLink)
	}
}

// TestUnparseableBodyIsA500OnTheLoginActionEndpoints is the four of F109's
// twelve sites that are not this page at all, and the order that reaches them.
//
// Measured 2026-09-02: a body carrying a bad percent escape answers 500 with
// application/json and the same 94 bytes POST /auth and POST /logout answer, on
// all three /login-actions endpoints. That is five endpoints on one rule, and
// the first time the rule was found by measuring a branch rather than by
// probing an endpoint.
//
// **The order is the second half of the finding.** The decode beats bad
// client_data, missing cookies and an unknown client, and loses only to the
// realm - so it is not the endpoint's own judgement. Gloak called ParseForm
// four levels down and answered the 400 page on three of those four rows.
func TestUnparseableBodyIsA500OnTheLoginActionEndpoints(t *testing.T) {
	const badBody = "a=1&%zz=2"
	paths := map[string]string{
		"authenticate":    "/realms/master/login-actions/authenticate",
		"required-action": "/realms/master/login-actions/required-action",
		"consent":         "/realms/master/login-actions/consent",
	}
	queries := map[string]string{
		"plain":             "?client_id=probe&tab_id=zz&client_data=e30",
		"bad client_data":   "?client_id=probe&tab_id=zz&client_data=%21%21%21%21",
		"an unknown client": "?client_id=nosuch&tab_id=zz&client_data=e30",
		"no parameters":     "",
	}
	for name, path := range paths {
		for qname, query := range queries {
			t.Run(name+", "+qname, func(t *testing.T) {
				b := newBrowser(t)
				w := b.doRaw(http.MethodPost, path+query, badBody)
				assertUnparseableBody(t, w)
			})
		}
	}

	// **The 500 here is not byte-identical to POST /auth's**, and the byte is a
	// Cache-Control. Measured side by side: /auth sends none and this sends the
	// family's own value, on responses that agree on everything else.
	t.Run("the Cache-Control is this endpoint's, not /auth's", func(t *testing.T) {
		b := newBrowser(t)
		here := b.doRaw(http.MethodPost, "/realms/master/login-actions/authenticate", badBody)
		if got := here.Header().Get("Cache-Control"); got != "no-store, must-revalidate, max-age=0" {
			t.Errorf("/login-actions 500 Cache-Control: got %q", got)
		}
		there := b.doRaw(http.MethodPost, "/realms/master/protocol/openid-connect/auth", badBody)
		if there.Code != http.StatusInternalServerError {
			t.Fatalf("control: want 500 from POST /auth, got %d", there.Code)
		}
		if got := there.Header().Get("Cache-Control"); got != "" {
			t.Errorf("POST /auth's 500 sends Cache-Control %q, measured to send none", got)
		}
	})

	// The realm is the one check that beats it: an unknown realm with the same
	// body answers the protocol side's 404 rather than the 500.
	t.Run("the realm wins", func(t *testing.T) {
		b := newBrowser(t)
		w := b.doRaw(http.MethodPost, "/realms/gloak-no-such-realm/login-actions/authenticate", badBody)
		if w.Code != http.StatusNotFound {
			t.Fatalf("an unknown realm with a bad body: want 404, got %d\n%s", w.Code, w.Body)
		}
	})

	// And a live tab reaches the same answer, which is the cell the four call
	// sites actually sat on.
	t.Run("a live tab", func(t *testing.T) {
		b := newBrowser(t)
		target, _ := actionParams(t, b.login(nil))
		assertUnparseableBody(t, b.doRaw(http.MethodPost, target, badBody))
	})
}

func assertUnparseableBody(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d\n%s", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", got)
	}
	const want = `{"error":"unknown_error","error_description":` +
		`"For more on this error consult the server log."}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("body:\n got %s\nwant %s", got, want)
	}
}
