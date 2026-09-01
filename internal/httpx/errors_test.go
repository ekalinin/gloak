package httpx_test

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/httpx"
)

// TestWriteJSONOmitsDateHeader proves Gloak sends no Date header, matching
// Keycloak 26.7.1, which sends none on any response. This cannot be proven
// with httptest.NewRecorder as every other test in this file uses: a
// ResponseRecorder never adds a Date header itself, so it can't tell a
// suppressed header from one net/http would have added anyway. A real
// http.Server does add one automatically unless the handler suppresses it,
// so this test needs httptest.NewServer.
func TestWriteJSONOmitsDateHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Date"); got != "" {
		t.Fatalf("want no Date header, got %q", got)
	}
}

// TestWriteBearerChallengeOmitsDateHeader is TestWriteJSONOmitsDateHeader's
// counterpart for the one response shape that does not go through writeJSON.
func TestWriteBearerChallengeOmitsDateHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, "master", "invalid_token", "Token verification failed")
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Date"); got != "" {
		t.Fatalf("want no Date header, got %q", got)
	}
}

// TestWriteNoContentOmitsDateHeader is the third of these, and the one that
// was missing while the rule it guards was false.
//
// Every 204 Gloak sent carried a Date header until this was added: the two
// tests above both go through writeJSON, and a 204 has no body to go through
// it. It was found by reading a live PUT .../default-groups/{id} off the wire
// while measuring P4, not by any test - which is the same blind spot the
// conformance harness has, since ResponseRecorder adds no Date either.
func TestWriteNoContentOmitsDateHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteNoContent(w, r)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("want 204, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Date"); got != "" {
		t.Fatalf("want no Date header, got %q", got)
	}
}

func TestWriteOAuthError(t *testing.T) {
	w := httptest.NewRecorder()

	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid user credentials")

	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `{"error":"invalid_grant","error_description":"Invalid user credentials"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteMessageError(t *testing.T) {
	// Shape 2: a bare error field holding prose, not an OAuth code.
	w := httptest.NewRecorder()

	httpx.WriteMessageError(w, http.StatusNotFound, "Realm not found.")

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm not found."}`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteAdminError(t *testing.T) {
	// Shape 3: errorMessage, used for admin conflicts and validation.
	w := httptest.NewRecorder()

	httpx.WriteAdminError(w, http.StatusConflict, "Client gloak-probe already exists")

	if w.Code != 409 {
		t.Fatalf("want 409, got %d", w.Code)
	}
	want := `{"errorMessage":"Client gloak-probe already exists"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteJSONCharset(t *testing.T) {
	// Realm info's success response carries a charset, unlike every other
	// JSON endpoint recorded so far.
	w := httptest.NewRecorder()

	httpx.WriteJSONCharset(w, http.StatusOK, map[string]string{"realm": "master"})

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json;charset=UTF-8"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `{"realm":"master"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteBearerChallenge(t *testing.T) {
	// userinfo with a bad token: 401, text/plain, empty body, error in the header.
	w := httptest.NewRecorder()

	httpx.WriteBearerChallenge(w, http.StatusUnauthorized, "master", "invalid_token", "Token verification failed")

	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if got := w.Body.Len(); got != 0 {
		t.Fatalf("want an empty body, got %d bytes: %q", got, w.Body.String())
	}
	if got, want := w.Header().Get("Content-Type"), "text/plain;charset=utf-8"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	// Read the header through the exact map key WriteBearerChallenge sets,
	// not Header.Get: Get canonicalises its argument to "Www-Authenticate"
	// before looking it up, which would miss the literal "WWW-Authenticate"
	// key this function deliberately sets. See WriteBearerChallenge's doc
	// comment and TestWriteBearerChallengeSendsKeycloaksHeaderCasing below.
	want := `Bearer realm="master", error="invalid_token", error_description="Token verification failed"`
	got := w.Header()["WWW-Authenticate"]
	if len(got) != 1 || got[0] != want {
		t.Fatalf("want [%s], got %v", want, got)
	}
}

// TestWriteBearerChallengeSendsKeycloaksHeaderCasing proves the header
// reaches the wire spelled "WWW-Authenticate", matching Keycloak 26.7.1, not
// "Www-Authenticate", the form Header.Set would produce. http.Get cannot
// distinguish the two: textproto.Reader canonicalises every header name it
// parses, so a client-side read always shows the canonical form regardless
// of what was actually sent. This test reads the raw bytes off the
// connection instead, the same class of blind spot as the Date header
// (TestWriteJSONOmitsDateHeader above), just on the client-parsing side
// rather than the server-writing side.
func TestWriteBearerChallengeSendsKeycloaksHeaderCasing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteBearerChallenge(w, http.StatusUnauthorized, "master", "invalid_token", "Token verification failed")
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req := "GET / HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if !bytes.Contains(raw, []byte("\r\nWWW-Authenticate:")) {
		t.Fatalf("want the wire header spelled WWW-Authenticate, got:\n%s", raw)
	}
	if bytes.Contains(raw, []byte("\r\nWww-Authenticate:")) {
		t.Fatalf("header was canonicalised to Www-Authenticate on the wire:\n%s", raw)
	}
}

func TestNoTrailingNewline(t *testing.T) {
	// Verify that no trailing newline is present in the JSON body,
	// regardless of payload size. This test uses a large error description
	// to ensure the payload is interesting.
	w := httptest.NewRecorder()

	longDescription := "This is a very long error description that might span multiple chunks if not handled correctly. " +
		"It contains lots of characters to make the JSON output large enough to be interesting. " +
		"The json.Encoder.Encode method appends a trailing newline, and we must strip it."
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", longDescription)

	body := w.Body.String()

	// Verify the body ends with }
	if len(body) == 0 || body[len(body)-1] != '}' {
		t.Fatalf("body must end with }, got: %q", body)
	}

	// Verify no newline exists anywhere in the body
	for i, ch := range body {
		if ch == '\n' {
			t.Fatalf("body contains newline at position %d: %q", i, body)
		}
	}
}

// TestWriteAuthorizationRedirect pins the header set measured on GET /auth's
// 302 back to the client. The absences are the contract: the router sets all
// five security headers before the handler runs, so an implementation that
// simply stopped deleting X-Frame-Options would send six headers where
// Keycloak sends four.
func TestWriteAuthorizationRedirect(t *testing.T) {
	w := httptest.NewRecorder()
	// The router sets the five before any handler runs, so the test starts the
	// way the handler is really entered.
	httpx.SetSecurityHeaders(w)

	httpx.WriteAuthorizationRedirect(w, "http://localhost:9999/callback?error=invalid_request")

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	present := map[string]string{
		"Cache-Control":             "no-store, must-revalidate, max-age=0",
		"Location":                  "http://localhost:9999/callback?error=invalid_request",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Robots-Tag":              "none",
	}
	for name, want := range present {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"X-Frame-Options", "Content-Security-Policy", "Content-Type"} {
		if got, ok := w.Header()[name]; ok {
			t.Errorf("%s = %q, want absent", name, got)
		}
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty", body)
	}
}

// TestWriteLogoutRedirect pins the one value that separates the logout redirect
// from the authorization redirect, and the four that do not.
//
// Measured 2026-08-29 side by side on one container: both endpoints redirect a
// browser to a client's own registered URI, both omit X-Frame-Options and
// Content-Security-Policy, and they disagree about Cache-Control alone. One
// shared writer taking that string as an argument is exactly what this test
// exists to make fail.
func TestWriteLogoutRedirect(t *testing.T) {
	w := httptest.NewRecorder()
	httpx.SetSecurityHeaders(w)

	httpx.WriteLogoutRedirect(w, "http://localhost:9999/callback?state=bye")

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	present := map[string]string{
		"Cache-Control":             "no-cache",
		"Location":                  "http://localhost:9999/callback?state=bye",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Robots-Tag":              "none",
	}
	for name, want := range present {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, name := range []string{"X-Frame-Options", "Content-Security-Policy", "Content-Type"} {
		if got, ok := w.Header()[name]; ok {
			t.Errorf("%s = %q, want absent", name, got)
		}
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("body = %q, want empty", body)
	}
}

// TestWriteThemePageCacheControl pins the disagreement between the two
// endpoints that serve the theme's pages: /auth sends no Cache-Control at all
// and /logout sends no-cache. Both directions are asserted, because a writer
// that always set the header and one that never set it would each pass a test
// checking only the other one.
func TestWriteThemePageCacheControl(t *testing.T) {
	chrome := httpx.ThemeChrome{Realm: "master"}
	none := httptest.NewRecorder()
	httpx.WriteThemeErrorPage(none, http.StatusBadRequest, "", chrome, "Invalid Request")
	if got, ok := none.Header()["Cache-Control"]; ok {
		t.Errorf("Cache-Control = %q, want absent for the authorization endpoint", got)
	}

	cached := httptest.NewRecorder()
	httpx.WriteThemeErrorPage(cached, http.StatusBadRequest, "no-cache", chrome, "Invalid Request")
	if got := cached.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q for the logout endpoint", got, "no-cache")
	}
	if none.Body.String() != cached.Body.String() {
		t.Errorf("the two pages differ in body:\n%q\n%q", none.Body, cached.Body)
	}
}

// TestWriteThemePageTitle guards the placeholder's one variable part. A 200
// carrying "We are sorry..." would say the request failed where it succeeded,
// which is the mistake one hard-coded body makes.
func TestWriteThemePageTitle(t *testing.T) {
	w := httptest.NewRecorder()
	httpx.WriteThemePage(w, http.StatusOK, "no-cache", "You are logged out")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<title>You are logged out</title>") {
		t.Errorf("body has no title: %q", body)
	}
	if strings.Contains(body, httpx.ThemeErrorTitle) {
		t.Errorf("body carries the error page's title: %q", body)
	}
	envelope := map[string]string{
		"Content-Type":            "text/html;charset=utf-8",
		"Content-Language":        "en",
		"Content-Security-Policy": "frame-src 'self'; frame-ancestors 'self'; object-src 'none';",
		"X-Frame-Options":         "SAMEORIGIN",
	}
	for name, want := range envelope {
		if got := w.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestFrameSrcPolicyIsTheMeasuredBytes pins the front-channel logout page's
// Content-Security-Policy, which is the one theme page whose policy is computed
// per response.
//
// Read off the wire with `od -c` on 2026-08-31, on a session holding two
// front-channel clients registered at the same host. The two details that a
// tidier implementation would lose are a duplicate host and a space.
func TestFrameSrcPolicyIsTheMeasuredBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hosts []string
		want  string
	}{
		{
			// No front-channel client, so the page is every other theme page.
			name: "none",
			want: httpx.ContentSecurityPolicy,
		},
		{
			name:  "one",
			hosts: []string{"localhost:9998"},
			want:  "frame-src 'self' localhost:9998 ; frame-ancestors 'self'; object-src 'none';",
		},
		{
			// The same host twice, which is what two clients on one host
			// produced. De-duplicating is the tidy-up that changes a byte.
			name:  "two on one host",
			hosts: []string{"localhost:9998", "localhost:9998"},
			want: "frame-src 'self' localhost:9998 localhost:9998 ; " +
				"frame-ancestors 'self'; object-src 'none';",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpx.FrameSrcPolicy(tc.hosts); got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestWriteThemePagePolicyKeepsTheEnvelope pins that the page with its own
// policy has every other header the eight measured theme pages have. The two
// writers share writeThemeHTMLPolicy for exactly this reason.
func TestWriteThemePagePolicyKeepsTheEnvelope(t *testing.T) {
	plain := httptest.NewRecorder()
	httpx.WriteThemePage(plain, http.StatusOK, "no-cache", "Logging out")
	computed := httptest.NewRecorder()
	httpx.WriteThemePagePolicy(computed, http.StatusOK, "no-cache", "Logging out",
		httpx.FrameSrcPolicy([]string{"localhost:9998"}))

	if plain.Code != computed.Code {
		t.Errorf("status %d vs %d", plain.Code, computed.Code)
	}
	if plain.Body.String() != computed.Body.String() {
		t.Error("the bodies differ; only the policy was meant to")
	}
	for name := range plain.Header() {
		if name == "Content-Security-Policy" {
			continue
		}
		if got, want := computed.Header().Get(name), plain.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if len(plain.Header()) != len(computed.Header()) {
		t.Errorf("header counts differ: %v vs %v", plain.Header(), computed.Header())
	}
	if computed.Header().Get("Content-Security-Policy") == httpx.ContentSecurityPolicy {
		t.Error("the computed policy is the constant; the page would be indistinguishable")
	}
}
