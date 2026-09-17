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

// The 204's X-Frame-Options is decided by an allow-list of three request media
// types, not by an `application/` prefix.
//
// The table is the 2026-09-06 re-sweep in WriteNoContent's doc comment, and the
// five rows that carry `application/` and answer without the header are what a
// prefix test cannot express. `application/json` and `application/yaml` sitting
// in one table is the pair that matters: a prefix test passes every other row
// here and fails those two together.
func TestWriteNoContentFramesThreeMediaTypesAndNoOthers(t *testing.T) {
	framed := []string{
		"application/json",
		"application/xml",
		"application/x-www-form-urlencoded",
		"application/json;charset=UTF-8",
		"APPLICATION/JSON",
		"Application/Json",
	}
	bare := []string{
		"",
		"*/*",
		"text/plain",
		"application/yaml",
		"application/yaml;charset=UTF-8",
		"application/YAML",
		"application/octet-stream",
		"application/pdf",
		"application/ld+json",
		// A space before the semicolon, measured to answer without the
		// header where the same value without the space carries it. It is
		// the row that says the parameters are cut and what is left is not
		// trimmed.
		"application/json ; charset=UTF-8",
	}

	send := func(contentType string) http.Header {
		w := httptest.NewRecorder()
		httpx.SetSecurityHeaders(w)
		r := httptest.NewRequest(http.MethodDelete, "/x", nil)
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		httpx.WriteNoContent(w, r)
		return w.Result().Header
	}

	for _, ct := range framed {
		if send(ct).Get("X-Frame-Options") == "" {
			t.Errorf("Content-Type %q: want X-Frame-Options", ct)
		}
	}
	for _, ct := range bare {
		if got := send(ct).Get("X-Frame-Options"); got != "" {
			t.Errorf("Content-Type %q: X-Frame-Options = %q, want it absent", ct, got)
		}
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

// redirectMediaTypeCells is the measured table both redirect writers answer,
// and it is shared so that the two tests below cannot come to disagree about
// what the rule is - which is how "it is this endpoint's redirect" was written
// down twice in the first place.
//
// Measured 2026-09-17 on a live 26.7.1, twice, on GET /auth and GET /logout
// alike, each on one 302 whose Location was byte-identical across every row.
// The two headers follow **two** allow-lists: three media types for
// X-Frame-Options and one for Content-Security-Policy, both with the
// parameters cut and not trimmed. application/json is the row that separates
// them and `application/json ; charset=UTF-8` is the row that says the space
// is not trimmed away.
var redirectMediaTypeCells = []struct {
	contentType string
	frame       bool
	policy      bool
}{
	{contentType: "", frame: false, policy: false},
	{contentType: "application/json", frame: true, policy: false},
	{contentType: "application/xml", frame: true, policy: false},
	{contentType: "application/x-www-form-urlencoded", frame: true, policy: true},
	{contentType: "application/json;charset=UTF-8", frame: true, policy: false},
	{contentType: "application/x-www-form-urlencoded;charset=UTF-8", frame: true, policy: true},
	{contentType: "application/json ; charset=UTF-8", frame: false, policy: false},
	{contentType: "application/ld+json", frame: false, policy: false},
	{contentType: "application/yaml", frame: false, policy: false},
	{contentType: "text/plain", frame: false, policy: false},
	{contentType: "*/*", frame: false, policy: false},
}

// checkRedirectCells runs the table against one writer, pinning the four
// headers that do not move as well as the two that do. The absences are as much
// of the contract as the presences: the router sets all five security headers
// before the handler runs, so a writer that stopped deleting X-Frame-Options
// would send it on every row, and one that set Content-Security-Policy
// unconditionally would too.
func checkRedirectCells(t *testing.T, location, cacheControl string,
	write func(http.ResponseWriter, *http.Request, string)) {
	t.Helper()
	for _, cell := range redirectMediaTypeCells {
		name := cell.contentType
		if name == "" {
			name = "(no Content-Type)"
		}
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/realms/master/probe", nil)
			if cell.contentType != "" {
				r.Header.Set("Content-Type", cell.contentType)
			}
			w := httptest.NewRecorder()
			// The router sets the five before any handler runs, so the test
			// starts the way the handler is really entered.
			httpx.SetSecurityHeaders(w)

			write(w, r, location)

			if w.Code != http.StatusFound {
				t.Errorf("status = %d, want 302", w.Code)
			}
			present := map[string]string{
				"Cache-Control":             cacheControl,
				"Location":                  location,
				"Referrer-Policy":           "no-referrer",
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options":    "nosniff",
				"X-Robots-Tag":              "none",
			}
			if cell.frame {
				present["X-Frame-Options"] = "SAMEORIGIN"
			}
			if cell.policy {
				present["Content-Security-Policy"] = httpx.ContentSecurityPolicy
			}
			for header, want := range present {
				if got := w.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
			absent := []string{"Content-Type"}
			if !cell.frame {
				absent = append(absent, "X-Frame-Options")
			}
			if !cell.policy {
				absent = append(absent, "Content-Security-Policy")
			}
			for _, header := range absent {
				if got, ok := w.Header()[header]; ok {
					t.Errorf("%s = %q, want absent", header, got)
				}
			}
			if body := w.Body.String(); body != "" {
				t.Errorf("body = %q, want empty", body)
			}
		})
	}
}

// TestWriteAuthorizationRedirect pins the header set measured on GET /auth's
// 302 back to the client, across the request media types that decide two of it.
func TestWriteAuthorizationRedirect(t *testing.T) {
	checkRedirectCells(t, "http://localhost:9999/callback?error=invalid_request",
		"no-store, must-revalidate, max-age=0", httpx.WriteAuthorizationRedirect)
}

// TestWriteLogoutRedirect pins the one value that separates the logout redirect
// from the authorization redirect, and everything that does not.
//
// Measured 2026-08-29 side by side on one container: both endpoints redirect a
// browser to a client's own registered URI and they disagree about
// Cache-Control alone. One shared writer taking that string as an argument is
// exactly what this test exists to make fail.
//
// The **rest** of that sentence used to read "both omit X-Frame-Options and
// Content-Security-Policy", and it was wrong on both endpoints: the omissions
// belonged to a request with no Content-Type, not to the redirect. Re-measured
// 2026-09-17, and the table is run twice here for that reason rather than
// inherited from the neighbour above.
func TestWriteLogoutRedirect(t *testing.T) {
	checkRedirectCells(t, "http://localhost:9999/callback?state=bye",
		"no-cache", httpx.WriteLogoutRedirect)
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

// TestWriteFormPostEscapesItsOwnWay pins the third escaping this package has,
// and pins it against the other two rather than on its own - which is the only
// way a shared-helper tidy-up gets caught.
//
// Measured 2026-09-06 with a state of a"b<c>d&e'f:
//
//	form_post          a&quot;b&lt;c&gt;d&amp;e&apos;f
//	theme title        a&quot;b&lt;c&gt;d&amp;e&#39;f     (Freemarker's)
//	html.EscapeString  a&#34;b&lt;c&gt;d&amp;e&#39;f
//
// So the single quote is where all three part company, and the double quote is
// where html.EscapeString parts from both.
func TestWriteFormPostEscapesItsOwnWay(t *testing.T) {
	w := httptest.NewRecorder()
	httpx.WriteFormPost(w, "http://localhost:9999/callback",
		map[string]string{"state": `a"b<c>d&e'f`}, "")
	const want = `VALUE="a&quot;b&lt;c&gt;d&amp;e&apos;f"`
	if !strings.Contains(w.Body.String(), want) {
		t.Errorf("body does not carry %s:\n%s", want, w.Body.String())
	}
	// The two spellings this must not be. Both appear in this repository and
	// both are right somewhere else.
	for _, wrong := range []string{"&#39;", "&#34;"} {
		if strings.Contains(w.Body.String(), wrong) {
			t.Errorf("body carries %s, which is another escaper's spelling", wrong)
		}
	}
}

// TestWriteFormPostScriptIsNotEscapedAndTheActionIs is one response with two
// escapings a few bytes apart, both measured.
func TestWriteFormPostScriptIsNotEscapedAndTheActionIs(t *testing.T) {
	w := httptest.NewRecorder()
	httpx.WriteFormPost(w, "http://localhost:9999/cb?a=1&b=2",
		map[string]string{"code": "x"},
		"http://localhost:8080/realms/master/login-actions/authenticate?client_id=p&tab_id=t")
	body := w.Body.String()
	if !strings.Contains(body, `ACTION="http://localhost:9999/cb?a=1&amp;b=2"`) {
		t.Errorf("the action is not escaped:\n%s", body)
	}
	if !strings.Contains(body,
		`"http://localhost:8080/realms/master/login-actions/authenticate?client_id=p&tab_id=t"`) {
		t.Errorf("the script's URL is escaped and the measured one is not:\n%s", body)
	}
}

// TestWriteFormPostHeadersAreNotTheThemes pins the two headers a reader would
// copy from the login page and be wrong about: the charset and the language.
func TestWriteFormPostHeadersAreNotTheThemes(t *testing.T) {
	w := httptest.NewRecorder()
	httpx.WriteFormPost(w, "http://localhost:9999/callback", map[string]string{"code": "x"}, "")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "text/html" {
		t.Errorf("Content-Type = %q, want text/html with no charset", got)
	}
	if got := w.Header().Get("Content-Language"); got != "" {
		t.Errorf("Content-Language = %q, want none", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store, must-revalidate, max-age=0" {
		t.Errorf("Cache-Control = %q", got)
	}
	for _, name := range []string{"Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag", "Content-Security-Policy"} {
		if w.Header().Get(name) == "" {
			t.Errorf("%s is missing", name)
		}
	}
}
