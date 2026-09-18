package httpx

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestLoginPageBodyIsTheMeasuredMarkup compares themeLoginPageBody against a
// page taken off a live Keycloak 26.7.1, byte for byte, with the five values
// that cannot agree substituted rather than skipped.
//
// **The oracle is Keycloak and not this package.** A markup template checked
// against a string another function in the same file built is a template
// checked against nothing, which is the failure this project has already caught
// in a signature verifier. So the fixture is the recorded response itself, in
// testdata, and the five substitutions are named one at a time - a substitution
// list that grew silently would be this test giving up a byte at a time.
//
// The recording is docs/superpowers/handover/saml-sso-success.md's §1: the
// HTTP-Redirect binding's login page for gloak-probe-saml-unsigned, taken on
// 2026-09-18 from quay.io/keycloak/keycloak:26.7.1 start-dev on port 18091.
func TestLoginPageBodyIsTheMeasuredMarkup(t *testing.T) {
	want, err := os.ReadFile("testdata/keycloak-26.7.1-login-page.html")
	if err != nil {
		t.Fatalf("reading the recorded page: %v", err)
	}
	const (
		resource = "g1oyr"
		tabID    = "NUX9s1mXi-s"
		hash     = "aHVjHTb/dQhgygi8tpBmRujiwtMPYHf1qtLg7uDXKaINfm0NQXYVL/QITUb0qzLt"
		code     = "e-JN6ANICnU3HPUZHZiZeQYcWefpxyITlmLZpzbEh6s"
		clientID = "gloak-probe-saml-unsigned"
		data     = "eyJydSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9hY3MiLCJydCI6IklEX2dsb2FrX3Byb2JlIiwicm0iOiJwb3N0Iiwic3QiOiJnbG9hay1yZWxheSJ9"
		base     = "http://localhost:18091"
	)
	c := ThemeChrome{
		Realm:           "master",
		DisplayName:     "Keycloak",
		DisplayNameHTML: `<div class="kc-logo-text"><span>Keycloak</span></div>`,
		RestartParams: ThemeRestartParams(
			"client_id="+clientID, "tab_id="+tabID, "client_data="+data),
		AuthSessionHash: hash,
	}
	action := base + "/realms/master/login-actions/authenticate?" + strings.Join([]string{
		"session_code=" + code,
		"execution=8f74661e-7dd2-4988-b524-276494dc0589",
		"client_id=" + clientID,
		"tab_id=" + tabID,
		"client_data=" + data,
	}, "&")

	// The resource version is this process's and Keycloak's is the recording's,
	// which is the one value internal/conformance's ReplaceThemeResource exists
	// to make comparable. It is rewritten here for the same reason and with the
	// same pattern shape, rather than by asking the recording to change.
	got := regexp.MustCompile(`/resources/[0-9a-z]{5}/`).ReplaceAllString(
		themeLoginPageBody(c, action, ""), "/resources/"+resource+"/")

	if got != string(want) {
		t.Errorf("the login page differs from the recording:\n%s", firstDifference(got, string(want)))
	}
}

// firstDifference reports where two bodies part company, with enough either
// side to read. A whole-body diff in a test log is unreadable at 6931 bytes and
// the offset alone says nothing about what moved.
func firstDifference(got, want string) string {
	n := min(len(got), len(want))
	for i := range n {
		if got[i] != want[i] {
			from := max(i-80, 0)
			return "at byte " + itoa(i) + "\n got: " + quoteRun(got, from, i) +
				"\nwant: " + quoteRun(want, from, i)
		}
	}
	if len(got) == len(want) {
		return "nowhere: the bodies are equal"
	}
	return "one body is a prefix of the other: got " + itoa(len(got)) +
		" bytes, want " + itoa(len(want)) + " bytes\n got tail: " +
		quoteRun(got, n, min(n+120, len(got))) + "\nwant tail: " +
		quoteRun(want, n, min(n+120, len(want)))
}

func quoteRun(s string, from, at int) string {
	to := min(at+80, len(s))
	return strings.ReplaceAll(s[from:to], "\n", "\\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// TestLoginPageHeaderSetsAreTheTwoMeasuredOnes holds the split this cut found:
// one body, two endpoints, complementary header sets.
//
// Measured 2026-09-18 on one container. GET /realms/master/protocol/saml with
// an AuthnRequest that passes every rung answers the login page with a
// Cache-Control, a Content-Language and a Content-Type and **nothing else**;
// GET /realms/master/protocol/openid-connect/auth answers the same body with
// all five security headers and a Content-Security-Policy. The two pages differ
// only in the client_id, tab_id, client_data, session_code and session hash.
func TestLoginPageHeaderSetsAreTheTwoMeasuredOnes(t *testing.T) {
	c := ThemeChrome{Realm: "master", RestartParams: ThemeRestartParams("client_id=x", "tab_id=y")}
	for _, tc := range []struct {
		name  string
		write func(http.ResponseWriter)
		bare  bool
	}{
		{"oidc", func(w http.ResponseWriter) { WriteThemeLoginPage(w, c, "/a", "", "") }, false},
		{"saml", func(w http.ResponseWriter) { WriteThemeLoginPageBare(w, c, "/a", "", "") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.write(rec)
			if rec.Code != http.StatusOK {
				t.Errorf("status %d, want 200", rec.Code)
			}
			for _, shared := range []struct{ name, want string }{
				{"Cache-Control", "no-store, must-revalidate, max-age=0"},
				{"Content-Language", "en"},
				{"Content-Type", "text/html;charset=utf-8"},
			} {
				if got := rec.Header().Get(shared.name); got != shared.want {
					t.Errorf("%s = %q, want %q", shared.name, got, shared.want)
				}
			}
			for name := range securityHeaders {
				got := rec.Header().Get(name)
				if tc.bare && got != "" {
					t.Errorf("%s = %q on the SAML page, which sends none of the five", name, got)
				}
				if !tc.bare && got == "" {
					t.Errorf("%s is absent on the OIDC page, which sends all five", name)
				}
			}
			policy := rec.Header().Get("Content-Security-Policy")
			if tc.bare && policy != "" {
				t.Errorf("Content-Security-Policy = %q on the SAML page, which sends none", policy)
			}
			if !tc.bare && policy != ContentSecurityPolicy {
				t.Errorf("Content-Security-Policy = %q, want %q", policy, ContentSecurityPolicy)
			}
		})
	}
}

// TestSAMLLoginRedirectSendsNoneOfTheSix is the POST binding's half of the same
// measurement, on a response with no body at all.
//
// It is the finding worth a test of its own: the "none of the five" rule on
// /realms/{realm}/protocol/saml was measured on six 400 **pages**, so a reader
// could take it for a fact about that template. It is not - a 302 with an empty
// body carries it too - and the Cache-Control is the verb's `no-cache` rather
// than the `no-store` every other redirect in this file sends.
func TestSAMLLoginRedirectSendsNoneOfTheSix(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteSAMLLoginRedirect(rec, "http://localhost:8080/realms/master/login-actions/authenticate?client_id=x")
	if rec.Code != http.StatusFound {
		t.Errorf("status %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-cache")
	}
	if rec.Header().Get("Location") == "" {
		t.Error("no Location header")
	}
	if got := rec.Header().Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, and the measured 302 carries none at all", got)
	}
	for name := range securityHeaders {
		if got := rec.Header().Get(name); got != "" {
			t.Errorf("%s = %q, and this route sends none of the five", name, got)
		}
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, and this route sends none", got)
	}
	if body := rec.Body.String(); body != "" {
		t.Errorf("body is %d bytes, and the measured 302 is empty", len(body))
	}
}
