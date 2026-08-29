package conformance

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSessionReachesTheCasesOwnRequest is the guard on the bug that recorded a
// 400 theme page as oidc/authorization/code-flow-redirect's contract.
//
// A case's own request is built and sent by the recorder and by the verifier,
// not by RunFixture, so before Session existed it left the fixture's cookies
// behind - and a credential POST with no authentication session is refused.
// The two call sites are in _test files behind their own machinery, so this
// asserts the piece they share.
func TestSessionReachesTheCasesOwnRequest(t *testing.T) {
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{Method: http.MethodGet, Path: "/login"},
		// A GET has to capture something to earn its place, and capturing the
		// form's action is what the real login step does.
		CaptureForm: map[string]string{"action": "action"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		w.Header().Add("Set-Cookie", "AUTH_SESSION_ID=abc;Path=/realms/master/")
		_, _ = w.WriteString(`<form action="/realms/master/login-actions/authenticate?session_code=s"></form>`)
		w.WriteHeader(200)
		return w.Result(), nil
	}

	sess, err := Run(f, "http://localhost:8080", do)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if sess.Vars["action"] != "/realms/master/login-actions/authenticate?session_code=s" {
		t.Fatalf("the action did not survive the run: %q", sess.Vars["action"])
	}
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080"+sess.Vars["action"], nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	sess.Apply(req)
	if got := req.Header.Get("Cookie"); got != "AUTH_SESSION_ID=abc" {
		t.Fatalf("the case's own request carries no session: %q", got)
	}
}

func TestSessionApplyToleratesNoSession(t *testing.T) {
	// Every case runs through Apply, including the many whose fixture never
	// sees a cookie. A nil or empty session must leave the request alone
	// rather than setting an empty Cookie header, which is a header Keycloak
	// would have to be measured against and nobody has.
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/x", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	(*Session)(nil).Apply(req)
	(&Session{Cookies: map[string]string{}}).Apply(req)

	if _, ok := req.Header["Cookie"]; ok {
		t.Fatalf("an empty session set a Cookie header: %q", req.Header.Get("Cookie"))
	}
}
