package conformance

import (
	"net/http"
	"strings"
	"testing"
)

// TestBuildRequestSendsOneKeyTwice is F48: Request.Query is a
// map[string]string, so until RawQuery existed no case could send a key twice,
// and an entire measured error family - `duplicated parameter`, step 7 of the
// authorization endpoint's ten - was served, unit-tested in internal/oidc, and
// under no golden.
//
// The assertion is on what the server would parse, not on the string, because
// the string is only interesting for what net/http does with it.
func TestBuildRequestSendsOneKeyTwice(t *testing.T) {
	req, err := buildRequest("http://localhost:8080", Request{
		Method:   http.MethodGet,
		Path:     "/realms/master/protocol/openid-connect/auth",
		RawQuery: "client_id=gloak-probe-browser&zz=1&zz=2",
	})
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	got := req.URL.Query()["zz"]
	if len(got) != 2 || got[0] != "1" || got[1] != "2" {
		t.Fatalf("want zz sent twice as 1 then 2, got %q", got)
	}
	if req.URL.Query().Get("client_id") != "gloak-probe-browser" {
		t.Errorf("the rest of the query was lost: %q", req.URL.RawQuery)
	}
}

// A raw query is sent as written: not sorted, not escaped. url.Values.Encode
// does both - it would put aa before zz and turn the slash into %2F - and a
// case whose subject is how the server reads the query it was given needs
// neither done for it.
func TestBuildRequestSendsARawQueryVerbatim(t *testing.T) {
	const raw = "zz=2&aa=1&redirect_uri=http://localhost:9999/callback"
	req, err := buildRequest("http://localhost:8080", Request{
		Method:   http.MethodGet,
		Path:     "/realms/master/protocol/openid-connect/auth",
		RawQuery: raw,
	})
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.URL.RawQuery != raw {
		t.Fatalf("the query was rewritten: %q", req.URL.RawQuery)
	}
}

// Query and RawQuery together have no honest merge: url.Values.Encode sorts,
// so appending one to the other would put the repeated key wherever the sort
// left it, and the authorization endpoint's answer to a repeat depends on what
// else is in the request. A loud refusal beats picking an order.
func TestBuildRequestRefusesBothQueryForms(t *testing.T) {
	_, err := buildRequest("http://localhost:8080", Request{
		Method:   http.MethodGet,
		Path:     "/realms/master/protocol/openid-connect/auth",
		Query:    map[string]string{"client_id": "gloak-probe-browser"},
		RawQuery: "zz=1&zz=2",
	})
	if err == nil {
		t.Fatal("a case setting both query forms was built rather than refused")
	}
	if !strings.Contains(err.Error(), "RawQuery") {
		t.Errorf("the error should name the field: %v", err)
	}
}

// The existing spelling has to keep working: a case with neither field sends no
// "?" at all, which is what the fixture steps capturing a form action rely on.
func TestBuildRequestSendsNoQuestionMarkWithoutAQuery(t *testing.T) {
	req, err := buildRequest("http://localhost:8080", Request{
		Method: http.MethodGet,
		Path:   "/realms/master",
	})
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if strings.Contains(req.URL.String(), "?") {
		t.Fatalf("an empty query added a separator: %q", req.URL.String())
	}
}
