package conformance

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestGoldenIsAssertedFollowsTheStatus pins the predicate both sides of the
// harness read: the recorder to decide what it may rewrite, TestConformance to
// decide what it compares. Getting the two out of step is the failure F69 is
// about, in the other direction - a golden rewritten by a run that nothing
// then checks.
func TestGoldenIsAssertedFollowsTheStatus(t *testing.T) {
	for _, tt := range []struct {
		status Status
		want   bool
	}{
		{Implemented, true},
		{Recorded, true},
		{Pending, false},
	} {
		if got := GoldenIsAsserted(Case{Status: tt.status}); got != tt.want {
			t.Errorf("status %d: want %v, got %v", tt.status, tt.want, got)
		}
	}
}

// TestNoPendingGoldenIsCompared is the same claim read off the catalogue rather
// than off three constructed cases, so that a status added later without a rule
// here fails rather than passing by default.
//
// Seven Pending cases carry a golden today. Four of them are the login-theme
// pages whose whole body churns per container start; the other three are stable
// bodies that were measured and parked. Every one of them has to come back
// false, or `make record` is rewriting a file no test reads.
func TestNoPendingGoldenIsCompared(t *testing.T) {
	parked := 0
	for _, c := range Catalog {
		if c.Status != Pending {
			continue
		}
		if GoldenIsAsserted(c) {
			t.Errorf("%q: Pending, so nothing compares its golden, "+
				"but the recorder would rewrite it", c.ID)
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); err == nil {
			parked++
		}
	}
	// A rule about parked goldens over a catalogue holding none asserts
	// nothing. The pollution guard fails the same way for the same reason.
	if parked == 0 {
		t.Fatal("no Pending case has a golden, so this test has stopped checking anything; " +
			"either they were all promoted or the goldens were removed, and both are worth reading about")
	}
}

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
