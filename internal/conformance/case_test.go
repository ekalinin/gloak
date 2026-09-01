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
// false, or `make record` is rewriting a file no test reads. Which seven, and
// why each is kept, is parkedGoldens.
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

// parkedGoldens is F72's answer: a Pending case **may** carry a golden, and it
// has to say so here.
//
// The file is a measurement, not a contract. Nothing compares it - a Pending
// case is skipped whether or not a golden exists - so it does not say what
// Gloak must serve, and nothing notices when Keycloak's answer moves underneath
// it. What it is for is reading: the measured status, headers and body of an
// endpoint this project has not built yet, without a container and without
// Docker. That is worth keeping and worth being unable to mistake for a
// contract, which is what a declared list buys that a bare file does not.
//
// The way to make one a contract is to promote the case to Recorded. That is
// what Recorded already means - measured, committed, not served yet, and the
// verifier requires it *not* to match - and it is a one-word edit a reviewer
// sees in the diff. There is no flag, here or in the recorder (F69).
//
// An eighth cannot appear by accident: a Pending case that grows a golden file
// without an entry here fails, and an entry naming a case that is no longer
// Pending, or whose file has gone, fails too. So the list can only be changed
// on purpose, and changing it is where the reason gets written down.
var parkedGoldens = map[string]string{
	"oidc/authorization/invalid-redirect-uri": "the keycloak.v2 theme's 400 error page; the /resources/<hash>/ " +
		"segment in the body is minted per container start, so these bytes are one container's rather than " +
		"a reproducible value - read the page's shape, its status and its headers, not that segment",
	"oidc/authorization/unknown-client-id": "the same theme page for the other half of the page family, " +
		"kept because the two differ in their instruction and nothing else",
	"oidc/logout/invalid-post-logout-redirect-uri": "the logout endpoint's copy of that page, which is the " +
		"only record in the repository that it carries Cache-Control: no-cache where the authorization " +
		"endpoint's carries none",
	"oidc/logout/invalid-id-token-hint": "the third instruction the 400 page serves, and the one that pins " +
		"the hint being judged before the redirect URI",
	// The device and CIBA entries were here until 2026-08-30 and both are gone
	// rather than moved: their cases are Implemented, so their goldens are
	// compared and the whole point of parking is that nothing compares them.
	// The device one's request has moved too - it measured the refusal on
	// admin-cli, which is now oidc/device/grant-disabled's, while
	// oidc/device/authorization-request measures the grant with a client that
	// has it on.
	"oidc/authorization/prompt-create": "the registration page, and the one record that /auth's " +
		"own page family disagrees with itself about Cache-Control - this one sends it where the " +
		"400 beside it does not",
	"oidc/authorization/max-age-invalid": "the other half of that pair, and the reason the " +
		"variable is the rejection rather than the endpoint",
	"oidc/device/verification-page": "the page whose own form cannot be submitted, because the two " +
		"device paths are one endpoint - read it for the form's action, which is the measurement",
	"oidc/device/status-page": "the end of a completed device login, kept for its two headings",
	// The dynamic-registration entry was here until 2026-08-31 and is gone
	// rather than moved, for the same reason the device and CIBA ones went:
	// oidc/registration/without-initial-access-token is Implemented, so its
	// golden is compared, and the whole point of parking is that nothing
	// compares it. Nine parked goldens are eight.
}

// TestEveryParkedGoldenIsDeclared enforces F72 in both directions.
//
// It is not a ratchet. Every Pending golden in the tree is declared today, and
// the test fails on the first one that is not - which is the run that adds it,
// rather than some later run that wonders where it came from.
func TestEveryParkedGoldenIsDeclared(t *testing.T) {
	declared := make(map[string]bool, len(parkedGoldens))
	for id, reason := range parkedGoldens {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%q: declared with no reason, which is the whole of what the list is for", id)
		}
		declared[id] = true
	}

	seen := make(map[string]bool, len(parkedGoldens))
	for _, c := range Catalog {
		_, err := os.Stat(GoldenPath(goldenDir, c.ID))
		hasGolden := err == nil
		switch {
		case c.Status == Pending && hasGolden && !declared[c.ID]:
			t.Errorf("%q: Pending and carrying a golden nothing compares, "+
				"and not in parkedGoldens - declare it with the reason a reader should keep it, "+
				"or promote the case to Recorded so the golden is compared", c.ID)
		case c.Status == Pending && !hasGolden && declared[c.ID]:
			t.Errorf("%q: declared in parkedGoldens, but there is no golden at %s",
				c.ID, GoldenPath(goldenDir, c.ID))
		case c.Status != Pending && declared[c.ID]:
			t.Errorf("%q: declared in parkedGoldens and is not Pending, so its golden "+
				"*is* compared - drop the entry", c.ID)
		}
		seen[c.ID] = true
	}

	for id := range parkedGoldens {
		if !seen[id] {
			t.Errorf("%q: declared in parkedGoldens and is not in the catalogue at all", id)
		}
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
