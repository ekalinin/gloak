package conformance

import (
	"encoding/base64"
	"encoding/json"
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

// TestNoPendingGoldenIsCompared was here until 2026-09-03 and is deliberately
// gone rather than loosened. It counted the Pending cases carrying a golden and
// failed when the count reached zero, saying "delete this test rather than
// loosening it: a guard that has nothing to guard is worse than none". The count
// reached zero when oidc/authorization/prompt-create was promoted, which is what
// F38's HTML mask was built for, so the instruction was followed. What it also
// asserted - that GoldenIsAsserted is false for Pending - is
// TestGoldenIsAssertedFollowsTheStatus's, unchanged and one line above.

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
// A second cannot appear by accident: a Pending case that grows a golden file
// without an entry here fails, and an entry naming a case that is no longer
// Pending, or whose file has gone, fails too. So the list can only be changed
// on purpose, and changing it is where the reason gets written down.
//
// **Seven of the eight left on 2026-09-01** and are gone rather than moved,
// because their cases are Implemented and a compared golden is the opposite of
// a parked one. What let them go was one substitution pass -
// ReplaceThemeResource - plus the theme's markup. The reasoning that had kept
// them is worth keeping: a cut wrote that pass, measured **prompt-create's**
// diff, found the resource segment was one churn source of three, called it a
// third of the problem and reverted. That was true of prompt-create and false
// of the other seven, where the segment was the whole of it. A judgement made
// from one example and generalised.
//
// **The eighth left on 2026-09-03 and the list is empty**, which is the state
// F72 anticipated. It stays: an empty exemption list still refuses the next
// Pending golden that arrives without a reason, which is the half of F72 that
// was never about how many there were. What went with the last entry is
// TestNoPendingGoldenIsCompared, whose own comment said to delete it.
var parkedGoldens = map[string]string{
	"admin/realms-admin/partial-export-clients": "measured 2026-09-06 by recording it twice: " +
		"every id in this body is minted with the database - the realm's, six clients', every " +
		"client scope's, every protocol mapper's, every component's and every authenticator " +
		"config's - and several of its collections have no reproducible order besides, so " +
		"`\"profile\",\"roles\"` came back `\"roles\",\"profile\"`. It was Recorded until then " +
		"and churned wholesale on every run, which put a hand-revert into three cuts' work. " +
		"Read it as a measurement of what partial-export carries, never as bytes Gloak must " +
		"serve.",
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

// TestAMintedProofIsFreshEveryTime is the property the whole mechanism rests
// on. A DPoP proof's jti may be used once, so two runs of one fixture must
// disagree - and if they did not, the second recording of a bound-token case
// would answer "DPoP proof has already been used" and write that as the
// contract.
func TestAMintedProofIsFreshEveryTime(t *testing.T) {
	p := Proof{Method: http.MethodPost, Path: tokenEndpointPath}
	first, err := mintProof(p, testIssuer)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	second, err := mintProof(p, testIssuer)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if first == second {
		t.Fatal("two mints of one declaration produced the same proof, so its jti is reusable")
	}
	// The header is the same bytes both times - the same key, the same typ,
	// the same alg - which is what says the difference is in the claims rather
	// than only in a randomised signature.
	if strings.SplitN(first, ".", 2)[0] != strings.SplitN(second, ".", 2)[0] {
		t.Error("the two proofs disagree in the JOSE header, so the key is not fixed")
	}
	if decodeProofClaims(t, first)["jti"] == decodeProofClaims(t, second)["jti"] {
		t.Error("the two proofs share a jti, which may be used once")
	}
}

// TestAMintedProofNamesTheRequestItWillBeSentOn pins the two claims that make
// this value uncomputable anywhere but here: htu is built from the base URL,
// which differs between the recorder and the verifier, and htm is the case's
// own verb.
func TestAMintedProofNamesTheRequestItWillBeSentOn(t *testing.T) {
	raw, err := mintProof(Proof{Method: http.MethodPost, Path: tokenEndpointPath},
		"http://example.test:9")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims := decodeProofClaims(t, raw)
	if got := claims["htu"]; got != "http://example.test:9"+tokenEndpointPath {
		t.Errorf("htu %v, want the base and the path", got)
	}
	if got := claims["htm"]; got != http.MethodPost {
		t.Errorf("htm %v, want POST", got)
	}
	for _, name := range []string{"iat", "jti"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("a proof with nothing declared wrong is missing %s", name)
		}
	}
}

// TestAProofRefusesAnOmissionThatIsNotAMandatoryClaim keeps Proof.Omit from
// being a field that silently does nothing. A typo there would produce a
// perfectly valid proof and a case measuring the wrong thing - which is the
// shape of the inert masks this repository has already paid for.
func TestAProofRefusesAnOmissionThatIsNotAMandatoryClaim(t *testing.T) {
	if _, err := mintProof(Proof{Method: http.MethodPost, Path: tokenEndpointPath,
		Omit: "nonce"}, testIssuer); err == nil {
		t.Fatal("omitting a claim that is not mandatory was accepted")
	}
	for _, name := range []string{"htm", "htu", "iat", "jti"} {
		raw, err := mintProof(Proof{Method: http.MethodPost, Path: tokenEndpointPath,
			Omit: name}, testIssuer)
		if err != nil {
			t.Fatalf("omit %s: %v", name, err)
		}
		if _, ok := decodeProofClaims(t, raw)[name]; ok {
			t.Errorf("omit %s: the claim is still there", name)
		}
	}
}

// decodeProofClaims reads a minted proof's payload.
func decodeProofClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return claims
}
