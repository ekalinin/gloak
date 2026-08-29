package conformance

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

// TestConformance runs every catalogue case against the in-process handler.
//
// The state table is the point of this test. An Implemented case with no
// golden is a failure, not a skip: it means an endpoint shipped without a
// measured contract, which is the rule AGENTS.md states and which nothing
// enforced before.
func TestConformance(t *testing.T) {
	for _, c := range Catalog {
		t.Run(c.ID, func(t *testing.T) {
			raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
			missing := errors.Is(err, fs.ErrNotExist)
			switch {
			case missing && c.Status == Implemented:
				t.Fatalf("%s is served but has no measured contract.\n"+
					"Record it: make record. Documented at %s (%s).",
					c.ID, c.Doc.URL, c.Doc.Section)
			case missing && c.Status == Recorded:
				t.Fatalf("%s is marked Recorded but has no golden.\n"+
					"Record it: make record, or set it back to Pending.", c.ID)
			case missing:
				t.Skipf("pending, no golden recorded yet: %s", c.Reason)
			case err != nil:
				t.Fatalf("read golden: %v", err)
			case c.Status == Pending:
				t.Skipf("pending, golden recorded and waiting: %s", c.Reason)
			}

			want, err := ParseGolden(raw)
			if err != nil {
				t.Fatalf("parse golden: %v", err)
			}
			got, vars, err := serve(t, c)
			if err != nil {
				// A fixture step that cannot run is the expected state for a
				// case whose endpoint is exactly what has not been built.
				if c.Status == Recorded {
					t.Skipf("recorded, not served yet (%s): %v", c.Reason, err)
				}
				t.Fatalf("serve: %v", err)
			}

			if c.Status == Recorded {
				diffs, dErr := diff(c, want, got, vars)
				if dErr != nil {
					t.Fatalf("compare: %v", dErr)
				}
				if len(diffs) == 0 {
					t.Fatalf("%s already matches the recorded Keycloak response.\n"+
						"Promote it to Implemented - as Recorded it is guarded by nothing.", c.ID)
				}
				t.Skipf("recorded, not served yet: %s", c.Reason)
			}
			compare(t, c, want, got, vars)
		})
	}
}

// serve runs one case against its fixture and returns the recorded response,
// along with whatever the fixture's steps captured so the caller can mask
// those values out of the body.
//
// It returns an error rather than failing the test directly because a fixture
// step failing is the *expected* state for a Recorded case: the endpoint its
// steps call is exactly what has not been built yet.
func serve(t *testing.T, c Case) (*httptest.ResponseRecorder, map[string]string, error) {
	t.Helper()
	f, ok := Fixtures[c.Fixture]
	if !ok {
		return nil, nil, fmt.Errorf("unknown fixture %q", c.Fixture)
	}
	h := newFixture(t, f.State)

	do := func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result(), nil
	}
	sess, err := Run(f, testIssuer, do)
	if err != nil {
		return nil, nil, err
	}
	vars := sess.Vars

	req, err := buildRequest(testIssuer, Expand(c.Request, vars))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	// The case's own request is not one of the fixture's steps, so the session
	// goes on it here, the same way the recorder does it. Both sides obtaining
	// their responses the same way is the property this suite rests on.
	sess.Apply(req)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, vars, nil
}

// volatileHeaderCase is the shape Task 1 of P2's plan exists for: a header the
// case asserts and whose value changes per response.
func volatileHeaderCase() (Case, Golden) {
	c := Case{
		ID:              "admin/clients/create",
		AssertHeaders:   []string{"Location"},
		VolatileHeaders: []string{"Location"},
	}
	want := Golden{
		Status:  201,
		Headers: []Header{{Name: "Location", Value: volatilePlaceholder}},
		Body:    []byte{},
	}
	return c, want
}

func TestDiffAcceptsADifferentVolatileHeaderValue(t *testing.T) {
	c, want := volatileHeaderCase()
	got := httptest.NewRecorder()
	got.Header().Set("Location", "http://localhost:8080/admin/realms/master/clients/a-different-uuid")
	got.WriteHeader(201)

	diffs, err := diff(c, want, got, nil)

	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(diffs) != 0 {
		t.Fatalf("a masked header should compare equal whatever its value: %v", diffs)
	}
}

func TestDiffRejectsAMissingVolatileHeader(t *testing.T) {
	// Masking that also hid absence would let an endpoint stop sending the
	// header entirely without anything noticing.
	c, want := volatileHeaderCase()
	got := httptest.NewRecorder()
	got.WriteHeader(201)

	diffs, err := diff(c, want, got, nil)

	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if len(diffs) == 0 {
		t.Fatal("a missing Location compared equal to a masked one")
	}
}

func compare(t *testing.T, c Case, want Golden, got *httptest.ResponseRecorder, vars map[string]string) {
	t.Helper()
	diffs, err := diff(c, want, got, vars)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	for _, d := range diffs {
		t.Error(d)
	}
}

// diff returns one entry per way got departs from want, and no entries when
// the two are equivalent under the case's normalisation rules. It is separate
// from compare so the Recorded branch can ask "do these match?" without a
// mismatch - the expected state for a case that is not built yet - failing
// the test.
func diff(c Case, want Golden, got *httptest.ResponseRecorder, vars map[string]string) ([]string, error) {
	var out []string
	if got.Code != want.Status {
		out = append(out, fmt.Sprintf("status: want %d, got %d\nbody: %s", want.Status, got.Code, got.Body))
	}

	// A repeated header name keeps every value, in order, on both sides. The
	// measured case is userinfo's 200, which sends Cache-Control twice -
	// no-store and then no-cache - and comparing first values alone would let
	// an implementation drop the second and pass.
	byName := make(map[string][]string, len(want.Headers))
	for _, h := range want.Headers {
		canonical := http.CanonicalHeaderKey(h.Name)
		byName[canonical] = append(byName[canonical], h.Value)
	}

	// Fold the response's headers into a canonicalised map too, rather than
	// reading them through Header.Get. Get canonicalises its argument and
	// then does a plain map lookup, so it can never see a header stored
	// under a non-canonical map key - which is exactly how
	// WriteBearerChallenge sets WWW-Authenticate, to match Keycloak's wire
	// casing (see internal/httpx/errors.go's WriteBearerChallenge doc
	// comment). Folding both sides the same way, with the same
	// canonicalisation, makes a literal "WWW-Authenticate" map key and a
	// canonical "Www-Authenticate" golden entry land in the same bucket.
	// The served side gets the same two passes recordedHeaders applied to the
	// golden. Without them a header holding the issuer can never compare equal:
	// the golden says {{issuer}} and the response says the handler's base URL.
	// It went unnoticed until P3 because every asserted Location so far is also
	// volatile, and a volatile header is compared on presence alone.
	gotByName := make(map[string][]string, len(got.Header()))
	for name, values := range got.Header() {
		if len(values) == 0 {
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		for _, v := range values {
			normalised := string(ReplaceIssuer(ReplaceCaptured([]byte(v), vars), testIssuer))
			gotByName[canonical] = append(gotByName[canonical], normalised)
		}
	}

	volatile := make(map[string]bool, len(c.VolatileHeaders))
	for _, name := range c.VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}

	for _, name := range c.AssertHeaders {
		canonical := http.CanonicalHeaderKey(name)
		expected, ok := byName[canonical]
		if !ok {
			out = append(out, fmt.Sprintf("header %s is asserted but absent from the golden", name))
			continue
		}
		actual, present := gotByName[canonical]
		// A volatile header is compared on presence alone: its recorded value
		// is the placeholder, so comparing values would fail every time. It is
		// still asserted, so an implementation that stopped sending it is
		// caught here rather than passing quietly.
		if volatile[canonical] {
			if !present || len(actual) == 0 || actual[0] == "" {
				out = append(out, fmt.Sprintf("header %s: want a value, got none", name))
			}
			continue
		}
		if !slices.Equal(actual, expected) {
			out = append(out, fmt.Sprintf("header %s: want %q, got %q", name, expected, actual))
		}
	}
	for _, name := range c.AssertAbsentHeaders {
		if actual, ok := gotByName[http.CanonicalHeaderKey(name)]; ok {
			out = append(out, fmt.Sprintf("header %s: want absent, got %q", name, actual))
		}
	}

	// The same passes the recorder applied, in the same order, so the two
	// sides are comparable. See passes.go.
	body, err := normalisePasses(got.Body.Bytes(), testIssuer, c, vars)
	if err != nil {
		return nil, err
	}
	if string(body) != string(want.Body) {
		out = append(out, fmt.Sprintf("body differs from the recorded Keycloak response.\nwant: %s\ngot:  %s",
			want.Body, body))
	}
	return out, nil
}
