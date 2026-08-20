package conformance

import (
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
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
			got := serve(t, c)
			compare(t, c, want, got)
		})
	}
}

// serve runs one case against its fixture and returns the recorded response.
func serve(t *testing.T, c Case) *httptest.ResponseRecorder {
	t.Helper()
	h := newFixture(t, c.Fixture)
	req, err := buildRequest(testIssuer, c.Request)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func compare(t *testing.T, c Case, want Golden, got *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != want.Status {
		t.Errorf("status: want %d, got %d\nbody: %s", want.Status, got.Code, got.Body)
	}

	byName := make(map[string]string, len(want.Headers))
	for _, h := range want.Headers {
		byName[http.CanonicalHeaderKey(h.Name)] = h.Value
	}
	for _, name := range c.AssertHeaders {
		canonical := http.CanonicalHeaderKey(name)
		expected, ok := byName[canonical]
		if !ok {
			t.Errorf("header %s is asserted but absent from the golden", name)
			continue
		}
		if actual := got.Header().Get(name); actual != expected {
			t.Errorf("header %s: want %q, got %q", name, expected, actual)
		}
	}

	// The same three passes the recorder applied, in the same order, so the
	// two sides are comparable.
	body := ReplaceIssuer(got.Body.Bytes(), testIssuer)
	body, err := SortUnordered(body, c.Unordered)
	if err != nil {
		t.Fatalf("sort unordered: %v", err)
	}
	body, err = Normalize(body, c.Volatile)
	if err != nil {
		t.Fatalf("normalize response: %v", err)
	}
	if string(body) != string(want.Body) {
		t.Errorf("body differs from the recorded Keycloak response.\nwant: %s\ngot:  %s",
			want.Body, body)
	}
}
