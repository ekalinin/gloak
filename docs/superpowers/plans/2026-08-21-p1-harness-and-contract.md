# P1 harness and contract implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `internal/conformance` able to express P1's contract, then record that contract from a live Keycloak 26.7.1, so every P1 implementation task starts from byte-exact expected output.

**Architecture:** Four harness changes, then the catalogue edits they unblock, then one recording run. The harness changes are independent of each other and each lands with its own tests. Nothing here touches production code: `internal/conformance` is test-only, and the packages P1 will add (`internal/token`, `internal/auth`) are deliberately not started - see section 6 of the spec for why their unit tests cannot come first.

**Tech Stack:** Go 1.26, standard library only for tests (no assertion library - the package uses plain `t.Errorf`), `testcontainers-go` behind the `docker` build tag, `modernc.org/sqlite`.

**Specs:**
- `docs/superpowers/specs/2026-08-21-p1-token-foundation-design.md`
- `docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md`
- `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` (the measured contract)
- `AGENTS.md` (the traps that look like bugs)

## Global Constraints

- Commit messages are `type(scope): subject`; allowed types `feat`, `fix`, `docs`, `refactor`, `perf`, `chore`.
- Never commit to `main`. This work is on branch `feat/parity-harness`.
- Code comments in English. Prefer the smallest diff that does the job; preserve existing names.
- `CGO_ENABLED=0 go test ./...` must pass with **exactly one** failure, `TestConformance/oidc/certs/master`, until task 6. Any other failure is a regression.
- `go test ./...` must never need Docker or network. Anything that does goes behind the `docker` build tag.
- `internal/conformance` is test-only. Production code must not import it.
- Response bodies are marshalled from structs with fields in Keycloak's order, never from `map[string]any`.
- Observable values are measured, never written from memory. The recorder supplies every expected byte.

---

### Task 1: The `Recorded` status

Adds the third case status from roadmap section 3.3: golden mandatory, served, and required *not* to match.

**Files:**
- Modify: `internal/conformance/case.go:22-34` (the `Status` constants)
- Modify: `internal/conformance/conformance_test.go:18-57` (the state table and `serve`)
- Modify: `internal/conformance/conformance_test.go:59-130` (split `compare` into `diff` + `compare`)
- Modify: `internal/conformance/catalog_test.go:32-46` (validation)
- Modify: `internal/conformance/coverage_test.go:19-61` (report column)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `Recorded Status` constant; `diff(c Case, want Golden, got *httptest.ResponseRecorder) ([]string, error)` returning one string per difference, empty when the two are equivalent under the case's normalisation rules.

- [ ] **Step 1: Write the failing test**

Append to `internal/conformance/catalog_test.go`:

```go
// TestRecordedCaseRules pins the two rules that make Recorded different from
// Pending: the golden is mandatory, and the case must say why it is not
// served yet.
func TestRecordedCaseRules(t *testing.T) {
	for _, c := range Catalog {
		if c.Status != Recorded {
			continue
		}
		if c.Reason == "" {
			t.Errorf("%q: a Recorded case must say why it is not served yet", c.ID)
		}
		if c.Fixture == "" {
			t.Errorf("%q: a Recorded case is served, so it needs a fixture", c.ID)
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%q: Recorded means the golden was measured, but none exists", c.ID)
		}
	}
}
```

Add `"errors"`, `"io/fs"` and `"os"` to that file's imports.

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestRecordedCaseRules`
Expected: FAIL, `undefined: Recorded`.

- [ ] **Step 3: Add the status**

In `internal/conformance/case.go`, replace the `Pending` constant block's tail so the constants read:

```go
const (
	// Implemented means Gloak serves this. It must have a golden file;
	// the verifier fails when it does not, which is how the project's
	// "measured, never remembered" rule becomes something the build checks.
	Implemented Status = iota
	// Pending means the behaviour is documented but not built yet.
	Pending
	// Recorded means the behaviour has been measured and written to a
	// golden, but Gloak does not serve it yet. It is Pending with the
	// contract already in the repository.
	//
	// The verifier serves a Recorded case and requires it *not* to match.
	// A skip would leave a case that starts passing as a side effect of
	// neighbouring work silently unguarded, so the next refactor could
	// break a contract nobody knew was being met. Making the match itself
	// a failure turns the list into one that clears itself.
	//
	// The assertion is weak on purpose: it passes on any difference and
	// proves only "not built yet". It is a status marker with an alarm on
	// it, not a correctness check.
	Recorded
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestRecordedCaseRules`
Expected: PASS (no case carries the new status yet, so the loop body never runs).

- [ ] **Step 5: Split `compare` so a match can be asked about without failing**

In `internal/conformance/conformance_test.go`, replace the body of `compare` with a wrapper and move the logic into `diff`. `diff` returns differences instead of reporting them, and returns an error only for a malformed body it could not normalise:

```go
func compare(t *testing.T, c Case, want Golden, got *httptest.ResponseRecorder) {
	t.Helper()
	diffs, err := diff(c, want, got)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	for _, d := range diffs {
		t.Error(d)
	}
}

// diff returns one entry per way got departs from want, and no entries when
// the two are equivalent under the case's normalisation rules. It is
// separate from compare so the Recorded branch can ask "do these match?"
// without a mismatch - the expected state for a case that is not built yet -
// failing the test.
func diff(c Case, want Golden, got *httptest.ResponseRecorder) ([]string, error) {
	var out []string
	if got.Code != want.Status {
		out = append(out, fmt.Sprintf("status: want %d, got %d\nbody: %s", want.Status, got.Code, got.Body))
	}

	// Keep the first value for a repeated header name, matching what
	// gotByName below also does: it is also first-value. A map built by
	// letting a later entry overwrite an earlier one would compare the
	// golden's last value against the response's first, disagreeing on any
	// golden with a duplicated header name.
	byName := make(map[string]string, len(want.Headers))
	for _, h := range want.Headers {
		canonical := http.CanonicalHeaderKey(h.Name)
		if _, seen := byName[canonical]; !seen {
			byName[canonical] = h.Value
		}
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
	gotByName := make(map[string]string, len(got.Header()))
	for name, values := range got.Header() {
		if len(values) == 0 {
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		if _, seen := gotByName[canonical]; !seen {
			gotByName[canonical] = values[0]
		}
	}

	for _, name := range c.AssertHeaders {
		canonical := http.CanonicalHeaderKey(name)
		expected, ok := byName[canonical]
		if !ok {
			out = append(out, fmt.Sprintf("header %s is asserted but absent from the golden", name))
			continue
		}
		if actual := gotByName[canonical]; actual != expected {
			out = append(out, fmt.Sprintf("header %s: want %q, got %q", name, expected, actual))
		}
	}
	for _, name := range c.AssertAbsentHeaders {
		if actual, ok := gotByName[http.CanonicalHeaderKey(name)]; ok {
			out = append(out, fmt.Sprintf("header %s: want absent, got %q", name, actual))
		}
	}

	// The same passes the recorder applied, in the same order (see
	// record_test.go), so the two sides are comparable.
	body, err := normalisePasses(got.Body.Bytes(), testIssuer, c)
	if err != nil {
		return nil, err
	}
	if string(body) != string(want.Body) {
		out = append(out, fmt.Sprintf("body differs from the recorded Keycloak response.\nwant: %s\ngot:  %s",
			want.Body, body))
	}
	return out, nil
}
```

Add `"fmt"` to the file's imports.

- [ ] **Step 6: Add the shared normalisation pass helper**

Both the recorder and the verifier run the same passes in the same order, and task 2 adds a fourth. Put the sequence in one place so they cannot drift. Create `internal/conformance/passes.go`:

```go
package conformance

// normalisePasses runs the passes that make a recorded response and a served
// response comparable, in the one order both sides must use.
//
// The order matters and is not arbitrary. ReplaceIssuer runs first so issuer
// URLs inside array elements are already rewritten before either later pass
// compares raw bytes. Normalize runs before SortUnordered so an array element
// whose own identity is volatile (oidc/certs/master's "keys" entries start
// with a random "kid") is sorted by what is left after normalisation rather
// than by the random bytes being masked; sorting first would make the
// recorded order depend on whichever "kid" happened to compare smaller.
//
// It lives in its own file, called from both record_test.go and
// conformance_test.go, because a pass added to one side and not the other is
// a divergence no test can see: both sides would simply agree on the wrong
// bytes.
func normalisePasses(body []byte, base string, c Case) ([]byte, error) {
	body = ReplaceIssuer(body, base)
	body, err := Normalize(body, c.Volatile)
	if err != nil {
		return nil, err
	}
	return SortUnordered(body, c.Unordered)
}
```

Then replace the three-pass block in `record_test.go` (lines 82-90) with:

```go
			body, err = normalisePasses(body, base, c)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
```

- [ ] **Step 7: Add the `Recorded` branch to the state table**

In `conformance_test.go`, `serve` currently cannot report a failure. Leave it as is for now (task 3 changes its signature). Change the `switch` in `TestConformance` and add the branch after it:

```go
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
			got := serve(t, c)

			if c.Status == Recorded {
				diffs, err := diff(c, want, got)
				if err != nil {
					t.Fatalf("compare: %v", err)
				}
				if len(diffs) == 0 {
					t.Fatalf("%s already matches the recorded Keycloak response.\n"+
						"Promote it to Implemented - as Recorded it is guarded by nothing.", c.ID)
				}
				t.Skipf("recorded, not served yet: %s", c.Reason)
			}
			compare(t, c, want, got)
```

- [ ] **Step 8: Report `Recorded` in the coverage table**

In `coverage_test.go`, add the field, the case and the column. Replace the `tally` struct and the `switch` with:

```go
	type tally struct {
		implemented, pending, recorded, hasGolden, inventoryOnly int
		pendingIDs                                               []string
	}
```

and

```go
		switch c.Status {
		case Implemented:
			tl.implemented++
		case Recorded:
			tl.recorded++
		case Pending:
			tl.pending++
			tl.pendingIDs = append(tl.pendingIDs, c.ID)
			if c.Fixture == "" {
				tl.inventoryOnly++
			}
		}
```

renaming the existing golden counter to `hasGolden` at its assignment (`tl.hasGolden++`), and updating the header and row format:

```go
	t.Log("chapter                     implemented  recorded  pending  golden  inventory-only")
	for _, name := range order {
		tl := chapters[name]
		total += tl.implemented + tl.recorded + tl.pending
		done += tl.implemented
		t.Logf("%-26s  %11d  %8d  %7d  %6d  %14d",
			name, tl.implemented, tl.recorded, tl.pending, tl.hasGolden, tl.inventoryOnly)
	}
```

- [ ] **Step 9: Run the whole suite**

Run: `CGO_ENABLED=0 go test ./... 2>&1 | tail -20`
Expected: exactly one failure, `TestConformance/oidc/certs/master`. Then:
Run: `make conformance 2>&1 | head -20`
Expected: the table prints with the new `recorded` column, all zeros.

- [ ] **Step 10: Commit**

```bash
git add internal/conformance/case.go internal/conformance/passes.go \
        internal/conformance/conformance_test.go internal/conformance/catalog_test.go \
        internal/conformance/coverage_test.go internal/conformance/record_test.go
git commit -m "feat(conformance): add the Recorded status for a measured but unserved case"
```

---

### Task 2: Sorting words inside a string

The token response's `scope` is a space-delimited string whose word order is not stable across container starts. `Unordered` sorts JSON arrays and cannot reach inside a string. This closes one of the four goldens the README says churn on every `make record`.

**Files:**
- Modify: `internal/conformance/normalize.go` (add `SortUnorderedWords` and `editor.sortWords`)
- Modify: `internal/conformance/case.go` (add the `UnorderedWords` field)
- Modify: `internal/conformance/passes.go` (add the fourth pass)
- Test: `internal/conformance/normalize_test.go`

**Interfaces:**
- Consumes: `normalisePasses` from Task 1; the `editor` walk in `normalize.go`.
- Produces: `SortUnorderedWords(raw []byte, paths []string) ([]byte, error)`; `Case.UnorderedWords []string`.

- [ ] **Step 1: Write the failing test**

Append to `internal/conformance/normalize_test.go`:

```go
func TestSortUnorderedWords(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		paths []string
		want  string
	}{
		{
			name:  "sorts the words of one string value",
			in:    `{"scope":"openid profile email","other":"b a"}`,
			paths: []string{"scope"},
			want:  `{"scope":"email openid profile","other":"b a"}`,
		},
		{
			name:  "leaves everything else byte-for-byte alone",
			in:    `{"a":1,"scope":"z y","b":[3,2]}`,
			paths: []string{"scope"},
			want:  `{"a":1,"scope":"y z","b":[3,2]}`,
		},
		{
			name:  "collapses nothing when already sorted",
			in:    `{"scope":"a b c"}`,
			paths: []string{"scope"},
			want:  `{"scope":"a b c"}`,
		},
		{
			name:  "no paths is a no-op",
			in:    `{"scope":"b a"}`,
			paths: nil,
			want:  `{"scope":"b a"}`,
		},
		{
			name:  "reaches through a wildcard segment",
			in:    `{"items":[{"scope":"b a"},{"scope":"d c"}]}`,
			paths: []string{"items/*/scope"},
			want:  `{"items":[{"scope":"a b"},{"scope":"c d"}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SortUnorderedWords([]byte(tt.in), tt.paths)
			if err != nil {
				t.Fatalf("SortUnorderedWords: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("want %s, got %s", tt.want, got)
			}
		})
	}
}

// A path naming something that is not a string is an error, not a silent
// no-op, for the same reason SortUnordered errors on a non-array: the path
// was wrong, and masking that produces a golden nobody is checking.
func TestSortUnorderedWordsRejectsNonString(t *testing.T) {
	if _, err := SortUnorderedWords([]byte(`{"scope":["b","a"]}`), []string{"scope"}); err == nil {
		t.Fatal("want an error for an array at the path, got nil")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestSortUnorderedWords`
Expected: FAIL, `undefined: SortUnorderedWords`.

- [ ] **Step 3: Implement it**

In `internal/conformance/normalize.go`, after `SortUnordered`, add:

```go
// SortUnorderedWords sorts the space-separated words inside the string values
// at the given paths, rewriting each as its words joined by single spaces.
//
// It exists because Keycloak emits at least one field - the token response's
// scope - whose word order inside a single string is not stable across
// container starts, for the same reason scopes_supported's array order is
// not: a Java set with no fixed iteration order. Unordered addresses JSON
// arrays and cannot reach inside a string value.
//
// Path syntax matches Normalize and SortUnordered. A path resolving to
// anything but a string is an error rather than a silent no-op: it means the
// wrong path was named, and a mask that masks nothing while claiming to have
// checked is worse than a loud failure.
func SortUnorderedWords(raw []byte, paths []string) ([]byte, error) {
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	e.onMatch = e.sortWords
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: sort unordered words: %w", err)
	}
	return applyEdits(raw, e.edits), nil
}
```

and, after `sortArray`:

```go
// sortWords records an edit that rewrites the string at the current position
// as its space-separated words in sorted order. It reuses replace's offset
// arithmetic to find the value's byte range.
func (e *editor) sortWords() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	start := end - len(raw)

	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("value at this path is not a string: %s", raw)
	}
	words := strings.Fields(s)
	sort.Strings(words)
	repl, err := json.Marshal(strings.Join(words, " "))
	if err != nil {
		return err
	}

	e.edits = append(e.edits, edit{start: start, end: end, repl: repl})
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestSortUnorderedWords -v`
Expected: PASS, all six subtests.

- [ ] **Step 5: Add the case field and wire it into the shared passes**

In `internal/conformance/case.go`, after the `Unordered` field:

```go
	// UnorderedWords lists paths pointing at JSON strings whose
	// space-separated words Keycloak emits in no stable order - the token
	// response's scope is the measured example. Their words are sorted
	// before comparison, so membership stays asserted while order does not.
	UnorderedWords []string
```

In `internal/conformance/passes.go`, extend `normalisePasses`:

```go
	body, err = SortUnordered(body, c.Unordered)
	if err != nil {
		return nil, err
	}
	return SortUnorderedWords(body, c.UnorderedWords)
```

(replacing the current `return SortUnordered(...)` tail).

- [ ] **Step 6: Run the whole suite**

Run: `CGO_ENABLED=0 go test ./... 2>&1 | tail -20`
Expected: exactly one failure, `TestConformance/oidc/certs/master`.

- [ ] **Step 7: Commit**

```bash
git add internal/conformance/normalize.go internal/conformance/normalize_test.go \
        internal/conformance/case.go internal/conformance/passes.go
git commit -m "feat(conformance): sort the words inside a string whose order Keycloak does not fix"
```

---

### Task 3: Fixture chaining

The blocker. Seven catalogue cases are inventory-only purely because a `Case`'s request cannot use a value from an earlier response: `oidc/token/refresh-token-grant`, `oidc/userinfo/get-with-valid-token`, `oidc/userinfo/post-with-valid-token`, `oidc/introspection/active-access-token`, `oidc/introspection/active-refresh-token`, `oidc/revocation/refresh-token` and `oidc/revocation/access-token`.

**Files:**
- Create: `internal/conformance/fixture.go`
- Create: `internal/conformance/fixture_test.go`
- Modify: `internal/conformance/case.go` (document what `Fixture` now names)
- Modify: `internal/conformance/normalize.go` (add `ReplaceCaptured`)
- Modify: `internal/conformance/passes.go` (mask captured values)
- Modify: `internal/conformance/server_test.go` (`newFixture` takes a state name)
- Modify: `internal/conformance/conformance_test.go` (`serve` runs steps and can fail)
- Modify: `internal/conformance/record_test.go` (run steps against the container)
- Modify: `internal/conformance/catalog_test.go` (a named fixture must exist)

**Interfaces:**
- Consumes: `buildRequest` from `case.go`; `normalisePasses` from Task 1.
- Produces:
  - `type Step struct { Request Request; Capture map[string]string }`
  - `type Fixture struct { State string; Steps []Step }`
  - `var Fixtures map[string]Fixture`
  - `type Do func(*http.Request) (*http.Response, error)`
  - `RunFixture(f Fixture, base string, do Do) (map[string]string, error)`
  - `Expand(r Request, vars map[string]string) Request`
  - `ReplaceCaptured(raw []byte, vars map[string]string) []byte`

- [ ] **Step 1: Write the failing test**

Create `internal/conformance/fixture_test.go`:

```go
package conformance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExpandSubstitutesCapturedValues(t *testing.T) {
	in := Request{
		Method:  http.MethodGet,
		Path:    "/realms/master/protocol/openid-connect/userinfo",
		Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		Form:    map[string]string{"token": "{{refresh_token}}", "kept": "literal"},
		Query:   map[string]string{"q": "{{access_token}}"},
	}
	got := Expand(in, map[string]string{"access_token": "AT", "refresh_token": "RT"})

	if got.Headers["Authorization"] != "Bearer AT" {
		t.Errorf("header: got %q", got.Headers["Authorization"])
	}
	if got.Form["token"] != "RT" {
		t.Errorf("form: got %q", got.Form["token"])
	}
	if got.Form["kept"] != "literal" {
		t.Errorf("literal form value was rewritten: got %q", got.Form["kept"])
	}
	if got.Query["q"] != "AT" {
		t.Errorf("query: got %q", got.Query["q"])
	}
	// Expand must not write through to the caller's maps: one Case is
	// expanded twice, once by the recorder and once by the verifier, with
	// different values each time.
	if in.Headers["Authorization"] != "Bearer {{access_token}}" {
		t.Errorf("Expand mutated its input: %q", in.Headers["Authorization"])
	}
}

func TestRunFixtureCapturesFromAStepResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "password" {
			t.Errorf("grant_type: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"AT","refresh_token":"RT"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form:   map[string]string{"grant_type": "password"},
		},
		Capture: map[string]string{"access_token": "access_token", "refresh_token": "refresh_token"},
	}}}

	vars, err := RunFixture(f, srv.URL, srv.Client().Do)
	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	if vars["access_token"] != "AT" || vars["refresh_token"] != "RT" {
		t.Errorf("captured %v", vars)
	}
}

// A step that does not produce the value a later request needs must fail
// loudly. Silently substituting an empty string would record a golden of
// whatever Keycloak answers for an empty token, which is a real response to
// a request nobody meant to make.
func TestRunFixtureFailsWhenACaptureIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{Method: http.MethodPost, Path: "/token"},
		Capture: map[string]string{"access_token": "access_token"},
	}}}

	if _, err := RunFixture(f, srv.URL, srv.Client().Do); err == nil {
		t.Fatal("want an error when the step's response has no such field, got nil")
	}
}

func TestReplaceCapturedMasksValuesThatLeakIntoABody(t *testing.T) {
	vars := map[string]string{"access_token": "AT-abc", "refresh_token": ""}
	got := ReplaceCaptured([]byte(`{"token":"AT-abc","active":true}`), vars)
	want := `{"token":"{{access_token}}","active":true}`
	if string(got) != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

// An empty captured value must never be substituted: strings.ReplaceAll with
// an empty old string inserts the placeholder between every byte.
func TestReplaceCapturedIgnoresEmptyValues(t *testing.T) {
	got := ReplaceCaptured([]byte(`{"a":1}`), map[string]string{"empty": ""})
	if string(got) != `{"a":1}` {
		t.Errorf("empty value was substituted: %s", got)
	}
}

func TestFixturesAreWellFormed(t *testing.T) {
	for name, f := range Fixtures {
		if f.State != "bootstrap" {
			t.Errorf("fixture %q: unknown state %q", name, f.State)
		}
		for i, s := range f.Steps {
			if s.Request.Method == "" || s.Request.Path == "" {
				t.Errorf("fixture %q step %d: needs a method and a path", name, i)
			}
			if len(s.Capture) == 0 {
				t.Errorf("fixture %q step %d: a step that captures nothing is dead weight", name, i)
			}
		}
	}
	if _, ok := Fixtures["bootstrap"]; !ok {
		t.Error(`Fixtures must contain "bootstrap"`)
	}
}

func TestCatalogFixturesExist(t *testing.T) {
	for _, c := range Catalog {
		if c.Fixture == "" {
			continue
		}
		if _, ok := Fixtures[c.Fixture]; !ok {
			t.Errorf("%q: names fixture %q, which is not declared", c.ID, c.Fixture)
		}
	}
}

// An unknown reference is left verbatim rather than becoming an empty
// string, so a typo shows up in the recorded request instead of quietly
// changing what was measured.
func TestExpandLeavesUnknownPlaceholdersAlone(t *testing.T) {
	got := Expand(Request{Headers: map[string]string{"A": "{{nope}}"}}, map[string]string{"x": "1"})
	if got.Headers["A"] != "{{nope}}" {
		t.Errorf("got %q", got.Headers["A"])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestExpand|TestRunFixture|TestReplaceCaptured|TestFixtures|TestCatalogFixtures'`
Expected: FAIL, `undefined: Expand`, `undefined: RunFixture`, `undefined: Fixtures`.

- [ ] **Step 3: Implement the fixture runner**

Create `internal/conformance/fixture.go`:

```go
package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Step is one request run before a case's own, whose response contributes
// values the case can refer to. Steps are never recorded as goldens: only the
// case's own response is. Recording them would commit a live token to the
// repository.
type Step struct {
	Request Request
	// Capture maps a variable name to a slash-separated path into the step's
	// JSON response body. "access_token" is the common one.
	Capture map[string]string
}

// Fixture is the setup a case runs against: a named server-side starting
// state, plus the steps that lead from it to the state the case measures.
type Fixture struct {
	// State names the starting point. "bootstrap" is a fresh master realm,
	// and is the only one today.
	State string
	Steps []Step
}

// Fixtures is every setup a case may name. One declaration, executed twice:
// by the recorder against the reference container and by the verifier against
// the in-process handler. Two declarations would compare responses obtained in
// different ways, which is the one thing this suite cannot afford.
var Fixtures = map[string]Fixture{
	"bootstrap": {State: "bootstrap"},

	// admin-token holds an access token and a refresh token for the
	// bootstrapped administrator, obtained the way kcadm.sh obtains one: the
	// password grant on admin-cli. Note that admin-cli is a lightweight
	// client, so the access token this yields carries no sub, aud or
	// realm_access - see the "Lightweight access tokens" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	"admin-token": {
		State: "bootstrap",
		Steps: []Step{{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  "admin-cli",
					"username":   "admin",
					"password":   "admin",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		}},
	},
}

// Do performs one request. The recorder's implementation talks to the
// reference container over HTTP; the verifier's serves the in-process handler
// through httptest. Both return the response with its body still readable.
type Do func(*http.Request) (*http.Response, error)

// RunFixture executes a fixture's steps in order against do, threading the
// values each step captures into the requests that follow, and returns
// everything captured.
//
// A step whose response lacks a captured path is an error, not an empty
// string. Substituting an empty token would record whatever Keycloak answers
// for a blank credential: a real response to a request nobody meant to make,
// and one that would look like a measured contract afterwards.
func RunFixture(f Fixture, base string, do Do) (map[string]string, error) {
	vars := map[string]string{}
	for i, s := range f.Steps {
		req, err := buildRequest(base, Expand(s.Request, vars))
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: build request: %w", i, err)
		}
		resp, err := do(req)
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: %w", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: read body: %w", i, err)
		}
		for name, path := range s.Capture {
			value, err := captureFrom(body, path)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d, body %s)",
					i, name, err, resp.StatusCode, body)
			}
			vars[name] = value
		}
	}
	return vars, nil
}

// captureFrom pulls one value out of a JSON body by slash-separated path.
//
// Unlike the golden comparison passes this unmarshals rather than splicing
// bytes: a captured value is fed back into a request, never written to a
// golden, so key order does not matter here.
func captureFrom(body []byte, path string) (string, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("response is not JSON: %w", err)
	}
	cur := doc
	for _, seg := range strings.Split(path, "/") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("path %q: %q is not an object", path, seg)
		}
		cur, ok = obj[seg]
		if !ok {
			return "", fmt.Errorf("path %q: no key %q", path, seg)
		}
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: value is %T, not a string", path, cur)
	}
	return s, nil
}

// Expand substitutes {{name}} references in a request's query, headers and
// form values with captured variables. A reference with no matching variable
// is left alone, so a typo shows up in the recorded request rather than
// silently becoming an empty string.
//
// It copies every map it touches. One Case is expanded twice - once by the
// recorder with the container's tokens, once by the verifier with Gloak's -
// so writing through to the catalogue's own maps would let the first run
// poison the second.
func Expand(r Request, vars map[string]string) Request {
	out := r
	out.Query = expandMap(r.Query, vars)
	out.Headers = expandMap(r.Headers, vars)
	out.Form = expandMap(r.Form, vars)
	return out
}

func expandMap(in, vars map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		for name, value := range vars {
			v = strings.ReplaceAll(v, "{{"+name+"}}", value)
		}
		out[k] = v
	}
	return out
}

// ReplaceCaptured masks captured values wherever they appear in a recorded
// body, using the same {{name}} spelling the request used to refer to them.
//
// Without it a golden for an endpoint that echoes its input - introspection
// is the obvious one - would hold a live token, and would therefore differ
// from itself on every recording. That is the churn four goldens already
// have, and it is what stops a `make record` diff from being read.
//
// An empty value is skipped: strings.ReplaceAll with an empty old string
// inserts the replacement between every byte of the input.
func ReplaceCaptured(raw []byte, vars map[string]string) []byte {
	for name, value := range vars {
		if value == "" {
			continue
		}
		raw = []byte(strings.ReplaceAll(string(raw), value, "{{"+name+"}}"))
	}
	return raw
}
```

- [ ] **Step 4: Run the fixture tests**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestExpand|TestRunFixture|TestReplaceCaptured|TestFixtures|TestCatalogFixtures' -v`
Expected: PASS.

- [ ] **Step 5: Mask captured values in the shared passes**

In `internal/conformance/passes.go`, change the signature and add the pass. Captured values are masked **first**, before anything else looks at the bytes:

```go
func normalisePasses(body []byte, base string, c Case, vars map[string]string) ([]byte, error) {
	body = ReplaceCaptured(body, vars)
	body = ReplaceIssuer(body, base)
	body, err := Normalize(body, c.Volatile)
	if err != nil {
		return nil, err
	}
	body, err = SortUnordered(body, c.Unordered)
	if err != nil {
		return nil, err
	}
	return SortUnorderedWords(body, c.UnorderedWords)
}
```

Extend the doc comment with a sentence naming the new pass:

```go
// ReplaceCaptured runs first, before any pass that could reorder or mask the
// bytes a captured token sits in, so a token can never survive into a golden.
```

- [ ] **Step 6: Teach the verifier to run steps**

In `internal/conformance/server_test.go`, `newFixture` now takes the *state* name rather than the fixture name:

```go
// newFixture builds the Gloak handler for a named starting state.
// "bootstrap" is a fresh file-backed store with the master realm created -
// file-backed rather than in-memory because tests on in-memory SQLite have
// passed here while the file-backed path was broken.
func newFixture(t *testing.T, state string) http.Handler {
```

with the `switch name` becoming `switch state` and the default message reading `unknown fixture state %q`.

In `internal/conformance/conformance_test.go`, `serve` runs the steps and can now fail:

```go
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
	vars, err := RunFixture(f, testIssuer, do)
	if err != nil {
		return nil, nil, err
	}

	req, err := buildRequest(testIssuer, Expand(c.Request, vars))
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, vars, nil
}
```

Update `diff` to take `vars` and pass them through:

```go
func diff(c Case, want Golden, got *httptest.ResponseRecorder, vars map[string]string) ([]string, error) {
```

with its body call becoming `normalisePasses(got.Body.Bytes(), testIssuer, c, vars)`, and `compare` gaining the same parameter.

Update the two call sites in `TestConformance`:

```go
			got, vars, err := serve(t, c)
			if err != nil {
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
```

- [ ] **Step 7: Teach the recorder to run steps**

In `internal/conformance/record_test.go`, replace the fixture guard and the request build. Delete the `if c.Fixture != "bootstrap"` branch and use:

```go
		f, ok := Fixtures[c.Fixture]
		if !ok {
			t.Errorf("%s: names fixture %q, which is not declared", c.ID, c.Fixture)
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			vars, err := RunFixture(f, base, client.Do)
			if err != nil {
				t.Fatalf("fixture %q: %v", c.Fixture, err)
			}
			req, err := buildRequest(base, Expand(c.Request, vars))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
```

and the normalisation call becomes:

```go
			body, err = normalisePasses(body, base, c, vars)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
```

Also mask captured values in the recorded headers, since a token can arrive in one. In `recordedHeaders`, add a `vars` parameter and apply it alongside `ReplaceIssuer`:

```go
func recordedHeaders(h http.Header, base string, vars map[string]string) []Header {
```

with the value line becoming:

```go
			value = string(ReplaceIssuer(ReplaceCaptured([]byte(value), vars), base))
```

and the call site `recordedHeaders(resp.Header, base, vars)`.

- [ ] **Step 8: Document what `Fixture` now names**

In `internal/conformance/case.go`, replace the `Fixture` field comment:

```go
	// Fixture names an entry in Fixtures: the server-side starting state,
	// plus any requests run before this one whose responses supply values
	// this one refers to as {{name}}. Empty means the setup does not exist
	// yet: the recorder skips the case and the coverage report counts it as
	// inventory only.
	Fixture string
```

- [ ] **Step 9: Run the whole suite**

Run: `CGO_ENABLED=0 go test ./... 2>&1 | tail -20`
Expected: exactly one failure, `TestConformance/oidc/certs/master`.
Run: `make lint`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add internal/conformance/fixture.go internal/conformance/fixture_test.go \
        internal/conformance/case.go internal/conformance/passes.go \
        internal/conformance/conformance_test.go internal/conformance/record_test.go \
        internal/conformance/server_test.go
git commit -m "feat(conformance): let a case chain onto values captured from earlier responses"
```

---

### Task 4: The parity meter

Gives the coverage report a denominator taken from outside the project, per roadmap section 3.

**Files:**
- Create: `internal/conformance/testdata/openapi/keycloak-26.7.1.json` (downloaded, 561 KB)
- Create: `internal/conformance/openapi.go`
- Create: `internal/conformance/openapi_test.go`
- Create: `internal/conformance/chapters.go`
- Modify: `internal/conformance/coverage_test.go`

**Interfaces:**
- Consumes: `chapterOf` from `coverage_test.go`.
- Produces: `OperationsByTag() (map[string]int, error)`; `type Chapter struct{...}`; `var Chapters []Chapter`; `const untaggedTag = "(untagged)"`.

- [ ] **Step 1: Vendor the description**

```bash
mkdir -p internal/conformance/testdata/openapi
curl -sSL --fail -o internal/conformance/testdata/openapi/keycloak-26.7.1.json \
  https://www.keycloak.org/docs-api/26.7.1/rest-api/openapi.json
ls -l internal/conformance/testdata/openapi/keycloak-26.7.1.json
```

Expected: about 561 KB.

- [ ] **Step 2: Write the failing test**

Create `internal/conformance/openapi_test.go`:

```go
package conformance

import "testing"

// The counts below are the vendored description's, checked so that swapping
// in another version cannot change the denominator silently: a version bump
// is supposed to be a deliberate act with a re-record beside it.
func TestOperationsByTag(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}

	total := 0
	for _, n := range byTag {
		total += n
	}
	if total != 413 {
		t.Errorf("total operations: want 413, got %d", total)
	}
	if len(byTag) != 22 {
		t.Errorf("tags: want 22, got %d", len(byTag))
	}

	for tag, want := range map[string]int{
		"Users":       34,
		"Clients":     35,
		"Realms Admin": 45,
		untaggedTag:   31,
	} {
		if got := byTag[tag]; got != want {
			t.Errorf("tag %q: want %d operations, got %d", tag, want, got)
		}
	}
}

// Every chapter that claims an OpenAPI tag must name one the description
// actually has. A typo would otherwise give that chapter a denominator of
// zero, which reads as "fully covered".
func TestChaptersReferenceRealTags(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}
	for _, ch := range Chapters {
		if ch.OpenAPITag == "" {
			continue
		}
		if _, ok := byTag[ch.OpenAPITag]; !ok {
			t.Errorf("chapter %q names tag %q, which the description does not have", ch.Name, ch.OpenAPITag)
		}
	}
}

// Every tag in the description belongs to exactly one chapter. A tag nobody
// claims is surface silently missing from the denominator.
func TestEveryTagIsClaimedOnce(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}
	claimed := map[string]string{}
	for _, ch := range Chapters {
		if ch.OpenAPITag == "" {
			continue
		}
		if prev, ok := claimed[ch.OpenAPITag]; ok {
			t.Errorf("tag %q is claimed by both %q and %q", ch.OpenAPITag, prev, ch.Name)
		}
		claimed[ch.OpenAPITag] = ch.Name
	}
	for tag := range byTag {
		if _, ok := claimed[tag]; !ok {
			t.Errorf("tag %q is in the description but no chapter claims it", tag)
		}
	}
}

// A chapter whose surface nobody has counted has to say so, or the total
// silently treats it as empty.
func TestUnenumeratedChaptersCarryAReason(t *testing.T) {
	for _, ch := range Chapters {
		if !ch.Enumerated && ch.Reason == "" {
			t.Errorf("chapter %q is not enumerated and does not say why", ch.Name)
		}
		if ch.Enumerated && ch.Reason != "" {
			t.Errorf("chapter %q is enumerated; Reason belongs to the ones that are not", ch.Name)
		}
	}
}

// Every catalogue case reports under some chapter. A case whose chapter is
// undeclared would vanish from the report entirely.
func TestEveryCaseHasAChapter(t *testing.T) {
	declared := map[string]bool{}
	for _, ch := range Chapters {
		declared[ch.Name] = true
	}
	for _, c := range Catalog {
		if !declared[chapterOf(c.ID)] {
			t.Errorf("%q reports under chapter %q, which is not declared", c.ID, chapterOf(c.ID))
		}
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestOperationsByTag|TestChapters|TestEveryTag|TestUnenumerated|TestEveryCaseHasAChapter'`
Expected: FAIL, `undefined: OperationsByTag`, `undefined: Chapters`, `undefined: untaggedTag`.

- [ ] **Step 4: Implement the reader**

Create `internal/conformance/openapi.go`:

```go
package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// openapiPath is Keycloak's own description of its Admin REST API, vendored
// rather than fetched so that `go test ./...` keeps needing neither Docker nor
// network.
//
// It supplies the parity denominator and nothing else. This is the same split
// the rest of the suite runs on - the documentation says which behaviours
// exist, a running Keycloak says what they emit - applied one level up. Not
// one expected byte comes from this file, only the names of operations that
// exist.
//
// Retargeting to another Keycloak version means committing that version's file
// alongside this one and repointing this constant, then re-recording every
// golden against the new container.
const openapiPath = "testdata/openapi/keycloak-26.7.1.json"

// untaggedTag stands for operations the description gives no tag. In 26.7.1
// all 31 of them are under
// /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server: they are
// Authorization Services.
const untaggedTag = "(untagged)"

// httpMethods are the keys of a path item that describe an operation. A path
// item also holds "parameters", "summary" and "$ref", which are not
// operations and must not be counted as surface.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"patch": true, "options": true, "head": true,
}

// OperationsByTag counts the operations the vendored description carries
// under each tag. An operation with several tags counts under each of them,
// which is how the description itself presents them.
func OperationsByTag() (map[string]int, error) {
	raw, err := os.ReadFile(filepath.FromSlash(openapiPath))
	if err != nil {
		return nil, fmt.Errorf("conformance: read openapi description: %w", err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			Tags []string `json:"tags"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("conformance: parse openapi description: %w", err)
	}

	byTag := map[string]int{}
	for _, item := range doc.Paths {
		for method, op := range item {
			if !httpMethods[method] {
				continue
			}
			if len(op.Tags) == 0 {
				byTag[untaggedTag]++
				continue
			}
			for _, tag := range op.Tags {
				byTag[tag]++
			}
		}
	}
	return byTag, nil
}
```

- [ ] **Step 5: Declare the chapters**

Create `internal/conformance/chapters.go`:

```go
package conformance

// Chapter is one slice of the parity surface, with the source of its
// denominator named.
//
// A percentage is only as good as its denominator. If the denominator is
// "cases somebody bothered to write down", it measures diligence rather than
// coverage: it grows when someone remembers a gap and shrinks when they
// forget one. So chapters say where their number comes from, and the ones
// nobody has counted say that too rather than being quietly left out of the
// total - which would inflate the percentage by hiding exactly the parts
// nobody has looked at.
//
// See docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md section 3.
type Chapter struct {
	// Name is the report's row label. For a chapter the catalogue covers it
	// matches chapterOf(case.ID).
	Name string

	// OpenAPITag names the tag in the vendored description whose operations
	// are this chapter's denominator. Empty means the denominator is the
	// number of catalogue cases instead.
	OpenAPITag string

	// Enumerated is false when nobody has counted this chapter's surface.
	// The report prints "?" for its denominator and keeps it out of the
	// total, saying how many chapters it left out.
	Enumerated bool

	// Reason says why the surface is not counted. Required when Enumerated
	// is false, forbidden when it is true.
	Reason string
}

// Chapters is the whole parity surface: the hand-written protocol chapters
// the catalogue covers, every tag of the vendored Admin API description, and
// the chapters whose surface has no machine-readable source and has not been
// counted by hand either.
var Chapters = []Chapter{
	// Protocol chapters. Their denominator is the catalogue's own case count,
	// which is a hand-kept number and says so.
	{Name: "http/fallback", Enumerated: true},
	{Name: "oidc/authorization", Enumerated: true},
	{Name: "oidc/certs", Enumerated: true},
	{Name: "oidc/ciba", Enumerated: true},
	{Name: "oidc/device", Enumerated: true},
	{Name: "oidc/discovery", Enumerated: true},
	{Name: "oidc/introspection", Enumerated: true},
	{Name: "oidc/logout", Enumerated: true},
	{Name: "oidc/registration", Enumerated: true},
	{Name: "oidc/revocation", Enumerated: true},
	{Name: "oidc/token", Enumerated: true},
	{Name: "oidc/userinfo", Enumerated: true},
	{Name: "realm/info", Enumerated: true},

	// Admin REST API. One chapter per tag, so every operation in the
	// description is counted exactly once.
	{Name: "admin/attack-detection", OpenAPITag: "Attack Detection", Enumerated: true},
	{Name: "admin/authentication-management", OpenAPITag: "Authentication Management", Enumerated: true},
	{Name: "admin/authz-resource-server", OpenAPITag: untaggedTag, Enumerated: true},
	{Name: "admin/client-attribute-certificate", OpenAPITag: "Client Attribute Certificate", Enumerated: true},
	{Name: "admin/client-initial-access", OpenAPITag: "Client Initial Access", Enumerated: true},
	{Name: "admin/client-registration-policy", OpenAPITag: "Client Registration Policy", Enumerated: true},
	{Name: "admin/client-role-mappings", OpenAPITag: "Client Role Mappings", Enumerated: true},
	{Name: "admin/client-scopes", OpenAPITag: "Client Scopes", Enumerated: true},
	{Name: "admin/clients", OpenAPITag: "Clients", Enumerated: true},
	{Name: "admin/component", OpenAPITag: "Component", Enumerated: true},
	{Name: "admin/groups", OpenAPITag: "Groups", Enumerated: true},
	{Name: "admin/identity-providers", OpenAPITag: "Identity Providers", Enumerated: true},
	{Name: "admin/key", OpenAPITag: "Key", Enumerated: true},
	{Name: "admin/organizations", OpenAPITag: "Organizations", Enumerated: true},
	{Name: "admin/protocol-mappers", OpenAPITag: "Protocol Mappers", Enumerated: true},
	{Name: "admin/realms-admin", OpenAPITag: "Realms Admin", Enumerated: true},
	{Name: "admin/role-mapper", OpenAPITag: "Role Mapper", Enumerated: true},
	{Name: "admin/roles", OpenAPITag: "Roles", Enumerated: true},
	{Name: "admin/roles-by-id", OpenAPITag: "Roles (by ID)", Enumerated: true},
	{Name: "admin/scope-mappings", OpenAPITag: "Scope Mappings", Enumerated: true},
	{Name: "admin/users", OpenAPITag: "Users", Enumerated: true},
	{Name: "admin/workflows", OpenAPITag: "Workflows", Enumerated: true},

	// Surface with no machine-readable description, not counted by hand
	// either. Listed so the report can say how much it is not measuring.
	{Name: "saml", Reason: "no machine-readable description; the SAML endpoints have not been enumerated by hand"},
	{Name: "account", Reason: "the account REST API is not described by the Admin API document and has not been enumerated"},
	{Name: "themes", Reason: "themes and i18n are served as resources, not as an API; no operation list exists"},
	{Name: "management", Reason: "the management port's health and metrics endpoints are not in the Admin API document"},
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestOperationsByTag|TestChapters|TestEveryTag|TestUnenumerated|TestEveryCaseHasAChapter' -v`
Expected: PASS, all five.

- [ ] **Step 7: Rewrite the coverage report to join the two sources**

Replace the body of `TestCoverage` in `internal/conformance/coverage_test.go`:

```go
func TestCoverage(t *testing.T) {
	type tally struct {
		implemented, recorded, pending, hasGolden, inventoryOnly int
		pendingIDs                                               []string
	}
	tallies := map[string]*tally{}
	for _, ch := range Chapters {
		tallies[ch.Name] = &tally{}
	}

	for _, c := range Catalog {
		tl, ok := tallies[chapterOf(c.ID)]
		if !ok {
			t.Errorf("%q reports under chapter %q, which is not declared", c.ID, chapterOf(c.ID))
			continue
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); !errors.Is(err, fs.ErrNotExist) {
			tl.hasGolden++
		}
		switch c.Status {
		case Implemented:
			tl.implemented++
		case Recorded:
			tl.recorded++
		case Pending:
			tl.pending++
			tl.pendingIDs = append(tl.pendingIDs, c.ID)
			if c.Fixture == "" {
				tl.inventoryOnly++
			}
		}
	}

	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}

	var served, documented, unenumerated int
	t.Log("chapter                              served  documented  source")
	for _, ch := range Chapters {
		tl := tallies[ch.Name]
		switch {
		case !ch.Enumerated:
			unenumerated++
			t.Logf("%-36s  %6d  %10s  not enumerated: %s", ch.Name, tl.implemented, "?", ch.Reason)
			continue
		case ch.OpenAPITag != "":
			n := byTag[ch.OpenAPITag]
			documented += n
			served += tl.implemented
			t.Logf("%-36s  %6d  %10d  openapi 26.7.1", ch.Name, tl.implemented, n)
		default:
			n := tl.implemented + tl.recorded + tl.pending
			documented += n
			served += tl.implemented
			t.Logf("%-36s  %6d  %10d  catalogue", ch.Name, tl.implemented, n)
		}
	}
	t.Logf("total: %d of %d enumerated behaviours served; %d chapters not enumerated",
		served, documented, unenumerated)

	for _, ch := range Chapters {
		tl := tallies[ch.Name]
		if len(tl.pendingIDs) == 0 {
			continue
		}
		sort.Strings(tl.pendingIDs)
		t.Logf("pending in %s:\n  %s", ch.Name, strings.Join(tl.pendingIDs, "\n  "))
	}
}
```

- [ ] **Step 8: Run the report and read it**

Run: `make conformance 2>&1 | head -50`
Expected: 13 protocol chapters with catalogue denominators, 22 admin chapters with openapi denominators, 4 chapters printing `?`, and a total line reading `8 of 481 enumerated behaviours served; 4 chapters not enumerated`.

- [ ] **Step 9: Run the whole suite**

Run: `CGO_ENABLED=0 go test ./... 2>&1 | tail -20`
Expected: exactly one failure, `TestConformance/oidc/certs/master`.

- [ ] **Step 10: Commit**

```bash
git add internal/conformance/testdata/openapi/keycloak-26.7.1.json \
        internal/conformance/openapi.go internal/conformance/openapi_test.go \
        internal/conformance/chapters.go internal/conformance/coverage_test.go
git commit -m "feat(conformance): take the parity denominator from Keycloak's own API description"
```

---

### Task 5: Point P1's cases at the new machinery

Turns the seven inventory-only cases into recordable ones and fixes the `scope` churn.

**Files:**
- Modify: `internal/conformance/catalog_oidc_pending.go`

**Interfaces:**
- Consumes: `Fixtures["admin-token"]` and `Case.UnorderedWords` from Tasks 2 and 3.
- Produces: nothing new; other tasks depend on the edits only through the recorder.

- [ ] **Step 1: Give the seven cases the `admin-token` fixture**

Each edit replaces an empty `Fixture` and its comment with `Fixture: "admin-token"`, and replaces the `REPLACE-WITH-A-REAL-...` literal with the matching `{{name}}`. The seven, with the literal each one carries:

| Case ID | `Fixture` becomes | Substitution |
|---|---|---|
| `oidc/token/refresh-token-grant` | `"admin-token"` | form `refresh_token` → `{{refresh_token}}` |
| `oidc/userinfo/get-with-valid-token` | `"admin-token"` | header `Authorization` → `Bearer {{access_token}}` |
| `oidc/userinfo/post-with-valid-token` | `"admin-token"` | form `access_token` → `{{access_token}}` |
| `oidc/introspection/active-access-token` | `"admin-token"` | form `token` → `{{access_token}}` |
| `oidc/introspection/active-refresh-token` | `"admin-token"` | form `token` → `{{refresh_token}}` |
| `oidc/revocation/refresh-token` | `"admin-token"` | form `token` → `{{refresh_token}}` |
| `oidc/revocation/access-token` | `"admin-token"` | form `token` → `{{access_token}}` |

Worked example, `oidc/userinfo/get-with-valid-token` (currently at `catalog_oidc_pending.go:752-768`):

```go
	{
		ID: "oidc/userinfo/get-with-valid-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "userinfo is not implemented",
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
```

Second worked example, `oidc/introspection/active-access-token`, whose form key differs:

```go
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":     "admin-cli",
				"token":         "{{access_token}}",
			},
		},
```

Read each case before editing: the existing form keys and `client_id` values stay exactly as they are. Only the placeholder literal and `Fixture` change.

- [ ] **Step 2: Mask the token wherever introspection echoes it**

`oidc/introspection/active-access-token` and `active-refresh-token` are the two cases whose response could echo the token they were given. `ReplaceCaptured` handles that automatically, so no `Volatile` entry is needed for the token itself - but the JWT claims in an introspection response carry per-response values. Leave `Volatile` as each case already declares it; the recording in Task 6 shows whether more is needed.

- [ ] **Step 3: Declare the `scope` word order on the token cases**

Every case whose golden holds a token response gets `UnorderedWords: []string{"scope"}`. Those are `oidc/token/password-grant-admin-cli` and `oidc/token/refresh-token-grant`. For the first, replace the long comment about the churn (lines 344-353) with:

```go
		// The recorded scope field's word order is not stable across
		// container starts - a Java set with no fixed iteration order,
		// surfacing inside a space-separated string rather than a JSON
		// array. See the "Token response scope word order" section of
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
		UnorderedWords: []string{"scope"},
```

placing the field after `Volatile` in each literal.

- [ ] **Step 4: Verify the catalogue still validates**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestCatalog|TestFixtures'`
Expected: PASS. `TestCatalogFixturesExist` from Task 3 is what proves the seven now name a declared fixture.

- [ ] **Step 5: Check the report moved**

Run: `make conformance 2>&1 | grep -E 'oidc/(token|userinfo|introspection|revocation)'`
Expected: `inventory-only` counts dropped by 7 in total - `oidc/token` from 10 to 9, `oidc/userinfo` from 3 to 1, `oidc/introspection` from 3 to 1, `oidc/revocation` from 2 to 0.

- [ ] **Step 6: Run the whole suite**

Run: `CGO_ENABLED=0 go test ./... 2>&1 | tail -20`
Expected: exactly one failure, `TestConformance/oidc/certs/master`.

- [ ] **Step 7: Commit**

```bash
git add internal/conformance/catalog_oidc_pending.go
git commit -m "feat(conformance): chain P1's token-bearing cases onto the admin-token fixture"
```

---

### Task 6: Record P1's contract

The one task that needs Docker. It produces the goldens every P1 implementation task will be measured against.

**Files:**
- Modify: `internal/conformance/testdata/golden/oidc/**` (written by the recorder)
- Modify: `internal/conformance/catalog_oidc_pending.go` (statuses)
- Modify: `README.md` (the record section's list of churning goldens)

**Interfaces:**
- Consumes: everything from Tasks 1 through 5.
- Produces: goldens on disk, and P1's cases at status `Recorded`.

- [ ] **Step 1: Point testcontainers at Colima**

Docker here runs through Colima, which testcontainers does not discover on its own:

```bash
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
docker version --format '{{.Server.Version}}'
```

Expected: a version prints.

- [ ] **Step 2: Record**

Run: `make record 2>&1 | tail -40`
Expected: `recorded ...` lines for the newly-chained cases, and a `skipped N cases with no fixture yet` line naming only the cases that genuinely still need P3 or P7 - `authorization-code-grant`, `replayed-code`, `pkce-verifier-mismatch`, `client-credentials-grant`, `device-code-grant`, `ciba-grant`, `token-exchange`, `jwt-authorization-grant`, `dpop-bound-token`, `userinfo/expired-token`, and the browser-flow cases.

- [ ] **Step 3: Read the diff before anything else**

```bash
git diff --stat internal/conformance/testdata/golden
git diff internal/conformance/testdata/golden
```

Check three things and do not skip them - an unreviewed re-record pins a regression as the new contract:

1. **No golden contains a JWT.** `grep -rn 'eyJ' internal/conformance/testdata/golden` must return nothing. A hit means `ReplaceCaptured` missed a value and a live token is about to be committed.
2. **The three login-theme goldens still churn** (`oidc/authorization/invalid-redirect-uri`, `oidc/authorization/unknown-client-id`, `oidc/logout/invalid-post-logout-redirect-uri`) - expected, they carry a per-container cache-busting hash.
3. **`oidc/token/password-grant-admin-cli` no longer churns on `scope`.** Record twice and diff to confirm: `make record && git diff --stat internal/conformance/testdata/golden` should show that file unchanged the second time.

- [ ] **Step 4: Promote P1's recorded cases to `Recorded`**

For every P1 case that now has a golden, change `Status: Pending` to `Status: Recorded`, keeping `Reason` as it is. Those are, in `catalog_oidc_pending.go`:

```
oidc/token/password-grant-admin-cli     oidc/token/unknown-client
oidc/token/refresh-token-grant          oidc/token/wrong-password
oidc/token/wrong-client-secret          oidc/token/missing-grant-type
oidc/token/unknown-grant-type           oidc/token/invalid-refresh-token
oidc/userinfo/invalid-token             oidc/userinfo/get-with-valid-token
oidc/userinfo/post-with-valid-token     oidc/userinfo/missing-authorization-header
oidc/introspection/active-access-token  oidc/introspection/active-refresh-token
oidc/introspection/inactive-token       oidc/introspection/unauthenticated-client
oidc/revocation/refresh-token           oidc/revocation/access-token
oidc/revocation/unknown-token           oidc/revocation/wrong-client
```

Leave every case without a golden at `Pending`.

- [ ] **Step 5: Verify the state table holds**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance 2>&1 | tail -30`
Expected: exactly one failure, `TestConformance/oidc/certs/master`. The twenty promoted cases **skip** with `recorded, not served yet`. If any of them *fails* with "already matches the recorded Keycloak response", that case is already served and belongs at `Implemented` - which would be a genuine and welcome surprise, so check it rather than suppressing it.

- [ ] **Step 6: Update the README's record section**

In `README.md`, the paragraph listing four churning goldens now lists three: drop the `oidc/token/password-grant-admin-cli` bullet about `scope` word order, since Task 2 fixed it. Change "four of the goldens it writes churn" to "three of the goldens it writes churn" and "All four are `Pending`" to "All three are `Pending`".

Also update the Status section's bullet list: the conformance suite now measures the parity surface against Keycloak's own API description, and 20 P1 behaviours have a recorded contract waiting.

- [ ] **Step 7: Run everything one last time**

```bash
CGO_ENABLED=0 go test ./... 2>&1 | tail -20
make lint
make build
make conformance 2>&1 | tail -5
```

Expected: one known failure, clean lint, a binary, and a total line that still reads `8 of 481` served - because nothing new is *served* yet. That is the point: the contract is in the repository, the code is not written.

- [ ] **Step 8: Commit**

```bash
git add internal/conformance/testdata/golden internal/conformance/catalog_oidc_pending.go README.md
git commit -m "feat(conformance): record P1's measured contract from Keycloak 26.7.1"
```

---

## What this plan deliberately does not do

`internal/token`, `internal/auth`, the session model, the key repositories and the four protocol handlers are **not** started here. Section 6 of the P1 spec explains why their unit tests cannot come first: a Go test for a package that does not exist fails to compile, and a package that does not compile takes `go test ./...` down with it, which is worse than a red test because it is no signal at all.

The red phase for those arrives per task, by flipping that task's cases from `Recorded` to `Implemented`, at which point the failure carries a byte-exact diff against a real Keycloak response. That is the next plan.
