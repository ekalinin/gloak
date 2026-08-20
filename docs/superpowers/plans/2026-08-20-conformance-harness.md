# Documentation Conformance Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a regression suite whose case list comes from the Keycloak documentation and whose expected bytes are recorded from a live Keycloak 26.7.1, and make the three shipped endpoints pass it.

**Architecture:** A test-only package `internal/conformance` holds a catalogue of `Case` values derived from the documentation. A recorder behind the `docker` build tag replays the catalogue against `quay.io/keycloak/keycloak:26.7.1` and writes normalised golden files. An offline verifier replays the same catalogue against an in-process Gloak handler and compares byte-for-byte. Normalisation edits byte ranges in place so key order and whitespace survive.

**Tech Stack:** Go 1.22+ method-and-path `http.ServeMux`, `encoding/json` token streaming, `testcontainers-go` (already a dependency), `go-jose/v4`, `modernc.org/sqlite`.

**Spec:** `docs/superpowers/specs/2026-08-20-conformance-harness-design.md`

## Global Constraints

- Compatibility target is **Keycloak 26.7.1**, pinned as a contract.
- **Observable values are measured, never remembered.** No expected value in this plan may be written from memory or copied from documentation prose. Where a value is unknown it is recorded first and transcribed from the golden file. This is why several tasks below say "read the golden and transcribe" instead of showing the value.
- `CGO_ENABLED=0 go test ./...` must never require Docker or network access. Anything that does goes behind the `docker` build tag.
- `CGO_ENABLED=0 go build ./...` must work.
- `internal/httpx` is the only place a response body is marshalled.
- Marshal from structs with fields declared in Keycloak's order, never from `map[string]any` and never from a third-party struct with its own order.
- Environment variables use the `GLOAK_` prefix, never `KC_`.
- Commit messages `type(scope): subject`; types limited to `feat`, `fix`, `docs`, `refactor`, `perf`, `chore`. No `Co-Authored-By` line.
- Never commit to `main`. Work happens on `feat/conformance-harness`.
- Code comments in English.
- Prefer the smallest diff that does the job; preserve existing names.

## File Structure

| File | Responsibility |
|---|---|
| `internal/conformance/case.go` | `Case`, `Status`, `Doc`, `Request` - the shape of one documented behaviour |
| `internal/conformance/catalog.go` | `Catalog`, assembled from the per-chapter slices |
| `internal/conformance/catalog_oidc.go` | the inventory read from `/securing-apps/oidc-layers` |
| `internal/conformance/normalize.go` | in-place byte rewriting: issuer substitution, volatile values |
| `internal/conformance/golden.go` | the `.http` golden format and its path rules |
| `internal/conformance/server_test.go` | building the in-process Gloak handler for a named fixture; a `_test.go` file because it imports `testing`, which must not reach a non-test build |
| `internal/conformance/catalog_test.go` | catalogue well-formedness |
| `internal/conformance/normalize_test.go` | the normaliser, including the negative test |
| `internal/conformance/golden_test.go` | golden round-trip |
| `internal/conformance/conformance_test.go` | the offline verifier |
| `internal/conformance/coverage_test.go` | the coverage report |
| `internal/conformance/record_test.go` | `//go:build docker` - the recorder |
| `internal/conformance/testdata/golden/**.http` | recorded expected responses |
| `internal/keys/keys.go` | gains a self-signed certificate for the realm key |
| `internal/oidc/discovery.go` | gains a Gloak-owned JWKS document type |
| `internal/oidc/router.go` | realm-info field order, response headers |
| `Makefile` | `conformance` and `record` targets |

---

### Task 1: The `Case` type and a catalogue that checks itself

**Files:**
- Create: `internal/conformance/case.go`
- Create: `internal/conformance/catalog.go`
- Create: `internal/conformance/catalog_oidc.go`
- Test: `internal/conformance/catalog_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Case`, `Status` (`Implemented`, `Pending`), `Doc`, `Request`, `var Catalog []Case`, `func (c Case) GoldenID() string`.

- [ ] **Step 1: Write the failing test**

Create `internal/conformance/catalog_test.go`:

```go
package conformance

import (
	"regexp"
	"testing"
)

// idPattern keeps IDs safe to use as file paths: lowercase slug segments
// separated by slashes, nothing that could escape testdata/golden.
var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)*$`)

func TestCatalogIsWellFormed(t *testing.T) {
	if len(Catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := make(map[string]bool, len(Catalog))
	for _, c := range Catalog {
		if !idPattern.MatchString(c.ID) {
			t.Errorf("%q: ID is not a slug path", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("%q: duplicate ID", c.ID)
		}
		seen[c.ID] = true

		if c.Doc.URL == "" || c.Doc.Section == "" || c.Doc.Retrieved == "" {
			t.Errorf("%q: Doc must carry URL, Section and Retrieved", c.ID)
		}
		if c.Request.Method == "" || c.Request.Path == "" {
			t.Errorf("%q: Request needs a method and a path", c.ID)
		}
		switch c.Status {
		case Pending:
			if c.Reason == "" {
				t.Errorf("%q: a Pending case must say why", c.ID)
			}
		case Implemented:
			if c.Fixture == "" {
				t.Errorf("%q: an Implemented case needs a fixture", c.ID)
			}
			if c.Reason != "" {
				t.Errorf("%q: Reason belongs to Pending cases only", c.ID)
			}
		default:
			t.Errorf("%q: unknown status %d", c.ID, c.Status)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestCatalogIsWellFormed`
Expected: FAIL - the package does not exist yet.

- [ ] **Step 3: Write `case.go`**

```go
// Package conformance holds the regression catalogue derived from the
// Keycloak documentation, and the machinery that compares Gloak's responses
// with bytes recorded from a live Keycloak 26.7.1.
//
// The two sources have separate jobs and must not be confused. The
// documentation says which behaviours exist; it never supplies a value. Every
// expected value comes from the recorder in record_test.go. See
// docs/superpowers/specs/2026-08-20-conformance-harness-design.md.
//
// This package is test-only. Production code must not import it.
package conformance

// Status says whether Gloak serves a documented behaviour today.
type Status int

const (
	// Implemented means Gloak serves this. It must have a golden file;
	// the verifier fails when it does not, which is how the project's
	// "measured, never remembered" rule becomes something the build checks.
	Implemented Status = iota
	// Pending means the behaviour is documented but not built yet.
	Pending
)

// Doc cites where a behaviour was read. The Securing Applications guide has
// no version-pinned URL - https://www.keycloak.org/docs/26.7.1/securing_apps/
// returns 404 - so its pages track latest and Retrieved is what dates them.
type Doc struct {
	URL       string
	Section   string
	Retrieved string // YYYY-MM-DD
}

// Request is one HTTP call, literal: no placeholders, the realm name included.
type Request struct {
	Method  string
	Path    string
	Query   map[string]string
	Headers map[string]string
	Form    map[string]string // sent as application/x-www-form-urlencoded
	Body    []byte            // used only when Form is empty
}

// Case is one documented behaviour.
type Case struct {
	ID     string // stable slug path; also the golden filename
	Doc    Doc
	Status Status
	Reason string // why it is Pending; required when Status is Pending

	// Fixture names the setup applied before the request. "bootstrap" is a
	// fresh store with the master realm created. Empty means the setup does
	// not exist yet: the recorder skips the case and the coverage report
	// counts it as inventory only.
	Fixture string

	Request Request

	// AssertHeaders lists the response headers compared exactly. Every header
	// is written to the golden; only these are asserted. The status line is
	// always compared.
	AssertHeaders []string

	// Volatile lists slash-separated paths into the JSON body whose values
	// change per response. Their values are replaced before comparison while
	// their presence and position stay asserted. "*" matches one segment.
	Volatile []string
}

// GoldenID is the case ID, named separately so callers reading golden paths
// do not reach for the field directly.
func (c Case) GoldenID() string { return c.ID }
```

- [ ] **Step 4: Write `catalog.go`**

```go
package conformance

// Catalog is every documented behaviour the suite knows about, assembled from
// the per-chapter slices. Adding a chapter means adding a file and a line here.
var Catalog = func() []Case {
	var all []Case
	all = append(all, oidcCore...)
	return all
}()
```

- [ ] **Step 5: Write `catalog_oidc.go` with the two discovery cases**

Only discovery is seeded here; the remaining endpoints arrive in later tasks
so that each one lands with the fix it needs.

```go
package conformance

import "net/http"

// oidcCore holds the OIDC protocol endpoints named at
// https://www.keycloak.org/securing-apps/oidc-layers.
var oidcCore = []Case{
	{
		ID: "oidc/discovery/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master/.well-known/openid-configuration"},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/discovery/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/.well-known/openid-configuration"},
		AssertHeaders: []string{"Content-Type"},
	},
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestCatalogIsWellFormed -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/conformance/
git commit -m "feat(conformance): add the documented-behaviour catalogue"
```

---

### Task 2: The normaliser

The heart of the harness. It must not re-marshal: marshalling through
`map[string]any` sorts keys alphabetically, which would erase the single
property the suite exists to check.

**Files:**
- Create: `internal/conformance/normalize.go`
- Test: `internal/conformance/normalize_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func ReplaceIssuer(raw []byte, base string) []byte`, `func Normalize(raw []byte, paths []string) ([]byte, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/conformance/normalize_test.go`:

```go
package conformance

import "testing"

func TestReplaceIssuerRewritesEveryOccurrence(t *testing.T) {
	in := []byte(`{"issuer":"http://localhost:18091/realms/master","jwks_uri":"http://localhost:18091/realms/master/certs"}`)
	want := `{"issuer":"{{issuer}}/realms/master","jwks_uri":"{{issuer}}/realms/master/certs"}`
	if got := string(ReplaceIssuer(in, "http://localhost:18091")); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// TestNormalizePreservesKeyOrder is the test that would fail against any
// implementation that unmarshals into a map and marshals back: Go would emit
// "a" before "z" before "m", and the whole point is that it must not.
func TestNormalizePreservesKeyOrder(t *testing.T) {
	in := []byte(`{"z":1,"a":"secret","m":true}`)
	got, err := Normalize(in, []string{"a"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := `{"z":1,"a":"{{string}}","m":true}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestNormalizeCarriesTheOriginalType(t *testing.T) {
	in := []byte(`{"s":"x","n":12,"b":false,"o":{"k":1},"arr":[1,2],"nul":null}`)
	got, err := Normalize(in, []string{"s", "n", "b", "o", "arr", "nul"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := `{"s":"{{string}}","n":"{{number}}","b":"{{bool}}","o":"{{object}}","arr":"{{array}}","nul":"{{null}}"}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestNormalizeWalksArraysWithAWildcard(t *testing.T) {
	in := []byte(`{"keys":[{"kid":"one","kty":"RSA"},{"kid":"two","kty":"RSA"}]}`)
	got, err := Normalize(in, []string{"keys/*/kid"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := `{"keys":[{"kid":"{{string}}","kty":"RSA"},{"kid":"{{string}}","kty":"RSA"}]}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestNormalizeAddressesOneArrayElement(t *testing.T) {
	in := []byte(`{"a":["keep","drop"]}`)
	got, err := Normalize(in, []string{"a/1"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := `{"a":["keep","{{string}}"]}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// TestNormalizePreservesSurroundingBytes pins the offset arithmetic that the
// whole approach rests on: the value occupies [InputOffset-len(raw), InputOffset),
// so a pretty-printed input must come back with its spacing intact and only the
// targeted value replaced.
func TestNormalizePreservesSurroundingBytes(t *testing.T) {
	in := []byte("{\n  \"outer\": {\n    \"inner\": \"secret\",\n    \"kept\": [1, 2]\n  }\n}")
	got, err := Normalize(in, []string{"outer/inner"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := "{\n  \"outer\": {\n    \"inner\": \"{{string}}\",\n    \"kept\": [1, 2]\n  }\n}"
	if string(got) != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestNormalizeKeepsTheMissingTrailingNewline(t *testing.T) {
	in := []byte(`{"a":1}`)
	got, err := Normalize(in, nil)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got[len(got)-1] != '}' {
		t.Fatalf("normalisation added a trailing byte: %q", got)
	}
}

func TestNormalizeLeavesNonJSONBodiesAlone(t *testing.T) {
	in := []byte("")
	got, err := Normalize(in, nil)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want an empty body back, got %q", got)
	}
}

// TestNormalizeStillDistinguishesTransposedKeys is the negative test. Without
// it the harness could pass while proving nothing.
func TestNormalizeStillDistinguishesTransposedKeys(t *testing.T) {
	a, err := Normalize([]byte(`{"first":"x","second":"y"}`), []string{"first", "second"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	b, err := Normalize([]byte(`{"second":"y","first":"x"}`), []string{"first", "second"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("normalisation erased key order: both became %s", a)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestNormalize -v`
Expected: FAIL - `undefined: Normalize`, `undefined: ReplaceIssuer`.

- [ ] **Step 3: Write `normalize.go`**

```go
package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// issuerPlaceholder stands in for the base URL of whichever server produced a
// body. The reference container answers on http://localhost:18091 and the test
// server on http://localhost:8080, so without this every absolute URL differs.
const issuerPlaceholder = "{{issuer}}"

// ReplaceIssuer swaps a server's base URL for the placeholder.
func ReplaceIssuer(raw []byte, base string) []byte {
	if base == "" {
		return raw
	}
	return bytes.ReplaceAll(raw, []byte(base), []byte(issuerPlaceholder))
}

// Normalize replaces the values at the given paths with placeholders that
// carry the original JSON type, so a string turning into a number is still
// caught.
//
// It edits byte ranges in place. It deliberately does not unmarshal and
// re-marshal: Go sorts map keys alphabetically, and key order is the contract
// this suite exists to check. Paths are slash-separated from the document
// root, array elements addressed by index, "*" matching any one segment.
//
// A body that is not a JSON value is returned unchanged - the userinfo
// rejection is 401 with an empty body, and that is a case, not an error.
func Normalize(raw []byte, paths []string) ([]byte, error) {
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: normalize: %w", err)
	}
	return applyEdits(raw, e.edits), nil
}

type edit struct {
	start, end int
	repl       []byte
}

type editor struct {
	dec      *json.Decoder
	patterns [][]string
	edits    []edit
}

// value handles the JSON value at the decoder's current position, given the
// path that leads to it.
func (e *editor) value(path []string) error {
	switch {
	case matchesAny(path, e.patterns):
		return e.replace()
	case prefixOfAny(path, e.patterns):
		return e.descend(path)
	default:
		// No pattern can be inside this subtree, so skip it whole.
		var skip json.RawMessage
		return e.dec.Decode(&skip)
	}
}

// replace records the byte range of the value at the current position. The
// value occupies [InputOffset-len(raw), InputOffset): Decode stops on the
// value's final byte and json.RawMessage holds that value verbatim.
func (e *editor) replace() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	e.edits = append(e.edits, edit{
		start: end - len(raw),
		end:   end,
		repl:  []byte(`"{{` + jsonTypeOf(raw) + `}}"`),
	})
	return nil
}

// descend walks into an object or array because some pattern points inside it.
func (e *editor) descend(path []string) error {
	tok, err := e.dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// A scalar sitting where a pattern expected a container. Nothing
		// below it to edit.
		return nil
	}
	switch delim {
	case '{':
		for e.dec.More() {
			keyTok, err := e.dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("want a string key, got %v", keyTok)
			}
			if err := e.value(append(path, key)); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; e.dec.More(); i++ {
			if err := e.value(append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	// Consume the closing delimiter.
	_, err = e.dec.Token()
	return err
}

func matchesAny(path []string, patterns [][]string) bool {
	if len(path) == 0 {
		return false
	}
	for _, p := range patterns {
		if len(p) == len(path) && segmentsMatch(path, p) {
			return true
		}
	}
	return false
}

func prefixOfAny(path []string, patterns [][]string) bool {
	for _, p := range patterns {
		if len(path) < len(p) && segmentsMatch(path, p[:len(path)]) {
			return true
		}
	}
	return false
}

func segmentsMatch(path, pattern []string) bool {
	for i := range path {
		if pattern[i] != "*" && pattern[i] != path[i] {
			return false
		}
	}
	return true
}

// jsonTypeOf names the type of a raw JSON value from its first byte.
func jsonTypeOf(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "null"
	}
	switch trimmed[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// applyEdits splices the recorded ranges, leaving every other byte - key
// order, spacing, the absence of a trailing newline - untouched.
func applyEdits(raw []byte, edits []edit) []byte {
	if len(edits) == 0 {
		return raw
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out bytes.Buffer
	prev := 0
	for _, ed := range edits {
		out.Write(raw[prev:ed.start])
		out.Write(ed.repl)
		prev = ed.end
	}
	out.Write(raw[prev:])
	return out.Bytes()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestNormalize|TestReplaceIssuer' -v`
Expected: PASS, nine tests.

If `TestNormalizePreservesSurroundingBytes` fails, the offset arithmetic
assumption is wrong and everything downstream rests on it - stop and fix it
here rather than working around it later.

- [ ] **Step 5: Vet and commit**

```bash
go vet ./internal/conformance/
git add internal/conformance/
git commit -m "feat(conformance): normalise volatile values without re-marshalling"
```

---

### Task 3: The golden file format

**Files:**
- Create: `internal/conformance/golden.go`
- Test: `internal/conformance/golden_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `type Golden struct{ RequestLine string; Status int; Headers []Header; Body []byte }`, `type Header struct{ Name, Value string }`, `func FormatGolden(g Golden) []byte`, `func ParseGolden(raw []byte) (Golden, error)`, `func GoldenPath(dir, id string) string`, `var VolatileHeaders = []string{"Date", "Content-Length"}`.

- [ ] **Step 1: Write the failing test**

Create `internal/conformance/golden_test.go`:

```go
package conformance

import (
	"path/filepath"
	"testing"
)

func TestGoldenRoundTrip(t *testing.T) {
	want := Golden{
		RequestLine: "GET /realms/master",
		Status:      200,
		Headers: []Header{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Date", Value: "{{volatile}}"},
		},
		Body: []byte(`{"realm":"master"}`),
	}
	got, err := ParseGolden(FormatGolden(want))
	if err != nil {
		t.Fatalf("ParseGolden: %v", err)
	}
	if got.RequestLine != want.RequestLine || got.Status != want.Status {
		t.Fatalf("head mismatch: %+v", got)
	}
	if string(got.Body) != string(want.Body) {
		t.Fatalf("body mismatch: %q", got.Body)
	}
	if len(got.Headers) != len(want.Headers) {
		t.Fatalf("header count: want %d, got %d", len(want.Headers), len(got.Headers))
	}
	for i := range want.Headers {
		if got.Headers[i] != want.Headers[i] {
			t.Errorf("header %d: want %+v, got %+v", i, want.Headers[i], got.Headers[i])
		}
	}
}

// TestGoldenKeepsAnEmptyBody covers the userinfo rejection: 401, text/plain,
// no body at all.
func TestGoldenKeepsAnEmptyBody(t *testing.T) {
	want := Golden{RequestLine: "GET /x", Status: 401, Body: nil}
	got, err := ParseGolden(FormatGolden(want))
	if err != nil {
		t.Fatalf("ParseGolden: %v", err)
	}
	if len(got.Body) != 0 {
		t.Fatalf("want an empty body, got %q", got.Body)
	}
}

func TestGoldenBodyKeepsNoTrailingNewline(t *testing.T) {
	raw := FormatGolden(Golden{RequestLine: "GET /x", Status: 200, Body: []byte(`{"a":1}`)})
	if raw[len(raw)-1] != '}' {
		t.Fatalf("golden file must end on the body's last byte, got %q", raw[len(raw)-8:])
	}
}

func TestGoldenPathTurnsSlugSegmentsIntoDirectories(t *testing.T) {
	want := filepath.Join("testdata", "golden", "oidc", "discovery", "master.http")
	if got := GoldenPath("testdata/golden", "oidc/discovery/master"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestGolden -v`
Expected: FAIL - `undefined: Golden`.

- [ ] **Step 3: Write `golden.go`**

```go
package conformance

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
)

// goldenDir is where recorded responses live, relative to the package.
const goldenDir = "testdata/golden"

// volatilePlaceholder replaces the value of a header that changes per
// response. The header keeps its name, so a header disappearing is still
// visible in the diff.
const volatilePlaceholder = "{{volatile}}"

// VolatileHeaders change on every response and would otherwise make every
// `make record` produce a diff, which is how a recorder's output stops being
// read.
var VolatileHeaders = []string{"Date", "Content-Length"}

// Header is one response header. Headers are stored as an ordered slice
// rather than an http.Header because a map loses the order a diff reads by.
type Header struct {
	Name  string
	Value string
}

// Golden is a recorded response.
type Golden struct {
	RequestLine string
	Status      int
	Headers     []Header
	Body        []byte
}

// FormatGolden renders a Golden as the .http file that gets committed:
// the request as a comment, the status line, every header, a blank line,
// then the body with nothing appended after it.
func FormatGolden(g Golden) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n", g.RequestLine)
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\n", g.Status, http.StatusText(g.Status))
	for _, h := range g.Headers {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	b.WriteByte('\n')
	b.Write(g.Body)
	return b.Bytes()
}

// ParseGolden reads back what FormatGolden wrote.
func ParseGolden(raw []byte) (Golden, error) {
	head, body, found := bytes.Cut(raw, []byte("\n\n"))
	if !found {
		return Golden{}, fmt.Errorf("conformance: golden has no blank line separating head from body")
	}
	lines := strings.Split(string(head), "\n")
	if len(lines) < 2 {
		return Golden{}, fmt.Errorf("conformance: golden needs a request comment and a status line")
	}
	if !strings.HasPrefix(lines[0], "# ") {
		return Golden{}, fmt.Errorf("conformance: golden must open with a request comment")
	}
	g := Golden{RequestLine: strings.TrimPrefix(lines[0], "# "), Body: body}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return Golden{}, fmt.Errorf("conformance: %q is not a status line", lines[1])
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return Golden{}, fmt.Errorf("conformance: status code in %q: %w", lines[1], err)
	}
	g.Status = status

	for _, line := range lines[2:] {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			return Golden{}, fmt.Errorf("conformance: %q is not a header", line)
		}
		g.Headers = append(g.Headers, Header{Name: name, Value: value})
	}
	return g, nil
}

// GoldenPath turns a case ID into a file path under dir. IDs are validated as
// slug paths by TestCatalogIsWellFormed, so no segment can escape dir.
func GoldenPath(dir, id string) string {
	return filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(id)+".http")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestGolden -v`
Expected: PASS, four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/conformance/
git commit -m "feat(conformance): add the golden response file format"
```

---

### Task 4: The recorder

**Files:**
- Create: `internal/conformance/record_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: `Catalog`, `Golden`, `FormatGolden`, `GoldenPath`, `ReplaceIssuer`, `Normalize`, `VolatileHeaders`.
- Produces: golden files under `internal/conformance/testdata/golden/`, and `func buildRequest(base string, r Request) (*http.Request, error)` used by the verifier in Task 5. Put `buildRequest` in `case.go` so both build tags see it.

- [ ] **Step 1: Add `buildRequest` to `case.go`**

`case.go` has no imports yet. Insert this block directly after the `package
conformance` clause - Go requires imports before any declaration - and append
the function to the end of the file:

```go
import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)
```

```go
// buildRequest turns a Case's Request into an *http.Request aimed at base.
// The recorder points base at the reference container; the verifier points it
// at the in-process handler's issuer.
func buildRequest(base string, r Request) (*http.Request, error) {
	target := base + r.Path
	if len(r.Query) > 0 {
		q := url.Values{}
		for k, v := range r.Query {
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}

	var body io.Reader
	form := len(r.Form) > 0
	switch {
	case form:
		values := url.Values{}
		for k, v := range r.Form {
			values.Set(k, v)
		}
		body = strings.NewReader(values.Encode())
	case len(r.Body) > 0:
		body = bytes.NewReader(r.Body)
	}

	req, err := http.NewRequest(r.Method, target, body)
	if err != nil {
		return nil, err
	}
	if form {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}
```

Keep the package doc comment at the top of the file, above the imports.

- [ ] **Step 2: Write `record_test.go`**

```go
//go:build docker

package conformance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestRecordGoldens replays the catalogue against a live Keycloak 26.7.1 and
// writes the expected bytes. It rewrites checked-in files, so it never runs as
// part of `make test`: run it deliberately with `make record` and read the
// diff before committing.
//
// Cases with an empty Fixture are skipped: they need setup that does not exist
// yet. A case naming a fixture this recorder cannot build is a failure, not a
// quiet skip.
func TestRecordGoldens(t *testing.T) {
	ctx := context.Background()
	base := startKeycloak(ctx, t)
	client := &http.Client{Timeout: 30 * time.Second}

	var skipped []string
	for _, c := range Catalog {
		if c.Fixture == "" {
			skipped = append(skipped, c.ID)
			continue
		}
		if c.Fixture != "bootstrap" {
			t.Errorf("%s: no recorder support for fixture %q", c.ID, c.Fixture)
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			req, err := buildRequest(base, c.Request)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			body = ReplaceIssuer(body, base)
			body, err = Normalize(body, c.Volatile)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}

			g := Golden{
				RequestLine: c.Request.Method + " " + c.Request.Path,
				Status:      resp.StatusCode,
				Headers:     recordedHeaders(resp.Header, base),
				Body:        body,
			}
			path := GoldenPath(goldenDir, c.ID)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, FormatGolden(g), 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			t.Logf("recorded %s", path)
		})
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		t.Logf("skipped %d cases with no fixture yet: %v", len(skipped), skipped)
	}
}

// recordedHeaders sorts headers by name so a re-record produces no spurious
// diff, and blanks the values that change per response.
func recordedHeaders(h http.Header, base string) []Header {
	volatile := make(map[string]bool, len(VolatileHeaders))
	for _, name := range VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Header, 0, len(names))
	for _, name := range names {
		value := h.Get(name)
		if volatile[name] {
			value = volatilePlaceholder
		} else {
			value = string(ReplaceIssuer([]byte(value), base))
		}
		out = append(out, Header{Name: name, Value: value})
	}
	return out
}

// startKeycloak runs the reference server and returns its base URL. The image
// tag is the project's pinned compatibility target and must not drift.
func startKeycloak(ctx context.Context, t *testing.T) string {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.7.1",
		Cmd:          []string{"start-dev"},
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForHTTP("/realms/master").
			WithPort("8080/tcp").
			WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
			WithStartupTimeout(5 * time.Minute),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start keycloak: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port())
}
```

- [ ] **Step 3: Add the Makefile targets**

Replace the `.PHONY` line and append:

```make
.PHONY: test build lint conformance record

conformance:
	CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage -v

# record rewrites the expected values in internal/conformance/testdata/golden
# from a live Keycloak 26.7.1. It needs Docker. Read the diff before committing:
# an unreviewed re-record pins a regression as the new contract.
record:
	CGO_ENABLED=0 go test -tags docker ./internal/conformance/ -run TestRecordGoldens -v -count=1
```

- [ ] **Step 4: Check that it compiles under the docker tag**

Run: `CGO_ENABLED=0 go vet -tags docker ./internal/conformance/`
Expected: no output.

- [ ] **Step 5: Record the discovery goldens**

Run: `make record`

If Docker runs through Colima, export the two variables README documents first.
Expected: two files appear, `internal/conformance/testdata/golden/oidc/discovery/master.http` and `.../unknown-realm.http`.

- [ ] **Step 6: Verify recording is idempotent**

Run: `make record && git status --short internal/conformance/testdata/`
Expected: the second run leaves the files unchanged - no modified entries. If a
file churns, a value that varies per response is missing from `VolatileHeaders`
or from that case's `Volatile`. Fix it here; a recorder whose diff is always
noisy is a recorder nobody reads.

- [ ] **Step 7: Read the goldens before committing them**

Run: `cat internal/conformance/testdata/golden/oidc/discovery/master.http`
Confirm the body is the compact discovery document with `{{issuer}}` in place
of the container URL, and that the unknown-realm golden carries 404 with the
bare-error shape.

- [ ] **Step 8: Commit**

```bash
git add internal/conformance/ Makefile
git commit -m "feat(conformance): record expected responses from Keycloak 26.7.1"
```

---

### Task 5: The offline verifier

**Files:**
- Create: `internal/conformance/server_test.go`
- Create: `internal/conformance/conformance_test.go`

**Interfaces:**
- Consumes: `Catalog`, `buildRequest`, `ParseGolden`, `GoldenPath`, `ReplaceIssuer`, `Normalize`, `VolatileHeaders`.
- Produces: `const testIssuer = "http://localhost:8080"`, `func newFixture(t *testing.T, name string) http.Handler`.

- [ ] **Step 1: Write `server_test.go`**

The name matters: this file imports `testing`, and a non-test file that does
so registers the testing package's flags in every binary that links it.

```go
package conformance

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// testIssuer is the externally visible base URL the handler under test is
// built with. Bodies have it replaced with {{issuer}} before comparison, so
// the value only has to be stable, not equal to the recorder's.
const testIssuer = "http://localhost:8080"

// newFixture builds the Gloak handler for a named setup. "bootstrap" is a
// fresh file-backed store with the master realm created - file-backed rather
// than in-memory because tests on in-memory SQLite have passed here while the
// file-backed path was broken.
func newFixture(t *testing.T, name string) http.Handler {
	t.Helper()
	switch name {
	case "bootstrap":
		ctx := context.Background()
		s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
			t.Fatalf("EnsureMaster: %v", err)
		}
		k, err := keys.Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return oidc.NewRouter(s, k, testIssuer)
	default:
		t.Fatalf("unknown fixture %q", name)
		return nil
	}
}
```

Note: `keys.Generate()` gains a parameter in Task 7. Update this call then.

- [ ] **Step 2: Write `conformance_test.go`**

```go
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

	body := ReplaceIssuer(got.Body.Bytes(), testIssuer)
	body, err := Normalize(body, c.Volatile)
	if err != nil {
		t.Fatalf("normalize response: %v", err)
	}
	if string(body) != string(want.Body) {
		t.Errorf("body differs from the recorded Keycloak response.\nwant: %s\ngot:  %s",
			want.Body, body)
	}
}
```

- [ ] **Step 3: Run the verifier**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance -v`
Expected: PASS for both discovery cases.

If the master discovery case fails on the body, read the diff carefully before
changing anything: the recorded bytes are the contract, and a difference here
is a real incompatibility in `internal/oidc/discovery.go`, not a test problem.

- [ ] **Step 4: Run the whole suite**

Run: `make test`
Expected: PASS across all packages.

- [ ] **Step 5: Commit**

```bash
git add internal/conformance/
git commit -m "feat(conformance): verify responses against the recorded goldens"
```

---

### Task 6: The coverage report

**Files:**
- Create: `internal/conformance/coverage_test.go`

**Interfaces:**
- Consumes: `Catalog`, `GoldenPath`.
- Produces: `TestCoverage`, the target of `make conformance`.

- [ ] **Step 1: Write the report**

```go
package conformance

import (
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestCoverage always passes. It exists to print how much of the documented
// surface is served, so that a pending count which never moves is visible
// rather than buried. `make conformance` runs it.
//
// It prints rather than writing a checked-in file: a generated file drifts
// from the tests that generate it.
func TestCoverage(t *testing.T) {
	type tally struct {
		implemented, pending, recorded, inventoryOnly int
		pendingIDs                                    []string
	}
	chapters := map[string]*tally{}
	var order []string

	for _, c := range Catalog {
		name := chapterOf(c.ID)
		tl, ok := chapters[name]
		if !ok {
			tl = &tally{}
			chapters[name] = tl
			order = append(order, name)
		}
		_, err := os.Stat(GoldenPath(goldenDir, c.ID))
		hasGolden := !errors.Is(err, fs.ErrNotExist)
		if hasGolden {
			tl.recorded++
		}
		switch c.Status {
		case Implemented:
			tl.implemented++
		case Pending:
			tl.pending++
			tl.pendingIDs = append(tl.pendingIDs, c.ID)
			if c.Fixture == "" {
				tl.inventoryOnly++
			}
		}
	}
	sort.Strings(order)

	var total, done int
	t.Log("chapter                     implemented  pending  recorded  inventory-only")
	for _, name := range order {
		tl := chapters[name]
		total += tl.implemented + tl.pending
		done += tl.implemented
		t.Logf("%-26s  %11d  %7d  %8d  %14d",
			name, tl.implemented, tl.pending, tl.recorded, tl.inventoryOnly)
	}
	t.Logf("total: %d of %d documented behaviours served", done, total)

	for _, name := range order {
		tl := chapters[name]
		if len(tl.pendingIDs) == 0 {
			continue
		}
		sort.Strings(tl.pendingIDs)
		t.Logf("pending in %s:\n  %s", name, strings.Join(tl.pendingIDs, "\n  "))
	}
}

// chapterOf groups a case ID by its first two slug segments, so
// "oidc/token/password-grant" reports under "oidc/token".
func chapterOf(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) < 2 {
		return id
	}
	return parts[0] + "/" + parts[1]
}
```

- [ ] **Step 2: Run it**

Run: `make conformance`
Expected: PASS, with a table showing `oidc/discovery  2  0  2  0`.

- [ ] **Step 3: Commit**

```bash
git add internal/conformance/
git commit -m "feat(conformance): report how much of the documented surface is served"
```

---

### Task 7: JWKS - certificate chain and a Gloak-owned document

Two defects land together because the golden cannot be satisfied without both:
the certificate fields are missing, and the key order is go-jose's rather than
Keycloak's.

**Files:**
- Modify: `internal/conformance/catalog_oidc.go`
- Modify: `internal/keys/keys.go`
- Modify: `internal/oidc/discovery.go` (add the JWKS document type)
- Modify: `internal/oidc/router.go:122-127` (the `certs` handler)
- Modify: `internal/conformance/server_test.go` (the `keys.Generate` call)
- Modify: `cmd/gloak/main.go` (the `keys.Generate` call)
- Modify: `internal/keys/keys_test.go`
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

**Interfaces:**
- Consumes: `Case`, the recorder.
- Produces: `func keys.Generate(subjectCN string) (*RealmKeys, error)`, `func (k *RealmKeys) CertificateDER() []byte`, `type oidc.jwksDocument`.

- [ ] **Step 1: Add the JWKS cases to `catalog_oidc.go`**

Append to `oidcCore`:

```go
	{
		ID: "oidc/certs/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master/protocol/openid-connect/certs"},
		AssertHeaders: []string{"Content-Type"},
		// The realm key is generated per process, so everything derived from
		// it varies. The field set, their order, and the algorithm metadata
		// are what this case pins.
		Volatile: []string{
			"keys/*/kid",
			"keys/*/n",
			"keys/*/x5c",
			"keys/*/x5t",
			"keys/*/x5t#S256",
		},
	},
	{
		ID: "oidc/certs/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/protocol/openid-connect/certs"},
		AssertHeaders: []string{"Content-Type"},
	},
```

- [ ] **Step 2: Record and read the golden**

Run: `make record`
Run: `cat internal/conformance/testdata/golden/oidc/certs/master.http`

Write down, from the file and not from memory:
- the exact order of the keys inside each JWKS entry
- which fields Keycloak emits that Gloak does not
- whether `x5t#S256` is present

Keycloak's `master` realm publishes more than one key in `keys`. Note how many
and with which `alg` values. If the entry count differs from Gloak's single
RSA key, that is a second finding: record it in the follow-ups document rather
than widening this task, since it belongs with F5 (keys are generated per
process and never persisted).

- [ ] **Step 3: Run the verifier to see it fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/oidc/certs' -v`
Expected: FAIL on the body, with the diff naming the missing fields and the
order difference.

- [ ] **Step 4: Give the realm key a certificate**

In `internal/keys/keys.go`, add to the struct and `Generate`:

```go
type RealmKeys struct {
	RSAKeyID  string
	HMACKeyID string

	rsaKey  *rsa.PrivateKey
	certDER []byte
	hmacKey []byte
}

// Generate creates a fresh RSA key for RS256, a self-signed certificate over
// it, and a fresh secret for HS512. Keycloak publishes the certificate in the
// JWKS as x5c with its two thumbprints, so the key alone is not enough.
// subjectCN is the realm name, which is what appears in the published
// certificate's subject.
func Generate(subjectCN string) (*RealmKeys, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keys: generate rsa: %w", err)
	}
	certDER, err := selfSign(rsaKey, subjectCN)
	if err != nil {
		return nil, err
	}
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("keys: generate hmac: %w", err)
	}
	return &RealmKeys{
		RSAKeyID:  model.NewID(),
		HMACKeyID: model.NewID(),
		rsaKey:    rsaKey,
		certDER:   certDER,
		hmacKey:   hmacKey,
	}, nil
}

// selfSign issues the certificate Keycloak publishes alongside a realm key.
// The validity window is fixed rather than derived from the clock so that two
// processes generating a key produce comparable certificates; nothing
// validates this chain, it is published for clients that pin x5c.
func selfSign(key *rsa.PrivateKey, subjectCN string) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Unix(0, 0).UTC().AddDate(100, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("keys: self-sign: %w", err)
	}
	return der, nil
}

// CertificateDER is the realm certificate, published as x5c and hashed into
// x5t and x5t#S256.
func (k *RealmKeys) CertificateDER() []byte { return k.certDER }
```

Add `crypto/x509`, `crypto/x509/pkix`, `math/big` and `time` to the imports.

Set the certificate's subject to whatever step 2 showed in the recorded x5c.
Decode it with:

```bash
python3 - <<'EOF'
import base64, json, re, subprocess
raw = open('internal/conformance/testdata/golden/oidc/certs/master.http','rb').read()
body = raw.split(b'\n\n',1)[1]
for k in json.loads(body)['keys']:
    for c in k.get('x5c', []):
        subprocess.run(['openssl','x509','-inform','DER','-noout','-subject','-dates'],
                       input=base64.b64decode(c))
EOF
```

If the golden shows `{{string}}` for `x5c` because the case marks it volatile,
re-run the request by hand against the container to read a real certificate.

- [ ] **Step 5: Update `Generate`'s callers**

- `cmd/gloak/main.go`: pass the realm name the server bootstraps, `"master"`.
- `internal/conformance/server_test.go`: `keys.Generate("master")`.
- `internal/oidc/discovery_test.go`: `keys.Generate("master")`.
- `internal/keys/keys_test.go`: pass `"master"` and add a case asserting
  `CertificateDER()` parses with `x509.ParseCertificate` and that its public
  key equals the JWKS entry's.

- [ ] **Step 6: Run the keys tests**

Run: `CGO_ENABLED=0 go test ./internal/keys/ -v`
Expected: PASS.

- [ ] **Step 7: Give JWKS a Gloak-owned document type**

`certs` currently hands `jose.JSONWebKeySet` to `httpx.WriteJSON`, so the order
is go-jose's `rawJSONWebKey`: `use, kty, kid, alg, n, e, x5c, x5t, x5t#S256`.
That is a third-party struct with a third-party order, the same failure
AGENTS.md describes for `map[string]any`.

In `internal/oidc/discovery.go`, add - with the field order transcribed from
the golden read in step 2, not from this plan:

```go
// jwksDocument is the JWKS as Keycloak orders it. Field order is taken from
// internal/conformance/testdata/golden/oidc/certs/master.http; go-jose's own
// marshalling uses a different order, which is why the set is not handed to
// httpx.WriteJSON directly.
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	// Declare these in the recorded order.
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	N       string   `json:"n"`
	E       string   `json:"e"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
}

// jwksFor builds the published key set from a realm's signing material.
func jwksFor(k *keys.RealmKeys) jwksDocument {
	set := k.JWKS()
	pub := set.Keys[0].Key.(*rsa.PublicKey)
	der := k.CertificateDER()
	sha1Sum := sha1.Sum(der)
	sha256Sum := sha256.Sum256(der)
	enc := base64.RawURLEncoding
	return jwksDocument{Keys: []jwksKey{{
		Kid:     set.Keys[0].KeyID,
		Kty:     "RSA",
		Alg:     set.Keys[0].Algorithm,
		Use:     set.Keys[0].Use,
		N:       enc.EncodeToString(pub.N.Bytes()),
		E:       enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		X5c:     []string{base64.StdEncoding.EncodeToString(der)},
		X5t:     enc.EncodeToString(sha1Sum[:]),
		X5tS256: enc.EncodeToString(sha256Sum[:]),
	}}}
}
```

Add `crypto/sha1`, `crypto/sha256`, `math/big` to the imports. `x5c` uses
standard base64 with padding, per RFC 7517; the thumbprints use base64url
without padding. Confirm both against the golden.

Then change the handler in `internal/oidc/router.go`:

```go
func (h *handler) certs(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.resolveRealm(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, jwksFor(h.keys))
}
```

- [ ] **Step 8: Run the verifier**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/oidc/certs' -v`
Expected: PASS. If the order is still wrong, reorder the struct fields to match
the golden - never the other way round.

- [ ] **Step 9: Record the measurement in the observed spec**

Add a `## Certificate endpoint` section to
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` holding the
field order, the number of published keys and their algorithms, the base64
variants, and the certificate subject. This closes half of follow-up F3, so
also strike the `/protocol/openid-connect/certs` half of the F3 entry in
`docs/superpowers/specs/2026-08-18-gloak-followups.md`.

- [ ] **Step 10: Run everything and commit**

Run: `make test && make lint`
Expected: PASS.

```bash
git add internal/ docs/ cmd/
git commit -m "fix(oidc): publish the realm certificate in JWKS in Keycloak's order"
```

---

### Task 8: Realm info

**Files:**
- Modify: `internal/conformance/catalog_oidc.go`
- Modify: `internal/oidc/router.go:129-165`
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`
- Modify: `docs/superpowers/specs/2026-08-18-gloak-followups.md`

**Interfaces:**
- Consumes: `Case`, the recorder.
- Produces: a measured `realmInfoDocument`.

- [ ] **Step 1: Add the cases**

Append to `oidcCore` in `catalog_oidc.go`, using the same shape as Task 7's
entries, with:

```go
	{
		ID: "realm/info/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/index.html",
			Section:   "Realm public information endpoint used by adapters",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master"},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"public_key"},
	},
	{
		ID: "realm/info/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/index.html",
			Section:   "Realm public information endpoint used by adapters",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm"},
		AssertHeaders: []string{"Content-Type"},
	},
```

- [ ] **Step 2: Record and read**

Run: `make record`
Run: `cat internal/conformance/testdata/golden/realm/info/master.http`

Note the exact field names and their order. The current
`realmInfoDocument` doc comment says the order was chosen rather than measured;
this step replaces the guess.

- [ ] **Step 3: Run the verifier to see it fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/realm/info' -v`
Expected: FAIL on the body if the field set or order differs.

- [ ] **Step 4: Correct `realmInfoDocument`**

Redeclare the struct in `internal/oidc/router.go` with the fields in the
recorded order, adding any field the golden shows and Gloak omits. Replace the
doc comment, which currently says the order is chosen:

```go
// realmInfoDocument is Keycloak's public realm descriptor. Field order is
// measured: see the realm info section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md and
// internal/conformance/testdata/golden/realm/info/master.http.
```

- [ ] **Step 5: Run the verifier**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/realm/info' -v`
Expected: PASS.

- [ ] **Step 6: Record the measurement and close F3**

Add a `## Realm info endpoint` section to the observed spec. Remove the F3
entry from the follow-ups document, since both of its endpoints are now
measured, and note in its place that the conformance verifier now enforces the
rule for every future endpoint.

- [ ] **Step 7: Run everything and commit**

Run: `make test && make lint`

```bash
git add internal/ docs/
git commit -m "fix(oidc): match the measured realm info document"
```

---

### Task 9: The 404 and 405 fallbacks

`internal/oidc/router.go:39-50` documents these two bodies as reused from the
admin API's bad-token shape because neither was measured. This task measures
them.

**Files:**
- Modify: `internal/conformance/catalog_oidc.go`
- Modify: `internal/oidc/router.go:51-77`
- Modify: `docs/superpowers/specs/2026-08-18-gloak-followups.md`

- [ ] **Step 1: Add the cases**

```go
	{
		ID: "http/fallback/unknown-path",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: paths outside the endpoint set",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/nosuchpath"},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "http/fallback/method-not-allowed",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodPost, Path: "/realms/master/.well-known/openid-configuration"},
		AssertHeaders: []string{"Content-Type"},
	},
```

- [ ] **Step 2: Record and read**

Run: `make record`
Run: `cat internal/conformance/testdata/golden/http/fallback/*.http`

Keycloak may answer either of these with HTML rather than JSON, or with a
status other than 404 and 405. Whatever it sends is the contract.

- [ ] **Step 3: Run the verifier to see it fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/http/fallback' -v`

- [ ] **Step 4: Correct `withKeycloakFallbacks`**

Change the bodies and statuses in `internal/oidc/router.go` to what was
recorded, and rewrite the function's doc comment: it currently explains that
the shapes are borrowed because they were not measured, and that is no longer
true. If Keycloak sends a non-JSON body, add a `httpx` writer for it rather
than writing bytes in the router - `internal/httpx` is the only place a
response body is formatted.

- [ ] **Step 5: Run the verifier and the whole suite**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/http/fallback' -v`
Run: `make test && make lint`
Expected: PASS.

- [ ] **Step 6: Close the follow-up item**

In `docs/superpowers/specs/2026-08-18-gloak-followups.md`, remove the bullet
reading "Two response shapes are chosen rather than measured", or narrow it to
whatever remains unmeasured.

- [ ] **Step 7: Commit**

```bash
git add internal/ docs/
git commit -m "fix(oidc): match the measured 404 and 405 fallback responses"
```

---

### Task 10: Measured response headers

Until now every case asserts only `Content-Type`. This task widens the
assertion to the headers Keycloak actually sends, which is where
`Cache-Control` and the CORS headers live - all written from memory today, per
follow-up F3.

**Files:**
- Modify: `internal/conformance/catalog_oidc.go`
- Modify: `internal/oidc/router.go`
- Modify: `internal/httpx/errors.go` if a header belongs on every response

- [ ] **Step 1: Read the recorded headers**

Run: `head -12 internal/conformance/testdata/golden/oidc/discovery/master.http`
Run: `head -12 internal/conformance/testdata/golden/oidc/certs/master.http`
Run: `head -12 internal/conformance/testdata/golden/realm/info/master.http`

List the headers that are not `Date` or `Content-Length`.

- [ ] **Step 2: Widen `AssertHeaders` on all eight cases**

Set `AssertHeaders` to every non-volatile header name the goldens show. Keep
the lists per case rather than sharing one slice: the endpoints differ, and a
shared list would hide that.

- [ ] **Step 3: Run the verifier to see it fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance -v`
Expected: FAIL, naming each missing or differing header.

- [ ] **Step 4: Set the headers**

Add them in the handlers, or in `internal/httpx` if a header is on every
response. Do not invent a value: each one comes from the golden.

- [ ] **Step 5: Run the verifier and the whole suite**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance -v`
Run: `make test && make lint`
Expected: PASS.

- [ ] **Step 6: Confirm re-recording is still clean**

Run: `make record && git status --short internal/conformance/testdata/`
Expected: no modified files.

- [ ] **Step 7: Commit**

```bash
git add internal/
git commit -m "fix(oidc): send the measured response headers"
```

---

### Task 11: The pending OIDC inventory

**Files:**
- Modify: `internal/conformance/catalog_oidc.go`
- Create: `internal/conformance/catalog_oidc_pending.go`

**Interfaces:**
- Consumes: `Case`.
- Produces: `var oidcPending []Case`, appended to `Catalog` in `catalog.go`.

- [ ] **Step 1: Re-read the source page**

Open `https://www.keycloak.org/securing-apps/oidc-layers` and list its
endpoints and grant types. As of 2026-08-20 it names eleven endpoints - the
well-known configuration, authorization, token, userinfo, logout, certificate,
introspection, dynamic client registration, token revocation, device
authorization and backchannel authentication endpoints - and six grants:
authorization code, implicit, resource owner password credentials, client
credentials, device authorization, and client initiated backchannel
authentication.

If the page has changed, the page wins: it is the inventory source. Update the
`Retrieved` dates accordingly.

- [ ] **Step 2: Write `catalog_oidc_pending.go`**

One `Case` per documented behaviour, every one `Status: Pending` with a
`Reason`. Set `Fixture: "bootstrap"` only where a freshly bootstrapped Keycloak
can serve the request unaided - the `admin-cli` password grant is the main one,
since the observed spec already documents it working with `admin`/`admin`.
Everything needing a confidential client, a second user or a completed browser
login gets `Fixture: ""` so the recorder skips it.

Group the file with a comment header per endpoint. The shape of each entry:

```go
// oidcPending is the documented OIDC surface Gloak does not serve yet. Each
// entry is one behaviour named at https://www.keycloak.org/securing-apps/oidc-layers.
// Recording a pending case is deliberate: the bytes become the specification
// for the feature before anybody starts writing it.
var oidcPending = []Case{
	// --- Token endpoint ---
	{
		ID: "oidc/token/password-grant-admin-cli",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: Resource Owner Password Credentials grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "bootstrap",
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
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token",
			"expires_in", "refresh_expires_in", "session_state",
		},
	},
	{
		ID: "oidc/token/unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: client authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "nosuchclient",
				"username":   "admin",
				"password":   "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/userinfo/invalid-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "userinfo is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer not-a-token"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
	},
	// ... the remaining IDs from the checklist below.
}
```

Write one entry per ID. Sixty in total, three of which are shown above:

**authorization** (11) - `oidc/authorization/` + `code-flow-redirect`,
`pkce-s256`, `pkce-plain`, `implicit-flow`, `response-mode-fragment`,
`response-mode-form-post`, `prompt-none-no-session`, `invalid-redirect-uri`,
`unknown-client-id`, `missing-response-type`, `unsupported-scope`.

Note that `admin-cli` has standard flow **disabled**, so authorization-endpoint
cases use `security-admin-console`, which is public with standard flow enabled.

**token** (17) - `oidc/token/` + `password-grant-admin-cli`, `unknown-client`,
`authorization-code-grant`, `refresh-token-grant`, `client-credentials-grant`,
`device-code-grant`, `ciba-grant`, `token-exchange`, `jwt-authorization-grant`,
`dpop-bound-token`, `wrong-password`, `wrong-client-secret`,
`missing-grant-type`, `unknown-grant-type`, `replayed-code`,
`invalid-refresh-token`, `pkce-verifier-mismatch`.

The last seven correspond row-for-row to the shape-1 table in the observed
spec, which is a useful cross-check once they are recorded.

**userinfo** (5) - `oidc/userinfo/` + `invalid-token`, `get-with-valid-token`,
`post-with-valid-token`, `expired-token`, `missing-authorization-header`.

**logout** (5) - `oidc/logout/` + `rp-initiated-with-id-token-hint`,
`rp-initiated-without-id-token-hint`, `invalid-post-logout-redirect-uri`,
`backchannel`, `frontchannel`.

**introspection** (4) - `oidc/introspection/` + `active-access-token`,
`active-refresh-token`, `inactive-token`, `unauthenticated-client`.

**revocation** (4) - `oidc/revocation/` + `refresh-token`, `access-token`,
`unknown-token`, `wrong-client`.

**device authorization** (5) - `oidc/device/` + `authorization-request`,
`poll-authorization-pending`, `poll-slow-down`, `poll-expired-token`,
`poll-access-denied`.

**backchannel authentication** (3) - `oidc/ciba/` + `authentication-request`,
`poll-pending`, `poll-complete`.

**dynamic client registration** (6) - `oidc/registration/` + `create-client`,
`read-client`, `update-client`, `delete-client`,
`without-initial-access-token`, `with-registration-access-token`.

Do not decide `Fixture` from theory. Set it to `"bootstrap"` wherever the
request plausibly needs nothing beyond a freshly bootstrapped realm - the
error cases mostly do - then run the recorder and move to `Fixture: ""` every
case that could not be recorded. Which of these Keycloak serves unaided is a
measurement, not a guess.

- [ ] **Step 3: Append the slice to the catalogue**

In `catalog.go`:

```go
	all = append(all, oidcPending...)
```

- [ ] **Step 4: Run the well-formedness test**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestCatalogIsWellFormed -v`
Expected: PASS. A failure here names the entry missing a `Reason` or carrying a
duplicate ID.

- [ ] **Step 5: Run the verifier**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance`
Expected: PASS, with the pending cases skipped and the eight implemented cases
passing.

- [ ] **Step 6: Record what the bootstrap fixture can reach**

Run: `make record`
Expected: goldens appear for the pending cases marked `Fixture: "bootstrap"`,
and the log lists the fixture-less ones as skipped.

Read the recorded token response and check it against the observed spec's
"Token endpoint response" section: field order `access_token, expires_in,
refresh_expires_in, refresh_token, token_type, id_token, not-before-policy,
session_state, scope`. A mismatch means either the spec or the recording is
wrong, and the recording wins - update the spec and say so in the commit.

- [ ] **Step 7: Check the coverage report**

Run: `make conformance`
Expected: a table with roughly 8 implemented against 60-odd pending, and the
inventory-only column showing the cases waiting on fixtures.

- [ ] **Step 8: Commit**

```bash
git add internal/conformance/
git commit -m "feat(conformance): catalogue the documented OIDC surface as pending"
```

---

### Task 12: Documentation

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`

- [ ] **Step 1: Add the boundary row to `AGENTS.md`**

In the Boundaries table, after the `cmd/gloak` row:

```markdown
| `internal/conformance` | the documentation-derived catalogue and golden comparison | be imported by production code, or know about SQL or handler internals; it sees only an `http.Handler` |
```

- [ ] **Step 2: Extend the "one rule" section of `AGENTS.md`**

Replace the paragraph naming the two unmeasured endpoints - both are measured
now - with a description of how the rule is enforced:

```markdown
The rule is no longer only a convention. `internal/conformance` fails the build
for any endpoint marked `Implemented` that has no recorded golden, so shipping a
response nobody measured is a red test rather than something a reviewer has to
catch.
```

- [ ] **Step 3: Add the record-and-review workflow to `README.md`**

Under Development, after the Postgres suite paragraph:

```markdown
### Conformance against a live Keycloak

The regression catalogue in `internal/conformance` lists documented Keycloak
behaviours. The documentation supplies the list; a running Keycloak supplies the
expected bytes. Nothing in the suite asserts a value taken from a document.

```bash
make conformance   # how much of the documented surface is served
make record        # re-record expected bytes from Keycloak 26.7.1; needs Docker
```

`make record` rewrites the expected values in
`internal/conformance/testdata/golden`. Read its diff before committing: an
unreviewed re-record pins a regression as the new contract.

An endpoint served without a recorded golden fails `make test`. That is
deliberate - it is how "measured, never remembered" stops being a convention.
```

- [ ] **Step 4: Update the status list in `README.md`**

The "Working today" list gains the conformance suite. The Documentation table
gains two rows:

```markdown
| `docs/superpowers/specs/2026-08-20-conformance-harness-design.md` | design of the conformance harness |
| `docs/superpowers/plans/2026-08-20-conformance-harness.md` | the plan that produced it |
```

- [ ] **Step 5: Verify everything one more time**

Run: `make test && make lint && make build`
Run: `make conformance`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add AGENTS.md README.md
git commit -m "docs: describe the conformance harness and its record workflow"
```

---

## Notes for the implementer

**When a recorded value contradicts something written here, the recording
wins.** Several tasks above deliberately do not state the expected value,
because stating it would mean writing it from memory. That is not an omission
to fill in with a guess - it is the method.

**Do not mark a shipped endpoint `Pending` to make a red test go away.** The
verifier's state table is the whole point of the harness; that shortcut removes
it.

**One thing this slice does not fix.** `httpx.WriteOAuthError` marshals from
`map[string]string`, which Go sorts alphabetically. It happens to produce
`error` before `error_description`, which matches Keycloak, so nothing is
broken today - but it is the pattern AGENTS.md forbids, and it is load-bearing
the moment a third field appears. The token endpoint is not implemented, so no
case exercises it in this slice. Leave it; note it in the follow-ups document
so the OIDC slice starts from it.
