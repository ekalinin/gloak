package conformance

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestReplaceIssuerRewritesEveryOccurrence(t *testing.T) {
	in := []byte(`{"issuer":"http://localhost:18091/realms/master","jwks_uri":"http://localhost:18091/realms/master/certs"}`)
	want := `{"issuer":"{{issuer}}/realms/master","jwks_uri":"{{issuer}}/realms/master/certs"}`
	if got := string(ReplaceIssuer(in, "http://localhost:18091")); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestReplaceIssuerRewritesAPercentEncodedIssuer(t *testing.T) {
	// The authorization endpoint's redirect carries the issuer as a query
	// parameter, percent-encoded, so the raw base URL never appears in it. A
	// raw-only pass leaves a golden that differs by the recorder's port.
	in := []byte("http://localhost:9999/callback?state=xyz123" +
		"&iss=http%3A%2F%2Flocalhost%3A18091%2Frealms%2Fmaster")
	want := "http://localhost:9999/callback?state=xyz123&iss={{issuer}}%2Frealms%2Fmaster"

	if got := string(ReplaceIssuer(in, "http://localhost:18091")); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestReplaceIssuerRewritesBothSpellingsInOneValue(t *testing.T) {
	// The Location header holds both at once: the redirect target is not the
	// issuer, but the iss parameter is, and the same header can hold a raw
	// issuer too when the client redirects back to the server itself.
	in := []byte("http://localhost:18091/admin/master/console/" +
		"?iss=http%3A%2F%2Flocalhost%3A18091%2Frealms%2Fmaster")
	want := "{{issuer}}/admin/master/console/?iss={{issuer}}%2Frealms%2Fmaster"

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

// TestNormalizeLeavesNonJSONBodiesAloneWhenNoPathsAreDeclared pins the
// no-op path: with an empty path list, Normalize never looks at the body,
// so a body that is not JSON - empty or otherwise - comes back untouched.
// This is what lets a 401 with an empty body (the userinfo rejection) go
// through this function safely.
func TestNormalizeLeavesNonJSONBodiesAloneWhenNoPathsAreDeclared(t *testing.T) {
	for _, in := range [][]byte{[]byte(""), []byte("not json at all")} {
		got, err := Normalize(in, nil)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		if string(got) != string(in) {
			t.Fatalf("want %q back, got %q", in, got)
		}
	}
}

// TestNormalizeErrorsOnANonJSONBodyWithPathsDeclared is the fail-loud
// counterpart. Once a case declares Volatile paths, Normalize has to parse
// the body to find them; a body that fails to parse is an error, not a
// silent pass-through, since matching Keycloak by coincidence because
// nobody looked would defeat what this harness exists to check.
func TestNormalizeErrorsOnANonJSONBodyWithPathsDeclared(t *testing.T) {
	if _, err := Normalize([]byte("not json at all"), []string{"a"}); err == nil {
		t.Fatal("want an error for a non-JSON body with paths declared, got nil")
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

// TestSortUnorderedSortsATwoElementArray pins the basic case: elements come
// back lexicographically ordered by their own raw bytes, and the fields
// surrounding the array are untouched.
func TestSortUnorderedSortsATwoElementArray(t *testing.T) {
	in := []byte(`{"before":1,"scopes":["b","a"],"after":2}`)
	got, err := SortUnordered(in, []string{"scopes"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}
	want := `{"before":1,"scopes":["a","b"],"after":2}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestSortUnorderedResolvesANestedPath(t *testing.T) {
	in := []byte(`{"a":{"b":["z","y","x"]}}`)
	got, err := SortUnordered(in, []string{"a/b"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}
	want := `{"a":{"b":["x","y","z"]}}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestSortUnorderedWildcardMatchesOneSegment(t *testing.T) {
	in := []byte(`{"items":[{"tags":["b","a"]},{"tags":["y","x"]}]}`)
	got, err := SortUnordered(in, []string{"items/*/tags"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}
	want := `{"items":[{"tags":["a","b"]},{"tags":["x","y"]}]}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestSortUnorderedLeavesAnAlreadySortedArrayUnchanged(t *testing.T) {
	in := []byte(`{"scopes":["a","b","c"]}`)
	got, err := SortUnordered(in, []string{"scopes"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}
	if string(got) != string(in) {
		t.Fatalf("want %s, got %s", in, got)
	}
}

// TestSortUnorderedRejectsANonArrayPath is the negative test: Unordered
// exists to assert membership while giving up order, and a path that does
// not point at an array means the wrong path was named. Silently doing
// nothing would hide that mistake.
func TestSortUnorderedRejectsANonArrayPath(t *testing.T) {
	in := []byte(`{"scopes":"not-an-array"}`)
	if _, err := SortUnordered(in, []string{"scopes"}); err == nil {
		t.Fatal("want an error for a path that is not an array, got nil")
	}
}

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
			name:  "changes nothing when already sorted",
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

// The role listings are bare arrays at the root of the body and their order is
// not stable across container starts, so the suite has to be able to sort a
// value that is not under any key.
func TestSortUnorderedReachesTheDocumentRoot(t *testing.T) {
	in := []byte(`[{"name":"zeta"},{"name":"alpha"},{"name":"mu"}]`)

	got, err := SortUnordered(in, []string{"."})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}

	want := `[{"name":"alpha"},{"name":"mu"},{"name":"zeta"}]`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// TestSortUnorderedSortsANestedPathUnderTheRoot is F59.
//
// editor.value matched the root first and editor.sortArray decoded the whole
// document in one go, so "*/protocolMappers" was never visited and no error
// said so. The case that found it - admin/client-scopes/list - looked as
// though it asserted each scope's mappers and did not.
//
// Both orders have to come out sorted here. The element bytes are chosen so
// that sorting the inner arrays changes which element sorts first at the root:
// with the mappers left alone, {"m":["z","a"]} sorts after {"m":["b"]}, and
// with them sorted it sorts before. So a version that sorts only the root
// fails on the root as well, and this cannot pass by only half working.
func TestSortUnorderedSortsANestedPathUnderTheRoot(t *testing.T) {
	in := []byte(`[{"m":["z","a"]},{"m":["b"]}]`)

	got, err := SortUnordered(in, []string{".", "*/m"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}

	want := `[{"m":["a","z"]},{"m":["b"]}]`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// The same shape one level in, so the fix is not about the root spelling: an
// outer path and an inner path are both honoured wherever they sit.
func TestSortUnorderedSortsAPathInsideAnotherPath(t *testing.T) {
	in := []byte(`{"outer":[{"m":["z","a"]},{"m":["b"]}]}`)

	got, err := SortUnordered(in, []string{"outer", "outer/*/m"})
	if err != nil {
		t.Fatalf("SortUnordered: %v", err)
	}

	want := `{"outer":[{"m":["a","z"]},{"m":["b"]}]}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// A nested path that names something that is not an array still fails loudly.
// The depth passes must not turn F59's silence into a different silence: the
// inner walk reaches the value, so the wrong path is reported as it always was.
func TestSortUnorderedStillRejectsANonArrayNestedPath(t *testing.T) {
	in := []byte(`[{"m":"not-an-array"}]`)

	if _, err := SortUnordered(in, []string{".", "*/m"}); err == nil {
		t.Fatal("want an error for a nested path that is not an array, got nil")
	}
}

// Normalize's outer mask still wins over an inner one. The depth passes make
// the inner edit first and the outer replacement then covers it, which is the
// same answer the single walk gave - the point being that the refactor did not
// quietly change what a case with both paths declares.
func TestNormalizeMasksAnOuterPathThatContainsAnInnerOne(t *testing.T) {
	in := []byte(`{"a":{"b":"secret"},"z":1}`)

	got, err := Normalize(in, []string{"a", "a/b"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	want := `{"a":"{{object}}","z":1}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// "." addresses the root and nothing else. A key that happens to be spelled
// "." is not something Keycloak emits, but the pattern language has to be
// unambiguous or a later reader will assume the wrong one.
func TestRootPathDoesNotMatchANestedKey(t *testing.T) {
	in := []byte(`{".":[2,1]}`)

	got, err := SortUnordered(in, []string{"."})
	if err == nil {
		t.Fatalf("want an error for a root path over an object, got %s", got)
	}
}

// MaskedValues is what lets a guard ask a mask what it covers. Its whole
// justification is that it is the masking walk with a different onMatch, so it
// is tested on the same shapes the masks are: a wildcard, a nested path and the
// root.
func TestMaskedValuesReturnsWhatTheMasksWouldEdit(t *testing.T) {
	in := []byte(`{"a":{"b":[1,2]},"rows":[{"id":"x"},{"id":"y"}],"c":"one two"}`)

	got, err := MaskedValues(in, []string{"a/b", "rows/*/id", "c"})
	if err != nil {
		t.Fatalf("MaskedValues: %v", err)
	}
	// Deepest path group first, which is editPaths' order and not the
	// document's: "rows/*/id" is three segments, "a/b" two and "c" one. Written
	// down because document order is what a reader assumes, and a caller that
	// pairs these values with the paths that asked for them would be wrong.
	want := []string{`"x"`, `"y"`, `[1,2]`, `"one two"`}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %s", want, got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("value %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

// A path addressing nothing is the finding the inertness guard rests on, and
// the masks are silent about it: Normalize walks the body, matches nothing and
// edits nothing, with no error at all. An empty result has to mean exactly that
// and not "something went wrong", or a guard reads a failure as a clean sweep.
func TestMaskedValuesReturnsNothingForAPathThatIsNotThere(t *testing.T) {
	in := []byte(`[]`)

	got, err := MaskedValues(in, []string{"*/id"})
	if err != nil {
		t.Fatalf("MaskedValues: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no values for a path over an empty array, got %s", got)
	}
	// The same body through the mask itself, to show the silence is the mask's
	// and not this function's.
	masked, err := Normalize(in, []string{"*/id"})
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if string(masked) != `[]` {
		t.Fatalf("Normalize edited a body it addresses nothing in: %s", masked)
	}
}

func TestMaskedValuesReachesTheDocumentRoot(t *testing.T) {
	in := []byte(`[{"id":"x"}]`)

	got, err := MaskedValues(in, []string{"."})
	if err != nil {
		t.Fatalf("MaskedValues: %v", err)
	}
	if len(got) != 1 || string(got[0]) != `[{"id":"x"}]` {
		t.Fatalf("want the whole document, got %s", got)
	}
}

// TestReplaceThemeResourceRewritesEveryMeasuredVersion runs the pass over the
// thirteen values a live 26.7.1 has actually produced.
//
// The list is the evidence for the pattern's alphabet and length and is not
// decoration: three come off the goldens this pass promotes, and ten were taken
// on 2026-09-01, two from two containers and eight from eight fresh databases
// inside one. Sixty-five characters, none of them upper case.
func TestReplaceThemeResourceRewritesEveryMeasuredVersion(t *testing.T) {
	measured := []string{
		"l3kth", "fl8wm", "ynxld", // off the parked goldens
		"t72jg", "880ae", // two containers
		"ooekw", "oupiz", "3fprx", "sktey", // eight fresh databases
		"foqmc", "k3fzh", "qctvi", "rj2lz",
	}
	for _, v := range measured {
		in := []byte(`<link href="/resources/` + v + `/login/keycloak.v2/css/styles.css" rel="stylesheet" />`)
		want := `<link href="/resources/{{theme_resource}}/login/keycloak.v2/css/styles.css" rel="stylesheet" />`
		if got := string(ReplaceThemeResource(in)); got != want {
			t.Errorf("version %q: want %s, got %s", v, want, got)
		}
	}
}

// A page carries the segment seven times and the pass has to reach all of
// them. One occurrence rewritten and six left is the shape a ReplaceFirst would
// take, and it would still make the pass look as though it worked on a diff of
// one line.
func TestReplaceThemeResourceRewritesEveryOccurrence(t *testing.T) {
	in := []byte(`<link href="/resources/t72jg/login/keycloak.v2/img/favicon.ico" />` +
		`<link href="/resources/t72jg/common/keycloak/vendor/patternfly-v5/patternfly.min.css" />` +
		`import { startSessionPolling } from "/resources/t72jg/login/keycloak.v2/js/authChecker.js";`)
	got := ReplaceThemeResource(in)
	if n := bytes.Count(got, []byte(themeResourcePlaceholder)); n != 3 {
		t.Fatalf("want three occurrences rewritten, got %d: %s", n, got)
	}
	if bytes.Contains(got, []byte("t72jg")) {
		t.Fatalf("a version survived the pass: %s", got)
	}
}

// The pattern is anchored on what has been measured, so a segment that is not
// five lowercase alphanumerics is left alone. These are the shapes a pattern
// written against "what a token could in principle be" would have swallowed.
func TestReplaceThemeResourceLeavesAnUnmeasuredShapeAlone(t *testing.T) {
	for _, in := range []string{
		`/resources/t72j/login/keycloak.v2/x.css`,   // four characters
		`/resources/t72jgg/login/keycloak.v2/x.css`, // six
		`/resources/T72JG/login/keycloak.v2/x.css`,  // upper case
		`/resources/t72-g/login/keycloak.v2/x.css`,  // a hyphen
		`/resources/t72jg`,                          // no trailing slash
	} {
		if got := string(ReplaceThemeResource([]byte(in))); got != in {
			t.Errorf("want %s untouched, got %s", in, got)
		}
	}
}

// TestReplaceThemeResourceOverReachesExactlyHere is the other half, and it
// asserts the damage rather than hiding it.
//
// Two shapes are swallowed that a reader would not expect, and both are worth
// having written down rather than discovered:
//
//   - **`login` is itself five lowercase alphanumerics.** A URL spelled
//     `/resources/login/...` is indistinguishable from a versioned one. The real
//     theme URLs are `/resources/<version>/login/...`, so `login` is always the
//     *second* segment and never the first - but a page whose prose named the
//     directory directly would be rewritten.
//   - **The pattern is not anchored to the start of a path.** `/admin/resources/`
//     matches as readily as `/resources/`.
//
// Neither reaches any committed golden, which is what
// TestThemeResourceAppearsOnlyInTheThemePages keeps true.
func TestReplaceThemeResourceOverReachesExactlyHere(t *testing.T) {
	cases := map[string]string{
		`/resources/login/keycloak.v2/x.css`:   `/resources/{{theme_resource}}/keycloak.v2/x.css`,
		`{"path":"/admin/resources/t72jg/x"}`:  `{"path":"/admin/resources/{{theme_resource}}/x"}`,
		`see /resources/theme/index.html here`: `see /resources/{{theme_resource}}/index.html here`,
	}
	for in, want := range cases {
		if got := string(ReplaceThemeResource([]byte(in))); got != want {
			t.Errorf("want %s, got %s", want, got)
		}
	}
}

// The pass is unconditional, so it runs over every JSON body in the catalogue
// too. It is idempotent by construction - the placeholder is not five lowercase
// alphanumerics - and this is what says so, because a second pass is exactly
// what the recorder and the verifier between them perform.
func TestReplaceThemeResourceIsIdempotent(t *testing.T) {
	in := []byte(`<link href="/resources/rj2lz/login/keycloak.v2/css/styles.css" />`)
	once := ReplaceThemeResource(in)
	twice := ReplaceThemeResource(once)
	if !bytes.Equal(once, twice) {
		t.Fatalf("second pass changed the body: %s then %s", once, twice)
	}
}

// TestThemeResourceAppearsOnlyInTheThemePages is the bound on the pass's
// over-reach, and it is a fact about the tree rather than a hope about regexes.
//
// The pattern rewrites `/resources/<five lowercase alphanumerics>/` wherever it
// finds it, prose included. What makes that safe is that `/resources/` appears
// in no committed golden outside the login theme's own pages, and that every
// one of those carries the segment a fixed number of times. The day a ninth
// occurrence appears, or the segment turns up in a body that is not a theme
// page, this test is what says so - one step before somebody wonders why a
// golden churned.
func TestThemeResourceAppearsOnlyInTheThemePages(t *testing.T) {
	// Counted from the goldens, not incremented: every theme page carries the
	// segment seven times, and the two rendered from **inside** an
	// authentication flow carry an eighth, because the head's checkAuthSession
	// block imports authChecker.js a second time. Measured on thirteen responses
	// on 2026-09-03: eight segments on every page with the block and seven on
	// every page without one, with no page in between.
	want := map[string]int{
		"oidc/authorization/invalid-redirect-uri": 7,
		"oidc/authorization/unknown-client-id":    7,
		// The ninth, and the same page as unknown-client-id served for a realm
		// that is not master: the segment count is a property of the head, not
		// of the realm, so it is seven here too.
		"oidc/authorization/second-realm-error-page": 7,
		"oidc/authorization/max-age-invalid":         7,
		"oidc/authorization/prompt-create":           8,
		// The second page with the block, and the first of F146's nine to carry
		// a golden at all.
		"oidc/authorization/session-code-wrong-execution": 8,
		"oidc/logout/invalid-post-logout-redirect-uri":    7,
		"oidc/logout/invalid-id-token-hint":               7,
		"oidc/device/verification-page":                   7,
		"oidc/device/status-page":                         7,
		// The tenth, and the device verification page served for a realm that
		// is not master. Seven again, for the ninth's reason: the count is a
		// property of the head, which every one of these pages shares.
		"oidc/device/second-realm-verification-page": 7,
		// The /login-actions family's error page, four times. Seven again, and
		// the reason is worth keeping beside the number: this page is the head
		// and nothing more, which is exactly why it is the one page in that
		// family that can carry a golden at all. prompt-create's eighth comes
		// from a checkAuthSession block these do not have.
		"oidc/authorization/login-actions-invalid-client-data":    7,
		"oidc/authorization/login-actions-restart-cookie-missing": 7,
		"oidc/authorization/login-actions-unknown-client":         7,
		"oidc/authorization/required-action-invalid-client-data":  7,
	}
	seen := map[string]bool{}
	for _, c := range Catalog {
		raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
		if err != nil {
			continue // no golden, which other tests are responsible for
		}
		n := bytes.Count(raw, []byte("/resources/"))
		if n == 0 {
			continue
		}
		seen[c.ID] = true
		if _, isThemePage := want[c.ID]; !isThemePage {
			t.Errorf("%q: holds %d /resources/ segments and is not a theme page - "+
				"ReplaceThemeResource runs over every body, so read what it would do to this one",
				c.ID, n)
			continue
		}
		if n != want[c.ID] {
			t.Errorf("%q: holds %d /resources/ segments, want %d", c.ID, n, want[c.ID])
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("%q: named here as a theme page and its golden holds no /resources/ segment", id)
		}
	}
}

// themePageFragment is the shape the HTML masks are written against: the two
// places a per-request value sits in a keycloak.v2 page, both read off a live
// 26.7.1 on 2026-09-03. The restart URL is inside a JavaScript string and spells
// its separators raw; the link is inside an href attribute and spells them
// &amp;. One page carries both spellings, which is why the masker accepts both.
const themePageFragment = `        startSessionPolling(
            "/realms/master/login-actions/restart?client_id=gloak-probe-browser&tab_id=oNX0Amj1DZE&client_data=eyJ4IjoxfQ&skip_logout=true"
        );
            <a id="loginRestartLink" href="/realms/master/login-actions/restart?client_id=gloak-probe-browser&amp;tab_id=oNX0Amj1DZE&amp;client_data=eyJ4IjoxfQ&amp;skip_logout=false">Click here</a>
            checkAuthSession(
                "doFZB1zRPGOwAFS6vATrE1oVD2qWWY6KFelQy8dCVcCt8s6bcYz+IRa0N1Yd/L8w"
            );`

// TestReplaceHTMLValuesMasksTheValueAndNothingElse is the whole bargain in one
// assertion: the tab_id goes at both of its spellings, the checkAuthSession
// argument goes, and every other byte - the realm, the endpoint, the client_id,
// the client_data, the two different skip_logout values, the order of all of
// them and the indentation - is still there to be compared.
func TestReplaceHTMLValuesMasksTheValueAndNothingElse(t *testing.T) {
	got, err := ReplaceHTMLValues([]byte(themePageFragment), Case{
		VolatileHTMLQuery: []string{"tab_id"},
		VolatileHTMLCall:  []string{"checkAuthSession"},
	})
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	want := strings.NewReplacer(
		"oNX0Amj1DZE", "{{tab_id}}",
		"doFZB1zRPGOwAFS6vATrE1oVD2qWWY6KFelQy8dCVcCt8s6bcYz+IRa0N1Yd/L8w", "{{checkAuthSession}}",
	).Replace(themePageFragment)
	if string(got) != want {
		t.Fatalf("want:\n%s\ngot:\n%s", want, got)
	}
}

// The values a mask covers are what the guard reads, from the same two finders
// the masker splices with. Two tab_ids, one argument.
func TestHTMLMaskedValuesReadsWhatTheMaskCovers(t *testing.T) {
	values, err := HTMLMaskedValues([]byte(themePageFragment), Case{
		VolatileHTMLQuery: []string{"tab_id", "skip_logout"},
		VolatileHTMLCall:  []string{"checkAuthSession"},
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for name, want := range map[string][]string{
		"tab_id":           {"oNX0Amj1DZE", "oNX0Amj1DZE"},
		"skip_logout":      {"true", "false"},
		"checkAuthSession": {"doFZB1zRPGOwAFS6vATrE1oVD2qWWY6KFelQy8dCVcCt8s6bcYz+IRa0N1Yd/L8w"},
	} {
		got := make([]string, 0, len(values[name]))
		for _, v := range values[name] {
			got = append(got, string(v))
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: covers %q, want %q", name, got, want)
		}
	}
}

// A mask naming something the body does not carry is refused rather than
// applied, because the failure it would otherwise produce blames the page.
// The golden would hold {{tab_id}}, the served body would hold the raw value,
// and the diff would say the markup was wrong.
func TestReplaceHTMLValuesRefusesAMaskThatCoversNothing(t *testing.T) {
	for _, c := range []Case{
		{VolatileHTMLQuery: []string{"session_code"}},
		{VolatileHTMLCall: []string{"noSuchFunction"}},
	} {
		if _, err := ReplaceHTMLValues([]byte(themePageFragment), c); err == nil {
			t.Errorf("%+v: a mask over nothing was applied rather than refused", c)
		}
	}
}

// A query mask fires on a whole parameter and not on the tail of a longer one.
// Without the boundary check `tab_id` would also mask `client_tab_id`, and a
// mask that reaches further than it says is the disease this file's other
// comments keep naming.
func TestHTMLQueryMaskDoesNotFireOnALongerParameterName(t *testing.T) {
	in := []byte(`href="/x?client_tab_id=AAA&tab_id=BBB"`)
	got, err := ReplaceHTMLValues(in, Case{VolatileHTMLQuery: []string{"tab_id"}})
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	if want := `href="/x?client_tab_id=AAA&tab_id={{tab_id}}"`; string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// The same rule for a call: a function whose name merely ends in the declared
// one is a different function.
//
// The prefix here is deliberately lower case. This test read
// `preCheckAuthSession` until a mutation removed the boundary check and survived
// it: the capital C means the needle `checkAuthSession(` never occurred in that
// name at all, so the test named a rule it could not see. A test whose input
// cannot reach the branch it is about is a test that passes for the wrong
// reason.
func TestHTMLCallMaskDoesNotFireOnALongerFunctionName(t *testing.T) {
	in := []byte(`xcheckAuthSession("A"); checkAuthSession("B");`)
	got, err := ReplaceHTMLValues(in, Case{VolatileHTMLCall: []string{"checkAuthSession"}})
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	if want := `xcheckAuthSession("A"); checkAuthSession("{{checkAuthSession}}");`; string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// A call whose first argument is not a quoted string is refused rather than
// masked, which is MaskURLTail's rule: covering something of another shape
// throws away a measurement while looking like it checked one.
//
// The second quoted string is what makes this test discriminate. Without it a
// masker that skipped the shape check still failed - on "the argument is not
// terminated" - so the mutation that removed the check survived. With a quote
// further down the body the unchecked masker finds one and covers everything
// between, which is the damage the check exists to stop.
func TestHTMLCallMaskRefusesAnArgumentThatIsNotAString(t *testing.T) {
	if _, err := ReplaceHTMLValues([]byte(`checkAuthSession(session); other("x");`),
		Case{VolatileHTMLCall: []string{"checkAuthSession"}}); err == nil {
		t.Fatal("a call with a bare identifier argument was masked rather than refused")
	}
}

// An empty value is refused too. A mask over no bytes asserts nothing and hides
// that it asserts nothing, which is the shape AGENTS.md calls worse than none.
func TestReplaceHTMLValuesRefusesAnEmptyValue(t *testing.T) {
	if _, err := ReplaceHTMLValues([]byte(`href="/x?tab_id=&y=1"`),
		Case{VolatileHTMLQuery: []string{"tab_id"}}); err == nil {
		t.Fatal("an empty query value was masked rather than refused")
	}
	if _, err := ReplaceHTMLValues([]byte(`checkAuthSession("");`),
		Case{VolatileHTMLCall: []string{"checkAuthSession"}}); err == nil {
		t.Fatal("an empty call argument was masked rather than refused")
	}
}

// TestHTMLMaskKeepsTheURLAroundItCompared is F38's third ground read from the
// other side. Masking a whole <script> block would do to a page what masking a
// whole Location did to a create - assert presence and nothing else - so the
// claim to check is not "the tab_id went" but "everything beside it still
// decides the comparison". Two bodies differing only in the client_id, with the
// tab_id masked on both, must not compare equal.
func TestHTMLMaskKeepsTheURLAroundItCompared(t *testing.T) {
	c := Case{VolatileHTMLQuery: []string{"tab_id"}}
	mask := func(body string) string {
		out, err := ReplaceHTMLValues([]byte(body), c)
		if err != nil {
			t.Fatalf("mask %q: %v", body, err)
		}
		return string(out)
	}
	// The tab_id is deliberately **not** the last parameter. It was, until a
	// mutation widened the value to "everything up to the closing quote" and
	// survived: with the tab_id last the two spellings cover the same bytes, so
	// the test could not see the difference between masking a value and masking
	// the rest of the URL.
	const one = `href="/realms/master/login-actions/restart?tab_id=AAA&client_id=gloak-probe-browser&skip_logout=true"`
	const other = `href="/realms/master/login-actions/restart?tab_id=BBB&client_id=gloak-probe-other&skip_logout=true"`
	if mask(one) == mask(other) {
		t.Fatal("two URLs naming different clients compared equal once the tab_id was masked")
	}
	// And the same URL with only the tab_id moved does compare equal, which is
	// the half that makes the mask worth having.
	const again = `href="/realms/master/login-actions/restart?tab_id=CCC&client_id=gloak-probe-browser&skip_logout=true"`
	if mask(one) != mask(again) {
		t.Fatal("the same URL with a fresh tab_id did not compare equal")
	}
}

// A case declaring no HTML mask has its body handed back untouched, JSON or
// not. Every body in the catalogue goes through this pass.
func TestReplaceHTMLValuesLeavesAnUndeclaredBodyAlone(t *testing.T) {
	in := []byte(`{"tab_id":"AAA","checkAuthSession":"BBB"}`)
	got, err := ReplaceHTMLValues(in, Case{})
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("a case with no HTML mask had its body rewritten: %s", got)
	}
}
