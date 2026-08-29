package conformance

import "testing"

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
