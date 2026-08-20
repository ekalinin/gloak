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
