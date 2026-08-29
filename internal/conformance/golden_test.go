package conformance

import (
	"net/http"
	"path/filepath"
	"strings"
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

func TestRecordedHeadersMasksACaseVolatileHeader(t *testing.T) {
	// Every admin 201 carries a Location holding a UUID minted at request
	// time. Without masking it, every create case churns on each recording -
	// the disease four goldens already had.
	c := Case{VolatileHeaders: []string{"Location"}}
	h := http.Header{
		"Location":     {"http://localhost:8080/admin/realms/master/clients/9f1c-uuid"},
		"Content-Type": {"application/json"},
	}

	got, err := recordedHeaders(h, "http://localhost:8080", c, nil)
	if err != nil {
		t.Fatalf("recordedHeaders: %v", err)
	}

	byName := map[string]string{}
	for _, entry := range got {
		byName[entry.Name] = entry.Value
	}
	if byName["Location"] != volatilePlaceholder {
		t.Errorf("Location was not masked: %q", byName["Location"])
	}
	// A header that is not named stays verbatim, or masking one would hide
	// every other divergence in the same response.
	if byName["Content-Type"] != "application/json" {
		t.Errorf("Content-Type was masked too: %q", byName["Content-Type"])
	}
}

// TestRecordedHeadersKeepsEverythingBeforeAVolatileTail is F46's whole point:
// the seven admin creates masked their Location entire, so a golden said
// nothing about the scheme, the host or the collection the new object landed
// in - only that some non-empty value came back.
func TestRecordedHeadersKeepsEverythingBeforeAVolatileTail(t *testing.T) {
	c := Case{VolatileTailHeaders: []string{"Location"}}
	h := http.Header{
		"Location": {"http://localhost:8080/admin/realms/master/clients/a7c1bc36-4492-48f4-8363-c7a7f47b0cc1"},
	}

	got, err := recordedHeaders(h, "http://localhost:8080", c, nil)
	if err != nil {
		t.Fatalf("recordedHeaders: %v", err)
	}

	want := issuerPlaceholder + "/admin/realms/master/clients/" + uuidTailPlaceholder
	if got[0].Value != want {
		t.Errorf("want %q, got %q", want, got[0].Value)
	}
}

// TestRecordedHeadersRefusesATailThatIsNotMinted covers the three admin creates
// that must not use this field: a role's Location ends in the role's name and a
// realm's in the realm's name. Masking those would throw away a measurement
// while looking like it had made one.
func TestRecordedHeadersRefusesATailThatIsNotMinted(t *testing.T) {
	c := Case{ID: "admin/realms-admin/create", VolatileTailHeaders: []string{"Location"}}
	h := http.Header{"Location": {"http://localhost:8080/admin/realms/gloak-probe-realm-created"}}

	_, err := recordedHeaders(h, "http://localhost:8080", c, nil)

	if err == nil {
		t.Fatal("a Location ending in a realm name was masked as though it were minted")
	}
	if !strings.Contains(err.Error(), "gloak-probe-realm-created") {
		t.Errorf("the error should name the value it refused: %v", err)
	}
}

func TestMaskURLTailRefusesAValueWithNoPath(t *testing.T) {
	if _, ok := MaskURLTail("a7c1bc36-4492-48f4-8363-c7a7f47b0cc1"); ok {
		t.Error("a bare UUID has no path to keep, so masking it asserts nothing")
	}
}

func TestGoldenPathTurnsSlugSegmentsIntoDirectories(t *testing.T) {
	want := filepath.Join("testdata", "golden", "oidc", "discovery", "master.http")
	if got := GoldenPath("testdata/golden", "oidc/discovery/master"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
