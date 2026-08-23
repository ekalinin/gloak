package conformance

import (
	"net/http"
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

func TestRecordedHeadersMasksACaseVolatileHeader(t *testing.T) {
	// Every admin 201 carries a Location holding a UUID minted at request
	// time. Without masking it, every create case churns on each recording -
	// the disease four goldens already had.
	c := Case{VolatileHeaders: []string{"Location"}}
	h := http.Header{
		"Location":     {"http://localhost:8080/admin/realms/master/clients/9f1c-uuid"},
		"Content-Type": {"application/json"},
	}

	got := recordedHeaders(h, "http://localhost:8080", c, nil)

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

func TestGoldenPathTurnsSlugSegmentsIntoDirectories(t *testing.T) {
	want := filepath.Join("testdata", "golden", "oidc", "discovery", "master.http")
	if got := GoldenPath("testdata/golden", "oidc/discovery/master"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
