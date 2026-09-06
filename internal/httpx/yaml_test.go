package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every want string below is bytes read off a live Keycloak 26.7.1 with
// `od -c` on 2026-09-06, container kc-wf on port 8177. None of it is what a
// YAML writer looked like it should produce.
func TestAppendYAMLDocumentReproducesTheMeasuredBodies(t *testing.T) {
	steps := []YAMLMap{{
		{Key: "uses", Value: "disable-user"},
		{Key: "after", Value: "P5D"},
		{Key: "id", Value: "c3bd4e19-a543-4db6-84d7-905cdb4bfcd8"},
	}}
	one := YAMLMap{
		{Key: "id", Value: "61ad9536-3e7b-454e-ba51-b101ed3a475a"},
		{Key: "name", Value: "t"},
		{Key: "on", Value: "user-created"},
		{Key: "steps", Value: steps},
	}

	cases := []struct {
		name string
		body any
		want string
	}{
		{
			// The empty listing, and the whole of what a default realm
			// answers: seven bytes with the marker and the empty flow
			// sequence on one line.
			name: "empty listing",
			body: []YAMLMap{},
			want: "--- []\n",
		},
		{
			// GET /admin/realms/master/workflows with one workflow. The
			// nested sequence's `-` is at column 2, the same column as the
			// `steps` key it belongs to.
			name: "listing of one",
			body: []YAMLMap{one},
			want: "---\n" +
				"- id: \"61ad9536-3e7b-454e-ba51-b101ed3a475a\"\n" +
				"  name: \"t\"\n" +
				"  \"on\": \"user-created\"\n" +
				"  steps:\n" +
				"  - uses: \"disable-user\"\n" +
				"    after: \"P5D\"\n" +
				"    id: \"c3bd4e19-a543-4db6-84d7-905cdb4bfcd8\"\n",
		},
		{
			// GET /admin/realms/master/workflows/{id}. The same workflow
			// one indent level out, which is the pair that says the
			// sequence indicator follows its parent key's column rather
			// than a fixed offset.
			name: "single read",
			body: one,
			want: "---\n" +
				"id: \"61ad9536-3e7b-454e-ba51-b101ed3a475a\"\n" +
				"name: \"t\"\n" +
				"\"on\": \"user-created\"\n" +
				"steps:\n" +
				"- uses: \"disable-user\"\n" +
				"  after: \"P5D\"\n" +
				"  id: \"c3bd4e19-a543-4db6-84d7-905cdb4bfcd8\"\n",
		},
		{
			// GET .../workflows/{id}?includeId=false drops `id` at both
			// levels, which is what makes a golden of this route hold no
			// server-minted value at all.
			name: "single read without ids",
			body: YAMLMap{
				{Key: "name", Value: "t"},
				{Key: "on", Value: "user-created"},
				{Key: "steps", Value: []YAMLMap{{
					{Key: "uses", Value: "disable-user"},
					{Key: "after", Value: "P5D"},
				}}},
			},
			want: "---\n" +
				"name: \"t\"\n" +
				"\"on\": \"user-created\"\n" +
				"steps:\n" +
				"- uses: \"disable-user\"\n" +
				"  after: \"P5D\"\n",
		},
		{
			// A nested mapping, and the one place an integer appears: a
			// schedule's `batch-size` is bare where every string beside it
			// is quoted. Measured on a workflow created with
			// `schedule: {after: P1D, batch-size: 25}`.
			name: "nested mapping and a bare integer",
			body: []YAMLMap{{
				{Key: "id", Value: "2b168459-e1a9-448d-841b-ad7d35947252"},
				{Key: "name", Value: "n4"},
				{Key: "on", Value: "user-created"},
				{Key: "schedule", Value: YAMLMap{
					{Key: "after", Value: "P1D"},
					{Key: "batch-size", Value: 25},
				}},
				{Key: "steps", Value: steps},
			}},
			want: "---\n" +
				"- id: \"2b168459-e1a9-448d-841b-ad7d35947252\"\n" +
				"  name: \"n4\"\n" +
				"  \"on\": \"user-created\"\n" +
				"  schedule:\n" +
				"    after: \"P1D\"\n" +
				"    batch-size: 25\n" +
				"  steps:\n" +
				"  - uses: \"disable-user\"\n" +
				"    after: \"P5D\"\n" +
				"    id: \"c3bd4e19-a543-4db6-84d7-905cdb4bfcd8\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(AppendYAMLDocument(nil, tc.body))
			if got != tc.want {
				t.Fatalf("body:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

// The quoting rule is the resolver's, not a list of one name. `on` is the only
// key any measured body quotes, and writing the rule is what keeps a step
// config key called `no` from round-tripping as a boolean.
func TestYAMLKeyQuotesOnlyWhatYAML11WouldResolveToANonString(t *testing.T) {
	quoted := []string{"on", "ON", "On", "off", "yes", "no", "n", "y", "true", "false", "null", "~", ""}
	for _, k := range quoted {
		if got := yamlKey(k); got != `"`+k+`"` {
			t.Errorf("yamlKey(%q) = %q, want it quoted", k, got)
		}
	}
	// Every key a measured workflow body carries, plus the two spellings
	// YAML 1.1's resolver does not match although a case-insensitive
	// comparison would.
	bare := []string{
		"id", "name", "steps", "uses", "after", "if", "schedule", "batch-size",
		"concurrency", "cancel-in-progress", "restart-in-progress",
		"scheduled-at", "status", "with", "state", "oN", "nO",
	}
	for _, k := range bare {
		if got := yamlKey(k); got != k {
			t.Errorf("yamlKey(%q) = %q, want it bare", k, got)
		}
	}
}

func TestAppendYAMLQuotedEscapes(t *testing.T) {
	cases := map[string]string{
		"plain":      `"plain"`,
		`a"b`:        `"a\"b"`,
		`a\b`:        `"a\\b"`,
		"a\nb":       `"a\nb"`,
		"a\tb":       `"a\tb"`,
		"a\rb":       `"a\rb"`,
		"a\x00b":     `"a\x00b"`,
		"già":        `"già"`,
		"disable-us": `"disable-us"`,
	}
	for in, want := range cases {
		if got := string(appendYAMLQuoted(nil, in)); got != want {
			t.Errorf("appendYAMLQuoted(%q) = %s, want %s", in, got, want)
		}
	}
}

// The header set is the finding this file exists to pin: four security headers
// and not five, on a 200 with a body, decided by the media type.
func TestWriteYAMLSendsFourSecurityHeadersAndNoCacheControl(t *testing.T) {
	rec := httptest.NewRecorder()
	// The router sets all five before the mux runs, so the writer has to
	// delete rather than decline to set. Reproduced here.
	SetSecurityHeaders(rec)
	WriteYAML(rec, http.StatusOK, []YAMLMap{})

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Type"); got != "application/yaml;charset=UTF-8" {
		t.Errorf("Content-Type %q", got)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "" {
		t.Errorf("X-Frame-Options = %q, want it absent on a YAML body", got)
	}
	for _, name := range []string{
		"Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Robots-Tag",
	} {
		if res.Header.Get(name) == "" {
			t.Errorf("%s is absent", name)
		}
	}
	if got := res.Header.Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control = %q, want none on any workflow route", got)
	}
	if body := rec.Body.String(); body != "--- []\n" {
		t.Errorf("body %q", body)
	}
}

// WriteYAML suppresses Date for the reason suppressDate gives, and the
// conformance harness cannot see it. This is the per-writer test AGENTS.md's
// Date bullet says a per-writer rule needs - WriteNoContent was the writer
// that did not have one.
func TestWriteYAMLSendsNoDateHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteYAML(w, http.StatusOK, YAMLMap{{Key: "name", Value: "t"}})
	}))
	defer srv.Close()

	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if _, ok := res.Header["Date"]; ok {
		t.Errorf("Date = %q, want it suppressed", res.Header.Get("Date"))
	}
}
