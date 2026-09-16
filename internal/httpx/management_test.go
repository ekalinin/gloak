package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The four documents the management interface serves, as they came off a
// socket on 2026-09-16 from `quay.io/keycloak/keycloak:26.7.1 start-dev` with
// KC_HEALTH_ENABLED set and KC_METRICS_ENABLED unset.
//
// **These are transcriptions of a recording, and that is a weaker thing than a
// golden.** The conformance suite compares five of the eight routes against
// committed goldens recorded by `make record`; the three documents no golden
// holds - the health-only index, the two-check aggregate and the 503 - are
// checked here and nowhere else, because the recorder runs its containers with
// both options and so records the other option set's bytes. A test comparing
// against bytes somebody typed is worth exactly the care taken typing them,
// which is why each carries the byte count the socket reported: a transcription
// error changes the length, and the length was read off the wire rather than
// counted here.
const (
	// 225 bytes. GET /health and GET /health/ready on a healthy server.
	measuredAggregateUp = "{\n" +
		"    \"status\": \"UP\",\n" +
		"    \"checks\": [\n" +
		"        {\n" +
		"            \"name\": \"Graceful Shutdown\",\n" +
		"            \"status\": \"UP\"\n" +
		"        },\n" +
		"        {\n" +
		"            \"name\": \"Keycloak Initialized\",\n" +
		"            \"status\": \"UP\"\n" +
		"        }\n" +
		"    ]\n" +
		"}"

	// 229 bytes, and a 503. The same two paths during an actual drain, caught
	// by polling through `docker kill -s TERM`.
	measuredAggregateDown = "{\n" +
		"    \"status\": \"DOWN\",\n" +
		"    \"checks\": [\n" +
		"        {\n" +
		"            \"name\": \"Graceful Shutdown\",\n" +
		"            \"status\": \"DOWN\"\n" +
		"        },\n" +
		"        {\n" +
		"            \"name\": \"Keycloak Initialized\",\n" +
		"            \"status\": \"UP\"\n" +
		"        }\n" +
		"    ]\n" +
		"}"

	// 45 bytes. GET /health/live, /health/started, /health/well, /health/group
	// and /health/group/{anything}, in every state measured including the
	// drain and a stopped database.
	measuredEmpty = "{\n" +
		"    \"status\": \"UP\",\n" +
		"    \"checks\": [\n" +
		"    ]\n" +
		"}"

	// 120 bytes. GET / with --health-enabled alone.
	measuredIndex = "<html>\n" +
		"<h2>Keycloak Management Interface</h2>\n" +
		"<ul><li><a href=\"/health\">/health</a> - Health endpoint</li></ul>\n" +
		"</html>\n"

	// 53 bytes. Every unmatched path, on every verb.
	measuredNotFound = "<html><body><h1>Resource not found</h1></body></html>"
)

// gracefulShutdown and keycloakInitialized are the two check names this project
// publishes. They are spelled here rather than imported from internal/management
// on purpose: a test reading the constant the code writes compares a value with
// itself, which is the tautology TestManagementCasesDeclareTheSecurityHeadersAbsent
// was rewritten to avoid. These two strings came off the wire.
const (
	gracefulShutdown    = "Graceful Shutdown"
	keycloakInitialized = "Keycloak Initialized"
)

// TestHealthDocumentIsTheMeasuredBytes compares all three documents, their
// statuses and their headers against the recording.
//
// The byte count is asserted separately from the bytes, and it is not
// redundant: the length is the one number that was read off the socket rather
// than transcribed, so it is the independent check on the transcription above.
func TestHealthDocumentIsTheMeasuredBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []HealthCheck
		want   string
		length int
		status int
	}{
		{
			name:   "the aggregate on a healthy server",
			checks: []HealthCheck{{gracefulShutdown, true}, {keycloakInitialized, true}},
			want:   measuredAggregateUp,
			length: 225,
			status: http.StatusOK,
		},
		{
			name:   "the aggregate during a drain",
			checks: []HealthCheck{{gracefulShutdown, false}, {keycloakInitialized, true}},
			want:   measuredAggregateDown,
			length: 229,
			status: http.StatusServiceUnavailable,
		},
		{
			name:   "a group with no checks in it",
			checks: nil,
			want:   measuredEmpty,
			length: 45,
			status: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteHealthDocument(w, tc.checks)

			if got := w.Body.String(); got != tc.want {
				t.Errorf("body differs from the recording.\nwant: %q\ngot:  %q", tc.want, got)
			}
			if got := w.Body.Len(); got != tc.length {
				t.Errorf("body is %d bytes, the socket reported %d", got, tc.length)
			}
			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			if got := w.Header().Get("Content-Type"); got != "application/json; charset=UTF-8" {
				t.Errorf("Content-Type = %q, want the upper-case charset this port sends", got)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store on every response in this family", got)
			}
		})
	}
}

// TestHealthDocumentIsAlwaysJSON walks the arities the measured table does not.
//
// The table above holds two checks and none, because those are the two a
// Keycloak with --health-enabled alone was measured serving. **One is the arity
// the separator logic is most likely to get wrong** and there is no recording of
// it, so this asserts a property rather than bytes: whatever the writer emits
// parses, and holds the entries it was given. Claiming bytes for an arity
// nothing measured would be inventing a contract; claiming the document is JSON
// is not.
func TestHealthDocumentIsAlwaysJSON(t *testing.T) {
	for n := 0; n <= 3; n++ {
		t.Run(fmt.Sprintf("%d checks", n), func(t *testing.T) {
			checks := make([]HealthCheck, n)
			for i := range checks {
				checks[i] = HealthCheck{Name: fmt.Sprintf("check %d", i), Up: true}
			}
			w := httptest.NewRecorder()
			WriteHealthDocument(w, checks)

			var doc struct {
				Status string `json:"status"`
				Checks []struct {
					Name   string `json:"name"`
					Status string `json:"status"`
				} `json:"checks"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
				t.Fatalf("the document does not parse: %v\n%q", err, w.Body)
			}
			if len(doc.Checks) != n {
				t.Errorf("document holds %d checks, want %d: %q", len(doc.Checks), n, w.Body)
			}
			for i, c := range doc.Checks {
				if want := fmt.Sprintf("check %d", i); c.Name != want {
					t.Errorf("check %d is named %q, want %q", i, c.Name, want)
				}
			}
			if doc.Status != "UP" {
				t.Errorf("status = %q, want UP", doc.Status)
			}
		})
	}
}

// TestHealthDocumentStatusFollowsTheChecks is the claim the status line is not
// a parameter.
//
// It is separate from the table above because that table pairs each check set
// with the document it produced, and a mutation making the status constant
// would be caught there only by the two rows that happen to disagree. This
// asks the question directly and on a set the table does not hold: a document
// whose **last** check is the failing one.
func TestHealthDocumentStatusFollowsTheChecks(t *testing.T) {
	w := httptest.NewRecorder()
	WriteHealthDocument(w, []HealthCheck{{gracefulShutdown, true}, {keycloakInitialized, false}})

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a document whose last check is DOWN answered %d, want 503", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "\"status\": \"DOWN\",\n") {
		t.Errorf("the top-level status did not follow the failing check: %q", body)
	}
	if !strings.Contains(body, "\"name\": \"Graceful Shutdown\",\n            \"status\": \"UP\"") {
		t.Errorf("the passing check was not left UP: %q", body)
	}
}

// onTheWire serves one writer through a real http.Server and returns the
// response as a client saw it.
//
// **An httptest.ResponseRecorder cannot answer the questions below.** It never
// adds a Date and it never sniffs a Content-Type, so a recorder-based check
// that either is absent passes whether or not the writer suppresses it - which
// is AGENTS.md's rule that a probe of an absence measures the probe, met inside
// this package rather than against a container. The existing Date tests in
// errors_test.go take the same route for the same reason.
func onTheWire(t *testing.T, write func(http.ResponseWriter)) *http.Response {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		write(w)
	}))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestManagementIndexSendsNoContentType is the finding made into an assertion.
//
// It is the only response in this repository that serves a body with no
// Content-Type, and Go will invent one for it: the body begins `<html>`, so
// net/http's sniffer sends `text/html; charset=utf-8` unless the header is
// explicitly suppressed. A reader of the writer cannot tell the suppression
// from its absence, which is exactly why this is a test - and why it goes
// through a real server, which is the only thing that sniffs.
func TestManagementIndexSendsNoContentType(t *testing.T) {
	w := httptest.NewRecorder()
	WriteManagementIndex(w)

	if got := w.Body.String(); got != measuredIndex {
		t.Errorf("index differs from the recording.\nwant: %q\ngot:  %q", measuredIndex, got)
	}
	if got := w.Body.Len(); got != 120 {
		t.Errorf("index is %d bytes, the socket reported 120", got)
	}

	resp := onTheWire(t, WriteManagementIndex)
	if got := resp.Header.Get("Content-Type"); got != "" {
		t.Errorf("the index page sent Content-Type %q; the measured response has none at all", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "" {
		t.Errorf("the index page sent Cache-Control %q; only the health family carries one", got)
	}
}

func TestManagementNotFoundIsTheMeasuredBytes(t *testing.T) {
	w := httptest.NewRecorder()
	WriteManagementNotFound(w)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if got := w.Body.String(); got != measuredNotFound {
		t.Errorf("body differs from the recording.\nwant: %q\ngot:  %q", measuredNotFound, got)
	}
	if got := w.Body.Len(); got != 53 {
		t.Errorf("body is %d bytes, the socket reported 53", got)
	}
	// Lower-case, where the health family's JSON on the same port is
	// upper-case. Both read off a socket.
	if got := w.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the lower-case charset this body sends", got)
	}
}

// TestManagementResponsesCarryNoSecurityHeadersAndNoDate sweeps all three
// writers against the five headers and Date.
//
// It is a sweep rather than three assertions because the mistake worth catching
// is the **next** writer added to this file, and because AGENTS.md's own bullet
// on these headers has been wrong six times - each correction adding a rule
// nobody had computed. This computes it.
func TestManagementResponsesCarryNoSecurityHeadersAndNoDate(t *testing.T) {
	writers := map[string]func(http.ResponseWriter){
		"WriteHealthDocument":     func(w http.ResponseWriter) { WriteHealthDocument(w, nil) },
		"WriteManagementIndex":    WriteManagementIndex,
		"WriteManagementNotFound": WriteManagementNotFound,
	}
	// Read from the package's own map, which is the set SetSecurityHeaders
	// sends. A list written out here could drop a name and agree with itself.
	if len(securityHeaders) != 5 {
		t.Fatalf("securityHeaders holds %d names; this sweep is about the five", len(securityHeaders))
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			resp := onTheWire(t, write)
			for header := range securityHeaders {
				if v := resp.Header.Get(header); v != "" {
					t.Errorf("%s sent %s: %q; no response on this port carries one", name, header, v)
				}
			}
			if v := resp.Header.Get("Date"); v != "" {
				t.Errorf("%s sent Date: %q; this port sends none, which agrees with the main one",
					name, v)
			}
		})
	}
}

// TestTheWireProbeCanSeeAHeaderItIsLookingFor is onTheWire's own guard.
//
// Every assertion above is an absence, and a probe that could see nothing at
// all would report every absence and mean none of them. This hands it a writer
// that sends all five security headers and a body Go would sniff, and requires
// it to see them.
func TestTheWireProbeCanSeeAHeaderItIsLookingFor(t *testing.T) {
	resp := onTheWire(t, func(w http.ResponseWriter) {
		SetSecurityHeaders(w)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>sniff me</html>"))
	})
	for header := range securityHeaders {
		if resp.Header.Get(header) == "" {
			t.Errorf("the probe could not see %s on a response that sends it", header)
		}
	}
	if got := resp.Header.Get("Content-Type"); got == "" {
		t.Error("the probe could not see the Content-Type net/http sniffs, so its " +
			"absence on the index page is asserted by nothing")
	}
	if got := resp.Header.Get("Date"); got == "" {
		t.Error("the probe could not see the Date net/http adds, so its absence " +
			"on these three writers is asserted by nothing")
	}
}
