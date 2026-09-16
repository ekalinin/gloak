package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The management interface's three response shapes.
//
// They are here rather than in internal/management for the reason every other
// body format is: this package owns response body formatting, and the one time
// a second writer appeared outside it, the two diverged on a trailing newline
// and nothing noticed. See the Boundaries table in AGENTS.md.
//
// **None of these carries any of the five security headers and none carries a
// Date**, which is not an omission but the widest measured exception to the
// security-header rule in this repository: a whole listener rather than a
// route, a family or a media type. Read off a socket on 2026-09-16 on every
// route shape and on the fallback, on containers started with
// KC_HEALTH_ENABLED alone and with both options.

// healthDocument is the MicroProfile Health document SmallRye renders, and it
// is **not** what encoding/json produces for the same values.
//
// Two details are the whole reason this is a written template rather than a
// MarshalIndent call, and both were read off a socket:
//
//   - an **empty** checks array is rendered `"checks": [` newline four spaces
//     `]`, where encoding/json writes `[]` however it is indented. The five
//     paths that answer the empty document are 45 bytes because of it;
//   - there is **no trailing newline**. The document ends at its closing brace.
//
// The name is marshalled through encoding/json rather than interpolated, so a
// name holding a quote could not break the document. No name this project
// publishes holds one; the escape is here because writing the string by hand is
// the thing that has to be got right, not because a measurement needs it.
const (
	healthOpen       = "{\n    \"status\": %q,\n    \"checks\": [\n"
	healthEntry      = "        {\n            \"name\": %s,\n            \"status\": %q\n        }"
	healthEntryComma = ",\n"
	healthEntryLast  = "\n"
	healthClose      = "    ]\n}"
)

// HealthCheck is one entry of a health document's checks array: a name the
// wire carries verbatim, and whether the predicate behind it holds.
//
// A check that is DOWN is **not** always a bare status. The datasource check
// Keycloak registers under --metrics-enabled gains a `data` object carrying
// `"Failing since": "<yyyy-MM-dd HH:mm:ss,SSS>"` when it fails, measured on a
// Postgres-backed container whose database was stopped under it. Neither check
// this project publishes has one: the graceful-shutdown check's DOWN was
// measured during an actual drain and carries `status` alone. So there is no
// Data field here, because no check Gloak serves has ever been measured with
// one - a field with no consumer is a claim about the shape that is not true.
type HealthCheck struct {
	// Name is the check's wire name, which is Keycloak's SPI name and is
	// reproduced rather than invented: a client polling /health and reading
	// check names is reading this string.
	Name string
	// Up is the predicate's current value. Whether it is computed or a
	// constant is the caller's business and is documented at the call site.
	Up bool
}

// WriteHealthDocument writes one MicroProfile Health document.
//
// **The status line follows the checks and is not a parameter**: a document
// whose top-level status disagreed with its own entries is a shape neither
// Keycloak nor this project can produce, and making it reachable would make it
// writable. Measured both ways on one container on 2026-09-16:
//
//	all checks UP    200 OK                   "status": "UP"
//	any check DOWN   503 Service Unavailable  "status": "DOWN"
//
// The 503 was caught by polling /health through an actual `docker kill -s TERM`
// drain - 799511 polls, three distinct answers - so the failure branch is a
// recording rather than an inference from the success one.
//
// Both headers are measured and neither is optional. Cache-Control is on every
// response in the health family, including the 503, and on nothing else this
// port serves.
func WriteHealthDocument(w http.ResponseWriter, checks []HealthCheck) {
	status := "UP"
	code := http.StatusOK
	for _, c := range checks {
		if !c.Up {
			status = "DOWN"
			code = http.StatusServiceUnavailable
			break
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, healthOpen, status)
	for i, c := range checks {
		// **The error is discarded rather than branched on.** json.Marshal of a
		// string cannot fail - invalid UTF-8 is replaced rather than refused -
		// so a branch here is one nothing can reach and nothing can test. It is
		// also a branch that would make things worse: skipping the entry would
		// leave the previous one's comma dangling and produce a document that is
		// not JSON, which is a worse answer than the one this cannot produce.
		name, _ := json.Marshal(c.Name)
		up := "UP"
		if !c.Up {
			up = "DOWN"
		}
		fmt.Fprintf(&b, healthEntry, name, up)
		if i == len(checks)-1 {
			b.WriteString(healthEntryLast)
		} else {
			b.WriteString(healthEntryComma)
		}
	}
	b.WriteString(healthClose)

	suppressDate(w)
	h := w.Header()
	// The charset is upper-case here and the Admin API's is not. This is the
	// management port's spelling, read off a socket, and it is a fourth
	// spelling of the parameter rather than one of the three AGENTS.md already
	// records for the application's own responses.
	h.Set("Content-Type", "application/json; charset=UTF-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(b.String()))
}

// managementIndex is the index page a Keycloak started with --health-enabled
// and **no** --metrics-enabled serves at `/`, byte for byte: 120 bytes,
// measured on a fresh container on 2026-09-16.
//
// **The page lists exactly the endpoints that are switched on**, so its bytes
// are a recording of an option set rather than of a version. The other two
// shapes were measured on their own containers the same day and this project
// serves neither: 180 bytes with both options - which is the shape
// management/index/root's golden holds - and 123 with --metrics-enabled alone.
//
// It is a constant and not a page assembled from a list of endpoints, because
// Gloak serves one option set and a builder would have one caller. If Gloak
// ever grows a metrics endpoint, the second line goes in here and the golden
// starts matching; until then a list would be a parameter with one value.
const managementIndex = "<html>\n" +
	"<h2>Keycloak Management Interface</h2>\n" +
	"<ul><li><a href=\"/health\">/health</a> - Health endpoint</li></ul>\n" +
	"</html>\n"

// WriteManagementIndex writes the management interface's index page.
//
// **It sends no Content-Type at all**, which is the only response in this
// repository that serves a body without one. Read at socket level the whole
// response is `HTTP/1.1 200 OK`, `content-length: 120`, and nothing else - no
// Content-Type, no Cache-Control, no Date, none of the five security headers.
//
// Go's http.Server sniffs a Content-Type from the first bytes written unless
// one is set, and this body begins `<html>`, so it would send
// `text/html; charset=utf-8` on its own. Setting the header to nil is what
// suppresses the sniff; leaving it unset would add a header the measurement
// says is absent.
func WriteManagementIndex(w http.ResponseWriter) {
	suppressDate(w)
	w.Header()["Content-Type"] = nil
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(managementIndex))
}

// managementNotFound is the management router's 404 body: 53 bytes of HTML from
// Quarkus's own management router, which never reaches Keycloak's JAX-RS
// application at all.
//
// It is a **third** producer of a 404 body in this repository and it is neither
// of the application's two - not `Unable to find matching target resource
// method` and not `HTTP 404 Not Found`. Every path on this port that is not one
// of the eight routes answers it, on every verb.
const managementNotFound = "<html><body><h1>Resource not found</h1></body></html>"

// WriteManagementNotFound writes the management router's 404.
//
// Its Content-Type is `text/html; charset=utf-8` with a **lower-case** charset,
// where the health family's JSON carries an upper-case one on the same port and
// in the same response set. Both were read off a socket.
func WriteManagementNotFound(w http.ResponseWriter) {
	suppressDate(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(managementNotFound))
}
