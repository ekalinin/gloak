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
