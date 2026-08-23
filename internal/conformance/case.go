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

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Status says whether Gloak serves a documented behaviour today.
type Status int

const (
	// Implemented means Gloak serves this. It must have a golden file;
	// the verifier fails when it does not, which is how the project's
	// "measured, never remembered" rule becomes something the build checks.
	Implemented Status = iota
	// Pending means the behaviour is documented but not built yet.
	Pending
	// Recorded means the behaviour has been measured and written to a
	// golden, but Gloak does not serve it yet. It is Pending with the
	// contract already in the repository.
	//
	// The verifier serves a Recorded case and requires it *not* to match. A
	// skip would leave a case that starts passing as a side effect of
	// neighbouring work silently unguarded, so the next refactor could break
	// a contract nobody knew was being met. Making the match itself a
	// failure turns the list into one that clears itself.
	//
	// The assertion is weak on purpose: it passes on any difference and
	// proves only "not built yet". It is a status marker with an alarm on
	// it, not a correctness check.
	Recorded
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

	// Fixture names an entry in Fixtures: the server-side starting state,
	// plus any requests run before this one whose responses supply values
	// this one refers to as {{name}}. Empty means the setup does not exist
	// yet: the recorder skips the case and the coverage report counts it as
	// inventory only.
	Fixture string

	// Operation names the OpenAPI operation this case demonstrates is
	// **served**, spelled "METHOD path" as the vendored description spells it
	// - for example "GET /admin/realms/{realm}/clients". The protocol chapters
	// have no operation list and ignore it.
	//
	// It exists because a chapter's denominator counts operations while the
	// catalogue holds cases. Several cases exercise one operation, and
	// counting cases would report more served than there is surface. See
	// TestServedOperationsCountsEachOperationOnce.
	//
	// "Demonstrates is served" is narrower than "sends a request to", and the
	// difference is deliberate. A case that only pins a rejection - no
	// credentials, a caller without the role, an unknown realm - proves the
	// route exists and refuses correctly, not that the operation does its job.
	// Those cases leave this empty, so an endpoint whose success path is still
	// a stub does not count towards parity. Naming one is what claims the
	// operation, and forgetting to undercounts rather than inflates.
	Operation string

	// PristineRealm marks a case whose golden describes the realm as a whole
	// rather than one object in it. The recorder records these before every
	// other case.
	//
	// One container is shared across the whole recording, so state
	// accumulates in catalogue order. That is harmless for a case addressing
	// one object by UUID and destructive for one enumerating them: the three
	// clients the OIDC fixtures create turned up inside the unfiltered client
	// list golden and would have been committed as the contract. Nothing
	// resets the realm between cases, so recording first is the whole
	// guarantee - which is why TestPristineRealmGoldensAreNotPolluted checks
	// the result rather than trusting the ordering.
	PristineRealm bool

	Request Request

	// AssertHeaders lists the response headers compared exactly. Every header
	// is written to the golden; only these are asserted. The status line is
	// always compared.
	AssertHeaders []string

	// VolatileHeaders lists response headers whose value changes per response.
	// The value is masked to {{volatile}} in the golden and skipped when
	// comparing, while the header's presence stays asserted - a header the
	// implementation stopped sending entirely still fails.
	//
	// The measured example is the admin API's Location on a 201, which carries
	// a UUID minted at request time. Without this, every create case churns on
	// each recording; four goldens already had that disease. The package-level
	// VolatileHeaders in golden.go is the same idea applied to every case.
	VolatileHeaders []string

	// AssertAbsentHeaders lists response headers that must not be present.
	// AssertHeaders only ever checks a header that is named, so it can never
	// catch one that should be missing - a header Keycloak omits on some
	// responses but sends on most others (the five security headers on the
	// unmatched-path 404, for instance) would silently start passing if an
	// implementation began sending it everywhere "for consistency". This is
	// the field that pins the negative.
	AssertAbsentHeaders []string

	// Volatile lists slash-separated paths into the JSON body whose values
	// change per response. Their values are replaced before comparison while
	// their presence and position stay asserted. "*" matches one segment.
	Volatile []string

	// Unordered lists paths pointing at JSON arrays Keycloak emits in no
	// stable order. Their elements are sorted before comparison, so membership
	// and length stay asserted while order does not.
	Unordered []string

	// UnorderedKeys lists paths pointing at JSON objects whose key order is
	// not reproducible: Keycloak's `attributes` is a Java Map serialised in
	// hash order, and Go sorts map keys alphabetically. Both sides are sorted
	// before comparison, so membership and values stay asserted and only the
	// order stops being. This is the suite's one documented retreat from
	// byte-exactness - see editor.sortKeys.
	UnorderedKeys []string

	// UnorderedWords lists paths pointing at JSON strings whose
	// space-separated words Keycloak emits in no stable order - the token
	// response's scope is the measured example. Their words are sorted
	// before comparison, so membership stays asserted while order does not.
	UnorderedWords []string
}

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
