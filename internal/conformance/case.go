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
	"fmt"
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

// GoldenIsAsserted reports whether anything compares c's golden, and therefore
// whether `make record` may rewrite it.
//
// One predicate, two callers, because the two answers have to be the same one.
// TestConformance skips a Pending case whether or not a golden exists, so a
// Pending golden is compared by nothing; a recorder that rewrote it anyway
// produces a diff that says nothing and has to be reverted by hand. Four of
// them did, every run: the login-theme pages carry a /resources/<version>/
// segment that is minted with the database, so their whole body churned on a
// fresh container. The count went from three to four inside two days, which is
// what made the hand-reverting stop being a habit anybody could keep (F23,
// F69). Seven of the eight are compared contracts as of 2026-09-01 and the
// churn is gone with them, but the predicate is unchanged: this is what kept
// them still while nothing compared them.
//
// The "unless asked" is a status change rather than a flag. A golden worth
// re-recording is one worth comparing, and the catalogue already spells that:
// Recorded means measured but not served yet, and a Recorded case is recorded.
// Promoting a case is a one-word edit a reviewer sees in the diff, where an
// environment variable is a thing nobody sets and nobody reads.
//
// What this does not do is keep a parked golden honest. Nothing compares it, so
// nothing notices when Keycloak's answer moves underneath it - which was
// already true before the recorder stopped rewriting it, since the rewrite was
// compared by nothing either.
//
// F72 asked whether a Pending case should carry a golden at all, and the answer
// is that it may, and must be declared: parkedGoldens in case_test.go names
// every one of them and says what a reader is to do with it, which is to read
// it as a measurement and never as a contract. A Pending golden that is not
// declared fails, so the next one cannot arrive by accident.
func GoldenIsAsserted(c Case) bool { return c.Status != Pending }

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

	// RawQuery is the query string sent verbatim, for the one thing a
	// map[string]string cannot say: **the same key twice**.
	//
	// That is not a hypothetical shape. A repeated parameter is its own
	// measured error on the authorization endpoint - `duplicated parameter`,
	// step 7 of ten, lower case where every other description there is
	// capitalised, and it fires on keys the endpoint never reads, so `zz` twice
	// is enough. internal/oidc serves it and unit-tests it, and no golden could
	// express the request until this field existed. See F48.
	//
	// It replaces Query rather than adding to it: setting both is a catalogue
	// error, because merging them would need an order and there is no honest
	// one. It is also **not** expanded, so it cannot carry a {{name}} captured
	// by a fixture step - TestCatalogIsWellFormed refuses one rather than
	// letting a case send the braces to the server. Expand lives in
	// fixture.go and teaching it this field is a one-line change for whoever
	// needs it.
	//
	// Encoding is the case's own business here. url.Values.Encode escapes what
	// it emits; a raw string is sent as written, which is what makes a
	// deliberately malformed query expressible too.
	RawQuery string
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
	// rather than one object in it. The recorder gives each of these a
	// container of its own.
	//
	// One container is otherwise shared across the whole recording, so state
	// accumulates in catalogue order. That is harmless for a case addressing
	// one object by UUID and destructive for one enumerating them: the three
	// clients the OIDC fixtures create turned up inside the unfiltered client
	// list golden and would have been committed as the contract.
	//
	// This meant "recorded before every other case" until 2026-08-29, and
	// ordering cannot carry it. A pristine case whose fixture creates
	// something pollutes every pristine case after it, which is not a
	// hypothetical: admin/groups/list creates a group, admin/groups/count
	// counts it, and that case's number was masked for it, because the recorder
	// said 3 where a pristine replay says 2. **The mask came off when the
	// container regime landed** - F47 - and the golden holds `{"count":2}`
	// again, so the example is history rather than a live defect. Ordering also
	// cannot be checked - admin/users/count's body is the single byte `1`, and
	// no guard can tell a polluted count from a clean one. So the container is what
	// resets, not the position: bootstrap plus this case's own fixture, which
	// is exactly what the verifier's newFixture builds.
	//
	// TestPristineRealmGoldensAreNotPolluted still checks the bytes
	// afterwards. Two mechanisms for one property is deliberate here: the
	// recorder is the thing a reviewer cannot run in CI.
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
	// Set-Cookie on the login page is the measured example: every one of its
	// values is minted per request and none of it is contract. The
	// package-level VolatileHeaders in golden.go is the same idea applied to
	// every case.
	//
	// It is the blunt instrument. A header whose value is a URL ending in a
	// server-minted id belongs in VolatileTailHeaders, which keeps the rest of
	// the URL asserted.
	VolatileHeaders []string

	// VolatileTailHeaders lists response headers whose value is a URL whose
	// **final path segment** is minted per request. Everything up to the last
	// "/" is compared exactly; the segment after it is written to the golden as
	// {{uuid}} and required to be a UUID on both sides.
	//
	// It exists because masking a whole header asserts almost nothing: diff
	// checks a VolatileHeaders entry is present with a non-empty first value,
	// so `Location: x` passes. The seven admin creates all masked their
	// Location that way, and none of them asserted the scheme, the host, or the
	// path saying which collection the new object landed in. See F46.
	//
	// Measured on a live 26.7.1 on 2026-08-29, all seven Locations, which is
	// why only four of them use this field:
	//
	//	POST .../clients          .../clients/<uuid>
	//	POST .../users            .../users/<uuid>
	//	POST .../groups           .../groups/<uuid>
	//	POST .../groups/{id}/children  .../groups/<uuid>   - not under /children
	//	POST .../roles            .../roles/<the role name>
	//	POST .../clients/{id}/roles    .../clients/{{client_uuid}}/roles/<name>
	//	POST /admin/realms        /admin/realms/<the realm name>
	//
	// The last three carry nothing minted once ReplaceCaptured and
	// ReplaceIssuer have run, so they mask nothing at all and assert their
	// Location whole. Declaring one of them here is a loud failure rather than
	// a wider mask: the tail is not a UUID and both the recorder and the
	// verifier say so.
	VolatileTailHeaders []string

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

	// Unordered names JSON arrays whose element order is not stable, sorted on
	// both sides before comparison so membership stays asserted and order does
	// not. Paths are slash-separated from the root with "*" matching one
	// segment, and "." names the root itself - which is what a bare array
	// response needs, and every role listing is one.
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
	switch {
	case r.RawQuery != "" && len(r.Query) > 0:
		return nil, fmt.Errorf("conformance: %s %s sets both Query and RawQuery, "+
			"and nothing says which order to merge them in", r.Method, r.Path)
	case r.RawQuery != "":
		// Verbatim, so a key can appear twice. url.Values cannot hold that and
		// Encode would sort it away besides.
		target += "?" + r.RawQuery
	case len(r.Query) > 0:
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
