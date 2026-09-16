package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The two documents this port serves, transcribed from a socket on 2026-09-16
// against `quay.io/keycloak/keycloak:26.7.1 start-dev` with KC_HEALTH_ENABLED
// set and KC_METRICS_ENABLED unset.
//
// The bytes themselves are asserted in internal/httpx, which is where they are
// written. What these hold is the **routing**: which path answers which
// document, which is the half of this surface a reader would get wrong.
const (
	aggregate = `"name": "Graceful Shutdown"`
	empty     = "{\n    \"status\": \"UP\",\n    \"checks\": [\n    ]\n}"
	index     = "<h2>Keycloak Management Interface</h2>"
	notFound  = "<html><body><h1>Resource not found</h1></body></html>"
)

// answer is what a request got: the status and enough of the body to say which
// of the four documents it was.
type answer struct {
	status int
	body   string
}

func ask(t *testing.T, i *Interface, method, target string) answer {
	t.Helper()
	w := httptest.NewRecorder()
	i.Handler().ServeHTTP(w, httptest.NewRequest(method, target, nil))
	return answer{w.Code, w.Body.String()}
}

// TestTheRouteTableIsTheMeasuredOne walks every path measured on the reference
// container and requires this router to answer the same document.
//
// **The negative rows are the ones worth having.** `/health/x` being a 404 one
// segment above a `/health/group/x` that is a 200 is this surface's trap, and a
// router that answered the empty document to anything under /health would pass
// every positive row.
func TestTheRouteTableIsTheMeasuredOne(t *testing.T) {
	i := New()
	for _, tc := range []struct {
		path string
		want string
		code int
	}{
		// The index, and the three paths that clean to it.
		{"/", index, 200},
		{"//", index, 200},
		{"/..", index, 200},
		{"/health/..", index, 200},

		// The aggregate, and the paths that clean to it.
		{"/health", aggregate, 200},
		{"/health/", aggregate, 200},
		{"//health", aggregate, 200},
		{"///health", aggregate, 200},
		{"/./health", aggregate, 200},
		{"/health/./", aggregate, 200},
		{"/foo/../health", aggregate, 200},
		{"/health/../health", aggregate, 200},
		{"/health/ready", aggregate, 200},
		{"/health/ready/", aggregate, 200},

		// The empty document. /health/started is in this group and not the one
		// above, which is the finding: four MicroProfile paths, two documents.
		{"/health/live", empty, 200},
		{"/health/live/", empty, 200},
		{"/health/started", empty, 200},
		{"/health/well", empty, 200},
		{"/health/well/", empty, 200},
		{"/health/group", empty, 200},
		{"/health/group/", empty, 200},
		{"/health/group/nosuchgroup", empty, 200},
		{"/health/group/a/b", empty, 200},

		// The fallback. /metrics is here because Gloak has no metrics endpoint,
		// and a metrics-disabled Keycloak answers it exactly this way -
		// measured, on the health-only container.
		{"/metrics", notFound, 404},
		{"/metrics/nosuchsuffix", notFound, 404},
		{"/health/x", notFound, 404},
		{"/health/wel", notFound, 404},
		{"/health/wellness", notFound, 404},
		{"/HEALTH", notFound, 404},
		{"/Health", notFound, 404},
		{"/q/health", notFound, 404},
		{"/index.html", notFound, 404},
		{"/nosuchpath", notFound, 404},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got := ask(t, i, http.MethodGet, tc.path)
			if got.status != tc.code {
				t.Errorf("status = %d, want %d; body %q", got.status, tc.code, got.body)
			}
			if !strings.Contains(got.body, tc.want) {
				t.Errorf("body does not hold %q:\n%q", tc.want, got.body)
			}
		})
	}
}

// TestTheRouteTableDistinguishesTheTwoDocuments is the vacuity guard the table
// above needs and cannot contain.
//
// Every row asserts a substring, and `empty` is a substring of nothing else
// while `aggregate` is a substring of the aggregate alone - but a bug that made
// every route answer one document would satisfy whichever rows named it and
// fail the others, which is only useful if the two documents really differ.
// This says they do, and that the substrings tell them apart.
func TestTheRouteTableDistinguishesTheTwoDocuments(t *testing.T) {
	i := New()
	agg := ask(t, i, http.MethodGet, "/health").body
	emp := ask(t, i, http.MethodGet, "/health/live").body

	if agg == emp {
		t.Fatal("the aggregate and the empty document are the same bytes, so every " +
			"routing row above is satisfied by one answer")
	}
	if strings.Contains(emp, aggregate) {
		t.Error("the empty document holds the aggregate's marker, so the marker " +
			"separates nothing")
	}
	if strings.Contains(agg, empty) {
		t.Error("the aggregate holds the empty document's marker, so the marker " +
			"separates nothing")
	}
}

// TestEveryVerbAnswersTheRoutesOwn200 is the eighth data point in AGENTS.md's
// wrong-method bullet and the first outside the 404/405/406 family altogether.
//
// Seven verbs were measured on /health/live on the reference container and all
// seven answered the route's own 200 with its own document. There is no 405
// anywhere on this port and no Allow header, which is the opposite of the main
// port one socket away.
//
// HEAD is in the list and its body is not asserted: http.Server strips a body
// for a HEAD and httptest.ResponseRecorder does not, so what this can check is
// the status and the headers. That is F175's shape and the reason no HEAD case
// exists in the catalogue either.
func TestEveryVerbAnswersTheRoutesOwn200(t *testing.T) {
	i := New()
	verbs := []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodOptions, http.MethodHead, http.MethodTrace,
	}
	for _, verb := range verbs {
		t.Run(verb, func(t *testing.T) {
			got := ask(t, i, verb, "/health/live")
			if got.status != http.StatusOK {
				t.Errorf("%s /health/live = %d, want the route's own 200", verb, got.status)
			}
			if verb != http.MethodHead && got.body != empty {
				t.Errorf("%s /health/live body = %q, want the route's own document", verb, got.body)
			}

			// And the same verb on a path that is not a route is the one 404,
			// not a 405.
			miss := ask(t, i, verb, "/nosuchpath")
			if miss.status != http.StatusNotFound {
				t.Errorf("%s /nosuchpath = %d, want 404", verb, miss.status)
			}
		})
	}
}

// TestNoResponseCarriesAnAllowHeader is the other half of the sentence above.
//
// "There is no 405" and "there is no Allow" are two claims and the statuses
// alone assert the first. Go's own ServeMux sets Allow when a pattern matches a
// path and not a method, so a router rewritten to use one would start sending
// it while every status above stayed 200.
func TestNoResponseCarriesAnAllowHeader(t *testing.T) {
	i := New()
	for _, p := range []string{"/", "/health", "/health/live", "/nosuchpath"} {
		for _, verb := range []string{http.MethodGet, http.MethodPut, http.MethodOptions} {
			w := httptest.NewRecorder()
			i.Handler().ServeHTTP(w, httptest.NewRequest(verb, p, nil))
			if v := w.Header().Get("Allow"); v != "" {
				t.Errorf("%s %s sent Allow: %q; nothing on this port does", verb, p, v)
			}
		}
	}
}

// TestDrainingTakesReadinessDownAndLeavesLivenessUp is the one computed check,
// tested on the asymmetry that is the reason the check exists.
//
// Measured through an actual `docker kill -s TERM` on a live container: /health
// and /health/ready answered 503 with the graceful-shutdown check DOWN, while
// /health/live and /health/started stayed 200 throughout and the index page did
// not move. An orchestrator relies on exactly that split - readiness fails so
// traffic stops arriving, liveness holds so the process is not killed mid-drain.
func TestDrainingTakesReadinessDownAndLeavesLivenessUp(t *testing.T) {
	i := New()

	if i.Draining() {
		t.Fatal("a new interface reports itself draining")
	}
	for _, p := range []string{"/health", "/health/ready"} {
		if got := ask(t, i, http.MethodGet, p); got.status != http.StatusOK {
			t.Fatalf("%s before the drain = %d, want 200", p, got.status)
		}
	}

	i.BeginDraining()

	if !i.Draining() {
		t.Error("BeginDraining did not take")
	}
	for _, p := range []string{"/health", "/health/ready"} {
		got := ask(t, i, http.MethodGet, p)
		if got.status != http.StatusServiceUnavailable {
			t.Errorf("%s during the drain = %d, want 503", p, got.status)
		}
		if !strings.Contains(got.body, "\"status\": \"DOWN\"") {
			t.Errorf("%s during the drain did not report DOWN: %q", p, got.body)
		}
		if !strings.Contains(got.body, "\"name\": \"Graceful Shutdown\",\n            \"status\": \"DOWN\"") {
			t.Errorf("%s during the drain did not take the graceful-shutdown check down: %q", p, got.body)
		}
		if !strings.Contains(got.body, "\"name\": \"Keycloak Initialized\",\n            \"status\": \"UP\"") {
			t.Errorf("%s during the drain took the other check down too: %q", p, got.body)
		}
	}
	for _, p := range []string{"/health/live", "/health/started"} {
		got := ask(t, i, http.MethodGet, p)
		if got.status != http.StatusOK {
			t.Errorf("%s during the drain = %d; liveness does not flip, measured", p, got.status)
		}
		if got.body != empty {
			t.Errorf("%s during the drain = %q, want the empty document unchanged", p, got.body)
		}
	}
	if got := ask(t, i, http.MethodGet, "/"); got.status != http.StatusOK ||
		!strings.Contains(got.body, index) {
		t.Errorf("the index page moved during the drain: %d %q", got.status, got.body)
	}

	// Idempotent: a second signal during a drain must change nothing.
	i.BeginDraining()
	if got := ask(t, i, http.MethodGet, "/health"); got.status != http.StatusServiceUnavailable {
		t.Errorf("a second BeginDraining moved the answer to %d", got.status)
	}
}

// TestTheHealthDocumentIsNotAConstant is the claim that one of the two checks
// is computed, asked directly.
//
// It is separate from the test above, which walks the asymmetry across five
// paths and would be satisfied by a router that served two hard-coded documents
// keyed on a flag. This asks the narrower question the brief on this cut asks:
// does anything in the served bytes depend on state the process actually holds?
func TestTheHealthDocumentIsNotAConstant(t *testing.T) {
	up := ask(t, New(), http.MethodGet, "/health")

	drained := New()
	drained.BeginDraining()
	down := ask(t, drained, http.MethodGet, "/health")

	if up.body == down.body {
		t.Fatal("the aggregate document is the same bytes in both states, so nothing " +
			"in it is computed and every check it publishes is a constant")
	}
	if up.status == down.status {
		t.Fatalf("the aggregate answered %d in both states; the 200/503 split is "+
			"measured and is the half a probe reads", up.status)
	}
}

// TestGloakPublishesNoDatabaseCheck is a refusal rather than an assertion, and
// it is the one this cut is most likely to be "fixed" against.
//
// Gloak has a store and could ping it, so a reader will reasonably ask why the
// third check is missing. The answer is measured: the datasource check is a
// function of `--metrics-enabled`, not of having a database. A container with
// `--health-enabled` alone answers 225 bytes and two checks; the same image with
// both answers 345 and three. Gloak has no metrics option, so publishing the
// check would produce a pair of responses - a 120-byte index listing only
// /health, beside a /health carrying the metrics-on check list - that no
// Keycloak can produce.
func TestGloakPublishesNoDatabaseCheck(t *testing.T) {
	body := ask(t, New(), http.MethodGet, "/health").body
	if strings.Contains(body, "database") {
		t.Errorf("/health publishes a database check:\n%q\n"+
			"That check appears only under --metrics-enabled, which Gloak does not have. "+
			"Adding it means adding the option and the endpoint behind it.", body)
	}
	// And the two it does publish are both there, so the refusal above is not
	// satisfied by an empty document.
	for _, name := range []string{gracefulShutdown, keycloakInitialized} {
		if !strings.Contains(body, name) {
			t.Errorf("/health does not publish %q, so the refusal above checks nothing", name)
		}
	}
}
