package conformance

import "net/http"

// managementDoc is where the management interface is documented. Keycloak's
// health and metrics guides are the only description of this surface; there is
// no operation list, which is why the chapter's denominator is a case count.
// See chapters.go for how the sweep behind that count was run.
var managementDoc = Doc{
	URL:       "https://www.keycloak.org/observability/health",
	Section:   "Enabling the health and metrics endpoints",
	Retrieved: "2026-09-15",
}

var managementMetricsDoc = Doc{
	URL:       "https://www.keycloak.org/observability/configuration-metrics",
	Section:   "Enabling metrics",
	Retrieved: "2026-09-15",
}

// managementSecurityHeaders is the five-header set AGENTS.md describes as
// present on everything Keycloak serves, with three exceptions. **The
// management port is a fourth, and it is the widest of them**: not one response
// on port 9000 carries one of these, measured at socket level on every route
// shape and on the fallback, because the bytes were read off a socket rather
// than through curl - a probe of an absence otherwise measures the probe.
//
// Every case below declares them absent. That declaration is not decoration:
// TestAssertAbsentHeadersAgreeWithTheGolden compares it against the recorded
// bytes, which is the half of F177 that works even on a Recorded case, where
// diff's "these differ" verdict is satisfied by any one difference and
// therefore asserts nothing on its own.
var managementSecurityHeaders = []string{
	"Referrer-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-Robots-Tag",
}

// managementCases is the management interface's surface: ten route shapes, the
// fallback, and the three cross-cutting facts that separate this port from the
// one every other chapter measures.
//
// **Nothing here is Implemented and nothing can be**, which is a statement
// about the verifier rather than about the catalogue. The verifier builds one
// handler and serves every case's request to it, so a management case is served
// to Gloak's main mux - a different server from the one the golden was recorded
// against. Case.ManagementPort refuses Implemented for that reason, and
// TestManagementCasesAreNotImplemented is where the refusal lives.
//
// Five of these goldens hold the same 45 bytes and three more hold the same 345
// as management/health/check. That is deliberate and it is not padding: a
// behaviour is a request and its answer, not an answer. /health/well being a
// route at all, and /health/group/{name} answering UP for a group that was
// never defined, are separately falsifiable claims about Keycloak that happen
// to share a response body, and the three cross-cutting cases each send a
// request no other case sends.
var managementCases = []Case{
	{
		// The index page, and it is the one response in this repository that
		// serves a body with **no Content-Type header at all**. Read at socket
		// level: the response is `HTTP/1.1 200 OK`, `content-length: 180`, and
		// nothing else.
		//
		// Its bytes are a function of the recorder's startup options, which no
		// other golden in this tree is: the page lists exactly the endpoints
		// that are switched on. Measured at 180 bytes with both options, 120
		// with `--health-enabled` alone and 123 with `--metrics-enabled` alone.
		// startKeycloak sets both and this golden is the both-enabled one. See
		// F245.
		ID:                  "management/index/root",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak serves no management interface, so it has no index page to list one",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/"},
		AssertHeaders:       []string{"Content-Length"},
		AssertAbsentHeaders: append([]string{"Content-Type"}, managementSecurityHeaders...),
	},
	{
		// The aggregate health document. Its `checks` array has **no
		// reproducible order across container starts**: two containers from one
		// image, both options set, answered with `Keycloak database connections
		// async health check` and `Keycloak Initialized` the other way round,
		// with `Graceful Shutdown` first in both. That is a disagreement
		// between two recordings, which is evidence of instability where two
		// recordings agreeing would have been evidence of nothing - AGENTS.md's
		// rule read in the direction that is actually valid.
		//
		// The three entries are themselves option-dependent: with
		// `--health-enabled` alone the document holds two, and enabling metrics
		// is what adds the database check. See F245.
		ID:                  "management/health/check",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no health checks to report",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
		Unordered:           []string{"checks"},
	},
	{
		// Liveness, and it is **not** the aggregate: its `checks` array is
		// empty, where /health's holds three. Byte-identical across two
		// containers, so nothing here needs a mask.
		ID:                  "management/health/live",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no liveness probe",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/live"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// Readiness, and it **is** the aggregate: byte-identical to /health,
		// including the unstable check order, so it carries the same mask. The
		// pair matters because liveness and readiness are the two paths an
		// orchestrator polls and they answer different documents - a server
		// answering the aggregate to /health/live would look healthy to a
		// reader and be wrong.
		ID:                  "management/health/ready",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no readiness probe",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/ready"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
		Unordered:           []string{"checks"},
	},
	{
		// Startup, and it answers liveness's empty document rather than
		// readiness's. So the four /health paths are two documents, and which
		// path gets which is not guessable from the names.
		ID:                  "management/health/started",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no startup probe",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/started"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// SmallRye's wellness endpoint, which is not a MicroProfile Health
		// path and is not in Keycloak's documentation. It is a route: the
		// discriminator says so, and the neighbouring spellings say it is an
		// exact one - `/health/wel` and `/health/wellness` are both the 404.
		ID:                  "management/health/well",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no wellness endpoint",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/well"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// The health-group endpoint with no group named.
		ID:                  "management/health/group",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no health groups",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/group"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// **A health group that was never defined answers 200 `UP`**, not 404.
		// That is the trap on this surface: a deployment polling
		// `/health/group/<typo>` is told the server is healthy by a route that
		// ran no checks at all. It is a route shape of its own rather than a
		// repeat of the case above, because the answer to a name that resolves
		// to nothing is the behaviour, and its sibling one segment up under
		// /health - `/health/x` - is the 404.
		ID:                  "management/health/group-unknown",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and no health groups to miss",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/health/group/nosuchgroup"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// **/health ignores `Accept` and /metrics negotiates on it.** Two
		// endpoints on one port, and the request header that selects a
		// representation on one is not read by the other: `text/plain`,
		// `text/html` and `application/xml` all get the JSON document here,
		// where `text/plain` on /metrics gets a different media type and
		// `application/openmetrics-text` gets a 406.
		//
		// Its golden holds the same bytes as management/health/check and it is
		// a separate behaviour: no other case in this chapter sends an `Accept`
		// to /health, so without it the claim that the header is ignored is
		// made by nothing.
		ID:             "management/health/accept-ignored",
		Doc:            managementDoc,
		Status:         Recorded,
		Reason:         "Gloak has no management interface, so it negotiates nothing on one",
		Fixture:        "bootstrap",
		ManagementPort: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/health",
			Headers: map[string]string{"Accept": "text/plain"},
		},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
		Unordered:           []string{"checks"},
	},
	{
		// **The management port has no wrong-method family.** A `PUT` on
		// /health answers /health's own 200 with /health's own document, where
		// the main port's answer to a wrong verb is a 404 or a 405 depending on
		// the route - the rule AGENTS.md records as measured too broad seven
		// times. This is the eighth data point and the first outside the
		// 404/405/406 family altogether, and it is counted once for the whole
		// port: 70 of the sweep's 77 cells say the same thing, and counting
		// them per path would report one behaviour seventy times.
		ID:                  "management/health/wrong-verb",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface, so it has no verb rule on one",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodPut, Path: "/health"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
		Unordered:           []string{"checks"},
	},
	{
		// **The path is not normalised on this port.** `//health` answers
		// /health's 200 here, and the identical request to 8080 on the same
		// container answers `400 {"error":"missingNormalization",...}`. One
		// container, one path, two ports, opposite answers - which is what says
		// AGENTS.md's "ahead of the route table, across the whole server" is a
		// sentence about one route table. `/health/../health` and
		// `/%2e%2e/health` answer the same 200, measured with
		// `curl --path-as-is` because curl normalises a path before sending it.
		ID:                  "management/health/unnormalised-path",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface, so it normalises nothing on one",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "//health"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: managementSecurityHeaders,
		Unordered:           []string{"checks"},
	},
	{
		// **Asking for the media type the endpoint serves by default is a
		// 406.** `/metrics` with no `Accept` answers
		// `application/openmetrics-text; version=1.0.0; charset=utf-8`; asking
		// for `application/openmetrics-text` is refused. The parameters are
		// what decide it and **both** are needed - `;version=1.0.0` alone and
		// `;charset=utf-8` alone are each a 406, and `;version=1.0.0;charset=utf-8`
		// is a 200 - so the accept value has to be the produced media type
		// spelled out in full. The space after the semicolon does not matter.
		//
		// This is the one recordable response the metrics endpoint has: the
		// body is empty, so F113 does not reach it, and it was identical across
		// three requests to one container and to a request on a second. It is
		// what keeps this half of the chapter from being a Reason string
		// nobody can check.
		//
		// **The status line carries a reason phrase that is not the standard
		// one** - `406 Micrometer prometheus endpoint does not support
		// application/openmetrics-text` - and no golden can hold it: FormatGolden
		// writes http.StatusText(406). See F246.
		ID:             "management/metrics/openmetrics-refused",
		Doc:            managementMetricsDoc,
		Status:         Recorded,
		Reason:         "Gloak has no management interface and no metrics endpoint to refuse a media type",
		Fixture:        "bootstrap",
		ManagementPort: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/metrics",
			Headers: map[string]string{"Accept": "application/openmetrics-text"},
		},
		AssertAbsentHeaders: append([]string{"Content-Type"}, managementSecurityHeaders...),
	},
	{
		// **/metrics is a prefix route and /health is not.** Any suffix under
		// /metrics reaches the metrics endpoint - `/metrics/nosuch` and
		// `/metrics/nosuch/deeper` both answer the dump - where any suffix under
		// /health that is not one of the six named above is the 404. Two
		// sibling families on one port, opposite answers.
		//
		// It is recorded through the 406 rather than through the dump, which is
		// the only way to record it at all: the dump is barred by F113 and the
		// 406 is the same endpoint answering from the same place. What the
		// golden pins is that the request reached Micrometer, which is exactly
		// the claim - a path that had not reached it would be the 53-byte 404.
		ID:             "management/metrics/prefix-match",
		Doc:            managementMetricsDoc,
		Status:         Recorded,
		Reason:         "Gloak has no management interface, so nothing of its routes under one",
		Fixture:        "bootstrap",
		ManagementPort: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/metrics/nosuchsuffix",
			Headers: map[string]string{"Accept": "application/openmetrics-text"},
		},
		AssertAbsentHeaders: append([]string{"Content-Type"}, managementSecurityHeaders...),
	},
	{
		// The fallback, and it is a **third** producer of a 404 body in this
		// repository - neither `Unable to find matching target resource method`
		// nor `HTTP 404 Not Found`, but 53 bytes of HTML from Quarkus's own
		// management router, which never reaches Keycloak's application at all.
		// It is what the discriminator in chapters.go rests on, and it answers
		// all seven verbs identically.
		ID:                  "management/fallback/unknown-path",
		Doc:                 managementDoc,
		Status:              Recorded,
		Reason:              "Gloak has no management interface and so no router to refuse a path on one",
		Fixture:             "bootstrap",
		ManagementPort:      true,
		Request:             Request{Method: http.MethodGet, Path: "/nosuchpath"},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: managementSecurityHeaders,
	},
	{
		// The metrics dump, and **no golden can hold it**. F113's rule is that
		// a body carrying a per-request value cannot be Recorded, and this body
		// is almost nothing else: two requests three seconds apart to one
		// container differed on 116 lines, and the `agroal_acquire_count_total`
		// counter rises with every request the container has ever served,
		// including the recorder's own.
		//
		// It does not survive a container either, which is the stronger
		// refusal: two containers from one image answered with 1326 and 1224
		// lines and 2156 lines differing, and every sample carries a
		// `node="<container id>-<port>"` label that is minted with the
		// container. There is no stable prefix to record - the `# TYPE` and
		// `# HELP` lines are interleaved with the samples rather than grouped -
		// so no mask in this harness reaches it, and none was built to try.
		ID:             "management/metrics/dump",
		Doc:            managementMetricsDoc,
		Status:         Pending,
		Reason:         "the body is a counter dump that moves with every request and every container - F113",
		Fixture:        "", // no golden can hold this body; see the comment above
		ManagementPort: true,
		Request:        Request{Method: http.MethodGet, Path: "/metrics"},
	},
	{
		// The same dump in Prometheus 0.0.4 text rather than OpenMetrics 1.0.0,
		// selected by `Accept: text/plain`, whose answer is
		// `text/plain; version=0.0.4; charset=utf-8`. A bare `text/plain` is
		// enough here where a bare `application/openmetrics-text` is a 406,
		// which is the asymmetry the case above records from the other side.
		//
		// Pending for F113 and not for the negotiation: the media type is a
		// contract and the body under it is the same moving counter dump.
		ID:     "management/metrics/prometheus-text",
		Doc:    managementMetricsDoc,
		Status: Pending,
		Reason: "text/plain selects Prometheus 0.0.4 and the body is still the moving counter dump - F113",
		Fixture: "", // no golden can hold this body either; see
		// management/metrics/dump
		ManagementPort: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/metrics",
			Headers: map[string]string{"Accept": "text/plain"},
		},
	},
}
