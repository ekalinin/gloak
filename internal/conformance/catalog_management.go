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
// **Twelve of these are Implemented and the other four are the metrics family,
// and the split is one fact rather than sixteen.** Gloak serves this port as a
// Keycloak started with `--health-enabled` and no `--metrics-enabled` serves
// it, because that is the only option set it can serve honestly: it keeps no
// counters, so it has no metrics endpoint, and a metrics-disabled Keycloak's
// answers are the ones it reproduces.
//
// Two of this port's responses are a function of the option set rather than of
// the version - the index page lists exactly the endpoints that are on, and
// /health's check list gains the database check only when metrics is on - and
// until 2026-09-16 the recorder set both options on every container, so six
// goldens held the other set's bytes and six cases stayed Recorded describing
// behaviours Gloak serves correctly. **Case.Configuration is what closed that**:
// those six declare StartDevHealth and are recorded against a container started
// the way Gloak is configured, so the bytes they hold are the bytes Gloak sends
// and the cases are Implemented.
//
// **Nothing in the metrics family can be Implemented, and it is recorded under
// the other configuration for a reason that is not the recorder's
// convenience.** Micrometer's content negotiation exists only under
// `--metrics-enabled`: with health alone, `/metrics` is the ordinary 53-byte
// 404, measured. Re-recording those two cases under StartDevHealth would
// replace their 406 with that 404, and Gloak - which answers the 404 - would
// then match, so two cases would read as served while the behaviour they name
// is not served at all. managementDefects refuses both halves: an Implemented
// metrics case, and a metrics case declaring a configuration with no metrics
// endpoint in it.
//
// The Implemented half of the chapter rests on a change made the week before:
// until 2026-09-16 no management case could be Implemented at all, because the
// verifier had one handler and served them to Gloak's main mux. It now builds
// two - see newManagementFixture - and
// TestTheVerifierAnswersAManagementCaseFromTheManagementServer reproduces, on
// Gloak's own pair, the `GET //health` disagreement that made the old refusal
// true on Keycloak's.
//
// Five of these goldens hold the same 45 bytes and **four** more hold the same
// **313** as management/health/check. (Both numbers were wrong here until
// 2026-09-16: it said three and 345. 345 is what the socket sent; 313 is what
// the golden holds, because the Unordered mask re-renders the array - see
// TestTheAggregateGoldenIsTheWireBytesAfterTheMask, which is that trap pinned.)
// That is deliberate and it is not padding: a
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
		// **Its bytes are a function of the container's startup options**, which
		// no other golden in this tree was until the theme chapter's
		// Cache-Control was measured: the page lists exactly the endpoints that
		// are switched on. Measured at 180 bytes with both options, 120 with
		// `--health-enabled` alone and 123 with `--metrics-enabled` alone.
		//
		// It declares StartDevHealth, so the golden holds the 120-byte page -
		// read off a socket on 2026-09-16 and byte for byte what Gloak serves,
		// because Gloak has no metrics endpoint to list. This case was Recorded
		// with a Reason naming F245 until the recorder could start a second
		// configuration; the behaviour never moved.
		ID:             "management/index/root",
		Doc:            managementDoc,
		Status:         Implemented,
		Configuration:  StartDevHealth,
		Fixture:        "bootstrap",
		ManagementPort: true,
		Request:        Request{Method: http.MethodGet, Path: "/"},
		// No AssertHeaders. Content-Length is masked package-wide, so asserting
		// it would assert that a response has a length - the inert kind of
		// declaration AGENTS.md says is worse than none. What this case asserts
		// is the status, the body, and the six headers it declares absent.
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
		// **The entries are themselves option-dependent**: with
		// `--health-enabled` alone the document holds two and the socket sends
		// 225 bytes, and enabling metrics adds
		// `Keycloak database connections async health check` and takes it to
		// 345. This case declares StartDevHealth, so the golden is the
		// two-check document - which is what Gloak serves, because it has no
		// metrics option to hang a database check on and publishing one anyway
		// would be tidying up a measured quirk: the coupling between a metrics
		// flag and a *health* check is Quarkus's, it looks like a bug, and
		// reproducing it is the whole job.
		//
		// The committed bytes are **202**, not the 225 the socket sent: the
		// Unordered mask parses the array and re-renders it, so the golden is
		// the normalised form of the response rather than the response. Both
		// sides go through normalisePasses, so nothing ever compares a golden to
		// a socket - TestTheAggregateGoldenIsTheWireBytesAfterTheMask is that
		// relationship pinned, and it holds the wire bytes of **both**
		// configurations so the option coupling stays measured after the
		// three-check document left the golden tree.
		ID:                  "management/health/check",
		Doc:                 managementDoc,
		Status:              Implemented,
		Configuration:       StartDevHealth,
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
		Status:              Implemented,
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
		//
		// It answers the same two-check document /health does under this
		// configuration - including the 503 during a drain, which is the pair's
		// whole point and is measured on both servers.
		ID:                  "management/health/ready",
		Doc:                 managementDoc,
		Status:              Implemented,
		Configuration:       StartDevHealth,
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
		Status:              Implemented,
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
		Status:              Implemented,
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
		Status:              Implemented,
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
		Status:              Implemented,
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
		//
		// **This is one of F256's three behaviours, and it is guarded by a
		// golden now.** It was Recorded while the recorder ran one
		// configuration, and a Recorded case is required *not* to match - so a
		// Gloak that read `Accept` here would have failed to match exactly as
		// thoroughly as one that ignores it.
		ID:             "management/health/accept-ignored",
		Doc:            managementDoc,
		Status:         Implemented,
		Configuration:  StartDevHealth,
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
		//
		// **F256's second behaviour, guarded by a golden now.** Gloak's
		// management port answers every verb with the route's own 200 and sends
		// no Allow, asserted over eight verbs in internal/management and, since
		// this case was recorded under the configuration Gloak serves, by this
		// golden too.
		ID:                  "management/health/wrong-verb",
		Doc:                 managementDoc,
		Status:              Implemented,
		Configuration:       StartDevHealth,
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
		//
		// **F256's third behaviour and the one that made the entry.** A
		// mutation making routePath compute the cleaned path and throw it away
		// survived the whole conformance suite while this case was Recorded,
		// and was killed only by internal/management's own route table. It is
		// killed here too now.
		ID:                  "management/health/unnormalised-path",
		Doc:                 managementDoc,
		Status:              Implemented,
		Configuration:       StartDevHealth,
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
		//
		// **It keeps the default configuration, and that is a decision rather
		// than the absence of one.** Every other case in this chapter is
		// recorded under StartDevHealth, which is the option set Gloak serves;
		// this behaviour does not exist there. `/metrics` with health alone is
		// the ordinary 53-byte 404, measured off a socket on 2026-09-16, so
		// re-recording this case under that configuration would replace the 406
		// with the fallback - and Gloak, which answers the fallback, would then
		// match and the case would read as served while Micrometer's
		// negotiation is served by nothing. managementDefects refuses it.
		ID:     "management/metrics/openmetrics-refused",
		Doc:    managementMetricsDoc,
		Status: Recorded,
		// **Gloak answers this path with the 53-byte 404, which is what a
		// metrics-disabled Keycloak answers** - measured on a container started
		// with --health-enabled alone. So this is not "Gloak serves nothing
		// here"; it is Gloak serving the other option set's answer. Building
		// the 406 would mean building an endpoint whose success branch could
		// only be a fabricated dump. managementDefects refuses Implemented for
		// this whole chapter and says why.
		Reason:         "Gloak keeps no counters, so /metrics is the 53-byte 404 a metrics-disabled Keycloak answers rather than Micrometer's 406",
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
		// the claim - a path that had not reached it would be the 53-byte 404,
		// and that is also why this case keeps the default configuration. See
		// its sibling above.
		ID:     "management/metrics/prefix-match",
		Doc:    managementMetricsDoc,
		Status: Recorded,
		// The same as its sibling, and the prefix claim goes with it: Gloak has
		// no /metrics, so it has no prefix under one and every suffix is the
		// 404. That is the metrics-disabled answer rather than a gap.
		Reason:         "Gloak keeps no counters, so nothing routes under /metrics and every suffix is the 53-byte 404",
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
		Status:              Implemented,
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
		ID:      "management/metrics/prometheus-text",
		Doc:     managementMetricsDoc,
		Status:  Pending,
		Reason:  "text/plain selects Prometheus 0.0.4 and the body is still the moving counter dump - F113",
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
