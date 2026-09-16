// Package management serves Keycloak's management interface: the second
// listener, on port 9000, that `--health-enabled` or `--metrics-enabled` brings
// up and that a default container does not have at all.
//
// # It is a second server, not a second route family
//
// Every rule internal/oidc's router applies is a rule of **one** JAX-RS
// application, and this is the other server in the same process. Measured on
// one container on 2026-09-15 and again on 2026-09-16, one path, two ports:
//
//	GET //health  on 8080  400 {"error":"missingNormalization",...}
//	GET //health  on 9000  200 with the health document
//
// So this package deliberately does **not** reuse WithKeycloakFallbacks, and
// the three things it does differently are each measured rather than chosen:
//
//   - **The path is cleaned, never refused.** `//health`, `///health`,
//     `/./health`, `/foo/../health` and `/%2e%2e/health` all answer /health's
//     200, and `/health/..`, `/..` and `//` all answer the index. There is no
//     `missingNormalization` on this port.
//   - **There is no wrong-method family.** Every verb answers the route's own
//     200 - GET, POST, PUT, DELETE, PATCH, OPTIONS and TRACE were each measured
//     on /health/live - and every verb on a path that is not a route answers
//     one 404. There is no 405 anywhere on this port and no `Allow` header.
//   - **None of the five security headers is sent, on anything**, which is the
//     widest exception to that rule in this repository: a listener rather than
//     a route, a family or a media type. httpx's three writers are where that
//     is enforced and asserted.
//
// # What Gloak serves, and the option set it is
//
// **This is Keycloak's management interface as a container started with
// `--health-enabled` and no `--metrics-enabled` serves it**, and every byte was
// measured on such a container on 2026-09-16. That is the whole of the choice:
// Gloak keeps no counters, so it has no `--metrics-enabled`, and a metrics-
// disabled Keycloak answers `/metrics` with the ordinary 53-byte 404 - measured -
// which is exactly what this router answers. The index page lists exactly the
// endpoints that are on, so Gloak's is the 120-byte page rather than the
// 180-byte one the conformance goldens hold.
//
// Six of the fourteen management goldens are recordings whose bytes are a
// function of the option set - the index page and the five aggregate documents.
// **Those six are recorded against a container started this way**, since
// conformance.Case.Configuration existed, so they hold the bytes this package
// sends and their cases are Implemented. Two more hold Micrometer's 406, which
// needs the metrics endpoint to exist, and stay Recorded under a configuration
// that has one - re-recording them here would replace the 406 with this
// package's 404 and make two cases read as served. See
// docs/superpowers/handover/recorder-configurations.md.
package management

import (
	"net/http"
	"path"
	"strings"
	"sync/atomic"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The two checks the aggregate document publishes, in the order Keycloak sends
// them. A container started with `--metrics-enabled` as well publishes a third,
// `Keycloak database connections async health check`, between them - measured
// at 225 bytes and two checks with health alone and 345 and three with both -
// and Gloak publishes no third because it has no metrics option to hang one on.
//
// **Publishing it anyway is the tidy-up this project exists not to make.** The
// coupling between a metrics flag and a *health* check is an artefact of how
// Quarkus registers the datasource binding, it looks like a bug, and it is
// measured. A Gloak whose index page lists only /health while its /health
// carries the metrics-on check list would be a pair of responses no Keycloak
// can produce.
const (
	// gracefulShutdown is **computed**: it is UP until the process begins
	// draining and DOWN from then until it exits. Both documents were measured
	// on a live container - the 200 in the ordinary state and the 503 caught by
	// polling through `docker kill -s TERM`, 799511 polls and three distinct
	// answers - so this check's failure branch is a recording rather than an
	// inference.
	gracefulShutdown = "Graceful Shutdown"

	// keycloakInitialized is a **constant**, and the constant is measured
	// rather than assumed, which is the whole of its defence.
	//
	// A fresh container was polled on /health from the instant `docker run`
	// returned until well after startup: 73395 polls, and exactly two distinct
	// answers - no connection at all, and the document with this check already
	// UP. **DOWN is not an observable state of this check on this port**,
	// because the management listener does not accept a connection until it
	// holds. Gloak reproduces that structurally: cmd/gloak opens the store and
	// bootstraps the master realm before either listener starts, so there is no
	// instant at which this port answers and the realm is missing.
	//
	// A flag set after bootstrap would be a variable with one reachable value
	// dressed as a predicate. This is the honest shape: a constant, with the
	// measurement that says the constant is what a client can observe.
	keycloakInitialized = "Keycloak Initialized"
)

// Interface is the management interface: its router, and the one piece of
// state the router reads.
//
// The state lives here rather than in cmd/gloak because cmd/gloak must hold no
// logic worth testing on its own - the Boundaries table in AGENTS.md - and
// "which check is DOWN while the process drains" is exactly that. cmd/gloak
// wires a signal to BeginDraining and nothing else.
type Interface struct {
	// draining is read on every aggregate request and written once, from a
	// signal handler, so it is atomic rather than guarded: the writer is a
	// different goroutine from every reader.
	draining atomic.Bool
}

// New returns an interface that is not draining.
func New() *Interface { return &Interface{} }

// BeginDraining flips the graceful-shutdown check to DOWN, which takes /health
// and /health/ready to 503 and leaves /health/live and /health/started at 200.
//
// **That asymmetry is the measurement and it is the point of the endpoint.**
// Polled through a real drain, /health and /health/ready answered 503 while
// /health/live and /health/started stayed 200 throughout, which is the contract
// an orchestrator relies on: readiness fails so traffic stops arriving, and
// liveness holds so the process is not killed mid-drain.
//
// It is idempotent, because a second signal during a drain must not restart
// anything.
func (i *Interface) BeginDraining() { i.draining.Store(true) }

// Draining reports whether BeginDraining has been called.
func (i *Interface) Draining() bool { return i.draining.Load() }

// aggregate is the document /health and /health/ready answer.
func (i *Interface) aggregate() []httpx.HealthCheck {
	return []httpx.HealthCheck{
		{Name: gracefulShutdown, Up: !i.Draining()},
		{Name: keycloakInitialized, Up: true},
	}
}

// The eight routes, and the fact that there are eight rather than four is the
// finding this surface is most likely to be got wrong on.
//
// **Which of the two documents a path answers is not guessable from its name.**
// /health and /health/ready answer the aggregate; /health/live and
// /health/started answer an empty check list, and so do SmallRye's /health/well
// - which is not a MicroProfile path and is in none of Keycloak's documentation
// - and the health-group pair. A server answering the aggregate to /health/live
// would look correct to a reader and be wrong.
//
// **A health group that was never defined answers 200 UP.** /health/group/x is
// a route at any depth - /health/group/a/b and /health/group/a%20b were both
// measured 200 - while /health/x one segment up is the 404. So a deployment
// polling /health/group/<typo> is told the server is healthy by a route that
// ran no checks at all. It looks like a bug; it is measured.
const (
	indexPath   = "/"
	healthPath  = "/health"
	readyPath   = "/health/ready"
	livePath    = "/health/live"
	startedPath = "/health/started"
	wellPath    = "/health/well"
	groupPath   = "/health/group"
	groupPrefix = "/health/group/"
)

// Handler returns the management interface's router.
//
// It is a switch rather than an http.ServeMux, and that is forced rather than
// preferred: Go's ServeMux cleans a path and then **redirects** to the cleaned
// form with a 301, where this port answers the route's own 200 directly.
// `GET //health` is 200 with the health document, not a redirect, measured.
func (i *Interface) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := routePath(r.URL.Path); {
		case p == indexPath:
			httpx.WriteManagementIndex(w)
		case p == healthPath, p == readyPath:
			httpx.WriteHealthDocument(w, i.aggregate())
		case p == livePath, p == startedPath, p == wellPath, p == groupPath,
			strings.HasPrefix(p, groupPrefix):
			// **These are not a stubbed-out aggregate.** The document is empty
			// because no check is registered in these groups, which is exactly
			// why Keycloak's is: liveness, startup, wellness and the health
			// groups each have their own registry and Keycloak puts nothing in
			// any of them. Gloak putting nothing in them is the same statement,
			// not a placeholder for one.
			//
			// The named group and the prefix are one arm rather than two
			// identical ones. `/health/group` and `/health/group/{anything}`
			// answer the same 45 bytes, and path.Clean never leaves a trailing
			// slash on anything but the root, so the equality and the prefix are
			// disjoint: nothing can fall through `p == groupPath` into
			// HasPrefix.
			httpx.WriteHealthDocument(w, nil)
		default:
			httpx.WriteManagementNotFound(w)
		}
	})
}

// routePath is the path this router matches on: the request's decoded path,
// cleaned.
//
// **Cleaning here is routing and never a refusal**, which is the opposite of
// the main port one socket away, where a doubled slash or a `..` segment is
// `400 missingNormalization` before the route table is consulted. Measured on
// one container, on this port:
//
//	//health  ///health  /./health  /foo/../health  /%2e%2e/health   -> /health
//	/health/  /health/./  /health/ready/  /health/group/             -> the route
//	/health/..  /..  //                                              -> /
//
// path.Clean gives every one of those, including the trailing-slash cases: it
// removes a trailing slash from any path but the root, and this port tolerates
// exactly one - and any number, since `///health` is /health too.
//
// It reads r.URL.Path, which net/http has already percent-decoded. That is
// right for `%2e%2e`, measured answering /health's 200, and it is the one place
// this router is measurably wrong: `/health%2Flive` is a 404 on Keycloak, where
// r.URL.Path decodes the escape into a separator and this answers the liveness
// document. No case covers it and nothing in the catalogue sends it. See F259.
func routePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		// `OPTIONS *`, which net/url special-cases to Path "*", and the
		// authority-form target a CONNECT carries, which leaves Path empty.
		// Both 404. **An absolute-form target does not come here** - `GET
		// http://host:9000/health` gives Path "/health" and routes normally -
		// which this comment claimed until a review checked it.
		return ""
	}
	return path.Clean(p)
}
