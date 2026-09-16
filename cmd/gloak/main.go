// Command gloak runs the Gloak server: it serves the OpenID Connect
// discovery document and the JWKS built so far. Token issuance and the
// browser flow are separate, later plans.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ekalinin/gloak/internal/account"
	"github.com/ekalinin/gloak/internal/admin"
	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/management"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/postgres"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: gloak serve [flags]")
		os.Exit(1)
	}
	if err := serve(os.Args[2:]); err != nil {
		slog.Error("gloak: exiting", "error", err)
		os.Exit(1)
	}
}

// config holds the serve flags, each with a GLOAK_-prefixed environment
// fallback used as its default before flag parsing overrides it.
type config struct {
	db            string
	dsn           string
	addr          string
	issuer        string
	adminUser     string
	adminPassword string

	// healthEnabled brings the management interface up, and **off is the
	// measured default**: a `quay.io/keycloak/keycloak:26.7.1 start-dev` with
	// neither --health-enabled nor --metrics-enabled has no listener on 9000 at
	// all. Its startup line names one address and /proc/net/tcp6 inside the
	// container holds one routable listening socket.
	//
	// Keycloak spells it --health-enabled and KC_HEALTH_ENABLED; Gloak's
	// environment variables use the GLOAK_ prefix and never KC_, so this is
	// GLOAK_HEALTH_ENABLED.
	//
	// **There is deliberately no --metrics-enabled.** Keycloak's other option
	// brings the same port up carrying /metrics, and Gloak keeps no counters to
	// put on it. A flag that accepted the word and served a fabricated dump
	// would be worse than its absence: a Prometheus scraper pointed at it would
	// get a 200 holding none of the series it charts and would read as healthy
	// while charting nothing. Without the option, /metrics answers the ordinary
	// 53-byte 404, which is exactly what a metrics-disabled Keycloak answers -
	// measured on its own container.
	healthEnabled bool

	// managementAddr is the management interface's listener. Keycloak's
	// management port is 9000 and is not the HTTP port; the two are two
	// servers, measured disagreeing about the same request.
	managementAddr string
}

func parseConfig(args []string) (*config, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg := &config{}
	fs.StringVar(&cfg.db, "db", envOr("GLOAK_DB", "sqlite"),
		"store driver: sqlite or postgres (env GLOAK_DB)")
	fs.StringVar(&cfg.dsn, "dsn", envOr("GLOAK_DSN", "gloak.db"),
		"store data source name (env GLOAK_DSN)")
	fs.StringVar(&cfg.addr, "addr", envOr("GLOAK_ADDR", ":8080"),
		"address to listen on (env GLOAK_ADDR)")
	fs.StringVar(&cfg.issuer, "issuer", envOr("GLOAK_ISSUER", "http://localhost:8080"),
		"externally visible issuer base URL, no trailing slash (env GLOAK_ISSUER)")
	fs.StringVar(&cfg.adminUser, "admin-user", envOr("GLOAK_ADMIN_USER", "admin"),
		"master realm admin username (env GLOAK_ADMIN_USER)")
	fs.BoolVar(&cfg.healthEnabled, "health-enabled", envTrue("GLOAK_HEALTH_ENABLED"),
		"serve the management interface on -management-addr (env GLOAK_HEALTH_ENABLED)")
	fs.StringVar(&cfg.managementAddr, "management-addr", envOr("GLOAK_MANAGEMENT_ADDR", ":9000"),
		"address the management interface listens on (env GLOAK_MANAGEMENT_ADDR)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// The admin password is deliberately not a flag: argv is visible to
	// any other process on the machine (e.g. via ps). It is also
	// deliberately not defaulted: a silent admin/admin bootstrap is a
	// credential an operator may never learn they have.
	cfg.adminPassword = os.Getenv("GLOAK_ADMIN_PASSWORD")
	if cfg.adminPassword == "" {
		return nil, errors.New("gloak: GLOAK_ADMIN_PASSWORD must be set; " +
			"the master realm admin password has no default")
	}
	return cfg, nil
}

// envOr returns the environment variable named key, or def if it is unset.
func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envTrue reports whether the environment variable named key is set to a value
// Go's flag package would read as true. It is envOr's boolean half and the
// default is always false, because the one option it serves is off by default
// on Keycloak too.
//
// **A value it cannot parse is false rather than an error**, which is a
// deliberate asymmetry with the flag: `-health-enabled=yes` is a usage error
// that stops the server, and `GLOAK_HEALTH_ENABLED=yes` starts it without the
// management port. Making the environment fatal would mean a typo in a
// deployment's env block stops a server that would otherwise serve every
// request correctly, to protect an endpoint that is off by default anyway.
func envTrue(key string) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	return err == nil && v
}

func serve(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}

	ctx := context.Background()

	s, err := openStore(ctx, cfg.db, cfg.dsn)
	if err != nil {
		return fmt.Errorf("gloak: open store: %w", err)
	}
	defer func() { _ = s.Close() }()

	// Converges rather than short-circuiting, so this is safe on every
	// startup, including restarts against an already-bootstrapped store.
	if err := bootstrap.EnsureMaster(ctx, s, cfg.adminUser, cfg.adminPassword); err != nil {
		return fmt.Errorf("gloak: bootstrap master realm: %w", err)
	}

	// Keys are resolved per realm on first use and persisted, so a restart
	// republishes the same kid and a realm created later gets its own set.
	km := keys.NewManager(s)

	// One mux for both APIs, wrapped once. Two muxes chained would each answer
	// their own 404 for paths the other owns, and there are exactly two
	// measured fallback bodies.
	mux := http.NewServeMux()
	oidc.Register(mux, s, km, cfg.issuer)
	admin.Register(mux, s, km, cfg.issuer)
	account.Register(mux, s, km, cfg.issuer)

	server := newHTTPServer(cfg.addr, logRequests(oidc.WithKeycloakFallbacks(mux)))

	// The management interface is a **second server on a second socket**, not a
	// route family on this one, and that is measured rather than stylistic:
	// `GET //health` is `400 missingNormalization` on 8080 and `200` with the
	// health document on 9000 of one container, seconds apart. Registering its
	// routes on the mux above would give them the main server's normalisation
	// rule, its security headers and its two fallback bodies, none of which
	// this port has.
	//
	// It is built whether or not it is served, because it is what holds the
	// draining flag: a `gloak serve` with no management port still drains, it
	// just has nobody to tell.
	mgmt := management.New()
	var mgmtServer *http.Server

	// Both listeners report through one channel, so a management socket that
	// cannot be bound **stops the server** rather than logging and leaving an
	// operator who asked for a health endpoint without one. A readiness probe
	// aimed at a port nothing listens on is the failure mode this endpoint
	// exists to prevent, and producing it silently would be worse than not
	// offering the option. It is buffered for two so neither goroutine can be
	// left blocked on a send after this function has returned.
	serveErr := make(chan error, 2)

	if cfg.healthEnabled {
		// The socket is taken **here** rather than inside the goroutine, so a
		// port that cannot be bound is an error before the main server starts,
		// and so the line logged below is true when it is printed rather than
		// hopeful. ListenAndServe in a goroutine reports the same failure a
		// moment later and through the channel, by which time the log has
		// already said the interface is listening.
		ln, err := net.Listen("tcp", cfg.managementAddr)
		if err != nil {
			return fmt.Errorf("gloak: management interface: %w", err)
		}
		mgmtServer = newHTTPServer(cfg.managementAddr, mgmt.Handler())
		go func() {
			if err := mgmtServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErr <- fmt.Errorf("gloak: management interface: %w", err)
			}
		}()
		slog.Info("gloak: management interface listening", "addr", cfg.managementAddr)
	}

	// Both listeners start **after** the store is open and the master realm is
	// bootstrapped, which is what makes the `Keycloak Initialized` check a
	// defensible constant rather than a variable with one reachable value.
	// Keycloak's own port behaves the same way: 73395 polls of /health from the
	// instant a fresh container started gave two answers - no connection, and
	// the check already UP.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("gloak: listening", "addr", cfg.addr, "issuer", cfg.issuer, "db", cfg.db)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- fmt.Errorf("gloak: serve: %w", err)
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	// The drain, and the order of these three statements is the contract the
	// graceful-shutdown health check exists to publish.
	//
	// Readiness goes DOWN **first**, so an orchestrator stops routing new
	// requests here before the server starts refusing them. The main server
	// drains next, finishing the requests it already has. The management
	// interface is stopped **last**, so /health answers 503 for the whole of the
	// drain rather than the probe's connection being refused - which is what
	// Keycloak does, measured by polling a container through `docker kill -s
	// TERM`: /health and /health/ready answered 503 while /health/live stayed
	// 200, and the port kept answering until the process went.
	slog.Info("gloak: draining")
	mgmt.BeginDraining()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	err = server.Shutdown(shutdownCtx)
	if mgmtServer != nil {
		_ = mgmtServer.Shutdown(shutdownCtx)
	}
	if err != nil {
		return fmt.Errorf("gloak: drain: %w", err)
	}
	return nil
}

// drainTimeout bounds how long a shutdown waits for requests in flight.
//
// **It is not a measured Keycloak value.** Quarkus's own shutdown timeout is
// configurable and nothing in this project has measured Keycloak's default, so
// this is Gloak's own bound rather than a claim about the reference server. It
// is generous against the requests Gloak serves, every one of which is a small
// JSON document, and it is finite so that a stuck client cannot hold a
// terminating process open indefinitely.
const drainTimeout = 30 * time.Second

// openStore opens the store selected by driver. sqlite and postgres both
// migrate on return, so the store is ready to use as soon as this succeeds.
func openStore(ctx context.Context, driver, dsn string) (store.Store, error) {
	switch driver {
	case "sqlite":
		return sqlite.Open(ctx, dsn)
	case "postgres":
		return postgres.Open(ctx, dsn)
	default:
		return nil, fmt.Errorf("gloak: unknown store driver %q (want sqlite or postgres)", driver)
	}
}

// newHTTPServer builds the http.Server for addr and handler with timeouts
// set on every stage of a connection's lifecycle, so a stalled or malicious
// peer cannot hold a connection - and the goroutine serving it - open
// indefinitely:
//   - ReadHeaderTimeout bounds how long a client may take to send request
//     headers, the standard defence against slowloris-style attacks.
//   - ReadTimeout bounds the full request, headers and body together; every
//     request Gloak serves today is a small, header-only GET, so this is
//     generous rather than tight.
//   - WriteTimeout bounds how long writing the response may take; Gloak's
//     bodies are small JSON documents, so this only guards against a stuck
//     client that stops reading.
//   - IdleTimeout bounds how long a keep-alive connection may sit idle
//     between requests before it is closed.
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// logRequests logs every request's method, path, status and duration.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
		)
	})
}

// statusWriter captures the status code the wrapped handler writes, since
// http.ResponseWriter exposes no way to read it back afterwards.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
