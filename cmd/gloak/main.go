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
	"net/http"
	"os"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
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

	k, err := keys.Generate()
	if err != nil {
		return fmt.Errorf("gloak: generate realm keys: %w", err)
	}

	server := newHTTPServer(cfg.addr, logRequests(oidc.NewRouter(s, k, cfg.issuer)))

	slog.Info("gloak: listening", "addr", cfg.addr, "issuer", cfg.issuer, "db", cfg.db)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("gloak: serve: %w", err)
	}
	return nil
}

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
