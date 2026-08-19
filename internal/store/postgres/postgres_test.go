//go:build docker

package postgres_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/postgres"
	"github.com/ekalinin/gloak/internal/store/storetest"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver used by wait.ForSQL below
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestConformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) store.Store {
		t.Helper()
		ctx := context.Background()
		dsn := startPostgres(ctx, t) // see startPostgres below
		s, err := postgres.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func startPostgres(ctx context.Context, t *testing.T) string {
	t.Helper()
	// Wait for an actual SQL connection to succeed rather than a log line: a
	// freshly started Postgres container logs its "ready" line, restarts
	// itself once during initdb, and the host-side port publish can lag
	// behind that by a moment too. Only a real connect-and-query proves the
	// server is actually serving.
	waitForConnection := wait.ForSQL("5432/tcp", "pgx", func(host string, port network.Port) string {
		return fmt.Sprintf("postgres://gloak:gloak@%s:%s/gloak?sslmode=disable", host, port.Port())
	})
	c, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("gloak"),
		tcpostgres.WithUsername("gloak"),
		tcpostgres.WithPassword("gloak"),
		testcontainers.WithWaitStrategy(waitForConnection),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return dsn
}
