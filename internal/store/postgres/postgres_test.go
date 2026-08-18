//go:build docker

package postgres_test

import (
	"context"
	"testing"

	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/postgres"
	"github.com/ekalinin/gloak/internal/store/storetest"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
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
	c, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("gloak"),
		tcpostgres.WithUsername("gloak"),
		tcpostgres.WithPassword("gloak"),
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
