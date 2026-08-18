package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
	"github.com/ekalinin/gloak/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) store.Store {
		t.Helper()
		dsn := filepath.Join(t.TempDir(), "gloak.db")
		s, err := sqlite.Open(context.Background(), dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
