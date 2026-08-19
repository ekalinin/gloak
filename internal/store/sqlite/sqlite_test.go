package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
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

// TestReopenAnAlreadyMigratedStoreSucceeds proves Open is safe to call a
// second time against a database file that already has all migrations
// applied - the situation every server restart hits. A file DSN in
// t.TempDir() is required rather than an in-memory database, since an
// in-memory database never survives a Close and would prove nothing about
// reopening persisted data.
func TestReopenAnAlreadyMigratedStoreSucceeds(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "gloak.db")

	s1, err := sqlite.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	want := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
	if err := s1.Realms().Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := sqlite.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	got, err := s2.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName after reopen: %v", err)
	}
	if got.ID != want.ID {
		t.Fatalf("realm lost across reopen: want id %q, got %q", want.ID, got.ID)
	}
}

// TestForeignKeysEnforcedWithExistingQueryString proves that Open still
// enables foreign key enforcement when the caller's DSN already carries a
// query string. Open used to build the pragma DSN as dsn+"?_pragma=...",
// which for a DSN like "file:x.db?cache=shared" produces two "?" characters;
// the driver's query parser then folds everything after "cache=" into that
// single value instead of seeing two parameters, so the pragma never takes
// effect and this insert would wrongly succeed.
func TestForeignKeysEnforcedWithExistingQueryString(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "gloak.db") + "?cache=shared"

	s, err := sqlite.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	err = s.Clients().Create(ctx, &model.Client{
		ID:           model.NewID(),
		RealmID:      "does-not-exist",
		ClientID:     "probe",
		RedirectURIs: []string{},
		WebOrigins:   []string{},
		Attributes:   map[string]string{},
	})
	if err == nil {
		t.Fatal("want foreign key violation for a client referencing a nonexistent realm, got nil error")
	}
}
