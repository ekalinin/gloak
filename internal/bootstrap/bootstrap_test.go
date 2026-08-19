package bootstrap_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEnsureMasterCreatesTheSixDefaultClients(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}

	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	clients, err := s.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	got := map[string]bool{}
	for _, c := range clients {
		got[c.ClientID] = true
	}
	for _, want := range []string{
		"account", "account-console", "admin-cli",
		"broker", "master-realm", "security-admin-console",
	} {
		if !got[want] {
			t.Errorf("missing default client %q", want)
		}
	}
	if len(clients) != 6 {
		t.Errorf("want 6 clients, got %d", len(clients))
	}
}

func TestAdminCLIMatchesKeycloakConfiguration(t *testing.T) {
	// Measured: public, direct grant on, standard flow OFF, and the lightweight
	// access token attribute set. Without the attribute its tokens carry a
	// different claim set than Keycloak's.
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	c, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")

	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	if !c.PublicClient {
		t.Error("want a public client")
	}
	if !c.DirectAccessGrantsEnabled {
		t.Error("want direct access grants enabled")
	}
	if c.StandardFlowEnabled {
		t.Error("want standard flow disabled")
	}
	if got := c.Attributes["client.use.lightweight.access.token.enabled"]; got != "true" {
		t.Errorf("want the lightweight token attribute set to true, got %q", got)
	}
}

func TestEnsureMasterCreatesTheFiveRealmRoles(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	roles, err := s.Roles().ListRealmRoles(ctx, realm.ID)

	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range roles {
		got[r.Name] = true
	}
	for _, want := range []string{
		"admin", "create-realm", "default-roles-master",
		"offline_access", "uma_authorization",
	} {
		if !got[want] {
			t.Errorf("missing realm role %q", want)
		}
	}
}

func TestEnsureMasterIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("first EnsureMaster: %v", err)
	}

	err := bootstrap.EnsureMaster(ctx, s, "admin", "admin")

	if err != nil {
		t.Fatalf("second EnsureMaster must be a no-op, got %v", err)
	}
}
