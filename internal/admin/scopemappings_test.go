package admin

import (
	"context"
	"slices"
	"testing"
)

// TestBootstrappedScopeMappings asserts the two scope mappings a bootstrapped
// realm has, for the reason TestBootstrappedClientMappers asserts the two
// protocol mappers: **no golden can**.
//
// Both live on objects whose UUIDs are minted at bootstrap - the
// `offline_access` client scope and the `account-console` client - so no
// conformance case can name either in a path, and the two cases that enumerate
// the realm do not reach a container's scope mappings at all.
//
// **Nineteen of the twenty-one containers have none**, and that is asserted
// here too rather than left implicit. It was counted, not assumed:
// `GET .../scope-mappings` was read on all fifteen bootstrapped client scopes
// and all six bootstrapped clients on a live Keycloak 26.7.1 on 2026-08-30, on
// master and on a realm created through `POST /admin/realms`, and the two below
// are the only ones that answered anything but `{}`.
func TestBootstrappedScopeMappings(t *testing.T) {
	_, s, realm := newServer(t)
	ctx := context.Background()

	names := func(t *testing.T, in []string) []string {
		t.Helper()
		out := slices.Clone(in)
		slices.Sort(out)
		return out
	}

	scope, err := s.ClientScopes().ByName(ctx, realm.ID, "offline_access")
	if err != nil {
		t.Fatalf("ByName(offline_access): %v", err)
	}
	mapped, err := s.Roles().ListClientScopeScopeMappings(ctx, scope.ID)
	if err != nil {
		t.Fatalf("ListClientScopeScopeMappings: %v", err)
	}
	if len(mapped) != 1 || mapped[0].Name != "offline_access" || mapped[0].ClientID != "" {
		t.Errorf("offline_access's scope mappings = %v, want the realm role offline_access", mapped)
	}

	console, err := s.Clients().ByClientID(ctx, realm.ID, "account-console")
	if err != nil {
		t.Fatalf("ByClientID(account-console): %v", err)
	}
	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}
	held, err := s.Roles().ListClientScopeMappings(ctx, console.ID)
	if err != nil {
		t.Fatalf("ListClientScopeMappings: %v", err)
	}
	got := make([]string, 0, len(held))
	for _, r := range held {
		if r.ClientID != account.ID {
			t.Errorf("%q is mapped from %q, want account's", r.Name, r.ClientID)
		}
		got = append(got, r.Name)
	}
	want := []string{"manage-account", "view-groups"}
	if !slices.Equal(names(t, got), want) {
		t.Errorf("account-console's scope mappings = %v, want %v", names(t, got), want)
	}

	// **The other nineteen containers have none.** A bootstrap that mapped
	// something into every scope would still pass the two assertions above.
	scopes, err := s.ClientScopes().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	if len(scopes) != 15 {
		t.Fatalf("the realm has %d client scopes, want 15", len(scopes))
	}
	for _, sc := range scopes {
		if sc.Name == "offline_access" {
			continue
		}
		mapped, err := s.Roles().ListClientScopeScopeMappings(ctx, sc.ID)
		if err != nil {
			t.Fatalf("ListClientScopeScopeMappings(%s): %v", sc.Name, err)
		}
		if len(mapped) != 0 {
			t.Errorf("client scope %q has %d scope mappings, want none", sc.Name, len(mapped))
		}
	}
	for _, clientID := range []string{"account", "admin-cli", "broker", "master-realm", "security-admin-console"} {
		c, err := s.Clients().ByClientID(ctx, realm.ID, clientID)
		if err != nil {
			t.Fatalf("ByClientID(%s): %v", clientID, err)
		}
		held, err := s.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			t.Fatalf("ListClientScopeMappings(%s): %v", clientID, err)
		}
		if len(held) != 0 {
			t.Errorf("client %q has %d scope mappings, want none", clientID, len(held))
		}
	}

	// **fullScopeAllowed is what makes account-console's two rows observable.**
	// A client with the flag set has every role in scope already, so its scope
	// mappings change nothing a caller can see - which is why the two clients
	// that carry the flag are the two that carry no mappings.
	for _, tc := range []struct {
		clientID string
		want     bool
	}{
		{"account", false}, {"account-console", false}, {"admin-cli", true},
		{"broker", false}, {"master-realm", false}, {"security-admin-console", true},
	} {
		c, err := s.Clients().ByClientID(ctx, realm.ID, tc.clientID)
		if err != nil {
			t.Fatalf("ByClientID(%s): %v", tc.clientID, err)
		}
		if c.FullScopeAllowed != tc.want {
			t.Errorf("%s fullScopeAllowed = %v, want %v", tc.clientID, c.FullScopeAllowed, tc.want)
		}
	}
}
