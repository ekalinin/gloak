package oidc

import (
	"context"
	"slices"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// TestTokenRolesReadsTheGrantedScopeForOptionalClientScopes pins the one clause
// of the fullScopeAllowed filter that **no conformance case can reach**, and it
// is here rather than in the catalogue for a reason that is worth writing down.
//
// The rule is measured: an optional client scope contributes its scope mappings
// exactly when the granted scope names it, and contributes nothing when it does
// not - four cells, all measured on a live 26.7.1 on 2026-09-08 and recorded in
// docs/superpowers/handover/full-scope-at-issuance.md.
//
// **Gloak's protocol path cannot name one.** grantedScope is F16's constant, so
// an optional client scope's name never reaches this function through an HTTP
// request, and a mutation replacing `scope` with `""` at the one call site
// survives the whole tree - measured, and reported as this cut's only survivor.
// That is not a statement about this rule; it is F16 showing through. Until F16
// lands, the seam is the only place the clause can be asserted at all, and a
// test here is strictly weaker than a golden and strictly stronger than the
// prose it replaces - internal/admin's TestKeystoreDownloadHeaders makes the
// same trade for the same reason.
//
// Both directions are asserted. A test that only checked the naming case would
// pass on an implementation that put every optional scope in scope always,
// which is the permissive half and the one this whole cut is about.
func TestTokenRolesReadsTheGrantedScopeForOptionalClientScopes(t *testing.T) {
	h, s, realm := newHandler(t)
	ctx := context.Background()

	// A realm role the user holds and nothing maps except the optional scope.
	role := &model.Role{
		ID: model.NewID(), RealmID: realm.ID, Name: "gloak-probe-optional-scope-role",
	}
	if err := s.Roles().Create(ctx, role); err != nil {
		t.Fatalf("Create(role): %v", err)
	}

	scope := &model.ClientScope{
		ID: model.NewID(), RealmID: realm.ID,
		Name: "gloak-probe-optional-scope", Protocol: "openid-connect",
	}
	if err := s.ClientScopes().Create(ctx, scope); err != nil {
		t.Fatalf("Create(scope): %v", err)
	}
	if err := s.Roles().AddClientScopeScopeMapping(ctx, scope.ID, role.ID); err != nil {
		t.Fatalf("AddClientScopeScopeMapping: %v", err)
	}

	// The client has the flag **off**, which is the whole point: with it on
	// every role is in scope and neither half of this test can fail.
	client := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-optional-client",
		Enabled: true, PublicClient: true, FullScopeAllowed: false,
		RedirectURIs: []string{}, WebOrigins: []string{},
	}
	if err := s.Clients().Create(ctx, client); err != nil {
		t.Fatalf("Create(client): %v", err)
	}
	if err := s.ClientScopes().AddClientScope(ctx, client.ID, scope.ID, false); err != nil {
		t.Fatalf("AddClientScope(optional): %v", err)
	}

	user := &model.User{
		ID: model.NewID(), RealmID: realm.ID,
		Username: "gloak-probe-optional-user", Enabled: true,
	}
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("Create(user): %v", err)
	}
	if err := s.Roles().AssignToUser(ctx, user.ID, role.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}

	for _, tc := range []struct {
		name  string
		scope string
		want  bool
	}{
		{"the granted scope names it", "openid profile gloak-probe-optional-scope", true},
		{"the granted scope does not", "openid profile email", false},
		{"an empty granted scope", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realmRoles, _, err := h.tokenRoles(ctx, realm, client, user, tc.scope)
			if err != nil {
				t.Fatalf("tokenRoles: %v", err)
			}
			if got := slices.Contains(realmRoles, role.Name); got != tc.want {
				t.Fatalf("scope %q: role in realm_access = %v, want %v (got %v)",
					tc.scope, got, tc.want, realmRoles)
			}
		})
	}
}

// TestScopesInEffectIsWhatTheIssuerAndTheEvaluatorShare is the seam's other
// half: the client's default scopes are in effect whatever the request says.
//
// It is separate from the test above because the two halves fail separately -
// an implementation reading only the defaults passes one and an implementation
// reading only the request passes the other.
func TestScopesInEffectIsWhatTheIssuerAndTheEvaluatorShare(t *testing.T) {
	_, s, realm := newHandler(t)
	ctx := context.Background()

	scope := &model.ClientScope{
		ID: model.NewID(), RealmID: realm.ID,
		Name: "gloak-probe-default-scope", Protocol: "openid-connect",
	}
	if err := s.ClientScopes().Create(ctx, scope); err != nil {
		t.Fatalf("Create(scope): %v", err)
	}
	client := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-default-scope-client",
		Enabled: true, PublicClient: true, FullScopeAllowed: false,
		RedirectURIs: []string{}, WebOrigins: []string{},
	}
	if err := s.Clients().Create(ctx, client); err != nil {
		t.Fatalf("Create(client): %v", err)
	}
	if err := s.ClientScopes().AddClientScope(ctx, client.ID, scope.ID, true); err != nil {
		t.Fatalf("AddClientScope(default): %v", err)
	}

	// The request names nothing, and the default scope is in effect anyway.
	got, err := roles.ScopesInEffect(ctx, s.ClientScopes(), client, "")
	if err != nil {
		t.Fatalf("ScopesInEffect: %v", err)
	}
	if !hasScopeNamed(got, scope.Name) {
		t.Fatalf("a default client scope is not in effect for an empty granted scope: %v", names(got))
	}
}

// TestTokenRolesKeepsTheIssuingClientsOwnRolesAndNoOtherClients is the
// own-roles clause, which had no package-level guard until a review said so.
//
// The clause is measured symmetrically: a user holding roles on two flag-off
// clients gets, from each client's own token, that client's roles and not the
// other's. `TestConformance/oidc/introspection/scope-filtered-access-token`
// asserts one half against a recording; this asserts **both**, which is what
// says the clause is about the issuing client rather than about client roles in
// general. An implementation putting every client role in scope passes the
// golden's half and fails here.
func TestTokenRolesKeepsTheIssuingClientsOwnRolesAndNoOtherClients(t *testing.T) {
	h, s, realm := newHandler(t)
	ctx := context.Background()

	user := &model.User{
		ID: model.NewID(), RealmID: realm.ID,
		Username: "gloak-probe-own-roles-user", Enabled: true,
	}
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("Create(user): %v", err)
	}

	// Two clients, both with the flag **off** and neither mapping anything.
	// Each owns one role and the user holds both.
	clients := map[string]*model.Client{}
	for _, name := range []string{"gloak-probe-own-a", "gloak-probe-own-b"} {
		c := &model.Client{
			ID: model.NewID(), RealmID: realm.ID, ClientID: name,
			Enabled: true, PublicClient: true, FullScopeAllowed: false,
			RedirectURIs: []string{}, WebOrigins: []string{},
		}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Create(%s): %v", name, err)
		}
		role := &model.Role{
			ID: model.NewID(), RealmID: realm.ID, ClientID: c.ID, Name: name + "-role",
		}
		if err := s.Roles().Create(ctx, role); err != nil {
			t.Fatalf("Create(%s role): %v", name, err)
		}
		if err := s.Roles().AssignToUser(ctx, user.ID, role.ID); err != nil {
			t.Fatalf("AssignToUser(%s): %v", name, err)
		}
		clients[name] = c
	}

	for issuing, other := range map[string]string{
		"gloak-probe-own-a": "gloak-probe-own-b",
		"gloak-probe-own-b": "gloak-probe-own-a",
	} {
		t.Run(issuing, func(t *testing.T) {
			_, clientRoles, err := h.tokenRoles(ctx, realm, clients[issuing], user, "")
			if err != nil {
				t.Fatalf("tokenRoles: %v", err)
			}
			if got := clientRoles[issuing]; len(got) != 1 || got[0] != issuing+"-role" {
				t.Errorf("the issuing client's own role is not in its own scope: %v", clientRoles)
			}
			if _, ok := clientRoles[other]; ok {
				t.Errorf("another client's role reached the token: %v", clientRoles)
			}
		})
	}
}

func hasScopeNamed(scopes []*model.ClientScope, name string) bool {
	for _, s := range scopes {
		if s.Name == name {
			return true
		}
	}
	return false
}

func names(scopes []*model.ClientScope) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, s.Name)
	}
	return out
}
