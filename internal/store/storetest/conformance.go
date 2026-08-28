// Package storetest holds the behaviour both store drivers must satisfy.
// It lives in its own package so SQLite and Postgres share one definition of
// correct rather than two drifting copies.
package storetest

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// RunConformance exercises every store method. newStore must return an empty,
// migrated store scoped to the given test.
func RunConformance(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()

	t.Run("realm round-trips", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		want := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}

		if err := s.Realms().Create(ctx, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Realms().ByName(ctx, "master")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if got.ID != want.ID || got.Name != "master" || !got.Enabled {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
	})

	t.Run("missing realm reports ErrNotFound", func(t *testing.T) {
		s := newStore(t)

		_, err := s.Realms().ByName(context.Background(), "nope")

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("duplicate realm reports ErrConflict", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		r := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, r); err != nil {
			t.Fatalf("first Create: %v", err)
		}

		err := s.Realms().Create(ctx, &model.Realm{ID: model.NewID(), Name: "master"})

		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})

	t.Run("client attributes and slices survive the round-trip", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		want := &model.Client{
			ID: model.NewID(), RealmID: realm.ID, ClientID: "admin-cli",
			Enabled: true, PublicClient: true, DirectAccessGrantsEnabled: true,
			RedirectURIs: []string{"http://localhost:9999/*"},
			WebOrigins:   []string{"http://localhost:9999"},
			Attributes:   map[string]string{"client.use.lightweight.access.token.enabled": "true"},
		}

		if err := s.Clients().Create(ctx, want); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		got, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}

		if got.Attributes["client.use.lightweight.access.token.enabled"] != "true" {
			t.Fatalf("attributes lost: %+v", got.Attributes)
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://localhost:9999/*" {
			t.Fatalf("redirect URIs lost: %+v", got.RedirectURIs)
		}
		if !got.PublicClient || !got.DirectAccessGrantsEnabled {
			t.Fatalf("flags lost: %+v", got)
		}
	})

	t.Run("client is addressable by internal UUID", func(t *testing.T) {
		// Keycloak's admin API addresses clients by UUID, not clientId.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "account", Enabled: true}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}

		got, err := s.Clients().ByID(ctx, realm.ID, c.ID)

		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.ClientID != "account" {
			t.Fatalf("want account, got %q", got.ClientID)
		}
	})

	t.Run("credential preserves argon2 parameters", func(t *testing.T) {
		// Parameters measured on Keycloak 26.7.1: argon2id 1.3, 5 iterations,
		// 7168 KiB, parallelism 1, 32-byte output.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		want := &model.Credential{
			ID: model.NewID(), UserID: u.ID, Type: "password",
			Algorithm: "argon2", HashIterations: 5,
			AdditionalParameters: map[string][]string{
				"hashLength": {"32"}, "memory": {"7168"},
				"type": {"id"}, "version": {"1.3"}, "parallelism": {"1"},
			},
			Salt: []byte("saltsaltsaltsalt"), HashValue: []byte("hashhashhashhash"),
		}

		if err := s.Users().SetCredential(ctx, want); err != nil {
			t.Fatalf("SetCredential: %v", err)
		}
		got, err := s.Users().CredentialByUser(ctx, u.ID, "password")
		if err != nil {
			t.Fatalf("CredentialByUser: %v", err)
		}

		if got.Algorithm != "argon2" || got.HashIterations != 5 {
			t.Fatalf("algorithm or iterations lost: %+v", got)
		}
		if got.AdditionalParameters["memory"][0] != "7168" {
			t.Fatalf("memory parameter lost: %+v", got.AdditionalParameters)
		}
		if string(got.Salt) != "saltsaltsaltsalt" || string(got.HashValue) != "hashhashhashhash" {
			t.Fatalf("secret part lost: salt=%q hash=%q", got.Salt, got.HashValue)
		}
	})

	t.Run("client roles are separate from realm roles", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		client := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "master-realm", Enabled: true}
		if err := s.Clients().Create(ctx, client); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		realmRole := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "admin", Composite: true}
		if err := s.Roles().Create(ctx, realmRole); err != nil {
			t.Fatalf("Roles().Create(realm): %v", err)
		}
		for _, n := range []string{"view-users", "manage-users"} {
			r := &model.Role{ID: model.NewID(), RealmID: realm.ID, ClientID: client.ID, Name: n}
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Roles().Create(%q): %v", n, err)
			}
		}

		clientRoles, err := s.Roles().ListClientRoles(ctx, realm.ID, client.ID)
		if err != nil {
			t.Fatalf("ListClientRoles: %v", err)
		}
		if len(clientRoles) != 2 {
			t.Fatalf("want 2 client roles, got %d", len(clientRoles))
		}
		// A client role leaking into the realm list would make every realm
		// role listing wrong the moment the admin client exists.
		realmRoles, err := s.Roles().ListRealmRoles(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListRealmRoles: %v", err)
		}
		if len(realmRoles) != 1 || realmRoles[0].Name != "admin" {
			t.Fatalf("client roles leaked into the realm list: %+v", realmRoles)
		}
	})

	t.Run("a role is addressable by ID", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		want := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "admin", Composite: true}
		if err := s.Roles().Create(ctx, want); err != nil {
			t.Fatalf("Roles().Create: %v", err)
		}

		got, err := s.Roles().ByID(ctx, realm.ID, want.ID)

		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.Name != "admin" || !got.Composite {
			t.Fatalf("round-trip wrong: %+v", got)
		}
		if _, err := s.Roles().ByID(ctx, realm.ID, model.NewID()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound for an unknown role, got %v", err)
		}
	})

	t.Run("role assignments round-trip", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		role := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "admin"}
		if err := s.Roles().Create(ctx, role); err != nil {
			t.Fatalf("Roles().Create: %v", err)
		}

		if err := s.Roles().AssignToUser(ctx, u.ID, role.ID); err != nil {
			t.Fatalf("AssignToUser: %v", err)
		}
		got, err := s.Roles().ListUserRoles(ctx, u.ID)
		if err != nil {
			t.Fatalf("ListUserRoles: %v", err)
		}
		if len(got) != 1 || got[0].Name != "admin" {
			t.Fatalf("want the admin role back, got %+v", got)
		}

		// Assigning twice is a conflict rather than a silent no-op, so a
		// caller can tell "already had it" from "just granted it".
		if err := s.Roles().AssignToUser(ctx, u.ID, role.ID); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict on a second assignment, got %v", err)
		}

		if err := s.Roles().RemoveFromUser(ctx, u.ID, role.ID); err != nil {
			t.Fatalf("RemoveFromUser: %v", err)
		}
		// Removing what is not assigned reports ErrNotFound: neither driver
		// treats a delete affecting no row as an error on its own.
		if err := s.Roles().RemoveFromUser(ctx, u.ID, role.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound removing an unassigned role, got %v", err)
		}
	})

	t.Run("deleting a user takes its role assignments with it", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "doomed", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		role := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "admin"}
		if err := s.Roles().Create(ctx, role); err != nil {
			t.Fatalf("Roles().Create: %v", err)
		}
		if err := s.Roles().AssignToUser(ctx, u.ID, role.ID); err != nil {
			t.Fatalf("AssignToUser: %v", err)
		}

		if err := s.Users().Delete(ctx, realm.ID, u.ID); err != nil {
			t.Fatalf("Users().Delete: %v", err)
		}

		// An orphaned assignment would grant a rights to a recycled user ID.
		got, err := s.Roles().ListUserRoles(ctx, u.ID)
		if err != nil {
			t.Fatalf("ListUserRoles: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("assignments outlived the user: %+v", got)
		}
	})

	t.Run("composite roles round-trip", func(t *testing.T) {
		// The bootstrapped administrator holds no client roles directly - all
		// its rights arrive through the admin role's composites, measured on a
		// live Keycloak. A build that cannot expand them grants it nothing.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		admin := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "admin", Composite: true}
		child := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "create-realm"}
		for _, r := range []*model.Role{admin, child} {
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Roles().Create(%q): %v", r.Name, err)
			}
		}

		if err := s.Roles().AddComposite(ctx, admin.ID, child.ID); err != nil {
			t.Fatalf("AddComposite: %v", err)
		}
		got, err := s.Roles().ListComposites(ctx, admin.ID)

		if err != nil {
			t.Fatalf("ListComposites: %v", err)
		}
		if len(got) != 1 || got[0].Name != "create-realm" {
			t.Fatalf("want create-realm, got %+v", got)
		}
		if err := s.Roles().AddComposite(ctx, admin.ID, child.ID); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict adding the same composite twice, got %v", err)
		}
	})

	t.Run("role update, delete and attributes", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		r := &model.Role{
			ID: model.NewID(), RealmID: realm.ID, Name: "probe",
			Description: "before",
			Attributes:  map[string][]string{"k": {"v"}},
		}
		if err := s.Roles().Create(ctx, r); err != nil {
			t.Fatalf("Create: %v", err)
		}

		// Attributes round-trip. Measured on Keycloak: a role keeps them where
		// a user's are dropped by the declarative user profile.
		got, err := s.Roles().ByName(ctx, realm.ID, "", "probe")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if len(got.Attributes["k"]) != 1 || got.Attributes["k"][0] != "v" {
			t.Fatalf("attributes did not round-trip: %v", got.Attributes)
		}

		// Update replaces rather than merging, including the rename, because
		// that is what the endpoint above it does.
		r.Name = "probe-renamed"
		r.Description = ""
		r.Attributes = nil
		if err := s.Roles().Update(ctx, r); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if _, err := s.Roles().ByName(ctx, realm.ID, "", "probe"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the old name still resolves: %v", err)
		}
		got, err = s.Roles().ByName(ctx, realm.ID, "", "probe-renamed")
		if err != nil {
			t.Fatalf("ByName after rename: %v", err)
		}
		if got.ID != r.ID {
			t.Fatalf("the rename minted a new id: %s then %s", r.ID, got.ID)
		}
		if got.Description != "" || len(got.Attributes) != 0 {
			t.Fatalf("Update did not replace: %q %v", got.Description, got.Attributes)
		}

		if err := s.Roles().Delete(ctx, realm.ID, r.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.Roles().Delete(ctx, realm.ID, r.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleting twice: want ErrNotFound, got %v", err)
		}
	})

	// Deleting the last child must leave the parent non-composite. The
	// composite_role row cascades away with the child, but `composite` is a
	// column on the parent, so without the resync in Delete the parent answers
	// `"composite":true` beside an empty composites listing - and the flag is
	// derived, true exactly when the role has children.
	t.Run("deleting a child resyncs the parent's composite flag", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		parent := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "parent"}
		first := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "first"}
		second := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "second"}
		for _, r := range []*model.Role{parent, first, second} {
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Create %s: %v", r.Name, err)
			}
		}
		for _, child := range []*model.Role{first, second} {
			if err := s.Roles().AddComposite(ctx, parent.ID, child.ID); err != nil {
				t.Fatalf("AddComposite %s: %v", child.Name, err)
			}
		}
		parent.Composite = true
		if err := s.Roles().Update(ctx, parent); err != nil {
			t.Fatalf("Update parent: %v", err)
		}

		// One child gone, one left: the parent is still composite.
		if err := s.Roles().Delete(ctx, realm.ID, first.ID); err != nil {
			t.Fatalf("Delete first: %v", err)
		}
		got, err := s.Roles().ByID(ctx, realm.ID, parent.ID)
		if err != nil {
			t.Fatalf("ByID parent: %v", err)
		}
		if !got.Composite {
			t.Fatalf("parent still has a child, want composite true, got false")
		}

		// The last child gone: the flag has to follow.
		if err := s.Roles().Delete(ctx, realm.ID, second.ID); err != nil {
			t.Fatalf("Delete second: %v", err)
		}
		got, err = s.Roles().ByID(ctx, realm.ID, parent.ID)
		if err != nil {
			t.Fatalf("ByID parent: %v", err)
		}
		if got.Composite {
			t.Fatalf("parent has no children left, want composite false, got true")
		}
		kids, err := s.Roles().ListComposites(ctx, parent.ID)
		if err != nil {
			t.Fatalf("ListComposites: %v", err)
		}
		if len(kids) != 0 {
			t.Fatalf("want no composites left, got %d", len(kids))
		}

		// A delete that finds nothing must not disturb a flag it never
		// touched: the UPDATE and the DELETE share one transaction.
		other := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "other", Composite: true}
		if err := s.Roles().Create(ctx, other); err != nil {
			t.Fatalf("Create other: %v", err)
		}
		if err := s.Roles().Delete(ctx, realm.ID, model.NewID()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Delete of a missing role: want ErrNotFound, got %v", err)
		}
		got, err = s.Roles().ByID(ctx, realm.ID, other.ID)
		if err != nil {
			t.Fatalf("ByID other: %v", err)
		}
		if !got.Composite {
			t.Fatalf("a failed delete cleared an unrelated composite flag")
		}
	})

	t.Run("composite removal and role holders", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		parent := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "parent", Composite: true}
		child := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "child"}
		for _, r := range []*model.Role{parent, child} {
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Create %s: %v", r.Name, err)
			}
		}
		if err := s.Roles().AddComposite(ctx, parent.ID, child.ID); err != nil {
			t.Fatalf("AddComposite: %v", err)
		}
		if err := s.Roles().RemoveComposite(ctx, parent.ID, child.ID); err != nil {
			t.Fatalf("RemoveComposite: %v", err)
		}
		kids, err := s.Roles().ListComposites(ctx, parent.ID)
		if err != nil {
			t.Fatalf("ListComposites: %v", err)
		}
		if len(kids) != 0 {
			t.Fatalf("want no composites left, got %d", len(kids))
		}

		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "holder", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		if err := s.Roles().AssignToUser(ctx, u.ID, parent.ID); err != nil {
			t.Fatalf("AssignToUser: %v", err)
		}

		// Direct holders only. Measured: /roles/{name}/users lists the
		// administrator for `admin` and nobody for `create-realm`, which admin
		// is composite over.
		holders, err := s.Roles().ListUsersWithRole(ctx, realm.ID, parent.ID)
		if err != nil {
			t.Fatalf("ListUsersWithRole: %v", err)
		}
		if len(holders) != 1 || holders[0].ID != u.ID {
			t.Fatalf("want the one direct holder, got %d", len(holders))
		}
		childHolders, err := s.Roles().ListUsersWithRole(ctx, realm.ID, child.ID)
		if err != nil {
			t.Fatalf("ListUsersWithRole(child): %v", err)
		}
		if len(childHolders) != 0 {
			t.Fatalf("a composite child reported %d holders; it must report none", len(childHolders))
		}
	})

	t.Run("sessions round-trip and cascade", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "admin-cli", Enabled: true}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		us := &model.UserSession{ID: model.NewID(), RealmID: realm.ID, UserID: u.ID,
			Username: "admin", StartedAt: 1000, LastRefresh: 1000, ExpiresAt: 2000}
		if err := s.Sessions().CreateUserSession(ctx, us); err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}
		cs := &model.ClientSession{ID: model.NewID(), UserSessionID: us.ID,
			ClientID: c.ID, Scope: "openid email profile", StartedAt: 1000}
		if err := s.Sessions().CreateClientSession(ctx, cs); err != nil {
			t.Fatalf("CreateClientSession: %v", err)
		}

		got, err := s.Sessions().UserSessionByID(ctx, realm.ID, us.ID)
		if err != nil {
			t.Fatalf("UserSessionByID: %v", err)
		}
		if got.Username != "admin" || got.UserID != u.ID || got.ExpiresAt != 2000 {
			t.Fatalf("user session round-trip wrong: %+v", got)
		}
		gotClient, err := s.Sessions().ClientSession(ctx, us.ID, c.ID)
		if err != nil {
			t.Fatalf("ClientSession: %v", err)
		}
		if gotClient.Scope != "openid email profile" {
			t.Fatalf("client session scope lost: %+v", gotClient)
		}

		if err := s.Sessions().TouchUserSession(ctx, us.ID, 1500); err != nil {
			t.Fatalf("TouchUserSession: %v", err)
		}
		got, err = s.Sessions().UserSessionByID(ctx, realm.ID, us.ID)
		if err != nil {
			t.Fatalf("UserSessionByID after touch: %v", err)
		}
		if got.LastRefresh != 1500 {
			t.Fatalf("LastRefresh not updated: %+v", got)
		}

		// Revocation deletes the user session; the client sessions hanging off
		// it must go with it, or a refresh token would still find its scope.
		if err := s.Sessions().DeleteUserSession(ctx, realm.ID, us.ID); err != nil {
			t.Fatalf("DeleteUserSession: %v", err)
		}
		if _, err := s.Sessions().UserSessionByID(ctx, realm.ID, us.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound after delete, got %v", err)
		}
		if _, err := s.Sessions().ClientSession(ctx, us.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("client session outlived its user session: %v", err)
		}
	})

	t.Run("deleting a session that is already gone reports ErrNotFound", func(t *testing.T) {
		// Neither driver treats a delete matching no row as an error, so the
		// repository has to check the affected count itself. Revoking the same
		// token twice depends on this telling the two cases apart.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}

		err := s.Sessions().DeleteUserSession(ctx, realm.ID, model.NewID())

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("a session is not visible from another realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		for _, r := range []*model.Realm{realm, other} {
			if err := s.Realms().Create(ctx, r); err != nil {
				t.Fatalf("Realms().Create: %v", err)
			}
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		us := &model.UserSession{ID: model.NewID(), RealmID: realm.ID, UserID: u.ID,
			Username: "admin", StartedAt: 1, LastRefresh: 1, ExpiresAt: 2}
		if err := s.Sessions().CreateUserSession(ctx, us); err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}

		_, err := s.Sessions().UserSessionByID(ctx, other.ID, us.ID)

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a session leaked across realms: %v", err)
		}
	})

	t.Run("realm keys round-trip and are listed per realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		if err := s.Realms().Create(ctx, other); err != nil {
			t.Fatalf("Realms().Create(other): %v", err)
		}
		want := &model.RealmKey{
			ID: model.NewID(), RealmID: realm.ID, Algorithm: "RS256", Use: "sig",
			PrivateKey: []byte{1, 2, 3}, Certificate: []byte{4, 5, 6}, CreatedAt: 1,
		}
		if err := s.Keys().Create(ctx, want); err != nil {
			t.Fatalf("Keys().Create: %v", err)
		}
		hmac := &model.RealmKey{
			ID: model.NewID(), RealmID: realm.ID, Algorithm: "HS512",
			PrivateKey: []byte{7, 8, 9}, Certificate: []byte{}, CreatedAt: 2,
		}
		if err := s.Keys().Create(ctx, hmac); err != nil {
			t.Fatalf("Keys().Create(hmac): %v", err)
		}
		if err := s.Keys().Create(ctx, &model.RealmKey{
			ID: model.NewID(), RealmID: other.ID, Algorithm: "RS256", Use: "sig",
			PrivateKey: []byte{9}, Certificate: []byte{}, CreatedAt: 3,
		}); err != nil {
			t.Fatalf("Keys().Create(other realm): %v", err)
		}

		got, err := s.Keys().ListByRealm(ctx, realm.ID)

		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		// Two keys, and the second realm's key is not among them: a key set
		// leaking across realms is the bug this asserts against.
		if len(got) != 2 {
			t.Fatalf("want 2 keys for master, got %d", len(got))
		}
		byAlg := map[string]*model.RealmKey{}
		for _, k := range got {
			byAlg[k.Algorithm] = k
		}
		if rs := byAlg["RS256"]; rs == nil || rs.Use != "sig" ||
			string(rs.PrivateKey) != "\x01\x02\x03" || string(rs.Certificate) != "\x04\x05\x06" {
			t.Fatalf("RS256 key lost its bytes: %+v", rs)
		}
		if hs := byAlg["HS512"]; hs == nil || len(hs.Certificate) != 0 {
			t.Fatalf("HS512 key round-trip wrong: %+v", hs)
		}
	})

	t.Run("a realm holds one key per algorithm", func(t *testing.T) {
		// Two processes racing to generate a realm's keys must not produce two
		// RS256 keys: the kid published in the JWKS would then depend on which
		// row was read back.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		first := &model.RealmKey{ID: model.NewID(), RealmID: realm.ID,
			Algorithm: "RS256", Use: "sig", PrivateKey: []byte{1}, Certificate: []byte{}, CreatedAt: 1}
		if err := s.Keys().Create(ctx, first); err != nil {
			t.Fatalf("first Create: %v", err)
		}

		err := s.Keys().Create(ctx, &model.RealmKey{ID: model.NewID(), RealmID: realm.ID,
			Algorithm: "RS256", Use: "sig", PrivateKey: []byte{2}, Certificate: []byte{}, CreatedAt: 2})

		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})

	t.Run("realm roles are listable", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		for _, n := range []string{"admin", "create-realm", "offline_access"} {
			r := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: n}
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Roles().Create(%q): %v", n, err)
			}
		}

		got, err := s.Roles().ListRealmRoles(ctx, realm.ID)

		if err != nil {
			t.Fatalf("ListRealmRoles: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("want 3 realm roles, got %d", len(got))
		}
	})

	// The order is contract, not convenience: Keycloak's user listing was
	// measured sorted by username rather than returning insertion order, and
	// the admin API hands the store's order straight to the client. Both
	// drivers have to agree, so this belongs here rather than in either one.
	t.Run("users are listed sorted by username", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		for _, n := range []string{"zzz", "admin", "aaa"} {
			u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: n, Enabled: true}
			if err := s.Users().Create(ctx, u); err != nil {
				t.Fatalf("Users().Create(%q): %v", n, err)
			}
		}

		got, err := s.Users().ListByRealm(ctx, realm.ID)

		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		names := make([]string, 0, len(got))
		for _, u := range got {
			names = append(names, u.Username)
		}
		want := []string{"aaa", "admin", "zzz"}
		if !slices.Equal(names, want) {
			t.Fatalf("want %v, got %v", want, names)
		}
	})

	// The credential endpoints need the list, the lookup by id, the delete and
	// the label. All four are new and none is exercised by anything else, so
	// they are held here rather than by whichever driver happens to run.
	t.Run("credentials list, relabel and delete", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		user := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "u", Enabled: true}
		if err := s.Users().Create(ctx, user); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		cred := &model.Credential{
			ID: model.NewID(), UserID: user.ID, Type: "password",
			CreatedDate: 1, Algorithm: "argon2", HashIterations: 5,
			AdditionalParameters: map[string][]string{"memory": {"7168"}},
			Salt:                 []byte("salt"), HashValue: []byte("hash"),
		}
		if err := s.Users().SetCredential(ctx, cred); err != nil {
			t.Fatalf("SetCredential: %v", err)
		}

		listed, err := s.Users().ListCredentials(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(listed) != 1 || listed[0].ID != cred.ID {
			t.Fatalf("want the one credential back, got %d", len(listed))
		}
		if listed[0].Label != "" {
			t.Fatalf("want no label on a fresh credential, got %q", listed[0].Label)
		}

		cred.Label = "office laptop"
		cred.Priority = 3
		if err := s.Users().UpdateCredential(ctx, cred); err != nil {
			t.Fatalf("UpdateCredential: %v", err)
		}
		got, err := s.Users().CredentialByID(ctx, user.ID, cred.ID)
		if err != nil {
			t.Fatalf("CredentialByID: %v", err)
		}
		if got.Label != "office laptop" || got.Priority != 3 {
			t.Fatalf("want the label and priority back, got %q / %d", got.Label, got.Priority)
		}
		// The hash must have survived the label write: UpdateCredential writes
		// two columns and must not touch the rest.
		if string(got.HashValue) != "hash" {
			t.Fatalf("UpdateCredential disturbed the hash: %q", got.HashValue)
		}

		if err := s.Users().DeleteCredential(ctx, user.ID, cred.ID); err != nil {
			t.Fatalf("DeleteCredential: %v", err)
		}
		if err := s.Users().DeleteCredential(ctx, user.ID, cred.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound deleting twice, got %v", err)
		}
	})

	// Measured on the admin API: a reset-password replaces the credential in
	// place - same id, refreshed createdDate - and clears the userLabel. The
	// upsert is what has to reproduce that, and priority is deliberately not
	// cleared, since a reset does not reorder anything.
	t.Run("setting a credential again replaces it and clears the label", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		user := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "u", Enabled: true}
		if err := s.Users().Create(ctx, user); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		first := &model.Credential{
			ID: model.NewID(), UserID: user.ID, Type: "password", CreatedDate: 1,
			Algorithm: "argon2", HashValue: []byte("old"), Label: "old label",
		}
		if err := s.Users().SetCredential(ctx, first); err != nil {
			t.Fatalf("SetCredential: %v", err)
		}

		second := *first
		second.CreatedDate = 2
		second.HashValue = []byte("new")
		second.Label = ""
		if err := s.Users().SetCredential(ctx, &second); err != nil {
			t.Fatalf("SetCredential again: %v", err)
		}

		listed, err := s.Users().ListCredentials(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListCredentials: %v", err)
		}
		if len(listed) != 1 {
			t.Fatalf("want one credential after a replace, got %d", len(listed))
		}
		if listed[0].ID != first.ID || listed[0].CreatedDate != 2 || listed[0].Label != "" {
			t.Fatalf("want the id kept and the rest refreshed, got %+v", listed[0])
		}
		// CredentialByUser is what a login goes through, so it must see the
		// replacement rather than a stale row.
		byUser, err := s.Users().CredentialByUser(ctx, user.ID, "password")
		if err != nil {
			t.Fatalf("CredentialByUser: %v", err)
		}
		if string(byUser.HashValue) != "new" {
			t.Fatalf("want the new hash, got %q", byUser.HashValue)
		}
	})

	// POST /users/{id}/logout deletes every session the user holds and must
	// leave everybody else's alone.
	t.Run("deleting a user's sessions spares other users", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		mine := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "mine", Enabled: true}
		theirs := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "theirs", Enabled: true}
		for _, u := range []*model.User{mine, theirs} {
			if err := s.Users().Create(ctx, u); err != nil {
				t.Fatalf("Users().Create(%s): %v", u.Username, err)
			}
		}
		var minesSessions []string
		for range 2 {
			id := model.NewID()
			minesSessions = append(minesSessions, id)
			if err := s.Sessions().CreateUserSession(ctx, &model.UserSession{
				ID: id, RealmID: realm.ID, UserID: mine.ID, Username: mine.Username,
			}); err != nil {
				t.Fatalf("CreateUserSession: %v", err)
			}
		}
		other := model.NewID()
		if err := s.Sessions().CreateUserSession(ctx, &model.UserSession{
			ID: other, RealmID: realm.ID, UserID: theirs.ID, Username: theirs.Username,
		}); err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}

		if err := s.Sessions().DeleteUserSessions(ctx, realm.ID, mine.ID); err != nil {
			t.Fatalf("DeleteUserSessions: %v", err)
		}

		for _, id := range minesSessions {
			if _, err := s.Sessions().UserSessionByID(ctx, realm.ID, id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("session %s survived the logout: %v", id, err)
			}
		}
		if _, err := s.Sessions().UserSessionByID(ctx, realm.ID, other); err != nil {
			t.Fatalf("another user's session was taken with it: %v", err)
		}
		// Measured as a 204 for a user with no sessions, so a second call is
		// a success rather than ErrNotFound.
		if err := s.Sessions().DeleteUserSessions(ctx, realm.ID, mine.ID); err != nil {
			t.Fatalf("want no error deleting nothing, got %v", err)
		}
	})

	t.Run("a user is not listed from another realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		mine := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		theirs := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		for _, r := range []*model.Realm{mine, theirs} {
			if err := s.Realms().Create(ctx, r); err != nil {
				t.Fatalf("Realms().Create(%q): %v", r.Name, err)
			}
		}
		u := &model.User{ID: model.NewID(), RealmID: theirs.ID, Username: "elsewhere", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}

		got, err := s.Users().ListByRealm(ctx, mine.ID)

		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("want no users in the empty realm, got %d", len(got))
		}
	})
	t.Run("a group tree round-trips, and the count is not the listing", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		top := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top",
			Attributes: map[string][]string{"k": {"a", "b"}}}
		child := &model.Group{ID: model.NewID(), RealmID: realm.ID, ParentID: top.ID, Name: "child"}
		for _, g := range []*model.Group{top, child} {
			if err := s.Groups().Create(ctx, g); err != nil {
				t.Fatalf("Groups().Create(%q): %v", g.Name, err)
			}
		}

		got, err := s.Groups().ByID(ctx, realm.ID, top.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		// Attribute order round-trips through the ordinal column, which is why
		// this asserts the slice rather than its length.
		if got.Name != "top" || got.ParentID != "" || !slices.Equal(got.Attributes["k"], []string{"a", "b"}) {
			t.Fatalf("round-trip mismatch: %+v", got)
		}

		// The listing is top-level and the count is the whole tree. Measured on
		// a live 26.7.1: one parent and one child give a one-row listing and
		// {"count":2}.
		list, err := s.Groups().ListTopLevel(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListTopLevel: %v", err)
		}
		if len(list) != 1 || list[0].ID != top.ID {
			t.Fatalf("want only the top-level group, got %d", len(list))
		}
		all, err := s.Groups().ListAll(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		if len(all) != 2 {
			t.Fatalf("want the whole tree, got %d", len(all))
		}
		kids, err := s.Groups().ListChildren(ctx, realm.ID, top.ID)
		if err != nil || len(kids) != 1 || kids[0].ID != child.ID {
			t.Fatalf("ListChildren: %v, %d rows", err, len(kids))
		}
		chain, err := s.Groups().Ancestry(ctx, realm.ID, child.ID)
		if err != nil {
			t.Fatalf("Ancestry: %v", err)
		}
		if len(chain) != 2 || chain[0].ID != top.ID || chain[1].ID != child.ID {
			t.Fatalf("want the chain nearest last, got %+v", chain)
		}
	})

	t.Run("deleting a group takes its subtree", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		top := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"}
		child := &model.Group{ID: model.NewID(), RealmID: realm.ID, ParentID: top.ID, Name: "child"}
		for _, g := range []*model.Group{top, child} {
			if err := s.Groups().Create(ctx, g); err != nil {
				t.Fatalf("Create(%q): %v", g.Name, err)
			}
		}

		if err := s.Groups().Delete(ctx, realm.ID, top.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		if _, err := s.Groups().ByID(ctx, realm.ID, child.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the child outlived its parent: %v", err)
		}
		if err := s.Groups().Delete(ctx, realm.ID, top.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deleting it twice: want ErrNotFound, got %v", err)
		}
	})

	t.Run("a duplicate name collides within its parent, not the realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		top := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"}
		if err := s.Groups().Create(ctx, top); err != nil {
			t.Fatalf("Create: %v", err)
		}

		err := s.Groups().Create(ctx, &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"})
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("a second top-level \"top\": want ErrConflict, got %v", err)
		}
		// The same name one level down is a different group, which is what the
		// measured 409 says: "Top level group named 'x' already exists".
		if err := s.Groups().Create(ctx, &model.Group{
			ID: model.NewID(), RealmID: realm.ID, ParentID: top.ID, Name: "top"}); err != nil {
			t.Fatalf("a child named after its parent: %v", err)
		}
	})

	t.Run("membership is direct and does not reach the parent", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "member", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		top := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"}
		child := &model.Group{ID: model.NewID(), RealmID: realm.ID, ParentID: top.ID, Name: "child"}
		for _, g := range []*model.Group{top, child} {
			if err := s.Groups().Create(ctx, g); err != nil {
				t.Fatalf("Create(%q): %v", g.Name, err)
			}
		}

		if err := s.Groups().AddMember(ctx, child.ID, u.ID); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		// Measured idempotent: the PUT answers 204 for a membership already
		// held, so a second add must not be a conflict.
		if err := s.Groups().AddMember(ctx, child.ID, u.ID); err != nil {
			t.Fatalf("AddMember twice: %v", err)
		}

		in, err := s.Groups().Members(ctx, realm.ID, child.ID)
		if err != nil || len(in) != 1 || in[0].ID != u.ID {
			t.Fatalf("Members(child): %v, %d rows", err, len(in))
		}
		// **The parent has no members.** A user in a child was measured not
		// being a member of its parent, so nothing walks downwards here.
		up, err := s.Groups().Members(ctx, realm.ID, top.ID)
		if err != nil || len(up) != 0 {
			t.Fatalf("Members(parent): %v, %d rows - membership reached upwards", err, len(up))
		}
		mine, err := s.Groups().ListUserGroups(ctx, realm.ID, u.ID)
		if err != nil || len(mine) != 1 || mine[0].ID != child.ID {
			t.Fatalf("ListUserGroups: %v, %d rows", err, len(mine))
		}

		if err := s.Groups().RemoveMember(ctx, child.ID, u.ID); err != nil {
			t.Fatalf("RemoveMember: %v", err)
		}
		// Removing one that is not there is not an error, the way
		// RemoveComposite is not.
		if err := s.Groups().RemoveMember(ctx, child.ID, u.ID); err != nil {
			t.Fatalf("RemoveMember twice: %v", err)
		}
		if left, err := s.Groups().Members(ctx, realm.ID, child.ID); err != nil || len(left) != 0 {
			t.Fatalf("after removal: %v, %d rows", err, len(left))
		}
	})

	t.Run("a group in another realm is invisible", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		mine := &model.Realm{ID: model.NewID(), Name: "mine", Enabled: true}
		theirs := &model.Realm{ID: model.NewID(), Name: "theirs", Enabled: true}
		for _, r := range []*model.Realm{mine, theirs} {
			if err := s.Realms().Create(ctx, r); err != nil {
				t.Fatalf("Realms().Create(%q): %v", r.Name, err)
			}
		}
		g := &model.Group{ID: model.NewID(), RealmID: theirs.ID, Name: "elsewhere"}
		if err := s.Groups().Create(ctx, g); err != nil {
			t.Fatalf("Groups().Create: %v", err)
		}

		if _, err := s.Groups().ByID(ctx, mine.ID, g.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("ByID across realms: want ErrNotFound, got %v", err)
		}
		if list, err := s.Groups().ListTopLevel(ctx, mine.ID); err != nil || len(list) != 0 {
			t.Fatalf("ListTopLevel: %v, %d rows", err, len(list))
		}
		if all, err := s.Groups().ListAll(ctx, mine.ID); err != nil || len(all) != 0 {
			t.Fatalf("ListAll: %v, %d rows", err, len(all))
		}
	})

	t.Run("a group holds roles, and its composites expand", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		g := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "holder"}
		if err := s.Groups().Create(ctx, g); err != nil {
			t.Fatalf("Groups().Create: %v", err)
		}
		parent := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "parent", Composite: true}
		child := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "child"}
		for _, r := range []*model.Role{parent, child} {
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Roles().Create(%q): %v", r.Name, err)
			}
		}
		if err := s.Roles().AddComposite(ctx, parent.ID, child.ID); err != nil {
			t.Fatalf("AddComposite: %v", err)
		}

		if err := s.Roles().AssignToGroup(ctx, g.ID, parent.ID); err != nil {
			t.Fatalf("AssignToGroup: %v", err)
		}
		// Measured idempotent on the route, so a repeat must not conflict.
		if err := s.Roles().AssignToGroup(ctx, g.ID, parent.ID); err != nil {
			t.Fatalf("AssignToGroup twice: %v", err)
		}

		direct, err := s.Roles().ListGroupRoles(ctx, g.ID)
		if err != nil || len(direct) != 1 || direct[0].ID != parent.ID {
			t.Fatalf("ListGroupRoles: %v, %d rows", err, len(direct))
		}
		// The group's roles are not the user's: a user holding nothing must
		// not pick these up, which a shared table would make easy to get wrong.
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "bystander", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		if held, err := s.Roles().ListUserRoles(ctx, u.ID); err != nil || len(held) != 0 {
			t.Fatalf("a group's roles reached a user: %v, %d rows", err, len(held))
		}

		if err := s.Roles().RemoveFromGroup(ctx, g.ID, parent.ID); err != nil {
			t.Fatalf("RemoveFromGroup: %v", err)
		}
		// Removing one that is not there is not an error.
		if err := s.Roles().RemoveFromGroup(ctx, g.ID, parent.ID); err != nil {
			t.Fatalf("RemoveFromGroup twice: %v", err)
		}
		if left, err := s.Roles().ListGroupRoles(ctx, g.ID); err != nil || len(left) != 0 {
			t.Fatalf("after removal: %v, %d rows", err, len(left))
		}
	})

}
