// Package storetest holds the behaviour both store drivers must satisfy.
// It lives in its own package so SQLite and Postgres share one definition of
// correct rather than two drifting copies.
package storetest

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
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

	t.Run("realm settings survive the round-trip byte for byte", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		// Two keys in an order neither driver would produce by sorting, because
		// the whole point of storing the representation as text rather than as
		// a structured type is that its key order is the contract.
		const settings = `{"zzz":1,"aaa":2}`
		r := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true, Settings: []byte(settings)}
		if err := s.Realms().Create(ctx, r); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := s.Realms().ByName(ctx, "master")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if string(got.Settings) != settings {
			t.Fatalf("settings: got %q, want %q", got.Settings, settings)
		}
	})

	t.Run("a realm with no settings reads back nil, not empty", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		if err := s.Realms().Create(ctx, &model.Realm{ID: model.NewID(), Name: "master"}); err != nil {
			t.Fatalf("Create: %v", err)
		}

		got, err := s.Realms().ByName(ctx, "master")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		// nil rather than []byte{} so the admin layer can tell "never written"
		// from "written as nothing" with one test. The two drivers store an
		// empty string either way, so this is the one place they could disagree.
		if got.Settings != nil {
			t.Fatalf("settings: got %q, want nil", got.Settings)
		}
	})

	t.Run("a realm can be renamed, keeping its id", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		r := &model.Realm{ID: model.NewID(), Name: "before", Enabled: false}
		if err := s.Realms().Create(ctx, r); err != nil {
			t.Fatalf("Create: %v", err)
		}

		r.Name = "after"
		r.Enabled = true
		r.Settings = []byte(`{"x":1}`)
		if err := s.Realms().Update(ctx, r); err != nil {
			t.Fatalf("Update: %v", err)
		}

		if _, err := s.Realms().ByName(ctx, "before"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("old name still resolves: %v", err)
		}
		got, err := s.Realms().ByName(ctx, "after")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if got.ID != r.ID || !got.Enabled || string(got.Settings) != `{"x":1}` {
			t.Fatalf("after rename: %+v", got)
		}
	})

	t.Run("renaming onto a taken name reports ErrConflict", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		for _, name := range []string{"master", "other"} {
			if err := s.Realms().Create(ctx, &model.Realm{ID: model.NewID(), Name: name}); err != nil {
				t.Fatalf("Create %s: %v", name, err)
			}
		}
		other, err := s.Realms().ByName(ctx, "other")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}

		other.Name = "master"
		err = s.Realms().Update(ctx, other)

		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})

	t.Run("updating a realm that is gone reports ErrNotFound", func(t *testing.T) {
		s := newStore(t)

		err := s.Realms().Update(context.Background(), &model.Realm{ID: model.NewID(), Name: "gone"})

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("deleting a realm takes everything in it", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		doomed := &model.Realm{ID: model.NewID(), Name: "doomed", Enabled: true}
		keep := &model.Realm{ID: model.NewID(), Name: "keep", Enabled: true}
		for _, r := range []*model.Realm{doomed, keep} {
			if err := s.Realms().Create(ctx, r); err != nil {
				t.Fatalf("Create %s: %v", r.Name, err)
			}
		}
		// One row in every table that hangs off a realm, so the cascade is
		// asserted rather than read off the DDL. Both drivers declare it;
		// SQLite only acts on it because Open sets the foreign_keys pragma,
		// which is exactly the kind of difference this suite exists to catch.
		client := &model.Client{ID: model.NewID(), RealmID: doomed.ID, ClientID: "c", Enabled: true}
		if err := s.Clients().Create(ctx, client); err != nil {
			t.Fatalf("Create client: %v", err)
		}
		user := &model.User{ID: model.NewID(), RealmID: doomed.ID, Username: "u", Enabled: true}
		if err := s.Users().Create(ctx, user); err != nil {
			t.Fatalf("Create user: %v", err)
		}
		role := &model.Role{ID: model.NewID(), RealmID: doomed.ID, Name: "r"}
		if err := s.Roles().Create(ctx, role); err != nil {
			t.Fatalf("Create role: %v", err)
		}
		group := &model.Group{ID: model.NewID(), RealmID: doomed.ID, Name: "g"}
		if err := s.Groups().Create(ctx, group); err != nil {
			t.Fatalf("Create group: %v", err)
		}
		if err := s.Keys().Create(ctx, &model.RealmKey{
			ID: model.NewID(), RealmID: doomed.ID, Algorithm: "RS256", Use: "SIG",
			PrivateKey: []byte("p"), Certificate: []byte("c"),
		}); err != nil {
			t.Fatalf("Create key: %v", err)
		}

		if err := s.Realms().Delete(ctx, doomed.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		if _, err := s.Realms().ByName(ctx, "doomed"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("realm survived: %v", err)
		}
		if _, err := s.Clients().ByID(ctx, doomed.ID, client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("client survived: %v", err)
		}
		if _, err := s.Users().ByID(ctx, doomed.ID, user.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("user survived: %v", err)
		}
		if _, err := s.Roles().ByID(ctx, doomed.ID, role.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("role survived: %v", err)
		}
		if _, err := s.Groups().ByID(ctx, doomed.ID, group.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("group survived: %v", err)
		}
		keys, err := s.Keys().ListByRealm(ctx, doomed.ID)
		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		if len(keys) != 0 {
			t.Fatalf("keys survived: %d", len(keys))
		}
		if _, err := s.Realms().ByName(ctx, "keep"); err != nil {
			t.Fatalf("the other realm went too: %v", err)
		}
	})

	t.Run("deleting a realm that is gone reports ErrNotFound", func(t *testing.T) {
		s := newStore(t)

		err := s.Realms().Delete(context.Background(), model.NewID())

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("the realm listing carries every realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		// Created out of alphabetical order deliberately. The listing's order
		// is not asserted - Keycloak's own is neither sorted nor by creation -
		// only that both drivers return the same set.
		for _, name := range []string{"zeta", "master", "alpha"} {
			if err := s.Realms().Create(ctx, &model.Realm{ID: model.NewID(), Name: name}); err != nil {
				t.Fatalf("Create %s: %v", name, err)
			}
		}

		got, err := s.Realms().List(ctx)
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		var names []string
		for _, r := range got {
			names = append(names, r.Name)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"alpha", "master", "zeta"}) {
			t.Fatalf("List = %v", names)
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

	t.Run("default groups add once, remove twice and follow the group", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		top := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"}
		other := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "other"}
		for _, g := range []*model.Group{top, other} {
			if err := s.Groups().Create(ctx, g); err != nil {
				t.Fatalf("Create(%q): %v", g.Name, err)
			}
		}

		// Adding the same group twice answers 204 twice and lists it once,
		// measured; the primary key is what makes that true without a read.
		for range 2 {
			if err := s.Groups().AddDefaultGroup(ctx, realm.ID, top.ID); err != nil {
				t.Fatalf("AddDefaultGroup: %v", err)
			}
		}
		if err := s.Groups().AddDefaultGroup(ctx, realm.ID, other.ID); err != nil {
			t.Fatalf("AddDefaultGroup(other): %v", err)
		}
		got, err := s.Groups().ListDefaultGroups(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListDefaultGroups: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want two default groups, got %d", len(got))
		}

		// Removing one that is not a default group is not an error, the way
		// RemoveMember is not - measured 204 on the second delete.
		for range 2 {
			if err := s.Groups().RemoveDefaultGroup(ctx, realm.ID, other.ID); err != nil {
				t.Fatalf("RemoveDefaultGroup: %v", err)
			}
		}

		// **Deleting the group takes the default-group row with it.** Measured:
		// a group deleted through the Groups API left the default-groups listing
		// with one fewer entry. The DDL says the cascade is there; this is what
		// says both drivers act on it.
		if err := s.Groups().Delete(ctx, realm.ID, top.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err = s.Groups().ListDefaultGroups(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListDefaultGroups after the delete: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("a deleted group is still a default group: %d rows", len(got))
		}
	})

	t.Run("a client scope round-trips with its attributes and mappers in order", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		want := &model.ClientScope{
			ID: model.NewID(), RealmID: realm.ID, Name: "probe",
			Description: "a probe scope", Protocol: "openid-connect",
			// Deliberately not alphabetical. A Go map here would come back
			// sorted and the representation would stop matching Keycloak's,
			// which is the whole reason model.StringMap exists.
			Attributes: model.StringMap{
				{Key: "include.in.token.scope", Value: "true"},
				{Key: "consent.screen.text", Value: "${x}"},
				{Key: "display.on.consent.screen", Value: "false"},
			},
			ProtocolMappers: []model.ProtocolMapper{{
				ID: model.NewID(), Name: "zeta", Protocol: "openid-connect",
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
				Config: model.StringMap{
					{Key: "introspection.token.claim", Value: "true"},
					{Key: "access.token.claim", Value: "true"},
				},
			}},
		}
		if err := s.ClientScopes().Create(ctx, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.ClientScopes().ByID(ctx, realm.ID, want.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round-trip:\n got %+v\nwant %+v", got, want)
		}
		byName, err := s.ClientScopes().ByName(ctx, realm.ID, "probe")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if byName.ID != want.ID {
			t.Errorf("ByName id = %q, want %q", byName.ID, want.ID)
		}
		if _, err := s.ClientScopes().ByID(ctx, realm.ID, model.NewID()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ByID(unknown) = %v, want ErrNotFound", err)
		}

		// A scope with no attributes and no mappers reads back with both
		// zero-valued rather than as an error: the representation turns the
		// first into `{}` and omits the second.
		bare := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID,
			Name: "bare", Protocol: "saml"}
		if err := s.ClientScopes().Create(ctx, bare); err != nil {
			t.Fatalf("Create(bare): %v", err)
		}
		gotBare, err := s.ClientScopes().ByID(ctx, realm.ID, bare.ID)
		if err != nil {
			t.Fatalf("ByID(bare): %v", err)
		}
		if len(gotBare.Attributes) != 0 || len(gotBare.ProtocolMappers) != 0 {
			t.Errorf("bare scope came back with %d attributes and %d mappers",
				len(gotBare.Attributes), len(gotBare.ProtocolMappers))
		}

		dup := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID, Name: "probe"}
		if err := s.ClientScopes().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate name = %v, want ErrConflict", err)
		}
	})

	t.Run("the realm's default client scopes keep their insertion order", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		// Added in an order that is neither alphabetical nor reverse, because
		// the listing's order is measured to be insertion order and nothing
		// else - ORDER BY name would pass a two-element test by accident.
		order := []string{"zeta", "alpha", "mid"}
		ids := map[string]string{}
		for _, name := range order {
			sc := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID,
				Name: name, Protocol: "openid-connect"}
			if err := s.ClientScopes().Create(ctx, sc); err != nil {
				t.Fatalf("Create(%q): %v", name, err)
			}
			ids[name] = sc.ID
			if err := s.ClientScopes().AddRealmDefault(ctx, realm.ID, sc.ID, true); err != nil {
				t.Fatalf("AddRealmDefault(%q): %v", name, err)
			}
		}
		got, err := s.ClientScopes().ListRealmDefaults(ctx, realm.ID, true)
		if err != nil {
			t.Fatalf("ListRealmDefaults: %v", err)
		}
		var names []string
		for _, sc := range got {
			names = append(names, sc.Name)
		}
		if !reflect.DeepEqual(names, order) {
			t.Errorf("realm defaults = %v, want %v", names, order)
		}

		// The two sets are one row with a flag: a repeat and a move to the
		// other list are both the measured 409.
		if err := s.ClientScopes().AddRealmDefault(ctx, realm.ID, ids["zeta"], true); !errors.Is(err, store.ErrConflict) {
			t.Errorf("adding twice = %v, want ErrConflict", err)
		}
		if err := s.ClientScopes().AddRealmDefault(ctx, realm.ID, ids["zeta"], false); !errors.Is(err, store.ErrConflict) {
			t.Errorf("adding to the other list = %v, want ErrConflict", err)
		}

		// The remove takes no list argument, because the measured DELETE
		// ignores the one its path names.
		if err := s.ClientScopes().RemoveRealmDefault(ctx, realm.ID, ids["alpha"]); err != nil {
			t.Fatalf("RemoveRealmDefault: %v", err)
		}
		if err := s.ClientScopes().RemoveRealmDefault(ctx, realm.ID, ids["alpha"]); err != nil {
			t.Fatalf("RemoveRealmDefault twice: %v", err)
		}
		got, err = s.ClientScopes().ListRealmDefaults(ctx, realm.ID, true)
		if err != nil {
			t.Fatalf("ListRealmDefaults after the remove: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want two defaults left, got %d", len(got))
		}

		// Deleting the scope takes the membership row with it.
		if err := s.ClientScopes().Delete(ctx, realm.ID, ids["zeta"]); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err = s.ClientScopes().ListRealmDefaults(ctx, realm.ID, true)
		if err != nil {
			t.Fatalf("ListRealmDefaults after the delete: %v", err)
		}
		if len(got) != 1 || got[0].Name != "mid" {
			t.Errorf("after deleting zeta the defaults are %v, want [mid]", got)
		}
	})

	t.Run("a client's scope names are derived from the attachment and survive a rename", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		sc := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID,
			Name: "email", Protocol: "openid-connect"}
		opt := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID,
			Name: "phone", Protocol: "openid-connect"}
		for _, x := range []*model.ClientScope{sc, opt} {
			if err := s.ClientScopes().Create(ctx, x); err != nil {
				t.Fatalf("Create(%q): %v", x.Name, err)
			}
		}

		// Create turns the names on the model into attachments; a name the
		// realm does not have is dropped rather than reported, measured.
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "probe",
			Protocol: "openid-connect", RedirectURIs: []string{}, WebOrigins: []string{},
			Attributes:           map[string]string{},
			DefaultClientScopes:  []string{"email", "nosuchscope"},
			OptionalClientScopes: []string{"phone"},
		}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		got, err := s.Clients().ByClientID(ctx, realm.ID, "probe")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}
		if !reflect.DeepEqual(got.DefaultClientScopes, []string{"email"}) {
			t.Errorf("defaults = %v, want [email]", got.DefaultClientScopes)
		}
		if !reflect.DeepEqual(got.OptionalClientScopes, []string{"phone"}) {
			t.Errorf("optionals = %v, want [phone]", got.OptionalClientScopes)
		}

		// **The attachment survives a rename**, which is the reason the names
		// are derived rather than stored: renaming a client scope was measured
		// changing the name in every client's list and keeping the attachment.
		sc.Name = "email2"
		if err := s.ClientScopes().Update(ctx, sc); err != nil {
			t.Fatalf("ClientScopes().Update: %v", err)
		}
		got, err = s.Clients().ByClientID(ctx, realm.ID, "probe")
		if err != nil {
			t.Fatalf("ByClientID after the rename: %v", err)
		}
		if !reflect.DeepEqual(got.DefaultClientScopes, []string{"email2"}) {
			t.Errorf("defaults after the rename = %v, want [email2]", got.DefaultClientScopes)
		}

		// Attaching twice, and attaching one already held in the other list,
		// are both measured no-ops answering 204.
		for range 2 {
			if err := s.ClientScopes().AddClientScope(ctx, c.ID, sc.ID, true); err != nil {
				t.Fatalf("AddClientScope: %v", err)
			}
		}
		if err := s.ClientScopes().AddClientScope(ctx, c.ID, opt.ID, true); err != nil {
			t.Fatalf("AddClientScope(the other list): %v", err)
		}
		got, err = s.Clients().ByClientID(ctx, realm.ID, "probe")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}
		if !reflect.DeepEqual(got.OptionalClientScopes, []string{"phone"}) {
			t.Errorf("attaching an optional as a default moved it: %v", got.OptionalClientScopes)
		}

		// Deleting the scope detaches it from the client.
		if err := s.ClientScopes().Delete(ctx, realm.ID, sc.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err = s.Clients().ByClientID(ctx, realm.ID, "probe")
		if err != nil {
			t.Fatalf("ByClientID after the delete: %v", err)
		}
		if len(got.DefaultClientScopes) != 0 {
			t.Errorf("a deleted scope is still attached: %v", got.DefaultClientScopes)
		}
	})

	t.Run("scope mappings round-trip on both containers and cascade with the role", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		sc := &model.ClientScope{ID: model.NewID(), RealmID: realm.ID,
			Name: "probe-scope", Protocol: "openid-connect"}
		if err := s.ClientScopes().Create(ctx, sc); err != nil {
			t.Fatalf("ClientScopes().Create: %v", err)
		}
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "probe",
			Protocol: "openid-connect", RedirectURIs: []string{}, WebOrigins: []string{},
			Attributes: map[string]string{}}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		rr := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: "realm-role"}
		cr := &model.Role{ID: model.NewID(), RealmID: realm.ID, ClientID: c.ID, Name: "client-role"}
		for _, role := range []*model.Role{rr, cr} {
			if err := s.Roles().Create(ctx, role); err != nil {
				t.Fatalf("Roles().Create(%q): %v", role.Name, err)
			}
		}

		// A container takes roles of either kind - measured: a client role
		// posted to .../scope-mappings/realm lands and reads back under the
		// client half of the combined view.
		for _, role := range []*model.Role{rr, cr} {
			if err := s.Roles().AddClientScopeScopeMapping(ctx, sc.ID, role.ID); err != nil {
				t.Fatalf("AddClientScopeScopeMapping(%q): %v", role.Name, err)
			}
			if err := s.Roles().AddClientScopeMapping(ctx, c.ID, role.ID); err != nil {
				t.Fatalf("AddClientScopeMapping(%q): %v", role.Name, err)
			}
		}
		// **Both adds are idempotent**, on both containers. A repeat is 204 and
		// not a conflict, so the store must not report one.
		if err := s.Roles().AddClientScopeScopeMapping(ctx, sc.ID, rr.ID); err != nil {
			t.Fatalf("AddClientScopeScopeMapping twice: %v", err)
		}
		if err := s.Roles().AddClientScopeMapping(ctx, c.ID, rr.ID); err != nil {
			t.Fatalf("AddClientScopeMapping twice: %v", err)
		}

		names := func(in []*model.Role) []string {
			out := make([]string, 0, len(in))
			for _, r := range in {
				out = append(out, r.Name)
			}
			return out
		}
		got, err := s.Roles().ListClientScopeScopeMappings(ctx, sc.ID)
		if err != nil {
			t.Fatalf("ListClientScopeScopeMappings: %v", err)
		}
		if !reflect.DeepEqual(names(got), []string{"client-role", "realm-role"}) {
			t.Errorf("the scope's mappings = %v, want [client-role realm-role]", names(got))
		}
		got, err = s.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			t.Fatalf("ListClientScopeMappings: %v", err)
		}
		if !reflect.DeepEqual(names(got), []string{"client-role", "realm-role"}) {
			t.Errorf("the client's mappings = %v, want [client-role realm-role]", names(got))
		}

		// **The two containers are separate rows.** Removing from one leaves
		// the other, which is what says the two tables are not one.
		if err := s.Roles().RemoveClientScopeScopeMapping(ctx, sc.ID, rr.ID); err != nil {
			t.Fatalf("RemoveClientScopeScopeMapping: %v", err)
		}
		got, err = s.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			t.Fatalf("ListClientScopeMappings after the scope's removal: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("removing from the scope changed the client: %v", names(got))
		}
		// **Both removes are idempotent** - a role that is not mapped is 204.
		if err := s.Roles().RemoveClientScopeScopeMapping(ctx, sc.ID, rr.ID); err != nil {
			t.Fatalf("RemoveClientScopeScopeMapping twice: %v", err)
		}
		if err := s.Roles().RemoveClientScopeMapping(ctx, c.ID, model.NewID()); err != nil {
			t.Fatalf("RemoveClientScopeMapping of a role never mapped: %v", err)
		}

		// **Deleting the role deletes the mapping**, measured on a live 26.7.1:
		// a mapped realm role deleted through DELETE /roles/{name} left the
		// scope answering one fewer. That cascade is the reason these are tables
		// with a foreign key rather than a JSON column on the container.
		if err := s.Roles().Delete(ctx, realm.ID, cr.ID); err != nil {
			t.Fatalf("Roles().Delete: %v", err)
		}
		got, err = s.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			t.Fatalf("ListClientScopeMappings after the role delete: %v", err)
		}
		if !reflect.DeepEqual(names(got), []string{"realm-role"}) {
			t.Errorf("the deleted role survives in the mappings: %v", names(got))
		}
		got, err = s.Roles().ListClientScopeScopeMappings(ctx, sc.ID)
		if err != nil {
			t.Fatalf("ListClientScopeScopeMappings after the role delete: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("the deleted role survives on the scope: %v", names(got))
		}

		// **The cascade itself**, which the two assertions above cannot see: the
		// listings JOIN keycloak_role, so a mapping row left behind by a deleted
		// role is invisible to them and dropping the foreign key changes no read.
		// A mutation removing `ON DELETE CASCADE` survived exactly there.
		//
		// Reusing the id is what makes it observable. A role id is a fresh UUID
		// in every path that mints one, so this can only be reached through the
		// store - which is the level the constraint lives at. With the cascade
		// the row went with the old role and the new one starts unmapped;
		// without it the orphan resurfaces under a role that was never mapped.
		reborn := &model.Role{ID: cr.ID, RealmID: realm.ID, ClientID: c.ID, Name: "reborn"}
		if err := s.Roles().Create(ctx, reborn); err != nil {
			t.Fatalf("Roles().Create reusing the deleted id: %v", err)
		}
		got, err = s.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			t.Fatalf("ListClientScopeMappings after the id was reused: %v", err)
		}
		if !reflect.DeepEqual(names(got), []string{"realm-role"}) {
			t.Errorf("a mapping outlived the role that carried it: %v", names(got))
		}
		// Both tables, because they are two tables: a mutation dropping the
		// foreign key from one of them survived a check that read the other.
		got, err = s.Roles().ListClientScopeScopeMappings(ctx, sc.ID)
		if err != nil {
			t.Fatalf("ListClientScopeScopeMappings after the id was reused: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("a scope's mapping outlived the role that carried it: %v", names(got))
		}
	})

	// ProtocolMapperOwner takes no realm, and that absence is the measurement:
	// a protocol mapper id is unique across the **server**, so a client scope
	// created in one realm carrying an id already in use in another is a 409.
	// A driver that added a realm filter would pass every other case in this
	// suite and every conformance case that stays inside one realm.
	t.Run("a protocol mapper id is found across realms and across containers", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		home := newRealm(t, s)
		away := &model.Realm{ID: model.NewID(), Name: "away", Enabled: true}
		if err := s.Realms().Create(ctx, away); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}

		scopeMapperID, clientMapperID := model.NewID(), model.NewID()
		scope := &model.ClientScope{
			ID: model.NewID(), RealmID: away.ID, Name: "probe-scope", Protocol: "openid-connect",
			ProtocolMappers: []model.ProtocolMapper{{
				ID: scopeMapperID, Name: "probe-scope-mapper", Protocol: "openid-connect",
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
			}},
		}
		if err := s.ClientScopes().Create(ctx, scope); err != nil {
			t.Fatalf("ClientScopes().Create: %v", err)
		}
		client := &model.Client{
			ID: model.NewID(), RealmID: away.ID, ClientID: "probe-client", Enabled: true,
			ProtocolMappers: []model.ProtocolMapper{{
				ID: clientMapperID, Name: "probe-client-mapper", Protocol: "openid-connect",
				ProtocolMapper: "oidc-usermodel-attribute-mapper",
			}},
		}
		if err := s.Clients().Create(ctx, client); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}

		// Both lookups are made from a session that knows only about `home`,
		// which is what a create in another realm would be doing.
		_ = home
		if got, err := s.ClientScopes().ProtocolMapperOwner(ctx, scopeMapperID); err != nil || got != scope.ID {
			t.Errorf("ClientScopes().ProtocolMapperOwner = %q, %v; want %q", got, err, scope.ID)
		}
		if got, err := s.Clients().ProtocolMapperOwner(ctx, clientMapperID); err != nil || got != client.ID {
			t.Errorf("Clients().ProtocolMapperOwner = %q, %v; want %q", got, err, client.ID)
		}

		// The two containers do not see each other's ids, which is why a caller
		// asking whether an id is free has to ask both.
		if _, err := s.Clients().ProtocolMapperOwner(ctx, scopeMapperID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Clients() found a client scope's mapper: %v", err)
		}
		if _, err := s.ClientScopes().ProtocolMapperOwner(ctx, clientMapperID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ClientScopes() found a client's mapper: %v", err)
		}
		if _, err := s.ClientScopes().ProtocolMapperOwner(ctx, model.NewID()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an id nothing holds: want ErrNotFound, got %v", err)
		}

		// A container with no mappers at all is an empty JSON array rather than
		// a NULL, and the scan has to survive it.
		bare := &model.ClientScope{
			ID: model.NewID(), RealmID: home.ID, Name: "probe-bare", Protocol: "openid-connect",
		}
		if err := s.ClientScopes().Create(ctx, bare); err != nil {
			t.Fatalf("ClientScopes().Create bare: %v", err)
		}
		if got, err := s.ClientScopes().ProtocolMapperOwner(ctx, scopeMapperID); err != nil || got != scope.ID {
			t.Errorf("after a mapper-less scope: got %q, %v; want %q", got, err, scope.ID)
		}
	})

	// The required actions have one column no other table in this schema has:
	// a **nullable** string whose NULL and whose empty value are two different
	// observable answers on the wire. That is the place two drivers are most
	// able to disagree, and it is the reason this block exists rather than the
	// package being trusted because it compiles.
	t.Run("required actions round-trip, including a null name and an empty alias", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		name := "Configure OTP"
		empty := ""

		rows := []*model.RequiredActionProvider{
			// A name that is set, out of priority order on purpose.
			{ID: model.NewID(), RealmID: realm.ID, Alias: "CONFIGURE_TOTP",
				Name: &name, ProviderID: "CONFIGURE_TOTP", Enabled: true, Priority: 54,
				Config: model.StringMap{{Key: "zzz", Value: "1"}, {Key: "aaa", Value: "2"}}},
			// A name that was never set. It must come back nil and not "".
			{ID: model.NewID(), RealmID: realm.ID, Alias: "UPDATE_EMAIL",
				ProviderID: "UPDATE_EMAIL", Priority: 70},
			// A name explicitly set to the empty string. It must come back ""
			// and not nil - the whole reason the column is nullable.
			{ID: model.NewID(), RealmID: realm.ID, Alias: "VERIFY_EMAIL",
				Name: &empty, ProviderID: "VERIFY_EMAIL", DefaultAction: true, Priority: 50},
			// The orphan a PUT with an empty body leaves: no alias at all.
			{ID: model.NewID(), RealmID: realm.ID, ProviderID: "VERIFY_PROFILE"},
		}
		for _, m := range rows {
			if err := s.RequiredActions().Create(ctx, m); err != nil {
				t.Fatalf("Create %q: %v", m.Alias, err)
			}
		}

		got, err := s.RequiredActions().ListByRealm(ctx, realm.ID)
		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		wantOrder := []string{"", "VERIFY_EMAIL", "CONFIGURE_TOTP", "UPDATE_EMAIL"}
		var gotOrder []string
		for _, m := range got {
			gotOrder = append(gotOrder, m.Alias)
		}
		if !slices.Equal(gotOrder, wantOrder) {
			t.Errorf("ListByRealm order: got %v, want %v", gotOrder, wantOrder)
		}

		byAlias := func(alias string) *model.RequiredActionProvider {
			t.Helper()
			m, err := s.RequiredActions().ByAlias(ctx, realm.ID, alias)
			if err != nil {
				t.Fatalf("ByAlias(%q): %v", alias, err)
			}
			return m
		}
		if m := byAlias("UPDATE_EMAIL"); m.Name != nil {
			t.Errorf("a name never set came back %q, want nil", *m.Name)
		}
		if m := byAlias("VERIFY_EMAIL"); m.Name == nil || *m.Name != "" {
			t.Errorf("a name set to the empty string came back nil")
		} else if !m.DefaultAction || m.Enabled {
			t.Errorf("the two flags did not round-trip: %+v", m)
		}
		// The orphan is addressable by the empty alias, which is how the listing
		// can hold a row no alias route reaches.
		if m := byAlias(""); m.ProviderID != "VERIFY_PROFILE" {
			t.Errorf("the empty alias resolved to %q", m.ProviderID)
		}
		// The config's key order is the contract, so a driver that stored it as
		// a structured type and sorted the keys has to fail here.
		if m := byAlias("CONFIGURE_TOTP"); len(m.Config) != 2 ||
			m.Config[0].Key != "zzz" || m.Config[1].Key != "aaa" {
			t.Errorf("config key order: %v", m.Config)
		}

		// Update writes every column, provider_id included: which fields an API
		// request may move is internal/admin's decision, not this layer's.
		m := byAlias("UPDATE_EMAIL")
		m.Alias = "renamed"
		m.ProviderID = "moved"
		m.Priority = 1
		m.Config = model.StringMap{{Key: "k", Value: "v"}}
		if err := s.RequiredActions().Update(ctx, m); err != nil {
			t.Fatalf("Update: %v", err)
		}
		back := byAlias("renamed")
		if back.ProviderID != "moved" || back.Priority != 1 || len(back.Config) != 1 {
			t.Errorf("Update did not write every column: %+v", back)
		}
		if _, err := s.RequiredActions().ByAlias(ctx, realm.ID, "UPDATE_EMAIL"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the old alias still resolves: %v", err)
		}

		if err := s.RequiredActions().Delete(ctx, realm.ID, back.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := s.RequiredActions().ByAlias(ctx, realm.ID, "renamed"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("after Delete: want ErrNotFound, got %v", err)
		}
		if err := s.RequiredActions().Delete(ctx, realm.ID, back.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete of a gone row: want ErrNotFound, got %v", err)
		}
		if err := s.RequiredActions().Update(ctx, back); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update of a gone row: want ErrNotFound, got %v", err)
		}
		if _, err := s.RequiredActions().ByAlias(ctx, realm.ID, "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ByAlias of nothing: want ErrNotFound, got %v", err)
		}
		// A realm with none at all is an empty slice rather than a nil one, so
		// the handler's `[]` does not become `null`.
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		if err := s.Realms().Create(ctx, other); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		if rows, err := s.RequiredActions().ListByRealm(ctx, other.ID); err != nil || rows == nil || len(rows) != 0 {
			t.Errorf("an empty realm: got %v, %v; want a non-nil empty slice", rows, err)
		}
	})

	t.Run("an organization round-trips with its domains and attributes", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID,
			Name: "probe-org", Alias: "probe-alias", Enabled: true,
			Description: strPtr("desc"), RedirectURL: "http://x/",
			Domains: []model.OrganizationDomain{
				{Name: "b.example.com", Verified: true},
				{Name: "a.example.com"},
			},
			Attributes: []model.OrganizationAttribute{
				{Name: "zz", Values: []string{"one", "two"}},
				{Name: "aa", Values: []string{"three"}},
			},
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Organizations().Create: %v", err)
		}
		back, err := s.Organizations().ByID(ctx, realm.ID, org.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if !reflect.DeepEqual(back, org) {
			t.Errorf("round-trip:\n got %+v\nwant %+v", back, org)
		}
		// The order the values arrived in, not the order a map would give:
		// `zz` before `aa` and `one` before `two`. Sorting either would be
		// invisible to a test that only counted them.
		if got := []string{back.Attributes[0].Name, back.Attributes[1].Name}; !slices.Equal(got, []string{"zz", "aa"}) {
			t.Errorf("attribute order: got %v, want [zz aa]", got)
		}
		if got := back.Domains[0].Name; got != "b.example.com" {
			t.Errorf("domain order: got %q first, want b.example.com", got)
		}
	})

	t.Run("the organization listing is sorted by name in byte order", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		// Created out of order, and with a capital, because the measured
		// listing put `UPPER` before `aaa-org`: the comparison is not folded.
		for _, name := range []string{"zzz-org", "aaa-org", "UPPER", "mmm-org"} {
			o := &model.Organization{ID: model.NewID(), RealmID: realm.ID, Name: name, Alias: name, Enabled: true}
			if err := s.Organizations().Create(ctx, o); err != nil {
				t.Fatalf("Create %q: %v", name, err)
			}
		}
		rows, err := s.Organizations().List(ctx, realm.ID)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var got []string
		for _, o := range rows {
			got = append(got, o.Name)
		}
		if want := []string{"UPPER", "aaa-org", "mmm-org", "zzz-org"}; !slices.Equal(got, want) {
			t.Errorf("List order: got %v, want %v", got, want)
		}
	})

	t.Run("name and alias collide separately, and a domain resolves realm-wide", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		first := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID, Name: "one", Alias: "one-alias", Enabled: true,
			Domains: []model.OrganizationDomain{{Name: "shared.example.com"}},
		}
		if err := s.Organizations().Create(ctx, first); err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Two constraints rather than one, because the handler answers the two
		// collisions with sentences that differ by a full stop and has to know
		// which fired.
		sameName := &model.Organization{ID: model.NewID(), RealmID: realm.ID, Name: "one", Alias: "other", Enabled: true}
		if err := s.Organizations().Create(ctx, sameName); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate name: want ErrConflict, got %v", err)
		}
		sameAlias := &model.Organization{ID: model.NewID(), RealmID: realm.ID, Name: "other", Alias: "one-alias", Enabled: true}
		if err := s.Organizations().Create(ctx, sameAlias); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate alias: want ErrConflict, got %v", err)
		}

		// The domain lookup is case-insensitive and reaches across the realm,
		// which is what lets the create name the *other* organization in its
		// refusal.
		held, err := s.Organizations().ByDomain(ctx, realm.ID, "SHARED.example.com")
		if err != nil {
			t.Fatalf("ByDomain: %v", err)
		}
		if held.Name != "one" {
			t.Errorf("ByDomain: got %q, want one", held.Name)
		}
		if _, err := s.Organizations().ByDomain(ctx, realm.ID, "absent.example.com"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ByDomain of nothing: want ErrNotFound, got %v", err)
		}
	})

	t.Run("update replaces the children and leaves the alias alone", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID, Name: "before", Alias: "keep-me", Enabled: true,
			Description: strPtr("d"), RedirectURL: "u",
			Domains:    []model.OrganizationDomain{{Name: "old.example.com"}},
			Attributes: []model.OrganizationAttribute{{Name: "k", Values: []string{"v"}}},
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Create: %v", err)
		}
		// A PUT was measured renaming the organization, clearing description,
		// redirectUrl and the domains, and **refusing** an alias change - so
		// Update writes everything but the alias, and the alias it is handed
		// is ignored rather than trusted.
		// Description goes back to nil rather than to "": a PUT that names no
		// description clears the key, and a PUT naming an empty one keeps it.
		org.Name, org.Alias, org.Description, org.RedirectURL = "after", "ignored", nil, ""
		org.Domains = nil
		org.Attributes = nil
		if err := s.Organizations().Update(ctx, org); err != nil {
			t.Fatalf("Update: %v", err)
		}
		back, err := s.Organizations().ByID(ctx, realm.ID, org.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if back.Name != "after" {
			t.Errorf("name: got %q, want after", back.Name)
		}
		if back.Alias != "keep-me" {
			t.Errorf("alias: got %q, want keep-me - Update must not write it", back.Alias)
		}
		if len(back.Domains) != 0 || len(back.Attributes) != 0 {
			t.Errorf("children survived the replace: %+v", back)
		}
		if back.Description != nil || back.RedirectURL != "" {
			t.Errorf("cleared fields survived: %+v", back)
		}
		// An empty description is **not** the same state as no description,
		// which is the whole reason the column is nullable.
		empty := ""
		org.Description = &empty
		if err := s.Organizations().Update(ctx, org); err != nil {
			t.Fatalf("Update with an empty description: %v", err)
		}
		back, err = s.Organizations().ByID(ctx, realm.ID, org.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if back.Description == nil || *back.Description != "" {
			t.Errorf("empty description: got %v, want a pointer to \"\"", back.Description)
		}
	})

	t.Run("an organization is scoped to its realm and cascades with it", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		if err := s.Realms().Create(ctx, other); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID, Name: "scoped", Alias: "scoped", Enabled: true,
			Domains: []model.OrganizationDomain{{Name: "d.example.com"}},
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := s.Organizations().ByID(ctx, other.ID, org.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cross-realm read: want ErrNotFound, got %v", err)
		}
		if err := s.Organizations().Delete(ctx, other.ID, org.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cross-realm delete: want ErrNotFound, got %v", err)
		}
		if rows, err := s.Organizations().List(ctx, other.ID); err != nil || rows == nil || len(rows) != 0 {
			t.Errorf("an empty realm: got %v, %v; want a non-nil empty slice", rows, err)
		}
		// Deleting twice is a 404 on the wire, so the second Delete has to
		// report ErrNotFound rather than succeeding quietly.
		if err := s.Organizations().Delete(ctx, realm.ID, org.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.Organizations().Delete(ctx, realm.ID, org.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second Delete: want ErrNotFound, got %v", err)
		}
		if err := s.Organizations().Update(ctx, org); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update of a gone row: want ErrNotFound, got %v", err)
		}
	})

	// The authorization services family. Its whole point is that the row's
	// existence is the client's authorizationServicesEnabled flag, so every
	// assertion here is about a client representation as much as about a
	// resource server - and the flag is read through ClientRepo, which is the
	// half a driver can get wrong while AuthzRepo looks right.
	t.Run("a resource server row is the client's authorizationServicesEnabled flag", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		client := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "authz-client", Enabled: true}
		if err := s.Clients().Create(ctx, client); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}

		// No row: the flag is off on all three client reads. All three are
		// checked because the subquery is written out three times.
		assertFlag := func(what string, want bool) {
			t.Helper()
			byID, err := s.Clients().ByID(ctx, realm.ID, client.ID)
			if err != nil {
				t.Fatalf("%s ByID: %v", what, err)
			}
			if byID.AuthorizationServicesEnabled != want {
				t.Errorf("%s ByID: flag = %v, want %v", what, byID.AuthorizationServicesEnabled, want)
			}
			byClientID, err := s.Clients().ByClientID(ctx, realm.ID, client.ClientID)
			if err != nil {
				t.Fatalf("%s ByClientID: %v", what, err)
			}
			if byClientID.AuthorizationServicesEnabled != want {
				t.Errorf("%s ByClientID: flag = %v, want %v", what, byClientID.AuthorizationServicesEnabled, want)
			}
			listed, err := s.Clients().ListByRealm(ctx, realm.ID)
			if err != nil {
				t.Fatalf("%s ListByRealm: %v", what, err)
			}
			for _, c := range listed {
				if c.ID == client.ID && c.AuthorizationServicesEnabled != want {
					t.Errorf("%s ListByRealm: flag = %v, want %v", what, c.AuthorizationServicesEnabled, want)
				}
			}
		}
		assertFlag("before Upsert", false)
		if _, err := s.Authz().ByClientID(ctx, client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ByClientID with no row: want ErrNotFound, got %v", err)
		}

		if err := s.Authz().Upsert(ctx, model.DefaultAuthzResourceServer(client.ID)); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		assertFlag("after Upsert", true)
		got, err := s.Authz().ByClientID(ctx, client.ID)
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}
		if want := model.DefaultAuthzResourceServer(client.ID); *got != *want {
			t.Errorf("defaults: got %+v, want %+v", *got, *want)
		}

		// Upsert twice replaces rather than conflicting, and it moves all
		// three columns. AllowRemoteResourceManagement goes true -> false so a
		// driver that stored a constant is caught.
		changed := &model.AuthzResourceServer{
			ClientID:                      client.ID,
			AllowRemoteResourceManagement: false,
			PolicyEnforcementMode:         "PERMISSIVE",
			DecisionStrategy:              "AFFIRMATIVE",
		}
		if err := s.Authz().Upsert(ctx, changed); err != nil {
			t.Fatalf("second Upsert: %v", err)
		}
		got, err = s.Authz().ByClientID(ctx, client.ID)
		if err != nil {
			t.Fatalf("ByClientID after replace: %v", err)
		}
		if *got != *changed {
			t.Errorf("after replace: got %+v, want %+v", *got, *changed)
		}
		assertFlag("after replace", true)

		// Delete turns the flag off and is idempotent - the second call is not
		// ErrNotFound, because PUT /clients/{uuid} answers 204 both times.
		if err := s.Authz().DeleteByClientID(ctx, client.ID); err != nil {
			t.Fatalf("DeleteByClientID: %v", err)
		}
		assertFlag("after delete", false)
		if err := s.Authz().DeleteByClientID(ctx, client.ID); err != nil {
			t.Errorf("second DeleteByClientID: want nil, got %v", err)
		}

		// The row cascades with the client, which is what makes the flag
		// impossible to strand: a deleted client cannot leave a resource
		// server behind for a client that reuses its id.
		if err := s.Authz().Upsert(ctx, model.DefaultAuthzResourceServer(client.ID)); err != nil {
			t.Fatalf("Upsert before cascade: %v", err)
		}
		if err := s.Clients().Delete(ctx, realm.ID, client.ID); err != nil {
			t.Fatalf("Clients().Delete: %v", err)
		}
		if _, err := s.Authz().ByClientID(ctx, client.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("after the client is deleted: want ErrNotFound, got %v", err)
		}
	})

	// The scope half of AuthzRepo. The assertion that matters most is the
	// **order**: ListScopes has to come back in creation order, because
	// GET .../settings serves that and GET .../scope sorts by name above this
	// layer. A driver that added an ORDER BY name would make the listing look
	// right and the export wrong, and only this subtest and one golden can see
	// it.
	t.Run("authorization scopes keep creation order and are scoped per resource server", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		mk := func(clientID string) *model.Client {
			t.Helper()
			c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: clientID, Enabled: true}
			if err := s.Clients().Create(ctx, c); err != nil {
				t.Fatalf("Clients().Create %s: %v", clientID, err)
			}
			if err := s.Authz().Upsert(ctx, model.DefaultAuthzResourceServer(c.ID)); err != nil {
				t.Fatalf("Upsert %s: %v", clientID, err)
			}
			return c
		}
		one, two := mk("authz-scope-one"), mk("authz-scope-two")

		if got, err := s.Authz().ListScopes(ctx, one.ID); err != nil || len(got) != 0 {
			t.Fatalf("ListScopes on an empty resource server: got %v, %v", got, err)
		}

		// Created in the reverse of name order on purpose: this is the
		// measured shape - zulu, yankee, xray, whiskey came back that way from
		// the export - and a sorted ListScopes passes a suite that creates
		// them alphabetically.
		names := []string{"zulu", "yankee", "xray", "whiskey"}
		ids := map[string]string{}
		for _, n := range names {
			sc := &model.AuthzScope{ID: model.NewID(), ClientID: one.ID, Name: n}
			if err := s.Authz().CreateScope(ctx, sc); err != nil {
				t.Fatalf("CreateScope %s: %v", n, err)
			}
			ids[n] = sc.ID
		}
		assertOrder := func(what string, want []string) {
			t.Helper()
			got, err := s.Authz().ListScopes(ctx, one.ID)
			if err != nil {
				t.Fatalf("%s ListScopes: %v", what, err)
			}
			var names []string
			for _, sc := range got {
				names = append(names, sc.Name)
			}
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Errorf("%s: order %v, want %v", what, names, want)
			}
		}
		assertOrder("after four creates", names)

		// A name another resource server holds is not a conflict, and its id
		// is invisible from here. Both measured: `alpha` exists in two
		// resource servers at once, and one server's scope id read through the
		// other is a 404.
		shared := &model.AuthzScope{ID: model.NewID(), ClientID: two.ID, Name: "zulu"}
		if err := s.Authz().CreateScope(ctx, shared); err != nil {
			t.Errorf("CreateScope of a name the other resource server holds: %v", err)
		}
		if _, err := s.Authz().ScopeByID(ctx, one.ID, shared.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ScopeByID across resource servers: want ErrNotFound, got %v", err)
		}
		if _, err := s.Authz().ScopeByName(ctx, one.ID, "nothing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ScopeByName miss: want ErrNotFound, got %v", err)
		}

		// A name this resource server already holds is ErrConflict, which is
		// what internal/admin turns into the 409.
		dup := &model.AuthzScope{ID: model.NewID(), ClientID: one.ID, Name: "zulu"}
		if err := s.Authz().CreateScope(ctx, dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("CreateScope of a duplicate name: want ErrConflict, got %v", err)
		}

		// An update replaces the three fields and leaves the ordinal alone.
		got, err := s.Authz().ScopeByID(ctx, one.ID, ids["xray"])
		if err != nil {
			t.Fatalf("ScopeByID: %v", err)
		}
		got.Name, got.IconURI, got.DisplayName = "xray-renamed", "http://i/x", "X"
		if err := s.Authz().UpdateScope(ctx, got); err != nil {
			t.Fatalf("UpdateScope: %v", err)
		}
		back, err := s.Authz().ScopeByName(ctx, one.ID, "xray-renamed")
		if err != nil {
			t.Fatalf("ScopeByName after update: %v", err)
		}
		if back.IconURI != "http://i/x" || back.DisplayName != "X" || back.ID != ids["xray"] {
			t.Errorf("after update: %+v", back)
		}
		assertOrder("after a rename", []string{"zulu", "yankee", "xray-renamed", "whiskey"})

		// Delete reports ErrNotFound for a scope this resource server does not
		// have - unlike DeleteByClientID, which is idempotent, because the two
		// answer different measured statuses: an unknown scope is a 404 and a
		// repeated flag-off is a 204.
		if err := s.Authz().DeleteScope(ctx, one.ID, ids["xray"]); err != nil {
			t.Fatalf("DeleteScope: %v", err)
		}
		if err := s.Authz().DeleteScope(ctx, one.ID, ids["xray"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second DeleteScope: want ErrNotFound, got %v", err)
		}
		if err := s.Authz().DeleteScope(ctx, one.ID, shared.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteScope across resource servers: want ErrNotFound, got %v", err)
		}

		// A recreated scope goes to the **end** of the export's order, not
		// back to where it was. Measured by deleting xray and recreating it.
		again := &model.AuthzScope{ID: model.NewID(), ClientID: one.ID, Name: "xray"}
		if err := s.Authz().CreateScope(ctx, again); err != nil {
			t.Fatalf("CreateScope after delete: %v", err)
		}
		assertOrder("after delete and recreate", []string{"zulu", "yankee", "whiskey", "xray"})

		// The scopes cascade with the resource server, which cascades with the
		// client. Turning the flag off destroys the settings, measured, and it
		// has to destroy the scopes with them.
		if err := s.Authz().DeleteByClientID(ctx, one.ID); err != nil {
			t.Fatalf("DeleteByClientID: %v", err)
		}
		if got, err := s.Authz().ListScopes(ctx, one.ID); err != nil || len(got) != 0 {
			t.Errorf("after the flag goes off: got %v, %v", got, err)
		}
		// The other resource server is untouched by that.
		if got, err := s.Authz().ListScopes(ctx, two.ID); err != nil || len(got) != 1 {
			t.Errorf("the neighbouring resource server: got %v, %v", got, err)
		}
	})

	// The resource half of AuthzRepo. Three things here are the assertions and
	// the rest is round-tripping:
	//
	//   - **ListResources comes back in creation order**, for ListScopes'
	//     reason on a second family: GET .../settings serves that order and
	//     GET .../resource sorts by name above this layer.
	//   - **URIs and Attributes keep the order they were given.** The two were
	//     measured chaining in opposite directions inside one Java collection
	//     each, so neither can be recovered from a sort and neither can be
	//     recovered from the other. A driver that returned them in primary-key
	//     order would pass every test that creates them alphabetically.
	//   - **A resource id is global and a resource name is per resource
	//     server**, which is what makes the cross-server lookups a not-found
	//     and the same name in two servers a success.
	t.Run("authorization resources keep creation order and their two collection orders", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		mk := func(clientID string) *model.Client {
			t.Helper()
			c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: clientID, Enabled: true}
			if err := s.Clients().Create(ctx, c); err != nil {
				t.Fatalf("Clients().Create %s: %v", clientID, err)
			}
			if err := s.Authz().Upsert(ctx, model.DefaultAuthzResourceServer(c.ID)); err != nil {
				t.Fatalf("Upsert %s: %v", clientID, err)
			}
			return c
		}
		one, two := mk("authz-res-one"), mk("authz-res-two")

		if got, err := s.Authz().ListResources(ctx, one.ID); err != nil || len(got) != 0 {
			t.Fatalf("ListResources on an empty resource server: got %v, %v", got, err)
		}

		scope := &model.AuthzScope{ID: model.NewID(), ClientID: one.ID, Name: "sc"}
		if err := s.Authz().CreateScope(ctx, scope); err != nil {
			t.Fatalf("CreateScope: %v", err)
		}

		// Created in the reverse of name order, for the reason the scope
		// subtest above gives.
		names := []string{"zulu", "yankee", "xray"}
		ids := map[string]string{}
		for _, n := range names {
			res := &model.AuthzResource{ID: model.NewID(), ClientID: one.ID, Name: n}
			if err := s.Authz().CreateResource(ctx, res); err != nil {
				t.Fatalf("CreateResource %s: %v", n, err)
			}
			ids[n] = res.ID
		}
		assertOrder := func(what string, want []string) {
			t.Helper()
			got, err := s.Authz().ListResources(ctx, one.ID)
			if err != nil {
				t.Fatalf("ListResources %s: %v", what, err)
			}
			have := make([]string, 0, len(got))
			for _, res := range got {
				have = append(have, res.Name)
			}
			if !slices.Equal(have, want) {
				t.Errorf("ListResources %s: got %v, want %v", what, have, want)
			}
		}
		assertOrder("after the creates", names)

		// The two collection orders. `/z, /a, /m` and `zz, aa, mm` are given
		// in an order that is neither sorted nor reverse-sorted, so a driver
		// that sorted either would be caught whichever direction it sorted in.
		full := &model.AuthzResource{
			ID: model.NewID(), ClientID: one.ID, Name: "full",
			DisplayName: "Full", Type: "urn:t", IconURI: "http://i",
			OwnerManagedAccess: true,
			URIs:               []string{"/z", "/a", "/m"},
			Attributes: []model.AuthzResourceAttribute{
				{Name: "zz", Values: []string{"1", "2"}},
				{Name: "aa", Values: []string{"3"}},
				{Name: "mm", Values: []string{"4"}},
			},
			ScopeIDs: []string{scope.ID},
		}
		if err := s.Authz().CreateResource(ctx, full); err != nil {
			t.Fatalf("CreateResource full: %v", err)
		}
		back, err := s.Authz().ResourceByID(ctx, one.ID, full.ID)
		if err != nil {
			t.Fatalf("ResourceByID: %v", err)
		}
		if !slices.Equal(back.URIs, []string{"/z", "/a", "/m"}) {
			t.Errorf("URIs: got %v, want the order they were written in", back.URIs)
		}
		if len(back.Attributes) != 3 ||
			back.Attributes[0].Name != "zz" || back.Attributes[1].Name != "aa" ||
			back.Attributes[2].Name != "mm" {
			t.Errorf("Attributes: got %v, want zz, aa, mm", back.Attributes)
		}
		if !slices.Equal(back.Attributes[0].Values, []string{"1", "2"}) {
			t.Errorf("a multivalued attribute: got %v", back.Attributes[0].Values)
		}
		if !slices.Equal(back.ScopeIDs, []string{scope.ID}) {
			t.Errorf("ScopeIDs: got %v, want %v", back.ScopeIDs, []string{scope.ID})
		}
		if back.DisplayName != "Full" || back.Type != "urn:t" || back.IconURI != "http://i" ||
			!back.OwnerManagedAccess {
			t.Errorf("the flat fields did not round-trip: %+v", back)
		}

		// A name is unique **per resource server** and an id is global.
		if err := s.Authz().CreateResource(ctx,
			&model.AuthzResource{ID: model.NewID(), ClientID: two.ID, Name: "zulu"}); err != nil {
			t.Fatalf("the same name in a second resource server: %v", err)
		}
		if err := s.Authz().CreateResource(ctx,
			&model.AuthzResource{ID: model.NewID(), ClientID: one.ID, Name: "zulu"}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a duplicate name: want ErrConflict, got %v", err)
		}
		if err := s.Authz().CreateResource(ctx,
			&model.AuthzResource{ID: ids["zulu"], ClientID: two.ID, Name: "borrowed"}); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a duplicate id across resource servers: want ErrConflict, got %v", err)
		}
		if _, err := s.Authz().ResourceByID(ctx, two.ID, ids["zulu"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResourceByID across resource servers: want ErrNotFound, got %v", err)
		}
		if _, err := s.Authz().ResourceByName(ctx, one.ID, "nothing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ResourceByName on a name nobody holds: want ErrNotFound, got %v", err)
		}

		// The update replaces the children outright and leaves the ordinal
		// alone. `full` was created fourth and stays fourth.
		full.Name = "full-renamed"
		full.URIs = []string{"/only"}
		full.Attributes = nil
		full.ScopeIDs = nil
		if err := s.Authz().UpdateResource(ctx, full); err != nil {
			t.Fatalf("UpdateResource: %v", err)
		}
		back, err = s.Authz().ResourceByName(ctx, one.ID, "full-renamed")
		if err != nil {
			t.Fatalf("ResourceByName after the update: %v", err)
		}
		if !slices.Equal(back.URIs, []string{"/only"}) || len(back.Attributes) != 0 ||
			len(back.ScopeIDs) != 0 {
			t.Errorf("the update did not replace the children: %+v", back)
		}
		assertOrder("after the update", append(slices.Clone(names), "full-renamed"))

		if err := s.Authz().UpdateResource(ctx,
			&model.AuthzResource{ID: "nobody", ClientID: one.ID, Name: "x"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdateResource on an id nobody holds: want ErrNotFound, got %v", err)
		}
		if err := s.Authz().DeleteResource(ctx, one.ID, ids["xray"]); err != nil {
			t.Fatalf("DeleteResource: %v", err)
		}
		if err := s.Authz().DeleteResource(ctx, one.ID, ids["xray"]); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteResource twice: want ErrNotFound, got %v", err)
		}

		// Deleting a scope takes the link with it and leaves the resource.
		linked := &model.AuthzResource{
			ID: model.NewID(), ClientID: one.ID, Name: "linked", ScopeIDs: []string{scope.ID},
		}
		if err := s.Authz().CreateResource(ctx, linked); err != nil {
			t.Fatalf("CreateResource linked: %v", err)
		}
		if err := s.Authz().DeleteScope(ctx, one.ID, scope.ID); err != nil {
			t.Fatalf("DeleteScope: %v", err)
		}
		got, err := s.Authz().ResourceByID(ctx, one.ID, linked.ID)
		if err != nil {
			t.Fatalf("ResourceByID after the scope went: %v", err)
		}
		if len(got.ScopeIDs) != 0 {
			t.Errorf("a deleted scope left a link behind: %v", got.ScopeIDs)
		}

		// The resources cascade with the resource server, which cascades with
		// the client - authz_scope's argument one table along.
		if err := s.Authz().DeleteByClientID(ctx, one.ID); err != nil {
			t.Fatalf("DeleteByClientID: %v", err)
		}
		if got, err := s.Authz().ListResources(ctx, one.ID); err != nil || len(got) != 0 {
			t.Errorf("after the flag goes off: got %v, %v", got, err)
		}
		if got, err := s.Authz().ListResources(ctx, two.ID); err != nil || len(got) != 1 {
			t.Errorf("the neighbouring resource server: got %v, %v", got, err)
		}
	})

	// The policy half of AuthzRepo. Four things here are the assertions and the
	// rest is round-tripping:
	//
	//   - **ListPolicies comes back in creation order**, for ListScopes' and
	//     ListResources' reason on a third family: GET .../settings serves that
	//     order - with the resource and scope rows moved to the end - and the
	//     two listings sort by name above this layer.
	//   - **Config keeps the order it was given.** It is a Java map whose wire
	//     order internal/admin computes from the arrival order, so a driver
	//     returning it in primary-key order would pass every test that writes
	//     it alphabetically. `zz` is written first here for exactly that.
	//   - **The three association sets stay apart and stay ordered.** They are
	//     one table with a `kind` column, so a driver that dropped the column
	//     from the read would merge all three into whichever slice it filled
	//     first.
	//   - **A policy id is global and a policy name is per resource server**,
	//     which is what makes the cross-server lookup a not-found, the same
	//     name in two servers a success, and the same id in two servers a
	//     conflict.
	t.Run("authorization policies keep creation order, config order and three association sets", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		mk := func(clientID string) *model.Client {
			t.Helper()
			c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: clientID, Enabled: true}
			if err := s.Clients().Create(ctx, c); err != nil {
				t.Fatalf("Clients().Create %s: %v", clientID, err)
			}
			if err := s.Authz().Upsert(ctx, model.DefaultAuthzResourceServer(c.ID)); err != nil {
				t.Fatalf("Upsert %s: %v", clientID, err)
			}
			return c
		}
		one, two := mk("authz-pol-one"), mk("authz-pol-two")

		if got, err := s.Authz().ListPolicies(ctx, one.ID); err != nil || len(got) != 0 {
			t.Fatalf("ListPolicies on an empty resource server: got %v, %v", got, err)
		}

		scope := &model.AuthzScope{ID: model.NewID(), ClientID: one.ID, Name: "psc"}
		if err := s.Authz().CreateScope(ctx, scope); err != nil {
			t.Fatalf("CreateScope: %v", err)
		}
		res := &model.AuthzResource{ID: model.NewID(), ClientID: one.ID, Name: "pres"}
		if err := s.Authz().CreateResource(ctx, res); err != nil {
			t.Fatalf("CreateResource: %v", err)
		}

		// Created in the reverse of name order, for the reason the two
		// subtests above give.
		names := []string{"zulu", "yankee", "xray"}
		ids := map[string]string{}
		for _, n := range names {
			p := &model.AuthzPolicy{
				ID: model.NewID(), ClientID: one.ID, Name: n, Type: "role",
				Logic:            model.DefaultAuthzPolicyLogic,
				DecisionStrategy: model.DefaultAuthzPolicyDecisionStrategy,
			}
			ids[n] = p.ID
			if err := s.Authz().CreatePolicy(ctx, p); err != nil {
				t.Fatalf("CreatePolicy %s: %v", n, err)
			}
		}
		assertOrder := func(what string, want []string) {
			t.Helper()
			got, err := s.Authz().ListPolicies(ctx, one.ID)
			if err != nil {
				t.Fatalf("ListPolicies %s: %v", what, err)
			}
			have := make([]string, 0, len(got))
			for _, p := range got {
				have = append(have, p.Name)
			}
			if !slices.Equal(have, want) {
				t.Errorf("ListPolicies %s: got %v, want %v", what, have, want)
			}
		}
		assertOrder("after the creates", names)

		// A policy carrying everything: a config written out of alphabetical
		// order and all three association sets at once.
		full := &model.AuthzPolicy{
			ID: model.NewID(), ClientID: one.ID, Name: "full", Description: "D",
			Type: "resource", Logic: "NEGATIVE", DecisionStrategy: "AFFIRMATIVE",
			Owner: "someone",
			Config: []model.AuthzPolicyConfig{
				{Name: "zz", Value: "1"},
				{Name: "aa", Value: "2"},
				{Name: "roles", Value: `[{"id":"r","required":false}]`},
			},
			AssociatedPolicies: []string{ids["zulu"], ids["yankee"]},
			Resources:          []string{res.ID},
			Scopes:             []string{scope.ID},
		}
		if err := s.Authz().CreatePolicy(ctx, full); err != nil {
			t.Fatalf("CreatePolicy full: %v", err)
		}
		got, err := s.Authz().PolicyByID(ctx, one.ID, full.ID)
		if err != nil {
			t.Fatalf("PolicyByID: %v", err)
		}
		if got.Description != "D" || got.Logic != "NEGATIVE" ||
			got.DecisionStrategy != "AFFIRMATIVE" || got.Owner != "someone" {
			t.Errorf("scalar round-trip: got %+v", got)
		}
		if len(got.Config) != 3 || got.Config[0].Name != "zz" ||
			got.Config[1].Name != "aa" || got.Config[2].Name != "roles" {
			t.Errorf("config order: got %v, want zz, aa, roles", got.Config)
		}
		if !slices.Equal(got.AssociatedPolicies, []string{ids["zulu"], ids["yankee"]}) {
			t.Errorf("associated policies: got %v", got.AssociatedPolicies)
		}
		if !slices.Equal(got.Resources, []string{res.ID}) {
			t.Errorf("associated resources: got %v", got.Resources)
		}
		if !slices.Equal(got.Scopes, []string{scope.ID}) {
			t.Errorf("associated scopes: got %v", got.Scopes)
		}

		// A name is per resource server and an id is global.
		shared := &model.AuthzPolicy{
			ID: model.NewID(), ClientID: two.ID, Name: "zulu", Type: "role",
			Logic: "POSITIVE", DecisionStrategy: "UNANIMOUS",
		}
		if err := s.Authz().CreatePolicy(ctx, shared); err != nil {
			t.Fatalf("the same name in a second resource server: %v", err)
		}
		if _, err := s.Authz().PolicyByID(ctx, one.ID, shared.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a policy id read through another resource server: want ErrNotFound, got %v", err)
		}
		if _, err := s.Authz().PolicyByName(ctx, one.ID, "nothing"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PolicyByName on a name nobody holds: want ErrNotFound, got %v", err)
		}
		dupName := &model.AuthzPolicy{
			ID: model.NewID(), ClientID: one.ID, Name: "zulu", Type: "role",
			Logic: "POSITIVE", DecisionStrategy: "UNANIMOUS",
		}
		if err := s.Authz().CreatePolicy(ctx, dupName); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a taken name in one resource server: want ErrConflict, got %v", err)
		}
		dupID := &model.AuthzPolicy{
			ID: ids["zulu"], ClientID: two.ID, Name: "elsewhere", Type: "role",
			Logic: "POSITIVE", DecisionStrategy: "UNANIMOUS",
		}
		if err := s.Authz().CreatePolicy(ctx, dupID); !errors.Is(err, store.ErrConflict) {
			t.Errorf("an id another resource server holds: want ErrConflict, got %v", err)
		}

		// The update replaces every field and every child row, and leaves the
		// ordinal where it was - which is what the import's merge needs.
		got.Name = "full-renamed"
		got.Config = []model.AuthzPolicyConfig{{Name: "only", Value: "x"}}
		got.AssociatedPolicies = nil
		got.Scopes = nil
		if err := s.Authz().UpdatePolicy(ctx, got); err != nil {
			t.Fatalf("UpdatePolicy: %v", err)
		}
		back, err := s.Authz().PolicyByName(ctx, one.ID, "full-renamed")
		if err != nil {
			t.Fatalf("PolicyByName after the update: %v", err)
		}
		if len(back.Config) != 1 || back.Config[0].Name != "only" {
			t.Errorf("config after the update: got %v", back.Config)
		}
		if len(back.AssociatedPolicies) != 0 || len(back.Scopes) != 0 || len(back.Resources) != 1 {
			t.Errorf("associations after the update: %v %v %v",
				back.AssociatedPolicies, back.Resources, back.Scopes)
		}
		assertOrder("after the update", append(slices.Clone(names), "full-renamed"))

		if err := s.Authz().UpdatePolicy(ctx,
			&model.AuthzPolicy{ID: "nobody", ClientID: one.ID, Name: "x"}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("UpdatePolicy on an id nobody holds: want ErrNotFound, got %v", err)
		}

		// The policies cascade with the resource server, which cascades with
		// the client - authz_scope's argument two tables along.
		if err := s.Authz().DeleteByClientID(ctx, one.ID); err != nil {
			t.Fatalf("DeleteByClientID: %v", err)
		}
		if got, err := s.Authz().ListPolicies(ctx, one.ID); err != nil || len(got) != 0 {
			t.Errorf("after the flag goes off: got %v, %v", got, err)
		}
		if got, err := s.Authz().ListPolicies(ctx, two.ID); err != nil || len(got) != 1 {
			t.Errorf("the neighbouring resource server: got %v, %v", got, err)
		}
	})

	t.Run("an identity provider round-trips, alias and all", func(t *testing.T) {
		ctx := context.Background()
		s := newStore(t)
		realm := newRealm(t, s)
		yes, no := true, false

		full := &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID, Alias: strPtr("full"),
			DisplayName: "Full", ProviderID: "oidc", Enabled: true,
			TrustEmail: &yes, StoreToken: &no, LinkOnly: &yes,
			FirstBrokerLoginFlowAlias: "first broker login",
			Config: []model.IdentityProviderConfigEntry{
				{Name: "clientId", Value: "cid"},
				{Name: "clientSecret", Value: "secret"},
			},
		}
		if err := s.IdentityProviders().Create(ctx, full); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.IdentityProviders().ByAlias(ctx, realm.ID, "full")
		if err != nil {
			t.Fatalf("ByAlias: %v", err)
		}
		// **The three flag states have to survive separately.** A driver that
		// stored them as plain booleans reads back three falses here and
		// nothing else in this file notices.
		if got.TrustEmail == nil || !*got.TrustEmail {
			t.Errorf("trustEmail: got %v, want true", got.TrustEmail)
		}
		if got.StoreToken == nil || *got.StoreToken {
			t.Errorf("storeToken: got %v, want false", got.StoreToken)
		}
		if got.HideOnLogin != nil {
			t.Errorf("hideOnLogin: got %v, want nil - absent is not false", got.HideOnLogin)
		}
		if len(got.Config) != 2 || got.Config[0].Name != "clientId" || got.Config[1].Value != "secret" {
			t.Errorf("config round-trip: got %v", got.Config)
		}

		// The alias is unique within the realm and the conflict is what the
		// measured 409 rests on.
		dup := &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID, Alias: strPtr("full"),
			ProviderID: "oidc", Enabled: true,
		}
		if err := s.IdentityProviders().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
			t.Errorf("duplicate alias: want ErrConflict, got %v", err)
		}

		// **The update replaces, and it writes the alias away.** That is the
		// state Keycloak's own PUT reaches with a body carrying no alias, so
		// the driver has to be able to reach it too.
		full.Alias = nil
		full.DisplayName = ""
		full.TrustEmail = nil
		full.Config = nil
		if err := s.IdentityProviders().Update(ctx, full); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if _, err := s.IdentityProviders().ByAlias(ctx, realm.ID, "full"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the old alias after the update: want ErrNotFound, got %v", err)
		}

		// The listing sorts by alias and puts the aliasless row first, which is
		// where the server puts it. Postgres sorts NULLs last by default, so
		// this is the assertion the two drivers would otherwise differ on
		// without either failing to compile.
		for _, alias := range []string{"zzz", "aaa", "mmm"} {
			p := &model.IdentityProvider{
				InternalID: model.NewID(), RealmID: realm.ID, Alias: strPtr(alias),
				ProviderID: "oidc", Enabled: true,
			}
			if err := s.IdentityProviders().Create(ctx, p); err != nil {
				t.Fatalf("Create %s: %v", alias, err)
			}
		}
		list, err := s.IdentityProviders().List(ctx, realm.ID)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var order []string
		for _, p := range list {
			if p.Alias == nil {
				order = append(order, "<none>")
				continue
			}
			order = append(order, *p.Alias)
		}
		want := []string{"<none>", "aaa", "mmm", "zzz"}
		if len(order) != len(want) {
			t.Fatalf("listing: got %v, want %v", order, want)
		}
		for i := range want {
			if order[i] != want[i] {
				t.Fatalf("listing: got %v, want %v", order, want)
			}
		}

		if err := s.IdentityProviders().Delete(ctx, realm.ID, "aaa"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.IdentityProviders().Delete(ctx, realm.ID, "aaa"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the second Delete: want ErrNotFound, got %v", err)
		}
	})

	t.Run("a component round-trips with its multivalued config", func(t *testing.T) {
		ctx := context.Background()
		s := newStore(t)
		realm := newRealm(t, s)

		named := &model.Component{
			ID: model.NewID(), RealmID: realm.ID, Name: strPtr("rsa-enc-generated"),
			ProviderID: "rsa-enc-generated", ProviderType: "org.keycloak.keys.KeyProvider",
			ParentID: realm.ID,
			Config: []model.ComponentConfigEntry{
				{Name: "priority", Values: []string{"100"}},
				{Name: "algorithm", Values: []string{"RSA-OAEP"}},
			},
		}
		// The nameless one, which is the only observable difference between an
		// absent name and an empty one this family has.
		nameless := &model.Component{
			ID: model.NewID(), RealmID: realm.ID,
			ProviderID: "declarative-user-profile", ProviderType: "org.keycloak.userprofile.UserProfileProvider",
			ParentID: realm.ID,
		}
		// A multivalued entry, which is what separates this config from an
		// identity provider's.
		multi := &model.Component{
			ID: model.NewID(), RealmID: realm.ID, Name: strPtr("Allowed Protocol Mapper Types"),
			ProviderID:   "allowed-protocol-mappers",
			ProviderType: "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
			ParentID:     realm.ID, SubType: "anonymous",
			Config: []model.ComponentConfigEntry{
				{Name: "allowed-protocol-mapper-types", Values: []string{"a", "b", "c"}},
			},
		}
		for _, c := range []*model.Component{named, nameless, multi} {
			if err := s.Components().Create(ctx, c); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		got, err := s.Components().ByID(ctx, realm.ID, named.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.Name == nil || *got.Name != "rsa-enc-generated" {
			t.Errorf("name: got %v", got.Name)
		}
		if len(got.Config) != 2 || got.Config[0].Name != "priority" ||
			got.Config[1].Values[0] != "RSA-OAEP" {
			t.Errorf("config: got %v", got.Config)
		}

		if got, err := s.Components().ByID(ctx, realm.ID, nameless.ID); err != nil || got.Name != nil {
			t.Errorf("the nameless component: got %v, %v - absent is not empty", got, err)
		}
		if got, err := s.Components().ByID(ctx, realm.ID, multi.ID); err != nil ||
			len(got.Config) != 1 || len(got.Config[0].Values) != 3 ||
			got.Config[0].Values[2] != "c" {
			t.Errorf("the multivalued config: got %v, %v", got, err)
		}

		if _, err := s.Components().ByID(ctx, realm.ID, "gloak-probe-nosuch"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("an unknown component: want ErrNotFound, got %v", err)
		}
		// The realm's own id is a parentId and not a component id.
		if _, err := s.Components().ByID(ctx, realm.ID, realm.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the realm as a component: want ErrNotFound, got %v", err)
		}

		// The listing is in the order the rows were written, which is what
		// makes a driver deterministic where the server is not.
		list, err := s.Components().List(ctx, realm.ID)
		if err != nil || len(list) != 3 {
			t.Fatalf("List: %v, %v", list, err)
		}
		if list[0].ID != named.ID || list[1].ID != nameless.ID || list[2].ID != multi.ID {
			t.Errorf("the listing is not in creation order")
		}
	})

	t.Run("an identity provider mapper is listed by alias and found without one", func(t *testing.T) {
		ctx := context.Background()
		s := newStore(t)
		realm := newRealm(t, s)

		// The names and the ids differ from each other on purpose: a repo that
		// looked one up by the other would pass a fixture that used one string
		// for both, and this project has lost four mutations to exactly that.
		under := &model.IdentityProviderMapper{
			ID: "11111111-1111-1111-1111-111111111111", RealmID: realm.ID,
			Alias: "gloak-probe-broker-one", Name: "gloak-probe-mapper-alpha",
			Mapper: "oidc-hardcoded-role-idp-mapper",
			Config: []model.IdentityProviderMapperConfigEntry{
				{Name: "zz", Value: "1"},
				{Name: "aa", Value: "2"},
				{Name: "mm", Value: "3"},
			},
		}
		second := &model.IdentityProviderMapper{
			ID: "22222222-2222-2222-2222-222222222222", RealmID: realm.ID,
			Alias: "gloak-probe-broker-one", Name: "gloak-probe-mapper-beta",
			Mapper: "oidc-username-idp-mapper",
		}
		elsewhere := &model.IdentityProviderMapper{
			ID: "33333333-3333-3333-3333-333333333333", RealmID: realm.ID,
			Alias: "gloak-probe-broker-two", Name: "gloak-probe-mapper-gamma",
			Mapper: "oidc-username-idp-mapper",
		}
		for _, m := range []*model.IdentityProviderMapper{under, second, elsewhere} {
			if err := s.IdentityProviderMappers().Create(ctx, m); err != nil {
				t.Fatalf("Create: %v", err)
			}
		}

		// The same name under a second alias is fine; the same name under the
		// same alias is the measured conflict.
		clash := &model.IdentityProviderMapper{
			ID: model.NewID(), RealmID: realm.ID,
			Alias: "gloak-probe-broker-one", Name: "gloak-probe-mapper-alpha",
			Mapper: "oidc-username-idp-mapper",
		}
		if err := s.IdentityProviderMappers().Create(ctx, clash); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a repeated name under one alias: want ErrConflict, got %v", err)
		}

		// The config keeps the order it was handed, which is what
		// javamap.SizedKeyOrder needs: those three keys share a bucket and the
		// insertion order is the only thing that decides them.
		got, err := s.IdentityProviderMappers().ByID(ctx, realm.ID, under.ID)
		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if len(got.Config) != 3 || got.Config[0].Name != "zz" ||
			got.Config[1].Name != "aa" || got.Config[2].Name != "mm" {
			t.Errorf("config order: got %v", got.Config)
		}
		if got.Name != "gloak-probe-mapper-alpha" || got.Alias != "gloak-probe-broker-one" ||
			got.Mapper != "oidc-hardcoded-role-idp-mapper" {
			t.Errorf("round trip: got %+v", got)
		}

		// **ByID takes no alias**, and this is the assertion that says so: the
		// mapper of one broker is found while its own listing has one row.
		if _, err := s.IdentityProviderMappers().ByID(ctx, realm.ID, elsewhere.ID); err != nil {
			t.Errorf("a mapper of another alias: want it found, got %v", err)
		}
		list, err := s.IdentityProviderMappers().List(ctx, realm.ID, "gloak-probe-broker-one")
		if err != nil || len(list) != 2 {
			t.Fatalf("List: %v, %v", list, err)
		}
		if list[0].ID != under.ID || list[1].ID != second.ID {
			t.Errorf("the listing is not in creation order: got %v, %v", list[0].ID, list[1].ID)
		}
		if list, err := s.IdentityProviderMappers().List(ctx, realm.ID, "gloak-probe-broker-nosuch"); err != nil || len(list) != 0 {
			t.Errorf("an alias with no mappers: want an empty list, got %v, %v", list, err)
		}

		// Update replaces, config included, and it can set an alias no
		// provider has - both measured on the server.
		under.Alias = "gloak-probe-broker-stranded"
		under.Name = "gloak-probe-mapper-alpha-renamed"
		under.Config = []model.IdentityProviderMapperConfigEntry{{Name: "only", Value: "9"}}
		if err := s.IdentityProviderMappers().Update(ctx, under); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, err = s.IdentityProviderMappers().ByID(ctx, realm.ID, under.ID)
		if err != nil || len(got.Config) != 1 || got.Config[0].Name != "only" ||
			got.Alias != "gloak-probe-broker-stranded" {
			t.Errorf("after Update: got %+v, %v", got, err)
		}
		if list, err := s.IdentityProviderMappers().List(ctx, realm.ID, "gloak-probe-broker-one"); err != nil || len(list) != 1 {
			t.Errorf("the old alias should have lost a row: got %v, %v", list, err)
		}

		missing := &model.IdentityProviderMapper{
			ID: "44444444-4444-4444-4444-444444444444", RealmID: realm.ID,
			Alias: "gloak-probe-broker-one", Name: "gloak-probe-mapper-delta",
		}
		if err := s.IdentityProviderMappers().Update(ctx, missing); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Update of a mapper that does not exist: want ErrNotFound, got %v", err)
		}
		if _, err := s.IdentityProviderMappers().ByID(ctx, realm.ID, missing.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ByID of a mapper that does not exist: want ErrNotFound, got %v", err)
		}
		if err := s.IdentityProviderMappers().Delete(ctx, realm.ID, second.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := s.IdentityProviderMappers().Delete(ctx, realm.ID, second.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the second Delete: want ErrNotFound, got %v", err)
		}
	})

	// An organization's members. A member is a user and nothing else, so the
	// two things a driver can get wrong here are the ordering and the two
	// cascades - and the cascades point in opposite directions, which is what
	// the last third of this subtest is about.
	t.Run("organization members are users, ordered by username, and cascade both ways", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)

		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID,
			Name: "gloak-probe-members-org", Alias: "gloak-probe-members-alias", Enabled: true,
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Organizations().Create: %v", err)
		}
		other := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID,
			Name: "gloak-probe-members-other", Alias: "gloak-probe-members-other-alias", Enabled: true,
		}
		if err := s.Organizations().Create(ctx, other); err != nil {
			t.Fatalf("Organizations().Create: %v", err)
		}

		// Created zzz, aaa, mmm so that insertion order and username order
		// disagree - and given e-mail addresses that sort the **other** way, so
		// that a driver ordering by e-mail is caught too.
		//
		// The second half is not decoration. This subtest carried
		// `name + "@members.example.com"` until a mutation swapping the ORDER BY
		// to `u.email` survived it: one string was doing the work of two, which
		// is the shape of hole AGENTS.md records swallowing four survivors in
		// three cuts.
		emails := map[string]string{
			"gloak-probe-zzz": "aaa@members.example.com",
			"gloak-probe-aaa": "zzz@members.example.com",
			"gloak-probe-mmm": "mmm@members.example.com",
		}
		users := map[string]*model.User{}
		for _, name := range []string{"gloak-probe-zzz", "gloak-probe-aaa", "gloak-probe-mmm"} {
			u := &model.User{
				ID: model.NewID(), RealmID: realm.ID, Username: name,
				Email: emails[name], Enabled: true,
			}
			if err := s.Users().Create(ctx, u); err != nil {
				t.Fatalf("Users().Create %s: %v", name, err)
			}
			users[name] = u
			if err := s.Organizations().AddMember(ctx, org.ID, u.ID); err != nil {
				t.Fatalf("AddMember %s: %v", name, err)
			}
		}

		members, err := s.Organizations().Members(ctx, org.ID)
		if err != nil {
			t.Fatalf("Members: %v", err)
		}
		var got []string
		for _, m := range members {
			got = append(got, m.Username)
		}
		want := []string{"gloak-probe-aaa", "gloak-probe-mmm", "gloak-probe-zzz"}
		if !slices.Equal(got, want) {
			t.Errorf("Members order: got %v, want %v", got, want)
		}
		// The rows are whole users, not ids: the member representation is a
		// user representation and a driver returning bare ids would compile.
		// The e-mail asserted here is the one that sorts **last**, which is the
		// other half of the ORDER BY assertion.
		if members[0].Email != "zzz@members.example.com" {
			t.Errorf("Members should carry the whole user: got %+v", members[0])
		}

		if err := s.Organizations().AddMember(ctx, org.ID, users["gloak-probe-aaa"].ID); !errors.Is(err, store.ErrConflict) {
			t.Errorf("a repeated AddMember: want ErrConflict, got %v", err)
		}
		if ok, err := s.Organizations().IsMember(ctx, org.ID, users["gloak-probe-aaa"].ID); err != nil || !ok {
			t.Errorf("IsMember of a member: got %v, %v", ok, err)
		}
		if ok, err := s.Organizations().IsMember(ctx, other.ID, users["gloak-probe-aaa"].ID); err != nil || ok {
			t.Errorf("IsMember of another organization: got %v, %v", ok, err)
		}
		if ok, err := s.Organizations().IsMember(ctx, org.ID, "00000000-0000-4000-8000-000000000000"); err != nil || ok {
			t.Errorf("IsMember of a stranger: got %v, %v", ok, err)
		}

		// One user in two organizations, so MemberOf cannot pass by returning
		// whatever single row it found.
		if err := s.Organizations().AddMember(ctx, other.ID, users["gloak-probe-aaa"].ID); err != nil {
			t.Fatalf("AddMember to the second organization: %v", err)
		}
		orgs, err := s.Organizations().MemberOf(ctx, realm.ID, users["gloak-probe-aaa"].ID)
		if err != nil || len(orgs) != 2 {
			t.Fatalf("MemberOf: got %v, %v; want two", orgs, err)
		}
		if orgs[0].Name != "gloak-probe-members-org" || orgs[1].Name != "gloak-probe-members-other" {
			t.Errorf("MemberOf order: got %s, %s", orgs[0].Name, orgs[1].Name)
		}
		if rows, err := s.Organizations().MemberOf(ctx, realm.ID, users["gloak-probe-mmm"].ID); err != nil || len(rows) != 1 {
			t.Errorf("MemberOf of a single-organization member: got %v, %v", rows, err)
		}

		if err := s.Organizations().RemoveMember(ctx, org.ID, users["gloak-probe-mmm"].ID); err != nil {
			t.Fatalf("RemoveMember: %v", err)
		}
		if err := s.Organizations().RemoveMember(ctx, org.ID, users["gloak-probe-mmm"].ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the second RemoveMember: want ErrNotFound, got %v", err)
		}
		// The user survives the removal - a member delete is 204 and the user
		// still reads 200.
		if _, err := s.Users().ByID(ctx, realm.ID, users["gloak-probe-mmm"].ID); err != nil {
			t.Errorf("the user should outlive the membership: %v", err)
		}

		// Deleting the user takes the membership with it.
		if err := s.Users().Delete(ctx, realm.ID, users["gloak-probe-zzz"].ID); err != nil {
			t.Fatalf("Users().Delete: %v", err)
		}
		if rows, err := s.Organizations().Members(ctx, org.ID); err != nil || len(rows) != 1 {
			t.Errorf("after deleting a user: got %v, %v; want one member", rows, err)
		}
		// Deleting the organization takes the memberships with it.
		if err := s.Organizations().Delete(ctx, realm.ID, other.ID); err != nil {
			t.Fatalf("Organizations().Delete: %v", err)
		}
		if rows, err := s.Organizations().MemberOf(ctx, realm.ID, users["gloak-probe-aaa"].ID); err != nil || len(rows) != 1 {
			t.Errorf("after deleting an organization: got %v, %v; want one", rows, err)
		}
	})

	// An organization's identity providers are a column on the provider, so
	// the two things to assert are that the filter reads that column and that
	// Update leaves it alone.
	t.Run("an identity provider carries its organization and keeps it across an update", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID,
			Name: "gloak-probe-broker-org", Alias: "gloak-probe-broker-org-alias", Enabled: true,
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Organizations().Create: %v", err)
		}

		linked := &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID,
			Alias: strPtr("gloak-probe-linked"), ProviderID: "oidc", Enabled: true,
			Config: []model.IdentityProviderConfigEntry{{Name: "clientId", Value: "c"}},
		}
		loose := &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID,
			Alias: strPtr("gloak-probe-loose"), ProviderID: "oidc", Enabled: true,
		}
		for _, p := range []*model.IdentityProvider{linked, loose} {
			if err := s.IdentityProviders().Create(ctx, p); err != nil {
				t.Fatalf("IdentityProviders().Create: %v", err)
			}
		}
		// A provider created carrying the organization keeps it, which is the
		// create path POST /identity-provider/instances takes.
		withOrg := &model.IdentityProvider{
			InternalID: model.NewID(), RealmID: realm.ID,
			Alias: strPtr("gloak-probe-born-linked"), ProviderID: "oidc", Enabled: true,
			OrganizationID: org.ID,
		}
		if err := s.IdentityProviders().Create(ctx, withOrg); err != nil {
			t.Fatalf("Create with an organization: %v", err)
		}

		if err := s.IdentityProviders().SetOrganization(ctx, realm.ID, "gloak-probe-linked", org.ID); err != nil {
			t.Fatalf("SetOrganization: %v", err)
		}
		got, err := s.IdentityProviders().ByAlias(ctx, realm.ID, "gloak-probe-linked")
		if err != nil || got.OrganizationID != org.ID {
			t.Errorf("ByAlias after SetOrganization: got %+v, %v", got, err)
		}
		if unlinked, err := s.IdentityProviders().ByAlias(ctx, realm.ID, "gloak-probe-loose"); err != nil || unlinked.OrganizationID != "" {
			t.Errorf("an unassociated provider: got %+v, %v", unlinked, err)
		}

		list, err := s.IdentityProviders().ListByOrganization(ctx, realm.ID, org.ID)
		if err != nil || len(list) != 2 {
			t.Fatalf("ListByOrganization: got %v, %v; want two", list, err)
		}
		if *list[0].Alias != "gloak-probe-born-linked" || *list[1].Alias != "gloak-probe-linked" {
			t.Errorf("ListByOrganization order: got %s, %s", *list[0].Alias, *list[1].Alias)
		}
		if list[1].Config == nil || list[1].Config[0].Name != "clientId" {
			t.Errorf("ListByOrganization should load the config: got %+v", list[1].Config)
		}

		// The update replaces everything else and must not clear the column:
		// a PUT on an associated provider was measured keeping it while
		// emptying the config beside it.
		got.Config = nil
		got.DisplayName = "touched"
		got.OrganizationID = ""
		if err := s.IdentityProviders().Update(ctx, got); err != nil {
			t.Fatalf("Update: %v", err)
		}
		after, err := s.IdentityProviders().ByAlias(ctx, realm.ID, "gloak-probe-linked")
		if err != nil || after.OrganizationID != org.ID || after.DisplayName != "touched" {
			t.Errorf("after Update: got %+v, %v", after, err)
		}

		if err := s.IdentityProviders().SetOrganization(ctx, realm.ID, "gloak-probe-linked", ""); err != nil {
			t.Fatalf("SetOrganization to nothing: %v", err)
		}
		if rows, err := s.IdentityProviders().ListByOrganization(ctx, realm.ID, org.ID); err != nil || len(rows) != 1 {
			t.Errorf("after clearing one: got %v, %v; want one", rows, err)
		}
		if err := s.IdentityProviders().SetOrganization(ctx, realm.ID, "gloak-probe-nosuch", org.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SetOrganization on an alias that does not exist: want ErrNotFound, got %v", err)
		}
		if rows, err := s.IdentityProviders().ListByOrganization(ctx, realm.ID, "00000000-0000-4000-8000-000000000000"); err != nil || len(rows) != 0 {
			t.Errorf("an organization with no providers: got %v, %v", rows, err)
		}
	})

	// ---- P12 third cut: an organization's groups.
	//
	// The names, the ids and the order they are created in are all deliberately
	// different: the groups are created `zzz, aaa, mmm` and the assertions read
	// the *first* row, so a driver returning insertion order fails where one
	// ordering by name passes. Five mutation survivors in four cuts were tests
	// using one string for two things.
	t.Run("an organization's groups are hidden from the realm tree and sorted by name", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := newRealm(t, s)
		org := &model.Organization{
			ID: model.NewID(), RealmID: realm.ID,
			Name: "gloak-probe-og-groups", Alias: "gloak-probe-og-groups-alias", Enabled: true,
		}
		if err := s.Organizations().Create(ctx, org); err != nil {
			t.Fatalf("Organizations().Create: %v", err)
		}
		root := &model.Group{
			ID: model.NewID(), RealmID: realm.ID, Name: org.ID, OrganizationID: org.ID,
		}
		if err := s.Groups().Create(ctx, root); err != nil {
			t.Fatalf("creating the root: %v", err)
		}
		// A realm group beside them, so every "hidden" assertion below has
		// something it is allowed to see.
		outsider := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "gloak-probe-outsider"}
		if err := s.Groups().Create(ctx, outsider); err != nil {
			t.Fatalf("creating the realm group: %v", err)
		}

		ids := map[string]string{}
		for _, name := range []string{"gloak-probe-zzz", "gloak-probe-aaa", "gloak-probe-mmm"} {
			g := &model.Group{
				ID: model.NewID(), RealmID: realm.ID, ParentID: root.ID,
				Name: name, OrganizationID: org.ID,
			}
			if err := s.Groups().Create(ctx, g); err != nil {
				t.Fatalf("creating %s: %v", name, err)
			}
			ids[name] = g.ID
		}

		// The realm's own three reads see the outsider and nothing else.
		tops, err := s.Groups().ListTopLevel(ctx, realm.ID)
		if err != nil || len(tops) != 1 || tops[0].ID != outsider.ID {
			t.Errorf("ListTopLevel: got %v, %v; want only the realm group", tops, err)
		}
		all, err := s.Groups().ListAll(ctx, realm.ID)
		if err != nil || len(all) != 1 || all[0].ID != outsider.ID {
			t.Errorf("ListAll: got %v, %v; want only the realm group", all, err)
		}

		// The organization's own read sees the three and **not** the root.
		orgAll, err := s.Groups().ListOrganizationAll(ctx, realm.ID, org.ID)
		if err != nil || len(orgAll) != 3 {
			t.Fatalf("ListOrganizationAll: got %v, %v; want three", orgAll, err)
		}
		if orgAll[0].Name != "gloak-probe-aaa" {
			t.Errorf("ListOrganizationAll order: got %s first, want gloak-probe-aaa", orgAll[0].Name)
		}
		for _, g := range orgAll {
			if g.OrganizationID != org.ID {
				t.Errorf("%s: organization %q, want %q", g.Name, g.OrganizationID, org.ID)
			}
		}

		gotRoot, err := s.Groups().OrganizationRoot(ctx, realm.ID, org.ID)
		if err != nil || gotRoot.ID != root.ID {
			t.Errorf("OrganizationRoot: got %v, %v; want %s", gotRoot, err, root.ID)
		}
		if _, err := s.Groups().OrganizationRoot(ctx, realm.ID, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OrganizationRoot of an organization with none: want ErrNotFound, got %v", err)
		}

		// Move puts one under another, and the ancestry follows it.
		if err := s.Groups().Move(ctx, realm.ID, ids["gloak-probe-mmm"], ids["gloak-probe-aaa"]); err != nil {
			t.Fatalf("Move: %v", err)
		}
		chain, err := s.Groups().Ancestry(ctx, realm.ID, ids["gloak-probe-mmm"])
		if err != nil || len(chain) != 3 || chain[0].ID != root.ID || chain[1].ID != ids["gloak-probe-aaa"] {
			t.Errorf("Ancestry after Move: got %v, %v", chain, err)
		}
		// The move survives the round trip: the row itself carries the parent.
		moved, err := s.Groups().ByID(ctx, realm.ID, ids["gloak-probe-mmm"])
		if err != nil || moved.ParentID != ids["gloak-probe-aaa"] {
			t.Errorf("after Move: got %+v, %v", moved, err)
		}
		if err := s.Groups().Move(ctx, realm.ID, "00000000-0000-4000-8000-000000000000", root.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Move of a group that does not exist: want ErrNotFound, got %v", err)
		}

		// A membership of an organization group is invisible to the realm's
		// listing and visible to everything that does not filter - which is
		// what makes the count and the listing disagree one layer up.
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "gloak-probe-og-member"}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		if err := s.Groups().AddMember(ctx, ids["gloak-probe-zzz"], u.ID); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		held, err := s.Groups().ListUserGroups(ctx, realm.ID, u.ID)
		if err != nil || len(held) != 1 || held[0].ID != ids["gloak-probe-zzz"] {
			t.Errorf("ListUserGroups: got %v, %v; want the organization group", held, err)
		}

		// Deleting the root takes the subtree and leaves the realm group.
		if err := s.Groups().Delete(ctx, realm.ID, root.ID); err != nil {
			t.Fatalf("Delete the root: %v", err)
		}
		if left, err := s.Groups().ListOrganizationAll(ctx, realm.ID, org.ID); err != nil || len(left) != 0 {
			t.Errorf("after deleting the root: got %v, %v; want none", left, err)
		}
		if _, err := s.Groups().ByID(ctx, realm.ID, outsider.ID); err != nil {
			t.Errorf("the realm group went with it: %v", err)
		}
	})
}

// strPtr is the "absent is not empty" helper the organization cases need, and
// nothing else in this file has wanted one.
func strPtr(s string) *string { return &s }

// newRealm creates one realm for a subtest that only needs somewhere to hang
// its objects.
func newRealm(t *testing.T, s store.Store) *model.Realm {
	t.Helper()
	realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
	if err := s.Realms().Create(context.Background(), realm); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	return realm
}
