// Package storetest holds the behaviour both store drivers must satisfy.
// It lives in its own package so SQLite and Postgres share one definition of
// correct rather than two drifting copies.
package storetest

import (
	"context"
	"errors"
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
}
