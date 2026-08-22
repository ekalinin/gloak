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
}
