// Package bootstrap creates the master realm on first startup: the realm
// itself, its default clients, its default realm roles and the
// administrator account. EnsureMaster is idempotent, so it is safe to call
// on every process start.
package bootstrap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

const masterRealmName = "master"

// passwordCredentialType is Keycloak's CredentialRepresentation.type value
// for a password credential.
const passwordCredentialType = "password"

// Lifespans measured on a live Keycloak 26.7.1 instance: 60s access tokens,
// 1800s refresh tokens in the master realm.
const (
	accessTokenLifespan  = 60 * time.Second
	refreshTokenLifespan = 1800 * time.Second
)

// defaultClients is the measured configuration of the six clients Keycloak
// creates in a fresh master realm.
var defaultClients = []model.Client{
	{ClientID: "account", PublicClient: true, StandardFlowEnabled: true},
	{ClientID: "account-console", PublicClient: true, StandardFlowEnabled: true},
	{
		ClientID: "admin-cli", PublicClient: true,
		StandardFlowEnabled: false, DirectAccessGrantsEnabled: true,
		Attributes: map[string]string{
			"client.use.lightweight.access.token.enabled": "true",
		},
	},
	{ClientID: "broker", PublicClient: false, StandardFlowEnabled: true},
	{ClientID: "master-realm", PublicClient: false, StandardFlowEnabled: true},
	{ClientID: "security-admin-console", PublicClient: true, StandardFlowEnabled: true},
}

// defaultRealmRoles is the measured set of realm-level roles Keycloak
// creates in a fresh master realm.
var defaultRealmRoles = []model.Role{
	{Name: "admin", Composite: true},
	{Name: "create-realm"},
	{Name: "default-roles-master", Composite: true},
	{Name: "offline_access"},
	{Name: "uma_authorization"},
}

// Argon2id parameters measured on Keycloak 26.7.1's default admin
// credential: 5 iterations, 7168 KiB of memory, parallelism 1, 32-byte
// output.
const (
	argonTime      = 5
	argonMemoryKiB = 7168
	argonThreads   = 1
	argonKeyLength = 32
	saltLength     = 16
)

// EnsureMaster creates the master realm, its default clients, its default
// realm roles and the administrator account, creating only whatever is
// currently missing. It converges rather than short-circuiting on "the realm
// already exists": every object is ensured individually, so a process that
// crashed midway through a previous run is repaired on the next call instead
// of being left permanently half-built. Existing objects are never modified;
// in particular, an existing admin credential is left alone rather than
// reset, so this is safe to call on every process start.
func EnsureMaster(ctx context.Context, s store.Store, adminUser, adminPassword string) error {
	realm, err := ensureRealm(ctx, s)
	if err != nil {
		return err
	}

	for _, c := range defaultClients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Enabled = true
		if err := s.Clients().Create(ctx, &c); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create client %q: %w", c.ClientID, err)
		}
	}

	for _, r := range defaultRealmRoles {
		r.ID = model.NewID()
		r.RealmID = realm.ID
		if err := s.Roles().Create(ctx, &r); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create role %q: %w", r.Name, err)
		}
	}

	user, err := ensureAdminUser(ctx, s, realm.ID, adminUser)
	if err != nil {
		return err
	}

	return ensureAdminCredential(ctx, s, user.ID, adminPassword)
}

// ensureRealm creates the master realm, or looks up the existing one if a
// previous run (or a concurrent one) already created it.
func ensureRealm(ctx context.Context, s store.Store) (*model.Realm, error) {
	realm := &model.Realm{
		ID:                   model.NewID(),
		Name:                 masterRealmName,
		Enabled:              true,
		AccessTokenLifespan:  accessTokenLifespan,
		RefreshTokenLifespan: refreshTokenLifespan,
	}
	err := s.Realms().Create(ctx, realm)
	switch {
	case err == nil:
		return realm, nil
	case errors.Is(err, store.ErrConflict):
		existing, err := s.Realms().ByName(ctx, masterRealmName)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: look up master realm: %w", err)
		}
		return existing, nil
	default:
		return nil, fmt.Errorf("bootstrap: create master realm: %w", err)
	}
}

// ensureAdminUser creates the admin user, or looks up the existing one.
// Fields of an existing user are left untouched.
func ensureAdminUser(ctx context.Context, s store.Store, realmID, adminUser string) (*model.User, error) {
	user := &model.User{
		ID:               model.NewID(),
		RealmID:          realmID,
		Username:         adminUser,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	err := s.Users().Create(ctx, user)
	switch {
	case err == nil:
		return user, nil
	case errors.Is(err, store.ErrConflict):
		existing, err := s.Users().ByUsername(ctx, realmID, adminUser)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: look up admin user: %w", err)
		}
		return existing, nil
	default:
		return nil, fmt.Errorf("bootstrap: create admin user: %w", err)
	}
}

// ensureAdminCredential stores a password credential for the admin user only
// if one is not already present. SetCredential upserts, so this check is
// what stops a second EnsureMaster call from resetting a password the
// operator has since changed.
func ensureAdminCredential(ctx context.Context, s store.Store, userID, adminPassword string) error {
	_, err := s.Users().CredentialByUser(ctx, userID, passwordCredentialType)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("bootstrap: look up admin credential: %w", err)
	}

	cred, err := passwordCredential(userID, adminPassword)
	if err != nil {
		return fmt.Errorf("bootstrap: hash admin password: %w", err)
	}
	if err := s.Users().SetCredential(ctx, cred); err != nil {
		return fmt.Errorf("bootstrap: store admin credential: %w", err)
	}
	return nil
}

// passwordCredential hashes password with the argon2id parameters measured
// on Keycloak 26.7.1 and returns the credential ready to store. A fresh
// random salt is generated per call.
func passwordCredential(userID, password string) (*model.Credential, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("bootstrap: generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLength)

	return &model.Credential{
		ID:             model.NewID(),
		UserID:         userID,
		Type:           passwordCredentialType,
		CreatedDate:    time.Now().UnixMilli(),
		Algorithm:      "argon2",
		HashIterations: argonTime,
		AdditionalParameters: map[string][]string{
			"hashLength":  {"32"},
			"memory":      {"7168"},
			"type":        {"id"},
			"version":     {"1.3"},
			"parallelism": {"1"},
		},
		Salt:      salt,
		HashValue: hash,
	}, nil
}
