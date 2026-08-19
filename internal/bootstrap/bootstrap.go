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
// realm roles and the administrator account if they do not already exist.
// It returns early, doing nothing, when the master realm is already
// present, which makes it safe to call on every process start.
func EnsureMaster(ctx context.Context, s store.Store, adminUser, adminPassword string) error {
	if _, err := s.Realms().ByName(ctx, masterRealmName); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("bootstrap: look up master realm: %w", err)
	}

	realm := &model.Realm{
		ID:                   model.NewID(),
		Name:                 masterRealmName,
		Enabled:              true,
		AccessTokenLifespan:  accessTokenLifespan,
		RefreshTokenLifespan: refreshTokenLifespan,
	}
	if err := s.Realms().Create(ctx, realm); err != nil {
		return fmt.Errorf("bootstrap: create master realm: %w", err)
	}

	for _, c := range defaultClients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Enabled = true
		if err := s.Clients().Create(ctx, &c); err != nil {
			return fmt.Errorf("bootstrap: create client %q: %w", c.ClientID, err)
		}
	}

	for _, r := range defaultRealmRoles {
		r.ID = model.NewID()
		r.RealmID = realm.ID
		if err := s.Roles().Create(ctx, &r); err != nil {
			return fmt.Errorf("bootstrap: create role %q: %w", r.Name, err)
		}
	}

	user := &model.User{
		ID:               model.NewID(),
		RealmID:          realm.ID,
		Username:         adminUser,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := s.Users().Create(ctx, user); err != nil {
		return fmt.Errorf("bootstrap: create admin user: %w", err)
	}

	cred, err := passwordCredential(user.ID, adminPassword)
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
		Type:           "password",
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
