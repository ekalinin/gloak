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

// adminRoleContainer is the client that owns the admin roles in the master
// realm. `realm-management` is the equivalent inside non-master realms, which
// is P4's problem; the original design named it for master and was wrong.
const adminRoleContainer = "master-realm"

// adminClientRoles is the measured set of 21 roles on the master-realm client.
// See "Admin roles on the master-realm client" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// Descriptions are theme message keys of the form ${role_<name>}, not prose,
// so they are derived rather than listed.
var adminClientRoles = []string{
	"create-client",
	"impersonation",
	"manage-authorization",
	"manage-clients",
	"manage-events",
	"manage-identity-providers",
	"manage-organizations",
	"manage-realm",
	"manage-users",
	"query-clients",
	"query-groups",
	"query-organizations",
	"query-realms",
	"query-users",
	"view-authorization",
	"view-clients",
	"view-events",
	"view-identity-providers",
	"view-organizations",
	"view-realm",
	"view-users",
}

// adminRoleComposites is the measured composite structure among those 21.
// The three view- roles each contain the query- role that backs them.
var adminRoleComposites = map[string][]string{
	"view-clients":       {"query-clients"},
	"view-users":         {"query-groups", "query-users"},
	"view-organizations": {"query-organizations"},
}

// adminComposites is what the realm role `admin` contains: measured as all 21
// client roles above plus the realm role create-realm, 22 in total.
//
// The administrator holds no client role directly - measured - so every right
// it has arrives through this composite. A build that does not expand
// composites transitively grants the bootstrapped administrator nothing at
// all.
const adminCompositeRealmRole = "create-realm"

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

	if err := ensureAdminRoles(ctx, s, realm.ID); err != nil {
		return err
	}

	user, err := ensureAdminUser(ctx, s, realm.ID, adminUser)
	if err != nil {
		return err
	}
	if err := ensureAdminRoleAssignment(ctx, s, realm.ID, user.ID); err != nil {
		return err
	}

	return ensureAdminCredential(ctx, s, user.ID, adminPassword)
}

// ensureAdminRoles creates the master-realm client's 21 roles and wires the
// measured composite structure: the three view- roles over their query-
// counterparts, and the realm role admin over all 21 plus create-realm.
func ensureAdminRoles(ctx context.Context, s store.Store, realmID string) error {
	container, err := s.Clients().ByClientID(ctx, realmID, adminRoleContainer)
	if err != nil {
		return fmt.Errorf("bootstrap: look up %s client: %w", adminRoleContainer, err)
	}

	for _, name := range adminClientRoles {
		r := &model.Role{
			ID: model.NewID(), RealmID: realmID, ClientID: container.ID, Name: name,
			Description: "${role_" + name + "}",
			Composite:   len(adminRoleComposites[name]) > 0,
		}
		if err := s.Roles().Create(ctx, r); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create client role %q: %w", name, err)
		}
	}

	for parent, children := range adminRoleComposites {
		if err := composeRoles(ctx, s, realmID, container.ID, parent, container.ID, children); err != nil {
			return err
		}
	}

	// admin is a realm role, so its own client_id is empty while its children
	// live on the container client - except create-realm, which is a realm
	// role too.
	if err := composeRoles(ctx, s, realmID, "", "admin", container.ID, adminClientRoles); err != nil {
		return err
	}
	return composeRoles(ctx, s, realmID, "", "admin", "", []string{adminCompositeRealmRole})
}

// composeRoles adds each child to parent, ignoring a composite that is already
// there so EnsureMaster stays safe to call on every start.
func composeRoles(ctx context.Context, s store.Store, realmID, parentClientID, parent, childClientID string, children []string) error {
	p, err := s.Roles().ByName(ctx, realmID, parentClientID, parent)
	if err != nil {
		return fmt.Errorf("bootstrap: look up role %q: %w", parent, err)
	}
	for _, name := range children {
		c, err := s.Roles().ByName(ctx, realmID, childClientID, name)
		if err != nil {
			return fmt.Errorf("bootstrap: look up role %q: %w", name, err)
		}
		if err := s.Roles().AddComposite(ctx, p.ID, c.ID); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: compose %q over %q: %w", parent, name, err)
		}
	}
	return nil
}

// ensureAdminRoleAssignment gives the administrator the two realm roles it was
// measured holding - admin and default-roles-master - and no client role
// directly.
func ensureAdminRoleAssignment(ctx context.Context, s store.Store, realmID, userID string) error {
	for _, name := range []string{"admin", "default-roles-master"} {
		r, err := s.Roles().ByName(ctx, realmID, "", name)
		if err != nil {
			return fmt.Errorf("bootstrap: look up role %q: %w", name, err)
		}
		if err := s.Roles().AssignToUser(ctx, userID, r.ID); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: assign %q: %w", name, err)
		}
	}
	return nil
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
