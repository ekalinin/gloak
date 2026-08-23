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

// Client scope names every bootstrapped client carries, measured identically
// on all six. They are names only: the client-scope objects behind them are
// P5. See section 1.1 of
// docs/superpowers/specs/2026-08-22-p2-admin-api-core-design.md.
var (
	defaultScopeNames  = []string{"web-origins", "acr", "profile", "roles", "basic", "email"}
	optionalScopeNames = []string{"address", "phone", "organization", "offline_access", "microprofile-jwt"}
)

// defaultClients is the measured configuration of the six clients Keycloak
// creates in a fresh master realm, transcribed from a recording of
// GET /admin/realms/master/clients rather than from the OpenAPI schema. See
// "Client representation" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// Two values here correct what this file had before, and neither was
// contradicted by an earlier measurement - nobody had looked:
//
//   - broker and master-realm are bearer-only. They were created as ordinary
//     confidential clients.
//   - security-admin-console also carries the lightweight-access-token
//     attribute. Only admin-cli was thought to.
//
// Name is a theme message key for five of the six; master-realm's is prose
// derived from the realm name, which is why it is filled in at creation time
// rather than listed here.
var defaultClients = []model.Client{
	{
		ClientID: "account", Name: "${client_account}",
		RootURL: "${authBaseUrl}", BaseURL: "/realms/master/account/",
		Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs: []string{"/realms/master/account/*"},
		Attributes: map[string]string{
			"realm_client": "false", "post.logout.redirect.uris": "+",
		},
	},
	{
		ClientID: "account-console", Name: "${client_account-console}",
		RootURL: "${authBaseUrl}", BaseURL: "/realms/master/account/",
		Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs: []string{"/realms/master/account/*"},
		Attributes: map[string]string{
			"realm_client": "false", "post.logout.redirect.uris": "+",
			"pkce.code.challenge.method": "S256",
		},
	},
	{
		ClientID: "admin-cli", Name: "${client_admin-cli}",
		Protocol: "openid-connect", PublicClient: true,
		StandardFlowEnabled: false, DirectAccessGrantsEnabled: true,
		FullScopeAllowed: true,
		Attributes: map[string]string{
			"realm_client": "false",
			"client.use.lightweight.access.token.enabled": "true",
		},
	},
	{
		ClientID: "broker", Name: "${client_broker}",
		Protocol: "openid-connect", PublicClient: false, BearerOnly: true,
		StandardFlowEnabled: true,
		Attributes:          map[string]string{"realm_client": "true"},
	},
	{
		// No Protocol: measured absent on this client alone.
		ClientID: "master-realm", PublicClient: false, BearerOnly: true,
		StandardFlowEnabled: true,
		Attributes:          map[string]string{"realm_client": "true"},
	},
	{
		ClientID: "security-admin-console", Name: "${client_security-admin-console}",
		RootURL: "${authAdminUrl}", BaseURL: "/admin/master/console/",
		Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
		FullScopeAllowed: true,
		RedirectURIs:     []string{"/admin/master/console/*"},
		WebOrigins:       []string{"+"},
		Attributes: map[string]string{
			"realm_client": "false", "post.logout.redirect.uris": "+",
			"pkce.code.challenge.method":                  "S256",
			"client.use.lightweight.access.token.enabled": "true",
		},
	},
}

// defaultRealmRoles is the measured set of realm-level roles Keycloak
// creates in a fresh master realm.
//
// Two of the descriptions do not follow the ${role_<name>} pattern the client
// roles all follow, measured 2026-08-23: offline_access is described as
// ${role_offline-access} with a hyphen where the name has an underscore, and
// default-roles-master as ${role_default-roles} without the realm name. They
// are spelled out for that reason rather than derived.
var defaultRealmRoles = []model.Role{
	{Name: "admin", Description: "${role_admin}", Composite: true},
	{Name: "create-realm", Description: "${role_create-realm}"},
	{Name: defaultRolesRealmRole, Description: "${role_default-roles}", Composite: true},
	{Name: "offline_access", Description: "${role_offline-access}"},
	{Name: "uma_authorization", Description: "${role_uma_authorization}"},
}

// defaultRolesRealmRole is the composite every user in the realm is given, and
// the reason an ordinary user's token carries any role at all. Its name
// carries the realm's, so a second realm gets its own.
const defaultRolesRealmRole = "default-roles-master"

// defaultRolesComposites is what that role contains, measured 2026-08-23:
// two realm roles and two of the account client's.
//
// This is what puts `account` in every token's aud and resource_access, so it
// is not decoration - without it Gloak issues tokens with no audience at all.
var defaultRolesComposites = struct {
	realm   []string
	account []string
}{
	realm:   []string{"offline_access", "uma_authorization"},
	account: []string{"manage-account", "view-profile"},
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

// roleContainers is every bootstrapped client that owns roles, measured
// 2026-08-23 by reading GET .../clients/{uuid}/roles on all six.
// account-console, admin-cli and security-admin-console own none, which is why
// they are absent rather than present with an empty list.
//
// account was missing entirely until follow-up F18. It is the client an
// ordinary user has roles on, so leaving it out did not merely lose three role
// names: it left every access token with an empty resource_access and, since
// aud is derived from that, no audience at all.
var roleContainers = []struct {
	client     string
	roles      []string
	composites map[string][]string
}{
	{
		client: "account",
		roles: []string{
			"delete-account",
			"manage-account",
			"manage-account-links",
			"manage-consent",
			"view-applications",
			"view-consent",
			"view-groups",
			"view-profile",
		},
		composites: map[string][]string{
			"manage-account": {"manage-account-links"},
			"manage-consent": {"view-consent"},
		},
	},
	{client: "broker", roles: []string{"read-token"}},
	{client: adminRoleContainer, roles: adminClientRoles, composites: adminRoleComposites},
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
		// Measured on every one of the six, so held here rather than repeated
		// in each literal above.
		c.ClientAuthenticatorType = "client-secret"
		c.DefaultClientScopes = defaultScopeNames
		c.OptionalClientScopes = optionalScopeNames
		if c.RedirectURIs == nil {
			c.RedirectURIs = []string{}
		}
		if c.WebOrigins == nil {
			c.WebOrigins = []string{}
		}
		if c.ClientID == adminRoleContainer {
			// "master Realm" - prose derived from the realm's name, not a
			// theme message key like the other five.
			c.Name = realm.Name + " Realm"
		}
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

	if err := ensureClientRoles(ctx, s, realm.ID); err != nil {
		return err
	}
	if err := ensureAdminComposites(ctx, s, realm.ID); err != nil {
		return err
	}
	if err := ensureDefaultRoles(ctx, s, realm.ID); err != nil {
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

// ensureClientRoles creates every role the bootstrapped clients own and wires
// the composites among them - the three admin view- roles over their query-
// counterparts, manage-account over manage-account-links, manage-consent over
// view-consent.
//
// Client role descriptions are all theme message keys of the form
// ${role_<name>}, measured on all 30, so they are derived rather than listed.
// The realm roles next door are not so tidy; see defaultRealmRoles.
func ensureClientRoles(ctx context.Context, s store.Store, realmID string) error {
	for _, container := range roleContainers {
		c, err := s.Clients().ByClientID(ctx, realmID, container.client)
		if err != nil {
			return fmt.Errorf("bootstrap: look up %s client: %w", container.client, err)
		}
		for _, name := range container.roles {
			r := &model.Role{
				ID: model.NewID(), RealmID: realmID, ClientID: c.ID, Name: name,
				Description: "${role_" + name + "}",
				Composite:   len(container.composites[name]) > 0,
			}
			if err := s.Roles().Create(ctx, r); err != nil && !errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("bootstrap: create client role %q on %q: %w", name, container.client, err)
			}
		}
		for parent, children := range container.composites {
			if err := composeRoles(ctx, s, realmID, c.ID, parent, c.ID, children); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureAdminComposites wires the realm role admin over all 21 admin client
// roles plus create-realm.
func ensureAdminComposites(ctx context.Context, s store.Store, realmID string) error {
	container, err := s.Clients().ByClientID(ctx, realmID, adminRoleContainer)
	if err != nil {
		return fmt.Errorf("bootstrap: look up %s client: %w", adminRoleContainer, err)
	}
	// admin is a realm role, so its own client_id is empty while its children
	// live on the container client - except create-realm, which is a realm
	// role too.
	if err := composeRoles(ctx, s, realmID, "", "admin", container.ID, adminClientRoles); err != nil {
		return err
	}
	return composeRoles(ctx, s, realmID, "", "admin", "", []string{adminCompositeRealmRole})
}

// ensureDefaultRoles wires default-roles-master over the two realm roles and
// the two account client roles it was measured containing.
func ensureDefaultRoles(ctx context.Context, s store.Store, realmID string) error {
	account, err := s.Clients().ByClientID(ctx, realmID, "account")
	if err != nil {
		return fmt.Errorf("bootstrap: look up account client: %w", err)
	}
	if err := composeRoles(ctx, s, realmID, "", defaultRolesRealmRole, "", defaultRolesComposites.realm); err != nil {
		return err
	}
	return composeRoles(ctx, s, realmID, "", defaultRolesRealmRole, account.ID, defaultRolesComposites.account)
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
	for _, name := range []string{"admin", defaultRolesRealmRole} {
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
		// Measured: the bootstrapped administrator carries this one attribute
		// and it is visible through the Admin API, so the user listing cannot
		// be reproduced without it. Keycloak sets it for an account created
		// from KC_BOOTSTRAP_ADMIN_USERNAME; what it goes on to mean is not
		// measured, only that it is there and that the value is the string
		// "true" in a one-element array.
		Attributes: map[string][]string{"is_temporary_admin": {"true"}},
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
