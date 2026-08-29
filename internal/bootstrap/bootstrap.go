// Package bootstrap creates a realm and everything Keycloak was measured
// creating with it: its default clients, its default realm roles, its admin
// role container and - for a realm that is not master - the client in master
// that carries the rights to administer it.
//
// EnsureMaster is the master-only part on top of that: the two realm roles only
// master has, the administrator account and its credential. Both it and
// CreateRealm are idempotent, so EnsureMaster is safe to call on every process
// start.
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

// MasterRealmName is the one realm that is bootstrapped at startup, carries the
// admin and create-realm realm roles, holds a {realm}-realm client for every
// other realm, and cannot be deleted. It is exported because internal/admin has
// to make the same distinction and a second copy of the string would be a
// second place to get it wrong.
const MasterRealmName = "master"

// passwordCredentialType is Keycloak's CredentialRepresentation.type value
// for a password credential.
const passwordCredentialType = "password"

// Lifespans measured on a live Keycloak 26.7.1 instance: 60s access tokens,
// 1800s refresh tokens in the master realm.
const (
	accessTokenLifespan  = 60 * time.Second
	refreshTokenLifespan = 1800 * time.Second
)

// The two client-scope name lists that used to live here are gone. They were
// the six and the five every bootstrapped client carries, written as constants
// because the client-scope objects behind them did not exist. They do now:
// clientscopes.go creates the realm's fifteen and its own two default sets, and
// a client's six and five fall out of inheriting from those filtered by its
// protocol. Keeping the constants beside the sets they are derived from would
// be two truths, and the derivation is what closes follow-up F49.

// realmClients is the measured configuration of the six clients Keycloak
// creates in a realm, transcribed from recordings of
// GET /admin/realms/{realm}/clients on master and on a realm created through
// POST /admin/realms rather than from the OpenAPI schema. See "Client
// representation" and "Realms" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// Two values here correct what this file had before, and neither was
// contradicted by an earlier measurement - nobody had looked:
//
//   - broker and the admin role container are bearer-only. They were created as
//     ordinary confidential clients.
//   - security-admin-console also carries the lightweight-access-token
//     attribute. Only admin-cli was thought to.
//
// **Three of the six carry the realm's name in their URLs** and the sixth is a
// different client in master than in any other realm - see AdminContainerFor.
// A function rather than a package variable for both reasons, and because it
// hands out maps and slices that a shared variable would let one realm's
// creation edit for every other.
func realmClients(realm string) []model.Client {
	return []model.Client{
		{
			ClientID: "account", Name: "${client_account}",
			RootURL: "${authBaseUrl}", BaseURL: "/realms/" + realm + "/account/",
			Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"/realms/" + realm + "/account/*"},
			Attributes: map[string]string{
				"realm_client": "false", "post.logout.redirect.uris": "+",
			},
		},
		{
			ClientID: "account-console", Name: "${client_account-console}",
			RootURL: "${authBaseUrl}", BaseURL: "/realms/" + realm + "/account/",
			Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"/realms/" + realm + "/account/*"},
			Attributes: map[string]string{
				"realm_client": "false", "post.logout.redirect.uris": "+",
				"pkce.code.challenge.method": "S256",
			},
			ProtocolMappers: []model.ProtocolMapper{audienceResolveMapper()},
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
		adminContainerClient(realm),
		{
			ClientID: "security-admin-console", Name: "${client_security-admin-console}",
			RootURL: "${authAdminUrl}", BaseURL: "/admin/" + realm + "/console/",
			Protocol: "openid-connect", PublicClient: true, StandardFlowEnabled: true,
			FullScopeAllowed: true,
			RedirectURIs:     []string{"/admin/" + realm + "/console/*"},
			WebOrigins:       []string{"+"},
			Attributes: map[string]string{
				"realm_client": "false", "post.logout.redirect.uris": "+",
				"pkce.code.challenge.method":                  "S256",
				"client.use.lightweight.access.token.enabled": "true",
			},
			ProtocolMappers: []model.ProtocolMapper{localeMapper()},
		},
	}
}

// audienceResolveMapper and localeMapper are the two protocol mappers a
// bootstrapped realm's clients carry, recorded verbatim from
// GET /admin/realms/{realm}/clients/{uuid}/protocol-mappers/models on a live
// 26.7.1 on 2026-08-30.
//
// **Four of the six clients carry none and these two carry one each.** That is
// worth stating because it was missed: the client scopes' thirty-five mappers
// were stored a day earlier and a client's own were not, so a token engine
// reading only the client scopes would have produced the wrong claim set for
// exactly these two clients and the fault would have looked like an engine bug.
//
// The config key order is the recorded one and is Keycloak's own Java map
// order, not insertion order and not sorted - the same reason
// internal/bootstrap/clientscopes.json is a recording rather than a
// transcription.
//
// `audience resolve` is one of two providers that mirror `access.token.claim`
// into `introspection.token.claim` and do **not** mirror `id.token.claim`,
// which is why it has two config keys where `locale` has seven.
func audienceResolveMapper() model.ProtocolMapper {
	return model.ProtocolMapper{
		ID:             model.NewID(),
		Name:           "audience resolve",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-audience-resolve-mapper",
		Config: model.StringMap{
			{Key: "introspection.token.claim", Value: "true"},
			{Key: "access.token.claim", Value: "true"},
		},
	}
}

func localeMapper() model.ProtocolMapper {
	return model.ProtocolMapper{
		ID:             model.NewID(),
		Name:           "locale",
		Protocol:       "openid-connect",
		ProtocolMapper: "oidc-usermodel-attribute-mapper",
		Config: model.StringMap{
			{Key: "introspection.token.claim", Value: "true"},
			{Key: "userinfo.token.claim", Value: "true"},
			{Key: "user.attribute", Value: "locale"},
			{Key: "id.token.claim", Value: "true"},
			{Key: "access.token.claim", Value: "true"},
			{Key: "claim.name", Value: "locale"},
			{Key: "jsonType.label", Value: "String"},
		},
	}
}

// AdminContainerFor is the client that owns a realm's admin roles as seen from
// inside that realm: master-realm in master, realm-management everywhere else.
//
// **The two are not the same client with two names.** master-realm owns 21
// roles and realm-management owns 22 - the extra one being realm-admin,
// composite over the other 21 - and master-realm's name is prose derived from
// the realm name where realm-management's is a theme message key. Both measured.
//
// It is exported because internal/admin has to make the same distinction, and
// getting it wrong there is a privilege escalation rather than a cosmetic bug:
// see ownedByRealmOwnClient.
func AdminContainerFor(realm string) string {
	if realm == MasterRealmName {
		return "master-realm"
	}
	return "realm-management"
}

// masterContainerFor is the client **in master** that carries the rights to
// administer a realm: master-realm for master itself, {realm}-realm for every
// other. Creating a realm was measured creating this client in master and
// adding its 21 roles to master's admin realm role.
func masterContainerFor(realm string) string {
	if realm == MasterRealmName {
		return "master-realm"
	}
	return realm + "-realm"
}

// adminContainerClient is the sixth of the six, and the one that differs.
//
// realm-management carries a theme message key for its name, a protocol and the
// usual six and five client scopes. master-realm carries prose, no protocol at
// all - measured absent on that client alone - and its scopes are filled in with
// the others'. The {realm}-realm client in master is a third shape again and is
// built by masterContainerClient rather than here.
func adminContainerClient(realm string) model.Client {
	if realm == MasterRealmName {
		return model.Client{
			ClientID: "master-realm", PublicClient: false, BearerOnly: true,
			StandardFlowEnabled: true,
			Attributes:          map[string]string{"realm_client": "true"},
		}
	}
	return model.Client{
		ClientID: "realm-management", Name: "${client_realm-management}",
		Protocol: "openid-connect", PublicClient: false, BearerOnly: true,
		StandardFlowEnabled: true,
		Attributes:          map[string]string{"realm_client": "true"},
	}
}

// masterContainerClient is the {realm}-realm client a created realm gets **in
// master**, recorded from GET /admin/realms/master/clients?clientId=p4cl-realm.
//
// It is not adminContainerClient's shape and not master-realm's either: it
// carries prose for a name like master-realm, no protocol like master-realm,
// and **empty** default and optional client scope lists where every other
// bootstrapped client carries six and five. The empty lists are why it is built
// here rather than run through the loop in createRealm.
func masterContainerClient(realm string) model.Client {
	return model.Client{
		ClientID: masterContainerFor(realm), Name: realm + " Realm",
		PublicClient: false, BearerOnly: true, StandardFlowEnabled: true,
		Attributes:           map[string]string{"realm_client": "true"},
		RedirectURIs:         []string{},
		WebOrigins:           []string{},
		DefaultClientScopes:  []string{},
		OptionalClientScopes: []string{},
	}
}

// realmRoles is the measured set of realm-level roles a realm carries.
//
// **A created realm has three of these and master has five.** admin and
// create-realm exist in master alone, measured on a realm created through
// POST /admin/realms, so extending master's five to every realm would hand
// every realm a role that confers the right to create realms.
//
// Two of the descriptions do not follow the ${role_<name>} pattern the client
// roles all follow, measured 2026-08-23: offline_access is described as
// ${role_offline-access} with a hyphen where the name has an underscore, and
// default-roles-{realm} as ${role_default-roles} without the realm name. They
// are spelled out for that reason rather than derived.
func realmRoles(realm string) []model.Role {
	roles := []model.Role{
		{Name: model.DefaultRolesName(realm), Description: "${role_default-roles}", Composite: true},
		{Name: "offline_access", Description: "${role_offline-access}"},
		{Name: "uma_authorization", Description: "${role_uma_authorization}"},
	}
	if realm == MasterRealmName {
		roles = append(roles,
			model.Role{Name: "admin", Description: "${role_admin}", Composite: true},
			model.Role{Name: adminCompositeRealmRole, Description: "${role_create-realm}"},
		)
	}
	return roles
}

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

// realmAdminRole is the twenty-second role, and realm-management has it where
// master-realm does not. It is composite over the other 21 and is what makes a
// realm administrable from inside itself: a caller holding it reads, writes and
// deletes its own realm and is 403 on every other, measured.
const realmAdminRole = "realm-admin"

// adminContainerRoles is what the container inside a realm owns: 21 in master,
// 22 everywhere else.
func adminContainerRoles(realm string) []string {
	if realm == MasterRealmName {
		return adminClientRoles
	}
	return append(append([]string{}, adminClientRoles...), realmAdminRole)
}

// adminContainerComposites is the composite structure on that container. The
// three view- roles are the same either side; realm-admin over all 21 is the
// difference, and it is what a realm-management caller's rights are expanded
// through.
func adminContainerComposites(realm string) map[string][]string {
	if realm == MasterRealmName {
		return adminRoleComposites
	}
	out := make(map[string][]string, len(adminRoleComposites)+1)
	for k, v := range adminRoleComposites {
		out[k] = v
	}
	out[realmAdminRole] = adminClientRoles
	return out
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
type roleContainer struct {
	client     string
	roles      []string
	composites map[string][]string
}

func roleContainers(realm string) []roleContainer {
	return []roleContainer{
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
		{
			client:     AdminContainerFor(realm),
			roles:      adminContainerRoles(realm),
			composites: adminContainerComposites(realm),
		},
	}
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
	realm, err := CreateRealm(ctx, s, MasterRealmName, nil)
	if err != nil {
		return err
	}
	if err := ensureAdminComposites(ctx, s, realm.ID); err != nil {
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

// CreateRealm builds a realm and everything Keycloak was measured creating
// alongside it: six clients, three realm roles, the admin role container with
// its 21 or 22 roles, the default-roles composite, and - for any realm that is
// not master - the {realm}-realm client **in master** that carries the rights
// to administer it.
//
// realm carries the fields the caller wants set; only ID, Name and the two
// lifespans are read, and a nil realm means "the defaults for this name". It is
// idempotent for the same reason EnsureMaster is: every object is ensured
// individually, so a process that crashed midway through is repaired on the
// next call rather than left permanently half-built.
//
// **It modifies master's admin realm role, and that is measured, not a
// shortcut.** Creating a realm was measured taking master's admin from 22
// composites to 43, and deleting it taking them back out. AGENTS.md's boundary
// for this package was rewritten in the same change that added this function
// rather than worked around.
func CreateRealm(ctx context.Context, s store.Store, name string, want *model.Realm) (*model.Realm, error) {
	realm, err := ensureRealm(ctx, s, name, want)
	if err != nil {
		return nil, err
	}

	// The scopes come before the clients: every client attaches to them, and
	// what a client with no lists of its own inherits is read out of the
	// realm's two default sets rather than written from a constant.
	if err := ensureClientScopes(ctx, s, realm.ID); err != nil {
		return nil, err
	}

	for _, c := range realmClients(name) {
		if err := createClient(ctx, s, realm.ID, c); err != nil {
			return nil, err
		}
	}

	for _, r := range realmRoles(name) {
		r.ID = model.NewID()
		r.RealmID = realm.ID
		if err := s.Roles().Create(ctx, &r); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("bootstrap: create role %q: %w", r.Name, err)
		}
	}

	if err := ensureClientRoles(ctx, s, realm.ID, name); err != nil {
		return nil, err
	}
	if err := ensureDefaultRoles(ctx, s, realm.ID, name); err != nil {
		return nil, err
	}
	if name != MasterRealmName {
		if err := ensureMasterContainer(ctx, s, name); err != nil {
			return nil, err
		}
	}
	return realm, nil
}

// createClient fills in the fields measured identical on every bootstrapped
// client, stores it, and attaches its client scopes.
//
// The two scope lists are **not** forced: masterContainerClient carries them
// empty, measured, where the other six inherit the realm's. AttachClientScopes
// draws exactly that distinction - nil inherits and an empty slice attaches
// nothing - so the shape this comment used to defend is now the shape a client
// created through the Admin API gets too, and it is written down once.
func createClient(ctx context.Context, s store.Store, realmID string, c model.Client) error {
	c.ID = model.NewID()
	c.RealmID = realmID
	c.Enabled = true
	c.ClientAuthenticatorType = "client-secret"
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.WebOrigins == nil {
		c.WebOrigins = []string{}
	}
	if err := InheritClientScopes(ctx, s, realmID, &c); err != nil {
		return err
	}
	if err := s.Clients().Create(ctx, &c); err != nil && !errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("bootstrap: create client %q: %w", c.ClientID, err)
	}
	return nil
}

// ensureMasterContainer creates the {realm}-realm client in **master** and adds
// its 21 roles to master's admin realm role.
//
// Both halves are measured: master gained a p4a-realm client when p4a was
// created, and its admin role went from 22 composites to 43. The client's name
// is prose - "p4a Realm" - not a theme message key.
func ensureMasterContainer(ctx context.Context, s store.Store, name string) error {
	master, err := s.Realms().ByName(ctx, MasterRealmName)
	if err != nil {
		return fmt.Errorf("bootstrap: look up master realm: %w", err)
	}
	if err := createClient(ctx, s, master.ID, masterContainerClient(name)); err != nil {
		return err
	}

	container, err := s.Clients().ByClientID(ctx, master.ID, masterContainerFor(name))
	if err != nil {
		return fmt.Errorf("bootstrap: look up %s client: %w", masterContainerFor(name), err)
	}
	for _, role := range adminClientRoles {
		r := &model.Role{
			ID: model.NewID(), RealmID: master.ID, ClientID: container.ID, Name: role,
			Description: "${role_" + role + "}",
			Composite:   len(adminRoleComposites[role]) > 0,
		}
		if err := s.Roles().Create(ctx, r); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create %s role %q: %w", container.ClientID, role, err)
		}
	}
	for parent, children := range adminRoleComposites {
		if err := composeRoles(ctx, s, master.ID, container.ID, parent, container.ID, children); err != nil {
			return err
		}
	}
	// The measured edit to an object that already exists.
	return composeRoles(ctx, s, master.ID, "", "admin", container.ID, adminClientRoles)
}

// DeleteRealm removes a realm and the client in master that administered it.
//
// The realm row cascades to its clients, users, roles, groups, sessions and
// keys. The client in master does **not** cascade to its roles - keycloak_role
// carries no foreign key to client, which is F29 - so the 21 are deleted
// explicitly, and deleting them is what takes their 21 rows back out of
// master's admin composite through composite_role's cascade. Measured: master's
// admin went from 127 composites to 106 when one realm was deleted.
func DeleteRealm(ctx context.Context, s store.Store, realm *model.Realm) error {
	if realm.Name == MasterRealmName {
		return fmt.Errorf("bootstrap: master realm cannot be deleted")
	}
	master, err := s.Realms().ByName(ctx, MasterRealmName)
	if err != nil {
		return fmt.Errorf("bootstrap: look up master realm: %w", err)
	}

	container, err := s.Clients().ByClientID(ctx, master.ID, masterContainerFor(realm.Name))
	switch {
	case err == nil:
		roles, err := s.Roles().ListClientRoles(ctx, master.ID, container.ID)
		if err != nil {
			return fmt.Errorf("bootstrap: list %s roles: %w", container.ClientID, err)
		}
		for _, r := range roles {
			if err := s.Roles().Delete(ctx, master.ID, r.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("bootstrap: delete role %q: %w", r.Name, err)
			}
		}
		if err := s.Clients().Delete(ctx, master.ID, container.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("bootstrap: delete client %q: %w", container.ClientID, err)
		}
	case errors.Is(err, store.ErrNotFound):
		// A realm whose container in master is already gone still deletes.
		// Converging rather than failing is the same reason CreateRealm
		// ensures each object individually.
	default:
		return fmt.Errorf("bootstrap: look up %s client: %w", masterContainerFor(realm.Name), err)
	}

	if err := s.Realms().Delete(ctx, realm.ID); err != nil {
		return fmt.Errorf("bootstrap: delete realm %q: %w", realm.Name, err)
	}
	return nil
}

// ensureClientRoles creates every role the bootstrapped clients own and wires
// the composites among them - the three admin view- roles over their query-
// counterparts, manage-account over manage-account-links, manage-consent over
// view-consent.
//
// Client role descriptions are all theme message keys of the form
// ${role_<name>}, measured on all 30, so they are derived rather than listed.
// The realm roles next door are not so tidy; see defaultRealmRoles.
func ensureClientRoles(ctx context.Context, s store.Store, realmID, realmName string) error {
	for _, container := range roleContainers(realmName) {
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
// roles plus create-realm. It is master's alone: no other realm has an admin
// realm role at all, measured.
func ensureAdminComposites(ctx context.Context, s store.Store, realmID string) error {
	const adminRoleContainer = "master-realm"
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

// ensureDefaultRoles wires default-roles-{realm} over the two realm roles and
// the two account client roles it was measured containing. A created realm's
// four are the same four master's has.
func ensureDefaultRoles(ctx context.Context, s store.Store, realmID, realmName string) error {
	account, err := s.Clients().ByClientID(ctx, realmID, "account")
	if err != nil {
		return fmt.Errorf("bootstrap: look up account client: %w", err)
	}
	defaultRoles := model.DefaultRolesName(realmName)
	if err := composeRoles(ctx, s, realmID, "", defaultRoles, "", defaultRolesComposites.realm); err != nil {
		return err
	}
	return composeRoles(ctx, s, realmID, "", defaultRoles, account.ID, defaultRolesComposites.account)
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
	for _, name := range []string{"admin", model.DefaultRolesName(MasterRealmName)} {
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

// ensureRealm creates the realm row, or looks up the existing one if a
// previous run (or a concurrent one) already created it.
//
// want carries what the caller asked for and may be nil. The defaults it fills
// in are **master's**, and they are not the product's: master's
// accessTokenLifespan is 60 where a realm created through POST /admin/realms
// gets 300, and a created realm is disabled where master is enabled. Both
// measured, and both are the admin handler's to supply rather than this
// function's to guess.
func ensureRealm(ctx context.Context, s store.Store, name string, want *model.Realm) (*model.Realm, error) {
	realm := &model.Realm{
		ID:                   model.NewID(),
		Name:                 name,
		Enabled:              true,
		AccessTokenLifespan:  accessTokenLifespan,
		RefreshTokenLifespan: refreshTokenLifespan,
	}
	if want != nil {
		realm = want
		realm.Name = name
		if realm.ID == "" {
			realm.ID = model.NewID()
		}
	}
	err := s.Realms().Create(ctx, realm)
	switch {
	case err == nil:
		return realm, nil
	case errors.Is(err, store.ErrConflict):
		existing, err := s.Realms().ByName(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: look up realm %q: %w", name, err)
		}
		return existing, nil
	default:
		return nil, fmt.Errorf("bootstrap: create realm %q: %w", name, err)
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
