package bootstrap_test

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// bootstrapped returns a store with EnsureMaster already run and the master
// realm looked up, which every role test below starts from.
func bootstrapped(t *testing.T) (store.Store, *model.Realm) {
	t.Helper()
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	return s, realm
}

func TestEnsureMasterCreatesTheSixDefaultClients(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}

	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	clients, err := s.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	got := map[string]bool{}
	for _, c := range clients {
		got[c.ClientID] = true
	}
	for _, want := range []string{
		"account", "account-console", "admin-cli",
		"broker", "master-realm", "security-admin-console",
	} {
		if !got[want] {
			t.Errorf("missing default client %q", want)
		}
	}
	if len(clients) != 6 {
		t.Errorf("want 6 clients, got %d", len(clients))
	}
}

func TestAdminCLIMatchesKeycloakConfiguration(t *testing.T) {
	// Measured: public, direct grant on, standard flow OFF, and the lightweight
	// access token attribute set. Without the attribute its tokens carry a
	// different claim set than Keycloak's.
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	c, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")

	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	if !c.PublicClient {
		t.Error("want a public client")
	}
	if !c.DirectAccessGrantsEnabled {
		t.Error("want direct access grants enabled")
	}
	if c.StandardFlowEnabled {
		t.Error("want standard flow disabled")
	}
	if got := c.Attributes["client.use.lightweight.access.token.enabled"]; got != "true" {
		t.Errorf("want the lightweight token attribute set to true, got %q", got)
	}
}

func TestEnsureMasterCreatesTheFiveRealmRoles(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	roles, err := s.Roles().ListRealmRoles(ctx, realm.ID)

	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range roles {
		got[r.Name] = true
	}
	for _, want := range []string{
		"admin", "create-realm", "default-roles-master",
		"offline_access", "uma_authorization",
	} {
		if !got[want] {
			t.Errorf("missing realm role %q", want)
		}
	}
}

func TestEnsureMasterIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("first EnsureMaster: %v", err)
	}

	err := bootstrap.EnsureMaster(ctx, s, "admin", "admin")

	if err != nil {
		t.Fatalf("second EnsureMaster must be a no-op, got %v", err)
	}
}

// TestEnsureMasterConvergesWhenOnlyTheRealmExists pins the regression where a
// crash between the realm insert and the rest of bootstrap - leaving a bare
// master realm row and nothing else - made every later EnsureMaster call a
// silent no-op with no repair path. EnsureMaster must converge: create
// whatever is missing rather than bailing out because the realm exists.
func TestEnsureMasterConvergesWhenOnlyTheRealmExists(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Seed only the realm row, simulating a first-boot crash right after the
	// realm insert but before any client, role or user was created.
	if err := s.Realms().Create(ctx, &model.Realm{
		ID:                   model.NewID(),
		Name:                 "master",
		Enabled:              true,
		AccessTokenLifespan:  60 * time.Second,
		RefreshTokenLifespan: 1800 * time.Second,
	}); err != nil {
		t.Fatalf("seed realm: %v", err)
	}

	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}

	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	clients, err := s.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	got := map[string]bool{}
	for _, c := range clients {
		got[c.ClientID] = true
	}
	for _, want := range []string{
		"account", "account-console", "admin-cli",
		"broker", "master-realm", "security-admin-console",
	} {
		if !got[want] {
			t.Errorf("missing default client %q", want)
		}
	}

	roles, err := s.Roles().ListRealmRoles(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	gotRoles := map[string]bool{}
	for _, r := range roles {
		gotRoles[r.Name] = true
	}
	for _, want := range []string{
		"admin", "create-realm", "default-roles-master",
		"offline_access", "uma_authorization",
	} {
		if !gotRoles[want] {
			t.Errorf("missing realm role %q", want)
		}
	}

	if _, err := s.Users().ByUsername(ctx, realm.ID, "admin"); err != nil {
		t.Errorf("admin user missing after convergence: %v", err)
	}
}

// TestEnsureMasterDoesNotResetAnExistingAdminCredential guards against a
// second EnsureMaster call clobbering an operator's password change: the
// stored hash and salt must be identical before and after.
func TestEnsureMasterDoesNotResetAnExistingAdminCredential(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("first EnsureMaster: %v", err)
	}

	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	before, err := s.Users().CredentialByUser(ctx, user.ID, "password")
	if err != nil {
		t.Fatalf("CredentialByUser: %v", err)
	}

	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("second EnsureMaster: %v", err)
	}

	after, err := s.Users().CredentialByUser(ctx, user.ID, "password")
	if err != nil {
		t.Fatalf("CredentialByUser after second call: %v", err)
	}
	if !bytes.Equal(before.HashValue, after.HashValue) || !bytes.Equal(before.Salt, after.Salt) {
		t.Error("want the admin credential untouched by a second EnsureMaster call")
	}
}

// TestEnsureMasterCreatesTheAdminRoleContainer pins the measured role set on
// the master-realm client. See "Admin roles on the master-realm client" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func TestEnsureMasterCreatesTheAdminRoleContainer(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()

	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID(master-realm): %v", err)
	}
	roles, err := s.Roles().ListClientRoles(ctx, realm.ID, container.ID)
	if err != nil {
		t.Fatalf("ListClientRoles: %v", err)
	}

	want := []string{
		"create-client", "impersonation", "manage-authorization", "manage-clients",
		"manage-events", "manage-identity-providers", "manage-organizations",
		"manage-realm", "manage-users", "query-clients", "query-groups",
		"query-organizations", "query-realms", "query-users", "view-authorization",
		"view-clients", "view-events", "view-identity-providers",
		"view-organizations", "view-realm", "view-users",
	}
	got := make([]string, 0, len(roles))
	for _, r := range roles {
		got = append(got, r.Name)
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("want %d roles, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("role %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

func TestEnsureMasterWiresTheMeasuredComposites(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}

	for parent, want := range map[string][]string{
		"view-clients":       {"query-clients"},
		"view-users":         {"query-groups", "query-users"},
		"view-organizations": {"query-organizations"},
	} {
		role, err := s.Roles().ByName(ctx, realm.ID, container.ID, parent)
		if err != nil {
			t.Fatalf("ByName(%q): %v", parent, err)
		}
		if !role.Composite {
			t.Errorf("%q is not marked composite", parent)
		}
		children, err := s.Roles().ListComposites(ctx, role.ID)
		if err != nil {
			t.Fatalf("ListComposites(%q): %v", parent, err)
		}
		got := make([]string, 0, len(children))
		for _, c := range children {
			got = append(got, c.Name)
		}
		sort.Strings(got)
		if len(got) != len(want) {
			t.Fatalf("%q: want %v, got %v", parent, want, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: want %v, got %v", parent, want, got)
			}
		}
	}
}

// TestAdminRoleIsCompositeOverTwentyTwo pins the measured count. The
// administrator holds no client role directly, so this composite is the only
// route to its rights.
func TestAdminRoleIsCompositeOverTwentyTwo(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()

	admin, err := s.Roles().ByName(ctx, realm.ID, "", "admin")
	if err != nil {
		t.Fatalf("ByName(admin): %v", err)
	}
	children, err := s.Roles().ListComposites(ctx, admin.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}

	if len(children) != 22 {
		t.Fatalf("want 22 composites, got %d", len(children))
	}
	var realmRoles int
	for _, c := range children {
		if c.ClientID == "" {
			realmRoles++
			if c.Name != "create-realm" {
				t.Errorf("unexpected realm role in admin's composites: %q", c.Name)
			}
		}
	}
	if realmRoles != 1 {
		t.Fatalf("want exactly one realm role among the composites, got %d", realmRoles)
	}
}

func TestEnsureMasterGivesTheAdministratorItsRoles(t *testing.T) {
	// Measured: exactly two realm roles and no client role directly.
	s, realm := bootstrapped(t)
	ctx := context.Background()
	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}

	roles, err := s.Roles().ListUserRoles(ctx, user.ID)

	if err != nil {
		t.Fatalf("ListUserRoles: %v", err)
	}
	got := make([]string, 0, len(roles))
	for _, r := range roles {
		if r.ClientID != "" {
			t.Errorf("the administrator holds client role %q directly", r.Name)
		}
		got = append(got, r.Name)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "admin" || got[1] != "default-roles-master" {
		t.Fatalf("want [admin default-roles-master], got %v", got)
	}
}

// TestEnsureMasterCreatesTheAccountAndBrokerRoles pins the two role sets
// follow-up F18 found missing. account's eight matter beyond their names: it
// is the client every user has roles on, so a bootstrap without them issues
// access tokens with an empty resource_access and no aud at all.
func TestEnsureMasterCreatesTheAccountAndBrokerRoles(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()

	for _, c := range []struct {
		client string
		want   []string
	}{
		{
			client: "account",
			want: []string{
				"delete-account", "manage-account", "manage-account-links",
				"manage-consent", "view-applications", "view-consent",
				"view-groups", "view-profile",
			},
		},
		{client: "broker", want: []string{"read-token"}},
		{client: "account-console", want: nil},
		{client: "admin-cli", want: nil},
		{client: "security-admin-console", want: nil},
	} {
		t.Run(c.client, func(t *testing.T) {
			client, err := s.Clients().ByClientID(ctx, realm.ID, c.client)
			if err != nil {
				t.Fatalf("ByClientID(%s): %v", c.client, err)
			}
			roles, err := s.Roles().ListClientRoles(ctx, realm.ID, client.ID)
			if err != nil {
				t.Fatalf("ListClientRoles: %v", err)
			}
			got := make([]string, 0, len(roles))
			for _, r := range roles {
				got = append(got, r.Name)
				// Every client role's description is a theme message key, and
				// unlike the realm roles' they all follow the name.
				if want := "${role_" + r.Name + "}"; r.Description != want {
					t.Errorf("%s: want description %q, got %q", r.Name, want, r.Description)
				}
			}
			sort.Strings(got)
			if !slices.Equal(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

// TestEnsureMasterWiresTheAccountComposites pins the two composites among
// account's own roles, measured 2026-08-23.
func TestEnsureMasterWiresTheAccountComposites(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()
	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}

	for parent, want := range map[string]string{
		"manage-account": "manage-account-links",
		"manage-consent": "view-consent",
	} {
		role, err := s.Roles().ByName(ctx, realm.ID, account.ID, parent)
		if err != nil {
			t.Fatalf("ByName(%s): %v", parent, err)
		}
		if !role.Composite {
			t.Errorf("%s is not marked composite", parent)
		}
		children, err := s.Roles().ListComposites(ctx, role.ID)
		if err != nil {
			t.Fatalf("ListComposites(%s): %v", parent, err)
		}
		if len(children) != 1 || children[0].Name != want {
			t.Fatalf("%s: want [%s], got %v", parent, want, names(children))
		}
	}
}

// TestEnsureMasterWiresDefaultRoles pins what default-roles-master contains:
// two realm roles and two of account's, measured 2026-08-23. This is the
// composite that gives an ordinary user any role at all.
func TestEnsureMasterWiresDefaultRoles(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()
	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}

	role, err := s.Roles().ByName(ctx, realm.ID, "", "default-roles-master")
	if err != nil {
		t.Fatalf("ByName(default-roles-master): %v", err)
	}
	children, err := s.Roles().ListComposites(ctx, role.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}

	var gotRealm, gotAccount []string
	for _, c := range children {
		switch c.ClientID {
		case "":
			gotRealm = append(gotRealm, c.Name)
		case account.ID:
			gotAccount = append(gotAccount, c.Name)
		default:
			t.Errorf("composite %q belongs to an unexpected client %q", c.Name, c.ClientID)
		}
	}
	sort.Strings(gotRealm)
	sort.Strings(gotAccount)
	if want := []string{"offline_access", "uma_authorization"}; !slices.Equal(gotRealm, want) {
		t.Fatalf("realm composites: want %v, got %v", want, gotRealm)
	}
	if want := []string{"manage-account", "view-profile"}; !slices.Equal(gotAccount, want) {
		t.Fatalf("account composites: want %v, got %v", want, gotAccount)
	}
}

// TestEnsureMasterDescribesTheRealmRoles pins the two descriptions that do not
// follow the name - measured, and the reason defaultRealmRoles spells all five
// out instead of deriving them.
func TestEnsureMasterDescribesTheRealmRoles(t *testing.T) {
	s, realm := bootstrapped(t)
	ctx := context.Background()

	want := map[string]string{
		"admin":                "${role_admin}",
		"create-realm":         "${role_create-realm}",
		"default-roles-master": "${role_default-roles}",
		"offline_access":       "${role_offline-access}",
		"uma_authorization":    "${role_uma_authorization}",
	}
	roles, err := s.Roles().ListRealmRoles(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	for _, r := range roles {
		if r.Description != want[r.Name] {
			t.Errorf("%s: want %q, got %q", r.Name, want[r.Name], r.Description)
		}
	}
}

func names(roles []*model.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, r.Name)
	}
	return out
}
