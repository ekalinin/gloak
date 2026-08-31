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
	// synchronous(off): a throwaway database in t.TempDir() has nothing to be
	// durable against, and the fsync it saves is what took CI past its
	// timeout on 2026-08-31. See conformance.testDSN for the measurement.
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "gloak.db")+"?_pragma=synchronous(off)")
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

// withRealm returns a bootstrapped store with a second realm created through
// CreateRealm, which is the path POST /admin/realms takes.
func withRealm(t *testing.T, name string) (store.Store, *model.Realm, *model.Realm) {
	t.Helper()
	s, master := bootstrapped(t)
	created, err := bootstrap.CreateRealm(context.Background(), s, name, nil)
	if err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}
	return s, master, created
}

func clientRoleNames(t *testing.T, s store.Store, realmID, clientID string) []string {
	t.Helper()
	c, err := s.Clients().ByClientID(context.Background(), realmID, clientID)
	if err != nil {
		t.Fatalf("ByClientID %s: %v", clientID, err)
	}
	roles, err := s.Roles().ListClientRoles(context.Background(), realmID, c.ID)
	if err != nil {
		t.Fatalf("ListClientRoles %s: %v", clientID, err)
	}
	out := names(roles)
	sort.Strings(out)
	return out
}

// TestCreateRealmMakesTheSixClients pins the six a created realm carries. Five
// of them are master's; the sixth is realm-management where master has
// master-realm, and getting that wrong is the privilege-escalation trap
// internal/admin's ownedByRealmOwnClient warns about.
func TestCreateRealmMakesTheSixClients(t *testing.T) {
	s, _, created := withRealm(t, "other")

	clients, err := s.Clients().ListByRealm(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	got := make([]string, 0, len(clients))
	for _, c := range clients {
		got = append(got, c.ClientID)
	}
	sort.Strings(got)
	want := []string{"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}
	if !slices.Equal(got, want) {
		t.Fatalf("clients = %v, want %v", got, want)
	}
	if slices.Contains(got, "master-realm") {
		t.Error("a created realm carries master-realm; measured absent")
	}
}

// TestCreateRealmCarriesTheRealmNameInThreeURLs pins the three clients whose
// URLs are not constants. Copying master's would give every realm links into
// master's account and console pages.
func TestCreateRealmCarriesTheRealmNameInThreeURLs(t *testing.T) {
	s, _, created := withRealm(t, "other")
	ctx := context.Background()

	for _, tc := range []struct{ client, base, redirect string }{
		{"account", "/realms/other/account/", "/realms/other/account/*"},
		{"account-console", "/realms/other/account/", "/realms/other/account/*"},
		{"security-admin-console", "/admin/other/console/", "/admin/other/console/*"},
	} {
		c, err := s.Clients().ByClientID(ctx, created.ID, tc.client)
		if err != nil {
			t.Fatalf("ByClientID %s: %v", tc.client, err)
		}
		if c.BaseURL != tc.base {
			t.Errorf("%s baseUrl = %q, want %q", tc.client, c.BaseURL, tc.base)
		}
		if !slices.Contains(c.RedirectURIs, tc.redirect) {
			t.Errorf("%s redirectUris = %v, want %q", tc.client, c.RedirectURIs, tc.redirect)
		}
	}
}

// TestCreateRealmMakesThreeRealmRoles: admin and create-realm exist in master
// alone. Giving every realm master's five would hand every realm the right to
// create realms.
func TestCreateRealmMakesThreeRealmRoles(t *testing.T) {
	s, _, created := withRealm(t, "other")

	roles, err := s.Roles().ListRealmRoles(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	got := names(roles)
	sort.Strings(got)
	want := []string{"default-roles-other", "offline_access", "uma_authorization"}
	if !slices.Equal(got, want) {
		t.Fatalf("realm roles = %v, want %v", got, want)
	}
}

// TestRealmManagementHasTwentyTwoRoles is the count that distinguishes the two
// containers: 22 inside a realm, 21 in master. realm-admin is the difference,
// and it is composite over the other 21.
func TestRealmManagementHasTwentyTwoRoles(t *testing.T) {
	s, master, created := withRealm(t, "other")
	ctx := context.Background()

	inRealm := clientRoleNames(t, s, created.ID, "realm-management")
	if len(inRealm) != 22 {
		t.Fatalf("realm-management has %d roles, want 22: %v", len(inRealm), inRealm)
	}
	if !slices.Contains(inRealm, "realm-admin") {
		t.Error("realm-management has no realm-admin")
	}

	inMaster := clientRoleNames(t, s, master.ID, "master-realm")
	if len(inMaster) != 21 {
		t.Fatalf("master-realm has %d roles, want 21", len(inMaster))
	}
	if slices.Contains(inMaster, "realm-admin") {
		t.Error("master-realm has realm-admin; measured absent")
	}

	c, err := s.Clients().ByClientID(ctx, created.ID, "realm-management")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	realmAdmin, err := s.Roles().ByName(ctx, created.ID, c.ID, "realm-admin")
	if err != nil {
		t.Fatalf("ByName realm-admin: %v", err)
	}
	children, err := s.Roles().ListComposites(ctx, realmAdmin.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}
	if len(children) != 21 {
		t.Fatalf("realm-admin is composite over %d, want 21", len(children))
	}
	if !realmAdmin.Composite {
		t.Error("realm-admin is not marked composite")
	}
}

// TestCreateRealmAddsAContainerToMaster is the half of realm creation that
// happens outside the realm: a {realm}-realm client in master with 21 roles,
// empty scope lists and a prose name.
func TestCreateRealmAddsAContainerToMaster(t *testing.T) {
	s, master, _ := withRealm(t, "other")
	ctx := context.Background()

	c, err := s.Clients().ByClientID(ctx, master.ID, "other-realm")
	if err != nil {
		t.Fatalf("ByClientID other-realm: %v", err)
	}
	if c.Name != "other Realm" {
		t.Errorf("name = %q, want %q", c.Name, "other Realm")
	}
	if c.Protocol != "" {
		t.Errorf("protocol = %q, want empty", c.Protocol)
	}
	if len(c.DefaultClientScopes) != 0 || len(c.OptionalClientScopes) != 0 {
		t.Errorf("scopes = %v / %v, want both empty", c.DefaultClientScopes, c.OptionalClientScopes)
	}
	if !c.BearerOnly {
		t.Error("not bearer-only")
	}

	roles := clientRoleNames(t, s, master.ID, "other-realm")
	if len(roles) != 21 {
		t.Fatalf("other-realm has %d roles, want 21: %v", len(roles), roles)
	}
	if slices.Contains(roles, "realm-admin") {
		t.Error("other-realm has realm-admin; measured absent from this container")
	}
}

// TestCreateRealmExtendsMastersAdminRole is the measured edit to an object that
// already exists: master's admin realm role went from 22 composites to 43 when
// one realm was created. It is the reason this package's boundary in AGENTS.md
// had to be rewritten.
func TestCreateRealmExtendsMastersAdminRole(t *testing.T) {
	s, master := bootstrapped(t)
	ctx := context.Background()

	before := adminComposites(t, s, master.ID)
	if before != 22 {
		t.Fatalf("admin starts with %d composites, want 22", before)
	}

	if _, err := bootstrap.CreateRealm(ctx, s, "other", nil); err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}
	after := adminComposites(t, s, master.ID)
	if after != 43 {
		t.Fatalf("admin has %d composites after one realm, want 43", after)
	}

	if _, err := bootstrap.CreateRealm(ctx, s, "third", nil); err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}
	if got := adminComposites(t, s, master.ID); got != 64 {
		t.Fatalf("admin has %d composites after two realms, want 64", got)
	}
}

// TestDeleteRealmTakesTheCompositesBackOut is the inverse, and it is the one
// that F29 would otherwise break: keycloak_role has no foreign key to client,
// so deleting the container client alone would leave 21 orphan roles still
// listed in master's admin composite.
func TestDeleteRealmTakesTheCompositesBackOut(t *testing.T) {
	s, master, created := withRealm(t, "other")
	ctx := context.Background()

	if got := adminComposites(t, s, master.ID); got != 43 {
		t.Fatalf("admin has %d composites, want 43", got)
	}

	if err := bootstrap.DeleteRealm(ctx, s, created); err != nil {
		t.Fatalf("DeleteRealm: %v", err)
	}

	if got := adminComposites(t, s, master.ID); got != 22 {
		t.Fatalf("admin has %d composites after the delete, want 22", got)
	}
	if _, err := s.Clients().ByClientID(ctx, master.ID, "other-realm"); err == nil {
		t.Error("other-realm survived the delete")
	}
	if _, err := s.Realms().ByName(ctx, "other"); err == nil {
		t.Error("the realm survived the delete")
	}
}

// TestDeleteRealmRefusesMaster: measured 400 "Can't remove master realm".
func TestDeleteRealmRefusesMaster(t *testing.T) {
	s, master := bootstrapped(t)

	if err := bootstrap.DeleteRealm(context.Background(), s, master); err == nil {
		t.Fatal("master was deleted")
	}
}

// TestCreateRealmIsIdempotent: it converges rather than short-circuiting, for
// the same reason EnsureMaster does. Two calls must not double master's admin
// composites.
func TestCreateRealmIsIdempotent(t *testing.T) {
	s, master, _ := withRealm(t, "other")
	ctx := context.Background()

	if _, err := bootstrap.CreateRealm(ctx, s, "other", nil); err != nil {
		t.Fatalf("second CreateRealm: %v", err)
	}

	if got := adminComposites(t, s, master.ID); got != 43 {
		t.Fatalf("admin has %d composites after two calls, want 43", got)
	}
	if got := clientRoleNames(t, s, master.ID, "other-realm"); len(got) != 21 {
		t.Fatalf("other-realm has %d roles, want 21", len(got))
	}
}

// TestCreateRealmWiresDefaultRoles: default-roles-{realm} is what puts account
// in every token's aud, and a realm whose users hold no roles issues tokens
// with no audience at all.
func TestCreateRealmWiresDefaultRoles(t *testing.T) {
	s, _, created := withRealm(t, "other")
	ctx := context.Background()

	role, err := s.Roles().ByName(ctx, created.ID, "", "default-roles-other")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	children, err := s.Roles().ListComposites(ctx, role.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}
	got := names(children)
	sort.Strings(got)
	want := []string{"manage-account", "offline_access", "uma_authorization", "view-profile"}
	if !slices.Equal(got, want) {
		t.Fatalf("default-roles-other = %v, want %v", got, want)
	}
}

func adminComposites(t *testing.T, s store.Store, masterID string) int {
	t.Helper()
	ctx := context.Background()
	admin, err := s.Roles().ByName(ctx, masterID, "", "admin")
	if err != nil {
		t.Fatalf("ByName admin: %v", err)
	}
	children, err := s.Roles().ListComposites(ctx, admin.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}
	return len(children)
}
