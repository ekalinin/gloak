package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The question P4 turns on: do a caller's rights in one realm reach another?
//
// Measured 2026-08-29 and recorded under "Rights are resolved against one
// container, chosen by the token's realm" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. Two containers,
// and which one a request reads is decided by the realm that **issued the
// token**, not by the realm in the path.

// secondRealm creates a realm through bootstrap.CreateRealm, which is the path
// POST /admin/realms takes, and returns it.
func secondRealm(t *testing.T, s store.Store, name string) *model.Realm {
	t.Helper()
	realm, err := bootstrap.CreateRealm(context.Background(), s, name, &model.Realm{
		Name: name, Enabled: true,
		AccessTokenLifespan:  60_000_000_000,
		RefreshTokenLifespan: 1_800_000_000_000,
	})
	if err != nil {
		t.Fatalf("CreateRealm(%s): %v", name, err)
	}
	return realm
}

// tokenInRealm is tokenFor against a realm that is not master. The protocol
// side is realm-parameterised already, so this is the same request with a
// different path.
func tokenInRealm(t *testing.T, h http.Handler, realm, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {username},
		"password":   {password},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token request for %q in %q: %d %s", username, realm, w.Code, w.Body)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body.AccessToken
}

// tokenForContainerRole creates a user in userRealm holding exactly one role of
// one client, and returns a token for it. It is tokenForRole with the container
// named, which is the whole point of these tests.
func tokenForContainerRole(t *testing.T, h http.Handler, s store.Store, userRealm *model.Realm, username, container, role string) string {
	t.Helper()
	ctx := context.Background()
	u := createUserWithPassword(t, s, userRealm, username, "pw")
	c, err := s.Clients().ByClientID(ctx, userRealm.ID, container)
	if err != nil {
		t.Fatalf("ByClientID(%s in %s): %v", container, userRealm.Name, err)
	}
	r, err := s.Roles().ByName(ctx, userRealm.ID, c.ID, role)
	if err != nil {
		t.Fatalf("ByName(%s on %s): %v", role, container, err)
	}
	if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
	return tokenInRealm(t, h, userRealm.Name, username, "pw")
}

// TestAMasterRoleDoesNotReachAnotherRealmsUsers is the measurement that says
// the container is chosen by the pair of realms and not by the path alone.
//
// A caller holding view-users on master-realm reads master's users and is 403
// on the other realm's; the same caller shape holding it on other-realm is the
// mirror. Reading the path realm's container for both would open each of them
// on the wrong realm.
func TestAMasterRoleDoesNotReachAnotherRealmsUsers(t *testing.T) {
	h, s, master := newServer(t)
	secondRealm(t, s, "other")

	onMaster := tokenForContainerRole(t, h, s, master, "m-on-master", "master-realm", "view-users")
	onOther := tokenForContainerRole(t, h, s, master, "m-on-other", "other-realm", "view-users")

	for _, tc := range []struct {
		name, token, path string
		want              int
	}{
		{"master-realm role on master's users", onMaster, "/admin/realms/master/users", http.StatusOK},
		{"master-realm role on the other realm's users", onMaster, "/admin/realms/other/users", http.StatusForbidden},
		{"other-realm role on the other realm's users", onOther, "/admin/realms/other/users", http.StatusOK},
		{"other-realm role on master's users", onOther, "/admin/realms/master/users", http.StatusForbidden},
	} {
		if w := get(t, h, tc.path, tc.token); w.Code != tc.want {
			t.Errorf("%s: want %d, got %d: %s", tc.name, tc.want, w.Code, w.Body)
		}
	}
}

// TestARealmsOwnAdminCannotReachAnother: nothing reaches upwards or sideways
// from a non-master realm. realm-admin is the strongest role such a realm has
// and it is 403 on master, measured.
func TestARealmsOwnAdminCannotReachAnother(t *testing.T) {
	h, s, _ := newServer(t)
	other := secondRealm(t, s, "other")
	secondRealm(t, s, "third")

	caller := tokenForContainerRole(t, h, s, other, "o-admin", "realm-management", "realm-admin")

	if w := get(t, h, "/admin/realms/other/users", caller); w.Code != http.StatusOK {
		t.Errorf("its own realm: want 200, got %d: %s", w.Code, w.Body)
	}
	for _, path := range []string{"/admin/realms/master/users", "/admin/realms/third/users"} {
		if w := get(t, h, path, caller); w.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d: %s", path, w.Code, w.Body)
		}
	}
}

// TestRealmAdminIsCompositeOverTheOtherTwentyOne: a caller holding only
// realm-admin gets every route in its realm, because the role is composite over
// the 21 and internal/roles expands it. Without the expansion it would open
// nothing at all, since no route names realm-admin.
func TestRealmAdminIsCompositeOverTheOtherTwentyOne(t *testing.T) {
	h, s, _ := newServer(t)
	other := secondRealm(t, s, "other")
	caller := tokenForContainerRole(t, h, s, other, "o-admin", "realm-management", "realm-admin")

	for _, path := range []string{
		"/admin/realms/other/users",
		"/admin/realms/other/clients",
		"/admin/realms/other/roles",
		"/admin/realms/other/groups",
	} {
		if w := get(t, h, path, caller); w.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d: %s", path, w.Code, w.Body)
		}
	}
}

// TestAnotherRealmsAdminRolesAreNotGrantableByName is the escalation
// ownedByRealmOwnClient's comment warned about, closed.
//
// Before realm creation, that predicate compared a role's owning client against
// "{realm}-realm" and nothing else, so realm-management's 22 roles - and the
// {realm}-realm clients master gains per realm - would have answered "not an
// admin role" and been grantable to any caller holding manage-users.
//
// Measured on the same four cells: a manage-users caller is 403 assigning
// other-realm's manage-realm **and** its view-users, although its own
// master-realm manage-users confers a view-users, and its available list for
// other-realm is empty.
func TestAnotherRealmsAdminRolesAreNotGrantableByName(t *testing.T) {
	h, s, master := newServer(t)
	secondRealm(t, s, "other")
	ctx := context.Background()

	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, master, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"subject","enabled":true}`, admin)
	subject := userID(t, s, master, "subject")

	otherRealm := clientUUID(t, s, master, "other-realm")
	base := "/admin/realms/master/users/" + subject + "/role-mappings/clients/" + otherRealm

	for _, role := range []string{"manage-realm", "view-users"} {
		c, err := s.Clients().ByClientID(ctx, master.ID, "other-realm")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}
		r, err := s.Roles().ByName(ctx, master.ID, c.ID, role)
		if err != nil {
			t.Fatalf("ByName(%s): %v", role, err)
		}
		body := `[{"id":"` + r.ID + `","name":"` + role + `"}]`
		if w := postJSON(t, h, base, body, caller); w.Code != http.StatusForbidden {
			t.Errorf("granting other-realm/%s: want 403, got %d: %s", role, w.Code, w.Body)
		}
	}

	if got := mappingNames(t, h, base+"/available", caller); len(got) != 0 {
		t.Errorf("available on another realm's container: want none, got %v", got)
	}
}

// TestARolesOwnContainerConfersItAcrossRealms is the other half, and it is why
// the refusal above is not simply "any foreign admin role".
//
// A full administrator reaches all 21 of every {realm}-realm client through the
// admin composite, and Keycloak lets it hand them out - measured 204 assigning
// other-realm/manage-realm and twenty available afterwards. Refusing every
// foreign container would have been the safe-looking answer and the wrong one.
func TestARolesOwnContainerConfersItAcrossRealms(t *testing.T) {
	h, s, master := newServer(t)
	secondRealm(t, s, "other")
	ctx := context.Background()

	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"subject","enabled":true}`, admin)
	subject := userID(t, s, master, "subject")

	otherRealm := clientUUID(t, s, master, "other-realm")
	base := "/admin/realms/master/users/" + subject + "/role-mappings/clients/" + otherRealm
	c, err := s.Clients().ByClientID(ctx, master.ID, "other-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	r, err := s.Roles().ByName(ctx, master.ID, c.ID, "manage-realm")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	body := `[{"id":"` + r.ID + `","name":"manage-realm"}]`
	if w := postJSON(t, h, base, body, admin); w.Code != http.StatusNoContent {
		t.Fatalf("the full administrator: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := mappingNames(t, h, base+"/available", admin); len(got) != 20 {
		t.Errorf("available afterwards: want 20, got %d: %v", len(got), got)
	}
}

// TestARealmsOwnContainerIsNotConfigurable pins the access block on both
// spellings and on the suffix. Measured on seven clients across two realms:
// master-realm, other-realm and a hand-made nosuch-realm are all
// "configure":false in master, realm-management is in a created realm, and
// broker is fully manageable in both although it carries realm_client "true".
func TestARealmsOwnContainerIsNotConfigurable(t *testing.T) {
	h, s, _ := newServer(t)
	secondRealm(t, s, "other")
	admin := tokenFor(t, h, "admin", "admin")

	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"nosuch-realm"}`, admin)

	for _, tc := range []struct {
		realm, client string
		configurable  bool
	}{
		{"master", "master-realm", false},
		{"master", "other-realm", false},
		{"master", "nosuch-realm", false},
		{"master", "broker", true},
		{"master", "account", true},
		{"other", "realm-management", false},
		{"other", "broker", true},
	} {
		w := get(t, h, "/admin/realms/"+tc.realm+"/clients?clientId="+tc.client, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s/%s: %d %s", tc.realm, tc.client, w.Code, w.Body)
		}
		var got []clientRepresentation
		if err := decodeJSON(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("%s/%s: %d clients", tc.realm, tc.client, len(got))
		}
		if got[0].Access.Configure != tc.configurable {
			t.Errorf("%s/%s configure = %v, want %v", tc.realm, tc.client, got[0].Access.Configure, tc.configurable)
		}
	}
}

// TestASecondRealmDoesNotDisturbMaster is the check every conformance case with
// PristineRealm depends on: creating a realm adds a client and 21 composites to
// master and touches nothing else.
func TestASecondRealmDoesNotDisturbMaster(t *testing.T) {
	h, s, master := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	before := listNames(t, h, "/admin/realms/master/clients", admin)

	secondRealm(t, s, "other")

	after := listNames(t, h, "/admin/realms/master/clients", admin)
	slices.Sort(before)
	slices.Sort(after)
	want := append(append([]string{}, before...), "other-realm")
	slices.Sort(want)
	if !slices.Equal(after, want) {
		t.Fatalf("master's clients = %v, want %v", after, want)
	}

	// The realm roles and the users are untouched. Only admin's composite grew.
	roles, err := s.Roles().ListRealmRoles(context.Background(), master.ID)
	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	if len(roles) != 5 {
		t.Errorf("master's realm roles = %d, want 5: %v", len(roles), roles)
	}
}

func listNames(t *testing.T, h http.Handler, path, token string) []string {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var got []clientRepresentation
	if err := decodeJSON(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := make([]string, 0, len(got))
	for _, c := range got {
		out = append(out, c.ClientID)
	}
	return out
}
