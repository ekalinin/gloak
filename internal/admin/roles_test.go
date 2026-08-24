package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// Two serialisations, measured. A listing carries six keys and a single read
// seven, the seventh being attributes. See the "Roles" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func TestRoleRepresentationHasTwoShapes(t *testing.T) {
	r := &model.Role{
		ID: "rid", Name: "admin", Description: "${role_admin}", Composite: true,
		Attributes: map[string][]string{"k": {"v"}},
	}

	brief, err := json.Marshal(roleRepresentationOf(r, "realm-uuid", true))
	if err != nil {
		t.Fatalf("marshal brief: %v", err)
	}
	want := `{"id":"rid","name":"admin","description":"${role_admin}","composite":true,"clientRole":false,"containerId":"realm-uuid"}`
	if string(brief) != want {
		t.Fatalf("brief:\nwant %s\ngot  %s", want, brief)
	}

	full, err := json.Marshal(roleRepresentationOf(r, "realm-uuid", false))
	if err != nil {
		t.Fatalf("marshal full: %v", err)
	}
	want = `{"id":"rid","name":"admin","description":"${role_admin}","composite":true,"clientRole":false,"containerId":"realm-uuid","attributes":{"k":["v"]}}`
	if string(full) != want {
		t.Fatalf("full:\nwant %s\ngot  %s", want, full)
	}
}

// A role with no description omits the key rather than sending "". Measured on
// a role created with only a name.
func TestRoleDescriptionIsAbsentWhenUnset(t *testing.T) {
	got, err := json.Marshal(roleRepresentationOf(&model.Role{ID: "rid", Name: "probe"}, "realm-uuid", true))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":"rid","name":"probe","composite":false,"clientRole":false,"containerId":"realm-uuid"}`
	if string(got) != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

// A role with no attributes still sends {} on a full read, because the key is
// present whenever it is asked for. Measured on `admin`, which has none.
func TestRoleAttributesAreEmptyObjectNotNull(t *testing.T) {
	got, err := json.Marshal(roleRepresentationOf(&model.Role{ID: "rid", Name: "probe"}, "c", false))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"attributes":{}`; !strings.Contains(string(got), want) {
		t.Fatalf("want %s in %s", want, got)
	}
}

// **The default is the brief shape here and the full one on the user
// listing.** Same parameter, two endpoints, opposite defaults - measured on
// both. A shared helper would get one of them wrong.
func TestBriefRolesDefaultsToTrue(t *testing.T) {
	for query, want := range map[string]bool{
		"":                          true,
		"briefRepresentation=true":  true,
		"briefRepresentation=false": false,
		"briefRepresentation=":      true,
	} {
		q, err := url.ParseQuery(query)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", query, err)
		}
		if got := briefRoles(q); got != want {
			t.Fatalf("briefRoles(%q): want %v, got %v", query, want, got)
		}
	}
}

func TestListRealmRolesIsBriefAndFiltered(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/roles", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json;charset=UTF-8" {
		t.Fatalf("want the charset Content-Type, got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("want Cache-Control no-cache, got %q", cc)
	}
	var brief []map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &brief); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(brief) != 5 {
		t.Fatalf("want the five bootstrapped realm roles, got %d", len(brief))
	}
	if _, ok := brief[0]["attributes"]; ok {
		t.Fatal("the listing sent attributes; its briefRepresentation defaults to true")
	}

	full := get(t, h, "/admin/realms/master/roles?briefRepresentation=false", admin)
	var rich []map[string]json.RawMessage
	if err := json.Unmarshal(full.Body.Bytes(), &rich); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := rich[0]["attributes"]; !ok {
		t.Fatal("briefRepresentation=false did not add attributes")
	}
}

// search is a case-insensitive substring over the name **and the
// description**. Three queries, each ruling out one simpler rule - see the
// "Roles" section of the observed-behaviour document.
func TestRealmRoleSearchIsASubstringOverNameAndDescription(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct {
		query string
		want  []string
		why   string
	}{
		{"adm", []string{"admin"}, "a prefix of the name"},
		{"ADM", []string{"admin"}, "case-insensitive"},
		{"ealm", []string{"create-realm"}, "inside the name, so not a prefix match"},
		{"{role_default-roles}", []string{"default-roles-master"}, "the description only, so not name-only"},
		{"nothing-matches-this", nil, "a filter matching nothing is 200 and []"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			w := get(t, h, "/admin/realms/master/roles?search="+url.QueryEscape(tc.query), admin)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
			}
			var got []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("parse: %v", err)
			}
			names := make([]string, 0, len(got))
			for _, r := range got {
				names = append(names, r.Name)
			}
			sort.Strings(names)
			if !slices.Equal(names, tc.want) {
				t.Fatalf("%s: want %v, got %v", tc.why, tc.want, names)
			}
		})
	}
}

func TestReadRealmRole(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/roles/admin", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var rep map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := rep["attributes"]; !ok {
		t.Fatal("a single read must carry attributes")
	}

	missing := get(t, h, "/admin/realms/master/roles/no-such-role", admin)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", missing.Code)
	}
	if body := missing.Body.String(); body != `{"error":"Could not find role"}` {
		t.Fatalf("unexpected 404 body: %s", body)
	}
}

// view-realm reads; nothing else does. Measured across eight single-role
// callers - view-users, manage-users, view-clients, manage-clients,
// query-clients and query-users are all 403 here.
func TestRealmRoleReadNeedsViewRealm(t *testing.T) {
	h, s, realm := newServer(t)
	for role, want := range map[string]int{
		"view-realm":   http.StatusOK,
		"manage-realm": http.StatusOK,
		"view-clients": http.StatusForbidden,
		"view-users":   http.StatusForbidden,
		"query-users":  http.StatusForbidden,
	} {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if got := get(t, h, "/admin/realms/master/roles", tok).Code; got != want {
				t.Fatalf("%s: want %d, got %d", role, want, got)
			}
		})
	}
}

func TestCreateRealmRole(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-role"}`, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body)
	}
	// Measured: Location names the role by **name**, where the client and user
	// creates both put a UUID there.
	if loc := w.Header().Get("Location"); loc != testIssuer+"/admin/realms/master/roles/probe-role" {
		t.Fatalf("unexpected Location: %q", loc)
	}
	if cl := w.Header().Get("Content-Length"); cl != "0" {
		t.Fatalf("want Content-Length 0, got %q", cl)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("want an empty body, got %q", w.Body)
	}

	dup := postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-role"}`, admin)
	if dup.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", dup.Code)
	}
	if body := dup.Body.String(); body != `{"errorMessage":"Role with name probe-role already exists"}` {
		t.Fatalf("unexpected 409 body: %s", body)
	}

	// Three error families on one endpoint, all measured: errorMessage for the
	// conflict, a bare lowercase error for the missing name.
	noName := postJSON(t, h, "/admin/realms/master/roles", `{}`, admin)
	if noName.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", noName.Code)
	}
	if body := noName.Body.String(); body != `{"error":"role has no name"}` {
		t.Fatalf("unexpected 400 body: %s", body)
	}
}

// **PUT replaces.** A body carrying only a name clears an existing
// description, which is the opposite of PUT on a client and PUT on a user.
// Measured directly.
func TestUpdateRealmRoleReplacesAndRenames(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles",
		`{"name":"probe-role","description":"before"}`, admin)
	before := readRole(t, h, "/admin/realms/master/roles/probe-role", admin)

	w := putJSON(t, h, "/admin/realms/master/roles/probe-role", `{"name":"probe-renamed"}`, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body)
	}

	if got := get(t, h, "/admin/realms/master/roles/probe-role", admin).Code; got != http.StatusNotFound {
		t.Fatalf("the old name still resolves: %d", got)
	}
	after := readRole(t, h, "/admin/realms/master/roles/probe-renamed", admin)
	if after.ID != before.ID {
		t.Fatalf("the rename minted a new id: %s then %s", before.ID, after.ID)
	}
	if after.Description != "" {
		t.Fatalf("PUT merged instead of replacing: description is still %q", after.Description)
	}

	noName := putJSON(t, h, "/admin/realms/master/roles/probe-renamed", `{"description":"x"}`, admin)
	if noName.Code != http.StatusBadRequest || noName.Body.String() != `{"error":"role has no name"}` {
		t.Fatalf("want 400 role has no name, got %d %s", noName.Code, noName.Body)
	}

	missing := putJSON(t, h, "/admin/realms/master/roles/no-such", `{"name":"no-such"}`, admin)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", missing.Code)
	}
}

func TestDeleteRealmRole(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-role"}`, admin)

	w := do(t, h, http.MethodDelete, "/admin/realms/master/roles/probe-role", admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("want Cache-Control no-cache, got %q", cc)
	}

	again := do(t, h, http.MethodDelete, "/admin/realms/master/roles/probe-role", admin)
	if again.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", again.Code)
	}
}

func TestRealmRoleWritesNeedManageRealm(t *testing.T) {
	h, s, realm := newServer(t)
	tok := tokenForRole(t, h, s, realm, "view-realm")

	if got := postJSON(t, h, "/admin/realms/master/roles", `{"name":"x"}`, tok).Code; got != http.StatusForbidden {
		t.Fatalf("view-realm created a role: %d", got)
	}
	if got := putJSON(t, h, "/admin/realms/master/roles/admin", `{"name":"admin"}`, tok).Code; got != http.StatusForbidden {
		t.Fatalf("view-realm updated a role: %d", got)
	}
}

// readRole is a typed read for the assertions above.
func readRole(t *testing.T, h http.Handler, path, token string) roleRepresentation {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("read %s: %d %s", path, w.Code, w.Body)
	}
	var rep roleRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return rep
}

func TestClientRolesMirrorRealmRolesWithTheirOwnGuards(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	uuid := clientUUID(t, s, realm, "probe-app")
	base := "/admin/realms/master/clients/" + uuid + "/roles"

	if got := postJSON(t, h, base, `{"name":"app-role"}`, admin).Code; got != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", got)
	}

	// clientRole is true and containerId is the client's UUID, not the realm's.
	rep := readRole(t, h, base+"/app-role", admin)
	if !rep.ClientRole {
		t.Fatal("clientRole is false on a client role")
	}
	if rep.ContainerID != uuid {
		t.Fatalf("containerId: want the client uuid %s, got %s", uuid, rep.ContainerID)
	}

	if got := putJSON(t, h, base+"/app-role", `{"name":"app-role"}`, admin).Code; got != http.StatusNoContent {
		t.Fatalf("update: want 204, got %d", got)
	}
	if got := do(t, h, http.MethodDelete, base+"/app-role", admin).Code; got != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", got)
	}

	// A missing client answers the client's 404, not the role's.
	missing := get(t, h, "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/roles", admin)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("want 404 for a missing client, got %d", missing.Code)
	}
}

func TestClientRolesUseTheClientsRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	base := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"

	// The view-clients token is kept for the write check below rather than
	// re-derived: tokenForRole mints a user named for the role, and asking for
	// "view-clients" a second time collides with the one the loop already made.
	var writer string
	for role, want := range map[string]int{
		"view-clients":   http.StatusOK,
		"manage-clients": http.StatusOK,
		"view-realm":     http.StatusForbidden,
		"manage-realm":   http.StatusForbidden,
	} {
		t.Run("read/"+role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if role == "view-clients" {
				writer = tok
			}
			if got := get(t, h, base, tok).Code; got != want {
				t.Fatalf("%s: want %d, got %d", role, want, got)
			}
		})
	}
	if got := postJSON(t, h, base, `{"name":"x"}`, writer).Code; got != http.StatusForbidden {
		t.Fatalf("view-clients created a client role: %d", got)
	}
}

// **The realm's own client takes no new roles from anybody**, measured with a
// full administrator. Same rule as "the realm's own client is never
// configurable".
func TestTheRealmsOwnClientRefusesNewRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "master-realm") + "/roles"

	if got := postJSON(t, h, base, `{"name":"admin-made-this"}`, admin).Code; got != http.StatusForbidden {
		t.Fatalf("want 403 from a full administrator, got %d", got)
	}
	// Reading them is still allowed - all 21 come back.
	if got := get(t, h, base, admin).Code; got != http.StatusOK {
		t.Fatalf("reading the realm client's roles: want 200, got %d", got)
	}
}

func clientUUID(t *testing.T, s store.Store, realm *model.Realm, clientID string) string {
	t.Helper()
	c, err := s.Clients().ByClientID(context.Background(), realm.ID, clientID)
	if err != nil {
		t.Fatalf("ByClientID(%s): %v", clientID, err)
	}
	return c.ID
}

func TestComposites(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/probe-child", admin)
	mrUUID := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mrUUID+"/roles/view-users", admin)

	body := `[{"id":"` + child.ID + `","name":"probe-child"},{"id":"` + viewUsers.ID + `","name":"view-users"}]`
	if got := postJSON(t, h, "/admin/realms/master/roles/probe-parent/composites", body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("add: want 204, got %d", got)
	}

	// The parent's own composite flag flips without being asked to.
	if !readRole(t, h, "/admin/realms/master/roles/probe-parent", admin).Composite {
		t.Fatal("the parent is not marked composite after gaining a child")
	}

	all := listRoleNames(t, h, "/admin/realms/master/roles/probe-parent/composites", admin)
	if !slices.Equal(all, []string{"probe-child", "view-users"}) {
		t.Fatalf("composites: want both children, got %v", all)
	}
	realmOnly := listRoleNames(t, h, "/admin/realms/master/roles/probe-parent/composites/realm", admin)
	if !slices.Equal(realmOnly, []string{"probe-child"}) {
		t.Fatalf("composites/realm: want the realm child only, got %v", realmOnly)
	}
	clientOnly := listRoleNames(t, h,
		"/admin/realms/master/roles/probe-parent/composites/clients/"+mrUUID, admin)
	if !slices.Equal(clientOnly, []string{"view-users"}) {
		t.Fatalf("composites/clients: want the client child only, got %v", clientOnly)
	}

	rm := `[{"id":"` + viewUsers.ID + `","name":"view-users"}]`
	if got := sendJSON(t, h, http.MethodDelete,
		"/admin/realms/master/roles/probe-parent/composites", rm, admin).Code; got != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d", got)
	}
	left := listRoleNames(t, h, "/admin/realms/master/roles/probe-parent/composites", admin)
	if !slices.Equal(left, []string{"probe-child"}) {
		t.Fatalf("after removal: want the realm child only, got %v", left)
	}

	// Removing one that is not there is still 204. Measured.
	if got := sendJSON(t, h, http.MethodDelete,
		"/admin/realms/master/roles/probe-parent/composites", rm, admin).Code; got != http.StatusNoContent {
		t.Fatalf("removing an absent composite: want 204, got %d", got)
	}
}

func TestClientRoleCompositesUseTheSameRoutes(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	uuid := clientUUID(t, s, realm, "probe-app")
	base := "/admin/realms/master/clients/" + uuid + "/roles"
	postJSON(t, h, base, `{"name":"app-parent"}`, admin)
	postJSON(t, h, base, `{"name":"app-child"}`, admin)
	child := readRole(t, h, base+"/app-child", admin)

	body := `[{"id":"` + child.ID + `","name":"app-child"}]`
	if got := postJSON(t, h, base+"/app-parent/composites", body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("add: want 204, got %d", got)
	}
	got := listRoleNames(t, h, base+"/app-parent/composites/clients/"+uuid, admin)
	if !slices.Equal(got, []string{"app-child"}) {
		t.Fatalf("want the client child, got %v", got)
	}
}

// listRoleNames reads a composite listing (or any role listing) and returns
// the names, sorted for a deterministic comparison. ListComposites already
// orders by name in both drivers, so this sort is belt and braces, not a
// correction.
func listRoleNames(t *testing.T, h http.Handler, path, token string) []string {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var reps []roleRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &reps); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := make([]string, 0, len(reps))
	for _, r := range reps {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// TestRealmRoleCompositeReadsAdmitViewOrManage measures what the brief could
// not: composite reads follow the same rule as the plain role reads next
// door, admitting either half of the pair rather than only the one the
// route's name suggests. Measured against a live 26.7.1: a caller holding
// only view-realm and one holding only manage-realm both get 200 on
// GET /roles/admin/composites; view-clients and manage-clients both get 403
// there. The client side mirrors it with view-clients/manage-clients.
func TestRealmRoleCompositeReadsAdmitViewOrManage(t *testing.T) {
	h, s, realm := newServer(t)
	for role, want := range map[string]int{
		"view-realm":     http.StatusOK,
		"manage-realm":   http.StatusOK,
		"view-clients":   http.StatusForbidden,
		"manage-clients": http.StatusForbidden,
	} {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if got := get(t, h, "/admin/realms/master/roles/admin/composites", tok).Code; got != want {
				t.Fatalf("%s: want %d, got %d", role, want, got)
			}
		})
	}
}

func TestClientRoleCompositeReadsAdmitViewOrManage(t *testing.T) {
	h, s, realm := newServer(t)
	mrUUID := clientUUID(t, s, realm, "master-realm")
	for role, want := range map[string]int{
		"view-clients":   http.StatusOK,
		"manage-clients": http.StatusOK,
		"view-realm":     http.StatusForbidden,
		"manage-realm":   http.StatusForbidden,
	} {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			path := "/admin/realms/master/clients/" + mrUUID + "/roles/view-users/composites"
			if got := get(t, h, path, tok).Code; got != want {
				t.Fatalf("%s: want %d, got %d", role, want, got)
			}
		})
	}
}

// TestCompositeWritesNeedManageAlone measures the write side: unlike the
// reads above, POST and DELETE .../composites admit only the manage role on
// either side, not view-realm/view-clients too. Measured against a live
// 26.7.1 the same way.
func TestCompositeWritesNeedManageAlone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"write-probe-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"write-probe-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/write-probe-child", admin)
	body := `[{"id":"` + child.ID + `","name":"write-probe-child"}]`

	for role, want := range map[string]int{
		"view-realm":     http.StatusForbidden,
		"view-clients":   http.StatusForbidden,
		"manage-clients": http.StatusForbidden,
		"manage-realm":   http.StatusNoContent,
	} {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if got := postJSON(t, h, "/admin/realms/master/roles/write-probe-parent/composites", body, tok).Code; got != want {
				t.Fatalf("%s: want %d, got %d", role, want, got)
			}
		})
	}
}
