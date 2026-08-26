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

// TestPageRoles pins pageRoles's measured contract: a listing pages when
// search is non-empty **or** when first and max are both present, and only a
// request carrying neither is answered unpaginated - see the "Role listing:
// first and max" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// Every row below is a query that was issued against a live 26.7.1. The rows
// that matter most are the four no-search ones with both bounds: an earlier
// version of this test asserted they came back whole, which was inferred from
// three probes that each sent only one bound.
func TestPageRoles(t *testing.T) {
	roles := []*model.Role{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	names := func(in []*model.Role) []string {
		out := make([]string, 0, len(in))
		for _, r := range in {
			out = append(out, r.Name)
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		query string
		want  []string
	}{
		{"no search: max alone is ignored", "max=2", []string{"a", "b", "c"}},
		{"no search: first alone is ignored", "first=1", []string{"a", "b", "c"}},
		{"no search: first and max together do page", "first=1&max=1", []string{"b"}},
		{"no search: both bounds, max only", "first=0&max=2", []string{"a", "b"}},
		{"no search: both bounds, first past the end", "first=99&max=2", []string{}},
		{"no search: both bounds, max zero is an empty page", "first=1&max=0", []string{}},
		{"no search: a negative first still opens the gate for max", "first=-1&max=2", []string{"a", "b"}},
		{"no search: a negative max still opens the gate for first", "first=1&max=-1", []string{"b", "c"}},
		{"no search: the admin client's no-paging convention pages with no bounds", "first=-1&max=-1", []string{"a", "b", "c"}},
		{"an empty search is not a search: max alone is ignored", "search=&max=2", []string{"a", "b", "c"}},
		{"an empty search with both bounds pages on the bounds alone", "search=&first=1&max=1", []string{"b"}},
		{"search with no first or max is unbounded", "search=x", []string{"a", "b", "c"}},
		{"search: max zero is an empty page", "search=x&max=0", []string{}},
		{"search: max bounds the page", "search=x&max=2", []string{"a", "b"}},
		{"search: first zero is a no-op offset", "search=x&first=0", []string{"a", "b", "c"}},
		{"search: first offsets from zero", "search=x&first=1", []string{"b", "c"}},
		{"search: first past the end", "search=x&first=3", []string{}},
		{"search: first and max compose", "search=x&first=1&max=1", []string{"b"}},
		{"search: negative max alone means absent", "search=x&max=-1", []string{"a", "b", "c"}},
		{"search: negative first alone means absent", "search=x&first=-1", []string{"a", "b", "c"}},
		{"search: negative first and max together means absent", "search=x&first=-1&max=-1", []string{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("bad query: %v", err)
			}
			got := names(pageRoles(roles, q))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("pageRoles(%q) = %v, want %v", tc.query, got, tc.want)
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

// **The refusal extends past creating a role: a composite write on a role the
// realm's own client already has is refused too**, to the full administrator
// and on both verbs. Measured against a live 26.7.1 on `master-realm`'s own
// `query-groups` role - `POST .../composites` 403, `DELETE .../composites`
// 403, `GET .../composites` 200.
//
// Both route families are exercised, and that is the point of the test rather
// than thoroughness for its own sake: the by-name routes reach the check
// through clientRoleLocator, the roles-by-id routes never touch
// clientRoleContainer at all - guardByRoleContainer resolves the role itself
// and hands it to byIDLocator - so a check placed in clientRoleContainer would
// pass the first half of this test and fail the second.
func TestTheRealmsOwnClientRefusesCompositeWrites(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	mrUUID := clientUUID(t, s, realm, "master-realm")

	postJSON(t, h, "/admin/realms/master/roles", `{"name":"escalation-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/escalation-child", admin)
	body := `[{"id":"` + child.ID + `","name":"escalation-child"}]`

	byName := "/admin/realms/master/clients/" + mrUUID + "/roles/query-groups/composites"
	victim := readRole(t, h, "/admin/realms/master/clients/"+mrUUID+"/roles/query-groups", admin)
	byID := "/admin/realms/master/roles-by-id/" + victim.ID + "/composites"

	for _, tc := range []struct{ name, path string }{
		{"by name", byName},
		{"by id", byID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := postJSON(t, h, tc.path, body, admin).Code; got != http.StatusForbidden {
				t.Fatalf("POST %s: want 403 from a full administrator, got %d", tc.path, got)
			}
			if got := sendJSON(t, h, http.MethodDelete, tc.path, body, admin).Code; got != http.StatusForbidden {
				t.Fatalf("DELETE %s: want 403 from a full administrator, got %d", tc.path, got)
			}
			// Reading the same role's composites is not refused - measured 200.
			if got := get(t, h, tc.path, admin).Code; got != http.StatusOK {
				t.Fatalf("GET %s: want 200, got %d", tc.path, got)
			}
		})
	}

	// The escalation this closes: a manage-clients-only caller naming a
	// *realm* management role as the child. Every other check passes - the
	// route guard wants manage-clients, and requiresChildManageRole would want
	// manage-clients too if the child were a client role - so without the
	// container check this is the whole path from manage-clients to
	// manage-realm.
	manageRealm := readRole(t, h, "/admin/realms/master/clients/"+mrUUID+"/roles/manage-realm", admin)
	escalate := `[{"id":"` + manageRealm.ID + `","name":"manage-realm"}]`
	writer := tokenForRole(t, h, s, realm, "manage-clients")
	target := "/admin/realms/master/clients/" + mrUUID + "/roles/manage-clients/composites"
	if got := postJSON(t, h, target, escalate, writer).Code; got != http.StatusForbidden {
		t.Fatalf("manage-clients escalating to manage-realm: want 403, got %d", got)
	}
	if got := listRoleNames(t, h, target, admin); len(got) != 0 {
		t.Fatalf("manage-clients gained composites: %v", got)
	}

	// An ordinary client's roles are untouched by any of this.
	postJSON(t, h, "/admin/realms/master/clients",
		`{"clientId":"ordinary-client"}`, admin)
	ordinary := clientUUID(t, s, realm, "ordinary-client")
	postJSON(t, h, "/admin/realms/master/clients/"+ordinary+"/roles", `{"name":"ordinary-role"}`, admin)
	ok := "/admin/realms/master/clients/" + ordinary + "/roles/ordinary-role/composites"
	if got := postJSON(t, h, ok, body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("an ordinary client's role: want 204, got %d", got)
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

// TestCompositeFlagFollowsChildCount measures the direction TestComposites
// does not: composite is derived from whether the role currently has any
// children, not latched true once set. Measured directly on a live Keycloak,
// on the very role whose last child is removed: it reads composite:false
// again immediately afterward.
func TestCompositeFlagFollowsChildCount(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"flag-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"flag-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/flag-child", admin)

	body := `[{"id":"` + child.ID + `","name":"flag-child"}]`
	if got := postJSON(t, h, "/admin/realms/master/roles/flag-parent/composites", body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("add: want 204, got %d", got)
	}
	if !readRole(t, h, "/admin/realms/master/roles/flag-parent", admin).Composite {
		t.Fatal("the parent is not marked composite after gaining its only child")
	}

	if got := sendJSON(t, h, http.MethodDelete,
		"/admin/realms/master/roles/flag-parent/composites", body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d", got)
	}
	if readRole(t, h, "/admin/realms/master/roles/flag-parent", admin).Composite {
		t.Fatal("the parent is still marked composite after losing its last child")
	}
}

// TestCompositeFlagSurvivesDeletingTheChild is the third way a role can lose
// its last child, after the two TestCompositeFlagFollowsChildCount covers:
// deleting the child role outright. The composite_role row cascades away, but
// `composite` is a column on the *parent*, so nothing on the delete path would
// resync it - the parent would answer `"composite":true` beside an empty
// composites listing, contradicting the derived-flag rule this cut measured.
//
// All three delete routes are exercised because all three used to be able to
// leave the flag stale; they are all fixed by one resync inside
// store.RoleRepo.Delete rather than by three edits here.
func TestCompositeFlagSurvivesDeletingTheChild(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"delete-probe-client"}`, admin)
	ordinary := clientUUID(t, s, realm, "delete-probe-client")

	for _, tc := range []struct {
		name       string
		createPath string
		deletePath func(name, id string) string
	}{
		{
			name:       "realm role by name",
			createPath: "/admin/realms/master/roles",
			deletePath: func(name, _ string) string { return "/admin/realms/master/roles/" + name },
		},
		{
			name:       "client role by name",
			createPath: "/admin/realms/master/clients/" + ordinary + "/roles",
			deletePath: func(name, _ string) string {
				return "/admin/realms/master/clients/" + ordinary + "/roles/" + name
			},
		},
		{
			name:       "role by id",
			createPath: "/admin/realms/master/roles",
			deletePath: func(_, id string) string { return "/admin/realms/master/roles-by-id/" + id },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := "dp-" + strings.ReplaceAll(tc.name, " ", "-")
			child := parent + "-child"
			postJSON(t, h, "/admin/realms/master/roles", `{"name":"`+parent+`"}`, admin)
			postJSON(t, h, tc.createPath, `{"name":"`+child+`"}`, admin)

			readChild := tc.createPath + "/" + child
			if tc.createPath == "/admin/realms/master/roles" {
				readChild = "/admin/realms/master/roles/" + child
			}
			kid := readRole(t, h, readChild, admin)
			body := `[{"id":"` + kid.ID + `","name":"` + child + `"}]`
			if got := postJSON(t, h, "/admin/realms/master/roles/"+parent+"/composites", body, admin).Code; got != http.StatusNoContent {
				t.Fatalf("add: want 204, got %d", got)
			}
			if !readRole(t, h, "/admin/realms/master/roles/"+parent, admin).Composite {
				t.Fatal("precondition: the parent is not composite after gaining its only child")
			}

			if got := sendJSON(t, h, http.MethodDelete, tc.deletePath(child, kid.ID), "", admin).Code; got != http.StatusNoContent {
				t.Fatalf("delete the child: want 204, got %d", got)
			}
			// The two answers have to agree. Before the resync in Delete, the
			// first said true and the second said [].
			if readRole(t, h, "/admin/realms/master/roles/"+parent, admin).Composite {
				t.Fatal("the parent is still marked composite after its last child was deleted")
			}
			if got := listRoleNames(t, h, "/admin/realms/master/roles/"+parent+"/composites", admin); len(got) != 0 {
				t.Fatalf("want no composites left, got %v", got)
			}
		})
	}
}

// TestCompositeAddRollsBackOnABadID measures the batch behaviour
// TestCompositeFlagFollowsChildCount does not exercise: a body with one real
// role id and one that does not exist. Measured on a live Keycloak, in both
// id orders, this answers 404 `{"error":"Could not find composite role"}`
// and applies **nothing** - not even the valid entry ahead of the bad one.
// eachComposite validates every id before applying any of them for exactly
// this reason, so the parent must come back unchanged: still not composite,
// and with no children at all.
func TestCompositeAddRollsBackOnABadID(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"partial-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"partial-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/partial-child", admin)
	if readRole(t, h, "/admin/realms/master/roles/partial-parent", admin).Composite {
		t.Fatal("precondition: a freshly created role must not start composite")
	}

	body := `[{"id":"` + child.ID + `","name":"partial-child"},` +
		`{"id":"00000000-0000-0000-0000-000000000000","name":"no-such-role"}]`
	w := postJSON(t, h, "/admin/realms/master/roles/partial-parent/composites", body, admin)
	if w.Code != http.StatusNotFound {
		t.Fatalf("add with one bad id: want 404, got %d", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"Could not find composite role"}` {
		t.Fatalf("unexpected 404 body: %s", got)
	}

	if readRole(t, h, "/admin/realms/master/roles/partial-parent", admin).Composite {
		t.Fatal("the whole batch should have rolled back, but the parent reads composite:true")
	}
	if left := listRoleNames(t, h, "/admin/realms/master/roles/partial-parent/composites", admin); len(left) != 0 {
		t.Fatalf("the whole batch should have rolled back, but the parent has children: %v", left)
	}
}

// TestCompositeRemoveRollsBackOnABadID is the mirror on DELETE, kept
// consistent with POST absent a measurement showing the two endpoints
// differ: a batch removing a role's only child, with a second entry that
// does not exist, must leave the role exactly as it was - still composite,
// still holding that child - rather than applying the valid removal ahead of
// the 404.
func TestCompositeRemoveRollsBackOnABadID(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"partial-remove-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"partial-remove-child"}`, admin)
	child := readRole(t, h, "/admin/realms/master/roles/partial-remove-child", admin)

	add := `[{"id":"` + child.ID + `","name":"partial-remove-child"}]`
	if got := postJSON(t, h, "/admin/realms/master/roles/partial-remove-parent/composites", add, admin).Code; got != http.StatusNoContent {
		t.Fatalf("add: want 204, got %d", got)
	}
	if !readRole(t, h, "/admin/realms/master/roles/partial-remove-parent", admin).Composite {
		t.Fatal("precondition: the parent must be composite before the removal below")
	}

	body := `[{"id":"` + child.ID + `","name":"partial-remove-child"},` +
		`{"id":"00000000-0000-0000-0000-000000000000","name":"no-such-role"}]`
	w := sendJSON(t, h, http.MethodDelete,
		"/admin/realms/master/roles/partial-remove-parent/composites", body, admin)
	if w.Code != http.StatusNotFound {
		t.Fatalf("remove with one bad id: want 404, got %d", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"Could not find composite role"}` {
		t.Fatalf("unexpected 404 body: %s", got)
	}

	if !readRole(t, h, "/admin/realms/master/roles/partial-remove-parent", admin).Composite {
		t.Fatal("the whole batch should have rolled back, but the parent reads composite:false")
	}
	if left := listRoleNames(t, h, "/admin/realms/master/roles/partial-remove-parent/composites", admin); !slices.Equal(left, []string{"partial-remove-child"}) {
		t.Fatalf("the whole batch should have rolled back, so the child must still be there: got %v", left)
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

// Direct holders only. The administrator holds `admin`, which is composite
// over `create-realm`; measured, /roles/admin/users lists the administrator
// and /roles/create-realm/users lists nobody.
func TestRoleUsersIsDirectHoldersOnly(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	holders := get(t, h, "/admin/realms/master/roles/admin/users", admin)
	if holders.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", holders.Code, holders.Body)
	}
	var users []struct {
		Username string          `json:"username"`
		Access   json.RawMessage `json:"access"`
	}
	if err := json.Unmarshal(holders.Body.Bytes(), &users); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("want the administrator alone, got %v", users)
	}
	// A fourth serialisation of a user: no access block, matching the
	// service-account read.
	if users[0].Access != nil {
		t.Fatalf("this listing must carry no access block, got %s", users[0].Access)
	}

	indirect := get(t, h, "/admin/realms/master/roles/create-realm/users", admin)
	var none []json.RawMessage
	if err := json.Unmarshal(indirect.Body.Bytes(), &none); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("a composite child reported %d holders; it must report none", len(none))
	}
}

// Groups are the third cut. Until then this is [] - which is also what
// Keycloak answers on a realm with no groups, so it is correct rather than a
// stub.
func TestRoleGroupsIsEmptyUntilGroupsExist(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/roles/admin/groups", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != "[]" {
		t.Fatalf("want [], got %s", body)
	}
}

// TestRoleGroupsAdmitViewOrManage measures the guard on .../groups: it is the
// plain realmRolesReadRoles/clientRolesReadRoles pair, exactly like the
// composite reads next door and unlike .../users below. Measured against a
// live 26.7.1 with four single-role callers, each checked against both the
// realm and the client route - one token per role, since tokenForRole mints a
// user named for the role and a second call with the same name would collide.
func TestRoleGroupsAdmitViewOrManage(t *testing.T) {
	h, s, realm := newServer(t)
	mrUUID := clientUUID(t, s, realm, "master-realm")
	cases := map[string]struct{ wantRealm, wantClient int }{
		"view-realm":     {http.StatusOK, http.StatusForbidden},
		"manage-realm":   {http.StatusOK, http.StatusForbidden},
		"view-clients":   {http.StatusForbidden, http.StatusOK},
		"manage-clients": {http.StatusForbidden, http.StatusOK},
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if got := get(t, h, "/admin/realms/master/roles/admin/groups", tok).Code; got != want.wantRealm {
				t.Fatalf("realm route: want %d, got %d", want.wantRealm, got)
			}
			path := "/admin/realms/master/clients/" + mrUUID + "/roles/view-users/groups"
			if got := get(t, h, path, tok).Code; got != want.wantClient {
				t.Fatalf("client route: want %d, got %d", want.wantClient, got)
			}
		})
	}
}

// TestRoleUsersNeedsRoleManagementAndUserRead measures the one guard in this
// plan that is neither a single role nor a plain view/manage pair: unlike
// every sibling next door, .../users needs a role-management role (the same
// pair .../groups takes) **and** a user-read role (view-users, manage-users
// or query-users) together. Measured directly against a live 26.7.1: a caller
// holding only view-realm gets 403, one holding only view-users gets 403 too,
// and only the pair together gets 200. Confirmed on both the realm and the
// client form, each against its own management pair.
func TestRoleUsersNeedsRoleManagementAndUserRead(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"holders-probe","enabled":true}`, admin)
	probeUUID := clientUUID(t, s, realm, "holders-probe")
	postJSON(t, h, "/admin/realms/master/clients/"+probeUUID+"/roles", `{"name":"probe-role"}`, admin)

	// grant assigns the named master-realm roles to a fresh user and returns a
	// token for it.
	grant := func(t *testing.T, username string, roleNames ...string) string {
		t.Helper()
		u := createUserWithPassword(t, s, realm, username, "pw")
		for _, name := range roleNames {
			r, err := s.Roles().ByName(ctx, realm.ID, container.ID, name)
			if err != nil {
				t.Fatalf("ByName(%s): %v", name, err)
			}
			if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
				t.Fatalf("AssignToUser(%s): %v", name, err)
			}
		}
		return tokenFor(t, h, username, "pw")
	}

	cases := []struct {
		name       string
		username   string
		roles      []string
		wantRealm  int
		wantClient int
	}{
		{"role management alone", "holders-rm-only", []string{"view-realm"}, http.StatusForbidden, http.StatusForbidden},
		{"user read alone", "holders-ur-only", []string{"view-users"}, http.StatusForbidden, http.StatusForbidden},
		{"realm pair + view-users", "holders-realm-vu", []string{"view-realm", "view-users"}, http.StatusOK, http.StatusForbidden},
		{"realm pair (manage) + query-users", "holders-realm-qu", []string{"manage-realm", "query-users"}, http.StatusOK, http.StatusForbidden},
		{"client pair + view-users", "holders-client-vu", []string{"view-clients", "view-users"}, http.StatusForbidden, http.StatusOK},
		{"client pair (manage) + manage-users", "holders-client-mu", []string{"manage-clients", "manage-users"}, http.StatusForbidden, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := grant(t, tc.username, tc.roles...)
			if got := get(t, h, "/admin/realms/master/roles/admin/users", tok).Code; got != tc.wantRealm {
				t.Fatalf("realm route: want %d, got %d", tc.wantRealm, got)
			}
			if got := get(t, h, "/admin/realms/master/clients/"+probeUUID+"/roles/probe-role/users", tok).Code; got != tc.wantClient {
				t.Fatalf("client route: want %d, got %d", tc.wantClient, got)
			}
		})
	}
}

// TestRolesByIDGuardFollowsTheRolesContainer measures the rule that makes
// roles-by-id its own task: the required role comes from the role that is
// addressed, not from the route. Measured on a live 26.7.1 across all four
// master-realm roles that could plausibly apply.
//
// **This corrects the plan's own brief.** The brief tried only view-realm and
// view-clients and read that as a lone required role each. Trying
// manage-realm and manage-clients too shows the read side is the same
// view/manage pair the by-name reads take next door, just picked by the
// resolved role's container rather than by the route: manage-realm alone
// also opens a realm role by id, and manage-clients alone also opens a
// client role by id. view-users opens neither.
func TestRolesByIDGuardFollowsTheRolesContainer(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	appBase := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"
	postJSON(t, h, appBase, `{"name":"app-role"}`, admin)
	clientRoleID := readRole(t, h, appBase+"/app-role", admin).ID
	realmRoleID := readRole(t, h, "/admin/realms/master/roles/admin", admin).ID

	// One token per role: tokenForRole mints a user named for the role, so
	// asking for the same role twice (once per target below) would collide.
	cases := map[string]struct{ wantRealm, wantClient int }{
		"view-realm":     {http.StatusOK, http.StatusForbidden},
		"manage-realm":   {http.StatusOK, http.StatusForbidden},
		"view-clients":   {http.StatusForbidden, http.StatusOK},
		"manage-clients": {http.StatusForbidden, http.StatusOK},
		"view-users":     {http.StatusForbidden, http.StatusForbidden},
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			if got := get(t, h, "/admin/realms/master/roles-by-id/"+realmRoleID, tok).Code; got != want.wantRealm {
				t.Fatalf("on a realm role: want %d, got %d", want.wantRealm, got)
			}
			if got := get(t, h, "/admin/realms/master/roles-by-id/"+clientRoleID, tok).Code; got != want.wantClient {
				t.Fatalf("on a client role: want %d, got %d", want.wantClient, got)
			}
		})
	}
}

// TestRolesByIDCompositesReadFollowsTheRolesContainer measures the same
// view/manage pair on the three composite reads, checked separately rather
// than assumed from the plain read above - the plan's own composites table
// needed exactly that correction twice already for the by-name routes.
func TestRolesByIDCompositesReadFollowsTheRolesContainer(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	appBase := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"
	postJSON(t, h, appBase, `{"name":"app-role"}`, admin)
	clientRoleID := readRole(t, h, appBase+"/app-role", admin).ID
	realmRoleID := readRole(t, h, "/admin/realms/master/roles/admin", admin).ID
	mrUUID := clientUUID(t, s, realm, "master-realm")

	cases := map[string]struct{ wantRealm, wantClient int }{
		"view-realm":     {http.StatusOK, http.StatusForbidden},
		"manage-realm":   {http.StatusOK, http.StatusForbidden},
		"view-clients":   {http.StatusForbidden, http.StatusOK},
		"manage-clients": {http.StatusForbidden, http.StatusOK},
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			tok := tokenForRole(t, h, s, realm, role)
			for _, suffix := range []string{"/composites", "/composites/realm", "/composites/clients/" + mrUUID} {
				if got := get(t, h, "/admin/realms/master/roles-by-id/"+realmRoleID+suffix, tok).Code; got != want.wantRealm {
					t.Fatalf("%s on a realm role: want %d, got %d", suffix, want.wantRealm, got)
				}
				if got := get(t, h, "/admin/realms/master/roles-by-id/"+clientRoleID+suffix, tok).Code; got != want.wantClient {
					t.Fatalf("%s on a client role: want %d, got %d", suffix, want.wantClient, got)
				}
			}
		})
	}
}

// TestRolesByIDWritesNeedManageAlone measures the write side: unlike the
// reads above, PUT and DELETE admit only the manage role on the resolved
// role's own side - view-realm/view-clients are refused, matching the
// by-name writes next door.
func TestRolesByIDWritesNeedManageAlone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	appBase := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"

	// One token per role, checked against both a realm role and a client role,
	// since tokenForRole mints a user named for the role and a second call
	// with the same name would collide.
	cases := map[string]struct{ wantRealm, wantClient int }{
		"view-realm":     {http.StatusForbidden, http.StatusForbidden},
		"view-clients":   {http.StatusForbidden, http.StatusForbidden},
		"manage-realm":   {http.StatusNoContent, http.StatusForbidden},
		"manage-clients": {http.StatusForbidden, http.StatusNoContent},
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			postJSON(t, h, "/admin/realms/master/roles", `{"name":"write-guard-realm-`+role+`"}`, admin)
			postJSON(t, h, appBase, `{"name":"write-guard-client-`+role+`"}`, admin)
			realmID := readRole(t, h, "/admin/realms/master/roles/write-guard-realm-"+role, admin).ID
			clientID := readRole(t, h, appBase+"/write-guard-client-"+role, admin).ID
			tok := tokenForRole(t, h, s, realm, role)
			if got := putJSON(t, h, "/admin/realms/master/roles-by-id/"+realmID, `{"name":"write-guard-realm-`+role+`"}`, tok).Code; got != want.wantRealm {
				t.Fatalf("PUT a realm role: want %d, got %d", want.wantRealm, got)
			}
			if got := putJSON(t, h, "/admin/realms/master/roles-by-id/"+clientID, `{"name":"write-guard-client-`+role+`"}`, tok).Code; got != want.wantClient {
				t.Fatalf("PUT a client role: want %d, got %d", want.wantClient, got)
			}
			// The PUT above only ever renames a role to its own name, so the
			// role is still there either way (rejected untouched, or accepted
			// and unchanged) - DELETE runs against the same id next, with the
			// same expectation, since a role that PUT could reach is exactly
			// the one DELETE should reach too.
			if got := do(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+realmID, tok).Code; got != want.wantRealm {
				t.Fatalf("DELETE a realm role: want %d, got %d", want.wantRealm, got)
			}
			if got := do(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+clientID, tok).Code; got != want.wantClient {
				t.Fatalf("DELETE a client role: want %d, got %d", want.wantClient, got)
			}
		})
	}
}

// TestRolesByIDCompositesWriteNeedsManageAlone measures POST and DELETE
// .../composites the same way, with a child from the same family as the
// parent - the case eachComposite exercises through this guard. Matches the
// by-name composite writes' rule exactly: only the manage role on the
// resolved role's own side, not the pair.
func TestRolesByIDCompositesWriteNeedsManageAlone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	appBase := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"

	cases := map[string]struct{ wantRealm, wantClient int }{
		"view-realm":     {http.StatusForbidden, http.StatusForbidden},
		"view-clients":   {http.StatusForbidden, http.StatusForbidden},
		"manage-realm":   {http.StatusNoContent, http.StatusForbidden},
		"manage-clients": {http.StatusForbidden, http.StatusNoContent},
	}
	for role, want := range cases {
		t.Run(role, func(t *testing.T) {
			postJSON(t, h, "/admin/realms/master/roles", `{"name":"composite-guard-realm-parent-`+role+`"}`, admin)
			postJSON(t, h, "/admin/realms/master/roles", `{"name":"composite-guard-realm-child-`+role+`"}`, admin)
			postJSON(t, h, appBase, `{"name":"composite-guard-client-parent-`+role+`"}`, admin)
			postJSON(t, h, appBase, `{"name":"composite-guard-client-child-`+role+`"}`, admin)
			realmParentID := readRole(t, h, "/admin/realms/master/roles/composite-guard-realm-parent-"+role, admin).ID
			realmChild := readRole(t, h, "/admin/realms/master/roles/composite-guard-realm-child-"+role, admin)
			clientParentID := readRole(t, h, appBase+"/composite-guard-client-parent-"+role, admin).ID
			clientChild := readRole(t, h, appBase+"/composite-guard-client-child-"+role, admin)
			tok := tokenForRole(t, h, s, realm, role)

			realmBody := `[{"id":"` + realmChild.ID + `","name":"` + realmChild.Name + `"}]`
			if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+realmParentID+"/composites", realmBody, tok).Code; got != want.wantRealm {
				t.Fatalf("POST composites, realm parent + realm child: want %d, got %d", want.wantRealm, got)
			}
			clientBody := `[{"id":"` + clientChild.ID + `","name":"` + clientChild.Name + `"}]`
			if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+clientParentID+"/composites", clientBody, tok).Code; got != want.wantClient {
				t.Fatalf("POST composites, client parent + client child: want %d, got %d", want.wantClient, got)
			}
			// Removing one that was never added is still 204 (measured
			// elsewhere in this file), so DELETE lands on the same want as
			// POST regardless of whether POST above actually attached it.
			if got := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+realmParentID+"/composites", realmBody, tok).Code; got != want.wantRealm {
				t.Fatalf("DELETE composites, realm parent + realm child: want %d, got %d", want.wantRealm, got)
			}
			if got := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+clientParentID+"/composites", clientBody, tok).Code; got != want.wantClient {
				t.Fatalf("DELETE composites, client parent + client child: want %d, got %d", want.wantClient, got)
			}
		})
	}
}

// TestRolesByIDCompositesCrossFamilyChildNeedsBothOnlyOnAdd measures a case
// neither the plan's brief nor the previously recorded composites-write
// table considered: the composite **child**'s own container matters too, not
// only the parent's - and it matters on `POST` only, not on `DELETE`.
//
// Add side, measured directly against a live 26.7.1: `manage-clients` alone
// (which opens `POST .../composites` for a client-role parent when the child
// is also a client role, per the test above) is refused when the child is a
// realm role instead, and the mirror holds for `manage-realm` with a
// client-role child on a realm-role parent. Only holding both opens either
// route in that case. The by-name composite routes were spot-checked too
// (`POST /roles/{name}/composites` with a client-role child, `manage-realm`
// alone: 403; the same request with `manage-realm` + `manage-clients`: 204)
// and match this exactly, since they run through the same `eachComposite`.
//
// Remove side, also measured directly (both directions): the identical
// caller holding only the parent-side manage role removes the identical
// cross-family child with a plain 204 - no second check at all. This is
// asymmetric and there is no known reason for it beyond "that is what
// Keycloak does" - see the observed-behaviour document.
//
// `guardByRoleContainer`, like the route-level guard on the by-name routes,
// decides from the parent's container alone and cannot see the body - it
// runs before the body is decoded, on both verbs equally. The asymmetry
// lives one level in, in `eachComposite`'s `checkChild` parameter:
// `addComposites` passes `requiresChildManageRole`, `removeComposites`
// passes `nil`. This test is what pins that difference - the POST 403 and
// the DELETE 204 below act on the exact same (parent, child, caller) triple,
// so the only thing that changed between them is the verb.
func TestRolesByIDCompositesCrossFamilyChildNeedsBothOnlyOnAdd(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app","enabled":true}`, admin)
	appBase := "/admin/realms/master/clients/" + clientUUID(t, s, realm, "probe-app") + "/roles"

	postJSON(t, h, "/admin/realms/master/roles", `{"name":"cross-family-realm-parent"}`, admin)
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"cross-family-realm-child"}`, admin)
	postJSON(t, h, appBase, `{"name":"cross-family-client-parent"}`, admin)
	postJSON(t, h, appBase, `{"name":"cross-family-client-child"}`, admin)
	realmParentID := readRole(t, h, "/admin/realms/master/roles/cross-family-realm-parent", admin).ID
	realmChild := readRole(t, h, "/admin/realms/master/roles/cross-family-realm-child", admin)
	clientParentID := readRole(t, h, appBase+"/cross-family-client-parent", admin).ID
	clientChild := readRole(t, h, appBase+"/cross-family-client-child", admin)

	// grant assigns the named master-realm roles to a fresh user and returns a
	// token for it - tokenForRole cannot express more than one role per user.
	grant := func(t *testing.T, username string, roleNames ...string) string {
		t.Helper()
		ctx := context.Background()
		container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}
		u := createUserWithPassword(t, s, realm, username, "pw")
		for _, name := range roleNames {
			r, err := s.Roles().ByName(ctx, realm.ID, container.ID, name)
			if err != nil {
				t.Fatalf("ByName(%s): %v", name, err)
			}
			if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
				t.Fatalf("AssignToUser(%s): %v", name, err)
			}
		}
		return tokenFor(t, h, username, "pw")
	}

	clientChildOnRealmParent := `[{"id":"` + clientChild.ID + `","name":"` + clientChild.Name + `"}]`
	realmChildOnClientParent := `[{"id":"` + realmChild.ID + `","name":"` + realmChild.Name + `"}]`

	mrOnly := grant(t, "cross-family-mr-only", "manage-realm")
	if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+realmParentID+"/composites", clientChildOnRealmParent, mrOnly).Code; got != http.StatusForbidden {
		t.Fatalf("manage-realm alone, client child on a realm parent: want 403, got %d", got)
	}

	mcOnly := grant(t, "cross-family-mc-only", "manage-clients")
	if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+clientParentID+"/composites", realmChildOnClientParent, mcOnly).Code; got != http.StatusForbidden {
		t.Fatalf("manage-clients alone, realm child on a client parent: want 403, got %d", got)
	}

	both := grant(t, "cross-family-both", "manage-realm", "manage-clients")
	if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+realmParentID+"/composites", clientChildOnRealmParent, both).Code; got != http.StatusNoContent {
		t.Fatalf("both roles, client child on a realm parent: want 204, got %d", got)
	}
	if got := postJSON(t, h, "/admin/realms/master/roles-by-id/"+clientParentID+"/composites", realmChildOnClientParent, both).Code; got != http.StatusNoContent {
		t.Fatalf("both roles, realm child on a client parent: want 204, got %d", got)
	}

	// DELETE does not carry the requirement above, and this is where that
	// shows up: measured directly (both directions), a caller holding only
	// the parent-side manage role removes a cross-family child outright, no
	// check on the child's own container at all. Both children are already
	// attached - the `both` assertions just above put them there - so this
	// is a real detach, not a no-op on something never linked. Kept right
	// next to the POST 403s above on purpose: the same caller is refused
	// adding and allowed removing the identical pair, and that asymmetry is
	// the whole point of this test.
	mrOnlyDelete := grant(t, "cross-family-mr-only-delete", "manage-realm")
	if got := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+realmParentID+"/composites", clientChildOnRealmParent, mrOnlyDelete).Code; got != http.StatusNoContent {
		t.Fatalf("DELETE, manage-realm alone, client child on a realm parent: want 204, got %d", got)
	}
	mcOnlyDelete := grant(t, "cross-family-mc-only-delete", "manage-clients")
	if got := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+clientParentID+"/composites", realmChildOnClientParent, mcOnlyDelete).Code; got != http.StatusNoContent {
		t.Fatalf("DELETE, manage-clients alone, realm child on a client parent: want 204, got %d", got)
	}

	// By name, not just by id: eachComposite is shared between the two, and
	// the guard that decides which manage role the *parent* needs is not -
	// guard("manage-realm", ...) here versus guardByRoleContainer above - so
	// this is not implied by the by-id cases and was measured on its own
	// against a live 26.7.1. A second realm parent is used so the mrOnly
	// grant above (already spent on the roles-by-id case) does not collide.
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"cross-family-byname-parent"}`, admin)
	bynameParent := "/admin/realms/master/roles/cross-family-byname-parent/composites"
	mrOnlyByName := grant(t, "cross-family-byname-mr-only", "manage-realm")
	if got := postJSON(t, h, bynameParent, clientChildOnRealmParent, mrOnlyByName).Code; got != http.StatusForbidden {
		t.Fatalf("by name, manage-realm alone, client child on a realm parent: want 403, got %d", got)
	}
	bothByName := grant(t, "cross-family-byname-both", "manage-realm", "manage-clients")
	if got := postJSON(t, h, bynameParent, clientChildOnRealmParent, bothByName).Code; got != http.StatusNoContent {
		t.Fatalf("by name, both roles, client child on a realm parent: want 204, got %d", got)
	}
}

// TestRolesByIDReportsMissingBeforeForbidden measures the ordering: a missing
// role answers 404 whatever the caller holds. This is Keycloak's own
// behaviour, kept because it is measured - not because it is the safer
// choice. It does leak existence to a caller who is not authorized to touch
// the role: a missing id reads 404 and an existing-but-forbidden id reads
// 403, so the two are distinguishable. The message is its own -
// "Could not find role with id" - not writeRoleNotFound's "Could not find
// role".
func TestRolesByIDReportsMissingBeforeForbidden(t *testing.T) {
	h, s, realm := newServer(t)
	tok := tokenForRole(t, h, s, realm, "view-users") // opens nothing here

	w := get(t, h, "/admin/realms/master/roles-by-id/00000000-0000-0000-0000-000000000000", tok)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); body != `{"error":"Could not find role with id"}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestRolesByIDUpdatesAndDeletes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-role","description":"before"}`, admin)
	id := readRole(t, h, "/admin/realms/master/roles/probe-role", admin).ID

	if got := putJSON(t, h, "/admin/realms/master/roles-by-id/"+id, `{"name":"probe-role"}`, admin).Code; got != http.StatusNoContent {
		t.Fatalf("update: want 204, got %d", got)
	}
	if d := readRole(t, h, "/admin/realms/master/roles/probe-role", admin).Description; d != "" {
		t.Fatalf("roles-by-id PUT merged instead of replacing: %q", d)
	}
	if got := do(t, h, http.MethodDelete, "/admin/realms/master/roles-by-id/"+id, admin).Code; got != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", got)
	}
}
