package admin

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
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
