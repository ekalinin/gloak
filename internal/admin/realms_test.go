package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// The five operations of P4's first cut. Every expectation here is measured
// against a live 26.7.1; see "Realms" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// TestCreateRealmIsDisabledUnlessAsked is the behaviour most likely to be
// "fixed" by a careful implementer. `enabled` has no default, so a create that
// does not say so makes a realm nobody can log into.
func TestCreateRealmIsDisabledUnlessAsked(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := postJSON(t, h, "/admin/realms", `{"realm":"probe-off"}`, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body)
	}
	if got := w.Body.Len(); got != 0 {
		t.Errorf("body: want empty, got %d bytes: %s", got, w.Body)
	}
	if got, want := w.Header().Get("Location"), "http://localhost:8080/admin/realms/probe-off"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	rep := readRealm(t, h, "probe-off", admin)
	if rep.Enabled {
		t.Error("a realm created without enabled came back enabled")
	}
	// And its lifespan is the product default, not master's 60.
	if rep.AccessTokenLifespan != 300 {
		t.Errorf("accessTokenLifespan = %d, want 300", rep.AccessTokenLifespan)
	}
	if len(rep.Attributes) != 8 {
		t.Errorf("attributes = %d keys, want 8: %v", len(rep.Attributes), rep.Attributes)
	}
}

// TestCreateRealmHonoursAnIDInTheBody: the create takes the id it is given,
// and Location still names the realm rather than that id.
func TestCreateRealmHonoursAnIDInTheBody(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	const id = "11111111-1111-1111-1111-111111111111"

	w := postJSON(t, h, "/admin/realms", `{"id":"`+id+`","realm":"probe-id","enabled":true}`, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); got != "http://localhost:8080/admin/realms/probe-id" {
		t.Errorf("Location = %q", got)
	}
	if rep := readRealm(t, h, "probe-id", admin); rep.ID != id {
		t.Errorf("id = %q, want %q", rep.ID, id)
	}
}

// TestUpdateRealmMerges: a body of {} changes nothing and a body naming one
// field leaves the rest alone. PUT on a role replaces; this one merges.
func TestUpdateRealmMerges(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms", `{"realm":"probe-put","enabled":true}`, admin)

	send := func(body string) {
		t.Helper()
		if w := sendJSON(t, h, http.MethodPut, "/admin/realms/probe-put", body, admin); w.Code != http.StatusNoContent {
			t.Fatalf("PUT %s: want 204, got %d: %s", body, w.Code, w.Body)
		}
	}

	send(`{"realm":"probe-put","displayName":"Probe"}`)
	send(`{"realm":"probe-put","accessTokenLifespan":123}`)
	send(`{}`)

	rep := readRealm(t, h, "probe-put", admin)
	if rep.DisplayName == nil || *rep.DisplayName != "Probe" {
		t.Errorf("displayName = %v, want Probe - a later PUT that omitted it dropped it", rep.DisplayName)
	}
	if rep.AccessTokenLifespan != 123 {
		t.Errorf("accessTokenLifespan = %d, want 123", rep.AccessTokenLifespan)
	}
	if !rep.Enabled {
		t.Error("enabled was dropped by a PUT that omitted it")
	}

	// null is ignored where an empty string is written, and the key stays.
	send(`{"displayName":null}`)
	if rep := readRealm(t, h, "probe-put", admin); rep.DisplayName == nil || *rep.DisplayName != "Probe" {
		t.Errorf("a null displayName cleared it: %v", rep.DisplayName)
	}
	send(`{"displayName":""}`)
	if rep := readRealm(t, h, "probe-put", admin); rep.DisplayName == nil || *rep.DisplayName != "" {
		t.Errorf(`displayName after "" = %v, want the key present and empty`, rep.DisplayName)
	}
}

// TestUpdateRealmRenames: the path segment and the body's realm do not have to
// agree, and the body wins. No other resource on this API can be renamed
// through its own PUT - a username explicitly cannot.
func TestUpdateRealmRenames(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms", `{"realm":"probe-before","enabled":true}`, admin)
	before := readRealm(t, h, "probe-before", admin)

	if w := sendJSON(t, h, http.MethodPut, "/admin/realms/probe-before", `{"realm":"probe-after"}`, admin); w.Code != http.StatusNoContent {
		t.Fatalf("rename: want 204, got %d: %s", w.Code, w.Body)
	}

	if w := get(t, h, "/admin/realms/probe-before", admin); w.Code != http.StatusNotFound {
		t.Errorf("the old name still resolves: %d", w.Code)
	}
	after := readRealm(t, h, "probe-after", admin)
	if after.ID != before.ID {
		t.Errorf("the id changed: %q -> %q", before.ID, after.ID)
	}

	// Renaming onto a taken name is a 409, and **not** the wording POST uses.
	postJSON(t, h, "/admin/realms", `{"realm":"probe-taken","enabled":true}`, admin)
	w := sendJSON(t, h, http.MethodPut, "/admin/realms/probe-after", `{"realm":"probe-taken"}`, admin)
	if w.Code != http.StatusConflict {
		t.Fatalf("rename onto a taken name: want 409, got %d: %s", w.Code, w.Body)
	}
	if got, want := w.Body.String(), `{"errorMessage":"Realm with same name exists"}`; got != want {
		t.Errorf("body:\n got %s\nwant %s", got, want)
	}
}

// TestUpdateRealmReplacesAttributes is the one field a PUT does not merge, and
// it is not replaced cleanly: the seven derived policy attributes come back and
// realmReusableOtpCode does not.
func TestUpdateRealmReplacesAttributes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms", `{"realm":"probe-attrs","enabled":true,"attributes":{"a":"1","b":"2"}}`, admin)

	// On create the body's attributes merge with the defaults.
	rep := readRealm(t, h, "probe-attrs", admin)
	if len(rep.Attributes) != 10 {
		t.Fatalf("after create: %d attributes, want 10: %v", len(rep.Attributes), rep.Attributes)
	}

	if w := sendJSON(t, h, http.MethodPut, "/admin/realms/probe-attrs", `{"attributes":{"c":"3"}}`, admin); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}

	rep = readRealm(t, h, "probe-attrs", admin)
	for _, gone := range []string{"a", "b", "realmReusableOtpCode"} {
		if _, ok := rep.Attributes[gone]; ok {
			t.Errorf("%q survived the replace", gone)
		}
	}
	if rep.Attributes["c"] != "3" {
		t.Errorf("c = %q, want 3", rep.Attributes["c"])
	}
	for _, kept := range derivedRealmAttributes {
		if _, ok := rep.Attributes[kept]; !ok {
			t.Errorf("the derived attribute %q was not put back", kept)
		}
	}
}

// TestDeleteMasterIsFourHundred: not a 403, not a 409, and the message carries
// an apostrophe and no full stop.
func TestDeleteMasterIsFourHundred(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := sendJSON(t, h, http.MethodDelete, "/admin/realms/master", "", admin)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body)
	}
	if got, want := w.Body.String(), `{"errorMessage":"Can't remove master realm"}`; got != want {
		t.Errorf("body:\n got %s\nwant %s", got, want)
	}
}

// TestDeleteRealmTakesItsContainerFromMaster: the realm goes, its container in
// master goes, and master's admin composite shrinks back.
func TestDeleteRealmTakesItsContainerFromMaster(t *testing.T) {
	h, s, master := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms", `{"realm":"probe-gone","enabled":true}`, admin)

	if w := get(t, h, "/admin/realms/master/clients?clientId=probe-gone-realm", admin); w.Code != http.StatusOK {
		t.Fatalf("the container was not created: %d", w.Code)
	}

	if w := sendJSON(t, h, http.MethodDelete, "/admin/realms/probe-gone", "", admin); w.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d: %s", w.Code, w.Body)
	}

	if w := get(t, h, "/admin/realms/probe-gone", admin); w.Code != http.StatusNotFound {
		t.Errorf("the realm survived: %d", w.Code)
	}
	if got := listNames(t, h, "/admin/realms/master/clients", admin); contains(got, "probe-gone-realm") {
		t.Errorf("the container survived in master: %v", got)
	}
	adminRole, err := s.Roles().ByName(context.Background(), master.ID, "", "admin")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	children, err := s.Roles().ListComposites(context.Background(), adminRole.ID)
	if err != nil {
		t.Fatalf("ListComposites: %v", err)
	}
	if len(children) != 22 {
		t.Errorf("master's admin has %d composites after the delete, want 22", len(children))
	}
}

// TestTheRealmReadHasThreeShapes is the behaviour a reviewer is most likely to
// call a bug: a caller that may not view the realm gets a **shorter body**, not
// a 403.
func TestTheRealmReadHasThreeShapes(t *testing.T) {
	h, s, master := newServer(t)

	for _, tc := range []struct {
		role string
		keys []string
	}{
		{"view-realm", nil}, // nil means "the full 104"
		{"manage-realm", nil},
		{"view-users", []string{"realm", "registrationEmailAsUsername", "bruteForceProtected", "supportedLocales", "organizationsEnabled"}},
		{"manage-users", []string{"realm", "registrationEmailAsUsername", "bruteForceProtected", "supportedLocales", "organizationsEnabled"}},
		{"query-realms", []string{"realm", "bruteForceProtected", "supportedLocales", "organizationsEnabled"}},
		{"view-clients", []string{"realm", "bruteForceProtected", "supportedLocales", "organizationsEnabled"}},
		{"create-client", []string{"realm", "bruteForceProtected", "supportedLocales", "organizationsEnabled"}},
	} {
		caller := tokenForRole(t, h, s, master, tc.role)
		w := get(t, h, "/admin/realms/master", caller)
		if w.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d: %s", tc.role, w.Code, w.Body)
			continue
		}
		got := topLevelKeys(t, w.Body.Bytes())
		if tc.keys == nil {
			if len(got) != 106 {
				t.Errorf("%s: %d keys, want the full 106 (master carries two display names)", tc.role, len(got))
			}
			continue
		}
		// The display names sit between realm and the rest on master.
		want := append([]string{tc.keys[0], "displayName", "displayNameHtml"}, tc.keys[1:]...)
		if !equalStrings(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", tc.role, got, want)
		}
	}
}

// TestImpersonationOpensNoRealm: twenty of the twenty-one admin roles open the
// read and this one does not. Nothing in the name predicts it.
func TestImpersonationOpensNoRealm(t *testing.T) {
	h, s, master := newServer(t)
	caller := tokenForRole(t, h, s, master, "impersonation")

	for _, path := range []string{"/admin/realms/master", "/admin/realms"} {
		if w := get(t, h, path, caller); w.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d: %s", path, w.Code, w.Body)
		}
	}
}

// TestCreateRealmTakesCreateRealmAlone: manage-realm is 403 on the create and
// create-realm is 403 on the listing, so the collection's two verbs disagree
// about who may use them in both directions.
func TestCreateRealmTakesCreateRealmAlone(t *testing.T) {
	h, s, master := newServer(t)
	ctx := context.Background()

	manageRealm := tokenForRole(t, h, s, master, "manage-realm")
	if w := postJSON(t, h, "/admin/realms", `{"realm":"probe-refused"}`, manageRealm); w.Code != http.StatusForbidden {
		t.Errorf("manage-realm creating a realm: want 403, got %d: %s", w.Code, w.Body)
	}

	// create-realm is a realm role, so it is assigned rather than taken from a
	// container.
	u := createUserWithPassword(t, s, master, "only-create-realm", "pw")
	role, err := s.Roles().ByName(ctx, master.ID, "", "create-realm")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if err := s.Roles().AssignToUser(ctx, u.ID, role.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
	creator := tokenFor(t, h, "only-create-realm", "pw")

	if w := postJSON(t, h, "/admin/realms", `{"realm":"probe-created"}`, creator); w.Code != http.StatusCreated {
		t.Errorf("create-realm creating a realm: want 201, got %d: %s", w.Code, w.Body)
	}
	// And the same caller is refused the listing, where it gets 200 on the
	// single read of every realm.
	if w := get(t, h, "/admin/realms", creator); w.Code != http.StatusForbidden {
		t.Errorf("create-realm listing realms: want 403, got %d: %s", w.Code, w.Body)
	}
	if w := get(t, h, "/admin/realms/master", creator); w.Code != http.StatusOK {
		t.Errorf("create-realm reading a realm: want 200, got %d: %s", w.Code, w.Body)
	}
}

// TestTheListingFiltersAndShrinks: one response can carry a 104-key object
// beside a one-key one, and briefRepresentation does nothing to the second.
func TestTheListingFiltersAndShrinks(t *testing.T) {
	h, s, master := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms", `{"realm":"probe-list","enabled":true}`, admin)

	viewRealm := tokenForRole(t, h, s, master, "view-realm")
	viewUsers := tokenForRole(t, h, s, master, "view-users")

	// A caller with view-realm on master-realm sees master and nothing else.
	entries := realmListing(t, h, "/admin/realms", viewRealm)
	if len(entries) != 1 || string(entries[0]["realm"]) != `"master"` {
		t.Fatalf("view-realm listing: %v", entries)
	}
	if len(entries[0]) < 100 {
		t.Errorf("view-realm entry has %d keys, want the full representation", len(entries[0]))
	}

	// A caller with view-users sees master with one key, and the flag changes
	// nothing about it.
	for _, path := range []string{"/admin/realms", "/admin/realms?briefRepresentation=true"} {
		entries = realmListing(t, h, path, viewUsers)
		if len(entries) != 1 || len(entries[0]) != 1 || string(entries[0]["realm"]) != `"master"` {
			t.Errorf("%s: want one one-key entry for master, got %v", path, entries)
		}
	}

	// The full administrator gets both realms, and brief gives three keys.
	entries = realmListing(t, h, "/admin/realms?briefRepresentation=true", admin)
	if len(entries) != 2 {
		t.Fatalf("admin brief listing: %v", entries)
	}
	for _, e := range entries {
		if _, ok := e["id"]; !ok {
			t.Errorf("brief entry has no id: %v", e)
		}
		if _, ok := e["enabled"]; !ok {
			t.Errorf("brief entry has no enabled: %v", e)
		}
		if _, ok := e["notBefore"]; ok {
			t.Errorf("brief entry is not brief: %v", e)
		}
	}
}

// TestAnUnknownRealmIsFourOhFourToEveryone: the realm is resolved before the
// caller is judged, so an unknown realm answers 404 to a caller holding no
// admin role at all. It does leak which realm names exist.
func TestAnUnknownRealmIsFourOhFourToEveryone(t *testing.T) {
	h, s, master := newServer(t)
	createUserWithPassword(t, s, master, "nobody", "pw")

	for _, token := range []string{
		tokenFor(t, h, "admin", "admin"),
		tokenForRole(t, h, s, master, "view-users"),
		tokenFor(t, h, "nobody", "pw"),
	} {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			w := sendJSON(t, h, m, "/admin/realms/nosuchrealm", `{}`, token)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: want 404, got %d: %s", m, w.Code, w.Body)
			}
			if got, want := w.Body.String(), `{"error":"Realm not found."}`; got != want {
				t.Errorf("%s body:\n got %s\nwant %s", m, got, want)
			}
		}
	}
}

// TestCreateRealmErrorShapes: three families on one resource, and POST and PUT
// answer the same malformed body differently.
func TestCreateRealmErrorShapes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"duplicate", http.MethodPost, "/admin/realms", `{"realm":"master"}`,
			http.StatusConflict, `{"errorMessage":"Realm master already exists"}`},
		{"no name", http.MethodPost, "/admin/realms", `{}`,
			http.StatusBadRequest, `{"errorMessage":"Realm name cannot be empty"}`},
		{"malformed", http.MethodPost, "/admin/realms", `nope`,
			http.StatusBadRequest, `{"errorMessage":"unable to read contents from stream"}`},
		{"empty", http.MethodPost, "/admin/realms", ``,
			http.StatusBadRequest, `{"errorMessage":"unable to read contents from stream"}`},
		{"PUT malformed", http.MethodPut, "/admin/realms/master", `nope`,
			http.StatusBadRequest, `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		{"PUT empty", http.MethodPut, "/admin/realms/master", ``,
			http.StatusInternalServerError, `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
	} {
		w := sendJSON(t, h, tc.method, tc.path, tc.body, admin)
		if w.Code != tc.status {
			t.Errorf("%s: want %d, got %d: %s", tc.name, tc.status, w.Code, w.Body)
		}
		if got := w.Body.String(); got != tc.want {
			t.Errorf("%s body:\n got %s\nwant %s", tc.name, got, tc.want)
		}
	}
}

func readRealm(t *testing.T, h http.Handler, name, token string) realmRepresentation {
	t.Helper()
	w := get(t, h, "/admin/realms/"+name, token)
	if w.Code != http.StatusOK {
		t.Fatalf("read %s: %d %s", name, w.Code, w.Body)
	}
	var rep realmRepresentation
	if err := decodeJSON(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rep
}

func realmListing(t *testing.T, h http.Handler, path, token string) []map[string]json.RawMessage {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var out []map[string]json.RawMessage
	if err := decodeJSON(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
