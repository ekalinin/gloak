package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// componentsOf reads the listing and returns the decoded rows.
func componentsOf(t *testing.T, h http.Handler, path, token string) []map[string]any {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// TestComponentsOnAFreshRealm pins the count and the shape of what bootstrap
// writes, which is the whole of what this cut serves.
//
// **Master has fifteen and a created realm has fourteen**, and the difference
// is the one component with no `name` key. Both halves are measured and a
// bootstrap that wrote one list for every realm would be wrong on one of them.
func TestComponentsOnAFreshRealm(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	master := componentsOf(t, h, "/admin/realms/master/components", admin)
	if len(master) != 15 {
		t.Errorf("master has %d components, want 15", len(master))
	}

	byType := map[string]int{}
	nameless := 0
	for _, c := range master {
		byType[c["providerType"].(string)]++
		if _, ok := c["name"]; !ok {
			nameless++
		}
	}
	if got := byType["org.keycloak.keys.KeyProvider"]; got != 4 {
		t.Errorf("master has %d key providers, want 4", got)
	}
	if got := byType["org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"]; got != 10 {
		t.Errorf("master has %d client-registration policies, want 10", got)
	}
	if got := byType["org.keycloak.userprofile.UserProfileProvider"]; got != 1 {
		t.Errorf("master has %d user profile providers, want 1", got)
	}
	if nameless != 1 {
		t.Errorf("%d components have no name key, want exactly 1", nameless)
	}

	// A realm created through the API. The measurement is that it is fourteen
	// and that the missing one is the nameless user-profile row.
	w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"gloak-probe-r9","enabled":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating the realm: %d %s", w.Code, w.Body)
	}
	created := componentsOf(t, h, "/admin/realms/gloak-probe-r9/components", admin)
	if len(created) != 14 {
		t.Errorf("a created realm has %d components, want 14", len(created))
	}
	for _, c := range created {
		if c["providerType"] == "org.keycloak.userprofile.UserProfileProvider" {
			t.Errorf("a created realm got the user profile component: %v", c)
		}
	}
}

// TestComponentParentIsTheRealm pins the value that says a component's parent
// is the realm rather than another component, and the 404 that says the realm
// is not itself one.
func TestComponentParentIsTheRealm(t *testing.T) {
	h, _, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, c := range componentsOf(t, h, "/admin/realms/master/components", admin) {
		if c["parentId"] != realm.ID {
			t.Fatalf("component %v is parented on %v, want the realm %s", c["name"], c["parentId"], realm.ID)
		}
	}

	// The realm's own id is not a component.
	w := get(t, h, "/admin/realms/master/components/"+realm.ID, admin)
	const want = `{"error":"Could not find component"}`
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("reading the realm as a component: got %d %s, want 404 %s", w.Code, w.Body, want)
	}
	// So is an id that names nothing, with the same body.
	w = get(t, h, "/admin/realms/master/components/gloak-probe-nosuch", admin)
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("an unknown component: got %d %s, want 404 %s", w.Code, w.Body, want)
	}
}

// TestComponentConfigKeyOrderIsThePlainHashMap is the assertion that separates
// this family from the identity providers.
//
// `{priority, algorithm}` is the only two-key set a default install has and
// both javamap functions agree on it, so the discriminating value has to come
// from the bootstrapped rows themselves. What is asserted here is the two-key
// order the server sent, byte for byte - a serialiser that sorted the keys
// would answer `algorithm, priority`.
func TestComponentConfigKeyOrderIsThePlainHashMap(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	want := map[string]string{
		"rsa-generated":        `{"priority":["100"]}`,
		"aes-generated":        `{"priority":["100"]}`,
		"rsa-enc-generated":    `{"priority":["100"],"algorithm":["RSA-OAEP"]}`,
		"hmac-generated-hs512": `{"priority":["100"],"algorithm":["HS512"]}`,
		"Trusted Hosts": `{"host-sending-registration-request-must-match":["true"],` +
			`"client-uris-must-match":["true"]}`,
		"Max Clients Limit": `{"max-clients":["200"]}`,
		"Consent Required":  `{}`,
	}
	w := get(t, h, "/admin/realms/master/components", admin)
	var list []struct {
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range list {
		if w, ok := want[c.Name]; ok {
			seen[c.Name] = true
			if string(c.Config) != w {
				t.Errorf("%s config: got %s, want %s", c.Name, c.Config, w)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("the listing has no component named %q", name)
		}
	}
}

// TestComponentFilters pins the three query parameters and, more usefully, that
// a value matching nothing is `[]` rather than a 404.
func TestComponentFilters(t *testing.T) {
	h, _, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 15},
		{"?type=org.keycloak.keys.KeyProvider", 4},
		{"?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy", 10},
		{"?type=bogus", 0},
		{"?parent=" + realm.ID, 15},
		{"?parent=bogus", 0},
		{"?name=aes-generated", 1},
		{"?name=bogus", 0},
		{"?type=org.keycloak.keys.KeyProvider&name=aes-generated", 1},
		// The bounds are ignored outright, which is measured and is the
		// opposite of the identity provider listing one path segment away.
		{"?first=1&max=2", 15},
	} {
		if got := len(componentsOf(t, h, "/admin/realms/master/components"+tc.query, admin)); got != tc.want {
			t.Errorf("%q: got %d rows, want %d", tc.query, got, tc.want)
		}
	}
}

// TestComponentSubTypeIsOnThePoliciesAlone pins the field that is present on
// ten rows and absent on five.
func TestComponentSubTypeIsOnThePoliciesAlone(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	counts := map[string]int{}
	for _, c := range componentsOf(t, h, "/admin/realms/master/components", admin) {
		sub, ok := c["subType"]
		if !ok {
			counts["<absent>"]++
			continue
		}
		counts[sub.(string)]++
	}
	for name, want := range map[string]int{"anonymous": 7, "authenticated": 3, "<absent>": 5} {
		if counts[name] != want {
			t.Errorf("subType %s: got %d, want %d (all: %v)", name, counts[name], want, counts)
		}
	}
}

// TestComponentGuardIsTheRealmPair pins the third failure of the description's
// tag to predict a guard - and the neighbouring family in this same commit
// takes the other pair.
func TestComponentGuardIsTheRealmPair(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	id := componentsOf(t, h, "/admin/realms/master/components", admin)[0]["id"].(string)

	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-realm", http.StatusOK},
		{"manage-realm", http.StatusOK},
		{"manage-identity-providers", http.StatusForbidden},
		{"view-identity-providers", http.StatusForbidden},
		{"view-clients", http.StatusForbidden},
		{"manage-clients", http.StatusForbidden},
		{"view-users", http.StatusForbidden},
	} {
		token := tokenForRoles(t, h, s, realm, tc.role)
		for _, path := range []string{
			"/admin/realms/master/components",
			"/admin/realms/master/components/" + id,
		} {
			if w := get(t, h, path, token); w.Code != tc.want {
				t.Errorf("%s as %s: got %d, want %d", path, tc.role, w.Code, tc.want)
			}
		}
	}

	// A caller holding nothing is 403 rather than the 404 an unknown id gets,
	// so the roles come before the resource here too.
	none := tokenForRoles(t, h, s, realm)
	if w := get(t, h, "/admin/realms/master/components/gloak-probe-nosuch", none); w.Code != http.StatusForbidden {
		t.Errorf("an unknown component to a caller holding nothing: got %d, want 403", w.Code)
	}
}
