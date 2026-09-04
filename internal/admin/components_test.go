package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
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

// ---- The four writes and sub-component-types ---------------------------

const policyType = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"

// createComponentIn posts one component into a realm and returns the recorder,
// so a caller can assert the refusal as well as the success.
func createComponentIn(t *testing.T, h http.Handler, realm, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return send(t, h, http.MethodPost, "/admin/realms/"+realm+"/components", token, body)
}

// componentBody builds a client-registration policy body with a fixed id.
func componentBody(id, name, provider, config string) string {
	out := `{"id":"` + id + `","name":"` + name + `","providerId":"` + provider +
		`","providerType":"` + policyType + `","subType":"anonymous"`
	if config != "" {
		out += `,"config":` + config
	}
	return out + `}`
}

// readComponentBody reads one component back as raw JSON, which is what the
// config's key order has to be asserted against.
func readComponentBody(t *testing.T, h http.Handler, realm, id, token string) string {
	t.Helper()
	w := get(t, h, "/admin/realms/"+realm+"/components/"+id, token)
	if w.Code != http.StatusOK {
		t.Fatalf("reading %s: %d %s", id, w.Code, w.Body)
	}
	return strings.TrimSpace(w.Body.String())
}

// TestComponentCreateFiltersTheConfigAndKeepsTheJavaMapOrder is the create's
// two measured behaviours in one place.
//
// **The filter is the catalogue**: an undeclared key is dropped silently rather
// than refused. **The order is javamap.KeyOrder's over the survivors**, not the
// request's - the request below sends `priority, zzzUndeclared, keySize,
// algorithm` and the answer is `keySize, priority, algorithm`, which neither
// the request order nor sorting produces.
func TestComponentCreateFiltersTheConfigAndKeepsTheJavaMapOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	const id = "c0e00000-0000-4000-9000-000000000001"
	body := `{"id":"` + id + `","name":"gloak-probe-keys","providerId":"rsa-generated",` +
		`"providerType":"org.keycloak.keys.KeyProvider","config":` +
		`{"priority":["7"],"zzzUndeclared":["v"],"keySize":["2048"],"algorithm":["RS256"]}}`
	if w := createComponentIn(t, h, "master", admin, body); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	got := readComponentBody(t, h, "master", id, admin)
	const want = `"config":{"keySize":["2048"],"priority":["7"],"algorithm":["RS256"]}`
	if !strings.Contains(got, want) {
		t.Errorf("config: got %s, want it to contain %s", got, want)
	}
}

// TestComponentCreateDefaultsAndOmissions pins four things a reader would
// expect to be refused and that are not.
func TestComponentCreateDefaultsAndOmissions(t *testing.T) {
	h, _, realm := newServer(t)
	admin := adminToken(t, h)

	// An absent parentId defaults to the realm's own id.
	const noParent = "c0e00000-0000-4000-9000-000000000002"
	if w := createComponentIn(t, h, "master", admin,
		componentBody(noParent, "gloak-probe-no-parent", "scope", "")); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if got := readComponentBody(t, h, "master", noParent, admin); !strings.Contains(got,
		`"parentId":"`+realm.ID+`"`) {
		t.Errorf("an absent parentId did not default to the realm: %s", got)
	}

	// A parentId naming nothing is a 201 and is stored raw.
	const oddParent = "c0e00000-0000-4000-9000-000000000003"
	if w := createComponentIn(t, h, "master", admin,
		`{"id":"`+oddParent+`","name":"gloak-probe-odd-parent","providerId":"scope",`+
			`"providerType":"`+policyType+`","parentId":"gloak-probe-nowhere"}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if got := readComponentBody(t, h, "master", oddParent, admin); !strings.Contains(got,
		`"parentId":"gloak-probe-nowhere"`) {
		t.Errorf("a parentId naming nothing was not stored raw: %s", got)
	}

	// No name at all: a 201, and the row reads back with no `name` key. That is
	// the state master's declarative-user-profile row is in, reached through
	// the API.
	const noName = "c0e00000-0000-4000-9000-000000000004"
	if w := createComponentIn(t, h, "master", admin,
		`{"id":"`+noName+`","providerId":"scope","providerType":"`+policyType+`"}`); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if got := readComponentBody(t, h, "master", noName, admin); strings.Contains(got, `"name"`) {
		t.Errorf("a create with no name produced a name key: %s", got)
	}

	// A duplicate name is a 201: this family has no name uniqueness, which is
	// why a default realm can hold two rows called `Allowed Client Scopes`.
	const dupName = "c0e00000-0000-4000-9000-000000000005"
	if w := createComponentIn(t, h, "master", admin,
		componentBody(dupName, "Max Clients Limit", "max-clients",
			`{"max-clients":["3"]}`)); w.Code != http.StatusCreated {
		t.Errorf("a duplicate name: got %d %s, want 201", w.Code, w.Body)
	}
}

// TestComponentCreateProviderOutcomes is the sweep a golden cannot hold: three
// different statuses for a provider the endpoint will not create, and only a
// registry of all 245 registered pairs tells them apart.
//
// The rows are the measured ones. `oidc-sub-mapper` is a **real** protocol
// mapper and `gloak-probe-nope` is not a real anything, and they answer
// differently under the same registered provider type - which is what says the
// 400 is about the pair rather than about the type.
func TestComponentCreateProviderOutcomes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		name         string
		providerID   string
		providerType string
		code         int
		want         string
	}{
		{"an unknown id under a known type", "gloak-probe-nope", policyType,
			http.StatusBadRequest, `{"error":"Invalid provider type or no such provider"}`},
		{"a known id under an unknown type", "max-clients", "gloak.probe.NoSuchType",
			http.StatusBadRequest, `{"error":"Invalid provider type or no such provider"}`},
		{"a known id under the wrong known type", "max-clients", "org.keycloak.keys.KeyProvider",
			http.StatusBadRequest, `{"error":"Invalid provider type or no such provider"}`},
		{"a registered Workflow provider", "notify-user",
			"org.keycloak.models.workflow.WorkflowStepProvider", http.StatusForbidden,
			`{"error":"Components managed through internal APIs cannot be managed through ` +
				`the component endpoint"}`},
		{"the other Workflow type", "default", "org.keycloak.models.workflow.WorkflowProvider",
			http.StatusForbidden,
			`{"error":"Components managed through internal APIs cannot be managed through ` +
				`the component endpoint"}`},
		{"a registered protocol mapper", "oidc-sub-mapper", "org.keycloak.protocol.ProtocolMapper",
			http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a registered authenticator", "auth-cookie", "org.keycloak.authentication.Authenticator",
			http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a registered validator", "length", "org.keycloak.validate.Validator",
			http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
	}
	for _, c := range cases {
		body := `{"name":"gloak-probe-x","providerId":"` + c.providerID +
			`","providerType":"` + c.providerType + `"}`
		w := createComponentIn(t, h, "master", admin, body)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != c.want {
			t.Errorf("%s: got %d %s, want %d %s", c.name, w.Code, w.Body, c.code, c.want)
		}
	}
}

// TestComponentConfigRulesRunInDeclaredPropertyOrder is the claim the fifteen
// refusals rest on, and it is the one a per-provider golden cannot make: it
// needs two faults in one request.
//
// `priority`, `enabled` and `active` are the first three properties every key
// provider declares, so a create wrong in one of them **and** in a
// provider-specific property answers about them. Measured on three pairs.
func TestComponentConfigRulesRunInDeclaredPropertyOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const keyType = "org.keycloak.keys.KeyProvider"

	cases := []struct {
		name     string
		provider string
		config   string
		want     string
	}{
		{"a bad priority beats a missing private key", "rsa",
			`{"priority":["abc"]}`, `'Priority' should be a number`},
		{"a bad priority beats a bad key size", "rsa-generated",
			`{"priority":["abc"],"keySize":["1000"]}`, `'Priority' should be a number`},
		{"enabled beats active", "rsa-generated",
			`{"enabled":["nope"],"active":["nope"]}`, `'Enabled' should be 'true' or 'false'`},
		{"a missing private key on its own", "rsa", `{}`, `'Private RSA Key' is required`},
		{"a bad key size on its own", "rsa-generated",
			`{"keySize":["1000"]}`, `'Key size' should be 1024, 2048, 3072 or 4096`},
		{"a bad secret size", "aes-generated",
			`{"secretSize":["5"]}`, `'Secret size' should be 16, 24, 32, 64, 128, 256 or 512`},
		{"a two-element curve list", "eddsa-generated",
			`{"eddsaEllipticCurveKey":["nope"]}`, `'Elliptic Curve' should be Ed25519 or Ed448`},
	}
	for _, c := range cases {
		body := `{"name":"gloak-probe-order","providerId":"` + c.provider +
			`","providerType":"` + keyType + `","config":` + c.config + `}`
		w := createComponentIn(t, h, "master", admin, body)
		want := `{"errorMessage":"` + c.want + `"}`
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("%s: got %d %s, want 400 %s", c.name, w.Code, w.Body, want)
		}
	}
}

// TestComponentConfigRulesAreNotTheRequiredFlag is the finding that makes the
// rules a table rather than a walk over the catalogue.
//
// `max-clients` declares its one property with `required:false` and a bare
// create is refused anyway; `allowed-client-templates` declares a boolean and a
// value that is not one is a 201. So the flag records what the server *says*
// and predicts neither refusal.
func TestComponentConfigRulesAreNotTheRequiredFlag(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	entry, ok := model.ComponentProvider(policyType, "max-clients")
	if !ok {
		t.Fatal("max-clients is not in the catalogue")
	}
	for _, p := range entry.Properties {
		if p.Required {
			t.Fatalf("max-clients declares %q required; the premise of this test has changed", p.Name)
		}
	}
	w := createComponentIn(t, h, "master", admin,
		componentBody("c0e00000-0000-4000-9000-000000000010", "gloak-probe-bare", "max-clients", ""))
	want := `{"errorMessage":"'Max Clients Per Realm' is required"}`
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("a bare max-clients: got %d %s, want 400 %s", w.Code, w.Body, want)
	}

	// The other direction: a declared boolean whose value is not one is a 201
	// on this provider, so validation is not applied to every typed property.
	w = createComponentIn(t, h, "master", admin,
		componentBody("c0e00000-0000-4000-9000-000000000011", "gloak-probe-loose",
			"allowed-client-templates", `{"allow-default-scopes":["nope"]}`))
	if w.Code != http.StatusCreated {
		t.Errorf("a bad boolean on allowed-client-templates: got %d %s, want 201", w.Code, w.Body)
	}
}

// TestComponentUpdateWritesThePathsComponent is the measurement that separates
// this route from the two that look identical.
//
// `PUT .../protocol-mappers/models/{id}` and
// `PUT .../identity-provider/instances/{alias}/mappers/{id}` both write the
// **body's** id; this one writes the **path's** and ignores the body's. It
// needs two real components, so no golden can show it.
func TestComponentUpdateWritesThePathsComponent(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	const a = "c0e00000-0000-4000-9000-00000000001a"
	const b = "c0e00000-0000-4000-9000-00000000001b"
	for id, name := range map[string]string{a: "gloak-probe-path-row", b: "gloak-probe-body-row"} {
		if w := createComponentIn(t, h, "master", admin,
			componentBody(id, name, "max-clients", `{"max-clients":["42"]}`)); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", id, w.Code, w.Body)
		}
	}
	w := send(t, h, http.MethodPut, "/admin/realms/master/components/"+a, admin,
		componentBody(b, "gloak-probe-which-one", "max-clients", `{"max-clients":["77"]}`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if got := readComponentBody(t, h, "master", a, admin); !strings.Contains(got, "gloak-probe-which-one") {
		t.Errorf("the path's component was not written: %s", got)
	}
	if got := readComponentBody(t, h, "master", b, admin); !strings.Contains(got, "gloak-probe-body-row") {
		t.Errorf("the body's component was written: %s", got)
	}
}

// TestComponentUpdateMergesAndRefilters pins the three halves of the PUT's
// config rule, each of which the 204 hides.
func TestComponentUpdateMergesAndRefilters(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const keyType = "org.keycloak.keys.KeyProvider"
	const id = "c0e00000-0000-4000-9000-00000000002a"

	create := `{"id":"` + id + `","name":"gloak-probe-merge","providerId":"rsa-generated",` +
		`"providerType":"` + keyType + `","config":` +
		`{"keySize":["2048"],"priority":["7"],"algorithm":["RS256"]}}`
	if w := createComponentIn(t, h, "master", admin, create); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	put := func(body string) {
		t.Helper()
		w := send(t, h, http.MethodPut, "/admin/realms/master/components/"+id, admin, body)
		if w.Code != http.StatusNoContent {
			t.Fatalf("PUT %s: %d %s", body, w.Code, w.Body)
		}
	}

	// The merge: a key the body does not name survives, an undeclared one is
	// dropped, the two named ones move.
	put(`{"name":"gloak-probe-merge","providerId":"rsa-generated","providerType":"` + keyType +
		`","config":{"priority":["9"],"junk":["v"],"algorithm":["RS512"]}}`)
	got := readComponentBody(t, h, "master", id, admin)
	if !strings.Contains(got, `"config":{"keySize":["2048"],"priority":["9"],"algorithm":["RS512"]}`) {
		t.Errorf("after the merge: %s", got)
	}

	// An empty config and an absent one both change nothing, so the config
	// cannot be cleared through this endpoint at all.
	before := got
	put(`{"name":"gloak-probe-merge","providerId":"rsa-generated","providerType":"` + keyType + `","config":{}}`)
	put(`{"name":"gloak-probe-merge","providerId":"rsa-generated","providerType":"` + keyType + `"}`)
	if after := readComponentBody(t, h, "master", id, admin); after != before {
		t.Errorf("an empty or absent config changed the row:\n before %s\n after  %s", before, after)
	}

	// Changing providerId re-filters against the new provider: hmac-generated
	// does not declare keySize, so that key goes.
	put(`{"name":"gloak-probe-merge","providerId":"hmac-generated","providerType":"` + keyType +
		`","config":{"algorithm":["HS256"]}}`)
	got = readComponentBody(t, h, "master", id, admin)
	if strings.Contains(got, "keySize") {
		t.Errorf("keySize survived a move to hmac-generated: %s", got)
	}
	if !strings.Contains(got, `"config":{"priority":["9"],"algorithm":["HS256"]}`) {
		t.Errorf("after the provider change: %s", got)
	}
}

// TestComponentUpdateNeedsBothProviderFields is the 500 a partial body earns,
// and the 404 that sits between the strict decode and the provider check.
func TestComponentUpdateNeedsBothProviderFields(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const id = "c0e00000-0000-4000-9000-00000000003a"
	if w := createComponentIn(t, h, "master", admin,
		componentBody(id, "gloak-probe-partial", "max-clients",
			`{"max-clients":["42"]}`)); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	const consult = `{"error":"unknown_error","error_description":` +
		`"For more on this error consult the server log."}`
	for _, body := range []string{
		`{}`,
		`{"name":"gloak-probe-renamed"}`,
		`{"providerId":"max-clients"}`,
		`{"providerType":"` + policyType + `"}`,
		`null`,
	} {
		w := send(t, h, http.MethodPut, "/admin/realms/master/components/"+id, admin, body)
		if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != consult {
			t.Errorf("PUT %s: got %d %s, want 500 %s", body, w.Code, w.Body, consult)
		}
	}
	// Nothing landed: the row is exactly as it was created.
	if got := readComponentBody(t, h, "master", id, admin); !strings.Contains(got, "gloak-probe-partial") {
		t.Errorf("a refused PUT wrote something: %s", got)
	}

	// The strict decode runs **before** the path's id is resolved: the same
	// missing id answers 400 with an unknown field and 404 without one.
	missing := "/admin/realms/master/components/gloak-probe-no-such-component"
	w := send(t, h, http.MethodPut, missing, admin, `{"providerId":"max-clients","zzUnknown":1}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Unrecognized field") {
		t.Errorf("an unknown field on a missing id: got %d %s, want the strict 400", w.Code, w.Body)
	}
	w = send(t, h, http.MethodPut, missing, admin,
		`{"providerId":"max-clients","providerType":"`+policyType+`"}`)
	const notFound = `{"error":"Could not find component"}`
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != notFound {
		t.Errorf("a good body on a missing id: got %d %s, want 404 %s", w.Code, w.Body, notFound)
	}
}

// TestComponentDeleteRepeatIs404 is the pair with the initial access tokens'
// repeat delete, which is a 204. Two families, one verb, opposite answers.
func TestComponentDeleteRepeatIs404(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const id = "c0e00000-0000-4000-9000-00000000004a"
	if w := createComponentIn(t, h, "master", admin,
		componentBody(id, "gloak-probe-doomed", "max-clients",
			`{"max-clients":["42"]}`)); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	path := "/admin/realms/master/components/" + id
	if w := send(t, h, http.MethodDelete, path, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("first delete: %d %s", w.Code, w.Body)
	}
	w := send(t, h, http.MethodDelete, path, admin, "")
	const want = `{"error":"Could not find component"}`
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("second delete: got %d %s, want 404 %s", w.Code, w.Body, want)
	}
	// The config went with it: nothing is left to read.
	if w := get(t, h, path, admin); w.Code != http.StatusNotFound {
		t.Errorf("reading a deleted component: %d %s", w.Code, w.Body)
	}
}

// TestSubComponentTypesIgnoreTheParent is the measurement the golden cannot
// make, because a golden addresses one parent.
//
// Byte-identical bodies came back for one type asked through three different
// parent components on the server; this asks through every component the realm
// has and requires them all to agree.
func TestSubComponentTypesIgnoreTheParent(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	rows := componentsOf(t, h, "/admin/realms/master/components", admin)
	if len(rows) < 3 {
		t.Fatalf("only %d components to ask through", len(rows))
	}
	const typ = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	var first string
	for i, c := range rows {
		w := get(t, h, "/admin/realms/master/components/"+c["id"].(string)+
			"/sub-component-types?type="+typ, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("through %v: %d %s", c["id"], w.Code, w.Body)
		}
		if i == 0 {
			first = w.Body.String()
			continue
		}
		if w.Body.String() != first {
			t.Errorf("the answer through %v differs from the first parent's", c["id"])
		}
	}
}

// TestSubComponentTypesRefusals pins the four answers that are not the
// catalogue, including the one a reader would expect to be a 404.
func TestSubComponentTypesRefusals(t *testing.T) {
	h, _, realm := newServer(t)
	admin := adminToken(t, h)
	parent := componentsOf(t, h, "/admin/realms/master/components", admin)[0]["id"].(string)
	base := "/admin/realms/master/components/"

	cases := []struct {
		name string
		path string
		code int
		want string
	}{
		{"no type at all", base + parent + "/sub-component-types",
			http.StatusBadRequest, `{"error":"must specify a subtype"}`},
		{"an empty type", base + parent + "/sub-component-types?type=",
			http.StatusBadRequest, `{"error":"must specify a subtype"}`},
		{"a type nobody registers", base + parent + "/sub-component-types?type=gloak.probe.Nope",
			http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"the same type upper-cased", base + parent +
			"/sub-component-types?type=ORG.KEYCLOAK.KEYS.KEYPROVIDER",
			http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a parent that does not exist", base + "gloak-probe-nope/sub-component-types?type=" +
			"org.keycloak.userprofile.UserProfileProvider",
			http.StatusNotFound, `{"error":"Could not find parent component"}`},
		{"the realm's own id as the parent", base + realm.ID + "/sub-component-types?type=" +
			"org.keycloak.userprofile.UserProfileProvider",
			http.StatusNotFound, `{"error":"Could not find parent component"}`},
		{"a registered type with no entries", base + parent +
			"/sub-component-types?type=org.keycloak.validate.Validator",
			http.StatusOK, `[]`},
	}
	for _, c := range cases {
		w := get(t, h, c.path, admin)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != c.want {
			t.Errorf("%s: got %d %s, want %d %s", c.name, w.Code, w.Body, c.code, c.want)
		}
	}

	// The missing-type 400 beats the parent's 404, which fixes the order.
	w := get(t, h, base+"gloak-probe-nope/sub-component-types", admin)
	if w.Code != http.StatusBadRequest {
		t.Errorf("no type against a missing parent: got %d %s, want the 400", w.Code, w.Body)
	}
}

// TestComponentWriteGuardIsManageRealmAlone is the read/write split inside one
// pair, and the pair itself is the finding the reads already record.
func TestComponentWriteGuardIsManageRealmAlone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	const id = "c0e00000-0000-4000-9000-00000000005a"
	if w := createComponentIn(t, h, "master", admin,
		componentBody(id, "gloak-probe-guarded", "max-clients",
			`{"max-clients":["42"]}`)); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}

	cases := []struct {
		role  string
		read  int
		write int
	}{
		{"view-realm", http.StatusOK, http.StatusForbidden},
		{"manage-realm", http.StatusOK, http.StatusNoContent},
		{"manage-identity-providers", http.StatusForbidden, http.StatusForbidden},
		{"view-clients", http.StatusForbidden, http.StatusForbidden},
		{"manage-clients", http.StatusForbidden, http.StatusForbidden},
		{"manage-users", http.StatusForbidden, http.StatusForbidden},
	}
	tokens := map[string]string{}
	for _, c := range cases {
		token := tokenForRole(t, h, s, realm, c.role)
		tokens[c.role] = token
		if w := get(t, h, "/admin/realms/master/components/"+id, token); w.Code != c.read {
			t.Errorf("%s reading: got %d, want %d", c.role, w.Code, c.read)
		}
		if w := get(t, h, "/admin/realms/master/components/"+id+
			"/sub-component-types?type=org.keycloak.validate.Validator", token); w.Code != c.read {
			t.Errorf("%s on sub-component-types: got %d, want %d", c.role, w.Code, c.read)
		}
		w := send(t, h, http.MethodPut, "/admin/realms/master/components/"+id, token,
			componentBody(id, "gloak-probe-guarded", "max-clients", `{"max-clients":["43"]}`))
		if w.Code != c.write {
			t.Errorf("%s updating: got %d %s, want %d", c.role, w.Code, w.Body, c.write)
		}
	}

	// The role is judged before the component is resolved, per verb: a
	// view-realm caller gets 404 on the read and 403 on the two writes for an
	// id that does not exist, where a manage-realm caller gets 404 on all
	// three.
	viewer, manager := tokens["view-realm"], tokens["manage-realm"]
	missing := "/admin/realms/master/components/gloak-probe-no-such-component"
	if w := get(t, h, missing, viewer); w.Code != http.StatusNotFound {
		t.Errorf("a viewer reading a missing component: %d", w.Code)
	}
	if w := send(t, h, http.MethodDelete, missing, viewer, ""); w.Code != http.StatusForbidden {
		t.Errorf("a viewer deleting a missing component: %d, want 403", w.Code)
	}
	if w := send(t, h, http.MethodDelete, missing, manager, ""); w.Code != http.StatusNotFound {
		t.Errorf("a manager deleting a missing component: %d, want 404", w.Code)
	}
}
