package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The eleven operations of P4's second cut. Every expectation here is measured
// against a live 26.7.1 on 2026-08-29; see the "Realm keys", "Default groups"
// and "Client policies" sections of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// TestKeysServesFourKeys is the measurement the cut turned on: master and a
// created realm both carry four, where Gloak minted three.
func TestKeysServesFourKeys(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/keys", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var body struct {
		Active map[string]string `json:"active"`
		Keys   []struct {
			ProviderID  string `json:"providerId"`
			KID         string `json:"kid"`
			Type        string `json:"type"`
			Algorithm   string `json:"algorithm"`
			Use         string `json:"use"`
			PublicKey   string `json:"publicKey"`
			Certificate string `json:"certificate"`
			ValidTo     *int64 `json:"validTo"`
		} `json:"keys"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(body.Keys) != 4 {
		t.Fatalf("want four keys, got %d: %s", len(body.Keys), w.Body)
	}
	want := map[string]struct {
		typ, use string
		material bool
	}{
		"RS256":    {"RSA", "SIG", true},
		"RSA-OAEP": {"RSA", "ENC", true},
		"HS512":    {"OCT", "SIG", false},
		"AES":      {"OCT", "ENC", false},
	}
	for _, key := range body.Keys {
		w, ok := want[key.Algorithm]
		if !ok {
			t.Fatalf("unexpected algorithm %q", key.Algorithm)
		}
		delete(want, key.Algorithm)
		if key.Type != w.typ || key.Use != w.use {
			t.Errorf("%s: want %s/%s, got %s/%s", key.Algorithm, w.typ, w.use, key.Type, key.Use)
		}
		// **The three material fields are present on an RSA key and absent on
		// an OCT one.** Measured on both realms; a struct without omitempty
		// would emit "" and 0 for the two OCT entries.
		if hasMaterial := key.PublicKey != "" || key.Certificate != "" || key.ValidTo != nil; hasMaterial != w.material {
			t.Errorf("%s: material present = %v, want %v", key.Algorithm, hasMaterial, w.material)
		}
		if key.ProviderID == key.KID {
			t.Errorf("%s: providerId equals kid; they are different values on every measured key", key.Algorithm)
		}
		if body.Active[key.Algorithm] != key.KID {
			t.Errorf("%s: active kid %q does not name the key's %q",
				key.Algorithm, body.Active[key.Algorithm], key.KID)
		}
	}
	if len(want) != 0 {
		t.Errorf("algorithms missing from the listing: %v", want)
	}
}

// TestKeysActiveIsInHashMapOrder pins the one part of the body that is a Java
// map: `RSA-OAEP, HS512, RS256, AES`, measured identically on master and on a
// created realm, and exactly what javamap.KeyOrder returns. Go would sort the
// four alphabetically to `AES, HS512, RS256, RSA-OAEP`.
func TestKeysActiveIsInHashMapOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	body := get(t, h, "/admin/realms/master/keys", admin).Body.String()

	const want = `{"active":{"RSA-OAEP":`
	if !strings.HasPrefix(body, want) {
		t.Fatalf("body does not start %q:\n%s", want, body[:min(len(body), 120)])
	}
	names := []string{"RSA-OAEP", "HS512", "RS256", "AES"}
	at := make([]int, len(names))
	active := body[:strings.Index(body, `,"keys":`)]
	for i, name := range names {
		at[i] = strings.Index(active, `"`+name+`":`)
		if at[i] < 0 {
			t.Fatalf("%q missing from active: %s", name, active)
		}
	}
	for i := 1; i < len(at); i++ {
		if at[i-1] > at[i] {
			t.Fatalf("active is not in HashMap order (%s before %s): %s", names[i], names[i-1], active)
		}
	}
}

// TestKeysTakesTheRealmReadRoles: view-realm or manage-realm, and nothing else.
// Measured across all 22 realm-management roles plus a caller holding none.
func TestKeysTakesTheRealmReadRoles(t *testing.T) {
	h, s, realm := newServer(t)
	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-realm", http.StatusOK},
		{"manage-realm", http.StatusOK},
		{"view-users", http.StatusForbidden},
		{"query-groups", http.StatusForbidden},
		{"view-clients", http.StatusForbidden},
		{"impersonation", http.StatusForbidden},
	} {
		t.Run(tc.role, func(t *testing.T) {
			token := tokenForRole(t, h, s, realm, tc.role)
			if w := get(t, h, "/admin/realms/master/keys", token); w.Code != tc.want {
				t.Fatalf("want %d, got %d: %s", tc.want, w.Code, w.Body)
			}
		})
	}
}

// TestDefaultGroupsRoundTrip: the add is idempotent, the remove of a group that
// is not there is a 204, and the listing entry is the membership shape.
func TestDefaultGroupsRoundTrip(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	gid := createGroup(t, h, "dg-top", admin)

	for range 2 {
		if w := sendJSON(t, h, http.MethodPut, "/admin/realms/master/default-groups/"+gid, "", admin); w.Code != http.StatusNoContent {
			t.Fatalf("PUT: want 204, got %d: %s", w.Code, w.Body)
		}
	}

	w := get(t, h, "/admin/realms/master/default-groups", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: want 200, got %d: %s", w.Code, w.Body)
	}
	// The membership shape: no subGroupCount, no attributes, no access.
	want := `[{"id":"` + gid + `","name":"dg-top","path":"/dg-top","subGroups":[]}]`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Fatalf("listing:\n got %s\nwant %s", got, want)
	}
	// briefRepresentation does nothing to it - measured, absent and false gave
	// byte-identical bodies.
	if got := strings.TrimSpace(get(t, h, "/admin/realms/master/default-groups?briefRepresentation=false", admin).Body.String()); got != want {
		t.Errorf("briefRepresentation=false changed the body:\n%s", got)
	}

	for range 2 {
		if w := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/default-groups/"+gid, "", admin); w.Code != http.StatusNoContent {
			t.Fatalf("DELETE: want 204, got %d: %s", w.Code, w.Body)
		}
	}
	if got := strings.TrimSpace(get(t, h, "/admin/realms/master/default-groups", admin).Body.String()); got != "[]" {
		t.Errorf("after the delete: %s", got)
	}
}

// TestDefaultGroupWritesJudgeTheCallerBeforeTheGroup is this cut's finding, and
// the one an implementer would "fix".
//
// Every other route naming a group answers 404 for a group that does not exist
// to every caller, including one holding no admin role - that is guardGroup and
// AGENTS.md records it. These two answer **403** to a caller that may read the
// listing but not write it, and 403 to a caller holding nothing. Measured on
// both verbs.
func TestDefaultGroupWritesJudgeTheCallerBeforeTheGroup(t *testing.T) {
	h, s, realm := newServer(t)
	const gone = "/admin/realms/master/default-groups/00000000-0000-0000-0000-000000000000"
	admin := tokenFor(t, h, "admin", "admin")
	reader := tokenForRole(t, h, s, realm, "view-realm")
	nobody := tokenFor(t, h, createUserWithPassword(t, s, realm, "dg-nobody", "pw").Username, "pw")

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			if w := sendJSON(t, h, method, gone, "", reader); w.Code != http.StatusForbidden {
				t.Errorf("view-realm: want 403, got %d: %s", w.Code, w.Body)
			}
			if w := sendJSON(t, h, method, gone, "", nobody); w.Code != http.StatusForbidden {
				t.Errorf("no admin role: want 403, got %d: %s", w.Code, w.Body)
			}
			// And once the caller may write, the group's absence is a 404 with
			// the membership routes' spelling, not the Groups routes'.
			w := sendJSON(t, h, method, gone, "", admin)
			if w.Code != http.StatusNotFound {
				t.Fatalf("manage-realm: want 404, got %d: %s", w.Code, w.Body)
			}
			if got, want := strings.TrimSpace(w.Body.String()), `{"error":"Group not found"}`; got != want {
				t.Errorf("body = %s, want %s", got, want)
			}
		})
	}
}

// TestGroupByPathResolvesThePathBeforeTheCaller is the opposite ordering on the
// route next door, which is why the two cannot share a guard.
func TestGroupByPathResolvesThePathBeforeTheCaller(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createGroup(t, h, "gbp-top", admin)
	nobody := tokenFor(t, h, createUserWithPassword(t, s, realm, "gbp-nobody", "pw").Username, "pw")

	// A path that resolves to nothing is 404 to a caller the route refuses.
	w := get(t, h, "/admin/realms/master/group-by-path/nosuchgroup", nobody)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown path: want 404, got %d: %s", w.Code, w.Body)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"error":"Group path does not exist"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
	// A path that resolves is 403 to the same caller.
	if w := get(t, h, "/admin/realms/master/group-by-path/gbp-top", nobody); w.Code != http.StatusForbidden {
		t.Errorf("known path: want 403, got %d: %s", w.Code, w.Body)
	}
	// query-groups opens the group listing and is 403 here.
	querier := tokenForRole(t, h, s, realm, "query-groups")
	if w := get(t, h, "/admin/realms/master/group-by-path/gbp-top", querier); w.Code != http.StatusForbidden {
		t.Errorf("query-groups: want 403, got %d: %s", w.Code, w.Body)
	}
	// manage-realm opens the default groups beside it and is 403 here.
	manager := tokenForRole(t, h, s, realm, "manage-realm")
	if w := get(t, h, "/admin/realms/master/group-by-path/gbp-top", manager); w.Code != http.StatusForbidden {
		t.Errorf("manage-realm: want 403, got %d: %s", w.Code, w.Body)
	}
}

// TestGroupByPathIsTheGroupReadWithoutAccess pins the sixth shape: identical to
// GET /groups/{id} but for the access block, measured side by side.
func TestGroupByPathIsTheGroupReadWithoutAccess(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	gid := createGroup(t, h, "shape-top", admin)
	child := postJSON(t, h, "/admin/realms/master/groups/"+gid+"/children", `{"name":"shape-child"}`, admin)
	if child.Code != http.StatusCreated {
		t.Fatalf("create the child: %d %s", child.Code, child.Body)
	}

	byID := strings.TrimSpace(get(t, h, "/admin/realms/master/groups/"+gid, admin).Body.String())
	byPath := strings.TrimSpace(get(t, h, "/admin/realms/master/group-by-path/shape-top", admin).Body.String())

	access := byID[strings.Index(byID, `,"access":`):]
	if want := strings.TrimSuffix(byID, access) + "}"; byPath != want {
		t.Fatalf("group-by-path:\n got %s\nwant %s", byPath, want)
	}
	// A leading slash is optional and a nested path walks down.
	for _, path := range []string{"/shape-top", "shape-top"} {
		if w := get(t, h, "/admin/realms/master/group-by-path"+ensureLeadingSlash(path), admin); w.Code != http.StatusOK {
			t.Errorf("%q: want 200, got %d", path, w.Code)
		}
	}
	nested := get(t, h, "/admin/realms/master/group-by-path/shape-top/shape-child", admin)
	if nested.Code != http.StatusOK || !strings.Contains(nested.Body.String(), `"path":"/shape-top/shape-child"`) {
		t.Errorf("nested: %d %s", nested.Code, nested.Body)
	}
}

func ensureLeadingSlash(s string) string {
	if strings.HasPrefix(s, "/") {
		return s
	}
	return "/" + s
}

// TestClientPoliciesAreTheRealmRepresentationsOwnState: the four operations and
// the realm representation read and write one place, measured in both
// directions.
func TestClientPoliciesAreTheRealmRepresentationsOwnState(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	const profiles = `{"profiles":[{"name":"prof-a","description":"d","executors":[{"executor":"secure-session","configuration":{}}]}]}`

	if w := sendJSON(t, h, http.MethodPut, "/admin/realms/master/client-policies/profiles", profiles, admin); w.Code != http.StatusNoContent {
		t.Fatalf("PUT profiles: %d %s", w.Code, w.Body)
	}
	if got := strings.TrimSpace(get(t, h, "/admin/realms/master/client-policies/profiles", admin).Body.String()); got != profiles {
		t.Fatalf("GET profiles:\n got %s\nwant %s", got, profiles)
	}
	rep := readRealm(t, h, "master", admin)
	if len(rep.ClientProfiles.Profiles) != 1 || rep.ClientProfiles.Profiles[0].Name != "prof-a" {
		t.Errorf("the realm representation does not carry the profile: %+v", rep.ClientProfiles)
	}

	// And the other way: a realm PUT replaces them.
	if w := sendJSON(t, h, http.MethodPut, "/admin/realms/master",
		`{"clientProfiles":{"profiles":[{"name":"via-realm","executors":[]}]}}`, admin); w.Code != http.StatusNoContent {
		t.Fatalf("PUT realm: %d %s", w.Code, w.Body)
	}
	if got, want := strings.TrimSpace(get(t, h, "/admin/realms/master/client-policies/profiles", admin).Body.String()),
		`{"profiles":[{"name":"via-realm","executors":[]}]}`; got != want {
		t.Errorf("after the realm PUT:\n got %s\nwant %s", got, want)
	}

	// And a clientProfiles object naming no array **clears** them, measured -
	// which is what makes the nil the merge leaves an empty array and not null.
	if w := sendJSON(t, h, http.MethodPut, "/admin/realms/master", `{"clientProfiles":{}}`, admin); w.Code != http.StatusNoContent {
		t.Fatalf("PUT realm with an empty clientProfiles: %d %s", w.Code, w.Body)
	}
	if got, want := strings.TrimSpace(get(t, h, "/admin/realms/master/client-policies/profiles", admin).Body.String()),
		`{"profiles":[]}`; got != want {
		t.Errorf("after clearing:\n got %s\nwant %s", got, want)
	}
}

// TestClientPolicyRejections: three error families on one endpoint, and the
// absent body is a 400 where PUT /admin/realms/{realm} answers a 500 for the
// very same absence.
func TestClientPolicyRejections(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct {
		name, method, path, body, want string
	}{
		{
			"malformed profiles", http.MethodPut, "/admin/realms/master/client-policies/profiles", "nope",
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`,
		},
		{
			"absent profiles", http.MethodPut, "/admin/realms/master/client-policies/profiles", "",
			`{"errorMessage":"Passing null clientProfiles not allowed"}`,
		},
		{
			"absent policies", http.MethodPut, "/admin/realms/master/client-policies/policies", "",
			`{"errorMessage":"Passing null clientPolicies not allowed"}`,
		},
		{
			"a policy naming a profile the realm does not have", http.MethodPut,
			"/admin/realms/master/client-policies/policies",
			`{"policies":[{"name":"pol-b","conditions":[],"profiles":["nope"]}]}`,
			`{"errorMessage":"Policy pol-b contains invalid profile nope"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := sendJSON(t, h, tc.method, tc.path, tc.body, admin)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body)
			}
			if got := strings.TrimSpace(w.Body.String()); got != tc.want {
				t.Fatalf("body:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestClientPolicyGlobalSets: the two query parameters each add one key, and
// the ten global profiles are served as recorded rather than re-marshalled.
func TestClientPolicyGlobalSets(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	if got, want := strings.TrimSpace(get(t, h, "/admin/realms/master/client-policies/policies?include-global-policies=true", admin).Body.String()),
		`{"policies":[],"globalPolicies":[]}`; got != want {
		t.Errorf("policies:\n got %s\nwant %s", got, want)
	}

	body := get(t, h, "/admin/realms/master/client-policies/profiles?include-global-profiles=true", admin).Body.Bytes()
	var out struct {
		GlobalProfiles []struct {
			Name string `json:"name"`
		} `json:"globalProfiles"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.GlobalProfiles) != 10 {
		t.Fatalf("want the ten recorded global profiles, got %d", len(out.GlobalProfiles))
	}
	if out.GlobalProfiles[0].Name != "fapi-1-baseline" {
		t.Errorf("first global profile = %q, want fapi-1-baseline", out.GlobalProfiles[0].Name)
	}
	// The recorded bytes go out unchanged, keys and all. This substring is one
	// of the configurations whose keys are not in alphabetical order, so a
	// re-marshalled map would not contain it.
	if !strings.Contains(string(body), `{"auto-configure":true,"allow-token-response-type":false}`) {
		t.Error("a global profile's configuration was re-marshalled; its keys are now sorted")
	}
	// And without the parameter the key is absent, not empty.
	if strings.Contains(get(t, h, "/admin/realms/master/client-policies/profiles", admin).Body.String(), "globalProfiles") {
		t.Error("globalProfiles is present without include-global-profiles")
	}
}

// TestClientTypesIsAFeatureThatIsOff: the 501 is the contract, and it comes
// after authentication and the realm but **before** authorization - every
// authenticated caller gets it, including one holding no admin role.
func TestClientTypesIsAFeatureThatIsOff(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	nobody := tokenFor(t, h, createUserWithPassword(t, s, realm, "ct-nobody", "pw").Username, "pw")
	const want = `{"error":"Feature not enabled","error_description":"For more on this error consult the server log."}`

	for _, token := range []string{admin, nobody} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			w := sendJSON(t, h, method, "/admin/realms/master/client-types", "{}", token)
			if w.Code != http.StatusNotImplemented {
				t.Fatalf("%s: want 501, got %d: %s", method, w.Code, w.Body)
			}
			if got := strings.TrimSpace(w.Body.String()); got != want {
				t.Fatalf("%s body:\n got %s\nwant %s", method, got, want)
			}
		}
	}
	// The realm still comes first, and no token still comes before that.
	if w := get(t, h, "/admin/realms/nosuchrealm/client-types", admin); w.Code != http.StatusNotFound {
		t.Errorf("unknown realm: want 404, got %d: %s", w.Code, w.Body)
	}
	if w := get(t, h, "/admin/realms/master/client-types", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: want 401, got %d: %s", w.Code, w.Body)
	}
}

// createGroup makes a top-level group through the API and returns its id.
func createGroup(t *testing.T, h http.Handler, name, token string) string {
	t.Helper()
	w := postJSON(t, h, "/admin/realms/master/groups", `{"name":"`+name+`"}`, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %q: %d %s", name, w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	return location[strings.LastIndex(location, "/")+1:]
}
