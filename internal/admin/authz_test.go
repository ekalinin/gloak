package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// createClientWithBody posts one client and returns the UUID its Location names.
func createClientWithBody(t *testing.T, h http.Handler, token, body string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/clients", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", body, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// createAuthzClient creates a client with authorization services on and returns
// its UUID.
func createAuthzClient(t *testing.T, h http.Handler, token, clientID string) string {
	t.Helper()
	return createClientWithBody(t, h, token,
		`{"clientId":"`+clientID+`","enabled":true,"publicClient":false,`+
			`"serviceAccountsEnabled":true,"authorizationServicesEnabled":true}`)
}

// TestAuthzGateRunsBeforeTheRoles pins the two halves of guardAuthz that are
// easiest to get wrong, and pins them against each other.
//
// **The gate precedes authorization.** A caller holding no admin role gets the
// 404 for a client without the flag, measured on four callers, so this is
// client-types' order and not organizations'. A guard that checked the roles
// first would answer 403 and this test names that cell.
//
// **The unknown client is the id-phishing branch.** view-clients sees
// `Could not find client` and manage-authorization - which reads the resource
// server of a client that does exist - sees 403. Measured one role at a time
// over seven callers.
func TestAuthzGateRunsBeforeTheRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	none := tokenForRoles(t, h, s, realm)
	viewClients := tokenForRoles(t, h, s, realm, "view-clients")
	manageAuthz := tokenForRoles(t, h, s, realm, "manage-authorization")

	off := createClientWithBody(t, h, admin, `{"clientId":"gloak-t-authz-off","enabled":true}`)
	on := createAuthzClient(t, h, admin, "gloak-t-authz-on")
	const missing = "00000000-0000-0000-0000-000000000000"
	const notEnabled = `{"error":"HTTP 404 Not Found"}`

	// A client without the flag: the same 404 to every caller, including one
	// holding nothing. Checked on more than one path because the gate lives in
	// the guard rather than in a handler.
	for _, suffix := range []string{"", "/settings", "/policy/providers", "/permission/providers"} {
		for name, token := range map[string]string{"admin": admin, "none": none, "manage-authorization": manageAuthz} {
			w := get(t, h, "/admin/realms/master/clients/"+off+"/authz/resource-server"+suffix, token)
			if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != notEnabled {
				t.Errorf("%s%s as %s: got %d %s, want 404 %s", off, suffix, name, w.Code, w.Body, notEnabled)
			}
		}
	}

	// The phishing branch: a client that does not exist at all.
	for _, tc := range []struct {
		caller string
		token  string
		status int
		body   string
	}{
		{"view-clients", viewClients, http.StatusNotFound, `{"error":"Could not find client"}`},
		{"manage-authorization", manageAuthz, http.StatusForbidden, `{"error":"HTTP 403 Forbidden"}`},
		{"none", none, http.StatusForbidden, `{"error":"HTTP 403 Forbidden"}`},
	} {
		w := get(t, h, "/admin/realms/master/clients/"+missing+"/authz/resource-server", tc.token)
		if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.body {
			t.Errorf("unknown client as %s: got %d %s, want %d %s",
				tc.caller, w.Code, w.Body, tc.status, tc.body)
		}
	}

	// And a client that does have the flag: now the roles decide, so the same
	// caller that got 404 above gets 403 here. Without this row the gate could
	// be "refuse everybody" and the rows above would still pass.
	if w := get(t, h, "/admin/realms/master/clients/"+on+"/authz/resource-server", none); w.Code != http.StatusForbidden {
		t.Errorf("a flagged client to a caller holding nothing: got %d %s, want 403", w.Code, w.Body)
	}
}

// TestAuthzRoleSetsAreTheMeasuredOnes walks the sweep taken on 2026-08-31, one
// single role at a time.
//
// Three cells are the reason it exists, and none follows from a role's name:
// query-clients is refused although it is in clientsReadRoles, manage-realm is
// refused although the route hangs off a client, and **GET .../settings takes
// the write set** although the read beside it does not.
func TestAuthzRoleSetsAreTheMeasuredOnes(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-roles")

	read := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"
	for _, tc := range []struct {
		role                            string
		wantRead, wantSettings, wantPut int
	}{
		{"", http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
		{"view-authorization", http.StatusOK, http.StatusForbidden, http.StatusForbidden},
		{"manage-authorization", http.StatusOK, http.StatusOK, http.StatusNoContent},
		{"view-clients", http.StatusOK, http.StatusForbidden, http.StatusForbidden},
		{"query-clients", http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
		{"manage-clients", http.StatusOK, http.StatusOK, http.StatusNoContent},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden, http.StatusForbidden},
	} {
		var token string
		if tc.role == "" {
			token = tokenForRoles(t, h, s, realm)
		} else {
			token = tokenForRoles(t, h, s, realm, tc.role)
		}
		if w := get(t, h, read, token); w.Code != tc.wantRead {
			t.Errorf("GET resource-server as %q: got %d, want %d", tc.role, w.Code, tc.wantRead)
		}
		if w := get(t, h, read+"/settings", token); w.Code != tc.wantSettings {
			t.Errorf("GET settings as %q: got %d, want %d", tc.role, w.Code, tc.wantSettings)
		}
		if w := get(t, h, read+"/policy/providers", token); w.Code != tc.wantRead {
			t.Errorf("GET policy/providers as %q: got %d, want %d", tc.role, w.Code, tc.wantRead)
		}
		w := send(t, h, http.MethodPut, read, token, `{"decisionStrategy":"UNANIMOUS"}`)
		if w.Code != tc.wantPut {
			t.Errorf("PUT resource-server as %q: got %d %s, want %d", tc.role, w.Code, w.Body, tc.wantPut)
		}
	}
}

// TestResourceServerPutIsGatedByDecisionStrategy is the case that caught a
// wrong explanation before it shipped.
//
// The first reading was "a body with no name is a 409", from `{}`. The probe
// that refutes it is `{"name":"x"}` - a 409 *with* a name - and
// `{"decisionStrategy":"AFFIRMATIVE"}` alone, which is a 204 with no name at
// all. Both are here, because either alone leaves the wrong rule passing.
func TestResourceServerPutIsGatedByDecisionStrategy(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-ds")
	path := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"

	const conflict = `{"error":"conflict","error_description":"Duplicate resource error"}`
	for _, body := range []string{
		`{}`,
		`{"name":"x"}`,
		`{"allowRemoteResourceManagement":false}`,
		`{"policyEnforcementMode":"PERMISSIVE"}`,
		`{"decisionStrategy":null}`,
	} {
		w := send(t, h, http.MethodPut, path, admin, body)
		if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != conflict {
			t.Errorf("PUT %s: got %d %s, want 409 %s", body, w.Code, w.Body, conflict)
		}
		// The 409 drops the five security headers, measured on this endpoint
		// and on the protocol mappers' - so it belongs to the shape rather than
		// to either route.
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("PUT %s: X-Frame-Options = %q, want it absent", body, got)
		}
	}
	// The name is not the rule: this body has none and is a 204.
	if w := send(t, h, http.MethodPut, path, admin, `{"decisionStrategy":"AFFIRMATIVE"}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT with decisionStrategy alone: got %d %s, want 204", w.Code, w.Body)
	}
}

// TestResourceServerPutReplacesWithDefaults pins what an absent field becomes,
// which is neither what was stored nor the Go zero value.
//
// Measured: a resource server sitting at `false / PERMISSIVE / AFFIRMATIVE`,
// sent `{"decisionStrategy":"UNANIMOUS"}`, came back
// `true / ENFORCING / UNANIMOUS`. A merge leaves `false / PERMISSIVE` and a
// zero-value replace leaves `false / ""`; both are wrong and they are wrong in
// opposite directions on allowRemoteResourceManagement, so a test that only
// checked one of the two fields would miss one of the two mistakes.
func TestResourceServerPutReplacesWithDefaults(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-replace")
	path := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"

	read := func() (bool, string, string) {
		t.Helper()
		w := get(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("read: %d %s", w.Code, w.Body)
		}
		var got struct {
			AllowRemote bool   `json:"allowRemoteResourceManagement"`
			Mode        string `json:"policyEnforcementMode"`
			Strategy    string `json:"decisionStrategy"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding: %v", err)
		}
		return got.AllowRemote, got.Mode, got.Strategy
	}

	if allow, mode, strategy := read(); !allow || mode != "ENFORCING" || strategy != "UNANIMOUS" {
		t.Fatalf("a fresh resource server: got %v %s %s, want true ENFORCING UNANIMOUS", allow, mode, strategy)
	}
	w := send(t, h, http.MethodPut, path, admin,
		`{"allowRemoteResourceManagement":false,"policyEnforcementMode":"PERMISSIVE","decisionStrategy":"AFFIRMATIVE"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("moving it off the defaults: %d %s", w.Code, w.Body)
	}
	if allow, mode, strategy := read(); allow || mode != "PERMISSIVE" || strategy != "AFFIRMATIVE" {
		t.Fatalf("after the full PUT: got %v %s %s, want false PERMISSIVE AFFIRMATIVE", allow, mode, strategy)
	}

	if w := send(t, h, http.MethodPut, path, admin, `{"decisionStrategy":"UNANIMOUS"}`); w.Code != http.StatusNoContent {
		t.Fatalf("the partial PUT: %d %s", w.Code, w.Body)
	}
	allow, mode, strategy := read()
	if !allow {
		t.Errorf("allowRemoteResourceManagement: got false, want true - an absent field takes the representation's default, not the zero value")
	}
	if mode != "ENFORCING" {
		t.Errorf("policyEnforcementMode: got %q, want ENFORCING - an absent field is reset, not kept", mode)
	}
	if strategy != "UNANIMOUS" {
		t.Errorf("decisionStrategy: got %q, want UNANIMOUS", strategy)
	}
}

// TestResourceServerPutEnums pins the three answers an enum value can get, and
// they are three rather than two.
//
// CONSENSUS is a documented decisionStrategy and a **500** here. An unknown
// value is a 400 whose description says the JSON cannot be parsed although it
// parses. Both are Keycloak's own defects and both are reproduced.
func TestResourceServerPutEnums(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-enums")
	path := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"

	for _, tc := range []struct {
		body   string
		status int
		want   string
	}{
		{`{"decisionStrategy":"AFFIRMATIVE"}`, http.StatusNoContent, ""},
		{`{"decisionStrategy":"UNANIMOUS"}`, http.StatusNoContent, ""},
		{`{"decisionStrategy":"CONSENSUS"}`, http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{`{"decisionStrategy":"NOPE"}`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{`{"decisionStrategy":""}`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{`{"policyEnforcementMode":"NOPE","decisionStrategy":"UNANIMOUS"}`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{`{"policyEnforcementMode":"DISABLED","decisionStrategy":"UNANIMOUS"}`, http.StatusNoContent, ""},
		// The strict decoder, and it runs **before** the decisionStrategy gate:
		// this body carries no decisionStrategy and answers the unknown-field
		// 400 rather than the 409.
		{`{"zzz":1}`, http.StatusBadRequest,
			`{"error":"Invalid json representation for ResourceServerRepresentation. Unrecognized field \"zzz\" at line 1 column 9."}`},
	} {
		w := send(t, h, http.MethodPut, path, admin, tc.body)
		if w.Code != tc.status {
			t.Errorf("PUT %s: got %d %s, want %d", tc.body, w.Code, w.Body, tc.status)
			continue
		}
		if tc.want != "" && strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("PUT %s: got %s, want %s", tc.body, w.Body, tc.want)
		}
	}
}

// TestTheTwoResourceServerReadsAreDifferentBodies is the guard against a shared
// serialiser.
//
// `GET .../authz/resource-server` carries id, clientId and name;
// `GET .../settings` carries none of the three. Both are measured, and the two
// are otherwise identical on a resource server holding nothing - which is
// exactly why one struct with omitempty would look right.
func TestTheTwoResourceServerReadsAreDifferentBodies(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-two-reads")
	base := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"

	full := get(t, h, base, admin)
	settings := get(t, h, base+"/settings", admin)
	if full.Code != http.StatusOK || settings.Code != http.StatusOK {
		t.Fatalf("reads: %d and %d", full.Code, settings.Code)
	}
	// The resource server read names the client twice, both times by UUID, and
	// once by clientId under the key `name`. Getting id and clientId from
	// different places is the mistake this asserts against.
	wantFull := `{"id":"` + uuid + `","clientId":"` + uuid + `","name":"gloak-t-authz-two-reads",` +
		`"allowRemoteResourceManagement":true,"policyEnforcementMode":"ENFORCING",` +
		`"resources":[],"policies":[],"scopes":[],"decisionStrategy":"UNANIMOUS"}`
	if got := strings.TrimSpace(full.Body.String()); got != wantFull {
		t.Errorf("resource-server:\n got %s\nwant %s", got, wantFull)
	}
	wantSettings := `{"allowRemoteResourceManagement":true,"policyEnforcementMode":"ENFORCING",` +
		`"resources":[],"policies":[],"scopes":[],"decisionStrategy":"UNANIMOUS"}`
	if got := strings.TrimSpace(settings.Body.String()); got != wantSettings {
		t.Errorf("settings:\n got %s\nwant %s", got, wantSettings)
	}
	// Neither read carries Cache-Control, where every sub-resource read on the
	// family does. Asserted on both because the two go through different
	// handlers.
	if got := full.Header().Get("Cache-Control"); got != "" {
		t.Errorf("resource-server Cache-Control: got %q, want it absent", got)
	}
	if got := settings.Header().Get("Cache-Control"); got != "" {
		t.Errorf("settings Cache-Control: got %q, want it absent", got)
	}
	// The provider catalogue does carry it, which is what makes the two lines
	// above an assertion about these routes rather than about the family.
	providers := get(t, h, base+"/policy/providers", admin)
	if got := providers.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("policy/providers Cache-Control: got %q, want no-cache", got)
	}
}

// TestTheTwoProviderCataloguesAreByteIdentical pins the thing that looks like a
// bug: the permission catalogue is not filtered to permission providers.
//
// Measured with cmp on the reference container - 588 bytes each, identical. The
// order is a Java map's; sorting it would be wrong and no mask hides it.
func TestTheTwoProviderCataloguesAreByteIdentical(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-providers")
	base := "/admin/realms/master/clients/" + uuid + "/authz/resource-server"

	policy := get(t, h, base+"/policy/providers", admin)
	permission := get(t, h, base+"/permission/providers", admin)
	if policy.Body.String() != permission.Body.String() {
		t.Errorf("the two catalogues differ:\n policy     %s\n permission %s", policy.Body, permission.Body)
	}
	const want = `[{"type":"regex","name":"Regex","group":"Identity Based"},` +
		`{"type":"role","name":"Role","group":"Identity Based"},` +
		`{"type":"resource","name":"Resource-Based","group":"Permission"},` +
		`{"type":"scope","name":"Scope-Based","group":"Permission"},` +
		`{"type":"client","name":"Client","group":"Identity Based"},` +
		`{"type":"time","name":"Time","group":"Time Based"},` +
		`{"type":"user","name":"User","group":"Identity Based"},` +
		`{"type":"client-scope","name":"Client Scope","group":"Identity Based"},` +
		`{"type":"group","name":"Group","group":"Identity Based"},` +
		`{"type":"aggregate","name":"Aggregated","group":"Others"}]`
	if got := strings.TrimSpace(policy.Body.String()); got != want {
		t.Errorf("policy/providers:\n got %s\nwant %s", got, want)
	}
	// `uma` is a registered policy provider and is not offered; `js` is absent
	// because SCRIPTS is disabled. Both would be additions nobody measured.
	for _, absent := range []string{`"uma"`, `"js"`} {
		if strings.Contains(policy.Body.String(), absent) {
			t.Errorf("the catalogue offers %s, which a default 26.7.1 does not", absent)
		}
	}
}

// TestTheFlagIsTheResourceServersExistence pins the lifecycle, and the last
// assertion is the one AGENTS.md's "a PUT on a client merges" does not cover.
//
// **A client PUT that does not name authorizationServicesEnabled turns it
// off.** Measured on a client carrying six non-default values: a
// `PUT {"description":"touched"}` left serviceAccountsEnabled,
// implicitFlowEnabled, consentRequired, fullScopeAllowed, publicClient,
// webOrigins and attributes exactly as they were, and dropped this one field.
// Seven fields that merge and one that does not, on one body.
func TestTheFlagIsTheResourceServersExistence(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-authz-flag")
	clientPath := "/admin/realms/master/clients/" + uuid
	rsPath := clientPath + "/authz/resource-server"

	flag := func() any {
		t.Helper()
		w := get(t, h, clientPath, admin)
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("decoding the client: %v", err)
		}
		v, ok := got["authorizationServicesEnabled"]
		if !ok {
			return nil
		}
		return v
	}

	if flag() != true {
		t.Fatalf("after a create naming the flag: got %v, want true", flag())
	}
	// Move the settings off the defaults so the reset below is visible.
	if w := send(t, h, http.MethodPut, rsPath, admin,
		`{"allowRemoteResourceManagement":false,"policyEnforcementMode":"PERMISSIVE","decisionStrategy":"AFFIRMATIVE"}`); w.Code != http.StatusNoContent {
		t.Fatalf("moving the settings: %d %s", w.Code, w.Body)
	}

	// Seven fields merge and this one does not.
	if w := send(t, h, http.MethodPut, clientPath, admin, `{"description":"touched"}`); w.Code != http.StatusNoContent {
		t.Fatalf("the client PUT: %d %s", w.Code, w.Body)
	}
	if f := flag(); f != nil {
		t.Errorf("after a client PUT that does not name it: got %v, want the key absent", f)
	}
	// The neighbour that *does* merge, so the assertion above is about this
	// field rather than about the whole body.
	w := get(t, h, clientPath, admin)
	var rep map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if rep["serviceAccountsEnabled"] != true {
		t.Errorf("serviceAccountsEnabled: got %v, want true - the rest of this body merges", rep["serviceAccountsEnabled"])
	}
	// With the flag off the whole family is the gate's 404.
	if w := get(t, h, rsPath, admin); w.Code != http.StatusNotFound {
		t.Errorf("the resource server after the flag went off: got %d %s, want 404", w.Code, w.Body)
	}

	// Turning it back on **resets the settings**, measured.
	if w := send(t, h, http.MethodPut, clientPath, admin, `{"authorizationServicesEnabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("turning it back on: %d %s", w.Code, w.Body)
	}
	got := get(t, h, rsPath, admin)
	if !strings.Contains(got.Body.String(), `"policyEnforcementMode":"ENFORCING"`) ||
		!strings.Contains(got.Body.String(), `"allowRemoteResourceManagement":true`) {
		t.Errorf("after the flag came back: got %s, want the defaults", got.Body)
	}
}

// TestBootstrappedClientsHaveNoAuthorizationServices is why no existing golden
// moved when the field was added.
//
// None of the six bootstrapped clients of a default 26.7.1 carries the key at
// all - not `false`, absent - so the representation omits it. Emitting `false`
// for symmetry with serviceAccountsEnabled beside it would move every client
// golden in the repository.
func TestBootstrappedClientsHaveNoAuthorizationServices(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	w := get(t, h, "/admin/realms/master/clients", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("listing clients: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "authorizationServicesEnabled") {
		t.Errorf("a bootstrapped client carries the key: %s", w.Body)
	}
	var clients []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &clients); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(clients) != 6 {
		t.Fatalf("bootstrapped clients: got %d, want 6", len(clients))
	}
}
