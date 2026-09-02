package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func authzImportPath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/import"
}

func authzSettingsPath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/settings"
}

// realmRoleID reads one realm role's id through the API.
func realmRoleID(t *testing.T, h http.Handler, token, name string) string {
	t.Helper()
	var role struct {
		ID string `json:"id"`
	}
	body := get(t, h, "/admin/realms/master/roles/"+name, token).Body.Bytes()
	if err := json.Unmarshal(body, &role); err != nil {
		t.Fatalf("reading role %s: %v (%s)", name, err, body)
	}
	return role.ID
}

// TestPolicyConfigIsNormalisedOnTheWayInAndBackOutOnTheExport is the two-
// directions claim, and it is the only test that can hold it: the goldens
// deliberately create no `role`, `client` or `group` policy carrying a real
// reference, because every id such a policy could resolve to is minted per
// container.
//
// Three providers, three answers to an unknown reference - dropped, dropped and
// a 500 - and the same three types are the only ones whose export is filtered.
func TestPolicyConfigIsNormalisedOnTheWayInAndBackOutOnTheExport(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-norm")
	base := authzPolicyPath(uuid)

	roleID := realmRoleID(t, h, admin, "admin")
	groupID := createGroup(t, h, "gloak-t-pol-group", admin)

	// A role name in, the role's uuid stored, the name back out again - and an
	// unknown role silently dropped on the way.
	mkPolicy(t, h, admin, base, `{"name":"r1","type":"role",`+
		`"config":{"roles":"[{\"id\":\"admin\"},{\"id\":\"nosuchrole\"}]"}}`)
	if got := get(t, h, base+"/search?name=r1", admin).Body.String(); !strings.Contains(got,
		`"roles":"[{\"id\":\"`+roleID+`\",\"required\":false}]"`) {
		t.Errorf("the stored role config: %s", got)
	}

	// A clientId in, the client's uuid stored - and an unknown clientId is a
	// 500 where the role above was dropped.
	mkPolicy(t, h, admin, base, `{"name":"c1","type":"client","config":{"clients":"[\"admin-cli\"]"}}`)
	if w := send(t, h, http.MethodPost, base, admin,
		`{"name":"c2","type":"client","config":{"clients":"[\"nosuchclient\"]"}}`); w.Code != http.StatusInternalServerError {
		t.Errorf("an unknown clientId: got %d %s, want 500", w.Code, w.Body)
	}

	// A group path in, the group's id stored, `extendChildren` filled in - and
	// an unknown path silently dropped.
	mkPolicy(t, h, admin, base, `{"name":"g1","type":"group",`+
		`"config":{"groups":"[{\"path\":\"/gloak-t-pol-group\"},{\"path\":\"/nope\"}]"}}`)
	if got := get(t, h, base+"/search?name=g1", admin).Body.String(); !strings.Contains(got,
		`"groups":"[{\"id\":\"`+groupID+`\",\"extendChildren\":false}]"`) {
		t.Errorf("the stored group config: %s", got)
	}

	// A value under one of those keys that is not JSON is invalid_request on a
	// 500, which is the shape this API has been measured producing on exactly
	// two inputs, both here.
	w := send(t, h, http.MethodPost, base, admin, `{"name":"j1","type":"role","config":{"roles":"notjson"}}`)
	if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) !=
		`{"error":"invalid_request","error_description":"Cannot parse the JSON"}` {
		t.Errorf("a config value that is not JSON: %d %s", w.Code, w.Body)
	}

	// And the export sends all three back as names.
	export := get(t, h, authzSettingsPath(uuid), admin).Body.String()
	for _, want := range []string{
		`"roles":"[{\"id\":\"admin\",\"required\":false}]"`,
		`"clients":"[\"admin-cli\"]"`,
		`"groups":"[{\"path\":\"/gloak-t-pol-group\",\"extendChildren\":false}]"`,
	} {
		if !strings.Contains(export, want) {
			t.Errorf("the export is missing %s:\n%s", want, export)
		}
	}
}

// TestConfigAssociationKeysAreConsumed pins the half of the config rule that no
// golden reaches: `applyPolicies`, `resources` and `scopes` arrive **inside**
// the config, are moved into the association sets and are gone from the stored
// config - on every type, so it is the family's behaviour and not the aggregate
// provider's.
//
// It exists because a mutation that disabled the whole consumption block
// survived: every fixture in the catalogue names its associations through the
// body's own three arrays, so the config path was reachable and unasserted.
func TestConfigAssociationKeysAreConsumed(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-consume")
	base := authzPolicyPath(uuid)
	mkScope(t, h, admin, authzScopePath(uuid), `{"id":"csc-id","name":"csc"}`)
	mkResource(t, h, admin, authzResourcePath(uuid), `{"_id":"cres-id","name":"cres"}`)
	mkPolicy(t, h, admin, base, `{"id":"cbase","name":"cbase","type":"role"}`)

	// Every type, so the claim is about the family rather than one provider.
	for _, typ := range []string{"aggregate", "resource", "uma", "time"} {
		mkPolicy(t, h, admin, base, `{"name":"con-`+typ+`","type":"`+typ+`","config":{`+
			`"applyPolicies":"[\"cbase\"]","resources":"[\"cres\"]","scopes":"[\"csc\"]"}}`)
		live := get(t, h, base+"/search?name=con-"+typ, admin).Body.String()
		for _, key := range []string{"applyPolicies", `"resources"`, `"scopes"`} {
			if strings.Contains(live, key) {
				t.Errorf("%s kept %s in its stored config: %s", typ, key, live)
			}
		}
		// They came back out of the associations on the listing's filters,
		// which is the only observable that says they were stored at all.
		if got := get(t, h, base+"?resource=cres&name=con-"+typ, admin).Body.String(); !strings.Contains(got, "con-"+typ) {
			t.Errorf("%s: the config's resources did not reach the association: %s", typ, got)
		}
		if got := get(t, h, base+"?scope=csc&name=con-"+typ, admin).Body.String(); !strings.Contains(got, "con-"+typ) {
			t.Errorf("%s: the config's scopes did not reach the association: %s", typ, got)
		}
	}
	// And the export synthesises all three back, by name.
	export := get(t, h, authzSettingsPath(uuid), admin).Body.String()
	for _, want := range []string{
		`"applyPolicies":"[\"cbase\"]"`, `"resources":"[\"cres\"]"`, `"scopes":"[\"csc\"]"`,
	} {
		if !strings.Contains(export, want) {
			t.Errorf("the export is missing %s:\n%s", want, export)
		}
	}
	// An unknown target in any of the three is the consult-log 500 - where the
	// body's own `scopes` array answers a bare 400 with no description.
	for _, key := range []string{"applyPolicies", "resources", "scopes"} {
		w := send(t, h, http.MethodPost, base, admin,
			`{"name":"bad-`+key+`","type":"uma","config":{"`+key+`":"[\"nothing\"]"}}`)
		if want := `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`; w.Code !=
			http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("config.%s naming nothing:\n got %d %s\nwant 500 %s", key, w.Code, w.Body, want)
		}
	}
	w := send(t, h, http.MethodPost, base, admin, `{"name":"bad-array","type":"uma","scopes":["nothing"]}`)
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != `{"error":"unknown_error"}` {
		t.Errorf("the body's own scopes naming nothing: %d %s", w.Code, w.Body)
	}
}

// TestExportFiltersTheConfigOfExactlyThreeTypes is the rule the import golden
// found: a role, client or group policy's exported config is the provider's own
// keys and nothing else, and the other six pass everything through.
//
// It was found by a conformance golden disagreeing with the implementation, not
// by a probe: every earlier probe of the export used a config the provider had
// written itself, so there was nothing for the filter to drop.
func TestExportFiltersTheConfigOfExactlyThreeTypes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-expfil")
	base := authzPolicyPath(uuid)

	// A junk key beside every provider's own, on all nine types.
	const config = `{"zzz":"1","defaultResourceType":"urn:d","nbf":"2026-01-01 00:00:00",` +
		`"hour":"3","targetClaim":"tc","pattern":"^a$","targetContextAttributes":"true",` +
		`"roles":"[]","clients":"[]","groups":"[]","groupsClaim":"gc","fetchRoles":"true"}`
	for _, typ := range authzPolicyTypes {
		mkPolicy(t, h, admin, base, `{"name":"f-`+typ+`","type":"`+typ+`","config":`+config+`}`)
	}

	var export struct {
		Policies []struct {
			Name   string            `json:"name"`
			Type   string            `json:"type"`
			Config map[string]string `json:"config"`
		} `json:"policies"`
	}
	body := get(t, h, authzSettingsPath(uuid), admin).Body.Bytes()
	if err := json.Unmarshal(body, &export); err != nil {
		t.Fatalf("parse the export: %v (%s)", err, body)
	}
	if len(export.Policies) != len(authzPolicyTypes) {
		t.Fatalf("the export has %d policies, want %d", len(export.Policies), len(authzPolicyTypes))
	}
	want := map[string]int{"role": 2, "client": 1, "group": 2}
	for _, p := range export.Policies {
		n, filtered := want[p.Type]
		if !filtered {
			n = 12
		}
		if len(p.Config) != n {
			t.Errorf("%s exported %d config keys, want %d: %v", p.Type, len(p.Config), n, p.Config)
		}
		if filtered && p.Config["zzz"] != "" {
			t.Errorf("%s exported the junk key: %v", p.Type, p.Config)
		}
		if !filtered && p.Config["zzz"] != "1" {
			t.Errorf("%s dropped the junk key: %v", p.Type, p.Config)
		}
	}
}

// TestImportResetsMergesAndDeletesNothing pins the three measured behaviours of
// `POST .../import`, and the third is the one the settings golden caught.
func TestImportResetsMergesAndDeletesNothing(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-import")
	base, imp := authzPolicyPath(uuid), authzImportPath(uuid)
	mkScope(t, h, admin, authzScopePath(uuid), `{"id":"isc","name":"keepscope"}`)
	mkResource(t, h, admin, authzResourcePath(uuid), `{"_id":"ires","name":"keepres"}`)
	mkPolicy(t, h, admin, base, `{"id":"ipol","name":"keeppol","type":"role"}`)

	// Move the three settings off their defaults, then import `{}`.
	send(t, h, http.MethodPut,
		"/admin/realms/master/clients/"+uuid+"/authz/resource-server", admin,
		`{"allowRemoteResourceManagement":false,"policyEnforcementMode":"PERMISSIVE",`+
			`"decisionStrategy":"AFFIRMATIVE"}`)
	w := send(t, h, http.MethodPost, imp, admin, `{}`)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("import {}: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "" {
		t.Errorf("import sent a Cache-Control: %q", w.Header().Get("Cache-Control"))
	}
	// **The three settings go back to the representation's own initialisers**,
	// which are not the zero values - a merge would have kept all three and a
	// zero-value replace would get allowRemoteResourceManagement wrong.
	settings := get(t, h, authzSettingsPath(uuid), admin).Body.String()
	if !strings.HasPrefix(settings, `{"allowRemoteResourceManagement":true,"policyEnforcementMode":"ENFORCING"`) {
		t.Errorf("the settings after import {}: %s", settings)
	}
	if !strings.HasSuffix(strings.TrimSpace(settings), `"decisionStrategy":"UNANIMOUS"}`) {
		t.Errorf("the decisionStrategy after import {}: %s", settings)
	}
	// **Nothing was deleted.**
	for _, want := range []string{"keepscope", "keepres", "keeppol"} {
		if !strings.Contains(settings, want) {
			t.Errorf("import {} deleted %s: %s", want, settings)
		}
	}

	// **A name it already holds is merged into rather than replaced**: the
	// type, the logic and the strategy stay and the config grows.
	w = send(t, h, http.MethodPost, imp, admin,
		`{"decisionStrategy":"AFFIRMATIVE",`+
			`"policies":[{"name":"keeppol","type":"regex","logic":"NEGATIVE",`+
			`"config":{"pattern":"^merged$"}}]}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("the merging import: %d %s", w.Code, w.Body)
	}
	live := strings.TrimSpace(get(t, h, base+"/search?name=keeppol", admin).Body.String())
	if want := `{"id":"ipol","name":"keeppol","type":"role","logic":"POSITIVE",` +
		`"decisionStrategy":"UNANIMOUS","config":{"pattern":"^merged$","roles":"[]"}}`; live != want {
		t.Errorf("the merged policy:\n got %s\nwant %s", live, want)
	}
	// And the export drops the merged-in key again, because a role policy's
	// export is the role provider's keys alone.
	settings = get(t, h, authzSettingsPath(uuid), admin).Body.String()
	if strings.Contains(settings, "^merged$") {
		t.Errorf("the export kept a key the role provider does not own: %s", settings)
	}
}

// TestImportIsStrictWhereTheCreateIsNot pins the ninth strict endpoint and the
// fact that its immediate neighbour disagrees with it.
func TestImportIsStrictWhereTheCreateIsNot(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-strict")
	imp, base := authzImportPath(uuid), authzPolicyPath(uuid)

	w := send(t, h, http.MethodPost, imp, admin, `{"zzz":1}`)
	if want := `{"error":"Invalid json representation for ResourceServerRepresentation. ` +
		`Unrecognized field \"zzz\" at line 1 column 9."}`; w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("import with an unknown field:\n got %d %s\nwant 400 %s", w.Code, w.Body, want)
	}
	// The same fault, one path segment away, is a 500.
	w = send(t, h, http.MethodPost, base, admin, `{"name":"x","type":"role","zzz":1}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("the create with an unknown field: got %d %s, want 500", w.Code, w.Body)
	}
	// An empty body and a literal null are the consult-log 500 here, where the
	// create answers two different bodies for those two inputs.
	for _, body := range []string{"", "null"} {
		w := send(t, h, http.MethodPost, imp, admin, body)
		if want := `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`; w.Code !=
			http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("import %q:\n got %d %s\nwant 500 %s", body, w.Code, w.Body, want)
		}
	}
}
