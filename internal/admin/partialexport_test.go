package admin

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const exportPath = "/admin/realms/master/partial-export"

// exportKeys reads a partial-export body back as its top-level key list, in
// order. The order is the whole claim of §1.1, so it is what the tests compare
// rather than a membership check.
func exportKeys(t *testing.T, h http.Handler, query, token string) []string {
	t.Helper()
	w := send(t, h, http.MethodPost, exportPath+query, token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export%s: %d %s", query, w.Code, w.Body)
	}
	return jsonKeyOrder(t, w.Body.Bytes())
}

// jsonKeyOrder is the key list of a JSON object in the order the bytes hold it.
// encoding/json unmarshals into a map, which loses the order this whole file is
// about, so the tokens are walked instead.
func jsonKeyOrder(t *testing.T, body []byte) []string {
	t.Helper()
	var keys []string
	if err := walkJSONObject(body, func(key string, _ json.RawMessage) error {
		keys = append(keys, key)
		return nil
	}); err != nil {
		t.Fatalf("walk the body: %v (%s)", err, truncate(body))
	}
	return keys
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// TestPartialExportIsTheRealmRepresentationPlusTwelveBlocks is the measurement
// the whole operation turns on, and it is computed from the two bodies rather
// than written as a list.
//
// Measured on a live 26.7.1 on 2026-09-06: the no-parameter export's key set is
// a strict superset of GET /admin/realms/{realm}'s, the shared keys come back
// in the realm representation's own order, and the difference is exactly
// twelve keys.
func TestPartialExportIsTheRealmRepresentationPlusTwelveBlocks(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodGet, "/admin/realms/master", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("read the realm: %d %s", w.Code, w.Body)
	}
	realmKeys := jsonKeyOrder(t, w.Body.Bytes())
	got := exportKeys(t, h, "", token)

	// The superset, and the shared order.
	var shared []string
	for _, k := range got {
		if slices.Contains(realmKeys, k) {
			shared = append(shared, k)
		}
	}
	if !slices.Equal(shared, realmKeys) {
		t.Errorf("the shared keys are not the realm representation's, in its order:\n got %v\nwant %v",
			shared, realmKeys)
	}

	var extra []string
	for _, k := range got {
		if !slices.Contains(realmKeys, k) {
			extra = append(extra, k)
		}
	}
	// The count is asserted beside the list rather than instead of it, which
	// is the discipline AGENTS.md's counted claims are under: this compares the
	// names, and the length follows.
	want := []string{
		"localizationTexts", "scopeMappings", "clientScopes",
		"defaultDefaultClientScopes", "defaultOptionalClientScopes",
		"identityProviders", "identityProviderMappers", "components",
		"authenticationFlows", "authenticatorConfig", "requiredActions",
		"keycloakVersion",
	}
	if !slices.Equal(extra, want) {
		t.Errorf("the export-only blocks:\n got %v\nwant %v", extra, want)
	}
}

// TestPartialExportBlocksLandWhereTheyWereMeasured pins the splice points. The
// indexes are read off a recorded body and a moved anchor changes them, which
// is what makes this the test that catches a rename in realmrep.go.
func TestPartialExportBlocksLandWhereTheyWereMeasured(t *testing.T) {
	h, _, _ := newServer(t)
	keys := exportKeys(t, h, "", adminToken(t, h))

	// Each pair is a block and the key that must immediately precede it.
	for _, pair := range [][2]string{
		{"localizationTexts", "otpSupportedApplications"},
		{"scopeMappings", "webAuthnPolicyPasswordlessExtraOrigins"},
		{"clientScopes", "scopeMappings"},
		{"defaultDefaultClientScopes", "clientScopes"},
		{"defaultOptionalClientScopes", "defaultDefaultClientScopes"},
		{"identityProviders", "adminEventsDetailsEnabled"},
		{"identityProviderMappers", "identityProviders"},
		{"components", "identityProviderMappers"},
		{"authenticationFlows", "internationalizationEnabled"},
		{"authenticatorConfig", "authenticationFlows"},
		{"requiredActions", "authenticatorConfig"},
		{"keycloakVersion", "attributes"},
	} {
		i := slices.Index(keys, pair[0])
		if i <= 0 {
			t.Errorf("%s is not in the body", pair[0])
			continue
		}
		if keys[i-1] != pair[1] {
			t.Errorf("%s follows %q, measured following %q", pair[0], keys[i-1], pair[1])
		}
	}
}

// TestPartialExportParametersAddTheKeysTheyWereMeasuredAdding is the two-flag
// claim, and it includes the cell **only a request supplying both conditions
// reaches**: roles.client.
//
// Measured: exportGroupsAndRoles alone gives roles={realm:[...]} and no client
// half; both together give roles={realm:[...],client:{...}}. A test sending one
// flag at a time pins nothing about that key.
func TestPartialExportParametersAddTheKeysTheyWereMeasuredAdding(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	base := exportKeys(t, h, "", token)

	added := func(query string) []string {
		var out []string
		for _, k := range exportKeys(t, h, query, token) {
			if !slices.Contains(base, k) {
				out = append(out, k)
			}
		}
		return out
	}

	if got, want := added("?exportClients=true"), []string{"clientScopeMappings", "clients"}; !slices.Equal(got, want) {
		t.Errorf("exportClients adds %v, measured adding %v", got, want)
	}
	if got, want := added("?exportGroupsAndRoles=true"), []string{"roles", "groups"}; !slices.Equal(got, want) {
		t.Errorf("exportGroupsAndRoles adds %v, measured adding %v", got, want)
	}
	if got, want := added("?exportClients=false&exportGroupsAndRoles=false"), []string(nil); !slices.Equal(got, want) {
		t.Errorf("both false adds %v, measured adding nothing", got)
	}

	// The two-condition cell.
	one := rolesBlock(t, h, "?exportGroupsAndRoles=true", token)
	both := rolesBlock(t, h, "?exportClients=true&exportGroupsAndRoles=true", token)
	if slices.Contains(one, "client") {
		t.Errorf("roles has a client half on one flag: %v", one)
	}
	if !slices.Contains(both, "client") {
		t.Errorf("roles has no client half on both flags: %v", both)
	}
	if !slices.Contains(one, "realm") || !slices.Contains(both, "realm") {
		t.Errorf("roles.realm is not in both bodies: %v / %v", one, both)
	}
}

func rolesBlock(t *testing.T, h http.Handler, query, token string) []string {
	t.Helper()
	w := send(t, h, http.MethodPost, exportPath+query, token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export%s: %d %s", query, w.Code, w.Body)
	}
	var body struct {
		Roles json.RawMessage `json:"roles"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse the body: %v", err)
	}
	return jsonKeyOrder(t, body.Roles)
}

// TestPartialExportFlagIsParseBoolean pins the spellings. **`1` is false**,
// which is what an implementation reaching for strconv.ParseBool would get
// wrong, and a repeated parameter takes the first.
func TestPartialExportFlagIsParseBoolean(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"?exportClients=true", true},
		{"?exportClients=TRUE", true},
		{"?exportClients=True", true},
		{"?exportClients=false", false},
		{"?exportClients=1", false},
		{"?exportClients=0", false},
		{"?exportClients=yes", false},
		{"?exportClients=on", false},
		{"?exportClients=", false},
		{"?exportClients=bogus", false},
		{"?exportClients=true&exportClients=false", true},
		{"?exportClients=false&exportClients=true", false},
		{"?nosuchparam=1", false},
	} {
		got := slices.Contains(exportKeys(t, h, tc.query, token), "clients")
		if got != tc.want {
			t.Errorf("%s exported clients=%v, measured %v", tc.query, got, tc.want)
		}
	}
}

// TestPartialExportSendsNoCharsetAndNoCacheControl is the header claim, with
// GET /admin/realms/master as the control in the same test - it is the response
// that carries both, one path segment away.
func TestPartialExportSendsNoCharsetAndNoCacheControl(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, exportPath, token, "")
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q, measured %q", got, "application/json")
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control is %q, measured absent", got)
	}

	c := send(t, h, http.MethodGet, "/admin/realms/master", token, "")
	if got := c.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
		t.Fatalf("the control does not differ: the realm read's Content-Type is %q", got)
	}
	if c.Header().Get("Cache-Control") == "" {
		t.Fatalf("the control does not differ: the realm read carries no Cache-Control either")
	}
}

// TestPartialExportGuardIsManageRealmPlusTheParametersFamilies is the
// conjunction, measured one role at a time.
//
// **view-realm is refused**, which is what makes realmConfigReadRoles the wrong
// set here even though every other realm-shaped read takes it.
func TestPartialExportGuardIsManageRealmPlusTheParametersFamilies(t *testing.T) {
	h, s, realm := newServer(t)

	for _, tc := range []struct {
		roles []string
		none  int
		cli   int
		gr    int
		both  int
	}{
		{[]string{"manage-realm"}, 200, 403, 403, 403},
		{[]string{"view-realm"}, 403, 403, 403, 403},
		{[]string{"manage-clients"}, 403, 403, 403, 403},
		{[]string{"query-groups"}, 403, 403, 403, 403},
		{[]string{"manage-realm", "view-clients"}, 200, 200, 403, 403},
		{[]string{"manage-realm", "manage-clients"}, 200, 200, 403, 403},
		{[]string{"manage-realm", "query-clients"}, 200, 403, 403, 403},
		{[]string{"manage-realm", "create-client"}, 200, 403, 403, 403},
		{[]string{"manage-realm", "query-groups"}, 200, 403, 200, 403},
		{[]string{"manage-realm", "view-users"}, 200, 403, 200, 403},
		{[]string{"manage-realm", "manage-users"}, 200, 403, 200, 403},
		{[]string{"manage-realm", "query-users"}, 200, 403, 403, 403},
		{[]string{"manage-realm", "view-clients", "query-groups"}, 200, 200, 200, 200},
		{[]string{"view-realm", "view-clients", "query-groups", "manage-users"}, 403, 403, 403, 403},
	} {
		token := tokenForRoles(t, h, s, realm, tc.roles...)
		name := strings.Join(tc.roles, "+")
		for _, cell := range []struct {
			query string
			want  int
		}{
			{"", tc.none},
			{"?exportClients=true", tc.cli},
			{"?exportGroupsAndRoles=true", tc.gr},
			{"?exportClients=true&exportGroupsAndRoles=true", tc.both},
		} {
			w := send(t, h, http.MethodPost, exportPath+cell.query, token, "")
			if w.Code != cell.want {
				t.Errorf("%s on partial-export%s: %d, measured %d", name, cell.query, w.Code, cell.want)
			}
		}
	}
}

// TestPartialExportResolvesTheRealmBeforeTheCaller pins the order: an unknown
// realm is 404 to a caller holding nothing, and a known realm is 403 to the
// same caller.
func TestPartialExportResolvesTheRealmBeforeTheCaller(t *testing.T) {
	h, s, realm := newServer(t)
	// A caller holding one role that opens nothing here, which is the floor of
	// the sweep above.
	token := tokenForRoles(t, h, s, realm, "view-events")

	w := send(t, h, http.MethodPost, "/admin/realms/gloak-no-such/partial-export", token, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown realm: %d %s, measured 404", w.Code, w.Body)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"error":"Realm not found."}`; got != want {
		t.Errorf("unknown realm body %s, measured %s", got, want)
	}
	if w := send(t, h, http.MethodPost, exportPath, token, ""); w.Code != http.StatusForbidden {
		t.Errorf("known realm, weak caller: %d %s, measured 403", w.Code, w.Body)
	}
}

// TestPartialExportCarriesNoKeyMaterialAndMasksTheSecret is the reproducibility
// half: what the body carries that a golden could not.
//
// Measured on a live 26.7.1: the four key-provider components come back with
// `priority` and sometimes `algorithm` and nothing else, and a confidential
// client's `secret` is exactly ten asterisks rather than the stored value.
func TestPartialExportCarriesNoKeyMaterialAndMasksTheSecret(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, "/admin/realms/master/clients", token,
		`{"clientId":"export-secret-probe","publicClient":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create the client: %d %s", w.Code, w.Body)
	}

	e := send(t, h, http.MethodPost, exportPath+"?exportClients=true", token, "")
	if e.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", e.Code, e.Body)
	}
	body := e.Body.String()
	if !strings.Contains(body, `"secret":"**********"`) {
		t.Errorf("the confidential client's secret is not the ten-asterisk mask")
	}
	for _, forbidden := range []string{"privateKey", "certificate", `"secret":"` + "gloak"} {
		if strings.Contains(body, forbidden) && forbidden != `"secret":"**********"` {
			if forbidden == "privateKey" || forbidden == "certificate" {
				t.Errorf("the export carries %s, measured carrying neither", forbidden)
			}
		}
	}

	// The stored secret must not be in the body at all, which is the claim the
	// mask makes and the one a length-derived mask would break.
	var parsed struct {
		Clients []struct {
			ClientID string `json:"clientId"`
			Secret   string `json:"secret"`
		} `json:"clients"`
	}
	if err := decodeJSON(e.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("parse the export: %v", err)
	}
	found := false
	for _, c := range parsed.Clients {
		if c.ClientID == "export-secret-probe" {
			found = true
			if c.Secret != "**********" {
				t.Errorf("secret is %q, measured %q", c.Secret, "**********")
			}
		}
	}
	if !found {
		t.Fatalf("the probe client is not in the export")
	}
}

// TestSpliceExportBlocksRefusesAnAnchorThatNamesNothing is the guard that makes
// anchoring by name worth doing: a field renamed in realmrep.go has to be a
// failure rather than a block that lands somewhere else.
func TestSpliceExportBlocksRefusesAnAnchorThatNamesNothing(t *testing.T) {
	_, err := spliceExportBlocks([]byte(`{"a":1}`), []exportBlock{
		{after: "nosuchkey", key: "x", value: 1},
	})
	if err == nil {
		t.Fatalf("an anchor that names nothing was accepted")
	}
	if !strings.Contains(err.Error(), "nosuchkey") {
		t.Errorf("the error does not name the anchor: %v", err)
	}

	// The control: the same block on an anchor that does exist.
	got, err := spliceExportBlocks([]byte(`{"a":1,"b":2}`), []exportBlock{
		{after: "a", key: "x", value: 1},
	})
	if err != nil {
		t.Fatalf("a valid anchor was refused: %v", err)
	}
	if want := `{"a":1,"x":1,"b":2}`; string(got) != want {
		t.Errorf("splice gave %s, want %s", got, want)
	}
}

// TestSamlECPIsTopLevelInTheExportAndHiddenFromTheListing is the disagreement
// the export made visible.
//
// Measured 2026-09-06 on master and on a created realm: `GET .../flows` answers
// seven flows in both, the export carries eighteen and twenty-one with
// `saml ecp` among them and `topLevel: true`, and
// `GET .../flows/saml%20ecp/executions` serves its one execution. One flow, two
// reads, and the read whose whole job is to enumerate top-level flows omits it.
func TestSamlECPIsTopLevelInTheExportAndHiddenFromTheListing(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodGet, "/admin/realms/master/authentication/flows", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list flows: %d %s", w.Code, w.Body)
	}
	var listed []struct {
		Alias    string `json:"alias"`
		TopLevel bool   `json:"topLevel"`
	}
	if err := decodeJSON(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("parse the listing: %v", err)
	}
	if len(listed) != 7 {
		t.Errorf("the listing has %d flows, measured 7", len(listed))
	}
	for _, f := range listed {
		if f.Alias == samlECPFlowAlias {
			t.Errorf("the listing carries %q, measured omitting it", samlECPFlowAlias)
		}
	}

	e := send(t, h, http.MethodPost, exportPath, token, "")
	if e.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", e.Code, e.Body)
	}
	var exported struct {
		Flows []struct {
			Alias    string `json:"alias"`
			TopLevel bool   `json:"topLevel"`
		} `json:"authenticationFlows"`
	}
	if err := decodeJSON(e.Body.Bytes(), &exported); err != nil {
		t.Fatalf("parse the export: %v", err)
	}
	if len(exported.Flows) != 18 {
		t.Errorf("the export has %d flows, measured 18", len(exported.Flows))
	}
	found := false
	for _, f := range exported.Flows {
		if f.Alias != samlECPFlowAlias {
			continue
		}
		found = true
		if !f.TopLevel {
			t.Errorf("%q is not topLevel in the export, measured true", samlECPFlowAlias)
		}
	}
	if !found {
		t.Errorf("the export does not carry %q", samlECPFlowAlias)
	}

	// The flow is addressable by its own route, which is what says the listing
	// filters rather than the flow being absent.
	x := send(t, h, http.MethodGet,
		"/admin/realms/master/authentication/flows/saml%20ecp/executions", token, "")
	if x.Code != http.StatusOK {
		t.Errorf("its executions: %d %s, measured 200", x.Code, x.Body)
	}
}

// TestExportFlowsAndConfigsAreSortedByAlias pins the two orders that are not
// the store's. **Neither of the endpoints beside them sorts**, which is what
// makes serving the store's order the mistake this catches.
func TestExportFlowsAndConfigsAreSortedByAlias(t *testing.T) {
	h, _, _ := newServer(t)
	w := send(t, h, http.MethodPost, exportPath, adminToken(t, h), "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", w.Code, w.Body)
	}
	var body struct {
		Flows []struct {
			Alias string `json:"alias"`
		} `json:"authenticationFlows"`
		Configs []struct {
			Alias string `json:"alias"`
		} `json:"authenticatorConfig"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	flows := make([]string, 0, len(body.Flows))
	for _, f := range body.Flows {
		flows = append(flows, f.Alias)
	}
	if !slices.IsSorted(flows) {
		t.Errorf("the export's flows are not sorted by alias: %v", flows)
	}
	// The recorded order, which a sort could agree with by accident on a
	// shorter list. Capitals first is what says it is a byte sort.
	if want := []string{
		"Account verification options", "Browser - Conditional 2FA",
		"Direct Grant - Conditional OTP", "First broker login - Conditional 2FA",
		"Handle Existing Account", "Reset - Conditional OTP",
		"User creation or linking", "Verify Existing Account by Re-authentication",
		"browser", "clients", "direct grant", "docker auth", "first broker login",
		"forms", "registration", "registration form", "reset credentials", "saml ecp",
	}; !slices.Equal(flows, want) {
		t.Errorf("flow order:\n got %v\nwant %v", flows, want)
	}

	configs := make([]string, 0, len(body.Configs))
	for _, c := range body.Configs {
		configs = append(configs, c.Alias)
	}
	if want := []string{
		"browser-conditional-credential", "create unique user config",
		"first-broker-login-conditional-credential", "review profile config",
	}; !slices.Equal(configs, want) {
		t.Errorf("authenticatorConfig order:\n got %v\nwant %v", configs, want)
	}
}

// TestExportComponentTypesAreInJavaMapOrder pins the one place this body needs
// javamap.
//
// A default realm's three provider types come back
// `ClientRegistrationPolicy, UserProfileProvider, KeyProvider`.
// javamap.KeyOrder places all three, javamap.SizedKeyOrder places none of them,
// and Go's sorted map order is wrong too - so this is one of the few measured
// key sets that tells the two constructors apart.
func TestExportComponentTypesAreInJavaMapOrder(t *testing.T) {
	h, _, _ := newServer(t)
	w := send(t, h, http.MethodPost, exportPath, adminToken(t, h), "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", w.Code, w.Body)
	}
	var body struct {
		Components json.RawMessage `json:"components"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{
		"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
		"org.keycloak.userprofile.UserProfileProvider",
		"org.keycloak.keys.KeyProvider",
	}
	if got := jsonKeyOrder(t, body.Components); !slices.Equal(got, want) {
		t.Errorf("component provider types:\n got %v\nwant %v", got, want)
	}
	// Sorting is the obvious implementation and it is wrong here, which is what
	// makes the assertion above load-bearing rather than incidental.
	if slices.IsSorted(want) {
		t.Fatalf("the control does not differ: the measured order happens to be sorted")
	}
}

// TestExportRolesClientKeysAreInJavaMapOrder is the same claim on the other map
// this body carries, and it needs both flags to be reachable.
func TestExportRolesClientKeysAreInJavaMapOrder(t *testing.T) {
	h, _, _ := newServer(t)
	w := send(t, h, http.MethodPost,
		exportPath+"?exportClients=true&exportGroupsAndRoles=true", adminToken(t, h), "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", w.Code, w.Body)
	}
	var body struct {
		Roles struct {
			Client json.RawMessage `json:"client"`
		} `json:"roles"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{
		"security-admin-console", "admin-cli", "account-console",
		"broker", "master-realm", "account",
	}
	if got := jsonKeyOrder(t, body.Roles.Client); !slices.Equal(got, want) {
		t.Errorf("roles.client keys:\n got %v\nwant %v", got, want)
	}
	if slices.IsSorted(want) {
		t.Fatalf("the control does not differ: the measured order happens to be sorted")
	}
}

// TestExportExecutionsCarryKeycloaksMisspelling pins `autheticatorFlow`. It is
// beside `authenticatorFlow` on every execution, and correcting the spelling is
// the tidy-up that breaks compatibility.
func TestExportExecutionsCarryKeycloaksMisspelling(t *testing.T) {
	h, _, _ := newServer(t)
	w := send(t, h, http.MethodPost, exportPath, adminToken(t, h), "")
	if w.Code != http.StatusOK {
		t.Fatalf("partial-export: %d %s", w.Code, w.Body)
	}
	var body struct {
		AuthenticationFlows []struct {
			Alias      string            `json:"alias"`
			Executions []json.RawMessage `json:"authenticationExecutions"`
		} `json:"authenticationFlows"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse the export: %v", err)
	}
	seen := 0
	for _, f := range body.AuthenticationFlows {
		for _, e := range f.Executions {
			keys := jsonKeyOrder(t, e)
			if !slices.Contains(keys, "autheticatorFlow") {
				t.Fatalf("%s: an execution with no autheticatorFlow: %v", f.Alias, keys)
			}
			if !slices.Contains(keys, "authenticatorFlow") {
				t.Fatalf("%s: an execution with no authenticatorFlow: %v", f.Alias, keys)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatalf("no executions in the export, so the claim is untested")
	}
}
