package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/store"
)

// flowRow is enough of the nested flow representation for the tests below to
// name a flow without depending on the execution shape.
type flowRow struct {
	ID          string `json:"id"`
	Alias       string `json:"alias"`
	Description string `json:"description"`
	ProviderID  string `json:"providerId"`
	TopLevel    bool   `json:"topLevel"`
	BuiltIn     bool   `json:"builtIn"`
	Executions  []struct {
		Authenticator     string `json:"authenticator"`
		AuthenticatorFlow bool   `json:"authenticatorFlow"`
		AutheticatorFlow  bool   `json:"autheticatorFlow"`
		Requirement       string `json:"requirement"`
		Priority          int    `json:"priority"`
		FlowAlias         string `json:"flowAlias"`
	} `json:"authenticationExecutions"`
}

func listFlows(t *testing.T, h http.Handler, realm, token string) []flowRow {
	t.Helper()
	w := get(t, h, "/admin/realms/"+realm+"/authentication/flows", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list flows: %d %s", w.Code, w.Body)
	}
	var rows []flowRow
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse flow listing: %v", err)
	}
	return rows
}

func flowByAlias(t *testing.T, rows []flowRow, alias string) flowRow {
	t.Helper()
	for _, f := range rows {
		if f.Alias == alias {
			return f
		}
	}
	t.Fatalf("no flow aliased %q in %d rows", alias, len(rows))
	return flowRow{}
}

// TestListFlowsIsTopLevelOnly is the seed's first assertion and the one every
// other read rests on.
//
// `GET /flows` serves **seven** rows on master where the realm holds
// seventeen flows, because ten of them are sub-flows reachable only through
// /flows/{alias}/executions. Serving the store's whole ListFlows is the obvious
// implementation and it is wrong by ten rows.
func TestListFlowsIsTopLevelOnly(t *testing.T) {
	h, s, realm := newServer(t)
	token := adminToken(t, h)

	rows := listFlows(t, h, "master", token)
	want := []string{
		"browser", "direct grant", "registration", "reset credentials",
		"clients", "first broker login", "docker auth",
	}
	if len(rows) != len(want) {
		t.Fatalf("GET /flows served %d flows, want %d", len(rows), len(want))
	}
	for i, alias := range want {
		if rows[i].Alias != alias {
			t.Errorf("flow %d is %q, want %q - the listing is insertion order", i, rows[i].Alias, alias)
		}
		if !rows[i].TopLevel {
			t.Errorf("flow %q is served with topLevel false", rows[i].Alias)
		}
	}

	stored, err := s.AuthenticationFlows().ListFlows(context.Background(), realm.ID)
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(stored) <= len(rows) {
		t.Fatalf("the store holds %d flows and the listing served %d - "+
			"the sub-flows are missing from the store, so this test cannot "+
			"tell a filtered listing from an unfiltered one", len(stored), len(rows))
	}
}

// TestMasterOmitsTheOrganizationFlows and its sibling below are the two halves
// of the one place the seed is not the same in every realm.
//
// Measured on a live 26.7.1: master holds 17 flows and 48 execution rows, a
// realm created through POST /admin/realms holds 20 and 55. The difference is
// exactly three flows and two rows, all of them the organization family. The
// client-scope precedent - identical in every realm - does not hold here, and
// a seed that ignored the distinction would be right on one realm and wrong on
// every other.
func TestMasterOmitsTheOrganizationFlows(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	rows := listFlows(t, h, "master", token)
	browser := flowByAlias(t, rows, "browser")
	for _, e := range browser.Executions {
		if e.FlowAlias == "Organization" {
			t.Fatalf("master's browser flow names the Organization sub-flow; " +
				"a created realm has it and master does not")
		}
	}
	if len(browser.Executions) != 4 {
		t.Errorf("master's browser flow has %d rows, want 4 "+
			"(auth-cookie, auth-spnego, identity-provider-redirector, forms)",
			len(browser.Executions))
	}
	fbl := flowByAlias(t, rows, "first broker login")
	if len(fbl.Executions) != 2 {
		t.Errorf("master's first broker login has %d rows, want 2", len(fbl.Executions))
	}
}

// TestCreatedRealmSeedsTheOrganizationFlows is the other half.
func TestCreatedRealmSeedsTheOrganizationFlows(t *testing.T) {
	h, s, _ := newServer(t)
	token := adminToken(t, h)
	ctx := context.Background()
	if _, err := bootstrap.CreateRealm(ctx, s, "gloak-test-orgflows", nil); err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}

	rows := listFlows(t, h, "gloak-test-orgflows", token)
	browser := flowByAlias(t, rows, "browser")
	var found bool
	for _, e := range browser.Executions {
		if e.FlowAlias == "Organization" {
			found = true
			if e.Priority != 26 {
				t.Errorf("the Organization row's priority is %d, want 26 - "+
					"it sits between identity-provider-redirector at 25 and forms at 30",
					e.Priority)
			}
			if e.Requirement != "ALTERNATIVE" {
				t.Errorf("the Organization row's requirement is %q, want ALTERNATIVE", e.Requirement)
			}
		}
	}
	if !found {
		t.Fatal("a created realm's browser flow is missing the Organization sub-flow")
	}

	realm, err := s.Realms().ByName(ctx, "gloak-test-orgflows")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	stored, err := s.AuthenticationFlows().ListFlows(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(stored) != 20 {
		t.Errorf("a created realm holds %d flows, want 20 (7 top-level, 13 sub)", len(stored))
	}
	total := 0
	for _, f := range stored {
		rows, err := s.AuthenticationFlows().ListExecutions(ctx, realm.ID, f.ID)
		if err != nil {
			t.Fatalf("ListExecutions: %v", err)
		}
		total += len(rows)
	}
	if total != 55 {
		t.Errorf("a created realm holds %d execution rows, want 55", total)
	}
	configs, err := s.AuthenticationFlows().ListConfigs(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListConfigs: %v", err)
	}
	if len(configs) != 4 {
		t.Errorf("a created realm holds %d authenticator configs, want 4", len(configs))
	}
}

// TestTheMisspelledAutheticatorFlowIsServedBesideTheCorrectOne pins the one
// field on this family a reader is most likely to delete.
//
// Keycloak serialises every nested execution row twice, once through a
// correctly spelled accessor and once through one missing its `n`. It is
// contract. This test compares the two rather than only asserting presence,
// because a serialiser that emitted a constant would satisfy presence alone.
func TestTheMisspelledAutheticatorFlowIsServedBesideTheCorrectOne(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	rows := listFlows(t, h, "master", token)
	browser := flowByAlias(t, rows, "browser")
	var sawTrue, sawFalse bool
	for _, e := range browser.Executions {
		if e.AuthenticatorFlow != e.AutheticatorFlow {
			t.Errorf("row %q serves authenticatorFlow=%v and autheticatorFlow=%v",
				e.Authenticator+e.FlowAlias, e.AuthenticatorFlow, e.AutheticatorFlow)
		}
		if e.AutheticatorFlow {
			sawTrue = true
		} else {
			sawFalse = true
		}
	}
	// Both values have to occur, or a serialiser hard-coding one would pass.
	if !sawTrue || !sawFalse {
		t.Fatalf("the browser flow served autheticatorFlow true=%v false=%v; "+
			"both are needed or a constant would satisfy this test", sawTrue, sawFalse)
	}
	raw := get(t, h, "/admin/realms/master/authentication/flows", token).Body.String()
	if !strings.Contains(raw, `"autheticatorFlow"`) {
		t.Error("the listing carries no autheticatorFlow key at all")
	}
}

// TestFlowNotFoundSpellingsDifferByRoute pins the pair separated by
// capitalisation alone.
//
// One missing flow, **three** sentences, decided by which route went looking:
//
//	GET/PUT /flows/{id}              Could not find flow with id
//	DELETE /flows/{id}, copy         Flow not found
//	PUT /flows/{alias}/executions    flow not found
//
// AGENTS.md's not-found list already holds three pairs separated by a full stop
// alone; this is the first separated by the case of a letter, and correcting it
// is the tidy-up that breaks compatibility.
func TestFlowNotFoundSpellingsDifferByRoute(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	const missing = "gloak-test-no-such-flow"

	cases := []struct {
		name, method, path, body, want string
	}{
		{"read by id", http.MethodGet, authBase + "/flows/" + missing, "",
			"Could not find flow with id"},
		{"update by id", http.MethodPut, authBase + "/flows/" + missing,
			`{"alias":"x","providerId":"basic-flow"}`, "Could not find flow with id"},
		{"delete by id", http.MethodDelete, authBase + "/flows/" + missing, "",
			"Flow not found"},
		{"copy", http.MethodPost, authBase + "/flows/" + missing + "/copy",
			`{"newName":"y"}`, "Flow not found"},
		{"update execution", http.MethodPut, authBase + "/flows/" + missing + "/executions",
			`{"id":"z","requirement":"REQUIRED"}`, "flow not found"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		w := send(t, h, c.method, c.path, token, c.body)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404: %s", c.name, w.Code, w.Body)
			continue
		}
		var body struct {
			Error string `json:"error"`
		}
		if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: parse: %v", c.name, err)
			continue
		}
		if body.Error != c.want {
			t.Errorf("%s: error is %q, want %q", c.name, body.Error, c.want)
		}
		seen[body.Error] = true
	}
	// The point of the test is that the three are distinct. Counting them here
	// rather than writing "three" in a comment is what keeps the claim honest.
	if len(seen) != 3 {
		t.Errorf("the family spelled %d distinct not-found sentences, want 3: %v", len(seen), seen)
	}
	if !seen["Flow not found"] || !seen["flow not found"] {
		t.Error("the capitalisation pair is not both present; " +
			"they differ only in the case of the first letter and both are measured")
	}
}

// TestRaisePrioritySwapsWithTheNeighbour pins the rule a decrement would look
// like it satisfied.
//
// raise-priority exchanges two rows' priorities. Decrementing one instead
// produces a duplicate priority and an order nothing defines, and both answer
// 204 - so the 204 is not the assertion, the listing after it is.
func TestRaisePrioritySwapsWithTheNeighbour(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, authBase+"/flows", token,
		`{"alias":"gloak-test-order","providerId":"basic-flow","topLevel":true,"builtIn":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create flow: %d %s", w.Code, w.Body)
	}
	// Two providers that differ, so the listing says which row moved rather
	// than only that a number changed.
	for _, provider := range []string{"auth-otp-form", "auth-spnego"} {
		w := send(t, h, http.MethodPost,
			authBase+"/flows/gloak-test-order/executions/execution", token,
			`{"provider":"`+provider+`"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("add %s: %d %s", provider, w.Code, w.Body)
		}
	}

	before := executionOrder(t, h, token, "gloak-test-order")
	if len(before) != 2 {
		t.Fatalf("the flow holds %d rows, want 2", len(before))
	}
	if before[0].providerID != "auth-otp-form" || before[1].providerID != "auth-spnego" {
		t.Fatalf("rows arrived as %v, want auth-otp-form then auth-spnego", before)
	}
	if before[0].priority == before[1].priority {
		t.Fatalf("both rows are at priority %d, so a swap would be invisible", before[0].priority)
	}

	w = send(t, h, http.MethodPost,
		authBase+"/executions/"+before[1].id+"/raise-priority", token, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("raise-priority: %d %s", w.Code, w.Body)
	}

	after := executionOrder(t, h, token, "gloak-test-order")
	if after[0].providerID != "auth-spnego" || after[1].providerID != "auth-otp-form" {
		t.Fatalf("after the raise the rows are %v, want auth-spnego then auth-otp-form", after)
	}
	// The swap keeps the same two priority values. A decrement would not.
	if after[0].priority != before[0].priority || after[1].priority != before[1].priority {
		t.Errorf("the priorities moved from (%d,%d) to (%d,%d); a swap exchanges "+
			"the rows and leaves the two values alone",
			before[0].priority, before[1].priority, after[0].priority, after[1].priority)
	}
}

type executionRow struct {
	id         string
	providerID string
	priority   int
}

func executionOrder(t *testing.T, h http.Handler, token, flowAlias string) []executionRow {
	t.Helper()
	w := get(t, h, authBase+"/flows/"+flowAlias+"/executions", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list executions: %d %s", w.Code, w.Body)
	}
	var rows []struct {
		ID         string `json:"id"`
		ProviderID string `json:"providerId"`
		Priority   int    `json:"priority"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse executions: %v", err)
	}
	out := make([]executionRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, executionRow{id: r.ID, providerID: r.ProviderID, priority: r.Priority})
	}
	return out
}

// TestSecondExecutionConfigReplacesTheFirst pins the upsert wearing a create's
// status code.
//
// Posting a second config to an execution that already has one answers 201,
// repoints the row and **deletes the first**. Appending instead would leave the
// first config addressable, which is what the second half asserts.
func TestSecondExecutionConfigReplacesTheFirst(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, authBase+"/flows", token,
		`{"alias":"gloak-test-cfg","providerId":"basic-flow","topLevel":true,"builtIn":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create flow: %d %s", w.Code, w.Body)
	}
	w = send(t, h, http.MethodPost,
		authBase+"/flows/gloak-test-cfg/executions/execution", token,
		`{"provider":"identity-provider-redirector"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("add execution: %d %s", w.Code, w.Body)
	}
	execID := lastSegment(w.Header().Get("Location"))

	first := postExecutionConfig(t, h, token, execID, "gloak-test-cfg-one", "alpha")
	second := postExecutionConfig(t, h, token, execID, "gloak-test-cfg-two", "beta")
	if first == second {
		t.Fatal("the two configs share an id, so this test cannot tell a replace from an append")
	}

	if w := get(t, h, authBase+"/config/"+second, token); w.Code != http.StatusOK {
		t.Errorf("the second config reads %d, want 200: %s", w.Code, w.Body)
	}
	w = get(t, h, authBase+"/config/"+first, token)
	if w.Code != http.StatusNotFound {
		t.Errorf("the first config reads %d, want 404 - a second POST replaces it "+
			"rather than adding beside it: %s", w.Code, w.Body)
	}

	rows := executionOrder(t, h, token, "gloak-test-cfg")
	if len(rows) != 1 {
		t.Fatalf("the flow holds %d rows, want 1", len(rows))
	}
	w = get(t, h, authBase+"/flows/gloak-test-cfg/executions", token)
	var listed []struct {
		AuthenticationConfig string `json:"authenticationConfig"`
		Alias                string `json:"alias"`
	}
	if err := decodeJSON(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if listed[0].AuthenticationConfig != second {
		t.Errorf("the row points at %q, want the second config %q",
			listed[0].AuthenticationConfig, second)
	}
	if listed[0].Alias != "gloak-test-cfg-two" {
		t.Errorf("the row's alias is %q, want the second config's", listed[0].Alias)
	}
}

func postExecutionConfig(t *testing.T, h http.Handler, token, execID, alias, value string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, authBase+"/executions/"+execID+"/config", token,
		`{"alias":"`+alias+`","config":{"defaultProvider":"`+value+`"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("post config %s: %d %s", alias, w.Code, w.Body)
	}
	return lastSegment(w.Header().Get("Location"))
}

func lastSegment(location string) string {
	if i := strings.LastIndex(location, "/"); i >= 0 {
		return location[i+1:]
	}
	return location
}

// TestViewClientsReadsTheFlowListingAndNothingElse pins the tag's second wide
// read, and pins that it is wide on **one** operation.
//
// Measured one role at a time across all 21 roles of the realm's own container:
// view-clients and query-clients answer 200 on GET /flows and 403 on
// GET /flows/{id} and GET /flows/{alias}/executions one segment away. Sharing
// one slice across the family opens two routes Keycloak refuses.
func TestViewClientsReadsTheFlowListingAndNothingElse(t *testing.T) {
	h, s, realm := newServer(t)
	adminTok := adminToken(t, h)
	rows := listFlows(t, h, "master", adminTok)
	browserID := flowByAlias(t, rows, "browser").ID

	for _, role := range []string{"view-clients", "query-clients"} {
		token := tokenForRole(t, h, s, realm, role)
		if w := get(t, h, authBase+"/flows", token); w.Code != http.StatusOK {
			t.Errorf("%s: GET /flows is %d, want 200: %s", role, w.Code, w.Body)
		}
		if w := get(t, h, authBase+"/flows/"+browserID, token); w.Code != http.StatusForbidden {
			t.Errorf("%s: GET /flows/{id} is %d, want 403 - the wide admission is "+
				"on the listing alone: %s", role, w.Code, w.Body)
		}
		if w := get(t, h, authBase+"/flows/browser/executions", token); w.Code != http.StatusForbidden {
			t.Errorf("%s: GET /flows/{alias}/executions is %d, want 403: %s", role, w.Code, w.Body)
		}
	}

	// The control: the users pair opens the *required-action* listing and not
	// this one, so the two wide reads on this tag do not share a role set.
	for _, role := range []string{"view-users", "query-users"} {
		token := tokenForRole(t, h, s, realm, role)
		if w := get(t, h, authBase+"/flows", token); w.Code != http.StatusForbidden {
			t.Errorf("%s: GET /flows is %d, want 403 - the users pair opens the "+
				"required-action listing, not this one: %s", role, w.Code, w.Body)
		}
		if w := get(t, h, authBase+"/required-actions", token); w.Code != http.StatusOK {
			t.Errorf("%s: GET /required-actions is %d, want 200 - "+
				"the control for the line above", role, w.Code)
		}
	}
}

// TestABuiltInFlowCanBeRenamedButNotDeleted pins the asymmetry that makes
// binding B1 observable.
//
// PUT renames `browser` and answers 204; DELETE refuses with a **400** and a
// body, not a 403 and not a 409. Only the delete checks builtIn.
func TestABuiltInFlowCanBeRenamedButNotDeleted(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	rows := listFlows(t, h, "master", token)
	browser := flowByAlias(t, rows, "browser")

	w := send(t, h, http.MethodDelete, authBase+"/flows/"+browser.ID, token, "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("delete of a built-in flow is %d, want 400: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "Can't delete built in flow") {
		t.Errorf("delete body is %s, want Can't delete built in flow", w.Body)
	}

	w = send(t, h, http.MethodPut, authBase+"/flows/"+browser.ID, token,
		`{"alias":"gloak-test-browser-renamed","description":"Browser based authentication",`+
			`"providerId":"basic-flow","topLevel":true,"builtIn":true}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("rename of a built-in flow is %d, want 204: %s", w.Code, w.Body)
	}
	after := listFlows(t, h, "master", token)
	if flowByAlias(t, after, "gloak-test-browser-renamed").ID != browser.ID {
		t.Error("the rename did not land on the same row")
	}
}

// TestCreateFlowWithoutAProviderIsDuplicateResourceError reproduces the answer
// nobody would design.
//
// A body naming an alias and no providerId answers
// `{"error":"conflict","error_description":"Duplicate resource error"}` for a
// body that duplicates nothing, where the same route's empty-alias refusal is
// the `errorMessage` shape. Measured, and reproduced as measured rather than as
// coherent.
func TestCreateFlowWithoutAProviderIsDuplicateResourceError(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, authBase+"/flows", token, `{"alias":"gloak-test-no-provider"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", w.Code, w.Body)
	}
	var body map[string]string
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body["error"] != "conflict" || body["error_description"] != "Duplicate resource error" {
		t.Errorf("body is %v, want the Duplicate resource error shape", body)
	}

	// The control, on the same route and the same verb: an empty alias answers
	// the other shape entirely. Two 409s, two bodies, one endpoint.
	w = send(t, h, http.MethodPost, authBase+"/flows", token, `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("empty alias status %d, want 409: %s", w.Code, w.Body)
	}
	var em map[string]string
	if err := decodeJSON(w.Body.Bytes(), &em); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if em["errorMessage"] != "Failed to create flow with empty alias name" {
		t.Errorf("empty-alias body is %v, want the errorMessage shape", em)
	}
}

// TestRequirementChoicesAreStoredPerProviderAndNotSorted pins the one list that
// would survive being sorted looking correct.
//
// Fifty-three providers carry four distinct lists. `http-basic-authenticator`
// alone holds CONDITIONAL, and holds it **third**, before DISABLED, where every
// other list ends with DISABLED. Sorting the field is the tidy-up that is wrong
// on exactly one row.
func TestRequirementChoicesAreStoredPerProviderAndNotSorted(t *testing.T) {
	if len(requirementChoices) != 53 {
		t.Errorf("the table holds %d providers; the four registries publish a "+
			"disjoint union of 53", len(requirementChoices))
	}
	got, ok := requirementChoices["http-basic-authenticator"]
	if !ok {
		t.Fatal("http-basic-authenticator is missing from the table")
	}
	want := []string{"REQUIRED", "ALTERNATIVE", "CONDITIONAL", "DISABLED"}
	if len(got) != len(want) {
		t.Fatalf("http-basic-authenticator has %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("http-basic-authenticator has %v, want %v - CONDITIONAL is "+
				"third and DISABLED last, which sorting would not produce", got, want)
		}
	}
	// The control: a provider whose list is one of the three ordinary ones, so
	// the test above is not satisfied by every row looking the same.
	if cookie := requirementChoices["auth-cookie"]; len(cookie) != 3 {
		t.Errorf("auth-cookie has %v, want three choices", cookie)
	}
}

// TestConfigurableIsTheProvidersOwnPropertyCount pins the derivation that saved
// a column.
//
// `configurable` on an execution row is exactly "the provider declares at least
// one config property", measured with zero mismatches across all fifty-three.
// Both directions have to occur or a constant would satisfy the test.
func TestConfigurableIsTheProvidersOwnPropertyCount(t *testing.T) {
	var withProps, withoutProps int
	for id := range requirementChoices {
		if configurableProvider(id) {
			withProps++
		} else {
			withoutProps++
		}
	}
	if withProps == 0 || withoutProps == 0 {
		t.Fatalf("configurableProvider answered %d true and %d false; both are "+
			"needed or a constant would pass", withProps, withoutProps)
	}
	if !configurableProvider("identity-provider-redirector") {
		t.Error("identity-provider-redirector is measured configurable")
	}
	if configurableProvider("auth-cookie") {
		t.Error("auth-cookie is measured not configurable")
	}
	if configurableProvider("gloak-test-not-a-provider") {
		t.Error("an unknown provider is not configurable")
	}
}

// TestDeletingAConfigClearsTheRowsThatPointedAtIt keeps a served
// `authenticationConfig` id from resolving to a 404.
func TestDeletingAConfigClearsTheRowsThatPointedAtIt(t *testing.T) {
	h, s, realm := newServer(t)
	token := adminToken(t, h)
	ctx := context.Background()

	w := send(t, h, http.MethodPost, authBase+"/flows", token,
		`{"alias":"gloak-test-cfgclear","providerId":"basic-flow","topLevel":true,"builtIn":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create flow: %d %s", w.Code, w.Body)
	}
	w = send(t, h, http.MethodPost,
		authBase+"/flows/gloak-test-cfgclear/executions/execution", token,
		`{"provider":"reset-otp"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("add execution: %d %s", w.Code, w.Body)
	}
	execID := lastSegment(w.Header().Get("Location"))
	cfgID := postExecutionConfig(t, h, token, execID, "gloak-test-cfgclear-alias", "gamma")

	stored, err := s.AuthenticationFlows().ExecutionByID(ctx, realm.ID, execID)
	if err != nil {
		t.Fatalf("ExecutionByID: %v", err)
	}
	if stored.ConfigID != cfgID {
		t.Fatalf("the row points at %q, want %q", stored.ConfigID, cfgID)
	}

	if w := send(t, h, http.MethodDelete, authBase+"/config/"+cfgID, token, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete config: %d %s", w.Code, w.Body)
	}
	stored, err = s.AuthenticationFlows().ExecutionByID(ctx, realm.ID, execID)
	if err != nil {
		t.Fatalf("ExecutionByID after delete: %v", err)
	}
	if stored.ConfigID != "" {
		t.Errorf("the row still points at %q; a served authenticationConfig id "+
			"that resolves to a 404 is what this clears", stored.ConfigID)
	}
}

// TestTheFlowModelDoesNotLeakAcrossRealms is the boundary every repository in
// this project is expected to hold and the one a WHERE clause omission breaks.
func TestTheFlowModelDoesNotLeakAcrossRealms(t *testing.T) {
	h, s, _ := newServer(t)
	token := adminToken(t, h)
	ctx := context.Background()
	if _, err := bootstrap.CreateRealm(ctx, s, "gloak-test-otherflows", nil); err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}
	other := listFlows(t, h, "gloak-test-otherflows", token)
	master := listFlows(t, h, "master", token)

	ids := map[string]bool{}
	for _, f := range master {
		ids[f.ID] = true
	}
	for _, f := range other {
		if ids[f.ID] {
			t.Fatalf("flow %q has the same id in both realms; seeded ids are "+
				"minted per realm because the login form's execution parameter "+
				"is one of them", f.Alias)
		}
	}
	// Reading the other realm's flow through master's path is a 404.
	w := get(t, h, authBase+"/flows/"+other[0].ID, token)
	if w.Code != http.StatusNotFound {
		t.Errorf("master served another realm's flow: %d %s", w.Code, w.Body)
	}
}

// storeErr is the assertion that the interface's sentinel reaches the handler,
// used by nothing else here but kept next to its family.
var _ = store.ErrNotFound

// jsonKeys is a small helper for the tests that care about key order.
func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		t.Fatalf("body is not an object")
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		keys = append(keys, k.(string))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("value: %v", err)
		}
	}
	return keys
}

// TestTheExecutionReadPutsIdAndParentFlowLast pins the third serialisation of
// one row.
//
// GET /executions/{id} is the nested shape with `id`, then `flowId`, then
// `parentFlow` appended **after** the misspelled `autheticatorFlow`. The flat
// listing puts `flowId` between `configurable` and `level` and the nested shape
// does not carry it at all. Three orders for one field, so one shared
// serialiser is wrong on two of them.
func TestTheExecutionReadPutsIdAndParentFlowLast(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, authBase+"/flows", token,
		`{"alias":"gloak-test-execread","providerId":"basic-flow","topLevel":true,"builtIn":false}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create flow: %d %s", w.Code, w.Body)
	}
	w = send(t, h, http.MethodPost,
		authBase+"/flows/gloak-test-execread/executions/execution", token,
		`{"provider":"auth-otp-form"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("add execution: %d %s", w.Code, w.Body)
	}
	execID := lastSegment(w.Header().Get("Location"))

	w = get(t, h, authBase+"/executions/"+execID, token)
	if w.Code != http.StatusOK {
		t.Fatalf("read execution: %d %s", w.Code, w.Body)
	}
	want := []string{
		"authenticator", "authenticatorFlow", "requirement", "priority",
		"autheticatorFlow", "id", "parentFlow",
	}
	got := jsonKeys(t, w.Body.Bytes())
	if len(got) != len(want) {
		t.Fatalf("keys are %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys are %v, want %v", got, want)
		}
	}
}
