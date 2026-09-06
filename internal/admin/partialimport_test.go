package admin

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const importPath = "/admin/realms/master/partialImport"

// importResult is the answer, parsed. The counts and the rows are what every
// claim below is stated in.
type importResult struct {
	Overwritten int `json:"overwritten"`
	Added       int `json:"added"`
	Skipped     int `json:"skipped"`
	Results     []struct {
		Action       string `json:"action"`
		ResourceType string `json:"resourceType"`
		ResourceName string `json:"resourceName"`
		ID           string `json:"id"`
	} `json:"results"`
}

func doImport(t *testing.T, h http.Handler, token, body string) (int, string) {
	t.Helper()
	w := send(t, h, http.MethodPost, importPath, token, body)
	return w.Code, strings.TrimSpace(w.Body.String())
}

func importOK(t *testing.T, h http.Handler, token, body string) importResult {
	t.Helper()
	w := send(t, h, http.MethodPost, importPath, token, body)
	if w.Code != http.StatusOK {
		t.Fatalf("partialImport: %d %s", w.Code, w.Body)
	}
	var out importResult
	if err := decodeJSON(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse the result: %v (%s)", err, w.Body)
	}
	return out
}

// TestPartialImportAnswersTheMeasuredResultShape pins the four keys, their
// order, and the four keys of a row.
func TestPartialImportAnswersTheMeasuredResultShape(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPost, importPath, token,
		`{"ifResourceExists":"FAIL","users":[{"username":"pi-shape"}]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("partialImport: %d %s", w.Code, w.Body)
	}
	if got, want := jsonKeyOrder(t, w.Body.Bytes()),
		[]string{"overwritten", "added", "skipped", "results"}; !slices.Equal(got, want) {
		t.Errorf("result keys %v, measured %v", got, want)
	}

	var body struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(body.Results) != 1 {
		t.Fatalf("%d rows, want 1", len(body.Results))
	}
	if got, want := jsonKeyOrder(t, body.Results[0]),
		[]string{"action", "resourceType", "resourceName", "id"}; !slices.Equal(got, want) {
		t.Errorf("row keys %v, measured %v", got, want)
	}

	// **The success carries the charset the export beside it does not, and no
	// Cache-Control, which the export does not either.** One response, one
	// header on each side of the neighbour.
	if got := w.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
		t.Errorf("Content-Type %q, measured %q", got, "application/json;charset=UTF-8")
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control %q, measured absent", got)
	}
	// The control: the export's own answer differs on the charset, and
	// GET /admin/realms/master differs on both.
	e := send(t, h, http.MethodPost, exportPath, token, "")
	if e.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("the control does not differ: the export sends %q", e.Header().Get("Content-Type"))
	}
	c := send(t, h, http.MethodGet, "/admin/realms/master", token, "")
	if c.Header().Get("Cache-Control") == "" {
		t.Fatalf("the control does not differ: the realm read carries no Cache-Control either")
	}
}

// TestPartialImportRefusalsCarryNoCacheControl is the other half of the header
// claim: the 409 and the 500 omit it too, so this is a per-endpoint rule rather
// than a per-status one.
func TestPartialImportRefusalsCarryNoCacheControl(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-cc"}]}`)

	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"the 409", `{"ifResourceExists":"FAIL","users":[{"username":"pi-cc"}]}`, http.StatusConflict},
		{"the 500", `{`, http.StatusInternalServerError},
	} {
		w := send(t, h, http.MethodPost, importPath, token, tc.body)
		if w.Code != tc.want {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "" {
			t.Errorf("%s carries Cache-Control %q, measured absent", tc.name, got)
		}
	}
}

// TestPartialImportPolicyOnAnExistingResource is the three dispositions, and
// the id each answers with. **OVERWRITE mints a new one**, which is what says
// it is a delete and a recreate rather than an update.
func TestPartialImportPolicyOnAnExistingResource(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	first := importOK(t, h, token, `{"ifResourceExists":"FAIL","users":[{"username":"pi-policy"}]}`)
	if first.Added != 1 || first.Results[0].Action != "ADDED" {
		t.Fatalf("the first import is not an ADDED: %+v", first)
	}
	original := first.Results[0].ID

	skip := importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-policy"}]}`)
	if skip.Skipped != 1 || skip.Added != 0 || skip.Overwritten != 0 {
		t.Errorf("SKIP counts %+v, measured skipped 1", skip)
	}
	if skip.Results[0].Action != "SKIPPED" {
		t.Errorf("SKIP action %q, measured SKIPPED", skip.Results[0].Action)
	}
	if skip.Results[0].ID != original {
		t.Errorf("SKIP answered id %q, measured the existing resource's %q",
			skip.Results[0].ID, original)
	}

	over := importOK(t, h, token, `{"ifResourceExists":"OVERWRITE","users":[{"username":"pi-policy"}]}`)
	if over.Overwritten != 1 || over.Added != 0 || over.Skipped != 0 {
		t.Errorf("OVERWRITE counts %+v, measured overwritten 1", over)
	}
	if over.Results[0].Action != "OVERWRITTEN" {
		t.Errorf("OVERWRITE action %q, measured OVERWRITTEN", over.Results[0].Action)
	}
	if over.Results[0].ID == original {
		t.Errorf("OVERWRITE kept the id %q; measured minting a new one", original)
	}
}

// TestPartialImportFailAndAbsentAnswerTheSameConflict pins the default and the
// six spellings, **three of which have a full stop and three of which do not**.
func TestPartialImportFailAndAbsentAnswerTheSameConflict(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	// The state each row needs.
	importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-c-user"}]}`)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","groups":[{"name":"pi-c-group","path":"/pi-c-group"}]}`)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","clients":[{"clientId":"pi-c-client"}]}`)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","roles":{"realm":[{"name":"pi-c-role"}]}}`)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","roles":{"client":{"pi-c-client":[{"name":"pi-c-crole"}]}}}`)

	for _, tc := range []struct{ name, body, want string }{
		{"user", `{"ifResourceExists":"FAIL","users":[{"username":"pi-c-user"}]}`,
			`{"errorMessage":"User with user name pi-c-user already exists."}`},
		{"group", `{"ifResourceExists":"FAIL","groups":[{"name":"pi-c-group","path":"/pi-c-group"}]}`,
			`{"errorMessage":"Group '/pi-c-group' already exists"}`},
		{"client", `{"ifResourceExists":"FAIL","clients":[{"clientId":"pi-c-client"}]}`,
			`{"errorMessage":"Client id 'pi-c-client' already exists"}`},
		{"realm role", `{"ifResourceExists":"FAIL","roles":{"realm":[{"name":"pi-c-role"}]}}`,
			`{"errorMessage":"Realm role 'pi-c-role' already exists."}`},
		{"client role", `{"ifResourceExists":"FAIL","roles":{"client":{"pi-c-client":[{"name":"pi-c-crole"}]}}}`,
			`{"errorMessage":"Client role 'pi-c-crole' for client 'pi-c-client' already exists."}`},
		// **Absent is FAIL**, measured on the same resource.
		{"absent policy", `{"users":[{"username":"pi-c-user"}]}`,
			`{"errorMessage":"User with user name pi-c-user already exists."}`},
		// `policy` is not the field's name and is ignored.
		{"policy is not read", `{"policy":"SKIP","users":[{"username":"pi-c-user"}]}`,
			`{"errorMessage":"User with user name pi-c-user already exists."}`},
	} {
		code, body := doImport(t, h, token, tc.body)
		if code != http.StatusConflict {
			t.Errorf("%s: %d %s, measured 409", tc.name, code, body)
		}
		if body != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, body, tc.want)
		}
	}
}

// TestPartialImportUnknownPolicyIsRejectedBeforeAnyResource is half the
// question the brief asked: what an unknown ifResourceExists does.
//
// An unknown **string** fails to bind, and it fails whether or not the resource
// exists, which is what separates it from the explicit null below.
func TestPartialImportUnknownPolicyIsRejectedBeforeAnyResource(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	const cannotParse = `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`

	importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-p"}]}`)

	for _, tc := range []struct{ name, body string }{
		{"BOGUS, a resource that exists", `{"ifResourceExists":"BOGUS","users":[{"username":"pi-p"}]}`},
		{"BOGUS, a resource that does not", `{"ifResourceExists":"BOGUS","users":[{"username":"pi-nobody"}]}`},
		{"lower case", `{"ifResourceExists":"skip","users":[{"username":"pi-p"}]}`},
		{"empty string", `{"ifResourceExists":"","users":[{"username":"pi-p"}]}`},
		{"a number", `{"ifResourceExists":5}`},
	} {
		code, body := doImport(t, h, token, tc.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s: %d %s, measured 500", tc.name, code, body)
		}
		if body != cannotParse {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, body, cannotParse)
		}
	}
	// The control: a policy that does bind, on the same shape of body.
	if code, body := doImport(t, h, token,
		`{"ifResourceExists":"SKIP","users":[{"username":"pi-p"}]}`); code != http.StatusOK {
		t.Fatalf("the control does not differ: SKIP answered %d %s", code, body)
	}
}

// TestPartialImportNullPolicyNeedsTheResourceToExist is the other half, and it
// is a **two-condition rule**: `"ifResourceExists":null` is a 200 ADDED on a
// resource that does not exist and a 500 on one that does.
//
// The first hand probe of this cell sent null only against a resource that
// already existed, wrote the 500 down as the whole answer, and was refuted by
// the golden recorded from Keycloak. Both conditions are supplied here, on two
// resource families, because one of them supplying both is what pins the rule.
func TestPartialImportNullPolicyNeedsTheResourceToExist(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	const consultLog = `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`

	for _, tc := range []struct{ name, body string }{
		{"a user", `{"ifResourceExists":null,"users":[{"username":"pi-null-user"}]}`},
		{"a group", `{"ifResourceExists":null,"groups":[{"name":"pi-null-g","path":"/pi-null-g"}]}`},
	} {
		// First condition: the resource does not exist.
		got := importOK(t, h, token, tc.body)
		if got.Added != 1 || got.Results[0].Action != "ADDED" {
			t.Errorf("%s, not yet there: %+v, measured one ADDED", tc.name, got)
		}
		// Second condition: the same body once it does.
		code, body := doImport(t, h, token, tc.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s, now there: %d %s, measured 500", tc.name, code, body)
		}
		if body != consultLog {
			t.Errorf("%s, now there:\n got %s\nwant %s", tc.name, body, consultLog)
		}
	}

	// The control that says null is not simply FAIL: an absent field on a
	// resource that exists is the 409, not this 500.
	importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-absent-user"}]}`)
	code, body := doImport(t, h, token, `{"users":[{"username":"pi-absent-user"}]}`)
	if code != http.StatusConflict {
		t.Fatalf("the control does not differ: an absent policy answered %d %s", code, body)
	}
}

// TestPartialImportSeparatesASyntaxErrorFromABindingFailure is F163's
// discriminating measurement, and this endpoint is where it can be taken: one
// route answers **both** codes, and what decides is where the failure happened.
func TestPartialImportSeparatesASyntaxErrorFromABindingFailure(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	const parse = `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`
	const bind = `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`

	for _, tc := range []struct{ name, body, want string }{
		{"unclosed object", `{`, parse},
		{"trailing comma", `{"users":[],}`, parse},
		{"unquoted key", `{users:[]}`, parse},
		{"a malformed bare word", `nul`, parse},
		{"unclosed array", `[`, bind},
		{"an array", `[]`, bind},
		{"a string", `"x"`, bind},
		{"true", `true`, bind},
		{"a number", `7`, bind},
		// The right shape carrying a value of the wrong type - the exact
		// request F163 says would settle it.
		{"users is a string", `{"ifResourceExists":"SKIP","users":"nope"}`, bind},
		{"users is a number", `{"ifResourceExists":"SKIP","users":7}`, bind},
	} {
		code, body := doImport(t, h, token, tc.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s: %d %s, measured 500", tc.name, code, body)
		}
		if body != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, body, tc.want)
		}
	}
}

// TestPartialImportAcceptsTheBodiesKeycloakAccepts is the other half of the
// decode: three shapes that are 200 rather than a refusal.
func TestPartialImportAcceptsTheBodiesKeycloakAccepts(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	for _, tc := range []struct{ name, body string }{
		{"empty object", `{}`},
		{"policy only", `{"ifResourceExists":"FAIL"}`},
		// An unknown top-level key is ignored, so this is not a strict decode.
		{"an unknown key", `{"ifResourceExists":"SKIP","nosuchkey":[1,2,3]}`},
		// Two documents: Jackson reads the first and stops.
		{"two documents", `{} {}`},
	} {
		got := importOK(t, h, token, tc.body)
		if got.Added != 0 || got.Skipped != 0 || got.Overwritten != 0 || len(got.Results) != 0 {
			t.Errorf("%s: %+v, measured an empty result set", tc.name, got)
		}
	}

	// **Jackson coerces a number to a string**, so this is a 200 and the user's
	// name is "7". Refusing it would be a 500 where Keycloak answers 200.
	got := importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":7}]}`)
	if len(got.Results) != 1 || got.Results[0].ResourceName != "7" {
		t.Errorf("a numeric username gave %+v, measured one row named \"7\"", got)
	}
}

// TestPartialImportGroupWithNoPathIsKeycloaksNullPointer reproduces the defect.
// The 500 is the answer and the realm keeps nothing.
func TestPartialImportGroupWithNoPathIsKeycloaksNullPointer(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	const consultLog = `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`
	for _, policy := range []string{"FAIL", "SKIP", "OVERWRITE"} {
		code, body := doImport(t, h, token,
			`{"ifResourceExists":"`+policy+`","groups":[{"name":"pi-nopath"}]}`)
		if code != http.StatusInternalServerError || body != consultLog {
			t.Errorf("%s: %d %s, measured 500 %s", policy, code, body, consultLog)
		}
	}
	// Nothing was left behind. The realm's group listing is the control.
	w := send(t, h, http.MethodGet, "/admin/realms/master/groups", token, "")
	if strings.Contains(w.Body.String(), "pi-nopath") {
		t.Errorf("the 500 left a group behind: %s", w.Body)
	}
	// The control: the same group with a path is a 200.
	got := importOK(t, h, token,
		`{"ifResourceExists":"FAIL","groups":[{"name":"pi-withpath","path":"/pi-withpath"}]}`)
	if got.Added != 1 {
		t.Fatalf("the control does not differ: a group with a path gave %+v", got)
	}
}

// TestPartialImportGroupTakesTheBodysID is the third endpoint on that side of
// the rule, after POST /client-scopes and POST /clients.
func TestPartialImportGroupTakesTheBodysID(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	const id = "11111111-1111-1111-1111-111111111111"

	got := importOK(t, h, token,
		`{"ifResourceExists":"FAIL","groups":[{"id":"`+id+`","name":"pi-id","path":"/pi-id"}]}`)
	if len(got.Results) != 1 || got.Results[0].ID != id {
		t.Fatalf("the result's id is %+v, measured the body's %q", got.Results, id)
	}
	w := send(t, h, http.MethodGet, "/admin/realms/master/groups", token, "")
	if !strings.Contains(w.Body.String(), id) {
		t.Errorf("the realm does not hold the body's id: %s", w.Body)
	}
}

// TestPartialImportResourceTypesAndTheClientRoleRow pins the six spellings, and
// the client role's row, whose **resourceName joins two names with `-->` and
// whose id is the client's rather than the role's**.
func TestPartialImportResourceTypesAndTheClientRoleRow(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	got := importOK(t, h, token, `{
	  "ifResourceExists":"SKIP",
	  "users":[{"username":"pi-t-user"}],
	  "groups":[{"name":"pi-t-group","path":"/pi-t-group"}],
	  "clients":[{"clientId":"pi-t-client"}],
	  "roles":{"realm":[{"name":"pi-t-role"}],"client":{"pi-t-client":[{"name":"pi-t-crole"}]}},
	  "identityProviders":[{"alias":"pi-t-idp","providerId":"oidc","config":{"clientId":"c","clientSecret":"s","authorizationUrl":"https://x/a","tokenUrl":"https://x/t"}}]
	}`)
	if got.Added != 6 {
		t.Fatalf("added %d, want 6: %+v", got.Added, got.Results)
	}
	byType := map[string]string{}
	ids := map[string]string{}
	for _, r := range got.Results {
		byType[r.ResourceType] = r.ResourceName
		ids[r.ResourceType] = r.ID
	}
	// **IDP, not IDENTITY_PROVIDER.**
	for _, want := range []string{"USER", "GROUP", "CLIENT", "REALM_ROLE", "CLIENT_ROLE", "IDP"} {
		if _, ok := byType[want]; !ok {
			t.Errorf("no %s row: %+v", want, got.Results)
		}
	}
	if byType["CLIENT_ROLE"] != "pi-t-client-->pi-t-crole" {
		t.Errorf("the client role's resourceName is %q, measured %q",
			byType["CLIENT_ROLE"], "pi-t-client-->pi-t-crole")
	}
	if ids["CLIENT_ROLE"] != ids["CLIENT"] {
		t.Errorf("the client role's id is %q; measured the client's own %q",
			ids["CLIENT_ROLE"], ids["CLIENT"])
	}
	if ids["REALM_ROLE"] == ids["CLIENT"] {
		t.Errorf("the control does not differ: a realm role reported the client's id")
	}
}

// TestPartialImportRollsBackOnAConflict is the transactional claim: a body
// naming a new resource and then one that already exists leaves neither.
func TestPartialImportRollsBackOnAConflict(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)
	importOK(t, h, token, `{"ifResourceExists":"SKIP","users":[{"username":"pi-r-existing"}]}`)

	code, body := doImport(t, h, token,
		`{"ifResourceExists":"FAIL","users":[{"username":"pi-r-new"},{"username":"pi-r-existing"}]}`)
	if code != http.StatusConflict {
		t.Fatalf("%d %s, measured 409", code, body)
	}
	// **The listing is parsed rather than searched for "[]".** A user
	// representation carries `"disableableCredentialTypes":[]` and
	// `"requiredActions":[]`, so a substring check for an empty array passes on
	// a body that holds the very user it is asserting is absent - which is
	// exactly what a mutation dropping the rollback survived on.
	if n := len(usersNamed(t, h, token, "pi-r-new")); n != 0 {
		t.Errorf("the 409 left %d copies of pi-r-new behind", n)
	}
	// The control: the user the fixture did create is still there, so a listing
	// that answers nothing for every name would not pass this test.
	if n := len(usersNamed(t, h, token, "pi-r-existing")); n != 1 {
		t.Fatalf("the control does not differ: pi-r-existing is there %d times", n)
	}
}

// usersNamed reads the user listing back as rows, so a test can count them.
func usersNamed(t *testing.T, h http.Handler, token, username string) []struct {
	ID       string `json:"id"`
	Username string `json:"username"`
} {
	t.Helper()
	w := send(t, h, http.MethodGet,
		"/admin/realms/master/users?username="+username+"&exact=true", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list users: %d %s", w.Code, w.Body)
	}
	var rows []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse the listing: %v", err)
	}
	return rows
}

// TestPartialImportRefusesADuplicateInsideOneBody pins the seventh conflict
// message, and that it fires **under SKIP too** - the policy is about resources
// that existed before the import, not about the body's own repeats.
func TestPartialImportRefusesADuplicateInsideOneBody(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	for _, policy := range []string{"FAIL", "SKIP"} {
		code, body := doImport(t, h, token,
			`{"ifResourceExists":"`+policy+`","users":[{"username":"pi-twice-`+policy+`"},{"username":"pi-twice-`+policy+`"}]}`)
		if code != http.StatusConflict {
			t.Errorf("%s: %d %s, measured 409", policy, code, body)
		}
		if want := `{"errorMessage":"Duplicate resource error"}`; body != want {
			t.Errorf("%s:\n got %s\nwant %s", policy, body, want)
		}
	}
}

// TestPartialImportGuardDoesNotFollowTheBody is the guard, and the contrast
// with the export next door.
func TestPartialImportGuardDoesNotFollowTheBody(t *testing.T) {
	h, s, realm := newServer(t)

	manageRealm := tokenForRoles(t, h, s, realm, "manage-realm")
	for _, tc := range []struct{ name, body string }{
		{"empty", `{"ifResourceExists":"SKIP"}`},
		{"a user", `{"ifResourceExists":"SKIP","users":[{"username":"pi-g-user"}]}`},
		{"a client", `{"ifResourceExists":"SKIP","clients":[{"clientId":"pi-g-client"}]}`},
		{"a group", `{"ifResourceExists":"SKIP","groups":[{"name":"pi-g-group","path":"/pi-g-group"}]}`},
	} {
		if code, body := doImport(t, h, manageRealm, tc.body); code != http.StatusOK {
			t.Errorf("manage-realm importing %s: %d %s, measured 200", tc.name, code, body)
		}
	}

	// Four roles that between them cover both halves of the export's guard and
	// still open nothing here.
	weak := tokenForRoles(t, h, s, realm, "view-realm", "view-clients", "query-groups", "manage-users")
	for _, body := range []string{`{"ifResourceExists":"SKIP"}`, `{`} {
		if code, out := doImport(t, h, weak, body); code != http.StatusForbidden {
			t.Errorf("a caller without manage-realm: %d %s, measured 403", code, out)
		}
	}
}

// TestPartialImportResolvesTheRealmBeforeTheCallerAndTheBody pins the order:
// the 404 wins over the 403, and the 403 wins over the malformed body.
func TestPartialImportResolvesTheRealmBeforeTheCallerAndTheBody(t *testing.T) {
	h, s, realm := newServer(t)
	weak := tokenForRoles(t, h, s, realm, "view-realm")

	w := send(t, h, http.MethodPost, "/admin/realms/gloak-no-such/partialImport", weak, `{`)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown realm, weak caller, bad body: %d %s, measured 404", w.Code, w.Body)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"error":"Realm not found."}`; got != want {
		t.Errorf("body %s, measured %s", got, want)
	}
	if code, body := doImport(t, h, weak, `{`); code != http.StatusForbidden {
		t.Errorf("known realm, weak caller, bad body: %d %s, measured 403", code, body)
	}
}
