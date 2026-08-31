package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// enableOrganizations turns the realm's flag on through the API, which is how a
// caller does it: `PUT /admin/realms/{realm}` with `{"organizationsEnabled":true}`
// answered 204 and opened the whole tag on the reference container.
func enableOrganizations(t *testing.T, h http.Handler, token, realm string) {
	t.Helper()
	w := send(t, h, http.MethodPut, "/admin/realms/"+realm, token, `{"organizationsEnabled":true}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("enabling organizations: %d %s", w.Code, w.Body)
	}
}

// createOrg posts one organization and returns the id its Location names.
func createOrg(t *testing.T, h http.Handler, token, body string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/organizations", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", body, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// TestOrganizationsAreRefusedUntilTheRealmSaysSo pins the gate and, more
// importantly, **where it sits**: after the caller's roles, not before them.
//
// That is the whole difference from client-types, whose 501 reaches a caller
// holding no admin role at all. Both halves are measured, and a guard that got
// the order wrong would pass a test that only checked the message.
func TestOrganizationsAreRefusedUntilTheRealmSaysSo(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	none := tokenForRoles(t, h, s, realm)

	const want = `{"errorMessage":"Organizations not enabled for this realm."}`
	for _, path := range []string{
		"/admin/realms/master/organizations",
		"/admin/realms/master/organizations/count",
		"/admin/realms/master/organizations/whatever",
	} {
		w := get(t, h, path, admin)
		if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("%s with the flag off: got %d %s, want 404 %s", path, w.Code, w.Body, want)
		}
		// Plain application/json, no charset: the error half of the split.
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s Content-Type: got %q, want application/json", path, ct)
		}
	}

	// **The role check runs first.** A caller holding nothing gets 403 for the
	// same request the administrator gets the 404 for - including for an
	// organization id that could not exist either way.
	for _, path := range []string{
		"/admin/realms/master/organizations",
		"/admin/realms/master/organizations/whatever",
	} {
		if w := get(t, h, path, none); w.Code != http.StatusForbidden {
			t.Errorf("%s for a caller holding nothing: got %d %s, want 403", path, w.Code, w.Body)
		}
	}

	enableOrganizations(t, h, admin, "master")
	if w := get(t, h, "/admin/realms/master/organizations", admin); w.Code != http.StatusOK {
		t.Fatalf("after enabling: got %d %s, want 200", w.Code, w.Body)
	}
	// And the flag still shuts a caller out before it is consulted.
	if w := get(t, h, "/admin/realms/master/organizations", none); w.Code != http.StatusForbidden {
		t.Errorf("after enabling, a caller holding nothing: got %d, want 403", w.Code)
	}
}

// TestOrganizationRolesAreTheMeasuredSets sweeps one role at a time, the way
// the reference container was swept.
//
// The two rows that matter and that no obvious guess produces: **manage-realm
// opens everything and view-realm opens nothing**, and **query-organizations
// opens the listing and the count and not the single read**.
func TestOrganizationRolesAreTheMeasuredSets(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"probe-roles"}`)

	cases := []struct {
		role                             string
		list, count, read, write, delete int
	}{
		{"", 403, 403, 403, 403, 403},
		{"view-organizations", 200, 200, 200, 403, 403},
		{"manage-organizations", 200, 200, 200, 201, 204},
		{"query-organizations", 200, 200, 403, 403, 403},
		{"manage-realm", 200, 200, 200, 201, 204},
		{"view-realm", 403, 403, 403, 403, 403},
		{"view-users", 403, 403, 403, 403, 403},
		{"manage-users", 403, 403, 403, 403, 403},
		{"view-clients", 403, 403, 403, 403, 403},
		{"manage-clients", 403, 403, 403, 403, 403},
		{"query-groups", 403, 403, 403, 403, 403},
	}
	for _, c := range cases {
		t.Run("role="+c.role, func(t *testing.T) {
			var token string
			if c.role == "" {
				token = tokenForRoles(t, h, s, realm)
			} else {
				token = tokenForRole(t, h, s, realm, c.role)
			}
			check := func(what string, w *httptest.ResponseRecorder, want int) {
				if w.Code != want {
					t.Errorf("%s: got %d %s, want %d", what, w.Code, w.Body, want)
				}
			}
			check("list", get(t, h, "/admin/realms/master/organizations", token), c.list)
			check("count", get(t, h, "/admin/realms/master/organizations/count", token), c.count)
			check("read", get(t, h, "/admin/realms/master/organizations/"+id, token), c.read)
			// A fresh name per role so a second admitted caller does not 409.
			check("create", send(t, h, http.MethodPost, "/admin/realms/master/organizations",
				token, `{"name":"probe-`+c.role+`"}`), c.write)

			// The delete removes what the create just made, so the sweep leaves
			// the realm as it found it.
			target := id
			if c.delete == http.StatusNoContent {
				target = createOrg(t, h, admin, `{"name":"probe-del-`+c.role+`"}`)
			}
			check("delete", send(t, h, http.MethodDelete,
				"/admin/realms/master/organizations/"+target, token, ""), c.delete)
		})
	}
}

// TestOrganizationHasTwoShapesAndOnlyTheListingReadsTheFlag pins the three
// bodies and the parameter that reaches one of them.
func TestOrganizationHasTwoShapesAndOnlyTheListingReadsTheFlag(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin,
		`{"name":"probe-shape","attributes":{"k":["v"]},"domains":[{"name":"d.example.com"}]}`)

	// The listing's default is brief: no attributes.
	body := get(t, h, "/admin/realms/master/organizations", admin).Body.String()
	if strings.Contains(body, `"attributes"`) {
		t.Errorf("the brief listing carries attributes: %s", body)
	}
	if !strings.Contains(body, `"domains":[{"name":"d.example.com","verified":false}]`) {
		t.Errorf("the brief listing's domains: %s", body)
	}
	// briefRepresentation=false adds them.
	body = get(t, h, "/admin/realms/master/organizations?briefRepresentation=false", admin).Body.String()
	if !strings.Contains(body, `"attributes":{"k":["v"]}`) {
		t.Errorf("the full listing's attributes: %s", body)
	}

	// **The single read ignores the parameter.** Absent and true were measured
	// giving byte-identical bodies, attributes included.
	plain := get(t, h, "/admin/realms/master/organizations/"+id, admin).Body.String()
	brief := get(t, h, "/admin/realms/master/organizations/"+id+"?briefRepresentation=true", admin).Body.String()
	if plain != brief {
		t.Errorf("briefRepresentation moved the single read:\n %s\n %s", plain, brief)
	}
	if !strings.Contains(plain, `"attributes":{"k":["v"]}`) {
		t.Errorf("the single read's attributes: %s", plain)
	}
	// The measured field order, asserted as bytes rather than parsed.
	want := `"id":"` + id + `","name":"probe-shape","alias":"probe-shape","enabled":true,` +
		`"attributes":{"k":["v"]},"domains":[{"name":"d.example.com","verified":false}]`
	if !strings.Contains(plain, want) {
		t.Errorf("field order:\n got %s\nwant it to contain %s", plain, want)
	}
}

// TestOrganizationDomainsAndAttributesHaveOppositeEmptyRules pins the pair of
// neighbouring keys that disagree: domains is absent when empty and attributes
// is `{}`.
func TestOrganizationDomainsAndAttributesHaveOppositeEmptyRules(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"probe-bare"}`)

	body := strings.TrimSpace(get(t, h, "/admin/realms/master/organizations/"+id, admin).Body.String())
	want := `{"id":"` + id + `","name":"probe-bare","alias":"probe-bare","enabled":true,"attributes":{}}`
	if body != want {
		t.Errorf("an organization with neither:\n got %s\nwant %s", body, want)
	}
}

// TestOrganizationAttributeKeyOrderIsAJavaMap asserts the one thing a Go map
// would silently get wrong.
//
// `{"k":["v1","v2"],"z":["w"]}` came back `{"z":["w"],"k":["v1","v2"]}` from a
// live 26.7.1 - neither sorted nor insertion order - and javamap.KeyOrder
// returns [z k] for those two keys. Sorting instead produces `k` first and
// every byte after it moves.
func TestOrganizationAttributeKeyOrderIsAJavaMap(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"probe-attrs","attributes":{"k":["v1","v2"],"z":["w"]}}`)

	body := get(t, h, "/admin/realms/master/organizations/"+id, admin).Body.String()
	if !strings.Contains(body, `"attributes":{"z":["w"],"k":["v1","v2"]}`) {
		t.Errorf("attribute key order:\n got %s\nwant z before k", body)
	}
}

// TestOrganizationCountIsABareNumber pins the shape this API disagrees with
// itself about: /users/count is a bare number, /groups/count is an object, and
// this one sides with /users/count.
func TestOrganizationCountIsABareNumber(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	createOrg(t, h, admin, `{"name":"probe-count-a"}`)
	createOrg(t, h, admin, `{"name":"probe-count-b"}`)

	if got := strings.TrimSpace(get(t, h, "/admin/realms/master/organizations/count", admin).Body.String()); got != "2" {
		t.Errorf("count: got %q, want the bare number 2", got)
	}
	// It honours search, and answers 0 rather than an error for no match.
	if got := strings.TrimSpace(get(t, h, "/admin/realms/master/organizations/count?search=nomatch", admin).Body.String()); got != "0" {
		t.Errorf("count?search=nomatch: got %q, want 0", got)
	}
}

// TestOrganizationCreateRefusals pins every measured 4xx of the create, and in
// particular the **two 409s that differ only in a full stop**.
func TestOrganizationCreateRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	createOrg(t, h, admin, `{"name":"taken","alias":"taken-alias","domains":[{"name":"held.example.com"}]}`)

	cases := []struct {
		name, body string
		status     int
		want       string
	}{
		{"no name", `{}`, 400, `{"errorMessage":"Name can not be null"}`},
		// An empty name is a null name here, unlike a client scope's.
		{"empty name", `{"name":""}`, 400, `{"errorMessage":"Name can not be null"}`},
		{"null name", `{"name":null}`, 400, `{"errorMessage":"Name can not be null"}`},
		// The full stop is the whole difference between these two.
		{"duplicate name", `{"name":"taken"}`, 409,
			`{"errorMessage":"A organization with the same name already exists."}`},
		{"duplicate alias", `{"name":"fresh","alias":"taken-alias"}`, 409,
			`{"errorMessage":"A organization with the same alias already exists"}`},
		// A duplicate domain is a **400**, not a 409, and names the other one.
		{"duplicate domain", `{"name":"fresh2","domains":[{"name":"held.example.com"}]}`, 400,
			`{"errorMessage":"Domain held.example.com is already linked to organization taken in realm master"}`},
		// A name that cannot be an alias: the errorMessage family, with the
		// prefix that says the name is being used as one.
		{"name with a slash", `{"name":"a/b"}`, 400,
			`{"errorMessage":"Name cannot be used as alias: Character '/' not allowed."}`},
		{"name with a space", `{"name":"a b"}`, 400,
			`{"errorMessage":"Name cannot be used as alias: Empty Space not allowed."}`},
		// An explicit alias goes to the **error** family with no prefix. One
		// validation, two shapes, decided by which field carried the value.
		{"alias with a slash", `{"name":"fine1","alias":"a/b"}`, 400,
			`{"error":"Character '/' not allowed."}`},
		{"alias with a space", `{"name":"fine2","alias":"a b"}`, 400,
			`{"error":"Empty Space not allowed."}`},
		// The body's shape decides the parse error's code: `[` is unknown_error.
		{"array body", `[`, 400,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"truncated object", `{`, 400,
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		// The create is a strict decoder, which the required-action PUTs were
		// the first of and these are not the last.
		{"unknown field", `{"name":"fine3","bogusField":"x"}`, 400,
			`{"error":"Invalid json representation for OrganizationRepresentation. Unrecognized field \"bogusField\" at line 1 column 31."}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := send(t, h, http.MethodPost, "/admin/realms/master/organizations", admin, c.body)
			if w.Code != c.status || strings.TrimSpace(w.Body.String()) != c.want {
				t.Errorf("got %d %s\nwant %d %s", w.Code, strings.TrimSpace(w.Body.String()), c.status, c.want)
			}
		})
	}
}

// TestOrganizationNameIsOnlyAliasCheckedWhenItBecomesTheAlias is the rule the
// refusals above would otherwise make look like a name rule.
//
// `{"name":"bad/name","alias":"goodalias"}` is a **201**, and the organization
// that comes out is named `bad/name`. The character set constrains the alias;
// the name is checked only because it is what the alias is derived from.
func TestOrganizationNameIsOnlyAliasCheckedWhenItBecomesTheAlias(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")

	id := createOrg(t, h, admin, `{"name":"bad/name","alias":"goodalias"}`)
	body := get(t, h, "/admin/realms/master/organizations/"+id, admin).Body.String()
	if !strings.Contains(body, `"name":"bad/name","alias":"goodalias"`) {
		t.Errorf("an organization named bad/name: %s", body)
	}
}

// TestOrganizationCreateIgnoresTheBodyID pins the inversion: POST /clients and
// POST /client-scopes both honour an id in the body, and this one does not.
func TestOrganizationCreateIgnoresTheBodyID(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")

	const asked = "11111111-2222-3333-4444-555555555555"
	id := createOrg(t, h, admin, `{"id":"`+asked+`","name":"probe-id"}`)
	if id == asked {
		t.Errorf("the body's id won: %s", id)
	}
	if w := get(t, h, "/admin/realms/master/organizations/"+asked, admin); w.Code != http.StatusNotFound {
		t.Errorf("the asked-for id resolves: %d %s", w.Code, w.Body)
	}
}

// TestOrganizationUpdateReplacesAndCannotRenameTheAlias pins the PUT's three
// measured behaviours: it replaces, the alias is immutable, and an absent alias
// means "derive it from the name" rather than "leave it alone".
func TestOrganizationUpdateReplacesAndCannotRenameTheAlias(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin,
		`{"name":"probe-put","alias":"probe-put-alias","enabled":false,"description":"d",`+
			`"redirectUrl":"http://x/","attributes":{"k":["v"]},`+
			`"domains":[{"name":"put.example.com","verified":true}]}`)
	path := "/admin/realms/master/organizations/" + id

	// An absent alias derives one from the name, which then differs from the
	// stored one. A read-modify-write that drops `alias` fails on every
	// organization whose alias is not its name.
	w := send(t, h, http.MethodPut, path, admin, `{"name":"probe-put"}`)
	if w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != `{"errorMessage":"Cannot change the alias"}` {
		t.Errorf("PUT with no alias: got %d %s, want 400 Cannot change the alias", w.Code, w.Body)
	}
	// A different alias is the same refusal.
	w = send(t, h, http.MethodPut, path, admin, `{"name":"probe-put","alias":"other"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("PUT with a new alias: got %d %s, want 400", w.Code, w.Body)
	}

	// The stored alias with a new name renames it, and everything the body does
	// not carry is cleared - except attributes, which survive.
	w = send(t, h, http.MethodPut, path, admin, `{"name":"probe-renamed","alias":"probe-put-alias"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT rename: got %d %s, want 204", w.Code, w.Body)
	}
	body := strings.TrimSpace(get(t, h, path, admin).Body.String())
	want := `{"id":"` + id + `","name":"probe-renamed","alias":"probe-put-alias","enabled":true,` +
		`"attributes":{"k":["v"]}}`
	if body != want {
		t.Errorf("after the PUT:\n got %s\nwant %s", body, want)
	}

	// attributes sent as {} are cleared, where attributes absent survived.
	w = send(t, h, http.MethodPut, path, admin,
		`{"name":"probe-renamed","alias":"probe-put-alias","attributes":{}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT clearing attributes: got %d %s", w.Code, w.Body)
	}
	if body := get(t, h, path, admin).Body.String(); !strings.Contains(body, `"attributes":{}`) {
		t.Errorf("attributes were not cleared: %s", body)
	}
}

// TestOrganizationUpdateAnsweringAConflictItDoesNotHave pins Keycloak's own
// defect: a PUT with no name falls back to the alias, which then collides with
// the organization's own row, so the answer is a 409 about a name the request
// never sent. The create answers the same missing name with a 400.
func TestOrganizationUpdateAnsweringAConflictItDoesNotHave(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"target","alias":"target"}`)
	path := "/admin/realms/master/organizations/" + id

	const want = `{"errorMessage":"A organization with the same name already exists."}`
	for _, body := range []string{`{"alias":"target"}`, `{"name":"","alias":"target"}`} {
		w := send(t, h, http.MethodPut, path, admin, body)
		if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("PUT %s: got %d %s, want 409 %s", body, w.Code, w.Body, want)
		}
	}

	// A real collision with another organization answers the same way.
	createOrg(t, h, admin, `{"name":"other","alias":"other"}`)
	w := send(t, h, http.MethodPut, path, admin, `{"name":"other","alias":"target"}`)
	if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("PUT onto a taken name: got %d %s, want 409", w.Code, w.Body)
	}
}

// TestOrganizationIsResolvedBeforeTheBodyIsRead pins the order the two writes
// disagree about with PUT /required-actions/{alias}, where the decode runs
// first: here an unknown id is a 404 even for a body that cannot be parsed.
func TestOrganizationIsResolvedBeforeTheBodyIsRead(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")

	const want = `{"errorMessage":"Organization not found."}`
	for _, body := range []string{`{"name":"x","alias":"wrong"}`, `{"name":"x","bogusField":1}`, `{`} {
		w := send(t, h, http.MethodPut, "/admin/realms/master/organizations/nosuch", admin, body)
		if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("PUT nosuch with %s: got %d %s, want 404 %s", body, w.Code, w.Body, want)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := send(t, h, method, "/admin/realms/master/organizations/nosuch", admin, "")
		if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("%s nosuch: got %d %s, want 404 %s", method, w.Code, w.Body, want)
		}
	}
}

// TestOrganizationDeleteIsNotIdempotent pins the second delete's 404, which the
// realm's default-groups delete answers 204 to.
func TestOrganizationDeleteIsNotIdempotent(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"probe-delete"}`)
	path := "/admin/realms/master/organizations/" + id

	if w := send(t, h, http.MethodDelete, path, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("first delete: got %d %s, want 204", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, path, admin, ""); w.Code != http.StatusNotFound {
		t.Errorf("second delete: got %d %s, want 404", w.Code, w.Body)
	}
}

// TestOrganizationSearchMatchesNameAndDomainAndNotAlias pins the third field,
// which the obvious "search every string" implementation gets wrong.
func TestOrganizationSearchMatchesNameAndDomainAndNotAlias(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	createOrg(t, h, admin,
		`{"name":"probe-search","alias":"unique-alias","domains":[{"name":"findme.example.com"}]}`)
	createOrg(t, h, admin, `{"name":"probe-other"}`)

	names := func(query string) []string {
		t.Helper()
		var rows []struct {
			Name string `json:"name"`
		}
		w := get(t, h, "/admin/realms/master/organizations"+query, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v (%s)", query, err, w.Body)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out
	}

	if got := names("?search=findme.example.com"); len(got) != 1 || got[0] != "probe-search" {
		t.Errorf("search by domain: got %v, want [probe-search]", got)
	}
	// Case-insensitive substring over the name.
	if got := names("?search=PROBE-SEARCH"); len(got) != 1 || got[0] != "probe-search" {
		t.Errorf("search is not case-insensitive: got %v", got)
	}
	// **The alias is not searched.**
	if got := names("?search=unique-alias"); len(got) != 0 {
		t.Errorf("search matched the alias: got %v, want none", got)
	}
	// exact narrows to an equal name.
	if got := names("?search=probe&exact=true"); len(got) != 0 {
		t.Errorf("exact=true matched a prefix: got %v", got)
	}
	if got := names("?search=probe-other&exact=true"); len(got) != 1 {
		t.Errorf("exact=true on a full name: got %v", got)
	}
}

// TestOrganizationListingPagesOnEitherBound pins the paging rule, which is the
// group listing's and **not** the role listings', where max alone is ignored.
func TestOrganizationListingPagesOnEitherBound(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	// Created out of order, and with a capital, because the listing sorts by
	// name in **byte** order: UPPER comes before aaa.
	for _, name := range []string{"zzz", "aaa", "UPPER", "mmm"} {
		createOrg(t, h, admin, `{"name":"`+name+`"}`)
	}

	names := func(query string) []string {
		t.Helper()
		var rows []struct {
			Name string `json:"name"`
		}
		w := get(t, h, "/admin/realms/master/organizations"+query, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out
	}

	all := names("")
	if len(all) != 4 || all[0] != "UPPER" || all[1] != "aaa" {
		t.Errorf("listing order: got %v, want UPPER first then aaa", all)
	}
	// max alone pages, which is what separates this from the role listings.
	if got := names("?max=1"); len(got) != 1 || got[0] != "UPPER" {
		t.Errorf("?max=1: got %v, want [UPPER]", got)
	}
	// first alone pages too.
	if got := names("?first=1"); len(got) != 3 || got[0] != "aaa" {
		t.Errorf("?first=1: got %v, want three rows starting at aaa", got)
	}
	if got := names("?first=1&max=1"); len(got) != 1 || got[0] != "aaa" {
		t.Errorf("?first=1&max=1: got %v, want [aaa]", got)
	}
}

// TestOrganizationDescriptionTellsAbsentFromEmpty pins the pair of neighbouring
// fields with opposite rules: `"description":""` reads back and
// `"redirectUrl":""` does not.
func TestOrganizationDescriptionTellsAbsentFromEmpty(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	id := createOrg(t, h, admin, `{"name":"probe-desc","description":"","redirectUrl":""}`)

	body := strings.TrimSpace(get(t, h, "/admin/realms/master/organizations/"+id, admin).Body.String())
	if !strings.Contains(body, `"description":""`) {
		t.Errorf("an empty description was dropped: %s", body)
	}
	if strings.Contains(body, `"redirectUrl"`) {
		t.Errorf("an empty redirectUrl was kept: %s", body)
	}
}

// TestOrganizationQueryFiltersOnAttributes pins `q`, and that a q with no colon
// is ignored rather than refused.
func TestOrganizationQueryFiltersOnAttributes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	createOrg(t, h, admin, `{"name":"probe-q-yes","attributes":{"k":["v"]}}`)
	createOrg(t, h, admin, `{"name":"probe-q-no"}`)

	count := func(query string) int {
		t.Helper()
		var rows []json.RawMessage
		w := get(t, h, "/admin/realms/master/organizations"+query, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return len(rows)
	}
	if got := count("?q=k:v"); got != 1 {
		t.Errorf("?q=k:v: got %d rows, want 1", got)
	}
	if got := count("?q=k:other"); got != 0 {
		t.Errorf("?q=k:other: got %d rows, want 0", got)
	}
	if got := count("?q=nocolon"); got != 2 {
		t.Errorf("?q=nocolon: got %d rows, want both - a q with no colon is ignored", got)
	}
}
