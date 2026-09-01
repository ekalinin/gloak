package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// The access block is the caller's permissions, not the target user's. Every
// row is measured: a user was given exactly one master-realm role in the
// reference container and used to read the administrator.
//
// No conformance case can cover this. Every fixture authenticates as the full
// administrator, and reaching a narrow-role caller needs role assignment
// through the API, which is P2's second cut.
func TestUserAccessIsTheCallersPermissions(t *testing.T) {
	for _, tc := range []struct {
		role string
		want userAccess
	}{
		{
			role: "manage-users",
			want: userAccess{
				ManageGroupMembership: true, ResetPassword: true, View: true,
				MapRoles: true, Impersonate: false, Manage: true,
			},
		},
		{
			role: "view-users",
			want: userAccess{View: true},
		},
		{
			// impersonation alone does not open the read at all - the caller
			// gets 403 - but if it ever reaches the representation, this is
			// the flag it sets and the only one.
			role: "impersonation",
			want: userAccess{Impersonate: true},
		},
		{
			role: "view-clients",
			want: userAccess{},
		},
	} {
		t.Run(tc.role, func(t *testing.T) {
			got := userAccessFor(&caller{adminGrants: map[string]bool{tc.role: true}})
			if got != tc.want {
				t.Fatalf("caller holding %q:\n want %+v\n got  %+v", tc.role, tc.want, got)
			}
		})
	}
}

// The user being read must not influence the block. Reading a disabled user
// with a different ID through the same caller gives the same permissions.
func TestUserAccessIgnoresTheUserBeingRead(t *testing.T) {
	h, s, realm := newServer(t)
	viewer := createUserWithPassword(t, s, realm, "viewer", "viewer")
	grantClientRole(t, s, realm, viewer, "view-users")
	target := createUserWithPassword(t, s, realm, "target", "target")

	for _, id := range []string{viewer.ID, target.ID} {
		w := get(t, h, "/admin/realms/master/users/"+id, tokenFor(t, h, "viewer", "viewer"))
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
		}
		var rep struct {
			Access userAccess `json:"access"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if rep.Access != (userAccess{View: true}) {
			t.Fatalf("reading %s: want the caller's own permissions, got %+v", id, rep.Access)
		}
	}
}

// query-users opens the listing and the count and not the single read.
// Measured: 200, 200, 403.
func TestQueryUsersOpensTheListingButNotTheRead(t *testing.T) {
	h, s, realm := newServer(t)
	user := createUserWithPassword(t, s, realm, "querier", "querier")
	grantClientRole(t, s, realm, user, "query-users")
	tok := tokenFor(t, h, "querier", "querier")

	for _, path := range []string{"/admin/realms/master/users", "/admin/realms/master/users/count"} {
		if w := get(t, h, path, tok); w.Code != http.StatusOK {
			t.Fatalf("%s: want 200 for query-users, got %d: %s", path, w.Code, w.Body)
		}
	}
	if w := get(t, h, "/admin/realms/master/users/"+user.ID, tok); w.Code != http.StatusForbidden {
		t.Fatalf("single read: want 403 for query-users, got %d: %s", w.Code, w.Body)
	}
}

// The whole filter set, applied to one user. The four named filters are
// case-insensitive substrings and exact=true turns them into equality; search
// is a prefix across all four fields and ignores exact. Every search term
// below happens to be a prefix - which is exactly how Task 13 came to record
// them as substrings, so TestSearchIsAPrefixAndNamedFiltersAreSubstrings
// exists to try the terms that are not.
func TestUserFiltersMatchTheMeasuredSemantics(t *testing.T) {
	u := &model.User{
		Username: "full-user", Email: "full@example.com",
		FirstName: "Ada", LastName: "Lovelace",
	}
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"username=full", true},             // substring
		{"username=FULL-USER", true},        // case-insensitive
		{"username=full&exact=true", false}, // exact kills the substring
		{"username=FULL-USER&exact=true", true},
		{"search=Ada", true},      // firstName
		{"search=Lovelace", true}, // lastName
		{"search=full@example.com", true},
		{"search=ADMI", false},
		{"search=full&exact=true", true}, // exact does not apply to search
		{"email=full@example.com", true},
		{"firstName=Ada&lastName=Turing", false}, // every named field must match
	} {
		t.Run(tc.query, func(t *testing.T) {
			q := parseQuery(t, tc.query)
			exact := len(q["exact"]) > 0 && q["exact"][0] == "true"
			if got := matchesFilters(u, q, exact); got != tc.want {
				t.Fatalf("%q: want %v, got %v", tc.query, tc.want, got)
			}
		})
	}
}

// search is a prefix and the named filters are substrings. The two families
// were measured separately and they disagree; Task 13 shipped them as one.
func TestSearchIsAPrefixAndNamedFiltersAreSubstrings(t *testing.T) {
	for _, tc := range []struct {
		value, term string
		want        bool
	}{
		{"full-user", "full", true},        // a bare term is a prefix
		{"full-user", "user", false},       // so a mid-string term finds nothing
		{"Lovelace", "ovelace", false},     // nor is it a suffix
		{"full-user", "user*", false},      // an explicit * is the whole pattern
		{"full-user", "*user", true},       //
		{"full-user", "*ull*", true},       //
		{"full-user", `"full-user"`, true}, // quotes mean equality
		{"full-user", `"full"`, false},     //
		{"full-user", "FULL", true},        // case-insensitive throughout
		{"full-user", "*", true},           //

		// **The row the ten above could not decide**, measured 2026-09-01 on a
		// user named `xabbcx`: `*bbc` matches, although `xabbcx` does not end
		// in `bbc`. So the pattern gets an implied trailing wildcard rather
		// than being anchored at its tail, and every row above is explained by
		// both readings - which is why the wrong one stood for a week.
		{"xabbcx", "*bbc", true},
		{"xabbcx", "*bbcx", true},
		{"xabbcx", "abb", false}, // the implied wildcard is only at the end
		{"abcz", "*z", true},
		{"abcz", "z", false}, // a bare term is still a prefix
	} {
		t.Run(tc.term, func(t *testing.T) {
			if got := matchesSearch(tc.value, tc.term); got != tc.want {
				t.Fatalf("search %q against %q: want %v, got %v", tc.term, tc.value, tc.want, got)
			}
		})
	}

	// The named filters take the same mid-string term and do match.
	if !matches("full-user", "ull", false) {
		t.Fatal("username=ull must find full-user; the named filters are substrings")
	}
	// And * is a literal there, not a wildcard.
	if matches("full-user", "*user", false) {
		t.Fatal("username=*user must find nothing; * is not a wildcard on the named filters")
	}
}

// Measured: a create naming Probe-UPPER answers 201 and the user reads back as
// probe-upper. No conformance case covers it - the fixtures all use lowercase
// usernames, and a case that did not would have to assert a value the create
// response does not carry.
func TestCreateLowercasesTheUsername(t *testing.T) {
	h, s, realm := newServer(t)

	w := postJSON(t, h, "/admin/realms/master/users",
		`{"username":"Probe-UPPER","enabled":true}`, tokenFor(t, h, "admin", "admin"))
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body)
	}

	if _, err := s.Users().ByUsername(t.Context(), realm.ID, "probe-upper"); err != nil {
		t.Fatalf("the username was not lowercased: %v", err)
	}
}

// Measured: a create carrying attributes answers 201 and the user reads back
// with none, because unmanaged attributes are off by default. Storing them
// would make Gloak remember what Keycloak forgets.
func TestCreateDropsAttributes(t *testing.T) {
	h, s, realm := newServer(t)

	w := postJSON(t, h, "/admin/realms/master/users",
		`{"username":"attributed","enabled":true,"attributes":{"dept":["eng"]}}`,
		tokenFor(t, h, "admin", "admin"))
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body)
	}

	u, err := s.Users().ByUsername(t.Context(), realm.ID, "attributed")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	if len(u.Attributes) != 0 {
		t.Fatalf("want the attributes dropped, got %v", u.Attributes)
	}
}

// The username does not change through PUT - measured, the master realm has
// username editing off - but a PUT naming somebody else's username still
// answers 409, so the conflict check runs before the change is discarded.
func TestUpdateKeepsTheUsernameButStillReportsAConflict(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := t.Context()
	tok := tokenFor(t, h, "admin", "admin")
	for _, name := range []string{"first-user", "second-user"} {
		if w := postJSON(t, h, "/admin/realms/master/users",
			`{"username":"`+name+`","enabled":true}`, tok); w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body)
		}
	}
	first, err := s.Users().ByUsername(ctx, realm.ID, "first-user")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}

	free := putJSON(t, h, "/admin/realms/master/users/"+first.ID, `{"username":"nobody-holds-this"}`, tok)
	if free.Code != http.StatusNoContent {
		t.Fatalf("renaming to a free username: want 204, got %d: %s", free.Code, free.Body)
	}
	again, err := s.Users().ByUsername(ctx, realm.ID, "first-user")
	if err != nil {
		t.Fatalf("the username changed: %v", err)
	}
	if again.Username != "first-user" {
		t.Fatalf("want the username left alone, got %q", again.Username)
	}

	taken := putJSON(t, h, "/admin/realms/master/users/"+first.ID, `{"username":"second-user"}`, tok)
	if taken.Code != http.StatusConflict {
		t.Fatalf("renaming to a taken username: want 409, got %d: %s", taken.Code, taken.Body)
	}
	if got := taken.Body.String(); got != `{"errorMessage":"User exists with same username"}` {
		t.Fatalf("unexpected body: %s", got)
	}
}

// userFromPath is the one place a {userID} becomes a user. The 404 body is
// measured and shared by every endpoint that takes one.
func TestUserFromPathWritesTheMeasuredNotFound(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/users/00000000-0000-0000-0000-000000000000", admin)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); body != `{"error":"User not found"}` {
		t.Fatalf("unexpected 404 body: %s", body)
	}
}

func postJSON(t *testing.T, h http.Handler, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	return sendJSON(t, h, http.MethodPost, path, body, token)
}

func putJSON(t *testing.T, h http.Handler, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	return sendJSON(t, h, http.MethodPut, path, body, token)
}

func sendJSON(t *testing.T, h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func parseQuery(t *testing.T, raw string) map[string][]string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://x/?"+raw, nil)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return req.URL.Query()
}

// The logout's visible effect beyond its 204: it stamps the user's notBefore
// with the moment it happened. No conformance case reads a logged-out user's
// representation, because the stamp differs between the reference container
// and Gloak on every run.
func TestLogoutStampsNotBefore(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := t.Context()
	tok := tokenFor(t, h, "admin", "admin")
	if w := postJSON(t, h, "/admin/realms/master/users",
		`{"username":"session-holder","enabled":true}`, tok); w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	user, err := s.Users().ByUsername(ctx, realm.ID, "session-holder")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	if user.NotBefore != 0 {
		t.Fatalf("precondition: want notBefore 0 on a fresh user, got %d", user.NotBefore)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/realms/master/users/"+user.ID+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout: want 204, got %d: %s", w.Code, w.Body)
	}

	after, err := s.Users().ByUsername(ctx, realm.ID, "session-holder")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	if after.NotBefore == 0 {
		t.Fatal("the logout left notBefore at 0")
	}
}

// TestCreatedUsersGetTheRealmDefaultRoles covers both creation paths at once,
// because both were measured landing in the same place: a user created through
// this API and the account behind a service-account client each hold
// default-roles-master and nothing else directly, and each expands to the same
// six effective roles.
//
// It asserts the expansion rather than the assignment, since the assignment on
// its own is worth nothing: what a token carries is what
// default-roles-master reaches.
func TestCreatedUsersGetTheRealmDefaultRoles(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	admin := tokenFor(t, h, "admin", "admin")

	if w := postJSON(t, h, "/admin/realms/master/users",
		`{"username":"probe-default","enabled":true}`, admin); w.Code != http.StatusCreated {
		t.Fatalf("create user: %d %s", w.Code, w.Body)
	}
	if w := postJSON(t, h, "/admin/realms/master/clients",
		`{"clientId":"probe-sa","enabled":true,"serviceAccountsEnabled":true}`, admin); w.Code != http.StatusCreated {
		t.Fatalf("create client: %d %s", w.Code, w.Body)
	}

	// The measured set: two realm roles from default-roles-master's own
	// composites, the composite itself, and the three account roles that
	// manage-account and view-profile expand to.
	want := []string{
		"default-roles-master", "manage-account", "manage-account-links",
		"offline_access", "uma_authorization", "view-profile",
	}
	for _, username := range []string{"probe-default", "service-account-probe-sa"} {
		t.Run(username, func(t *testing.T) {
			user, err := s.Users().ByUsername(ctx, realm.ID, username)
			if err != nil {
				t.Fatalf("ByUsername(%s): %v", username, err)
			}
			direct, err := s.Roles().ListUserRoles(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListUserRoles: %v", err)
			}
			if len(direct) != 1 || direct[0].Name != "default-roles-master" {
				t.Fatalf("want exactly default-roles-master assigned directly, got %v", roleNames(direct))
			}

			effective, err := roles.Effective(ctx, s.Roles(), user.ID)
			if err != nil {
				t.Fatalf("Effective: %v", err)
			}
			got := roleNames(effective)
			sort.Strings(got)
			if !slices.Equal(got, want) {
				t.Fatalf("effective roles:\nwant %v\ngot  %v", want, got)
			}
		})
	}
}

func roleNames(rs []*model.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return out
}

// The coarse gate is usersReadRoles, and it is wider than any route in the
// family. Measured 2026-08-28 on a live 26.7.1 across all 18 routes naming a
// {userID}: view-users, query-users and manage-users all get 404 "User not
// found" for a subject that does not exist, whatever the route, and every role
// outside those three gets 403.
//
// query-users is the row that matters. It opens **no** route in the family -
// not the read, not a write, not one role mapping - and still learns that the
// user is absent. A single-stage guard cannot produce that: name query-users
// and the real-subject 403s break, leave it out and these 404s do.
func TestAMissingSubjectIs404ToTheWholeUsersFamily(t *testing.T) {
	h, s, realm := newServer(t)
	missing := "/admin/realms/master/users/00000000-0000-0000-0000-000000000000"
	cred := missing + "/credentials/00000000-0000-0000-0000-000000000000"
	routes := []struct{ method, path string }{
		{http.MethodGet, missing},
		{http.MethodPut, missing},
		{http.MethodDelete, missing},
		{http.MethodGet, missing + "/credentials"},
		{http.MethodPut, missing + "/reset-password"},
		{http.MethodDelete, cred},
		{http.MethodPut, cred + "/userLabel"},
		{http.MethodPost, cred + "/moveToFirst"},
		{http.MethodPut, missing + "/disable-credential-types"},
		{http.MethodPost, missing + "/logout"},
		{http.MethodGet, missing + "/role-mappings"},
		{http.MethodGet, missing + "/role-mappings/realm"},
		{http.MethodGet, missing + "/role-mappings/realm/available"},
		{http.MethodGet, missing + "/role-mappings/realm/composite"},
		{http.MethodPost, missing + "/role-mappings/realm"},
		{http.MethodDelete, missing + "/role-mappings/realm"},
	}
	for _, role := range usersReadRoles {
		tok := tokenForRole(t, h, s, realm, role)
		for _, rt := range routes {
			w := sendJSON(t, h, rt.method, rt.path, `[]`, tok)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s as %s %s: want 404, got %d: %s", role, rt.method, rt.path, w.Code, w.Body)
			}
		}
	}
	// The control: outside the coarse gate the subject is never reached, so
	// the same requests are 403 and say nothing about the user.
	for _, role := range []string{"view-clients", "manage-clients", "view-realm", "manage-realm"} {
		tok := tokenForRole(t, h, s, realm, role)
		for _, rt := range routes {
			w := sendJSON(t, h, rt.method, rt.path, `[]`, tok)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s as %s %s: want 403, got %d: %s", role, rt.method, rt.path, w.Code, w.Body)
			}
		}
	}
}

// The user listing is filtered by what the caller may view and the count is
// not, measured on the same realm at the same moment. The two endpoints
// disagreeing is the contract.
func TestTheUserListingIsFilteredAndTheCountIsNot(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	for _, u := range []string{"probe-a", "probe-b"} {
		postJSON(t, h, "/admin/realms/master/users", `{"username":"`+u+`","enabled":true}`, admin)
	}
	full := len(listUsernames(t, h, admin))
	if full < 3 {
		t.Fatalf("only %d users, so an empty list would not be distinguishable", full)
	}

	for _, tc := range []struct {
		role      string
		seesEvery bool
	}{
		{"view-users", true},
		{"manage-users", true},
		{"query-users", false},
	} {
		tok := tokenForRole(t, h, s, realm, tc.role)
		// Each caller is a user, so the realm grows as this loop runs. Both
		// numbers below are taken against the administrator at the same
		// moment rather than against the count read before the loop.
		want := 0
		if tc.seesEvery {
			want = len(listUsernames(t, h, admin))
		}
		if got := len(listUsernames(t, h, tok)); got != want {
			t.Errorf("%s sees %d users in the listing, want %d", tc.role, got, want)
		}
		w := get(t, h, "/admin/realms/master/users/count", tok)
		if w.Code != http.StatusOK {
			t.Errorf("%s on the count: %d %s", tc.role, w.Code, w.Body)
			continue
		}
		// The count is unfiltered for all three, including the caller whose
		// listing is empty. It grows as this test adds callers, so it is
		// compared against a fresh read rather than against `full`.
		if want := len(listUsernames(t, h, admin)); w.Body.String() != fmt.Sprint(want) {
			t.Errorf("%s counts %s, want the unfiltered %d", tc.role, w.Body.String(), want)
		}
	}
}

// The client listing admits three roles and shows two of them everything.
// Measured 2026-08-28: it took view-clients alone, so it refused query-clients,
// which Keycloak admits and empties, and manage-clients, which Keycloak serves
// in full. manage-clients is not composite over view-clients, so nothing in the
// role graph predicted it.
func TestTheClientListingAdmitsThreeRolesAndFiltersOne(t *testing.T) {
	h, s, realm := newServer(t)
	full := len(listClientIDs(t, h, tokenFor(t, h, "admin", "admin")))
	if full == 0 {
		t.Fatal("no clients, so an empty list would not be distinguishable")
	}
	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-clients", full},
		{"manage-clients", full},
		{"query-clients", 0},
	} {
		if got := len(listClientIDs(t, h, tokenForRole(t, h, s, realm, tc.role))); got != tc.want {
			t.Errorf("%s sees %d clients, want %d", tc.role, got, tc.want)
		}
	}
	for _, role := range []string{"view-users", "manage-users", "view-realm"} {
		w := get(t, h, "/admin/realms/master/clients", tokenForRole(t, h, s, realm, role))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s on the client listing: want 403, got %d", role, w.Code)
		}
	}
}

func listUsernames(t *testing.T, h http.Handler, token string) []string {
	t.Helper()
	w := get(t, h, "/admin/realms/master/users", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list users: %d %s", w.Code, w.Body)
	}
	var out []struct{ Username string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse user listing: %v", err)
	}
	names := make([]string, 0, len(out))
	for _, u := range out {
		names = append(names, u.Username)
	}
	return names
}

func listClientIDs(t *testing.T, h http.Handler, token string) []string {
	t.Helper()
	w := get(t, h, "/admin/realms/master/clients", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list clients: %d %s", w.Code, w.Body)
	}
	var out []struct {
		ClientID string `json:"clientId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse client listing: %v", err)
	}
	ids := make([]string, 0, len(out))
	for _, c := range out {
		ids = append(ids, c.ClientID)
	}
	return ids
}
