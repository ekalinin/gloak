package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
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
			got := userAccessFor(&caller{roles: map[string]bool{tc.role: true}})
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
