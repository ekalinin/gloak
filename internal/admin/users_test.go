package admin

import (
	"encoding/json"
	"net/http"
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

// The filters are measured on a live Keycloak: case-insensitive substrings,
// with exact=true turning the four field filters into equality and leaving
// search alone.
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

func parseQuery(t *testing.T, raw string) map[string][]string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://x/?"+raw, nil)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return req.URL.Query()
}
