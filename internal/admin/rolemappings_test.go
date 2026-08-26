package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The three realm-mapping reads answer three different questions, and the
// difference is the whole point of the endpoints. Measured on the bootstrapped
// administrator, which holds admin and default-roles-master directly.
func TestRealmMappingReadsAnswerThreeDifferentQuestions(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"

	direct := mappingNames(t, h, base, admin)
	if want := []string{"admin", "default-roles-master"}; !slices.Equal(direct, want) {
		t.Fatalf("direct: want %v, got %v", want, direct)
	}

	// The transitive expansion: admin is composite over create-realm, and
	// default-roles-master over offline_access and uma_authorization.
	composite := mappingNames(t, h, base+"/composite", admin)
	want := []string{"admin", "create-realm", "default-roles-master", "offline_access", "uma_authorization"}
	if !slices.Equal(composite, want) {
		t.Fatalf("composite: want %v, got %v", want, composite)
	}

	// available is "not assigned **directly**", which is not the complement of
	// composite. create-realm appears in both: the administrator effectively
	// holds it through admin, and it is still offered because it is not
	// assigned directly. Measured, and the single most misreadable of the three.
	available := mappingNames(t, h, base+"/available", admin)
	if slices.Contains(available, "admin") {
		t.Fatal("available offered a directly assigned role")
	}
	if !slices.Contains(available, "create-realm") {
		t.Fatal("available dropped a role reachable through a composite; " +
			"it is the complement of direct, not of composite")
	}
}

// A client role never appears in a realm-mapping listing, whichever of the
// three asks. The administrator holds none directly, so the direct list is the
// weakest check; its composite expansion carries all 22 master-realm roles and
// the listing must still show only the five realm ones.
func TestRealmMappingReadsExcludeClientRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"

	// view-users is a master-realm client role the administrator reaches
	// through admin, so it is in the effective set and must not be listed.
	for _, path := range []string{base, base + "/composite", base + "/available"} {
		if got := mappingNames(t, h, path, admin); slices.Contains(got, "view-users") {
			t.Fatalf("%s leaked a client role: %v", path, got)
		}
	}
}

// The guard is view-users **or** manage-users, and nothing else - measured
// against a live 26.7.1 with one user per role and a fresh token minted
// immediately before each call, on two different subjects.
//
// manage-users is not composite over view-users - it has no children at all -
// so it has to be admitted here rather than reached through view-users. The
// brief predicted view-users alone, which would refuse a manage-users caller
// Keycloak admits.
//
// query-users is the surprise in the other direction: it opens the user
// listing and the count (see usersReadRoles) and is 403 on all three of these,
// so this family cannot reuse that slice.
func TestRealmMappingReadsNeedViewOrManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"
	paths := []string{base, base + "/available", base + "/composite"}

	for _, role := range []string{"view-users", "manage-users"} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusOK {
				t.Errorf("%s as %s: want 200, got %d", path, role, got)
			}
		}
	}
	for _, role := range []string{
		"query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", path, role, got)
			}
		}
	}
}

// briefRepresentation is honoured by **composite alone**. Measured on a realm
// role carrying attributes and assigned directly: `.../realm/composite` grows
// an attributes key when the parameter is false, and `.../realm` and
// `.../realm/available` ignore the parameter entirely and never carry one.
//
// Three sibling endpoints, two behaviours. The brief hardcoded the brief shape
// for all three, which is right twice out of three.
func TestOnlyCompositeRealmMappingsHonourBriefRepresentation(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-attr","attributes":{"probe":["v1","v2"]}}`, admin)
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-subject","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-subject")
	assignRole(t, s, realm, uid, "probe-attr")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"

	// composite honours it, and carries the role's real attributes.
	full := mappingReps(t, h, base+"/composite?briefRepresentation=false", admin)
	rep, ok := repNamed(full, "probe-attr")
	if !ok {
		t.Fatalf("composite lost probe-attr: %v", full)
	}
	if rep.Attributes == nil {
		t.Fatal("composite?briefRepresentation=false: no attributes key")
	}
	if got := (*rep.Attributes)["probe"]; !slices.Equal(got, []string{"v1", "v2"}) {
		t.Fatalf("composite attributes: want [v1 v2], got %v", got)
	}
	// and defaults to the brief shape when the parameter is absent.
	brief := mappingReps(t, h, base+"/composite", admin)
	if rep, _ := repNamed(brief, "probe-attr"); rep.Attributes != nil {
		t.Fatalf("composite defaulted to the full shape: %v", *rep.Attributes)
	}

	// direct and available ignore it: no attributes key either way.
	for _, path := range []string{base, base + "/available"} {
		for _, q := range []string{"", "?briefRepresentation=false"} {
			for _, rep := range mappingReps(t, h, path+q, admin) {
				if rep.Attributes != nil {
					t.Errorf("%s%s: %s carries attributes; measured absent",
						path, q, rep.Name)
				}
			}
		}
	}
}

// The round trip: POST puts a realm role on a user, DELETE takes it off, and
// both answer 204.
//
// The 204 carries X-Frame-Options because these requests send an
// application/json Content-Type - measured, and the reason the DELETE goes
// through sendJSON rather than the bodyless do(). A bodyless delete on this
// same path would be observably different.
func TestAssignAndRemoveRealmMappings(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)

	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	w := postJSON(t, h, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("assign 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); !slices.Contains(got, "offline_access") {
		t.Fatalf("assign did not stick: %v", got)
	}

	w = sendJSON(t, h, http.MethodDelete, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("remove 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); slices.Contains(got, "offline_access") {
		t.Fatalf("remove did not stick: %v", got)
	}
}

// Both verbs validate the whole batch before applying any of it: one bad id
// and nothing in the request lands.
//
// Measured on both verbs and in both id orders rather than carried over from
// POST .../composites, which behaves the same way. The two happen to agree, but
// the composite writes were separately measured **disagreeing** with each other
// on the per-child manage check, so agreement between neighbours is not
// something this file assumes.
func TestRealmMappingWritesAreAllOrNothing(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	good := `{"id":"` + offline.ID + `","name":"offline_access"}`
	bad := `{"id":"00000000-0000-0000-0000-000000000000","name":"nope"}`

	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := postJSON(t, h, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("assign %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		if got := mappingNames(t, h, base, admin); slices.Contains(got, "offline_access") {
			t.Fatalf("assign %s applied the valid half: %v", body, got)
		}
	}

	// The remove side, with the valid half genuinely assigned first so that a
	// non-atomic implementation would have something to take away.
	postJSON(t, h, base, "["+good+"]", admin)
	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := sendJSON(t, h, http.MethodDelete, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("remove %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		if got := mappingNames(t, h, base, admin); !slices.Contains(got, "offline_access") {
			t.Fatalf("remove %s applied the valid half: %v", body, got)
		}
	}
}

// A client role sent to the **realm** endpoint is 404 "Role not found" on both
// verbs - a different message from the roles endpoints' "Could not find role"
// two paths away, and from the composite batch's "Could not find composite
// role". Measured; it is the sixth of eight not-found spellings.
//
// The id used here resolves to a role that exists. It is refused for being a
// client role, not for being unknown.
func TestRealmMappingWritesRejectAClientRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	mr := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)
	body := `[{"id":"` + viewUsers.ID + `","name":"view-users"}]`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		w := sendJSON(t, h, method, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d: %s", method, w.Code, w.Body)
			continue
		}
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("%s: unexpected body: %s", method, got)
		}
	}
}

// The writes take manage-users **alone**, which is narrower than the reads next
// door: view-users opens all three reads and neither write.
//
// Measured against a live 26.7.1 with one user per role and a fresh token
// minted immediately before each call, on both verbs. The read sweep is
// deliberately not reused - the previous half of this sub-project twice
// extended a rule measured on one verb to its neighbour and had to revert both
// times - and this is the case where reusing it would have been wrong.
//
// The bodies below name a role that exists, so a 403 here is the route guard
// and not the caller-relative filter recorded under "A mapping write **is**
// filtered by what the caller may grant"; the same callers were measured
// getting 403 for an empty array too, which has nothing to filter.
func TestRealmMappingWritesNeedManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	methods := []string{http.MethodPost, http.MethodDelete}

	token := tokenForRole(t, h, s, realm, "manage-users")
	for _, method := range methods {
		if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusNoContent {
			t.Errorf("%s as manage-users: want 204, got %d", method, got)
		}
	}
	for _, role := range []string{
		"view-users", "query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, method := range methods {
			if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", method, role, got)
			}
		}
	}
}

// Both verbs are idempotent and neither reports a conflict: assigning a role
// the user already holds is 204, and removing one it does not hold is 204.
// Measured - not 409 and not 404, although the store reports ErrConflict and
// ErrNotFound respectively for exactly these two cases.
//
// An empty array is 204 as well, with nothing to validate or apply.
func TestRealmMappingWritesAreIdempotent(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`

	postJSON(t, h, base, body, admin)
	if got := postJSON(t, h, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("assigning twice: want 204, got %d", got)
	}
	sendJSON(t, h, http.MethodDelete, base, body, admin)
	if got := sendJSON(t, h, http.MethodDelete, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("removing what is not held: want 204, got %d", got)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		if got := sendJSON(t, h, method, base, `[]`, admin).Code; got != http.StatusNoContent {
			t.Errorf("%s []: want 204, got %d", method, got)
		}
	}
}

// The array-taking endpoints answer `unknown_error`, where POST /users answers
// `invalid_request` for the same "Cannot parse the JSON" description.
//
// Measured 2026-08-26 on both verbs of this endpoint and on POST
// .../composites, with a malformed body and a well-formed non-array body, all
// four giving the same answer - and POST /users re-measured alongside to
// confirm the difference is per endpoint rather than a version change. That
// correction lives in decodeRoleList, which both families share.
func TestRealmMappingWritesRejectANonArrayBody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	want := `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, body := range []string{`{"id":"x"}`, `{not json`} {
			w := sendJSON(t, h, method, base, body, admin)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s: want 400, got %d", method, body, w.Code)
				continue
			}
			if got := w.Body.String(); got != want {
				t.Errorf("%s %s: want %s, got %s", method, body, want, got)
			}
		}
	}
}

// mappingNames reads a role-mapping listing and returns the names, sorted.
func mappingNames(t *testing.T, h http.Handler, path, token string) []string {
	t.Helper()
	names := make([]string, 0)
	for _, r := range mappingReps(t, h, path, token) {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// mappingReps reads a role-mapping listing whole, for the assertions that care
// about the shape rather than the membership.
func mappingReps(t *testing.T, h http.Handler, path, token string) []roleRepresentation {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var reps []roleRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &reps); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return reps
}

func repNamed(reps []roleRepresentation, name string) (roleRepresentation, bool) {
	for _, r := range reps {
		if r.Name == name {
			return r, true
		}
	}
	return roleRepresentation{}, false
}

// userID is clientUUID's shape for a user: the store lookup the API cannot do
// yet, since a username is not a path segment anywhere.
func userID(t *testing.T, s store.Store, realm *model.Realm, username string) string {
	t.Helper()
	u, err := s.Users().ByUsername(context.Background(), realm.ID, username)
	if err != nil {
		t.Fatalf("ByUsername(%s): %v", username, err)
	}
	return u.ID
}

// assignRole gives a user a realm role through the store. The API can do this
// now, but the read tests above must not depend on the write path: a broken
// POST would otherwise make them fail for a reason that has nothing to do with
// what they assert.
func assignRole(t *testing.T, s store.Store, realm *model.Realm, userID, role string) {
	t.Helper()
	ctx := context.Background()
	r, err := s.Roles().ByName(ctx, realm.ID, "", role)
	if err != nil {
		t.Fatalf("ByName(%s): %v", role, err)
	}
	if err := s.Roles().AssignToUser(ctx, userID, r.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
}
