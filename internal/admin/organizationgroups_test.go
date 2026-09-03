package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// orgWithGroups builds a realm with organizations on, one organization and a
// group under it, and returns the admin token, the organization id, the hidden
// root's id and the group's id.
//
// **The ids and the names are deliberately different strings.** Five mutation
// survivors in four cuts were tests using one value for two things, so the
// group is named `gp-alpha` while its member is `probe-omega` with the e-mail
// `aaa@…`: nothing here can compare equal by accident.
func orgWithGroups(t *testing.T, h http.Handler) (token, orgID, rootID, groupID string) {
	t.Helper()
	token = tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, token, "master")
	orgID = createOrg(t, h, token, `{"name":"gp-org","alias":"gp-org-alias"}`)

	w := send(t, h, http.MethodPost,
		"/admin/realms/master/organizations/"+orgID+"/groups", token, `{"name":"gp-alpha"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating the group: %d %s", w.Code, w.Body)
	}
	var created struct {
		ID       string `json:"id"`
		ParentID string `json:"parentId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding the create: %v", err)
	}
	return token, orgID, created.ParentID, created.ID
}

// TestOrganizationGroupRoutesRegister is the guard on F153's hazard.
//
// `.../groups/group-by-path/{path...}` cannot be registered beside the deeper
// patterns under `{groupID}`: `/groups/group-by-path/children` matches both and
// neither is a strict subset of the other, so `net/http` panics at
// registration. Eight patterns conflict with it. The literal is read inside
// readOrganizationGroup instead, and this test is what says the two really do
// end up in different handlers - building the router at all is half of it, and
// the other half is that both concrete paths answer.
func TestOrganizationGroupRoutesRegister(t *testing.T) {
	h, _, _ := newServer(t)
	token, orgID, _, groupID := orgWithGroups(t, h)
	base := "/admin/realms/master/organizations/" + orgID + "/groups"

	// A child, so the deeper path that collides with the wildcard is real.
	w := send(t, h, http.MethodPost, base+"/"+groupID+"/children", token, `{"name":"gp-kid"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating the child: %d %s", w.Code, w.Body)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{base + "/group-by-path/gp-alpha", `"name":"gp-alpha"`},
		{base + "/group-by-path/gp-alpha/gp-kid", `"name":"gp-kid"`},
		{base + "/" + groupID, `"name":"gp-alpha"`},
		{base + "/" + groupID + "/children", `"name":"gp-kid"`},
	} {
		w := get(t, h, tc.path, token)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: got %d %s, want 200 containing %s", tc.path, w.Code, w.Body, tc.want)
		}
	}

	// The literal is not a group id: a group-by-path that resolves to nothing
	// answers the path family's 404 and not the group family's.
	w = get(t, h, base+"/group-by-path/nosuchgroup", token)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"error":"Group path does not exist"}` {
		t.Errorf("unknown path: got %d %s", w.Code, got)
	}
}

// TestOrganizationGroupPathDropsTheHiddenRoot is the one rule the realm family's
// groupPath cannot express.
//
// The root's own path is its name, which is the organization's id; a group
// directly under it is `/gp-alpha` and **not** `/<org id>/gp-alpha`; a child of
// that is `/gp-alpha/gp-kid`. A shared walk answers the organization id as a
// first segment on every group there is.
func TestOrganizationGroupPathDropsTheHiddenRoot(t *testing.T) {
	h, _, _ := newServer(t)
	token, orgID, rootID, groupID := orgWithGroups(t, h)
	base := "/admin/realms/master/organizations/" + orgID + "/groups"

	w := send(t, h, http.MethodPost, base+"/"+groupID+"/children", token, `{"name":"gp-kid"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating the child: %d %s", w.Code, w.Body)
	}
	var kid struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &kid); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if kid.Path != "/gp-alpha/gp-kid" {
		t.Errorf("child path: got %q, want /gp-alpha/gp-kid", kid.Path)
	}

	for _, tc := range []struct{ id, want string }{
		{rootID, "/" + orgID},
		{groupID, "/gp-alpha"},
	} {
		w := get(t, h, base+"/"+tc.id, token)
		var g struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
			t.Fatalf("decoding %s: %v", tc.id, err)
		}
		if g.Path != tc.want {
			t.Errorf("path of %s: got %q, want %q", tc.id, g.Path, tc.want)
		}
	}
}

// TestOrganizationGroupsAreInvisibleToTheRealmGroupFamily is the other half of
// the column's meaning.
//
// `GET /groups` and `GET /groups/count` do not see an organization group, and
// every realm route naming one answers one 400 sentence. **And one realm route
// does see it and it is a count**: `GET /users/{id}/groups` filters them out
// while `GET /users/{id}/groups/count` beside it counts them - one membership,
// two routes, two answers.
func TestOrganizationGroupsAreInvisibleToTheRealmGroupFamily(t *testing.T) {
	h, _, _ := newServer(t)
	token, orgID, _, groupID := orgWithGroups(t, h)
	base := "/admin/realms/master/organizations/" + orgID + "/groups"

	w := get(t, h, "/admin/realms/master/groups", token)
	if body := strings.TrimSpace(w.Body.String()); body != "[]" {
		t.Errorf("realm group listing: got %s, want []", body)
	}
	w = get(t, h, "/admin/realms/master/groups/count", token)
	if body := strings.TrimSpace(w.Body.String()); body != `{"count":0}` {
		t.Errorf("realm group count: got %s, want {\"count\":0}", body)
	}

	// The member, and the two realm reads that disagree about it.
	user := createUserReturningID(t, h, token, "probe-omega", "aaa@gp-groups.example.com")
	if w := send(t, h, http.MethodPost,
		"/admin/realms/master/organizations/"+orgID+"/members", token,
		`"`+user+`"`); w.Code != http.StatusCreated {
		t.Fatalf("adding the member: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPut, base+"/"+groupID+"/members/"+user, token, ""); w.Code != http.StatusNoContent {
		t.Fatalf("joining the group: %d %s", w.Code, w.Body)
	}

	w = get(t, h, "/admin/realms/master/users/"+user+"/groups", token)
	if body := strings.TrimSpace(w.Body.String()); body != "[]" {
		t.Errorf("user groups: got %s, want []", body)
	}
	w = get(t, h, "/admin/realms/master/users/"+user+"/groups/count", token)
	if body := strings.TrimSpace(w.Body.String()); body != `{"count":1}` {
		t.Errorf("user group count: got %s, want {\"count\":1}", body)
	}

	// And the member's organization groups, which were an unconditional [] on
	// this route until this cut.
	w = get(t, h, "/admin/realms/master/organizations/"+orgID+"/members/"+user+"/groups", token)
	if !strings.Contains(w.Body.String(), `"name":"gp-alpha"`) {
		t.Errorf("member groups: got %s, want the group", w.Body)
	}
}

// TestOrganizationGroupMemberWritesDisagreeAboutTheRepeat pins the inversion.
//
// `PUT /users/{id}/groups/{gid}` on the realm family is idempotent, measured
// 204 twice; this one answers 409 on the repeat. And the delete is idempotent
// on both. So the two verbs of one pair follow two different rules, and only
// one of them matches the realm family.
func TestOrganizationGroupMemberWritesDisagreeAboutTheRepeat(t *testing.T) {
	h, _, _ := newServer(t)
	token, orgID, _, groupID := orgWithGroups(t, h)
	base := "/admin/realms/master/organizations/" + orgID + "/groups/" + groupID + "/members/"

	user := createUserReturningID(t, h, token, "probe-omega", "aaa@gp-repeat.example.com")

	// A user who is not a member of the **organization** is a 400 and not a
	// 404: the group membership narrows the organization membership.
	w := send(t, h, http.MethodPut, base+user, token, "")
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusBadRequest ||
		got != `{"errorMessage":"User is not member of the organization"}` {
		t.Fatalf("joining as a non-member: got %d %s", w.Code, got)
	}

	if w := send(t, h, http.MethodPost,
		"/admin/realms/master/organizations/"+orgID+"/members", token,
		`"`+user+`"`); w.Code != http.StatusCreated {
		t.Fatalf("adding the member: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPut, base+user, token, ""); w.Code != http.StatusNoContent {
		t.Fatalf("first join: %d %s", w.Code, w.Body)
	}
	w = send(t, h, http.MethodPut, base+user, token, "")
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusConflict ||
		got != `{"errorMessage":"User is already a member of the group"}` {
		t.Errorf("second join: got %d %s, want 409", w.Code, got)
	}

	// Both deletes are 204, and so is one for a user who was never in it.
	for i := 0; i < 2; i++ {
		if w := send(t, h, http.MethodDelete, base+user, token, ""); w.Code != http.StatusNoContent {
			t.Errorf("delete %d: got %d %s", i, w.Code, w.Body)
		}
	}
}

// TestOrganizationGroupCreateMovesOnAnID pins the half of both creates that a
// body's `id` selects, and the three refusals around it.
//
// The move's own 404 is the **realm** family's `Could not find group by id`,
// where every other 404 on these routes is `Group does not exist`: one endpoint,
// two spellings, decided by which of the two things went missing.
func TestOrganizationGroupCreateMovesOnAnID(t *testing.T) {
	h, _, _ := newServer(t)
	token, orgID, rootID, groupID := orgWithGroups(t, h)
	base := "/admin/realms/master/organizations/" + orgID + "/groups"

	w := send(t, h, http.MethodPost, base+"/"+groupID+"/children", token, `{"name":"gp-kid"}`)
	var kid struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &kid); err != nil {
		t.Fatalf("decoding the child: %v", err)
	}

	// The move to the top of the organization: 204, and the group's parent is
	// the hidden root afterwards.
	w = send(t, h, http.MethodPost, base, token, `{"id":"`+kid.ID+`","name":"gp-kid"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("moving to the top: %d %s", w.Code, w.Body)
	}
	w = get(t, h, base+"/"+kid.ID, token)
	var moved struct {
		ParentID string `json:"parentId"`
		Path     string `json:"path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &moved); err != nil {
		t.Fatalf("decoding the moved group: %v", err)
	}
	if moved.ParentID != rootID || moved.Path != "/gp-kid" {
		t.Errorf("after the move: parentId %q path %q, want %q and /gp-kid", moved.ParentID, moved.Path, rootID)
	}

	// An id that resolves to nothing is the realm family's spelling.
	w = send(t, h, http.MethodPost, base, token,
		`{"id":"00000000-0000-4000-8000-000000000000","name":"gp-kid"}`)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"error":"Could not find group by id"}` {
		t.Errorf("moving an unknown id: got %d %s", w.Code, got)
	}

	// A realm group is refused, and the sentence is not the read's.
	realmGroup := createRealmGroupReturningID(t, h, token, "gp-outsider")
	w = send(t, h, http.MethodPost, base, token, `{"id":"`+realmGroup+`","name":"gp-outsider"}`)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusBadRequest ||
		got != `{"errorMessage":"Can only move organization groups"}` {
		t.Errorf("moving a realm group: got %d %s", w.Code, got)
	}

	// The name is validated and then discarded: no name is still the 400.
	w = send(t, h, http.MethodPost, base, token, `{"id":"`+kid.ID+`"}`)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusBadRequest ||
		got != `{"errorMessage":"Group name is missing"}` {
		t.Errorf("moving with no name: got %d %s", w.Code, got)
	}
}

// TestOrganizationGroupGuardResolvesTheGroupBeforeTheWriteRole pins the
// resolution order, which is four deep and is **not** the member family's.
//
// Measured 2026-09-03 with one token per role: a `view-users` caller is 403 on
// every route whatever the ids are; a `view-organizations` caller gets
// `Organization not found.` for an organization that does not exist,
// `Group does not exist` for a group that does not exist **on a write route it
// may not use**, and 403 only once both resolve. A guard checking the write
// role first - which is what the nineteen member routes do - answers 403 where
// Keycloak answers 404 on every write in this family.
func TestOrganizationGroupGuardResolvesTheGroupBeforeTheWriteRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin, orgID, _, groupID := orgWithGroups(t, h)
	_ = admin

	viewer := tokenForRoles(t, h, s, realm, "view-organizations")
	stranger := tokenForRoles(t, h, s, realm, "view-users")
	const missing = "00000000-0000-4000-8000-000000000000"
	base := "/admin/realms/master/organizations/"

	for _, tc := range []struct {
		name, token, method, path, body string
		status                          int
		want                            string
	}{
		{
			name:  "a caller outside the tag never sees an id at all",
			token: stranger, method: http.MethodDelete,
			path:   base + missing + "/groups/" + missing,
			status: http.StatusForbidden, want: `{"error":"HTTP 403 Forbidden"}`,
		},
		{
			name:  "the organization comes before the group",
			token: viewer, method: http.MethodDelete,
			path:   base + missing + "/groups/" + missing,
			status: http.StatusNotFound, want: `{"errorMessage":"Organization not found."}`,
		},
		{
			name:  "the group comes before the write role",
			token: viewer, method: http.MethodDelete,
			path:   base + orgID + "/groups/" + missing,
			status: http.StatusNotFound, want: `{"errorMessage":"Group does not exist"}`,
		},
		{
			name:  "and the write role is judged once both resolve",
			token: viewer, method: http.MethodDelete,
			path:   base + orgID + "/groups/" + groupID,
			status: http.StatusForbidden, want: `{"error":"HTTP 403 Forbidden"}`,
		},
		{
			name:  "the same order on the role mappings",
			token: viewer, method: http.MethodPost,
			path: base + orgID + "/groups/" + missing + "/role-mappings/realm", body: `[]`,
			status: http.StatusNotFound, want: `{"errorMessage":"Group does not exist"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := send(t, h, tc.method, tc.path, tc.token, tc.body)
			if got := strings.TrimSpace(w.Body.String()); w.Code != tc.status || got != tc.want {
				t.Errorf("got %d %s, want %d %s", w.Code, got, tc.status, tc.want)
			}
		})
	}
}

// TestOrganizationGroupMemberWriteJudgesTheUserBeforeManageUsers is the fifth
// step of that chain, and it is the one the member family's guard cannot
// express.
//
// A caller holding `manage-organizations` and no user role gets
// `404 {"errorMessage":"User does not exist"}` for a user id that resolves to
// nothing and 403 for one that does - so the user is fetched **before**
// `manage-users` is judged, and a guard that checked both roles up front would
// answer 403 to both.
func TestOrganizationGroupMemberWriteJudgesTheUserBeforeManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	admin, orgID, _, groupID := orgWithGroups(t, h)
	user := createUserReturningID(t, h, admin, "probe-omega", "aaa@gp-order.example.com")

	manager := tokenForRoles(t, h, s, realm, "manage-organizations")
	base := "/admin/realms/master/organizations/" + orgID + "/groups/" + groupID + "/members/"

	w := send(t, h, http.MethodPut, base+"00000000-0000-4000-8000-000000000000", manager, "")
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"errorMessage":"User does not exist"}` {
		t.Errorf("an unknown user: got %d %s, want 404 about the user", w.Code, got)
	}
	w = send(t, h, http.MethodPut, base+user, manager, "")
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusForbidden ||
		got != `{"error":"HTTP 403 Forbidden"}` {
		t.Errorf("a real user: got %d %s, want 403", w.Code, got)
	}
}

// createUserReturningID posts a user and returns the id its Location names.
func createUserReturningID(t *testing.T, h http.Handler, token, username, email string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/users", token,
		`{"username":"`+username+`","email":"`+email+`","enabled":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", username, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// createRealmGroupReturningID posts a group through the realm family.
func createRealmGroupReturningID(t *testing.T, h http.Handler, token, name string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/groups", token, `{"name":"`+name+`"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", name, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}
