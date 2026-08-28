package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// The four shapes, asserted as whole JSON documents rather than field by field.
//
// The key **order** is the reason. Go's struct order is the only thing that
// produces it, and a field moved during a refactor changes the bytes on the
// wire while every field-by-field assertion still passes. Comparing the
// serialised document is what catches that.
//
// The bodies below are the recordings from a live 26.7.1 on 2026-08-28 with the
// ids and names substituted; see "Groups: P2's third cut" section 4.
func TestTheFourGroupShapes(t *testing.T) {
	admin := &caller{adminGrants: map[string]bool{"manage-users": true}}
	top := &model.Group{ID: "g1", RealmID: "r", Name: "probe-top"}
	child := &model.Group{ID: "g2", RealmID: "r", ParentID: "g1", Name: "probe-child"}

	for _, tc := range []struct {
		name  string
		group *model.Group
		path  string
		count int
		shape groupShape
		want  string
	}{
		{
			name: "the top-level listing", group: top, path: "/probe-top", shape: groupBrief,
			want: `{"id":"g1","name":"probe-top","path":"/probe-top","subGroupCount":0,` +
				`"subGroups":[],"access":{"view":true,"viewMembers":true,"manageMembers":true,` +
				`"manage":true,"manageMembership":true}}`,
		},
		{
			name: "the single read", group: top, path: "/probe-top", count: 1, shape: groupFull,
			want: `{"id":"g1","name":"probe-top","path":"/probe-top","subGroupCount":1,` +
				`"subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{},` +
				`"access":{"view":true,"viewMembers":true,"manageMembers":true,` +
				`"manage":true,"manageMembership":true}}`,
		},
		{
			// No subGroupCount, and that is the measurement rather than an
			// oversight: the create's response omits it where the children
			// listing below carries one.
			name: "the child create's response", group: child,
			path: "/probe-top/probe-child", shape: groupCreated,
			want: `{"id":"g2","name":"probe-child","path":"/probe-top/probe-child",` +
				`"parentId":"g1","subGroups":[],"attributes":{},"realmRoles":[],` +
				`"clientRoles":{},"access":{"view":true,"viewMembers":true,` +
				`"manageMembers":true,"manage":true,"manageMembership":true}}`,
		},
		{
			name: "the children listing", group: child,
			path: "/probe-top/probe-child", shape: groupFull,
			want: `{"id":"g2","name":"probe-child","path":"/probe-top/probe-child",` +
				`"parentId":"g1","subGroupCount":0,"subGroups":[],"attributes":{},` +
				`"realmRoles":[],"clientRoles":{},"access":{"view":true,"viewMembers":true,` +
				`"manageMembers":true,"manage":true,"manageMembership":true}}`,
		},
		{
			// The narrowest of the four: no subGroupCount and no access.
			name: "a user's groups", group: child,
			path: "/probe-top/probe-child", shape: groupMembership,
			want: `{"id":"g2","name":"probe-child","path":"/probe-top/probe-child",` +
				`"parentId":"g1","subGroups":[]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := groupRepresentationOf(tc.group, tc.path, tc.count, admin, tc.shape)
			got, err := json.Marshal(rep)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

// A group with attributes carries them; one without carries {} rather than
// omitting the key. The second half is what the pointer field is for, and it is
// the half omitempty would break.
func TestGroupAttributesAreEmptyRatherThanAbsent(t *testing.T) {
	admin := &caller{adminGrants: map[string]bool{"manage-users": true}}
	with := &model.Group{ID: "g", Name: "n", Attributes: map[string][]string{"k": {"v"}}}
	got, err := json.Marshal(groupRepresentationOf(with, "/n", 0, admin, groupFull))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"attributes":{"k":["v"]}`; !strings.Contains(string(got), want) {
		t.Fatalf("want %s in %s", want, got)
	}

	without := &model.Group{ID: "g", Name: "n"}
	got, err = json.Marshal(groupRepresentationOf(without, "/n", 0, admin, groupFull))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `"attributes":{}`; !strings.Contains(string(got), want) {
		t.Fatalf("want %s in %s", want, got)
	}
}

// access is the caller's, never the group's. Measured on three callers:
// view and viewMembers come from view-users, the other three from manage-users.
func TestGroupAccessFollowsTheCaller(t *testing.T) {
	for _, tc := range []struct {
		role string
		want groupAccess
	}{
		{"manage-users", groupAccess{true, true, true, true, true}},
		{"view-users", groupAccess{View: true, ViewMembers: true}},
		{"query-users", groupAccess{}},
	} {
		got := groupAccessFor(&caller{adminGrants: map[string]bool{tc.role: true}})
		if got != tc.want {
			t.Errorf("caller holding %q:\n got  %+v\n want %+v", tc.role, got, tc.want)
		}
	}
}

// The path is the ancestry's names, and renaming an ancestor moves it while the
// descendants' own names stay put. That cascade is the measured behaviour and
// the reason the path is not a stored column.
func TestGroupPathIsDerivedAndFollowsARename(t *testing.T) {
	_, s, realm := newServer(t)
	ctx := context.Background()
	root := &model.Group{ID: model.NewID(), RealmID: realm.ID, Name: "top"}
	mid := &model.Group{ID: model.NewID(), RealmID: realm.ID, ParentID: root.ID, Name: "mid"}
	leaf := &model.Group{ID: model.NewID(), RealmID: realm.ID, ParentID: mid.ID, Name: "leaf"}
	for _, g := range []*model.Group{root, mid, leaf} {
		if err := s.Groups().Create(ctx, g); err != nil {
			t.Fatalf("Create(%q): %v", g.Name, err)
		}
	}

	path := func(id string) string {
		chain, err := s.Groups().Ancestry(ctx, realm.ID, id)
		if err != nil {
			t.Fatalf("Ancestry: %v", err)
		}
		return groupPath(chain)
	}
	for _, tc := range []struct{ id, want string }{
		{root.ID, "/top"}, {mid.ID, "/top/mid"}, {leaf.ID, "/top/mid/leaf"},
	} {
		if got := path(tc.id); got != tc.want {
			t.Errorf("path: got %q, want %q", got, tc.want)
		}
	}

	// The rename, and the whole point: two descendants move, neither is
	// touched, and nothing was rewritten in the store.
	root.Name = "renamed"
	if err := s.Groups().Update(ctx, root); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, tc := range []struct{ id, want string }{
		{root.ID, "/renamed"}, {mid.ID, "/renamed/mid"}, {leaf.ID, "/renamed/mid/leaf"},
	} {
		if got := path(tc.id); got != tc.want {
			t.Errorf("after the rename: got %q, want %q", got, tc.want)
		}
	}
	if got, err := s.Groups().ByID(ctx, realm.ID, leaf.ID); err != nil || got.Name != "leaf" {
		t.Fatalf("the rename reached a descendant's name: %v %+v", err, got)
	}
}

// groupTree creates a small tree through the API and returns the ids by name.
func groupTree(t *testing.T, h http.Handler, tok string, tree map[string][]string) map[string]string {
	t.Helper()
	ids := map[string]string{}
	find := func(name string) string {
		w := get(t, h, "/admin/realms/master/groups?search="+name, tok)
		var got []groupRepresentation
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("parse listing: %v", err)
		}
		for _, g := range got {
			if g.Name == name {
				return g.ID
			}
		}
		t.Fatalf("group %q not in %s", name, w.Body)
		return ""
	}
	for parent, kids := range tree {
		if w := postJSON(t, h, "/admin/realms/master/groups", `{"name":"`+parent+`"}`, tok); w.Code != http.StatusCreated {
			t.Fatalf("create %q: %d %s", parent, w.Code, w.Body)
		}
		ids[parent] = find(parent)
		for _, kid := range kids {
			w := postJSON(t, h, "/admin/realms/master/groups/"+ids[parent]+"/children",
				`{"name":"`+kid+`"}`, tok)
			if w.Code != http.StatusCreated {
				t.Fatalf("create child %q: %d %s", kid, w.Code, w.Body)
			}
			var rep groupRepresentation
			if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil {
				t.Fatalf("parse child: %v", err)
			}
			ids[kid] = rep.ID
		}
	}
	return ids
}

// listedNames flattens a group listing, writing a parent's nested children in
// brackets so the nesting is part of the comparison.
func listedNames(t *testing.T, h http.Handler, query, tok string) []string {
	t.Helper()
	w := get(t, h, "/admin/realms/master/groups"+query, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("listing%s: %d %s", query, w.Code, w.Body)
	}
	var got []groupRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse listing: %v", err)
	}
	var walk func([]groupRepresentation) []string
	walk = func(in []groupRepresentation) []string {
		out := []string{}
		for _, g := range in {
			name := g.Name
			if kids := walk(g.SubGroups); len(kids) > 0 {
				name += "(" + strings.Join(kids, ",") + ")"
			}
			out = append(out, name)
		}
		return out
	}
	return walk(got)
}

// search matches the whole tree, pages the matches rather than the rows, and
// returns the top-level ancestors of the page with the matching descendants
// nested. Measured on a live 26.7.1; ?search=alpha&max=1 answering beta-alpha
// rather than alpha-one is what says the page is taken from the matches.
func TestGroupSearchPagesTheMatchesAndNestsThem(t *testing.T) {
	h, _, _ := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")
	groupTree(t, h, tok, map[string][]string{
		"alpha-one":  nil,
		"beta-alpha": {"alpha-kid"},
		"zeta":       nil,
	})

	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"?search=alpha", []string{"alpha-one", "beta-alpha(alpha-kid)"}},
		// The first match by name is the child, so the page of one is its
		// ancestor.
		{"?search=alpha&max=1", []string{"beta-alpha(alpha-kid)"}},
		{"?search=alpha&max=2", []string{"alpha-one", "beta-alpha(alpha-kid)"}},
		// first=1 skips the child, so beta-alpha comes back with nothing
		// nested although it matched itself.
		{"?search=alpha&first=1", []string{"alpha-one", "beta-alpha"}},
		{"?search=alpha&first=2", []string{"beta-alpha"}},
		{"?search=alpha&first=1&max=1", []string{"alpha-one"}},
		// A case-insensitive substring.
		{"?search=ALPHA", []string{"alpha-one", "beta-alpha(alpha-kid)"}},
		{"?search=one", []string{"alpha-one"}},
		{"?search=nothing", []string{}},
	} {
		if got := listedNames(t, h, tc.query, tok); !slices.Equal(got, tc.want) {
			t.Errorf("%s:\n got  %v\n want %v", tc.query, got, tc.want)
		}
	}
}

// Without a search the listing is top-level and either bound alone pages. That
// is a third paging rule on this API: the role listings page only when search
// is set or both bounds are present, and the user listing has its own.
func TestGroupListingPagesOnEitherBoundAlone(t *testing.T) {
	h, _, _ := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")
	groupTree(t, h, tok, map[string][]string{
		"alpha-one":  nil,
		"beta-alpha": {"alpha-kid"},
		"zeta":       nil,
	})

	for _, tc := range []struct {
		query string
		want  []string
	}{
		// Top-level only: alpha-kid is nowhere here.
		{"", []string{"alpha-one", "beta-alpha", "zeta"}},
		{"?max=1", []string{"alpha-one"}},
		{"?first=1", []string{"beta-alpha", "zeta"}},
		{"?first=1&max=1", []string{"beta-alpha"}},
		{"?max=0", []string{}},
		{"?first=99", []string{}},
		// A negative bound is ignored rather than clamped.
		{"?max=-1", []string{"alpha-one", "beta-alpha", "zeta"}},
	} {
		if got := listedNames(t, h, tc.query, tok); !slices.Equal(got, tc.want) {
			t.Errorf("%s:\n got  %v\n want %v", tc.query, got, tc.want)
		}
	}
}

// The count is an object where the user count is a bare number, it counts the
// whole tree where the listing is top-level, and top=true is ignored when
// search is set.
func TestGroupCountIsTheTreeAndTopIsIgnoredUnderSearch(t *testing.T) {
	h, _, _ := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")
	groupTree(t, h, tok, map[string][]string{
		"alpha-one":  nil,
		"beta-alpha": {"alpha-kid"},
		"zeta":       nil,
	})

	for _, tc := range []struct{ query, want string }{
		{"", `{"count":4}`},
		{"?top=true", `{"count":3}`},
		{"?search=alpha", `{"count":3}`},
		// Two of the three top-level groups match, so an honoured top would
		// answer 2.
		{"?search=alpha&top=true", `{"count":3}`},
		{"?search=nothing", `{"count":0}`},
	} {
		w := get(t, h, "/admin/realms/master/groups/count"+tc.query, tok)
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("count%s: %d %s, want %s", tc.query, w.Code, w.Body, tc.want)
		}
	}
}

// The two creates disagree about whether a create has a body, and the two
// conflicts disagree about what to call a duplicate. Both measured.
func TestTheTwoGroupCreatesDisagree(t *testing.T) {
	h, _, _ := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")

	w := postJSON(t, h, "/admin/realms/master/groups", `{"name":"top"}`, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w.Body.Len() != 0 {
		t.Errorf("POST /groups: want an empty body, got %s", w.Body)
	}
	if w.Header().Get("Location") == "" {
		t.Error("POST /groups: no Location")
	}
	list := get(t, h, "/admin/realms/master/groups?search=top", tok)
	var got []groupRepresentation
	if err := json.Unmarshal(list.Body.Bytes(), &got); err != nil || len(got) != 1 {
		t.Fatalf("find top: %v %s", err, list.Body)
	}
	top := got[0].ID

	child := postJSON(t, h, "/admin/realms/master/groups/"+top+"/children", `{"name":"kid"}`, tok)
	if child.Code != http.StatusCreated {
		t.Fatalf("create child: %d %s", child.Code, child.Body)
	}
	if child.Body.Len() == 0 {
		t.Error("POST .../children: want the group in the body, got nothing")
	}
	if child.Header().Get("Location") == "" {
		t.Error("POST .../children: no Location")
	}

	// The two conflict messages, which is why they are not one helper.
	dup := postJSON(t, h, "/admin/realms/master/groups", `{"name":"top"}`, tok)
	if want := `{"errorMessage":"Top level group named 'top' already exists."}`; dup.Code != http.StatusConflict ||
		strings.TrimSpace(dup.Body.String()) != want {
		t.Errorf("duplicate top level: %d %s, want %s", dup.Code, dup.Body, want)
	}
	sib := postJSON(t, h, "/admin/realms/master/groups/"+top+"/children", `{"name":"kid"}`, tok)
	if want := `{"errorMessage":"Sibling group named 'kid' already exists."}`; sib.Code != http.StatusConflict ||
		strings.TrimSpace(sib.Body.String()) != want {
		t.Errorf("duplicate sibling: %d %s, want %s", sib.Code, sib.Body, want)
	}
	for _, path := range []string{"/admin/realms/master/groups", "/admin/realms/master/groups/" + top + "/children"} {
		noName := postJSON(t, h, path, `{}`, tok)
		if want := `{"errorMessage":"Group name is missing"}`; noName.Code != http.StatusBadRequest ||
			strings.TrimSpace(noName.Body.String()) != want {
			t.Errorf("%s with no name: %d %s", path, noName.Code, noName.Body)
		}
	}
}

// A group that does not exist is 404 to every caller, including one holding no
// admin role at all - the group is resolved before the caller is judged.
// Measured across all six routes and seven callers.
func TestAMissingGroupIs404ToEveryCaller(t *testing.T) {
	h, s, realm := newServer(t)
	missing := "/admin/realms/master/groups/00000000-0000-0000-0000-000000000000"
	routes := []struct{ method, path string }{
		{http.MethodGet, missing},
		{http.MethodPut, missing},
		{http.MethodDelete, missing},
		{http.MethodGet, missing + "/children"},
		{http.MethodPost, missing + "/children"},
		{http.MethodGet, missing + "/members"},
	}
	tokens := map[string]string{"the bootstrapped administrator": tokenFor(t, h, "admin", "admin")}
	for _, role := range []string{"view-users", "query-users", "manage-users", "query-groups",
		"view-clients", "manage-realm"} {
		tokens[role] = tokenForRole(t, h, s, realm, role)
	}
	for who, tok := range tokens {
		for _, rt := range routes {
			w := sendJSON(t, h, rt.method, rt.path, `{"name":"x"}`, tok)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s on %s %s: want 404, got %d: %s", who, rt.method, rt.path, w.Code, w.Body)
			}
			if want := `{"error":"Could not find group by id"}`; strings.TrimSpace(w.Body.String()) != want {
				t.Errorf("%s on %s %s: body %s", who, rt.method, rt.path, w.Body)
			}
		}
	}
}

// query-groups opens the listing and the count and nothing else, which is why
// the group read sets are not usersReadRoles. manage-realm is 403 on every one
// of them: groups are authorised out of the users family.
func TestGroupGuardsAreTheUsersFamilyPlusQueryGroups(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	ids := groupTree(t, h, admin, map[string][]string{"top": nil})

	for _, tc := range []struct {
		role                        string
		list, read, create, members int
	}{
		{"view-users", 200, 200, 403, 200},
		{"manage-users", 200, 200, 201, 200},
		{"query-groups", 200, 403, 403, 403},
		{"query-users", 403, 403, 403, 403},
		{"view-clients", 403, 403, 403, 403},
		{"manage-realm", 403, 403, 403, 403},
	} {
		tok := tokenForRole(t, h, s, realm, tc.role)
		base := "/admin/realms/master/groups"
		checks := []struct {
			what string
			got  int
			want int
		}{
			{"listing", get(t, h, base, tok).Code, tc.list},
			{"count", get(t, h, base+"/count", tok).Code, tc.list},
			{"read", get(t, h, base+"/"+ids["top"], tok).Code, tc.read},
			{"members", get(t, h, base+"/"+ids["top"]+"/members", tok).Code, tc.members},
			{"create", postJSON(t, h, base, `{"name":"by-`+tc.role+`"}`, tok).Code, tc.create},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("%s on the %s: want %d, got %d", tc.role, c.what, c.want, c.got)
			}
		}
	}
}

// The membership routes resolve the group **last** - after the subject and
// after the caller check - where the Groups routes resolve it first, before
// judging anybody. Two families, opposite orders, the same group.
//
// Measured 2026-08-28 on seven callers. The two rows that say so are the last
// two: query-users opens none of the four routes and still gets the 404 for a
// user that does not exist, and view-users is refused a write before the group
// is looked at where manage-users reaches the 404.
func TestMembershipResolvesTheGroupLast(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	ids := groupTree(t, h, admin, map[string][]string{"top": {"kid"}})
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-member","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-member")
	missing := "00000000-0000-0000-0000-000000000000"

	for _, tc := range []struct {
		role                                   string
		list, write, unknownUser, unknownGroup int
	}{
		{"view-users", 200, 403, 404, 403},
		{"manage-users", 200, 204, 404, 404},
		{"query-users", 403, 403, 404, 403},
		{"query-groups", 403, 403, 403, 403},
		{"view-clients", 403, 403, 403, 403},
		{"manage-realm", 403, 403, 403, 403},
	} {
		tok := tokenForRole(t, h, s, realm, tc.role)
		base := "/admin/realms/master/users/" + uid + "/groups"
		for _, c := range []struct {
			what string
			got  int
			want int
		}{
			{"listing", get(t, h, base, tok).Code, tc.list},
			{"count", get(t, h, base+"/count", tok).Code, tc.list},
			{"join", sendJSON(t, h, http.MethodPut, base+"/"+ids["kid"], "", tok).Code, tc.write},
			// The coarse gate: query-users opens none of these and still
			// learns the user is absent.
			{"unknown user", get(t, h, "/admin/realms/master/users/"+missing+"/groups", tok).Code, tc.unknownUser},
			// The group last: view-users is refused before it is looked at.
			{"unknown group", sendJSON(t, h, http.MethodPut, base+"/"+missing, "", tok).Code, tc.unknownGroup},
		} {
			if c.got != c.want {
				t.Errorf("%s on the %s: want %d, got %d", tc.role, c.what, c.want, c.got)
			}
		}
	}

	// The user wins when both are missing.
	w := sendJSON(t, h, http.MethodPut,
		"/admin/realms/master/users/"+missing+"/groups/"+missing, "", admin)
	if want := `{"error":"User not found"}`; w.Code != http.StatusNotFound ||
		strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("both missing: %d %s, want 404 %s", w.Code, w.Body, want)
	}
	// And the group's 404 here is not the Groups routes' spelling.
	w = sendJSON(t, h, http.MethodPut,
		"/admin/realms/master/users/"+uid+"/groups/"+missing, "", admin)
	if want := `{"error":"Group not found"}`; strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("unknown group: %s, want %s", w.Body, want)
	}
}

// The writes are forgiving about the membership and strict about the group: a
// second join is 204, and so is leaving a group never joined.
func TestMembershipWritesAreIdempotent(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	ids := groupTree(t, h, admin, map[string][]string{"top": {"kid"}, "other": nil})
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-member","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-member")
	base := "/admin/realms/master/users/" + uid + "/groups"

	join := func(id string) int { return sendJSON(t, h, http.MethodPut, base+"/"+id, "", admin).Code }
	leave := func(id string) int { return sendJSON(t, h, http.MethodDelete, base+"/"+id, "", admin).Code }

	for _, tc := range []struct {
		what string
		got  int
	}{
		{"first join", join(ids["kid"])},
		{"second join", join(ids["kid"])},
		{"leave", leave(ids["kid"])},
		{"leave again", leave(ids["kid"])},
		{"leave a group never joined", leave(ids["other"])},
	} {
		if tc.got != http.StatusNoContent {
			t.Errorf("%s: want 204, got %d", tc.what, tc.got)
		}
	}

	// **Membership does not reach upwards.** Joining the child leaves the
	// parent's member list empty, measured.
	if join(ids["kid"]) != http.StatusNoContent {
		t.Fatal("rejoin")
	}
	for _, tc := range []struct {
		group string
		want  int
	}{{"kid", 1}, {"top", 0}} {
		w := get(t, h, "/admin/realms/master/groups/"+ids[tc.group]+"/members", admin)
		var members []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &members); err != nil {
			t.Fatalf("parse members: %v", err)
		}
		if len(members) != tc.want {
			t.Errorf("%s has %d members, want %d", tc.group, len(members), tc.want)
		}
	}
}

// The membership listing is the fifth shape, and briefRepresentation=false
// gains the attributes trio without gaining subGroupCount or access.
func TestTheMembershipListingIsTheFifthShape(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	ids := groupTree(t, h, admin, map[string][]string{"top": {"kid"}})
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-member","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-member")
	base := "/admin/realms/master/users/" + uid + "/groups"
	if w := sendJSON(t, h, http.MethodPut, base+"/"+ids["kid"], "", admin); w.Code != http.StatusNoContent {
		t.Fatalf("join: %d %s", w.Code, w.Body)
	}

	brief := get(t, h, base, admin).Body.String()
	for _, absent := range []string{"subGroupCount", "access", "attributes", "realmRoles", "clientRoles"} {
		if strings.Contains(brief, absent) {
			t.Errorf("the brief listing carries %q: %s", absent, brief)
		}
	}
	for _, present := range []string{`"parentId"`, `"subGroups":[]`, `"path":"/top/kid"`} {
		if !strings.Contains(brief, present) {
			t.Errorf("the brief listing lacks %s: %s", present, brief)
		}
	}

	full := get(t, h, base+"?briefRepresentation=false", admin).Body.String()
	for _, present := range []string{`"attributes":{}`, `"realmRoles":[]`, `"clientRoles":{}`} {
		if !strings.Contains(full, present) {
			t.Errorf("the full listing lacks %s: %s", present, full)
		}
	}
	// **Still neither**, which is what makes this a fifth shape rather than
	// the single read's.
	for _, absent := range []string{"subGroupCount", "access"} {
		if strings.Contains(full, absent) {
			t.Errorf("briefRepresentation=false gained %q: %s", absent, full)
		}
	}
}
