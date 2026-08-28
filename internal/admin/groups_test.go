package admin

import (
	"context"
	"encoding/json"
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
