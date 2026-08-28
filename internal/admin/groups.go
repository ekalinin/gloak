package admin

import (
	"context"
	"strings"

	"github.com/ekalinin/gloak/internal/model"
)

// groupRepresentation is Keycloak's GroupRepresentation, in the field order
// measured 2026-08-28.
//
// **One resource, four shapes, and they are not a hierarchy.** Measured on a
// live 26.7.1:
//
//	GET  /groups                     id name path subGroupCount subGroups access
//	GET  /groups/{id}                id name path subGroupCount subGroups attributes realmRoles clientRoles access
//	POST /groups/{id}/children       id name path parentId           subGroups attributes realmRoles clientRoles access
//	GET  /groups/{id}/children       id name path parentId subGroupCount subGroups attributes realmRoles clientRoles access
//	GET  /users/{id}/groups          id name path parentId           subGroups
//
// The create's response has **no subGroupCount** and the children listing next
// door has one, so no single "brief" boolean produces all four. The listing
// with briefRepresentation=false is the single read's shape, which is the one
// place a flag does explain the difference - and it defaults the opposite way
// from the user listing's.
//
// Five fields are pointers, and none of that is style. subGroups is `[]` in
// every shape and attributes is `{}` where present, and both are exactly what
// omitempty drops; a pointer makes "absent" and "present and empty" different
// things. userRepresentation carries the same technique for the same reason.
//
// parentId is absent on a top-level group rather than empty, so it is the one
// field that omitempty is right for.
type groupRepresentation struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Path          string                `json:"path"`
	ParentID      string                `json:"parentId,omitempty"`
	SubGroupCount *int                  `json:"subGroupCount,omitempty"`
	SubGroups     []groupRepresentation `json:"subGroups"`
	Attributes    *map[string][]string  `json:"attributes,omitempty"`
	RealmRoles    *[]string             `json:"realmRoles,omitempty"`
	ClientRoles   *map[string][]string  `json:"clientRoles,omitempty"`
	Access        *groupAccess          `json:"access,omitempty"`
}

// groupAccess is the permissions block, in the measured key order.
//
// Every flag is computed from the **caller's** roles, never from anything about
// the group. Measured on three callers on 2026-08-28, on the listing and the
// single read alike:
//
//	view, viewMembers                            view-users or manage-users
//	manageMembers, manage, manageMembership      manage-users
type groupAccess struct {
	View             bool `json:"view"`
	ViewMembers      bool `json:"viewMembers"`
	ManageMembers    bool `json:"manageMembers"`
	Manage           bool `json:"manage"`
	ManageMembership bool `json:"manageMembership"`
}

func groupAccessFor(c *caller) groupAccess {
	manage := c.has("manage-users")
	return groupAccess{
		View:             manage || c.has("view-users"),
		ViewMembers:      manage || c.has("view-users"),
		ManageMembers:    manage,
		Manage:           manage,
		ManageMembership: manage,
	}
}

// groupShape says which of the four bodies is being written. The four differ in
// ways a single boolean cannot express, so the choice is named at the call site
// rather than derived from a flag whose meaning would have to be guessed.
type groupShape int

const (
	// groupBrief is the top-level listing: no attributes, no roles.
	groupBrief groupShape = iota
	// groupFull is the single read, and the listing under
	// briefRepresentation=false.
	groupFull
	// groupCreated is the child create's response: groupFull without
	// subGroupCount.
	groupCreated
	// groupMembership is a user's groups: the narrowest, with neither
	// subGroupCount nor access.
	groupMembership
)

// groupRepresentationOf converts a stored group for the wire.
//
// path is passed in rather than read off the model because it is derived from
// the ancestry - see groupPath - and subGroupCount likewise, because counting
// children is the store's business and not this function's.
func groupRepresentationOf(g *model.Group, path string, subGroupCount int, c *caller, shape groupShape) groupRepresentation {
	rep := groupRepresentation{
		ID:       g.ID,
		Name:     g.Name,
		Path:     path,
		ParentID: g.ParentID,
		// Always present and always empty. Measured on every shape: the tree
		// is never expanded here, and subGroupCount is what carries the truth.
		SubGroups: []groupRepresentation{},
	}
	if shape != groupCreated && shape != groupMembership {
		n := subGroupCount
		rep.SubGroupCount = &n
	}
	if shape != groupBrief && shape != groupMembership {
		attrs := g.Attributes
		if attrs == nil {
			// Measured: a group with no attributes reads back {} rather than
			// omitting the key, which is why this is a pointer.
			attrs = map[string][]string{}
		}
		rep.Attributes = &attrs
		// Empty until cut C. A group holding roles is not served yet, and a
		// representation guessing at the non-empty shape would be inventing a
		// contract - see the cut's design document, section 8.
		realmRoles := []string{}
		clientRoles := map[string][]string{}
		rep.RealmRoles = &realmRoles
		rep.ClientRoles = &clientRoles
	}
	if shape != groupMembership {
		access := groupAccessFor(c)
		rep.Access = &access
	}
	return rep
}

// groupPath is a group's path: every name from the root down, each preceded by
// a slash. A top-level group named probe-top is "/probe-top"; a child of it
// named probe-child is "/probe-top/probe-child".
//
// **It is computed, never stored.** Renaming a parent was measured moving every
// descendant's path while leaving their names alone, so a stored path would
// have to be rewritten for the whole subtree on every rename and the first
// missed rewrite is a divergence nothing would catch.
//
// ancestry is nearest last, which is what GroupRepo.Ancestry returns.
func groupPath(ancestry []*model.Group) string {
	var b strings.Builder
	for _, g := range ancestry {
		b.WriteByte('/')
		b.WriteString(g.Name)
	}
	return b.String()
}

// pathOf resolves one group's path through the store.
func (h *handler) pathOf(ctx context.Context, realmID, groupID string) (string, error) {
	chain, err := h.store.Groups().Ancestry(ctx, realmID, groupID)
	if err != nil {
		return "", err
	}
	return groupPath(chain), nil
}
