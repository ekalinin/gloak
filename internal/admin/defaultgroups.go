package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The four group operations the OpenAPI description files under Realms Admin
// rather than Groups: the realm's default groups, and the read by path.
//
// **They are not authorised like each other and neither is authorised like the
// Groups routes.** The three default-groups operations take the realm's own
// roles - view-realm/manage-realm to read, manage-realm to write - and
// group-by-path takes the users family's, view-users or manage-users. Measured
// across all 22 realm-management roles and a caller holding none. See
// router.go, where the three guards are declared.

// listDefaultGroups serves GET /admin/realms/{realm}/default-groups.
//
// The entry is `groupMembership`, the same shape a user's group listing sends:
// id, name, path, parentId when there is one, and an empty subGroups. **No
// subGroupCount, no attributes and no access**, and `briefRepresentation` does
// nothing to it - the flag was measured giving a byte-identical body.
//
// The order is the store's and it reproduces nothing: three groups added
// zzz, aaa, mmm came back in that order and a parent added before its child
// came back after it, so neither insertion order nor name nor id nor path
// explains both measurements. The conformance case compares this array
// unordered.
func (h *handler) listDefaultGroups(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	groups, err := h.store.Groups().ListDefaultGroups(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]groupRepresentation, 0, len(groups))
	for _, g := range groups {
		path, err := h.pathOf(r.Context(), rc.realm.ID, g.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, groupRepresentationOf(g, path, 0, rc.caller, groupMembership))
	}
	writeAdminJSON(w, out)
}

// addDefaultGroup serves PUT /admin/realms/{realm}/default-groups/{group-id}.
//
// Idempotent: the same group added twice was measured answering 204 both times
// and appearing once in the listing.
func (h *handler) addDefaultGroup(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	group, ok := h.defaultGroupFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Groups().AddDefaultGroup(r.Context(), rc.realm.ID, group.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMembershipNoContent(w, r)
}

// removeDefaultGroup serves DELETE .../default-groups/{group-id}.
//
// Removing a group that is not a default group is a 204, measured, the way
// removing a group membership that is not there is.
func (h *handler) removeDefaultGroup(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	group, ok := h.defaultGroupFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Groups().RemoveDefaultGroup(r.Context(), rc.realm.ID, group.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMembershipNoContent(w, r)
}

// defaultGroupFromPath resolves {groupID} **after** the guard has judged the
// caller, and that ordering is the finding of this cut.
//
// Every other route naming a {groupID} resolves the group first: an unknown one
// answers 404 to a caller holding no admin role at all, which is what guardGroup
// implements and what AGENTS.md records for the Groups family. These two do the
// opposite. Measured on both verbs: an unknown group id answers **403** to a
// view-realm caller, which may read the listing but not write it, and 403 to a
// caller holding nothing. So the rule holds on the routes the description tags
// Groups and is inverted on the two it tags Realms Admin, and the group is
// resolved here rather than in a combinator.
//
// The 404 is "Group not found", the membership routes' spelling, and not the
// Groups routes' "Could not find group by id" for the very same condition.
func (h *handler) defaultGroupFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Group, bool) {
	group, err := h.store.Groups().ByID(r.Context(), rc.realm.ID, r.PathValue("groupID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writePlainGroupNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return group, true
}

// readGroupByPath serves GET /admin/realms/{realm}/group-by-path/{path}.
//
// **The body is the sixth shape of a group**: groupFull minus `access`.
// Measured side by side against GET /groups/{id} on the same group, which is
// identical but for that one key, and `briefRepresentation` does nothing to
// either.
func (h *handler) readGroupByPath(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	path, err := h.pathOf(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	children, err := h.store.Groups().ListChildren(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, groupRepresentationOf(g, path, len(children), rc.caller, groupByPath))
}

// groupByPathSegments splits the {path} wildcard into the names to walk.
//
// A leading slash is optional: `/group-by-path/g1` and `/group-by-path/%2Fg1`
// were both measured answering 200 for the same group, and net/http hands the
// second over already decoded, so both arrive here as "g1" and "/g1". An empty
// path is no segments, which resolves to nothing and is the measured 404.
func groupByPathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// groupAtPath walks the tree from the top down, one name per segment.
//
// It walks rather than matching a stored path because a group's path is
// derived: renaming a parent moves every descendant's path, so there is nothing
// to match against. See groupPath.
func (h *handler) groupAtPath(r *http.Request, realmID string, segments []string) (*model.Group, error) {
	if len(segments) == 0 {
		return nil, store.ErrNotFound
	}
	parentID := ""
	var found *model.Group
	for _, name := range segments {
		siblings, err := h.store.Groups().ListChildren(r.Context(), realmID, parentID)
		if err != nil {
			return nil, err
		}
		found = nil
		for _, g := range siblings {
			if g.Name == name {
				found = g
				break
			}
		}
		if found == nil {
			return nil, store.ErrNotFound
		}
		parentID = found.ID
	}
	return found, nil
}

// writeGroupPathNotFound is the third group 404 on this API, after
// "Could not find group by id" and "Group not found": a path that resolves to
// nothing answers "Group path does not exist", with `application/json` and no
// Cache-Control. One missing group, three spellings, decided by the route that
// went looking for it.
func writeGroupPathNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Group path does not exist")
}
