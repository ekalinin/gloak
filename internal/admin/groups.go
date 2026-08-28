package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
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

// listGroups serves GET /admin/realms/{realm}/groups.
//
// **Top-level only**, unlike the count next door, which counts the whole tree.
//
// briefRepresentation defaults to **true** here, the opposite way from the user
// listing's, and `false` produces the single read's shape.
func (h *handler) listGroups(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	shape := groupBrief
	if q.Get("briefRepresentation") == "false" {
		shape = groupFull
	}
	var out []groupRepresentation
	var err error
	if search := q.Get("search"); search != "" {
		out, err = h.searchGroups(r.Context(), rc, search, q, shape)
	} else {
		out, err = h.topLevelGroups(r.Context(), rc, q, shape)
	}
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, out)
}

// topLevelGroups is the listing without a search: the groups with no parent,
// sliced by first and max.
func (h *handler) topLevelGroups(ctx context.Context, rc *reqContext, q url.Values, shape groupShape) ([]groupRepresentation, error) {
	tops, err := h.store.Groups().ListTopLevel(ctx, rc.realm.ID)
	if err != nil {
		return nil, err
	}
	tops = pageGroups(tops, q)
	out := make([]groupRepresentation, 0, len(tops))
	for _, g := range tops {
		rep, err := h.groupRepWithChildren(ctx, rc, g, "", nil, shape)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, nil
}

// searchGroups is the listing with a search, and it is a different query rather
// than a filter over the one above.
//
// **The match runs over the whole tree, the page is taken from the matches, and
// what comes back is their top-level ancestors with the matching descendants
// nested.** Measured 2026-08-28: with alpha-one and beta-alpha at the top level
// and alpha-kid a child of beta-alpha, `?search=alpha&max=1` answers
// `[beta-alpha]` and not `[alpha-one]`, because the first match by name is the
// child. Six rows of first/max fit that rule and no simpler one.
//
// This is the only place subGroups is ever non-empty. The design document said
// "always empty" until this was measured.
func (h *handler) searchGroups(ctx context.Context, rc *reqContext, search string, q url.Values, shape groupShape) ([]groupRepresentation, error) {
	all, err := h.store.Groups().ListAll(ctx, rc.realm.ID)
	if err != nil {
		return nil, err
	}
	var matched []*model.Group
	for _, g := range all {
		// A case-insensitive substring: "one" matches alpha-one and "ALPHA"
		// matches both alpha-one and beta-alpha, measured.
		if strings.Contains(strings.ToLower(g.Name), strings.ToLower(search)) {
			matched = append(matched, g)
		}
	}
	matched = pageGroups(matched, q)

	// Each match contributes its top-level ancestor once, and every match is
	// kept so the ancestor can be written with them nested.
	keep := map[string]bool{}
	seen := map[string]bool{}
	var roots []*model.Group
	for _, m := range matched {
		chain, err := h.store.Groups().Ancestry(ctx, rc.realm.ID, m.ID)
		if err != nil {
			return nil, err
		}
		keep[m.ID] = true
		root := chain[0]
		if !seen[root.ID] {
			seen[root.ID] = true
			roots = append(roots, root)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Name < roots[j].Name })

	out := make([]groupRepresentation, 0, len(roots))
	for _, root := range roots {
		rep, err := h.groupRepWithChildren(ctx, rc, root, "", keep, shape)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, nil
}

// groupRepWithChildren writes one group, nesting the descendants in keep.
//
// keep is nil for every listing but the search, and a nil keep means subGroups
// stays `[]` - which is what every other measurement shows.
//
// parentPath is the ancestor's path, so a walk computes each path from the one
// above rather than re-reading the ancestry per node.
func (h *handler) groupRepWithChildren(ctx context.Context, rc *reqContext, g *model.Group, parentPath string, keep map[string]bool, shape groupShape) (groupRepresentation, error) {
	kids, err := h.store.Groups().ListChildren(ctx, rc.realm.ID, g.ID)
	if err != nil {
		return groupRepresentation{}, err
	}
	path := parentPath + "/" + g.Name
	rep := groupRepresentationOf(g, path, len(kids), rc.caller, shape)
	if keep == nil {
		return rep, nil
	}
	for _, kid := range kids {
		nested, err := h.groupRepWithChildren(ctx, rc, kid, path, keep, shape)
		if err != nil {
			return groupRepresentation{}, err
		}
		// A child is written when it matched or when something under it did,
		// so the path from the root to every match is present.
		if keep[kid.ID] || len(nested.SubGroups) > 0 {
			rep.SubGroups = append(rep.SubGroups, nested)
		}
	}
	return rep, nil
}

// pageGroups applies first and max.
//
// **Either bound alone pages**, which is a third rule on this API: the role
// listings page only when search is non-empty or both bounds are present, and
// the user listing has its own. Measured 2026-08-28 - `?max=1` alone returns one
// row, `?first=1` alone skips one, `max=0` is an empty array, and a negative
// bound is ignored rather than clamped.
func pageGroups[T any](in []T, q url.Values) []T {
	out := in
	if v, err := strconv.Atoi(q.Get("first")); err == nil && v > 0 {
		if v >= len(out) {
			return out[:0]
		}
		out = out[v:]
	}
	if v, err := strconv.Atoi(q.Get("max")); err == nil && v >= 0 && v < len(out) {
		out = out[:v]
	}
	return out
}

// countGroups serves GET /admin/realms/{realm}/groups/count.
//
// **The body is an object, `{"count":2}`, where GET /users/count next door is a
// bare JSON number.** The two counts on this API do not agree about what a
// count is.
//
// It counts the **whole tree** while the listing beside it is top-level only,
// and `top=true` narrows it to the top level - except when `search` is set,
// where top is ignored. Measured: two of three top-level groups match `alpha`
// and `?search=alpha&top=true` answers 3, the number that includes the matching
// child.
func (h *handler) countGroups(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	all, err := h.store.Groups().ListAll(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	q := r.URL.Query()
	search := q.Get("search")
	n := 0
	for _, g := range all {
		if search != "" {
			if strings.Contains(strings.ToLower(g.Name), strings.ToLower(search)) {
				n++
			}
			continue
		}
		if q.Get("top") == "true" && g.ParentID != "" {
			continue
		}
		n++
	}
	writeAdminJSON(w, map[string]int{"count": n})
}

// createGroup serves POST /admin/realms/{realm}/groups.
//
// **201 with an empty body**, Location, and content-length 0 - where
// POST .../children below answers 201 **with the group in it**. Two creates on
// one resource, disagreeing about whether a create has a body. Measured, both.
func (h *handler) createGroup(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeGroup(w, r)
	if !ok {
		return
	}
	g, ok := h.insertGroup(w, r, rc, rep, "")
	if !ok {
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/groups/"+g.ID)
	w.WriteHeader(http.StatusCreated)
}

// createChild serves POST /admin/realms/{realm}/groups/{group-id}/children.
//
// 201 **with a body**, and the body is the one shape that carries no
// subGroupCount. Both measured on this route rather than shared with the create
// above, which they disagree with.
func (h *handler) createChild(w http.ResponseWriter, r *http.Request, rc *reqContext, parent *model.Group) {
	rep, ok := decodeGroup(w, r)
	if !ok {
		return
	}
	g, ok := h.insertGroup(w, r, rc, rep, parent.ID)
	if !ok {
		return
	}
	path, err := h.pathOf(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/groups/"+g.ID)
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusCreated,
		groupRepresentationOf(g, path, 0, rc.caller, groupCreated))
}

// insertGroup is what the two creates share: the name check, the write and the
// conflict. **The conflict message is not shared**, because it is not the same
// string: a duplicate at the top level is "Top level group named 'x' already
// exists." and a duplicate beside a sibling is "Sibling group named 'x' already
// exists.", measured on each. Two spellings, like the two the 404 has.
func (h *handler) insertGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, rep groupRepresentation, parentID string) (*model.Group, bool) {
	if rep.Name == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Group name is missing")
		return nil, false
	}
	g := &model.Group{ID: model.NewID(), RealmID: rc.realm.ID, ParentID: parentID, Name: rep.Name}
	if rep.Attributes != nil {
		g.Attributes = *rep.Attributes
	}
	if err := h.store.Groups().Create(r.Context(), g); err != nil {
		if errors.Is(err, store.ErrConflict) {
			kind := "Top level group"
			if parentID != "" {
				kind = "Sibling group"
			}
			httpx.WriteAdminError(w, http.StatusConflict,
				kind+" named '"+rep.Name+"' already exists.")
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return g, true
}

// readGroup serves GET /admin/realms/{realm}/groups/{group-id}.
func (h *handler) readGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	rep, err := h.oneGroup(r.Context(), rc, g, groupFull)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, rep)
}

// listChildren serves GET /admin/realms/{realm}/groups/{group-id}/children.
// Each row carries parentId **and** subGroupCount, where the create's response
// carries the first and not the second.
func (h *handler) listChildren(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	kids, err := h.store.Groups().ListChildren(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	kids = pageGroups(kids, r.URL.Query())
	out := make([]groupRepresentation, 0, len(kids))
	for _, kid := range kids {
		rep, err := h.oneGroup(r.Context(), rc, kid, groupFull)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, rep)
	}
	writeAdminJSON(w, out)
}

// oneGroup writes a group with its path and child count resolved.
func (h *handler) oneGroup(ctx context.Context, rc *reqContext, g *model.Group, shape groupShape) (groupRepresentation, error) {
	path, err := h.pathOf(ctx, rc.realm.ID, g.ID)
	if err != nil {
		return groupRepresentation{}, err
	}
	kids, err := h.store.Groups().ListChildren(ctx, rc.realm.ID, g.ID)
	if err != nil {
		return groupRepresentation{}, err
	}
	return groupRepresentationOf(g, path, len(kids), rc.caller, shape), nil
}

// updateGroup serves PUT /admin/realms/{realm}/groups/{group-id}: 204, carrying
// X-Frame-Options because the request had a JSON body - see
// httpx.WriteNoContent.
//
// The body is merged rather than replacing, the way a client's is: a field the
// caller omitted keeps its stored value.
func (h *handler) updateGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	rep, ok := decodeGroup(w, r)
	if !ok {
		return
	}
	if rep.Name != "" {
		g.Name = rep.Name
	}
	if rep.Attributes != nil {
		g.Attributes = *rep.Attributes
	}
	if err := h.store.Groups().Update(r.Context(), g); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteGroup serves DELETE /admin/realms/{realm}/groups/{group-id}: 204, and
// it omits X-Frame-Options because the request carried no body. It carries no
// Cache-Control either, where DELETE on a client does - measured on each.
func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	if err := h.store.Groups().Delete(r.Context(), rc.realm.ID, g.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeGroupNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// groupMembers serves GET /admin/realms/{realm}/groups/{group-id}/members.
//
// **Direct members only.** A user in a child was measured not being a member of
// its parent, so this does not walk down.
//
// The body is the user representation **without the access block**, where the
// user listing next door carries a one-key one. It honours briefRepresentation
// and paging, both measured on this route.
func (h *handler) groupMembers(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	users, err := h.store.Groups().Members(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	q := r.URL.Query()
	users = pageGroups(users, q)
	brief := q.Get("briefRepresentation") == "true"
	out := make([]userRepresentation, 0, len(users))
	for _, u := range users {
		// Access is left nil: this listing carries no access key at all.
		out = append(out, userRepresentationOf(u, brief))
	}
	writeAdminJSON(w, out)
}

// decodeGroup reads a GroupRepresentation from the request body.
func decodeGroup(w http.ResponseWriter, r *http.Request) (groupRepresentation, bool) {
	var rep groupRepresentation
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return rep, false
	}
	return rep, true
}

// writeGroupNotFound is the 404 the Groups routes answer. The membership route
// in cut B spells the same condition "Group not found", measured, so this is
// deliberately not a shared helper.
func writeGroupNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find group by id")
}
