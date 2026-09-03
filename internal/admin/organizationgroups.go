package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// organizationGroupRepresentation is what the eleven routes under
// `/organizations/{org-id}/groups` serve.
//
// **It is not groupRepresentation with a different prefix**, and the difference
// is not one field. Measured 2026-09-03, the two families side by side on one
// container:
//
//	realm  GET  /groups                 id name path subGroupCount subGroups access
//	realm  GET  /groups/{id}            id name path subGroupCount subGroups attributes realmRoles clientRoles access
//	realm  GET  /groups/{id}/children   id name path parentId subGroupCount subGroups attributes realmRoles clientRoles access
//
//	org    GET  /groups                 id name path parentId subGroups
//	org    GET  /groups/{id}            id name path parentId subGroups attributes realmRoles clientRoles
//	org    GET  /groups/{id}/children   id name path parentId subGroups
//
// **No body in this family carries `access` or `subGroupCount`, and every one
// of them carries `parentId`** - including a group at the top of the
// organization, which has the hidden root as its parent where a top-level realm
// group has none. So the realm family's six shapes and this family's two are
// disjoint key sets and no boolean produces both.
//
// The pointers are groupRepresentation's technique for its reason: `subGroups`
// is `[]` and `attributes` is `{}` in every body that has them, which is exactly
// what omitempty drops, so "absent" and "present and empty" need a pointer to be
// two different things. ParentID is the one field omitempty is right for - the
// hidden root itself is served with no `parentId` key at all.
type organizationGroupRepresentation struct {
	ID          string                            `json:"id"`
	Name        string                            `json:"name"`
	Path        string                            `json:"path"`
	ParentID    string                            `json:"parentId,omitempty"`
	SubGroups   []organizationGroupRepresentation `json:"subGroups"`
	Attributes  *javaMapAttributes                `json:"attributes,omitempty"`
	RealmRoles  *[]string                         `json:"realmRoles,omitempty"`
	ClientRoles *javaMapRoleNames                 `json:"clientRoles,omitempty"`
}

// javaMapAttributes serialises a group's attributes in Keycloak's HashMap
// bucket order rather than Go's sorted one.
//
// It is a slice with a marshaller of its own for organizationAttributes'
// reason, and it is measured here rather than carried over: a group created
// with `{"k":["v1","v2"],"z":["w"]}` reads back `{"z":["w"],"k":["v1","v2"]}`,
// which is `javamap.KeyOrder(["k","z"])` and neither insertion order nor
// sorted. The realm group family beside it serialises a Go map and would answer
// the other order; that is a divergence this cut found rather than one it adds,
// and it is recorded rather than fixed here because fixing it re-records
// another chapter's goldens.
type javaMapAttributes []namedValues

// javaMapRoleNames is `clientRoles`: a client id to the role names held on it.
// It is the same shape and the same reason, with the values as a name list.
type javaMapRoleNames []namedValues

// MarshalJSON writes the entries as a JSON object in the order they are held.
func (a javaMapAttributes) MarshalJSON() ([]byte, error) { return marshalJavaMap(a) }

// MarshalJSON writes the entries as a JSON object in the order they are held.
func (a javaMapRoleNames) MarshalJSON() ([]byte, error) { return marshalJavaMap(a) }

// namedValues is one entry of either map, kept beside its neighbours in the
// order javamap.KeyOrder put them in. model.StringPair is a Key/Value pair and
// both of these hold a **list** of values, so it does not fit.
type namedValues struct {
	Name   string
	Values []string
}

// marshalJavaMap writes name/values pairs as a JSON object, keeping the order.
//
// It goes through marshalOrderedValue rather than json.Marshal because a custom
// MarshalJSON cannot inherit the encoder's SetEscapeHTML(false), which
// orderedjson.go records as a divergence this repository shipped once.
func marshalJavaMap(pairs []namedValues) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(p.Name)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		values, err := marshalOrderedValue(p.Values)
		if err != nil {
			return nil, err
		}
		b.Write(values)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// orderJavaMap puts a decoded map into Keycloak's HashMap bucket order.
func orderJavaMap(in map[string][]string) []namedValues {
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	out := make([]namedValues, 0, len(names))
	for _, name := range javamap.KeyOrder(names) {
		out = append(out, namedValues{Name: name, Values: in[name]})
	}
	return out
}

// organizationGroupShape is which of the two bodies is being written. The two
// differ by three keys that arrive together, so one boolean would do - it is
// named instead because the *routes* disagree about which they serve in a way
// no parameter explains: the listing honours briefRepresentation and the
// children listing beside it ignores it, always answering the brief shape.
type organizationGroupShape int

const (
	// organizationGroupBrief is the listing's default, the children listing's
	// only shape, group-by-path's only shape and both creates' first body.
	organizationGroupBrief organizationGroupShape = iota
	// organizationGroupFull adds attributes, realmRoles and clientRoles. It is
	// the single read, the listing under briefRepresentation=false and the
	// child create's 201.
	organizationGroupFull
)

// organizationGroupRepresentationOf converts a stored group for the wire.
func organizationGroupRepresentationOf(g *model.Group, path string, shape organizationGroupShape,
	realmRoles []string, clientRoles []namedValues) organizationGroupRepresentation {
	rep := organizationGroupRepresentation{
		ID:       g.ID,
		Name:     g.Name,
		Path:     path,
		ParentID: g.ParentID,
		// Always present and always empty: nothing in this family expands the
		// tree, not even the search, which answers its matches flat.
		SubGroups: []organizationGroupRepresentation{},
	}
	if shape == organizationGroupFull {
		attrs := javaMapAttributes(orderJavaMap(g.Attributes))
		rep.Attributes = &attrs
		if realmRoles == nil {
			realmRoles = []string{}
		}
		rep.RealmRoles = &realmRoles
		roles := javaMapRoleNames(clientRoles)
		rep.ClientRoles = &roles
	}
	return rep
}

// organizationGroupPath is a group's path, and **the hidden root is not in it**.
//
// Measured on one organization: the root's own path is `/<organization id>`,
// which is its own name; a group directly under it is `/gp-top` and not
// `/<organization id>/gp-top`; a child of that is `/gp-top/gp-kid`. So the
// ancestry's first element is dropped whenever there is anything below it, and
// groupPath's plain walk - which the realm family shares - answers the
// organization id as a first segment on every group there is.
//
// ancestry is nearest last, which is what GroupRepo.Ancestry returns.
func organizationGroupPath(ancestry []*model.Group) string {
	if len(ancestry) > 1 {
		ancestry = ancestry[1:]
	}
	return groupPath(ancestry)
}

// organizationGroupPathOf resolves one group's path through the store.
func (h *handler) organizationGroupPathOf(ctx context.Context, realmID, groupID string) (string, error) {
	chain, err := h.store.Groups().Ancestry(ctx, realmID, groupID)
	if err != nil {
		return "", err
	}
	return organizationGroupPath(chain), nil
}

// organizationGroupOf builds one group's body, resolving whatever the shape
// needs. The full shape reads the group's role mappings, because **this family
// really does serve them**: a group holding four realm roles and one client
// role answers `"realmRoles":["aa-role","mm-role","ogattr","zz-role"]` and
// `"clientRoles":{"account":["ogcrole-a"]}` - sorted by name, measured on an
// insertion order that disagrees with it.
func (h *handler) organizationGroupOf(ctx context.Context, realmID string, g *model.Group,
	shape organizationGroupShape) (organizationGroupRepresentation, error) {
	path, err := h.organizationGroupPathOf(ctx, realmID, g.ID)
	if err != nil {
		return organizationGroupRepresentation{}, err
	}
	if shape != organizationGroupFull {
		return organizationGroupRepresentationOf(g, path, shape, nil, nil), nil
	}
	realmRoles, clientRoles, err := h.groupRoleNames(ctx, realmID, g.ID)
	if err != nil {
		return organizationGroupRepresentation{}, err
	}
	return organizationGroupRepresentationOf(g, path, shape, realmRoles, clientRoles), nil
}

// groupRoleNames reads a group's directly assigned roles as the two projections
// the full shape carries: realm role names sorted, and client role names by
// clientId in Keycloak's map order.
func (h *handler) groupRoleNames(ctx context.Context, realmID, groupID string) ([]string, []namedValues, error) {
	roles, err := h.store.Roles().ListGroupRoles(ctx, groupID)
	if err != nil {
		return nil, nil, err
	}
	var realmRoles []string
	byClient := map[string][]string{}
	for _, role := range roles {
		if role.ClientID == "" {
			realmRoles = append(realmRoles, role.Name)
			continue
		}
		c, err := h.store.Clients().ByID(ctx, realmID, role.ClientID)
		if err != nil {
			return nil, nil, err
		}
		byClient[c.ClientID] = append(byClient[c.ClientID], role.Name)
	}
	sort.Strings(realmRoles)
	for _, names := range byClient {
		sort.Strings(names)
	}
	return realmRoles, orderJavaMap(byClient), nil
}

// listOrganizationGroups serves GET /organizations/{org-id}/groups.
//
// **It answers the hidden root's children, and the root is never in it.**
//
// `search` is Keycloak's LIKE - each `*` becomes `%` and a trailing `%` is
// appended - and what comes back is **flat**: `?search=*rd` answered every
// group whose name contains `rd` at any depth, as top-level entries sorted by
// name, with `subGroups` still `[]`. The realm group listing answers the same
// match with the matches' top-level ancestors and the matches nested inside
// them, so searchGroups next door cannot be reused however similar the two
// listings look.
//
// `exact=true` narrows the search to an equal name and is honoured here where
// the realm listing has no such parameter. `populateHierarchy` and `top` are
// read and ignored, both values of each measured answering the same body.
func (h *handler) listOrganizationGroups(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	q := r.URL.Query()
	groups, ok := h.organizationGroupRows(w, r, rc, o, q)
	if !ok {
		return
	}
	groups = pageGroups(groups, q)

	shape := organizationGroupBrief
	if q.Get("briefRepresentation") == "false" {
		shape = organizationGroupFull
	}
	h.writeOrganizationGroups(w, r, rc, groups, shape)
}

// organizationGroupRows is the listing's row set: the root's children with no
// search, and every matching group in the organization with one.
func (h *handler) organizationGroupRows(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization, q url.Values) ([]*model.Group, bool) {
	search := q.Get("search")
	if search == "" {
		root, ok := h.organizationRoot(w, r, rc, o)
		if !ok {
			return nil, false
		}
		kids, err := h.store.Groups().ListChildren(r.Context(), rc.realm.ID, root.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return nil, false
		}
		return kids, true
	}
	all, err := h.store.Groups().ListOrganizationAll(r.Context(), rc.realm.ID, o.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	exact := q.Get("exact") == "true"
	out := make([]*model.Group, 0, len(all))
	for _, g := range all {
		if exact {
			if g.Name == search {
				out = append(out, g)
			}
			continue
		}
		if matchesSearch(g.Name, search) {
			out = append(out, g)
		}
	}
	return out, true
}

// writeOrganizationGroups writes a row set in one shape.
func (h *handler) writeOrganizationGroups(w http.ResponseWriter, r *http.Request, rc *reqContext,
	groups []*model.Group, shape organizationGroupShape) {
	out := make([]organizationGroupRepresentation, 0, len(groups))
	for _, g := range groups {
		rep, err := h.organizationGroupOf(r.Context(), rc.realm.ID, g, shape)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out = append(out, rep)
	}
	writeAdminJSON(w, out)
}

// readOrganizationGroup serves GET /organizations/{org-id}/groups/{group-id}.
//
// **The bare literal `group-by-path` is a group id here**, not the start of a
// path: `GET .../groups/group-by-path` with nothing after it answered
// `404 {"errorMessage":"Group does not exist"}`, where
// `.../groups/group-by-path/` with only a trailing slash answered
// `{"error":"Group path does not exist"}`. So the literal is dispatched by the
// routes that have a tail, and this one treats it as an id like any other.
func (h *handler) readOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	g, ok := h.organizationGroupFromPath(w, r, rc, o)
	if !ok {
		return
	}
	h.writeOrganizationGroup(w, r, rc, g, organizationGroupFull)
}

// organizationGroupByPathSegment is the literal that occupies the `{groupID}`
// slot on the read by path.
const organizationGroupByPathSegment = "group-by-path"

// readOrganizationGroupTail serves every GET under
// `.../groups/{groupID}/` that no more specific pattern matched.
//
// **It exists because `group-by-path` cannot have a pattern of its own.**
// `.../groups/group-by-path/{path...}` conflicts with every deeper pattern
// under `{groupID}` - `children`, `members`, `role-mappings` and its five
// descendants - because `/groups/group-by-path/children` matches both and
// neither is a strict subset of the other. Checked against Go 1.26.6 by
// registering the intended set one pattern at a time: **eight** panics, which
// is F153's shape and eight times its size. A single-segment `{path}` does not
// help, and the measured paths are multi-segment anyway.
//
// **The tail 404 it writes is measured rather than delegated**, and it is not
// the unmatched-path body. On a live 26.7.1, `.../groups/{g}/bogus`,
// `.../groups/{g}/role-mappings/bogus` and `GET .../groups/{g}/members/{u}` all
// answer `404 {"error":"HTTP 404 Not Found"}` **with all five security
// headers** - the "the router found nothing to run" body, because the request
// did reach the filter chain through the group's own sub-resource locator. So
// letting these fall through to WithKeycloakFallbacks, which answers
// `Unable to find matching target resource method` with none of the five, is
// what would be wrong here; this is the one place in this family where the
// catch-all is more faithful than the fallback.
//
// And the group is resolved **first**: `.../groups/{unknown}/children/deeper`
// answers `Group does not exist`, not the generic 404.
func (h *handler) readOrganizationGroupTail(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	if r.PathValue("groupID") == organizationGroupByPathSegment {
		h.readOrganizationGroupByPath(w, r, rc, o)
		return
	}
	if _, ok := h.organizationGroupFromPath(w, r, rc, o); !ok {
		return
	}
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}

// readOrganizationGroupByPath serves
// GET /organizations/{org-id}/groups/group-by-path/{path}.
//
// **It answers the brief shape**, where the realm's own group-by-path answers
// the single read minus `access`. Two routes with one name in two families, two
// bodies.
//
// The walk starts at the organization's hidden root, which is why
// `group-by-path/<organization id>/gp-top` is a 404 and `group-by-path/gp-top`
// is the group: the root is not a segment of any path.
func (h *handler) readOrganizationGroupByPath(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	root, ok := h.organizationRoot(w, r, rc, o)
	if !ok {
		return
	}
	segments := groupByPathSegments(organizationGroupTailOf(r))
	parentID := root.ID
	var found *model.Group
	for _, name := range segments {
		siblings, err := h.store.Groups().ListChildren(r.Context(), rc.realm.ID, parentID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		found = nil
		for _, s := range siblings {
			if s.Name == name {
				found = s
				break
			}
		}
		if found == nil {
			writeGroupPathNotFound(w)
			return
		}
		parentID = found.ID
	}
	if found == nil {
		writeGroupPathNotFound(w)
		return
	}
	h.writeOrganizationGroup(w, r, rc, found, organizationGroupBrief)
}

// organizationGroupTailOf is the path after the `group-by-path` segment.
//
// It is read off r.URL.Path rather than from a wildcard because the route has
// none - see readOrganizationGroup. net/http has already decoded the escapes,
// so `%2Fgp-top` and `/gp-top` arrive here the same way, which is what makes
// both measured 200s come out alike.
func organizationGroupTailOf(r *http.Request) string {
	marker := "/" + organizationGroupByPathSegment
	i := strings.LastIndex(r.URL.Path, marker)
	if i < 0 {
		return ""
	}
	return r.URL.Path[i+len(marker):]
}

// writeOrganizationGroup writes one group in one shape.
func (h *handler) writeOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	g *model.Group, shape organizationGroupShape) {
	rep, err := h.organizationGroupOf(r.Context(), rc.realm.ID, g, shape)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, rep)
}

// listOrganizationGroupChildren serves
// GET /organizations/{org-id}/groups/{group-id}/children.
//
// **It ignores briefRepresentation**, always answering the five-key shape -
// measured with both values, and the opposite of the realm family's children
// listing, which honours it and defaults to the *full* body. It pages on either
// bound, like the listing.
func (h *handler) listOrganizationGroupChildren(w http.ResponseWriter, r *http.Request, rc *reqContext, _ *model.Organization, g *model.Group) {
	kids, err := h.store.Groups().ListChildren(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeOrganizationGroups(w, r, rc, pageGroups(kids, r.URL.Query()), organizationGroupBrief)
}

// createOrganizationGroup serves POST /organizations/{org-id}/groups.
//
// **201 with the group in the body**, where the realm's own POST /groups
// answers 201 with an empty one. Its `Location` is under the organization -
// `/organizations/{org}/groups/{new id}` - and it carries **no Cache-Control**,
// where the child create one path segment down carries `no-cache`. Both
// measured on the same container minutes apart.
//
// A body carrying an `id` is a **move** rather than a create: 204 with an empty
// body. See moveOrganizationGroup.
func (h *handler) createOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	root, ok := h.organizationRoot(w, r, rc, o)
	if !ok {
		return
	}
	h.insertOrganizationGroup(w, r, rc, o, root, organizationGroupBrief, false)
}

// createOrganizationGroupChild serves
// POST /organizations/{org-id}/groups/{group-id}/children.
//
// 201 with the **full** body - the one place in this family where a create and
// its sibling create disagree about the shape - `application/json` with **no
// charset**, and `Cache-Control: no-cache`.
//
// **Its Location echoes the creating route**:
// `/organizations/{org}/groups/{parent}/children/{new id}`. The realm family's
// child create points at the addressing route instead, `/groups/{new id}`,
// which AGENTS.md records as "the route that makes a child is not the route
// that addresses it". Here it is.
func (h *handler) createOrganizationGroupChild(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization, parent *model.Group) {
	h.insertOrganizationGroup(w, r, rc, o, parent, organizationGroupFull, true)
}

// insertOrganizationGroup is what the two creates share, and the four things
// they do not are all arguments: the shape of the 201, the `Location`, the
// `Cache-Control` and the conflict sentence.
func (h *handler) insertOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization, parent *model.Group, shape organizationGroupShape, child bool) {
	var body organizationGroupBody
	if !decodeStrict(w, r, "GroupRepresentation", &body) {
		return
	}
	// **The name is checked before the move**, measured: a body naming an id
	// and no name is `400 Group name is missing`, and one naming an id and a
	// *different* name is a 204 that moves the group and leaves its name alone.
	// So the name is validated and then discarded on the move path.
	if body.Name == "" {
		writeGroupNameMissing(w)
		return
	}
	if body.ID != "" {
		h.moveOrganizationGroup(w, r, rc, o, parent, body.ID, child)
		return
	}

	g := &model.Group{
		ID:             model.NewID(),
		RealmID:        rc.realm.ID,
		ParentID:       parent.ID,
		Name:           body.Name,
		OrganizationID: o.ID,
		Attributes:     body.Attributes,
	}
	if err := h.store.Groups().Create(r.Context(), g); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeOrganizationGroupConflict(w, child)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	path, err := h.organizationGroupPathOf(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	base := h.issuerBase + "/admin/realms/" + rc.realm.Name + "/organizations/" + o.ID + "/groups/"
	if child {
		// The creating route, not the addressing one.
		base += parent.ID + "/children/"
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Set("Location", base+g.ID)
	var realmRoles []string
	var clientRoles []namedValues
	// **application/json with no charset**, on both creates.
	httpx.WriteJSON(w, http.StatusCreated,
		organizationGroupRepresentationOf(g, path, shape, realmRoles, clientRoles))
}

// moveOrganizationGroup is the half of both creates that a body's `id`
// selects: 204 with an empty body, `application/json` and no group written.
//
// Three refusals, each measured with its own request:
//
//	an id that resolves to nothing         404 {"error":"Could not find group by id"}
//	a group of the realm rather than an
//	  organization                         400 {"errorMessage":"Can only move organization groups"}
//	a group of a **different** organization 400 {"errorMessage":"Group does not belong to this organization"}
//
// The first is the *realm* group family's not-found spelling on a route whose
// every other 404 is `Group does not exist`, so one endpoint answers two
// spellings depending on which of the two things went missing.
func (h *handler) moveOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization, parent *model.Group, id string, child bool) {
	g, err := h.store.Groups().ByID(r.Context(), rc.realm.ID, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeGroupNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if g.OrganizationID == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Can only move organization groups")
		return
	}
	if g.OrganizationID != o.ID {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Group does not belong to this organization")
		return
	}
	switch err := h.store.Groups().Move(r.Context(), rc.realm.ID, g.ID, parent.ID); {
	case errors.Is(err, store.ErrConflict):
		writeOrganizationGroupConflict(w, child)
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if child {
		w.Header().Set("Cache-Control", "no-cache")
	}
	// The 204 carries a Content-Type although it has no body, on both routes.
	w.Header().Set("Content-Type", "application/json")
	httpx.WriteNoContent(w, r)
}

// updateOrganizationGroup serves PUT /organizations/{org-id}/groups/{group-id}.
//
// 204, and it is the one write in this family that behaves exactly like its
// realm sibling: a rename moves every descendant's `path`, `attributes` sent in
// the body replace the stored ones and a body naming none leaves them.
//
// The body is decoded **strictly and after the group is resolved**: an unknown
// field on a group that does not exist answers the 404.
func (h *handler) updateOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	_ *model.Organization, g *model.Group) {
	var body organizationGroupBody
	if !decodeStrict(w, r, "GroupRepresentation", &body) {
		return
	}
	if body.Name == "" {
		writeGroupNameMissing(w)
		return
	}
	g.Name = body.Name
	if body.Attributes != nil {
		g.Attributes = body.Attributes
	}
	if err := h.store.Groups().Update(r.Context(), g); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeOrganizationGroupConflict(w, g.ParentID != "")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteOrganizationGroup serves DELETE
// /organizations/{org-id}/groups/{group-id}: 204, no Cache-Control, and four of
// the five security headers because the request carries no Content-Type.
//
// **The hidden root is deletable and doing it destroys the organization** -
// measured, and reproduced no further than the 204: on a live 26.7.1 the
// organization's own read then answers 500 and its group create answers
// `400 {"errorMessage":"Organization group <id> not found"}`. Gloak refuses
// nothing here that Keycloak accepts, and the wreckage afterwards is not
// something this project has a way to serve.
func (h *handler) deleteOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	_ *model.Organization, g *model.Group) {
	if err := h.store.Groups().Delete(r.Context(), rc.realm.ID, g.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationGroupNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// listOrganizationGroupMembers serves
// GET /organizations/{org-id}/groups/{group-id}/members.
//
// **It serves the organization member representation**, `membershipType` and
// all, not the user shape the realm family's group members listing serves.
//
// **briefRepresentation defaults to false here and to true on
// `GET /organizations/{org}/members` one path segment up** - one parameter, one
// representation, two defaults, measured with all three values on both routes.
//
// It pages on either bound and reads nothing else: `search`, `exact` and
// `membershipType` are all accepted and ignored, measured against a two-member
// group where the member listing next door honours all three and the count
// beside *that* honours none. Three routes on one resource, three answers.
func (h *handler) listOrganizationGroupMembers(w http.ResponseWriter, r *http.Request, rc *reqContext,
	_ *model.Organization, g *model.Group) {
	users, err := h.store.Groups().Members(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	q := r.URL.Query()
	users = pageGroups(users, q)
	brief := q.Get("briefRepresentation") == "true"
	out := make([]organizationMemberRepresentation, 0, len(users))
	for _, u := range users {
		out = append(out, organizationMemberOf(u, brief))
	}
	writeAdminJSON(w, out)
}

// joinOrganizationGroup serves
// PUT /organizations/{org-id}/groups/{group-id}/members/{userId}.
//
// **It is not idempotent**, where the realm family's
// `PUT /users/{id}/groups/{groupId}` is: the repeat is
// `409 {"errorMessage":"User is already a member of the group"}`, measured
// twice over on one container in the same sweep that measured the realm route
// answering 204 twice.
//
// A user who is not a member of the **organization** is
// `400 {"errorMessage":"User is not member of the organization"}` - so the
// group membership is a narrowing of the organization membership rather than a
// second, independent one.
func (h *handler) joinOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization, g *model.Group) {
	u, ok := h.organizationGroupMemberUser(w, r, rc)
	if !ok {
		return
	}
	member, err := h.store.Organizations().IsMember(r.Context(), o.ID, u.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !member {
		httpx.WriteAdminError(w, http.StatusBadRequest, "User is not member of the organization")
		return
	}
	held, err := h.store.Groups().Members(r.Context(), rc.realm.ID, g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	for _, m := range held {
		if m.ID == u.ID {
			httpx.WriteAdminError(w, http.StatusConflict, "User is already a member of the group")
			return
		}
	}
	if err := h.store.Groups().AddMember(r.Context(), g.ID, u.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMembershipNoContent(w, r)
}

// leaveOrganizationGroup serves
// DELETE /organizations/{org-id}/groups/{group-id}/members/{userId}.
//
// **204 whatever the state**, which is the half of the pair that does match the
// realm family: a user who was never in the group, a user who is not a member
// of the organization at all and a repeat all answer 204. Only an unknown user
// is refused, and the two verbs agree about that one.
func (h *handler) leaveOrganizationGroup(w http.ResponseWriter, r *http.Request, rc *reqContext,
	_ *model.Organization, g *model.Group) {
	u, ok := h.organizationGroupMemberUser(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Groups().RemoveMember(r.Context(), g.ID, u.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMembershipNoContent(w, r)
}

// organizationGroupMemberUser resolves the {userID} segment, and then checks
// `manage-users` - **in that order**, which is what the sweep found.
//
// A `manage-organizations` caller holding no user role naming an unknown user
// gets `404 {"errorMessage":"User does not exist"}` and the same caller naming
// a real one gets 403, so the user is fetched before the second family's role
// is judged. The group and the organization's own write role are already
// behind it - see guardOrganizationGroupOf - which makes the chain five deep:
// tag read role, organization, group, organization write role, user,
// manage-users.
//
// `User does not exist` is a **404** here and the invitation family answers the
// same words with a 400, so the two are separate spellings rather than one
// shared string.
func (h *handler) organizationGroupMemberUser(w http.ResponseWriter, r *http.Request,
	rc *reqContext) (*model.User, bool) {
	u, err := h.store.Users().ByID(r.Context(), rc.realm.ID, r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteAdminError(w, http.StatusNotFound, "User does not exist")
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if !rc.caller.hasAny(organizationMemberWriteRoles) {
		writeForbidden(w)
		return nil, false
	}
	return u, true
}

// organizationGroupBody is what the three writes decode.
//
// **All three decode strictly**, and all three report a position:
// `{"error":"Invalid json representation for GroupRepresentation.
// Unrecognized field \"bogusField\" at line 1 column 32."}`. That makes eleven
// strict decoders on this API where AGENTS.md's bullet lists ten - and the
// realm family's own `POST /groups`, measured as a control in the same sweep,
// is a twelfth that is also not on it.
//
// The four fields below `Name` are decoded and discarded because the server
// accepts them: `path`, `subGroups` and `parentId` in a create body were each
// measured 201 and each ignored, where a field this struct did not name would
// be the 400 above.
type organizationGroupBody struct {
	// ID selects the move. It is not a caller-chosen id the way
	// POST /clients' is: a create carrying an id that resolves to nothing is a
	// 404 rather than a create with that id.
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Path       string              `json:"path"`
	ParentID   string              `json:"parentId"`
	SubGroups  []json.RawMessage   `json:"subGroups"`
	Attributes map[string][]string `json:"attributes"`
	// RealmRoles and ClientRoles are read and **not applied**: a create naming
	// `"realmRoles":["ogrole-a"]` answered 201 and the group's realm mappings
	// were `[]`.
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
}

// organizationRoot resolves the hidden root group Keycloak creates with an
// organization.
func (h *handler) organizationRoot(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization) (*model.Group, bool) {
	root, err := h.store.Groups().OrganizationRoot(r.Context(), rc.realm.ID, o.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return root, true
}

// organizationGroupFromPath resolves the {groupID} segment.
//
// **Three answers, not two.** An id that resolves to nothing is
// `404 {"errorMessage":"Group does not exist"}`; one naming a group of a
// *different* organization is `400 {"errorMessage":"Group does not belong to
// the organization"}` - a 400 rather than a 404, and one word away from the
// move's `...to this organization`, which is the same condition on the same
// resource one code path apart.
func (h *handler) organizationGroupFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext,
	o *model.Organization) (*model.Group, bool) {
	g, err := h.store.Groups().ByID(r.Context(), rc.realm.ID, r.PathValue("groupID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationGroupNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if g.OrganizationID != o.ID {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Group does not belong to the organization")
		return nil, false
	}
	return g, true
}

// writeOrganizationGroupNotFound is the 404 twenty-one of the twenty-two routes
// answer for a group that does not exist. The twenty-second is the create's
// move path, which answers the realm family's `Could not find group by id` -
// see moveOrganizationGroup.
func writeOrganizationGroupNotFound(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusNotFound, "Group does not exist")
}

// writeGroupNameMissing is the 400 the two creates and the update share. The
// realm family answers the same words for the same condition, measured on both
// in one sweep, which is why this is the one string in the family that is
// shared rather than doubled.
func writeGroupNameMissing(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusBadRequest, "Group name is missing")
}

// writeOrganizationGroupConflict is the duplicate-name 409, and **its two
// sentences differ from the realm family's and from each other**:
//
//	org   top level  Group with the given name already exists.        with a full stop
//	org   sibling    Sibling group with the given name already exists  without one
//	realm top level  Top level group named 'x' already exists.
//	realm sibling    Sibling group named 'x' already exists.
//
// One condition, four sentences over two families; the organization's pair
// neither quotes the name nor agrees with itself about the full stop.
func writeOrganizationGroupConflict(w http.ResponseWriter, child bool) {
	if child {
		httpx.WriteAdminError(w, http.StatusConflict, "Sibling group with the given name already exists")
		return
	}
	httpx.WriteAdminError(w, http.StatusConflict, "Group with the given name already exists.")
}
