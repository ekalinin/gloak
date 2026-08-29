package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// listRealmRoles serves GET /admin/realms/{realm}/roles.
//
// The order Keycloak returns is not reproduced and cannot be: measured across
// three container starts, the five bootstrapped roles came back in three
// different orders. It is a Java set, like scopes_supported. This sorts by
// name, which is deterministic, and the conformance case says so with
// Case.Unordered over the document root.
func (h *handler) listRealmRoles(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	roles, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeRoleList(w, r, filterRoles(roles, r.URL.Query().Get("search")), rc.realm.ID)
}

// readRealmRole serves GET /admin/realms/{realm}/roles/{role-name}.
func (h *handler) readRealmRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	role, ok := h.realmRole(w, r, rc)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, roleRepresentationOf(role, rc.realm.ID, false))
}

// realmRole resolves {role-name} under the realm, writing the measured 404 and
// returning false when there is none.
func (h *handler) realmRole(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Role, bool) {
	role, err := h.store.Roles().ByName(r.Context(), rc.realm.ID, "", r.PathValue("roleName"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeRoleNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return role, true
}

// writeRoleNotFound is the measured 404 for a role addressed by name.
// roles-by-id has its own, different message - see writeRoleIDNotFound - a bad
// id in a composite batch has a third, see writeCompositeRoleNotFound, and a
// role rejected by a role-mapping write has a fourth, see
// writeMappingRoleNotFound. Four spellings, one resource; all measured.
//
// WriteMessageError, not WriteAdminError: this is `{"error":...}` and the 409
// beside it is `{"errorMessage":...}`. Two shapes on one resource, measured.
func writeRoleNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find role")
}

// writeCompositeRoleNotFound is the measured 404 for POST/DELETE
// .../composites when one of the body's ids does not resolve to a role -
// "Could not find composite role", not writeRoleNotFound's "Could not find
// role". A resource addressed by name, by id and now by a bad entry in a
// composite batch each get their own spelling; see eachComposite for why
// this one specifically means nothing in the batch was applied.
func writeCompositeRoleNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find composite role")
}

// manageRoleForContainer is the manage role a role's own container needs:
// manage-realm for a realm role, manage-clients for a client role. Used by
// requiresChildManageRole below.
func manageRoleForContainer(role *model.Role) string {
	if role.ClientID != "" {
		return "manage-clients"
	}
	return "manage-realm"
}

// requiresChildManageRole is one half of eachComposite's per-child check on
// the **add** path - see addComposites and the asymmetry note on eachComposite
// below for why removeComposites passes nil instead of mayAttachChild.
func requiresChildManageRole(c *caller, child *model.Role) bool {
	return c.has(manageRoleForContainer(child))
}

// mayAttachChild is what addComposites passes eachComposite as checkChild: the
// two measured per-child rules, in the order their 403s cannot tell apart.
//
// Both are add-only. The child's own manage role was measured asymmetric
// between the verbs long ago; the caller-relative one was measured the same way
// in the F28 pass and agrees - a caller holding manage-realm and manage-clients
// is refused `POST` naming `admin` and allowed `DELETE` of the same child off
// the same parent, 204, with the parent left without it.
func (h *handler) mayAttachChild(ctx context.Context, rc *reqContext, child *model.Role) (bool, error) {
	if !requiresChildManageRole(rc.caller, child) {
		return false, nil
	}
	return h.mayGrantRole(ctx, rc.realm, rc.caller, child)
}

// writeRoleList is the body every role listing in this file sends: sorted by
// name, paged by pageRoles, in the shape briefRepresentation asks for, with
// the measured Cache-Control and charset Content-Type.
func (h *handler) writeRoleList(w http.ResponseWriter, r *http.Request, roles []*model.Role, containerID string) {
	brief := briefRoles(r.URL.Query())
	roles = pageRoles(roles, r.URL.Query())
	out := make([]roleRepresentation, 0, len(roles))
	for _, role := range roles {
		out = append(out, roleRepresentationOf(role, containerID, brief))
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}

// filterRoles applies the listing's search parameter: a case-insensitive
// substring over the name **and the description**.
//
// All three halves of that are measured, each ruling out a simpler rule.
// "ealm" finds create-realm, so it is not a prefix. "{role_default-roles}"
// finds default-roles-master, whose name does not contain it, so it is not
// name-only. "ADM" finds admin, so it is not case-sensitive.
func filterRoles(roles []*model.Role, search string) []*model.Role {
	if search == "" {
		return roles
	}
	needle := strings.ToLower(search)
	out := make([]*model.Role, 0, len(roles))
	for _, r := range roles {
		if strings.Contains(strings.ToLower(r.Name), needle) ||
			strings.Contains(strings.ToLower(r.Description), needle) {
			out = append(out, r)
		}
	}
	return out
}

// pageRoles applies the listing's first and max parameters to roles, which
// has already been through filterRoles. writeRoleList is shared by the realm
// listing (listRealmRoles) and the client listing (listClientRoles), and both
// were measured on a live 26.7.1 to follow the same rule - see the "Role
// listing: first and max" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// **Measured, not predicted: the listing pages when search is non-empty, or
// when first and max are both present.** Either condition on its own is
// enough. A request carrying neither - no search and at most one of the two
// bounds - is answered with every role, unpaginated.
//
// That second condition is why max=2 alone and first=1 alone are ignored
// while first=1&max=5 is not, and it is the whole of the difference: measured
// against 18 realm roles created in reverse-alphabetical order, first=1&max=5
// with no search returns exactly five roles and max=5 with no search returns
// all 23. It also explains the one thing the earlier "search only" rule could
// not, that first=-1&max=-1 came back sorted where max=2 came back unsorted:
// both bounds are present there, so it takes this path too, and a negative
// bound then means "no bound" rather than "do not page".
//
// **The paged path is sorted by name.** Measured on both listings: the same
// 18 roles created z..i come back i..z whenever this path is taken, with or
// without search, while the unpaginated path keeps the unstable Java-set
// order listRealmRoles documents. Gloak sorts every listing by name in the
// store (both drivers ORDER BY name), so it already matches here and diverges
// only on the unpaginated path, which is what Case.Unordered covers.
//
// first is a zero-based offset and max a page size, counted over that sorted
// order; an absent or negative value means no bound, on both listings. A
// negative bound was measured to mean "no bound" with search and without it -
// the same shape the Java admin client puts on the wire for "no paging",
// since it sends first=-1&max=-1 rather than omitting them.
//
// An empty search is not a non-empty one: search=&max=2 was measured
// unpaginated, and search=&first=1&max=5 paged only because both bounds are
// there. q.Get("search") == "" covers both, which is why the gate below reads
// the value rather than only asking whether the parameter was sent.
//
// An unparseable value (first=abc) is treated as no bound, but that is
// Gloak's own choice, not something measured: the real admin client always
// sends a well-formed integer or omits the parameter, so a live 26.7.1's
// behaviour on a malformed one was never probed. Note it still opens the gate,
// because q.Has is about the parameter being sent, not about it parsing.
func pageRoles(roles []*model.Role, q url.Values) []*model.Role {
	if q.Get("search") == "" && !(q.Has("first") && q.Has("max")) {
		return roles
	}

	bound := func(name string) int {
		v, err := strconv.Atoi(q.Get(name))
		if err != nil || v < 0 {
			return -1
		}
		return v
	}

	out := roles
	if first := bound("first"); first >= 0 {
		if first >= len(out) {
			return []*model.Role{}
		}
		out = out[first:]
	}
	if max := bound("max"); max >= 0 && max < len(out) {
		out = out[:max]
	}
	return out
}

// createRealmRole serves POST /admin/realms/{realm}/roles.
//
// Measured: 201 with an empty body, Content-Length 0, and a Location naming
// the role **by name** - the client and user creates both put a UUID there.
func (h *handler) createRealmRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeRole(w, r)
	if !ok {
		return
	}
	if rep.Name == "" {
		writeRoleHasNoName(w)
		return
	}
	m := &model.Role{
		ID: model.NewID(), RealmID: rc.realm.ID, Name: rep.Name,
		Description: rep.Description,
	}
	if rep.Attributes != nil {
		m.Attributes = *rep.Attributes
	}
	if err := h.store.Roles().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeRoleConflict(w, rep.Name)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/roles/"+m.Name)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// updateRealmRole serves PUT /admin/realms/{realm}/roles/{role-name}.
//
// **This replaces, where the client and user updates merge.** Measured: a body
// carrying only a name clears an existing description. Do not copy
// updateClient's shape here; it unmarshals over the current representation on
// purpose and this must not.
//
// It also renames: the id survives and the old path 404s.
func (h *handler) updateRealmRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	current, ok := h.realmRole(w, r, rc)
	if !ok {
		return
	}
	h.applyRoleUpdate(w, r, current)
}

// applyRoleUpdate is the half of the update that does not depend on how the
// role was addressed, so realm roles, client roles and roles-by-id share it.
func (h *handler) applyRoleUpdate(w http.ResponseWriter, r *http.Request, current *model.Role) {
	rep, ok := decodeRole(w, r)
	if !ok {
		return
	}
	if rep.Name == "" {
		writeRoleHasNoName(w)
		return
	}
	updated := &model.Role{
		ID: current.ID, RealmID: current.RealmID, ClientID: current.ClientID,
		Name: rep.Name, Description: rep.Description, Composite: current.Composite,
	}
	if rep.Attributes != nil {
		updated.Attributes = *rep.Attributes
	}
	if err := h.store.Roles().Update(r.Context(), updated); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeRoleConflict(w, rep.Name)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteRealmRole serves DELETE /admin/realms/{realm}/roles/{role-name}.
// Measured: 204 carrying Cache-Control: no-cache.
func (h *handler) deleteRealmRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	role, ok := h.realmRole(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Roles().Delete(r.Context(), rc.realm.ID, role.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// decodeRole reads a RoleRepresentation from the request body.
func decodeRole(w http.ResponseWriter, r *http.Request) (roleRepresentation, bool) {
	var rep roleRepresentation
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return rep, false
	}
	return rep, true
}

// writeRoleHasNoName is the measured 400 for a create or an update with no
// name. Note the lowercase prose: the 404 two lines down is sentence case, and
// the 409 uses a different shape again.
func writeRoleHasNoName(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusBadRequest, "role has no name")
}

func writeRoleConflict(w http.ResponseWriter, name string) {
	httpx.WriteAdminError(w, http.StatusConflict, "Role with name "+name+" already exists")
}

// clientRoleContainer resolves {client-uuid}, writing the client's own
// measured 404 - "Could not find client", not the role's message - and
// returning false when there is none.
func (h *handler) clientRoleContainer(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, bool) {
	c, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return c, true
}

// ownedByRealmOwnClient reports whether role belongs to a client that carries a
// realm's admin roles - the container Keycloak refuses to reconfigure.
//
// **Two spellings, and a suffix.** Keycloak keeps the master realm's admin roles
// on `master-realm` and every other realm's on that realm's own
// `realm-management` client, which internal/bootstrap.AdminContainerFor names.
// Master also holds a `{realm}-realm` client per realm, carrying the rights to
// administer it from outside. Until this cut Gloak bootstrapped only master, so
// only the first spelling was reachable and this function tested only it; the
// comment here said in as many words that whoever added realm creation had to
// add the others in the same change, because every admin role outside master
// would otherwise answer false and become grantable to anyone.
//
// The suffix half is measured, and it is wider than "names a realm that
// exists": a client called `nosuch-realm` created by hand in master, naming no
// realm at all, answers 403 to `POST .../roles` and carries
// `"configure":false` exactly as `master-realm` does. So the test is on the
// name and not on the realm behind it, and adding a realm lookup here would be
// stricter than Keycloak.
//
// A realm role can never be owned by a client, so it answers false without a
// lookup.
func (h *handler) ownedByRealmOwnClient(ctx context.Context, realm *model.Realm, role *model.Role) (bool, error) {
	if role.ClientID == "" {
		return false, nil
	}
	c, err := h.store.Clients().ByID(ctx, realm.ID, role.ClientID)
	if err != nil {
		return false, err
	}
	return isAdminContainerName(realm.Name, c.ClientID), nil
}

// isAdminContainerName reports whether a clientId names a client that carries
// admin roles, as seen from within realmName.
//
// Measured on seven clients across two realms: master-realm, other-realm and
// nosuch-realm in master all answer `"configure":false`, realm-management in a
// created realm does too, and broker and account in both realms are fully
// manageable although broker carries `realm_client: "true"` - so the attribute
// is not the test and the name is.
func isAdminContainerName(realmName, clientID string) bool {
	return clientID == bootstrap.AdminContainerFor(realmName) ||
		strings.HasSuffix(clientID, "-realm")
}

// listClientRoles serves GET /admin/realms/{realm}/clients/{client-uuid}/roles.
func (h *handler) listClientRoles(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	c, ok := h.clientRoleContainer(w, r, rc)
	if !ok {
		return
	}
	roles, err := h.store.Roles().ListClientRoles(r.Context(), rc.realm.ID, c.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeRoleList(w, r, filterRoles(roles, r.URL.Query().Get("search")), c.ID)
}

// readClientRole serves GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}.
func (h *handler) readClientRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	c, role, ok := h.clientRole(w, r, rc)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, roleRepresentationOf(role, c.ID, false))
}

// clientRole resolves both {client-uuid} and {role-name}.
func (h *handler) clientRole(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, *model.Role, bool) {
	c, ok := h.clientRoleContainer(w, r, rc)
	if !ok {
		return nil, nil, false
	}
	role, err := h.store.Roles().ByName(r.Context(), rc.realm.ID, c.ID, r.PathValue("roleName"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeRoleNotFound(w)
			return nil, nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, nil, false
	}
	return c, role, true
}

// createClientRole serves POST /admin/realms/{realm}/clients/{client-uuid}/roles.
func (h *handler) createClientRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	c, ok := h.clientRoleContainer(w, r, rc)
	if !ok {
		return
	}
	// Measured: the realm's own client refuses a new role even to a full
	// administrator. Reading its 21 is still allowed, so this is on the create
	// alone. internal/bootstrap names that client "{realm}-realm" -
	// adminRoleContainer there, unexported - so it is rebuilt here.
	if c.ClientID == rc.realm.Name+"-realm" {
		writeForbidden(w)
		return
	}
	rep, ok := decodeRole(w, r)
	if !ok {
		return
	}
	if rep.Name == "" {
		writeRoleHasNoName(w)
		return
	}
	m := &model.Role{
		ID: model.NewID(), RealmID: rc.realm.ID, ClientID: c.ID,
		Name: rep.Name, Description: rep.Description,
	}
	if rep.Attributes != nil {
		m.Attributes = *rep.Attributes
	}
	if err := h.store.Roles().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeRoleConflict(w, rep.Name)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location",
		h.issuerBase+"/admin/realms/"+rc.realm.Name+"/clients/"+c.ID+"/roles/"+m.Name)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// updateClientRole serves PUT /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}.
func (h *handler) updateClientRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	_, role, ok := h.clientRole(w, r, rc)
	if !ok {
		return
	}
	h.applyRoleUpdate(w, r, role)
}

// deleteClientRole serves DELETE /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}.
func (h *handler) deleteClientRole(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	_, role, ok := h.clientRole(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.Roles().Delete(r.Context(), rc.realm.ID, role.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// roleLocator finds the role a composite route acts on. The realm and client
// forms of every composite endpoint differ in nothing else, so this is the
// whole of the difference between the ten routes.
type roleLocator func(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Role, bool)

// h.realmRole already has this signature, so it is a roleLocator as it stands
// and is passed directly at the call sites in router.go.
// h.clientRole returns the client too, so it needs this wrapper.
func (h *handler) clientRoleLocator(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Role, bool) {
	_, role, ok := h.clientRole(w, r, rc)
	return role, ok
}

// listComposites serves GET .../composites and its two filtered forms. filter
// decides which children survive; nil keeps them all.
func (h *handler) listComposites(locate roleLocator, filter func(*model.Role, *http.Request) bool) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		role, ok := locate(w, r, rc)
		if !ok {
			return
		}
		children, err := h.store.Roles().ListComposites(r.Context(), role.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out := make([]roleRepresentation, 0, len(children))
		for _, c := range children {
			if filter != nil && !filter(c, r) {
				continue
			}
			container := rc.realm.ID
			if c.ClientID != "" {
				container = c.ClientID
			}
			// Measured directly against briefRepresentation=false: a composite
			// listing still carries no "attributes" key, so it stays brief
			// regardless of the parameter. Passing true rather than
			// briefRoles(...) is deliberate, not an oversight.
			out = append(out, roleRepresentationOf(c, container, true))
		}
		// No sort here: ListComposites already orders by name in both drivers,
		// and filtering a sorted slice keeps it sorted.
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteJSONCharset(w, http.StatusOK, out)
	}
}

// onlyRealmRoles and onlyThisClientsRoles are the two filters.
func onlyRealmRoles(c *model.Role, _ *http.Request) bool { return c.ClientID == "" }

func onlyThisClientsRoles(c *model.Role, r *http.Request) bool {
	return c.ClientID == r.PathValue("targetClientUUID")
}

// addComposites serves POST .../composites. The body is an array of role
// representations and only their ids are acted on.
//
// Passes mayAttachChild to eachComposite: measured on a live 26.7.1,
// attaching a child needs the manage role matching *that child's own*
// container, in addition to the parent-side manage role the route guard
// already checked, **and** the caller's own rights have to already confer the
// child when the child is an admin role. removeComposites below carries
// neither - measured separately on both rules, and the verbs do not match.
func (h *handler) addComposites(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return h.eachComposite(locate, h.mayAttachChild, func(ctx context.Context, roleID, childID string) error {
		err := h.store.Roles().AddComposite(ctx, roleID, childID)
		if errors.Is(err, store.ErrConflict) {
			// Already a child. Measured 204, not 409.
			return nil
		}
		return err
	})
}

// removeComposites serves DELETE .../composites. Removing one that is not
// there is 204, measured.
//
// Passes nil where addComposites passes mayAttachChild: measured on a live
// 26.7.1 (both directions - a client-role child removed from a realm-role
// parent, and the mirror), a caller holding only the parent-side manage role
// can remove a cross-family child with no check on the child's own container
// at all. Gloak used to apply the same per-child check to both verbs, on the
// reasoning that they should stay consistent absent a measurement showing
// otherwise; that measurement now exists and shows they differ, so this no
// longer runs it. Nobody knows why Keycloak draws this line only on the add
// side - it is recorded as measured and asymmetric, not rationalised.
//
// F28's caller-relative rule was measured on this verb rather than assumed to
// follow the one beside it, and it lands the same way: a caller holding
// manage-realm and manage-clients, refused `POST` naming `admin`, removes that
// same child with 204. So this stays nil for both rules, not one. The
// role-mapping writes next door are the counter-example that made it worth
// measuring - there the caller-relative rule **does** apply to `DELETE`.
func (h *handler) removeComposites(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return h.eachComposite(locate, nil, func(ctx context.Context, roleID, childID string) error {
		return h.store.Roles().RemoveComposite(ctx, roleID, childID)
	})
}

// eachComposite is what addComposites and removeComposites share: resolve
// the role, decode the body, validate every entry, apply each only once they
// all validate, then resync the parent's own composite flag before
// answering.
//
// **The batch validates in full before anything is applied.** Measured on a
// live Keycloak, in both id orders: a body of one real role id and one that
// does not exist applies neither and answers 404
// `{"error":"Could not find composite role"}` - a message of its own, not
// writeRoleNotFound's "Could not find role". So the two loops below are
// deliberately separate rather than merged into one: the first only reads,
// resolving every id before the second writes any of them, and nothing is
// applied unless every id resolves.
//
// checkChild is an extra per-child check run in that same first loop,
// immediately after a child resolves - addComposites passes mayAttachChild,
// removeComposites passes nil. It is a parameter rather than something the two
// verbs' shared loop always runs, because a live 26.7.1 was measured doing this
// asymmetrically: `POST .../composites` needs the manage role matching *each
// child's own* container in addition to the parent-side manage role the route
// guard already checked, and needs the caller's own rights to already confer an
// admin-role child, while `DELETE .../composites` needs neither - a caller
// holding only the parent-side manage role can remove a cross-family child, or
// `admin` itself, outright. Nobody knows why Keycloak only enforces these going
// one direction; they are implemented as measured, not as a guess at the
// reason. Threading the check through as a parameter, rather than duplicating
// this loop once per verb, keeps that asymmetry in one place instead of two
// copies that could drift.
//
// It returns an error as well as a verdict because the caller-relative half has
// to resolve the child's owning client to know whether the child is an admin
// role at all, and a store failure there is a 500 rather than a 403.
//
// checkChild runs in the same loop as the existence check, not a separate
// pass, so the two interleave per entry exactly as Keycloak's own validation
// does: measured with a batch mixing a nonexistent id and a cross-family id
// in both orders, whichever comes first in the array decides whether the
// batch answers 404 or 403.
//
// Because of that split, the store is only ever written on the path that
// goes on to answer 204 (or, in the rare case of a genuine store failure
// partway through an already-validated batch, the 500 in the apply loop
// below) - a decode failure and a validation failure both leave the role's
// children untouched, so neither of those needs to resync the flag. This
// replaces an earlier version that applied entries as it validated them and
// had to defer the resync to cover a partial-apply exit; once nothing partial
// can be applied, that defer was no longer needed.
func (h *handler) eachComposite(locate roleLocator, checkChild func(context.Context, *reqContext, *model.Role) (bool, error), apply func(context.Context, string, string) error) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		role, ok := locate(w, r, rc)
		if !ok {
			return
		}
		// A composite write on a role the realm's own client owns is refused
		// to **everybody**, the full administrator included - measured on a
		// live 26.7.1 on both verbs, POST and DELETE, against
		// `master-realm`'s own `query-groups`. Reading the same role's
		// composites stays 200, so this is on the two writes alone and must
		// not move up into a locator, which the reads share.
		//
		// It sits here rather than in clientRoleContainer because
		// clientRoleContainer is not on every path that gets here: the
		// roles-by-id routes resolve their role in guardByRoleContainer and
		// reach eachComposite through byIDLocator, never touching it. This is
		// the one place both route families meet.
		//
		// The refusal is decided after locate, so a role that does not exist
		// still answers its 404 rather than this 403 - the same
		// existence-before-authorization order guardByRoleContainer was
		// measured taking.
		refused, err := h.ownedByRealmOwnClient(r.Context(), rc.realm, role)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if refused {
			writeForbidden(w)
			return
		}
		reps, ok := decodeRoleList(w, r)
		if !ok {
			return
		}
		for _, rep := range reps {
			child, err := h.store.Roles().ByID(r.Context(), rc.realm.ID, rep.ID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeCompositeRoleNotFound(w)
					return
				}
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if checkChild != nil {
				allowed, err := checkChild(r.Context(), rc, child)
				if err != nil {
					httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
					return
				}
				if !allowed {
					writeForbidden(w)
					return
				}
			}
		}
		for _, rep := range reps {
			if err := apply(r.Context(), role.ID, rep.ID); err != nil {
				// Every id was already confirmed to exist above, so this can
				// only be a genuine store failure, not a bad id - and it may
				// have applied some of the batch before hitting it. Best-effort
				// resync so the flag does not go stale; its own error is
				// swallowed rather than risking a second write on top of the
				// 500 below.
				_ = h.syncCompositeFlag(r.Context(), role)
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
		if err := h.syncCompositeFlag(r.Context(), role); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		httpx.WriteNoContent(w, r)
	}
}

// syncCompositeFlag keeps the role's own composite flag derived from whether
// it currently has any children at all: true when it has at least one, false
// when it has none. Measured on a live Keycloak in both directions on the
// same role - composite flips to true when the first child is added, and
// back to false when the last one is removed - so this recomputes it fresh
// after every composite write rather than only setting it on add. Neither
// store driver's AddComposite/RemoveComposite touches the flag itself, so
// this runs once per write, after the loop in eachComposite, rather than
// once per child.
func (h *handler) syncCompositeFlag(ctx context.Context, role *model.Role) error {
	children, err := h.store.Roles().ListComposites(ctx, role.ID)
	if err != nil {
		return err
	}
	has := len(children) > 0
	if role.Composite == has {
		return nil
	}
	updated := *role
	updated.Composite = has
	return h.store.Roles().Update(ctx, &updated)
}

// roleUsers serves GET .../roles/{role-name}/users.
//
// Direct holders only - it must not go through internal/roles.Effective.
// Measured: the administrator appears for `admin` and not for `create-realm`,
// which `admin` is composite over.
//
// The user representation here carries **no access block**, which is the
// fourth serialisation of a user in this API and matches the service-account
// read.
func (h *handler) roleUsers(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		role, ok := locate(w, r, rc)
		if !ok {
			return
		}
		users, err := h.store.Roles().ListUsersWithRole(r.Context(), rc.realm.ID, role.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out := make([]userRepresentation, 0, len(users))
		for _, u := range users {
			// No Access assigned: absent is the measured shape here.
			out = append(out, userRepresentationOf(u, false))
		}
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteJSONCharset(w, http.StatusOK, out)
	}
}

// roleGroups serves GET .../roles/{role-name}/groups.
//
// Always empty, and correct: the realm has no groups until P2's third cut, and
// a realm with no groups answers [] - measured. When groups arrive this gains
// a body and needs no new route.
func (h *handler) roleGroups(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if _, ok := locate(w, r, rc); !ok {
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteJSONCharset(w, http.StatusOK, []struct{}{})
	}
}

// decodeRoleList reads the array body the composite and role-mapping writes
// take. A body that is not an array answers the measured 400.
//
// **unknown_error, not invalid_request.** This helper is reached from ten
// route registrations - the six eachComposite serves (realm role by name,
// client role by name and roles-by-id, POST and DELETE each) and the four
// role-mapping writes, realm and client - and **all ten were measured**,
// 2026-08-26, with a malformed body and a well-formed non-array body, plus both
// of guardByRoleContainer's branches for roles-by-id. Every one answers
// `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`, and
// the two bad-body forms are indistinguishable, so there is no
// parse-versus-shape split to model.
//
// The whole sweep is recorded rather than one route's, because an earlier draft
// of this comment measured POST .../composites alone and generalised - which is
// the inference this cut has reverted twice, and the role-mapping writes are
// themselves the case where POST and DELETE agreed while the composite writes'
// per-child check had them diverging.
//
// POST /users was re-measured alongside and still answers `invalid_request`
// for the same description, so the difference is per endpoint and not a change
// of version. That is the only object-taking endpoint re-measured in this pass;
// the six other "Cannot parse the JSON" call sites in this package keep
// `invalid_request` on their existing measurements, not on this one.
//
// The client role-mapping writes were the two the first sweep listed as
// uncovered, because they were not shipped when it ran. They shipped with the
// client half of the cut and were measured then; both answer `unknown_error`
// like the rest, which is what completes the sweep at ten.
func decodeRoleList(w http.ResponseWriter, r *http.Request) ([]roleRepresentation, bool) {
	var reps []roleRepresentation
	if err := json.NewDecoder(r.Body).Decode(&reps); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unknown_error", "Cannot parse the JSON")
		return nil, false
	}
	return reps, true
}

// writeRoleIDNotFound is the measured 404 for a role addressed by id. The
// by-name endpoints say "Could not find role" and a bad id in a composite
// batch says "Could not find composite role"; this is a third spelling for
// the same resource, measured on its own.
func writeRoleIDNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find role with id")
}

// byIDLocator adapts a role already resolved by guardByRoleContainer to the
// roleLocator the composite handlers take. guardByRoleContainer has already
// done the lookup - and the 404 that goes with it - so this only hands the
// result on; it cannot fail.
func byIDLocator(role *model.Role) roleLocator {
	return func(http.ResponseWriter, *http.Request, *reqContext) (*model.Role, bool) {
		return role, true
	}
}

// readRoleByID serves GET /admin/realms/{realm}/roles-by-id/{role-id}.
func (h *handler) readRoleByID(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
	container := rc.realm.ID
	if role.ClientID != "" {
		container = role.ClientID
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, roleRepresentationOf(role, container, false))
}

// updateRoleByID serves PUT /admin/realms/{realm}/roles-by-id/{role-id}. It
// shares applyRoleUpdate with the by-name update, so it replaces rather than
// merges the same way.
func (h *handler) updateRoleByID(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
	h.applyRoleUpdate(w, r, role)
}

// deleteRoleByID serves DELETE /admin/realms/{realm}/roles-by-id/{role-id}.
func (h *handler) deleteRoleByID(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
	if err := h.store.Roles().Delete(r.Context(), rc.realm.ID, role.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// compositesByID, addCompositesByID and removeCompositesByID wrap the Task 7
// composite handlers with byIDLocator: guardByRoleContainer has already
// resolved the role, so there is nothing left for these to locate.
func (h *handler) compositesByID(filter func(*model.Role, *http.Request) bool) func(http.ResponseWriter, *http.Request, *reqContext, *model.Role) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
		h.listComposites(byIDLocator(role), filter)(w, r, rc)
	}
}

func (h *handler) addCompositesByID(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
	h.addComposites(byIDLocator(role))(w, r, rc)
}

func (h *handler) removeCompositesByID(w http.ResponseWriter, r *http.Request, rc *reqContext, role *model.Role) {
	h.removeComposites(byIDLocator(role))(w, r, rc)
}
