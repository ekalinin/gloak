package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

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
// roles-by-id has its own, different message - see writeRoleIDNotFound - and a
// role rejected by a role-mapping write has a third. Three spellings, one
// resource; all measured.
//
// WriteMessageError, not WriteAdminError: this is `{"error":...}` and the 409
// beside it is `{"errorMessage":...}`. Two shapes on one resource, measured.
func writeRoleNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find role")
}

// writeRoleList is the body every role listing in this file sends: sorted by
// name, in the shape briefRepresentation asks for, with the measured
// Cache-Control and charset Content-Type.
func (h *handler) writeRoleList(w http.ResponseWriter, r *http.Request, roles []*model.Role, containerID string) {
	brief := briefRoles(r.URL.Query())
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
func (h *handler) addComposites(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return h.eachComposite(locate, func(ctx context.Context, roleID, childID string) error {
		err := h.store.Roles().AddComposite(ctx, roleID, childID)
		if errors.Is(err, store.ErrConflict) {
			// Already a child. Measured 204, not 409.
			return nil
		}
		return err
	}, h.markComposite)
}

// markComposite flips the parent's own composite flag to true once it has
// gained a child. Measured on a live Keycloak: reading the parent back after
// POST .../composites shows composite:true without being asked for it.
// Neither store driver's AddComposite does this itself - both round-trip a
// composite parent only because storetest's conformance cases build it with
// the flag already set by hand - so it is done here instead, once per write
// rather than once per child.
func (h *handler) markComposite(ctx context.Context, role *model.Role) error {
	if role.Composite {
		return nil
	}
	updated := *role
	updated.Composite = true
	return h.store.Roles().Update(ctx, &updated)
}

// removeComposites serves DELETE .../composites. Removing one that is not
// there is 204, measured.
func (h *handler) removeComposites(locate roleLocator) func(http.ResponseWriter, *http.Request, *reqContext) {
	return h.eachComposite(locate, func(ctx context.Context, roleID, childID string) error {
		return h.store.Roles().RemoveComposite(ctx, roleID, childID)
	}, nil)
}

// eachComposite is what addComposites and removeComposites share: resolve the
// role, decode the body, apply the per-child operation to each entry, then
// run the optional whole-role step once before answering. after is nil for
// removeComposites, which has nothing whole-role to do.
func (h *handler) eachComposite(locate roleLocator, apply func(context.Context, string, string) error, after func(context.Context, *model.Role) error) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		role, ok := locate(w, r, rc)
		if !ok {
			return
		}
		reps, ok := decodeRoleList(w, r)
		if !ok {
			return
		}
		for _, rep := range reps {
			if _, err := h.store.Roles().ByID(r.Context(), rc.realm.ID, rep.ID); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeRoleNotFound(w)
					return
				}
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if err := apply(r.Context(), role.ID, rep.ID); err != nil {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
		if after != nil {
			if err := after(r.Context(), role); err != nil {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
		httpx.WriteNoContent(w, r)
	}
}

// decodeRoleList reads the array body the composite and role-mapping writes
// take. A body that is not an array answers the measured 400.
func decodeRoleList(w http.ResponseWriter, r *http.Request) ([]roleRepresentation, bool) {
	var reps []roleRepresentation
	if err := json.NewDecoder(r.Body).Decode(&reps); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return nil, false
	}
	return reps, true
}
