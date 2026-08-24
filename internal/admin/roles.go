package admin

import (
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
