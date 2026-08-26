package admin

import (
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// listRealmMappings serves GET /users/{id}/role-mappings/realm: the realm roles
// assigned **directly**, with no composite expansion.
//
// The brief shape is not negotiable here: measured on a live 26.7.1, this
// endpoint ignores briefRepresentation entirely and never carries an
// attributes key, where its composite sibling honours it. See
// writeMappingList.
func (h *handler) listRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, realmRolesOnly(direct), rc.realm.ID, true)
}

// compositeRealmMappings serves .../realm/composite: the transitive expansion.
//
// The one of the three that honours briefRepresentation - measured, not
// inferred from its siblings, which do not.
func (h *handler) compositeRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, realmRolesOnly(effective), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableRealmMappings serves .../realm/available: every realm role **not
// directly assigned**.
//
// It is the complement of the direct list, not of the composite one. Measured:
// create-realm is in the administrator's composite expansion *and* in its
// available list, because the administrator reaches it through admin without
// holding it directly. Computing this from the effective set would silently
// drop it.
//
// **Keycloak also filters this list by what the caller may grant**, and that
// part is not implemented here. Measured on the same subject: a caller holding
// only view-users gets `[]`, one holding only manage-users gets
// offline_access and uma_authorization, and a full administrator gets those two
// plus create-realm and admin. That filter is the same caller-relative
// predicate F28 covers, whose rule is derived in Task 7; until then this
// answers the administrator's list to every caller the guard admits. See the
// "available is filtered by what the caller may grant" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func (h *handler) availableRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, without(all, direct), rc.realm.ID, true)
}

// realmRolesOnly keeps the roles that belong to the realm rather than a client.
func realmRolesOnly(in []*model.Role) []*model.Role {
	out := make([]*model.Role, 0, len(in))
	for _, r := range in {
		if r.ClientID == "" {
			out = append(out, r)
		}
	}
	return out
}

// without returns the roles in all that are not in exclude, by id.
func without(all, exclude []*model.Role) []*model.Role {
	held := make(map[string]bool, len(exclude))
	for _, r := range exclude {
		held[r.ID] = true
	}
	out := make([]*model.Role, 0, len(all))
	for _, r := range all {
		if !held[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// writeMappingList is the body every mapping listing sends.
//
// brief is a parameter rather than a constant because the three realm reads do
// not agree, which is measurable and was not guessable: `.../realm/composite`
// grows an attributes key for briefRepresentation=false and carries the role's
// real attribute values, while `.../realm` and `.../realm/available` ignore the
// parameter and never carry the key at all. Two behaviours across three
// siblings, so the caller decides.
func writeMappingList(w http.ResponseWriter, in []*model.Role, realmID string, brief bool) {
	out := make([]roleRepresentation, 0, len(in))
	for _, role := range in {
		container := realmID
		if role.ClientID != "" {
			container = role.ClientID
		}
		out = append(out, roleRepresentationOf(role, container, brief))
	}
	writeAdminJSON(w, out)
}
