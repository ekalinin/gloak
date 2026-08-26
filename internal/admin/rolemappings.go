package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
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

// assignRealmMappings serves POST /users/{id}/role-mappings/realm.
//
// Assigning a role the user already holds is 204, not 409 - measured - so the
// store's ErrConflict is swallowed here the way addComposites swallows
// AddComposite's.
func (h *handler) assignRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.eachRealmMapping(w, r, rc, func(ctx context.Context, userID, roleID string) error {
		err := h.store.Roles().AssignToUser(ctx, userID, roleID)
		if errors.Is(err, store.ErrConflict) {
			return nil
		}
		return err
	})
}

// removeRealmMappings serves DELETE /users/{id}/role-mappings/realm.
//
// Removing a role the user does not hold is 204, measured, so RemoveFromUser's
// ErrNotFound - which it reports when no row matched - is swallowed. That is
// the mirror of the ErrConflict above and of removeComposites next door.
func (h *handler) removeRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.eachRealmMapping(w, r, rc, func(ctx context.Context, userID, roleID string) error {
		err := h.store.Roles().RemoveFromUser(ctx, userID, roleID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	})
}

// eachRealmMapping is what the two mapping writes share: resolve the user,
// decode the body, validate every entry, then apply each only once they all
// validate.
//
// **The batch validates in full before anything is applied, on both verbs.**
// Measured on a live 26.7.1 in both id orders and for POST and DELETE alike: a
// body of one real realm role id and one that resolves to nothing applies
// neither and answers 404 `{"error":"Role not found"}`. That is the same shape
// eachComposite takes, and it is measured here rather than carried over from
// it - the composite writes were separately measured *disagreeing* with each
// other on the per-child manage check, so agreement between neighbouring
// endpoints is not something this file infers.
//
// The guarantee is against a **bad request**, not against a store failure. A
// decode failure and a validation failure both leave the user's roles
// untouched, but the apply loop below writes one row at a time, so a genuine
// store error partway through an already-validated batch can still leave part
// of it applied under the 500. That hole is structural and shared with
// eachComposite, which names it too: store.Store exposes no transaction that
// spans several calls, so neither loop can be made atomic against a driver
// failure without changing that interface. Closing it is a store concern, not
// one of these two handlers'.
//
// Unlike eachComposite there is no per-entry caller check. Keycloak has one -
// a `manage-users` caller is refused `admin` and `create-realm` and allowed
// `offline_access` and `uma_authorization`, on both verbs, all-or-nothing -
// and it is the same caller-relative predicate F28 covers, whose rule is
// derived in Task 7. Until then this applies whatever the route guard admits,
// which means a `manage-users` caller here can hand out `admin`. Recorded
// under "A mapping write **is** filtered by what the caller may grant" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md; deliberately
// not half-implemented, because a partial version of that predicate is worse
// than none.
func (h *handler) eachRealmMapping(w http.ResponseWriter, r *http.Request, rc *reqContext, apply func(context.Context, string, string) error) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	reps, ok := decodeRoleList(w, r)
	if !ok {
		return
	}
	for _, rep := range reps {
		role, err := h.store.Roles().ByID(r.Context(), rc.realm.ID, rep.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeMappingRoleNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		// A client role is refused by the realm endpoint although it exists,
		// with the same 404 an unknown id gets - measured on both verbs.
		if role.ClientID != "" {
			writeMappingRoleNotFound(w)
			return
		}
	}
	for _, rep := range reps {
		if err := apply(r.Context(), user.ID, rep.ID); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// writeMappingRoleNotFound is the measured 404 for a role a mapping write
// cannot use. It is **not** the roles endpoints' "Could not find role", not
// roles-by-id's "Could not find role with id", and not the composite batch's
// "Could not find composite role". Four spellings, one resource; all measured.
func writeMappingRoleNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Role not found")
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
