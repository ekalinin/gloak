package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
)

// The eleven role-mapping routes whose holder is a group.
//
// **Every rule here was re-measured on a group rather than carried over.** The
// design document forbids the carry-over by name: `eachMapping`'s id-and-name
// agreement, `mayGrantRole` and `grantable` were all measured on a user holder,
// and this repository has reverted two rules extended from a neighbouring
// endpoint. All three hold, and the sweep of 2026-08-28 is what says so - see
// "The role-mapping rules hold on a group holder, and that was measured" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// So the handlers below share every helper with the user half: writeMappingList,
// grantable, realmRolesOnly, rolesOfClient, without and eachMapping. What they
// do not share is the guard. The reads take view-users or manage-users and the
// writes manage-users, which is the user routes' pair - but an unknown group is
// 404 to **every** caller, including one holding no admin role, so these take
// guardGroup and not guardUserSubject.

// listGroupRealmMappings serves GET /groups/{id}/role-mappings/realm: the realm
// roles assigned directly, with no composite expansion.
func (h *handler) listGroupRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	direct, err := h.store.Roles().ListGroupRoles(r.Context(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, realmRolesOnly(direct), rc.realm.ID, true)
}

// compositeGroupRealmMappings serves .../realm/composite: the transitive
// expansion, and the one of the three that honours briefRepresentation.
func (h *handler) compositeGroupRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	effective, err := roles.EffectiveForGroup(r.Context(), h.store.Roles(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, realmRolesOnly(effective), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableGroupRealmMappings serves .../realm/available: every realm role not
// directly assigned, filtered by what the caller may grant.
//
// grantable is the user half's, unchanged. Measured on a group holder: a
// view-users caller gets `[]` here as it does on a user, and a manage-users
// caller gets the subset it could actually write.
func (h *handler) availableGroupRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	all, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	direct, err := h.store.Roles().ListGroupRoles(r.Context(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	offer, err := h.grantable(r.Context(), rc, without(all, direct))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, offer, rc.realm.ID, true)
}

// listGroupClientMappings serves .../role-mappings/clients/{client-uuid}.
func (h *handler) listGroupClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	c, ok := h.mappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	direct, err := h.store.Roles().ListGroupRoles(r.Context(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, rolesOfClient(direct, c.ID), rc.realm.ID, true)
}

// compositeGroupClientMappings serves .../clients/{client-uuid}/composite.
//
// The expansion runs over the whole effective set and is narrowed afterwards: a
// client role reached through a realm role has to be listed, so the walk cannot
// be narrowed before it starts.
func (h *handler) compositeGroupClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	c, ok := h.mappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	effective, err := roles.EffectiveForGroup(r.Context(), h.store.Roles(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, rolesOfClient(effective, c.ID), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableGroupClientMappings serves .../clients/{client-uuid}/available.
func (h *handler) availableGroupClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	c, ok := h.mappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListClientRoles(r.Context(), rc.realm.ID, c.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	direct, err := h.store.Roles().ListGroupRoles(r.Context(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	offer, err := h.grantable(r.Context(), rc, without(all, rolesOfClient(direct, c.ID)))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, offer, rc.realm.ID, true)
}

// allGroupMappings serves GET /groups/{id}/role-mappings: the combined view,
// and the only body in this family that is not a bare array. A holder with
// nothing answers `{}`, measured, the same empty object the user's does.
func (h *handler) allGroupMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	direct, err := h.store.Roles().ListGroupRoles(r.Context(), g.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	clients, err := h.clientMappingsOf(r.Context(), rc, direct)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, mappingsRepresentation{
		RealmMappings:  mappingListOf(realmRolesOnly(direct), rc.realm.ID, true),
		ClientMappings: clients,
	})
}

// assignGroupRealmMappings and its three siblings are eachMapping with a group
// holder. The batch rules - validate in full before applying, answer in array
// order, and require the entry's id and name to agree in the route's own
// container - are eachMapping's, re-measured on a group and unchanged.
func (h *handler) assignGroupRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	h.eachMapping(w, r, rc, g.ID, func(role *model.Role) bool { return role.ClientID == "" },
		h.store.Roles().AssignToGroup)
}

func (h *handler) removeGroupRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	h.eachMapping(w, r, rc, g.ID, func(role *model.Role) bool { return role.ClientID == "" },
		h.store.Roles().RemoveFromGroup)
}

func (h *handler) assignGroupClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	c, ok := h.mappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	h.eachMapping(w, r, rc, g.ID, func(role *model.Role) bool { return role.ClientID == c.ID },
		h.store.Roles().AssignToGroup)
}

func (h *handler) removeGroupClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, g *model.Group) {
	c, ok := h.mappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	h.eachMapping(w, r, rc, g.ID, func(role *model.Role) bool { return role.ClientID == c.ID },
		h.store.Roles().RemoveFromGroup)
}

// mappingClientFromPath resolves the {clientUUID} segment for a group route.
//
// It answers the mapping family's "Client not found", not the client
// endpoints' "Could not find client" for the very same UUID - the same pair the
// user mapping routes already carry.
func (h *handler) mappingClientFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, bool) {
	c, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeMappingClientNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return c, true
}
