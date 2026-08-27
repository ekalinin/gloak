package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
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
// **Keycloak also filters this list by what the caller may grant**, which is
// what grantable applies. Measured on the same subject: a caller holding only
// view-users gets `[]`, one holding only manage-users gets offline_access and
// uma_authorization, and a full administrator gets those two plus create-realm
// and admin. See the "available is filtered by what the caller may grant"
// section of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
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
	offer, err := h.grantable(r.Context(), rc, without(all, direct))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, offer, rc.realm.ID, true)
}

// grantable narrows an available list to the roles this caller could actually
// assign, which is what the two available reads answer.
//
// Two conditions, and the first is not the read's own guard. `available` admits
// view-users **or** manage-users, and a view-users caller was measured getting
// 200 with an empty body on every container tried - the realm, master-realm and
// an ordinary client - because it may read the list and assign none of it. So
// the filter re-applies the *write* guard before judging any role, rather than
// trusting the one the route already ran. mayGrantRole is then the same
// predicate the writes use, which is the measured relationship between the two:
// the set a caller may write is exactly the set its own available read shows it.
func (h *handler) grantable(ctx context.Context, rc *reqContext, in []*model.Role) ([]*model.Role, error) {
	out := make([]*model.Role, 0, len(in))
	if !rc.caller.has(userMappingsWriteRole) {
		return out, nil
	}
	for _, role := range in {
		allowed, err := h.mayGrantRole(ctx, rc.realm, rc.caller, role)
		if err != nil {
			return nil, err
		}
		if allowed {
			out = append(out, role)
		}
	}
	return out, nil
}

// listClientMappings serves GET /users/{id}/role-mappings/clients/{client-uuid}:
// the roles of that one client assigned **directly**.
//
// The brief shape is measured on this route, not carried over from
// listRealmMappings: the two families of listings this API already has
// disagree about briefRepresentation, so the client triple was swept in full.
// It answers the same way its realm mirror does - only .../composite honours
// the parameter.
func (h *handler) listClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, c, ok := h.clientMappingSubject(w, r, rc)
	if !ok {
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, rolesOfClient(direct, c.ID), rc.realm.ID, true)
}

// compositeClientMappings serves .../clients/{client-uuid}/composite: the
// transitive expansion, narrowed to that client.
//
// The one of the three that honours briefRepresentation, measured on this
// route. Note the expansion runs over the user's whole effective set and is
// filtered afterwards: a client role reached through a *realm* role - which is
// exactly how the administrator holds all 21 master-realm ones - has to be
// listed, so the walk cannot be narrowed before it starts.
func (h *handler) compositeClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, c, ok := h.clientMappingSubject(w, r, rc)
	if !ok {
		return
	}
	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, rolesOfClient(effective, c.ID), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableClientMappings serves .../clients/{client-uuid}/available: every
// role of that client **not directly assigned**.
//
// The complement of the direct list, not of the composite one - measured on
// this route rather than inherited from availableRealmMappings. On a subject
// holding master-realm's view-users directly, query-users and query-groups are
// in the composite expansion *and* in the available list, because the subject
// reaches them through view-users without holding either directly.
//
// **Keycloak also filters this list by what the caller may grant**, exactly as
// on the realm mirror, and grantable applies it. Measured on the administrator
// as the subject: a caller holding only view-users gets `[]`, one holding only
// manage-users gets seven of master-realm's 21, and a full administrator gets
// all 21. F28 named this measurement as one that had to be taken rather than
// inferred from the realm side; it was, and it agrees. See the "`available` is
// filtered by what the caller may grant" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func (h *handler) availableClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, c, ok := h.clientMappingSubject(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListClientRoles(r.Context(), rc.realm.ID, c.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
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

// allMappings serves GET /users/{id}/role-mappings: the combined view, and the
// only body in this family that is not a bare array.
//
// It is the **direct** assignments on both halves, not the composite expansion.
// Measured on the bootstrapped administrator, which reaches all 21 master-realm
// roles through the realm role admin and still gets no clientMappings key at
// all - so this composes listRealmMappings and listClientMappings rather than
// their composite siblings.
//
// briefRepresentation does nothing here. Measured with the parameter absent,
// true and false on a subject holding a client role carrying a real attribute
// value: the three bodies were byte-identical and none carried an attributes
// key. Only the two .../composite routes in this family honour it, so this one
// passes the constant true down like the four listings that ignore it.
//
// It is not caller-filtered either: a view-users caller reading the
// administrator gets the same body a full administrator does, which is what
// separates this from the two available reads that F28 covers.
func (h *handler) allMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
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

// clientMappingsOf groups the client half of a user's direct roles by their
// owning client, in Keycloak's key order.
//
// The order is javamap.KeyOrder's and not the store's, because Keycloak builds
// this object as a Java Map and serialises it in HashMap bucket order. Sorting
// instead would put alpha-client before zeta-client where Keycloak measurably
// puts zeta-client first.
//
// A role whose owning client no longer exists makes this return an error and
// the endpoint answer 500. That state is unreachable on Keycloak, which deletes
// a client's roles with it, and reachable on Gloak, which does not - follow-up
// F29. Skipping the orphan instead would make this endpoint the one place that
// hides F29 while reporting a role list it knows to be short, so it fails
// rather than skips.
//
// Fails quietly, though: allMappings discards this error for the generic
// Internal Server Error body, and handler carries no logger, so the caller gets
// a bare 500 and nothing is recorded anywhere. That is the only behaviour
// consistent with the rest of the package today - every other 500 in this file
// does the same - so it is not a gap this endpoint can close on its own. F29 is
// what removes the state; giving the 500 a diagnosis is a separate concern.
func (h *handler) clientMappingsOf(ctx context.Context, rc *reqContext, direct []*model.Role) (clientMappings, error) {
	byClient := make(map[string][]*model.Role)
	for _, role := range direct {
		if role.ClientID != "" {
			byClient[role.ClientID] = append(byClient[role.ClientID], role)
		}
	}
	if len(byClient) == 0 {
		// nil rather than an empty slice, so omitempty drops the key: measured
		// absent, never {}.
		return nil, nil
	}

	// Keyed by clientId, which the roles do not carry, so each owning client
	// has to be resolved before the order can be decided.
	entries := make(map[string]clientMappingsEntry, len(byClient))
	ids := make([]string, 0, len(byClient))
	for uuid, roles := range byClient {
		c, err := h.store.Clients().ByID(ctx, rc.realm.ID, uuid)
		if err != nil {
			return nil, err
		}
		entries[c.ClientID] = clientMappingsEntry{
			ClientID: c.ClientID,
			ID:       c.ID,
			Client:   c.ClientID,
			Mappings: mappingListOf(roles, rc.realm.ID, true),
		}
		ids = append(ids, c.ClientID)
	}

	out := make(clientMappings, 0, len(ids))
	for _, id := range javamap.KeyOrder(ids) {
		out = append(out, entries[id])
	}
	return out, nil
}

// clientMappingSubject resolves the two path segments a client mapping read
// takes, in the order Keycloak resolves them: the **user first**. Measured on
// all three routes - an unknown user with an unknown client answers "User not
// found", so a client that does not exist is never the answer to a subject
// that does not either.
//
// It does not call clientRoleContainer, although that helper resolves the same
// {clientUUID} segment: the 404 body differs. See writeMappingClientNotFound.
func (h *handler) clientMappingSubject(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.User, *model.Client, bool) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return nil, nil, false
	}
	c, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeMappingClientNotFound(w)
			return nil, nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, nil, false
	}
	return user, c, true
}

// writeMappingClientNotFound is the measured 404 for a client UUID a mapping
// read cannot resolve.
//
// It is **not** writeClientNotFound's "Could not find client", which is what
// GET /clients/{uuid} and GET /clients/{uuid}/roles answer for the very same
// unknown UUID - the two were measured side by side in one session, on a live
// 26.7.1, precisely because reusing clientRoleContainer here was the obvious
// move. Ninth not-found spelling on this API.
func writeMappingClientNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Client not found")
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

// eachRealmMapping is what the two realm mapping writes share: resolve the
// user, then run the shared batch over the roles the **realm** owns.
//
// A client role is refused here although it exists, with the same 404 an
// unknown id gets - measured on both verbs.
func (h *handler) eachRealmMapping(w http.ResponseWriter, r *http.Request, rc *reqContext, apply func(context.Context, string, string) error) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	h.eachMapping(w, r, rc, user.ID, func(role *model.Role) bool { return role.ClientID == "" }, apply)
}

// assignClientMappings serves POST /users/{id}/role-mappings/clients/{client-uuid}.
//
// Assigning a role the user already holds is 204, measured on this route, so
// the store's ErrConflict is swallowed exactly as on the realm mirror.
func (h *handler) assignClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.eachClientMapping(w, r, rc, func(ctx context.Context, userID, roleID string) error {
		err := h.store.Roles().AssignToUser(ctx, userID, roleID)
		if errors.Is(err, store.ErrConflict) {
			return nil
		}
		return err
	})
}

// removeClientMappings serves DELETE /users/{id}/role-mappings/clients/{client-uuid}.
//
// Removing a role the user does not hold is 204, measured on this route, so
// RemoveFromUser's ErrNotFound is swallowed.
func (h *handler) removeClientMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.eachClientMapping(w, r, rc, func(ctx context.Context, userID, roleID string) error {
		err := h.store.Roles().RemoveFromUser(ctx, userID, roleID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	})
}

// eachClientMapping is eachRealmMapping's counterpart: resolve the user **and
// the client**, then run the shared batch over the roles that one client owns.
//
// The accepted set is `role.ClientID == c.ID`, not `role.ClientID != ""`.
// Measured on both verbs: a **realm** role and **another client's** role are
// both refused here, both with 404 `{"error":"Role not found"}`, and both ids
// name a role that exists - master-realm's own endpoint takes the second one in
// the same session. So the check is which container owns the role, not merely
// whether one does.
//
// That message is the one thing in this pair the plan flagged as unmeasured,
// with an explicit instruction not to assume it matched the realm mirror's. It
// was measured, and it does match - no tenth not-found spelling.
//
// The two path segments are resolved before the body is read, and
// clientMappingSubject resolves them in the measured order. The evidence for
// "before the body" is its own probe rather than an assumption from the reads,
// which have no body: an unknown client sent a body that cannot be parsed
// answers `Client not found`, not the decoder's 400.
func (h *handler) eachClientMapping(w http.ResponseWriter, r *http.Request, rc *reqContext, apply func(context.Context, string, string) error) {
	user, c, ok := h.clientMappingSubject(w, r, rc)
	if !ok {
		return
	}
	h.eachMapping(w, r, rc, user.ID, func(role *model.Role) bool { return role.ClientID == c.ID }, apply)
}

// eachMapping is what the four mapping writes share once the subject is
// resolved: decode the body, validate every entry, then apply each only once
// they all validate. accepts is what the endpoint's own locator will take -
// the realm's roles for one pair, one client's for the other.
//
// **The batch validates in full before anything is applied, on both verbs.**
// Measured on a live 26.7.1 in both id orders and for POST and DELETE alike, on
// the realm pair and again on the client pair: a body of one real role id and
// one that resolves to nothing applies neither and answers 404
// `{"error":"Role not found"}`. That is the same shape eachComposite takes, and
// it is measured on each of these routes rather than carried over - the
// composite writes were separately measured *disagreeing* with each other on
// the per-child manage check, so agreement between neighbouring endpoints is
// not something this file infers.
//
// The guarantee is against a **bad request**, not against a store failure. A
// decode failure and a validation failure both leave the user's roles
// untouched, but the apply loop below writes one row at a time, so a genuine
// store error partway through an already-validated batch can still leave part
// of it applied under the 500. That hole is structural and shared with
// eachComposite, which names it too: store.Store exposes no transaction that
// spans several calls, so neither loop can be made atomic against a driver
// failure without changing that interface. Closing it is a store concern, not
// one of these handlers'.
//
// Like eachComposite it runs a per-entry caller check, mayGrantRole, and
// unlike eachComposite it runs it on **both** verbs. That difference is
// measured on each of the four routes rather than shared: a `manage-users`
// caller is refused the realm roles `admin` and `create-realm` and allowed
// `offline_access` and `uma_authorization`, is refused `master-realm`'s
// `manage-realm`, `manage-clients` and `impersonation` and allowed its
// `view-users`, and is refused `DELETE` of `admin` off a subject that holds it -
// where `DELETE .../composites` next door allows the same removal. The set it
// may write is exactly the set its own `available` read shows it, which is why
// that read runs the same predicate.
//
// The check sits **after** the guard, not instead of it: `view-users` is
// refused these routes outright, even for an empty array with no role to judge,
// so the coarse "may you write user role mappings at all" question is the route
// guard's and this is a second stage. And it sits inside the validate loop, in
// array order, because Keycloak answers in array order - a body naming a
// nonexistent id and then a refused role is 404, the same two entries the other
// way round are 403, measured on this route and on the composite one.
func (h *handler) eachMapping(w http.ResponseWriter, r *http.Request, rc *reqContext, userID string, accepts func(*model.Role) bool, apply func(context.Context, string, string) error) {
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
		if !accepts(role) {
			writeMappingRoleNotFound(w)
			return
		}
		allowed, err := h.mayGrantRole(r.Context(), rc.realm, rc.caller, role)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !allowed {
			writeForbidden(w)
			return
		}
	}
	for _, rep := range reps {
		if err := apply(r.Context(), userID, rep.ID); err != nil {
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
//
// Both write pairs send it, and that was measured on each rather than shared by
// assumption: the client writes' 404 for a role of the wrong container is the
// same string, so this stays four spellings rather than becoming five.
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

// rolesOfClient keeps the roles owned by one client, realmRolesOnly's
// counterpart for the client triple.
//
// Not spelled clientRolesOnly: roles.go already carries onlyRealmRoles and
// onlyThisClientsRoles for the composite listings, realmRolesOnly above is
// already one near-anagram of the first, and a fourth name in that shape would
// be a coin toss at every call site. This one reads as what it returns.
func rolesOfClient(in []*model.Role, clientID string) []*model.Role {
	out := make([]*model.Role, 0, len(in))
	for _, r := range in {
		if r.ClientID == clientID {
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
// brief is a parameter rather than a constant because the six routes that call
// this do not agree, which is measurable and was not guessable:
// `.../realm/composite` and `.../clients/{uuid}/composite` grow an attributes
// key for briefRepresentation=false and carry the role's real attribute values,
// while the other four - the two direct reads and the two available reads -
// ignore the parameter and never carry the key at all. The client triple was
// swept in full rather than inherited from the realm one. Two behaviours across
// six siblings, so the caller decides.
func writeMappingList(w http.ResponseWriter, in []*model.Role, realmID string, brief bool) {
	writeAdminJSON(w, mappingListOf(in, realmID, brief))
}

// mappingListOf builds that body without sending it, which is what the combined
// view needs: there the same list is a value inside a larger object rather than
// the whole response.
//
// The slice is non-nil even when empty, because the six listings that send it
// alone are measured answering `[]`. The combined view's own omission of an
// empty half is decided in clientMappingsOf and by omitempty, not here.
func mappingListOf(in []*model.Role, realmID string, brief bool) []roleRepresentation {
	out := make([]roleRepresentation, 0, len(in))
	for _, role := range in {
		container := realmID
		if role.ClientID != "" {
			container = role.ClientID
		}
		out = append(out, roleRepresentationOf(role, container, brief))
	}
	return out
}
