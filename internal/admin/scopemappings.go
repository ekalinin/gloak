package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
)

// A scope mapping is a role a client or a client scope may put into a token.
//
// **It is not a role anybody holds**, which is the thing that makes this family
// different from the eleven operations of user role mappings and the eleven of
// group role mappings next door. A scope mapping is a filter: it decides which
// of the roles a user *already* has survive into a token issued for that
// client. Nothing is granted by writing one.
//
// That difference is measurable and was measured, because the naive move is to
// reuse mayGrantRole - it is next door, it has the right signature, and its
// predicate governs the two families that look identical to this one. See
// mayMapRole for the three measurements that falsify it.

// scopeContainer is a thing that owns scope mappings: a client scope or a
// client. The eleven handlers below are written against it once and registered
// under three path spellings.
//
// The two implementations differ in more than which table they write.
// fullScope and ownRoles are a client's alone, and both are inputs to what
// .../composite answers - see hasScope.
type scopeContainer interface {
	// mappings are the roles mapped **directly** into this container's scope,
	// with no composite expansion.
	mappings(ctx context.Context) ([]*model.Role, error)
	add(ctx context.Context, roleID string) error
	remove(ctx context.Context, roleID string) error
	// fullScope reports the container's fullScopeAllowed. Always false for a
	// client scope, which has no such flag.
	fullScope() bool
	// ownRoles are the roles the container itself owns. **A client's own roles
	// are in its own scope** - measured: a client with fullScopeAllowed off and
	// nothing mapped answers `[]` from
	// .../scope-mappings/clients/{itself}/available and its own single role
	// from the composite beside it. A client scope owns no roles and returns
	// nothing.
	ownRoles(ctx context.Context) ([]*model.Role, error)
}

type clientScopeContainer struct {
	h  *handler
	sc *model.ClientScope
}

func (s clientScopeContainer) mappings(ctx context.Context) ([]*model.Role, error) {
	return s.h.store.Roles().ListClientScopeScopeMappings(ctx, s.sc.ID)
}

func (s clientScopeContainer) add(ctx context.Context, roleID string) error {
	return s.h.store.Roles().AddClientScopeScopeMapping(ctx, s.sc.ID, roleID)
}

func (s clientScopeContainer) remove(ctx context.Context, roleID string) error {
	return s.h.store.Roles().RemoveClientScopeScopeMapping(ctx, s.sc.ID, roleID)
}

func (s clientScopeContainer) fullScope() bool { return false }

func (s clientScopeContainer) ownRoles(context.Context) ([]*model.Role, error) {
	return nil, nil
}

type clientContainer struct {
	h *handler
	c *model.Client
}

func (c clientContainer) mappings(ctx context.Context) ([]*model.Role, error) {
	return c.h.store.Roles().ListClientScopeMappings(ctx, c.c.ID)
}

func (c clientContainer) add(ctx context.Context, roleID string) error {
	return c.h.store.Roles().AddClientScopeMapping(ctx, c.c.ID, roleID)
}

func (c clientContainer) remove(ctx context.Context, roleID string) error {
	return c.h.store.Roles().RemoveClientScopeMapping(ctx, c.c.ID, roleID)
}

func (c clientContainer) fullScope() bool { return c.c.FullScopeAllowed }

func (c clientContainer) ownRoles(ctx context.Context) ([]*model.Role, error) {
	return c.h.store.Roles().ListClientRoles(ctx, c.c.RealmID, c.c.ID)
}

// allScopeMappings serves GET .../scope-mappings: the combined view, and the
// only body in this family that is not a bare array.
//
// It is the same MappingsRepresentation GET /users/{id}/role-mappings sends,
// and it composes the two **direct** listings rather than their composite
// siblings - measured: a client with fullScopeAllowed set answers `{}` here
// while its .../realm/composite answers every realm role in the realm.
//
// Neither half is caller-filtered. Measured: a view-clients caller and a full
// administrator get the same body, which is what separates this from the two
// available reads.
func (h *handler) allScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	direct, err := sc.mappings(r.Context())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	clients, err := h.scopeClientMappingsOf(r.Context(), rc, direct)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, mappingsRepresentation{
		RealmMappings:  mappingListOf(realmRolesOnly(direct), rc.realm.ID, true),
		ClientMappings: clients,
	})
}

// scopeClientMappingsOf groups the client half of a container's direct
// mappings, in Keycloak's key order.
//
// It is clientMappingsOf's twin and is deliberately a second function rather
// than a shared one: that one takes a user's roles and this one a container's,
// and the only thing they have in common is the grouping. Merging them would
// mean a helper whose argument is "some roles from somewhere", which is exactly
// the shape that makes the two families' measured differences invisible.
func (h *handler) scopeClientMappingsOf(ctx context.Context, rc *reqContext, direct []*model.Role) (clientMappings, error) {
	byClient := make(map[string][]*model.Role)
	for _, role := range direct {
		if role.ClientID != "" {
			byClient[role.ClientID] = append(byClient[role.ClientID], role)
		}
	}
	// There is deliberately no `if len(byClient) == 0 { return nil, nil }` here.
	// A container with no client mappings was measured answering `realmMappings`
	// alone, and one with nothing at all answering `{}`, and `omitempty` on a
	// slice already drops an empty one - nil or not. An early return spelling
	// that out is dead code, which a mutation replacing it with `if false`
	// proved by surviving; the absent-key rule is pinned by
	// admin/scope-mappings/refused-batch-writes-nothing, whose whole body is
	// `{}`, and by mutating the struct tag rather than this branch. The same
	// mistake was made and found once already, on protocolMapperListOrNil.
	entries := make(map[string]clientMappingsEntry, len(byClient))
	ids := make([]string, 0, len(byClient))
	for uuid, held := range byClient {
		c, err := h.store.Clients().ByID(ctx, rc.realm.ID, uuid)
		if err != nil {
			return nil, err
		}
		entries[c.ClientID] = clientMappingsEntry{
			ClientID: c.ClientID,
			ID:       c.ID,
			Client:   c.ClientID,
			Mappings: mappingListOf(held, rc.realm.ID, true),
		}
		ids = append(ids, c.ClientID)
	}
	out := make(clientMappings, 0, len(ids))
	for _, id := range javamap.KeyOrder(ids) {
		out = append(out, entries[id])
	}
	return out, nil
}

// listRealmScopeMappings serves GET .../scope-mappings/realm: the realm roles
// mapped directly, with no composite expansion.
//
// The brief shape is not negotiable: measured, this route ignores
// briefRepresentation entirely where its composite sibling honours it - the
// same split the user role-mapping family has, measured here rather than
// carried over.
func (h *handler) listRealmScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	direct, err := sc.mappings(r.Context())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, realmRolesOnly(direct), rc.realm.ID, true)
}

// compositeRealmScopeMappings serves .../scope-mappings/realm/composite: every
// realm role that is **in scope**, which is not the same as every realm role
// reachable from the mappings.
//
// The one of the three that honours briefRepresentation - measured on this
// route and on its client twin, and `false` grows the attributes key.
func (h *handler) compositeRealmScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	all, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	inScope, err := h.hasScope(r.Context(), sc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, keep(all, inScope), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableRealmScopeMappings serves .../scope-mappings/realm/available: every
// realm role **not mapped directly**, narrowed to what this caller could write.
//
// It is the complement of the **direct** list, not of the composite one.
// Measured: with a composite realm role mapped, the child realm role is in
// .../realm/composite *and* in this list, because the container reaches it
// through the parent without holding it directly. Computing this from hasScope
// would silently drop it.
//
// **Keycloak also filters it by what the caller may write**, which is what
// mappable applies - and the predicate inside the filter is this family's, not
// the user family's. Measured: a manage-clients caller gets `[]` here where a
// manage-clients + manage-realm caller gets five.
func (h *handler) availableRealmScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	all, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	offer, err := h.availableScopeRoles(r.Context(), rc, sc, all)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, offer, rc.realm.ID, true)
}

// listClientRoleScopeMappings serves GET .../scope-mappings/clients/{client}:
// the roles of that one client mapped directly.
func (h *handler) listClientRoleScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	c, ok := h.scopeMappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	direct, err := sc.mappings(r.Context())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, rolesOfClient(direct, c.ID), rc.realm.ID, true)
}

// compositeClientRoleScopeMappings serves
// .../scope-mappings/clients/{client}/composite.
func (h *handler) compositeClientRoleScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	c, ok := h.scopeMappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListClientRoles(r.Context(), rc.realm.ID, c.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	inScope, err := h.hasScope(r.Context(), sc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, keep(all, inScope), rc.realm.ID, briefRoles(r.URL.Query()))
}

// availableClientRoleScopeMappings serves
// .../scope-mappings/clients/{client}/available.
func (h *handler) availableClientRoleScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	c, ok := h.scopeMappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListClientRoles(r.Context(), rc.realm.ID, c.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	offer, err := h.availableScopeRoles(r.Context(), rc, sc, all)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeMappingList(w, offer, rc.realm.ID, true)
}

// availableScopeRoles is what the two available reads share: subtract what is
// in scope **directly**, then keep what this caller could write.
func (h *handler) availableScopeRoles(ctx context.Context, rc *reqContext, sc scopeContainer, all []*model.Role) ([]*model.Role, error) {
	direct, err := h.directScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	out := make([]*model.Role, 0, len(all))
	for _, role := range without(all, direct) {
		if mayMapRole(rc.caller, role) {
			out = append(out, role)
		}
	}
	return out, nil
}

// directScope is hasDirectScope's set: the direct mappings, plus - on a client
// alone - the client's own roles.
//
// The second half is measured and is easy to miss. A client's own roles are in
// its own scope without ever being mapped, so
// .../clients/{uuid}/scope-mappings/clients/{that same uuid}/available answers
// `[]` on a client that owns roles and has mapped none. There is no composite
// expansion in either half: `available` subtracts what is held **directly**.
func (h *handler) directScope(ctx context.Context, sc scopeContainer) ([]*model.Role, error) {
	direct, err := sc.mappings(ctx)
	if err != nil {
		return nil, err
	}
	own, err := sc.ownRoles(ctx)
	if err != nil {
		return nil, err
	}
	return append(direct, own...), nil
}

// hasScope is the predicate .../composite keeps, and it is three clauses on a
// client and one on a client scope. Measured:
//
//   - a client with fullScopeAllowed answers **every** realm role from
//     .../realm/composite while .../realm answers `[]`; turn the flag off and
//     the same read answers `[]`;
//   - a mapped composite role puts its children in scope, so a scope with one
//     composite mapped answers two realm roles and one client role across the
//     two composite reads;
//   - a client's own roles are in scope without being mapped.
//
// A client scope has no flag and owns no roles, so for it this reduces to the
// composite closure of what is mapped - which is why the interface carries
// fullScope and ownRoles rather than this function branching on a type.
func (h *handler) hasScope(ctx context.Context, sc scopeContainer) (func(*model.Role) bool, error) {
	if sc.fullScope() {
		return func(*model.Role) bool { return true }, nil
	}
	direct, err := h.directScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	reachable, err := roles.ExpandFrom(ctx, h.store.Roles(), direct)
	if err != nil {
		return nil, err
	}
	in := make(map[string]bool, len(reachable))
	for _, role := range reachable {
		in[role.ID] = true
	}
	return func(role *model.Role) bool { return in[role.ID] }, nil
}

// addRealmScopeMappings serves POST .../scope-mappings/realm.
func (h *handler) addRealmScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	h.eachScopeMappingByID(w, r, rc, sc, sc.add)
}

// removeRealmScopeMappings serves DELETE .../scope-mappings/realm.
func (h *handler) removeRealmScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	h.eachScopeMappingByID(w, r, rc, sc, sc.remove)
}

// eachScopeMappingByID is the realm pair's body, and its name says the thing
// that surprised: **it resolves each entry by `id`, realm-wide, and never looks
// at `name`.**
//
// Measured on both verbs, on both containers:
//
//	[{"id":<realm role>}]                      204
//	[{"id":<realm role>,"name":"anything"}]    204 - the name is not compared
//	[{"name":"<a real realm role>"}]           **500** - there is no id to read
//	[{"id":<unknown>}]                         404 {"error":"Role not found"}
//	[{"id":<a CLIENT role>}]                   **204** - and it lands under
//	                                           clientMappings, readable at
//	                                           .../scope-mappings/clients/{that
//	                                           client} and removable through
//	                                           this same route
//
// So the `realm` path segment is a precondition on nothing at all: it decides
// what the matching **read** filters to and not what the write accepts. Adding
// a `role.ClientID == ""` check to make the write agree with its own path is
// the tidy-up that breaks it - and eachRealmMapping next door, on the user
// family, does have exactly that check, measured, which is why this one could
// not be shared.
//
// The 500 for a missing id is Keycloak's own defect reproduced: the lookup is
// by id and a null id reaches the store.
//
// **The batch validates in full before it applies**, on both verbs. Measured in
// both array orders: a body of one real id and one that resolves to nothing
// applies neither and answers 404, and a body of one role this caller may map
// and one it may not applies neither and answers 403. Array order is what
// decides which of the two answers a body that is wrong in both ways gets.
func (h *handler) eachScopeMappingByID(w http.ResponseWriter, r *http.Request, rc *reqContext,
	sc scopeContainer, apply func(context.Context, string) error) {
	reps, ok := decodeScopeMappings(w, r)
	if !ok {
		return
	}
	resolved := make([]*model.Role, 0, len(reps))
	for _, rep := range reps {
		if rep.ID == "" {
			writeScopeMappingUnknownError(w)
			return
		}
		role, err := h.store.Roles().ByID(r.Context(), rc.realm.ID, rep.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeMappingRoleNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !mayMapRole(rc.caller, role) {
			writeForbidden(w)
			return
		}
		resolved = append(resolved, role)
	}
	h.applyScopeMappings(w, r, resolved, apply)
}

// addClientRoleScopeMappings serves POST .../scope-mappings/clients/{client}.
func (h *handler) addClientRoleScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	h.eachScopeMappingByName(w, r, rc, sc, sc.add)
}

// removeClientRoleScopeMappings serves DELETE .../scope-mappings/clients/{client}.
func (h *handler) removeClientRoleScopeMappings(w http.ResponseWriter, r *http.Request, rc *reqContext, sc scopeContainer) {
	h.eachScopeMappingByName(w, r, rc, sc, sc.remove)
}

// eachScopeMappingByName is the client pair's body, and it reads **the other
// key off the same JSON**.
//
// Measured on both verbs, against the realm pair above in the same session:
//
//	[{"name":"<a role of {client}>"}]        204
//	[{"id":"<bogus>","name":"<that role>"}]  **204** - the id is not compared
//	[{"id":<that role's real id>}]           **404** - there is no name to read
//	[{"name":"<a realm role>"}]              404 {"error":"Role not found"}
//	[{"name":"<another client's role>"}]     404
//
// Two write pairs on one tag, four operations, and each ignores the key the
// other resolves by. Writing one decoder that accepts a role when *either* key
// matches passes every happy-path case and gets four measured rejections wrong.
//
// The lookup is scoped to the client the path names, so a role of another
// client is the same 404 an unknown name is - which is the one thing this pair
// shares with its user-family neighbour.
func (h *handler) eachScopeMappingByName(w http.ResponseWriter, r *http.Request, rc *reqContext,
	sc scopeContainer, apply func(context.Context, string) error) {
	c, ok := h.scopeMappingClientFromPath(w, r, rc)
	if !ok {
		return
	}
	reps, ok := decodeScopeMappings(w, r)
	if !ok {
		return
	}
	resolved := make([]*model.Role, 0, len(reps))
	for _, rep := range reps {
		role, err := h.store.Roles().ByName(r.Context(), rc.realm.ID, c.ID, rep.Name)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeMappingRoleNotFound(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if !mayMapRole(rc.caller, role) {
			writeForbidden(w)
			return
		}
		resolved = append(resolved, role)
	}
	h.applyScopeMappings(w, r, resolved, apply)
}

// applyScopeMappings is the second half of both write pairs: nothing is written
// until every entry has validated.
//
// Both verbs are idempotent - adding a role already mapped and removing one
// that is not mapped are both 204, measured - so neither the store's
// ErrConflict nor its ErrNotFound can arrive here, and the repository swallows
// them rather than this loop.
func (h *handler) applyScopeMappings(w http.ResponseWriter, r *http.Request,
	resolved []*model.Role, apply func(context.Context, string) error) {
	for _, role := range resolved {
		if err := apply(r.Context(), role.ID); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// mayMapRole is the per-role check both writes and both available reads run.
//
// **It is the composite-write rule and not the caller-relative rule**, and the
// difference is measured rather than reasoned. AGENTS.md records the
// caller-relative rule - a caller may hand out a role only if the role is not
// one of the realm's own admin roles, or the caller's own effective roles
// already confer it - governing the user and group role-mapping families. It
// does not govern this one. Three measurements say so, taken on a live 26.7.1
// on 2026-08-30 with probe users holding one role each and measured pairs:
//
//  1. `manage-clients` is refused `create-realm` and `offline_access`, which
//     are ordinary realm roles and not admin roles at all. mayGrantRole allows
//     both.
//  2. `manage-clients` + `manage-realm` is **allowed** master's `admin`, the
//     superuser realm role. mayGrantRole refuses it: `admin` is composite over
//     `manage-realm`, not the reverse, so `manage-realm` confers nothing.
//  3. `manage-clients` alone is **allowed** `master-realm`'s `manage-realm`, a
//     client role conferring full realm management. mayGrantRole refuses
//     exactly this on POST /users/{id}/role-mappings/clients/{uuid}.
//
// So the predicate is the one the composite writes already use: the manage role
// of the role's **own container**. It is not shared with them either, because
// theirs runs on the add path alone where this runs on both - measured, a
// manage-clients caller is refused DELETE of a realm role off a scope's
// mappings where DELETE .../composites next door allows the same removal.
//
// The permissive direction is not an escalation. A scope mapping grants
// nothing; it decides which of a subject's existing roles survive into a token.
// The caller-relative rule exists on the user family because that write really
// does hand out a right.
func mayMapRole(c *caller, role *model.Role) bool {
	if role.ClientID != "" {
		return c.has("manage-clients")
	}
	return c.has("manage-realm")
}

// keep is filter, spelled locally because the two composite reads want the same
// three lines and `without` next door takes a set rather than a predicate.
func keep(in []*model.Role, ok func(*model.Role) bool) []*model.Role {
	out := make([]*model.Role, 0, len(in))
	for _, role := range in {
		if ok(role) {
			out = append(out, role)
		}
	}
	return out
}

// writeScopeMappingUnknownError is the 500 the realm write answers for an entry
// with no `id`. Keycloak's own defect - the lookup is by id and a null one
// reaches the store - and the same shape POST /client-scopes answers for a body
// with no `name`.
//
// It delegates rather than repeating the two strings. This package already
// spells that body in two places and a measured string written a third time is
// the drift `writeRealmNotFound` exists to prevent.
func writeScopeMappingUnknownError(w http.ResponseWriter) {
	writeProtocolMapperUnknownError(w)
}

// decodeScopeMappings decodes the array all four writes take.
//
// It goes through decodeMapperBody - cut B's **shape** classifier - rather than
// decodeRoleList, because the shape rule is what these four endpoints were
// measured answering:
//
//	`[`   truncated array   400 invalid_request
//	`{`   wrong shape       400 unknown_error
//	``    empty, or `null`  500 unknown_error
//
// decodeRoleList answers `unknown_error` to all three and 400 to the last,
// which is right for the ten role-array endpoints only because no case sends
// them the other shapes. That is F64, and this is the second family to use the
// classifier it asks for.
//
// One case is left divergent, the same one cut B left: `[{` - a truncated
// array **element** - answers a third code, `{"error":"HTTP 400 Bad Request"}`,
// which needs the decoder to report where it stopped.
func decodeScopeMappings(w http.ResponseWriter, r *http.Request) ([]roleRepresentation, bool) {
	if !requireJSONBody(w, r) {
		return nil, false
	}
	var reps []roleRepresentation
	ok := decodeMapperBody(w, r, '[', func(dec *json.Decoder) error {
		return dec.Decode(&reps)
	})
	return reps, ok
}

// requireJSONBody is the measured 415, and this family is where it became
// reachable: these are the first routes in Gloak whose **DELETE** carries a
// body, and a `DELETE` with a body is what a client sends with whatever
// Content-Type its HTTP library defaults to.
//
// Measured on both verbs: `application/json` and **no Content-Type at all** are
// accepted, and `text/plain` and `application/x-www-form-urlencoded` are 415
// with `{"error":"The content-type header value did not match the value in
// @Consumes"}`. Absent being accepted is JAX-RS defaulting to the single
// @Consumes, and it is not an oversight in the probe: it was measured
// separately from the suppressed-header case that first looked like it.
//
// It is applied here and nowhere else, because here is where it was measured.
// `PUT .../credentials/{id}/userLabel` has the mirror-image rule - it consumes
// `text/plain` and answers 415 to JSON - recorded in a comment in
// credentials.go and served by nothing. Generalising this to every admin route
// is the change that needs its own sweep.
func requireJSONBody(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" || strings.HasPrefix(ct, "application/json") {
		return true
	}
	httpx.WriteMessageError(w, http.StatusUnsupportedMediaType,
		"The content-type header value did not match the value in @Consumes")
	return false
}

// scopeMappingClientFromPath resolves the `{client}` segment of the six routes
// that name one.
//
// The 404 is **`Could not find client`**, not the role-mapping family's `Client
// not found` - measured side by side in one session, because reusing
// mappingClientFromPath was the obvious move and it spells the other one. Same
// missing client, two routes, two strings, and this family picks the same one
// the client and client-scope endpoints do.
//
// It is resolved **before** the body is read on the two writes, which is its own
// probe rather than an inference from the reads: an unknown client sent a body
// that cannot be parsed answers this 404 and not the decoder's 400.
func (h *handler) scopeMappingClientFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, bool) {
	c, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("roleClientUUID"))
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

// guardScopeScopeMappings is the guard for the twenty-two routes under a client
// scope, both path spellings.
//
// The order is measured by giving one caller one role and varying which id is
// bad:
//
//	no clients role   403 even for a scope that does not exist
//	query-clients     **404** for a scope that does not exist, 403 for one that does
//	view-clients      404 for a bad scope, 200 on a read, 403 on a write
//	manage-clients    404 for a bad scope, 200 on a read, 204 on a write it may make
//
// So: coarse gate, then the container, then the fine role check, then the role.
// That is the protocol-mapper family's order exactly, and both the gate
// (clientsReadRoles) and the fine check (mayUseClientMappers) are reused rather
// than copied - measured to be the same, on this family, one role at a time.
//
// The per-role check that follows is **not** shared with them: see mayMapRole.
func (h *handler) guardScopeScopeMappings(write bool,
	next func(http.ResponseWriter, *http.Request, *reqContext, scopeContainer)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			sc, err := h.store.ClientScopes().ByID(r.Context(), rc.realm.ID,
				r.PathValue("clientScopeID"))
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeClientScopeNotFound(w)
					return
				}
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if !mayUseClientMappers(rc.caller, write) {
				writeForbidden(w)
				return
			}
			next(w, r, rc, clientScopeContainer{h: h, sc: sc})
		})
}

// guardClientScopeMappings is guardScopeScopeMappings over a client. Same gate,
// same order, and the only difference a caller can see is which 404 an unknown
// container gets: `Could not find client` rather than `Could not find client
// scope`.
func (h *handler) guardClientScopeMappings(write bool,
	next func(http.ResponseWriter, *http.Request, *reqContext, scopeContainer)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			client, ok := h.clientFromPath(w, r, rc)
			if !ok {
				return
			}
			if !mayUseClientMappers(rc.caller, write) {
				writeForbidden(w)
				return
			}
			next(w, r, rc, clientContainer{h: h, c: client})
		})
}
