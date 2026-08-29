// Package admin serves Keycloak's Admin REST API.
//
// Its authorization model is not a variation on the protocol side's. An
// admin-cli access token carries azp, exp, iat, iss, jti, scope, sid and typ
// and nothing else - no sub, no realm_access - so there is nothing in the
// token to authorise against. Keycloak resolves the caller server-side from
// sid, and that was measured, not assumed: a caller holding only view-users
// gets 200 on a user listing and 403 on a user create, with a token carrying
// neither role. See "Admin roles on the master-realm client" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// caller is an authenticated administrator and the **admin** roles it
// effectively holds: its direct assignments plus everything reachable through
// composites, reduced by container to the admin ones - see adminRoleNames.
//
// **The container decides, never the name.** This carried a second set until
// 2026-08-28: every name the caller held from any container, which is what the
// route guards asked about. That was F32, a privilege escalation - a caller
// holding manage-clients could mint a client role named manage-realm on any
// client that is not the realm's own, assign it to itself, and pass every
// guard that names manage-realm. Measured: Keycloak refuses that caller
// POST /admin/realms/master/roles with 403, Gloak answered 201.
//
// Every question asked of a caller on this API is an admin-role question - the
// route guards, the access claims on a user and a client representation, and
// F28's grant predicate - so one set answers all of them and there is no
// remaining call site that means "any container".
type caller struct {
	user        *model.User
	adminGrants map[string]bool
	granted     map[string]bool

	// authRealm is the realm that issued the caller's token and holds its
	// session, which is **not** always the realm named in the path: a master
	// administrator managing another realm authenticates in master. It is kept
	// so foreignGrants can read the caller's rights on a second container.
	authRealm *model.Realm
	// effective is the caller's whole expanded role set, before adminGrants
	// narrowed it to one container. foreignGrants narrows it again, to a
	// different one.
	effective []*model.Role
	// container is the client adminGrants were read from - the one
	// containerFor chose for this pair of realms - or nil when the caller has
	// no rights over the realm in the path at all. mayGrantRole compares a
	// role's own container against it to decide whether the implication
	// closure applies or exact names do.
	container *model.Client
	// foreign memoises foreignGrants per container client id, because a
	// role-mapping batch asks about many roles of one container.
	foreign map[string]map[string]bool
}

// has reports whether the caller holds an admin role by name. Names are unique
// within the admin role container, so the client a role belongs to does not
// need naming at the call site - but the set this reads has already been
// narrowed to that container, which is what makes the name safe to ask about.
func (c *caller) has(role string) bool { return c.adminGrants[role] }

// hasAny reports whether the caller holds at least one of the roles a route
// accepts. Some routes take more than one: the user listing admits
// view-users, query-users or manage-users, measured.
func (c *caller) hasAny(roles []string) bool {
	for _, role := range roles {
		if c.adminGrants[role] {
			return true
		}
	}
	return false
}

// adminRoleImplications is what holding one admin role lets its holder hand
// out **beyond that role itself**. It is Keycloak's internal admin-permission
// model, which is not in this repository, derived by measurement.
//
// Method: 22 admin roles as the caller's role, 27 children each, swept over
// four surfaces on a live 26.7.1 with a fresh token minted immediately before
// every call - the two `available` reads, the role-mapping writes and `POST
// .../composites` on a realm parent and on a client parent. Each surface has a
// different route guard, so each contributes a different baseline and between
// them the per-role contribution is separable. The table below reproduces all
// 3178 measured cells with nothing left over; see the "A caller may hand out a
// role only if its own rights already confer it" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// Two shapes are deliberately **absent** and both were checked:
//
//   - Reflexivity is not listed. Every role confers itself, which grants()
//     gets from the caller's own role set rather than from an entry here.
//   - `admin` is not listed although it confers everything. It is composite
//     over all 21 client roles plus create-realm, so the caller's effective
//     set already carries them and the closure below reaches the rest.
//
// The three real composites among the admin roles - view-clients over
// query-clients, view-users over query-groups and query-users, view-organizations
// over query-organizations - **are** listed, because the closure runs over role
// names and an implied role is never expanded through the store.
//
// One family of edges is unobservable through this API and is therefore
// recorded only where it was measured directly: whether a role confers the
// query-* roles. Naming a client role as a composite child needs
// manage-clients (the parent-side guard, or requiresChildManageRole for a
// cross-family child), and a role-mapping write needs manage-users; both of
// those confer all five query roles, so no reachable request can distinguish
// whether, say, manage-events confers query-realms. The entries below are the
// two that were measured on their own, not a guess extended to their
// neighbours.
var adminRoleImplications = map[string][]string{
	"manage-realm":              {"view-realm", "manage-organizations"},
	"manage-clients":            {"view-clients", "create-client", "manage-authorization", "query-groups", "query-organizations", "query-realms", "query-users"},
	"manage-users":              {"view-users", "query-clients", "query-organizations", "query-realms"},
	"manage-organizations":      {"view-organizations"},
	"manage-authorization":      {"view-authorization"},
	"manage-events":             {"view-events"},
	"manage-identity-providers": {"view-identity-providers"},
	"view-clients":              {"view-authorization", "query-clients"},
	"view-users":                {"query-users", "query-groups"},
	"view-organizations":        {"query-organizations"},
}

// grants is the set of admin role names this caller may hand out: the admin
// roles it effectively holds, closed over adminRoleImplications.
//
// **It is seeded from adminGrants, not from the whole effective set.** Seeding
// it from every name the caller holds was a privilege escalation: mayGrantRole
// consults this map *before* deciding whether the role being handed out is an
// admin one, so an ordinary role named admin - minted on any client that is not
// the realm's own, or renamed into place - made the caller's own name set
// contain "admin" and unlocked the real realm role of that name. The closure
// below amplified it, since one collided name pulls in everything
// adminRoleImplications says that name confers.
//
// Ordinary roles are not in this map and do not need to be: mayGrantRole lets
// every non-admin role through on the container test below.
//
// Computed once per request and memoised on the caller, which is built per
// request and never shared.
func (c *caller) grants() map[string]bool {
	if c.granted == nil {
		c.granted = make(map[string]bool, len(c.adminGrants))
		for name := range c.adminGrants {
			c.implies(name)
		}
	}
	return c.granted
}

// implies adds one role name and everything it confers to c.granted. The
// guard on the way in is what terminates it: adminRoleImplications has cycles
// through nothing today, but a table that grew one would otherwise not stop.
func (c *caller) implies(name string) {
	if c.granted[name] {
		return
	}
	c.granted[name] = true
	for _, next := range adminRoleImplications[name] {
		c.implies(next)
	}
}

// mayGrantRole is F28's predicate: may this caller hand this role to anybody?
//
// **The role's container decides whether it is an admin role, not its name.**
// Measured: a client of one's own carrying roles literally named admin,
// impersonation and manage-realm is assignable in full by a caller holding only
// manage-users, and all three appear in that caller's available list, while
// master-realm's roles of the same names are refused to it.
//
// Ordinary roles are never checked this way, on any of the three call sites -
// roles.go's mayAttachChild and rolemappings.go's grantable and eachMapping.
// The admin roles are the ones the realm's own "{realm}-realm" client owns,
// plus the realm roles admin and create-realm - which exist in the master realm
// only, so a name test is enough for those two and Gloak bootstraps no other
// realm.
//
// **The same container test decides both sides.** grants() carries admin role
// names only, because adminRoleNames applied ownedByRealmOwnClient to the
// caller's own effective set when the caller was resolved; the lookup below
// applies it to the role being handed out. A caller that may grant the role
// short-circuits on the coverage test and pays no lookup here.
func (h *handler) mayGrantRole(ctx context.Context, realm *model.Realm, c *caller, role *model.Role) (bool, error) {
	if role.ClientID == "" {
		if c.grants()[role.Name] {
			return true, nil
		}
		return role.Name != "admin" && role.Name != "create-realm", nil
	}

	container, err := h.store.Clients().ByID(ctx, realm.ID, role.ClientID)
	if err != nil {
		return false, err
	}
	owner := adminRealmOf(realm.Name, container.ClientID)
	if owner == "" {
		return true, nil
	}
	if owner == realm.Name {
		// The realm being administered. This is the case that existed before
		// realm creation and its answer is unchanged: the caller's own admin
		// names, closed over adminRoleImplications.
		return c.grants()[role.Name], nil
	}

	// **An admin role belonging to a different realm**, which only exists now
	// that master holds a {realm}-realm client per realm. Measured on four
	// cells: a master caller holding manage-users on master-realm may hand out
	// exactly the one manage-users it holds on another realm's container and
	// nothing its implications would add, while a full administrator - which
	// reaches all 21 through the admin composite - may hand out all of them.
	// So conferral is computed per container and does not travel between them.
	//
	// The container is looked up in the caller's **own** realm, not in the
	// realm being administered: the same rights are spelled other-realm in
	// master and realm-management inside other, and a caller in master holds
	// them under the first spelling.
	ownerContainer, err := h.containerFor(ctx, c.authRealm, owner)
	if err != nil {
		return false, err
	}
	return c.foreignGrants(ownerContainer)[role.Name], nil
}

// adminRealmOf names the realm whose admin roles a client carries, or "" when
// it carries none.
//
// Two spellings and a suffix, all measured: master-realm in master and
// realm-management inside any other realm carry that realm's, and master holds
// a {realm}-realm client per realm carrying its. The suffix is wider than
// "names a realm that exists" - a hand-made nosuch-realm in master behaves
// exactly like master-realm - so no lookup narrows it here; the container it
// names simply resolves to nothing and confers nothing.
func adminRealmOf(realmName, clientID string) string {
	if clientID == bootstrap.AdminContainerFor(realmName) {
		return realmName
	}
	if owner, ok := strings.CutSuffix(clientID, "-realm"); ok && owner != "" {
		return owner
	}
	return ""
}

// resolveCaller turns a bearer token into the administrator behind it.
//
// Every failure is reported as the same measured 401. A missing header and a
// garbage token are byte-identical on this API - unlike userinfo, which
// distinguishes them - so telling them apart here would be a divergence, not a
// courtesy.
// **The caller is not always in the realm it is administering.** A token is
// accepted from the realm named in the path or from master, and the two are
// tried in that order - a realm-issued token must not be resolvable against
// master's keys by accident, and token.ParseAccess checks iss, so a token from
// the wrong realm fails closed rather than being mistaken for one from the
// right one. Measured: a caller in master holding view-users on p4e-realm reads
// /admin/realms/p4e/users, and a caller inside p4e holding realm-admin is 403
// on /admin/realms/master.
func (h *handler) resolveCaller(w http.ResponseWriter, r *http.Request, realm *model.Realm) *caller {
	raw := bearerToken(r)
	if raw == "" {
		writeUnauthorized(w)
		return nil
	}

	authRealm, user := h.authenticate(w, r, raw)
	if user == nil {
		return nil
	}

	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	container, err := h.containerFor(r.Context(), authRealm, realm.Name)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}

	return &caller{
		user:        user,
		adminGrants: adminRoleNames(authRealm, container, effective),
		authRealm:   authRealm,
		effective:   effective,
		container:   container,
	}
}

// authenticate resolves the bearer token in **the realm that issued it**, which
// is read from the token's own iss claim before any verification and then
// confirmed by it.
//
// That order is what makes a 403 reachable for a caller from a third realm. A
// caller inside `other` reaching `/admin/realms/master/users` was measured
// getting 403, not 401: Keycloak authenticated it - it holds a real session
// somewhere - and then found it holds nothing that opens master. Verifying only
// against the path realm, or only against the path realm and master, answers
// 401 there and loses the distinction.
//
// The unverified read selects a key and decides nothing else: ParseAccess then
// checks the signature, the issuer, the type and the expiry against that
// realm's keys, so a token naming a realm it was not issued by fails closed.
//
// Every failure is the same measured 401, byte for byte with a missing header.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, raw string) (*model.Realm, *model.User) {
	iss, err := token.UnverifiedIssuer(raw)
	if err != nil {
		writeUnauthorized(w)
		return nil, nil
	}
	name, ok := strings.CutPrefix(iss, h.issuerBase+"/realms/")
	if !ok || name == "" || strings.Contains(name, "/") {
		writeUnauthorized(w)
		return nil, nil
	}
	authRealm, err := h.store.Realms().ByName(r.Context(), name)
	if err != nil {
		writeUnauthorized(w)
		return nil, nil
	}

	k, err := h.keys.ForRealm(r.Context(), authRealm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, nil
	}
	parsed, err := token.ParseAccess(k, h.realmIssuer(authRealm.Name), raw, time.Now())
	if err != nil {
		writeUnauthorized(w)
		return nil, nil
	}
	session, err := h.store.Sessions().UserSessionByID(r.Context(), authRealm.ID, parsed.SessionID)
	if err != nil {
		writeUnauthorized(w)
		return nil, nil
	}
	user, err := h.store.Users().ByID(r.Context(), authRealm.ID, session.UserID)
	if err != nil || !user.Enabled {
		writeUnauthorized(w)
		return nil, nil
	}
	return authRealm, user
}

// containerFor is the client whose roles decide what this caller may do to the
// realm named in the path. It lives in the realm the caller authenticated in.
//
//	master administering master  -> master-realm
//	master administering other   -> other-realm
//	other  administering other   -> realm-management
//	other  administering a third -> nothing, so the caller holds no admin role
//
// Measured on all four: a master caller holding view-users on master-realm is
// 403 on /admin/realms/p4e/users and 200 on master's, and the same caller
// holding it on p4e-realm is the mirror. Nothing reaches upwards - realm-admin
// inside p4e is 403 on master - which the last row produces by having no
// container to read rights from at all.
//
// A container that does not exist is not an error: it is a caller with no admin
// roles, which every guard then refuses.
func (h *handler) containerFor(ctx context.Context, authRealm *model.Realm, targetRealm string) (*model.Client, error) {
	var name string
	switch {
	case authRealm.Name == bootstrap.MasterRealmName:
		name = masterContainerFor(targetRealm)
	case authRealm.Name == targetRealm:
		name = bootstrap.AdminContainerFor(targetRealm)
	default:
		return nil, nil
	}
	c, err := h.store.Clients().ByClientID(ctx, authRealm.ID, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return c, err
}

// masterContainerFor is the client in master carrying the rights to administer
// a realm: master-realm for master itself, {realm}-realm for every other.
// internal/bootstrap creates them; this rebuilds the name rather than importing
// an unexported one.
func masterContainerFor(realm string) string {
	if realm == bootstrap.MasterRealmName {
		return "master-realm"
	}
	return realm + "-realm"
}

// adminRoleNames reduces a role set to the names of the **admin** roles in it:
// the ones owned by container, plus the two realm roles admin and create-realm,
// which exist in master alone.
//
// This is the caller side of F28's predicate and the reason it cannot be
// defeated by a name. Deciding it here rather than in grants() is what keeps
// grants() a pure name closure over adminRoleImplications, which has to run over
// names because an implied role is never expanded through the store.
//
// **The container is passed in rather than looked up per role, and that is the
// change realm creation forced.** Until this cut there was one container per
// realm - "{realm}-realm" - and a role's own client was compared against it. A
// caller in master administering another realm holds its rights on that other
// realm's container in master, so the container is decided once by
// containerFor and every role is compared against that one client id. A nil
// container is a caller with no admin roles at all, which is what an in-realm
// caller reaching for a third realm was measured being.
//
// A role whose owning client no longer exists simply does not match the
// container, so F29's orphans confer nothing and cost no lookup. The earlier
// version needed a per-client lookup and a careful decision about swallowing
// ErrNotFound; this one needs neither, because it compares ids rather than
// asking what a client is called.
func adminRoleNames(authRealm *model.Realm, container *model.Client, in []*model.Role) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, role := range in {
		if role.ClientID == "" {
			// admin and create-realm exist in master alone, measured, so a
			// realm role of either name anywhere else is an ordinary role.
			if authRealm.Name == bootstrap.MasterRealmName &&
				(role.Name == "admin" || role.Name == "create-realm") {
				out[role.Name] = true
			}
			continue
		}
		if container != nil && role.ClientID == container.ID {
			out[role.Name] = true
		}
	}
	return out
}

// foreignGrants is the caller's admin role names on a container that is **not**
// the one this request's guards were decided by - the case a second realm
// creates, where a role being handed out lives on another realm's container.
//
// **Exact names, no implication closure, and that is measured.** A master
// caller holding manage-users on master-realm sees seven roles available on
// master-realm - manage-users and the six adminRoleImplications says it confers
// - and exactly one on other-realm, the manage-users it holds there. The full
// administrator, which reaches all 21 of other-realm through the admin
// composite, sees twenty. So conferral is computed per container and does not
// travel between them.
//
// Memoised per container, because a role-mapping batch asks about many roles of
// one.
func (c *caller) foreignGrants(container *model.Client) map[string]bool {
	if container == nil {
		return nil
	}
	if c.foreign == nil {
		c.foreign = make(map[string]map[string]bool, 1)
	}
	if names, ok := c.foreign[container.ID]; ok {
		return names
	}
	names := make(map[string]bool)
	for _, role := range c.effective {
		if role.ClientID == container.ID {
			names[role.Name] = true
		}
	}
	c.foreign[container.ID] = names
	return names
}

// writeUnauthorized emits the measured 401. It is shape 2 carrying the generic
// HTTP-status body, the same construction as the protocol side's
// {"error":"HTTP 404 Not Found"}, and it carries no WWW-Authenticate.
func writeUnauthorized(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusUnauthorized, "HTTP 401 Unauthorized")
}

// writeForbidden emits the measured 403 for a caller lacking the role an
// operation requires.
func writeForbidden(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusForbidden, "HTTP 403 Forbidden")
}

// bearerToken reads the access token out of the Authorization header. The
// admin API takes credentials no other way.
func bearerToken(r *http.Request) string {
	after, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(after)
}

// resolveRealm looks up the realm named in the path, writing the measured 404
// and returning nil when there is none.
//
// The message differs from the protocol side's by a trailing full stop -
// "Realm not found." here, "Realm does not exist" there - which is why this
// does not call into internal/oidc's version.
func (h *handler) resolveRealm(w http.ResponseWriter, r *http.Request) *model.Realm {
	realm, err := h.store.Realms().ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Realm not found.")
			return nil
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return realm
}
