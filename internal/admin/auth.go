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

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// caller is an authenticated administrator and the roles it effectively holds:
// its direct assignments plus everything reachable through composites.
type caller struct {
	user    *model.User
	roles   map[string]bool
	granted map[string]bool
}

// has reports whether the caller holds a role by name. Names are unique within
// the admin role container, so the client a role belongs to does not need
// naming at the call site.
func (c *caller) has(role string) bool { return c.roles[role] }

// hasAny reports whether the caller holds at least one of the roles a route
// accepts. Some routes take more than one: the user listing admits
// view-users, query-users or manage-users, measured.
func (c *caller) hasAny(roles []string) bool {
	for _, role := range roles {
		if c.roles[role] {
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

// grants is the set of role names this caller may hand out: everything it
// effectively holds, closed over adminRoleImplications.
//
// It is seeded from the whole effective set rather than from the admin roles
// alone, because this package has no list of the 21 admin role names - which
// container owns a role is what makes it an admin role, and that is a store
// lookup mayGrantRole does per role rather than a constant here. Ordinary role
// names landing in this map costs nothing: mayGrantRole only consults it for a
// role it has already decided is an admin one.
//
// Computed once per request and memoised on the caller, which is built per
// request and never shared.
func (c *caller) grants() map[string]bool {
	if c.granted == nil {
		c.granted = make(map[string]bool, len(c.roles))
		for name := range c.roles {
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
// Ordinary roles are never checked this way, on any of the four call sites.
// The admin roles are the ones the realm's own "{realm}-realm" client owns,
// plus the realm roles admin and create-realm - which exist in the master realm
// only, so a name test is enough for those two and Gloak bootstraps no other
// realm.
//
// The coverage test runs **before** the container lookup, so a caller that may
// grant the role never pays for one; a full administrator does none at all.
func (h *handler) mayGrantRole(ctx context.Context, realm *model.Realm, c *caller, role *model.Role) (bool, error) {
	if c.grants()[role.Name] {
		return true, nil
	}
	if role.ClientID == "" {
		return role.Name != "admin" && role.Name != "create-realm", nil
	}
	adminRole, err := h.ownedByRealmOwnClient(ctx, realm, role)
	if err != nil {
		return false, err
	}
	return !adminRole, nil
}

// resolveCaller turns a bearer token into the administrator behind it.
//
// Every failure is reported as the same measured 401. A missing header and a
// garbage token are byte-identical on this API - unlike userinfo, which
// distinguishes them - so telling them apart here would be a divergence, not a
// courtesy.
func (h *handler) resolveCaller(w http.ResponseWriter, r *http.Request, realm *model.Realm) *caller {
	raw := bearerToken(r)
	if raw == "" {
		writeUnauthorized(w)
		return nil
	}
	k, err := h.keys.ForRealm(r.Context(), realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	parsed, err := token.ParseAccess(k, h.realmIssuer(realm.Name), raw, time.Now())
	if err != nil {
		writeUnauthorized(w)
		return nil
	}

	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		writeUnauthorized(w)
		return nil
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, session.UserID)
	if err != nil {
		writeUnauthorized(w)
		return nil
	}
	if !user.Enabled {
		writeUnauthorized(w)
		return nil
	}

	roles, err := h.effectiveRoles(r, user)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return &caller{user: user, roles: roles}
}

// effectiveRoles is the caller's rights: its direct assignments expanded
// through composites, reduced to names.
//
// The expansion is internal/roles' because internal/oidc needs the same one to
// fill a token's realm_access and resource_access, and the two must not be
// able to disagree about who is an administrator.
func (h *handler) effectiveRoles(r *http.Request, user *model.User) (map[string]bool, error) {
	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		return nil, err
	}
	return roles.Names(effective), nil
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
