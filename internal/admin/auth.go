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
	user  *model.User
	roles map[string]bool
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
