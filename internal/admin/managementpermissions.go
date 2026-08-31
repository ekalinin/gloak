package admin

import (
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The twelve `management/permissions` operations, and every one of them is a
// refusal.
//
// **`ADMIN_FINE_GRAINED_AUTHZ` is a DEPRECATED feature and is disabled on a
// default 26.7.1**, so both verbs on all six paths answer
//
//	501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
//
// byte for byte what `client-types` answers. `ADMIN_FINE_GRAINED_AUTHZ_V2` is
// enabled and `DEFAULT` and does **not** open them, which is the trap here:
// `GET /admin/serverinfo` reports one of the pair enabled and the other not,
// and the endpoints follow the deprecated one. Measured on all twelve, on both
// verbs, on 2026-08-31. These are contracts, not stubs, the same way
// `client-types`' 501 and `client-secret/rotated`'s 404 are.
//
// **The refusal runs before authorization on all twelve.** A caller holding no
// admin role at all gets the 501 rather than a 403, measured on four callers.
//
// **Where it runs relative to the path's own resource is not uniform, and that
// is the finding.** Measured with an id or a name that resolves to nothing:
//
//	/roles/{name}/management/permissions                       501 - the role is never looked up
//	/roles-by-id/{id}/management/permissions                   501 - nor is it here
//	/identity-provider/instances/{alias}/management/permissions 501 - nor here
//	/groups/{id}/management/permissions                        404 Could not find group by id
//	/clients/{uuid}/management/permissions                     404 Could not find client / 403
//	/clients/{uuid}/roles/{name}/management/permissions        404 for the client, 501 for the role
//
// Five orders on one refusal, on one API, and the realm precedes all of them.
// A rule stated over "every route naming a {something}" breaks here for the
// fifth time in this repository, and the description's tag predicts it where
// the path's shape does not: the three that resolve nothing are tagged
// `Roles`, `Roles (by ID)` and `Identity Providers`, and the two that resolve
// first are tagged `Groups` and `Clients` - which are exactly the two families
// AGENTS.md already records as resolving their resource before the caller.
//
// So this file registers three different combinators for one body, and
// collapsing them into one would be wrong on three routes whichever one was
// chosen.

// managementPermissions is the terminal every one of the twelve reaches. It
// takes the same shape as the other handlers so the guards can hand over to it,
// and it ignores everything it is given because the answer does not depend on
// any of it.
func (h *handler) managementPermissions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	writeFeatureNotEnabled(w, r, rc)
}

// managementPermissionsAfterGroup is the terminal for the two group routes,
// whose group is resolved first. guardGroup hands the group over and it is
// discarded here for the same reason.
func (h *handler) managementPermissionsAfterGroup(w http.ResponseWriter, r *http.Request, rc *reqContext, _ *model.Group) {
	writeFeatureNotEnabled(w, r, rc)
}

// guardClientFeature resolves the {clientUUID} and then refuses.
//
// It is the client-shaped `guardRealmFeature`: realm, caller, **client**, then
// the feature refusal with no role list, because the refusal precedes
// authorization. The client lookup uses the same id-phishing branch guardAuthz
// does - measured on the same container, in the same sweep:
// `view-clients`, `query-clients` and `manage-clients` see
// `Could not find client` and every other caller sees 403.
//
// The four routes it serves are `/clients/{uuid}/management/permissions` on
// both verbs and `/clients/{uuid}/roles/{name}/management/permissions` on both.
// The role name in the second pair is **not** resolved - a real client with a
// role that does not exist answers the 501 - so one combinator serves all four
// and the role segment is only ever matched by the mux.
func (h *handler) guardClientFeature(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if _, err := h.store.Clients().ByID(r.Context(), realm.ID, r.PathValue("clientUUID")); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				if c.hasAny(clientsReadRoles) {
					writeClientNotFound(w)
					return
				}
				writeForbidden(w)
				return
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}
