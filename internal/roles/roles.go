// Package roles answers the one question both halves of the server ask about
// a user: what does this user actually hold?
//
// The answer is never the direct assignments. Measured on the bootstrapped
// administrator: it is assigned two realm roles and no client role at all,
// while its token carries five realm roles and twenty-four client roles across
// two clients. Everything else arrives through composites, so a caller that
// reads the assignments and stops sees an administrator with almost nothing.
//
// It lives in its own package because both callers need it and they need the
// same answer. internal/admin authorises a request with it; internal/oidc
// fills realm_access and resource_access with it. Two copies of the expansion
// would be two chances to disagree about who is an administrator.
//
// # The second question, and why it is here too
//
// InScope answers the other half: of the roles a user holds, which survive
// into a token issued for one client? That is Keycloak's fullScopeAllowed
// filter, and it has four callers who must not be able to disagree -
// internal/oidc's issuance and introspection, internal/account's audience gate
// and internal/admin's scope evaluator. It is a **set computation over the
// same composite walk**, not a policy: AGENTS.md records that a scope mapping
// grants nothing and is not an escalation surface, so this stays inside the
// boundary table's "must not decide who may do what". mayMapRole and
// mayGrantRole - which do decide that - deliberately stay in internal/admin.
package roles

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// Effective returns every role a user holds, each once: the direct
// assignments plus everything reachable through composites, however deep.
//
// The walk is iterative with a seen-set rather than recursive. A composite
// cycle is data, not a program error - nothing stops an administrator from
// making one through the API - so it has to exhaust the queue rather than the
// stack.
func Effective(ctx context.Context, repo store.RoleRepo, userID string) ([]*model.Role, error) {
	direct, err := repo.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	return ExpandFrom(ctx, repo, direct)
}

// EffectiveForGroup is Effective for a group holder. The expansion below is the
// same walk, and it is shared rather than copied because a group's composite
// read and a user's answer the same question and must not be able to disagree.
func EffectiveForGroup(ctx context.Context, repo store.RoleRepo, groupID string) ([]*model.Role, error) {
	direct, err := repo.ListGroupRoles(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return ExpandFrom(ctx, repo, direct)
}

// ExpandFrom closes a direct set over its composites.
func ExpandFrom(ctx context.Context, repo store.RoleRepo, direct []*model.Role) ([]*model.Role, error) {
	out := make([]*model.Role, 0, len(direct))
	seen := make(map[string]bool, len(direct))
	queue := make([]*model.Role, 0, len(direct))
	queue = append(queue, direct...)

	for len(queue) > 0 {
		role := queue[0]
		queue = queue[1:]
		if seen[role.ID] {
			continue
		}
		seen[role.ID] = true
		out = append(out, role)

		if !role.Composite {
			continue
		}
		children, err := repo.ListComposites(ctx, role.ID)
		if err != nil {
			return nil, err
		}
		queue = append(queue, children...)
	}
	return out, nil
}

// ScopesInEffect is the client scopes one issuance evaluates against: the
// client's default client scopes, plus the optional ones the granted scope
// names.
//
// Measured 2026-09-08 on a client with fullScopeAllowed off and a client scope
// carrying a scope mapping to a realm role the user holds:
//
//	the scope exists but is attached to nothing   the role is NOT in the token
//	attached as a default client scope            the role IS in the token
//	attached as optional, not named by `scope`    the role is NOT in the token
//	attached as optional, named by `scope`        the role IS in the token
//
// So the attachment is not enough on its own and neither is the request: an
// optional scope contributes exactly when the granted scope carries its name,
// which is also the name Keycloak writes into the token's own scope claim.
//
// A name in the granted scope that is not one of this client's optional scopes
// contributes nothing and is not an error - the admin evaluator's `?scope=`
// was measured silently ignoring one, and the protocol side never gets that
// far because grantedScope drops it first.
func ScopesInEffect(ctx context.Context, repo store.ClientScopeRepo, c *model.Client, granted string) ([]*model.ClientScope, error) {
	defaults, err := repo.ListClientScopes(ctx, c.ID, true)
	if err != nil {
		return nil, err
	}
	optional, err := repo.ListClientScopes(ctx, c.ID, false)
	if err != nil {
		return nil, err
	}
	asked := strings.Fields(granted)
	out := make([]*model.ClientScope, 0, len(defaults)+len(optional))
	out = append(out, defaults...)
	for _, s := range optional {
		if slices.Contains(asked, s.Name) {
			out = append(out, s)
		}
	}
	return out, nil
}

// InScope reports which of a subject's roles survive into a token issued for
// this client: Keycloak's fullScopeAllowed filter.
//
// Measured 2026-09-08 against a live 26.7.1, on a realm built for the purpose.
// A user holding five realm roles and three clients' roles asked a client with
// the flag **off** for a password grant:
//
//	nothing mapped        realm_access ABSENT, resource_access {capp: [capp-own]}
//	realm role rr1 mapped realm_access {roles: [rr1]}
//	client role co1 mapped resource_access gains {cother: [co1]}, and aud becomes
//	                      "cother" - the filter moves a second observable
//
// Three clauses, each refutable by a case the others pass:
//
//   - the flag short-circuits everything, and the control client differing only
//     in the flag answered all eight realm roles and three clients;
//   - **a client's own roles are in its own scope without being mapped** -
//     `capp-own` above - and it is the *issuing* client's, not every client's:
//     the same user's token from `cother` carried `cother`'s two roles and not
//     `capp-own`;
//   - an attached client scope contributes its own scope mappings, which is the
//     input the three scope-mapping *reads* do not have: with the scope
//     attached, .../scope-mappings, .../realm and .../realm/composite on the
//     client all answered empty while the token carried the role.
//
// # The composite question, and the measurement that settled it
//
// **The subject's roles are expanded first and the filter runs per role.** The
// discriminating fixture is a user holding a composite parent and *not* its
// child, with the **child alone** mapped into the scope: expand-then-filter
// answers the child, filter-then-expand answers nothing. Keycloak answered
// `{"roles":["rrchild"]}`.
//
// The scope side is expanded too, and separately: with the **parent alone**
// mapped the token carried parent and child both. So it is set membership over
// two independent closures, and mapping a child does not pull its parent in -
// measured, the parent stayed out.
//
// # The membership is keyed by id, and a name would be a hole
//
// `in` is keyed by `role.ID` and never by `role.Name`. **A name does not
// identify a role**: model.Role's own comment says a role is a realm role when
// ClientID is empty and a client role otherwise, so one name can name two
// roles in two containers. Keying by name is a consistent implementation that
// agrees with this one on every set of roles whose names are distinct - which
// is every fixture in this repository except the one built to refute it - and
// it is wrong in the **permissive** direction, which is the direction this
// whole function exists to close: it would let a client role through because
// some realm role of the same name is in scope.
//
// Measured 2026-09-08 on a realm built for it. A realm role and a client role
// share a name, the user holds both, and only the realm one is mapped into a
// flag-off client's scope: the token carries `realm_access {"roles":["twin"]}`
// and **no resource_access at all**. Pinned by
// oidc/introspection/scope-filtered-access-token, where a name-keyed map moves
// three claims at once - resource_access gains a client key and `aud` turns
// from a bare string into an array.
func InScope(ctx context.Context, repo store.RoleRepo, c *model.Client, scopes []*model.ClientScope) (func(*model.Role) bool, error) {
	if c.FullScopeAllowed {
		return func(*model.Role) bool { return true }, nil
	}
	direct, err := repo.ListClientScopeMappings(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	own, err := repo.ListClientRoles(ctx, c.RealmID, c.ID)
	if err != nil {
		return nil, err
	}
	direct = append(direct, own...)
	for _, s := range scopes {
		mapped, err := repo.ListClientScopeScopeMappings(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		direct = append(direct, mapped...)
	}
	reachable, err := ExpandFrom(ctx, repo, direct)
	if err != nil {
		return nil, err
	}
	in := make(map[string]bool, len(reachable))
	for _, role := range reachable {
		in[role.ID] = true
	}
	return func(role *model.Role) bool { return in[role.ID] }, nil
}

// Filter keeps the roles a predicate accepts, in order.
func Filter(in []*model.Role, ok func(*model.Role) bool) []*model.Role {
	out := make([]*model.Role, 0, len(in))
	for _, role := range in {
		if ok(role) {
			out = append(out, role)
		}
	}
	return out
}

// AssignDefaults gives a newly created user the realm's default-roles-<realm>
// composite, which is what Keycloak gives one.
//
// Measured 2026-08-23 both ways round: a user created through the admin API
// comes back holding it, and one it is taken away from issues an access token
// with no aud, no realm_access and no resource_access at all. Every user
// creation path has to call this - the admin API's and the service account
// one - or Gloak mints tokens Keycloak would not recognise as a user's.
//
// An existing assignment is not an error: this is called from paths that
// converge rather than fail.
func AssignDefaults(ctx context.Context, repo store.RoleRepo, realmID, realmName, userID string) error {
	role, err := repo.ByName(ctx, realmID, "", model.DefaultRolesName(realmName))
	if err != nil {
		return err
	}
	if err := repo.AssignToUser(ctx, userID, role.ID); err != nil && !errors.Is(err, store.ErrConflict) {
		return err
	}
	return nil
}

// Names was the effective set reduced to names, and it is deliberately not
// here any more. Its premise - "role names are unique within the client that
// owns them, and the admin API's roles all live on one client, so a name alone
// identifies a right" - is true of that client and false of the realm, which
// was F32: an ordinary client role named manage-realm passed every guard that
// names manage-realm.
//
// internal/admin reduces by **container** instead, in adminRoleNames, and it
// has to be done there because the container test needs the realm and the
// client store. A name-only reduction has no safe caller left on this API, so
// leaving one here would only be somewhere for the next one to come from.
