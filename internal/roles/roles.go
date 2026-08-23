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
package roles

import (
	"context"
	"errors"

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

// Names is the effective set reduced to the names an authorization check asks
// about. Role names are unique within the client that owns them, and the admin
// API's roles all live on one client, so a name alone identifies a right
// there.
func Names(effective []*model.Role) map[string]bool {
	names := make(map[string]bool, len(effective))
	for _, r := range effective {
		names[r.Name] = true
	}
	return names
}
