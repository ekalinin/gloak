package oidc

import (
	"context"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// tokenRoles resolves what a token's realm_access and resource_access carry:
// the user's effective roles, split by the container that owns them.
//
// Client roles come back keyed by clientId rather than by the client's UUID,
// because that is what the claim names and what a resource server checks its
// own audience against.
//
// A role naming a client this realm does not have is dropped rather than
// keyed by its UUID. That cannot happen through the API - a client's roles go
// with it when it is deleted - but a token claiming roles on a client nobody
// can look up is worse than a token missing them.
func (h *handler) tokenRoles(ctx context.Context, realm *model.Realm, user *model.User) ([]string, map[string][]string, error) {
	effective, err := roles.Effective(ctx, h.store.Roles(), user.ID)
	if err != nil {
		return nil, nil, err
	}

	var realmRoles []string
	clientRoles := map[string][]string{}
	names := map[string]string{}
	for _, r := range effective {
		if r.ClientID == "" {
			realmRoles = append(realmRoles, r.Name)
			continue
		}
		name, ok := names[r.ClientID]
		if !ok {
			c, err := h.store.Clients().ByID(ctx, realm.ID, r.ClientID)
			if err != nil {
				continue
			}
			name = c.ClientID
			names[r.ClientID] = name
		}
		clientRoles[name] = append(clientRoles[name], r.Name)
	}
	return realmRoles, clientRoles, nil
}
