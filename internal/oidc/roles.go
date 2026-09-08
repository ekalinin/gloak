package oidc

import (
	"context"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// tokenRoles resolves what a token's realm_access and resource_access carry:
// the user's effective roles **filtered by the issuing client's token scope**,
// split by the container that owns them.
//
// Client roles come back keyed by clientId rather than by the client's UUID,
// because that is what the claim names and what a resource server checks its
// own audience against.
//
// A role naming a client this realm does not have is dropped rather than
// keyed by its UUID. That cannot happen through the API - a client's roles go
// with it when it is deleted - but a token claiming roles on a client nobody
// can look up is worse than a token missing them.
//
// # The filter, and which client's it is
//
// `client` is the client the token is **for**, which is not always the caller.
// Issuance and the exchange pass the requesting client; introspection passes
// the client named by the subject token's azp, measured 2026-09-08 - a second
// client introspecting a filtered token got the *issuing* client's filtered
// role set and not its own.
//
// `scope` is the granted scope, and it is read for one thing only: which of
// the client's optional client scopes are in effect. See roles.ScopesInEffect.
//
// The filter reaches four observables, not one: realm_access,
// resource_access, `aud` and the refresh token's `aud_x` - the last two
// because token.Audience is computed from the client roles this function
// returns. Measured: mapping one client role into a filtered client's scope
// moved `aud` from absent to that client's name.
func (h *handler) tokenRoles(ctx context.Context, realm *model.Realm, client *model.Client, user *model.User, scope string) ([]string, map[string][]string, error) {
	effective, err := roles.Effective(ctx, h.store.Roles(), user.ID)
	if err != nil {
		return nil, nil, err
	}
	scopes, err := roles.ScopesInEffect(ctx, h.store.ClientScopes(), client, scope)
	if err != nil {
		return nil, nil, err
	}
	inScope, err := roles.InScope(ctx, h.store.Roles(), client, scopes)
	if err != nil {
		return nil, nil, err
	}

	var realmRoles []string
	clientRoles := map[string][]string{}
	names := map[string]string{}
	for _, r := range roles.Filter(effective, inScope) {
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
