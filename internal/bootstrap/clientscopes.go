package bootstrap

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// clientScopesJSON is the fifteen client scopes a realm is created with,
// recorded from GET /admin/realms/{realm}/client-scopes on a live Keycloak
// 26.7.1 on 2026-08-29 with the per-container UUIDs removed.
//
// It is a recording, not a transcription. The same dump was taken from master
// and from a realm created through POST /admin/realms and the two were compared
// after stripping ids and sorting each scope's mappers by name: fifteen scopes,
// thirty-five protocol mappers, zero differences. So one file serves every
// realm.
//
// Key order inside `attributes` and inside each mapper's `config` is Keycloak's
// own and is preserved through model.StringMap, which is why the bootstrapped
// bodies need no Case.UnorderedKeys mask where a scope created through the API
// does.
//
//go:embed clientscopes.json
var clientScopesJSON []byte

// clientScopeSeed is the decode target for clientscopes.json. It exists rather
// than putting json tags on model.ClientScope because model carries no
// serialisation: the wire shape lives in internal/admin, and this file is a
// third thing again - a recording of what a realm starts with.
type clientScopeSeed struct {
	Scopes []struct {
		Name            string          `json:"name"`
		Description     string          `json:"description"`
		Protocol        string          `json:"protocol"`
		Attributes      model.StringMap `json:"attributes"`
		ProtocolMappers []struct {
			Name            string          `json:"name"`
			Protocol        string          `json:"protocol"`
			ProtocolMapper  string          `json:"protocolMapper"`
			ConsentRequired bool            `json:"consentRequired"`
			Config          model.StringMap `json:"config"`
		} `json:"protocolMappers"`
	} `json:"scopes"`
	// DefaultScopes and OptionalScopes are the realm's own two sets. Nine and
	// five, not six and five: the three SAML scopes are in the realm's default
	// set and are filtered out when an openid-connect client inherits from it.
	DefaultScopes  []string `json:"defaultScopes"`
	OptionalScopes []string `json:"optionalScopes"`
}

// seed is parsed once. A malformed file is a programming error in this
// repository rather than anything a running server can cause, so it panics
// rather than making every caller carry an error it cannot handle.
var seed = func() clientScopeSeed {
	var s clientScopeSeed
	if err := json.Unmarshal(clientScopesJSON, &s); err != nil {
		panic("bootstrap: clientscopes.json: " + err.Error())
	}
	return s
}()

// ensureClientScopes creates the realm's fifteen client scopes and its own two
// default sets. Like everything else in this package it converges rather than
// short-circuiting, so a half-built realm is repaired on the next call.
func ensureClientScopes(ctx context.Context, s store.Store, realmID string) error {
	for _, sc := range seed.Scopes {
		m := &model.ClientScope{
			ID:          model.NewID(),
			RealmID:     realmID,
			Name:        sc.Name,
			Description: sc.Description,
			Protocol:    sc.Protocol,
			Attributes:  sc.Attributes,
		}
		for _, pm := range sc.ProtocolMappers {
			m.ProtocolMappers = append(m.ProtocolMappers, model.ProtocolMapper{
				ID:              model.NewID(),
				Name:            pm.Name,
				Protocol:        pm.Protocol,
				ProtocolMapper:  pm.ProtocolMapper,
				ConsentRequired: pm.ConsentRequired,
				Config:          pm.Config,
			})
		}
		if err := s.ClientScopes().Create(ctx, m); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create client scope %q: %w", sc.Name, err)
		}
	}

	add := func(names []string, defaultScope bool) error {
		for _, name := range names {
			sc, err := s.ClientScopes().ByName(ctx, realmID, name)
			if err != nil {
				return fmt.Errorf("bootstrap: look up client scope %q: %w", name, err)
			}
			err = s.ClientScopes().AddRealmDefault(ctx, realmID, sc.ID, defaultScope)
			if err != nil && !errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("bootstrap: default client scope %q: %w", name, err)
			}
		}
		return nil
	}
	if err := add(seed.DefaultScopes, true); err != nil {
		return err
	}
	return add(seed.OptionalScopes, false)
}

// InheritClientScopes fills a client's two scope name lists from the realm's
// own default sets when the client does not name them, and is the one place
// that decides what "the body did not say" means.
//
// Measured on POST /admin/realms/{realm}/clients, three ways:
//
//	{"clientId":"x"}                                  -> the realm's defaults
//	{"clientId":"x","defaultClientScopes":[]}         -> none
//	{"clientId":"x","defaultClientScopes":["email"]}  -> exactly email
//
// So nil means inherit and an empty slice means none, which is the distinction
// encoding/json already draws between an absent key and `[]`. Inheritance is
// filtered by the client's protocol: a saml client created bare inherits
// AuthnContextClassRef, role_list and saml_organization and no optionals, where
// an openid-connect one inherits six and five out of the same nine and five.
//
// It runs **before** Clients().Create, which is what turns the names into
// attachments. Names a realm does not have are dropped there, in silence,
// measured: a client created naming "nosuchscope" answered 201 and carries an
// empty list.
//
// It is exported because internal/admin's POST /clients needs exactly this and
// a second copy would be a second place for the nil/empty distinction to be
// got wrong. Closing follow-up F49 is what it does.
func InheritClientScopes(ctx context.Context, s store.Store, realmID string, c *model.Client) error {
	if c.DefaultClientScopes == nil {
		names, err := inheritedNames(ctx, s, realmID, c.Protocol, true)
		if err != nil {
			return err
		}
		c.DefaultClientScopes = names
	}
	if c.OptionalClientScopes == nil {
		names, err := inheritedNames(ctx, s, realmID, c.Protocol, false)
		if err != nil {
			return err
		}
		c.OptionalClientScopes = names
	}
	return nil
}

// inheritedNames is the realm's own set for this list, kept to the scopes a
// client of this protocol can carry.
//
// The protocol filter is measured on the write path too: PUT
// /clients/{uuid}/default-client-scopes/{id} naming a saml scope on an
// openid-connect client answers 204 and attaches nothing. A client with no
// protocol of its own - master-realm is the one - matches nothing, and that
// client's two lists were measured empty.
func inheritedNames(ctx context.Context, s store.Store, realmID, protocol string,
	defaultScope bool) ([]string, error) {
	scopes, err := s.ClientScopes().ListRealmDefaults(ctx, realmID, defaultScope)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read the realm's client scopes: %w", err)
	}
	out := []string{}
	for _, sc := range scopes {
		if ScopeMatchesProtocol(sc, protocol) {
			out = append(out, sc.Name)
		}
	}
	return out, nil
}

// ScopeMatchesProtocol reports whether a client of the given protocol may carry
// this client scope. A scope with no protocol of its own matches nothing, the
// same way a client with none does.
func ScopeMatchesProtocol(sc *model.ClientScope, protocol string) bool {
	return protocol != "" && sc.Protocol == protocol
}
