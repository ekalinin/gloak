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

// requiredActionsJSON is the fourteen required action providers a pristine
// realm registers, read off a live 26.7.1 with
// `GET /admin/realms/{realm}/authentication/required-actions` and stored
// verbatim rather than transcribed.
//
// **They are identical in master and in a realm created through
// POST /admin/realms**, byte for byte - checked in both directions on one
// container. That is the client-scope precedent holding, and it is worth
// naming because the *flows* on the same tag do **not** hold it: a created
// realm has two Organization sub-flows master has not got.
//
// The order in the file is the order the listing serves, which is priority
// ascending. It is not relied on - ListByRealm sorts - but keeping the file in
// it makes the seed diffable against a fresh measurement.
//
//go:embed requiredactions.json
var requiredActionsJSON []byte

// requiredActionSeed is one row of that file. It carries no config: all
// fourteen are registered with an empty one, and `{}` is what the
// representation serves for them.
type requiredActionSeed struct {
	Alias         string `json:"alias"`
	Name          string `json:"name"`
	ProviderID    string `json:"providerId"`
	Enabled       bool   `json:"enabled"`
	DefaultAction bool   `json:"defaultAction"`
	Priority      int    `json:"priority"`
}

var requiredActionSeeds = func() []requiredActionSeed {
	var s []requiredActionSeed
	if err := json.Unmarshal(requiredActionsJSON, &s); err != nil {
		panic("bootstrap: requiredactions.json: " + err.Error())
	}
	return s
}()

// ensureRequiredActions registers the realm's fourteen required actions.
//
// Like everything else in this package it converges rather than
// short-circuiting: a row that is already there is left alone, so a realm whose
// creation crashed midway is repaired on the next call. "Already there" is
// decided by alias, which is the only thing about a seeded row that is stable -
// the id is minted here.
//
// A row an operator has since **deleted** is not put back, because a delete is
// exactly what `unregistered-required-actions` reports and re-seeding it would
// undo a measured operation on the next process start.
func ensureRequiredActions(ctx context.Context, s store.Store, realmID string) error {
	existing, err := s.RequiredActions().ListByRealm(ctx, realmID)
	if err != nil {
		return fmt.Errorf("bootstrap: list required actions: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	for _, seed := range requiredActionSeeds {
		name := seed.Name
		m := &model.RequiredActionProvider{
			ID:            model.NewID(),
			RealmID:       realmID,
			Alias:         seed.Alias,
			Name:          &name,
			ProviderID:    seed.ProviderID,
			Enabled:       seed.Enabled,
			DefaultAction: seed.DefaultAction,
			Priority:      seed.Priority,
		}
		err := s.RequiredActions().Create(ctx, m)
		if err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: register required action %q: %w", seed.Alias, err)
		}
	}
	return nil
}
