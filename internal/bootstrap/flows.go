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

// flowsJSON is the authentication flow model a pristine realm seeds, read off a
// live 26.7.1 on 2026-09-03 by walking `GET /authentication/flows`, then every
// `flowId` its execution listings named until the set closed, and finally every
// `authenticationConfig` those listings referenced.
//
// It was **walked rather than assumed**, because `GET /flows` serves top-level
// flows only: seven of the twenty are reachable from it and the other thirteen
// are not.
//
// A realm created through POST /admin/realms gets **20 flows, 55 execution rows
// and 4 configs**; master gets 17, 48 and 4. The difference is exactly three
// flows and two execution rows, which is why there is one table with a
// `notInMaster` flag rather than two files - the same device components.go
// uses, inverted. It was computed by diffing the two measured dumps field by
// field rather than transcribed, and everything outside the organization family
// compared byte-identical between the two realms.
//
// The client-scope precedent - "a realm's fifteen client scopes are identical
// in every realm" - does **not** hold here, and this is the second chapter
// where it does not.
//
//go:embed flows.json
var flowsJSON []byte

// flowSeed is one flow of that file.
type flowSeed struct {
	Alias       string `json:"alias"`
	Description string `json:"description"`
	ProviderID  string `json:"providerId"`
	TopLevel    bool   `json:"topLevel"`
	BuiltIn     bool   `json:"builtIn"`
	// NotInMaster marks the three flows only a created realm has:
	// `Organization`, `Browser - Conditional Organization` and
	// `First Broker Login - Conditional Organization`.
	NotInMaster bool            `json:"notInMaster"`
	Executions  []executionSeed `json:"executions"`
}

// executionSeed is one row inside a flow.
//
// Authenticator and FlowAlias are not exclusive: the `registration` flow's
// single row carries both, `registration-page-form` pointing at the
// `registration form` sub-flow. A seed type that made them a union would refuse
// the measurement.
type executionSeed struct {
	Requirement   string `json:"requirement"`
	Priority      int    `json:"priority"`
	Authenticator string `json:"authenticator"`
	FlowAlias     string `json:"flowAlias"`
	ConfigAlias   string `json:"configAlias"`
	// NotInMaster marks the two rows only a created realm has: `Organization`
	// at priority 26 in `browser`, and `First Broker Login - Conditional
	// Organization` at priority 60 in `first broker login`.
	NotInMaster bool `json:"notInMaster"`
}

type configSeed struct {
	Alias  string          `json:"alias"`
	Config json.RawMessage `json:"config"`
}

type flowSeedFile struct {
	Configs []configSeed `json:"configs"`
	Flows   []flowSeed   `json:"flows"`
}

var flowSeeds = func() flowSeedFile {
	var f flowSeedFile
	if err := json.Unmarshal(flowsJSON, &f); err != nil {
		panic("bootstrap: flows.json: " + err.Error())
	}
	return f
}()

// ensureAuthenticationFlows seeds the realm's flows, executions and configs.
//
// Ids are minted here rather than fixed in the file, and that is measured
// rather than tidy: the login page's `execution` parameter **is** the browser
// flow's `auth-username-password-form` execution id, and it differs between two
// realms on one container. A fixed id would make two realms serve one value.
//
// Like everything else in this package it converges rather than
// short-circuiting on a partial realm, but a realm that already has flows is
// left entirely alone - re-seeding would undo an operator's DELETE /flows/{id},
// which is the same reason ensureRequiredActions returns early.
func ensureAuthenticationFlows(ctx context.Context, s store.Store, realmID string, isMaster bool) error {
	repo := s.AuthenticationFlows()
	existing, err := repo.ListFlows(ctx, realmID)
	if err != nil {
		return fmt.Errorf("bootstrap: list authentication flows: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}

	configIDs := make(map[string]string, len(flowSeeds.Configs))
	for _, c := range flowSeeds.Configs {
		var m model.StringMap
		if err := json.Unmarshal(c.Config, &m); err != nil {
			return fmt.Errorf("bootstrap: authenticator config %q: %w", c.Alias, err)
		}
		id := model.NewID()
		cfg := &model.AuthenticationConfig{ID: id, RealmID: realmID, Alias: c.Alias, Config: m}
		if err := repo.CreateConfig(ctx, cfg); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create authenticator config %q: %w", c.Alias, err)
		}
		configIDs[c.Alias] = id
	}

	// Two passes, because an execution row names its sub-flow by alias and the
	// sub-flow may be seeded after the flow that points at it - `browser` names
	// `forms`, which is nine entries further down the file.
	flowIDs := make(map[string]string, len(flowSeeds.Flows))
	ordinal := 0
	for _, f := range flowSeeds.Flows {
		if isMaster && f.NotInMaster {
			continue
		}
		alias := f.Alias
		id := model.NewID()
		m := &model.AuthenticationFlow{
			ID:          id,
			RealmID:     realmID,
			Alias:       &alias,
			Description: f.Description,
			ProviderID:  f.ProviderID,
			TopLevel:    f.TopLevel,
			BuiltIn:     f.BuiltIn,
			Ordinal:     ordinal,
		}
		if err := repo.CreateFlow(ctx, m); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create authentication flow %q: %w", f.Alias, err)
		}
		flowIDs[f.Alias] = id
		ordinal++
	}

	for _, f := range flowSeeds.Flows {
		if isMaster && f.NotInMaster {
			continue
		}
		parent := flowIDs[f.Alias]
		for _, e := range f.Executions {
			if isMaster && e.NotInMaster {
				continue
			}
			m := &model.AuthenticationExecution{
				ID:            model.NewID(),
				RealmID:       realmID,
				ParentFlowID:  parent,
				Authenticator: e.Authenticator,
				FlowID:        flowIDs[e.FlowAlias],
				ConfigID:      configIDs[e.ConfigAlias],
				Requirement:   e.Requirement,
				Priority:      e.Priority,
			}
			if e.FlowAlias != "" && m.FlowID == "" {
				return fmt.Errorf("bootstrap: flow %q names sub-flow %q, which the seed does not contain", f.Alias, e.FlowAlias)
			}
			if e.ConfigAlias != "" && m.ConfigID == "" {
				return fmt.Errorf("bootstrap: flow %q names config %q, which the seed does not contain", f.Alias, e.ConfigAlias)
			}
			if err := repo.CreateExecution(ctx, m); err != nil && !errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("bootstrap: create execution in %q: %w", f.Alias, err)
			}
		}
	}
	return nil
}
