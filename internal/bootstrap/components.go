package bootstrap

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// componentsJSON is what `GET /admin/realms/{realm}/components` answers on a
// realm nobody has touched, recorded from a live Keycloak 26.7.1 on 2026-09-01
// with the per-container UUIDs removed.
//
// **A created realm has fourteen and master has fifteen**, which is measured
// and is the reason the file carries a `masterOnly` flag rather than one list.
// The fifteenth is the `declarative-user-profile` row, and it is also the one
// component in the whole family with **no `name` key at all**. A realm created
// through `POST /admin/realms` does not get it; every other row is identical in
// the two realms once the ids are stripped.
//
// The rows are stored in this file's order and **that is not Keycloak's**. The
// listing's row order was measured having no reproducible order: two realms
// created minutes apart on one container returned the same fourteen rows in two
// entirely different orders, matching neither insertion, name, id nor provider.
// The conformance case masks the array. This order is a readable one - the four
// key providers in the order the keys endpoint names them, then the ten
// policies grouped by subType and name - chosen so a person can diff the file
// against the server, not because the server agrees with it.
//
// The `allowed-protocol-mapper-types` array inside two of the configs has no
// reproducible order either, measured the same way on the same two realms.
//
//go:embed components.json
var componentsJSON []byte

// componentSeed is the decode target. It exists rather than putting json tags
// on model.Component for the reason clientScopeSeed does: model carries no
// serialisation, and this file is a recording rather than a wire shape.
//
// Name is a pointer because the user-profile row has no `name` key, and Config
// is a plain map because **the stored order does not decide the wire order**:
// javamap.KeyOrder does, in internal/admin, and none of the seven key sets in
// this file has a bucket collision - which is the only case where the order a
// key arrived in would matter. Sorting the names here is what makes the two
// drivers write the same rows.
type componentSeed struct {
	Name         *string             `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	SubType      string              `json:"subType"`
	Config       map[string][]string `json:"config"`
	// MasterOnly marks the one row a realm created through POST /admin/realms
	// does not get.
	MasterOnly bool `json:"masterOnly"`
}

// componentSeeds is parsed once. A malformed file is a programming error in
// this repository rather than anything a running server can cause, so it panics
// rather than making every caller carry an error it cannot handle - the shape
// clientscopes.go's seed already uses.
var componentSeeds = func() []componentSeed {
	var out []componentSeed
	if err := json.Unmarshal(componentsJSON, &out); err != nil {
		panic(fmt.Sprintf("bootstrap: components.json: %v", err))
	}
	return out
}()

// ensureComponents writes a realm's SPI components.
//
// It is idempotent the way every other ensure in this package is: a row whose
// (providerType, providerId, subType, name) is already there is left alone, so
// a process that crashed midway through is repaired rather than duplicated.
// The identity is that quadruple rather than the name, because two policies
// share the name `Allowed Client Scopes` and differ only in the subType.
func ensureComponents(ctx context.Context, s store.Store, realm *model.Realm, master bool) error {
	existing, err := s.Components().List(ctx, realm.ID)
	if err != nil {
		return fmt.Errorf("bootstrap: list components: %w", err)
	}
	have := map[string]bool{}
	for _, c := range existing {
		have[componentKey(c.ProviderType, c.ProviderID, c.SubType, c.Name)] = true
	}
	for _, seed := range componentSeeds {
		if seed.MasterOnly && !master {
			continue
		}
		if have[componentKey(seed.ProviderType, seed.ProviderID, seed.SubType, seed.Name)] {
			continue
		}
		c := &model.Component{
			ID:           model.NewID(),
			RealmID:      realm.ID,
			Name:         seed.Name,
			ProviderID:   seed.ProviderID,
			ProviderType: seed.ProviderType,
			// Every component a default install has is parented on the realm's
			// own internal id, measured on both realms.
			ParentID: realm.ID,
			SubType:  seed.SubType,
			Config:   componentConfigOf(seed.Config),
		}
		if err := s.Components().Create(ctx, c); err != nil && !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("bootstrap: create component %q: %w", seed.ProviderID, err)
		}
	}
	return nil
}

func componentKey(providerType, providerID, subType string, name *string) string {
	n := "\x00"
	if name != nil {
		n = *name
	}
	return providerType + "\x1f" + providerID + "\x1f" + subType + "\x1f" + n
}

// componentConfigOf turns the decoded map into the ordered slice the model
// holds. The map's own iteration order is random, so the names are sorted here
// to make the store deterministic; javamap.KeyOrder decides the wire order
// afterwards and does not care what order it is handed - organizations.go's
// organizationAttributesOf makes the same trade for the same reason.
func componentConfigOf(in map[string][]string) []model.ComponentConfigEntry {
	if len(in) == 0 {
		return nil
	}
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.ComponentConfigEntry, 0, len(names))
	for _, name := range names {
		out = append(out, model.ComponentConfigEntry{Name: name, Values: in[name]})
	}
	return out
}
