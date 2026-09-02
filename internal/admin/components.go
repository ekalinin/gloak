package admin

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// componentRepresentation is Keycloak's ComponentRepresentation, in the field
// order measured 2026-09-01:
//
//	id name providerId providerType parentId subType config
//
// Two of the seven carry omitempty and each for its own measured reason:
//
//   - **Name is omitted when absent**, and exactly one component in a default
//     install is in that state: master's `declarative-user-profile` row has no
//     `name` key at all, where the other fourteen have one. It is also the one
//     row a realm created through POST /admin/realms does not get, so "the
//     nameless component" and "the master-only component" are the same row.
//   - **SubType is omitted when empty**, and it is present on the ten
//     client-registration policies (`anonymous` or `authenticated`) and on
//     nothing else.
//
// `config` is always present, `{}` when empty - measured on the three policies
// that have none.
type componentRepresentation struct {
	ID           string          `json:"id"`
	Name         string          `json:"name,omitempty"`
	ProviderID   string          `json:"providerId"`
	ProviderType string          `json:"providerType"`
	ParentID     string          `json:"parentId"`
	SubType      string          `json:"subType,omitempty"`
	Config       componentConfig `json:"config"`
}

// componentConfig is the `config` object, a Keycloak MultivaluedHashMap: every
// value on the wire is a JSON array even when it holds one string,
// `{"priority":["100"]}`.
//
// It is a slice with its own marshaller for the reason identityProviderConfig
// is, and **it uses the other of Keycloak's two HashMap constructors**.
// javamap.KeyOrder places six of the seven key sets measured on this endpoint
// exactly and javamap.SizedKeyOrder gets two of those six wrong; on the
// identity providers next door the answer is the other way round, nine to nine
// against four wrong. So the two families are one function apart and a shared
// serialiser is wrong on whichever one it was not written for.
//
// The seventh set is twelve LDAP keys with three colliding pairs, which neither
// function can place because a collision chains in an insertion order nothing
// observable reveals. Nothing in this cut serves it - `POST /components` is not
// built - and it is recorded rather than approximated.
//
// **No body this package serves can tell the two functions apart**, and that is
// not a reason to relax: every config a default install has holds nought, one
// or two keys, and the two agree on all of those. A mutation swapping this call
// for SizedKeyOrder survived components_test.go's whole file. The claim
// therefore lives where the discriminating measurements do -
// javamap.TestKeyOrderReproducesAComponentsConfig and its counted counterpart -
// and the call here is right because those vectors say which constructor it is,
// not because anything here would notice.
type componentConfig []model.ComponentConfigEntry

func (c componentConfig) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range c {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(entry.Name)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		values, err := marshalOrderedValue(entry.Values)
		if err != nil {
			return nil, err
		}
		b.Write(values)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func componentRepresentationOf(c *model.Component) componentRepresentation {
	rep := componentRepresentation{
		ID:           c.ID,
		ProviderID:   c.ProviderID,
		ProviderType: c.ProviderType,
		ParentID:     c.ParentID,
		SubType:      c.SubType,
		Config:       orderComponentConfig(c.Config),
	}
	if c.Name != nil {
		rep.Name = *c.Name
	}
	return rep
}

// orderComponentConfig puts the stored entries into Keycloak's HashMap bucket
// order. The store keeps them in the order bootstrap wrote them, which is what
// would let a collision chain the way it did on the way in; javamap.KeyOrder
// decides the rest, and none of the seven key sets a default install has
// collides.
func orderComponentConfig(in []model.ComponentConfigEntry) componentConfig {
	byName := make(map[string]model.ComponentConfigEntry, len(in))
	names := make([]string, 0, len(in))
	for _, e := range in {
		byName[e.Name] = e
		names = append(names, e.Name)
	}
	out := make(componentConfig, 0, len(in))
	for _, name := range javamap.KeyOrder(names) {
		out = append(out, byName[name])
	}
	return out
}

// listComponents serves GET /admin/realms/{realm}/components.
//
// **The listing is neither empty nor about user federation on a fresh
// install.** A realm created through POST /admin/realms has fourteen rows and
// master has fifteen: four key providers, ten client-registration policies and
// - on master alone - the declarative user profile.
//
// **The row order is masked rather than asserted.** Two realms created minutes
// apart on one container returned the same fourteen rows in two entirely
// different orders, matching neither insertion, name, id nor provider. So is
// the `allowed-protocol-mapper-types` array inside two of the configs, measured
// the same way.
//
// The three filters run here rather than in the store, OrganizationRepo's
// precedent. **Every one of them answers `[]` for a value that matches
// nothing** - `?parent=bogus` and `?type=bogus` were both measured 200 with an
// empty array rather than a 404 - so they are a filter over rows and never a
// lookup that can fail.
//
// **`first` and `max` are ignored outright**, which is measured and is not the
// same as "there is no paging": `?first=1&max=2` returned all fourteen rows and
// `?first=abc` returned them too, where the identity provider listing one path
// segment away answers that malformed bound with a 404.
func (h *handler) listComponents(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	components, err := h.store.Components().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]componentRepresentation, 0, len(components))
	for _, c := range filterComponents(components, r.URL.Query()) {
		out = append(out, componentRepresentationOf(c))
	}
	writeAdminJSON(w, out)
}

// filterComponents applies type, parent and name, each an exact match.
func filterComponents(in []*model.Component, q url.Values) []*model.Component {
	out := in
	if t := q.Get("type"); t != "" {
		var kept []*model.Component
		for _, c := range out {
			if c.ProviderType == t {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	if p := q.Get("parent"); p != "" {
		var kept []*model.Component
		for _, c := range out {
			if c.ParentID == p {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	if n := q.Get("name"); n != "" {
		var kept []*model.Component
		for _, c := range out {
			if c.Name != nil && *c.Name == n {
				kept = append(kept, c)
			}
		}
		out = kept
	}
	return out
}

// readComponent serves GET /admin/realms/{realm}/components/{id}.
func (h *handler) readComponent(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	c, err := h.store.Components().ByID(r.Context(), rc.realm.ID, r.PathValue("componentID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeComponentNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, componentRepresentationOf(c))
}

// writeComponentNotFound is the 404 for a component id that resolves to
// nothing.
//
// **It is a new spelling of not-found**, and so is the
// `Could not find parent component` that `sub-component-types` answers - a
// route this cut does not build. It is in the bare-`error` family rather than
// the `errorMessage` one, like `Could not find client scope` and unlike
// `Client scope not found`.
//
// **The realm's own id answers it too.** Every component a default install has
// is parented on the realm, and `GET .../components/{realm id}` is this 404 -
// so the realm is a parent and is not itself a component.
func writeComponentNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find component")
}
