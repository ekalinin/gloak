package admin

import (
	"bytes"
	"errors"
	"io"
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

// componentWriteBody is what `POST /components` and `PUT /components/{id}`
// decode, and it is the representation rather than a create-specific type:
// unlike `POST /clients-initial-access` next door, every key the read serves is
// accepted on the way in.
//
// Config is a map here and an ordered slice on the way out, which is safe
// because **the wire order of a config is decided by javamap.KeyOrder and not
// by the request**: a create sending `{priority, zzzUndeclared, keySize,
// algorithm}` came back `{keySize, priority, algorithm}`, which is the
// function's order over the survivors and not the request's.
type componentWriteBody struct {
	ID           string              `json:"id"`
	Name         *string             `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId"`
	SubType      string              `json:"subType"`
	Config       map[string][]string `json:"config"`
}

// createComponent serves POST /admin/realms/{realm}/components.
//
// The measured order of its refusals:
//
//	Content-Type not JSON       415
//	empty body or null          500  unknown_error / consult the server log
//	a body that is not JSON     400  Cannot parse the JSON, code by body shape
//	an unknown field            400  strict, `ComponentRepresentation`, line+column
//	the pair does not resolve   400  {"error":"Invalid provider type or no such provider"}
//	a Workflow pair             403  managed through internal APIs
//	any other registered pair   500  unknown_error
//	the config                  400  {"errorMessage": …}, per provider
//	the body's id is taken      409  conflict / Duplicate resource error
//
// Four things a reader would expect to be refused and are not:
//
//   - **A duplicate `name` is a 201.** Components have no name uniqueness at
//     all, which is why the two `Allowed Client Scopes` rows a default realm
//     has can exist.
//   - **An absent `name` is a 201** and the row reads back with no `name` key,
//     so the state master's `declarative-user-profile` is in is reachable
//     through the API and a `name` column that cannot be null is wrong twice.
//   - **An absent `parentId` defaults to the realm's own id**, and a `parentId`
//     naming nothing at all is a 201 that stores it raw.
//   - **The body's `id` wins**, `POST /clients`' rule, and it goes into
//     `Location`. AGENTS.md's Location bullet lists this route among the
//     server-minted uuid tails without the qualifier it gives the identity
//     provider mapper create; the two behave the same way.
func (h *handler) createComponent(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, ok := decodeComponentBody(w, r)
	if !ok {
		return
	}
	if !h.resolveComponentProvider(w, body.ProviderType, body.ProviderID) {
		return
	}
	config, refusal := filterAndValidateComponentConfig(body.ProviderType, body.ProviderID, body.Config)
	if refusal != "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, refusal)
		return
	}
	c := &model.Component{
		ID:           body.ID,
		RealmID:      rc.realm.ID,
		Name:         body.Name,
		ProviderID:   body.ProviderID,
		ProviderType: body.ProviderType,
		ParentID:     body.ParentID,
		SubType:      body.SubType,
		Config:       config,
	}
	if c.ID == "" {
		c.ID = model.NewID()
	}
	if c.ParentID == "" {
		c.ParentID = rc.realm.ID
	}
	switch err := h.store.Components().Create(r.Context(), c); {
	case errors.Is(err, store.ErrConflict):
		httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/components/"+c.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateComponent serves PUT /admin/realms/{realm}/components/{id}.
//
// Three measured behaviours that the obvious implementation gets wrong:
//
//   - **It writes the component the *path* names.** A PUT addressed to one real
//     component and carrying another real component's `id` changed the
//     addressed one and left the other exactly as it was. That is the opposite
//     of `PUT .../protocol-mappers/models/{id}` and of
//     `PUT .../identity-provider/instances/{alias}/mappers/{id}`, both of which
//     write the body's - so the three routes in this API that look alike do not
//     agree, and the body's id is simply ignored here.
//   - **The config merges and is then re-filtered against the body's
//     providerId.** A PUT naming `{priority, junk, algorithm}` on a component
//     holding `{keySize, priority, algorithm}` left `keySize`, dropped `junk`
//     and moved the other two; moving the same component to `hmac-generated`,
//     which does not declare `keySize`, dropped that key. So `{"config":{}}`
//     and an absent `config` change nothing, and **the config cannot be cleared
//     through this endpoint at all**.
//   - **`providerId` and `providerType` are both required in the body.** Either
//     one alone is a 500, and so are `{}` and an empty body. The strict decode
//     runs **before** the path's id is resolved, so a PUT to a component that
//     does not exist carrying an unknown field answers the 400 and one carrying
//     a good body answers `Could not find component`.
//
// Two of Keycloak's own defects on this route are **not** reproduced and are
// filed as F159: a body carrying a `config` and no `providerId` writes the
// config and then answers 500, and a PUT naming an unknown `providerId` writes
// it and leaves the component unreadable for ever.
func (h *handler) updateComponent(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, ok := decodeComponentBody(w, r)
	if !ok {
		return
	}
	// The decode is strict before this, the provider check is after it, and the
	// 404 sits between the two - which is what the paired probes fix.
	if body.ProviderID == "" || body.ProviderType == "" {
		writeComponentConsultLog(w)
		return
	}
	c, err := h.store.Components().ByID(r.Context(), rc.realm.ID, r.PathValue("componentID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeComponentNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !h.resolveComponentProvider(w, body.ProviderType, body.ProviderID) {
		return
	}
	merged := mergeComponentConfig(c.Config, body.Config)
	config, refusal := filterAndValidateComponentConfig(body.ProviderType, body.ProviderID, merged)
	if refusal != "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, refusal)
		return
	}
	c.Name = body.Name
	c.ProviderID = body.ProviderID
	c.ProviderType = body.ProviderType
	c.SubType = body.SubType
	c.Config = config
	if body.ParentID != "" {
		c.ParentID = body.ParentID
	}
	if err := h.store.Components().Update(r.Context(), c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeComponentNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteComponent serves DELETE /admin/realms/{realm}/components/{id}.
//
// 204 with no `Cache-Control`, and `X-Frame-Options` only when the request
// declared an `application/*` `Content-Type` - which WriteNoContent decides.
// A second delete of the same id is `404 {"error":"Could not find component"}`,
// the opposite of `DELETE /clients-initial-access/{id}`, whose repeat is a 204.
//
// **This is F145, and this cut disagrees with it.** F145 left the delete
// unbuilt because Gloak's `GET /keys` is not backed by this table, so deleting
// a key-provider row would leave a realm in a state Keycloak cannot reach. The
// premise is confirmed and sharpened - a key's `providerId` *is* its
// component's id, one to one on all four, and deleting the component removes
// the key from `GET /keys` and from the JWKS alike - but the argument is
// symmetric with `POST /components`, which this cut builds: creating an
// `rsa-generated` component in Keycloak adds a key that Gloak's `/keys` would
// not see either. Wiring the two is half inside this package and half inside
// internal/oidc, so it is one branch's work rather than this one's, and F145
// stays open carrying the measurement.
func (h *handler) deleteComponent(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	err := h.store.Components().Delete(r.Context(), rc.realm.ID, r.PathValue("componentID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeComponentNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// resolveComponentProvider writes the refusal for a (providerType, providerId)
// pair the component endpoint will not create, and reports whether to carry on.
//
// The three refusals are three different statuses and only a registry tells
// them apart - which is why internal/model carries all 245 registered pairs and
// not just the 33 with declared properties.
func (h *handler) resolveComponentProvider(w http.ResponseWriter, providerType, providerID string) bool {
	switch model.ComponentCreateOutcomeOf(providerType, providerID) {
	case model.ComponentCreateUnregistered:
		// The same sentence for an unknown providerId under a known type and for
		// an unknown type, measured on all eighteen types - so it is about the
		// pair and not about either half, whatever its wording suggests.
		httpx.WriteMessageError(w, http.StatusBadRequest, "Invalid provider type or no such provider")
		return false
	case model.ComponentCreateManagedInternally:
		httpx.WriteMessageError(w, http.StatusForbidden,
			"Components managed through internal APIs cannot be managed through the component endpoint")
		return false
	case model.ComponentCreateUnsupported:
		writeComponentConsultLog(w)
		return false
	}
	return true
}

// mergeComponentConfig lays the request's config over the stored one. A name
// the request does not mention is kept, which is what makes the config
// unclearable through the PUT.
func mergeComponentConfig(stored []model.ComponentConfigEntry, in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(stored)+len(in))
	for _, e := range stored {
		out[e.Name] = e.Values
	}
	for name, values := range in {
		out[name] = values
	}
	return out
}

// filterAndValidateComponentConfig drops the keys the provider does not declare
// and then runs the provider's rules, returning the first refusal.
//
// **The filter is the catalogue and the validator is not.** A key the provider
// does not declare is dropped silently rather than refused, and the `required`
// flag the catalogue carries is not what refuses anything - fifteen providers
// refuse a bare create and only eight of those declare a required property. The
// rules are their own measured table.
//
// **The rules run in the provider's declared property order**, which is
// measured: `priority`, `enabled` and `active` are the first three properties
// every key provider declares and a create wrong in one of them and in a
// provider-specific property answers about them.
func filterAndValidateComponentConfig(providerType, providerID string,
	in map[string][]string) ([]model.ComponentConfigEntry, string) {
	entry, ok := model.ComponentProvider(providerType, providerID)
	if !ok {
		return nil, ""
	}
	declared := make([]string, 0, len(entry.Properties))
	kept := make(map[string][]string, len(in))
	for _, p := range entry.Properties {
		declared = append(declared, p.Name)
		if values, present := in[p.Name]; present {
			kept[p.Name] = values
		}
	}
	for _, rule := range model.ComponentConfigRules(providerType, providerID) {
		values, present := kept[rule.Property]
		if msg := model.ComponentRuleFails(rule, values, present); msg != "" {
			return nil, msg
		}
	}
	names := make([]string, 0, len(kept))
	for _, name := range declared {
		if _, present := kept[name]; present {
			names = append(names, name)
		}
	}
	out := make([]model.ComponentConfigEntry, 0, len(kept))
	for _, name := range javamap.KeyOrder(names) {
		out = append(out, model.ComponentConfigEntry{Name: name, Values: kept[name]})
	}
	return out, ""
}

// decodeComponentBody splits the empty body from the merely malformed one, the
// way the identity provider mapper create does: an empty body and a literal
// `null` are a 500 on both writes here where `{` is a 400 and `[` is a 400 with
// the other code.
func decodeComponentBody(w http.ResponseWriter, r *http.Request) (*componentWriteBody, bool) {
	if !requireJSONBody(w, r) {
		return nil, false
	}
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(r.Body)
		if err != nil {
			writeComponentConsultLog(w)
			return nil, false
		}
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || string(trimmed) == "null" {
		writeComponentConsultLog(w)
		return nil, false
	}
	var body componentWriteBody
	if !decodeStrictBytes(w, raw, "ComponentRepresentation", &body) {
		return nil, false
	}
	return &body, true
}
