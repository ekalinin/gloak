package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// identityProviderMapperRepresentation is Keycloak's
// IdentityProviderMapperRepresentation, in the field order measured 2026-09-02:
//
//	id name identityProviderAlias identityProviderMapper config
//
// Nothing here carries omitempty. All five keys were present on every measured
// body, `config` as `{}` on a mapper created without one, and
// `identityProviderAlias` even when its value names no provider in the realm.
type identityProviderMapperRepresentation struct {
	ID                     string                       `json:"id"`
	Name                   string                       `json:"name"`
	IdentityProviderAlias  string                       `json:"identityProviderAlias"`
	IdentityProviderMapper string                       `json:"identityProviderMapper"`
	Config                 identityProviderMapperConfig `json:"config"`
}

// identityProviderMapperConfig is the `config` object.
//
// **Single-valued**, where a component's config is a list of strings: a
// mapper's is `{"role":"offline_access"}` and a component's is
// `{"priority":["100"]}`, one chapter apart.
//
// **It is javamap.SizedKeyOrder**, the same constructor its parent identity
// provider's config uses and the other one from the component's. Ten key sets
// were measured on this endpoint, SizedKeyOrder places all ten and KeyOrder
// gets six of them wrong. One key set settles it without any inference:
// `{priority, enabled, active}` sent to a mapper comes back
// `priority active enabled` and sent to a component comes back
// `active priority enabled`, on one container.
type identityProviderMapperConfig []model.IdentityProviderMapperConfigEntry

func (c identityProviderMapperConfig) MarshalJSON() ([]byte, error) {
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
		value, err := marshalOrderedValue(entry.Value)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func identityProviderMapperRepresentationOf(m *model.IdentityProviderMapper) identityProviderMapperRepresentation {
	return identityProviderMapperRepresentation{
		ID:                     m.ID,
		Name:                   m.Name,
		IdentityProviderAlias:  m.Alias,
		IdentityProviderMapper: m.Mapper,
		Config:                 orderIdentityProviderMapperConfig(m.Config),
	}
}

// orderIdentityProviderMapperConfig puts the stored pairs into Keycloak's
// HashMap bucket order.
//
// The store keeps them in the order the request carried them, which is what
// SizedKeyOrder's first argument means and what a bucket collision chains by.
// That order is preserved end to end here rather than sorted, which is the one
// thing this handler does that its neighbour in identityproviders.go does not -
// see decodeIdentityProviderMapperBody.
func orderIdentityProviderMapperConfig(in []model.IdentityProviderMapperConfigEntry) identityProviderMapperConfig {
	byName := make(map[string]model.IdentityProviderMapperConfigEntry, len(in))
	names := make([]string, 0, len(in))
	for _, e := range in {
		byName[e.Name] = e
		names = append(names, e.Name)
	}
	out := make(identityProviderMapperConfig, 0, len(in))
	for _, name := range javamap.SizedKeyOrder(len(names), names) {
		out = append(out, byName[name])
	}
	return out
}

// identityProviderMapperBody is what the two writes decode.
//
// Decoded with decodeStrict: `POST .../mappers` is the **tenth** strict
// endpoint, naming its own class with a line and a column,
//
//	400 {"error":"Invalid json representation for IdentityProviderMapperRepresentation.
//	     Unrecognized field \"zzz\" at line 1 column 22."}
//
// Config is a json.RawMessage rather than a map[string]string, and that is the
// whole reason this type exists instead of reusing the neighbouring one: a Go
// map loses the order the request carried, and the order is observable.
// `{"zz":..,"aa":..,"mm":..}` and `{"aa":..,"mm":..,"zz":..}` were both sent and
// both came back in the order they went in, because those three keys share a
// bucket at this table size and only the insertion order separates them.
type identityProviderMapperBody struct {
	ID                     string          `json:"id"`
	Name                   string          `json:"name"`
	IdentityProviderAlias  string          `json:"identityProviderAlias"`
	IdentityProviderMapper string          `json:"identityProviderMapper"`
	Config                 json.RawMessage `json:"config"`
}

// listIdentityProviderMappers serves
// GET /admin/realms/{realm}/identity-provider/instances/{alias}/mappers.
//
// **It is the only route of the five that reads the path's alias.** The three
// that name a mapper id resolve it realm-wide - see readIdentityProviderMapper.
//
// It takes no parameters at all: `first`, `max`, `search` and
// `briefRepresentation` were each measured returning the whole set, and so was
// the malformed `first=abc`, where the listing one path segment up answers that
// with a 404.
func (h *handler) listIdentityProviderMappers(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	alias := ""
	if p.Alias != nil {
		alias = *p.Alias
	}
	mappers, err := h.store.IdentityProviderMappers().List(r.Context(), rc.realm.ID, alias)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]identityProviderMapperRepresentation, 0, len(mappers))
	for _, m := range mappers {
		out = append(out, identityProviderMapperRepresentationOf(m))
	}
	writeAdminJSON(w, out)
}

// readIdentityProviderMapper serves
// GET .../identity-provider/instances/{alias}/mappers/{id}.
//
// **The path's alias decides only whether the request reaches here.** Once the
// provider it names exists, the mapper id is resolved realm-wide: a mapper
// created under one broker was served through a second broker's path with a
// 200, while that second broker's own listing answered `[]`. The delete
// behaves the same way and removed it. Scoping the lookup to the alias is the
// tidy-up that turns two measured 2xx into 404s.
func (h *handler) readIdentityProviderMapper(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	m, ok := h.identityProviderMapperByPath(w, r, rc)
	if !ok {
		return
	}
	writeAdminJSON(w, identityProviderMapperRepresentationOf(m))
}

// deleteIdentityProviderMapper serves
// DELETE .../identity-provider/instances/{alias}/mappers/{id}.
//
// Its 204 carries `Cache-Control: no-cache` and no `X-Frame-Options` - the
// request sends no Content-Type, which is what decides the second. The repeat
// is `Model not found`.
func (h *handler) deleteIdentityProviderMapper(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	if _, ok := h.identityProviderMapperByPath(w, r, rc); !ok {
		return
	}
	if err := h.store.IdentityProviderMappers().Delete(r.Context(), rc.realm.ID, r.PathValue("mapperID")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeIdentityProviderMapperNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// createIdentityProviderMapper serves
// POST .../identity-provider/instances/{alias}/mappers.
//
// The check order is measured and no two steps share a shape:
//
//	unknown field            strict 400 naming IdentityProviderMapperRepresentation
//	empty body or null       500 unknown_error / consult the server log
//	malformed body           400 invalid_request / Cannot parse the JSON
//	no name                  409 {"error":"conflict","error_description":"Duplicate resource error"}
//	duplicate name           400 {"errorMessage":"Failed to add mapper 'x' to identity provider [oidc]."}
//
// **A missing name answers the same 409 a duplicate resource does**, which is
// the policy family's answer to a body with no name and the third family in
// this API to give it. And **a duplicate is a 400 rather than a 409**, with a
// sentence naming the provider's `providerId` where the route carries its
// alias - so the two failures a name can have are two different statuses and
// neither is the one the rest of the API uses.
//
// **The mapper type is not validated.** A create naming
// `identityProviderMapper: "nope"` answered 201, and so did one whose
// `identityProviderAlias` named no provider at all. Validating either against
// the catalogue this cut adds is the obvious tightening and it is measurably
// wrong.
//
// The body's `id` wins, the fifth create in this API with that rule.
func (h *handler) createIdentityProviderMapper(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	body, ok := decodeIdentityProviderMapperBody(w, r)
	if !ok {
		return
	}
	if body.Name == "" {
		httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
		return
	}
	m := identityProviderMapperOf(rc.realm.ID, body)
	if m.ID == "" {
		m.ID = model.NewID()
	}
	switch err := h.store.IdentityProviderMappers().Create(r.Context(), m); {
	case errors.Is(err, store.ErrConflict):
		// The sentence names the **providerId** of the provider the path
		// resolved, not the alias in the path and not the alias in the body.
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Failed to add mapper '"+body.Name+"' to identity provider ["+p.ProviderID+"].")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	alias := ""
	if p.Alias != nil {
		alias = *p.Alias
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/identity-provider/instances/"+alias+"/mappers/"+m.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateIdentityProviderMapper serves
// PUT .../identity-provider/instances/{alias}/mappers/{id}.
//
// **It writes the mapper the body's `id` names, not the path's.** A PUT
// addressed to one mapper and carrying another's id answered 204 and changed
// the other one, leaving the addressed mapper exactly as it was. That is
// `PUT .../protocol-mappers/models/{id}`'s defect, and this one is worse in one
// respect: the protocol mapper route writes two fields and discards three,
// where this writes **all four** - the name, the alias, the mapper type and the
// config. Reproduced, both halves measured.
//
// **The config is replaced, not merged.** A PUT naming one key on a mapper
// holding four left it holding one. `PUT /components/{id}` one chapter away
// merges and cannot clear a config at all, so the two neighbouring updates are
// opposite on the same verb.
//
// The path's mapper is still resolved, because that is what decides the 404.
func (h *handler) updateIdentityProviderMapper(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	body, ok := decodeIdentityProviderMapperBody(w, r)
	if !ok {
		return
	}
	existing, ok := h.identityProviderMapperByPath(w, r, rc)
	if !ok {
		return
	}
	m := identityProviderMapperOf(rc.realm.ID, body)
	if m.ID == "" {
		// A body with no id writes the mapper the path names, which is the
		// only case where the two agree.
		m.ID = existing.ID
	}
	switch err := h.store.IdentityProviderMappers().Update(r.Context(), m); {
	case errors.Is(err, store.ErrNotFound):
		writeIdentityProviderMapperNotFound(w)
		return
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Failed to add mapper '"+body.Name+"' to identity provider ["+p.ProviderID+"].")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// identityProviderMapperByPath resolves the {id} segment and writes the
// measured 404 when it names nothing. It is realm-wide on purpose - see
// readIdentityProviderMapper.
func (h *handler) identityProviderMapperByPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.IdentityProviderMapper, bool) {
	m, err := h.store.IdentityProviderMappers().ByID(r.Context(), rc.realm.ID, r.PathValue("mapperID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeIdentityProviderMapperNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return m, true
}

// decodeIdentityProviderMapperBody runs the strict decode and the empty-body
// 500 in the measured order.
//
// **An empty body and a literal `null` are a 500** where a malformed one is a
// 400, which is the same defect `POST /users` has and is reproduced for the
// same reason. It is checked before the decode because an empty body is not
// JSON and would otherwise fall into the parse family.
func decodeIdentityProviderMapperBody(w http.ResponseWriter, r *http.Request) (*identityProviderMapperBody, bool) {
	if !requireJSONBody(w, r) {
		return nil, false
	}
	// r.Body is nil rather than http.NoBody on a request built by hand, which
	// the conformance harness does. decodeStrict never met it because every
	// other strict endpoint reaches io.ReadAll through a request the server
	// built; this one is the first to read the body itself, and the golden of
	// the empty-body 500 is what found it.
	var raw []byte
	if r.Body != nil {
		var err error
		raw, err = io.ReadAll(r.Body)
		if err != nil {
			writeIdentityProviderConsultLog(w)
			return nil, false
		}
	}
	// An empty body and the literal `null` are one case, and it is the 500.
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || string(trimmed) == "null" {
		writeIdentityProviderConsultLog(w)
		return nil, false
	}
	var body identityProviderMapperBody
	if !decodeStrictBytes(w, raw, "IdentityProviderMapperRepresentation", &body) {
		return nil, false
	}
	return &body, true
}

// identityProviderMapperOf builds the stored mapper from a decoded body. The
// create and the update share it because the update replaces, so both want the
// same thing from the same fields.
func identityProviderMapperOf(realmID string, body *identityProviderMapperBody) *model.IdentityProviderMapper {
	return &model.IdentityProviderMapper{
		ID:      body.ID,
		RealmID: realmID,
		Alias:   body.IdentityProviderAlias,
		Name:    body.Name,
		Mapper:  body.IdentityProviderMapper,
		Config:  decodeOrderedMapperConfig(body.Config),
	}
}

// decodeOrderedMapperConfig reads the config object **in the order the request
// carried it**.
//
// `encoding/json` into a map would lose that order, and the order is
// observable: `{"zz":"1","aa":"2","mm":"3"}` and `{"aa":"2","mm":"3","zz":"1"}`
// were both sent to the server and both came back in the order they went in,
// because those three keys share a bucket at this table size and a collision
// chains by insertion. javamap.SizedKeyOrder takes that order as its argument,
// so losing it here would make the serialiser's answer a guess on exactly the
// key sets where it matters.
//
// A repeated key keeps the **last** value at the **first** position, which is
// what a Java map built by iterating the parsed object does.
func decodeOrderedMapperConfig(raw json.RawMessage) []model.IdentityProviderMapperConfigEntry {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var out []model.IdentityProviderMapperConfigEntry
	index := map[string]int{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return out
		}
		name, _ := keyTok.(string)
		var value string
		if err := dec.Decode(&value); err != nil {
			return out
		}
		if i, seen := index[name]; seen {
			out[i].Value = value
			continue
		}
		index[name] = len(out)
		out = append(out, model.IdentityProviderMapperConfigEntry{Name: name, Value: value})
	}
	return out
}

// writeIdentityProviderMapperNotFound is the 404 for a mapper id that resolves
// to nothing.
//
// **`Model not found` is a new spelling of not-found**, the twenty-fourth, and
// it is in the bare-`error` family. The provider family around it answers the
// generic `HTTP 404 Not Found` for an unknown alias, so one chapter now has
// both.
func writeIdentityProviderMapperNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Model not found")
}
