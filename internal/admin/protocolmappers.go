package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The Protocol Mappers tag, all twenty-one operations.
//
// They are three families of seven over two kinds of container - a client scope
// and a client - and the `client-templates` spelling of the first. Measured
// 2026-08-30 against a live 26.7.1: the alias serves what its sibling serves
// byte for byte on every one of the seven, headers included, with the single
// exception the first cut found on the parent family - `POST` answers a
// `Location` under the path it was called on. So there is one handler set here,
// registered three times.

// mapperHolder is a thing that owns protocol mappers: a client scope or a
// client. The two differ in exactly two observable ways - which 404 an unknown
// container answers, and which path a create echoes into `Location` - and both
// of those are decided before a handler runs, so every handler below is written
// once.
type mapperHolder interface {
	mappers() []model.ProtocolMapper
	setMappers([]model.ProtocolMapper)
	save(ctx context.Context) error
}

type scopeMapperHolder struct {
	h  *handler
	sc *model.ClientScope
}

func (s scopeMapperHolder) mappers() []model.ProtocolMapper { return s.sc.ProtocolMappers }

func (s scopeMapperHolder) setMappers(m []model.ProtocolMapper) { s.sc.ProtocolMappers = m }

func (s scopeMapperHolder) save(ctx context.Context) error {
	return s.h.store.ClientScopes().Update(ctx, s.sc)
}

type clientMapperHolder struct {
	h *handler
	c *model.Client
}

func (c clientMapperHolder) mappers() []model.ProtocolMapper { return c.c.ProtocolMappers }

func (c clientMapperHolder) setMappers(m []model.ProtocolMapper) { c.c.ProtocolMappers = m }

func (c clientMapperHolder) save(ctx context.Context) error {
	return c.h.store.Clients().Update(ctx, c.c)
}

// protocolMapperProvider is one row of the measured provider table.
//
// The table serves two behaviours rather than one, which is why it is a table
// and not two lists. Membership is what `ProtocolMapper provider not found`
// tests - a `protocolMapper` outside these 39 ids is a **404 on a create**,
// checked before the name and before the protocol. And the two flags are the
// config keys the create fills in for itself.
//
// **The flags follow the provider, not the mapper's `protocol`.** Measured both
// ways round: `oidc-usermodel-attribute-mapper` declared `"protocol":"saml"`
// gets the mirrors and `saml-user-property-mapper` declared
// `"protocol":"openid-connect"` does not. Reading the mapper's own protocol is
// the obvious implementation and it is wrong on both.
type protocolMapperProvider struct {
	// Introspection mirrors `access.token.claim` into
	// `introspection.token.claim` - the **value**, not a constant `"true"`:
	// `access.token.claim: "false"` produced `introspection.token.claim:
	// "false"`.
	Introspection bool
	// Userinfo mirrors `id.token.claim` into `userinfo.token.claim` the same
	// way.
	Userinfo bool
}

// protocolMapperProviders is the set `GET /admin/serverinfo` reports for
// 26.7.1: 24 `openid-connect`, 14 `saml`, 1 `docker-v2`. The two flags were
// measured one provider at a time, by creating a mapper of each with
// `access.token.claim` and `id.token.claim` set and reading back which keys
// the server had added.
//
// Twenty of the twenty-four OIDC providers do both. The four exceptions are
// the reason this is a table rather than a `strings.HasPrefix(id, "oidc-")`,
// which would have been right 20 times out of 39 and silently wrong four times
// on the family it was written for.
//
// **Two providers seed further config keys of their own and this is not
// reproduced**: `oidc-organization-membership-mapper` adds five, and
// `oidc-sha256-pairwise-sub-mapper` adds a random `pairwiseSubAlgorithmSalt` no
// golden could hold. Both are recorded as a follow-up rather than guessed at.
var protocolMapperProviders = map[string]protocolMapperProvider{
	"oidc-acr-mapper":                           {Introspection: true, Userinfo: true},
	"oidc-address-mapper":                       {Introspection: true, Userinfo: true},
	"oidc-allowed-origins-mapper":               {Introspection: true},
	"oidc-amr-mapper":                           {Introspection: true, Userinfo: true},
	"oidc-audience-mapper":                      {Introspection: true, Userinfo: true},
	"oidc-audience-resolve-mapper":              {Introspection: true},
	"oidc-claims-param-token-mapper":            {Introspection: true, Userinfo: true},
	"oidc-claims-param-value-idtoken-mapper":    {Introspection: true, Userinfo: true},
	"oidc-full-name-mapper":                     {Introspection: true, Userinfo: true},
	"oidc-group-membership-mapper":              {Introspection: true, Userinfo: true},
	"oidc-hardcoded-claim-mapper":               {Introspection: true, Userinfo: true},
	"oidc-hardcoded-role-mapper":                {Introspection: true, Userinfo: true},
	"oidc-nonce-backwards-compatible-mapper":    {},
	"oidc-organization-group-membership-mapper": {Introspection: true, Userinfo: true},
	"oidc-organization-membership-mapper":       {},
	"oidc-role-name-mapper":                     {Introspection: true, Userinfo: true},
	"oidc-session-state-mapper":                 {Introspection: true, Userinfo: true},
	"oidc-sha256-pairwise-sub-mapper":           {Introspection: true, Userinfo: true},
	"oidc-sub-mapper":                           {Introspection: true, Userinfo: true},
	"oidc-usermodel-attribute-mapper":           {Introspection: true, Userinfo: true},
	"oidc-usermodel-client-role-mapper":         {Introspection: true, Userinfo: true},
	"oidc-usermodel-property-mapper":            {Introspection: true, Userinfo: true},
	"oidc-usermodel-realm-role-mapper":          {Introspection: true, Userinfo: true},
	"oidc-usersessionmodel-note-mapper":         {Introspection: true, Userinfo: true},

	"saml-audience-mapper":                      {},
	"saml-audience-resolve-mapper":              {},
	"saml-authn-context-class-ref-mapper":       {},
	"saml-group-membership-mapper":              {},
	"saml-hardcode-attribute-mapper":            {},
	"saml-hardcode-role-mapper":                 {},
	"saml-organization-group-membership-mapper": {},
	"saml-organization-membership-mapper":       {},
	"saml-role-list-mapper":                     {},
	"saml-role-name-mapper":                     {},
	"saml-user-attribute-mapper":                {},
	"saml-user-attribute-nameid-mapper":         {},
	"saml-user-property-mapper":                 {},
	"saml-user-session-note-mapper":             {},

	"docker-v2-allow-all-mapper": {},
}

// The four config keys the mirroring rule reads and writes.
const (
	accessTokenClaim        = "access.token.claim"
	introspectionTokenClaim = "introspection.token.claim"
	idTokenClaim            = "id.token.claim"
	userinfoTokenClaim      = "userinfo.token.claim"
)

// protocolMapperRequest is the decode target for the three writes.
//
// ConsentRequired is read and thrown away on purpose: a create sending `true`
// reads back `false`, on every provider tried. The field is here so the key is
// consumed rather than looked at, and so a reader of this struct sees that the
// omission is deliberate.
type protocolMapperRequest struct {
	ID              string          `json:"id"`
	Name            *string         `json:"name"`
	Protocol        *string         `json:"protocol"`
	ProtocolMapper  string          `json:"protocolMapper"`
	ConsentRequired bool            `json:"consentRequired"`
	Config          model.StringMap `json:"config"`
}

// listProtocolMappers serves GET .../protocol-mappers/models.
func (h *handler) listProtocolMappers(w http.ResponseWriter, _ *http.Request, _ *reqContext, holder mapperHolder) {
	writeAdminJSON(w, protocolMapperListOf(holder.mappers()))
}

// listProtocolMappersByProtocol serves GET .../protocol-mappers/protocol/{protocol}.
//
// The filter is on the **mapper's own** `protocol` field, which is not
// validated anywhere: a mapper created with `"protocol":"bogus"` is a 201 and
// is returned by `.../protocol/bogus`. An unknown protocol is 200 and `[]`
// rather than a 400, and so is `saml` on a scope holding only OIDC mappers.
func (h *handler) listProtocolMappersByProtocol(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	want := r.PathValue("protocol")
	out := []model.ProtocolMapper{}
	for _, m := range holder.mappers() {
		if m.Protocol == want {
			out = append(out, m)
		}
	}
	writeAdminJSON(w, protocolMapperListOf(out))
}

// readProtocolMapper serves GET .../protocol-mappers/models/{id}.
func (h *handler) readProtocolMapper(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	m := findProtocolMapper(holder.mappers(), r.PathValue("mapperID"))
	if m == nil {
		writeModelNotFound(w)
		return
	}
	writeAdminJSON(w, protocolMapperRepresentationOf(*m))
}

// createProtocolMapper serves POST .../protocol-mappers/models.
//
// The order of the checks is measured, one body at a time, and it is not the
// order that reads naturally:
//
//	{}                                     404 ProtocolMapper provider not found
//	{"name":"x","protocol":"openid-connect"}   the same 404 - no provider
//	{"protocol":"...","protocolMapper":"..."}  409 Duplicate resource error
//	{"name":"x","protocolMapper":"..."}        409 Duplicate resource error
//	{"name":"taken",...}                   409 {"errorMessage":"Protocol mapper exists with same name"}
//	{"name":"","protocol":...,"protocolMapper":...}  **201** - an empty name is legal
//
// So the **provider is checked first**, before the name and before anything
// else; an absent `name` or an absent `protocol` is a 409 rather than a 400 or
// a 500, because both columns are NOT NULL and Keycloak surfaces the
// constraint violation through the exception mapper that spells every conflict
// `Duplicate resource error`; and an *empty* name is accepted where a client
// scope's empty name is a 400. Three things a reader would get wrong.
func (h *handler) createProtocolMapper(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	rep, ok := decodeProtocolMapper(w, r)
	if !ok {
		return
	}
	if _, known := protocolMapperProviders[rep.ProtocolMapper]; !known {
		writeProviderNotFound(w)
		return
	}
	if rep.Name == nil || rep.Protocol == nil {
		writeDuplicateResource(w)
		return
	}
	// The name check and the id check share this message, which is why the
	// order between them is not observable and why both are here. See the id
	// uniqueness note above findProtocolMapper: an id this container already
	// holds is the local conflict, and one anywhere else on the server is the
	// generic duplicate.
	if findProtocolMapperByName(holder.mappers(), *rep.Name) != nil ||
		(rep.ID != "" && findProtocolMapper(holder.mappers(), rep.ID) != nil) {
		httpx.WriteAdminError(w, http.StatusConflict, "Protocol mapper exists with same name")
		return
	}
	taken, err := h.protocolMapperIDTaken(r.Context(), rep.ID, "")
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if taken {
		writeDuplicateResource(w)
		return
	}

	holder.setMappers(append(holder.mappers(), protocolMapperFrom(rep)))
	if err := holder.save(r.Context()); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	// The alias echoes its own path here exactly as it does on
	// POST /client-templates: a create through
	// /client-templates/{id}/protocol-mappers/models answers a Location under
	// /client-templates. Building it from r.URL.Path is what keeps that true
	// for all three families with one line.
	w.Header().Set("Location", h.issuerBase+r.URL.Path+"/"+lastMapper(holder).ID)
	w.WriteHeader(http.StatusCreated)
}

// addProtocolMappers serves POST .../protocol-mappers/add-models, which takes
// an array and answers **204**, not 201, and carries no Location.
//
// **The batch validates before it applies.** An array whose second entry
// duplicates a name already held left the first entry unwritten - measured by
// reading the listing afterwards, which is the only way to see it. Its 409 is a
// third spelling again, `{"error":"conflict","error_description":"Protocol
// mapper name must be unique per protocol"}`, neither of the two the single
// create uses.
//
// A name colliding **within the array** is the same 409, which is why the
// uniqueness check runs against the growing set rather than against the stored
// one.
func (h *handler) addProtocolMappers(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	reps, ok := decodeProtocolMappers(w, r)
	if !ok {
		return
	}
	next := holder.mappers()
	for _, rep := range reps {
		if _, known := protocolMapperProviders[rep.ProtocolMapper]; !known {
			writeProviderNotFound(w)
			return
		}
		if rep.Name == nil || rep.Protocol == nil {
			writeDuplicateResource(w)
			return
		}
		if findProtocolMapperByName(next, *rep.Name) != nil {
			httpx.WriteOAuthError(w, http.StatusConflict, "conflict",
				"Protocol mapper name must be unique per protocol")
			return
		}
		// **This route has one answer where the single create has two.** An id
		// already in the growing set - the container's own mappers plus the
		// entries before this one - and an id held anywhere else on the server
		// are both the generic duplicate here, where the single create answers
		// the first of those with its name conflict. Measured on both cells.
		taken, err := h.protocolMapperIDTaken(r.Context(), rep.ID, "")
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if taken || (rep.ID != "" && findProtocolMapper(next, rep.ID) != nil) {
			writeDuplicateResource(w)
			return
		}
		next = append(next, protocolMapperFrom(rep))
	}
	holder.setMappers(next)
	if err := holder.save(r.Context()); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// updateProtocolMapper serves PUT .../protocol-mappers/models/{id}, and it is
// the strangest operation in this cut.
//
// **The path names which mapper must exist and the body names which mapper is
// written.** Measured: a PUT addressed to mapper A carrying B's `id` answered
// 204 and changed **B**, leaving A alone. A body with no `id` at all, or one
// naming a mapper that does not exist, is a **500**. So the path id is a
// precondition and the body id is the target.
//
// **And it writes two fields.** `protocolMapper` and `config`, replacing the
// config outright rather than merging it. `name`, `protocol` and
// `consentRequired` are read off the wire and discarded: a PUT renaming a
// mapper answers 204 and does not rename it, and a PUT moving one to `saml`
// leaves its protocol alone. Writing the whole representation back is the
// obvious implementation and it is wrong on three fields.
//
// Both are Keycloak's own defects, reproduced. `ClientScopeAdapter`'s update
// sets the provider and replaces the config map and touches nothing else, and
// it looks the entity up by the model's id, which is the body's.
func (h *handler) updateProtocolMapper(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	if findProtocolMapper(holder.mappers(), r.PathValue("mapperID")) == nil {
		writeModelNotFound(w)
		return
	}
	rep, ok := decodeProtocolMapper(w, r)
	if !ok {
		return
	}
	if _, known := protocolMapperProviders[rep.ProtocolMapper]; !known {
		writeProviderNotFound(w)
		return
	}
	target := findProtocolMapper(holder.mappers(), rep.ID)
	if target == nil {
		writeProtocolMapperUnknownError(w)
		return
	}

	target.ProtocolMapper = rep.ProtocolMapper
	target.Config = mapperConfig(rep)
	if err := holder.save(r.Context()); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// deleteProtocolMapper serves DELETE .../protocol-mappers/models/{id}.
//
// 204 with Cache-Control: no-cache and **no X-Frame-Options** - the delete
// sends no Content-Type, and that is what decides the header. The second delete
// of the same id is 404, not another 204.
func (h *handler) deleteProtocolMapper(w http.ResponseWriter, r *http.Request, _ *reqContext, holder mapperHolder) {
	id := r.PathValue("mapperID")
	in := holder.mappers()
	out := make([]model.ProtocolMapper, 0, len(in))
	for _, m := range in {
		if m.ID != id {
			out = append(out, m)
		}
	}
	if len(out) == len(in) {
		writeModelNotFound(w)
		return
	}
	holder.setMappers(out)
	if err := holder.save(r.Context()); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// protocolMapperFrom turns a validated request into a stored mapper.
//
// The body's `id` wins when it carries one, the way it does on
// POST /client-scopes and POST /clients: a create naming an id produced a
// mapper with exactly that id and put it in Location. It is what lets a
// conformance fixture create a mapper at a known id in one request.
func protocolMapperFrom(rep protocolMapperRequest) model.ProtocolMapper {
	m := model.ProtocolMapper{
		ID:             rep.ID,
		Name:           *rep.Name,
		Protocol:       *rep.Protocol,
		ProtocolMapper: rep.ProtocolMapper,
		Config:         mapperConfig(rep),
	}
	if m.ID == "" {
		m.ID = model.NewID()
	}
	return m
}

// mapperConfig applies the two measured transformations a config goes through
// on its way in, in the order they were measured.
//
// First, **entries whose value is `""` or `null` are dropped**, before anything
// else looks at them: `{"access.token.claim":""}` produced `{}` and no mirrored
// key, so the removal happens first and the mirroring reads what survives.
//
// Then the provider's two flags mirror `access.token.claim` into
// `introspection.token.claim` and `id.token.claim` into
// `userinfo.token.claim`, **appending** rather than inserting, and only when
// the key is not already present - a body sending
// `{"access.token.claim":"true","introspection.token.claim":"false"}` kept the
// false.
func mapperConfig(rep protocolMapperRequest) model.StringMap {
	out := model.StringMap{}
	for _, p := range rep.Config {
		if p.Value != "" {
			out = append(out, p)
		}
	}
	provider := protocolMapperProviders[rep.ProtocolMapper]
	mirror := func(from, to string, enabled bool) {
		if !enabled {
			return
		}
		v, ok := out.Get(from)
		if !ok {
			return
		}
		if _, exists := out.Get(to); exists {
			return
		}
		out = append(out, model.StringPair{Key: to, Value: v})
	}
	mirror(accessTokenClaim, introspectionTokenClaim, provider.Introspection)
	mirror(idTokenClaim, userinfoTokenClaim, provider.Userinfo)
	return out
}

// protocolMappersFromRepresentation converts the `protocolMappers` array that
// `POST /clients`, `POST /client-scopes` and `PUT /clients/{uuid}` carry.
//
// It puts the same two config transformations and the same id rule through as
// the dedicated create route - measured: a scope created with a mapper whose
// config held `access.token.claim`, `id.token.claim` and an empty value read
// back with the empty one gone, both mirrors added and `consentRequired` false,
// which is byte for byte what `POST .../protocol-mappers/models` produces.
//
// **What it does not do is check the provider.** `protocolMapper: "nope"` is a
// 201 here and a 404 on the dedicated route - the same field, validated on one
// route and stored blindly on its neighbour. Measured on all three of these and
// on both dedicated creates.
func protocolMappersFromRepresentation(in []protocolMapperRepresentation) []model.ProtocolMapper {
	out := make([]model.ProtocolMapper, 0, len(in))
	for _, rep := range in {
		name, protocol := rep.Name, rep.Protocol
		out = append(out, protocolMapperFrom(protocolMapperRequest{
			ID:             rep.ID,
			Name:           &name,
			Protocol:       &protocol,
			ProtocolMapper: rep.ProtocolMapper,
			Config:         rep.Config,
		}))
	}
	return out
}

// A protocol mapper id is unique across the **server**, not the realm and not
// the container. F78, measured 2026-08-30: a client scope created in a
// different realm carrying a mapper id already in use in master is a 409.
//
// Five routes enforce it - POST /clients, POST /client-scopes,
// PUT /clients/{uuid}, POST .../protocol-mappers/models and
// POST .../protocol-mappers/add-models - and they do not answer alike. The
// follow-up said the answer is decided by *where* the colliding mapper is and
// not by which route asked; measured on a 2x2 that is half right. The location
// decides on `models` and decides nothing on `add-models`, whose two cells are
// the same body:
//
//	                        id in this container      id anywhere else
//	POST models             Protocol mapper exists    Duplicate resource error
//	                        with same name (409)      (409)
//	POST add-models         Duplicate resource        Duplicate resource error
//	                        error (409)               (409)
//	POST /clients           Client <id> already       Duplicate resource error
//	                        exists (409)              (409)
//	POST /client-scopes     Client Scope <name>       Duplicate resource error
//	                        already exists (409)      (409)
//	PUT /clients/{uuid}     Cannot add protocol       Duplicate resource error
//	                        mapper '<name>'.          (409)
//	                        Duplicate resource
//	                        error (400 invalid_input)
//
// The rule the six local cells share is that a collision the route can see in
// the object it is building gets that route's **own** conflict, and one only
// the rest of the server knows about gets the generic one - which is Keycloak
// catching a duplicate in the persistence context and letting a database
// constraint through at flush. Reading it as "the location decides" alone puts
// the wrong body on `add-models`.
//
// On the two mapper routes the id check runs **after** the provider check and
// after the name check: an id held elsewhere plus a name held here answers
// about the name, and an id held here plus an unknown provider answers about
// the provider.

// duplicateProtocolMapperID returns the first id two mappers in one list share,
// and "" when they are all distinct. A container holds at most fourteen
// mappers, so the quadratic walk is cheaper than the map it would replace.
func duplicateProtocolMapperID(in []model.ProtocolMapper) string {
	for i := range in {
		if in[i].ID == "" {
			continue
		}
		for j := i + 1; j < len(in); j++ {
			if in[j].ID == in[i].ID {
				return in[i].ID
			}
		}
	}
	return ""
}

// protocolMapperIDTaken reports whether any container other than holderID holds
// this protocol mapper id, over both kinds of container and every realm.
//
// holderID is the container the caller is writing, and excluding it is what
// lets a create check itself after it has been written: the row is already
// there by then, so without the exclusion every create would collide with
// itself. Pass "" when nothing should be excluded.
func (h *handler) protocolMapperIDTaken(ctx context.Context, mapperID, holderID string) (bool, error) {
	if mapperID == "" {
		return false, nil
	}
	for _, owner := range []func(context.Context, string) (string, error){
		h.store.Clients().ProtocolMapperOwner,
		h.store.ClientScopes().ProtocolMapperOwner,
	} {
		id, err := owner(ctx, mapperID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return false, err
		}
		if id != holderID {
			return true, nil
		}
	}
	return false, nil
}

// protocolMapperConflict is the whole check for the two creates that carry a
// `protocolMappers` array, returning the response to write or nil.
//
// local is the message that route uses for a duplicate it can see in its own
// request - `Client <id> already exists` and `Client Scope <name> already
// exists`, which are the same messages those routes answer a clientId or a name
// conflict with. Measured both ways: two mappers in one body sharing an id
// answer it, and an id another container holds answers the generic duplicate.
//
// holderID is the container that was just written, excluded from the search for
// the reason protocolMapperIDTaken gives.
func (h *handler) protocolMapperConflict(ctx context.Context, in []model.ProtocolMapper,
	holderID, local string) func(http.ResponseWriter) {
	if duplicateProtocolMapperID(in) != "" {
		return func(w http.ResponseWriter) {
			httpx.WriteAdminError(w, http.StatusConflict, local)
		}
	}
	for _, m := range in {
		taken, err := h.protocolMapperIDTaken(ctx, m.ID, holderID)
		if err != nil {
			return func(w http.ResponseWriter) {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}
		if taken {
			return writeDuplicateResource
		}
	}
	return nil
}

func findProtocolMapper(in []model.ProtocolMapper, id string) *model.ProtocolMapper {
	for i := range in {
		if in[i].ID == id {
			return &in[i]
		}
	}
	return nil
}

func findProtocolMapperByName(in []model.ProtocolMapper, name string) *model.ProtocolMapper {
	for i := range in {
		if in[i].Name == name {
			return &in[i]
		}
	}
	return nil
}

// findProtocolMapperByProtocolAndName is findProtocolMapperByName with the key
// PUT /clients/{uuid} actually matches on. The protocol half is measured: a PUT
// naming an existing mapper's name under a **different** protocol does not
// match it - the old mapper is removed and a new one added with a new id.
func findProtocolMapperByProtocolAndName(in []model.ProtocolMapper, protocol, name string) *model.ProtocolMapper {
	for i := range in {
		if in[i].Protocol == protocol && in[i].Name == name {
			return &in[i]
		}
	}
	return nil
}

// mergeClientProtocolMappers applies a PUT /clients/{uuid} body's
// protocolMappers array onto the client's current ones, or returns the refusal
// the request gets instead.
//
// **It matches by (protocol, name), not by id**, which is measured and is not
// what a reader would guess from a body that carries ids:
//
//	same name, different id       204, and the mapper **keeps its own id**
//	same name, no id              204, same
//	same name, other protocol     204, old mapper gone, new id
//	name the client does not hold added
//	a mapper the body omits       removed
//
// A match is updated in place and only `protocolMapper` and `config` are
// written onto it, which is the same pair `PUT .../protocol-mappers/models`
// writes and discards the rest of.
//
// The id only matters on the **add** path, and that is where the fifth of
// F78's routes enforces uniqueness: an id this client already holds, or one an
// earlier entry in the same body took, is a 400 `invalid_input` naming the
// mapper, and an id another container holds anywhere on the server is the
// generic 409. Sending a client's own representation straight back is
// therefore a 204 rather than a conflict, which is the read-modify-write a
// naive "an id in use is refused" check would break.
func (h *handler) mergeClientProtocolMappers(ctx context.Context, current, want []model.ProtocolMapper,
	holderID string) ([]model.ProtocolMapper, func(http.ResponseWriter)) {
	out := make([]model.ProtocolMapper, 0, len(want))
	for _, m := range want {
		if existing := findProtocolMapperByProtocolAndName(current, m.Protocol, m.Name); existing != nil {
			kept := *existing
			kept.ProtocolMapper = m.ProtocolMapper
			kept.Config = m.Config
			out = append(out, kept)
			continue
		}
		if findProtocolMapper(current, m.ID) != nil || findProtocolMapper(out, m.ID) != nil {
			name := m.Name
			return nil, func(w http.ResponseWriter) {
				httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_input",
					"Cannot add protocol mapper '"+name+"'. Duplicate resource error")
			}
		}
		taken, err := h.protocolMapperIDTaken(ctx, m.ID, holderID)
		if err != nil {
			return nil, func(w http.ResponseWriter) {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}
		if taken {
			return nil, writeDuplicateResource
		}
		out = append(out, m)
	}
	return out, nil
}

func lastMapper(holder mapperHolder) model.ProtocolMapper {
	in := holder.mappers()
	return in[len(in)-1]
}

// protocolMapperListOf converts a container's mappers for the wire.
//
// There is no second function for the client representation, which **omits**
// the key when there are no mappers where the dedicated routes answer a bare
// `[]`. There was one, and a mutation showed it did nothing: `omitempty` on a
// slice already drops an empty one, so the two shapes fall out of the struct
// tag and the same helper serves both.
func protocolMapperListOf(in []model.ProtocolMapper) []protocolMapperRepresentation {
	out := make([]protocolMapperRepresentation, 0, len(in))
	for _, m := range in {
		out = append(out, protocolMapperRepresentationOf(m))
	}
	return out
}

func protocolMapperRepresentationOf(m model.ProtocolMapper) protocolMapperRepresentation {
	return protocolMapperRepresentation{
		ID:              m.ID,
		Name:            m.Name,
		Protocol:        m.Protocol,
		ProtocolMapper:  m.ProtocolMapper,
		ConsentRequired: m.ConsentRequired,
		Config:          m.Config,
	}
}

// writeModelNotFound is the 404 every route naming a {id} under
// protocol-mappers answers for a mapper that is not there - and for a path
// segment that is not a UUID at all, which is not a 400.
//
// `Model not found` is a **fifteenth** spelling of not-found on the admin API,
// and it is the least specific of the fifteen: it names neither the resource
// nor the key it was looked up by.
func writeModelNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Model not found")
}

// writeProviderNotFound is the 404 a create or an update answers for a
// `protocolMapper` outside the 39 registered provider ids - including an absent
// one, which is why `{}` answers about the provider rather than about the name.
//
// A 404 on a create is the part that looks like a bug. It is Keycloak looking
// the provider up in the session's factory registry and answering about the
// lookup rather than about the request.
func writeProviderNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "ProtocolMapper provider not found")
}

// writeDuplicateResource is the 409 an absent `name` or an absent `protocol`
// answers, and it is the one response on this family that carries **none of the
// five security headers**.
//
// Measured on three bodies, side by side with the other 409 on the same route,
// which carries all five. Both are conflicts, both are 409, and only one
// reaches the filter chain. The router sets the five before the mux runs, so
// this deletes them - httpx.WriteAuthorizationRedirect does the same for the
// same reason.
//
// The message is about a duplicate and the request contains no duplicate. That
// is Keycloak surfacing a NOT NULL violation through the exception mapper it
// installs for every constraint violation, and the mapper does not distinguish
// them.
func writeDuplicateResource(w http.ResponseWriter) {
	h := w.Header()
	for _, name := range []string{
		"Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
		"X-Frame-Options", "X-Robots-Tag",
	} {
		h.Del(name)
	}
	httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
}

// writeProtocolMapperUnknownError is the 500 a PUT whose body names no mapper
// answers - Keycloak dereferencing the entity it did not find.
func writeProtocolMapperUnknownError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// decodeProtocolMapper decodes the object the two single writes take.
//
// The parse failures are three different codes and **the body's first token
// decides which**, not the endpoint. See decodeMapperBody.
func decodeProtocolMapper(w http.ResponseWriter, r *http.Request) (protocolMapperRequest, bool) {
	var rep protocolMapperRequest
	ok := decodeMapperBody(w, r, '{', func(dec *json.Decoder) error {
		return dec.Decode(&rep)
	})
	return rep, ok
}

// decodeProtocolMappers decodes the array add-models takes.
func decodeProtocolMappers(w http.ResponseWriter, r *http.Request) ([]protocolMapperRequest, bool) {
	var reps []protocolMapperRequest
	ok := decodeMapperBody(w, r, '[', func(dec *json.Decoder) error {
		return dec.Decode(&reps)
	})
	return reps, ok
}

// decodeMapperBody is the measured parse-failure rule, which is a **shape**
// rule and not the per-endpoint rule this project had written down.
//
// Swept 2026-08-30 across both of this family's decoders and `POST /users` and
// two role-array endpoints as controls:
//
//	first token is the one the endpoint wants, document truncated  invalid_request
//	first token is some other shape                                unknown_error
//	an empty body, or a literal `null`                             500 unknown_error
//
// `POST /users` answers `invalid_request` for `{` and **`unknown_error` for
// `[`**; `POST .../role-mappings/realm` answers `unknown_error` for `{` and
// **`invalid_request` for `[`**. Every previous probe of the role-array
// endpoints had sent `{`, which is the wrong shape for an array, so the rule
// looked like it belonged to the endpoint. It belongs to the body.
//
// One case is left divergent on purpose: an array whose *element* is truncated
// - `[{` - answers `{"error":"HTTP 400 Bad Request",...}`, a fourth code, and
// nothing in this cut serves it. It is written up rather than implemented,
// because telling it apart means reporting on where inside the document the
// decoder stopped and no endpoint here has a case that needs it.
func decodeMapperBody(w http.ResponseWriter, r *http.Request, want byte,
	decode func(*json.Decoder) error) bool {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if trimmed == "" || strings.HasPrefix(trimmed, "null") {
		writeProtocolMapperUnknownError(w)
		return false
	}
	if trimmed[0] != want {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unknown_error", "Cannot parse the JSON")
		return false
	}
	if err := decode(json.NewDecoder(strings.NewReader(trimmed))); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return false
	}
	return true
}

// guardScopeMappers is the read guard for the fourteen routes under a client
// scope, and the write guard is the same thing with a manage-clients check
// inside the handler's own wrapper below.
//
// The order is measured by giving one caller one role and varying which id is
// bad:
//
//	no clients role   403 even for a scope that does not exist
//	query-clients     **404** for a scope that does not exist, 403 for one that does
//	view-clients      404 for a bad scope, 404 for a bad mapper, 403 for a write
//	manage-clients    404 for everything
//
// So: coarse gate, then the container, then the fine role check, and - on a
// read - the mapper after it; on a write the manage-clients check sits between
// the container and the provider.
//
// **The query-clients row is why the gate is three roles and the fine check is
// two.** It was written as a two-role gate first, from a sweep that had only
// asked what query-clients gets on a scope that **exists** - 403, the same
// answer either arrangement gives. The scope that does not exist is what tells
// them apart, and it says query-clients is admitted and then refused, not
// refused at the door. `GET /client-scopes` one level up admits it too and
// answers `200 []` rather than 403, so the gate is shared with the parent
// family and only the fine check differs.
func (h *handler) guardScopeMappers(write bool,
	next func(http.ResponseWriter, *http.Request, *reqContext, mapperHolder)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			sc, err := h.store.ClientScopes().ByID(r.Context(), rc.realm.ID,
				r.PathValue("clientScopeID"))
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeClientScopeNotFound(w)
					return
				}
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			if !mayUseClientMappers(rc.caller, write) {
				writeForbidden(w)
				return
			}
			next(w, r, rc, scopeMapperHolder{h: h, sc: sc})
		})
}

// guardClientMappers is guardScopeMappers over a client. Same gate, same order,
// and the only difference a caller can see is the 404: an unknown client is
// `Could not find client` where an unknown scope is `Could not find client
// scope`.
func (h *handler) guardClientMappers(write bool,
	next func(http.ResponseWriter, *http.Request, *reqContext, mapperHolder)) http.HandlerFunc {
	return h.guardAnyRejecting(clientsReadRoles, writeForbidden,
		func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
			client, ok := h.clientFromPath(w, r, rc)
			if !ok {
				return
			}
			if !mayUseClientMappers(rc.caller, write) {
				writeForbidden(w)
				return
			}
			next(w, r, rc, clientMapperHolder{h: h, c: client})
		})
}

// mayUseClientMappers is the **fine** check, after the container is resolved.
//
// A read takes view-clients or manage-clients and a write takes manage-clients
// alone, swept one role at a time over eight candidates on ten routes.
// `query-clients` opens neither, although the coarse gate above admits it -
// which is what makes a scope that does not exist a 404 to a query-clients
// caller and a scope that does a 403.
//
// It is not maySeeClientScopes, although it reads identically for a read: that
// one empties a body and this one refuses a request. `GET /client-scopes`
// answers query-clients `200 []`; nothing on this family answers it 200 at all.
func mayUseClientMappers(c *caller, write bool) bool {
	if write {
		return c.has("manage-clients")
	}
	return c.has("view-clients") || c.has("manage-clients")
}
