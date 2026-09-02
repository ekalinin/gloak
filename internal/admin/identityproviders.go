package admin

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// identityProviderRepresentation is Keycloak's IdentityProviderRepresentation,
// in the field order measured 2026-09-01 from a create carrying every field
// the type accepts:
//
//	alias displayName internalId providerId enabled trustEmail storeToken
//	addReadTokenRoleOnCreate authenticateByDefault linkOnly hideOnLogin
//	firstBrokerLoginFlowAlias config types
//
// Three fields the create **accepts and never echoes** are deliberately absent
// from this struct's output and present in the body type next door:
// `updateProfileFirstLoginMode` and `postBrokerLoginFlowAlias` were sent and
// never came back, and `organizationId` is a 400 for any value including the
// empty string. Declaring them here would invent three keys the server does not
// send.
//
// The omitempty on each field is measured rather than tidiness, and the rules
// are not uniform:
//
//   - **Alias is omitted when absent**, and that state is reachable: a PUT with
//     no alias in the body clears it and the listing then serves the row
//     without the key. See updateIdentityProvider.
//   - **The six flags are pointers**, because absent and `false` are two
//     answers. A create never mentioning `trustEmail` reads back with no such
//     key; one sending `"trustEmail":false` reads back carrying `false`.
//   - **DisplayName is not a pointer**: `""` was sent and came back as `""`, so
//     empty and absent are one state there and two on the six flags. Two rules
//     on one body, measured side by side.
//   - **Enabled is never omitted** and defaults to true.
//   - **Config is always present**, `{}` when empty, like an organization's
//     attributes and unlike its domains.
//   - **Types is always present** and is derived from the provider id.
type identityProviderRepresentation struct {
	Alias                     string                 `json:"alias,omitempty"`
	DisplayName               string                 `json:"displayName,omitempty"`
	InternalID                string                 `json:"internalId"`
	ProviderID                string                 `json:"providerId"`
	Enabled                   bool                   `json:"enabled"`
	TrustEmail                *bool                  `json:"trustEmail,omitempty"`
	StoreToken                *bool                  `json:"storeToken,omitempty"`
	AddReadTokenRoleOnCreate  *bool                  `json:"addReadTokenRoleOnCreate,omitempty"`
	AuthenticateByDefault     *bool                  `json:"authenticateByDefault,omitempty"`
	LinkOnly                  *bool                  `json:"linkOnly,omitempty"`
	HideOnLogin               *bool                  `json:"hideOnLogin,omitempty"`
	FirstBrokerLoginFlowAlias string                 `json:"firstBrokerLoginFlowAlias,omitempty"`
	Config                    identityProviderConfig `json:"config"`
	// Types is a pointer so that briefRepresentation=true can drop the key
	// outright, which is one of the four things that parameter does - see
	// identityProviderRepresentationOf. The single read **ignores** it and
	// always sends the full shape.
	Types *[]string `json:"types,omitempty"`
}

// identityProviderConfig is the `config` object.
//
// It is a slice with its own marshaller rather than a map for the reason
// organizationAttributes is: Keycloak serialises a Java map and Go sorts a
// map's keys.
//
// **This one is javamap.SizedKeyOrder and the component config next door is
// javamap.KeyOrder.** Nine key sets were measured on this endpoint and
// SizedKeyOrder places all nine while KeyOrder gets four wrong - including
// `{clientId, clientSecret}`, which comes back `clientSecret, clientId`. Seven
// were measured on `/components` and the answer is the other way round. So the
// two families use Keycloak's two HashMap constructors, one each, and a shared
// serialiser is wrong on one of them - which one depending on the key count.
type identityProviderConfig []model.IdentityProviderConfigEntry

func (c identityProviderConfig) MarshalJSON() ([]byte, error) {
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

// identityProviderSecretMask is what every read serves in place of a stored
// `clientSecret`: ten asterisks, measured byte for byte on the listing and on
// the single read. The value is never returned, so a caller cannot round-trip
// a provider through a GET and a PUT without losing it - which is Keycloak's
// behaviour and not something to smooth over.
const identityProviderSecretMask = "**********"

// identityProviderRepresentationOf converts a stored provider for the wire.
//
// **The brief shape is six keys and it is not the full shape minus one.**
// Measured 2026-09-01 on a provider carrying a displayName, `trustEmail` and
// four config entries:
//
//	default                    alias displayName internalId providerId enabled
//	                           trustEmail config(4 entries) types
//	briefRepresentation=true   alias displayName internalId providerId enabled
//	                           config({})
//
// So it drops the six tri-state flags, `firstBrokerLoginFlowAlias`, `types`
// **and the config's contents** - the key stays and is emptied, which is a
// third thing again. The first reading of this parameter was "it drops types",
// taken on providers that happened to carry no config and no flags; the probe
// that refutes it is a provider that carries both, and it was **a recorded
// golden that sent it** rather than a hand probe.
//
// `briefRepresentation=false` is byte-identical to the default.
func identityProviderRepresentationOf(p *model.IdentityProvider, brief bool) identityProviderRepresentation {
	rep := identityProviderRepresentation{
		DisplayName: p.DisplayName,
		InternalID:  p.InternalID,
		ProviderID:  p.ProviderID,
		Enabled:     p.Enabled,
		Config:      identityProviderConfig{},
	}
	if p.Alias != nil {
		rep.Alias = *p.Alias
	}
	if brief {
		return rep
	}
	rep.TrustEmail = p.TrustEmail
	rep.StoreToken = p.StoreToken
	rep.AddReadTokenRoleOnCreate = p.AddReadTokenRoleOnCreate
	rep.AuthenticateByDefault = p.AuthenticateByDefault
	rep.LinkOnly = p.LinkOnly
	rep.HideOnLogin = p.HideOnLogin
	rep.FirstBrokerLoginFlowAlias = p.FirstBrokerLoginFlowAlias
	rep.Config = orderIdentityProviderConfig(p.Config)
	types := model.IdentityProviderTypes(p.ProviderID)
	rep.Types = &types
	return rep
}

// orderIdentityProviderConfig puts the stored pairs into Keycloak's HashMap
// bucket order and masks the client secret.
//
// The store keeps the entries in the order they arrived, which is what lets a
// bucket collision chain the way it did on the way in; javamap.SizedKeyOrder
// decides the rest, taking the entry count as its first argument because this
// map is built from another one and never grown by the create.
func orderIdentityProviderConfig(in []model.IdentityProviderConfigEntry) identityProviderConfig {
	byName := make(map[string]model.IdentityProviderConfigEntry, len(in))
	names := make([]string, 0, len(in))
	for _, e := range in {
		byName[e.Name] = e
		names = append(names, e.Name)
	}
	out := make(identityProviderConfig, 0, len(in))
	for _, name := range javamap.SizedKeyOrder(len(names), names) {
		e := byName[name]
		if e.Name == "clientSecret" {
			e.Value = identityProviderSecretMask
		}
		out = append(out, e)
	}
	return out
}

// listIdentityProviders serves
// GET /admin/realms/{realm}/identity-provider/instances.
//
// **The order is by alias**, measured: three providers created `zzz, mmm, aaa`
// came back `aaa, mmm, zzz`, and the store sorts them.
//
// `search`, `first` and `max` all run here rather than in the store, so the
// comparison is written once instead of once per driver.
func (h *handler) listIdentityProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	first, ok := identityProviderBound(w, q, "first")
	if !ok {
		return
	}
	max, ok := identityProviderBound(w, q, "max")
	if !ok {
		return
	}
	providers, err := h.store.IdentityProviders().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	providers = filterIdentityProviders(providers, q.Get("search"))
	providers = pageIdentityProviders(providers, first, max)

	// **briefRepresentation defaults to false here**, and what it does when it
	// is true is a six-key shape rather than one dropped field - see
	// identityProviderRepresentationOf. It is true on the role listing and on
	// the organization listing and false on the user listing; this is the
	// fourth listing measured for it and the second to default false. One
	// shared helper would get one of them wrong.
	brief := q.Get("briefRepresentation") == "true"
	out := make([]identityProviderRepresentation, 0, len(providers))
	for _, p := range providers {
		out = append(out, identityProviderRepresentationOf(p, brief))
	}
	writeAdminJSON(w, out)
}

// identityProviderBound parses one of first and max.
//
// **A malformed bound is the measured 404** `{"error":"HTTP 404 Not Found"}`,
// the same answer the scope family gives and the same body AGENTS.md attributes
// to a router that found nothing to run. `/components` next door **ignores both
// bounds outright** - `?first=1&max=2` was measured returning all fourteen rows
// and `?first=abc` a 200 with the whole list - so two neighbouring families
// answer one malformed input two ways, measured in one cut on one container.
// See F134.
//
// It is written here rather than shared with authzIntBound because that
// function writes its refusal through writeAuthzNotEnabled, whose name is a
// claim about a client flag that has nothing to do with this route. The two
// produce the same bytes for different reasons, and folding them together
// would attach one reason to both.
//
// The return is -1 for "no bound", covering an absent parameter and a negative
// one alike: `?first=-1&max=-1` returned everything.
func identityProviderBound(w http.ResponseWriter, q url.Values, name string) (int, bool) {
	raw := q.Get(name)
	if raw == "" {
		return -1, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		writeIdentityProviderNotFound(w)
		return 0, false
	}
	if v < 0 {
		return -1, true
	}
	return v, true
}

// filterIdentityProviders applies `search`, which is matchesSearch's rule.
//
// **The two were measured identical rather than assumed so**, on the probe that
// separates that rule from every neighbouring one: with a value `xabbcx`,
// `search=*bbc` matches on this listing and on the user listing, and matches
// **nothing** on the role listing. Sharing the helper is a claim, and this is
// the request that earns it. See matchesSearch, which the same measurement
// corrected.
//
// An empty `search=` returns everything, so it neither opens the filter nor
// closes it.
func filterIdentityProviders(in []*model.IdentityProvider, search string) []*model.IdentityProvider {
	if search == "" {
		return in
	}
	var kept []*model.IdentityProvider
	for _, p := range in {
		alias := ""
		if p.Alias != nil {
			alias = *p.Alias
		}
		if matchesSearch(alias, search) {
			kept = append(kept, p)
		}
	}
	return kept
}

// pageIdentityProviders applies first and max, either of which alone is enough
// to page. A negative bound means "no bound".
func pageIdentityProviders(in []*model.IdentityProvider, first, max int) []*model.IdentityProvider {
	if first > 0 {
		if first >= len(in) {
			return nil
		}
		in = in[first:]
	}
	if max >= 0 && max < len(in) {
		in = in[:max]
	}
	return in
}

// readIdentityProvider serves
// GET /admin/realms/{realm}/identity-provider/instances/{alias}.
//
// It writes the full shape unconditionally: `?briefRepresentation=true` was
// measured answering a body carrying `types`, identical to the one with no
// parameter. That is the organization read's behaviour on the same parameter,
// measured here rather than inherited from it.
func (h *handler) readIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	writeAdminJSON(w, identityProviderRepresentationOf(p, false))
}

// exportIdentityProvider serves
// GET /admin/realms/{realm}/identity-provider/instances/{alias}/export.
//
// **Every provider this cut can serve answers 204 with no body and no
// Content-Type**, measured on `oidc` and on `github`. Only a `saml` provider
// answers a body, and that body is SAML SP metadata carrying a freshly minted
// `ID="ID_<uuid>"` on every request - which is why the SAML case is not
// `Recorded`: a page carrying a per-request value cannot be.
//
// The 204 carries `Cache-Control: no-cache` and no `X-Frame-Options`, the
// request having sent no Content-Type.
func (h *handler) exportIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// reloadIdentityProviderKeys serves
// GET /admin/realms/{realm}/identity-provider/instances/{alias}/reload-keys.
//
// **The body is the bare JSON `false`**, measured on `oidc`, `saml` and
// `github` alike. It reports whether anything was reloaded, and nothing is,
// because no provider on a default container has a JWKS Keycloak has cached.
//
// **It is the one read on this family that refuses the view role.** It needs
// `manage-identity-providers` where its six siblings take
// `view-identity-providers` too - measured one role at a time. That makes it
// the second read in the whole API with this shape, after
// `GET .../authz/resource-server/settings`, and the role list is in the router
// rather than here for the same reason that one's is.
func (h *handler) reloadIdentityProviderKeys(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	writeAdminJSON(w, false)
}

// identityProviderBody is what the two writes decode.
//
// Decoded with decodeStrict: `POST` and `PUT` here are the **sixth and
// seventh** strict endpoints, after the two required-action PUTs, the two
// organization writes and `PUT .../authz/resource-server`. An unknown field
// answers
//
//	400 {"error":"Invalid json representation for IdentityProviderRepresentation.
//	     Unrecognized field \"zzz\" at line 1 column 58."}
//
// naming the class, the field, the line and the column - which is why
// AGENTS.md's claim that client registration is "the only one that reports a
// position" is wrong four ways over.
//
// The field set is what a create was measured accepting and no more, so the
// three fields the server takes and never echoes are here and unused:
// `updateProfileFirstLoginMode` and `postBrokerLoginFlowAlias` are read and
// discarded, and `organizationId` is refused below rather than stored.
type identityProviderBody struct {
	Alias                       *string           `json:"alias"`
	DisplayName                 string            `json:"displayName"`
	InternalID                  string            `json:"internalId"`
	ProviderID                  *string           `json:"providerId"`
	Enabled                     *bool             `json:"enabled"`
	UpdateProfileFirstLoginMode string            `json:"updateProfileFirstLoginMode"`
	TrustEmail                  *bool             `json:"trustEmail"`
	StoreToken                  *bool             `json:"storeToken"`
	AddReadTokenRoleOnCreate    *bool             `json:"addReadTokenRoleOnCreate"`
	AuthenticateByDefault       *bool             `json:"authenticateByDefault"`
	LinkOnly                    *bool             `json:"linkOnly"`
	HideOnLogin                 *bool             `json:"hideOnLogin"`
	FirstBrokerLoginFlowAlias   string            `json:"firstBrokerLoginFlowAlias"`
	PostBrokerLoginFlowAlias    string            `json:"postBrokerLoginFlowAlias"`
	OrganizationID              *string           `json:"organizationId"`
	Config                      map[string]string `json:"config"`
}

// createIdentityProvider serves
// POST /admin/realms/{realm}/identity-provider/instances.
//
// **The body's internalId wins**, measured: a create naming
// `11111111-1111-1111-1111-111111111111` produced a provider with exactly that
// id and put nothing else in its place. That is the third create with this rule
// after POST /clients and POST /client-scopes, against POST /organizations
// where the id is read and discarded.
//
// The 201 carries a `Location` ending in the **alias** and no Content-Type at
// all. A name tail, not a uuid tail, which joins POST /roles,
// POST /clients/{uuid}/roles and POST /admin/realms - and it is one of the two
// creates AGENTS.md's Location bullet records as unreachable on a default
// container.
//
// The check order is measured four deep and no two steps share a shape:
//
//	unknown field                strict 400
//	organizationId, any value    400 {"errorMessage":"Organization associated with broker does not exist"}
//	no alias                     400 {"errorMessage":"path is null"}
//	unregistered providerId      400 {"errorMessage":"Invalid identity provider id [x]"}
//	duplicate alias              409 {"errorMessage":"Identity Provider a already exists"}
func (h *handler) createIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body identityProviderBody
	if !decodeStrict(w, r, "IdentityProviderRepresentation", &body) {
		return
	}
	if !checkBrokerOrganization(w, &body) {
		return
	}
	if body.Alias == nil || *body.Alias == "" {
		// Keycloak's own message, and it is about a path rather than about the
		// field the request is missing. Copied verbatim.
		httpx.WriteAdminError(w, http.StatusBadRequest, "path is null")
		return
	}
	if !checkIdentityProviderID(w, body.ProviderID) {
		return
	}

	p := identityProviderOf(rc.realm.ID, &body)
	if p.InternalID == "" {
		p.InternalID = model.NewID()
	}
	switch err := h.store.IdentityProviders().Create(r.Context(), p); {
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusConflict,
			"Identity Provider "+*body.Alias+" already exists")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/identity-provider/instances/"+*body.Alias)
	w.WriteHeader(http.StatusCreated)
}

// updateIdentityProvider serves
// PUT /admin/realms/{realm}/identity-provider/instances/{alias}.
//
// **It replaces and does not merge.** A provider carrying eight non-default
// fields and four config keys, updated with a body naming only the alias, the
// provider id and a display name, kept its internalId and lost every other
// field and its whole config. That is `PUT` on a role's rule and not `PUT` on a
// client's.
//
// **A body with no alias answers 204 and clears the alias**, which strands the
// row: the listing then serves it with no `alias` key, sorted first, and
// nothing can address it again. The rename check below is
// `Identity Provider alias cannot be changed`, and a null alias is not a
// change, so the check passes and the write lands anyway. Keycloak's own
// defect, reproduced. Refusing an absent alias here would be the tidy-up that
// makes a measured 204 into a 400.
//
// **The strict decode runs before the alias in the path is resolved**, which is
// the required-action PUT's order and the opposite of the organization PUT's:
// a PUT to an alias that does not exist carrying an unknown field answers the
// 400 rather than the 404. That ordering lives in the router, which resolves
// nothing for this route.
func (h *handler) updateIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body identityProviderBody
	if !decodeStrict(w, r, "IdentityProviderRepresentation", &body) {
		return
	}
	existing, err := h.store.IdentityProviders().ByAlias(r.Context(), rc.realm.ID, r.PathValue("alias"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeIdentityProviderNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !checkBrokerOrganization(w, &body) {
		return
	}
	// A **present** alias that differs is refused; an absent one is not a
	// change and falls through to the write, which then clears it. The two
	// halves of that sentence are one measurement each.
	if body.Alias != nil && existing.Alias != nil && *body.Alias != *existing.Alias {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Identity Provider alias cannot be changed")
		return
	}
	if !checkIdentityProviderID(w, body.ProviderID) {
		return
	}

	updated := identityProviderOf(rc.realm.ID, &body)
	// The internal id is the row's, never the body's: the PUT was measured
	// keeping it across a replace that lost everything else.
	updated.InternalID = existing.InternalID
	switch err := h.store.IdentityProviders().Update(r.Context(), updated); {
	case errors.Is(err, store.ErrNotFound):
		writeIdentityProviderNotFound(w)
		return
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusConflict,
			"Identity Provider "+*body.Alias+" already exists")
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// deleteIdentityProvider serves
// DELETE /admin/realms/{realm}/identity-provider/instances/{alias}.
//
// Its 204 carries `Cache-Control: no-cache` and no `X-Frame-Options` - the
// request sends no Content-Type, which is what decides the second. It is not
// idempotent: the second delete is the generic 404.
func (h *handler) deleteIdentityProvider(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	alias := ""
	if p.Alias != nil {
		alias = *p.Alias
	}
	if err := h.store.IdentityProviders().Delete(r.Context(), rc.realm.ID, alias); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeIdentityProviderNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// checkIdentityProviderID refuses a provider id Keycloak does not register.
//
// An absent id and an unknown one share one message with the value
// interpolated, `null` for the absent case - so the two are one check with one
// spelling, which is why this is a single function and not a presence test
// followed by a membership test.
func checkIdentityProviderID(w http.ResponseWriter, providerID *string) bool {
	if providerID == nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Invalid identity provider id [null]")
		return false
	}
	if !model.IsIdentityProvider(*providerID) {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"Invalid identity provider id ["+*providerID+"]")
		return false
	}
	return true
}

// checkBrokerOrganization refuses any organizationId, including the empty
// string.
//
// **An empty string is not an absent field here**, measured: a create carrying
// `"organizationId":""` alongside a complete and otherwise valid body answered
// 400. Nothing in this cut creates a broker inside an organization, so every
// value that reaches this function names an organization that does not exist,
// and the message is the same for all of them.
func checkBrokerOrganization(w http.ResponseWriter, body *identityProviderBody) bool {
	if body.OrganizationID == nil {
		return true
	}
	httpx.WriteAdminError(w, http.StatusBadRequest,
		"Organization associated with broker does not exist")
	return false
}

// identityProviderOf builds the stored provider from a decoded body. It is
// shared by the create and the update because the update replaces, so the two
// want the same thing from the same fields.
func identityProviderOf(realmID string, body *identityProviderBody) *model.IdentityProvider {
	p := &model.IdentityProvider{
		InternalID:                body.InternalID,
		RealmID:                   realmID,
		Alias:                     body.Alias,
		DisplayName:               body.DisplayName,
		Enabled:                   body.Enabled == nil || *body.Enabled,
		TrustEmail:                body.TrustEmail,
		StoreToken:                body.StoreToken,
		AddReadTokenRoleOnCreate:  body.AddReadTokenRoleOnCreate,
		AuthenticateByDefault:     body.AuthenticateByDefault,
		LinkOnly:                  body.LinkOnly,
		HideOnLogin:               body.HideOnLogin,
		FirstBrokerLoginFlowAlias: body.FirstBrokerLoginFlowAlias,
		Config:                    identityProviderConfigOf(body.Config),
	}
	if body.ProviderID != nil {
		p.ProviderID = *body.ProviderID
	}
	return p
}

// identityProviderConfigOf turns the decoded map into the ordered slice the
// model holds. The map's own iteration order is random, so the names are sorted
// here to make the store deterministic; javamap.SizedKeyOrder decides the wire
// order afterwards and does not care what order it is handed.
func identityProviderConfigOf(in map[string]string) []model.IdentityProviderConfigEntry {
	if len(in) == 0 {
		return nil
	}
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]model.IdentityProviderConfigEntry, 0, len(names))
	for _, name := range names {
		out = append(out, model.IdentityProviderConfigEntry{Name: name, Value: in[name]})
	}
	return out
}

// writeIdentityProviderNotFound is the 404 for an alias that does not exist.
//
// **It is the generic `{"error":"HTTP 404 Not Found"}` and not a spelling of
// not-found**, measured on the read, the update and the delete alike. So this
// family adds nothing to the list of spellings while the Component family next
// door adds two, which is another thing the description's tag does not predict.
func writeIdentityProviderNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}
