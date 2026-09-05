// This file serves the authentication flow model: the twenty-one operations of
// the Authentication Management tag's `flows`, `executions` and `config`
// families.
//
// # What of this model Gloak actually reads, and what it does not
//
// F103 deferred these twenty-one because "Gloak walks a hard-coded
// authentication flow", so serving them would let a caller edit a description
// of something the server does not read. This file exists because that is now
// **partly** false, and the boundary is here rather than only in a handover
// because a handover is not where the next reader meets the code.
//
// `internal/oidc`'s browser login reads **three** things from what these
// handlers write:
//
//  1. the realm's `browserFlow` binding, which selects the top-level flow the
//     login walks. It was served on every realm representation and read by
//     nothing before this cut.
//  2. that flow's `auth-username-password-form` execution **id**, which is the
//     `execution` parameter the login form carries and the value
//     `/login-actions/authenticate` checks. It was a SHA-256 of the realm id.
//  3. that flow's `auth-cookie` execution's `requirement`, read as DISABLED or
//     not: DISABLED stops the SSO short-circuit. Measured on 26.7.1, three
//     states with the revert reverting.
//
// **Everything else in this model is stored, served and not read.** Named,
// because an unnamed exception is what F103 objects to:
//
//   - the other six flow bindings on the realm - `registrationFlow`,
//     `directGrantFlow`, `resetCredentialsFlow`, `clientAuthenticationFlow`,
//     `dockerAuthenticationFlow`, `firstBrokerLoginFlow` - still resolve
//     nothing.
//   - thirteen of the browser flow's fifteen execution rows are not read,
//     `auth-spnego` and `identity-provider-redirector` among them: Gloak has
//     neither Kerberos nor an identity-provider redirect in the login path, so
//     their requirements move nothing.
//   - `REQUIRED`, `ALTERNATIVE` and `CONDITIONAL` are stored and compared for
//     equality and never interpreted. Keycloak's requirement semantics over a
//     tree are not implemented and nothing here pretends they are.
//   - the `registration`, `reset credentials`, `first broker login`,
//     `docker auth` and `clients` flows are seeded, served and walked by
//     nothing.
//
// See docs/superpowers/plans/2026-09-03-f103-authentication-flows.md §1.

package admin

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// requirementChoicesJSON is `requirementChoices` per provider id, measured on
// 2026-09-03 by adding all fifty-three providers the four registries publish to
// one scratch flow and reading the execution listing back.
//
// It is a file of its own rather than a field on authProvider, because
// authProvider is a **serialiser**: its declared fields are the registry
// listings' bytes, and a new tag there would put a key into four responses that
// do not carry one.
//
// It is a stored list and not a derived set. Four distinct lists cover the
// fifty-three, and `http-basic-authenticator` alone carries `CONDITIONAL` -
// **third**, before `DISABLED`, where every other list ends with `DISABLED`. So
// the order is per provider and sorting it is wrong on exactly one row, which
// is the kind of thing that survives review by looking like tidiness.
//
//go:embed requirementchoices.json
var requirementChoicesJSON []byte

var requirementChoices = func() map[string][]string {
	var m map[string][]string
	if err := json.Unmarshal(requirementChoicesJSON, &m); err != nil {
		panic("admin: requirementchoices.json: " + err.Error())
	}
	return m
}()

// subFlowRequirementChoices is what a row with no provider id carries: a pure
// sub-flow reference. Measured on every seeded sub-flow row and on two created
// ones.
//
// A row carrying **both** a provider and a flow - the `registration` flow's
// only row, `registration-page-form` pointing at `registration form` - takes
// the **provider's** list, not this one. So the provider is the discriminator
// and the flow is not.
var subFlowRequirementChoices = []string{"REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL"}

// The five refusals this family spells. They are written out rather than shared
// because two of them differ **only in the case of the first letter**, which no
// shared constant survives.
const (
	// flowNotFoundByID is what GET and PUT /flows/{id} answer.
	flowNotFoundByID = "Could not find flow with id"
	// flowNotFound is what DELETE /flows/{id} and POST /flows/{alias}/copy
	// answer for a flow that is not there.
	flowNotFound = "Flow not found"
	// flowNotFoundLower is what PUT /flows/{alias}/executions answers, and the
	// **F is lower case**. One missing flow, three spellings, decided by which
	// route went looking. Correcting the capital is the tidy-up that breaks it.
	flowNotFoundLower = "flow not found"
	// illegalExecution is every /executions/{id} route's not-found, including
	// POST /executions/{id}/config. It is a 404 despite reading as a 400.
	illegalExecution = "Illegal execution"
	// authenticatorConfigNotFound is all four config routes' not-found, and
	// GET /executions/{id}/config/{id}'s.
	authenticatorConfigNotFound = "Could not find authenticator config"
)

// The refusals that are not 404s, in the `errorMessage` shape.
const (
	flowEmptyAliasOnCreate   = "Failed to create flow with empty alias name"
	flowEmptyAliasOnUpdate   = "Failed to update flow with empty alias name"
	flowAliasExists          = " already exists"
	copyAliasExists          = "New flow alias name already exists"
	cannotDeleteBuiltIn      = "Can't delete built in flow"
	parentFlowMissing        = "Parent flow doesn't exist"
	noAuthenticationProvider = "No authentication provider found for id: "
)

// authenticationFlowRepresentation is the nested body GET /flows and
// GET /flows/{id} serve.
//
// `alias` and `description` are omitempty for different reasons. A flow with no
// alias is reachable - POST /flows/{alias}/copy with no `newName` makes one -
// and its representation carries **no `alias` key**; `docker auth` and every
// other seeded flow has a description, but a flow created without one carries
// no key either.
type authenticationFlowRepresentation struct {
	ID                       string                          `json:"id"`
	Alias                    string                          `json:"alias,omitempty"`
	Description              string                          `json:"description,omitempty"`
	ProviderID               string                          `json:"providerId"`
	TopLevel                 bool                            `json:"topLevel"`
	BuiltIn                  bool                            `json:"builtIn"`
	AuthenticationExecutions []nestedExecutionRepresentation `json:"authenticationExecutions"`
}

// nestedExecutionRepresentation is one row inside that body.
//
// **`autheticatorFlow` is not a typo here.** Keycloak serialises the row twice,
// once through a correctly spelled accessor and once through one missing its
// `n`, always with the same value. It is contract. Removing it is the tidy-up
// that breaks every flow read.
type nestedExecutionRepresentation struct {
	AuthenticatorConfig string `json:"authenticatorConfig,omitempty"`
	Authenticator       string `json:"authenticator,omitempty"`
	AuthenticatorFlow   bool   `json:"authenticatorFlow"`
	Requirement         string `json:"requirement"`
	Priority            int    `json:"priority"`
	AutheticatorFlow    bool   `json:"autheticatorFlow"`
	FlowAlias           string `json:"flowAlias,omitempty"`
	UserSetupAllowed    bool   `json:"userSetupAllowed"`
}

// executionInfoRepresentation is the **flat** body
// GET /flows/{alias}/executions serves, and it is a different object from the
// nested one rather than a projection of it: it carries `level`, `index`,
// `displayName`, `requirementChoices` and `configurable`, which are properties
// of the walk and of the SPI rather than of the row, and it names a sub-flow by
// `flowId` where the nested shape names it by `flowAlias`.
//
// Five key orders were measured on a seeded realm and a sixth on a sub-flow
// created without an alias, which omits `displayName`. The declared order below
// is their merge. **The relative order of `description` and `alias`, and of
// `flowId` and `authenticationConfig`, is unmeasured**: no observed row carries
// either pair together. It is recorded rather than resolved.
type executionInfoRepresentation struct {
	ID                   string   `json:"id"`
	Requirement          string   `json:"requirement"`
	DisplayName          string   `json:"displayName,omitempty"`
	Description          string   `json:"description,omitempty"`
	Alias                string   `json:"alias,omitempty"`
	RequirementChoices   []string `json:"requirementChoices"`
	Configurable         bool     `json:"configurable"`
	AuthenticationFlow   bool     `json:"authenticationFlow,omitempty"`
	ProviderID           string   `json:"providerId,omitempty"`
	FlowID               string   `json:"flowId,omitempty"`
	AuthenticationConfig string   `json:"authenticationConfig,omitempty"`
	Level                int      `json:"level"`
	Index                int      `json:"index"`
	Priority             int      `json:"priority"`
}

// executionRepresentation is the **third** serialisation of one row, served by
// GET /executions/{id}: the nested shape with `id` appended, then `flowId`,
// then `parentFlow`.
//
// `flowId` sits between `id` and `parentFlow` here and between `configurable`
// and `level` in the flat listing, and the nested shape does not carry it at
// all - it carries `flowAlias`. Three orders for one field, so one shared
// serialiser is wrong on two of them.
type executionRepresentation struct {
	AuthenticatorConfig string `json:"authenticatorConfig,omitempty"`
	Authenticator       string `json:"authenticator,omitempty"`
	AuthenticatorFlow   bool   `json:"authenticatorFlow"`
	Requirement         string `json:"requirement"`
	Priority            int    `json:"priority"`
	AutheticatorFlow    bool   `json:"autheticatorFlow"`
	ID                  string `json:"id"`
	FlowID              string `json:"flowId,omitempty"`
	ParentFlow          string `json:"parentFlow"`
}

// authenticatorConfigRepresentation is what all four config routes serve, and
// GET /executions/{id}/config/{id} serves it **byte-identically** - measured on
// the same config through both paths.
type authenticatorConfigRepresentation struct {
	ID     string          `json:"id"`
	Alias  string          `json:"alias"`
	Config model.StringMap `json:"config"`
}

// The four request bodies. Each names the representation class its strict
// decoder reports, and those three class names are measured strings inside the
// 400.
type flowBody struct {
	ID                       string          `json:"id"`
	Alias                    *string         `json:"alias"`
	Description              string          `json:"description"`
	ProviderID               string          `json:"providerId"`
	TopLevel                 bool            `json:"topLevel"`
	BuiltIn                  bool            `json:"builtIn"`
	AuthenticationExecutions json.RawMessage `json:"authenticationExecutions"`
}

type copyBody struct {
	NewName string `json:"newName"`
}

type executionInfoBody struct {
	ID                   string          `json:"id"`
	Requirement          string          `json:"requirement"`
	DisplayName          string          `json:"displayName"`
	Description          string          `json:"description"`
	Alias                string          `json:"alias"`
	RequirementChoices   json.RawMessage `json:"requirementChoices"`
	Configurable         bool            `json:"configurable"`
	AuthenticationFlow   bool            `json:"authenticationFlow"`
	ProviderID           string          `json:"providerId"`
	FlowID               string          `json:"flowId"`
	AuthenticationConfig string          `json:"authenticationConfig"`
	Level                int             `json:"level"`
	Index                int             `json:"index"`
	Priority             int             `json:"priority"`
}

type executionCreateBody struct {
	Provider string `json:"provider"`
}

type subFlowCreateBody struct {
	Alias       string `json:"alias"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Provider    string `json:"provider"`
}

type authenticatorConfigBody struct {
	ID     string          `json:"id"`
	Alias  string          `json:"alias"`
	Config model.StringMap `json:"config"`
}

// flowAliasOf is the empty string for a flow with no alias, which is what makes
// the representation omit the key.
func flowAliasOf(f *model.AuthenticationFlow) string {
	if f.Alias == nil {
		return ""
	}
	return *f.Alias
}

// configurableProvider reports whether a provider id declares any config
// property, which is exactly what `configurable` means on an execution row.
//
// Measured across all fifty-three providers with **zero** mismatches, which is
// why there is no `configurable` column and no second table: it is the registry
// this package already embeds, asked a different question.
func configurableProvider(providerID string) bool {
	if providerID == "" {
		return false
	}
	for _, list := range [][]authProvider{
		authProviders.Authenticators, authProviders.FormActions,
		authProviders.ClientAuthenticators, authProviders.FormProviders,
	} {
		for _, p := range list {
			if p.ID == providerID {
				return len(p.Properties) > 0
			}
		}
	}
	return false
}

// knownAuthenticationProvider reports whether an id names one of the fifty-three
// the four registries publish. They are disjoint, so the union is exactly that.
func knownAuthenticationProvider(providerID string) bool {
	_, ok := requirementChoices[providerID]
	return ok
}

// displayNameOf is the provider's `displayName` for a leaf row and the
// sub-flow's alias for a flow row. A sub-flow with no alias yields the empty
// string, which is what makes that row's `displayName` key absent.
func displayNameOf(providerID string) string {
	for _, list := range [][]authProvider{
		authProviders.Authenticators, authProviders.FormActions,
		authProviders.ClientAuthenticators, authProviders.FormProviders,
	} {
		for _, p := range list {
			if p.ID == providerID {
				return p.DisplayName
			}
		}
	}
	return ""
}

func descriptionOf(providerID string) string {
	for _, list := range [][]authProvider{
		authProviders.Authenticators, authProviders.FormActions,
		authProviders.ClientAuthenticators, authProviders.FormProviders,
	} {
		for _, p := range list {
			if p.ID == providerID {
				return p.Description
			}
		}
	}
	return ""
}

func (h *handler) flowInternalError(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
}

// flowsByID and flowsByAlias index one realm's flows once, because every
// operation on this tag needs both and the alternative is a query per row.
type flowIndex struct {
	byID    map[string]*model.AuthenticationFlow
	byAlias map[string]*model.AuthenticationFlow
	ordered []*model.AuthenticationFlow
}

func (h *handler) loadFlows(w http.ResponseWriter, r *http.Request, rc *reqContext) (*flowIndex, bool) {
	rows, err := h.store.AuthenticationFlows().ListFlows(r.Context(), rc.realm.ID)
	if err != nil {
		h.flowInternalError(w)
		return nil, false
	}
	idx := &flowIndex{
		byID:    make(map[string]*model.AuthenticationFlow, len(rows)),
		byAlias: make(map[string]*model.AuthenticationFlow, len(rows)),
		ordered: rows,
	}
	for _, f := range rows {
		idx.byID[f.ID] = f
		if f.Alias != nil && *f.Alias != "" {
			idx.byAlias[*f.Alias] = f
		}
	}
	return idx, true
}

// nestedExecutionsOf builds a flow's `authenticationExecutions`: its **direct**
// rows only, in priority order. The whole tree is what the flat listing serves;
// this one stops at the children, which is why `browser` shows four rows on
// master and fifteen appear in its execution listing.
func (h *handler) nestedExecutionsOf(r *http.Request, rc *reqContext, idx *flowIndex,
	flowID string, configAliases map[string]string) ([]nestedExecutionRepresentation, error) {
	rows, err := h.store.AuthenticationFlows().ListExecutions(r.Context(), rc.realm.ID, flowID)
	if err != nil {
		return nil, err
	}
	out := make([]nestedExecutionRepresentation, 0, len(rows))
	for _, e := range rows {
		isFlow := e.FlowID != ""
		rep := nestedExecutionRepresentation{
			AuthenticatorConfig: configAliases[e.ConfigID],
			Authenticator:       e.Authenticator,
			AuthenticatorFlow:   isFlow,
			Requirement:         e.Requirement,
			Priority:            e.Priority,
			AutheticatorFlow:    isFlow,
		}
		if isFlow {
			if sub := idx.byID[e.FlowID]; sub != nil {
				rep.FlowAlias = flowAliasOf(sub)
			}
		}
		out = append(out, rep)
	}
	return out, nil
}

// configAliasIndex maps a config id to its alias, which is what the **nested**
// representation carries where the flat listing carries the id. Two shapes of
// one pointer.
func (h *handler) configAliasIndex(r *http.Request, rc *reqContext) (map[string]string, error) {
	rows, err := h.store.AuthenticationFlows().ListConfigs(r.Context(), rc.realm.ID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(rows))
	for _, c := range rows {
		m[c.ID] = c.Alias
	}
	return m, nil
}

func (h *handler) flowRepresentation(r *http.Request, rc *reqContext, idx *flowIndex,
	f *model.AuthenticationFlow, configAliases map[string]string) (authenticationFlowRepresentation, error) {
	execs, err := h.nestedExecutionsOf(r, rc, idx, f.ID, configAliases)
	if err != nil {
		return authenticationFlowRepresentation{}, err
	}
	return authenticationFlowRepresentation{
		ID:                       f.ID,
		Alias:                    flowAliasOf(f),
		Description:              f.Description,
		ProviderID:               f.ProviderID,
		TopLevel:                 f.TopLevel,
		BuiltIn:                  f.BuiltIn,
		AuthenticationExecutions: execs,
	}, nil
}

// listFlows serves GET .../authentication/flows.
//
// **Top-level flows only** - seven of a created realm's twenty. The thirteen
// sub-flows are reachable through /flows/{alias}/executions and by id, and
// serving all twenty here is the mistake a single ListFlows call invites.
//
// Its role set is **wider than every other read on this family**, and that is
// measured one role at a time across all twenty-one of the realm's own admin
// roles: `view-clients` and `query-clients` get a 200 here and a **403** on
// GET /flows/{id} and GET /flows/{alias}/executions immediately beside it. It
// is not the "200 with a shorter list to a weaker caller" pattern - a
// query-clients caller's body is byte-identical to a manage-realm caller's. See
// flowListReadRoles.
func (h *handler) listFlows(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	aliases, err := h.configAliasIndex(r, rc)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	out := make([]authenticationFlowRepresentation, 0, len(idx.ordered))
	for _, f := range idx.ordered {
		if !f.TopLevel {
			continue
		}
		rep, err := h.flowRepresentation(r, rc, idx, f, aliases)
		if err != nil {
			h.flowInternalError(w)
			return
		}
		out = append(out, rep)
	}
	writeAdminJSON(w, out)
}

// readFlow serves GET .../authentication/flows/{id}.
//
// The segment is an **id**, never an alias: `GET /flows/browser` on a realm
// that has a `browser` flow answers 404 `Could not find flow with id`. That is
// measured, and it is the opposite of the /flows/{flowAlias}/... routes one
// segment away, which take an alias and never an id.
func (h *handler) readFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	f := idx.byID[r.PathValue("id")]
	if f == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFoundByID)
		return
	}
	aliases, err := h.configAliasIndex(r, rc)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	rep, err := h.flowRepresentation(r, rc, idx, f, aliases)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	writeAdminJSON(w, rep)
}

// createFlow serves POST .../authentication/flows.
//
// Three refusals, and the middle one is the surprise:
//
//   - an absent or empty `alias` is a **409**, not a 400, in the `errorMessage`
//     shape.
//   - an alias with **no `providerId`** is a 409 `Duplicate resource error` -
//     the RFC-shaped body - for a body that duplicates nothing. Measured, and
//     reproduced as measured rather than as coherent. It carries **none** of
//     the five security headers where the empty-alias 409 on this same route
//     carries all five, which is another instance of the split AGENTS.md
//     records as unexplained and a second one on a single route.
//   - a taken alias is a 409 naming it.
//
// The order matters: `{}` answers about the alias, `{"alias":"x"}` answers
// about the provider.
func (h *handler) createFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body flowBody
	if !decodeStrict(w, r, "AuthenticationFlowRepresentation", &body) {
		return
	}
	if body.Alias == nil || *body.Alias == "" {
		httpx.WriteAdminError(w, http.StatusConflict, flowEmptyAliasOnCreate)
		return
	}
	if body.ProviderID == "" {
		writeDuplicateResource(w)
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	if idx.byAlias[*body.Alias] != nil {
		httpx.WriteAdminError(w, http.StatusConflict, "Flow "+*body.Alias+flowAliasExists)
		return
	}
	alias := *body.Alias
	f := &model.AuthenticationFlow{
		ID:          model.NewID(),
		RealmID:     rc.realm.ID,
		Alias:       &alias,
		Description: body.Description,
		ProviderID:  body.ProviderID,
		TopLevel:    body.TopLevel,
		BuiltIn:     body.BuiltIn,
		Ordinal:     len(idx.ordered),
	}
	if err := h.store.AuthenticationFlows().CreateFlow(r.Context(), f); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/flows/"+f.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateFlow serves PUT .../authentication/flows/{id}.
//
// **A built-in flow can be renamed through it**, measured on a created realm's
// `browser` flow: 204, and the listing then serves `browser-renamed`. Only the
// DELETE checks `builtIn`. Renaming the realm's bound browser flow is how a
// caller detaches the login from it, which is exactly what binding B1 makes
// observable.
//
// A body with no alias is a 409, the update's own spelling of the create's.
func (h *handler) updateFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body flowBody
	if !decodeStrict(w, r, "AuthenticationFlowRepresentation", &body) {
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	f := idx.byID[r.PathValue("id")]
	if f == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFoundByID)
		return
	}
	if body.Alias == nil || *body.Alias == "" {
		httpx.WriteAdminError(w, http.StatusConflict, flowEmptyAliasOnUpdate)
		return
	}
	alias := *body.Alias
	f.Alias = &alias
	f.Description = body.Description
	if err := h.store.AuthenticationFlows().UpdateFlow(r.Context(), f); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// deleteFlow serves DELETE .../authentication/flows/{id}.
//
// A built-in flow is a **400** with a body, not a 403 and not a 409:
// `{"error":"Can't delete built in flow"}`, apostrophe included. A flow that is
// not there is `Flow not found`, which is a different sentence from the
// `Could not find flow with id` its own GET answers for the same id.
func (h *handler) deleteFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	f := idx.byID[r.PathValue("id")]
	if f == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFound)
		return
	}
	if f.BuiltIn {
		httpx.WriteMessageError(w, http.StatusBadRequest, cannotDeleteBuiltIn)
		return
	}
	if err := h.store.AuthenticationFlows().DeleteFlow(r.Context(), rc.realm.ID, f.ID); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// copyFlow serves POST .../authentication/flows/{flowAlias}/copy.
//
// Two measured oddities, both reproduced:
//
//   - **its `Location` echoes its own creating path**,
//     `.../flows/{alias}/copy/{new id}`, where POST /flows answers
//     `.../flows/{new id}`. AGENTS.md records that inversion on the
//     organization group family; this is a second family with it, on the same
//     tag as three routes that do not.
//   - **a body with no `newName` is a 201** and creates a top-level flow whose
//     representation has no `alias` key at all - a resource the API cannot
//     name afterwards. It is Keycloak's own defect, the family F97 and F159
//     belong to, and tidying it is what breaks the copy.
//
// The copy is deep: the sub-flows are copied too, so copying `browser` on a
// created realm produces four new flows, not one.
func (h *handler) copyFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body copyBody
	if !decodeStrict(w, r, "Map", &body) {
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	src := idx.byAlias[r.PathValue("flowAlias")]
	if src == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFound)
		return
	}
	if body.NewName != "" && idx.byAlias[body.NewName] != nil {
		httpx.WriteAdminError(w, http.StatusConflict, copyAliasExists)
		return
	}
	newID, err := h.copyFlowTree(r, rc, idx, src, body.NewName, len(idx.ordered))
	if err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/flows/"+r.PathValue("flowAlias")+"/copy/"+newID)
	w.WriteHeader(http.StatusCreated)
}

// copyFlowTree copies one flow and everything under it, returning the new
// flow's id. A sub-flow keeps its own alias - only the root is renamed - which
// is why copying `browser` twice is a 409 on the second `newName` and not on
// the sub-flows it duplicates.
func (h *handler) copyFlowTree(r *http.Request, rc *reqContext, idx *flowIndex,
	src *model.AuthenticationFlow, newName string, ordinal int) (string, error) {
	repo := h.store.AuthenticationFlows()
	dst := &model.AuthenticationFlow{
		ID:          model.NewID(),
		RealmID:     rc.realm.ID,
		Description: src.Description,
		ProviderID:  src.ProviderID,
		TopLevel:    src.TopLevel,
		BuiltIn:     false,
		Ordinal:     ordinal,
	}
	if newName != "" {
		alias := newName
		dst.Alias = &alias
	} else if !src.TopLevel {
		alias := flowAliasOf(src)
		dst.Alias = &alias
	}
	if err := repo.CreateFlow(r.Context(), dst); err != nil {
		return "", err
	}
	rows, err := repo.ListExecutions(r.Context(), rc.realm.ID, src.ID)
	if err != nil {
		return "", err
	}
	for _, e := range rows {
		copied := &model.AuthenticationExecution{
			ID:            model.NewID(),
			RealmID:       rc.realm.ID,
			ParentFlowID:  dst.ID,
			Authenticator: e.Authenticator,
			ConfigID:      e.ConfigID,
			Requirement:   e.Requirement,
			Priority:      e.Priority,
		}
		if e.FlowID != "" {
			sub := idx.byID[e.FlowID]
			if sub != nil {
				subID, err := h.copyFlowTree(r, rc, idx, sub, "", ordinal)
				if err != nil {
					return "", err
				}
				copied.FlowID = subID
			}
		}
		if err := repo.CreateExecution(r.Context(), copied); err != nil {
			return "", err
		}
	}
	return dst.ID, nil
}

// walkedExecution is one row of the flat listing plus the walk's own two
// numbers.
type walkedExecution struct {
	row   *model.AuthenticationExecution
	level int
	index int
}

// walkExecutions produces the depth-first pre-order traversal
// GET /flows/{alias}/executions serves.
//
// `level` is the depth below the addressed flow and `index` the position among
// siblings, so a sub-flow's rows appear **between** their parent row and its
// next sibling. That is what puts `first broker login`'s level-0 organization
// row after rows at level 5.
func (h *handler) walkExecutions(r *http.Request, rc *reqContext, idx *flowIndex,
	flowID string, level int, out *[]walkedExecution) error {
	rows, err := h.store.AuthenticationFlows().ListExecutions(r.Context(), rc.realm.ID, flowID)
	if err != nil {
		return err
	}
	for i, e := range rows {
		*out = append(*out, walkedExecution{row: e, level: level, index: i})
		if e.FlowID != "" && idx.byID[e.FlowID] != nil {
			if err := h.walkExecutions(r, rc, idx, e.FlowID, level+1, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *handler) executionInfoOf(idx *flowIndex, we walkedExecution,
	configAliases map[string]string) executionInfoRepresentation {
	e := we.row
	isFlow := e.FlowID != ""
	rep := executionInfoRepresentation{
		ID:                   e.ID,
		Requirement:          e.Requirement,
		ProviderID:           e.Authenticator,
		FlowID:               e.FlowID,
		AuthenticationConfig: e.ConfigID,
		AuthenticationFlow:   isFlow,
		Level:                we.level,
		Index:                we.index,
		Priority:             e.Priority,
	}
	if e.Authenticator != "" {
		rep.DisplayName = displayNameOf(e.Authenticator)
		rep.RequirementChoices = requirementChoices[e.Authenticator]
		rep.Configurable = configurableProvider(e.Authenticator)
	}
	if isFlow {
		sub := idx.byID[e.FlowID]
		if sub != nil {
			// A sub-flow row's displayName and description are the sub-flow's
			// own alias and description, not the provider's - and the row that
			// carries **both** a provider and a flow takes the sub-flow's
			// names and the provider's requirementChoices. Measured on the
			// `registration` flow's only row.
			rep.DisplayName = flowAliasOf(sub)
			rep.Description = sub.Description
		}
		if e.Authenticator == "" {
			rep.RequirementChoices = subFlowRequirementChoices
		}
	}
	if alias := configAliases[e.ConfigID]; alias != "" {
		rep.Alias = alias
	}
	if rep.RequirementChoices == nil {
		rep.RequirementChoices = []string{}
	}
	return rep
}

// listFlowExecutions serves GET .../authentication/flows/{flowAlias}/executions.
func (h *handler) listFlowExecutions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	f := idx.byAlias[r.PathValue("flowAlias")]
	if f == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFoundLower)
		return
	}
	aliases, err := h.configAliasIndex(r, rc)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	var walked []walkedExecution
	if err := h.walkExecutions(r, rc, idx, f.ID, 0, &walked); err != nil {
		h.flowInternalError(w)
		return
	}
	out := make([]executionInfoRepresentation, 0, len(walked))
	for _, we := range walked {
		out = append(out, h.executionInfoOf(idx, we, aliases))
	}
	writeAdminJSON(w, out)
}

// updateFlowExecution serves PUT .../authentication/flows/{flowAlias}/executions.
//
// The body addresses a row by `id` and the path names its flow, and **the two
// are checked in that order**: an unknown id under a known flow is
// `Illegal execution`, and a known id under an unknown flow is the lower-case
// `flow not found`. So the flow is resolved first and the row second.
//
// `requirement` is the only field it moves. An unparseable value is a **500**
// `unknown_error` on the reference; Gloak reproduces the status and the body
// rather than validating into a 400.
func (h *handler) updateFlowExecution(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body executionInfoBody
	if !decodeStrict(w, r, "AuthenticationExecutionInfoRepresentation", &body) {
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	if idx.byAlias[r.PathValue("flowAlias")] == nil {
		httpx.WriteMessageError(w, http.StatusNotFound, flowNotFoundLower)
		return
	}
	e, err := h.store.AuthenticationFlows().ExecutionByID(r.Context(), rc.realm.ID, body.ID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusNotFound, illegalExecution)
		return
	}
	if err != nil {
		h.flowInternalError(w)
		return
	}
	if !validRequirement(body.Requirement) {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"For more on this error consult the server log.")
		return
	}
	e.Requirement = body.Requirement
	if err := h.store.AuthenticationFlows().UpdateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// validRequirement is membership in the four values, not in the row's own
// requirementChoices: setting `auth-cookie` to CONDITIONAL, which its choices
// do not offer, was accepted with a 204.
func validRequirement(v string) bool {
	switch v {
	case "REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL":
		return true
	}
	return false
}

// createFlowExecution serves
// POST .../authentication/flows/{flowAlias}/executions/execution.
//
// **Its `Location` points at a different route family** than the one that
// created it, `.../authentication/executions/{id}`, where the sibling
// `.../executions/flow` points at `.../authentication/flows/{id}` and the copy
// beside them echoes its own path. Three creates on one family, three Location
// shapes.
//
// The provider is checked **before** the flow: an unknown provider on an
// unknown flow answers about the provider. Both are 400s rather than 404s, and
// an absent provider is reported as the literal `null`.
func (h *handler) createFlowExecution(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body executionCreateBody
	if !decodeStrict(w, r, "Map", &body) {
		return
	}
	if !knownAuthenticationProvider(body.Provider) {
		name := body.Provider
		if name == "" {
			name = "null"
		}
		httpx.WriteMessageError(w, http.StatusBadRequest, noAuthenticationProvider+name)
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	f := idx.byAlias[r.PathValue("flowAlias")]
	if f == nil {
		httpx.WriteMessageError(w, http.StatusBadRequest, parentFlowMissing)
		return
	}
	priority, err := h.nextPriority(r, rc, f.ID)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	e := &model.AuthenticationExecution{
		ID:            model.NewID(),
		RealmID:       rc.realm.ID,
		ParentFlowID:  f.ID,
		Authenticator: body.Provider,
		// DISABLED, not the provider's first choice: a row added to a flow
		// comes back DISABLED whatever it is, measured on all fifty-three.
		Requirement: "DISABLED",
		Priority:    priority,
	}
	if err := h.store.AuthenticationFlows().CreateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/executions/"+e.ID)
	w.WriteHeader(http.StatusCreated)
}

// nextPriority is the count of a flow's direct rows, which is what an added row
// gets: 0, 1, 2 on an empty flow, not 10, 20, 30. The seed's tens are the
// seed's, not the endpoint's.
func (h *handler) nextPriority(r *http.Request, rc *reqContext, flowID string) (int, error) {
	rows, err := h.store.AuthenticationFlows().ListExecutions(r.Context(), rc.realm.ID, flowID)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// createSubFlow serves POST .../authentication/flows/{flowAlias}/executions/flow.
//
// A body with no `type` is a **500** `unknown_error` on the reference, and one
// with no `alias` is a **201** creating a sub-flow whose execution row omits
// `displayName` and carries `description: ""`. Both reproduced.
//
// `provider` is accepted and stored on the row rather than on the flow, which
// is what makes the `registration` flow's single row carry an authenticator and
// a flow at once.
func (h *handler) createSubFlow(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body subFlowCreateBody
	if !decodeStrict(w, r, "Map", &body) {
		return
	}
	if body.Type == "" {
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"For more on this error consult the server log.")
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	parent := idx.byAlias[r.PathValue("flowAlias")]
	if parent == nil {
		httpx.WriteMessageError(w, http.StatusBadRequest, parentFlowMissing)
		return
	}
	if body.Alias != "" && idx.byAlias[body.Alias] != nil {
		httpx.WriteAdminError(w, http.StatusConflict, copyAliasExists)
		return
	}
	sub := &model.AuthenticationFlow{
		ID:          model.NewID(),
		RealmID:     rc.realm.ID,
		Description: body.Description,
		ProviderID:  body.Type,
		TopLevel:    false,
		BuiltIn:     false,
		Ordinal:     len(idx.ordered),
	}
	if body.Alias != "" {
		alias := body.Alias
		sub.Alias = &alias
	}
	if err := h.store.AuthenticationFlows().CreateFlow(r.Context(), sub); err != nil {
		h.flowInternalError(w)
		return
	}
	priority, err := h.nextPriority(r, rc, parent.ID)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	e := &model.AuthenticationExecution{
		ID:            model.NewID(),
		RealmID:       rc.realm.ID,
		ParentFlowID:  parent.ID,
		Authenticator: body.Provider,
		FlowID:        sub.ID,
		Requirement:   "DISABLED",
		Priority:      priority,
	}
	if err := h.store.AuthenticationFlows().CreateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/flows/"+sub.ID)
	w.WriteHeader(http.StatusCreated)
}

// executionFromPath resolves the {executionId} segment, answering
// `Illegal execution` when it matches nothing - which is a 404 for an id that
// names nothing **and** for one that is not a UUID, measured on both.
func (h *handler) executionFromPath(w http.ResponseWriter, r *http.Request,
	rc *reqContext) (*model.AuthenticationExecution, bool) {
	e, err := h.store.AuthenticationFlows().ExecutionByID(r.Context(), rc.realm.ID,
		r.PathValue("executionId"))
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusNotFound, illegalExecution)
		return nil, false
	}
	if err != nil {
		h.flowInternalError(w)
		return nil, false
	}
	return e, true
}

// readExecution serves GET .../authentication/executions/{executionId}.
func (h *handler) readExecution(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	e, ok := h.executionFromPath(w, r, rc)
	if !ok {
		return
	}
	aliases, err := h.configAliasIndex(r, rc)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	isFlow := e.FlowID != ""
	writeAdminJSON(w, executionRepresentation{
		AuthenticatorConfig: aliases[e.ConfigID],
		Authenticator:       e.Authenticator,
		AuthenticatorFlow:   isFlow,
		Requirement:         e.Requirement,
		Priority:            e.Priority,
		AutheticatorFlow:    isFlow,
		ID:                  e.ID,
		FlowID:              e.FlowID,
		ParentFlow:          e.ParentFlowID,
	})
}

// deleteExecution serves DELETE .../authentication/executions/{executionId}.
func (h *handler) deleteExecution(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	e, ok := h.executionFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.AuthenticationFlows().DeleteExecution(r.Context(), rc.realm.ID, e.ID); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// createExecution serves POST .../authentication/executions.
//
// It is the flow-alias-free spelling of `.../flows/{alias}/executions/execution`
// and takes the parent by **id** in the body rather than by alias in the path.
func (h *handler) createExecution(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body struct {
		Authenticator string `json:"authenticator"`
		ParentFlow    string `json:"parentFlow"`
		Requirement   string `json:"requirement"`
		Priority      int    `json:"priority"`
	}
	if !decodeStrict(w, r, "AuthenticationExecutionRepresentation", &body) {
		return
	}
	idx, ok := h.loadFlows(w, r, rc)
	if !ok {
		return
	}
	parent := idx.byID[body.ParentFlow]
	if parent == nil {
		httpx.WriteMessageError(w, http.StatusBadRequest, parentFlowMissing)
		return
	}
	if !knownAuthenticationProvider(body.Authenticator) {
		name := body.Authenticator
		if name == "" {
			name = "null"
		}
		httpx.WriteMessageError(w, http.StatusBadRequest, noAuthenticationProvider+name)
		return
	}
	requirement := body.Requirement
	if !validRequirement(requirement) {
		requirement = "DISABLED"
	}
	e := &model.AuthenticationExecution{
		ID:            model.NewID(),
		RealmID:       rc.realm.ID,
		ParentFlowID:  parent.ID,
		Authenticator: body.Authenticator,
		Requirement:   requirement,
		Priority:      body.Priority,
	}
	if err := h.store.AuthenticationFlows().CreateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/executions/"+e.ID)
	w.WriteHeader(http.StatusCreated)
}

// movePriority is raise-priority and lower-priority.
//
// **It swaps two rows' priorities with its neighbour rather than decrementing
// one.** Measured: three rows at 0, 1, 2, raising the middle one produced 0, 1,
// 2 again with the first two rows exchanged. Decrementing would produce a
// duplicate priority and an order nothing defines, and P8 §1.2 recorded the
// same rule for the required actions - the second family on this tag that works
// this way.
//
// A row already first (or last) is a 204 that changes nothing.
func (h *handler) movePriority(w http.ResponseWriter, r *http.Request, rc *reqContext, up bool) {
	e, ok := h.executionFromPath(w, r, rc)
	if !ok {
		return
	}
	repo := h.store.AuthenticationFlows()
	siblings, err := repo.ListExecutions(r.Context(), rc.realm.ID, e.ParentFlowID)
	if err != nil {
		h.flowInternalError(w)
		return
	}
	at := -1
	for i, s := range siblings {
		if s.ID == e.ID {
			at = i
			break
		}
	}
	other := at + 1
	if up {
		other = at - 1
	}
	if at < 0 || other < 0 || other >= len(siblings) {
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteNoContent(w, r)
		return
	}
	neighbour := siblings[other]
	e.Priority, neighbour.Priority = neighbour.Priority, e.Priority
	if err := repo.UpdateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	if err := repo.UpdateExecution(r.Context(), neighbour); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

func (h *handler) raiseExecutionPriority(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.movePriority(w, r, rc, true)
}

func (h *handler) lowerExecutionPriority(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.movePriority(w, r, rc, false)
}

// createExecutionConfig serves
// POST .../authentication/executions/{executionId}/config.
//
// **It is an upsert wearing a create's status code.** Posting a second config
// to an execution that already has one answers 201, repoints the row and
// **deletes the first** - a subsequent DELETE /config/{first id} answers 404.
// Measured in both directions.
//
// Its `Location` echoes its own creating path,
// `.../executions/{execId}/config/{cfgId}`, which is the second route on this
// tag to do so and the fifth create with a shape of its own.
func (h *handler) createExecutionConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body authenticatorConfigBody
	if !decodeStrict(w, r, "AuthenticatorConfigRepresentation", &body) {
		return
	}
	e, ok := h.executionFromPath(w, r, rc)
	if !ok {
		return
	}
	repo := h.store.AuthenticationFlows()
	previous := e.ConfigID
	c := &model.AuthenticationConfig{
		ID:      model.NewID(),
		RealmID: rc.realm.ID,
		Alias:   body.Alias,
		Config:  body.Config,
	}
	if err := repo.CreateConfig(r.Context(), c); err != nil {
		h.flowInternalError(w)
		return
	}
	e.ConfigID = c.ID
	if err := repo.UpdateExecution(r.Context(), e); err != nil {
		h.flowInternalError(w)
		return
	}
	if previous != "" {
		if err := repo.DeleteConfig(r.Context(), rc.realm.ID, previous); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			h.flowInternalError(w)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/executions/"+e.ID+"/config/"+c.ID)
	w.WriteHeader(http.StatusCreated)
}

// readExecutionConfig serves
// GET .../authentication/executions/{executionId}/config/{id}.
//
// **It does not check that the config belongs to the execution**, and the body
// is byte-identical to GET /config/{id}'s - measured on the same pair. So the
// `{executionId}` segment is resolved and then plays no part, which is why the
// two routes share one serialiser here where three other pairs on this tag do
// not.
func (h *handler) readExecutionConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.executionFromPath(w, r, rc); !ok {
		return
	}
	h.writeConfigByID(w, r, rc, r.PathValue("id"))
}

func (h *handler) writeConfigByID(w http.ResponseWriter, r *http.Request, rc *reqContext, id string) {
	c, err := h.store.AuthenticationFlows().ConfigByID(r.Context(), rc.realm.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusNotFound, authenticatorConfigNotFound)
		return
	}
	if err != nil {
		h.flowInternalError(w)
		return
	}
	writeAdminJSON(w, authenticatorConfigRepresentation{ID: c.ID, Alias: c.Alias, Config: c.Config})
}

// createConfig serves POST .../authentication/config.
//
// It creates a config attached to **no execution**, which is a row nothing can
// reach except by id. It is the deprecated create the description still carries
// and it is served as measured.
func (h *handler) createConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body authenticatorConfigBody
	if !decodeStrict(w, r, "AuthenticatorConfigRepresentation", &body) {
		return
	}
	c := &model.AuthenticationConfig{
		ID:      model.NewID(),
		RealmID: rc.realm.ID,
		Alias:   body.Alias,
		Config:  body.Config,
	}
	if err := h.store.AuthenticationFlows().CreateConfig(r.Context(), c); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+
		"/authentication/config/"+c.ID)
	w.WriteHeader(http.StatusCreated)
}

func (h *handler) readConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.writeConfigByID(w, r, rc, r.PathValue("id"))
}

// updateConfig serves PUT .../authentication/config/{id}. It replaces both the
// alias and the map rather than merging into either.
func (h *handler) updateConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body authenticatorConfigBody
	if !decodeStrict(w, r, "AuthenticatorConfigRepresentation", &body) {
		return
	}
	c, err := h.store.AuthenticationFlows().ConfigByID(r.Context(), rc.realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusNotFound, authenticatorConfigNotFound)
		return
	}
	if err != nil {
		h.flowInternalError(w)
		return
	}
	c.Alias = body.Alias
	c.Config = body.Config
	if err := h.store.AuthenticationFlows().UpdateConfig(r.Context(), c); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// deleteConfig serves DELETE .../authentication/config/{id}. The store clears
// the pointer on every execution holding it, so no row is left serving an
// `authenticationConfig` id that resolves to a 404.
func (h *handler) deleteConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	id := r.PathValue("id")
	if _, err := h.store.AuthenticationFlows().ConfigByID(r.Context(), rc.realm.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, authenticatorConfigNotFound)
			return
		}
		h.flowInternalError(w)
		return
	}
	if err := h.store.AuthenticationFlows().DeleteConfig(r.Context(), rc.realm.ID, id); err != nil {
		h.flowInternalError(w)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// sortedAliases is used by the tests to compare a realm's flow set without
// depending on the order two drivers happen to return.
func sortedAliases(rows []*model.AuthenticationFlow) []string {
	out := make([]string, 0, len(rows))
	for _, f := range rows {
		out = append(out, flowAliasOf(f))
	}
	sort.Strings(out)
	return out
}
