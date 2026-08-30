package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// requiredActionRepresentation is the body the required-action routes serve.
//
// Seven keys in the measured order, and **the two conditional ones are
// conditional in opposite ways** - which is the sort of thing one shared rule
// gets wrong:
//
//   - `alias` is plain omitempty. A row whose alias is the empty string, which
//     is what `PUT` with `{}` leaves behind, reads back with **no `alias` key
//     at all**.
//   - `name` is a **pointer**, because absent and empty are two different
//     measured answers here. A row registered with no `name` reads back without
//     the key; a row whose name was set to `""` reads back carrying
//     `"name":""`. omitempty on a string collapses those two into one.
//
// Two adjacent string keys on one body, opposite emptiness rules, both
// measured. Giving `alias` the pointer treatment or `name` the omitempty one
// puts a key in a body Keycloak leaves it out of, or the reverse.
//
// `config` is unconditional and `{}` when empty - model.StringMap marshals nil
// as `{}` for that reason. DELETE .../config was measured leaving
// `{"config":{}}` rather than removing the key.
type requiredActionRepresentation struct {
	Alias         string          `json:"alias,omitempty"`
	Name          *string         `json:"name,omitempty"`
	ProviderID    string          `json:"providerId"`
	Enabled       bool            `json:"enabled"`
	DefaultAction bool            `json:"defaultAction"`
	Priority      int             `json:"priority"`
	Config        model.StringMap `json:"config"`
}

// unregisteredRequiredAction is what GET .../unregistered-required-actions
// serves: **two** keys, not the seven above.
//
// The `name` is the SPI provider's own display name and **not** the deleted
// row's. Measured: a row renamed to "MY OWN NAME" and then deleted came back as
// "Linking Identity Provider", the name its provider carries.
type unregisteredRequiredAction struct {
	ProviderID string `json:"providerId"`
	Name       string `json:"name"`
}

// requiredActionConfigRepresentation is GET .../required-actions/{alias}/config.
// One key wrapping the map, which is why it is not model.StringMap directly.
type requiredActionConfigRepresentation struct {
	Config model.StringMap `json:"config"`
}

func requiredActionRepresentationOf(m *model.RequiredActionProvider) requiredActionRepresentation {
	return requiredActionRepresentation{
		Alias:         m.Alias,
		Name:          m.Name,
		ProviderID:    m.ProviderID,
		Enabled:       m.Enabled,
		DefaultAction: m.DefaultAction,
		Priority:      m.Priority,
		Config:        m.Config,
	}
}

// The four refusals this family spells for one alias. They are written out
// rather than shared because each is a different sentence for what looks like
// the same condition, and three of them are new spellings of not-found.
const (
	// requiredActionNotFound is what GET and PUT /required-actions/{alias}
	// answer. It has **no full stop**.
	requiredActionNotFound = "Failed to find required action"
	// requiredActionNotFoundStop is what DELETE and the two priority POSTs
	// answer for the same missing row. It has one. Two spellings of one
	// resource split by verb, which is the `Realm not found.` pattern a second
	// time - and the reason writeRequiredActionNotFound takes the sentence as
	// an argument instead of choosing it.
	requiredActionNotFoundStop = "Failed to find required action."
	// requiredActionNotConfigurable is the /config sub-resource's answer when
	// the path's alias is not a **configurable provider id**, and it is a
	// **400** where its parent route's miss is a 404.
	requiredActionNotConfigurable = "RequiredAction is not configurable"
	// requiredActionConfigNotFound is the same sub-resource's answer when the
	// alias *is* a configurable provider id and no row carries it.
	requiredActionConfigNotFound = "Could not find RequiredAction config"
	// requiredActionProviderNotFound is what
	// /required-actions/{alias}/config-description answers for an alias that is
	// not a configurable provider id - 404, where /config answers 400 to the
	// identical request.
	requiredActionProviderNotFound = "Could not find configurable RequiredAction provider"
)

// listRequiredActions serves GET .../authentication/required-actions.
//
// **Its role set is wider than every other read on this tag**, and that is
// measured across all 21 roles of the realm's own container: view-users and
// query-users get a 200 here and a 403 on each of its siblings. It is not the
// "200 with a shorter list to a weaker caller" pattern this API has three
// instances of - a query-users caller's body is byte-identical to a
// manage-realm caller's. See requiredActionsListReadRoles.
func (h *handler) listRequiredActions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rows, err := h.store.RequiredActions().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]requiredActionRepresentation, 0, len(rows))
	for _, m := range rows {
		out = append(out, requiredActionRepresentationOf(m))
	}
	writeAdminJSON(w, out)
}

// listUnregisteredRequiredActions serves
// GET .../authentication/unregistered-required-actions.
//
// It is `[]` on a default install and it is **not** a constant: deleting a
// required action puts its provider here, and POST /register-required-action
// takes it back out. Registration is tracked by **providerId**, not by alias -
// a row renamed to ZZZ still keeps its provider registered, measured.
func (h *handler) listUnregisteredRequiredActions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rows, err := h.store.RequiredActions().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	registered := make(map[string]bool, len(rows))
	for _, m := range rows {
		registered[m.ProviderID] = true
	}
	out := []unregisteredRequiredAction{}
	for _, p := range requiredActionProviders {
		if !registered[p.ProviderID] {
			out = append(out, unregisteredRequiredAction{ProviderID: p.ProviderID, Name: p.Name})
		}
	}
	writeAdminJSON(w, out)
}

// requiredActionFromPath resolves the {alias} segment, writing the 404 the
// caller's verb spells when it matches nothing.
func (h *handler) requiredActionFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext,
	message string) (*model.RequiredActionProvider, bool) {
	m, err := h.store.RequiredActions().ByAlias(r.Context(), rc.realm.ID, r.PathValue("alias"))
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusNotFound, message)
		return nil, false
	}
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return m, true
}

func (h *handler) readRequiredAction(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	m, ok := h.requiredActionFromPath(w, r, rc, requiredActionNotFound)
	if !ok {
		return
	}
	writeAdminJSON(w, requiredActionRepresentationOf(m))
}

// updateRequiredAction serves PUT .../authentication/required-actions/{alias}.
//
// Three measured surprises, all reproduced:
//
//   - **The body's alias wins.** A PUT addressed to UPDATE_PROFILE carrying
//     `{"alias":"ZZZ",...}` answered 204, made the old alias a 404 and the new
//     one a 200. This is the rename.
//   - **providerId is read off the wire and discarded.** The same body said
//     `"providerId":"XXX"` and the stored row kept UPDATE_PROFILE. The
//     assignment below is deliberately absent, and this is the **only** place
//     that decides it: the store writes every column it is given, so adding
//     `m.ProviderID = rep.ProviderID` here is enough to break the rule and is
//     therefore enough for a test to catch. It used to be enforced in the store
//     as well, and a mutation test found that the two guards made each other
//     invisible.
//   - **`{}` is a 204 that orphans the row.** Every field takes its zero value,
//     so the alias becomes "", the row leaves every alias-addressed route and
//     stays in the listing as a six-key object with no `alias` key at all. It
//     is Keycloak's own defect and it falls straight out of the two rules above
//     rather than being coded for.
//
// The decode runs **before** the alias is resolved: a PUT to an unknown alias
// carrying an unknown field answers the 400 below, not the 404.
func (h *handler) updateRequiredAction(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var rep requiredActionRepresentation
	if !decodeStrict(w, r, "RequiredActionProviderRepresentation", &rep) {
		return
	}
	m, ok := h.requiredActionFromPath(w, r, rc, requiredActionNotFound)
	if !ok {
		return
	}
	m.Alias = rep.Alias
	m.Name = rep.Name
	m.Enabled = rep.Enabled
	m.DefaultAction = rep.DefaultAction
	m.Priority = rep.Priority
	// config is written unfiltered here, and that is the difference from
	// PUT .../config, which drops keys the provider does not declare. One
	// field, two writers, one filter. Measured on the same key in both.
	m.Config = rep.Config
	if err := h.store.RequiredActions().Update(r.Context(), m); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// No Cache-Control: this verb and its DELETE sibling are the two operations
	// on the family measured without one, where the four others carry
	// `no-cache`. Pinned per endpoint, as AGENTS.md records.
	httpx.WriteNoContent(w, r)
}

func (h *handler) deleteRequiredAction(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	m, ok := h.requiredActionFromPath(w, r, rc, requiredActionNotFoundStop)
	if !ok {
		return
	}
	if err := h.store.RequiredActions().Delete(r.Context(), rc.realm.ID, m.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// requiredActionConfigTarget is the two-stage resolution the three /config
// verbs share, and it is not the resolution it looks like.
//
// The path's `{alias}` is used first as a **provider id** against the SPI's
// configurable required actions, and only then as a row alias. Measured by
// renaming CONFIGURE_TOTP's row to ZZZ:
//
//	ZZZ/config              400 RequiredAction is not configurable
//	ZZZ/config-description  404 Could not find configurable RequiredAction provider
//	CONFIGURE_TOTP/config              404 Could not find RequiredAction config
//	CONFIGURE_TOTP/config-description  200, with the properties, and no row exists
//
// So the sub-resource never follows the rename, and "resolve the row, then ask
// whether it is configurable" - the obvious implementation - gets all four of
// those wrong.
func (h *handler) requiredActionConfigTarget(w http.ResponseWriter, r *http.Request,
	rc *reqContext) (*model.RequiredActionProvider, bool) {
	alias := r.PathValue("alias")
	if _, ok := authProviders.RequiredActionProperties[alias]; !ok {
		httpx.WriteMessageError(w, http.StatusBadRequest, requiredActionNotConfigurable)
		return nil, false
	}
	return h.requiredActionFromPath(w, r, rc, requiredActionConfigNotFound)
}

func (h *handler) readRequiredActionConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	m, ok := h.requiredActionConfigTarget(w, r, rc)
	if !ok {
		return
	}
	writeAdminJSON(w, requiredActionConfigRepresentation{Config: m.Config})
}

// updateRequiredActionConfig serves PUT .../required-actions/{alias}/config.
//
// **It filters the config to the provider's declared property names**, where
// the representation's own PUT does not: `{"max_auth_age":"700","zzz":"nope"}`
// stored max_auth_age alone. A body with no `config` key at all is a 204 that
// clears it.
func (h *handler) updateRequiredActionConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var rep requiredActionConfigRepresentation
	if !decodeStrict(w, r, "RequiredActionConfigRepresentation", &rep) {
		return
	}
	m, ok := h.requiredActionConfigTarget(w, r, rc)
	if !ok {
		return
	}
	m.Config = declaredConfigOnly(m.ProviderID, rep.Config)
	if err := h.store.RequiredActions().Update(r.Context(), m); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

func (h *handler) deleteRequiredActionConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	m, ok := h.requiredActionConfigTarget(w, r, rc)
	if !ok {
		return
	}
	m.Config = nil
	if err := h.store.RequiredActions().Update(r.Context(), m); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// declaredConfigOnly drops the keys the provider does not declare, keeping the
// order the request sent the survivors in.
func declaredConfigOnly(providerID string, in model.StringMap) model.StringMap {
	declared := authProviders.RequiredActionProperties[providerID]
	names := make(map[string]bool, len(declared))
	for _, p := range declared {
		names[p.Name] = true
	}
	var out model.StringMap
	for _, pair := range in {
		if names[pair.Key] {
			out = append(out, pair)
		}
	}
	return out
}

// readRequiredActionConfigDescription serves
// GET .../required-actions/{alias}/config-description.
//
// The body is `{"properties":[...]}` and **nothing else** - it is not the
// four-key shape .../config-description/{providerId} serves. Two endpoints on
// one tag whose paths differ by a segment and whose bodies share one key.
//
// It answers 200 for any configurable provider id whether or not a row carries
// that alias, which is the second half of requiredActionConfigTarget's finding.
func (h *handler) readRequiredActionConfigDescription(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	props, ok := authProviders.RequiredActionProperties[r.PathValue("alias")]
	if !ok {
		httpx.WriteMessageError(w, http.StatusNotFound, requiredActionProviderNotFound)
		return
	}
	writeAdminJSON(w, requiredActionConfigDescription{Properties: nonNilProperties(props)})
}

// raiseRequiredActionPriority and lowerRequiredActionPriority serve the two
// POSTs.
//
// **They swap the two rows' priority values**; they do not decrement. Measured
// on a non-adjacent pair: UPDATE_PASSWORD 57 and CONFIGURE_TOTP 54 became 54
// and 57. Raising the first row and lowering the last are both 204 and change
// nothing.
func (h *handler) raiseRequiredActionPriority(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.swapRequiredActionPriority(w, r, rc, -1)
}

func (h *handler) lowerRequiredActionPriority(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	h.swapRequiredActionPriority(w, r, rc, 1)
}

func (h *handler) swapRequiredActionPriority(w http.ResponseWriter, r *http.Request, rc *reqContext, step int) {
	m, ok := h.requiredActionFromPath(w, r, rc, requiredActionNotFoundStop)
	if !ok {
		return
	}
	rows, err := h.store.RequiredActions().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	at := -1
	for i, row := range rows {
		if row.ID == m.ID {
			at = i
			break
		}
	}
	// A row at either end has no neighbour to trade with, and that is a 204
	// rather than an error - measured on both ends.
	if next := at + step; at >= 0 && next >= 0 && next < len(rows) {
		a, b := rows[at], rows[next]
		a.Priority, b.Priority = b.Priority, a.Priority
		if err := h.store.RequiredActions().Update(r.Context(), a); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if err := h.store.RequiredActions().Update(r.Context(), b); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// registerRequiredActionRequest is POST .../authentication/register-required-action.
//
// Name is a pointer for requiredActionRepresentation's reason: the body's name
// is honoured verbatim, and a body without one produces a row whose
// representation has six keys.
type registerRequiredActionRequest struct {
	ProviderID string  `json:"providerId"`
	Name       *string `json:"name"`
}

// registerRequiredAction puts an unregistered provider back.
//
// **This endpoint is not strict**, where both PUTs on the family are: an
// unknown field alongside a good providerId answered 204 rather than the
// Jackson 400. Three write endpoints on one tag, two strict decoders and one
// lax one.
//
// The new row lands at max(priority)+1 with enabled true and defaultAction
// false, all measured. An empty body is a 500 - the same family as an empty
// body on POST /users.
func (h *handler) registerRequiredAction(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !requireJSONBody(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeCannotParseJSON(w, body)
		return
	}
	var req registerRequiredActionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeCannotParseJSON(w, body)
		return
	}
	if !knownRequiredActionProvider(req.ProviderID) {
		httpx.WriteMessageError(w, http.StatusBadRequest,
			"Required Action Provider with given providerId not found")
		return
	}
	rows, err := h.store.RequiredActions().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	top := 0
	for _, row := range rows {
		if row.ProviderID == req.ProviderID {
			// The 409 is the RFC 6749 shape, not the errorMessage one.
			httpx.WriteOAuthError(w, http.StatusConflict, "conflict",
				"A Required Action Provider with given alias already exists.")
			return
		}
		if row.Priority > top {
			top = row.Priority
		}
	}
	m := &model.RequiredActionProvider{
		ID:         model.NewID(),
		RealmID:    rc.realm.ID,
		Alias:      req.ProviderID,
		Name:       req.Name,
		ProviderID: req.ProviderID,
		Enabled:    true,
		Priority:   top + 1,
	}
	if err := h.store.RequiredActions().Create(r.Context(), m); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}
