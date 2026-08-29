package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// clientScopeRepresentation is the body the Client Scopes tag serves.
//
// Field order is the measured serialisation order. Four of the five keys are
// unconditional and the fifth is not:
//
//   - description carries omitempty because a scope created without one has no
//     `description` key at all.
//   - attributes does **not**: an attribute-less scope reads back
//     `"attributes":{}`. model.StringMap marshals nil as `{}` for that reason.
//   - protocolMappers carries omitempty because `offline_access` - the one
//     bootstrapped scope with no mappers - reads back with **five** keys where
//     every other scope reads back with six. Serialising `[]` there is the
//     tidy-up that breaks it.
type clientScopeRepresentation struct {
	ID              string                         `json:"id"`
	Name            string                         `json:"name"`
	Description     string                         `json:"description,omitempty"`
	Protocol        string                         `json:"protocol,omitempty"`
	Attributes      model.StringMap                `json:"attributes"`
	ProtocolMappers []protocolMapperRepresentation `json:"protocolMappers,omitempty"`
}

// protocolMapperRepresentation is one entry of the array above. Nothing writes
// one yet - the Protocol Mappers tag is P5's next cut - so this exists to serve
// what bootstrap stored rather than to be decoded from a request.
type protocolMapperRepresentation struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Protocol        string          `json:"protocol"`
	ProtocolMapper  string          `json:"protocolMapper"`
	ConsentRequired bool            `json:"consentRequired"`
	Config          model.StringMap `json:"config"`
}

// briefClientScopeRepresentation is what the **realm's** two default listings
// serve: three keys, no attributes and no mappers.
type briefClientScopeRepresentation struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol,omitempty"`
}

// clientBriefClientScopeRepresentation is what a **client's** two listings
// serve: two keys. It is not briefClientScopeRepresentation with an empty
// protocol - the key is absent altogether, on scopes whose protocol is set.
//
// Three shapes of one object, and which one you get is decided by the route.
// One shared serialiser would be wrong on two of them.
type clientBriefClientScopeRepresentation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func clientScopeRepresentationOf(m *model.ClientScope) clientScopeRepresentation {
	rep := clientScopeRepresentation{
		ID:          m.ID,
		Name:        m.Name,
		Description: m.Description,
		Protocol:    m.Protocol,
		Attributes:  m.Attributes,
	}
	for _, pm := range m.ProtocolMappers {
		rep.ProtocolMappers = append(rep.ProtocolMappers, protocolMapperRepresentation{
			ID:              pm.ID,
			Name:            pm.Name,
			Protocol:        pm.Protocol,
			ProtocolMapper:  pm.ProtocolMapper,
			ConsentRequired: pm.ConsentRequired,
			Config:          pm.Config,
		})
	}
	return rep
}

// listClientScopes serves GET /admin/realms/{realm}/client-scopes and its
// client-templates spelling.
//
// The result is filtered by what the caller may see rather than gated on it:
// measured, query-clients gets **200 and `[]`** where view-clients and
// manage-clients get all fifteen. That is the client listing's shape, and the
// third time this API has answered a weaker caller with a shorter list instead
// of a refusal.
func (h *handler) listClientScopes(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	scopes, err := h.store.ClientScopes().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := make([]clientScopeRepresentation, 0, len(scopes))
	if maySeeClientScopes(rc.caller) {
		for _, sc := range scopes {
			out = append(out, clientScopeRepresentationOf(sc))
		}
	}
	writeAdminJSON(w, out)
}

// maySeeClientScopes is the read half of the coarse gate. The gate itself
// (clientsReadRoles) admits query-clients so the request reaches the handler;
// this is what empties its body.
func maySeeClientScopes(c *caller) bool {
	return c.has("view-clients") || c.has("manage-clients")
}

// readClientScope serves GET /admin/realms/{realm}/client-scopes/{id}.
func (h *handler) readClientScope(w http.ResponseWriter, r *http.Request, rc *reqContext, sc *model.ClientScope) {
	if !maySeeClientScopes(rc.caller) {
		writeForbidden(w)
		return
	}
	writeAdminJSON(w, clientScopeRepresentationOf(sc))
}

// createClientScope serves POST /admin/realms/{realm}/client-scopes.
//
// Five rejections, measured, and the order between them is measured too:
//
//	{}                                 500 unknown_error
//	{"protocol":"openid-connect"}      500 unknown_error
//	{"name":"x"}                       400 {"errorMessage":"Unexpected protocol"}
//	{"name":"x","protocol":"bogus"}    400 the same message - an absent protocol
//	                                       and an invalid one are one answer
//	{"name":"","protocol":"..."}       400 {"errorMessage":"Unexpected name \"\" for ClientScope"}
//
// An **absent** name is a 500 whatever else the body says - Keycloak's own
// defect, reproduced, the same family as an empty body on POST /users. A
// **present and empty** name is a 400, and it is checked *after* the protocol.
// So `name` is looked at twice with the protocol check between the two halves,
// which is why `{}` answers about the name and `{"name":"x"}` answers about the
// protocol. Collapsing the two name checks into one puts the wrong message on
// one of those two bodies whichever side of the protocol check it lands.
func (h *handler) createClientScope(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeClientScope(w, r)
	if !ok {
		return
	}
	if rep.Name == nil {
		writeClientScopeUnknownError(w)
		return
	}
	if !knownProtocol(rep.Protocol) {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Unexpected protocol")
		return
	}
	if *rep.Name == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			`Unexpected name "" for ClientScope`)
		return
	}

	m := &model.ClientScope{
		ID:          rep.ID,
		RealmID:     rc.realm.ID,
		Name:        *rep.Name,
		Description: rep.Description,
		Protocol:    rep.Protocol,
		Attributes:  rep.Attributes,
	}
	// The body's id wins when it carries one. Measured: a POST naming
	// "11111111-1111-1111-1111-111111111111" created a scope with exactly that
	// id and put it in the Location header. Minting one regardless is the
	// obvious implementation and it is wrong.
	if m.ID == "" {
		m.ID = model.NewID()
	}
	if err := h.store.ClientScopes().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeClientScopeConflict(w, m.Name)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// Unlike POST /clients, this 201 carries Cache-Control: no-cache. Two
	// creates on one API, one with the header and one without; it is pinned per
	// endpoint like every other Cache-Control on this API.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location",
		h.issuerBase+"/admin/realms/"+rc.realm.Name+"/client-scopes/"+m.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateClientScope serves PUT /admin/realms/{realm}/client-scopes/{id}.
//
// It **merges**, like a client and unlike a role: a PUT carrying only `name`
// keeps the description and the attributes, and a PUT carrying
// `"attributes":{}` does not clear them. It can change the protocol, which the
// create path validates and this one is measured accepting. A body with no
// `name` is the same 500 the create answers.
func (h *handler) updateClientScope(w http.ResponseWriter, r *http.Request, rc *reqContext, sc *model.ClientScope) {
	if !rc.caller.has("manage-clients") {
		writeForbidden(w)
		return
	}
	rep, ok := decodeClientScope(w, r)
	if !ok {
		return
	}
	if rep.Name == nil {
		writeClientScopeUnknownError(w)
		return
	}

	sc.Name = *rep.Name
	if rep.Description != "" {
		sc.Description = rep.Description
	}
	if rep.Protocol != "" {
		sc.Protocol = rep.Protocol
	}
	for _, p := range rep.Attributes {
		sc.Attributes.Set(p.Key, p.Value)
	}

	if err := h.store.ClientScopes().Update(r.Context(), sc); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeClientScopeConflict(w, sc.Name)
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeClientScopeNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteClientScope serves DELETE /admin/realms/{realm}/client-scopes/{id}.
//
// The 204 carries Cache-Control: no-cache where the update's does not - the
// same per-endpoint split every other delete/update pair on this API shows.
// The row's cascades take the scope out of the realm's default sets and out of
// every client's, which is measured: deleting a scope that was both left both
// listings without it.
func (h *handler) deleteClientScope(w http.ResponseWriter, r *http.Request, rc *reqContext, sc *model.ClientScope) {
	if !rc.caller.has("manage-clients") {
		writeForbidden(w)
		return
	}
	if err := h.store.ClientScopes().Delete(r.Context(), rc.realm.ID, sc.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientScopeNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// clientScopeRequest is the decode target for the two writes.
//
// Name is a *string because an absent name and an empty one answer differently:
// absent is a 500 and `""` is a 400 naming the empty string. Nothing else on
// this body needs the distinction.
type clientScopeRequest struct {
	ID          string          `json:"id"`
	Name        *string         `json:"name"`
	Description string          `json:"description"`
	Protocol    string          `json:"protocol"`
	Attributes  model.StringMap `json:"attributes"`
}

func decodeClientScope(w http.ResponseWriter, r *http.Request) (clientScopeRequest, bool) {
	var rep clientScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return rep, false
	}
	return rep, true
}

// knownProtocol is the set a client scope's protocol may take. Measured: an
// absent protocol and "bogus" both answer "Unexpected protocol", so the check
// is membership rather than presence.
func knownProtocol(p string) bool {
	return p == "openid-connect" || p == "saml"
}

// writeClientScopeNotFound is the 404 the /client-scopes/{id} routes answer.
//
// "Could not find client scope" - and its sibling below is "Client scope not
// found", for the same missing object. Which one you get is decided by the
// route that went looking, exactly as one missing group has three spellings.
func writeClientScopeNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find client scope")
}

// writePlainClientScopeNotFound is the 404 the realm's default-scope routes and
// a client's scope routes answer for the very same missing scope.
func writePlainClientScopeNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Client scope not found")
}

// writeClientScopeUnknownError is the 500 both writes answer for a body with no
// `name` key at all. It is the RFC 6749 shape on the admin API, which is the
// fourth of the four error shapes this project reproduces.
func writeClientScopeUnknownError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

func writeClientScopeConflict(w http.ResponseWriter, name string) {
	httpx.WriteAdminError(w, http.StatusConflict, "Client Scope "+name+" already exists")
}

// listRealmDefaultScopes serves GET .../default-default-client-scopes and
// GET .../default-optional-client-scopes.
//
// Nine and five on a pristine realm, not six and five: the three saml scopes
// are in the realm's default set and are filtered out only when an
// openid-connect client inherits from it.
func (h *handler) listRealmDefaultScopes(defaultScope bool) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		if !maySeeClientScopes(rc.caller) {
			writeForbidden(w)
			return
		}
		scopes, err := h.store.ClientScopes().ListRealmDefaults(r.Context(), rc.realm.ID, defaultScope)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out := make([]briefClientScopeRepresentation, 0, len(scopes))
		for _, sc := range scopes {
			out = append(out, briefClientScopeRepresentation{
				ID: sc.ID, Name: sc.Name, Protocol: sc.Protocol,
			})
		}
		writeAdminJSON(w, out)
	}
}

// addRealmDefaultScope serves PUT .../default-{default,optional}-client-scopes/{id}.
//
// **Not idempotent**, where the client-level PUT beside it is: putting the same
// scope twice answers 409, and so does putting into one list a scope already in
// the other. That is what says the realm's two sets are one row carrying a
// flag, and it is the opposite of PUT .../default-groups/{groupId}, which is
// idempotent.
func (h *handler) addRealmDefaultScope(defaultScope bool) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		sc, ok := h.realmScopeFromPath(w, r, rc)
		if !ok {
			return
		}
		err := h.store.ClientScopes().AddRealmDefault(r.Context(), rc.realm.ID, sc.ID, defaultScope)
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
			return
		}
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteNoContent(w, r)
	}
}

// removeRealmDefaultScope serves DELETE .../default-{default,optional}-client-scopes/{id}.
//
// It **ignores which list its path names**. Measured: DELETE
// .../default-default-client-scopes/{id} removed a scope that was in the realm's
// *optional* list. So there is no defaultScope argument here, and adding one to
// make the two verbs symmetrical is the tidy-up that would break it.
//
// A scope that is in neither list answers 204; a scope that does not exist
// answers 404.
func (h *handler) removeRealmDefaultScope(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	sc, ok := h.realmScopeFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.ClientScopes().RemoveRealmDefault(r.Context(), rc.realm.ID, sc.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// realmScopeFromPath resolves {clientScopeId} for the realm's two write routes,
// **after** the manage-clients check the router applied.
//
// The ordering is measured and it is not the one /client-scopes/{id} uses: a
// view-clients caller naming a scope that does not exist gets 403 here and 404
// there. Two neighbouring families, one missing object, opposite answers.
func (h *handler) realmScopeFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.ClientScope, bool) {
	sc, err := h.store.ClientScopes().ByID(r.Context(), rc.realm.ID, r.PathValue("clientScopeID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writePlainClientScopeNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return sc, true
}

// listClientClientScopes serves GET /clients/{uuid}/{default,optional}-client-scopes.
//
// Two keys per entry, not the realm listing's three: the protocol is absent
// here on scopes that have one.
func (h *handler) listClientClientScopes(defaultScope bool) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		client, ok := h.clientFromPath(w, r, rc)
		if !ok {
			return
		}
		if !maySeeClientScopes(rc.caller) {
			writeForbidden(w)
			return
		}
		scopes, err := h.store.ClientScopes().ListClientScopes(r.Context(), client.ID, defaultScope)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		out := make([]clientBriefClientScopeRepresentation, 0, len(scopes))
		for _, sc := range scopes {
			out = append(out, clientBriefClientScopeRepresentation{ID: sc.ID, Name: sc.Name})
		}
		writeAdminJSON(w, out)
	}
}

// addClientClientScope serves PUT /clients/{uuid}/{default,optional}-client-scopes/{id}.
//
// Idempotent and silent, where the realm's PUT is a 409 on the repeat. Three
// measured no-ops that all answer 204: attaching a scope the client already
// holds in this list, attaching one it holds in the **other** list - which does
// not move it - and attaching one whose protocol is not the client's.
//
// The order of the three checks is measured. The client is resolved before the
// manage-clients check and the scope after it: a view-clients caller naming an
// unknown client gets 404 "Could not find client" and the same caller naming a
// known client and an unknown scope gets 403.
func (h *handler) addClientClientScope(defaultScope bool) func(http.ResponseWriter, *http.Request, *reqContext) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqContext) {
		client, sc, ok := h.clientAndScopeFromPath(w, r, rc)
		if !ok {
			return
		}
		if bootstrap.ScopeMatchesProtocol(sc, client.Protocol) {
			if err := h.store.ClientScopes().AddClientScope(r.Context(), client.ID, sc.ID, defaultScope); err != nil {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		httpx.WriteNoContent(w, r)
	}
}

// removeClientClientScope serves DELETE
// /clients/{uuid}/{default,optional}-client-scopes/{id}, and like the realm's
// delete it ignores which list its path names.
func (h *handler) removeClientClientScope(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, sc, ok := h.clientAndScopeFromPath(w, r, rc)
	if !ok {
		return
	}
	if err := h.store.ClientScopes().RemoveClientScope(r.Context(), client.ID, sc.ID); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteNoContent(w, r)
}

// clientAndScopeFromPath resolves the client, checks manage-clients, then
// resolves the scope - in that order, because that is the order the three
// answers were measured in.
func (h *handler) clientAndScopeFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, *model.ClientScope, bool) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return nil, nil, false
	}
	if !rc.caller.has("manage-clients") {
		writeForbidden(w)
		return nil, nil, false
	}
	sc, ok := h.realmScopeFromPath(w, r, rc)
	if !ok {
		return nil, nil, false
	}
	return client, sc, true
}
