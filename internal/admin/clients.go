package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// listClients serves GET /admin/realms/{realm}/clients.
//
// The clientId query parameter filters to an exact match, which is how a
// caller finds a client's internal UUID - the admin API addresses clients by
// UUID everywhere else, and that UUID is minted by the server.
func (h *handler) listClients(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	clients, err := h.store.Clients().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	wanted := r.URL.Query().Get("clientId")
	out := make([]clientRepresentation, 0, len(clients))
	for _, c := range clients {
		if wanted != "" && c.ClientID != wanted {
			continue
		}
		out = append(out, clientRepresentationOf(c, rc.caller, rc.realm.Name))
	}
	writeAdminJSON(w, out)
}

// readClient serves GET /admin/realms/{realm}/clients/{client-uuid}.
func (h *handler) readClient(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, clientRepresentationOf(client, rc.caller, rc.realm.Name))
}

// createClient serves POST /admin/realms/{realm}/clients.
//
// Measured: 201 with an empty body, no Content-Type at all, and the new
// object's absolute URL in Location. A conflicting clientId answers 409 with
// the errorMessage shape, not the OAuth one.
func (h *handler) createClient(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, ok := decodeClient(w, r)
	if !ok {
		return
	}
	if rep.ClientID == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Client ID is missing")
		return
	}

	m := newClientFrom(rep, rc.realm.ID)
	if err := h.store.Clients().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteAdminError(w, http.StatusConflict,
				"Client "+rep.ClientID+" already exists")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// Absolute, including the host the request arrived on, which is what the
	// recording shows and what a client follows.
	w.Header().Set("Location", h.issuerBase+"/admin/realms/"+rc.realm.Name+"/clients/"+m.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateClient serves PUT /admin/realms/{realm}/clients/{client-uuid}.
//
// Measured: 204 with no body and, unlike delete, no Cache-Control.
//
// The body is merged rather than replacing: it is unmarshalled *over* the
// client's current representation, so a field the caller omitted keeps its
// stored value. Replacing wholesale would silently blank every field a partial
// update left out.
//
// Unmeasured: whether Keycloak merges or replaces the attributes map when the
// body carries one. Unmarshalling into a non-nil map merges keys, which is
// what happens here.
func (h *handler) updateClient(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	current, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	merged := clientRepresentationOf(current, rc.caller, rc.realm.Name)
	if err := json.NewDecoder(r.Body).Decode(&merged); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return
	}

	updated := newClientFrom(merged, rc.realm.ID)
	// Identity is not the caller's to change through this endpoint.
	updated.ID = current.ID
	updated.Secret = current.Secret
	if err := h.store.Clients().Update(r.Context(), updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteClient serves DELETE /admin/realms/{realm}/clients/{client-uuid}.
//
// Measured: 204 carrying Cache-Control: no-cache and **omitting
// X-Frame-Options**, which makes it the third exception to the five security
// headers, after the unmatched-path 404 and userinfo. Update's 204 next door
// has neither peculiarity, so this is not a "204 on the admin API" rule.
func (h *handler) deleteClient(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	err := h.store.Clients().Delete(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Del("X-Frame-Options")
	w.WriteHeader(http.StatusNoContent)
}

// decodeClient reads a ClientRepresentation from the request body, writing the
// measured admin-API parse failure and returning false when it cannot.
func decodeClient(w http.ResponseWriter, r *http.Request) (clientRepresentation, bool) {
	var rep clientRepresentation
	if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
		return rep, false
	}
	return rep, true
}

// newClientFrom turns a representation into a stored client, filling the
// defaults Keycloak applies to a client created with a minimal body.
func newClientFrom(rep clientRepresentation, realmID string) *model.Client {
	m := &model.Client{
		ID:                        rep.ID,
		RealmID:                   realmID,
		ClientID:                  rep.ClientID,
		Name:                      rep.Name,
		RootURL:                   rep.RootURL,
		BaseURL:                   rep.BaseURL,
		Enabled:                   rep.Enabled,
		PublicClient:              rep.PublicClient,
		Protocol:                  rep.Protocol,
		ClientAuthenticatorType:   rep.ClientAuthenticatorType,
		SurrogateAuthRequired:     rep.SurrogateAuthRequired,
		AlwaysDisplayInConsole:    rep.AlwaysDisplayInConsole,
		BearerOnly:                rep.BearerOnly,
		ConsentRequired:           rep.ConsentRequired,
		StandardFlowEnabled:       rep.StandardFlowEnabled,
		ImplicitFlowEnabled:       rep.ImplicitFlowEnabled,
		DirectAccessGrantsEnabled: rep.DirectAccessGrantsEnabled,
		ServiceAccountsEnabled:    rep.ServiceAccountsEnabled,
		FrontchannelLogout:        rep.FrontchannelLogout,
		FullScopeAllowed:          rep.FullScopeAllowed,
		NotBefore:                 rep.NotBefore,
		NodeReRegistrationTimeout: rep.NodeReRegistrationTimeout,
		RedirectURIs:              nonNil(rep.RedirectURIs),
		WebOrigins:                nonNil(rep.WebOrigins),
		DefaultClientScopes:       nonNil(rep.DefaultClientScopes),
		OptionalClientScopes:      nonNil(rep.OptionalClientScopes),
		Attributes:                nonNilMap(rep.Attributes),
	}
	if m.ID == "" {
		m.ID = model.NewID()
	}
	if m.ClientAuthenticatorType == "" {
		m.ClientAuthenticatorType = "client-secret"
	}
	return m
}

// writeClientNotFound emits the measured 404 for a client that does not exist.
//
// The message differs from the user one - "Could not find client" against
// "User not found" - and from the realm one, which alone ends in a full stop.
// A shared not-found helper would get two of the three wrong.
func writeClientNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Could not find client")
}

// writeAdminJSON writes an admin API success body.
//
// Measured on the client endpoints: the success carries a charset on its
// Content-Type and a Cache-Control, while the 404 beside it carries plain
// application/json and no Cache-Control. That is the same split already
// measured on GET /realms/{realm}, so it is not a client-endpoint quirk.
func writeAdminJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, body)
}
