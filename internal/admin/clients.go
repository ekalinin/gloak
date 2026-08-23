package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

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
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	writeAdminJSON(w, clientRepresentationOf(client, rc.caller, rc.realm.Name))
}

// clientFromPath resolves the {client-uuid} segment, writing the measured 404
// and returning false when there is no such client.
//
// Every operation nested under a client answers that same 404 for an unknown
// UUID - the secret endpoints and service-account-user were measured doing so -
// so the lookup is shared rather than repeated per handler.
func (h *handler) clientFromPath(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.Client, bool) {
	client, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeClientNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return client, true
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
	// Measured: every client created through this endpoint gains both
	// attributes, public or not, but only a non-public one gains a secret. A
	// public client ends up with a creation time and nothing created, which is
	// why the two are not set together.
	m.Attributes["realm_client"] = "false"
	m.Attributes["client.secret.creation.time"] = strconv.FormatInt(time.Now().Unix(), 10)
	if !m.PublicClient {
		m.Secret = model.NewSecret()
	}

	if err := h.store.Clients().Create(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			httpx.WriteAdminError(w, http.StatusConflict,
				"Client "+rep.ClientID+" already exists")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if m.ServiceAccountsEnabled {
		if _, err := h.ensureServiceAccount(r.Context(), rc.realm, m); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
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
	// Measured: switching serviceAccountsEnabled on through this endpoint
	// creates the account, so the next read of service-account-user finds one.
	if updated.ServiceAccountsEnabled {
		if _, err := h.ensureServiceAccount(r.Context(), rc.realm, updated); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// deleteClient serves DELETE /admin/realms/{realm}/clients/{client-uuid}.
//
// Measured: 204 carrying Cache-Control: no-cache and omitting X-Frame-Options.
// Update's 204 next door has neither peculiarity. The omission turned out to
// belong to every successful DELETE rather than to this response - see
// httpx.WriteNoContent - while the Cache-Control does not: three of
// the four measured DELETEs carry it and one does not.
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
	httpx.WriteNoContent(w, r)
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
		Description:               rep.Description,
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
