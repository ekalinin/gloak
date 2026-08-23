package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// userRepresentation is Keycloak's UserRepresentation in the field order
// measured on GET .../clients/{client-uuid}/service-account-user.
//
// It carries the nine fields that response carries and no more. The full
// representation has others - email, firstName, lastName, attributes - and
// where they sit in the order is not measured yet, because a service account
// has none of them. Putting them in a guessed position is the kind of mistake
// only a byte comparison finds, so they wait for the recording that shows one.
//
// **There is no access block here**, and that is measured rather than an
// omission: the same user fetched through GET /users/{id} carries a six-key
// access block and through GET /users a one-key one. Three serialisations of
// one object, so a single shared user serialiser would be wrong twice.
type userRepresentation struct {
	ID                         string   `json:"id"`
	Username                   string   `json:"username"`
	EmailVerified              bool     `json:"emailVerified"`
	Enabled                    bool     `json:"enabled"`
	CreatedTimestamp           int64    `json:"createdTimestamp"`
	TOTP                       bool     `json:"totp"`
	DisableableCredentialTypes []string `json:"disableableCredentialTypes"`
	RequiredActions            []string `json:"requiredActions"`
	NotBefore                  int      `json:"notBefore"`
}

// readServiceAccountUser serves GET .../clients/{client-uuid}/service-account-user.
//
// A client without service accounts answers 400, not 404, and the message
// names the clientId in single quotes rather than the UUID the request used.
func (h *handler) readServiceAccountUser(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	if !client.ServiceAccountsEnabled {
		httpx.WriteMessageError(w, http.StatusBadRequest,
			"Service account not enabled for the client '"+client.ClientID+"'")
		return
	}
	user, err := h.ensureServiceAccount(r.Context(), rc.realm.ID, client)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, userRepresentation{
		ID:                         user.ID,
		Username:                   user.Username,
		EmailVerified:              user.EmailVerified,
		Enabled:                    user.Enabled,
		CreatedTimestamp:           user.CreatedTimestamp,
		DisableableCredentialTypes: []string{},
		RequiredActions:            []string{},
	})
}

// ensureServiceAccount returns the account a service-account client acts as,
// creating it if it is not there yet.
//
// Measured: the account exists as soon as the client does. A GET on
// service-account-user immediately after a create answers 200 with no token
// grant in between, and switching serviceAccountsEnabled on through PUT
// creates it too. That is why createClient and updateClient call this rather
// than leaving it to the first client_credentials grant.
//
// internal/oidc creates the same account on demand during that grant, and both
// paths stay. This one is what the admin API observes; that one covers every
// client that never went through the admin API - the six bootstrap makes, and
// every client a test builds straight through the store.
func (h *handler) ensureServiceAccount(ctx context.Context, realmID string, c *model.Client) (*model.User, error) {
	username := model.ServiceAccountUsername(c.ClientID)
	user, err := h.store.Users().ByUsername(ctx, realmID, username)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	user = &model.User{
		ID:               model.NewID(),
		RealmID:          realmID,
		Username:         username,
		Enabled:          true,
		CreatedTimestamp: time.Now().UnixMilli(),
	}
	if err := h.store.Users().Create(ctx, user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return h.store.Users().ByUsername(ctx, realmID, username)
		}
		return nil, err
	}
	return user, nil
}
