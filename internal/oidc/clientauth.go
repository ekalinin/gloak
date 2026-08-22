package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// clientAuthError is a client authentication failure, carrying the exact
// OAuth error the endpoint has to report.
type clientAuthError struct {
	Code        string
	Description string
	Status      int
}

// write emits the failure in the RFC 6749 shape the token, introspection and
// revocation endpoints all use for it.
func (e *clientAuthError) write(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, e.Status, e.Code, e.Description)
}

// The two measured failures. They carry different codes and *identical*
// descriptions: an unknown client is invalid_client, a known client presenting
// the wrong secret is unauthorized_client. Collapsing them into one is a
// compatibility break, not a tidy-up - AGENTS.md lists it among the things
// that look like bugs and are not.
//
// Measured in internal/conformance/testdata/golden/oidc/token/unknown-client.http
// and .../oidc/token/wrong-client-secret.http.
var (
	errInvalidClient = &clientAuthError{
		Code:        "invalid_client",
		Description: "Invalid client or Invalid client credentials",
		Status:      http.StatusUnauthorized,
	}
	errUnauthorizedClient = &clientAuthError{
		Code:        "unauthorized_client",
		Description: "Invalid client or Invalid client credentials",
		Status:      http.StatusUnauthorized,
	}
)

// authenticateClient resolves and authenticates the client a request speaks
// for. Credentials arrive either as client_id/client_secret form fields or as
// HTTP Basic; the form wins when both are present, which is what Keycloak's
// own clients send.
//
// A public client authenticates on its client_id alone. A confidential client
// must present a secret matching the stored one - and a confidential client
// whose stored secret is empty can never authenticate, whatever is presented.
// broker and master-realm are bootstrapped exactly that way, so a plain
// "presented == stored" comparison would let anybody in by sending nothing.
func (h *handler) authenticateClient(ctx context.Context, realm *model.Realm, form url.Values, header http.Header) (*model.Client, *clientAuthError) {
	clientID, secret := clientCredentials(form, header)
	if clientID == "" {
		return nil, errInvalidClient
	}

	client, err := h.store.Clients().ByClientID(ctx, realm.ID, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errInvalidClient
		}
		return nil, errInvalidClient
	}
	if !client.Enabled {
		return nil, errInvalidClient
	}
	if client.PublicClient {
		return client, nil
	}
	if client.Secret == "" {
		return nil, errUnauthorizedClient
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(client.Secret)) != 1 {
		return nil, errUnauthorizedClient
	}
	return client, nil
}

// clientCredentials reads the client's identity from the form, falling back to
// HTTP Basic. The two are the credential forms RFC 6749 defines; Keycloak
// accepts both on every endpoint measured so far.
func clientCredentials(form url.Values, header http.Header) (id, secret string) {
	if v := form.Get("client_id"); v != "" {
		return v, form.Get("client_secret")
	}
	req := &http.Request{Header: header}
	if user, pass, ok := req.BasicAuth(); ok {
		return user, pass
	}
	return "", ""
}
