package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// newHandler builds a handler over a freshly bootstrapped master realm, which
// is the state every conformance fixture starts from.
func newHandler(t *testing.T) (*handler, store.Store, *model.Realm) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	return &handler{store: s, keys: keys.NewManager(s), issuerBase: "http://localhost:8080"}, s, realm
}

func TestAuthenticateClientAcceptsAPublicClientWithNoSecret(t *testing.T) {
	// admin-cli is public, which is why the measured password grant carries no
	// client_secret at all.
	h, _, realm := newHandler(t)

	client, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{"client_id": {"admin-cli"}}, http.Header{})

	if authErr != nil {
		t.Fatalf("want admin-cli to authenticate, got %+v", authErr)
	}
	if client.ClientID != "admin-cli" {
		t.Fatalf("wrong client: %q", client.ClientID)
	}
}

func TestAuthenticateClientRejectsAnUnknownClientAsInvalidClient(t *testing.T) {
	// Measured: internal/conformance/testdata/golden/oidc/token/unknown-client.http
	h, _, realm := newHandler(t)

	_, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{"client_id": {"nosuchclient"}}, http.Header{})

	assertAuthError(t, authErr, "invalid_client", 401)
}

func TestAuthenticateClientRejectsAWrongSecretAsUnauthorizedClient(t *testing.T) {
	// Measured: .../oidc/token/wrong-client-secret.http. Different code from
	// the unknown-client case, identical description.
	h, _, realm := newHandler(t)

	_, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{"client_id": {"broker"}, "client_secret": {"wrong-secret"}}, http.Header{})

	assertAuthError(t, authErr, "unauthorized_client", 401)
	if authErr.Description != errInvalidClient.Description {
		t.Fatalf("the two failures must share one description, got %q", authErr.Description)
	}
}

func TestAuthenticateClientRejectsAnEmptySecretOnAConfidentialClient(t *testing.T) {
	// broker and master-realm are bootstrapped confidential with an empty
	// stored secret. A plain "presented == stored" comparison would let anybody
	// authenticate as either of them by sending nothing.
	h, _, realm := newHandler(t)

	for _, clientID := range []string{"broker", "master-realm"} {
		t.Run(clientID, func(t *testing.T) {
			_, authErr := h.authenticateClient(context.Background(), realm,
				url.Values{"client_id": {clientID}, "client_secret": {""}}, http.Header{})

			assertAuthError(t, authErr, "unauthorized_client", 401)
		})
	}
}

func TestAuthenticateClientRejectsAMissingClientID(t *testing.T) {
	// Measured: .../oidc/introspection/unauthenticated-client.http sends only a
	// token, with no client_id at all.
	h, _, realm := newHandler(t)

	_, authErr := h.authenticateClient(context.Background(), realm, url.Values{}, http.Header{})

	assertAuthError(t, authErr, "invalid_client", 401)
}

func TestAuthenticateClientAcceptsHTTPBasic(t *testing.T) {
	h, s, realm := newHandler(t)
	confidential := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-app",
		Enabled: true, Secret: "s3cret",
	}
	if err := s.Clients().Create(context.Background(), confidential); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}

	client, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{}, basic("gloak-app", "s3cret"))
	if authErr != nil {
		t.Fatalf("Basic credentials did not authenticate: %+v", authErr)
	}
	if client.ClientID != "gloak-app" {
		t.Fatalf("wrong client: %q", client.ClientID)
	}

	_, authErr = h.authenticateClient(context.Background(), realm,
		url.Values{}, basic("gloak-app", "wrong"))
	assertAuthError(t, authErr, "unauthorized_client", 401)
}

func TestAuthenticateClientRejectsADisabledClient(t *testing.T) {
	h, s, realm := newHandler(t)
	disabled := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "retired",
		Enabled: false, PublicClient: true,
	}
	if err := s.Clients().Create(context.Background(), disabled); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}

	_, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{"client_id": {"retired"}}, http.Header{})

	assertAuthError(t, authErr, "invalid_client", 401)
}

func TestFormCredentialsWinOverBasic(t *testing.T) {
	// Keycloak's own clients send the form fields. A request carrying both must
	// not silently authenticate as whoever is in the header.
	h, _, realm := newHandler(t)

	client, authErr := h.authenticateClient(context.Background(), realm,
		url.Values{"client_id": {"admin-cli"}}, basic("broker", "wrong-secret"))

	if authErr != nil {
		t.Fatalf("want admin-cli from the form, got %+v", authErr)
	}
	if client.ClientID != "admin-cli" {
		t.Fatalf("wrong client: %q", client.ClientID)
	}
}

func basic(user, pass string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	return h
}

func assertAuthError(t *testing.T, got *clientAuthError, code string, status int) {
	t.Helper()
	if got == nil {
		t.Fatal("want an authentication failure, got none")
	}
	if got.Code != code || got.Status != status {
		t.Fatalf("want %s/%d, got %s/%d", code, status, got.Code, got.Status)
	}
}
