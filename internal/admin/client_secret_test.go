package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

func newJSONBody(s string) io.Reader { return strings.NewReader(s) }

// grantClientRole assigns one master-realm client role to a user. Every case
// below needs a caller holding exactly one, which is how the roles themselves
// were measured against the reference container.
func grantClientRole(t *testing.T, s store.Store, realm *model.Realm, user *model.User, name string) {
	t.Helper()
	ctx := context.Background()
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID(master-realm): %v", err)
	}
	role, err := s.Roles().ByName(ctx, realm.ID, container.ID, name)
	if err != nil {
		t.Fatalf("ByName(%s): %v", name, err)
	}
	if err := s.Roles().AssignToUser(ctx, user.ID, role.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
}

func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// createClient inserts a client straight through the store, which is how a
// test reaches a client with a known secret without going through the create
// endpoint.
func createStoredClient(t *testing.T, s store.Store, realm *model.Realm, c *model.Client) *model.Client {
	t.Helper()
	c.ID = model.NewID()
	c.RealmID = realm.ID
	if err := s.Clients().Create(context.Background(), c); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}
	return c
}

// The split is measured and is not what the role names suggest: reading a
// secret is a view operation and regenerating one is a manage operation, on the
// same path. No conformance case can cover it, because a fixture reaching a
// narrow-role caller needs role assignment through the API, which is P2's
// second cut.
func TestReadingASecretNeedsOnlyViewClients(t *testing.T) {
	h, s, realm := newServer(t)
	user := createUserWithPassword(t, s, realm, "viewer", "viewer")
	grantClientRole(t, s, realm, user, "view-clients")
	c := createStoredClient(t, s, realm, &model.Client{ClientID: "with-secret", Secret: "s3cret"})
	tok := tokenFor(t, h, "viewer", "viewer")

	read := do(t, h, http.MethodGet, "/admin/realms/master/clients/"+c.ID+"/client-secret", tok)
	if read.Code != http.StatusOK {
		t.Fatalf("want 200 reading a secret with view-clients, got %d: %s", read.Code, read.Body)
	}
	if got := read.Body.String(); got != `{"type":"secret","value":"s3cret"}` {
		t.Fatalf("unexpected body: %s", got)
	}

	regenerate := do(t, h, http.MethodPost, "/admin/realms/master/clients/"+c.ID+"/client-secret", tok)
	if regenerate.Code != http.StatusForbidden {
		t.Fatalf("want 403 regenerating with view-clients, got %d: %s", regenerate.Code, regenerate.Body)
	}
}

// Keycloak's own defect, reproduced. See deleteRotatedSecretRejection.
func TestDeletingARotatedSecretWithoutTheRoleAnswers500(t *testing.T) {
	h, s, realm := newServer(t)
	user := createUserWithPassword(t, s, realm, "viewer", "viewer")
	grantClientRole(t, s, realm, user, "view-clients")
	c := createStoredClient(t, s, realm, &model.Client{ClientID: "rotated", Secret: "s3cret"})

	w := do(t, h, http.MethodDelete,
		"/admin/realms/master/clients/"+c.ID+"/client-secret/rotated", tokenFor(t, h, "viewer", "viewer"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want the measured 500, got %d: %s", w.Code, w.Body)
	}
	const want = `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`
	if got := w.Body.String(); got != want {
		t.Fatalf("unexpected body: %s", got)
	}
	// Unlike the 204 on this same path, the 500 carries X-Frame-Options.
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("want X-Frame-Options on the 500, got %q", got)
	}
}

// The representation hides a public client's secret and shows a bearer-only
// client's. Measured against the reference container, and invisible to the
// conformance suite: its recorded representations mask the secret as volatile,
// so only the presence of the key is compared and only for one kind of client.
func TestRepresentationHidesAPublicClientSecret(t *testing.T) {
	admin := &caller{roles: map[string]bool{"manage-clients": true}}

	public := clientRepresentationOf(
		&model.Client{ClientID: "pub", PublicClient: true, Secret: "s3cret"}, admin, "master")
	if public.Secret != "" {
		t.Fatalf("want a public client's secret hidden, got %q", public.Secret)
	}

	bearer := clientRepresentationOf(
		&model.Client{ClientID: "bear", BearerOnly: true, Secret: "s3cret"}, admin, "master")
	if bearer.Secret != "s3cret" {
		t.Fatalf("want a bearer-only client's secret shown, got %q", bearer.Secret)
	}
}

// Creating a client provisions the account, so a read finds one with no token
// grant in between. Keycloak was measured doing this; leaving it to the first
// client_credentials grant would answer 400 here.
func TestCreatingAServiceAccountClientProvisionsTheUser(t *testing.T) {
	h, s, realm := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")

	req := httptest.NewRequest(http.MethodPost, "/admin/realms/master/clients",
		newJSONBody(`{"clientId":"sa-client","enabled":true,"serviceAccountsEnabled":true}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	created := httptest.NewRecorder()
	h.ServeHTTP(created, req)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", created.Code, created.Body)
	}

	if _, err := s.Users().ByUsername(context.Background(), realm.ID,
		model.ServiceAccountUsername("sa-client")); err != nil {
		t.Fatalf("the service account was not created: %v", err)
	}
}
