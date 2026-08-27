package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

const testIssuer = "http://localhost:8080"

// newServer builds the composed handler cmd/gloak serves: both APIs on one
// mux, wrapped once. The protocol side is needed even for admin tests because
// a caller obtains its token from it.
func newServer(t *testing.T) (http.Handler, store.Store, *model.Realm) {
	t.Helper()
	return newServerWrapping(t, nil)
}

// newServerWrapping is newServer with the store the **admin** API sees passed
// through wrap first, which is how a test reaches an error path no fixture can
// produce.
//
// Only the admin side is wrapped. The protocol side mints the caller's token,
// so a fault that reached it would fail the test setup rather than the handler
// under test, and the store returned is the unwrapped one so a test still
// arranges its state against a working database.
func newServerWrapping(t *testing.T, wrap func(store.Store) store.Store) (http.Handler, store.Store, *model.Realm) {
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
	km := keys.NewManager(s)
	mux := http.NewServeMux()
	oidc.Register(mux, s, km, testIssuer)
	adminStore := store.Store(s)
	if wrap != nil {
		adminStore = wrap(s)
	}
	Register(mux, adminStore, km, testIssuer)
	return oidc.WithKeycloakFallbacks(mux), s, realm
}

// errInjected is what a fault-injecting repository returns. It is deliberately
// neither store.ErrNotFound nor store.ErrConflict: the handlers map those to
// measured 404s and 204s, and the paths this exists to test are the ones that
// have no measured answer but must still not be an authorization decision.
var errInjected = errors.New("injected store failure")

// faultyStore is store.Store with one repository replaced by a fault-injecting
// one. Everything else is delegated by embedding, so the wrapper does not have
// to track store.Store as it grows.
//
// It exists for the authorization error paths, which no fixture can reach:
// mayGrantRole's container lookup can fail, and what it must do then is refuse.
// A predicate that answered "may grant" on a store error would be a fail-open
// authorization bypass and, before this helper, nothing in the package could
// tell the difference.
type faultyStore struct {
	store.Store
	clients *faultyClients
}

func (f *faultyStore) Clients() store.ClientRepo { return f.clients }

// faultyClients fails Clients().ByID when fail says so. fail is consulted on
// every lookup and sees the client's id, so a test that has to aim at one
// lookup out of several the same request makes for the same client counts them
// in its own closure - which is also what keeps the arming visible at the call
// site rather than hidden in a counter here.
type faultyClients struct {
	store.ClientRepo
	fail func(id string) error
}

func (f *faultyClients) ByID(ctx context.Context, realmID, id string) (*model.Client, error) {
	if f.fail != nil {
		if err := f.fail(id); err != nil {
			return nil, err
		}
	}
	return f.ClientRepo.ByID(ctx, realmID, id)
}

// failingClientLookup builds newServerWrapping's argument: a store whose client
// lookup fails according to fail.
func failingClientLookup(fail func(id string) error) func(store.Store) store.Store {
	return func(s store.Store) store.Store {
		return &faultyStore{Store: s, clients: &faultyClients{ClientRepo: s.Clients(), fail: fail}}
	}
}

// tokenFor obtains an access token for a user through admin-cli, the way
// kcadm.sh does. admin-cli is lightweight, so the token carries no sub and no
// realm_access - which is the whole point: the roles below are resolved from
// the session, not read out of the token.
func tokenFor(t *testing.T, h http.Handler, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {username},
		"password":   {password},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token request for %q: %d %s", username, w.Code, w.Body)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body.AccessToken
}

func get(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeJSON(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// createUserWithPassword adds a user the password grant can authenticate.
//
// The argon2id parameters are the measured ones internal/bootstrap uses to
// create the administrator's password. They are repeated here rather than
// shared because nothing exports a hashing helper yet; Task 15 of P2's plan
// adds reset-password, which is where that belongs.
func createUserWithPassword(t *testing.T, s store.Store, realm *model.Realm, username, password string) *model.User {
	t.Helper()
	ctx := context.Background()
	user := &model.User{
		ID: model.NewID(), RealmID: realm.ID, Username: username, Enabled: true,
	}
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("Users().Create: %v", err)
	}
	salt := []byte("saltsaltsaltsalt")
	cred := &model.Credential{
		ID: model.NewID(), UserID: user.ID, Type: "password",
		Algorithm: "argon2", HashIterations: 5,
		AdditionalParameters: map[string][]string{
			"hashLength": {"32"}, "memory": {"7168"},
			"type": {"id"}, "version": {"1.3"}, "parallelism": {"1"},
		},
		Salt:      salt,
		HashValue: argon2.IDKey([]byte(password), salt, 5, 7168, 1, 32),
	}
	if err := s.Users().SetCredential(ctx, cred); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	return user
}

// tokenForRole creates a user holding exactly one master-realm role and
// returns an access token for it. It writes to the store rather than going
// through the API because role assignment is part two of this cut.
func tokenForRole(t *testing.T, h http.Handler, s store.Store, realm *model.Realm, role string) string {
	t.Helper()
	return tokenForRoles(t, h, s, realm, role)
}

// tokenForRoles is tokenForRole for a caller that needs more than one.
//
// F28's rule is about what a caller's rights add up to, and the sweep that
// derived it used two-role and three-role callers throughout: the too-permissive
// direction only shows up when the caller holds one role and is offered a role
// it does not hold, and the too-restrictive one only when it holds two.
func tokenForRoles(t *testing.T, h http.Handler, s store.Store, realm *model.Realm, roles ...string) string {
	t.Helper()
	ctx := context.Background()
	username := "only-" + strings.Join(roles, "+")
	u := createUserWithPassword(t, s, realm, username, "pw")
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	for _, role := range roles {
		r, err := s.Roles().ByName(ctx, realm.ID, container.ID, role)
		if err != nil {
			t.Fatalf("ByName(%s): %v", role, err)
		}
		if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
			t.Fatalf("AssignToUser(%s): %v", role, err)
		}
	}
	return tokenFor(t, h, username, "pw")
}

// sessionIDOf reads sid out of an access token without verifying it. A test
// wanting the session behind a token does not need the signature checked - the
// handler under test is what does that.
func sessionIDOf(t *testing.T, _ http.Handler, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Sid string `json:"sid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	return claims.Sid
}

func TestAdministratorReachesTheAdminAPI(t *testing.T) {
	// The bootstrapped administrator holds no client role directly - measured.
	// Every right it has arrives through the admin realm role's 22 composites,
	// so this passing is what proves the expansion works at all.
	h, _, _ := newServer(t)

	w := get(t, h, "/admin/realms/master/users", tokenFor(t, h, "admin", "admin"))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
}

func TestCallerWithoutTheRoleIsForbidden(t *testing.T) {
	// Measured on a live Keycloak: a caller holding view-users and nothing
	// else gets 200 listing users. Here the caller holds nothing at all, so
	// the same route must refuse it - which is what makes the check real
	// rather than a formality that always passes for anyone authenticated.
	h, s, realm := newServer(t)
	createUserWithPassword(t, s, realm, "narrow", "narrow")

	w := get(t, h, "/admin/realms/master/users", tokenFor(t, h, "narrow", "narrow"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body)
	}
	if got := w.Body.String(); got != `{"error":"HTTP 403 Forbidden"}` {
		t.Fatalf("unexpected body: %s", got)
	}
}

func TestGrantingTheRoleOpensTheRoute(t *testing.T) {
	// The same caller as above, plus view-users. If this did not flip to 200,
	// the 403 above would prove nothing about the role check.
	h, s, realm := newServer(t)
	ctx := context.Background()
	user := createUserWithPassword(t, s, realm, "narrow", "narrow")
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	role, err := s.Roles().ByName(ctx, realm.ID, container.ID, "view-users")
	if err != nil {
		t.Fatalf("ByName(view-users): %v", err)
	}
	if err := s.Roles().AssignToUser(ctx, user.ID, role.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}

	w := get(t, h, "/admin/realms/master/users", tokenFor(t, h, "narrow", "narrow"))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 once view-users is granted, got %d: %s", w.Code, w.Body)
	}
}

func TestRevokedSessionLosesAdminAccess(t *testing.T) {
	// The token still verifies - revocation deletes the session, not the
	// signature - so this is what proves the caller is resolved through the
	// session rather than trusted from the token's own claims.
	h, s, realm := newServer(t)
	tok := tokenFor(t, h, "admin", "admin")
	if w := get(t, h, "/admin/realms/master/users", tok); w.Code != http.StatusOK {
		t.Fatalf("precondition: want 200, got %d", w.Code)
	}
	sessions, err := s.Sessions().UserSessionByID(context.Background(), realm.ID, sessionIDOf(t, h, tok))
	if err != nil {
		t.Fatalf("UserSessionByID: %v", err)
	}
	if err := s.Sessions().DeleteUserSession(context.Background(), realm.ID, sessions.ID); err != nil {
		t.Fatalf("DeleteUserSession: %v", err)
	}

	w := get(t, h, "/admin/realms/master/users", tok)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 after the session is gone, got %d: %s", w.Code, w.Body)
	}
}

func TestUnknownRealmIsNotFound(t *testing.T) {
	// "Realm not found." with a trailing full stop, unlike the protocol side's
	// "Realm does not exist". Measured, and the reason this package does not
	// call into internal/oidc's realm resolution.
	h, _, _ := newServer(t)

	w := get(t, h, "/admin/realms/nosuchrealm/users", tokenFor(t, h, "admin", "admin"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"Realm not found."}` {
		t.Fatalf("unexpected body: %s", got)
	}
}

func TestRealmIsCheckedBeforeCredentials(t *testing.T) {
	// An unknown realm answers 404 even with no credentials at all. Checking
	// the token first would turn every typo into a 401 and hide the realm.
	h, _, _ := newServer(t)

	w := get(t, h, "/admin/realms/nosuchrealm/users", "")

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
}
