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
	"slices"
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

// A caller holding a role whose owning client is gone still reaches the admin
// API, and still cannot hand out an admin role.
//
// F29 leaves a client's role rows behind when the client is deleted, so this
// state is reachable on Gloak and not on Keycloak. Resolving the caller now
// asks each of its client roles which container owns it, and propagating that
// lookup's ErrNotFound answered 500 on **every** admin route - including the
// role-mapping route that would remove the offending mapping, so the caller
// could not dig itself out, and including everything the bootstrapped
// administrator does the moment anything deletes the master-realm client, which
// Gloak answers 204.
//
// Both halves are the test. The 200 is the regression. The 403 is the guarantee
// that must not be lost while fixing it: skipping the orphan must not skip the
// admin roles beside it.
func TestARoleOnADeletedClientDoesNotLockTheCallerOut(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	admin := tokenFor(t, h, "admin", "admin")

	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-orphan"}`, admin)
	orphanClient := clientUUID(t, s, realm, "probe-orphan")
	postJSON(t, h, "/admin/realms/master/clients/"+orphanClient+"/roles", `{"name":"probe-orphan-role"}`, admin)

	user := createUserWithPassword(t, s, realm, "probe-orphaned", "pw")
	mr, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	for _, r := range []struct{ container, name string }{
		{mr.ID, "manage-users"},
		{orphanClient, "probe-orphan-role"},
	} {
		role, err := s.Roles().ByName(ctx, realm.ID, r.container, r.name)
		if err != nil {
			t.Fatalf("ByName(%s): %v", r.name, err)
		}
		if err := s.Roles().AssignToUser(ctx, user.ID, role.ID); err != nil {
			t.Fatalf("AssignToUser(%s): %v", r.name, err)
		}
	}
	caller := tokenFor(t, h, "probe-orphaned", "pw")

	// The precondition: entitled before the client goes away.
	if w := get(t, h, "/admin/realms/master/users", caller); w.Code != http.StatusOK {
		t.Fatalf("precondition: want 200 before the client is deleted, got %d: %s", w.Code, w.Body)
	}
	if w := sendJSON(t, h, http.MethodDelete, "/admin/realms/master/clients/"+orphanClient, "", admin); w.Code != http.StatusNoContent {
		t.Fatalf("delete the client: want 204, got %d: %s", w.Code, w.Body)
	}
	// F29 in one line: the role outlives its client, which is the state under
	// test. If Gloak ever deletes the roles too, this test stops testing
	// anything and should be deleted with the behaviour.
	if _, err := s.Roles().ByName(ctx, realm.ID, orphanClient, "probe-orphan-role"); err != nil {
		t.Fatalf("F29's orphan is gone, so this test no longer reaches the path it exists for: %v", err)
	}

	if w := get(t, h, "/admin/realms/master/users", caller); w.Code != http.StatusOK {
		t.Fatalf("a role on a deleted client locked the caller out: want 200, got %d: %s", w.Code, w.Body)
	}

	// And the grant decision is unchanged: the orphan is skipped, the real
	// admin roles beside it are not.
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-orphan-subject","enabled":true}`, admin)
	subject := userID(t, s, realm, "probe-orphan-subject")
	base := "/admin/realms/master/users/" + subject + "/role-mappings/realm"
	realmAdmin := readRole(t, h, "/admin/realms/master/roles/admin", admin)
	if w := postJSON(t, h, base, `[{"id":"`+realmAdmin.ID+`","name":"admin"}]`, caller); w.Code != http.StatusForbidden {
		t.Fatalf("granting the realm role admin: want 403, got %d: %s", w.Code, w.Body)
	}
	if got := mappingNames(t, h, base, admin); slices.Contains(got, "admin") {
		t.Fatalf("the subject was promoted: %v", got)
	}
	// The route itself is open to this caller, so the 403 above is the
	// predicate's answer and not the guard's.
	uma := readRole(t, h, "/admin/realms/master/roles/uma_authorization", admin)
	if w := postJSON(t, h, base, `[{"id":"`+uma.ID+`","name":"uma_authorization"}]`, caller); w.Code != http.StatusNoContent {
		t.Fatalf("granting an ordinary realm role: want 204, got %d: %s", w.Code, w.Body)
	}
}

// The other half of that rule: only ErrNotFound is swallowed. A store that is
// failing for any other reason must still stop the request, because "the
// container could not be read" and "the container is not there" are different
// facts and only the second one means "not an admin role".
//
// Without this, the orphan fix would be a fail-open one: a driver error would
// quietly empty the caller's admin grant set instead of refusing the request.
func TestAFailingClientLookupStillStopsTheRequest(t *testing.T) {
	var armed bool
	h, s, realm := newServerWrapping(t, failingClientLookup(func(string) error {
		if armed {
			return errInjected
		}
		return nil
	}))
	caller := tokenForRole(t, h, s, realm, "manage-users")

	if w := get(t, h, "/admin/realms/master/users", caller); w.Code != http.StatusOK {
		t.Fatalf("precondition: want 200 before the fault, got %d: %s", w.Code, w.Body)
	}

	armed = true
	w := get(t, h, "/admin/realms/master/users", caller)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a failing store must not be read as an absent container: want 500, got %d: %s", w.Code, w.Body)
	}
}
