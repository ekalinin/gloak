package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
	"github.com/ekalinin/gloak/internal/token"
)

// Dynamic client registration's tests live in package oidc for the reason the
// device grant's do: **most of what was measured here is an order or a pair of
// answers to one condition**, and a golden holds one request at one moment.
//
// The catalogue's fourteen registration cases each break exactly one thing.
// What they cannot say is that the Content-Type check runs *before* the caller
// is judged, that the 401 sentence splits by verb, that a PUT rotates the
// registration access token and a GET does not, or that a create naming
// `private_key_jwt` is refused while a read produces it. Every one of those was
// measured by sending a request wrong in two ways at once, and every one of them
// lives here.

const registrationPath = "/realms/master/clients-registrations/openid-connect"

// registrationServer is a bootstrapped master behind the real router, with the
// handler beside it so a test can reach the registration store.
func registrationServer(t *testing.T) (http.Handler, *handler, store.Store, *model.Realm) {
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
	h := &handler{store: s, keys: keys.NewManager(s), issuerBase: "http://localhost:8080",
		auth: newAuthStore(), device: newDeviceStore(), consents: newConsentStore(),
		registrations: newRegistrationStore()}
	mux := http.NewServeMux()
	h.register(mux)
	return WithKeycloakFallbacks(mux), h, s, realm
}

// adminTokens is the administrator's token pair, obtained the way kcadm.sh
// obtains one.
func adminTokens(t *testing.T, h http.Handler) (access, refresh string) {
	t.Helper()
	w := postForm(t, h, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"},
		"username": {"admin"}, "password": {"admin"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("admin token: want 200, got %d: %s", w.Code, w.Body)
	}
	var body tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body.AccessToken, body.RefreshToken
}

// registrationRequestOf builds one request to this family. bearer empty means
// no Authorization header at all, which is a measured state of its own.
func registrationRequestOf(t *testing.T, h http.Handler, method, path, bearer, body string,
	contentType bool) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if contentType {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func registerJSON(t *testing.T, h http.Handler, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	return registrationRequestOf(t, h, http.MethodPost, registrationPath, bearer, body, true)
}

// registered is the create's body, decoded.
func registered(t *testing.T, w *httptest.ResponseRecorder) oidcClientRepresentation {
	t.Helper()
	if w.Code != http.StatusCreated {
		t.Fatalf("register: want 201, got %d: %s", w.Code, w.Body)
	}
	var body oidcClientRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse registration response: %v", err)
	}
	return body
}

// registerProbe registers one client with an administrator's token.
func registerProbe(t *testing.T, h http.Handler, name string) (oidcClientRepresentation, string) {
	t.Helper()
	access, _ := adminTokens(t, h)
	w := registerJSON(t, h, access, `{"client_name":"`+name+`"}`)
	return registered(t, w), access
}

// wantError asserts the status and the two fields of an RFC 6749 body.
func wantError(t *testing.T, w *httptest.ResponseRecorder, status int, code, description string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("want %d, got %d: %s", status, w.Code, w.Body)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error body: %v (%s)", err, w.Body)
	}
	if body.Error != code || body.Description != description {
		t.Errorf("want %q / %q, got %q / %q", code, description, body.Error, body.Description)
	}
}

// TestAnAdministratorsTokenRegistersAClient is the measurement the whole cut
// rests on: **no initial access token is needed**. The catalogue's five
// registration cases were Pending on the belief that one was, and minting one
// is an Admin API route Gloak does not serve.
func TestAnAdministratorsTokenRegistersAClient(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	body, _ := registerProbe(t, h, "gloak-probe-created")

	if body.ClientID == "" {
		t.Fatal("no client_id in the response")
	}
	if body.ClientName != "gloak-probe-created" {
		t.Errorf("client_name: want gloak-probe-created, got %q", body.ClientName)
	}
	// The registered client persists, which is the difference between this
	// store and the device store beside it.
	c, err := s.Clients().ByClientID(context.Background(), realm.ID, body.ClientID)
	if err != nil {
		t.Fatalf("the registered client is not in the store: %v", err)
	}
	if c.ClientID != c.ID {
		t.Errorf("a registered client's clientId is its own uuid: %q vs %q", c.ClientID, c.ID)
	}
}

// TestTheCreateEmitsTheMeasuredKeyOrder pins the twenty keys and the order they
// come in, which no other test in this package can see: the conformance golden
// compares them, but only against a container.
func TestTheCreateEmitsTheMeasuredKeyOrder(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)
	w := registerJSON(t, h, access, `{"client_name":"gloak-probe-order"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body)
	}
	want := []string{
		"redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types",
		"client_id", "client_secret", "client_name", "scope", "subject_type", "request_uris",
		"tls_client_certificate_bound_access_tokens", "dpop_bound_access_tokens",
		"post_logout_redirect_uris", "client_id_issued_at", "client_secret_expires_at",
		"registration_client_uri", "registration_access_token",
		"backchannel_logout_session_required", "require_pushed_authorization_requests",
		"frontchannel_logout_session_required",
	}
	got := jsonKeyOrder(t, w.Body.Bytes())
	if len(got) != len(want) {
		t.Fatalf("want %d keys, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("key %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

// jsonKeyOrder reads an object's keys in the order they appear on the wire,
// which encoding/json's map decoding throws away.
func jsonKeyOrder(t *testing.T, body []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(body)))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("not a JSON object: %v", err)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		keys = append(keys, k.(string))
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatalf("read value: %v", err)
		}
	}
	return keys
}

// TestTheCreatesTwoRefusalsHaveDifferentBodies is the pair a single "not
// allowed" constant would collapse: a caller with no bearer at all is told
// about the Trusted Hosts policy, and one holding a token that is not an
// administrator's is told something else entirely.
func TestTheCreatesTwoRefusalsHaveDifferentBodies(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	_, refresh := adminTokens(t, h)

	anonymous := registerJSON(t, h, "", `{"client_name":"gloak-probe-anon"}`)
	wantError(t, anonymous, http.StatusForbidden, errInsufficientScope, descTrustedHosts)

	// A refresh token verifies against the realm's own key and is the wrong
	// kind, which is its own 401 rather than either 403.
	wrongKind := registerJSON(t, h, refresh, `{"client_name":"gloak-probe-refresh"}`)
	wantError(t, wrongKind, http.StatusUnauthorized, errInvalidToken, descInvalidTokenType)
}

// TestABearerThatDoesNotVerifyIsADecodeFailure covers both halves of a word
// that is measured to be wider than it reads: unparseable input **and** a
// well-formed JWT with a wrong signature answer the same thing.
func TestABearerThatDoesNotVerifyIsADecodeFailure(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	for _, bearer := range []string{
		"not-a-token",
		// Three parts, decodable, and signed by nobody.
		"eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL21hc3RlciJ9.AAAA",
	} {
		w := registerJSON(t, h, bearer, `{"client_name":"gloak-probe-decode"}`)
		wantError(t, w, http.StatusUnauthorized, errInvalidToken, descFailedDecode)
	}
}

// TestAnEmptyBearerCountsAsNone is why registrationBearer trims: `Bearer ` with
// nothing after it was measured getting the anonymous 403 rather than a decode
// failure, and so was a Basic credential.
func TestAnEmptyBearerCountsAsNone(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	for _, header := range []string{"Bearer ", "Bearer", "Basic YWRtaW46YWRtaW4="} {
		req := httptest.NewRequest(http.MethodPost, registrationPath,
			strings.NewReader(`{"client_name":"gloak-probe-empty"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", header)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%q: want 403, got %d: %s", header, w.Code, w.Body)
		}
	}
}

// TestTheBodyIsJudgedBeforeTheCaller is the order that is the opposite of every
// other guarded route in this project.
//
// **The credential has to be one that would have written a refusal.** The first
// version of this test sent no Authorization header at all, and a mutation that
// resolved the caller *first* survived it: an anonymous caller writes nothing on
// the way through, so moving the decode behind it changed no byte. A garbage
// bearer is the request that tells the two orders apart, because it produces a
// 401 - and the measurement says the 415 and the 400 still win.
func TestTheBodyIsJudgedBeforeTheCaller(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	const garbage = "not-a-token"

	// A Content-Type that is present and refused. An **absent** one is
	// accepted, so this half of the order needs a header that is wrong rather
	// than a header that is missing.
	req := httptest.NewRequest(http.MethodPost, registrationPath,
		strings.NewReader(`{"client_name":"gloak-probe-media"}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+garbage)
	badType := httptest.NewRecorder()
	h.ServeHTTP(badType, req)
	if badType.Code != http.StatusUnsupportedMediaType {
		t.Errorf("a refused Content-Type beats a bearer that does not verify: want 415, got %d: %s",
			badType.Code, badType.Body)
	}

	badJSON := registerJSON(t, h, garbage, `{`)
	wantError(t, badJSON, http.StatusBadRequest, authErrInvalidRequest, descCannotParseJSON)

	// And the control: the same bearer with a body that is fine reaches the
	// 401, so the two above are the body winning rather than the bearer never
	// being looked at.
	good := registerJSON(t, h, garbage, `{"client_name":"gloak-probe-control"}`)
	wantError(t, good, http.StatusUnauthorized, errInvalidToken, descFailedDecode)

	// The update decodes before the caller too, measured on the same pair.
	put := registrationRequestOf(t, h, http.MethodPut, registrationPath+"/admin-cli", garbage, `{`, true)
	wantError(t, put, http.StatusBadRequest, authErrInvalidRequest, descCannotParseJSON)
}

// TestTheConsumedMediaTypesAreAMatchNotAPrefix is the eight-value sweep. The
// row an implementation gets wrong is the first: **an absent Content-Type is
// accepted**, which is also how the conformance harness reaches this endpoint,
// since buildRequest sets no Content-Type for a case sending a Body.
func TestTheConsumedMediaTypesAreAMatchNotAPrefix(t *testing.T) {
	for _, tc := range []struct {
		value    string
		accepted bool
	}{
		{"", true},
		{"application/json", true},
		{"application/json;charset=UTF-8", true},
		{"application/JSON", true},
		{"*/*", true},
		{"application/x-www-form-urlencoded", false},
		{"text/plain", false},
		{"application/xml", false},
		// Not a prefix: one character past the media type is refused.
		{"application/jsonx", false},
	} {
		if got := registrationConsumes(tc.value); got != tc.accepted {
			t.Errorf("%q: want accepted=%v, got %v", tc.value, tc.accepted, got)
		}
	}
}

// TestACreateMayNotNameItsOwnClientID is why every registered client is
// addressed by a UUID, and therefore why the read, update and delete cases
// capture one rather than spelling it.
func TestACreateMayNotNameItsOwnClientID(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)
	w := registerJSON(t, h, access, `{"client_id":"gloak-probe-named","client_name":"x"}`)
	wantError(t, w, http.StatusBadRequest, errInvalidClientMeta, descClientIdentifierIncluded)
}

// TestTokenEndpointAuthMethodIsAcceptedAndRefusedByName pins the set this
// endpoint takes, including the one that surprises: **private_key_jwt is
// refused**, although the discovery document advertises it and a read produces
// it for a client-jwt client.
func TestTokenEndpointAuthMethodIsAcceptedAndRefusedByName(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)

	accepted := []string{authMethodSecretBasic, authMethodSecretPost, authMethodSecretJWT,
		authMethodTLS, authMethodNone}
	for i, method := range accepted {
		w := registerJSON(t, h, access,
			`{"client_name":"gloak-probe-team`+string(rune('a'+i))+`","token_endpoint_auth_method":"`+method+`"}`)
		body := registered(t, w)
		if body.TokenEndpointAuthMethod != method {
			t.Errorf("%s: read back as %q", method, body.TokenEndpointAuthMethod)
		}
	}
	for _, method := range []string{authMethodPrivateJWT, "self_signed_tls_client_auth", "bogus", ""} {
		w := registerJSON(t, h, access,
			`{"client_name":"gloak-probe-bad","token_endpoint_auth_method":"`+method+`"}`)
		wantError(t, w, http.StatusBadRequest, errInvalidClientMeta, descClientMetadataInvalid)
	}
}

// TestTheSecretAndItsExpiryAreDecidedSeparately is the pair admin-cli made
// visible on the live container: a public client whose authenticator is
// client-secret carries client_secret_expires_at and no client_secret, and a
// client registered with `none` carries neither.
//
// All five accepted methods are driven rather than the two that differ, because
// the rule is about which **group** a method is in and a test over two of them
// cannot see a method moving between groups.
func TestTheSecretAndItsExpiryAreDecidedSeparately(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	access, _ := adminTokens(t, h)

	for i, tc := range []struct {
		method       string
		secret       bool
		expiresAt    bool
		publicClient bool
	}{
		{authMethodSecretBasic, true, true, false},
		{authMethodSecretPost, true, true, false},
		{authMethodSecretJWT, true, true, false},
		{authMethodTLS, false, false, false},
		{authMethodNone, false, false, true},
	} {
		got := registered(t, registerJSON(t, h, access,
			`{"client_name":"gloak-probe-sx`+string(rune('a'+i))+`","token_endpoint_auth_method":"`+
				tc.method+`"}`))
		if (got.ClientSecret != "") != tc.secret {
			t.Errorf("%s: client_secret present=%v, want %v", tc.method, got.ClientSecret != "", tc.secret)
		}
		if (got.ClientSecretExpiresAt != nil) != tc.expiresAt {
			t.Errorf("%s: client_secret_expires_at present=%v, want %v",
				tc.method, got.ClientSecretExpiresAt != nil, tc.expiresAt)
		}
	}

	// admin-cli is the measured counterexample: public, authenticator
	// client-secret, so the expiry is there and the secret is not.
	adminCLI, err := s.Clients().ByClientID(context.Background(), realm.ID, "admin-cli")
	if err != nil {
		t.Fatalf("admin-cli: %v", err)
	}
	w := registrationRequestOf(t, h, http.MethodGet, registrationPath+"/admin-cli", access, "", false)
	if w.Code != http.StatusOK {
		t.Fatalf("read admin-cli: want 200, got %d: %s", w.Code, w.Body)
	}
	var body oidcClientRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !adminCLI.PublicClient {
		t.Fatal("this test needs admin-cli to be public, which bootstrap makes it")
	}
	if body.TokenEndpointAuthMethod != authMethodSecretBasic {
		t.Errorf("admin-cli reads back as %q, not client_secret_basic - the method follows "+
			"clientAuthenticatorType, not publicClient", body.TokenEndpointAuthMethod)
	}
	if body.ClientSecret != "" {
		t.Error("a public client must not publish a secret")
	}
	if body.ClientSecretExpiresAt == nil {
		t.Error("client_secret_expires_at is decided by the method, so a public " +
			"client-secret client still carries it")
	}
}

// TestTheTwoReadShapesDifferByCredential is the finding a shared serialiser
// would lose: one route, two bodies, decided by which token asked.
func TestTheTwoReadShapesDifferByCredential(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	body, access := registerProbe(t, h, "gloak-probe-shapes")
	path := registrationPath + "/" + body.ClientID

	byToken := registrationRequestOf(t, h, http.MethodGet, path, body.RegistrationAccessToken, "", false)
	if byToken.Code != http.StatusOK {
		t.Fatalf("read with the registration token: want 200, got %d: %s", byToken.Code, byToken.Body)
	}
	var held oidcClientRepresentation
	if err := json.Unmarshal(byToken.Body.Bytes(), &held); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if held.RegistrationAccessToken != body.RegistrationAccessToken {
		t.Errorf("the holder's read must echo the token it presented, got %q", held.RegistrationAccessToken)
	}
	if held.ClientIDIssuedAt != nil {
		t.Error("client_id_issued_at is the create's key and no read emits it")
	}

	byAdmin := registrationRequestOf(t, h, http.MethodGet, path, access, "", false)
	if byAdmin.Code != http.StatusOK {
		t.Fatalf("read with the admin token: want 200, got %d: %s", byAdmin.Code, byAdmin.Body)
	}
	var seen oidcClientRepresentation
	if err := json.Unmarshal(byAdmin.Body.Bytes(), &seen); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if seen.RegistrationAccessToken != "" {
		t.Error("an administrator's read must not carry registration_access_token")
	}
	if strings.Contains(byAdmin.Body.String(), "registration_access_token") {
		t.Error("the key must be absent, not empty")
	}
}

// TestAPutRotatesTheRegistrationTokenAndAGetDoesNot is the asymmetry, and the
// half that matters is the negative one: an implementation that rotated on
// every request would pass a test that only checked the PUT.
func TestAPutRotatesTheRegistrationTokenAndAGetDoesNot(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	body, _ := registerProbe(t, h, "gloak-probe-rotate")
	path := registrationPath + "/" + body.ClientID
	original := body.RegistrationAccessToken

	// Two reads leave it alone and it goes on working.
	for i := range 2 {
		w := registrationRequestOf(t, h, http.MethodGet, path, original, "", false)
		if w.Code != http.StatusOK {
			t.Fatalf("read %d: want 200, got %d: %s", i, w.Code, w.Body)
		}
		var read oidcClientRepresentation
		if err := json.Unmarshal(w.Body.Bytes(), &read); err != nil {
			t.Fatalf("parse: %v", err)
		}
		if read.RegistrationAccessToken != original {
			t.Fatalf("read %d rotated the token", i)
		}
	}

	put := registrationRequestOf(t, h, http.MethodPut, path, original,
		`{"client_id":"`+body.ClientID+`","client_name":"gloak-probe-rotated"}`, true)
	if put.Code != http.StatusOK {
		t.Fatalf("update: want 200, got %d: %s", put.Code, put.Body)
	}
	var updated oidcClientRepresentation
	if err := json.Unmarshal(put.Body.Bytes(), &updated); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if updated.RegistrationAccessToken == original {
		t.Error("the update must rotate the registration access token")
	}
	stale := registrationRequestOf(t, h, http.MethodGet, path, original, "", false)
	wantError(t, stale, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedView)
	fresh := registrationRequestOf(t, h, http.MethodGet, path, updated.RegistrationAccessToken, "", false)
	if fresh.Code != http.StatusOK {
		t.Errorf("the rotated token must work: %d %s", fresh.Code, fresh.Body)
	}
}

// TestTheUpdateKeepsTheSecret is measured: a PUT answered with the same
// client_secret the create minted.
func TestTheUpdateKeepsTheSecret(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	body, _ := registerProbe(t, h, "gloak-probe-keepsecret")
	put := registrationRequestOf(t, h, http.MethodPut, registrationPath+"/"+body.ClientID,
		body.RegistrationAccessToken,
		`{"client_id":"`+body.ClientID+`","client_name":"gloak-probe-keepsecret2"}`, true)
	if put.Code != http.StatusOK {
		t.Fatalf("update: want 200, got %d: %s", put.Code, put.Body)
	}
	var updated oidcClientRepresentation
	if err := json.Unmarshal(put.Body.Bytes(), &updated); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if updated.ClientSecret != body.ClientSecret {
		t.Error("an update must not mint a new secret")
	}
}

// TestTheUpdateDemandsItsOwnClientID covers both conditions that share one
// message: a body naming another client and a body naming none at all.
func TestTheUpdateDemandsItsOwnClientID(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	body, _ := registerProbe(t, h, "gloak-probe-idcheck")
	path := registrationPath + "/" + body.ClientID
	for _, update := range []string{`{"client_id":"admin-cli"}`, `{"client_name":"x"}`} {
		w := registrationRequestOf(t, h, http.MethodPut, path, body.RegistrationAccessToken, update, true)
		wantError(t, w, http.StatusBadRequest, errInvalidClientMeta, descClientIdentifierModified)
	}
}

// TestTheDeleteRemovesTheClientAndItsToken.
func TestTheDeleteRemovesTheClientAndItsToken(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	body, access := registerProbe(t, h, "gloak-probe-delete")
	path := registrationPath + "/" + body.ClientID

	w := registrationRequestOf(t, h, http.MethodDelete, path, body.RegistrationAccessToken, "", false)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d: %s", w.Code, w.Body)
	}
	// A DELETE sends no Content-Type, so the 204 omits X-Frame-Options. That
	// rule lives in httpx.WriteNoContent; this is the assertion that this route
	// goes through it.
	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("a 204 with no request Content-Type must omit X-Frame-Options, got %q", got)
	}
	if _, err := s.Clients().ByClientID(context.Background(), realm.ID, body.ClientID); err == nil {
		t.Error("the client is still in the store")
	}
	gone := registrationRequestOf(t, h, http.MethodGet, path, access, "", false)
	wantError(t, gone, http.StatusNotFound, authErrInvalidRequest, descClientNotFound)
}

// TestTheItemPathsThreeRefusalsAreThreeDifferentAnswers is the grid that fixes
// the resolution order. Only the missing-client column tells the three possible
// orders apart, and the verb splits the 401 in two.
func TestTheItemPathsThreeRefusalsAreThreeDifferentAnswers(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)
	missing := registrationPath + "/gloak-probe-absent"

	// A caller who proves nothing never learns whether the client exists.
	anonymous := registrationRequestOf(t, h, http.MethodGet, missing, "", "", false)
	wantError(t, anonymous, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedView)

	// A caller who does gets the 404.
	admin := registrationRequestOf(t, h, http.MethodGet, missing, access, "", false)
	wantError(t, admin, http.StatusNotFound, authErrInvalidRequest, descClientNotFound)

	// The sentence splits by verb, on a client that exists so the verb is the
	// only variable.
	del := registrationRequestOf(t, h, http.MethodDelete, registrationPath+"/admin-cli", "", "", false)
	wantError(t, del, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedUpdate)
	get := registrationRequestOf(t, h, http.MethodGet, registrationPath+"/admin-cli", "", "", false)
	wantError(t, get, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedView)
}

// TestAnotherClientsRegistrationTokenIsRefused. The token verifies, and it is
// not this client's, so it answers what a caller with no token gets rather than
// a decode failure.
func TestAnotherClientsRegistrationTokenIsRefused(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	first, _ := registerProbe(t, h, "gloak-probe-first")
	second, _ := registerProbe(t, h, "gloak-probe-second")

	w := registrationRequestOf(t, h, http.MethodGet, registrationPath+"/"+first.ClientID,
		second.RegistrationAccessToken, "", false)
	wantError(t, w, http.StatusUnauthorized, errInvalidToken, descNotAuthorizedView)
}

// TestAnUnknownRealmIsAnsweredBeforeAnythingElse, on both the collection and an
// item, and with no credentials so nothing else could have answered.
func TestAnUnknownRealmIsAnsweredBeforeAnythingElse(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	for _, path := range []string{
		"/realms/nope/clients-registrations/openid-connect",
		"/realms/nope/clients-registrations/openid-connect/admin-cli",
	} {
		method := http.MethodPost
		if strings.HasSuffix(path, "admin-cli") {
			method = http.MethodGet
		}
		w := registrationRequestOf(t, h, method, path, "", `{`, true)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d: %s", path, w.Code, w.Body)
		}
		if got := w.Body.String(); got != `{"error":"Realm does not exist"}` {
			t.Errorf("%s: got %s", path, got)
		}
	}
}

// TestGrantTypesAndResponseTypesAreDerivedBothWays is the grid measured over
// nine request bodies and eight clients. The empty array is the row that says
// the two halves are separate.
func TestGrantTypesAndResponseTypesAreDerivedBothWays(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)

	for i, tc := range []struct {
		body          string
		grantTypes    []string
		responseTypes []string
	}{
		{`{}`, []string{"authorization_code", "refresh_token"}, []string{"code", "none"}},
		{`{"grant_types":[]}`, []string{"authorization_code"}, []string{"code", "none"}},
		{`{"grant_types":["authorization_code"]}`, []string{"authorization_code"}, []string{"code", "none"}},
		{`{"grant_types":["refresh_token"]}`, []string{"refresh_token"}, []string{}},
		{`{"grant_types":["password"]}`, []string{"password"}, []string{}},
		{`{"grant_types":["client_credentials"]}`, []string{"client_credentials"}, []string{}},
		{`{"grant_types":["implicit"]}`, []string{"implicit"}, []string{"id_token", "id_token token"}},
		{`{"response_types":["code"]}`, []string{"authorization_code", "refresh_token"}, []string{"code", "none"}},
		{`{"response_types":["token","id_token"]}`, []string{"implicit", "refresh_token"},
			[]string{"id_token", "id_token token"}},
	} {
		w := registerJSON(t, h, access, tc.body)
		body := registered(t, w)
		if !equalStrings(body.GrantTypes, tc.grantTypes) {
			t.Errorf("%d %s: grant_types want %v, got %v", i, tc.body, tc.grantTypes, body.GrantTypes)
		}
		if !equalStrings(body.ResponseTypes, tc.responseTypes) {
			t.Errorf("%d %s: response_types want %v, got %v", i, tc.body, tc.responseTypes, body.ResponseTypes)
		}
	}
}

// TestTheGrantTypeOrderPutsRefreshTokenSeventh is the one part of the list
// nobody would guess, and the only way to see it is a client with all nine on.
func TestTheGrantTypeOrderPutsRefreshTokenSeventh(t *testing.T) {
	c := &model.Client{
		StandardFlowEnabled:       true,
		ImplicitFlowEnabled:       true,
		DirectAccessGrantsEnabled: true,
		ServiceAccountsEnabled:    true,
		Attributes: map[string]string{
			attrDeviceGrant:    "true",
			attrCIBAGrant:      "true",
			attrExchangeGrant:  "true",
			attrJWTBearerGrant: "true",
		},
	}
	want := []string{
		"authorization_code", "implicit", "password", "client_credentials",
		grantDeviceCode, grantCIBA, grantRefreshToken, grantTokenExchange, grantJWTBearer,
	}
	if got := registrationGrantTypes(c); !equalStrings(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
	// The same client with refresh tokens off, so the position of the one that
	// moves is fixed rather than inferred from the list above.
	c.Attributes[attrUseRefreshTokens] = "false"
	withoutRefresh := []string{
		"authorization_code", "implicit", "password", "client_credentials",
		grantDeviceCode, grantCIBA, grantTokenExchange, grantJWTBearer,
	}
	if got := registrationGrantTypes(c); !equalStrings(got, withoutRefresh) {
		t.Errorf("without refresh: want %v, got %v", withoutRefresh, got)
	}
}

// TestRegisteringGrantTypesSwitchesOnFourOtherGrants is the second way into the
// device grant, CIBA, token exchange and the JWT bearer grant - measured, and
// the reason the JWT bearer attribute's name was found at all.
func TestRegisteringGrantTypesSwitchesOnFourOtherGrants(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	access, _ := adminTokens(t, h)
	body := registered(t, registerJSON(t, h, access, `{"client_name":"gloak-probe-urns","grant_types":`+
		`["authorization_code","refresh_token","`+grantDeviceCode+`","`+grantCIBA+`","`+
		grantTokenExchange+`","`+grantJWTBearer+`"]}`))

	c, err := s.Clients().ByClientID(context.Background(), realm.ID, body.ClientID)
	if err != nil {
		t.Fatalf("stored client: %v", err)
	}
	for _, name := range []string{attrDeviceGrant, attrCIBAGrant, attrExchangeGrant, attrJWTBearerGrant} {
		if c.Attributes[name] != "true" {
			t.Errorf("%s: want true, got %q", name, c.Attributes[name])
		}
	}
}

// TestBackchannelLogoutSessionRequiredIsAConstantFalse is the trap: the
// attribute is written "true" and the field reads back false whatever the
// request said. Its neighbour does follow its attribute, with the opposite
// default, which is what makes one helper for the pair wrong.
func TestBackchannelLogoutSessionRequiredIsAConstantFalse(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	access, _ := adminTokens(t, h)
	for i, body := range []string{
		`{"client_name":"gloak-probe-bc1"}`,
		`{"client_name":"gloak-probe-bc2","backchannel_logout_session_required":true}`,
		`{"client_name":"gloak-probe-bc3","backchannel_logout_session_required":false}`,
	} {
		got := registered(t, registerJSON(t, h, access, body))
		if got.BackchannelLogoutSessionRequired {
			t.Errorf("%d: backchannel_logout_session_required must be false whatever was asked", i)
		}
		c, err := s.Clients().ByClientID(context.Background(), realm.ID, got.ClientID)
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if c.Attributes[attrBackchannelSess] != "true" {
			t.Errorf("%d: the stored attribute is written true, got %q", i, c.Attributes[attrBackchannelSess])
		}
	}
	// The neighbour, which does read its attribute and defaults the other way.
	on := registered(t, registerJSON(t, h, access,
		`{"client_name":"gloak-probe-fc","frontchannel_logout_session_required":true}`))
	if !on.FrontchannelLogoutSessionRequired {
		t.Error("frontchannel_logout_session_required must follow the request")
	}
	off := registered(t, registerJSON(t, h, access, `{"client_name":"gloak-probe-fc2"}`))
	if off.FrontchannelLogoutSessionRequired {
		t.Error("a registration writes the frontchannel attribute false, so its field is false")
	}
}

// TestScopeIsTheOptionalClientScopes pins what the field is: the client's
// optional list joined by spaces, which a reader would otherwise take for the
// requested scope.
//
// The words are compared as a **set**, and that is not laziness. The list's
// order is not reproducible - one recording of oidc/registration/create-client
// answered `address phone offline_access organization microprofile-jwt` where a
// hand probe minutes earlier put `organization` before `offline_access` - which
// is why the catalogue cases declare UnorderedWords on this field.
func TestScopeIsTheOptionalClientScopes(t *testing.T) {
	h, _, s, realm := registrationServer(t)
	access, _ := adminTokens(t, h)
	body := registered(t, registerJSON(t, h, access, `{"client_name":"gloak-probe-scope"}`))
	c, err := s.Clients().ByClientID(context.Background(), realm.ID, body.ClientID)
	if err != nil {
		t.Fatalf("stored client: %v", err)
	}
	want := slices.Clone(c.OptionalClientScopes)
	got := strings.Fields(body.Scope)
	slices.Sort(want)
	slices.Sort(got)
	if !equalStrings(got, want) {
		t.Errorf("scope is the optional client scopes; want %v, got %v", want, got)
	}
	if len(c.DefaultClientScopes) == 0 {
		t.Error("a registered client inherits the realm's default client scopes")
	}
}

// TestTheCreateSetsLocationAndNoCacheControl. The Location is the eighth create
// measured for that rule and the fifth ending in a UUID; the missing
// Cache-Control is the whole family's, and the token endpoint one path away
// sends one on everything.
func TestTheCreateSetsLocationAndNoCacheControl(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)
	w := registerJSON(t, h, access, `{"client_name":"gloak-probe-location"}`)
	body := registered(t, w)
	want := "http://localhost:8080" + registrationPath + "/" + body.ClientID
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location: want %q, got %q", want, got)
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("this family sends no Cache-Control, got %q", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
		t.Errorf("Content-Type: want the charset, got %q", got)
	}
}

// TestARegistrationRefusalCarriesNoCharset is the other half of the rule this
// family breaks: its 2xx carries `;charset=UTF-8` and its errors carry plain
// `application/json`, which is the Admin API's split on a realm path.
func TestARegistrationRefusalCarriesNoCharset(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	w := registerJSON(t, h, "", `{"client_name":"gloak-probe-charset"}`)
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("a refusal carries plain application/json, got %q", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// callerHolding creates a user carrying one client role on master-realm and
// returns an access token for it, or a user holding nothing when role is empty.
//
// The role goes on **directly** rather than through a composite, which is what
// makes the grid below one role per caller: the bootstrapped administrator holds
// everything through `admin`'s composites, so a test using it could not tell any
// of the six roles apart.
//
// The token is minted rather than obtained through the password grant. Six
// callers would mean six argon2 hashes and six logins for a question none of
// this is about; what the endpoint reads is the token's session and the user
// behind it, and both are written here directly.
func callerHolding(t *testing.T, h *handler, s store.Store, realm *model.Realm,
	username, role string) string {
	t.Helper()
	ctx := context.Background()
	user := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: username, Enabled: true}
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	if role != "" {
		container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
		if err != nil {
			t.Fatalf("master-realm: %v", err)
		}
		r, err := s.Roles().ByName(ctx, realm.ID, container.ID, role)
		if err != nil {
			t.Fatalf("role %s: %v", role, err)
		}
		if err := s.Roles().AssignToUser(ctx, user.ID, r.ID); err != nil {
			t.Fatalf("assign %s: %v", role, err)
		}
	}
	now := time.Now().UnixMilli()
	session := &model.UserSession{
		ID: model.NewID(), RealmID: realm.ID, UserID: user.ID, Username: username,
		StartedAt: now, LastRefresh: now, ExpiresAt: now + realm.RefreshTokenLifespan.Milliseconds(),
	}
	if err := s.Sessions().CreateUserSession(ctx, session); err != nil {
		t.Fatalf("session for %s: %v", username, err)
	}
	k, err := h.keys.ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	client, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")
	if err != nil {
		t.Fatalf("admin-cli: %v", err)
	}
	issuer := &token.Issuer{Keys: k, Issuer: h.realmIssuer(realm.Name)}
	set, err := issuer.Issue(token.Request{
		Client: client, User: user, UserSession: session,
		AccessLife: time.Minute, RefreshLife: time.Hour,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return set.AccessToken
}

// TestTheThreeVerbsTakeThreeRoleSets is the grid measured one caller at a time,
// and the reason it is a grid rather than a list: `view-clients` opens a read
// and refuses a write, `create-client` opens the create and refuses everything
// else, and `manage-clients` opens all three. `query-clients` and `manage-realm`
// open nothing here, which is not what the client listing's own guard does.
func TestTheThreeVerbsTakeThreeRoleSets(t *testing.T) {
	h, handler, s, realm := registrationServer(t)
	// One client to read and to write, registered by the administrator.
	target, _ := registerProbe(t, h, "gloak-probe-roles")
	item := registrationPath + "/" + target.ClientID

	for i, tc := range []struct {
		role              string
		create, read, put bool
	}{
		{"", false, false, false},
		{"create-client", true, false, false},
		{"manage-clients", true, true, true},
		{"view-clients", false, true, false},
		{"query-clients", false, false, false},
		{"manage-realm", false, false, false},
	} {
		name := tc.role
		if name == "" {
			name = "none"
		}
		bearer := callerHolding(t, handler, s, realm, "gloak-probe-caller-"+string(rune('a'+i)), tc.role)

		create := registerJSON(t, h, bearer, `{"client_name":"gloak-probe-byrole`+string(rune('a'+i))+`"}`)
		if (create.Code == http.StatusCreated) != tc.create {
			t.Errorf("%s: create got %d, want allowed=%v (%s)", name, create.Code, tc.create, create.Body)
		}
		read := registrationRequestOf(t, h, http.MethodGet, item, bearer, "", false)
		if (read.Code == http.StatusOK) != tc.read {
			t.Errorf("%s: read got %d, want allowed=%v (%s)", name, read.Code, tc.read, read.Body)
		}
		// The write is a DELETE on a client that does not exist, so a caller
		// that gets past the guard lands on the 404 rather than destroying the
		// client the next caller reads.
		put := registrationRequestOf(t, h, http.MethodDelete,
			registrationPath+"/gloak-probe-absent", bearer, "", false)
		if (put.Code == http.StatusNotFound) != tc.put {
			t.Errorf("%s: write got %d, want allowed=%v (%s)", name, put.Code, tc.put, put.Body)
		}
	}
}

// TestARegisteredClientCanUseTheGrantsItAskedFor is the end-to-end assertion
// that registration writes a client the rest of the server can serve, rather
// than a representation that only this endpoint understands.
func TestARegisteredClientCanUseTheGrantsItAskedFor(t *testing.T) {
	h, _, _, _ := registrationServer(t)
	access, _ := adminTokens(t, h)
	body := registered(t, registerJSON(t, h, access,
		`{"client_name":"gloak-probe-usable","grant_types":["password","refresh_token"],`+
			`"token_endpoint_auth_method":"none"}`))

	w := postForm(t, h, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {body.ClientID},
		"username": {"admin"}, "password": {"admin"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("a registered public client with the direct grant must get tokens: %d %s", w.Code, w.Body)
	}
}
