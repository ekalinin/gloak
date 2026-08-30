package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// The device grant's tests are in package oidc rather than oidc_test for one
// reason: **most of what is measured here is an ordering or a clock, and a
// golden holds one request at one moment.**
//
// Six adjacencies were measured by driving two faults at once, `slow_down` was
// measured to leave the poll clock alone across three requests, and the
// expired-code grace window is a third answer the same code gives at a third
// time. None of those is expressible as a golden, and the conformance cases
// that *are* goldens each break exactly one thing.

const devicePath = "/realms/master/protocol/openid-connect/auth/device"

// deviceServer is a bootstrapped master with the clients the measurements
// needed, and the handler behind the router so a test can reach the device
// store the way an approval will.
//
// The four clients are the four the live probes used, spelled the same way:
// a public client with the grant on, a second one so a client mismatch can be
// measured between two clients that differ in **nothing else** (the observed
// document records that the same probe run with a confidential client once
// measured client authentication by mistake), a public client with the grant
// off, and a confidential one with the grant on.
func deviceServer(t *testing.T) (http.Handler, *handler, store.Store, *model.Realm) {
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
	on := map[string]string{attrDeviceGrantEnabled: "true"}
	clients := []*model.Client{
		{ClientID: "dev-on", Enabled: true, PublicClient: true, Attributes: on},
		{ClientID: "dev-on2", Enabled: true, PublicClient: true, Attributes: on},
		{ClientID: "dev-off", Enabled: true, PublicClient: true},
		{ClientID: "dev-conf", Enabled: true, Secret: "s3cret", Attributes: on},
		{ClientID: "dev-short", Enabled: true, PublicClient: true, Attributes: map[string]string{
			attrDeviceGrantEnabled: "true",
			attrDeviceCodeLifespan: "1",
			attrDevicePollInterval: "2",
		}},
		{ClientID: "ciba-on", Enabled: true, Secret: "s3cret",
			Attributes: map[string]string{attrCIBAGrantEnabled: "true"}},
	}
	for _, c := range clients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Protocol = "openid-connect"
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.ClientID, err)
		}
	}
	h := &handler{store: s, keys: keys.NewManager(s), issuerBase: "http://localhost:8080",
		auth: newAuthStore(), device: newDeviceStore()}
	mux := http.NewServeMux()
	h.register(mux)
	return WithKeycloakFallbacks(mux), h, s, realm
}

// deviceForm is a device authorization request with nothing wrong with it.
func deviceForm(clientID string) url.Values {
	return url.Values{"client_id": {clientID}, "scope": {"openid"}}
}

// pollForm is a device_code redemption with nothing wrong with it.
func pollForm(clientID, deviceCode string) url.Values {
	return url.Values{
		"grant_type":  {grantDeviceCode},
		"client_id":   {clientID},
		"device_code": {deviceCode},
	}
}

// mintDeviceCode runs a real device authorization request and returns the body.
func mintDeviceCode(t *testing.T, h http.Handler, clientID string) deviceAuthorizationResponse {
	t.Helper()
	w := postForm(t, h, devicePath, deviceForm(clientID))
	if w.Code != http.StatusOK {
		t.Fatalf("mint: want 200, got %d: %s", w.Code, w.Body)
	}
	var body deviceAuthorizationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse device authorization response: %v", err)
	}
	return body
}

// wantOAuthError asserts a status and an {"error","error_description"} pair.
func wantOAuthError(t *testing.T, w *httptest.ResponseRecorder, status int, code, description string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("want %d, got %d: %s", status, w.Code, w.Body)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error body: %v", err)
	}
	if body.Error != code || body.Description != description {
		t.Fatalf("want %s/%q, got %s/%q", code, description, body.Error, body.Description)
	}
}

// TestDeviceAuthorizationResponseShape pins the six keys, their order and the
// two measured formats.
//
// The conformance golden masks device_code, user_code and
// verification_uri_complete as volatile, so nothing there says the codes have
// a shape at all - an endpoint returning two empty strings would match it.
func TestDeviceAuthorizationResponseShape(t *testing.T) {
	router, _, _, _ := deviceServer(t)

	w := postForm(t, router, devicePath, deviceForm("dev-on"))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	// Measured on every 200: this endpoint's success carries Cache-Control and
	// **no Pragma**, where the token endpoint carries both on every response.
	if got := w.Header().Get("Cache-Control"); got != deviceAuthorizationCacheControl {
		t.Errorf("Cache-Control: want %q, got %q", deviceAuthorizationCacheControl, got)
	}
	if got := w.Header().Get("Pragma"); got != "" {
		t.Errorf("this endpoint sends no Pragma; got %q", got)
	}

	var body deviceAuthorizationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// 43 characters of base64url: 32 random bytes, unpadded. Measured over
	// sixty mints, with the alphabet checked as well as the length.
	if len(body.DeviceCode) != 43 {
		t.Errorf("device_code is %d characters, want 43: %q", len(body.DeviceCode), body.DeviceCode)
	}
	// XXXX-XXXX, upper-case letters only. Sixty mints produced 480 code
	// characters and not one digit.
	if len(body.UserCode) != 9 || body.UserCode[4] != '-' {
		t.Errorf("user_code is not XXXX-XXXX: %q", body.UserCode)
	}
	for _, c := range body.UserCode {
		if c != '-' && !strings.ContainsRune(userCodeAlphabet, c) {
			t.Errorf("user_code %q holds %q, which is outside the measured alphabet", body.UserCode, c)
		}
	}
	if want := "http://localhost:8080/realms/master/device"; body.VerificationURI != want {
		t.Errorf("verification_uri: want %q, got %q", want, body.VerificationURI)
	}
	if want := body.VerificationURI + "?user_code=" + body.UserCode; body.VerificationURIComplete != want {
		t.Errorf("verification_uri_complete: want %q, got %q", want, body.VerificationURIComplete)
	}
	if body.ExpiresIn != 600 || body.Interval != 5 {
		t.Errorf("want the realm's measured 600/5, got %d/%d", body.ExpiresIn, body.Interval)
	}

	// The key order is the measured one, and unmarshalling into the struct
	// above succeeds whatever order the keys arrived in - so the bytes are
	// compared, not the decoded value. Go emits map keys alphabetically, which
	// would put device_code, expires_in, interval, user_code, verification_uri
	// first, so this is what says the response is a struct.
	want := `{"device_code":"` + body.DeviceCode + `","user_code":"` + body.UserCode +
		`","verification_uri":"` + body.VerificationURI +
		`","verification_uri_complete":"` + body.VerificationURIComplete +
		`","expires_in":600,"interval":5}`
	if got := w.Body.String(); got != want {
		t.Errorf("body bytes:\n want %s\n  got %s", want, got)
	}
}

// TestDeviceClientAttributesOverrideTheRealm pins the two client attributes
// that make the expired-token case recordable without touching the realm.
//
// Neither is written down anywhere else in this repository, and the obvious
// wrong guess - the realm field's own spelling, oauth2DeviceCodeLifespan, as a
// client attribute - was measured to do nothing, which is why the fallback is
// asserted here too.
func TestDeviceClientAttributesOverrideTheRealm(t *testing.T) {
	router, _, _, _ := deviceServer(t)

	short := mintDeviceCode(t, router, "dev-short")
	if short.ExpiresIn != 1 || short.Interval != 2 {
		t.Fatalf("client attributes ignored: want 1/2, got %d/%d", short.ExpiresIn, short.Interval)
	}
	plain := mintDeviceCode(t, router, "dev-on")
	if plain.ExpiresIn != 600 || plain.Interval != 5 {
		t.Fatalf("a client with no override should get the realm's 600/5, got %d/%d",
			plain.ExpiresIn, plain.Interval)
	}
}

// TestDeviceAuthorizationRejectionOrder is the endpoint's four adjacencies,
// each driven by a request that is wrong in two ways at once.
//
// A golden per rejection proves each answer exists and says nothing about which
// one wins, because each golden's request is wrong in one way only.
func TestDeviceAuthorizationRejectionOrder(t *testing.T) {
	router, _, _, _ := deviceServer(t)

	for _, tc := range []struct {
		name        string
		path        string
		form        url.Values
		status      int
		code        string
		description string
	}{
		{
			// The realm beats an unknown client: both wrong, and the answer is
			// about the realm.
			name:        "the realm beats the client",
			path:        "/realms/nope/protocol/openid-connect/auth/device",
			form:        deviceForm("no-such-client"),
			status:      http.StatusNotFound,
			code:        "", // the message shape, not the OAuth one
			description: "",
		},
		{
			// Client authentication beats the duplicate check.
			name:        "client authentication beats the duplicate",
			form:        url.Values{"client_id": {"no-such-client"}, "zz": {"1", "2"}},
			status:      http.StatusUnauthorized,
			code:        "invalid_client",
			description: "Invalid client or Invalid client credentials",
		},
		{
			// A confidential client with no secret, sending a key twice.
			name:        "a missing secret beats the duplicate",
			form:        url.Values{"client_id": {"dev-conf"}, "zz": {"1", "2"}},
			status:      http.StatusUnauthorized,
			code:        "unauthorized_client",
			description: "Invalid client or Invalid client credentials",
		},
		{
			// The duplicate beats the grant flag: a grant-disabled client
			// sending a key twice is told about the key.
			name:        "the duplicate beats the grant flag",
			form:        url.Values{"client_id": {"dev-off"}, "zz": {"1", "2"}},
			status:      http.StatusBadRequest,
			code:        "invalid_grant",
			description: descDuplicatedParameter,
		},
		{
			name:        "the grant flag",
			form:        deviceForm("dev-off"),
			status:      http.StatusBadRequest,
			code:        authErrUnauthorizedClient,
			description: descDeviceGrantOffAtDevice,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "" {
				path = devicePath
			}
			w := postForm(t, router, path, tc.form)
			if tc.code == "" {
				if w.Code != tc.status {
					t.Fatalf("want %d, got %d: %s", tc.status, w.Code, w.Body)
				}
				return
			}
			wantOAuthError(t, w, tc.status, tc.code, tc.description)
			// Measured: no rejection on this endpoint carries Cache-Control,
			// where its own 200 does. The token endpoint is the other way
			// round and sends it on everything.
			if got := w.Header().Get("Cache-Control"); got != "" {
				t.Errorf("this endpoint's rejections send no Cache-Control; got %q", got)
			}
		})
	}
}

// TestDeviceAuthorizationIgnoresTheScopeAndTheQuery is two measured non-checks.
//
// GET /auth refuses both of these and this endpoint accepts both, so a shared
// validation helper between the two would be wrong here. And the duplicate
// check reads the body only: the same key twice on the query answered 200.
func TestDeviceAuthorizationIgnoresTheScopeAndTheQuery(t *testing.T) {
	router, _, _, _ := deviceServer(t)

	for _, scope := range []string{"bogus-scope", ""} {
		form := deviceForm("dev-on")
		form.Set("scope", scope)
		if w := postForm(t, router, devicePath, form); w.Code != http.StatusOK {
			t.Errorf("scope=%q: want 200, got %d: %s", scope, w.Code, w.Body)
		}
	}

	w := postForm(t, router, devicePath+"?zz=1&zz=2", deviceForm("dev-on"))
	if w.Code != http.StatusOK {
		t.Errorf("a duplicated query key is not this endpoint's error: got %d: %s", w.Code, w.Body)
	}
}

// TestDeviceGrantRejectionOrder is the token endpoint's half, again with two
// faults per request.
func TestDeviceGrantRejectionOrder(t *testing.T) {
	router, _, _, _ := deviceServer(t)
	pending := mintDeviceCode(t, router, "dev-on")

	for _, tc := range []struct {
		name        string
		form        url.Values
		status      int
		code        string
		description string
	}{
		{
			// The duplicate beats the grant flag here too - and the code is
			// invalid_request, where the device endpoint spells the identical
			// description invalid_grant.
			name: "the duplicate beats the grant flag",
			form: url.Values{"grant_type": {grantDeviceCode}, "client_id": {"dev-off"},
				"zz": {"1", "2"}},
			status:      http.StatusBadRequest,
			code:        authErrInvalidRequest,
			description: descDuplicatedParameter,
		},
		{
			// The grant flag beats the device_code presence check: a
			// grant-disabled client sending no device_code is told about the
			// grant.
			name:        "the grant flag beats the missing parameter",
			form:        url.Values{"grant_type": {grantDeviceCode}, "client_id": {"dev-off"}},
			status:      http.StatusBadRequest,
			code:        "invalid_grant",
			description: descDeviceGrantOffAtToken,
		},
		{
			name:        "an absent device_code",
			form:        url.Values{"grant_type": {grantDeviceCode}, "client_id": {"dev-on"}},
			status:      http.StatusBadRequest,
			code:        authErrInvalidRequest,
			description: descMissingDeviceCode,
		},
		{
			// Presence, not value: an empty device_code= reaches the lookup.
			name:        "an empty device_code",
			form:        pollForm("dev-on", ""),
			status:      http.StatusBadRequest,
			code:        "invalid_grant",
			description: descDeviceCodeNotValid,
		},
		{
			name:        "an unknown device_code",
			form:        pollForm("dev-on", "not-a-device-code"),
			status:      http.StatusBadRequest,
			code:        "invalid_grant",
			description: descDeviceCodeNotValid,
		},
		{
			// Two public clients with the grant on, differing in nothing but
			// which one minted the code.
			name:        "another client's device_code",
			form:        pollForm("dev-on2", pending.DeviceCode),
			status:      http.StatusBadRequest,
			code:        "invalid_grant",
			description: descDeviceWrongClient,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postForm(t, router, "/realms/master/protocol/openid-connect/token", tc.form)
			wantOAuthError(t, w, tc.status, tc.code, tc.description)
			// Measured on every response to this grant, unlike the device
			// endpoint beside it.
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control: want no-store, got %q", got)
			}
			if got := w.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma: want no-cache, got %q", got)
			}
		})
	}
}

// TestTheTwoGrantDisabledAnswersAreNotOneString is the finding a pair of
// goldens records and cannot defend.
//
// One condition - this client may not use the device grant - has a different
// code and a different sentence at each of the two endpoints. Two goldens hold
// the two strings; nothing in them stops a later refactor from making them one
// constant and re-recording both. This does.
func TestTheTwoGrantDisabledAnswersAreNotOneString(t *testing.T) {
	if descDeviceGrantOffAtDevice == descDeviceGrantOffAtToken {
		t.Fatal("the two grant-disabled descriptions have been collapsed into one; " +
			"they are measured to differ, at two endpoints in one flow")
	}
	router, _, _, _ := deviceServer(t)

	atDevice := postForm(t, router, devicePath, deviceForm("dev-off"))
	wantOAuthError(t, atDevice, http.StatusBadRequest,
		authErrUnauthorizedClient, descDeviceGrantOffAtDevice)

	atToken := postForm(t, router, "/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {grantDeviceCode}, "client_id": {"dev-off"}})
	wantOAuthError(t, atToken, http.StatusBadRequest, "invalid_grant", descDeviceGrantOffAtToken)
}

// TestDuplicatedParameterHasTwoCodesInOneFlow is the same shape for the other
// pair: the description is one string and the code is not.
func TestDuplicatedParameterHasTwoCodesInOneFlow(t *testing.T) {
	router, _, _, _ := deviceServer(t)
	dup := url.Values{"client_id": {"dev-on"}, "zz": {"1", "2"}}

	wantOAuthError(t, postForm(t, router, devicePath, dup),
		http.StatusBadRequest, "invalid_grant", descDuplicatedParameter)

	dup.Set("grant_type", grantDeviceCode)
	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token", dup),
		http.StatusBadRequest, authErrInvalidRequest, descDuplicatedParameter)
}

// TestSlowDownDoesNotMoveThePollClock is the sharpest of the clock
// measurements and no golden can hold it: it is three requests at three times.
//
// Measured live at t=0, t=3 and t=6 with interval 5: pending, slow_down,
// pending. An implementation that stamped the clock on every poll answers
// slow_down at t=6, and every single-request golden in the catalogue would
// still pass.
func TestSlowDownDoesNotMoveThePollClock(t *testing.T) {
	router, h, _, _ := deviceServer(t)
	dc := mintDeviceCode(t, router, "dev-on")
	base := time.Now()
	h.device.now = func() time.Time { return base }
	stored, ok := h.device.deviceCodeByCode("master", dc.DeviceCode)
	if !ok {
		t.Fatal("the code just minted is not in the store")
	}

	poll := func(offset time.Duration) *httptest.ResponseRecorder {
		stored.LastPoll = base.Add(offset - time.Duration(dc.Interval)*time.Second)
		return postForm(t, router, "/realms/master/protocol/openid-connect/token",
			pollForm("dev-on", dc.DeviceCode))
	}
	// t=0: no previous poll at all, so never slow_down.
	stored.LastPoll = time.Time{}
	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, deviceErrAuthorizationPending, descAuthorizationPending)
	stamped := stored.LastPoll
	if stamped.IsZero() {
		t.Fatal("a poll that got as far as the pending answer did not stamp the clock")
	}

	// t=3 with interval 5: inside the window.
	wantOAuthError(t, poll(3*time.Second), http.StatusBadRequest, deviceErrSlowDown, descSlowDown)

	// The slow_down must not have moved it. Re-reading the stored value is the
	// whole assertion: if the handler stamped here, the next poll three seconds
	// later would be refused too.
	if got := stored.LastPoll; !got.Equal(base.Add(3*time.Second - time.Duration(dc.Interval)*time.Second)) {
		t.Fatalf("slow_down moved the poll clock to %v; measured, it leaves it alone", got)
	}
}

// TestAWrongClientDoesNotStampThePollClock is the second clock measurement,
// and it is the reason the client check sits in front of the interval check
// rather than after it.
//
// Measured live: three wrong-client polls in a row, then the right client
// immediately, answered authorization_pending rather than slow_down.
func TestAWrongClientDoesNotStampThePollClock(t *testing.T) {
	router, h, _, _ := deviceServer(t)
	dc := mintDeviceCode(t, router, "dev-on")
	tokenTarget := "/realms/master/protocol/openid-connect/token"

	for range 3 {
		wantOAuthError(t, postForm(t, router, tokenTarget, pollForm("dev-on2", dc.DeviceCode)),
			http.StatusBadRequest, "invalid_grant", descDeviceWrongClient)
	}
	stored, ok := h.device.deviceCodeByCode("master", dc.DeviceCode)
	if !ok {
		t.Fatal("the wrong-client polls consumed the code")
	}
	if !stored.LastPoll.IsZero() {
		t.Fatal("a wrong-client poll stamped the clock; measured, it does not")
	}
	wantOAuthError(t, postForm(t, router, tokenTarget, pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, deviceErrAuthorizationPending, descAuthorizationPending)
}

// TestExpiryBeatsTheInterval is the third clock measurement: an expired code
// polled twice in a row inside its interval answered expired_token both times,
// where a pending code answers slow_down on the second.
func TestExpiryBeatsTheInterval(t *testing.T) {
	router, h, _, _ := deviceServer(t)
	dc := mintDeviceCode(t, router, "dev-on")
	stored, _ := h.device.deviceCodeByCode("master", dc.DeviceCode)
	stored.ExpiresAt = time.Now().Add(-time.Second)
	stored.LastPoll = time.Now()

	for range 2 {
		wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
			pollForm("dev-on", dc.DeviceCode)),
			http.StatusBadRequest, deviceErrExpiredToken, descDeviceCodeExpired)
	}
}

// TestAnExpiredCodeStopsBeingFound is the grace window: expired_token is a
// window rather than a permanent state.
//
// Measured at three client lifespans - the answer turns into "Device code not
// valid" some seconds after the expiry, reproducibly, and fifteen seconds is
// inside all three brackets. The two obvious implementations get one end each:
// sweeping at expiry loses the expired_token answer the catalogue records, and
// never sweeping answers expired_token for ever.
func TestAnExpiredCodeStopsBeingFound(t *testing.T) {
	router, h, _, _ := deviceServer(t)
	dc := mintDeviceCode(t, router, "dev-on")
	stored, _ := h.device.deviceCodeByCode("master", dc.DeviceCode)
	stored.ExpiresAt = time.Now().Add(-time.Second)

	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, deviceErrExpiredToken, descDeviceCodeExpired)

	// Past the grace window the entry is gone, and the answer collapses onto
	// the one a code that never existed gets.
	stored.ExpiresAt = time.Now().Add(-deviceCodeGrace - time.Second)
	h.device.mu.Lock()
	h.device.sweepLocked()
	h.device.mu.Unlock()

	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, "invalid_grant", descDeviceCodeNotValid)
}

// TestADeniedCodeIsNotConsumed is the state a denial leaves behind: measured,
// a denied code answered access_denied on every later poll rather than becoming
// "not valid", which is what distinguishes a denial from a redemption.
//
// The poll interval still runs in front of it - the poll immediately after the
// denial answered slow_down live - so the branch order is asserted too.
func TestADeniedCodeIsNotConsumed(t *testing.T) {
	router, h, _, _ := deviceServer(t)
	dc := mintDeviceCode(t, router, "dev-on")
	if !h.device.denyDeviceCode(dc.UserCode) {
		t.Fatal("denyDeviceCode did not find the code it was given")
	}
	stored, _ := h.device.deviceCodeByCode("master", dc.DeviceCode)

	for range 3 {
		stored.LastPoll = time.Time{}
		wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
			pollForm("dev-on", dc.DeviceCode)),
			http.StatusBadRequest, deviceErrAccessDenied, descAccessDenied)
	}
	// And the interval is still in front of it.
	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, deviceErrSlowDown, descSlowDown)
}

// TestAnApprovedCodeIssuesTokensAndIsSpent is the success path, reached the way
// cut B's verification page will reach it.
//
// Nothing in this cut approves a device code over HTTP, because approving one
// means the verification page and the consent page. The grant itself is built
// and asserted here, so cut B adds pages rather than a grant.
func TestAnApprovedCodeIssuesTokensAndIsSpent(t *testing.T) {
	router, h, s, realm := deviceServer(t)
	ctx := context.Background()
	dc := mintDeviceCode(t, router, "dev-on")

	user, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	client, err := s.Clients().ByClientID(ctx, realm.ID, "dev-on")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	session, err := h.startSession(ctx, realm, client, user, "openid email profile")
	if err != nil {
		t.Fatalf("startSession: %v", err)
	}
	if !h.device.approveDeviceCode(dc.UserCode, user.ID, session.ID) {
		t.Fatal("approveDeviceCode did not find the code it was given")
	}

	w := postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode))
	body := decodeTokenResponse(t, w)
	if body.AccessToken == "" || body.RefreshToken == "" || body.IDToken == "" {
		t.Fatalf("the device grant's success is the ordinary nine keys; got %+v", body)
	}
	if body.SessionState != session.ID {
		t.Errorf("session_state: want %q, got %q", session.ID, body.SessionState)
	}

	// Measured: the poll after a successful exchange answers "Device code not
	// valid", so a redeemed code and one that never existed are one answer.
	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		pollForm("dev-on", dc.DeviceCode)),
		http.StatusBadRequest, "invalid_grant", descDeviceCodeNotValid)
}

// TestCIBAsTwoEndpointsShareOneStringAndNotOneStatus is CIBA's mirror-image
// finding: where the device grant's two endpoints agree on nothing, CIBA's
// agree on the sentence and the code and differ on the status.
//
// One shared constant is right here and wrong for the device grant, which is
// why there are three constants across the two files and not two.
func TestCIBAsTwoEndpointsShareOneStringAndNotOneStatus(t *testing.T) {
	router, _, _, _ := deviceServer(t)
	cibaPath := "/realms/master/protocol/openid-connect/ext/ciba/auth"

	wantOAuthError(t, postForm(t, router, cibaPath,
		url.Values{"client_id": {"dev-on"}, "scope": {"openid"}, "login_hint": {"admin"}}),
		http.StatusUnauthorized, "invalid_grant", descCIBAGrantOff)

	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {grantCIBA}, "client_id": {"dev-on"}}),
		http.StatusBadRequest, "invalid_grant", descCIBAGrantOff)
}

// TestCIBAsAuthenticationChannelIsUnconfigured is the 503 a fully valid CIBA
// request gets on a default 26.7.1, and it is a contract rather than a stub.
//
// The default ciba-http-auth-channel provider needs an external HTTP endpoint
// that start-dev does not configure, so there is no auth_req_id a default
// deployment could ever mint. That is why oidc/ciba/poll-pending and
// oidc/ciba/poll-complete are Pending as **unmeasurable** rather than as
// unimplemented.
func TestCIBAsAuthenticationChannelIsUnconfigured(t *testing.T) {
	router, _, _, _ := deviceServer(t)
	cibaPath := "/realms/master/protocol/openid-connect/ext/ciba/auth"
	valid := url.Values{"client_id": {"ciba-on"}, "client_secret": {"s3cret"},
		"scope": {"openid"}, "login_hint": {"admin"}}

	wantOAuthError(t, postForm(t, router, cibaPath, valid),
		http.StatusServiceUnavailable, cibaErrServerError, descCIBAChannelFailed)

	// The two parameter checks in front of it, whose descriptions carry a space
	// on both sides of the colon and are lower case - unlike every other
	// missing-parameter description on the protocol side, including the one the
	// CIBA grant itself uses one endpoint away.
	noScope := url.Values{"client_id": {"ciba-on"}, "client_secret": {"s3cret"}, "login_hint": {"admin"}}
	wantOAuthError(t, postForm(t, router, cibaPath, noScope),
		http.StatusBadRequest, authErrInvalidRequest, descCIBAMissingScope)

	noHint := url.Values{"client_id": {"ciba-on"}, "client_secret": {"s3cret"}, "scope": {"openid"}}
	wantOAuthError(t, postForm(t, router, cibaPath, noHint),
		http.StatusBadRequest, authErrInvalidRequest, descCIBAMissingHint)

	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {grantCIBA}, "client_id": {"ciba-on"}, "client_secret": {"s3cret"}}),
		http.StatusBadRequest, authErrInvalidRequest, descMissingAuthReqID)

	wantOAuthError(t, postForm(t, router, "/realms/master/protocol/openid-connect/token",
		url.Values{"grant_type": {grantCIBA}, "client_id": {"ciba-on"},
			"client_secret": {"s3cret"}, "auth_req_id": {"nope"}}),
		http.StatusBadRequest, "invalid_grant", descInvalidAuthReqID)
}
