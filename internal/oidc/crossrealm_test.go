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

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// The values this package derives from the realm name of the request.
//
// **Every other test file here builds nothing but bootstrap.EnsureMaster**, so
// a handler answering with the literal "master" compares equal to one deriving
// the name - and the conformance catalogue could not tell them apart either,
// because fifty-eight of the sixty goldens carrying a realm name address
// master. That is F142. Three of its sites were measured **survivors** on
// 2026-09-01: hard-coding master into registrationURI, into the device grant's
// verification_uri and into /auth's error-redirect iss left the whole tree
// green, all three at once.
//
// This file is where each of those fails. It is a second realm and four claims,
// one per site, plus the realm's two display fields, which is a fifth thing the
// page derives and which internal/httpx renders.
//
// A created realm is **not** master under another name, which is the trap this
// whole family of cuts keeps paying: it carries no displayName and no
// displayNameHtml, its admin container is realm-management rather than
// master-realm, and its registration endpoint refuses master's own
// administrator. See TestRegistrationURINamesTheRequestsRealm.

const (
	crossRealmName        = "gloak-probe-other"
	crossRealmRedirectURI = "http://localhost:9997/callback"
	crossRealmIssuerBase  = "http://localhost:8080"
)

// crossRealmServer is a bootstrapped master with a **second realm beside it**,
// created the way POST /admin/realms creates one, holding the two clients the
// claims below need.
//
// bootstrap.CreateRealm is what internal/admin's own cross-realm test uses, so
// the second realm here is the same object the Admin API would have made rather
// than a hand-built row.
func crossRealmServer(t *testing.T) (http.Handler, *handler, store.Store, *model.Realm) {
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
	second, err := bootstrap.CreateRealm(ctx, s, crossRealmName, nil)
	if err != nil {
		t.Fatalf("CreateRealm: %v", err)
	}
	clients := []*model.Client{
		{ClientID: "probe-device", Enabled: true, PublicClient: true,
			Attributes: map[string]string{attrDeviceGrantEnabled: "true"}},
		{ClientID: "probe-browser", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{crossRealmRedirectURI}},
		{ClientID: "probe-registered", Enabled: true, PublicClient: true,
			RedirectURIs: []string{crossRealmRedirectURI}},
	}
	for _, c := range clients {
		c.ID = model.NewID()
		c.RealmID = second.ID
		c.Protocol = "openid-connect"
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.ClientID, err)
		}
	}
	h := &handler{store: s, keys: keys.NewManager(s), issuerBase: crossRealmIssuerBase,
		auth: newAuthStore(), device: newDeviceStore(), consents: newConsentStore(),
		registrations: newRegistrationStore()}
	mux := http.NewServeMux()
	h.register(mux)
	return WithKeycloakFallbacks(mux), h, s, second
}

// crossRealmGet issues one GET and returns the response.
func crossRealmGet(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

// TestDeviceVerificationPageNamesTheRequestsRealm is site 14 of the derivation
// table.
//
// The form's action is `/realms/<realm>/device`, **relative, and not the path
// the request arrived on** - the page is byte-identical at both of its paths,
// measured 2026-09-01. Both halves of that need a second realm to be worth
// anything: on master the action, the arrival path and the literal are three
// spellings of one string.
func TestDeviceVerificationPageNamesTheRequestsRealm(t *testing.T) {
	h, _, _, _ := crossRealmServer(t)
	for _, path := range []string{
		"/realms/" + crossRealmName + "/device",
		"/realms/" + crossRealmName + "/protocol/openid-connect/auth/device",
	} {
		w := crossRealmGet(t, h, path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d: %s", path, w.Code, w.Body)
		}
		want := `action="/realms/` + crossRealmName + `/device"`
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: the page is missing %s", path, want)
		}
		if strings.Contains(w.Body.String(), "/realms/master/") {
			t.Errorf("%s: the page names master, which is not the realm it was asked about", path)
		}
	}
}

// TestDeviceAuthorizationNamesTheRequestsRealm is site 15, and a **measured
// survivor**: hard-coding master into verificationURI left the conformance
// suite, this package and internal/httpx green on 2026-09-01.
//
// Both URLs come from one expression, so one of them would be enough to catch a
// hard-coded literal. Both are asserted because they are two keys a client
// reads: verification_uri is what a device shows a person and
// verification_uri_complete is the only way a device login can actually be
// completed - the form on that page cannot be submitted, which is measured and
// is reproduced.
func TestDeviceAuthorizationNamesTheRequestsRealm(t *testing.T) {
	h, _, _, _ := crossRealmServer(t)
	w := postForm(t, h, "/realms/"+crossRealmName+"/protocol/openid-connect/auth/device",
		url.Values{"client_id": {"probe-device"}, "scope": {"openid"}})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var body deviceAuthorizationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse device authorization response: %v", err)
	}
	want := crossRealmIssuerBase + "/realms/" + crossRealmName + "/device"
	if body.VerificationURI != want {
		t.Errorf("verification_uri = %q, want %q", body.VerificationURI, want)
	}
	if got := body.VerificationURIComplete; got != want+"?user_code="+body.UserCode {
		t.Errorf("verification_uri_complete = %q, want %q", got, want+"?user_code="+body.UserCode)
	}
}

// TestRegistrationURINamesTheRequestsRealm is site 17, the second **measured
// survivor**, and the one with no conformance case behind it.
//
// **A second realm's registration endpoint refuses master's administrator.**
// Measured 2026-09-02 with a control: the bootstrapped administrator's bearer
// registers a client in master (201) and is refused in a created realm with
// `401 {"error":"invalid_token","error_description":"Failed decode token"}` -
// the same answer a garbage bearer gets, because the token is verified against
// the realm in the path. So the two credentials that can reach this endpoint in
// a second realm are an initial access token, which is
// POST /admin/realms/{r}/clients-initial-access and is an Admin API route Gloak
// does not serve, and a registration access token, which is the one used here.
// That is why the site is closed by this test and not by a golden.
//
// Two claims, because the builder and its wiring can fail apart: the function
// derives the path from the realm it is given, and the read hands it the realm
// of the request rather than a constant.
func TestRegistrationURINamesTheRequestsRealm(t *testing.T) {
	h, handle, s, second := crossRealmServer(t)
	ctx := context.Background()

	want := crossRealmIssuerBase + "/realms/" + crossRealmName +
		"/clients-registrations/openid-connect/probe-registered"
	if got := handle.registrationURI(crossRealmName, "probe-registered"); got != want {
		t.Errorf("registrationURI = %q, want %q", got, want)
	}

	client, err := s.Clients().ByClientID(ctx, second.ID, "probe-registered")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	k, err := handle.keys.ForRealm(ctx, second)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}
	rat, err := handle.mintRegistrationToken(second, client, k)
	if err != nil {
		t.Fatalf("mintRegistrationToken: %v", err)
	}
	w := registrationRequestOf(t, h, http.MethodGet,
		"/realms/"+crossRealmName+"/clients-registrations/openid-connect/probe-registered",
		rat, "", false)
	if w.Code != http.StatusOK {
		t.Fatalf("read: want 200, got %d: %s", w.Code, w.Body)
	}
	var body oidcClientRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse registration body: %v", err)
	}
	if body.RegistrationClientURI != want {
		t.Errorf("registration_client_uri = %q, want %q", body.RegistrationClientURI, want)
	}
}

// TestAuthorizationErrorRedirectNamesTheRequestsRealm is site 19, the third
// **measured survivor**.
//
// The iss is the one parameter of the four that a second realm can tell apart:
// error, error_description and state are the same bytes whatever realm asked.
// It is asserted as the whole parameter rather than by substring, because
// `iss=...` holding the right realm somewhere inside a wrong issuer would pass a
// looser check.
func TestAuthorizationErrorRedirectNamesTheRequestsRealm(t *testing.T) {
	h, _, _, _ := crossRealmServer(t)
	q := url.Values{
		"client_id":    {"probe-browser"},
		"redirect_uri": {crossRealmRedirectURI},
		"scope":        {"openid"},
		"state":        {"xyz123"},
	}
	w := crossRealmGet(t, h,
		"/realms/"+crossRealmName+"/protocol/openid-connect/auth?"+q.Encode())
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	want := "iss=" + url.QueryEscape(crossRealmIssuerBase+"/realms/"+crossRealmName)
	if !strings.HasSuffix(location, "&"+want) {
		t.Errorf("Location = %q, want it to end in &%s", location, want)
	}
}

// TestRealmDisplayReadsTheRealmsSettings is the fifth value a theme page
// derives from the realm, and the one that is not a URL.
//
// **master's two values live in code on both sides of the internal/admin
// boundary**, because internal/bootstrap writes no settings blob at all. This
// test is what says the two copies agree, and what says a created realm gets
// neither - which is the whole reason the page's title and brand fall back.
//
// The stored-blob rows are pointers on purpose: an absent key and a stored ""
// are two different states even though the page renders them the same way, and
// a `PUT {"displayName":""}` on master has to override master's default rather
// than read as "unset".
func TestRealmDisplayReadsTheRealmsSettings(t *testing.T) {
	_, _, s, second := crossRealmServer(t)
	master, err := s.Realms().ByName(context.Background(), bootstrap.MasterRealmName)
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if name, html := realmDisplay(master); name != masterDisplayName || html != masterDisplayNameHTML {
		t.Errorf("master = (%q, %q), want (%q, %q)", name, html,
			masterDisplayName, masterDisplayNameHTML)
	}
	if name, html := realmDisplay(second); name != "" || html != "" {
		t.Errorf("a created realm = (%q, %q), want neither value", name, html)
	}

	for _, tc := range []struct {
		name, settings, wantName, wantHTML string
		realm                              string
	}{
		{"a created realm with both", `{"displayName":"D","displayNameHtml":"<b>H</b>"}`,
			"D", "<b>H</b>", crossRealmName},
		{"a created realm with one", `{"displayName":"D"}`, "D", "", crossRealmName},
		{"master's blob overrides master's defaults", `{"displayName":"D"}`,
			"D", masterDisplayNameHTML, bootstrap.MasterRealmName},
		{"master cleared to an empty string", `{"displayName":"","displayNameHtml":""}`,
			"", "", bootstrap.MasterRealmName},
		{"a blob that will not decode", `{`, "", "", crossRealmName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			realm := &model.Realm{Name: tc.realm, Settings: []byte(tc.settings)}
			name, html := realmDisplay(realm)
			if name != tc.wantName || html != tc.wantHTML {
				t.Errorf("= (%q, %q), want (%q, %q)", name, html, tc.wantName, tc.wantHTML)
			}
		})
	}
}

// TestThemePagesNameTheRealmAndNotMaster covers the page's chrome end to end,
// which is site 13 and the one site F142's own cut pinned.
//
// It asserts three things at once because they are three lines of one page, and
// because a page that got two of them right and one wrong is exactly what this
// project shipped until 2026-09-02: the restart URL followed the realm and the
// title and the brand were master's constants.
func TestThemePagesNameTheRealmAndNotMaster(t *testing.T) {
	h, _, _, _ := crossRealmServer(t)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"nosuchclient"},
		"redirect_uri":  {crossRealmRedirectURI},
		"scope":         {"openid"},
		"state":         {"xyz123"},
	}
	w := crossRealmGet(t, h,
		"/realms/"+crossRealmName+"/protocol/openid-connect/auth?"+q.Encode())
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	page := w.Body.String()
	for _, want := range []string{
		"<title>Sign in to " + crossRealmName + "</title>",
		`class="pf-v5-c-brand">` + crossRealmName + `</div>`,
		`"/realms/` + crossRealmName + `/login-actions/restart?skip_logout=true"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing %s", want)
		}
	}
	for _, unwanted := range []string{"Keycloak", "kc-logo-text", "/realms/master/"} {
		if strings.Contains(page, unwanted) {
			t.Errorf("the page holds %q, which belongs to master and not to this realm", unwanted)
		}
	}
}
