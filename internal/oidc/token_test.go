package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/token"
)

// postForm runs a form POST against a handler and returns the recorder.
func postForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeTokenResponse(t *testing.T, w *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var body tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body
}

func passwordGrantForm(scope string) url.Values {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// TestPasswordGrantIssuesTokensThatVerify is what the conformance case cannot
// check: every token in that golden is masked to {{string}}, so an endpoint
// returning empty strings would still match it byte for byte.
func TestPasswordGrantIssuesTokensThatVerify(t *testing.T) {
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	body := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("")))

	k, err := h.keys.ForRealm(context.Background(), realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}
	issuer := "http://localhost:8080/realms/master"
	access, err := token.ParseAccess(k, issuer, body.AccessToken, time.Now())
	if err != nil {
		t.Fatalf("the access token this endpoint issued does not verify: %v", err)
	}
	if access.SessionID != body.SessionState {
		t.Errorf("sid %q and session_state %q disagree", access.SessionID, body.SessionState)
	}
	if access.ClientID != "admin-cli" {
		t.Errorf("want azp admin-cli, got %q", access.ClientID)
	}
	if _, err := token.ParseRefresh(k, issuer, body.RefreshToken, time.Now()); err != nil {
		t.Fatalf("the refresh token this endpoint issued does not verify: %v", err)
	}
	if body.IDToken != "" {
		t.Errorf("an ID token was issued without the openid scope: %q", body.IDToken)
	}
}

func TestPasswordGrantWithOpenidScopeIssuesAnIDToken(t *testing.T) {
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	body := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("openid")))

	if body.IDToken == "" {
		t.Fatal("no id_token was issued for a request carrying the openid scope")
	}
	if !hasScope(body.Scope, "openid") {
		t.Fatalf("openid missing from the granted scope %q", body.Scope)
	}
}

func TestRefreshGrantKeepsTheSessionAndItsScope(t *testing.T) {
	// The conformance golden masks both tokens, so it cannot see that a
	// refresh reuses the session it was issued against rather than starting a
	// new one - which is what makes sid stable for the whole SSO session.
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	first := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("openid")))

	second := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {"admin-cli"},
			"refresh_token": {first.RefreshToken},
		}))

	if second.SessionState != first.SessionState {
		t.Errorf("the refresh started a new session: %q then %q",
			first.SessionState, second.SessionState)
	}
	if second.Scope != first.Scope {
		t.Errorf("granted scope changed on refresh: %q then %q", first.Scope, second.Scope)
	}
	k, err := h.keys.ForRealm(context.Background(), realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}
	if _, err := token.ParseAccess(k, "http://localhost:8080/realms/master",
		second.AccessToken, time.Now()); err != nil {
		t.Fatalf("the refreshed access token does not verify: %v", err)
	}
}

func TestRefreshGrantRejectsAnotherClientsToken(t *testing.T) {
	// A refresh token names its client in azp. Without that check, any client
	// that got hold of the string could refresh somebody else's session.
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	if err := s.Clients().Create(context.Background(), &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "other-cli",
		Enabled: true, PublicClient: true,
	}); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}
	issued := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("")))

	w := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"other-cli"},
		"refresh_token": {issued.RefreshToken},
	})

	assertOAuthError(t, w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
}

func TestClientCredentialsGrantIsOnlyForServiceAccountClients(t *testing.T) {
	// The response body this grant returns is unmeasured, so nothing here
	// asserts its shape - only who is allowed to ask for it.
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	ctx := context.Background()
	clients := []*model.Client{
		{ID: model.NewID(), RealmID: realm.ID, ClientID: "svc", Enabled: true,
			Secret: "s3cret", ServiceAccountsEnabled: true},
		{ID: model.NewID(), RealmID: realm.ID, ClientID: "no-svc", Enabled: true,
			Secret: "s3cret"},
	}
	for _, c := range clients {
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create(%s): %v", c.ClientID, err)
		}
	}

	granted := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc"},
		"client_secret": {"s3cret"},
	})
	if granted.Code != http.StatusOK {
		t.Fatalf("a service-account client was refused: %d %s", granted.Code, granted.Body)
	}

	refused := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"no-svc"},
		"client_secret": {"s3cret"},
	})
	assertOAuthError(t, refused, http.StatusBadRequest, "unauthorized_client",
		"Client not enabled to retrieve service account")

	// A public client cannot use it either: it has no credentials of its own
	// to act on behalf of.
	public := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"admin-cli"},
	})
	assertOAuthError(t, public, http.StatusBadRequest, "unauthorized_client",
		"Client not enabled to retrieve service account")
}

func assertOAuthError(t *testing.T, w *httptest.ResponseRecorder, status int, code, description string) {
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

// TestPasswordGrantRecordsTheSession pins what P2 depends on: an admin-cli
// access token carries no sub, so the only way back to the user is the session
// named by sid.
func TestPasswordGrantRecordsTheSession(t *testing.T) {
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	body := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("")))

	ctx := context.Background()
	session, err := s.Sessions().UserSessionByID(ctx, realm.ID, body.SessionState)
	if err != nil {
		t.Fatalf("the grant issued a token for a session it did not store: %v", err)
	}
	if session.Username != "admin" {
		t.Fatalf("wrong session: %+v", session)
	}
	client, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	clientSession, err := s.Sessions().ClientSession(ctx, session.ID, client.ID)
	if err != nil {
		t.Fatalf("no client session was recorded: %v", err)
	}
	if clientSession.Scope != body.Scope {
		t.Fatalf("stored scope %q differs from the granted scope %q",
			clientSession.Scope, body.Scope)
	}
}
