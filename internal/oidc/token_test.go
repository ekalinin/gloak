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
