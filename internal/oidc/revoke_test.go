package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// TestRevocationEndsTheSession is what the golden cannot see: its body is
// empty, so a handler that answered 200 and did nothing would match it
// exactly.
func TestRevocationEndsTheSession(t *testing.T) {
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	issued := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("")))

	w := postForm(t, router, "/realms/master/protocol/openid-connect/revoke", url.Values{
		"client_id": {"admin-cli"},
		"token":     {issued.RefreshToken},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("want an empty body, got %q", w.Body)
	}
	if _, err := s.Sessions().UserSessionByID(context.Background(), realm.ID, issued.SessionState); err == nil {
		t.Fatal("the session survived its own revocation")
	}

	// And the refresh token it revoked no longer works.
	//
	// The message is "Session not active", not "Invalid refresh token".
	// Measured 2026-08-23 against the reference container, on a token whose
	// session had been ended by revocation and again on one ended by an admin
	// logout - both say this, while the garbage token recorded in P1's
	// oidc/token/invalid-refresh-token golden still says the other. This
	// assertion carried P1's guess until then.
	refreshed := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"admin-cli"},
		"refresh_token": {issued.RefreshToken},
	})
	assertOAuthError(t, refreshed, http.StatusBadRequest, "invalid_grant", "Session not active")
}

func TestRevocationRejectsAnotherClientsToken(t *testing.T) {
	// Without the azp check, any client could end another client's session by
	// replaying a token it had seen.
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

	w := postForm(t, router, "/realms/master/protocol/openid-connect/revoke", url.Values{
		"client_id": {"other-cli"},
		"token":     {issued.RefreshToken},
	})

	// Measured shape for a token this endpoint will not act on: 200 with an
	// error body.
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	if _, err := s.Sessions().UserSessionByID(context.Background(), realm.ID, issued.SessionState); err != nil {
		t.Fatal("another client revoked this session")
	}
}

func TestIntrospectionRefusesAPublicClient(t *testing.T) {
	// Measured while recording P1's contract, and recorded in the observed
	// document's "Revocation accepts a public client; introspection does not"
	// section. It has no golden of its own: reaching one needs a confidential
	// client with a known secret, which is P2.
	h, s, _ := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)

	w := postForm(t, router, "/realms/master/protocol/openid-connect/token/introspect", url.Values{
		"client_id": {"admin-cli"},
		"token":     {"not-a-token"},
	})

	assertOAuthError(t, w, http.StatusForbidden, "invalid_request", "Client not allowed.")
}

func TestIntrospectionReportsALiveTokenActive(t *testing.T) {
	// The response body's shape is unmeasured, so this asserts only the one
	// field RFC 7662 makes mandatory, and that revocation flips it.
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	ctx := context.Background()
	if err := s.Clients().Create(ctx, &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-app",
		Enabled: true, Secret: "s3cret",
	}); err != nil {
		t.Fatalf("Clients().Create: %v", err)
	}
	issued := decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", passwordGrantForm("")))

	if !introspectActive(t, router, issued.AccessToken) {
		t.Fatal("a freshly issued access token introspected as inactive")
	}

	postForm(t, router, "/realms/master/protocol/openid-connect/revoke", url.Values{
		"client_id": {"admin-cli"},
		"token":     {issued.RefreshToken},
	})

	if introspectActive(t, router, issued.AccessToken) {
		t.Fatal("a revoked token still introspects as active")
	}
}

func introspectActive(t *testing.T, router http.Handler, tok string) bool {
	t.Helper()
	w := postForm(t, router, "/realms/master/protocol/openid-connect/token/introspect", url.Values{
		"client_id":     {"gloak-app"},
		"client_secret": {"s3cret"},
		"token":         {tok},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 from introspection, got %d: %s", w.Code, w.Body)
	}
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse introspection body: %v", err)
	}
	return body.Active
}
