package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// TestRelyingPartyAcceptsOurIDToken runs coreos/go-oidc, an implementation
// with none of this project's assumptions in it, against a live in-process
// Gloak. It fetches the discovery document, fetches the JWKS, picks the right
// key by kid, verifies the ID token's signature, issuer, audience and expiry,
// and recomputes at_hash against the access token.
//
// None of that is reachable from a golden diff, which sees every token as
// {{string}} and never parses one. This is layer 3 of the P1 design's test
// plan and section 10 of the original design, which specified it and never
// got it.
func TestRelyingPartyAcceptsOurIDToken(t *testing.T) {
	// The router needs the issuer at construction and httptest only reveals
	// its URL after Start, so the handler is installed through a variable the
	// server dereferences per request. go-oidc rejects a discovery document
	// whose issuer differs from the URL it fetched, so the two have to agree
	// exactly.
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	handler = NewRouter(s, keys.NewManager(s), srv.URL)

	body := passwordGrantOver(t, srv.URL)

	provider, err := gooidc.NewProvider(ctx, srv.URL+"/realms/master")
	if err != nil {
		t.Fatalf("an independent relying party could not read our discovery document: %v", err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: "admin-cli"})

	idToken, err := verifier.Verify(ctx, body.IDToken)
	if err != nil {
		t.Fatalf("an independent relying party rejected our ID token: %v", err)
	}
	if err := idToken.VerifyAccessToken(body.AccessToken); err != nil {
		t.Fatalf("at_hash does not match the access token it was computed over: %v", err)
	}
	if idToken.Subject == "" {
		t.Error("the verified ID token carries no subject")
	}
}

// passwordGrantOver runs the admin-cli password grant against a real server
// rather than a recorder, since go-oidc needs a URL to fetch from anyway.
func passwordGrantOver(t *testing.T, base string) tokenResponse {
	t.Helper()
	form := passwordGrantForm("openid")
	resp, err := http.Post(base+"/realms/master/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200 from the token endpoint, got %d", resp.StatusCode)
	}
	var body tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	if body.IDToken == "" {
		t.Fatal("no id_token to hand the relying party")
	}
	return body
}
