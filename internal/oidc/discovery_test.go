package oidc_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newServer(t *testing.T) http.Handler {
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
	k, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return oidc.NewRouter(s, k, "http://localhost:8080")
}

func TestDiscoveryKeySetMatchesKeycloak(t *testing.T) {
	raw, err := os.ReadFile("testdata/discovery-26.7.1.json")
	if err != nil {
		t.Fatalf("read reference: %v", err)
	}
	var reference map[string]any
	if err := json.Unmarshal(raw, &reference); err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	var missing []string
	for k := range reference {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("discovery is missing %d keys Keycloak emits: %v", len(missing), missing)
	}
}

// topLevelKeyOrder walks a JSON object's top-level keys in the order they
// appear in raw, without sorting them the way unmarshalling into a Go map
// would. dec.More paired with decoding each value into json.RawMessage
// advances past nested objects and arrays without needing to parse them.
func topLevelKeyOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("read opening token: %v", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		t.Fatalf("want a top-level JSON object, got %v", tok)
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			t.Fatalf("read key: %v", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			t.Fatalf("want a string key, got %v", keyTok)
		}
		keys = append(keys, key)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("skip value for %q: %v", key, err)
		}
	}
	return keys
}

// TestDiscoveryKeyOrderMatchesKeycloak pins the discovery document's field
// order, byte position by byte position, against
// testdata/discovery-26.7.1.json - the order captured from a live Keycloak
// 26.7.1 instance. Go marshals map[string]any alphabetically, which does not
// match Keycloak's order (it begins with "issuer", not "acr_values_supported");
// this test would fail against a map-based implementation, and only passes
// against a struct whose fields are declared in the captured order.
func TestDiscoveryKeyOrderMatchesKeycloak(t *testing.T) {
	raw, err := os.ReadFile("testdata/discovery-26.7.1.json")
	if err != nil {
		t.Fatalf("read reference: %v", err)
	}
	want := topLevelKeyOrder(t, raw)

	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	newServer(t).ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	got := topLevelKeyOrder(t, w.Body.Bytes())

	for i := range want {
		if i >= len(got) {
			t.Fatalf("response has only %d keys, want at least %d; first missing at position %d: %q",
				len(got), len(want), i, want[i])
		}
		if got[i] != want[i] {
			t.Fatalf("key order mismatch at position %d: want %q, got %q\nwant order: %v\ngot order:  %v",
				i, want[i], got[i], want, got)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("key count mismatch: want %d, got %d\ngot order: %v", len(want), len(got), got)
	}
}

// TestSuccessBodyEndsWithoutTrailingNewline proves the discovery response
// ends with '}', not the newline json.Encoder.Encode appends. Keycloak sends
// no trailing newline; a router-local writer that skips package httpx's
// trimming step would fail this.
func TestSuccessBodyEndsWithoutTrailingNewline(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	body := w.Body.Bytes()
	if len(body) == 0 || body[len(body)-1] != '}' {
		t.Fatalf("success body must end with '}', got: %q", body)
	}
}

func TestDiscoveryEndpointsUseTheConfiguredIssuer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"issuer":                 "http://localhost:8080/realms/master",
		"authorization_endpoint": "http://localhost:8080/realms/master/protocol/openid-connect/auth",
		"token_endpoint":         "http://localhost:8080/realms/master/protocol/openid-connect/token",
		"jwks_uri":               "http://localhost:8080/realms/master/protocol/openid-connect/certs",
		"userinfo_endpoint":      "http://localhost:8080/realms/master/protocol/openid-connect/userinfo",
		"end_session_endpoint":   "http://localhost:8080/realms/master/protocol/openid-connect/logout",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: want %q, got %q", k, v, got[k])
		}
	}
}

func TestDiscoveryForUnknownRealm(t *testing.T) {
	// Measured: 404 with the bare-error shape and this exact message.
	req := httptest.NewRequest(http.MethodGet,
		"/realms/nosuchrealm/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm does not exist"}`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestJWKSServesOneRSAKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/certs", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want one key, got %d", len(set.Keys))
	}
	if set.Keys[0].Kty != "RSA" || set.Keys[0].Alg != "RS256" || set.Keys[0].Use != "sig" {
		t.Fatalf("unexpected key: %+v", set.Keys[0])
	}
}
