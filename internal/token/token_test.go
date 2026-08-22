package token_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/token"
)

const issuer = "http://localhost:8080/realms/master"

func realmKeys(t *testing.T) *keys.RealmKeys {
	t.Helper()
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("keys.Generate: %v", err)
	}
	return k
}

// request builds an issuance request for an ordinary confidential client.
func request() token.Request {
	user := &model.User{ID: model.NewID(), Username: "admin", EmailVerified: true}
	return token.Request{
		Client: &model.Client{
			ID: model.NewID(), ClientID: "gloak-app", Enabled: true,
			WebOrigins: []string{"https://app.example"},
		},
		User: user,
		UserSession: &model.UserSession{
			ID: model.NewID(), UserID: user.ID, Username: "admin",
		},
		Scope:          "openid profile email",
		RealmRoles:     []string{"default-roles-master"},
		AccessLife:     60 * time.Second,
		RefreshLife:    1800 * time.Second,
		IncludeIDToken: true,
	}
}

// claimNames returns the payload's keys, sorted, so a claim set can be
// compared as a set rather than as an object.
func claimNames(t *testing.T, raw string) []string {
	t.Helper()
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload(t, raw), &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// payload decodes a compact JWS's claims without verifying it, which is what
// lets these tests look at the bytes rather than at what a parser chose to
// expose.
func payload(t *testing.T, raw string) []byte {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("want a compact JWS with three parts, got %d", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return body
}

func algorithmOf(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	head, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(head, &h); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return h.Alg
}

func issue(t *testing.T, k *keys.RealmKeys, r token.Request) token.Set {
	t.Helper()
	set, err := (&token.Issuer{Keys: k, Issuer: issuer}).Issue(r)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return set
}

func TestAccessTokenCarriesTheMeasuredClaimSet(t *testing.T) {
	// Measured in the "Claim sets" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. No golden
	// pins this: every token is Volatile in every recorded response, so this
	// test is the only thing holding the claim set in place.
	set := issue(t, realmKeys(t), request())

	want := []string{
		"acr", "allowed-origins", "aud", "azp", "email_verified", "exp", "iat",
		"iss", "jti", "preferred_username", "realm_access", "resource_access",
		"scope", "sid", "sub", "typ",
	}
	if got := claimNames(t, set.AccessToken); !equal(got, want) {
		t.Fatalf("access token claim set:\nwant %v\ngot  %v", want, got)
	}

	var claims struct {
		Typ string          `json:"typ"`
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload(t, set.AccessToken), &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	if claims.Typ != "Bearer" {
		t.Errorf("want typ Bearer, got %q", claims.Typ)
	}
	// aud is an array on the access token and a string on the ID token. That
	// asymmetry is Keycloak's and is measured.
	var audience []string
	if err := json.Unmarshal(claims.Aud, &audience); err != nil {
		t.Errorf("access token aud is not an array: %s", claims.Aud)
	}
}

func TestLightweightAccessTokenDropsSubAndAud(t *testing.T) {
	// admin-cli ships with this attribute, which is why the Admin API cannot
	// authorise from the token and has to resolve the session from sid.
	r := request()
	r.Client.Attributes = map[string]string{
		"client.use.lightweight.access.token.enabled": "true",
	}

	set := issue(t, realmKeys(t), r)

	want := []string{"azp", "exp", "iat", "iss", "jti", "scope", "sid", "typ"}
	if got := claimNames(t, set.AccessToken); !equal(got, want) {
		t.Fatalf("lightweight claim set:\nwant %v\ngot  %v", want, got)
	}
}

func TestIDTokenAudIsAStringNotAnArray(t *testing.T) {
	set := issue(t, realmKeys(t), request())

	want := []string{
		"acr", "at_hash", "aud", "azp", "email_verified", "exp", "iat", "iss",
		"jti", "preferred_username", "sid", "sub", "typ",
	}
	if got := claimNames(t, set.IDToken); !equal(got, want) {
		t.Fatalf("ID token claim set:\nwant %v\ngot  %v", want, got)
	}

	var claims struct {
		Typ string `json:"typ"`
		Aud string `json:"aud"`
	}
	if err := json.Unmarshal(payload(t, set.IDToken), &claims); err != nil {
		t.Fatalf("ID token aud is not a string: %v", err)
	}
	if claims.Typ != "ID" {
		t.Errorf("want typ ID, got %q", claims.Typ)
	}
	if claims.Aud != "gloak-app" {
		t.Errorf("want aud gloak-app, got %q", claims.Aud)
	}
}

func TestNoIDTokenWithoutTheOpenidScope(t *testing.T) {
	// Measured: the admin-cli password grant's response has no id_token key at
	// all. See internal/conformance/testdata/golden/oidc/token/password-grant-admin-cli.http.
	r := request()
	r.IncludeIDToken = false
	r.Scope = "profile email"

	set := issue(t, realmKeys(t), r)

	if set.IDToken != "" {
		t.Fatalf("an ID token was issued without the openid scope: %s", set.IDToken)
	}
}

func TestRefreshTokenIsSignedHS512AndCarriesAudX(t *testing.T) {
	set := issue(t, realmKeys(t), request())

	want := []string{
		"aud", "aud_x", "azp", "exp", "iat", "iss", "jti", "prov", "scope",
		"sid", "sub", "typ",
	}
	if got := claimNames(t, set.RefreshToken); !equal(got, want) {
		t.Fatalf("refresh token claim set:\nwant %v\ngot  %v", want, got)
	}
	if alg := algorithmOf(t, set.RefreshToken); alg != "HS512" {
		t.Errorf("want the refresh token signed HS512, got %s", alg)
	}

	var claims struct {
		Typ  string   `json:"typ"`
		Aud  string   `json:"aud"`
		AudX []string `json:"aud_x"`
		Prov string   `json:"prov"`
	}
	if err := json.Unmarshal(payload(t, set.RefreshToken), &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	if claims.Typ != "Refresh" {
		t.Errorf("want typ Refresh, got %q", claims.Typ)
	}
	if claims.Aud != issuer {
		t.Errorf("want aud %q, got %q", issuer, claims.Aud)
	}
	if claims.Prov != "default" {
		t.Errorf("want prov default, got %q", claims.Prov)
	}
	if len(claims.AudX) == 0 {
		t.Error("aud_x is empty; it carries what the access token puts in aud")
	}
}

func TestAccessAndIDTokensAreSignedRS256(t *testing.T) {
	// The mistake this catches is the two signers swapped, which leaves access
	// tokens symmetrically signed with a secret no client can check.
	set := issue(t, realmKeys(t), request())

	if alg := algorithmOf(t, set.AccessToken); alg != "RS256" {
		t.Errorf("want the access token signed RS256, got %s", alg)
	}
	if alg := algorithmOf(t, set.IDToken); alg != "RS256" {
		t.Errorf("want the ID token signed RS256, got %s", alg)
	}
}

func TestSignedTokensNameTheirKid(t *testing.T) {
	// A JWS with no kid forces a client to try every published key, and the
	// published set now has two.
	k := realmKeys(t)
	set := issue(t, k, request())

	jws, err := jose.ParseSigned(set.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	if got := jws.Signatures[0].Header.KeyID; got != k.RSAKeyID {
		t.Fatalf("want kid %q, got %q", k.RSAKeyID, got)
	}
}

func TestParseAccessReturnsWhatTheHandlersNeed(t *testing.T) {
	k := realmKeys(t)
	r := request()
	set := issue(t, k, r)

	got, err := token.ParseAccess(k, issuer, set.AccessToken, time.Now())

	if err != nil {
		t.Fatalf("ParseAccess: %v", err)
	}
	if got.Type != "Bearer" {
		t.Errorf("want type Bearer, got %q", got.Type)
	}
	if got.SessionID != r.UserSession.ID {
		t.Errorf("want sid %q, got %q", r.UserSession.ID, got.SessionID)
	}
	if got.ClientID != "gloak-app" {
		t.Errorf("want azp gloak-app, got %q", got.ClientID)
	}
	if got.Scope != "openid profile email" {
		t.Errorf("want the granted scope back, got %q", got.Scope)
	}
	if got.Subject != r.User.ID {
		t.Errorf("want sub %q, got %q", r.User.ID, got.Subject)
	}
}

func TestParseAccessRejectsATokenFromAnotherRealm(t *testing.T) {
	// Two realms, two key sets. A token one realm signed must not verify
	// against the other's key, whatever its claims say.
	set := issue(t, realmKeys(t), request())

	_, err := token.ParseAccess(realmKeys(t), issuer, set.AccessToken, time.Now())

	if !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestParseAccessRejectsAWrongIssuer(t *testing.T) {
	k := realmKeys(t)
	set := issue(t, k, request())

	_, err := token.ParseAccess(k, "http://localhost:8080/realms/other", set.AccessToken, time.Now())

	if !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestParseAccessRejectsAnExpiredToken(t *testing.T) {
	k := realmKeys(t)
	set := issue(t, k, request())

	_, err := token.ParseAccess(k, issuer, set.AccessToken, time.Now().Add(2*time.Minute))

	if !errors.Is(err, token.ErrExpiredToken) {
		t.Fatalf("want ErrExpiredToken, got %v", err)
	}
}

func TestParseAccessRejectsRubbish(t *testing.T) {
	// "not-a-token" is what oidc/userinfo/invalid-token and
	// oidc/revocation/unknown-token send.
	_, err := token.ParseAccess(realmKeys(t), issuer, "not-a-token", time.Now())

	if !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestParseRefreshRejectsAnAccessToken(t *testing.T) {
	// Same realm, same issuer, valid signature - and still the wrong token.
	// Without the typ check, an access token would refresh a session.
	k := realmKeys(t)
	set := issue(t, k, request())

	_, err := token.ParseRefresh(k, issuer, set.AccessToken, time.Now())

	if !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestParseAccessRejectsARefreshToken(t *testing.T) {
	k := realmKeys(t)
	set := issue(t, k, request())

	_, err := token.ParseAccess(k, issuer, set.RefreshToken, time.Now())

	if !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestParseRefreshAcceptsARefreshToken(t *testing.T) {
	k := realmKeys(t)
	r := request()
	set := issue(t, k, r)

	got, err := token.ParseRefresh(k, issuer, set.RefreshToken, time.Now())

	if err != nil {
		t.Fatalf("ParseRefresh: %v", err)
	}
	if got.Type != "Refresh" || got.SessionID != r.UserSession.ID {
		t.Fatalf("refresh token parsed wrong: %+v", got)
	}
}

func equal(a, b []string) bool {
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
