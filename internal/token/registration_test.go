package token

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/keys"
)

// These tests are in package token rather than token_test, which every other
// test in this package is in. The reason is the last case below: telling a
// registration access token from a refresh token means minting a refresh token
// with the same key, and refreshClaims is unexported. Asserting only what the
// exported surface can reach would leave the type check - the one thing a
// shared HS512 key makes necessary - unpinned.
func testRealmKeys(t *testing.T) *keys.RealmKeys {
	t.Helper()
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("keys.Generate: %v", err)
	}
	return k
}

// TestIssueRegistrationEmitsTheMeasuredClaims pins the claim set and its order.
// The token is opaque to every client, so nothing else in this repository would
// notice it changing.
func TestIssueRegistrationEmitsTheMeasuredClaims(t *testing.T) {
	k := testRealmKeys(t)
	const issuer = "http://localhost:8080/realms/master"
	raw, err := IssueRegistration(k, issuer, "78c80870-637c-6565-6a79-49d590e8f752",
		time.Unix(1788251317, 0))
	if err != nil {
		t.Fatalf("IssueRegistration: %v", err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", raw)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	want := `{"exp":0,"iat":1788251317,"jti":"78c80870-637c-6565-6a79-49d590e8f752",` +
		`"iss":"http://localhost:8080/realms/master",` +
		`"aud":"http://localhost:8080/realms/master","typ":"RegistrationAccessToken",` +
		`"registration_auth":"authenticated","allowed-origins":[]}`
	if string(payload) != want {
		t.Errorf("claims differ\nwant: %s\ngot:  %s", want, payload)
	}
	// aud is a bare string, not the access token's absent/string/array rule,
	// and it is the issuer rather than a client. Asserted separately so a
	// change to audienceClaim cannot quietly reach this token.
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := claims["aud"].(string); !ok {
		t.Errorf("aud must be a bare string, got %T", claims["aud"])
	}
	if _, ok := claims["allowed-origins"].([]any); !ok {
		t.Errorf("allowed-origins must be an empty array rather than absent, got %T",
			claims["allowed-origins"])
	}
}

// TestParseRegistrationReturnsTheJti is the whole mechanism: the token carries
// no subject and no client, so recognising the jti is the only thing that says
// which client it belongs to and whether it is still current.
func TestParseRegistrationReturnsTheJti(t *testing.T) {
	k := testRealmKeys(t)
	const issuer = "http://localhost:8080/realms/master"
	raw, err := IssueRegistration(k, issuer, "the-jti", time.Now())
	if err != nil {
		t.Fatalf("IssueRegistration: %v", err)
	}
	jti, err := ParseRegistration(k, issuer, raw)
	if err != nil {
		t.Fatalf("ParseRegistration: %v", err)
	}
	if jti != "the-jti" {
		t.Errorf("jti: want the-jti, got %q", jti)
	}
}

// TestParseRegistrationDoesNotExpire is why this type does not go through
// check(): its exp is 0, so every one of these tokens would be expired the
// moment it was minted.
func TestParseRegistrationDoesNotExpire(t *testing.T) {
	k := testRealmKeys(t)
	const issuer = "http://localhost:8080/realms/master"
	raw, err := IssueRegistration(k, issuer, "the-jti", time.Now().Add(-100*time.Hour))
	if err != nil {
		t.Fatalf("IssueRegistration: %v", err)
	}
	if _, err := ParseRegistration(k, issuer, raw); err != nil {
		t.Errorf("a registration access token never expires, got %v", err)
	}
}

// TestParseRegistrationRefusesWhatASignatureDoesNotAssert covers the three
// things left over: the wrong issuer, the wrong type, and a token signed with
// the RSA key rather than the HMAC one.
func TestParseRegistrationRefusesWhatASignatureDoesNotAssert(t *testing.T) {
	k := testRealmKeys(t)
	const issuer = "http://localhost:8080/realms/master"
	raw, err := IssueRegistration(k, issuer, "the-jti", time.Now())
	if err != nil {
		t.Fatalf("IssueRegistration: %v", err)
	}
	if _, err := ParseRegistration(k, "http://localhost:8080/realms/other", raw); err == nil {
		t.Error("a token from another realm's issuer must be refused")
	}
	// A refresh token is HS512 over the same key and is the wrong typ, which is
	// the confusion this check exists to prevent.
	i := &Issuer{Keys: k, Issuer: issuer}
	refresh, err := i.signHMAC(refreshClaims{Iss: issuer, Typ: TypeRefresh, Jti: "x"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ParseRegistration(k, issuer, refresh); err == nil {
		t.Error("a refresh token must not pass as a registration access token")
	}
	// And a token with the right typ and no jti says nothing about which client
	// it belongs to, so it cannot be current.
	empty, err := i.signHMAC(registrationClaims{Iss: issuer, Aud: issuer, Typ: TypeRegistration})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := ParseRegistration(k, issuer, empty); err == nil {
		t.Error("a registration access token with no jti must be refused")
	}
}
