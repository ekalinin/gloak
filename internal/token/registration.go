package token

import (
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
)

// TypeRegistration is the typ of the token dynamic client registration hands
// back with a newly registered client, and demands on every later request about
// it. Measured 2026-08-31 by decoding a live one:
//
//	{"exp":0,"iat":1788251317,"jti":"78c80870-…","iss":"…/realms/master",
//	 "aud":"…/realms/master","typ":"RegistrationAccessToken",
//	 "registration_auth":"authenticated","allowed-origins":[]}
//
// Three things about it are measured rather than assumed.
//
//   - **exp is 0 and the token does not expire.** Every other token this
//     project mints carries a real exp and check() refuses an expired one, so
//     this type cannot go through check(): a zero exp is in the past.
//   - **aud is the realm's issuer URL**, the same string as iss, and a bare
//     string rather than the access token's absent/string/array rule.
//   - **registration_auth is "authenticated" whichever credential minted it.**
//     An initial access token and an administrator's access token were measured
//     side by side and both produce that value, so nothing in the token says
//     which of the two the caller used.
const TypeRegistration = "RegistrationAccessToken"

// registrationAuthAuthenticated is the only value of registration_auth this
// project can produce, because both measured credentials produce it. Keycloak's
// enumeration has an anonymous member; no probe reached it.
const registrationAuthAuthenticated = "authenticated"

// registrationClaims is the registration access token's claim set in the
// measured key order.
//
// allowed-origins is an empty array rather than absent, which is the opposite
// of the access token's rule - there the claim is dropped when the client has
// no web origins. Two tokens, one claim name, opposite treatments of empty.
type registrationClaims struct {
	Exp              int64    `json:"exp"`
	Iat              int64    `json:"iat"`
	Jti              string   `json:"jti"`
	Iss              string   `json:"iss"`
	Aud              string   `json:"aud"`
	Typ              string   `json:"typ"`
	RegistrationAuth string   `json:"registration_auth"`
	AllowedOrigins   []string `json:"allowed-origins"`
}

// IssueRegistration mints a registration access token carrying id as its jti.
//
// The caller keeps the jti, because that is the only thing that tells one of
// these tokens from another: they carry no subject, no client and no expiry, so
// a token is current exactly while the server still recognises its jti. A PUT
// rotates it, measured.
//
// It is signed HS512 with the realm's HMAC secret, the same key the refresh
// token uses - read off the wire, whose header names the realm's HMAC kid.
func IssueRegistration(k *keys.RealmKeys, issuer, id string, now time.Time) (string, error) {
	signer, err := k.HMACSigner()
	if err != nil {
		return "", err
	}
	return sign(signer, registrationClaims{
		Exp:              0,
		Iat:              now.UTC().Unix(),
		Jti:              id,
		Iss:              issuer,
		Aud:              issuer,
		Typ:              TypeRegistration,
		RegistrationAuth: registrationAuthAuthenticated,
		AllowedOrigins:   []string{},
	})
}

// ParseRegistration verifies a registration access token and returns its jti.
//
// It deliberately does not call check(): that helper refuses a token whose exp
// has passed, and this token's exp is 0, so every one of them would be expired
// the moment it was minted. What is asserted instead is everything else a
// signature does not say - the realm's own HMAC key, the realm's issuer and the
// typ - and the jti is then the caller's to recognise or not.
func ParseRegistration(k *keys.RealmKeys, issuer, raw string) (string, error) {
	claims, err := verify(raw, []jose.SignatureAlgorithm{jose.HS512}, k.HMACSecret())
	if err != nil {
		return "", err
	}
	if claims.Iss != issuer || claims.Typ != TypeRegistration || claims.Jti == "" {
		return "", ErrInvalidToken
	}
	return claims.Jti, nil
}
