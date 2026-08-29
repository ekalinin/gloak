package token

import (
	"time"

	"github.com/ekalinin/gloak/internal/keys"
)

// identityClaims is the payload of the KEYCLOAK_IDENTITY cookie a successful
// browser login sets.
//
// The key set and its order are measured on a live 26.7.1 login on 2026-08-30:
// exp, iat, jti, iss, sub, typ, sid, state_checker - eight keys, with `typ`
// spelled `Serialized-ID` and `sid` carrying the same value the redirect's
// session_state carries. exp - iat measured 36000.
//
// It is signed **HS512**, like the refresh token and unlike the access and ID
// tokens: the cookie's JOSE header measured
// {"alg":"HS512","typ":"JWT","kid":"<the realm's HMAC kid>"}. That is why a
// realm holds two keys, and it is the same signer refreshClaims already uses.
type identityClaims struct {
	Expiry       int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	ID           string `json:"jti"`
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
	Type         string `json:"typ"`
	SessionID    string `json:"sid"`
	StateChecker string `json:"state_checker"`
}

// SerializedIDType is the `typ` the identity cookie carries. It is not one of
// the three token types internal/token otherwise mints, and it is never
// accepted at any endpoint - a cookie is not a bearer token.
const SerializedIDType = "Serialized-ID"

// IdentityCookieLifespan is exp - iat on the measured cookie: ten hours, which
// is Keycloak's default ssoSessionMaxLifespan.
const IdentityCookieLifespan = 36000 * time.Second

// IssueIdentityCookie signs the KEYCLOAK_IDENTITY value for a session that has
// just been established.
//
// stateChecker is an opaque per-session value in the measured payload. Keycloak
// uses it to guard its own account-console forms against CSRF; nothing Gloak
// serves reads it back, so it is stored as minted rather than given a meaning
// this project cannot observe.
func IssueIdentityCookie(k *keys.RealmKeys, issuer, subject, sessionID, jti, stateChecker string, now time.Time) (string, error) {
	signer, err := k.HMACSigner()
	if err != nil {
		return "", err
	}
	return sign(signer, identityClaims{
		Expiry:       now.Add(IdentityCookieLifespan).Unix(),
		IssuedAt:     now.Unix(),
		ID:           jti,
		Issuer:       issuer,
		Subject:      subject,
		Type:         SerializedIDType,
		SessionID:    sessionID,
		StateChecker: stateChecker,
	})
}
