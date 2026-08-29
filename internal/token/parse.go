package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
)

var (
	// ErrInvalidToken covers every way a token fails to be one: rubbish
	// input, the wrong signature, another realm's key, the wrong issuer, the
	// wrong typ.
	ErrInvalidToken = errors.New("token: invalid")
	// ErrExpiredToken is a token that was valid and is not any more. It is
	// separate from ErrInvalidToken because the endpoints answer the two
	// differently.
	ErrExpiredToken = errors.New("token: expired")
)

// Parsed is what a verified token carries. Subject is empty for a lightweight
// access token, which has no sub; callers resolve the user through SessionID
// instead.
//
// Audience is what the token's aud claim named, normalised to a list: the
// claim is a string when it names one client and an array when it names
// several, and absent when it names none. Introspection has to compare against
// it, so the three shapes cannot stay the caller's problem.
type Parsed struct {
	Type      string
	Subject   string
	SessionID string
	ClientID  string // azp
	ID        string // jti
	Audience  []string
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// UnverifiedIssuer reads the iss claim **without checking the signature**, so
// that a caller holding a token from an unknown realm can find out which
// realm's key to verify it with.
//
// It is safe for that one use and for nothing else. Nothing may be authorised
// on its result: it selects a key, and ParseAccess then rejects the token if
// the signature, the issuer, the type or the expiry disagrees. A caller that
// trusted this value instead of verifying afterwards would accept any token
// anybody wrote.
//
// The admin API needs it because a request to /admin/realms/{realm} may carry a
// token from that realm or from master - measured - and neither the path nor
// the key is known before the issuer is.
func UnverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidToken
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss == "" {
		return "", ErrInvalidToken
	}
	return claims.Iss, nil
}

// ParseAccess verifies an RS256 access token issued by this realm.
func ParseAccess(k *keys.RealmKeys, issuer, raw string, now time.Time) (*Parsed, error) {
	claims, err := verify(raw, []jose.SignatureAlgorithm{jose.RS256}, k.SigningPublicKey())
	if err != nil {
		return nil, err
	}
	return check(claims, issuer, TypeAccess, now)
}

// ParseID verifies an RS256 ID token issued by this realm and **does not check
// whether it has expired**.
//
// The omission is measured, not an oversight. Its one caller is the logout
// endpoint's id_token_hint, and a client pinned to access.token.lifespan=1,
// waited out past its ID token's own exp, still logged out and still redirected
// on a live 26.7.1 (2026-08-29). Routing this through ParseAccess's check and
// then forgiving ErrExpiredToken would be the same behaviour written so that
// the next reader has to reconstruct which of the two endpoints wanted it.
//
// Everything a valid signature does not assert is still asserted: the realm's
// own key, the realm's issuer, and typ=ID - so an access token or a refresh
// token offered as a hint is refused, which is measured too.
func ParseID(k *keys.RealmKeys, issuer, raw string) (*Parsed, error) {
	claims, err := verify(raw, []jose.SignatureAlgorithm{jose.RS256}, k.SigningPublicKey())
	if err != nil {
		return nil, err
	}
	if claims.Iss != issuer || claims.Typ != TypeID {
		return nil, ErrInvalidToken
	}
	return &Parsed{
		Type:      claims.Typ,
		Subject:   claims.Sub,
		SessionID: claims.Sid,
		ClientID:  claims.Azp,
		ID:        claims.Jti,
		Audience:  parseAudience(claims.Aud),
		Scope:     claims.Scope,
		IssuedAt:  time.Unix(claims.Iat, 0),
		ExpiresAt: time.Unix(claims.Exp, 0),
	}, nil
}

// ParseRefresh verifies an HS512 refresh token issued by this realm. The
// algorithm list is separate from ParseAccess's on purpose: accepting RS256
// here would let an access token stand in for a refresh token, and accepting
// HS512 there would let anybody holding the symmetric secret mint access
// tokens.
func ParseRefresh(k *keys.RealmKeys, issuer, raw string, now time.Time) (*Parsed, error) {
	claims, err := verify(raw, []jose.SignatureAlgorithm{jose.HS512}, k.HMACSecret())
	if err != nil {
		return nil, err
	}
	return check(claims, issuer, TypeRefresh, now)
}

// verify parses and checks the signature. The permitted algorithms are passed
// in rather than read from the token's own header: trusting a token's alg is
// the classic JWT confusion bug, and go-jose requires the list precisely so
// that mistake cannot be made by omission.
func verify(raw string, algs []jose.SignatureAlgorithm, key any) (*parsedClaims, error) {
	jws, err := jose.ParseSigned(raw, algs)
	if err != nil {
		return nil, ErrInvalidToken
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, ErrInvalidToken
	}
	claims := &parsedClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// check applies the assertions a valid signature does not make: the right
// issuer, the right token type, and a token that has not expired.
func check(claims *parsedClaims, issuer, wantType string, now time.Time) (*Parsed, error) {
	if claims.Iss != issuer {
		return nil, ErrInvalidToken
	}
	if claims.Typ != wantType {
		return nil, ErrInvalidToken
	}
	expires := time.Unix(claims.Exp, 0)
	if !now.Before(expires) {
		return nil, ErrExpiredToken
	}
	return &Parsed{
		Type:      claims.Typ,
		Subject:   claims.Sub,
		SessionID: claims.Sid,
		ClientID:  claims.Azp,
		ID:        claims.Jti,
		Audience:  parseAudience(claims.Aud),
		Scope:     claims.Scope,
		IssuedAt:  time.Unix(claims.Iat, 0),
		ExpiresAt: expires,
	}, nil
}

// parseAudience flattens the aud claim's three shapes - absent, a string, an
// array - into a list. A claim that is none of the three yields no audiences
// rather than an error: the signature already said this token is ours, and a
// token with an unreadable aud simply names nobody.
func parseAudience(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}
