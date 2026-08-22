// Package token issues and parses the three tokens Keycloak mints: an RS256
// access token, an RS256 ID token and an HS512 refresh token.
//
// # The claim sets here are copied, not derived
//
// In Keycloak a token's claim set is produced by protocol mappers attached to
// client scopes. That model is sub-project P5. P1 reproduces the measured
// results directly - see the "Claim sets" and "Lightweight access tokens"
// sections of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// This is staging, and section 6 of
// docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md carries it as debt.
// P5 has to *replace* this file with a mapper model rather than extend it,
// because "just add mappers" on top of hardcoded sets means rewriting issuance.
package token

// Claim structs declare their fields in the order the claim sets were measured
// in, which happens to be alphabetical. Nothing compares a token byte for byte
// - every token is Volatile in every recorded response - so the order is
// discipline rather than contract. The claim *set* is contract, and
// internal/token's tests are the only thing holding it.

// accessClaims is the ordinary access token's claim set.
//
// allowed-origins is a non-standard claim holding the client's web origins.
// aud is an array here and a string on the ID token; that asymmetry is
// Keycloak's, not a slip.
//
// Unmeasured, and marked as such rather than presented as contract: what aud
// actually contains for an ordinary client, and the value of acr. Both are
// unreachable today, since no client on a bootstrapped master realm can issue
// a non-lightweight token - which is also why oidc/userinfo/get-with-valid-token
// has no golden.
type accessClaims struct {
	Acr               string               `json:"acr"`
	AllowedOrigins    []string             `json:"allowed-origins"`
	Aud               []string             `json:"aud"`
	Azp               string               `json:"azp"`
	EmailVerified     bool                 `json:"email_verified"`
	Exp               int64                `json:"exp"`
	Iat               int64                `json:"iat"`
	Iss               string               `json:"iss"`
	Jti               string               `json:"jti"`
	PreferredUsername string               `json:"preferred_username"`
	RealmAccess       roleClaim            `json:"realm_access"`
	ResourceAccess    map[string]roleClaim `json:"resource_access"`
	Scope             string               `json:"scope"`
	Sid               string               `json:"sid"`
	Sub               string               `json:"sub"`
	Typ               string               `json:"typ"`
}

type roleClaim struct {
	Roles []string `json:"roles"`
}

// lightweightClaims is what a client carrying
// client.use.lightweight.access.token.enabled = true gets: no sub, no aud, no
// realm_access. admin-cli is such a client, which is why the Admin API cannot
// authorise from the token and must resolve the session from sid - see section
// 4.1 of docs/superpowers/specs/2026-08-21-p1-token-foundation-design.md.
type lightweightClaims struct {
	Azp   string `json:"azp"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Iss   string `json:"iss"`
	Jti   string `json:"jti"`
	Scope string `json:"scope"`
	Sid   string `json:"sid"`
	Typ   string `json:"typ"`
}

// idClaims is the ID token's claim set. aud is a string here.
type idClaims struct {
	Acr               string `json:"acr"`
	AtHash            string `json:"at_hash"`
	Aud               string `json:"aud"`
	Azp               string `json:"azp"`
	EmailVerified     bool   `json:"email_verified"`
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	Iss               string `json:"iss"`
	Jti               string `json:"jti"`
	PreferredUsername string `json:"preferred_username"`
	Sid               string `json:"sid"`
	Sub               string `json:"sub"`
	Typ               string `json:"typ"`
}

// refreshClaims is the refresh token's claim set. aud is the issuer URL and
// aud_x carries what the access token puts in aud; prov is "default".
type refreshClaims struct {
	Aud   string   `json:"aud"`
	AudX  []string `json:"aud_x"`
	Azp   string   `json:"azp"`
	Exp   int64    `json:"exp"`
	Iat   int64    `json:"iat"`
	Iss   string   `json:"iss"`
	Jti   string   `json:"jti"`
	Prov  string   `json:"prov"`
	Scope string   `json:"scope"`
	Sid   string   `json:"sid"`
	Sub   string   `json:"sub"`
	Typ   string   `json:"typ"`
}

// parsedClaims is the subset every token type shares, read back on the way in.
// A lightweight access token carries no sub, so Sub is legitimately empty and
// callers resolve the user through Sid instead.
type parsedClaims struct {
	Typ   string `json:"typ"`
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Azp   string `json:"azp"`
	Sid   string `json:"sid"`
	Scope string `json:"scope"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// Token types, spelled as Keycloak spells them in the typ claim.
const (
	TypeAccess  = "Bearer"
	TypeID      = "ID"
	TypeRefresh = "Refresh"
)
