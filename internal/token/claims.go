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

import (
	"bytes"
	"encoding/json"

	"github.com/ekalinin/gloak/internal/javamap"
)

// Claim structs declare their fields in the order Keycloak was measured
// emitting them, which is *not* alphabetical - it was recorded as such until
// 2026-08-23, from tokens nobody had decoded. Every one of the four sets below
// was read off a live 26.7.1 that day.
//
// A token is Volatile in every recorded response, so this order is discipline
// rather than contract - but the introspection endpoint serves the access
// token's claim set as an ordinary JSON body, and that body *is* compared byte
// for byte. See Introspection.

// accessClaims is the ordinary access token's claim set.
//
// Four keys are absent rather than empty, all measured:
//
//   - aud when the user holds no client role, and a **string** rather than an
//     array when it holds roles on exactly one client.
//   - allowed-origins when the client has no web origins. It is a non-standard
//     claim holding them.
//   - realm_access when the user holds no realm role.
//   - resource_access when it holds no client role.
//
// A user with no roles at all therefore gets a token with none of the four,
// which is why they are pointers and interfaces rather than plain values: Go's
// omitempty would drop a populated `realm_access` with an empty role list too,
// and that is a state Keycloak can reach.
type accessClaims struct {
	Exp               int64          `json:"exp"`
	Iat               int64          `json:"iat"`
	Jti               string         `json:"jti"`
	Iss               string         `json:"iss"`
	Aud               any            `json:"aud,omitempty"`
	Sub               string         `json:"sub"`
	Typ               string         `json:"typ"`
	Azp               string         `json:"azp"`
	Sid               string         `json:"sid"`
	Acr               string         `json:"acr"`
	AllowedOrigins    []string       `json:"allowed-origins,omitempty"`
	RealmAccess       *roleClaim     `json:"realm_access,omitempty"`
	ResourceAccess    resourceAccess `json:"resource_access,omitempty"`
	Scope             string         `json:"scope"`
	EmailVerified     bool           `json:"email_verified"`
	PreferredUsername string         `json:"preferred_username"`
}

type roleClaim struct {
	Roles []string `json:"roles"`
}

// resourceAccess is the resource_access claim: one entry per client the user
// holds roles on.
//
// It is a slice rather than a map because the key order is Keycloak's and Go
// sorts a map's keys. The administrator's token carries master-realm before
// account, which is neither sorted nor insertion order - it is a Java HashMap
// walking its buckets. See internal/javamap.
type resourceAccess []clientRoleClaim

type clientRoleClaim struct {
	ClientID string
	Roles    []string
}

// MarshalJSON writes the entries as a JSON object in the order they are held.
func (r resourceAccess) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range r {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(entry.ClientID)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := json.Marshal(roleClaim{Roles: entry.Roles})
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// lightweightClaims is what a client carrying
// client.use.lightweight.access.token.enabled = true gets: no sub, no aud, no
// realm_access. admin-cli is such a client, which is why the Admin API cannot
// authorise from the token and must resolve the session from sid - see section
// 4.1 of docs/superpowers/specs/2026-08-21-p1-token-foundation-design.md.
type lightweightClaims struct {
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Jti   string `json:"jti"`
	Iss   string `json:"iss"`
	Typ   string `json:"typ"`
	Azp   string `json:"azp"`
	Sid   string `json:"sid"`
	Scope string `json:"scope"`
}

// idClaims is the ID token's claim set. aud is a string here, and it is the
// issuing client rather than the audiences the access token resolves - the one
// place the two disagree.
type idClaims struct {
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	Jti               string `json:"jti"`
	Iss               string `json:"iss"`
	Aud               string `json:"aud"`
	Sub               string `json:"sub"`
	Typ               string `json:"typ"`
	Azp               string `json:"azp"`
	Sid               string `json:"sid"`
	AtHash            string `json:"at_hash"`
	Acr               string `json:"acr"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
}

// refreshClaims is the refresh token's claim set. aud is the issuer URL - a
// string always, even when the access token's aud is an array - and aud_x
// carries what the access token puts in aud, under the same absent/string/array
// rule. prov is "default".
type refreshClaims struct {
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Jti   string `json:"jti"`
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
	Sub   string `json:"sub"`
	Typ   string `json:"typ"`
	Azp   string `json:"azp"`
	Sid   string `json:"sid"`
	Scope string `json:"scope"`
	AudX  any    `json:"aud_x,omitempty"`
	Prov  string `json:"prov"`
}

// parsedClaims is the subset every token type shares, read back on the way in.
// A lightweight access token carries no sub, so Sub is legitimately empty and
// callers resolve the user through Sid instead.
//
// Aud is deferred rather than typed because it is a string on some tokens and
// an array on others; see Parsed.Audience.
type parsedClaims struct {
	Typ   string          `json:"typ"`
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Azp   string          `json:"azp"`
	Sid   string          `json:"sid"`
	Jti   string          `json:"jti"`
	Aud   json.RawMessage `json:"aud"`
	Scope string          `json:"scope"`
	Iat   int64           `json:"iat"`
	Exp   int64           `json:"exp"`
}

// Token types, spelled as Keycloak spells them in the typ claim.
const (
	TypeAccess  = "Bearer"
	TypeID      = "ID"
	TypeRefresh = "Refresh"
)

// audienceClaim renders a list of audiences the way Keycloak does: absent when
// there are none, a bare string when there is one, an array when there are
// several. The same rule governs the access token's aud, the refresh token's
// aud_x and the introspection body's aud.
func audienceClaim(audiences []string) any {
	switch len(audiences) {
	case 0:
		return nil
	case 1:
		return audiences[0]
	default:
		return audiences
	}
}

// realmAccessClaim is realm_access, or nil when the user holds no realm role
// and Keycloak omits the key.
func realmAccessClaim(names []string) *roleClaim {
	if len(names) == 0 {
		return nil
	}
	return &roleClaim{Roles: javamap.KeyOrder(names)}
}

// resourceAccessClaim is resource_access in Keycloak's key order, or nil when
// the user holds no client role and Keycloak omits the key.
func resourceAccessClaim(clientRoles map[string][]string) resourceAccess {
	if len(clientRoles) == 0 {
		return nil
	}
	clients := make([]string, 0, len(clientRoles))
	for c := range clientRoles {
		clients = append(clients, c)
	}

	out := make(resourceAccess, 0, len(clients))
	for _, c := range javamap.KeyOrder(clients) {
		out = append(out, clientRoleClaim{ClientID: c, Roles: javamap.KeyOrder(clientRoles[c])})
	}
	return out
}
