package token

import "slices"

// Introspection is the body Keycloak's introspection endpoint returns for a
// token it reports active.
//
// It is not RFC 7662's small set. Measured 2026-08-23: Keycloak rebuilds the
// *access* token's whole claim set from whatever token was presented -
// realm_access, resource_access, acr, preferred_username and all - and appends
// client_id, username, token_type and active, with active last.
//
// Three things distinguish it from accessClaims, all measured:
//
//   - there is no allowed-origins, even on a client that has web origins;
//   - scope is absent for a token that has none, which is the ID token;
//   - aud merges the token's own audiences with the ones resolved now, so a
//     refresh token - whose own aud is the realm URL - comes back naming the
//     realm *and* the user's clients.
//
// typ and token_type both carry the presented token's type, so a refresh token
// introspects as "Refresh" in both places rather than as "Bearer".
//
// It lives beside the claim sets rather than in internal/oidc because that is
// what it is: the same claim set, one key order, changed in one place.
type Introspection struct {
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
	RealmAccess       *roleClaim     `json:"realm_access,omitempty"`
	ResourceAccess    resourceAccess `json:"resource_access,omitempty"`
	Scope             string         `json:"scope,omitempty"`
	EmailVerified     bool           `json:"email_verified"`
	PreferredUsername string         `json:"preferred_username"`
	ClientID          string         `json:"client_id"`
	Username          string         `json:"username"`
	TokenType         string         `json:"token_type"`
	Active            bool           `json:"active"`
}

// IntrospectionRequest is what building that body needs: the token as it was
// presented, plus the roles resolved for its user now. The roles are resolved
// at introspection time rather than read out of the token, which is how a
// refresh token - carrying none - comes back with the full set.
type IntrospectionRequest struct {
	Parsed      *Parsed
	Issuer      string
	Username    string
	Realm       []string
	Clients     map[string][]string
	EmailVerify bool
}

// Introspect builds the active body.
func Introspect(r IntrospectionRequest) Introspection {
	return Introspection{
		Exp:               r.Parsed.ExpiresAt.Unix(),
		Iat:               r.Parsed.IssuedAt.Unix(),
		Jti:               r.Parsed.ID,
		Iss:               r.Issuer,
		Aud:               audienceClaim(introspectionAudience(r)),
		Sub:               r.Parsed.Subject,
		Typ:               r.Parsed.Type,
		Azp:               r.Parsed.ClientID,
		Sid:               r.Parsed.SessionID,
		Acr:               "1",
		RealmAccess:       realmAccessClaim(r.Realm),
		ResourceAccess:    resourceAccessClaim(r.Clients),
		Scope:             r.Parsed.Scope,
		EmailVerified:     r.EmailVerify,
		PreferredUsername: r.Username,
		ClientID:          r.Parsed.ClientID,
		Username:          r.Username,
		TokenType:         r.Parsed.Type,
		Active:            true,
	}
}

// introspectionAudience is the token's own aud followed by the audiences
// resolved now, each once.
//
// The order is measured and is not the resolved order alone: a refresh token
// comes back with the realm URL first - its own aud - and the user's clients
// after it, in the order Audience puts them.
func introspectionAudience(r IntrospectionRequest) []string {
	out := slices.Clone(r.Parsed.Audience)
	for _, a := range Audience(r.Parsed.ClientID, r.Clients) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}
