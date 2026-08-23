package token

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
)

// LightweightAttribute marks a client whose access tokens carry the reduced
// claim set. admin-cli ships with it set to "true".
const LightweightAttribute = "client.use.lightweight.access.token.enabled"

// refreshOnlyScopes is what a refresh token's scope carries on top of the
// access token's.
//
// Measured 2026-08-23: the refresh token's scope is the granted scope followed
// by the client's default client scopes that are not already in it. On a
// bootstrapped realm those are the six every client carries, of which profile
// and email are already granted, leaving these four.
//
// P1 recorded this as a fixed list of eight including openid and
// service_account. That was wrong twice over: openid appears only when it was
// asked for, and service_account only on a client with service accounts
// enabled - measured by creating one and finding a seventh word appear. Hence
// serviceAccountScope below rather than a constant covering both.
//
// Deriving it from the client's own DefaultClientScopes is what Keycloak does
// and what this cannot do yet: a client created through the admin API comes
// back with an empty list, because the realm does not model default scopes
// until P5. See follow-up F16.
var refreshOnlyScopes = []string{"web-origins", "acr", "basic", "roles"}

// serviceAccountScope is the seventh default client scope a client with
// service accounts enabled carries, measured 2026-08-23.
const serviceAccountScope = "service_account"

// Issuer turns a session into tokens. Now exists so tests can pin time; nil
// means time.Now.
type Issuer struct {
	Keys   *keys.RealmKeys
	Issuer string // the realm's issuer URL, e.g. http://host/realms/master
	Now    func() time.Time
}

// Request is one issuance. Scope is the granted scope, space-separated, as it
// will appear in the token response.
//
// RealmRoles and ClientRoles are passed in rather than looked up here: this
// package signs claim sets and does not reach a store. The caller resolves
// them - see internal/roles - and both are the user's *effective* roles, with
// composites already expanded. ClientRoles is keyed by clientId, not by the
// client's UUID, because that is what the claim carries.
type Request struct {
	Client         *model.Client
	User           *model.User
	UserSession    *model.UserSession
	Scope          string
	RealmRoles     []string
	ClientRoles    map[string][]string
	AccessLife     time.Duration
	RefreshLife    time.Duration
	IncludeIDToken bool
}

// Set is what one issuance produces. IDToken is empty unless the openid scope
// was granted: the measured admin-cli password grant has no id_token key at
// all, not an empty one.
type Set struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Issue mints the access token first, because the ID token's at_hash is
// computed over it.
func (i *Issuer) Issue(r Request) (Set, error) {
	now := i.now().UTC()
	iat := now.Unix()
	accessExp := now.Add(r.AccessLife).Unix()

	access, err := i.signRSA(i.accessClaims(r, iat, accessExp))
	if err != nil {
		return Set{}, err
	}

	var idToken string
	if r.IncludeIDToken {
		if idToken, err = i.signRSA(i.idClaims(r, access, iat, accessExp)); err != nil {
			return Set{}, err
		}
	}

	refresh, err := i.signHMAC(i.refreshClaims(r, iat, now.Add(r.RefreshLife).Unix()))
	if err != nil {
		return Set{}, err
	}
	return Set{AccessToken: access, IDToken: idToken, RefreshToken: refresh}, nil
}

// accessClaims returns either the full set or the lightweight one, chosen by
// the client's attribute rather than by anything about the request.
func (i *Issuer) accessClaims(r Request, iat, exp int64) any {
	if IsLightweight(r.Client) {
		return lightweightClaims{
			Exp:   exp,
			Iat:   iat,
			Jti:   model.NewID(),
			Iss:   i.Issuer,
			Typ:   TypeAccess,
			Azp:   r.Client.ClientID,
			Sid:   r.UserSession.ID,
			Scope: r.Scope,
		}
	}
	return accessClaims{
		Exp:               exp,
		Iat:               iat,
		Jti:               model.NewID(),
		Iss:               i.Issuer,
		Aud:               audienceClaim(Audience(r.Client.ClientID, r.ClientRoles)),
		Sub:               r.UserSession.UserID,
		Typ:               TypeAccess,
		Azp:               r.Client.ClientID,
		Sid:               r.UserSession.ID,
		Acr:               "1",
		AllowedOrigins:    r.Client.WebOrigins,
		RealmAccess:       realmAccessClaim(r.RealmRoles),
		ResourceAccess:    resourceAccessClaim(r.ClientRoles),
		Scope:             r.Scope,
		EmailVerified:     r.User.EmailVerified,
		PreferredUsername: r.UserSession.Username,
	}
}

func (i *Issuer) idClaims(r Request, accessToken string, iat, exp int64) idClaims {
	return idClaims{
		Exp:               exp,
		Iat:               iat,
		Jti:               model.NewID(),
		Iss:               i.Issuer,
		Aud:               r.Client.ClientID,
		Sub:               r.UserSession.UserID,
		Typ:               TypeID,
		Azp:               r.Client.ClientID,
		Sid:               r.UserSession.ID,
		AtHash:            atHash(accessToken),
		Acr:               "1",
		EmailVerified:     r.User.EmailVerified,
		PreferredUsername: r.UserSession.Username,
	}
}

func (i *Issuer) refreshClaims(r Request, iat, exp int64) refreshClaims {
	return refreshClaims{
		Exp:   exp,
		Iat:   iat,
		Jti:   model.NewID(),
		Iss:   i.Issuer,
		Aud:   i.Issuer,
		Sub:   r.UserSession.UserID,
		Typ:   TypeRefresh,
		Azp:   r.Client.ClientID,
		Sid:   r.UserSession.ID,
		Scope: RefreshScope(r.Scope, r.Client),
		AudX:  audienceClaim(Audience(r.Client.ClientID, r.ClientRoles)),
		Prov:  "default",
	}
}

// IsLightweight reports whether a client's access tokens carry the reduced
// claim set.
func IsLightweight(c *model.Client) bool {
	return c.Attributes[LightweightAttribute] == "true"
}

// Audience is what the access token puts in aud and the refresh token in
// aud_x: the clients the *user* holds roles on, in Keycloak's key order,
// **minus the issuing client**.
//
// The exclusion is measured, not defensive, and it is the whole of follow-up
// F18's second half. Assigning the administrator a role on the issuing client
// puts that client in resource_access and still leaves it out of aud, so a
// client can never introspect a token it asked for itself. Until 2026-08-23
// this returned the issuing client and nothing else, which was the opposite of
// the contract in every particular.
func Audience(issuingClient string, clientRoles map[string][]string) []string {
	out := make([]string, 0, len(clientRoles))
	for c := range clientRoles {
		if c != issuingClient {
			out = append(out, c)
		}
	}
	return javamap.KeyOrder(out)
}

// RefreshScope is the refresh token's scope: the granted scope followed by the
// client's default client scopes that are not already in it. See
// refreshOnlyScopes for why those are a constant rather than the client's own.
func RefreshScope(granted string, c *model.Client) string {
	words := strings.Fields(granted)
	extra := refreshOnlyScopes
	if c != nil && c.ServiceAccountsEnabled {
		extra = append(slices.Clone(extra), serviceAccountScope)
	}
	for _, w := range extra {
		if !slices.Contains(words, w) {
			words = append(words, w)
		}
	}
	return strings.Join(words, " ")
}

// atHash is the base64url, unpadded encoding of the left half of the SHA-256
// of the access token, per OpenID Connect Core 3.1.3.6.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func (i *Issuer) signRSA(claims any) (string, error) {
	signer, err := i.Keys.RSASigner()
	if err != nil {
		return "", err
	}
	return sign(signer, claims)
}

func (i *Issuer) signHMAC(claims any) (string, error) {
	signer, err := i.Keys.HMACSigner()
	if err != nil {
		return "", err
	}
	return sign(signer, claims)
}

func sign(signer jose.Signer, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("token: marshal claims: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("token: serialise: %w", err)
	}
	return compact, nil
}
