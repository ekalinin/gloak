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

	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
)

// LightweightAttribute marks a client whose access tokens carry the reduced
// claim set. admin-cli ships with it set to "true".
const LightweightAttribute = "client.use.lightweight.access.token.enabled"

// internalRefreshScope is the scope string measured on a live refresh token:
// Keycloak's full internal client-scope list, longer than the access token's.
// See the "Claim sets" section of the observed-behaviour document.
//
// It is a constant here because deriving it needs the client-scope model,
// which is P5. Words granted to this request that are not in the measured list
// are appended, so a non-default request degrades honestly instead of
// reporting a scope it was not granted.
const internalRefreshScope = "openid email acr roles basic service_account web-origins profile"

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
// RealmRoles and ClientRoles are passed in rather than looked up: role
// mappings are not modelled until P2, so today's callers pass what they know,
// which for a bootstrapped realm is nothing.
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
			Azp:   r.Client.ClientID,
			Exp:   exp,
			Iat:   iat,
			Iss:   i.Issuer,
			Jti:   model.NewID(),
			Scope: r.Scope,
			Sid:   r.UserSession.ID,
			Typ:   TypeAccess,
		}
	}
	resource := map[string]roleClaim{}
	for client, roles := range r.ClientRoles {
		resource[client] = roleClaim{Roles: roles}
	}
	return accessClaims{
		Acr:               "1",
		AllowedOrigins:    r.Client.WebOrigins,
		Aud:               audience(r),
		Azp:               r.Client.ClientID,
		EmailVerified:     r.User.EmailVerified,
		Exp:               exp,
		Iat:               iat,
		Iss:               i.Issuer,
		Jti:               model.NewID(),
		PreferredUsername: r.UserSession.Username,
		RealmAccess:       roleClaim{Roles: r.RealmRoles},
		ResourceAccess:    resource,
		Scope:             r.Scope,
		Sid:               r.UserSession.ID,
		Sub:               r.UserSession.UserID,
		Typ:               TypeAccess,
	}
}

func (i *Issuer) idClaims(r Request, accessToken string, iat, exp int64) idClaims {
	return idClaims{
		Acr:               "1",
		AtHash:            atHash(accessToken),
		Aud:               r.Client.ClientID,
		Azp:               r.Client.ClientID,
		EmailVerified:     r.User.EmailVerified,
		Exp:               exp,
		Iat:               iat,
		Iss:               i.Issuer,
		Jti:               model.NewID(),
		PreferredUsername: r.UserSession.Username,
		Sid:               r.UserSession.ID,
		Sub:               r.UserSession.UserID,
		Typ:               TypeID,
	}
}

func (i *Issuer) refreshClaims(r Request, iat, exp int64) refreshClaims {
	return refreshClaims{
		Aud:   i.Issuer,
		AudX:  audience(r),
		Azp:   r.Client.ClientID,
		Exp:   exp,
		Iat:   iat,
		Iss:   i.Issuer,
		Jti:   model.NewID(),
		Prov:  "default",
		Scope: refreshScope(r.Scope),
		Sid:   r.UserSession.ID,
		Sub:   r.UserSession.UserID,
		Typ:   TypeRefresh,
	}
}

// IsLightweight reports whether a client's access tokens carry the reduced
// claim set.
func IsLightweight(c *model.Client) bool {
	return c.Attributes[LightweightAttribute] == "true"
}

// audience is what the access token puts in aud and the refresh token in
// aud_x. What Keycloak actually puts there for an ordinary client is
// unmeasured - no bootstrapped client can issue a non-lightweight token - so
// this is the client's own ID, which is the value a resource server checking
// its own audience would expect.
func audience(r Request) []string {
	return []string{r.Client.ClientID}
}

// refreshScope reproduces the measured internal scope list, appending any
// granted word it does not already contain.
func refreshScope(granted string) string {
	words := strings.Fields(internalRefreshScope)
	for w := range strings.FieldsSeq(granted) {
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
