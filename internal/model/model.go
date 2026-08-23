// Package model holds Gloak's domain types. It depends on nothing else in the
// project, so every other package can import it without creating a cycle.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewID returns a random RFC 4122 version 4 UUID in lowercase string form.
// Identifiers are strings rather than binary because they appear verbatim in
// admin API responses and in token claims.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("model: entropy source failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// secretAlphabet is the character set Keycloak draws a generated client secret
// from, and secretLength is how many it draws.
//
// Both are measured, over 25 secrets regenerated through
// POST /admin/realms/master/clients/{uuid}/client-secret on 2026-08-23: every
// one was 86 characters, and the 2150 characters between them covered these 62
// and nothing else. Base64url would have shown '-' and '_' about three times
// per secret, so the encoding is alphanumeric rather than base64 - which is the
// sort of thing that is invisible until somebody parses a secret.
const (
	secretAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	secretLength   = 86
)

// NewSecret returns a client secret in Keycloak's measured shape.
//
// Bytes at or above 248 are drawn again rather than folded in: 248 is 4*62, so
// keeping them would make the first eight characters of the alphabet slightly
// likelier than the rest. The bias would be small and permanent, and rejecting
// costs one extra byte in thirty.
func NewSecret() string {
	out := make([]byte, 0, secretLength)
	buf := make([]byte, secretLength)
	for len(out) < secretLength {
		if _, err := rand.Read(buf); err != nil {
			panic("model: entropy source failed: " + err.Error())
		}
		for _, b := range buf {
			if b >= 248 {
				continue
			}
			out = append(out, secretAlphabet[b%62])
			if len(out) == secretLength {
				break
			}
		}
	}
	return string(out)
}

// ServiceAccountUsername is the account a client with service accounts enabled
// acts as.
//
// P1 guessed this convention when it created the account on demand during a
// client_credentials grant, and said so. P2 measured it through
// GET /admin/realms/{realm}/clients/{uuid}/service-account-user, which returned
// username "service-account-probe-secret" for clientId "probe-secret". The
// guess was right; this function is where it stops being one.
func ServiceAccountUsername(clientID string) string {
	return "service-account-" + clientID
}

// Realm is a tenant. Lifespans are stored as durations but are emitted as
// whole seconds in token responses.
type Realm struct {
	ID                   string
	Name                 string
	Enabled              bool
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

// Client is an OAuth2 client. ID is the internal UUID used in admin API paths;
// ClientID is the human-facing identifier used in protocol requests. Keeping
// both is mandatory: Keycloak addresses clients by UUID in /admin/realms paths.
//
// The field set is what Keycloak's ClientRepresentation carries, measured on a
// live instance rather than read off the OpenAPI schema - the schema lists what
// may appear, and the recording says what does. See "Client representation" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// DefaultClientScopes and OptionalClientScopes are lists of scope *names*, not
// the client-scope objects themselves. Those objects, and protocol mappers, are
// P5. Keeping the names here is the least that lets the representation be
// reproduced from stored state rather than invented per client.
type Client struct {
	ID                        string
	RealmID                   string
	ClientID                  string
	Name                      string
	RootURL                   string
	BaseURL                   string
	Enabled                   bool
	PublicClient              bool
	Secret                    string
	Protocol                  string
	ClientAuthenticatorType   string
	SurrogateAuthRequired     bool
	AlwaysDisplayInConsole    bool
	BearerOnly                bool
	ConsentRequired           bool
	StandardFlowEnabled       bool
	ImplicitFlowEnabled       bool
	DirectAccessGrantsEnabled bool
	ServiceAccountsEnabled    bool
	FrontchannelLogout        bool
	FullScopeAllowed          bool
	NotBefore                 int
	NodeReRegistrationTimeout int
	RedirectURIs              []string
	WebOrigins                []string
	DefaultClientScopes       []string
	OptionalClientScopes      []string
	Attributes                map[string]string
}

// User is an account within a realm.
type User struct {
	ID               string
	RealmID          string
	Username         string
	Email            string
	EmailVerified    bool
	Enabled          bool
	FirstName        string
	LastName         string
	CreatedTimestamp int64
	Attributes       map[string][]string
}

// Credential is a stored secret, split the way Keycloak splits it: a public
// part describing the hashing parameters and a secret part holding the result.
type Credential struct {
	ID                   string
	UserID               string
	Type                 string
	CreatedDate          int64
	Algorithm            string
	HashIterations       int
	AdditionalParameters map[string][]string
	Salt                 []byte
	HashValue            []byte
}

// UserSession is an SSO session: one login, however many clients use it. Its
// ID is what a token carries as sid and what the token response returns as
// session_state. Timestamps are Unix milliseconds.
type UserSession struct {
	ID          string
	RealmID     string
	UserID      string
	Username    string
	StartedAt   int64
	LastRefresh int64
	ExpiresAt   int64
}

// ClientSession is one client's participation in a UserSession. Scope is the
// space-separated scope granted to that client, which is what a refresh knows
// to re-issue.
type ClientSession struct {
	ID            string
	UserSessionID string
	ClientID      string // the client's internal UUID, not its clientId
	Scope         string
	StartedAt     int64
}

// RealmKey is one of a realm's signing keys, persisted so the kid a client
// caches survives a restart and so two replicas publish the same key set.
// Algorithm is RS256, RSA-OAEP or HS512; Use is "sig" or "enc" and is empty
// for the HMAC key, which is never published. PrivateKey holds PKCS#8 DER for
// the RSA keys and the raw secret for HS512; Certificate holds the self-signed
// DER published as x5c, and is empty for HS512.
type RealmKey struct {
	ID          string
	RealmID     string
	Algorithm   string
	Use         string
	PrivateKey  []byte
	Certificate []byte
	CreatedAt   int64
}

// Role is a realm role when ClientID is empty, otherwise a client role.
type Role struct {
	ID          string
	RealmID     string
	ClientID    string
	Name        string
	Description string
	Composite   bool
}
