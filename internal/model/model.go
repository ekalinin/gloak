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
type Client struct {
	ID                        string
	RealmID                   string
	ClientID                  string
	Name                      string
	Enabled                   bool
	PublicClient              bool
	Secret                    string
	StandardFlowEnabled       bool
	DirectAccessGrantsEnabled bool
	ServiceAccountsEnabled    bool
	RedirectURIs              []string
	WebOrigins                []string
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

// Role is a realm role when ClientID is empty, otherwise a client role.
type Role struct {
	ID          string
	RealmID     string
	ClientID    string
	Name        string
	Description string
	Composite   bool
}
