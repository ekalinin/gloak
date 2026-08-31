// Package model holds Gloak's domain types. It depends on nothing else in the
// project, so every other package can import it without creating a cycle.
package model

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

// DefaultRolesName is the realm role every new user in a realm is given. Its
// name carries the realm's, so `master` has default-roles-master and a second
// realm gets its own.
//
// Measured: a user created through the admin API holds it and nothing else,
// and it is the only reason an ordinary user's token carries any role at all.
// See internal/bootstrap for what it contains.
func DefaultRolesName(realm string) string {
	return "default-roles-" + realm
}

// Realm is a tenant. Lifespans are stored as durations but are emitted as
// whole seconds in token responses.
//
// The four fields above Settings are the ones Gloak reads. Keycloak's
// RealmRepresentation carries 104 keys on a created realm; the other hundred
// are configuration this project stores and does not interpret -
// otpPolicyDigits is P8's, smtpServer is P14's, browserFlow is P8's - so they
// live in Settings as the JSON they arrived as rather than as a hundred columns
// across two drivers, each of which would be a migration when a later cut needs
// the hundred and first.
//
// Settings holds the representation **as last written**. Its copies of the four
// fields above are never read: the admin layer overwrites them from these
// columns after decoding, so the row stays the single observable truth and the
// two cannot drift into a divergence. Nil means "never written", which is what
// a realm bootstrapped before this field existed has, and the admin layer falls
// back to the measured defaults for that realm's name.
type Realm struct {
	ID                   string
	Name                 string
	Enabled              bool
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	Settings             []byte
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
	Description               string
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
	// AuthorizationServicesEnabled is **derived, not stored**: it is true
	// exactly when the client has a row in authz_resource_server. The client
	// repositories read it with a subquery and never write it; AuthzRepo owns
	// it, because a boolean beside the settings table would be a second truth
	// that could disagree with it. See 0019_authz_resource_server.sql.
	AuthorizationServicesEnabled bool
	FrontchannelLogout           bool
	FullScopeAllowed             bool
	NotBefore                    int
	NodeReRegistrationTimeout    int
	RedirectURIs                 []string
	WebOrigins                   []string
	DefaultClientScopes          []string
	OptionalClientScopes         []string
	Attributes                   map[string]string
	// ProtocolMappers are the client's own, distinct from the ones it reaches
	// through its client scopes. Two of the six bootstrapped clients carry one:
	// account-console's `audience resolve` and security-admin-console's
	// `locale`. Like a client scope's, they are **omitted** from the
	// representation when empty rather than serialised as `[]`.
	ProtocolMappers []ProtocolMapper
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
	// RequiredActions is what the user must do at next login. Measured: a
	// reset-password carrying temporary true adds UPDATE_PASSWORD, and the
	// user representation shows it.
	RequiredActions []string
	// NotBefore is a Unix second before which the user's tokens are refused.
	// Measured: POST /users/{id}/logout sets it to the moment of the logout,
	// and the user representation shows it - so the endpoint's effect is
	// visible beyond its 204.
	NotBefore int
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
	// Label is the userLabel a caller can attach through
	// PUT .../credentials/{id}/userLabel. Measured: it appears in the
	// credential representation between type and createdDate, and a
	// reset-password clears it.
	Label string
	// Priority is the credential's position in the user's list, which
	// moveAfter and moveToFirst rewrite. Lower comes first.
	Priority int
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
// Group is a node in the realm's group tree.
//
// **Path is not a field.** A group's path is derived from its ancestry:
// renaming a parent was measured moving every descendant's path while leaving
// their names alone, so storing it would mean rewriting the whole subtree on
// every rename. See groupPath in internal/admin.
//
// ParentID is empty for a top-level group, the way Role.ClientID is empty for a
// realm role. The two mean the same thing and are spelled the same way on
// purpose.
type Group struct {
	ID       string
	RealmID  string
	ParentID string
	Name     string
	// Attributes are stored and read back verbatim, like a role's. A group
	// with none reads back {} rather than being absent, measured.
	Attributes map[string][]string
}

type Role struct {
	ID          string
	RealmID     string
	ClientID    string
	Name        string
	Description string
	Composite   bool
	// Attributes are stored and read back verbatim. Measured: a role keeps
	// them, where a user's are dropped because the declarative user profile
	// rejects unmanaged attributes. Nothing here reads one; Keycloak gives
	// some of them meaning and that is P5's problem.
	Attributes map[string][]string
}

// StringPair is one entry of a Keycloak map, kept beside its neighbours in the
// order the map was serialised in.
type StringPair struct {
	Key   string
	Value string
}

// StringMap is a Java map whose serialised key order is part of the contract.
//
// A client scope's `attributes` and a protocol mapper's `config` are Java maps
// emitted in HashMap bucket order. The conformance suite can sort both sides of
// such an object (Case.UnorderedKeys), but the fifteen client scopes a realm is
// bootstrapped with are recorded bodies rather than data a client supplied, and
// for those the order is reproducible: it is whatever the recording says. Going
// through a Go map would sort it alphabetically and lose that for nothing.
//
// This is the same technique internal/admin already uses for the five argon2
// keys inside a credential's credentialData.
//
// UnmarshalJSON preserves the order it is given, so a scope created through the
// API reads back with its attributes in the order the request wrote them.
type StringMap []StringPair

// Get returns the value stored under key, and whether it was present.
func (m StringMap) Get(key string) (string, bool) {
	for _, p := range m {
		if p.Key == key {
			return p.Value, true
		}
	}
	return "", false
}

// Set replaces the value under key in place, or appends it if it is new.
// Appending rather than sorting is what keeps a merge's key order stable.
func (m *StringMap) Set(key, value string) {
	for i := range *m {
		if (*m)[i].Key == key {
			(*m)[i].Value = value
			return
		}
	}
	*m = append(*m, StringPair{Key: key, Value: value})
}

// MarshalJSON writes the pairs as a JSON object in the order they are held.
// A nil StringMap is `{}` rather than `null`: an attribute-less client scope
// was measured carrying `"attributes":{}`, never omitting the key.
func (m StringMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, p := range m {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(p.Key)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(p.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON reads a JSON object token by token so the pairs keep the order
// they arrived in. Decoding into a map[string]string and ranging over it would
// not: Go randomises map iteration and encoding/json sorts on the way out.
func (m *StringMap) UnmarshalJSON(data []byte) error {
	if string(bytes.TrimSpace(data)) == "null" {
		*m = nil
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("model: StringMap: expected an object, got %v", tok)
	}
	out := StringMap{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("model: StringMap: expected a key, got %v", keyTok)
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return err
		}
		out.Set(key, value)
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	*m = out
	return nil
}

// ProtocolMapper is one entry of a client scope's protocolMappers array.
//
// Nothing reads a mapper yet: token issuance still reproduces the measured
// claim set directly, which is the staging the parity roadmap's section 6
// records. Storing them is what lets a client scope be served from stored state
// rather than spliced together from a constant at write time, and it is the
// prerequisite for the engine rather than the engine.
//
// Field order is the measured serialisation order.
type ProtocolMapper struct {
	ID              string
	Name            string
	Protocol        string
	ProtocolMapper  string
	ConsentRequired bool
	Config          StringMap
}

// ClientScope is a named bundle of protocol mappers and role scope that a
// client can carry by default or optionally.
//
// Field order is the measured serialisation order:
// `id, name, description, protocol, attributes, protocolMappers`.
type ClientScope struct {
	ID          string
	RealmID     string
	Name        string
	Description string
	Protocol    string
	// Attributes is always serialised, `{}` when empty.
	Attributes StringMap
	// ProtocolMappers is **omitted** from the representation when empty rather
	// than serialised as `[]`. Measured: `offline_access` is the one
	// bootstrapped scope with no mappers and its body has five keys where every
	// other scope's has six.
	ProtocolMappers []ProtocolMapper
}

// RequiredActionProvider is one row of a realm's registered required actions -
// what the user must do at the next login, and in which order.
//
// Field order is the measured serialisation order:
// `alias, name, providerId, enabled, defaultAction, priority, config`.
type RequiredActionProvider struct {
	// ID is server-minted and is the row's identity, because Alias is not.
	// PUT /required-actions/{alias} writes the body's alias over the row's, so
	// a PUT with `{}` leaves a row whose alias is the empty string, addressable
	// by nothing and still in the listing. See 0017_required_action.sql.
	ID      string
	RealmID string
	Alias   string
	// Name is a pointer because absent and empty are two measured answers. A
	// row registered with no `name` reads back with six keys; one registered
	// with `""` reads back carrying `"name":""`. A string with omitempty
	// collapses the two.
	Name          *string
	ProviderID    string
	Enabled       bool
	DefaultAction bool
	Priority      int
	// Config is always serialised, `{}` when empty - like ClientScope's
	// Attributes and unlike its ProtocolMappers. DELETE .../config was measured
	// leaving `{"config":{}}` rather than removing the key.
	Config StringMap
}

// AuthzResourceServer is a client's authorization services settings.
//
// It has exactly three fields because exactly three are settable. The
// representation also carries `id`, `clientId` and `name`, and none of them is
// state: `id` and `clientId` are **both** the client's internal UUID and `name`
// is the client's `clientId` string - so the representation's `clientId` is not
// the client's `clientId`, measured 2026-08-31. internal/admin fills all three
// from the client it already holds.
//
// The `resources`, `policies` and `scopes` arrays are not here for a different
// reason: on `GET .../authz/resource-server` they are **always empty**, measured
// against a resource server holding four scopes. `GET .../settings` is the read
// that populates them, and it is a different body.
//
// The zero value is not the default. A resource server Keycloak creates carries
// AllowRemoteResourceManagement true, PolicyEnforcementMode ENFORCING and
// DecisionStrategy UNANIMOUS; DefaultAuthzResourceServer is that value.
type AuthzResourceServer struct {
	ClientID                      string
	AllowRemoteResourceManagement bool
	PolicyEnforcementMode         string
	DecisionStrategy              string
}

// DefaultAuthzResourceServer is what a client gets when its
// authorizationServicesEnabled is turned on, through the create or through the
// update. Measured on both paths, and measured again after the flag was turned
// off and back on, which resets to exactly this.
func DefaultAuthzResourceServer(clientID string) *AuthzResourceServer {
	return &AuthzResourceServer{
		ClientID:                      clientID,
		AllowRemoteResourceManagement: true,
		PolicyEnforcementMode:         "ENFORCING",
		DecisionStrategy:              "UNANIMOUS",
	}
}

// Organization is a realm's organization: a name, an immutable alias, a set of
// e-mail domains and a multivalued attribute map.
//
// Field order is the measured serialisation order,
// `id, name, alias, enabled, description, redirectUrl, attributes, domains` -
// with description and redirectUrl present only when set. See
// internal/admin/organizations.go for the three shapes that order feeds.
//
// **Alias is stored rather than derived.** It defaults to the name at creation
// and is then immutable: a PUT carrying a different alias, or carrying none
// after a rename, was measured answering 400 "Cannot change the alias". A field
// computed from the name on every read could not answer that.
//
// Attributes is a MultivaluedHashMap - one name to many values - which is a
// group's attribute type and not a client's. StringMap does not apply.
type Organization struct {
	ID      string
	RealmID string
	Name    string
	Alias   string
	Enabled bool
	// Description is a pointer because absent and empty are two measured
	// answers. A create sending `"description":""` reads back carrying
	// `"description":""`; one sending nothing reads back with no such key.
	// RequiredActionProvider.Name is a pointer for exactly this reason.
	Description *string
	// RedirectURL is **not** a pointer, and that is measured rather than a
	// choice: the same create sending `"redirectUrl":""` reads back with no
	// `redirectUrl` key, so empty and absent are one state here where they are
	// two next door. Two neighbouring fields, opposite rules.
	RedirectURL string
	// Domains is **absent** from the representation when empty rather than
	// serialised as `[]`, which is why internal/admin holds it behind a
	// pointer. Measured on every shape.
	Domains []OrganizationDomain
	// Attributes is always serialised, `{}` when empty - the opposite rule
	// from Domains beside it, on the same body.
	Attributes []OrganizationAttribute
}

// OrganizationDomain is one e-mail domain an organization claims. A domain is
// unique across the whole realm, not just within its organization: a create
// naming a domain another organization already holds was measured answering
// 400 and naming that other organization.
type OrganizationDomain struct {
	Name     string
	Verified bool
}

// OrganizationAttribute is one attribute name and its values, kept as a slice
// rather than a map because the wire order is the order it arrived in and a Go
// map would sort it - the reason StringMap exists, applied to a multivalued
// map.
type OrganizationAttribute struct {
	Name   string
	Values []string
}

// AddAttribute appends one value under name, starting a new entry when the name
// is new and extending the existing one otherwise.
//
// It is on the model rather than in a driver because both drivers rebuild the
// same slice from the same ordered rows, and two copies of "append or extend"
// is two places the attribute order could start to differ.
func (o *Organization) AddAttribute(name, value string) {
	for i := range o.Attributes {
		if o.Attributes[i].Name == name {
			o.Attributes[i].Values = append(o.Attributes[i].Values, value)
			return
		}
	}
	o.Attributes = append(o.Attributes, OrganizationAttribute{Name: name, Values: []string{value}})
}
