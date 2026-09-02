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

// AuthzScope is one authorization scope of a resource server.
//
// ID is a free string rather than a UUID, measured 2026-09-01:
// `POST .../scope` with `{"id":"zzz","name":"idshape"}` answered 201 and
// created a scope whose id is `zzz`. So nothing here parses or generates a
// UUID for a body that named one.
//
// Ordinal is the order the scope was created in, and it is state rather than
// presentation because **one set of scopes has two reads and two orders**:
// `GET .../scope` comes back sorted by name and `GET .../settings` comes back
// in creation order. Four scopes created zulu, yankee, xray, whiskey - the
// reverse of name order - came back that way from the export and the other way
// from the listing, and deleting xray and recreating it moved it to the end of
// the export. Sorting in the store would make the listing right and the export
// wrong.
//
// There is no ResourceServerID separate from a client id: a resource server is
// keyed by its client's UUID, which is what AuthzResourceServer.ClientID holds.
type AuthzScope struct {
	ID          string
	ClientID    string
	Name        string
	IconURI     string
	DisplayName string
	Ordinal     int
}

// AuthzResource is one protected resource of a resource server.
//
// **Its wire name for the id is `_id`, and `id` is refused.** The strict
// decoder says so: `POST .../resource` with `{"id":"x"}` answers
// `Unrecognized field "id"`, where `{"_id":"x"}` is a 201 creating a resource
// with exactly that id. So the body's id wins here as it does on the scope
// create, and nothing parses or generates a UUID for a body that named one.
//
// **Three of its fields are collections and no two of them are ordered by the
// same rule**, measured 2026-09-01 on one container:
//
//   - URIs is a Java HashSet of strings. `["/z","/a","/m"]` came back
//     `["/a","/z","/m"]` and a repeated entry collapses. Two uris in one
//     bucket chain in **request** order: `["aa","bb","zz"]` came back
//     `aa, bb, zz` and `["zz","bb","aa"]` came back `zz, bb, aa`.
//   - Attributes is a Java HashMap whose chain runs the **other** way. The
//     same six keys, one field apart on the same body: `{"aa","bb","zz"}` came
//     back `zz, bb, aa` and `{"zz","bb","aa"}` came back `aa, bb, zz`. All six
//     hash to bucket 0 at every table size - a two-letter string of one
//     repeated character has a hashCode that is a multiple of 32 - so the
//     bucket says nothing there and the chain says everything.
//   - ScopeIDs is a set keyed on the scope's **name**: the same three names
//     came back in the same order from two resource servers holding different
//     scope ids.
//
// All three are slices for OrganizationAttribute's stated reason - the wire
// order is the order it arrived in and a Go map would sort it - and the
// serialiser in internal/admin decides the bucket order from them.
//
// Ordinal is creation order, which is what `GET .../settings` serves; the
// listing beside it sorts by name. That is the scope family's two-orders rule
// holding on a second family, and it is why sorting in the store would make one
// of the two reads wrong.
type AuthzResource struct {
	ID       string
	ClientID string
	Name     string
	// DisplayName, Type and IconURI are omitted from every representation when
	// empty - measured on a resource created with only a name - so absent and
	// empty are one state on the wire.
	DisplayName string
	Type        string
	// IconURI is spelled `icon_uri` on the wire and `iconUri` is **refused**,
	// which is the opposite of every other object in this API.
	IconURI            string
	OwnerManagedAccess bool
	URIs               []string
	Attributes         []AuthzResourceAttribute
	ScopeIDs           []string
	Ordinal            int
}

// AuthzResourceAttribute is one attribute name and its values, the shape
// OrganizationAttribute already uses for a multivalued Java map.
//
// A scalar value is accepted on the wire and coerced: `{"k":"v"}` came back
// `{"k":["v"]}`, so the model holds only the multivalued form.
type AuthzResourceAttribute struct {
	Name   string
	Values []string
}

// AddAttribute appends one value under name, starting a new entry when the name
// is new and extending the existing one otherwise.
//
// It is on the model rather than in a driver for Organization.AddAttribute's
// reason: both drivers rebuild the same slice from the same ordered rows.
func (r *AuthzResource) AddAttribute(name, value string) {
	for i := range r.Attributes {
		if r.Attributes[i].Name == name {
			r.Attributes[i].Values = append(r.Attributes[i].Values, value)
			return
		}
	}
	r.Attributes = append(r.Attributes, AuthzResourceAttribute{Name: name, Values: []string{value}})
}

// AuthzPolicy is one policy of a resource server, and a permission is one of
// these too.
//
// **There is no separate permission type**, because there is no separate row.
// `GET .../policy?permission=true` and `GET .../permission` returned the same
// rows one key apart on 26.7.1, measured 2026-09-02, and the family a row
// belongs to is decided by its Type alone.
//
// ID is a free string rather than a UUID, the way AuthzScope.ID and
// AuthzResource.ID are: `POST .../policy` with `{"id":"echo1",...}` answered
// 201 and created a policy with exactly that id. **Unlike a resource it does
// not upsert** - a repeat of an id this resource server already holds is a 409
// `Duplicate resource error` - so the create's id is a wish that the primary
// key either grants or refuses.
//
// Config is a Java map whose serialised key order is part of the contract, and
// it is a slice for AuthzResource.Attributes' reason: the wire order is
// computed from the order the entries arrived in and a Go map would sort it.
// `javamap.SizedKeyOrder(len(config), keys)` places every measured key set and
// `javamap.KeyOrder` gets two of eight wrong.
//
// **Config is what the typed view is a projection of.** One config carrying
// every provider's keys at once was sent to all nine types and the generic view
// came back byte-identical on all nine, while the typed view served exactly the
// keys the type owns - eight distinct field sets over the nine types, with
// `resource` and `scope` sharing one. So there are not nine representations to
// store, there is one map and a projection table; see internal/admin.
//
// AssociatedPolicies, Resources and Scopes are the three association sets, and
// they are not symmetrical on the wire: the create echoes the first two and no
// read serves them, while Scopes is served by exactly one type's typed view -
// `uma`'s, always, and by name rather than by id. All three are kept because
// the two listings filter on two of them and because `GET .../settings`
// synthesises an aggregate policy's `config.applyPolicies` back out of the
// first.
//
// Ordinal is creation order. `GET .../policy` sorts by name byte-wise and
// `GET .../settings` serves creation order with the `resource` and `scope` rows
// moved to the end, so neither read can be derived from the other's order.
type AuthzPolicy struct {
	ID       string
	ClientID string
	Name     string
	// Description is omitted from every representation when empty and Owner is
	// served by none of them - it is echoed by the create and dropped by every
	// read - so absent and empty are one state for both.
	Description string
	Type        string
	// Logic and DecisionStrategy default to POSITIVE and UNANIMOUS. Both are
	// case-sensitive on the way in and a bad value is a 500 `Cannot parse the
	// JSON` rather than a validation error, because Jackson refuses the token
	// while binding the enum. **CONSENSUS is accepted here** and is a 500 on
	// `PUT .../authz/resource-server`, one path segment away.
	Logic              string
	DecisionStrategy   string
	Owner              string
	Config             []AuthzPolicyConfig
	AssociatedPolicies []string
	Resources          []string
	Scopes             []string
	Ordinal            int
}

// AuthzPolicyConfig is one config key and its value.
//
// The value is a string even when it carries a collection: `config.roles` is
// served as the **string** `"[{\"id\":\"...\",\"required\":false}]"` and not as
// a nested array, on every one of the four keys that hold one.
type AuthzPolicyConfig struct {
	Name  string
	Value string
}

// DefaultAuthzPolicyLogic and DefaultAuthzPolicyDecisionStrategy are what a
// policy created without them carries, measured on all nine types.
const (
	DefaultAuthzPolicyLogic            = "POSITIVE"
	DefaultAuthzPolicyDecisionStrategy = "UNANIMOUS"
)

// AuthzPolicyAssociationKinds is the `kind` column's domain, in the order both
// drivers write the rows.
var AuthzPolicyAssociationKinds = []string{"policy", "resource", "scope"}

// AssociationSet returns the ids stored under one association kind.
//
// It is on the model rather than in a driver for AddAttribute's reason: both
// drivers write the same three sets into the same table from the same slices,
// and a copy in each is a copy that can diverge.
func (p *AuthzPolicy) AssociationSet(kind string) []string {
	switch kind {
	case "policy":
		return p.AssociatedPolicies
	case "resource":
		return p.Resources
	case "scope":
		return p.Scopes
	}
	return nil
}

// AddAssociation appends one id under kind, which is what both drivers do while
// scanning the association rows back.
func (p *AuthzPolicy) AddAssociation(kind, id string) {
	switch kind {
	case "policy":
		p.AssociatedPolicies = append(p.AssociatedPolicies, id)
	case "resource":
		p.Resources = append(p.Resources, id)
	case "scope":
		p.Scopes = append(p.Scopes, id)
	}
}

// ConfigValue returns the value stored under name.
func (p *AuthzPolicy) ConfigValue(name string) (string, bool) {
	for _, c := range p.Config {
		if c.Name == name {
			return c.Value, true
		}
	}
	return "", false
}

// SetConfig writes name, replacing an existing entry in place so the order the
// entries arrived in survives an overwrite - which is what the import's merge
// needs, since it writes over a config that is already there.
func (p *AuthzPolicy) SetConfig(name, value string) {
	for i := range p.Config {
		if p.Config[i].Name == name {
			p.Config[i].Value = value
			return
		}
	}
	p.Config = append(p.Config, AuthzPolicyConfig{Name: name, Value: value})
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

// IdentityProvider is one entry of a realm's identity brokering configuration,
// the object `/admin/realms/{realm}/identity-provider/instances` serves.
//
// Its identity is the InternalID and its address is the Alias, and the two are
// not interchangeable: every route in the family takes the alias, while the
// representation carries both.
//
// **Alias is a pointer because a provider with no alias at all is reachable.**
// `PUT .../instances/{alias}` with a body carrying no `alias` answers 204 and
// leaves the row with its alias cleared - the listing then serves it with no
// `alias` key and nothing can address it again. That is Keycloak's own defect
// and it is reproduced, so the model has to be able to hold the state.
type IdentityProvider struct {
	InternalID  string
	RealmID     string
	Alias       *string
	DisplayName string
	ProviderID  string
	Enabled     bool
	// The six tri-state flags. **Absent and false are two measured answers**:
	// a create that never mentions trustEmail reads back with no `trustEmail`
	// key, and one sending `"trustEmail":false` reads back carrying
	// `"trustEmail":false`. A plain bool collapses the pair, on six fields at
	// once. Enabled above is not one of them - it is always serialised and
	// defaults to true.
	TrustEmail               *bool
	StoreToken               *bool
	AddReadTokenRoleOnCreate *bool
	AuthenticateByDefault    *bool
	LinkOnly                 *bool
	HideOnLogin              *bool
	// FirstBrokerLoginFlowAlias is omitted when empty, so empty and absent are
	// one state here and two on the six flags above.
	FirstBrokerLoginFlowAlias string
	// Config is a slice rather than a map for the reason
	// OrganizationAttribute is: the wire order is a Java map's and a Go map
	// would sort it. Unlike an organization's attributes it is single-valued.
	Config []IdentityProviderConfigEntry
}

// IdentityProviderConfigEntry is one `config` key and its value.
type IdentityProviderConfigEntry struct {
	Name  string
	Value string
}

// identityProviderRegistry is the seventeen providers a default 26.7.1
// registers, counted from `GET /admin/serverinfo` on 2026-09-01 rather than
// incremented.
//
// It is a list rather than a predicate because `POST .../instances` refuses
// anything outside it with `Invalid identity provider id [x]`, and because two
// members - `oauth2` and `jwt-authorization-grant` - are registered and still
// refuse a bare create, for required **config** rather than for being unknown.
// Reading their 400 as "not registered" is the mistake this comment exists to
// prevent; `GET /admin/serverinfo` lists all seventeen.
var identityProviderRegistry = []string{
	"kubernetes", "jwt-authorization-grant", "saml", "oauth2", "oidc",
	"keycloak-oidc", "linkedin-openid-connect", "twitter", "github",
	"openshift-v4", "facebook", "google", "gitlab", "microsoft", "bitbucket",
	"paypal", "stackoverflow",
}

// IsIdentityProvider reports whether Keycloak registers this provider id.
func IsIdentityProvider(providerID string) bool {
	for _, p := range identityProviderRegistry {
		if p == providerID {
			return true
		}
	}
	return false
}

// The four measured `types` arrays. The value is **derived from the provider
// id and stored nowhere**, so it is a function rather than a field: a provider
// created before its capabilities were known would otherwise serve a stale
// list.
//
// Measured on all seventeen registered providers on 2026-09-01, one create
// each. The eleven social providers, `oauth2` and `jwt-authorization-grant`
// answer `[]`; `kubernetes` answers one type; `saml` answers a different one;
// `oidc` and `keycloak-oidc` answer five. Four answers over seventeen
// providers, so a boolean "is it OIDC" gets two of the four wrong.
var (
	identityProviderTypesOIDC = []string{
		"USER_AUTHENTICATION", "CLIENT_ASSERTION", "TRUST_MATERIAL",
		"EXCHANGE_EXTERNAL_TOKEN", "JWT_AUTHORIZATION_GRANT",
	}
	identityProviderTypesSAML       = []string{"USER_AUTHENTICATION"}
	identityProviderTypesKubernetes = []string{"CLIENT_ASSERTION"}
)

// IdentityProviderTypes returns the `types` array for a provider id. An
// unregistered id answers the empty list, which is what the eleven social
// providers answer too - no create can reach it, since the id is validated
// first.
func IdentityProviderTypes(providerID string) []string {
	switch providerID {
	case "oidc", "keycloak-oidc":
		return identityProviderTypesOIDC
	case "saml":
		return identityProviderTypesSAML
	case "kubernetes":
		return identityProviderTypesKubernetes
	default:
		return []string{}
	}
}

// Component is one row of the generic SPI-component store, the object
// `/admin/realms/{realm}/components` serves.
//
// A default realm has fourteen of them and master has fifteen: four key
// providers, ten client-registration policies, and - on master alone - the
// declarative user profile. So the listing is neither empty nor about user
// federation on a fresh install, which is what a first look at the tag name
// suggests.
//
// **Name is a pointer** because the user-profile component has no `name` key at
// all where every other row has one, and that is the only observable
// difference between "no name" and "empty name" this family offers.
type Component struct {
	ID           string
	RealmID      string
	Name         *string
	ProviderID   string
	ProviderType string
	// ParentID is the realm's own internal id on every component a default
	// install has. It is stored rather than derived because the schema allows a
	// component to parent another one and `sub-component-types` addresses that
	// case, even though nothing in this cut creates one.
	ParentID string
	// SubType is `anonymous` or `authenticated` on the ten client-registration
	// policies and absent on everything else.
	SubType string
	Config  []ComponentConfigEntry
}

// ComponentConfigEntry is one `config` key and its values. The values are a
// list because a component's config is Keycloak's MultivaluedHashMap and every
// value on the wire is a JSON array, `{"priority":["100"]}`, even when it holds
// one string.
type ComponentConfigEntry struct {
	Name   string
	Values []string
}

// AddConfig appends one value under name, extending the existing entry when
// the name repeats. It is on the model for the reason Organization.AddAttribute
// is: both drivers rebuild the same slice from the same ordered rows.
func (c *Component) AddConfig(name, value string) {
	for i := range c.Config {
		if c.Config[i].Name == name {
			c.Config[i].Values = append(c.Config[i].Values, value)
			return
		}
	}
	c.Config = append(c.Config, ComponentConfigEntry{Name: name, Values: []string{value}})
}

// IdentityProviderMapper is one entry of
// `/admin/realms/{realm}/identity-provider/instances/{alias}/mappers`.
//
// **Alias is a plain string on the row and it is the body's, not the path's.**
// Measured 2026-09-02: a create sends `identityProviderAlias` and it is stored
// and echoed raw, a `PUT` can change it to a value no provider has, and the
// three single-mapper routes resolve the id **without looking at the alias in
// the path at all** - a mapper of one provider was read and then deleted
// through another provider's path. Only the listing is filtered by alias. So
// this is a stored field rather than a foreign key onto IdentityProvider, and
// making it one would refuse a state the server reaches.
//
// Config is single-valued, where a Component's is a list: an identity provider
// mapper's config is `{"role":"offline_access"}` on the wire and a component's
// is `{"priority":["100"]}`.
type IdentityProviderMapper struct {
	ID      string
	RealmID string
	Alias   string
	Name    string
	// Mapper is the wire's `identityProviderMapper`. **It is not validated**:
	// a create naming a mapper type that does not exist answered 201, so this
	// holds whatever the caller sent.
	Mapper string
	Config []IdentityProviderMapperConfigEntry
}

// IdentityProviderMapperConfigEntry is one `config` key and its value.
//
// It is its own type rather than a reuse of IdentityProviderConfigEntry, which
// has the identical shape, because the two are only measured to agree today:
// the parent provider's config masks a `clientSecret` on the way out and this
// one masks nothing, so a field added to either for its own reason would arrive
// in the other by accident.
type IdentityProviderMapperConfigEntry struct {
	Name  string
	Value string
}
