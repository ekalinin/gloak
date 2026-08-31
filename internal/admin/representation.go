package admin

import (
	"bytes"
	"encoding/json"
	"net/url"

	"github.com/ekalinin/gloak/internal/model"
)

// clientRepresentation is Keycloak's ClientRepresentation, in the field order
// measured on a live instance and transcribed from
// internal/conformance/testdata/golden/admin/clients/read.http - not from the
// OpenAPI schema, which lists what may appear rather than what does.
//
// Three fields carry omitempty and the rest do not, and that split is measured
// rather than chosen: rootUrl and baseUrl are absent on admin-cli, broker and
// master-realm, and protocol is absent on master-realm alone. Everything else
// appears on all six bootstrapped clients, including the false booleans and
// the empty arrays - so redirectUris and webOrigins must marshal as [] rather
// than null, which is why the store keeps them non-nil.
//
// protocolMappers is the one key that is absent rather than empty. Four of the
// six bootstrapped clients have no such key and account-console and
// security-admin-console have one mapper each, so nonNil would be wrong here
// where it is right for redirectUris and webOrigins two fields up.
type clientRepresentation struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	// Name joins its three neighbours in carrying omitempty. Measured on a
	// client created with clientId alone: the representation has **no** `name`
	// key, exactly as it has no `rootUrl`, `baseUrl` or `description`. The one
	// case omitempty gets wrong is a client created with `"name":""`, which
	// Keycloak answers with the key present and empty; nothing distinguishes
	// that from an absent key on a plain string, and reproducing it means a
	// *string on four fields to serve a body nobody sends.
	Name string `json:"name,omitempty"`
	// Measured between name and rootUrl, and carrying omitempty for the same
	// reason those two do: none of the six bootstrapped clients has one. It
	// was missing entirely until kcadm.sh set one and it vanished - see
	// TestKcadmDrivesTheAdminAPI.
	Description               string   `json:"description,omitempty"`
	RootURL                   string   `json:"rootUrl,omitempty"`
	BaseURL                   string   `json:"baseUrl,omitempty"`
	SurrogateAuthRequired     bool     `json:"surrogateAuthRequired"`
	Enabled                   bool     `json:"enabled"`
	AlwaysDisplayInConsole    bool     `json:"alwaysDisplayInConsole"`
	ClientAuthenticatorType   string   `json:"clientAuthenticatorType"`
	Secret                    string   `json:"secret,omitempty"`
	RedirectURIs              []string `json:"redirectUris"`
	WebOrigins                []string `json:"webOrigins"`
	NotBefore                 int      `json:"notBefore"`
	BearerOnly                bool     `json:"bearerOnly"`
	ConsentRequired           bool     `json:"consentRequired"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool     `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled"`
	// AuthorizationServicesEnabled is **absent rather than false**, which is why
	// it carries omitempty where every boolean around it does not. Measured on
	// all six bootstrapped clients of a default 26.7.1: none of them has the
	// key at all, and a client created with the flag carries `true`. Emitting
	// `false` "for consistency with the neighbours" would move every client
	// golden in the repository, and it would be wrong.
	//
	// It sits between serviceAccountsEnabled and publicClient, which is where
	// the recording puts it.
	AuthorizationServicesEnabled       bool              `json:"authorizationServicesEnabled,omitempty"`
	PublicClient                       bool              `json:"publicClient"`
	FrontchannelLogout                 bool              `json:"frontchannelLogout"`
	Protocol                           string            `json:"protocol,omitempty"`
	Attributes                         map[string]string `json:"attributes"`
	AuthenticationFlowBindingOverrides map[string]string `json:"authenticationFlowBindingOverrides"`
	FullScopeAllowed                   bool              `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout          int               `json:"nodeReRegistrationTimeout"`
	// ProtocolMappers is the client's own mappers, and it is **absent** when
	// there are none rather than `[]` - the same rule a client scope's follows,
	// measured on the same day: four of the six bootstrapped clients have no
	// `protocolMappers` key at all, and account-console and
	// security-admin-console have one each. It sits between
	// nodeReRegistrationTimeout and defaultClientScopes, which is where the
	// recording puts it.
	ProtocolMappers      []protocolMapperRepresentation `json:"protocolMappers,omitempty"`
	DefaultClientScopes  []string                       `json:"defaultClientScopes"`
	OptionalClientScopes []string                       `json:"optionalClientScopes"`
	Access               accessClaim                    `json:"access"`
}

// accessClaim is the computed permissions block Keycloak appends to a
// representation. It describes what the **caller** may do with the object, not
// anything stored about the object itself - getting that backwards produces a
// response that is plausible and wrong for every caller but an administrator.
type accessClaim struct {
	View      bool `json:"view"`
	Configure bool `json:"configure"`
	Manage    bool `json:"manage"`
}

// clientAccessFor computes the access block for a client.
//
// **The realm's own client is not configurable, whatever the caller holds.**
// Measured: listing clients as a full administrator returns
// {"view":true,"configure":true,"manage":true} for five of the six
// bootstrapped clients and {"view":true,"configure":false,"manage":false} for
// master-realm. broker is a realm client too - it carries realm_client "true" -
// and is fully manageable, so the distinction is not that attribute but this
// one client, the container Keycloak keeps the realm's own admin roles on.
//
// Only the administrator's values are measured. Which role backs each flag for
// a narrower caller is not, because reaching that recording needs role
// assignment, which is P2's second cut. The role mapping below is the obvious
// reading of the names and is inference, not contract.
//
// **The "realm's own client" test is a suffix, not one name.** Measured across
// seven clients and two realms: master-realm, other-realm and a hand-made
// nosuch-realm are all `"configure":false` in master, realm-management is in a
// created realm, and broker is fully manageable in both although it carries
// realm_client "true". So a realm-creating build has to ask
// isAdminContainerName rather than rebuilding one name, or every realm's own
// container outside master comes back configurable.
func clientAccessFor(c *caller, m *model.Client, realmName string) accessClaim {
	manage := c.has("manage-clients")
	if isAdminContainerName(realmName, m.ClientID) {
		return accessClaim{View: manage || c.has("view-clients")}
	}
	return accessClaim{
		View:      manage || c.has("view-clients"),
		Configure: manage,
		Manage:    manage,
	}
}

// clientRepresentationOf converts a stored client for the wire.
//
// The secret follows publicClient rather than what is stored, which is
// measured and not obvious. A public client given a secret through
// POST .../client-secret goes on showing none here, while a bearer-only
// client shows its. And none of the six bootstrapped clients has a secret at
// all, which is why the field never appeared in the earlier recordings.
func clientRepresentationOf(m *model.Client, c *caller, realmName string) clientRepresentation {
	secret := m.Secret
	if m.PublicClient {
		secret = ""
	}
	return clientRepresentation{
		ID:                                 m.ID,
		ClientID:                           m.ClientID,
		Name:                               m.Name,
		Description:                        m.Description,
		RootURL:                            m.RootURL,
		BaseURL:                            m.BaseURL,
		SurrogateAuthRequired:              m.SurrogateAuthRequired,
		Enabled:                            m.Enabled,
		AlwaysDisplayInConsole:             m.AlwaysDisplayInConsole,
		ClientAuthenticatorType:            m.ClientAuthenticatorType,
		Secret:                             secret,
		RedirectURIs:                       nonNil(m.RedirectURIs),
		WebOrigins:                         nonNil(m.WebOrigins),
		NotBefore:                          m.NotBefore,
		BearerOnly:                         m.BearerOnly,
		ConsentRequired:                    m.ConsentRequired,
		StandardFlowEnabled:                m.StandardFlowEnabled,
		ImplicitFlowEnabled:                m.ImplicitFlowEnabled,
		DirectAccessGrantsEnabled:          m.DirectAccessGrantsEnabled,
		ServiceAccountsEnabled:             m.ServiceAccountsEnabled,
		AuthorizationServicesEnabled:       m.AuthorizationServicesEnabled,
		PublicClient:                       m.PublicClient,
		FrontchannelLogout:                 m.FrontchannelLogout,
		Protocol:                           m.Protocol,
		Attributes:                         nonNilMap(m.Attributes),
		AuthenticationFlowBindingOverrides: map[string]string{},
		FullScopeAllowed:                   m.FullScopeAllowed,
		NodeReRegistrationTimeout:          m.NodeReRegistrationTimeout,
		ProtocolMappers:                    protocolMapperListOf(m.ProtocolMappers),
		DefaultClientScopes:                nonNil(m.DefaultClientScopes),
		OptionalClientScopes:               nonNil(m.OptionalClientScopes),
		Access:                             clientAccessFor(c, m, realmName),
	}
}

// nonNil turns a nil slice into an empty one. encoding/json marshals nil as
// null and an empty slice as [], and the measured representation carries [].
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// roleRepresentation is Keycloak's RoleRepresentation in the measured key
// order.
//
// Attributes is a pointer because the key's presence is what distinguishes the
// two measured shapes, and its natural value - an empty map - is exactly what
// omitempty would drop. A listing sends six keys, a single read seven. See
// briefRoles for the flag that picks, and note that it defaults the opposite
// way from the user listing's.
//
// containerId is the realm's UUID for a realm role and the client's UUID for a
// client role. Not the realm name.
type roleRepresentation struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description,omitempty"`
	Composite   bool                 `json:"composite"`
	ClientRole  bool                 `json:"clientRole"`
	ContainerID string               `json:"containerId"`
	Attributes  *map[string][]string `json:"attributes,omitempty"`
}

func roleRepresentationOf(r *model.Role, containerID string, brief bool) roleRepresentation {
	rep := roleRepresentation{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Composite:   r.Composite,
		ClientRole:  r.ClientID != "",
		ContainerID: containerID,
	}
	if !brief {
		attrs := r.Attributes
		if attrs == nil {
			// Measured: a role with no attributes reads back {} rather than
			// null, so the map has to exist even when the role's does not.
			attrs = map[string][]string{}
		}
		rep.Attributes = &attrs
	}
	return rep
}

// briefRoles reads briefRepresentation for a role listing, where it **defaults
// to true**. The user listing's version of this parameter defaults to false,
// measured on both, which is why the two do not share a helper.
func briefRoles(q url.Values) bool {
	return q.Get("briefRepresentation") != "false"
}

// mappingsRepresentation is the combined view GET /users/{id}/role-mappings
// sends - the one body in this family that is not a bare array.
//
// **Both keys are absent when their list would be empty**, measured: the
// bootstrapped administrator holds two realm roles and no client role directly
// and its body carries realmMappings alone, and a user stripped of every role
// answers `{}` with content-length 2. Neither `[]` nor `{}` is ever emitted for
// an empty half.
//
// Plain omitempty is enough for that, so neither field is a pointer. The plan
// asked for one on RealmMappings, reasoning that "omitempty on a slice cannot
// tell none from absent"; it can - encoding/json drops a slice field whose
// length is zero, nil or not. A pointer is what roleRepresentation.Attributes
// needs, because there the empty value has to be *emitted* as {}; here the
// empty value has to disappear, which is exactly what omitempty does.
type mappingsRepresentation struct {
	RealmMappings  []roleRepresentation `json:"realmMappings,omitempty"`
	ClientMappings clientMappings       `json:"clientMappings,omitempty"`
}

// clientMappings is the clientMappings object: one entry per client the user
// holds a role on, keyed by clientId.
//
// It is a slice rather than a map for the reason resourceAccess in
// internal/token is: Keycloak builds it from a Java Map and serialises it in
// HashMap bucket order, and Go sorts a map's keys. Measured on a subject
// holding one role on each of six clients cx1..cx6, created and assigned in
// that order, the keys came back cx6, cx5, cx2, cx1, cx4, cx3 - neither sorted
// nor insertion order, and exactly what javamap.KeyOrder predicts. See
// internal/javamap and the "clientMappings is a Java HashMap" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
type clientMappings []clientMappingsEntry

// clientMappingsEntry is one client's block inside clientMappings, which is
// keyed by clientId and then repeats the clientId as `client` alongside the
// UUID. ClientID is `json:"-"` because MarshalJSON below writes it as the
// object key rather than as a field of the value.
type clientMappingsEntry struct {
	ClientID string               `json:"-"`
	ID       string               `json:"id"`
	Client   string               `json:"client"`
	Mappings []roleRepresentation `json:"mappings"`
}

// MarshalJSON writes the entries as a JSON object in the order they are held,
// which is the order clientMappingsOf put them in.
func (m clientMappings) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range m {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(entry.ClientID)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := json.Marshal(entry)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
