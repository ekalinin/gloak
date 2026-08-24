package admin

import (
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
// Not represented: protocolMappers, which two bootstrapped clients carry and
// whose model is P5. A client with mappers cannot be reproduced yet, which is
// why the recorded list case filters down to one that has none.
type clientRepresentation struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
	// Measured between name and rootUrl, and carrying omitempty for the same
	// reason those two do: none of the six bootstrapped clients has one. It
	// was missing entirely until kcadm.sh set one and it vanished - see
	// TestKcadmDrivesTheAdminAPI.
	Description                        string            `json:"description,omitempty"`
	RootURL                            string            `json:"rootUrl,omitempty"`
	BaseURL                            string            `json:"baseUrl,omitempty"`
	SurrogateAuthRequired              bool              `json:"surrogateAuthRequired"`
	Enabled                            bool              `json:"enabled"`
	AlwaysDisplayInConsole             bool              `json:"alwaysDisplayInConsole"`
	ClientAuthenticatorType            string            `json:"clientAuthenticatorType"`
	Secret                             string            `json:"secret,omitempty"`
	RedirectURIs                       []string          `json:"redirectUris"`
	WebOrigins                         []string          `json:"webOrigins"`
	NotBefore                          int               `json:"notBefore"`
	BearerOnly                         bool              `json:"bearerOnly"`
	ConsentRequired                    bool              `json:"consentRequired"`
	StandardFlowEnabled                bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled                bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled          bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled             bool              `json:"serviceAccountsEnabled"`
	PublicClient                       bool              `json:"publicClient"`
	FrontchannelLogout                 bool              `json:"frontchannelLogout"`
	Protocol                           string            `json:"protocol,omitempty"`
	Attributes                         map[string]string `json:"attributes"`
	AuthenticationFlowBindingOverrides map[string]string `json:"authenticationFlowBindingOverrides"`
	FullScopeAllowed                   bool              `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout          int               `json:"nodeReRegistrationTimeout"`
	DefaultClientScopes                []string          `json:"defaultClientScopes"`
	OptionalClientScopes               []string          `json:"optionalClientScopes"`
	Access                             accessClaim       `json:"access"`
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
func clientAccessFor(c *caller, m *model.Client, realmName string) accessClaim {
	manage := c.has("manage-clients")
	if m.ClientID == realmName+"-realm" {
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
		PublicClient:                       m.PublicClient,
		FrontchannelLogout:                 m.FrontchannelLogout,
		Protocol:                           m.Protocol,
		Attributes:                         nonNilMap(m.Attributes),
		AuthenticationFlowBindingOverrides: map[string]string{},
		FullScopeAllowed:                   m.FullScopeAllowed,
		NodeReRegistrationTimeout:          m.NodeReRegistrationTimeout,
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
