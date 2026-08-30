package admin

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
)

// authProvidersJSON is the authentication SPI registry, read off a live 26.7.1
// and stored verbatim.
//
// It is one file for six operations, and that is a measurement rather than a
// convenience. For all 52 ids that `GET .../config-description/{providerId}`
// resolves, its `name` is the registry entry's `displayName` and its `helpText`
// is that entry's `description`, with **zero** mismatches across the three
// registries that resolve. So the registry listing and the config description
// are two views of one table, and holding them apart would be two places for
// one string to drift.
//
// The four registries are **disjoint**: 53 ids, none in two of them.
// `config-description` resolves 52 of the 53 and answers 404 for the
// fifty-third - `registration-page-form`, the one form provider - which is why
// formProviders carries no properties and is looked up separately.
//
// All four listings, `per-client-config-description` and all 52 config
// descriptions were re-read after a `docker restart` and came back byte for
// byte identical, so none of this needs Case.Unordered.
//
//go:embed authproviders.json
var authProvidersJSON []byte

// configProperty is one entry of a provider's `properties` array.
//
// The field order is the measured serialisation order and the three omitempty
// members are measured too: 87 properties across the three registries came back
// in five distinct key orders, and one field list with `helpText`,
// `defaultValue` and `options` optional reproduces all five. `user-session-limits`'
// `behavior` is the one property with no `helpText` at all.
//
// DefaultValue is `any` because three types were measured in it - string, bool
// and **number** - and the number is on a property whose `type` is `"String"`:
// `max_auth_age` defaults to `300`, not `"300"`. Typing this as a string is the
// tidy-up that changes a byte.
type configProperty struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	HelpText     string   `json:"helpText,omitempty"`
	Type         string   `json:"type"`
	DefaultValue any      `json:"defaultValue,omitempty"`
	Options      []string `json:"options,omitempty"`
	Secret       bool     `json:"secret"`
	Required     bool     `json:"required"`
	ReadOnly     bool     `json:"readOnly"`
}

// authProvider is one row of a registry.
//
// The registry listings are Java `Map<String,Object>`s Keycloak builds by hand,
// not beans, so their key order is `HashMap` bucket order and not the order
// anything was put in. `javamap.KeyOrder` places both shapes exactly:
//
//	{id, displayName, description}                 -> displayName, description, id
//	{id, displayName, description, supportsSecret} -> supportsSecret, displayName, description, id
//
// The two serialiser types below carry those orders as declared fields, which
// is what AGENTS.md's "Response bodies" section asks for. javamap is what says
// the orders are not arbitrary; it is not called at runtime.
type authProvider struct {
	ID             string           `json:"id"`
	DisplayName    string           `json:"displayName"`
	Description    string           `json:"description"`
	SupportsSecret bool             `json:"supportsSecret"`
	Properties     []configProperty `json:"properties"`
}

type authProviderRegistry struct {
	Authenticators       []authProvider `json:"authenticators"`
	FormActions          []authProvider `json:"formActions"`
	ClientAuthenticators []authProvider `json:"clientAuthenticators"`
	FormProviders        []authProvider `json:"formProviders"`
	// RequiredActionProperties is the other registry on this tag: the config
	// properties of a required action provider, keyed by provider id. Thirteen
	// of the fourteen registered actions are configurable; `delete_account` is
	// not and is absent from this map, which is what makes its
	// `config-description` a 404 and its `config` a 400.
	RequiredActionProperties map[string][]configProperty `json:"requiredActionProperties"`

	// RequiredActions is the fourteen required action providers in the order
	// `GET .../unregistered-required-actions` serves them - which is neither
	// alphabetical, nor by priority, nor the order they were deleted in. It was
	// read off the server by unregistering all fourteen, because filtering a
	// stored order is the only way to reproduce a list whose order nothing in
	// the request explains.
	//
	// It is `HashMap` bucket order: `javamap.KeyOrder` puts twelve of the
	// fourteen in the measured position and swaps exactly the two colliding
	// pairs - `{TERMS_AND_CONDITIONS, update_user_locale}` and
	// `{VERIFY_EMAIL, delete_account}` - which is the documented limit of that
	// function rather than a failure of it, since a chain orders by an
	// insertion order nothing observable reveals. So the order is stored.
	RequiredActions []requiredActionProvider `json:"requiredActions"`
}

// requiredActionProvider is one of the fourteen, and its two fields are exactly
// what `unregistered-required-actions` serves for it. The `name` here is the
// provider's own display name, which is what that endpoint emits even for a row
// that had been renamed before it was deleted.
type requiredActionProvider struct {
	ProviderID string `json:"providerId"`
	Name       string `json:"name"`
}

var authProviders = func() authProviderRegistry {
	var r authProviderRegistry
	if err := json.Unmarshal(authProvidersJSON, &r); err != nil {
		panic("admin: authproviders.json: " + err.Error())
	}
	return r
}()

// requiredActionProviders is the fourteen in their serving order.
var requiredActionProviders = authProviders.RequiredActions

// knownRequiredActionProvider reports whether an id names one of the fourteen.
// It is wider than the configurable-provider check the /config routes make:
// `delete_account` is registrable and is not configurable.
func knownRequiredActionProvider(id string) bool {
	for _, p := range requiredActionProviders {
		if p.ProviderID == id {
			return true
		}
	}
	return false
}

// providerListEntry is what the three registries without a secret flag serve:
// three keys in HashMap bucket order.
type providerListEntry struct {
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	ID          string `json:"id"`
}

// clientProviderListEntry is `client-authenticator-providers`' own shape. The
// extra key comes **first**, which is what a fourth key does to the bucket
// order rather than anything about its meaning.
type clientProviderListEntry struct {
	SupportsSecret bool   `json:"supportsSecret"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description"`
	ID             string `json:"id"`
}

// authConfigDescription is `GET .../config-description/{providerId}`.
//
// Four keys, and `properties` is `[]` rather than absent on the 32 providers
// that have none.
type authConfigDescription struct {
	Name       string           `json:"name"`
	ProviderID string           `json:"providerId"`
	HelpText   string           `json:"helpText"`
	Properties []configProperty `json:"properties"`
}

// requiredActionConfigDescription is
// `GET .../required-actions/{alias}/config-description`, and it is **not** the
// shape above with fewer keys - it carries `properties` and nothing else. Two
// endpoints on one tag whose names differ by a path segment and whose bodies
// share one key.
type requiredActionConfigDescription struct {
	Properties []configProperty `json:"properties"`
}

func providerList(in []authProvider) []providerListEntry {
	out := make([]providerListEntry, 0, len(in))
	for _, p := range in {
		out = append(out, providerListEntry{
			DisplayName: p.DisplayName,
			Description: p.Description,
			ID:          p.ID,
		})
	}
	return out
}

// findAuthProvider resolves an id across the three registries
// `config-description` can see. The form provider is deliberately not searched:
// `config-description/registration-page-form` is a **404** on a live server,
// and adding it here would serve a body Keycloak does not.
func findAuthProvider(id string) (authProvider, bool) {
	for _, group := range [][]authProvider{
		authProviders.Authenticators,
		authProviders.FormActions,
		authProviders.ClientAuthenticators,
	} {
		for _, p := range group {
			if p.ID == id {
				return p, true
			}
		}
	}
	return authProvider{}, false
}

// nonNilProperties keeps `properties` marshalling as `[]` rather than `null`.
func nonNilProperties(p []configProperty) []configProperty {
	if p == nil {
		return []configProperty{}
	}
	return p
}

func (h *handler) listAuthenticatorProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	writeAdminJSON(w, providerList(authProviders.Authenticators))
}

func (h *handler) listFormActionProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	writeAdminJSON(w, providerList(authProviders.FormActions))
}

func (h *handler) listFormProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	writeAdminJSON(w, providerList(authProviders.FormProviders))
}

func (h *handler) listClientAuthenticatorProviders(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	out := make([]clientProviderListEntry, 0, len(authProviders.ClientAuthenticators))
	for _, p := range authProviders.ClientAuthenticators {
		out = append(out, clientProviderListEntry{
			SupportsSecret: p.SupportsSecret,
			DisplayName:    p.DisplayName,
			Description:    p.Description,
			ID:             p.ID,
		})
	}
	writeAdminJSON(w, out)
}

// perClientConfigDescription is a JSON object whose key order is measured and
// therefore cannot be a Go map, which encoding/json sorts.
//
// It is model.StringMap's problem with a value type that is not a string, and
// it is local to this package because it is one endpoint's shape rather than a
// domain type. The marshaller is hand-written for the same reason
// internal/admin writes a credential's five argon2 keys out in order instead of
// marshalling a map.
type perClientConfigDescription []perClientEntry

type perClientEntry struct {
	id         string
	properties []configProperty
}

func (d perClientConfigDescription) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range d {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(e.id)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		value, err := json.Marshal(nonNilProperties(e.properties))
		if err != nil {
			return nil, err
		}
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// readPerClientConfigDescription serves
// GET .../authentication/per-client-config-description.
//
// It is the one operation of the six that is not a list: a JSON **object**
// keyed by client-authenticator id, five keys, each an array of properties.
// The brief that scoped this cut called it a provider list and it is not.
//
// Its key order is the `client-authenticator-providers` listing's order, and
// that identity was checked rather than assumed - the two came back in the same
// order on one container. Both are `javamap.KeyOrder`'s answer for those five
// ids; `SizedKeyOrder` gets the same five wrong.
func (h *handler) readPerClientConfigDescription(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	out := make(perClientConfigDescription, 0, len(authProviders.ClientAuthenticators))
	for _, p := range authProviders.ClientAuthenticators {
		out = append(out, perClientEntry{id: p.ID, properties: p.Properties})
	}
	writeAdminJSON(w, out)
}

// readAuthenticatorConfigDescription serves
// GET .../authentication/config-description/{providerId}.
//
// An id no registry knows is 404 `Could not find authenticator provider`, which
// is a **sixteenth** spelling of not-found on this API and the first of three
// this one tag adds.
func (h *handler) readAuthenticatorConfigDescription(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	p, ok := findAuthProvider(r.PathValue("providerID"))
	if !ok {
		httpx.WriteMessageError(w, http.StatusNotFound, "Could not find authenticator provider")
		return
	}
	writeAdminJSON(w, authConfigDescription{
		Name:       p.DisplayName,
		ProviderID: p.ID,
		HelpText:   p.Description,
		Properties: nonNilProperties(p.Properties),
	})
}
