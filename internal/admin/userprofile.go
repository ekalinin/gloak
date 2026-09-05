package admin

import (
	"encoding/json"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The three reads this cut takes out of the user-profile neighbourhood, and one
// measurement that governs all of them.
//
// **`GET /users/profile` re-serialises the stored config; it does not echo
// it** - and the first version of this file had it the other way round, because
// master's component holds 988 bytes and the endpoint answers the same 988,
// md5 7a2c214069eb9085ff019a8e75cbb6c7 on both. That agreement is a
// coincidence of the shipped config already being canonical. A config stored
// with odd spacing and `groups` before `attributes` was measured coming back
// compacted, reordered, and with `"multivalued":false` **added** to every
// attribute that lacked one.
//
// So the field order below is measured rather than transcribed, from a config
// carrying every field at once in a deliberately wrong order:
//
//	UPConfig     attributes, groups, unmanagedAttributePolicy
//	UPAttribute  name, displayName, validations, annotations, required,
//	             permissions, selector, group, multivalued
//	UPGroup      name, displayHeader, displayDescription, annotations
//	required     roles, scopes
//	permissions  view, edit           - sent edit-first, came back view-first
//
// **`validations` keeps the order it was stored in** and `annotations` does
// not: `{"up-username-not-idn-homograph":{},"length":{...}}` came back
// unchanged, where `{"z":"1","a":"2"}` came back `{"a":"2","z":"1"}`. So
// validations passes through as raw bytes and annotations does too - one
// measured pair cannot tell sorting from a Java map, and guessing which would
// turn an open question into a contract. No config Gloak ships carries an
// annotation, so the cell is unreachable here; it is recorded rather than
// resolved.
//
// **A realm created through POST /admin/realms has no such component** - the
// component listing filtered to `org.keycloak.userprofile.UserProfileProvider`
// is `[]` - and the endpoint answers a built-in default that **differs from
// master's**: `email`, `firstName` and `lastName` each carry
// `"required":{"roles":["user"]}` where master's config has no `required` at
// all. `internal/bootstrap/components.go` already models that split with its
// `masterOnly` flag, so both cells are reachable here and neither is invented.
//
// Two things this file deliberately does not serve, with the measurements that
// decided it:
//
//   - **`PUT /users/profile`** is `manage-realm` alone and answers 200 with the
//     stored profile, `application/json` and **no charset**. It replaces rather
//     than merges. It is left out because of what it does next: on a created
//     realm a profile declaring `length:{min:3}` on `username` made
//     `POST /users` with `{"username":"u1"}` answer
//     `400 {"field":"username","errorMessage":"error-invalid-length","params":["username",3,255]}`,
//     and on master a `PUT {}` - which omits `username` - **broke every login
//     in the realm**, the admin's own direct grant answering
//     `{"error":"invalid_grant","error_description":"Account is not fully set
//     up"}` afterwards. Gloak implements neither the validation nor the login
//     coupling, so serving the 200 alone lets a caller change something Gloak
//     then ignores.
//   - **`GET /users/profile/metadata`** is a derivation of the same config:
//     `validations` becomes `validators`, every validator gains
//     `"ignore.empty.value":true`, a `multivalued:{"max":"1"}` validator is
//     synthesised, and `required`/`readOnly` become booleans. `required` is
//     `false` for `email`, `firstName` and `lastName` **even on the created
//     realm whose profile marks all three required for the `user` role**,
//     because the metadata is rendered in the admin context. The two configs a
//     default install can have produce **byte-identical** metadata although
//     their profiles differ, so nothing reachable distinguishes the derivation
//     from a constant, and the `validators` key order on `username` -
//     `username-prohibited-characters, multivalued, length,
//     up-username-not-idn-homograph` - is neither sorted nor the profile's.

// userProfileComponentType is the providerType the realm's user profile is
// stored under. There is at most one row of it per realm.
const userProfileComponentType = "org.keycloak.userprofile.UserProfileProvider"

// userProfileConfigKey is the single config key that row carries. Its value is
// a JSON **string** holding the whole profile document, which is why this file
// writes a json.RawMessage rather than marshalling a Go value.
const userProfileConfigKey = "kc.user.profile.config"

// defaultUserProfile is what a realm with no `declarative-user-profile`
// component answers, recorded verbatim from a realm created through
// POST /admin/realms on a live 26.7.1 on 2026-09-05.
//
// It is **not** master's, and the difference is the three `required` blocks.
// Keeping the two apart is the whole reason this constant exists rather than
// the handler falling back on bootstrap's seed.
const defaultUserProfile = `{"attributes":[{"name":"username","displayName":"${username}",` +
	`"validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},` +
	`"up-username-not-idn-homograph":{}},"permissions":{"view":["admin","user"],` +
	`"edit":["admin","user"]},"multivalued":false},{"name":"email","displayName":"${email}",` +
	`"validations":{"email":{},"length":{"max":255}},"required":{"roles":["user"]},` +
	`"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},` +
	`{"name":"firstName","displayName":"${firstName}","validations":{"length":{"max":255},` +
	`"person-name-prohibited-characters":{}},"required":{"roles":["user"]},` +
	`"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},` +
	`{"name":"lastName","displayName":"${lastName}","validations":{"length":{"max":255},` +
	`"person-name-prohibited-characters":{}},"required":{"roles":["user"]},` +
	`"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false}],` +
	`"groups":[{"name":"user-metadata","displayHeader":"User metadata",` +
	`"displayDescription":"Attributes, which refer to user metadata"}]}`

// upConfig is Keycloak's UPConfig on the wire.
//
// `groups` has **no** omitempty and `attributes` has: a `PUT /users/profile {}`
// was measured leaving `{"groups":[]}`, one key, so the empty array is a
// default the server fills in and the empty attribute list is not.
type upConfig struct {
	Attributes               []upAttribute `json:"attributes,omitempty"`
	Groups                   []upGroup     `json:"groups"`
	UnmanagedAttributePolicy string        `json:"unmanagedAttributePolicy,omitempty"`
}

// upAttribute is UPAttribute in the measured field order.
//
// `multivalued` alone carries no omitempty, because it is emitted as `false`
// for an attribute that never mentioned it - measured on an attribute whose
// whole stored form was `{"name":"email"}`, which came back
// `{"name":"email","multivalued":false}`.
//
// Validations, Annotations and Selector are raw so that the order inside them
// is the stored one. That is measured for validations and measured **wrong**
// for annotations; see this file's header.
type upAttribute struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName,omitempty"`
	Validations json.RawMessage `json:"validations,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
	Required    *upRequired     `json:"required,omitempty"`
	Permissions *upPermissions  `json:"permissions,omitempty"`
	Selector    json.RawMessage `json:"selector,omitempty"`
	Group       string          `json:"group,omitempty"`
	Multivalued bool            `json:"multivalued"`
}

// upRequired is a class rather than a map: a stored `{"scopes":…,"roles":…}`
// came back `{"roles":…,"scopes":…}`.
type upRequired struct {
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// upPermissions is a class too, and the same probe says so: a stored
// `{"edit":…,"view":…}` came back `{"view":…,"edit":…}`.
type upPermissions struct {
	View []string `json:"view,omitempty"`
	Edit []string `json:"edit,omitempty"`
}

// upGroup is UPGroup, whose four fields were measured in this order by storing
// them in the reverse.
type upGroup struct {
	Name               string          `json:"name"`
	DisplayHeader      string          `json:"displayHeader,omitempty"`
	DisplayDescription string          `json:"displayDescription,omitempty"`
	Annotations        json.RawMessage `json:"annotations,omitempty"`
}

// readUserProfile serves GET /admin/realms/{realm}/users/profile.
//
// 200, `application/json;charset=UTF-8` and **no `Cache-Control`** - which is
// why it does not go through writeAdminJSON, the writer every other read in
// this cut uses. Measured: `no-cache` is on `unmanagedAttributes`,
// `federated-identity`, `credential-registrators` and the node routes, and not
// on this one.
//
// A stored config that does not parse is served as it stands rather than
// refused. Nothing measured says what Keycloak does with one, and this package
// cannot produce one: the only writer of that config in Gloak is
// `PUT /components/{id}`, which stores a string.
func (h *handler) readUserProfile(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	raw, err := h.userProfileConfig(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var cfg upConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		httpx.WriteJSONCharset(w, http.StatusOK, json.RawMessage(raw))
		return
	}
	if cfg.Groups == nil {
		cfg.Groups = []upGroup{}
	}
	httpx.WriteJSONCharset(w, http.StatusOK, cfg)
}

// userProfileConfig returns the realm's stored profile document, or the
// built-in default when the realm has no component holding one.
//
// It looks the component up by provider type rather than by id because the id
// is server-minted per realm and nothing addresses this row by it.
func (h *handler) userProfileConfig(r *http.Request, rc *reqContext) (string, error) {
	components, err := h.store.Components().List(r.Context(), rc.realm.ID)
	if err != nil {
		return "", err
	}
	for _, c := range components {
		if c.ProviderType != userProfileComponentType {
			continue
		}
		for _, entry := range c.Config {
			if entry.Name == userProfileConfigKey && len(entry.Values) > 0 {
				return entry.Values[0], nil
			}
		}
	}
	return defaultUserProfile, nil
}

// unmanagedAttributePolicy is the one field this package reads out of the
// profile document. Everything else in it is passed through as bytes.
type unmanagedAttributePolicyDocument struct {
	UnmanagedAttributePolicy string `json:"unmanagedAttributePolicy"`
}

// readUnmanagedAttributes serves
// GET /admin/realms/{realm}/users/{user-id}/unmanagedAttributes.
//
// Two cells, both measured 2026-09-05, and the branch between them is the point:
//
//   - a default realm's profile carries **no** `unmanagedAttributePolicy`, and
//     the endpoint answers `{}` for a user whose stored attributes are not
//     empty;
//   - a realm whose profile declares `"unmanagedAttributePolicy":"ENABLED"`
//     answers the user's attributes exactly -
//     `{"custom1":["v1"],"custom2":["a","b"]}` for a user created with them.
//
// A handler answering `{}` to both would be a probe measuring itself, and the
// policy is reachable through `PUT /components/{id}`, which this package
// already serves.
//
// The other policy values Keycloak's enumeration has - ADMIN_VIEW and
// ADMIN_EDIT - were **not** measured and are treated as ENABLED here, because
// both of them name an admin permission and this endpoint is the admin's. That
// is the one cell in this file resting on a reading rather than a measurement,
// and it is called out rather than hidden.
func (h *handler) readUnmanagedAttributes(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	raw, err := h.userProfileConfig(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var doc unmanagedAttributePolicyDocument
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := map[string][]string{}
	if doc.UnmanagedAttributePolicy != "" {
		for name, values := range user.Attributes {
			out[name] = values
		}
	}
	writeAdminJSON(w, out)
}

// readConfiguredUserStorageCredentialTypes serves
// GET /admin/realms/{realm}/users/{user-id}/configured-user-storage-credential-types.
//
// **`[]` is the whole reachable answer, not a stub.** The endpoint enumerates
// the credential types the user's *user storage federation provider* has
// configured. A default 26.7.1 has no federation provider, and **Gloak has none
// at all** - no `UserStorageProvider` type in the component catalogue, nothing
// that could back a user out of process - so every user in every Gloak realm is
// a local user and this is the answer for the entire input space. It is
// `client-types`' 501 and `client-secret/rotated`'s 404 in a third shape: a
// constant that is a contract because the feature behind it cannot be switched
// on.
func (h *handler) readConfiguredUserStorageCredentialTypes(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.userFromPath(w, r, rc); !ok {
		return
	}
	writeAdminJSON(w, []string{})
}

// credentialRegistrators is what GET /admin/realms/{realm}/credential-registrators
// answers, in the measured order.
//
// The same four names came back on master and on a realm created through
// POST /admin/realms, so the list does not follow the realm's required actions
// or its OTP policy. It is the set of required-action providers that register a
// credential, which on a default install is fixed.
var credentialRegistrators = []string{
	"CONFIGURE_TOTP",
	"webauthn-register",
	"webauthn-register-passwordless",
	"CONFIGURE_RECOVERY_AUTHN_CODES",
}

// listCredentialRegistrators serves GET /admin/realms/{realm}/credential-registrators.
//
// 200 with `Cache-Control: no-cache`. Its guard is the realm pair and nothing
// else: `view-realm` and `manage-realm` answer 200 and thirteen other admin
// roles were swept and all answer 403, `view-users` and `manage-users`
// included - which is what makes it a Realms Admin route in guard as well as in
// tag, unlike the client-scope defaults AGENTS.md records going the other way.
func (h *handler) listCredentialRegistrators(w http.ResponseWriter, _ *http.Request, _ *reqContext) {
	writeAdminJSON(w, credentialRegistrators)
}
