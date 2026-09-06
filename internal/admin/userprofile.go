package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
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
// The other two operations on this path are served here as well, and the
// sentence that used to stand in their place is worth keeping because it was
// half wrong:
//
//	"The two configs a default install can have produce **byte-identical**
//	 metadata although their profiles differ, so nothing reachable
//	 distinguishes the derivation from a constant."
//
// The first clause is measured and holds - master's metadata and a created
// realm's are both 1196 bytes, md5 d96998890507ef0a1b55714721f626c3, while
// their profiles are 988 and 1078 bytes and differ. **The second clause stopped
// being true when this package's own `POST`/`PUT /components/{id}` made a third
// profile reachable**, and the request was sent on 2026-09-06: a created realm
// carrying `username` at `length:{min:4,max:60}` and a fifth attribute answered
// 1278 bytes with both changes in it. A constant cannot move. See
// userProfileMetadata for the rules and metadataValidators for the key order.
//
// **A profile edited through either route breaks nothing in Gloak and breaks
// every login in Keycloak**, which is the one divergence this pair carries and
// is older than either: `PUT /components/{id}` has written the identical row
// since P9, with no validation at all. What this cut adds is the validation, so
// the divergence narrows rather than widening. Every `PUT /users/profile` in
// the measuring was addressed to a realm the probe had just created, never to
// master, because `{}` is the body that costs a container.
//
// One cell in the neighbourhood is measured and **deliberately left wrong**.
// The header above says annotations "passes through as stored" because one
// measured pair could not tell sorting from a Java map. Nine key sets say it is
// a Java map, and three of the nine were chosen in Go precisely because the two
// surviving models disagreed on them:
//
//	z, m, a                      -> m, a, z
//	aa, bb, cc, dd               -> aa, bb, cc, dd
//	inputType, kc.foo, zzz       -> kc.foo, inputType, zzz
//	one, two, three, four, five  -> two, three, five, four, one
//	b, a                         -> a, b
//	k1, k2, k3                   -> k3, k1, k2
//	a, b, c, d, e                -> a, b, c, d, e
//	d, e, f, g, h                -> h, d, e, f, g
//	f, g, h, i, j                -> h, i, j, f, g
//
// Read through `PUT /components/{id}`, which stores the bytes it is handed and
// is therefore the only writer that can tell the read's canonicalisation from
// the write's. The model that fits all nine is one Java table asked for the
// entry count, walked in insertion order - a **third** shape after
// javamap.KeyOrder and javamap.SizedKeyOrder. It is not fixed here: the place
// for a third constructor is internal/javamap, which this branch may not touch,
// and nothing in the tree moves either way because no profile a default install
// ships carries an annotation. Filed rather than guessed.

// upMetadata is UserProfileMetadata: what GET /users/profile/metadata answers.
//
// `groups` is the profile's own array **verbatim** - names, display fields,
// annotations and order alike - measured on a profile carrying two groups in a
// deliberately unsorted order. Only the attributes are derived.
type upMetadata struct {
	Attributes []upAttributeMetadata `json:"attributes"`
	Groups     []upGroup             `json:"groups"`
}

// upAttributeMetadata is one rendered attribute, in the measured field order.
//
// `displayName` and `validators` carry no omitempty and `annotations` and
// `group` do: an attribute that declares no display name is rendered with its
// own **name** there rather than with the key absent, and one that declares no
// validations still carries `"validators":{}`.
type upAttributeMetadata struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	Required    bool            `json:"required"`
	ReadOnly    bool            `json:"readOnly"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
	Validators  upValidators    `json:"validators"`
	Group       string          `json:"group,omitempty"`
	Multivalued bool            `json:"multivalued"`
}

// upValidators is the `validators` object, which is a Java map and therefore
// cannot be a Go map: encoding/json would sort it.
type upValidators []upValidator

// upValidator is one entry of that object.
//
// builtFor is how many keys the **profile** stored in this validator's config,
// which is not len(config) whenever the render appended `ignore.empty.value`.
// It is the argument javamap.SizedKeyOrder needs and the one measurement that
// separates the two spellings depends on it - see metadataValidators.
type upValidator struct {
	name     string
	config   []upValidatorConfigEntry
	builtFor int
}

// upValidatorConfigEntry is one key of a validator's config, kept as an ordered
// slice for the same reason upValidators is.
type upValidatorConfigEntry struct {
	name  string
	value json.RawMessage
}

// MarshalJSON writes the validators object in Keycloak's key order.
//
// **The two maps here are built by two different Java constructors, one nesting
// level apart**, which is the third time this API has done that after an
// identity provider's config against a component's. Measured 2026-09-06:
//
//	the validators object    javamap.KeyOrder                 5 of 6 key sets exact
//	a validator's config     javamap.SizedKeyOrder(builtFor)  7 of 7 exact
//
// The outer one's single miss is an attribute carrying six validators, where
// `pattern` and `options` come back the other way round - a bucket collision
// chaining in insertion order, which is exactly the limit javamap's own package
// comment states and not a new finding. **No realm a default install can
// produce reaches it**: it needs five validators declared on one attribute, so
// only a caller writing the profile can get there. It is written down here
// rather than hidden behind a Case.UnorderedKeys, because that mask would claim
// the value varies when it is exactly determined and merely unmodelled.
func (v upValidators) MarshalJSON() ([]byte, error) {
	names := make([]string, len(v))
	byName := make(map[string]upValidator, len(v))
	for i, e := range v {
		names[i] = e.name
		byName[e.name] = e
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, name := range javamap.KeyOrder(names) {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := marshalOrderedValue(name)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		body, err := byName[name].marshalConfig()
		if err != nil {
			return nil, err
		}
		buf.Write(body)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalConfig writes one validator's own config object.
//
// The order is javamap.SizedKeyOrder over the keys **in the order the profile
// stored them**, followed by whatever the render appended, built for the stored
// count. That is the protocol-mapper rule unchanged, and the argument is
// load-bearing rather than decorative: `length` carrying `min` and `max` -
// which is in master's own metadata - comes back `max, ignore.empty.value, min`
// from SizedKeyOrder(2, ...) and `ignore.empty.value, max, min` from
// SizedKeyOrder(3, ...). It is the one measured key set that separates the two
// spellings.
func (e upValidator) marshalConfig() ([]byte, error) {
	names := make([]string, len(e.config))
	byName := make(map[string]json.RawMessage, len(e.config))
	for i, c := range e.config {
		names[i] = c.name
		byName[c.name] = c.value
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, name := range javamap.SizedKeyOrder(e.builtFor, names) {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := marshalOrderedValue(name)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(byName[name])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// adminProfileRole is the role the metadata is rendered for. The endpoint is
// the administrator's, so an attribute's permissions and its required condition
// are both judged against this one name.
const adminProfileRole = "admin"

// usernameAttribute is the one attribute whose `required` does not follow the
// rule below.
const usernameAttribute = "username"

// readUserProfileMetadata serves GET /admin/realms/{realm}/users/profile/metadata.
//
// Same writer as the read beside it - `application/json;charset=UTF-8` and **no
// Cache-Control** - and the same guard, which is measured rather than inherited:
// fifteen master-realm roles one at a time, a fresh token each, and the five
// that open GET /users/profile open this and the ten that do not, do not.
func (h *handler) readUserProfileMetadata(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	raw, err := h.userProfileConfig(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var cfg upConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, userProfileMetadata(cfg))
}

// userProfileMetadata renders a stored profile the way the admin context sees
// it. Every rule below is one measured cell with a control that differs.
//
//	an attribute is rendered at all   iff permissions.view names "admin";
//	                                  an absent permissions block and `{}` both
//	                                  drop the attribute outright
//	displayName                       the attribute's own, falling back to its
//	                                  name - and `""` counts as absent
//	readOnly                          true unless permissions.edit names "admin",
//	                                  so edit:["user"], edit:[] and an absent
//	                                  edit are all read-only
//	required                          `username` always; otherwise a `required`
//	                                  block whose `scopes` is empty and whose
//	                                  `roles` is empty or names "admin"
//	multivalued                       the attribute's own
//
// The `required` rule took seven requests because three readings fit fewer:
// `{}` and `{"roles":[]}` are both **true**, `{"roles":["user"]}` is false,
// `{"roles":["user","admin"]}` is true, and `{"scopes":["profile"]}` - which
// has no roles at all and would be true under "roles empty means everybody" -
// is **false**. So a non-empty `scopes` is a second condition rather than a
// second spelling of the first, and the admin context requests no scopes.
//
// `username` overriding it is measured on the request that separates the two:
// a profile marking `username` required for the `user` role alone still renders
// `"required":true`, where the identical block on `email` renders false.
func userProfileMetadata(cfg upConfig) upMetadata {
	out := upMetadata{Attributes: []upAttributeMetadata{}, Groups: cfg.Groups}
	if out.Groups == nil {
		out.Groups = []upGroup{}
	}
	for _, a := range cfg.Attributes {
		if a.Permissions == nil || !slices.Contains(a.Permissions.View, adminProfileRole) {
			continue
		}
		display := a.DisplayName
		if display == "" {
			display = a.Name
		}
		out.Attributes = append(out.Attributes, upAttributeMetadata{
			Name:        a.Name,
			DisplayName: display,
			Required:    metadataRequired(a),
			ReadOnly:    !slices.Contains(a.Permissions.Edit, adminProfileRole),
			Annotations: a.Annotations,
			Validators:  metadataValidators(a),
			Group:       a.Group,
			Multivalued: a.Multivalued,
		})
	}
	return out
}

// metadataRequired is the `required` boolean. See userProfileMetadata for the
// seven requests behind it.
func metadataRequired(a upAttribute) bool {
	if a.Name == usernameAttribute {
		return true
	}
	if a.Required == nil {
		return false
	}
	if len(a.Required.Scopes) > 0 {
		return false
	}
	return len(a.Required.Roles) == 0 || slices.Contains(a.Required.Roles, adminProfileRole)
}

// ignoreEmptyValue is the key the render appends to every validator the profile
// declared - and to none that it synthesises.
const ignoreEmptyValue = "ignore.empty.value"

// metadataValidators turns an attribute's `validations` into its `validators`.
//
// Two things happen and they are not the same thing:
//
//   - every validator the **profile** declared gains `"ignore.empty.value":true`;
//   - a `multivalued:{"max":"1"}` validator is **synthesised, and only for a
//     single-valued attribute**. A multivalued one carrying one validator
//     answers one validator, and a multivalued one carrying none answers
//     `"validators":{}` - which is what says the synthesis is conditional
//     rather than the bound being different.
//
// The synthesised entry does **not** get `ignore.empty.value`, measured on
// every attribute of every profile read: its config is the single pair
// `{"max":"1"}`, and the `1` is a JSON **string** where a declared `length`'s
// `max` is a number.
func metadataValidators(a upAttribute) upValidators {
	out := upValidators{}
	if !a.Multivalued {
		out = append(out, upValidator{
			name:     "multivalued",
			config:   []upValidatorConfigEntry{{name: "max", value: json.RawMessage(`"1"`)}},
			builtFor: 1,
		})
	}
	for _, v := range decodeOrderedObject(a.Validations) {
		entries := decodeOrderedObject(v.value)
		config := make([]upValidatorConfigEntry, 0, len(entries)+1)
		config = append(config, entries...)
		config = append(config, upValidatorConfigEntry{
			name:  ignoreEmptyValue,
			value: json.RawMessage(`true`),
		})
		out = append(out, upValidator{name: v.name, config: config, builtFor: len(entries)})
	}
	return out
}

// decodeOrderedObject reads a JSON object into its members in the order they
// were written, which a map cannot preserve and which is the whole input to
// both key-order models above.
//
// Anything that is not an object - absent, null, an array - is no members
// rather than an error. The only producer of these bytes is a stored profile,
// and this package cannot make a malformed one: the two routes that write the
// config both parse it first.
func decodeOrderedObject(raw json.RawMessage) []upValidatorConfigEntry {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	var out []upValidatorConfigEntry
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return out
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return out
		}
		out = append(out, upValidatorConfigEntry{name: key, value: value})
	}
	return out
}

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

// updateUserProfile serves PUT /admin/realms/{realm}/users/profile.
//
// 200 with the canonicalised profile, `application/json` and **no charset** -
// the third Admin API 2xx body outside the charset rule, after
// `POST /groups/{id}/children`'s 201 and `POST /partial-export` - and no
// `Cache-Control`. Which is why it does not go through writeAdminJSON or
// through the charset writer the read beside it uses: **three writers on two
// routes of one path.**
//
// The answer is byte-identical to what `GET /users/profile` then serves and to
// what the component stores, measured all three ways round on one realm. So
// this handler renders once and writes the same bytes it answers, rather than
// answering a read of its own write - which is the shape
// `POST .../authz/resource-server/scope` warns about, where the create's echo
// and the read disagree.
//
// Guard: **manage-realm alone**, and the first sweep of it was wrong. It put
// master's callers against a created realm, where a master caller's rights do
// not reach, and read 403 in every cell - a probe measuring the realm boundary
// rather than the route. Re-run with callers inside the realm they address:
// view-realm 403, manage-users 403, manage-realm 200, realm-admin 200. So a
// manage-users caller may read this profile and may not write it, and the write
// guard is not a slice of the read guard's five.
func (h *handler) updateUserProfile(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !requireJSONBody(w, r) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **An absent body and the literal `null` delete the row**, where `{}`
	// stores a document with no attributes in it. Measured with a control: a
	// marker attribute was written, read back, and was gone afterwards, and the
	// realm then answered the built-in default rather than what it had held.
	// On master - which is the realm where the two differ - the same request
	// dropped the shipped 988-byte profile and left the realm answering the
	// 1078-byte default, with no component row at all. So the reset is a delete
	// and not a write of the default, and defaultUserProfile is already what
	// userProfileConfig falls back to.
	if isAbsentJSONBody(body) {
		if err := h.deleteUserProfileComponent(r, rc); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		h.writeUserProfile(w, r, rc)
		return
	}

	var cfg upConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		writeCannotParseJSON(w, body)
		return
	}
	if field, class, ok := firstUnknownProfileField(body); ok {
		httpx.WriteMessageError(w, http.StatusBadRequest, fmt.Sprintf(
			"Invalid json representation for %s. Unrecognized field %q at line %d column %d.",
			class, field.name, field.line, field.column))
		return
	}
	scopes, err := h.realmClientScopeNames(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if problems := validateUserProfile(cfg, scopes); len(problems) > 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest,
			"["+strings.Join(problems, ", ")+"]")
		return
	}

	if cfg.Groups == nil {
		cfg.Groups = []upGroup{}
	}
	rendered, err := marshalOrderedValue(cfg)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.storeUserProfile(r, rc, string(rendered)); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// The success writer, spelled out rather than shared: no charset and no
	// Cache-Control, which is neither writeAdminJSON's pair nor the read's.
	httpx.WriteJSON(w, http.StatusOK, json.RawMessage(rendered))
}

// writeUserProfile answers with whatever the realm now holds. It is the reset
// path's response, and it goes through the PUT's writer rather than the read's:
// the reset answers `application/json` with no charset like every other 200 on
// this route, measured.
func (h *handler) writeUserProfile(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	raw, err := h.userProfileConfig(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	var cfg upConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		httpx.WriteJSON(w, http.StatusOK, json.RawMessage(raw))
		return
	}
	if cfg.Groups == nil {
		cfg.Groups = []upGroup{}
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// userProfileComponent returns the realm's profile row, or nil when it has
// none. Looked up by provider type for the reason userProfileConfig gives: the
// id is server-minted per realm and nothing addresses this row by it.
func (h *handler) userProfileComponent(r *http.Request, rc *reqContext) (*model.Component, error) {
	components, err := h.store.Components().List(r.Context(), rc.realm.ID)
	if err != nil {
		return nil, err
	}
	for _, c := range components {
		if c.ProviderType == userProfileComponentType {
			return c, nil
		}
	}
	return nil, nil
}

// storeUserProfile writes the document into the realm's profile row, creating
// the row when there is none.
//
// **The created row carries no `name`.** That is measured rather than an
// omission: the row `PUT /users/profile` creates on a realm that had none comes
// back with `providerId`, `providerType`, `parentId` and `config` and no `name`
// key, which is the same nameless shape AGENTS.md records master's shipped
// `declarative-user-profile` having.
func (h *handler) storeUserProfile(r *http.Request, rc *reqContext, document string) error {
	existing, err := h.userProfileComponent(r, rc)
	if err != nil {
		return err
	}
	if existing != nil {
		existing.Config = []model.ComponentConfigEntry{{
			Name:   userProfileConfigKey,
			Values: []string{document},
		}}
		return h.store.Components().Update(r.Context(), existing)
	}
	return h.store.Components().Create(r.Context(), &model.Component{
		ID:           model.NewID(),
		RealmID:      rc.realm.ID,
		ProviderID:   userProfileProviderID,
		ProviderType: userProfileComponentType,
		ParentID:     rc.realm.ID,
		Config: []model.ComponentConfigEntry{{
			Name:   userProfileConfigKey,
			Values: []string{document},
		}},
	})
}

// deleteUserProfileComponent removes the row, and is a no-op on a realm that
// has none - which is what makes the bodyless PUT idempotent.
func (h *handler) deleteUserProfileComponent(r *http.Request, rc *reqContext) error {
	existing, err := h.userProfileComponent(r, rc)
	if err != nil || existing == nil {
		return err
	}
	return h.store.Components().Delete(r.Context(), rc.realm.ID, existing.ID)
}

// userProfileProviderID is the providerId of the row this endpoint writes.
const userProfileProviderID = "declarative-user-profile"

// realmClientScopeNames is what `required.scopes` and `selector.scopes` are
// checked against. Both refusals name the scope, so the set has to be the
// realm's real one rather than a constant.
func (h *handler) realmClientScopeNames(r *http.Request, rc *reqContext) (map[string]bool, error) {
	scopes, err := h.store.ClientScopes().ListByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		out[s.Name] = true
	}
	return out, nil
}

// undeletableAttributes are the two the profile may not drop. **firstName and
// lastName may be dropped**, measured: a profile naming only username and email
// is a 200, so this is a pair rather than the four the representation has.
var undeletableAttributes = []string{"username", "email"}

// profileRoles is the closed set `permissions.view` and `permissions.edit` may
// name. An unsupported one is refused by name.
var profileRoles = map[string]bool{"admin": true, "user": true}

// profileValidators is the set of validator ids the profile may name, and it is
// **the thirty registered validator providers rather than the thirteen the
// component catalogue declares**.
//
// `GET /admin/serverinfo` offers both lists and they disagree by seventeen
// names. Validating against the smaller one would refuse `not-blank`,
// `up-duplicate-email` and fifteen others that a live 26.7.1 accepts - which is
// the mistake AGENTS.md already records the authorization policy family
// punishing, where "validating against the catalogue this repository already
// ships would refuse one working type and admit two that fail". So all thirty
// were sent one at a time: twenty-six answered 200 with an empty config and the
// other four answered about their **configuration** rather than their
// existence. Only a name outside the thirty answers `doesn't exist`.
var profileValidators = map[string]bool{
	"double": true, "email": true, "integer": true, "iso-date": true,
	"length": true, "local-date": true, "multivalued": true, "not-blank": true,
	"not-empty": true, "options": true, "organization-member-validator": true,
	"pattern": true, "person-name-prohibited-characters": true,
	"up-attribute-required-by-metadata-value":          true,
	"up-blank-attribute-value":                         true,
	"up-brokering-federated-username-has-value":        true,
	"up-duplicate-did":                                 true,
	"up-duplicate-email":                               true,
	"up-duplicate-username":                            true,
	"up-email-exists-as-username":                      true,
	"up-immutable-attribute":                           true,
	"up-readonly-attribute-unchanged":                  true,
	"up-registration-email-as-username-email-value":    true,
	"up-registration-email-as-username-username-value": true,
	"up-registration-username-exists":                  true,
	"up-username-has-value":                            true,
	"up-username-mutation":                             true,
	"up-username-not-idn-homograph":                    true,
	"uri":                                              true,
	"username-prohibited-characters":                   true,
}

// hintKind is what a validator's configuration entry has to be.
type hintKind int

const (
	numberHint hintKind = iota
	stringHint
	listHint
)

// validatorConfigRule is the configuration one validator requires.
//
// **Exactly four of the thirty have one**, and that is a complete sweep rather
// than a sample: every one of the thirty was sent `{}` and only these four
// objected. The other twenty-six accept an empty configuration, `integer` and
// `uri` among them.
type validatorConfigRule struct {
	// requiredAny are the hints of which at least one must be present. When
	// none is, **every one of them is reported missing**: `length:{}` answers
	// about `min` and about `max` in one response, where `length:{"min":1}` is
	// a 200 and says nothing about the absent `max`.
	requiredAny []string
	kind        map[string]hintKind
	// echoBadValue is whether the invalid-value error carries the offending
	// value in its messageParameters. `length` and `pattern` do and
	// `multivalued` does **not** - `{"multivalued":{"max":"x"}}` answers
	// `messageParameters=[]` where `{"length":{"min":"x"}}` answers
	// `messageParameters=[x]`. One error kind, two behaviours, and a shared
	// formatter that always echoes is wrong on the third of the three.
	echoBadValue bool
	// listParameter is the fixed text `options` reports instead of the value.
	listParameter string
}

var profileValidatorConfigs = map[string]validatorConfigRule{
	"length": {
		requiredAny:  []string{"min", "max"},
		kind:         map[string]hintKind{"min": numberHint, "max": numberHint},
		echoBadValue: true,
	},
	"pattern": {
		requiredAny:  []string{"pattern"},
		kind:         map[string]hintKind{"pattern": stringHint},
		echoBadValue: true,
	},
	"options": {
		requiredAny:   []string{"options"},
		kind:          map[string]hintKind{"options": listHint},
		listParameter: "must be list of values",
	},
	"multivalued": {
		requiredAny: []string{"max"},
		kind:        map[string]hintKind{"max": numberHint},
	},
}

// validateUserProfile returns the refusals a document earns, in the order
// Keycloak reports them.
//
// **The 400 carries a list and not a sentence**: the body is
// `{"errorMessage":"[...]"}` and the entries inside the brackets are joined
// with `, `, so `{"attributes":[]}` answers about `username` **and** `email` in
// one response. A validator that returned on the first problem would be right
// on every single-fault body and wrong on that one, which is the body a caller
// clearing the profile actually sends.
//
// The nine rules and the request that measured each:
//
//	[The attribute 'username' can not be removed]                username, email only
//	[The attribute 'email' can not be removed]                   dropping firstName is a 200
//	[Attribute configuration already exists with 'name':'email']
//	[Attribute configuration without 'name' is not allowed]      absent and "" alike
//	[Validator 'x' defined for attribute 'y' doesn't exist]
//	['permissions.view' configuration for attribute 'x' contains unsupported role 'y']
//	['required.scopes' configuration for attribute 'x' contains unsupported scope 'y']
//	['selector.scopes' configuration for attribute 'x' contains unsupported scope 'y']
//	[Attribute 'x' references unknown group 'y']
func validateUserProfile(cfg upConfig, scopes map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	groups := map[string]bool{}
	for _, g := range cfg.Groups {
		groups[g.Name] = true
	}
	for _, a := range cfg.Attributes {
		if a.Name == "" {
			out = append(out, "Attribute configuration without 'name' is not allowed")
			continue
		}
		if seen[a.Name] {
			out = append(out, "Attribute configuration already exists with 'name':'"+a.Name+"'")
			continue
		}
		seen[a.Name] = true
		for _, v := range decodeOrderedObject(a.Validations) {
			if !profileValidators[v.name] {
				out = append(out, "Validator '"+v.name+"' defined for attribute '"+a.Name+
					"' doesn't exist")
				continue
			}
			if errs := validatorConfigErrors(v.name, v.value); errs != "" {
				out = append(out, "Validator '"+v.name+"' defined for attribute '"+a.Name+
					"' has incorrect configuration: "+errs)
			}
		}
		if a.Permissions != nil {
			out = append(out, unsupportedRoles("permissions.view", a.Name, a.Permissions.View)...)
			out = append(out, unsupportedRoles("permissions.edit", a.Name, a.Permissions.Edit)...)
		}
		if a.Required != nil {
			out = append(out, unsupportedScopes("required.scopes", a.Name, a.Required.Scopes, scopes)...)
		}
		out = append(out, unsupportedScopes("selector.scopes", a.Name,
			selectorScopes(a.Selector), scopes)...)
		if a.Group != "" && !groups[a.Group] {
			out = append(out, "Attribute '"+a.Name+"' references unknown group '"+a.Group+"'")
		}
	}
	// **An absent `attributes` is not an empty one.** `{}` and `{"groups":[]}`
	// are 200s that store a document with no attributes at all, where
	// `{"attributes":[]}` is the 400 naming both undeletable names. So the
	// check runs over a list the document supplied and is skipped when it
	// supplied none - which encoding/json already distinguishes, nil against an
	// empty slice, and which a `len(...) == 0` test would collapse.
	if cfg.Attributes == nil {
		return out
	}
	// The two undeletable ones are reported after everything else and in the
	// representation's own order, which is what `{"attributes":[]}` says:
	// username before email, whatever the document held.
	for _, name := range undeletableAttributes {
		if !seen[name] {
			out = append(out, "The attribute '"+name+"' can not be removed")
		}
	}
	return out
}

// validatorConfigErrors renders the `ValidationError{...}` list one validator's
// configuration earns, or "" when it earns none.
//
// **The list has a trailing separator and the list around it does not.** The
// outer refusals are joined with `, ` and this one appends `, ` after every
// entry including the last, so a single bad validator answers
// `... messageParameters=[]}, ]` and two of them on one attribute answer
// `...[]}, , Validator 'pattern' ...`, with the empty gap the two conventions
// leave between them. Measured on both, and a shared join is wrong on whichever
// of the two it is not written for.
func validatorConfigErrors(name string, config json.RawMessage) string {
	rule, ok := profileValidatorConfigs[name]
	if !ok {
		return ""
	}
	entries := decodeOrderedObject(config)
	present := make(map[string]json.RawMessage, len(entries))
	for _, e := range entries {
		present[e.name] = e.value
	}
	var b strings.Builder
	add := func(hint, message, parameters string) {
		fmt.Fprintf(&b, "ValidationError{validatorId='%s', inputHint='%s', message='%s', "+
			"messageParameters=[%s]}, ", name, hint, message, parameters)
	}

	any := false
	for _, hint := range rule.requiredAny {
		if _, ok := present[hint]; ok {
			any = true
		}
	}
	if !any {
		for _, hint := range rule.requiredAny {
			add(hint, "error-validator-config-missing-value", "")
		}
		return b.String()
	}
	// The hints are walked in the rule's own order rather than the request's,
	// because that is the order `length:{}` reports its pair in - min then max -
	// whatever order a document that carried them would have used.
	for _, hint := range rule.requiredAny {
		raw, ok := present[hint]
		if !ok {
			continue
		}
		switch rule.kind[hint] {
		case numberHint:
			if isJSONNumberValue(raw) {
				continue
			}
			parameter := ""
			if rule.echoBadValue {
				parameter = javaValueText(raw)
			}
			add(hint, "error-validator-config-invalid-number-value", parameter)
		case stringHint:
			if isJSONStringValue(raw) {
				continue
			}
			add(hint, "error-validator-config-invalid-value", javaValueText(raw))
		case listHint:
			if isJSONArrayValue(raw) {
				continue
			}
			add(hint, "error-validator-config-invalid-value", rule.listParameter)
		}
	}
	return b.String()
}

// isJSONNumberValue reports whether a configuration value counts as a number.
// **A numeric string does**: `{"length":{"min":"5"}}` is a 200 and
// `{"length":{"min":"x"}}` is not, so the check is a parse rather than a JSON
// type test. `true` is refused, which is what rules out "anything that is not
// an object".
func isJSONNumberValue(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		trimmed = s
	}
	_, err := strconv.ParseFloat(strings.TrimSpace(trimmed), 64)
	return err == nil
}

func isJSONStringValue(raw json.RawMessage) bool {
	var s string
	return json.Unmarshal(raw, &s) == nil
}

func isJSONArrayValue(raw json.RawMessage) bool {
	return strings.HasPrefix(strings.TrimSpace(string(raw)), "[")
}

// javaValueText renders a configuration value the way Java's toString does
// inside messageParameters: a string as its contents with no quotes, and
// anything else as the JSON it arrived as. `{"length":{"min":"x"}}` reports
// `[x]` and `{"length":{"min":true}}` reports `[true]`.
func javaValueText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// unsupportedRoles is the refusal both permission lists share, named after the
// list that carried the bad value.
func unsupportedRoles(field, attribute string, list []string) []string {
	var out []string
	for _, role := range list {
		if !profileRoles[role] {
			out = append(out, "'"+field+"' configuration for attribute '"+attribute+
				"' contains unsupported role '"+role+"'")
		}
	}
	return out
}

// unsupportedScopes is the same refusal for the two scope lists, checked
// against the realm's own client scopes rather than a constant: `profile` is
// accepted and `nope` is not, on a realm holding the default fifteen.
func unsupportedScopes(field, attribute string, list []string, scopes map[string]bool) []string {
	var out []string
	for _, scope := range list {
		if !scopes[scope] {
			out = append(out, "'"+field+"' configuration for attribute '"+attribute+
				"' contains unsupported scope '"+scope+"'")
		}
	}
	return out
}

// selectorScopes reads the one field of `selector` this package looks at. The
// rest of the object is passed through as bytes, the way the profile read
// already treats it.
func selectorScopes(raw json.RawMessage) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var sel struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &sel); err != nil {
		return nil
	}
	return sel.Scopes
}

// firstUnknownProfileField finds the field Jackson would reject first anywhere
// in the document, and names the class that rejected it.
//
// **Three classes, and the position is absolute in all three.** A field at the
// top is `UPConfig`, one inside an element of `attributes` is `UPAttribute` and
// one inside `groups` is `UPGroup` - measured on eight bodies, with the column
// counted by hand on the short ones so the arithmetic is pinned rather than
// fitted. An unknown field 192 bytes into the document answered column 199
// whether it was at the top level or inside an attribute, which is what says
// only the class varies with depth.
//
// The candidates are compared by **offset** rather than by the order they are
// checked in, because Jackson reads the document once: a body with a bad field
// inside `attributes[0]` and another at the end must answer about the first.
func firstUnknownProfileField(body []byte) (unknownField, string, bool) {
	best, bestClass, found := unknownField{}, "", false
	consider := func(from int, class string, out any) {
		f, ok := firstUnknownFieldFrom(body, from, out)
		if !ok {
			return
		}
		if !found || f.offset < best.offset {
			best, bestClass, found = f, class, true
		}
	}
	consider(0, "UPConfig", &upConfig{})
	for _, off := range profileArrayElements(body, "attributes") {
		consider(off, "UPAttribute", &upAttribute{})
	}
	for _, off := range profileArrayElements(body, "groups") {
		consider(off, "UPGroup", &upGroup{})
	}
	return best, bestClass, found
}

// profileArrayElements returns the body offset of each object inside the named
// top-level array. Anything that is not an array of objects contributes
// nothing, which leaves the answer to the ordinary parse failure.
func profileArrayElements(body []byte, name string) []int {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, _ := keyTok.(string)
		var raw json.RawMessage
		// InputOffset before Decode is just past the key; after it, just past
		// the value. The value therefore occupies the bytes between the first
		// non-space after the colon and that end offset.
		start := skipToValue(body, int(dec.InputOffset()))
		if err := dec.Decode(&raw); err != nil {
			return nil
		}
		if key != name {
			continue
		}
		return objectOffsetsIn(body, start, int(dec.InputOffset()))
	}
	return nil
}

// objectOffsetsIn returns the offset of every object directly inside the array
// occupying body[start:end].
func objectOffsetsIn(body []byte, start, end int) []int {
	if start >= end || start >= len(body) || body[start] != '[' {
		return nil
	}
	inner := body[start:end]
	dec := json.NewDecoder(bytes.NewReader(inner))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return nil
	}
	var out []int
	for dec.More() {
		at := skipToArrayElement(body, start+int(dec.InputOffset()))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return out
		}
		if at < len(body) && body[at] == '{' {
			out = append(out, at)
		}
	}
	return out
}

// skipToArrayElement walks past the separator and any whitespace between two
// array elements. It is not skipToValue: that one skips a colon, which is what
// separates a key from a value and never what separates two elements, and using
// it here left every element after the first pointing at its own comma.
func skipToArrayElement(body []byte, from int) int {
	i := from
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' ||
		body[i] == '\n' || body[i] == ',' || body[i] == '[') {
		i++
	}
	return i
}
