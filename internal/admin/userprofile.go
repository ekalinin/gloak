package admin

import (
	"encoding/json"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The three reads this cut takes out of the user-profile neighbourhood, and one
// measurement that governs all of them.
//
// **`GET /users/profile` is an echo, not a derivation.** Master's
// `declarative-user-profile` component holds 988 bytes under
// `kc.user.profile.config`, and `GET /admin/realms/master/users/profile`
// answers the **same 988 bytes** - md5 7a2c214069eb9085ff019a8e75cbb6c7 on
// both, measured 2026-09-05. So the handler serves a stored string rather than
// re-serialising a decoded model, which is what makes it right for a config
// nobody has measured as well as for the one that ships.
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

// readUserProfile serves GET /admin/realms/{realm}/users/profile.
//
// 200, `application/json;charset=UTF-8` and **no `Cache-Control`** - which is
// why it does not go through writeAdminJSON, the writer every other read in
// this cut uses. Measured: `no-cache` is on `unmanagedAttributes`,
// `federated-identity`, `credential-registrators` and the node routes, and not
// on this one.
func (h *handler) readUserProfile(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	raw, err := h.userProfileConfig(r, rc)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, json.RawMessage(raw))
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
