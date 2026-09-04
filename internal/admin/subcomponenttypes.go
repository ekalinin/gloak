package admin

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// GET /admin/realms/{realm}/components/{id}/sub-component-types.
//
// **The parent component is read only to decide whether the request is a 404.**
// Byte-identical bodies came back for one `type` asked through three different
// parent components - a key provider, the user-profile row and a
// client-registration policy - and again through a fourth on another realm and
// a fifth on another container. After the 404, the `type` parameter is the
// whole input.
//
// The realm's own id answers the 404 too, which is the listing family's finding
// from the other side: a component is parented on the realm and the realm is
// not one.

// componentTypeEntry is one entry of the array.
//
// **HelpText is a pointer because the field has three states.** Thirty of the
// thirty-three carry a sentence, `ldap` and `kerberos` carry the empty string,
// and `declarative-user-profile` has no `helpText` key at all - so omitempty
// would drop two real values and a plain string would invent one.
type componentTypeEntry struct {
	ID         string                  `json:"id"`
	HelpText   *string                 `json:"helpText,omitempty"`
	Properties []componentTypeProperty `json:"properties"`
	Metadata   componentTypeMetadata   `json:"metadata"`
}

// componentTypeProperty is `ConfigPropertyRepresentation` again, and it is a
// second struct rather than a reuse of providerProperty for one measured
// reason: **`label` and `helpText` are absent on 36 of the 168 properties
// here** - all 35 of `ldap`'s and `declarative-user-profile`'s one - where
// every property of the two identity provider tables carries both. Adding
// omitempty to the shared struct would be inert there today and would silently
// change what that chapter serves the day a provider grows an empty label.
//
// No property in this table carries an empty-string label or helpText, so
// omitempty expresses absence exactly here.
type componentTypeProperty struct {
	Name         string   `json:"name"`
	Label        string   `json:"label,omitempty"`
	HelpText     string   `json:"helpText,omitempty"`
	Type         string   `json:"type"`
	DefaultValue any      `json:"defaultValue,omitempty"`
	Options      []string `json:"options,omitempty"`
	Secret       bool     `json:"secret"`
	Required     bool     `json:"required"`
	ReadOnly     bool     `json:"readOnly"`
}

// componentTypeMetadata is the entry's `metadata` object. It marshals itself
// because Go sorts a map's keys and Keycloak does not: the four-key sync map
// on `group-ldap-mapper` comes back
// `fedToKeycloakSyncSupported, keycloakToFedSyncSupported,
// fedToKeycloakSyncMessage, keycloakToFedSyncMessage`, which sorting reverses.
// The order is stored rather than computed, for the reason
// identityProviderMapperTypes' is.
type componentTypeMetadata []model.ComponentTypeMetadata

func (m componentTypeMetadata) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range m {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(entry.Name)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := marshalOrderedValue(entry.Value)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// listSubComponentTypes serves
// GET /admin/realms/{realm}/components/{id}/sub-component-types.
//
// Four answers, all measured:
//
//	no ?type= at all, or ?type=  400 {"error":"must specify a subtype"}
//	a parent that resolves to nothing, the realm id included
//	                             404 {"error":"Could not find parent component"}
//	a registered provider type   200, the catalogue - `[]` for thirteen of the
//	                             eighteen
//	anything else                500 unknown_error
//
// The `type` value is compared **case-sensitively**: the same name upper-cased
// is the 500.
//
// The parent 404 comes after the missing-subtype 400, which is the order the
// two probes fix: a request naming no type against a parent that does not exist
// answers about the type.
func (h *handler) listSubComponentTypes(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	providerType := r.URL.Query().Get("type")
	if providerType == "" {
		httpx.WriteMessageError(w, http.StatusBadRequest, "must specify a subtype")
		return
	}
	if _, err := h.store.Components().ByID(r.Context(), rc.realm.ID,
		r.PathValue("componentID")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Could not find parent component")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	entries, registered := model.ComponentSubTypes(providerType)
	if !registered {
		writeComponentConsultLog(w)
		return
	}
	writeAdminJSON(w, subComponentTypesOf(entries))
}

// subComponentTypesOf builds the array.
//
// It is a function rather than a loop inside the handler for the reason
// identityProviderInfoOf is: a byte-for-byte test that assembles the body
// itself cannot fail on a mutation of the assembly, and this project has caught
// exactly that mutation surviving twice.
func subComponentTypesOf(entries []model.ComponentTypeEntry) []componentTypeEntry {
	out := make([]componentTypeEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, componentTypeEntry{
			ID:         e.ID,
			HelpText:   e.HelpText,
			Properties: componentTypePropertiesOf(e.Properties),
			Metadata:   componentTypeMetadata(e.Metadata),
		})
	}
	return out
}

func componentTypePropertiesOf(in []model.ProviderProperty) []componentTypeProperty {
	out := make([]componentTypeProperty, 0, len(in))
	for _, p := range in {
		out = append(out, componentTypeProperty{
			Name:         p.Name,
			Label:        p.Label,
			HelpText:     p.HelpText,
			Type:         p.Type,
			DefaultValue: p.DefaultValue,
			Options:      p.Options,
			Secret:       p.Secret,
			Required:     p.Required,
			ReadOnly:     p.ReadOnly,
		})
	}
	return out
}

// writeComponentConsultLog is Keycloak's 500 for a fault it declines to
// describe. This family reaches it for a provider type it does not register on
// `sub-component-types`, and for a registered pair under one of the eleven
// types the component endpoint cannot create on `POST`.
func writeComponentConsultLog(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}
