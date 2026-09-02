package admin

import (
	"bytes"

	"net/http"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// providerProperty is Keycloak's ConfigPropertyRepresentation, the one object
// the three catalogue endpoints share.
//
// The field order is measured and fixed:
//
//	name label helpText type [defaultValue] [options] secret required readOnly
//
// **DefaultValue is `any` and its omitempty is load-bearing in both
// directions.** `encoding/json` treats an interface as empty only when it is
// nil, so a property whose default is the JSON literal `false` - `github`'s
// `githubJsonFormat` - still serialises the key, while a property with no
// default at all drops it. A `bool` field would serialise `false` for both and a
// `*bool` could not hold `"3600"`, which is what `google`'s max-assertion
// property sends against `"type":"Number"`.
type providerProperty struct {
	Name         string   `json:"name"`
	Label        string   `json:"label"`
	HelpText     string   `json:"helpText"`
	Type         string   `json:"type"`
	DefaultValue any      `json:"defaultValue,omitempty"`
	Options      []string `json:"options,omitempty"`
	Secret       bool     `json:"secret"`
	Required     bool     `json:"required"`
	ReadOnly     bool     `json:"readOnly"`
}

func providerPropertiesOf(in []model.ProviderProperty) []providerProperty {
	out := make([]providerProperty, 0, len(in))
	for _, p := range in {
		out = append(out, providerProperty{
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

// identityProviderInfo is what `.../identity-provider/providers/{id}` serves.
//
// `helpText` and `configMetadata` are always `""` and `[]` - measured on all
// seventeen registered providers - so they are written here rather than carried
// through the catalogue, where seventeen copies of one value would read as
// data somebody had checked.
type identityProviderInfo struct {
	Name             string             `json:"name"`
	ID               string             `json:"id"`
	ConfigProperties []providerProperty `json:"configProperties"`
	HelpText         string             `json:"helpText"`
	ConfigMetadata   []struct{}         `json:"configMetadata"`
}

// readIdentityProviderInfo serves
// GET /admin/realms/{realm}/identity-provider/providers/{provider_id}.
//
// **Eleven of the seventeen answer an empty `configProperties`**, `oidc` and
// `saml` among them, so this is a provider's *extra* configuration and not its
// whole surface. That is worth stating because the endpoint's name says
// otherwise and because an `oidc` broker plainly has a `clientId`.
//
// **An unregistered id is a 400, not a 404**:
// `{"error":"HTTP 400 Bad Request"}`, the generic body rather than a sentence.
// So this route and the instance routes one path segment apart answer an
// unknown name with two different statuses.
func (h *handler) readIdentityProviderInfo(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	body, ok := identityProviderInfoOf(r.PathValue("providerID"))
	if !ok {
		httpx.WriteMessageError(w, http.StatusBadRequest, "HTTP 400 Bad Request")
		return
	}
	writeAdminJSON(w, body)
}

// identityProviderInfoOf builds the body for one provider id.
//
// It is a function rather than four lines inside the handler **because of a
// surviving mutation**. The byte-for-byte test against the thirty-two measured
// bodies used to assemble the body itself, so a mutation of the assembly inside
// the handler changed the served bytes and the test could not see it. A claim
// has to live where the code is; this is the seam that puts it there.
func identityProviderInfoOf(providerID string) (identityProviderInfo, bool) {
	entry, ok := model.IdentityProviderCatalogue(providerID)
	if !ok {
		return identityProviderInfo{}, false
	}
	return identityProviderInfo{
		Name:             entry.Name,
		ID:               providerID,
		ConfigProperties: providerPropertiesOf(entry.Properties),
		ConfigMetadata:   []struct{}{},
	}, true
}

// identityProviderMapperType is one entry of the mapper-types map. It repeats
// the map's own key as `id`, which is the server's shape and not a redundancy
// worth removing.
type identityProviderMapperType struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Category   string             `json:"category"`
	HelpText   string             `json:"helpText"`
	Properties []providerProperty `json:"properties"`
}

// identityProviderMapperTypes is the whole body: a Java map whose key order is
// stored rather than computed.
//
// It marshals itself for the reason identityProviderConfig does - Go sorts a
// map's keys and Java does not - but the resemblance stops there. This order is
// **not** javamap's: all thirteen measured key sets are bucket-monotone at
// capacity 16 and javamap.KeyOrder places eight of the thirteen, the five
// misses holding six colliding pairs between them. The chains would have to be
// guessed, and there is nothing to gain by guessing: the order was byte-
// identical across two container starts on every provider, so it is a constant
// of the Keycloak version and the catalogue simply records it.
type identityProviderMapperTypes []identityProviderMapperType

func (m identityProviderMapperTypes) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range m {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(entry.ID)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := marshalOrderedValue(entry)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// listIdentityProviderMapperTypes serves
// GET /admin/realms/{realm}/identity-provider/instances/{alias}/mapper-types.
//
// **Two of the seventeen providers answer this route with a 500** on an
// instance that was created without complaint and reads back normally through
// every other route in the family - `linkedin-openid-connect` and
// `openshift-v4`. Reproduced rather than smoothed into an empty map, because a
// caller asking for those two gets a 500 and that is the observable.
//
// The set is per provider and ranges from four types to eleven. The four a
// `kubernetes`, `oauth2` or `jwt-authorization-grant` instance offers are the
// base set every provider has; `saml` swaps six of its ten for SAML spellings
// and `keycloak-oidc` is `oidc`'s ten plus one.
func (h *handler) listIdentityProviderMapperTypes(w http.ResponseWriter, r *http.Request, rc *reqContext, p *model.IdentityProvider) {
	if model.IdentityProviderMapperTypesFail(p.ProviderID) {
		writeIdentityProviderConsultLog(w)
		return
	}
	out, ok := identityProviderMapperTypesOf(p.ProviderID)
	if !ok {
		// Unreachable through the router: a stored provider's id was checked
		// against the same registry on the way in. Kept so that a provider id
		// added to the registry without a mapper set fails loudly here rather
		// than serving an empty map that looks measured.
		writeIdentityProviderConsultLog(w)
		return
	}
	writeAdminJSON(w, out)
}

// identityProviderMapperTypesOf builds the map one provider serves, in the
// catalogue's stored order.
//
// A function for the reason identityProviderInfoOf is: a mutation that reversed
// this loop **survived** the byte-for-byte test against the measured bodies,
// because that test assembled the body itself instead of asking for it. The
// seam is what makes the order a claim the test can fail on.
func identityProviderMapperTypesOf(providerID string) (identityProviderMapperTypes, bool) {
	ids, ok := model.IdentityProviderMapperTypes(providerID)
	if !ok {
		return nil, false
	}
	out := make(identityProviderMapperTypes, 0, len(ids))
	for _, id := range ids {
		t, found := model.IdentityProviderMapperTypeByID(id)
		if !found {
			continue
		}
		out = append(out, identityProviderMapperType{
			ID:         id,
			Name:       t.Name,
			Category:   t.Category,
			HelpText:   t.HelpText,
			Properties: providerPropertiesOf(t.Properties),
		})
	}
	return out, true
}

// writeIdentityProviderConsultLog is Keycloak's 500 for a fault it declines to
// describe. Two providers reach it on mapper-types, and the mapper create
// reaches it for an empty body.
func writeIdentityProviderConsultLog(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}
