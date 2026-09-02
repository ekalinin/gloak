package model

// The per-provider property catalogue.
//
// Three Admin API endpoints serve it and **no two of them serve the same
// bytes**. What they share is one inner object, Keycloak's
// `ConfigPropertyRepresentation`, which is [ProviderProperty] below:
//
//	GET .../identity-provider/providers/{id}     an object, key `configProperties`
//	GET .../instances/{alias}/mapper-types       a Java Map, key `properties`
//	GET .../components/{id}/sub-component-types  an array,  key `properties`
//
// The third is not in this file. It is the expensive half - 33 providers, 168
// properties and 47650 bytes against the first two's 73 entries and 27806 - and
// the two `/components` writes that would go with it need per-provider
// validators the catalogue does not encode. See §5 of the plan.
//
// **The two tables that are here were measured byte for byte on two container
// starts and were identical**, 34 comparisons, so the catalogue is a function
// of the Keycloak version and of nothing that happens at runtime. That is what
// makes a table the right shape for it rather than anything computed.

// ProviderProperty is one entry of a provider's declared configuration, the
// object Keycloak calls a `ConfigPropertyRepresentation`.
//
// The wire order is
//
//	name label helpText type [defaultValue] [options] secret required readOnly
//
// and it is fixed - three key shapes were measured across the two tables and
// they differ only in whether `defaultValue` and `options` are present.
//
// **DefaultValue is `any` because one field carries two JSON types.** `github`'s
// `githubJsonFormat` sends the JSON literal `false` and `saml`'s
// `allowCreate` sends the string `"false"`, both against `"type":"boolean"`, and
// `google`'s max-assertion-expiration sends the string `"3600"` against
// `"type":"Number"`. A `string` field loses the first and a `bool` loses the
// other two. Absent is a third state and is the commonest.
//
// Secret, Required and ReadOnly are plain bools: all three are present on every
// measured property, so absent is not a state they have.
//
// **Required is not the validator.** `POST /components` refuses fifteen of the
// thirty-three component providers and only eight of those declare a required
// property, so this flag records what the server *says* rather than what it
// enforces. Nothing in this package reads it.
type ProviderProperty struct {
	Name         string
	Label        string
	HelpText     string
	Type         string
	DefaultValue any
	Options      []string
	Secret       bool
	Required     bool
	ReadOnly     bool
}

// IdentityProviderCatalogueEntry is one row of what
// `GET .../identity-provider/providers/{provider_id}` serves.
//
// The served body carries a `helpText` and a `configMetadata` beside these two
// fields; both are constant across all seventeen providers - `""` and `[]` - so
// they live in the serialiser rather than here, where seventeen copies of one
// value would look like data.
type IdentityProviderCatalogueEntry struct {
	Name       string
	Properties []ProviderProperty
}

// IdentityProviderMapperType is one entry of what
// `GET .../instances/{alias}/mapper-types` serves. The map's key is the mapper
// id, which the body repeats inside each entry as `id`.
type IdentityProviderMapperType struct {
	Name       string
	Category   string
	HelpText   string
	Properties []ProviderProperty
}

// IdentityProviderCatalogue returns a provider's declared properties.
//
// The second return is false for an id Keycloak does not register, which is a
// **400** on this endpoint and not a 404:
// `GET .../providers/nope` answers `{"error":"HTTP 400 Bad Request"}`.
func IdentityProviderCatalogue(providerID string) (IdentityProviderCatalogueEntry, bool) {
	e, ok := identityProviderCatalogue[providerID]
	return e, ok
}

// IdentityProviderMapperTypes returns the mapper types a provider offers, in
// the measured server order, and the definition of each.
//
// The second return is false for the two providers whose `mapper-types` is a
// **500** - see [IdentityProviderMapperTypesFail] - and for an id that is not
// registered at all. The caller tells the two apart with
// [IsIdentityProvider], because they answer differently.
func IdentityProviderMapperTypes(providerID string) ([]string, bool) {
	ids, ok := identityProviderMapperIDs[providerID]
	return ids, ok
}

// IdentityProviderMapperTypeByID returns one mapper type's definition.
func IdentityProviderMapperTypeByID(id string) (IdentityProviderMapperType, bool) {
	m, ok := identityProviderMapperCatalogue[id]
	return m, ok
}

// IdentityProviderMapperTypesFail reports whether `mapper-types` on a provider
// of this id is Keycloak's consult-the-log 500.
//
// **Two of the seventeen are**, `linkedin-openid-connect` and `openshift-v4`,
// measured on providers that were created without complaint and read back
// normally through every other route in the family. It is a defect of those two
// providers' mapper lookup and it is reproduced, because a caller that asks
// gets a 500 and a handler answering 200 with an empty map would not be a copy.
func IdentityProviderMapperTypesFail(providerID string) bool {
	return providerID == "linkedin-openid-connect" || providerID == "openshift-v4"
}
