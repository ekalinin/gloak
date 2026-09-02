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
// **The second return is false for exactly two registered providers, and both
// of them are a measured 500** rather than a gap in the catalogue:
// `linkedin-openid-connect` and `openshift-v4` answer `mapper-types` with
// Keycloak's consult-the-log `unknown_error` on an instance that was created
// without complaint and reads back normally through every other route in the
// family. So "this provider has no mapper set" and "this provider answers a
// 500" are one condition, and a caller needs one branch rather than two.
//
// That is asserted rather than implemented. There used to be an
// IdentityProviderMapperTypesFail predicate and a branch in the serving path
// that consulted it, and **deleting all four of those lines changed no byte of
// any response** - the two providers it named are the two this map has no entry
// for, so the fallback answered them identically. It is gone, and
// TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s pins the set in both
// directions instead: an id going missing from the map fails it, and an entry
// arriving for either of these two fails it.
func IdentityProviderMapperTypes(providerID string) ([]string, bool) {
	ids, ok := identityProviderMapperIDs[providerID]
	return ids, ok
}

// IdentityProviderMapperTypeByID returns one mapper type's definition.
func IdentityProviderMapperTypeByID(id string) (IdentityProviderMapperType, bool) {
	m, ok := identityProviderMapperCatalogue[id]
	return m, ok
}
