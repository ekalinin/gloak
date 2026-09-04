package model

import "strconv"

// The component provider catalogue: what `sub-component-types` serves and what
// `POST`/`PUT /components` validate against.
//
// It is the third table of this kind in the package, after the identity
// provider catalogue and its mapper types, and it is the expensive one - 33
// entries, 168 properties, 47650 bytes of JSON against those two's 27806. That
// is why P9 measured it and left it out; the two component writes are what
// make it worth carrying.
//
// **The measurement that makes a table right is that the bodies do not move.**
// Byte-identical across three parent components, two realms and two container
// starts, which is the same evidence the identity provider tables rest on.

// ComponentTypeEntry is one entry of
// `GET .../components/{id}/sub-component-types?type=X`.
//
// **HelpText is a pointer because the field has three states, not two.** Thirty
// of the thirty-three carry a sentence, `ldap` and `kerberos` carry the empty
// string, and `declarative-user-profile` has no `helpText` key at all. A plain
// string with omitempty gets the middle two wrong; a plain string without it
// gets the last one wrong.
type ComponentTypeEntry struct {
	ID         string
	HelpText   *string
	Properties []ProviderProperty
	// Metadata is the entry's `metadata` object, `{}` on 20 of the 33 and a
	// small Java map on the other 13 - `{"synchronizable":true}` on `ldap` and
	// a four- or two-key sync-capability map on the LDAP mappers. The order is
	// the server's, recorded rather than computed, for the reason
	// identityProviderMapperTypes' is.
	Metadata []ComponentTypeMetadata
}

// ComponentTypeMetadata is one `metadata` key. Value is `any` because the
// measured values are booleans and strings on the same map.
type ComponentTypeMetadata struct {
	Name  string
	Value any
}

func strptr(s string) *string { return &s }

// ComponentSubTypes returns the entries one provider type offers, and whether
// the type is registered at all.
//
// The two returns are not the same question and `POST /components` needs both:
// thirteen of the eighteen registered types answer `sub-component-types` with
// `[]` while still being types a real provider id lives under, and a type
// nobody registered is a different answer again.
func ComponentSubTypes(providerType string) ([]ComponentTypeEntry, bool) {
	entries, ok := componentSubTypes[providerType]
	if ok {
		return entries, true
	}
	if _, registered := componentProviderRegistry[providerType]; registered {
		return nil, true
	}
	return nil, false
}

// ComponentProvider returns one (providerType, providerId) pair's catalogue
// entry, or false when the pair has no declared properties here - which
// includes every pair under the thirteen types that answer `[]`.
func ComponentProvider(providerType, providerID string) (ComponentTypeEntry, bool) {
	for _, e := range componentSubTypes[providerType] {
		if e.ID == providerID {
			return e, true
		}
	}
	return ComponentTypeEntry{}, false
}

// IsRegisteredComponentProvider says whether `GET /admin/serverinfo` registers
// this (providerType, providerId) pair at all. It is what tells
// `POST /components`' three refusals apart - see ComponentCreateRefusal.
func IsRegisteredComponentProvider(providerType, providerID string) bool {
	for _, id := range componentProviderRegistry[providerType] {
		if id == providerID {
			return true
		}
	}
	return false
}

// componentWorkflowTypes are the two provider types whose registered providers
// answer `POST /components` with a 403 rather than being created or failing.
// Measured over all 245 registered pairs: they are the only two.
var componentWorkflowTypes = map[string]bool{
	"org.keycloak.models.workflow.WorkflowProvider":     true,
	"org.keycloak.models.workflow.WorkflowStepProvider": true,
}

// ComponentCreateOutcome is what a (providerType, providerId) pair earns before
// its config is looked at.
type ComponentCreateOutcome int

const (
	// ComponentCreateUnregistered is a pair `GET /admin/serverinfo` does not
	// register - 400 `Invalid provider type or no such provider`. It is the
	// answer for an unknown providerId under a **known** type as well as for an
	// unknown type, measured on all eighteen types, so the sentence is about
	// the pair and not about either half.
	ComponentCreateUnregistered ComponentCreateOutcome = iota
	// ComponentCreateManagedInternally is a registered Workflow pair - 403.
	ComponentCreateManagedInternally
	// ComponentCreateUnsupported is a registered pair under one of the eleven
	// remaining types - a 500. `oidc-sub-mapper` under
	// org.keycloak.protocol.ProtocolMapper is the measured example.
	ComponentCreateUnsupported
	// ComponentCreateAllowed is a pair under one of the five types
	// `sub-component-types` answers non-empty for.
	ComponentCreateAllowed
)

// ComponentCreateOutcomeOf classifies a pair. The order of the branches is the
// measured order of the answers, not a preference.
func ComponentCreateOutcomeOf(providerType, providerID string) ComponentCreateOutcome {
	if !IsRegisteredComponentProvider(providerType, providerID) {
		return ComponentCreateUnregistered
	}
	if componentWorkflowTypes[providerType] {
		return ComponentCreateManagedInternally
	}
	if _, ok := componentSubTypes[providerType]; !ok {
		return ComponentCreateUnsupported
	}
	return ComponentCreateAllowed
}

// ComponentConfigRule is one validator, keyed on the config property it reads.
//
// **The rules run in the provider's declared property order**, which is
// measured rather than assumed: a `rsa-generated` create carrying a bad
// `priority` and a bad `keySize` answers about the priority, one carrying a bad
// `enabled` and a bad `active` answers about `enabled`, and a `java-keystore`
// create carrying a bad `priority` and a valid `keystore` answers about the
// priority - and `priority`, `enabled` and `active` are the first three
// properties every key provider declares.
//
// **Label is carried here rather than read off the catalogue**, because the
// two disagree. The property serves `"label":"max-clients.label"` and the
// refusal says `'Max Clients Per Realm'`: the sentence interpolates a resolved
// message bundle the catalogue does not ship. Twelve of the fifteen refusals
// name no catalogue label at all.
type ComponentConfigRule struct {
	// Property is the config key this rule reads.
	Property string
	// Kind decides the sentence and the test.
	Kind ComponentRuleKind
	// Label is the interpolated name, empty when Sentence is set.
	Label string
	// Options is the accepted set for ComponentRuleOptions, and the words after
	// "should be" are built from it.
	Options []string
	// Sentence is the whole errorMessage, for the providers whose refusal
	// interpolates nothing.
	Sentence string
}

// ComponentRuleKind is what a rule checks.
type ComponentRuleKind int

const (
	// ComponentRuleRequired refuses an absent, empty or empty-array value:
	// `{"max-clients":[""]}` and `{"max-clients":[]}` are both the same 400 as
	// no key at all.
	ComponentRuleRequired ComponentRuleKind = iota
	// ComponentRuleNumber refuses a present value that is not an integer.
	// **An empty value passes**: `{"priority":[""]}` is a 201, so this is not
	// the required check with a different sentence.
	ComponentRuleNumber
	// ComponentRuleBoolean refuses anything but the literals `true` and
	// `false`, case-sensitively - `TRUE` was measured refused.
	ComponentRuleBoolean
	// ComponentRuleOptions refuses a present non-empty value outside a set.
	ComponentRuleOptions
	// ComponentRuleSingle refuses a value list holding more than one entry.
	ComponentRuleSingle
	// ComponentRuleSentence is a refusal whose whole sentence is stored,
	// because it interpolates no property label - `Edit Mode is mandatory`,
	// `Missing configuration for LDAP Groups DN`, `Role cant be null`.
	ComponentRuleSentence
)

// ComponentConfigRules returns the rules for one pair, in the order Keycloak
// runs them.
//
// **This is the first refusal of each provider and not the whole sequence.**
// Fifteen of the thirty-three providers refuse a bare create; every one of
// those fifteen is here. What is past the first refusal needs a real LDAP
// server, a PEM private key parser or a keystore file on disk - Keycloak's
// provider implementations rather than a table - and is F158.
func ComponentConfigRules(providerType, providerID string) []ComponentConfigRule {
	return componentConfigRules[providerType+"\x1f"+providerID]
}

// ComponentRuleFails runs one rule against a config value list and returns the
// errorMessage, or "" when it passes.
func ComponentRuleFails(rule ComponentConfigRule, values []string, present bool) string {
	switch rule.Kind {
	case ComponentRuleRequired, ComponentRuleSentence:
		if present && len(values) > 0 && values[0] != "" {
			return ""
		}
		if rule.Kind == ComponentRuleSentence {
			return rule.Sentence
		}
		return "'" + rule.Label + "' is required"
	case ComponentRuleSingle:
		if len(values) <= 1 {
			return ""
		}
		return "'" + rule.Label + "' should be a single entry"
	case ComponentRuleNumber:
		if !present || len(values) == 0 || values[0] == "" {
			return ""
		}
		if _, err := strconv.Atoi(values[0]); err == nil {
			return ""
		}
		return "'" + rule.Label + "' should be a number"
	case ComponentRuleBoolean:
		if !present || len(values) == 0 || values[0] == "" {
			return ""
		}
		if values[0] == "true" || values[0] == "false" {
			return ""
		}
		return "'" + rule.Label + "' should be 'true' or 'false'"
	case ComponentRuleOptions:
		if !present || len(values) == 0 || values[0] == "" {
			return ""
		}
		for _, o := range rule.Options {
			if values[0] == o {
				return ""
			}
		}
		return "'" + rule.Label + "' should be " + joinOptions(rule.Options)
	}
	return ""
}

// joinOptions builds the tail of a `should be` sentence: the options separated
// by ", " with " or " before the last. Measured on three of them -
// `1024, 2048, 3072 or 4096`, `16, 24, 32, 64, 128, 256 or 512` and
// `P-256, P-384 or P-521` - and on the two-element `Ed25519 or Ed448`, which is
// what says there is no comma before the `or`.
func joinOptions(options []string) string {
	switch len(options) {
	case 0:
		return ""
	case 1:
		return options[0]
	}
	out := ""
	for i, o := range options[:len(options)-1] {
		if i > 0 {
			out += ", "
		}
		out += o
	}
	return out + " or " + options[len(options)-1]
}

// keyProviderCommonRules are the three every key provider declares first, and
// they are the reason the order matters: a create wrong in one of these and in
// a provider-specific property answers about these.
var keyProviderCommonRules = []ComponentConfigRule{
	{Property: "priority", Kind: ComponentRuleNumber, Label: "Priority"},
	{Property: "enabled", Kind: ComponentRuleBoolean, Label: "Enabled"},
	{Property: "active", Kind: ComponentRuleBoolean, Label: "Active"},
}

const (
	keyProviderType = "org.keycloak.keys.KeyProvider"
	policyType      = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	ldapMapperType  = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	userStorageType = "org.keycloak.storage.UserStorageProvider"
)

// componentConfigRules is the measured table. Every sentence in it was read off
// a live 26.7.1 on 2026-09-03; see section 3.5 of the plan.
//
// **The client-registration policies do not run the key providers' three**: a
// `max-clients` create carrying `priority: abc` answers about `max-clients`,
// not about the priority, so `priority` is not a shared validator across the
// families even though every provider declares the property.
var componentConfigRules = func() map[string][]ComponentConfigRule {
	m := map[string][]ComponentConfigRule{}
	key := func(t, p string, rules ...ComponentConfigRule) {
		m[t+"\x1f"+p] = rules
	}
	// The ten key providers. All ten run the common three; seven have nothing
	// after them and are the seven that accept a bare create.
	keySizes := []string{"1024", "2048", "3072", "4096"}
	secretSizes := []string{"16", "24", "32", "64", "128", "256", "512"}
	ecCurves := []string{"P-256", "P-384", "P-521"}
	edCurves := []string{"Ed25519", "Ed448"}
	withCommon := func(rules ...ComponentConfigRule) []ComponentConfigRule {
		return append(append([]ComponentConfigRule{}, keyProviderCommonRules...), rules...)
	}
	key(keyProviderType, "rsa", withCommon(
		ComponentConfigRule{Property: "privateKey", Kind: ComponentRuleRequired, Label: "Private RSA Key"})...)
	key(keyProviderType, "rsa-enc", withCommon(
		ComponentConfigRule{Property: "privateKey", Kind: ComponentRuleRequired, Label: "Private RSA Key"})...)
	key(keyProviderType, "java-keystore", withCommon(
		ComponentConfigRule{Property: "keystore", Kind: ComponentRuleRequired, Label: "Keystore"},
		ComponentConfigRule{Property: "keystorePassword", Kind: ComponentRuleRequired, Label: "Keystore Password"},
		ComponentConfigRule{Property: "keyAlias", Kind: ComponentRuleRequired, Label: "Key Alias"},
		ComponentConfigRule{Property: "keyPassword", Kind: ComponentRuleRequired, Label: "Key Password"})...)
	key(keyProviderType, "rsa-generated", withCommon(
		ComponentConfigRule{Property: "keySize", Kind: ComponentRuleOptions, Label: "Key size", Options: keySizes})...)
	key(keyProviderType, "rsa-enc-generated", withCommon(
		ComponentConfigRule{Property: "keySize", Kind: ComponentRuleOptions, Label: "Key size", Options: keySizes})...)
	key(keyProviderType, "aes-generated", withCommon(
		ComponentConfigRule{Property: "secretSize", Kind: ComponentRuleOptions, Label: "Secret size", Options: secretSizes})...)
	key(keyProviderType, "hmac-generated", withCommon(
		ComponentConfigRule{Property: "secretSize", Kind: ComponentRuleOptions, Label: "Secret size", Options: secretSizes})...)
	key(keyProviderType, "ecdh-generated", withCommon(
		ComponentConfigRule{Property: "ecdhEllipticCurveKey", Kind: ComponentRuleOptions, Label: "Elliptic Curve", Options: ecCurves})...)
	key(keyProviderType, "ecdsa-generated", withCommon(
		ComponentConfigRule{Property: "ecdsaEllipticCurveKey", Kind: ComponentRuleOptions, Label: "Elliptic Curve", Options: ecCurves})...)
	key(keyProviderType, "eddsa-generated", withCommon(
		ComponentConfigRule{Property: "eddsaEllipticCurveKey", Kind: ComponentRuleOptions, Label: "Elliptic Curve", Options: edCurves})...)

	// The two client-registration policies that refuse a bare create. The other
	// six accept one, and `allowed-client-templates`' own boolean is **not**
	// validated - `allow-default-scopes: nope` is a 201 - so only these two
	// booleans are here.
	key(policyType, "max-clients",
		ComponentConfigRule{Property: "max-clients", Kind: ComponentRuleRequired, Label: "Max Clients Per Realm"},
		ComponentConfigRule{Property: "max-clients", Kind: ComponentRuleSingle, Label: "Max Clients Per Realm"},
		ComponentConfigRule{Property: "max-clients", Kind: ComponentRuleNumber, Label: "Max Clients Per Realm"})
	key(policyType, "trusted-hosts",
		ComponentConfigRule{Property: "host-sending-registration-request-must-match", Kind: ComponentRuleRequired,
			Label: "Host Sending Client Registration Request Must Match"},
		ComponentConfigRule{Property: "client-uris-must-match", Kind: ComponentRuleRequired,
			Label: "Client URIs Must Match"},
		ComponentConfigRule{Property: "host-sending-registration-request-must-match", Kind: ComponentRuleBoolean,
			Label: "Host Sending Client Registration Request Must Match"},
		ComponentConfigRule{Property: "client-uris-must-match", Kind: ComponentRuleBoolean,
			Label: "Client URIs Must Match"})

	// `ldap`, and the nine LDAP mappers that refuse a bare create. Every one of
	// these sentences is the provider's own; none interpolates a label the
	// catalogue carries, and four spell "missing" three different ways.
	key(userStorageType, "ldap",
		ComponentConfigRule{Property: "editMode", Kind: ComponentRuleSentence, Sentence: "Edit Mode is mandatory"})
	sentence := func(provider, property, s string) {
		key(ldapMapperType, provider,
			ComponentConfigRule{Property: property, Kind: ComponentRuleSentence, Sentence: s})
	}
	sentence("group-ldap-mapper", "groups.dn", "Missing configuration for LDAP Groups DN")
	sentence("role-ldap-mapper", "roles.dn", "Missing configuration for LDAP Roles DN")
	sentence("user-attribute-ldap-mapper", "user.model.attribute", "Missing configuration for User Model Attribute")
	sentence("certificate-ldap-mapper", "user.model.attribute", "Missing configuration for User Model Attribute")
	sentence("full-name-ldap-mapper", "ldap.full.name.attribute", "Missing configuration for LDAP Full Name Attribute")
	sentence("hardcoded-ldap-role-mapper", "role", "Role cant be null")
	sentence("hardcoded-ldap-group-mapper", "group", "Group cant be null")
	key(ldapMapperType, "hardcoded-attribute-mapper",
		ComponentConfigRule{Property: "user.model.attribute", Kind: ComponentRuleRequired, Label: "Attribute Name"},
		ComponentConfigRule{Property: "attribute.value", Kind: ComponentRuleRequired, Label: "Attribute Value"})
	key(ldapMapperType, "hardcoded-ldap-attribute-mapper",
		ComponentConfigRule{Property: "ldap.attribute", Kind: ComponentRuleRequired, Label: "LDAP Attribute Name"})
	return m
}()
