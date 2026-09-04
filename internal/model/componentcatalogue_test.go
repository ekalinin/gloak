package model

import "testing"

// TestComponentSubTypesTotals is the arithmetic of the whole table, computed
// rather than written down beside it.
//
// **The five types, the 33 entries and the 168 properties are one measurement**
// - swept over every provider type `GET /admin/serverinfo` registers - and a
// row lost from a hand-transcribed table of this size is invisible to every
// other test in the tree. The numbers are asserted here so that a regeneration
// that dropped something fails loudly rather than serving a shorter catalogue.
func TestComponentSubTypesTotals(t *testing.T) {
	wantEntries := map[string]int{
		"org.keycloak.keys.KeyProvider":                                            10,
		"org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy": 8,
		"org.keycloak.storage.UserStorageProvider":                                 2,
		"org.keycloak.storage.ldap.mappers.LDAPStorageMapper":                      12,
		"org.keycloak.userprofile.UserProfileProvider":                             1,
	}
	if len(componentSubTypes) != len(wantEntries) {
		t.Errorf("%d provider types answer non-empty, want %d", len(componentSubTypes), len(wantEntries))
	}
	entries, properties := 0, 0
	for typ, want := range wantEntries {
		got, ok := ComponentSubTypes(typ)
		if !ok {
			t.Errorf("%s is not registered", typ)
			continue
		}
		if len(got) != want {
			t.Errorf("%s has %d entries, want %d", typ, len(got), want)
		}
		entries += len(got)
		for _, e := range got {
			properties += len(e.Properties)
		}
	}
	if entries != 33 {
		t.Errorf("%d entries over the five types, want 33", entries)
	}
	if properties != 168 {
		t.Errorf("%d properties over the 33 entries, want 168", properties)
	}
}

// TestComponentSubTypesTellsEmptyFromUnregistered is the distinction
// `POST /components` needs and a single table cannot make.
//
// Thirteen of the eighteen registered types answer `[]` and a type nobody
// registers is a 500 on the same route, so "no entries" and "no such type" are
// two answers rather than one.
func TestComponentSubTypesTellsEmptyFromUnregistered(t *testing.T) {
	empty := 0
	for typ := range componentProviderRegistry {
		entries, ok := ComponentSubTypes(typ)
		if !ok {
			t.Errorf("%s is in the registry and not registered", typ)
		}
		if len(entries) == 0 {
			empty++
		}
	}
	if len(componentProviderRegistry) != 18 {
		t.Errorf("%d provider types are registered, want 18", len(componentProviderRegistry))
	}
	if empty != 13 {
		t.Errorf("%d registered types answer an empty catalogue, want 13", empty)
	}
	if _, ok := ComponentSubTypes("gloak.probe.NoSuchType"); ok {
		t.Error("an unregistered type reported registered")
	}
}

// TestComponentProviderRegistryHolds245Pairs pins the sweep the three create
// refusals rest on. It is a count over a table nothing else reads in bulk, and
// it is the only thing that would notice a type losing its provider list.
func TestComponentProviderRegistryHolds245Pairs(t *testing.T) {
	pairs := 0
	for _, ids := range componentProviderRegistry {
		pairs += len(ids)
	}
	if pairs != 245 {
		t.Errorf("the registry holds %d (providerType, providerId) pairs, want 245", pairs)
	}
}

// TestComponentCreateOutcomes is the three-way split, asserted on the exact
// pairs it was measured on.
func TestComponentCreateOutcomes(t *testing.T) {
	const policy = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	cases := []struct {
		providerType string
		providerID   string
		want         ComponentCreateOutcome
	}{
		{policy, "max-clients", ComponentCreateAllowed},
		{"org.keycloak.keys.KeyProvider", "rsa-generated", ComponentCreateAllowed},
		{"org.keycloak.userprofile.UserProfileProvider", "declarative-user-profile", ComponentCreateAllowed},
		{policy, "gloak-probe-nope", ComponentCreateUnregistered},
		{"gloak.probe.NoSuchType", "max-clients", ComponentCreateUnregistered},
		{"org.keycloak.keys.KeyProvider", "max-clients", ComponentCreateUnregistered},
		{"org.keycloak.models.workflow.WorkflowStepProvider", "notify-user", ComponentCreateManagedInternally},
		{"org.keycloak.models.workflow.WorkflowProvider", "default", ComponentCreateManagedInternally},
		{"org.keycloak.protocol.ProtocolMapper", "oidc-sub-mapper", ComponentCreateUnsupported},
		{"org.keycloak.validate.Validator", "length", ComponentCreateUnsupported},
		{"org.keycloak.broker.provider.IdentityProvider", "oidc", ComponentCreateUnsupported},
	}
	for _, c := range cases {
		if got := ComponentCreateOutcomeOf(c.providerType, c.providerID); got != c.want {
			t.Errorf("(%s, %s): got %d, want %d", c.providerType, c.providerID, got, c.want)
		}
	}
}

// TestFifteenProvidersRefuseABareCreate is the counted claim, computed from the
// rule table rather than written beside it.
//
// Eighteen of the thirty-three accept a bare create and fifteen refuse one; the
// fifteen are exactly the pairs `componentConfigRules` gives a rule that fires
// on an empty config. A rule added for a provider that does not refuse, or one
// lost from a provider that does, moves this number.
func TestFifteenProvidersRefuseABareCreate(t *testing.T) {
	refusing, accepting := 0, 0
	for typ, entries := range componentSubTypes {
		for _, e := range entries {
			refused := false
			for _, rule := range ComponentConfigRules(typ, e.ID) {
				if ComponentRuleFails(rule, nil, false) != "" {
					refused = true
					break
				}
			}
			if refused {
				refusing++
			} else {
				accepting++
			}
		}
	}
	if refusing != 15 {
		t.Errorf("%d providers refuse a bare create, want 15", refusing)
	}
	if accepting != 18 {
		t.Errorf("%d providers accept a bare create, want 18", accepting)
	}
}

// TestComponentRuleSentences pins the shapes the sentences take, including the
// two-element option list that says there is no comma before the `or`.
func TestComponentRuleSentences(t *testing.T) {
	cases := []struct {
		name    string
		rule    ComponentConfigRule
		values  []string
		present bool
		want    string
	}{
		{"an absent required property", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleRequired, Label: "Max Clients Per Realm"},
			nil, false, "'Max Clients Per Realm' is required"},
		{"an empty required property", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleRequired, Label: "Max Clients Per Realm"},
			[]string{""}, true, "'Max Clients Per Realm' is required"},
		{"an empty array", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleRequired, Label: "Max Clients Per Realm"},
			[]string{}, true, "'Max Clients Per Realm' is required"},
		{"a satisfied required property", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleRequired, Label: "Max Clients Per Realm"},
			[]string{"42"}, true, ""},
		{"two entries where one is allowed", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleSingle, Label: "Max Clients Per Realm"},
			[]string{"42", "43"}, true, "'Max Clients Per Realm' should be a single entry"},
		{"a value that is not a number", ComponentConfigRule{
			Property: "max-clients", Kind: ComponentRuleNumber, Label: "Max Clients Per Realm"},
			[]string{"4.5"}, true, "'Max Clients Per Realm' should be a number"},
		// An empty value passes the number check, which is measured:
		// {"priority":[""]} is a 201 and {"priority":["abc"]} is a 400. So this
		// is not the required check with a different sentence.
		{"an empty value under a number check", ComponentConfigRule{
			Property: "priority", Kind: ComponentRuleNumber, Label: "Priority"},
			[]string{""}, true, ""},
		{"a negative number", ComponentConfigRule{
			Property: "priority", Kind: ComponentRuleNumber, Label: "Priority"},
			[]string{"-3"}, true, ""},
		{"an upper-case TRUE", ComponentConfigRule{
			Property: "client-uris-must-match", Kind: ComponentRuleBoolean, Label: "Client URIs Must Match"},
			[]string{"TRUE"}, true, "'Client URIs Must Match' should be 'true' or 'false'"},
		{"a lower-case true", ComponentConfigRule{
			Property: "client-uris-must-match", Kind: ComponentRuleBoolean, Label: "Client URIs Must Match"},
			[]string{"true"}, true, ""},
		{"four options", ComponentConfigRule{
			Property: "keySize", Kind: ComponentRuleOptions, Label: "Key size",
			Options: []string{"1024", "2048", "3072", "4096"}},
			[]string{"1000"}, true, "'Key size' should be 1024, 2048, 3072 or 4096"},
		{"two options", ComponentConfigRule{
			Property: "eddsaEllipticCurveKey", Kind: ComponentRuleOptions, Label: "Elliptic Curve",
			Options: []string{"Ed25519", "Ed448"}},
			[]string{"nope"}, true, "'Elliptic Curve' should be Ed25519 or Ed448"},
		{"a per-provider sentence", ComponentConfigRule{
			Property: "editMode", Kind: ComponentRuleSentence, Sentence: "Edit Mode is mandatory"},
			nil, false, "Edit Mode is mandatory"},
	}
	for _, c := range cases {
		if got := ComponentRuleFails(c.rule, c.values, c.present); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestComponentHelpTextHasThreeStates is why the entry's HelpText is a pointer.
//
// Thirty of the thirty-three carry a sentence, `ldap` and `kerberos` carry the
// empty string, and `declarative-user-profile` has no key at all. A plain
// string with omitempty gets the middle two wrong and one without it gets the
// last one wrong.
func TestComponentHelpTextHasThreeStates(t *testing.T) {
	absent, empty, populated := 0, 0, 0
	for _, entries := range componentSubTypes {
		for _, e := range entries {
			switch {
			case e.HelpText == nil:
				absent++
			case *e.HelpText == "":
				empty++
			default:
				populated++
			}
		}
	}
	if absent != 1 || empty != 2 || populated != 30 {
		t.Errorf("helpText states: %d absent, %d empty, %d populated; want 1, 2, 30",
			absent, empty, populated)
	}
}

// TestComponentPropertyLabelsAreAbsentOnThirtySix is the other omitempty
// decision, and it is why this family does not share providerProperty's
// serialiser with the identity provider tables.
//
// Thirty-six of the 168 properties carry neither a label nor a helpText - all
// thirty-five of `ldap`'s and `declarative-user-profile`'s one - and **no
// property carries an empty-string one**, which is what makes omitempty exact
// here and would make it a guess anywhere else.
func TestComponentPropertyLabelsAreAbsentOnThirtySix(t *testing.T) {
	bare, labelled := 0, 0
	for _, entries := range componentSubTypes {
		for _, e := range entries {
			for _, p := range e.Properties {
				if p.Label == "" && p.HelpText == "" {
					bare++
					continue
				}
				if p.Label == "" || p.HelpText == "" {
					t.Errorf("%s/%s carries one of label and helpText and not the other",
						e.ID, p.Name)
				}
				labelled++
			}
		}
	}
	if bare != 36 {
		t.Errorf("%d properties carry neither a label nor a helpText, want 36", bare)
	}
	if bare+labelled != 168 {
		t.Errorf("%d properties in all, want 168", bare+labelled)
	}
}

// TestComponentMetadataOrderIsNotAlphabetical is why the metadata object has a
// marshaller of its own: a Go map would sort these four keys and the server
// does not.
func TestComponentMetadataOrderIsNotAlphabetical(t *testing.T) {
	e, ok := ComponentProvider("org.keycloak.storage.ldap.mappers.LDAPStorageMapper",
		"group-ldap-mapper")
	if !ok {
		t.Fatal("group-ldap-mapper is not in the catalogue")
	}
	want := []string{
		"fedToKeycloakSyncSupported", "keycloakToFedSyncSupported",
		"fedToKeycloakSyncMessage", "keycloakToFedSyncMessage",
	}
	if len(e.Metadata) != len(want) {
		t.Fatalf("metadata has %d keys, want %d", len(e.Metadata), len(want))
	}
	for i, name := range want {
		if e.Metadata[i].Name != name {
			t.Errorf("metadata[%d] is %q, want %q", i, e.Metadata[i].Name, name)
		}
	}
}
