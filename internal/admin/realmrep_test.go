package admin

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// TestDefaultRealmRepresentationMatchesTheRecording compares the defaults byte
// for byte against a recording of GET /admin/realms/p4a taken from a live
// 26.7.1 immediately after POST /admin/realms -d '{"realm":"p4a"}'.
//
// It is a golden inside a unit test on purpose. The conformance suite compares
// the served body, which catches the same divergence one layer out - but only
// once a handler exists and only against a container. This runs with
// CGO_ENABLED=0 and no Docker, so a field moved during a refactor fails at the
// package that owns the field.
func TestDefaultRealmRepresentationMatchesTheRecording(t *testing.T) {
	raw, err := os.ReadFile("testdata/realm-created-26.7.1.json")
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}

	var recorded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &recorded); err != nil {
		t.Fatalf("parse recording: %v", err)
	}

	rep := defaultRealmRepresentation("p4a")
	rep.ID = "eb495f2c-32b0-4648-baa9-2f080981ee27"
	rep.Realm = "p4a"
	rep.Enabled = false
	rep.DefaultRole = &roleRepresentation{
		ID:          "145503e4-0d25-4145-a2f9-b4e9a59c1783",
		Name:        "default-roles-p4a",
		Description: "${role_default-roles}",
		Composite:   true,
		ClientRole:  false,
		ContainerID: "eb495f2c-32b0-4648-baa9-2f080981ee27",
	}

	got, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The recording is compared key by key rather than as one string, because
	// attributes is a Java map in hash order that Go sorts - the one
	// normalisation the conformance suite also makes. Everything else,
	// including the order of the 104 keys, is asserted exactly.
	assertKeyOrder(t, raw, got)

	var mine map[string]json.RawMessage
	if err := json.Unmarshal(got, &mine); err != nil {
		t.Fatalf("parse mine: %v", err)
	}
	for key, want := range recorded {
		if key == "attributes" {
			assertSameMap(t, want, mine[key])
			continue
		}
		if string(mine[key]) != string(want) {
			t.Errorf("%s:\n got %s\nwant %s", key, mine[key], want)
		}
	}
}

// TestMasterDefaultsCarryTheTwoDisplayNames pins the three ways master's
// defaults differ from a created realm's. It is a separate test because each
// difference was found by comparing two recordings rather than by reading one,
// and a reader who only sees the created realm's defaults would take them for
// the product's.
func TestMasterDefaultsCarryTheTwoDisplayNames(t *testing.T) {
	master := defaultRealmRepresentation("master")

	if master.DisplayName == nil || *master.DisplayName != "Keycloak" {
		t.Errorf("displayName = %v, want Keycloak", master.DisplayName)
	}
	const wantHTML = `<div class="kc-logo-text"><span>Keycloak</span></div>`
	if master.DisplayNameHTML == nil || *master.DisplayNameHTML != wantHTML {
		t.Errorf("displayNameHtml = %v, want %s", master.DisplayNameHTML, wantHTML)
	}
	if len(master.Attributes) != 6 {
		t.Errorf("master attributes = %d keys, want 6: %v", len(master.Attributes), master.Attributes)
	}
	if _, ok := master.Attributes["oauth2DeviceCodeLifespan"]; ok {
		t.Error("master carries oauth2DeviceCodeLifespan as an attribute; measured absent")
	}

	created := defaultRealmRepresentation("other")
	if created.DisplayName != nil || created.DisplayNameHTML != nil {
		t.Errorf("a created realm carries display names: %v %v", created.DisplayName, created.DisplayNameHTML)
	}
	if len(created.Attributes) != 8 {
		t.Errorf("created attributes = %d keys, want 8: %v", len(created.Attributes), created.Attributes)
	}
}

// TestDisplayNameDistinguishesAbsentFromEmpty is the reason the two display
// names are pointers. A created realm omits the key; a realm whose displayName
// was set to "" by a PUT carries it with an empty value. omitempty on a string
// cannot express both.
func TestDisplayNameDistinguishesAbsentFromEmpty(t *testing.T) {
	absent, err := json.Marshal(realmBriefRepresentation{ID: "i", Realm: "r"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(absent), `{"id":"i","realm":"r","enabled":false}`; got != want {
		t.Errorf("absent:\n got %s\nwant %s", got, want)
	}

	empty, err := json.Marshal(realmBriefRepresentation{ID: "i", Realm: "r", DisplayName: ptr("")})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(empty), `{"id":"i","realm":"r","displayName":"","enabled":false}`; got != want {
		t.Errorf("empty:\n got %s\nwant %s", got, want)
	}
}

// TestReducedShapesDifferByOneKey pins the two short bodies. Sixteen of the
// twenty-one admin roles get four keys and the two users-family roles get five,
// the extra one being registrationEmailAsUsername - and supportedLocales is
// present on both, where the full 104-key body has no such key at all.
func TestReducedShapesDifferByOneKey(t *testing.T) {
	narrow, err := json.Marshal(realmReducedRepresentation{Realm: "p4e", SupportedLocales: []string{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const wantNarrow = `{"realm":"p4e","bruteForceProtected":false,"supportedLocales":[],"organizationsEnabled":false}`
	if string(narrow) != wantNarrow {
		t.Errorf("four-key:\n got %s\nwant %s", narrow, wantNarrow)
	}

	users, err := json.Marshal(realmReducedRepresentation{
		Realm:                       "p4e",
		RegistrationEmailAsUsername: ptr(false),
		SupportedLocales:            []string{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const wantUsers = `{"realm":"p4e","registrationEmailAsUsername":false,"bruteForceProtected":false,"supportedLocales":[],"organizationsEnabled":false}`
	if string(users) != wantUsers {
		t.Errorf("five-key:\n got %s\nwant %s", users, wantUsers)
	}
}

// TestNarrowListingEntryIsOneKey pins the fifth shape: what a caller without
// view-realm gets in the listing, which is narrower than the reduced single
// read the same caller gets for the same realm.
func TestNarrowListingEntryIsOneKey(t *testing.T) {
	got, err := json.Marshal([]realmNarrowRepresentation{{Realm: "p4e"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := `[{"realm":"p4e"}]`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// assertKeyOrder compares the top-level key sequence of two JSON objects. It
// decodes with a token stream rather than into a map, because a map loses the
// order that is the whole point.
func assertKeyOrder(t *testing.T, want, got []byte) {
	t.Helper()
	wantKeys, gotKeys := topLevelKeys(t, want), topLevelKeys(t, got)
	if len(wantKeys) != len(gotKeys) {
		t.Errorf("key count: got %d, want %d", len(gotKeys), len(wantKeys))
	}
	for i := range min(len(wantKeys), len(gotKeys)) {
		if wantKeys[i] != gotKeys[i] {
			t.Fatalf("key %d: got %q, want %q", i, gotKeys[i], wantKeys[i])
		}
	}
}

func topLevelKeys(t *testing.T, b []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err := dec.Token(); err != nil { // the opening brace
		t.Fatalf("token: %v", err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return keys
}

// assertSameMap compares two JSON objects ignoring key order, which is what the
// conformance suite's UnorderedKeys does for a Java map.
func assertSameMap(t *testing.T, want, got json.RawMessage) {
	t.Helper()
	var w, g map[string]string
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("want: %v", err)
	}
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got: %v", err)
	}
	if len(w) != len(g) {
		t.Errorf("attributes: got %d keys %v, want %d %v", len(g), g, len(w), w)
		return
	}
	for k, v := range w {
		if g[k] != v {
			t.Errorf("attributes[%q]: got %q, want %q", k, g[k], v)
		}
	}
}
