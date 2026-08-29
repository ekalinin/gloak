package admin

import (
	"context"
	"slices"
	"testing"
)

// TestBootstrappedClientScopeMappers asserts one bootstrapped scope's protocol
// mappers directly, because no golden can.
//
// The conformance suite's `admin/client-scopes/list` case masks
// `*/protocolMappers` whole. Case.Unordered cannot sort a nested array inside
// an array it also sorts at the root - its sortArray decodes the matched value
// in one go and never descends - and both orders are unstable across container
// starts, so one of the two has to be given up and the root is not the one that
// can be. That leaves the thirty-five mappers in
// internal/bootstrap/clientscopes.json unguarded by any golden.
//
// This closes the hole for the richest of them. The fourteen names and the one
// full config below are the measurement, taken from GET
// /admin/realms/master/client-scopes on a live Keycloak 26.7.1 on 2026-08-29,
// and they are written here for the reason internal/keys/keys_test.go writes a
// kid vector: a measured value a golden cannot carry belongs in a test that
// can. The order is not asserted, because it is not reproducible.
func TestBootstrappedClientScopeMappers(t *testing.T) {
	_, s, realm := newServer(t)

	scope, err := s.ClientScopes().ByName(context.Background(), realm.ID, "profile")
	if err != nil {
		t.Fatalf("ByName(profile): %v", err)
	}

	want := []string{
		"birthdate", "family name", "full name", "gender", "given name",
		"locale", "middle name", "nickname", "picture", "profile", "updated at",
		"username", "website", "zoneinfo",
	}
	var got []string
	for _, m := range scope.ProtocolMappers {
		got = append(got, m.Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("profile's mapper names:\n got %v\nwant %v", got, want)
	}

	// One mapper in full, including its config's key **order**: it is a Java
	// map in hash order and model.StringMap is what reproduces it, where a Go
	// map would come back sorted and the representation would stop matching.
	var username *mapperUnderTest
	for _, m := range scope.ProtocolMappers {
		if m.Name == "username" {
			username = &mapperUnderTest{
				protocol: m.Protocol, kind: m.ProtocolMapper,
				consent: m.ConsentRequired,
			}
			for _, p := range m.Config {
				username.configKeys = append(username.configKeys, p.Key)
				username.configValues = append(username.configValues, p.Value)
			}
		}
	}
	if username == nil {
		t.Fatal("profile has no `username` mapper")
	}
	if username.protocol != "openid-connect" ||
		username.kind != "oidc-usermodel-attribute-mapper" ||
		username.consent {
		t.Errorf("username mapper = %+v", username)
	}
	wantKeys := []string{
		"introspection.token.claim", "userinfo.token.claim", "user.attribute",
		"id.token.claim", "access.token.claim", "claim.name", "jsonType.label",
	}
	wantValues := []string{
		"true", "true", "username", "true", "true", "preferred_username", "String",
	}
	if !slices.Equal(username.configKeys, wantKeys) {
		t.Errorf("config key order:\n got %v\nwant %v", username.configKeys, wantKeys)
	}
	if !slices.Equal(username.configValues, wantValues) {
		t.Errorf("config values:\n got %v\nwant %v", username.configValues, wantValues)
	}

	// offline_access is the one bootstrapped scope with no mappers at all, and
	// that is what makes its representation five keys where every other scope's
	// is six.
	bare, err := s.ClientScopes().ByName(context.Background(), realm.ID, "offline_access")
	if err != nil {
		t.Fatalf("ByName(offline_access): %v", err)
	}
	if len(bare.ProtocolMappers) != 0 {
		t.Errorf("offline_access has %d mappers, want none", len(bare.ProtocolMappers))
	}
}

type mapperUnderTest struct {
	protocol     string
	kind         string
	consent      bool
	configKeys   []string
	configValues []string
}
