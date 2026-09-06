package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const clientRegistrationPolicyPath = "/admin/realms/master/client-registration-policy/providers"

// registrationPolicyOptions reads one property's options out of the listing,
// in the order the body carries them.
func registrationPolicyOptions(t *testing.T, h http.Handler, token, path, provider, property string) []string {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
	}
	var out []struct {
		ID         string `json:"id"`
		Properties []struct {
			Name    string   `json:"name"`
			Options []string `json:"options"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse the listing: %v", err)
	}
	for _, p := range out {
		if p.ID != provider {
			continue
		}
		for _, prop := range p.Properties {
			if prop.Name == property {
				return prop.Options
			}
		}
	}
	t.Fatalf("%s/%s is not in the listing", provider, property)
	return nil
}

// TestAllowedClientScopesFollowsTheRealm is the one value in this listing that
// is not the embedded file, and the test is written in both directions because
// a handler serving the file unchanged passes a one-sided one.
//
// Creating a client scope makes its name appear, which is the measured
// behaviour; the neighbouring 39-name mapper list is read in the same two
// requests and must **not** move, which is what says the fill reached one
// property rather than every property with options.
func TestAllowedClientScopesFollowsTheRealm(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	before := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
		"allowed-client-templates", "allowed-client-scopes")
	mappersBefore := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
		"allowed-protocol-mappers", "allowed-protocol-mapper-types")
	for _, name := range before {
		if name == "gloak-probe-crp" {
			t.Fatalf("the probe scope is already in the listing: %v", before)
		}
	}

	if w := send(t, h, http.MethodPost, "/admin/realms/master/client-scopes", admin,
		`{"name":"gloak-probe-crp","protocol":"openid-connect"}`); w.Code != http.StatusCreated {
		t.Fatalf("create a client scope: %d %s", w.Code, w.Body)
	}

	after := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
		"allowed-client-templates", "allowed-client-scopes")
	if len(after) != len(before)+1 {
		t.Errorf("options went from %d to %d, want one more: %v", len(before), len(after), after)
	}
	found := false
	for _, name := range after {
		if name == "gloak-probe-crp" {
			found = true
		}
	}
	if !found {
		t.Errorf("the new client scope is not in the options: %v", after)
	}

	mappersAfter := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
		"allowed-protocol-mappers", "allowed-protocol-mapper-types")
	if strings.Join(mappersBefore, ",") != strings.Join(mappersAfter, ",") {
		t.Errorf("CONTROL: the mapper option list moved with the client scope:\n%v\n%v",
			mappersBefore, mappersAfter)
	}
}

// TestAllowedClientScopesCarriesOpenIDWhichIsNotAClientScope pins the
// sixteenth name.
//
// The realm has fifteen client scopes and the listing offers sixteen values.
// `openid` is the extra one and `GET /client-scopes` does not carry it, so a
// handler that only listed the realm's scopes would be one short and a handler
// that read `openid` out of the store would find nothing.
func TestAllowedClientScopesCarriesOpenIDWhichIsNotAClientScope(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	options := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
		"allowed-client-templates", "allowed-client-scopes")
	if len(options) == 0 || options[len(options)-1] != "openid" {
		t.Errorf("options: %v, want openid last", options)
	}

	w := get(t, h, "/admin/realms/master/client-scopes", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /client-scopes: %d %s", w.Code, w.Body)
	}
	var scopes []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &scopes); err != nil {
		t.Fatalf("parse the client scopes: %v", err)
	}
	for _, s := range scopes {
		if s.Name == "openid" {
			t.Fatalf("openid is a client scope after all; the extra name is not extra")
		}
	}
	if len(options) != len(scopes)+1 {
		t.Errorf("%d options for %d client scopes, want one more", len(options), len(scopes))
	}
}

// TestTheRegistrationPolicyListingIsTheRealmPairAndNotTheClientsPair is the
// guard, measured one role at a time on a live 26.7.1 with `GET /clients`
// beside it.
//
// The control differs in **both** directions, which is what makes it a control
// rather than a second assertion: the three clients roles read the client
// listing and are refused here, and the realm pair is refused there and reads
// this. A guard that had been given the clients pair by analogy with the
// endpoint's name would pass a one-directional check.
func TestTheRegistrationPolicyListingIsTheRealmPairAndNotTheClientsPair(t *testing.T) {
	h, s, realm := newServer(t)
	for _, tc := range []struct {
		role                   string
		wantPolicies, wantList int
	}{
		{"view-realm", http.StatusOK, http.StatusForbidden},
		{"manage-realm", http.StatusOK, http.StatusForbidden},
		{"view-clients", http.StatusForbidden, http.StatusOK},
		{"manage-clients", http.StatusForbidden, http.StatusOK},
		{"query-clients", http.StatusForbidden, http.StatusOK},
		{"view-users", http.StatusForbidden, http.StatusForbidden},
		{"manage-users", http.StatusForbidden, http.StatusForbidden},
		{"view-identity-providers", http.StatusForbidden, http.StatusForbidden},
		{"view-authorization", http.StatusForbidden, http.StatusForbidden},
		{"view-events", http.StatusForbidden, http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		if w := get(t, h, clientRegistrationPolicyPath, token); w.Code != tc.wantPolicies {
			t.Errorf("%s on the policy listing: %d %s, want %d", tc.role, w.Code, w.Body, tc.wantPolicies)
		}
		if w := get(t, h, "/admin/realms/master/clients", token); w.Code != tc.wantList {
			t.Errorf("CONTROL: %s on GET /clients: %d, want %d", tc.role, w.Code, tc.wantList)
		}
	}
}

// TestTheRegistrationPolicyListingDoesNotLeakOneRealmsScopesIntoAnother is the
// bug a package-level decoded value invites: the providers are decoded once and
// shared, so filling the option list in place would make the first realm to ask
// the answer every later realm gets.
//
// Two realms, and the assertion is on the **second** read of the first one, so
// a handler that mutated the shared value fails on the realm it got right the
// first time.
func TestTheRegistrationPolicyListingDoesNotLeakOneRealmsScopesIntoAnother(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"gloak-probe-crp2","enabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create a realm: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, "/admin/realms/master/client-scopes", admin,
		`{"name":"gloak-probe-master-only","protocol":"openid-connect"}`); w.Code != http.StatusCreated {
		t.Fatalf("create a client scope: %d %s", w.Code, w.Body)
	}

	other := "/admin/realms/gloak-probe-crp2/client-registration-policy/providers"
	for i := 0; i < 2; i++ {
		master := registrationPolicyOptions(t, h, admin, clientRegistrationPolicyPath,
			"allowed-client-templates", "allowed-client-scopes")
		second := registrationPolicyOptions(t, h, admin, other,
			"allowed-client-templates", "allowed-client-scopes")
		if !contains(master, "gloak-probe-master-only") {
			t.Fatalf("round %d: master lost its own scope: %v", i, master)
		}
		if contains(second, "gloak-probe-master-only") {
			t.Errorf("round %d: the second realm was given master's scope: %v", i, second)
		}
	}
}
