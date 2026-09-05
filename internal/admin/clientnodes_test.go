package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// nodeClient creates a client through the API and returns its UUID.
func nodeClient(t *testing.T, h http.Handler, token, clientID string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/clients", token,
		`{"clientId":"`+clientID+`","enabled":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", clientID, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// TestRegisteredNodesIsAbsentUntilThereIsOne pins both directions of the
// omitempty, which one golden cannot: the key's absence on a client with no
// node is asserted by every other client golden in the tree, and its presence
// by one - and only a test can say that one request turns the first into the
// second.
func TestRegisteredNodesIsAbsentUntilThereIsOne(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-absent")
	path := "/admin/realms/master/clients/" + uuid

	before := clientKeys(t, h, admin, path)
	if _, ok := before["registeredNodes"]; ok {
		t.Errorf("a client with no node carries registeredNodes: %v", before["registeredNodes"])
	}

	if w := send(t, h, http.MethodPost, path+"/nodes", admin, `{"node":"n1.example.com"}`); w.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	after := clientKeys(t, h, admin, path)
	nodes, ok := after["registeredNodes"].(map[string]any)
	if !ok {
		t.Fatalf("after registering: %v", after["registeredNodes"])
	}
	if _, ok := nodes["n1.example.com"]; !ok || len(nodes) != 1 {
		t.Errorf("registeredNodes: %v", nodes)
	}

	// And back again. The unregister returns the representation to the shape
	// every other client golden holds, which is what says the key really is
	// keyed on emptiness and not on the client having ever had a node.
	if w := send(t, h, http.MethodDelete, path+"/nodes/n1.example.com", admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("unregister: %d %s", w.Code, w.Body)
	}
	if _, ok := clientKeys(t, h, admin, path)["registeredNodes"]; ok {
		t.Errorf("registeredNodes survived the unregister")
	}
}

// TestRegisteredNodesSitsBeforeProtocolMappers pins the field's **position**,
// which the goldens of this cut cannot: the one client that has a node has no
// protocol mapper, so its golden cannot separate "before protocolMappers" from
// "before defaultClientScopes".
//
// Measured on a live 26.7.1 on a client carrying both, in the single read and
// in the listing alike.
func TestRegisteredNodesSitsBeforeProtocolMappers(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-position")
	path := "/admin/realms/master/clients/" + uuid

	if w := send(t, h, http.MethodPut, path, admin,
		`{"protocolMappers":[{"name":"m","protocol":"openid-connect",`+
			`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"x"}}]}`); w.Code != http.StatusNoContent {
		t.Fatalf("add a mapper: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, path+"/nodes", admin, `{"node":"n2.example.com"}`); w.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}

	body := get(t, h, path, admin).Body.String()
	nodes := strings.Index(body, `"registeredNodes"`)
	mappers := strings.Index(body, `"protocolMappers"`)
	timeout := strings.Index(body, `"nodeReRegistrationTimeout"`)
	if nodes < 0 || mappers < 0 || timeout < 0 {
		t.Fatalf("one of the three keys is missing: %s", body)
	}
	if !(timeout < nodes && nodes < mappers) {
		t.Errorf("order is nodeReRegistrationTimeout=%d registeredNodes=%d protocolMappers=%d, want ascending",
			timeout, nodes, mappers)
	}
}

// TestRegisteredNodesKeyOrderIsTheSizedJavaMap is the measurement javamap
// already carries the machinery for, applied to a third family.
//
// Three key sets came off a live 26.7.1 on 2026-09-05 and `SizedKeyOrder`
// places all three where `KeyOrder` places two - and the one it misses is not a
// bucket collision, so it is a real disagreement between the two constructors
// rather than the chaining javamap says it cannot resolve.
//
// **Sorting and insertion order are both refuted here**, which is the point of
// asserting the bytes rather than the set: `kn1` then `kn2` comes back
// `kn2, kn1`, which is neither.
func TestRegisteredNodesKeyOrderIsTheSizedJavaMap(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-order")
	path := "/admin/realms/master/clients/" + uuid

	for _, node := range []string{"kn1", "kn2", "zzz", "aaa"} {
		if w := send(t, h, http.MethodPost, path+"/nodes", admin, `{"node":"`+node+`"}`); w.Code != http.StatusNoContent {
			t.Fatalf("register %s: %d %s", node, w.Code, w.Body)
		}
	}
	body := get(t, h, path, admin).Body.String()
	start := strings.Index(body, `"registeredNodes":{`)
	if start < 0 {
		t.Fatalf("no registeredNodes: %s", body)
	}
	end := strings.Index(body[start:], "}")
	if end < 0 {
		t.Fatalf("registeredNodes is not closed: %s", body[start:])
	}
	block := body[start : start+end+1]

	// The names in the order they appear, timestamps stripped. Asserting the
	// sequence rather than the pairs is what makes the comparison independent
	// of the second the test ran in.
	var got []string
	for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(block, `"registeredNodes":{`), "}"), ",") {
		got = append(got, strings.Trim(strings.SplitN(part, ":", 2)[0], `"`))
	}
	want := []string{"aaa", "zzz", "kn2", "kn1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("key order %v, want %v - sorted would be [aaa kn1 kn2 zzz] and insertion order [kn1 kn2 zzz aaa]",
			got, want)
	}
}

// TestTheNodeWritesResolveTheClientBeforeTheirRole is guardClientSubject's five
// cells, and it is the whole reason that combinator exists rather than
// h.guard("manage-clients").
//
// The distinguishing cell is the third: a `view-clients` caller sees
// `Could not find client` for a UUID that resolves to nothing and 403 for one
// that resolves. h.guard would answer 403 to both.
func TestTheNodeWritesResolveTheClientBeforeTheirRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-guard")
	real := "/admin/realms/master/clients/" + uuid + "/nodes"
	missing := "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/nodes"

	for _, tc := range []struct {
		role                  string
		wantReal, wantMissing int
	}{
		{"manage-clients", http.StatusNoContent, http.StatusNotFound},
		{"view-clients", http.StatusForbidden, http.StatusNotFound},
		{"query-clients", http.StatusForbidden, http.StatusNotFound},
		{"manage-users", http.StatusForbidden, http.StatusForbidden},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		if w := send(t, h, http.MethodPost, real, token, `{"node":"g-`+tc.role+`"}`); w.Code != tc.wantReal {
			t.Errorf("%s on a real client: %d %s, want %d", tc.role, w.Code, w.Body, tc.wantReal)
		}
		w := send(t, h, http.MethodPost, missing, token, `{"node":"x"}`)
		if w.Code != tc.wantMissing {
			t.Errorf("%s on an unknown client: %d %s, want %d", tc.role, w.Code, w.Body, tc.wantMissing)
		}
		if tc.wantMissing == http.StatusNotFound {
			if got, want := w.Body.String(), `{"error":"Could not find client"}`; got != want {
				t.Errorf("%s 404 body: %s, want %s", tc.role, got, want)
			}
		}
	}
}

// TestANodeWriteWithNoBodyIsAFiveHundred is the third route in this cut to
// reproduce Keycloak's empty-body defect, and the only place it is stated: the
// harness sends no bodyless request on this route.
func TestANodeWriteWithNoBodyIsAFiveHundred(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-nobody")
	path := "/admin/realms/master/clients/" + uuid + "/nodes"

	w := send(t, h, http.MethodPost, path, admin, "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("no body: %d %s, want 500", w.Code, w.Body)
	}
	want := `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`
	if got := w.Body.String(); got != want {
		t.Errorf("body:\n got %s\nwant %s", got, want)
	}
}

// TestANodeRegistrationIsAnUpsert pins that the same name twice is 204 twice
// and leaves one entry, which is measured and is the opposite of what the
// federated-identity write one file away does with a repeat.
func TestANodeRegistrationIsAnUpsert(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	uuid := nodeClient(t, h, admin, "node-upsert")
	path := "/admin/realms/master/clients/" + uuid

	for i := 0; i < 2; i++ {
		if w := send(t, h, http.MethodPost, path+"/nodes", admin, `{"node":"same"}`); w.Code != http.StatusNoContent {
			t.Fatalf("register %d: %d %s", i, w.Code, w.Body)
		}
	}
	nodes, _ := clientKeys(t, h, admin, path)["registeredNodes"].(map[string]any)
	if len(nodes) != 1 {
		t.Errorf("registeredNodes after two identical registrations: %v", nodes)
	}
}

// clientKeys reads a client representation back as a decoded map.
func clientKeys(t *testing.T, h http.Handler, token, path string) map[string]any {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse client: %v", err)
	}
	return out
}
