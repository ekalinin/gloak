package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The three realm-mapping reads answer three different questions, and the
// difference is the whole point of the endpoints. Measured on the bootstrapped
// administrator, which holds admin and default-roles-master directly.
func TestRealmMappingReadsAnswerThreeDifferentQuestions(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"

	direct := mappingNames(t, h, base, admin)
	if want := []string{"admin", "default-roles-master"}; !slices.Equal(direct, want) {
		t.Fatalf("direct: want %v, got %v", want, direct)
	}

	// The transitive expansion: admin is composite over create-realm, and
	// default-roles-master over offline_access and uma_authorization.
	composite := mappingNames(t, h, base+"/composite", admin)
	want := []string{"admin", "create-realm", "default-roles-master", "offline_access", "uma_authorization"}
	if !slices.Equal(composite, want) {
		t.Fatalf("composite: want %v, got %v", want, composite)
	}

	// available is "not assigned **directly**", which is not the complement of
	// composite. create-realm appears in both: the administrator effectively
	// holds it through admin, and it is still offered because it is not
	// assigned directly. Measured, and the single most misreadable of the three.
	available := mappingNames(t, h, base+"/available", admin)
	if slices.Contains(available, "admin") {
		t.Fatal("available offered a directly assigned role")
	}
	if !slices.Contains(available, "create-realm") {
		t.Fatal("available dropped a role reachable through a composite; " +
			"it is the complement of direct, not of composite")
	}
}

// A client role never appears in a realm-mapping listing, whichever of the
// three asks. The administrator holds none directly, so the direct list is the
// weakest check; its composite expansion carries all 22 master-realm roles and
// the listing must still show only the five realm ones.
func TestRealmMappingReadsExcludeClientRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"

	// view-users is a master-realm client role the administrator reaches
	// through admin, so it is in the effective set and must not be listed.
	for _, path := range []string{base, base + "/composite", base + "/available"} {
		if got := mappingNames(t, h, path, admin); slices.Contains(got, "view-users") {
			t.Fatalf("%s leaked a client role: %v", path, got)
		}
	}
}

// The guard is view-users **or** manage-users, and nothing else - measured
// against a live 26.7.1 with one user per role and a fresh token minted
// immediately before each call, on two different subjects.
//
// manage-users is not composite over view-users - it has no children at all -
// so it has to be admitted here rather than reached through view-users. The
// brief predicted view-users alone, which would refuse a manage-users caller
// Keycloak admits.
//
// query-users is the surprise in the other direction: it opens the user
// listing and the count (see usersReadRoles) and is 403 on all three of these,
// so this family cannot reuse that slice.
func TestRealmMappingReadsNeedViewOrManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"
	paths := []string{base, base + "/available", base + "/composite"}

	for _, role := range []string{"view-users", "manage-users"} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusOK {
				t.Errorf("%s as %s: want 200, got %d", path, role, got)
			}
		}
	}
	for _, role := range []string{
		"query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", path, role, got)
			}
		}
	}
}

// briefRepresentation is honoured by **composite alone**. Measured on a realm
// role carrying attributes and assigned directly: `.../realm/composite` grows
// an attributes key when the parameter is false, and `.../realm` and
// `.../realm/available` ignore the parameter entirely and never carry one.
//
// Three sibling endpoints, two behaviours. The brief hardcoded the brief shape
// for all three, which is right twice out of three.
func TestOnlyCompositeRealmMappingsHonourBriefRepresentation(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/roles", `{"name":"probe-attr","attributes":{"probe":["v1","v2"]}}`, admin)
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-subject","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-subject")
	assignRole(t, s, realm, uid, "", "probe-attr")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"

	// composite honours it, and carries the role's real attributes.
	full := mappingReps(t, h, base+"/composite?briefRepresentation=false", admin)
	rep, ok := repNamed(full, "probe-attr")
	if !ok {
		t.Fatalf("composite lost probe-attr: %v", full)
	}
	if rep.Attributes == nil {
		t.Fatal("composite?briefRepresentation=false: no attributes key")
	}
	if got := (*rep.Attributes)["probe"]; !slices.Equal(got, []string{"v1", "v2"}) {
		t.Fatalf("composite attributes: want [v1 v2], got %v", got)
	}
	// and defaults to the brief shape when the parameter is absent.
	brief := mappingReps(t, h, base+"/composite", admin)
	if rep, _ := repNamed(brief, "probe-attr"); rep.Attributes != nil {
		t.Fatalf("composite defaulted to the full shape: %v", *rep.Attributes)
	}

	// direct and available ignore it: no attributes key either way.
	for _, path := range []string{base, base + "/available"} {
		for _, q := range []string{"", "?briefRepresentation=false"} {
			for _, rep := range mappingReps(t, h, path+q, admin) {
				if rep.Attributes != nil {
					t.Errorf("%s%s: %s carries attributes; measured absent",
						path, q, rep.Name)
				}
			}
		}
	}
}

// The client triple answers the same three questions the realm one does, on
// the same subject. Measured on the bootstrapped administrator against a live
// 26.7.1: it holds no `master-realm` role **directly** - which is why its
// combined `/role-mappings` view carries no clientMappings key at all - so
// direct is 0, while `admin` is composite over all 21 and none of them is
// assigned directly, so composite and available are both 21.
func TestClientMappingReadsMirrorTheRealmTriple(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	mr := clientUUID(t, s, realm, "master-realm")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/clients/" + mr

	if got := mappingNames(t, h, base, admin); len(got) != 0 {
		t.Fatalf("direct: want none, got %v", got)
	}
	if got := mappingNames(t, h, base+"/composite", admin); len(got) != 21 {
		t.Fatalf("composite: want all 21 through the admin role, got %d: %v", len(got), got)
	}
	if got := mappingNames(t, h, base+"/available", admin); len(got) != 21 {
		t.Fatalf("available: want all 21, since none is assigned directly, got %d: %v", len(got), got)
	}
}

// available is the complement of **direct**, not of composite - the client
// mirror of the create-realm case in the realm triple above, and measured on
// its own subject rather than inferred from it.
//
// Measured on a subject holding `master-realm`'s view-users directly:
// composite is view-users plus the two it is composite over, and both of those
// are offered by available as well, because neither is assigned directly.
// Computing available from the effective set would drop them.
func TestClientAvailableIsTheComplementOfDirect(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-client-subject","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-client-subject")
	mr := clientUUID(t, s, realm, "master-realm")
	assignRole(t, s, realm, uid, mr, "view-users")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + mr

	direct := mappingNames(t, h, base, admin)
	if want := []string{"view-users"}; !slices.Equal(direct, want) {
		t.Fatalf("direct: want %v, got %v", want, direct)
	}
	// The representation's own shape, which nothing asserted before these
	// routes existed: writeMappingList's client branch is what fills it, and
	// every earlier caller pre-filtered to realm roles so it never ran.
	// Measured - clientRole is true and containerId is the client's UUID.
	rep, ok := repNamed(mappingReps(t, h, base, admin), "view-users")
	if !ok {
		t.Fatalf("direct lost view-users")
	}
	if !rep.ClientRole {
		t.Errorf("direct: clientRole is false for a client role: %+v", rep)
	}
	if rep.ContainerID != mr {
		t.Errorf("direct: containerId is %q, want the client's UUID %q", rep.ContainerID, mr)
	}
	composite := mappingNames(t, h, base+"/composite", admin)
	if want := []string{"query-groups", "query-users", "view-users"}; !slices.Equal(composite, want) {
		t.Fatalf("composite: want %v, got %v", want, composite)
	}
	available := mappingNames(t, h, base+"/available", admin)
	if len(available) != 20 {
		t.Fatalf("available: want the other 20, got %d: %v", len(available), available)
	}
	if slices.Contains(available, "view-users") {
		t.Fatal("available offered a directly assigned role")
	}
	for _, name := range []string{"query-groups", "query-users"} {
		if !slices.Contains(available, name) {
			t.Fatalf("available dropped %s, reachable through a composite but not "+
				"assigned directly; it is the complement of direct, not of composite", name)
		}
	}
}

// A client mapping listing carries **that client's roles and nothing else**:
// not the realm roles the same user holds, and not another client's. Measured
// on the administrator, whose effective set carries five realm roles and all
// 21 master-realm ones.
func TestClientMappingReadsExcludeOtherContainers(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	mr := clientUUID(t, s, realm, "master-realm")
	account := clientUUID(t, s, realm, "account")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/clients/"

	// admin and create-realm are realm roles in the administrator's effective
	// set; view-profile belongs to the account client, not to master-realm.
	for _, path := range []string{mr, mr + "/composite", mr + "/available"} {
		got := mappingNames(t, h, base+path, admin)
		for _, alien := range []string{"admin", "create-realm", "default-roles-master", "view-profile"} {
			if slices.Contains(got, alien) {
				t.Errorf("clients/%s leaked %s: %v", path, alien, got)
			}
		}
	}
	// And the other container's listing does not carry master-realm's.
	for _, path := range []string{account, account + "/composite", account + "/available"} {
		if got := mappingNames(t, h, base+path, admin); slices.Contains(got, "view-users") {
			t.Errorf("clients/%s leaked a master-realm role: %v", path, got)
		}
	}
}

// The guard is view-users **or** manage-users, exactly as the realm triple's -
// measured on the client routes directly rather than inherited from it, with
// one user per role, a fresh token minted immediately before each call, two
// subjects and two containers.
//
// A client-scoped route plausibly wants a client role too, and it does not:
// view-clients and manage-clients are 403 on all three. Two roles open the
// routes single-handed, so no pair was tried.
func TestClientMappingReadsNeedViewOrManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	adminID := userID(t, s, realm, "admin")
	mr := clientUUID(t, s, realm, "master-realm")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/clients/" + mr
	paths := []string{base, base + "/available", base + "/composite"}

	for _, role := range []string{"view-users", "manage-users"} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusOK {
				t.Errorf("%s as %s: want 200, got %d", path, role, got)
			}
		}
	}
	for _, role := range []string{
		"query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, path := range paths {
			if got := get(t, h, path, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", path, role, got)
			}
		}
	}
}

// briefRepresentation is honoured by **composite alone** on the client triple
// too. Measured on the client routes themselves, on a client role carrying
// attributes and assigned directly, with a second attribute-carrying role left
// unassigned so that available has something whose shape can be read.
//
// The realm triple behaving this way is one family's evidence and was not
// enough: the three composite listings in the roles half ignore the parameter
// outright, so two of this API's families already disagree about it.
func TestOnlyCompositeClientMappingsHonourBriefRepresentation(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app"}`, admin)
	app := clientUUID(t, s, realm, "probe-app")
	roles := "/admin/realms/master/clients/" + app + "/roles"
	postJSON(t, h, roles, `{"name":"probe-app-attr","attributes":{"probe":["v1","v2"]}}`, admin)
	postJSON(t, h, roles, `{"name":"probe-app-attr-free","attributes":{"free":["f1"]}}`, admin)
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-app-subject","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-app-subject")
	assignRole(t, s, realm, uid, app, "probe-app-attr")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app

	// composite honours it, and carries the role's real attributes.
	full := mappingReps(t, h, base+"/composite?briefRepresentation=false", admin)
	rep, ok := repNamed(full, "probe-app-attr")
	if !ok {
		t.Fatalf("composite lost probe-app-attr: %v", full)
	}
	if rep.Attributes == nil {
		t.Fatal("composite?briefRepresentation=false: no attributes key")
	}
	if got := (*rep.Attributes)["probe"]; !slices.Equal(got, []string{"v1", "v2"}) {
		t.Fatalf("composite attributes: want [v1 v2], got %v", got)
	}
	// and defaults to the brief shape when the parameter is absent.
	brief := mappingReps(t, h, base+"/composite", admin)
	rep, ok = repNamed(brief, "probe-app-attr")
	if !ok {
		t.Fatalf("composite lost probe-app-attr: %v", brief)
	}
	if rep.Attributes != nil {
		t.Fatalf("composite defaulted to the full shape: %v", *rep.Attributes)
	}

	// direct and available ignore it: no attributes key either way.
	for _, path := range []string{base, base + "/available"} {
		for _, q := range []string{"", "?briefRepresentation=false"} {
			reps := mappingReps(t, h, path+q, admin)
			if len(reps) == 0 {
				t.Fatalf("%s%s: empty, so it asserts nothing", path, q)
			}
			for _, rep := range reps {
				if rep.Attributes != nil {
					t.Errorf("%s%s: %s carries attributes; measured absent",
						path, q, rep.Name)
				}
			}
		}
	}
}

// Both top-level keys are ABSENT when their list would be empty - not [] and
// not {}. Measured on the bootstrapped administrator, which holds two realm
// roles and no client role directly.
func TestCombinedMappingViewOmitsWhatIsEmpty(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	path := "/admin/realms/master/users/" + adminID + "/role-mappings"

	var body map[string]json.RawMessage
	w := get(t, h, path, admin)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := body["realmMappings"]; !ok {
		t.Fatal("realmMappings is missing for a user that has some")
	}
	if _, ok := body["clientMappings"]; ok {
		t.Fatal("clientMappings is present for a user with no client role; " +
			"measured absent, not {}")
	}

	// Assign one and the key appears, keyed by clientId, carrying the client's
	// UUID and its clientId again.
	mr := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)
	postJSON(t, h, "/admin/realms/master/users/"+adminID+"/role-mappings/clients/"+mr,
		`[{"id":"`+viewUsers.ID+`","name":"view-users"}]`, admin)

	w = get(t, h, path, admin)
	var full struct {
		ClientMappings map[string]struct {
			ID       string `json:"id"`
			Client   string `json:"client"`
			Mappings []struct {
				Name string `json:"name"`
			} `json:"mappings"`
		} `json:"clientMappings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatalf("parse: %v", err)
	}
	entry, ok := full.ClientMappings["master-realm"]
	if !ok {
		t.Fatalf("want the entry keyed by clientId, got %v", full.ClientMappings)
	}
	if entry.ID != mr || entry.Client != "master-realm" {
		t.Fatalf("entry carries id %q client %q", entry.ID, entry.Client)
	}
}

// A user holding nothing at all gets `{}` - both keys gone, not one of them
// left behind as an empty container. Measured by stripping default-roles-master
// and both client roles off a subject and re-reading it.
func TestCombinedMappingViewOfAUserWithNoRolesIsAnEmptyObject(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-bare","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-bare")
	path := "/admin/realms/master/users/" + uid + "/role-mappings"

	defaults := readRole(t, h, "/admin/realms/master/roles/default-roles-master", admin)
	sendJSON(t, h, http.MethodDelete, path+"/realm",
		`[{"id":"`+defaults.ID+`","name":"default-roles-master"}]`, admin)

	if got := get(t, h, path, admin).Body.String(); got != "{}" {
		t.Fatalf("want {}, got %s", got)
	}
}

// clientMappings is a Java HashMap and Keycloak writes it in bucket order, so
// Gloak must not let Go sort the keys.
//
// zeta-client and alpha-client are the pair this asserts on because they are
// the discriminating one: they land in buckets 6 and 13, so the HashMap order
// is zeta-client, alpha-client - the reverse of what a Go map would emit.
// Measured, and see internal/javamap for the bucket rule.
func TestCombinedMappingViewKeysClientsInHashMapOrder(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-two","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-two")
	for _, c := range []string{"alpha-client", "zeta-client"} {
		postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"`+c+`"}`, admin)
		uuid := clientUUID(t, s, realm, c)
		postJSON(t, h, "/admin/realms/master/clients/"+uuid+"/roles", `{"name":"r-`+c+`"}`, admin)
		assignRole(t, s, realm, uid, uuid, "r-"+c)
	}

	body := get(t, h, "/admin/realms/master/users/"+uid+"/role-mappings", admin).Body.String()
	zeta := strings.Index(body, `"zeta-client":{`)
	alpha := strings.Index(body, `"alpha-client":{`)
	if zeta < 0 || alpha < 0 {
		t.Fatalf("want both clients keyed in the body, got %s", body)
	}
	if zeta > alpha {
		t.Fatalf("keys came out sorted; measured zeta-client first: %s", body)
	}
}

// The six-client vector, which is what actually pins the order.
//
// The two-client test above rules out sorting, but any deterministic
// non-alphabetical scheme has even odds of passing it. cx1..cx6 land in six
// **distinct** HashMap buckets - 13, 12, 15, 14, 1, 0 - so javamap is fully
// determined for this set with no collision to guess at, and Keycloak's
// measured answer is one particular permutation out of 720.
//
// The clients are created and the roles assigned in cx1..cx6 order on purpose:
// that is the order the fixture on the live 26.7.1 was built in, so insertion
// order is ruled out by the same assertion rather than left unmeasured.
func TestCombinedMappingViewReproducesTheMeasuredSixClientOrder(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-six","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-six")
	for _, c := range []string{"cx1", "cx2", "cx3", "cx4", "cx5", "cx6"} {
		postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"`+c+`"}`, admin)
		uuid := clientUUID(t, s, realm, c)
		postJSON(t, h, "/admin/realms/master/clients/"+uuid+"/roles", `{"name":"r-`+c+`"}`, admin)
		assignRole(t, s, realm, uid, uuid, "r-"+c)
	}

	w := get(t, h, "/admin/realms/master/users/"+uid+"/role-mappings", admin)
	want := []string{"cx6", "cx5", "cx2", "cx1", "cx4", "cx3"}
	if got := clientMappingOrder(t, w.Body.Bytes()); !slices.Equal(got, want) {
		t.Fatalf("want %v, got %v\nbody: %s", want, got, w.Body)
	}
}

// realmMappings is omitted on its own rule, not as a side effect of
// clientMappings being present. Measured on a subject stripped of
// default-roles-master while it still held a client role: the body came back
// carrying clientMappings alone, content-length 514.
//
// The two tests above cover realm-present/client-absent and both-absent, which
// leaves this third combination the only one where a per-key rule and a
// whole-body rule would disagree.
func TestCombinedMappingViewOmitsRealmMappingsAlone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app"}`, admin)
	app := clientUUID(t, s, realm, "probe-app")
	postJSON(t, h, "/admin/realms/master/clients/"+app+"/roles", `{"name":"probe-app-role"}`, admin)
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-clientonly","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-clientonly")
	assignRole(t, s, realm, uid, app, "probe-app-role")
	path := "/admin/realms/master/users/" + uid + "/role-mappings"

	defaults := readRole(t, h, "/admin/realms/master/roles/default-roles-master", admin)
	sendJSON(t, h, http.MethodDelete, path+"/realm",
		`[{"id":"`+defaults.ID+`","name":"default-roles-master"}]`, admin)

	var body map[string]json.RawMessage
	w := get(t, h, path, admin)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := body["realmMappings"]; ok {
		t.Fatalf("realmMappings is present for a user with no realm role; "+
			"measured absent, not []: %s", w.Body)
	}
	if _, ok := body["clientMappings"]; !ok {
		t.Fatalf("clientMappings is missing for a user that has one: %s", w.Body)
	}
}

// clientMappingOrder returns the clientMappings keys in the order the body
// carries them.
//
// Decoding into a map cannot be used here: Go loses the order, and the order is
// the whole assertion. So the object is walked as a token stream instead.
func clientMappingOrder(t *testing.T, body []byte) []string {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("parse: %v", err)
	}
	raw, ok := top["clientMappings"]
	if !ok {
		t.Fatalf("no clientMappings in %s", body)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil { // the opening brace
		t.Fatalf("clientMappings is not an object: %v", err)
	}
	out := make([]string, 0)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		name, ok := key.(string)
		if !ok {
			t.Fatalf("key %v is not a string", key)
		}
		out = append(out, name)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("value of %s: %v", name, err)
		}
	}
	return out
}

// The combined view takes the same pair the other six reads take - measured on
// this route across the same seven single-role callers, not inherited from
// them. view-clients was the plausible one on a body that is keyed by clientId,
// and it is 403 here like every other role outside the users family.
func TestCombinedMappingViewNeedsViewOrManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	adminID := userID(t, s, realm, "admin")
	path := "/admin/realms/master/users/" + adminID + "/role-mappings"

	for _, role := range []string{"view-users", "manage-users"} {
		token := tokenForRole(t, h, s, realm, role)
		if got := get(t, h, path, token).Code; got != http.StatusOK {
			t.Errorf("%s as %s: want 200, got %d", path, role, got)
		}
	}
	for _, role := range []string{
		"query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		if got := get(t, h, path, token).Code; got != http.StatusForbidden {
			t.Errorf("%s as %s: want 403, got %d", path, role, got)
		}
	}
}

// briefRepresentation does **nothing** on this route. Measured on a subject
// holding a client role that carries a real attribute value, with the parameter
// absent, true and false: all three bodies came back byte-identical and none
// carried an attributes key. So this endpoint is neither the composite listings
// that honour it nor a special case - it is the majority behaviour.
func TestCombinedMappingViewIgnoresBriefRepresentation(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app"}`, admin)
	app := clientUUID(t, s, realm, "probe-app")
	postJSON(t, h, "/admin/realms/master/clients/"+app+"/roles",
		`{"name":"probe-app-attr","attributes":{"probe":["v1"]}}`, admin)
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-brief","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-brief")
	assignRole(t, s, realm, uid, app, "probe-app-attr")
	path := "/admin/realms/master/users/" + uid + "/role-mappings"

	w := get(t, h, path, admin)
	want := w.Body.String()
	// Asserted before the comparison below, which three identical error bodies
	// would otherwise satisfy while asserting nothing.
	if w.Code != http.StatusOK || !strings.Contains(want, `"probe-app-attr"`) {
		t.Fatalf("want a 200 carrying the attribute-bearing role, got %d %s", w.Code, want)
	}
	if strings.Contains(want, `"attributes"`) {
		t.Fatalf("the default shape carries attributes; measured absent: %s", want)
	}
	for _, q := range []string{"?briefRepresentation=false", "?briefRepresentation=true"} {
		if got := get(t, h, path+q, admin).Body.String(); got != want {
			t.Errorf("%s changed the body\n want %s\n  got %s", q, want, got)
		}
	}
}

// A client UUID that resolves to nothing answers `{"error":"Client not
// found"}` on all three - which is **not** the "Could not find client" the
// client and role endpoints send for the same unknown UUID. Measured side by
// side in one session; it is the ninth not-found spelling.
//
// The subject is resolved first: an unknown user with an unknown client
// answers "User not found", so userFromPath runs before the client lookup.
func TestClientMappingReadsAnswerTheMeasuredNotFounds(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	const none = "00000000-0000-0000-0000-000000000000"

	for _, suffix := range []string{"", "/available", "/composite"} {
		path := "/admin/realms/master/users/" + adminID + "/role-mappings/clients/" + none + suffix
		w := get(t, h, path, admin)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d: %s", path, w.Code, w.Body)
			continue
		}
		if got := w.Body.String(); got != `{"error":"Client not found"}` {
			t.Errorf("%s: unexpected body: %s", path, got)
		}
	}
	// The control, in the same test: the roles endpoint's spelling differs.
	if got := get(t, h, "/admin/realms/master/clients/"+none+"/roles", admin).Body.String(); got != `{"error":"Could not find client"}` {
		t.Errorf("the roles endpoint's client 404 changed: %s", got)
	}
	// Unknown user and unknown client together: the user is answered.
	unknown := "/admin/realms/master/users/" + none + "/role-mappings/clients/" + none
	w := get(t, h, unknown, admin)
	if w.Code != http.StatusNotFound || w.Body.String() != `{"error":"User not found"}` {
		t.Errorf("unknown user and client: want 404 User not found, got %d %s", w.Code, w.Body)
	}
}

// The round trip: POST puts a realm role on a user, DELETE takes it off, and
// both answer 204.
//
// The 204 carries X-Frame-Options because these requests send an
// application/json Content-Type - measured, and the reason the DELETE goes
// through sendJSON rather than the bodyless do(). A bodyless delete on this
// same path would be observably different.
func TestAssignAndRemoveRealmMappings(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)

	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	w := postJSON(t, h, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("assign 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); !slices.Contains(got, "offline_access") {
		t.Fatalf("assign did not stick: %v", got)
	}

	w = sendJSON(t, h, http.MethodDelete, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("remove 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); slices.Contains(got, "offline_access") {
		t.Fatalf("remove did not stick: %v", got)
	}
}

// Both verbs validate the whole batch before applying any of it: one bad id
// and nothing in the request lands.
//
// Measured on both verbs and in both id orders rather than carried over from
// POST .../composites, which behaves the same way. The two happen to agree, but
// the composite writes were separately measured **disagreeing** with each other
// on the per-child manage check, so agreement between neighbours is not
// something this file assumes.
func TestRealmMappingWritesAreAllOrNothing(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	good := `{"id":"` + offline.ID + `","name":"offline_access"}`
	bad := `{"id":"00000000-0000-0000-0000-000000000000","name":"nope"}`

	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := postJSON(t, h, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("assign %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		// The measured body for an id that resolves to nothing, pinned here as
		// well as in the client-role case below: the status alone would pass
		// for any 404 this API can produce.
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("assign %s: unexpected body: %s", body, got)
		}
		if got := mappingNames(t, h, base, admin); slices.Contains(got, "offline_access") {
			t.Fatalf("assign %s applied the valid half: %v", body, got)
		}
	}

	// The remove side, with the valid half genuinely assigned first so that a
	// non-atomic implementation would have something to take away.
	postJSON(t, h, base, "["+good+"]", admin)
	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := sendJSON(t, h, http.MethodDelete, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("remove %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("remove %s: unexpected body: %s", body, got)
		}
		if got := mappingNames(t, h, base, admin); !slices.Contains(got, "offline_access") {
			t.Fatalf("remove %s applied the valid half: %v", body, got)
		}
	}
}

// A client role sent to the **realm** endpoint is 404 "Role not found" on both
// verbs - a different message from the roles endpoints' "Could not find role"
// two paths away, and from the composite batch's "Could not find composite
// role". Measured; it is the sixth of eight not-found spellings.
//
// The id used here resolves to a role that exists. It is refused for being a
// client role, not for being unknown.
func TestRealmMappingWritesRejectAClientRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	mr := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)
	body := `[{"id":"` + viewUsers.ID + `","name":"view-users"}]`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		w := sendJSON(t, h, method, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: want 404, got %d: %s", method, w.Code, w.Body)
			continue
		}
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("%s: unexpected body: %s", method, got)
		}
	}
}

// The writes take manage-users **alone**, which is narrower than the reads next
// door: view-users opens all three reads and neither write.
//
// Measured against a live 26.7.1 with one user per role and a fresh token
// minted immediately before each call, on both verbs. The read sweep is
// deliberately not reused - the previous half of this sub-project twice
// extended a rule measured on one verb to its neighbour and had to revert both
// times - and this is the case where reusing it would have been wrong.
//
// The bodies below name a role that exists, so a 403 here is the route guard
// and not the caller-relative filter recorded under "A mapping write **is**
// filtered by what the caller may grant"; the same callers were measured
// getting 403 for an empty array too, which has nothing to filter.
func TestRealmMappingWritesNeedManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	methods := []string{http.MethodPost, http.MethodDelete}

	token := tokenForRole(t, h, s, realm, "manage-users")
	for _, method := range methods {
		if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusNoContent {
			t.Errorf("%s as manage-users: want 204, got %d", method, got)
		}
	}
	for _, role := range []string{
		"view-users", "query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, method := range methods {
			if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", method, role, got)
			}
		}
	}
}

// Both verbs are idempotent and neither reports a conflict: assigning a role
// the user already holds is 204, and removing one it does not hold is 204.
// Measured - not 409 and not 404, although the store reports ErrConflict and
// ErrNotFound respectively for exactly these two cases.
//
// An empty array is 204 as well, with nothing to validate or apply.
func TestRealmMappingWritesAreIdempotent(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`

	postJSON(t, h, base, body, admin)
	if got := postJSON(t, h, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("assigning twice: want 204, got %d", got)
	}
	sendJSON(t, h, http.MethodDelete, base, body, admin)
	if got := sendJSON(t, h, http.MethodDelete, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("removing what is not held: want 204, got %d", got)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		if got := sendJSON(t, h, method, base, `[]`, admin).Code; got != http.StatusNoContent {
			t.Errorf("%s []: want 204, got %d", method, got)
		}
	}
}

// The array-taking endpoints answer `unknown_error`, where POST /users answers
// `invalid_request` for the same "Cannot parse the JSON" description.
//
// Measured 2026-08-26 on both verbs of this endpoint and on POST
// .../composites, with a malformed body and a well-formed non-array body, all
// four giving the same answer - and POST /users re-measured alongside to
// confirm the difference is per endpoint rather than a version change. That
// correction lives in decodeRoleList, which both families share.
func TestRealmMappingWritesRejectANonArrayBody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	want := `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, body := range []string{`{"id":"x"}`, `{not json`} {
			w := sendJSON(t, h, method, base, body, admin)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s: want 400, got %d", method, body, w.Code)
				continue
			}
			if got := w.Body.String(); got != want {
				t.Errorf("%s %s: want %s, got %s", method, body, want, got)
			}
		}
	}
}

// The client round trip: POST puts one client's role on a user, DELETE takes
// it off, and both answer 204.
//
// The 204 carries X-Frame-Options here too, because these requests send an
// application/json Content-Type - measured on this route, not carried over from
// the realm pair, and the reason the DELETE goes through sendJSON rather than
// the bodyless do().
func TestAssignAndRemoveClientMappings(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	role := readRole(t, h, "/admin/realms/master/clients/"+app+"/roles/probe-app-role", admin)

	body := `[{"id":"` + role.ID + `","name":"probe-app-role"}]`
	w := postJSON(t, h, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("assign 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); !slices.Contains(got, "probe-app-role") {
		t.Fatalf("assign did not stick: %v", got)
	}

	w = sendJSON(t, h, http.MethodDelete, base, body, admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("remove 204: want X-Frame-Options SAMEORIGIN, got %q", got)
	}
	if got := mappingNames(t, h, base, admin); slices.Contains(got, "probe-app-role") {
		t.Fatalf("remove did not stick: %v", got)
	}
}

// A role this endpoint's client does not own is 404 `{"error":"Role not
// found"}` on both verbs, whether it is a **realm** role or **another
// client's**.
//
// The message was measured on this route rather than assumed from the realm
// mirror's: the task before this one found a ninth not-found spelling exactly
// where a mirror was taken for granted. Here the mirror holds - it is the same
// "Role not found", not a tenth spelling.
//
// Both ids name a role that exists, so neither is refused for being unknown.
// The realm role is the case the plan named; the other client's role is the one
// that decides the implementation, because it is what makes the check
// `ClientID != this client` rather than `ClientID == ""`.
func TestClientMappingWritesRejectARoleOfAnotherContainer(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	mr := clientUUID(t, s, realm, "master-realm")
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)

	for _, alien := range []struct{ what, body string }{
		{"a realm role", `[{"id":"` + offline.ID + `","name":"offline_access"}]`},
		{"another client's role", `[{"id":"` + viewUsers.ID + `","name":"view-users"}]`},
	} {
		for _, method := range []string{http.MethodPost, http.MethodDelete} {
			w := sendJSON(t, h, method, base, alien.body, admin)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s: want 404, got %d: %s", method, alien.what, w.Code, w.Body)
				continue
			}
			if got := w.Body.String(); got != `{"error":"Role not found"}` {
				t.Errorf("%s %s: unexpected body: %s", method, alien.what, got)
			}
		}
	}
	// The control: both ids are real, and their own endpoints take them.
	realmBase := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	if got := postJSON(t, h, realmBase, `[{"id":"`+offline.ID+`","name":"offline_access"}]`, admin).Code; got != http.StatusNoContent {
		t.Errorf("the realm endpoint refused its own role: %d", got)
	}
	mrBase := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + mr
	if got := postJSON(t, h, mrBase, `[{"id":"`+viewUsers.ID+`","name":"view-users"}]`, admin).Code; got != http.StatusNoContent {
		t.Errorf("master-realm's endpoint refused its own role: %d", got)
	}
}

// Both verbs validate the whole batch before applying any of it, exactly as the
// realm pair does - measured on these routes, in both id orders and on both
// verbs, rather than inherited from that mirror.
func TestClientMappingWritesAreAllOrNothing(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	role := readRole(t, h, "/admin/realms/master/clients/"+app+"/roles/probe-app-role", admin)
	good := `{"id":"` + role.ID + `","name":"probe-app-role"}`
	bad := `{"id":"00000000-0000-0000-0000-000000000000","name":"nope"}`

	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := postJSON(t, h, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("assign %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		// The body is the measured one for an id that resolves to nothing,
		// which is the same string the wrong-container case sends. Pinned here
		// too: the status alone would pass for any 404 this API can produce.
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("assign %s: unexpected body: %s", body, got)
		}
		if got := mappingNames(t, h, base, admin); slices.Contains(got, "probe-app-role") {
			t.Fatalf("assign %s applied the valid half: %v", body, got)
		}
	}

	// The remove side, with the valid half genuinely assigned first so that a
	// non-atomic implementation would have something to take away.
	postJSON(t, h, base, "["+good+"]", admin)
	for _, body := range []string{"[" + good + "," + bad + "]", "[" + bad + "," + good + "]"} {
		w := sendJSON(t, h, http.MethodDelete, base, body, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("remove %s: want 404, got %d: %s", body, w.Code, w.Body)
		}
		if got := w.Body.String(); got != `{"error":"Role not found"}` {
			t.Errorf("remove %s: unexpected body: %s", body, got)
		}
		if got := mappingNames(t, h, base, admin); !slices.Contains(got, "probe-app-role") {
			t.Fatalf("remove %s applied the valid half: %v", body, got)
		}
	}
}

// The client writes take manage-users **alone** - the realm writes' guard, and
// narrower than the client reads next door, which view-users opens.
//
// Measured on these routes with one user per role, a fresh token minted
// immediately before each call, and an empty array as well as a real one so
// that the refusal is the route guard rather than the caller-relative filter.
// A client-scoped **write** is where manage-clients was most plausible, and it
// is 403 on both verbs, on an ordinary client and on the realm's own.
func TestClientMappingWritesNeedManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	// appRole, not role: the loop below binds role to the caller's guard role,
	// and two role variables in a dozen lines is a re-read every time.
	appRole := readRole(t, h, "/admin/realms/master/clients/"+app+"/roles/probe-app-role", admin)
	body := `[{"id":"` + appRole.ID + `","name":"probe-app-role"}]`
	methods := []string{http.MethodPost, http.MethodDelete}

	token := tokenForRole(t, h, s, realm, "manage-users")
	for _, method := range methods {
		if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusNoContent {
			t.Errorf("%s as manage-users: want 204, got %d", method, got)
		}
	}
	for _, role := range []string{
		"view-users", "query-users", "view-realm", "manage-realm", "view-clients", "manage-clients",
	} {
		token := tokenForRole(t, h, s, realm, role)
		for _, method := range methods {
			if got := sendJSON(t, h, method, base, body, token).Code; got != http.StatusForbidden {
				t.Errorf("%s as %s: want 403, got %d", method, role, got)
			}
			if got := sendJSON(t, h, method, base, `[]`, token).Code; got != http.StatusForbidden {
				t.Errorf("%s [] as %s: want 403, got %d", method, role, got)
			}
		}
	}
}

// Both verbs are idempotent here too: assigning a role the user already holds
// is 204 and removing one it does not hold is 204, and an empty array is 204
// with nothing to validate. Measured on these routes.
func TestClientMappingWritesAreIdempotent(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	role := readRole(t, h, "/admin/realms/master/clients/"+app+"/roles/probe-app-role", admin)
	body := `[{"id":"` + role.ID + `","name":"probe-app-role"}]`

	postJSON(t, h, base, body, admin)
	if got := postJSON(t, h, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("assigning twice: want 204, got %d", got)
	}
	sendJSON(t, h, http.MethodDelete, base, body, admin)
	if got := sendJSON(t, h, http.MethodDelete, base, body, admin).Code; got != http.StatusNoContent {
		t.Errorf("removing what is not held: want 204, got %d", got)
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		if got := sendJSON(t, h, method, base, `[]`, admin).Code; got != http.StatusNoContent {
			t.Errorf("%s []: want 204, got %d", method, got)
		}
	}
}

// The two path segments are resolved **before the body is read**, and in the
// measured order: the user, then the client, then the JSON.
//
// The last of those is what pins the order rather than merely the pair: an
// unknown client sent a body that cannot be parsed answers the client's 404,
// not the decoder's 400. A handler that decoded first would answer the 400.
func TestClientMappingWritesResolveThePathBeforeTheBody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	const none = "00000000-0000-0000-0000-000000000000"
	role := readRole(t, h, "/admin/realms/master/clients/"+app+"/roles/probe-app-role", admin)
	body := `[{"id":"` + role.ID + `","name":"probe-app-role"}]`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, c := range []struct{ what, path, body, want string }{
			{"an unknown client",
				"/admin/realms/master/users/" + uid + "/role-mappings/clients/" + none,
				body, `{"error":"Client not found"}`},
			{"an unknown user with a real client",
				"/admin/realms/master/users/" + none + "/role-mappings/clients/" + app,
				body, `{"error":"User not found"}`},
			{"an unknown user with an unknown client",
				"/admin/realms/master/users/" + none + "/role-mappings/clients/" + none,
				body, `{"error":"User not found"}`},
			{"an unknown client with a body that cannot be parsed",
				"/admin/realms/master/users/" + uid + "/role-mappings/clients/" + none,
				`{"id":"x"}`, `{"error":"Client not found"}`},
			{"an unknown user with a body that cannot be parsed",
				"/admin/realms/master/users/" + none + "/role-mappings/clients/" + app,
				`{"id":"x"}`, `{"error":"User not found"}`},
		} {
			w := sendJSON(t, h, method, c.path, c.body, admin)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s %s: want 404, got %d: %s", method, c.what, w.Code, w.Body)
				continue
			}
			if got := w.Body.String(); got != c.want {
				t.Errorf("%s %s: want %s, got %s", method, c.what, c.want, got)
			}
		}
	}
}

// These are the two registrations the observed document's sweep of
// decodeRoleList's call sites listed as **not covered** - "they will reach the
// same helper, and they should be measured when they land rather than assumed
// from this sweep". Measured on both verbs and both body forms: they answer
// `unknown_error` like the other eight, so the sweep is now complete at ten.
func TestClientMappingWritesRejectANonArrayBody(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uid, app := clientWriteFixture(t, h, s, realm)
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + app
	want := `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, body := range []string{`{"id":"x"}`, `{not json`} {
			w := sendJSON(t, h, method, base, body, admin)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s: want 400, got %d", method, body, w.Code)
				continue
			}
			if got := w.Body.String(); got != want {
				t.Errorf("%s %s: want %s, got %s", method, body, want, got)
			}
		}
	}
}

// clientWriteFixture is the subject and container the client-write tests share:
// the user probe-mapped and an ordinary client probe-app owning one role.
//
// An ordinary client rather than master-realm, because master-realm's roles are
// the ones the caller-relative filter F28 covers would judge, and the guard
// sweep above must not be measuring that filter by accident.
func clientWriteFixture(t *testing.T, h http.Handler, s store.Store, realm *model.Realm) (subject, container string) {
	t.Helper()
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-app"}`, admin)
	app := clientUUID(t, s, realm, "probe-app")
	postJSON(t, h, "/admin/realms/master/clients/"+app+"/roles", `{"name":"probe-app-role"}`, admin)
	return userID(t, s, realm, "probe-mapped"), app
}

// mappingNames reads a role-mapping listing and returns the names, sorted.
func mappingNames(t *testing.T, h http.Handler, path, token string) []string {
	t.Helper()
	names := make([]string, 0)
	for _, r := range mappingReps(t, h, path, token) {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}

// mappingReps reads a role-mapping listing whole, for the assertions that care
// about the shape rather than the membership.
func mappingReps(t *testing.T, h http.Handler, path, token string) []roleRepresentation {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var reps []roleRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &reps); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return reps
}

func repNamed(reps []roleRepresentation, name string) (roleRepresentation, bool) {
	for _, r := range reps {
		if r.Name == name {
			return r, true
		}
	}
	return roleRepresentation{}, false
}

// userID is clientUUID's shape for a user: the store lookup the API cannot do
// yet, since a username is not a path segment anywhere.
func userID(t *testing.T, s store.Store, realm *model.Realm, username string) string {
	t.Helper()
	u, err := s.Users().ByUsername(context.Background(), realm.ID, username)
	if err != nil {
		t.Fatalf("ByUsername(%s): %v", username, err)
	}
	return u.ID
}

// assignRole gives a user a role through the store. container is the owning
// client's UUID, or "" for a realm role - the same convention RoleRepo.ByName
// takes, rather than a second helper for the client side.
//
// The API can do this now, but the read tests above must not depend on the
// write path: a broken POST would otherwise make them fail for a reason that
// has nothing to do with what they assert.
func assignRole(t *testing.T, s store.Store, realm *model.Realm, userID, container, role string) {
	t.Helper()
	ctx := context.Background()
	r, err := s.Roles().ByName(ctx, realm.ID, container, role)
	if err != nil {
		t.Fatalf("ByName(%s): %v", role, err)
	}
	if err := s.Roles().AssignToUser(ctx, userID, r.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
}

// F28's escalation on the second call site: the same caller assigning `admin`
// to a user. This is the one that became reachable when role assignment
// shipped - a manage-users caller could hand out admin and, from that user's
// token, do anything at all.
//
// Measured against a live 26.7.1 with a fresh token minted immediately before
// each call, subject read back after every request: admin 403, create-realm
// 403, uma_authorization 204, and the full administrator 204 on all three.
func TestMappingWriteRefusesAnAdminRoleTheCallerCannotGrant(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"

	for _, tc := range []struct {
		role string
		want int
	}{
		{"admin", http.StatusForbidden},
		{"create-realm", http.StatusForbidden},
		{"uma_authorization", http.StatusNoContent},
	} {
		role := readRole(t, h, "/admin/realms/master/roles/"+tc.role, admin)
		body := `[{"id":"` + role.ID + `","name":"` + tc.role + `"}]`
		w := postJSON(t, h, base, body, caller)
		if w.Code != tc.want {
			t.Errorf("assign %s: want %d, got %d: %s", tc.role, tc.want, w.Code, w.Body)
			continue
		}
		if got := mappingNames(t, h, base, admin); slices.Contains(got, tc.role) != (tc.want == http.StatusNoContent) {
			t.Errorf("assign %s: status %d but the subject holds %v", tc.role, w.Code, got)
		}
		// The control in the same loop: a full administrator is not refused
		// any of them, so the 403s above are about the caller and not the role.
		if w := postJSON(t, h, base, body, admin); w.Code != http.StatusNoContent {
			t.Errorf("full administrator assigning %s: want 204, got %d: %s", tc.role, w.Code, w.Body)
		}
	}
}

// The removal is filtered too, which is where this pair parts company with
// `DELETE .../composites`. Measured: a manage-users caller is refused DELETE
// naming admin on a subject that holds it, and the subject keeps it.
func TestMappingRemovalIsFilteredTheSameWay(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	body := `[{"id":"` + readRole(t, h, "/admin/realms/master/roles/admin", admin).ID + `","name":"admin"}]`

	if w := postJSON(t, h, base, body, admin); w.Code != http.StatusNoContent {
		t.Fatalf("setup: full administrator assigning admin: %d %s", w.Code, w.Body)
	}
	w := sendJSON(t, h, http.MethodDelete, base, body, caller)
	if w.Code != http.StatusForbidden {
		t.Fatalf("remove admin: want 403, got %d: %s", w.Code, w.Body)
	}
	if got := mappingNames(t, h, base, admin); !slices.Contains(got, "admin") {
		t.Fatalf("the refusal still removed the role: %v", got)
	}
}

// The client pair takes the same predicate, measured on its own routes rather
// than inherited from the realm one.
//
// Caller holding only manage-users, container master-realm: view-users is
// allowed, manage-realm, manage-clients and impersonation are refused - and the
// set it may write is exactly the set its own available read shows it, which is
// what ties this to the read filter below.
func TestClientMappingWritesTakeTheSamePredicate(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	mrUUID := clientUUID(t, s, realm, "master-realm")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + mrUUID

	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-users", http.StatusNoContent},
		{"manage-realm", http.StatusForbidden},
		{"manage-clients", http.StatusForbidden},
		{"impersonation", http.StatusForbidden},
	} {
		role := readRole(t, h, "/admin/realms/master/clients/"+mrUUID+"/roles/"+tc.role, admin)
		body := `[{"id":"` + role.ID + `","name":"` + tc.role + `"}]`
		w := postJSON(t, h, base, body, caller)
		if w.Code != tc.want {
			t.Errorf("assign %s: want %d, got %d: %s", tc.role, tc.want, w.Code, w.Body)
			continue
		}
		if got := mappingNames(t, h, base, admin); slices.Contains(got, tc.role) != (tc.want == http.StatusNoContent) {
			t.Errorf("assign %s: status %d but the subject holds %v", tc.role, w.Code, got)
		}
	}
	// The writable set is the available set, on the same caller and container.
	if got := mappingNames(t, h, base+"/available", caller); !slices.Contains(got, "manage-users") || slices.Contains(got, "manage-realm") {
		t.Errorf("available disagrees with the write: %v", got)
	}
}

// The refusal is all-or-nothing and answers in array order, both measured. A
// batch naming one role the caller may grant and one it may not applies
// neither, whichever comes first; a bad id in front answers 404 before the
// refused role is looked at.
func TestMappingWriteRefusalIsAllOrNothing(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	allowed := `{"id":"` + readRole(t, h, "/admin/realms/master/roles/uma_authorization", admin).ID + `","name":"uma_authorization"}`
	refused := `{"id":"` + readRole(t, h, "/admin/realms/master/roles/admin", admin).ID + `","name":"admin"}`
	missing := `{"id":"00000000-0000-0000-0000-000000000000","name":"nope"}`

	for _, tc := range []struct {
		body string
		want int
	}{
		{"[" + allowed + "," + refused + "]", http.StatusForbidden},
		{"[" + refused + "," + allowed + "]", http.StatusForbidden},
		{"[" + missing + "," + refused + "]", http.StatusNotFound},
		{"[" + refused + "," + missing + "]", http.StatusForbidden},
	} {
		w := postJSON(t, h, base, tc.body, caller)
		if w.Code != tc.want {
			t.Errorf("%s: want %d, got %d: %s", tc.body, tc.want, w.Code, w.Body)
		}
		// The subject holds default-roles-master from its creation and nothing
		// else, so anything more than that is a half-applied batch.
		if got := mappingNames(t, h, base, admin); !slices.Equal(got, []string{"default-roles-master"}) {
			t.Errorf("%s applied part of the batch: %v", tc.body, got)
		}
	}
}

// Both available reads are filtered by what the caller may grant, and the
// view-users row is the one that shows the filter is not simply the route
// guard: it is 200 with an empty body, on the realm and on a client.
//
// Measured on one subject with three callers, a fresh token minted immediately
// before each call. The full administrator's answer is exactly the complement
// of the direct assignments; manage-users loses admin and create-realm on the
// realm side and keeps seven of master-realm's 21 on the client side;
// view-users loses everything, because it may read the list and assign none of
// it.
func TestAvailableMappingsAreFilteredByWhatTheCallerMayGrant(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	viewUsers := tokenForRole(t, h, s, realm, "view-users")
	manageUsers := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	mrUUID := clientUUID(t, s, realm, "master-realm")
	realmBase := "/admin/realms/master/users/" + uid + "/role-mappings/realm/available"
	clientBase := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + mrUUID + "/available"

	for _, tc := range []struct {
		name   string
		token  string
		realm  []string
		client []string
	}{
		{"view-users", viewUsers, []string{}, []string{}},
		// default-roles-master is in neither row: the subject holds it
		// directly, and available is the complement of the direct list.
		{"manage-users", manageUsers,
			[]string{"offline_access", "uma_authorization"},
			[]string{"manage-users", "query-clients", "query-groups", "query-organizations", "query-realms", "query-users", "view-users"}},
		{"full administrator", admin,
			[]string{"admin", "create-realm", "offline_access", "uma_authorization"},
			[]string{"create-client", "impersonation", "manage-authorization", "manage-clients", "manage-events",
				"manage-identity-providers", "manage-organizations", "manage-realm", "manage-users", "query-clients",
				"query-groups", "query-organizations", "query-realms", "query-users", "view-authorization",
				"view-clients", "view-events", "view-identity-providers", "view-organizations", "view-realm", "view-users"}},
	} {
		if got := mappingNames(t, h, realmBase, tc.token); !slices.Equal(got, tc.realm) {
			t.Errorf("caller %s realm available: want %v, got %v", tc.name, tc.realm, got)
		}
		if got := mappingNames(t, h, clientBase, tc.token); !slices.Equal(got, tc.client) {
			t.Errorf("caller %s client available: want %v, got %v", tc.name, tc.client, got)
		}
	}
}

// The role's **container** decides whether it is an admin role, not its name.
//
// Measured on a live 26.7.1 with a client of one's own carrying roles named
// admin, impersonation and manage-realm: a caller holding only manage-users
// assigns all three, 204 each, and sees all three in that client's available
// list - while master-realm's roles of the very same names are refused to it.
// A predicate keyed on the name would refuse these and diverge.
func TestOnlyTheRealmsOwnClientCarriesAdminRoles(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRole(t, h, s, realm, "manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	postJSON(t, h, "/admin/realms/master/clients", `{"clientId":"probe-imposter"}`, admin)
	impostor := clientUUID(t, s, realm, "probe-imposter")
	names := []string{"admin", "impersonation", "manage-realm"}
	for _, n := range names {
		postJSON(t, h, "/admin/realms/master/clients/"+impostor+"/roles", `{"name":"`+n+`"}`, admin)
	}
	base := "/admin/realms/master/users/" + uid + "/role-mappings/clients/" + impostor

	for _, n := range names {
		role := readRole(t, h, "/admin/realms/master/clients/"+impostor+"/roles/"+n, admin)
		body := `[{"id":"` + role.ID + `","name":"` + n + `"}]`
		if w := postJSON(t, h, base, body, caller); w.Code != http.StatusNoContent {
			t.Errorf("assign probe-imposter/%s: want 204, got %d: %s", n, w.Code, w.Body)
		}
	}
	if got := mappingNames(t, h, base, admin); !slices.Equal(got, names) {
		t.Errorf("subject holds %v, want %v", got, names)
	}
}

// The mirror of the test above, on the **caller's** side of the predicate: an
// ordinary role named `admin` must not unlock the realm role `admin`.
//
// The two halves are not the same statement. The test above says the role being
// handed out is judged by its container; this one says the roles the caller
// already holds are judged the same way. Getting the first right and the second
// wrong is a privilege escalation and it shipped: grants() was seeded from every
// name the caller held, from any container, and mayGrantRole consults grants()
// before it looks at any container - so a client role of one's own named `admin`
// made the predicate answer true for the realm role of that name.
//
// The route guard is not the thing under test here. The caller holds
// manage-users legitimately, so it reaches the handler either way; what it must
// not reach is realm superuser. See F28's entry in the follow-ups, and F32 for
// the name-keying that survives in `has`.
func TestAnOrdinaryRoleNamedAdminDoesNotUnlockTheRealmRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRoles(t, h, s, realm, "manage-clients", "manage-users")
	callerID := userID(t, s, realm, "only-manage-clients+manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-victim","enabled":true}`, admin)
	victim := userID(t, s, realm, "probe-victim")
	victimBase := "/admin/realms/master/users/" + victim + "/role-mappings/realm"
	grantAdmin := `[{"id":"` + readRole(t, h, "/admin/realms/master/roles/admin", admin).ID + `","name":"admin"}]`

	// The control, before the collision exists: refused.
	if got := postJSON(t, h, victimBase, grantAdmin, caller).Code; got != http.StatusForbidden {
		t.Fatalf("control: want 403 before the collision, got %d", got)
	}

	// admin-cli is not the realm's own client, so manage-clients may mint a role
	// named `admin` on it and the caller may assign it to itself. Both of those
	// are legitimate and stay 201/204 - the escalation was the third step.
	adminCli := clientUUID(t, s, realm, "admin-cli")
	if w := postJSON(t, h, "/admin/realms/master/clients/"+adminCli+"/roles", `{"name":"admin"}`, caller); w.Code != http.StatusCreated {
		t.Fatalf("mint an ordinary role named admin: %d %s", w.Code, w.Body)
	}
	impostor := readRole(t, h, "/admin/realms/master/clients/"+adminCli+"/roles/admin", caller)
	self := "/admin/realms/master/users/" + callerID + "/role-mappings/clients/" + adminCli
	if w := postJSON(t, h, self, `[{"id":"`+impostor.ID+`","name":"admin"}]`, caller); w.Code != http.StatusNoContent {
		t.Fatalf("self-assign the ordinary role: %d %s", w.Code, w.Body)
	}

	if w := postJSON(t, h, victimBase, grantAdmin, caller); w.Code != http.StatusForbidden {
		t.Fatalf("an ordinary role named admin unlocked the realm role: %d %s", w.Code, w.Body)
	}
	if got := mappingNames(t, h, victimBase, admin); slices.Contains(got, "admin") {
		t.Fatalf("the victim was promoted: %v", got)
	}
}

// The same collision through the implication closure rather than through a
// direct name match, and on the read rather than the write.
//
// adminRoleImplications is keyed by name, so seeding grants() with an ordinary
// name did not merely add that name - it added everything the admin role of that
// name confers. Measured on the shipped code by the reviewer: three ordinary
// roles named manage-realm, impersonation and manage-events took this caller's
// `available` list on master-realm from 12 roles to 19.
func TestOrdinaryNamesDoNotSeedTheImplicationClosure(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	caller := tokenForRoles(t, h, s, realm, "manage-clients", "manage-users")
	callerID := userID(t, s, realm, "only-manage-clients+manage-users")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-victim","enabled":true}`, admin)
	victim := userID(t, s, realm, "probe-victim")
	mrUUID := clientUUID(t, s, realm, "master-realm")
	available := "/admin/realms/master/users/" + victim + "/role-mappings/clients/" + mrUUID + "/available"

	before := mappingNames(t, h, available, caller)

	adminCli := clientUUID(t, s, realm, "admin-cli")
	for _, n := range []string{"manage-realm", "impersonation", "manage-events"} {
		if w := postJSON(t, h, "/admin/realms/master/clients/"+adminCli+"/roles", `{"name":"`+n+`"}`, caller); w.Code != http.StatusCreated {
			t.Fatalf("mint an ordinary role named %s: %d %s", n, w.Code, w.Body)
		}
		impostor := readRole(t, h, "/admin/realms/master/clients/"+adminCli+"/roles/"+n, caller)
		self := "/admin/realms/master/users/" + callerID + "/role-mappings/clients/" + adminCli
		if w := postJSON(t, h, self, `[{"id":"`+impostor.ID+`","name":"`+n+`"}]`, caller); w.Code != http.StatusNoContent {
			t.Fatalf("self-assign the ordinary role %s: %d %s", n, w.Code, w.Body)
		}
	}

	if got := mappingNames(t, h, available, caller); !slices.Equal(got, before) {
		t.Fatalf("ordinary role names widened available from %v to %v", before, got)
	}
}
