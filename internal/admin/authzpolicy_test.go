package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// authzPolicyPath and authzPermissionPath are the two spellings of one family's
// prefix for one client UUID. Every test below that cares about the difference
// asks both.
func authzPolicyPath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/policy"
}

func authzPermissionPath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/permission"
}

// mkPolicy creates one policy and returns its id.
func mkPolicy(t *testing.T, h http.Handler, token, base, body string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, base, token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", body, w.Code, w.Body)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse create response %s: %v", w.Body, err)
	}
	return got.ID
}

// TestPolicyGenericViewIsOneShapeForAllNineTypes is the measurement that sized
// the cut, asserted from the side the goldens cannot reach.
//
// One config carrying every provider's keys was sent to all nine types on a
// live 26.7.1 and **the generic view came back byte-identical on all nine** -
// the same thirteen keys in the same order. So `config` is stored and served
// without regard to the type, and everything per-type happens in the typed
// view. A serialiser that filtered the config by type would pass every
// single-type test and fail this one.
func TestPolicyGenericViewIsOneShapeForAllNineTypes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-shape")
	base := authzPolicyPath(uuid)

	// The three keys that are really associations are left out: they are
	// consumed on the way in and are a different measurement. The three
	// provider keys **are** in, so that no type has one added and every row
	// holds the same nine - which is what the byte-identical claim is about.
	// A set that let three of the nine grow would compare unequal for a reason
	// that is about the table size and not about the type.
	const config = `{"defaultResourceType":"urn:d","nbf":"2026-01-01 00:00:00",` +
		`"hour":"3","targetClaim":"tc","pattern":"^a$","targetContextAttributes":"true",` +
		`"roles":"[]","clients":"[]","groups":"[]"}`

	var first string
	for _, typ := range authzPolicyTypes {
		mkPolicy(t, h, admin, base, `{"name":"p-`+typ+`","type":"`+typ+`","config":`+config+`}`)
		body := get(t, h, base+"/search?name=p-"+typ, admin).Body.String()
		cut := strings.Index(body, `"config":`)
		if cut < 0 {
			t.Fatalf("%s: no config in %s", typ, body)
		}
		got := body[cut:]
		if first == "" {
			first = got
			continue
		}
		if got != first {
			t.Errorf("%s serialised its config differently:\n got %s\nwant %s", typ, got, first)
		}
	}
	if want := `"config":{"defaultResourceType":"urn:d","targetContextAttributes":"true",` +
		`"nbf":"2026-01-01 00:00:00","clients":"[]","hour":"3","roles":"[]",` +
		`"pattern":"^a$","groups":"[]","targetClaim":"tc"}}`; first != want {
		t.Errorf("the nine-key config order:\n got %s\nwant %s", first, want)
	}
}

// TestPolicyConfigTableSizeIsTheStoredCount pins the argument
// javamap.SizedKeyOrder is given, and it is the answer AGENTS.md's protocol
// mapper bullet does **not** predict.
//
// That bullet says a config the create grew "was built for the request's key
// count and serialised at a larger one". Here it is the other way round.
// Measured with a six-key config sent to a `uma` policy, which adds nothing,
// and to a `role` policy, which adds `roles`:
//
//	uma  6 sent, 6 stored   defaultResourceType targetContextAttributes
//	                        pattern targetClaim nbf hour
//	role 6 sent, 7 stored   defaultResourceType targetContextAttributes
//	                        nbf hour roles pattern targetClaim
//	uma  7 sent, 7 stored   the same as the row above, byte for byte
//
// The role policy's six-key request came back in the **seven**-key order, and
// the two orders differ - `pattern` and `targetClaim` move across `nbf` and
// `hour` - so the request's count is refuted rather than merely unpinned. The
// third cut's handover recorded this question as unanswerable; the vector that
// answers it fell out of the test above.
func TestPolicyConfigTableSizeIsTheStoredCount(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzPolicyPath(createAuthzClient(t, h, admin, "gloak-t-pol-size"))

	const six = `{"defaultResourceType":"urn:d","nbf":"2026-01-01 00:00:00",` +
		`"hour":"3","targetClaim":"tc","pattern":"^a$","targetContextAttributes":"true"}`
	const seven = `{"defaultResourceType":"urn:d","nbf":"2026-01-01 00:00:00",` +
		`"hour":"3","targetClaim":"tc","pattern":"^a$","targetContextAttributes":"true","roles":"[]"}`

	mkPolicy(t, h, admin, base, `{"name":"six","type":"uma","config":`+six+`}`)
	mkPolicy(t, h, admin, base, `{"name":"grown","type":"role","config":`+six+`}`)
	mkPolicy(t, h, admin, base, `{"name":"seven","type":"uma","config":`+seven+`}`)

	configOf := func(name string) string {
		t.Helper()
		body := get(t, h, base+"/search?name="+name, admin).Body.String()
		return body[strings.Index(body, `"config":`):]
	}
	sixKeys := `"config":{"defaultResourceType":"urn:d","targetContextAttributes":"true",` +
		`"pattern":"^a$","targetClaim":"tc","nbf":"2026-01-01 00:00:00","hour":"3"}}`
	sevenKeys := `"config":{"defaultResourceType":"urn:d","targetContextAttributes":"true",` +
		`"nbf":"2026-01-01 00:00:00","hour":"3","roles":"[]","pattern":"^a$","targetClaim":"tc"}}`
	if got := strings.TrimSpace(configOf("six")); got != sixKeys {
		t.Errorf("six keys:\n got %s\nwant %s", got, sixKeys)
	}
	if got := strings.TrimSpace(configOf("seven")); got != sevenKeys {
		t.Errorf("seven keys:\n got %s\nwant %s", got, sevenKeys)
	}
	// The one that decides: six sent, seven stored, and it is the seven-key
	// order that comes back.
	if got := strings.TrimSpace(configOf("grown")); got != sevenKeys {
		t.Errorf("a config the create grew:\n got %s\nwant %s", got, sevenKeys)
	}
	if sixKeys == sevenKeys {
		t.Fatal("the two orders are equal, so this test cannot separate them")
	}
}

// TestPolicyTypedViewProjectsOnlyTheTypesOwnKeys is the same probe read through
// the other view, and it is the assertion that there are **eight** field sets
// over nine types rather than one or nine.
//
// The config below carries every provider's keys at once, so a projection that
// emitted a field for a key belonging to another provider would be caught on
// eight of the nine rows.
func TestPolicyTypedViewProjectsOnlyTheTypesOwnKeys(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-typed")
	base, perm := authzPolicyPath(uuid), authzPermissionPath(uuid)

	const config = `{"defaultResourceType":"urn:d","nbf":"2026-01-01 00:00:00",` +
		`"hour":"3","targetClaim":"tc","pattern":"^a$","targetContextAttributes":"true",` +
		`"groupsClaim":"gc","fetchRoles":"true"}`

	want := map[string]string{
		// The subclass's fields come after decisionStrategy.
		"regex": `,"targetClaim":"tc","pattern":"^a$","targetContextAttributes":true}`,
		"role":  `,"roles":[],"fetchRoles":true}`,
		// `resourceType` is at the **base** position and is projected for these
		// two types alone, although every type stores the key.
		"resource":  `,"resourceType":"urn:d"}`,
		"scope":     `,"resourceType":"urn:d"}`,
		"client":    `,"clients":[]}`,
		"time":      `,"notBefore":"2026-01-01 00:00:00","hour":"3"}`,
		"group":     `,"groupsClaim":"gc","groups":[]}`,
		"aggregate": `"decisionStrategy":"UNANIMOUS"}`,
		// uma's `scopes` is ahead of `logic`, because it is a base field.
		"uma": `"type":"uma","scopes":[],"logic":"POSITIVE","decisionStrategy":"UNANIMOUS"}`,
	}
	for _, typ := range authzPolicyTypes {
		mkPolicy(t, h, admin, base, `{"name":"t-`+typ+`","type":"`+typ+`","config":`+config+`}`)
		body := strings.TrimSpace(get(t, h, perm+"/search?name=t-"+typ, admin).Body.String())
		if !strings.HasSuffix(body, want[typ]) {
			t.Errorf("%s typed view:\n got %s\nwant a suffix of %s", typ, body, want[typ])
		}
		if strings.Contains(body, `"config"`) {
			t.Errorf("%s typed view carried a config key: %s", typ, body)
		}
	}
}

// TestPolicyCreateIsTheRequestEchoed pins the three halves that say the 201 is
// not a read.
//
// A role create's config comes back exactly as it was sent where the read has
// the provider's own key added; `owner` and `resourceType` are echoed and no
// read serves either; and the association arrays are echoed as the **resolved**
// ids where the request named the targets.
func TestPolicyCreateIsTheRequestEchoed(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-echo")
	base := authzPolicyPath(uuid)
	scopeID := mkScope(t, h, admin, authzScopePath(uuid), `{"id":"esc","name":"esc"}`)

	w := send(t, h, http.MethodPost, base, admin,
		`{"id":"echoed","name":"e1","description":"D","type":"uma","logic":"NEGATIVE",`+
			`"decisionStrategy":"AFFIRMATIVE","owner":"o","resourceType":"urn:rt",`+
			`"scopes":["esc"],"policies":[],"config":{"zzz":"1"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	got := strings.TrimSpace(w.Body.String())
	want := `{"id":"echoed","name":"e1","description":"D","type":"uma","policies":[],` +
		`"scopes":["` + scopeID + `"],"logic":"NEGATIVE","decisionStrategy":"AFFIRMATIVE",` +
		`"owner":"o","resourceType":"urn:rt","config":{"zzz":"1"}}`
	if got != want {
		t.Errorf("the create's echo:\n got %s\nwant %s", got, want)
	}
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control: got %q", w.Header().Get("Cache-Control"))
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("the create sent a Location: %q", loc)
	}

	// And the read serves neither owner nor resourceType.
	read := strings.TrimSpace(get(t, h, base+"/search?name=e1", admin).Body.String())
	if strings.Contains(read, "owner") || strings.Contains(read, "resourceType") {
		t.Errorf("the read served owner or resourceType: %s", read)
	}

	// The role-shaped half of the same claim, and it needs a **role** create
	// **carrying a config**. A body with no config echoes `{}` whichever
	// source the echo reads, and a `uma` body's stored config equals its
	// request's - so neither can tell the two sources apart. This one can: the
	// request says two keys, the 201 says the same two, and the read says
	// three, because the role provider's key is written after the response
	// representation is built.
	//
	// `aa` and `bb` rather than a single `zz`, and that is the protocol
	// mappers' sidestep: `{roles, zzz}` is a key set `javamap.SizedKeyOrder`
	// places **wrongly** - the server answers `[roles, zzz]` from both request
	// orders and the model answers the request's - so a test built on it would
	// be asserting a known divergence. `{aa, bb, roles}` is measured and is
	// placed exactly.
	created := send(t, h, http.MethodPost, base, admin,
		`{"name":"e2","type":"role","config":{"aa":"1","bb":"2"}}`)
	if !strings.Contains(created.Body.String(), `"config":{"aa":"1","bb":"2"}}`) {
		t.Errorf("a role create's own 201 already had the provider's key: %s", created.Body)
	}
	back := get(t, h, base+"/search?name=e2", admin).Body.String()
	if !strings.Contains(back, `"config":{"aa":"1","bb":"2","roles":"[]"}`) {
		t.Errorf("the role provider's key was not added: %s", back)
	}
	// And the same with no config at all, which is where `{}` comes from.
	created = send(t, h, http.MethodPost, base, admin, `{"name":"e3","type":"role"}`)
	if !strings.Contains(created.Body.String(), `"config":{}`) {
		t.Errorf("a bare role create's 201: %s", created.Body)
	}
}

// TestPolicyCreateRefusalsRunInTheMeasuredOrder pins the seven refusals and the
// two adjacencies that surprise.
//
// Each row is a body wrong in **two** ways at once, which is the only kind of
// request that can tell an order from a coincidence: a set that breaks one
// thing at a time passes an implementation with the checks in any order.
func TestPolicyCreateRefusalsRunInTheMeasuredOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-refuse")
	base := authzPolicyPath(uuid)
	mkScope(t, h, admin, authzScopePath(uuid), `{"id":"rsc","name":"rsc"}`)
	mkPolicy(t, h, admin, base, `{"id":"takenid","name":"taken","type":"role"}`)

	const nameTaken = `{"error":"Policy with name [taken] already exists","error_description":"Conflicting policy"}`
	const duplicate = `{"error":"conflict","error_description":"Duplicate resource error"}`
	const parse = `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`
	const consult = `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`

	for _, tc := range []struct {
		what   string
		body   string
		status int
		want   string
	}{
		// 1. The unknown field is ahead of the taken name.
		{"an unknown field beside a taken name", `{"name":"taken","type":"role","zzz":1}`,
			http.StatusInternalServerError, parse},
		// 1. So is a bad enum, and the comparison is case-sensitive.
		{"a lower-case logic", `{"name":"free","type":"role","logic":"positive"}`,
			http.StatusInternalServerError, parse},
		// 2. The taken name is ahead of the type check...
		{"a taken name beside an unknown type", `{"name":"taken","type":"nope"}`,
			http.StatusConflict, nameTaken},
		// ...and ahead of the association resolution.
		{"a taken name beside an unknown scope", `{"name":"taken","type":"uma","scopes":["nope"]}`,
			http.StatusConflict, nameTaken},
		// 3. The association resolution is ahead of the presence check, which
		// is the adjacency nobody would guess.
		{"an unknown scope and no name at all", `{"type":"uma","scopes":["nope"]}`,
			http.StatusBadRequest, `{"error":"unknown_error"}`},
		// 3. And resources are resolved before scopes.
		{"an unknown resource beside an unknown scope",
			`{"name":"free","type":"resource","resources":["nope"],"scopes":["nope"]}`,
			http.StatusInternalServerError, consult},
		// 5. Presence, and it is a **name and a type**, not the type alone.
		{"a type and no name", `{"type":"role"}`, http.StatusConflict, duplicate},
		{"a name and no type", `{"name":"free"}`, http.StatusConflict, duplicate},
		{"a null name", `{"name":null,"type":"role"}`, http.StatusConflict, duplicate},
		// 6. The type, compared case-sensitively.
		{"an upper-case type", `{"name":"free","type":"ROLE"}`,
			http.StatusInternalServerError, consult},
		{"a type in the provider catalogue and not in the accepted set",
			`{"name":"free","type":"user"}`, http.StatusInternalServerError, consult},
		// 7. The id, last.
		{"a taken id under a free name", `{"id":"takenid","name":"free","type":"role"}`,
			http.StatusConflict, duplicate},
	} {
		w := send(t, h, http.MethodPost, base, admin, tc.body)
		if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("%s:\n got %d %s\nwant %d %s", tc.what, w.Code, w.Body, tc.status, tc.want)
		}
	}

	// An empty name is a 201, so absent and empty are two states.
	if w := send(t, h, http.MethodPost, base, admin, `{"name":"","type":"role"}`); w.Code != http.StatusCreated {
		t.Errorf("an empty name: got %d %s, want 201", w.Code, w.Body)
	}
	// **CONSENSUS is accepted here and is a 500 on PUT .../authz/resource-server.**
	if w := send(t, h, http.MethodPost, base, admin,
		`{"name":"cons","type":"role","decisionStrategy":"CONSENSUS"}`); w.Code != http.StatusCreated {
		t.Errorf("CONSENSUS: got %d %s, want 201", w.Code, w.Body)
	}
}

// TestPolicyCreateNameTakenKeepsTheFiveSecurityHeaders is the half of the
// duplicate-name claim that the body cannot carry.
//
// The create's 409 and the family's other 409 spell different bodies, so a
// mutation that swapped the writers is caught by the body alone - but the
// *header* claim needs its own assertion, and the third cut lost a mutation to
// exactly that gap on the resource family.
func TestPolicyCreateNameTakenKeepsTheFiveSecurityHeaders(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-409hdr")
	base := authzPolicyPath(uuid)
	mkPolicy(t, h, admin, base, `{"name":"dup","type":"role"}`)

	w := send(t, h, http.MethodPost, base, admin, `{"name":"dup","type":"role"}`)
	for _, name := range []string{
		"Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
		"X-Frame-Options", "X-Robots-Tag",
	} {
		if w.Header().Get(name) == "" {
			t.Errorf("the duplicate-name 409 dropped %s", name)
		}
	}
	// The presence 409 keeps them too, and it is the writer the protocol
	// mappers' helper would have dropped them from.
	w = send(t, h, http.MethodPost, base, admin, `{"type":"role"}`)
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("the presence 409 dropped X-Frame-Options")
	}
}

// TestPolicyUnusableBodiesHaveThreeAnswers pins the split that is the inverse
// of writeCannotParseJSON's.
//
// Eight inputs, three answers: `null` is the consult-log 500, a body beginning
// `{` is `invalid_request`, and everything else - empty, whitespace, `[`, `[]`,
// a string, a number, a literal - is `unknown_error`. The status is 500 on all
// eight where the endpoints writeCannotParseJSON serves answer 400.
func TestPolicyUnusableBodiesHaveThreeAnswers(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzPolicyPath(createAuthzClient(t, h, admin, "gloak-t-pol-bodies"))

	const parse = `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`
	const invalid = `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`
	const consult = `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`

	for _, tc := range []struct{ body, want string }{
		{"null", consult},
		{"{", invalid},
		{"", parse},
		{" ", parse},
		{"[", parse},
		{"[]", parse},
		{`"x"`, parse},
		{"5", parse},
		{"true", parse},
	} {
		w := send(t, h, http.MethodPost, base, admin, tc.body)
		if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("body %q:\n got %d %s\nwant 500 %s", tc.body, w.Code, w.Body, tc.want)
		}
	}
}

// TestPolicyListingFiltersAndOrders pins the eight comparisons and the sort,
// and every one of them is a different rule.
func TestPolicyListingFiltersAndOrders(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-list")
	base := authzPolicyPath(uuid)
	// **The id and the name have to differ**, or `?resource=` and `?scope=`
	// cannot tell a name match from an id match and a comparator that dropped
	// half of each would pass. The third cut lost a mutation to exactly this
	// shape on the resource listing's sort.
	scopeID := mkScope(t, h, admin, authzScopePath(uuid), `{"id":"lsc-id","name":"lsc-name"}`)
	resID := mkResource(t, h, admin, authzResourcePath(uuid), `{"_id":"lres-id","name":"lres-name"}`)

	mkPolicy(t, h, admin, base, `{"id":"p1","name":"zulu","type":"role"}`)
	mkPolicy(t, h, admin, base, `{"id":"p2","name":"yankee","type":"resource",`+
		`"resources":["lres-name"],"config":{"defaultResourceType":"urn:tt"}}`)
	mkPolicy(t, h, admin, base, `{"id":"p3","name":"xray","type":"time"}`)
	// **Zebra is what makes the sort an assertion**: it leads a byte-wise sort
	// and comes third under a case-folded one. The third cut lost a mutation to
	// a set that could not tell those apart.
	mkPolicy(t, h, admin, base, `{"id":"p4","name":"Zebra","type":"uma","scopes":["lsc-name"]}`)

	names := func(query string) []string {
		t.Helper()
		var rows []struct {
			Name string `json:"name"`
		}
		body := get(t, h, base+query, admin).Body.Bytes()
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatalf("parse %s: %v (%s)", query, err, body)
		}
		out := []string{}
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out
	}
	eq := func(what string, got, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v, want %v", what, got, want)
		}
	}

	eq("the byte-wise sort", names(""), []string{"Zebra", "xray", "yankee", "zulu"})
	eq("name is a case-insensitive substring", names("?name=XRA"), []string{"xray"})
	// `RA` alone would match `Zebra` too, which is what says the comparison is
	// a substring rather than a prefix.
	eq("name is not anchored", names("?name=RA"), []string{"Zebra", "xray"})
	// **type is a substring too**, which §1.9 records as exact.
	eq("type is a case-insensitive substring", names("?type=GG"), nil)
	eq("type finds a substring", names("?type=OL"), []string{"zulu"})
	eq("type=e spans the types holding an e", names("?type=e"),
		[]string{"xray", "yankee", "zulu"})
	eq("policyId is exact", names("?policyId=p3"), []string{"xray"})
	eq("resource by name", names("?resource=lres-name"), []string{"yankee"})
	eq("resource by id", names("?resource="+resID), []string{"yankee"})
	eq("scope by name", names("?scope=lsc-name"), []string{"Zebra"})
	eq("scope by id", names("?scope="+scopeID), []string{"Zebra"})
	// **resourceType is the one filter that does not fold case.**
	eq("resourceType exact", names("?resourceType=urn:tt"), []string{"yankee"})
	eq("resourceType is case-sensitive", names("?resourceType=urn:TT"), nil)
	eq("fields is declared and ignored", names("?fields=id"),
		[]string{"Zebra", "xray", "yankee", "zulu"})
	eq("either bound pages: max", names("?max=2"), []string{"Zebra", "xray"})
	eq("either bound pages: first", names("?first=3"), []string{"zulu"})
	eq("a negative bound means no bound", names("?first=-1&max=-1"),
		[]string{"Zebra", "xray", "yankee", "zulu"})
	eq("the filters are ANDed", names("?type=uma&name=ZE"), []string{"Zebra"})
}

// TestPolicyAndPermissionAreOneListingWithTwoViews is the probe that separates
// the family filter from the serialisation, which §1.9 records as the finding
// that sized this cut.
//
// `?permission=true` on the `/policy` path and the bare `/permission` path
// return the **same rows** and serialise them differently; `?permission=false`
// on `/permission` is ignored, because the route pins it.
func TestPolicyAndPermissionAreOneListingWithTwoViews(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-views")
	base, perm := authzPolicyPath(uuid), authzPermissionPath(uuid)
	mkPolicy(t, h, admin, base, `{"id":"v1","name":"arole","type":"role"}`)
	mkPolicy(t, h, admin, base, `{"id":"v2","name":"bres","type":"resource",`+
		`"config":{"defaultResourceType":"urn:v"}}`)

	// **The bare listing returns both families**, which is the state a two-way
	// predicate gets wrong and which every other assertion here is blind to:
	// `?permission=true`, `?permission=false` and the `/permission` path all
	// name a half, so only this request can see the whole.
	both := strings.TrimSpace(get(t, h, base, admin).Body.String())
	if !strings.Contains(both, "arole") || !strings.Contains(both, "bres") {
		t.Errorf("the bare listing dropped a family: %s", both)
	}
	filtered := strings.TrimSpace(get(t, h, base+"?permission=true", admin).Body.String())
	typed := strings.TrimSpace(get(t, h, perm, admin).Body.String())
	if want := `[{"id":"v2","name":"bres","type":"resource","logic":"POSITIVE",` +
		`"decisionStrategy":"UNANIMOUS","config":{"defaultResourceType":"urn:v"}}]`; filtered != want {
		t.Errorf("the generic view of the permission half:\n got %s\nwant %s", filtered, want)
	}
	if want := `[{"id":"v2","name":"bres","type":"resource","logic":"POSITIVE",` +
		`"decisionStrategy":"UNANIMOUS","resourceType":"urn:v"}]`; typed != want {
		t.Errorf("the typed view of the same row:\n got %s\nwant %s", typed, want)
	}
	// The route pins the filter: `permission=false` changes nothing here.
	if got := strings.TrimSpace(get(t, h, perm+"?permission=false", admin).Body.String()); got != typed {
		t.Errorf("permission=false was honoured on the /permission path: %s", got)
	}
	// And the other half of the partition is on /policy and nowhere else.
	if got := strings.TrimSpace(get(t, h, base+"?permission=false", admin).Body.String()); !strings.Contains(got, "arole") {
		t.Errorf("permission=false on /policy: %s", got)
	}
	// **The create does not restrict the type**: a role policy made through
	// /permission lands on /policy.
	mkPolicy(t, h, admin, perm, `{"id":"v3","name":"crole","type":"role"}`)
	if got := get(t, h, perm, admin).Body.String(); strings.Contains(got, "crole") {
		t.Errorf("a role policy created through /permission appeared in its listing: %s", got)
	}
	if got := get(t, h, base, admin).Body.String(); !strings.Contains(got, "crole") {
		t.Errorf("a role policy created through /permission is missing from /policy: %s", got)
	}
}

// TestPolicySearchIsExactCaseSensitiveAndUnfilteredByFamily pins all four
// answers of both spellings.
//
// **Neither search is filtered by family**, which is what makes
// `/permission/search` the only operation in the description that shows the
// typed representation of the six types the listing hides.
func TestPolicySearchIsExactCaseSensitiveAndUnfilteredByFamily(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-search")
	base, perm := authzPolicyPath(uuid), authzPermissionPath(uuid)
	mkPolicy(t, h, admin, base, `{"id":"s1","name":"solo","type":"role"}`)

	hit := get(t, h, base+"/search?name=solo", admin)
	if hit.Code != http.StatusOK || !strings.HasPrefix(hit.Body.String(), `{"id":"s1"`) {
		t.Errorf("the hit is not a bare object: %d %s", hit.Code, hit.Body)
	}
	if hit.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("the hit's Cache-Control: %q", hit.Header().Get("Cache-Control"))
	}
	for _, tc := range []struct {
		what   string
		query  string
		status int
	}{
		{"an uppercase name", "/search?name=SOLO", http.StatusNoContent},
		{"a prefix", "/search?name=sol", http.StatusNoContent},
		{"a substring", "/search?name=olo", http.StatusNoContent},
		{"an absent name", "/search", http.StatusBadRequest},
		{"an empty name", "/search?name=", http.StatusBadRequest},
	} {
		for _, prefix := range []string{base, perm} {
			w := get(t, h, prefix+tc.query, admin)
			if w.Code != tc.status || w.Body.Len() != 0 {
				t.Errorf("%s on %s: got %d %q, want %d and an empty body",
					tc.what, prefix, w.Code, w.Body, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-cache" {
				t.Errorf("%s on %s: Cache-Control %q", tc.what, prefix, w.Header().Get("Cache-Control"))
			}
		}
	}
	// The family bypass: a role policy through the permission spelling, typed.
	typed := strings.TrimSpace(get(t, h, perm+"/search?name=solo", admin).Body.String())
	if want := `{"id":"s1","name":"solo","type":"role","logic":"POSITIVE",` +
		`"decisionStrategy":"UNANIMOUS","roles":[]}`; typed != want {
		t.Errorf("a role policy through /permission/search:\n got %s\nwant %s", typed, want)
	}
}

// TestPolicyNullEnumStoresNothing pins the state a create can reach that no
// default covers.
//
// `{"logic":null}` is a 201 and the row reads back with **no `logic` key at
// all**, on the listing, the search and the typed view alike - so absent and
// null are two different stored states and only the first gets POSITIVE. An
// implementation with a plain string field and a default cannot express it.
func TestPolicyNullEnumStoresNothing(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-null")
	base, perm := authzPolicyPath(uuid), authzPermissionPath(uuid)
	mkPolicy(t, h, admin, base, `{"id":"n1","name":"nologic","type":"role","logic":null}`)
	mkPolicy(t, h, admin, base, `{"id":"n2","name":"nods","type":"role","decisionStrategy":null}`)

	if got := strings.TrimSpace(get(t, h, base+"/search?name=nologic", admin).Body.String()); got !=
		`{"id":"n1","name":"nologic","type":"role","decisionStrategy":"UNANIMOUS","config":{"roles":"[]"}}` {
		t.Errorf("a null logic: %s", got)
	}
	if got := strings.TrimSpace(get(t, h, base+"/search?name=nods", admin).Body.String()); got !=
		`{"id":"n2","name":"nods","type":"role","logic":"POSITIVE","config":{"roles":"[]"}}` {
		t.Errorf("a null decisionStrategy: %s", got)
	}
	if got := strings.TrimSpace(get(t, h, perm+"/search?name=nologic", admin).Body.String()); strings.Contains(got, "logic") &&
		!strings.Contains(got, "decisionStrategy") {
		t.Errorf("the typed view of a null logic: %s", got)
	}
}

// TestPolicyRolesAndGate sweeps the family's guard on all seven of this cut's
// routes.
//
// The role sets are the scope and resource families' and were re-measured here
// rather than carried over, which is the fourth time this repository has swept
// a role set that then agreed - and the reason to sweep is that the previous
// three cuts each found one cell that did not.
func TestPolicyRolesAndGate(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-roles")
	base, perm := authzPolicyPath(uuid), authzPermissionPath(uuid)
	imp := "/admin/realms/master/clients/" + uuid + "/authz/resource-server/import"

	reads := []string{base, base + "/search?name=x", perm, perm + "/search?name=x"}
	writes := []struct{ method, path, body string }{
		{http.MethodPost, base, `{"name":"g1","type":"role"}`},
		{http.MethodPost, perm, `{"name":"g2","type":"resource"}`},
		{http.MethodPost, imp, `{}`},
	}
	tokens := map[string]string{}
	for _, tc := range []struct {
		role     string
		mayRead  bool
		mayWrite bool
	}{
		{"view-authorization", true, false},
		{"manage-authorization", true, true},
		{"view-clients", true, false},
		{"query-clients", false, false},
		{"manage-clients", true, true},
		{"manage-realm", false, false},
		{"view-users", false, false},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		tokens[tc.role] = token
		for _, path := range reads {
			w := get(t, h, path, token)
			if forbidden := w.Code == http.StatusForbidden; forbidden == tc.mayRead {
				t.Errorf("%s reading %s: got %d", tc.role, path, w.Code)
			}
		}
		for _, wr := range writes {
			w := send(t, h, wr.method, wr.path, token, wr.body)
			if forbidden := w.Code == http.StatusForbidden; forbidden == tc.mayWrite {
				t.Errorf("%s writing %s: got %d %s", tc.role, wr.path, w.Code, w.Body)
			}
		}
	}

	// **The gate runs before the roles**: a client without authorization
	// services answers the generic 404 to every caller, including one holding
	// no admin role at all.
	plain := createClientWithBody(t, h, admin, `{"clientId":"gloak-t-pol-plain","enabled":true}`)
	off := "/admin/realms/master/clients/" + plain + "/authz/resource-server/policy"
	for _, token := range []string{admin, tokens["view-authorization"]} {
		w := get(t, h, off, token)
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("a client without authorization services: %d %s", w.Code, w.Body)
		}
	}
}

// TestPolicyListingBoundThatDoesNotParseIsA404 makes these the seventh and
// eighth listings measured answering the generic 404 for an unparseable bound.
func TestPolicyListingBoundThatDoesNotParseIsA404(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-pol-bound")
	for _, path := range []string{authzPolicyPath(uuid), authzPermissionPath(uuid)} {
		for _, query := range []string{"?first=abc", "?max=abc", "?first=1.5"} {
			w := get(t, h, path+query, admin)
			if w.Code != http.StatusNotFound ||
				strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
				t.Errorf("%s%s: got %d %s", path, query, w.Code, w.Body)
			}
		}
		// An empty value counts as absent rather than as unparseable.
		if w := get(t, h, path+"?first=", admin); w.Code != http.StatusOK {
			t.Errorf("%s?first=: got %d %s", path, w.Code, w.Body)
		}
	}
}
