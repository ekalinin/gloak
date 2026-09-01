package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// authzResourcePath is the family's prefix for one client UUID.
func authzResourcePath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/resource"
}

// mkResource creates one resource and returns its `_id`.
func mkResource(t *testing.T, h http.Handler, token, base, body string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, base, token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", body, w.Code, w.Body)
	}
	var got struct {
		ID string `json:"_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse create response %s: %v", w.Body, err)
	}
	return got.ID
}

// TestResourceRepresentationPutsTheIDInTheMiddle pins the measured field order
// and the present-or-absent split, both of which a struct can get wrong without
// any test noticing if the assertions parse JSON instead of reading bytes.
//
// **`_id` is between `attributes` and `uris`.** Every other representation in
// this package leads with its id, so a serialiser written from habit produces a
// body that reads correctly and is wrong.
func TestResourceRepresentationPutsTheIDInTheMiddle(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-res-order")
	base := authzResourcePath(uuid)

	id := mkResource(t, h, admin, base,
		`{"_id":"fixed-order","name":"r","displayName":"R","type":"urn:t",`+
			`"icon_uri":"http://i","ownerManagedAccess":true,"uris":["/a"],`+
			`"attributes":{"k1":["v1"]},"scopes":[{"name":"s1"}]}`)
	_ = id

	body := get(t, h, base+"/fixed-order", admin).Body.String()
	want := `{"name":"r","type":"urn:t","owner":{"id":"` + uuid + `","name":"gloak-t-res-order"},` +
		`"ownerManagedAccess":true,"displayName":"R","attributes":{"k1":["v1"]},` +
		`"_id":"fixed-order","uris":["/a"],"scopes":[{"id":`
	if !strings.HasPrefix(body, want) {
		t.Errorf("field order:\n got %s\nwant a prefix of %s", body, want)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), `"icon_uri":"http://i"}`) {
		t.Errorf("icon_uri is not last: %s", body)
	}

	// A resource with only a name: four keys always present, four dropped.
	mkResource(t, h, admin, base,
		`{"_id":"bare","name":"bare"}`)
	bare := strings.TrimSpace(get(t, h, base+"/bare", admin).Body.String())
	if want := `{"name":"bare","owner":{"id":"` + uuid + `","name":"gloak-t-res-order"},` +
		`"ownerManagedAccess":false,"attributes":{},"_id":"bare","uris":[]}`; bare != want {
		t.Errorf("the bare shape:\n got %s\nwant %s", bare, want)
	}
}

// TestResourceInlineScopeHasThreeShapes pins the finding that a scope inside a
// resource is **not** the scope family's body, and that the three places it
// appears carry three different key sets.
//
// Measured on one scope holding both an iconUri and a displayName: the inline
// copy drops the displayName, `/scopes` drops the iconUri too, and the settings
// export drops the id as well. A shared serialiser emits a key Keycloak does
// not, in three places at once.
func TestResourceInlineScopeHasThreeShapes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-res-scopes")
	base := authzResourcePath(uuid)
	scopeBase := authzScopePath(uuid)

	mkScope(t, h, admin, scopeBase, `{"id":"rich","name":"rich","iconUri":"http://si","displayName":"Rich"}`)
	mkResource(t, h, admin, base,
		`{"_id":"withrich","name":"withrich","scopes":[{"id":"rich"}]}`)

	inline := get(t, h, base+"/withrich", admin).Body.String()
	if !strings.Contains(inline, `"scopes":[{"id":"rich","name":"rich","iconUri":"http://si"}]`) {
		t.Errorf("the inline scope: %s", inline)
	}
	if strings.Contains(inline, "Rich") {
		t.Errorf("the inline scope carried a displayName: %s", inline)
	}

	sub := strings.TrimSpace(get(t, h, base+"/withrich/scopes", admin).Body.String())
	if sub != `[{"id":"rich","name":"rich"}]` {
		t.Errorf("/scopes: got %s", sub)
	}

	settings := get(t, h,
		"/admin/realms/master/clients/"+uuid+"/authz/resource-server/settings", admin).Body.String()
	if !strings.Contains(settings, `"scopes":[{"name":"rich"}]`) {
		t.Errorf("the export's inline scope: %s", settings)
	}
	// And the export drops `_id` and `owner` from the resource itself while
	// keeping everything else.
	if strings.Contains(settings, `"_id":"withrich"`) || strings.Contains(settings, `"owner"`) {
		t.Errorf("the export kept _id or owner: %s", settings)
	}
}

// TestResourceUrisAndAttributesKeepTheirMeasuredOrders is the collection-order
// assertion, and both halves are chosen so that a Go map or a sort would be
// caught.
//
// The key sets here have **no bucket collision**, which is what lets the
// goldens assert real bytes: `javamap.KeyOrder` places both exactly. A set that
// collides is a different measurement - the uri chain runs forwards and the
// attribute chain runs backwards - and lives in the handover as a vector,
// because internal/javamap was not this branch's to change.
func TestResourceUrisAndAttributesKeepTheirMeasuredOrders(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-collections"))

	// `/z, /a, /m` hash to buckets 11, 2 and 14 at capacity 16, so the answer
	// is `/a, /z, /m` - neither the request order nor a sort.
	mkResource(t, h, admin, base,
		`{"_id":"coll","name":"coll","uris":["/z","/a","/m"],`+
			`"attributes":{"k2":["b"],"k1":["a"]}}`)
	body := get(t, h, base+"/coll", admin).Body.String()
	if !strings.Contains(body, `"uris":["/a","/z","/m"]`) {
		t.Errorf("uris: %s", body)
	}
	// k1 and k2 land in buckets 6 and 7, so k1 comes first whichever order the
	// request used.
	if !strings.Contains(body, `"attributes":{"k1":["a"],"k2":["b"]}`) {
		t.Errorf("attributes: %s", body)
	}

	// A repeated uri collapses, because the field is a Java Set, and the
	// legacy singular `uri` folds into the same set.
	mkResource(t, h, admin, base,
		`{"_id":"dup","name":"dup","uris":["/a","/a"],"uri":"/a"}`)
	if body := get(t, h, base+"/dup", admin).Body.String(); !strings.Contains(body, `"uris":["/a"]`) {
		t.Errorf("a repeated uri did not collapse: %s", body)
	}

	// A scalar attribute value is coerced and an empty array drops the key.
	mkResource(t, h, admin, base,
		`{"_id":"coer","name":"coer","attributes":{"s":"v","e":[]}}`)
	if body := get(t, h, base+"/coer", admin).Body.String(); !strings.Contains(body, `"attributes":{"s":["v"]}`) {
		t.Errorf("coercion or the empty-array drop: %s", body)
	}
}

// TestResourceListingFiltersAndOrders pins the ten query parameters that are
// read and the two orders one set of rows has.
func TestResourceListingFiltersAndOrders(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-res-list")
	base := authzResourcePath(uuid)

	// Created in the reverse of name order, so the listing's sort and the
	// export's creation order cannot record the same bytes.
	mkResource(t, h, admin, base,
		`{"_id":"r-zulu","name":"zulu","type":"urn:TT"}`)
	mkResource(t, h, admin, base,
		`{"_id":"r-yank","name":"yankee","scopes":[{"name":"alpha"}]}`)
	mkResource(t, h, admin, base,
		`{"_id":"r-zebra","name":"Zebra","uris":["/one/two"]}`)

	names := func(query string) []string {
		t.Helper()
		w := get(t, h, base+query, admin)
		var got []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("parse %s: %v (%s)", query, err, w.Body)
		}
		out := make([]string, 0, len(got))
		for _, g := range got {
			out = append(out, g.Name)
		}
		return out
	}
	eq := func(what string, got, want []string) {
		t.Helper()
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v, want %v", what, got, want)
		}
	}

	// **Sorted by name, byte-wise**: `Zebra` leads because a capital sorts
	// before every lowercase letter, and a case-folded sort would put it
	// **second**. `Xray` was the first spelling here and it cannot tell the two
	// sorts apart - it leads under both - which is exactly the hole a mutation
	// found: folding case in the comparator left this test green.
	eq("the whole listing", names(""), []string{"Zebra", "yankee", "zulu"})
	eq("_id", names("?_id=r-zulu"), []string{"zulu"})
	// name is a case-insensitive substring; exactName makes it exact.
	eq("name substring", names("?name=EB"), []string{"Zebra"})
	eq("exactName", names("?name=Zebra&exactName=true"), []string{"Zebra"})
	eq("exactName on a substring", names("?name=ebra&exactName=true"), nil)
	// exactName with no name does nothing at all.
	eq("exactName alone", names("?exactName=true"), []string{"Zebra", "yankee", "zulu"})
	eq("type substring, folded", names("?type=urn:tt"), []string{"zulu"})
	eq("scope", names("?scope=ALPH"), []string{"yankee"})
	eq("owner by clientId", names("?owner=gloak-t-res-list"), []string{"Zebra", "yankee", "zulu"})
	eq("owner by uuid", names("?owner="+uuid), []string{"Zebra", "yankee", "zulu"})
	// The one filter that is not a substring of anything: it does not fold
	// case and it does not match a prefix.
	eq("owner folded", names("?owner=GLOAK-T-RES-LIST"), nil)
	eq("owner as a prefix", names("?owner=gloak-t-res"), nil)
	eq("uri exact", names("?uri=/one/two"), []string{"Zebra"})
	eq("uri as a prefix", names("?uri=/one"), nil)
	// Either bound alone pages.
	eq("max alone", names("?max=1"), []string{"Zebra"})
	eq("first alone", names("?first=2"), []string{"zulu"})
	// An unknown parameter is ignored.
	eq("an unknown parameter", names("?zzz=1"), []string{"Zebra", "yankee", "zulu"})

	// The export serves the same rows in **creation order**.
	settings := get(t, h,
		"/admin/realms/master/clients/"+uuid+"/authz/resource-server/settings", admin).Body.String()
	zulu, yankee := strings.Index(settings, `"name":"zulu"`), strings.Index(settings, `"name":"yankee"`)
	zebra := strings.Index(settings, `"name":"Zebra"`)
	if !(zulu < yankee && yankee < zebra) {
		t.Errorf("the export is not in creation order: %s", settings)
	}
}

// TestResourceDeepDropsTwoKeysAndOnlyOnTheListing pins the parameter that is
// easiest to implement as one key, and the two routes that ignore it.
func TestResourceDeepDropsTwoKeysAndOnlyOnTheListing(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-deep"))
	mkResource(t, h, admin, base,
		`{"_id":"deep","name":"deep","attributes":{"k":["v"]},"scopes":[{"name":"s"}]}`)

	shallow := get(t, h, base+"?deep=false", admin).Body.String()
	if strings.Contains(shallow, `"attributes"`) || strings.Contains(shallow, `"scopes"`) {
		t.Errorf("deep=false kept a key it drops: %s", shallow)
	}
	if !strings.Contains(shallow, `"uris":[]`) || !strings.Contains(shallow, `"owner"`) {
		t.Errorf("deep=false dropped a key it keeps: %s", shallow)
	}
	// Anything that is not the literal `false` is deep.
	if body := get(t, h, base+"?deep=abc", admin).Body.String(); !strings.Contains(body, `"attributes"`) {
		t.Errorf("deep=abc was read as false: %s", body)
	}
	// The single read and the search ignore it entirely.
	if body := get(t, h, base+"/deep?deep=false", admin).Body.String(); !strings.Contains(body, `"attributes"`) {
		t.Errorf("the read honoured deep: %s", body)
	}
	if body := get(t, h, base+"/search?name=deep&deep=false", admin).Body.String(); !strings.Contains(body, `"attributes"`) {
		t.Errorf("the search honoured deep: %s", body)
	}
}

// TestResourceMatchingUriIsABestMatch pins the modifier that is not a filter.
// Without it `uri` is equality; with it the most specific matching pattern in
// the whole set wins, and an exact registration beats a wildcard covering it.
func TestResourceMatchingUriIsABestMatch(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-uri"))
	mkResource(t, h, admin, base,
		`{"_id":"wild","name":"wild","uris":["/deep/*"]}`)
	mkResource(t, h, admin, base,
		`{"_id":"exact","name":"exact","uris":["/deep/a/b"]}`)

	only := func(query, want string) {
		t.Helper()
		var got []struct {
			Name string `json:"name"`
		}
		w := get(t, h, base+query, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("parse %s: %v", query, err)
		}
		if want == "" {
			if len(got) != 0 {
				t.Errorf("%s: got %v, want nothing", query, got)
			}
			return
		}
		if len(got) != 1 || got[0].Name != want {
			t.Errorf("%s: got %v, want %s alone", query, got, want)
		}
	}
	only("?uri=/deep/a/b/c&matchingUri=true", "wild")
	only("?uri=/deep/a/b&matchingUri=true", "exact")
	only("?uri=/deep/x&matchingUri=true", "wild")
	only("?uri=/one/two/three&matchingUri=true", "")
	only("?uri=/deep/a/b/c", "")
	// matchingUri with no uri does nothing rather than emptying the set.
	if w := get(t, h, base+"?matchingUri=true", admin); !strings.Contains(w.Body.String(), "wild") {
		t.Errorf("matchingUri with no uri emptied the listing: %s", w.Body)
	}
}

// TestResourceWriteRefusalsAndTheirTwo409s pins the refusal order and the pair
// of 409s that one condition answers on two verbs.
func TestResourceWriteRefusalsAndTheirTwo409s(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-refuse"))
	mkResource(t, h, admin, base,
		`{"_id":"taken","name":"taken"}`)

	// The strict decode runs first: ahead of the name gate, ahead of the
	// duplicate check and, on the PUT, ahead of the path's id.
	for _, c := range []struct{ what, path, body string }{
		{"unknown field alone", base, `{"name":"n","zzz":1}`},
		{"unknown field and no name", base, `{"zzz":1}`},
		{"unknown field and a taken name", base, `{"name":"taken","zzz":1}`},
	} {
		w := send(t, h, http.MethodPost, c.path, admin, c.body)
		if w.Code != http.StatusBadRequest ||
			!strings.Contains(w.Body.String(), "Unrecognized field \\\"zzz\\\"") {
			t.Errorf("%s: got %d %s", c.what, w.Code, w.Body)
		}
	}
	if w := send(t, h, http.MethodPut, base+"/nosuch", admin, `{"name":"n","zzz":1}`); w.Code != http.StatusBadRequest {
		t.Errorf("the PUT's decode is not ahead of its path: %d %s", w.Code, w.Body)
	}
	// But a good body addressed to an id that does not exist is the 404, so
	// the path is ahead of the name check.
	if w := send(t, h, http.MethodPut, base+"/nosuch", admin, `{}`); w.Code != http.StatusNotFound {
		t.Errorf("the PUT's path is not ahead of its name check: %d %s", w.Code, w.Body)
	}

	// One condition, two verbs, two bodies.
	w := send(t, h, http.MethodPost, base, admin, `{"name":"taken"}`)
	if w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "Resource with name [taken] already exists.") {
		t.Errorf("the create's duplicate name: %d %s", w.Code, w.Body)
	}
	mkResource(t, h, admin, base,
		`{"_id":"other","name":"other"}`)
	w = send(t, h, http.MethodPut, base+"/other", admin, `{"name":"taken"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Duplicate resource error") {
		t.Errorf("the update's duplicate name: %d %s", w.Code, w.Body)
	}
	// **And the two disagree about the five security headers**: the create's
	// keeps them and the update's drops them, on identical requests one path
	// segment apart.
	if send(t, h, http.MethodPost, base, admin, `{"name":"taken"}`).Header().Get("X-Frame-Options") == "" {
		t.Error("the create's 409 dropped the security headers")
	}
	if send(t, h, http.MethodPut, base+"/other", admin, `{"name":"taken"}`).
		Header().Get("X-Frame-Options") != "" {
		t.Error("the update's 409 kept the security headers")
	}

	// A body with no name: 409 on the create, 500 on the update. **The
	// create's carries the five security headers too**, which is what says
	// this 409 and the update's differ in the headers as well as the body -
	// asserting the body alone left a mutation swapping the two writers
	// alive, because both spell `Duplicate resource error`.
	if w := send(t, h, http.MethodPost, base, admin, `{}`); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "Duplicate resource error") ||
		w.Header().Get("X-Frame-Options") == "" {
		t.Errorf("the create with no name: %d %s %v", w.Code, w.Body, w.Header())
	}
	if w := send(t, h, http.MethodPut, base+"/other", admin, `{}`); w.Code != http.StatusInternalServerError {
		t.Errorf("the update with no name: %d %s", w.Code, w.Body)
	}
	// `{"name":null}` counts as no name on both.
	if w := send(t, h, http.MethodPost, base, admin, `{"name":null}`); w.Code != http.StatusConflict {
		t.Errorf("the create with a null name: %d %s", w.Code, w.Body)
	}

	// An empty body is a **400 with an empty body** on the create and a 500 on
	// the update - two writes on one resource server, opposite answers to
	// nothing at all, and the scope family answers the create's bytes with the
	// update's status.
	w = sendCT(t, h, http.MethodPost, base, admin, "application/json", "")
	if w.Code != http.StatusBadRequest || w.Body.Len() != 0 {
		t.Errorf("the create with an empty body: %d %q", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, base, admin, "null"); w.Code != http.StatusBadRequest ||
		w.Body.Len() != 0 {
		t.Errorf("the create with a null body: %d %q", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPut, base+"/other", admin, "null"); w.Code != http.StatusInternalServerError {
		t.Errorf("the update with a null body: %d %s", w.Code, w.Body)
	}

	// **Any owner is a 500 and it is checked ahead of the name**, measured in
	// both cells: an owner beside no name and an owner beside a taken name
	// both answer about the owner.
	for _, body := range []string{`{"owner":"o"}`, `{"name":"taken","owner":"o"}`,
		`{"name":"n","owner":{"id":"x","name":"y"}}`} {
		if w := send(t, h, http.MethodPost, base, admin, body); w.Code != http.StatusInternalServerError {
			t.Errorf("owner %s: got %d %s, want 500", body, w.Code, w.Body)
		}
	}
	// `null` counts as absent.
	if w := send(t, h, http.MethodPost, base, admin, `{"name":"ownernull","owner":null}`); w.Code != http.StatusCreated {
		t.Errorf("owner null: %d %s", w.Code, w.Body)
	}
}

// TestResourceCreateUpsertsOnTheIDAndNotOnTheName is the inverse of the scope
// family's rule, and both halves are the assertion.
func TestResourceCreateUpsertsOnTheIDAndNotOnTheName(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-upsert"))

	mkResource(t, h, admin, base,
		`{"_id":"mine","name":"first"}`)
	mkResource(t, h, admin, base,
		`{"_id":"mine","name":"second"}`)
	if body := get(t, h, base+"/mine", admin).Body.String(); !strings.Contains(body, `"name":"second"`) {
		t.Errorf("the second create did not overwrite: %s", body)
	}
	// Exactly one row survives.
	var listing []struct{}
	if err := json.Unmarshal(get(t, h, base, admin).Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing) != 1 {
		t.Errorf("the upsert made a second row: %d", len(listing))
	}
	// The body's id wins outright, so a caller may name it.
	if body := get(t, h, base+"/mine", admin).Body.String(); !strings.Contains(body, `"_id":"mine"`) {
		t.Errorf("the body's id did not win: %s", body)
	}
}

// TestResourcePutReplacesEverythingExceptAttributes is the family's one merge,
// and the case that says the exception is about absence rather than the field.
func TestResourcePutReplacesEverythingExceptAttributes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-put"))
	mkResource(t, h, admin, base,
		`{"_id":"full","name":"full","displayName":"D","type":"urn:t","icon_uri":"http://i",`+
			`"ownerManagedAccess":true,"uris":["/a"],"attributes":{"k":["v"]},"scopes":[{"name":"s"}]}`)

	if w := send(t, h, http.MethodPut, base+"/full", admin, `{"name":"full"}`); w.Code != http.StatusNoContent {
		t.Fatalf("the PUT: %d %s", w.Code, w.Body)
	}
	body := strings.TrimSpace(get(t, h, base+"/full", admin).Body.String())
	for _, gone := range []string{`"displayName"`, `"type"`, `"icon_uri"`, `"scopes"`, `"/a"`} {
		if strings.Contains(body, gone) {
			t.Errorf("the PUT kept %s: %s", gone, body)
		}
	}
	if strings.Contains(body, `"ownerManagedAccess":true`) {
		t.Errorf("the PUT kept ownerManagedAccess: %s", body)
	}
	// The one field a replace does not replace.
	if !strings.Contains(body, `"attributes":{"k":["v"]}`) {
		t.Errorf("the PUT dropped the attributes: %s", body)
	}
	// And `{}` does clear them, so the exception is about absence.
	if w := send(t, h, http.MethodPut, base+"/full", admin,
		`{"name":"full","attributes":{}}`); w.Code != http.StatusNoContent {
		t.Fatalf("the clearing PUT: %d %s", w.Code, w.Body)
	}
	if body := get(t, h, base+"/full", admin).Body.String(); !strings.Contains(body, `"attributes":{}`) {
		t.Errorf("`attributes:{}` did not clear them: %s", body)
	}
	// The body's `_id` is read and discarded; the path decides which row moves.
	mkResource(t, h, admin, base,
		`{"_id":"bystander","name":"bystander"}`)
	if w := send(t, h, http.MethodPut, base+"/full", admin,
		`{"_id":"bystander","name":"renamed"}`); w.Code != http.StatusNoContent {
		t.Fatalf("the PUT naming another id: %d %s", w.Code, w.Body)
	}
	if body := get(t, h, base+"/bystander", admin).Body.String(); !strings.Contains(body, `"name":"bystander"`) {
		t.Errorf("the body's id moved the wrong row: %s", body)
	}
	if body := get(t, h, base+"/full", admin).Body.String(); !strings.Contains(body, `"name":"renamed"`) {
		t.Errorf("the path's id did not move: %s", body)
	}
}

// TestResourceHasTwoNotFoundsOnePathSegmentApart is the finding this family is
// least likely to survive a shared helper.
//
// The read, the update and the delete answer the generic JSON body with no
// Cache-Control; `/attributes`, `/permissions` and `/scopes` answer an empty
// body **with** Cache-Control. Six routes, two answers, and the scope family
// next door answers its own single read the second way.
func TestResourceHasTwoNotFoundsOnePathSegmentApart(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-404"))

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, base + "/nosuch"},
		{http.MethodDelete, base + "/nosuch"},
	} {
		w := send(t, h, c.method, c.path, admin, "")
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "" {
			t.Errorf("%s %s carried a Cache-Control", c.method, c.path)
		}
	}
	if w := send(t, h, http.MethodPut, base+"/nosuch", admin, `{"name":"n"}`); w.Code != http.StatusNotFound ||
		strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
		t.Errorf("PUT on a missing resource: %d %s", w.Code, w.Body)
	}

	for _, suffix := range []string{"/attributes", "/permissions", "/scopes"} {
		w := get(t, h, base+"/nosuch"+suffix, admin)
		if w.Code != http.StatusNotFound || w.Body.Len() != 0 {
			t.Errorf("%s: %d %q", suffix, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s dropped the Cache-Control", suffix)
		}
		if w.Header().Get("Content-Type") != "" {
			t.Errorf("%s carried a Content-Type: %q", suffix, w.Header().Get("Content-Type"))
		}
	}
}

// TestResourceSearchIsExactAndCaseSensitive pins the three answers and the one
// difference from the listing's `name`.
func TestResourceSearchIsExactAndCaseSensitive(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-search"))
	mkResource(t, h, admin, base,
		`{"_id":"solo","name":"solo"}`)

	w := get(t, h, base+"/search?name=solo", admin)
	if w.Code != http.StatusOK || !strings.HasPrefix(strings.TrimSpace(w.Body.String()), `{"name":"solo"`) {
		t.Errorf("a hit: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Error("a hit dropped the Cache-Control")
	}
	for _, query := range []string{"?name=SOLO", "?name=sol"} {
		w := get(t, h, base+"/search"+query, admin)
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Errorf("%s: %d %q", query, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s dropped the Cache-Control", query)
		}
	}
	for _, query := range []string{"", "?name="} {
		w := get(t, h, base+"/search"+query, admin)
		if w.Code != http.StatusBadRequest || w.Body.Len() != 0 {
			t.Errorf("%q: %d %q", query, w.Code, w.Body)
		}
	}
}

// TestResourceScopeRefsResolveTheIDFirst pins the three ways a `scopes` entry
// is read, including the one that is a 409.
func TestResourceScopeRefsResolveTheIDFirst(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-res-refs")
	base, scopeBase := authzResourcePath(uuid), authzScopePath(uuid)
	mkScope(t, h, admin, scopeBase, `{"id":"known","name":"known"}`)

	// A name nobody holds creates the scope.
	mkResource(t, h, admin, base,
		`{"_id":"byname","name":"byname","scopes":[{"name":"minted"}]}`)
	if body := get(t, h, scopeBase, admin).Body.String(); !strings.Contains(body, `"name":"minted"`) {
		t.Errorf("a scope named in a resource was not created: %s", body)
	}
	// An id that resolves wins over a name naming something else.
	mkResource(t, h, admin, base,
		`{"_id":"byid","name":"byid","scopes":[{"id":"known","name":"minted"}]}`)
	if body := get(t, h, base+"/byid", admin).Body.String(); !strings.Contains(body, `"id":"known"`) ||
		strings.Contains(body, "minted") {
		t.Errorf("the id did not win: %s", body)
	}
	// An id that resolves to nothing is the 409, not a fall-through.
	if w := send(t, h, http.MethodPost, base,
		admin, `{"name":"bad","scopes":[{"id":"nosuchscope"}]}`); w.Code != http.StatusConflict {
		t.Errorf("an unknown scope id: %d %s", w.Code, w.Body)
	}
	// `resource_scopes` is an alias and it **wins** when both are sent.
	mkResource(t, h, admin, base,
		`{"_id":"alias","name":"alias","scopes":[{"name":"minted"}],`+
			`"resource_scopes":[{"id":"known"}]}`)
	if body := get(t, h, base+"/alias", admin).Body.String(); !strings.Contains(body, `"id":"known"`) ||
		strings.Contains(body, "minted") {
		t.Errorf("resource_scopes did not win: %s", body)
	}
}

// TestScopeResourcesListsTheResourcesNamingIt is the fix to a route the second
// cut shipped answering `[]` unconditionally. Its entry is two keys with the
// **name first**, which is the only body in this API shaped that way.
func TestScopeResourcesListsTheResourcesNamingIt(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-scope-res")
	base, scopeBase := authzResourcePath(uuid), authzScopePath(uuid)
	mkScope(t, h, admin, scopeBase, `{"id":"sc","name":"sc"}`)
	mkScope(t, h, admin, scopeBase, `{"id":"other","name":"other"}`)
	mkResource(t, h, admin, base,
		`{"_id":"r1","name":"zulu","scopes":[{"id":"sc"}]}`)
	mkResource(t, h, admin, base,
		`{"_id":"r2","name":"alpha","scopes":[{"id":"other"}]}`)
	mkResource(t, h, admin, base,
		`{"_id":"r3","name":"mike","scopes":[{"id":"sc"}]}`)

	// Creation order, not name order, and only the two naming `sc`.
	if got := strings.TrimSpace(get(t, h, scopeBase+"/sc/resources", admin).Body.String()); got !=
		`[{"name":"zulu","_id":"r1"},{"name":"mike","_id":"r3"}]` {
		t.Errorf("/scope/sc/resources: %s", got)
	}
	// The permissions route beside it still answers [] and that is the store's
	// truth rather than a stub.
	if got := strings.TrimSpace(get(t, h, scopeBase+"/sc/permissions", admin).Body.String()); got != "[]" {
		t.Errorf("/scope/sc/permissions: %s", got)
	}
}

// TestResourceRolesAndGate pins the two guards this family shares with its
// neighbours, because sharing them was measured rather than assumed.
func TestResourceRolesAndGate(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-res-roles")
	base := authzResourcePath(uuid)
	mkResource(t, h, admin, base,
		`{"_id":"one","name":"one"}`)

	reads := []string{base, base + "/search?name=one", base + "/one",
		base + "/one/attributes", base + "/one/permissions", base + "/one/scopes"}
	// One user per role, minted once: tokenForRoles names the user after the
	// roles it is given, so asking twice for the same one is a store conflict.
	tokens := map[string]string{}
	for _, role := range []string{"view-authorization", "manage-authorization", "view-clients",
		"manage-clients", "query-clients", "manage-realm", "view-users"} {
		tokens[role] = tokenForRoles(t, h, s, realm, role)
	}
	for _, role := range []string{"view-authorization", "manage-authorization", "view-clients", "manage-clients"} {
		token := tokens[role]
		for _, path := range reads {
			if w := get(t, h, path, token); w.Code != http.StatusOK {
				t.Errorf("%s reading %s: %d", role, path, w.Code)
			}
		}
	}
	for _, role := range []string{"query-clients", "manage-realm", "view-users"} {
		token := tokens[role]
		for _, path := range reads {
			if w := get(t, h, path, token); w.Code != http.StatusForbidden {
				t.Errorf("%s reading %s: %d, want 403", role, path, w.Code)
			}
		}
	}
	// The writes take the narrower pair, and **the role check precedes the
	// resource lookup**: a viewer deleting an id that does not exist is 403
	// where a manager is 404.
	viewer := tokens["view-authorization"]
	if w := send(t, h, http.MethodDelete, base+"/nosuch", viewer, ""); w.Code != http.StatusForbidden {
		t.Errorf("a viewer deleting a missing resource: %d, want 403", w.Code)
	}
	manager := tokens["manage-authorization"]
	if w := send(t, h, http.MethodDelete, base+"/nosuch", manager, ""); w.Code != http.StatusNotFound {
		t.Errorf("a manager deleting a missing resource: %d, want 404", w.Code)
	}

	// The gate covers all nine routes on a client without the flag, and it
	// runs before the roles - a caller holding nothing gets the 404 too.
	off := authzResourcePath(createClientWithBody(t, h, admin, `{"clientId":"gloak-t-res-off","enabled":true}`))
	none := tokenForRoles(t, h, s, realm)
	for _, token := range []string{admin, none} {
		for _, c := range []struct{ method, path, body string }{
			{http.MethodGet, off, ""},
			{http.MethodPost, off, `{"name":"n"}`},
			{http.MethodGet, off + "/search?name=n", ""},
			{http.MethodGet, off + "/x", ""},
			{http.MethodPut, off + "/x", `{"name":"n"}`},
			{http.MethodDelete, off + "/x", ""},
			{http.MethodGet, off + "/x/attributes", ""},
			{http.MethodGet, off + "/x/permissions", ""},
			{http.MethodGet, off + "/x/scopes", ""},
		} {
			w := send(t, h, c.method, c.path, token, c.body)
			if w.Code != http.StatusNotFound ||
				strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
				t.Errorf("the gate on %s %s: %d %s", c.method, c.path, w.Code, w.Body)
			}
		}
	}
}

// TestResourceListingBoundThatDoesNotParseIsA404 keeps authzIntBound's rule
// pinned on a sixth listing.
func TestResourceListingBoundThatDoesNotParseIsA404(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzResourcePath(createAuthzClient(t, h, admin, "gloak-t-res-bound"))
	for _, query := range []string{"?first=abc", "?max=abc", "?first=1.5"} {
		w := get(t, h, base+query, admin)
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("%s: %d %s", query, w.Code, w.Body)
		}
	}
	// An empty value counts as absent rather than as unparseable.
	if w := get(t, h, base+"?first=", admin); w.Code != http.StatusOK {
		t.Errorf("?first= : %d %s", w.Code, w.Body)
	}
}
