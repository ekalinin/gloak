package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

const localizationBase = "/admin/realms/master/localization"

// sendTyped is send with the Content-Type spelled out, which the localization
// family needs: its PUT consumes text/plain and answers 415 to anything else.
func sendTyped(t *testing.T, h http.Handler, method, path, token, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestLocalizationMergeReproducesTheMeasuredOrders is the claim the whole
// family rests on: `POST .../localization/{locale}` re-buckets the merged
// document through a Java map and the other writes do not.
//
// The three vectors were read off a live 26.7.1 on 2026-09-03 as a sequence on
// one locale, so the insertion orders are real rather than constructed. Two of
// them share a key set with a different order, which is what says the answer is
// a function of the table size and not of the keys.
func TestLocalizationMergeReproducesTheMeasuredOrders(t *testing.T) {
	cases := []struct {
		name      string
		insertion []string
		want      []string
	}{
		{
			// k1..k5 stored, then a POST naming k6. Six entries, capacity 8.
			"five then one",
			[]string{"k1", "k2", "k3", "k4", "k5", "k6"},
			[]string{"k3", "k4", "k5", "k6", "k1", "k2"},
		},
		{
			// The same locale seven entries later, then a POST naming k9.
			// Eight entries, capacity 16 - and the order of the six they share
			// is not the order above.
			"seven then one",
			[]string{"k3", "k4", "k5", "k6", "k2", "k7", "k8", "k9"},
			[]string{"k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9"},
		},
		{
			// A different key set on a different realm, five entries, capacity 8.
			"four then two",
			[]string{"zz.key", "aa.key", "mm.key", "new.key", "qq.key"},
			[]string{"aa.key", "new.key", "qq.key", "zz.key", "mm.key"},
		},
	}
	separating := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := make([]model.LocalizationText, len(c.insertion))
			for i, k := range c.insertion {
				in[i] = model.LocalizationText{Key: k, Value: "v-" + k}
			}
			got := orderLocalizationMerge(in)
			keys := make([]string, len(got))
			for i, e := range got {
				keys[i] = e.Key
				if e.Value != "v-"+e.Key {
					t.Errorf("%s carries %q", e.Key, e.Value)
				}
			}
			if !slices.Equal(keys, c.want) {
				t.Errorf("got %v, want %v", keys, c.want)
			}
		})
		if !slices.Equal(javamap.KeyOrder(c.insertion), c.want) {
			separating++
		}
	}
	// javamap.KeyOrder is the obvious function to reach for here and it is the
	// wrong one: it sorts first and uses the no-argument constructor's table.
	// **Only two of these three vectors can tell the two apart** - the eight-key
	// one comes back sorted from both, because at that size the two tables agree
	// and the keys happen to sort into their own bucket order. Counting the
	// vectors that separate them is what stops the set drifting into a shape
	// where the swap would pass.
	if separating < 2 {
		t.Errorf("%d of %d vectors separate orderLocalizationMerge from javamap.KeyOrder; "+
			"want at least 2", separating, len(cases))
	}
}

// TestLocalizationWritesKeepTheDocumentsOrder walks the measured sequence
// through the served API, which is the half orderLocalizationMerge's unit test
// cannot see: which write runs it.
func TestLocalizationWritesKeepTheDocumentsOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	// A locale that does not exist yet keeps the request's own key order.
	if w := send(t, h, http.MethodPost, localizationBase+"/t1", admin,
		`{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5"}`); w.Code != http.StatusNoContent {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "t1", `{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5"}`)

	// A POST onto a locale that does exist re-buckets.
	if w := send(t, h, http.MethodPost, localizationBase+"/t1", admin,
		`{"k6":"6"}`); w.Code != http.StatusNoContent {
		t.Fatalf("second import: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "t1",
		`{"k3":"3","k4":"4","k5":"5","k6":"6","k1":"1","k2":"2"}`)

	// A PUT appends and moves nothing.
	if w := sendTyped(t, h, http.MethodPut, localizationBase+"/t1/k7", admin,
		"text/plain", "7"); w.Code != http.StatusNoContent {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "t1",
		`{"k3":"3","k4":"4","k5":"5","k6":"6","k1":"1","k2":"2","k7":"7"}`)

	// A DELETE removes and moves nothing. The surviving order is the
	// document's own and **not** what the same six keys would re-bucket to,
	// which is what makes this assertion worth making.
	if w := send(t, h, http.MethodDelete, localizationBase+"/t1/k1", admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete key: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "t1",
		`{"k3":"3","k4":"4","k5":"5","k6":"6","k2":"2","k7":"7"}`)

	// A PUT naming a key the document already holds replaces the value in
	// place.
	if w := sendTyped(t, h, http.MethodPut, localizationBase+"/t1/k2", admin,
		"text/plain", "two"); w.Code != http.StatusNoContent {
		t.Fatalf("put over: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "t1",
		`{"k3":"3","k4":"4","k5":"5","k6":"6","k2":"two","k7":"7"}`)
}

func assertLocalizationBody(t *testing.T, h http.Handler, token, locale, want string) {
	t.Helper()
	w := get(t, h, localizationBase+"/"+locale, token)
	if w.Code != http.StatusOK {
		t.Fatalf("read %s: %d %s", locale, w.Code, w.Body)
	}
	if got := w.Body.String(); got != want {
		t.Errorf("read %s:\n got %s\nwant %s", locale, got, want)
	}
}

// TestLocalizationImportThatChangesNothingReordersNothing is the rule the
// re-bucketing hangs off, and it is the one a handler gets wrong by being
// thorough: a POST whose body the document already holds writes no row, and a
// document that is not written keeps its bytes.
//
// Measured 2026-09-03 as three probes on one container: the same six pairs
// posted three times over never moved, the same six keys with **one value
// changed** came back re-bucketed, and five keys plus a sixth came back
// re-bucketed too. The three together are what separate "the POST re-orders"
// from "a write re-orders".
func TestLocalizationImportThatChangesNothingReordersNothing(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	const six = `{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5","k6":"6"}`

	for i := range 3 {
		if w := send(t, h, http.MethodPost, localizationBase+"/same", admin, six); w.Code != http.StatusNoContent {
			t.Fatalf("import %d: %d %s", i, w.Code, w.Body)
		}
		assertLocalizationBody(t, h, admin, "same", six)
	}

	// One value changed, and the whole document moves.
	if w := send(t, h, http.MethodPost, localizationBase+"/same", admin,
		`{"k3":"CHANGED"}`); w.Code != http.StatusNoContent {
		t.Fatalf("changing import: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "same",
		`{"k3":"CHANGED","k4":"4","k5":"5","k6":"6","k1":"1","k2":"2"}`)

	// A subset whose values already match writes nothing either, which is what
	// says the comparison is over the merged document rather than over the
	// request's own keys.
	if w := send(t, h, http.MethodPost, localizationBase+"/same", admin,
		`{"k5":"5"}`); w.Code != http.StatusNoContent {
		t.Fatalf("subset import: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "same",
		`{"k3":"CHANGED","k4":"4","k5":"5","k6":"6","k1":"1","k2":"2"}`)
}

// TestLocalizationEmptyBodyPoisonsTheLocale is Keycloak's own defect,
// reproduced: a POST with no body at all creates a locale nothing can read.
//
// The three reads and the two other writes answer 500 and the two deletes do
// not, which is five different call sites agreeing and two deliberately
// disagreeing - so the assertion is the whole grid rather than one cell.
func TestLocalizationEmptyBodyPoisonsTheLocale(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	// An empty object is the control: same verb, same route, a locale that
	// reads back.
	if w := send(t, h, http.MethodPost, localizationBase+"/ok", admin, `{}`); w.Code != http.StatusNoContent {
		t.Fatalf("empty object: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "ok", `{}`)

	if w := sendTyped(t, h, http.MethodPost, localizationBase+"/bad", admin,
		"application/json", ""); w.Code != http.StatusNoContent {
		t.Fatalf("empty body: %d %s", w.Code, w.Body)
	}

	// The locale is in the listing even though nothing can read it.
	w := get(t, h, localizationBase, admin)
	if got := w.Body.String(); got != `["bad","ok"]` {
		t.Errorf("listing: %s", got)
	}

	for _, probe := range []struct {
		name string
		w    *httptest.ResponseRecorder
	}{
		{"read the locale", get(t, h, localizationBase+"/bad", admin)},
		{"read a key", get(t, h, localizationBase+"/bad/anything", admin)},
		{"put a key", sendTyped(t, h, http.MethodPut, localizationBase+"/bad/k", admin, "text/plain", "v")},
		{"import over it", send(t, h, http.MethodPost, localizationBase+"/bad", admin, `{"k":"v"}`)},
	} {
		if probe.w.Code != http.StatusInternalServerError {
			t.Errorf("%s: %d %s, want 500", probe.name, probe.w.Code, probe.w.Body)
		}
	}

	// The two deletes are the way out, and they answer differently: the key
	// delete is the family's ordinary 404 and the locale delete works.
	if w := send(t, h, http.MethodDelete, localizationBase+"/bad/k", admin, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete a key of a poisoned locale: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, localizationBase+"/bad", admin, ""); w.Code != http.StatusNoContent {
		t.Errorf("delete the poisoned locale: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, localizationBase, admin); w.Body.String() != `["ok"]` {
		t.Errorf("listing after the delete: %s", w.Body)
	}
}

// TestLocalizationRefusals pins the five answers the family gives to a request
// it will not serve, each of which is a different shape.
func TestLocalizationRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPost, localizationBase+"/en", admin, `{"a":"b"}`); w.Code != http.StatusNoContent {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}

	// A locale nobody has written is a 200 on the read and a 404 on the
	// delete. One absence, two answers, decided by the verb.
	if w := get(t, h, localizationBase+"/nosuch", admin); w.Code != http.StatusOK || w.Body.String() != "{}" {
		t.Errorf("read of an unknown locale: %d %s", w.Code, w.Body)
	}
	w := send(t, h, http.MethodDelete, localizationBase+"/nosuch", admin, "")
	if w.Code != http.StatusNotFound ||
		w.Body.String() != `{"error":"No localization texts for locale nosuch found."}` {
		t.Errorf("delete of an unknown locale: %d %s", w.Code, w.Body)
	}

	// The key read and the key delete share one spelling, and it has no full
	// stop where the one above has one.
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		w := send(t, h, method, localizationBase+"/en/nosuch", admin, "")
		if w.Code != http.StatusNotFound ||
			w.Body.String() != `{"error":"Localization text not found"}` {
			t.Errorf("%s of an unknown key: %d %s", method, w.Code, w.Body)
		}
	}

	// **Two 400s on one route, and it is not the first byte that picks.** A
	// body that is not JSON is invalid_request; one that is JSON and is not an
	// object of scalars is unknown_error, whether it starts with `[` or `{`.
	for body, want := range map[string]string{
		"{":          `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`,
		"[]":         `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
		`{"n":{}}`:   `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
		`{"n":[1]}`:  `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`,
		`{"n":"x",}`: `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`,
	} {
		w := send(t, h, http.MethodPost, localizationBase+"/en", admin, body)
		if w.Code != http.StatusBadRequest || w.Body.String() != want {
			t.Errorf("import %q: %d %s", body, w.Code, w.Body)
		}
	}

	// A number and a boolean are coerced into strings and a null is dropped -
	// three answers to one question about a value's type.
	if w := send(t, h, http.MethodPost, localizationBase+"/coerce", admin,
		`{"num":123,"frac":1.5,"flag":true,"gone":null}`); w.Code != http.StatusNoContent {
		t.Fatalf("coercing import: %d %s", w.Code, w.Body)
	}
	assertLocalizationBody(t, h, admin, "coerce",
		`{"num":"123","frac":"1.5","flag":"true"}`)
}

// TestLocalizationPutConsumesPlainText pins the 415 over the nine spellings it
// was measured on. Four are accepted and four are refused, and the absent
// header is on the accepting side - which is the half a test sending only
// wrong values would miss.
func TestLocalizationPutConsumesPlainText(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	for _, ct := range []string{"text/plain", "text/plain;charset=UTF-8", "TEXT/PLAIN", "*/*", ""} {
		w := sendTyped(t, h, http.MethodPut, localizationBase+"/en/k", admin, ct, "v")
		if w.Code != http.StatusNoContent {
			t.Errorf("Content-Type %q: %d %s, want 204", ct, w.Code, w.Body)
		}
	}
	for _, ct := range []string{"application/json", "application/xml", "text/html", "application/octet-stream"} {
		w := sendTyped(t, h, http.MethodPut, localizationBase+"/en/k", admin, ct, "v")
		if w.Code != http.StatusUnsupportedMediaType ||
			w.Body.String() != `{"error":"The content-type header value did not match the value in @Consumes"}` {
			t.Errorf("Content-Type %q: %d %s, want 415", ct, w.Code, w.Body)
		}
	}
}

// TestLocalizationKeyReadIsPlainTextWithoutXFrameOptions is the header
// measurement, and it is a 2x2 rather than a single response.
//
// The request's Content-Type moves nothing here; the response's media type
// decides. That is the whole finding, and it needs both routes and both
// request headers to state.
func TestLocalizationKeyReadIsPlainTextWithoutXFrameOptions(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	if w := send(t, h, http.MethodPost, localizationBase+"/en", admin, `{"k":"a<b>c&d"}`); w.Code != http.StatusNoContent {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}

	for _, ct := range []string{"", "application/json", "text/plain"} {
		req := httptest.NewRequest(http.MethodGet, localizationBase+"/en/k", nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("key read with Content-Type %q: %d %s", ct, w.Code, w.Body)
		}
		if got := w.Header().Get("Content-Type"); got != "text/plain;charset=UTF-8" {
			t.Errorf("key read Content-Type %q: got %q", ct, got)
		}
		// The value is written raw: no JSON quoting, and no HTML escaping of
		// the three characters a custom marshaller would escape.
		if got := w.Body.String(); got != "a<b>c&d" {
			t.Errorf("key read body: %q", got)
		}
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("key read with Content-Type %q carries X-Frame-Options %q", ct, got)
		}
		if w.Header().Get("Cache-Control") != "" {
			t.Errorf("key read carries Cache-Control")
		}

		// The sibling read on the same family with the same request header
		// carries it, which is what says the request is not the variable.
		req = httptest.NewRequest(http.MethodGet, localizationBase+"/en", nil)
		req.Header.Set("Authorization", "Bearer "+admin)
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		w = httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
			t.Errorf("locale read with Content-Type %q: X-Frame-Options %q", ct, got)
		}
	}

	// And the same route's own 404 is application/json and does carry it: one
	// route, one verb, two media types, two header sets.
	w := get(t, h, localizationBase+"/en/nosuch", admin)
	if w.Code != http.StatusNotFound {
		t.Fatalf("404: %d", w.Code)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("the key read's 404 omits X-Frame-Options")
	}
}

// TestLocalizationDefaultLocaleFallback replays the sequence this behaviour was
// measured with on 2026-09-03, step for step, and asserts the bytes the server
// answered.
//
// The keys and the two-step seeding are the measurement's own: `k` is in both
// locales and is what says the requested locale wins, and each locale is built
// by two posts so that its stored order is the re-bucketed one rather than a
// request's.
func TestLocalizationDefaultLocaleFallback(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	for _, seed := range []struct{ locale, body string }{
		{"aa", `{"k":"aa"}`},
		{"zz", `{"k":"zz"}`},
		{"zz", `{"only.zz":"z"}`},
		{"aa", `{"only.aa":"a"}`},
	} {
		if w := send(t, h, http.MethodPost, localizationBase+"/"+seed.locale, admin,
			seed.body); w.Code != http.StatusNoContent {
			t.Fatalf("seed %s %s: %d %s", seed.locale, seed.body, w.Code, w.Body)
		}
	}
	assertLocalizationBody(t, h, admin, "aa", `{"only.aa":"a","k":"aa"}`)
	assertLocalizationBody(t, h, admin, "zz", `{"only.zz":"z","k":"zz"}`)

	// With no defaultLocale the parameter does nothing at all.
	assertLocalizationQuery(t, h, admin, "zz?useRealmDefaultLocaleFallback=true",
		`{"only.zz":"z","k":"zz"}`)

	if w := send(t, h, http.MethodPut, "/admin/realms/master", admin,
		`{"defaultLocale":"aa"}`); w.Code != http.StatusNoContent {
		t.Fatalf("set defaultLocale: %d %s", w.Code, w.Body)
	}

	// The requested locale wins on `k` and the default's own key is added, and
	// **the merged map is re-bucketed** rather than served in either
	// document's order. internationalizationEnabled is still off, which is
	// what says the fallback follows defaultLocale alone.
	assertLocalizationQuery(t, h, admin, "zz?useRealmDefaultLocaleFallback=true",
		`{"only.aa":"a","only.zz":"z","k":"zz"}`)
	assertLocalizationQuery(t, h, admin, "zz?useRealmDefaultLocaleFallback=false",
		`{"only.zz":"z","k":"zz"}`)
	assertLocalizationQuery(t, h, admin, "zz", `{"only.zz":"z","k":"zz"}`)
	// A locale that does not exist answers the default's texts outright.
	assertLocalizationQuery(t, h, admin, "nosuch?useRealmDefaultLocaleFallback=true",
		`{"only.aa":"a","k":"aa"}`)
	// The single-key read ignores the parameter, measured: it is a 404 for a
	// key only the default locale holds.
	if w := get(t, h, localizationBase+"/zz/only.aa?useRealmDefaultLocaleFallback=true", admin); w.Code != http.StatusNotFound {
		t.Errorf("the key read honoured the fallback: %d %s", w.Code, w.Body)
	}
}

func assertLocalizationQuery(t *testing.T, h http.Handler, token, suffix, want string) {
	t.Helper()
	w := get(t, h, localizationBase+"/"+suffix, token)
	if w.Code != http.StatusOK {
		t.Fatalf("read %s: %d %s", suffix, w.Code, w.Body)
	}
	if got := w.Body.String(); got != want {
		t.Errorf("read %s:\n got %s\nwant %s", suffix, got, want)
	}
}

// TestLocalizationGuards is the sweep, served: the three reads do not share one
// admission and the four writes take manage-realm alone.
func TestLocalizationGuards(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	if w := send(t, h, http.MethodPost, localizationBase+"/en", admin, `{"k":"v"}`); w.Code != http.StatusNoContent {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}

	viewRealm := tokenForRole(t, h, s, realm, "view-realm")
	viewUsers := tokenForRole(t, h, s, realm, "view-users")
	impersonation := tokenForRole(t, h, s, realm, "impersonation")
	nobody := tokenFor(t, h, mustCreateUserWithNoRoles(t, s, realm), "pw")
	createRealm := tokenForRealmRole(t, h, s, realm, "gloak-probe-loc-cr", "create-realm")

	// Every container role but impersonation opens all three reads.
	for _, token := range []string{viewRealm, viewUsers} {
		for _, path := range []string{localizationBase, localizationBase + "/en", localizationBase + "/en/k"} {
			if w := get(t, h, path, token); w.Code != http.StatusOK {
				t.Errorf("read %s: %d %s", path, w.Code, w.Body)
			}
		}
	}
	// impersonation and a caller holding nothing open none of them.
	for _, token := range []string{impersonation, nobody} {
		for _, path := range []string{localizationBase, localizationBase + "/en", localizationBase + "/en/k"} {
			if w := get(t, h, path, token); w.Code != http.StatusForbidden {
				t.Errorf("read %s by a caller that may not: %d %s", path, w.Code, w.Body)
			}
		}
	}

	// **The three reads do not share one admission, and a create-realm holder
	// is what separates them.** It owns no container at all, so
	// GET /admin/realms/{realm}'s guard admits it and the container's own role
	// set does not - measured on all three routes. Without this caller the two
	// guards are indistinguishable and swapping them passes.
	if w := get(t, h, localizationBase+"/en", createRealm); w.Code != http.StatusOK {
		t.Errorf("the locale read by a create-realm holder: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{localizationBase, localizationBase + "/en/k"} {
		if w := get(t, h, path, createRealm); w.Code != http.StatusForbidden {
			t.Errorf("%s by a create-realm holder: %d %s, want 403", path, w.Code, w.Body)
		}
	}

	// The writes take manage-realm alone: view-realm reads every one of them
	// and writes none.
	writes := []struct{ method, path, contentType, body string }{
		{http.MethodPost, localizationBase + "/en", "application/json", `{"a":"b"}`},
		{http.MethodPut, localizationBase + "/en/k", "text/plain", "v"},
		{http.MethodDelete, localizationBase + "/en/k", "", ""},
		{http.MethodDelete, localizationBase + "/en", "", ""},
	}
	for _, wr := range writes {
		if w := sendTyped(t, h, wr.method, wr.path, viewRealm, wr.contentType, wr.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s by view-realm: %d %s", wr.method, wr.path, w.Code, w.Body)
		}
	}
	manageRealm := tokenForRole(t, h, s, realm, "manage-realm")
	for _, wr := range writes {
		if w := sendTyped(t, h, wr.method, wr.path, manageRealm, wr.contentType, wr.body); w.Code != http.StatusNoContent {
			t.Errorf("%s %s by manage-realm: %d %s", wr.method, wr.path, w.Code, w.Body)
		}
	}
}

// mustCreateUserWithNoRoles is the "holding nothing" caller the guard sweep
// needs. It is a distinct username from every tokenForRole user so a failure
// names the right subject.
func mustCreateUserWithNoRoles(t *testing.T, s store.Store, realm *model.Realm) string {
	t.Helper()
	createUserWithPassword(t, s, realm, "gloak-probe-loc-nobody", "pw")
	return "gloak-probe-loc-nobody"
}

// tokenForRealmRole is tokenForRole for a **realm** role rather than a role on
// the realm's admin container. `create-realm` is one of the two that exist in
// master alone, and it is the caller that separates GET /admin/realms/{realm}'s
// admission from the container's own role set.
func tokenForRealmRole(t *testing.T, h http.Handler, s store.Store, realm *model.Realm, username, role string) string {
	t.Helper()
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, username, "pw")
	r, err := s.Roles().ByName(ctx, realm.ID, "", role)
	if err != nil {
		t.Fatalf("ByName(%s): %v", role, err)
	}
	if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
	return tokenFor(t, h, username, "pw")
}
