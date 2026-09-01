package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authzScopePath is the family's prefix for one client UUID.
func authzScopePath(uuid string) string {
	return "/admin/realms/master/clients/" + uuid + "/authz/resource-server/scope"
}

// sendCT is send with an explicit Content-Type, including none at all. The
// header is what decides X-Frame-Options on every empty-bodied response on
// this family, so a helper that always set application/json could not see the
// rule.
func sendCT(t *testing.T, h http.Handler, method, path, token, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
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

// mkScope creates one scope and returns its id.
func mkScope(t *testing.T, h http.Handler, token, base, body string) string {
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

// TestScopeCreateIsAnUpsertAndItsKeyIsTheBodysID pins the five measured create
// bodies. The one that matters is the fourth: an id that names nothing plus a
// name that is taken is a **409**, which is what says the id is looked up
// first and alone rather than "id or name, whichever matches".
func TestScopeCreateIsAnUpsertAndItsKeyIsTheBodysID(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-upsert"))

	alpha := mkScope(t, h, admin, base, `{"name":"alpha"}`)
	if again := mkScope(t, h, admin, base, `{"name":"alpha"}`); again != alpha {
		t.Errorf("a duplicate name minted a new id: %s then %s", alpha, again)
	}

	// The half §1.9 of the first cut's handover did not record: the repeat
	// **writes** the body's other fields onto the row it found.
	mkScope(t, h, admin, base, `{"name":"alpha","displayName":"changed","iconUri":"http://i"}`)
	w := get(t, h, base+"/"+alpha, admin)
	if !strings.Contains(w.Body.String(), `"displayName":"changed"`) ||
		!strings.Contains(w.Body.String(), `"iconUri":"http://i"`) {
		t.Errorf("the repeat did not write the other fields: %s", w.Body)
	}

	// An id that names a scope wins outright and renames it.
	mkScope(t, h, admin, base, `{"id":"`+alpha+`","name":"totally-new"}`)
	if body := get(t, h, base+"/"+alpha, admin).Body.String(); !strings.Contains(body, `"name":"totally-new"`) {
		t.Errorf("the body's id did not win: %s", body)
	}

	// An id that names nothing plus a taken name is the 409, not an upsert
	// onto the name. This is the probe that tells the two rules apart.
	mkScope(t, h, admin, base, `{"name":"delta"}`)
	w = send(t, h, http.MethodPost, base, admin,
		`{"id":"99999999-9999-4999-8999-999999999999","name":"delta"}`)
	if w.Code != http.StatusConflict {
		t.Errorf("unknown id + taken name: got %d %s, want 409", w.Code, w.Body)
	}

	// An id is a free string, not a UUID.
	if id := mkScope(t, h, admin, base, `{"id":"zzz","name":"idshape"}`); id != "zzz" {
		t.Errorf("a non-UUID id was rewritten to %q", id)
	}

	// A name that is present and empty is a 201; only an absent name is the
	// 409, so the check is presence.
	if w := send(t, h, http.MethodPost, base, admin, `{"name":""}`); w.Code != http.StatusCreated {
		t.Errorf(`{"name":""}: got %d %s, want 201`, w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, base, admin, `{}`); w.Code != http.StatusConflict {
		t.Errorf(`{}: got %d %s, want 409`, w.Code, w.Body)
	}
}

// TestScopeCreateKeepsTheSecurityHeadersAndTheUpdateDropsThem is the sharpest
// pair this cut measured, and the one AGENTS.md's fifth security-header
// exception gets wrong.
//
// `POST .../scope` with `{}` and `PUT .../scope/{id}` with `{}` produce
// byte-identical 409 bodies from identical requests - same Content-Type, same
// resource server, one path segment apart - and disagree on all five headers.
// Both causes of each verb's 409 agree with each other, so it is decided per
// verb on this endpoint and not by the body, the cause or the status.
func TestScopeCreateKeepsTheSecurityHeadersAndTheUpdateDropsThem(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-409"))
	id := mkScope(t, h, admin, base, `{"name":"kept"}`)
	mkScope(t, h, admin, base, `{"name":"taken"}`)

	const wantBody = `{"error":"conflict","error_description":"Duplicate resource error"}`
	five := []string{"Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag"}

	for _, tc := range []struct {
		what   string
		method string
		path   string
		body   string
		want   bool
	}{
		{"create, no name", http.MethodPost, base, `{}`, true},
		{"create, unknown id + taken name", http.MethodPost, base,
			`{"id":"88888888-8888-4888-8888-888888888888","name":"taken"}`, true},
		{"update, no name", http.MethodPut, base + "/" + id, `{}`, false},
		{"update, name taken", http.MethodPut, base + "/" + id, `{"name":"taken"}`, false},
	} {
		w := send(t, h, tc.method, tc.path, admin, tc.body)
		if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != wantBody {
			t.Fatalf("%s: got %d %s, want 409 %s", tc.what, w.Code, w.Body, wantBody)
		}
		for _, name := range five {
			if got := w.Header().Get(name) != ""; got != tc.want {
				t.Errorf("%s: %s present = %v, want %v", tc.what, name, got, tc.want)
			}
		}
	}
}

// TestScopeListingSortsAndTheSettingsExportDoesNot is the two-orders
// assertion, and the fixture is built in the reverse of name order on purpose:
// a set created alphabetically passes a store that sorts and a store that does
// not.
func TestScopeListingSortsAndTheSettingsExportDoesNot(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-scope-order")
	base := authzScopePath(uuid)
	for _, n := range []string{"zulu", "yankee", "xray", "whiskey"} {
		mkScope(t, h, admin, base, `{"name":"`+n+`"}`)
	}

	names := func(body string) []string {
		var rows []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(body), &rows); err != nil {
			t.Fatalf("parse %s: %v", body, err)
		}
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.Name
		}
		return out
	}
	got := strings.Join(names(get(t, h, base, admin).Body.String()), ",")
	if want := "whiskey,xray,yankee,zulu"; got != want {
		t.Errorf("the listing is not sorted by name: %s, want %s", got, want)
	}

	var settings struct {
		Scopes []struct {
			Name string `json:"name"`
		} `json:"scopes"`
	}
	w := get(t, h, "/admin/realms/master/clients/"+uuid+"/authz/resource-server/settings", admin)
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatalf("parse settings %s: %v", w.Body, err)
	}
	var exported []string
	for _, s := range settings.Scopes {
		exported = append(exported, s.Name)
	}
	if got, want := strings.Join(exported, ","), "zulu,yankee,xray,whiskey"; got != want {
		t.Errorf("the settings export is not in creation order: %s, want %s", got, want)
	}

	// A delete and a recreate move the scope to the **end** of the export.
	id := mkScope(t, h, admin, base, `{"name":"xray"}`)
	if w := send(t, h, http.MethodDelete, base+"/"+id, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	mkScope(t, h, admin, base, `{"name":"xray"}`)
	w = get(t, h, "/admin/realms/master/clients/"+uuid+"/authz/resource-server/settings", admin)
	settings.Scopes = nil
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil {
		t.Fatalf("parse settings %s: %v", w.Body, err)
	}
	exported = nil
	for _, s := range settings.Scopes {
		exported = append(exported, s.Name)
	}
	if got, want := strings.Join(exported, ","), "zulu,yankee,whiskey,xray"; got != want {
		t.Errorf("after a delete and recreate: %s, want %s", got, want)
	}
}

// TestScopeSettingsExportStripsTheIDAndKeepsTheRest. One key differs between
// the export's entry and every other view of the same scope, and it is the id.
func TestScopeSettingsExportStripsTheIDAndKeepsTheRest(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-scope-export")
	base := authzScopePath(uuid)
	mkScope(t, h, admin, base, `{"name":"full","iconUri":"http://i","displayName":"DN"}`)

	w := get(t, h, "/admin/realms/master/clients/"+uuid+"/authz/resource-server/settings", admin)
	const want = `"scopes":[{"name":"full","iconUri":"http://i","displayName":"DN"}]`
	if !strings.Contains(w.Body.String(), want) {
		t.Errorf("settings scopes: %s, want a substring %s", w.Body, want)
	}
}

// TestScopeListingFiltersAndPaging. The two `name` parameters on this family
// mean different things and the pair is asserted together, because a shared
// matcher gets exactly one of them wrong.
func TestScopeListingFiltersAndPaging(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-filter"))
	ids := map[string]string{}
	for _, n := range []string{"Bravo", "alpha", "charlie", "delta", "ALPHAX"} {
		ids[n] = mkScope(t, h, admin, base, `{"name":"`+n+`"}`)
	}

	names := func(path string) string {
		var rows []struct {
			Name string `json:"name"`
		}
		w := get(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("parse %s: %v", w.Body, err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return strings.Join(out, ",")
	}

	for _, tc := range []struct{ query, want string }{
		// Byte-wise, so the two uppercase names sort before the lowercase ones.
		{"", "ALPHAX,Bravo,alpha,charlie,delta"},
		// A case-insensitive substring, all three ways.
		{"?name=alpha", "ALPHAX,alpha"},
		{"?name=ALPHA", "ALPHAX,alpha"},
		{"?name=lph", "ALPHAX,alpha"},
		{"?name=", "ALPHAX,Bravo,alpha,charlie,delta"},
		{"?name=nomatch", ""},
		// Either bound alone pages, which the role listings do not do.
		{"?first=1", "Bravo,alpha,charlie,delta"},
		{"?max=2", "ALPHAX,Bravo"},
		{"?first=1&max=2", "Bravo,alpha"},
		{"?first=-1&max=-1", "ALPHAX,Bravo,alpha,charlie,delta"},
		{"?first=100", ""},
		{"?max=0", ""},
		// scopeId is exact and is ANDed with name.
		{"?scopeId=" + ids["alpha"], "alpha"},
		{"?scopeId=00000000-0000-0000-0000-000000000000", ""},
		{"?scopeId=", "ALPHAX,Bravo,alpha,charlie,delta"},
		{"?name=delta&scopeId=" + ids["charlie"], ""},
		// The filter runs before the page.
		{"?name=a&max=1", "ALPHAX"},
	} {
		if got := names(base + tc.query); got != tc.want {
			t.Errorf("listing %q: got %q, want %q", tc.query, got, tc.want)
		}
	}
}

// TestScopeSearchIsExactAndCaseSensitive is the other half of the `name` pair.
// Two scopes differing only in case coexist and each is found by its own
// spelling alone, which no case-insensitive matcher can do.
func TestScopeSearchIsExactAndCaseSensitive(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-search"))
	upper := mkScope(t, h, admin, base, `{"name":"CaseTest"}`)
	lower := mkScope(t, h, admin, base, `{"name":"casetest"}`)
	mkScope(t, h, admin, base, `{"name":"Two Words"}`)

	for _, tc := range []struct {
		query  string
		status int
		id     string
	}{
		{"?name=CaseTest", http.StatusOK, upper},
		{"?name=casetest", http.StatusOK, lower},
		{"?name=Two%20Words", http.StatusOK, ""},
		{"?name=CASETEST", http.StatusNoContent, ""},
		{"?name=aseTes", http.StatusNoContent, ""},
		{"?name=nomatch", http.StatusNoContent, ""},
		{"?name=", http.StatusBadRequest, ""},
		{"", http.StatusBadRequest, ""},
	} {
		w := get(t, h, base+"/search"+tc.query, admin)
		if w.Code != tc.status {
			t.Errorf("search %q: got %d %s, want %d", tc.query, w.Code, w.Body, tc.status)
			continue
		}
		if tc.status != http.StatusOK {
			// A bare status with no body and no Content-Type - the 400 and the
			// 204 both carry Cache-Control and nothing else.
			if w.Body.Len() != 0 || w.Header().Get("Content-Type") != "" {
				t.Errorf("search %q: body %q, Content-Type %q, want neither",
					tc.query, w.Body, w.Header().Get("Content-Type"))
			}
			if w.Header().Get("Cache-Control") != "no-cache" {
				t.Errorf("search %q: Cache-Control %q, want no-cache", tc.query, w.Header().Get("Cache-Control"))
			}
			continue
		}
		// A bare object, not an array of one.
		if !strings.HasPrefix(w.Body.String(), "{") {
			t.Errorf("search %q: %s, want an object", tc.query, w.Body)
		}
		if tc.id != "" && !strings.Contains(w.Body.String(), `"id":"`+tc.id+`"`) {
			t.Errorf("search %q found the wrong scope: %s", tc.query, w.Body)
		}
	}
}

// TestScopeNotFoundIsTheAbsenceOfASpelling, and the Cache-Control on it splits
// by verb where AGENTS.md's rule for deletes says the verb explains nothing.
func TestScopeNotFoundIsTheAbsenceOfASpelling(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-404"))
	const missing = "/00000000-0000-0000-0000-000000000000"

	for _, tc := range []struct {
		what     string
		method   string
		path     string
		body     string
		noCache  bool
		wantCode int
	}{
		{"GET", http.MethodGet, base + missing, "", true, http.StatusNotFound},
		{"GET permissions", http.MethodGet, base + missing + "/permissions", "", true, http.StatusNotFound},
		{"GET resources", http.MethodGet, base + missing + "/resources", "", true, http.StatusNotFound},
		{"PUT", http.MethodPut, base + missing, `{"name":"x"}`, false, http.StatusNotFound},
		{"DELETE", http.MethodDelete, base + missing, "", false, http.StatusNotFound},
	} {
		w := send(t, h, tc.method, tc.path, admin, tc.body)
		if w.Code != tc.wantCode {
			t.Errorf("%s: got %d %s, want %d", tc.what, w.Code, w.Body, tc.wantCode)
			continue
		}
		if w.Body.Len() != 0 {
			t.Errorf("%s: body %q, want empty", tc.what, w.Body)
		}
		if ct := w.Header().Get("Content-Type"); ct != "" {
			t.Errorf("%s: Content-Type %q, want none", tc.what, ct)
		}
		if got := w.Header().Get("Cache-Control") == "no-cache"; got != tc.noCache {
			t.Errorf("%s: Cache-Control no-cache = %v, want %v", tc.what, got, tc.noCache)
		}
	}
}

// TestEmptyBodiedResponsesFollowTheRequestContentType. AGENTS.md records this
// rule for a 204 and names httpx.WriteNoContent as the one place that decides
// it. These are 404s, a 400 and a 204 on one family, and they agree - so the
// variable is the empty body rather than the status.
func TestEmptyBodiedResponsesFollowTheRequestContentType(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-xfo"))
	id := mkScope(t, h, admin, base, `{"name":"xfo"}`)
	const missing = "/00000000-0000-0000-0000-000000000000"

	for _, tc := range []struct {
		what        string
		method      string
		path        string
		contentType string
		body        string
		want        bool
	}{
		{"404 GET, no Content-Type", http.MethodGet, base + missing, "", "", false},
		{"404 GET, text/plain", http.MethodGet, base + missing, "text/plain", "", false},
		{"404 GET, application/json", http.MethodGet, base + missing, "application/json", "", true},
		{"404 DELETE, no Content-Type", http.MethodDelete, base + missing, "", "", false},
		{"404 DELETE, application/json", http.MethodDelete, base + missing, "application/json", "", true},
		{"400 search, no Content-Type", http.MethodGet, base + "/search", "", "", false},
		{"400 search, application/json", http.MethodGet, base + "/search", "application/json", "", true},
		{"204 search miss, no Content-Type", http.MethodGet, base + "/search?name=nope", "", "", false},
		{"204 DELETE success, no Content-Type", http.MethodDelete, base + "/" + id, "", "", false},
	} {
		w := sendCT(t, h, tc.method, tc.path, admin, tc.contentType, tc.body)
		if got := w.Header().Get("X-Frame-Options") != ""; got != tc.want {
			t.Errorf("%s: X-Frame-Options present = %v, want %v (status %d)",
				tc.what, got, tc.want, w.Code)
		}
	}
}

// TestScopeUpdateReplacesAndIgnoresTheBodysID. Both halves are measured and
// the second is the opposite of PUT .../protocol-mappers/models/{id}, which
// writes the mapper the body's id names.
func TestScopeUpdateReplacesAndIgnoresTheBodysID(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-put"))
	a := mkScope(t, h, admin, base, `{"name":"a","iconUri":"http://i","displayName":"DN"}`)
	b := mkScope(t, h, admin, base, `{"name":"b"}`)

	// Replace: a body with only a name drops the other two.
	if w := send(t, h, http.MethodPut, base+"/"+a, admin, `{"name":"a"}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if body := get(t, h, base+"/"+a, admin).Body.String(); strings.Contains(body, "iconUri") ||
		strings.Contains(body, "displayName") {
		t.Errorf("the PUT merged instead of replacing: %s", body)
	}
	// A 204 with no Cache-Control - the endpoint decides it, not the method.
	w := send(t, h, http.MethodPut, base+"/"+a, admin, `{"name":"a"}`)
	if cc := w.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("PUT 204 Cache-Control %q, want none", cc)
	}

	// The body's id is discarded: the path decides which row moves.
	if w := send(t, h, http.MethodPut, base+"/"+a, admin,
		`{"id":"`+b+`","name":"a-renamed"}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT with another id: %d %s", w.Code, w.Body)
	}
	if body := get(t, h, base+"/"+a, admin).Body.String(); !strings.Contains(body, `"name":"a-renamed"`) {
		t.Errorf("the path's scope did not move: %s", body)
	}
	if body := get(t, h, base+"/"+b, admin).Body.String(); !strings.Contains(body, `"name":"b"`) {
		t.Errorf("the body's scope moved: %s", body)
	}

	// Renaming to the name it already holds is a 204, not the 409.
	if w := send(t, h, http.MethodPut, base+"/"+b, admin, `{"name":"b"}`); w.Code != http.StatusNoContent {
		t.Errorf("renaming to its own name: %d %s", w.Code, w.Body)
	}
}

// TestScopeWriteOrderings pins the three adjacencies that decide what a
// request wrong in two ways answers.
func TestScopeWriteOrderings(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-order2"))
	id := mkScope(t, h, admin, base, `{"name":"here"}`)
	const missing = "/00000000-0000-0000-0000-000000000000"

	for _, tc := range []struct {
		what   string
		method string
		path   string
		body   string
		status int
		want   string
	}{
		// The strict decode runs before the scope lookup.
		{"PUT unknown scope, unknown field", http.MethodPut, base + missing, `{"name":"x","zzz":1}`,
			http.StatusBadRequest, `Unrecognized field \"zzz\"`},
		// ... and before the 409, on both verbs.
		{"POST unknown field and no name", http.MethodPost, base, `{"zzz":1}`,
			http.StatusBadRequest, `Unrecognized field \"zzz\"`},
		// The lookup runs before the name check.
		{"PUT unknown scope, no name", http.MethodPut, base + missing, `{}`,
			http.StatusNotFound, ""},
		{"PUT known scope, no name", http.MethodPut, base + "/" + id, `{}`,
			http.StatusConflict, "Duplicate resource error"},
		// A malformed body is the ordinary parse failure, and its code follows
		// the body's shape.
		{"POST malformed object", http.MethodPost, base, `{`,
			http.StatusBadRequest, `"invalid_request"`},
		{"POST malformed array", http.MethodPost, base, `[`,
			http.StatusBadRequest, `"unknown_error"`},
		// An empty body and a literal null are 500s on both verbs, where a
		// merely malformed one is a 400.
		{"POST null body", http.MethodPost, base, `null`,
			http.StatusInternalServerError, "consult the server log"},
		{"PUT null body", http.MethodPut, base + "/" + id, `null`,
			http.StatusInternalServerError, "consult the server log"},
	} {
		w := send(t, h, tc.method, tc.path, admin, tc.body)
		if w.Code != tc.status {
			t.Errorf("%s: got %d %s, want %d", tc.what, w.Code, w.Body, tc.status)
			continue
		}
		if tc.want != "" && !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: %s, want a substring %s", tc.what, w.Body, tc.want)
		}
	}

	// An empty body with no Content-Type at all is the same 500. send with an
	// empty body sends no Content-Type, which requireJSONBody allows.
	if w := sendCT(t, h, http.MethodPost, base, admin, "application/json", ""); w.Code != http.StatusInternalServerError {
		t.Errorf("POST empty body: got %d %s, want 500", w.Code, w.Body)
	}
	// A non-JSON Content-Type is the 415, and it precedes everything.
	if w := sendCT(t, h, http.MethodPost, base, admin, "text/plain", `{"name":"x"}`); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("POST text/plain: got %d %s, want 415", w.Code, w.Body)
	}
}

// TestScopeCreateEchoesPoliciesAndResources. The 201 is the request's
// representation with an id filled in, not a read: no other view of the same
// scope carries either key, and neither is stored.
func TestScopeCreateEchoesPoliciesAndResources(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-echo"))

	w := send(t, h, http.MethodPost, base,
		admin, `{"resources":[],"policies":[],"displayName":"DN","iconUri":"http://i","name":"all","id":"all-id"}`)
	// The measured field order, from a create that sent all six in reverse.
	const want = `{"id":"all-id","name":"all","iconUri":"http://i","policies":[],"resources":[],"displayName":"DN"}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("create body:\n got %s\nwant %s", got, want)
	}
	// Every other view omits both.
	const stored = `{"id":"all-id","name":"all","iconUri":"http://i","displayName":"DN"}`
	if got := strings.TrimSpace(get(t, h, base+"/all-id", admin).Body.String()); got != stored {
		t.Errorf("read back:\n got %s\nwant %s", got, stored)
	}
	// null is not [] - the key is absent rather than echoed.
	w = send(t, h, http.MethodPost, base, admin, `{"name":"nulls","policies":null,"resources":null}`)
	if strings.Contains(w.Body.String(), "policies") || strings.Contains(w.Body.String(), "resources") {
		t.Errorf("a null array was echoed: %s", w.Body)
	}
}

// TestScopeBoundThatDoesNotParseIsA404 pins the fourth producer of
// `{"error":"HTTP 404 Not Found"}`: a query parameter the description types as
// an integer that cannot bind, on a route the caller may use and a resource
// that exists.
func TestScopeBoundThatDoesNotParseIsA404(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-bound"))
	mkScope(t, h, admin, base, `{"name":"one"}`)

	for _, tc := range []struct {
		query  string
		status int
	}{
		{"?first=abc", http.StatusNotFound},
		{"?max=abc", http.StatusNotFound},
		{"?first=1.5", http.StatusNotFound},
		{"?first=999999999999999999999", http.StatusNotFound},
		// An empty value counts as absent, not as unparseable.
		{"?first=", http.StatusOK},
		{"?max=", http.StatusOK},
	} {
		w := get(t, h, base+tc.query, admin)
		if w.Code != tc.status {
			t.Errorf("%q: got %d %s, want %d", tc.query, w.Code, w.Body, tc.status)
			continue
		}
		if tc.status == http.StatusNotFound {
			if got := strings.TrimSpace(w.Body.String()); got != `{"error":"HTTP 404 Not Found"}` {
				t.Errorf("%q: body %s", tc.query, got)
			}
		}
	}
}

// TestScopeRoleSetsAreTheFamilysOwn. Seven callers over the eight routes, the
// way they were measured. query-clients is the cell that surprises: it is
// admitted by the client lookup on this very path and is 403 on every route
// under it.
func TestScopeRoleSetsAreTheFamilysOwn(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-roles"))
	id := mkScope(t, h, admin, base, `{"name":"guarded"}`)
	const missing = "/00000000-0000-0000-0000-000000000000"

	reads := []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodGet, base + "/" + id, ""},
		{http.MethodGet, base + "/search?name=guarded", ""},
		{http.MethodGet, base + "/" + id + "/permissions", ""},
		{http.MethodGet, base + "/" + id + "/resources", ""},
	}
	// The writes are aimed at a scope that does not exist so that an opened
	// route answers 404 and a refused one 403 - which is also what says the
	// role check runs **before** the scope lookup.
	writes := []struct{ method, path, body string }{
		{http.MethodPost, base, `{"name":"guarded"}`},
		{http.MethodPut, base + missing, `{"name":"x"}`},
		{http.MethodDelete, base + missing, ""},
	}

	for _, tc := range []struct {
		role     string
		mayRead  bool
		mayWrite bool
	}{
		{"", false, false},
		{"view-authorization", true, false},
		{"manage-authorization", true, true},
		{"view-clients", true, false},
		{"query-clients", false, false},
		{"manage-clients", true, true},
		{"manage-realm", false, false},
	} {
		var token string
		if tc.role == "" {
			token = tokenForRoles(t, h, s, realm)
		} else {
			token = tokenForRoles(t, h, s, realm, tc.role)
		}
		for _, req := range reads {
			w := send(t, h, req.method, req.path, token, req.body)
			if forbidden := w.Code == http.StatusForbidden; forbidden == tc.mayRead {
				t.Errorf("%s on %s %s: %d %s, mayRead=%v", tc.role, req.method, req.path, w.Code, w.Body, tc.mayRead)
			}
		}
		for _, req := range writes {
			w := send(t, h, req.method, req.path, token, req.body)
			if forbidden := w.Code == http.StatusForbidden; forbidden == tc.mayWrite {
				t.Errorf("%s on %s %s: %d %s, mayWrite=%v", tc.role, req.method, req.path, w.Code, w.Body, tc.mayWrite)
			}
		}
	}
}

// TestScopeGateCoversTheWholeFamily is the question the first cut left open:
// the gate was established on the resource server and nothing said whether
// every route under authz/resource-server shared it. All eight scope routes do,
// to a caller holding manage-authorization and to one holding nothing alike.
func TestScopeGateCoversTheWholeFamily(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	off := createClientWithBody(t, h, admin, `{"clientId":"gloak-t-scope-gate","enabled":true}`)
	base := authzScopePath(off)
	none := tokenForRoles(t, h, s, realm)
	manageAuthz := tokenForRoles(t, h, s, realm, "manage-authorization")
	const missing = "/00000000-0000-0000-0000-000000000000"
	const want = `{"error":"HTTP 404 Not Found"}`

	routes := []struct{ method, path, body string }{
		{http.MethodGet, base, ""},
		{http.MethodPost, base, `{"name":"x"}`},
		{http.MethodGet, base + "/search?name=x", ""},
		{http.MethodGet, base + missing, ""},
		{http.MethodPut, base + missing, `{"name":"x"}`},
		{http.MethodDelete, base + missing, ""},
		{http.MethodGet, base + missing + "/permissions", ""},
		{http.MethodGet, base + missing + "/resources", ""},
	}
	for name, token := range map[string]string{"none": none, "manage-authorization": manageAuthz, "admin": admin} {
		for _, req := range routes {
			w := send(t, h, req.method, req.path, token, req.body)
			if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
				t.Errorf("%s %s as %s: got %d %s, want 404 %s",
					req.method, req.path, name, w.Code, w.Body, want)
			}
		}
	}
}

// TestScopesAreScopedToTheirResourceServer. A name exists independently in two
// resource servers and an id is invisible from the other, both measured.
func TestScopesAreScopedToTheirResourceServer(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	one := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-rs1"))
	two := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-rs2"))

	id := mkScope(t, h, admin, one, `{"name":"alpha"}`)
	other := mkScope(t, h, admin, two, `{"name":"alpha"}`)
	if id == other {
		t.Fatalf("the two resource servers share one row: %s", id)
	}
	if w := get(t, h, two+"/"+id, admin); w.Code != http.StatusNotFound {
		t.Errorf("reading rs1's scope through rs2: %d %s, want 404", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, two+"/"+id, admin, ""); w.Code != http.StatusNotFound {
		t.Errorf("deleting rs1's scope through rs2: %d %s, want 404", w.Code, w.Body)
	}
	if w := get(t, h, one+"/"+id, admin); w.Code != http.StatusOK {
		t.Errorf("rs1's own scope after that: %d %s", w.Code, w.Body)
	}
}

// TestScopeSubListingsAnswerAnEmptyArray. The 404 is the half that is real
// behaviour today; the [] is the measured answer for a resource server with no
// permissions and no resources, which is every state Gloak can reach.
func TestScopeSubListingsAnswerAnEmptyArray(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	base := authzScopePath(createAuthzClient(t, h, admin, "gloak-t-scope-sub"))
	id := mkScope(t, h, admin, base, `{"name":"sub"}`)

	for _, suffix := range []string{"/permissions", "/resources"} {
		w := get(t, h, base+"/"+id+suffix, admin)
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Errorf("%s: got %d %s, want 200 []", suffix, w.Code, w.Body)
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: Cache-Control %q, want no-cache", suffix, w.Header().Get("Cache-Control"))
		}
	}
}

// TestTurningTheFlagOffDestroysTheScopes. The resource server's row is the
// client's authorizationServicesEnabled flag, and the scopes hang off it - so
// a PUT that omits the flag takes them with it, and turning it on again gives
// an empty resource server rather than the old one.
func TestTurningTheFlagOffDestroysTheScopes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	uuid := createAuthzClient(t, h, admin, "gloak-t-scope-flag")
	base := authzScopePath(uuid)
	mkScope(t, h, admin, base, `{"name":"doomed"}`)

	// A PUT that does not name the flag turns it off, which is the one field
	// on a client that does not merge.
	if w := send(t, h, http.MethodPut, "/admin/realms/master/clients/"+uuid, admin,
		`{"description":"touched"}`); w.Code != http.StatusNoContent {
		t.Fatalf("client PUT: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, base, admin); w.Code != http.StatusNotFound {
		t.Errorf("the scope listing after the flag went off: %d %s, want 404", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPut, "/admin/realms/master/clients/"+uuid, admin,
		`{"authorizationServicesEnabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("turning it back on: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, base, admin); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("the scopes survived the flag: %d %s, want 200 []", w.Code, w.Body)
	}
}
