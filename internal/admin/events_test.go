package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const eventsConfigPath = "/admin/realms/master/events/config"

// The rejection table below goes through authzscope_test.go's sendCT, which
// already spells the Content-Type out including absence. That matters here for
// the reason it mattered there and for one more: the hand probe that first
// reported "no Content-Type is a 415" on this endpoint was `curl -d`, which
// sets application/x-www-form-urlencoded of its own accord, so it measured that
// value and called it absence. A genuinely absent header is accepted.

func eventsConfigOfRealm(t *testing.T, h http.Handler, token string) map[string]any {
	t.Helper()
	w := get(t, h, eventsConfigPath, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET events/config: %d %s", w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse events/config: %v", err)
	}
	return out
}

// TestFreshEventsConfigIsTheMeasuredBody pins the five keys, their order and the
// 103-name default list a realm that has never been written answers.
//
// The body was measured byte-identical on master and on a realm created through
// POST /admin/realms - 2739 bytes, cmp-verified - so nothing in it is derived
// from the realm, and eventsExpiration is absent rather than zero.
func TestFreshEventsConfigIsTheMeasuredBody(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := get(t, h, eventsConfigPath, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json;charset=UTF-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control %q, want no-cache", cc)
	}
	body := strings.TrimSpace(w.Body.String())
	if strings.Contains(body, `"eventsExpiration"`) {
		t.Errorf("eventsExpiration is present on a fresh realm: %s", body[:120])
	}
	keys := []string{
		`"eventsEnabled":`, `"eventsListeners":`, `"enabledEventTypes":`,
		`"adminEventsEnabled":`, `"adminEventsDetailsEnabled":`,
	}
	at := -1
	for _, k := range keys {
		i := strings.Index(body, k)
		if i <= at {
			t.Fatalf("%s is at %d, out of order", k, i)
		}
		at = i
	}
	cfg := eventsConfigOfRealm(t, h, admin)
	types, _ := cfg["enabledEventTypes"].([]any)
	if len(types) != 103 {
		t.Errorf("enabledEventTypes has %d names, want 103", len(types))
	}
	if len(types) > 0 && types[0] != "LOGIN" {
		t.Errorf("the list starts %v, want LOGIN - it is enum declaration order, not sorted", types[0])
	}
	if len(defaultEnabledEventTypes) != 103 {
		t.Errorf("defaultEnabledEventTypes holds %d, want 103", len(defaultEnabledEventTypes))
	}
	if len(eventTypeNames) != 132 || len(resourceTypeNames) != 39 || len(operationTypeNames) != 4 {
		t.Errorf("enum sizes %d/%d/%d, want 132/39/4",
			len(eventTypeNames), len(resourceTypeNames), len(operationTypeNames))
	}
}

// TestRealmRepAndEventsConfigDisagreeOnTheEmptyTypeList is the one cell where
// the two views of this state differ, and it is the state every default realm is
// in.
//
// GET /admin/realms/{realm} answers `enabledEventTypes: []` while
// GET .../events/config answers the 103 defaults - measured on master and on a
// fresh created realm. Write a non-empty list and both views agree again, which
// is what says the expansion is the read's and not the store's.
func TestRealmRepAndEventsConfigDisagreeOnTheEmptyTypeList(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	var realm map[string]any
	w := get(t, h, "/admin/realms/master", admin)
	if err := json.Unmarshal(w.Body.Bytes(), &realm); err != nil {
		t.Fatalf("parse realm: %v", err)
	}
	if got, _ := realm["enabledEventTypes"].([]any); len(got) != 0 {
		t.Errorf("the realm representation lists %d types, want []", len(got))
	}
	if got, _ := eventsConfigOfRealm(t, h, admin)["enabledEventTypes"].([]any); len(got) != 103 {
		t.Errorf("events/config lists %d types, want 103", len(got))
	}

	if w := send(t, h, http.MethodPut, eventsConfigPath, admin,
		`{"enabledEventTypes":["LOGIN","LOGOUT"]}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	w = get(t, h, "/admin/realms/master", admin)
	if err := json.Unmarshal(w.Body.Bytes(), &realm); err != nil {
		t.Fatalf("parse realm: %v", err)
	}
	fromRealm, _ := realm["enabledEventTypes"].([]any)
	fromConfig, _ := eventsConfigOfRealm(t, h, admin)["enabledEventTypes"].([]any)
	if len(fromRealm) != 2 || len(fromConfig) != 2 {
		t.Fatalf("after a write: realm %v, config %v - both should be the two names", fromRealm, fromConfig)
	}
	for i := range fromRealm {
		if fromRealm[i] != fromConfig[i] {
			t.Errorf("the two views disagree on a non-empty list: %v against %v", fromRealm, fromConfig)
		}
	}
	// The Java HashSet order, not the request's: LOGOUT before LOGIN, from both
	// insertion orders on the server.
	if fromConfig[0] != "LOGOUT" || fromConfig[1] != "LOGIN" {
		t.Errorf("got %v, want [LOGOUT LOGIN] - javamap.KeyOrder's order", fromConfig)
	}
}

// TestEventsConfigPutReplacesTwoAndMergesFour is the split a shared merge helper
// gets wrong in whichever direction it is written.
//
// Measured with a `PUT {}` on a realm carrying six non-default values: it reset
// eventsEnabled and eventsExpiration and left the other four exactly as they
// were.
func TestEventsConfigPutReplacesTwoAndMergesFour(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	full := `{"eventsEnabled":true,"eventsExpiration":900,"eventsListeners":["email"],` +
		`"enabledEventTypes":["LOGIN","LOGOUT"],"adminEventsEnabled":true,` +
		`"adminEventsDetailsEnabled":true}`
	if w := send(t, h, http.MethodPut, eventsConfigPath, admin, full); w.Code != http.StatusNoContent {
		t.Fatalf("PUT full: %d %s", w.Code, w.Body)
	}
	before := eventsConfigOfRealm(t, h, admin)
	if before["eventsEnabled"] != true || before["eventsExpiration"] != float64(900) {
		t.Fatalf("the full write did not land: %v", before)
	}

	if w := send(t, h, http.MethodPut, eventsConfigPath, admin, `{}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT {}: %d %s", w.Code, w.Body)
	}
	after := eventsConfigOfRealm(t, h, admin)
	if after["eventsEnabled"] != false {
		t.Errorf("eventsEnabled is %v after PUT {}, want false - an omitted value replaces", after["eventsEnabled"])
	}
	if _, ok := after["eventsExpiration"]; ok {
		t.Errorf("eventsExpiration survived PUT {} as %v, want absent", after["eventsExpiration"])
	}
	if after["adminEventsEnabled"] != true {
		t.Errorf("adminEventsEnabled is %v after PUT {}, want true - an omitted value merges", after["adminEventsEnabled"])
	}
	if after["adminEventsDetailsEnabled"] != true {
		t.Errorf("adminEventsDetailsEnabled is %v, want true", after["adminEventsDetailsEnabled"])
	}
	if got, _ := after["eventsListeners"].([]any); len(got) != 1 || got[0] != "email" {
		t.Errorf("eventsListeners is %v, want [email] - an omitted value merges", got)
	}
	if got, _ := after["enabledEventTypes"].([]any); len(got) != 2 {
		t.Errorf("enabledEventTypes is %v, want the two names it was given", got)
	}
}

// TestEventsExpirationIsAbsentOnlyAtZero pins the rule that makes the field a
// pointer: 0 disappears and -5 does not.
func TestEventsExpirationIsAbsentOnlyAtZero(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	for _, c := range []struct {
		body   string
		want   float64
		absent bool
	}{
		{`{"eventsExpiration":900}`, 900, false},
		{`{"eventsExpiration":0}`, 0, true},
		{`{"eventsExpiration":-5}`, -5, false},
	} {
		if w := send(t, h, http.MethodPut, eventsConfigPath, admin, c.body); w.Code != http.StatusNoContent {
			t.Fatalf("PUT %s: %d %s", c.body, w.Code, w.Body)
		}
		got, ok := eventsConfigOfRealm(t, h, admin)["eventsExpiration"]
		if c.absent {
			if ok {
				t.Errorf("%s left eventsExpiration present as %v", c.body, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("%s gave %v (present %v), want %v", c.body, got, ok, c.want)
		}
	}
}

// TestTheTwoEventListsReadEmptyInOppositeDirections is one request each and they
// are the whole point of not sharing a list helper.
//
// `enabledEventTypes: []` means all of them and reads back as the 103 defaults;
// `eventsListeners: []` means none of them and reads back empty.
func TestTheTwoEventListsReadEmptyInOppositeDirections(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPut, eventsConfigPath, admin,
		`{"enabledEventTypes":[],"eventsListeners":[]}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	cfg := eventsConfigOfRealm(t, h, admin)
	if got, _ := cfg["enabledEventTypes"].([]any); len(got) != 103 {
		t.Errorf("enabledEventTypes [] gave %d names, want the 103 defaults", len(got))
	}
	got, ok := cfg["eventsListeners"].([]any)
	if !ok || len(got) != 0 {
		t.Errorf("eventsListeners [] gave %v, want an empty array that is still there", cfg["eventsListeners"])
	}
}

// TestEventListenersHaveTwoRefusals pins the field that looks like one
// validation and is two, decided per entry in the array's own order.
//
// An unregistered name is `Unknown event listener`;
// `workflow-event-listener` - which GET /admin/serverinfo does report as a
// provider - is `Global event listeners not allowed in realm specific
// configuration`. A list holding both answers about whichever comes first.
//
// **Neither refusal writes anything**: the same body without the bad entry turns
// eventsEnabled on, which is the control that makes the assertion mean
// something.
func TestEventListenersHaveTwoRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	const unknown = `{"error":"Unknown event listener"}`
	const global = `{"error":"Global event listeners not allowed in realm specific configuration"}`
	for _, c := range []struct{ body, want string }{
		{`{"eventsEnabled":true,"eventsListeners":["nope"]}`, unknown},
		{`{"eventsEnabled":true,"eventsListeners":["workflow-event-listener"]}`, global},
		{`{"eventsEnabled":true,"eventsListeners":["jboss-logging","workflow-event-listener"]}`, global},
		{`{"eventsEnabled":true,"eventsListeners":["nope","workflow-event-listener"]}`, unknown},
		{`{"eventsEnabled":true,"eventsListeners":["workflow-event-listener","nope"]}`, global},
	} {
		w := send(t, h, http.MethodPut, eventsConfigPath, admin, c.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s, want 400", c.body, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != c.want {
			t.Errorf("%s: body %s, want %s", c.body, got, c.want)
		}
		if eventsConfigOfRealm(t, h, admin)["eventsEnabled"] != false {
			t.Fatalf("%s: the refused write turned eventsEnabled on - validation must complete first", c.body)
		}
	}

	// The control, and the dedupe and the order with it.
	if w := send(t, h, http.MethodPut, eventsConfigPath, admin,
		`{"eventsEnabled":true,"eventsListeners":["email","jboss-logging","email"]}`); w.Code != http.StatusNoContent {
		t.Fatalf("two listeners: %d %s", w.Code, w.Body)
	}
	cfg := eventsConfigOfRealm(t, h, admin)
	got, _ := cfg["eventsListeners"].([]any)
	if len(got) != 2 || got[0] != "jboss-logging" || got[1] != "email" {
		t.Errorf("got %v, want [jboss-logging email] - deduped and in javamap.KeyOrder's order", got)
	}
	if cfg["eventsEnabled"] != true {
		t.Error("the accepted write did not land, so the refusals above prove nothing")
	}
}

// TestUnknownEventTypeIsStoredAndUnknownQueryTypeIs500 is the pair that shows
// the same enumeration is validated on one route and not on the other.
func TestUnknownEventTypeIsStoredAndUnknownQueryTypeIs500(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPut, eventsConfigPath, admin,
		`{"enabledEventTypes":["NOT_A_TYPE"]}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	got, _ := eventsConfigOfRealm(t, h, admin)["enabledEventTypes"].([]any)
	if len(got) != 1 || got[0] != "NOT_A_TYPE" {
		t.Errorf("got %v, want the unvalidated name stored as it stands", got)
	}
	if w := get(t, h, "/admin/realms/master/events?type=NOT_A_TYPE", admin); w.Code != http.StatusInternalServerError {
		t.Errorf("?type=NOT_A_TYPE: %d %s, want 500", w.Code, w.Body)
	}
	if w := get(t, h, "/admin/realms/master/events?type=LOGIN", admin); w.Code != http.StatusOK {
		t.Errorf("?type=LOGIN: %d %s, want 200 - the control", w.Code, w.Body)
	}
}

// TestEventsConfigRejectionOrder pins every refusal the write has and the order
// the ones that can be sent together resolve in.
func TestEventsConfigRejectionOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		name        string
		contentType string
		body        string
		status      int
		want        string
	}{
		{"absent content type", "", `{"eventsEnabled":true}`, http.StatusNoContent, ""},
		{"json content type", "application/json", `{"eventsEnabled":true}`, http.StatusNoContent, ""},
		{"charset content type", "application/json;charset=UTF-8", `{"eventsEnabled":true}`, http.StatusNoContent, ""},
		{"text/plain", "text/plain", `{"eventsEnabled":true}`, http.StatusUnsupportedMediaType,
			`{"error":"The content-type header value did not match the value in @Consumes"}`},
		{"form", "application/x-www-form-urlencoded", `{"eventsEnabled":true}`, http.StatusUnsupportedMediaType,
			`{"error":"The content-type header value did not match the value in @Consumes"}`},
		{"empty body", "application/json", ``, http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"literal null", "application/json", `null`, http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"truncated object", "application/json", `{`, http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		{"an array", "application/json", `[]`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"a value of the wrong type", "application/json", `{"eventsEnabled":"yes"}`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"unknown field", "application/json", `{"zz":1}`, http.StatusBadRequest,
			`{"error":"Invalid json representation for RealmEventsConfigRepresentation. Unrecognized field \"zz\" at line 1 column 8."}`},
		// The unknown field beats the bad listener, and the bad value type beats
		// one too, so the listener check is last of the three.
		{"unknown field over bad listener", "application/json", `{"zz":1,"eventsListeners":["nope"]}`, http.StatusBadRequest,
			`{"error":"Invalid json representation for RealmEventsConfigRepresentation. Unrecognized field \"zz\" at line 1 column 8."}`},
		{"bad type over bad listener", "application/json", `{"eventsListeners":["nope"],"eventsEnabled":"yes"}`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
	}
	for _, c := range cases {
		w := sendCT(t, h, http.MethodPut, eventsConfigPath, admin, c.contentType, c.body)
		if w.Code != c.status {
			t.Errorf("%s: got %d %s, want %d", c.name, w.Code, w.Body, c.status)
			continue
		}
		if got := strings.TrimSpace(w.Body.String()); got != c.want {
			t.Errorf("%s: body %s, want %s", c.name, got, c.want)
		}
	}
}

// TestMalformedBoundBeatsTheRoleCheck is the reason the listings have a guard of
// their own.
//
// A caller holding no admin role gets the generic 404 for `?first=abc` and a 403
// for the same request without it, while every other bad parameter on the same
// route answers that caller 403. One parameter binds ahead of authorization and
// the rest do not.
func TestMalformedBoundBeatsTheRoleCheck(t *testing.T) {
	h, s, realm := newServer(t)
	none := tokenForRole(t, h, s, realm, "view-clients")

	for _, path := range []string{
		"/admin/realms/master/events?first=abc",
		"/admin/realms/master/events?max=abc",
		"/admin/realms/master/admin-events?first=abc",
	} {
		w := get(t, h, path, none)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d %s, want 404 before the role check", path, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("%s: body %s", path, got)
		}
	}
	// The controls: the same caller, and the same parameters that are checked
	// after the role.
	for _, path := range []string{
		"/admin/realms/master/events",
		"/admin/realms/master/events?type=NOPE",
		"/admin/realms/master/events?dateFrom=x",
		"/admin/realms/master/events?direction=y",
		"/admin/realms/master/events?first=-1&max=-1",
	} {
		if w := get(t, h, path, none); w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d %s, want 403 - this parameter is checked after the role", path, w.Code, w.Body)
		}
	}
	// And an unknown realm still comes first, malformed bound or not.
	for _, path := range []string{
		"/admin/realms/gloak-no-such-realm/events",
		"/admin/realms/gloak-no-such-realm/events?first=abc",
	} {
		w := get(t, h, path, none)
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"Realm not found."}` {
			t.Errorf("%s: got %d %s, want the realm's own 404", path, w.Code, w.Body)
		}
	}
}

// TestEventListingParameterOrder pins the four checks that run after the role,
// each pair sent together so the adjacency is measured rather than assumed.
func TestEventListingParameterOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		query  string
		status int
		want   string
	}{
		{"?first=abc&dateFrom=x", http.StatusNotFound, `{"error":"HTTP 404 Not Found"}`},
		{"?first=abc&type=NOPE", http.StatusNotFound, `{"error":"HTTP 404 Not Found"}`},
		{"?dateFrom=x&type=NOPE", http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"?direction=y&type=NOPE", http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"?dateFrom=x&direction=y", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		{"?dateFrom=x&dateTo=y", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		{"?dateTo=x", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateTo', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		// direction is case-sensitive, and the sentence names a parameter the
		// query string does not have.
		{"?direction=DESC", http.StatusBadRequest,
			`{"error":"Invalid value for sortDirection, expected value is asc or desc"}`},
		{"?direction=Asc", http.StatusBadRequest,
			`{"error":"Invalid value for sortDirection, expected value is asc or desc"}`},
		{"?direction=asc", http.StatusOK, `[]`},
		{"?direction=desc", http.StatusOK, `[]`},
		// The accepted date spellings, and the ones that are not.
		{"?dateFrom=2020-01-01", http.StatusOK, `[]`},
		{"?dateFrom=1700000000", http.StatusOK, `[]`},
		{"?dateFrom=0", http.StatusOK, `[]`},
		{"?dateFrom=2020-1-1", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		{"?dateFrom=2020-13-01", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		{"?dateFrom=-1", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		{"?dateFrom=1.5", http.StatusBadRequest,
			`{"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}`},
		// An empty value is ignored on every one of them, and an unknown key is
		// ignored outright.
		{"?type=&first=&max=&dateFrom=&direction=", http.StatusOK, `[]`},
		{"?zz=1", http.StatusOK, `[]`},
		{"?type=LOGIN&type=LOGOUT", http.StatusOK, `[]`},
	}
	for _, c := range cases {
		w := get(t, h, "/admin/realms/master/events"+c.query, admin)
		if w.Code != c.status || strings.TrimSpace(w.Body.String()) != c.want {
			t.Errorf("%s: got %d %s, want %d %s", c.query, w.Code, strings.TrimSpace(w.Body.String()), c.status, c.want)
		}
	}

	adminCases := []struct {
		query  string
		status int
	}{
		{"?operationTypes=CREATE", http.StatusOK},
		{"?operationTypes=create", http.StatusInternalServerError},
		{"?operationTypes=NOPE", http.StatusInternalServerError},
		{"?resourceTypes=REALM", http.StatusOK},
		{"?resourceTypes=NOPE", http.StatusInternalServerError},
		{"?resourceTypes=NOPE&operationTypes=NOPE", http.StatusInternalServerError},
		{"?authClient=x&authRealm=y&authUser=z&authIpAddress=1&resourcePath=p", http.StatusOK},
	}
	for _, c := range adminCases {
		if w := get(t, h, "/admin/realms/master/admin-events"+c.query, admin); w.Code != c.status {
			t.Errorf("admin-events%s: got %d %s, want %d", c.query, w.Code, w.Body, c.status)
		}
	}
}

// TestEventListingsAreEmptyAndTheDeletesAre204 is the honest half of the
// chapter, stated once so that "we serve it" cannot be read as "we record it".
func TestEventListingsAreEmptyAndTheDeletesAre204(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	// Turning both flags on changes nothing here, and that is the divergence
	// this cut is declaring rather than hiding: on Keycloak the write below
	// would itself appear in the admin listing.
	if w := send(t, h, http.MethodPut, eventsConfigPath, admin,
		`{"eventsEnabled":true,"adminEventsEnabled":true,"adminEventsDetailsEnabled":true}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/admin/realms/master/events", "/admin/realms/master/admin-events"} {
		w := get(t, h, path, admin)
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `[]` {
			t.Errorf("GET %s: got %d %s, want 200 []", path, w.Code, w.Body)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s: Cache-Control %q, want no-cache", path, cc)
		}
		d := send(t, h, http.MethodDelete, path, admin, "")
		if d.Code != http.StatusNoContent || d.Body.Len() != 0 {
			t.Errorf("DELETE %s: got %d %s, want 204 empty", path, d.Code, d.Body)
		}
		if cc := d.Header().Get("Cache-Control"); cc != "" {
			t.Errorf("DELETE %s: Cache-Control %q, want none", path, cc)
		}
	}
}

// TestEventsGuardIsItsOwnPair is the finding the six routes cannot show: the
// family is authorised out of view-events and manage-events, which nothing in
// this project had read before, and the realm pair the description's tag would
// suggest is 403 on all six.
func TestEventsGuardIsItsOwnPair(t *testing.T) {
	h, s, realm := newServer(t)

	cases := []struct {
		role  string
		read  int
		write int
	}{
		{"view-events", http.StatusOK, http.StatusForbidden},
		{"manage-events", http.StatusOK, http.StatusNoContent},
		{"view-realm", http.StatusForbidden, http.StatusForbidden},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden},
		{"view-users", http.StatusForbidden, http.StatusForbidden},
		{"manage-users", http.StatusForbidden, http.StatusForbidden},
		{"query-users", http.StatusForbidden, http.StatusForbidden},
		{"view-clients", http.StatusForbidden, http.StatusForbidden},
		{"manage-clients", http.StatusForbidden, http.StatusForbidden},
	}
	reads := []string{
		"/admin/realms/master/events",
		"/admin/realms/master/admin-events",
		eventsConfigPath,
	}
	for _, c := range cases {
		token := tokenForRole(t, h, s, realm, c.role)
		for _, path := range reads {
			if w := get(t, h, path, token); w.Code != c.read {
				t.Errorf("%s reading %s: got %d %s, want %d", c.role, path, w.Code, w.Body, c.read)
			}
		}
		for _, path := range []string{"/admin/realms/master/events", "/admin/realms/master/admin-events"} {
			if w := send(t, h, http.MethodDelete, path, token, ""); w.Code != c.write {
				t.Errorf("%s on DELETE %s: got %d, want %d", c.role, path, w.Code, c.write)
			}
		}
		if w := send(t, h, http.MethodPut, eventsConfigPath, token, `{}`); w.Code != c.write {
			t.Errorf("%s on PUT events/config: got %d %s, want %d", c.role, w.Code, w.Body, c.write)
		}
	}
}
