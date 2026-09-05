package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// sessionFor password-grants a user and returns the session id the grant
// created, which is the response's session_state.
//
// It goes through the protocol endpoint rather than writing a row, because a
// session written behind the API's back would not have the client session that
// makes it visible to five of the eleven routes - and losing that join is
// exactly the mistake these tests exist to catch.
func sessionFor(t *testing.T, h http.Handler, username, password string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/token",
		strings.NewReader("grant_type=password&client_id=admin-cli&username="+username+"&password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("password grant for %q: %d %s", username, w.Code, w.Body)
	}
	var body struct {
		SessionState string `json:"session_state"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	if body.SessionState == "" {
		t.Fatalf("the grant minted no session_state: %s", w.Body)
	}
	return body.SessionState
}

func adminCLIUUID(t *testing.T, s store.Store, realm *model.Realm) string {
	t.Helper()
	c, err := s.Clients().ByClientID(t.Context(), realm.ID, "admin-cli")
	if err != nil {
		t.Fatalf("ByClientID(admin-cli): %v", err)
	}
	return c.ID
}

func postTo(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func deleteFrom(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestUserSessionRepresentationKeyOrder pins the nine keys and their order.
//
// Moving a field in the struct is a silent divergence - a client parsing JSON
// would not notice and neither would a test asserting a few values - so this
// asserts the marshalled key list itself, which is the same guard realmrep_test
// puts on the realm representation.
func TestUserSessionRepresentationKeyOrder(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-sess-keys", "pw")
	sessionFor(t, h, "gloak-probe-sess-keys", "pw")
	user, err := s.Users().ByUsername(t.Context(), realm.ID, "gloak-probe-sess-keys")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}

	w := get(t, h, "/admin/realms/master/users/"+user.ID+"/sessions", admin)

	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	want := []string{"id", "username", "userId", "ipAddress", "start",
		"lastAccess", "rememberMe", "clients", "transientUser"}
	body := w.Body.String()
	at := -1
	for _, k := range want {
		i := strings.Index(body, `"`+k+`":`)
		if i < 0 {
			t.Fatalf("%q is missing from %s", k, body)
		}
		if i < at {
			t.Fatalf("%q is out of order in %s", k, body)
		}
		at = i
	}
	// The key set is closed: an extra key would pass the ordering walk above.
	var rows []map[string]any
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one session, got %d", len(rows))
	}
	if len(rows[0]) != len(want) {
		t.Fatalf("want %d keys, got %d: %s", len(want), len(rows[0]), body)
	}
}

// TestClientSessionStatsRowIsInJavaMapOrder computes the claim rather than
// transcribing it.
//
// The four keys come back `offline, clientId, active, id` from a live 26.7.1,
// which is neither sorted nor anything a person would write - it is a
// HashMap's iteration order. Asserting the measured order against
// javamap.KeyOrder's is what says the two agree, so a struct reordered to look
// tidier fails here with the reason attached.
func TestClientSessionStatsRowIsInJavaMapOrder(t *testing.T) {
	measured := []string{"offline", "clientId", "active", "id"}
	if got := javamap.KeyOrder([]string{"active", "clientId", "id", "offline"}); !slices.Equal(got, measured) {
		t.Fatalf("javamap.KeyOrder gives %v, the server gave %v", got, measured)
	}

	raw, err := json.Marshal(clientSessionStatsRow{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	at := -1
	for _, k := range measured {
		i := strings.Index(string(raw), `"`+k+`":`)
		if i < 0 || i < at {
			t.Fatalf("clientSessionStatsRow is not in the measured order: %s", raw)
		}
		at = i
	}
	// The counts are strings, because the description's schema says the row is
	// a Map<String,String> and the server quotes them.
	if !strings.Contains(string(raw), `"offline":""`) || !strings.Contains(string(raw), `"active":""`) {
		t.Fatalf("the counts are not strings: %s", raw)
	}
}

// TestClientSessionStatsCountsWhatTheOtherReadsDoNot is the chapter's own
// claim: the stats listing holds one row per client **that has a session**,
// and no row for one that has none.
//
// A handler that listed every client with a zero count would pass any test
// that only looked at the client with a session.
func TestClientSessionStatsCountsWhatTheOtherReadsDoNot(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-stats-u", "pw")
	sessionFor(t, h, "gloak-probe-stats-u", "pw")

	w := get(t, h, "/admin/realms/master/client-session-stats", admin)

	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var rows []map[string]string
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Bootstrap creates six clients and only admin-cli has been used, by the
	// administrator's own token and by the probe user.
	if len(rows) != 1 {
		t.Fatalf("want one row, got %d: %s", len(rows), w.Body)
	}
	if rows[0]["clientId"] != "admin-cli" {
		t.Fatalf("wrong client: %s", w.Body)
	}
	if rows[0]["active"] != "2" {
		t.Fatalf("want two active sessions, got %q: %s", rows[0]["active"], w.Body)
	}
	// Offline is always "0" and there is no table behind it. If Gloak ever
	// grows offline sessions this is the assertion that says so.
	if rows[0]["offline"] != "0" {
		t.Fatalf("offline is not zero: %s", w.Body)
	}
	if rows[0]["id"] != adminCLIUUID(t, s, realm) {
		t.Fatalf("the row's id is not the client's UUID: %s", w.Body)
	}
}

// TestTheOfflineHalfIsEmptyForEveryInput is F157's shape stated as a test.
//
// Gloak has no offline session and no way to make one, so the four offline
// reads answer the empty shape for a client with sessions and for one without,
// and DELETE ... ?isOffline=true is the 404 even for a session id that exists.
// Serving them from a real listing would be the change this catches.
func TestTheOfflineHalfIsEmptyForEveryInput(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-off-u", "pw")
	sid := sessionFor(t, h, "gloak-probe-off-u", "pw")
	cli := adminCLIUUID(t, s, realm)
	account, err := s.Clients().ByClientID(t.Context(), realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}

	for _, tc := range []struct{ path, want string }{
		// admin-cli holds two live sessions and still reports none offline.
		{"/admin/realms/master/clients/" + cli + "/offline-session-count", `{"count":0}`},
		{"/admin/realms/master/clients/" + cli + "/offline-sessions", `[]`},
		{"/admin/realms/master/clients/" + account.ID + "/offline-session-count", `{"count":0}`},
		{"/admin/realms/master/clients/" + account.ID + "/offline-sessions", `[]`},
		{"/admin/realms/master/users/" + user.ID + "/offline-sessions/" + cli, `[]`},
		{"/admin/realms/master/users/" + user.ID + "/offline-sessions/" + account.ID, `[]`},
	} {
		w := get(t, h, tc.path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.path, got, tc.want)
		}
	}

	// A live session id, asked for in the offline space, is as absent as one
	// that never existed - and the online delete beside it still works, which
	// is what says the 404 is the parameter and not the id.
	w := deleteFrom(t, h, "/admin/realms/master/sessions/"+sid+"?isOffline=true", admin)
	if w.Code != http.StatusNotFound {
		t.Fatalf("isOffline=true on a live session: %d %s", w.Code, w.Body)
	}
	if w = deleteFrom(t, h, "/admin/realms/master/sessions/"+sid, admin); w.Code != http.StatusNoContent {
		t.Fatalf("the same session without isOffline: %d %s", w.Code, w.Body)
	}
}

// TestIsOfflineIsParsedLenientlyWhereABoundIsNot is the family's sharpest
// measured contrast, and one handler could easily get it backwards.
//
// `isOffline=bogus` deletes the online session - it falls back to false - where
// `first=abc` on the listing one path segment away is the generic 404. One
// family, one malformed value, two answers, decided by the type of the
// parameter.
func TestIsOfflineIsParsedLenientlyWhereABoundIsNot(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-lenient", "pw")
	sid := sessionFor(t, h, "gloak-probe-lenient", "pw")
	cli := adminCLIUUID(t, s, realm)

	w := deleteFrom(t, h, "/admin/realms/master/sessions/"+sid+"?isOffline=bogus", admin)
	if w.Code != http.StatusNoContent {
		t.Fatalf("isOffline=bogus: want 204, got %d %s", w.Code, w.Body)
	}

	for _, q := range []string{"?first=abc", "?max=abc", "?first=1&max=zz"} {
		w := get(t, h, "/admin/realms/master/clients/"+cli+"/user-sessions"+q, admin)
		if w.Code != http.StatusNotFound {
			t.Errorf("user-sessions%s: want 404, got %d %s", q, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("user-sessions%s: %s", q, got)
		}
	}
}

// TestTheTwoListingsDisagreeAboutBounds is the split within one family.
//
// The client listing pages and answers a malformed bound with a 404; the user
// listing and the stats read take no bounds at all and answer 200 with
// everything. A shared helper would get one of the two wrong, which is what
// this asserts against - and it needs **more than one session**, because a
// bound cannot be seen to be ignored on a listing of one.
func TestTheTwoListingsDisagreeAboutBounds(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-bounds", "pw")
	for range 3 {
		sessionFor(t, h, "gloak-probe-bounds", "pw")
	}
	user, err := s.Users().ByUsername(t.Context(), realm.ID, "gloak-probe-bounds")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	cli := adminCLIUUID(t, s, realm)

	count := func(path string) int {
		t.Helper()
		w := get(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		var rows []map[string]any
		if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		return len(rows)
	}

	base := "/admin/realms/master/users/" + user.ID + "/sessions"
	// Three sessions for this user, and every bound is ignored - including a
	// malformed one, which is a 404 on the client listing.
	for _, q := range []string{"", "?max=1", "?first=1", "?first=1&max=1", "?max=0", "?first=abc"} {
		if n := count(base + q); n != 3 {
			t.Errorf("users/{id}/sessions%s: got %d rows, want all 3", q, n)
		}
	}

	// admin-cli holds four: the administrator's own and the three above.
	client := "/admin/realms/master/clients/" + cli + "/user-sessions"
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 4},
		{"?max=2", 2},           // either bound alone pages
		{"?first=1", 3},         //
		{"?first=1&max=2", 2},   //
		{"?first=-1&max=-1", 4}, // a negative bound means no bound
		{"?max=0", 0},           // and zero is a real bound, not the absent one
	} {
		if n := count(client + tc.query); n != tc.want {
			t.Errorf("clients/{uuid}/user-sessions%s: got %d rows, want %d", tc.query, n, tc.want)
		}
	}
}

// TestSessionListingsAreSortedById pins the order the two paged reads take
// their bounds from. Without it `first=1` would drop an arbitrary row.
func TestSessionListingsAreSortedById(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-sorted", "pw")
	for range 5 {
		sessionFor(t, h, "gloak-probe-sorted", "pw")
	}
	cli := adminCLIUUID(t, s, realm)

	w := get(t, h, "/admin/realms/master/clients/"+cli+"/user-sessions", admin)
	var rows []struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) < 5 {
		t.Fatalf("want at least five sessions, got %d", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].ID >= rows[i].ID {
			t.Fatalf("not sorted by id: %q then %q", rows[i-1].ID, rows[i].ID)
		}
	}
}

// TestTheClientReadsCountTheClientAndNotTheRealm was written because a
// mutation survived.
//
// Replacing ListUserSessionsByClient with ListUserSessionsByRealm in
// clientSessionCount left the whole admin package and the whole conformance
// suite green: every fixture in this family has **one** client with sessions in
// its realm, so realm-wide and client-wide agree on all of them. The
// distinguishing input is a second client in the same realm that nobody has
// logged into - which master has five of, and which no case had asked about.
//
// Both reads are checked here rather than only the one the mutation touched:
// the listing has the same shape and the same way of going wrong.
func TestTheClientReadsCountTheClientAndNotTheRealm(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-per-client", "pw")
	sessionFor(t, h, "gloak-probe-per-client", "pw")
	sessionFor(t, h, "gloak-probe-per-client", "pw")
	// The realm now holds three sessions - these two and the administrator's -
	// and every one of them is at admin-cli.
	all, err := s.Sessions().ListUserSessionsByRealm(t.Context(), realm.ID)
	if err != nil {
		t.Fatalf("ListUserSessionsByRealm: %v", err)
	}
	if len(all) < 2 {
		t.Fatalf("want at least two sessions in the realm, got %d", len(all))
	}
	account, err := s.Clients().ByClientID(t.Context(), realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}

	w := get(t, h, "/admin/realms/master/clients/"+account.ID+"/session-count", admin)
	if got := strings.TrimSpace(w.Body.String()); got != `{"count":0}` {
		t.Errorf("a client nobody has used counts %s, and the realm holds %d sessions",
			got, len(all))
	}
	w = get(t, h, "/admin/realms/master/clients/"+account.ID+"/user-sessions", admin)
	if got := strings.TrimSpace(w.Body.String()); got != `[]` {
		t.Errorf("a client nobody has used lists %s", got)
	}
	// The control: the client they *are* at reports them, so the zero above is
	// the join and not a read that answers zero for everything.
	w = get(t, h, "/admin/realms/master/clients/"+adminCLIUUID(t, s, realm)+"/session-count", admin)
	if got := strings.TrimSpace(w.Body.String()); got == `{"count":0}` {
		t.Errorf("the client the sessions are at counts %s too", got)
	}
}

// TestTheTwoMissingClientSpellingsDiffer is the pair this family adds.
//
// One missing client, two sentences, one route family apart - and the user is
// resolved before the client on the one route naming both, so an unknown user
// with an unknown client answers about the user.
func TestTheTwoMissingClientSpellingsDiffer(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-spell", "pw")
	const nope = "gloak-probe-no-such-client"

	for _, path := range []string{
		"/admin/realms/master/clients/" + nope + "/session-count",
		"/admin/realms/master/clients/" + nope + "/user-sessions",
		"/admin/realms/master/clients/" + nope + "/offline-session-count",
		"/admin/realms/master/clients/" + nope + "/offline-sessions",
	} {
		w := get(t, h, path, admin)
		if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
			got != `{"error":"Could not find client"}` {
			t.Errorf("%s: %d %s", path, w.Code, got)
		}
	}
	w := postTo(t, h, "/admin/realms/master/clients/"+nope+"/push-revocation", admin)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"error":"Could not find client"}` {
		t.Errorf("push-revocation: %d %s", w.Code, got)
	}

	// The very same missing client, one route family away, is a different
	// sentence.
	w = get(t, h, "/admin/realms/master/users/"+user.ID+"/offline-sessions/"+nope, admin)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"error":"Client not found"}` {
		t.Errorf("offline-sessions with a bad client: %d %s", w.Code, got)
	}

	// The user comes first: both unknown answers about the user.
	w = get(t, h, "/admin/realms/master/users/gloak-probe-no-such-user/offline-sessions/"+nope, admin)
	if got := strings.TrimSpace(w.Body.String()); w.Code != http.StatusNotFound ||
		got != `{"error":"User not found"}` {
		t.Errorf("both unknown: %d %s", w.Code, got)
	}
}

// TestSessionNotFoundKeepsKeycloaksTypo guards the one spelling in this API
// that is misspelled. Correcting it is the tidy-up that breaks compatibility,
// and a reviewer reading `Sesssion` would otherwise be right to fix it.
func TestSessionNotFoundKeepsKeycloaksTypo(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	for _, id := range []string{"gloak-probe-no-such-session", "not-a-uuid", "00000000"} {
		w := deleteFrom(t, h, "/admin/realms/master/sessions/"+id, admin)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", id, w.Code)
		}
		if got := strings.TrimSpace(w.Body.String()); got != `{"error":"Sesssion not found"}` {
			t.Errorf("%s: got %s", id, got)
		}
	}
}

// TestLogoutAllEndsEverySessionAndStampsTheRealm is the write's two effects.
//
// The stamp is what makes the endpoint's result visible beyond its body, the
// way POST /users/{id}/logout's stamp is - and it is the **realm's** notBefore,
// not the user's, measured on three fresh realms one write at a time.
func TestLogoutAllEndsEverySessionAndStampsTheRealm(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-logoutall", "pw")
	sessionFor(t, h, "gloak-probe-logoutall", "pw")
	sessionFor(t, h, "gloak-probe-logoutall", "pw")

	before := realmNotBefore(t, h, admin)
	if before != 0 {
		t.Fatalf("the realm starts stamped: %d", before)
	}

	w := postTo(t, h, "/admin/realms/master/logout-all", admin)

	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// An empty GlobalRequestResult is `{}` and not two empty arrays.
	if got := strings.TrimSpace(w.Body.String()); got != `{}` {
		t.Fatalf("want {}, got %s", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("the 200 writes carry no Cache-Control, got %q", got)
	}
	sessions, err := s.Sessions().ListUserSessionsByRealm(t.Context(), realm.ID)
	if err != nil {
		t.Fatalf("ListUserSessionsByRealm: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("logout-all left %d sessions", len(sessions))
	}
	// **It ended the caller's own session too**, so reading the realm back
	// needs a fresh token. That is not incidental: it is why the conformance
	// case for this endpoint cannot address master, where it would end the
	// recorder's session and break every case after it.
	if realmNotBefore(t, h, adminToken(t, h)) == 0 {
		t.Fatal("logout-all did not stamp the realm's notBefore")
	}
	// It stamps the realm and not the user, which is the half a handler
	// copied from logoutUser would get wrong.
	stored, err := s.Users().ByID(t.Context(), realm.ID, user.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if stored.NotBefore != 0 {
		t.Errorf("logout-all stamped the user too: %d", stored.NotBefore)
	}
}

// TestPushRevocationStampsNothing is the neighbour that does not.
//
// push-revocation pushes a policy that logout-all sets. Reading the two names
// the other way round is the obvious mistake and it is wrong on both, so this
// asserts the absence rather than leaving it implied.
func TestPushRevocationStampsNothing(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	cli := adminCLIUUID(t, s, realm)
	createUserWithPassword(t, s, realm, "gloak-probe-push", "pw")
	sessionFor(t, h, "gloak-probe-push", "pw")

	for _, path := range []string{
		"/admin/realms/master/push-revocation",
		"/admin/realms/master/clients/" + cli + "/push-revocation",
	} {
		w := postTo(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != `{}` {
			t.Errorf("%s: want {}, got %s", path, got)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
			t.Errorf("%s: Content-Type %q", path, got)
		}
	}
	if got := realmNotBefore(t, h, admin); got != 0 {
		t.Errorf("push-revocation stamped the realm: %d", got)
	}
	// And it ends nothing: a push is not a logout.
	sessions, err := s.Sessions().ListUserSessionsByRealm(t.Context(), realm.ID)
	if err != nil {
		t.Fatalf("ListUserSessionsByRealm: %v", err)
	}
	if len(sessions) != 2 {
		t.Errorf("push-revocation moved the sessions: %d", len(sessions))
	}
}

func realmNotBefore(t *testing.T, h http.Handler, token string) int {
	t.Helper()
	w := get(t, h, "/admin/realms/master", token)
	if w.Code != http.StatusOK {
		t.Fatalf("read realm: %d %s", w.Code, w.Body)
	}
	var rep struct {
		NotBefore int `json:"notBefore"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rep); err != nil {
		t.Fatalf("parse realm: %v", err)
	}
	return rep.NotBefore
}

// TestTheSessionFamilyTakesFourRoleSets is the guard sweep, and the point of
// it is that the description's tag predicts none of the four.
//
// The `Realms Admin` tag alone answers three ways: client-session-stats to the
// realm read pair, push-revocation to manage-realm, and logout-all and the
// session delete to **manage-users**. Measured one role at a time against a
// live 26.7.1.
func TestTheSessionFamilyTakesFourRoleSets(t *testing.T) {
	h, s, realm := newServer(t)
	cli := adminCLIUUID(t, s, realm)
	user := createUserWithPassword(t, s, realm, "gloak-probe-guard-subject", "pw")

	type call struct {
		method, path string
	}
	ops := []struct {
		name  string
		call  call
		opens []string
	}{
		{"clients/session-count", call{http.MethodGet, "/admin/realms/master/clients/" + cli + "/session-count"},
			[]string{"view-clients", "manage-clients"}},
		{"clients/user-sessions", call{http.MethodGet, "/admin/realms/master/clients/" + cli + "/user-sessions"},
			[]string{"view-clients", "manage-clients"}},
		{"clients/offline-session-count", call{http.MethodGet, "/admin/realms/master/clients/" + cli + "/offline-session-count"},
			[]string{"view-clients", "manage-clients"}},
		{"clients/offline-sessions", call{http.MethodGet, "/admin/realms/master/clients/" + cli + "/offline-sessions"},
			[]string{"view-clients", "manage-clients"}},
		{"clients/push-revocation", call{http.MethodPost, "/admin/realms/master/clients/" + cli + "/push-revocation"},
			[]string{"manage-clients"}},
		{"users/sessions", call{http.MethodGet, "/admin/realms/master/users/" + user.ID + "/sessions"},
			[]string{"view-users", "manage-users"}},
		{"users/offline-sessions", call{http.MethodGet, "/admin/realms/master/users/" + user.ID + "/offline-sessions/" + cli},
			[]string{"view-users", "manage-users"}},
		{"client-session-stats", call{http.MethodGet, "/admin/realms/master/client-session-stats"},
			[]string{"view-realm", "manage-realm"}},
		{"push-revocation", call{http.MethodPost, "/admin/realms/master/push-revocation"},
			[]string{"manage-realm"}},
		{"logout-all", call{http.MethodPost, "/admin/realms/master/logout-all"},
			[]string{"manage-users"}},
	}
	candidates := []string{"view-clients", "manage-clients", "query-clients",
		"view-users", "manage-users", "query-users", "view-realm", "manage-realm"}

	for _, role := range candidates {
		token := tokenForRole(t, h, s, realm, role)
		for _, op := range ops {
			var w *httptest.ResponseRecorder
			if op.call.method == http.MethodGet {
				w = get(t, h, op.call.path, token)
			} else {
				w = postTo(t, h, op.call.path, token)
			}
			opens := false
			for _, r := range op.opens {
				if r == role {
					opens = true
				}
			}
			// manage-clients confers view-clients and manage-users confers
			// view-users through the implication table, so "opens" is read
			// through the same relation the guard uses rather than by name.
			if opens && w.Code == http.StatusForbidden {
				t.Errorf("%s refused %s", op.name, role)
			}
			if !opens && w.Code != http.StatusForbidden {
				t.Errorf("%s admitted %s: %d %s", op.name, role, w.Code, w.Body)
			}
		}
	}
}

// TestTheSessionDeleteIsGuardedByManageUsers is separated from the sweep above
// because it is destructive and because its 404 is the evidence for the
// ordering: a manage-users caller gets 404 for a session that does not exist
// where every other role gets 403, so the role is checked first.
func TestTheSessionDeleteIsGuardedByManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	const path = "/admin/realms/master/sessions/gloak-probe-no-such-session"

	for _, role := range []string{"view-clients", "manage-clients", "query-clients",
		"view-users", "query-users", "view-realm", "manage-realm"} {
		w := deleteFrom(t, h, path, tokenForRole(t, h, s, realm, role))
		if w.Code != http.StatusForbidden {
			t.Errorf("the session delete admitted %s: %d %s", role, w.Code, w.Body)
		}
	}
	w := deleteFrom(t, h, path, tokenForRole(t, h, s, realm, "manage-users"))
	if w.Code != http.StatusNotFound {
		t.Errorf("manage-users: want 404, got %d %s", w.Code, w.Body)
	}
}

// TestSessionReadsCarryNoCacheAndTheWritesDoNot is the header split, measured
// as a table on one container.
//
// It is one more instance of "Cache-Control is pinned per endpoint" rather than
// a new axis, and it is asserted here because the goldens assert it per case
// and nothing states the rule.
func TestSessionReadsCarryNoCacheAndTheWritesDoNot(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	cli := adminCLIUUID(t, s, realm)
	user := createUserWithPassword(t, s, realm, "gloak-probe-headers", "pw")
	sid := sessionFor(t, h, "gloak-probe-headers", "pw")

	reads := []string{
		"/admin/realms/master/clients/" + cli + "/session-count",
		"/admin/realms/master/clients/" + cli + "/user-sessions",
		"/admin/realms/master/clients/" + cli + "/offline-session-count",
		"/admin/realms/master/clients/" + cli + "/offline-sessions",
		"/admin/realms/master/users/" + user.ID + "/sessions",
		"/admin/realms/master/users/" + user.ID + "/offline-sessions/" + cli,
		"/admin/realms/master/client-session-stats",
	}
	for _, path := range reads {
		w := get(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("%s: Cache-Control %q, want no-cache", path, got)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json;charset=UTF-8" {
			t.Errorf("%s: Content-Type %q", path, got)
		}
	}
	for _, path := range []string{
		"/admin/realms/master/clients/" + cli + "/push-revocation",
		"/admin/realms/master/push-revocation",
		"/admin/realms/master/logout-all",
	} {
		w := postTo(t, h, path, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "" {
			t.Errorf("%s: the writes carry no Cache-Control, got %q", path, got)
		}
	}
	// The delete's 204 carries neither, and no Content-Type either. The token
	// is minted again because logout-all above ended the caller's own session
	// along with everything else, and a fresh grant re-makes the one addressed
	// here.
	sid = sessionFor(t, h, "gloak-probe-headers", "pw")
	w := deleteFrom(t, h, "/admin/realms/master/sessions/"+sid, adminToken(t, h))
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("the 204 carries Cache-Control %q", got)
	}
	if got := w.Header().Get("Content-Type"); got != "" {
		t.Errorf("the 204 carries Content-Type %q", got)
	}
}

// TestSessionTimestampsAreTruncatedToTheSecond guards the one transform the
// representation applies.
//
// Keycloak stores seconds and the representation multiplies, so every measured
// value ends in three zeros. Gloak stores milliseconds, so serving them raw
// would be observably different on a field a client reads.
func TestSessionTimestampsAreTruncatedToTheSecond(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-times", "pw")
	sessionFor(t, h, "gloak-probe-times", "pw")
	user, err := s.Users().ByUsername(t.Context(), realm.ID, "gloak-probe-times")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}

	w := get(t, h, "/admin/realms/master/users/"+user.ID+"/sessions", admin)
	var rows []struct {
		Start      int64 `json:"start"`
		LastAccess int64 `json:"lastAccess"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one session, got %d", len(rows))
	}
	if rows[0].Start == 0 || rows[0].Start%1000 != 0 {
		t.Errorf("start is not a whole second in milliseconds: %d", rows[0].Start)
	}
	if rows[0].LastAccess == 0 || rows[0].LastAccess%1000 != 0 {
		t.Errorf("lastAccess is not a whole second in milliseconds: %d", rows[0].LastAccess)
	}
}

// TestTheClientsMapNamesTheClientTheSessionReached is the join the
// representation rests on. A handler that filled the map from the realm's
// clients rather than from the session's would pass every other test here.
func TestTheClientsMapNamesTheClientTheSessionReached(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	createUserWithPassword(t, s, realm, "gloak-probe-clients-map", "pw")
	sessionFor(t, h, "gloak-probe-clients-map", "pw")
	user, err := s.Users().ByUsername(t.Context(), realm.ID, "gloak-probe-clients-map")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}

	w := get(t, h, "/admin/realms/master/users/"+user.ID+"/sessions", admin)
	var rows []struct {
		Clients map[string]string `json:"clients"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 || len(rows[0].Clients) != 1 {
		t.Fatalf("want one session at one client, got %s", w.Body)
	}
	// Bootstrap creates six clients; the session reached one of them.
	if rows[0].Clients[adminCLIUUID(t, s, realm)] != "admin-cli" {
		t.Fatalf("the clients map does not name admin-cli by its UUID: %s", w.Body)
	}
}
