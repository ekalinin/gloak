package admin

import (
	"net/http"
	"strings"
	"testing"
)

const bruteForceBase = "/admin/realms/master/attack-detection/brute-force/users"

// TestBruteForceStatusIsTheSameForEveryUser is the chapter's whole shape, and
// it is a claim two goldens can each half-record and neither can state.
//
// **The route does not resolve the user.** A real user, a user id that names
// nothing and the realm's own id all answer the identical zero record, so a
// handler that grew a lookup - which is what anybody would add to be safe -
// would invent a 404 Keycloak does not send.
func TestBruteForceStatusIsTheSameForEveryUser(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-bf", "pw")

	const want = `{"failedLoginNotBefore":0,"numFailures":0,"numTemporaryLockouts":0,` +
		`"disabled":false,"numSecondaryAuthFailures":0,"lastIPFailure":"n/a","lastFailure":0}`
	for _, id := range []string{user.ID, "gloak-probe-no-such-user", realm.ID} {
		w := get(t, h, bruteForceBase+"/"+id, admin)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, w.Code, w.Body)
		}
		if got := strings.TrimSpace(w.Body.String()); got != want {
			t.Errorf("%s: got %s, want %s", id, got, want)
		}
	}
}

// TestBruteForceKeyOrderIsTheJavaMapOrder pins the seven keys in the order the
// server sent them, byte for byte.
//
// Keycloak builds the body from a `HashMap<String,Object>`, so the order is
// javamap.KeyOrder's over the seven names and not the order anybody would write
// them in. Sorting would answer `disabled` first; insertion order in Keycloak's
// own source would answer `numFailures` first. The golden asserts these bytes
// too, but a golden says "this is what came back" where this says "and that is
// the whole key set, in that order, for a reason".
func TestBruteForceKeyOrderIsTheJavaMapOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := get(t, h, bruteForceBase+"/gloak-probe-anyone", admin)
	body := strings.TrimSpace(w.Body.String())
	keys := []string{
		"failedLoginNotBefore", "numFailures", "numTemporaryLockouts", "disabled",
		"numSecondaryAuthFailures", "lastIPFailure", "lastFailure",
	}
	at := -1
	for _, k := range keys {
		i := strings.Index(body, `"`+k+`":`)
		if i < 0 {
			t.Fatalf("%q is missing from %s", k, body)
		}
		if i <= at {
			t.Errorf("%q is at %d, after the key before it - body %s", k, i, body)
		}
		at = i
	}
	if n := strings.Count(body, `":`); n != len(keys) {
		t.Errorf("the body has %d keys, want exactly %d: %s", n, len(keys), body)
	}
}

// TestBruteForceClearsAre204ForEveryone pins both deletes, including for an id
// that names nothing - which is measured and is why neither has a 404 branch.
func TestBruteForceClearsAre204ForEveryone(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	user := createUserWithPassword(t, s, realm, "gloak-probe-bf-del", "pw")

	for _, path := range []string{
		bruteForceBase + "/" + user.ID,
		bruteForceBase + "/gloak-probe-no-such-user",
		bruteForceBase,
	} {
		w := send(t, h, http.MethodDelete, path, admin, "")
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Errorf("DELETE %s: got %d %s, want 204 with no body", path, w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "" {
			t.Errorf("DELETE %s: Cache-Control %q, want none", path, got)
		}
	}
}

// TestBruteForceGuardIsTheUsersPair is the finding the routes cannot show: the
// Attack Detection tag is authorised out of the **users** pair, although
// nothing in its path or its tag says users.
//
// `query-users` is the discriminating role. It opens `GET /users` and is 403 on
// all three of these, so a guard written from the user listing's role set would
// be wrong; and `view-realm`, which opens the components family this branch
// also builds, is 403 too.
func TestBruteForceGuardIsTheUsersPair(t *testing.T) {
	h, s, realm := newServer(t)

	cases := []struct {
		role  string
		read  int
		write int
	}{
		{"view-users", http.StatusOK, http.StatusForbidden},
		{"manage-users", http.StatusOK, http.StatusNoContent},
		{"query-users", http.StatusForbidden, http.StatusForbidden},
		{"view-realm", http.StatusForbidden, http.StatusForbidden},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden},
		{"view-clients", http.StatusForbidden, http.StatusForbidden},
		{"manage-clients", http.StatusForbidden, http.StatusForbidden},
	}
	for _, c := range cases {
		token := tokenForRole(t, h, s, realm, c.role)
		if w := get(t, h, bruteForceBase+"/gloak-probe-anyone", token); w.Code != c.read {
			t.Errorf("%s reading: got %d, want %d", c.role, w.Code, c.read)
		}
		for _, path := range []string{bruteForceBase + "/gloak-probe-anyone", bruteForceBase} {
			if w := send(t, h, http.MethodDelete, path, token, ""); w.Code != c.write {
				t.Errorf("%s on DELETE %s: got %d, want %d", c.role, path, w.Code, c.write)
			}
		}
	}
}
