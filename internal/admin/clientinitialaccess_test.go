package admin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const initialAccessBase = "/admin/realms/master/clients-initial-access"

// createInitialAccess posts one row and returns the decoded 201.
func createInitialAccess(t *testing.T, h http.Handler, token, body string) map[string]any {
	t.Helper()
	w := send(t, h, http.MethodPost, initialAccessBase, token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST %s: %d %s", body, w.Code, w.Body)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("parse 201: %v", err)
	}
	return out
}

// TestInitialAccessTokenIsOnTheCreateAndNowhereElse is the family's shape, and
// no single golden can state it: the 201 has six keys and the listing has five,
// and the missing one is the only thing the resource is for.
func TestInitialAccessTokenIsOnTheCreateAndNowhereElse(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	created := createInitialAccess(t, h, admin, `{"count":2,"expiration":600}`)
	if _, ok := created["token"]; !ok {
		t.Fatalf("the create has no token: %v", created)
	}
	if len(created) != 6 {
		t.Errorf("the create has %d keys, want 6: %v", len(created), created)
	}

	w := get(t, h, initialAccessBase, admin)
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("the listing has %d rows, want 1", len(rows))
	}
	if _, ok := rows[0]["token"]; ok {
		t.Errorf("the listing serves a token: %v", rows[0])
	}
	if len(rows[0]) != 5 {
		t.Errorf("the listing row has %d keys, want 5: %v", len(rows[0]), rows[0])
	}
}

// TestInitialAccessTokenClaims decodes the minted token, which is the one thing
// in this family a conformance golden cannot assert: the value is per request
// and every case masks it.
//
// **`exp` is the literal 0 when the row has no expiry**, not an absent claim and
// not a far-future instant - so the arithmetic is a branch rather than an
// addition, and `iat + expiration` is what the other branch is.
func TestInitialAccessTokenClaims(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	for _, tc := range []struct {
		body      string
		wantExpIs string
	}{
		{`{}`, "zero"},
		{`{"count":3,"expiration":600}`, "iat plus 600"},
	} {
		created := createInitialAccess(t, h, admin, tc.body)
		claims := decodeJWTPayload(t, created["token"].(string))

		want := []string{"exp", "iat", "jti", "iss", "aud", "typ"}
		at := -1
		for _, k := range want {
			i := strings.Index(claims, `"`+k+`":`)
			if i < 0 {
				t.Fatalf("%s: %q missing from %s", tc.body, k, claims)
			}
			if i <= at {
				t.Errorf("%s: %q is out of the measured order in %s", tc.body, k, claims)
			}
			at = i
		}
		var c struct {
			Exp int64  `json:"exp"`
			Iat int64  `json:"iat"`
			Jti string `json:"jti"`
			Iss string `json:"iss"`
			Aud string `json:"aud"`
			Typ string `json:"typ"`
		}
		if err := json.Unmarshal([]byte(claims), &c); err != nil {
			t.Fatal(err)
		}
		if c.Typ != "InitialAccessToken" {
			t.Errorf("%s: typ %q", tc.body, c.Typ)
		}
		if c.Iss != c.Aud {
			t.Errorf("%s: iss %q and aud %q differ; they are measured identical", tc.body, c.Iss, c.Aud)
		}
		if !strings.HasSuffix(c.Iss, "/realms/master") {
			t.Errorf("%s: iss %q is not the realm's issuer", tc.body, c.Iss)
		}
		// The jti is the row's id, which is what makes the token a pointer at
		// the row rather than a copy of it.
		if c.Jti != created["id"] {
			t.Errorf("%s: jti %q is not the row's id %v", tc.body, c.Jti, created["id"])
		}
		switch tc.wantExpIs {
		case "zero":
			if c.Exp != 0 {
				t.Errorf("%s: exp %d, want the literal 0", tc.body, c.Exp)
			}
		default:
			if c.Exp != c.Iat+600 {
				t.Errorf("%s: exp %d, want iat+600 = %d", tc.body, c.Exp, c.Iat+600)
			}
		}
	}
}

func decodeJWTPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts: %s", len(parts), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return string(raw)
}

// TestInitialAccessListingIsInsertionOrder pins the order the golden asserts,
// with three rows rather than the golden's two - which is what tells insertion
// order from "the two happened to come back that way".
func TestInitialAccessListingIsInsertionOrder(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	want := []float64{7, 1, 4}
	for _, n := range want {
		createInitialAccess(t, h, admin, `{"count":`+itoa(int(n))+`}`)
	}
	w := get(t, h, initialAccessBase, admin)
	var rows []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d", len(rows), len(want))
	}
	for i, n := range want {
		if rows[i]["count"] != n {
			t.Errorf("row %d has count %v, want %v - the listing is not in insertion order: %v",
				i, rows[i]["count"], n, rows)
		}
	}
}

// TestInitialAccessCreateRefusals pins the six measured refusals in one place.
//
// The first four are the decoder's and the last two are the family's own. The
// pair that matters is `{"count":0}` against `{"count":-1}`: zero is a 201
// creating a token that can never be used, so the check is a sign test.
func TestInitialAccessCreateRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		name string
		body string
		code int
		want string
	}{
		{"an unknown field", `{"id":"x","count":2}`, http.StatusBadRequest,
			`{"error":"Invalid json representation for ClientInitialAccessCreatePresentation. ` +
				`Unrecognized field \"id\" at line 1 column 8."}`},
		{"a body that is not JSON", `{`, http.StatusBadRequest,
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		{"an array", `[`, http.StatusBadRequest,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"a literal null", `null`, http.StatusInternalServerError,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a negative count", `{"count":-5}`, http.StatusBadRequest,
			`{"error":"Invalid value for count","error_description":"The count cannot be less than 0"}`},
		{"a negative expiration", `{"expiration":-1}`, http.StatusBadRequest,
			`{"error":"Invalid value for expiration",` +
				`"error_description":"The expiration time interval cannot be less than 0"}`},
	}
	for _, c := range cases {
		w := send(t, h, http.MethodPost, initialAccessBase, admin, c.body)
		if w.Code != c.code || strings.TrimSpace(w.Body.String()) != c.want {
			t.Errorf("%s: got %d %s, want %d %s", c.name, w.Code, w.Body, c.code, c.want)
		}
	}

	// Zero is accepted, which is what makes the two above sign tests.
	created := createInitialAccess(t, h, admin, `{"count":0}`)
	if created["count"] != float64(0) || created["remainingCount"] != float64(0) {
		t.Errorf(`{"count":0} produced %v, want a row that can never be used`, created)
	}
}

// TestInitialAccessDeleteIsAlways204 is the pair with the component delete's
// 404 one route family away. Two families in one branch, one verb, opposite
// answers to the same repeat.
func TestInitialAccessDeleteIsAlways204(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)
	created := createInitialAccess(t, h, admin, `{"count":1}`)

	for _, id := range []string{created["id"].(string), created["id"].(string), "gloak-probe-no-such-token"} {
		w := send(t, h, http.MethodDelete, initialAccessBase+"/"+id, admin, "")
		if w.Code != http.StatusNoContent {
			t.Errorf("DELETE %s: got %d %s, want 204", id, w.Code, w.Body)
		}
	}
}

// TestInitialAccessSends2xxWithNoCacheControl is the divergence the recorded
// golden found and a hand probe had transcribed wrong.
//
// **Every 2xx of this family omits `Cache-Control`**, where nearly every other
// Admin API read sends `no-cache`. It is asserted here as well as in the
// goldens because writeAdminJSON is the obvious writer to reach for and it sets
// the header.
func TestInitialAccessSends2xxWithNoCacheControl(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := send(t, h, http.MethodPost, initialAccessBase, admin, `{"count":1}`)
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("the create sends Cache-Control %q, want none", got)
	}
	w = get(t, h, initialAccessBase, admin)
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("the listing sends Cache-Control %q, want none", got)
	}
}

// TestInitialAccessGuardIsTheClientsPair is the second half of this branch's
// guard finding: two chapters, two disjoint role pairs, and the description's
// tag predicts neither. `view-realm` and `manage-realm` open the components
// family and are 403 on all three of these.
func TestInitialAccessGuardIsTheClientsPair(t *testing.T) {
	h, s, realm := newServer(t)

	cases := []struct {
		role  string
		read  int
		write int
	}{
		{"view-clients", http.StatusOK, http.StatusForbidden},
		{"manage-clients", http.StatusOK, http.StatusCreated},
		{"query-clients", http.StatusForbidden, http.StatusForbidden},
		{"view-realm", http.StatusForbidden, http.StatusForbidden},
		{"manage-realm", http.StatusForbidden, http.StatusForbidden},
		{"view-users", http.StatusForbidden, http.StatusForbidden},
		{"manage-users", http.StatusForbidden, http.StatusForbidden},
	}
	for _, c := range cases {
		token := tokenForRole(t, h, s, realm, c.role)
		if w := get(t, h, initialAccessBase, token); w.Code != c.read {
			t.Errorf("%s reading: got %d, want %d", c.role, w.Code, c.read)
		}
		if w := send(t, h, http.MethodPost, initialAccessBase, token, `{"count":1}`); w.Code != c.write {
			t.Errorf("%s creating: got %d, want %d", c.role, w.Code, c.write)
		}
		want := http.StatusForbidden
		if c.write == http.StatusCreated {
			want = http.StatusNoContent
		}
		w := send(t, h, http.MethodDelete, initialAccessBase+"/gloak-probe-any", token, "")
		if w.Code != want {
			t.Errorf("%s deleting: got %d, want %d", c.role, w.Code, want)
		}
	}
}
