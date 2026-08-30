package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const authBase = "/admin/realms/master/authentication"

// send issues a request with a JSON body, or none when body is empty.
func send(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func adminToken(t *testing.T, h http.Handler) string {
	t.Helper()
	return tokenFor(t, h, "admin", "admin")
}

// requiredActionAliases reads the listing back as `alias=priority` pairs, which
// is the shape the priority rules are stated in.
func requiredActionAliases(t *testing.T, h http.Handler, token string) []string {
	t.Helper()
	w := get(t, h, authBase+"/required-actions", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list required actions: %d %s", w.Code, w.Body)
	}
	var rows []struct {
		Alias    string `json:"alias"`
		Priority int    `json:"priority"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse listing: %v", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Alias)
	}
	return out
}

// TestRequiredActionNotFoundHasTwoSpellingsSplitByVerb pins the full stop.
//
// One resource, one missing alias, **two sentences**: GET and PUT answer
// `Failed to find required action` and DELETE and the two priority POSTs answer
// `Failed to find required action.`. Measured on a live 26.7.1 on 2026-08-30,
// all five verbs in one sweep. No golden pairs the five, so this test is what
// keeps a shared constant from quietly making them agree.
func TestRequiredActionNotFoundHasTwoSpellingsSplitByVerb(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	cases := []struct {
		method, path, want string
	}{
		{http.MethodGet, "/required-actions/NOPE", `{"error":"Failed to find required action"}`},
		{http.MethodPut, "/required-actions/NOPE", `{"error":"Failed to find required action"}`},
		{http.MethodDelete, "/required-actions/NOPE", `{"error":"Failed to find required action."}`},
		{http.MethodPost, "/required-actions/NOPE/raise-priority", `{"error":"Failed to find required action."}`},
		{http.MethodPost, "/required-actions/NOPE/lower-priority", `{"error":"Failed to find required action."}`},
	}
	for _, c := range cases {
		body := ""
		if c.method == http.MethodPut {
			body = `{"alias":"NOPE"}`
		}
		w := send(t, h, c.method, authBase+c.path, token, body)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: status %d, want 404", c.method, c.path, w.Code)
		}
		if got := w.Body.String(); got != c.want {
			t.Errorf("%s %s:\n got %s\nwant %s", c.method, c.path, got, c.want)
		}
	}
}

// TestRequiredActionConfigResolvesTheAliasAsAProviderID pins the two-stage
// lookup that the obvious implementation gets backwards.
//
// The `/config` and `/config-description` sub-resources use the path's alias as
// a **provider id** first, and only then look for a row. Measured by renaming
// CONFIGURE_TOTP's row to ZZZ on a live 26.7.1: the sub-resources do not follow
// the rename, and the abandoned alias still answers a config description.
func TestRequiredActionConfigResolvesTheAliasAsAProviderID(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	rename := `{"alias":"ZZZ","name":"Configure OTP","providerId":"CONFIGURE_TOTP",` +
		`"enabled":true,"defaultAction":false,"priority":54}`
	if w := send(t, h, http.MethodPut, authBase+"/required-actions/CONFIGURE_TOTP", token, rename); w.Code != http.StatusNoContent {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}

	cases := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		// The new alias is not a provider id at all, so it is "not
		// configurable" - a 400, where the parent route's miss is a 404.
		{"/required-actions/ZZZ/config", http.StatusBadRequest,
			`{"error":"RequiredAction is not configurable"}`},
		{"/required-actions/ZZZ/config-description", http.StatusNotFound,
			`{"error":"Could not find configurable RequiredAction provider"}`},
		// The old alias is still a configurable provider id, so the config
		// description answers 200 with no row behind it, and the config itself
		// answers a **third** sentence.
		{"/required-actions/CONFIGURE_TOTP/config", http.StatusNotFound,
			`{"error":"Could not find RequiredAction config"}`},
	}
	for _, c := range cases {
		w := get(t, h, authBase+c.path, token)
		if w.Code != c.wantStatus {
			t.Errorf("GET %s: status %d, want %d (%s)", c.path, w.Code, c.wantStatus, w.Body)
		}
		if got := w.Body.String(); got != c.wantBody {
			t.Errorf("GET %s:\n got %s\nwant %s", c.path, got, c.wantBody)
		}
	}
	if w := get(t, h, authBase+"/required-actions/CONFIGURE_TOTP/config-description", token); w.Code != http.StatusOK {
		t.Errorf("the abandoned alias still describes its config: %d %s", w.Code, w.Body)
	}
}

// TestRaisePriorityExchangesValuesWithTheNeighbour pins the swap.
//
// It is not a decrement: UPDATE_PASSWORD at 57 and CONFIGURE_TOTP at 54 became
// 54 and 57 on a live server, so the two rows trade values rather than one
// moving. The pair is deliberately **non-adjacent in value** - 54 and 57 - so
// that a decrementing implementation cannot pass by coincidence.
func TestRaisePriorityExchangesValuesWithTheNeighbour(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	before := requiredActionPriorities(t, h, token)
	if before["UPDATE_PASSWORD"] != 57 || before["CONFIGURE_TOTP"] != 54 {
		t.Fatalf("the seeded priorities moved: %v", before)
	}
	w := send(t, h, http.MethodPost, authBase+"/required-actions/UPDATE_PASSWORD/raise-priority", token, `{}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("raise-priority: %d %s", w.Code, w.Body)
	}
	after := requiredActionPriorities(t, h, token)
	if after["UPDATE_PASSWORD"] != 54 || after["CONFIGURE_TOTP"] != 57 {
		t.Errorf("want the two values exchanged, got UPDATE_PASSWORD=%d CONFIGURE_TOTP=%d",
			after["UPDATE_PASSWORD"], after["CONFIGURE_TOTP"])
	}
	// Every other row is untouched, which a re-numbering implementation would
	// break while still swapping the pair.
	for alias, priority := range before {
		if alias == "UPDATE_PASSWORD" || alias == "CONFIGURE_TOTP" {
			continue
		}
		if after[alias] != priority {
			t.Errorf("%s moved from %d to %d", alias, priority, after[alias])
		}
	}
}

// TestPriorityAtTheEndsIsANoOp420 pins both ends: raising the first row and
// lowering the last are 204 and change nothing.
func TestPriorityAtTheEndsIsANoOp(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	before := requiredActionAliases(t, h, token)
	for _, c := range []struct{ alias, op string }{
		{before[0], "raise-priority"},
		{before[len(before)-1], "lower-priority"},
	} {
		w := send(t, h, http.MethodPost,
			authBase+"/required-actions/"+c.alias+"/"+c.op, token, `{}`)
		if w.Code != http.StatusNoContent {
			t.Errorf("%s on %s: %d %s", c.op, c.alias, w.Code, w.Body)
		}
	}
	after := requiredActionAliases(t, h, token)
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Errorf("the order moved:\n got %v\nwant %v", after, before)
	}
}

func requiredActionPriorities(t *testing.T, h http.Handler, token string) map[string]int {
	t.Helper()
	w := get(t, h, authBase+"/required-actions", token)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var rows []struct {
		Alias    string `json:"alias"`
		Priority int    `json:"priority"`
	}
	if err := decodeJSON(w.Body.Bytes(), &rows); err != nil {
		t.Fatalf("parse: %v", err)
	}
	out := map[string]int{}
	for _, r := range rows {
		out[r.Alias] = r.Priority
	}
	return out
}

// TestUpdateRequiredActionRenamesAndDiscardsProviderID pins two of the three
// surprises in PUT /required-actions/{alias}.
//
// The body's alias wins - this is the rename - and providerId is read off the
// wire and thrown away. Measured together on one request, because a body that
// changes both is the only place the difference between them is observable.
func TestUpdateRequiredActionRenamesAndDiscardsProviderID(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	body := `{"alias":"ZZZ","name":"renamed","providerId":"XXX","enabled":true,` +
		`"defaultAction":true,"priority":999,"config":{}}`
	if w := send(t, h, http.MethodPut, authBase+"/required-actions/UPDATE_PROFILE", token, body); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, authBase+"/required-actions/UPDATE_PROFILE", token); w.Code != http.StatusNotFound {
		t.Errorf("the old alias should be gone: %d %s", w.Code, w.Body)
	}
	w := get(t, h, authBase+"/required-actions/ZZZ", token)
	want := `{"alias":"ZZZ","name":"renamed","providerId":"UPDATE_PROFILE",` +
		`"enabled":true,"defaultAction":true,"priority":999,"config":{}}`
	if got := w.Body.String(); got != want {
		t.Errorf("the renamed row:\n got %s\nwant %s", got, want)
	}
}

// TestUpdateWithAnEmptyBodyOrphansTheRow pins Keycloak's own defect.
//
// `PUT {}` is a 204 that renames the row to the empty string. It then answers
// nothing under any alias and stays in the listing as a **six**-key object with
// no `alias` key at all - which also pins that `alias` is omitempty where
// `name` beside it is not.
func TestUpdateWithAnEmptyBodyOrphansTheRow(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	if w := send(t, h, http.MethodPut, authBase+"/required-actions/VERIFY_PROFILE", token, `{}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT {}: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, authBase+"/required-actions/VERIFY_PROFILE", token); w.Code != http.StatusNotFound {
		t.Errorf("the row should be unreachable: %d %s", w.Code, w.Body)
	}
	w := get(t, h, authBase+"/required-actions", token)
	orphan := `{"providerId":"VERIFY_PROFILE","enabled":false,"defaultAction":false,"priority":0,"config":{}}`
	if !strings.Contains(w.Body.String(), orphan) {
		t.Errorf("the orphan is not in the listing in its measured shape:\n%s", w.Body)
	}
	// Priority 0 sorts it first, which is what a reader of the listing sees.
	if got := requiredActionAliases(t, h, token); got[0] != "" {
		t.Errorf("the orphan should sort first, got %v", got)
	}
}

// TestNameIsAbsentWhenUnsetAndPresentWhenEmpty pins the pointer.
//
// A row registered with no `name` reads back with six keys; the same row given
// `""` reads back carrying `"name":""`. A `string` with omitempty collapses
// those two, which is why the field is a `*string`.
func TestNameIsAbsentWhenUnsetAndPresentWhenEmpty(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	if w := send(t, h, http.MethodDelete, authBase+"/required-actions/UPDATE_EMAIL", token, ""); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodPost, authBase+"/register-required-action", token,
		`{"providerId":"UPDATE_EMAIL"}`); w.Code != http.StatusNoContent {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	w := get(t, h, authBase+"/required-actions/UPDATE_EMAIL", token)
	if strings.Contains(w.Body.String(), `"name"`) {
		t.Errorf("a row registered without a name must have no name key:\n%s", w.Body)
	}

	empty := `{"alias":"UPDATE_EMAIL","name":"","providerId":"UPDATE_EMAIL",` +
		`"enabled":true,"defaultAction":false,"priority":1001}`
	if w := send(t, h, http.MethodPut, authBase+"/required-actions/UPDATE_EMAIL", token, empty); w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	w = get(t, h, authBase+"/required-actions/UPDATE_EMAIL", token)
	if !strings.Contains(w.Body.String(), `"name":""`) {
		t.Errorf("a name set to the empty string must be present:\n%s", w.Body)
	}
}

// TestTheTwoConfigWritersDisagreeAboutUnknownKeys pins the asymmetry.
//
// `PUT .../config` filters the config down to the provider's declared property
// names; `PUT` on the representation writes the same field unfiltered. One
// field, two writers, measured on the identical key in both directions.
func TestTheTwoConfigWritersDisagreeAboutUnknownKeys(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPut, authBase+"/required-actions/CONFIGURE_TOTP/config", token,
		`{"config":{"max_auth_age":"700","zzz":"nope"}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT config: %d %s", w.Code, w.Body)
	}
	w = get(t, h, authBase+"/required-actions/CONFIGURE_TOTP/config", token)
	if got, want := w.Body.String(), `{"config":{"max_auth_age":"700"}}`; got != want {
		t.Errorf("the config write must drop undeclared keys:\n got %s\nwant %s", got, want)
	}

	rep := `{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP",` +
		`"enabled":true,"defaultAction":false,"priority":54,` +
		`"config":{"max_auth_age":"111","zzz":"survives"}}`
	if w := send(t, h, http.MethodPut, authBase+"/required-actions/CONFIGURE_TOTP", token, rep); w.Code != http.StatusNoContent {
		t.Fatalf("PUT representation: %d %s", w.Code, w.Body)
	}
	w = get(t, h, authBase+"/required-actions/CONFIGURE_TOTP/config", token)
	want := `{"config":{"max_auth_age":"111","zzz":"survives"}}`
	if got := w.Body.String(); got != want {
		t.Errorf("the representation write must not filter:\n got %s\nwant %s", got, want)
	}
}

// TestStrictDecoderReportsJacksonsColumn pins the location arithmetic.
//
// The column is one past the last character Jackson consumed, and what that is
// depends on the value's token: a number and a literal cost all of themselves,
// while a string, an array and an object cost only their opening character.
// These seven vectors were read off a live 26.7.1 - see strictjson.go - and
// they are here because no golden holds more than one of them.
func TestStrictDecoderReportsJacksonsColumn(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	cases := []struct {
		body   string
		column int
	}{
		{`{"zz":1}`, 8},
		{`{"zz":12}`, 9},
		{`{"zz":"a"}`, 8},
		{`{"zz":null}`, 11},
		{`{"zz":true}`, 11},
		{`{"zz":[1,2]}`, 8},
		{`{"zz":{"a":1}}`, 8},
		{`{ "zz" : 1 }`, 11},
		{`{"zz":1,"alias":"VERIFY_EMAIL"}`, 8},
		{`{"alias":"VERIFY_EMAIL","zz":1}`, 31},
	}
	for _, c := range cases {
		w := send(t, h, http.MethodPut, authBase+"/required-actions/VERIFY_EMAIL", token, c.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", c.body, w.Code)
			continue
		}
		want := `{"error":"Invalid json representation for RequiredActionProviderRepresentation. ` +
			`Unrecognized field \"zz\" at line 1 column ` + itoa(c.column) + `."}`
		if got := w.Body.String(); got != want {
			t.Errorf("%s:\n got %s\nwant %s", c.body, got, want)
		}
	}
}

// TestStrictDecodeRunsBeforeTheAliasIsResolved pins the order between the two
// rejections: a PUT to an alias that does not exist carrying an unknown field
// answers the 400, not the 404.
func TestStrictDecodeRunsBeforeTheAliasIsResolved(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	w := send(t, h, http.MethodPut, authBase+"/required-actions/NOPE", token, `{"zz":1}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "Unrecognized field") {
		t.Errorf("want the decode rejection, got %s", w.Body)
	}
}

// TestRegisterRequiredActionIsNotStrict pins the third write on the tag, which
// is **not** strict where its two neighbours are: an unknown field beside a
// good providerId is a 204.
func TestRegisterRequiredActionIsNotStrict(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	if w := send(t, h, http.MethodDelete, authBase+"/required-actions/idp_link", token, ""); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body)
	}
	w := send(t, h, http.MethodPost, authBase+"/register-required-action", token,
		`{"providerId":"idp_link","zz":1}`)
	if w.Code != http.StatusNoContent {
		t.Errorf("status %d, want 204: %s", w.Code, w.Body)
	}
}

// TestRequiredActionListingAdmitsTheUsersRoles pins the widest read on the tag.
//
// view-users and query-users answer 200 here and 403 on every sibling, and the
// body they get is **byte-identical** to a manage-realm caller's - so this is a
// wider admission and not the "200 with a shorter list" pattern. Measured
// across all 21 roles of the realm's own container.
func TestRequiredActionListingAdmitsTheUsersRoles(t *testing.T) {
	h, s, realm := newServer(t)
	full := get(t, h, authBase+"/required-actions", adminToken(t, h)).Body.String()

	// One token per role: tokenForRole names its user after the role, so asking
	// twice for the same one is a conflict rather than a second caller.
	tokens := map[string]string{}
	for _, role := range []string{"view-realm", "manage-realm", "view-users", "query-users"} {
		tokens[role] = tokenForRole(t, h, s, realm, role)
		w := get(t, h, authBase+"/required-actions", tokens[role])
		if w.Code != http.StatusOK {
			t.Errorf("%s on the listing: %d %s", role, w.Code, w.Body)
			continue
		}
		if w.Body.String() != full {
			t.Errorf("%s got a different body from an administrator", role)
		}
	}
	// The siblings refuse the two users roles, which is what makes the listing
	// a separate role set rather than the tag's.
	for _, role := range []string{"view-users", "query-users"} {
		token := tokens[role]
		for _, path := range []string{
			"/required-actions/CONFIGURE_TOTP",
			"/unregistered-required-actions",
			"/authenticator-providers",
		} {
			if w := get(t, h, authBase+path, token); w.Code != http.StatusForbidden {
				t.Errorf("%s on %s: %d, want 403", role, path, w.Code)
			}
		}
	}
}

// TestUnregisteredCarriesTheProviderNameInSPIOrder pins two things no golden
// can, because a pristine realm's answer here is `[]`.
//
// The `name` is the **provider's** display name and not the deleted row's: a
// row renamed to "MY OWN NAME" and then deleted came back as "Linking Identity
// Provider" on a live 26.7.1.
//
// And the order is the SPI's own, which is neither alphabetical, nor by
// priority, nor the order the rows were deleted in. **All fourteen are
// unregistered** rather than a readable handful, and that is the whole point:
// the first version of this test deleted three, and a mutation swapping
// `TERMS_AND_CONDITIONS` with `update_user_locale` in the seed survived it,
// because only one of that pair was in the answer. Those two are one of the two
// **bucket collisions** in this key set - the exact places `javamap.KeyOrder`
// puts the pair the other way round - so a test that does not hold both
// members of both pairs is not testing the part of the order that is hard.
func TestUnregisteredCarriesTheProviderNameInSPIOrder(t *testing.T) {
	h, _, _ := newServer(t)
	token := adminToken(t, h)

	rename := `{"alias":"idp_link","name":"MY OWN NAME","providerId":"idp_link",` +
		`"enabled":true,"defaultAction":false,"priority":120}`
	if w := send(t, h, http.MethodPut, authBase+"/required-actions/idp_link", token, rename); w.Code != http.StatusNoContent {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	// Deleted in priority order, which the answer is measurably not in.
	for _, alias := range []string{
		"TERMS_AND_CONDITIONS", "UPDATE_PROFILE", "VERIFY_EMAIL", "CONFIGURE_TOTP",
		"UPDATE_PASSWORD", "delete_account", "UPDATE_EMAIL", "webauthn-register",
		"webauthn-register-passwordless", "VERIFY_PROFILE", "delete_credential",
		"idp_link", "CONFIGURE_RECOVERY_AUTHN_CODES", "update_user_locale",
	} {
		if w := send(t, h, http.MethodDelete, authBase+"/required-actions/"+alias, token, ""); w.Code != http.StatusNoContent {
			t.Fatalf("DELETE %s: %d %s", alias, w.Code, w.Body)
		}
	}
	w := get(t, h, authBase+"/unregistered-required-actions", token)
	want := `[{"providerId":"CONFIGURE_TOTP","name":"Configure OTP"},` +
		`{"providerId":"webauthn-register-passwordless","name":"Webauthn Register Passwordless"},` +
		`{"providerId":"UPDATE_PASSWORD","name":"Update Password"},` +
		`{"providerId":"update_user_locale","name":"Update User Locale"},` +
		`{"providerId":"TERMS_AND_CONDITIONS","name":"Terms and Conditions"},` +
		`{"providerId":"idp_link","name":"Linking Identity Provider"},` +
		`{"providerId":"delete_account","name":"Delete Account"},` +
		`{"providerId":"VERIFY_EMAIL","name":"Verify Email"},` +
		`{"providerId":"UPDATE_EMAIL","name":"Update Email"},` +
		`{"providerId":"webauthn-register","name":"Webauthn Register"},` +
		`{"providerId":"VERIFY_PROFILE","name":"Verify Profile"},` +
		`{"providerId":"delete_credential","name":"Delete Credential"},` +
		`{"providerId":"CONFIGURE_RECOVERY_AUTHN_CODES","name":"Recovery Authentication Codes"},` +
		`{"providerId":"UPDATE_PROFILE","name":"Update Profile"}]`
	if got := w.Body.String(); got != want {
		t.Errorf("unregistered:\n got %s\nwant %s", got, want)
	}
	// And the listing beside it is empty, which is what says a delete really
	// unregisters rather than hiding.
	if w := get(t, h, authBase+"/required-actions", token); w.Body.String() != "[]" {
		t.Errorf("required-actions after deleting all fourteen: %s", w.Body)
	}
}

// itoa avoids importing strconv for one call in a table.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
