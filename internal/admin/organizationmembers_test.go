package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// orgMemberFixture turns organizations on, makes one organization and one user,
// and returns the two ids. The username and the e-mail deliberately share no
// substring with each other, so a handler that searched the wrong field cannot
// pass by accident.
func orgMemberFixture(t *testing.T, h http.Handler, token string) (orgID, userID string) {
	t.Helper()
	enableOrganizations(t, h, token, "master")
	orgID = createOrg(t, h, token,
		`{"name":"gloak-probe-member-org","alias":"gloak-probe-member-alias"}`)
	userID = createOrgUser(t, h, token, "gloak-probe-alpha", "bravo@example.com", "Charlie", "Delta")
	return orgID, userID
}

// createOrgUser posts a user and returns the id its Location names.
func createOrgUser(t *testing.T, h http.Handler, token, username, email, first, last string) string {
	t.Helper()
	body := `{"username":"` + username + `","email":"` + email +
		`","firstName":"` + first + `","lastName":"` + last + `","enabled":true}`
	w := send(t, h, http.MethodPost, "/admin/realms/master/users", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", username, w.Code, w.Body)
	}
	loc := w.Header().Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:]
}

// addMember posts a user id to the member collection with the raw body the
// endpoint really takes.
func addMember(t *testing.T, h http.Handler, token, orgID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/admin/realms/master/organizations/"+orgID+"/members", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestTheMemberAddReadsARawUserIDRatherThanJSON pins the body rule, which is
// the one decision the whole family rests on.
//
// **The body is not JSON.** Measured over ten bodies on 2026-09-02; a handler
// that calls json.Unmarshal is right on the quoted form and wrong on the four
// unquoted ones that succeed, and a handler that strips every quote is wrong on
// the two that fail.
func TestTheMemberAddReadsARawUserIDRatherThanJSON(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, _ := orgMemberFixture(t, h, admin)

	accepted := []struct{ name, tmpl string }{
		{"quoted", `"%s"`},
		{"unquoted", `%s`},
		{"one leading quote", `"%s`},
		{"one trailing quote", `%s"`},
		{"surrounding spaces", `  %s  `},
		{"a trailing newline", "%s\n"},
	}
	for _, c := range accepted {
		u := createOrgUser(t, h, admin, "gloak-probe-ok-"+strings.ReplaceAll(c.name, " ", "-"),
			"", "", "")
		body := strings.Replace(c.tmpl, "%s", u, 1)
		if w := addMember(t, h, admin, orgID, body); w.Code != http.StatusCreated {
			t.Errorf("%s (%q): got %d %s, want 201", c.name, body, w.Code, w.Body)
		}
	}

	refused := []struct{ name, tmpl string }{
		{"a quote in the middle", `%s`},
		{"two quotes each end", `""%s""`},
		{"single quotes", `'%s'`},
		{"a JSON array", `["%s"]`},
		{"a UserRepresentation", `{"id":"%s"}`},
	}
	for _, c := range refused {
		u := createOrgUser(t, h, admin, "gloak-probe-no-"+strings.ReplaceAll(c.name, " ", "-"),
			"", "", "")
		body := strings.Replace(c.tmpl, "%s", u, 1)
		if c.name == "a quote in the middle" {
			body = u[:8] + `"` + u[8:]
		}
		w := addMember(t, h, admin, orgID, body)
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("%s (%q): got %d %s, want 404 the generic body", c.name, body, w.Code, w.Body)
		}
	}
}

// TestTheMemberAddRefusesAnAbsentContentType is F149's rule measured on this
// route, and it is the opposite of the one requireJSONBody carries.
//
// The scope mappings accept a write with no Content-Type; this one answers 415.
// One API, two answers, and a single shared helper would get one of them wrong.
func TestTheMemberAddRefusesAnAbsentContentType(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)

	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/xml"} {
		req := httptest.NewRequest(http.MethodPost,
			"/admin/realms/master/organizations/"+orgID+"/members", strings.NewReader(userID))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		const want = `{"error":"The content-type header value did not match the value in @Consumes"}`
		if w.Code != http.StatusUnsupportedMediaType || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("Content-Type %q: got %d %s, want 415 %s", ct, w.Code, w.Body, want)
		}
	}
	// And the one it does accept.
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Errorf("application/json: got %d %s, want 201", w.Code, w.Body)
	}
}

// TestTheMemberListingPagesByDefault is the finding no other listing in this
// API shares: with no parameters at all it answers ten rows.
func TestTheMemberListingPagesByDefault(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding the fixture member: %d %s", w.Code, w.Body)
	}
	for i := 0; i < 11; i++ {
		u := createOrgUser(t, h, admin, "gloak-probe-page-"+string(rune('a'+i)), "", "", "")
		if w := addMember(t, h, admin, orgID, u); w.Code != http.StatusCreated {
			t.Fatalf("adding member %d: %d %s", i, w.Code, w.Body)
		}
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members"
	for _, c := range []struct {
		query string
		want  int
	}{
		{"", 10},
		{"?max=100", 12},
		{"?max=-1", 12},
		{"?first=-1", 10},
		{"?max=0", 0},
		{"?first=11&max=100", 1},
		{"?first=100", 0},
	} {
		var rows []map[string]any
		w := get(t, h, base+c.query, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %v", c.query, err)
		}
		if len(rows) != c.want {
			t.Errorf("%q: got %d rows, want %d", c.query, len(rows), c.want)
		}
	}
}

// TestTheMemberSearchIsASubstringWhereTheUserListingsIsAPrefix issues the two
// requests that separate the two rules, against one realm holding one user.
//
// This is the pair that was measured side by side on the reference container,
// and it is the reason organizationMemberMatches does not call matchesSearch.
func TestTheMemberSearchIsASubstringWhereTheUserListingsIsAPrefix(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding the member: %d %s", w.Code, w.Body)
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members"

	count := func(path string) int {
		var rows []map[string]any
		w := get(t, h, path, admin)
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s: %d %s: %v", path, w.Code, w.Body, err)
		}
		return len(rows)
	}

	// The username is gloak-probe-alpha; "robe-alpha" sits inside it and is not
	// a prefix of it, which is the whole separation.
	if n := count(base + "?search=robe-alpha"); n != 1 {
		t.Errorf("members ?search=robe-alpha: got %d rows, want 1", n)
	}
	if n := count("/admin/realms/master/users?search=robe-alpha"); n != 0 {
		t.Errorf("users ?search=robe-alpha: got %d rows, want 0 - the user listing is a prefix", n)
	}

	for _, c := range []struct {
		query string
		want  int
	}{
		{"?search=gloak-probe-alpha", 1},
		{"?search=GLOAK-PROBE-ALPHA", 1},
		{"?search=Charlie", 1},             // firstName
		{"?search=Delta", 1},               // lastName
		{"?search=bravo@ex", 1},            // email, and an infix of it
		{"?search=*obe*alp*", 1},           // * is the wildcard
		{"?search=%25obe%25", 0},           // % is a literal, not a SQL wildcard
		{"?search=_lpha", 0},               // _ is a literal
		{"?search=" + userID, 0},           // the id is not a search field
		{`?search="gloak-probe-alpha"`, 0}, // quotes do not mean equality here
		{"?search=gloak-probe-alpha&exact=true", 1},
		{"?search=robe-alpha&exact=true", 0},
		{"?search=Charlie&exact=true", 1},
		{"?search=bravo@example.com&exact=true", 1},
		{"?search=robe-alpha&exact=bogus", 1},
		{"?membershipType=UNMANAGED", 1},
		{"?membershipType=MANAGED", 0},
	} {
		if n := count(base + c.query); n != c.want {
			t.Errorf("%q: got %d rows, want %d", c.query, n, c.want)
		}
	}
}

// TestTheMemberCountIgnoresEveryFilter pins the disagreement between the two
// counts on one resource: the organization count honours its search and this
// one honours nothing.
func TestTheMemberCountIgnoresEveryFilter(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	second := createOrgUser(t, h, admin, "gloak-probe-second", "", "", "")
	for _, u := range []string{userID, second} {
		if w := addMember(t, h, admin, orgID, u); w.Code != http.StatusCreated {
			t.Fatalf("adding %s: %d %s", u, w.Code, w.Body)
		}
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members/count"
	for _, query := range []string{"", "?search=gloak-probe-alpha", "?membershipType=MANAGED",
		"?max=1", "?first=1", "?exact=true&search=nothing"} {
		w := get(t, h, base+query, admin)
		if strings.TrimSpace(w.Body.String()) != "2" {
			t.Errorf("count%s: got %s, want 2", query, w.Body)
		}
	}
	// The organization count next door does read its search, which is what
	// makes the two disagree rather than both being unfiltered.
	w := get(t, h, "/admin/realms/master/organizations/count?search=nothing-matches", admin)
	if strings.TrimSpace(w.Body.String()) != "0" {
		t.Errorf("the organization count: got %s, want 0", w.Body)
	}
}

// TestTheMemberFamilyNeedsARoleFromEachOfTwoFamilies is the guard, and no
// golden can see it because a golden has one caller.
//
// **No single role opens any of these routes.** That is measured, and it makes
// this family the second in the API to need a conjunction.
func TestTheMemberFamilyNeedsARoleFromEachOfTwoFamilies(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding the member: %d %s", w.Code, w.Body)
	}
	spare := createOrgUser(t, h, admin, "gloak-probe-spare", "", "", "")

	base := "/admin/realms/master/organizations/" + orgID
	callers := map[string]string{
		"none":    tokenForRoles(t, h, s, realm),
		"vo":      tokenForRoles(t, h, s, realm, "view-organizations"),
		"mo":      tokenForRoles(t, h, s, realm, "manage-organizations"),
		"vu":      tokenForRoles(t, h, s, realm, "view-users"),
		"mu":      tokenForRoles(t, h, s, realm, "manage-users"),
		"vo+vu":   tokenForRoles(t, h, s, realm, "view-organizations", "view-users"),
		"vo+qu":   tokenForRoles(t, h, s, realm, "view-organizations", "query-users"),
		"vo+mu":   tokenForRoles(t, h, s, realm, "view-organizations", "manage-users"),
		"mo+mu":   tokenForRoles(t, h, s, realm, "manage-organizations", "manage-users"),
		"mr+vu":   tokenForRoles(t, h, s, realm, "manage-realm", "view-users"),
		"mr+mu":   tokenForRoles(t, h, s, realm, "manage-realm", "manage-users"),
		"vr+vu":   tokenForRoles(t, h, s, realm, "view-realm", "view-users"),
		"qo+vu":   tokenForRoles(t, h, s, realm, "query-organizations", "view-users"),
		"vo+vidp": tokenForRoles(t, h, s, realm, "view-organizations", "view-identity-providers"),
		"mo+midp": tokenForRoles(t, h, s, realm, "manage-organizations", "manage-identity-providers"),
		"mo+vidp": tokenForRoles(t, h, s, realm, "manage-organizations", "view-identity-providers"),
		"vo+midp": tokenForRoles(t, h, s, realm, "view-organizations", "manage-identity-providers"),
	}

	reads := []struct {
		path    string
		allowed []string
	}{
		{base + "/members", []string{"vo+vu", "vo+qu", "vo+mu", "mo+mu", "mr+vu", "mr+mu"}},
		{base + "/members/count", []string{"vo+vu", "vo+qu", "vo+mu", "mo+mu", "mr+vu", "mr+mu"}},
		{base + "/members/" + userID, []string{"vo+vu", "vo+mu", "mo+mu", "mr+vu", "mr+mu"}},
		{base + "/members/" + userID + "/groups", []string{"vo+vu", "vo+mu", "mo+mu", "mr+vu", "mr+mu"}},
		{base + "/members/" + userID + "/organizations", []string{"vo+vu", "vo+mu", "mo+mu", "mr+vu", "mr+mu"}},
		{base + "/invitations", []string{"mo", "mo+mu", "mr+vu", "mr+mu", "mo+midp", "mo+vidp"}},
		{base + "/identity-providers", []string{"vo+vidp", "mo+midp", "mo+vidp", "vo+midp"}},
	}
	for _, r := range reads {
		allowed := map[string]bool{}
		for _, name := range r.allowed {
			allowed[name] = true
		}
		for name, token := range callers {
			w := get(t, h, r.path, token)
			if allowed[name] && w.Code == http.StatusForbidden {
				t.Errorf("GET %s as %s: got 403, want it opened", r.path, name)
			}
			if !allowed[name] && w.Code != http.StatusForbidden {
				t.Errorf("GET %s as %s: got %d %s, want 403", r.path, name, w.Code, w.Body)
			}
		}
	}

	// The writes need the manage role of both families. mr+vu is refused here
	// and opens every read above, which is what says the two guards differ.
	for name, token := range callers {
		w := addMember(t, h, token, orgID, spare)
		wantAllowed := name == "mo+mu" || name == "mr+mu"
		if wantAllowed && w.Code == http.StatusForbidden {
			t.Errorf("POST members as %s: got 403, want it opened", name)
		}
		if !wantAllowed && w.Code != http.StatusForbidden {
			t.Errorf("POST members as %s: got %d %s, want 403", name, w.Code, w.Body)
		}
		if w.Code == http.StatusCreated {
			send(t, h, http.MethodDelete, base+"/members/"+spare, admin, "")
		}
	}
}

// TestAMemberIsAUserAndTheDeleteSparesIt pins the two cascade directions the
// wire shows: removing a membership leaves the user, and deleting the user
// removes the membership.
func TestAMemberIsAUserAndTheDeleteSparesIt(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	base := "/admin/realms/master/organizations/" + orgID + "/members"
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding: %d %s", w.Code, w.Body)
	}

	if w := send(t, h, http.MethodDelete, base+"/"+userID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("removing: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, "/admin/realms/master/users/"+userID, admin); w.Code != http.StatusOK {
		t.Errorf("the user after the membership went: got %d, want 200", w.Code)
	}
	// Not idempotent, and a non-member is the same 404 as a stranger.
	for _, path := range []string{base + "/" + userID, base + "/11111111-2222-3333-4444-555555555555"} {
		w := send(t, h, http.MethodDelete, path, admin, "")
		if w.Code != http.StatusNotFound ||
			strings.TrimSpace(w.Body.String()) != `{"error":"HTTP 404 Not Found"}` {
			t.Errorf("DELETE %s: got %d %s, want the generic 404", path, w.Code, w.Body)
		}
	}

	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("re-adding: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, "/admin/realms/master/users/"+userID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("deleting the user: %d %s", w.Code, w.Body)
	}
	var rows []map[string]any
	w := get(t, h, base, admin)
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || len(rows) != 0 {
		t.Errorf("after deleting the user: got %s, want []", w.Body)
	}
}

// TestTheMemberSingleReadIgnoresBriefRepresentation pins the pair of shapes and
// the parameter that reaches one route of the two.
func TestTheMemberSingleReadIgnoresBriefRepresentation(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding: %d %s", w.Code, w.Body)
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members"

	brief := get(t, h, base, admin).Body.String()
	full := get(t, h, base+"?briefRepresentation=false", admin).Body.String()
	explicitBrief := get(t, h, base+"?briefRepresentation=true", admin).Body.String()
	if brief != explicitBrief {
		t.Errorf("the listing's default is not briefRepresentation=true:\n%s\n%s", brief, explicitBrief)
	}
	if brief == full {
		t.Fatalf("briefRepresentation=false changed nothing: %s", full)
	}
	for _, key := range []string{"totp", "disableableCredentialTypes", "requiredActions", "notBefore"} {
		if strings.Contains(brief, key) {
			t.Errorf("the brief shape should not carry %s: %s", key, brief)
		}
		if !strings.Contains(full, key) {
			t.Errorf("the full shape should carry %s: %s", key, full)
		}
	}
	if !strings.Contains(brief, `"membershipType":"UNMANAGED"`) {
		t.Errorf("membershipType is missing from the brief shape: %s", brief)
	}

	single := get(t, h, base+"/"+userID, admin).Body.String()
	if single != get(t, h, base+"/"+userID+"?briefRepresentation=true", admin).Body.String() {
		t.Error("the single read should ignore briefRepresentation")
	}
	// The single read is a full listing entry, byte for byte.
	if full != "["+single+"]" {
		t.Errorf("the single read is not the full listing entry:\n%s\n%s", single, full)
	}
	// Neither carries the caller's access block.
	if strings.Contains(full, `"access"`) {
		t.Errorf("a member should carry no access block: %s", full)
	}
}

// TestTheMemberOrganizationsReadRefusesANonMember pins the org-scoped
// `.../organizations` route's 404, which is the half its unserved top-level
// twin does not share.
func TestTheMemberOrganizationsReadRefusesANonMember(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	stranger := createOrgUser(t, h, admin, "gloak-probe-outsider", "", "", "")
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding: %d %s", w.Code, w.Body)
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members/"

	w := get(t, h, base+userID+"/organizations", admin)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "gloak-probe-member-org") {
		t.Errorf("a member's organizations: got %d %s", w.Code, w.Body)
	}
	// The brief shape by default, the full one on request.
	if strings.Contains(w.Body.String(), `"attributes"`) {
		t.Errorf("the default should be the brief shape: %s", w.Body)
	}
	if full := get(t, h, base+userID+"/organizations?briefRepresentation=false", admin); !strings.Contains(full.Body.String(), `"attributes"`) {
		t.Errorf("briefRepresentation=false should add attributes: %s", full.Body)
	}
	for _, path := range []string{stranger + "/organizations", stranger + "/groups",
		"11111111-2222-3333-4444-555555555555/organizations"} {
		if w := get(t, h, base+path, admin); w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d %s, want 404", path, w.Code, w.Body)
		}
	}
	// A member's organization groups are always empty: the group family is
	// F120's and nothing can create one.
	if w := get(t, h, base+userID+"/groups", admin); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("a member's groups: got %s, want []", w.Body)
	}
}
