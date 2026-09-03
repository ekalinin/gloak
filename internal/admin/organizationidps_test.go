package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// createBroker posts one identity provider and returns nothing - every route
// that wants it addresses it by the alias the caller chose.
func createBroker(t *testing.T, h http.Handler, token, alias string) {
	t.Helper()
	body := `{"alias":"` + alias + `","providerId":"oidc","config":{"clientId":"c","clientSecret":"s"}}`
	w := send(t, h, http.MethodPost,
		"/admin/realms/master/identity-provider/instances", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", alias, w.Code, w.Body)
	}
}

// associate posts an alias to an organization's identity provider collection.
func associate(t *testing.T, h http.Handler, token, orgID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/admin/realms/master/organizations/"+orgID+"/identity-providers", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestAnOrganizationIdentityProviderIsAColumnOnTheProvider pins the finding the
// whole family rests on: associating one changes what the **realm's** own read
// of that provider answers, and the delete leaves the provider behind.
func TestAnOrganizationIdentityProviderIsAColumnOnTheProvider(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	orgID := createOrg(t, h, admin,
		`{"name":"gloak-probe-broker-org","alias":"gloak-probe-broker-org-alias"}`)
	createBroker(t, h, admin, "gloak-probe-linked")

	const realmRead = "/admin/realms/master/identity-provider/instances/gloak-probe-linked"
	if body := get(t, h, realmRead, admin).Body.String(); strings.Contains(body, "organizationId") {
		t.Fatalf("before the association: %s", body)
	}

	w := associate(t, h, admin, orgID, `"gloak-probe-linked"`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("associating: %d %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("the association carries no Location; got %q", loc)
	}
	after := get(t, h, realmRead, admin).Body.String()
	if !strings.Contains(after, `"organizationId":"`+orgID+`"`) {
		t.Errorf("the realm's own read should carry organizationId: %s", after)
	}
	// The organization's read is the realm's, byte for byte.
	orgRead := get(t, h,
		"/admin/realms/master/organizations/"+orgID+"/identity-providers/gloak-probe-linked", admin)
	if orgRead.Body.String() != after {
		t.Errorf("the two reads differ:\n%s\n%s", orgRead.Body, after)
	}
	// And organizationId sits between firstBrokerLoginFlowAlias and config.
	if i, j := strings.Index(after, "organizationId"), strings.Index(after, `"config"`); i < 0 || j < 0 || i > j {
		t.Errorf("organizationId should precede config: %s", after)
	}

	del := send(t, h, http.MethodDelete,
		"/admin/realms/master/organizations/"+orgID+"/identity-providers/gloak-probe-linked", admin, "")
	if del.Code != http.StatusNoContent {
		t.Fatalf("removing the association: %d %s", del.Code, del.Body)
	}
	back := get(t, h, realmRead, admin)
	if back.Code != http.StatusOK || strings.Contains(back.Body.String(), "organizationId") {
		t.Errorf("after removing the association: %d %s", back.Code, back.Body)
	}
}

// TestTheOrganizationBrokerErrorsAreFiveSentences pins the family's refusals,
// which disagree with each other on the sentence, the status or both.
func TestTheOrganizationBrokerErrorsAreFiveSentences(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	first := createOrg(t, h, admin, `{"name":"gloak-probe-b1","alias":"gloak-probe-b1-alias"}`)
	second := createOrg(t, h, admin, `{"name":"gloak-probe-b2","alias":"gloak-probe-b2-alias"}`)
	createBroker(t, h, admin, "gloak-probe-shared")

	const (
		unassociated = `{"errorMessage":"Identity provider not associated with the organization"}`
		missing      = `{"errorMessage":"Identity provider not found with the given alias"}`
	)
	base := "/admin/realms/master/organizations/" + first + "/identity-providers"

	// **The read and the delete answer the same missing association with two
	// different sentences.** This is the pair that forbids one helper.
	for _, path := range []string{base + "/gloak-probe-shared", base + "/gloak-probe-shared/groups",
		base + "/gloak-probe-nosuch"} {
		w := get(t, h, path, admin)
		if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != unassociated {
			t.Errorf("GET %s: got %d %s, want 404 %s", path, w.Code, w.Body, unassociated)
		}
	}
	w := send(t, h, http.MethodDelete, base+"/gloak-probe-shared", admin, "")
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != missing {
		t.Errorf("DELETE an unassociated alias: got %d %s, want 404 %s", w.Code, w.Body, missing)
	}

	// The same sentence, as a 400, from the create.
	if w := associate(t, h, admin, first, `"gloak-probe-nosuch"`); w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != missing {
		t.Errorf("associating an unknown alias: got %d %s, want 400 %s", w.Code, w.Body, missing)
	}
	if w := associate(t, h, admin, first, ``); w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != missing {
		t.Errorf("an empty body: got %d %s, want 400 %s", w.Code, w.Body, missing)
	}

	if w := associate(t, h, admin, first, `"gloak-probe-shared"`); w.Code != http.StatusNoContent {
		t.Fatalf("associating: %d %s", w.Code, w.Body)
	}
	// The two near-identical sentences, one preposition apart.
	const already = `{"errorMessage":"Identity provider already associated to the organization"}`
	const elsewhere = `{"errorMessage":"Identity provider already associated with a different organization"}`
	if w := associate(t, h, admin, first, `"gloak-probe-shared"`); w.Code != http.StatusConflict ||
		strings.TrimSpace(w.Body.String()) != already {
		t.Errorf("associating twice: got %d %s, want 409 %s", w.Code, w.Body, already)
	}
	if w := associate(t, h, admin, second, `"gloak-probe-shared"`); w.Code != http.StatusBadRequest ||
		strings.TrimSpace(w.Body.String()) != elsewhere {
		t.Errorf("associating elsewhere: got %d %s, want 400 %s", w.Code, w.Body, elsewhere)
	}

	// The Content-Type rule is the member add's: a wrong one is a 415 and an
	// absent one is accepted, so this request reaches the duplicate check.
	req := httptest.NewRequest(http.MethodPost, base, strings.NewReader(`"gloak-probe-shared"`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer "+admin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: got %d %s, want 415", rec.Code, rec.Body)
	}
	req = httptest.NewRequest(http.MethodPost, base, strings.NewReader(`"gloak-probe-shared"`))
	req.Header.Set("Authorization", "Bearer "+admin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("no Content-Type: got %d %s, want the 409 - an absent header is accepted", rec.Code, rec.Body)
	}
}

// TestABrokerCreateCanNameItsOrganization is the correction this cut made to a
// rule the repository had written down from a realm where it could not hold.
//
// `organizationId` on `POST` and `PUT .../identity-provider/instances` was
// recorded as "a 400 for any value including the empty string". That was
// measured on master, where organizations are off and no organization exists,
// so every value the probe could try resolved to nothing. In a realm with the
// flag on, a **real** id is a 201 and associates the provider.
func TestABrokerCreateCanNameItsOrganization(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	orgID := createOrg(t, h, admin, `{"name":"gloak-probe-bc","alias":"gloak-probe-bc-alias"}`)

	const refused = `{"errorMessage":"Organization associated with broker does not exist"}`
	for i, value := range []string{"", "nosuchorg", "11111111-2222-3333-4444-555555555555"} {
		body := `{"alias":"gloak-probe-bad-` + string(rune('a'+i)) +
			`","providerId":"oidc","organizationId":"` + value + `"}`
		w := send(t, h, http.MethodPost, "/admin/realms/master/identity-provider/instances", admin, body)
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != refused {
			t.Errorf("organizationId=%q: got %d %s, want 400 %s", value, w.Code, w.Body, refused)
		}
	}

	body := `{"alias":"gloak-probe-born","providerId":"oidc","organizationId":"` + orgID + `"}`
	if w := send(t, h, http.MethodPost, "/admin/realms/master/identity-provider/instances", admin, body); w.Code != http.StatusCreated {
		t.Fatalf("a real organizationId: got %d %s, want 201", w.Code, w.Body)
	}
	listing := get(t, h, "/admin/realms/master/organizations/"+orgID+"/identity-providers", admin)
	if !strings.Contains(listing.Body.String(), "gloak-probe-born") {
		t.Errorf("the create should have associated it: %s", listing.Body)
	}

	// **A PUT carrying no organizationId keeps the association**, where it
	// replaces everything else - the config is emptied by the same request.
	put := `{"alias":"gloak-probe-born","providerId":"oidc","displayName":"touched"}`
	if w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-born", admin, put); w.Code != http.StatusNoContent {
		t.Fatalf("the update: %d %s", w.Code, w.Body)
	}
	after := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-born", admin).Body.String()
	if !strings.Contains(after, `"organizationId":"`+orgID+`"`) || !strings.Contains(after, `"displayName":"touched"`) {
		t.Errorf("after the update: %s", after)
	}

	// And a PUT that names one associates a provider that had none.
	createBroker(t, h, admin, "gloak-probe-late")
	late := `{"alias":"gloak-probe-late","providerId":"oidc","organizationId":"` + orgID + `"}`
	if w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-late", admin, late); w.Code != http.StatusNoContent {
		t.Fatalf("the late update: %d %s", w.Code, w.Body)
	}
	if body := get(t, h, "/admin/realms/master/organizations/"+orgID+"/identity-providers", admin).Body.String(); !strings.Contains(body, "gloak-probe-late") {
		t.Errorf("the update should have associated it: %s", body)
	}
	// briefRepresentation=true drops organizationId, which makes it a ninth
	// thing that parameter drops.
	brief := get(t, h, "/admin/realms/master/identity-provider/instances?briefRepresentation=true", admin)
	if strings.Contains(brief.Body.String(), "organizationId") {
		t.Errorf("the brief listing should drop organizationId: %s", brief.Body)
	}
}

// TestTheInvitationFamilyIsEmptyAndItsInvitesAre500 pins the four invitation
// routes and the two invite endpoints, whose reachable half is all validation.
func TestTheInvitationFamilyIsEmptyAndItsInvitesAre500(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	enableOrganizations(t, h, admin, "master")
	orgID := createOrg(t, h, admin, `{"name":"gloak-probe-inv","alias":"gloak-probe-inv-alias"}`)
	base := "/admin/realms/master/organizations/" + orgID

	listing := get(t, h, base+"/invitations", admin)
	if listing.Code != http.StatusOK || strings.TrimSpace(listing.Body.String()) != "[]" {
		t.Errorf("the listing: got %d %s, want 200 []", listing.Code, listing.Body)
	}
	// **No Cache-Control**, where every other read in the tag carries one.
	if cc := listing.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("the invitations listing carries no Cache-Control; got %q", cc)
	}
	if cc := get(t, h, base+"/members", admin).Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("the member listing should carry no-cache; got %q", cc)
	}

	const notFound = `{"errorMessage":"Invitation not found"}`
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, base + "/invitations/anything"},
		{http.MethodDelete, base + "/invitations/anything"},
		{http.MethodPost, base + "/invitations/anything/resend"},
	} {
		w := send(t, h, c.method, c.path, admin, "")
		if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != notFound {
			t.Errorf("%s %s: got %d %s, want 404 %s", c.method, c.path, w.Code, w.Body, notFound)
		}
	}
}

// TestTheTwoInviteEndpointsDisagreeAboutEverything is the finding: two sibling
// endpoints, and their missing-field errors are in two different error
// families, one refuses a member and the other does not.
func TestTheTwoInviteEndpointsDisagreeAboutEverything(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	orgID, userID := orgMemberFixture(t, h, admin)
	if w := addMember(t, h, admin, orgID, userID); w.Code != http.StatusCreated {
		t.Fatalf("adding the member: %d %s", w.Code, w.Body)
	}
	base := "/admin/realms/master/organizations/" + orgID + "/members"

	form := func(path string, values url.Values, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	const urlencoded = "application/x-www-form-urlencoded"
	const sendFailed = `{"errorMessage":"Failed to send invite email"}`

	// invite-user: the errorMessage family for a missing field.
	for _, values := range []url.Values{{}, {"email": {""}}} {
		w := form(base+"/invite-user", values, urlencoded)
		const want = `{"errorMessage":"Email is required to invite a member"}`
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("invite-user %v: got %d %s, want 400 %s", values, w.Code, w.Body, want)
		}
	}
	// It refuses a member's e-mail, with a sentence that is not the member
	// add's: no full stop, and "already a member" rather than "is already".
	w := form(base+"/invite-user", url.Values{"email": {"bravo@example.com"}}, urlencoded)
	const member = `{"errorMessage":"User already a member of the organization"}`
	if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != member {
		t.Errorf("invite-user for a member: got %d %s, want 409 %s", w.Code, w.Body, member)
	}
	// Anything else reaches the mail sender that is not there.
	w = form(base+"/invite-user", url.Values{"email": {"stranger@example.com"}}, urlencoded)
	if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != sendFailed {
		t.Errorf("invite-user for a stranger: got %d %s, want 500 %s", w.Code, w.Body, sendFailed)
	}
	// **Without the form Content-Type the body is not read at all**, so the
	// request answers about the field it is then missing rather than 415. The
	// member add beside it can answer 415 and these two cannot.
	for _, ct := range []string{"", "application/json"} {
		w := form(base+"/invite-user", url.Values{"email": {"stranger@example.com"}}, ct)
		const want = `{"errorMessage":"Email is required to invite a member"}`
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("invite-user with Content-Type %q: got %d %s, want 400 %s", ct, w.Code, w.Body, want)
		}
	}

	// invite-existing-user: the **error** family for a missing field.
	for _, values := range []url.Values{{}, {"id": {""}}} {
		w := form(base+"/invite-existing-user", values, urlencoded)
		const want = `{"error":"To invite a member you need to provide the user id"}`
		if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
			t.Errorf("invite-existing-user %v: got %d %s, want 400 %s", values, w.Code, w.Body, want)
		}
	}
	w = form(base+"/invite-existing-user", url.Values{"id": {"nosuch"}}, urlencoded)
	const noUser = `{"errorMessage":"User does not exist"}`
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != noUser {
		t.Errorf("invite-existing-user with an unknown id: got %d %s, want 400 %s", w.Code, w.Body, noUser)
	}
	bare := createOrgUser(t, h, admin, "gloak-probe-emailless", "", "", "")
	w = form(base+"/invite-existing-user", url.Values{"id": {bare}}, urlencoded)
	const noEmail = `{"errorMessage":"User does not have an email address"}`
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != noEmail {
		t.Errorf("invite-existing-user for a user with no e-mail: got %d %s, want 400 %s", w.Code, w.Body, noEmail)
	}
	// **It does not check membership.** The same person invite-user refuses
	// with a 409 reaches the mail sender here.
	w = form(base+"/invite-existing-user", url.Values{"id": {userID}}, urlencoded)
	if w.Code != http.StatusInternalServerError || strings.TrimSpace(w.Body.String()) != sendFailed {
		t.Errorf("invite-existing-user for a member: got %d %s, want 500 %s", w.Code, w.Body, sendFailed)
	}
}
