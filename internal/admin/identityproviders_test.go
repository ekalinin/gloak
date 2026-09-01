package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// createIDP posts one provider and fails the test if it is not a 201. It
// returns the Location, whose tail is the **alias** rather than an id - which
// is what the tail assertion below is about.
func createIDP(t *testing.T, h http.Handler, token, body string) string {
	t.Helper()
	w := send(t, h, http.MethodPost, "/admin/realms/master/identity-provider/instances", token, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("creating %s: %d %s", body, w.Code, w.Body)
	}
	return w.Header().Get("Location")
}

// TestIdentityProviderCreateAndRead pins the representation a create produces,
// byte for byte, on the two bodies that differ in every rule the type has.
//
// The minimal body is the one that says the six flags are **absent** rather
// than false, and the full body is the one that says `""` on displayName is
// **kept** where the same emptiness on those flags is not a state at all. Both
// come from the same container on 2026-09-01.
func TestIdentityProviderCreateAndRead(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	createIDP(t, h, admin, `{"alias":"gloak-probe-min","providerId":"oidc"}`)
	w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-min", admin)
	got := strings.TrimSpace(w.Body.String())
	// internalId is minted, so it is cut out and the rest compared exactly.
	const wantMin = `"providerId":"oidc","enabled":true,"config":{},` +
		`"types":["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL",` +
		`"EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]}`
	if !strings.HasPrefix(got, `{"alias":"gloak-probe-min","internalId":"`) || !strings.HasSuffix(got, wantMin) {
		t.Errorf("minimal create reads back as %s", got)
	}

	// The full body. internalId is named, so the whole body is asserted - and
	// naming it is itself the measurement: the body's id wins on this endpoint.
	createIDP(t, h, admin, `{"alias":"gloak-probe-full","displayName":"Full Probe",`+
		`"internalId":"11111111-1111-1111-1111-111111111111","providerId":"oidc",`+
		`"enabled":true,"updateProfileFirstLoginMode":"on","trustEmail":true,`+
		`"storeToken":true,"addReadTokenRoleOnCreate":true,"authenticateByDefault":true,`+
		`"linkOnly":true,"hideOnLogin":true,"firstBrokerLoginFlowAlias":"first broker login",`+
		`"postBrokerLoginFlowAlias":"",`+
		`"config":{"clientId":"cid","clientSecret":"csecret",`+
		`"authorizationUrl":"https://example.com/auth","tokenUrl":"https://example.com/token"}}`)
	w = get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-full", admin)
	const wantFull = `{"alias":"gloak-probe-full","displayName":"Full Probe",` +
		`"internalId":"11111111-1111-1111-1111-111111111111","providerId":"oidc",` +
		`"enabled":true,"trustEmail":true,"storeToken":true,"addReadTokenRoleOnCreate":true,` +
		`"authenticateByDefault":true,"linkOnly":true,"hideOnLogin":true,` +
		`"firstBrokerLoginFlowAlias":"first broker login",` +
		`"config":{"clientSecret":"**********","clientId":"cid",` +
		`"tokenUrl":"https://example.com/token","authorizationUrl":"https://example.com/auth"},` +
		`"types":["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL",` +
		`"EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]}`
	if got := strings.TrimSpace(w.Body.String()); got != wantFull {
		t.Errorf("full create reads back as\n %s\nwant\n %s", got, wantFull)
	}
}

// TestIdentityProviderConfigKeyOrderIsTheSizedHashMap is the assertion that
// separates this family from the components one.
//
// `{clientId, clientSecret, authorizationUrl, tokenUrl}` comes back
// `clientSecret, clientId, tokenUrl, authorizationUrl` - which is
// javamap.SizedKeyOrder's answer and **not** javamap.KeyOrder's, which puts
// clientId first. The two-key case is the shortest one that tells them apart
// and it is here for that reason: a serialiser using the wrong constructor
// passes every other test in this file.
func TestIdentityProviderConfigKeyOrderIsTheSizedHashMap(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct{ alias, config, want string }{
		{"two", `{"clientId":"cid","clientSecret":"s"}`,
			`{"clientSecret":"**********","clientId":"cid"}`},
		{"four", `{"clientId":"cid","clientSecret":"s","authorizationUrl":"https://x/a","tokenUrl":"https://x/t"}`,
			`{"clientSecret":"**********","clientId":"cid","tokenUrl":"https://x/t","authorizationUrl":"https://x/a"}`},
		{"seven", `{"clientId":"1","clientSecret":"2","authorizationUrl":"https://x/a",` +
			`"tokenUrl":"https://x/t","userInfoUrl":"https://x/u","logoutUrl":"https://x/l","issuer":"https://x"}`,
			`{"userInfoUrl":"https://x/u","clientId":"1","tokenUrl":"https://x/t",` +
				`"authorizationUrl":"https://x/a","logoutUrl":"https://x/l",` +
				`"clientSecret":"**********","issuer":"https://x"}`},
	} {
		createIDP(t, h, admin, `{"alias":"gloak-probe-`+tc.alias+`","providerId":"oidc","config":`+tc.config+`}`)
		w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-"+tc.alias, admin)
		var body struct {
			Config json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", tc.alias, err)
		}
		if string(body.Config) != tc.want {
			t.Errorf("%s config: got %s, want %s", tc.alias, body.Config, tc.want)
		}
	}
}

// TestIdentityProviderLocationEndsInTheAlias pins a name tail rather than a
// uuid tail, which is the whole reason this create is not in
// Case.VolatileTailHeaders.
func TestIdentityProviderLocationEndsInTheAlias(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	loc := createIDP(t, h, admin, `{"alias":"gloak-probe-loc","providerId":"github"}`)
	if !strings.HasSuffix(loc, "/admin/realms/master/identity-provider/instances/gloak-probe-loc") {
		t.Errorf("Location %q does not end in the alias", loc)
	}
}

// TestIdentityProviderTypesFollowTheProvider pins all four measured answers.
// A boolean "is it OIDC" reproduces two of them and gets the other two wrong.
func TestIdentityProviderTypesFollowTheProvider(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct{ provider, want string }{
		{"oidc", `["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL","EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]`},
		{"keycloak-oidc", `["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL","EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]`},
		{"saml", `["USER_AUTHENTICATION"]`},
		{"kubernetes", `["CLIENT_ASSERTION"]`},
		{"github", `[]`},
		{"google", `[]`},
		{"oauth2", `[]`},
	} {
		createIDP(t, h, admin, `{"alias":"gloak-probe-t-`+tc.provider+`","providerId":"`+tc.provider+`"}`)
		w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-t-"+tc.provider, admin)
		var body struct {
			Types json.RawMessage `json:"types"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", tc.provider, err)
		}
		if string(body.Types) != tc.want {
			t.Errorf("%s types: got %s, want %s", tc.provider, body.Types, tc.want)
		}
	}
}

// TestIdentityProviderCreateRefusals pins the five measured 400s and the 409,
// each of which is a different shape.
func TestIdentityProviderCreateRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-taken","providerId":"oidc"}`)

	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"no alias", `{"providerId":"oidc"}`, 400, `{"errorMessage":"path is null"}`},
		{"empty alias", `{"alias":"","providerId":"oidc"}`, 400, `{"errorMessage":"path is null"}`},
		{"no providerId", `{"alias":"gloak-probe-x"}`, 400,
			`{"errorMessage":"Invalid identity provider id [null]"}`},
		{"unknown providerId", `{"alias":"gloak-probe-x","providerId":"nonesuch"}`, 400,
			`{"errorMessage":"Invalid identity provider id [nonesuch]"}`},
		{"organizationId", `{"alias":"gloak-probe-x","providerId":"oidc","organizationId":""}`, 400,
			`{"errorMessage":"Organization associated with broker does not exist"}`},
		{"duplicate", `{"alias":"gloak-probe-taken","providerId":"oidc"}`, 409,
			`{"errorMessage":"Identity Provider gloak-probe-taken already exists"}`},
		{"unknown field", `{"alias":"gloak-probe-x","providerId":"oidc","zzz":1}`, 400,
			`{"error":"Invalid json representation for IdentityProviderRepresentation. Unrecognized field \"zzz\" at line 1 column 53."}`},
		{"malformed", `{`, 400,
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
	} {
		w := send(t, h, http.MethodPost, "/admin/realms/master/identity-provider/instances", admin, tc.body)
		if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("%s: got %d %s, want %d %s", tc.name, w.Code, w.Body, tc.status, tc.want)
		}
	}
}

// TestIdentityProviderCreateOrdersItsChecks is the half of the refusals that a
// one-fault-at-a-time table cannot see.
//
// Each row breaks two things at once and names which of the two answers.
// **organizationId beats a missing alias**, which is why a body carrying both
// is the probe: it is the only request that distinguishes the measured order
// from the obvious one, where a presence check would come first.
func TestIdentityProviderCreateOrdersItsChecks(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	for _, tc := range []struct{ name, body, want string }{
		{"unknown field beats everything",
			`{"providerId":"nonesuch","organizationId":"","zzz":1}`,
			`{"error":"Invalid json representation for IdentityProviderRepresentation. Unrecognized field \"zzz\" at line 1 column 53."}`},
		{"organizationId beats a missing alias",
			`{"providerId":"oidc","organizationId":""}`,
			`{"errorMessage":"Organization associated with broker does not exist"}`},
		{"a missing alias beats a bad providerId",
			`{"providerId":"nonesuch"}`,
			`{"errorMessage":"path is null"}`},
	} {
		w := send(t, h, http.MethodPost, "/admin/realms/master/identity-provider/instances", admin, tc.body)
		if strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, w.Body, tc.want)
		}
	}
}

// TestIdentityProviderUpdateReplaces pins the PUT's two measured halves: it
// replaces rather than merges, and it keeps the internalId while losing
// everything else.
func TestIdentityProviderUpdateReplaces(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-put","providerId":"oidc",`+
		`"internalId":"22222222-2222-2222-2222-222222222222","displayName":"before",`+
		`"trustEmail":true,"storeToken":true,"linkOnly":true,`+
		`"firstBrokerLoginFlowAlias":"first broker login",`+
		`"config":{"clientId":"cid","clientSecret":"s"}}`)

	w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-put", admin,
		`{"alias":"gloak-probe-put","providerId":"oidc","displayName":"Renamed"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("PUT Cache-Control: got %q, want no-cache", cc)
	}

	w = get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-put", admin)
	const want = `{"alias":"gloak-probe-put","displayName":"Renamed",` +
		`"internalId":"22222222-2222-2222-2222-222222222222","providerId":"oidc",` +
		`"enabled":true,"config":{},` +
		`"types":["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL",` +
		`"EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("after the PUT the provider reads\n %s\nwant\n %s", got, want)
	}
}

// TestIdentityProviderUpdateWithNoAliasStrandsTheRow reproduces Keycloak's own
// defect, which is the one behaviour here somebody would "fix" by accident.
//
// A PUT whose body carries no alias answers 204 and clears it. The listing then
// serves the row with **no `alias` key**, sorted first, and nothing can address
// it again. Refusing an absent alias is the tidy-up that turns a measured 204
// into a 400.
func TestIdentityProviderUpdateWithNoAliasStrandsTheRow(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-strand","providerId":"oidc"}`)
	createIDP(t, h, admin, `{"alias":"gloak-probe-zzz","providerId":"oidc"}`)

	w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-strand", admin,
		`{"providerId":"oidc"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("PUT with no alias: got %d %s, want 204", w.Code, w.Body)
	}
	if w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-strand", admin); w.Code != http.StatusNotFound {
		t.Errorf("the old alias still resolves: %d %s", w.Code, w.Body)
	}

	w = get(t, h, "/admin/realms/master/identity-provider/instances", admin)
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("listing holds %d rows, want 2", len(list))
	}
	// The stranded row sorts first and has no alias key at all.
	if _, ok := list[0]["alias"]; ok {
		t.Errorf("the stranded row still carries an alias: %v", list[0])
	}
	if list[1]["alias"] != "gloak-probe-zzz" {
		t.Errorf("the stranded row does not sort first: %v", list)
	}
}

// TestIdentityProviderUpdateRefusesAnAliasChange pins the 400 that a *present*
// and different alias gets - the other half of the sentence above.
func TestIdentityProviderUpdateRefusesAnAliasChange(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-rename","providerId":"oidc"}`)

	w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-rename", admin,
		`{"alias":"gloak-probe-other","providerId":"oidc"}`)
	const want = `{"errorMessage":"Identity Provider alias cannot be changed"}`
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("renaming: got %d %s, want 400 %s", w.Code, w.Body, want)
	}
	if w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-rename", admin); w.Code != http.StatusOK {
		t.Errorf("the refusal moved the row: %d %s", w.Code, w.Body)
	}
}

// TestIdentityProviderUpdateDecodesBeforeItResolves is the ordering assertion.
//
// A PUT to an alias that does not exist carrying an unknown field answers the
// strict 400, not the 404. That is the required-action PUT's order and the
// opposite of the organization PUT's, and it is why the route is registered on
// guardAny rather than on guardIdentityProvider.
func TestIdentityProviderUpdateDecodesBeforeItResolves(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-nosuch", admin,
		`{"alias":"x","providerId":"oidc","zzz":1}`)
	const want = `{"error":"Invalid json representation for IdentityProviderRepresentation. ` +
		`Unrecognized field \"zzz\" at line 1 column 41."}`
	if w.Code != http.StatusBadRequest || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("unknown field on an unknown alias: got %d %s, want 400 %s", w.Code, w.Body, want)
	}

	// The same alias with a clean body is the 404, so the 400 above is about
	// the order and not about the route being unreachable.
	w = send(t, h, http.MethodPut,
		"/admin/realms/master/identity-provider/instances/gloak-probe-nosuch", admin,
		`{"alias":"gloak-probe-nosuch","providerId":"oidc"}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("clean body on an unknown alias: got %d %s, want 404", w.Code, w.Body)
	}
}

// TestIdentityProviderDelete pins the 204's headers and that it is not
// idempotent.
func TestIdentityProviderDelete(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-del","providerId":"oidc"}`)

	w := send(t, h, http.MethodDelete,
		"/admin/realms/master/identity-provider/instances/gloak-probe-del", admin, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("DELETE Cache-Control: got %q, want no-cache", cc)
	}
	// No request Content-Type, so no X-Frame-Options - the rule the security
	// header bullet records for an empty response.
	if xf := w.Header().Get("X-Frame-Options"); xf != "" {
		t.Errorf("DELETE X-Frame-Options: got %q, want none", xf)
	}

	w = send(t, h, http.MethodDelete,
		"/admin/realms/master/identity-provider/instances/gloak-probe-del", admin, "")
	const want = `{"error":"HTTP 404 Not Found"}`
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("the second DELETE: got %d %s, want 404 %s", w.Code, w.Body, want)
	}
}

// TestIdentityProviderExportAndReloadKeys pins the two reads that are neither
// the listing nor the representation.
func TestIdentityProviderExportAndReloadKeys(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-ex","providerId":"oidc"}`)

	w := get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-ex/export", admin)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Errorf("export: got %d %q, want 204 and no body", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "" {
		t.Errorf("export Content-Type: got %q, want none", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("export Cache-Control: got %q, want no-cache", cc)
	}

	w = get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-ex/reload-keys", admin)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "false" {
		t.Errorf("reload-keys: got %d %s, want 200 false", w.Code, w.Body)
	}
}

// TestIdentityProviderListingSearchIsAPrefix is the discriminating test.
//
// `search=abb` against an alias `xabbcx` is the one probe that separates the
// measured prefix rule from the substring rule the four user-listing filters
// use. An implementation calling strings.Contains passes every other row here.
func TestIdentityProviderListingSearchIsAPrefix(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	for _, alias := range []string{"xabbcx", "UPPER", "aaa"} {
		createIDP(t, h, admin, `{"alias":"`+alias+`","providerId":"oidc"}`)
	}

	for _, tc := range []struct {
		search string
		want   []string
	}{
		// The decisive row: `*bbc` is a substring match and not a suffix one,
		// which is what separates the measured LIKE rule from the anchored
		// glob this repository implemented until 2026-09-01. `xabbcx` does not
		// end in `bbc`.
		{"*bbc", []string{"xabbcx"}},
		{"abb", nil},
		{"xab", []string{"xabbcx"}},
		{"XAB", []string{"xabbcx"}},
		{"*abb*", []string{"xabbcx"}},
		{"x*", []string{"xabbcx"}},
		{`"xabbcx"`, []string{"xabbcx"}},
		{"upper", []string{"UPPER"}},
		{"", []string{"UPPER", "aaa", "xabbcx"}},
	} {
		w := get(t, h, "/admin/realms/master/identity-provider/instances?search="+
			strings.ReplaceAll(tc.search, `"`, "%22"), admin)
		if got := aliasesOf(t, w.Body.Bytes()); !equalStrings(got, tc.want) {
			t.Errorf("search=%q: got %v, want %v", tc.search, got, tc.want)
		}
	}
}

// TestIdentityProviderListingPagesOnEitherBound pins the rule that separates
// this listing from the role listings' "both or search" and from the user
// listing's.
func TestIdentityProviderListingPagesOnEitherBound(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	for _, alias := range []string{"zzz", "mmm", "aaa"} {
		createIDP(t, h, admin, `{"alias":"`+alias+`","providerId":"oidc"}`)
	}

	for _, tc := range []struct {
		query string
		want  []string
	}{
		// Sorted by alias although they were created the other way round.
		{"", []string{"aaa", "mmm", "zzz"}},
		{"?max=1", []string{"aaa"}},
		{"?first=1", []string{"mmm", "zzz"}},
		{"?first=1&max=1", []string{"mmm"}},
		{"?first=-1&max=-1", []string{"aaa", "mmm", "zzz"}},
	} {
		w := get(t, h, "/admin/realms/master/identity-provider/instances"+tc.query, admin)
		if got := aliasesOf(t, w.Body.Bytes()); !equalStrings(got, tc.want) {
			t.Errorf("%q: got %v, want %v", tc.query, got, tc.want)
		}
	}

	// A malformed bound is the measured 404, where /components next door
	// ignores the same parameter outright.
	w := get(t, h, "/admin/realms/master/identity-provider/instances?first=abc", admin)
	const want = `{"error":"HTTP 404 Not Found"}`
	if w.Code != http.StatusNotFound || strings.TrimSpace(w.Body.String()) != want {
		t.Errorf("first=abc: got %d %s, want 404 %s", w.Code, w.Body, want)
	}
	if w := get(t, h, "/admin/realms/master/components?first=abc", admin); w.Code != http.StatusOK {
		t.Errorf("first=abc on /components: got %d, want 200 - the two families disagree", w.Code)
	}
}

// TestIdentityProviderBriefRepresentation pins the parameter's third default
// and the single read's indifference to it.
func TestIdentityProviderBriefRepresentation(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-brief","providerId":"oidc"}`)

	// Default is false: types is there.
	w := get(t, h, "/admin/realms/master/identity-provider/instances", admin)
	if !strings.Contains(w.Body.String(), `"types"`) {
		t.Errorf("the listing's default dropped types: %s", w.Body)
	}
	w = get(t, h, "/admin/realms/master/identity-provider/instances?briefRepresentation=true", admin)
	if strings.Contains(w.Body.String(), `"types"`) {
		t.Errorf("briefRepresentation=true kept types: %s", w.Body)
	}
	// The single read ignores it.
	w = get(t, h, "/admin/realms/master/identity-provider/instances/gloak-probe-brief?briefRepresentation=true", admin)
	if !strings.Contains(w.Body.String(), `"types"`) {
		t.Errorf("the single read honoured briefRepresentation: %s", w.Body)
	}
}

// TestIdentityProviderGuard pins the fifth gate shape, including the one read
// that refuses the view role and the order the alias is resolved in.
func TestIdentityProviderGuard(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-guard","providerId":"oidc"}`)

	view := tokenForRoles(t, h, s, realm, "view-identity-providers")
	manage := tokenForRoles(t, h, s, realm, "manage-identity-providers")
	other := tokenForRoles(t, h, s, realm, "manage-realm")
	none := tokenForRoles(t, h, s, realm)

	const base = "/admin/realms/master/identity-provider/instances"
	for _, tc := range []struct {
		path                            string
		wantView, wantManage, wantOther int
	}{
		{base, 200, 200, 403},
		{base + "/gloak-probe-guard", 200, 200, 403},
		{base + "/gloak-probe-guard/export", 204, 204, 403},
		// The one read that refuses the view role.
		{base + "/gloak-probe-guard/reload-keys", 403, 200, 403},
	} {
		if w := get(t, h, tc.path, view); w.Code != tc.wantView {
			t.Errorf("%s as view-identity-providers: got %d, want %d", tc.path, w.Code, tc.wantView)
		}
		if w := get(t, h, tc.path, manage); w.Code != tc.wantManage {
			t.Errorf("%s as manage-identity-providers: got %d, want %d", tc.path, w.Code, tc.wantManage)
		}
		if w := get(t, h, tc.path, other); w.Code != tc.wantOther {
			t.Errorf("%s as manage-realm: got %d, want %d", tc.path, w.Code, tc.wantOther)
		}
		if w := get(t, h, tc.path, none); w.Code != http.StatusForbidden {
			t.Errorf("%s as a caller holding nothing: got %d, want 403", tc.path, w.Code)
		}
	}

	// The alias is resolved **after** the roles: an alias that does not exist
	// is 403 to a caller the route refuses and 404 to one it admits. That is
	// the whole difference from the Groups tag.
	if w := send(t, h, http.MethodDelete, base+"/gloak-probe-nosuch", view, ""); w.Code != http.StatusForbidden {
		t.Errorf("DELETE of a missing alias as view-identity-providers: got %d, want 403", w.Code)
	}
	if w := send(t, h, http.MethodDelete, base+"/gloak-probe-nosuch", manage, ""); w.Code != http.StatusNotFound {
		t.Errorf("DELETE of a missing alias as manage-identity-providers: got %d, want 404", w.Code)
	}
}

func aliasesOf(t *testing.T, body []byte) []string {
	t.Helper()
	var list []struct {
		Alias string `json:"alias"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	var out []string
	for _, e := range list {
		out = append(out, e.Alias)
	}
	return out
}
