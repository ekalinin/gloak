package admin

import (
	"net/http"
	"strings"
	"testing"
)

// mapperPath is the mappers collection of one broker. The alias and every
// mapper name in this file differ from each other on purpose: a handler that
// looked one up by the other would pass a fixture that used one string for
// both, and four of the last two cuts' five surviving mutations were exactly
// that hole.
const mapperPath = "/admin/realms/master/identity-provider/instances/gloak-probe-broker/mappers"

// newBrokerWithMappers creates one broker and returns an admin token.
func newBrokerWithMappers(t *testing.T) (http.Handler, string) {
	t.Helper()
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-broker","providerId":"oidc"}`)
	return h, admin
}

// TestIdentityProviderMapperCreateAndRead pins the representation byte for
// byte, on the two bodies that differ in every rule the type has.
//
// The minimal one is what says `config` is `{}` rather than absent; the full
// one is what says an **undeclared** config key is kept, which is the opposite
// of what `POST /components` does with one a chapter away.
func TestIdentityProviderMapperCreateAndRead(t *testing.T) {
	h, admin := newBrokerWithMappers(t)

	w := send(t, h, http.MethodPost, mapperPath, admin,
		`{"id":"11111111-1111-1111-1111-111111111111","name":"gloak-probe-mapper-bare",`+
			`"identityProviderAlias":"gloak-probe-broker",`+
			`"identityProviderMapper":"oidc-username-idp-mapper"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("the bare create: %d %s", w.Code, w.Body)
	}
	// The body's id wins, which is what lets this path be a constant.
	if got, want := w.Header().Get("Location"), mapperPath+"/11111111-1111-1111-1111-111111111111"; !strings.HasSuffix(got, want) {
		t.Errorf("Location: got %q, want a tail of %q", got, want)
	}

	w = get(t, h, mapperPath+"/11111111-1111-1111-1111-111111111111", admin)
	const wantBare = `{"id":"11111111-1111-1111-1111-111111111111",` +
		`"name":"gloak-probe-mapper-bare",` +
		`"identityProviderAlias":"gloak-probe-broker",` +
		`"identityProviderMapper":"oidc-username-idp-mapper","config":{}}`
	if got := strings.TrimSpace(w.Body.String()); got != wantBare {
		t.Errorf("the bare mapper reads back as\n %s\nwant\n %s", got, wantBare)
	}

	// An undeclared config key and a mapper type that does not exist: both
	// measured 201, both kept.
	w = send(t, h, http.MethodPost, mapperPath, admin,
		`{"id":"22222222-2222-2222-2222-222222222222","name":"gloak-probe-mapper-loose",`+
			`"identityProviderAlias":"gloak-probe-broker",`+
			`"identityProviderMapper":"gloak-probe-no-such-mapper-type",`+
			`"config":{"role":"offline_access","undeclared":"kept"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("the loose create: %d %s", w.Code, w.Body)
	}
	w = get(t, h, mapperPath+"/22222222-2222-2222-2222-222222222222", admin)
	const wantLoose = `{"id":"22222222-2222-2222-2222-222222222222",` +
		`"name":"gloak-probe-mapper-loose",` +
		`"identityProviderAlias":"gloak-probe-broker",` +
		`"identityProviderMapper":"gloak-probe-no-such-mapper-type",` +
		`"config":{"undeclared":"kept","role":"offline_access"}}`
	if got := strings.TrimSpace(w.Body.String()); got != wantLoose {
		t.Errorf("the loose mapper reads back as\n %s\nwant\n %s", got, wantLoose)
	}
}

// TestIdentityProviderMapperConfigKeyOrderIsTheSizedHashMap is the assertion
// that separates this family from the components one.
//
// **The same three keys come back two ways from the two families**, measured on
// one container: `{priority, enabled, active}` is `priority active enabled` on
// a mapper and `active priority enabled` on a component. Nothing else in this
// repository pins the two constructors against one key set, and swapping the
// call in orderIdentityProviderMapperConfig fails here.
//
// The `{zz, aa, mm}` pair is the other half: those three share a bucket, so the
// answer is whatever order the **request** carried, and a config decoded into a
// Go map cannot reproduce it.
func TestIdentityProviderMapperConfigKeyOrderIsTheSizedHashMap(t *testing.T) {
	h, admin := newBrokerWithMappers(t)

	for _, tc := range []struct{ name, id, config, want string }{
		{"priority-enabled-active", "aaaaaaaa-0000-0000-0000-000000000001",
			`{"priority":"1","enabled":"2","active":"3"}`,
			`{"priority":"1","active":"3","enabled":"2"}`},
		{"zz-aa-mm", "aaaaaaaa-0000-0000-0000-000000000002",
			`{"zz":"1","aa":"2","mm":"3"}`,
			`{"zz":"1","aa":"2","mm":"3"}`},
		{"aa-mm-zz", "aaaaaaaa-0000-0000-0000-000000000003",
			`{"aa":"2","mm":"3","zz":"1"}`,
			`{"aa":"2","mm":"3","zz":"1"}`},
		{"ten-keys", "aaaaaaaa-0000-0000-0000-000000000004",
			`{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5","k6":"6","k7":"7","k8":"8","k9":"9","k10":"10"}`,
			`{"k1":"1","k2":"2","k3":"3","k4":"4","k5":"5","k6":"6","k10":"10","k7":"7","k8":"8","k9":"9"}`},
		{"client-pair", "aaaaaaaa-0000-0000-0000-000000000005",
			`{"clientId":"a","clientSecret":"b"}`,
			`{"clientSecret":"b","clientId":"a"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := send(t, h, http.MethodPost, mapperPath, admin,
				`{"id":"`+tc.id+`","name":"gloak-probe-order-`+tc.name+`",`+
					`"identityProviderAlias":"gloak-probe-broker",`+
					`"identityProviderMapper":"oidc-user-attribute-idp-mapper",`+
					`"config":`+tc.config+`}`)
			if w.Code != http.StatusCreated {
				t.Fatalf("create: %d %s", w.Code, w.Body)
			}
			w = get(t, h, mapperPath+"/"+tc.id, admin)
			got := strings.TrimSpace(w.Body.String())
			want := `"config":` + tc.want + `}`
			if !strings.HasSuffix(got, want) {
				t.Errorf("config order:\n got %s\nwant a tail of %s", got, want)
			}
		})
	}
}

// TestIdentityProviderMapperListingIsPerAliasAndTheIDLookupIsNot is the
// measured asymmetry: the listing filters by the path's alias and the three
// routes that name a mapper id do not look at it at all.
func TestIdentityProviderMapperListingIsPerAliasAndTheIDLookupIsNot(t *testing.T) {
	h, admin := newBrokerWithMappers(t)
	createIDP(t, h, admin, `{"alias":"gloak-probe-broker-other","providerId":"saml"}`)
	const otherPath = "/admin/realms/master/identity-provider/instances/gloak-probe-broker-other/mappers"

	for _, name := range []string{"gloak-probe-zzz", "gloak-probe-mmm", "gloak-probe-aaa"} {
		w := send(t, h, http.MethodPost, mapperPath, admin,
			`{"name":"`+name+`","identityProviderAlias":"gloak-probe-broker",`+
				`"identityProviderMapper":"oidc-username-idp-mapper"}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body)
		}
	}

	w := get(t, h, mapperPath, admin)
	if n := strings.Count(w.Body.String(), `"id":`); n != 3 {
		t.Errorf("the broker's listing holds %d mappers, want 3: %s", n, w.Body)
	}
	if w := get(t, h, otherPath, admin); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("the other broker's listing: got %s, want []", w.Body)
	}

	// One of the first broker's mappers, read and then deleted through the
	// other broker's path. Both were measured as 2xx on the server.
	id := firstMapperID(t, w.Body.String())
	if w := get(t, h, otherPath+"/"+id, admin); w.Code != http.StatusOK {
		t.Errorf("reading a mapper through another broker's path: %d %s", w.Code, w.Body)
	}
	if w := send(t, h, http.MethodDelete, otherPath+"/"+id, admin, ""); w.Code != http.StatusNoContent {
		t.Errorf("deleting a mapper through another broker's path: %d %s", w.Code, w.Body)
	}
	if w := get(t, h, mapperPath, admin); strings.Count(w.Body.String(), `"id":`) != 2 {
		t.Errorf("the delete did not reach the first broker's listing: %s", w.Body)
	}
}

// TestIdentityProviderMapperUpdateWritesTheBodysID reproduces Keycloak's own
// defect: a PUT addressed to one mapper carrying another's id writes the other
// one and leaves the addressed one alone.
//
// It also pins the **replace**: the config a PUT does not name is gone, which
// is the opposite of PUT /components/{id} one chapter away.
func TestIdentityProviderMapperUpdateWritesTheBodysID(t *testing.T) {
	h, admin := newBrokerWithMappers(t)
	const target = "bbbbbbbb-0000-0000-0000-000000000001"
	const addressed = "bbbbbbbb-0000-0000-0000-000000000002"

	for _, spec := range []struct{ id, name string }{
		{target, "gloak-probe-target"},
		{addressed, "gloak-probe-addressed"},
	} {
		w := send(t, h, http.MethodPost, mapperPath, admin,
			`{"id":"`+spec.id+`","name":"`+spec.name+`",`+
				`"identityProviderAlias":"gloak-probe-broker",`+
				`"identityProviderMapper":"oidc-username-idp-mapper",`+
				`"config":{"claim":"kept","syncMode":"INHERIT"}}`)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", spec.name, w.Code, w.Body)
		}
	}

	w := send(t, h, http.MethodPut, mapperPath+"/"+addressed, admin,
		`{"id":"`+target+`","name":"gloak-probe-crossed",`+
			`"identityProviderAlias":"gloak-probe-broker",`+
			`"identityProviderMapper":"oidc-username-idp-mapper",`+
			`"config":{"claim":"moved"}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("the crossed PUT: %d %s", w.Code, w.Body)
	}

	// The mapper the body named changed, config replaced rather than merged.
	got := strings.TrimSpace(get(t, h, mapperPath+"/"+target, admin).Body.String())
	if !strings.Contains(got, `"name":"gloak-probe-crossed"`) ||
		!strings.HasSuffix(got, `"config":{"claim":"moved"}}`) {
		t.Errorf("the body's mapper reads back as %s", got)
	}
	// The mapper the path named did not.
	got = strings.TrimSpace(get(t, h, mapperPath+"/"+addressed, admin).Body.String())
	if !strings.Contains(got, `"name":"gloak-probe-addressed"`) ||
		!strings.Contains(got, `"claim":"kept"`) {
		t.Errorf("the path's mapper reads back as %s", got)
	}
}

// TestIdentityProviderMapperErrors walks the measured failures. Each row is one
// request against a live 26.7.1 on 2026-09-02.
func TestIdentityProviderMapperErrors(t *testing.T) {
	h, admin := newBrokerWithMappers(t)
	w := send(t, h, http.MethodPost, mapperPath, admin,
		`{"name":"gloak-probe-taken","identityProviderAlias":"gloak-probe-broker",`+
			`"identityProviderMapper":"oidc-username-idp-mapper"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("seeding: %d %s", w.Code, w.Body)
	}

	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		want                     string
	}{
		{"a body with no name is the duplicate-resource 409", http.MethodPost, mapperPath,
			`{"identityProviderAlias":"gloak-probe-broker","identityProviderMapper":"oidc-username-idp-mapper"}`,
			http.StatusConflict, `{"error":"conflict","error_description":"Duplicate resource error"}`},
		{"a name the alias already holds is a 400 naming the providerId", http.MethodPost, mapperPath,
			`{"name":"gloak-probe-taken","identityProviderAlias":"gloak-probe-broker","identityProviderMapper":"oidc-username-idp-mapper"}`,
			http.StatusBadRequest, `{"errorMessage":"Failed to add mapper 'gloak-probe-taken' to identity provider [oidc]."}`},
		// The column is this body's, not the probe's: the server answered
		// column 22 for `{"name":"rm4","zzz":1}` and the arithmetic that
		// produces it is decodeStrict's, pinned where that lives. What this row
		// asserts is the **class name**, which is per endpoint.
		{"an unknown field is the strict decoder", http.MethodPost, mapperPath,
			`{"name":"gloak-probe-x","zzz":1}`,
			http.StatusBadRequest, `{"error":"Invalid json representation for IdentityProviderMapperRepresentation. Unrecognized field \"zzz\" at line 1 column 32."}`},
		{"an empty body is a 500", http.MethodPost, mapperPath, ``,
			http.StatusInternalServerError, `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a literal null is the same 500", http.MethodPost, mapperPath, `null`,
			http.StatusInternalServerError, `{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a malformed body is a 400", http.MethodPost, mapperPath, `{`,
			http.StatusBadRequest, `{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		{"an unknown mapper id on the read", http.MethodGet, mapperPath + "/gloak-probe-nosuch", ``,
			http.StatusNotFound, `{"error":"Model not found"}`},
		{"an unknown mapper id on the delete", http.MethodDelete, mapperPath + "/gloak-probe-nosuch", ``,
			http.StatusNotFound, `{"error":"Model not found"}`},
		{"an unknown mapper id on the update", http.MethodPut, mapperPath + "/gloak-probe-nosuch",
			`{"name":"gloak-probe-y","identityProviderAlias":"gloak-probe-broker","identityProviderMapper":"oidc-username-idp-mapper"}`,
			http.StatusNotFound, `{"error":"Model not found"}`},
		{"an unknown alias is the family's generic 404", http.MethodGet,
			"/admin/realms/master/identity-provider/instances/gloak-probe-nosuch/mappers", ``,
			http.StatusNotFound, `{"error":"HTTP 404 Not Found"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := send(t, h, tc.method, tc.path, admin, tc.body)
			if w.Code != tc.status {
				t.Errorf("status: got %d, want %d (%s)", w.Code, tc.status, w.Body)
			}
			if got := strings.TrimSpace(w.Body.String()); got != tc.want {
				t.Errorf("body:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestIdentityProviderMapperUpdateDecodesBeforeItResolves pins the order: the
// strict decode runs before the path's mapper is looked up, so a PUT to an id
// that does not exist carrying an unknown field answers the 400.
func TestIdentityProviderMapperUpdateDecodesBeforeItResolves(t *testing.T) {
	h, admin := newBrokerWithMappers(t)
	w := send(t, h, http.MethodPut, mapperPath+"/gloak-probe-nosuch", admin,
		`{"name":"gloak-probe-z","zzz":1}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400 (%s)", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "Unrecognized field") {
		t.Errorf("body: got %s, want the strict decoder's 400", w.Body)
	}
}

// TestMapperTypesFollowTheProvider pins the per-provider selection and the two
// providers whose mapper-types is a 500.
func TestMapperTypesFollowTheProvider(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	for _, spec := range []struct {
		alias, providerID string
		status            int
		firstMapper       string
	}{
		{"gloak-probe-mt-oidc", "oidc", http.StatusOK, "oidc-advanced-group-idp-mapper"},
		{"gloak-probe-mt-saml", "saml", http.StatusOK, "saml-username-idp-mapper"},
		{"gloak-probe-mt-kube", "kubernetes", http.StatusOK, "hardcoded-user-session-attribute-idp-mapper"},
		{"gloak-probe-mt-li", "linkedin-openid-connect", http.StatusInternalServerError, ""},
		{"gloak-probe-mt-os", "openshift-v4", http.StatusInternalServerError, ""},
	} {
		createIDP(t, h, admin, `{"alias":"`+spec.alias+`","providerId":"`+spec.providerID+`"}`)
		w := get(t, h, "/admin/realms/master/identity-provider/instances/"+spec.alias+"/mapper-types", admin)
		if w.Code != spec.status {
			t.Errorf("%s: status %d, want %d (%s)", spec.providerID, w.Code, spec.status, w.Body)
			continue
		}
		if spec.firstMapper == "" {
			if got, want := strings.TrimSpace(w.Body.String()),
				`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`; got != want {
				t.Errorf("%s: body %s, want %s", spec.providerID, got, want)
			}
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(w.Body.String()), `{"`+spec.firstMapper+`":`) {
			t.Errorf("%s: the map does not start with %s: %.80s",
				spec.providerID, spec.firstMapper, w.Body)
		}
	}
}

// TestProviderInfoRefusesAnUnknownIDWithA400 is the one route in this chapter
// whose unknown name is a 400 rather than a 404.
func TestProviderInfoRefusesAnUnknownIDWithA400(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/identity-provider/providers/oidc", admin)
	if got, want := strings.TrimSpace(w.Body.String()),
		`{"name":"OpenID Connect v1.0","id":"oidc","configProperties":[],"helpText":"","configMetadata":[]}`; got != want {
		t.Errorf("oidc:\n got %s\nwant %s", got, want)
	}
	w = get(t, h, "/admin/realms/master/identity-provider/providers/gloak-probe-nosuch", admin)
	if w.Code != http.StatusBadRequest {
		t.Errorf("an unknown provider id: got %d, want 400", w.Code)
	}
	if got, want := strings.TrimSpace(w.Body.String()), `{"error":"HTTP 400 Bad Request"}`; got != want {
		t.Errorf("body: got %s, want %s", got, want)
	}
}

// TestMapperFamilyGuard pins the two role sets across all seven routes this cut
// adds, measured one role at a time over six callers on 2026-09-02.
//
// The four reads take either identity-provider role and the three writes take
// `manage-identity-providers` alone. `view-realm` and `manage-realm` - the pair
// that opens the Component chapter one path segment away - are 403 on every one
// of them, which is the disjointness the first cut measured and this one
// re-measured rather than inherited.
func TestMapperFamilyGuard(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	createIDP(t, h, admin, `{"alias":"gloak-probe-guard-broker","providerId":"oidc"}`)
	const base = "/admin/realms/master/identity-provider"
	const mappers = base + "/instances/gloak-probe-guard-broker/mappers"
	w := send(t, h, http.MethodPost, mappers, admin,
		`{"id":"cccccccc-0000-0000-0000-000000000001","name":"gloak-probe-guard-mapper",`+
			`"identityProviderAlias":"gloak-probe-guard-broker",`+
			`"identityProviderMapper":"oidc-username-idp-mapper"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("seeding: %d %s", w.Code, w.Body)
	}

	view := tokenForRoles(t, h, s, realm, "view-identity-providers")
	manage := tokenForRoles(t, h, s, realm, "manage-identity-providers")
	realmManager := tokenForRoles(t, h, s, realm, "manage-realm")
	none := tokenForRoles(t, h, s, realm)
	const mapper = mappers + "/cccccccc-0000-0000-0000-000000000001"

	for _, tc := range []struct {
		method, path, body  string
		wantView, wantWrite int
	}{
		{http.MethodGet, base + "/providers/oidc", "", 200, 200},
		{http.MethodGet, base + "/instances/gloak-probe-guard-broker/mapper-types", "", 200, 200},
		{http.MethodGet, mappers, "", 200, 200},
		{http.MethodGet, mapper, "", 200, 200},
		{http.MethodPost, mappers,
			`{"name":"gloak-probe-guard-added","identityProviderAlias":"gloak-probe-guard-broker",` +
				`"identityProviderMapper":"oidc-username-idp-mapper"}`, 403, 201},
		{http.MethodPut, mapper,
			`{"id":"cccccccc-0000-0000-0000-000000000001","name":"gloak-probe-guard-mapper",` +
				`"identityProviderAlias":"gloak-probe-guard-broker",` +
				`"identityProviderMapper":"oidc-username-idp-mapper"}`, 403, 204},
		{http.MethodDelete, mapper, "", 403, 204},
	} {
		if w := send(t, h, tc.method, tc.path, view, tc.body); w.Code != tc.wantView {
			t.Errorf("%s %s as view-identity-providers: got %d, want %d",
				tc.method, tc.path, w.Code, tc.wantView)
		}
		if w := send(t, h, tc.method, tc.path, realmManager, tc.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as manage-realm: got %d, want 403", tc.method, tc.path, w.Code)
		}
		if w := send(t, h, tc.method, tc.path, none, tc.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s as a caller holding nothing: got %d, want 403", tc.method, tc.path, w.Code)
		}
		// The write set last, because three of these rows change the mapper.
		if w := send(t, h, tc.method, tc.path, manage, tc.body); w.Code != tc.wantWrite {
			t.Errorf("%s %s as manage-identity-providers: got %d, want %d",
				tc.method, tc.path, w.Code, tc.wantWrite)
		}
	}
}

// firstMapperID pulls the first `"id":"..."` out of a listing body.
func firstMapperID(t *testing.T, body string) string {
	t.Helper()
	const key = `"id":"`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("no mapper id in %s", body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("unterminated id in %s", body)
	}
	return rest[:j]
}
