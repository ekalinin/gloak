package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

const userProfilePath = "/admin/realms/master/users/profile"

// TestTheUserProfileIsCanonicalisedAndNotEchoed is the measurement that decides
// the shape of the handler, and no golden can state it: master's stored config
// is already canonical, so its golden is byte-identical under both
// implementations.
//
// The input below is the one measured against a live 26.7.1 on 2026-09-05, and
// every difference between it and the expected output is a separate measured
// transformation: the spacing goes, `groups` moves after `attributes`, the
// attribute's own keys move into the class order, `permissions` is rewritten
// view-first from an edit-first input, `required` roles-first from a
// scopes-first one, and `multivalued` appears on the attribute that never
// mentioned it.
//
// `validations` is the control that keeps this from being "sort everything":
// its two keys are stored in an order that is neither alphabetical nor
// Keycloak's own, and they come back that way.
func TestTheUserProfileIsCanonicalisedAndNotEchoed(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()

	components, err := s.Components().List(ctx, realm.ID)
	if err != nil {
		t.Fatalf("Components().List: %v", err)
	}
	var profile *model.Component
	for _, c := range components {
		if c.ProviderType == userProfileComponentType {
			profile = c
		}
	}
	if profile == nil {
		t.Fatalf("master has no %s component", userProfileComponentType)
	}

	const stored = `{ "groups" : [] , "attributes":[` +
		`{"multivalued":true,"group":"g1","selector":{"scopes":["profile"]},` +
		`"permissions":{"edit":["admin"],"view":["admin","user"]},` +
		`"required":{"scopes":["profile"],"roles":["user"]},` +
		`"validations":{"up-username-not-idn-homograph":{},"length":{"max":255,"min":3}},` +
		`"displayName":"DN","name":"username"},` +
		`{"name":"email"}] , "unmanagedAttributePolicy":"ADMIN_EDIT" }`
	const want = `{"attributes":[{"name":"username","displayName":"DN",` +
		`"validations":{"up-username-not-idn-homograph":{},"length":{"max":255,"min":3}},` +
		`"required":{"roles":["user"],"scopes":["profile"]},` +
		`"permissions":{"view":["admin","user"],"edit":["admin"]},` +
		`"selector":{"scopes":["profile"]},"group":"g1","multivalued":true},` +
		`{"name":"email","multivalued":false}],` +
		`"groups":[],"unmanagedAttributePolicy":"ADMIN_EDIT"}`

	profile.Config = []model.ComponentConfigEntry{{Name: userProfileConfigKey, Values: []string{stored}}}
	if err := s.Components().Update(ctx, profile); err != nil {
		t.Fatalf("Components().Update: %v", err)
	}

	w := get(t, h, userProfilePath, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("GET profile: %d %s", w.Code, w.Body)
	}
	if got := w.Body.String(); got != want {
		t.Errorf("canonicalisation:\n got %s\nwant %s", got, want)
	}
	if w.Body.String() == stored {
		t.Errorf("the stored bytes were echoed; they were measured being rewritten")
	}
}

// TestTheBuiltInUserProfileIsAlreadyCanonical is what makes the constant safe:
// the default a created realm answers goes through the same serialiser and
// comes out unchanged, so the constant records a response rather than a stored
// form that happens to derive to one.
func TestTheBuiltInUserProfileIsAlreadyCanonical(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"up-canon","enabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create realm: %d %s", w.Code, w.Body)
	}
	if got := get(t, h, "/admin/realms/up-canon/users/profile", admin).Body.String(); got != defaultUserProfile {
		t.Errorf("the default is not its own canonical form:\n got %s\nwant %s", got, defaultUserProfile)
	}
}

// TestARealmWithNoUserProfileComponentAnswersTheBuiltInDefault is the second
// cell, and the two differ: the default carries `"required":{"roles":["user"]}`
// on email, firstName and lastName where master's component carries no
// `required` at all.
//
// A handler falling back on bootstrap's seed instead would answer master's
// bytes here and be wrong in a way no golden on master could see.
func TestARealmWithNoUserProfileComponentAnswersTheBuiltInDefault(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	if w := send(t, h, http.MethodPost, "/admin/realms", admin,
		`{"realm":"up-probe","enabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create realm: %d %s", w.Code, w.Body)
	}

	w := get(t, h, "/admin/realms/up-probe/users/profile", admin)
	if w.Code != http.StatusOK {
		t.Fatalf("GET profile: %d %s", w.Code, w.Body)
	}
	if got := w.Body.String(); got != defaultUserProfile {
		t.Errorf("a created realm's profile:\n got %s\nwant %s", got, defaultUserProfile)
	}
	master := get(t, h, userProfilePath, admin).Body.String()
	if master == w.Body.String() {
		t.Errorf("master and a created realm answer the same profile; they were measured differing")
	}
}

// TestTheUserProfileReadCarriesNoCacheControl pins the header that makes this
// endpoint different from every other read in its own cut. It is asserted here
// as well as in the golden because the golden's absence assertion would survive
// a handler that set the header on some other realm.
func TestTheUserProfileReadCarriesNoCacheControl(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := get(t, h, userProfilePath, admin)
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Errorf("Cache-Control: %q, want none", got)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json;charset=UTF-8"; got != want {
		t.Errorf("Content-Type: %q, want %q", got, want)
	}
	// The control: the read one route away does carry it.
	u := get(t, h, "/admin/realms/master/credential-registrators", admin)
	if got, want := u.Header().Get("Cache-Control"), "no-cache"; got != want {
		t.Errorf("credential-registrators Cache-Control: %q, want %q", got, want)
	}
}

// TestTheUserProfileReadTakesFiveRoles is the union no existing role-set
// variable expresses. It is a sweep rather than a golden because a golden is
// one caller.
//
// query-users is the discriminating entry: it opens this route and no other in
// the user family, so a handler reusing userReadRoles refuses it and one
// reusing realmConfigReadRoles refuses view-users.
func TestTheUserProfileReadTakesFiveRoles(t *testing.T) {
	h, s, realm := newServer(t)

	for _, tc := range []struct {
		role string
		want int
	}{
		{"view-users", http.StatusOK},
		{"manage-users", http.StatusOK},
		{"query-users", http.StatusOK},
		{"view-realm", http.StatusOK},
		{"manage-realm", http.StatusOK},
		{"view-clients", http.StatusForbidden},
		{"manage-clients", http.StatusForbidden},
		{"query-clients", http.StatusForbidden},
		{"view-identity-providers", http.StatusForbidden},
		{"view-events", http.StatusForbidden},
	} {
		token := tokenForRole(t, h, s, realm, tc.role)
		if w := get(t, h, userProfilePath, token); w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.role, w.Code, tc.want)
		}
	}
}

// TestUnmanagedAttributesFollowsTheProfilesPolicy is the branch, and it is the
// reason this handler is not the constant `{}` its golden holds: the golden's
// realm has no policy, and the cell that a policy reaches is only visible from
// here.
//
// The user carries attributes in **both** halves, so the difference between
// them is the policy and nothing else.
func TestUnmanagedAttributesFollowsTheProfilesPolicy(t *testing.T) {
	h, s, realm := newServer(t)
	admin := adminToken(t, h)
	ctx := context.Background()

	u := createUserWithPassword(t, s, realm, "unmanaged", "pw")
	u.Attributes = map[string][]string{"custom1": {"v1"}, "custom2": {"a", "b"}}
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatalf("Users().Update: %v", err)
	}
	path := "/admin/realms/master/users/" + u.ID + "/unmanagedAttributes"

	if got := get(t, h, path, admin).Body.String(); got != `{}` {
		t.Errorf("with no policy: %s, want {}", got)
	}

	setUserProfilePolicy(t, s, realm.ID, "ENABLED")

	var out map[string][]string
	if err := json.Unmarshal(get(t, h, path, admin).Body.Bytes(), &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 || out["custom1"][0] != "v1" || len(out["custom2"]) != 2 {
		t.Errorf("with ENABLED: %v, want the user's two attributes", out)
	}
}

// setUserProfilePolicy rewrites the realm's profile to carry one policy value
// and nothing else that matters here.
func setUserProfilePolicy(t *testing.T, s store.Store, realmID, policy string) {
	t.Helper()
	ctx := context.Background()
	components, err := s.Components().List(ctx, realmID)
	if err != nil {
		t.Fatalf("Components().List: %v", err)
	}
	for _, c := range components {
		if c.ProviderType != userProfileComponentType {
			continue
		}
		c.Config = []model.ComponentConfigEntry{{
			Name:   userProfileConfigKey,
			Values: []string{`{"attributes":[],"groups":[],"unmanagedAttributePolicy":"` + policy + `"}`},
		}}
		if err := s.Components().Update(ctx, c); err != nil {
			t.Fatalf("Components().Update: %v", err)
		}
		return
	}
	t.Fatalf("no %s component in realm %s", userProfileComponentType, realmID)
}
