package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
	"github.com/ekalinin/gloak/internal/token"
)

// The goldens are the contract and these are the rules beside them. Each of
// these is something no committed golden can say, for the reason the SAML cut
// wrote down: a golden compares against a recording, and a test compares
// against what this project believes.

// TestSocialDisplayNamesAreNotACaseTransformation computes the claim the table's
// comment makes rather than asserting it in prose.
//
// The comment says seven of the eleven names defeat any case transformation. If
// that stopped being true - because somebody replaced the table with a
// generator, or because a name was transcribed wrongly into the shape a
// generator would produce - the table would look derivable and the next cut
// would derive it. This is the second opinion: it applies the two obvious
// generators and requires them to fail on exactly the seven named.
func TestSocialDisplayNamesAreNotACaseTransformation(t *testing.T) {
	// The generators a reader reaches for: capitalise the id, and title-case it
	// with hyphens turned into spaces.
	capitalise := func(id string) string {
		return strings.ToUpper(id[:1]) + id[1:]
	}
	titleCase := func(id string) string {
		words := strings.Split(id, "-")
		for i, w := range words {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
		return strings.Join(words, " ")
	}

	// The seven the table's comment names. Written out here rather than
	// computed, so a change to the table has to disagree with two places.
	wantUngenerable := map[string]bool{
		"bitbucket":               true,
		"github":                  true,
		"gitlab":                  true,
		"linkedin-openid-connect": true,
		"openshift-v4":            true,
		"paypal":                  true,
		"stackoverflow":           true,
	}
	for id, name := range socialProviderNames {
		generable := capitalise(id) == name || titleCase(id) == name
		if wantUngenerable[id] && generable {
			t.Errorf("%q: %q is what a case transformation gives, so the table "+
				"reads as derivable where the measurement says it is not", id, name)
		}
		if !wantUngenerable[id] && !generable {
			t.Errorf("%q: %q is not what a case transformation gives, so the "+
				"count of seven in socialProviderNames' comment is now wrong", id, name)
		}
	}
	if got := len(socialProviderNames); got != 11 {
		t.Errorf("socialProviderNames holds %d entries, want the 11 measured - "+
			"AGENTS.md's `types` derivation counts the same eleven and the two "+
			"readings agreeing is what the table rests on", got)
	}
}

// TestTheTwoUnlistedProvidersAreNotAlsoInTheSocialTable pins the one thing that
// would make the two tables contradict each other: a provider that the listing
// never shows cannot have a display name the listing would show.
func TestTheTwoUnlistedProvidersAreNotAlsoInTheSocialTable(t *testing.T) {
	for id := range unlistedProviderIDs {
		if _, ok := socialProviderNames[id]; ok {
			t.Errorf("%q is in both tables: it is filtered out of the listing and "+
				"also declared to have a display name the listing would serve", id)
		}
	}
	if got := len(unlistedProviderIDs); got != 2 {
		t.Errorf("unlistedProviderIDs holds %d entries, want the 2 measured", got)
	}
}

// TestTheTwoServedReadsTakeDifferentRoleSets is the rule that stops the two
// handlers sharing one guard, computed from the constants they use.
//
// It is a unit test rather than a golden because the goldens can only ever show
// it one refusal at a time: account/gate/wrong-role-groups and
// account/gate/wrong-role-linked-accounts are two cases and neither of them
// says that the two sets are *different*, only that each refuses one role.
func TestTheTwoServedReadsTakeDifferentRoleSets(t *testing.T) {
	groups := map[string]bool{roleViewGroups: true, roleManageAccount: true}
	linked := map[string]bool{roleViewProfile: true, roleManageAccount: true}

	if groups[roleViewProfile] {
		t.Error("view-profile is measured 403 on /groups and the groups guard admits it")
	}
	if linked[roleViewGroups] {
		t.Error("view-groups is measured 403 on /linked-accounts and the guard admits it")
	}
	// manage-account is the only role in both, which is what makes it the
	// superset rather than a third pair.
	shared := 0
	for name := range groups {
		if linked[name] {
			shared++
		}
	}
	if shared != 1 {
		t.Errorf("the two role sets share %d roles, want exactly manage-account", shared)
	}
	// manage-account-links opens neither, which is the measurement a reader is
	// most likely to undo, since it is the only account role whose name matches
	// a route this package serves.
	if groups["manage-account-links"] || linked["manage-account-links"] {
		t.Error("manage-account-links is measured 403 on both served reads")
	}
}

// TestBearerTokenFoldsTheSchemeAndRefusesOthers pins the account API's own
// reading of the Authorization header, one vector per measured spelling.
//
// **Two of these vectors were the other way round until they were measured.**
// The first version of this test asserted `Bearer   abc  ` yields `abc` and
// `Bearer a b` yields `a b` - what a `TrimSpace` over the remainder gives - and
// a live 26.7.1 answers 401 to both. The separator is exactly one space; what
// surrounds the *whole* value is ignored. See bearerToken for all sixteen rows
// and the requests behind them.
func TestBearerTokenFoldsTheSchemeAndRefusesOthers(t *testing.T) {
	cases := map[string]string{
		// The scheme folds case - measured 200 on all four.
		"Bearer abc": "abc",
		"bearer abc": "abc",
		"BEARER abc": "abc",
		"BeArEr abc": "abc",
		// Exactly one space separates the two. Measured 401 on all three, and
		// these are the rows a trimming implementation gets wrong.
		"Bearer  abc":  "",
		"Bearer   abc": "",
		"Bearer\tabc":  "",
		// Whitespace around the whole value is ignored. Measured 200 on all five.
		"Bearer abc ":  "abc",
		"Bearer abc  ": "abc",
		"Bearer abc\t": "abc",
		" Bearer abc":  "abc",
		"  Bearer abc": "abc",
		// A third word is refused, which is what stops "ignore the surroundings"
		// being read as "take everything after the first space". Measured 401.
		"Bearer abc extra": "",
		// The scheme is compared whole, so a trailing comma is not the scheme.
		"Bearer, abc": "",
		// No separator, no token, another scheme, no header.
		"Bearerabc":      "",
		"Bearer":         "",
		"Bearer ":        "",
		"abc":            "",
		"":               "",
		"Basic YWRtaW4=": "",
		"Negotiate abc":  "",
		"DPoP abc":       "",
		"Token abc":      "",
	}
	for header, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/realms/master/account/groups", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := bearerToken(r); got != want {
			t.Errorf("Authorization %q: got %q, want %q", header, got, want)
		}
	}
}

// TestGroupPathIsBuiltFromTheAncestry pins the path this package computes.
//
// It is this package's own function rather than internal/admin's, and the
// vector below is what stops the two silently converging: a shared helper would
// be the first step towards a shared serialiser, and the two APIs' group shapes
// differ in four keys.
func TestGroupPathIsBuiltFromTheAncestry(t *testing.T) {
	cases := []struct {
		ancestry []*model.Group
		want     string
	}{
		{nil, ""},
		{[]*model.Group{{Name: "top"}}, "/top"},
		{[]*model.Group{{Name: "top"}, {Name: "child"}}, "/top/child"},
		{[]*model.Group{{Name: "a"}, {Name: "b"}, {Name: "c"}}, "/a/b/c"},
		// A name that is already a path separator is not escaped, which is what
		// Keycloak does too - a group cannot be created with one, and pretending
		// otherwise here would be a rule nothing measured.
		{[]*model.Group{{Name: "a/b"}}, "/a/b"},
	}
	for _, c := range cases {
		if got := groupPath(c.ancestry); got != c.want {
			t.Errorf("groupPath(%v) = %q, want %q", c.ancestry, got, c.want)
		}
	}
}

// TestSubjectRoleQuestionsAreAskedOfOneContainer is the F32 lesson stated for
// this API: the grants map is built from roles owned by the account client, so
// a name held on some other client must not answer.
//
// The map itself carries only names, so this asserts the shape rather than the
// filter - accountGrants is what applies the container test and it needs a
// store. What is worth pinning without one is that hasAny is a membership test
// over that map and nothing wider.
func TestSubjectRoleQuestionsAreAskedOfOneContainer(t *testing.T) {
	s := &subject{grants: map[string]bool{roleViewGroups: true}}
	if !s.has(roleViewGroups) {
		t.Error("a granted name is not reported held")
	}
	if s.has(roleManageAccount) {
		t.Error("a name that is not granted is reported held")
	}
	if !s.hasAny(roleManageAccount, roleViewGroups) {
		t.Error("hasAny missed the second name")
	}
	if s.hasAny(roleManageAccount, roleViewProfile) {
		t.Error("hasAny admitted a subject holding neither name")
	}
	if (&subject{}).hasAny(roleViewGroups) {
		t.Error("a subject with no grants at all was admitted")
	}
}

// newAccountHandler builds a handler over a freshly bootstrapped master realm.
//
// It is the first one in this package and it exists for one branch: everything
// above is a pure function and grantedRoles needs a store. It holds no keys,
// because nothing it is used for verifies a token.
func newAccountHandler(t *testing.T) (*handler, store.Store, *model.Realm) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	return &handler{store: s, issuerBase: "http://localhost:8080"}, s, realm
}

// TestGrantedRolesRefusesATokenWhoseClientIsGone pins the fall-open branch of
// the audience gate, and **the state it describes is reachable in Gloak.**
//
// `client_session` cascades when a client is deleted and `user_session` does
// not - 0003_session.sql - so a token minted by a client that has since been
// deleted still resolves to a live user session, reaches grantedRoles, and
// finds no client to read fullScopeAllowed from. Answering with the user's
// whole role set there hands the account API to that token; answering with
// nothing refuses it, which is what this gate already does for a caller holding
// no account role.
//
// No conformance case can reach it - no fixture deletes a client it has minted
// a token at - and a mutation flipping the branch survived the whole tree. So
// the direction is asserted here, with the control beside it: the same user and
// realm through a client that **does** exist answers the account roles, which is
// what makes the refusal a statement about the missing client rather than about
// the user.
func TestGrantedRolesRefusesATokenWhoseClientIsGone(t *testing.T) {
	h, s, realm := newAccountHandler(t)
	ctx := context.Background()

	user := &model.User{
		ID: model.NewID(), RealmID: realm.ID,
		Username: "gloak-probe-gone-client-user", Enabled: true,
	}
	if err := s.Users().Create(ctx, user); err != nil {
		t.Fatalf("Create(user): %v", err)
	}
	if err := roles.AssignDefaults(ctx, s.Roles(), realm.ID, realm.Name, user.ID); err != nil {
		t.Fatalf("AssignDefaults: %v", err)
	}

	// The control. admin-cli carries fullScopeAllowed, so every role the user
	// holds is in its scope and the account roles come through.
	held, err := h.grantedRoles(ctx, realm, &token.Parsed{ClientID: "admin-cli"}, user)
	if err != nil {
		t.Fatalf("grantedRoles(admin-cli): %v", err)
	}
	grants, err := h.accountGrants(ctx, realm, held)
	if err != nil {
		t.Fatalf("accountGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("the control client granted no account role, so the refusal below asserts nothing")
	}

	gone, err := h.grantedRoles(ctx, realm, &token.Parsed{ClientID: "gloak-probe-deleted"}, user)
	if err != nil {
		t.Fatalf("grantedRoles(missing client): %v", err)
	}
	if len(gone) != 0 {
		t.Fatalf("a token whose azp names no client granted %d role(s); want none", len(gone))
	}
}
