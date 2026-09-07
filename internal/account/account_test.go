package account

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
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
// reading of the Authorization header.
//
// The lower-case spelling is measured succeeding here, and internal/admin's
// bearerToken cuts the exact prefix "Bearer ". The two disagree on purpose and
// this is where the disagreement is written down.
func TestBearerTokenFoldsTheSchemeAndRefusesOthers(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":        "abc",
		"bearer abc":        "abc",
		"BEARER abc":        "abc",
		"BeArEr abc":        "abc",
		"Bearer   abc  ":    "abc",
		"Basic YWRtaW4=":    "",
		"abc":               "",
		"":                  "",
		"Bearerabc":         "",
		"Negotiate abc":     "",
		"DPoP abc":          "",
		"Bearer":            "",
		"Bearer ":           "",
		"Bearer a b":        "a b",
		"  Bearer   spaced": "",
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
