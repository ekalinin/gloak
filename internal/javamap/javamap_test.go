package javamap_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/javamap"
)

// The vectors are key orders read off a live Keycloak 26.7.1 on 2026-08-23,
// not orders anybody chose. Each is a JSON object Keycloak built from a Java
// Map or Set, so the order it came back in is the order a HashMap iterates.
//
// They are here rather than in the packages that emit these shapes because
// this is the one place the rule is implemented: if the rule is wrong, it is
// wrong for all of them at once.
func TestKeyOrderReproducesMeasuredKeycloakOrders(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{
			// The `access` block of GET /admin/realms/master/users/{id}. Six
			// keys, and the strongest of the vectors: one permutation out of
			// 720.
			name: "user access block",
			want: []string{
				"manageGroupMembership", "resetPassword", "view",
				"mapRoles", "impersonate", "manage",
			},
		},
		{
			// resource_access on the administrator's access token, issued by a
			// confidential client.
			name: "resource_access clients",
			want: []string{"master-realm", "account"},
		},
		{
			// realm_access.roles on the same token - a Set rather than a Map,
			// which is a HashMap underneath and orders the same way.
			name: "administrator realm roles",
			want: []string{
				"create-realm", "default-roles-master", "offline_access",
				"admin", "uma_authorization",
			},
		},
		{
			name: "account client roles",
			want: []string{"manage-account", "manage-account-links", "view-profile"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Shuffled by sorting: KeyOrder must not depend on the order it
			// was handed, since a Go map hands keys over in a random one.
			in := slices.Sorted(slices.Values(c.want))
			if got := javamap.KeyOrder(in); !slices.Equal(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

// The measured order that KeyOrder gets wrong, pinned so the limit stays
// visible. Two pairs collide - view-realm with view-identity-providers, and
// query-organizations with query-groups - and Keycloak chains a collision in
// insertion order while this sorts. Every one of the other seventeen positions
// is right, which is what says the bucket rule holds at this size and only the
// tie-break does not.
func TestKeyOrderCannotResolveBucketCollisions(t *testing.T) {
	measured := []string{
		"view-realm", "view-identity-providers", "manage-organizations",
		"manage-identity-providers", "impersonation", "create-client",
		"manage-users", "query-realms", "view-authorization", "query-clients",
		"query-users", "manage-events", "manage-realm", "view-organizations",
		"view-events", "view-users", "view-clients", "manage-authorization",
		"manage-clients", "query-organizations", "query-groups",
	}
	got := javamap.KeyOrder(slices.Sorted(slices.Values(measured)))

	if slices.Equal(got, measured) {
		t.Fatal("the collision tie-break now agrees with Keycloak; " +
			"if that is real, this test and the package doc are out of date")
	}
	var differing []int
	for i := range measured {
		if got[i] != measured[i] {
			differing = append(differing, i)
		}
	}
	if len(differing) != 4 {
		t.Fatalf("want exactly the two swapped pairs, got %d differing positions: %v",
			len(differing), differing)
	}
}

// A HashMap that has resized masks with a bigger table, so the order changes.
// 12 entries fit in the default 16; the thirteenth doubles it.
func TestKeyOrderAccountsForResizing(t *testing.T) {
	keys := []string{
		"k00", "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09",
		"k10", "k11",
	}
	small := javamap.KeyOrder(keys)

	grown := javamap.KeyOrder(append(slices.Clone(keys), "k12"))
	grown = slices.DeleteFunc(grown, func(s string) bool { return s == "k12" })

	if slices.Equal(small, grown) {
		t.Fatalf("want the thirteenth entry to reorder the other twelve, got %v twice", small)
	}
}

func TestKeyOrderDoesNotModifyItsInput(t *testing.T) {
	in := []string{"master-realm", "account"}
	javamap.KeyOrder(in)
	if !slices.Equal(in, []string{"master-realm", "account"}) {
		t.Fatalf("input was modified: %v", in)
	}
}

// vector is one measured (insertion order, served order) pair. Both are
// space-separated because no measured key contains a space, and a table of
// forty of them is unreadable written out as slices.
type vector struct {
	name string
	in   string // the order the create request's JSON carried the keys
	want string // the order the mapper route served them back in
}

func (v vector) keys() []string  { return strings.Fields(v.in) }
func (v vector) order() []string { return strings.Fields(v.want) }

func checkVectors(t *testing.T, vectors []vector) {
	t.Helper()
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got := javamap.SizedKeyOrder(v.keys())
			if !slices.Equal(got, v.order()) {
				t.Fatalf("\nin   %v\nwant %v\ngot  %v", v.keys(), v.order(), got)
			}
		})
	}
}

// mapperConfigVectors are the fourteen the P5 cut measured F80 against,
// re-measured on 2026-08-30 against a live Keycloak 26.7.1 because only five of
// them had been written down. Each was created through
// POST .../client-scopes/{id}/protocol-mappers/models with the config keys in
// the order below and read back from the dedicated mapper route.
//
// The provider is oidc-nonce-backwards-compatible-mapper throughout: it is one
// of the four registered providers that mirrors neither access.token.claim nor
// id.token.claim into a second key, so the served config holds exactly the keys
// the request sent and nothing was appended behind them.
var mapperConfigVectors = []vector{
	{
		name: "two mapper keys, natural order",
		in:   "user.attribute claim.name",
		want: "claim.name user.attribute",
	},
	{
		name: "two mapper keys, reversed",
		in:   "claim.name user.attribute",
		want: "claim.name user.attribute",
	},
	{
		name: "three colliding, zz aa mm",
		in:   "zz aa mm",
		want: "zz aa mm",
	},
	{
		name: "three colliding, mm zz aa",
		in:   "mm zz aa",
		want: "mm zz aa",
	},
	{
		name: "twelve keys k12 down to k01",
		in:   "k12 k11 k10 k09 k08 k07 k06 k05 k04 k03 k02 k01",
		want: "k06 k05 k08 k07 k09 k11 k10 k02 k12 k01 k04 k03",
	},
	{
		name: "one key",
		in:   "claim.name",
		want: "claim.name",
	},
	{
		name: "three realistic mapper keys",
		in:   "claim.name jsonType.label user.attribute",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "four keys",
		in:   "access.token.claim id.token.claim claim.name user.attribute",
		want: "user.attribute id.token.claim access.token.claim claim.name",
	},
	{
		name: "five keys",
		in:   "a b c d e",
		want: "a b c d e",
	},
	{
		name: "six keys at the load factor",
		in:   "k1 k2 k3 k4 k5 k6",
		want: "k3 k4 k5 k6 k1 k2",
	},
	{
		name: "seven keys past the load factor",
		in:   "k1 k2 k3 k4 k5 k6 k7",
		want: "k1 k2 k3 k4 k5 k6 k7",
	},
	{
		name: "thirteen keys",
		in:   "k01 k02 k03 k04 k05 k06 k07 k08 k09 k10 k11 k12 k13",
		want: "k11 k10 k02 k13 k01 k12 k04 k03 k06 k05 k08 k07 k09",
	},
	{
		name: "sixteen keys",
		in:   "n00 n01 n02 n03 n04 n05 n06 n07 n08 n09 n10 n11 n12 n13 n14 n15",
		want: "n10 n01 n12 n00 n11 n03 n14 n02 n13 n05 n04 n15 n07 n06 n09 n08",
	},
	{
		name: "full mapper config as Keycloak writes one",
		in: "introspection.token.claim userinfo.token.claim " +
			"user.attribute id.token.claim access.token.claim claim.name " +
			"jsonType.label",
		want: "introspection.token.claim userinfo.token.claim " +
			"user.attribute id.token.claim access.token.claim claim.name " +
			"jsonType.label",
	},
}

// F80's whole claim, as an assertion. The five vectors the P5 handover names -
// the two-key pair in both orders, {zz, aa, mm} in two of its orders, and the
// twelve-key one - are in here byte for byte, and reproduced on a second
// container a week later.
func TestSizedKeyOrderReproducesMeasuredMapperConfigOrders(t *testing.T) {
	checkVectors(t, mapperConfigVectors)
}

// The other half of F80: KeyOrder is not merely imprecise on a sized map, it is
// wrong on half of them, and the count is pinned so that "javamap reproduces
// Keycloak's map order" cannot be read as covering this case.
//
// Seven of the fourteen, not the six the follow-up says, because the follow-up
// counted a set of vectors that was never written down and this one counts the
// fourteen above.
func TestKeyOrderIsWrongOnHalfTheMapperConfigs(t *testing.T) {
	var wrong []string
	for _, v := range mapperConfigVectors {
		if !slices.Equal(javamap.KeyOrder(v.keys()), v.order()) {
			wrong = append(wrong, v.name)
		}
	}
	if len(wrong) != 7 {
		t.Fatalf("want KeyOrder wrong on 7 of the %d mapper configs, got %d: %v",
			len(mapperConfigVectors), len(wrong), wrong)
	}
}

// insertionOrderVectors are two key sets in all six of their insertion orders
// each, and they are why SizedKeyOrder takes an order rather than a set.
//
// {zz, aa, mm} comes back in whichever order it went in, all six times: the
// three collide everywhere and a chain is insertion order. {claim.name,
// jsonType.label, user.attribute} comes back in one order from all six: they
// collide in the final table and something ahead of it has already separated
// them. One table cannot produce both answers, which is the measurement that
// forced the intermediate one.
var insertionOrderVectors = []vector{
	{
		name: "three realistic keys, permutation 0",
		in:   "claim.name jsonType.label user.attribute",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "three realistic keys, permutation 1",
		in:   "claim.name user.attribute jsonType.label",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "three realistic keys, permutation 2",
		in:   "jsonType.label claim.name user.attribute",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "three realistic keys, permutation 3",
		in:   "jsonType.label user.attribute claim.name",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "three realistic keys, permutation 4",
		in:   "user.attribute claim.name jsonType.label",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "three realistic keys, permutation 5",
		in:   "user.attribute jsonType.label claim.name",
		want: "claim.name user.attribute jsonType.label",
	},
	{
		name: "zz aa mm, permutation 0",
		in:   "zz aa mm",
		want: "zz aa mm",
	},
	{
		name: "zz aa mm, permutation 1",
		in:   "zz mm aa",
		want: "zz mm aa",
	},
	{
		name: "zz aa mm, permutation 2",
		in:   "aa zz mm",
		want: "aa zz mm",
	},
	{
		name: "zz aa mm, permutation 3",
		in:   "aa mm zz",
		want: "aa mm zz",
	},
	{
		name: "zz aa mm, permutation 4",
		in:   "mm zz aa",
		want: "mm zz aa",
	},
	{
		name: "zz aa mm, permutation 5",
		in:   "mm aa zz",
		want: "mm aa zz",
	},
}

func TestSizedKeyOrderFollowsInsertionOrderInsideAChainAndNotOutsideOne(t *testing.T) {
	checkVectors(t, insertionOrderVectors)
}

// intermediateTableVectors read the intermediate table's size off the server,
// one entry count at a time.
//
// Two keys that agree at capacity C agree at every smaller capacity, because
// the mask is a suffix. So a pair agreeing at the final table's size and
// differing at twice it answers exactly one question: does anything ahead of
// the final table have at least that many buckets? If it does, the pair comes
// back in hash order whatever order it was sent in. If it does not, it comes
// back in the order it was sent.
//
// The answer flips between n=5 and n=6, between n=9 and n=10, and between n=18
// and n=19 - three boundaries that no round multiple of n fits and 7n/4 does.
// It was swept at every entry count from 1 to 50 and the fourth boundary, n=37
// to n=38, is in the handover; these six sizes are the ones that pin the
// arithmetic.
var intermediateTableVectors = []vector{
	{
		name: "n=5 keeps the pair in the order it was sent",
		in:   "y00020 y00006 y00000 y00001 y00002",
		want: "y00020 y00006 y00000 y00002 y00001",
	},
	{
		name: "n=5 keeps the pair in the other order it was sent",
		in:   "y00006 y00020 y00000 y00001 y00002",
		want: "y00006 y00020 y00000 y00002 y00001",
	},
	{
		name: "n=6 puts the pair in hash order",
		in:   "y00020 y00006 y00000 y00001 y00002 y00003",
		want: "y00020 y00006 y00000 y00002 y00001 y00003",
	},
	{
		name: "n=6 puts the pair in hash order from the other side",
		in:   "y00006 y00020 y00000 y00001 y00002 y00003",
		want: "y00020 y00006 y00000 y00002 y00001 y00003",
	},
	{
		name: "n=9 keeps the pair in the order it was sent",
		in:   "y00020 y00509 y00000 y00001 y00002 y00003 y00004 y00005 y00006",
		want: "y00020 y00509 y00000 y00006 y00005 y00002 y00001 y00004 y00003",
	},
	{
		name: "n=9 keeps the pair in the other order it was sent",
		in:   "y00509 y00020 y00000 y00001 y00002 y00003 y00004 y00005 y00006",
		want: "y00509 y00020 y00000 y00006 y00005 y00002 y00001 y00004 y00003",
	},
	{
		name: "n=10 puts the pair in hash order",
		in:   "y00020 y00509 y00000 y00001 y00002 y00003 y00004 y00005 y00006 y00007",
		want: "y00020 y00509 y00000 y00006 y00005 y00007 y00002 y00001 y00004 y00003",
	},
	{
		name: "n=10 puts the pair in hash order from the other side",
		in:   "y00509 y00020 y00000 y00001 y00002 y00003 y00004 y00005 y00006 y00007",
		want: "y00020 y00509 y00000 y00006 y00005 y00007 y00002 y00001 y00004 y00003",
	},
	{
		name: "n=18 keeps the pair in the order it was sent",
		in: "y00031 y00020 y00000 y00001 y00002 y00003 y00004 y00005 " +
			"y00006 y00007 y00008 y00009 y00010 y00011 y00012 y00013 " +
			"y00014 y00015",
		want: "y00031 y00020 y00000 y00011 y00010 y00006 y00005 y00008 " +
			"y00007 y00002 y00013 y00001 y00012 y00004 y00015 y00003 " +
			"y00014 y00009",
	},
	{
		name: "n=18 keeps the pair in the other order it was sent",
		in: "y00020 y00031 y00000 y00001 y00002 y00003 y00004 y00005 " +
			"y00006 y00007 y00008 y00009 y00010 y00011 y00012 y00013 " +
			"y00014 y00015",
		want: "y00020 y00031 y00000 y00011 y00010 y00006 y00005 y00008 " +
			"y00007 y00002 y00013 y00001 y00012 y00004 y00015 y00003 " +
			"y00014 y00009",
	},
	{
		name: "n=19 puts the pair in hash order",
		in: "y00031 y00020 y00000 y00001 y00002 y00003 y00004 y00005 " +
			"y00006 y00007 y00008 y00009 y00010 y00011 y00012 y00013 " +
			"y00014 y00015 y00016",
		want: "y00031 y00020 y00011 y00000 y00010 y00006 y00016 y00005 " +
			"y00008 y00007 y00013 y00002 y00012 y00001 y00015 y00004 " +
			"y00014 y00003 y00009",
	},
	{
		name: "n=19 puts the pair in hash order from the other side",
		in: "y00020 y00031 y00000 y00001 y00002 y00003 y00004 y00005 " +
			"y00006 y00007 y00008 y00009 y00010 y00011 y00012 y00013 " +
			"y00014 y00015 y00016",
		want: "y00031 y00020 y00011 y00000 y00010 y00006 y00016 y00005 " +
			"y00008 y00007 y00013 y00002 y00012 y00001 y00015 y00004 " +
			"y00014 y00003 y00009",
	},
}

func TestSizedKeyOrderPinsTheIntermediateTableSize(t *testing.T) {
	checkVectors(t, intermediateTableVectors)
}

// The two functions are not interchangeable, and a caller that reaches for the
// wrong one should get a visibly wrong answer rather than a nearly right one.
func TestSizedKeyOrderIsNotKeyOrder(t *testing.T) {
	in := []string{"user.attribute", "claim.name"}
	sized := javamap.SizedKeyOrder(in)
	plain := javamap.KeyOrder(in)
	if slices.Equal(sized, plain) {
		t.Fatalf("the two constructors agree on %v, so one of the two models is now unused", in)
	}
}

func TestSizedKeyOrderDoesNotModifyItsInput(t *testing.T) {
	in := []string{"user.attribute", "claim.name"}
	javamap.SizedKeyOrder(in)
	if !slices.Equal(in, []string{"user.attribute", "claim.name"}) {
		t.Fatalf("input was modified: %v", in)
	}
}

func TestSizedKeyOrderHandlesTheEmptyAndSingleCases(t *testing.T) {
	if got := javamap.SizedKeyOrder(nil); len(got) != 0 {
		t.Fatalf("nil produced %v", got)
	}
	if got := javamap.SizedKeyOrder([]string{"claim.name"}); !slices.Equal(got, []string{"claim.name"}) {
		t.Fatalf("one key produced %v", got)
	}
}
