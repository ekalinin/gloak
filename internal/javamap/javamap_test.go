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

// F90's answer: a client's `attributes` is the **no-argument** constructor's
// map, and KeyOrder places it exactly.
//
// The five vectors are every distinct attribute key set a default 26.7.1 has
// on this resource, read off a live container on 2026-08-30: the four shapes
// the six bootstrapped clients come in, and the one a client created through
// `POST /admin/realms/{realm}/clients` gets. Sorting is measurably not the
// answer to any of them - `realm_client` sorts last in four of the five and
// comes back first in all five.
//
// SizedKeyOrder is wrong on the four-key one, which is what says the choice of
// constructor is a real fork here rather than a distinction without a
// difference. The conformance suite's `attributes` retreat rests on this, so
// the vectors live where the rule does.
//
// **What they do not pin is the tie-break.** Every key here lands in a bucket
// of its own - 0, 2, 3, 9 and 11 at the default 16 - so no vector in this test
// exercises a chain, and a build that resolved collisions the other way round
// would pass all five. That limit is pinned by
// TestKeyOrderCannotResolveBucketCollisions below and by nothing here. They do
// pin the table size: at 8, 32 or 64 buckets at least one of the five comes
// back in a different order.
func TestKeyOrderReproducesAClientsAttributes(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{"account", []string{"realm_client", "post.logout.redirect.uris"}},
		{"account-console", []string{
			"realm_client", "post.logout.redirect.uris", "pkce.code.challenge.method",
		}},
		{"admin-cli", []string{
			"realm_client", "client.use.lightweight.access.token.enabled",
		}},
		// broker and master-realm carry realm_client alone, which no order can
		// get wrong, so they are not vectors.
		{"security-admin-console", []string{
			"realm_client", "client.use.lightweight.access.token.enabled",
			"post.logout.redirect.uris", "pkce.code.challenge.method",
		}},
		{"a client created through the Admin API", []string{
			"realm_client", "client.secret.creation.time",
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := slices.Sorted(slices.Values(c.want))
			if got := javamap.KeyOrder(in); !slices.Equal(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

// F105's three: the authentication SPI's provider registries, re-measured on a
// live Keycloak 26.7.1 on 2026-08-31 rather than transcribed from the P8
// handover that found them.
//
// Every one is a Java `Map<String,Object>` Keycloak builds by hand, so the
// order it serialises in is a HashMap's and not the order anything was put in:
//
//	GET .../authentication/authenticator-providers        42 rows, one key order
//	GET .../authentication/form-providers                  1 row,  the same order
//	GET .../authentication/form-action-providers           5 rows, the same order
//	GET .../authentication/client-authenticator-providers  5 rows, one key order
//	GET .../authentication/per-client-config-description   the object's own keys
//
// Measured on `master` and on a realm created through `POST /admin/realms`, and
// byte-identical on both.
//
// **What they pin that the client `attributes` vectors do not is the table
// size.** The five client-authenticator ids are reproduced at a capacity of 16
// and at **no other power of two** from 1 to 128, so a build that got
// capacityFor wrong for a five-key map fails here. The four-key registry row
// narrows it to 16 or 32 and the three-key one only to 2, 16, 32 or 64, which is
// why the weakest of the three is not the one carrying the claim.
//
// **What they do not pin is the tie-break**, exactly as with a client's
// attributes: no key set here collides. Buckets 6, 9 and 11 for the three-key
// row; 4, 6, 9 and 11 for the four-key one; 1, 5, 7, 14 and 15 for the five
// ids. TestKeyOrderMissesTheCollidingRequiredActionPairs below is the vector
// that exercises a chain.
//
// SizedKeyOrder is wrong on all three, which is what makes them evidence about
// *which* constructor the SPI registries use rather than only about the bucket
// rule.
func TestKeyOrderReproducesTheAuthenticationRegistries(t *testing.T) {
	cases := []struct {
		name string
		want []string
	}{
		{
			// authenticator-providers, form-providers and form-action-providers
			// all serve this shape, and all three came back in this order.
			name: "a provider registry row",
			want: []string{"displayName", "description", "id"},
		},
		{
			// client-authenticator-providers is the same row plus the flag, and
			// the flag comes back first rather than last.
			name: "a client authenticator row",
			want: []string{"supportsSecret", "displayName", "description", "id"},
		},
		{
			// per-client-config-description is an object keyed by client
			// authenticator id, which is the one of the six operations on this
			// tag that is not a list. SizedKeyOrder gets these five wrong.
			name: "per-client-config-description's five ids",
			want: []string{
				"client-jwt", "client-secret", "federated-jwt", "client-x509",
				"client-secret-jwt",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := slices.Sorted(slices.Values(c.want))
			if got := javamap.KeyOrder(in); !slices.Equal(got, c.want) {
				t.Fatalf("want %v, got %v", c.want, got)
			}
			if slices.Equal(in, c.want) {
				t.Fatalf("sorting reproduces %v, so this vector says nothing", c.want)
			}
			if got := javamap.SizedKeyOrder(len(in), in); slices.Equal(got, c.want) {
				t.Fatalf("SizedKeyOrder reproduces %v too, so this vector does not "+
					"say which constructor the registry uses", c.want)
			}
		})
	}
}

// F105's fourth, and the one worth more than the other three: the fourteen
// required action providers `GET .../unregistered-required-actions` serves once
// all fourteen have been unregistered.
//
// Re-measured on 2026-08-31 by deleting all fourteen rows in priority order,
// which is measurably not the order they come back in - on `master` and on a
// created realm, identically.
//
// It is a **near-miss and that is the point.** Twelve of the fourteen land
// exactly where KeyOrder puts them; the other two are the two bucket collisions,
// and Keycloak chains a collision in an insertion order nothing observable
// reveals while KeyOrder sorts. This is the second key set to demonstrate that
// limit after the 21 admin role names, and it demonstrates a stronger claim:
// the pairs are named here, so the test pins **which** positions are wrong
// rather than only how many.
//
// **Its chains agree with the 21 roles' and disagree with a realm's
// attributes.** Both pairs here come back in *descending* alphabetical order,
// and so do both of the 21 roles' - four of the five measured two-key chains in
// this repository. Reversing KeyOrder's pre-sort would therefore pass this test,
// TestKeyOrderCannotResolveBucketCollisions and every vector above. It is still
// a guess: a realm's `attributes` has a two-key chain that comes back
// *ascending* and a four-key chain that fits neither direction, so no
// alphabetical tie-break can be right, and four of five is what a coin looks
// like when it has been flipped five times. The tie-break is unpinned by
// construction and these vectors do not change that - they only make the size
// of the gap visible.
func TestKeyOrderMissesTheCollidingRequiredActionPairs(t *testing.T) {
	measured := []string{
		"CONFIGURE_TOTP", "webauthn-register-passwordless", "UPDATE_PASSWORD",
		"update_user_locale", "TERMS_AND_CONDITIONS", "idp_link", "delete_account",
		"VERIFY_EMAIL", "UPDATE_EMAIL", "webauthn-register", "VERIFY_PROFILE",
		"delete_credential", "CONFIGURE_RECOVERY_AUTHN_CODES", "UPDATE_PROFILE",
	}
	got := javamap.KeyOrder(slices.Sorted(slices.Values(measured)))

	if slices.Equal(got, measured) {
		t.Fatal("KeyOrder now places all fourteen required action providers; " +
			"if that is real, this test and the package doc are out of date")
	}

	// The two chains, named. A count alone would pass a build that swapped some
	// other pair, and the whole value of this vector over the 21 role names is
	// that it collides twice in fourteen keys rather than twice in twenty-one.
	want := slices.Clone(measured)
	for _, pair := range [][2]int{{3, 4}, {6, 7}} {
		want[pair[0]], want[pair[1]] = want[pair[1]], want[pair[0]]
	}
	if !slices.Equal(got, want) {
		t.Fatalf("want exactly {update_user_locale, TERMS_AND_CONDITIONS} and "+
			"{delete_account, VERIFY_EMAIL} swapped and nothing else\nwant %v\ngot  %v",
			want, got)
	}
}

// The other half of F90's answer, and the reason the conformance suite's
// retreat is not one thing: a **realm's** attributes are the same constructor
// and KeyOrder still cannot place them, because four of the eight keys share
// bucket 0 and Keycloak chains a collision in an insertion order nothing
// observable reveals.
//
// Measured 2026-08-30 on a realm created through POST /admin/realms. The
// assertion is that the first three positions are wrong and the last five are
// right: the bucket rule holds and only the chain does not, exactly as on the
// 21 admin role names.
func TestKeyOrderCannotPlaceARealmsAttributes(t *testing.T) {
	measured := []string{
		"cibaBackchannelTokenDeliveryMode", "cibaExpiresIn", "cibaAuthRequestedUserHint",
		"oauth2DeviceCodeLifespan", "oauth2DevicePollingInterval", "parRequestUriLifespan",
		"cibaInterval", "realmReusableOtpCode",
	}
	got := javamap.KeyOrder(slices.Sorted(slices.Values(measured)))

	if slices.Equal(got, measured) {
		t.Fatal("KeyOrder now places a realm's attributes; if that is real, " +
			"internal/conformance's UnorderedKeys mask on them can come off")
	}
	var differing []int
	for i := range measured {
		if got[i] != measured[i] {
			differing = append(differing, i)
		}
	}
	if !slices.Equal(differing, []int{0, 1, 2}) {
		t.Fatalf("want the bucket-0 chain wrong and nothing else, got %v", differing)
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
// fifty of them is unreadable written out as slices.
type vector struct {
	name     string
	builtFor int    // how many keys the create request carried; 0 means all of them
	in       string // the order the keys were inserted in
	want     string // the order the mapper route served them back in
}

func (v vector) keys() []string  { return strings.Fields(v.in) }
func (v vector) order() []string { return strings.Fields(v.want) }

func checkVectors(t *testing.T, vectors []vector) {
	t.Helper()
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			keys := v.keys()
			builtFor := v.builtFor
			if builtFor == 0 {
				builtFor = len(keys)
			}
			got := javamap.SizedKeyOrder(builtFor, keys)
			if !slices.Equal(got, v.order()) {
				t.Fatalf("\nin   %v\nwant %v\ngot  %v", keys, v.order(), got)
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

// grownVectors are configs whose create appended keys of its own: a provider
// that mirrors access.token.claim into introspection.token.claim, and
// id.token.claim into userinfo.token.claim, adds them **after** the map has
// already been through the first table. So the map was built for the request's
// key count and serialised at a larger one, and the two counts are what
// builtFor carries.
//
// Eleven of these twelve come out right if builtFor is ignored, which is why
// there are twelve. The one that does not - a request of four grown to six -
// puts access.token.claim and introspection.token.claim in one final bucket,
// and whether the first table separated them is decided by a count the keys
// themselves do not carry.
var grownVectors = []vector{
	{
		name:     "two mirrored keys, access first",
		builtFor: 2,
		in: "access.token.claim id.token.claim " +
			"introspection.token.claim userinfo.token.claim",
		want: "id.token.claim access.token.claim " +
			"introspection.token.claim userinfo.token.claim",
	},
	{
		name:     "two mirrored keys, id first",
		builtFor: 2,
		in: "id.token.claim access.token.claim " +
			"introspection.token.claim userinfo.token.claim",
		want: "id.token.claim access.token.claim " +
			"introspection.token.claim userinfo.token.claim",
	},
	{
		name:     "request of three grown to four",
		builtFor: 3,
		in: "access.token.claim claim.name user.attribute " +
			"introspection.token.claim",
		want: "user.attribute access.token.claim " +
			"introspection.token.claim claim.name",
	},
	{
		name:     "request of four grown to six",
		builtFor: 4,
		in: "claim.name id.token.claim access.token.claim " +
			"jsonType.label introspection.token.claim " +
			"userinfo.token.claim",
		want: "id.token.claim access.token.claim " +
			"introspection.token.claim claim.name jsonType.label " +
			"userinfo.token.claim",
	},
	{
		name:     "request of five grown to seven",
		builtFor: 5,
		in: "user.attribute access.token.claim id.token.claim " +
			"claim.name jsonType.label introspection.token.claim " +
			"userinfo.token.claim",
		want: "introspection.token.claim userinfo.token.claim " +
			"user.attribute id.token.claim access.token.claim " +
			"claim.name jsonType.label",
	},
	{
		name:     "request of six grown to eight",
		builtFor: 6,
		in: "user.attribute access.token.claim id.token.claim " +
			"claim.name jsonType.label multivalued " +
			"introspection.token.claim userinfo.token.claim",
		want: "introspection.token.claim multivalued userinfo.token.claim " +
			"user.attribute id.token.claim access.token.claim " +
			"claim.name jsonType.label",
	},
	{
		name:     "request of seven grown to eight",
		builtFor: 7,
		in:       "a b c d access.token.claim e f introspection.token.claim",
		want:     "a b c introspection.token.claim d e f access.token.claim",
	},
	{
		name:     "request of eight grown to nine",
		builtFor: 8,
		in:       "k1 k2 k3 k4 k5 k6 k7 id.token.claim userinfo.token.claim",
		want:     "k1 k2 userinfo.token.claim k3 k4 k5 id.token.claim k6 k7",
	},
	{
		name:     "the colliding trio with two mirrors behind it",
		builtFor: 5,
		in: "zz aa mm access.token.claim id.token.claim " +
			"introspection.token.claim userinfo.token.claim",
		want: "zz aa mm introspection.token.claim userinfo.token.claim " +
			"id.token.claim access.token.claim",
	},
	{
		name:     "request of ten grown to eleven",
		builtFor: 10,
		in: "p1 p2 p3 p4 p5 p6 p7 p8 p9 access.token.claim " +
			"introspection.token.claim",
		want: "p1 p2 p3 introspection.token.claim p4 p5 p6 p7 p8 p9 " +
			"access.token.claim",
	},
	{
		name:     "request of twelve grown to fourteen",
		builtFor: 12,
		in: "q01 q02 q03 q04 q05 q06 q07 q08 q09 q10 access.token.claim " +
			"id.token.claim introspection.token.claim " +
			"userinfo.token.claim",
		want: "access.token.claim q10 q02 q01 introspection.token.claim " +
			"q04 q03 q06 q05 userinfo.token.claim q08 q07 " +
			"id.token.claim q09",
	},
	{
		name:     "a mirroring provider that had nothing to mirror",
		builtFor: 2,
		in:       "claim.name user.attribute",
		want:     "claim.name user.attribute",
	},
	// This one is here because the twelve above cannot tell whether the
	// appended key goes through the first table with the rest or arrives after
	// it, and every realistic config is too small to say: the two spellings
	// differ only when introspection.token.claim shares the final table's
	// bucket with a key that outranks it in the intermediate one, which needs
	// a request of 19 to 23 keys or of 38 to 47. Measured at 19: the appended
	// key stays behind z00014, so it arrives after the first table.
	{
		name:     "request of nineteen grown to twenty",
		builtFor: 19,
		in: "z00014 z00000 z00001 z00002 z00003 z00004 z00005 z00006 " +
			"z00007 z00008 z00009 z00010 z00011 z00012 z00013 z00015 " +
			"z00016 z00017 access.token.claim " +
			"introspection.token.claim",
		want: "access.token.claim z00004 z00015 z00005 z00016 z00002 " +
			"z00013 z00003 z00014 introspection.token.claim z00008 " +
			"z00009 z00006 z00017 z00007 z00000 z00011 z00001 z00012 " +
			"z00010",
	},
}

func TestSizedKeyOrderModelsAMapThatGrewAfterItWasBuilt(t *testing.T) {
	checkVectors(t, grownVectors)
}

// builtFor is a count and not a hint, so a caller that has none should get the
// ungrown answer rather than a silently different one.
func TestSizedKeyOrderReadsAnImpossibleBuiltForAsTheWholeSlice(t *testing.T) {
	keys := []string{"claim.name", "jsonType.label", "user.attribute"}
	want := javamap.SizedKeyOrder(len(keys), keys)
	for _, builtFor := range []int{-1, 0, len(keys) + 1, 1 << 20} {
		if got := javamap.SizedKeyOrder(builtFor, keys); !slices.Equal(got, want) {
			t.Errorf("builtFor=%d: want %v, got %v", builtFor, want, got)
		}
	}
}

// The two functions are not interchangeable, and a caller that reaches for the
// wrong one should get a visibly wrong answer rather than a nearly right one.
func TestSizedKeyOrderIsNotKeyOrder(t *testing.T) {
	in := []string{"user.attribute", "claim.name"}
	sized := javamap.SizedKeyOrder(len(in), in)
	plain := javamap.KeyOrder(in)
	if slices.Equal(sized, plain) {
		t.Fatalf("the two constructors agree on %v, so one of the two models is now unused", in)
	}
}

func TestSizedKeyOrderDoesNotModifyItsInput(t *testing.T) {
	in := []string{"user.attribute", "claim.name"}
	javamap.SizedKeyOrder(len(in), in)
	if !slices.Equal(in, []string{"user.attribute", "claim.name"}) {
		t.Fatalf("input was modified: %v", in)
	}
}

func TestSizedKeyOrderHandlesTheEmptyAndSingleCases(t *testing.T) {
	if got := javamap.SizedKeyOrder(0, nil); len(got) != 0 {
		t.Fatalf("nil produced %v", got)
	}
	if got := javamap.SizedKeyOrder(1, []string{"claim.name"}); !slices.Equal(got, []string{"claim.name"}) {
		t.Fatalf("one key produced %v", got)
	}
}
