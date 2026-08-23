package javamap_test

import (
	"slices"
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
