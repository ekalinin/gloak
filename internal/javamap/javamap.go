// Package javamap reproduces the order a Java `HashMap` iterates its keys in,
// which is the order Keycloak's JSON serialiser writes them in.
//
// Go sorts map keys when it marshals a map; Java does not sort them at all. A
// JSON object Keycloak built from a `HashMap` therefore comes back in an order
// that looks arbitrary and is in fact exactly determined: `HashMap` walks its
// table from bucket 0 upwards, and a key's bucket is
//
//	(h ^ (h >>> 16)) & (capacity - 1)
//
// over `String.hashCode`.
//
// # There are two constructors and this package models both, separately
//
// The bucket rule is shared. The **table size** is not, and it is what the
// hash is masked with, so two maps holding the same keys iterate differently
// when they were built differently.
//
//   - [KeyOrder] models `new HashMap<>()`: 16 buckets, doubling each time the
//     0.75 load factor is crossed. Measured 2026-08-23 against Keycloak 26.7.1
//     and confirmed on six key sets - see javamap_test.go, which carries them as
//     vectors, and the "Java map key order" section of
//     docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//   - [SizedKeyOrder] models the map Keycloak serialises a protocol mapper's
//     `config` from, which is built for the entry count it was given and passes
//     through a second, larger table on the way. Measured 2026-08-30, and there
//     is no single table size that fits.
//
// Handing a sized map to KeyOrder is wrong on more than half of the measured
// mapper configs, so the two are separate exported functions rather than one
// with a heuristic. Which one a caller needs is a fact about the Java that
// built the map, and no Go function can read it off the keys.
//
// # The one thing KeyOrder cannot reproduce
//
// Two keys landing in the same bucket are chained in *insertion* order, and
// nothing observable says what Keycloak inserted first for the maps KeyOrder
// serves. KeyOrder breaks such ties alphabetically, which is a guess with even
// odds. It was measured going wrong on exactly one of its vectors: the 21 admin
// role names collide in two buckets, and both pairs come back the other way
// round.
//
// So it is right for the small key sets it is used on - `resource_access`
// carries one entry per client the user has roles on - and approximate for
// large ones. A conformance case comparing a large set has to say so with
// Case.Unordered rather than rely on this.
//
// SizedKeyOrder has no such gap and pays for it differently: it takes the keys
// in **insertion order** and is only as right as that argument is.
package javamap

import (
	"cmp"
	"slices"
	"unicode/utf16"
)

// KeyOrder returns keys in the order a Java HashMap built by the no-argument
// constructor iterates. The input is not modified.
//
// It is the wrong function for a map Java built with an explicit size - see
// [SizedKeyOrder], and the package comment for why the choice cannot be made
// here.
func KeyOrder(keys []string) []string {
	out := slices.Clone(keys)
	// Sorted first so that a bucket collision resolves the same way on every
	// call, whatever order the caller's map handed the keys over in.
	slices.Sort(out)
	byBucket(out, capacityFor(len(out)))
	return out
}

// SizedKeyOrder returns keys in the order Keycloak serialises a protocol
// mapper's `config` in. The input is not modified.
//
// keys are the keys in the order they were **inserted**, which for a mapper
// config is the order the create request's JSON carried them, followed by any
// the create appended for itself. That argument is load-bearing: keys that
// collide chain in insertion order, and this reproduces that rather than
// guessing at it the way KeyOrder has to.
//
// builtFor is how many entries the map was built for, which is the number of
// keys the request carried. It is len(keys) for a config the create left alone
// and smaller for one it grew: a provider that mirrors `access.token.claim`
// into `introspection.token.claim` appends the mirror **after** the map has
// already been through the first table, so the two counts differ and the answer
// does with them. Anything outside 1..len(keys) is read as len(keys), which is
// the ungrown case.
//
// Two tables, not one, and the measurement is what says so. `{claim.name,
// jsonType.label, user.attribute}` comes back in one order from all six of its
// insertion orders, so something ahead of the final table has already put those
// three in hash order; `{zz, aa, mm}` comes back in whichever order it went in,
// from all six, so that something does not separate *those* three. One table
// cannot do both. Read off the server at every entry count from 1 to 50: the
// keys pass through a table asked for 7n/4 buckets and are then re-inserted
// into one asked for the entry count.
func SizedKeyOrder(builtFor int, keys []string) []string {
	out := slices.Clone(keys)
	if builtFor <= 0 || builtFor > len(out) {
		builtFor = len(out)
	}
	// The order the keys reach the final table in, which is what decides a
	// chain there. 7n/4 is measured, not derived: the doubling it produces
	// moves between n=9 and n=10, n=18 and n=19, and n=37 and n=38, and those
	// three boundaries are what pin the numerator. Only the keys the map was
	// built for go through it - the appended ones arrive afterwards and keep
	// their place at the end.
	byBucket(out[:builtFor], capacity(7*builtFor/4, builtFor))
	byBucket(out, capacity(len(out), len(out)))
	return out
}

// byBucket sorts keys into table order in place, stably, so that keys sharing a
// bucket keep the order they arrived in.
func byBucket(keys []string, capacity uint32) {
	slices.SortStableFunc(keys, func(a, b string) int {
		return cmp.Compare(bucket(a, capacity), bucket(b, capacity))
	})
}

// capacityFor is the table size a HashMap holding n entries ends up with when
// it was built by the no-argument constructor: 16, doubling each time the 0.75
// load factor is crossed.
//
// The capacity matters because it is what the hash is masked with, so a map
// that has resized iterates in a different order than one that has not.
func capacityFor(n int) uint32 {
	capacity := uint32(16)
	for n > int(capacity/4*3) {
		capacity *= 2
	}
	return capacity
}

// capacity is the table a HashMap ends up with when it was asked for requested
// buckets and then given entries entries.
//
// `new HashMap<>(requested)` rounds the request up to a power of two and makes
// that the table; the 0.75 load factor then doubles it once if the entries do
// not fit. It can only double once, because the rounded-up request is already
// at least the entry count.
func capacity(requested, entries int) uint32 {
	c := tableSizeFor(requested)
	if entries*4 > int(c)*3 {
		c *= 2
	}
	return c
}

// tableSizeFor is HashMap.tableSizeFor: the smallest power of two that is not
// less than n, and 1 for anything below that.
func tableSizeFor(n int) uint32 {
	c := uint32(1)
	for c < uint32(n) {
		c *= 2
	}
	return c
}

// bucket is HashMap.hash(key) masked to the table size.
func bucket(s string, capacity uint32) uint32 {
	h := hashCode(s)
	// HashMap spreads the hash by xor-ing the high half down, so that keys
	// differing only above the mask still land in different buckets.
	return (h ^ (h >> 16)) & (capacity - 1)
}

// hashCode is java.lang.String.hashCode: 31*h + c over the UTF-16 code units,
// wrapping at 32 bits.
//
// The code units matter rather than the runes. Every key this is used on is
// ASCII today, where the two are the same, but a non-BMP rune is one rune and
// two code units and would hash differently.
func hashCode(s string) uint32 {
	var h uint32
	for _, u := range utf16.Encode([]rune(s)) {
		h = 31*h + uint32(u)
	}
	return h
}
