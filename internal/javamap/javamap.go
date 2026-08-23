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
// over `String.hashCode`. Measured 2026-08-23 against Keycloak 26.7.1 and
// confirmed on four independent key sets - see javamap_test.go, which carries
// them as vectors, and the "Java map key order" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// # The one thing this cannot reproduce
//
// Two keys landing in the same bucket are chained in *insertion* order, and
// nothing observable says what Keycloak inserted first. KeyOrder breaks such
// ties alphabetically, which is a guess with even odds. It was measured going
// wrong on exactly one of the four vectors: the 21 admin role names collide in
// two buckets, and both pairs come back the other way round.
//
// So this is right for the small key sets it is used on - `resource_access`
// carries one entry per client the user has roles on - and approximate for
// large ones. A conformance case comparing a large set has to say so with
// Case.Unordered rather than rely on this.
package javamap

import (
	"cmp"
	"slices"
	"unicode/utf16"
)

// KeyOrder returns keys in the order a Java HashMap built from them iterates.
// The input is not modified.
func KeyOrder(keys []string) []string {
	out := slices.Clone(keys)
	// Sorted first so that a bucket collision resolves the same way on every
	// call, whatever order the caller's map handed the keys over in.
	slices.Sort(out)
	capacity := capacityFor(len(out))
	slices.SortStableFunc(out, func(a, b string) int {
		return cmp.Compare(bucket(a, capacity), bucket(b, capacity))
	})
	return out
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
