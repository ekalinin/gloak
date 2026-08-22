package conformance

// normalisePasses runs the passes that make a recorded response and a served
// response comparable, in the one order both sides must use.
//
// The order matters and is not arbitrary. ReplaceIssuer runs first so issuer
// URLs inside array elements are already rewritten before either later pass
// compares raw bytes. Normalize runs before SortUnordered so an array element
// whose own identity is volatile (oidc/certs/master's "keys" entries start
// with a random "kid") is sorted by what is left after normalisation rather
// than by the random bytes being masked; sorting first would make the
// recorded order depend on whichever "kid" happened to compare smaller, which
// is exactly the kind of per-run churn this order exists to avoid.
//
// It lives in its own file, called from both record_test.go and
// conformance_test.go, because a pass added to one side and not the other is
// a divergence no test can see: both sides would simply agree on the wrong
// bytes.
func normalisePasses(body []byte, base string, c Case) ([]byte, error) {
	body = ReplaceIssuer(body, base)
	body, err := Normalize(body, c.Volatile)
	if err != nil {
		return nil, err
	}
	body, err = SortUnordered(body, c.Unordered)
	if err != nil {
		return nil, err
	}
	return SortUnorderedWords(body, c.UnorderedWords)
}
