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
// ReplaceCaptured runs before all of them, ahead of any pass that could mask
// or reorder the bytes a captured token sits in, so a live token can never
// survive into a golden.
//
// ReplaceThemeResource runs beside ReplaceIssuer and after it. The order of
// those two is free rather than load-bearing and the reason is worth writing
// down: the theme's asset URLs are **relative** - `/resources/<version>/...` -
// so no issuer ever appears inside one and no `/resources/` segment ever
// appears inside an issuer. Putting it after keeps the two unconditional
// substitutions together and ahead of every Case-declared mask, which is the
// property that does matter.
//
// ReplaceHTMLValues is the first Case-declared mask and runs immediately after
// the two unconditional passes, which keeps the property above: everything
// unconditional first, then everything the catalogue declares. It has to run
// **before** ReplaceCaptured could be undone by anything and after it rather
// than before, because a value a fixture already captured comes out
// `{{captured}}` and an HTML mask sitting on one is then visibly covering a
// value that does not move - which is what TestNoHTMLMaskVariesNothing reports.
// Running it before ReplaceCaptured would hide exactly that.
//
// ReplaceXMLValues runs beside ReplaceHTMLValues and after it. The order of
// those two is free rather than load-bearing, and for a sharper reason than the
// one above: no case declares both, because no body is HTML and XML at once.
// They are kept adjacent so that every markup mask sits between the
// unconditional passes and the four JSON ones, which is the property that does
// matter - a JSON path cannot address a markup body and a markup mask cannot
// address a JSON one, so the two groups can never see each other's edits.
//
// SortUnorderedBracketed runs beside SortUnorderedWords and after it. The
// order of those two is free rather than load-bearing, and it is worth saying
// why: they are the two masks that reach inside a string, and both refuse a
// value that is not one, so a path naming a string can carry either - but no
// case declares both, and if one ever did, the words pass would have joined the
// brackets to their neighbouring items and the bracket pass would then find a
// string with no run left to sort. They are kept adjacent so that reading the
// pair as "the string masks" is what a reader does.
//
// It lives in its own file, called from both record_test.go and
// conformance_test.go, because a pass added to one side and not the other is
// a divergence no test can see: both sides would simply agree on the wrong
// bytes.
func normalisePasses(body []byte, base string, c Case, vars map[string]string) ([]byte, error) {
	body = ReplaceCaptured(body, vars)
	body = ReplaceIssuer(body, base)
	body = ReplaceThemeResource(body)
	body, err := ReplaceHTMLValues(body, c)
	if err != nil {
		return nil, err
	}
	body, err = ReplaceXMLValues(body, c)
	if err != nil {
		return nil, err
	}
	body, err = Normalize(body, c.Volatile)
	if err != nil {
		return nil, err
	}
	body, err = SortUnordered(body, c.Unordered)
	if err != nil {
		return nil, err
	}
	body, err = SortUnorderedWords(body, c.UnorderedWords)
	if err != nil {
		return nil, err
	}
	body, err = SortUnorderedBracketed(body, c.UnorderedBracketed)
	if err != nil {
		return nil, err
	}
	return SortUnorderedKeys(body, c.UnorderedKeys)
}
