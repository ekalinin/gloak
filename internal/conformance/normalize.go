package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// issuerPlaceholder stands in for the base URL of whichever server produced a
// body. The reference container answers on http://localhost:18091 and the test
// server on http://localhost:8080, so without this every absolute URL differs.
const issuerPlaceholder = "{{issuer}}"

// rootPath is how a Case names the value at the root of the body, which has no
// key to be addressed by. It exists because Keycloak returns bare arrays whose
// order is not stable - every role listing is one - and Case.Unordered has to
// be able to say so.
const rootPath = "."

// compilePaths turns the slash-separated path spellings a Case carries into
// the segment patterns the editor matches against. The root compiles to the
// empty pattern, which is the one thing strings.Split cannot produce: it
// returns [""] for an empty string, a one-segment pattern matching a key whose
// name is empty.
func compilePaths(paths []string) [][]string {
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		if p == rootPath {
			patterns = append(patterns, []string{})
			continue
		}
		patterns = append(patterns, strings.Split(p, "/"))
	}
	return patterns
}

// ReplaceIssuer swaps a server's base URL for the placeholder, in both its raw
// and its percent-encoded spelling.
//
// The encoded pass is not decoration. The authorization endpoint's redirect
// carries the issuer as a query parameter of its Location header:
//
//	Location: http://localhost:9999/callback?state=xyz123&iss=http%3A%2F%2Flocalhost%3A8083%2Frealms%2Fmaster
//
// The raw base URL does not appear in that string, so a raw-only substitution
// misses it and a golden recorded on one port differs from the handler's on
// that parameter alone.
//
// The alternative was to mask the whole header with Case.VolatileHeaders, and
// the two are not equivalent: masking discards the query key order, the error
// code and the error description, which for the authorization endpoint's
// rejections is the entire contract.
//
// Raw first. The other order would leave an encoded occurrence untouched
// inside a value that also holds a raw one, since the raw pass would have
// already rewritten the substring the encoded pattern was built from.
func ReplaceIssuer(raw []byte, base string) []byte {
	if base == "" {
		return raw
	}
	raw = bytes.ReplaceAll(raw, []byte(base), []byte(issuerPlaceholder))
	return bytes.ReplaceAll(raw, []byte(url.QueryEscape(base)), []byte(issuerPlaceholder))
}

// themeResourcePlaceholder stands in for the login theme's cache-busting
// segment, the one value a keycloak.v2 page carries that belongs to the
// installation rather than to the request.
const themeResourcePlaceholder = "{{theme_resource}}"

// themeResourcePattern is `/resources/<version>/`, and the version is written
// against what has been measured rather than against what a token could in
// principle be.
//
// Thirteen values have been measured: `l3kth`, `fl8wm` and `ynxld` off the
// goldens this pass promotes, plus ten taken on 2026-09-01 - `t72jg`, `880ae`
// and eight more from eight fresh databases. Every one is **exactly five
// characters, lowercase letters and digits**. Sixty-five sampled characters
// with no uppercase among them; a mixed-case alphanumeric alphabet would do
// that with probability (36/62)^65, about 1e-15.
//
// A value outside the alphabet would fail loudly rather than quietly: the
// recording side would write the raw segment into the golden, the serving side
// would write Gloak's own, and TestConformance would go red on the difference.
var themeResourcePattern = regexp.MustCompile(`/resources/[0-9a-z]{5}/`)

// ReplaceThemeResource swaps the login theme's `/resources/<version>/` segment
// for a placeholder, so that a page recorded against one installation and the
// same page served by another compare equal.
//
// Keycloak mints the version once and stores it: six `docker restart` of one
// container gave one value, a second container gave another, and wiping
// `/opt/keycloak/data/h2` and restarting gave eight more - the value is inside
// `keycloakdb.mv.db`. Every document in this repository that mentions it says
// "per container start", which is measurably not what it is; the harness is
// unaffected either way, because `make record` starts a fresh container each
// time. Gloak mints its own the same shape, so the pass has two sides to make
// comparable rather than one to erase.
//
// It is unconditional, like ReplaceIssuer and unlike every Case mask, because
// the value is a property of whichever server answered rather than of the case
// that asked. A per-case flag would be a mask somebody forgets on the ninth
// theme page, and a forgotten mask here churns a golden on every re-record -
// which is the disease this pass exists to cure.
//
// **What it does to a page that legitimately holds `/resources/` in prose**: it
// rewrites it, if and only if the next path segment is five lowercase
// alphanumerics followed by a slash. `see /resources/login/index.html` would
// come out as `see /resources/{{theme_resource}}/index.html`. That over-reach
// is bounded by a fact rather than a hope - `/resources/` appears in no golden
// in this repository outside the eight theme pages, and
// TestThemeResourceAppearsOnlyInTheThemePages is what keeps saying so.
func ReplaceThemeResource(raw []byte) []byte {
	return themeResourcePattern.ReplaceAll(raw,
		[]byte("/resources/"+themeResourcePlaceholder+"/"))
}

// The HTML body masks, and why they are not any of the four passes above.
//
// `Case.Volatile` and its three siblings address a **JSON document**: Normalize
// hands the body to editPaths, which builds a json.NewDecoder over it. A theme
// page is not JSON, so with any path declared editPaths returns a decode error
// rather than a mask; there is no path to write, not merely an awkward one.
// ReplaceIssuer and ReplaceThemeResource are unconditional and have to stay so -
// the value each of them rewrites is a property of whichever server answered
// rather than of the case that asked, which ReplaceThemeResource's doc comment
// states as the reason it has no catalogue surface. A tab_id is the opposite: it
// is a property of the request, and an unconditional pass would rewrite it in
// bodies where it is the contract.
//
// And ReplaceCaptured reaches exactly what a **fixture step** captured. That
// boundary is narrower than "minted by the case's own request", and the two come
// apart: on a page reached by walking the flow the tab_id in the markup is the
// tab the fixture's own GET /auth minted, so CaptureForm's `action` already
// holds it. What no capture reaches is a value the case's **own** request mints
// (prompt-create is that request), a session_code a page rotates while rendering
// itself, and the KC_AUTH_SESSION_HASH, which arrives only inside a Set-Cookie
// whose whole header line is what CaptureHeader yields.
//
// So the mask is per case, per named value, and it covers the **value** and
// never its frame. Masking startSessionPolling's whole argument instead of the
// tab_id inside it would be F46's retreat one level down: it would give up the
// realm, the endpoint, client_id, client_data and skip_logout to hide eleven
// characters. See Case.VolatileHTMLQuery and Case.VolatileHTMLCall.

// htmlValueTerminators are the bytes a query parameter's value can end at inside
// a body. `&` covers both the raw separator and the first byte of `&amp;`, which
// is how the same URL is spelled inside an href where it is spelled raw inside a
// JavaScript string - both spellings appear on one measured page.
const htmlValueTerminators = "&\"'<> \t\r\n"

// htmlMatch is the byte range one HTML mask covers.
type htmlMatch struct{ start, end int }

// htmlQueryMatches is every place a URL in raw carries `name=<value>`.
//
// The occurrence has to be a whole parameter rather than the tail of a longer
// one, so the byte in front of it is required to be `?`, `&`, or the `;` closing
// an `&amp;`. Without that, masking `tab_id` would also fire on a parameter
// named `client_tab_id`, and a mask that reaches further than it says is the
// failure this file's other doc comments keep naming.
func htmlQueryMatches(raw []byte, name string) []htmlMatch {
	needle := []byte(name + "=")
	var out []htmlMatch
	for i := 0; ; {
		j := bytes.Index(raw[i:], needle)
		if j < 0 {
			return out
		}
		at := i + j
		i = at + len(needle)
		if !openedAsQueryKey(raw, at) {
			continue
		}
		end := i + bytes.IndexAny(raw[i:], htmlValueTerminators)
		if end < i {
			end = len(raw)
		}
		out = append(out, htmlMatch{start: i, end: end})
	}
}

// openedAsQueryKey reports whether the parameter starting at i is a whole query
// key rather than the suffix of a longer one.
func openedAsQueryKey(raw []byte, i int) bool {
	if i == 0 {
		return false
	}
	if raw[i-1] == '?' || raw[i-1] == '&' {
		return true
	}
	return raw[i-1] == ';' && i >= len("&amp;") && string(raw[i-len("&amp;"):i]) == "&amp;"
}

// htmlCallMatches is every place raw calls `name(` with one quoted argument, and
// it is where the KC_AUTH_SESSION_HASH inside checkAuthSession(...) is reached.
//
// It refuses rather than masking when the first thing after the parenthesis is
// not a quoted string, for MaskURLTail's reason: a mask that quietly covers
// something of another shape is a measurement thrown away while looking like one
// that was checked.
func htmlCallMatches(raw []byte, name string) ([]htmlMatch, error) {
	needle := []byte(name + "(")
	var out []htmlMatch
	for i := 0; ; {
		j := bytes.Index(raw[i:], needle)
		if j < 0 {
			return out, nil
		}
		at := i + j
		i = at + len(needle)
		// A call whose name merely ends in this one is a different call.
		rest := raw[i:]
		open := bytes.IndexFunc(rest, func(r rune) bool {
			return r != ' ' && r != '\t' && r != '\r' && r != '\n'
		})
		if open < 0 || rest[open] != '"' {
			return nil, fmt.Errorf("%s(...) is not called with a quoted string", name)
		}
		start := i + open + 1
		shut := bytes.IndexByte(raw[start:], '"')
		if shut < 0 {
			return nil, fmt.Errorf("%s(...)'s argument is not terminated", name)
		}
		out = append(out, htmlMatch{start: start, end: start + shut})
		i = start + shut
	}
}

func isIdentifierByte(b byte) bool {
	return b == '_' || b == '$' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// HTMLMaskedValues returns the raw bytes every HTML mask on c covers, keyed by
// the name that declared it.
//
// It exists so a guard can ask what a mask actually covers, and it is the same
// two finders the masker splices with rather than a second pair written in a
// test - MaskedValues' doc comment has the argument, and it is the same one: two
// resolvers drift, and the one that drifts is the one nobody runs against a real
// body.
//
// An empty slice for a name is a fact about the mask: it addressed nothing.
func HTMLMaskedValues(raw []byte, c Case) (map[string][][]byte, error) {
	out := map[string][][]byte{}
	collect := func(name string, ms []htmlMatch) {
		values := make([][]byte, 0, len(ms))
		for _, m := range ms {
			values = append(values, raw[m.start:m.end])
		}
		out[name] = values
	}
	for _, name := range c.VolatileHTMLQuery {
		collect(name, htmlQueryMatches(raw, name))
	}
	for _, name := range c.VolatileHTMLCall {
		ms, err := htmlCallMatches(raw, name)
		if err != nil {
			return nil, fmt.Errorf("conformance: html call mask %q: %w", name, err)
		}
		collect(name, ms)
	}
	return out, nil
}

// ReplaceHTMLValues masks every value c's HTML masks name, writing `{{name}}`
// where the value was and leaving every other byte of the page alone.
//
// **A declared name that the body does not carry is an error**, on both sides,
// the way SortUnordered errors on a path that is not an array. A mask that masks
// nothing while claiming to have checked is worse than a loud failure, and here
// it is worse still: the golden would hold the placeholder, the served body
// would hold the raw value, and the diff would blame the page rather than the
// declaration. So would an **empty** value, which is why one is refused too.
//
// It is called from normalisePasses and from nowhere else, which is what makes
// it survive `make record`: a pass on the replay side alone lets the two sides
// agree on the wrong bytes, and passes.go's doc comment is where that is written
// down.
func ReplaceHTMLValues(raw []byte, c Case) ([]byte, error) {
	var edits []edit
	add := func(name string, ms []htmlMatch) error {
		if len(ms) == 0 {
			return fmt.Errorf("conformance: html mask %q covers nothing in this body - "+
				"drop the mask, or name the value the page actually carries", name)
		}
		for _, m := range ms {
			if m.end <= m.start {
				return fmt.Errorf("conformance: html mask %q covers an empty value - "+
					"a mask over no bytes asserts nothing and hides that it does", name)
			}
			edits = append(edits, edit{start: m.start, end: m.end, repl: []byte("{{" + name + "}}")})
		}
		return nil
	}
	for _, name := range c.VolatileHTMLQuery {
		if err := add(name, htmlQueryMatches(raw, name)); err != nil {
			return nil, err
		}
	}
	for _, name := range c.VolatileHTMLCall {
		ms, err := htmlCallMatches(raw, name)
		if err != nil {
			return nil, fmt.Errorf("conformance: html call mask %q: %w", name, err)
		}
		if err := add(name, ms); err != nil {
			return nil, err
		}
	}
	return applyEdits(raw, edits), nil
}

// Normalize replaces the values at the given paths with placeholders that
// carry the original JSON type, so a string turning into a number is still
// caught.
//
// It edits byte ranges in place. It deliberately does not unmarshal and
// re-marshal: Go sorts map keys alphabetically, and key order is the contract
// this suite exists to check. Paths are slash-separated from the document
// root, array elements addressed by index, "*" matching any one segment.
//
// With an empty path list, or an empty (or whitespace-only) body, the body
// is returned unchanged without being looked at, JSON or not - this is what
// lets a 401 with an empty body (the userinfo rejection) pass through
// safely with no paths declared. Outside those two cases, though, Normalize
// has to parse the body to find the declared paths, and a non-empty body
// that is not valid JSON at that point is an error, not a silent
// pass-through: masking nothing while claiming to have checked is worse
// than failing loud.
func Normalize(raw []byte, paths []string) ([]byte, error) {
	out, err := editPaths(raw, paths, (*editor).replace)
	if err != nil {
		return nil, fmt.Errorf("conformance: normalize: %w", err)
	}
	return out, nil
}

// SortUnordered reorders the elements of the JSON arrays at the given paths,
// sorted by each element's own raw bytes. Each element keeps its bytes
// verbatim; only their sequence changes. Everything else - key order,
// spacing, the rest of the document - is untouched, using the same
// byte-range splice machinery as Normalize.
//
// Path syntax matches Normalize: slash-separated from the document root,
// "*" matching one segment. A path that does not resolve to an array is an
// error rather than a silent no-op: Unordered exists to keep asserting
// membership while giving up order, and a scalar or object at that path
// means the wrong path was named.
//
// A path inside another path is sorted too, innermost first, which is what
// editPaths' depth passes are for. `{".", "*/protocolMappers"}` sorts every
// scope's mappers and then sorts the scopes, and both orders are asserted.
// It silently sorted only the root until 2026-08-30 - see F59 and editPaths.
func SortUnordered(raw []byte, paths []string) ([]byte, error) {
	out, err := editPaths(raw, paths, (*editor).sortArray)
	if err != nil {
		return nil, fmt.Errorf("conformance: sort unordered: %w", err)
	}
	return out, nil
}

// SortUnorderedKeys rewrites the objects at the given paths with their keys
// sorted, on both sides of a comparison, so that key order stops being
// asserted there while membership and values stay asserted.
//
// It is the deliberate exception to this suite's rule that key order is
// contract. See editor.sortKeys for why.
func SortUnorderedKeys(raw []byte, paths []string) ([]byte, error) {
	out, err := editPaths(raw, paths, (*editor).sortKeys)
	if err != nil {
		return nil, fmt.Errorf("conformance: sort unordered keys: %w", err)
	}
	return out, nil
}

// SortUnorderedWords sorts the space-separated words inside the string values
// at the given paths, rewriting each as its words joined by single spaces.
//
// It exists because Keycloak emits at least one field - the token response's
// scope - whose word order inside a single string is not stable across
// container starts, for the same reason scopes_supported's array order is
// not: a Java set with no fixed iteration order. SortUnordered addresses JSON
// arrays and cannot reach inside a string value.
//
// Path syntax matches Normalize and SortUnordered. A path resolving to
// anything but a string is an error rather than a silent no-op: it means the
// wrong path was named, and a mask that masks nothing while claiming to have
// checked is worse than a loud failure.
func SortUnorderedWords(raw []byte, paths []string) ([]byte, error) {
	out, err := editPaths(raw, paths, (*editor).sortWords)
	if err != nil {
		return nil, fmt.Errorf("conformance: sort unordered words: %w", err)
	}
	return out, nil
}

// MaskedValues returns the raw JSON of every value the given paths address,
// without changing a byte.
//
// The order is editPaths': deepest path group first, document order inside a
// group. It is **not** the document's, and it does not pair value i with path i.
// Callers ask "what does this mask cover?" of one path at a time, which is the
// question the ordering is irrelevant to.
//
// It exists so that a guard can ask what a mask actually covers. The obvious
// way to write one is a second little path resolver in the test file, and that
// is the way it must not be written: two resolvers drift, and the one that
// drifts is the one nobody runs against a real golden. This is the same
// editPaths walk with an onMatch that reads instead of splices, so a mask the
// guard says covers nothing is a mask the masker also covers nothing with.
//
// An empty result is therefore a fact about the mask, not about this function:
// the paths addressed no value in the body at all.
func MaskedValues(raw []byte, paths []string) ([][]byte, error) {
	var out [][]byte
	_, err := editPaths(raw, paths, func(e *editor) error {
		var v json.RawMessage
		if err := e.dec.Decode(&v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("conformance: masked values: %w", err)
	}
	return out, nil
}

// editPaths walks raw once per distinct path depth, deepest first, splicing the
// edits of each walk before the next one starts, and calls onMatch at every
// value a path addresses.
//
// **The depth passes are the fix for F59, and one walk cannot do the job.**
// editor.value asks "does a pattern match this path?" before "is this path
// inside one?", and onMatch decodes the whole value it matched. So a pattern
// matching an outer value consumed everything under it and the patterns
// pointing inside were never visited: `Unordered: {".", "*/protocolMappers"}`
// sorted the root and ignored the nested path **with no error at all**. The
// case looked as though it asserted the nested set and did not, which is the
// disease F39 was corrected for - masking nothing while appearing to have
// checked - and admin/client-scopes/list gave up on thirty-five bootstrapped
// protocol mappers because of it.
//
// Erroring on the combination was the other candidate and would have been
// honest. Handling it is cheaper than it looks and asserts more: inside one
// depth no path can be a prefix of another - being a prefix means being
// shorter - so each walk is the old walk with the ambiguity arithmetically
// impossible, and the only new machinery is the grouping and the splice
// between passes. Sorting the inner arrays first also makes the outer sort
// deterministic, since an element's bytes are settled before anything compares
// them.
//
// A body with no paths declared, or one that is empty or whitespace, is
// returned unchanged without being looked at. Everything else has to parse.
func editPaths(raw []byte, paths []string, onMatch func(*editor) error) ([]byte, error) {
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	for _, group := range byDepth(compilePaths(paths)) {
		e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: group}
		e.onMatch = func() error { return onMatch(e) }
		if err := e.value(nil); err != nil {
			if err == io.EOF {
				// Nothing was decoded, so nothing was edited either.
				return raw, nil
			}
			return nil, err
		}
		raw = applyEdits(raw, e.edits)
	}
	return raw, nil
}

// byDepth groups patterns by how many segments they have, deepest group first.
// The root pattern - compilePaths' empty slice - is depth zero and therefore
// last, which is what lets it be sorted after everything nested inside it.
func byDepth(patterns [][]string) [][][]string {
	groups := map[int][][]string{}
	depths := make([]int, 0, len(patterns))
	for _, p := range patterns {
		if _, seen := groups[len(p)]; !seen {
			depths = append(depths, len(p))
		}
		groups[len(p)] = append(groups[len(p)], p)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(depths)))
	out := make([][][]string, 0, len(depths))
	for _, d := range depths {
		out = append(out, groups[d])
	}
	return out
}

type edit struct {
	start, end int
	repl       []byte
}

type editor struct {
	dec      *json.Decoder
	patterns [][]string
	edits    []edit
	// onMatch is called with the decoder positioned at a value whose path
	// matched a pattern exactly. Normalize and SortUnordered plug in
	// different behaviour here; the walk and the splice are shared.
	onMatch func() error
}

// value handles the JSON value at the decoder's current position, given the
// path that leads to it.
func (e *editor) value(path []string) error {
	switch {
	case matchesAny(path, e.patterns):
		return e.onMatch()
	case prefixOfAny(path, e.patterns):
		return e.descend(path)
	default:
		// No pattern can be inside this subtree, so skip it whole.
		var skip json.RawMessage
		return e.dec.Decode(&skip)
	}
}

// replace records the byte range of the value at the current position. The
// value occupies [InputOffset-len(raw), InputOffset): Decode stops on the
// value's final byte and json.RawMessage holds that value verbatim.
func (e *editor) replace() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	e.edits = append(e.edits, edit{
		start: end - len(raw),
		end:   end,
		repl:  []byte(`"{{` + jsonTypeOf(raw) + `}}"`),
	})
	return nil
}

// sortArray records an edit that reorders the elements of the array at the
// current position, sorted by their own raw bytes. It reuses replace's
// offset arithmetic to find the array's byte range, then re-decodes just
// that range to split it into elements without disturbing their bytes.
func (e *editor) sortArray() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	start := end - len(raw)

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return fmt.Errorf("value at this path is not an array: %s", raw)
	}

	elemDec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := elemDec.Token(); err != nil { // consume '['
		return err
	}
	var elems []json.RawMessage
	for elemDec.More() {
		var el json.RawMessage
		if err := elemDec.Decode(&el); err != nil {
			return err
		}
		elems = append(elems, el)
	}

	sort.Slice(elems, func(i, j int) bool { return bytes.Compare(elems[i], elems[j]) < 0 })

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, el := range elems {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(el)
	}
	buf.WriteByte(']')

	e.edits = append(e.edits, edit{start: start, end: end, repl: buf.Bytes()})
	return nil
}

// sortKeys records an edit that rewrites the object at the current position
// with its keys in sorted order, leaving each value's bytes untouched.
//
// This is the one place the suite gives up on key order, and it is a
// deliberate, documented deviation rather than an oversight. Keycloak's
// `attributes` is a Java Map serialised in hash order: deterministic for a
// given key set, but a function of Java's string hashing rather than of
// anything Keycloak decided. Go sorts map keys alphabetically, so reproducing
// it byte for byte would mean emulating java.util.HashMap's iteration order in
// Go - a large amount of fragile code to match an order no client can depend
// on and no documentation states.
//
// Sorting both sides keeps membership and values asserted, which is the part
// that is contract. See "Client attribute key order" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func (e *editor) sortKeys() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	start := end - len(raw)

	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("value at this path is not an object: %s", raw)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(name)
		if err != nil {
			return err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(fields[name])
	}
	buf.WriteByte('}')

	e.edits = append(e.edits, edit{start: start, end: end, repl: buf.Bytes()})
	return nil
}

// sortWords records an edit that rewrites the string at the current position
// as its space-separated words in sorted order. It reuses replace's offset
// arithmetic to find the value's byte range.
func (e *editor) sortWords() error {
	var raw json.RawMessage
	if err := e.dec.Decode(&raw); err != nil {
		return err
	}
	end := int(e.dec.InputOffset())
	start := end - len(raw)

	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return fmt.Errorf("value at this path is not a string: %s", raw)
	}
	words := strings.Fields(s)
	sort.Strings(words)
	repl, err := json.Marshal(strings.Join(words, " "))
	if err != nil {
		return err
	}

	e.edits = append(e.edits, edit{start: start, end: end, repl: repl})
	return nil
}

// descend walks into an object or array because some pattern points inside it.
func (e *editor) descend(path []string) error {
	tok, err := e.dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// A scalar sitting where a pattern expected a container. Nothing
		// below it to edit.
		return nil
	}
	switch delim {
	case '{':
		for e.dec.More() {
			keyTok, err := e.dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("want a string key, got %v", keyTok)
			}
			// Cap path's capacity to its length so this append always
			// allocates a new backing array rather than writing into one a
			// sibling call is still holding a slice over. Nothing retains a
			// path today, which is exactly the kind of invariant that stops
			// being true silently.
			if err := e.value(append(path[:len(path):len(path)], key)); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; e.dec.More(); i++ {
			if err := e.value(append(path[:len(path):len(path)], strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	// Consume the closing delimiter.
	_, err = e.dec.Token()
	return err
}

// matchesAny reports whether path is addressed by any pattern. A zero-length
// path is the document root, and only the empty pattern - which compilePaths
// produces for "." and strings.Split can never produce - matches it.
func matchesAny(path []string, patterns [][]string) bool {
	for _, p := range patterns {
		if len(p) == len(path) && segmentsMatch(path, p) {
			return true
		}
	}
	return false
}

func prefixOfAny(path []string, patterns [][]string) bool {
	for _, p := range patterns {
		if len(path) < len(p) && segmentsMatch(path, p[:len(path)]) {
			return true
		}
	}
	return false
}

func segmentsMatch(path, pattern []string) bool {
	for i := range path {
		if pattern[i] != "*" && pattern[i] != path[i] {
			return false
		}
	}
	return true
}

// jsonTypeOf names the type of a raw JSON value from its first byte.
func jsonTypeOf(raw []byte) string {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "null"
	}
	switch trimmed[0] {
	case '"':
		return "string"
	case '{':
		return "object"
	case '[':
		return "array"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// applyEdits splices the recorded ranges, leaving every other byte - key
// order, spacing, the absence of a trailing newline - untouched.
func applyEdits(raw []byte, edits []edit) []byte {
	if len(edits) == 0 {
		return raw
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out bytes.Buffer
	prev := 0
	for _, ed := range edits {
		out.Write(raw[prev:ed.start])
		out.Write(ed.repl)
		prev = ed.end
	}
	out.Write(raw[prev:])
	return out.Bytes()
}
