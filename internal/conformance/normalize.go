package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// issuerPlaceholder stands in for the base URL of whichever server produced a
// body. The reference container answers on http://localhost:18091 and the test
// server on http://localhost:8080, so without this every absolute URL differs.
const issuerPlaceholder = "{{issuer}}"

// ReplaceIssuer swaps a server's base URL for the placeholder.
func ReplaceIssuer(raw []byte, base string) []byte {
	if base == "" {
		return raw
	}
	return bytes.ReplaceAll(raw, []byte(base), []byte(issuerPlaceholder))
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
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	e.onMatch = e.replace
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: normalize: %w", err)
	}
	return applyEdits(raw, e.edits), nil
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
func SortUnordered(raw []byte, paths []string) ([]byte, error) {
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	e.onMatch = e.sortArray
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: sort unordered: %w", err)
	}
	return applyEdits(raw, e.edits), nil
}

// SortUnorderedKeys rewrites the objects at the given paths with their keys
// sorted, on both sides of a comparison, so that key order stops being
// asserted there while membership and values stay asserted.
//
// It is the deliberate exception to this suite's rule that key order is
// contract. See editor.sortKeys for why.
func SortUnorderedKeys(raw []byte, paths []string) ([]byte, error) {
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	e.onMatch = e.sortKeys
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: sort unordered keys: %w", err)
	}
	return applyEdits(raw, e.edits), nil
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
	if len(paths) == 0 || len(bytes.TrimSpace(raw)) == 0 {
		return raw, nil
	}
	patterns := make([][]string, 0, len(paths))
	for _, p := range paths {
		patterns = append(patterns, strings.Split(p, "/"))
	}

	e := &editor{dec: json.NewDecoder(bytes.NewReader(raw)), patterns: patterns}
	e.onMatch = e.sortWords
	if err := e.value(nil); err != nil {
		if err == io.EOF {
			return raw, nil
		}
		return nil, fmt.Errorf("conformance: sort unordered words: %w", err)
	}
	return applyEdits(raw, e.edits), nil
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

func matchesAny(path []string, patterns [][]string) bool {
	if len(path) == 0 {
		return false
	}
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
