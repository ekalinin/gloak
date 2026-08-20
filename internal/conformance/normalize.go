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
// A body that is not a JSON value is returned unchanged - the userinfo
// rejection is 401 with an empty body, and that is a case, not an error.
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
			if err := e.value(append(path, key)); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; e.dec.More(); i++ {
			if err := e.value(append(path, strconv.Itoa(i))); err != nil {
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
