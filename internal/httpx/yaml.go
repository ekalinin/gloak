package httpx

import (
	"net/http"
	"strconv"
	"strings"
)

// This file is the second body format Gloak writes, and it is here rather than
// in internal/admin for the reason WriteJSON's doc comment gives: this package
// owns every response body, so the byte-exactness guarantee cannot drift
// between call sites. See AGENTS.md's boundary table.
//
// **A Go YAML library cannot produce these bytes**, which is why there is an
// emitter here at all rather than a dependency. Measured 2026-09-06 against
// gopkg.in/yaml.v3 v3.0.1 - already in go.mod as an indirect requirement, so
// the dependency itself would have been free - on the exact body
// GET /admin/realms/{realm}/workflows answers:
//
//	                                     SetIndent(2)   SetIndent(4)
//	a Go struct with yaml tags           differs        differs
//	a hand-built yaml.Node tree          differs        differs
//	the measured bytes, reparsed         differs        -
//
// The last row is the control: hand the library its own target and it does not
// give it back. Four differences, and only the last two are reachable through
// any option the library has:
//
//   - **No `---`.** yaml.v3 emits a document-start marker only when there is
//     more than one document.
//   - **The nested sequence is indented one level too far.** Keycloak puts a
//     sequence's `-` at the parent mapping's key column; yaml.v3 puts it at
//     that column plus the indent, and SetIndent moves both together -
//     SetIndent(2) and SetIndent(4) produced byte-identical output on this
//     shape.
//   - Scalars are plain where Keycloak double-quotes every string.
//   - `on` is emitted bare where Keycloak writes `"on"`, because SnakeYAML is
//     YAML 1.1 - in which `on` is a boolean - and yaml.v3 is YAML 1.2.
//
// This is internal/javamap's situation one layer up: a Java library's output
// shape that a Go library will not produce, over a closed enough set of values
// to model directly. It is deliberately **not** a general YAML writer. It emits
// the four value kinds the workflow representation has and nothing else, and a
// fifth kind arriving is a compile error at the call site rather than a silent
// wrong shape.

// YAMLPair is one key and its value inside a YAMLMap.
type YAMLPair struct {
	Key   string
	Value any
}

// YAMLMap is a mapping in the order it is written. It is a slice rather than a
// map for the reason every ordered structure in this project is: Go's map
// iteration order is not the wire's, and the wire's is the contract.
//
// A Value may be a string (emitted double-quoted), an int (emitted bare), a
// YAMLMap (a nested block mapping) or a []YAMLMap (a block sequence of
// mappings). appendYAMLValue panics on anything else, which is the loud
// failure a silently skipped key would not be.
type YAMLMap []YAMLPair

// WriteYAML writes a YAML response body byte-exact to what Keycloak sends.
//
// body is a YAMLMap or a []YAMLMap - the two roots measured, a single workflow
// and a listing of them.
//
// The header set is measured on GET /admin/realms/{realm}/workflows and
// GET .../workflows/{id} on 2026-09-06:
//
//	Content-Type: application/yaml;charset=UTF-8
//	Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Robots-Tag
//	**no X-Frame-Options**
//	no Cache-Control
//	chunked, so no Content-Length
//
// **The missing X-Frame-Options is the part that looks like a bug.** The same
// route, the same status and the same caller, differing only in an `Accept`
// header that makes the answer `application/json;charset=UTF-8`, carries all
// five. So it is not the endpoint and not the status; it is the media type. It
// is deleted rather than never set because the router sets all five before the
// mux runs - the same reason SetUserinfoSecurityHeaders deletes it.
//
// Cache-Control is not set here for the reason WriteNoContent gives: it is
// pinned per endpoint. All nine workflow routes send none.
//
// The chunked transfer encoding is not reproduced and cannot be asserted:
// Go's net/http chooses it by body size, Go's client strips the header on the
// way in, and the conformance harness serves through httptest.ResponseRecorder,
// which sets neither. Nothing observable in the harness depends on it.
func WriteYAML(w http.ResponseWriter, status int, body any) {
	suppressDate(w)
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Content-Type", "application/yaml;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(AppendYAMLDocument(nil, body))
}

// AppendYAMLDocument appends one YAML document - the `---` marker and the value
// under it - to dst.
//
// It is exported so internal/httpx's own tests can assert the bytes without a
// ResponseWriter, and so a caller that needs the body without the response can
// have it. Nothing outside this package writes a response body with it; see
// this file's opening comment.
//
// **An empty sequence is `--- []` on one line**, measured as the seven bytes a
// realm with no workflows answers, where a non-empty one puts the marker on a
// line of its own. That is SnakeYAML emitting an empty collection in flow style
// because block style has no spelling for it, and it is the one shape here that
// is not a special case of the general rule.
//
// An empty YAMLMap at the root has not been measured - no route can produce one
// - so it is emitted as `--- {}` by the same reasoning rather than by
// measurement, and this sentence is the flag on it.
func AppendYAMLDocument(dst []byte, body any) []byte {
	switch v := body.(type) {
	case []YAMLMap:
		if len(v) == 0 {
			return append(dst, "--- []\n"...)
		}
		dst = append(dst, "---\n"...)
		return appendYAMLSequence(dst, v, 0)
	case YAMLMap:
		if len(v) == 0 {
			return append(dst, "--- {}\n"...)
		}
		dst = append(dst, "---\n"...)
		return appendYAMLMapping(dst, v, 0, "")
	default:
		panic("httpx: AppendYAMLDocument takes a YAMLMap or a []YAMLMap")
	}
}

// appendYAMLSequence writes a block sequence of mappings whose `-` sits at
// column indent and whose keys sit at indent+2.
//
// **The `-` is at the parent key's column, not one level in from it.** Measured
// on both roots: a listing's `steps:` sits at column 2 and its `- uses:` at
// column 2, and a single read's `steps:` sits at column 0 with its `- uses:` at
// column 0. That is SnakeYAML's default indicatorIndent of 0, and it is the one
// rule gopkg.in/yaml.v3 has no option to reproduce.
func appendYAMLSequence(dst []byte, items []YAMLMap, indent int) []byte {
	for _, item := range items {
		dst = appendYAMLMapping(dst, item, indent+2, strings.Repeat(" ", indent)+"- ")
	}
	return dst
}

// appendYAMLMapping writes a block mapping whose keys sit at column indent.
//
// first replaces the indent of the very first line alone, which is how a
// sequence item puts its `- ` where the first key's indent would be. An empty
// first means "indent this line like the rest".
func appendYAMLMapping(dst []byte, m YAMLMap, indent int, first string) []byte {
	pad := strings.Repeat(" ", indent)
	for i, p := range m {
		lead := pad
		if i == 0 && first != "" {
			lead = first
		}
		dst = append(dst, lead...)
		dst = append(dst, yamlKey(p.Key)...)
		dst = append(dst, ':')
		dst = appendYAMLValue(dst, p.Value, indent)
	}
	return dst
}

// appendYAMLValue writes what follows a key's colon, including the newline that
// ends the key's own line.
//
// indent is the column the key sits at, so a nested mapping goes to indent+2
// and a nested sequence's `-` goes to indent - see appendYAMLSequence.
func appendYAMLValue(dst []byte, v any, indent int) []byte {
	switch value := v.(type) {
	case string:
		dst = append(dst, ' ')
		dst = appendYAMLQuoted(dst, value)
		return append(dst, '\n')
	case int:
		dst = append(dst, ' ')
		dst = strconv.AppendInt(dst, int64(value), 10)
		return append(dst, '\n')
	case int64:
		dst = append(dst, ' ')
		dst = strconv.AppendInt(dst, value, 10)
		return append(dst, '\n')
	case YAMLMap:
		if len(value) == 0 {
			return append(dst, " {}\n"...)
		}
		dst = append(dst, '\n')
		return appendYAMLMapping(dst, value, indent+2, "")
	case []YAMLMap:
		if len(value) == 0 {
			return append(dst, " []\n"...)
		}
		dst = append(dst, '\n')
		return appendYAMLSequence(dst, value, indent)
	default:
		panic("httpx: a YAMLMap value must be a string, an int, a YAMLMap or a []YAMLMap")
	}
}

// yamlPlainResolvesToNonString is the set of plain scalars YAML 1.1's resolver
// reads as a boolean or a null rather than as a string.
//
// SnakeYAML quotes a scalar whose plain form would come back as something other
// than what went in, which is why Keycloak writes `"on": "user-created"` and
// leaves `id`, `name`, `steps`, `uses`, `after`, `if`, `schedule`,
// `batch-size`, `concurrency`, `cancel-in-progress`, `restart-in-progress`,
// `scheduled-at` and `status` bare - all measured on the wire.
//
// It is the exact spellings YAML 1.1 lists rather than a case-insensitive
// comparison, because that is what the specification's resolver matches:
// `oN` is a string and `ON` is a boolean.
//
// The empty string is in the set because YAML 1.1 resolves an empty plain
// scalar to null.
var yamlPlainResolvesToNonString = map[string]bool{
	"": true, "~": true,
	"null": true, "Null": true, "NULL": true,
	"y": true, "Y": true, "n": true, "N": true,
	"yes": true, "Yes": true, "YES": true,
	"no": true, "No": true, "NO": true,
	"true": true, "True": true, "TRUE": true,
	"false": true, "False": true, "FALSE": true,
	"on": true, "On": true, "ON": true,
	"off": true, "Off": true, "OFF": true,
}

// yamlKey renders a mapping key: bare unless a plain scalar of that spelling
// would resolve to something other than a string.
//
// The only key any measured workflow body quotes is `on`. Writing the rule
// rather than that one name is what stops a workflow whose step config carries
// a key called `no` from round-tripping as a boolean - a shape no measurement
// has produced and the resolver above says is real.
func yamlKey(k string) string {
	if yamlPlainResolvesToNonString[k] {
		return `"` + k + `"`
	}
	return k
}

// appendYAMLQuoted writes a double-quoted scalar.
//
// Every string value in a measured workflow body is double-quoted, including
// ones that would need no quotes at all - `"t"`, `"P5D"`, `"disable-user"` -
// so this is unconditional rather than a decision per value.
//
// The escapes are the four a measured value could carry. Everything else in
// the ASCII range is written through, which is what SnakeYAML does with
// allowUnicode on; **a control byte other than these has not been measured**,
// and it is written as its \xNN escape rather than raw so a body cannot become
// something RefuseNonTextBody would reject in a golden.
func appendYAMLQuoted(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			dst = append(dst, `\\`...)
		case '"':
			dst = append(dst, `\"`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\t':
			dst = append(dst, `\t`...)
		case '\r':
			dst = append(dst, `\r`...)
		default:
			if c < 0x20 || c == 0x7f {
				const hex = "0123456789abcdef"
				dst = append(dst, '\\', 'x', hex[c>>4], hex[c&0x0f])
				continue
			}
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}
