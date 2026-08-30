package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
)

// decodeStrict decodes a body that Keycloak decodes with Jackson's
// FAIL_ON_UNKNOWN_PROPERTIES turned on.
//
// **This is the first strict decoder measured in this API.** Every other
// endpoint recorded here ignores a field it does not know; the two PUTs on the
// Authentication Management tag answer
//
//	400 {"error":"Invalid json representation for RequiredActionProviderRepresentation.
//	     Unrecognized field \"bogusField\" at line 1 column 118."}
//
// naming the Java class, the field, the line and the column. The third write on
// the same tag - POST /register-required-action - is **not** strict: an unknown
// field beside a good providerId answered 204. So the strictness is per
// endpoint and this helper is applied at two call sites rather than to
// everything.
//
// The decode runs **before** the path's alias is resolved: a PUT to an alias
// that does not exist carrying an unknown field answers this 400 rather than
// the 404.
//
// A body that is not JSON at all falls through to the ordinary "Cannot parse
// the JSON" family, whose code is decided by the body's **shape** and not by
// the endpoint - `{` is invalid_request and `[` is unknown_error, measured on
// these routes and matching what AGENTS.md already records.
func decodeStrict(w http.ResponseWriter, r *http.Request, class string, out any) bool {
	if !requireJSONBody(w, r) {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeCannotParseJSON(w, body)
		return false
	}
	if err := json.Unmarshal(body, out); err != nil {
		writeCannotParseJSON(w, body)
		return false
	}
	if field, ok := firstUnknownField(body, out); ok {
		httpx.WriteMessageError(w, http.StatusBadRequest, fmt.Sprintf(
			"Invalid json representation for %s. Unrecognized field %q at line %d column %d.",
			class, field.name, field.line, field.column))
		return false
	}
	return true
}

// writeCannotParseJSON writes the measured parse failure, whose error **code**
// follows the body's shape rather than the endpoint: an object endpoint sent
// `{` answers invalid_request and sent `[` answers unknown_error. Both were
// measured on PUT /required-actions/{alias}, which is the control this rule
// wanted - AGENTS.md records it from the other direction, where eleven probes
// all sent `{`.
func writeCannotParseJSON(w http.ResponseWriter, body []byte) {
	code := "invalid_request"
	if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("[")) {
		code = "unknown_error"
	}
	httpx.WriteOAuthError(w, http.StatusBadRequest, code, "Cannot parse the JSON")
}

type unknownField struct {
	name   string
	line   int
	column int
}

// firstUnknownField finds the first top-level key of body that out's type does
// not declare, and reports Jackson's location for it.
//
// **The location is Jackson's, not Go's**, and the rule was derived from twelve
// paired measurements rather than guessed. The column is one past the last
// character Jackson had physically consumed when it rejected the field, and how
// much that is depends on the value's token:
//
//	{"zz":1}          column 8   a number consumes all of its own digits
//	{"zz":12}         column 9
//	{"zz":null}       column 11  so do null, true and false
//	{"zz":"a"}        column 8   a string consumes only its opening quote
//	{"zz":[1,2]}      column 8   so does an array
//	{"zz":{"a":1}}    column 8   and an object
//	{ "zz" : 1 }      column 11  whitespace counts, so the offsets are real
//
// A scanner that reported Go's byte offset would be right on none of them.
func firstUnknownField(body []byte, out any) (unknownField, bool) {
	known := declaredJSONNames(reflect.TypeOf(out))
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return unknownField{}, false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return unknownField{}, false
		}
		key, _ := keyTok.(string)
		// InputOffset after the key is the offset of the character just past
		// the key's closing quote; the value's own token starts after any
		// whitespace and the colon.
		start := skipToValue(body, int(dec.InputOffset()))
		end := consumedThrough(body, start)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return unknownField{}, false
		}
		if !known[key] {
			return unknownField{
				name: key,
				line: 1 + bytes.Count(body[:start], []byte("\n")),
				// end is the zero-based index of the last consumed character,
				// so end+1 is how many characters of the line were consumed and
				// end+2 is the one-based position of the next one. Jackson
				// reports that next position, which is why `{"zz":1}` is column
				// 8 and not 7 - a first attempt got exactly that wrong on all
				// four measured bodies at once.
				column: end - lineStart(body, start) + 2,
			}, true
		}
	}
	return unknownField{}, false
}

// skipToValue walks past the colon and any whitespace after a key, returning
// the index of the value's first character.
func skipToValue(body []byte, from int) int {
	i := from
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' ||
		body[i] == '\n' || body[i] == ':') {
		i++
	}
	return i
}

// consumedThrough returns the index of the last character Jackson consumes
// while positioning on the value that starts at i. A string, an array and an
// object cost their opening character alone; a number and a literal cost all of
// themselves.
func consumedThrough(body []byte, i int) int {
	if i >= len(body) {
		return i
	}
	switch body[i] {
	case '"', '[', '{':
		return i
	}
	j := i
	for j < len(body) && !strings.ContainsRune(" \t\r\n,}]", rune(body[j])) {
		j++
	}
	return j - 1
}

// lineStart returns the index of the first character of the line holding i, so
// the column can be reported 1-based within that line.
func lineStart(body []byte, i int) int {
	if n := bytes.LastIndexByte(body[:i], '\n'); n >= 0 {
		return n + 1
	}
	return 0
}

// declaredJSONNames lists the JSON names a struct type declares, which is what
// Jackson compares an incoming field against.
func declaredJSONNames(t reflect.Type) map[string]bool {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	names := map[string]bool{}
	if t == nil || t.Kind() != reflect.Struct {
		return names
	}
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = t.Field(i).Name
		}
		if name != "-" {
			names[name] = true
		}
	}
	return names
}
