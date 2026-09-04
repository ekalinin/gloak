package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The seven localization operations of the Realms Admin tag. Measured against a
// live 26.7.1 on 2026-09-03; see
// docs/superpowers/plans/2026-09-03-realms-admin-remainder.md and
// docs/superpowers/handover/realms-admin-remainder.md.
//
// **Nothing in this family carries Cache-Control** - not a success, not a
// refusal, on any of the seven - which is why none of these handlers uses
// writeAdminJSON. The realm's own reads one path segment away all carry
// `no-cache`.

// localizationDocument is one locale's bundle on the wire.
//
// It is a slice with a marshaller rather than a map because **the key order is
// the contract**: Keycloak stores the bundle as one JSON document and serves it
// back verbatim, and the order a write leaves behind differs per write path -
// see importLocalizationTexts. A Go map would sort it.
type localizationDocument []model.LocalizationText

func (d localizationDocument) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range d {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := marshalOrderedValue(e.Key)
		if err != nil {
			return nil, err
		}
		value, err := marshalOrderedValue(e.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// listLocales serves GET /admin/realms/{realm}/localization.
//
// **Sorted**, measured: five locales written `zz, aa, mm, ru, de-CH` came back
// `aa, de-CH, mm, ru, zz`. A locale whose document the empty-body POST left
// absent is in the list like any other - it is only reading it that fails.
func (h *handler) listLocales(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	locales, err := h.store.Localizations().Locales(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeLocalizationJSON(w, locales)
}

// readLocalizationTexts serves GET /admin/realms/{realm}/localization/{locale}.
//
// **A locale that does not exist is `200 {}`**, where the DELETE beside it is a
// 404 for the same absence. One missing locale, two answers, decided by the
// verb.
//
// useRealmDefaultLocaleFallback merges the realm's defaultLocale bundle
// **under** this one: a key both hold keeps this locale's value and a key only
// the default holds is added. It is driven by `defaultLocale` alone - measured
// with `internationalizationEnabled` both on and off, which changed nothing -
// and the two neighbouring reads ignore the parameter entirely.
func (h *handler) readLocalizationTexts(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	texts, ok := h.localizationTexts(w, r, rc, r.PathValue("locale"))
	if !ok {
		return
	}
	if r.URL.Query().Get("useRealmDefaultLocaleFallback") == "true" {
		fallback, ok := h.defaultLocaleTexts(w, r, rc)
		if !ok {
			return
		}
		if fallback != nil {
			texts = &model.LocalizationTexts{
				Locale: texts.Locale,
				Texts:  mergeLocalizationTexts(fallback.Texts, texts.Texts),
			}
		}
	}
	writeLocalizationJSON(w, localizationDocument(texts.Texts))
}

// readLocalizationText serves GET /admin/realms/{realm}/localization/{locale}/{key}.
//
// **It is this API's only `text/plain` 200**, and it is what says the
// X-Frame-Options exception AGENTS.md records for `userinfo` is about the
// response's media type rather than about the endpoint: the same route answers
// its own 404 as `application/json` **with** the header. See
// writeLocalizationText.
func (h *handler) readLocalizationText(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	texts, ok := h.localizationTexts(w, r, rc, r.PathValue("locale"))
	if !ok {
		return
	}
	value, found := texts.Value(r.PathValue("key"))
	if !found {
		writeLocalizationTextNotFound(w)
		return
	}
	writeLocalizationText(w, value)
}

// importLocalizationTexts serves POST /admin/realms/{realm}/localization/{locale}.
//
// **It merges, and it is the only write that re-orders.** Measured as a
// sequence on one locale: a POST onto a locale that does not exist stores the
// request's own key order, and a POST onto one that does re-buckets the whole
// document through a Java map - `k1..k5` then `{k6}` came back
// `k3,k4,k5,k6,k1,k2`. The other three writes preserve the document's order.
//
// javamap.SizedKeyOrder is asked for **one** built-for entry on purpose: that
// function models two tables, and this map goes through the second one alone.
// The keys are handed over in insertion order - the stored document first, then
// whatever the request adds - because that is what decides a chain. Pinned by
// TestLocalizationMergeReproducesTheMeasuredOrders.
func (h *handler) importLocalizationTexts(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	locale := r.PathValue("locale")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	existing, err := h.store.Localizations().ByLocale(r.Context(), rc.realm.ID, locale)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		existing = nil
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// A locale the empty-body POST left with no document at all poisons this
	// route too: measured 500, and the document stays absent.
	if existing != nil && existing.Texts == nil {
		writeLocalizationServerError(w)
		return
	}

	// **An empty body and a literal `null` are a 204 that leaves the locale
	// unreadable for ever.** Keycloak's own defect, reproduced: the row is
	// created, `GET /localization` lists it, and every read of it is a 500. An
	// empty *object* is a different body and a different outcome.
	if isAbsentJSONBody(body) {
		h.putLocalizationTexts(w, r, rc, &model.LocalizationTexts{Locale: locale})
		return
	}

	incoming, err := decodeLocalizationBody(body)
	if err != nil {
		writeCannotParseJSON(w, body)
		return
	}

	next := &model.LocalizationTexts{Locale: locale, Texts: incoming}
	if existing != nil {
		next.Texts = orderLocalizationMerge(mergeLocalizationTexts(existing.Texts, incoming))
	}
	h.putLocalizationTexts(w, r, rc, next)
}

// setLocalizationText serves PUT /admin/realms/{realm}/localization/{locale}/{key}.
//
// **It appends a new key at the end and replaces an existing one in place**, so
// unlike the POST it never re-orders. An empty body is a 204 storing the empty
// string, which the read answers with a zero-length `text/plain` 200.
func (h *handler) setLocalizationText(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !consumesPlainText(w, r) {
		return
	}
	locale := r.PathValue("locale")
	value, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	texts, err := h.store.Localizations().ByLocale(r.Context(), rc.realm.ID, locale)
	switch {
	case err == nil:
		if texts.Texts == nil {
			writeLocalizationServerError(w)
			return
		}
	case errors.Is(err, store.ErrNotFound):
		texts = &model.LocalizationTexts{Locale: locale, Texts: []model.LocalizationText{}}
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	texts.Texts = mergeLocalizationTexts(texts.Texts,
		[]model.LocalizationText{{Key: r.PathValue("key"), Value: string(value)}})
	h.putLocalizationTexts(w, r, rc, texts)
}

// deleteLocale serves DELETE /admin/realms/{realm}/localization/{locale}.
//
// Its 404 is a spelling of not-found this API did not have, it carries a full
// stop, and it names the locale.
func (h *handler) deleteLocale(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	locale := r.PathValue("locale")
	err := h.store.Localizations().DeleteLocale(r.Context(), rc.realm.ID, locale)
	switch {
	case err == nil:
		httpx.WriteNoContent(w, r)
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteMessageError(w, http.StatusNotFound,
			"No localization texts for locale "+locale+" found.")
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
	}
}

// deleteLocalizationText serves
// DELETE /admin/realms/{realm}/localization/{locale}/{key}.
//
// **It removes the key and moves nothing else**, which is measured rather than
// assumed: the surviving order after deleting a key from a re-bucketed document
// is the document's own, and not the order the same key set would re-bucket to.
// A locale with no document at all answers the ordinary 404 here, where the
// three reads and the two other writes answer 500.
func (h *handler) deleteLocalizationText(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	locale, key := r.PathValue("locale"), r.PathValue("key")
	texts, err := h.store.Localizations().ByLocale(r.Context(), rc.realm.ID, locale)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		writeLocalizationTextNotFound(w)
		return
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	kept := make([]model.LocalizationText, 0, len(texts.Texts))
	for _, e := range texts.Texts {
		if e.Key != key {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(texts.Texts) {
		writeLocalizationTextNotFound(w)
		return
	}
	texts.Texts = kept
	h.putLocalizationTexts(w, r, rc, texts)
}

// localizationTexts is the read every route in the family starts from: a locale
// with no row is an empty bundle rather than an error, and a locale whose
// document is absent is the 500 that only an empty POST body can produce.
func (h *handler) localizationTexts(w http.ResponseWriter, r *http.Request, rc *reqContext, locale string) (*model.LocalizationTexts, bool) {
	texts, err := h.store.Localizations().ByLocale(r.Context(), rc.realm.ID, locale)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return &model.LocalizationTexts{Locale: locale, Texts: []model.LocalizationText{}}, true
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if texts.Texts == nil {
		writeLocalizationServerError(w)
		return nil, false
	}
	return texts, true
}

// defaultLocaleTexts is the realm's defaultLocale bundle, or nil when the realm
// names no default locale. A default locale that has no bundle of its own is
// nil too, so the fallback adds nothing rather than failing.
func (h *handler) defaultLocaleTexts(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.LocalizationTexts, bool) {
	rep, err := h.realmRepresentationOf(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	if rep.DefaultLocale == nil || *rep.DefaultLocale == "" {
		return nil, true
	}
	texts, err := h.store.Localizations().ByLocale(r.Context(), rc.realm.ID, *rep.DefaultLocale)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		return nil, true
	default:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	// The default locale's own document being absent is not this read's error:
	// the poisoned locale is only a 500 when it is the one being read.
	if texts.Texts == nil {
		return nil, true
	}
	return texts, true
}

// putLocalizationTexts stores a bundle and writes the measured 204.
func (h *handler) putLocalizationTexts(w http.ResponseWriter, r *http.Request, rc *reqContext, t *model.LocalizationTexts) {
	if err := h.store.Localizations().Put(r.Context(), rc.realm.ID, t); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// mergeLocalizationTexts writes over into base: a key base already holds keeps
// its position and takes the new value, and a key it does not hold is appended.
//
// That is `PUT .../{key}`'s whole behaviour, and it is also the insertion order
// the POST's re-bucketing runs over, which is why one function serves both.
func mergeLocalizationTexts(base, over []model.LocalizationText) []model.LocalizationText {
	out := make([]model.LocalizationText, len(base))
	copy(out, base)
	for _, e := range over {
		replaced := false
		for i := range out {
			if out[i].Key == e.Key {
				out[i].Value = e.Value
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, e)
		}
	}
	return out
}

// orderLocalizationMerge re-buckets a merged document the way Keycloak's own
// merge does. See importLocalizationTexts for why builtFor is 1.
func orderLocalizationMerge(texts []model.LocalizationText) []model.LocalizationText {
	keys := make([]string, len(texts))
	for i, e := range texts {
		keys[i] = e.Key
	}
	byKey := make(map[string]string, len(texts))
	for _, e := range texts {
		byKey[e.Key] = e.Value
	}
	out := make([]model.LocalizationText, 0, len(texts))
	for _, key := range javamap.SizedKeyOrder(1, keys) {
		out = append(out, model.LocalizationText{Key: key, Value: byKey[key]})
	}
	return out
}

// decodeLocalizationBody reads the POST's object in the order it was written.
//
// **A JSON number is coerced to a string**, measured: `{"n":123}` stores
// `"123"`, which is the coercion F97 records for `POST /users`. A value that is
// not a scalar is a parse failure here, which is the same 400 a malformed body
// gets.
func decodeLocalizationBody(body []byte) ([]model.LocalizationText, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errNotAnObject
	}
	out := []model.LocalizationText{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		value, err := localizationScalar(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, model.LocalizationText{Key: key, Value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

var errNotAnObject = errors.New("admin: localization body is not a JSON object")

// localizationScalar renders one value the way Jackson coerces it into a
// String: a JSON string as itself, a number or a boolean as its own text.
func localizationScalar(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", errNotAnObject
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", err
		}
		return s, nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return "", errNotAnObject
	}
	return string(trimmed), nil
}

// isAbsentJSONBody reports whether a POST body is the one that leaves a locale
// with no document at all: nothing, whitespace, or a literal null.
func isAbsentJSONBody(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) == 0 || string(trimmed) == "null"
}

// consumesPlainText is PUT .../{locale}/{key}'s 415.
//
// Measured over nine spellings: `text/plain`, `text/plain;charset=UTF-8`,
// `TEXT/PLAIN`, `*/*` and an **absent** header are all 204, and
// `application/json`, `application/xml`, `text/html` and
// `application/octet-stream` are all 415. An absent Content-Type being accepted
// is the rule AGENTS.md already records for this API's JSON writes, met here on
// a text one.
func consumesPlainText(w http.ResponseWriter, r *http.Request) bool {
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" || ct == "*/*" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return true
	}
	httpx.WriteMessageError(w, http.StatusUnsupportedMediaType,
		"The content-type header value did not match the value in @Consumes")
	return false
}

// writeLocalizationJSON is the family's success writer: the charset the admin
// API's 2xx bodies carry, and **no Cache-Control**, which is what separates it
// from writeAdminJSON.
func writeLocalizationJSON(w http.ResponseWriter, body any) {
	httpx.WriteJSONCharset(w, http.StatusOK, body)
}

// writeLocalizationText writes the single-key read: `text/plain;charset=UTF-8`,
// the value raw, no Cache-Control, and **no X-Frame-Options**.
//
// The header is what makes this route worth reading twice. Measured as a 2x2 on
// 2026-09-03: this 200 omits X-Frame-Options whether the request declared
// `application/json`, `text/plain` or nothing, and `GET /localization` beside
// it - an `application/json` 200 - carries it under all three. So the request's
// Content-Type does not decide a response that has a media type of its own; the
// response's does, and the request's is only the fallback for a response with
// no body, which is httpx.WriteNoContent's measured rule.
//
// **The charset is spelled `UTF-8` here and `utf-8` on userinfo's text/plain
// rejections.** One media type, two spellings, one server.
//
// It writes here rather than in internal/httpx for writeEmptyStatus's reason:
// that package was not this branch's to change. The body is the stored value
// with nothing done to it, so the divergence httpx's boundary exists to prevent
// - a second JSON marshaller drifting - is not reachable through it. See the
// follow-up.
func writeLocalizationText(w http.ResponseWriter, value string) {
	// Keycloak sends no Date on any response and net/http adds one; every
	// writer in internal/httpx suppresses it and this one is no exception.
	w.Header()["Date"] = nil
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, value)
}

// writeLocalizationTextNotFound is the 404 the single-key read and its delete
// share. It has **no full stop**, where the locale delete's has one - the
// fourth pair in this API separated by nothing else.
func writeLocalizationTextNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Localization text not found")
}

// writeLocalizationServerError is the answer to a locale whose document an
// empty POST body left absent. Keycloak's own defect, reproduced: the row
// exists, the listing shows it, and nothing but the two deletes can touch it.
func writeLocalizationServerError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}
