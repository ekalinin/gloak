package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The events family: six operations on three paths, every one tagged
// `Realms Admin` by the description and none of them authorised out of the
// realm role pair.
//
// **Gloak records no events, and that is what shapes this file.** The two
// listings answer `[]` for every request that gets past their parameters, and
// the two deletes clear nothing, because nothing writes a row for either of
// them. The reason is different on each half and neither is F157's:
//
//   - A **user** event is written by the login path. Three Admin API writes
//     that look most likely to write one - `POST /users`,
//     `PUT .../reset-password` and `POST .../logout` - were measured writing an
//     admin event each and no user event at all, while two password grants at
//     the token endpoint wrote two. That path is `internal/oidc`'s, which is
//     F122's and F148's shape: a boundary, not a bug.
//   - An **admin** event *is* written by requests this package serves, so
//     unlike a brute-force record the non-zero state is reachable from here.
//     What is not reachable in one cut is its content. An admin event carries
//     an `(operationType, resourceType, resourcePath, representation)`
//     quadruple and none of the four follows from the route: `resourceType`
//     took ten distinct values over twelve measured writes, a child group
//     create records its **parent's** id where the same request's `Location`
//     carries the child's, `PUT /admin/realms/{realm}` records no
//     `resourcePath` key at all, and `representation` is the request body on
//     one route, the body plus a minted id on the next and absent on a third.
//     `internal/admin` registers 152 write routes; shape 2 is 152 measured
//     quadruples, which is a chapter rather than a cut. A quadruple written
//     from the route instead is a claim about Keycloak that is not true.
//
// So `events/config` is real state served from real storage, and the four
// operations around it are honest about holding nothing. See F162, and
// docs/superpowers/plans/2026-09-04-events-family.md for the twelve-write sweep
// the paragraph above is drawn from.
//
// There is no table and no model type for the same reason `attack-detection`
// has none: a column nothing writes is a claim about the model that is not
// true. `events/config` needs neither, because it **is** the realm
// representation's own state - measured in both directions, the way
// `client-policies/profiles` already is - and `model.Realm.Settings` has
// persisted it since P4.

// eventsReadRoles and eventsWriteRoles are the family's guard, and it is its
// own pair rather than a borrowed one.
//
// Measured one role at a time over eleven callers on all six operations:
// `view-events` and `manage-events` read, `manage-events` alone writes, and
// `view-realm`, `manage-realm`, the users trio and the clients pair are 403 on
// every one of the six. That is the third family whose guard the description's
// `Realms Admin` tag fails to predict, after the two realm-level client-scope
// listings and the chapters `small-chapters` measured - and it is the first use
// this project has had for either of these two roles, which `internal/bootstrap`
// has been creating and nothing has been reading.
var eventsReadRoles = []string{"view-events", "manage-events"}

var eventsWriteRoles = []string{"manage-events"}

// knownEventListeners and globalEventListeners are what `eventsListeners` will
// accept, and there are **two different 400s** rather than one.
//
// `GET /admin/serverinfo` reports three `eventsListener` providers on a default
// 26.7.1. A name outside those three is
// `400 {"error":"Unknown event listener"}`; `workflow-event-listener`, which is
// one of the three, is
// `400 {"error":"Global event listeners not allowed in realm specific
// configuration"}`. Only `email` and `jboss-logging` can be stored.
//
// The two refusals are decided **per entry in array order**: a list naming an
// unknown name and then the global one answers the first sentence and the
// reverse order answers the second, so it is one pass with two tests and not two
// passes. Measured on a created realm and on master, which agree.
//
// (This pair read `workflow-event-listener` as "accepted and silently dropped"
// until the fixture for this chapter refused to take. The probe that said so had
// `curl -o /dev/null` with no `-w`, so it never saw the 400 and read the
// unchanged config as a drop. **Never pipe a probe anywhere without reading its
// own status code** - which is the same rule this repository already has for
// `go test`.)
var knownEventListeners = map[string]bool{
	"email":                   true,
	"jboss-logging":           true,
	"workflow-event-listener": true,
}

var globalEventListeners = map[string]bool{
	"workflow-event-listener": true,
}

// realmEventsConfig is the body `GET /admin/realms/{realm}/events/config`
// serves. Field order is the contract, transcribed from a recorded read:
// `eventsEnabled`, then `eventsExpiration` when it is there, then the two lists,
// then the two admin flags.
//
// **`eventsExpiration` is absent exactly when it is zero**, which is why it is a
// pointer with omitempty rather than an int: set to 900 it appears, set to 0 it
// disappears, and set to **-5 it appears as -5**. So the rule is `== 0` and not
// `<= 0`, and a plain int with omitempty would drop the negative one too.
type realmEventsConfig struct {
	EventsEnabled             bool     `json:"eventsEnabled"`
	EventsExpiration          *int     `json:"eventsExpiration,omitempty"`
	EventsListeners           []string `json:"eventsListeners"`
	EnabledEventTypes         []string `json:"enabledEventTypes"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
}

// realmEventsConfigUpdate is the same six fields as the `PUT` reads them, and
// the pointers are the whole point.
//
// **The write replaces two fields and merges four.** A `PUT {}` on a realm
// carrying six non-default values answered 204 and reset `eventsEnabled` to
// false and `eventsExpiration` to absent, while leaving `eventsListeners`,
// `enabledEventTypes`, `adminEventsEnabled` and `adminEventsDetailsEnabled`
// exactly as they were. Two booleans reset and two booleans on the same body
// left alone: a decoder that treats the six alike is wrong on two of them
// whichever way it is written.
//
// `PUT /admin/realms/{realm}` writes the **same** storage and merges all six -
// a `{}` body there changed none of them. One state, two writers, two merge
// rules.
type realmEventsConfigUpdate struct {
	EventsEnabled             bool      `json:"eventsEnabled"`
	EventsExpiration          int       `json:"eventsExpiration"`
	EventsListeners           *[]string `json:"eventsListeners"`
	EnabledEventTypes         *[]string `json:"enabledEventTypes"`
	AdminEventsEnabled        *bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled *bool     `json:"adminEventsDetailsEnabled"`
}

// readEventsConfig serves GET /admin/realms/{realm}/events/config.
//
// The body is byte-identical on `master` and on a realm created through the API
// - 2739 bytes, `cmp`-verified - so nothing here is derived from the realm.
func (h *handler) readEventsConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	rep, err := decodeRealmSettings(rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, eventsConfigOf(&rep))
}

// eventsConfigOf projects the realm representation onto the events config, and
// the one difference between the two views lives here.
//
// **An empty `enabledEventTypes` means "all of them" on this endpoint and `[]`
// on the realm representation.** Measured on a fresh realm and on `master`:
// `GET /admin/realms/{realm}` answers `enabledEventTypes: []` while
// `GET .../events/config` answers the 103 defaults, for one stored value at one
// moment. Store a non-empty list through either route and both views agree
// again, so the disagreement is exactly the state every default realm is in.
//
// `eventsListeners` has no such expansion - an empty list there reads back
// empty, which is the opposite reading of `[]` one key away.
func eventsConfigOf(rep *realmRepresentation) realmEventsConfig {
	types := rep.EnabledEventTypes
	if len(types) == 0 {
		types = defaultEnabledEventTypes
	}
	listeners := rep.EventsListeners
	if listeners == nil {
		listeners = []string{}
	}
	return realmEventsConfig{
		EventsEnabled:             rep.EventsEnabled,
		EventsExpiration:          rep.EventsExpiration,
		EventsListeners:           listeners,
		EnabledEventTypes:         types,
		AdminEventsEnabled:        rep.AdminEventsEnabled,
		AdminEventsDetailsEnabled: rep.AdminEventsDetailsEnabled,
	}
}

// updateEventsConfig serves PUT /admin/realms/{realm}/events/config.
//
// The order of its refusals is measured rather than convenient, and three pairs
// of them were sent together to pin it:
//
//	absent Content-Type          204 - accepted, so requireJSONBody's rule holds
//	text/plain, xml, form        415 The content-type header value did not match the value in @Consumes
//	empty body, literal null     500 unknown_error
//	an unknown field             400 Invalid json representation for RealmEventsConfigRepresentation...
//	a value of the wrong type    400 unknown_error   / Cannot parse the JSON
//	truncated JSON               400 invalid_request / Cannot parse the JSON
//	an unknown eventsListeners   400 Unknown event listener
//	an unknown enabledEventTypes 204 - stored as given, never validated
//
// An unknown field beats a bad listener, and a bad value type beats one too, so
// the listener check is last. And **a refused listener leaves nothing written**:
// `{"eventsEnabled":true,"eventsListeners":["nope"]}` on a realm with events off
// answered 400 and left it off, where the same body without the listener
// answered 204 and turned it on. Validation completes before anything is
// stored.
func (h *handler) updateEventsConfig(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if !requireJSONBody(w, r) {
		return
	}
	// readRequestBody rather than io.ReadAll: the conformance verifier hands the
	// handler a request whose Body is **nil** for a case that sends none, where
	// net/http's server never does. The measured "no body at all" case is the
	// only one that reaches it, so io.ReadAll here panicked on exactly the case
	// this endpoint most needed - which is how localization.go found the same
	// thing, also on the run that recorded its goldens.
	body, err := readRequestBody(r)
	if err != nil {
		writeEventsConfigNoBody(w)
		return
	}
	// An empty body and a literal `null` are the same 500, which is Keycloak's
	// own NullPointerException and the same answer `PUT /admin/realms/{realm}`
	// gives to an empty body. It has to be caught before the decode, because
	// encoding/json unmarshals `null` into a struct without complaining.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		writeEventsConfigNoBody(w)
		return
	}

	var upd realmEventsConfigUpdate
	if err := json.Unmarshal(body, &upd); err != nil {
		writeEventsConfigParseError(w, err)
		return
	}
	if field, ok := firstUnknownField(body, &upd); ok {
		httpx.WriteMessageError(w, http.StatusBadRequest,
			"Invalid json representation for RealmEventsConfigRepresentation. "+
				"Unrecognized field \""+field.name+"\" at line "+
				strconv.Itoa(field.line)+" column "+strconv.Itoa(field.column)+".")
		return
	}
	if upd.EventsListeners != nil {
		for _, name := range *upd.EventsListeners {
			if !knownEventListeners[name] {
				httpx.WriteMessageError(w, http.StatusBadRequest, "Unknown event listener")
				return
			}
			if globalEventListeners[name] {
				httpx.WriteMessageError(w, http.StatusBadRequest,
					"Global event listeners not allowed in realm specific configuration")
				return
			}
		}
	}

	rep, err := decodeRealmSettings(rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	applyEventsConfig(&rep, &upd)
	rc.realm.Settings = marshalRealmSettings(&rep)
	if err := h.store.Realms().Update(r.Context(), rc.realm); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// applyEventsConfig is the two-replace, four-merge split, written out field by
// field because that is what it is. Sharing a merge helper with the realm PUT
// is the tidy-up that gets the first two wrong.
func applyEventsConfig(rep *realmRepresentation, upd *realmEventsConfigUpdate) {
	rep.EventsEnabled = upd.EventsEnabled
	if upd.EventsExpiration == 0 {
		rep.EventsExpiration = nil
	} else {
		v := upd.EventsExpiration
		rep.EventsExpiration = &v
	}
	if upd.EventsListeners != nil {
		// Both lists are Java sets, so a repeated name collapses - measured,
		// ["email","email"] stores one. The *order* they come back in is
		// decodeRealmSettings' job, because two routes write this state and one
		// reader serves it.
		rep.EventsListeners = uniqueStrings(*upd.EventsListeners)
	}
	if upd.EnabledEventTypes != nil {
		// An unknown name is stored as it stands - this list is never validated
		// where eventsListeners beside it is twice over. Measured:
		// {"enabledEventTypes":["NOT_A_TYPE"]} is a 204 and reads back holding
		// it.
		rep.EnabledEventTypes = uniqueStrings(*upd.EnabledEventTypes)
	}
	if upd.AdminEventsEnabled != nil {
		rep.AdminEventsEnabled = *upd.AdminEventsEnabled
	}
	if upd.AdminEventsDetailsEnabled != nil {
		rep.AdminEventsDetailsEnabled = *upd.AdminEventsDetailsEnabled
	}
}

// uniqueStrings collapses a list into the set a Java HashSet would hold. The
// result is never nil, so an empty list marshals as `[]` rather than as null -
// which is the reading `eventsListeners` has and `enabledEventTypes` does not.
func uniqueStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, name := range in {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// writeEventsConfigNoBody is the 500 an empty body and a literal `null` share.
func writeEventsConfigNoBody(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// writeEventsConfigParseError splits Jackson's two failures, which this endpoint
// separates where writeCannotParseJSON uses a proxy for them.
//
// Measured on this route: a truncated `{` is `invalid_request`, while `[]` and
// `{"eventsEnabled":"yes"}` are both `unknown_error` - so the code follows
// **syntax against binding**, not the body's first character.
// writeCannotParseJSON's prefix test agrees with that on every body measured
// before this cut, because in each of those the shape and the failure kind
// coincided; `{"eventsEnabled":"yes"}` is the first measured body where they do
// not. Nothing shared is changed on the strength of one endpoint - whether the
// other fourteen decoders answer the same way is unmeasured, and that is F163,
// whose text is in docs/superpowers/handover/events-family.md until somebody
// folds it into the follow-ups list.
func writeEventsConfigParseError(w http.ResponseWriter, err error) {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "unknown_error", "Cannot parse the JSON")
		return
	}
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "Cannot parse the JSON")
}

// listEvents serves GET /admin/realms/{realm}/events and listAdminEvents the
// one beside it. Both answer `[]` and both mean it.
//
// The empty array is `[]any{}` rather than an empty slice of a declared event
// type on purpose. Nothing here ever fills one, and a struct that names an
// event's ten fields would be the same claim about the model that a column
// nothing writes is. The measured shape is in the handover, where a reader can
// see it is a measurement rather than an implementation.
func (h *handler) listEvents(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	if !validEventEnum(w, q["type"], eventTypeNames) {
		return
	}
	if !validEventDates(w, q) {
		return
	}
	if !validEventDirection(w, q) {
		return
	}
	writeAdminJSON(w, []any{})
}

func (h *handler) listAdminEvents(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	// operationTypes before resourceTypes: sending both unknown answers the
	// same 500 either way, so the pair is unordered by measurement and this
	// order is the description's.
	if !validEventEnum(w, q["operationTypes"], operationTypeNames) {
		return
	}
	if !validEventEnum(w, q["resourceTypes"], resourceTypeNames) {
		return
	}
	if !validEventDates(w, q) {
		return
	}
	if !validEventDirection(w, q) {
		return
	}
	writeAdminJSON(w, []any{})
}

// clearEvents and clearAdminEvents serve the two deletes. 204 with no
// `Cache-Control`, on a realm that has never had a row and on one that could
// not, because there is nothing either of them could find to remove.
func (h *handler) clearEvents(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteNoContent(w, r)
}

func (h *handler) clearAdminEvents(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteNoContent(w, r)
}

// validEventEnum refuses a value outside one of the three enumerations, and the
// refusal is a **500**.
//
// That is Keycloak's own defect and it is reproduced: `?type=NOPE`,
// `?operationTypes=NOPE` and `?resourceTypes=NOPE` all answer
// `500 unknown_error` where every other bad parameter on these two routes
// answers a 400 or a 404. The comparison is case-sensitive - `type=login` and
// `operationTypes=create` are both the 500 - and an **empty** value is ignored
// rather than refused, so `?type=` is a 200.
func validEventEnum(w http.ResponseWriter, values []string, known map[string]bool) bool {
	for _, v := range values {
		if v == "" {
			continue
		}
		if !known[v] {
			httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
				"For more on this error consult the server log.")
			return false
		}
	}
	return true
}

// validEventDates checks dateFrom and then dateTo, in that order: sending both
// malformed answers about dateFrom.
func validEventDates(w http.ResponseWriter, q url.Values) bool {
	return validEventDate(w, q, "dateFrom") && validEventDate(w, q, "dateTo")
}

// validEventDate accepts `yyyy-MM-dd` or a non-negative epoch and refuses
// everything else with a sentence that names the parameter.
//
// The two accepted forms and the boundaries between them are measured:
// `2020-01-01` and `1700000000` and `0` and `20200101` are 200; `2020-1-1`
// (unpadded), `2020-13-01` and `2020-01-32` (out of range), `-1`, `1.5`,
// `2020-01-01T00:00:00Z` and `abc` are 400. So the date parse is strict about
// its own shape and about the calendar, and the epoch branch is digits only.
func validEventDate(w http.ResponseWriter, q url.Values, name string) bool {
	raw := q.Get(name)
	if raw == "" {
		return true
	}
	if _, err := time.Parse("2006-01-02", raw); err == nil {
		return true
	}
	if isDigits(raw) {
		return true
	}
	httpx.WriteMessageError(w, http.StatusBadRequest,
		"Invalid value for '"+name+"', expected format is yyyy-MM-dd or an Epoch timestamp")
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// validEventDirection is checked last of the four, and it is case-sensitive.
//
// `asc` and `desc` are the only two values: `DESC` and `Asc` are both the 400.
// The sentence **names a parameter that does not exist** - the query key is
// `direction` and the message says `sortDirection` - which is why it is a
// literal here rather than built from the key.
func validEventDirection(w http.ResponseWriter, q url.Values) bool {
	raw := q.Get("direction")
	if raw == "" || raw == "asc" || raw == "desc" {
		return true
	}
	httpx.WriteMessageError(w, http.StatusBadRequest,
		"Invalid value for sortDirection, expected value is asc or desc")
	return false
}

// eventsBound parses `first` or `max`, and where it runs is the finding.
//
// **A malformed bound is checked before the caller's role**: a caller holding no
// admin role at all gets `404 {"error":"HTTP 404 Not Found"}` for `?first=abc`
// where the same caller gets 403 for the same request without it. Every other
// parameter on these routes is checked *after* the role - an unknown `type`, a
// bad `dateFrom` and a bad `direction` are all 403 to that caller - so one
// parameter binds ahead of authorization and the other seven do not. That is
// why guardEventsListing exists instead of guardAny.
//
// The 404 body is the generic one, which AGENTS.md already attributes to a
// malformed integer bound on five listings across four families; these two make
// it seven. A negative bound and an empty value are both "no bound" and answer
// 200.
func eventsBound(w http.ResponseWriter, q url.Values, name string) bool {
	raw := q.Get(name)
	if raw == "" {
		return true
	}
	if _, err := strconv.Atoi(raw); err != nil {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return false
	}
	return true
}

// guardEventsListing is the two listings' guard: the realm, then the integer
// bounds, then the caller.
//
// It is a guard of its own rather than guardAny because of the order measured
// above, and the realm still comes first - an unknown realm answers
// `Realm not found.` to every caller, with or without a malformed bound.
//
// **One adjacency in here is a guess and is marked as one.** What is measured is
// that the bound is answered before the caller's *role*: a caller that
// authenticated and holds no admin role gets the 404 for `?first=abc` and a 403
// without it. Whether it is answered before the caller is *authenticated* is
// not - the request that would say so is a garbage bearer sent with a malformed
// bound, 401 against 404, and nothing in this repository has sent it on this
// family or on the seven others that answer the same 404. Moving resolveCaller
// above the bound changes that one cell and nothing else, which is why a
// mutation doing exactly that survives on purpose rather than being killed by a
// test that would be pinning a value nobody has seen. See the ninth survivor in
// docs/superpowers/handover/events-family.md.
func (h *handler) guardEventsListing(next func(http.ResponseWriter, *http.Request, *reqContext)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := h.resolveRealm(w, r)
		if realm == nil {
			return
		}
		q := r.URL.Query()
		if !eventsBound(w, q, "first") || !eventsBound(w, q, "max") {
			return
		}
		c := h.resolveCaller(w, r, realm)
		if c == nil {
			return
		}
		if !c.hasAny(eventsReadRoles) {
			writeForbidden(w)
			return
		}
		next(w, r, &reqContext{realm: realm, caller: c})
	}
}
