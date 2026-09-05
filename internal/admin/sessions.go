package admin

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The session family: eleven operations across three tags, all measured
// against a live 26.7.1 on 2026-09-03. See
// docs/superpowers/plans/2026-09-03-session-family.md and the "session" section
// of docs/superpowers/handover/session-family.md.
//
// # The offline half is served from the empty set, and that is exact
//
// Four of the eleven read offline sessions, and Gloak has none: grantedScope in
// internal/oidc drops `offline_access` before anything is stored, so no request
// this server can receive creates one. The reads therefore answer `{"count":0}`
// and `[]`, `client-session-stats` reports `"offline":"0"`, and
// `DELETE .../sessions/{id}?isOffline=true` is always the 404 - every one of
// which is byte-exact for every state this server can reach.
//
// **No offline_session table is added for it.** F157's rule: a table nothing
// writes is a claim about the model that is not true, and the only possible
// writer lives in a package this cut does not own. `attack-detection` is the
// same arrangement - a chapter whose whole reachable state is the empty one.
//
// The same reasoning covers three fields of the representation below.

// userSessionRepresentation is Keycloak's UserSessionRepresentation.
//
// The nine keys and their order are transcribed from a recorded response and
// are the contract; sessions_test.go asserts the marshalled key list rather
// than spot values, because moving a field here is a silent divergence.
//
// It is **not** a Java map, which was checked rather than assumed:
// javamap.KeyOrder over these nine names returns a completely different order,
// so this is a POJO and a Go struct in declaration order is the right model.
type userSessionRepresentation struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	UserID   string `json:"userId"`
	// IPAddress is the address the login came from, and **Gloak serves it
	// empty**.
	//
	// The value is a property of the request that created the session, so its
	// only possible writer is internal/oidc's startSession - a package this cut
	// does not own. A column here with no writer would be a claim about the
	// model that is not true, which is F157's rule, so there is no column and
	// the key goes out empty rather than absent: Keycloak always emits it.
	//
	// No golden can see this. The recorded value is the container's view of the
	// recorder's address and the served one is whatever this process has, so
	// the field is masked either way - which means the suite is structurally
	// blind to the gap, and it is written down here instead. See the handover.
	IPAddress string `json:"ipAddress"`
	// Start and LastAccess are Unix **milliseconds truncated to the second**.
	// Every measured value ends in three zeros, because Keycloak stores seconds
	// and the representation multiplies. LastAccess moves on a refresh and
	// Start does not, measured three seconds apart.
	Start      int64 `json:"start"`
	LastAccess int64 `json:"lastAccess"`
	// RememberMe is false on every session Gloak can make, for the same reason
	// IPAddress is empty: nothing in this server sets it and no column claims
	// otherwise.
	RememberMe bool `json:"rememberMe"`
	// Clients maps a client's internal UUID to its clientId - one entry per
	// client that took part in this session.
	//
	// It is a Java map, and javamap.KeyOrder is measured **wrong** on it: six
	// clients came back in an order KeyOrder gets right except for one colliding
	// pair, which chains in insertion order. KeyOrder is still what is used,
	// because it is exact on every collision-free key set and this is the only
	// model of that order the project has; a session reaching enough clients to
	// collide is beyond what any golden here holds.
	Clients orderedStringMap `json:"clients"`
	// TransientUser is false on every measured session. Same reasoning as
	// RememberMe.
	TransientUser bool `json:"transientUser"`
}

// orderedStringMap marshals a string map in javamap.KeyOrder rather than
// sorted, which is what Go would do with a map[string]string.
type orderedStringMap struct {
	keys   []string
	values map[string]string
}

func newOrderedStringMap(values map[string]string) orderedStringMap {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	return orderedStringMap{keys: javamap.KeyOrder(keys), values: values}
}

func (m orderedStringMap) MarshalJSON() ([]byte, error) {
	out := []byte("{")
	for i, k := range m.keys {
		if i > 0 {
			out = append(out, ',')
		}
		key, err := marshalOrderedValue(k)
		if err != nil {
			return nil, err
		}
		value, err := marshalOrderedValue(m.values[k])
		if err != nil {
			return nil, err
		}
		out = append(out, key...)
		out = append(out, ':')
		out = append(out, value...)
	}
	return append(out, '}'), nil
}

// clientSessionStatsRow is one row of GET .../client-session-stats.
//
// **It is a Map<String,String>, not a POJO**, and both halves of that sentence
// are measured. The description's schema says
// `additionalProperties: {"type":"string"}`, which is why the two counts are
// quoted; and the key order is javamap.KeyOrder's over those four names, which
// TestClientSessionStatsRowIsInJavaMapOrder computes rather than transcribes.
//
// The key set never varies, so the order is a constant and a struct expresses
// it exactly. A map here would be sorted by encoding/json and wrong.
type clientSessionStatsRow struct {
	// Offline is always "0": see the offline note at the top of this file.
	Offline  string `json:"offline"`
	ClientID string `json:"clientId"`
	Active   string `json:"active"`
	ID       string `json:"id"`
}

// globalRequestResult is Keycloak's GlobalRequestResult, the body of
// logout-all and both push-revocations.
//
// Both arrays are omitempty, because an empty result is measured as `{}` and
// not as `{"successRequests":[],"failedRequests":[]}`.
type globalRequestResult struct {
	SuccessRequests []string `json:"successRequests,omitempty"`
	FailedRequests  []string `json:"failedRequests,omitempty"`
}

// writeSessionJSON is the 200 shape shared by the seven reads of this family:
// the charset and `Cache-Control: no-cache`.
//
// The three 200 **writes** carry no Cache-Control at all, measured on the same
// container in the same sweep, which is why they do not go through here. That
// is "Cache-Control is pinned per endpoint" again rather than a new rule.
func writeSessionJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, body)
}

// sessionRepresentations turns stored sessions into the wire shape, reading
// each one's clients.
func (h *handler) sessionRepresentations(ctx context.Context, sessions []*model.UserSession, realmID string) ([]userSessionRepresentation, error) {
	out := make([]userSessionRepresentation, 0, len(sessions))
	for _, s := range sessions {
		clients, err := h.sessionClients(ctx, s.ID, realmID)
		if err != nil {
			return nil, err
		}
		out = append(out, userSessionRepresentation{
			ID:       s.ID,
			Username: s.Username,
			UserID:   s.UserID,
			// Truncated to the second: see the field comments above.
			Start:      s.StartedAt / 1000 * 1000,
			LastAccess: s.LastRefresh / 1000 * 1000,
			Clients:    newOrderedStringMap(clients),
		})
	}
	return out, nil
}

// sessionClients is the `clients` map: the client UUID against its clientId,
// for every client taking part in the session.
func (h *handler) sessionClients(ctx context.Context, sessionID, realmID string) (map[string]string, error) {
	rows, err := h.store.Sessions().ListClientSessions(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, cs := range rows {
		client, err := h.store.Clients().ByID(ctx, realmID, cs.ClientID)
		if err != nil {
			// A client session whose client has gone is not a state this
			// schema allows - the row cascades - so it is skipped rather than
			// turned into a 500 that would name an impossible cause.
			continue
		}
		out[client.ID] = client.ClientID
	}
	return out, nil
}

// countBody is the `{"count":n}` both session counts answer with. It is an
// object here where GET /users/count is a bare number, which is the group
// count's shape rather than the user count's.
type countBody struct {
	Count int `json:"count"`
}

// clientSessionCount serves GET .../clients/{client-uuid}/session-count.
//
// Guard: view-clients or manage-clients, measured one role at a time. An
// unknown client is "Could not find client", the /clients family's spelling.
func (h *handler) clientSessionCount(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	sessions, err := h.store.Sessions().ListUserSessionsByClient(r.Context(), rc.realm.ID, client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeSessionJSON(w, countBody{Count: len(sessions)})
}

// clientOfflineSessionCount serves
// GET .../clients/{client-uuid}/offline-session-count.
//
// Always zero: see the offline note at the top of this file. The client is
// still resolved, because the 404 for an unknown one is measured and is not a
// function of how many sessions there are.
func (h *handler) clientOfflineSessionCount(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.clientFromPath(w, r, rc); !ok {
		return
	}
	writeSessionJSON(w, countBody{Count: 0})
}

// clientUserSessions serves GET .../clients/{client-uuid}/user-sessions.
//
// This is one of the **two** listings in the family that page. Either bound
// alone pages, a negative bound means no bound, max=0 is zero rows and a
// malformed integer is the generic 404 - all measured over four sessions.
func (h *handler) clientUserSessions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	first, max, ok := parseSessionBounds(w, r)
	if !ok {
		return
	}
	sessions, err := h.store.Sessions().ListUserSessionsByClient(r.Context(), rc.realm.ID, client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	rows, err := h.sessionRepresentations(r.Context(), pageSessions(sessions, first, max), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeSessionJSON(w, rows)
}

// clientOfflineSessions serves GET .../clients/{client-uuid}/offline-sessions.
//
// Always `[]`. The bounds are still parsed, because the malformed-integer 404
// is measured on this route too and it is checked before anything is counted -
// so a route that skipped the parse because the answer is empty would answer
// 200 where Keycloak answers 404.
func (h *handler) clientOfflineSessions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.clientFromPath(w, r, rc); !ok {
		return
	}
	if _, _, ok := parseSessionBounds(w, r); !ok {
		return
	}
	writeSessionJSON(w, []userSessionRepresentation{})
}

// userSessions serves GET .../users/{user-id}/sessions.
//
// **It reads no query parameters at all**, and that is measured rather than
// read off the description: with six sessions in the realm, `max=1`, `first=1`,
// `max=0`, `first=abc` and `max=abc` each answered all six with a 200 - where
// the two client listings above answer a malformed bound with a 404. One
// family, one input, two answers.
//
// The first reading of this was wrong: a single `?max=1` against a user holding
// one session answered one row and looked like paging. A probe whose input
// cannot change its output is measuring itself.
func (h *handler) userSessions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.userFromPath(w, r, rc)
	if !ok {
		return
	}
	sessions, err := h.store.Sessions().ListUserSessionsByUser(r.Context(), rc.realm.ID, user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	rows, err := h.sessionRepresentations(r.Context(), sessions, rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeSessionJSON(w, rows)
}

// userOfflineSessions serves
// GET .../users/{user-id}/offline-sessions/{clientUuid}.
//
// Always `[]`, and the two resolutions are what the route really asserts: the
// **user comes first** - an unknown user with a real client answers about the
// user, and so does a request whose ids are both unknown - and the client's own
// 404 is `Client not found`, where the five routes under /clients/{uuid} answer
// `Could not find client` for the very same missing client. One missing client,
// two spellings, one route family apart.
func (h *handler) userOfflineSessions(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.userFromPath(w, r, rc); !ok {
		return
	}
	_, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, r.PathValue("clientUUID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Client not found")
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeSessionJSON(w, []userSessionRepresentation{})
}

// clientSessionStats serves GET .../client-session-stats.
//
// It is the one read of the eleven that sees something the other ten do not:
// both counts side by side, per client, and **a row survives an active count of
// zero** - a client with only offline sessions is listed with `"active":"0"`.
// A client with neither gets no row at all, which is why this is not simply the
// client listing with numbers attached.
//
// The array is a Java map keyed on the client's UUID: six clients came back in
// javamap.KeyOrder's order exactly, which is a measured key set for that
// function rather than an assumption about this one.
//
// Guard: view-realm or manage-realm - the third of the three guards this one
// tag takes.
func (h *handler) clientSessionStats(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	sessions, err := h.store.Sessions().ListUserSessionsByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	active := map[string]int{}
	for _, s := range sessions {
		rows, err := h.store.Sessions().ListClientSessions(r.Context(), s.ID)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		for _, cs := range rows {
			active[cs.ClientID]++
		}
	}
	uuids := make([]string, 0, len(active))
	for id := range active {
		uuids = append(uuids, id)
	}
	out := make([]clientSessionStatsRow, 0, len(uuids))
	for _, id := range javamap.KeyOrder(uuids) {
		client, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, id)
		if err != nil {
			continue
		}
		out = append(out, clientSessionStatsRow{
			Offline:  "0",
			ClientID: client.ClientID,
			Active:   strconv.Itoa(active[id]),
			ID:       client.ID,
		})
	}
	writeSessionJSON(w, out)
}

// deleteSession serves DELETE .../sessions/{session}.
//
// Three things are measured and none of them is obvious.
//
// **`isOffline` selects which of two disjoint id spaces the path segment is
// looked up in.** An online id with `isOffline=true` is a 404 and an offline id
// without it is a 404 too, so the parameter is not a filter on one namespace.
// Gloak's offline space is empty, so `isOffline=true` is always the 404.
//
// **A malformed boolean is not a malformed integer.** `isOffline=bogus` was
// measured deleting an online session - it parses leniently and falls back to
// false - where `first=abc` on the sibling listing one path segment away is a
// 404. One family, one malformed value, two answers, decided by the type.
//
// **The 404 body carries Keycloak's own typo**: `Sesssion not found`, with three
// `s`s, for an unknown id and for one that is not a UUID alike. Correcting it is
// the tidy-up that breaks the one thing this project exists to do.
//
// Guard: manage-users alone, on a route the description tags `Realms Admin`.
// A manage-users caller gets the 404 and every other role gets 403, which is
// what says the role is checked before the session is resolved.
func (h *handler) deleteSession(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if r.URL.Query().Get("isOffline") == "true" {
		writeSessionNotFound(w)
		return
	}
	err := h.store.Sessions().DeleteUserSession(r.Context(), rc.realm.ID, r.PathValue("sessionID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeSessionNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// writeSessionNotFound is the twenty-eighth spelling of not-found on this API,
// and the first that is misspelled. Kept in one place so a second, corrected
// spelling cannot appear beside it.
func writeSessionNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Sesssion not found")
}

// logoutAll serves POST .../logout-all.
//
// Three measured behaviours, and the third is what makes it servable here.
//
//  1. It ends every session in the realm - **including the offline ones**,
//     where POST /users/{id}/logout leaves them alone. Measured twice with the
//     state rebuilt in between. Gloak has no offline sessions, so the two
//     endpoints agree here and the divergence is only reachable on a server
//     that has them.
//  2. It stamps the **realm's** notBefore with the second it happened, and
//     leaves every user's and every client's alone. That is the realm-level
//     twin of the user logout's stamp.
//  3. Its GlobalRequestResult reports every client carrying an adminUrl as a
//     **success, whether or not that URL is reachable** - measured against an
//     unroutable address, with a session at that client and without one, where
//     push-revocation on the same client and the same address reports a
//     failure. So the body is a pure function of the realm's clients and needs
//     no outbound call at all, which is why this handler makes none.
//
// Guard: manage-users alone.
func (h *handler) logoutAll(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	sessions, err := h.store.Sessions().ListUserSessionsByRealm(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	for _, s := range sessions {
		if err := h.store.Sessions().DeleteUserSession(r.Context(), rc.realm.ID, s.ID); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}
	if !h.stampRealmNotBefore(w, r, rc) {
		return
	}
	// The success list is every non-empty adminUrl in the realm, and **Gloak
	// has no adminUrl at all**: the field is absent from model.Client and from
	// the client representation, so no client this server serves can carry one
	// and the list is empty on every realm. A helper computing it would be a
	// function that can only return nil, which is the same claim-that-is-not-
	// true this file already declines to make about an offline session table.
	httpx.WriteJSONCharset(w, http.StatusOK, globalRequestResult{})
}

// stampRealmNotBefore writes the realm's notBefore through the settings blob
// the realm representation already lives in, which is why this needs no
// migration.
func (h *handler) stampRealmNotBefore(w http.ResponseWriter, r *http.Request, rc *reqContext) bool {
	rep, err := decodeRealmSettings(rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	rep.NotBefore = int(time.Now().Unix())
	updated := *rc.realm
	updated.Settings = marshalRealmSettings(&rep)
	if err := h.store.Realms().Update(r.Context(), &updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

// pushRealmRevocation serves POST .../push-revocation.
//
// **It stamps nothing.** Measured on a fresh realm with the realm and its
// client read before and after: neither notBefore moved. push-revocation
// pushes a policy that logout-all sets; reading the two names the other way
// round is the obvious mistake and it is wrong on both.
//
// The body is `{}` when no client in the realm carries an adminUrl, which is
// every default install, and that is what Gloak serves. When one does, Keycloak
// POSTs a signed JWT to `{adminUrl}/k_push_not_before` and reports the outcome
// per URL - a second outbound mechanism beside the OIDC back-channel one, with
// its own path, claim set and `text/plain` content type. Gloak makes no such
// call, so it reports no outcome. Building the poster in this package would put
// half of internal/oidc's machinery here; see the handover's disposition of
// F122.
//
// Guard: manage-realm alone.
func (h *handler) pushRealmRevocation(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	httpx.WriteJSONCharset(w, http.StatusOK, globalRequestResult{})
}

// pushClientRevocation serves POST .../clients/{client-uuid}/push-revocation.
//
// The client-scoped twin of pushRealmRevocation, with the same body and the
// same reason for it. The client is resolved because an unknown one is
// "Could not find client" whatever the body would have been.
//
// Guard: manage-clients. view-clients is 403 here and 200 on the four reads
// beside it, which is the reads-take-the-view-role split measured again.
func (h *handler) pushClientRevocation(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	if _, ok := h.clientFromPath(w, r, rc); !ok {
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, globalRequestResult{})
}

// parseSessionBounds reads first and max for the two listings that page.
//
// A malformed integer is `{"error":"HTTP 404 Not Found"}` - the generic body,
// whose producers AGENTS.md already counts, reached here by a route the caller
// may legitimately use. A negative bound means "no bound" and max=0 means zero
// rows, so the two cannot share a sentinel: -1 is "unbounded" and 0 is a real
// bound.
func parseSessionBounds(w http.ResponseWriter, r *http.Request) (first, max int, ok bool) {
	first, ok = sessionBound(w, r, "first", 0)
	if !ok {
		return 0, 0, false
	}
	max, ok = sessionBound(w, r, "max", -1)
	if !ok {
		return 0, 0, false
	}
	return first, max, true
}

func sessionBound(w http.ResponseWriter, r *http.Request, name string, missing int) (int, bool) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return missing, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
		return 0, false
	}
	if v < 0 {
		return missing, true
	}
	return v, true
}

// pageSessions applies the bounds to an already-sorted listing.
func pageSessions(sessions []*model.UserSession, first, max int) []*model.UserSession {
	if first > 0 {
		if first >= len(sessions) {
			return nil
		}
		sessions = sessions[first:]
	}
	if max >= 0 && max < len(sessions) {
		sessions = sessions[:max]
	}
	return sessions
}
