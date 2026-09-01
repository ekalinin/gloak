package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The scope family of authorization services: eight of the description's
// thirty-one untagged operations, measured 2026-09-01 against a live 26.7.1.
//
// All eight sit behind guardAuthz, and that the gate covers every one of them
// is measured rather than assumed - the first cut established it on the
// resource server and left open whether the whole surface shared it. It does:
// a client without authorizationServicesEnabled answers
// `404 {"error":"HTTP 404 Not Found"}` on all eight, to a caller holding
// manage-authorization and to one holding no admin role alike.
//
// Three things on this family disagree with what a neighbouring route does,
// and each has its own comment below:
//
//   - the create's 409 carries the five security headers and the update's 409
//     does not, on identical bodies;
//   - the listing's `name` is a case-insensitive substring and the search's is
//     exact and case-sensitive;
//   - one set of scopes comes back sorted from the listing and in creation
//     order from GET .../settings.

// authzScopeBody is what POST .../scope and PUT .../scope/{id} decode.
//
// **Six fields, and the last two are echoed rather than stored.** The strict
// decoder is what says which six: `type`, `owner`, `uris`, `attributes` and
// `scopes` all answer
// `Invalid json representation for ScopeRepresentation. Unrecognized field ...`,
// and `policies` and `resources` do not. So they are declared here because
// declaring them is what stops the 400, and they are raw because nothing in
// this cut can interpret them.
//
// The pointers distinguish absent from empty, which the wire does:
// `{"policies":null}` comes back with no `policies` key and `{"policies":[]}`
// comes back with `"policies":[]`.
type authzScopeBody struct {
	ID          string             `json:"id"`
	Name        *string            `json:"name"`
	IconURI     string             `json:"iconUri"`
	DisplayName string             `json:"displayName"`
	Policies    *[]json.RawMessage `json:"policies"`
	Resources   *[]json.RawMessage `json:"resources"`
}

// authzScopeCreated is the create's 201 body, and it is **not** a read.
//
// Measured: a create carrying `policies` and `resources` echoes both back, and
// every other view of the same scope omits them - the read, the listing, the
// search and the settings export all answer four keys. Nothing is stored: the
// resource and policy listings beside it stay `[]`. So the 201 is the request's
// representation with an id filled in rather than a read of what was written,
// and answering it with authzScopeRepresentation - which is the obvious
// implementation, since the two agree on every body that omits the pair -
// loses the one thing that says so.
//
// The field order is measured on a create that sent all six in reverse:
// `id, name, iconUri, policies, resources, displayName`. `displayName` is last,
// after the two echoed arrays, which is why authzScopeRepresentation's
// four-key order and this six-key one are not the same list with two entries
// removed - they are, but only by luck of where the pair sits.
type authzScopeCreated struct {
	ID          string             `json:"id,omitempty"`
	Name        string             `json:"name"`
	IconURI     string             `json:"iconUri,omitempty"`
	Policies    *[]json.RawMessage `json:"policies,omitempty"`
	Resources   *[]json.RawMessage `json:"resources,omitempty"`
	DisplayName string             `json:"displayName,omitempty"`
}

// scopeRepresentationOf is the four-key body the read, the listing and the
// search all serve. authzScopeRepresentation itself lives in authz.go, where
// the settings export - which is the same struct with the id left empty -
// already used it.
func scopeRepresentationOf(s *model.AuthzScope) authzScopeRepresentation {
	return authzScopeRepresentation{
		ID:          s.ID,
		Name:        s.Name,
		IconURI:     s.IconURI,
		DisplayName: s.DisplayName,
	}
}

// listAuthzScopes serves GET .../authz/resource-server/scope.
//
// **Sorted by name, byte-wise and not case-folded.** Measured:
// `ALPHAX, Bravo, brand-new, charlie, delta, idshape, probe-role-sweep` from a
// container where they were created in another order - `A` before `B` before
// `b` before `c`, which is `sort.Strings` and is not `strings.ToLower`
// ordering. The sort runs with no query parameters too, unlike the role
// listings, whose unpaginated path is not sorted at all.
//
// `name` here is a **case-insensitive substring**: `lph` matches `alpha` and
// `ALPHAX`, and `ALPHA` matches `alpha`. The `name` on `/scope/search` one path
// segment away is exact and case-sensitive. Two parameters of one name on one
// family, two meanings, and a shared matcher gets one of them wrong.
//
// `scopeId` is an exact id filter and is **ANDed** with `name`:
// `?name=delta&scopeId=<charlie's id>` is `[]`. An empty value of either does
// not filter.
func (h *handler) listAuthzScopes(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	scopes, err := h.store.Authz().ListScopes(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	q := r.URL.Query()
	first, ok := authzIntBound(w, q, "first")
	if !ok {
		return
	}
	max, ok := authzIntBound(w, q, "max")
	if !ok {
		return
	}

	out := []authzScopeRepresentation{}
	name := strings.ToLower(q.Get("name"))
	scopeID := q.Get("scopeId")
	for _, s := range scopes {
		if name != "" && !strings.Contains(strings.ToLower(s.Name), name) {
			continue
		}
		if scopeID != "" && s.ID != scopeID {
			continue
		}
		out = append(out, scopeRepresentationOf(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	// **Either bound alone pages**, which is neither the role listings' rule -
	// they need `search`, or `first` and `max` together - nor a coincidence:
	// `?max=2` alone returned two of five and `?first=1` alone returned four.
	// A negative bound means no bound, and `?max=0` is `[]`.
	if first >= 0 {
		if first >= len(out) {
			out = []authzScopeRepresentation{}
		} else {
			out = out[first:]
		}
	}
	if max >= 0 && max < len(out) {
		out = out[:max]
	}
	writeAdminJSON(w, out)
}

// authzIntBound reads `first` or `max`, and **a value that does not parse is a
// 404**.
//
// Measured 2026-09-01, and it is not this family's rule alone: `?first=abc` is
// `404 {"error":"HTTP 404 Not Found"}` on this listing, on `GET /roles`,
// `GET /users`, `GET /groups` and `GET /clients`, all five alike. `?first=1.5`
// and a value that overflows an int are the same 404; `?first=` is 200 and
// filters nothing, so an empty value counts as absent rather than as
// unparseable.
//
// The body is the one AGENTS.md attributes to an unmatched path, a wrong verb
// on a known path and a switched-off resource. A query parameter the
// description types as `integer` that cannot bind is a **fourth** producer of
// it, and it is the only one of the four that reaches a route the caller may
// use, on a resource that exists.
//
// Gloak diverges on the other four listings, which treat an unparseable bound
// as no bound - pageRoles says in as many words that the case had never been
// probed. It has now; see the follow-up. This function is deliberately not
// wired into them here, because four listings in three other chapters are not
// this branch's to move.
//
// The return is -1 for "no bound", which covers both an absent parameter and a
// negative one - `?first=-1&max=-1` returned everything.
func authzIntBound(w http.ResponseWriter, q url.Values, name string) (int, bool) {
	raw := q.Get(name)
	if raw == "" {
		return -1, true
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		writeAuthzNotEnabled(w)
		return 0, false
	}
	if v < 0 {
		return -1, true
	}
	return v, true
}

// createAuthzScope serves POST .../authz/resource-server/scope.
//
// **It is an upsert and the body's id decides which key it upserts on.**
// Measured across five bodies:
//
//	{"name":"alpha"} where alpha exists          201, the existing scope, same id
//	{"name":"alpha","displayName":"changed"}     201, and it *writes* displayName
//	{"id":<alpha's>,"name":"totally-new"}        201, renames alpha
//	{"id":<unknown>,"name":"delta"} delta exists 409 Duplicate resource error
//	{"id":"zzz","name":"idshape"}                201, id is the three bytes zzz
//
// So an id that names a scope wins outright, an id that names nothing creates
// with that id and then meets the name's uniqueness, and no id at all upserts
// by name. "Return the existing one" is what §1.9 of the first cut's handover
// recorded and it is half of it - the create also writes the body's other
// fields onto the row it found.
//
// **A body with no name is a 409 `Duplicate resource error` that carries all
// five security headers**, where the same body on the PUT one path segment
// away carries none. That pair is measured on one container with identical
// requests, so writeDuplicateResource - which deletes the five - must not be
// reached from here. See updateAuthzScope.
//
// `{"name":""}` is a 201 creating a scope named the empty string, so the check
// is presence and not emptiness.
//
// 201 with Cache-Control: no-cache, the charset, and **no Location**.
func (h *handler) createAuthzScope(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	body, ok := decodeAuthzScopeBody(w, r)
	if !ok {
		return
	}
	if body.Name == nil {
		// Not writeDuplicateResource: this 409 keeps the five headers.
		writeAuthzScopeConflict(w)
		return
	}

	existing, err := h.resolveScopeForUpsert(r, a.client.ID, body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	stored := &model.AuthzScope{
		ID:          body.ID,
		ClientID:    a.client.ID,
		Name:        *body.Name,
		IconURI:     body.IconURI,
		DisplayName: body.DisplayName,
	}
	if existing != nil {
		stored.ID = existing.ID
		err = h.store.Authz().UpdateScope(r.Context(), stored)
	} else {
		if stored.ID == "" {
			stored.ID = model.NewID()
		}
		err = h.store.Authz().CreateScope(r.Context(), stored)
	}
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAuthzScopeConflict(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusCreated, authzScopeCreated{
		ID:          stored.ID,
		Name:        stored.Name,
		IconURI:     stored.IconURI,
		Policies:    body.Policies,
		Resources:   body.Resources,
		DisplayName: stored.DisplayName,
	})
}

// resolveScopeForUpsert finds the row a create should write over: the one the
// body's id names, or failing that the one its name names. Nil means create.
//
// The id is looked up **first and alone** - an id that names nothing falls
// through to the create rather than to the name lookup, which is what makes
// `{"id":<unknown>,"name":<taken>}` a 409 instead of an update.
func (h *handler) resolveScopeForUpsert(r *http.Request, clientID string, body authzScopeBody) (*model.AuthzScope, error) {
	lookup := func(f func() (*model.AuthzScope, error)) (*model.AuthzScope, error) {
		s, err := f()
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return s, err
	}
	if body.ID != "" {
		return lookup(func() (*model.AuthzScope, error) {
			return h.store.Authz().ScopeByID(r.Context(), clientID, body.ID)
		})
	}
	return lookup(func() (*model.AuthzScope, error) {
		return h.store.Authz().ScopeByName(r.Context(), clientID, *body.Name)
	})
}

// searchAuthzScope serves GET .../authz/resource-server/scope/search.
//
// Three answers and none of them is a JSON array:
//
//	?name=alpha  matching     200 with a **bare object**
//	?name=ALPHA  not matching 204, empty body
//	?name= or absent          400, empty body
//
// **The match is exact and case-sensitive**, which the listing's `name` is
// not: `CaseTest` and `casetest` coexist as two scopes and each is found only
// by its own spelling, and `?name=lph` is a 204 where the listing's `?name=lph`
// returns two rows.
//
// All three carry `Cache-Control: no-cache`. The 400 and the 204 carry no
// `Content-Type` at all, because they carry no body.
func (h *handler) searchAuthzScope(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Cache-Control", "no-cache")
	if name == "" {
		writeEmptyStatus(w, r, http.StatusBadRequest)
		return
	}
	s, err := h.store.Authz().ScopeByName(r.Context(), a.client.ID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeEmptyStatus(w, r, http.StatusNoContent)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, scopeRepresentationOf(s))
}

// readAuthzScope serves GET .../authz/resource-server/scope/{scope-id}.
//
// The 404 **carries Cache-Control: no-cache and the PUT's and DELETE's on the
// same path do not**. Two 404s on one resource differing only in that header,
// and here the method does decide it - which is the opposite of what
// AGENTS.md's Cache-Control bullet concludes about deletes, where the method
// explains nothing and only the endpoint does.
func (h *handler) readAuthzScope(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	w.Header().Set("Cache-Control", "no-cache")
	s, ok := h.authzScopeFromPath(w, r, a)
	if !ok {
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, scopeRepresentationOf(s))
}

// updateAuthzScope serves PUT .../authz/resource-server/scope/{scope-id}.
//
// **It replaces**: a body carrying only `name` drops the scope's iconUri and
// displayName. And it **ignores the body's id** - a PUT addressed to scope A
// carrying scope B's id changed A and left B alone, which is the exact
// opposite of `PUT .../protocol-mappers/models/{id}`, where the body's id is
// the one that gets written.
//
// The order is measured three ways: the strict decode runs first (an unknown
// field addressed to a scope that does not exist is the 400, not the 404),
// then the scope lookup (a good body addressed to it is the empty 404), then
// the name (`{}` addressed to a scope that exists is the 409).
//
// **Its 409 drops the five security headers where the create's keeps them.**
// Both causes agree within each verb - an absent name and a name another scope
// holds both drop them here, and both keep them there - so it is decided per
// verb on this endpoint and not by the body, the cause or the status class.
// This is the third call site of writeDuplicateResource and the reason the
// create does not share it.
//
// Renaming a scope to the name it already has is a 204.
func (h *handler) updateAuthzScope(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	body, ok := decodeAuthzScopeBody(w, r)
	if !ok {
		return
	}
	s, ok := h.authzScopeFromPath(w, r, a)
	if !ok {
		return
	}
	if body.Name == nil {
		writeDuplicateResource(w)
		return
	}
	if *body.Name != s.Name {
		taken, err := h.store.Authz().ScopeByName(r.Context(), a.client.ID, *body.Name)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if taken != nil {
			writeDuplicateResource(w)
			return
		}
	}

	// The body's id is read and discarded; the path decides which row moves.
	updated := *s
	updated.Name = *body.Name
	updated.IconURI = body.IconURI
	updated.DisplayName = body.DisplayName
	if err := h.store.Authz().UpdateScope(r.Context(), &updated); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeDuplicateResource(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteAuthzScope serves DELETE .../authz/resource-server/scope/{scope-id}.
//
// 204 with **no Cache-Control**, which makes it an eighth measured delete and
// keeps "pinned per endpoint" the only surviving generalisation. Its 404 sends
// no Cache-Control either, unlike the GET's on the same path.
func (h *handler) deleteAuthzScope(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	err := h.store.Authz().DeleteScope(r.Context(), a.client.ID, r.PathValue("scopeID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAuthzScopeNotFound(w, r)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// listAuthzScopePermissions and listAuthzScopeResources serve
// GET .../scope/{scope-id}/permissions and .../resources.
//
// Both resolve the scope - an unknown one is the same empty 404 with
// `Cache-Control: no-cache` that the read beside them answers.
//
// **The two stopped agreeing when P10's third cut landed, exactly as the
// comment here predicted they would.** `/resources` lists every resource naming
// the scope and `/permissions` still answers `[]`. That is why they were two
// named handlers over one body rather than one handler registered twice.
func (h *handler) listAuthzScopePermissions(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	// Set before the lookup: the 404 carries it too, as the plain read's does.
	w.Header().Set("Cache-Control", "no-cache")
	if _, ok := h.authzScopeFromPath(w, r, a); !ok {
		return
	}
	// **The `[]` is the measured answer and not a stub, for exactly as long as
	// Gloak has no permissions.** There is no route that creates one, so the
	// empty array is a fact about the store rather than a placeholder. The half
	// of this route that is real behaviour today is the 404.
	writeAdminJSON(w, []struct{}{})
}

// listAuthzScopeResources serves GET .../scope/{scope-id}/resources.
//
// **Its entry is two keys and `name` comes first**: `{"name":...,"_id":...}`,
// measured 2026-09-01. That is neither the resource representation nor either
// of the three shapes a scope takes inside a resource - it is a fourth
// two-key body on this family, and the only one in the whole API that puts a
// name ahead of an id.
//
// The rows come back in **creation order**, which is what store.ListResources
// returns; the resource listing is the one that sorts.
func (h *handler) listAuthzScopeResources(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	w.Header().Set("Cache-Control", "no-cache")
	s, ok := h.authzScopeFromPath(w, r, a)
	if !ok {
		return
	}
	resources, err := h.store.Authz().ListResources(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := []authzScopeResourceRef{}
	for _, res := range resources {
		for _, id := range res.ScopeIDs {
			if id == s.ID {
				out = append(out, authzScopeResourceRef{Name: res.Name, ID: res.ID})
				break
			}
		}
	}
	writeAdminJSON(w, out)
}

// authzScopeResourceRef is one entry of GET .../scope/{scope-id}/resources.
// See the handler for why the field order is what it is.
type authzScopeResourceRef struct {
	Name string `json:"name"`
	ID   string `json:"_id"`
}

// authzScopeFromPath resolves the {scope-id} segment.
//
// It writes the empty 404 itself and reports false, and it does **not** set
// Cache-Control - the three routes that want one set it before calling, since
// the PUT and the DELETE measurably do not.
func (h *handler) authzScopeFromPath(w http.ResponseWriter, r *http.Request, a *authzContext) (*model.AuthzScope, bool) {
	s, err := h.store.Authz().ScopeByID(r.Context(), a.client.ID, r.PathValue("scopeID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAuthzScopeNotFound(w, r)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return s, true
}

// decodeAuthzScopeBody decodes the create's and the update's body.
//
// **An empty body and a literal `null` are both a 500**, measured on both
// verbs, where a body that is merely malformed is the ordinary 400. That check
// has to run before the strict decode, which would answer 400 for the same
// bytes.
func decodeAuthzScopeBody(w http.ResponseWriter, r *http.Request) (authzScopeBody, bool) {
	var body authzScopeBody
	if !requireJSONBody(w, r) {
		return body, false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return body, false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		writeAuthzScopeUnknownError(w)
		return body, false
	}
	r.Body = io.NopCloser(strings.NewReader(string(raw)))
	if !decodeStrict(w, r, "ScopeRepresentation", &body) {
		return body, false
	}
	return body, true
}

// writeAuthzScopeConflict is the create's 409, and the whole of what
// distinguishes it from writeDuplicateResource is that it **keeps** the five
// security headers.
//
// The two were measured side by side with identical bodies and identical
// request Content-Types: `POST .../scope` with `{}` carries all five and
// `PUT .../scope/{id}` with `{}` carries none. AGENTS.md's fifth
// security-header exception says a 409 `Duplicate resource error` sends none
// of the five, which is false in both directions - this endpoint sends them,
// and so does the repository's own committed golden for
// `PUT /default-default-client-scopes/{id}`.
//
// **The reason that exception now gives is wrong too**, corrected 2026-09-01 by
// P10's third cut. It says the variable is an empty response body and cites
// `PUT .../scope/{id}` as the half that "answers with nothing in it"; that 409
// answers with 67 bytes in it, which its own golden
// (`admin/authz-resource-server/scope-put-conflict.http`) has recorded since
// the day the sentence was written. The resource family reproduces the same
// split - a POST's 409 keeps the five and a PUT's drops them, both with
// bodies - so the variable is the endpoint or the verb and not the emptiness.
func writeAuthzScopeConflict(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
}

// writeAuthzScopeUnknownError is the 500 an empty or `null` body answers on
// both writes. Keycloak's own defect, reproduced, the same family as
// POST /users with an empty body.
func writeAuthzScopeUnknownError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// writeAuthzScopeNotFound is the 404 for a scope that does not exist.
//
// **It is not one of the twenty-one spellings of not-found. It is the absence
// of one**: no body, no `Content-Type`, and `Content-Length: 0`. Measured on
// the GET, the PUT, the DELETE and the two sub-listings alike, and on an id
// belonging to another resource server, which answers the same thing.
func writeAuthzScopeNotFound(w http.ResponseWriter, r *http.Request) {
	writeEmptyStatus(w, r, http.StatusNotFound)
}

// writeEmptyStatus writes a status with no body, deciding X-Frame-Options the
// way httpx.WriteNoContent does.
//
// **The rule AGENTS.md records for a 204 is really about an empty body.**
// Measured 2026-09-01 on `GET .../scope/{unknown}`, whose 404 carries
// `X-Frame-Options` when the request declared `application/json` and omits it
// for `text/plain` and for no Content-Type at all - and on the DELETE's 404
// and the search's 400 and 204, which agree. httpx.WriteNoContent is the one
// place that decides it for 204s and it is hard-wired to that status.
//
// **This belongs in internal/httpx and is here because that package was not
// this branch's to change.** It writes no body, so the divergence that
// package's boundary rule exists to prevent - a second marshaller drifting on
// the bytes - is not reachable through it, and the Date suppression it does
// need is one line. See the follow-up; moving it is a rename.
func writeEmptyStatus(w http.ResponseWriter, r *http.Request, status int) {
	// Keycloak sends no Date on any response and net/http adds one; every
	// writer in internal/httpx suppresses it, and an empty-bodied response is
	// no exception. The conformance harness cannot see this - it serves
	// through httptest.ResponseRecorder, which adds no Date either.
	w.Header()["Date"] = nil
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/") {
		w.Header().Del("X-Frame-Options")
	}
	w.WriteHeader(status)
}
