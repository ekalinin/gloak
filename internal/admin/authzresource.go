package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The resource family of authorization services: nine of the description's
// thirty-one untagged operations, measured 2026-09-01 against a live 26.7.1.
//
// All nine sit behind guardAuthz, measured on each of them: a client without
// authorizationServicesEnabled answers `404 {"error":"HTTP 404 Not Found"}` on
// every one, to a caller holding manage-authorization and to one holding no
// admin role alike. The role sets are the first cut's, re-measured here one
// single role at a time over eight callers rather than carried over.
//
// **The family disagrees with the scope family next door in five places**, and
// every one of them is a place where sharing an implementation would be wrong:
//
//   - an unknown id is a **JSON** 404 with no Cache-Control here, where the
//     scope family's is an empty body **with** Cache-Control;
//   - the three sub-routes invert that again - their 404 is the scope family's
//     empty body with Cache-Control, one path segment below the read whose 404
//     is JSON without it;
//   - a create with no name is `Duplicate resource error` on both families, but
//     a create with a **taken** name is `Resource with name [x] already exists.`
//     here and an upsert there;
//   - an empty request body is a **400 with an empty body** here and a 500
//     there, on the same resource server;
//   - `POST` is not an upsert on the name. It upserts on `_id` alone.
type authzResourceOwner struct {
	// Both halves come from the **client**, and neither says what its name
	// says: the id is the client's internal UUID and the name is the client's
	// `clientId` string. That is resourceServerRepresentation's inversion again
	// and it is measured on every resource this family serves.
	ID   string `json:"id"`
	Name string `json:"name"`
}

// authzInlineScope is a scope as it appears **inside** a resource, and it is
// not the scope family's four-key body.
//
// Three views of one scope, measured on a scope carrying both an iconUri and a
// displayName:
//
//	inside a resource                 {id, name, iconUri}   - displayName dropped
//	GET .../resource/{id}/scopes      {id, name}            - iconUri dropped too
//	inside the settings export        {name}                - and the id with it
//
// A second scope carrying a displayName and no iconUri came back `{id, name}`
// from inside a resource, which is what says the missing key is dropped rather
// than merely empty. Serving authzScopeRepresentation in any of the three
// places would emit a key Keycloak does not.
type authzInlineScope struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	IconURI string `json:"iconUri,omitempty"`
}

// authzResourceAttributes is a resource's `attributes`: a multivalued Java map
// whose serialised key order is part of the contract.
//
// It is a slice rather than a map for model.StringMap's reason, applied to a
// multivalued map the way OrganizationAttribute already is. The order it holds
// is the order the request wrote, and the wire order is computed from that -
// see authzResourceRepresentationOf.
type authzResourceAttributes []model.AuthzResourceAttribute

// MarshalJSON writes the pairs as a JSON object in the order they are held. A
// nil value is `{}` rather than `null`: a resource with no attributes was
// measured carrying `"attributes":{}` and never omitting the key.
func (a authzResourceAttributes) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, entry := range a {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(entry.Name)
		if err != nil {
			return nil, err
		}
		values := entry.Values
		if values == nil {
			values = []string{}
		}
		v, err := json.Marshal(values)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON reads a JSON object token by token so the entries keep the
// order they arrived in, which is what internal/admin needs to place a bucket
// collision. Decoding into a Go map would lose it twice over.
//
// **A scalar value is accepted and coerced**: `{"k":"v"}` was measured coming
// back `{"k":["v"]}`. **An empty array drops the key entirely**: `{"k":[]}`
// came back `{}`, so an entry with no values is not stored at all.
func (a *authzResourceAttributes) UnmarshalJSON(data []byte) error {
	if string(bytes.TrimSpace(data)) == "null" {
		*a = nil
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("admin: resource attributes: expected an object")
	}
	out := authzResourceAttributes{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("admin: resource attributes: expected a key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		values, err := authzAttributeValues(raw)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			continue
		}
		out = append(out, model.AuthzResourceAttribute{Name: key, Values: values})
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	*a = out
	return nil
}

// authzAttributeValues reads one attribute value, which the server accepts as a
// string or as an array of strings.
func authzAttributeValues(raw json.RawMessage) ([]string, error) {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []string{one}, nil
}

// authzResourceRepresentation is a resource as the read, the listing, the
// search, the create's 201 and the settings export all serve it.
//
// The measured field order is
// `name type owner ownerManagedAccess displayName attributes _id uris scopes
// icon_uri`. **`_id` is in the middle**, which is why this is a struct with
// fields in that order and not the tidy id-first one every other representation
// in this package has.
//
// Present-or-absent is measured on a resource created with only a name:
// `name`, `owner`, `ownerManagedAccess`, `attributes` and `uris` are always
// there - `{}` and `[]` when empty - and `type`, `displayName`, `scopes` and
// `icon_uri` are dropped.
//
// Three of the fields are pointers or omitempty for reasons that are not
// cosmetic:
//
//   - `owner` and `_id` are **dropped by the settings export** and nothing
//     else drops them;
//   - `attributes` is dropped by `?deep=false` on the listing, along with
//     `scopes` - two keys, one parameter, and the single read and the search
//     ignore it entirely.
type authzResourceRepresentation struct {
	Name               string                   `json:"name"`
	Type               string                   `json:"type,omitempty"`
	Owner              *authzResourceOwner      `json:"owner,omitempty"`
	OwnerManagedAccess bool                     `json:"ownerManagedAccess"`
	DisplayName        string                   `json:"displayName,omitempty"`
	Attributes         *authzResourceAttributes `json:"attributes,omitempty"`
	ID                 string                   `json:"_id,omitempty"`
	URIs               []string                 `json:"uris"`
	Scopes             []authzInlineScope       `json:"scopes,omitempty"`
	IconURI            string                   `json:"icon_uri,omitempty"`
}

// authzResourceView says which of the three serialisations a caller wants.
type authzResourceView int

const (
	// authzResourceFull is the read, the search, the create's 201 and the
	// listing with deep left alone.
	authzResourceFull authzResourceView = iota
	// authzResourceShallow is the listing under `?deep=false`, which drops
	// `attributes` and `scopes` and keeps everything else.
	authzResourceShallow
	// authzResourceExported is the settings export, which drops `_id` and
	// `owner`, keeps `type`, `displayName` and `icon_uri`, and reduces each
	// inline scope to its **name alone**. All four halves measured on one
	// resource carrying all of them.
	authzResourceExported
)

// authzResourceRepresentationOf builds one of the three views.
//
// scopeNames maps a scope id to the scope, because a resource stores scope ids
// and every view of it serves at least the name.
//
// **The two collection orders are computed here and they are not the same
// rule**, measured on one body on one container:
//
//	uris       ["/z","/a","/m"]        ->  /a, /z, /m       HashSet bucket order
//	uris       ["aa","bb","zz"]        ->  aa, bb, zz       one bucket, request order
//	uris       ["zz","bb","aa"]        ->  zz, bb, aa
//	attributes {"aa":..,"bb":..,"zz":..} -> zz, bb, aa      one bucket, **reverse**
//	attributes {"zz":..,"bb":..,"aa":..} -> aa, bb, zz
//
// All six of those keys hash to bucket 0 at every table size - a two-letter
// string of one repeated character has a hashCode that is a multiple of 32 - so
// the bucket says nothing there and the chain says everything: the uri chain
// runs forwards and the attribute chain runs backwards. `javamap.KeyOrder`
// sorts before bucketing, so it is exact on any key set with no collision and
// wrong on both chains. It is used for both anyway, because internal/javamap
// was not this branch's to change; the two chain rules are vectors for it and
// live in the handover. Every key set the goldens use is measured collision-free.
func authzResourceRepresentationOf(res *model.AuthzResource, clientID, clientName string,
	scopes map[string]*model.AuthzScope, view authzResourceView) authzResourceRepresentation {
	rep := authzResourceRepresentation{
		Name:               res.Name,
		Type:               res.Type,
		OwnerManagedAccess: res.OwnerManagedAccess,
		DisplayName:        res.DisplayName,
		URIs:               orderAuthzURIs(res.URIs),
		IconURI:            res.IconURI,
	}
	if view != authzResourceExported {
		rep.ID = res.ID
		rep.Owner = &authzResourceOwner{ID: clientID, Name: clientName}
	}
	if view != authzResourceShallow {
		attrs := orderAuthzResourceAttributes(res.Attributes)
		rep.Attributes = &attrs
		rep.Scopes = inlineScopesOf(res, scopes, view)
	}
	return rep
}

// inlineScopesOf builds a resource's `scopes` array, in the bucket order of
// the scope **names** - measured stable across two resource servers holding
// different scope ids for the same three names, so the order follows the name
// and not the id.
//
// The export's entry is the name alone; every other view carries the id and the
// iconUri and never the displayName.
func inlineScopesOf(res *model.AuthzResource, scopes map[string]*model.AuthzScope,
	view authzResourceView) []authzInlineScope {
	byName := map[string]*model.AuthzScope{}
	names := make([]string, 0, len(res.ScopeIDs))
	for _, id := range res.ScopeIDs {
		s, ok := scopes[id]
		if !ok {
			continue
		}
		byName[s.Name] = s
		names = append(names, s.Name)
	}
	if len(names) == 0 {
		return nil
	}
	out := make([]authzInlineScope, 0, len(names))
	for _, name := range javamap.KeyOrder(names) {
		s := byName[name]
		if view == authzResourceExported {
			out = append(out, authzInlineScope{Name: s.Name})
			continue
		}
		out = append(out, authzInlineScope{ID: s.ID, Name: s.Name, IconURI: s.IconURI})
	}
	return out
}

// orderAuthzURIs puts a resource's uris into the order a Java HashSet iterates.
// The store keeps them in the order they arrived, which is what lets a bucket
// collision chain the way it did on the way in; javamap.KeyOrder decides the
// rest. orderOrganizationAttributes' shape, one field along.
func orderAuthzURIs(in []string) []string {
	out := javamap.KeyOrder(in)
	if out == nil {
		return []string{}
	}
	return out
}

// orderAuthzResourceAttributes puts the stored entries into Keycloak's HashMap
// bucket order, the way orderOrganizationAttributes does for an organization's.
func orderAuthzResourceAttributes(in []model.AuthzResourceAttribute) authzResourceAttributes {
	byName := make(map[string]model.AuthzResourceAttribute, len(in))
	names := make([]string, 0, len(in))
	for _, a := range in {
		byName[a.Name] = a
		names = append(names, a.Name)
	}
	out := make(authzResourceAttributes, 0, len(in))
	for _, name := range javamap.KeyOrder(names) {
		out = append(out, byName[name])
	}
	return out
}

// authzResourceBody is what POST .../resource and PUT .../resource/{id} decode.
//
// **Twelve fields, and the strict decoder is what says which twelve.** Probed
// one field at a time: `_id`, `name`, `displayName`, `type`, `icon_uri`,
// `uris`, `uri`, `owner`, `ownerManagedAccess`, `attributes`, `scopes` and
// `resource_scopes` are accepted; `id`, `iconUri`, `policies` and `typedScopes`
// answer `Unrecognized field`.
//
// Three of those are worth their own sentence:
//
//   - **the id's wire name is `_id` and `id` is refused**, which is the
//     opposite of every other create in this API;
//   - **`iconUri` is refused and `icon_uri` is the spelling**, which is the
//     opposite of the scope family one path segment away;
//   - **`uri` is a legacy alias** that becomes a one-element `uris`, and
//     `resource_scopes` is an alias for `scopes` that **wins** when both are
//     sent - measured with a different scope in each.
//
// `owner` is declared and unused: any value is a 500, including an object of
// the right shape, so the field exists to keep the request off the strict 400
// and the handler refuses it separately. `null` counts as absent.
//
// Name is a pointer because absent and empty are two answers: a body with no
// name is the 409 and `{"name":""}` is a 201. Attributes is a pointer because
// **absent and `{}` are two answers on the PUT**: absent keeps what is stored
// and `{}` clears it, which is the one field on this body that a replace does
// not replace.
type authzResourceBody struct {
	ID                 string                   `json:"_id"`
	Name               *string                  `json:"name"`
	DisplayName        string                   `json:"displayName"`
	Type               string                   `json:"type"`
	IconURI            string                   `json:"icon_uri"`
	URIs               []string                 `json:"uris"`
	URI                string                   `json:"uri"`
	Owner              json.RawMessage          `json:"owner"`
	OwnerManagedAccess bool                     `json:"ownerManagedAccess"`
	Attributes         *authzResourceAttributes `json:"attributes"`
	Scopes             []authzScopeRef          `json:"scopes"`
	ResourceScopes     []authzScopeRef          `json:"resource_scopes"`
}

// authzScopeRef is one entry of a resource's `scopes`. **The id is resolved
// first and alone**: an entry carrying a real id and a name naming another
// scope resolved to the id's scope, and an entry carrying an id that names
// nothing is a 409 `Duplicate resource error` rather than falling through to
// the name. An entry carrying a name nobody holds **creates** the scope.
type authzScopeRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// scopeRefs returns the entries the body means, with `resource_scopes` winning
// over `scopes` when both are present - measured, and the opposite of what
// "the documented name wins" would give.
func (b authzResourceBody) scopeRefs() []authzScopeRef {
	if b.ResourceScopes != nil {
		return b.ResourceScopes
	}
	return b.Scopes
}

// uris returns the uris the body means, folding the legacy singular `uri` in.
// A repeated value collapses, because the field is a Java Set.
func (b authzResourceBody) uris() []string {
	in := b.URIs
	if b.URI != "" {
		in = append(append([]string{}, in...), b.URI)
	}
	seen := map[string]bool{}
	out := []string{}
	for _, u := range in {
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// listAuthzResources serves GET .../authz/resource-server/resource.
//
// **Ten of the description's eleven query parameters are read**, counted from
// the description's list rather than incremented: `_id`, `deep`, `exactName`,
// `first`, `matchingUri`, `max`, `name`, `owner`, `scope`, `type` and `uri`,
// with `exactName` and `matchingUri` modifying `name` and `uri` rather than
// filtering on their own. F129 said eight. An unknown parameter is ignored.
//
// The filters and their measured comparisons, each probed on its own:
//
//	name       case-insensitive substring; ?exactName=true makes it exact,
//	           and ?exactName=true with no name does nothing at all
//	_id        exact
//	type       case-insensitive substring - `urn:tt` and `TT` both find `urn:TT`
//	scope      case-insensitive substring over the resource's scope names
//	owner      exact, against the client's clientId string **or** its UUID.
//	           Both work; neither folds case and neither is a substring, so
//	           this is the one filter on the family that is not a substring of
//	           something.
//	uri        exact against one of the resource's uris
//
// The row order is **sorted by name** and `GET .../settings` serves the same
// rows in creation order - the scope family's two-orders rule on a second
// family. Either bound alone pages, and a bound that does not parse is
// authzIntBound's 404.
func (h *handler) listAuthzResources(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	q := r.URL.Query()
	first, ok := authzIntBound(w, q, "first")
	if !ok {
		return
	}
	max, ok := authzIntBound(w, q, "max")
	if !ok {
		return
	}
	resources, scopes, err := h.authzResourcesAndScopes(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	kept := []*model.AuthzResource{}
	for _, res := range resources {
		if authzResourceMatches(res, scopes, a, q) {
			kept = append(kept, res)
		}
	}
	kept = filterByMatchingURI(kept, q)
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Name < kept[j].Name })
	if first >= 0 {
		if first >= len(kept) {
			kept = nil
		} else {
			kept = kept[first:]
		}
	}
	if max >= 0 && max < len(kept) {
		kept = kept[:max]
	}

	// **`deep=false` drops two keys, not one**: `attributes` and `scopes`. The
	// default is true, and any value that is not the literal `false` is true -
	// `?deep=abc` returned the deep shape.
	view := authzResourceFull
	if q.Get("deep") == "false" {
		view = authzResourceShallow
	}
	out := make([]authzResourceRepresentation, 0, len(kept))
	for _, res := range kept {
		out = append(out, authzResourceRepresentationOf(res, a.client.ID, a.client.ClientID, scopes, view))
	}
	writeAdminJSON(w, out)
}

// authzResourceMatches applies the six filters that compare one resource at a
// time. `matchingUri` is not among them because it is a comparison **across**
// the set - see filterByMatchingURI.
func authzResourceMatches(res *model.AuthzResource, scopes map[string]*model.AuthzScope,
	a *authzContext, q map[string][]string) bool {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if id := get("_id"); id != "" && res.ID != id {
		return false
	}
	if name := get("name"); name != "" {
		if get("exactName") == "true" {
			if res.Name != name {
				return false
			}
		} else if !containsFold(res.Name, name) {
			return false
		}
	}
	if t := get("type"); t != "" && !containsFold(res.Type, t) {
		return false
	}
	if owner := get("owner"); owner != "" && owner != a.client.ID && owner != a.client.ClientID {
		return false
	}
	if want := get("scope"); want != "" {
		found := false
		for _, id := range res.ScopeIDs {
			if s, ok := scopes[id]; ok && containsFold(s.Name, want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Without matchingUri the comparison is plain equality against one of the
	// resource's uris: `?uri=/one` found nothing on a resource registering
	// `/one/two`, and neither did `?uri=/one/two/three`.
	if uri := get("uri"); uri != "" && get("matchingUri") != "true" {
		found := false
		for _, u := range res.URIs {
			if u == uri {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// filterByMatchingURI applies `?uri=` under `?matchingUri=true`, which is a
// **best** match rather than a filter: only the resources whose most specific
// matching uri is the most specific in the whole set survive.
//
// Measured on two resources, `/deep/*` and `/deep/a/b`:
//
//	?uri=/deep/a/b/c&matchingUri=true   the wildcard one
//	?uri=/deep/a/b&matchingUri=true     the exact one, which beats the wildcard
//	?uri=/deep/x&matchingUri=true       the wildcard one
//	?uri=/one/two/three&matchingUri=true  nothing, because `/one/two` is not a
//	                                      pattern and does not match
//
// `matchingUri=true` with no `uri` at all does nothing, measured, which is why
// this returns the set untouched rather than emptying it.
func filterByMatchingURI(in []*model.AuthzResource, q map[string][]string) []*model.AuthzResource {
	uri, matching := "", false
	if v := q["uri"]; len(v) > 0 {
		uri = v[0]
	}
	if v := q["matchingUri"]; len(v) > 0 {
		matching = v[0] == "true"
	}
	if uri == "" || !matching {
		return in
	}
	best := -1
	scores := make([]int, len(in))
	for i, res := range in {
		scores[i] = -1
		for _, pattern := range res.URIs {
			if s := matchingURIScore(pattern, uri); s > scores[i] {
				scores[i] = s
			}
		}
		if scores[i] > best {
			best = scores[i]
		}
	}
	if best < 0 {
		return nil
	}
	out := []*model.AuthzResource{}
	for i, res := range in {
		if scores[i] == best {
			out = append(out, res)
		}
	}
	return out
}

// matchingURIScore says how specifically pattern matches requested, or -1 when
// it does not. An exact match scores one more than its own length so that it
// beats a wildcard covering the same prefix, which is the pair the measurement
// pins: `/deep/a/b` won `/deep/a/b` from `/deep/*` and lost `/deep/a/b/c` to it.
func matchingURIScore(pattern, requested string) int {
	if pattern == requested {
		return len(pattern) + 1
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(requested, prefix) {
		return len(prefix)
	}
	return -1
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// searchAuthzResource serves GET .../authz/resource-server/resource/search.
//
// The scope family's search shape exactly, re-measured here rather than
// inherited: three answers and none of them is an array.
//
//	?name=withdn  matching     200 with a bare object
//	?name=WITHDN  not matching 204, empty body - the match is **case-sensitive**
//	?name= or absent           400, empty body
//
// All three carry `Cache-Control: no-cache`, and `deep` is ignored here: the
// search answered the full shape under `?deep=false`.
func (h *handler) searchAuthzResource(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Cache-Control", "no-cache")
	if name == "" {
		writeEmptyStatus(w, r, http.StatusBadRequest)
		return
	}
	res, err := h.store.Authz().ResourceByName(r.Context(), a.client.ID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeEmptyStatus(w, r, http.StatusNoContent)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeAuthzResource(w, r, a, res)
}

// readAuthzResource serves GET .../authz/resource-server/resource/{resource-id}.
//
// **`deep` is ignored here**, measured: `?deep=false` on this route still
// carried `attributes`. It is the listing's parameter alone.
func (h *handler) readAuthzResource(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	res, ok := h.authzResourceFromPath(w, r, a, func() { writeAuthzResourceNotFound(w) })
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	h.writeAuthzResource(w, r, a, res)
}

func (h *handler) writeAuthzResource(w http.ResponseWriter, r *http.Request, a *authzContext,
	res *model.AuthzResource) {
	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK,
		authzResourceRepresentationOf(res, a.client.ID, a.client.ClientID, scopes, authzResourceFull))
}

// readAuthzResourceAttributes serves .../resource/{resource-id}/attributes: the
// attribute map on its own, in the same order the representation puts it in.
func (h *handler) readAuthzResourceAttributes(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	w.Header().Set("Cache-Control", "no-cache")
	res, ok := h.authzResourceFromPath(w, r, a, func() { writeEmptyStatus(w, r, http.StatusNotFound) })
	if !ok {
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, orderAuthzResourceAttributes(res.Attributes))
}

// listAuthzResourceScopes serves .../resource/{resource-id}/scopes, whose entry
// is `{id, name}` - the inline shape minus its iconUri. See authzInlineScope.
func (h *handler) listAuthzResourceScopes(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	w.Header().Set("Cache-Control", "no-cache")
	res, ok := h.authzResourceFromPath(w, r, a, func() { writeEmptyStatus(w, r, http.StatusNotFound) })
	if !ok {
		return
	}
	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	out := []authzInlineScope{}
	for _, s := range inlineScopesOf(res, scopes, authzResourceFull) {
		out = append(out, authzInlineScope{ID: s.ID, Name: s.Name})
	}
	writeAdminJSON(w, out)
}

// listAuthzResourcePermissions serves .../resource/{resource-id}/permissions.
//
// **The `[]` is the measured answer and not a stub, for exactly as long as
// Gloak has no permissions.** On a live server it lists every permission naming
// the resource **and** every scope permission naming a scope the resource
// carries, which is a computation over a family this cut does not build. There
// is no route that creates a permission, so the empty array is a fact about the
// store. The half of this route that is real behaviour today is its 404, which
// is the empty-bodied one its two neighbours answer and not the JSON one the
// read one segment above answers.
func (h *handler) listAuthzResourcePermissions(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	w.Header().Set("Cache-Control", "no-cache")
	if _, ok := h.authzResourceFromPath(w, r, a, func() { writeEmptyStatus(w, r, http.StatusNotFound) }); !ok {
		return
	}
	writeAdminJSON(w, []struct{}{})
}

// createAuthzResource serves POST .../authz/resource-server/resource.
//
// 201, `Cache-Control: no-cache`, the charset and **no Location**. The body is
// a read of what was written rather than the request echoed - which is the
// opposite of the scope create beside it, and is measured: a create carrying
// `scopes:[{"name":"s1"}]` comes back with that scope's minted id in it.
//
// **`_id` is the upsert key and the name is not.** Two creates naming the same
// `_id` left one row holding the second body, where two creates naming the same
// **name** are the 409. That is the inverse of the scope family, where the name
// upserts.
//
// Four refusals, in the order they were measured to run:
//
//	{"zzz":1}                    the strict 400, ahead of everything below
//	empty body or `null`         400 with an **empty body** - the scope family
//	                             answers the same bytes with a 500
//	{} or {"name":null}          409 {"error":"conflict",
//	                                  "error_description":"Duplicate resource error"}
//	{"name":<taken>}             409 {"error":"invalid_request",
//	                                  "error_description":"Resource with name [x] already exists."}
//
// **All three 409s carry the five security headers**, where the PUT's 409 one
// path segment away carries none - the same split the scope family has, and the
// second family to have it.
//
// `{"name":<taken>}` together with an `_id` another resource server holds
// answers about the **name**, so the name check runs first.
func (h *handler) createAuthzResource(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	body, ok := h.decodeAuthzResourceBody(w, r)
	if !ok {
		return
	}
	if body.Name == nil {
		writeAuthzScopeConflict(w)
		return
	}
	if _, err := h.store.Authz().ResourceByName(r.Context(), a.client.ID, *body.Name); err == nil {
		writeAuthzResourceNameTaken(w, *body.Name)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	scopeIDs, ok := h.resolveAuthzScopeRefs(w, r, a, body.scopeRefs())
	if !ok {
		return
	}
	stored := &model.AuthzResource{
		ID:                 body.ID,
		ClientID:           a.client.ID,
		Name:               *body.Name,
		DisplayName:        body.DisplayName,
		Type:               body.Type,
		IconURI:            body.IconURI,
		OwnerManagedAccess: body.OwnerManagedAccess,
		URIs:               body.uris(),
		ScopeIDs:           scopeIDs,
	}
	if body.Attributes != nil {
		stored.Attributes = *body.Attributes
	}

	// The upsert. An `_id` this resource server already holds is a replace; one
	// another resource server holds falls through to the insert and meets the
	// global primary key, which is the measured 409.
	write := h.store.Authz().CreateResource
	if stored.ID == "" {
		stored.ID = model.NewID()
	} else if _, err := h.store.Authz().ResourceByID(r.Context(), a.client.ID, stored.ID); err == nil {
		write = h.store.Authz().UpdateResource
	} else if !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := write(r.Context(), stored); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAuthzScopeConflict(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusCreated,
		authzResourceRepresentationOf(stored, a.client.ID, a.client.ClientID, scopes, authzResourceFull))
}

// updateAuthzResource serves PUT .../authz/resource-server/resource/{resource-id}.
//
// 204, no `Cache-Control`, no body. **It replaces every field except
// `attributes`**, which is the one field where absent means unchanged: a PUT
// carrying only a name against a resource holding a type, a displayName, an
// icon_uri, two uris and a scope left the attributes exactly as they were and
// cleared all five of the others. `{"attributes":{}}` does clear them, so the
// exception is about absence and not about the field.
//
// That is AGENTS.md's "PUT replaces / PUT merges - except for one field" a
// third time, and it points the other way: this verb replaces, and one field
// merges.
//
// Four refusals, and three of them disagree with the create one path segment up:
//
//	{"zzz":1} to an id that does not exist   the strict 400, so the decode is
//	                                         ahead of the path
//	{} to an id that does not exist          the JSON 404, so the path is ahead
//	                                         of the name check
//	{}, {"name":null}, empty body, `null`    500 unknown_error, where the create
//	                                         answers 409 for the first two and a
//	                                         400 with an empty body for the last
//	                                         two
//	{"name":<taken>}                         409 `Duplicate resource error`,
//	                                         where the create answers
//	                                         `Resource with name [x] already
//	                                         exists.` - **and this 409 carries
//	                                         none of the five security headers**
//
// The body's `_id` is read and discarded; the path decides which row moves.
func (h *handler) updateAuthzResource(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	var body authzResourceBody
	if !h.readAuthzResourceJSON(w, r, &body) {
		return
	}
	current, ok := h.authzResourceFromPath(w, r, a, func() { writeAuthzResourceNotFound(w) })
	if !ok {
		return
	}
	if body.Name == nil {
		writeAuthzScopeUnknownError(w)
		return
	}
	if !authzOwnerAbsent(body.Owner) {
		writeAuthzScopeUnknownError(w)
		return
	}
	scopeIDs, ok := h.resolveAuthzScopeRefs(w, r, a, body.scopeRefs())
	if !ok {
		return
	}
	updated := &model.AuthzResource{
		ID:                 current.ID,
		ClientID:           a.client.ID,
		Name:               *body.Name,
		DisplayName:        body.DisplayName,
		Type:               body.Type,
		IconURI:            body.IconURI,
		OwnerManagedAccess: body.OwnerManagedAccess,
		URIs:               body.uris(),
		ScopeIDs:           scopeIDs,
		Ordinal:            current.Ordinal,
	}
	// The one field a replace does not replace.
	if body.Attributes != nil {
		updated.Attributes = *body.Attributes
	} else {
		updated.Attributes = current.Attributes
	}
	if err := h.store.Authz().UpdateResource(r.Context(), updated); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// writeDuplicateResource rather than writeAuthzScopeConflict: this
			// 409 drops the five security headers and the create's keeps them,
			// measured on both with identical request Content-Types.
			writeDuplicateResource(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteAuthzResource serves DELETE .../resource/{resource-id}: 204 with **no
// Cache-Control**, a ninth measured delete, and the JSON 404 the read answers
// rather than the empty one the scope family's delete answers.
func (h *handler) deleteAuthzResource(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	err := h.store.Authz().DeleteResource(r.Context(), a.client.ID, r.PathValue("resourceID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAuthzResourceNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// authzResourceFromPath resolves the {resource-id} segment, writing the 404 its
// caller asks for.
//
// **The 404 is a per-route argument because the family has two of them.** The
// read, the update and the delete answer the generic JSON body with no
// Cache-Control; `/attributes`, `/permissions` and `/scopes` - one path segment
// below - answer an empty body **with** Cache-Control, which is the scope
// family's shape. Measured on all six. A helper that picked one would be wrong
// on three routes, and picking by the path's suffix would put the rule in the
// wrong place.
func (h *handler) authzResourceFromPath(w http.ResponseWriter, r *http.Request, a *authzContext,
	notFound func()) (*model.AuthzResource, bool) {
	res, err := h.store.Authz().ResourceByID(r.Context(), a.client.ID, r.PathValue("resourceID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound()
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return res, true
}

// authzResourcesAndScopes reads both collections at once, because every view of
// a resource needs the scopes to turn its ids into names.
func (h *handler) authzResourcesAndScopes(r *http.Request, a *authzContext) ([]*model.AuthzResource,
	map[string]*model.AuthzScope, error) {
	resources, err := h.store.Authz().ListResources(r.Context(), a.client.ID)
	if err != nil {
		return nil, nil, err
	}
	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		return nil, nil, err
	}
	return resources, scopes, nil
}

func (h *handler) authzScopesByID(r *http.Request, a *authzContext) (map[string]*model.AuthzScope, error) {
	list, err := h.store.Authz().ListScopes(r.Context(), a.client.ID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*model.AuthzScope, len(list))
	for _, s := range list {
		out[s.ID] = s
	}
	return out, nil
}

// resolveAuthzScopeRefs turns a body's `scopes` entries into stored scope ids,
// creating a scope for any entry naming one that does not exist.
//
// **The id is resolved first and alone.** An entry carrying a real id and a
// name naming something else resolved to the id's scope, and an entry carrying
// an id nobody holds is the 409 rather than a fall-through to the name.
func (h *handler) resolveAuthzScopeRefs(w http.ResponseWriter, r *http.Request, a *authzContext,
	refs []authzScopeRef) ([]string, bool) {
	out := []string{}
	seen := map[string]bool{}
	for _, ref := range refs {
		var s *model.AuthzScope
		var err error
		switch {
		case ref.ID != "":
			s, err = h.store.Authz().ScopeByID(r.Context(), a.client.ID, ref.ID)
			if errors.Is(err, store.ErrNotFound) {
				writeAuthzScopeConflict(w)
				return nil, false
			}
		case ref.Name != "":
			s, err = h.store.Authz().ScopeByName(r.Context(), a.client.ID, ref.Name)
			if errors.Is(err, store.ErrNotFound) {
				s = &model.AuthzScope{ID: model.NewID(), ClientID: a.client.ID, Name: ref.Name}
				err = h.store.Authz().CreateScope(r.Context(), s)
			}
		default:
			continue
		}
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return nil, false
		}
		if seen[s.ID] {
			continue
		}
		seen[s.ID] = true
		out = append(out, s.ID)
	}
	return out, true
}

// decodeAuthzResourceBody decodes the create's body and refuses an owner.
//
// **An empty body and a literal `null` are a 400 with an empty body here**,
// where the scope create answers the same bytes with a 500. Two writes on one
// resource server, opposite answers to nothing at all, and the check has to run
// before the strict decode either way.
func (h *handler) decodeAuthzResourceBody(w http.ResponseWriter, r *http.Request) (authzResourceBody, bool) {
	var body authzResourceBody
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
		w.Header().Set("Cache-Control", "no-cache")
		writeEmptyStatus(w, r, http.StatusBadRequest)
		return body, false
	}
	r.Body = io.NopCloser(strings.NewReader(string(raw)))
	if !decodeStrict(w, r, "ResourceRepresentation", &body) {
		return body, false
	}
	// **Any owner is a 500**, including an object of the right shape; `null`
	// counts as absent. The owner is the resource server's client and nothing
	// on the wire can move it.
	if !authzOwnerAbsent(body.Owner) {
		writeAuthzScopeUnknownError(w)
		return body, false
	}
	return body, true
}

// readAuthzResourceJSON is the update's decode. It differs from the create's in
// exactly one place and that place is measured: an empty body is the 500 here
// and the 400 there.
func (h *handler) readAuthzResourceJSON(w http.ResponseWriter, r *http.Request, body *authzResourceBody) bool {
	if !requireJSONBody(w, r) {
		return false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		writeAuthzScopeUnknownError(w)
		return false
	}
	r.Body = io.NopCloser(strings.NewReader(string(raw)))
	return decodeStrict(w, r, "ResourceRepresentation", body)
}

// authzOwnerAbsent reports whether the body named no owner. An explicit `null`
// counts as absent, measured: `{"name":"x","owner":null}` is a 201.
func authzOwnerAbsent(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed == "" || trimmed == "null"
}

// writeAuthzResourceNameTaken is the create's duplicate-name 409, and it is the
// **only** refusal in this whole family that names the thing it refused.
//
//	409 {"error":"invalid_request",
//	     "error_description":"Resource with name [r1] already exists."}
//
// It carries the five security headers, and the PUT's 409 for the same
// condition is `Duplicate resource error` and carries none. One condition, two
// verbs, two bodies and two header sets.
func writeAuthzResourceNameTaken(w http.ResponseWriter, name string) {
	httpx.WriteOAuthError(w, http.StatusConflict, "invalid_request",
		"Resource with name ["+name+"] already exists.")
}

// writeAuthzResourceNotFound is the 404 for a resource that does not exist on
// the read, the update and the delete.
//
// **It is the generic `{"error":"HTTP 404 Not Found"}` with a plain
// `application/json` and no `Cache-Control`** - a fifth producer of that body,
// after an unmatched path, a wrong verb, a switched-off resource and an
// unparseable integer bound, and the first that is an ordinary missing row.
// The scope family answers the same condition with an empty body and a
// `Cache-Control`, so the two families invert each other on both halves.
func writeAuthzResourceNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
}
