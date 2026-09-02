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

// The policy and permission families of authorization services, and `import`:
// the last nine of the description's thirty-one untagged operations, measured
// 2026-09-02 against a live 26.7.1.
//
// **A permission is a policy.** `GET .../policy?permission=true` and
// `GET .../permission` returned the same rows one key apart, so there is one
// table, one create and one search behind six of the nine routes; the path
// decides the view and the filter, not the storage.
//
// **The typed view is a projection of one stored `config` map.** One config
// carrying every provider's keys at once was sent to all nine types: the
// generic view came back byte-identical on all nine and the typed view served
// exactly the keys the type owns. So there are eight distinct field sets over
// the nine types - `resource` and `scope` share one - and they are produced by
// authzTypedFields below rather than by eight structs.
//
// The role sets are the family's, swept on all nine routes one single role at a
// time over seven callers: the four reads **and both `evaluate`s** take
// authzReadRoles, and the two creates and `import` take authzWriteRoles.

// authzPolicyTypes is the set `POST .../policy` and `POST .../permission`
// accept, and **it is not `GET .../policy/providers`' catalogue**.
//
// `uma` is accepted here and is absent from that catalogue; `user` and
// `client-scope` are in it and answer a 500. Validating against policyProviders
// would refuse one working type and admit two that fail, which is why this is a
// second list rather than a reuse of the first.
//
// The comparison is case-sensitive: `{"type":"ROLE"}` is the unknown-type 500,
// where the two listings' `?type=` filter folds case. One spelling of one word,
// two rules, one path segment apart.
var authzPolicyTypes = []string{
	"regex", "role", "resource", "scope", "client", "time", "group", "aggregate", "uma",
}

// authzPermissionTypes is what `GET .../permission` keeps and what
// `?permission=true` selects on the listing beside it.
//
// **It is not the settings export's partition**, which moves `resource` and
// `scope` to the end and leaves `uma` among the policies. Two notions of
// "permission" in one API, one path segment apart, and a shared predicate is
// wrong in one of the two places - see authzExportedPolicies.
var authzPermissionTypes = []string{"resource", "scope", "uma"}

// The two enums the create binds, and neither list is the resource server's.
//
// **CONSENSUS is accepted here and is a 500 on `PUT .../authz/resource-server`**,
// measured on both on one container: `{"name":"d1","type":"role",
// "decisionStrategy":"CONSENSUS"}` is a 201 and reads back carrying it.
// authzDecisionStrategies next door deliberately excludes it, so the two lists
// stay apart.
//
// A value outside either is `500 {"error":"unknown_error",
// "error_description":"Cannot parse the JSON"}` - a parse failure for a body
// that parses, because Jackson refuses the token while binding the enum - and
// the comparison is case-sensitive: `"positive"` is that 500.
var (
	authzPolicyLogics            = []string{"POSITIVE", "NEGATIVE"}
	authzPolicyDecisionStrategies = []string{"AFFIRMATIVE", "UNANIMOUS", "CONSENSUS"}
)

// authzPolicyConfigMap is a policy's `config`: a Java map whose serialised key
// order is part of the contract.
//
// It is a slice for model.AuthzPolicy.Config's reason and it marshals in the
// order it is handed, so the caller decides the wire order - see
// authzOrderedConfig.
type authzPolicyConfigMap []model.AuthzPolicyConfig

// MarshalJSON writes the pairs as a JSON object in the order they are held. A
// nil value is `{}` rather than `null`: every measured policy carried a
// `config` key and a policy with nothing in it carried `{}`.
func (c authzPolicyConfigMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, entry := range c {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(entry.Name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(entry.Value)
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
// order they arrived in. Decoding into a Go map would lose it, and the wire
// order is computed from the stored order whenever javamap cannot decide it.
//
// Every value is a string, including the four that carry a collection:
// `config.roles` arrives and leaves as the **string**
// `"[{\"id\":\"...\",\"required\":false}]"`.
func (c *authzPolicyConfigMap) UnmarshalJSON(data []byte) error {
	if string(bytes.TrimSpace(data)) == "null" {
		*c = nil
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("admin: policy config: expected an object")
	}
	out := authzPolicyConfigMap{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("admin: policy config: expected a key")
		}
		var value string
		if err := dec.Decode(&value); err != nil {
			return err
		}
		out = append(out, model.AuthzPolicyConfig{Name: key, Value: value})
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	*c = out
	return nil
}

// authzOrderedConfig puts stored config entries into Keycloak's map order.
//
// **It is SizedKeyOrder and not KeyOrder**, which is measured rather than
// carried over from a neighbouring family: `{nbf, hour}` comes back
// `{hour, nbf}` and the twelve-key time set comes back with two pairs swapped,
// and KeyOrder is wrong on both. So this family takes the protocol mappers' and
// identity providers' constructor and not the components'.
//
// **Whether the size argument is the stored count or the request's is not
// pinned.** A role, client or group policy gains a key on the way in, so the
// two counts differ by one on every such row; a search over every key set of
// the shape `{roles, z1..zn}` for n up to 13 found none where the two sizes
// disagree, so no probe separates them and this uses the stored count.
func authzOrderedConfig(in []model.AuthzPolicyConfig) authzPolicyConfigMap {
	byName := make(map[string]string, len(in))
	names := make([]string, 0, len(in))
	for _, c := range in {
		byName[c.Name] = c.Value
		names = append(names, c.Name)
	}
	out := make(authzPolicyConfigMap, 0, len(in))
	for _, name := range javamap.SizedKeyOrder(len(names), names) {
		out = append(out, model.AuthzPolicyConfig{Name: name, Value: byName[name]})
	}
	return out
}

// authzPolicyRepresentation is a policy as `GET .../policy`,
// `GET .../policy/search` and the two `POST`s' own 201 all describe the generic
// view of it: the field order `id name description type logic decisionStrategy
// config`.
//
// **`logic` and `decisionStrategy` are omitted rather than defaulted when the
// create sent an explicit `null`.** `{"logic":null}` is a 201 and the row reads
// back with no `logic` key at all, on the listing, the search and the typed
// view alike - so absent-in-the-body and null-in-the-body are two different
// stored states and only the first gets POSITIVE.
type authzPolicyRepresentation struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Type             string               `json:"type"`
	Logic            string               `json:"logic,omitempty"`
	DecisionStrategy string               `json:"decisionStrategy,omitempty"`
	Config           authzPolicyConfigMap `json:"config"`
}

func authzPolicyRepresentationOf(p *model.AuthzPolicy) authzPolicyRepresentation {
	return authzPolicyRepresentation{
		ID:               p.ID,
		Name:             p.Name,
		Description:      p.Description,
		Type:             p.Type,
		Logic:            p.Logic,
		DecisionStrategy: p.DecisionStrategy,
		Config:           authzOrderedConfig(p.Config),
	}
}

// authzPolicyCreated is the create's 201, and it is **the request echoed** with
// the id filled in rather than a read of what was written.
//
// Three things say so. A `role` create's config comes back exactly as it was
// sent, where the read beside it has the role names resolved to uuids and
// `required` filled in. A create carrying `owner` or `resourceType` echoes
// both, and no read serves either. And a `role` create with no config at all
// answers `config:{}` where its own read answers `{"roles":"[]"}` - the
// provider's key is added after the response representation is built.
//
// The three association arrays are pointers because an **empty** one is echoed:
// `{"policies":[]}` came back `"policies":[]` where an absent one is dropped.
// Their values are the resolved ids, so the echo is not quite the request -
// a create naming `res1` echoes that resource's uuid.
type authzPolicyCreated struct {
	ID               string               `json:"id"`
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Type             string               `json:"type"`
	Policies         *[]string            `json:"policies,omitempty"`
	Resources        *[]string            `json:"resources,omitempty"`
	Scopes           *[]string            `json:"scopes,omitempty"`
	Logic            string               `json:"logic,omitempty"`
	DecisionStrategy string               `json:"decisionStrategy,omitempty"`
	Owner            string               `json:"owner,omitempty"`
	ResourceType     string               `json:"resourceType,omitempty"`
	Config           authzPolicyConfigMap `json:"config"`
}

// authzPolicyExport is one entry of `GET .../settings`' `policies` array:
// `{name, description?, type, logic?, decisionStrategy?, config}`, with the id
// and the owner dropped. It is the scopes' and resources' rule on a third
// collection - the export drops what identifies a row and keeps what describes
// it.
type authzPolicyExport struct {
	Name             string               `json:"name"`
	Description      string               `json:"description,omitempty"`
	Type             string               `json:"type"`
	Logic            string               `json:"logic,omitempty"`
	DecisionStrategy string               `json:"decisionStrategy,omitempty"`
	Config           authzPolicyConfigMap `json:"config"`
}

// authzTypedField is one row of the projection table: the config key it reads
// and the JSON field it becomes.
type authzTypedField struct {
	configKey string
	field     string
	kind      authzTypedKind
}

type authzTypedKind int

const (
	// authzTypedString emits the config value as a JSON string when the key is
	// present.
	authzTypedString authzTypedKind = iota
	// authzTypedJSON emits the config value **raw**, because the four
	// collection keys already hold JSON inside a string.
	authzTypedJSON
	// authzTypedBool emits `true`/`false` when the key is present.
	authzTypedBool
	// authzTypedBoolAlways emits it whether the key is there or not, defaulting
	// to false. Only `targetContextAttributes` is this: a `regex` policy with
	// `config:{}` still answers `"targetContextAttributes":false`, where a
	// `role` policy with `config:{}` answers no `roles` at all - and the reason
	// they differ is that the role provider *writes* its key on create and the
	// regex provider does not.
	authzTypedBoolAlways
)

// authzTypedFields is the projection of §0 of the plan: which config keys each
// type serves in the typed view, in the order they were measured coming back.
//
// Measured by sending **one** config carrying every provider's keys to all nine
// types at once and reading each row back. That probe is what says the table is
// per type rather than shared: a `role` policy carrying `defaultResourceType`
// serves it in the generic view and does **not** project it, so `resourceType`
// is not a base field on the read even though it is one in the create's echo.
//
// `resource` and `scope` are absent from this table because their one field,
// `resourceType`, sits at the base position ahead of the provider's own fields
// - see authzTypedPolicy. `aggregate` and `uma` project nothing at all; uma's
// `scopes` comes from the association set rather than from the config.
var authzTypedFields = map[string][]authzTypedField{
	"regex": {
		{"targetClaim", "targetClaim", authzTypedString},
		{"pattern", "pattern", authzTypedString},
		{"targetContextAttributes", "targetContextAttributes", authzTypedBoolAlways},
	},
	"role": {
		{"roles", "roles", authzTypedJSON},
		{"fetchRoles", "fetchRoles", authzTypedBool},
	},
	"client": {
		{"clients", "clients", authzTypedJSON},
	},
	"group": {
		{"groupsClaim", "groupsClaim", authzTypedString},
		{"groups", "groups", authzTypedJSON},
	},
	"time": {
		{"nbf", "notBefore", authzTypedString},
		{"noa", "notOnOrAfter", authzTypedString},
		{"dayMonth", "dayMonth", authzTypedString},
		{"dayMonthEnd", "dayMonthEnd", authzTypedString},
		{"month", "month", authzTypedString},
		{"monthEnd", "monthEnd", authzTypedString},
		{"year", "year", authzTypedString},
		{"yearEnd", "yearEnd", authzTypedString},
		{"hour", "hour", authzTypedString},
		{"hourEnd", "hourEnd", authzTypedString},
		{"minute", "minute", authzTypedString},
		{"minuteEnd", "minuteEnd", authzTypedString},
	},
}

// authzJSONField is one key of an ordered JSON object.
type authzJSONField struct {
	name  string
	value json.RawMessage
}

// authzOrderedObject marshals its fields in the order it holds them.
//
// It exists because the typed view's key order is not a struct's: the fields a
// type projects come last, `uma`'s `scopes` comes **between `type` and
// `logic`**, and `resourceType` comes after `decisionStrategy` for two types
// and never for the other seven. Eight field sets over nine types cannot be one
// Go struct, and eight structs would put the shared head in eight places.
type authzOrderedObject []authzJSONField

func (o authzOrderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(f.name)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(f.value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o authzOrderedObject) add(name string, value any) (authzOrderedObject, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return o, err
	}
	return append(o, authzJSONField{name: name, value: raw}), nil
}

// authzTypedPolicy builds the typed view of one policy, which is what
// `GET .../permission` and `GET .../permission/search` serve.
//
// The field order is Keycloak's AbstractPolicyRepresentation - `id name
// description type policies resources scopes logic decisionStrategy owner
// resourceType` - followed by the subclass's own fields, which is why `uma`'s
// `scopes` is ahead of `logic` and everything else is behind
// `decisionStrategy`.
//
// Of the base collections only `scopes` is ever filled, only for `uma`, and
// **by name**: a uma permission created naming a scope's id reads back naming
// the scope. `policies`, `resources` and `owner` are echoed by the create and
// served by no read at all.
func authzTypedPolicy(p *model.AuthzPolicy, scopes map[string]*model.AuthzScope) (authzOrderedObject, error) {
	var out authzOrderedObject
	var err error
	add := func(name string, value any) {
		if err == nil {
			out, err = out.add(name, value)
		}
	}
	add("id", p.ID)
	add("name", p.Name)
	if p.Description != "" {
		add("description", p.Description)
	}
	add("type", p.Type)
	if p.Type == "uma" {
		names := []string{}
		for _, id := range p.Scopes {
			if s, ok := scopes[id]; ok {
				names = append(names, s.Name)
			}
		}
		add("scopes", names)
	}
	if p.Logic != "" {
		add("logic", p.Logic)
	}
	if p.DecisionStrategy != "" {
		add("decisionStrategy", p.DecisionStrategy)
	}
	if p.Type == "resource" || p.Type == "scope" {
		if v, ok := p.ConfigValue("defaultResourceType"); ok {
			add("resourceType", v)
		}
	}
	for _, f := range authzTypedFields[p.Type] {
		v, ok := p.ConfigValue(f.configKey)
		switch f.kind {
		case authzTypedBoolAlways:
			out = append(out, authzJSONField{name: f.field, value: authzRawBool(v)})
		case authzTypedBool:
			if ok {
				out = append(out, authzJSONField{name: f.field, value: authzRawBool(v)})
			}
		case authzTypedJSON:
			if ok {
				out = append(out, authzJSONField{name: f.field, value: json.RawMessage(v)})
			}
		default:
			if ok {
				add(f.field, v)
			}
		}
	}
	return out, err
}

func authzRawBool(v string) json.RawMessage {
	if v == "true" {
		return json.RawMessage("true")
	}
	return json.RawMessage("false")
}

// listAuthzPolicies serves `GET .../policy` and `GET .../permission`, which are
// one listing with two views and one filter between them.
//
// **Ten of the description's eleven query parameters are read**, counted from
// its own list rather than incremented: `fields`, `first`, `max`, `name`,
// `owner`, `permission`, `policyId`, `resource`, `resourceType`, `scope` and
// `type`, with `fields` declared and ignored. Their comparisons, each probed on
// its own, and no two are the same rule:
//
//	name          case-insensitive substring
//	type          case-insensitive **substring** - `?type=gg` finds `aggregate`
//	              and `?type=e` finds seven of the nine types. The create's own
//	              `type` is case-sensitive and exact, one field apart.
//	policyId      exact
//	resource      exact, against a resource's **name or its id** - both work
//	scope         exact, against a scope's **name or its id** - both work
//	resourceType  exact and case-**sensitive**: `urn:X` finds nothing where
//	              `urn:x` finds the row. The one filter here that folds no case.
//	owner         exact against the stored owner, which no create can set to
//	              anything a read serves
//	permission    Boolean.parseBoolean - `true` keeps authzPermissionTypes and
//	              anything else keeps the other six. On the `/permission` path
//	              it is ignored, because the route pins it.
//
// Sorted **by name, byte-wise**: `Zebra, aaa, f147-a` came back in that order.
// Either bound alone pages and a negative bound means no bound.
func (h *handler) listAuthzPolicies(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	q := r.URL.Query()
	first, ok := authzIntBound(w, q, "first")
	if !ok {
		return
	}
	max, ok := authzIntBound(w, q, "max")
	if !ok {
		return
	}
	policies, err := h.store.Authz().ListPolicies(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	resources, err := h.store.Authz().ListResources(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	typed := authzTypedRoute(r)
	wantPermission := typed || q.Get("permission") == "true"
	kept := []*model.AuthzPolicy{}
	for _, p := range policies {
		if containsString(authzPermissionTypes, p.Type) != wantPermission {
			continue
		}
		if authzPolicyMatches(p, q, scopes, resources) {
			kept = append(kept, p)
		}
	}
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

	if typed {
		out := make([]authzOrderedObject, 0, len(kept))
		for _, p := range kept {
			body, err := authzTypedPolicy(p, scopes)
			if err != nil {
				httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
				return
			}
			out = append(out, body)
		}
		writeAdminJSON(w, out)
		return
	}
	out := make([]authzPolicyRepresentation, 0, len(kept))
	for _, p := range kept {
		out = append(out, authzPolicyRepresentationOf(p))
	}
	writeAdminJSON(w, out)
}

// authzTypedRoute reports whether the request arrived on the `/permission`
// spelling, which is the only thing that decides the serialisation.
//
// The path is read rather than the route registered twice with a flag, because
// the same predicate has to answer for the listing and for the search and the
// two are registered in different places.
func authzTypedRoute(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/authz/resource-server/permission")
}

// authzPolicyMatches applies the eight filters that compare one policy at a
// time. `permission` is not among them because it partitions the set rather
// than filtering it, and the route can pin it.
func authzPolicyMatches(p *model.AuthzPolicy, q map[string][]string,
	scopes map[string]*model.AuthzScope, resources []*model.AuthzResource) bool {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if name := get("name"); name != "" && !containsFold(p.Name, name) {
		return false
	}
	if t := get("type"); t != "" && !containsFold(p.Type, t) {
		return false
	}
	if id := get("policyId"); id != "" && p.ID != id {
		return false
	}
	if owner := get("owner"); owner != "" && p.Owner != owner {
		return false
	}
	// resourceType is the only filter on this listing that does not fold case,
	// measured with `urn:x` and `urn:X` against one row.
	if want := get("resourceType"); want != "" {
		if v, ok := p.ConfigValue("defaultResourceType"); !ok || v != want {
			return false
		}
	}
	if want := get("resource"); want != "" {
		found := false
		for _, id := range p.Resources {
			if id == want {
				found = true
				break
			}
			for _, res := range resources {
				if res.ID == id && res.Name == want {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	if want := get("scope"); want != "" {
		found := false
		for _, id := range p.Scopes {
			if id == want {
				found = true
				break
			}
			if s, ok := scopes[id]; ok && s.Name == want {
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

// searchAuthzPolicy serves `GET .../policy/search` and
// `GET .../permission/search`.
//
// The scope and resource searches' shape exactly, re-measured on this family
// rather than inherited: three answers and none of them is an array.
//
//	?name=seed  matching     200 with a bare object
//	?name=SEED  not matching 204, empty body - the match is **case-sensitive**
//	?name=see   not matching 204 - and exact, not a prefix
//	?name= or absent         400, empty body
//
// All four carry `Cache-Control: no-cache`.
//
// **Neither spelling is filtered by family.** `permission/search` naming a
// `role` policy found it and served it in the typed shape, which makes this the
// only operation in the description that shows the typed representation of the
// six types `GET .../permission` hides.
func (h *handler) searchAuthzPolicy(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Cache-Control", "no-cache")
	if name == "" {
		writeEmptyStatus(w, r, http.StatusBadRequest)
		return
	}
	p, err := h.store.Authz().PolicyByName(r.Context(), a.client.ID, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeEmptyStatus(w, r, http.StatusNoContent)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !authzTypedRoute(r) {
		httpx.WriteJSONCharset(w, http.StatusOK, authzPolicyRepresentationOf(p))
		return
	}
	scopes, err := h.authzScopesByID(r, a)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	body, err := authzTypedPolicy(p, scopes)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, body)
}

// authzPolicyBody is what `POST .../policy` and `POST .../permission` decode.
//
// **Twelve fields, and the strict decoder is what says which twelve.** Probed
// one field at a time: `id`, `name`, `description`, `type`, `policies`,
// `resources`, `scopes`, `logic`, `decisionStrategy`, `owner`, `resourceType`
// and `config` are accepted; every typed field - `roles`, `clients`, `groups`,
// `users`, `clientScopes`, `targetClaim`, `pattern`, `notBefore`, `code`,
// `condition`, `fetchRoles`, `groupsClaim` - answers the 500. So the documented
// create binds Keycloak's PolicyRepresentation, whose only free-form field is
// `config`, and the undocumented `POST .../policy/{type}` routes are where the
// typed fields go.
//
// Four fields are pointers and each has to tell absent from a value:
//
//   - `id`: `{"id":""}` is a **201** creating a policy whose id is the empty
//     string, so absent is the only case that mints one;
//   - `name` and `type`: absent and `null` are the 409 and `{"name":""}` is a
//     201, so empty is a value;
//   - `logic` and `decisionStrategy`: absent gets the default and an explicit
//     `null` stores nothing, and the row then reads back with the key missing.
type authzPolicyBody struct {
	ID               *string               `json:"id"`
	Name             *string               `json:"name"`
	Description      string                `json:"description"`
	Type             *string               `json:"type"`
	Policies         *[]string             `json:"policies"`
	Resources        *[]string             `json:"resources"`
	Scopes           *[]string             `json:"scopes"`
	Logic            *string               `json:"logic"`
	DecisionStrategy *string               `json:"decisionStrategy"`
	Owner            string                `json:"owner"`
	ResourceType     string                `json:"resourceType"`
	Config           *authzPolicyConfigMap `json:"config"`
}

// createAuthzPolicy serves `POST .../policy` and `POST .../permission`, which
// are one handler.
//
// They were measured identical on eight bodies - the 201, all four bad-body
// 500s, the unknown field, the duplicate name and the missing name - and
// **neither restricts the type**: `POST .../permission` with `type: role` is a
// 201 and the row then appears on `GET .../policy` and not on
// `GET .../permission`. Only the listing filters.
//
// 201, `Cache-Control: no-cache`, the charset and **no Location**.
//
// The refusals, in the order they were measured to run. Each adjacency was
// pinned by a body wrong in two ways at once:
//
//	1  an unknown field, or a `logic`/`decisionStrategy` outside its enum
//	       500 unknown_error / "Cannot parse the JSON"
//	2  a taken name
//	       409 {"error":"Policy with name [x] already exists",
//	            "error_description":"Conflicting policy"}
//	3  a `resources` or `policies` entry naming nothing
//	       500 consult-log
//	4  a `scopes` entry naming nothing
//	       400 {"error":"unknown_error"} - **no error_description at all**
//	5  an absent or null `name` **or** an absent or null `type`
//	       409 conflict / "Duplicate resource error"
//	6  a `type` outside the nine
//	       500 consult-log
//	7  an `id` any resource server already holds
//	       409 conflict / "Duplicate resource error"
//
// Two of those orderings are the surprises. **The name check is ahead of
// everything about the body's contents** - `{"name":"taken","type":"nope"}`
// answers about the name - and **the association resolution is ahead of the
// presence check and ahead of the type check**: `{"type":"nope",
// "scopes":["nope"]}` answers about the scope and so does a body with no name
// at all.
//
// §1.9 of the third cut's handover and AGENTS.md both say `type` is the gate.
// It is one of two: `{"type":"role"}` with no name is the same 409.
func (h *handler) createAuthzPolicy(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	body, ok := h.decodeAuthzPolicyBody(w, r)
	if !ok {
		return
	}

	// 2. The taken name, ahead of everything the body says about itself.
	if body.Name != nil {
		if _, err := h.store.Authz().PolicyByName(r.Context(), a.client.ID, *body.Name); err == nil {
			writeAuthzPolicyNameTaken(w, *body.Name)
			return
		} else if !errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}

	// 3 and 4. The association sets, resources before scopes.
	stored := &model.AuthzPolicy{ClientID: a.client.ID}
	if body.Policies != nil {
		ids, ok := h.resolveAuthzPolicyRefs(w, r, a, *body.Policies)
		if !ok {
			return
		}
		stored.AssociatedPolicies = ids
	}
	if body.Resources != nil {
		ids, ok := h.resolveAuthzResourceRefs(w, r, a, *body.Resources)
		if !ok {
			return
		}
		stored.Resources = ids
	}
	if body.Scopes != nil {
		ids, ok := h.resolveAuthzScopeNames(w, r, a, *body.Scopes)
		if !ok {
			return
		}
		stored.Scopes = ids
	}

	// 5. A policy needs a name **and** a type.
	if body.Name == nil || body.Type == nil {
		writeAuthzScopeConflict(w)
		return
	}
	// 6. And the type has to be one of the nine, compared case-sensitively.
	if !containsString(authzPolicyTypes, *body.Type) {
		writeAuthzScopeUnknownError(w)
		return
	}

	stored.ID = model.NewID()
	if body.ID != nil {
		stored.ID = *body.ID
	}
	stored.Name = *body.Name
	stored.Description = body.Description
	stored.Type = *body.Type
	stored.Owner = body.Owner
	stored.Logic = model.DefaultAuthzPolicyLogic
	if body.Logic != nil {
		stored.Logic = *body.Logic
	}
	stored.DecisionStrategy = model.DefaultAuthzPolicyDecisionStrategy
	if body.DecisionStrategy != nil {
		stored.DecisionStrategy = *body.DecisionStrategy
	}
	if body.Config != nil {
		stored.Config = *body.Config
	}
	// The request's config is normalised on the way in and the provider's own
	// key is added; the echo below deliberately shows neither.
	if !h.normaliseAuthzPolicyConfig(w, r, rc, a, stored) {
		return
	}

	// 7. The id, which is global and does not upsert - unlike `POST
	// .../resource`, where a repeat of the server's own `_id` replaces the row.
	if err := h.store.Authz().CreatePolicy(r.Context(), stored); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAuthzScopeConflict(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	echo := authzPolicyCreated{
		ID:               stored.ID,
		Name:             stored.Name,
		Description:      stored.Description,
		Type:             stored.Type,
		Logic:            stored.Logic,
		DecisionStrategy: stored.DecisionStrategy,
		Owner:            stored.Owner,
		ResourceType:     body.ResourceType,
	}
	if body.Policies != nil {
		echo.Policies = &stored.AssociatedPolicies
	}
	if body.Resources != nil {
		echo.Resources = &stored.Resources
	}
	if body.Scopes != nil {
		echo.Scopes = &stored.Scopes
	}
	if body.Config != nil {
		echo.Config = authzOrderedConfig(*body.Config)
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusCreated, echo)
}

// decodeAuthzPolicyBody reads the create's body and answers the four measured
// 500s for a body that cannot be used.
//
// **There are four bodies and three answers, and the split is not the one
// writeCannotParseJSON makes.** Measured on eight inputs:
//
//	`null`                       500 unknown_error / consult-log
//	`{`                          500 invalid_request / "Cannot parse the JSON"
//	empty, ` `, `[`, `[]`, `"x"`,
//	`5`, `true`                  500 unknown_error / "Cannot parse the JSON"
//
// So a body that begins with `{` is invalid_request and everything else is
// unknown_error, which is the **inverse** of the predicate the required-action
// and organization writes use - there `[` alone is unknown_error. AGENTS.md
// says the code follows the body's shape rather than the endpoint; two shapes
// agree and the rest do not, so the predicate is written out here rather than
// shared.
//
// The status is 500 on every one of them, where the endpoints
// writeCannotParseJSON serves answer 400.
func (h *handler) decodeAuthzPolicyBody(w http.ResponseWriter, r *http.Request) (authzPolicyBody, bool) {
	var body authzPolicyBody
	if !requireJSONBody(w, r) {
		return body, false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return body, false
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" {
		writeAuthzScopeUnknownError(w)
		return body, false
	}
	if !strings.HasPrefix(trimmed, "{") {
		writeAuthzPolicyParseError(w, "unknown_error")
		return body, false
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeAuthzPolicyParseError(w, "invalid_request")
		return body, false
	}
	// An unknown field and a bad enum answer the same 500, which is why they
	// are one branch: Jackson refuses both while binding and neither reaches
	// the strict-decoder 400 this API uses elsewhere.
	if _, unknown := firstUnknownField(raw, &body); unknown {
		writeAuthzPolicyParseError(w, "unknown_error")
		return body, false
	}
	if body.Logic != nil && !containsString(authzPolicyLogics, *body.Logic) {
		writeAuthzPolicyParseError(w, "unknown_error")
		return body, false
	}
	if body.DecisionStrategy != nil &&
		!containsString(authzPolicyDecisionStrategies, *body.DecisionStrategy) {
		writeAuthzPolicyParseError(w, "unknown_error")
		return body, false
	}
	return body, true
}

// writeAuthzPolicyParseError is this family's parse failure: the same sentence
// writeCannotParseJSON writes and a **500** rather than a 400.
func writeAuthzPolicyParseError(w http.ResponseWriter, code string) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, code, "Cannot parse the JSON")
}

// writeAuthzPolicyNameTaken is the create's duplicate-name 409, and it is the
// **second** refusal in this family that names what it refused - and the only
// body in this API measured putting prose in `error` and a category in
// `error_description`, which is the other way round from every other shape:
//
//	409 {"error":"Policy with name [taken] already exists",
//	     "error_description":"Conflicting policy"}
//
// It carries the five security headers where a `PUT` onto the same taken name
// carries none - see the handover's F147 section, which is where this cut's
// probe of that split is recorded.
func writeAuthzPolicyNameTaken(w http.ResponseWriter, name string) {
	httpx.WriteOAuthError(w, http.StatusConflict,
		"Policy with name ["+name+"] already exists", "Conflicting policy")
}

// writeAuthzScopeRefUnknown is the create's answer to a `scopes` entry naming
// nothing: `400 {"error":"unknown_error"}` with **no `error_description` at
// all**, an error shape this API has not been measured producing anywhere else.
// A `resources` or `policies` entry naming nothing answers the ordinary 500
// instead, which is why the three sets do not share a resolver.
func writeAuthzScopeRefUnknown(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusBadRequest, "unknown_error")
}

// resolveAuthzScopeNames turns a `scopes` entry into a stored scope id. Each
// entry is a scope's **name or its id**, both measured working, and one naming
// neither is the 400 above rather than a create - which is the opposite of a
// resource's inline `scopes`, where an unknown name creates the scope.
func (h *handler) resolveAuthzScopeNames(w http.ResponseWriter, r *http.Request, a *authzContext,
	refs []string) ([]string, bool) {
	scopes, err := h.store.Authz().ListScopes(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	out := []string{}
	for _, ref := range refs {
		found := ""
		for _, s := range scopes {
			if s.ID == ref || s.Name == ref {
				found = s.ID
				break
			}
		}
		if found == "" {
			writeAuthzScopeRefUnknown(w)
			return nil, false
		}
		out = append(out, found)
	}
	return out, true
}

// resolveAuthzResourceRefs turns a `resources` entry into a stored resource id,
// by name or by id. An entry naming nothing is the consult-log 500.
func (h *handler) resolveAuthzResourceRefs(w http.ResponseWriter, r *http.Request, a *authzContext,
	refs []string) ([]string, bool) {
	resources, err := h.store.Authz().ListResources(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	out := []string{}
	for _, ref := range refs {
		found := ""
		for _, res := range resources {
			if res.ID == ref || res.Name == ref {
				found = res.ID
				break
			}
		}
		if found == "" {
			writeAuthzScopeUnknownError(w)
			return nil, false
		}
		out = append(out, found)
	}
	return out, true
}

// resolveAuthzPolicyRefs turns a `policies` entry into a stored policy id, by
// name or by id. An entry naming nothing is the consult-log 500.
func (h *handler) resolveAuthzPolicyRefs(w http.ResponseWriter, r *http.Request, a *authzContext,
	refs []string) ([]string, bool) {
	policies, err := h.store.Authz().ListPolicies(r.Context(), a.client.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	out := []string{}
	for _, ref := range refs {
		found := ""
		for _, p := range policies {
			if p.ID == ref || p.Name == ref {
				found = p.ID
				break
			}
		}
		if found == "" {
			writeAuthzScopeUnknownError(w)
			return nil, false
		}
		out = append(out, found)
	}
	return out, true
}
