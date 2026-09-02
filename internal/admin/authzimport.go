package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// A policy's config travels in two directions and the two do not agree, which
// is the finding this file exists for.
//
//	on the way in    a role name becomes the role's uuid, a clientId becomes the
//	                 client's uuid, a group path becomes the group's id
//	the live read    serves those ids
//	the export       serves the names and the path back again
//
// Three providers resolve a reference and **all three answer an unknown one
// differently**: an unknown role is silently dropped, an unknown group path is
// silently dropped, and an unknown clientId is a 500. A shared resolver would
// be wrong on one of the three whichever answer it picked.
//
// Three more keys are not config at all. `applyPolicies`, `resources` and
// `scopes` arrive inside `config`, are **consumed into the association sets**
// and are gone from the stored config - measured on four types, so it is not
// the aggregate provider's behaviour but the family's - and the export
// synthesises them back out of the associations, by name.

// authzConfigAssociationKeys maps the three config keys that are really
// associations onto the association kind they feed. The export writes the same
// mapping backwards.
var authzConfigAssociationKeys = map[string]string{
	"applyPolicies": "policy",
	"resources":     "resource",
	"scopes":        "scope",
}

// authzAssociationConfigKey is that map read the other way, which the export
// needs.
func authzAssociationConfigKey(kind string) string {
	for key, k := range authzConfigAssociationKeys {
		if k == kind {
			return key
		}
	}
	return ""
}

// authzProviderDefaultKey is the key each provider writes into a config that
// does not carry it, measured on a create with `config:{}` for every type.
//
// **Only three providers do it**, which is what makes a `role` policy answer
// `config:{"roles":"[]"}` from its own read while its 201 said `{}`, and what
// makes `targetContextAttributes` different: the regex provider writes no key,
// so the typed view defaults that field rather than reading it - see
// authzTypedBoolAlways.
var authzProviderDefaultKey = map[string]string{
	"role":   "roles",
	"client": "clients",
	"group":  "groups",
}

// authzExportKeeps says which config keys the settings export keeps, for the
// three types that do not keep all of them.
//
// **The export rewrites a role, client or group policy's config to the
// provider's own keys and throws the rest away**, and the other six types pass
// the whole config through unchanged. Measured by storing one fourteen-key
// config on all nine types: the live read served all fourteen on all nine, and
// the export served fourteen on six of them and two, one and two on these
// three.
//
// **It is the same three types three times over** - the three that resolve a
// reference on the way in, the three that write a default key, and the three
// that filter here - which is what makes one map of three entries the honest
// shape rather than a coincidence worth three lists. Nothing measured separates
// them, and a fourth type joining any one of the three would be the probe that
// does.
//
// The synthesised association keys are added **after** this filter: a role
// policy holding an associated policy exports `{applyPolicies, roles}`.
var authzExportKeeps = map[string][]string{
	"role":   {"roles", "fetchRoles"},
	"client": {"clients"},
	"group":  {"groups", "groupsClaim"},
}

// normaliseAuthzPolicyConfig turns the request's config into the stored one.
//
// Four things happen and each is measured:
//
//   - the three association keys are consumed into the association sets and
//     removed, on every type;
//   - `roles`, `clients` and `groups` are resolved from names to ids;
//   - the provider's own key is added when it is absent;
//   - a value under one of those keys that is not JSON is
//     `500 {"error":"invalid_request","error_description":"Cannot parse the
//     JSON"}` - `invalid_request` on a 500, which is a shape this API has been
//     measured producing on exactly two inputs, both of them here.
//
// The error return is reserved for a store failure; a refusal is written to w
// and reported by the false.
func (h *handler) normaliseAuthzPolicyConfig(w http.ResponseWriter, r *http.Request,
	rc *reqContext, a *authzContext, p *model.AuthzPolicy) bool {
	kept := make([]model.AuthzPolicyConfig, 0, len(p.Config))
	for _, entry := range p.Config {
		kind, isAssociation := authzConfigAssociationKeys[entry.Name]
		if !isAssociation {
			kept = append(kept, entry)
			continue
		}
		var refs []string
		if err := json.Unmarshal([]byte(entry.Value), &refs); err != nil {
			writeAuthzPolicyParseError(w, "invalid_request")
			return false
		}
		ids, ok := h.resolveAuthzAssociation(w, r, a, kind, refs)
		if !ok {
			return false
		}
		for _, id := range ids {
			if !containsString(p.AssociationSet(kind), id) {
				p.AddAssociation(kind, id)
			}
		}
	}
	p.Config = kept

	if key, ok := authzProviderDefaultKey[p.Type]; ok {
		if _, present := p.ConfigValue(key); !present {
			p.SetConfig(key, "[]")
		}
	}
	switch p.Type {
	case "role":
		return h.normaliseAuthzRoleConfig(w, r, rc, p)
	case "client":
		return h.normaliseAuthzClientConfig(w, r, rc, p)
	case "group":
		return h.normaliseAuthzGroupConfig(w, r, rc, p)
	}
	return true
}

// authzRoleRef is one entry of a role policy's `config.roles`. The id is a role
// **name** on the way in and a role uuid on the way out, and `required` is
// filled in when the request left it out - measured on a create naming `admin`,
// which came back as that role's uuid with `"required":false` beside it.
type authzRoleRef struct {
	ID       string `json:"id"`
	Required bool   `json:"required"`
}

// authzGroupRef is one entry of a group policy's `config.groups`. A request
// naming a `path` comes back naming an `id`, with `extendChildren` filled in
// and the path gone.
type authzGroupRef struct {
	ID             string `json:"id,omitempty"`
	Path           string `json:"path,omitempty"`
	ExtendChildren bool   `json:"extendChildren"`
}

// normaliseAuthzRoleConfig resolves `config.roles`. **An entry naming no role
// is silently dropped** - `[{"id":"admin"},{"id":"nope"}]` was stored holding
// admin's uuid alone - which is one of the three answers this family gives an
// unknown reference.
func (h *handler) normaliseAuthzRoleConfig(w http.ResponseWriter, r *http.Request,
	rc *reqContext, p *model.AuthzPolicy) bool {
	raw, _ := p.ConfigValue("roles")
	var refs []authzRoleRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		writeAuthzPolicyParseError(w, "invalid_request")
		return false
	}
	out := []authzRoleRef{}
	for _, ref := range refs {
		role, err := h.authzRoleByRef(r.Context(), rc.realm.ID, ref.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return false
		}
		out = append(out, authzRoleRef{ID: role.ID, Required: ref.Required})
	}
	return authzSetJSONConfig(w, p, "roles", out)
}

// normaliseAuthzClientConfig resolves `config.clients`. **An entry naming no
// client is a 500**, where the role and group providers drop theirs.
func (h *handler) normaliseAuthzClientConfig(w http.ResponseWriter, r *http.Request,
	rc *reqContext, p *model.AuthzPolicy) bool {
	raw, _ := p.ConfigValue("clients")
	var refs []string
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		writeAuthzPolicyParseError(w, "invalid_request")
		return false
	}
	out := []string{}
	for _, ref := range refs {
		c, err := h.authzClientByRef(r.Context(), rc.realm.ID, ref)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAuthzScopeUnknownError(w)
				return false
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return false
		}
		out = append(out, c.ID)
	}
	return authzSetJSONConfig(w, p, "clients", out)
}

// normaliseAuthzGroupConfig resolves `config.groups`. **An entry naming no
// group is silently dropped**, like a role and unlike a client, and the `path`
// it arrived under is replaced by the group's id.
func (h *handler) normaliseAuthzGroupConfig(w http.ResponseWriter, r *http.Request,
	rc *reqContext, p *model.AuthzPolicy) bool {
	raw, _ := p.ConfigValue("groups")
	var refs []authzGroupRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		writeAuthzPolicyParseError(w, "invalid_request")
		return false
	}
	groups, err := h.store.Groups().ListAll(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	out := []authzGroupRef{}
	for _, ref := range refs {
		id := ""
		for _, g := range groups {
			if ref.ID != "" && g.ID == ref.ID {
				id = g.ID
				break
			}
			if ref.Path != "" {
				path, err := h.pathOf(r.Context(), rc.realm.ID, g.ID)
				if err != nil {
					httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
					return false
				}
				if path == ref.Path {
					id = g.ID
					break
				}
			}
		}
		if id == "" {
			continue
		}
		out = append(out, authzGroupRef{ID: id, ExtendChildren: ref.ExtendChildren})
	}
	return authzSetJSONConfig(w, p, "groups", out)
}

// authzSetJSONConfig writes a resolved collection back into the config as the
// JSON **string** the server serves it as.
func authzSetJSONConfig(w http.ResponseWriter, p *model.AuthzPolicy, key string, value any) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	p.SetConfig(key, string(raw))
	return true
}

// authzRoleByRef resolves a role by its realm-role name or by its id, which is
// what a `config.roles` entry may hold. The name is tried first because that is
// what the admin console sends and what the measured create used.
func (h *handler) authzRoleByRef(ctx context.Context, realmID, ref string) (*model.Role, error) {
	if ref == "" {
		return nil, store.ErrNotFound
	}
	if role, err := h.store.Roles().ByName(ctx, realmID, "", ref); err == nil {
		return role, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return h.store.Roles().ByID(ctx, realmID, ref)
}

// authzClientByRef resolves a client by its clientId or by its uuid.
func (h *handler) authzClientByRef(ctx context.Context, realmID, ref string) (*model.Client, error) {
	if ref == "" {
		return nil, store.ErrNotFound
	}
	if c, err := h.store.Clients().ByClientID(ctx, realmID, ref); err == nil {
		return c, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return h.store.Clients().ByID(ctx, realmID, ref)
}

// resolveAuthzAssociation resolves the three config-borne association sets.
//
// **An unknown reference is the consult-log 500 for all three, including
// `scopes`** - where the body's own `scopes` array answers the bare
// `400 {"error":"unknown_error"}`. One name, two positions on one request, two
// refusals, which is why this is not resolveAuthzScopeNames.
func (h *handler) resolveAuthzAssociation(w http.ResponseWriter, r *http.Request, a *authzContext,
	kind string, refs []string) ([]string, bool) {
	out := []string{}
	for _, ref := range refs {
		id, err := h.authzAssociationTarget(r, a, kind, ref)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAuthzScopeUnknownError(w)
				return nil, false
			}
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

func (h *handler) authzAssociationTarget(r *http.Request, a *authzContext, kind, ref string) (string, error) {
	switch kind {
	case "policy":
		if p, err := h.store.Authz().PolicyByName(r.Context(), a.client.ID, ref); err == nil {
			return p.ID, nil
		}
		p, err := h.store.Authz().PolicyByID(r.Context(), a.client.ID, ref)
		if err != nil {
			return "", err
		}
		return p.ID, nil
	case "resource":
		if res, err := h.store.Authz().ResourceByName(r.Context(), a.client.ID, ref); err == nil {
			return res.ID, nil
		}
		res, err := h.store.Authz().ResourceByID(r.Context(), a.client.ID, ref)
		if err != nil {
			return "", err
		}
		return res.ID, nil
	default:
		if s, err := h.store.Authz().ScopeByName(r.Context(), a.client.ID, ref); err == nil {
			return s.ID, nil
		}
		s, err := h.store.Authz().ScopeByID(r.Context(), a.client.ID, ref)
		if err != nil {
			return "", err
		}
		return s.ID, nil
	}
}

// authzExportedPolicies builds `GET .../settings`' `policies` array.
//
// **Its partition is not the `/permission` listing's**, measured on seven
// policies created with the two families interleaved: the export serves
// creation order with the `resource` and `scope` rows moved to the end and
// leaves `uma` among the policies, where `GET .../permission` counts `uma` as a
// permission. Two notions of "permission" one path segment apart, and reusing
// authzPermissionTypes here would move a uma row to the wrong half.
//
// Each entry drops the id and the owner, and **its config is the live config
// denormalised**: role, client and group references go back to names and paths,
// and the three association sets are synthesised back into `applyPolicies`,
// `resources` and `scopes` by name. So a policy whose live read answers
// `config:{}` exports a config with three keys in it.
func (h *handler) authzExportedPolicies(r *http.Request, rc *reqContext, a *authzContext,
	policies []*model.AuthzPolicy) ([]authzPolicyExport, error) {
	first := []*model.AuthzPolicy{}
	last := []*model.AuthzPolicy{}
	for _, p := range policies {
		if p.Type == "resource" || p.Type == "scope" {
			last = append(last, p)
			continue
		}
		first = append(first, p)
	}
	out := []authzPolicyExport{}
	for _, p := range append(first, last...) {
		config, err := h.exportedAuthzConfig(r, rc, a, p)
		if err != nil {
			return nil, err
		}
		out = append(out, authzPolicyExport{
			Name:             p.Name,
			Description:      p.Description,
			Type:             p.Type,
			Logic:            p.Logic,
			DecisionStrategy: p.DecisionStrategy,
			Config:           authzOrderedConfig(config),
		})
	}
	return out, nil
}

// exportedAuthzConfig denormalises one policy's config for the export.
func (h *handler) exportedAuthzConfig(r *http.Request, rc *reqContext, a *authzContext,
	p *model.AuthzPolicy) ([]model.AuthzPolicyConfig, error) {
	keep, filtered := authzExportKeeps[p.Type]
	out := make([]model.AuthzPolicyConfig, 0, len(p.Config)+3)
	for _, entry := range p.Config {
		if filtered && !containsString(keep, entry.Name) {
			continue
		}
		value := entry.Value
		var err error
		switch {
		case p.Type == "role" && entry.Name == "roles":
			value, err = h.exportAuthzRoles(r, rc, entry.Value)
		case p.Type == "client" && entry.Name == "clients":
			value, err = h.exportAuthzClients(r, rc, entry.Value)
		case p.Type == "group" && entry.Name == "groups":
			value, err = h.exportAuthzGroups(r, rc, entry.Value)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, model.AuthzPolicyConfig{Name: entry.Name, Value: value})
	}
	// Iterated over the ordered kinds rather than over the map, so two runs of
	// one build produce one order. The wire order is javamap's and does not
	// depend on this, but a Go map's iteration order would leak into the store
	// order and from there into any key set javamap cannot place.
	for _, kind := range model.AuthzPolicyAssociationKinds {
		key := authzAssociationConfigKey(kind)
		ids := p.AssociationSet(kind)
		if len(ids) == 0 {
			continue
		}
		names := make([]string, 0, len(ids))
		for _, id := range ids {
			name, err := h.authzAssociationName(r, a, kind, id)
			if err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		raw, err := json.Marshal(names)
		if err != nil {
			return nil, err
		}
		out = append(out, model.AuthzPolicyConfig{Name: key, Value: string(raw)})
	}
	return out, nil
}

func (h *handler) authzAssociationName(r *http.Request, a *authzContext, kind, id string) (string, error) {
	switch kind {
	case "policy":
		p, err := h.store.Authz().PolicyByID(r.Context(), a.client.ID, id)
		if err != nil {
			return "", err
		}
		return p.Name, nil
	case "resource":
		res, err := h.store.Authz().ResourceByID(r.Context(), a.client.ID, id)
		if err != nil {
			return "", err
		}
		return res.Name, nil
	default:
		s, err := h.store.Authz().ScopeByID(r.Context(), a.client.ID, id)
		if err != nil {
			return "", err
		}
		return s.Name, nil
	}
}

func (h *handler) exportAuthzRoles(r *http.Request, rc *reqContext, raw string) (string, error) {
	var refs []authzRoleRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return raw, nil
	}
	for i, ref := range refs {
		role, err := h.store.Roles().ByID(r.Context(), rc.realm.ID, ref.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return "", err
		}
		refs[i].ID = role.Name
	}
	out, err := json.Marshal(refs)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (h *handler) exportAuthzClients(r *http.Request, rc *reqContext, raw string) (string, error) {
	var refs []string
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return raw, nil
	}
	for i, ref := range refs {
		c, err := h.store.Clients().ByID(r.Context(), rc.realm.ID, ref)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return "", err
		}
		refs[i] = c.ClientID
	}
	out, err := json.Marshal(refs)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (h *handler) exportAuthzGroups(r *http.Request, rc *reqContext, raw string) (string, error) {
	var refs []authzGroupRef
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		return raw, nil
	}
	out := make([]authzGroupRef, 0, len(refs))
	for _, ref := range refs {
		path, err := h.pathOf(r.Context(), rc.realm.ID, ref.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				out = append(out, ref)
				continue
			}
			return "", err
		}
		out = append(out, authzGroupRef{Path: path, ExtendChildren: ref.ExtendChildren})
	}
	raw2, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw2), nil
}

// authzImportBody is what `POST .../import` decodes: the settings export's own
// shape, read back.
//
// **It is a strict decoder where `POST .../policy` beside it is not.** An
// unknown field here is
// `400 Invalid json representation for ResourceServerRepresentation.
// Unrecognized field "zzz" at line 1 column 9.` and there it is a 500. Two
// writes on one resource server, two answers to the same fault, which makes
// this the ninth strict endpoint.
type authzImportBody struct {
	ID                            string                  `json:"id"`
	ClientID                      string                  `json:"clientId"`
	Name                          string                  `json:"name"`
	AllowRemoteResourceManagement *bool                   `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string                  `json:"policyEnforcementMode"`
	DecisionStrategy              *string                 `json:"decisionStrategy"`
	Resources                     []authzImportResource   `json:"resources"`
	Policies                      []authzImportPolicy     `json:"policies"`
	Scopes                        []authzScopeImportEntry `json:"scopes"`
}

type authzImportResource struct {
	ID                 string                   `json:"_id"`
	Name               string                   `json:"name"`
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

type authzImportPolicy struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Description      string                `json:"description"`
	Type             string                `json:"type"`
	Logic            json.RawMessage       `json:"logic"`
	DecisionStrategy json.RawMessage       `json:"decisionStrategy"`
	Owner            string                `json:"owner"`
	Config           *authzPolicyConfigMap `json:"config"`
}

type authzScopeImportEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IconURI     string `json:"iconUri"`
	DisplayName string `json:"displayName"`
}

// importAuthzSettings serves `POST .../authz/resource-server/import`.
//
// 204, no `Cache-Control`, no body. Three measured behaviours, and two of them
// are the opposite of what "import" suggests:
//
//   - **It resets the three settings to the representation's own initialisers
//     and then overwrites what the body names**, which is
//     `PUT .../authz/resource-server`'s rule: `{}` against a stored
//     `false/PERMISSIVE/AFFIRMATIVE` produced `true/ENFORCING/UNANIMOUS`.
//   - **It deletes nothing.** A pre-existing scope, resource and policy all
//     survived an import that did not mention them.
//   - **A name it already holds is merged into rather than replaced.**
//     Importing `{"name":"keep","type":"regex","config":{"pattern":"^z$"}}`
//     over a `role` policy named `keep` left the type `role` and the config
//     `{"pattern":"^z$","roles":"[]"}`. So the type, the logic and the strategy
//     of an existing row are kept and only the config grows.
func (h *handler) importAuthzSettings(w http.ResponseWriter, r *http.Request, rc *reqContext, a *authzContext) {
	var body authzImportBody
	if !h.readAuthzImportJSON(w, r, &body) {
		return
	}

	updated := model.DefaultAuthzResourceServer(a.client.ID)
	if body.AllowRemoteResourceManagement != nil {
		updated.AllowRemoteResourceManagement = *body.AllowRemoteResourceManagement
	}
	if body.PolicyEnforcementMode != "" {
		updated.PolicyEnforcementMode = body.PolicyEnforcementMode
	}
	if body.DecisionStrategy != nil {
		updated.DecisionStrategy = *body.DecisionStrategy
	}
	if err := h.store.Authz().Upsert(r.Context(), updated); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	// The scopes go in first because a resource may name one and a policy may
	// name a resource, and the import was measured resolving both.
	for _, entry := range body.Scopes {
		if !h.importAuthzScope(w, r, a, entry) {
			return
		}
	}
	for _, entry := range body.Resources {
		if !h.importAuthzResource(w, r, a, entry) {
			return
		}
	}
	for _, entry := range body.Policies {
		if !h.importAuthzPolicy(w, r, rc, a, entry) {
			return
		}
	}
	httpx.WriteNoContent(w, r)
}

// readAuthzImportJSON is the import's decode. An empty body and a literal
// `null` are the consult-log 500, where the create beside it answers two
// different bodies for those two inputs.
func (h *handler) readAuthzImportJSON(w http.ResponseWriter, r *http.Request, body *authzImportBody) bool {
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
	return decodeStrict(w, r, "ResourceServerRepresentation", body)
}

func (h *handler) importAuthzScope(w http.ResponseWriter, r *http.Request, a *authzContext,
	entry authzScopeImportEntry) bool {
	if entry.Name == "" {
		return true
	}
	existing, err := h.store.Authz().ScopeByName(r.Context(), a.client.ID, entry.Name)
	if err == nil {
		existing.IconURI = entry.IconURI
		existing.DisplayName = entry.DisplayName
		if err := h.store.Authz().UpdateScope(r.Context(), existing); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return false
		}
		return true
	}
	if !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	s := &model.AuthzScope{
		ID: entry.ID, ClientID: a.client.ID, Name: entry.Name,
		IconURI: entry.IconURI, DisplayName: entry.DisplayName,
	}
	if s.ID == "" {
		s.ID = model.NewID()
	}
	if err := h.store.Authz().CreateScope(r.Context(), s); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

func (h *handler) importAuthzResource(w http.ResponseWriter, r *http.Request, a *authzContext,
	entry authzImportResource) bool {
	if entry.Name == "" {
		return true
	}
	body := authzResourceBody{
		ID: entry.ID, Name: &entry.Name, DisplayName: entry.DisplayName, Type: entry.Type,
		IconURI: entry.IconURI, URIs: entry.URIs, URI: entry.URI,
		OwnerManagedAccess: entry.OwnerManagedAccess,
		Attributes:         entry.Attributes, Scopes: entry.Scopes, ResourceScopes: entry.ResourceScopes,
	}
	scopeIDs, ok := h.resolveAuthzScopeRefs(w, r, a, body.scopeRefs())
	if !ok {
		return false
	}
	stored := &model.AuthzResource{
		ClientID: a.client.ID, Name: entry.Name, DisplayName: entry.DisplayName,
		Type: entry.Type, IconURI: entry.IconURI, OwnerManagedAccess: entry.OwnerManagedAccess,
		URIs: body.uris(), ScopeIDs: scopeIDs,
	}
	if entry.Attributes != nil {
		stored.Attributes = *entry.Attributes
	}
	existing, err := h.store.Authz().ResourceByName(r.Context(), a.client.ID, entry.Name)
	if err == nil {
		stored.ID = existing.ID
		stored.Ordinal = existing.Ordinal
		if err := h.store.Authz().UpdateResource(r.Context(), stored); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return false
		}
		return true
	}
	if !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	stored.ID = entry.ID
	if stored.ID == "" {
		stored.ID = model.NewID()
	}
	if err := h.store.Authz().CreateResource(r.Context(), stored); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}

// importAuthzPolicy writes one policy. **An existing name is merged into**:
// the type, the logic and the decision strategy stay as they were and the
// config grows, which is what an import of a `regex` body over a `role` policy
// was measured doing.
func (h *handler) importAuthzPolicy(w http.ResponseWriter, r *http.Request, rc *reqContext,
	a *authzContext, entry authzImportPolicy) bool {
	if entry.Name == "" {
		return true
	}
	existing, err := h.store.Authz().PolicyByName(r.Context(), a.client.ID, entry.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	merging := err == nil

	stored := &model.AuthzPolicy{
		ClientID: a.client.ID, Name: entry.Name, Description: entry.Description,
		Type: entry.Type, Owner: entry.Owner,
		Logic:            model.DefaultAuthzPolicyLogic,
		DecisionStrategy: model.DefaultAuthzPolicyDecisionStrategy,
	}
	if v, present, _ := authzEnumValue(entry.Logic); present {
		stored.Logic = v
	}
	if v, present, _ := authzEnumValue(entry.DecisionStrategy); present {
		stored.DecisionStrategy = v
	}
	if merging {
		stored.ID = existing.ID
		stored.Ordinal = existing.Ordinal
		stored.Type = existing.Type
		stored.Logic = existing.Logic
		stored.DecisionStrategy = existing.DecisionStrategy
		stored.Config = append([]model.AuthzPolicyConfig{}, existing.Config...)
		stored.AssociatedPolicies = existing.AssociatedPolicies
		stored.Resources = existing.Resources
		stored.Scopes = existing.Scopes
	} else {
		stored.ID = entry.ID
		if stored.ID == "" {
			stored.ID = model.NewID()
		}
		if !containsString(authzPolicyTypes, stored.Type) {
			writeAuthzScopeUnknownError(w)
			return false
		}
	}
	if entry.Config != nil {
		for _, c := range *entry.Config {
			stored.SetConfig(c.Name, c.Value)
		}
	}
	if !h.normaliseAuthzPolicyConfig(w, r, rc, a, stored) {
		return false
	}
	if merging {
		err = h.store.Authz().UpdatePolicy(r.Context(), stored)
	} else {
		err = h.store.Authz().CreatePolicy(r.Context(), stored)
	}
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return false
	}
	return true
}
