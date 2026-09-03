package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// organizationRepresentation is Keycloak's OrganizationRepresentation, in the
// field order measured 2026-08-31:
//
//	id name alias enabled description redirectUrl attributes domains
//
// **Two shapes, and the parameter that picks between them reaches one route of
// the two.** Measured on a live 26.7.1:
//
//	GET /organizations                            id name alias enabled [description] [redirectUrl]            [domains]
//	GET /organizations?briefRepresentation=false  id name alias enabled [description] [redirectUrl] attributes [domains]
//	GET /organizations/{id}                       id name alias enabled [description] [redirectUrl] attributes [domains]
//
// briefRepresentation defaults to **true** on the listing, the same way the
// group listing's does. The single read **ignores** it: `?briefRepresentation=true`
// answered a body byte-identical to the one with no parameter at all,
// `attributes` included. A shared serialiser taking one boolean gets one of the
// two wrong.
//
// Four fields are pointers or carry omitempty, and each for its own measured
// reason rather than for symmetry:
//
//   - Description distinguishes absent from empty. A create sending
//     `"description":""` reads back carrying it; one sending nothing reads back
//     without the key.
//   - RedirectURL does **not**. The same create sending `"redirectUrl":""` reads
//     back with no `redirectUrl` key at all, so empty and absent are one state
//     here and two next door. Two neighbouring fields, opposite rules.
//   - Attributes is `{}` where present rather than omitted, so it is a pointer:
//     omitempty would drop the empty object the server sends.
//   - Domains is **absent** rather than `[]` when an organization has none, on
//     every shape - the opposite rule from Attributes beside it. Also a
//     pointer, for the opposite reason.
type organizationRepresentation struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Alias       string                  `json:"alias"`
	Enabled     bool                    `json:"enabled"`
	Description *string                 `json:"description,omitempty"`
	RedirectURL string                  `json:"redirectUrl,omitempty"`
	Attributes  *organizationAttributes `json:"attributes,omitempty"`
	Domains     *[]organizationDomain   `json:"domains,omitempty"`
}

// organizationDomain is one entry of the domains array. Both keys are always
// present: a domain created without `verified` reads back `"verified":false`.
type organizationDomain struct {
	Name     string `json:"name"`
	Verified bool   `json:"verified"`
}

// organizationAttributes is the attributes object, and it is a slice rather
// than a map for the reason clientMappings is: Keycloak serialises a Java map
// in HashMap bucket order and Go sorts a map's keys.
//
// **This one is placed exactly rather than masked.** An organization created
// with `{"k":["v1","v2"],"z":["w"]}` came back `{"z":["w"],"k":["v1","v2"]}` -
// not insertion order and not sorted - and `javamap.KeyOrder(["k","z"])`
// returns `[z k]`. So this is a seventh confirmed vector for that function and
// the goldens assert real bytes with no `UnorderedKeys` retreat, which is what
// F95 is still waiting for on a client's attributes.
type organizationAttributes []model.OrganizationAttribute

// MarshalJSON writes the entries as a JSON object in the order they are held,
// which is the order organizationRepresentationOf put them in.
func (a organizationAttributes) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(entry.Name)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		values, err := json.Marshal(entry.Values)
		if err != nil {
			return nil, err
		}
		b.Write(values)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// organizationRepresentationOf converts a stored organization for the wire.
//
// full says whether the attributes block is written: true for the single read
// and for the listing under briefRepresentation=false, false for the listing's
// default.
func organizationRepresentationOf(o *model.Organization, full bool) organizationRepresentation {
	rep := organizationRepresentation{
		ID:          o.ID,
		Name:        o.Name,
		Alias:       o.Alias,
		Enabled:     o.Enabled,
		Description: o.Description,
		RedirectURL: o.RedirectURL,
	}
	if len(o.Domains) > 0 {
		domains := make([]organizationDomain, 0, len(o.Domains))
		for _, d := range o.Domains {
			domains = append(domains, organizationDomain{Name: d.Name, Verified: d.Verified})
		}
		rep.Domains = &domains
	}
	if full {
		attrs := orderOrganizationAttributes(o.Attributes)
		rep.Attributes = &attrs
	}
	return rep
}

// orderOrganizationAttributes puts the stored pairs into Keycloak's HashMap
// bucket order. The store keeps them in the order they arrived, which is what
// lets a bucket collision chain the way it did on the way in; javamap.KeyOrder
// decides the rest.
func orderOrganizationAttributes(in []model.OrganizationAttribute) organizationAttributes {
	byName := make(map[string]model.OrganizationAttribute, len(in))
	names := make([]string, 0, len(in))
	for _, a := range in {
		byName[a.Name] = a
		names = append(names, a.Name)
	}
	out := make(organizationAttributes, 0, len(in))
	for _, name := range javamap.KeyOrder(names) {
		out = append(out, byName[name])
	}
	return out
}

// listOrganizations serves GET /admin/realms/{realm}/organizations.
//
// The four filters and the two bounds all run here rather than in the store,
// so "case-insensitive substring" is written down once instead of once per
// driver.
func (h *handler) listOrganizations(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	orgs, err := h.store.Organizations().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	orgs = filterOrganizations(orgs, q)
	orgs = pageGroups(orgs, q)

	full := q.Get("briefRepresentation") == "false"
	out := make([]organizationRepresentation, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, organizationRepresentationOf(o, full))
	}
	writeAdminJSON(w, out)
}

// countOrganizations serves GET /admin/realms/{realm}/organizations/count.
//
// **The body is a bare JSON number**, like GET /users/count and unlike
// GET /groups/count's `{"count":2}`. Three counts on this API, two shapes, and
// the organizations one sides with the users one - measured rather than
// inherited from the neighbour whose path it most resembles.
//
// It honours `search` and was measured answering 0 for one that matches
// nothing.
func (h *handler) countOrganizations(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	orgs, err := h.store.Organizations().List(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, len(filterOrganizations(orgs, r.URL.Query())))
}

// filterOrganizations applies search, exact and q.
//
// **search matches the name and the domains, and not the alias.** Measured:
// `search=full.example.com` matched an organization whose name does not contain
// it, and `search=full-alias` matched nothing although it is a substring of
// that same organization's alias. The obvious implementation searches every
// string field and is wrong on the third one.
//
// exact narrows search to an equal name. q is `key:value` over the attributes
// and a q with no colon was measured being ignored rather than refused.
func filterOrganizations(in []*model.Organization, q url.Values) []*model.Organization {
	out := in
	if search := q.Get("search"); search != "" {
		exact := q.Get("exact") == "true"
		var kept []*model.Organization
		for _, o := range out {
			if organizationMatches(o, search, exact) {
				kept = append(kept, o)
			}
		}
		out = kept
	}
	if attr := q.Get("q"); attr != "" {
		name, value, ok := strings.Cut(attr, ":")
		if ok {
			var kept []*model.Organization
			for _, o := range out {
				if organizationHasAttribute(o, name, value) {
					kept = append(kept, o)
				}
			}
			out = kept
		}
	}
	return out
}

func organizationMatches(o *model.Organization, search string, exact bool) bool {
	if exact {
		return o.Name == search
	}
	needle := strings.ToLower(search)
	if strings.Contains(strings.ToLower(o.Name), needle) {
		return true
	}
	for _, d := range o.Domains {
		if strings.Contains(strings.ToLower(d.Name), needle) {
			return true
		}
	}
	return false
}

func organizationHasAttribute(o *model.Organization, name, value string) bool {
	for _, a := range o.Attributes {
		if a.Name != name {
			continue
		}
		for _, v := range a.Values {
			if v == value {
				return true
			}
		}
	}
	return false
}

// readOrganization serves GET /admin/realms/{realm}/organizations/{org-id}.
//
// It writes the full shape unconditionally. briefRepresentation is **not**
// read: `?briefRepresentation=true` was measured answering a body identical to
// the one with no parameter, attributes and all, so honouring it here would be
// a divergence dressed up as consistency with the listing next door.
func (h *handler) readOrganization(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	writeAdminJSON(w, organizationRepresentationOf(o, true))
}

// organizationBody is what the two writes decode.
//
// It is decoded with decodeStrict, because POST and PUT on this resource are
// both strict: an unknown field answers
// `Invalid json representation for OrganizationRepresentation. Unrecognized
// field "bogusField" at line 1 column 50.` The Authentication Management PUTs
// were the first strict endpoints measured in this API and these are the third
// and fourth, so "the two required-action PUTs" is no longer the whole list.
// The field set is what a create was measured accepting, and no more: an
// undeclared field is the 400 above, so a field guessed into this struct would
// silently start accepting a body Keycloak refuses.
type organizationBody struct {
	// ID is decoded and discarded. It is here because the server accepts it -
	// a create carrying one answered 201 rather than the unknown-field 400 -
	// and it is unused because the server ignores it.
	ID          string               `json:"id"`
	Name        *string              `json:"name"`
	Alias       string               `json:"alias"`
	Enabled     *bool                `json:"enabled"`
	Description *string              `json:"description"`
	RedirectURL string               `json:"redirectUrl"`
	Attributes  map[string][]string  `json:"attributes"`
	Domains     []organizationDomain `json:"domains"`
}

// createOrganization serves POST /admin/realms/{realm}/organizations.
//
// **The body's id does not win**, which is the opposite of POST /clients and
// POST /client-scopes: a create carrying an id answered 201 with a Location
// ending in a different, server-minted UUID, and the id it asked for resolves
// to nothing. So the id is read off the wire and discarded.
//
// The 201 carries a Location and **no Content-Type at all** - content-length is
// 0 and the body is empty.
func (h *handler) createOrganization(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	var body organizationBody
	if !decodeStrict(w, r, "OrganizationRepresentation", &body) {
		return
	}
	if body.Name == nil || *body.Name == "" {
		// An **empty** name is a null name here, unlike a client scope's, where
		// absent is a 500 and empty is its own 400.
		httpx.WriteAdminError(w, http.StatusBadRequest, "Name can not be null")
		return
	}
	alias := body.Alias
	if alias == "" {
		// The alias defaults to the name **verbatim** - not lowercased, where a
		// username would be. `UPPER` produced the alias `UPPER`.
		alias = *body.Name
		if msg, ok := badAliasCharacter(alias); !ok {
			// Derived from the name: the errorMessage family, with a prefix
			// naming the name. See badAliasCharacter.
			httpx.WriteAdminError(w, http.StatusBadRequest, "Name cannot be used as alias: "+msg)
			return
		}
	} else if msg, ok := badAliasCharacter(alias); !ok {
		// Supplied as the alias: the **error** family, and no prefix. One
		// validation, two error shapes, decided by which field carried the
		// value.
		httpx.WriteMessageError(w, http.StatusBadRequest, msg)
		return
	}

	o := &model.Organization{
		ID:          model.NewID(),
		RealmID:     rc.realm.ID,
		Name:        *body.Name,
		Alias:       alias,
		Enabled:     body.Enabled == nil || *body.Enabled,
		Description: body.Description,
		RedirectURL: body.RedirectURL,
		Attributes:  organizationAttributesOf(body.Attributes),
	}
	for _, d := range body.Domains {
		o.Domains = append(o.Domains, model.OrganizationDomain{Name: d.Name, Verified: d.Verified})
	}
	if !h.checkOrganizationDomains(w, r, rc, o) {
		return
	}

	switch err := h.store.Organizations().Create(r.Context(), o); {
	case errors.Is(err, store.ErrConflict):
		h.writeOrganizationConflict(w, r, rc, o)
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// **An organization comes with a group.** Keycloak creates a hidden root
	// group with it whose `name` and `path` are the organization's own id, and
	// every group under `/organizations/{org}/groups` is a descendant of it.
	// Nothing on the wire says it was created here - the create's own 201 has
	// no body - but `GET /organizations/{org}/groups/{that id}` reads it, so an
	// organization without one is an organization whose group family is a 500.
	if err := h.store.Groups().Create(r.Context(), &model.Group{
		ID:             model.NewID(),
		RealmID:        rc.realm.ID,
		Name:           o.ID,
		OrganizationID: o.ID,
	}); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	w.Header().Set("Location",
		h.issuerBase+"/admin/realms/"+rc.realm.Name+"/organizations/"+o.ID)
	w.WriteHeader(http.StatusCreated)
}

// updateOrganization serves PUT /admin/realms/{realm}/organizations/{org-id}.
//
// **PUT replaces, and its check order is measured three deep.** The
// organization is resolved first - an unknown id answers 404 even for a body
// that is malformed or carries an unknown field, which is the opposite of
// PUT /required-actions/{alias}, where the decode runs first. Then the name
// conflict, then the alias.
//
// **A body with no name, or an empty one, is a 409 rather than the create's
// 400** - a conflict about a name the request does not have. One resource, one
// missing field, two verbs, two answers. Keycloak's own defect, reproduced.
//
// The first reading of it was that the missing name falls back to the alias and
// then collides with this organization's own row, and that reading was wrong:
// it was taken on an organization whose name and alias were the same string.
// On one where they differ, a PUT naming the alias **as the name** is a 204 and
// a PUT naming nothing is still the 409, so the empty name is its own branch.
// The conformance case update-without-name is what caught it.
//
// Every field but the alias and the attributes is replaced. Attributes absent
// from the body **survive**, and attributes sent as `{}` are cleared: one field
// on this body merges where the rest replace.
func (h *handler) updateOrganization(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	var body organizationBody
	if !decodeStrict(w, r, "OrganizationRepresentation", &body) {
		return
	}

	name := ""
	if body.Name != nil {
		name = *body.Name
	}
	// **An absent or empty name is the conflict, outright.** It is not a
	// fallback to the alias colliding with this row: measured on an
	// organization whose name and alias differ, a PUT naming the alias as the
	// name is a 204 while a PUT naming nothing is a 409. So the missing name is
	// its own branch and the two only looked like one because the first
	// organization measured happened to have name == alias.
	if name == "" {
		httpx.WriteAdminError(w, http.StatusConflict,
			"A organization with the same name already exists.")
		return
	}
	if name != o.Name {
		other, err := h.organizationByName(r, rc, name)
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
		if other != nil {
			httpx.WriteAdminError(w, http.StatusConflict,
				"A organization with the same name already exists.")
			return
		}
	}

	alias := body.Alias
	if alias == "" {
		alias = name
	}
	if alias != o.Alias {
		httpx.WriteAdminError(w, http.StatusBadRequest, "Cannot change the alias")
		return
	}

	updated := *o
	updated.Name = name
	updated.Enabled = body.Enabled == nil || *body.Enabled
	updated.Description = body.Description
	updated.RedirectURL = body.RedirectURL
	updated.Domains = nil
	for _, d := range body.Domains {
		updated.Domains = append(updated.Domains, model.OrganizationDomain{Name: d.Name, Verified: d.Verified})
	}
	if body.Attributes != nil {
		updated.Attributes = organizationAttributesOf(body.Attributes)
	}
	if !h.checkOrganizationDomains(w, r, rc, &updated) {
		return
	}

	switch err := h.store.Organizations().Update(r.Context(), &updated); {
	case errors.Is(err, store.ErrNotFound):
		writeOrganizationNotFound(w)
		return
	case errors.Is(err, store.ErrConflict):
		h.writeOrganizationConflict(w, r, rc, &updated)
		return
	case err != nil:
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// deleteOrganization serves DELETE /admin/realms/{realm}/organizations/{org-id}.
//
// Its 204 carries neither Cache-Control nor X-Frame-Options: the request sends
// no Content-Type, which is what decides the second, and this endpoint is one
// of the ones that sends no Cache-Control on a 204 at all.
//
// It is **not** idempotent - the second delete is 404, where a group's
// default-group removal is 204.
func (h *handler) deleteOrganization(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	// The organization's groups go with it. keycloak_group carries no foreign
	// key to organization - 0026_organization_group.sql says why - so the root
	// is removed here and GroupRepo.Delete walks the subtree under it.
	if root, err := h.store.Groups().OrganizationRoot(r.Context(), rc.realm.ID, o.ID); err == nil {
		if err := h.store.Groups().Delete(r.Context(), rc.realm.ID, root.ID); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if err := h.store.Organizations().Delete(r.Context(), rc.realm.ID, o.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeOrganizationNotFound(w)
			return
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteNoContent(w, r)
}

// checkOrganizationDomains refuses a domain another organization in the realm
// already holds.
//
// **It is a 400 and not a 409**, where a duplicate name is a 409 - so the
// conflict status on this resource is per field rather than per resource. The
// message names the other organization and the realm, which is why the store
// resolves the row rather than answering a boolean.
func (h *handler) checkOrganizationDomains(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) bool {
	for _, d := range o.Domains {
		held, err := h.store.Organizations().ByDomain(r.Context(), rc.realm.ID, d.Name)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return false
		}
		if held.ID == o.ID {
			continue
		}
		httpx.WriteAdminError(w, http.StatusBadRequest, "Domain "+d.Name+
			" is already linked to organization "+held.Name+" in realm "+rc.realm.Name)
		return false
	}
	return true
}

// writeOrganizationConflict tells the two 409s apart.
//
// **They differ only in a full stop**, on one verb of one resource:
//
//	name  409 {"errorMessage":"A organization with the same name already exists."}
//	alias 409 {"errorMessage":"A organization with the same alias already exists"}
//
// "A organization" is Keycloak's grammar, in both, and is copied. The schema
// carries two unique constraints so this function can ask which one it was
// rather than guessing.
func (h *handler) writeOrganizationConflict(w http.ResponseWriter, r *http.Request, rc *reqContext, o *model.Organization) {
	if other, err := h.organizationByName(r, rc, o.Name); err == nil && other != nil && other.ID != o.ID {
		httpx.WriteAdminError(w, http.StatusConflict,
			"A organization with the same name already exists.")
		return
	}
	httpx.WriteAdminError(w, http.StatusConflict,
		"A organization with the same alias already exists")
}

// organizationByName resolves one organization by name, or nil when there is
// none. The store lists by name rather than offering a lookup, so this is where
// the scan lives.
func (h *handler) organizationByName(r *http.Request, rc *reqContext, name string) (*model.Organization, error) {
	orgs, err := h.store.Organizations().List(r.Context(), rc.realm.ID)
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		if o.Name == name {
			return o, nil
		}
	}
	return nil, nil
}

// organizationAttributesOf turns the decoded map into the ordered slice the
// model holds. The map's own iteration order is random, so the names are sorted
// here to make the store deterministic; javamap.KeyOrder decides the wire order
// afterwards and does not care what order it is handed.
func organizationAttributesOf(in map[string][]string) []model.OrganizationAttribute {
	if len(in) == 0 {
		return nil
	}
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]model.OrganizationAttribute, 0, len(names))
	for _, name := range names {
		out = append(out, model.OrganizationAttribute{Name: name, Values: in[name]})
	}
	return out
}

// aliasForbiddenCharacters is the set measured to be refused, character by
// character, on 2026-08-31.
//
// It is **nearly** RFC 3986's gen-delims plus sub-delims and it is not that
// rule: `'` is a sub-delim and was measured **accepted**, while `\` is neither
// and was measured refused. `_ - . ~ % " < > | ^ { } ` + "`" + ` are all accepted too, so
// this is a list rather than a predicate, and writing it as "reject anything
// not unreserved" would refuse eight characters Keycloak takes.
const aliasForbiddenCharacters = `!#$&()*+,/:;=?@[]\`

// badAliasCharacter reports the first thing wrong with a would-be alias, and
// whether it is usable at all.
//
// **Whitespace is checked over the whole string before any character is**, which
// is measured and is not the obvious scan: `a/b c` answers about the space
// although the slash comes first. Two passes, whitespace first.
//
// The message is the tail of both error shapes; which shape it is wrapped in is
// decided by the caller, because the same complaint reaches the wire as
// `errorMessage` when the value came from the name and as `error` when it came
// from the alias.
func badAliasCharacter(alias string) (string, bool) {
	for _, r := range alias {
		if unicode.IsSpace(r) {
			return "Empty Space not allowed.", false
		}
	}
	for _, r := range alias {
		if strings.ContainsRune(aliasForbiddenCharacters, r) {
			return "Character '" + string(r) + "' not allowed.", false
		}
	}
	return "", true
}

// writeOrganizationNotFound is the 404 for an organization that does not exist.
// It has a trailing full stop, where the group family's `Group does not exist`
// - the twentieth spelling of not-found, and the fourth for a missing group -
// has none.
func writeOrganizationNotFound(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusNotFound, "Organization not found.")
}

// writeOrganizationsNotEnabled is what every route under /organizations answers
// on a realm whose organizationsEnabled is false, which is every realm by
// default - master's and every realm POST /admin/realms creates.
//
// **It is a 404 with an errorMessage, not client-types' 501**, and
// `ORGANIZATION` is not a preview feature: `GET /admin/serverinfo` reports it
// `"type":"DEFAULT","enabled":true` on a default start-dev, and it is absent
// from profileInfo.disabledFeatures where CLIENT_TYPES and
// CLIENT_SECRET_ROTATION both appear. What is off is the realm's own flag, and
// one PUT on the realm turns the whole tag on. See guardOrganizations for where
// in the order this sits, which is the other half of the difference.
func writeOrganizationsNotEnabled(w http.ResponseWriter) {
	httpx.WriteAdminError(w, http.StatusNotFound, "Organizations not enabled for this realm.")
}

// organizationsEnabled reports the realm's flag, which is one of the 106 keys
// of its representation and lives in the settings blob like the rest of them.
func organizationsEnabled(realm *model.Realm) bool {
	rep, err := decodeRealmSettings(realm)
	if err != nil {
		return false
	}
	return rep.OrganizationsEnabled
}
