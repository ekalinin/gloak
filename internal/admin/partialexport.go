package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// partial-export is POST /admin/realms/{realm}/partial-export.
//
// **It is GET /admin/realms/{realm} with sixteen keys spliced into it, and
// every key the two bodies share holds a byte-identical value.** That is the
// measurement, taken on a live 26.7.1 on 2026-09-06 and computed over the
// parsed bodies rather than read off:
//
//	GET  /admin/realms/master                        106 keys   4477 bytes
//	POST .../partial-export                          118 keys  40509 bytes
//	POST .../partial-export?exportClients=true       120 keys  46595 bytes
//	POST .../partial-export?exportGroupsAndRoles     120 keys  42162 bytes
//	POST .../partial-export?both                     122 keys  55118 bytes
//
// The export's key set is a strict superset of the realm representation's on
// all four settings, the shared keys come back in the realm representation's
// own order, and no shared value differs. So realmrep.go stays the one truth
// for those 106 fields and this file splices rather than re-declaring them. A
// 122-field struct would be a second copy of a body whose order
// realmrep_test.go already asserts, and AGENTS.md's rule about second truths is
// about exactly that.
//
// Two things the parameter names do not say, both measured because assuming
// either would have been wrong:
//
//   - **exportClients adds three keys, not two**, and master cannot show the
//     third. `users` is present only when the realm holds a service account
//     user, and it holds nothing else. None of master's six bootstrapped
//     clients has service accounts enabled, so the third key is invisible
//     there; it appeared as soon as a client with one existed in a created
//     realm.
//   - **The two booleans are not independent.** `roles.client` appears only
//     when *both* are true. exportGroupsAndRoles alone gives
//     `roles = {realm:[...]}` and nothing else, so a test sending one flag at a
//     time pins nothing about that cell.
//
// The response is the other measured oddity: `application/json` with **no
// charset** and **no Cache-Control at all**, against a control taken in the same
// script where GET /admin/realms/master answered with both. AGENTS.md records
// this route as one of the charset rule's three counterexamples.

// **Every fragment here goes through marshalOrderedValue rather than
// json.Marshal**, and the difference is `SetEscapeHTML`. httpx.WriteJSON turns
// escaping off for the body it encodes, but this handler hands it a
// json.RawMessage, which is copied through verbatim - so a fragment marshalled
// with the standard function arrives pre-escaped and survives. master's
// `displayNameHtml` is
// `<div class="kc-logo-text"><span>Keycloak</span></div>`, so the very first
// block of the very first golden says so, and it said so loudly: forty bytes of
// \u003c where Keycloak sends the characters.

// exportBlock is one key spliced into the realm representation, named by the
// key it follows.
//
// The anchor is a key name rather than an index because an index is a number in
// prose beside the thing it counts, and this project's own history says such a
// number drifts. spliceExportBlocks fails loudly when an anchor names a key the
// body does not have, so moving a field in realmrep.go is a red test rather
// than a block that silently lands somewhere else.
type exportBlock struct {
	after string
	key   string
	value any
}

// keycloakVersion is the value the export's own key carries. It is the version
// this project copies.
const keycloakVersion = "26.7.1"

// exportedSecret is what a confidential client's `secret` reads as in an
// export: ten asterisks, Keycloak's ComponentRepresentation.SECRET_VALUE. It is
// a constant rather than a length, because a mask derived from the secret's own
// length would leak it.
//
// This was measured rather than reasoned about, and the first reading of the
// key set had it the other way round: a confidential client created for the
// probe reported a `secret` key, and only printing the value showed it was not
// the stored one.
const exportedSecret = "**********"

// partialExport serves POST /admin/realms/{realm}/partial-export.
//
// The order is the realm, then manage-realm, then the parameters - measured: an
// unknown realm is 404 to a caller holding no admin role at all, a known realm
// is 403 to that caller, and a manage-realm caller sending exportClients=true
// against an unknown realm gets the 404 rather than the 403 the parameter would
// otherwise earn. guardAny supplies the first two steps and the conditional
// roles are checked here, which is where the parameters are first known.
func (h *handler) partialExport(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	q := r.URL.Query()
	exportClients := exportFlag(q["exportClients"])
	exportGroupsAndRoles := exportFlag(q["exportGroupsAndRoles"])

	// The conjunction, measured one role at a time over all 22
	// realm-management roles and then again with manage-realm plus each of the
	// other 21. manage-realm alone opens the no-parameter export and neither
	// parameterised one; query-clients and create-client do not open the
	// clients half although view-clients and manage-clients do; query-users
	// does not open the other half although view-users and manage-users do.
	if exportClients && !rc.caller.hasAny(exportClientsRoles) {
		writeForbidden(w)
		return
	}
	if exportGroupsAndRoles && !rc.caller.hasAny(exportGroupsAndRolesRoles) {
		writeForbidden(w)
		return
	}

	body, err := h.partialExportBody(r.Context(), rc, exportClients, exportGroupsAndRoles)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	// Not writeAdminJSON: this response carries neither the charset nor the
	// Cache-Control that helper sets, measured on both.
	httpx.WriteJSON(w, http.StatusOK, json.RawMessage(body))
}

// exportFlag is Keycloak's Boolean.parseBoolean over the first occurrence of a
// repeated parameter.
//
// Measured across ten spellings: `true`, `TRUE` and `True` export, and `false`,
// `1`, `0`, `yes`, `on`, the empty value and `bogus` do not. **`1` is false**,
// which is the spelling an implementation reaching for strconv.ParseBool would
// get wrong. A repeated parameter takes the **first**:
// `?exportClients=true&exportClients=false` exported and the reverse did not.
func exportFlag(values []string) bool {
	if len(values) == 0 {
		return false
	}
	return strings.EqualFold(values[0], "true")
}

// partialExportBody assembles the body. It is separate from the handler so a
// test can assert the key list without going through HTTP.
func (h *handler) partialExportBody(ctx context.Context, rc *reqContext,
	exportClients, exportGroupsAndRoles bool) ([]byte, error) {

	rep, err := h.realmRepresentationOf(ctx, rc.realm)
	if err != nil {
		return nil, err
	}
	base, err := marshalOrderedValue(rep)
	if err != nil {
		return nil, err
	}
	blocks, err := h.exportBlocks(ctx, rc, exportClients, exportGroupsAndRoles)
	if err != nil {
		return nil, err
	}
	return spliceExportBlocks(base, blocks)
}

// exportBlocks builds the spliced keys in the measured order. Each anchor was
// read off a recorded body: it is the key that precedes the block there.
//
// The `users` block is the one whose presence depends on realm state rather
// than on the request, so it is appended only when there is a service account
// to put in it - an empty `users` key is not a shape any measured body has.
func (h *handler) exportBlocks(ctx context.Context, rc *reqContext,
	exportClients, exportGroupsAndRoles bool) ([]exportBlock, error) {

	realm := rc.realm
	var blocks []exportBlock

	if exportGroupsAndRoles {
		roles, err := h.exportRoles(ctx, realm, exportClients)
		if err != nil {
			return nil, err
		}
		groups, err := h.exportGroups(ctx, realm)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks,
			exportBlock{after: "maxSecondaryAuthFailures", key: "roles", value: roles},
			exportBlock{after: "roles", key: "groups", value: groups},
		)
	}

	blocks = append(blocks, exportBlock{
		after: "otpSupportedApplications",
		key:   "localizationTexts",
		// Always `{}` on every body measured. Gloak stores texts per locale and
		// the export's shape here is a flat object; what a realm carrying texts
		// answers was not measured, so this is the one shape that was rather
		// than a guess at the other. See the handover's follow-ups.
		value: map[string]string{},
	})

	if exportClients {
		users, err := h.exportServiceAccountUsers(ctx, realm)
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			blocks = append(blocks, exportBlock{
				after: "webAuthnPolicyPasswordlessExtraOrigins",
				key:   "users",
				value: users,
			})
		}
	}

	scopeMappings, err := h.exportScopeMappings(ctx, realm)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks, exportBlock{
		after: "webAuthnPolicyPasswordlessExtraOrigins",
		key:   "scopeMappings",
		value: scopeMappings,
	})

	if exportClients {
		mappings, clients, err := h.exportClients(ctx, rc)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks,
			exportBlock{after: "scopeMappings", key: "clientScopeMappings", value: mappings},
			exportBlock{after: "clientScopeMappings", key: "clients", value: clients},
		)
	}

	scopes, err := h.store.ClientScopes().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	scopeReps := make([]clientScopeRepresentation, 0, len(scopes))
	for _, s := range scopes {
		scopeReps = append(scopeReps, clientScopeRepresentationOf(s))
	}
	defaults, err := h.exportRealmDefaultScopeNames(ctx, realm, true)
	if err != nil {
		return nil, err
	}
	optionals, err := h.exportRealmDefaultScopeNames(ctx, realm, false)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks,
		exportBlock{after: "scopeMappings", key: "clientScopes", value: scopeReps},
		exportBlock{after: "clientScopes", key: "defaultDefaultClientScopes", value: defaults},
		exportBlock{after: "defaultDefaultClientScopes", key: "defaultOptionalClientScopes", value: optionals},
	)

	providers, mappers, err := h.exportIdentityProviders(ctx, realm)
	if err != nil {
		return nil, err
	}
	components, err := h.exportComponents(ctx, realm)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks,
		exportBlock{after: "adminEventsDetailsEnabled", key: "identityProviders", value: providers},
		exportBlock{after: "identityProviders", key: "identityProviderMappers", value: mappers},
		exportBlock{after: "identityProviderMappers", key: "components", value: components},
	)

	flows, configs, err := h.exportAuthenticationFlows(ctx, realm)
	if err != nil {
		return nil, err
	}
	actions, err := h.exportRequiredActions(ctx, realm)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks,
		exportBlock{after: "internationalizationEnabled", key: "authenticationFlows", value: flows},
		exportBlock{after: "authenticationFlows", key: "authenticatorConfig", value: configs},
		exportBlock{after: "authenticatorConfig", key: "requiredActions", value: actions},
		exportBlock{after: "attributes", key: "keycloakVersion", value: keycloakVersion},
	)
	return blocks, nil
}

// spliceExportBlocks re-emits a JSON object with blocks inserted after the keys
// they name.
//
// It walks the base object's top-level keys in order and copies each value
// through as a json.RawMessage, so nothing about the base's bytes is re-encoded
// and its key order is carried rather than reconstructed. A block may anchor on
// another block's key, which is what lets the five scope-related keys chain off
// `scopeMappings`.
//
// **An anchor that names nothing is an error rather than a silent drop.** That
// is the whole reason to anchor by name: a field renamed or moved in
// realmrep.go turns into a failure naming the anchor, where an index would have
// quietly put the block somewhere else.
func spliceExportBlocks(base []byte, blocks []exportBlock) ([]byte, error) {
	byAnchor := make(map[string][]exportBlock, len(blocks))
	for _, b := range blocks {
		byAnchor[b.after] = append(byAnchor[b.after], b)
	}

	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	seen := make(map[string]bool, len(blocks))

	// emit writes one pair and then everything anchored on it, recursively, so
	// a chain of blocks comes out in the order it was declared.
	var emit func(key string, raw json.RawMessage) error
	emit = func(key string, raw json.RawMessage) error {
		if !first {
			out.WriteByte(',')
		}
		first = false
		name, err := marshalOrderedValue(key)
		if err != nil {
			return err
		}
		out.Write(name)
		out.WriteByte(':')
		out.Write(raw)
		seen[key] = true
		for _, b := range byAnchor[key] {
			v, err := marshalOrderedValue(b.value)
			if err != nil {
				return err
			}
			if err := emit(b.key, v); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walkJSONObject(base, emit); err != nil {
		return nil, err
	}
	out.WriteByte('}')

	for anchor := range byAnchor {
		if !seen[anchor] {
			return nil, fmt.Errorf("partial export: no key %q to splice after", anchor)
		}
	}
	return out.Bytes(), nil
}

// omitJSONKey re-emits a JSON object without one top-level key. It is
// spliceExportBlocks' other half and exists for one caller: the export's client
// is clientRepresentation minus `access` and nothing else.
func omitJSONKey(base []byte, drop string) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	first := true
	err := walkJSONObject(base, func(key string, raw json.RawMessage) error {
		if key == drop {
			return nil
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		name, err := marshalOrderedValue(key)
		if err != nil {
			return err
		}
		out.Write(name)
		out.WriteByte(':')
		out.Write(raw)
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// walkJSONObject calls visit for each top-level key of a JSON object, in the
// order the bytes hold them, with the value uninterpreted.
func walkJSONObject(base []byte, visit func(key string, raw json.RawMessage) error) error {
	dec := json.NewDecoder(bytes.NewReader(base))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("partial export: expected a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("partial export: a non-string key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if err := visit(key, raw); err != nil {
			return err
		}
	}
	return nil
}

// exportRealmDefaultScopeNames is one of the two name lists. They are bare
// names rather than the three-key brief shape the realm's own default listings
// serve, which makes them a fourth serialisation of a client scope and is why
// this does not reuse briefClientScopeRepresentation.
func (h *handler) exportRealmDefaultScopeNames(ctx context.Context, realm *model.Realm,
	defaultScope bool) ([]string, error) {

	scopes, err := h.store.ClientScopes().ListRealmDefaults(ctx, realm.ID, defaultScope)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(scopes))
	for _, s := range scopes {
		names = append(names, s.Name)
	}
	return names, nil
}

// exportScopeMapping is one entry of the realm-level scopeMappings array: the
// client scope's name and the realm-role names mapped into it. On a default
// realm it is one entry, `offline_access` holding the role of the same name.
type exportScopeMapping struct {
	ClientScope string   `json:"clientScope"`
	Roles       []string `json:"roles"`
}

func (h *handler) exportScopeMappings(ctx context.Context, realm *model.Realm) ([]exportScopeMapping, error) {
	scopes, err := h.store.ClientScopes().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := []exportScopeMapping{}
	for _, s := range scopes {
		roles, err := h.store.Roles().ListClientScopeScopeMappings(ctx, s.ID)
		if err != nil {
			return nil, err
		}
		if len(roles) == 0 {
			continue
		}
		names := make([]string, 0, len(roles))
		for _, role := range roles {
			names = append(names, role.Name)
		}
		out = append(out, exportScopeMapping{ClientScope: s.Name, Roles: names})
	}
	return out, nil
}

// exportClientScopeMapping is one entry of a clientScopeMappings value: the
// client whose scope the roles were taken into, and their names. The block as a
// whole is keyed by the **container** client, so master's one entry reads
// `{"account":[{"client":"account-console","roles":[...]}]}` - the roles belong
// to `account` and `account-console` is the client scoped to them.
type exportClientScopeMapping struct {
	Client string   `json:"client"`
	Roles  []string `json:"roles"`
}

// exportClients builds the clientScopeMappings object and the clients array
// together, because both walk the same client list and the mappings are keyed
// by a container the clients array has already resolved.
func (h *handler) exportClients(ctx context.Context, rc *reqContext) (
	map[string][]exportClientScopeMapping, []json.RawMessage, error) {

	realm := rc.realm
	clients, err := h.store.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]*model.Client, len(clients))
	for _, c := range clients {
		byID[c.ID] = c
	}

	mappings := map[string][]exportClientScopeMapping{}
	reps := make([]json.RawMessage, 0, len(clients))
	for _, c := range clients {
		rep := clientRepresentationOf(c, rc.caller, realm.Name)
		// **The secret is masked to exactly ten asterisks**, not omitted and
		// not the stored value. A public client has no `secret` key at all,
		// which is the field's existing omitempty.
		if rep.Secret != "" {
			rep.Secret = exportedSecret
		}
		// **The export's client is clientRepresentation minus `access`**, and
		// nothing else: the twenty-eight keys before it come back in the same
		// order with the same values, checked key by key against a recording.
		// So the key is dropped from the marshalled bytes rather than a
		// twenty-eight-field copy of the struct being declared, which is the
		// bargain spliceExportBlocks makes one level up. `access` describes the
		// caller and an export describes the realm, which is why it is the one
		// key that goes.
		raw, err := marshalOrderedValue(rep)
		if err != nil {
			return nil, nil, err
		}
		raw, err = omitJSONKey(raw, "access")
		if err != nil {
			return nil, nil, err
		}
		reps = append(reps, raw)

		scoped, err := h.store.Roles().ListClientScopeMappings(ctx, c.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, role := range scoped {
			container, ok := byID[role.ClientID]
			if !ok {
				continue
			}
			mappings[container.ClientID] = appendClientScopeMapping(
				mappings[container.ClientID], c.ClientID, role.Name)
		}
	}
	return mappings, reps, nil
}

func appendClientScopeMapping(in []exportClientScopeMapping, client, role string) []exportClientScopeMapping {
	for i := range in {
		if in[i].Client == client {
			in[i].Roles = append(in[i].Roles, role)
			return in
		}
	}
	return append(in, exportClientScopeMapping{Client: client, Roles: []string{role}})
}

// exportRoles is the `roles` object. Its `realm` half is present whenever
// exportGroupsAndRoles is set; **its `client` half needs exportClients as
// well**, which is the cell only a request supplying both conditions reaches.
// Measured: one flag gave `{realm:[5]}` at 1736 bytes and both gave
// `{realm:[5],client:{6 clients}}` at 9057, with the realm halves identical.
//
// `client` is an ordered slice rather than a map for the reason
// exportComponentsByType is: master's six containers come back
// `security-admin-console, admin-cli, account-console, broker, master-realm,
// account`, which `javamap.KeyOrder` places exactly, `javamap.SizedKeyOrder`
// does not, and sorting gets wrong.
type exportRoles struct {
	Realm  []json.RawMessage `json:"realm"`
	Client exportClientRoles `json:"client,omitempty"`
}

// exportClientRoles is the `roles.client` object in Java map order.
type exportClientRoles []exportClientRoleEntry

type exportClientRoleEntry struct {
	clientID string
	roles    []json.RawMessage
}

func (c exportClientRoles) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range c {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(e.clientID)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := marshalOrderedValue(e.roles)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (h *handler) exportRoles(ctx context.Context, realm *model.Realm, exportClients bool) (exportRoles, error) {
	out := exportRoles{Realm: []json.RawMessage{}}
	realmRoles, err := h.store.Roles().ListRealmRoles(ctx, realm.ID)
	if err != nil {
		return out, err
	}
	for _, role := range realmRoles {
		rep, err := h.exportRoleRepresentation(ctx, role, realm.ID, realm)
		if err != nil {
			return out, err
		}
		out.Realm = append(out.Realm, rep)
	}
	if !exportClients {
		return out, nil
	}

	clients, err := h.store.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		return out, err
	}
	byClient := map[string][]json.RawMessage{}
	names := []string{}
	for _, c := range clients {
		clientRoles, err := h.store.Roles().ListClientRoles(ctx, realm.ID, c.ID)
		if err != nil {
			return out, err
		}
		// **Every client gets an entry, including one with no roles at all.**
		// Three of master's six - security-admin-console, admin-cli and
		// account-console - come back as empty arrays, so skipping them is the
		// obvious implementation and it drops half the block's keys. Found by
		// the key-order assertion rather than by a count.
		reps := make([]json.RawMessage, 0, len(clientRoles))
		for _, role := range clientRoles {
			rep, err := h.exportRoleRepresentation(ctx, role, c.ID, realm)
			if err != nil {
				return out, err
			}
			reps = append(reps, rep)
		}
		byClient[c.ClientID] = reps
		names = append(names, c.ClientID)
	}
	out.Client = make(exportClientRoles, 0, len(names))
	for _, name := range javamap.KeyOrder(names) {
		out.Client = append(out.Client, exportClientRoleEntry{clientID: name, roles: byClient[name]})
	}
	return out, nil
}

// exportRoleComposites names a composite role's children by name. Both halves
// are omitempty: a role composite over client roles alone has no `realm` key.
type exportRoleComposites struct {
	Realm  []string            `json:"realm,omitempty"`
	Client map[string][]string `json:"client,omitempty"`
}

// exportRoleRepresentation is the role shape the export carries: the full
// representation, with `composites` naming the children by name.
//
// `composites` sits between `composite` and `clientRole`, which is *inside*
// roleRepresentation rather than after it, so it is spliced for the reason the
// top-level blocks are - representation.go stays the one truth for the seven
// keys around it.
func (h *handler) exportRoleRepresentation(ctx context.Context, role *model.Role,
	containerID string, realm *model.Realm) (json.RawMessage, error) {

	base, err := marshalOrderedValue(roleRepresentationOf(role, containerID, false))
	if err != nil {
		return nil, err
	}
	if !role.Composite {
		return base, nil
	}
	children, err := h.store.Roles().ListComposites(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	comp := exportRoleComposites{}
	for _, child := range children {
		if child.ClientID == "" {
			comp.Realm = append(comp.Realm, child.Name)
			continue
		}
		container, err := h.store.Clients().ByID(ctx, realm.ID, child.ClientID)
		if err != nil {
			continue
		}
		if comp.Client == nil {
			comp.Client = map[string][]string{}
		}
		comp.Client[container.ClientID] = append(comp.Client[container.ClientID], child.Name)
	}
	return spliceExportBlocks(base, []exportBlock{
		{after: "composite", key: "composites", value: comp},
	})
}

// exportGroup is the export's group shape, and it is a **seventh**
// representation of a group where AGENTS.md records six. It has no `access` and
// no `subGroupCount`, and it alone carries `realmRoles` and `clientRoles`. A
// child carries `parentId`; a group at the top of the realm does not.
type exportGroup struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	ParentID    string              `json:"parentId,omitempty"`
	SubGroups   []exportGroup       `json:"subGroups"`
	Attributes  map[string][]string `json:"attributes"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
}

func (h *handler) exportGroups(ctx context.Context, realm *model.Realm) ([]exportGroup, error) {
	tops, err := h.store.Groups().ListTopLevel(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := []exportGroup{}
	for _, g := range tops {
		rep, err := h.exportGroupTree(ctx, realm, g)
		if err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, nil
}

func (h *handler) exportGroupTree(ctx context.Context, realm *model.Realm, g *model.Group) (exportGroup, error) {
	path, err := h.pathOf(ctx, realm.ID, g.ID)
	if err != nil {
		return exportGroup{}, err
	}
	attrs := g.Attributes
	if attrs == nil {
		attrs = map[string][]string{}
	}
	rep := exportGroup{
		ID:          g.ID,
		Name:        g.Name,
		Path:        path,
		ParentID:    g.ParentID,
		SubGroups:   []exportGroup{},
		Attributes:  attrs,
		RealmRoles:  []string{},
		ClientRoles: map[string][]string{},
	}
	roles, err := h.store.Roles().ListGroupRoles(ctx, g.ID)
	if err != nil {
		return rep, err
	}
	for _, role := range roles {
		if role.ClientID == "" {
			rep.RealmRoles = append(rep.RealmRoles, role.Name)
			continue
		}
		container, err := h.store.Clients().ByID(ctx, realm.ID, role.ClientID)
		if err != nil {
			continue
		}
		rep.ClientRoles[container.ClientID] = append(rep.ClientRoles[container.ClientID], role.Name)
	}

	children, err := h.store.Groups().ListChildren(ctx, realm.ID, g.ID)
	if err != nil {
		return rep, err
	}
	for _, child := range children {
		sub, err := h.exportGroupTree(ctx, realm, child)
		if err != nil {
			return rep, err
		}
		rep.SubGroups = append(rep.SubGroups, sub)
	}
	return rep, nil
}

// exportUser is the shape a service account user takes in an export. The three
// empty arrays are present rather than omitted, and `totp` sits between
// `createdTimestamp` and `serviceAccountClientId`.
type exportUser struct {
	ID                         string   `json:"id"`
	Username                   string   `json:"username"`
	EmailVerified              bool     `json:"emailVerified"`
	Enabled                    bool     `json:"enabled"`
	CreatedTimestamp           int64    `json:"createdTimestamp"`
	Totp                       bool     `json:"totp"`
	ServiceAccountClientID     string   `json:"serviceAccountClientId"`
	DisableableCredentialTypes []string `json:"disableableCredentialTypes"`
	RequiredActions            []string `json:"requiredActions"`
	RealmRoles                 []string `json:"realmRoles"`
	NotBefore                  int      `json:"notBefore"`
	Groups                     []string `json:"groups"`
}

// exportServiceAccountUsers is the `users` block, and **service accounts are all
// it holds**. A realm full of ordinary users exports none of them; the block
// appeared only once a client with serviceAccountsEnabled existed, and it
// carried that client's user alone.
func (h *handler) exportServiceAccountUsers(ctx context.Context, realm *model.Realm) ([]exportUser, error) {
	clients, err := h.store.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := []exportUser{}
	for _, c := range clients {
		if !c.ServiceAccountsEnabled {
			continue
		}
		u, err := h.store.Users().ByUsername(ctx, realm.ID, model.ServiceAccountUsername(c.ClientID))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, err
		}
		rep := exportUser{
			ID:                         u.ID,
			Username:                   u.Username,
			EmailVerified:              u.EmailVerified,
			Enabled:                    u.Enabled,
			CreatedTimestamp:           u.CreatedTimestamp,
			ServiceAccountClientID:     c.ClientID,
			DisableableCredentialTypes: []string{},
			RequiredActions:            []string{},
			RealmRoles:                 []string{},
			Groups:                     []string{},
		}
		roles, err := h.store.Roles().ListUserRoles(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if role.ClientID == "" {
				rep.RealmRoles = append(rep.RealmRoles, role.Name)
			}
		}
		out = append(out, rep)
	}
	return out, nil
}

// exportComponentRepresentation is the component shape an export carries, and
// it is **not** componentRepresentation. `providerType` and `parentId` are gone
// - the first is the key the block is filed under and the second is the realm -
// and `subComponents` is present, `{}` on every measured row.
type exportComponentRepresentation struct {
	ID            string                                     `json:"id"`
	Name          string                                     `json:"name,omitempty"`
	ProviderID    string                                     `json:"providerId"`
	SubType       string                                     `json:"subType,omitempty"`
	SubComponents map[string][]exportComponentRepresentation `json:"subComponents"`
	Config        componentConfig                            `json:"config"`
}

// exportComponentsByType is the `components` object, and it is a slice with its
// own marshaller rather than a map because **its key order is a Java map's**.
//
// A default realm's three provider types come back
// `ClientRegistrationPolicy, UserProfileProvider, KeyProvider`, which Go's
// sorted map order gets wrong on all three. `javamap.KeyOrder` places them
// exactly and `javamap.SizedKeyOrder` does not - a fifteenth measured key set
// for that function, and one of the few that tells the two constructors apart.
type exportComponentsByType []exportComponentTypeEntry

type exportComponentTypeEntry struct {
	providerType string
	components   []exportComponentRepresentation
}

func (c exportComponentsByType) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, e := range c {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := marshalOrderedValue(e.providerType)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := marshalOrderedValue(e.components)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// exportComponents groups the realm's components by provider type. The four key
// providers are in it and **their key material is not**: their config holds
// `priority` and sometimes `algorithm`, with no privateKey, no certificate and
// no secret. That is measured, not a redaction this code performs - Gloak keeps
// no key material in a component row either.
func (h *handler) exportComponents(ctx context.Context, realm *model.Realm) (exportComponentsByType, error) {
	components, err := h.store.Components().List(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	byType := map[string][]exportComponentRepresentation{}
	for _, c := range components {
		rep := exportComponentRepresentation{
			ID:            c.ID,
			ProviderID:    c.ProviderID,
			SubType:       c.SubType,
			SubComponents: map[string][]exportComponentRepresentation{},
			Config:        orderComponentConfig(c.Config),
		}
		if c.Name != nil {
			rep.Name = *c.Name
		}
		byType[c.ProviderType] = append(byType[c.ProviderType], rep)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	out := make(exportComponentsByType, 0, len(types))
	for _, t := range javamap.KeyOrder(types) {
		out = append(out, exportComponentTypeEntry{providerType: t, components: byType[t]})
	}
	return out, nil
}

// exportIdentityProviders is the two identity-provider blocks. Both are `[]` on
// a default realm, which is two of the three empty blocks among the twelve.
func (h *handler) exportIdentityProviders(ctx context.Context, realm *model.Realm) (
	[]identityProviderRepresentation, []identityProviderMapperRepresentation, error) {

	providers, err := h.store.IdentityProviders().List(ctx, realm.ID)
	if err != nil {
		return nil, nil, err
	}
	preps := make([]identityProviderRepresentation, 0, len(providers))
	mreps := []identityProviderMapperRepresentation{}
	for _, p := range providers {
		preps = append(preps, identityProviderRepresentationOf(p, false))
		alias := ""
		if p.Alias != nil {
			alias = *p.Alias
		}
		mappers, err := h.store.IdentityProviderMappers().List(ctx, realm.ID, alias)
		if err != nil {
			return nil, nil, err
		}
		for _, m := range mappers {
			mreps = append(mreps, identityProviderMapperRepresentationOf(m))
		}
	}
	return preps, mreps, nil
}

// exportAuthenticationFlow is a flow with its executions nested, which is not
// the shape GET /authentication/flows/{alias}/executions serves: that one is a
// flat list carrying ids, levels and indexes, and this one is a tree carrying
// none of them.
type exportAuthenticationFlow struct {
	ID                       string                        `json:"id"`
	Alias                    string                        `json:"alias,omitempty"`
	Description              string                        `json:"description"`
	ProviderID               string                        `json:"providerId"`
	TopLevel                 bool                          `json:"topLevel"`
	BuiltIn                  bool                          `json:"builtIn"`
	AuthenticationExecutions []exportAuthenticationExecute `json:"authenticationExecutions"`
}

// exportAuthenticationExecute is one execution inside an exported flow.
//
// **It carries `autheticatorFlow` beside `authenticatorFlow`**, spelled without
// its `n`, holding the same boolean. That is Keycloak's own typo - a deprecated
// field on AuthenticationExecutionExportRepresentation that is still serialised
// - and it is on every execution of every flow. Correcting the spelling here is
// the tidy-up that breaks the one thing this project exists to do.
//
// `authenticator` is absent on an execution that references a sub-flow and
// `flowAlias` is absent on one that names an authenticator, so the two are
// opposite halves rather than one optional extra. `authenticatorConfig` names
// the config's **alias**, not its id.
type exportAuthenticationExecute struct {
	AuthenticatorConfig string `json:"authenticatorConfig,omitempty"`
	Authenticator       string `json:"authenticator,omitempty"`
	AuthenticatorFlow   bool   `json:"authenticatorFlow"`
	Requirement         string `json:"requirement"`
	Priority            int    `json:"priority"`
	AutheticatorFlow    bool   `json:"autheticatorFlow"`
	FlowAlias           string `json:"flowAlias,omitempty"`
	UserSetupAllowed    bool   `json:"userSetupAllowed"`
}

// exportAuthenticatorConfig is the authenticatorConfig block's entry: three
// keys, and the config is a plain string map rather than the multivalued one a
// component carries.
type exportAuthenticatorConfig struct {
	ID     string          `json:"id"`
	Alias  string          `json:"alias"`
	Config model.StringMap `json:"config"`
}

func (h *handler) exportAuthenticationFlows(ctx context.Context, realm *model.Realm) (
	[]exportAuthenticationFlow, []exportAuthenticatorConfig, error) {

	flows, err := h.store.AuthenticationFlows().ListFlows(ctx, realm.ID)
	if err != nil {
		return nil, nil, err
	}
	configs, err := h.store.AuthenticationFlows().ListConfigs(ctx, realm.ID)
	if err != nil {
		return nil, nil, err
	}
	configAlias := make(map[string]string, len(configs))
	creps := make([]exportAuthenticatorConfig, 0, len(configs))
	for _, c := range configs {
		configAlias[c.ID] = c.Alias
		creps = append(creps, exportAuthenticatorConfig{ID: c.ID, Alias: c.Alias, Config: c.Config})
	}
	flowAlias := make(map[string]string, len(flows))
	for _, f := range flows {
		if f.Alias != nil {
			flowAlias[f.ID] = *f.Alias
		}
	}

	freps := make([]exportAuthenticationFlow, 0, len(flows))
	for _, f := range flows {
		rep := exportAuthenticationFlow{
			ID:                       f.ID,
			Description:              f.Description,
			ProviderID:               f.ProviderID,
			TopLevel:                 f.TopLevel,
			BuiltIn:                  f.BuiltIn,
			AuthenticationExecutions: []exportAuthenticationExecute{},
		}
		if f.Alias != nil {
			rep.Alias = *f.Alias
		}
		executions, err := h.store.AuthenticationFlows().ListExecutions(ctx, realm.ID, f.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range executions {
			sub := e.FlowID != ""
			freq := exportAuthenticationExecute{
				AuthenticatorConfig: configAlias[e.ConfigID],
				Authenticator:       e.Authenticator,
				AuthenticatorFlow:   sub,
				Requirement:         e.Requirement,
				Priority:            e.Priority,
				AutheticatorFlow:    sub,
				FlowAlias:           flowAlias[e.FlowID],
			}
			rep.AuthenticationExecutions = append(rep.AuthenticationExecutions, freq)
		}
		freps = append(freps, rep)
	}

	// **Both arrays are sorted by alias, and neither of the endpoints beside
	// them is.** Measured: the export's eighteen flows come back
	// `Account verification options, Browser - Conditional 2FA, ... browser,
	// clients, ...` - a byte sort, capitals first - where
	// GET /authentication/flows serves seven in seed order, and the four
	// authenticator configs come back sorted too. Serving either in the order
	// the store holds them is what the first recording of this body caught.
	slices.SortFunc(freps, func(a, b exportAuthenticationFlow) int {
		return strings.Compare(a.Alias, b.Alias)
	})
	slices.SortFunc(creps, func(a, b exportAuthenticatorConfig) int {
		return strings.Compare(a.Alias, b.Alias)
	})
	return freps, creps, nil
}

// exportRequiredAction is the required-action shape an export carries: the
// listing's six keys plus `config`, and **no `id`**. The endpoint's own body has
// the id and no config, so the two are not the same struct.
type exportRequiredAction struct {
	Alias         string          `json:"alias"`
	Name          string          `json:"name,omitempty"`
	ProviderID    string          `json:"providerId"`
	Enabled       bool            `json:"enabled"`
	DefaultAction bool            `json:"defaultAction"`
	Priority      int             `json:"priority"`
	Config        model.StringMap `json:"config"`
}

func (h *handler) exportRequiredActions(ctx context.Context, realm *model.Realm) ([]exportRequiredAction, error) {
	actions, err := h.store.RequiredActions().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := make([]exportRequiredAction, 0, len(actions))
	for _, a := range actions {
		rep := exportRequiredAction{
			Alias:         a.Alias,
			ProviderID:    a.ProviderID,
			Enabled:       a.Enabled,
			DefaultAction: a.DefaultAction,
			Priority:      a.Priority,
			Config:        a.Config,
		}
		if a.Name != nil {
			rep.Name = *a.Name
		}
		out = append(out, rep)
	}
	return out, nil
}
