package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// TestEvaluateScopesGuardsAreTwoDifferentShapes pins the split no golden can
// see: the three reads take one role and the two generators take **two**.
//
// A conformance case authenticates as the bootstrapped administrator, which
// holds everything, so every cell below is invisible to the suite. The sweep
// this reproduces was run against a live 26.7.1 on 2026-09-05 with
// GET /admin/realms/master/clients as a control that answers 200 to three of
// these callers and 403 to the rest - without which a table of 403s would be
// measuring the probe.
func TestEvaluateScopesGuardsAreTwoDifferentShapes(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()

	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}
	admin, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername(admin): %v", err)
	}
	base := "/admin/realms/master/clients/" + account.ID + "/evaluate-scopes"

	reads := []string{
		base + "/protocol-mappers",
		base + "/scope-mappings/master/granted",
		base + "/scope-mappings/master/not-granted",
	}
	generators := []string{
		base + "/generate-example-access-token?userId=" + admin.ID,
		base + "/generate-example-id-token?userId=" + admin.ID,
	}

	for _, tc := range []struct {
		roles          []string
		control        int // GET /admin/realms/master/clients
		read, generate int
	}{
		{[]string{"view-clients"}, 200, 200, 403},
		{[]string{"manage-clients"}, 200, 200, 403},
		{[]string{"query-clients"}, 200, 403, 403},
		{[]string{"view-users"}, 403, 403, 403},
		{[]string{"manage-realm"}, 403, 403, 403},
		{[]string{"view-clients", "view-users"}, 200, 200, 200},
		{[]string{"view-clients", "manage-users"}, 200, 200, 200},
		{[]string{"manage-clients", "view-users"}, 200, 200, 200},
		{[]string{"manage-clients", "manage-users"}, 200, 200, 200},
		// Neither family's query- role opens its half.
		{[]string{"view-clients", "query-users"}, 200, 200, 403},
		{[]string{"query-clients", "view-users"}, 200, 403, 403},
		// A second clients role does not substitute for a users one.
		{[]string{"view-clients", "view-realm"}, 200, 200, 403},
	} {
		token := tokenForRoles(t, h, s, realm, tc.roles...)
		if got := get(t, h, "/admin/realms/master/clients", token).Code; got != tc.control {
			t.Errorf("%v: control GET /clients = %d, want %d", tc.roles, got, tc.control)
		}
		for _, p := range reads {
			if got := get(t, h, p, token).Code; got != tc.read {
				t.Errorf("%v: GET %s = %d, want %d", tc.roles, p, got, tc.read)
			}
		}
		for _, p := range generators {
			if got := get(t, h, p, token).Code; got != tc.generate {
				t.Errorf("%v: GET %s = %d, want %d", tc.roles, p, got, tc.generate)
			}
		}
	}
}

// TestEvaluateScopesGeneratorOrder pins the three answers a generator gives
// about its userId, and the order they are decided in.
//
// The interesting row is the middle one: a caller that may read clients and not
// users is told the parameter is **missing** before it is told it may not read
// the user. Checking the role first is the obvious order and it hides a 404
// from the one caller a golden cannot be recorded as.
func TestEvaluateScopesGeneratorOrder(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()

	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}
	base := "/admin/realms/master/clients/" + account.ID +
		"/evaluate-scopes/generate-example-access-token"
	clientsOnly := tokenForRoles(t, h, s, realm, "view-clients")
	both := tokenForRoles(t, h, s, realm, "view-clients", "view-users")

	for _, tc := range []struct {
		name, path, token string
		status            int
		body              string
	}{
		{"no userId, no user role", base, clientsOnly, 404, `{"error":"No userId provided"}`},
		{"a userId, no user role", base + "?userId=whatever", clientsOnly, 403,
			`{"error":"You have no access to this user"}`},
		{"no userId, both roles", base, both, 404, `{"error":"No userId provided"}`},
		{"unknown userId, both roles", base + "?userId=nosuchuser", both, 404,
			`{"error":"No user found"}`},
	} {
		rec := get(t, h, tc.path, tc.token)
		if rec.Code != tc.status || rec.Body.String() != tc.body {
			t.Errorf("%s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.body)
		}
	}
}

// TestEvaluatedScopeReadsTheLinkedClientScopesMappings is the measurement that
// says this family is not the scope-mapping family with a prefix.
//
// A client with fullScopeAllowed off, one realm role mapped directly and
// composite over a second, and a **linked client scope** carrying a scope
// mapping to a third:
//
//	evaluate-scopes/.../granted      r1, r2, r3
//	scope-mappings/realm/composite   r1, r2
//
// The third arrives through the client scope, which the neighbour does not
// read. Both bodies are asserted here rather than only the new one, because
// what is being pinned is that the two **disagree** - a test naming only the
// new route would pass a handler that had quietly changed the old one too.
func TestEvaluatedScopeReadsTheLinkedClientScopesMappings(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	token := adminToken(t, h)

	r1 := makeRealmRole(t, s, realm, "gloak-probe-ev-r1")
	r2 := makeRealmRole(t, s, realm, "gloak-probe-ev-r2")
	r3 := makeRealmRole(t, s, realm, "gloak-probe-ev-r3")
	r4 := makeRealmRole(t, s, realm, "gloak-probe-ev-r4")
	r1.Composite = true
	if err := s.Roles().Update(ctx, r1); err != nil {
		t.Fatalf("Update(r1): %v", err)
	}
	if err := s.Roles().AddComposite(ctx, r1.ID, r2.ID); err != nil {
		t.Fatalf("AddComposite: %v", err)
	}

	scope := &model.ClientScope{
		ID: model.NewID(), RealmID: realm.ID,
		Name: "gloak-probe-ev-scope", Protocol: "openid-connect",
	}
	if err := s.ClientScopes().Create(ctx, scope); err != nil {
		t.Fatalf("Create(scope): %v", err)
	}
	if err := s.Roles().AddClientScopeScopeMapping(ctx, scope.ID, r3.ID); err != nil {
		t.Fatalf("AddClientScopeScopeMapping: %v", err)
	}
	optional := &model.ClientScope{
		ID: model.NewID(), RealmID: realm.ID,
		Name: "gloak-probe-ev-opt", Protocol: "openid-connect",
	}
	if err := s.ClientScopes().Create(ctx, optional); err != nil {
		t.Fatalf("Create(optional): %v", err)
	}
	if err := s.Roles().AddClientScopeScopeMapping(ctx, optional.ID, r4.ID); err != nil {
		t.Fatalf("AddClientScopeScopeMapping(optional): %v", err)
	}

	c := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-ev-client",
		Enabled: true, PublicClient: true, FullScopeAllowed: false,
		RedirectURIs: []string{}, WebOrigins: []string{},
	}
	if err := s.Clients().Create(ctx, c); err != nil {
		t.Fatalf("Create(client): %v", err)
	}
	if err := s.Roles().AddClientScopeMapping(ctx, c.ID, r1.ID); err != nil {
		t.Fatalf("AddClientScopeMapping: %v", err)
	}
	if err := s.ClientScopes().AddClientScope(ctx, c.ID, scope.ID, true); err != nil {
		t.Fatalf("AddClientScope(default): %v", err)
	}
	if err := s.ClientScopes().AddClientScope(ctx, c.ID, optional.ID, false); err != nil {
		t.Fatalf("AddClientScope(optional): %v", err)
	}

	base := "/admin/realms/master/clients/" + c.ID
	probeNames := func(t *testing.T, path string) []string {
		t.Helper()
		rec := get(t, h, path, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
		}
		var rows []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		var out []string
		for _, r := range rows {
			if len(r.Name) > 13 && r.Name[:13] == "gloak-probe-e" {
				out = append(out, r.Name)
			}
		}
		return out
	}

	granted := probeNames(t, base+"/evaluate-scopes/scope-mappings/master/granted")
	if !sameSet(granted, []string{"gloak-probe-ev-r1", "gloak-probe-ev-r2", "gloak-probe-ev-r3"}) {
		t.Errorf("granted = %v, want r1, r2 and the linked client scope's r3", granted)
	}
	composite := probeNames(t, base+"/scope-mappings/realm/composite")
	if !sameSet(composite, []string{"gloak-probe-ev-r1", "gloak-probe-ev-r2"}) {
		t.Errorf("the neighbour's composite = %v, want r1 and r2 only", composite)
	}
	notGranted := probeNames(t, base+"/evaluate-scopes/scope-mappings/master/not-granted")
	if !sameSet(notGranted, []string{"gloak-probe-ev-r4"}) {
		t.Errorf("not-granted = %v, want the optional scope's r4", notGranted)
	}

	// The `scope` parameter moves r4 across, which is the second input the
	// neighbour has none of.
	withScope := probeNames(t, base+
		"/evaluate-scopes/scope-mappings/master/granted?scope=gloak-probe-ev-opt")
	if !sameSet(withScope, []string{"gloak-probe-ev-r1", "gloak-probe-ev-r2",
		"gloak-probe-ev-r3", "gloak-probe-ev-r4"}) {
		t.Errorf("granted?scope=... = %v, want r4 as well", withScope)
	}
	// A scope naming nothing is a 200 that changes no byte, not a 400.
	unknown := get(t, h, base+"/evaluate-scopes/scope-mappings/master/granted?scope=nosuchscope", token)
	plain := get(t, h, base+"/evaluate-scopes/scope-mappings/master/granted", token)
	if unknown.Code != http.StatusOK || unknown.Body.String() != plain.Body.String() {
		t.Errorf("scope=nosuchscope = %d %s, want the plain body", unknown.Code, unknown.Body.String())
	}
}

// TestRoleContainerAcceptsTheRealmNameAndTheClientUUID pins the two spellings
// that resolve, and the two neighbouring ones that do not.
//
// Both refusals are the surprise. The realm's own **id** is what every realm
// role's containerId carries and it is a 404 here; a client's **clientId** is
// how every other route in this API that names a client by anything but a UUID
// names it, and it is a 404 too.
func TestRoleContainerAcceptsTheRealmNameAndTheClientUUID(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	token := adminToken(t, h)

	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}
	base := "/admin/realms/master/clients/" + account.ID + "/evaluate-scopes/scope-mappings/"

	for _, tc := range []struct {
		name, container string
		status          int
	}{
		{"the realm's name", "master", 200},
		{"the realm's own id", realm.ID, 404},
		{"a client's UUID", account.ID, 200},
		{"a client's clientId", "account", 404},
		{"nothing at all", "00000000-0000-0000-0000-000000000000", 404},
	} {
		rec := get(t, h, base+tc.container+"/granted", token)
		if rec.Code != tc.status {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.status, rec.Body.String())
		}
		if tc.status == 404 && rec.Body.String() != `{"error":"Role Container not found"}` {
			t.Errorf("%s: body %s, want the Role Container spelling", tc.name, rec.Body.String())
		}
	}
}

// TestExampleAudienceIsComputedRatherThanRefused pins the parameter whose two
// halves are the opposite way round from what a reader expects: an audience
// naming a client that **does not exist** is dropped, and one naming a client
// that does but is out of the token's own aud is a 404.
//
// The positive case is here because it is the one a defensive implementation
// gets wrong: refusing every resolvable audience passes both refusals below and
// fails the only value that succeeds.
func TestExampleAudienceIsComputedRatherThanRefused(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	token := adminToken(t, h)

	// A second client owning a role, granted to a user, and mapped into the
	// first client's scope - which is what puts it in the token's aud.
	holder := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-aud-holder",
		Enabled: true, PublicClient: true, RedirectURIs: []string{}, WebOrigins: []string{},
	}
	if err := s.Clients().Create(ctx, holder); err != nil {
		t.Fatalf("Create(holder): %v", err)
	}
	role := &model.Role{
		ID: model.NewID(), RealmID: realm.ID, ClientID: holder.ID, Name: "gloak-probe-aud-role",
	}
	if err := s.Roles().Create(ctx, role); err != nil {
		t.Fatalf("Create(role): %v", err)
	}
	subject := createUserWithPassword(t, s, realm, "gloak-probe-aud-user", "pw")
	if err := s.Roles().AssignToUser(ctx, subject.ID, role.ID); err != nil {
		t.Fatalf("AssignToUser: %v", err)
	}
	asker := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-aud-asker",
		Enabled: true, PublicClient: true, RedirectURIs: []string{}, WebOrigins: []string{},
	}
	if err := s.Clients().Create(ctx, asker); err != nil {
		t.Fatalf("Create(asker): %v", err)
	}
	if err := s.Roles().AddClientScopeMapping(ctx, asker.ID, role.ID); err != nil {
		t.Fatalf("AddClientScopeMapping: %v", err)
	}

	base := "/admin/realms/master/clients/" + asker.ID +
		"/evaluate-scopes/generate-example-access-token?userId=" + subject.ID
	for _, tc := range []struct {
		name, audience string
		status         int
	}{
		{"absent", "", 200},
		{"a client in the token's own aud", "&audience=gloak-probe-aud-holder", 200},
		{"the asking client itself", "&audience=gloak-probe-aud-asker", 404},
		{"a client out of scope", "&audience=account", 404},
		{"a client that does not exist", "&audience=nosuchclient", 200},
	} {
		rec := get(t, h, base+tc.audience, token)
		if rec.Code != tc.status {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.status, rec.Body.String())
		}
	}
}

// TestExampleTokenScopeReadsIncludeInTokenScope pins the claim that decides
// which of a client's scope names reach the `scope` claim.
//
// The reading is "anything but the string false", which is how the six
// bootstrapped default scopes split - and it is what makes `account`'s example
// answer two words rather than the six names it is attached to.
func TestExampleTokenScopeReadsIncludeInTokenScope(t *testing.T) {
	in := []*model.ClientScope{
		{Name: "profile", Attributes: model.StringMap{{Key: "include.in.token.scope", Value: "true"}}},
		{Name: "roles", Attributes: model.StringMap{{Key: "include.in.token.scope", Value: "false"}}},
		{Name: "no-attribute-at-all"},
		{Name: "empty-value", Attributes: model.StringMap{{Key: "include.in.token.scope", Value: ""}}},
	}
	if got, want := exampleTokenScope(in), "profile no-attribute-at-all empty-value"; got != want {
		t.Errorf("exampleTokenScope = %q, want %q", got, want)
	}
}

// TestExampleTokensCarryTheScopeFilteredRoles is the difference between a
// preview and a token dump: `account` has fullScopeAllowed off and no realm
// role in scope, so the administrator's example carries **no realm_access at
// all** although the administrator holds five realm roles.
//
// It also pins the ID token's missing at_hash, which is the one place the two
// previews disagree and the reason idClaims.AtHash carries omitempty.
func TestExampleTokensCarryTheScopeFilteredRoles(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	token := adminToken(t, h)

	account, err := s.Clients().ByClientID(ctx, realm.ID, "account")
	if err != nil {
		t.Fatalf("ByClientID(account): %v", err)
	}
	admin, err := s.Users().ByUsername(ctx, realm.ID, "admin")
	if err != nil {
		t.Fatalf("ByUsername(admin): %v", err)
	}
	held, err := s.Roles().ListUserRoles(ctx, admin.ID)
	if err != nil {
		t.Fatalf("ListUserRoles: %v", err)
	}
	if len(held) == 0 {
		t.Fatal("the administrator holds no role at all; the control below is vacuous")
	}
	base := "/admin/realms/master/clients/" + account.ID + "/evaluate-scopes/"

	var access map[string]json.RawMessage
	rec := get(t, h, base+"generate-example-access-token?userId="+admin.ID, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("access token = %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &access); err != nil {
		t.Fatalf("access token: %v", err)
	}
	if _, ok := access["realm_access"]; ok {
		t.Errorf("realm_access is present; account has no realm role in scope, so it is absent")
	}
	if _, ok := access["resource_access"]; !ok {
		t.Errorf("resource_access is absent; the administrator holds account's own roles")
	}
	if _, ok := access["aud"]; ok {
		t.Errorf("aud is present; a client is never its own audience and there is no other")
	}

	var id map[string]json.RawMessage
	rec = get(t, h, base+"generate-example-id-token?userId="+admin.ID, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("id token = %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &id); err != nil {
		t.Fatalf("id token: %v", err)
	}
	if _, ok := id["at_hash"]; ok {
		t.Errorf("at_hash is present; this exchange mints no access token to hash")
	}
	if string(id["aud"]) != `"account"` {
		t.Errorf("aud = %s, want the issuing client as a bare string", id["aud"])
	}
}

// TestEvaluatedProtocolMappersNameTheirContainer pins the two containerType
// spellings and the empty containerName a client's own mapper carries - which
// is measured on a client that **has** a name, so it is not a fallback that
// happened not to fire.
func TestEvaluatedProtocolMappersNameTheirContainer(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()
	token := adminToken(t, h)

	c := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "gloak-probe-ev-mapper-client",
		Name: "Probe Client Name", Enabled: true, PublicClient: true,
		RedirectURIs: []string{}, WebOrigins: []string{},
		// Named rather than inherited, because Clients().Create attaches from
		// these two lists and a nil pair attaches nothing - so a client built
		// straight in the store has no scope at all unless it says so.
		DefaultClientScopes:  []string{"profile", "email"},
		OptionalClientScopes: []string{},
		ProtocolMappers: []model.ProtocolMapper{{
			ID: model.NewID(), Name: "gloak-probe-direct", Protocol: "openid-connect",
			ProtocolMapper: "oidc-hardcoded-claim-mapper",
		}},
	}
	if err := s.Clients().Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rec := get(t, h, "/admin/realms/master/clients/"+c.ID+"/evaluate-scopes/protocol-mappers", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	var rows []protocolMapperEvaluationRepresentation
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var own, scoped int
	for _, row := range rows {
		switch row.ContainerType {
		case containerTypeClient:
			own++
			if row.ContainerName != "" {
				t.Errorf("a client's own mapper names container %q; measured empty even "+
					"on a client carrying a name", row.ContainerName)
			}
			if row.ContainerID != c.ID {
				t.Errorf("containerId = %q, want the client's own id", row.ContainerID)
			}
		case containerTypeClientScope:
			scoped++
			if row.ContainerName == "" {
				t.Errorf("a client scope's mapper names no container; its name is measured present")
			}
		default:
			t.Errorf("containerType %q; only %q and %q are measured",
				row.ContainerType, containerTypeClient, containerTypeClientScope)
		}
	}
	if own != 1 {
		t.Errorf("%d rows of the client's own mappers, want 1", own)
	}
	if scoped == 0 {
		t.Error("no client-scope rows at all; the control for the assertion above is vacuous")
	}
	// The client's own mappers come last, measured.
	if len(rows) == 0 || rows[len(rows)-1].ContainerType != containerTypeClient {
		t.Error("the client's own mapper is not last")
	}
}

// makeRealmRole is a realm role created straight in the store, which is what a
// test arranging scope wants: the API path for this is another chapter's.
func makeRealmRole(t *testing.T, s store.Store, realm *model.Realm, name string) *model.Role {
	t.Helper()
	r := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: name}
	if err := s.Roles().Create(context.Background(), r); err != nil {
		t.Fatalf("Create(%s): %v", name, err)
	}
	return r
}

// sameSet compares two name lists ignoring order, because the order these
// listings come back in is the one thing the conformance cases mask.
func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		if seen[w] == 0 {
			return false
		}
		seen[w]--
	}
	return true
}
