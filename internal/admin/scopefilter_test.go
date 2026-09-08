package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// scopedClient creates a client with fullScopeAllowed as given and scope-maps
// the named master-realm roles into it, then returns it.
//
// It writes to the store rather than going through the API because the API's
// own scope-mapping writes are guarded by the very predicate these tests are
// about, and a setup that has to pass a guard cannot be used to test it.
func scopedClient(t *testing.T, s store.Store, realm *model.Realm, clientID string,
	full bool, scoped ...string,
) *model.Client {
	t.Helper()
	ctx := context.Background()
	c := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: clientID, Enabled: true,
		Protocol: "openid-connect", PublicClient: true,
		DirectAccessGrantsEnabled: true, FullScopeAllowed: full,
	}
	if err := s.Clients().Create(ctx, c); err != nil {
		t.Fatalf("Clients().Create(%s): %v", clientID, err)
	}
	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID(master-realm): %v", err)
	}
	for _, name := range scoped {
		r, err := s.Roles().ByName(ctx, realm.ID, container.ID, name)
		if err != nil {
			t.Fatalf("Roles().ByName(%s): %v", name, err)
		}
		if err := s.Roles().AddClientScopeMapping(ctx, c.ID, r.ID); err != nil {
			t.Fatalf("AddClientScopeMapping(%s): %v", name, err)
		}
	}
	return c
}

// tokenForClient is tokenFor through a client other than admin-cli, which is
// the whole difficulty of this chapter: admin-cli's fullScopeAllowed is on, so
// no token minted through it can see the filter.
func tokenForClient(t *testing.T, h http.Handler, clientID, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token for %q at %q: %d %s", username, clientID, w.Code, w.Body)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := decodeJSON(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body.AccessToken
}

// administrator creates a user holding the realm role admin, which is composite
// over all 21 of master-realm's roles plus create-realm. Every test below rests
// on the user being a full administrator, so that a refusal can only be about
// the client its token came from.
func administrator(t *testing.T, s store.Store, realm *model.Realm, username string) *model.User {
	t.Helper()
	ctx := context.Background()
	u := createUserWithPassword(t, s, realm, username, "pw")
	r, err := s.Roles().ByName(ctx, realm.ID, "", "admin")
	if err != nil {
		t.Fatalf("Roles().ByName(admin): %v", err)
	}
	if err := s.Roles().AssignToUser(ctx, u.ID, r.ID); err != nil {
		t.Fatalf("AssignToUser(admin): %v", err)
	}
	return u
}

// TestGrantsAreComputedFromTheRolesTheCallerHolds pins the half of F198 that no
// golden can reach: the **conferral** predicate behind mayGrantRole is not
// scope-filtered, although every route guard on this API is.
//
// Measured 2026-09-08 on a live 26.7.1, on three callers and the same write:
//
//	full administrator through a flag-off client scoping manage-users
//	                                     hands out manage-realm   204, available 21
//	a user genuinely holding manage-users and manage-clients
//	                                     hands out manage-realm   403, available 12
//	full administrator through admin-cli  hands out manage-realm   204, available 21
//
// So the first row answers what the third answers and not what the second does,
// although the first row's *route guard* answers what the second's does - it is
// admitted here by manage-users, which is the only admin role its token scope
// carries. Two questions, two sets, one request.
//
// **Both directions are asserted.** The refusal below is what stops the answer
// being "this caller may hand out anything", which a test checking only the 204
// would accept: the same flag-off client, scoping the same manage-users, over a
// user that is *not* an administrator, is refused the same role.
func TestGrantsAreComputedFromTheRolesTheCallerHolds(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()

	scopedClient(t, s, realm, "narrow-manage-users", false, "manage-users")
	administrator(t, s, realm, "scoped-admin")
	subject := createUserWithPassword(t, s, realm, "grant-subject", "pw")

	container, err := s.Clients().ByClientID(ctx, realm.ID, "master-realm")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	manageRealm, err := s.Roles().ByName(ctx, realm.ID, container.ID, "manage-realm")
	if err != nil {
		t.Fatalf("ByName(manage-realm): %v", err)
	}
	path := "/admin/realms/master/users/" + subject.ID + "/role-mappings/clients/" + container.ID
	body := `[{"id":"` + manageRealm.ID + `","name":"manage-realm"}]`

	// The flag-off caller. Its token scope carries manage-users alone, which is
	// what admits it to this route at all, and the role it hands out is one
	// manage-users does not confer.
	scopedAdmin := tokenForClient(t, h, "narrow-manage-users", "scoped-admin", "pw")
	if w := post(t, h, path, scopedAdmin, "application/json", body); w.Code != http.StatusNoContent {
		t.Errorf("a full administrator through a flag-off client granting manage-realm = %d %s, want 204",
			w.Code, w.Body)
	}

	// The control that makes it a statement about the *source* of the set: a
	// caller who really holds manage-users and nothing more is refused, through
	// a client whose flag is on.
	held := tokenForRoles(t, h, s, realm, "manage-users")
	if w := post(t, h, path, held, "application/json", body); w.Code != http.StatusForbidden {
		t.Errorf("a caller genuinely holding manage-users granting manage-realm = %d %s, want 403",
			w.Code, w.Body)
	}

	// And the other direction on the flag-off client: an ordinary user reaching
	// the same route through it is refused, so the 204 above is about the roles
	// the caller holds and not about the client opening everything.
	createUserWithPassword(t, s, realm, "scoped-nobody", "pw")
	plain, err := s.Users().ByUsername(ctx, realm.ID, "scoped-nobody")
	if err != nil {
		t.Fatalf("ByUsername: %v", err)
	}
	manageUsers, err := s.Roles().ByName(ctx, realm.ID, container.ID, "manage-users")
	if err != nil {
		t.Fatalf("ByName(manage-users): %v", err)
	}
	if err := s.Roles().AssignToUser(ctx, plain.ID, manageUsers.ID); err != nil {
		t.Fatalf("AssignToUser(manage-users): %v", err)
	}
	scopedPlain := tokenForClient(t, h, "narrow-manage-users", "scoped-nobody", "pw")
	if w := post(t, h, path, scopedPlain, "application/json", body); w.Code != http.StatusForbidden {
		t.Errorf("a manage-users holder through the same flag-off client granting manage-realm = %d %s, want 403",
			w.Code, w.Body)
	}
}

// TestWorkflowsReadsTheRolesTheCallerHolds pins the one family of the 79 routes
// swept that is not scope-filtered.
//
// Measured 2026-09-08: a full administrator through a client with
// fullScopeAllowed off and nothing mapped answers 403 on every other route on
// this API and **200** on GET .../workflows, while a caller holding only
// create-realm answers 403 there through either client. So the family
// authorises, and it authorises against the roles the caller really holds.
//
// The golden `admin/workflows/scope-filtered-held-roles` asserts the 200. This
// asserts the refusal beside it, which is what stops the answer being "the
// Workflows guard admits everybody" - a mutation that drops the check entirely
// passes the golden and fails here.
func TestWorkflowsReadsTheRolesTheCallerHolds(t *testing.T) {
	h, s, realm := newServer(t)

	scopedClient(t, s, realm, "narrow-nothing", false)
	administrator(t, s, realm, "workflow-admin")

	scoped := tokenForClient(t, h, "narrow-nothing", "workflow-admin", "pw")
	if w := get(t, h, "/admin/realms/master/workflows", scoped); w.Code != http.StatusOK {
		t.Errorf("workflows for a full administrator through a flag-off client = %d %s, want 200",
			w.Code, w.Body)
	}
	// The same token on a neighbouring route, so the 200 above is the family's
	// answer and not a client that opens everything.
	if w := get(t, h, "/admin/realms/master/users", scoped); w.Code != http.StatusForbidden {
		t.Errorf("the user listing for the same token = %d %s, want 403", w.Code, w.Body)
	}
	// And a caller that is not an administrator, through the same flag-off
	// client: the family still refuses it.
	createUserWithPassword(t, s, realm, "workflow-nobody", "pw")
	plain := tokenForClient(t, h, "narrow-nothing", "workflow-nobody", "pw")
	if w := get(t, h, "/admin/realms/master/workflows", plain); w.Code != http.StatusForbidden {
		t.Errorf("workflows for a caller holding no admin role = %d %s, want 403", w.Code, w.Body)
	}
	// The mirror on the other side of the flag: a caller holding manage-users
	// through a full-scope client is refused, because the family takes `admin`
	// and nothing else.
	held := tokenForRoles(t, h, s, realm, "manage-users")
	if w := get(t, h, "/admin/realms/master/workflows", held); w.Code != http.StatusForbidden {
		t.Errorf("workflows for a manage-users holder = %d %s, want 403", w.Code, w.Body)
	}
}

// TestScopeFilterRefusesATokenWhoseClientIsGone pins inTokenScope's missing
// client, which no case can reach: a client delete cascades the client session
// and not the user session, so a token minted by a deleted client still
// verifies, still resolves to a live user session, and reaches the lookup.
//
// **Measured rather than chosen.** On a live 26.7.1 a token was minted at a
// client and the client deleted; the same request that had answered 200 through
// a flag-on client and 403 through a flag-off one answered **401** through both
// afterwards. That is not internal/account's answer to the same shape - its
// gate refuses with an empty role set, which is a 401 there for a different
// reason - and it is not a fall-open, which is what the control below rules out.
func TestScopeFilterRefusesATokenWhoseClientIsGone(t *testing.T) {
	h, s, realm := newServer(t)
	ctx := context.Background()

	c := scopedClient(t, s, realm, "doomed-client", true)
	administrator(t, s, realm, "doomed-admin")
	tok := tokenForClient(t, h, "doomed-client", "doomed-admin", "pw")

	// The control: while the client exists, this administrator reads the realm.
	if w := get(t, h, "/admin/realms/master", tok); w.Code != http.StatusOK {
		t.Fatalf("before the delete = %d %s, want 200", w.Code, w.Body)
	}
	if err := s.Clients().Delete(ctx, realm.ID, c.ID); err != nil {
		t.Fatalf("Clients().Delete: %v", err)
	}
	w := get(t, h, "/admin/realms/master", tok)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("after the delete = %d %s, want 401", w.Code, w.Body)
	}
	if got := w.Body.String(); got != `{"error":"HTTP 401 Unauthorized"}` {
		t.Errorf("body = %s, want the measured 401", got)
	}
}
