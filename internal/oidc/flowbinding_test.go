package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The three bindings F103's shape-three cut makes between the stored
// authentication flow model and the browser login. Each was measured on a live
// 26.7.1 before it was written, and each has a test here whose failure names
// which binding broke rather than which page changed.
//
// They are in package oidc_test rather than oidc because every one of them is a
// claim about what a browser observes. A test that called the binding function
// directly would pass while the login went on using the old constant, which is
// exactly the failure mode this cut is paying off.

// browserFlowExecutions is the realm's bound browser flow's rows, walked the
// way the binding walks them, so a test can name the row it expects the login
// to have used.
func browserFlowExecutions(t *testing.T, s store.Store, realm *model.Realm,
	authenticator string) *model.AuthenticationExecution {
	t.Helper()
	ctx := context.Background()
	flows, err := s.AuthenticationFlows().ListFlows(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	byID := map[string]*model.AuthenticationFlow{}
	var root *model.AuthenticationFlow
	for _, f := range flows {
		byID[f.ID] = f
		if f.TopLevel && f.Alias != nil && *f.Alias == "browser" {
			root = f
		}
	}
	if root == nil {
		t.Fatal("the realm has no top-level flow aliased browser")
	}
	var walk func(string) *model.AuthenticationExecution
	walk = func(id string) *model.AuthenticationExecution {
		rows, err := s.AuthenticationFlows().ListExecutions(ctx, realm.ID, id)
		if err != nil {
			t.Fatalf("ListExecutions: %v", err)
		}
		for _, e := range rows {
			if e.Authenticator == authenticator {
				return e
			}
			if e.FlowID != "" && byID[e.FlowID] != nil {
				if found := walk(e.FlowID); found != nil {
					return found
				}
			}
		}
		return nil
	}
	found := walk(root.ID)
	if found == nil {
		t.Fatalf("the browser flow has no %s row", authenticator)
	}
	return found
}

func masterRealm(t *testing.T, s store.Store) *model.Realm {
	t.Helper()
	realm, err := s.Realms().ByName(context.Background(), "master")
	if err != nil {
		t.Fatalf("ByName(master): %v", err)
	}
	return realm
}

// TestExecutionParameterIsTheUsernamePasswordExecutionID is binding B2, and it
// is the pivot the whole shape-three argument turns on.
//
// Before this cut the login form's `execution` parameter was
// `sha256("gloak-login-execution:" + realm.ID)` - a fabrication, and its own
// doc comment said so. Keycloak's value is the id of the
// `auth-username-password-form` execution inside the realm's bound browser
// flow, measured on two realms of one container whose two values differed and
// each matched its own realm's row.
//
// The assertion is the equality, not the format. A hash is a valid UUID shape,
// so "it looks like a uuid" would pass on the old code.
func TestExecutionParameterIsTheUsernamePasswordExecutionID(t *testing.T) {
	h, s := authServerAndStore(t)
	realm := masterRealm(t, s)
	row := browserFlowExecutions(t, s, realm, "auth-username-password-form")

	b := &browser{h: h, t: t, jar: map[string]string{}}
	action := b.login(nil)
	_, params := actionParams(t, action)

	got := params.Get("execution")
	if got == "" {
		t.Fatal("the login form's action carries no execution parameter")
	}
	if got != row.ID {
		t.Fatalf("the login page emitted execution=%q; the browser flow's "+
			"auth-username-password-form row is %q. This is binding B2: the "+
			"parameter is that row's id, not a hash of the realm id.", got, row.ID)
	}
}

// TestTheExecutionParameterIsAcceptedByTheEndpointThatChecksIt is the other
// half of B2, and it exists because the two halves are two call sites.
//
// `/login-actions/authenticate` compares the submitted `execution` against the
// same value. If only one of the two sites were moved the login would break;
// if only the *page* were moved and the check left on the hash, a login would
// answer "Page has expired" and no test that read the page would notice.
func TestTheExecutionParameterIsAcceptedByTheEndpointThatChecksIt(t *testing.T) {
	h, s := authServerAndStore(t)
	realm := masterRealm(t, s)
	row := browserFlowExecutions(t, s, realm, "auth-username-password-form")

	b := &browser{h: h, t: t, jar: map[string]string{}}
	action := b.login(nil)
	target, params := actionParams(t, action)

	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("login with the page's own execution: want 302, got %d\n%s", w.Code, w.Body)
	}

	// The control, which is what says the check runs at all: the same request
	// with a different execution answers the expired page instead.
	b2 := &browser{h: h, t: t, jar: map[string]string{}}
	action2 := b2.login(nil)
	_, params2 := actionParams(t, action2)
	wrong := replaceParam(action2, params2, "execution", "gloak-test-not-the-execution")
	u, err := url.Parse(wrong)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	w := b2.do(http.MethodPost, u.Path+"?"+u.RawQuery, credentials("admin", "admin"))
	if w.Code != http.StatusOK {
		t.Fatalf("a wrong execution: want 200 with the expired page, got %d", w.Code)
	}
	if params.Get("execution") != row.ID || params2.Get("execution") != row.ID {
		t.Fatalf("the two pages emitted %q and %q, want the row id %q",
			params.Get("execution"), params2.Get("execution"), row.ID)
	}
}

// TestLoginWalksTheRealmsBoundBrowserFlow is binding B1.
//
// The realm's `browserFlow` selects which top-level flow the login reads. It
// was served on every realm representation and read by nothing before this cut,
// which is F103's own complaint with an example already shipped.
//
// The test moves the binding to a copy of the flow and asserts the `execution`
// parameter follows it. A login that resolved the alias `browser` literally
// would keep emitting the old row's id.
func TestLoginWalksTheRealmsBoundBrowserFlow(t *testing.T) {
	h, s := authServerAndStore(t)
	ctx := context.Background()
	realm := masterRealm(t, s)
	original := browserFlowExecutions(t, s, realm, "auth-username-password-form")

	b := &browser{h: h, t: t, jar: map[string]string{}}
	_, before := actionParams(t, b.login(nil))
	if before.Get("execution") != original.ID {
		t.Fatalf("before the rebind the page emitted %q, want %q",
			before.Get("execution"), original.ID)
	}

	// A second top-level flow holding its own username-password row, aliased so
	// it cannot be confused with the seeded one.
	alias := "gloak-test-second-browser"
	second := &model.AuthenticationFlow{
		ID: model.NewID(), RealmID: realm.ID, Alias: &alias,
		Description: "a second browser flow", ProviderID: "basic-flow",
		TopLevel: true, BuiltIn: false,
	}
	if err := s.AuthenticationFlows().CreateFlow(ctx, second); err != nil {
		t.Fatalf("CreateFlow: %v", err)
	}
	row := &model.AuthenticationExecution{
		ID: model.NewID(), RealmID: realm.ID, ParentFlowID: second.ID,
		Authenticator: "auth-username-password-form", Requirement: "REQUIRED", Priority: 10,
	}
	if err := s.AuthenticationFlows().CreateExecution(ctx, row); err != nil {
		t.Fatalf("CreateExecution: %v", err)
	}
	if row.ID == original.ID {
		t.Fatal("the two rows share an id, so this test could not tell them apart")
	}

	setRealmSetting(t, s, realm, "browserFlow", alias)

	b2 := &browser{h: h, t: t, jar: map[string]string{}}
	_, after := actionParams(t, b2.login(nil))
	if after.Get("execution") != row.ID {
		t.Fatalf("after binding browserFlow to %q the page emitted %q, want the "+
			"new flow's row %q. This is binding B1: the realm's browserFlow "+
			"selects the flow, it is not the literal alias \"browser\".",
			alias, after.Get("execution"), row.ID)
	}
}

// TestAnUnresolvableBrowserFlowFallsBackRatherThanFailing pins the fallback the
// binding needs to be safe.
//
// A `browserFlow` naming a flow that does not exist is a state a caller reaches
// through the Admin API - a rename of `browser` is a 204 - and a login that
// 500s because of it would be a worse answer than a stable one.
func TestAnUnresolvableBrowserFlowFallsBackRatherThanFailing(t *testing.T) {
	h, s := authServerAndStore(t)
	realm := masterRealm(t, s)
	setRealmSetting(t, s, realm, "browserFlow", "gloak-test-no-such-flow")

	b := &browser{h: h, t: t, jar: map[string]string{}}
	action := b.login(nil)
	target, params := actionParams(t, action)
	if params.Get("execution") == "" {
		t.Fatal("the page carries no execution parameter at all")
	}
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("a login against an unresolvable browserFlow: want 302, got %d\n%s", w.Code, w.Body)
	}
}

// TestDisablingAuthCookieStopsTheSSOShortCircuit is binding B3.
//
// Measured on a live 26.7.1 with one cookie jar and one unchanged GET /auth:
// with `auth-cookie` ALTERNATIVE the request answered 302 with a code, with it
// DISABLED it answered 200 and the login page, and restored to ALTERNATIVE it
// answered 302 again. Three states, and the revert reverted.
//
// The test does the same three, in that order, because two states would not
// distinguish "the flag is read" from "something else broke SSO".
func TestDisablingAuthCookieStopsTheSSOShortCircuit(t *testing.T) {
	h, s := authServerAndStore(t)
	ctx := context.Background()
	realm := masterRealm(t, s)
	cookieRow := browserFlowExecutions(t, s, realm, "auth-cookie")
	if cookieRow.Requirement != "ALTERNATIVE" {
		t.Fatalf("the seeded auth-cookie row is %q, want ALTERNATIVE", cookieRow.Requirement)
	}

	b := &browser{h: h, t: t, jar: map[string]string{}}
	action := b.login(nil)
	target, _ := actionParams(t, action)
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("login: want 302, got %d\n%s", w.Code, w.Body)
	}

	// State one: seeded. SSO short-circuits.
	if code := authorizeStatus(b); code != http.StatusFound {
		t.Fatalf("with auth-cookie ALTERNATIVE a live session answered %d, want 302", code)
	}

	// State two: DISABLED. The same jar, the same request, the login page.
	cookieRow.Requirement = "DISABLED"
	if err := s.AuthenticationFlows().UpdateExecution(ctx, cookieRow); err != nil {
		t.Fatalf("UpdateExecution: %v", err)
	}
	if code := authorizeStatus(b); code != http.StatusOK {
		t.Fatalf("with auth-cookie DISABLED a live session answered %d, want 200 "+
			"with the login page. This is binding B3.", code)
	}

	// State three: restored. The revert has to revert.
	cookieRow.Requirement = "ALTERNATIVE"
	if err := s.AuthenticationFlows().UpdateExecution(ctx, cookieRow); err != nil {
		t.Fatalf("UpdateExecution: %v", err)
	}
	if code := authorizeStatus(b); code != http.StatusFound {
		t.Fatalf("after restoring ALTERNATIVE a live session answered %d, want 302 - "+
			"the revert did not revert", code)
	}
}

// TestARealmWithNoSeededFlowStillLogsIn is the compatibility half of both
// bindings: a store written before migration 0030 has no flow rows at all, and
// both fall back rather than refusing.
func TestARealmWithNoSeededFlowStillLogsIn(t *testing.T) {
	h, s := authServerAndStore(t)
	ctx := context.Background()
	realm := masterRealm(t, s)

	flows, err := s.AuthenticationFlows().ListFlows(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("the realm seeded no flows, so this test proves nothing")
	}
	for _, f := range flows {
		if !f.TopLevel {
			continue
		}
		if err := s.AuthenticationFlows().DeleteFlow(ctx, realm.ID, f.ID); err != nil {
			t.Fatalf("DeleteFlow(%s): %v", f.ID, err)
		}
	}

	b := &browser{h: h, t: t, jar: map[string]string{}}
	action := b.login(nil)
	target, params := actionParams(t, action)
	if params.Get("execution") == "" {
		t.Fatal("with no flows the page carries no execution parameter")
	}
	if w := b.do(http.MethodPost, target, credentials("admin", "admin")); w.Code != http.StatusFound {
		t.Fatalf("a login against a realm with no flow model: want 302, got %d\n%s", w.Code, w.Body)
	}
	// SSO is enabled when there is no auth-cookie row to consult, which is what
	// every realm did before this cut.
	if code := authorizeStatus(b); code != http.StatusFound {
		t.Fatalf("with no flow model a live session answered %d, want 302", code)
	}
}

// authorizeStatus issues one GET /auth on an existing jar and returns the
// status, which is the whole of what the SSO short-circuit changes.
func authorizeStatus(b *browser) int {
	b.t.Helper()
	w := b.do(http.MethodGet,
		"/realms/master/protocol/openid-connect/auth?"+baseQuery(nil), nil)
	return w.Code
}

// setRealmSetting rewrites one key of the realm's Settings blob, which is where
// the seven flow bindings live. model.Realm has no column for any of them, and
// that is the point: browserFlow was round-tripping through this blob and being
// read by nothing.
func setRealmSetting(t *testing.T, s store.Store, realm *model.Realm, key, value string) {
	t.Helper()
	ctx := context.Background()
	settings := map[string]any{}
	if len(realm.Settings) > 0 {
		if err := json.Unmarshal(realm.Settings, &settings); err != nil {
			t.Fatalf("parse settings: %v", err)
		}
	}
	settings[key] = value
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	realm.Settings = raw
	if err := s.Realms().Update(ctx, realm); err != nil {
		t.Fatalf("Realms().Update: %v", err)
	}
}
