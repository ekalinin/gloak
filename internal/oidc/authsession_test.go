package oidc

import (
	"encoding/base64"
	"testing"
	"time"
)

// The store's tests are in-package because two of the things worth guarding are
// not reachable from outside: the expiry rules need the injectable clock, and
// the authorization code's single-use rule has no caller yet - the token
// endpoint's authorization_code grant is the next cut. A helper with no caller
// and no test is how a wrong one ships.

// testSessionHash is a stand-in for sessionHash's output: 48 bytes in standard
// base64, which is the measured shape of KC_AUTH_SESSION_HASH. It is a constant
// rather than a call so that the store's tests need no realm keys.
const testSessionHash = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"

func testStore(t *testing.T) (*authStore, *time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	s := newAuthStore()
	s.now = func() time.Time { return now }
	return s, &now
}

func newTestSession(t *testing.T, s *authStore) (*authSession, *authTab) {
	t.Helper()
	tab := &authTab{TabID: "tab-1", ClientID: "probe", ClientUUID: "uuid-1",
		RedirectURI: "http://localhost:9999/callback"}
	// The root id and the hash are the caller's now, because the SSO branch has
	// to supply the user session's own id rather than mint one. The values here
	// stand in for what resumeAuthSession derives; the lengths are the measured
	// ones, which is what the tests below read.
	rootID, err := randomBase64URL(rootIDBytes)
	if err != nil {
		t.Fatalf("randomBase64URL: %v", err)
	}
	sess, err := s.newAuthSession("master", rootID, testSessionHash, tab)
	if err != nil {
		t.Fatalf("newAuthSession: %v", err)
	}
	if _, err := s.rotateSessionCode(sess, tab, ""); err != nil {
		t.Fatalf("rotateSessionCode: %v", err)
	}
	return sess, tab
}

// TestMintedIdentifiersHaveTheMeasuredLengths. Every one of these is a value a
// client sees, and every one was counted off a live 26.7.1 login.
func TestMintedIdentifiersHaveTheMeasuredLengths(t *testing.T) {
	s, _ := testStore(t)
	sess, tab := newTestSession(t, s)

	for _, tc := range []struct {
		name  string
		value string
		want  int
	}{
		{"the root id, which becomes session_state", sess.RootID, 24},
		{"the AUTH_SESSION_ID secret", sess.Secret, 86},
		{"KC_AUTH_SESSION_HASH", sess.Hash, 64},
		{"the session code", tab.SessionCode, 43},
	} {
		if got := len(tc.value); got != tc.want {
			t.Errorf("%s: want %d characters, got %d (%q)", tc.name, tc.want, got, tc.value)
		}
	}
	// The hash is the one value in the flow that is **standard** base64 rather
	// than base64url, which is what makes keycloakSessionValue necessary.
	if _, err := base64.StdEncoding.DecodeString(sess.Hash); err != nil {
		t.Errorf("KC_AUTH_SESSION_HASH is not standard base64: %v", err)
	}
	for _, v := range []string{sess.RootID, sess.Secret, tab.SessionCode} {
		if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
			t.Errorf("%q is not unpadded base64url: %v", v, err)
		}
	}
}

// TestAuthSessionCookieRoundTripsAndIsBound. The cookie names the session and
// carries a secret; a request presenting the right root id and a wrong secret
// is not that session, and neither realm may borrow the other's.
func TestAuthSessionCookieRoundTripsAndIsBound(t *testing.T) {
	s, _ := testStore(t)
	sess, _ := newTestSession(t, s)
	cookie := encodeAuthSessionID(sess.RootID, sess.Secret)

	if got, ok := s.sessionByCookie("master", cookie); !ok || got.RootID != sess.RootID {
		t.Fatalf("the session did not resolve from its own cookie")
	}
	if _, ok := s.sessionByCookie("other", cookie); ok {
		t.Errorf("another realm resolved this realm's session cookie")
	}
	forged := encodeAuthSessionID(sess.RootID, "not-the-secret")
	if _, ok := s.sessionByCookie("master", forged); ok {
		t.Errorf("a cookie with the right root id and a wrong secret resolved")
	}
	for _, bad := range []string{"", "!!!!", base64.RawURLEncoding.EncodeToString([]byte("no-dot"))} {
		if _, ok := s.sessionByCookie("master", bad); ok {
			t.Errorf("%q resolved to a session", bad)
		}
	}
}

// TestExpiredSessionCodeIsTheSameCaseAsASpentOne is measured, by shortening the
// realm's accessCodeLifespanLogin to a second: a code that has timed out takes
// the identical branch a replayed one takes. So the store must forget the
// session rather than reporting a distinguishable "expired".
func TestExpiredSessionCodeIsTheSameCaseAsASpentOne(t *testing.T) {
	s, now := testStore(t)
	sess, tab := newTestSession(t, s)
	code := tab.SessionCode

	if _, ok := s.tabByCode(sess, tab.TabID, code); !ok {
		t.Fatalf("a fresh session code did not resolve")
	}
	*now = now.Add(authSessionLifespan + time.Second)
	if _, ok := s.tabByCode(sess, tab.TabID, code); ok {
		t.Errorf("an expired session code still resolved")
	}
	if _, ok := s.sessionByCookie("master", encodeAuthSessionID(sess.RootID, sess.Secret)); ok {
		t.Errorf("an expired session still resolved from its cookie")
	}
}

// TestEndSessionMakesTheCodeUnreplayable is what a completed login does, and it
// is why a replayed session_code has nothing left to replay against.
func TestEndSessionMakesTheCodeUnreplayable(t *testing.T) {
	s, _ := testStore(t)
	sess, tab := newTestSession(t, s)
	s.endSession(sess.RootID)
	if _, ok := s.tabByCode(sess, tab.TabID, tab.SessionCode); ok {
		t.Errorf("the session code still resolved after the login completed")
	}
	if _, ok := s.tabByID(sess, tab.TabID); ok {
		t.Errorf("the tab still resolved after the login completed")
	}
}

// TestAuthorizationCodeIsSpentOnFirstUse. **A failed exchange spends the code
// too**: measured, a wrong code_verifier answers "PKCE verification failed:
// Code mismatch" and the immediate retry answers "Code not valid". So the store
// removes the code before the caller has decided whether to accept it, and
// single use means single *attempt*.
func TestAuthorizationCodeIsSpentOnFirstUse(t *testing.T) {
	s, now := testStore(t)
	code, err := s.newCode(&authCode{
		Realm: "master", ClientUUID: "uuid-1", SessionID: "sess-1",
		RedirectURI: "http://localhost:9999/callback",
	})
	if err != nil {
		t.Fatalf("newCode: %v", err)
	}
	got, ok := s.spendCode("master", code)
	if !ok || got.SessionID != "sess-1" {
		t.Fatalf("the code did not redeem")
	}
	if _, ok := s.spendCode("master", code); ok {
		t.Errorf("the code redeemed a second time")
	}

	// Another realm's code is not this realm's, and it is spent all the same -
	// a rejected attempt still burns it.
	second, err := s.newCode(&authCode{Realm: "master", ClientUUID: "uuid-1", SessionID: "sess-2"})
	if err != nil {
		t.Fatalf("newCode: %v", err)
	}
	if _, ok := s.spendCode("other", second); ok {
		t.Errorf("another realm redeemed this realm's code")
	}
	if _, ok := s.spendCode("master", second); ok {
		t.Errorf("a code rejected for the wrong realm was not spent by the attempt")
	}

	// And expiry: the measured accessCodeLifespan is 60 seconds.
	third, err := s.newCode(&authCode{Realm: "master", ClientUUID: "uuid-1", SessionID: "sess-3"})
	if err != nil {
		t.Fatalf("newCode: %v", err)
	}
	*now = now.Add(authCodeLifespan + time.Second)
	if _, ok := s.spendCode("master", third); ok {
		t.Errorf("an expired code redeemed")
	}
}

// TestCodeCarriesTheSessionStateAndTheClientUUID pins the two parts of the code
// that are not random. The third is the client's own internal UUID, which is
// identical on every login by any user at that client.
func TestCodeCarriesTheSessionStateAndTheClientUUID(t *testing.T) {
	s, _ := testStore(t)
	code, err := s.newCode(&authCode{Realm: "master", ClientUUID: "the-client-uuid",
		SessionID: "the-session-state"})
	if err != nil {
		t.Fatalf("newCode: %v", err)
	}
	want := ".the-session-state.the-client-uuid"
	if len(code) <= len(want) || code[len(code)-len(want):] != want {
		t.Errorf("code %q does not end in %q", code, want)
	}
}

// TestKeycloakSessionValueIsTheHashInBase64URL is the pair of cookies that
// carry one value in two alphabets, isolated from the handler so the rule is
// stated once and checked once.
func TestKeycloakSessionValueIsTheHashInBase64URL(t *testing.T) {
	const hash = "a+b/c+d/e"
	if got, want := keycloakSessionValue(hash), "a-b_c-d_e"; got != want {
		t.Errorf("want %q, got %q", got, want)
	}
}

// TestExecutionIDIsStableAndPerRealm. Keycloak's execution is the id of the
// realm's username-password-form execution: measured stable across logins in
// one container while the other four action parameters vary per request.
func TestExecutionIDIsStableAndPerRealm(t *testing.T) {
	if executionID("realm-a") != executionID("realm-a") {
		t.Errorf("executionID is not stable for one realm")
	}
	if executionID("realm-a") == executionID("realm-b") {
		t.Errorf("two realms share an execution id")
	}
	if got := len(executionID("realm-a")); got != 36 {
		t.Errorf("execution id is %d characters, Keycloak's is a 36-character UUID", got)
	}
}

// TestValidClientDataAcceptsAbsentAndRejectsRubbish is the pair of measurements
// that makes client_data a hint rather than an input: dropping it succeeds, and
// corrupting it is a 400.
func TestValidClientDataAcceptsAbsentAndRejectsRubbish(t *testing.T) {
	good, err := encodeClientData("http://localhost:9999/callback", "code", "", "xyz", true)
	if err != nil {
		t.Fatalf("encodeClientData: %v", err)
	}
	for _, tc := range []struct {
		raw  string
		want bool
	}{
		{"", true},
		{good, true},
		{"!!!!", false},
		{base64.RawURLEncoding.EncodeToString([]byte("not json")), false},
	} {
		if got := validClientData(tc.raw); got != tc.want {
			t.Errorf("validClientData(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
