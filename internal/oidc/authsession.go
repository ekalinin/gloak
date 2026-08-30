package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ekalinin/gloak/internal/keys"
)

// The authentication session is what carries state from GET /auth to
// POST /login-actions/authenticate, and it lives in memory.
//
// **That is the faithful model, not a shortcut.** Keycloak keeps authentication
// sessions and authorization codes in Infinispan caches rather than in the
// database, because both are short-lived: an authentication session lasts one
// login attempt and a code is spent on first use. Neither is in Keycloak's
// schema either.
//
// What it does mean is that this cut is **single-process**. Two Gloak replicas
// behind a load balancer will not share an authentication session or a code, so
// a login that starts on one and finishes on the other restarts. Realm signing
// keys are persisted precisely so that two replicas agree, and this is the
// opposite decision on the neighbouring piece of state. It is filed as a
// follow-up with the design rather than left to be discovered.
//
// Every length below is measured against a live 26.7.1 on 2026-08-30; see
// section 1.1 of docs/superpowers/plans/2026-08-30-p13-login.md.
const (
	// rootIDBytes makes a 24-character base64url root id, which is the value
	// that ends up in session_state, in the code's second part and in
	// KEYCLOAK_IDENTITY's sid.
	rootIDBytes = 18
	// tabIDBytes makes an 11-character base64url tab id.
	tabIDBytes = 8
	// sessionCodeBytes makes a 43-character base64url session code.
	sessionCodeBytes = 32
	// authHashBytes makes the 64-character **standard** base64 value
	// KC_AUTH_SESSION_HASH carries, quoted, and KEYCLOAK_SESSION carries with
	// "+/" rewritten to "-_".
	//
	// It is derived rather than drawn; see sessionHash for why.
	authHashBytes = 48
	// cookieSecretBytes makes the 86-character second half of AUTH_SESSION_ID's
	// decoded value. Keycloak's is a signature; nothing observable says over
	// what, so Gloak's is a random string it stores and compares. The shape is
	// measured, the contents are not observable, and pretending to a signature
	// nobody can verify would be worse than saying so.
	cookieSecretBytes = 64
)

// The five cookie names the browser flow uses, spelled once. Three are set by
// GET /auth and three by the successful login, and KC_RESTART is the one that
// appears in both lists - set on the way in and cleared on the way out.
const (
	authSessionCookie = "AUTH_SESSION_ID"
	authHashCookie    = "KC_AUTH_SESSION_HASH"
	restartCookie     = "KC_RESTART"
	identityCookie    = "KEYCLOAK_IDENTITY"
	sessionCookie     = "KEYCLOAK_SESSION"
)

// The two measured Max-Age values in the flow. KC_AUTH_SESSION_HASH's minute is
// far shorter than the session it names, and KEYCLOAK_SESSION's ten hours match
// KEYCLOAK_IDENTITY's exp - iat exactly.
const (
	authHashMaxAge        = 60 * time.Second
	keycloakSessionMaxAge = 36000 * time.Second
)

// realmCookiePath is the Path every cookie in the flow carries, **with its
// trailing slash**. Measured: `Path=/realms/master/`, not `/realms/master`.
func realmCookiePath(realm string) string {
	return "/realms/" + realm + "/"
}

// responseTypeCode is what client_data's `rt` holds for the flow this cut
// serves. It is spelled here rather than inline because client_data is written
// in three places and a typo in one of them would be invisible.
const responseTypeCode = "code"

// authSessionLifespan is how long an authentication session may sit unused
// before the login has to restart. Keycloak's is the realm's
// accessCodeLifespanLogin, 1800 seconds by default - measured by setting it to
// 1 and watching the same restart branch a spent code takes.
//
// It is a constant here rather than a realm field because the realm attribute
// is not modelled yet, and inventing a column in internal/store is not this
// cut's to do.
const authSessionLifespan = 30 * time.Minute

// authCodeLifespan is how long an authorization code may be redeemed for. The
// realm's accessCodeLifespan measured 60 seconds on a default 26.7.1.
const authCodeLifespan = 60 * time.Second

// authSession is one browser's login attempt at one realm, holding one tab per
// authorization request that browser has open.
//
// The root id is minted at GET /auth and is the session_state the flow will
// end with, which is the single fact the rest of this file rests on. Measured
// three ways at once on one login: AUTH_SESSION_ID base64-decodes to
// "<root id>.<86 chars>", the redirect's session_state is that root id,
// KEYCLOAK_IDENTITY's sid is that root id, and the authorization code's second
// part is that root id. So session_state is decided **before any credential is
// seen**, and a design that mints it at login time gets four observables wrong
// at once.
type authSession struct {
	RootID string
	Realm  string
	// Secret is the opaque half of AUTH_SESSION_ID's decoded value. A request
	// presenting the right root id and the wrong secret is not this session.
	Secret string
	// Hash is KC_AUTH_SESSION_HASH's value. KEYCLOAK_SESSION carries the same
	// bytes in the base64url alphabet, which is measured on the pair of
	// responses where both appear.
	Hash      string
	Tabs      map[string]*authTab
	ExpiresAt time.Time
}

// authTab is one authorization request inside that session. Two browser tabs at
// one client share a root id and a KC_AUTH_SESSION_HASH and have their own
// tab_id and session_code - measured, and both tabs' logins succeed and report
// the same session_state.
type authTab struct {
	TabID string
	// SessionCode is spent on use and rotated on a failed credential. Measured:
	// after a wrong password the re-served page carries a new session_code while
	// execution, tab_id and client_data are unchanged.
	SessionCode string
	ClientID    string
	ClientUUID  string
	RedirectURI string
	// ResponseMode is where the parameters go, and it is read from **here**
	// rather than from client_data, which is measured to be ignored.
	ResponseMode string
	State        string
	HasState     bool
	// Scope, Nonce and the two PKCE fields are the rest of the authorization
	// request, carried here because the **token endpoint** consumes them and
	// there is nowhere else they survive: the code's three parts are a random
	// value, the session_state and the client's UUID.
	//
	// Scope decides the token response's scope and therefore whether an id_token
	// exists at all - measured "openid profile email" for a request asking
	// scope=openid. Nonce is the ID token's nonce claim. The PKCE pair is what
	// the code_verifier is checked against, and without it the verifier check has
	// nothing to check.
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Username is echoed back into the re-served form's value attribute, the way
	// the measured page echoes it.
	Username string
	// Prompt is the authorization request's raw prompt parameter, kept because
	// the consent decision is taken **after** the credentials and prompt=consent
	// is measured to force the page on a client whose grant already exists.
	Prompt string
	// UserID is set once the credentials verify and before the consent page is
	// served, because the login and the approval are two requests: measured, the
	// login's own 302 to the consent page sets no cookies, so the user has to be
	// carried on the tab rather than in a session that does not exist yet.
	UserID string
	// DeviceUserCode is the user_code a device verification landing put here, and
	// it is what makes finishFlow two endings rather than one. It is the user
	// code and not the device code because the device code never leaves the
	// device.
	DeviceUserCode string
}

// restartRecord is what KC_RESTART holds: enough of the original authorization
// request to start the login again.
//
// Keycloak's KC_RESTART is a self-contained `dir`/`A256GCM` JWE; Gloak's cookie
// value is a handle into this map instead. The difference is not observable -
// the value is opaque to the client either way, and every conformance case in
// this flow masks Set-Cookie as volatile - but it is another thing two replicas
// would not share, and it is filed with the rest.
// It carries the PKCE pair for a reason worth spelling out: a restart that
// dropped it would let a client downgrade its own PKCE by discarding one
// cookie, and Keycloak's JWE carries the whole original request.
type restartRecord struct {
	Realm               string
	ClientID            string
	RedirectURI         string
	State               string
	HasState            bool
	ResponseMode        string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// DeviceUserCode carries a device authorization across a restart, so that a
	// browser whose device login timed out restarts into the same approval
	// rather than into an authorization request that has no client to answer.
	DeviceUserCode string
	ExpiresAt      time.Time
}

// authCode is a minted authorization code and everything the token endpoint
// will need to redeem one.
//
// It is stored whole rather than encoded into the code string. The code's three
// parts are measured to be a random UUID-shaped value, the session_state and
// the client's internal UUID - there is nowhere in them to put a redirect URI
// or a PKCE challenge, so Keycloak must be looking the rest up too.
type authCode struct {
	Code                string
	Realm               string
	ClientUUID          string
	RedirectURI         string
	UserID              string
	SessionID           string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// authStore holds every authentication session, restart record and
// authorization code this process has minted.
//
// Expired entries are swept on write rather than by a goroutine. A background
// sweeper would be a goroutine per server that the tests would have to stop,
// and the cost of walking these maps is bounded by how many logins are in
// flight, which is small by construction: an authentication session lives for
// one login and a code for sixty seconds.
type authStore struct {
	mu       sync.Mutex
	sessions map[string]*authSession
	restarts map[string]*restartRecord
	codes    map[string]*authCode
	// now is time.Now except in tests, which need to reach an expiry without
	// waiting for one.
	now func() time.Time
}

func newAuthStore() *authStore {
	return &authStore{
		sessions: map[string]*authSession{},
		restarts: map[string]*restartRecord{},
		codes:    map[string]*authCode{},
		now:      time.Now,
	}
}

// newAuthSession mints a session and its first tab, and returns both.
//
// **The root id is an argument rather than something minted here**, because the
// SSO branch needs an authentication session whose root id is the user session
// the browser already has: measured, the AUTH_SESSION_ID on an SSO redirect
// decodes to the *original* session id and a fresh opaque half. Minting one here
// would give the SSO redirect a session_state the browser had never seen.
func (s *authStore) newAuthSession(realm, rootID, hash string, tab *authTab) (*authSession, error) {
	secret, err := randomBase64URL(cookieSecretBytes)
	if err != nil {
		return nil, err
	}
	sess := &authSession{
		RootID:    rootID,
		Realm:     realm,
		Secret:    secret,
		Hash:      hash,
		Tabs:      map[string]*authTab{tab.TabID: tab},
		ExpiresAt: s.now().Add(authSessionLifespan),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.sessions[rootID] = sess
	return sess, nil
}

// addTab puts a second authorization request into an existing session, which is
// what a browser opening a second tab at the same realm produces. Measured: the
// AUTH_SESSION_ID does not change and both tabs can complete.
func (s *authStore) addTab(sess *authSession, tab *authTab) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live, ok := s.sessions[sess.RootID]
	if !ok {
		return
	}
	live.Tabs[tab.TabID] = tab
	live.ExpiresAt = s.now().Add(authSessionLifespan)
}

// sessionByCookie resolves the session a decoded AUTH_SESSION_ID names, and
// reports false when the root id is unknown, the secret does not match, the
// realm is another one or the session has expired.
//
// The realm check is not decoration. AUTH_SESSION_ID's Path is
// /realms/{realm}/, so a browser never sends one realm's cookie to another -
// but a handler that trusted the cookie's own claim about which session it is
// would be relying on the client to enforce that.
func (s *authStore) sessionByCookie(realm, cookie string) (*authSession, bool) {
	rootID, secret, ok := decodeAuthSessionID(cookie)
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[rootID]
	if !ok || sess.Realm != realm || sess.Secret != secret {
		return nil, false
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, rootID)
		return nil, false
	}
	return sess, true
}

// tabByCode resolves the tab a request names, and it insists on all three of
// tab_id, the tab's own session code and the session being live.
//
// **An expired session code and a spent one are one case, not two.** Measured
// by shortening the realm's accessCodeLifespanLogin to a second: a code that
// has timed out takes exactly the same branch a replayed one takes.
func (s *authStore) tabByCode(sess *authSession, tabID, sessionCode string) (*authTab, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live, ok := s.sessions[sess.RootID]
	if !ok || s.now().After(live.ExpiresAt) {
		return nil, false
	}
	tab, ok := live.Tabs[tabID]
	if !ok || tab.SessionCode == "" || tab.SessionCode != sessionCode {
		return nil, false
	}
	return tab, true
}

// tabByID resolves a tab without asking for a session code, which is what the
// restart landing needs: the redirect that produced it carries a tab_id and
// deliberately no session_code, and the landing request is what mints one.
func (s *authStore) tabByID(sess *authSession, tabID string) (*authTab, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	live, ok := s.sessions[sess.RootID]
	if !ok || s.now().After(live.ExpiresAt) {
		return nil, false
	}
	tab, ok := live.Tabs[tabID]
	return tab, ok
}

// rotateSessionCode mints the tab a new session code, which is what a failed
// credential does. The old one stops working; the retry uses the new one and
// succeeds.
func (s *authStore) rotateSessionCode(sess *authSession, tab *authTab, username string) (string, error) {
	code, err := randomBase64URL(sessionCodeBytes)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tab.SessionCode = code
	tab.Username = username
	if live, ok := s.sessions[sess.RootID]; ok {
		live.ExpiresAt = s.now().Add(authSessionLifespan)
	}
	return code, nil
}

// endSession removes the whole authentication session, which is what a
// completed login does: the session_code cannot be replayed afterwards because
// there is nothing left to replay it against.
func (s *authStore) endSession(rootID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, rootID)
}

// newRestart records what KC_RESTART will point at and returns the cookie value.
func (s *authStore) newRestart(rec *restartRecord) (string, error) {
	id, err := randomBase64URL(cookieSecretBytes)
	if err != nil {
		return "", err
	}
	rec.ExpiresAt = s.now().Add(authSessionLifespan)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.restarts[id] = rec
	return id, nil
}

// restartByCookie resolves a KC_RESTART value.
//
// **An empty value counts as absent.** That is measured and it is what makes
// the three-way branch in loginactions.go reachable at all: the successful
// login clears KC_RESTART with Max-Age=0, a browser that has not yet expired it
// sends `KC_RESTART=`, and Keycloak answers such a request the client redirect
// rather than a restart.
func (s *authStore) restartByCookie(realm, cookie string) (*restartRecord, bool) {
	if cookie == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.restarts[cookie]
	if !ok || rec.Realm != realm || s.now().After(rec.ExpiresAt) {
		return nil, false
	}
	return rec, true
}

// newCode mints an authorization code and stores what redeeming it will need.
func (s *authStore) newCode(c *authCode) (string, error) {
	part1, err := uuidShaped()
	if err != nil {
		return "", err
	}
	// The three parts are measured: a UUID-shaped random value, the
	// session_state, and the client's own internal UUID. The first is
	// deliberately not a real UUID - the version and variant nibbles measured
	// `d` and `f` on one sample and `2` and `7` on another, so it is random
	// bytes wearing a UUID's punctuation.
	code := part1 + "." + c.SessionID + "." + c.ClientUUID
	c.Code = code
	c.ExpiresAt = s.now().Add(authCodeLifespan)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.codes[code] = c
	return code, nil
}

// spendCode takes a code out of the store and returns it, or reports that there
// was none.
//
// It removes the code whether or not the caller goes on to accept it, because
// **a failed exchange spends the code**: measured, a wrong code_verifier
// answers "PKCE verification failed: Code mismatch" and the immediate retry
// answers "Code not valid". Single use means single attempt.
func (s *authStore) spendCode(realm, code string) (*authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, false
	}
	delete(s.codes, code)
	if c.Realm != realm || s.now().After(c.ExpiresAt) {
		return nil, false
	}
	return c, true
}

// sweepLocked drops what has expired. Called on every write, never on a read,
// so a long-lived process that stops logging people in stops growing rather
// than shrinking - which is the right trade for maps this small.
func (s *authStore) sweepLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	for id, rec := range s.restarts {
		if now.After(rec.ExpiresAt) {
			delete(s.restarts, id)
		}
	}
	for id, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, id)
		}
	}
}

// encodeAuthSessionID builds AUTH_SESSION_ID's value: base64url of
// "<root id>.<secret>", unpadded.
//
// Measured on a live login, the cookie is 148 characters and decodes to 111
// bytes - a 24-character root id, a dot, and 86 characters - so the shape here
// is the measured one rather than a convenient one.
func encodeAuthSessionID(rootID, secret string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(rootID + "." + secret))
}

// decodeAuthSessionID is its inverse, reporting false for anything that is not
// the measured shape.
func decodeAuthSessionID(cookie string) (rootID, secret string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cookie)
	if err != nil {
		return "", "", false
	}
	rootID, secret, found := strings.Cut(string(raw), ".")
	if !found || rootID == "" || secret == "" {
		return "", "", false
	}
	return rootID, secret, true
}

// keycloakSessionValue is KEYCLOAK_SESSION's value, derived from
// KC_AUTH_SESSION_HASH's.
//
// The two cookies carry one value in two base64 alphabets: measured byte for
// byte on the pair of responses where both appear, "+/" in the hash becoming
// "-_" in the session cookie. Minting a second random value would be the
// obvious implementation and it would break a client that compares them.
func keycloakSessionValue(hash string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(hash)
}

// clientData is the JSON that the login form's client_data parameter carries,
// unpadded base64url.
//
// **Its key order is measured**: ru, rt, rm, st. `rm` is present only when the
// authorization request named a response_mode, and `st` follows /auth's own
// state rule exactly - absent when no state was sent, present and empty when
// `state=` was. So the two pointers are not tidiness: a `json:",omitempty"` on
// State would emit three keys where Keycloak emits four for `state=`.
type clientData struct {
	RedirectURI  string  `json:"ru"`
	ResponseType string  `json:"rt"`
	ResponseMode *string `json:"rm,omitempty"`
	State        *string `json:"st,omitempty"`
}

// encodeClientData renders it the way the measured action URL carries it.
func encodeClientData(redirectURI, responseType, responseMode, state string, hasState bool) (string, error) {
	cd := clientData{RedirectURI: redirectURI, ResponseType: responseType}
	if responseMode != "" {
		cd.ResponseMode = &responseMode
	}
	if hasState {
		cd.State = &state
	}
	raw, err := json.Marshal(cd)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// deviceClientData is the client_data a device authorization carries: `e30`,
// which is base64url of `{}`.
//
// The device flow has no redirect URI, no response type and no state, so the
// browser's restart hint is an **empty object** rather than the two-key one
// encodeClientData would produce. Measured on all three places the value
// appears in a device login - the verification redirect, the login form's action
// and the consent page's action - and it is `e30` on every one.
const deviceClientData = "e30"

// clientData renders the tab's own client_data, which is the empty object for a
// device authorization and the four-key encoding for everything else.
func (t *authTab) clientData() (string, error) {
	if t.DeviceUserCode != "" {
		return deviceClientData, nil
	}
	return encodeClientData(t.RedirectURI, responseTypeCode, t.ResponseMode, t.State, t.HasState)
}

// decodeClientData parses one, for the single caller that is allowed to read
// its contents - see clientDataTarget for why that caller is the only one.
func decodeClientData(raw string) (clientData, error) {
	var cd clientData
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cd, err
	}
	if err := json.Unmarshal(decoded, &cd); err != nil {
		return cd, err
	}
	return cd, nil
}

// validClientData reports whether a client_data parameter parses.
//
// **It is parsed and then ignored**, which is the measurement this function
// exists to encode. A client_data naming another redirect URI still redirects
// to the registered one, one naming another state still echoes the original,
// and one adding rm=fragment still puts the parameters in the query; dropping
// it entirely succeeds. But `client_data=!!!!` is a 400, so it is parsed.
//
// Reading the redirect URI out of it is therefore the mistake this rejects: it
// is a restart hint the browser carries, never an authority.
func validClientData(raw string) bool {
	if raw == "" {
		return true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	var cd clientData
	return json.Unmarshal(decoded, &cd) == nil
}

// executionID is the `execution` the login form carries.
//
// Keycloak's is the id of the realm's username-password-form authentication
// execution, and it is measured **stable across logins in one container** while
// the other four action parameters vary per request. Gloak has no
// authentication-flow model, so it derives a stable per-realm UUID from the
// realm's id the way the keys endpoint derives a providerId from a kid: a fixed
// hash, so that it is the same on every request and different between realms,
// without inventing a table.
func executionID(realmID string) string {
	sum := sha256.Sum256([]byte("gloak-login-execution:" + realmID))
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// randomBase64URL returns n random bytes as unpadded base64url, which is the
// alphabet every identifier in this flow uses.
func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// sessionHash is KC_AUTH_SESSION_HASH's value: **standard** base64, which is
// the one value in the flow that is not base64url and the reason
// keycloakSessionValue exists.
//
// It is derived from the session id under the realm's HMAC key rather than
// drawn at random, and that is a measurement rather than a convenience.
// KC_AUTH_SESSION_HASH and KEYCLOAK_SESSION are **stable for the life of a user
// session**: three SSO redirects on a jar carrying only KEYCLOAK_IDENTITY each
// re-emitted the value the original login had set, and a second, independent
// login emitted a different one. A random value would have to outlive the
// authentication session that minted it - and the login destroys that session -
// so deriving is what makes the invariant hold rather than storing a string
// somewhere it can be lost.
//
// The bytes themselves are not observable: Keycloak's are 64 characters that
// look like a MAC over something nothing reveals. What is observable is the
// length, the alphabet and the stability, and all three hold here. The realm's
// HMAC key is the input so that one realm's value cannot be computed from
// another's, and so that a session id - which a client does see, as
// session_state - is not enough on its own.
func sessionHash(k *keys.RealmKeys, sessionID string) string {
	mac := hmac.New(sha512.New, k.HMACSecret())
	mac.Write([]byte("gloak-auth-session-hash:" + sessionID))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:authHashBytes])
}

// consentStore remembers which clients a user has approved, and it is in memory
// for a reason that is **not** the one authStore and deviceStore give.
//
// Keycloak persists a consent: it is a row a user can read and revoke through
// `GET`/`DELETE /admin/realms/{realm}/users/{id}/consents/{clientId}`, and it
// survives a restart. Measured: after one accept, later logins at that client
// skip the consent page entirely. Gloak keeps it in memory only because
// internal/store and internal/model belong to another stream this session, so a
// restart forgets every grant and asks again. That is a real divergence and it
// is filed rather than hidden - see the follow-ups, where it is named separately
// from F75 precisely because F75's three objects are short-lived by design and
// this one is not.
type consentStore struct {
	mu     sync.Mutex
	grants map[string]bool
}

func newConsentStore() *consentStore {
	return &consentStore{grants: map[string]bool{}}
}

// consentKey is scoped by realm as well as by user and client, because two
// realms mint their own user ids and nothing stops them colliding across a
// restore.
func consentKey(realmID, userID, clientUUID string) string {
	return realmID + "\x00" + userID + "\x00" + clientUUID
}

func (s *consentStore) granted(realmID, userID, clientUUID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grants[consentKey(realmID, userID, clientUUID)]
}

func (s *consentStore) grant(realmID, userID, clientUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[consentKey(realmID, userID, clientUUID)] = true
}

// uuidShaped returns 16 random bytes wearing a UUID's punctuation, with no
// version or variant nibbles forced.
//
// That is measured: the authorization code's first part is laid out like a UUID
// and is not one. Two samples carried version nibble `d` variant `f` and
// version `2` variant `7`, neither of which any UUID version produces.
func uuidShaped() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
