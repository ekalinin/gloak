package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The authorization_code grant's tests drive the whole browser flow and then
// redeem what it produced, because every claim here is about a value carried
// from GET /auth to the token endpoint through a code that has nowhere to put
// it: the code's three parts are a random value, the session_state and the
// client's UUID.
//
// The conformance goldens cover three of these answers. They cannot cover the
// rest, because a case that redeems a code spends it - measured, single use
// means single *attempt* - so an adjacency needs two logins and a golden has
// one request.

// RFC 7636 appendix B's pair, the same literals the conformance fixtures use.
const (
	pkceVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

const tokenPath = "/realms/master/protocol/openid-connect/token"

// loginForCode runs a whole browser login and returns the code it produced.
func (b *browser) loginForCode(overrides map[string]string) string {
	b.t.Helper()
	action := b.login(overrides)
	target, _ := actionParams(b.t, action)
	w := b.do(http.MethodPost, target, credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		b.t.Fatalf("login: want 302, got %d\n%s", w.Code, w.Body)
	}
	location := w.Header().Get("Location")
	raw := strings.TrimPrefix(location, probeRedirectURI+"?")
	if raw == location {
		b.t.Fatalf("login did not redirect to the registered URI: %s", location)
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		b.t.Fatalf("parse redirect query: %v", err)
	}
	code := q.Get("code")
	if code == "" {
		b.t.Fatalf("no code in %s", location)
	}
	return code
}

// exchangeForm is a redemption with nothing wrong with it, which each test
// below breaks in exactly the ways it names.
func exchangeForm(code string, overrides map[string]string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "probe")
	form.Set("redirect_uri", probeRedirectURI)
	form.Set("code", code)
	for k, v := range overrides {
		if v == absent {
			form.Del(k)
			continue
		}
		form.Set(k, v)
	}
	return form
}

// oauthError asserts a status and an {"error","error_description"} body.
func oauthError(t *testing.T, w *httptest.ResponseRecorder, status int, code, description string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("want %d, got %d: %s", status, w.Code, w.Body)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse error body: %v", err)
	}
	if body.Error != code || body.Description != description {
		t.Fatalf("want %s/%q, got %s/%q", code, description, body.Error, body.Description)
	}
}

// tokenBody is the success body's keys, decoded generically so that a missing
// key and an empty one are distinguishable.
func tokenBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse token response: %v", err)
	}
	return body
}

// jwtClaims decodes a JWT's payload without verifying it. Verification is
// TestRelyingPartyAcceptsOurIDToken's job; this is about which keys are there.
func jwtClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload is not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("JWT payload is not JSON: %v", err)
	}
	return claims
}

// TestCodeGrantCarriesTheAuthorizationRequest is the success path, and what it
// asserts is the four values the code has nowhere to hold.
//
// The scope is the measured one: a login asking scope=openid produces a
// response whose scope carries openid and therefore an id_token, where the same
// login asking for nothing produces neither. Gloak minted its code with a
// constant scope until this cut, so the response's own golden could not have
// matched.
func TestCodeGrantCarriesTheAuthorizationRequest(t *testing.T) {
	b := newBrowser(t)
	code := b.loginForCode(map[string]string{"nonce": "n-0S6_WzA2Mj"})

	body := tokenBody(t, b.do(http.MethodPost, tokenPath, exchangeForm(code, nil)))

	// The nine keys, in the measured order.
	want := []string{"access_token", "expires_in", "refresh_expires_in", "refresh_token",
		"token_type", "id_token", "not-before-policy", "session_state", "scope"}
	for _, key := range want {
		if _, ok := body[key]; !ok {
			t.Errorf("the success body has no %s", key)
		}
	}
	if got := body["scope"]; got != "openid profile email" {
		t.Errorf("scope: want %q, got %v", "openid profile email", got)
	}
	// session_state is the code's second part: one value, decided at GET /auth.
	if got, want := body["session_state"], strings.Split(code, ".")[1]; got != want {
		t.Errorf("session_state: want the code's second part %q, got %v", want, got)
	}

	id := jwtClaims(t, body["id_token"].(string))
	if id["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("the ID token lost the request's nonce: %v", id["nonce"])
	}
	if id["auth_time"] == nil {
		t.Error("the ID token has no auth_time")
	}
	access := jwtClaims(t, body["access_token"].(string))
	if access["auth_time"] == nil {
		t.Error("the access token has no auth_time")
	}
	if access["nonce"] != nil {
		t.Errorf("nonce is measured on the ID token alone, and the access token has %v", access["nonce"])
	}
	// auth_time is when the user authenticated, not when the token was issued.
	// Both are the same second here, so what is asserted is that they agree
	// rather than the six-second gap the live measurement produced.
	if access["auth_time"] != access["iat"] {
		t.Errorf("auth_time %v and iat %v disagree on a login redeemed at once",
			access["auth_time"], access["iat"])
	}
}

// TestCodeGrantWithoutOpenidIssuesNoIDToken is the other half of the scope
// carry-through, and it is the one that fails loudly if the code goes back to a
// constant scope: a constant carrying openid would make this body wrong.
func TestCodeGrantWithoutOpenidIssuesNoIDToken(t *testing.T) {
	b := newBrowser(t)
	code := b.loginForCode(map[string]string{"scope": absent})

	body := tokenBody(t, b.do(http.MethodPost, tokenPath, exchangeForm(code, nil)))

	if _, ok := body["id_token"]; ok {
		t.Errorf("an id_token was issued for a login that did not ask for openid: %v", body["id_token"])
	}
	if got := body["scope"]; got != "profile email" {
		t.Errorf("scope: want %q, got %v", "profile email", got)
	}
}

// TestPasswordGrantStillHasNoAuthTime pins the difference the browser flow
// introduces. Measured on one container minutes apart: an authorization_code
// grant's tokens carry auth_time and a password grant's carry none, so a
// handler that started stamping every issuance would diverge on three grants to
// fix one.
func TestPasswordGrantStillHasNoAuthTime(t *testing.T) {
	b := newBrowser(t)

	body := tokenBody(t, b.do(http.MethodPost, tokenPath, url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
		"scope":      {"openid"},
	}))

	for _, key := range []string{"access_token", "id_token"} {
		if claims := jwtClaims(t, body[key].(string)); claims["auth_time"] != nil {
			t.Errorf("the password grant's %s carries auth_time %v", key, claims["auth_time"])
		}
	}
}

// TestCodeGrantRejectionOrder drives two faults at once, one pair per
// adjacency, the way the live measurement was taken. Each case needs its own
// login because the attempt spends the code.
func TestCodeGrantRejectionOrder(t *testing.T) {
	s256 := map[string]string{"code_challenge": pkceChallenge, "code_challenge_method": "S256"}
	cases := []struct {
		name        string
		auth        map[string]string
		exchange    map[string]string
		status      int
		code        string
		description string
	}{{
		name:        "a duplicated key beats a missing code",
		exchange:    map[string]string{"code": absent, "zz": "1"},
		status:      http.StatusBadRequest,
		code:        "invalid_request",
		description: "duplicated parameter",
	}, {
		name:        "a missing code beats a missing redirect_uri",
		exchange:    map[string]string{"code": absent, "redirect_uri": absent},
		status:      http.StatusBadRequest,
		code:        "invalid_request",
		description: "Missing parameter: code",
	}, {
		name:        "an unusable code beats a wrong redirect_uri",
		exchange:    map[string]string{"code": "not-a-code", "redirect_uri": "http://localhost:9999/other"},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Code not valid",
	}, {
		name:        "an empty code reaches the lookup rather than the presence check",
		exchange:    map[string]string{"code": ""},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Code not valid",
	}, {
		name:        "a wrong redirect_uri beats a wrong verifier",
		auth:        s256,
		exchange:    map[string]string{"redirect_uri": "http://localhost:9999/other", "code_verifier": "gloak-probe-wrong-code-verifier-0123456789A"},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Incorrect redirect_uri",
	}, {
		name:        "a missing redirect_uri is not a missing parameter",
		exchange:    map[string]string{"redirect_uri": absent},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Incorrect redirect_uri",
	}, {
		name:        "a registered redirect_uri that is not the code's is still wrong",
		exchange:    map[string]string{"redirect_uri": "http://localhost:9999/callback/"},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Incorrect redirect_uri",
	}, {
		// The one adjacency nobody would guess: the redirect URI is compared
		// before the caller is compared with the code's own client, so a
		// stranger sending a wrong redirect_uri is told about the URI.
		name:        "a wrong redirect_uri beats another client",
		exchange:    map[string]string{"client_id": "probe-implicit", "redirect_uri": "http://localhost:9999/other"},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Incorrect redirect_uri",
	}, {
		name:        "another client beats a missing verifier",
		auth:        s256,
		exchange:    map[string]string{"client_id": "probe-implicit"},
		status:      http.StatusBadRequest,
		code:        "invalid_grant",
		description: "Auth error: Found different client_id in clientSession",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			code := b.loginForCode(tc.auth)
			form := exchangeForm(code, tc.exchange)
			if _, dup := tc.exchange["zz"]; dup {
				form["zz"] = []string{"1", "2"}
			}
			oauthError(t, b.do(http.MethodPost, tokenPath, form), tc.status, tc.code, tc.description)
		})
	}
}

// TestCodeVerifierHasFourAnswers is the PKCE grid, and it is the part of this
// endpoint the catalogue names once and measures four times.
func TestCodeVerifierHasFourAnswers(t *testing.T) {
	s256 := map[string]string{"code_challenge": pkceChallenge, "code_challenge_method": "S256"}
	plain := map[string]string{"code_challenge": pkceVerifier, "code_challenge_method": "plain"}
	cases := []struct {
		name        string
		auth        map[string]string
		verifier    string
		description string // empty means the exchange succeeds
	}{
		{name: "no challenge and no verifier", verifier: absent},
		{name: "no challenge and a verifier", verifier: pkceVerifier,
			description: "PKCE code verifier specified but challenge not present in authorization"},
		{name: "a challenge and no verifier", auth: s256, verifier: absent,
			description: "PKCE code verifier not specified"},
		{name: "a challenge and an empty verifier", auth: s256, verifier: "",
			description: "PKCE verification failed: Invalid code verifier"},
		{name: "a verifier one character too short", auth: s256, verifier: strings.Repeat("a", 42),
			description: "PKCE verification failed: Invalid code verifier"},
		{name: "a verifier one character too long", auth: s256, verifier: strings.Repeat("a", 129),
			description: "PKCE verification failed: Invalid code verifier"},
		{name: "a verifier outside the unreserved alphabet", auth: s256, verifier: strings.Repeat("!", 43),
			description: "PKCE verification failed: Invalid code verifier"},
		// 128 is inside the production, so this one reaches the comparison and
		// answers about the value rather than the shape - which is what says the
		// upper bound is 128 and not 127.
		{name: "a well-formed verifier at the upper bound", auth: s256, verifier: strings.Repeat("a", 128),
			description: "PKCE verification failed: Code mismatch"},
		{name: "a well-formed verifier that does not match", auth: s256,
			verifier:    "gloak-probe-wrong-code-verifier-0123456789A",
			description: "PKCE verification failed: Code mismatch"},
		{name: "the S256 verifier", auth: s256, verifier: pkceVerifier},
		{name: "the plain verifier", auth: plain, verifier: pkceVerifier},
		{name: "a plain verifier against a challenge sent with no method",
			auth:     map[string]string{"code_challenge": pkceVerifier},
			verifier: pkceVerifier},
		{name: "the S256 verifier offered as plain", auth: plain, verifier: pkceChallenge,
			description: "PKCE verification failed: Code mismatch"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBrowser(t)
			code := b.loginForCode(tc.auth)
			w := b.do(http.MethodPost, tokenPath,
				exchangeForm(code, map[string]string{"code_verifier": tc.verifier}))
			if tc.description == "" {
				tokenBody(t, w)
				return
			}
			oauthError(t, w, http.StatusBadRequest, "invalid_grant", tc.description)
		})
	}
}

// TestS256ChallengeIsTheHashOfTheVerifier keeps the RFC 7636 pair honest
// against its own arithmetic rather than against two literals that agree
// because they were copied together.
func TestS256ChallengeIsTheHashOfTheVerifier(t *testing.T) {
	sum := sha256.Sum256([]byte(pkceVerifier))
	if got := base64.RawURLEncoding.EncodeToString(sum[:]); got != pkceChallenge {
		t.Fatalf("the test pair is not an S256 pair: %q hashes to %q", pkceVerifier, got)
	}
}

// TestEveryRedemptionFailureSpendsTheCodeExceptOne is the boundary AGENTS.md's
// "a failed code exchange spends the code" does not draw.
//
// Measured over five failures: four spend it and the 401 does not, because
// client authentication happens before the code is looked at. So the retry
// after a wrong redirect_uri answers "Code not valid" and the retry after a
// missing client secret succeeds.
func TestEveryRedemptionFailureSpendsTheCodeExceptOne(t *testing.T) {
	spend := []struct {
		name     string
		auth     map[string]string
		exchange map[string]string
	}{
		{name: "a wrong redirect_uri",
			exchange: map[string]string{"redirect_uri": "http://localhost:9999/other"}},
		{name: "another client's client_id",
			exchange: map[string]string{"client_id": "probe-implicit"}},
		{name: "a missing verifier",
			auth: map[string]string{"code_challenge": pkceChallenge, "code_challenge_method": "S256"}},
		{name: "a mismatched verifier",
			auth:     map[string]string{"code_challenge": pkceChallenge, "code_challenge_method": "S256"},
			exchange: map[string]string{"code_verifier": "gloak-probe-wrong-code-verifier-0123456789A"}},
	}
	for _, tc := range spend {
		t.Run(tc.name+" spends it", func(t *testing.T) {
			b := newBrowser(t)
			code := b.loginForCode(tc.auth)
			if w := b.do(http.MethodPost, tokenPath, exchangeForm(code, tc.exchange)); w.Code != http.StatusBadRequest {
				t.Fatalf("the first attempt was meant to fail: %d %s", w.Code, w.Body)
			}
			retry := exchangeForm(code, nil)
			if tc.auth != nil {
				retry.Set("code_verifier", pkceVerifier)
			}
			oauthError(t, b.do(http.MethodPost, tokenPath, retry),
				http.StatusBadRequest, "invalid_grant", "Code not valid")
		})
	}

	t.Run("a failed client authentication does not spend it", func(t *testing.T) {
		b := newBrowser(t)
		code := b.loginForCode(map[string]string{"client_id": "probe-confidential"})
		form := exchangeForm(code, map[string]string{"client_id": "probe-confidential"})

		oauthError(t, b.do(http.MethodPost, tokenPath, form), http.StatusUnauthorized,
			"unauthorized_client", "Invalid client or Invalid client credentials")

		form.Set("client_secret", "s3cret")
		tokenBody(t, b.do(http.MethodPost, tokenPath, form))
	})
}

// TestCodeForADeadSessionIsNotValid is the branch measured by deleting the
// session between the login and the exchange: the answer is "Code not valid"
// rather than a session error, so a code is redeemable only while the session
// it names lives.
//
// It reaches past the protocol surface because no request this package can
// issue ends a session it holds no token for, and redeeming the code to get one
// would spend the very code under test.
func TestCodeForADeadSessionIsNotValid(t *testing.T) {
	h, s := authServerAndStore(t)
	b := &browser{h: h, t: t, jar: map[string]string{}}
	code := b.loginForCode(nil)

	ctx := context.Background()
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	if err := s.Sessions().DeleteUserSession(ctx, realm.ID, strings.Split(code, ".")[1]); err != nil {
		t.Fatalf("DeleteUserSession: %v", err)
	}

	oauthError(t, b.do(http.MethodPost, tokenPath, exchangeForm(code, nil)),
		http.StatusBadRequest, "invalid_grant", "Code not valid")
}

// TestDuplicatedFormParameterIsRejectedOnEveryGrant pins the two things about
// this check that are the token endpoint's own rather than /auth's: it reads
// the body and not the query, and it runs after client authentication.
func TestDuplicatedFormParameterIsRejectedOnEveryGrant(t *testing.T) {
	b := newBrowser(t)

	// Any key, including one the endpoint never reads.
	w := b.do(http.MethodPost, tokenPath, url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
		"zz":         {"1", "2"},
	})
	oauthError(t, w, http.StatusBadRequest, "invalid_request", "duplicated parameter")

	// grant_type twice is the same answer, and it is not caught by the
	// grant_type checks above it.
	w = b.do(http.MethodPost, tokenPath, url.Values{
		"grant_type": {"password", "password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
	})
	oauthError(t, w, http.StatusBadRequest, "invalid_request", "duplicated parameter")

	// The query string is not read at all, so a key repeated there is not a
	// duplicate and the grant succeeds.
	w = b.do(http.MethodPost, tokenPath+"?zz=1&zz=2", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {"admin"},
		"password":   {"admin"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("a duplicate in the query string was treated as one: %d %s", w.Code, w.Body)
	}

	// Client authentication comes first: the same duplicate with an unknown
	// client is the 401.
	w = b.do(http.MethodPost, tokenPath, url.Values{
		"grant_type": {"password"},
		"client_id":  {"nosuchclient"},
		"zz":         {"1", "2"},
	})
	oauthError(t, w, http.StatusUnauthorized, "invalid_client",
		"Invalid client or Invalid client credentials")

	// And the grant_type checks come before that: the same duplicate with no
	// grant_type answers about grant_type.
	w = b.do(http.MethodPost, tokenPath, url.Values{
		"client_id": {"admin-cli"},
		"zz":        {"1", "2"},
	})
	oauthError(t, w, http.StatusBadRequest, "invalid_request",
		"Missing form parameter: grant_type")
}

// TestRestartedLoginKeepsItsPKCEBinding is the security-shaped half of carrying
// the authorization request. A restart rebuilds the tab from KC_RESTART, and a
// restart that dropped the code_challenge would let a client downgrade its own
// PKCE by discarding one cookie.
func TestRestartedLoginKeepsItsPKCEBinding(t *testing.T) {
	b := newBrowser(t)
	action := b.login(map[string]string{
		"code_challenge": pkceChallenge, "code_challenge_method": "S256",
	})
	target, _ := actionParams(t, action)

	// Spend the session code, then replay it: with KC_RESTART still in the jar
	// that is the restart branch.
	if w := b.do(http.MethodPost, target, credentials("admin", "wrong")); w.Code != http.StatusOK {
		t.Fatalf("wrong password: want 200, got %d", w.Code)
	}
	replay := b.do(http.MethodPost, target, credentials("admin", "admin"))
	if replay.Code != http.StatusFound {
		t.Fatalf("replayed session code: want the restart 302, got %d", replay.Code)
	}
	landing := b.do(http.MethodGet, replay.Header().Get("Location"), nil)
	if landing.Code != http.StatusOK {
		t.Fatalf("restart landing: want 200, got %d", landing.Code)
	}
	restartTarget, _ := actionParams(t, formAction(t, landing.Body.String()))
	if restartTarget == target {
		t.Fatal("the restart did not mint a new tab")
	}

	w := b.do(http.MethodPost, restartTarget, credentials("admin", "admin"))
	if w.Code != http.StatusFound {
		t.Fatalf("login after restart: want 302, got %d\n%s", w.Code, w.Body)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(w.Header().Get("Location"), probeRedirectURI+"?"))
	if err != nil {
		t.Fatalf("parse redirect query: %v", err)
	}

	// The restarted login's code still demands the verifier.
	oauthError(t, b.do(http.MethodPost, tokenPath, exchangeForm(q.Get("code"), nil)),
		http.StatusBadRequest, "invalid_grant", "PKCE code verifier not specified")
}
