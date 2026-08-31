package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// capturedCall is one outbound back-channel logout POST, as the client saw it.
type capturedCall struct {
	method      string
	path        string
	contentType string
	form        url.Values
}

// listener stands in for a client's registered backchannel.logout.url. It is an
// httptest.NewServer on 127.0.0.1 rather than a mock, because the thing under
// test is a real HTTP request: the method, the Content-Type and the form
// encoding are all measured values, and a fake http.RoundTripper would let
// three of them be wrong.
//
// status is what every path answers, so one listener covers the success and the
// two measured failure statuses.
type listener struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []capturedCall
	status int
}

func newListener(t *testing.T, status int) *listener {
	t.Helper()
	l := &listener{status: status}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		l.mu.Lock()
		l.calls = append(l.calls, capturedCall{
			method:      r.Method,
			path:        r.URL.Path,
			contentType: r.Header.Get("Content-Type"),
			form:        form,
		})
		l.mu.Unlock()
		w.WriteHeader(l.status)
	}))
	t.Cleanup(l.Close)
	return l
}

func (l *listener) seen() []capturedCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]capturedCall(nil), l.calls...)
}

// channelClient describes one client the fixture below registers.
type channelClient struct {
	clientID   string
	attributes map[string]string
	frontFlag  bool
}

// channelServer builds a router whose handler will call the test's own
// listener, and registers the clients given. Every client can start a session
// with a direct grant, which is how the conformance fixtures do it too.
func channelServer(t *testing.T, l *listener, clients ...channelClient) (http.Handler, *handler, store.Store, *model.Realm) {
	t.Helper()
	h, s, realm := newHandler(t)
	ctx := context.Background()
	for _, c := range clients {
		client := &model.Client{
			ID:                        model.NewID(),
			RealmID:                   realm.ID,
			ClientID:                  c.clientID,
			Protocol:                  "openid-connect",
			Enabled:                   true,
			PublicClient:              true,
			DirectAccessGrantsEnabled: true,
			FrontchannelLogout:        c.frontFlag,
			RedirectURIs:              []string{logoutRedirectURI},
			Attributes:                map[string]string{postLogoutRedirectAttribute: logoutRedirectURI},
		}
		for k, v := range c.attributes {
			client.Attributes[k] = v
		}
		if err := s.Clients().Create(ctx, client); err != nil {
			t.Fatalf("create %s: %v", c.clientID, err)
		}
	}
	h.auth, h.device, h.consents = newAuthStore(), newDeviceStore(), newConsentStore()
	if l != nil {
		h.httpClient = l.Client()
	}
	mux := http.NewServeMux()
	h.register(mux)
	return WithKeycloakFallbacks(mux), h, s, realm
}

// backchannelURL is the attribute a client registers to be called.
func backchannelURL(l *listener, path string) map[string]string {
	return map[string]string{backchannelLogoutURLAttribute: l.URL + path}
}

// logoutWithHint drives a direct grant at clientID and then logs that session
// out through the GET family, returning the logout's own response.
func logoutWithHint(t *testing.T, router http.Handler, clientID string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	tokens := logoutTokens(t, router, clientID, "")
	if query == nil {
		query = url.Values{}
	}
	query.Set("id_token_hint", tokens.IDToken)
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?"+query.Encode(), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeJWT splits a compact JWS and returns the two raw JSON segments, so a
// test can assert **key order** rather than a parsed map. The logout token's
// claim order is measured and a map comparison would not see it.
func decodeJWT(t *testing.T, compact string) (header, payload string) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	p, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return string(h), string(p)
}

// TestBackchannelLogoutPostsTheMeasuredRequest pins the whole outbound call:
// the method, the path, the Content-Type, the one form key, the JOSE header and
// the payload's key order and values.
//
// Measured 2026-08-31 from a listener the reference container could reach. See
// docs/superpowers/plans/2026-08-31-p6-channel-logout.md sections 1.4 and 1.5.
func TestBackchannelLogoutPostsTheMeasuredRequest(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, h, _, realm := channelServer(t, l,
		channelClient{clientID: "bc-plain", attributes: backchannelURL(l, "/bc")})

	rec := logoutWithHint(t, router, "bc-plain", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200", rec.Code)
	}
	calls := l.seen()
	if len(calls) != 1 {
		t.Fatalf("outbound calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.method != http.MethodPost {
		t.Errorf("method = %q, want POST", call.method)
	}
	if call.path != "/bc" {
		t.Errorf("path = %q, want /bc", call.path)
	}
	// Measured with no charset, which is what url.Values.Encode + this header
	// produces and what a Content-Type built with "; charset=utf-8" would not.
	if call.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", call.contentType)
	}
	if len(call.form) != 1 {
		t.Errorf("form keys = %v, want logout_token alone", call.form)
	}

	header, payload := decodeJWT(t, call.form.Get("logout_token"))
	k, err := h.keys.ForRealm(context.Background(), realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}
	// The header names the realm's active RSA key and the logout typ. The kid
	// is the one the ID token carries, so a client that already fetched the
	// JWKS needs nothing new.
	var head struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal([]byte(header), &head); err != nil {
		t.Fatalf("header: %v", err)
	}
	if head.Alg != "RS256" || head.Typ != "logout+jwt" || head.Kid != k.RSAKeyID {
		t.Errorf("header = %s, want RS256/logout+jwt/%s", header, k.RSAKeyID)
	}

	// The payload is asserted as **bytes in order**, because the key order is
	// the measurement. The four per-request values are cut out first.
	got := maskJWTValues(t, payload)
	const want = `{"exp":0,"iat":0,"jti":"","iss":"http://localhost:8080/realms/master",` +
		`"aud":"bc-plain","sub":"","typ":"Logout",` +
		`"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}`
	if got != want {
		t.Errorf("payload\n got %s\nwant %s", got, want)
	}
}

// maskJWTValues replaces the four per-request values in a logout token's
// payload with zero values, leaving the key order and everything else exactly
// as it arrived. It also checks the one arithmetic claim, exp - iat.
func maskJWTValues(t *testing.T, payload string) string {
	t.Helper()
	var claims struct {
		Exp int64  `json:"exp"`
		Iat int64  `json:"iat"`
		Jti string `json:"jti"`
		Sub string `json:"sub"`
		Sid string `json:"sid"`
	}
	if err := json.Unmarshal([]byte(payload), &claims); err != nil {
		t.Fatalf("payload: %v", err)
	}
	// Measured on every logout token a sweep produced: a two-minute lifetime,
	// which is not the access token's.
	if claims.Exp-claims.Iat != 120 {
		t.Errorf("exp - iat = %d, want 120", claims.Exp-claims.Iat)
	}
	if claims.Sub == "" {
		t.Error("sub is empty; the token must name the subject")
	}
	out := payload
	for _, r := range []struct{ from, to string }{
		{`"exp":` + strconv.FormatInt(claims.Exp, 10), `"exp":0`},
		{`"iat":` + strconv.FormatInt(claims.Iat, 10), `"iat":0`},
		{`"jti":"` + claims.Jti + `"`, `"jti":""`},
		{`"sub":"` + claims.Sub + `"`, `"sub":""`},
	} {
		out = strings.Replace(out, r.from, r.to, 1)
	}
	if claims.Sid != "" {
		out = strings.Replace(out, `"sid":"`+claims.Sid+`"`, `"sid":""`, 1)
	}
	return out
}

// TestBackchannelLogoutEmitsSidOnlyWhenTheClientAsks pins the attribute whose
// default is the opposite of its front-channel namesake's.
//
// Measured 2026-08-31 on three clients differing only in
// backchannel.logout.session.required: "true" emits sid, "false" omits it, and
// **an absent attribute behaves as "false"**. Emitting it always is the obvious
// implementation and it is wrong on two of the three rows.
func TestBackchannelLogoutEmitsSidOnlyWhenTheClientAsks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   string
		present bool
		wantSid bool
	}{
		{name: "true", value: "true", present: true, wantSid: true},
		{name: "false", value: "false", present: true},
		{name: "absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newListener(t, http.StatusOK)
			attrs := backchannelURL(l, "/bc")
			if tc.present {
				attrs[backchannelLogoutSessionAttribute] = tc.value
			}
			router, _, _, _ := channelServer(t, l,
				channelClient{clientID: "bc-sid", attributes: attrs})

			logoutWithHint(t, router, "bc-sid", nil)

			calls := l.seen()
			if len(calls) != 1 {
				t.Fatalf("outbound calls = %d, want 1", len(calls))
			}
			_, payload := decodeJWT(t, calls[0].form.Get("logout_token"))
			var claims struct {
				Sid string `json:"sid"`
			}
			if err := json.Unmarshal([]byte(payload), &claims); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if got := claims.Sid != ""; got != tc.wantSid {
				t.Errorf("sid present = %v, want %v; payload %s", got, tc.wantSid, payload)
			}
			// The sid sits between typ and events when it is there at all.
			if tc.wantSid && !strings.Contains(payload, `"typ":"Logout","sid":"`) {
				t.Errorf("sid is not between typ and events: %s", payload)
			}
		})
	}
}

// TestBackchannelLogoutCallsOnlyTheClientsInTheSession pins the scope of the
// notification. Measured on a three-client SSO session: the two clients with
// the attribute were called, the plain one was not, and a registered
// back-channel client with no session on it was left alone.
func TestBackchannelLogoutCallsOnlyTheClientsInTheSession(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, _, s, realm := channelServer(t, l,
		channelClient{clientID: "bc-in", attributes: backchannelURL(l, "/in")},
		channelClient{clientID: "bc-joined", attributes: backchannelURL(l, "/joined")},
		channelClient{clientID: "bc-absent", attributes: backchannelURL(l, "/absent")},
		channelClient{clientID: "bc-plainclient"})

	// One session at bc-in, with bc-joined and bc-plainclient joining it the
	// way a second client joins an SSO session. bc-absent registers a URL and
	// never joins.
	tokens := logoutTokens(t, router, "bc-in", "")
	ctx := context.Background()
	for _, id := range []string{"bc-joined", "bc-plainclient"} {
		client, err := s.Clients().ByClientID(ctx, realm.ID, id)
		if err != nil {
			t.Fatalf("ByClientID %s: %v", id, err)
		}
		if err := s.Sessions().CreateClientSession(ctx, &model.ClientSession{
			ID: model.NewID(), UserSessionID: tokens.SessionState, ClientID: client.ID,
			Scope: "openid", StartedAt: 1,
		}); err != nil {
			t.Fatalf("CreateClientSession %s: %v", id, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?id_token_hint="+tokens.IDToken, nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	var paths []string
	for _, c := range l.seen() {
		paths = append(paths, c.path)
	}
	if len(paths) != 2 {
		t.Fatalf("outbound paths = %v, want /in and /joined", paths)
	}
	seen := strings.Join(paths, " ")
	if !strings.Contains(seen, "/in") || !strings.Contains(seen, "/joined") {
		t.Errorf("outbound paths = %v, want /in and /joined", paths)
	}
}

// TestBackchannelLogoutSwallowsAFailingClient pins the measurement that a
// client answering an error changes nothing a caller can see.
//
// Measured across 500, 404, connection refused, an unroutable address and a
// client that never answers: the logout's own status and the session were
// identical to a healthy client's every time, and a 500 drew exactly one POST
// rather than a retry.
func TestBackchannelLogoutSwallowsAFailingClient(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			l := newListener(t, status)
			router, _, s, realm := channelServer(t, l,
				channelClient{clientID: "bc-bad", attributes: backchannelURL(l, "/bad")})

			tokens := logoutTokens(t, router, "bc-bad", "")
			req := httptest.NewRequest(http.MethodGet,
				"/realms/master/protocol/openid-connect/logout?id_token_hint="+tokens.IDToken+
					"&post_logout_redirect_uri="+url.QueryEscape(logoutRedirectURI), nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Errorf("status = %d, want 302 even though the client failed", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != logoutRedirectURI {
				t.Errorf("Location = %q", got)
			}
			if n := len(l.seen()); n != 1 {
				t.Errorf("outbound calls = %d, want exactly 1 - Keycloak does not retry", n)
			}
			if _, err := s.Sessions().UserSessionByID(context.Background(), realm.ID,
				tokens.SessionState); err == nil {
				t.Error("the session survived a failing back-channel client")
			}
		})
	}
}

// TestRejectedLogoutCallsNobody pins that validation runs first. Measured: a
// valid id_token_hint with an unregistered post_logout_redirect_uri answers the
// 400 page and makes no outbound call, which is the same "a rejected logout
// ends nothing" the endpoint already records.
func TestRejectedLogoutCallsNobody(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, _, s, realm := channelServer(t, l,
		channelClient{clientID: "bc-reject", attributes: backchannelURL(l, "/reject")})

	tokens := logoutTokens(t, router, "bc-reject", "")
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?id_token_hint="+tokens.IDToken+
			"&post_logout_redirect_uri=https%3A%2F%2Fevil.example%2Fx", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if n := len(l.seen()); n != 0 {
		t.Errorf("outbound calls = %d, want 0", n)
	}
	if _, err := s.Sessions().UserSessionByID(context.Background(), realm.ID,
		tokens.SessionState); err != nil {
		t.Error("a rejected logout ended the session")
	}
}

// TestBackchannelLogoutIsSentBeforeTheSessionIsRemoved pins the ordering
// measured through a hanging client: while the client held the socket open the
// Admin API still listed the session, so the notification goes out while what
// it announces is still true.
func TestBackchannelLogoutIsSentBeforeTheSessionIsRemoved(t *testing.T) {
	var (
		alive bool
		s     store.Store
		realm *model.Realm
		sid   string
	)
	l := &listener{status: http.StatusOK}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := s.Sessions().UserSessionByID(r.Context(), realm.ID, sid)
		alive = err == nil
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(l.Close)

	var router http.Handler
	router, _, s, realm = channelServer(t, l,
		channelClient{clientID: "bc-order", attributes: backchannelURL(l, "/order")})
	tokens := logoutTokens(t, router, "bc-order", "")
	sid = tokens.SessionState

	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?id_token_hint="+tokens.IDToken, nil)
	router.ServeHTTP(httptest.NewRecorder(), req)

	if !alive {
		t.Error("the session was already gone when the client was called")
	}
}

// TestFrontchannelLogoutPageReplacesTheRedirect is the headline measurement of
// this cut: the same request that answers 302 on a plain client answers a 200
// theme page when the session holds a front-channel client - with a valid hint,
// a registered target and a state.
func TestFrontchannelLogoutPageReplacesTheRedirect(t *testing.T) {
	router, _, _, _ := channelServer(t, nil, channelClient{
		clientID:   "fc-page",
		frontFlag:  true,
		attributes: map[string]string{frontchannelLogoutURLAttribute: "http://localhost:9998/fc"},
	})

	rec := logoutWithHint(t, router, "fc-page", url.Values{
		"post_logout_redirect_uri": {logoutRedirectURI},
		"state":                    {"xyz123"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 - a front-channel client replaces the 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("Location = %q, want none", got)
	}
	// One client, one host, and the space before the semicolon.
	const wantCSP = "frame-src 'self' localhost:9998 ; frame-ancestors 'self'; object-src 'none';"
	if got := rec.Header().Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("Content-Security-Policy\n got %q\nwant %q", got, wantCSP)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html;charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	// The title is the confirmation page's, which is why the policy is what
	// tells the two pages apart.
	if !strings.Contains(rec.Body.String(), logoutConfirmPageTitle) {
		t.Errorf("body does not carry %q: %s", logoutConfirmPageTitle, rec.Body.String())
	}
}

// TestFrontchannelLogoutPageReplacesTheLoggedOutPage pins the other half:
// measured, a front-channel client with **no** post_logout_redirect_uri is
// still this page rather than "You are logged out".
func TestFrontchannelLogoutPageReplacesTheLoggedOutPage(t *testing.T) {
	router, _, _, _ := channelServer(t, nil, channelClient{
		clientID:   "fc-notarget",
		frontFlag:  true,
		attributes: map[string]string{frontchannelLogoutURLAttribute: "http://localhost:9998/fc"},
	})

	rec := logoutWithHint(t, router, "fc-notarget", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "localhost:9998") {
		t.Errorf("Content-Security-Policy = %q, want the front-channel page's", got)
	}
	if strings.Contains(rec.Body.String(), logoutSuccessPageTitle) {
		t.Error(`answered "You are logged out" where the front-channel page was measured`)
	}
}

// TestFrontchannelLogoutNeedsBothTheFlagAndTheURL pins the two-part condition.
// Measured: frontchannelLogout with no URL produces no iframe, and a URL on a
// client whose flag is false produces none either - so neither half alone
// reaches the page.
func TestFrontchannelLogoutNeedsBothTheFlagAndTheURL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frontFlag bool
		url       string
	}{
		{name: "flag without url", frontFlag: true},
		{name: "url without flag", url: "http://localhost:9998/fc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{}
			if tc.url != "" {
				attrs[frontchannelLogoutURLAttribute] = tc.url
			}
			router, _, _, _ := channelServer(t, nil, channelClient{
				clientID: "fc-half", frontFlag: tc.frontFlag, attributes: attrs,
			})

			rec := logoutWithHint(t, router, "fc-half", url.Values{
				"post_logout_redirect_uri": {logoutRedirectURI},
			})

			if rec.Code != http.StatusFound {
				t.Errorf("status = %d, want 302 - half a registration is no registration", rec.Code)
			}
		})
	}
}

// TestFrontchannelAndBackchannelCoexist pins that the two are not alternatives:
// measured, one session holding one of each answered the page **and** made the
// outbound call.
func TestFrontchannelAndBackchannelCoexist(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, _, s, realm := channelServer(t, l,
		channelClient{clientID: "both-bc", attributes: backchannelURL(l, "/both")},
		channelClient{clientID: "both-fc", frontFlag: true,
			attributes: map[string]string{frontchannelLogoutURLAttribute: "http://localhost:9998/fc"}})

	tokens := logoutTokens(t, router, "both-bc", "")
	ctx := context.Background()
	fc, err := s.Clients().ByClientID(ctx, realm.ID, "both-fc")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	if err := s.Sessions().CreateClientSession(ctx, &model.ClientSession{
		ID: model.NewID(), UserSessionID: tokens.SessionState, ClientID: fc.ID,
		Scope: "openid", StartedAt: 1,
	}); err != nil {
		t.Fatalf("CreateClientSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?id_token_hint="+tokens.IDToken+
			"&post_logout_redirect_uri="+url.QueryEscape(logoutRedirectURI), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the front-channel page's 200", rec.Code)
	}
	if n := len(l.seen()); n != 1 {
		t.Errorf("outbound calls = %d, want 1", n)
	}
}

// TestPostLogoutNotifiesEveryClientInTheSession pins that the POST family's
// scope is the session and not the caller. Measured on a two-client SSO
// session logged out through POST /logout: two outbound calls, one of them to
// the client that did not ask.
func TestPostLogoutNotifiesEveryClientInTheSession(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, _, s, realm := channelServer(t, l,
		channelClient{clientID: "post-caller", attributes: backchannelURL(l, "/caller")},
		channelClient{clientID: "post-other", attributes: backchannelURL(l, "/other")})

	tokens := logoutTokens(t, router, "post-caller", "")
	ctx := context.Background()
	other, err := s.Clients().ByClientID(ctx, realm.ID, "post-other")
	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	if err := s.Sessions().CreateClientSession(ctx, &model.ClientSession{
		ID: model.NewID(), UserSessionID: tokens.SessionState, ClientID: other.ID,
		Scope: "openid", StartedAt: 1,
	}); err != nil {
		t.Fatalf("CreateClientSession: %v", err)
	}

	form := url.Values{"client_id": {"post-caller"}, "refresh_token": {tokens.RefreshToken}}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if n := len(l.seen()); n != 2 {
		t.Errorf("outbound calls = %d, want 2 - the session, not the caller", n)
	}
}

// TestBackchannelLogoutIsNotFiredWithoutARegistration is the control the other
// tests need: a session whose clients registered nothing makes no call at all,
// so `go test` never opens a socket it did not create.
func TestBackchannelLogoutIsNotFiredWithoutARegistration(t *testing.T) {
	l := newListener(t, http.StatusOK)
	router, _, _, _ := channelServer(t, l, channelClient{clientID: "bc-none"})

	logoutWithHint(t, router, "bc-none", nil)

	if n := len(l.seen()); n != 0 {
		t.Errorf("outbound calls = %d, want 0", n)
	}
}

// TestFrontchannelHostsKeepsDuplicates pins the half of the measured policy
// that lives in this package: the host list is one entry per client, in order,
// with duplicates kept. httpx.FrameSrcPolicy pins the rest.
func TestFrontchannelHostsKeepsDuplicates(t *testing.T) {
	clients := []*model.Client{
		{Attributes: map[string]string{frontchannelLogoutURLAttribute: "http://localhost:9998/a"}},
		{Attributes: map[string]string{frontchannelLogoutURLAttribute: "http://localhost:9998/b"}},
		{Attributes: map[string]string{frontchannelLogoutURLAttribute: "https://app.example:8443/c"}},
	}

	got := frontchannelHosts(clients)

	want := []string{"localhost:9998", "localhost:9998", "app.example:8443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("hosts = %v, want %v", got, want)
	}
}
