package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// probeRedirectURI is what the browser conformance fixtures register and what
// every test here sends. It never has to resolve.
const probeRedirectURI = "http://localhost:9999/callback"

// authServer bootstraps master and registers the clients the measurements were
// taken against: a public one with the standard flow on, one with the standard
// flow off, one that is bearer-only, one that is disabled, and one whose
// redirect pattern ends in a wildcard.
//
// The six bootstrapped clients cannot stand in for any of these -
// security-admin-console's redirect pattern is host-relative and admin-cli
// registers none at all - which is the same reason the conformance fixtures
// register their own.
func authServer(t *testing.T) http.Handler {
	t.Helper()
	h, _ := authServerAndStore(t)
	return h
}

// authServerAndStore is authServer for the one test that has to reach past the
// protocol surface: a code whose user session has been removed answers "Code
// not valid", and no request this package can issue ends a session it does not
// hold a token for.
func authServerAndStore(t *testing.T) (http.Handler, store.Store) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	clients := []*model.Client{
		{
			ClientID: "probe", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs:         []string{probeRedirectURI},
			DefaultClientScopes:  []string{"acr", "basic", "email", "profile", "roles", "web-origins"},
			OptionalClientScopes: []string{"address", "microprofile-jwt", "offline_access", "organization", "phone"},
		},
		{ClientID: "probe-noflow", Enabled: true, PublicClient: true,
			RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-implicit", Enabled: true, PublicClient: true,
			StandardFlowEnabled: true, ImplicitFlowEnabled: true,
			RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-bearer", Enabled: true, BearerOnly: true, StandardFlowEnabled: true,
			RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-disabled", PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-wild", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"http://localhost:9998/*"}},
		// A wildcard whose "*" is not preceded by a slash, a wildcard pattern
		// carrying a query, and a "*" that is not last: three shapes that each
		// behave differently and that a single prefix rule would collapse.
		{ClientID: "probe-pathwild", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"http://localhost:9994/cb*"}},
		{ClientID: "probe-querywild", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"http://localhost:9993/cb?a=*"}},
		{ClientID: "probe-midstar", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{"http://localhost:9992/*/cb"}},
		// A confidential client that can complete a browser login, for the one
		// measurement about the token endpoint that needs client authentication
		// to fail: its 401 is reached before the code is looked at, so it is the
		// only redemption failure that does **not** spend the code.
		{ClientID: "probe-confidential", Enabled: true, StandardFlowEnabled: true,
			Secret: "s3cret", RedirectURIs: []string{probeRedirectURI}},
		// The device grant's browser half needs a client the grant is enabled
		// on - it is off on all six a default 26.7.1 bootstraps - and the
		// consent page needs one that asks for consent. They are two clients
		// rather than one because the two flows disagree about consent in a way
		// worth testing separately: the device grant asks every time and the
		// browser flow remembers.
		{ClientID: "probe-device", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RedirectURIs: []string{probeRedirectURI},
			Attributes:   map[string]string{"oauth2.device.authorization.grant.enabled": "true"}},
		{ClientID: "probe-consent", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			ConsentRequired: true, RedirectURIs: []string{probeRedirectURI}},
		// The four rootUrl/baseUrl shapes the error page's "Back to
		// Application" link was measured over, plus the fourth cell that gets
		// no link at all. See TestBackToApplicationFollowsTheBaseURL.
		{ClientID: "probe-home", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			BaseURL: "http://abs.example/home", RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-relhome", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			BaseURL: "/rel/home", RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-roothome", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RootURL: "http://root.example", BaseURL: "/rel/home",
			RedirectURIs: []string{probeRedirectURI}},
		{ClientID: "probe-rootonly", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
			RootURL: "http://root.example", RedirectURIs: []string{probeRedirectURI}},
	}
	for _, c := range clients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Protocol = "openid-connect"
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.ClientID, err)
		}
	}
	return oidc.NewRouter(s, keys.NewManager(s), testIssuerBase), s
}

// authorize issues one GET /auth and returns the response.
func authorize(t *testing.T, h http.Handler, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/auth?"+query, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// testIssuerBase is the base URL every handler in these tests is built with,
// and it is what a client's relative baseUrl resolves against.
const testIssuerBase = "http://localhost:8080"

// absent is the override value that removes a parameter. An empty string means
// "sent, with no value", which is a different request and often a different
// answer: response_type= is unsupported_response_type where an absent one is
// "Missing parameter: response_type".
const absent = "\x00"

// baseQuery is a request with nothing wrong with it. Each test below breaks
// exactly the parameters it names.
func baseQuery(overrides map[string]string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "probe")
	q.Set("redirect_uri", probeRedirectURI)
	q.Set("scope", "openid")
	q.Set("state", "xyz123")
	for k, v := range overrides {
		if v == absent {
			q.Del(k)
			continue
		}
		q.Set(k, v)
	}
	return q.Encode()
}

// locationQuery returns the Location header's query, or its fragment prefixed
// with "#" when the response mode put the parameters there.
//
// It splits the raw header rather than using url.Parse, which decodes both -
// and the percent-encoding is part of what is being asserted.
func locationQuery(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	raw := w.Header().Get("Location")
	if raw == "" {
		t.Fatalf("no Location header; status %d", w.Code)
	}
	if _, fragment, ok := strings.Cut(raw, "#"); ok {
		return "#" + fragment
	}
	_, query, _ := strings.Cut(raw, "?")
	return query
}

// TestAuthorizeRejectionOrder is the whole point of this file: every case sends
// a request that is wrong in **two** ways and asserts the earlier check wins.
// A test sending one fault at a time can prove a set of checks exists and can
// never prove the order they run in, which is what decides the answer.
//
// Measured 2026-08-29 against a live 26.7.1 on port 8085. Each row here was
// issued against the container and the expected string is what it answered.
func TestAuthorizeRejectionOrder(t *testing.T) {
	h := authServer(t)
	const issuer = "iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fmaster"

	for _, tc := range []struct {
		name      string
		overrides map[string]string
		want      string
	}{
		{
			// response_type beats scope.
			"missing response_type beats an invalid scope",
			map[string]string{"response_type": absent, "scope": "openid nosuchscope"},
			"error=invalid_request&error_description=Missing+parameter%3A+response_type&state=xyz123&" + issuer,
		},
		{
			// An unusable response_type is a different answer from an absent
			// one, and it carries no error_description key at all.
			"unsupported response_type beats an invalid scope",
			map[string]string{"response_type": "foo", "scope": "openid nosuchscope"},
			"error=unsupported_response_type&state=xyz123&" + issuer,
		},
		{
			// response_type beats response_mode.
			"unsupported response_type beats an invalid response_mode",
			map[string]string{"response_type": "foo", "response_mode": "bogus"},
			"error=unsupported_response_type&state=xyz123&" + issuer,
		},
		{
			// response_mode beats the flow check: the same request with a
			// valid mode answers unauthorized_client below.
			"invalid response_mode beats the implicit flow check",
			map[string]string{"response_type": "token", "response_mode": "bogus"},
			"error=invalid_request&error_description=Invalid+parameter%3A+response_mode&state=xyz123&" + issuer,
		},
		{
			// The flow check beats the duplicate check.
			"the disabled standard flow beats a duplicated parameter",
			map[string]string{"client_id": "probe-noflow", "__dup": "nonce=a&nonce=b"},
			"error=unauthorized_client&error_description=Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Standard+flow+is+disabled+for+the+client.&state=xyz123&" + issuer,
		},
		{
			// The duplicate check beats scope.
			"a duplicated parameter beats an invalid scope",
			map[string]string{"scope": "openid nosuchscope", "__dup": "nonce=a&nonce=b"},
			"error=invalid_request&error_description=duplicated+parameter&state=xyz123&" + issuer,
		},
		{
			// Scope beats PKCE.
			"an invalid scope beats a missing code_challenge",
			map[string]string{"scope": "openid nosuchscope", "code_challenge_method": "S256"},
			"error=invalid_scope&error_description=Invalid+scopes%3A+openid+nosuchscope&state=xyz123&" + issuer,
		},
		{
			// Inside PKCE, the absent challenge beats the invalid method. This
			// is the one nobody would guess: a bogus method with no challenge
			// answers about the challenge.
			"a missing code_challenge beats an invalid code_challenge_method",
			map[string]string{"code_challenge_method": "bogus"},
			"error=invalid_request&error_description=Missing+parameter%3A+code_challenge&state=xyz123&" + issuer,
		},
		{
			"an invalid code_challenge_method needs a challenge to be reached",
			map[string]string{
				"code_challenge_method": "bogus",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			},
			"error=invalid_request&error_description=Invalid+parameter%3A+code_challenge_method&state=xyz123&" + issuer,
		},
		{
			"a malformed code_challenge is its own answer",
			map[string]string{"code_challenge_method": "S256", "code_challenge": "abc"},
			"error=invalid_request&error_description=Invalid+parameter%3A+code_challenge&state=xyz123&" + issuer,
		},
		{
			// PKCE beats prompt=none.
			"a missing code_challenge beats prompt=none",
			map[string]string{"code_challenge_method": "S256", "prompt": "none"},
			"error=invalid_request&error_description=Missing+parameter%3A+code_challenge&state=xyz123&" + issuer,
		},
		{
			"prompt=none with no session is last",
			map[string]string{"prompt": "none"},
			"error=login_required&state=xyz123&" + issuer,
		},
		{
			// The implicit flow's rejection goes to the fragment without any
			// response_mode being asked for: the default mode follows the
			// response type.
			"the implicit flow's rejection lands in the fragment",
			map[string]string{"response_type": "token"},
			"#error=unauthorized_client&error_description=Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Implicit+flow+is+disabled+for+the+client.&state=xyz123&" + issuer,
		},
		{
			// An explicit fragment moves an error that would have gone to the
			// query.
			"response_mode=fragment moves an error to the fragment",
			map[string]string{"response_type": absent, "response_mode": "fragment"},
			"#error=invalid_request&error_description=Missing+parameter%3A+response_type&state=xyz123&" + issuer,
		},
		{
			// A state sent empty comes back empty; see the next case for the
			// absent one.
			"an empty state is echoed as an empty state",
			map[string]string{"response_type": absent, "state": ""},
			"error=invalid_request&error_description=Missing+parameter%3A+response_type&state=&" + issuer,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dup := tc.overrides["__dup"]
			overrides := map[string]string{}
			for k, v := range tc.overrides {
				if k != "__dup" {
					overrides[k] = v
				}
			}
			query := baseQuery(overrides)
			if dup != "" {
				query += "&" + dup
			}
			w := authorize(t, h, query)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302; body %s", w.Code, w.Body)
			}
			if got := locationQuery(t, w); got != tc.want {
				t.Errorf("Location query:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestAuthorizeDropsAnAbsentState pins the shape with three keys rather than an
// empty fourth. It is separate from the table because baseQuery cannot express
// "no state" and "state=" with one map.
func TestAuthorizeDropsAnAbsentState(t *testing.T) {
	h := authServer(t)
	q := url.Values{}
	q.Set("client_id", "probe")
	q.Set("redirect_uri", probeRedirectURI)
	q.Set("scope", "openid")

	w := authorize(t, h, q.Encode())

	want := "error=invalid_request&error_description=Missing+parameter%3A+response_type&" +
		"iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fmaster"
	if got := locationQuery(t, w); got != want {
		t.Errorf("Location query:\n got %s\nwant %s", got, want)
	}
}

// TestAuthorizeRedirectHeaders pins the header set on the redirect family, and
// the two absences in particular.
func TestAuthorizeRedirectHeaders(t *testing.T) {
	h := authServer(t)

	w := authorize(t, h, baseQuery(map[string]string{"response_type": absent}))

	if got, want := w.Header().Get("Cache-Control"), "no-store, must-revalidate, max-age=0"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}
	for _, name := range []string{"Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Robots-Tag"} {
		if w.Header().Get(name) == "" {
			t.Errorf("%s is missing", name)
		}
	}
	for _, name := range []string{"X-Frame-Options", "Content-Security-Policy", "Content-Type"} {
		if got, ok := w.Header()[name]; ok {
			t.Errorf("%s = %q, want absent", name, got)
		}
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", w.Body)
	}
}

// TestAuthorizePageFamily pins the other family: the rejections that cannot be
// reported to the client, because the client or its redirect URI is what
// failed. Everything here is a page, and the page carries **no Cache-Control**.
//
// Every row omits response_type as well, for the reason
// TestAuthorizeRedirectURIIsCompared gives: a fully validated request is a 400
// too until there is a login page, so without a second fault a check that
// stopped running would still answer 400 and pass.
func TestAuthorizePageFamily(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		name      string
		overrides map[string]string
		status    int
	}{
		{"an unknown client", map[string]string{"client_id": "nosuchclient"}, http.StatusBadRequest},
		{"an absent client_id", map[string]string{"client_id": absent}, http.StatusBadRequest},
		{"a disabled client", map[string]string{"client_id": "probe-disabled"}, http.StatusBadRequest},
		{"an unregistered redirect_uri", map[string]string{"redirect_uri": "https://evil.example/cb"}, http.StatusBadRequest},
		{"an absent redirect_uri", map[string]string{"redirect_uri": absent}, http.StatusBadRequest},
		// Measured: the bearer-only client answers 403 with a bad redirect URI,
		// with none at all and with a missing response_type alike, so the check
		// precedes the redirect URI rather than following it.
		{"a bearer-only client", map[string]string{"client_id": "probe-bearer"}, http.StatusForbidden},
		{"a bearer-only client with a bad redirect_uri",
			map[string]string{"client_id": "probe-bearer", "redirect_uri": "https://evil.example/cb"},
			http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			overrides := map[string]string{"response_type": absent}
			for k, v := range tc.overrides {
				overrides[k] = v
			}
			w := authorize(t, h, baseQuery(overrides))

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			if got, want := w.Header().Get("Content-Type"), "text/html;charset=utf-8"; got != want {
				t.Errorf("Content-Type = %q, want %q", got, want)
			}
			if got, want := w.Header().Get("Content-Language"), "en"; got != want {
				t.Errorf("Content-Language = %q, want %q", got, want)
			}
			if w.Header().Get("Content-Security-Policy") == "" {
				t.Error("Content-Security-Policy is missing")
			}
			if w.Header().Get("X-Frame-Options") == "" {
				t.Error("X-Frame-Options is missing")
			}
			if got, ok := w.Header()["Cache-Control"]; ok {
				t.Errorf("Cache-Control = %q, want absent", got)
			}
			if w.Header().Get("Location") != "" {
				t.Errorf("Location = %q, want none", w.Header().Get("Location"))
			}
		})
	}
}

// TestAuthorizeRedirectURIIsCompared byte for byte, with no normalisation at
// all. Each of these is a 400 against a client registering exactly
// http://localhost:9999/callback, so any implementation that parses either side
// as a URL - and so folds a trailing slash, a case difference or a percent
// escape - fails here.
//
// **Every request here also omits response_type**, and that is not decoration.
// A request Gloak validates completely is answered with the page family's 400
// too, until there is a login page, so a matching redirect URI and a rejected
// one would otherwise be the same status and the test could not tell them
// apart. A mutation making the comparison case-insensitive survived exactly
// that way before this was added. With response_type gone, a match is a 302
// and only a rejection is a 400.
func TestAuthorizeRedirectURIIsCompared(t *testing.T) {
	h := authServer(t)
	for _, uri := range []string{
		probeRedirectURI + "/",
		probeRedirectURI + "?x=1",
		probeRedirectURI + "#f",
		"HTTP://LOCALHOST:9999/callback",
		"http://localhost:9999/Callback",
		"http://localhost:9999/x/../callback",
		"http://localhost:9999/%63allback",
		probeRedirectURI + "/more",
		"http://127.0.0.1:9999/callback",
		"https://localhost:9999/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{
				"redirect_uri": uri, "response_type": absent,
			}))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 - %q must not match %q",
					w.Code, uri, probeRedirectURI)
			}
		})
	}
	t.Run("the registered URI itself", func(t *testing.T) {
		w := authorize(t, h, baseQuery(map[string]string{"response_type": absent}))
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302 - the registered URI was rejected", w.Code)
		}
	})
}

// TestAuthorizeRedirectURIWildcard. A pattern ending in "*" is not a bare
// prefix match: http://localhost:99980/evil is refused by
// http://localhost:9998/*, which is the row that separates the measured rule
// from the obvious wrong one. Every row here was issued against a live 26.7.1.
func TestAuthorizeRedirectURIWildcard(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		client string
		uri    string
		accept bool
	}{
		// The prefix ends in a slash, so the pattern also matches the URI with
		// that slash removed.
		{"probe-wild", "http://localhost:9998", true},
		{"probe-wild", "http://localhost:9998/", true},
		{"probe-wild", "http://localhost:9998/cb", true},
		{"probe-wild", "http://localhost:9998/a/b", true},
		// The query and the fragment are cut before the comparison - in this
		// branch only. The exact branch keeps both; see the test above.
		{"probe-wild", "http://localhost:9998/cb?x=1", true},
		{"probe-wild", "http://localhost:9998?x=1", true},
		{"probe-wild", "http://localhost:9998#f", true},
		{"probe-wild", "http://localhost:9998?x=1#f", true},
		// Not a prefix match on the pattern minus its "*".
		{"probe-wild", "http://localhost:99980/evil", false},
		{"probe-wild", "http://localhost:9998x/evil", false},
		{"probe-wild", "http://localhost:9997/cb", false},
		// The "*" was not preceded by a slash, so there is no second chance.
		{"probe-pathwild", "http://localhost:9994/cb", true},
		{"probe-pathwild", "http://localhost:9994/cbx", true},
		{"probe-pathwild", "http://localhost:9994/cb/y", true},
		{"probe-pathwild", "http://localhost:9994/", false},
		// A pattern containing "?" is never a wildcard, even ending in one.
		{"probe-querywild", "http://localhost:9993/cb?a=*", true},
		{"probe-querywild", "http://localhost:9993/cb?a=1", false},
		// The "*" has to be last.
		{"probe-midstar", "http://localhost:9992/x/cb", false},
		{"probe-midstar", "http://localhost:9992/anything", false},
	} {
		t.Run(tc.client+" "+tc.uri, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{
				"client_id":     tc.client,
				"redirect_uri":  tc.uri,
				"response_type": absent,
			}))
			rejected := w.Code == http.StatusBadRequest
			if tc.accept == rejected {
				t.Fatalf("status = %d for %q, accept = %v", w.Code, tc.uri, tc.accept)
			}
		})
	}
}

// TestAuthorizeScopeFollowsTheClient. The accepted set is openid plus the
// client's own default and optional client scopes, not the realm's list of
// them: service_account is a client scope of master that this client does not
// carry, and it is refused.
func TestAuthorizeScopeFollowsTheClient(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		scope  string
		accept bool
	}{
		{"openid", true},
		{"profile", true},
		{"openid profile email", true},
		{"offline_access", true},
		{"service_account", false},
		{"nosuchscope", false},
		{"openid nosuchscope", false},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{"scope": tc.scope}))
			rejected := strings.Contains(w.Header().Get("Location"), "invalid_scope")
			if tc.accept == rejected {
				t.Fatalf("scope %q: Location %q, accept = %v",
					tc.scope, w.Header().Get("Location"), tc.accept)
			}
		})
	}
}

// TestAuthorizeScopeDescriptionEchoesTheRawParameter. The description is the
// parameter as sent, so a doubled space survives into the redirect - which
// means it cannot be rebuilt by joining the parsed words.
func TestAuthorizeScopeDescriptionEchoesTheRawParameter(t *testing.T) {
	h := authServer(t)

	w := authorize(t, h, baseQuery(map[string]string{"scope": "openid  nosuchscope"}))

	want := "error=invalid_scope&error_description=Invalid+scopes%3A+openid++nosuchscope&" +
		"state=xyz123&iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fmaster"
	if got := locationQuery(t, w); got != want {
		t.Errorf("Location query:\n got %s\nwant %s", got, want)
	}
}

// TestAuthorizeAcceptsTheUsableResponseTypes. "code", "none" and the repeated
// "code code" are all usable; "code none" is not, and neither is any case
// variation.
func TestAuthorizeAcceptsTheUsableResponseTypes(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		responseType string
		usable       bool
	}{
		{"code", true},
		{"none", true},
		{"code code", true},
		{"code none", false},
		{"CODE", false},
		{"None", false},
		{"foo", false},
	} {
		t.Run(tc.responseType, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{"response_type": tc.responseType}))
			unsupported := strings.Contains(w.Header().Get("Location"), "unsupported_response_type")
			if tc.usable == unsupported {
				t.Fatalf("response_type %q: Location %q, usable = %v",
					tc.responseType, w.Header().Get("Location"), tc.usable)
			}
		})
	}
}

// TestAuthorizeResponseModeSet. The accepted set is seven values and the
// comparison is case-sensitive; the four jwt spellings are accepted although
// nothing implements JARM.
func TestAuthorizeResponseModeSet(t *testing.T) {
	h := authServer(t)
	for _, tc := range []struct {
		mode  string
		valid bool
	}{
		{"query", true},
		{"fragment", true},
		{"form_post", true},
		{"jwt", true},
		{"query.jwt", true},
		{"fragment.jwt", true},
		{"form_post.jwt", true},
		{"QUERY", false},
		{"Query", false},
		{"web_message", false},
		{"direct_post", false},
		{"", false},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{"response_mode": tc.mode}))
			refused := strings.Contains(w.Header().Get("Location"), "Invalid+parameter%3A+response_mode")
			if tc.valid == refused {
				t.Fatalf("response_mode %q: Location %q, valid = %v",
					tc.mode, w.Header().Get("Location"), tc.valid)
			}
		})
	}
}

// TestAuthorizeUnservableResponseModesAnswerThePageFamily. Five of the seven
// accepted modes carry a rejection Gloak cannot write - form_post and
// form_post.jwt answer 200 with an HTML form, and the three other jwt spellings
// answer with a signed JARM assertion in a `response` parameter. Every one of
// those was measured on a request with **no response_type**, so this is the
// error path.
//
// Gloak answers the page family rather than emitting the plain parameters,
// which would hand a JARM client an unsigned error where it asked for a signed
// one. The test's job is to catch that fabrication reappearing.
func TestAuthorizeUnservableResponseModesAnswerThePageFamily(t *testing.T) {
	h := authServer(t)
	for _, mode := range []string{"form_post", "form_post.jwt", "jwt", "query.jwt", "fragment.jwt"} {
		t.Run(mode, func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{
				"response_mode": mode, "response_type": absent,
			}))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want the page family's 400", w.Code)
			}
			if got := w.Header().Get("Location"); got != "" {
				t.Fatalf("Location = %q, want none - the parameters must not be fabricated", got)
			}
		})
	}
	// The two Gloak can transport still redirect, so the gate above is not a
	// blanket refusal of every named mode.
	for _, mode := range []string{"query", "fragment"} {
		t.Run(mode+" still redirects", func(t *testing.T) {
			w := authorize(t, h, baseQuery(map[string]string{
				"response_mode": mode, "response_type": absent,
			}))
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
		})
	}
}

// TestAuthorizeDuplicateAppliesToEveryParameter, including ones the endpoint
// never reads.
func TestAuthorizeDuplicateAppliesToEveryParameter(t *testing.T) {
	h := authServer(t)
	for _, dup := range []string{"nonce=a&nonce=b", "prompt=none&prompt=none", "zz=a&zz=b"} {
		t.Run(dup, func(t *testing.T) {
			w := authorize(t, h, baseQuery(nil)+"&"+dup)
			want := "error=invalid_request&error_description=duplicated+parameter&state=xyz123&" +
				"iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fmaster"
			if got := locationQuery(t, w); got != want {
				t.Errorf("Location query:\n got %s\nwant %s", got, want)
			}
		})
	}
}

// TestAuthorizePostReadsTheBodyNotTheQuery. Measured: a POST carrying the
// parameters on the query string with no body answers the page family, and the
// same parameters in a form body are read. r.Form merges the two and would hide
// the difference.
func TestAuthorizePostReadsTheBodyNotTheQuery(t *testing.T) {
	h := authServer(t)
	body := baseQuery(map[string]string{"response_type": absent})

	t.Run("the body is read", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost,
			"/realms/master/protocol/openid-connect/auth", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302; body %s", w.Code, w.Body)
		}
	})

	t.Run("the query is not", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost,
			"/realms/master/protocol/openid-connect/auth?"+body, nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want the page family's 400", w.Code)
		}
	})
}

// TestAuthorizeUnknownRealmIsNeitherFamily: it is the protocol side's usual
// JSON 404, which is why the realm is resolved before anything else.
func TestAuthorizeUnknownRealmIsNeitherFamily(t *testing.T) {
	h := authServer(t)
	req := httptest.NewRequest(http.MethodGet,
		"/realms/nosuchrealm/protocol/openid-connect/auth?"+baseQuery(nil), nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm does not exist"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}
