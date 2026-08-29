package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// logoutRedirectURI is what every client registered here accepts back, and what
// the conformance fixtures register too. It never has to resolve.
const logoutRedirectURI = "http://localhost:9999/callback"

// logoutServer registers the clients the measurements were taken against. Each
// differs from the next in exactly one thing, because
// post.logout.redirect.uris was measured to have five behaviours and four of
// them are decided by the attribute's value alone.
func logoutServer(t *testing.T) (http.Handler, *handler) {
	t.Helper()
	h, s, realm := newHandler(t)
	ctx := context.Background()
	clients := []*model.Client{
		// The attribute registers the same URI the client redirects to.
		{ClientID: "lo-exact", Enabled: true, PublicClient: true,
			DirectAccessGrantsEnabled: true,
			RedirectURIs:              []string{logoutRedirectURI},
			Attributes:                map[string]string{postLogoutRedirectAttribute: logoutRedirectURI}},
		// No attribute at all. Measured: its redirectUris still validate,
		// which is the sentence in AGENTS.md this client falsifies.
		{ClientID: "lo-none", Enabled: true, PublicClient: true,
			DirectAccessGrantsEnabled: true,
			RedirectURIs:              []string{"http://localhost:9998/callback"}},
		// "+" means the same as absent.
		{ClientID: "lo-plus", Enabled: true, PublicClient: true,
			DirectAccessGrantsEnabled: true,
			RedirectURIs:              []string{"http://localhost:9997/callback"},
			Attributes:                map[string]string{postLogoutRedirectAttribute: "+"}},
		// "-" means nothing is accepted, not even its own redirectUris.
		{ClientID: "lo-minus", Enabled: true, PublicClient: true,
			DirectAccessGrantsEnabled: true,
			RedirectURIs:              []string{"http://localhost:9996/callback"},
			Attributes:                map[string]string{postLogoutRedirectAttribute: "-"}},
		// A "##"-separated pair, one of them a wildcard.
		{ClientID: "lo-multi", Enabled: true, PublicClient: true,
			DirectAccessGrantsEnabled: true,
			RedirectURIs:              []string{"http://localhost:9995/callback"},
			Attributes: map[string]string{
				postLogoutRedirectAttribute: "http://localhost:9995/cb*##http://localhost:9995/exact"}},
		// A confidential client, for the POST family's two 401s.
		{ClientID: "lo-conf", Enabled: true, DirectAccessGrantsEnabled: true,
			Secret:       "s3cret",
			RedirectURIs: []string{"http://localhost:9994/callback"},
			Attributes: map[string]string{
				postLogoutRedirectAttribute: "http://localhost:9994/callback"}},
	}
	for _, c := range clients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Protocol = "openid-connect"
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.ClientID, err)
		}
	}
	return NewRouter(s, h.keys, h.issuerBase), h
}

// logoutTokens mints a real session on one of the clients above, the way the
// conformance fixtures do: a direct grant asking for openid, so the response
// carries an ID token the logout endpoint will accept as a hint.
func logoutTokens(t *testing.T, router http.Handler, clientID, secret string) tokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {"admin"},
		"password":   {"admin"},
		"scope":      {"openid"},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	return decodeTokenResponse(t, postForm(t, router,
		"/realms/master/protocol/openid-connect/token", form))
}

// getLogout issues one GET /logout and returns the response.
func getLogout(t *testing.T, h http.Handler, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/logout?"+query.Encode(), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// sessionAlive reports whether a refresh token still works, which is the only
// observable that says a logout ended anything.
func sessionAlive(t *testing.T, router http.Handler, clientID, refresh string) bool {
	t.Helper()
	w := postForm(t, router, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {refresh},
	})
	return w.Code == http.StatusOK
}

// TestLogoutRedirectCarriesStateAndNothingElse is the case the catalogue's
// golden covers, asserted here for the part a golden cannot see: that the
// Location is built rather than echoed.
//
// The two absences are the contract. No iss, where /auth's redirect carries
// one, and no session_state, where the successful authorization redirect
// carries one.
func TestLogoutRedirectCarriesStateAndNothingElse(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	w := getLogout(t, router, url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {logoutRedirectURI},
		"state":                    {"bye"},
	})

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), logoutRedirectURI+"?state=bye"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
		t.Error("the session survived a successful logout")
	}
}

// TestLogoutDropsAnEmptyState is the one place this endpoint and /auth answer
// the same input differently, and the difference is invisible in any test that
// only ever sends a non-empty state.
//
//	/auth    state=  ->  the redirect carries state=
//	/logout  state=  ->  the redirect carries no state at all
func TestLogoutDropsAnEmptyState(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	w := getLogout(t, router, url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {logoutRedirectURI},
		"state":                    {""},
	})

	if got := w.Header().Get("Location"); got != logoutRedirectURI {
		t.Errorf("Location = %q, want %q with no state key", got, logoutRedirectURI)
	}
}

// TestLogoutWithoutAHintRedirects is the measurement that falsified AGENTS.md's
// "logout without an id_token_hint does not redirect". Without a browser
// session there is nothing to confirm, so a client_id and a registered target
// are enough.
func TestLogoutWithoutAHintRedirects(t *testing.T) {
	router, _ := logoutServer(t)

	w := getLogout(t, router, url.Values{
		"client_id":                {"lo-exact"},
		"post_logout_redirect_uri": {logoutRedirectURI},
		"state":                    {"bye"},
	})

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), logoutRedirectURI+"?state=bye"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// TestPostLogoutRedirectAttribute is the five-value table the attribute was
// measured to have. Reading it as a plain registration - "the client accepts
// what this attribute lists" - gets three of the five rows wrong.
func TestPostLogoutRedirectAttribute(t *testing.T) {
	router, _ := logoutServer(t)

	for _, tc := range []struct {
		name     string
		clientID string
		target   string
		want     int
	}{
		{"no attribute falls back to redirectUris", "lo-none",
			"http://localhost:9998/callback", http.StatusFound},
		{"no attribute refuses a sibling path", "lo-none",
			"http://localhost:9998/other", http.StatusBadRequest},
		{"+ means redirectUris", "lo-plus",
			"http://localhost:9997/callback", http.StatusFound},
		{"+ refuses a sibling path", "lo-plus",
			"http://localhost:9997/other", http.StatusBadRequest},
		{"- refuses even its own redirectUris", "lo-minus",
			"http://localhost:9996/callback", http.StatusBadRequest},
		{"## separates two patterns, the wildcard one", "lo-multi",
			"http://localhost:9995/cbxyz", http.StatusFound},
		{"## separates two patterns, the exact one", "lo-multi",
			"http://localhost:9995/exact", http.StatusFound},
		{"a listed attribute does not also accept redirectUris", "lo-multi",
			"http://localhost:9995/callback", http.StatusBadRequest},
		{"the comparison is case-sensitive", "lo-multi",
			"http://localhost:9995/CB", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := logoutTokens(t, router, tc.clientID, "")
			w := getLogout(t, router, url.Values{
				"id_token_hint":            {tok.IDToken},
				"post_logout_redirect_uri": {tc.target},
			})
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d (Location %q)",
					w.Code, tc.want, w.Header().Get("Location"))
			}
		})
	}
}

// TestLogoutHintIsCheckedBeforeTheRedirectURI drives two faults at once, which
// is the only way the order is observable: both rejections are the same 400
// page, so a request wrong in one way cannot tell them apart.
//
// Gloak's placeholder body cannot carry Keycloak's three different
// instructions, so what is asserted is that the *session survives* the
// rejection, which is the observable difference the order produces.
func TestLogoutRejectionEndsNothing(t *testing.T) {
	router, _ := logoutServer(t)

	for _, tc := range []struct {
		name  string
		query func(tok tokenResponse) url.Values
	}{
		{"an unregistered target", func(tok tokenResponse) url.Values {
			return url.Values{"id_token_hint": {tok.IDToken},
				"post_logout_redirect_uri": {"https://evil.example/cb"}}
		}},
		{"a client_id disagreeing with the hint", func(tok tokenResponse) url.Values {
			return url.Values{"id_token_hint": {tok.IDToken}, "client_id": {"lo-none"},
				"post_logout_redirect_uri": {logoutRedirectURI}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := logoutTokens(t, router, "lo-exact", "")
			w := getLogout(t, router, tc.query(tok))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if !sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
				t.Error("a rejected logout ended the session anyway")
			}
		})
	}
}

// TestLogoutRejectsAnUnusableHint covers the four measured ways an
// id_token_hint fails, each of which answers the same page.
func TestLogoutRejectsAnUnusableHint(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")
	parts := strings.Split(tok.IDToken, ".")

	for _, tc := range []struct {
		name string
		hint string
	}{
		{"not a JWT", "not-a-jwt"},
		{"an access token in the hint's place", tok.AccessToken},
		{"a refresh token in the hint's place", tok.RefreshToken},
		{"a rewritten signature", parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := getLogout(t, router, url.Values{
				"id_token_hint":            {tc.hint},
				"post_logout_redirect_uri": {logoutRedirectURI},
			})
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (Location %q)", w.Code, w.Header().Get("Location"))
			}
		})
	}
	if !sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
		t.Error("a rejected hint ended the session anyway")
	}
}

// TestLogoutAcceptsASpentHint is the measured idempotence: presenting the same
// id_token_hint twice answers the same 302, because a session that is already
// gone is a logout that has already succeeded.
func TestLogoutAcceptsASpentHint(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")
	query := url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {logoutRedirectURI},
		"state":                    {"bye"},
	}

	first := getLogout(t, router, query)
	second := getLogout(t, router, query)

	if first.Code != http.StatusFound || second.Code != http.StatusFound {
		t.Fatalf("statuses = %d then %d, want 302 twice", first.Code, second.Code)
	}
	if first.Header().Get("Location") != second.Header().Get("Location") {
		t.Errorf("the two Locations differ: %q and %q",
			first.Header().Get("Location"), second.Header().Get("Location"))
	}
}

// TestLogoutWithNoTargetServesTheRightPage covers the branch Gloak's
// placeholder body would otherwise hide: the two 200s are the same envelope
// and different pages, and which one is served says whether anybody was logged
// out.
func TestLogoutWithNoTargetServesTheRightPage(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	loggedOut := getLogout(t, router, url.Values{"id_token_hint": {tok.IDToken}})
	confirm := getLogout(t, router, url.Values{})

	for _, w := range []*httptest.ResponseRecorder{loggedOut, confirm} {
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("Cache-Control = %q, want no-cache", got)
		}
	}
	if !strings.Contains(loggedOut.Body.String(), "You are logged out") {
		t.Errorf("a valid hint did not serve the logged-out page: %s", loggedOut.Body)
	}
	if !strings.Contains(confirm.Body.String(), "Logging out") {
		t.Errorf("a bare request did not serve the confirmation page: %s", confirm.Body)
	}
	if sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
		t.Error("a hint with no redirect target did not end the session")
	}
}

// TestLogoutTargetIsAbsentWhenEmpty pins that an empty
// post_logout_redirect_uri means absent rather than unmatched - it serves the
// page instead of the 400 an unregistered target gets.
func TestLogoutTargetIsAbsentWhenEmpty(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	w := getLogout(t, router, url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {""},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
	}
}

// TestLogoutTargetWithNoClientToValidateItIsRefused covers the third
// instruction Keycloak's page carries, "Missing parameters: id_token_hint": a
// target arriving with nothing that identifies a client.
func TestLogoutTargetWithNoClientToValidateItIsRefused(t *testing.T) {
	router, _ := logoutServer(t)

	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{"no client_id and no hint", url.Values{
			"post_logout_redirect_uri": {logoutRedirectURI}}},
		{"an unknown client_id", url.Values{"client_id": {"nope"},
			"post_logout_redirect_uri": {logoutRedirectURI}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w := getLogout(t, router, tc.query); w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
		})
	}
}

// TestPostLogoutFamily is the other verb's whole contract: one success and four
// rejections, each a different shape.
func TestPostLogoutFamily(t *testing.T) {
	router, _ := logoutServer(t)

	t.Run("a refresh token ends its session and answers 204", func(t *testing.T) {
		tok := logoutTokens(t, router, "lo-exact", "")
		w := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-exact"},
			"refresh_token": {tok.RefreshToken},
		})
		if w.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204: %s", w.Code, w.Body)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("Cache-Control = %q, want no-cache", got)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Error("the 204 carries no Content-Security-Policy, and the measured one does")
		}
		if sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
			t.Error("the session survived a 204")
		}
		// Idempotent: the same token again is the same 204.
		again := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-exact"},
			"refresh_token": {tok.RefreshToken},
		})
		if again.Code != http.StatusNoContent {
			t.Errorf("the replay answered %d, want 204: %s", again.Code, again.Body)
		}
	})

	t.Run("an unusable refresh token is 400 invalid_grant", func(t *testing.T) {
		w := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-exact"},
			"refresh_token": {"not-a-jwt"},
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		const want = `{"error":"invalid_grant","error_description":"Invalid refresh token"}`
		if got := w.Body.String(); got != want {
			t.Errorf("body = %s, want %s", got, want)
		}
	})

	t.Run("another client's refresh token has its own description", func(t *testing.T) {
		tok := logoutTokens(t, router, "lo-exact", "")
		w := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-none"},
			"refresh_token": {tok.RefreshToken},
		})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		const want = `{"error":"invalid_grant","error_description":"Invalid refresh token. ` +
			`Token client and authorized client don't match"}`
		if got := w.Body.String(); got != want {
			t.Errorf("body = %s, want %s", got, want)
		}
		if !sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
			t.Error("a refused logout ended the session anyway")
		}
	})

	t.Run("no client_id is 401 invalid_client", func(t *testing.T) {
		w := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"refresh_token": {"not-a-jwt"},
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if !strings.Contains(w.Body.String(), `"invalid_client"`) {
			t.Errorf("body = %s, want invalid_client", w.Body)
		}
	})

	t.Run("a confidential client with no secret is 401 unauthorized_client", func(t *testing.T) {
		tok := logoutTokens(t, router, "lo-conf", "s3cret")
		w := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-conf"},
			"refresh_token": {tok.RefreshToken},
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401: %s", w.Code, w.Body)
		}
		if !strings.Contains(w.Body.String(), `"unauthorized_client"`) {
			t.Errorf("body = %s, want unauthorized_client", w.Body)
		}
		// And it succeeds with the secret, so the 401 was about the credential.
		ok := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
			"client_id":     {"lo-conf"},
			"client_secret": {"s3cret"},
			"refresh_token": {tok.RefreshToken},
		})
		if ok.Code != http.StatusNoContent {
			t.Errorf("with the secret: %d, want 204: %s", ok.Code, ok.Body)
		}
	})
}

// TestPostLogoutWithoutARefreshTokenFallsThrough is the measured branch point:
// the refresh_token decides which family a POST is in, and a POST without one
// answers the GET families rather than a 400 about the missing parameter.
func TestPostLogoutWithoutARefreshTokenFallsThrough(t *testing.T) {
	router, _ := logoutServer(t)

	page := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
		"client_id": {"lo-exact"},
	})
	if page.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 confirmation page: %s", page.Code, page.Body)
	}

	redirect := postForm(t, router, "/realms/master/protocol/openid-connect/logout", url.Values{
		"client_id":                {"lo-exact"},
		"post_logout_redirect_uri": {logoutRedirectURI},
	})
	if redirect.Code != http.StatusFound {
		t.Errorf("status = %d, want 302: %s", redirect.Code, redirect.Body)
	}
}

// TestPostLogoutReadsTheBodyNotTheQuery is the same asymmetry /auth has, and
// r.Form would merge the two and hide it.
func TestPostLogoutReadsTheBodyNotTheQuery(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/openid-connect/logout?"+url.Values{
			"client_id":     {"lo-exact"},
			"refresh_token": {tok.RefreshToken},
		}.Encode(), strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want the 200 page the query is ignored into: %s", w.Code, w.Body)
	}
	if !sessionAlive(t, router, "lo-exact", tok.RefreshToken) {
		t.Error("the query string's refresh_token was acted on")
	}
}

// TestLogoutDuplicatedParametersAreNotAnError is the absence /auth does not
// share: any key sent twice there is "duplicated parameter", and here the first
// value simply wins.
func TestLogoutDuplicatedParametersAreNotAnError(t *testing.T) {
	router, _ := logoutServer(t)
	tok := logoutTokens(t, router, "lo-exact", "")

	w := getLogout(t, router, url.Values{
		"id_token_hint":            {tok.IDToken},
		"post_logout_redirect_uri": {logoutRedirectURI, "https://evil.example/cb"},
		"state":                    {"a", "b"},
		"zz":                       {"1", "2"},
	})

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), logoutRedirectURI+"?state=a"; got != want {
		t.Errorf("Location = %q, want %q - the first value of each key", got, want)
	}
}

// TestLogoutResolvesTheRealmFirst pins the one rejection that is JSON rather
// than a page, and that it precedes everything else.
func TestLogoutResolvesTheRealmFirst(t *testing.T) {
	router, _ := logoutServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/realms/nope/protocol/openid-connect/logout?"+url.Values{
			"id_token_hint":            {"not-a-jwt"},
			"post_logout_redirect_uri": {"https://evil.example/cb"},
		}.Encode(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", w.Code, w.Body)
	}
	const want = `{"error":"Realm does not exist"}`
	if got := w.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

// TestLogoutIgnoresTheClientsEnabledFlag is measured and is the opposite of
// /auth, which answers a disabled client the 400 page.
func TestLogoutIgnoresTheClientsEnabledFlag(t *testing.T) {
	h, s, realm := newHandler(t)
	router := NewRouter(s, h.keys, h.issuerBase)
	client := &model.Client{
		ID: model.NewID(), RealmID: realm.ID, ClientID: "lo-off", Protocol: "openid-connect",
		PublicClient: true, RedirectURIs: []string{logoutRedirectURI},
		Attributes: map[string]string{postLogoutRedirectAttribute: logoutRedirectURI},
	}
	if err := s.Clients().Create(context.Background(), client); err != nil {
		t.Fatalf("create: %v", err)
	}

	w := getLogout(t, router, url.Values{
		"client_id":                {"lo-off"},
		"post_logout_redirect_uri": {logoutRedirectURI},
	})

	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 for a disabled client: %s", w.Code, w.Body)
	}
}
