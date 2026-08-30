package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/token"
)

// The logout endpoint's six response shapes, and which request reaches each.
//
// Measured 2026-08-29 against a live 26.7.1, container kc-p6 on 8092, across
// sixty-odd probes. See docs/superpowers/plans/2026-08-29-p6-logout.md
// section 2.
//
//	302 to post_logout_redirect_uri   a validated logout with a target
//	400 theme error page              three distinct rejections
//	200 theme "Logging out" page      no hint and no target
//	200 theme "You are logged out"    a valid hint and no target
//	204 empty                         POST carrying a refresh_token
//	400/401 JSON                      the POST family's rejections
//
// Three of these differ from the authorization endpoint in a way that a reader
// comparing the two would assume away:
//
//   - **The redirect carries state and nothing else.** No iss, where /auth's
//     redirect carries one.
//   - **An empty state= is dropped**, where /auth echoes it back as state=.
//     Two endpoints, one parameter, opposite answers to the same input.
//   - **The page family carries Cache-Control: no-cache**, where /auth's page
//     family carries no Cache-Control at all. Measured side by side.
//
// A fourth difference is an absence: **there is no duplicated-parameter check**.
// /auth answers `duplicated parameter` to any key sent twice, including one it
// never reads; /logout takes the first value and acts. Measured with a good and
// a bad post_logout_redirect_uri together, with state twice, with id_token_hint
// twice and with an unread key twice - four probes, four successes.
const (
	logoutConfirmPageTitle = "Logging out"
	logoutSuccessPageTitle = "You are logged out"
	// The page family's Cache-Control, which /auth's identical-looking page
	// family does not send.
	logoutCacheControl = "no-cache"
	// The POST family's two measured invalid_grant descriptions. The second is
	// a spelling nothing else in the project carries.
	descInvalidRefreshToken = "Invalid refresh token"
	descRefreshTokenClient  = "Invalid refresh token. Token client and authorized client don't match"
)

// postLogoutRedirectAttribute holds the client's accepted post-logout targets,
// and it is a **filter over redirectUris rather than a separate registration**.
//
// Measured across five clients differing only in this attribute:
//
//	absent            the client's redirectUris
//	""                the client's redirectUris
//	"+"               the client's redirectUris
//	"-"               nothing at all; every target is refused
//	anything else     that ##-separated list, and not redirectUris
//
// This refutes the sentence AGENTS.md carried until 2026-08-29 - "a client
// whose redirect_uri validates at the authorization endpoint is still refused
// at the logout endpoint until it is set". A client registering redirectUris
// and no attribute at all was measured redirecting.
const postLogoutRedirectAttribute = "post.logout.redirect.uris"

// logout serves GET and POST /realms/{realm}/protocol/openid-connect/logout.
//
// **It serves the envelopes and not the theme's page bodies.** Three of the six
// shapes above are pages Keycloak renders from keycloak.v2 Freemarker, carrying
// a per-container resource hash; P13 builds those. What is served here is the
// measured envelope with Gloak's placeholder body, which is the same decision
// P3 made for the authorization endpoint's page family and for the same reason:
// the status, the headers and which branch was taken are what a client acts on.
//
// The confirmation page's browser-session branch is now served, which is F65.
// See confirmBeforeRedirect for the grid that places it: the browser session
// changes **one** cell of seven.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	params, err := logoutParams(r)
	if err != nil {
		h.writeLogoutErrorPage(w)
		return
	}
	// A POST carrying a refresh_token is the other family entirely: it is
	// client-authenticated, it answers JSON rather than a page, and it ignores
	// the post_logout_redirect_uri it was given. Measured: a POST with both a
	// refresh_token and an id_token_hint answers 204, so the refresh token
	// decides and not the hint.
	if r.Method == http.MethodPost && params.Get("refresh_token") != "" {
		h.logoutByRefreshToken(w, r, realm, params)
		return
	}
	h.logoutFrontChannel(w, r, realm, params)
}

// logoutFrontChannel is the browser-facing family: the id_token_hint, the
// post_logout_redirect_uri, and the pages.
//
// The order below is measured by driving two faults at once, and one step is
// not where it looks. **The id_token_hint is checked before the redirect URI**:
// a garbage hint with an unregistered URI answers about the hint, and a good
// hint with an unregistered URI answers about the URI. Reordering them changes
// the answer to a request that is wrong in two ways.
func (h *handler) logoutFrontChannel(w http.ResponseWriter, r *http.Request, realm *model.Realm, params url.Values) {
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	// Step 2. The hint, if one was sent. Every way it can fail is one page:
	// rubbish, an access or refresh token in its place, a bad signature, a
	// rewritten payload, and another realm's issuer were all measured
	// answering "Invalid parameter: id_token_hint".
	//
	// Its expiry is deliberately not checked; see token.ParseID.
	hint, ok := h.resolveLogoutHint(k, realm, params)
	if !ok {
		h.writeLogoutErrorPage(w)
		return
	}

	// Step 3. The redirect URI, validated against whichever client the request
	// identified. Measured: a target with no client to validate it against is
	// refused, which covers an absent client_id, an unknown one, and a hint
	// whose client has since been deleted.
	target, hasTarget := logoutTarget(params)
	if hasTarget {
		client := h.logoutClient(r, realm, hint, params.Get("client_id"))
		if client == nil || !matchRedirectURI(postLogoutPatterns(client), target) {
			h.writeLogoutErrorPage(w)
			return
		}
	}

	// Step 4. A browser that is signed in and has sent nothing that authorises a
	// logout is **asked** rather than redirected, and it is asked before
	// anything is destroyed. See confirmBeforeRedirect.
	if hint == nil && h.confirmBeforeRedirect(r, realm, k) {
		httpx.WriteThemePage(w, http.StatusOK, logoutCacheControl, logoutConfirmPageTitle)
		return
	}

	// Validated. Only now is anything destroyed: measured, every rejection
	// above leaves the session alive, so a failed logout is not a partial one.
	if hint != nil {
		h.endSession(r, realm, hint.SessionID)
	}

	if !hasTarget {
		// No target, so there is nothing to redirect to. Which of the two
		// pages depends on whether a session was ended, not on the request's
		// shape: a valid hint logs the user out and says so, and a request
		// carrying no authority to log anybody out asks.
		title := logoutConfirmPageTitle
		if hint != nil {
			title = logoutSuccessPageTitle
		}
		httpx.WriteThemePage(w, http.StatusOK, logoutCacheControl, title)
		return
	}
	httpx.WriteLogoutRedirect(w, logoutLocation(target, params))
}

// confirmBeforeRedirect reports whether this request gets the `Logging out`
// confirmation page instead of the redirect it asked for.
//
// **The browser session changes exactly one cell of seven**, measured with each
// row on its own fresh login:
//
//	session  hint  target   answer
//	live     no    no       200 Logging out
//	live     no    YES      200 Logging out      <- the cell, and F65
//	live     yes   no       200 You are logged out
//	live     yes   yes      302
//	none     no    no       200 Logging out
//	none     no    yes      302
//	none     yes   no       200 You are logged out
//
// So this is not "a live session means the page": a valid `id_token_hint` still
// redirects on a signed-in browser, which is why the caller asks only when there
// is no hint. Gloak answered the target cell with a 302 until now, and F65 said
// it would become a divergence the moment a session cookie was set - it did, and
// this is it.
//
// The page **ends nothing**. Measured: GET /auth immediately after it still
// answers a code, so a browser that asks to log out and is asked to confirm is
// still signed in. Destroying the session here would be the tidy-up that turns a
// question into an answer.
//
// A cookie that does not verify is not a session, and it is deliberately not
// cleared here the way the authorization endpoint clears it: nothing was
// measured clearing it on this endpoint, and inventing a Set-Cookie is inventing
// a response.
func (h *handler) confirmBeforeRedirect(r *http.Request, realm *model.Realm, k *keys.RealmKeys) bool {
	cookie, err := r.Cookie(identityCookie)
	if err != nil {
		return false
	}
	parsed, err := token.ParseIdentityCookie(k, h.realmIssuer(realm.Name), cookie.Value, time.Now())
	if err != nil {
		return false
	}
	_, err = h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	return err == nil
}

// resolveLogoutHint verifies the id_token_hint, reporting false for every way
// it can fail. A request that sent no hint at all is (nil, true): the hint is
// optional and its absence is not a rejection.
//
// The client_id check inside it is measured and is not obvious: when a request
// sends **both** an id_token_hint and a client_id and the two name different
// clients, the answer is about the hint rather than about the client. So this
// is not "the hint is well formed", it is "the hint is well formed and nothing
// beside it disagrees".
func (h *handler) resolveLogoutHint(k *keys.RealmKeys, realm *model.Realm, params url.Values) (*token.Parsed, bool) {
	raw := params.Get("id_token_hint")
	if raw == "" {
		return nil, true
	}
	parsed, err := token.ParseID(k, h.realmIssuer(realm.Name), raw)
	if err != nil {
		return nil, false
	}
	if clientID := params.Get("client_id"); clientID != "" && clientID != parsed.ClientID {
		return nil, false
	}
	return parsed, true
}

// logoutClient is the client whose registered targets a post_logout_redirect_uri
// is compared against: the hint's own client when there is a hint, and the
// client_id parameter otherwise.
//
// It returns nil when there is no such client, which the caller answers with
// the same page an unregistered URI gets. Measured: a hint whose client has
// been deleted answers "Invalid redirect uri" rather than
// "Invalid parameter: id_token_hint", so a resolvable token and a resolvable
// client are two different questions.
//
// The client's `enabled` flag is **not** consulted. Measured on a disabled
// client with a registered target: 302, where the authorization endpoint
// answers the same client a 400 page.
func (h *handler) logoutClient(r *http.Request, realm *model.Realm, hint *token.Parsed, clientID string) *model.Client {
	if hint != nil {
		clientID = hint.ClientID
	}
	if clientID == "" {
		return nil
	}
	client, err := h.store.Clients().ByClientID(r.Context(), realm.ID, clientID)
	if err != nil {
		return nil
	}
	return client
}

// endSession removes the session a hint named. A session that is already gone
// is not an error: measured, presenting the same id_token_hint a second time
// answers the same 302 rather than a rejection, so "already logged out" is a
// successful logout.
func (h *handler) endSession(r *http.Request, realm *model.Realm, sessionID string) {
	if sessionID == "" {
		return
	}
	_ = h.store.Sessions().DeleteUserSession(r.Context(), realm.ID, sessionID)
}

// logoutByRefreshToken is the POST family: a client authenticating itself and
// naming the session to end.
//
// Measured, and the three rejections are three different shapes:
//
//	no client_id at all      401 {"error":"invalid_client", ...}
//	a confidential client
//	  with no secret         401 {"error":"unauthorized_client", ...}
//	an unusable token        400 {"error":"invalid_grant",
//	                              "error_description":"Invalid refresh token"}
//	another client's token   400 {"error":"invalid_grant",
//	                              "error_description":"Invalid refresh token. Token
//	                               client and authorized client don't match"}
//
// An access token and an ID token offered as the refresh_token both take the
// third row, so the token type is asserted rather than the shape.
//
// The success is 204 with Cache-Control: no-cache and a
// Content-Security-Policy - the second protocol response measured carrying that
// header, beside revocation's success. It is idempotent: the same refresh token
// twice answers 204 twice.
func (h *handler) logoutByRefreshToken(w http.ResponseWriter, r *http.Request, realm *model.Realm, params url.Values) {
	client, authErr := h.authenticateClient(r.Context(), realm, params, r.Header)
	if authErr != nil {
		authErr.write(w)
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}

	parsed, err := token.ParseRefresh(k, h.realmIssuer(realm.Name), params.Get("refresh_token"), time.Now())
	if err != nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descInvalidRefreshToken)
		return
	}
	if parsed.ClientID != client.ClientID {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", descRefreshTokenClient)
		return
	}
	if err := h.store.Sessions().DeleteUserSession(r.Context(), realm.ID, parsed.SessionID); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.SetContentSecurityPolicy(w)
	w.Header().Set("Cache-Control", logoutCacheControl)
	httpx.WriteNoContent(w, r)
}

// logoutTarget reads the post_logout_redirect_uri, reporting absent for an
// empty one. Measured: post_logout_redirect_uri= with nothing in it serves the
// page a request with no target at all gets, where /auth's empty scope= is
// checked and fails. An empty value means absent on this parameter.
func logoutTarget(params url.Values) (string, bool) {
	target := params.Get("post_logout_redirect_uri")
	return target, target != ""
}

// logoutLocation builds the redirect.
//
// **state and nothing else.** No iss, where the authorization endpoint's
// redirect carries one, and no session_state. And an empty state= is dropped
// rather than echoed, which is the opposite of /auth: there, state= comes back
// as state=. Measured on both endpoints.
func logoutLocation(target string, params url.Values) string {
	state := params.Get("state")
	if state == "" {
		return target
	}
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + "state=" + url.QueryEscape(state)
}

// postLogoutPatterns is the set of targets a client accepts, derived from the
// attribute described at postLogoutRedirectAttribute. The patterns it returns
// are compared by matchRedirectURI, which is the authorization endpoint's own
// comparison - measured identical here on seven probes: exact and
// non-normalised, case-sensitive, "*" only as a suffix, and the query and
// fragment cut in the wildcard branch alone.
func postLogoutPatterns(client *model.Client) []string {
	raw, present := client.Attributes[postLogoutRedirectAttribute]
	switch {
	case !present, raw == "", raw == "+":
		return client.RedirectURIs
	case raw == "-":
		return nil
	}
	return strings.Split(raw, "##")
}

// writeLogoutErrorPage serves the 400 the three measured rejections share:
// an unusable id_token_hint, a post_logout_redirect_uri that does not validate,
// and a target sent with neither a hint nor a client_id to validate it against.
//
// Keycloak distinguishes the three in the page's prose - "Invalid parameter:
// id_token_hint", "Invalid redirect uri" and "Missing parameters:
// id_token_hint" - and Gloak's placeholder body cannot, which is exactly the
// gap P13 closes. The envelope is identical across all three and is what is
// served.
func (h *handler) writeLogoutErrorPage(w http.ResponseWriter) {
	httpx.WriteThemeErrorPage(w, http.StatusBadRequest, logoutCacheControl)
}

// logoutParams reads the request's parameters from the place the method puts
// them. **POST reads the body and not the query**, measured the same way
// /auth's was: the same parameters on a POST's query string answer the
// confirmation page rather than acting.
func logoutParams(r *http.Request) (url.Values, error) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.PostForm, nil
	}
	return r.URL.Query(), nil
}
