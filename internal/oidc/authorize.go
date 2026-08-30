package oidc

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
)

// The authorization endpoint's two error families, and which one a request
// gets is decided before anything else is looked at.
//
// If the client_id resolves and the redirect_uri matches one of its registered
// patterns, every later rejection is a **302 to that URI** carrying error,
// error_description where there is one, state if one was sent, and iss.
// If either fails, the answer is a **400 serving the theme's error page**,
// text/html;charset=utf-8, with no Cache-Control at all. A bearer-only client
// gets the same page with a **403**.
//
// So the order below is not a preference. Get it wrong and the status, the
// family and the Content-Type are all wrong.
//
// Measured 2026-08-29 against a live 26.7.1 by driving two faults at once,
// twenty-nine paired requests, each pair deciding one adjacency:
//
//  1. realm                     404 {"error":"Realm does not exist"} - JSON, not a page
//  2. client                    400 page: absent, empty, unknown, disabled
//     2b. bearer-only              403 page, and **before** the redirect URI
//  3. redirect_uri              400 page
//     --- everything below is a 302 to the redirect URI ---
//  4. response_type absent      invalid_request "Missing parameter: response_type"
//     4b. response_type unusable   unsupported_response_type, with no description key
//  5. response_mode invalid     invalid_request "Invalid parameter: response_mode"
//  6. flow disabled             unauthorized_client, naming Standard or Implicit
//  7. a repeated parameter      invalid_request "duplicated parameter"
//  8. scope                     invalid_scope "Invalid scopes: <raw scope string>"
//  9. code_challenge absent     invalid_request "Missing parameter: code_challenge"
//     9b. method invalid           invalid_request "Invalid parameter: code_challenge_method"
//     9c. challenge malformed      invalid_request "Invalid parameter: code_challenge"
//  10. prompt and max_age        see resolveSSO
//
// Two more steps were measured on 2026-08-30 and both are in the page family,
// on the far side of the client rather than the far side of the redirect URI:
//
//	2c. max_age unparseable      400 page, "Invalid Request", **no Cache-Control**
//	10. prompt=create            400 page, "Registration not allowed", **with one**
//
// max_age's is placed by six pairs: it loses to an unknown client_id and to a
// bearer-only client and beats a bad redirect_uri, an absent response_type, a
// bad scope and prompt=none. So it sits between step 2b and step 3 - a page
// rejection between two page rejections, which is why it cannot be folded into
// either. prompt=create's is placed by five more and sits at step 10, behind
// every 302 rejection.
//
// Two steps sit where nobody would have guessed. **Step 7 is seventh**: a
// duplicated parameter on a client with the standard flow off answers "Standard
// flow is disabled", and a duplicated parameter with an invalid scope answers
// "duplicated parameter", so it is neither first nor last. And **step 9 is
// three checks whose first is the absent challenge**: code_challenge_method=bogus
// with no challenge answers "Missing parameter: code_challenge", not
// "Invalid parameter: code_challenge_method".
//
// See docs/superpowers/plans/2026-08-29-p3-serve-auth.md section 2.
const (
	authErrInvalidRequest      = "invalid_request"
	authErrUnsupportedResponse = "unsupported_response_type"
	authErrUnauthorizedClient  = "unauthorized_client"
	authErrInvalidScope        = "invalid_scope"
	authErrLoginRequired       = "login_required"
	// Measured on a consent page a browser cancelled: three keys, error, state
	// and iss, with **no error_description**. It is the same code the device
	// grant's poll answers with a sentence attached, and here there is none.
	authErrAccessDenied = "access_denied"
	// Measured on POST /login-actions/authenticate, not here: a browser whose
	// authentication session is gone and whose KC_RESTART has been cleared is
	// told its login expired, in the same four-key redirect this endpoint's own
	// rejections use. The description is lower case with an underscore, unlike
	// every prose description above it.
	authErrTemporarilyUnavailable = "temporarily_unavailable"
	descAuthenticationExpired     = "authentication_expired"
	descMissingResponseType       = "Missing parameter: response_type"
	descInvalidResponseMode       = "Invalid parameter: response_mode"
	descDuplicatedParameter       = "duplicated parameter"
	descMissingChallenge          = "Missing parameter: code_challenge"
	descInvalidChallengeMeth      = "Invalid parameter: code_challenge_method"
	descInvalidChallenge          = "Invalid parameter: code_challenge"
	descStandardFlowOff           = "Client is not allowed to initiate browser login with given response_type. " +
		"Standard flow is disabled for the client."
	descImplicitFlowOff = "Client is not allowed to initiate browser login with given response_type. " +
		"Implicit flow is disabled for the client."
)

// responseModes is the set a request may name, measured by sending fifteen
// values at an otherwise valid request. The four dotted and undotted `jwt`
// spellings are accepted although nothing here implements JARM; web_message,
// direct_post, an empty value and every case variation of an accepted one -
// QUERY, Query, FRAGMENT, FORM_POST - are refused. So the comparison is
// case-sensitive and the set is larger than the three the design named.
var responseModes = map[string]bool{
	"query":         true,
	"fragment":      true,
	"form_post":     true,
	"jwt":           true,
	"query.jwt":     true,
	"fragment.jwt":  true,
	"form_post.jwt": true,
}

// servableResponseModes is the subset whose transport Gloak can produce today,
// and the gap between it and responseModes is measured rather than assumed.
//
// The other five carry a **rejection** Gloak cannot write:
//
//	form_post, form_post.jwt   200, Content-Type text/html with no charset,
//	                           an auto-submitting HTML form
//	jwt, query.jwt             302 whose query is response=<a signed JWT>
//	fragment.jwt               the same in the fragment
//
// All five measured 2026-08-29 on a request with no response_type, so this is
// the error path and not an extrapolation from the success one. The jwt
// spellings are real JARM: the parameters are gone and a signed assertion is in
// their place.
//
// A request naming one of them answers the page family, which is what every
// branch Gloak cannot serve answers. Emitting the plain parameters instead
// would hand a JARM client an unsigned error where it asked for a signed one,
// which is worse than answering nothing.
var servableResponseModes = map[string]bool{
	"query":    true,
	"fragment": true,
}

// authorize serves GET and POST /realms/{realm}/protocol/openid-connect/auth.
//
// A request that survives all ten checks now opens an authentication session
// and renders the login form, which is what closes follow-up F50: this endpoint
// answered its own success with the page family's 400 for a day, because
// Keycloak renders a login page there and Gloak had none.
//
// **The body is still a placeholder and the envelope is measured.** Reproducing
// keycloak.v2's Freemarker output is the rest of P13; what is served here is
// the 200's headers, its three cookies and a form carrying the five parameters
// the measured one carries - which is what a browser, and the conformance
// fixtures, actually need to get to the next request.
//
// A browser that is already signed in is now recognised: KEYCLOAK_IDENTITY is
// read, and a request that survives all ten checks on a live session redirects
// with a code rather than serving the form. See sso.go, which owns step 10.
func (h *handler) authorize(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	params, err := authorizationParams(r)
	if err != nil {
		h.writeErrorPage(w, http.StatusBadRequest)
		return
	}

	// Step 2. Everything about the client that cannot be reported to it is a
	// page: an absent, empty, unknown or disabled client_id all answer the same
	// 400, and the four pages differ only in the prose Gloak does not serve.
	client, ok := h.resolveAuthClient(r, realm, params.Get("client_id"))
	if !ok {
		h.writeErrorPage(w, http.StatusBadRequest)
		return
	}
	// Step 2b. A bearer-only client is a 403 and it comes before the redirect
	// URI: master-realm answers 403 with a bad redirect_uri, with none at all,
	// and with a missing response_type alike.
	if client.BearerOnly {
		h.writeErrorPage(w, http.StatusForbidden)
		return
	}
	// Step 2c. max_age has to be a whole number, and it is checked **here**:
	// before the redirect URI and therefore before this endpoint can report
	// anything to the client at all. An empty max_age= is refused with the
	// non-numeric ones, which is the opposite of prompt=, where empty means
	// absent - two parameters on one endpoint, opposite answers to emptiness.
	//
	// The page it writes carries no Cache-Control, where prompt=create's page at
	// step 10 carries one. See writeRegistrationPage.
	if _, _, ok := parseMaxAge(params); !ok {
		h.writeErrorPage(w, http.StatusBadRequest)
		return
	}

	// Step 3. From here on the client can be told what went wrong.
	redirectURI := params.Get("redirect_uri")
	if !matchRedirectURI(client.RedirectURIs, redirectURI) {
		h.writeErrorPage(w, http.StatusBadRequest)
		return
	}

	// A response mode Gloak cannot transport stops here, before any rejection
	// is written. It has to be before rather than beside the checks below,
	// because the mode governs **every** rejection from here on: measured,
	// response_mode=form_post with no response_type answers 200 with a form
	// rather than the 302 the same request gets under query. See
	// servableResponseModes.
	if raw, present := params["response_mode"]; present &&
		responseModes[raw[0]] && !servableResponseModes[raw[0]] {
		h.writeErrorPage(w, http.StatusBadRequest)
		return
	}

	// state is echoed whenever the request sent one, **including an empty one**:
	// a request with state= comes back with state= and one with no state comes
	// back with three keys rather than an empty fourth.
	stateValues, hasState := params["state"]
	state := ""
	if hasState {
		state = stateValues[0]
	}
	reject := func(mode, code, description string) {
		httpx.WriteAuthorizationRedirect(w,
			h.authorizationErrorLocation(realm.Name, redirectURI, mode, code, description, state, hasState))
	}

	// Step 4. Absent and present-but-unusable are two different answers, and
	// an empty response_type= counts as present.
	responseType, ok := params["response_type"]
	if !ok {
		reject(defaultResponseMode(params, ""), authErrInvalidRequest, descMissingResponseType)
		return
	}
	flow, known := classifyResponseType(responseType[0])
	if !known {
		// unsupported_response_type carries no error_description at all.
		reject(defaultResponseMode(params, responseType[0]), authErrUnsupportedResponse, "")
		return
	}
	mode := defaultResponseMode(params, responseType[0])

	// Step 5. response_mode's own validity, after the response type and before
	// the flow check: a bogus mode with response_type=foo answers about the
	// response type, and with response_type=token about the mode.
	if raw, present := params["response_mode"]; present && !responseModes[raw[0]] {
		// Measured: this one rejection always goes to the **query**, even for
		// response_type=token, whose every other rejection lands in the
		// fragment. The mode that would have moved it is the invalid one, and
		// the fallback is the query rather than the response type's default.
		reject("query", authErrInvalidRequest, descInvalidResponseMode)
		return
	}

	// Step 6. The flow the response type asks for has to be enabled on the
	// client. Measured on a client with the standard flow off **and a
	// registered redirect URI**: a 302 carrying unauthorized_client, not the
	// 400 the observed document's admin-cli row suggests - admin-cli has no
	// registered redirect URI and so never reaches this step.
	switch {
	case flow == flowImplicit && !client.ImplicitFlowEnabled:
		reject(mode, authErrUnauthorizedClient, descImplicitFlowOff)
		return
	case flow == flowStandard && !client.StandardFlowEnabled:
		reject(mode, authErrUnauthorizedClient, descStandardFlowOff)
		return
	}

	// Step 7. Any repeated query parameter, including one Keycloak never reads.
	if hasDuplicate(params) {
		reject(mode, authErrInvalidRequest, descDuplicatedParameter)
		return
	}

	// Step 8. The description echoes the raw parameter, so a doubled space
	// inside it survives into the redirect.
	if raw, present := params["scope"]; present && !scopesAllowed(client, raw[0]) {
		reject(mode, authErrInvalidScope, "Invalid scopes: "+raw[0])
		return
	}

	// Step 9, three checks in this order.
	if desc, bad := checkPKCE(client, params); bad {
		reject(mode, authErrInvalidRequest, desc)
		return
	}

	// Step 10. prompt, max_age and the browser session between them decide
	// whether this browser has to type a password. sso.go owns the whole of it,
	// because the answer is one of five and only two of them are rejections.
	h.resolveSSO(w, r, realm, client, parsePrompt(params.Get("prompt")),
		&authRequest{Params: params, RedirectURI: redirectURI, Mode: mode, State: state, HasState: hasState},
		func(code, description string) { reject(mode, code, description) })
}

// authRequest is the part of a validated authorization request that outlives
// step 3, carried as one value because step 10 has five outcomes and each of
// them needs a different subset of it.
type authRequest struct {
	Params      url.Values
	RedirectURI string
	// Mode is the already-resolved response mode rather than the raw parameter,
	// so a request that named none carries the empty string here - which is what
	// makes client_data omit `rm`, the way the measured one does.
	Mode     string
	State    string
	HasState bool
}

// namedMode is the response mode the tab records: the resolved one when the
// request named a mode, and the empty string when it did not.
func (a *authRequest) namedMode() string {
	if _, present := a.Params["response_mode"]; present {
		return a.Mode
	}
	return ""
}

// tab builds the authentication tab an authorization request opens.
//
// **Four more of the request are stored than the login itself needs**: the
// scope, the nonce and the PKCE pair are consumed at the *token* endpoint, and
// the authorization code has nowhere to carry them - its three parts are a
// random value, the session_state and the client's UUID.
func (a *authRequest) tab(client *model.Client) *authTab {
	return &authTab{
		ClientID:            client.ClientID,
		ClientUUID:          client.ID,
		RedirectURI:         a.RedirectURI,
		ResponseMode:        a.namedMode(),
		State:               a.State,
		HasState:            a.HasState,
		Scope:               a.Params.Get("scope"),
		Nonce:               a.Params.Get("nonce"),
		CodeChallenge:       a.Params.Get("code_challenge"),
		CodeChallengeMethod: a.Params.Get("code_challenge_method"),
		Prompt:              a.Params.Get("prompt"),
	}
}

// restart is what KC_RESTART will point at: the same request again.
//
// It carries the PKCE pair for a reason worth spelling out: a restart that
// dropped it would let a client downgrade its own PKCE by discarding one cookie.
func (a *authRequest) restart(realm *model.Realm, client *model.Client) *restartRecord {
	return &restartRecord{
		Realm:               realm.Name,
		ClientID:            client.ClientID,
		RedirectURI:         a.RedirectURI,
		State:               a.State,
		HasState:            a.HasState,
		ResponseMode:        a.namedMode(),
		Scope:               a.Params.Get("scope"),
		Nonce:               a.Params.Get("nonce"),
		CodeChallenge:       a.Params.Get("code_challenge"),
		CodeChallengeMethod: a.Params.Get("code_challenge_method"),
	}
}

// beginLoginFromParams is what a request that survived all ten checks and has
// to be authenticated gets: an authentication session, its three cookies, and
// the login form.
//
// **The response mode is taken from the request and stored on the tab**, not
// re-derived at the login. Measured: a login started with
// response_mode=fragment puts the code in the fragment, and a client_data that
// claims rm=fragment on a tab that did not ask for it does not - so the tab is
// the authority and the browser's copy is not.
//
// It is also `prompt=login`'s answer on a browser that is already signed in.
// Keycloak serves a different **body** there - 7975 bytes against 6824, with a
// readonly kc-attempted-username, a `Please re-authenticate to continue` alert
// and a `Restart login` button - and the same status, the same headers and the
// same form action. The branch is right and the markup is P13's later work, the
// arrangement F67 already records for the other theme pages.
func (h *handler) beginLoginFromParams(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, req *authRequest) {
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	tab := req.tab(client)
	sess, err := h.beginAuthSession(w, r, realm, k, tab, req.restart(realm, client))
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.serveLoginPage(w, realm, sess, tab, "", "")
}

// beginAuthSession puts a tab into an authentication session - **the browser's
// existing one when it has a live one** - and writes only the cookies that
// request actually moves.
//
// Which cookies those are is measured, and it is not "always three":
//
//	GET /auth, first request        AUTH_SESSION_ID, KC_AUTH_SESSION_HASH, KC_RESTART
//	GET /auth, second tab, same jar KC_RESTART alone
//	the restart 302, live session   none at all
//	the restart 302, no live session AUTH_SESSION_ID, KC_AUTH_SESSION_HASH
//
// So two browser tabs share one root id - measured, and both tabs then log in
// and report the **same** session_state - and a handler that minted a session
// per authorization request would move AUTH_SESSION_ID on every one of them and
// give the two tabs different session states.
//
// KC_AUTH_SESSION_HASH's spelling is the odd one of the three: its value is
// quoted, it alone omits HttpOnly, and it carries Max-Age=60 where the session
// it names lives for half an hour.
//
// restart is nil on the restart path itself: the KC_RESTART the browser already
// holds is what it restarted from, and measured, no second one is set.
func (h *handler) beginAuthSession(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	k *keys.RealmKeys, tab *authTab, restart *restartRecord) (*authSession, error) {
	if sess, reused := h.liveAuthSession(r, realm); reused {
		if err := h.openTab(tab); err != nil {
			return nil, err
		}
		h.auth.addTab(sess, tab)
		return sess, h.writeRestartCookie(w, realm, restart)
	}
	rootID, err := randomBase64URL(rootIDBytes)
	if err != nil {
		return nil, err
	}
	return h.resumeAuthSession(w, r, realm, k, rootID, tab, restart)
}

// resumeAuthSession opens an authentication session whose root id is **given**
// and writes AUTH_SESSION_ID and KC_AUTH_SESSION_HASH for it.
//
// It is what the SSO branch needs and what beginAuthSession falls back to.
// Measured, the AUTH_SESSION_ID on an SSO redirect base64url-decodes to the
// *original user session id* and a fresh 86-character opaque half, so the root
// id is an input here rather than something minted - and KC_AUTH_SESSION_HASH
// is derived from it, which is what makes the value the same one the original
// login set.
//
// The browser's existing authentication session is deliberately **not** reused
// on the SSO path: it has to name the user session, and a session opened by an
// earlier tab does not. Every measured SSO redirect sets both cookies, on a jar
// holding all four and on one holding KEYCLOAK_IDENTITY alone.
func (h *handler) resumeAuthSession(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	k *keys.RealmKeys, rootID string, tab *authTab, restart *restartRecord) (*authSession, error) {
	if err := h.openTab(tab); err != nil {
		return nil, err
	}
	sess, err := h.auth.newAuthSession(realm.Name, rootID, sessionHash(k, rootID), tab)
	if err != nil {
		return nil, err
	}
	path := realmCookiePath(realm.Name)
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: authSessionCookie, Value: encodeAuthSessionID(sess.RootID, sess.Secret),
		Path: path, Secure: true, HTTPOnly: true, SameSite: "None",
	})
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: authHashCookie, Value: sess.Hash, Quoted: true, Path: path,
		MaxAge: int(authHashMaxAge.Seconds()), SetMaxAge: true,
		Secure: true, SameSite: "None",
	})
	return sess, h.writeRestartCookie(w, realm, restart)
}

// openTab gives a tab its id. It is the one thing every path into an
// authentication session does, and it is separate so that neither path can
// forget it: a tab with no id is a tab the login form cannot address.
func (h *handler) openTab(tab *authTab) error {
	tabID, err := randomBase64URL(tabIDBytes)
	if err != nil {
		return err
	}
	tab.TabID = tabID
	return nil
}

// writeRestartCookie sets KC_RESTART, and a nil record means no cookie at all
// rather than an empty one.
//
// Two paths pass nil and they are measured separately. The restart 302 passes
// nil because the KC_RESTART the browser already holds is what it restarted
// from; the prompt=none paths pass nil because **prompt=none never sets one** -
// its code carries four Set-Cookie headers and its login_required carries two,
// and no Max-Age=0 KC_RESTART appears on either.
func (h *handler) writeRestartCookie(w http.ResponseWriter, realm *model.Realm, restart *restartRecord) error {
	if restart == nil {
		return nil
	}
	value, err := h.auth.newRestart(restart)
	if err != nil {
		return err
	}
	httpx.SetKeycloakCookie(w, httpx.Cookie{
		Name: restartCookie, Value: value, Path: realmCookiePath(realm.Name),
		Secure: true, HTTPOnly: true, SameSite: "None",
	})
	return nil
}

// liveAuthSession resolves the authentication session a request's
// AUTH_SESSION_ID names, when it names one that is still usable.
//
// A cookie naming a session that has been **consumed by a completed login** is
// not live, and that is measured on both sides of the same value: a restart
// carrying such a cookie mints a new AUTH_SESSION_ID where a restart carrying a
// live one sets no cookie at all.
func (h *handler) liveAuthSession(r *http.Request, realm *model.Realm) (*authSession, bool) {
	cookie, err := r.Cookie(authSessionCookie)
	if err != nil {
		return nil, false
	}
	return h.auth.sessionByCookie(realm.Name, cookie.Value)
}

// responseFlow is which of the client's flow flags a response_type asks for.
type responseFlow int

const (
	flowStandard responseFlow = iota
	flowImplicit
)

// classifyResponseType splits a response_type into the flow it needs, or
// reports that Keycloak cannot use it at all.
//
// Measured: "code" and "none" are usable and so is the repeated "code code",
// because the value is read as a **set** of space-separated tokens. "code none"
// is not, nor is any case variation - "CODE" and "None" both answer
// unsupported_response_type. Anything naming "token" or "id_token" is the
// implicit or hybrid flow, and on a client with implicit disabled its error
// lands in the fragment, because the default response mode follows the
// response type.
func classifyResponseType(raw string) (responseFlow, bool) {
	tokens := map[string]bool{}
	for _, t := range strings.Fields(raw) {
		tokens[t] = true
	}
	if len(tokens) == 0 {
		return flowStandard, false
	}
	if tokens["token"] || tokens["id_token"] {
		// A hybrid response type names code as well; both need implicit.
		for t := range tokens {
			if t != "token" && t != "id_token" && t != "code" {
				return flowStandard, false
			}
		}
		return flowImplicit, true
	}
	if tokens["code"] && len(tokens) == 1 {
		return flowStandard, true
	}
	if tokens["none"] && len(tokens) == 1 {
		return flowStandard, true
	}
	return flowStandard, false
}

// defaultResponseMode is where the parameters go: the mode the request named
// when it named a usable one, and otherwise the one the response type implies.
//
// Measured: a response type naming token or id_token defaults to the fragment
// without any response_mode being sent, and everything else defaults to the
// query. An explicit response_mode=fragment moves even an error there.
func defaultResponseMode(params url.Values, responseType string) string {
	if raw, present := params["response_mode"]; present && responseModes[raw[0]] {
		return raw[0]
	}
	for _, t := range strings.Fields(responseType) {
		if t == "token" || t == "id_token" {
			return "fragment"
		}
	}
	return "query"
}

// authorizationErrorLocation builds the redirect a rejection takes.
//
// The query key order is measured: error, error_description, state, iss - and
// error_description is absent, not empty, when there is none. state is emitted
// whenever the request sent one, **including when it sent an empty one**: a
// request with state= comes back with state= and a request with no state comes
// back with three keys.
// url.Values.Encode sorts by key, which is not the measured order, so the
// parameters are joined by hand instead.
func (h *handler) authorizationErrorLocation(realm, redirectURI, mode, code, description, state string, hasState bool) string {
	parts := []string{"error=" + url.QueryEscape(code)}
	if description != "" {
		parts = append(parts, "error_description="+url.QueryEscape(description))
	}
	if hasState {
		parts = append(parts, "state="+url.QueryEscape(state))
	}
	parts = append(parts, "iss="+url.QueryEscape(h.realmIssuer(realm)))
	query := strings.Join(parts, "&")

	separator := "?"
	if mode == "fragment" || mode == "fragment.jwt" {
		separator = "#"
	}
	return redirectURI + separator + query
}

// resolveAuthClient looks up the client a request names, reporting false for
// every reason the endpoint answers with a page: an absent or empty client_id,
// one naming no client, and a disabled one.
func (h *handler) resolveAuthClient(r *http.Request, realm *model.Realm, clientID string) (*model.Client, bool) {
	if clientID == "" {
		return nil, false
	}
	client, err := h.store.Clients().ByClientID(r.Context(), realm.ID, clientID)
	if err != nil {
		// A store failure and an unknown client are the same page here. Nothing
		// observable tells them apart, and inventing a 500 for one would be a
		// shape no measurement supports.
		return nil, false
	}
	if !client.Enabled {
		return nil, false
	}
	return client, true
}

// matchRedirectURI is the measured comparison, and it is a string comparison.
//
// Against a client registering exactly http://localhost:9999/callback, all of
// these are refused: a trailing slash, an added query string, an added
// fragment, an uppercased scheme or host, an uppercased path, a ".." segment, a
// percent-encoded path character, a sub-path, 127.0.0.1 for localhost, and
// https for http. Nothing is normalised, so parsing either side as a URL is the
// tidy-up that makes half of those start comparing equal.
//
// A pattern ending in "*" is a wildcard, and it is **not** a bare prefix
// match. Measured on http://localhost:9998/*:
//
//	http://localhost:9998        accepted   the prefix with its trailing / removed
//	http://localhost:9998/       accepted
//	http://localhost:9998/a/b    accepted
//	http://localhost:9998?x=1    accepted   the query is cut before comparing
//	http://localhost:9998#f      accepted   and so is the fragment
//	http://localhost:99980/evil  refused    so it is not startsWith(".../9998")
//	http://localhost:9998x/evil  refused
//
// and on http://localhost:9994/cb*, where the prefix does not end in a slash:
// /cb, /cbx and /cb/y are accepted and a bare / is not. So the second chance
// exists only when the "*" was preceded by a slash.
//
// Two more measured qualifications. A pattern **containing a "?" is never a
// wildcard** even when it ends in one: http://localhost:9993/cb?a=* matches
// only itself and refuses ?a=1. And the "*" must be last:
// http://localhost:9992/*/cb matches nothing at all, not even /x/cb.
//
// The query and fragment are cut in the wildcard branch **only**. The exact
// branch keeps them, which is why http://localhost:9999/callback?x=1 and
// ...#f are both refused by a client registering ...callback.
func matchRedirectURI(patterns []string, uri string) bool {
	if uri == "" {
		return false
	}
	for _, pattern := range patterns {
		prefix, wildcard := strings.CutSuffix(pattern, "*")
		if !wildcard || strings.Contains(pattern, "?") {
			if pattern == uri {
				return true
			}
			continue
		}
		bare, _, _ := strings.Cut(uri, "?")
		bare, _, _ = strings.Cut(bare, "#")
		if strings.HasPrefix(bare, prefix) {
			return true
		}
		if root, ok := strings.CutSuffix(prefix, "/"); ok && bare == root {
			return true
		}
	}
	return false
}

// scopesAllowed reports whether every scope a request names is one the client
// may grant.
//
// The accepted set is openid plus the **client's** own defaultClientScopes and
// optionalClientScopes. Measured on a client the browser fixtures create: all
// eleven names in its two lists pass, and service_account, role_list,
// AuthnContextClassRef and saml_organization - client scopes of the realm that
// this client does not carry - all fail. So the set follows the client and not
// the realm, and it is not the constant list token.go grants.
//
// An absent scope is not checked at all; an empty scope= is checked and fails,
// which is why the caller tests for presence rather than for a non-empty value.
//
// A gap this cannot close on its own: internal/admin's client create does not
// default the two lists the way Keycloak does, so a client created through
// Gloak's admin API carries empty lists and refuses scope=profile where
// Keycloak accepts it. Client scopes are P5's, and the follow-up is recorded.
func scopesAllowed(client *model.Client, requested string) bool {
	allowed := map[string]bool{"openid": true}
	for _, s := range client.DefaultClientScopes {
		allowed[s] = true
	}
	for _, s := range client.OptionalClientScopes {
		allowed[s] = true
	}
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		// scope= with nothing in it: Keycloak answers "Invalid scopes: ".
		return false
	}
	for _, s := range fields {
		if !allowed[s] {
			return false
		}
	}
	return true
}

// checkPKCE runs the three PKCE checks in the measured order and returns the
// description of the first that fails.
//
// The order is the surprise. A request naming a code_challenge_method and no
// code_challenge answers "Missing parameter: code_challenge" **whatever the
// method is** - a bogus method with no challenge does not answer about the
// method. Only with a challenge present is the method's validity looked at,
// and only then the challenge's own shape.
//
// A code_challenge with no method at all is accepted: the method defaults to
// plain. A client pinning pkce.code.challenge.method refuses any other method
// and also refuses a request omitting PKCE entirely; that is measured and is
// the login page's branch, so it is not reached by this cut.
func checkPKCE(client *model.Client, params url.Values) (string, bool) {
	method, hasMethod := params["code_challenge_method"]
	challenge, hasChallenge := params["code_challenge"]
	if hasMethod && !hasChallenge {
		return descMissingChallenge, true
	}
	if !hasChallenge {
		return "", false
	}
	if hasMethod && method[0] != "plain" && method[0] != "S256" {
		return descInvalidChallengeMeth, true
	}
	if !validCodeChallenge(challenge[0]) {
		return descInvalidChallenge, true
	}
	return "", false
}

// validCodeChallenge is RFC 7636's code_challenge production: 43 to 128
// characters of unreserved base64url. Measured: a three-character challenge and
// a 43-character one made of "!" both answer "Invalid parameter:
// code_challenge", and the RFC's own 43-character example is accepted.
func validCodeChallenge(challenge string) bool {
	if len(challenge) < 43 || len(challenge) > 128 {
		return false
	}
	for _, c := range challenge {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// hasDuplicate reports whether any parameter arrived more than once. Measured:
// it applies to every key, including ones the endpoint never reads - nonce
// twice, prompt twice and an unknown zz twice all answer "duplicated
// parameter". A repeated client_id never reaches here, because the client
// cannot be resolved and the answer is the page family instead.
func hasDuplicate(params url.Values) bool {
	for _, values := range params {
		if len(values) > 1 {
			return true
		}
	}
	return false
}

// authorizationParams reads the request's parameters from the place the method
// puts them.
//
// **POST reads the body and not the query.** Measured: a POST carrying the
// parameters on the query string with no body answers the error page, and the
// same parameters in an application/x-www-form-urlencoded body serve the login
// page. r.Form would merge the two and hide the difference, so the two sources
// are read separately.
func authorizationParams(r *http.Request) (url.Values, error) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.PostForm, nil
	}
	return r.URL.Query(), nil
}

// writeErrorPage serves the family a rejection takes when it cannot be reported
// to the client: a page rather than a redirect. The body and the header set
// live in internal/httpx, which owns every response body Gloak writes.
//
// The empty Cache-Control is measured, not a default. This endpoint's page
// family sends none at all, where the logout endpoint's identical-looking page
// family sends "no-cache". Both were re-measured side by side on one container
// on 2026-08-29, which is why the writer takes the value rather than choosing.
func (h *handler) writeErrorPage(w http.ResponseWriter, status int) {
	httpx.WriteThemeErrorPage(w, status, "")
}
