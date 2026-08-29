package oidc

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
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
//  10. prompt=none, no session   login_required
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
	descMissingResponseType    = "Missing parameter: response_type"
	descInvalidResponseMode    = "Invalid parameter: response_mode"
	descDuplicatedParameter    = "duplicated parameter"
	descMissingChallenge       = "Missing parameter: code_challenge"
	descInvalidChallengeMeth   = "Invalid parameter: code_challenge_method"
	descInvalidChallenge       = "Invalid parameter: code_challenge"
	descStandardFlowOff        = "Client is not allowed to initiate browser login with given response_type. " +
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
// **It serves the rejections and not yet the login.** A request that survives
// every check reaches the point where Keycloak renders its login page, which is
// P13's theme work, so it is answered with the page family's 400 - the same
// envelope the unknown-client and bad-redirect rejections take, whose body is
// equally Gloak's placeholder until P13. That is a real divergence from
// Keycloak, which answers 200 with a login form, and it is recorded as a
// follow-up rather than hidden: the alternatives were a login form whose POST
// target does not exist, or a status no measurement supports.
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

	// Step 10. Gloak has no browser session, so prompt=none is always the
	// no-session case. A prompt=none on a live session redirects with a real
	// code, which is the success path this cut does not serve.
	if strings.Contains(params.Get("prompt"), "none") {
		reject(mode, authErrLoginRequired, "")
		return
	}

	// Validated. Keycloak renders its login page here; see the doc comment.
	h.writeErrorPage(w, http.StatusBadRequest)
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
