package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/token"
)

// Recognising a browser that has already logged in.
//
// Everything here was measured on 2026-08-30 against a live 26.7.1, container
// kc-browser on 8112. See section 0 of
// docs/superpowers/plans/2026-08-30-p13-sso-and-consent.md for the probes.

// The two errors an SSO request that cannot be served without interaction gets.
// Both are the ordinary four-key redirect, and neither carries an
// error_description.
const (
	// authErrInteractionRequired is prompt=none's answer when the browser *is*
	// signed in and the only thing missing is consent. It is measured on a
	// consentRequired client whose grant had just been revoked, and it is **not**
	// consent_required, which is the spelling RFC 8252 would suggest.
	authErrInteractionRequired = "interaction_required"
)

// The prompt values Keycloak acts on. Measured by sending twelve values at an
// otherwise valid request against a signed-in jar and an empty one.
//
// **An unrecognised value is ignored rather than refused** - prompt=bogus and
// prompt=NONE behave exactly as an absent prompt - so this is not a membership
// check with a rejection behind it. The comparison is case-sensitive, which is
// what NONE says.
const (
	promptNone    = "none"
	promptLogin   = "login"
	promptConsent = "consent"
	promptCreate  = "create"
)

// descRegistrationNotAllowed is the page prompt=create answers on a realm with
// registration disabled, which every default 26.7.1 realm is.
//
// It is the one page in this endpoint's family that carries a Cache-Control;
// see writeRegistrationPage.
const descRegistrationNotAllowed = "Registration not allowed"

// promptSet is a prompt parameter read as what it is: a set of space-separated
// tokens.
type promptSet map[string]bool

// parsePrompt splits the raw parameter. An absent or empty value is the empty
// set, and so is one holding only spaces - measured, `prompt=` and `prompt=%20`
// both behave as an absent prompt.
func parsePrompt(raw string) promptSet {
	set := promptSet{}
	for _, token := range strings.Fields(raw) {
		set[token] = true
	}
	return set
}

// browserSession is a live SSO session: the user session KEYCLOAK_IDENTITY
// names, the user it belongs to, and when that user actually authenticated.
//
// AuthTime is the session's start rather than the moment this request arrived,
// which is the whole point: measured, an access token minted from an SSO
// redirect three seconds after the login carries the **login's** auth_time and a
// later iat.
type browserSession struct {
	Session  *model.UserSession
	User     *model.User
	AuthTime time.Time
}

// resolveBrowserSession reads KEYCLOAK_IDENTITY and reports the session it
// names, when it names one that is still alive.
//
// **It is the only cookie that decides.** Measured by replaying GET /auth with
// every subset of the four cookies a completed login leaves: KEYCLOAK_IDENTITY
// alone is a code, and KEYCLOAK_SESSION, AUTH_SESSION_ID and
// KC_AUTH_SESSION_HASH in any combination without it are the login page.
// AUTH_SESSION_ID is the one a reader of the login cut would reach for, because
// it names the authentication session, and it decides nothing here.
//
// A cookie that cannot be used is **cleared**, together with KEYCLOAK_SESSION,
// and the request then proceeds as an anonymous one. Measured on three ways of
// failing - a value that is not a JWT, a valid one with three signature bytes
// rewritten, and a correctly signed one naming a session an admin had ended -
// all three answering the same pair of Max-Age=0 cookies.
func (h *handler) resolveBrowserSession(w http.ResponseWriter, r *http.Request,
	realm *model.Realm, k *keys.RealmKeys) *browserSession {
	cookie, err := r.Cookie(identityCookie)
	if err != nil {
		return nil
	}
	parsed, err := token.ParseIdentityCookie(k, h.realmIssuer(realm.Name), cookie.Value, time.Now())
	if err != nil {
		h.clearBrowserSessionCookies(w, realm)
		return nil
	}
	session, err := h.store.Sessions().UserSessionByID(r.Context(), realm.ID, parsed.SessionID)
	if err != nil {
		h.clearBrowserSessionCookies(w, realm)
		return nil
	}
	user, err := h.store.Users().ByID(r.Context(), realm.ID, parsed.Subject)
	if err != nil || !user.Enabled {
		h.clearBrowserSessionCookies(w, realm)
		return nil
	}
	return &browserSession{
		Session:  session,
		User:     user,
		AuthTime: time.UnixMilli(session.StartedAt),
	}
}

// clearBrowserSessionCookies writes the pair a browser holding an unusable
// KEYCLOAK_IDENTITY is sent.
//
// **Both go, not just the one that failed.** Measured on all three ways an
// identity cookie can be unusable, and both clears carry neither Secure nor
// HttpOnly where the cookies they clear carry them - the same asymmetry
// KC_RESTART's clear already has.
func (h *handler) clearBrowserSessionCookies(w http.ResponseWriter, realm *model.Realm) {
	path := realmCookiePath(realm.Name)
	httpx.SetKeycloakCookie(w, httpx.Cookie{Name: identityCookie, Path: path, MaxAge: 0, SetMaxAge: true})
	httpx.SetKeycloakCookie(w, httpx.Cookie{Name: sessionCookie, Path: path, MaxAge: 0, SetMaxAge: true})
}

// maxAgeSatisfied reports whether a session is fresh enough for the request's
// max_age.
//
// Measured as `now - auth_time > max_age` forces re-authentication, with the
// comparison strict: max_age=0 on a session created in the same second answers a
// code, and the same max_age=0 minutes later answers the re-authentication page.
// A negative value therefore always forces one, which is what max_age=-1
// measured on a session zero seconds old.
func maxAgeSatisfied(sess *browserSession, maxAge int64, now time.Time) bool {
	return int64(now.Sub(sess.AuthTime).Seconds()) <= maxAge
}

// parseMaxAge reads the parameter, reporting false for a value the endpoint
// refuses outright.
//
// **An empty max_age= is refused as well as a non-numeric one**, which is the
// opposite of prompt=, where an empty value is an absent one. Two parameters on
// one endpoint, opposite answers to the same emptiness.
func parseMaxAge(params url.Values) (maxAge int64, present, ok bool) {
	raw, present := params["max_age"]
	if !present {
		return 0, false, true
	}
	seconds, err := strconv.ParseInt(raw[0], 10, 64)
	if err != nil {
		return 0, true, false
	}
	return seconds, true, true
}

// resolveSSO is step 10 of the authorization endpoint: everything about whether
// this browser has to type a password.
//
// The measured decision, in this order. Nothing below it is reached once one
// branch fires:
//
//  1. prompt contains "none": no interaction is allowed.
//     - no live session                       -> login_required
//     - prompt also contains "login"          -> login_required
//     - max_age not satisfied                 -> login_required
//     - consent needed and not granted        -> interaction_required
//     - otherwise                             -> the code
//  2. prompt contains "login": always the login page, session or not.
//  3. prompt contains "create": the registration flow, which a default realm
//     refuses with a page.
//  4. a live session that satisfies max_age    -> the code, or the consent page
//  5. otherwise                                -> the login page
//
// **Rules 1 and 3 are the two a reader would get wrong.** `prompt=none login`
// is login_required on a signed-in browser, where `none` alone is a code - so
// "none must be the only value" is not the rule, `none consent` being a code
// says so. And `prompt=create` fires **only as the sole token**: `none create`,
// `create none`, `create login` and `login create` all behave as though create
// were absent, which is why rule 3 sits behind rules 1 and 2 rather than in
// front of them.
func (h *handler) resolveSSO(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, prompt promptSet, req *authRequest, reject func(code, description string)) {
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	maxAge, hasMaxAge, _ := parseMaxAge(req.Params)
	sess := h.resolveBrowserSession(w, r, realm, k)
	fresh := sess != nil && (!hasMaxAge || maxAgeSatisfied(sess, maxAge, time.Now()))

	// A pending required action is resolved once, before the branches, because
	// two of them need it and it is a store read. It is only asked for when
	// there is a session to ask about.
	var pending string
	if fresh {
		var err error
		if pending, err = h.nextRequiredAction(r.Context(), realm, sess.User); err != nil {
			httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}
	}

	if prompt[promptNone] {
		switch {
		case !fresh || prompt[promptLogin]:
			h.openSilentSession(w, r, realm, client, k, req)
			h.clearPresentedRestart(w, r, realm)
			reject(authErrLoginRequired, "")
		// **A pending required action is interaction_required, the same code a
		// pending consent gets.** Measured on a signed-in browser whose user had
		// just been given UPDATE_PASSWORD: prompt=none answered
		// error=interaction_required rather than a code, so a login that cannot
		// be finished silently is reported as one whether the missing thing is a
		// consent or an action.
		case pending != "" || h.consentNeeded(realm, client, sess.User, prompt):
			h.openSilentSession(w, r, realm, client, k, req)
			h.clearPresentedRestart(w, r, realm)
			reject(authErrInteractionRequired, "")
		default:
			h.completeSSO(w, r, realm, client, k, sess, req)
		}
		return
	}
	if prompt[promptLogin] {
		h.beginLoginFromParams(w, r, realm, client, req)
		return
	}
	if prompt[promptCreate] {
		tab := h.openSilentSession(w, r, realm, client, k, req)
		h.writeRegistrationPage(w, realm, client, tab)
		return
	}
	if fresh {
		// The action outranks the consent here as it does after a credential
		// check: measured, a consentRequired client whose user carries
		// UPDATE_PASSWORD is sent to execution=UPDATE_PASSWORD.
		if pending != "" {
			h.beginRequiredActionFromSSO(w, r, realm, client, k, sess, req, pending)
			return
		}
		if h.consentNeeded(realm, client, sess.User, prompt) {
			h.beginRequiredActionFromSSO(w, r, realm, client, k, sess, req, executionOAuthGrant)
			return
		}
		h.completeSSO(w, r, realm, client, k, sess, req)
		return
	}
	h.beginLoginFromParams(w, r, realm, client, req)
}

// The redirect a signed-in browser gets when the flow still wants a consent or a
// required action lives in requiredactions.go, as beginRequiredActionFromSSO.
//
// Measured with prompt=consent on a live session at an already-consented client:
// a **302 straight to /login-actions/required-action?execution=OAUTH_GRANT**,
// setting AUTH_SESSION_ID, KC_AUTH_SESSION_HASH and KC_RESTART, with no login
// page in between. And accepting it answers a code carrying the **original**
// session_state, so the SSO session is reused here exactly as it is on the
// silent path - which is why the authentication session is rooted at the user
// session's id and the user goes onto the tab now rather than at a credential
// check that never happens. A pending required action was measured taking the
// identical redirect with the alias in place of OAUTH_GRANT.

// openSilentSession is the pair of cookies the two rejections at step 10 send,
// and it is the part of them a reader would leave out.
//
// **login_required and prompt=create's page both set AUTH_SESSION_ID and
// KC_AUTH_SESSION_HASH**, and no KC_RESTART. Measured on four rows, each on its
// own fresh login: prompt=none anonymous, prompt=none login signed in,
// prompt=create anonymous and prompt=create signed in - all four send the same
// two. So an authorization request that got this far opens an authentication
// session whether or not anybody is ever going to log in through it, and only
// max_age's rejection at step 2c - which never reaches here - sends none at all.
//
// A failure to open one is swallowed rather than turned into a 500: the caller
// is about to write a measured rejection, and losing it to a cookie nothing
// observable asserts would be the worse answer.
func (h *handler) openSilentSession(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, k *keys.RealmKeys, req *authRequest) *authTab {
	tab := req.tab(client)
	_, _ = h.beginAuthSession(w, r, realm, k, tab, nil)
	return tab
}

// clearPresentedRestart adds a Max-Age=0 KC_RESTART when the request carried
// one, and this is the strangest measured thing in the cut.
//
// **A response can set KC_RESTART twice, in opposite directions.** The SSO
// success sets a fresh one and then clears it, six Set-Cookie headers with one
// name twice - so a browser that arrived holding a KC_RESTART leaves without
// one, because the clear is last and the last wins, while a browser that
// arrived without one leaves holding a fresh one. Measured across a jar sending
// an empty KC_RESTART, a live one and the literal `junk`; all three produce it,
// and a jar sending none produces five cookies rather than six.
//
// It is not a property of the endpoint. Measured on six branches with the same
// junk cookie present:
//
//	SSO code                   sets one and clears it
//	SSO code under prompt=none clears it, and sets none
//	login_required             clears it, and sets none
//	prompt=create's 400 page   **does not clear it**
//	the login page             sets a fresh one and does not clear it
//	max_age's 400 page         no cookies at all
//
// So the clear happens exactly when the authorization request is **finished** -
// with a code or with login_required - and not when it is refused or continued.
// Writing it in the cookie writer, or making it unconditional, gets three of
// those six rows wrong.
func (h *handler) clearPresentedRestart(w http.ResponseWriter, r *http.Request, realm *model.Realm) {
	if _, err := r.Cookie(restartCookie); err != nil {
		return
	}
	clearRestartCookie(w, realm)
}

// consentNeeded reports whether this request has to show the consent page.
//
// Two inputs, measured separately: the client's own consentRequired flag with no
// grant recorded, and prompt=consent, which re-asks a client that **has** been
// granted. prompt=consent on a client that does not require consent at all is
// measured to be a plain code, so it forces the page rather than creating a
// requirement.
func (h *handler) consentNeeded(realm *model.Realm, client *model.Client, user *model.User, prompt promptSet) bool {
	if !client.ConsentRequired {
		return false
	}
	if prompt[promptConsent] {
		return true
	}
	return !h.consents.granted(realm.ID, user.ID, client.ID)
}

// tabConsentNeeded is consentNeeded for a login in progress, and it has one more
// input than the authorization endpoint's: **the device grant asks every time.**
//
// Measured three device logins in a row, on one user, on a client whose
// consentRequired is false: all three served the OAUTH_GRANT page after the
// credentials. And a consent record **is** written - the user's `/consents`
// listing holds `dev-a` afterwards - so this is an endpoint recording a grant it
// then ignores, not an endpoint that fails to record one. Reusing the
// authorization endpoint's predicate here is the obvious saving and it skips the
// only page the device grant has.
func (h *handler) tabConsentNeeded(realm *model.Realm, client *model.Client, user *model.User, tab *authTab) bool {
	if tab.DeviceUserCode != "" {
		return true
	}
	return h.consentNeeded(realm, client, user, parsePrompt(tab.Prompt))
}

// completeSSO is the redirect a recognised browser gets: a fresh authorization
// code against the session it already has.
//
// **Three things are carried out of the original login rather than minted**, and
// all three are measured on one browser:
//
//	session_state   the original user session id, not a new one
//	auth_time       the original login's, with a later iat beside it
//	the session     no second user session is created, and the first login's
//	                refresh token still works afterwards
//
// The authentication session opened here takes the user session's id as its root
// id, which is what puts that id inside the fresh AUTH_SESSION_ID the response
// sets - measured by base64url-decoding it. It is opened rather than skipped
// because the response sets AUTH_SESSION_ID and KC_RESTART, and a browser that
// followed either of them would otherwise find nothing behind them.
func (h *handler) completeSSO(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, k *keys.RealmKeys, sess *browserSession, req *authRequest) {
	if err := h.writeSSOCode(w, r, realm, client, k, sess, req); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
	}
}

// writeSSOCode opens the authentication session, mints the code and writes the
// redirect.
//
// **prompt=none sets no KC_RESTART at all**, and it is never set rather than
// cleared: measured, the prompt=none code carries four Set-Cookie headers and
// the prompt=none login_required carries two, and neither holds a Max-Age=0
// KC_RESTART. Every other path through this endpoint sets one, which is why the
// restart record is nil-ed here rather than in resumeAuthSession.
func (h *handler) writeSSOCode(w http.ResponseWriter, r *http.Request, realm *model.Realm,
	client *model.Client, k *keys.RealmKeys, sess *browserSession, req *authRequest) error {
	tab := req.tab(client)
	restart := req.restart(realm, client)
	if parsePrompt(req.Params.Get("prompt"))[promptNone] {
		restart = nil
	}
	if _, err := h.resumeAuthSession(w, r, realm, k, sess.Session.ID, tab, restart); err != nil {
		return err
	}
	h.clearPresentedRestart(w, r, realm)
	scope := grantedScope(tab.Scope)
	// A second client on one browser session needs its own client session, or
	// the refresh token it is about to be given would have nothing to refresh
	// against. Measured: sso-b on sso-a's jar answers a code whose token carries
	// the same sid, so the user session is shared and the client session is not.
	if err := h.attachClientSession(r, sess.Session, client, scope); err != nil {
		return err
	}
	code, err := h.auth.newCode(&authCode{
		Realm:               realm.Name,
		ClientUUID:          client.ID,
		RedirectURI:         tab.RedirectURI,
		UserID:              sess.User.ID,
		SessionID:           sess.Session.ID,
		Scope:               scope,
		Nonce:               tab.Nonce,
		CodeChallenge:       tab.CodeChallenge,
		CodeChallengeMethod: tab.CodeChallengeMethod,
	})
	if err != nil {
		return err
	}
	if err := h.setLoginCookies(w, realm, k, sess.Session.ID, sess.User); err != nil {
		return err
	}
	// The redirect is /auth's own, not the login action's: measured, this
	// response omits X-Frame-Options and Content-Security-Policy the way every
	// other /auth redirect does, where POST /login-actions/authenticate's
	// carries both.
	httpx.WriteAuthorizationRedirect(w, h.authorizationCodeLocation(realm.Name, tab, sess.Session.ID, code))
	return nil
}

// attachClientSession records that this client is taking part in a user session
// that already exists, unless it already is.
//
// It is idempotent because SSO at one client is measured to be repeatable: a
// third GET /auth on the same jar answers another code, and creating a second
// client session row each time would leave the store growing for no observable
// reason.
func (h *handler) attachClientSession(r *http.Request, session *model.UserSession,
	client *model.Client, scope string) error {
	return h.attachClientSessionTo(r.Context(), session, client, scope)
}

func (h *handler) attachClientSessionTo(ctx context.Context, session *model.UserSession,
	client *model.Client, scope string) error {
	if _, err := h.store.Sessions().ClientSession(ctx, session.ID, client.ID); err == nil {
		return nil
	}
	return h.store.Sessions().CreateClientSession(ctx, &model.ClientSession{
		ID:            model.NewID(),
		UserSessionID: session.ID,
		ClientID:      client.ID,
		Scope:         scope,
		StartedAt:     time.Now().UnixMilli(),
	})
}

// writeRegistrationPage is prompt=create's answer on a realm with registration
// disabled, which is every realm a default 26.7.1 has.
//
// **It is the one page in this endpoint's family that carries a
// Cache-Control**, and that refutes AGENTS.md's three-endpoint table, which
// records /auth's page family as sending none at all. Measured side by side on
// one container:
//
//	GET /auth  max_age=abc     400 page  no Cache-Control
//	GET /auth  prompt=create   400 page  no-store, must-revalidate, max-age=0
//
// The predictor is not the endpoint but how far the request got: max_age fails
// while the parameters are being read, prompt=create fails inside the
// authentication flow, after an authentication session exists, and picks up the
// flow's header on the way out.
//
// Gloak has no registration flow, so a realm that allowed registration would
// still land here. registrationAllowed is not modelled in internal/model, which
// belongs to another stream; it is false on every default realm, so this is the
// measured answer for every realm Gloak can serve today.
// Its chrome is the only one in the family with more than a client_id in it.
// Measured 2026-09-01, the restart URL is
//
//	?client_id=<id>&tab_id=<11 chars>&client_data=<base64url>&skip_logout=true
//
// because the page is rendered from inside the authentication flow and the tab
// already exists. Those two extra values are also why this page's golden stays
// parked: the tab_id and the session hash inside checkAuthSession move on every
// request, and masking a value at a named position inside HTML is F38's
// mechanism, which is still declined.
func (h *handler) writeRegistrationPage(w http.ResponseWriter, realm *model.Realm,
	client *model.Client, tab *authTab) {
	extra := []string{"tab_id=" + url.QueryEscape(tab.TabID)}
	if data, err := tab.clientData(); err == nil {
		extra = append(extra, "client_data="+url.QueryEscape(data))
	}
	httpx.WriteThemeErrorPage(w, http.StatusBadRequest, loginActionCacheControl,
		h.themeChromeFor(realm, client, extra...), pageRegistrationNotAllowed)
}
