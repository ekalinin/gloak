// Package httpx owns Keycloak's error formats. They live in one package because
// compatibility breaks on error paths far more often than on success paths, and
// a format spread across handlers is a format that drifts.
//
// Keycloak 26.7.1 emits four distinct shapes. They do not split along the
// protocol/admin boundary; both sides use more than one. See
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
)

// SetSecurityHeaders sets the five security headers Keycloak 26.7.1 attaches
// to a response that reaches its filter chain: Referrer-Policy,
// Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options and
// X-Robots-Tag. This is not called from writeJSON: Keycloak does not send
// these on a request matching no route at all (see the "Fallback responses"
// section of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md),
// so callers set them explicitly rather than getting them on every response.
func SetSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("X-Robots-Tag", "none")
}

// ContentSecurityPolicy is the value every page the login theme renders sends,
// and the value the token revocation success sends. It is one of the realm's
// browserSecurityHeaders, so any response Keycloak produces through the page
// path carries it; revocation is the odd one on the protocol side rather than
// the only one in the server.
//
// (This constant's doc comment said "measured on exactly one response so far:
// the token revocation success. No other recorded response carries it" until
// 2026-08-31, and P3's sweep had falsified that on 2026-08-29 - six of the
// seven responses in the browser flow carry it, and AGENTS.md has said so
// since. The function was already called from writeThemeHTML and from
// WriteLoginActionRedirect when the sentence was still here, which is the
// failure mode AGENTS.md's charset bullet describes: the code knew and the
// comment beside it did not.)
//
// It is **not** universal, and the exception is why the value is a constant
// rather than a hard-coded string: the front-channel logout page computes its
// own - see FrameSrcPolicy.
const ContentSecurityPolicy = "frame-src 'self'; frame-ancestors 'self'; object-src 'none';"

// SetContentSecurityPolicy sets ContentSecurityPolicy. It is set at its call
// sites rather than alongside the five security headers because the responses
// that carry it and the responses that carry those are different sets: the
// authorization endpoint's redirect sends the five and not this one.
func SetContentSecurityPolicy(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
}

// FrameSrcPolicy is the Content-Security-Policy the front-channel logout page
// carries, which is the one theme page whose policy is computed per response.
//
// Measured 2026-08-31 with `od -c`, on a session holding two front-channel
// clients registered at the same host:
//
//	frame-src 'self' localhost:9998 localhost:9998 ; frame-ancestors 'self'; object-src 'none';
//
// Two details are what make this a function rather than a join:
//
//   - **The hosts are not de-duplicated.** Two clients on one host put the host
//     in twice. Deduplicating is the tidy-up that changes a measured byte.
//   - **There is a space before the semicolon.** The list is built by appending
//     "<host> " per client, so the separator that follows the last host is the
//     one the loop left behind rather than one somebody wrote.
//
// An empty list gives ContentSecurityPolicy exactly, which is what every other
// theme page sends, so the two shapes meet rather than diverging at zero.
func FrameSrcPolicy(hosts []string) string {
	if len(hosts) == 0 {
		return ContentSecurityPolicy
	}
	var b strings.Builder
	b.WriteString("frame-src 'self' ")
	for _, h := range hosts {
		b.WriteString(h)
		b.WriteString(" ")
	}
	b.WriteString("; frame-ancestors 'self'; object-src 'none';")
	return b.String()
}

// WriteAuthorizationRedirect writes the authorization endpoint's 302 back to a
// client's own registered redirect URI: the response every rejection past the
// redirect-URI check takes, and the one a successful authorization will take
// once there is a code to carry.
//
// Its header set is measured and is not any other response's. Swept 2026-08-29
// across seven different rejections on GET /auth:
//
//	Cache-Control: no-store, must-revalidate, max-age=0
//	Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options,
//	X-Robots-Tag
//	no Content-Type, no body
//	**no X-Frame-Options and no Content-Security-Policy**
//
// The two absences are the part that looks like a bug. They are not "errors
// omit them": POST /login-actions/authenticate's error redirect, to the same
// URI with the same status, carries all six. They are not "302s omit them",
// for the same reason. They are not "failures omit them": prompt=none with a
// live session redirects with a real code and omits them too. It is this
// endpoint's redirect, and RP-initiated logout's behaves the same way.
//
// X-Frame-Options is deleted rather than never set, because the router sets all
// five security headers before the mux runs - the same reason
// SetUserinfoSecurityHeaders deletes it.
func WriteAuthorizationRedirect(w http.ResponseWriter, location string) {
	suppressDate(w)
	SetSecurityHeaders(w)
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// WriteLogoutRedirect writes the RP-initiated logout endpoint's 302 back to a
// client's registered post-logout redirect URI.
//
// It is WriteAuthorizationRedirect's header set with **one** value changed, and
// that one value is why it is a separate function rather than a parameter.
// Measured 2026-08-29 side by side on one container:
//
//	GET /auth    redirect   Cache-Control: no-store, must-revalidate, max-age=0
//	GET /logout  redirect   Cache-Control: no-cache
//
// A shared writer taking the string as an argument would put the difference one
// call site away from being invisible, and this is the difference that a reader
// comparing the two endpoints most easily assumes away. Everything else is
// identical and re-measured here rather than inherited: no Content-Type, an
// empty body, the five security headers minus X-Frame-Options, and no
// Content-Security-Policy - the same two omissions, on the second endpoint that
// redirects a browser to a client's own registered URI.
func WriteLogoutRedirect(w http.ResponseWriter, location string) {
	suppressDate(w)
	SetSecurityHeaders(w)
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// WriteLoginActionRedirect writes POST /realms/{realm}/login-actions/authenticate's
// 302, and it is deliberately not WriteAuthorizationRedirect.
//
// The two are the same status, to the same client-registered URI, in the same
// flow - and their header sets differ. Measured 2026-08-30 on one container:
//
//	GET  /auth                        302   no X-Frame-Options, no Content-Security-Policy
//	POST /login-actions/authenticate  302   both present
//
// So the two omissions are `/auth`'s, not "errors omit them" and not "302s omit
// them": this endpoint's *error* redirect carries all six too, and so does its
// success. Sharing one writer and passing a flag would put that difference one
// call site away from being invisible, which is the reason WriteLogoutRedirect
// is separate as well.
//
// Cache-Control is the same string /auth's redirect sends. That is measured
// rather than inherited - the logout redirect beside them sends "no-cache".
func WriteLoginActionRedirect(w http.ResponseWriter, location string) {
	suppressDate(w)
	SetSecurityHeaders(w)
	SetContentSecurityPolicy(w)
	w.Header().Set("Cache-Control", "no-store, must-revalidate, max-age=0")
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// Cookie is one Set-Cookie header in Keycloak's own spelling.
//
// It exists because net/http's http.SetCookie cannot produce that spelling at
// all. Keycloak 26.7.1 writes its attributes with **no space after the
// semicolon** and leads with `Version=1`, an RFC 2965 attribute
// http.Cookie has no field for:
//
//	AUTH_SESSION_ID=<v>;Version=1;Path=/realms/master/;Secure;HttpOnly;SameSite=None
//	KC_AUTH_SESSION_HASH="<v>";Version=1;Path=/realms/master/;Max-Age=60;Secure;SameSite=None
//	KC_RESTART=;Version=1;Path=/realms/master/;Max-Age=0
//
// A Set-Cookie header is observable, so this is response formatting and it
// belongs in this package with every other byte Gloak writes.
//
// Quoted is for KC_AUTH_SESSION_HASH alone, whose value arrives wrapped in
// double quotes where no other cookie in the flow does. MaxAge is emitted only
// when Set is true, because 0 is a meaningful value - it is how the login
// clears KC_RESTART - and an int cannot say "absent" on its own.
type Cookie struct {
	Name      string
	Value     string
	Quoted    bool
	Path      string
	MaxAge    int
	SetMaxAge bool
	Secure    bool
	HTTPOnly  bool
	SameSite  string
}

// SetKeycloakCookie appends one Set-Cookie header in the spelling above.
//
// The header is appended through the map rather than through http.SetCookie so
// that the value is written exactly as given: SetCookie sanitises, and
// sanitising drops the double quotes around KC_AUTH_SESSION_HASH's value - so
// the cookie a browser sent back would not be the cookie it received. The
// conformance suite cannot catch that, because every case in the flow masks
// Set-Cookie as volatile; internal/httpx's own test is the guard.
func SetKeycloakCookie(w http.ResponseWriter, c Cookie) {
	value := c.Value
	if c.Quoted {
		value = `"` + value + `"`
	}
	parts := []string{c.Name + "=" + value, "Version=1"}
	if c.Path != "" {
		parts = append(parts, "Path="+c.Path)
	}
	if c.SetMaxAge {
		parts = append(parts, "Max-Age="+strconv.Itoa(c.MaxAge))
	}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HTTPOnly {
		parts = append(parts, "HttpOnly")
	}
	if c.SameSite != "" {
		parts = append(parts, "SameSite="+c.SameSite)
	}
	w.Header().Add("Set-Cookie", strings.Join(parts, ";"))
}

// LoginPageTitle is the heading Keycloak's login page carries, and the one
// WriteThemeLoginPage renders. Measured: the page's <title> is "Sign in to
// Keycloak" and its kc-page-title heading is "Sign in to your account". The
// heading is what the other theme pages differ in, so it is the heading Gloak's
// placeholder reproduces - the same choice ThemeErrorTitle already makes.
const LoginPageTitle = "Sign in to your account"

// ExpiredPageTitle is the heading of the page an unknown or absent `execution`
// answers: 200, "Page has expired". It is a third theme page, distinct from the
// login page and from the error page, and it is a 200 rather than a 400.
const ExpiredPageTitle = "Page has expired"

// WriteThemeLoginPage writes the login page: the one response in this flow
// whose body a fixture actually reads.
//
// Everything else Gloak serves through this package is a placeholder nobody
// parses. This one is parsed - `internal/conformance`'s CaptureForm tokenises
// the first <form> out of it and takes its action - so the form is real even
// though the styling is not. Measured, the page holds exactly one form, and its
// only inputs are username (text), password (password) and credentialId
// (hidden, with **no value attribute at all**).
//
// message is the feedback line a re-served page carries: "Invalid username or
// password." after a wrong credential, "Account is disabled, contact your
// administrator." for a disabled user, and empty on the first render. username
// is echoed back into the input the way the measured page echoes it.
//
// The action is written with the raw ampersands the tokeniser expects to
// unescape, so it is HTML-escaped here exactly once.
func WriteThemeLoginPage(w http.ResponseWriter, action, username, message string) {
	var body strings.Builder
	body.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Sign in to Keycloak</title></head><body>` +
		`<h1 id="kc-page-title">` + LoginPageTitle + `</h1>`)
	if message != "" {
		body.WriteString(`<span class="kc-feedback-text">` + html.EscapeString(message) + `</span>`)
	}
	body.WriteString(`<form id="kc-form-login" action="` + html.EscapeString(action) +
		`" method="post" novalidate="novalidate">` +
		`<input id="username" name="username" value="` + html.EscapeString(username) +
		`" type="text" autocomplete="username"/>` +
		`<input id="password" name="password" value="" type="password" autocomplete="current-password"/>` +
		`<input type="hidden" id="id-hidden-input" name="credentialId"/>` +
		`</form></body></html>`)
	writeThemeHTML(w, http.StatusOK, "no-store, must-revalidate, max-age=0", body.String())
}

// The headings the three pages this flow gained on 2026-08-30 carry. All three
// are measured on a live 26.7.1, and like every other page in this family the
// <title> is "Sign in to Keycloak" and the kc-page-title heading is what moves.
//
// DeviceStatusPageTitle and DeviceStatusFailedTitle are the **two** headings
// /realms/{realm}/device/status has, and the split is not the one the query
// suggests: `?error=` with an empty value is the success heading, and every
// non-empty value - including one Keycloak does not recognise - is the failure
// heading. The *instruction* underneath does distinguish `access_denied`
// ("Consent denied for connecting the device.") from an unknown code ("… and try
// connecting again."), so the page has two headings and three bodies.
const (
	DevicePageTitle         = "Device Login"
	DeviceStatusPageTitle   = "Device Login Successful"
	DeviceStatusFailedTitle = "Device Login Failed"
)

// ConsentPageTitle builds the consent page's heading, which names the client:
// measured "Grant Access to dev-a" and "Grant Access to con-a" on two clients.
// It is a function rather than a constant because it is the one heading in the
// family that is not fixed.
func ConsentPageTitle(clientID string) string { return "Grant Access to " + clientID }

// The headings /realms/{realm}/login-actions/required-action serves for the
// seven required actions a default 26.7.1 realm can reach, measured 2026-08-31
// one alias at a time on container kc-reqact.
//
// **Two aliases share one heading.** webauthn-register and
// webauthn-register-passwordless are two providers at two priorities, and both
// answer "Passkey Registration" - so a table keyed by heading would lose one of
// them, and the alias stays the key.
//
// The first four have real forms here; the last three are envelopes under a
// measured heading, because completing them needs a credential type Gloak does
// not model. That is the same debt every theme page in this package already
// carries and not a different one.
const (
	UpdatePasswordPageTitle = "Update password"
	UpdateProfilePageTitle  = "Update Account Information"
	ConfigureTOTPPageTitle  = "Mobile Authenticator Setup"
	PasskeyPageTitle        = "Passkey Registration"
	RecoveryCodesPageTitle  = "Recovery Authentication Codes"
)

// The feedback lines the two required-action pages Gloak executes carry.
//
// The first line of each is the one an untouched page shows - a warning rather
// than an error, and measured on the first render of each page. The other two
// are UPDATE_PASSWORD's two failures, and they are separate constants because
// they are measured to be different sentences for what a reader would call one
// condition: an empty new password and a mismatched confirmation.
const (
	UpdatePasswordPrompt    = "You need to change your password to activate your account."
	UpdateProfilePrompt     = "You need to update your user profile to activate your account."
	PasswordMissingMessage  = "Please specify password."
	PasswordMismatchMessage = "Passwords don't match."
)

// WriteThemeUpdatePasswordPage writes the UPDATE_PASSWORD required action's
// page, the third in this flow whose body a fixture reads.
//
// Measured, its form is a POST back to
// /realms/{realm}/login-actions/required-action **itself** - not to a sibling
// path the way the consent page posts to /login-actions/consent - carrying
// session_code, execution, client_id, tab_id and client_data, the login form's
// five with the alias in execution.
//
// Its three inputs are password-new, password-confirm and an **unchecked**
// logout-sessions checkbox with no value attribute. The checkbox is rendered
// because Keycloak renders it and nothing here reads it: what it does to a
// user's other sessions was not measured, and a form that omitted it would look
// like a form whose endpoint had never had one. That is the reasoning
// WriteThemeConsentPage already applies to its hidden `code`.
func WriteThemeUpdatePasswordPage(w http.ResponseWriter, action, message string) {
	var body strings.Builder
	body.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Sign in to Keycloak</title></head><body>` +
		`<h1 id="kc-page-title">` + UpdatePasswordPageTitle + `</h1>`)
	if message != "" {
		body.WriteString(`<span class="kc-feedback-text">` + html.EscapeString(message) + `</span>`)
	}
	body.WriteString(`<form id="kc-passwd-update-form" action="` + html.EscapeString(action) +
		`" method="post" novalidate="novalidate">` +
		`<input id="password-new" name="password-new" value="" type="password" autocomplete="new-password"/>` +
		`<input id="password-confirm" name="password-confirm" value="" type="password" autocomplete="new-password"/>` +
		`<input type="checkbox" id="logout-sessions" name="logout-sessions"/>` +
		`</form></body></html>`)
	writeThemeHTML(w, http.StatusOK, "no-store, must-revalidate, max-age=0", body.String())
}

// WriteThemeUpdateProfilePage writes the UPDATE_PROFILE required action's page.
//
// Measured, its three inputs are email, firstName and lastName, each echoing
// the user's current value, and there is **no** logout-sessions checkbox - the
// one page in this family that does not carry one, which is why the checkbox is
// written per page rather than by a shared helper.
func WriteThemeUpdateProfilePage(w http.ResponseWriter, action, email, firstName, lastName, message string) {
	var body strings.Builder
	body.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Sign in to Keycloak</title></head><body>` +
		`<h1 id="kc-page-title">` + UpdateProfilePageTitle + `</h1>`)
	if message != "" {
		body.WriteString(`<span class="kc-feedback-text">` + html.EscapeString(message) + `</span>`)
	}
	body.WriteString(`<form id="kc-update-profile-form" action="` + html.EscapeString(action) +
		`" method="post" novalidate="novalidate">` +
		`<input type="text" id="email" name="email" value="` + html.EscapeString(email) + `"/>` +
		`<input type="text" id="firstName" name="firstName" value="` + html.EscapeString(firstName) + `"/>` +
		`<input type="text" id="lastName" name="lastName" value="` + html.EscapeString(lastName) + `"/>` +
		`</form></body></html>`)
	writeThemeHTML(w, http.StatusOK, "no-store, must-revalidate, max-age=0", body.String())
}

// WriteThemeConsentPage writes the OAUTH_GRANT page: the second page in this
// flow whose body a fixture reads, after the login page.
//
// Measured, its form is a POST to /realms/{realm}/login-actions/consent with the
// authorization request's own three parameters on the query, one hidden input
// named `code`, and two submit buttons named `accept` and `cancel`. The buttons
// are what the endpoint reads - `cancel` alone decides, and the absence of both
// is an approval - so they are real inputs here even though the styling is not.
//
// The hidden `code` is rendered because Keycloak renders it. It is measurably
// **not checked**: a POST carrying `code=BOGUS` with `accept` granted the
// consent and redirected with a real authorization code. Serving the page
// without it would be a page a browser could still submit, and would hide the
// thing the endpoint's own test pins.
func WriteThemeConsentPage(w http.ResponseWriter, action, clientID, code string) {
	title := ConsentPageTitle(clientID)
	body := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>Sign in to Keycloak</title></head><body>` +
		`<h1 id="kc-page-title">` + html.EscapeString(title) + `</h1>` +
		`<form id="kc-form-consent" action="` + html.EscapeString(action) + `" method="post">` +
		`<input type="hidden" name="code" value="` + html.EscapeString(code) + `"/>` +
		`<button name="accept" id="kc-login" type="submit">Yes</button>` +
		`<button name="cancel" id="kc-cancel" type="submit">No</button>` +
		`</form></body></html>`
	writeThemeHTML(w, http.StatusOK, "no-store, must-revalidate, max-age=0", body)
}

// WriteThemeDeviceCodePage writes the device verification page, the one that
// asks for a user code.
//
// **The form it renders cannot work, and that is measured rather than a
// shortcut.** Keycloak's own page posts `device_user_code` to
// /realms/{realm}/device, and that path's POST is the RFC 8628 device
// *authorization* request - the same handler /protocol/openid-connect/auth/device
// serves - so a submission with no client_id answers 401
// {"error":"invalid_client",...}. Six probes: with the page's own cookies, with
// none, with a valid code, with an invalid one, with the code renamed and with
// it on the query. The only route through a device login is
// verification_uri_complete, the GET. Rendering a form that works would be the
// tidy-up that diverges.
//
// message is the feedback line an unusable code produces: measured "Invalid
// code, please try again." for both a well-formed unknown code and a malformed
// one, and empty on the first render. It is rendered in the alert block
// keycloak.v2 puts it in, not beside the heading.
func WriteThemeDeviceCodePage(w http.ResponseWriter, action string, c ThemeChrome, message string) {
	writeThemeHTML(w, http.StatusOK, "no-store, must-revalidate, max-age=0",
		themeDeviceVerifyBody(c, action, message))
}

// themePageBody is Gloak's placeholder for a page the login theme renders and
// this project cannot yet reproduce.
//
// Keycloak serves 3616 to 12443 bytes of keycloak.v2 Freemarker output here,
// carrying a /resources/<version>/ cache-busting segment. Nine pages are still
// this, and on 2026-09-02 every one of them was measured rather than left
// unread. The reason each is still a placeholder is no longer "nobody has read
// it off a server":
//
//	page                  data-page-id                            what stops it
//	logout confirmation   login-logout-confirm                    a tab_id and a session_code
//	You are logged out    login-info                              a tab_id
//	Page has expired      login-login-page-expired                a tab_id, the session hash
//	consent               login-login-oauth-grant                 a tab_id, a session code
//	UPDATE_PASSWORD       login-login-update-password             a tab_id, a session code
//	UPDATE_PROFILE        login-login-update-profile              a tab_id, a session code
//	CONFIGURE_TOTP        login-login-config-totp                 and a minted TOTP secret
//	Passkey               login-webauthn-register                 and a WebAuthn challenge
//	recovery codes        login-login-recovery-authn-code-config  and twelve generated codes
//
// **All nine carry a tab_id minted by the request that renders them**, and the
// first two carry it on a path where Gloak has no authentication session to
// take it from. So the placeholder is now waiting on state rather than on a
// measurement, and none of the nine can carry a conformance golden whatever
// else changes - see F146 and F38.
//
// The title is a parameter because the measured pages are not all the error
// page: `/logout` serves "Logging out" and "You are logged out" with 200s
// through the same envelope, and a 200 whose body says "We are sorry..." would
// be a placeholder that misleads about which branch was taken. The logout
// confirmation's own <title> is measured to be "Logging out" rather than
// "Sign in to <realm>", which is the one page in the family whose <title> is
// not the head template's.
func themePageBody(title string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>` + title + `</title></head><body><h1 id="kc-page-title">` + title +
		`</h1></body></html>`
}

// ThemeErrorTitle is the title Keycloak's error page carries, and the one
// WriteThemeErrorPage renders. It is exported so a handler serving a different
// theme page names its own title rather than passing a bare literal.
const ThemeErrorTitle = "We are sorry..."

// WriteThemeErrorPage writes the authorization endpoint's page family: the
// answer to every rejection that cannot be reported back to the client,
// because the client or its redirect URI is what failed.
//
// Measured 2026-08-29 on five 400s and one 403 from GET /auth:
//
//	Content-Language: en
//	Content-Security-Policy: frame-src 'self'; frame-ancestors 'self'; object-src 'none';
//	Content-Type: text/html;charset=utf-8
//	the five security headers
//	**no Cache-Control at all**
//
// The missing Cache-Control is the part that looks like an oversight: the 302
// beside it and the 200 login page both send
// "no-store, must-revalidate, max-age=0". Adding one here for consistency is
// the fix that breaks it.
//
// status is a parameter because it is not always 400: a bearer-only client
// answers 403 with this same page and these same headers.
//
// cacheControl is a parameter because the two endpoints serving this page
// disagree about it, measured 2026-08-29 side by side on one container:
//
//	GET /auth    400 page and 403 page   no Cache-Control at all
//	GET /logout  400 page                Cache-Control: no-cache
//
// So "the theme error page sends no Cache-Control" is a fact about `/auth` and
// not about the page. Callers pass "" for no header. Hard-coding either value
// here breaks the other endpoint.
//
// instruction is the sentence the page's one <p class="instruction"> carries,
// and it is the whole of what one rejection has that another does not. Thirteen
// spellings have been measured across four endpoints; they live at the call
// sites, because which one a request gets is the handler's decision and not
// this package's. F67 was the gap this closes: three logout rejections shared
// one placeholder.
func WriteThemeErrorPage(w http.ResponseWriter, status int, cacheControl string,
	c ThemeChrome, instruction string) {
	writeThemeHTML(w, status, cacheControl, themeErrorPageBody(c, instruction))
}

// WriteThemeInfoPage writes the login-info template, which is the error page
// with a different data-page-id, a different heading indentation and
// kc-info-message in place of kc-error-message.
//
// The device status page is its only measured user, and it is the reason the
// title is a parameter: that one page has **two** headings, decided by whether
// `error=` is non-empty, and three instructions.
func WriteThemeInfoPage(w http.ResponseWriter, status int, cacheControl string,
	c ThemeChrome, title, instruction string) {
	writeThemeHTML(w, status, cacheControl, themeInfoPageBody(c, title, instruction))
}

// WriteThemePage writes the envelope every page the login theme renders shares,
// with Gloak's placeholder body under the given title.
//
// The envelope is measured on eight responses across two endpoints: `/auth`'s
// five 400s and its 403, and `/logout`'s 400 error page, its "Logging out"
// confirmation page and its "You are logged out" page. All of them carry
// Content-Language: en, Content-Security-Policy, text/html;charset=utf-8 and
// the five security headers. Only the status, the Cache-Control and the body
// differ, which is why those three are the parameters and nothing else is.
//
// **A ninth page was measured on 2026-08-31 and it breaks the last sentence.**
// The front-channel logout page carries the same envelope with a
// Content-Security-Policy computed from the clients in the session, so the
// policy is a fourth thing that differs - which is why WriteThemePagePolicy
// exists beside this and why the value is not written here.
func WriteThemePage(w http.ResponseWriter, status int, cacheControl, title string) {
	WriteThemePagePolicy(w, status, cacheControl, title, ContentSecurityPolicy)
}

// WriteThemePagePolicy is WriteThemePage with the Content-Security-Policy
// chosen by the caller, which only the front-channel logout page needs. See
// FrameSrcPolicy for what it builds and why.
func WriteThemePagePolicy(w http.ResponseWriter, status int, cacheControl, title, policy string) {
	writeThemeHTMLPolicy(w, status, cacheControl, themePageBody(title), policy)
}

// writeThemeHTML is the envelope itself, shared by the placeholder pages and by
// the login page, whose body is real where theirs is a placeholder. It is one
// function so that a page gaining a real body cannot quietly gain a different
// header set with it.
func writeThemeHTML(w http.ResponseWriter, status int, cacheControl, body string) {
	writeThemeHTMLPolicy(w, status, cacheControl, body, ContentSecurityPolicy)
}

// writeThemeHTMLPolicy is writeThemeHTML with the policy as an argument. The
// two are one function rather than two so that the one page with its own policy
// cannot also quietly acquire its own header set.
func writeThemeHTMLPolicy(w http.ResponseWriter, status int, cacheControl, body, policy string) {
	suppressDate(w)
	SetSecurityHeaders(w)
	w.Header().Set("Content-Security-Policy", policy)
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.Header().Set("Content-Language", "en")
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// suppressDate omits the Date header net/http would otherwise add
// automatically. Keycloak 26.7.1 sends no Date header on any response, so a
// running Gloak that let net/http add one would differ from Keycloak on
// every single response - a divergence the conformance harness cannot see,
// since it serves through httptest.ResponseRecorder, which adds no Date
// either. Setting the map entry to nil is net/http's documented way to omit
// an otherwise-automatic header; see http.ResponseWriter.Header.
func suppressDate(w http.ResponseWriter) {
	w.Header()["Date"] = nil
}

// WriteOAuthError writes shape 1, the RFC 6749 body used by the token endpoint
// and by the admin API for an unparseable JSON payload.
func WriteOAuthError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// WriteMessageError writes shape 2: a bare error field carrying prose rather
// than an OAuth error code, used for 401 and 404 on both sides.
func WriteMessageError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// WriteAdminError writes shape 3: the errorMessage field the admin API uses for
// conflicts and validation failures.
func WriteAdminError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"errorMessage": message})
}

// SetUserinfoSecurityHeaders leaves userinfo with the four security headers it
// was measured sending. It omits X-Frame-Options, which is the second
// exception to the five reaching every response - and unlike the first (a path
// matching no route at all) it is not explained by routing, since userinfo does
// reach Keycloak's filter chain. See AGENTS.md's "Things that look like bugs
// and are not".
//
// It deletes rather than setting a smaller set because the router sets all five
// before the mux runs.
func SetUserinfoSecurityHeaders(w http.ResponseWriter) {
	SetSecurityHeaders(w)
	w.Header().Del("X-Frame-Options")
}

// WriteNoContent writes a 204, deciding from the request whether it carries
// X-Frame-Options.
//
// **The rule is about the request's Content-Type, not the method.** Measured
// 2026-08-23 by sending DELETE /users/{id} seven times with seven different
// Content-Type headers, every one answering 204:
//
//	absent              no X-Frame-Options
//	text/plain          no X-Frame-Options
//	*/*                 no X-Frame-Options
//	application/json    X-Frame-Options
//	application/xml     X-Frame-Options
//	application/x-www-form-urlencoded   X-Frame-Options
//	application/json;charset=UTF-8      X-Frame-Options
//
// It holds across every 204 measured elsewhere: the client, user, realm-role
// and credential deletes send no Content-Type and omit the header; the client
// and user updates, reset-password and disable-credential-types send JSON and
// carry it; PUT .../userLabel sends text/plain and omits it; moveToFirst and
// moveAfter send no body at all and omit it.
//
// P2's Task 11 wrote this down as "a successful DELETE's 204 omits it", from
// four DELETEs that happened to send no Content-Type. PUT .../userLabel is
// what falsified that.
//
// Cache-Control is not set here: three of the four measured deletes carry
// no-cache and DELETE .../client-secret/rotated does not, so it stays with the
// caller.
// It is also the one writer here that used not to suppress Date, so every 204
// a running Gloak sent carried one where Keycloak sends none - on the deletes,
// the updates, the credential moves and the group joins alike. The conformance
// harness cannot see it, for the reason suppressDate gives, and neither could
// the two tests that guard the rule, because both went through WriteJSON.
// Found by reading a live 204 off the wire while measuring P4's default
// groups.
func WriteNoContent(w http.ResponseWriter, r *http.Request) {
	suppressDate(w)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/") {
		w.Header().Del("X-Frame-Options")
	}
	w.WriteHeader(http.StatusNoContent)
}

// WriteBearerChallenge writes the userinfo rejection: text/plain, an empty
// body, and the error carried entirely in WWW-Authenticate.
//
// status is measured per rejection and is not always 401: a token missing the
// openid scope is answered 403. An empty errCode emits the bare
// `Bearer realm="master"` challenge Keycloak sends when no Authorization
// header arrived at all. All four shapes are recorded under
// internal/conformance/testdata/golden/oidc/userinfo/.
//
// The header name is set through the map directly rather than Header.Set,
// which would canonicalise it to "Www-Authenticate". Keycloak 26.7.1 sends
// "WWW-Authenticate" on the wire; net/http writes a header exactly as its map
// key spells it, so this is the one place that spelling has to be forced.
// The same blind spot the Date header has applies here too: a client parsing
// the response - including this package's own tests via http.Get - always
// sees the canonical form, since textproto.Reader re-canonicalises on the
// way in. Only a raw read of the wire, as in
// TestWriteBearerChallengeSendsKeycloaksHeaderCasing, can tell the two apart.
func WriteBearerChallenge(w http.ResponseWriter, status int, realm, errCode, description string) {
	suppressDate(w)
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	challenge := fmt.Sprintf("Bearer realm=%q", realm)
	if errCode != "" {
		challenge += fmt.Sprintf(", error=%q, error_description=%q", errCode, description)
	}
	w.Header()["WWW-Authenticate"] = []string{challenge}
	w.WriteHeader(status)
}

// WriteJSON writes a JSON response body byte-exact to what Keycloak sends:
// Content-Type: application/json, no trailing newline. json.Encoder always
// appends one; WriteJSON trims it. This is the only function in Gloak that
// is allowed to format a response body - every package that writes JSON,
// success or error, must go through it, so the byte-exactness guarantee
// cannot drift between call sites.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	writeJSON(w, status, "application/json", body)
}

// WriteJSONCharset is WriteJSON with ";charset=UTF-8" appended to the
// Content-Type. Measured on GET /realms/{realm}: unlike every other endpoint
// recorded so far, which sends plain "application/json", Keycloak 26.7.1
// sends this on the realm info endpoint's success response. See the "Realm
// info endpoint" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func WriteJSONCharset(w http.ResponseWriter, status int, body any) {
	writeJSON(w, status, "application/json;charset=UTF-8", body)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body any) {
	suppressDate(w)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	// Keycloak emits no trailing newline; SetEscapeHTML(false) keeps
	// descriptions containing quotes or angle brackets byte-identical.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)

	// Trim the trailing newline that json.Encoder.Encode appends
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	_, _ = w.Write(b)
}
