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
	"net/http"
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

// SetContentSecurityPolicy sets the header measured on exactly one response so
// far: the token revocation success. No other recorded response carries it,
// including revocation's own error responses, so it is set at that one call
// site rather than alongside the five security headers. See
// internal/conformance/testdata/golden/oidc/revocation/refresh-token.http.
func SetContentSecurityPolicy(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"frame-src 'self'; frame-ancestors 'self'; object-src 'none';")
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

// themePageBody is Gloak's placeholder for a page the login theme renders.
//
// Keycloak serves 3574 to 4645 bytes of keycloak.v2 Freemarker output here,
// carrying a /resources/<hash>/ cache-busting segment regenerated on every
// container start. Several conformance cases are Pending against exactly that
// churn and stay Pending until P13 builds themes. What Gloak reproduces today
// is the response's **envelope**, which is measured and stable.
//
// The title is a parameter because the measured pages are not all the error
// page: `/logout` serves "Logging out" and "You are logged out" with 200s
// through the same envelope, and a 200 whose body says "We are sorry..." would
// be a placeholder that misleads about which branch was taken.
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
func WriteThemeErrorPage(w http.ResponseWriter, status int, cacheControl string) {
	WriteThemePage(w, status, cacheControl, ThemeErrorTitle)
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
func WriteThemePage(w http.ResponseWriter, status int, cacheControl, title string) {
	suppressDate(w)
	SetSecurityHeaders(w)
	SetContentSecurityPolicy(w)
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}
	w.Header().Set("Content-Language", "en")
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(themePageBody(title)))
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
