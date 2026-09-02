package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// What a keycloak.v2 page says about the request that produced it.
//
// Two things vary and they are decided by the same fact - whether the
// rejection happened after a client was resolved - and then by one more:
//
//   - the restart URL inside startSessionPolling carries `client_id=<id>` when
//     a client was resolved, and nothing when one was not;
//   - the "« Back to Application" link is there when that client has a
//     **baseUrl**, and its href is built from the baseUrl and the rootUrl.
//
// Measured 2026-09-01 on eight rejections across three endpoints. Two of them
// are the cells nobody would guess: a **bearer-only** client is resolved and
// the page still names no client, and the logout endpoint's id_token_hint
// rejection names no client even when the request sent a good `client_id`,
// because the hint is judged first.

// pageInstruction values are the sentences the login-error template's one
// <p class="instruction"> carries. Every one is measured; see
// docs/superpowers/plans/2026-09-01-p13-theme-markup.md for the sweep.
//
// **`Client not found.` has a full stop and `internal/oidc`'s neighbouring
// JSON error does not.** registration.go's descClientNotFound is
// `Client not found`. They are two surfaces rather than one value, which is why
// they are two constants.
const (
	pageInvalidRequest         = "Invalid Request"
	pageClientNotFound         = "Client not found."
	pageClientDisabled         = "Client disabled."
	pageBearerOnly             = "Bearer-only applications are not allowed to initiate browser login"
	pageInvalidRedirectURI     = "Invalid parameter: redirect_uri"
	pageRegistrationNotAllowed = "Registration not allowed"
	pageInvalidIDTokenHint     = "Invalid parameter: id_token_hint"
	pageInvalidLogoutRedirect  = "Invalid redirect uri"
	pageMissingIDTokenHint     = "Missing parameters: id_token_hint"
)

// The three sentences the /login-actions family's 400 page carries, and the one
// its VERIFY_EMAIL landing carries with a 500.
//
// Measured 2026-09-02, one branch at a time, across all twelve call sites that
// reach this page - see §2 of
// docs/superpowers/plans/2026-09-02-theme-remaining-pages.md. Twelve sites,
// **three** sentences and one answer that is not this page at all.
//
// pageLoginActionError is the answer to every way the client can fail on these
// three endpoints: unknown, absent, empty, and a **real client that is not the
// tab's**. That last cell is the one worth knowing, because it is the only place
// the page's own chrome and its instruction disagree - the sentence says the
// client failed and the chrome names it. `/auth` splits the same four ways into
// three different sentences; this family collapses all four into one.
//
// pageRestartCookieNotFound is the one long sentence in the family and its
// wording is the contract, full stops and all.
const (
	pageLoginActionError      = "An error occurred, please login again through your application."
	pageRestartCookieNotFound = "Restart login cookie not found. It may have expired; it may have " +
		"been deleted or cookies are disabled in your browser. If cookies are disabled then enable " +
		"them. Click Back to Application to login again."
	pageVerifyEmailFailed = "Failed to send email, please try again later."
)

// The device status page's three bodies, under two headings. The heading is in
// internal/httpx beside the other page titles; these are the sentences.
//
// The split is measured and is not the one the query suggests: `error=` with an
// empty value is the success page, and every non-empty value is a failure page,
// but only `access_denied` gets its own sentence.
const (
	pageDeviceComplete = "You may close this browser window and go back to your device."
	pageDeviceDenied   = "Consent denied for connecting the device."
	pageDeviceFailed   = "You may close this browser window and go back to your device and try connecting again."
)

// masterDisplayName and masterDisplayNameHTML are master's two display fields.
//
// They live in code rather than in the realm row because internal/bootstrap
// writes no settings blob at all, so master's realm has none to read - which is
// how internal/admin's defaultRealmRepresentation carries the same two literals
// for the same reason. Two copies of one measurement, on opposite sides of the
// boundary internal/oidc is not allowed to cross.
const (
	masterDisplayName     = "Keycloak"
	masterDisplayNameHTML = `<div class="kc-logo-text"><span>Keycloak</span></div>`
)

// realmDisplay reads the two values the theme's chrome names the realm with.
//
// The shape is decodeRealmSettings' - defaults first, the stored blob over the
// top - because that is what makes a PUT that sets or clears either of them
// visible here. The fields are pointers so a stored `""` overrides master's
// default rather than reading as absent: an empty string and an absent key are
// two different stored states, even though the page renders them the same way.
//
// A blob that will not decode is served as the defaults rather than propagated.
// This is a page's chrome; there is no answer to give a person instead.
func realmDisplay(realm *model.Realm) (displayName, displayNameHTML string) {
	if realm.Name == bootstrap.MasterRealmName {
		displayName, displayNameHTML = masterDisplayName, masterDisplayNameHTML
	}
	if len(realm.Settings) == 0 {
		return displayName, displayNameHTML
	}
	var stored struct {
		DisplayName     *string `json:"displayName"`
		DisplayNameHTML *string `json:"displayNameHtml"`
	}
	if err := json.Unmarshal(realm.Settings, &stored); err != nil {
		return displayName, displayNameHTML
	}
	if stored.DisplayName != nil {
		displayName = *stored.DisplayName
	}
	if stored.DisplayNameHTML != nil {
		displayNameHTML = *stored.DisplayNameHTML
	}
	return displayName, displayNameHTML
}

// themeChrome is the chrome of a page whose rejection resolved no client.
func (h *handler) themeChrome(realm *model.Realm) httpx.ThemeChrome {
	displayName, displayNameHTML := realmDisplay(realm)
	return httpx.ThemeChrome{
		Realm:           realm.Name,
		DisplayName:     displayName,
		DisplayNameHTML: displayNameHTML,
	}
}

// themeChromeFor is the chrome of a page that did resolve one, with any extra
// restart parameters the page carries in front of skip_logout.
//
// extra exists for prompt=create alone, whose page is rendered from inside the
// authentication flow and whose restart URL therefore carries a tab_id and a
// client_data as well.
func (h *handler) themeChromeFor(realm *model.Realm, client *model.Client, extra ...string) httpx.ThemeChrome {
	params := append([]string{"client_id=" + url.QueryEscape(client.ClientID)}, extra...)
	c := h.themeChrome(realm)
	c.RestartParams = httpx.ThemeRestartParams(params...)
	c.BackToApplication = h.clientHomeURL(client)
	return c
}

// loginActionChrome is the chrome every page the /login-actions family serves
// carries, and it follows the request's own client_id rather than the tab's.
//
// Measured 2026-09-02 as a four-cell sweep on one container, on a tab belonging
// to one client:
//
//	client_id resolves            restart?client_id=<it>&skip_logout=true, and its Back to Application link
//	client_id is another real one restart?client_id=<that other one>, and **that** client's link
//	client_id unknown or empty    restart?skip_logout=true, no link
//	client_id absent              restart?skip_logout=true, no link
//
// The second cell is the finding. The page's instruction on that cell says the
// client failed - it is not the tab's - and the chrome names it anyway, so the
// two halves of one response describe two different judgements. Reading the
// chrome off the tab is the obvious implementation and it is wrong there.
//
// It is also why this takes url.Values rather than a resolved client: three of
// the four cells have no client to pass.
func (h *handler) loginActionChrome(r *http.Request, realm *model.Realm, q url.Values) httpx.ThemeChrome {
	if client, ok := h.authClient(r, realm, q.Get("client_id")); ok {
		return h.themeChromeFor(realm, client)
	}
	return h.themeChrome(realm)
}

// flowChrome is the chrome of a page rendered from **inside** the
// authentication flow, where a tab already exists.
//
// Measured on the two pages that are: prompt=create's 400 and VERIFY_EMAIL's
// 500. Their restart URL carries three parameters where the rest of the family
// carries one:
//
//	?client_id=<id>&tab_id=<11 chars>&client_data=<base64url>&skip_logout=true
//
// Those two extra values are also why neither page can carry a golden. A tab
// whose client_data will not encode contributes nothing rather than an empty
// parameter, because an empty client_data is not a shape any measurement shows.
func (h *handler) flowChrome(realm *model.Realm, client *model.Client, tab *authTab) httpx.ThemeChrome {
	extra := []string{"tab_id=" + url.QueryEscape(tab.TabID)}
	if data, err := tab.clientData(); err == nil {
		extra = append(extra, "client_data="+url.QueryEscape(data))
	}
	return h.themeChromeFor(realm, client, extra...)
}

// clientHomeURL is the href of the error page's "Back to Application" link,
// and it is empty when there is no link.
//
// Measured over five clients on 2026-09-01:
//
//	baseUrl absolute                    the baseUrl
//	baseUrl relative, no rootUrl        the server's base URL + baseUrl
//	baseUrl relative, rootUrl absolute  the rootUrl + baseUrl
//	rootUrl set, no baseUrl             **no link at all**
//	baseUrl ""                          no link
//
// The fourth row is the one to keep: a client whose only URL is a rootUrl gets
// nothing, so the link is decided by baseUrl alone and rootUrl only supplies a
// prefix. The admin console presents the two as one "Home URL", which is what
// makes the obvious implementation - concatenate whatever is there - wrong on
// that row.
//
// `${authBaseUrl}` and `${authAdminUrl}` are the two placeholders a default
// realm's clients carry, and both were measured expanding to the server's own
// base URL: security-admin-console's link is <base>/admin/master/console/ and
// account's is <base>/realms/master/account/.
func (h *handler) clientHomeURL(client *model.Client) string {
	if client.BaseURL == "" {
		return ""
	}
	// An absolute baseUrl wins outright. The test is a scheme separator rather
	// than a full parse: nothing in this project normalises a URL, and the two
	// shapes measured are "http://host/path" and "/path".
	if strings.Contains(client.BaseURL, "://") {
		return client.BaseURL
	}
	return h.rootURLBase(client.RootURL) + client.BaseURL
}

// rootURLBase resolves the prefix a relative baseUrl hangs off.
func (h *handler) rootURLBase(rootURL string) string {
	switch rootURL {
	case "", "${authBaseUrl}", "${authAdminUrl}":
		return h.issuerBase
	}
	return rootURL
}

// descUnparseableBody is the 500 both browser-facing endpoints answer a request
// body they cannot form-decode.
//
// Measured 2026-09-01 on POST /auth and POST /logout with
// `client_id=x&%zz=1`: **500**, `application/json`, the five security headers,
// and no Content-Language, Content-Security-Policy or Cache-Control - so it is
// not the page family at all, which is what Gloak answered until this cut. The
// two endpoints agree byte for byte.
const (
	errUnknown          = "unknown_error"
	descUnparseableBody = "For more on this error consult the server log."
)

// writeUnparseableBody writes that 500.
func writeUnparseableBody(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, errUnknown, descUnparseableBody)
}
