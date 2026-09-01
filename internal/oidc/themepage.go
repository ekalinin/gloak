package oidc

import (
	"net/http"
	"net/url"
	"strings"

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

// themeChrome is the chrome of a page whose rejection resolved no client.
func (h *handler) themeChrome(realm *model.Realm) httpx.ThemeChrome {
	return httpx.ThemeChrome{Realm: realm.Name}
}

// themeChromeFor is the chrome of a page that did resolve one, with any extra
// restart parameters the page carries in front of skip_logout.
//
// extra exists for prompt=create alone, whose page is rendered from inside the
// authentication flow and whose restart URL therefore carries a tab_id and a
// client_data as well.
func (h *handler) themeChromeFor(realm *model.Realm, client *model.Client, extra ...string) httpx.ThemeChrome {
	params := append([]string{"client_id=" + url.QueryEscape(client.ClientID)}, extra...)
	return httpx.ThemeChrome{
		Realm:             realm.Name,
		RestartParams:     httpx.ThemeRestartParams(params...),
		BackToApplication: h.clientHomeURL(client),
	}
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
