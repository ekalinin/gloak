package httpx

import (
	"crypto/rand"
	"html"
	"strings"
)

// The keycloak.v2 login theme's markup.
//
// Every byte below was read off a live Keycloak 26.7.1 on 2026-09-01, container
// kc-theme on port 8152, and the whitespace is part of it: the Freemarker
// templates indent their output unevenly and the three page headings do not
// agree on how far. See docs/superpowers/plans/2026-09-01-p13-theme-markup.md.
//
// One head and three body templates cover the pages this project serves. The
// nine that keep the placeholder body in errors.go are measured now - the
// logout confirmation, "You are logged out", "Page has expired", the consent
// page and the five required-action pages - and what keeps them placeholders is
// a per-request value each of them carries rather than an unread instruction.
// themePageBody's doc comment has the table.

// themeResourceAlphabet is the character set every measured resource version is
// drawn from: lowercase letters and digits, no upper case.
const themeResourceAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// themeResourceLength is how long every measured one is.
const themeResourceLength = 5

// themeResourceVersion is the cache-busting segment this process serves inside
// every theme asset URL, minted once and never changed.
//
// **Keycloak mints it with the database, not with the process**, which is
// measured and is not what any document in this repository said before
// 2026-09-01: six `docker restart` of one container gave one value, wiping
// /opt/keycloak/data/h2 gave a new one each time, and `grep` finds it inside
// keycloakdb.mv.db. Gloak has no equivalent moment - its store is created by
// something else and outlives nothing - so it mints per process, which is the
// same observable: a value a client cannot predict and that is constant for as
// long as anything is being served.
//
// Thirteen of Keycloak's have been measured and all thirteen are five lowercase
// alphanumerics, which is why the alphabet and the length are what they are.
// internal/conformance's ReplaceThemeResource is what makes the two comparable.
var themeResourceVersion = mintThemeResourceVersion()

// ThemeResourceVersion is the segment this process serves. It is exported so a
// test can assert the shape of the thing it cannot predict the value of.
func ThemeResourceVersion() string { return themeResourceVersion }

// mintThemeResourceVersion draws themeResourceLength characters from
// themeResourceAlphabet.
//
// The modulo is deliberately not rejection-sampled. This value is a cache
// buster, not a secret: nothing is authorised by it, and a bias of six symbols
// in thirty-six changes nothing a client can act on. crypto/rand.Read cannot
// fail on Go 1.24 and later, so its error is not checked.
func mintThemeResourceVersion() string {
	raw := make([]byte, themeResourceLength)
	_, _ = rand.Read(raw)
	out := make([]byte, themeResourceLength)
	for i, b := range raw {
		out[i] = themeResourceAlphabet[int(b)%len(themeResourceAlphabet)]
	}
	return string(out)
}

// ThemeChrome is what the shared head and footer of a theme page vary in.
//
// Realm and RestartParams build the URL the page's session poller calls;
// BackToApplication is the error page's one optional element. All of them are
// strings the caller has already resolved, because internal/httpx owns
// formatting and knows nothing domain-specific.
//
// **A page names the realm three times and only one of them is that URL.** The
// other two are the <title> and the header brand, and they are the realm's
// displayName and displayNameHtml - see DisplayName below. Measured 2026-09-02
// by diffing the whole 400 page between two realms: three lines, and no more.
type ThemeChrome struct {
	// Realm names the realm in the restart URL's path.
	Realm string
	// DisplayName and DisplayNameHTML are the realm's two display fields **as
	// stored**, empty when the realm has neither - which is what a realm
	// created through POST /admin/realms has.
	//
	// The fallback between them lives here rather than in the caller because
	// it is the login template's rule rather than a domain one, and because
	// the zero value then renders what a created realm measurably gets.
	// Measured 2026-09-02 across a realm with both, one, the other, neither,
	// two empty strings and two whitespace strings:
	//
	//	title  =  displayName      or  realm name
	//	brand  =  displayNameHtml  or  displayName  or  realm name
	//
	// **The brand falls back to displayName and not to the realm name**, which
	// is one `if` more than the handover that found this recorded, and the one
	// a realm carrying neither cannot show. An empty string counts as absent
	// and a whitespace string does not: `""` renders the realm name and `"  "`
	// renders two spaces.
	//
	// The <div class="kc-logo-text"><span> wrapper master's brand carries is
	// displayNameHtml's own markup and not the template's: a realm whose
	// displayNameHtml is `plain no markup` renders exactly that, and every
	// realm reaching the brand through a fallback gets no wrapper at all.
	DisplayName     string
	DisplayNameHTML string
	// RestartParams are the parameters in front of skip_logout=true in that
	// URL, already escaped and joined with "&", with a trailing "&". It is
	// empty when the page's own rejection happened before a client was
	// resolved - measured on eight rejections, and a bearer-only client is one
	// of them, so "the request named a client" is not the test.
	RestartParams string
	// BackToApplication is the href of the "« Back to Application" link. It is
	// empty when there is no link, which is decided by the client's baseUrl
	// alone: measured over five clients, one carrying a rootUrl and no baseUrl
	// gets no link at all.
	BackToApplication string
	// AuthSessionHash is the value the head's checkAuthSession(...) block is
	// called with, and empty on a page that carries no such block.
	//
	// **It is the KC_AUTH_SESSION_HASH cookie's value, byte for byte**, measured
	// 2026-09-03 on the two responses that carry both - prompt=create's 400 page
	// and the login page - where the cookie and the argument agreed exactly,
	// quoting aside.
	//
	// Which pages carry the block was measured on one container rather than
	// inferred from what a page is for: it is on prompt=create's page, the login
	// page, "Page has expired", the consent page, all four required-action pages
	// and VERIFY_EMAIL's 500, and it is **not** on /auth's three 400 pages, the
	// /logout 400 page, the /login-actions 400 page or either device page. The
	// rule that fits all thirteen is the one this field spells: a page rendered
	// from inside an authentication flow has a session to poll and the rest do
	// not. Every page with the block carries **eight** /resources/ segments and
	// every page without it carries seven, which is what
	// internal/conformance's TestThemeResourceAppearsOnlyInTheThemePages counts.
	AuthSessionHash string
}

// title is what the page's <title> names the realm, before escaping.
func (c ThemeChrome) title() string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return c.Realm
}

// brand is the header's markup, ready to write.
//
// The two branches escape differently and that is measured rather than an
// oversight. displayNameHtml is emitted raw - it is markup, and it is what
// carries master's kc-logo-text wrapper. The fallback is a plain string and is
// escaped.
//
// **Keycloak sanitises the raw branch and Gloak does not**, which is a
// divergence rather than a simplification and is filed as one. Measured
// 2026-09-02: `<b onclick="x">Bold</b>` comes back `<b>Bold</b>`, a <script>
// element goes with its content, and a `javascript:` anchor is unwrapped to its
// text. Copying that means an HTML parser with a safelist; nothing this project
// serves needs one, because master's value passes through it unchanged and a
// created realm has none.
//
// html.EscapeString is byte-exact against that sanitiser on the fallback branch
// for any value carrying no markup and no backtick - measured, the sanitiser
// spells `&` `&amp;`, `"` `&#34;` and `'` `&#39;`, which is what Go spells them
// - so the fallback diverges only on a realm name or a displayName that carries
// markup.
func (c ThemeChrome) brand() string {
	if c.DisplayNameHTML != "" {
		return c.DisplayNameHTML
	}
	return html.EscapeString(c.title())
}

// escapeThemeTitle is Freemarker's HTML escaping, which the login templates
// apply to every value they interpolate outside the brand.
//
// Measured 2026-09-02 on one realm's displayName rendered into the <title>:
//
//	a&b<c>d"e'f`g/h  ->  a&amp;b&lt;c&gt;d&quot;e&#39;f`g/h
//
// It is html.EscapeString with one difference, and the difference is the whole
// reason this function exists: Go spells a double quote `&#34;` and Freemarker
// spells it `&quot;`. Backtick and slash are untouched by both.
//
// The rest of this file keeps html.EscapeString on purpose. Nothing else
// reaching it can carry a double quote - every instruction, page title and form
// action is a measured constant, and Keycloak refuses to store a client baseUrl
// containing one, answering `Base URL is not a valid URL`. A realm's
// displayName is the one value here an administrator sets to anything.
func escapeThemeTitle(s string) string { return themeTitleEscaper.Replace(s) }

var themeTitleEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#39;",
)

// themeAuthCheck is the block a page carries when it was rendered from inside an
// authentication flow, and nothing when it was not.
//
// It sits between the data-once-link script and the Firefox workaround, indented
// eight spaces where its two neighbours are indented four - which is Freemarker's
// nesting and not a tidy-up waiting to happen. Read off four different pages on
// one container on 2026-09-03 - prompt=create's 400, "Page has expired", the
// consent page and UPDATE_PROFILE - and byte-identical on all four apart from the
// argument. See ThemeChrome.AuthSessionHash for which pages have it.
//
// The eighth /resources/ segment of a page that carries one is this import.
func themeAuthCheck(hash string) string {
	if hash == "" {
		return ""
	}
	return `        <script type="module">
            import { checkAuthSession } from "/resources/` + themeResourceVersion + `/login/keycloak.v2/js/authChecker.js";

            checkAuthSession(
                "` + hash + `"
            );
        </script>
`
}

// themeHead is the <head> every measured page shares, plus the opening two
// lines. It ends with the blank line after </head>.
//
// The four substitutions are the resource version (seven times here, and an
// eighth inside themeAuthCheck when a page has an authentication session), the
// <title>'s display name, and the restart URL's realm and parameters.
//
// extra is markup one page appends inside the head, and it is emitted on the
// same line as </head> because that is where the one page carrying it puts it:
// "Page has expired" ends its head `…</SCRIPT></head>` with no newline between
// them. It is a parameter rather than a ThemeChrome field because it is decided
// by the request - whether the session code was still spendable - where every
// field on ThemeChrome is decided by the realm or the client.
func themeHead(c ThemeChrome, extra string) string {
	v := themeResourceVersion
	return `<!DOCTYPE html>
<html class="login-pf" lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="color-scheme" content="light dark">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Sign in to ` + escapeThemeTitle(c.title()) + `</title>
        <link rel="icon" href="/resources/` + v + `/login/keycloak.v2/img/favicon.ico" />
        <link href="/resources/` + v + `/common/keycloak/vendor/patternfly-v5/patternfly.min.css" rel="stylesheet" />
        <link href="/resources/` + v + `/common/keycloak/vendor/patternfly-v5/patternfly-addons.css" rel="stylesheet" />
        <link href="/resources/` + v + `/login/keycloak.v2/css/styles.css" rel="stylesheet" />
    <script type="importmap">
        {
            "imports": {
                "rfc4648": "/resources/` + v + `/common/keycloak/vendor/rfc4648/rfc4648.js"
            }
        }
    </script>
      <script type="module" async blocking="render">
          const DARK_MODE_CLASS = "pf-v5-theme-dark";
          const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");

          updateDarkMode(mediaQuery.matches);
          mediaQuery.addEventListener("change", (event) => updateDarkMode(event.matches));

          function updateDarkMode(isEnabled) {
            const { classList } = document.documentElement;

            if (isEnabled) {
              classList.add(DARK_MODE_CLASS);
            } else {
              classList.remove(DARK_MODE_CLASS);
            }
          }
      </script>
    <script type="module" src="/resources/` + v + `/login/keycloak.v2/js/passwordVisibility.js"></script>
    <script type="module">
        import { startSessionPolling } from "/resources/` + v + `/login/keycloak.v2/js/authChecker.js";

        startSessionPolling(
            "/realms/` + c.Realm + `/login-actions/restart?` + c.RestartParams + `skip_logout=true"
        );
    </script>
    <script type="module">
        document.addEventListener("click", (event) => {
            const link = event.target.closest("a[data-once-link]");

            if (!link) {
                return;
            }

            if (link.getAttribute("aria-disabled") === "true") {
                event.preventDefault();
                return;
            }

            const { disabledClass } = link.dataset;

            if (disabledClass) {
                link.classList.add(...disabledClass.trim().split(/\s+/));
            }

            link.setAttribute("role", "link");
            link.setAttribute("aria-disabled", "true");
        });
    </script>
` + themeAuthCheck(c.AuthSessionHash) + `    <script>
      // Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1404468
      const isFirefox = true;
    </script>
` + extra + `</head>

`
}

// themeFeedback is the alert block a page carries when the flow has something
// to tell the person. Measured on the device verification page answering an
// unusable user code, which is the one page in this cut that can produce one.
//
// The three runs of trailing whitespace inside the icon div are Freemarker
// directives that expanded to nothing, and they are bytes like any other.
func themeFeedback(message string) string {
	if message == "" {
		return ""
	}
	return `            <div class="pf-v5-c-alert pf-m-inline pf-v5-u-mb-md pf-m-danger">
                <div class="pf-v5-c-alert__icon">
                    ` + `
                    ` + `
                    <span class="fa fa-fw fa-exclamation-circle"></span>
                    ` + `
                </div>
                <span class="pf-v5-c-alert__title kc-feedback-text">` +
		html.EscapeString(message) + `</span>
            </div>
`
}

// themeShell wraps the three body templates in the markup they share.
//
// pageID is <body data-page-id>, heading is everything between the opening
// <h1> and the newline before </h1> - which is where the three templates
// disagree on indentation, so it is passed whole rather than built here -
// feedback is themeFeedback's block or nothing, main is the block inside
// pf-v5-c-login__main-body, and footer is the one line the device page puts
// inside the inner footer and the other two leave empty.
func themeShell(c ThemeChrome, headExtra, pageID, heading, feedback, main, footer string) string {
	return themeHead(c, headExtra) + `<body id="keycloak-bg" class="" data-page-id="` + pageID + `">
<div class="pf-v5-c-login">
  <div class="pf-v5-c-login__container">
    <header id="kc-header" class="pf-v5-c-login__header">
      <div id="kc-header-wrapper"
              class="pf-v5-c-brand">` + c.brand() + `</div>
    </header>
    <main class="pf-v5-c-login__main">
      <div class="pf-v5-c-login__main-header">
        <h1 class="pf-v5-c-title pf-m-3xl" id="kc-page-title">` + heading + `
</h1>
      </div>
      <div class="pf-v5-c-login__main-body">

` + feedback + `
` + main + `



          <div class="pf-v5-c-login__main-footer">
` + footer + `
          </div>
      </div>

        <div class="pf-v5-c-login__main-footer">
        </div>
    </main>
  </div>
</div>
</body>
</html>
`
}

// themeErrorPageBody is the login-error template: six measured instructions on
// /auth, three on /logout, three on /login-actions/authenticate and one on the
// required-action landing, all the same page with one sentence changed.
//
// The « is Keycloak's, not a typographic improvement.
func themeErrorPageBody(c ThemeChrome, instruction string) string {
	main := `        <div id="kc-error-message">
            <p class="instruction">` + html.EscapeString(instruction) + `</p>`
	if c.BackToApplication != "" {
		main += "\n" + `                    <p><a id="backToApplication" href="` +
			html.EscapeString(c.BackToApplication) + `">« Back to Application</a></p>`
	}
	main += "\n" + `        </div>`
	return themeShell(c, "", "login-error", "        "+html.EscapeString(ThemeErrorTitle), "", main, "")
}

// themeInfoPageBody is the login-info template, which the device status page is
// the only measured user of.
//
// Its heading is indented twelve spaces where the error page's is indented
// eight - one template, one indentation, and no rule joins them.
func themeInfoPageBody(c ThemeChrome, title, instruction string) string {
	main := `    <div id="kc-info-message">
        <p class="instruction">` + html.EscapeString(instruction) + `</p>
    </div>`
	return themeShell(c, "", "login-info", "            "+html.EscapeString(title), "", main, "")
}

// themeReplaceState is the block "Page has expired" carries when the request's
// session code was still spendable, and nothing when it was not.
//
// Measured 2026-09-03 as a five-cell grid on one container: a valid session_code
// with a wrong execution and a valid one with no execution both get it; the same
// request repeated, an absent code and a bogus one all get the page without it.
// So the rule is the code, not the execution.
//
// **The URL inside it is rebuilt rather than echoed** - a request sending
// execution=BOGUS gets the realm's real execution id back - and it is the same
// string the page's own loginContinueLink carries, which is why one caller
// supplies both. The separators are raw here and &amp; in the link, because this
// one is a JavaScript string literal and that one is an href.
//
// The uppercase tag, the two spaces after the brace and the "some title" are
// Keycloak's own.
//
// **Only the cell that carries it is served.** The page's other cell is reached
// through the required-action landing, whose continue link would have to name an
// execution nothing has measured, so that site keeps the placeholder rather than
// getting a guessed URL. See internal/oidc's consent.go.
func themeReplaceState(url string) string {
	return `<SCRIPT> if (typeof history.replaceState === 'function') {  ` +
		`history.replaceState({}, "some title", "` + url + `"); }</SCRIPT>`
}

// themeExpiredPageBody is the login-login-page-expired template, the fourth body
// this file serves and the first with two links in it.
//
// Measured 2026-09-03. Its heading is indented eight spaces, like the error
// page's and unlike the info page's, and its instruction is one <p id=
// "instruction1"> holding both links with a <br/> between them. The trailing
// " ." after each </a> is Keycloak's, space included.
//
// The two hrefs are not the same shape and neither is the head's:
//
//	the head's restart URL   relative,   …&client_data=…&skip_logout=true
//	loginRestartLink         relative,   …&client_data=…&skip_logout=false
//	loginContinueLink        absolute,   ?execution=…&client_id=…&tab_id=…&client_data=…
//
// One page, three URLs to the same two endpoints, disagreeing on the base, on
// skip_logout and on the parameter order. Building any of them from either of
// the others is the tidy-up that breaks it.
func themeExpiredPageBody(c ThemeChrome, restartURL, continueURL string) string {
	main := `        <p id="instruction1" class="instruction">
            To restart the login process <a id="loginRestartLink" href="` +
		html.EscapeString(restartURL) + `">Click here</a> .<br/>
            To continue the login process <a id="loginContinueLink" href="` +
		html.EscapeString(continueURL) + `">Click here</a> .
        </p>`
	return themeShell(c, themeReplaceState(continueURL), "login-login-page-expired",
		"        "+html.EscapeString(ExpiredPageTitle), "", main, "")
}

// deviceVerifyTemplateComment is the FTL comment keycloak.v2 emits three times
// on the device verification page - inside the <h1>, above the form and inside
// the inner footer. It is a comment and it is contract.
const deviceVerifyTemplateComment = `<!-- template: login-oauth2-device-verify-user-code.ftl -->`

// themeDeviceVerifyBody is the login-oauth2-device-verify-user-code template.
//
// **The form it renders cannot be submitted**, which is measured rather than a
// shortcut: its action is the device *authorization* endpoint, so a POST with no
// client_id answers 401 invalid_client. See WriteThemeDeviceCodePage.
//
// The action is the same string on both paths the page is served at. Measured
// 2026-09-01: GET /realms/master/device and
// GET /realms/master/protocol/openid-connect/auth/device produce byte-identical
// 4692-byte pages, both naming /realms/master/device. The doc comment on
// internal/oidc's serveDeviceCodePage said the action echoed the arrival path
// and that was never true.
//
// The trailing whitespace after `autofocus` is Keycloak's own and is two
// Freemarker directives that expanded to nothing.
func themeDeviceVerifyBody(c ThemeChrome, action, message string) string {
	main := deviceVerifyTemplateComment + `
        <form id="kc-user-verify-device-user-code-form" class="pf-v5-c-form pf-v5-u-w-100" action="` +
		html.EscapeString(action) + `" method="post">

<div class="pf-v5-c-form__group">
    <div class="pf-v5-c-form__group-label pf-v5-u-pb-xs">
        <label for="device_user_code" class="pf-v5-c-form__label">
        <span class="pf-v5-c-form__label-text">
            Enter the code provided by your device and click Submit
        </span>
        </label>
    </div>

    <span class="pf-v5-c-form-control ">
        <input id="device_user_code" name="device_user_code" value="" type="text" autocomplete="off" autofocus
                ` + `
                ` + `aria-invalid=""/>
    </span>

    <div id="input-error-container-device_user_code">
    </div>
</div>


  <div class="pf-v5-c-form__group">
    <div class="pf-v5-c-form__actions pf-v5-u-pt-xs pf-v5-u-flex-wrap">
  <button class="pf-v5-c-button pf-m-primary pf-m-block" name="" id="kc-login"
          type="submit" >
  Submit
  </button>
    </div>
  </div>
        </form>`
	heading := deviceVerifyTemplateComment + "\n        " + DevicePageTitle
	// The footer's comment is followed by a blank line, which is the newline
	// here plus the one the shell writes. The pages with an empty footer get
	// that blank line and nothing else, so the two shapes are one template.
	return themeShell(c, "", "login-login-oauth2-device-verify-user-code", heading,
		themeFeedback(message), main, deviceVerifyTemplateComment+"\n")
}

// ThemeRestartParams joins the parameters the restart URL carries, adding the
// trailing "&" the head expects. With none it returns the empty string, which
// is what a page whose rejection resolved no client serves.
func ThemeRestartParams(params ...string) string {
	if len(params) == 0 {
		return ""
	}
	return strings.Join(params, "&") + "&"
}
