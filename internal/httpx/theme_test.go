package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/httpx"
)

// The three recorders. They exist so the assertions below read as statements
// about the page rather than about httptest.
func recordThemeError(c httpx.ThemeChrome, instruction string) string {
	w := httptest.NewRecorder()
	httpx.WriteThemeErrorPage(w, http.StatusBadRequest, "", c, instruction)
	return w.Body.String()
}

func recordThemeInfo(c httpx.ThemeChrome, title, instruction string) string {
	w := httptest.NewRecorder()
	httpx.WriteThemeInfoPage(w, http.StatusOK, "", c, title, instruction)
	return w.Body.String()
}

func recordThemeDevice(c httpx.ThemeChrome, action, message string) string {
	w := httptest.NewRecorder()
	httpx.WriteThemeDeviceCodePage(w, action, c, message)
	return w.Body.String()
}

// TestThemeResourceVersionIsTheMeasuredShape.
//
// Thirteen of Keycloak's have been measured and every one is five lowercase
// alphanumerics. internal/conformance's ReplaceThemeResource matches exactly
// that shape on **both** sides of a comparison, so a Gloak that minted anything
// else would leave its own segment raw in a served body and the seven theme
// goldens would go red - loudly, but for a reason nobody would find here. This
// is where it is found.
func TestThemeResourceVersionIsTheMeasuredShape(t *testing.T) {
	v := httpx.ThemeResourceVersion()
	if !regexp.MustCompile(`^[0-9a-z]{5}$`).MatchString(v) {
		t.Fatalf("version = %q, want five lowercase alphanumerics", v)
	}
}

// TestThemeResourceVersionIsStableWithinAProcess. Keycloak mints it with the
// database and it survives a restart; Gloak mints it once per process. Either
// way a client that fetched the CSS on one request has to get the same URL on
// the next, which a per-response mint would break.
func TestThemeResourceVersionIsStableWithinAProcess(t *testing.T) {
	if httpx.ThemeResourceVersion() != httpx.ThemeResourceVersion() {
		t.Fatal("the resource version moved between two calls")
	}
}

// TestThemeErrorPageCarriesTheChrome pins the two places the chrome shows up
// and the one place it does not.
//
// The link is deliberately absent when BackToApplication is empty rather than
// rendered pointing at nothing: measured, a client with no baseUrl gets no
// <a id="backToApplication"> at all, and an empty href would be a link a person
// can click.
//
// **The realm here is deliberately not "master".** Hard-coding the literal into
// the restart URL survived the whole suite on 2026-09-01, and this is where a
// mutation doing it fails. It is no longer the only place: four second-realm
// cases address a realm their fixture creates, and this one and
// oidc/authorization/second-realm-error-page both read the restart URL. The
// sentence here used to say "every conformance case in this repository runs
// against master", which had been false since P4 - sixty-six Admin API cases
// addressed a created realm when it was written - and is false twice over now.
func TestThemeErrorPageCarriesTheChrome(t *testing.T) {
	const realm = "gloak-probe-other"
	with := recordThemeError(httpx.ThemeChrome{
		Realm:             realm,
		RestartParams:     "client_id=probe&",
		BackToApplication: "http://abs.example/home",
	}, "Invalid parameter: redirect_uri")
	for _, want := range []string{
		`"/realms/` + realm + `/login-actions/restart?client_id=probe&skip_logout=true"`,
		`<p><a id="backToApplication" href="http://abs.example/home">`,
		`<p class="instruction">Invalid parameter: redirect_uri</p>`,
		`data-page-id="login-error"`,
	} {
		if !strings.Contains(with, want) {
			t.Errorf("page is missing %s", want)
		}
	}
	if strings.Contains(with, "/realms/master/") {
		t.Error("the page names master, which is not the realm it was given")
	}

	without := recordThemeError(httpx.ThemeChrome{Realm: realm}, "Client not found.")
	if !strings.Contains(without, `"/realms/`+realm+`/login-actions/restart?skip_logout=true"`) {
		t.Error("a page naming no client still has to have a restart URL")
	}
	if strings.Contains(without, "backToApplication") {
		t.Error("a page with no BackToApplication rendered a link anyway")
	}
}

// themeTitleAndBrand pulls the two lines a realm's display fields decide out of
// a rendered page, so the table below reads as the measurement it came from.
func themeTitleAndBrand(t *testing.T, c httpx.ThemeChrome) (title, brand string) {
	t.Helper()
	page := recordThemeError(c, "Client not found.")
	for _, line := range strings.Split(page, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "<title>Sign in to "); ok {
			title = strings.TrimSuffix(rest, "</title>")
		}
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), `class="pf-v5-c-brand">`); ok {
			brand = strings.TrimSuffix(rest, "</div>")
		}
	}
	if title == "" || brand == "" {
		t.Fatalf("the page has no title or no brand:\n%s", page)
	}
	return title, brand
}

// TestThemeChromeFollowsTheRealmsDisplayNames is the claim the second-realm
// conformance case cannot make, because a realm created through
// POST /admin/realms carries neither field and so cannot tell the two fallbacks
// apart.
//
// Measured 2026-09-02 on container kc-oidc2, one realm per row, each asked for
// the 400 page an unknown client_id produces:
//
//	displayName  displayNameHtml   <title>          brand
//	Keycloak     <div ...>         Keycloak         <div ...>       (master)
//	absent       absent            <the realm>      <the realm>
//	Probe Name   absent            Probe Name       **Probe Name**
//	absent       <div ...>         <the realm>      <div ...>
//	""           ""                <the realm>      <the realm>
//	"   "        "  "              "   "            "  "
//
// The third row is the one nothing in the catalogue can reach and the one the
// handover that found this got wrong: it read the fallback as "the realm name in
// both", from the single realm that carries neither. The brand falls back to
// **displayName** and only then to the realm name, so a realm with a plain
// display name names it twice.
//
// The fifth and sixth rows are the emptiness rule: an empty string counts as
// absent and a whitespace string does not.
func TestThemeChromeFollowsTheRealmsDisplayNames(t *testing.T) {
	const realm = "gloak-probe-other"
	const wrapper = `<div class="kc-logo-text"><span>Keycloak</span></div>`
	for _, tc := range []struct {
		name             string
		displayName      string
		displayNameHTML  string
		wantTitle, brand string
	}{
		{"master's pair", "Keycloak", wrapper, "Keycloak", wrapper},
		{"neither", "", "", realm, realm},
		{"display name alone", "Probe Name", "", "Probe Name", "Probe Name"},
		{"html alone", "", wrapper, realm, wrapper},
		{"both", "Probe Both", wrapper, "Probe Both", wrapper},
		{"two empty strings", "", "", realm, realm},
		{"whitespace is content", "   ", "  ", "   ", "  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			title, brand := themeTitleAndBrand(t, httpx.ThemeChrome{
				Realm:           realm,
				DisplayName:     tc.displayName,
				DisplayNameHTML: tc.displayNameHTML,
			})
			if title != tc.wantTitle {
				t.Errorf("title = %q, want %q", title, tc.wantTitle)
			}
			if brand != tc.brand {
				t.Errorf("brand = %q, want %q", brand, tc.brand)
			}
		})
	}
}

// TestThemeBrandWrapperBelongsToDisplayNameHtml.
//
// The <div class="kc-logo-text"><span> around master's brand is not chrome the
// template puts there: it is displayNameHtml's own markup, so it disappears with
// the value rather than wrapping the fallback. Measured on a realm whose
// displayNameHtml is the literal `plain no markup`, which renders exactly that
// and nothing around it.
//
// Rendering the wrapper around whatever is there is the obvious implementation -
// it is right on master, which is the realm every theme golden addresses - and
// it is wrong on every other realm on the server.
func TestThemeBrandWrapperBelongsToDisplayNameHtml(t *testing.T) {
	const wrapper = "kc-logo-text"
	if _, brand := themeTitleAndBrand(t, httpx.ThemeChrome{
		Realm: "gloak-probe-other", DisplayNameHTML: "plain no markup",
	}); brand != "plain no markup" {
		t.Errorf("brand = %q, want the displayNameHtml verbatim", brand)
	}
	for _, c := range []httpx.ThemeChrome{
		{Realm: "gloak-probe-other"},
		{Realm: "gloak-probe-other", DisplayName: "Probe Name"},
	} {
		if _, brand := themeTitleAndBrand(t, c); strings.Contains(brand, wrapper) {
			t.Errorf("brand = %q, which wraps a fallback in markup the value it "+
				"replaced was carrying", brand)
		}
	}
}

// TestThemeDisplayNamesAreEscapedByTwoDifferentRules.
//
// Measured 2026-09-02, one realm carrying every character an escaper might
// touch, read out of the title and out of the brand's fallback branch:
//
//	displayName  a&b<c>d"e'f`g/h
//	<title>      a&amp;b&lt;c&gt;d&quot;e&#39;f`g/h
//	brand        a&amp;bd&#34;e&#39;f&#96;g/h
//
// The double quote is spelled two ways on one page - `&quot;` in the title and
// `&#34;` in the brand - which is why escapeThemeTitle exists rather than
// html.EscapeString being used for both. Only the title's half is asserted
// here: the brand's is Keycloak's HTML sanitiser, Gloak does not reproduce it,
// and the divergence is recorded in ThemeChrome.brand rather than pretended
// away by a test written to what Gloak does.
//
// The raw half is asserted, because it is what carries master's wrapper: a
// displayNameHtml is written through untouched, so escaping it would turn every
// theme page's brand into visible angle brackets.
func TestThemeDisplayNamesAreEscapedByTwoDifferentRules(t *testing.T) {
	title, _ := themeTitleAndBrand(t, httpx.ThemeChrome{
		Realm: "gloak-probe-other", DisplayName: `a&b<c>d"e'f` + "`" + `g/h`,
	})
	const want = "a&amp;b&lt;c&gt;d&quot;e&#39;f`g/h"
	if title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
	if _, brand := themeTitleAndBrand(t, httpx.ThemeChrome{
		Realm: "gloak-probe-other", DisplayNameHTML: `<b class="x">R</b>`,
	}); brand != `<b class="x">R</b>` {
		t.Errorf("brand = %q, want the markup written through untouched", brand)
	}
}

// TestThemePagesCarryTheResourceVersionSevenTimes.
//
// Seven is counted from the measured pages, not incremented: every one of the
// eight carries it seven times except prompt-create, whose extra
// checkAuthSession import makes eight. A page that grew a ninth asset would
// move a golden, and this says so one step earlier.
func TestThemePagesCarryTheResourceVersionSevenTimes(t *testing.T) {
	segment := "/resources/" + httpx.ThemeResourceVersion() + "/"
	for name, body := range map[string]string{
		"error": recordThemeError(httpx.ThemeChrome{Realm: "master"}, "Client not found."),
		"info":  recordThemeInfo(httpx.ThemeChrome{Realm: "master"}, "Device Login Successful", "x"),
		"device verify": recordThemeDevice(httpx.ThemeChrome{Realm: "master"},
			"/realms/master/device", ""),
	} {
		if got := strings.Count(body, segment); got != 7 {
			t.Errorf("%s page carries the resource version %d times, want 7", name, got)
		}
	}
}
