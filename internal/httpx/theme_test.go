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
// **The realm here is deliberately not "master".** Every conformance case in
// this repository runs against master, so hard-coding the literal into the
// restart URL passes all seven theme goldens - a mutation doing exactly that
// survived the whole suite on 2026-09-01 and is caught here and nowhere else.
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
