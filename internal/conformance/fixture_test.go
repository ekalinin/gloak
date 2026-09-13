package conformance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// The cookie tests are the newest thing in this file; the CaptureHeader block
// under them is P2's, and the rest is P1's body-capture coverage.

// twoStepFixture is two requests against one recording handler, which is the
// smallest shape that can show a value crossing from one step to the next.
func twoStepFixture() Fixture {
	return Fixture{State: "bootstrap", Steps: []Step{
		{Request: Request{Method: http.MethodGet, Path: "/first"}},
		{Request: Request{Method: http.MethodGet, Path: "/second"}},
	}}
}

// recordingDo answers every request from h and keeps the requests it saw.
func recordingDo(h http.HandlerFunc) (Do, *[]*http.Request) {
	var seen []*http.Request
	do := func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r)
		w := httptest.NewRecorder()
		h(w, r)
		return w.Result(), nil
	}
	return do, &seen
}

func TestRunFixtureCarriesACookieToTheNextStep(t *testing.T) {
	// A login is a session. Without this every step is an independent request
	// and the credential POST arrives with no authentication session at all.
	do, seen := recordingDo(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			w.Header().Add("Set-Cookie", "AUTH_SESSION_ID=abc;Version=1;Path=/realms/master/;Secure;HttpOnly")
		}
		w.WriteHeader(200)
	})

	if _, err := RunFixture(twoStepFixture(), "http://localhost:8080", do); err != nil {
		t.Fatalf("RunFixture: %v", err)
	}

	if len(*seen) != 2 {
		t.Fatalf("want 2 requests, got %d", len(*seen))
	}
	if got := (*seen)[0].Header.Get("Cookie"); got != "" {
		t.Fatalf("the first step sent a cookie it could not have had: %q", got)
	}
	// The value only, with every attribute dropped: Version, Path, Secure and
	// HttpOnly are instructions to a browser, not part of what one sends back.
	if got := (*seen)[1].Header.Get("Cookie"); got != "AUTH_SESSION_ID=abc" {
		t.Fatalf("want AUTH_SESSION_ID=abc, got %q", got)
	}
}

func TestRunFixtureSendsEveryCookieInNameOrder(t *testing.T) {
	// A recording that reordered its Cookie header between runs would make any
	// golden downstream of a login churn for no reason.
	do, seen := recordingDo(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			w.Header().Add("Set-Cookie", "KC_RESTART=jwe;Path=/realms/master/")
			w.Header().Add("Set-Cookie", "AUTH_SESSION_ID=abc;Path=/realms/master/")
		}
		w.WriteHeader(200)
	})

	if _, err := RunFixture(twoStepFixture(), "http://localhost:8080", do); err != nil {
		t.Fatalf("RunFixture: %v", err)
	}

	want := "AUTH_SESSION_ID=abc; KC_RESTART=jwe"
	if got := (*seen)[1].Header.Get("Cookie"); got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestRunFixtureKeepsTheQuotesKeycloakSends(t *testing.T) {
	// KC_AUTH_SESSION_HASH's value arrives wrapped in double quotes.
	// http.Request.AddCookie sanitises them away, so the cookie sent back would
	// not be the cookie received; send writes the header itself for this.
	do, seen := recordingDo(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			w.Header().Add("Set-Cookie", `KC_AUTH_SESSION_HASH="wc8IgcQt+LWFo/sO6";Version=1;Max-Age=60`)
		}
		w.WriteHeader(200)
	})

	if _, err := RunFixture(twoStepFixture(), "http://localhost:8080", do); err != nil {
		t.Fatalf("RunFixture: %v", err)
	}

	want := `KC_AUTH_SESSION_HASH="wc8IgcQt+LWFo/sO6"`
	if got := (*seen)[1].Header.Get("Cookie"); got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestRunFixtureResendsAClearedCookie(t *testing.T) {
	// The measured login clears KC_RESTART with Max-Age=0 and an empty value.
	// This jar has no expiry semantics on purpose, so the cookie stays as an
	// empty value - which is what a browser that has not yet expired it sends.
	f := Fixture{State: "bootstrap", Steps: []Step{
		{Request: Request{Method: http.MethodGet, Path: "/first"}},
		{Request: Request{Method: http.MethodGet, Path: "/second"}},
		{Request: Request{Method: http.MethodGet, Path: "/third"}},
	}}
	do, seen := recordingDo(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			w.Header().Add("Set-Cookie", "KC_RESTART=jwe;Path=/realms/master/")
		case "/second":
			w.Header().Add("Set-Cookie", "KC_RESTART=;Version=1;Path=/realms/master/;Max-Age=0")
		}
		w.WriteHeader(200)
	})

	if _, err := RunFixture(f, "http://localhost:8080", do); err != nil {
		t.Fatalf("RunFixture: %v", err)
	}

	if got := (*seen)[1].Header.Get("Cookie"); got != "KC_RESTART=jwe" {
		t.Fatalf("step 2 want KC_RESTART=jwe, got %q", got)
	}
	if got := (*seen)[2].Header.Get("Cookie"); got != "KC_RESTART=" {
		t.Fatalf("step 3 want the cleared value, got %q", got)
	}
}

// loginPage is the shape of the measured 26.7.1 login form, cut down to the
// markup that matters: one form whose action carries five query parameters,
// HTML-escaped, and the three inputs the page actually has. Recorded
// 2026-08-29; see the "The login page, and the five parameters its form
// carries" section of the observed spec.
const loginPage = `<!DOCTYPE html><html><body>
<form id="kc-form-login" class="pf-v5-c-form" action="http://localhost:8080/realms/master/login-actions/authenticate?session_code=EoGc7S7XZ432-zJ7UJniMdTLmhQQCSvhHgEj8IL0h58&amp;execution=7b471cd2-b236-4c9f-9e06-dd40365b16eb&amp;client_id=gloak-probe-browser&amp;tab_id=PKFZNyff0dc&amp;client_data=eyJydSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9jYWxsYmFjayJ9" method="post" novalidate="novalidate">
  <input id="username" name="username" value="" type="text" autocomplete="username" autofocus aria-invalid=""/>
  <input id="password" name="password" value="" type="password" autocomplete="current-password" aria-invalid=""/>
  <input type="hidden" id="id-hidden-input" name="credentialId" />
</form>
</body></html>`

func TestCaptureFromFormTakesTheActionRelativeToBase(t *testing.T) {
	// Absolute, it would send the next step at the recorder's container when
	// the verifier runs it. The five query parameters have to survive whole:
	// every one is minted per request and the POST is refused without them.
	got, err := captureFromForm([]byte(loginPage), "action", "http://localhost:8080")

	if err != nil {
		t.Fatalf("captureFromForm: %v", err)
	}
	want := "/realms/master/login-actions/authenticate" +
		"?session_code=EoGc7S7XZ432-zJ7UJniMdTLmhQQCSvhHgEj8IL0h58" +
		"&execution=7b471cd2-b236-4c9f-9e06-dd40365b16eb" +
		"&client_id=gloak-probe-browser" +
		"&tab_id=PKFZNyff0dc" +
		"&client_data=eyJydSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9jYWxsYmFjayJ9"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestCaptureFromFormUnescapesTheAction(t *testing.T) {
	// The attribute arrives with &amp; between its parameters. Left escaped,
	// the whole query would be one parameter named session_code.
	got, err := captureFromForm([]byte(loginPage), "action", "http://localhost:8080")

	if err != nil {
		t.Fatalf("captureFromForm: %v", err)
	}
	if strings.Contains(got, "&amp;") {
		t.Fatalf("the action is still HTML-escaped: %q", got)
	}
}

func TestCaptureFromFormReadsAnInput(t *testing.T) {
	page := `<form action="/go"><input name="csrf" value="tok-1"/></form>`

	got, err := captureFromForm([]byte(page), "input:csrf", "")

	if err != nil {
		t.Fatalf("captureFromForm: %v", err)
	}
	if got != "tok-1" {
		t.Fatalf("want tok-1, got %q", got)
	}
}

func TestCaptureFromFormTakesTheFirstOfTwoSiblings(t *testing.T) {
	// The login page carries other forms in some themes, and the credential
	// form is the one served first. Taking the last would post the wrong one.
	//
	// This case is guarded by the early return on </form>, not by the nested
	// check the next test covers. Both are needed and neither implies the
	// other: mutating away the nested guard leaves this test passing.
	page := `<form action="/first"></form><form action="/second"></form>`

	got, err := captureFromForm([]byte(page), "action", "")

	if err != nil {
		t.Fatalf("captureFromForm: %v", err)
	}
	if got != "/first" {
		t.Fatalf("want /first, got %q", got)
	}
}

func TestCaptureFromFormIgnoresAFormNestedInTheFirst(t *testing.T) {
	// A nested form never reaches the early return, so without the guard the
	// inner action overwrites the outer one and the credentials go to the
	// wrong URL. Nested forms are invalid HTML and a tokenizer reports them
	// anyway, which is the whole risk of tokenising rather than parsing.
	page := `<form action="/outer"><form action="/inner"></form></form>`

	got, err := captureFromForm([]byte(page), "action", "")

	if err != nil {
		t.Fatalf("captureFromForm: %v", err)
	}
	if got != "/outer" {
		t.Fatalf("want /outer, got %q", got)
	}
}

func TestCaptureFromFormFailsWhenThereIsNoForm(t *testing.T) {
	// A rejected authorization request answers a 302 with no body at all. An
	// empty action would send the next step at the base URL and record
	// whatever that answers as the contract.
	if _, err := captureFromForm([]byte(""), "action", ""); err == nil {
		t.Fatal("a body with no form reported success")
	}
}

func TestCaptureFromFormFailsOnAnAbsentInput(t *testing.T) {
	page := `<form action="/go"><input name="csrf" value="tok-1"/></form>`

	if _, err := captureFromForm([]byte(page), "input:nosuchfield", ""); err == nil {
		t.Fatal("capturing an input the form does not have reported success")
	}
}

func TestCaptureFromQueryReadsTheCodeOutOfALocation(t *testing.T) {
	// captureFromHeader yields a URL's last path segment, so on this Location
	// it would return "callback".
	h := http.Header{"Location": {"http://localhost:9999/callback?state=xyz123" +
		"&session_state=YXHeH_ZlGX3waefvdJu7mjD3" +
		"&iss=http%3A%2F%2Flocalhost%3A8080%2Frealms%2Fmaster" +
		"&code=9a543c31-84f1-5b93-dc94-0f03f2486340.YXHeH_ZlGX3waefvdJu7mjD3.f15a3b32-d263-4590-a18a-e1578f3144b3"}}

	got, err := captureFromQuery(h, "code")

	if err != nil {
		t.Fatalf("captureFromQuery: %v", err)
	}
	want := "9a543c31-84f1-5b93-dc94-0f03f2486340.YXHeH_ZlGX3waefvdJu7mjD3.f15a3b32-d263-4590-a18a-e1578f3144b3"
	if got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestCaptureFromQueryFailsOnAnAbsentParameter(t *testing.T) {
	// An empty code would be exchanged at the token endpoint and the refusal
	// recorded as the authorization code grant's contract.
	h := http.Header{"Location": {"http://localhost:9999/callback?error=login_required"}}

	if _, err := captureFromQuery(h, "code"); err == nil {
		t.Fatal("capturing an absent query parameter reported success")
	}
}

func TestCaptureFromQueryFailsOnAnAbsentLocation(t *testing.T) {
	if _, err := captureFromQuery(http.Header{}, "code"); err == nil {
		t.Fatal("capturing from a response with no Location reported success")
	}
}

// The CaptureHeader tests below are P2's.

func TestRunFixtureCapturesFromAHeader(t *testing.T) {
	// The admin API answers a create with 201, an empty body and the new
	// object's URL in Location. Reading a value out of the body cannot work
	// when there is no body.
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:       Request{Method: http.MethodPost, Path: "/things"},
		CaptureHeader: map[string]string{"thing_id": "Location"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Header:     http.Header{"Location": {"http://localhost:8080/things/abc-123"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	vars, err := RunFixture(f, "http://localhost:8080", do)

	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	// The last path segment, not the whole URL: a case substitutes it into a
	// path, and the base URL differs between the recorder and the verifier.
	if vars["thing_id"] != "abc-123" {
		t.Fatalf("want abc-123, got %q", vars["thing_id"])
	}
}

func TestRunFixtureKeepsANonURLHeaderWhole(t *testing.T) {
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:       Request{Method: http.MethodPost, Path: "/things"},
		CaptureHeader: map[string]string{"etag": "ETag"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Header:     http.Header{"Etag": {"W/\"v1\""}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	vars, err := RunFixture(f, "http://localhost:8080", do)

	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	if vars["etag"] != "W/\"v1\"" {
		t.Fatalf("a header that is not a URL was truncated: %q", vars["etag"])
	}
}

func TestRunFixtureFailsOnAMissingHeader(t *testing.T) {
	// A capture that silently yielded "" would substitute an empty path
	// segment and record a 404 as though it were the contract.
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:       Request{Method: http.MethodPost, Path: "/things"},
		CaptureHeader: map[string]string{"thing_id": "Location"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	_, err := RunFixture(f, "http://localhost:8080", do)

	if err == nil {
		t.Fatal("a fixture capturing an absent header reported success")
	}
}

func TestHeaderCapturesAreMaskedOutOfARecording(t *testing.T) {
	// A captured UUID left verbatim in a golden makes the file churn on every
	// recording - the same rule body captures already follow.
	vars := map[string]string{"thing_id": "abc-123"}

	got := ReplaceCaptured([]byte(`{"id":"abc-123"}`), vars)

	if string(got) != `{"id":"{{thing_id}}"}` {
		t.Fatalf("captured header value not masked: %s", got)
	}
}

func TestCaptureFromIndexesAnArray(t *testing.T) {
	// A filtered list is how a fixture finds a bootstrapped object whose UUID
	// differs between the reference container and Gloak.
	body := []byte(`[{"id":"abc-123","clientId":"account"}]`)

	got, err := captureFrom(body, "0/id")

	if err != nil {
		t.Fatalf("captureFrom: %v", err)
	}
	if got != "abc-123" {
		t.Fatalf("want abc-123, got %q", got)
	}
}

func TestCaptureFromRejectsAnEmptyArray(t *testing.T) {
	// An empty result means the filter matched nothing. Yielding "" would
	// substitute an empty path segment and record a 404 as the contract.
	if _, err := captureFrom([]byte(`[]`), "0/id"); err == nil {
		t.Fatal("indexing an empty array reported success")
	}
}

func TestExpandSubstitutesCapturedValues(t *testing.T) {
	in := Request{
		Method:  http.MethodGet,
		Path:    "/realms/master/protocol/openid-connect/userinfo",
		Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		Form:    map[string]string{"token": "{{refresh_token}}", "kept": "literal"},
		Query:   map[string]string{"q": "{{access_token}}"},
	}
	got := Expand(in, map[string]string{"access_token": "AT", "refresh_token": "RT"})

	if got.Headers["Authorization"] != "Bearer AT" {
		t.Errorf("header: got %q", got.Headers["Authorization"])
	}
	if got.Form["token"] != "RT" {
		t.Errorf("form: got %q", got.Form["token"])
	}
	if got.Form["kept"] != "literal" {
		t.Errorf("literal form value was rewritten: got %q", got.Form["kept"])
	}
	if got.Query["q"] != "AT" {
		t.Errorf("query: got %q", got.Query["q"])
	}
	// Expand must not write through to the caller's maps: one Case is
	// expanded twice, once by the recorder and once by the verifier, with
	// different values each time.
	if in.Headers["Authorization"] != "Bearer {{access_token}}" {
		t.Errorf("Expand mutated its input: %q", in.Headers["Authorization"])
	}
}

// An unknown reference is left verbatim rather than becoming an empty string,
// so a typo shows up in the recorded request instead of quietly changing what
// was measured.
func TestExpandSubstitutesThePath(t *testing.T) {
	// The admin API addresses objects by a server-minted UUID in the path, so
	// a case can never spell one literally. Leaving the path out recorded a
	// 404 as the contract for the first case that needed it.
	in := Request{
		Method: http.MethodGet,
		Path:   "/admin/realms/master/clients/{{client_uuid}}",
		Body:   []byte(`{"id":"{{client_uuid}}"}`),
	}

	got := Expand(in, map[string]string{"client_uuid": "abc-123"})

	if got.Path != "/admin/realms/master/clients/abc-123" {
		t.Errorf("path: got %q", got.Path)
	}
	if string(got.Body) != `{"id":"abc-123"}` {
		t.Errorf("body: got %s", got.Body)
	}
	if in.Path != "/admin/realms/master/clients/{{client_uuid}}" {
		t.Errorf("Expand mutated its input path: %q", in.Path)
	}
	if string(in.Body) != `{"id":"{{client_uuid}}"}` {
		t.Errorf("Expand mutated its input body: %s", in.Body)
	}
}

func TestExpandLeavesUnknownPlaceholdersAlone(t *testing.T) {
	got := Expand(Request{Headers: map[string]string{"A": "{{nope}}"}}, map[string]string{"x": "1"})
	if got.Headers["A"] != "{{nope}}" {
		t.Errorf("got %q", got.Headers["A"])
	}
}

func TestRunFixtureCapturesFromAStepResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "password" {
			t.Errorf("grant_type: got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"AT","refresh_token":"RT"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form:   map[string]string{"grant_type": "password"},
		},
		Capture: map[string]string{"access_token": "access_token", "refresh_token": "refresh_token"},
	}}}

	vars, err := RunFixture(f, srv.URL, srv.Client().Do)
	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	if vars["access_token"] != "AT" || vars["refresh_token"] != "RT" {
		t.Errorf("captured %v", vars)
	}
}

// A step that does not produce the value a later request needs must fail
// loudly. Silently substituting an empty string would record a golden of
// whatever Keycloak answers for an empty token, which is a real response to a
// request nobody meant to make.
func TestRunFixtureFailsWhenACaptureIsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{Method: http.MethodPost, Path: "/token"},
		Capture: map[string]string{"access_token": "access_token"},
	}}}

	if _, err := RunFixture(f, srv.URL, srv.Client().Do); err == nil {
		t.Fatal("want an error when the step's response has no such field, got nil")
	}
}

// A step that is refused must fail the fixture, even though it captures
// nothing and nothing later reads from it.
//
// This is F34's mechanism. Without it a refused setup request was silent: the
// fixture ran to completion, the case's own request met a server in a state the
// fixture only claimed to have built, and the recorder wrote that response as
// the contract. It fired for real on feat/p2-role-mappings - nineteen goldens,
// every subtest passing, every one describing a subject holding no roles.
func TestRunFixtureFailsOnARefusedStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"HTTP 403 Forbidden"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request: Request{Method: http.MethodPost, Path: "/admin/realms/master/users/u/role-mappings/realm"},
	}}}

	_, err := RunFixture(f, srv.URL, srv.Client().Do)
	if err == nil {
		t.Fatal("want an error for a step answering 403, got nil")
	}
	// The symptom shows up one request later at the earliest, so the message
	// has to name the step, the method, the path and the body.
	for _, want := range []string{"step 0", http.MethodPost, "/role-mappings/realm", "2xx", "403", "HTTP 403 Forbidden"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message lacks %q: %v", want, err)
		}
	}
}

// The override the idempotent creates need: the recorder shares one container,
// so a fixture more than one case names answers 409 on every run after the
// first, and that is the state the case wants.
func TestRunFixtureAcceptsAnExpectedNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"errorMessage":"Client gloak-probe already exists"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:      Request{Method: http.MethodPost, Path: "/admin/realms/master/clients"},
		ExpectStatus: idempotentCreate,
	}}}

	if _, err := RunFixture(f, srv.URL, srv.Client().Do); err != nil {
		t.Fatalf("a create naming 409 must pass: %v", err)
	}
}

// A later step sees what an earlier one captured, which is what makes a
// fixture a chain rather than a list.
func TestRunFixtureThreadsValuesBetweenSteps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/second" {
			if got := r.Header.Get("Authorization"); got != "Bearer AT" {
				t.Errorf("second step did not see the first step's capture: %q", got)
			}
			_, _ = io.WriteString(w, `{"sid":"S"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"AT"}`)
	}))
	defer srv.Close()

	f := Fixture{State: "bootstrap", Steps: []Step{
		{
			Request: Request{Method: http.MethodPost, Path: "/first"},
			Capture: map[string]string{"access_token": "access_token"},
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/second",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"sid": "sid"},
		},
	}}

	vars, err := RunFixture(f, srv.URL, srv.Client().Do)
	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	if vars["sid"] != "S" {
		t.Errorf("captured %v", vars)
	}
}

func TestReplaceCapturedMasksValuesThatLeakIntoABody(t *testing.T) {
	vars := map[string]string{"access_token": "AT-abc", "refresh_token": ""}
	got := ReplaceCaptured([]byte(`{"token":"AT-abc","active":true}`), vars)
	want := `{"token":"{{access_token}}","active":true}`
	if string(got) != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

// An empty captured value must never be substituted: strings.ReplaceAll with
// an empty old string inserts the placeholder between every byte.
func TestReplaceCapturedIgnoresEmptyValues(t *testing.T) {
	got := ReplaceCaptured([]byte(`{"a":1}`), map[string]string{"empty": ""})
	if string(got) != `{"a":1}` {
		t.Errorf("empty value was substituted: %s", got)
	}
}

func TestFixturesAreWellFormed(t *testing.T) {
	for name, f := range Fixtures {
		if f.State != "bootstrap" {
			t.Errorf("fixture %q: unknown state %q", name, f.State)
		}
		for i, s := range f.Steps {
			if s.Request.Method == "" || s.Request.Path == "" {
				t.Errorf("fixture %q step %d: needs a method and a path", name, i)
			}
			// A step earns its place by capturing something or by changing
			// server state. Either form of capture counts: a step may take
			// its value from the body or, as the admin API's create does,
			// from a response header - the 201 there has no body at all.
			//
			// A step that captures nothing must at least be a write.
			// confidentialClientFixture has one: it creates a client and then
			// looks the UUID up in a separate GET, so that a re-run's 409 is
			// harmless. A GET capturing nothing really is dead weight.
			//
			// All four capture kinds count. The browser fixtures' GET /auth
			// takes its value from the login page's HTML, and this test named
			// only two kinds until they existed - which reported every one of
			// them as dead weight.
			//
			// The rule rests on "a GET does not change server state", and one
			// measured endpoint falsifies it: GET /logout with a valid
			// id_token_hint ends the session. Such a step says Mutates, which
			// is a declaration rather than a path list - see Step.Mutates.
			capturesNothing := len(s.Capture) == 0 && len(s.CaptureHeader) == 0 &&
				len(s.CaptureForm) == 0 && len(s.CaptureQuery) == 0
			if capturesNothing && !s.Mutates && s.Request.Method == http.MethodGet {
				t.Errorf("fixture %q step %d: a GET that captures nothing is dead weight", name, i)
			}
			if s.Mutates && !capturesNothing {
				t.Errorf("fixture %q step %d: Mutates is for a step that captures nothing", name, i)
			}
			if s.Mutates && s.Request.Method != http.MethodGet {
				t.Errorf("fixture %q step %d: Mutates only excuses a GET; a %s is a write already",
					name, i, s.Request.Method)
			}
		}
	}
	if _, ok := Fixtures["bootstrap"]; !ok {
		t.Error(`Fixtures must contain "bootstrap"`)
	}
}

// TestNoTwoFixturesMintOneIdentityProviderID is the ratchet F230 earned.
//
// **An identity provider's internalId is its primary key and it is global**, so
// two fixtures naming one id are fine apart and collide on the shared container
// the recorder uses. The collision is silent in the worst possible way: the
// second create answers
// `409 {"errorMessage":"Identity Provider <new alias> already exists"}` -
// naming the alias that does **not** exist - `idempotentCreate` accepts the 409,
// and the case that addresses that alias gets a 404 from a fixture that reported
// success. Measured on a cold container 2026-09-13.
//
// Three values in this tree were duplicated when this test was written and none
// of them reached a case: `…0002`, where idp-minimal and idp-taken mint one id
// **for one alias** and the 409 therefore leaves exactly the resource the case
// wants, and `…0020` and `…0021`, where identityProviderStrandedFixture and the
// two mapper-types fixtures disagree about the alias and are held apart only by
// PristineRealm on the case naming the first - a flag set because that case
// enumerates the realm, for a reason with nothing to do with ids. Clearing it,
// or adding one non-pristine case naming idp-stranded, turns two 200 goldens
// into 404s with no fixture reporting a failure. That is too load-bearing for a
// flag nobody set for the purpose, so the invariant is asserted here instead:
// **one internalId may be minted twice only for one alias.**
func TestNoTwoFixturesMintOneIdentityProviderID(t *testing.T) {
	// minters maps an internalId to the "fixture:alias" of every create that
	// names it. The alias is in the key because sharing an id **and** an alias
	// is the one harmless case, and reporting it would train people to ignore
	// this test.
	minters := map[string]map[string][]string{}
	for name, f := range Fixtures {
		for _, s := range f.Steps {
			if s.Request.Method != http.MethodPost ||
				!strings.HasSuffix(s.Request.Path, "/identity-provider/instances") {
				continue
			}
			id := jsonStringField(s.Request.Body, "internalId")
			if id == "" {
				// A create with no internalId gets a server-minted UUID, which
				// cannot collide with this tree's literals. Nothing to check.
				continue
			}
			alias := jsonStringField(s.Request.Body, "alias")
			if minters[id] == nil {
				minters[id] = map[string][]string{}
			}
			minters[id][alias] = append(minters[id][alias], name)
		}
	}
	// A sweep that matched nothing passes, and a passing sweep that matched
	// nothing is indistinguishable from a correct one. The tree held 23 creates
	// carrying a literal internalId when this was written; the floor is what
	// fails if the path suffix, the method or jsonStringField stops matching.
	if len(minters) < 20 {
		t.Fatalf("the sweep found %d identity provider ids, want at least 20: "+
			"it is matching nothing and would pass whatever the fixtures hold", len(minters))
	}
	for id, byAlias := range minters {
		if len(byAlias) < 2 {
			continue
		}
		var where []string
		for alias, fixtures := range byAlias {
			for _, f := range fixtures {
				where = append(where, f+" as "+alias)
			}
		}
		sort.Strings(where)
		t.Errorf("internalId %s is minted for %d different aliases: %s\n"+
			"\tthe second create on a shared container is a 409 idempotentCreate "+
			"swallows, and the case addressing the losing alias gets a 404",
			id, len(byAlias), strings.Join(where, ", "))
	}
}

// identityProvidersFetchingOnConstruction is the measured set of provider ids
// whose factory performs an **outbound HTTP request** while Keycloak constructs
// the provider.
//
// `linkedin-openid-connect` is the one in it:
// `LinkedInOIDCIdentityProviderFactory.create` fetches
// `https://www.linkedin.com/oauth/.well-known/openid-configuration` from the
// public internet. Measured 2026-09-13 off the container's own stack trace.
//
// `openshift-v4` is deliberately **not** in it. It fetches too, but from the
// `baseUrl` in its own config, and a create that does not carry one fails in
// Apache's route planner - `Target host is not specified` - before a socket is
// opened. A bare `openshift-v4` instance therefore answers the same 500 on any
// host, including one with no network at all.
var identityProvidersFetchingOnConstruction = []string{"linkedin-openid-connect"}

// TestNoMapperTypesCaseAsksAProviderThatFetchesOnConstruction is the other
// ratchet F230 earned, and it exists because a mutation survived.
//
// `GET .../mapper-types` **instantiates the provider** -
// `IdentityProviderResource.getMapperTypes` calls
// `createIdentityProviderInstance` - so a provider in the set above answers this
// route with whatever the recording host's egress is: a 500 where the fetch
// fails, which is three measured draws on a cold container and one on a second,
// and a 200 with six mapper types where it succeeds, which is what ten draws on
// a better-connected host saw. That is the whole of F230: one golden that four
// `make record` runs and two cuts' worth of direct draws could not agree on,
// because the value was a property of the network rather than of Keycloak.
//
// Nothing else in the tree can catch a relapse. Pointing the fixture back at
// `linkedin-openid-connect` leaves every test green, because Gloak answers the
// 500 for both ids whatever the config says, so the verifier compares equal and
// only a `make record` on a host that can reach LinkedIn would show it - by
// which time the golden has moved and somebody is reading the diff wondering
// which of the two is wrong. For the third time.
func TestNoMapperTypesCaseAsksAProviderThatFetchesOnConstruction(t *testing.T) {
	checked := 0
	for _, c := range Catalog {
		if !strings.HasSuffix(c.Request.Path, "/mapper-types") {
			continue
		}
		f, ok := Fixtures[c.Fixture]
		if !ok {
			// TestCatalogFixturesExist is what reports this.
			continue
		}
		for _, s := range f.Steps {
			if s.Request.Method != http.MethodPost ||
				!strings.HasSuffix(s.Request.Path, "/identity-provider/instances") {
				continue
			}
			checked++
			provider := jsonStringField(s.Request.Body, "providerId")
			for _, fetches := range identityProvidersFetchingOnConstruction {
				if provider != fetches {
					continue
				}
				t.Errorf("%s: its fixture %q creates a %q instance, whose factory "+
					"fetches over the network while this route constructs it - so the "+
					"recorded status is the recording host's egress and not Keycloak's "+
					"answer. See F230.", c.ID, c.Fixture, provider)
			}
		}
	}
	// The vacuity guard TestNoTwoFixturesMintOneIdentityProviderID needs, for
	// the same reason: three mapper-types cases create a provider between them.
	if checked < 3 {
		t.Fatalf("checked %d mapper-types fixtures, want at least 3: "+
			"this test is matching nothing", checked)
	}
}

// jsonStringField reads one top-level string field out of a fixture body.
//
// A full unmarshal would do, and this does not use one on purpose: the bodies
// here are literals written to be read, several carry a `config` object whose
// value types differ between providers, and a decode into a typed struct is a
// second place to keep a field list in step. What the caller needs is one
// string, and the bodies are flat enough at the top level for the key to be
// found by name.
func jsonStringField(body []byte, field string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(m[field], &s); err != nil {
		return ""
	}
	return s
}

func TestCatalogFixturesExist(t *testing.T) {
	for _, c := range Catalog {
		if c.Fixture == "" {
			continue
		}
		if _, ok := Fixtures[c.Fixture]; !ok {
			t.Errorf("%q: names fixture %q, which is not declared", c.ID, c.Fixture)
		}
	}
}
