package conformance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The CaptureHeader tests below live at the top of this file because they are
// the newest thing in it; the rest is P1's body-capture coverage.

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
			capturesNothing := len(s.Capture) == 0 && len(s.CaptureHeader) == 0
			if capturesNothing && s.Request.Method == http.MethodGet {
				t.Errorf("fixture %q step %d: a GET that captures nothing is dead weight", name, i)
			}
		}
	}
	if _, ok := Fixtures["bootstrap"]; !ok {
		t.Error(`Fixtures must contain "bootstrap"`)
	}
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
