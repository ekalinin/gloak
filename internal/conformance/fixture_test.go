package conformance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
			if len(s.Capture) == 0 {
				t.Errorf("fixture %q step %d: a step that captures nothing is dead weight", name, i)
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
