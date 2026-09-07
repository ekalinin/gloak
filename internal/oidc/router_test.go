package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// securityHeaders is the five Keycloak attaches to a response that reached its
// filter chain. The tests below assert the whole set on both sides of the
// split, because the header set is what separates the dispatcher's 404s from
// the unmatched-path one and a test naming one header cannot see the
// difference.
var securityHeaders = []string{
	"Referrer-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-Robots-Tag",
}

// get runs one GET through the router and returns the recorder.
func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// wantSecurityHeaders asserts all five are present, or that none of them is.
func wantSecurityHeaders(t *testing.T, w *httptest.ResponseRecorder, want bool) {
	t.Helper()
	for _, name := range securityHeaders {
		got := w.Header().Get(name) != ""
		if got != want {
			t.Fatalf("%s present=%v, want %v", name, got, want)
		}
	}
}

// TestUnknownPathReturnsKeycloakShapedNotFound proves a path matching no
// registered route returns package httpx's shape 2 body, not net/http's own
// "404 page not found\n" text/plain response. No Keycloak client expects a
// Go-shaped 404. Body and status are measured: see
// internal/conformance/testdata/golden/http/fallback/unknown-path.http and
// the "Fallback responses" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func TestUnknownPathReturnsKeycloakShapedNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/realms/master/nope", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want Content-Type %q, got %q", want, got)
	}
	if got, want := w.Body.String(), `{"error":"Unable to find matching target resource method"}`; got != want {
		t.Fatalf("want body %s, got %s", want, got)
	}
}

// TestWrongMethodReturnsKeycloakShapedNotFound proves a known path hit with
// an unsupported method returns package httpx's shape, not net/http's own
// "Method Not Allowed\n" text/plain response. Keycloak answers this with its
// generic 404 shape, not 405: see
// internal/conformance/testdata/golden/http/fallback/method-not-allowed.http
// and the "Fallback responses" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
func TestWrongMethodReturnsKeycloakShapedNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/realms/master", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want Content-Type %q, got %q", want, got)
	}
	if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
		t.Fatalf("want body %s, got %s", want, got)
	}
}

// TestOneTrailingSlashIsStripped is F177's rule and the positive control the
// refusals below need: without it a dispatcher that answered 404 to everything
// would satisfy every other test in this file.
//
// The five paths are three different downstream answers - a 200 JSON body, a
// 200 XML body and a 400 theme page - so a strip that reached only the JSON
// endpoints would fail here rather than pass. Measured 2026-09-07 on a live
// 26.7.1: each slashed path answers byte-identically to its bare one.
func TestOneTrailingSlashIsStripped(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect/certs",
		"/realms/master/protocol/saml/descriptor",
		"/realms/master/protocol/openid-connect/auth",
		"/realms/master/.well-known/openid-configuration",
		"/realms/master",
	} {
		t.Run(path, func(t *testing.T) {
			bare := get(t, h, path)
			slashed := get(t, h, path+"/")
			if bare.Code != slashed.Code {
				t.Fatalf("status %d bare, %d slashed", bare.Code, slashed.Code)
			}
			if bare.Body.String() != slashed.Body.String() {
				t.Fatalf("bodies differ:\n bare    %.120s\n slashed %.120s",
					bare.Body.String(), slashed.Body.String())
			}
			if got, want := slashed.Header().Get("Content-Type"),
				bare.Header().Get("Content-Type"); got != want {
				t.Fatalf("Content-Type %q slashed, %q bare", got, want)
			}
		})
	}
}

// TestTheTwoFallbackShapesAlsoStripOneTrailingSlash is the half of the rule
// that says it is a strip and not a route: the two measured fallback bodies
// answer a slashed path exactly as they answer the bare one, so nothing
// downstream needs to know the slash was there.
func TestTheTwoFallbackShapesAlsoStripOneTrailingSlash(t *testing.T) {
	h := newServer(t)

	unmatched := get(t, h, "/nosuchpath/")
	if got, want := unmatched.Body.String(),
		`{"error":"Unable to find matching target resource method"}`; got != want {
		t.Fatalf("unmatched: want %s, got %s", want, got)
	}
	wantSecurityHeaders(t, unmatched, false)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/realms/master/.well-known/openid-configuration/", nil))
	if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
		t.Fatalf("wrong method: want %s, got %s", want, got)
	}
	wantSecurityHeaders(t, w, true)
}

// TestASecondTrailingSlashIsNotStripped is the boundary of the rule above, and
// it is the case a loop would get wrong. Measured 2026-09-07 with raw sockets:
// two or more slashes never reach a route at all.
func TestASecondTrailingSlashIsNotStripped(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect/certs//",
		"/realms/master/protocol/openid-connect/certs///",
		"/realms/master//",
	} {
		w := get(t, h, path)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d (body %.80s)", path, w.Code, w.Body.String())
		}
	}
}

// TestAPathThatIsNotNormalisedIsRefused pins the whole response, because every
// part of it is measured and two parts are what a reader would get wrong: the
// Content-Type spells its parameter with a space where nothing else in this
// server does, and the response carries **none** of the five security headers.
func TestAPathThatIsNotNormalisedIsRefused(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect/certs//",
		"//realms/master",
		"/realms//master",
		"/realms/master/./protocol",
		"/realms/master/../master",
		"/realms/master/protocol/openid-connect/certs/.",
		"/realms/master/protocol/openid-connect/certs/..",
		"/nosuchthing//",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", w.Code)
			}
			if got, want := w.Header().Get("Content-Type"),
				"application/json; charset=UTF-8"; got != want {
				t.Fatalf("want Content-Type %q, got %q", want, got)
			}
			if got, want := w.Body.String(),
				`{"error":"missingNormalization","error_description":"Request path not normalized"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			wantSecurityHeaders(t, w, false)
		})
	}
}

// TestANormalisedPathIsNotRefused is the positive control for the predicate
// above: a dot inside a realm name, a dot inside a segment and a segment of
// three dots are all paths a "contains a dot" reading would refuse.
//
// The third is the sharp one. The refusal fires on the percent-encoded
// spelling too, because url.Parse decodes %2E%2E to ".." before the predicate
// sees it - so the segment comparison has to be exact rather than a substring,
// or a name that merely contains dots stops resolving.
func TestANormalisedPathIsNotRefused(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/a.b/protocol/openid-connect/certs",
		"/realms/master/protocol/openid-connect/cert.s",
		"/realms/...",
	} {
		w := get(t, h, path)
		if w.Code == http.StatusBadRequest {
			t.Fatalf("%s: refused as unnormalised, and it is normalised", path)
		}
	}
}

// TestProtocolNotFound is F178. It is measured on nine shapes rather than one
// because a dispatcher that answered the sentence for everything under
// /protocol/ passes any single one of them - which is the failure shape
// AGENTS.md names, a set of inputs an incorrect implementation satisfies
// entirely. TestARegisteredProtocolStopsTheDispatch is the discriminating
// half.
func TestProtocolNotFound(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/nosuchproto",
		"/realms/master/protocol/nosuchproto/descriptor",
		"/realms/master/protocol/nosuchproto/certs",
		"/realms/master/protocol/x/a/b/c/d",
		"/realms/master/protocol/saml-ecp",
		"/realms/master/protocol/docker-v2",
		"/realms/master/protocol/oidc",
		"/realms/master/protocol/SAML",
		"/realms/master/protocol/OPENID-CONNECT",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", w.Code)
			}
			if got, want := w.Body.String(), `{"error":"Protocol not found"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
				t.Fatalf("want Content-Type %q, got %q", want, got)
			}
			wantSecurityHeaders(t, w, true)
			if cc := w.Header().Get("Cache-Control"); cc != "" {
				t.Fatalf("want no Cache-Control, got %q", cc)
			}
		})
	}
}

// TestProtocolNotFoundAnswersEveryVerb is the one route in this package that
// really does answer every method the same way, measured on six.
func TestProtocolNotFoundAnswersEveryVerb(t *testing.T) {
	h := newServer(t)
	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodOptions, http.MethodHead,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/realms/master/protocol/x", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404, got %d", method, w.Code)
		}
		// HEAD is served through httptest.ResponseRecorder, which does not
		// strip a body where http.Server does - F180's note - so the recorder
		// holds the same bytes for all six.
		if got, want := w.Body.String(), `{"error":"Protocol not found"}`; got != want {
			t.Fatalf("%s: want body %s, got %s", method, want, got)
		}
		wantSecurityHeaders(t, w, true)
	}
}

// TestARegisteredProtocolStopsTheDispatch is the case that kills the
// implementation TestProtocolNotFound alone would let through. A path under a
// protocol Keycloak has registered answers the router's own generic 404, and it
// does so at any depth - so the dispatcher's map is load-bearing rather than
// decoration.
//
// The bare /protocol segment is in the list because it is a third answer to
// the same predicate: the empty protocol name is not a protocol, and leaving
// it out of the map would send it the wrong sentence.
func TestARegisteredProtocolStopsTheDispatch(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect",
		"/realms/master/protocol/openid-connect/nosuchsub",
		"/realms/master/protocol/openid-connect/nosuchsub/deeper",
		"/realms/master/protocol/openid-connect/certs/extra",
		"/realms/master/protocol/openid-connect/auth/nosuch",
		"/realms/master/protocol/saml/nosuchsubpath",
		"/realms/master/protocol/saml/descriptor/extra",
		"/realms/master/protocol",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", w.Code)
			}
			if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			wantSecurityHeaders(t, w, true)
		})
	}
}

// TestTheDispatcherResolvesTheRealmFirst pins the order. An unknown realm
// answers about the realm even when the protocol is unknown too, so a
// dispatcher that read its map before looking the realm up would be wrong on
// every request that gets both wrong - and right on every request that gets
// only one wrong, which is every probe a reader writes first.
func TestTheDispatcherResolvesTheRealmFirst(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/nosuchrealm/protocol",
		"/realms/nosuchrealm/protocol/nosuchproto",
		"/realms/nosuchrealm/protocol/nosuchproto/descriptor",
		"/realms/nosuchrealm/protocol/openid-connect/nosuchsub",
		"/realms/nosuchrealm/protocol/saml",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", w.Code)
			}
			if got, want := w.Body.String(), `{"error":"Realm does not exist"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			wantSecurityHeaders(t, w, true)
		})
	}
}

// TestTheDispatcherDoesNotSwallowAServedRoute is the composition F178 warned
// about: a catch-all under /realms/{realm}/protocol/ changes what a trailing
// slash matches, and the two rules were not to be fixed in isolation and
// assumed to compose.
//
// Every route this package serves under /protocol is asked for, bare and
// slashed, and required not to answer any of the three 404 sentences. A
// dispatcher registered too broadly, or a strip running after the mux instead
// of before it, fails here.
func TestTheDispatcherDoesNotSwallowAServedRoute(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/openid-connect/certs",
		"/realms/master/protocol/openid-connect/auth",
		"/realms/master/protocol/openid-connect/auth/device",
		"/realms/master/protocol/openid-connect/logout",
		"/realms/master/protocol/saml/descriptor",
	} {
		for _, p := range []string{path, path + "/"} {
			w := get(t, h, p)
			body := w.Body.String()
			if strings.Contains(body, "Protocol not found") ||
				strings.Contains(body, "HTTP 404 Not Found") ||
				strings.Contains(body, "Unable to find matching target resource method") {
				t.Fatalf("%s: the dispatcher swallowed a served route: %d %.100s",
					p, w.Code, body)
			}
		}
	}
}
