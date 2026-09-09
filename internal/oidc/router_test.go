package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/account"
	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// newServerWithAccount is newServer plus the account API on the same mux, which
// is how cmd/gloak and the conformance server build the real one. It exists for
// TestTheRealmResourceDispatcherDoesNotSwallowAServedRoute: F184's catch-all
// covers every path under /realms/{realm}, including the ones a package other
// than this one registers, and neither package's own tests would otherwise see
// the two combined.
func newServerWithAccount(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	mux := http.NewServeMux()
	km := keys.NewManager(s)
	oidc.Register(mux, s, km, "http://localhost:8080")
	account.Register(mux, s, km, "http://localhost:8080")
	return oidc.WithKeycloakFallbacks(mux)
}

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
//
// **The path is outside /realms/ and that is load-bearing.** It was
// /realms/master/nope until F184, which is not an unmatched path on a live
// 26.7.1 at all: everything under a realm that resolves reaches the filter
// chain and answers `HTTP 404 Not Found` with all five security headers. This
// body is what is left once realmResourceDispatch has taken that tree.
func TestUnknownPathReturnsKeycloakShapedNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nosuchpath", nil)
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
//
// **It builds its own mux, because F184 made this branch unreachable through
// this package's route table.** realmResourceDispatch is registered with no
// method on /realms/{realm} and /realms/{realm}/{rest...}, so every path under
// a realm now matches something and the wrong-method probe never runs for one.
// The branch is still live for the routes internal/admin registers under
// /admin, which this package cannot see - so the input that exercises it here
// is a mux of the wrapper's own, which is what WithKeycloakFallbacks takes.
// Asserting it through /realms/master instead would pass on the dispatcher's
// identical body and stop testing the probe at all.
//
// **A mux built here is not the whole guard, and it should not be.** A unit
// test compares against what this project believes; a golden compares against a
// recording. http/fallback/method-not-allowed-admin is the recording - POST on
// an Admin API path Gloak serves with GET alone - and it exists because a
// branch that had a corpus witness and lost it to a refactor is the kind of
// thing nobody notices until it is wrong.
func TestWrongMethodReturnsKeycloakShapedNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /outside/{$}", func(w http.ResponseWriter, _ *http.Request) {})
	req := httptest.NewRequest(http.MethodPost, "/outside", nil)
	w := httptest.NewRecorder()

	oidc.WithKeycloakFallbacks(mux).ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want Content-Type %q, got %q", want, got)
	}
	if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
		t.Fatalf("want body %s, got %s", want, got)
	}
	// The half the body cannot see: a known path hit with the wrong method
	// reached the filter chain, so it carries all five where the unmatched-path
	// body above carries none.
	wantSecurityHeaders(t, w, true)
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
//
// Since F184 the second half reaches realmResourceDispatch rather than the
// wrong-method probe - same status, same body, same header set, a different
// producer - so what it now pins is that the strip runs ahead of the catch-all
// too. The bytes are unchanged either way, which is the point: the strip is
// invisible downstream.
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

// TestTheRootPathIsNotStrippedToNothing pins the one guard on the strip that
// no measurement against Keycloak names: "/" ends in a slash, and stripping it
// leaves the empty path, which is not a request any router can be asked about.
//
// It builds its own mux because **Gloak serves nothing at "/" today**, and
// against the real route table the guard is an equivalent mutation - removing
// it turns "/" into "", ServeMux matches neither, and both spellings answer the
// same unmatched-path 404. That was a surviving mutation until this test was
// written the way it is now. Keycloak answers "/" with a 302 to /admin/ and
// four of the five security headers; the day Gloak serves that, the guard
// carries the request, and this test is what says so in the meantime.
//
// WithKeycloakFallbacks takes any mux, so a mux built here is the wrapper's
// real input rather than a stand-in for it.
func TestTheRootPathIsNotStrippedToNothing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("root"))
	})
	w := httptest.NewRecorder()
	oidc.WithKeycloakFallbacks(mux).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if got, want := w.Body.String(), "root"; got != want {
		t.Fatalf("the root path did not reach its own route: %d %q", w.Code, got)
	}
}

// TestAnEscapedPathKeepsItsEscapesAcrossTheStrip is the half of the strip that
// no measurement against Keycloak reaches and that Go's URL type makes easy to
// get wrong. url.URL carries the path twice - decoded in Path and raw in
// RawPath - and a copy that trims one and not the other leaves the two
// disagreeing, at which point EscapedPath quietly discards the raw form and
// re-escapes the decoded one. Nothing about the status or the body moves, which
// is why this asserts EscapedPath directly: the assertion a reader writes first
// leaves the mutation alive.
//
// The realm is spelled with an escaped "s" so that Path and RawPath differ at
// all, which httptest.NewRequest is checked for below - the fixture stops
// separating them the moment the escape is dropped from the literal.
func TestAnEscapedPathKeepsItsEscapesAcrossTheStrip(t *testing.T) {
	const escaped = "/realms/ma%73ter/probe"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /realms/{realm}/probe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.EscapedPath()))
	})
	h := oidc.WithKeycloakFallbacks(mux)

	req := httptest.NewRequest(http.MethodGet, escaped+"/", nil)
	if got, want := req.URL.RawPath, escaped+"/"; got != want {
		t.Fatalf("the fixture no longer separates Path from RawPath: RawPath %q", got)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if got := w.Body.String(); got != escaped {
		t.Fatalf("EscapedPath after the strip is %q, want %q", got, escaped)
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

// TestTheProtocolDispatcherBeatsTheRealmResourceDispatcher is the precedence
// F184 said to establish rather than assume. Both dispatchers are catch-alls
// registered with no method, one nested inside the other's tree, and they
// answer **different sentences** for the same status - so if the wider one won,
// `Protocol not found` would disappear from the server and every test that
// asserts it would still pass on the narrower paths.
//
// Go's ServeMux gives the more specific pattern the request:
// /realms/{realm}/protocol/{protocol} matches a strict subset of
// /realms/{realm}/{rest...}. That is verified here by running the routes rather
// than read from the documentation, because the two cuts' patterns are not the
// same patterns and F153 is in this repository because a ServeMux assumption
// was wrong once.
func TestTheProtocolDispatcherBeatsTheRealmResourceDispatcher(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/protocol/nosuchproto",
		"/realms/master/protocol/nosuchproto/descriptor",
		"/realms/master/protocol/x/a/b/c/d",
		"/realms/master/protocol/SAML",
	} {
		t.Run(path, func(t *testing.T) {
			if got, want := get(t, h, path).Body.String(),
				`{"error":"Protocol not found"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
		})
	}
}

// TestARealmResourceThatNoRouteServes is F184's leading shape. Six paths rather
// than one, because a dispatcher that answered this sentence for everything
// under /realms/ satisfies any single one of them - the failure shape AGENTS.md
// names - and because four of the six are paths a *neighbouring* family owns on
// a live 26.7.1 and answers with this same body:
// /login-actions/nosuchaction, /device/nosuchsub and /.well-known/nosuchdoc all
// sit beside routes this package serves.
//
// Depth is in the list because it is a decision: one {rest...} pattern rather
// than a pattern per depth, measured identical at one, two and six segments.
func TestARealmResourceThatNoRouteServes(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/master/nosuchthing",
		"/realms/master/nosuchthing/deeper",
		"/realms/master/nosuchthing/a/b/c/d/e",
		"/realms/master/login-actions/nosuchaction",
		"/realms/master/device/nosuchsub",
		"/realms/master/.well-known/nosuchdoc",
	} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", w.Code)
			}
			if got, want := w.Body.String(), `{"error":"HTTP 404 Not Found"}`; got != want {
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

// TestTheRealmResourceDispatcherResolvesTheRealmFirst is the discriminating
// half: the same paths under a realm that does not exist answer about the realm
// instead. A dispatcher that wrote its sentence without looking the realm up
// passes the test above and fails here.
func TestTheRealmResourceDispatcherResolvesTheRealmFirst(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{
		"/realms/nosuchrealm/nosuchthing",
		"/realms/nosuchrealm/nosuchthing/deeper",
		"/realms/nosuchrealm/account/nosuchsub",
		"/realms/nosuchrealm",
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

// TestTheRealmIsResolvedBeforeTheMethodIsDispatched is why both patterns carry
// no method, and it is the cell a GET-only catch-all gets wrong while passing
// everything above. Measured 2026-09-09: a path this router serves, hit with a
// method it does not serve, under a realm that does not exist, answers about
// the realm and not the wrong-method 404.
//
// Registering the catch-all with a method would leave these to
// WithKeycloakFallbacks, which has no store and cannot resolve a realm, so it
// would answer `HTTP 404 Not Found` - the right body for the wrong reason on
// master and the wrong body outright here.
func TestTheRealmIsResolvedBeforeTheMethodIsDispatched(t *testing.T) {
	h := newServer(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/realms/nosuchrealm/.well-known/openid-configuration"},
		{http.MethodPost, "/realms/nosuchrealm"},
		{http.MethodPut, "/realms/nosuchrealm"},
		{http.MethodDelete, "/realms/nosuchrealm/account/groups"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if got, want := w.Body.String(), `{"error":"Realm does not exist"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			wantSecurityHeaders(t, w, true)
		})
	}
}

// TestTheRealmCollectionStaysOffTheRouteTable is F184's other half and the
// constraint on where the catch-all may be registered. /realms and /realms/ are
// the one measured place in this server where a **shorter** path is less
// reachable than a longer one: both answer the unmatched-path body with none of
// the five security headers, where everything below them carries all five.
//
// A catch-all one segment higher - /realms/{rest...}, or a /realms/ subtree -
// serves both of them and passes every other test in this file.
func TestTheRealmCollectionStaysOffTheRouteTable(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{"/realms", "/realms/"} {
		t.Run(path, func(t *testing.T) {
			w := get(t, h, path)
			if w.Code != http.StatusNotFound {
				t.Fatalf("want 404, got %d", w.Code)
			}
			if got, want := w.Body.String(),
				`{"error":"Unable to find matching target resource method"}`; got != want {
				t.Fatalf("want body %s, got %s", want, got)
			}
			wantSecurityHeaders(t, w, false)
		})
	}
}

// TestTheRealmResourceDispatcherNeverRedirects is the F153-shaped hazard this
// cut met, and it is the reason the bare /realms/{realm} pattern is registered
// beside the {rest...} one.
//
// Go's ServeMux registers an implicit redirect at the root of a subtree
// pattern. With /realms/{realm}/{rest...} alone, POST /realms/master answers a
// **307 to /realms/master/** - and mux.Handler reports a non-empty pattern for
// it, so WithKeycloakFallbacks hands it straight to the mux and net/http writes
// a body this project never produces. Registering /realms/{realm} shadows it.
//
// Verified by running the route table rather than read from the documentation,
// which is what F178 told the dispatch cut to do and what F153 is in this
// repository for. The status is what this asserts, because the body of a 307 is
// not what a reader would look at.
func TestTheRealmResourceDispatcherNeverRedirects(t *testing.T) {
	h := newServer(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/realms/master"},
		{http.MethodPut, "/realms/master"},
		{http.MethodPost, "/realms/nosuchrealm"},
		{http.MethodGet, "/realms/master/nosuchthing"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code >= 300 && w.Code < 400 {
				t.Fatalf("want no redirect, got %d to %q", w.Code, w.Header().Get("Location"))
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Fatalf("want no Location header, got %q", loc)
			}
		})
	}
}

// TestTheRealmResourceDispatcherDoesNotSwallowAServedRoute is the composition
// question F184 named, asked of the whole realm tree rather than of /protocol.
// Every route this package serves under /realms/{realm} is asked for, bare and
// slashed, and required not to answer any of the three 404 sentences.
//
// **The account API's two routes are in the list and they are registered by
// another package.** That is the point of the test: the catch-all is one mux
// entry away from taking a path it does not own, and the two packages are
// combined only in cmd/gloak and in the conformance server, so nothing else in
// either package's own tests would notice. account.Register is imported here
// for that reason alone.
func TestTheRealmResourceDispatcherDoesNotSwallowAServedRoute(t *testing.T) {
	h := newServerWithAccount(t)
	for _, path := range []string{
		"/realms/master",
		"/realms/master/.well-known/openid-configuration",
		"/realms/master/protocol/openid-connect/certs",
		"/realms/master/protocol/openid-connect/auth",
		"/realms/master/protocol/saml/descriptor",
		"/realms/master/protocol/nosuchproto",
		"/realms/master/device",
		"/realms/master/device/status",
		"/realms/master/login-actions/authenticate",
		"/realms/master/account/groups",
		"/realms/master/account/linked-accounts",
	} {
		for _, p := range []string{path, path + "/"} {
			w := get(t, h, p)
			body := w.Body.String()
			if strings.Contains(body, "HTTP 404 Not Found") ||
				strings.Contains(body, "Unable to find matching target resource method") {
				t.Fatalf("%s: the dispatcher swallowed a served route: %d %.100s",
					p, w.Code, body)
			}
		}
	}
}
