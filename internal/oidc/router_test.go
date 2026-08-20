package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
