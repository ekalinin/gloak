package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ekalinin/gloak/internal/httpx"
)

func TestWriteOAuthError(t *testing.T) {
	w := httptest.NewRecorder()

	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid user credentials")

	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `{"error":"invalid_grant","error_description":"Invalid user credentials"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteMessageError(t *testing.T) {
	// Shape 2: a bare error field holding prose, not an OAuth code.
	w := httptest.NewRecorder()

	httpx.WriteMessageError(w, http.StatusNotFound, "Realm not found.")

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm not found."}`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteAdminError(t *testing.T) {
	// Shape 3: errorMessage, used for admin conflicts and validation.
	w := httptest.NewRecorder()

	httpx.WriteAdminError(w, http.StatusConflict, "Client gloak-probe already exists")

	if w.Code != 409 {
		t.Fatalf("want 409, got %d", w.Code)
	}
	want := `{"errorMessage":"Client gloak-probe already exists"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteBearerChallenge(t *testing.T) {
	// userinfo with a bad token: 401, text/plain, empty body, error in the header.
	w := httptest.NewRecorder()

	httpx.WriteBearerChallenge(w, "master", "invalid_token", "Token verification failed")

	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if got := w.Body.Len(); got != 0 {
		t.Fatalf("want an empty body, got %d bytes: %q", got, w.Body.String())
	}
	if got, want := w.Header().Get("Content-Type"), "text/plain;charset=utf-8"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `Bearer realm="master", error="invalid_token", error_description="Token verification failed"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestNoTrailingNewline(t *testing.T) {
	// Verify that no trailing newline is present in the JSON body,
	// regardless of payload size. This test uses a large error description
	// to ensure the payload is interesting.
	w := httptest.NewRecorder()

	longDescription := "This is a very long error description that might span multiple chunks if not handled correctly. " +
		"It contains lots of characters to make the JSON output large enough to be interesting. " +
		"The json.Encoder.Encode method appends a trailing newline, and we must strip it."
	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", longDescription)

	body := w.Body.String()

	// Verify the body ends with }
	if len(body) == 0 || body[len(body)-1] != '}' {
		t.Fatalf("body must end with }, got: %q", body)
	}

	// Verify no newline exists anywhere in the body
	for i, ch := range body {
		if ch == '\n' {
			t.Fatalf("body contains newline at position %d: %q", i, body)
		}
	}
}
