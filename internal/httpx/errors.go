// Package httpx owns Keycloak's error formats. They live in one package because
// compatibility breaks on error paths far more often than on success paths, and
// a format spread across handlers is a format that drifts.
//
// Keycloak 26.7.1 emits four distinct shapes. They do not split along the
// protocol/admin boundary; both sides use more than one. See
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
package httpx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// WriteOAuthError writes shape 1, the RFC 6749 body used by the token endpoint
// and by the admin API for an unparseable JSON payload.
func WriteOAuthError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// WriteMessageError writes shape 2: a bare error field carrying prose rather
// than an OAuth error code, used for 401 and 404 on both sides.
func WriteMessageError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// WriteAdminError writes shape 3: the errorMessage field the admin API uses for
// conflicts and validation failures.
func WriteAdminError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"errorMessage": message})
}

// WriteBearerChallenge writes the userinfo rejection: 401, text/plain, an empty
// body, and the error carried entirely in WWW-Authenticate.
func WriteBearerChallenge(w http.ResponseWriter, realm, errCode, description string) {
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		"Bearer realm=%q, error=%q, error_description=%q", realm, errCode, description))
	w.WriteHeader(http.StatusUnauthorized)
}

// WriteJSON writes a JSON response body byte-exact to what Keycloak sends:
// Content-Type: application/json, no trailing newline. json.Encoder always
// appends one; WriteJSON trims it. This is the only function in Gloak that
// is allowed to format a response body - every package that writes JSON,
// success or error, must go through it, so the byte-exactness guarantee
// cannot drift between call sites.
func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Keycloak emits no trailing newline; SetEscapeHTML(false) keeps
	// descriptions containing quotes or angle brackets byte-identical.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)

	// Trim the trailing newline that json.Encoder.Encode appends
	b := buf.Bytes()
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	_, _ = w.Write(b)
}
