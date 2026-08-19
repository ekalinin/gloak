package main

import (
	"net/http"
	"testing"
)

// TestParseConfigRequiresAdminPassword proves parseConfig refuses to invent
// an admin/admin credential: with GLOAK_ADMIN_PASSWORD unset, it must fail
// rather than silently default the master realm admin password.
func TestParseConfigRequiresAdminPassword(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "")

	if _, err := parseConfig(nil); err == nil {
		t.Fatal("want an error when GLOAK_ADMIN_PASSWORD is unset, got nil")
	}
}

// TestParseConfigReadsAdminPasswordFromEnv proves the password is still
// accepted, from the environment only.
func TestParseConfigReadsAdminPasswordFromEnv(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")

	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.adminPassword != "s3cret" {
		t.Fatalf("want adminPassword %q, got %q", "s3cret", cfg.adminPassword)
	}
}

// TestParseConfigRejectsAdminPasswordFlag proves the password can no longer
// be passed on the command line, since argv is visible to any other process
// on the machine.
func TestParseConfigRejectsAdminPasswordFlag(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")

	if _, err := parseConfig([]string{"-admin-password=whatever"}); err == nil {
		t.Fatal("want an error for the removed -admin-password flag, got nil")
	}
}

// TestParseConfigKeepsAdminUserFlag proves -admin-user is unaffected.
func TestParseConfigKeepsAdminUserFlag(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")

	cfg, err := parseConfig([]string{"-admin-user=root"})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.adminUser != "root" {
		t.Fatalf("want adminUser %q, got %q", "root", cfg.adminUser)
	}
}

// TestNewHTTPServerSetsTimeouts proves the server never has a zero-value
// (unbounded) timeout on any stage of a connection's lifecycle.
func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	s := newHTTPServer(":0", http.NotFoundHandler())

	if s.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout must be set")
	}
	if s.ReadTimeout <= 0 {
		t.Error("ReadTimeout must be set")
	}
	if s.WriteTimeout <= 0 {
		t.Error("WriteTimeout must be set")
	}
	if s.IdleTimeout <= 0 {
		t.Error("IdleTimeout must be set")
	}
}
