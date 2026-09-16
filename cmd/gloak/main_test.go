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

// TestManagementPortIsOffByDefault is the measured default reproduced.
//
// A `quay.io/keycloak/keycloak:26.7.1 start-dev` with neither --health-enabled
// nor --metrics-enabled has **no listener on 9000 at all**: its startup line
// names one address and /proc/net/tcp6 inside the container holds one routable
// listening socket. A Gloak that served the management port unasked would be
// opening a socket the reference server does not, which is a divergence in the
// direction nobody looks for.
func TestManagementPortIsOffByDefault(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")
	t.Setenv("GLOAK_HEALTH_ENABLED", "")

	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.healthEnabled {
		t.Error("the management interface is on with nothing asking for it")
	}
	// The address still has its default, because turning the option on must not
	// also require naming a port.
	if cfg.managementAddr != ":9000" {
		t.Errorf("managementAddr = %q, want Keycloak's :9000", cfg.managementAddr)
	}
}

// TestHealthEnabledIsReadFromBothPlaces walks the flag and the environment
// variable, and the values each accepts.
//
// The asymmetry in the last row is deliberate and is documented on envTrue: an
// unparseable **flag** is a usage error that stops the server, and an
// unparseable **environment variable** is false. Making the environment fatal
// would let a typo in a deployment's env block stop a server that would
// otherwise serve every request correctly, to protect an endpoint that is off
// by default.
func TestHealthEnabledIsReadFromBothPlaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		args []string
		want bool
	}{
		{name: "unset", want: false},
		{name: "the environment says true", env: "true", want: true},
		{name: "the environment says 1", env: "1", want: true},
		{name: "the environment says false", env: "false", want: false},
		{name: "the flag says true", args: []string{"-health-enabled"}, want: true},
		{name: "the flag overrides the environment", env: "true",
			args: []string{"-health-enabled=false"}, want: false},
		{name: "an unparseable environment value is off", env: "yes", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")
			t.Setenv("GLOAK_HEALTH_ENABLED", tc.env)

			cfg, err := parseConfig(tc.args)
			if err != nil {
				t.Fatalf("parseConfig: %v", err)
			}
			if cfg.healthEnabled != tc.want {
				t.Errorf("healthEnabled = %v, want %v", cfg.healthEnabled, tc.want)
			}
		})
	}
}

// TestThereIsNoMetricsFlag is a refusal rather than a check.
//
// Gloak keeps no counters, so it has no --metrics-enabled and /metrics answers
// the ordinary 53-byte 404 - which is exactly what a metrics-disabled Keycloak
// answers, measured on its own container. Somebody adding the flag has to
// remove this test, and removing a test is a thing a reviewer sees.
func TestThereIsNoMetricsFlag(t *testing.T) {
	t.Setenv("GLOAK_ADMIN_PASSWORD", "s3cret")

	if _, err := parseConfig([]string{"-metrics-enabled"}); err == nil {
		t.Fatal("-metrics-enabled was accepted; Gloak has nothing to meter, and a " +
			"flag that turned on a fabricated dump would be worse than its absence")
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
