//go:build docker

package conformance

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestRecordGoldens replays the catalogue against a live Keycloak 26.7.1 and
// writes the expected bytes. It rewrites checked-in files, so it never runs as
// part of `make test`: run it deliberately with `make record` and read the
// diff before committing.
//
// Cases with an empty Fixture are skipped: they need setup that does not exist
// yet. A case naming a fixture this recorder cannot build is a failure, not a
// quiet skip.
func TestRecordGoldens(t *testing.T) {
	ctx := context.Background()
	base := startKeycloak(ctx, t)
	// A redirect is the response being measured, not a step on the way to
	// one: for the authorization and logout endpoints the contract is the
	// 3xx status and its Location header (the code/state/session_state/iss,
	// or error, Keycloak puts there), not whatever page the client would
	// land on next. Without this, http.Client's default redirect-following
	// silently turns those recordings into a capture of Keycloak's login
	// theme instead - a giant HTML page that is not part of the contract and
	// churns per container start besides.
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var skipped []string
	for _, c := range Catalog {
		if c.Fixture == "" {
			skipped = append(skipped, c.ID)
			continue
		}
		f, ok := Fixtures[c.Fixture]
		if !ok {
			t.Errorf("%s: names fixture %q, which is not declared", c.ID, c.Fixture)
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			// The fixture's own steps are run but never recorded: only the
			// case's response becomes a golden. Recording a step would commit
			// a live token to the repository.
			vars, err := RunFixture(f, base, client.Do)
			if err != nil {
				t.Fatalf("fixture %q: %v", c.Fixture, err)
			}
			req, err := buildRequest(base, Expand(c.Request, vars))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			// The same passes the verifier applies, in the same order, from
			// the one place that defines them. See passes.go.
			body, err = normalisePasses(body, base, c, vars)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}

			g := Golden{
				RequestLine: c.Request.Method + " " + c.Request.Path,
				Status:      resp.StatusCode,
				Headers:     recordedHeaders(resp.Header, base, c, vars),
				Body:        body,
			}
			path := GoldenPath(goldenDir, c.ID)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, FormatGolden(g), 0o644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			t.Logf("recorded %s", path)
		})
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		t.Logf("skipped %d cases with no fixture yet: %v", len(skipped), skipped)
	}
}

// startKeycloak runs the reference server and returns its base URL. The image
// tag is the project's pinned compatibility target and must not drift.
func startKeycloak(ctx context.Context, t *testing.T) string {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.7.1",
		Cmd:          []string{"start-dev"},
		ExposedPorts: []string{"8080/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
		},
		WaitingFor: wait.ForHTTP("/realms/master").
			WithPort("8080/tcp").
			WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
			WithStartupTimeout(5 * time.Minute),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start keycloak: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port())
}
