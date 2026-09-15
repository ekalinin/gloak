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
//
// A Pending case is skipped too, and its golden is left byte for byte as it was
// found. Nothing compares a Pending golden, so rewriting it can only add noise
// to the diff - which four login-theme pages did on every single run, because
// their /resources/<version>/ segment is minted with the database - see
// ReplaceThemeResource, which is what made seven of the eight comparable. See
// GoldenIsAsserted for why the way to ask for one is to promote the case rather
// than to set a flag.
//
// There are two container regimes and the catalogue decides which a case gets.
// Almost every case is recorded against one shared container, in catalogue
// order, which is why a whole run costs one Keycloak start and not three
// hundred. A PristineRealm case gets a container to itself, because its body is
// a function of everything in the realm and the verifier will serve it from a
// handler that has seen nothing but its own fixture. Recording those first on
// the shared container was the previous answer and it does not hold: the
// pristine group pollutes itself, which is how admin/groups/count came to have
// its number masked (F40).
func TestRecordGoldens(t *testing.T) {
	ctx := context.Background()
	// Every case that does not enumerate the realm is recorded against this
	// one, which accumulates state in catalogue order. That is harmless for a
	// case addressing one object by UUID, and it is the reason the whole run
	// does not cost one container start per case.
	shared, sharedManagement := startKeycloak(ctx, t)
	// A redirect is the response being measured, not a step on the way to
	// one: for the authorization and logout endpoints the contract is the
	// 3xx status and its Location header (the code/state/session_state/iss,
	// or error, Keycloak puts there), not whatever page the client would
	// land on next. Without this, http.Client's default redirect-following
	// silently turns those recordings into a capture of Keycloak's login
	// theme instead - a giant HTML page that is not part of the contract and
	// churns with every fresh database besides.
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var skipped, parked []string
	for _, c := range Catalog {
		if c.Fixture == "" {
			skipped = append(skipped, c.ID)
			continue
		}
		// A golden nothing compares is left exactly as it was found. See
		// GoldenIsAsserted: rewriting one produces churn in the diff this
		// project asks people to read carefully, and says nothing in return.
		if !GoldenIsAsserted(c) {
			parked = append(parked, c.ID)
			continue
		}
		f, ok := Fixtures[c.Fixture]
		if !ok {
			t.Errorf("%s: names fixture %q, which is not declared", c.ID, c.Fixture)
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			// A case that enumerates the realm gets a container of its own,
			// thrown away when the subtest ends. See Case.PristineRealm: the
			// verifier builds a fresh handler per case, so the only recording
			// that reproduces what it will serve is one against a realm no
			// other fixture has touched.
			base, management := shared, sharedManagement
			if c.PristineRealm {
				base, management = startKeycloak(ctx, t)
			}
			// The fixture's steps always go to the main port - see
			// Case.ManagementPort, which refuses a fixture with steps for
			// exactly this reason - and only the case's own request may go
			// elsewhere. Everything downstream of the response uses the base
			// the response came from, so a body or header carrying the server's
			// own URL is masked against the right one. No management body
			// carries an absolute URL today, measured: the index page's two
			// links are relative and the health documents hold none. The
			// symmetry is what matters rather than the current inertness, since
			// the verifier normalises against the one base it has.
			target := RecordTarget(base, management, c)

			// The fixture's own steps are run but never recorded: only the
			// case's response becomes a golden. Recording a step would commit
			// a live token to the repository.
			sess, err := Run(f, base, client.Do)
			if err != nil {
				t.Fatalf("fixture %q: %v", c.Fixture, err)
			}
			vars := sess.Vars
			req, err := buildRequest(target, Expand(c.Request, vars))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			// The case's own request is not one of the fixture's steps, so it
			// needs the session put on it here. Without this a credential POST
			// arrives with no authentication session and Keycloak answers a
			// 400 theme page - which is what the first recording of
			// oidc/authorization/code-flow-redirect wrote down.
			sess.Apply(req)
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
			body, err = normalisePasses(body, target, c, vars)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}

			// Refused here as well as in CI, for the reason recordedHeaders
			// gives for MaskURLTail: loud at the moment of recording rather
			// than a surprise in a diff nobody can read. This is the one call
			// site that stops a binary golden from reaching the tree at all.
			if err := RefuseNonTextBody(body); err != nil {
				t.Fatalf("%v\n"+
					"%s answers a body no golden can hold. Leave it Pending with that as "+
					"its reason - see F161.", err, c.ID)
			}

			headers, err := recordedHeaders(resp.Header, target, c, vars)
			if err != nil {
				t.Fatalf("headers: %v", err)
			}
			g := Golden{
				RequestLine: c.Request.Method + " " + c.Request.Path,
				Status:      resp.StatusCode,
				Headers:     headers,
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
	if len(parked) > 0 {
		sort.Strings(parked)
		t.Logf("left %d Pending goldens alone, because nothing compares them: %v",
			len(parked), parked)
	}
}

// startKeycloak runs the reference server and returns two base URLs - the HTTP
// port and the management interface - and terminates it when t finishes. The
// image tag is the project's pinned compatibility target and must not drift.
//
// It is called once for the shared container and once more per PristineRealm
// case, where the t it is given is the subtest's, so the container lives for
// exactly that one recording.
//
// **The two options are what make the second URL exist.** A default `start-dev`
// listens on 8080 alone: its startup line names one address, and
// /proc/net/tcp6 inside the container holds one listening socket. Neither
// `--health-enabled` nor `--metrics-enabled` is on by default, and either one
// alone brings port 9000 up with only its own endpoints on it - measured on
// four containers on 2026-09-15. Both are set here because the management
// chapter enumerates the surface with both, and because setting them on every
// container is what keeps the management port out of the container regimes: a
// PristineRealm case gets its own container and its own pair of ports without
// this function knowing which case asked.
//
// They are build-time options, so `start-dev` re-augments on startup. Measured
// at roughly a second on top of a seven-second start, which is why this is one
// image and not two.
//
// Setting them changes nothing on 8080 that any golden holds, and that is the
// claim the `make record` diff checked rather than this comment asserting it:
// the run that introduced them moved no file outside the management chapter.
func startKeycloak(ctx context.Context, t *testing.T) (base, management string) {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/keycloak/keycloak:26.7.1",
		Cmd:          []string{"start-dev"},
		ExposedPorts: []string{"8080/tcp", "9000/tcp"},
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			"KC_HEALTH_ENABLED":           "true",
			"KC_METRICS_ENABLED":          "true",
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
	// Two literals rather than a helper taking a string: MappedPort's parameter
	// is nat.Port, and only an untyped constant converts to it without naming
	// the type - which would mean importing github.com/docker/go-connections
	// directly for a two-line saving.
	http8080, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("container port 8080: %v", err)
	}
	http9000, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatalf("container port 9000: %v", err)
	}
	return fmt.Sprintf("http://%s:%s", host, http8080.Port()),
		fmt.Sprintf("http://%s:%s", host, http9000.Port())
}
