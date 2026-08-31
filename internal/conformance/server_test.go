package conformance

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/admin"
	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// testIssuer is the externally visible base URL the handler under test is
// built with. Bodies have it replaced with {{issuer}} before comparison, so
// the value only has to be stable, not equal to the recorder's.
const testIssuer = "http://localhost:8080"

// newFixture builds the Gloak handler for a named starting state.
// "bootstrap" is a fresh file-backed store with the master realm created -
// file-backed rather than in-memory because tests on in-memory SQLite have
// passed here while the file-backed path was broken.
//
// It handles only the state. Whatever requests a fixture runs on top of it to
// reach the state a case measures are Fixture.Steps, executed by RunFixture
// testDSN is a throwaway SQLite file with fsync turned off.
//
// **This is not a performance tweak, it is the difference between a suite that
// finishes and one that does not.** Every case gets a fresh database and
// bootstraps it, and a bootstrap is hundreds of writes; with the default
// synchronous=full each one waits on fsync. On 2026-08-31 CI spent thirty
// minutes inside modernc.org/libc.Xfsync and was killed there, having reported
// the same tree green twice before - the runner's disk was the variable and
// nothing in the output said so.
//
// Durability is meaningless here: the file lives in t.TempDir() for the length
// of one subtest and a crash mid-run loses the whole run anyway. Production is
// untouched; sqlite.Open's own default still applies to everything that is not
// a test.
func testDSN(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "gloak.db") + "?_pragma=synchronous(off)"
}

// against the handler this returns.
func newFixture(t *testing.T, state string) http.Handler {
	t.Helper()
	switch state {
	case "bootstrap":
		ctx := context.Background()
		s, err := sqlite.Open(ctx, testDSN(t))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
			t.Fatalf("EnsureMaster: %v", err)
		}
		// Both APIs on one mux, wrapped once, exactly as cmd/gloak composes
		// them - otherwise the suite would verify a handler nobody serves.
		km := keys.NewManager(s)
		mux := http.NewServeMux()
		oidc.Register(mux, s, km, testIssuer)
		admin.Register(mux, s, km, testIssuer)
		return oidc.WithKeycloakFallbacks(mux)
	default:
		t.Fatalf("unknown fixture state %q", state)
		return nil
	}
}
