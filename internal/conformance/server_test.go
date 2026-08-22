package conformance

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

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
// against the handler this returns.
func newFixture(t *testing.T, state string) http.Handler {
	t.Helper()
	switch state {
	case "bootstrap":
		ctx := context.Background()
		s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
			t.Fatalf("EnsureMaster: %v", err)
		}
		return oidc.NewRouter(s, keys.NewManager(s), testIssuer)
	default:
		t.Fatalf("unknown fixture state %q", state)
		return nil
	}
}
