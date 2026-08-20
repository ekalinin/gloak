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

// newFixture builds the Gloak handler for a named setup. "bootstrap" is a
// fresh file-backed store with the master realm created - file-backed rather
// than in-memory because tests on in-memory SQLite have passed here while the
// file-backed path was broken.
func newFixture(t *testing.T, name string) http.Handler {
	t.Helper()
	switch name {
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
		k, err := keys.Generate("master")
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return oidc.NewRouter(s, k, testIssuer)
	default:
		t.Fatalf("unknown fixture %q", name)
		return nil
	}
}
