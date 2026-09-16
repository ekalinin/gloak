package conformance

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/account"
	"github.com/ekalinin/gloak/internal/admin"
	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/management"
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
	return oidc.WithKeycloakFallbacks(newFixtureMux(t, state))
}

// newManagementFixture builds Gloak's **second** server for a named starting
// state: the management interface, which is a different server from the one
// above and not a route family on it.
//
// This is what closes F244. The verifier had one handler and one base URL, so a
// management case's request went to Gloak's main mux while its golden had been
// recorded from port 9000 - two servers, measured disagreeing about the same
// request - and Case.ManagementPort refused Implemented so that nothing claimed
// more than that. It now has two, and the refusal is narrowed rather than
// deleted; see managementDefects.
//
// **It takes no state, and that is measured rather than lazy.** Gloak's
// management interface reads no store: the only computed value it publishes is
// whether the process is draining, and the other check is a constant whose
// constancy was measured on the reference server. Nothing a fixture can do
// reaches this handler, which is the same fact Case.ManagementPort's third
// refusal rests on from the recorder's side - a realm, a client, a user and a
// group created on 8080 left /health, /health/live and / byte-identical on 9000
// of the same container.
//
// It took a state and switched on it until a review pointed out the cost. serve
// builds **both** handlers for every case, so a second `switch` over fixture
// states would be a second place every new state has to be added - and it would
// catch nothing, because newFixture runs one line earlier and fatals on an
// unknown state with the same message. A duplicate guard that can only ever fire
// after the real one is maintenance with no consumer.
//
// If a later cut gives this interface a check that reads the store, this has to
// take the fixture's store rather than growing its own, or the health endpoint
// will be reporting on a database no case wrote to.
func newManagementFixture(t *testing.T) http.Handler {
	t.Helper()
	return management.New().Handler()
}

// newFixtureMux is the route table newFixture wraps.
//
// It is split out for TestNoReasonClaimsAServedEndpointIsUnserved, which since
// F184 has to ask **what is registered** rather than what is answered: the
// realm resource dispatcher matches every path under /realms/{realm}, so the
// two fallback bodies no longer tell a served endpoint from an invented one.
func newFixtureMux(t *testing.T, state string) *http.ServeMux {
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
		// All three APIs on one mux, wrapped once, exactly as cmd/gloak
		// composes them - otherwise the suite would verify a handler nobody
		// serves.
		km := keys.NewManager(s)
		mux := http.NewServeMux()
		oidc.Register(mux, s, km, testIssuer)
		admin.Register(mux, s, km, testIssuer)
		account.Register(mux, s, km, testIssuer)
		return mux
	default:
		t.Fatalf("unknown fixture state %q", state)
		return nil
	}
}
