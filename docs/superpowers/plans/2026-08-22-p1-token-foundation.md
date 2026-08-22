# P1 token foundation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Gloak issue, parse and revoke tokens the way Keycloak 26.7.1 does, so that the seventeen `Recorded` cases of P1 become `Implemented` and the project's one deliberately red test goes green.

**Architecture:** Realm signing material moves from a per-process `keys.Generate` call into the store, one set per realm, resolved through a `keys.Manager`. A session model lands underneath it. `internal/token` turns a session plus a client into the three measured claim sets; `internal/auth` verifies passwords against the parameters stored on the credential rather than against constants. The four protocol endpoints (`token`, `userinfo`, `token/introspect`, `revoke`) are thin handlers over those two packages, with client authentication shared between them.

**Tech Stack:** Go 1.26, `CGO_ENABLED=0`, `go-jose/v4` for JWS, `golang.org/x/crypto/argon2`, `modernc.org/sqlite` and `jackc/pgx/v5`, `coreos/go-oidc/v3` (added in Task 11, test-only).

**Specs:** `docs/superpowers/specs/2026-08-21-p1-token-foundation-design.md` (scope),
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` (every observable value),
`docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md` (where P1 sits).

## Global constraints

These apply to every task below. They are not repeated per task.

- **Observable values are measured, never remembered.** If a value is not in
  `2026-08-18-keycloak-26.7.1-observed.md` or in a golden under
  `internal/conformance/testdata/golden/`, it has not been measured. Do not invent
  one; either measure it (`make record`, needs Docker) or write down in the code
  comment that it is unmeasured and leave the case `Pending`.
- **`internal/httpx` is the only place a response body is marshalled.** Never write
  JSON from a handler.
- **Response structs declare fields in Keycloak's order.** Never marshal a
  `map[string]any` into a response body: Go sorts map keys and key order is part of
  the contract. (Claims inside a JWT are exempt in the sense that no golden compares
  them, but the same discipline applies - use structs.)
- **A store interface method must be implemented in both drivers** and covered in
  `internal/store/storetest`. Compiling is not proof.
- **`go test ./...` must never need Docker or network.** Anything that does goes
  behind the `docker` build tag.
- **`CGO_ENABLED=0 go build ./...` must work.**
- **Never commit to `main`.** This plan is executed on `feat/p1-token-foundation`.
- Commit messages: `type(scope): subject`, types limited to `feat`, `fix`, `docs`,
  `refactor`, `perf`, `chore`. No `Co-Authored-By` line. No mention of the tooling
  used to write them.
- Code comments in English. Prefer the smallest diff that does the job and preserve
  existing names.
- Environment variables use the `GLOAK_` prefix, never `KC_`.

## How a task's red phase starts

A task that closes conformance cases begins by flipping those cases from `Recorded`
to `Implemented` in `internal/conformance/catalog_oidc_pending.go` and deleting
their `Reason`. `make test` then fails with a byte-exact diff against a real
Keycloak response, and that diff is the task's brief. The task is done when it is
green again.

Until then `make test` has exactly one expected failure,
`TestConformance/oidc/certs/master`. **Task 2 removes it.** From Task 3 onward the
suite is expected to be completely clean between tasks.

## File structure

| File | Responsibility |
|---|---|
| `internal/model/model.go` | add `RealmKey`, `UserSession`, `ClientSession` |
| `internal/store/store.go` | add `KeyRepo`, `SessionRepo`, wire into `Store` |
| `internal/store/{sqlite,postgres}/migrations/0002_realm_key.sql` | key table |
| `internal/store/{sqlite,postgres}/migrations/0003_session.sql` | session tables |
| `internal/store/{sqlite,postgres}/{sqlite,postgres}.go` | the two repositories |
| `internal/store/storetest/conformance.go` | shared behaviour for both |
| `internal/keys/keys.go` | generation and encoding of a realm's three keys |
| `internal/keys/manager.go` | load-or-create per realm, cached, from the store |
| `internal/auth/password.go` | argon2id verification from the stored parameters |
| `internal/token/claims.go` | the three measured claim sets as structs |
| `internal/token/issue.go` | issuing access, ID and refresh tokens |
| `internal/token/parse.go` | parsing and validating them back |
| `internal/oidc/clientauth.go` | client resolution and authentication |
| `internal/oidc/token.go` | `POST .../token`, grant dispatch |
| `internal/oidc/userinfo.go` | `GET POST .../userinfo` |
| `internal/oidc/introspect.go` | `POST .../token/introspect` |
| `internal/oidc/revoke.go` | `POST .../revoke` |
| `internal/httpx/errors.go` | generalise the bearer challenge, add the CSP header |

---

### Task 1: Realm keys in the store

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/store/store.go`
- Create: `internal/store/sqlite/migrations/0002_realm_key.sql`
- Create: `internal/store/postgres/migrations/0002_realm_key.sql`
- Modify: `internal/store/sqlite/sqlite.go`
- Modify: `internal/store/postgres/postgres.go`
- Modify: `internal/store/storetest/conformance.go`

**Interfaces:**
- Produces: `model.RealmKey`, `store.KeyRepo` with
  `Create(ctx context.Context, k *model.RealmKey) error` and
  `ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error)`,
  and `store.Store.Keys() store.KeyRepo`.

- [ ] **Step 1: Write the failing store conformance test**

Append to `RunConformance` in `internal/store/storetest/conformance.go`:

```go
	t.Run("realm keys round-trip and are listed per realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		if err := s.Realms().Create(ctx, other); err != nil {
			t.Fatalf("Realms().Create(other): %v", err)
		}
		want := &model.RealmKey{
			ID: model.NewID(), RealmID: realm.ID, Algorithm: "RS256", Use: "sig",
			PrivateKey: []byte{1, 2, 3}, Certificate: []byte{4, 5, 6}, CreatedAt: 1,
		}
		if err := s.Keys().Create(ctx, want); err != nil {
			t.Fatalf("Keys().Create: %v", err)
		}
		hmac := &model.RealmKey{
			ID: model.NewID(), RealmID: realm.ID, Algorithm: "HS512",
			PrivateKey: []byte{7, 8, 9}, CreatedAt: 2,
		}
		if err := s.Keys().Create(ctx, hmac); err != nil {
			t.Fatalf("Keys().Create(hmac): %v", err)
		}
		if err := s.Keys().Create(ctx, &model.RealmKey{
			ID: model.NewID(), RealmID: other.ID, Algorithm: "RS256", Use: "sig",
			PrivateKey: []byte{9}, CreatedAt: 3,
		}); err != nil {
			t.Fatalf("Keys().Create(other realm): %v", err)
		}

		got, err := s.Keys().ListByRealm(ctx, realm.ID)

		if err != nil {
			t.Fatalf("ListByRealm: %v", err)
		}
		// Two keys, and the second realm's key is not among them: a key set
		// leaking across realms is the bug this asserts against.
		if len(got) != 2 {
			t.Fatalf("want 2 keys for master, got %d", len(got))
		}
		byAlg := map[string]*model.RealmKey{}
		for _, k := range got {
			byAlg[k.Algorithm] = k
		}
		if rs := byAlg["RS256"]; rs == nil || rs.Use != "sig" ||
			string(rs.PrivateKey) != "\x01\x02\x03" || string(rs.Certificate) != "\x04\x05\x06" {
			t.Fatalf("RS256 key lost its bytes: %+v", rs)
		}
		if hs := byAlg["HS512"]; hs == nil || len(hs.Certificate) != 0 {
			t.Fatalf("HS512 key round-trip wrong: %+v", hs)
		}
	})

	t.Run("a realm holds one key per algorithm", func(t *testing.T) {
		// Two processes racing to generate a realm's keys must not produce two
		// RS256 keys: the kid published in the JWKS would then depend on which
		// row was read back.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		first := &model.RealmKey{ID: model.NewID(), RealmID: realm.ID,
			Algorithm: "RS256", Use: "sig", PrivateKey: []byte{1}, CreatedAt: 1}
		if err := s.Keys().Create(ctx, first); err != nil {
			t.Fatalf("first Create: %v", err)
		}

		err := s.Keys().Create(ctx, &model.RealmKey{ID: model.NewID(), RealmID: realm.ID,
			Algorithm: "RS256", Use: "sig", PrivateKey: []byte{2}, CreatedAt: 2})

		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/store/...`
Expected: compile failure - `s.Keys undefined`, `model.RealmKey undefined`.

- [ ] **Step 3: Add the model type**

Append to `internal/model/model.go`:

```go
// RealmKey is one of a realm's signing keys, persisted so the kid a client
// caches survives a restart and so two replicas publish the same key set.
// Algorithm is RS256, RSA-OAEP or HS512; Use is "sig" or "enc" and is empty
// for the HMAC key, which is never published. PrivateKey holds PKCS#8 DER for
// the RSA keys and the raw secret for HS512; Certificate holds the self-signed
// DER published as x5c, and is empty for HS512.
type RealmKey struct {
	ID          string
	RealmID     string
	Algorithm   string
	Use         string
	PrivateKey  []byte
	Certificate []byte
	CreatedAt   int64
}
```

- [ ] **Step 4: Add the repository interface**

In `internal/store/store.go`, add `Keys() KeyRepo` to the `Store` interface and:

```go
// KeyRepo stores a realm's signing material. There is no update method: a key
// is created once and read back, and rotation - which Keycloak models as a
// second active key rather than a mutation - is not P1.
type KeyRepo interface {
	Create(ctx context.Context, k *model.RealmKey) error
	ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error)
}
```

- [ ] **Step 5: Write both migrations**

`internal/store/sqlite/migrations/0002_realm_key.sql`:

```sql
CREATE TABLE realm_key (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    key_use     TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    certificate BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (realm_id, algorithm)
);
```

`internal/store/postgres/migrations/0002_realm_key.sql`:

```sql
CREATE TABLE realm_key (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    key_use     TEXT NOT NULL DEFAULT '',
    private_key BYTEA NOT NULL,
    certificate BYTEA NOT NULL,
    created_at  BIGINT NOT NULL,
    UNIQUE (realm_id, algorithm)
);
```

The column is `key_use`, not `use`: `USE` is a reserved word in several dialects
and quoting it in every query is a trap waiting for the next driver.

- [ ] **Step 6: Implement the SQLite repository**

In `internal/store/sqlite/sqlite.go`, add `func (s *Store) Keys() store.KeyRepo { return &keyRepo{s.db} }`
next to the other four, and:

```go
type keyRepo struct{ db *sql.DB }

func (r *keyRepo) Create(ctx context.Context, m *model.RealmKey) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm_key (id, realm_id, algorithm, key_use, private_key, certificate, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.RealmID, m.Algorithm, m.Use, m.PrivateKey, m.Certificate, m.CreatedAt)
	return classify(err)
}

func (r *keyRepo) ListByRealm(ctx context.Context, realmID string) ([]*model.RealmKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, realm_id, algorithm, key_use, private_key, certificate, created_at
		 FROM realm_key WHERE realm_id = ? ORDER BY algorithm`, realmID)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.RealmKey
	for rows.Next() {
		m, err := scanRealmKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}

func scanRealmKey(row scanner) (*model.RealmKey, error) {
	m := &model.RealmKey{}
	if err := row.Scan(&m.ID, &m.RealmID, &m.Algorithm, &m.Use,
		&m.PrivateKey, &m.Certificate, &m.CreatedAt); err != nil {
		return nil, classify(err)
	}
	return m, nil
}
```

- [ ] **Step 7: Implement the Postgres repository**

The same, mirrored: `pool.Exec`/`pool.Query`, `$1`-style placeholders, and
`func (s *Store) Keys() store.KeyRepo { return &keyRepo{s.pool} }`. Copy the
structure of `roleRepo` in that file so the two drivers stay method-for-method
identical.

- [ ] **Step 8: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/store/...`
Expected: PASS.

Run: `go test -tags docker ./internal/store/postgres/`
Expected: PASS. This is the only evidence the two drivers agree; do not skip it.
If Docker is unavailable, say so explicitly in the task report rather than
recording the task as verified.

- [ ] **Step 9: Commit**

```bash
git add internal/model internal/store
git commit -m "feat(store): persist a realm's signing keys"
```

---

### Task 2: One key set per realm, two keys published

**Files:**
- Modify: `internal/keys/keys.go`
- Create: `internal/keys/manager.go`
- Create: `internal/keys/manager_test.go`
- Modify: `internal/keys/keys_test.go`
- Modify: `internal/oidc/discovery.go` (`jwksFor`)
- Modify: `internal/oidc/router.go`
- Modify: `internal/oidc/router_test.go`, `internal/oidc/discovery_test.go`
- Modify: `internal/conformance/server_test.go`
- Modify: `internal/conformance/record_test.go` if it constructs a router
- Modify: `cmd/gloak/main.go`
- Modify: `AGENTS.md`, `README.md`, `docs/superpowers/specs/2026-08-18-gloak-followups.md`

**Interfaces:**
- Consumes: `store.KeyRepo` from Task 1.
- Produces:
  - `keys.RealmKeys` gains `EncKeyID string`, `EncCertificateDER() []byte` and
    `HMACSecret() []byte`. The last one exists because verifying a refresh token
    needs the secret; it stays out of `JWKS()` and out of every response body.
  - `keys.NewManager(s store.Store) *keys.Manager` and
    `(*Manager).ForRealm(ctx context.Context, realm *model.Realm) (*RealmKeys, error)`.
  - `oidc.NewRouter(s store.Store, m *keys.Manager, issuerBase string) http.Handler`.

- [ ] **Step 1: Write the failing manager test**

Create `internal/keys/manager_test.go`:

```go
package keys_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newStore(t *testing.T) (store.Store, *model.Realm) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	r := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
	if err := s.Realms().Create(ctx, r); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	return s, r
}

func TestManagerKeepsKidAcrossRestarts(t *testing.T) {
	// F5: the kid used to change on every process start, invalidating every
	// cached JWKS a client held.
	s, realm := newStore(t)
	ctx := context.Background()

	first, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("first ForRealm: %v", err)
	}
	// A second Manager is a second process: same store, no shared cache.
	second, err := keys.NewManager(s).ForRealm(ctx, realm)
	if err != nil {
		t.Fatalf("second ForRealm: %v", err)
	}

	if first.RSAKeyID != second.RSAKeyID {
		t.Errorf("RSA kid changed across restarts: %q then %q", first.RSAKeyID, second.RSAKeyID)
	}
	if first.EncKeyID != second.EncKeyID {
		t.Errorf("encryption kid changed across restarts: %q then %q", first.EncKeyID, second.EncKeyID)
	}
	if first.HMACKeyID != second.HMACKeyID {
		t.Errorf("HMAC kid changed across restarts: %q then %q", first.HMACKeyID, second.HMACKeyID)
	}
}

func TestManagerIsolatesRealms(t *testing.T) {
	s, master := newStore(t)
	ctx := context.Background()
	other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
	if err := s.Realms().Create(ctx, other); err != nil {
		t.Fatalf("Realms().Create: %v", err)
	}
	m := keys.NewManager(s)

	a, err := m.ForRealm(ctx, master)
	if err != nil {
		t.Fatalf("ForRealm(master): %v", err)
	}
	b, err := m.ForRealm(ctx, other)
	if err != nil {
		t.Fatalf("ForRealm(other): %v", err)
	}

	if a.RSAKeyID == b.RSAKeyID {
		t.Fatal("two realms share one signing key")
	}
}

func TestManagerPublishesSigAndEncButNotHMAC(t *testing.T) {
	s, realm := newStore(t)

	k, err := keys.NewManager(s).ForRealm(context.Background(), realm)
	if err != nil {
		t.Fatalf("ForRealm: %v", err)
	}

	set := k.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 published keys, got %d", len(set.Keys))
	}
	byUse := map[string]string{}
	for _, key := range set.Keys {
		byUse[key.Use] = key.Algorithm
	}
	if byUse["sig"] != "RS256" || byUse["enc"] != "RSA-OAEP" {
		t.Fatalf("published algorithms wrong: %+v", byUse)
	}
	for _, key := range set.Keys {
		if key.KeyID == k.HMACKeyID {
			t.Fatal("the HMAC key is published; it signs refresh tokens and must not be")
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/keys/`
Expected: compile failure - `undefined: keys.NewManager`.

- [ ] **Step 3: Extend `RealmKeys` with the encryption key**

In `internal/keys/keys.go`, add `encKey *rsa.PrivateKey`, `encCertDER []byte` and
`EncKeyID string` to `RealmKeys`; have `Generate` produce them the same way it
produces the signing pair (2048-bit RSA, `selfSign(key, subjectCN)`); and rewrite
`JWKS` to publish both:

```go
// JWKS returns the public key set served at
// /realms/{realm}/protocol/openid-connect/certs. A live master realm publishes
// two keys - RS256/sig and RSA-OAEP/enc - see the "Certificate endpoint"
// section of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
// The HMAC key is never published: it signs refresh tokens, which clients
// treat as opaque.
func (k *RealmKeys) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: k.rsaKey.Public(), KeyID: k.RSAKeyID, Algorithm: string(jose.RS256), Use: "sig"},
		{Key: k.encKey.Public(), KeyID: k.EncKeyID, Algorithm: string(jose.RSA_OAEP), Use: "enc"},
	}}
}

// CertificateDER is the signing key's certificate, published as x5c on the
// sig entry. EncCertificateDER is the encryption key's.
func (k *RealmKeys) EncCertificateDER() []byte { return k.encCertDER }
```

Parsing a refresh token needs the HMAC secret, so add an accessor for it:

```go
// HMACSecret is the HS512 secret, needed to verify a refresh token this realm
// issued. It is deliberately not exported through JWKS or any response body -
// see the package doc and internal/keys' row in AGENTS.md's boundary table.
func (k *RealmKeys) HMACSecret() []byte { return k.hmacKey }
```

- [ ] **Step 4: Write the manager**

Create `internal/keys/manager.go`:

```go
package keys

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// Algorithm names as they are stored, and as the JWKS publishes them.
const (
	algRS256   = "RS256"
	algRSAOAEP = "RSA-OAEP"
	algHS512   = "HS512"
)

// Manager resolves a realm's key set, generating and persisting one the first
// time a realm is asked for. Keys are cached in memory per realm: they are
// immutable once created, so a cached set can never go stale.
//
// Before this existed, keys.Generate ran once per process and one set served
// every realm - follow-up F5. The kid therefore changed on every restart,
// invalidating every cached JWKS a client held, and two replicas published
// different keys for the same realm.
type Manager struct {
	store store.Store

	mu     sync.Mutex
	cached map[string]*RealmKeys // by realm ID
}

func NewManager(s store.Store) *Manager {
	return &Manager{store: s, cached: make(map[string]*RealmKeys)}
}

// ForRealm returns realm's key set, creating it if the realm has none.
func (m *Manager) ForRealm(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if k, ok := m.cached[realm.ID]; ok {
		return k, nil
	}
	k, err := m.load(ctx, realm)
	if err != nil {
		return nil, err
	}
	if k == nil {
		if k, err = m.create(ctx, realm); err != nil {
			return nil, err
		}
	}
	m.cached[realm.ID] = k
	return k, nil
}

// load rebuilds a key set from the store, or returns nil when the realm has no
// keys yet. A realm holding some but not all three is a corrupt state rather
// than a partial one: it is reported, not silently completed, because
// generating the missing key would publish a kid no client has ever seen while
// leaving the others alone.
func (m *Manager) load(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	rows, err := m.store.Keys().ListByRealm(ctx, realm.ID)
	if err != nil {
		return nil, fmt.Errorf("keys: list realm keys: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	k := &RealmKeys{}
	for _, row := range rows {
		switch row.Algorithm {
		case algRS256:
			key, err := x509.ParsePKCS8PrivateKey(row.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("keys: parse signing key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("keys: stored signing key is not RSA")
			}
			k.RSAKeyID, k.rsaKey, k.certDER = row.ID, rsaKey, row.Certificate
		case algRSAOAEP:
			key, err := x509.ParsePKCS8PrivateKey(row.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("keys: parse encryption key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("keys: stored encryption key is not RSA")
			}
			k.EncKeyID, k.encKey, k.encCertDER = row.ID, rsaKey, row.Certificate
		case algHS512:
			k.HMACKeyID, k.hmacKey = row.ID, row.PrivateKey
		}
	}
	if k.rsaKey == nil || k.encKey == nil || k.hmacKey == nil {
		return nil, fmt.Errorf("keys: realm %q has an incomplete key set", realm.Name)
	}
	return k, nil
}

// create generates a set and persists it. A concurrent creator is handled by
// the unique constraint on (realm_id, algorithm): on conflict the set another
// process just wrote is read back, so both end up publishing the same kid.
func (m *Manager) create(ctx context.Context, realm *model.Realm) (*RealmKeys, error) {
	k, err := Generate(realm.Name)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	rows, err := k.rows(realm.ID, now)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := m.store.Keys().Create(ctx, row); err != nil {
			if errors.Is(err, store.ErrConflict) {
				existing, lerr := m.load(ctx, realm)
				if lerr != nil {
					return nil, lerr
				}
				if existing == nil {
					return nil, fmt.Errorf("keys: realm %q lost its keys mid-creation", realm.Name)
				}
				return existing, nil
			}
			return nil, fmt.Errorf("keys: store realm key: %w", err)
		}
	}
	return k, nil
}

// rows encodes a generated set for storage: PKCS#8 DER for the two RSA keys,
// the raw secret for HS512. The key IDs are the row IDs, so a kid read back
// from the store is the same kid that was published before the restart.
func (k *RealmKeys) rows(realmID string, now int64) ([]*model.RealmKey, error) {
	sigDER, err := x509.MarshalPKCS8PrivateKey(k.rsaKey)
	if err != nil {
		return nil, fmt.Errorf("keys: encode signing key: %w", err)
	}
	encDER, err := x509.MarshalPKCS8PrivateKey(k.encKey)
	if err != nil {
		return nil, fmt.Errorf("keys: encode encryption key: %w", err)
	}
	return []*model.RealmKey{
		{ID: k.RSAKeyID, RealmID: realmID, Algorithm: algRS256, Use: "sig",
			PrivateKey: sigDER, Certificate: k.certDER, CreatedAt: now},
		{ID: k.EncKeyID, RealmID: realmID, Algorithm: algRSAOAEP, Use: "enc",
			PrivateKey: encDER, Certificate: k.encCertDER, CreatedAt: now},
		{ID: k.HMACKeyID, RealmID: realmID, Algorithm: algHS512,
			PrivateKey: k.hmacKey, Certificate: []byte{}, CreatedAt: now},
	}, nil
}
```

Add `"crypto/rsa"` to the import list.

- [ ] **Step 5: Run the manager tests**

Run: `CGO_ENABLED=0 go test ./internal/keys/`
Expected: PASS.

- [ ] **Step 6: Publish both keys from `jwksFor`**

Rewrite `jwksFor` in `internal/oidc/discovery.go` to build one `jwksKey` per
published JWK rather than hard-coding index 0. Extract the per-entry work into a
helper so the two entries cannot drift:

```go
// jwksFor builds the published key set from a realm's signing material. The
// live master realm publishes two entries, RS256/sig and RSA-OAEP/enc; see the
// "Certificate endpoint" section of the observed-behaviour document and
// internal/conformance/testdata/golden/oidc/certs/master.http.
func jwksFor(k *keys.RealmKeys) jwksDocument {
	set := k.JWKS()
	certs := map[string][]byte{
		k.RSAKeyID: k.CertificateDER(),
		k.EncKeyID: k.EncCertificateDER(),
	}
	doc := jwksDocument{Keys: make([]jwksKey, 0, len(set.Keys))}
	for _, key := range set.Keys {
		doc.Keys = append(doc.Keys, jwksEntry(key, certs[key.KeyID]))
	}
	return doc
}

// jwksEntry encodes one published key. The base64 variants are not uniform
// across the entry and that is measured, not an oversight: x5c is standard
// base64 with padding because it is a certificate, while x5t, x5t#S256, n and
// e are base64url without padding per RFC 7517.
func jwksEntry(key jose.JSONWebKey, certDER []byte) jwksKey {
	pub := key.Key.(*rsa.PublicKey)
	sha1Sum := sha1.Sum(certDER)
	sha256Sum := sha256.Sum256(certDER)
	enc := base64.RawURLEncoding
	return jwksKey{
		Kid:     key.KeyID,
		Kty:     "RSA",
		Alg:     key.Algorithm,
		Use:     key.Use,
		X5c:     []string{base64.StdEncoding.EncodeToString(certDER)},
		X5t:     enc.EncodeToString(sha1Sum[:]),
		X5tS256: enc.EncodeToString(sha256Sum[:]),
		N:       enc.EncodeToString(pub.N.Bytes()),
		E:       enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
```

Import `jose "github.com/go-jose/go-jose/v4"` in that file.

- [ ] **Step 7: Resolve keys per realm in the router**

In `internal/oidc/router.go`:

- change the `handler` field `keys *keys.RealmKeys` to `keys *keys.Manager`;
- change `NewRouter`'s second parameter to `*keys.Manager`;
- change `resolveRealm` to return the realm itself, since every new handler needs
  its ID and its lifespans:

```go
// resolveRealm looks up the realm named in the request path. On
// store.ErrNotFound it writes Keycloak's measured 404 shape and returns nil;
// callers must stop handling the request in that case.
func (h *handler) resolveRealm(w http.ResponseWriter, r *http.Request) *model.Realm {
	realm, err := h.store.Realms().ByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteMessageError(w, http.StatusNotFound, "Realm does not exist")
			return nil
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return realm
}

// realmKeys resolves the realm's key set, writing the 500 shape and returning
// nil when it cannot.
func (h *handler) realmKeys(w http.ResponseWriter, r *http.Request, realm *model.Realm) *keys.RealmKeys {
	k, err := h.keys.ForRealm(r.Context(), realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil
	}
	return k
}
```

Update `discovery`, `certs` and `realmInfo` to the new signatures. `discovery` uses
`realm.Name`; `certs` and `realmInfo` additionally call `realmKeys`.

- [ ] **Step 8: Update every caller**

- `cmd/gloak/main.go`: replace `keys.Generate("master")` with
  `keys.NewManager(s)` and pass it to `oidc.NewRouter`. The generation now happens
  lazily on first request, which is also what makes it work for realms created
  later.
- `internal/conformance/server_test.go`: same change inside `newFixture`.
- `internal/oidc/router_test.go` and `discovery_test.go`: same change wherever a
  router is built. Where a test needs the realm row, create it through
  `bootstrap.EnsureMaster` as the conformance fixture does.

- [ ] **Step 9: Run everything, including the case this closes**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS, with **no failures at all** - `TestConformance/oidc/certs/master`
was the project's one sanctioned red test and this task is what closes it.

If it still fails, read the diff: the two entries' field order, the base64
variants, and `Unordered: ["keys"]` sorting after normalisation are the three
things it is sensitive to.

- [ ] **Step 10: Update the documents that promised a red test**

- `AGENTS.md`, "Build and test": replace the paragraph saying
  `TestConformance/oidc/certs/master` fails deliberately with a statement that
  `make test` is clean and **any** failure is a regression.
- `README.md`: same, in the "Conformance against a live Keycloak" section, and drop
  the sentence in "Status" about the one known exception.
- `docs/superpowers/specs/2026-08-18-gloak-followups.md`: mark F5 closed, naming
  this task and the two tests that guard it.

- [ ] **Step 11: Commit**

```bash
git add internal/keys internal/oidc internal/conformance cmd AGENTS.md README.md docs
git commit -m "feat(keys): give each realm a persisted key set with sig and enc keys"
```

---

### Task 3: Password verification

**Files:**
- Create: `internal/auth/password.go`
- Create: `internal/auth/password_test.go`

**Interfaces:**
- Produces: `auth.VerifyPassword(cred *model.Credential, password string) error`,
  and the sentinel `auth.ErrInvalidCredential`.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/password_test.go`:

```go
package auth_test

import (
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/auth"
	"github.com/ekalinin/gloak/internal/model"
)

// credential builds a stored password credential the way internal/bootstrap
// does, with the argon2id parameters measured on Keycloak 26.7.1: 5 iterations,
// 7168 KiB, parallelism 1, 32-byte output, and values stored as arrays of
// strings.
func credential(password string, iterations int, memory, parallelism, length string) *model.Credential {
	salt := []byte("saltsaltsaltsalt")
	hash := argon2.IDKey([]byte(password), salt, 5, 7168, 1, 32)
	return &model.Credential{
		ID: model.NewID(), UserID: model.NewID(), Type: "password",
		Algorithm: "argon2", HashIterations: iterations,
		AdditionalParameters: map[string][]string{
			"hashLength": {length}, "memory": {memory},
			"type": {"id"}, "version": {"1.3"}, "parallelism": {parallelism},
		},
		Salt: salt, HashValue: hash,
	}
}

func TestVerifyPasswordAcceptsTheStoredPassword(t *testing.T) {
	c := credential("admin", 5, "7168", "1", "32")

	if err := auth.VerifyPassword(c, "admin"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
}

func TestVerifyPasswordRejectsAWrongPassword(t *testing.T) {
	c := credential("admin", 5, "7168", "1", "32")

	err := auth.VerifyPassword(c, "wrong-password")

	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("want ErrInvalidCredential, got %v", err)
	}
}

func TestVerifyPasswordReadsParametersFromTheCredential(t *testing.T) {
	// The parameters in internal/bootstrap are the ones used to *create* a
	// password. Verifying against those constants instead of against what is
	// stored would lock out every existing account the day they change.
	c := credential("admin", 5, "7168", "1", "32")
	c.HashIterations = 6 // no longer the constant bootstrap used

	err := auth.VerifyPassword(c, "admin")

	if !errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("iterations were ignored: %v", err)
	}
}

func TestVerifyPasswordRejectsAnUnknownAlgorithm(t *testing.T) {
	c := credential("admin", 5, "7168", "1", "32")
	c.Algorithm = "pbkdf2-sha512"

	err := auth.VerifyPassword(c, "admin")

	if err == nil || errors.Is(err, auth.ErrInvalidCredential) {
		t.Fatalf("an unsupported algorithm must be an error of its own, got %v", err)
	}
}

func TestVerifyPasswordRejectsAnUnknownArgon2Variant(t *testing.T) {
	// Only argon2id is supported. Silently treating argon2i as argon2id would
	// accept a hash it did not produce.
	c := credential("admin", 5, "7168", "1", "32")
	c.AdditionalParameters["type"] = []string{"i"}

	if err := auth.VerifyPassword(c, "admin"); err == nil {
		t.Fatal("argon2i was accepted as argon2id")
	}
}

func TestVerifyPasswordRejectsAMissingParameter(t *testing.T) {
	c := credential("admin", 5, "7168", "1", "32")
	delete(c.AdditionalParameters, "memory")

	if err := auth.VerifyPassword(c, "admin"); err == nil {
		t.Fatal("a credential with no memory parameter verified anyway")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/auth/`
Expected: `no Go files` / `undefined: auth.VerifyPassword`.

- [ ] **Step 3: Implement it**

Create `internal/auth/password.go`:

```go
// Package auth verifies stored credentials. It is deliberately separate from
// internal/bootstrap, which owns the parameters used to *create* a password:
// verification must work with whatever is stored, including credentials
// written by an older build or imported from elsewhere.
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"

	"github.com/ekalinin/gloak/internal/model"
)

// ErrInvalidCredential means the password did not match. It is deliberately
// the same error for "wrong password" and for "user has no password", so
// callers cannot turn the distinction into an account-enumeration oracle.
var ErrInvalidCredential = errors.New("auth: invalid credential")

// VerifyPassword checks password against a stored credential, using the
// parameters recorded on the credential rather than any constant. Keycloak
// stores them as arrays of strings - see the "Password hashing" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md - so every one
// of them is parsed out of a []string here.
func VerifyPassword(cred *model.Credential, password string) error {
	if cred == nil {
		return ErrInvalidCredential
	}
	if cred.Algorithm != "argon2" {
		return fmt.Errorf("auth: unsupported password algorithm %q", cred.Algorithm)
	}

	variant, err := param(cred, "type")
	if err != nil {
		return err
	}
	if variant != "id" {
		return fmt.Errorf("auth: unsupported argon2 variant %q", variant)
	}
	memory, err := uintParam(cred, "memory")
	if err != nil {
		return err
	}
	parallelism, err := uintParam(cred, "parallelism")
	if err != nil {
		return err
	}
	length, err := uintParam(cred, "hashLength")
	if err != nil {
		return err
	}
	if cred.HashIterations <= 0 {
		return fmt.Errorf("auth: credential has no iteration count")
	}

	got := argon2.IDKey([]byte(password), cred.Salt,
		uint32(cred.HashIterations), memory, uint8(parallelism), length)

	// Constant time: a length-dependent early return would leak the output
	// size, and a byte-by-byte compare would leak the hash itself.
	if subtle.ConstantTimeCompare(got, cred.HashValue) != 1 {
		return ErrInvalidCredential
	}
	return nil
}

// param returns the single value of a credential parameter. An absent or empty
// parameter is an error rather than a zero value: verifying with a silently
// defaulted cost parameter would accept a hash nobody produced.
func param(cred *model.Credential, name string) (string, error) {
	values := cred.AdditionalParameters[name]
	if len(values) == 0 {
		return "", fmt.Errorf("auth: credential has no %s parameter", name)
	}
	return values[0], nil
}

func uintParam(cred *model.Credential, name string) (uint32, error) {
	raw, err := param(cred, name)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("auth: %s parameter %q is not a number: %w", name, raw, err)
	}
	return uint32(v), nil
}
```

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/auth/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth
git commit -m "feat(auth): verify argon2id passwords against the stored parameters"
```

---

### Task 4: Sessions in the store

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/store/store.go`
- Create: `internal/store/sqlite/migrations/0003_session.sql`
- Create: `internal/store/postgres/migrations/0003_session.sql`
- Modify: `internal/store/sqlite/sqlite.go`, `internal/store/postgres/postgres.go`
- Modify: `internal/store/storetest/conformance.go`

**Interfaces:**
- Produces: `model.UserSession`, `model.ClientSession`, `store.SessionRepo`:

```go
type SessionRepo interface {
	CreateUserSession(ctx context.Context, s *model.UserSession) error
	UserSessionByID(ctx context.Context, realmID, id string) (*model.UserSession, error)
	TouchUserSession(ctx context.Context, id string, lastRefresh int64) error
	DeleteUserSession(ctx context.Context, realmID, id string) error
	CreateClientSession(ctx context.Context, s *model.ClientSession) error
	ClientSession(ctx context.Context, userSessionID, clientID string) (*model.ClientSession, error)
}
```

- [ ] **Step 1: Write the failing store conformance test**

Append to `RunConformance`:

```go
	t.Run("sessions round-trip and cascade", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "admin-cli", Enabled: true}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		us := &model.UserSession{ID: model.NewID(), RealmID: realm.ID, UserID: u.ID,
			Username: "admin", StartedAt: 1000, LastRefresh: 1000, ExpiresAt: 2000}
		if err := s.Sessions().CreateUserSession(ctx, us); err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}
		cs := &model.ClientSession{ID: model.NewID(), UserSessionID: us.ID,
			ClientID: c.ID, Scope: "openid email profile", StartedAt: 1000}
		if err := s.Sessions().CreateClientSession(ctx, cs); err != nil {
			t.Fatalf("CreateClientSession: %v", err)
		}

		got, err := s.Sessions().UserSessionByID(ctx, realm.ID, us.ID)
		if err != nil {
			t.Fatalf("UserSessionByID: %v", err)
		}
		if got.Username != "admin" || got.UserID != u.ID || got.ExpiresAt != 2000 {
			t.Fatalf("user session round-trip wrong: %+v", got)
		}
		gotClient, err := s.Sessions().ClientSession(ctx, us.ID, c.ID)
		if err != nil {
			t.Fatalf("ClientSession: %v", err)
		}
		if gotClient.Scope != "openid email profile" {
			t.Fatalf("client session scope lost: %+v", gotClient)
		}

		if err := s.Sessions().TouchUserSession(ctx, us.ID, 1500); err != nil {
			t.Fatalf("TouchUserSession: %v", err)
		}
		got, err = s.Sessions().UserSessionByID(ctx, realm.ID, us.ID)
		if err != nil {
			t.Fatalf("UserSessionByID after touch: %v", err)
		}
		if got.LastRefresh != 1500 {
			t.Fatalf("LastRefresh not updated: %+v", got)
		}

		// Revocation deletes the user session; the client sessions hanging off
		// it must go with it, or a refresh token would still find its scope.
		if err := s.Sessions().DeleteUserSession(ctx, realm.ID, us.ID); err != nil {
			t.Fatalf("DeleteUserSession: %v", err)
		}
		if _, err := s.Sessions().UserSessionByID(ctx, realm.ID, us.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound after delete, got %v", err)
		}
		if _, err := s.Sessions().ClientSession(ctx, us.ID, c.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("client session outlived its user session: %v", err)
		}
	})

	t.Run("a session is not visible from another realm", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		other := &model.Realm{ID: model.NewID(), Name: "other", Enabled: true}
		for _, r := range []*model.Realm{realm, other} {
			if err := s.Realms().Create(ctx, r); err != nil {
				t.Fatalf("Realms().Create: %v", err)
			}
		}
		u := &model.User{ID: model.NewID(), RealmID: realm.ID, Username: "admin", Enabled: true}
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatalf("Users().Create: %v", err)
		}
		us := &model.UserSession{ID: model.NewID(), RealmID: realm.ID, UserID: u.ID,
			Username: "admin", StartedAt: 1, LastRefresh: 1, ExpiresAt: 2}
		if err := s.Sessions().CreateUserSession(ctx, us); err != nil {
			t.Fatalf("CreateUserSession: %v", err)
		}

		_, err := s.Sessions().UserSessionByID(ctx, other.ID, us.ID)

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a session leaked across realms: %v", err)
		}
	})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/store/...`
Expected: compile failure - `s.Sessions undefined`.

- [ ] **Step 3: Add the model types**

```go
// UserSession is an SSO session: one login, however many clients use it. Its
// ID is what a token carries as sid and what the token response returns as
// session_state. Timestamps are Unix milliseconds.
type UserSession struct {
	ID          string
	RealmID     string
	UserID      string
	Username    string
	StartedAt   int64
	LastRefresh int64
	ExpiresAt   int64
}

// ClientSession is one client's participation in a UserSession. Scope is the
// space-separated scope granted to that client, which is what a refresh knows
// to re-issue.
type ClientSession struct {
	ID            string
	UserSessionID string
	ClientID      string // the client's internal UUID, not its clientId
	Scope         string
	StartedAt     int64
}
```

- [ ] **Step 4: Add the interface, both migrations and both drivers**

`internal/store/sqlite/migrations/0003_session.sql`:

```sql
CREATE TABLE user_session (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    username     TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    last_refresh INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

CREATE TABLE client_session (
    id              TEXT PRIMARY KEY,
    user_session_id TEXT NOT NULL REFERENCES user_session(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    scope           TEXT NOT NULL DEFAULT '',
    started_at      INTEGER NOT NULL,
    UNIQUE (user_session_id, client_id)
);
```

The Postgres file is the same with `BIGINT` in place of `INTEGER`.

The cascade from `user_session` to `client_session` is what the "cascade" half of
the test above asserts. SQLite only enforces it because `withForeignKeysPragma`
turns foreign keys on; that pragma is already there and must not be removed.

The two repositories follow the shape of `keyRepo` from Task 1.
`DeleteUserSession` and `TouchUserSession` return `store.ErrNotFound` when they
affect no row - check `RowsAffected()` (SQLite) / `CommandTag().RowsAffected()`
(pgx), because neither driver reports a no-op delete as an error.

- [ ] **Step 5: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/store/...` then
`go test -tags docker ./internal/store/postgres/`
Expected: PASS on both. Report explicitly if Docker was unavailable.

- [ ] **Step 6: Commit**

```bash
git add internal/model internal/store
git commit -m "feat(store): persist user and client sessions"
```

---

### Task 5: Issuing and parsing tokens

**Files:**
- Create: `internal/token/claims.go`
- Create: `internal/token/issue.go`
- Create: `internal/token/parse.go`
- Create: `internal/token/token_test.go`

**Interfaces:**
- Consumes: `keys.RealmKeys` (Task 2), `model.UserSession`, `model.ClientSession`.
- Produces:

```go
// Issuer turns a session into the three tokens.
type Issuer struct {
	Keys       *keys.RealmKeys
	Issuer     string // the realm's issuer URL, e.g. http://localhost:8080/realms/master
	Now        func() time.Time // nil means time.Now
}

type Request struct {
	Client        *model.Client
	UserSession   *model.UserSession
	Scope         string // space-separated, as granted
	AccessLife    time.Duration
	RefreshLife   time.Duration
	IncludeIDToken bool
}

type Set struct {
	AccessToken  string
	IDToken      string // empty unless the openid scope was granted
	RefreshToken string
}

func (i *Issuer) Issue(r Request) (Set, error)

// Parsed is what a token carries once verified.
type Parsed struct {
	Type      string // Bearer, ID or Refresh
	Subject   string
	SessionID string
	ClientID  string // azp
	Scope     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Lightweight bool
}

func ParseAccess(k *keys.RealmKeys, issuer, raw string, now time.Time) (*Parsed, error)
func ParseRefresh(k *keys.RealmKeys, issuer, raw string, now time.Time) (*Parsed, error)

var ErrInvalidToken = errors.New("token: invalid")
var ErrExpiredToken = errors.New("token: expired")
```

- [ ] **Step 1: Write the failing test**

Create `internal/token/token_test.go` covering, one test function each:

1. `TestAccessTokenCarriesTheMeasuredClaimSet` - issue for an ordinary client,
   parse the JWS payload with `encoding/json` into a `map[string]json.RawMessage`,
   and assert the key set is exactly
   `acr, allowed-origins, aud, azp, email_verified, exp, iat, iss, jti,
   preferred_username, realm_access, resource_access, scope, sid, sub, typ`
   with `typ == "Bearer"` and `aud` a JSON array.
2. `TestLightweightAccessTokenDropsSubAndAud` - a client carrying
   `client.use.lightweight.access.token.enabled = "true"` yields exactly
   `azp, exp, iat, iss, jti, scope, sid, typ`.
3. `TestIDTokenAudIsAStringNotAnArray` - assert `aud` unmarshals into a `string`,
   and that the claim set is the measured ID-token set with `typ == "ID"`.
4. `TestRefreshTokenIsSignedHS512AndCarriesAudX` - inspect the JWS header's `alg`,
   assert `typ == "Refresh"`, `aud` equal to the issuer URL, `prov == "default"`.
5. `TestAccessAndIDTokensAreSignedRS256` - same header check.
6. `TestParseAccessRejectsATokenSignedWithAnotherRealmsKey` - issue with one
   `RealmKeys`, parse with another, expect `ErrInvalidToken`.
7. `TestParseAccessRejectsAnExpiredToken` - issue with `Now` set in the past,
   expect `ErrExpiredToken`.
8. `TestParseRefreshRejectsAnAccessToken` - a token of the wrong `typ` must not
   verify as a refresh token, even though the same realm signed it.

Build the fixture keys with `keys.Generate("master")`; this package's tests need
no store.

The claim-set assertions cite the "Claim sets" and "Lightweight access tokens"
sections of the observed-behaviour document in a comment. They are the only
place P1 pins those sets: no golden compares them, because every token is
`Volatile` in every recorded response.

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/token/`
Expected: build failure, the package does not exist.

- [ ] **Step 3: Write the claim structs**

`internal/token/claims.go` declares four structs, fields in the measured order,
all `json` tags spelled exactly as measured:

```go
// accessClaims is the ordinary access token's claim set, in the order measured
// on Keycloak 26.7.1 - see the "Claim sets" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
//
// allowed-origins is a non-standard claim holding the client's web origins.
// aud is an array here and a string on the ID token; that asymmetry is
// Keycloak's, not a mistake.
type accessClaims struct {
	Acr               string              `json:"acr"`
	AllowedOrigins    []string            `json:"allowed-origins"`
	Aud               []string            `json:"aud"`
	Azp               string              `json:"azp"`
	EmailVerified     bool                `json:"email_verified"`
	Exp               int64               `json:"exp"`
	Iat               int64               `json:"iat"`
	Iss               string              `json:"iss"`
	Jti               string              `json:"jti"`
	PreferredUsername string              `json:"preferred_username"`
	RealmAccess       roleClaim           `json:"realm_access"`
	ResourceAccess    map[string]roleClaim `json:"resource_access"`
	Scope             string              `json:"scope"`
	Sid               string              `json:"sid"`
	Sub               string              `json:"sub"`
	Typ               string              `json:"typ"`
}

type roleClaim struct {
	Roles []string `json:"roles"`
}

// lightweightClaims is what a client with
// client.use.lightweight.access.token.enabled = true gets: no sub, no aud, no
// realm_access. admin-cli is such a client, which is why the Admin API cannot
// authorise from the token and must resolve the session from sid (see section
// 4.1 of the P1 design).
type lightweightClaims struct {
	Azp   string `json:"azp"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	Iss   string `json:"iss"`
	Jti   string `json:"jti"`
	Scope string `json:"scope"`
	Sid   string `json:"sid"`
	Typ   string `json:"typ"`
}

type idClaims struct {
	Acr               string `json:"acr"`
	AtHash            string `json:"at_hash"`
	Aud               string `json:"aud"`
	Azp               string `json:"azp"`
	EmailVerified     bool   `json:"email_verified"`
	Exp               int64  `json:"exp"`
	Iat               int64  `json:"iat"`
	Iss               string `json:"iss"`
	Jti               string `json:"jti"`
	PreferredUsername string `json:"preferred_username"`
	Sid               string `json:"sid"`
	Sub               string `json:"sub"`
	Typ               string `json:"typ"`
}

// refreshClaims: aud is the issuer URL and aud_x carries what the access token
// puts in aud. prov is "default".
type refreshClaims struct {
	Aud   string   `json:"aud"`
	AudX  []string `json:"aud_x"`
	Azp   string   `json:"azp"`
	Exp   int64    `json:"exp"`
	Iat   int64    `json:"iat"`
	Iss   string   `json:"iss"`
	Jti   string   `json:"jti"`
	Prov  string   `json:"prov"`
	Scope string   `json:"scope"`
	Sid   string   `json:"sid"`
	Sub   string   `json:"sub"`
	Typ   string   `json:"typ"`
}
```

Add a package doc comment stating plainly that these sets are **copied, not
derived**: in Keycloak they are produced by protocol mappers attached to client
scopes, which is P5, and P5 has to replace this file rather than extend it (see
section 6 of the roadmap).

Add, next to `Jti`, the one measured detail P1 does not reproduce:

```go
// Measured but not reproduced: Keycloak's access-token jti carries a
// per-instance prefix, for example "onrtro:13f91f50-...". ID and refresh tokens
// use a plain UUID. One sample is not enough to know the prefix's alphabet or
// length, and guessing would be exactly the kind of remembered value this
// project forbids, so all three use a plain UUID here. Tracked as F13.
```

- [ ] **Step 4: Write `issue.go`**

Marshal the right struct through `json.Marshal`, then sign with
`k.RSASigner()` (access, ID) or `k.HMACSigner()` (refresh) and serialise compact.
`at_hash` is the base64url, unpadded encoding of the **left half** of the
SHA-256 of the access token's ASCII bytes. `acr` is `"1"`. Lifespans come from
`Request`, not from constants.

- [ ] **Step 5: Write `parse.go`**

`jose.ParseSigned` with the allowed algorithms named explicitly
(`[]jose.SignatureAlgorithm{jose.RS256}` for access and ID,
`{jose.HS512}` for refresh) - never accept a token's own `alg` header as
authority, which is the classic JWT confusion bug. Verify with the realm's public
key or HMAC secret, then check `iss`, then `exp` against `now`, then `typ`.
Return `ErrExpiredToken` for an expired token and `ErrInvalidToken` for
everything else, so the handlers can tell the two apart.

- [ ] **Step 6: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/token/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/token
git commit -m "feat(token): issue and parse access, ID and refresh tokens"
```

---

### Task 6: Client authentication

**Files:**
- Create: `internal/oidc/clientauth.go`
- Create: `internal/oidc/clientauth_test.go`

**Interfaces:**
- Produces, inside package `oidc`:

```go
// clientAuthError carries the exact OAuth error a failure must be reported as.
type clientAuthError struct {
	Code        string
	Description string
	Status      int
}

// authenticateClient resolves and authenticates the client named in the
// request, by form parameters or HTTP Basic.
func (h *handler) authenticateClient(r *http.Request, realm *model.Realm) (*model.Client, *clientAuthError)
```

- [ ] **Step 1: Write the failing test**

`internal/oidc/clientauth_test.go` asserts, against a bootstrapped store:

1. `admin-cli` with no secret authenticates - it is public.
2. An unknown `client_id` fails with code `invalid_client`, description
   `Invalid client or Invalid client credentials`, status 401. Measured in
   `internal/conformance/testdata/golden/oidc/token/unknown-client.http`.
3. `broker` with `client_secret=wrong-secret` fails with `unauthorized_client`
   and the **same** description, status 401. Measured in
   `.../oidc/token/wrong-client-secret.http`. The two codes differing while the
   descriptions match is Keycloak's, and AGENTS.md lists it as a trap.
4. No `client_id` at all fails with `invalid_client`, status 401. Measured in
   `.../oidc/introspection/unauthenticated-client.http`.
5. **`broker` with an empty `client_secret` fails.** `broker` and `master-realm`
   are bootstrapped confidential with an empty stored secret, so a naive
   `provided == stored` comparison authenticates anybody who sends nothing. This
   is the hole the P1 design names in section 7.
6. HTTP Basic carrying the same credentials behaves identically to the form.

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/oidc/`
Expected: `undefined: authenticateClient`.

- [ ] **Step 3: Implement it**

Key points, all of them load-bearing:

```go
// invalidClient and unauthorizedClient are the two measured failures. They
// carry different codes and identical descriptions: an unknown client is
// invalid_client, a known client with the wrong secret is unauthorized_client.
// Collapsing them into one is a compatibility break, not a tidy-up.
var (
	invalidClient      = &clientAuthError{Code: "invalid_client", Description: "Invalid client or Invalid client credentials", Status: http.StatusUnauthorized}
	unauthorizedClient = &clientAuthError{Code: "unauthorized_client", Description: "Invalid client or Invalid client credentials", Status: http.StatusUnauthorized}
)
```

- A confidential client with an **empty stored secret can never authenticate**,
  whatever is presented. Check `client.Secret == ""` before comparing.
- Compare secrets with `subtle.ConstantTimeCompare`.
- A disabled client fails as `invalid_client`.
- Form parameters win over Basic when both are present; that is what Keycloak's
  own clients send.

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/oidc/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/oidc
git commit -m "feat(oidc): authenticate confidential and public clients"
```

---

### Task 7: The token endpoint, password grant

**Closes:** `oidc/token/password-grant-admin-cli`, `oidc/token/unknown-client`,
`oidc/token/wrong-password`, `oidc/token/wrong-client-secret`,
`oidc/token/missing-grant-type`, `oidc/token/unknown-grant-type`.

**Files:**
- Create: `internal/oidc/token.go`
- Modify: `internal/oidc/router.go`
- Modify: `internal/conformance/catalog_oidc_pending.go`

- [ ] **Step 1: Start the red phase**

In `internal/conformance/catalog_oidc_pending.go`, change those six cases from
`Status: Recorded` to `Status: Implemented` and delete their `Reason` lines. An
`Implemented` case with a `Reason` fails `TestCatalogIsWellFormed`, so the two
edits go together.

- [ ] **Step 2: Run the suite and read the brief**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance`
Expected: six failures, each carrying the byte-exact response Keycloak sent.
That output is this task's specification.

- [ ] **Step 3: Write the response document**

In `internal/oidc/token.go`:

```go
// tokenResponse is the token endpoint's success body, in the order Keycloak
// emits it - see the "Token endpoint response" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md and
// internal/conformance/testdata/golden/oidc/token/password-grant-admin-cli.http.
//
// not-before-policy is spelled with hyphens. IDToken is omitted rather than
// emitted empty when the openid scope was not requested: the measured
// admin-cli password grant has no id_token key at all.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	IDToken          string `json:"id_token,omitempty"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}
```

- [ ] **Step 4: Write the handler**

Validation order, which the four measured error cases together pin:

1. Parse the form. A missing `grant_type` is
   `400 invalid_request "Missing form parameter: grant_type"` even when the
   client is valid, so this check comes **before** client authentication.
2. An unrecognised `grant_type` is
   `400 unsupported_grant_type "Unsupported grant_type"`, again before client
   authentication - measured with a valid `admin-cli`.
3. Authenticate the client (Task 6).
4. Run the grant.

Every response from this endpoint carries `Cache-Control: no-store`,
`Pragma: no-cache` and the five security headers; the security headers already
come from `withKeycloakFallbacks`, the other two are set here.

The password grant itself:

- reject the client when `DirectAccessGrantsEnabled` is false;
- look up the user by `username`, then the `password` credential, then
  `auth.VerifyPassword`. A missing user, a missing credential and a wrong
  password all produce the identical measured
  `400 invalid_grant "Invalid user credentials"` - a different message for
  "no such user" would be an account-enumeration oracle;
- create a `UserSession` and a `ClientSession`;
- grant scope: the client's default scopes plus `openid` when it was requested.
  The measured `admin-cli` response is `scope: "profile email"` with word order
  unstable across container starts, which is why the case carries
  `UnorderedWords: ["scope"]`. Emit exactly those two words plus `openid` when
  asked for it, and no others.
- lifespans come from `realm.AccessTokenLifespan` and
  `realm.RefreshTokenLifespan` - 60 and 1800 for master, which is what the golden
  pins.

- [ ] **Step 5: Register the route**

`mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token", h.token)`.

- [ ] **Step 6: Run the suite**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS, all packages.

Then read the six diffs one at a time if any remain. The likeliest mismatches are
the `scope` word set and a stray `id_token` key.

- [ ] **Step 7: Commit**

```bash
git add internal/oidc internal/conformance
git commit -m "feat(oidc): serve the token endpoint's password grant"
```

---

### Task 8: Refresh and client credentials grants

**Closes:** `oidc/token/refresh-token-grant`, `oidc/token/invalid-refresh-token`.

**Files:**
- Modify: `internal/oidc/token.go`
- Modify: `internal/conformance/catalog_oidc_pending.go`
- Create: `internal/oidc/token_test.go` (the client-credentials coverage, which
  no golden can reach)

- [ ] **Step 1: Start the red phase**

Flip those two cases to `Implemented`, dropping their `Reason`.

- [ ] **Step 2: Run and read**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestConformance`
Expected: two failures.

- [ ] **Step 3: Implement `refresh_token`**

- `token.ParseRefresh`; anything that fails is the measured
  `400 invalid_grant "Invalid refresh token"` - including a syntactically
  invalid string, which is what `invalid-refresh-token` sends;
- load the user session named by `sid`; a missing session is the same error;
- `TouchUserSession`, then issue a fresh set against the client session's stored
  scope;
- the response is the same `tokenResponse`, and the golden shows the same
  `expires_in: 60` / `refresh_expires_in: 1800`.

Note in a comment, from the observed-behaviour document, that
`refresh_expires_in` on a refresh response is bounded by the remaining SSO
session lifetime rather than purely by the configured lifespan; the recorded
value agrees because the session is seconds old.

- [ ] **Step 4: Implement `client_credentials`**

In scope for P1 and reachable by no golden: no bootstrapped client has a service
account, so this is covered by `internal/oidc/token_test.go` only. Create a
confidential client with `ServiceAccountsEnabled` in the test, request the grant,
and assert a 200 whose body has an `access_token` and **no** `refresh_token`
field... unless that is measured otherwise. It is not measured. Therefore:

**Write the test to assert only what P1 can honestly claim** - that the grant
succeeds for a confidential client with service accounts enabled, fails with
`unauthorized_client` for one without, and fails for a public client - and leave
the response-shape assertion out, with a comment saying the shape is unmeasured
and `oidc/token/client-credentials-grant` stays `Pending` until P2 can create
such a client and record it.

- [ ] **Step 5: Run everything**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc internal/conformance
git commit -m "feat(oidc): serve the refresh_token and client_credentials grants"
```

---

### Task 9: Userinfo

**Closes:** `oidc/userinfo/missing-authorization-header`,
`oidc/userinfo/invalid-token`, `oidc/userinfo/token-without-openid-scope`,
`oidc/userinfo/lightweight-token`.

**Files:**
- Modify: `internal/httpx/errors.go`
- Modify: `internal/httpx/errors_test.go`
- Create: `internal/oidc/userinfo.go`
- Modify: `internal/oidc/router.go`
- Modify: `internal/conformance/catalog_oidc_pending.go`
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

- [ ] **Step 1: Start the red phase**

Flip the four cases to `Implemented`.

- [ ] **Step 2: Run and read the four goldens**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/oidc/userinfo'`

The four measured refusals, from the goldens, are:

| Case | Status | `WWW-Authenticate` |
|---|---|---|
| no Authorization header | 401 | `Bearer realm="master"` |
| `Bearer not-a-token` | 401 | `Bearer realm="master", error="invalid_token", error_description="Token verification failed"` |
| valid token, no openid scope | **403** | `Bearer realm="master", error="insufficient_scope", error_description="Missing openid scope"` |
| valid token, lightweight | 401 | `Bearer realm="master", error="invalid_token", error_description="Lightweight access token not allowed for userinfo endpoint"` |

All four: `Content-Type: text/plain;charset=utf-8`, empty body,
`Cache-Control: no-store`, `Pragma: no-cache`, and **four** security headers -
`X-Frame-Options` is omitted, which each case pins with `AssertAbsentHeaders`.

- [ ] **Step 3: Generalise the bearer challenge**

`WriteBearerChallenge` currently hardcodes 401 and always emits `error` and
`error_description`. Two of the four responses need something else. Change it to:

```go
// WriteBearerChallenge writes the userinfo rejection: an empty text/plain body
// with the error carried entirely in WWW-Authenticate. status is 401 for a
// token problem and 403 for insufficient scope, both measured. An empty errCode
// emits the bare `Bearer realm="master"` challenge Keycloak sends when no
// Authorization header arrived at all.
func WriteBearerChallenge(w http.ResponseWriter, status int, realm, errCode, description string) {
	suppressDate(w)
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	challenge := fmt.Sprintf("Bearer realm=%q", realm)
	if errCode != "" {
		challenge += fmt.Sprintf(", error=%q, error_description=%q", errCode, description)
	}
	w.Header()["WWW-Authenticate"] = []string{challenge}
	w.WriteHeader(status)
}
```

The header name still goes into the map directly rather than through
`Header.Set`, for the wire-casing reason its existing comment gives. Keep that
comment and the test that guards it, updating both call sites.

- [ ] **Step 4: Add the four-header helper**

`SetSecurityHeaders` sets five. Userinfo sends four. Add:

```go
// SetUserinfoSecurityHeaders sets the four security headers userinfo sends.
// It omits X-Frame-Options, which is measured and is not explained by routing -
// userinfo does reach Keycloak's filter chain. See AGENTS.md's "Things that
// look like bugs and are not".
func SetUserinfoSecurityHeaders(w http.ResponseWriter) {
	SetSecurityHeaders(w)
	w.Header().Del("X-Frame-Options")
}
```

`withKeycloakFallbacks` sets all five before the mux runs, so deleting is what
works here rather than setting a smaller set.

- [ ] **Step 5: Write the handler**

Check order, which the two token cases together pin: a lightweight token with the
openid scope gives the lightweight refusal, and a lightweight token **without**
it gives the scope refusal - so the scope check runs first.

1. no bearer token in header or `access_token` form field -> 401, bare challenge;
2. `token.ParseAccess` fails -> 401 `invalid_token` / `Token verification failed`;
3. granted scope lacks `openid` -> 403 `insufficient_scope` / `Missing openid scope`;
4. the client is lightweight -> 401 `invalid_token` /
   `Lightweight access token not allowed for userinfo endpoint`;
5. otherwise the success body.

Register both methods:
`GET /realms/{realm}/protocol/openid-connect/userinfo` and the `POST` twin, which
reads the token from the `access_token` form field.

**On the success body:** it is **not measured**. No client on a bootstrapped
`master` realm can produce a token userinfo accepts, which is exactly why
`oidc/userinfo/get-with-valid-token` and `post-with-valid-token` are `Pending`
with no golden. Derive it from the measured ID-token claim set - `sub`,
`email_verified`, `preferred_username` - and put a comment above it saying in as
many words that the shape is unmeasured, that the two cases stay `Pending`, and
that whoever first creates a confidential client (P2) must record them and correct
this. Do not flip those two cases.

- [ ] **Step 6: Record the third refusal shape in the observed document**

The "Userinfo rejections" section already lists three shapes. Confirm all four
rows of the table in Step 2 appear there, adding the missing one, each citing its
golden by path.

- [ ] **Step 7: Run everything**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/httpx internal/oidc internal/conformance docs
git commit -m "feat(oidc): serve the userinfo endpoint"
```

---

### Task 10: Introspection and revocation

**Closes:** `oidc/introspection/unauthenticated-client`,
`oidc/revocation/refresh-token`, `oidc/revocation/access-token`,
`oidc/revocation/unknown-token`, `oidc/revocation/wrong-client`.

**Files:**
- Create: `internal/oidc/introspect.go`, `internal/oidc/revoke.go`
- Modify: `internal/oidc/router.go`
- Modify: `internal/conformance/catalog_oidc_pending.go`
- Modify: `AGENTS.md`
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

- [ ] **Step 1: Fix two cases before flipping them**

`oidc/revocation/refresh-token` and `oidc/revocation/access-token` declare
`AssertHeaders: []string{"Content-Type"}`, but their goldens have **no**
`Content-Type` - the measured 200 is an empty body with none. As written, both
would fail on promotion with "header Content-Type is asserted but absent from the
golden", which says nothing about the implementation.

What the goldens do show, uniquely among the four revocation cases, is a sixth
header:

```
Content-Security-Policy: frame-src 'self'; frame-ancestors 'self'; object-src 'none';
```

So change both cases to:

```go
			AssertHeaders:       []string{"Content-Security-Policy"},
			AssertAbsentHeaders: []string{"Content-Type"},
```

This is a catalogue correction, not a contract change: the goldens are untouched.

- [ ] **Step 2: Start the red phase**

Flip all five cases to `Implemented`.

- [ ] **Step 3: Run and read**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/oidc/(introspection|revocation)'`
Expected: five failures.

- [ ] **Step 4: Implement revocation**

Measured behaviour, in order:

1. authenticate the client. `broker` with a wrong secret gives
   `401 unauthorized_client` - the same shape the token endpoint gives;
2. a public client **is** allowed here. `admin-cli` revoking succeeds, which is
   the opposite of introspection and is written up in the observed document's
   "Revocation accepts a public client; introspection does not";
3. an unparseable token gives **200** with
   `{"error":"invalid_token","error_description":"Invalid token"}` and
   `Content-Type: application/json`. A 200 carrying an error body is not a typo
   in the golden;
4. a valid token gives 200, an empty body, no `Content-Type`, and the
   `Content-Security-Policy` header above. Revoking deletes the user session, so
   the refresh token stops working.

Only the success path sets the CSP header. Add it through a named helper in
`internal/httpx` so the literal lives in one place, with a comment saying it was
measured on exactly this response and nowhere else yet.

- [ ] **Step 5: Implement introspection**

Only one case is recorded: no `client_id` at all gives
`401 invalid_client "Invalid client or Invalid client credentials"`, with **no**
`Cache-Control` and no `Pragma` - unlike the token endpoint. Do not add them.

The second measured behaviour has no golden but is recorded in the observed
document and in the catalogue comments: a **public** client is refused with
`403 {"error":"invalid_request","error_description":"Client not allowed."}`.
Implement it and cite the source in the comment; it is measured, just not
recorded as a case, because recording it needs a `make record` run.

The active/inactive response bodies are **unmeasured** for the same reason the
three `Pending` introspection cases give: reaching them needs a confidential
client with a known secret, which arrives with P2. Implement the RFC 7662 shape,
mark it unmeasured in a comment, and leave those three cases `Pending`.

- [ ] **Step 6: Write both traps into AGENTS.md**

Add to "Things that look like bugs and are not":

- revocation answers an unknown token with **200** and an error body, not 400;
- the revocation success is the only response measured so far carrying
  `Content-Security-Policy`, and it carries no `Content-Type`;
- a public client may revoke but may not introspect.

- [ ] **Step 7: Run everything**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/oidc internal/httpx internal/conformance AGENTS.md docs
git commit -m "feat(oidc): serve the introspection and revocation endpoints"
```

---

### Task 11: A real relying party validates an ID token

This is layer 3 of the P1 design's test plan, and section 10 of the original
design specified it and nobody delivered it. A response diff cannot catch a token
that is well-formed and wrongly signed, an `at_hash` that does not match, or an
`aud` a real library rejects. A relying party can.

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/oidc/relyingparty_test.go`

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/coreos/go-oidc/v3@latest
```

This needs network access. If it is unavailable, stop and report the task as
blocked rather than writing a hand-rolled substitute - a verifier we wrote
ourselves would share our own misconceptions, which is the entire point of using
somebody else's.

- [ ] **Step 2: Write the test**

```go
package oidc_test

// TestRelyingPartyAcceptsOurIDToken runs coreos/go-oidc, an independent
// implementation, against a live in-process Gloak: it fetches the discovery
// document, fetches the JWKS, verifies the ID token's signature, issuer,
// audience and expiry, and checks at_hash against the access token. None of
// that is reachable by a golden diff, which sees every token as {{string}}.
func TestRelyingPartyAcceptsOurIDToken(t *testing.T) {
	// The router needs the issuer at construction and httptest only reveals
	// its URL after Start, so the handler is installed through a pointer the
	// server dereferences per request.
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	// ... open a file-backed SQLite store in t.TempDir(), EnsureMaster,
	// h = oidc.NewRouter(s, keys.NewManager(s), srv.URL)

	// A password grant with scope=openid against admin-cli returns an
	// id_token, per the "Token endpoint response" section of the observed
	// document.
	// ... POST the form, decode the response

	provider, err := gooidc.NewProvider(context.Background(), srv.URL+"/realms/master")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: "admin-cli"})
	idToken, err := verifier.Verify(context.Background(), body.IDToken)
	if err != nil {
		t.Fatalf("an independent relying party rejected our ID token: %v", err)
	}
	if err := idToken.VerifyAccessToken(body.AccessToken); err != nil {
		t.Fatalf("at_hash does not match the access token: %v", err)
	}
}
```

Fill in the elided setup; every piece of it exists already in
`internal/conformance/server_test.go`.

Note the two things this asserts that nothing else does: `provider.Verifier`
requires the discovery document's `issuer` to equal the URL it was constructed
with, and `VerifyAccessToken` recomputes `at_hash`.

- [ ] **Step 3: Run it**

Run: `CGO_ENABLED=0 go test ./internal/oidc/ -run TestRelyingParty -v`
Expected: PASS. A failure here is a real finding, not a test bug: read what
go-oidc says before changing the test.

- [ ] **Step 4: Confirm the suite still needs no network**

Run: `CGO_ENABLED=0 go test ./...` with network disabled if you can. The test
above talks only to `httptest`; go-oidc fetches discovery and JWKS over the
loopback server, not the internet.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/oidc
git commit -m "test(oidc): verify an ID token with an independent relying party"
```

---

### Task 12: Close P1 in the documents

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md`
- Modify: `docs/superpowers/specs/2026-08-18-gloak-followups.md`
- Modify: `docs/superpowers/specs/2026-08-21-p1-token-foundation-design.md`

- [ ] **Step 1: Re-read the meter**

Run: `make conformance`

Record the new numbers rather than predicting them. Every case promoted in Tasks
7 to 10 moves from inventory to served.

- [ ] **Step 2: Update the README**

- "Status": add the token endpoint, userinfo, introspection and revocation to
  what works; remove them from the not-implemented list; replace the
  "8 of 483" figure with what `make conformance` just printed, and the count of
  `Recorded` cases with what remains.
- The "one known failure" paragraph should already be gone from Task 2. Confirm.

- [ ] **Step 3: Update the roadmap**

Mark P1 done in the table, with the measured served count. Leave P2 to P14
untouched: section 7 of that document says on purpose that nothing past P1 is
decided.

- [ ] **Step 4: Update the follow-ups**

- F5: closed in Task 2, if that has not already been written.
- Add **F13**: the access token's `jti` instance prefix is measured and not
  reproduced, with the one-sample argument from Task 5.
- Add **F14**: userinfo's success body and introspection's active/inactive
  bodies are unmeasured; both need a confidential client, which is P2.
- Amend the follow-up on `broker` and `master-realm` shipping an empty secret:
  P1 now refuses to authenticate an empty secret, so it is no longer a hole, but
  bootstrap still creates clients that can never authenticate. That is P2's to
  decide.

- [ ] **Step 5: Update the P1 design's status**

Change its header to `Status: implemented` and add a short closing section
listing what P1 shipped, what it deliberately left unmeasured, and the debt it
hands to P5 - the hardcoded claim sets - so P5 does not rediscover it mid-flight.

- [ ] **Step 6: Final verification**

```bash
CGO_ENABLED=0 go test ./...
make lint
make build
gofmt -l .
```

All four clean. `gofmt -l` exits 0 whether or not it prints anything, so read its
output rather than chaining on its exit status.

- [ ] **Step 7: Commit**

```bash
git add README.md docs
git commit -m "docs: close P1 and record what it left unmeasured"
```

---

## What this plan deliberately does not do

- **The `authorization_code` grant.** It needs `/auth` to mint a code, which is
  P3. `oidc/token/authorization-code-grant`, `replayed-code` and
  `pkce-verifier-mismatch` stay `Pending`.
- **Protocol mappers.** The claim sets are copied from the observed document, not
  derived from a mapper model. That is P5, and the roadmap already carries it as
  debt.
- **Offline sessions, device flow, CIBA, token exchange, DPoP, PAR.** P6 and P7.
- **Recording new goldens.** Every case this plan closes already has one. The
  behaviours that are measured but unrecorded - introspection refusing a public
  client, the userinfo success body - are named in Tasks 9 and 10 and left to the
  sub-project that can reach them.
