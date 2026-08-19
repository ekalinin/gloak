# Gloak Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `gloak serve` binary that bootstraps the `master` realm into Postgres or SQLite and serves a Keycloak-compatible discovery document and JWKS.

**Architecture:** Domain types in `internal/model` with no dependencies, repository interfaces in `internal/store` implemented twice (SQLite and Postgres) against one shared conformance suite, realm signing keys in `internal/keys`, and Keycloak's four error shapes isolated in `internal/httpx`. HTTP handlers depend only on interfaces, so every protocol test runs on SQLite without Docker.

**Tech Stack:** Go 1.26, `net/http` from the standard library, `go-jose/go-jose` v4, `jackc/pgx` v5, `modernc.org/sqlite`, `log/slog`, `testcontainers-go` (tests only).

## Global Constraints

- Module path is `github.com/ekalinin/gloak`. Go 1.26.
- Compatibility target is Keycloak **26.7.1**. Every observable value comes from `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`, never from memory.
- `go test ./...` must never require Docker or network access. Tests needing either are guarded by the `docker` build tag.
- SQLite must stay cgo-free: `modernc.org/sqlite` only, so `CGO_ENABLED=0 go build` works.
- Entity identifiers are string UUIDs, because they leak into API responses and tokens.
- Environment variables are prefixed `GLOAK_`. Never `KC_`.
- Code comments in English. Commit messages `type(scope): subject`, types limited to `feat`, `fix`, `docs`, `refactor`, `perf`, `chore`. No `Co-Authored-By` trailer.
- Never commit to `main`. Work happens on `feat/foundation`.

---

### Task 1: Repository scaffolding and domain model

**Files:**
- Create: `go.mod`
- Create: `internal/model/model.go`
- Create: `Makefile`
- Create: `.gitignore`
- Test: `internal/model/model_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `model.Realm`, `model.Client`, `model.User`, `model.Credential`, `model.Role` structs; `model.NewID() string` returning a lowercase RFC 4122 UUID string.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feat/foundation
```

- [ ] **Step 2: Initialise the module**

```bash
go mod init github.com/ekalinin/gloak
go mod edit -go=1.26
```

- [ ] **Step 3: Write `.gitignore`**

```
/gloak
/dist/
*.db
*.db-shm
*.db-wal
```

- [ ] **Step 4: Write the failing test**

Create `internal/model/model_test.go`:

```go
package model_test

import (
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

func TestNewIDIsAUniqueLowercaseUUID(t *testing.T) {
	a, b := model.NewID(), model.NewID()

	if a == b {
		t.Fatalf("NewID returned the same value twice: %q", a)
	}
	if len(a) != 36 {
		t.Fatalf("want a 36-character UUID, got %d characters: %q", len(a), a)
	}
	for _, r := range a {
		if r >= 'A' && r <= 'Z' {
			t.Fatalf("want lowercase, got %q", a)
		}
	}
}

func TestClientCarriesKeycloakAttributes(t *testing.T) {
	// admin-cli must round-trip the lightweight access token attribute, or its
	// tokens will not match Keycloak 26.7.1. See the observed-behaviour doc.
	c := model.Client{
		ClientID:   "admin-cli",
		Attributes: map[string]string{"client.use.lightweight.access.token.enabled": "true"},
	}

	if got := c.Attributes["client.use.lightweight.access.token.enabled"]; got != "true" {
		t.Fatalf("want attribute preserved, got %q", got)
	}
}
```

- [ ] **Step 5: Run the test to verify it fails**

Run: `go test ./internal/model/`
Expected: FAIL, `no required module provides package github.com/ekalinin/gloak/internal/model`

- [ ] **Step 6: Write the model**

Create `internal/model/model.go`:

```go
// Package model holds Gloak's domain types. It depends on nothing else in the
// project, so every other package can import it without creating a cycle.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewID returns a random RFC 4122 version 4 UUID in lowercase string form.
// Identifiers are strings rather than binary because they appear verbatim in
// admin API responses and in token claims.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("model: entropy source failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// Realm is a tenant. Lifespans are stored as durations but are emitted as
// whole seconds in token responses.
type Realm struct {
	ID                   string
	Name                 string
	Enabled              bool
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

// Client is an OAuth2 client. ID is the internal UUID used in admin API paths;
// ClientID is the human-facing identifier used in protocol requests. Keeping
// both is mandatory: Keycloak addresses clients by UUID in /admin/realms paths.
type Client struct {
	ID                        string
	RealmID                   string
	ClientID                  string
	Name                      string
	Enabled                   bool
	PublicClient              bool
	Secret                    string
	StandardFlowEnabled       bool
	DirectAccessGrantsEnabled bool
	ServiceAccountsEnabled    bool
	RedirectURIs              []string
	WebOrigins                []string
	Attributes                map[string]string
}

// User is an account within a realm.
type User struct {
	ID               string
	RealmID          string
	Username         string
	Email            string
	EmailVerified    bool
	Enabled          bool
	FirstName        string
	LastName         string
	CreatedTimestamp int64
	Attributes       map[string][]string
}

// Credential is a stored secret, split the way Keycloak splits it: a public
// part describing the hashing parameters and a secret part holding the result.
type Credential struct {
	ID                   string
	UserID               string
	Type                 string
	CreatedDate          int64
	Algorithm            string
	HashIterations       int
	AdditionalParameters map[string][]string
	Salt                 []byte
	HashValue            []byte
}

// Role is a realm role when ClientID is empty, otherwise a client role.
type Role struct {
	ID          string
	RealmID     string
	ClientID    string
	Name        string
	Description string
	Composite   bool
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `go test ./internal/model/`
Expected: PASS, both tests

- [ ] **Step 8: Write the Makefile**

```makefile
.PHONY: test build lint

test:
	CGO_ENABLED=0 go test ./...

build:
	CGO_ENABLED=0 go build -o gloak ./cmd/gloak

lint:
	go vet ./...
```

- [ ] **Step 9: Verify the cgo-free constraint holds**

Run: `make test`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add go.mod Makefile .gitignore internal/model/
git commit -m "feat(model): add domain types and UUID generation"
```

---

### Task 2: Store interfaces and the shared conformance suite

**Files:**
- Create: `internal/store/store.go`
- Create: `internal/store/storetest/conformance.go`
- Test: exercised by Tasks 3 and 4

**Interfaces:**
- Consumes: `model.Realm`, `model.Client`, `model.User`, `model.Role`, `model.Credential`, `model.NewID`.
- Produces: `store.Store` with methods `Realms() store.RealmRepo`, `Clients() store.ClientRepo`, `Users() store.UserRepo`, `Roles() store.RoleRepo`, `Close() error`; sentinel errors `store.ErrNotFound` and `store.ErrConflict`; `storetest.RunConformance(t *testing.T, newStore func(t *testing.T) store.Store)`.

- [ ] **Step 1: Write the interfaces**

Create `internal/store/store.go`:

```go
// Package store defines the persistence boundary. Handlers depend on these
// interfaces and never on a concrete database, which is what lets protocol
// tests run against SQLite with no Docker.
package store

import (
	"context"
	"errors"

	"github.com/ekalinin/gloak/internal/model"
)

var (
	// ErrNotFound is returned when a lookup matches nothing. Handlers map it
	// to Keycloak's 404 shapes.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a uniqueness constraint is violated.
	// Handlers map it to Keycloak's 409 errorMessage shape.
	ErrConflict = errors.New("store: conflict")
)

type Store interface {
	Realms() RealmRepo
	Clients() ClientRepo
	Users() UserRepo
	Roles() RoleRepo
	Close() error
}

type RealmRepo interface {
	Create(ctx context.Context, r *model.Realm) error
	ByName(ctx context.Context, name string) (*model.Realm, error)
	List(ctx context.Context) ([]*model.Realm, error)
}

type ClientRepo interface {
	Create(ctx context.Context, c *model.Client) error
	ByClientID(ctx context.Context, realmID, clientID string) (*model.Client, error)
	ByID(ctx context.Context, realmID, id string) (*model.Client, error)
	ListByRealm(ctx context.Context, realmID string) ([]*model.Client, error)
}

type UserRepo interface {
	Create(ctx context.Context, u *model.User) error
	ByUsername(ctx context.Context, realmID, username string) (*model.User, error)
	ByID(ctx context.Context, realmID, id string) (*model.User, error)
	SetCredential(ctx context.Context, c *model.Credential) error
	CredentialByUser(ctx context.Context, userID, typ string) (*model.Credential, error)
}

type RoleRepo interface {
	Create(ctx context.Context, r *model.Role) error
	ByName(ctx context.Context, realmID, clientID, name string) (*model.Role, error)
	ListRealmRoles(ctx context.Context, realmID string) ([]*model.Role, error)
}
```

- [ ] **Step 2: Write the conformance suite**

Both drivers must behave identically, so the assertions live in one place and each driver supplies a constructor. Create `internal/store/storetest/conformance.go`:

```go
// Package storetest holds the behaviour both store drivers must satisfy.
// It lives in its own package so SQLite and Postgres share one definition of
// correct rather than two drifting copies.
package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// RunConformance exercises every store method. newStore must return an empty,
// migrated store scoped to the given test.
func RunConformance(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Helper()

	t.Run("realm round-trips", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		want := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}

		if err := s.Realms().Create(ctx, want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := s.Realms().ByName(ctx, "master")
		if err != nil {
			t.Fatalf("ByName: %v", err)
		}
		if got.ID != want.ID || got.Name != "master" || !got.Enabled {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
	})

	t.Run("missing realm reports ErrNotFound", func(t *testing.T) {
		s := newStore(t)

		_, err := s.Realms().ByName(context.Background(), "nope")

		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("duplicate realm reports ErrConflict", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		r := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, r); err != nil {
			t.Fatalf("first Create: %v", err)
		}

		err := s.Realms().Create(ctx, &model.Realm{ID: model.NewID(), Name: "master"})

		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})

	t.Run("client attributes and slices survive the round-trip", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		want := &model.Client{
			ID: model.NewID(), RealmID: realm.ID, ClientID: "admin-cli",
			Enabled: true, PublicClient: true, DirectAccessGrantsEnabled: true,
			RedirectURIs: []string{"http://localhost:9999/*"},
			WebOrigins:   []string{"http://localhost:9999"},
			Attributes:   map[string]string{"client.use.lightweight.access.token.enabled": "true"},
		}

		if err := s.Clients().Create(ctx, want); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}
		got, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")
		if err != nil {
			t.Fatalf("ByClientID: %v", err)
		}

		if got.Attributes["client.use.lightweight.access.token.enabled"] != "true" {
			t.Fatalf("attributes lost: %+v", got.Attributes)
		}
		if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "http://localhost:9999/*" {
			t.Fatalf("redirect URIs lost: %+v", got.RedirectURIs)
		}
		if !got.PublicClient || !got.DirectAccessGrantsEnabled {
			t.Fatalf("flags lost: %+v", got)
		}
	})

	t.Run("client is addressable by internal UUID", func(t *testing.T) {
		// Keycloak's admin API addresses clients by UUID, not clientId.
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		c := &model.Client{ID: model.NewID(), RealmID: realm.ID, ClientID: "account", Enabled: true}
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("Clients().Create: %v", err)
		}

		got, err := s.Clients().ByID(ctx, realm.ID, c.ID)

		if err != nil {
			t.Fatalf("ByID: %v", err)
		}
		if got.ClientID != "account" {
			t.Fatalf("want account, got %q", got.ClientID)
		}
	})

	t.Run("credential preserves argon2 parameters", func(t *testing.T) {
		// Parameters measured on Keycloak 26.7.1: argon2id 1.3, 5 iterations,
		// 7168 KiB, parallelism 1, 32-byte output.
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
		want := &model.Credential{
			ID: model.NewID(), UserID: u.ID, Type: "password",
			Algorithm: "argon2", HashIterations: 5,
			AdditionalParameters: map[string][]string{
				"hashLength": {"32"}, "memory": {"7168"},
				"type": {"id"}, "version": {"1.3"}, "parallelism": {"1"},
			},
			Salt: []byte("saltsaltsaltsalt"), HashValue: []byte("hashhashhashhash"),
		}

		if err := s.Users().SetCredential(ctx, want); err != nil {
			t.Fatalf("SetCredential: %v", err)
		}
		got, err := s.Users().CredentialByUser(ctx, u.ID, "password")
		if err != nil {
			t.Fatalf("CredentialByUser: %v", err)
		}

		if got.Algorithm != "argon2" || got.HashIterations != 5 {
			t.Fatalf("algorithm or iterations lost: %+v", got)
		}
		if got.AdditionalParameters["memory"][0] != "7168" {
			t.Fatalf("memory parameter lost: %+v", got.AdditionalParameters)
		}
		if string(got.Salt) != "saltsaltsaltsalt" || string(got.HashValue) != "hashhashhashhash" {
			t.Fatalf("secret part lost: salt=%q hash=%q", got.Salt, got.HashValue)
		}
	})

	t.Run("realm roles are listable", func(t *testing.T) {
		s := newStore(t)
		ctx := context.Background()
		realm := &model.Realm{ID: model.NewID(), Name: "master", Enabled: true}
		if err := s.Realms().Create(ctx, realm); err != nil {
			t.Fatalf("Realms().Create: %v", err)
		}
		for _, n := range []string{"admin", "create-realm", "offline_access"} {
			r := &model.Role{ID: model.NewID(), RealmID: realm.ID, Name: n}
			if err := s.Roles().Create(ctx, r); err != nil {
				t.Fatalf("Roles().Create(%q): %v", n, err)
			}
		}

		got, err := s.Roles().ListRealmRoles(ctx, realm.ID)

		if err != nil {
			t.Fatalf("ListRealmRoles: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("want 3 realm roles, got %d", len(got))
		}
	})
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./internal/store/...`
Expected: success. There is nothing to run yet; Task 3 supplies the first driver.

- [ ] **Step 4: Commit**

```bash
git add internal/store/
git commit -m "feat(store): add repository interfaces and conformance suite"
```

---

### Task 3: SQLite driver and migrations

**Files:**
- Create: `internal/store/sqlite/sqlite.go`
- Create: `internal/store/sqlite/migrations/0001_init.sql`
- Test: `internal/store/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: `store.Store`, `store.ErrNotFound`, `store.ErrConflict`, `storetest.RunConformance`.
- Produces: `sqlite.Open(ctx context.Context, dsn string) (store.Store, error)`, which applies migrations before returning.

- [ ] **Step 1: Write the failing test**

Create `internal/store/sqlite/sqlite_test.go`:

```go
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
	"github.com/ekalinin/gloak/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) store.Store {
		t.Helper()
		dsn := filepath.Join(t.TempDir(), "gloak.db")
		s, err := sqlite.Open(context.Background(), dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/store/sqlite/`
Expected: FAIL, package `sqlite` does not exist

- [ ] **Step 3: Add the driver dependency**

```bash
go get modernc.org/sqlite
```

- [ ] **Step 4: Write the migration**

Create `internal/store/sqlite/migrations/0001_init.sql`. Slice-valued and map-valued
columns are stored as JSON text; SQLite has no array type and inventing side tables
for them now would be work the first slice does not need.

```sql
CREATE TABLE realm (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    enabled                INTEGER NOT NULL DEFAULT 1,
    access_token_lifespan  INTEGER NOT NULL DEFAULT 60,
    refresh_token_lifespan INTEGER NOT NULL DEFAULT 1800
);

CREATE TABLE client (
    id                           TEXT PRIMARY KEY,
    realm_id                     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id                    TEXT NOT NULL,
    name                         TEXT NOT NULL DEFAULT '',
    enabled                      INTEGER NOT NULL DEFAULT 1,
    public_client                INTEGER NOT NULL DEFAULT 0,
    secret                       TEXT NOT NULL DEFAULT '',
    standard_flow_enabled        INTEGER NOT NULL DEFAULT 1,
    direct_access_grants_enabled INTEGER NOT NULL DEFAULT 0,
    service_accounts_enabled     INTEGER NOT NULL DEFAULT 0,
    redirect_uris                TEXT NOT NULL DEFAULT '[]',
    web_origins                  TEXT NOT NULL DEFAULT '[]',
    attributes                   TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id)
);

CREATE TABLE user_entity (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    username          TEXT NOT NULL,
    email             TEXT NOT NULL DEFAULT '',
    email_verified    INTEGER NOT NULL DEFAULT 0,
    enabled           INTEGER NOT NULL DEFAULT 1,
    first_name        TEXT NOT NULL DEFAULT '',
    last_name         TEXT NOT NULL DEFAULT '',
    created_timestamp INTEGER NOT NULL DEFAULT 0,
    attributes        TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, username)
);

CREATE TABLE credential (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    type                  TEXT NOT NULL,
    created_date          INTEGER NOT NULL DEFAULT 0,
    algorithm             TEXT NOT NULL DEFAULT '',
    hash_iterations       INTEGER NOT NULL DEFAULT 0,
    additional_parameters TEXT NOT NULL DEFAULT '{}',
    salt                  BLOB,
    hash_value            BLOB,
    UNIQUE (user_id, type)
);

CREATE TABLE keycloak_role (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    composite   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (realm_id, client_id, name)
);
```

- [ ] **Step 5: Write the driver**

Create `internal/store/sqlite/sqlite.go`:

```go
// Package sqlite implements store.Store on modernc.org/sqlite, a cgo-free
// driver, so the binary stays a single static file.
package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ db *sql.DB }

// Open opens the database at dsn and applies all migrations.
func Open(ctx context.Context, dsn string) (store.Store, error) {
	db, err := sql.Open("sqlite", dsn+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func migrate(ctx context.Context, db *sql.DB) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("sqlite: read migrations: %w", err)
	}
	for _, e := range entries {
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("sqlite: read %s: %w", e.Name(), err)
		}
		if _, err := db.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("sqlite: apply %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (s *Store) Close() error              { return s.db.Close() }
func (s *Store) Realms() store.RealmRepo   { return &realmRepo{s.db} }
func (s *Store) Clients() store.ClientRepo { return &clientRepo{s.db} }
func (s *Store) Users() store.UserRepo     { return &userRepo{s.db} }
func (s *Store) Roles() store.RoleRepo     { return &roleRepo{s.db} }

// classify maps driver errors onto the store's sentinels so handlers never
// inspect driver-specific error text.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return store.ErrConflict
	}
	return err
}

func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic("sqlite: encoding a value that must be encodable: " + err.Error())
	}
	return string(b)
}

func decode(s string, v any) error { return json.Unmarshal([]byte(s), v) }

type realmRepo struct{ db *sql.DB }

func (r *realmRepo) Create(ctx context.Context, m *model.Realm) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO realm (id, name, enabled, access_token_lifespan, refresh_token_lifespan)
		 VALUES (?, ?, ?, ?, ?)`,
		m.ID, m.Name, m.Enabled, int64(m.AccessTokenLifespan.Seconds()), int64(m.RefreshTokenLifespan.Seconds()))
	return classify(err)
}

func (r *realmRepo) ByName(ctx context.Context, name string) (*model.Realm, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, name, enabled, access_token_lifespan, refresh_token_lifespan
		 FROM realm WHERE name = ?`, name)
	return scanRealm(row)
}

func (r *realmRepo) List(ctx context.Context) ([]*model.Realm, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name, enabled, access_token_lifespan, refresh_token_lifespan
		 FROM realm ORDER BY name`)
	if err != nil {
		return nil, classify(err)
	}
	defer rows.Close()

	var out []*model.Realm
	for rows.Next() {
		m, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, classify(rows.Err())
}
```

The remaining repositories follow the same three shapes already demonstrated:
`Create` inserts and returns `classify(err)`, single-row getters delegate to a
`scanX` helper, list methods iterate. Write `scanRealm`, `scanClient`, `scanUser`,
`scanCredential` and `scanRole` against a `interface{ Scan(...any) error }`
parameter so `QueryRow` and `Rows` share one implementation, and use `encode` and
`decode` for `redirect_uris`, `web_origins`, `attributes` and
`additional_parameters`.

- [ ] **Step 6: Run the conformance suite**

Run: `go test ./internal/store/sqlite/ -v`
Expected: PASS, all seven subtests

- [ ] **Step 7: Verify the build stays cgo-free**

Run: `CGO_ENABLED=0 go build ./...`
Expected: success

- [ ] **Step 8: Commit**

```bash
git add internal/store/sqlite/
git commit -m "feat(store): add cgo-free sqlite driver"
```

---

### Task 4: Postgres driver

**Files:**
- Create: `internal/store/postgres/postgres.go`
- Create: `internal/store/postgres/migrations/0001_init.sql`
- Test: `internal/store/postgres/postgres_test.go`

**Interfaces:**
- Consumes: the same interfaces as Task 3.
- Produces: `postgres.Open(ctx context.Context, dsn string) (store.Store, error)`.

- [ ] **Step 1: Write the failing test, guarded by a build tag**

The `docker` tag keeps `go test ./...` runnable without a container. Create
`internal/store/postgres/postgres_test.go`:

```go
//go:build docker

package postgres_test

import (
	"context"
	"testing"

	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/postgres"
	"github.com/ekalinin/gloak/internal/store/storetest"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestConformance(t *testing.T) {
	storetest.RunConformance(t, func(t *testing.T) store.Store {
		t.Helper()
		ctx := context.Background()
		dsn := startPostgres(ctx, t) // see Step 4
		s, err := postgres.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -tags docker ./internal/store/postgres/`
Expected: FAIL, package `postgres` does not exist

- [ ] **Step 3: Add dependencies**

```bash
go get github.com/jackc/pgx/v5
go get github.com/testcontainers/testcontainers-go/modules/postgres
```

- [ ] **Step 4: Add the container helper**

Append to `postgres_test.go`:

```go
func startPostgres(ctx context.Context, t *testing.T) string {
	t.Helper()
	c, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("gloak"),
		tcpostgres.WithUsername("gloak"),
		tcpostgres.WithPassword("gloak"),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	return dsn
}
```

Import the module as `tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"` to avoid colliding with our own `postgres` package.

- [ ] **Step 5: Write the migration**

Create `internal/store/postgres/migrations/0001_init.sql`. Same tables as SQLite
with Postgres types: `TEXT` stays, `INTEGER` booleans become `BOOLEAN`, JSON columns
become `JSONB`, `BLOB` becomes `BYTEA`, and `BIGINT` carries the timestamps.

```sql
CREATE TABLE realm (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL UNIQUE,
    enabled                BOOLEAN NOT NULL DEFAULT TRUE,
    access_token_lifespan  BIGINT NOT NULL DEFAULT 60,
    refresh_token_lifespan BIGINT NOT NULL DEFAULT 1800
);

CREATE TABLE client (
    id                           TEXT PRIMARY KEY,
    realm_id                     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id                    TEXT NOT NULL,
    name                         TEXT NOT NULL DEFAULT '',
    enabled                      BOOLEAN NOT NULL DEFAULT TRUE,
    public_client                BOOLEAN NOT NULL DEFAULT FALSE,
    secret                       TEXT NOT NULL DEFAULT '',
    standard_flow_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    direct_access_grants_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    service_accounts_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    redirect_uris                JSONB NOT NULL DEFAULT '[]',
    web_origins                  JSONB NOT NULL DEFAULT '[]',
    attributes                   JSONB NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id)
);

CREATE TABLE user_entity (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    username          TEXT NOT NULL,
    email             TEXT NOT NULL DEFAULT '',
    email_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    first_name        TEXT NOT NULL DEFAULT '',
    last_name         TEXT NOT NULL DEFAULT '',
    created_timestamp BIGINT NOT NULL DEFAULT 0,
    attributes        JSONB NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, username)
);

CREATE TABLE credential (
    id                    TEXT PRIMARY KEY,
    user_id               TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    type                  TEXT NOT NULL,
    created_date          BIGINT NOT NULL DEFAULT 0,
    algorithm             TEXT NOT NULL DEFAULT '',
    hash_iterations       INTEGER NOT NULL DEFAULT 0,
    additional_parameters JSONB NOT NULL DEFAULT '{}',
    salt                  BYTEA,
    hash_value            BYTEA,
    UNIQUE (user_id, type)
);

CREATE TABLE keycloak_role (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    composite   BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (realm_id, client_id, name)
);
```

- [ ] **Step 6: Write the driver**

Mirror `sqlite.go` with three differences: placeholders are `$1`, `$2` rather than
`?`; `classify` detects conflicts through `*pgconn.PgError` with `Code == "23505"`
rather than by matching error text; and `pgx.ErrNoRows` maps to `store.ErrNotFound`.

```go
func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return store.ErrConflict
	}
	return err
}
```

- [ ] **Step 7: Run the conformance suite**

Run: `go test -tags docker ./internal/store/postgres/ -v`
Expected: PASS, the same seven subtests as SQLite

- [ ] **Step 8: Verify the default test run still needs no Docker**

Run: `make test`
Expected: PASS, and the postgres package reports `[no test files]`

- [ ] **Step 9: Commit**

```bash
git add internal/store/postgres/
git commit -m "feat(store): add postgres driver"
```

---

### Task 5: Keycloak's four error shapes

**Files:**
- Create: `internal/httpx/errors.go`
- Test: `internal/httpx/errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `httpx.WriteOAuthError(w http.ResponseWriter, status int, code, description string)`, `httpx.WriteMessageError(w http.ResponseWriter, status int, message string)`, `httpx.WriteAdminError(w http.ResponseWriter, status int, message string)`, `httpx.WriteBearerChallenge(w http.ResponseWriter, realm, errCode, description string)`.

- [ ] **Step 1: Write the failing test**

Every expected value below was measured on Keycloak 26.7.1. Create
`internal/httpx/errors_test.go`:

```go
package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ekalinin/gloak/internal/httpx"
)

func TestWriteOAuthError(t *testing.T) {
	w := httptest.NewRecorder()

	httpx.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid user credentials")

	if w.Code != 400 {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if got, want := w.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `{"error":"invalid_grant","error_description":"Invalid user credentials"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteMessageError(t *testing.T) {
	// Shape 2: a bare error field holding prose, not an OAuth code.
	w := httptest.NewRecorder()

	httpx.WriteMessageError(w, http.StatusNotFound, "Realm not found.")

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm not found."}`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteAdminError(t *testing.T) {
	// Shape 3: errorMessage, used for admin conflicts and validation.
	w := httptest.NewRecorder()

	httpx.WriteAdminError(w, http.StatusConflict, "Client gloak-probe already exists")

	if w.Code != 409 {
		t.Fatalf("want 409, got %d", w.Code)
	}
	want := `{"errorMessage":"Client gloak-probe already exists"}`
	if got := w.Body.String(); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestWriteBearerChallenge(t *testing.T) {
	// userinfo with a bad token: 401, text/plain, empty body, error in the header.
	w := httptest.NewRecorder()

	httpx.WriteBearerChallenge(w, "master", "invalid_token", "Token verification failed")

	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if got := w.Body.Len(); got != 0 {
		t.Fatalf("want an empty body, got %d bytes: %q", got, w.Body.String())
	}
	if got, want := w.Header().Get("Content-Type"), "text/plain;charset=utf-8"; got != want {
		t.Fatalf("want %q, got %q", want, got)
	}
	want := `Bearer realm="master", error="invalid_token", error_description="Token verification failed"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/httpx/`
Expected: FAIL, package `httpx` does not exist

- [ ] **Step 3: Write the implementation**

Create `internal/httpx/errors.go`:

```go
// Package httpx owns Keycloak's error formats. They live in one package because
// compatibility breaks on error paths far more often than on success paths, and
// a format spread across handlers is a format that drifts.
//
// Keycloak 26.7.1 emits four distinct shapes. They do not split along the
// protocol/admin boundary; both sides use more than one. See
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// WriteOAuthError writes shape 1, the RFC 6749 body used by the token endpoint
// and by the admin API for an unparseable JSON payload.
func WriteOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// WriteMessageError writes shape 2: a bare error field carrying prose rather
// than an OAuth error code, used for 401 and 404 on both sides.
func WriteMessageError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// WriteAdminError writes shape 3: the errorMessage field the admin API uses for
// conflicts and validation failures.
func WriteAdminError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"errorMessage": message})
}

// WriteBearerChallenge writes the userinfo rejection: 401, text/plain, an empty
// body, and the error carried entirely in WWW-Authenticate.
func WriteBearerChallenge(w http.ResponseWriter, realm, errCode, description string) {
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		"Bearer realm=%q, error=%q, error_description=%q", realm, errCode, description))
	w.WriteHeader(http.StatusUnauthorized)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Keycloak emits no trailing newline; SetEscapeHTML(false) keeps
	// descriptions containing quotes or angle brackets byte-identical.
	enc := json.NewEncoder(noNewline{w})
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

// noNewline strips the trailing newline json.Encoder appends.
type noNewline struct{ w http.ResponseWriter }

func (n noNewline) Write(p []byte) (int, error) {
	if len(p) > 0 && p[len(p)-1] == '\n' {
		p = p[:len(p)-1]
	}
	return n.w.Write(p)
}
```

Note that `map[string]string` marshals with keys sorted alphabetically, which
happens to put `error` before `error_description`. That matches the observed
output, and the tests above pin it.

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/httpx/ -v`
Expected: PASS, four tests

- [ ] **Step 5: Commit**

```bash
git add internal/httpx/
git commit -m "feat(httpx): add keycloak error formats"
```

---

### Task 6: Realm keys and JWKS

**Files:**
- Create: `internal/keys/keys.go`
- Test: `internal/keys/keys_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `keys.Generate() (*keys.RealmKeys, error)`; `(*RealmKeys).JWKS() jose.JSONWebKeySet`; `(*RealmKeys).RSASigner() (jose.Signer, error)`; `(*RealmKeys).HMACSigner() (jose.Signer, error)`; fields `RSAKeyID string`, `HMACKeyID string`.

- [ ] **Step 1: Write the failing test**

Keycloak signs access and ID tokens RS256 but refresh tokens HS512, so a realm
needs two keys from the start. Create `internal/keys/keys_test.go`:

```go
package keys_test

import (
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
)

func TestGenerateProducesBothKeys(t *testing.T) {
	k, err := keys.Generate()

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k.RSAKeyID == "" || k.HMACKeyID == "" {
		t.Fatalf("want both key IDs set, got rsa=%q hmac=%q", k.RSAKeyID, k.HMACKeyID)
	}
	if k.RSAKeyID == k.HMACKeyID {
		t.Fatal("want distinct key IDs for the RSA and HMAC keys")
	}
}

func TestJWKSExposesOnlyThePublicRSAKey(t *testing.T) {
	// The HMAC key signs refresh tokens, which are opaque to clients. Publishing
	// it would hand out the ability to mint refresh tokens.
	k, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	set := k.JWKS()

	if len(set.Keys) != 1 {
		t.Fatalf("want exactly one published key, got %d", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.KeyID != k.RSAKeyID {
		t.Fatalf("want key ID %q, got %q", k.RSAKeyID, jwk.KeyID)
	}
	if !jwk.IsPublic() {
		t.Fatal("want a public key in the JWKS, got a private one")
	}
	if jwk.Algorithm != "RS256" || jwk.Use != "sig" {
		t.Fatalf("want RS256/sig, got %s/%s", jwk.Algorithm, jwk.Use)
	}
}

func TestSignersUseTheExpectedAlgorithms(t *testing.T) {
	// Signing and reading the JWS header back is what catches the mistake that
	// matters here: the two signers swapped, so refresh tokens end up RS256 and
	// access tokens HS512.
	k, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cases := []struct {
		name    string
		signer  func() (jose.Signer, error)
		wantAlg string
		wantKid string
	}{
		{"access and ID tokens", k.RSASigner, "RS256", k.RSAKeyID},
		{"refresh tokens", k.HMACSigner, "HS512", k.HMACKeyID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := tc.signer()
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			jws, err := signer.Sign([]byte(`{"sub":"probe"}`))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			serialised, err := jws.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			parsed, err := jose.ParseSigned(serialised,
				[]jose.SignatureAlgorithm{jose.RS256, jose.HS512})
			if err != nil {
				t.Fatalf("ParseSigned: %v", err)
			}

			hdr := parsed.Signatures[0].Header
			if string(hdr.Algorithm) != tc.wantAlg {
				t.Errorf("want alg %s, got %s", tc.wantAlg, hdr.Algorithm)
			}
			if hdr.KeyID != tc.wantKid {
				t.Errorf("want kid %s, got %s", tc.wantKid, hdr.KeyID)
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/keys/`
Expected: FAIL, package `keys` does not exist

- [ ] **Step 3: Add the dependency**

```bash
go get github.com/go-jose/go-jose/v4
```

- [ ] **Step 4: Write the implementation**

Create `internal/keys/keys.go`:

```go
// Package keys manages a realm's signing material. It is deliberately separate
// from token issuance: Keycloak signs access and ID tokens RS256 but refresh
// tokens HS512, so a realm holds more than one key even before rotation and
// multiple active JWKS entries arrive.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/ekalinin/gloak/internal/model"
)

type RealmKeys struct {
	RSAKeyID  string
	HMACKeyID string

	rsaKey  *rsa.PrivateKey
	hmacKey []byte
}

// Generate creates a fresh RSA key for RS256 and a fresh secret for HS512.
func Generate() (*RealmKeys, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keys: generate rsa: %w", err)
	}
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("keys: generate hmac: %w", err)
	}
	return &RealmKeys{
		RSAKeyID:  model.NewID(),
		HMACKeyID: model.NewID(),
		rsaKey:    rsaKey,
		hmacKey:   hmacKey,
	}, nil
}

// JWKS returns the public key set served at
// /realms/{realm}/protocol/openid-connect/certs. The HMAC key is never
// published: it signs refresh tokens, which clients treat as opaque.
func (k *RealmKeys) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.rsaKey.Public(),
		KeyID:     k.RSAKeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

// RSASigner signs access and ID tokens.
func (k *RealmKeys) RSASigner() (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k.rsaKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.RSAKeyID),
	)
}

// HMACSigner signs refresh tokens.
func (k *RealmKeys) HMACSigner() (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS512, Key: k.hmacKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.HMACKeyID),
	)
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/keys/ -v`
Expected: PASS, three tests

- [ ] **Step 6: Commit**

```bash
git add internal/keys/
git commit -m "feat(keys): add realm signing keys and jwks"
```

---

### Task 7: Master realm bootstrap

**Files:**
- Create: `internal/bootstrap/bootstrap.go`
- Test: `internal/bootstrap/bootstrap_test.go`

**Interfaces:**
- Consumes: `store.Store`, `model.*`.
- Produces: `bootstrap.EnsureMaster(ctx context.Context, s store.Store, adminUser, adminPassword string) error`.

- [ ] **Step 1: Write the failing test**

The expected objects are the ones measured on Keycloak 26.7.1. Create
`internal/bootstrap/bootstrap_test.go`:

```go
package bootstrap_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newStore(t *testing.T) store.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEnsureMasterCreatesTheSixDefaultClients(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}

	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	clients, err := s.Clients().ListByRealm(ctx, realm.ID)
	if err != nil {
		t.Fatalf("ListByRealm: %v", err)
	}
	got := map[string]bool{}
	for _, c := range clients {
		got[c.ClientID] = true
	}
	for _, want := range []string{
		"account", "account-console", "admin-cli",
		"broker", "master-realm", "security-admin-console",
	} {
		if !got[want] {
			t.Errorf("missing default client %q", want)
		}
	}
	if len(clients) != 6 {
		t.Errorf("want 6 clients, got %d", len(clients))
	}
}

func TestAdminCLIMatchesKeycloakConfiguration(t *testing.T) {
	// Measured: public, direct grant on, standard flow OFF, and the lightweight
	// access token attribute set. Without the attribute its tokens carry a
	// different claim set than Keycloak's.
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	c, err := s.Clients().ByClientID(ctx, realm.ID, "admin-cli")

	if err != nil {
		t.Fatalf("ByClientID: %v", err)
	}
	if !c.PublicClient {
		t.Error("want a public client")
	}
	if !c.DirectAccessGrantsEnabled {
		t.Error("want direct access grants enabled")
	}
	if c.StandardFlowEnabled {
		t.Error("want standard flow disabled")
	}
	if got := c.Attributes["client.use.lightweight.access.token.enabled"]; got != "true" {
		t.Errorf("want the lightweight token attribute set to true, got %q", got)
	}
}

func TestEnsureMasterCreatesTheFiveRealmRoles(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}

	roles, err := s.Roles().ListRealmRoles(ctx, realm.ID)

	if err != nil {
		t.Fatalf("ListRealmRoles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range roles {
		got[r.Name] = true
	}
	for _, want := range []string{
		"admin", "create-realm", "default-roles-master",
		"offline_access", "uma_authorization",
	} {
		if !got[want] {
			t.Errorf("missing realm role %q", want)
		}
	}
}

func TestEnsureMasterIsIdempotent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("first EnsureMaster: %v", err)
	}

	err := bootstrap.EnsureMaster(ctx, s, "admin", "admin")

	if err != nil {
		t.Fatalf("second EnsureMaster must be a no-op, got %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/bootstrap/`
Expected: FAIL, package `bootstrap` does not exist

- [ ] **Step 3: Write the implementation**

Create `internal/bootstrap/bootstrap.go`. `EnsureMaster` returns early when the
realm already exists, creates the realm with the measured lifespans (60s access,
1800s refresh), inserts the six clients with the flags recorded in the
observed-behaviour document, inserts the five realm roles, creates the admin user
and stores its password. The client table below is the measured configuration:

```go
var defaultClients = []model.Client{
	{ClientID: "account", PublicClient: true, StandardFlowEnabled: true},
	{ClientID: "account-console", PublicClient: true, StandardFlowEnabled: true},
	{
		ClientID: "admin-cli", PublicClient: true,
		StandardFlowEnabled: false, DirectAccessGrantsEnabled: true,
		Attributes: map[string]string{
			"client.use.lightweight.access.token.enabled": "true",
		},
	},
	{ClientID: "broker", PublicClient: false, StandardFlowEnabled: true},
	{ClientID: "master-realm", PublicClient: false, StandardFlowEnabled: true},
	{ClientID: "security-admin-console", PublicClient: true, StandardFlowEnabled: true},
}

var defaultRealmRoles = []model.Role{
	{Name: "admin", Composite: true},
	{Name: "create-realm"},
	{Name: "default-roles-master", Composite: true},
	{Name: "offline_access"},
	{Name: "uma_authorization"},
}
```

Password storage uses the measured argon2id parameters. Add
`golang.org/x/crypto` and hash with `argon2.IDKey(password, salt, 5, 7168, 1, 32)`,
storing `Algorithm: "argon2"`, `HashIterations: 5` and `AdditionalParameters`
holding `hashLength=32`, `memory=7168`, `type=id`, `version=1.3`, `parallelism=1`.

```bash
go get golang.org/x/crypto
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/bootstrap/ -v`
Expected: PASS, four tests

- [ ] **Step 5: Commit**

```bash
git add internal/bootstrap/
git commit -m "feat(bootstrap): create the master realm"
```

---

### Task 8: Discovery, JWKS and the serve command

**Files:**
- Create: `internal/oidc/discovery.go`
- Create: `internal/oidc/router.go`
- Create: `cmd/gloak/main.go`
- Test: `internal/oidc/discovery_test.go`
- Test data: `internal/oidc/testdata/discovery-26.7.1.json`

**Interfaces:**
- Consumes: `store.Store`, `keys.RealmKeys`, `httpx.WriteMessageError`.
- Produces: `oidc.NewRouter(s store.Store, k *keys.RealmKeys, issuerBase string) http.Handler`.

- [ ] **Step 1: Capture the reference discovery document**

The key set is the contract, so it comes from the original rather than from
this plan.

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
mkdir -p internal/oidc/testdata
curl -s http://localhost:18091/realms/master/.well-known/openid-configuration \
  > internal/oidc/testdata/discovery-26.7.1.json
docker rm -f gloak-ref
```

Verify it holds 56 keys before continuing:

```bash
python3 -c "import json;print(len(json.load(open('internal/oidc/testdata/discovery-26.7.1.json'))))"
```

Expected output: `56`

- [ ] **Step 2: Write the failing test**

```go
package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/oidc"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	k, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return oidc.NewRouter(s, k, "http://localhost:8080")
}

func TestDiscoveryKeySetMatchesKeycloak(t *testing.T) {
	raw, err := os.ReadFile("testdata/discovery-26.7.1.json")
	if err != nil {
		t.Fatalf("read reference: %v", err)
	}
	var reference map[string]any
	if err := json.Unmarshal(raw, &reference); err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	var missing []string
	for k := range reference {
		if _, ok := got[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("discovery is missing %d keys Keycloak emits: %v", len(missing), missing)
	}
}

func TestDiscoveryEndpointsUseTheConfiguredIssuer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"issuer":                 "http://localhost:8080/realms/master",
		"authorization_endpoint": "http://localhost:8080/realms/master/protocol/openid-connect/auth",
		"token_endpoint":         "http://localhost:8080/realms/master/protocol/openid-connect/token",
		"jwks_uri":               "http://localhost:8080/realms/master/protocol/openid-connect/certs",
		"userinfo_endpoint":      "http://localhost:8080/realms/master/protocol/openid-connect/userinfo",
		"end_session_endpoint":   "http://localhost:8080/realms/master/protocol/openid-connect/logout",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: want %q, got %q", k, v, got[k])
		}
	}
}

func TestDiscoveryForUnknownRealm(t *testing.T) {
	// Measured: 404 with the bare-error shape and this exact message.
	req := httptest.NewRequest(http.MethodGet,
		"/realms/nosuchrealm/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("want 404, got %d", w.Code)
	}
	if got, want := w.Body.String(), `{"error":"Realm does not exist"}`; got != want {
		t.Fatalf("want %s, got %s", want, got)
	}
}

func TestJWKSServesOneRSAKey(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/protocol/openid-connect/certs", nil)
	w := httptest.NewRecorder()

	newServer(t).ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want one key, got %d", len(set.Keys))
	}
	if set.Keys[0].Kty != "RSA" || set.Keys[0].Alg != "RS256" || set.Keys[0].Use != "sig" {
		t.Fatalf("unexpected key: %+v", set.Keys[0])
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/oidc/`
Expected: FAIL, package `oidc` does not exist

- [ ] **Step 4: Write the discovery document and router**

`discovery.go` builds the document from the issuer base and the realm name. Every
endpoint is `{base}/realms/{realm}/protocol/openid-connect/{name}`; the algorithm
and capability arrays are copied from
`internal/oidc/testdata/discovery-26.7.1.json`, which the first test pins.

`router.go` wires a `http.ServeMux` using Go 1.22 path parameters:

```go
func NewRouter(s store.Store, k *keys.RealmKeys, issuerBase string) http.Handler {
	mux := http.NewServeMux()
	h := &handler{store: s, keys: k, issuerBase: issuerBase}
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/certs", h.certs)
	mux.HandleFunc("GET /realms/{realm}", h.realmInfo)
	return mux
}
```

Each handler resolves `r.PathValue("realm")` through `s.Realms().ByName`. On
`store.ErrNotFound` the discovery handler replies with
`httpx.WriteMessageError(w, 404, "Realm does not exist")`.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/oidc/ -v`
Expected: PASS, four tests

- [ ] **Step 6: Write the serve command**

`cmd/gloak/main.go` reads flags with `GLOAK_`-prefixed environment fallbacks
(`GLOAK_DB` selecting `sqlite` or `postgres`, `GLOAK_DSN`, `GLOAK_ADDR`,
`GLOAK_ISSUER`, `GLOAK_ADMIN_USER`, `GLOAK_ADMIN_PASSWORD`), opens the selected
store, calls `bootstrap.EnsureMaster`, generates realm keys, and serves
`oidc.NewRouter` over `http.Server` with `slog` request logging.

- [ ] **Step 7: Verify end to end by hand**

```bash
make build
GLOAK_DB=sqlite GLOAK_DSN=/tmp/gloak.db GLOAK_ADDR=:8080 ./gloak serve &
curl -s localhost:8080/realms/master/.well-known/openid-configuration | head -c 200
curl -s localhost:8080/realms/master/protocol/openid-connect/certs
kill %1
```

Expected: a discovery document whose `issuer` is `http://localhost:8080/realms/master`, and a JWKS containing exactly one RSA key.

- [ ] **Step 8: Run the whole suite**

Run: `make test`
Expected: PASS, no Docker required

- [ ] **Step 9: Commit**

```bash
git add internal/oidc/ cmd/
git commit -m "feat(oidc): serve discovery and jwks"
```

---

## What this plan deliberately leaves out

These belong to the following plans of the first slice, in this order:

1. **Tokens and direct grants** - `internal/token`, the `password` and
   `client_credentials` grants, the exact claim sets, RS256 for access and ID
   tokens against HS512 for refresh.
2. **Browser flow** - the authorization endpoint, the login form, PKCE S256, the
   composite authorization code, session cookies, `userinfo`, `logout`,
   `introspect`, `revoke`.
3. **Admin REST API** - representations, CRUD, role mappings, bearer
   authentication against tokens Gloak itself issued.
4. **Golden harness** - record and check modes, the normalisation rule list, the
   end-to-end test driven by `coreos/go-oidc`.

Each is planned separately, after the preceding one has been executed, so that
what is learned in the earlier phase reaches the later plan instead of being
guessed at now.
