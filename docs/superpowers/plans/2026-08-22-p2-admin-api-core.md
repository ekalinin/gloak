# P2 Admin API core implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve 24 Admin REST API operations on `clients` and `users`, each guarded by the `master-realm` client role Keycloak guards it with, and close the six P1 cases that have been waiting for a confidential client.

**Architecture:** A new `internal/admin` package holds the admin router, its authorization filter and its representations. Authorization resolves the caller the only way an `admin-cli` token allows - `sid` to session to user to role mappings - which needs a role-mapping model and the `master-realm` client's roles in `internal/bootstrap` first. The conformance harness gains three things before any of it: volatile header masking, capture from a response header, and an operation-aware parity meter.

**Tech Stack:** Go 1.26, `CGO_ENABLED=0`, `modernc.org/sqlite` and `jackc/pgx/v5`, `testcontainers-go` behind the `docker` tag.

**Spec:** `docs/superpowers/specs/2026-08-22-p2-admin-api-core-design.md`
**Observed contract:** `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

## Global constraints

Every constraint from `docs/superpowers/plans/2026-08-22-p1-token-foundation.md`
applies unchanged. The ones this plan leans on hardest:

- **Observable values are measured, never remembered.** Nothing in this plan
  writes an expected byte from the OpenAPI schema. The schema says an operation
  exists and what *may* appear in it; a running Keycloak says what does.
- **`internal/httpx` is the only place a response body is marshalled.**
- **Response structs declare fields in the measured order.** Never a
  `map[string]any`.
- **A store interface method is implemented in both drivers** and covered in
  `internal/store/storetest`.
- **`go test ./...` needs neither Docker nor network.**
- **`make test` is clean.** P1 removed the last sanctioned failure. Any failure
  is a regression.
- **Never commit to `main`.** This plan runs on `feat/p2-admin-api-core`.
- Commit messages `type(scope): subject`. No `Co-Authored-By`. No mention of
  tooling.
- **Do not use `git add -A`.** List paths explicitly. An earlier session swept
  an untracked file into a commit that way.

## Two things this plan will not do

**It will not derive `realm_access` from the new role mappings.** P2 adds
exactly the data a `roles` protocol mapper would read, and emitting it from
`internal/token` would be a two-line change. That model is P5 and the roadmap
carries it as debt. Half-building it here is how P5 turns into a rewrite.

**It will not implement Keycloak's fine-grained admin permissions.** Those are
Authorization Services policies on the admin client, which is P10. P2 does the
role check only.

## Measurement comes first

Three values this plan depends on are not in the observed-behaviour document:

1. the 21 role names on the `master-realm` client
2. the admin API's 403 shape for a caller lacking a role
3. the representations returned by each of the 24 operations

Task 4 measures the first two before anything depends on them. The third is
measured per slice, as each endpoint's golden is recorded. **No task may write
one of these from memory**, and a task blocked on Docker reports itself blocked
rather than guessing.

## File structure

| File | Responsibility |
|---|---|
| `internal/conformance/case.go` | `Operation` field, `VolatileHeaders` |
| `internal/conformance/fixture.go` | capture from a response header |
| `internal/conformance/coverage_test.go` | count distinct operations |
| `internal/conformance/catalog_admin.go` | new: the admin catalogue |
| `internal/model/model.go` | `RoleMapping`; composite membership on `Role` |
| `internal/store/store.go` | client roles, role mappings, list/search/update/delete |
| `internal/store/{sqlite,postgres}/migrations/0004_role_mapping.sql` | the tables |
| `internal/bootstrap/bootstrap.go` | `master-realm` roles, `admin` composite, assignment |
| `internal/admin/router.go` | new: routing and the realm prefix |
| `internal/admin/auth.go` | new: caller resolution and the role check |
| `internal/admin/representation.go` | new: the measured field sets |
| `internal/admin/clients.go`, `users.go`, `credentials.go` | the handlers |
| `cmd/gloak/main.go` | mount the admin router |

---

### Task 1: Volatile response headers

**Files:**
- Modify: `internal/conformance/case.go`
- Modify: `internal/conformance/golden.go`
- Modify: `internal/conformance/record_test.go`
- Modify: `internal/conformance/conformance_test.go`
- Modify: `internal/conformance/golden_test.go`

**Interfaces:**
- Produces: `Case.VolatileHeaders []string`, masking a named response header's
  value to `{{volatile}}` in both the recorder and the verifier.

This is the half of follow-up F12 P1 did not need. Every admin 201 carries a
`Location` holding a UUID minted at request time, so without it every create
case churns on each recording.

- [ ] **Step 1: Write the failing test**

In `internal/conformance/golden_test.go`, a test that a golden recorded with
`VolatileHeaders: []string{"Location"}` stores `Location: {{volatile}}`, and a
test in `conformance_test.go` that two different `Location` values compare
equal while a *missing* `Location` still fails. The second is the one that
matters: masking that also hides absence would let an endpoint stop sending the
header unnoticed.

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/`
Expected: `unknown field VolatileHeaders`.

- [ ] **Step 3: Implement**

Add the field with a doc comment saying what it is for and naming `Location` as
the measured example. Apply it in `recordedHeaders` and in `diff`'s
`gotByName` fold, in both cases *after* the captured-value masking already
there, so the two passes cannot fight.

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/conformance/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/conformance
git commit -m "feat(conformance): mask a volatile response header"
```

---

### Task 2: Capture from a response header

**Files:**
- Modify: `internal/conformance/fixture.go`
- Modify: `internal/conformance/fixture_test.go`

**Interfaces:**
- Consumes: Task 1's masking.
- Produces: `Step.CaptureHeader map[string]string` - variable name to header
  name - alongside the existing body-reading `Capture`.

Recording `GET .../clients/{uuid}` means creating a client first and reading its
UUID out of `Location`. `Capture` reads the body, and a 201 from the admin API
has no body at all.

- [ ] **Step 1: Write the failing test**

```go
func TestRunFixtureCapturesFromAHeader(t *testing.T) {
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:       Request{Method: http.MethodPost, Path: "/things"},
		CaptureHeader: map[string]string{"thing_id": "Location"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Header:     http.Header{"Location": {"http://localhost:8080/things/abc-123"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	vars, err := RunFixture(f, "http://localhost:8080", do)

	if err != nil {
		t.Fatalf("RunFixture: %v", err)
	}
	// The last path segment, not the whole URL: a case substitutes it into a
	// path, and the base URL differs between the recorder and the verifier.
	if vars["thing_id"] != "abc-123" {
		t.Fatalf("want abc-123, got %q", vars["thing_id"])
	}
}

func TestRunFixtureFailsOnAMissingHeader(t *testing.T) {
	// A capture that silently yields "" would substitute an empty path
	// segment and record a 404 as though it were the contract.
	f := Fixture{State: "bootstrap", Steps: []Step{{
		Request:       Request{Method: http.MethodPost, Path: "/things"},
		CaptureHeader: map[string]string{"thing_id": "Location"},
	}}}
	do := func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	_, err := RunFixture(f, "http://localhost:8080", do)

	if err == nil {
		t.Fatal("a fixture capturing an absent header reported success")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestRunFixture`
Expected: `unknown field CaptureHeader`.

- [ ] **Step 3: Implement**

`CaptureHeader` reads the named header, takes the final path segment when the
value parses as a URL, and errors when the header is absent. Captured values
join the same `vars` map, so `ReplaceCaptured` already masks them out of the
recorded response - which is what stops a fresh UUID churning the golden.

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/conformance/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/conformance
git commit -m "feat(conformance): let a fixture capture a value from a response header"
```

---

### Task 3: A parity meter that counts operations

**Files:**
- Modify: `internal/conformance/case.go`
- Modify: `internal/conformance/openapi.go`
- Modify: `internal/conformance/coverage_test.go`
- Modify: `internal/conformance/catalog_test.go`

**Interfaces:**
- Produces: `Case.Operation string`, holding `METHOD path` as the vendored
  description spells it; `conformance.Operations() (map[string]bool, error)`
  returning every `METHOD path` in the description.

`TestCoverage` computes a chapter's `served` as its number of `Implemented`
cases while the admin denominator is an operation count. Three cases for one
endpoint would report "3 of 34 served" - overcounting hardest where the error
handling is most careful.

**The key is `METHOD path`, not `operationId`.** The description carries no
`operationId` on any of its 413 operations. Do not add one; do not derive one.

- [ ] **Step 1: Write the failing tests**

```go
func TestOperationsAreKeyedByMethodAndPath(t *testing.T) {
	ops, err := Operations()
	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	if len(ops) != 413 {
		t.Fatalf("want 413 operations, got %d", len(ops))
	}
	if !ops["GET /admin/realms/{realm}/clients"] {
		t.Fatal("the clients list operation is missing")
	}
}

func TestAdminCasesNameARealOperation(t *testing.T) {
	ops, err := Operations()
	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	byName := map[string]Chapter{}
	for _, ch := range Chapters {
		byName[ch.Name] = ch
	}
	for _, c := range Catalog {
		ch := byName[chapterOf(c.ID)]
		if ch.OpenAPITag == "" {
			continue // protocol chapters have no operation list
		}
		if c.Operation == "" {
			t.Errorf("%q is in an OpenAPI-counted chapter and names no operation", c.ID)
			continue
		}
		if !ops[c.Operation] {
			t.Errorf("%q names operation %q, which is not in the description", c.ID, c.Operation)
		}
	}
}

// servedOperations is the counting rule TestCoverage uses, extracted so it can
// be tested without reading log output.
func TestServedOperationsCountsEachOperationOnce(t *testing.T) {
	// Two Implemented cases on one operation count once. Without this the
	// meter rewards writing more error cases for an endpoint already served.
	cases := []Case{
		{ID: "admin/users/list", Status: Implemented, Operation: "GET /admin/realms/{realm}/users"},
		{ID: "admin/users/list-forbidden", Status: Implemented, Operation: "GET /admin/realms/{realm}/users"},
		{ID: "admin/users/read", Status: Implemented, Operation: "GET /admin/realms/{realm}/users/{user-id}"},
		{ID: "admin/users/create", Status: Pending, Operation: "POST /admin/realms/{realm}/users"},
	}

	if got := servedOperations(cases); got != 2 {
		t.Fatalf("want 2 distinct served operations, got %d", got)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/conformance/`
Expected: `undefined: Operations`.

- [ ] **Step 3: Implement**

`Operations()` walks the same `paths` map `OperationsByTag` already walks,
filtering by HTTP method before touching anything else - the reason that filter
exists is a path item's `parameters` key, which holds an array, not an
operation. Return `map[string]bool` keyed `strings.ToUpper(method) + " " + path`.

In `TestCoverage`, a chapter with an `OpenAPITag` counts distinct
`c.Operation` values among its `Implemented` cases. Chapters without one keep
counting cases, which is what `source: catalogue` already tells the reader.

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/conformance/` then `make conformance`
Expected: PASS, and the printed total unchanged at 25 of 483 - no admin case
exists yet, so nothing should move.

- [ ] **Step 5: Commit**

```bash
git add internal/conformance
git commit -m "feat(conformance): count served admin operations, not cases"
```

---

### Task 4: Measure what P2 depends on

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

**Needs Docker.** If Docker is unavailable, stop and report the task blocked.
Every later task depends on these values and none may guess them.

- [ ] **Step 1: Start a reference container**

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
```

- [ ] **Step 2: Measure the `master-realm` client's roles**

Obtain an admin token, find the `master-realm` client's UUID, list its roles.
Record the full set of names, and for each the `composite` flag, into a new
"Admin roles on the master-realm client" section of the observed document.

- [ ] **Step 3: Measure the admin API's 403 shape**

Create a user with `view-users` and not `manage-users`, obtain a token for it
through `admin-cli`, and call a write operation. Record the status, body, and
every header, including whether the five security headers are present.

Also record the 401 shape for a request with no `Authorization` header at all,
and for one with a garbage bearer token. The admin API is a different chapter
from `userinfo` and its rejection shapes must not be assumed to match.

- [ ] **Step 4: Measure the admin API's 404 shape**

`GET /admin/realms/master/users/{a-uuid-that-does-not-exist}`. AGENTS.md
already records that "Realm not found." has a trailing period on the admin API
and none on the protocol endpoint, so this family is known to differ; do not
extrapolate from the protocol 404.

- [ ] **Step 5: Write it all down and tear the container down**

```bash
docker rm -f gloak-ref
```

Every value goes into the observed-behaviour document with the date it was
measured. Values not written there do not exist.

- [ ] **Step 6: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md
git commit -m "docs(observed): record the admin API's roles and rejection shapes"
```

---

### Task 5: Role mappings in the store

**Files:**
- Modify: `internal/model/model.go`
- Modify: `internal/store/store.go`
- Create: `internal/store/sqlite/migrations/0004_role_mapping.sql`
- Create: `internal/store/postgres/migrations/0004_role_mapping.sql`
- Modify: `internal/store/{sqlite,postgres}/*.go`
- Modify: `internal/store/storetest/conformance.go`

**Interfaces:**
- Produces, on `RoleRepo`:

```go
	ByID(ctx context.Context, realmID, id string) (*model.Role, error)
	ListClientRoles(ctx context.Context, realmID, clientID string) ([]*model.Role, error)
	AddComposite(ctx context.Context, roleID, childRoleID string) error
	ListComposites(ctx context.Context, roleID string) ([]*model.Role, error)
	AssignToUser(ctx context.Context, userID, roleID string) error
	RemoveFromUser(ctx context.Context, userID, roleID string) error
	ListUserRoles(ctx context.Context, userID string) ([]*model.Role, error)
```

`Role` already carries `ClientID` and `Composite`, and `ListRealmRoles` already
filters on an empty `client_id`, so client roles need no schema change - only
the query. Composite membership and user assignment need two join tables.

- [ ] **Step 1: Write the failing store conformance tests**

Append to `RunConformance`: client roles are listed separately from realm roles
and do not leak into `ListRealmRoles`; a role assigned to a user comes back from
`ListUserRoles`; assigning twice is `ErrConflict`; removing a role that is not
assigned is `ErrNotFound`; composites round-trip; and deleting a user removes
its assignments through the cascade.

- [ ] **Step 2: Run to verify they fail**

Run: `CGO_ENABLED=0 go test ./internal/store/...`
Expected: compile failure on the new methods.

- [ ] **Step 3: Write both migrations**

```sql
CREATE TABLE user_role_mapping (
    user_id TEXT NOT NULL REFERENCES user_entity(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE composite_role (
    composite TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    child_role TEXT NOT NULL REFERENCES keycloak_role(id) ON DELETE CASCADE,
    PRIMARY KEY (composite, child_role)
);
```

Identical in both drivers; neither table has a typed column, so there is no
`INTEGER`/`BIGINT` split this time.

- [ ] **Step 4: Implement both repositories**

Follow `keyRepo` and `sessionRepo` from P1. `RemoveFromUser` checks the affected
row count and returns `ErrNotFound` on zero, the way `DeleteUserSession` does -
neither driver reports a no-op delete as an error.

- [ ] **Step 5: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/store/...` then
`go test -tags docker ./internal/store/postgres/`
Expected: PASS on both. Report explicitly if Docker was unavailable.

- [ ] **Step 6: Commit**

```bash
git add internal/model internal/store
git commit -m "feat(store): persist role mappings and composite roles"
```

---

### Task 6: Bootstrap the admin role container

**Files:**
- Modify: `internal/bootstrap/bootstrap.go`
- Modify: `internal/bootstrap/bootstrap_test.go`

**Interfaces:**
- Consumes: Task 5's `RoleRepo`, Task 4's measured role names.

**Every role name in this task comes from Task 4's recording.** The 21 names are
measured; do not type them from the Keycloak documentation.

- [ ] **Step 1: Write the failing test**

That a bootstrapped master realm has the measured role set on the `master-realm`
client, that `admin` is composite over them, and that the admin user holds
`admin`. Assert the *set* against a slice declared from the recording, so a
missing or invented role fails.

- [ ] **Step 2: Run to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/bootstrap/`
Expected: FAIL, no client roles exist.

- [ ] **Step 3: Implement**

Extend `EnsureMaster`, keeping its converging shape: every object ensured
individually, existing objects never modified, safe on every process start.

- [ ] **Step 4: Run the tests**

Run: `CGO_ENABLED=0 go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/bootstrap
git commit -m "feat(bootstrap): create the master-realm client's admin roles"
```

---

### Task 7: The admin router and caller resolution

**Files:**
- Create: `internal/admin/router.go`, `internal/admin/auth.go`
- Create: `internal/admin/auth_test.go`
- Modify: `cmd/gloak/main.go`
- Modify: `internal/conformance/server_test.go`
- Create: `internal/conformance/catalog_admin.go`
- Modify: `internal/conformance/chapters.go` if a chapter needs adding

**Interfaces:**
- Produces: `admin.NewRouter(s store.Store, k *keys.Manager, issuerBase string) http.Handler`,
  and a `caller` carrying the resolved user and its effective role set.

- [ ] **Step 1: Add the first two conformance cases**

`admin/users/list-unauthenticated` and `admin/users/list-garbage-token`, both
`Fixture: "bootstrap"` and both naming
`Operation: "GET /admin/realms/{realm}/users"`. Then `make record` to write
their goldens - Task 4 measured these shapes into the observed document, but a
golden is written by the recorder, never by hand. Set them `Recorded` once the
goldens exist.

- [ ] **Step 2: Run and read the brief**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/admin'`
Expected: both `Recorded` cases skip with a mismatch, which is the state they
should be in before the router exists.

- [ ] **Step 3: Write the resolution chain**

```go
// resolveCaller turns a bearer token into the roles its owner holds. It goes
// through the session rather than through the token's claims, because an
// admin-cli access token carries neither sub nor realm_access - measured, and
// the reason section 4.1 of the P1 design gave for this being the only route.
func (h *handler) resolveCaller(r *http.Request, realm *model.Realm) (*caller, error)
```

Effective roles are the user's direct assignments plus the transitive closure of
composites. Compute the closure iteratively with a seen-set: `admin` is
composite over 21 roles and a cycle in the data must not hang the server.

- [ ] **Step 4: Flip the two cases and make them pass**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/admin'`
Expected: PASS against the measured 401 shapes.

- [ ] **Step 5: Mount it**

`cmd/gloak/main.go` and `internal/conformance/server_test.go` both build a
handler; the admin router mounts alongside the OIDC one. Keep
`withKeycloakFallbacks`'s behaviour intact - an unmatched admin path must still
produce the measured protocol-level 404, not a new shape.

- [ ] **Step 6: Run everything and commit**

```bash
CGO_ENABLED=0 go test ./...
git add internal/admin internal/conformance cmd
git commit -m "feat(admin): resolve the caller from the session behind a token"
```

---

### Task 8: The role check

**Files:**
- Modify: `internal/admin/auth.go`, `internal/admin/router.go`
- Modify: `internal/admin/auth_test.go`
- Modify: `internal/conformance/catalog_admin.go`

- [ ] **Step 1: Add the 403 case**

`admin/users/list-without-view-users`, `Recorded`, from Task 4's measurement.
Its fixture creates a user holding a deliberately narrow role set, which is why
this case comes after Task 7 rather than with it.

- [ ] **Step 2: Write the failing unit test**

That an operation declaring `view-users` is refused to a caller without it and
allowed to one with it; that `admin`, being composite, satisfies both; and that
the refusal carries the measured body.

- [ ] **Step 3: Implement**

Each route declares the role it requires next to its handler, so the pairing is
visible at the routing table rather than buried in the handler. A route with no
declared role is a compile-time-visible mistake, not a silent allow: make the
registration helper require one.

- [ ] **Step 4: Run and commit**

```bash
CGO_ENABLED=0 go test ./...
git add internal/admin internal/conformance
git commit -m "feat(admin): require a per-operation role"
```

---

### Task 9: Client representation, list and read

**Closes:** `GET /clients`, `GET /clients/{uuid}`

**Files:**
- Create: `internal/admin/representation.go`, `internal/admin/clients.go`
- Modify: `internal/store/store.go` and both drivers, for client search
- Modify: `internal/conformance/catalog_admin.go`

- [ ] **Step 1: Record the contract**

Add the cases, run `make record`, read the diff. `ClientRepresentation` is 26
fields as returned by the list endpoint - the observed document says so - and
**the single-read endpoint's field set is not assumed to match it**. Record
both.

- [ ] **Step 2: Declare the representation from the recording**

Transcribe the field order out of the golden, not out of the OpenAPI schema.
Add a comment above the struct naming the golden it came from.

- [ ] **Step 3: Flip to Implemented, run, and read the diffs**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run 'TestConformance/admin/clients'`

- [ ] **Step 4: Implement until green, then commit**

```bash
git add internal/admin internal/store internal/conformance
git commit -m "feat(admin): list and read clients"
```

---

### Task 10: Client create, update and delete

**Closes:** `POST /clients`, `PUT /clients/{uuid}`, `DELETE /clients/{uuid}`

This is the task that unblocks P1's leftovers, so it comes before the secret
endpoints.

- [ ] **Step 1: Record the contract**

The 201's `Location` is what Task 1 and Task 2 exist for. Record the create
response's status, its `Location`, and whether it carries a body at all - do not
assume it is empty.

- [ ] **Step 2: Implement create, update and delete**

Validation shapes - a duplicate `clientId`, a missing required field - are
measured, not invented. Record a case for each rather than choosing a status.

- [ ] **Step 3: Run and commit**

```bash
git add internal/admin internal/store internal/conformance
git commit -m "feat(admin): create, update and delete clients"
```

---

### Task 11: Client secrets and the service account user

**Closes:** `GET` and `POST /clients/{uuid}/client-secret`, `GET` and `DELETE
/clients/{uuid}/client-secret/rotated`, `GET /clients/{uuid}/service-account-user`

- [ ] **Step 1: Record the contract**

Including what `GET .../client-secret/rotated` returns when nothing has been
rotated, which is exactly the kind of value nobody would guess correctly.

- [ ] **Step 2: Implement**

Rotation needs a second secret column with an expiry. Add it in the same
migration style as Task 5.

**Amended after the recording, 2026-08-23: no such column was added.**
`CLIENT_SECRET_ROTATION` is a preview feature disabled by default and
`secret-rotation` is not a registered client-policy executor, so no client on
this distribution can hold a rotated secret. The endpoints answer a constant
404 and a constant 204, and that is the measured contract in full. A column
modelling a state that cannot occur would be dead schema in both drivers.

`GET .../service-account-user` returns the account P1 creates on demand as
`service-account-<clientId>`. **This is the operation that measures whether that
convention is right.** If the recording disagrees, P1's guess was wrong and
`internal/oidc/token.go` gets corrected in this task, not left for later.

- [ ] **Step 3: Run and commit**

```bash
git add internal/admin internal/store internal/oidc internal/conformance
git commit -m "feat(admin): manage client secrets and read the service account"
```

---

### Task 12: Close P1's leftovers and F15

**Closes:** `oidc/userinfo/get-with-valid-token`, `post-with-valid-token`,
`oidc/introspection/active-access-token`, `active-refresh-token`,
`inactive-token`, `oidc/token/client-credentials-grant`

**Needs Docker.**

The point of putting `clients` first. A confidential client with a known secret
is now creatable, so the six bodies follow-up F15 describes as
served-but-unmeasured can be recorded.

- [ ] **Step 1: Give each case a fixture that creates its client**

The fixture chains: obtain an admin token, create a confidential client
capturing its UUID from `Location`, read or set its secret, then obtain a token
as that client. Every piece exists after Tasks 1, 2, 10 and 11.

- [ ] **Step 2: Record, and read the diff against what P1 guessed**

Run: `make record`

The measured bodies are compared against `userinfoDocument`,
`introspectionDocument` and `tokenResponse` as P1 left them. **Expect
differences.** Those structs were derived from the ID-token claim set and RFC
7662, and the code says so in as many words.

- [ ] **Step 3: Correct the three response types and flip the six cases**

- [ ] **Step 4: Also settle `oidc/userinfo/expired-token`**

The spec lists it as a candidate rather than a deliverable: its blocker is
waiting out a 60-second token, and whether a client attribute can shorten the
lifespan is a guess about Keycloak, not a measurement. Try it. If it works,
record the case; if it does not, write down what was tried in the case comment
and leave it `Pending`.

- [ ] **Step 5: Close F15 and commit**

```bash
git add internal/oidc internal/conformance docs
git commit -m "feat(oidc): record the response bodies P1 could not reach"
```

---

### Task 13: User representation, list, count and read

**Closes:** `GET /users`, `GET /users/count`, `GET /users/{id}`

- [ ] **Step 1: Record the contract**

`UserRepresentation` for the bootstrapped admin is 11 fields:

```
access, attributes, createdTimestamp, disableableCredentialTypes,
emailVerified, enabled, id, notBefore, requiredActions, totp, username
```

`totp` and `disableableCredentialTypes` are legacy fields Keycloak still emits;
`access` is a computed permissions block. Record the list endpoint and the
single-read endpoint separately - they are not assumed to agree - and record a
search with `?username=`, `?search=` and `?briefRepresentation=true`, since
those change the field set.

- [ ] **Step 2: Implement**

`access` is computed from the *caller's* roles, not the target user's. Getting
this backwards produces a plausible response that is wrong for every caller but
one.

- [ ] **Step 3: Run and commit**

```bash
git add internal/admin internal/store internal/conformance
git commit -m "feat(admin): list, count and read users"
```

---

### Task 14: User create, update and delete

**Closes:** `POST /users`, `PUT /users/{id}`, `DELETE /users/{id}`

Same shape as Task 10, including recording the validation shapes rather than
choosing them. A duplicate username and a malformed body each get a case.

- [ ] **Step 1: Record, implement, run, commit**

```bash
git add internal/admin internal/store internal/conformance
git commit -m "feat(admin): create, update and delete users"
```

---

### Task 15: Credentials

**Closes:** `PUT /users/{id}/reset-password`, `GET` and `DELETE on
/users/{id}/credentials`, `moveAfter`, `moveToFirst`, `userLabel`,
`PUT /users/{id}/disable-credential-types`

**Files:**
- Create: `internal/admin/credentials.go`
- Modify: `internal/model/model.go`, `internal/store/store.go`, both drivers

`Credential` gains `Label` and `Priority`, and `UserRepo` gains list, delete and
reorder. `SetCredential` currently upserts on `(user_id, type)`, which allows
exactly one credential per type; the reorder endpoints only mean something once
that constraint is relaxed. **Relaxing it changes P1's password lookup**, so
`CredentialByUser` must keep returning a deterministic row - the
highest-priority one - and its test must say so.

Hashing on reset reuses `internal/bootstrap`'s parameters. Those are the
creation parameters, which is correct here: this endpoint creates a password.
`internal/auth` keeps reading its parameters from the stored credential.

- [ ] **Step 1: Record the contract, including what reset-password returns**

- [ ] **Step 2: Extend the model and both drivers, with storetest coverage**

- [ ] **Step 3: Implement, run, commit**

```bash
git add internal/model internal/store internal/admin internal/conformance
git commit -m "feat(admin): manage a user's credentials"
```

---

### Task 16: User logout

**Closes:** `POST /users/{id}/logout`

Deletes every session the user holds. P1's `SessionRepo` deletes one session by
ID; this needs a delete-by-user, which is a store method and therefore both
drivers plus `storetest`.

Record what the endpoint returns - a 204 is likely and is still a guess until
recorded.

- [ ] **Step 1: Record, extend the store, implement, run, commit**

```bash
git add internal/store internal/admin internal/conformance
git commit -m "feat(admin): log out all of a user's sessions"
```

---

### Task 17: An oracle nobody here wrote

**Files:**
- Create: `internal/admin/kcadm_docker_test.go` (build tag `docker`)

`kcadm.sh` ships inside the Keycloak image, so it needs no separate install: run
it in a container pointed at a Gloak served over the loopback.

Its useful subset today is create, read, update and delete on a client and on a
user. `kcadm` usually starts by creating a realm, which is P4, so the test
authenticates against `master` directly and does no more than the subset above.
The roadmap's caveat stands and belongs in the test's doc comment: this becomes
a real oracle after P4 and P5, and until then it proves a narrow thing.

- [ ] **Step 1: Write it, run it, commit**

```bash
go test -tags docker ./internal/admin/
git add internal/admin
git commit -m "test(admin): drive the admin API with kcadm.sh"
```

---

### Task 18: Close the first cut in the documents

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md`
- Modify: `docs/superpowers/specs/2026-08-18-gloak-followups.md`
- Modify: `docs/superpowers/specs/2026-08-22-p2-admin-api-core-design.md`
- Modify: `AGENTS.md` if the recordings turned up new traps

- [ ] **Step 1: Read the meter**

Run: `make conformance`. Record what it prints; do not predict it. Expect
`admin/clients 10 of 35` and `admin/users 14 of 34` at most, and section 1.1 of
the spec is the explanation for the remainder.

- [ ] **Step 2: Update the README, the roadmap and the follow-ups**

Close F15. Add any new follow-up the recordings created - the admin API is a
large surface and it would be surprising if it created none.

- [ ] **Step 3: Mark the spec implemented and write its closing section**

What shipped, what stayed unmeasured, and the debt handed on - the same three
headings P1's spec ends with, because they are the three things the next
sub-project needs.

- [ ] **Step 4: Final verification**

```bash
CGO_ENABLED=0 go test ./...
go test -tags docker ./internal/store/postgres/
make lint
make build
gofmt -l .
```

`gofmt -l` exits 0 whether or not it prints anything. Read its output rather
than chaining on its exit status.

- [ ] **Step 5: Commit**

```bash
git add README.md AGENTS.md docs
git commit -m "docs: close P2's first cut"
```

---

## What this plan deliberately does not do

- **The 45 operations section 1.1 of the spec attributes elsewhere.** Each is
  named there with its owner.
- **P2's other five resource groups.** `Roles`, `Roles (by ID)`, `Groups`,
  `Role Mapper`, `Client Role Mappings` get a second spec once this cut is
  serving and the shape of the work is known from having done it.
- **Deriving token claims from role mappings.** P5.
- **Fine-grained admin permissions as policies.** P10.
