# P2 second cut, part two: role mappings on a user

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the 11 `Role Mapper` and `Client Role Mappings` operations that
act on a user, and close **F28** - the privilege-escalation path the first half
left open on purpose.

**Architecture:** Everything this needs already exists.
`RoleRepo.AssignToUser`/`RemoveFromUser`/`ListUserRoles` have been in the store
since the foundation slice, `internal/roles.Effective` expands composites, and
`roleRepresentation` was built in the roles half. This adds one handler file,
one resolver, and the caller-relative authorization rule F28 names.

**Tech Stack:** Go 1.26, `CGO_ENABLED=0`, `net/http.ServeMux` routing,
`modernc.org/sqlite` and `jackc/pgx/v5` behind one `store.Store`, testcontainers
behind the `docker` build tag.

## What the previous half taught, and what it costs to ignore

The roles half wrote down a guard rule from expectation **five times** and was
wrong **four**. Once it was not merely wrong but a different shape entirely:
`/roles/{name}/users` needs a *conjunction* of two role families where its three
siblings need one role from one family. Twice a rule measured on `POST` was
extended to `DELETE` "for consistency" and had to be reverted, because Keycloak
was more permissive than the extension.

So, binding on every task here:

- **A guard is measured before it is registered.** Not inferred from a sibling,
  however many siblings agree. The observed document already records
  `view-users` to read and `manage-users` to write for this whole family - that
  is one measurement of one caller set, and the roles half showed what a single
  measurement misses. Re-measure with the full single-role sweep, and test pairs
  if nothing single-role opens a route.
- **Mint a fresh token immediately before each probe.** A stale token produced a
  false 403 on the last branch and cost a full re-measurement round.
- **Report raw request and response text, not summary tables.** A reviewer
  cannot check a table against anything.
- **Check helper names against the file before using them.** Eight defects on
  the last branch were plan code written from memory: helpers that do not exist,
  a table named `role` that is `keycloak_role`, a test that creates the same
  user twice.
- **A bodyless `DELETE` uses the `do(...)` test helper, not `sendJSON`.**
  `httpx.WriteNoContent` emits `X-Frame-Options` only for an `application/*`
  request Content-Type. These endpoints' `DELETE`s **do** send a JSON body, so
  here `sendJSON` is right - which is exactly why the distinction has to be
  thought about rather than copied.

## Why this plan carries less code than the last one

The roles plan spelled out every handler and every test verbatim, on the
principle that a plan should contain what an engineer needs rather than a
description of it. Eight of those transcriptions were **wrong** - helpers that
do not exist, a table named `role` that is `keycloak_role`, a column list
missing two `NOT NULL` fields, a test that creates the same user twice - and
every one was caught by an implementer reading the actual file. A ninth was
caught while self-reviewing this document.

So the code below is spelled out where it encodes a **measurement** or a
decision that is easy to get subtly wrong, and reduced to precise instructions
where it is mechanical and the real shape is already in the repository. Where a
task says "shaped like Task N's", that is not an invitation to skip it: it means
the neighbouring task's code is the reference and it is in the tree, correct and
tested, rather than in this document, transcribed and possibly wrong.

Read the file before you copy from here. Every time.

## Global constraints

From `AGENTS.md`, which applies in full:

- **Observable values are measured, never remembered.** The contract of record
  is `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`. Anything
  not in it gets measured against a live `quay.io/keycloak/keycloak:26.7.1` and
  written there in the same task.
- `internal/httpx` owns all response body formatting.
- The two store drivers must not diverge; `internal/store/storetest` is what
  proves it.
- Code comments in English. Minimal diff, existing names preserved.
- Never `git add -A`. Commit and push are separate commands.
- Commit messages `type(scope): subject`, type one of feat/fix/docs/refactor/
  perf/chore. No Co-Authored-By. No mention of Claude or Claude Code.

## File structure

| File | Responsibility |
|---|---|
| `internal/admin/rolemappings.go` | **new** - every handler in this plan |
| `internal/admin/representation.go` | the two mapping-view shapes |
| `internal/admin/users.go` | `resolveUser`, extracted from the four inline copies |
| `internal/admin/router.go` | the 11 routes |
| `internal/admin/roles.go` | F28's predicate, shared with the composite writes |
| `internal/conformance/catalog_admin.go` | the cases |

`rolemappings.go` is separate from `roles.go` because the two resources are
guarded by different things: a role endpoint is judged by the role's container,
a mapping endpoint by the **subject**. Keeping them in one file is how the two
rules get confused.

---

## Task 1: resolve a user once, in one place

Four handlers in `internal/admin/users.go` open with the same eight lines:
`Users().ByID`, `errors.Is(err, store.ErrNotFound)`, `writeUserNotFound`, the
500. Eleven more are about to.

**Files:**
- Modify: `internal/admin/users.go`
- Test: `internal/admin/users_test.go`

**Interfaces:**
- Produces: `func (h *handler) resolveUser(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.User, bool)`, used by every task below.

- [ ] **Step 1: Write the failing test**

```go
// resolveUser is the one place a {userID} becomes a user. The 404 body is
// measured and shared by every endpoint that takes one.
func TestResolveUserWritesTheMeasuredNotFound(t *testing.T) {
	h, _, _ := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")

	w := get(t, h, "/admin/realms/master/users/00000000-0000-0000-0000-000000000000", admin)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); body != `{"error":"User not found"}` {
		t.Fatalf("unexpected 404 body: %s", body)
	}
}
```

`writeUserNotFound` goes through `httpx.WriteMessageError`, which emits
`{"error":...}`; `httpx.WriteAdminError` emits `{"errorMessage":...}` and is
what the 409 conflicts use. **Verified against the source, not remembered** -
the first draft of this step asserted `errorMessage` and was wrong, in the very
step that warns about this. That is the ninth instance of the same failure mode
on this sub-project: plan code written from memory instead of read from the
file. Assume the same bug is elsewhere in this document and check before you
transcribe.

- [ ] **Step 2: Run it**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -run TestResolveUser -v`

Expected: PASS already, since `readUser` serves this path today. That is the
point - this test pins the behaviour *before* the refactor, so the refactor
cannot change it silently.

- [ ] **Step 3: Extract the helper**

In `internal/admin/users.go`:

```go
// resolveUser turns {userID} into a user, writing the measured 404 and
// returning false when there is none.
//
// Every endpoint that takes a user ID goes through this. It exists because the
// role-mapping endpoints added eleven more callers to what was already four
// copies of the same eight lines, and a fifth spelling of "User not found"
// would have been indistinguishable from a real divergence.
func (h *handler) resolveUser(w http.ResponseWriter, r *http.Request, rc *reqContext) (*model.User, bool) {
	user, err := h.store.Users().ByID(r.Context(), rc.realm.ID, r.PathValue("userID"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeUserNotFound(w)
			return nil, false
		}
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return nil, false
	}
	return user, true
}
```

- [ ] **Step 4: Route the existing callers through it**

`readUser`, `updateUser`, `deleteUser` and `logoutUser` each lose their inline
copy. Do not change any behaviour: same status, same body, same order relative
to whatever else the handler does first.

- [ ] **Step 5: Run the whole admin suite**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -count=1`

Expected: PASS, unchanged. A refactor that moves a test is a refactor that
changed behaviour.

- [ ] **Step 6: Commit**

```bash
git add internal/admin/users.go internal/admin/users_test.go
git commit -m "refactor(admin): resolve a user in one place"
```

---

## Task 2: reading a user's realm roles

Serves `GET /users/{id}/role-mappings/realm`, `.../realm/available` and
`.../realm/composite` - three operations that answer three different questions
and are easy to conflate.

**Files:**
- Create: `internal/admin/rolemappings.go`
- Modify: `internal/admin/router.go`
- Test: `internal/admin/rolemappings_test.go` (new)

**Interfaces:**
- Consumes: `resolveUser` (Task 1); `roleRepresentationOf` and `briefRoles` (roles half); `RoleRepo.ListUserRoles`, `ListRealmRoles`; `roles.Effective`.
- Produces: `func (h *handler) listRealmMappings/availableRealmMappings/compositeRealmMappings(w, r, rc)`.

- [ ] **Step 1: Measure the guards before writing the routes**

The observed document records `view-users` to read and `manage-users` to write
for this family. That is one measurement. Sweep it properly:

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
```
Docker needs `DOCKER_HOST=unix:///Users/shorrty/.colima/default/docker.sock`.
Create one user per role - `view-users`, `manage-users`, `query-users`,
`view-realm`, `manage-realm`, `view-clients`, `manage-clients` - and call all
three read endpoints as each, minting a fresh token immediately before each
call. If nothing single-role opens a route, test pairs: `/roles/{name}/users`
needed a conjunction and nobody expected it.

Record the sweep in the observed document with raw text. Register the routes to
match. Keep the container up - Task 3 needs it.

- [ ] **Step 2: Write the failing test**

```go
// The three realm-mapping reads answer three different questions, and the
// difference is the whole point of the endpoints. Measured on the bootstrapped
// administrator, which holds admin and default-roles-master directly.
func TestRealmMappingReadsAnswerThreeDifferentQuestions(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/realm"

	direct := mappingNames(t, h, base, admin)
	if want := []string{"admin", "default-roles-master"}; !slices.Equal(direct, want) {
		t.Fatalf("direct: want %v, got %v", want, direct)
	}

	// The transitive expansion: admin is composite over create-realm, and
	// default-roles-master over offline_access and uma_authorization.
	composite := mappingNames(t, h, base+"/composite", admin)
	want := []string{"admin", "create-realm", "default-roles-master", "offline_access", "uma_authorization"}
	if !slices.Equal(composite, want) {
		t.Fatalf("composite: want %v, got %v", want, composite)
	}

	// available is "not assigned **directly**", which is not the complement of
	// composite. create-realm appears in both: the administrator effectively
	// holds it through admin, and it is still offered because it is not
	// assigned directly. Measured, and the single most misreadable of the three.
	available := mappingNames(t, h, base+"/available", admin)
	if slices.Contains(available, "admin") {
		t.Fatal("available offered a directly assigned role")
	}
	if !slices.Contains(available, "create-realm") {
		t.Fatal("available dropped a role reachable through a composite; " +
			"it is the complement of direct, not of composite")
	}
}

// mappingNames reads a role-mapping listing and returns the names, sorted.
func mappingNames(t *testing.T, h http.Handler, path, token string) []string {
	t.Helper()
	w := get(t, h, path, token)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	var reps []roleRepresentation
	if err := json.Unmarshal(w.Body.Bytes(), &reps); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	names := make([]string, 0, len(reps))
	for _, r := range reps {
		names = append(names, r.Name)
	}
	sort.Strings(names)
	return names
}
```

`userID` may or may not exist as a test helper - check `internal/admin` before
adding one, and reuse `clientUUID`'s shape if you do add it.

- [ ] **Step 3: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -run TestRealmMappingReads -v`

Expected: FAIL with the fallback 404 - the routes do not exist.

- [ ] **Step 4: Implement**

Create `internal/admin/rolemappings.go`:

```go
package admin

import (
	"net/http"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/roles"
)

// listRealmMappings serves GET /users/{id}/role-mappings/realm: the realm roles
// assigned **directly**, with no composite expansion.
func (h *handler) listRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.resolveUser(w, r, rc)
	if !ok {
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeMappingList(w, r, realmRolesOnly(direct), rc.realm.ID)
}

// compositeRealmMappings serves .../realm/composite: the transitive expansion.
func (h *handler) compositeRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.resolveUser(w, r, rc)
	if !ok {
		return
	}
	effective, err := roles.Effective(r.Context(), h.store.Roles(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeMappingList(w, r, realmRolesOnly(effective), rc.realm.ID)
}

// availableRealmMappings serves .../realm/available: every realm role **not
// directly assigned**.
//
// It is the complement of the direct list, not of the composite one. Measured:
// create-realm is in the administrator's composite expansion *and* in its
// available list, because the administrator reaches it through admin without
// holding it directly. Computing this from the effective set would silently
// drop it.
func (h *handler) availableRealmMappings(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	user, ok := h.resolveUser(w, r, rc)
	if !ok {
		return
	}
	all, err := h.store.Roles().ListRealmRoles(r.Context(), rc.realm.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	direct, err := h.store.Roles().ListUserRoles(r.Context(), user.ID)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeMappingList(w, r, without(all, direct), rc.realm.ID)
}

// realmRolesOnly keeps the roles that belong to the realm rather than a client.
func realmRolesOnly(in []*model.Role) []*model.Role {
	out := make([]*model.Role, 0, len(in))
	for _, r := range in {
		if r.ClientID == "" {
			out = append(out, r)
		}
	}
	return out
}

// without returns the roles in all that are not in exclude, by id.
func without(all, exclude []*model.Role) []*model.Role {
	held := make(map[string]bool, len(exclude))
	for _, r := range exclude {
		held[r.ID] = true
	}
	out := make([]*model.Role, 0, len(all))
	for _, r := range all {
		if !held[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

// writeMappingList is the body every mapping listing sends. The role
// representation is the roles half's; whether it is the brief or the full shape
// is measured per endpoint, not assumed - see the task's measurement step.
func (h *handler) writeMappingList(w http.ResponseWriter, r *http.Request, in []*model.Role, realmID string) {
	out := make([]roleRepresentation, 0, len(in))
	for _, role := range in {
		container := realmID
		if role.ClientID != "" {
			container = role.ClientID
		}
		out = append(out, roleRepresentationOf(role, container, true))
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}
```

**`writeMappingList` hardcodes the brief shape and that is a claim you must
check** while the container is up: does `?briefRepresentation=false` add
`attributes` to a mapping listing? The composite listings in the roles half did
*not* change, and this looks the same - which is exactly the reasoning that was
wrong four times. Measure it, then either keep `true` with the measurement cited
or read `briefRoles(r.URL.Query())`.

- [ ] **Step 5: Register the routes**

Use whatever the Step 1 sweep measured. If it confirms the recorded rule:

```go
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm",
		h.guard("view-users", h.listRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/available",
		h.guard("view-users", h.availableRealmMappings))
	mux.HandleFunc("GET /admin/realms/{realm}/users/{userID}/role-mappings/realm/composite",
		h.guard("view-users", h.compositeRealmMappings))
```

- [ ] **Step 6: Run the tests**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -count=1`

- [ ] **Step 7: Mutation-test**

| Mutation | Should fail |
|---|---|
| `availableRealmMappings` excludes the effective set instead of the direct one | the `create-realm` assertion |
| `listRealmMappings` uses `roles.Effective` | the direct-list assertion |
| `realmRolesOnly` keeps client roles | the direct-list assertion |
| the guard is `manage-users` | the Step 1 sweep's test |

- [ ] **Step 8: Commit**

```bash
git add internal/admin/rolemappings.go internal/admin/rolemappings_test.go \
        internal/admin/router.go docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md
git commit -m "feat(admin): read a user's realm role mappings"
```

---

## Task 3: writing a user's realm roles

Serves `POST` and `DELETE /users/{id}/role-mappings/realm`.

**Files:**
- Modify: `internal/admin/rolemappings.go`, `internal/admin/router.go`
- Test: `internal/admin/rolemappings_test.go`

**Interfaces:**
- Consumes: `resolveUser`, `decodeRoleList` (roles half), `RoleRepo.AssignToUser`/`RemoveFromUser`.
- Produces: `assignRealmMappings`, `removeRealmMappings`, `writeMappingRoleNotFound`.

- [ ] **Step 1: Measure what the roles half would have got wrong**

Two things, both while the container is up:

1. **Is a batch atomic?** The composite writes were measured rolling the whole
   request back on one bad id. Do **not** assume the same here - the roles half
   was burned twice extending a measured rule to a neighbouring endpoint. Send
   `[validRealmRoleID, nonexistentID]` and see whether the valid one lands.
2. **Does `DELETE` differ from `POST`?** Same question, same body, both verbs.
   On the composite endpoints they turned out asymmetric.

Record both. The recorded contract already says a **client** role posted to
`/role-mappings/realm` answers 404 `{"error":"Role not found"}` and a non-array
body answers 400 `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`.

- [ ] **Step 2: Write the failing test**

```go
func TestAssignAndRemoveRealmMappings(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	base := "/admin/realms/master/users/" + uid + "/role-mappings/realm"
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)

	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	if got := postJSON(t, h, base, body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d", got)
	}
	if got := mappingNames(t, h, base, admin); !slices.Contains(got, "offline_access") {
		t.Fatalf("assign did not stick: %v", got)
	}

	if got := sendJSON(t, h, http.MethodDelete, base, body, admin).Code; got != http.StatusNoContent {
		t.Fatalf("remove: want 204, got %d", got)
	}
	if got := mappingNames(t, h, base, admin); slices.Contains(got, "offline_access") {
		t.Fatalf("remove did not stick: %v", got)
	}
}

// A client role posted to the realm endpoint is 404 "Role not found" - a
// different message from the roles endpoints' "Could not find role" two paths
// away. Measured; it is the sixth of eight not-found spellings.
func TestRealmMappingRejectsAClientRole(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	mr := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)

	w := postJSON(t, h, "/admin/realms/master/users/"+uid+"/role-mappings/realm",
		`[{"id":"`+viewUsers.ID+`","name":"view-users"}]`, admin)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
	if body := w.Body.String(); body != `{"error":"Role not found"}` {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestRealmMappingWritesNeedManageUsers(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	postJSON(t, h, "/admin/realms/master/users", `{"username":"probe-mapped","enabled":true}`, admin)
	uid := userID(t, s, realm, "probe-mapped")
	offline := readRole(t, h, "/admin/realms/master/roles/offline_access", admin)
	body := `[{"id":"` + offline.ID + `","name":"offline_access"}]`
	viewer := tokenForRole(t, h, s, realm, "view-users")

	if got := postJSON(t, h, "/admin/realms/master/users/"+uid+"/role-mappings/realm", body, viewer).Code; got != http.StatusForbidden {
		t.Fatalf("view-users assigned a role: %d", got)
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -run 'TestAssignAndRemove|TestRealmMapping' -v`

- [ ] **Step 4: Implement**

Follow whatever Step 1 measured for atomicity. If the batch is atomic, resolve
and validate every entry before assigning any, the way `eachComposite` does -
read that function rather than reinventing its shape. If it is not, apply in
order and stop at the first failure.

```go
// writeMappingRoleNotFound is the measured 404 for a role a mapping write
// cannot use. It is **not** the roles endpoints' "Could not find role", and not
// the composite batch's "Could not find composite role". Three spellings, one
// resource; all measured.
func writeMappingRoleNotFound(w http.ResponseWriter) {
	httpx.WriteMessageError(w, http.StatusNotFound, "Role not found")
}
```

- [ ] **Step 5: Register, run, mutate, commit**

Guards per the Step 1 sweep of Task 2 extended to the write verbs. Mutations:
drop the client-role rejection (the rejection test fails); use
`writeRoleNotFound` instead of `writeMappingRoleNotFound` (the body assertion
fails); make `DELETE` a no-op (the round-trip test fails).

```bash
git commit -m "feat(admin): assign and remove a user's realm roles"
```

---

## Task 4: reading a user's client roles

Serves `GET /users/{id}/role-mappings/clients/{client-id}`, `.../available` and
`.../composite`.

**Files:**
- Modify: `internal/admin/rolemappings.go`, `internal/admin/router.go`
- Test: `internal/admin/rolemappings_test.go`

**Interfaces:**
- Consumes: everything from Task 2, plus `clientRoleContainer` from the roles half - **read it first**, it resolves `{clientUUID}` and writes the client's own 404.
- Produces: `listClientMappings`, `availableClientMappings`, `compositeClientMappings`.

- [ ] **Step 1: Note the path parameter and check it**

The OpenAPI spells this `{client-id}` but it carries the client's **UUID**, and
`net/http` requires a wildcard name to be a Go identifier. The roles half
registers `{clientUUID}`. Match that; `Case.Operation` keeps Keycloak's spelling
separately.

- [ ] **Step 2: Write the failing test**

```go
// Measured on the administrator with one master-realm role assigned directly:
// direct is 1, available is 20, composite is 21 - because admin is composite
// over all 21 and the assignment is one of them.
func TestClientMappingReadsMirrorTheRealmTriple(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	mr := clientUUID(t, s, realm, "master-realm")
	base := "/admin/realms/master/users/" + adminID + "/role-mappings/clients/" + mr

	// The administrator holds no client role directly - measured, and the
	// reason its combined view has no clientMappings key at all.
	if got := mappingNames(t, h, base, admin); len(got) != 0 {
		t.Fatalf("direct: want none, got %v", got)
	}
	if got := mappingNames(t, h, base+"/composite", admin); len(got) != 21 {
		t.Fatalf("composite: want all 21 through the admin role, got %d", len(got))
	}
	if got := mappingNames(t, h, base+"/available", admin); len(got) != 21 {
		t.Fatalf("available: want all 21, since none is assigned directly, got %d", len(got))
	}
}
```

- [ ] **Step 3: Run it, implement, register, run**

The three handlers are the realm triple with the client filter substituted for
`realmRolesOnly` and `ListClientRoles` for `ListRealmRoles`. Write them out;
do not parameterise the realm ones into a shared function unless the code
genuinely reads better for it, and say which you chose and why in the report.

- [ ] **Step 4: Mutation-test and commit**

Mutations: `available` computed from the composite set (the 21 assertion moves);
the client filter dropped (realm roles leak into the client listing).

```bash
git commit -m "feat(admin): read a user's client role mappings"
```

---

## Task 5: writing a user's client roles

Serves `POST` and `DELETE /users/{id}/role-mappings/clients/{client-uuid}`.

- [ ] **Step 1: Measure the mirror of Task 3's questions** - atomicity and
  verb asymmetry - on the client endpoints. They are different operations and
  the roles half proved neighbouring operations diverge.
- [ ] **Step 2: Write the failing round-trip test**, shaped like Task 3's, plus
  one asserting that a **realm** role posted to the client endpoint is rejected.
  **The message for that is unmeasured** - measure it, do not assume it matches
  the mirror case's "Role not found".
- [ ] **Step 3: Implement, register, run, mutate, commit**

```bash
git commit -m "feat(admin): assign and remove a user's client roles"
```

---

## Task 6: the combined view

Serves `GET /users/{id}/role-mappings`, whose body is the one shape in this plan
that is not a bare array.

**Files:**
- Modify: `internal/admin/representation.go`, `internal/admin/rolemappings.go`, `internal/admin/router.go`

**Interfaces:**
- Produces: `mappingsRepresentation`, `clientMappingsEntry`.

- [ ] **Step 1: Write the failing test**

```go
// Both top-level keys are ABSENT when their list would be empty - not [] and
// not {}. Measured on the bootstrapped administrator, which holds two realm
// roles and no client role directly.
func TestCombinedMappingViewOmitsWhatIsEmpty(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	adminID := userID(t, s, realm, "admin")
	path := "/admin/realms/master/users/" + adminID + "/role-mappings"

	var body map[string]json.RawMessage
	w := get(t, h, path, admin)
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := body["realmMappings"]; !ok {
		t.Fatal("realmMappings is missing for a user that has some")
	}
	if _, ok := body["clientMappings"]; ok {
		t.Fatal("clientMappings is present for a user with no client role; " +
			"measured absent, not {}")
	}

	// Assign one and the key appears, keyed by clientId, carrying the client's
	// UUID and its clientId again.
	mr := clientUUID(t, s, realm, "master-realm")
	viewUsers := readRole(t, h, "/admin/realms/master/clients/"+mr+"/roles/view-users", admin)
	postJSON(t, h, "/admin/realms/master/users/"+adminID+"/role-mappings/clients/"+mr,
		`[{"id":"`+viewUsers.ID+`","name":"view-users"}]`, admin)

	w = get(t, h, path, admin)
	var full struct {
		ClientMappings map[string]struct {
			ID      string `json:"id"`
			Client  string `json:"client"`
			Mappings []struct {
				Name string `json:"name"`
			} `json:"mappings"`
		} `json:"clientMappings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatalf("parse: %v", err)
	}
	entry, ok := full.ClientMappings["master-realm"]
	if !ok {
		t.Fatalf("want the entry keyed by clientId, got %v", full.ClientMappings)
	}
	if entry.ID != mr || entry.Client != "master-realm" {
		t.Fatalf("entry carries id %q client %q", entry.ID, entry.Client)
	}
}
```

- [ ] **Step 2: Implement**

```go
// mappingsRepresentation is the combined view. Both fields are pointers
// because the measured body **omits** a key whose list would be empty, and
// omitempty on a slice cannot tell "none" from "absent" the way this endpoint
// needs - the administrator's body has realmMappings and no clientMappings key
// at all.
type mappingsRepresentation struct {
	RealmMappings  *[]roleRepresentation          `json:"realmMappings,omitempty"`
	ClientMappings map[string]clientMappingsEntry `json:"clientMappings,omitempty"`
}

// clientMappingsEntry is one client's block inside clientMappings, which is
// keyed by clientId and then repeats the clientId as `client` alongside the
// UUID.
type clientMappingsEntry struct {
	ID       string                `json:"id"`
	Client   string                `json:"client"`
	Mappings []roleRepresentation  `json:"mappings"`
}
```

**`clientMappings` is a Go map, so Go will sort its keys and Keycloak will
not.** The roles half found that Keycloak emits Java `HashMap` order and
reproduced it in `internal/javamap`; `resource_access` in the token package uses
it. Decide, with a measurement of a user holding roles on two clients, whether
this endpoint needs the same treatment or whether the conformance case can
declare the keys unordered. Say which and why.

- [ ] **Step 3: Register, run, mutate, commit**

Mutations: emit `clientMappings: {}` instead of omitting (the absence assertion
fails); key the map by UUID instead of clientId (the lookup fails).

```bash
git commit -m "feat(admin): the combined role-mapping view"
```

---

## Task 7: close F28

The first half of this cut left a privilege-escalation path open on purpose.
This is where it closes, and it must close **in this branch** - the moment role
assignment ships, which is Task 3 above, F28 stops being unreachable.

**Files:**
- Modify: `internal/admin/roles.go` (the composite-write predicate), `internal/admin/rolemappings.go`
- Test: both test files

- [ ] **Step 1: Read the measurement already in the repository**

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`, the section
"Adding an admin role as a composite is judged against the *caller*, not the
role". Twenty-seven children swept against two callers. **Read the whole
section before forming a hypothesis**, and note what it already rules out:

- The parent does not matter.
- The child alone does not matter - the same request is 204 for one caller and
  403 for another.
- **"The caller must already hold the child" is falsified.** A caller holding
  `manage-realm`+`manage-clients` gets 204 attaching `create-client`,
  `manage-authorization`, `view-clients`, `view-realm` and ten others it does
  not hold. Implementing that rule would refuse fourteen requests Keycloak
  allows - the too-restrictive direction this cut has already reverted twice.

What the data suggests, and what you must confirm or refute rather than
assume: the 403 set is exactly the roles whose *domain* the caller's own rights
do not cover. `manage-clients` covers the client domain, `manage-realm` the
realm and organization domains, and neither covers users, events, identity
providers or impersonation - which is the 403 set, plus `admin` and
`create-realm`.

- [ ] **Step 2: Measure the implication graph**

The rule needs a mapping from a role to what it lets its holder do. That mapping
is Keycloak's internal `AdminPermissions` model and it is **not** in this
repository. Derive it by measurement: for each of the 22 admin roles as the
**caller's single role**, sweep which children it may attach. That is a 22×27
matrix; script it, mint a fresh token per call, and expect it to take a while.

If the matrix does not resolve to a rule you can state in one sentence, **stop
and report** rather than implementing a partial one. A rule nobody can state is
a rule nobody can maintain, and the fallback - refusing everything a full
administrator would allow - is worse than the current gap.

- [ ] **Step 3: Implement the predicate once, use it twice**

The same question governs two operations: attaching a role as a composite child,
and assigning a role to a user. Keycloak evaluates the caller for both. Write
one predicate and call it from `eachComposite`'s child check and from the
mapping writes in Tasks 3 and 5.

- [ ] **Step 4: Test both call sites**, including the exact escalation F28
  describes: a caller holding one narrow manage role attaching `admin` to
  `default-roles-master`, and the same caller assigning `admin` to a user.
  Both must be 403; a full administrator doing either must be 204.

- [ ] **Step 5: Close F28 in the follow-ups document** and say what closed it.
  If the matrix forced a partial implementation, say exactly which part remains
  and re-file it rather than closing.

```bash
git commit -m "fix(admin): judge an admin role's assignment against the caller"
```

---

## Task 8: conformance cases

- [ ] **Step 1: Add cases** for the 11 operations, on the pattern in
  `internal/conformance/catalog_admin.go`. Every listing here is a **bare array
  at the root**, so it needs `Unordered: []string{"."}` - the spelling the roles
  half added. The combined view is an object; its `clientMappings` keys need
  whatever Task 6 decided.
- [ ] **Step 2: Set `Case.Operation` on exactly one case per operation.** The
  roles half misfiled one and the per-chapter meter was wrong until it was
  caught. Check with a script, not by eye.
- [ ] **Step 3: Record** with `make record` under Docker, then **read the
  diff**. Three login-theme goldens churn per container start - revert them,
  do not commit them. Nothing outside `admin/role-mapper*` and
  `admin/client-role-mappings*` should change.
- [ ] **Step 4: Run the suite and the meter**, and report both.

```bash
git commit -m "test(conformance): record the role-mapping endpoints"
```

---

## Task 9: documentation and F17

- [ ] **Step 1:** New `AGENTS.md` entries for whatever Tasks 2-7 measured that
  contradicted an expectation. Do not write this list in advance - take it from
  the task reports.
- [ ] **Step 2:** Update the observed document with every sweep.
- [ ] **Step 3: F17 becomes reachable.** It says the client and user listings
  are gated where Keycloak filters, and that no conformance case could reach it
  "until role assignment is served". It is served now. Either fix F17 in this
  branch and close it, or update it to say precisely what is now possible and
  why it is still deferred.
- [ ] **Step 4:** README and roadmap: the meter, and the second cut's second
  half marked done.
- [ ] **Step 5: Verify** - build, vet, the full suite, the Postgres driver suite
  under Docker, `make oracle`, `make conformance`.

```bash
git commit -m "docs(p2): what the role-mapping endpoints measured"
```

---

## Task 10: finish the branch

- [ ] **REQUIRED SUB-SKILL:** `superpowers:finishing-a-development-branch`.

## What this plan does not cover

The **groups** third cut: `Groups` 9 operations, a user's group membership 4,
and the group halves of both mapping tags 11. `/roles/{name}/groups` already
answers `[]` from the roles half and needs no new route when they arrive.

F25, F26, F27 and F29 stay open. **F28 does not** - it is Task 7, and shipping
role assignment without it would make a currently-unreachable escalation
reachable.
