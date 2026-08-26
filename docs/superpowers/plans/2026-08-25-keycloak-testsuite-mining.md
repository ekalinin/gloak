# Mining Keycloak's test suite for conformance cases: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the assertions in Keycloak's own role tests into recorded conformance cases over the role surface Gloak already serves, and close the first gap that exercise uncovers: `first` and `max` are accepted and ignored by both role listings.

**Architecture:** Nothing is imported and nothing Java is built. A pinned sparse checkout of `github.com/keycloak/keycloak` at tag `26.7.1` becomes a readable reference; each claim it makes about surface Gloak serves is measured against a live 26.7.1 container, written into the catalogue as a `Case`, and recorded as a golden. This is track A of `docs/superpowers/specs/2026-08-25-keycloak-upstream-testsuite-as-oracle.md`; tracks B and C are blocked on P4 and P3 and are not in this plan.

**Tech Stack:** Go 1.x, `internal/conformance` (the existing golden harness), `make record` against `quay.io/keycloak/keycloak:26.7.1` under Docker, `git` sparse checkout.

## Global constraints

- **Observable values are measured, never remembered.** Every expected value in this plan comes out of `make record` against a live Keycloak 26.7.1, or out of a `curl` against the same container. Upstream's test source says *which* behaviour to look at; it never supplies a value. Where a step below states an expected result, it is a prediction to be checked, and the measurement wins.
- `CGO_ENABLED=0 go test ./...` must never need Docker or the network. Anything that does goes behind the `docker` build tag.
- `make test` is clean. Any failure is a real regression.
- `internal/conformance` is test-only. Production code must not import it.
- Marshal response bodies from structs in Keycloak's field order, never from `map[string]any`.
- Commit messages are `type(scope): subject`, types limited to `feat`, `fix`, `docs`, `refactor`, `perf`, `chore`. Never commit to `main`.
- Upstream is Apache-2.0. No upstream source is copied into this repository by this plan. `Case.Doc.Section` cites the upstream file and test method that a case was mined from, which is a citation, not a copy.
- The pinned upstream commit for the whole plan is `73f08b397f193712b26d317210dce99898129709`, tag `26.7.1`.

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `Makefile` | the `kcsrc` target that materialises the pinned upstream checkout | 1 |
| `.gitignore` | keep the checkout out of the repository | 1 |
| `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` | the measured contract; gains a section on the role listing's pagination | 2 |
| `internal/conformance/fixture.go` | `pagedRolesFixture`, the three-role setup the pagination cases need | 3 |
| `internal/conformance/catalog_admin.go` | the new `Case` entries | 3, 5, 6 |
| `internal/conformance/testdata/golden/admin/roles/*.http` | the recorded goldens, written by `make record` | 3, 5, 6 |
| `internal/admin/roles.go` | `first` and `max` on the two role listings | 4 |
| `internal/admin/roles_test.go` | the unit tests for the paging helper | 4 |
| `AGENTS.md` | the mining procedure, so the next case follows the same path | 7 |

---

### Task 1: Pin the upstream checkout

**Files:**
- Modify: `Makefile`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: a directory `.kc-testsuite/` at the repository root holding `tests/` and `test-framework/` of Keycloak `26.7.1`, and a `make kcsrc` target that creates it idempotently. Every later task cites paths relative to it.

- [ ] **Step 1: Add the ignore entry**

Add to `.gitignore`, after `/dist/`:

```gitignore
/.kc-testsuite/
```

- [ ] **Step 2: Add the make target**

Add to `Makefile`, after the `oracle` target, and add `kcsrc` to the `.PHONY` line at the top:

```makefile
# kcsrc materialises a read-only checkout of Keycloak's own test sources at the
# pinned tag, for mining behaviours the catalogue is missing. Nothing builds
# from it and nothing is copied out of it: see
# docs/superpowers/specs/2026-08-25-keycloak-upstream-testsuite-as-oracle.md.
KC_TESTSUITE_TAG := 26.7.1
KC_TESTSUITE_SHA := 73f08b397f193712b26d317210dce99898129709

kcsrc:
	@if [ ! -d .kc-testsuite ]; then \
		git clone --filter=blob:none --sparse --depth 1 \
			--branch $(KC_TESTSUITE_TAG) \
			https://github.com/keycloak/keycloak.git .kc-testsuite; \
		git -C .kc-testsuite sparse-checkout set tests test-framework; \
	fi
	@test "$$(git -C .kc-testsuite rev-parse HEAD)" = "$(KC_TESTSUITE_SHA)" \
		|| { echo "kcsrc: checkout is not $(KC_TESTSUITE_SHA)"; exit 1; }
	@echo "kcsrc: $(KC_TESTSUITE_TAG) at $(KC_TESTSUITE_SHA)"
```

- [ ] **Step 3: Run it and verify the pin**

Run: `make kcsrc`
Expected: it clones, then prints `kcsrc: 26.7.1 at 73f08b397f193712b26d317210dce99898129709`.

Run it a second time.
Expected: the same line, no second clone, no error.

- [ ] **Step 4: Verify the sources the later tasks need are present**

Run:

```bash
ls .kc-testsuite/tests/base/src/test/java/org/keycloak/tests/admin/realm/RealmRolesSearchTest.java \
   .kc-testsuite/tests/base/src/test/java/org/keycloak/tests/admin/realm/AbstractRealmRolesTest.java
```

Expected: both paths exist.

- [ ] **Step 5: Verify the repository is still clean**

Run: `git status --short`
Expected: only `Makefile` and `.gitignore` modified. `.kc-testsuite/` must not appear.

- [ ] **Step 6: Commit**

```bash
git add Makefile .gitignore
git commit -m "chore(make): pin a checkout of Keycloak's test sources for mining"
```

---

### Task 2: Measure the role listing's pagination

**Files:**
- Modify: `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`

**Interfaces:**
- Consumes: `.kc-testsuite/` from Task 1.
- Produces: a section in the observed spec titled "Role listing: first and max", stating for Keycloak 26.7.1 what `first`, `max` and `max=0` do on `GET /admin/realms/{realm}/roles`, and whether a paginated result is reproducible across container starts. Task 3 chooses which cases are recordable from it.

This task measures. It does not change any Go code.

- [ ] **Step 1: Read the claim being mined**

Read `.kc-testsuite/tests/base/src/test/java/org/keycloak/tests/admin/realm/RealmRolesSearchTest.java`, methods `testSearchForRoles` and `testPaginationRoles`.

The claims are: `roles().list(first, max)` pages; `list("testrole", 1, 5)` yields 5 of 15 matches; `list(1, 5)` yields 5; and `list(1, null)` yields more than 15, so a missing `max` means no limit.

`internal/admin/roles.go` reads only `search` and `briefRepresentation`. Both parameters are accepted and ignored today.

- [ ] **Step 2: Start the reference container**

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
```

- [ ] **Step 3: Create three probe roles and measure**

```bash
TOKEN=$(curl -s -d client_id=admin-cli -d username=admin -d password=admin \
  -d grant_type=password \
  http://localhost:18091/realms/master/protocol/openid-connect/token | \
  python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')

for n in a b c; do
  curl -s -o /dev/null -w "create $n %{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"name\":\"gloak-probe-page-$n\"}" \
    http://localhost:18091/admin/realms/master/roles
done

probe() {
  echo "--- $1"
  curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:18091/admin/realms/master/roles?$1"
  echo
}
probe 'search=gloak-probe-page'
probe 'search=gloak-probe-page&max=0'
probe 'search=gloak-probe-page&max=2'
probe 'search=gloak-probe-page&first=1'
probe 'search=gloak-probe-page&first=3'
probe 'search=gloak-probe-page&first=1&max=1'
probe 'max=2'
probe 'first=1'
probe 'first=-1&max=-1'
```

Record every status line and body verbatim. The four questions to answer are:

1. Is `max` a page size, and is `first` an offset counted from zero or from one?
2. What does `max=0` return: an empty array, or everything?
3. What does `first` past the end of the set return: `[]`, or an error?
4. What do the negative values `first=-1&max=-1` do? Upstream's `list(first, max)` sends them for "no paging", so this is the shape the admin client itself puts on the wire.

- [ ] **Step 4: Measure reproducibility across container starts**

`AGENTS.md` records that role listings have no stable order across container starts, which is why `admin/roles/list-realm` carries `Unordered: ["."]`. A paginated listing returns a *subset* picked by that order, and sorting the two sides cannot repair a difference in membership.

Restart the container from scratch and repeat step 3:

```bash
docker rm -f gloak-ref
```

Then repeat steps 2 and 3 verbatim, and compare the bodies of `search=gloak-probe-page&max=2` and `search=gloak-probe-page&first=1&max=1` between the two runs.

Expected: the full set `search=gloak-probe-page` agrees on membership and possibly not on order. The question is whether the two-element and one-element pages hold the same roles both times.

- [ ] **Step 5: Write the measurement into the observed spec**

Add a section to `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` next to the other role-listing material:

```markdown
### Role listing: first and max

Measured 2026-08-25 against quay.io/keycloak/keycloak:26.7.1, on
`GET /admin/realms/master/roles` narrowed with `search=gloak-probe-page` to
three roles created for the purpose.

| Query | Status | Body |
|---|---|---|
| `search=gloak-probe-page` | ... | ... |
| `search=gloak-probe-page&max=0` | ... | ... |
| `search=gloak-probe-page&max=2` | ... | ... |
| `search=gloak-probe-page&first=1` | ... | ... |
| `search=gloak-probe-page&first=3` | ... | ... |
| `search=gloak-probe-page&first=1&max=1` | ... | ... |
| `first=-1&max=-1` | ... | ... |

Reproducibility across two container starts: <agrees / does not agree>, for
<which queries>.

Mined from `tests/base/src/test/java/org/keycloak/tests/admin/realm/RealmRolesSearchTest.java`,
methods `testSearchForRoles` and `testPaginationRoles`, at Keycloak 26.7.1.
```

Fill every cell from step 3's output. Leave no cell as a dash unless the measurement produced nothing.

- [ ] **Step 6: Stop the container**

```bash
docker rm -f gloak-ref
```

- [ ] **Step 7: Commit**

```bash
git add docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md
git commit -m "docs(observed): measure first and max on the role listing"
```

---

### Task 3: Record the pagination cases

**Files:**
- Modify: `internal/conformance/fixture.go`
- Modify: `internal/conformance/catalog_admin.go`
- Create: `internal/conformance/testdata/golden/admin/roles/list-realm-page-empty.http` (written by `make record`)
- Create: `internal/conformance/testdata/golden/admin/roles/list-realm-page-past-end.http` (written by `make record`)

**Interfaces:**
- Consumes: the observed-spec section from Task 2.
- Produces: fixture `admin-token-paged-roles` in `Fixtures`, and two cases with IDs `admin/roles/list-realm-page-empty` and `admin/roles/list-realm-page-past-end`, both `Status: Recorded` at the end of this task. Task 4 flips them to `Implemented`.

Only order-independent queries are recorded. `max=0` and a `first` past the end of the set both answer with a body whose membership does not depend on the container's role order; `max=2` over a three-role set does depend on it, and is left out unless Task 2's step 4 measured it reproducible. If step 4 found the pages reproducible, add a third case `admin/roles/list-realm-page-first` for `search=gloak-probe-page&first=1&max=1` alongside the two below, built the same way.

- [ ] **Step 1: Add the fixture**

In `internal/conformance/fixture.go`, beside `realmRoleFixture`, add:

```go
// pagedRolesFixture creates three realm roles sharing one search prefix, so a
// listing can be narrowed to a set of known size before first and max are
// applied to it.
//
// Narrowing first is what makes the goldens recordable at all. A page taken
// out of the whole realm is a subset chosen by Keycloak's own role order,
// which AGENTS.md records as differing between container starts, and
// Case.Unordered cannot repair a difference in membership - only in order.
func pagedRolesFixture() Fixture {
	steps := []Step{adminTokenStep()}
	for _, suffix := range []string{"a", "b", "c"} {
		steps = append(steps, Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-page-` + suffix + `"}`),
			},
		})
	}
	return Fixture{State: "bootstrap", Steps: steps}
}
```

Register it in `Fixtures`, next to the other role fixtures:

```go
	"admin-token-paged-roles": pagedRolesFixture(),
```

- [ ] **Step 2: Add the two cases**

In `internal/conformance/catalog_admin.go`, after the `admin/roles/list-realm` case, add:

```go
	{
		ID: "admin/roles/list-realm-page-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, max=0; mined from RealmRolesSearchTest.testPaginationRoles",
			Retrieved: "2026-08-25",
		},
		Status: Recorded,
		Reason: "the role listings read only search and briefRepresentation; max is accepted and ignored",
		// No Operation: GET /admin/realms/{realm}/roles is already claimed by
		// admin/roles/list-realm, and an operation is counted once.
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-page", "max": "0"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-page-past-end",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, first past the end of the match set; mined from RealmRolesSearchTest.testPaginationRoles",
			Retrieved: "2026-08-25",
		},
		Status:  Recorded,
		Reason:  "the role listings read only search and briefRepresentation; first is accepted and ignored",
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-page", "first": "3"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
```

- [ ] **Step 3: Confirm the catalogue compiles**

Run: `CGO_ENABLED=0 go vet ./internal/conformance/`
Expected: no output.

Do not run `make test` yet, and do not be surprised when it is red between here and step 6. `TestRecordedCaseRules` requires a `Recorded` case to have a `Reason`, a `Fixture` **and a golden on disk**; the golden arrives in step 4. `Reason` is required for `Recorded` as well as `Pending`, which the doc comment on `Case.Reason` does not say and the test does.

- [ ] **Step 4: Record the goldens**

Run: `make record`
Expected: it starts the reference container and writes
`internal/conformance/testdata/golden/admin/roles/list-realm-page-empty.http` and
`list-realm-page-past-end.http`.

- [ ] **Step 5: Read the diff before believing it**

Run: `git status --short && git diff --stat`
Expected: exactly the two new goldens, and **no change to any existing golden**. An existing golden that moved means the new fixture polluted the shared container; the recorder runs cases in catalogue order and `PristineRealm` cases first, so a change to `list-realm.http` in particular means the three probe roles leaked into it and the fixture ordering has to be fixed before going on.

Open both new goldens and check the bodies against the table written in Task 2 step 5. They must agree. If they do not, the table was wrong: fix the table, not the golden.

- [ ] **Step 6: Verify the cases are red in the right way**

Run: `make test`
Expected: PASS, with both new cases reported as skipped, `recorded, not served yet: ...`. A `Recorded` case is required *not* to match, and Gloak ignores `max` and `first` today, so both differ from their golden.

If either one *matches*, `TestConformance` fails with `already matches the recorded Keycloak response. Promote it to Implemented - as Recorded it is guarded by nothing.` That would mean Gloak already serves the behaviour: flip that case to `Implemented` here and drop it from Task 4 step 6.

- [ ] **Step 7: Commit**

```bash
git add internal/conformance/fixture.go internal/conformance/catalog_admin.go internal/conformance/testdata/golden/admin/roles/
git commit -m "test(conformance): record first and max on the realm role listing"
```

---

### Task 4: Serve first and max on both role listings

**Files:**
- Modify: `internal/admin/roles.go`
- Modify: `internal/admin/roles_test.go`
- Modify: `internal/conformance/catalog_admin.go` (status flip only)

**Interfaces:**
- Consumes: `filterRoles(roles []*model.Role, search string) []*model.Role` and `writeRoleList(w http.ResponseWriter, r *http.Request, roles []*model.Role, containerID string)`, both in `internal/admin/roles.go`.
- Produces: `pageRoles(roles []*model.Role, q url.Values) []*model.Role`, applied inside `writeRoleList` so both the realm listing and the client listing get it from one place.

The code below implements the semantics upstream's own test asserts: `first` is a zero-based offset, `max` is a page size, and an absent parameter means no bound. **Task 2's measurement overrides this.** If the measurement says `max=0` returns everything, or `first` is one-based, or a negative value is not the same as absent, change this code to match what was measured and say so in the comment.

- [ ] **Step 1: Write the failing test**

Add to `internal/admin/roles_test.go`:

```go
func TestPageRoles(t *testing.T) {
	roles := []*model.Role{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	names := func(in []*model.Role) []string {
		out := make([]string, 0, len(in))
		for _, r := range in {
			out = append(out, r.Name)
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		query string
		want  []string
	}{
		{"no parameters", "", []string{"a", "b", "c"}},
		{"max zero is an empty page", "max=0", []string{}},
		{"max bounds the page", "max=2", []string{"a", "b"}},
		{"first offsets from zero", "first=1", []string{"b", "c"}},
		{"first past the end", "first=3", []string{}},
		{"first and max together", "first=1&max=1", []string{"b"}},
		{"negative means absent", "first=-1&max=-1", []string{"a", "b", "c"}},
		{"unparseable means absent", "first=x&max=y", []string{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("bad query: %v", err)
			}
			got := names(pageRoles(roles, q))
			if !slices.Equal(got, tc.want) {
				t.Fatalf("pageRoles(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}
```

Add `net/url`, `slices` and the `internal/model` import to the file's import block if they are not already there.

- [ ] **Step 2: Run it and watch it fail**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -run TestPageRoles`
Expected: FAIL, `undefined: pageRoles`.

- [ ] **Step 3: Implement the helper**

Add to `internal/admin/roles.go`, below `filterRoles`:

```go
// pageRoles applies the listing's first and max parameters, after filterRoles
// has narrowed the set.
//
// first is a zero-based offset and max is a page size; an absent, negative or
// unparseable value means no bound, which is the shape the Java admin client
// puts on the wire for "no paging" - it sends first=-1&max=-1 rather than
// omitting them. See the "Role listing: first and max" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md for the
// measurement.
func pageRoles(roles []*model.Role, q url.Values) []*model.Role {
	bound := func(name string) int {
		v, err := strconv.Atoi(q.Get(name))
		if err != nil || v < 0 {
			return -1
		}
		return v
	}

	out := roles
	if first := bound("first"); first >= 0 {
		if first >= len(out) {
			return []*model.Role{}
		}
		out = out[first:]
	}
	if max := bound("max"); max >= 0 && max < len(out) {
		out = out[:max]
	}
	return out
}
```

Add `net/url` and `strconv` to the file's import block if they are not already there.

- [ ] **Step 4: Run the test and watch it pass**

Run: `CGO_ENABLED=0 go test ./internal/admin/ -run TestPageRoles -v`
Expected: PASS, all eight sub-tests.

- [ ] **Step 5: Apply it to both listings**

In `writeRoleList`, page before building the representations, so the realm listing and the client listing get it from one place:

```go
func (h *handler) writeRoleList(w http.ResponseWriter, r *http.Request, roles []*model.Role, containerID string) {
	brief := briefRoles(r.URL.Query())
	roles = pageRoles(roles, r.URL.Query())
	out := make([]roleRepresentation, 0, len(roles))
	for _, role := range roles {
		out = append(out, roleRepresentationOf(role, containerID, brief))
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}
```

- [ ] **Step 6: Flip the two cases to Implemented**

In `internal/conformance/catalog_admin.go`, change `Status: Recorded` to `Status: Implemented` on `admin/roles/list-realm-page-empty` and `admin/roles/list-realm-page-past-end`.

- [ ] **Step 7: Run the whole suite**

Run: `make test`
Expected: PASS. The two cases now match their goldens, and no existing case moved: `first` and `max` are absent from every other role case's query, and an absent bound leaves the set alone.

- [ ] **Step 8: Check the meter moved the way it should**

Run: `make conformance`
Expected: `admin/roles` served count is **unchanged**. Neither new case names an `Operation`, because `GET /admin/realms/{realm}/roles` is already claimed by `admin/roles/list-realm` and an operation is counted once. The cases are guards, not parity.

- [ ] **Step 9: Commit**

```bash
git add internal/admin/roles.go internal/admin/roles_test.go internal/conformance/catalog_admin.go
git commit -m "feat(admin): apply first and max to the role listings"
```

---

### Task 5: Guard briefRepresentation over a role's attributes

**Files:**
- Modify: `internal/conformance/fixture.go`
- Modify: `internal/conformance/catalog_admin.go`
- Create: `internal/conformance/testdata/golden/admin/roles/list-realm-brief.http` (written by `make record`)
- Create: `internal/conformance/testdata/golden/admin/roles/list-realm-full.http` (written by `make record`)

**Interfaces:**
- Consumes: `pagedRolesFixture` from Task 3 as the shape to copy; `briefRoles(q url.Values) bool` and `roleRepresentationOf(r *model.Role, containerID string, brief bool)` in `internal/admin/representation.go`, unchanged by this task.
- Produces: fixture `admin-token-role-with-attributes` and cases `admin/roles/list-realm-brief` and `admin/roles/list-realm-full`.

Mined from `RealmRolesSearchTest.getRolesWithFullRepresentation` and `getRolesWithBriefRepresentation`: a role created with `attribute1` comes back with its attributes under `briefRepresentation=false` and with `attributes` absent under `briefRepresentation=true`.

Gloak implements this already (`briefRoles` defaults to true on a role listing, `roleRepresentationOf` omits `attributes` when brief). **Both cases are therefore expected to pass on the first run.** That is the point: the behaviour is currently held up by one line in `representation.go` with no golden under it. If either case does not pass, a real defect has been found and it is fixed here rather than filed.

Both go in as `Implemented`, not through `Recorded` the way Task 3's did. `Recorded` means "measured but not served", and `TestConformance` fails a `Recorded` case that *matches* - as it should, since a case in that state is guarded by nothing.

- [ ] **Step 1: Add the fixture**

In `internal/conformance/fixture.go`, beside `pagedRolesFixture`:

```go
// attributedRoleFixture creates one realm role carrying attributes, so the
// listing's briefRepresentation can be measured against something that has
// something to hide. Exactly one role matches the search prefix, so the
// resulting body is a one-element array and the realm's unstable role order
// cannot reach it.
func attributedRoleFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-attrs","attributes":{"attribute1":["value1","value2"]}}`),
			},
		}},
	}
}
```

Register it in `Fixtures`:

```go
	"admin-token-role-with-attributes": attributedRoleFixture(),
```

- [ ] **Step 2: Add the two cases**

In `internal/conformance/catalog_admin.go`, after the Task 3 cases:

```go
	{
		ID: "admin/roles/list-realm-brief",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, briefRepresentation=true over a role with attributes; mined from RealmRolesSearchTest.getRolesWithBriefRepresentation",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-role-with-attributes",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-attrs", "briefRepresentation": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, briefRepresentation=false over a role with attributes; mined from RealmRolesSearchTest.getRolesWithFullRepresentation",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-role-with-attributes",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-attrs", "briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
		// attributes is a Java Map in hash order and Go sorts map keys. This is
		// the suite's one documented retreat from byte-exactness; see the
		// UnorderedKeys note in case.go.
		UnorderedKeys: []string{"*/attributes"},
	},
```

- [ ] **Step 3: Record**

Run: `make record`
Expected: two new goldens, no existing golden changed.

- [ ] **Step 4: Read the goldens**

Open `list-realm-brief.http` and `list-realm-full.http`. Confirm the brief body has no `attributes` key at all and the full one carries `"attribute1":["value1","value2"]`. If the brief body carries `"attributes":{}` instead of omitting the key, the measurement contradicts what `roleRepresentationOf` does and Task 4's comment about "measured, never remembered" applies: the golden is right and `representation.go` needs a follow-up.

- [ ] **Step 5: Run the suite**

Run: `make test`
Expected: PASS.

If a case fails, do not demote it to `Recorded` to make the suite green. Read the diff the verifier prints, fix `internal/admin`, and run again. A mined case that fails is the finding this whole plan exists to produce.

- [ ] **Step 6: Commit**

```bash
git add internal/conformance/fixture.go internal/conformance/catalog_admin.go internal/conformance/testdata/golden/admin/roles/
git commit -m "test(conformance): guard briefRepresentation over a role's attributes"
```

---

### Task 6: Guard that the realm role search never crosses into client roles

**Files:**
- Modify: `internal/conformance/fixture.go`
- Modify: `internal/conformance/catalog_admin.go`
- Create: `internal/conformance/testdata/golden/admin/roles/list-realm-search-excludes-client-roles.http` (written by `make record`)

**Interfaces:**
- Consumes: `clientRoleFixture(clientID, roleName string) Fixture` in `internal/conformance/fixture.go` as the shape to copy.
- Produces: fixture `admin-token-same-named-roles` and case `admin/roles/list-realm-search-excludes-client-roles`.

Mined from `RealmRolesSearchTest.testSearchForRealmRoles`, which carries the comment `// issue #9587` and asserts that no role returned by the realm listing has `clientRole` true. The regression it guards is a search that leaks client roles into the realm listing, which is exactly the failure mode a shared `filterRoles` invites.

- [ ] **Step 1: Add the fixture**

In `internal/conformance/fixture.go`:

```go
// sameNamedRolesFixture creates a realm role and a client role sharing one
// search prefix, so a listing narrowed by that prefix has something to leak.
//
// Mined from RealmRolesSearchTest.testSearchForRealmRoles, upstream's guard on
// issue #9587: the realm listing must never return a role whose clientRole is
// true, however the search is spelled.
func sameNamedRolesFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-shared-realm"}`),
				},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"gloak-probe-shared-client"}`),
				},
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "gloak-probe-shared-client"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"client_uuid": "0/id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-shared-on-client"}`),
				},
			},
		},
	}
}
```

The client is looked up rather than read out of `Location` for the reason `clientRoleFixture` gives: the recorder runs a fixture's steps once per case against a shared container, and a repeated create answers 409 with no `Location`.

Register it in `Fixtures`:

```go
	"admin-token-same-named-roles": sameNamedRolesFixture(),
```

- [ ] **Step 2: Add the case**

```go
	{
		ID: "admin/roles/list-realm-search-excludes-client-roles",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, search matching a client role too; mined from RealmRolesSearchTest.testSearchForRealmRoles, upstream issue #9587",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-same-named-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-shared"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
```

- [ ] **Step 3: Record**

Run: `make record`
Expected: one new golden, no existing golden changed.

- [ ] **Step 4: Read the golden**

Open `list-realm-search-excludes-client-roles.http`. The body must be a one-element array holding `gloak-probe-shared-realm` with `"clientRole":false`, and must not mention `gloak-probe-shared-on-client`.

If it holds both roles, the measurement contradicts upstream's own assertion. In that case the golden still wins: record what was measured, and add a note under it saying which upstream test it disagrees with, so the next reader does not re-litigate it.

- [ ] **Step 5: Run the suite**

Run: `make test`
Expected: PASS. The case goes in as `Implemented` for the same reason Task 5's two did. `listRealmRoles` reads only realm roles out of the store before filtering, so the client role is never a candidate, and the case should match on the first run.

- [ ] **Step 6: Commit**

```bash
git add internal/conformance/fixture.go internal/conformance/catalog_admin.go internal/conformance/testdata/golden/admin/roles/
git commit -m "test(conformance): guard that a realm role search excludes client roles"
```

---

### Task 7: Write the procedure down

**Files:**
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: everything the six tasks above established.
- Produces: a section of `AGENTS.md` naming `make kcsrc` and the sequence a mined case goes through, so the next behaviour does not have to rediscover it.

- [ ] **Step 1: Add the section**

Add to `AGENTS.md`, after the "Build and test" section:

```markdown
## Where a new case can come from

Three sources, in order of how much they cost:

1. **The vendored OpenAPI description.** It says which operations exist. It
   never says what one answers.
2. **A live 26.7.1.** Every expected value comes from here. This is the rule
   at the top of this file.
3. **Keycloak's own test suite.** `make kcsrc` materialises a read-only
   checkout of `tests/` and `test-framework/` at the pinned tag under
   `.kc-testsuite/`. Its 2490 test methods are claims somebody upstream thought
   worth guarding; the ones about surface Gloak already serves are cases this
   catalogue may be missing.

A mined case goes: read the upstream assertion, measure the same thing against
a live 26.7.1, add the `Case` as `Recorded`, `make record`, read the diff, then
flip it to `Implemented` when Gloak serves it. Cite the upstream file and test
method in `Case.Doc.Section`. Nothing is copied out of `.kc-testsuite/`:
upstream is Apache-2.0 and this repository carries no upstream source.

**Most mined cases pass on the first run, and that is the expected outcome.**
An already-correct behaviour with a golden under it is one the next refactor
cannot break silently. The ones that fail are the finds: `first` and `max` on
the role listings were accepted and ignored until
`RealmRolesSearchTest.testPaginationRoles` was read.

Do not mine `testsuite/`. `testsuite/DEPRECATED.md` freezes it, and
`make kcsrc` does not check it out.
```

- [ ] **Step 2: Verify the claims in it are still true**

Run: `make kcsrc && make test && make conformance`
Expected: the pin line, a clean suite, and a report whose `admin/roles` served count is what it was before this plan started.

- [ ] **Step 3: Commit**

```bash
git add AGENTS.md
git commit -m "docs(agents): record where a mined conformance case comes from"
```

---

## Self-review

**Spec coverage.** Track A of `2026-08-25-keycloak-upstream-testsuite-as-oracle.md` section 5.1 has four parts: a pinned checkout (Task 1), the mining workflow (Tasks 2 to 6 exercise it three times), the `first`/`max` gap named in the spec as the first find (Tasks 2 to 4), and the workflow written down so it repeats (Task 7). Tracks B and C are explicitly out of scope and have no tasks, which is what the spec's section 5 says should happen.

**Placeholders.** The one deliberate blank is the table in Task 2 step 5, which is a measurement form to be filled from step 3's output; that is the task's deliverable, not a deferral. Task 4's implementation is written against upstream's asserted semantics with an explicit instruction that Task 2's measurement overrides it, and the specific ways it might differ are enumerated rather than left as "handle edge cases".

**Type consistency.** `pageRoles(roles []*model.Role, q url.Values) []*model.Role` is defined in Task 4 step 3 and called in Task 4 step 5 with the same signature. `pagedRolesFixture()`, `attributedRoleFixture()` and `sameNamedRolesFixture()` all return `Fixture` and are registered under the keys the cases name: `admin-token-paged-roles`, `admin-token-role-with-attributes`, `admin-token-same-named-roles`. `adminTokenStep()` is the existing helper the other role fixtures already use. The five new case IDs match the five new golden filenames, which is what the harness requires.

**Status choice.** Task 3's cases enter as `Recorded` because Gloak provably does not serve them yet; Tasks 5 and 6 enter as `Implemented` because it provably does. That is not a stylistic difference: `TestConformance` fails a `Recorded` case that matches, and fails an `Implemented` case that has no golden, so each task's step order is what keeps the suite honest rather than merely green.

**One risk worth restating.** Every new fixture creates objects in the container the recorder shares across the whole run. Task 3 step 5, Task 5 step 3 and Task 6 step 3 each check that no existing golden moved, because a `PristineRealm` golden silently absorbing three probe roles is the failure this suite has already had once.
