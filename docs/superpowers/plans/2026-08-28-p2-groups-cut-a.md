# P2's third cut, A: the group tree

Date: 2026-08-28
Spec: `docs/superpowers/specs/2026-08-28-p2-groups-design.md`

Nine operations: `GET`/`POST /groups`, `GET /groups/count`,
`GET`/`PUT`/`DELETE /groups/{id}`, `GET`/`POST /groups/{id}/children`,
`GET /groups/{id}/members`.

Cuts B and C get their own plans when this one lands, for the reason the roadmap
gives: a plan written before anyone reaches the work has the appearance of
accuracy without the measurement behind it. Section 7 of the spec already names
one measurement this cut must take that nobody has.

## Files

| File | Why |
|---|---|
| `internal/model/model.go` | **new type** `Group` |
| `internal/store/store.go` | **new** `GroupRepo`, added to `Store` |
| `internal/store/sqlite/migrations/0010_groups.sql` | **new** |
| `internal/store/postgres/migrations/0010_groups.sql` | **new** - the two drivers migrate separately |
| `internal/store/sqlite/sqlite.go` | `GroupRepo` |
| `internal/store/postgres/postgres.go` | `GroupRepo` |
| `internal/store/storetest/conformance.go` | the driver-agreement suite gains groups |
| `internal/admin/groups.go` | **new** - the nine handlers |
| `internal/admin/groups_test.go` | **new** |
| `internal/admin/router.go` | nine registrations, one new role set |
| `internal/conformance/catalog_admin.go` | the cases |
| `internal/conformance/fixture.go` | group fixtures |

## Task 1: the missing measurement

Section 7 of the spec measured the guards on a group **that exists**. The
two-stage question - what a caller that passes the coarse gate gets for a group
that does not - is unmeasured, and the answer decides whether the group routes
take `guardUserSubject`'s shape or a plain `guardAny`.

Sweep, on a live 26.7.1, one caller per role with a fresh token before each
call, against `/groups/00000000-0000-0000-0000-000000000000` and its
`/children` and `/members`:

- `view-users`, `manage-users`, `query-groups`, `query-users`, `view-clients`,
  `manage-realm`, and a caller with no admin role
- `GET`, `PUT`, `DELETE` on the group, `GET`/`POST` on children, `GET` on members

Record the table in the observed document under a heading of its own, beside
"The whole users family takes the same two stages, and the listings filter", and
say plainly whether the shape is the same rule with a different coarse gate or a
different rule.

**Do not implement anything in this task.** Its output is the measurement and a
sentence saying which combinator Task 5 uses.

Commit: `docs(groups): measure the guards on a group that does not exist`

## Task 2: the model and the store

`model.Group`: `ID`, `RealmID`, `Name`, `ParentID`, `Attributes`.

**`Path` is not a field.** The spec measured it cascading when a parent is
renamed, so it is computed from the ancestry on read. Storing it would need
every descendant rewritten on every rename, and the first missed rewrite is a
divergence nothing would catch.

`GroupRepo`: `Create`, `ByID`, `Update`, `Delete`, `ListTopLevel`,
`ListChildren`, `CountAll`, `Members`, `AddMember`, `RemoveMember`,
`ListUserGroups`. The last four are Cut B's, declared here because the migration
that carries the membership table belongs with the groups table and a second
migration for one join table is worse than one wide enough.

Both migrations. `0010_groups.sql` in each driver, and they are written
separately rather than shared: `AGENTS.md` requires the Postgres suite to be run
by hand after touching either driver, and that requirement exists because the
two have diverged before.

Verify: `CGO_ENABLED=0 go test ./internal/store/...`, then the Postgres suite by
hand, and paste both outputs into the commit.

Commit: `feat(store): a group tree and its membership`

## Task 3: the four representations

`internal/admin/groups.go`, representations only, no routes.

Section 4 of the spec has all four bodies as recorded. The trap is
`omitempty`: `subGroups` is `[]` everywhere and `attributes` is `{}` where
present, and both are exactly what `omitempty` drops. Use the pointer technique
`userRepresentation` already uses, and put the reason in the doc comment rather
than leaving the next reader to rediscover it.

The four differ in ways that are not a strict hierarchy - the create's response
has no `subGroupCount` and the children listing does - so a single "brief"
boolean will not produce all four. Model what the measurements show, not what
would be tidy.

A test per shape, each asserting the **key order** as recorded, because Go's
struct order is the only thing that produces it and a field moved during a
refactor is otherwise silent.

Commit: `feat(admin): the four group representations`

## Task 4: `path`, computed

One function: ancestry to a path. `/probe-top/probe-child` for a child of a
top-level group, `/probe-top` for the top-level one.

Tests: a top-level group, one child, a grandchild, and a rename of the root that
moves both descendants without touching their names. That last one is the
measured cascade and the reason `Path` is not stored.

Commit: `feat(admin): derive a group's path from its ancestry`

## Task 5: the nine routes

The guards from section 7, and the combinator Task 1's measurement chose:

| Route | Roles |
|---|---|
| `GET /groups`, `GET /groups/count` | `view-users`, `manage-users`, `query-groups` |
| `GET /groups/{id}`, `GET /groups/{id}/children`, `GET /groups/{id}/members` | `view-users`, `manage-users` |
| `POST /groups`, `POST /groups/{id}/children`, `PUT`, `DELETE` | `manage-users` |

A new `groupsReadRoles` for the first row. It is **not** `usersReadRoles`:
`query-users` is 403 on the group listing and `query-groups` is 200, which is
the pair the sweep found and the reason the set is its own.

The four error shapes from section 6, including both spellings of a missing
group. Two helpers, not one.

`GET /groups` is top-level only; `GET /groups/count` counts the whole tree.

Commit: `feat(admin): the group tree, nine operations`

## Task 6: the cases and the goldens

Fixtures: a top-level group, a group with a child, a group with a member. The
member one composes with `callerFixture` from F37 if a guard case wants a narrow
caller.

Cases, one per operation plus the four error shapes and the two spellings. Each
carries `Operation` so the meter counts it once.

Record against the container. **Read the diff before committing**: an
unreviewed re-record pins a regression as the contract.

Then `make conformance` and state the number in the commit body. This is the
first cut in four PRs that should move it, and by how much is the check that the
`Operation` strings are right.

Commit: `test(conformance): the group tree`

## Task 7: the documents

`AGENTS.md`: groups are authorised out of the users family, and the six
behaviours in section 5 join the list of things that must not be tidied up.

The roadmap: P2's third cut marked done with the served count, and P2 marked
complete if the numbers say it is.

`README.md` if it carries a parity number.

Commit: `docs(p2): record the group tree`

## What this plan deliberately does not do

**No group role-mappings.** `realmRoles` and `clientRoles` are served as `[]` and
`{}` because that is what a group with no roles returns, and Cut C is where they
stop being empty. A representation that guesses at the non-empty shape would be
inventing a contract.

**No `management/permissions`.** P10.

**No `subGroups` expansion.** Every measurement shows `[]`; if a parameter fills
it, nothing has found it, and inventing one is worse than serving what was
measured.
