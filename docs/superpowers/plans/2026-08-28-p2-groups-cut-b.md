# P2's third cut, B: a user's group membership

Date: 2026-08-28
Spec: `docs/superpowers/specs/2026-08-28-p2-groups-design.md`
Follows: `2026-08-28-p2-groups-cut-a.md`, merged as #18

Four operations, all tagged `Users` in the description:
`GET`/`GET .../count` and `PUT`/`DELETE` on `/users/{user-id}/groups`.

The store is already there: `GroupRepo`'s `Members`, `AddMember`, `RemoveMember`
and `ListUserGroups` shipped with cut A, because the migration carrying the join
table belonged with the table it joins.

## The measurement, taken 2026-08-28 before this plan was written

**The order is the opposite of cut A's, on routes naming the same group.**

```
coarse gate usersReadRoles   else 403
resolve the user             else 404 {"error":"User not found"}
the route's own roles        else 403
resolve the group            else 404 {"error":"Group not found"}
```

That is `guardUserSubject` with the group resolved inside the handler. The group
routes put the group first and judged nobody until it was found; these put it
last. Two families, opposite orders, one object.

The table that says so:

```
route                             view-users  query-users  manage-users  query-groups  view-clients  manage-realm  none
GET  .../groups                      200         403          200           403           403           403        403
GET  .../groups/count                200         403          200           403           403           403        403
PUT  .../groups/{id}                 403         403          204           403           403           403        403
DEL  .../groups/{id}                 403         403          204           403           403           403        403
GET  .../groups, unknown user        404         404          404           403           403           403        403
PUT  .../groups, unknown group       403         403          404           403           403           403        403
```

Row 5 is the coarse gate: `query-users` opens none of these four and still gets
the 404. Row 6 is the group coming last: `view-users` is refused before the
group is looked at.

`PUT` with **both** unknown answers `User not found`, so the subject wins.

## The rest of the contract

- `PUT` is idempotent - 204 for a membership already held.
- `DELETE` answers **204 for a group the user was never in**, and 404 only when
  the group does not exist. Membership need not be there; the group must.
- The listing is a **fifth** representation:
  `{id, name, path, parentId, subGroups}`, and `briefRepresentation=false` adds
  `attributes`, `realmRoles` and `clientRoles` but **neither `subGroupCount` nor
  `access`**. Cut A's four shapes become five.
- Both reads honour `search` and paging; the count is `{"count":n}`, an object,
  like the group count and unlike the user count.

## Files

| File | Why |
|---|---|
| `internal/admin/groups.go` | `groupMembershipFull`, four handlers |
| `internal/admin/router.go` | four registrations on `guardUserSubject` |
| `internal/admin/groups_test.go` | the order, the idempotence, the fifth shape |
| `internal/conformance/fixture.go` | a user in a group |
| `internal/conformance/catalog_admin.go` | the cases |

## Task 1: the fifth shape

`groupMembershipFull` beside the four. The test that compares whole serialised
documents gains a row; it is the test that would otherwise let a field move
silently.

Commit: `feat(admin): a fifth group shape, the membership listing's full form`

## Task 2: the four handlers and their routes

`guardUserSubject(userReadRoles, ...)` for the two reads and
`guardUserSubject(userWriteRoles, ...)` for the two writes - the same sets the
rest of the user family takes, and the same combinator, which is what the
measurement says.

The group is resolved **in the handler**, after the guard, and answers
`Group not found` - not `Could not find group by id`, which is the Groups
routes' spelling for the same condition.

Commit: `feat(admin): a user's group membership, four operations`

## Task 3: the cases

One per operation, plus the two 404s in both orders and the two 204s that look
like failures - `PUT` twice and `DELETE` of a group never joined.

The `admin/groups/members` case from cut A can stop running on an empty group
once the membership write exists. **Re-record it and say so**: its comment
currently explains why it is empty, and that reason expires here.

Commit: `test(conformance): a user's group membership`

## Task 4: the documents

`AGENTS.md`: the two families resolving the same group in opposite orders.
The roadmap: cut B done, with the served count.

Commit: `docs(p2): record the membership half`

## What this plan deliberately does not do

**No group role-mappings.** Cut C.

**It does not touch `realmRoles` and `clientRoles`.** They are `[]` and `{}`
here as they are everywhere else in cut A, and they stop being empty in cut C.
