# Groups: P2's third cut

Date: 2026-08-28
Status: accepted

## 1. What this is

P2's third and last cut, and what closes P2. The roadmap allots it 24
operations: `Groups` 9, a user's group membership 4, and the group halves of
`Role Mapper` and `Client Role Mappings` 11.

That decomposition was written before anyone counted, so it was checked against
the vendored description before this document was written. It holds exactly:

| Piece | In the description | Counted here |
|---|---|---|
| `Groups` tag | 11 | **9** - the two `management/permissions` operations are fine-grained admin permissions, which is P10 |
| a user's group membership | 4, all tagged `Users` | 4 |
| group role-mappings | 22 | **11** - the other 11 are under `/organizations/{org-id}/groups/...`, which is P12 |

9 + 4 + 11 = 24.

Everything below section 3 is measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on 2026-08-28, with the transcript
printed from the same argv that was executed.

## 2. Three sub-cuts, in dependency order

**Cut A, the group tree - 9 operations.** `GET`/`POST /groups`,
`GET /groups/count`, `GET`/`PUT`/`DELETE /groups/{id}`,
`GET`/`POST /groups/{id}/children`, `GET /groups/{id}/members`. It needs a new
model, a new store repository and a new handler file, and nothing else in the
cut can start without it.

**Cut B, membership - 4 operations.** `GET`/`PUT`/`DELETE` on
`/users/{id}/groups...` and its count. Small, and it depends on A for the group
and on the existing user family for the subject.

**Cut C, the group role-mappings - 11 operations.** The five realm reads and
writes and the five client ones, plus the combined view. Every shape here is
already built for users; what is new is that the holder is a group.

The order is forced by the model, not by preference: B and C both address a
group by id.

## 3. What is already known to be reusable

The role-mapping half of P2's second cut left three things that Cut C needs and
that must not be re-derived:

- `eachMapping`'s **id-and-name agreement rule**, closed as F33: an entry is
  accepted exactly when both keys resolve to the same role in the route's
  container, decided before the caller check.
- `mayGrantRole`, F28's caller-relative predicate, and `grantable`, which
  re-applies the write guard before filtering an `available` read.
- `guardUserSubject`, the two-stage guard: coarse gate, resolve the subject,
  fine check.

**None of them may be assumed to transfer.** Every one was measured on the user
routes; the group routes are a different resource, and this repository has
already had to revert two rules extended from a neighbouring endpoint. Cut C's
first task is to re-measure them on a group holder, and the plan says so.

## 4. The representations, and there are four of them

Measured 2026-08-28. The bodies below are as recorded, so the key order is part
of the contract.

**The listing**, `GET /groups`, defaults to the brief shape:

```json
[{"id":"...","name":"probe-top","path":"/probe-top","subGroupCount":0,"subGroups":[],
  "access":{"view":true,"viewMembers":true,"manageMembers":true,"manage":true,"manageMembership":true}}]
```

**The single read**, `GET /groups/{id}`, adds three keys between `subGroups` and
`access`:

```json
{"id":"...","name":"probe-top","path":"/probe-top","subGroupCount":0,"subGroups":[],
 "attributes":{},"realmRoles":[],"clientRoles":{},"access":{...}}
```

`briefRepresentation=false` on the listing produces this shape, so the two are
one representation with a flag, and the flag defaults the opposite way from the
user listing's.

**A child** carries `parentId`, and the create's response and the children
listing **disagree about `subGroupCount`**. The `POST /groups/{id}/children`
response has no `subGroupCount`:

```json
{"id":"...","name":"probe-child","path":"/probe-top/probe-child","parentId":"...",
 "subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{},"access":{...}}
```

while `GET /groups/{id}/children` has one:

```json
[{"id":"...","name":"probe-child","path":"/probe-top/probe-child","parentId":"...",
  "subGroupCount":0,"subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{},"access":{...}}]
```

**A user's groups**, `GET /users/{id}/groups`, is a fourth shape and the
narrowest of them - no `subGroupCount`, no `attributes`, no `access`:

```json
[{"id":"...","name":"probe-child","path":"/probe-renamed/probe-child","parentId":"...","subGroups":[]}]
```

Four shapes of one resource. Serving them from one struct with `omitempty` will
not reproduce this: `subGroups` is `[]` in all four and `attributes` is `{}`
where present, and both are what `omitempty` drops. The user representation
already solved this with pointer fields, and the same technique applies.

## 5. Six behaviours that look like bugs and are not

Each is measured, and each would be "tidied up" by a careful implementer.

**`POST /groups` returns 201 with an empty body; `POST /groups/{id}/children`
returns 201 with the group in it.** Two creates on one resource, one page apart,
disagreeing about whether a create has a body.

**`GET /groups/count` returns `{"count":0}`, an object.** `GET /users/count`
next door returns a bare JSON number. The two counts on this API do not agree
about what a count is.

**The count counts the whole tree.** One top-level group with one child answers
`{"count":2}`, while the listing shows one row. The listing is top-level and the
count is not.

**`subGroups` is `[]` unless `search` is set, and `subGroupCount` carries the
truth.** A parent with one child lists as `"subGroupCount":1,"subGroups":[]`,
and `children` is how the tree is walked.

**This paragraph asserted "always" and that was wrong.** Corrected 2026-08-28
while building cut A, from the measurement in section 5.1: under `search` the
listing nests the matching descendants inside their ancestor. Section 8's first
version listed "whether `subGroups` is ever non-empty" as undecided and said
none was assumed, which is the only reason this cost a measurement rather than a
wrong implementation.

### 5.1 `search` matches the whole tree and pages the matches, not the rows

Measured 2026-08-28. Three groups match `alpha`: `alpha-one` and `beta-alpha` at
the top level, and `alpha-kid`, a child of `beta-alpha`.

```
?search=alpha                -> 2  [alpha-one, beta-alpha]
?search=alpha&max=1          -> 1  [beta-alpha]
?search=alpha&max=2          -> 2  [alpha-one, beta-alpha]
?search=alpha&first=1        -> 2  [alpha-one, beta-alpha]
?search=alpha&first=2        -> 1  [beta-alpha]
?search=alpha&first=1&max=1  -> 1  [alpha-one]
```

`max=1` returning `beta-alpha` rather than `alpha-one` is what gives it away.
One rule fits all six rows: **match over the whole tree, sort by name, page the
matches, then return the top-level ancestors of the page.** The matches are
`[alpha-kid, alpha-one, beta-alpha]`, so `max=1` takes `alpha-kid`, whose
top-level ancestor is `beta-alpha`.

The matching descendant comes back **nested**:

```json
[{"id":"...","name":"beta-alpha","path":"/beta-alpha","subGroupCount":1,
  "subGroups":[{"id":"...","name":"alpha-kid","path":"/beta-alpha/alpha-kid",
                "parentId":"...","subGroupCount":0,"subGroups":[],"access":{...}}],
  "access":{...}}]
```

The match is a case-insensitive substring: `one` matches `alpha-one`, and
`ALPHA` matches both.

### 5.2 Paging without `search` is a plain slice, and it is a third rule

```
?max=1   -> 1     ?first=1  -> 2     ?first=1&max=1  -> 1
?max=0   -> 0     ?first=99 -> 0
?max=-1  -> 3 (ignored)     ?first=-1&max=1 -> 1 (ignored)
```

Either bound alone pages. That is **not** the role listings' rule, which pages
only when `search` is non-empty or both bounds are present, and not the user
listing's either. Three listings on this API, three paging rules, each measured
on its own.

### 5.3 `top=true` on the count is ignored when `search` is set

```
/groups/count                        -> {"count":4}   the whole tree
/groups/count?top=true               -> {"count":3}   top level only
/groups/count?search=alpha           -> {"count":3}   matches over the whole tree
/groups/count?search=alpha&top=true  -> {"count":3}   top ignored
```

Two of the three top-level groups match `alpha`, so an honoured `top=true` would
answer 2. It answers 3.

**`path` is derived and cascades.** Renaming a parent from `probe-top` to
`probe-renamed` changed the child's `path` to `/probe-renamed/probe-child` while
its `name` stayed `probe-child`. So `path` is computed from the ancestry on
read, not stored on write.

**Membership does not cascade upward.** A user in the child is a member of the
child and **not** of the parent: `GET /groups/{child}/members` returns the user
and `GET /groups/{top}/members` returns `[]`.

## 6. Four error shapes, and two spellings for one missing group

```
POST /groups, duplicate name  -> 409 {"errorMessage":"Top level group named 'probe-top' already exists."}
POST /groups, no name         -> 400 {"errorMessage":"Group name is missing"}
GET|PUT|DELETE /groups/{unknown} -> 404 {"error":"Could not find group by id"}
PUT /users/{id}/groups/{unknown} -> 404 {"error":"Group not found"}
```

Three things to carry over exactly.

The 409 and the 400 use `errorMessage`; the two 404s use `error`. **One resource,
two error families**, which is the shape the clients and users endpoints already
have.

The 409 ends in a full stop and the 400 does not.

**A missing group is spelled two different ways** depending on which route family
asked. `Could not find group by id` on the `Groups` routes, `Group not found` on
the membership route. A shared not-found helper gets one of the two wrong, which
is the mistake the four role not-found spellings already record.

## 7. The guards, and `query-groups` is the tell

One caller per role, a fresh token minted immediately before each call:

```
caller          LIST  COUNT  READ  CREATE  MEMBERS  PUT membership
view-users      200   200    200   403     200      403
query-users     403   403    403   403     403      403
manage-users    200   200    200   201     200      204
view-clients    403   403    403   403     403      403
query-groups    200   200    403   403     403      403
manage-realm    403   403    403   403     403      403
```

**Groups are authorised out of the users family, not a family of their own.**
`manage-realm` is 403 on every one of them, and `view-users` opens the reads.

`query-groups` opens the listing and the count and nothing else - the same shape
`query-users` has over the user routes, which the sweep of 2026-08-28 turned into
`guardUserSubject`'s two stages. So the group routes want the same combinator
with a different coarse gate, and **whether the two-stage rule holds here at all
is a measurement Cut A must take**: the guards above were measured on a group
that exists. Nothing yet says what a caller that passes the coarse gate gets for
a group that does not.

`query-users` being 403 on the group listing while `query-groups` is 200 is
worth stating on its own, because the two roles are otherwise siblings and
`view-users` is composite over both.

## 8. What this document does not decide

**The store shape.** Whether the parent link is a column on the group row or a
join table, and how `path` is computed, are implementation questions the plan
takes. Nothing observable depends on the answer.

**Group attributes, realm roles and client roles in the representation.** They
are measured as `{}`, `[]` and `{}` on a group that has none. What a group that
has some looks like is not measured, and Cut C is where `realmRoles` and
`clientRoles` stop being empty. Cut A serves the empty shapes and says so.

~~**Whether `subGroups` is ever non-empty.**~~ Decided 2026-08-28: `search`
expands it, and section 5.1 has the measurement. The original wording said none
was found and none was assumed, which is why finding one cost a measurement
rather than a wrong implementation.

**Fine-grained admin permissions**, the two `management/permissions` operations.
They are P10 and they are excluded from the 9 above by that allocation, not by
this document.
