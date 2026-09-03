# P12 third cut: an organization's groups and their role mappings

Branch `feat/p12-organization-groups`, off `1431331`. Twenty-two operations:
eleven under `/organizations/{org-id}/groups`, and eleven role mappings the
description tags `Role Mapper` (6) and `Client Role Mappings` (5).

Measured against a live Keycloak 26.7.1 on 2026-09-03, container `kc-orggroups`
on `:8162`, `start-dev` with no feature flags, removed afterwards. Organizations
were turned on through the API on a **created** realm - `POST /admin/realms`,
then a `PUT` of the representation with `organizationsEnabled` true. Master's
flag was never touched, which matters more here than in the previous cut: one
probe in §1.9 destroys an organization and another orphans a group from both
group listings.

Every probe was built at socket level by a thirty-line raw-HTTP helper that
writes the request line, the headers and the body itself. Nothing in this cut
used a library that fills a header in.

---

## 1. Measurements

### 1.0 Which of the eleven behave like the realm group family, and which do not

This is the question the cut turned on, and **the table below is the answer** -
read the count off it rather than out of a sentence. Most of the eleven differ,
in both directions: some are shaped differently and some invert a rule outright.

(The plan's own prose said "two" while its table said three, before any code was
written. A count in prose beside the list it counts is a count that will drift;
both documents now leave the counting to the table.)

The realm family's bodies, re-measured on the same container beside the
organization's rather than read out of AGENTS.md:

```
realm  GET  /groups                 id name path subGroupCount subGroups access
realm  GET  /groups/{id}            id name path subGroupCount subGroups attributes realmRoles clientRoles access
realm  GET  /groups/{id}/children   id name path parentId subGroupCount subGroups attributes realmRoles clientRoles access
realm  POST /groups                 201, empty body
realm  POST /groups/{id}/children   201, id name path parentId subGroups attributes realmRoles clientRoles access

org    GET  /groups                 id name path parentId subGroups
org    GET  /groups/{id}            id name path parentId subGroups attributes realmRoles clientRoles
org    GET  /groups/{id}/children   id name path parentId subGroups
org    POST /groups                 201, id name path parentId subGroups
org    POST /groups/{id}/children   201, id name path parentId subGroups attributes realmRoles clientRoles
```

**No organization group body carries `access` or `subGroupCount`, and every one
of them carries `parentId`** - including a group at the top of the organization,
where the realm family has none because a top-level group has no parent. So the
realm family's six shapes and this family's two are disjoint key sets, and a
shared serialiser cannot produce both from one flag.

Operation by operation:

| # | operation | same as the realm family? |
|---|---|---|
| 1 | `GET /groups` | **no** - `search` returns a **flat** list of matches anywhere in the tree, sorted by name, where the realm's returns their top-level ancestors with the matches nested; `exact=true` is honoured, which the realm listing does not offer |
| 2 | `POST /groups` | **no** - 201 **with the group in the body**, where the realm's create answers an empty one; `Location` under the organization's own path; **no `Cache-Control`**; a different duplicate sentence; and the body's `id` makes it a **move** |
| 3 | `GET /groups/group-by-path/{path}` | **no** - the five-key listing shape, where the realm's `group-by-path` is the single read minus `access` |
| 4 | `GET /groups/{id}` | **no** - no `subGroupCount`, no `access`, `parentId` present |
| 5 | `PUT /groups/{id}` | **yes** - 204, a rename cascades the descendants' `path`, `attributes` merge and the rest replaces |
| 6 | `DELETE /groups/{id}` | **yes** - 204, four of the five security headers, no `Cache-Control`; and the hidden root is deletable and destroys the organization (§1.9) |
| 7 | `GET /groups/{id}/children` | **no** - **ignores `briefRepresentation`** and always answers the five-key shape, where the realm's honours it and defaults to the full one |
| 8 | `POST /groups/{id}/children` | partly - 201 with a body, `application/json` **with no charset** and `Cache-Control: no-cache` on both; but the `Location` **echoes the creating route** where the realm's names the addressing route, and the duplicate 409 is a different sentence |
| 9 | `GET /groups/{id}/members` | **no** - it serves the **organization member** representation, `membershipType` and all, and `briefRepresentation` defaults to **false** where the organization member listing one path segment up defaults to true |
| 10 | `PUT /groups/{id}/members/{userId}` | **no** - a different route shape from `PUT /users/{id}/groups/{gid}`, **409 on the repeat** where the realm's is idempotent, and a 400 for a user who is not an organization member |
| 11 | `DELETE /groups/{id}/members/{userId}` | **yes** - 204, idempotent, `Cache-Control: no-cache` |

The role-mapping half is the other way round: **all eleven behave exactly like
the realm group family's**, and that was measured on this third locator rather
than inherited from the two that already agree. §1.7.

### 1.1 The hidden root, and what `path` is

`POST /organizations/{org}/groups` answers a group whose `parentId` names a group
the listing never shows. That group's `name` and `path` are the **organization's
own id** - which is what the previous cut established and what this cut confirmed
on a second organization.

What the previous cut did **not** establish, and what decides the schema:

```
root       name = <org id>          path = /<org id>
gp-top     parentId = <root id>     path = /gp-top
gp-kid     parentId = <gp-top id>   path = /gp-top/gp-kid
```

**`path` does not include the root.** A group directly under the root is
`/gp-top`, not `/<org id>/gp-top`, while the root's own path is `/<org id>`. So
the path is the ancestry with the organization root dropped, except on the root
itself, where it is the root's own name. `groupPath`'s plain walk - which the
realm family shares - answers the organization id as a first segment on every
organization group there is.

The root is invisible to the listing and reachable by id:

```
GET /organizations/{org}/groups                  the root's children, not the root
GET /organizations/{org}/groups/{root}           200, the single-read shape, and no parentId key
GET /organizations/{org}/groups/{root}/children  the same rows as the listing
```

### 1.2 The realm group family cannot see any of it, except one count

```
GET    /groups                       []            on a realm holding two organization groups
GET    /groups/count                 {"count":0}
GET    /groups/{orgGroup}            400 {"errorMessage":"Cannot manage organization related group via non Organization API."}
PUT    /groups/{orgGroup}            the same 400
DELETE /groups/{orgGroup}            the same 400
GET    /groups/{orgGroup}/children   the same 400
GET    /groups/{orgGroup}/role-mappings  the same 400
GET    /group-by-path/{any org path} 404 {"error":"Group path does not exist"}
```

One sentence for every route of the realm family that names an organization
group, on every verb. It is a **new 400 on the group family**.

**One realm route does see them and it is a count.**
`GET /users/{id}/groups` answers `[]` for a user in an organization group and
`GET /users/{id}/groups/count` beside it answers `{"count":1}`. One membership,
two routes, two answers - the listing filters organization groups out and the
count does not. That is why the filter sits in `internal/admin` rather than in
`GroupRepo.ListUserGroups`, which serves both.

### 1.3 The listing, its parameters and its order

```
no parameters              the root's children, sorted by name, no default bound
?max=2                     pages - either bound alone is enough
?first=1&max=2             pages
?max=0                     []
?max=abc  ?first=abc       404 {"error":"HTTP 404 Not Found"}
?briefRepresentation=false id name path parentId subGroups attributes realmRoles clientRoles
?briefRepresentation=true  the five-key shape - the default
?populateHierarchy=false   ignored, both values
?top=true                  ignored
?search=ord                ord-aaa, ord-mmm, ord-zzz - a **flat** list
?search=*rd                every group whose name contains `rd`, at any depth, flat
?search=ORD                the same three - case-insensitive
?search=%22ord-aaa%22      []  - quotes do **not** mean equality here
?search=ord&exact=true     []
?search=ord-aaa&exact=true one row
?search=                   everything - an empty search neither opens nor closes the gate
```

`search` is Keycloak's LIKE: each `*` becomes `%`, a trailing `%` is appended, so
`ord` is a prefix and `*rd` an infix. That is the rule AGENTS.md records for the
user, group and identity-provider listings. What is **not** shared is the shape:
the realm group listing answers a search with the matches' top-level ancestors
and the matches nested inside them, and this one answers the matching groups
themselves, flat and sorted by name, with `subGroups` still `[]`.

The children listing takes `first` and `max` and **ignores**
`briefRepresentation`.

### 1.4 The writes

```
POST /groups {"name":"x"}                 201, five-key body, Location under the org, no Cache-Control
POST /groups {}                           400 {"errorMessage":"Group name is missing"}
POST /groups {"name":""}                  the same 400
POST /groups  (no body at all)            500 {"error":"unknown_error",...}
POST /groups {"name":"x","bogusField":1}  400 {"error":"Invalid json representation for GroupRepresentation. Unrecognized field \"bogusField\" at line 1 column 32."}
POST /groups  a name already at this level  409 {"errorMessage":"Group with the given name already exists."}
POST /groups {"id":"<unknown>"}           404 {"error":"Could not find group by id"}
POST /groups {"id":"<an org group>"}      204, and the group moves to the top of the organization
POST /groups {"id":"<a realm group>"}     400 {"errorMessage":"Can only move organization groups"}
POST /groups {"id":"<another org's>"}     400 {"errorMessage":"Group does not belong to this organization"}
POST /groups/{g}/children  a sibling name 409 {"errorMessage":"Sibling group with the given name already exists"}
PUT  /groups/{g} {"name":"y"}             204, and every descendant's path moves
PUT  /groups/{g}  a sibling's name        409 {"error":"conflict","error_description":"Duplicate resource error"}
PUT  /groups/{g} {}                       400 {"errorMessage":"Group name is missing"}
PUT  /groups/{g} {"attributes":{...}}     replaces them; a PUT naming none leaves them
DELETE /groups/{g}                        204, no Cache-Control, four of the five security headers
```

Four of those are findings rather than bookkeeping.

**The duplicate-name sentences differ from the realm family's, from each other,
and across the two verbs.** Keycloak says `Group with the given name already
exists.` **with** a full stop at the top level and `Sibling group with the given
name already exists` **without one** beside a sibling; the realm family says
`Top level group named 'x' already exists.` and `Sibling group named 'x' already
exists.`, both with a full stop and both quoting the name. And the `PUT` renaming
a group onto a sibling's name answers a **fourth** shape,
`{"error":"conflict","error_description":"Duplicate resource error"}` - so one
condition on one resource has two error *families* one path segment apart.

**Names are unique per sibling set and not per realm.** A top-level name may be
reused as a child of another group and back again; both were measured 201.

**The create's `id` is a move, and the move has its own 404.** A body naming an
id that resolves to nothing answers `Could not find group by id` - the *realm*
group family's spelling - where every other 404 on these routes is `Group does
not exist`. Two not-found spellings inside one endpoint, decided by which of the
two things went missing. The move also **reads the name and discards it**: a body
naming an id and a *different* name is a 204 that moves the group and leaves its
name alone, while a body naming an id and **no** name is still the 400.

**All three writes decode strictly**, and all three report a line and a column.
See §2 for what that does to AGENTS.md's count.

### 1.5 The members half

```
GET    /groups/{g}/members                 the organization member representation, full shape
GET    /groups/{g}/members?briefRepresentation=true   the seven-key member shape
GET    /groups/{g}/members?first=&max=     pages
GET    /groups/{g}/members?search=&exact=&membershipType=   all three read and **ignored**
PUT    /groups/{g}/members/{u}             204, Cache-Control: no-cache
PUT    again                               409 {"errorMessage":"User is already a member of the group"}
PUT    a user who is not an org member     400 {"errorMessage":"User is not member of the organization"}
PUT    an unknown user                     404 {"errorMessage":"User does not exist"}
DELETE /groups/{g}/members/{u}             204, and 204 again, and 204 for a user who was never in it
DELETE an unknown user                     404 {"errorMessage":"User does not exist"}
```

**`briefRepresentation` defaults to `false` here and to `true` on
`GET /organizations/{org}/members` one path segment up.** Same parameter, same
representation, two defaults.

**Three routes on one resource, three answers about the query.** The organization
member listing filters and pages, its count does neither, and this listing pages
and does not filter - `search=zzzz` answered both members. `membershipType=bogus`
is a 200 here and a `500 unknown_error` on the member listing.

**The 409 on the repeat is the inversion.** `PUT /users/{id}/groups/{gid}` on the
realm family is idempotent - measured 204 twice on the same container in the same
sweep - and this one refuses the repeat. Its `DELETE` sibling is idempotent on
both, so one pair follows two rules.

`User does not exist` as a **404** is new: the invitation family answers the same
sentence as a **400**.

Removing the organization membership takes the group memberships with it:
`DELETE /organizations/{org}/members/{u}` left the group's member listing empty.

### 1.6 `GET /organizations/{org}/members/{u}/groups` was unblocked and wrong

Gloak served that route as an unconditional `[]`, with a comment saying the
groups it would answer were F120's and could not exist. They can now: it answers
the member's organization groups at any depth in the five-key listing shape.
**Fixed on this branch**, with a golden (`members-groups-populated`).
`GET .../identity-providers/{alias}/groups` is its sibling and stays `[]` until a
broker can carry a group.

### 1.7 The role mappings: the third locator agrees, measured

```
GET  role-mappings                     {} empty; {"realmMappings":[...]}; {"clientMappings":{...}}
GET  role-mappings/realm               [] / the brief role shape
POST role-mappings/realm               204, all five security headers, no Cache-Control
DELETE role-mappings/realm             204
GET  role-mappings/realm/available     every realm role not assigned, filtered by the caller
GET  role-mappings/realm/composite     the transitive expansion
GET  role-mappings/clients/{c} + available + composite, POST, DELETE   the same
POST with a malformed body             400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
POST naming an unknown role            404 {"error":"Role not found"}
any route with an unknown client       404 {"error":"Client not found"}
any route with an unknown group        404 {"errorMessage":"Group does not exist"}
briefRepresentation                    honoured by .../composite alone, on both triples
```

The caller-relative rules hold too, and they were measured on this locator rather
than assumed: a `manage-organizations` caller reads
`.../clients/{realm-management}/available` as `[]`, a
`manage-organizations` + `manage-users` caller sees the nine roles its own
effective roles confer, and the write of `manage-realm` is 403 to the first and
204 to a full administrator.

So `groupmappings.go` is reusable **as handlers** and all eleven are served by
them unchanged. What is not reusable is the guard - these take the organization
roles, where the realm group family's take `view-users`/`manage-users` - and the
404 sentence, which is the organization family's.

**A group's `realmRoles` and `clientRoles` are populated, on both families.** A
group holding `ogattr` plus `zz-role, aa-role, mm-role` answered
`"realmRoles":["aa-role","mm-role","ogattr","zz-role"]` - sorted by name, from an
insertion order that disagrees - and `"clientRoles":{"account":["ogcrole-a"]}`.
The **realm** family populates them identically. Gloak's `groupRepresentationOf`
writes `[]` and `{}` unconditionally with a comment saying "Empty until cut C",
so the realm group family is measurably wrong there. **Not fixed** - it is the
groups chapter's and moving it re-records that chapter's goldens; §3 files it.

### 1.8 The guards: nineteen of the twenty-two need no conjunction at all

One user per role, one token each, every route once, in the created realm.

```
the eighteen reads and writes over groups   (view|manage-organizations|manage-realm)  reads
                                            (manage-organizations|manage-realm)       writes
GET  .../groups/{g}/members                 (vo|mo|mr) AND (view|manage|query-users)
PUT/DELETE .../groups/{g}/members/{u}       (mo|mr)    AND manage-users
```

**That is the previous cut's rule inverted, not extended.** Its nineteen routes
each needed a role from two families and no single role opened any of them; here
`manage-organizations` alone opens nineteen of twenty-two, and only the three
routes that name a **user** need a second family. `query-organizations` and
`query-groups` open nothing at all. `view-realm`, `view-clients` and
`manage-clients` reach nothing.

The resolution order is **five** deep, and every step was separated by its own
request:

```
1  the tag's read role      a view-users caller is 403 on every route, unknown ids and all
2  the organization         404 {"errorMessage":"Organization not found."}
3  the group                404 Group does not exist - to a view-organizations caller on a
                            **write** route, so the group precedes the write role
4  the organization's write role   403
5  the user, then manage-users     a manage-organizations caller naming an unknown user gets
                                   404 "User does not exist" and the same caller naming a
                                   real one gets 403
```

A guard that checked the write role first - which is what the member family's
does - answers 403 where Keycloak answers 404 on every write in this family.
`TestOrganizationGroupGuardResolvesTheGroupBeforeTheWriteRole` and
`TestOrganizationGroupMemberWriteJudgesTheUserBeforeManageUsers` pin steps 1-4
and step 5.

### 1.9 Two probes that damage state, and one that orphans a group

**`DELETE /organizations/{org}/groups/{rootId}` is a 204 and it destroys the
organization.** Afterwards `GET /organizations/{org}` is a 500, its group listing
is a 500, and a group create answers
`400 {"errorMessage":"Organization group <root id> not found"}`. The listing
`GET /organizations` still serves the row. Keycloak's own defect; run it in a
created realm. Gloak refuses nothing here that Keycloak accepts, and the wreckage
afterwards is not something this project has a way to serve.

**Moving an organization group under a realm group is a 204 and orphans it.**
`POST /groups/{realmGroup}/children` with an organization group's id answers 204,
the group's `path` becomes `/outsider/beta-kid`, and it is then in neither
listing: `GET /groups/{realmGroup}/children` is `[]` and its `subGroupCount` is
0, while the organization's own listing does not show it either. It is still an
organization group - the realm's read of it is still the 400. Gloak has no
operation that reaches this state.

**Moving a group under its own child** is `400 {"errorMessage":"Database
operation failed"}`, and **moving a group under itself** is a 204 that does
nothing.

### 1.10 Headers, verb by verb

```
GET   any read              200  Cache-Control: no-cache  application/json;charset=UTF-8  five headers
POST  /groups               201  Location  application/json (no charset)  **no Cache-Control**  five headers
POST  /groups/{g}/children  201  Location  application/json (no charset)  Cache-Control: no-cache  five headers
POST  /groups (a move)      204  application/json          no Cache-Control
POST  children (a move)     204  application/json          Cache-Control: no-cache
PUT   /groups/{g}           204  five headers              no Cache-Control
DELETE /groups/{g}          204  four headers, no X-Frame-Options (no request Content-Type), no Cache-Control
PUT/DELETE members/{u}      204  Cache-Control: no-cache, no X-Frame-Options
404 Group does not exist         application/json, five headers, no Cache-Control
```

The two creates differing on `Cache-Control` extends AGENTS.md's "pinned per
endpoint" from 204s to **201s**: one route sends it, its sibling one path segment
away does not, both are 201s with bodies.

### 1.11 Wrong verbs, and a path under a group that no route serves

```
PUT, PATCH, DELETE  /organizations/{org}/groups              405 {"error":"HTTP 405 Method Not Allowed"}
PATCH               /organizations/{org}/groups/{g}          405
POST                /organizations/{org}/groups/{g}          404 {"error":"HTTP 404 Not Found"}
PUT                 .../groups/{g}/children                  404
POST                .../groups/{g}/members                   404
GET                 .../groups/{g}/members/{u}               404
PUT                 .../groups/{g}/role-mappings             405
PATCH               .../role-mappings/realm                  405
```

**`DELETE` on a collection is a 405 here and was a 404 on
`/organizations/{org}/members`** in the previous cut, on one tag. So "the
role-mapping paths' split" does not describe this family either. Gloak answers
404 to all of them through `WithKeycloakFallbacks` and **nothing was changed on
the strength of it**, which is what F31 asks for.

**A deeper path under a group that no route serves is a different case, and it is
served.** Measured with all five security headers:

```
GET .../groups/{g}/bogus                  404 {"error":"HTTP 404 Not Found"}   five headers
GET .../groups/{g}/role-mappings/bogus    the same
GET .../groups/{g}/members/{u}/x          the same
GET .../groups/{unknown}/children/deeper  404 {"errorMessage":"Group does not exist"}
GET .../groups/group-by-path              404 {"errorMessage":"Group does not exist"}
GET .../groups/group-by-path/             404 {"error":"Group path does not exist"}
```

So the request **does** reach the filter chain - through the group's own
sub-resource locator - and the group is resolved before the routing fails.
Letting these fall through to `WithKeycloakFallbacks`, which answers `Unable to
find matching target resource method` with **none** of the five, is what would be
wrong. The bare literal `group-by-path` is a group **id**; only the form with a
tail is the path read.

### 1.12 The `ServeMux` hazard, checked before anything was registered

F153 is live here and eight times its size.
`GET .../groups/group-by-path/{path...}` conflicts with **every** deeper `GET`
under `{groupID}` - `children`, `members`, `role-mappings` and its five
descendants - because `/groups/group-by-path/children` matches both patterns and
neither is a strict subset of the other. Checked against Go 1.26.6 by registering
the whole intended set one pattern at a time: **eight panics**. A single-segment
`{path}` does not help, and the measured paths are multi-segment
(`group-by-path/gp-top/gp-kid` resolves the child).

**The resolution is a catch-all, and here it is more faithful than the
fallback.** `GET .../groups/{groupID}/{rest...}` conflicts with nothing - every
specific pattern is a strict subset of it - and §1.11 says what it must answer
for a tail no route serves. `TestOrganizationGroupRoutesRegister` builds the real
router and asserts the four concrete paths route where they should.

**One corner is a divergence and it is filed rather than fixed.** JAX-RS prefers
the group-by-path locator where Go's `ServeMux` prefers the literal:
`GET .../groups/group-by-path/children` answers the group *named* `children` on a
live 26.7.1, measured with such a group in the organization. The guard checks the
literal before resolving the group, so all three collidable names - `children`,
`members`, `role-mappings` - behave, and `group-by-path/role-mappings/realm`
resolves a two-segment path. **Fixed on this branch** inside
`guardOrganizationGroupOf`.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **An organization's groups are the realm's own tree with a column, and three
  measurements say so at once.** They have a parent like any other group; moving
  one under a realm group is a **204** that leaves it an organization group, still
  refused by the realm's own read; and `GET /users/{id}/groups` filters them out
  while `GET /users/{id}/groups/count` beside it **counts** them. One membership,
  two routes, two answers - so the filter cannot live in the store, which serves
  both. A second table could not express a row that is in one tree and hidden
  from one of that tree's two reads.

- **The organization group family is not the realm group family with a different
  prefix, and only three of its eleven operations agree.** No body it serves
  carries `access` or `subGroupCount`, and every one carries `parentId` -
  including a group at the top of the organization, where a top-level realm group
  has none. The two families' key sets are disjoint. What agrees: the update, the
  delete and the member removal. What inverts: the children listing **ignores**
  `briefRepresentation` where the realm's honours it; `POST /groups` answers 201
  **with the group** where the realm's answers an empty body; the child create's
  `Location` echoes the **creating** route where the realm's names the addressing
  one; and the member join is a **409** on the repeat where
  `PUT /users/{id}/groups/{gid}` is idempotent.

- **`path` does not include the hidden root.** The root's own path is
  `/<organization id>`, which is its own name; a group directly under it is
  `/gp-top` and **not** `/<organization id>/gp-top`; a child of that is
  `/gp-top/gp-kid`. So the ancestry's first element is dropped whenever there is
  anything below it, and the shared `groupPath` walk answers the organization id
  as a first segment on every organization group there is. `group-by-path` starts
  at the root for the same reason, which is why
  `group-by-path/<organization id>/gp-top` is a 404.

- **Nineteen of the twenty-two routes are opened by a single role, which is the
  previous cut's rule inverted.** `manage-organizations` alone was 403 on every
  one of the member family's nineteen routes and opens nineteen of these
  twenty-two. Only the three that name a **user** need a second family:
  `GET .../groups/{g}/members` takes the read pair **and**
  `view|manage|query-users`, and the two member writes take the write pair **and**
  `manage-users`. `query-organizations` and `query-groups` open nothing at all.

- **The order is five deep and the group precedes the write role.** The tag's
  read pair gates first, then the organization
  (`404 Organization not found.`), then the group
  (`404 Group does not exist` - answered to a `view-organizations` caller on a
  **write** route), then the organization's write role, then the user, then
  `manage-users`. A guard checking the write role first - the member family's
  shape - answers 403 where Keycloak answers 404 on every write in this family.

- **One condition, four sentences, and two error families.** A duplicate group
  name is `{"errorMessage":"Group with the given name already exists."}` at the
  top level **with** a full stop and
  `{"errorMessage":"Sibling group with the given name already exists"}` beside a
  sibling **without** one; the realm family's two both quote the name and both end
  in a full stop. And a `PUT` renaming a group onto a sibling's name answers a
  fourth shape entirely,
  `{"error":"conflict","error_description":"Duplicate resource error"}` - so the
  same condition on the same resource has two error *families* one path segment
  apart.

- **A group create's body `id` is a move, and the move has its own not-found
  spelling.** `POST .../groups` and `POST .../groups/{g}/children` carrying an
  `id` answer 204 with an empty body and reparent that group; the name is read,
  validated and **discarded**, so a different name moves the group and leaves its
  name alone while no name at all is still `400 Group name is missing`. An id that
  resolves to nothing answers the **realm** family's `Could not find group by id`,
  where every other 404 on these twenty-two routes is `Group does not exist` - one
  endpoint, two spellings, decided by which of the two things went missing. A
  realm group is `Can only move organization groups` and another organization's is
  `Group does not belong to this organization`, one preposition from the read's
  `Group does not belong to the organization`.

- **A group of another organization is a 400, not a 404.** Every route naming a
  `{groupID}` has three answers rather than two: `404 Group does not exist` for an
  id that resolves to nothing, `400 Group does not belong to the organization` for
  one that resolves to another organization's group, and the body for one of this
  organization's.

- **`briefRepresentation` defaults to `false` on
  `GET .../groups/{g}/members` and to `true` on `GET /organizations/{org}/members`
  one path segment up** - one parameter, one representation, two defaults. And the
  three routes over that representation disagree three ways about the rest of the
  query: the member listing filters and pages, its count does neither, and the
  group member listing pages and ignores `search`, `exact` and `membershipType`
  outright, where `membershipType=bogus` is a 200 here and a `500 unknown_error`
  next door.

- **`search` on the organization group listing answers its matches flat.** The
  match rule is Keycloak's LIKE, the same one the user, group and identity
  provider listings follow - `ord` is a prefix, `*rd` an infix - and `"quotes"`
  mean nothing here where they mean equality on the user listing. What differs is
  the **shape**: the realm group listing answers a search with the matches'
  top-level ancestors and the matches nested inside them, and this one answers the
  matching groups themselves, sorted by name, with `subGroups` still `[]`.
  `exact=true` is honoured here and the realm listing has no such parameter.

- **The hidden root is deletable and deleting it destroys the organization.**
  `DELETE /organizations/{org}/groups/{rootId}` is a 204; afterwards the
  organization's own read is a 500, its group listing is a 500, and a group create
  answers `400 {"errorMessage":"Organization group <id> not found"}` - while
  `GET /organizations` still serves the row. **Moving an organization group under
  a realm group is a 204 that orphans it**: it appears in neither listing and is
  still refused by the realm's read. Both are Keycloak's own defects; measure them
  in a created realm.

- **A path under a group that no route serves is the generic 404 with all five
  security headers, not the unmatched-path body with none of them.**
  `.../groups/{g}/bogus`, `.../groups/{g}/role-mappings/bogus` and
  `GET .../groups/{g}/members/{u}` all answer `{"error":"HTTP 404 Not Found"}`
  with the five, because the request reached the filter chain through the group's
  own sub-resource locator - and `.../groups/{unknown}/children/deeper` answers
  `Group does not exist`, so the group is resolved before the routing fails. The
  bare literal `group-by-path` is a group **id** (`Group does not exist`) and only
  the form with a tail is the path read.

- **A group's `realmRoles` and `clientRoles` are populated, on both families.**
  A group holding four realm roles and one client role answers
  `"realmRoles":["aa-role","mm-role","ogattr","zz-role"]` - sorted by name, from an
  insertion order that disagrees - and `"clientRoles":{"account":["ogcrole-a"]}`.
  The **realm** group family populates them identically, and Gloak's
  `groupRepresentationOf` writes `[]` and `{}` unconditionally. The organization
  family serves them; the realm family's gap is filed rather than fixed.

- **The organization group tag answers a wrong verb three ways, and `DELETE` on a
  collection is a 405 here where it was a 404 on the member collection.**
  `PUT`, `PATCH` and `DELETE` on `.../groups` are all
  `405 {"error":"HTTP 405 Method Not Allowed"}`; `POST` on an item, `PUT` on
  `children`, `POST` on `members` and `GET` on `members/{u}` are the generic 404.
  So the role-mapping paths' split does not describe this family, and the previous
  cut's `DELETE .../members` 404 and this `DELETE .../groups` 405 are one tag
  disagreeing with itself. Gloak answers 404 to all of them and nothing was
  changed on the strength of it.

### Lines this cut contradicts

- **"Ten strict JSON decoders"** is short by at least four. `POST
  /organizations/{org}/groups`, `PUT .../groups/{group-id}` and
  `POST .../groups/{group-id}/children` all decode strictly and all report a line
  and a column - and the **realm family's own `POST /groups`**, measured as a
  control in the same sweep, does too and is not on the list either. The bullet
  also asks whether the organization pair reports a position; the group writes do,
  which is a fourth family that does.

- **The twenty-four not-found spellings, entry (20).** It reads
  "`Group does not exist` from all twenty-two operations under
  `/organizations/{org-id}/groups`". It is **twenty-one**: the two creates' move
  path answers `Could not find group by id` for an id that resolves to nothing.
  And `User does not exist` as a **404** is a new spelling - the invitation family
  answers the same words with a 400.

- **The `Location` bullet's "the route that makes a child is not the route that
  addresses it".** True of the realm family and false here:
  `POST /organizations/{org}/groups/{g}/children` answers
  `.../organizations/{org}/groups/{parent}/children/<new id>`. So there are two
  more server-minted uuid tails, and one of them contradicts the sentence the
  bullet draws from its neighbour.

- **The `Cache-Control` bullet is about 204s and the split reaches 201s.** The
  two organization group creates are both 201s with bodies, one path segment
  apart; `POST .../groups` sends no `Cache-Control` and
  `POST .../groups/{g}/children` sends `no-cache`. "Pinned per endpoint" survives;
  "on a 204" does not.

- **The group-tree bullet's `POST /groups` answers 201 with an empty body** is
  the realm family's rule alone. The organization family's `POST .../groups`
  answers 201 with the group in it, `application/json` with no charset.

---

## 3. Follow-up dispositions

### F120 - the organization group family is blocked on a hidden root group

**Closed.** All twenty-two operations are served, and every one of them carries a
golden of its own; the error cases carry more. The root group is created with the
organization, its `name` is the organization's id, and `path` drops it (§1.1).
The entry's remaining sentence - "the eleven group
operations and the eleven role-mapping operations that go with them are still
unbuilt" - is now false and the entry can be closed in the follow-ups list, which
this cut did not edit.

`GET /organizations/{org}/members/{member-id}/groups` was an unconditional `[]`
on F120's authority and is now correct; that was a **shipped divergence**, not a
gap, and it is fixed on this branch.

### F153 - two organization member routes overlap on one path and `ServeMux` panics

**Untouched, and its shape recurred eight times over.** The nineteenth member
operation is still unbuilt for the reason the entry gives. What this cut adds is
that the same hazard has a **resolution** where the overlapping pattern can be
made a strict superset: `.../groups/{groupID}/{rest...}` swallows every deeper
`GET`, and §1.11 measures what those must answer -
`404 {"error":"HTTP 404 Not Found"}` **with all five security headers**, not the
unmatched-path body. The entry's objection to a wildcard dispatcher - "those
answer the unmatched-path 404 with none of the five security headers, which only
`WithKeycloakFallbacks` can produce" - **is false for a path under a resolvable
sub-resource locator**, which is what the group paths are. Whether it is also
false for `/organizations/{a}/{b}/{c}` is unmeasured and is the request to send
before anybody reopens F153.

### F121 - the `Workflows` tag needs a YAML writer

**Untouched.** Nothing in this cut goes near it and the entry's own reason - that
it is a decision about `internal/httpx` before it is nine handlers - is unchanged.

### F95 - a client's `attributes` is serialised from a Go map

**Untouched, and the pattern it asks for gained a sixth member.** An organization
group's `attributes` and its `clientRoles` are both Java maps and both go through
an ordered slice with a marshaller of its own, `javaMapAttributes` and
`javaMapRoleNames`, placed by `javamap.KeyOrder` and asserting real bytes:
`admin/organizations/groups-update-attributes` holds
`{"gloak-probe-z":["w"],"gloak-probe-k":["v1","v2"]}`, which a Go map would
invert. Both go through `marshalOrderedValue` so the `SetEscapeHTML(false)`
divergence cannot come back.

The client is still the holdout and the fix is still one `model.StringMap` away.

### New: the realm group family serves two empty collections Keycloak populates

`groupRepresentationOf` writes `"realmRoles":[]` and `"clientRoles":{}`
unconditionally, with a comment reading "Empty until cut C. A group holding roles
is not served yet". Measured 2026-09-03 on a **realm** group holding one realm
role and one client role: Keycloak answers `"realmRoles":["ogattr"]` and
`"clientRoles":{"account":["ogcrole-a"]}`. So the comment is stale and the
representation is wrong on any group that holds a role.

**Not fixed here.** It lives in `groups.go`, it re-records the groups chapter's
goldens, and no committed golden can currently see it because no realm-group
fixture assigns a role - which is also why it survived. The organization family
serves it correctly and `admin/organizations/groups-list-full` pins it.

---

## 4. Parity before and after

```
                            before      after
admin/organizations         24 / 36     35 / 36
admin/role-mapper           12 / 18     18 / 18
admin/client-role-mappings  10 / 15     15 / 15
total                      400 / 541   422 / 541      +22
```

Twenty-two operations, and two chapters are now complete. The one operation
`admin/organizations` still lacks is F153's
`GET /organizations/members/{member-id}/organizations`.

**The eleven role-mapping cases are filed under the chapters whose tags own
them**, not under `admin/organizations` where their paths live. They were under
`admin/organizations` first, and the meter read **46 of 36** - it counts distinct
operations against the OpenAPI tag's count, so a case filed by path rather than by
tag inflates one chapter's numerator past its denominator and hides two other
chapters' progress. That is the failure `Case.SecondRealm`'s doc comment names in
another form: counting the wrong thing reports diligence as coverage.

### The mutation pass

Twenty-three mutations, one per claim, each confirming the **named** test fails,
each reverted with `git status --porcelain` checked afterwards. Two survived the
first pass and both were findings:

- **`sort.Strings(realmRoles)` and the `sort.Strings` over each client's role
  names in `groupRoleNames` were dead code.** `RoleRepo.ListGroupRoles` already
  carries `ORDER BY r.name` in both drivers, so the rows arrive sorted and neither
  sort could change a byte. **Both removed on this branch**; the claim now lives
  where the order is actually decided, and mutating that `ORDER BY` to `DESC`
  kills `admin/organizations/groups-list-full`.
- **The golden that was meant to pin the role order held one role**, where a sort
  is the identity. The fixture now creates two realm roles and assigns them in the
  order that disagrees with their names, so the golden reads
  `["gloak-probe-og-arole","gloak-probe-og-role"]` and a serving path in insertion
  order fails. That is the same hole AGENTS.md records swallowing five survivors in
  four cuts.

A third looked like a survivor and was a mis-named test:
`admin/organizations/groups-create-moves` is a golden over a **204 with an empty
body**, so it cannot see the move at all. The effect is asserted by
`TestOrganizationGroupCreateMovesOnAnID` in `internal/admin`, which the mutation
does kill.

### Recordings this cut moved, and why

- Four goldens gained `"containerId":"{{string}}"` - a realm role's `containerId`
  is the realm's internal id, which the harness has **no capture for** where a
  client role's is captured by a fixture step. Declaring `Volatile` follows
  `admin/role-mapper/list-realm.http`'s precedent, and because `Normalize` runs
  inside `normalisePasses` the recorder writes the placeholder too, so the
  declaration forced the re-record.
- Three `Unordered` masks were dropped as inert: `"."` over one element and over
  `[]`. The sibling that keeps its mask,
  `admin/role-mapper/org-group-realm-available`, carries three elements, which is
  what establishes that the order really is irreproducible where there is
  something to order.
- Five goldens moved when the second realm role landed
  (`groups-list-full`, `groups-read`, `org-group-all`, `org-group-realm`,
  `org-group-realm-composite`).

### What is left undone

- The realm group family's empty `realmRoles`/`clientRoles`, filed in §3.
- F153's nineteenth member operation, and the measurement that would let it be
  reopened.
- `GET .../identity-providers/{alias}/groups` is still `[]` for want of a broker
  that can carry a group, which is a fixture problem rather than a handler one.
