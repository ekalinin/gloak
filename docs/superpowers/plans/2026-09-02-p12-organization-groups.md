# P12 third cut: an organization's groups and their role mappings

Branch `feat/p12-organization-groups`, off `1431331`. Twenty-two operations:
eleven under `/organizations/{org-id}/groups`, and eleven role mappings the
description tags `Role Mapper` (6) and `Client Role Mappings` (5).

Measured against a live Keycloak 26.7.1 on 2026-09-03, container `kc-orggroups`
on `:8162`, `start-dev` with no feature flags. Organizations were turned on
through the API on a **created** realm - `POST /admin/realms`, then a `PUT` of
the representation with `organizationsEnabled` true. Master's flag was never
touched, which matters more here than in the previous cut: one probe in §1.9
destroys an organization and another orphans a group from both group listings.

Every probe was built at socket level by `/tmp/orggroups/kc.py`, which writes
the request line, the headers and the body itself. Nothing in this cut used a
library that adds a header.

---

## 1. Which of the eleven behave like the realm group family's, and which do not

This is the question the cut turns on, and the answer is **two of the eleven**.
The rest differ, and they differ in both directions - one is narrower than its
realm sibling, five are shaped differently, and three invert a rule outright.

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
five realm shapes and the organization's are disjoint sets of keys, and a shared
serialiser cannot produce both from one flag.

Operation by operation:

| # | operation | same as the realm family? |
|---|---|---|
| 1 | `GET /groups` | **no** - `search` returns a **flat** list of matches anywhere in the tree, sorted by name, where the realm's returns their top-level ancestors with the matches nested; `exact=true` is honoured, which the realm listing does not offer |
| 2 | `POST /groups` | **no** - 201 **with the group in the body**, where the realm's create answers an empty one; `Location` is under the organization's own path; **no `Cache-Control`**; the duplicate 409 is a different sentence; the body's `id` makes it a **move** |
| 3 | `GET /groups/group-by-path/{path}` | **no** - the 5-key listing shape, where the realm's `group-by-path` is the single read minus `access` |
| 4 | `GET /groups/{id}` | **no** - no `subGroupCount`, no `access`, `parentId` present |
| 5 | `PUT /groups/{id}` | **yes** - 204, rename cascades the descendants' `path`, `attributes` merge and the rest replaces |
| 6 | `DELETE /groups/{id}` | **yes** on a group, and the hidden root is deletable and destroys the organization (§1.9) |
| 7 | `GET /groups/{id}/children` | **no** - **ignores `briefRepresentation`** and always answers the 5-key shape, where the realm's honours it and defaults to the full one |
| 8 | `POST /groups/{id}/children` | partly - 201 with a body and `application/json` **with no charset** on both, and `Cache-Control: no-cache` on both; but the `Location` **echoes the creating route** where the realm's names the addressing route, and the duplicate 409 is a different sentence |
| 9 | `GET /groups/{id}/members` | **no** - it serves the **organization member** representation, `membershipType` and all, and `briefRepresentation` defaults to **false** where the organization member listing one path segment up defaults to true |
| 10 | `PUT /groups/{id}/members/{userId}` | **no** - a different route shape from `PUT /users/{id}/groups/{gid}`, **409 on the repeat** where the realm's is idempotent, and a 400 for a user who is not an organization member |
| 11 | `DELETE /groups/{id}/members/{userId}` | **yes** - 204, idempotent, `Cache-Control: no-cache` |

The role-mapping half is the other way round: **all eleven behave exactly like
the realm group family's**, and that was measured rather than inherited from the
two locators that already agree. §1.7.

---

### 1.1 The hidden root, and what `path` is

`POST /organizations/{org}/groups` answers a group whose `parentId` names a
group the listing never shows. That group's `name` and `path` are the
**organization's own id** - which is what the previous cut established and what
this cut confirmed on a second organization.

What the previous cut did **not** establish, and what decides the schema:

```
root       name = <org id>          path = /<org id>
gp-top     parentId = <root id>     path = /gp-top
gp-kid     parentId = <gp-top id>   path = /gp-top/gp-kid
```

**`path` does not include the root.** A group directly under the root is
`/gp-top`, not `/<org id>/gp-top`, while the root's own path is `/<org id>`. So
the path is the ancestry with the organization root dropped, except on the root
itself, where it is the root's own name. A single `groupPath(ancestry)` shared
with the realm family answers `/<org id>/gp-top` and is wrong on every
organization group there is.

The root is invisible to the listing and reachable by id:

```
GET /organizations/{org}/groups                  the root's children, not the root
GET /organizations/{org}/groups/{root}           200, the single-read shape
GET /organizations/{org}/groups/{root}/children  the same rows as the listing
```

### 1.2 The realm group family cannot see any of it

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
group, on every verb. It is a **new 400 on the group family** and the fourth
`errorMessage` body the group chapter has.

**One realm route does see them and it is a count.**
`GET /users/{id}/groups` answers `[]` for a user in an organization group and
`GET /users/{id}/groups/count` beside it answers `{"count":1}`. One membership,
two routes, two answers - the listing filters organization groups out and the
count does not.

### 1.3 The listing, its parameters and its order

```
no parameters              the root's children, sorted by name, no default bound
?max=2                     pages - either bound alone is enough
?first=1&max=2             pages
?max=0                     []
?max=abc  ?first=abc       404 {"error":"HTTP 404 Not Found"}
?briefRepresentation=false id name path parentId subGroups attributes realmRoles clientRoles
?briefRepresentation=true  the 5-key shape - the default
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

`search` is Keycloak's LIKE: each `*` becomes `%`, a trailing `%` is appended,
so `ord` is a prefix and `*rd` an infix. That is the rule AGENTS.md records for
the user, group and identity-provider listings. What is **not** shared is the
shape: the realm group listing answers a search with the matches' top-level
ancestors and the matches nested inside them, and this one answers the matching
groups themselves, flat and sorted by name, with `subGroups` still `[]`.

The children listing takes `first` and `max` and **ignores** `briefRepresentation`.

### 1.4 The writes

```
POST /groups {"name":"x"}                 201, the 5-key body, Location under the org, no Cache-Control
POST /groups {}                           400 {"errorMessage":"Group name is missing"}
POST /groups {"name":""}                  the same 400
POST /groups  (no body at all)            500 {"error":"unknown_error",...}
POST /groups {"name":"x","bogusField":1}  400 {"error":"Invalid json representation for GroupRepresentation. Unrecognized field \"bogusField\" at line 1 column 32."}
POST /groups  a name already at this level  409 {"errorMessage":"Group with the given name already exists."}
POST /groups {"id":"<unknown>"}           404 {"error":"Could not find group by id"}
POST /groups {"id":"<an org group>"}      204, and the group moves to the top of the organization
POST /groups/{g}/children  a sibling name 409 {"errorMessage":"Sibling group with the given name already exists"}
PUT  /groups/{g} {"name":"y"}             204, and every descendant's path moves
PUT  /groups/{g} {}                       400 {"errorMessage":"Group name is missing"}
PUT  /groups/{g} {"attributes":{...}}     replaces them; a PUT naming none leaves them
DELETE /groups/{g}                        204, no Cache-Control, four of the five security headers
```

Three things there are findings rather than bookkeeping.

**The two duplicate sentences differ from the realm family's and from each
other.** Keycloak says `Group with the given name already exists.` with a full
stop at the top level and `Sibling group with the given name already exists`
**without one** beside a sibling; the realm family says
`Top level group named 'x' already exists.` and `Sibling group named 'x' already
exists.`, both with a full stop and both quoting the name. One condition, four
sentences over two families, and the pair inside this family is a fourth
full-stop split for AGENTS.md's list.

**Names are unique per sibling set and not per realm.** A top-level name can be
reused as a child of another group and back again; both were measured 201.

**The create's `id` is a move, and the move has its own 404.** A body naming an
id that resolves to nothing answers `Could not find group by id` - the *realm*
group family's spelling - where every other 404 on these twenty-two routes is
`Group does not exist`. Two not-found spellings inside one endpoint, decided by
which of the two things went missing.

**Both writes decode strictly**, and so does `POST .../children`. All three
report a line and a column. That is three more strict decoders for AGENTS.md's
list of ten - and the realm family's own `POST /groups` is strict too and is
not on that list either, which the same sweep measured as a control.

### 1.5 The members half

```
GET    /groups/{g}/members                 the organization member representation, full shape
GET    /groups/{g}/members?briefRepresentation=true   id username [firstName] [lastName] [email] emailVerified [attributes] enabled createdTimestamp membershipType
PUT    /groups/{g}/members/{u}             204, Cache-Control: no-cache
PUT    again                               409 {"errorMessage":"User is already a member of the group"}
PUT    a user who is not an org member     400 {"errorMessage":"User is not member of the organization"}
PUT    an unknown user                     404 {"errorMessage":"User does not exist"}
DELETE /groups/{g}/members/{u}             204, and 204 again, and 204 for a user who was never in it
DELETE an unknown user                     404 {"errorMessage":"User does not exist"}
```

**`briefRepresentation` defaults to `false` here and to `true` on
`GET /organizations/{org}/members` one path segment up.** Same parameter, same
representation, two defaults, and this is the fourth default that one parameter
has in this API.

**The 409 is the inversion.** `PUT /users/{id}/groups/{gid}` on the realm family
is idempotent - measured 204 twice on the same container in the same sweep - and
this one refuses the repeat.

`User does not exist` as a **404** is a new spelling: the invitation family
answers the same sentence as a **400**.

Removing the organization membership takes the group memberships with it:
`DELETE /organizations/{org}/members/{u}` left the group's member listing empty.

### 1.6 `GET /organizations/{org}/members/{u}/groups` is unblocked and wrong

Gloak serves that route as an unconditional `[]`, with a comment saying the
groups it would answer are F120's. They are not F120's any more: it answers the
member's organization groups, at any depth, in the 5-key listing shape, and this
cut has to fix it. `GET .../identity-providers/{alias}/groups` is the same
route's sibling and stays `[]` until a broker can carry a group.

### 1.7 The role mappings: the third locator agrees, measured

```
GET  role-mappings                     {} empty; {"realmMappings":[...]}; {"clientMappings":{...}}
GET  role-mappings/realm               [] / the brief role shape
POST role-mappings/realm               204, all five security headers
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

The caller-relative rules hold too, and they were measured on this locator
rather than assumed: a `manage-organizations` caller reads
`.../clients/{realm-management}/available` as `[]`, a
`manage-organizations`+`manage-users` caller sees the nine roles its own effective
roles confer, and the write of `manage-realm` is 403 to the first and 204 to a
full administrator.

So `groupmappings.go` is reusable **as handlers**. What is not reusable is the
guard: these routes take the organization roles, and the 404 sentence is the
organization family's.

### 1.8 The guards: nineteen of the twenty-two need no conjunction at all

One user per role, one token each, every route once, in the created realm.

```
the eighteen reads and writes over groups   (view|manage-organizations|manage-realm)  reads
                                            (manage-organizations|manage-realm)       writes
GET  .../groups/{g}/members                 (vo|mo|mr) AND (view|manage|query-users)
PUT/DELETE .../groups/{g}/members/{u}       (mo|mr)    AND manage-users
```

**That is the opposite of the member family.** The previous cut's nineteen
routes each needed a role from two families and no single role opened any of
them; here a single organization role opens twenty of the twenty-two, and only
the three routes that name a **user** need a second family. `query-organizations`
and `query-groups` open nothing. `view-realm`, `view-clients` and `manage-clients`
reach nothing.

The resolution order is four deep and was measured with the same tokens:

```
1  the tag's read role      a view-users caller is 403 on every route, unknown ids and all
2  the organization         404 {"errorMessage":"Organization not found."}
3  the group                404 {"errorMessage":"Group does not exist"} - to a view-organizations
                            caller on a write route, so the group precedes the write role
4  the write role           403
5  the user, on the member writes, and manage-users after it: a manage-organizations
   caller naming an unknown user gets 404 "User does not exist" and the same caller
   naming a real one gets 403
```

### 1.9 Two probes that damage state, and one that orphans a group

**`DELETE /organizations/{org}/groups/{rootId}` is a 204 and it destroys the
organization.** Afterwards `GET /organizations/{org}` is a 500, its group
listing is a 500, and a group create answers
`400 {"errorMessage":"Organization group <root id> not found"}`. The listing
`GET /organizations` still serves the row. Keycloak's own defect; run it in a
created realm.

**Moving an organization group under a realm group is a 204 and orphans it.**
`POST /groups/{realmGroup}/children` with an organization group's id answers 204,
the group's `path` becomes `/outsider/beta-kid`, and it is then in neither
listing: `GET /groups/{realmGroup}/children` is `[]` and its `subGroupCount` is
0, while the organization's own listing does not show it either. It is still an
organization group - the realm's read of it is still the 400.

The three refusals that do fire:

```
POST /organizations/{org}/groups            {"id": a realm group}   400 "Can only move organization groups"
POST /organizations/{org}/groups/{g}/children  the same             400 "Can only move organization groups"
POST /groups                                {"id": an org group}    400 "Cannot manage organization related group via non Organization API."
```

Moving a group under itself is a **204 that does nothing**.

### 1.10 Headers, verb by verb

```
GET   any read              200  Cache-Control: no-cache  application/json;charset=UTF-8  five security headers
POST  /groups               201  Location  application/json (no charset)  **no Cache-Control**  five headers
POST  /groups/{g}/children  201  Location  application/json (no charset)  Cache-Control: no-cache  five headers
POST  /groups (a move)      204  application/json          no Cache-Control
POST  children (a move)     204  application/json          Cache-Control: no-cache
PUT   /groups/{g}           204  five headers              no Cache-Control
DELETE /groups/{g}          204  four headers, no X-Frame-Options (no request Content-Type), no Cache-Control
PUT/DELETE members/{u}      204  Cache-Control: no-cache
404 Group does not exist         application/json, five headers, no Cache-Control
```

The two creates differing on `Cache-Control` is a fourth data point for
AGENTS.md's "pinned per endpoint": one route sends it, its sibling one path
segment away does not, both are 201s with bodies.

### 1.11 Wrong verbs

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
`/organizations/{org}/members`** in the previous cut, on one container regime and
one tag. So "the role-mapping paths' split" does not describe this family
either. Gloak answers 404 to all of them through `WithKeycloakFallbacks` and
**nothing is changed on the strength of it**, which is what F31 asks for.

---

## 2. The `ServeMux` hazard, checked before anything was registered

F153 is live and it is worse here than on the member routes.
`GET .../groups/group-by-path/{path...}` conflicts with **every** deeper `GET`
under `{groupID}` - `children`, `members`, `role-mappings` and its five
descendants - because a path such as
`/groups/group-by-path/children` matches both patterns and neither is a strict
subset of the other. Checked against Go 1.26.6 by registering the whole
intended set one pattern at a time: eight panics.

`{path}` as a single segment does not help - the same overlap, and the measured
paths are multi-segment (`group-by-path/gp-top/gp-kid` resolves the child).

**The resolution: `group-by-path` gets no pattern of its own.** It is served
from the `{groupID}` handler, which reads the segment and dispatches - the one
place where the literal and the wildcard genuinely occupy the same slot, so the
router is not asked to decide. Concretely one pattern,
`GET .../groups/{groupID}/{rest...}` is **not** used either; instead:

```
GET /admin/realms/{realm}/organizations/{orgID}/groups/{groupID}
```

handles `{groupID} == "group-by-path"` by reading `r.URL.Path` past the
segment. `PathValue` is unavailable for the tail, so the tail is taken off
`r.URL.EscapedPath()` and unescaped per segment, which is what
`readGroupByPath` already does for the realm route.

That is checked in `TestOrganizationGroupRoutesRegister`, which builds the real
router and asserts the four concrete paths route where they should.

---

## 3. Implementation

### 3.1 Store and schema - migration `0026_organization_group.sql`

```sql
ALTER TABLE keycloak_group ADD COLUMN organization_id TEXT;
```

One nullable column on the existing tree, not a table of its own. What says so:
an organization group is a row of the realm's tree - it has a parent, it can be
moved under a realm group and stay an organization group, and the realm's
`GET /users/{id}/groups/count` counts it while the listing filters it out. Two
tables could not express a group that is in one tree and hidden from one of its
two listings.

`GroupRepo` gains, and both drivers implement:

- `ByIDAnyOrganization` is **not** added. Instead `ByID` keeps its meaning and
  the organization filter is a new argument nowhere: the existing realm methods
  gain an `organizationID string` filter where they need one -
  `ListTopLevel`, `ListAll` and `ListUserGroups` filter to `organization_id IS
  NULL`, and three new methods serve the organization side:
  - `ListOrganizationTop(ctx, realmID, orgID)` - the root's children, by name
  - `ListOrganizationAll(ctx, realmID, orgID)` - every group of the organization, by name
  - `OrganizationRootID(ctx, realmID, orgID)` - the hidden root's id
- `Create` writes `organization_id`; `model.Group` gains `OrganizationID`.

The root group is created by `OrganizationRepo.Create` - one row per
organization, `name` = the organization's id, `parent_id` = '' - and goes with
it on delete.

### 3.2 `internal/admin/organizationgroups.go`

- `organizationGroupRepresentation` with its own field order and **no**
  `access`, **no** `subGroupCount`. Three shapes: brief (5), full (8) and the
  child create's full.
- `organizationGroupPath` - the ancestry with the root dropped.
- the eleven handlers.
- `guardOrganizationGroup(readRoles, writeRoles, fn)` in `router.go`: the tag
  role, the organization, the group, then the write role.

### 3.3 The role mappings

`groupmappings.go`'s eleven handlers are used unchanged. Only the guard is new,
and it is `guardOrganizationGroup` with the organization read/write role sets.

### 3.4 The member-groups route

`listOrganizationMemberGroups` stops answering `[]` and answers the member's
organization groups.

---

## 4. Conformance

New cases appended at the very end of `adminCases`, with fixtures appended at
the end of the map and helpers after the last helper. One fixture family,
`organizationGroupFixture(realm, seeds)`, building a realm with organizations
on, one organization, groups and members.

Ids and names are deliberately different strings - the group names sort one way
and the member usernames and e-mails another - so a test cannot pass by using
one string for two things.

## 5. Parity

`admin/organizations` is 24 / 36 before. The eleven group operations take it to
35 / 36; the eleven role mappings move `admin/role-mapper` and
`admin/client-role-mappings`. F153's nineteenth member operation stays unbuilt.
