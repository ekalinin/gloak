# P12 first cut: organizations

Measured against a live Keycloak 26.7.1 (`quay.io/keycloak/keycloak:26.7.1
start-dev`, container `kc-org` on port 8122) on 2026-08-31. Every value below
came off that server; none is written from memory.

## 1. What a default container answers

The brief for this cut proposed that `ORGANIZATION` might be a preview feature,
in which case a default `start-dev` would answer the whole tag the way
`client-types` answers 501. **It is not, and it does not.** Both halves of that
guess are wrong, and they are wrong in different directions.

`GET /admin/serverinfo` on a default container:

```json
{"name":"ORGANIZATION","label":"Organization support within realms",
 "type":"DEFAULT","dependencies":[],"enabled":true}
```

`type` is `DEFAULT`, not `PREVIEW`, and `enabled` is `true`. `ORGANIZATION` is
**not** in `profileInfo.disabledFeatures`, where `CLIENT_TYPES` and
`CLIENT_SECRET_ROTATION` both are. `--features=organization` is not needed and
was never used: everything in this document is a default `start-dev`.

What refuses the tag is a **per-realm flag**, `organizationsEnabled`, which is
one of the realm representation's 106 keys and is `false` on master and on every
realm `POST /admin/realms` creates. With it off, every path under
`/admin/realms/{realm}/organizations` answers:

```
404 Not Found
Content-Type: application/json
{"errorMessage":"Organizations not enabled for this realm."}
```

Sixty bytes, the `errorMessage` family, `application/json` with no charset -
which is the error half of the charset rule, not an exception to it. Measured on
six different paths across five of the tag's six sub-families, all identical.

**One `PUT` opens the whole tag.** `PUT /admin/realms/master` with
`{"organizationsEnabled":true}` answers 204, and `GET .../organizations` answers
`200 []` immediately afterwards. `POST /admin/realms` with the flag in the
creation body works too, so a realm can be born with organizations on.

So this cut is **not** one measured refusal repeated. It is a real
thirty-six-operation tag on an endpoint family a default container serves, plus
a refusal that is itself a contract and that governs all forty-seven paths.

### Where the gate sits in the order

The gate is **after** authorization, which is the opposite of `client-types`.
Measured on `GET /admin/realms/master/organizations` with the flag off:

| caller | answer |
|---|---|
| no `Authorization` header | 401 `{"error":"HTTP 401 Unauthorized"}` |
| valid token, unknown realm | 404 `{"error":"Realm not found."}` |
| valid token, **no admin role** | **403** `{"error":"HTTP 403 Forbidden"}` |
| valid token, `view-organizations` | 404 `Organizations not enabled for this realm.` |
| full administrator | 404 `Organizations not enabled for this realm.` |
| `PATCH`, no admin role | **405** `{"error":"HTTP 405 Method Not Allowed"}` |

Six steps, pinned one at a time: method, then realm, then authentication, then
**authorization**, then the feature, then the organization. `client-types` puts
its feature check *before* authorization and therefore has no role list at all;
organizations puts it *after* and therefore has one. Reusing `guardRealmFeature`
here would answer 404 to a caller Keycloak answers 403, so the two need separate
guards even though they look like one shape.

## 2. The allocation exercise

The vendored description tags **36** operations `Organizations` and **9**
`Workflows`. Counted from the file, not from the roadmap.

**Forty-seven operations have `/organizations` in their path**, not
thirty-six. The extra eleven are tagged elsewhere:

| tag | count | paths |
|---|---|---|
| `Organizations` | 36 | the tag's own |
| `Role Mapper` | 6 | `.../organizations/{org-id}/groups/{group-id}/role-mappings[/realm[/available\|/composite]]` |
| `Client Role Mappings` | 5 | `.../organizations/{org-id}/groups/{group-id}/role-mappings/clients/{client-id}[/available\|/composite]` |

**The brief's open question has a clean answer: they are a *different* eleven,
at overlapping paths.** The `Organizations` tag's own `/groups` family is also
exactly eleven -

```
GET  POST         .../organizations/{org-id}/groups
GET               .../organizations/{org-id}/groups/group-by-path/{path}
GET  PUT  DELETE  .../organizations/{org-id}/groups/{group-id}
GET  POST         .../organizations/{org-id}/groups/{group-id}/children
GET               .../organizations/{org-id}/groups/{group-id}/members
PUT  DELETE       .../organizations/{org-id}/groups/{group-id}/members/{userId}
```

- and it shares the `/{org-id}/groups/{group-id}` prefix with the role-mapping
eleven while sharing not one operation with them. Two elevens, one prefix,
disjoint sets. The coincidence of the count is what made the question worth
asking.

**Building organizations does unlock them, and they should be counted when they
are built.** They are live on the server: every one of the eleven answers
`404 {"errorMessage":"Group does not exist"}` for a group that is not in the
organization, which is a real handler refusing a real lookup rather than a
router miss. They are not in *this* cut - see section 3 - but they are P12's,
and when the org group tree lands they come with it. That moves
`admin/role-mapper` 6 -> 12 of 18 and `admin/client-role-mappings` 5 -> 10 of
15, closing both tags outright.

### The description checked against the server

Three previous cuts have been paid for doing this, so it was done again. Two
things came back that the description does not say.

**Workflows is not gated by `organizationsEnabled`** and is not part of the
organizations feature at all: `GET /admin/realms/{realm}/workflows` answers
`200` on a realm with the flag off. It is an independent surface that happens to
share this roadmap row.

**And the Workflows tag does not serve JSON.**

```
GET /admin/realms/master/workflows
200
transfer-encoding: chunked
Content-Type: application/yaml;charset=UTF-8

--- []
```

`application/yaml`, a YAML document body, and **no `Content-Length` at all** -
the only chunked response this project has measured. Every other tag in the
Admin API is `application/json` with a length. Its error bodies are JSON,
though, and there are two shapes within the tag: `POST /workflows` with `{}`
answers `{"errorMessage":"Workflow name cannot be null or empty."}` and
`GET /workflows/{id}` with a bad id answers
`{"error":"Not a valid workflow resource: nosuchid"}`. Serving Workflows means
teaching `internal/httpx` a YAML writer, which is a boundary decision and not a
handler. **Deferred out of P12's first cut and out of any organizations cut**;
it is filed as a finding rather than planned here.

## 3. The cut

**The organization as a resource: six operations.** The same shape as P4's first
cut, which took the realm as a resource and left its sub-families to the second.

```
GET    /admin/realms/{realm}/organizations
POST   /admin/realms/{realm}/organizations
GET    /admin/realms/{realm}/organizations/count
GET    /admin/realms/{realm}/organizations/{org-id}
PUT    /admin/realms/{realm}/organizations/{org-id}
DELETE /admin/realms/{realm}/organizations/{org-id}
```

Left for later cuts, with reasons rather than as an unexplained remainder:

| family | ops | why not now |
|---|---|---|
| `/groups` | 11 | an organization owns a **hidden root group** - a created org group came back with a `parentId` naming an id the org's own representation never mentions - and it is a second group tree beside the realm's. That is a schema question, not a handler. |
| role-mappings | 11 | depend on the org group tree above. |
| `/members` | 9 | needs a user in an organization, and `POST .../members/invite-user` is **500 `Failed to send invite email`** on a container with no SMTP, which is a contract to measure carefully rather than in passing. |
| `/identity-providers` | 5 | P9 owns identity providers and Gloak has none. |
| `/invitations` | 4 | invitations are created by the member routes, so an empty listing is all that is reachable without them. |
| Workflows | 9 | YAML, see above. |

## 4. The measured contract for the six

### Two shapes of an organization, and a third decided by a query parameter

```
GET  /organizations                          id name alias enabled       domains
GET  /organizations?briefRepresentation=false id name alias enabled attributes domains
GET  /organizations/{id}                     id name alias enabled attributes domains
```

`briefRepresentation` defaults to **true** on the listing and adds `attributes`
when `false`. **The single read ignores it**: `?briefRepresentation=true` gave a
body identical to the one with no parameter at all, `attributes` included. That
is this API's usual shape - a parameter honoured by one route and ignored by its
neighbour - and a shared serialiser taking a boolean would get one of the two
wrong.

`description` and `redirectUrl` are present only when set, between `enabled` and
`attributes`:

```json
{"id":"…","name":"gloak-probe-full","alias":"gloak-probe-full-alias","enabled":false,
 "description":"desc","redirectUrl":"http://x/","attributes":{"k":["v"]},
 "domains":[{"name":"full.example.com","verified":true}]}
```

**`domains` is absent rather than empty and `attributes` is present rather than
absent.** An organization with no domains has no `domains` key on any shape; one
with no attributes carries `"attributes":{}` on the two shapes that have the
key. Two neighbouring keys, opposite rules - the same pair of rules a client
scope's `protocolMappers` and `attributes` already follow.

`attributes` values are **arrays of strings**, not strings: `{"k":["v"]}`. It is
a `MultivaluedHashMap`, so it is a group's `attributes` type and not a client's,
and `model.StringMap` does not apply to it.

### The alias is the name, and the name is validated as an alias

`alias` defaults to the `name` verbatim. **Not lowercased** - a name `UPPER`
produced alias `UPPER`, where a username would have been folded. A name that
cannot be an alias is a 400 naming the offending character:

```
{"name":"Gloak Probe Space"} 400 {"errorMessage":"Name cannot be used as alias: Empty Space not allowed."}
{"name":"with/slash"}        400 {"errorMessage":"Name cannot be used as alias: Character '/' not allowed."}
{"name":"with.dot"}          201
```

### Create

| body | answer |
|---|---|
| `{}` | 400 `{"errorMessage":"Name can not be null"}` |
| `{"name":""}` | 400 `{"errorMessage":"Name can not be null"}` - an empty name **is** a null name here |
| `{"name":"x"}`, no domains | 201 |
| duplicate name | 409 `{"errorMessage":"A organization with the same name already exists."}` |
| duplicate alias | 409 `{"errorMessage":"A organization with the same alias already exists"}` |
| duplicate domain | 400 `{"errorMessage":"Domain d is already linked to organization o in realm r"}` |
| `{` | 400 `{"error":"invalid_request","error_description":"Cannot parse the JSON"}` |
| no body at all | 400 `{"errorMessage":"Organization cannot be null."}` |

Three things in that table are worth naming separately.

**The two 409s differ only in a full stop.** `…name already exists.` has one and
`…alias already exists` has none, on one verb of one resource two lines apart in
Keycloak's own source. "A organization" is Keycloak's grammar, twice, and is
copied.

**A duplicate domain is a 400 and a duplicate name is a 409**, so the conflict
status is per field rather than per resource.

**No body is a 400 here**, where `POST /users` is a 500 for the same request.

**The body's `id` does not win.** A create carrying
`{"id":"11111111-2222-3333-4444-555555555555", …}` answered 201 with a
`Location` ending in a *different*, server-minted UUID, and
`GET /organizations/11111111-…` is 404. This is the opposite of `POST /clients`
and `POST /client-scopes`.

201 carries `Location`, `X-Frame-Options`, `content-length: 0` and **no
`Content-Type` and no `Cache-Control`**. The `Location` ends in the new id, so
`Case.VolatileTailHeaders` is right for it.

### Update

`PUT` **replaces**, and the alias is immutable.

- `PUT {"name":"gloak-probe-full"}` on an organization whose alias is
  `gloak-probe-full-alias` is **400 `{"errorMessage":"Cannot change the
  alias"}`**. An absent `alias` does not mean "leave it alone"; it means "derive
  it from the name", and the derived value then collides with the stored one.
  So a read-modify-write that drops `alias` fails on every organization whose
  alias differs from its name.
- Sending the stored alias with a new `name` succeeds, 204, and the
  organization **is renamed**.
- Sending a different alias is the same 400.
- Absent fields are cleared: a `PUT` that named only `name` and `alias` left
  `description` and `redirectUrl` gone, `enabled` back to `true` and the
  `domains` array empty.
- **`attributes` is the exception.** Absent from the body, it survived; sent as
  `{}`, it was cleared. So one field on this body merges where the rest replace.
- Unknown organization: 404 `{"errorMessage":"Organization not found."}`.
- No body: **500** `{"error":"unknown_error","error_description":"For more on
  this error consult the server log."}`, the same answer
  `PUT /admin/realms/{realm}` gives.

204 carries `X-Frame-Options` (the request declared `application/json`) and
**no `Cache-Control`**.

### Delete

204, no body, **no `X-Frame-Options`** (no request `Content-Type`) and **no
`Cache-Control`**. Deleting twice is 404
`{"errorMessage":"Organization not found."}`, so it is not idempotent.

### The listing and the count

- Sorted by name in byte order: `UPPER, aaa-org, mmm-org, with.dot, zzz-org`
  came back from creations in a different order, with the capital first.
- **Either bound alone pages.** `?max=1` returned one row and `?first=1&max=1`
  returned the second. That is the group listing's rule, not the role listings'.
- `search` is a case-insensitive **substring** over the **name and the domain**,
  and **not** the alias: `full.example.com` matched an organization whose name
  does not contain it; `full-alias` matched nothing although it is a substring
  of that organization's alias.
- `exact=true` narrows `search` to an exact name match.
- `q=k:v` filters on attributes.
- `GET /organizations/count` is a **bare JSON number**, like `/users/count` and
  unlike `/groups/count`'s `{"count":2}`. It honours `search`.
- Both carry `Cache-Control: no-cache` and
  `Content-Type: application/json;charset=UTF-8`.

### Authorization

One role per call, minted fresh, eleven roles swept against seven requests:

| role | listing | count | single read | create | update | missing org |
|---|---|---|---|---|---|---|
| none | 403 | 403 | 403 | 403 | 403 | 403 |
| `view-organizations` | 200 | 200 | 200 | 403 | 403 | 404 |
| `manage-organizations` | 200 | 200 | 200 | 201 | 204 | 404 |
| `query-organizations` | 200 | 200 | **403** | 403 | 403 | 404 |
| `manage-realm` | 200 | 200 | 200 | 201 | 204 | 404 |
| `view-realm` | **403** | 403 | 403 | 403 | 403 | 403 |
| `view-users`, `manage-users`, `view-clients`, `manage-clients`, `query-groups` | 403 | 403 | 403 | 403 | 403 | 403 |

- Reads: `view-organizations`, `manage-organizations`, `manage-realm`.
- Listing and count additionally: `query-organizations`, which opens nothing
  else - exactly `query-groups`' shape on the group listing.
- Writes: `manage-organizations`, `manage-realm`.
- **`manage-realm` opens everything and `view-realm` opens nothing.** The realm
  role pair is not a view/manage pair here; only the manage half reaches.
- **The caller is judged before the organization is resolved**: a caller with no
  role gets 403 for an organization that does not exist, where the `Groups` tag
  answers 404 to every caller. This family follows the *users* shape, not the
  groups one, and the description's tag does not predict it.

`master-realm` carries the three roles - `view-organizations`,
`manage-organizations`, `query-organizations` - and they are already three of
the 21 roles Gloak bootstraps. Nothing new is needed there; confirm and move on.

## 5. Implementation

### Schema, migration `0018_organization.sql`

Identical in both drivers, as every migration in this repository is.

```sql
CREATE TABLE organization (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    alias        TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,   -- BOOLEAN on postgres
    description  TEXT NOT NULL DEFAULT '',
    redirect_url TEXT NOT NULL DEFAULT '',
    UNIQUE (realm_id, name),
    UNIQUE (realm_id, alias)
);

CREATE TABLE organization_domain (
    organization_id TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    verified        INTEGER NOT NULL DEFAULT 0,
    ordinal         INTEGER NOT NULL
);

CREATE TABLE organization_attribute (
    organization_id TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    value           TEXT NOT NULL,
    ordinal         INTEGER NOT NULL
);
```

Two unique constraints rather than one, because the two collisions answer
differently - 409 with a full stop and 409 without one - so the handler has to
know which fired and cannot infer it.

A domain is a row rather than a JSON blob because the duplicate-domain 400 is
realm-wide: it names the *other* organization the domain is linked to, so the
check is a query across the realm and not a field comparison.

`ordinal` on both child tables for the same reason `group_attribute` has one:
the order came off the wire and going through a Go map would sort it.

### `internal/model`

```go
type Organization struct {
    ID, RealmID, Name, Alias, Description, RedirectURL string
    Enabled     bool
    Domains     []OrganizationDomain
    Attributes  []OrganizationAttribute   // name -> values, in wire order
}
type OrganizationDomain struct { Name string; Verified bool }
```

### `internal/store`

```go
type OrganizationRepo interface {
    Create(ctx, *model.Organization) error
    Update(ctx, *model.Organization) error
    Delete(ctx, realmID, id string) error
    Get(ctx, realmID, id string) (*model.Organization, error)
    List(ctx, realmID string) ([]*model.Organization, error)
    ByDomain(ctx, realmID, domain string) (*model.Organization, error)
}
```

`List` returns everything name-sorted and the handler filters and pages, which
is what `groups.go` does and what keeps `search`, `exact` and `q` in one place
that a test can read. `ByDomain` exists because the duplicate-domain 400 names
the colliding organization.

Both drivers implement it, and `internal/store/storetest/conformance.go` gains
the cases - the brief is explicit that the Postgres suite passed last week while
exercising none of a cut's new code because nothing had been added there.

### `internal/admin/organizations.go`

- `organizationRepresentation`, with `Attributes` and `Domains` as pointers so
  "absent" and "present and empty" are different things, the technique
  `groupRepresentation` already uses for exactly this.
- `guardOrganizations(roles, next)`: `guardAnyRejecting` with the
  `organizationsEnabled` check wrapped *inside* the admitted path, which is the
  measured order. It is **not** `guardRealmFeature`, and the doc comment says
  why.
- `writeOrganizationsNotEnabled` beside `writeFeatureNotEnabled`, so the two
  refusals sit together and the difference between them is visible.
- Alias validation as a character check with the two measured messages.

### `internal/bootstrap`

Nothing. The three roles already exist; a realm's `organizationsEnabled` already
round-trips through the settings blob, and this cut re-checks that rather than
assuming it.

## 6. Conformance cases

Appended at the very end of `adminCases`, and nowhere else. Fixtures appended at
the very end of the map and after the last helper.

One fixture creates a realm with `{"organizationsEnabled":true}` in the creation
body - measured to work, so it is one step and not a create plus a `PUT`. A
second creates the same realm without the flag, for the refusal. A realm of its
own rather than master, for `defaultGroupsFixture`'s reason: master's goldens are
`PristineRealm` and an organization in master would show up in them.

| case | what it pins |
|---|---|
| `admin/organizations/not-enabled` | the 404 and its exact sixty bytes |
| `admin/organizations/list-empty` | `[]`, `Cache-Control`, the charset |
| `admin/organizations/create` | 201, `Location`, no `Content-Type` |
| `admin/organizations/list` | the brief shape, `domains` present, no `attributes` |
| `admin/organizations/list-full` | `briefRepresentation=false` adds `attributes` |
| `admin/organizations/read` | the single read's shape |
| `admin/organizations/read-brief-ignored` | `?briefRepresentation=true` is the same body |
| `admin/organizations/count` | the bare number |
| `admin/organizations/create-no-name` | `Name can not be null` |
| `admin/organizations/create-duplicate-name` | the 409 **with** its full stop |
| `admin/organizations/create-duplicate-alias` | the 409 **without** one |
| `admin/organizations/create-bad-alias` | `Character '/' not allowed.` |
| `admin/organizations/update` | 204, `X-Frame-Options`, no `Cache-Control` |
| `admin/organizations/update-alias-refused` | `Cannot change the alias` |
| `admin/organizations/update-replaces` | the read after a `PUT`, showing the cleared fields and the surviving `attributes` |
| `admin/organizations/delete` | 204 with **no** `X-Frame-Options` |
| `admin/organizations/read-missing` | `Organization not found.` |

No case's body is a function of the whole realm, so none is `PristineRealm`.

No mask is added that changes nothing. The `Location` on the create is
`VolatileTailHeaders`, which the four routes minting a UUID already take; the
ids inside bodies are captured and rewritten, so they need no `Volatile`.

## 7. Verification

- `CGO_ENABLED=0 go test ./...`, with no Docker and no network.
- `make lint` - `gofmt` and both vets.
- `go test -tags docker ./internal/store/postgres/` by hand, after the
  `storetest` cases exist.
- `make record` against the reference container, then `make test`.
- A different mutation per claim, each confirming the **named** test fails, each
  reverted. A survivor is a finding about the test.
