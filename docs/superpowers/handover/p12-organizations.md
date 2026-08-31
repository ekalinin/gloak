# P12's first cut: organizations

Branch `feat/p12-organizations`. Measured against a live Keycloak 26.7.1
(`quay.io/keycloak/keycloak:26.7.1 start-dev`, container `kc-org`, port 8122,
removed at the end) on 2026-08-31. The plan is
`docs/superpowers/plans/2026-08-31-p12-organizations.md`.

## 1. Measurements

### The question the cut opened with, and its answer

The brief proposed that `ORGANIZATION` might be a preview feature, in which case
a default `start-dev` would answer the whole tag the way `client-types` answers
501. **Both halves are wrong.**

```json
GET /admin/serverinfo
{"name":"ORGANIZATION","label":"Organization support within realms",
 "type":"DEFAULT","dependencies":[],"enabled":true}
```

`type` is `DEFAULT` and `enabled` is `true`. `ORGANIZATION` is absent from
`profileInfo.disabledFeatures`, where `CLIENT_TYPES` and
`CLIENT_SECRET_ROTATION` both appear. `--features=organization` was never used;
everything below is a default container.

What refuses the tag is a **per-realm flag**, `organizationsEnabled`, one of the
realm representation's 106 keys, `false` on master and on every realm
`POST /admin/realms` creates. With it off, every path under
`/admin/realms/{realm}/organizations` answers

```
404  Content-Type: application/json
{"errorMessage":"Organizations not enabled for this realm."}
```

sixty bytes, measured identical on six paths across five of the tag's six
sub-families. **One `PUT` opens the whole tag**, and `POST /admin/realms`
carrying the flag creates a realm with it already on. So this cut is thirty-six
real operations, not one refusal repeated.

### Where the gate sits

| caller, flag off | answer |
|---|---|
| no `Authorization` | 401 `{"error":"HTTP 401 Unauthorized"}` |
| unknown realm | 404 `{"error":"Realm not found."}` |
| **holding no admin role** | **403** `{"error":"HTTP 403 Forbidden"}` |
| `view-organizations` | 404 `Organizations not enabled for this realm.` |
| full administrator | 404 `Organizations not enabled for this realm.` |
| `PATCH`, no admin role | 405 `{"error":"HTTP 405 Method Not Allowed"}` |

Six steps: method, realm, authentication, **authorization**, feature,
organization. `client-types` puts its feature check *before* authorization and
therefore has no role list; this one puts it *after* and therefore has one.
Reusing `guardRealmFeature` answers 404 where Keycloak answers 403.

### The allocation exercise

**Forty-seven operations have `/organizations` in their path, not thirty-six.**

| tag | count |
|---|---|
| `Organizations` | 36 |
| `Role Mapper` | 6, all under `.../organizations/{org-id}/groups/{group-id}/role-mappings[/realm...]` |
| `Client Role Mappings` | 5, all under `.../role-mappings/clients/{client-id}[...]` |

**The brief's open question: they are a *different* eleven at overlapping
paths.** The `Organizations` tag's own `/groups` family is also exactly eleven
and shares the `/{org-id}/groups/{group-id}` prefix with them while sharing not
one operation. Two elevens, one prefix, disjoint sets.

**Building organizations does unlock them.** All eleven are live: each answers
`404 {"errorMessage":"Group does not exist"}` for a group not in the
organization, which is a handler refusing a lookup rather than a router miss.
When the org group tree lands they move `admin/role-mapper` 6 -> 12 of 18 and
`admin/client-role-mappings` 5 -> 10 of 15, closing both tags outright.

### The description checked against the server

**Workflows is not part of the organizations feature.** `GET /workflows`
answers 200 on a realm with `organizationsEnabled` false.

**And the Workflows tag does not serve JSON.**

```
GET /admin/realms/master/workflows
200
transfer-encoding: chunked
Content-Type: application/yaml;charset=UTF-8

--- []
```

`application/yaml`, a YAML body, and **no `Content-Length` at all** - the only
chunked response this project has measured. Its errors are JSON and there are
two shapes inside the one tag: `POST /workflows` with `{}` answers
`{"errorMessage":"Workflow name cannot be null or empty."}` while
`GET /workflows/{id}` with a bad id answers
`{"error":"Not a valid workflow resource: nosuchid"}`. Serving Workflows means a
YAML writer in `internal/httpx`, which is a boundary decision rather than a
handler. Deferred, and filed as a finding rather than planned.

### The organization as a resource

Two shapes, and the parameter that picks between them reaches one route of two.

```
GET /organizations                            id name alias enabled [description] [redirectUrl]            [domains]
GET /organizations?briefRepresentation=false  id name alias enabled [description] [redirectUrl] attributes [domains]
GET /organizations/{id}                       id name alias enabled [description] [redirectUrl] attributes [domains]
```

`briefRepresentation` defaults to **true** on the listing. **The single read
ignores it** - absent and `true` gave byte-identical bodies, `attributes`
included.

**Four presence rules on one body, and three of them disagree with a
neighbour:**

- `domains` is **absent** when empty, on every shape.
- `attributes` is **`{}`** where the shape has it.
- `description` tells absent from empty: `"description":""` reads back.
- `redirectUrl` does **not**: the same create sending `"redirectUrl":""` reads
  back with no such key. Two neighbouring fields, one empty value, opposite
  answers.

**`attributes` values are arrays** (`{"k":["v"]}`) - a `MultivaluedHashMap`, so
a group's type and not a client's, and `model.StringMap` does not apply.

**Its key order is `javamap.KeyOrder`'s and is placed exactly.** An organization
created with `{"k":["v1","v2"],"z":["w"]}` came back `{"z":["w"],"k":["v1","v2"]}`
and `javamap.KeyOrder(["k","z"])` returns `[z k]`. **A seventh confirmed vector
for that function**, and the goldens assert real bytes with no `UnorderedKeys`.

### The alias

`alias` defaults to the `name` **verbatim** - not lowercased, where a username
would be: `UPPER` produced alias `UPPER`.

**The character set constrains the alias, and the name only when it becomes
one.** `{"name":"bad/name","alias":"goodalias"}` is a **201** and produces an
organization named `bad/name`.

Swept character by character. Refused: ``! # $ & ( ) * + , / : ; = ? @ [ ] \``
and whitespace. Accepted: ``_ - . ~ ' % " < > | ^ { } ` `` and every letter.
That is **nearly** RFC 3986's gen-delims plus sub-delims and is not that rule:
`'` is a sub-delim and is accepted, `\` is neither and is refused. It is a list,
not a predicate.

**Whitespace is checked over the whole string before any character is.**
`a/b c` answers about the space although the slash comes first. Two passes.

**One validation, two error families, decided by which field carried the value:**

```
{"name":"a/b"}                     400 {"errorMessage":"Name cannot be used as alias: Character '/' not allowed."}
{"name":"ok","alias":"a/b"}        400 {"error":"Character '/' not allowed."}
```

`errorMessage` with a prefix from the name, `error` with no prefix from the
alias.

### Create

| body | answer |
|---|---|
| `{}`, `{"name":""}`, `{"name":null}` | 400 `{"errorMessage":"Name can not be null"}` |
| duplicate name | 409 `{"errorMessage":"A organization with the same name already exists."}` |
| duplicate alias | 409 `{"errorMessage":"A organization with the same alias already exists"}` |
| duplicate domain | 400 `{"errorMessage":"Domain d is already linked to organization o in realm r"}` |
| `{` | 400 `{"error":"invalid_request","error_description":"Cannot parse the JSON"}` |
| `[`, `[]` | 400 `{"error":"unknown_error",...}` |
| no body | 400 `{"errorMessage":"Organization cannot be null."}` |
| an unknown field | 400 `Invalid json representation for OrganizationRepresentation. Unrecognized field "bogusField" at line 1 column 31.` |
| no JSON `Content-Type` | 415 |

- **The two 409s differ only in a full stop**, on one verb of one resource.
  "A organization" is Keycloak's grammar in both and is copied.
- **A duplicate domain is a 400 where a duplicate name is a 409**: the conflict
  status is per field.
- **No body is a 400 here** where `POST /users` is a 500.
- **`POST` and `PUT` are strict decoders** - the third and fourth measured in
  this API after the two required-action PUTs.
- **The body's `id` does not win.** A create carrying one answered 201 with a
  `Location` ending in a different UUID; the asked-for id resolves to nothing.

201 carries `Location`, `X-Frame-Options`, `content-length: 0` and **no
`Content-Type` and no `Cache-Control`**.

### Update

- `PUT` **replaces**; absent fields are cleared. **`attributes` is the
  exception**: absent, it survives; sent as `{}`, it is cleared.
- **The alias is immutable, and an absent alias means "derive it from the name"
  rather than "leave it alone"**, so a read-modify-write that drops the key is
  400 `{"errorMessage":"Cannot change the alias"}` on every organization whose
  alias is not its name.
- **A body with no name, or an empty one, is a 409** -
  `A organization with the same name already exists.` - about a name the request
  does not have. The create answers the same missing name with a 400.
- Order, measured: **the organization is resolved before the body is read**
  (an unknown id is 404 for a malformed body and for an unknown field alike),
  then the name conflict, then the alias.
- No body at all: **500** `unknown_error`, as `PUT /admin/realms/{realm}`.

204 carries `X-Frame-Options` (the request declared JSON) and **no
`Cache-Control`**.

### Delete

204, **no `X-Frame-Options`** (no request `Content-Type`) and no
`Cache-Control`. **Not idempotent**: the second delete is 404.

### Listing and count

- Sorted by name in **byte** order: `UPPER, aaa-org, mmm-org, with.dot, zzz-org`.
- **Either bound alone pages** - the group listing's rule, not the role
  listings'.
- `search` is a case-insensitive **substring over the name and the domains**,
  and **not the alias**: `full.example.com` matched, `full-alias` did not.
- `exact=true` narrows to an equal name; `q=k:v` filters on attributes; a `q`
  with no colon is ignored rather than refused.
- `GET /organizations/count` is a **bare JSON number** and honours `search`.
  `/users/count` is a bare number, `/groups/count` is `{"count":2}`; this one
  sides with the users one. So is `.../members/count`.

### Authorization

One role per call, tokens minted fresh, eleven single-role callers against seven
requests.

| role | listing | count | read | create | update | missing org |
|---|---|---|---|---|---|---|
| none | 403 | 403 | 403 | 403 | 403 | 403 |
| `view-organizations` | 200 | 200 | 200 | 403 | 403 | 404 |
| `manage-organizations` | 200 | 200 | 200 | 201 | 204 | 404 |
| `query-organizations` | 200 | 200 | **403** | 403 | 403 | 404 |
| `manage-realm` | 200 | 200 | 200 | 201 | 204 | 404 |
| `view-realm` | **403** | 403 | 403 | 403 | 403 | 403 |
| `view-users`, `manage-users`, `view-clients`, `manage-clients`, `query-groups` | 403 | 403 | 403 | 403 | 403 | 403 |

- **`manage-realm` opens everything and `view-realm` opens nothing.** The realm
  pair is not a view/manage pair here.
- `query-organizations` opens the listing and the count and nothing else -
  `query-groups`' shape.
- **The caller is judged before the organization is resolved**, which is the
  users family's order and **not** the groups family's.

`master-realm` carries the three roles already and Gloak bootstraps all three;
`view-organizations` is composite over `query-organizations`. Nothing needed in
`internal/bootstrap`.

### Measured and not built

- An organization owns a **hidden root group**: a group created through
  `POST /organizations/{id}/groups` came back with a `parentId` naming an id the
  organization's own representation never mentions, and its `path` is
  `/<child>` - the root is not in it. A second group tree beside the realm's,
  and a schema question rather than a handler.
- `POST .../members/invite-user` is **500 `Failed to send invite email`** on a
  container with no SMTP - CIBA's 503 shape.
- The identity-provider family has three different not-found sentences across
  four operations: `Identity provider not found with the given alias` (400 on
  the `POST`, 404 on the `DELETE`) and `Identity provider not associated with
  the organization` (404 on both `GET`s).
- `GET /organizations/{id}/members/{member-id}` and its two sub-reads answer the
  **generic router 404** `{"error":"HTTP 404 Not Found"}` for an unknown member,
  not an `errorMessage`.
- `PATCH`, `PUT` and `DELETE` on `/organizations` answer a **real 405** with no
  `Allow` header, and do so even on a realm where organizations are disabled -
  so the 405 precedes the gate. `HEAD` is 200 and `OPTIONS` is 200 with no
  `Allow`.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **Organizations are refused per realm, not per feature, and the check is on
  the far side of the caller from `client-types`'s.** `ORGANIZATION` is
  `"type":"DEFAULT","enabled":true` on a default 26.7.1 and is not in
  `disabledFeatures`; what is off is the realm's own `organizationsEnabled`, one
  of its 106 representation keys, and one `PUT` on the realm turns the whole tag
  on. Every path under `/organizations` then answers
  `404 {"errorMessage":"Organizations not enabled for this realm."}` while it is
  off - **and answers 403 first to a caller holding no admin role**, where
  `client-types` hands its 501 to everybody because its check runs *before*
  authorization. Two feature gates on one API, on opposite sides of the role
  check. Reusing one guard for the other is the saving that gets one of them
  wrong.

- **The alias is what the character rules constrain, and the name only when it
  becomes one.** `{"name":"bad/name","alias":"goodalias"}` is a 201 and produces
  an organization named `bad/name`; `{"name":"bad/name"}` is a 400. The refused
  set is ``! # $ & ( ) * + , / : ; = ? @ [ ] \`` and whitespace, which is nearly
  RFC 3986's gen-delims plus sub-delims and is not that rule - `'` is a sub-delim
  and is accepted and `\` is neither and is refused, so it is a list rather than
  a predicate. **Whitespace is checked over the whole string before any
  character is**: `a/b c` answers about the space. And the same complaint reaches
  the wire in **two error families** - `{"errorMessage":"Name cannot be used as
  alias: Character '/' not allowed."}` when the value arrived as the name and
  `{"error":"Character '/' not allowed."}` when it arrived as the alias. One
  check, two shapes, decided by which field carried it.

- **Two 409s on one verb that differ only in a full stop.** A duplicate name is
  `A organization with the same name already exists.` and a duplicate alias is
  `A organization with the same alias already exists`. "A organization" is
  Keycloak's grammar in both. That is the **fourth** pair in this document
  separated by a full stop alone, after `Realm not found.`, the group family's
  and the required actions' - and the first split by which *field* collided
  rather than by which route or verb went looking. A duplicate **domain** is a
  **400** rather than a 409 and names the other organization and the realm, so
  the conflict status is per field too.

- **A `PUT` with no name is a 409 about a name it does not have.** `{"alias":"x"}`
  on the organization aliased `x` answers `A organization with the same name
  already exists.`, and so does `{"name":""}`, where the create answers the same
  missing name with a 400 `Name can not be null`. One resource, one missing
  field, two verbs, two answers. **The obvious explanation is wrong and was
  believed for an afternoon**: it is not "the missing name falls back to the
  alias and collides with this row". That reading came from an organization
  created `{"name":"target","alias":"target"}`, where both readings give a 409.
  On one whose name and alias differ, a `PUT` naming the **alias as the name** is
  a 204 and a `PUT` naming nothing is still the 409. The conformance case is what
  caught it; the unit test written on the first organization passed both
  implementations.

- **`PUT` replaces every field but one, and the alias is immutable in a way that
  breaks read-modify-write.** An absent `alias` does not mean "leave it alone",
  it means "derive it from the name" - so a client that reads an organization,
  changes its name and puts it back without the alias gets 400 `Cannot change
  the alias` on every organization whose alias is not its name. `attributes` is
  the one field that merges: absent from the body it survives, sent as `{}` it
  is cleared. Everything else absent is cleared.

- **The body's `id` does **not** win on `POST /organizations`**, where it does on
  `POST /clients` and `POST /client-scopes`. A create carrying an id answered 201
  with a `Location` ending in a different, server-minted UUID and the asked-for
  id resolves to nothing. The rule those two endpoints established does not
  generalise, and the fixture technique that rests on it - naming an id so a case
  knows it before asking - is unavailable here.

- **`description` tells absent from empty and `redirectUrl` does not.** A create
  sending `{"description":"","redirectUrl":""}` reads back carrying
  `"description":""` and **no `redirectUrl` key at all**. Two neighbouring
  fields, one empty value, opposite answers, which is why `organization`'s
  `description` column is nullable and its `redirect_url` is not. Their two
  neighbours disagree the other way: `domains` is absent when empty and
  `attributes` is `{}`.

- **An organization's `attributes` key order is a Java `HashMap`'s and
  `javamap.KeyOrder` places it exactly.** `{"k":["v1","v2"],"z":["w"]}` came back
  `{"z":["w"],"k":["v1","v2"]}` - neither sorted nor insertion order - and
  `KeyOrder(["k","z"])` returns `[z k]`. A seventh confirmed vector for that
  function, the first on a **multivalued** map, and the goldens assert the real
  bytes with no `UnorderedKeys` retreat. It is the same shape as F95's client
  attributes and shows that half of that fix works; what still blocks F95 is the
  Go map on the model, not the ordering.

- **`Group does not exist` is a fourth spelling for a missing group and
  `Organization not found.` is a new one.** The eleven role-mapping operations
  and the eleven group operations under `/organizations/{org-id}/groups` all
  answer `{"errorMessage":"Group does not exist"}`, where `/groups/{id}` answers
  `Could not find group by id`, `/users/{id}/groups/{id}` and the default-groups
  writes answer `Group not found`, and `group-by-path` answers `Group path does
  not exist`. So the count is **twenty-one spellings, not nineteen**, and one
  missing group has **four** answers.

- **The Workflows tag is `application/yaml`.** `GET
  /admin/realms/{realm}/workflows` answers `200`,
  `Content-Type: application/yaml;charset=UTF-8`, `transfer-encoding: chunked`
  and a YAML body `--- []`. It is the only chunked response and the only non-JSON
  success this project has measured on the Admin API, and it is **not** gated by
  `organizationsEnabled` - it answers 200 on a realm with the flag off, so it is
  not part of the organizations feature at all despite sharing a roadmap row.
  Its *errors* are JSON and there are two shapes inside the tag:
  `{"errorMessage":"Workflow name cannot be null or empty."}` from `POST
  /workflows` and `{"error":"Not a valid workflow resource: nosuchid"}` from
  `GET /workflows/{id}`.

- **An organization owns a hidden root group.** A group created through
  `POST /organizations/{id}/groups` comes back with a `parentId` naming an id
  that appears nowhere in the organization's representation, and its `path` is
  `/<its own name>` - the root is not in the path. So the organization group
  tree is a second tree beside the realm's, with a root the API never shows.

## 3. Follow-up dispositions

**F95 - a client's `attributes` is serialised from a Go map. Not closed, and it
does not fit this cut.** The move itself is one field, but closing it means
taking `UnorderedKeys` off five **existing** `admin/clients/*` cases and
re-recording their goldens - and this stream's file rules are to append at the
end of `catalog_admin.go` and nowhere else, so editing five existing cases is
outside what it may touch. It also lands in `internal/admin/clients.go`, which
another stream may hold this session.

What the cut *does* contribute to it is evidence rather than code: an
organization's `attributes` is the same problem one level harder - a
**multivalued** Java map - and it is served with its key order **placed** by
`javamap.KeyOrder` and asserted as real bytes in three goldens, with no mask.
`organizationAttributes` in `internal/admin/organizations.go` is the pattern,
built on `clientMappings`'. So F95's remaining risk is not "will the ordering
reproduce" - that is now confirmed on a seventh key set - it is only the model
field's type. **F95 should be re-read as smaller than it is written.**

**F94 - a `Reason` naming a plan phase expires when the phase closes.**
Untouched. This cut files no `Recorded` case and no `Reason` at all: all
twenty-two organization cases are `Implemented`.

**New, not filed as follow-ups because nobody has decided them:**

- **Workflows needs a YAML writer in `internal/httpx`.** Nine operations behind
  one boundary decision. It is the cheapest remaining chunk of P12 by operation
  count and the most expensive by architecture.
- **`ORDER BY name` and Postgres collation.** The organization listing sorts by
  name in **byte** order, which is what the reference container answers and what
  the driver suite asserts. The Postgres suite passes today because the test
  container's database is C-collated; a deployment whose Postgres uses
  `en_US.UTF-8` would sort `UPPER` after `aaa-org` and diverge from SQLite. Six
  existing `ORDER BY name` sites have the same exposure, which is why this cut
  followed the pattern rather than changing it here.

## 4. Parity before and after

`make conformance`: **285 -> 291 of 523 enumerated behaviours (+6)**, four
chapters still unenumerated. `cmd/parity` against the merge base agrees.

| chapter | before | after | denominator | source |
|---|---|---|---|---|
| `admin/organizations` | 0 | **6** | 36 | openapi 26.7.1 |
| `admin/workflows` | 0 | 0 | 9 | openapi 26.7.1 |
| every other chapter | unchanged | unchanged | | |

The six are `GET`/`POST /organizations`, `GET /organizations/count`, and
`GET`/`PUT`/`DELETE /organizations/{org-id}`. Twenty-two conformance cases carry
them: sixteen of the twenty-two assert behaviour the six operations have beyond
their own existence - the refusal, the two shapes, the ignored parameter, the
two 409s, the two error families, the strict decode, the replace and the
non-idempotent delete.

**What P12 has left, with the count corrected.** The roadmap's P12 row reads
"Organizations 36, Workflows 9 / 45 ops". **The true size is 56**: eleven more
operations live under `/organizations` and are counted in the `Role Mapper` and
`Client Role Mappings` tags. Remaining:

| family | ops | blocked on |
|---|---|---|
| `/organizations/{id}/groups` | 11 | the hidden root group - a second group tree |
| role-mappings under `/organizations` | 11 | the above; closes both mapping tags |
| `/organizations/{id}/members` | 9 | a member model, and the SMTP 500 |
| `/organizations/{id}/identity-providers` | 5 | P9 |
| `/organizations/{id}/invitations` | 4 | the member routes create them |
| Workflows | 9 | a YAML writer in `internal/httpx` |

## 5. Lines in AGENTS.md and the observed document these measurements contradict

Six, of which two are fixed on this branch.

1. **"Nineteen spellings of not-found in the admin API now, including four for
   one resource, three for a missing group."** There are **twenty-one**, and a
   missing group has **four** answers. `Group does not exist` comes from all
   twenty-two operations under `/organizations/{org-id}/groups`, and
   `Organization not found.` is new. *Not fixed*: the group routes are not in
   this cut, but `Organization not found.` is served and is in a golden.

2. **"The body's `id` wins on create, on `POST /client-scopes` and on
   `POST /clients` alike."** The heading generalises past its own two endpoints.
   `POST /organizations` inverts it: the id is read and discarded.
   `TestOrganizationCreateIgnoresTheBodyID` pins the inversion. *Served as
   measured.*

3. **"`make record` is silent on a clean checkout - 433 rewritten with identical
   bytes, none moved."** **Four moved on this branch's run** -
   `oidc/authorization/max-age-invalid`, `oidc/authorization/prompt-create`,
   `oidc/device/status-page` and `oidc/device/verification-page` - and the only
   difference is Keycloak's per-container theme resource hash, `ynxld` to
   `27g26`. All four are `Status: Recorded`, and the fix that stopped the theme
   pages churning covers `Pending` alone (`GoldenIsAsserted`). The claim was true
   when written and stopped being true when these four arrived. *Not fixed and
   reverted*: this stream does not own `testdata/golden/oidc/`. It is a real
   trap - the next cut to run `make record` will see four unrelated files move
   and has no way to tell that from a regression.

4. **`internal/admin/strictjson.go`: "This is the first strict decoder measured
   in this API. Every other endpoint recorded here ignores a field it does not
   know."** There are **four**. `POST` and `PUT /organizations` are strict and
   name `OrganizationRepresentation`. **Fixed on this branch**, along with a
   second half the same comment got wrong by generalising: *"The decode runs
   before the path's alias is resolved"* is true of the required-action PUT and
   **false** of the organization PUT, where an unknown id answers
   `Organization not found.` for an unknown field and for unparseable JSON
   alike. Two families, opposite orders.

5. **"Either bound alone pages, which is neither the role listings' rule nor the
   user listing's - three listings, three paging rules."** Four listings now, and
   organizations **agrees with groups**. The count of listings is wrong; the
   count of rules still stands at three. *Served as measured*, through the same
   `pageGroups` the group listing uses.

6. **"`Cache-Control` on a 204 does not follow the method. Four of the five
   measured deletes carry `no-cache`."** Organizations' `DELETE` and `PUT` carry
   **none**, so it is now four of six. "Pinned per endpoint" is the part that
   survives, for the third time. *Served as measured*, asserted by
   `AssertAbsentHeaders` on two goldens.

Also worth recording, though it contradicts nothing written down: **the
description's tag failed to predict the guard again, and in a new direction.**
The `Organizations` tag resolves its resource **after** the caller, which is the
users family's order; the `Groups` tag resolves before. Both tags name their own
resource in the path and in the tag, so nothing about the description separates
them.

## 6. What was run

- `CGO_ENABLED=0 go test ./...` - green, no Docker, no network.
- `make lint` - `gofmt` and both vets, clean.
- `make record` against the reference container, then `make test`: twenty-two
  goldens recorded, one case failed on the first replay and found finding 4 of
  section 2 (the `PUT` no-name rule), fixed, green.
- `go test -tags docker ./internal/store/postgres/` - green, and it exercises
  the new code: five organization subtests were added to
  `internal/store/storetest`.
- **Sixteen mutations, one per claim, each confirming the named test fails, each
  reverted. No survivors.** The gate's position, the role sets, the ignored
  `briefRepresentation` (against the unit test and against the golden), the
  `javamap` order (both), the missing full stop, the `domains` rule, the bare
  number, the `PUT` 409, the alias not being searched, the empty description,
  the whitespace-first scan, the discarded body id, the store's untouched alias
  column, the `Location`'s last segment, and the paging.

**The one mutation that mattered was the one that ran before the sweep.** The
`PUT`-with-no-name rule was implemented from a measurement taken on an
organization whose name and alias were the same string, and both the unit test
and the implementation agreed with each other and with the wrong explanation.
`admin/organizations/update-without-name`, recorded against a fixture whose
organization has a name and an alias that differ, is what disagreed. The unit
test has since been rewritten onto an organization where they differ, and the
old version passes either implementation.

## 7. Files this cut touched

Owned and changed: `internal/model/model.go`, `internal/store/store.go`, both
drivers and their `0018_organization.sql`, `internal/store/storetest/conformance.go`,
`internal/admin/organizations.go` (new), `internal/admin/organizations_test.go`
(new), `internal/admin/router.go`, `internal/admin/strictjson.go`,
`internal/conformance/catalog_admin.go` (appended at the end only), twenty-two
new goldens.

**`internal/conformance/fixture.go` was touched, and this is the flag the brief
asked for.** Eight entries were appended at the very end of the `Fixtures` map
and two helpers - `organizationRealmFixture` and `organizationFixture` - after
the last existing helper. Nothing existing was edited or moved. Another stream
holds this file this session.

`internal/bootstrap` was read and needed nothing: the three organization roles
are already in the 21 `master-realm` roles and `view-organizations` is already
composite over `query-organizations`.
