# `partial-export` and `partialImport`

Date: 2026-09-06
Branch: `feat/partial-export-import`
Reference container: Keycloak 26.7.1 on `:8176`, measured 2026-09-06.

Two operations, both `POST`, both tagged `Realms Admin` by the vendored
description:

```
POST /admin/realms/{realm}/partial-export
POST /admin/realms/{realm}/partialImport
```

**The brief's hint was checked against the description before anything was
planned**, because three of its predecessors had been wrong. This one is right:
both paths exist, both carry the single verb, both carry the tag, and
`Realms Admin` holds **45** operations - counted out of the description, which
is the number `docs/superpowers/handover/events-family.md` also reports. The
description declares `exportClients` and `exportGroupsAndRoles` as the export's
two query booleans and gives `partialImport` a request body of
`{"format":"binary","type":"string"}` with no schema at all, so **everything
about the import's body and its answer had to be measured**; the description
says only that 200, 403 and 409 are possible.

One hint was wrong: the handover named as the source is
`docs/superpowers/handover/scattered-remainder.md`, which does not exist. The
inheritance is in two places instead -
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` under
`### partial-export`, and AGENTS.md's charset bullet.

---

## 1. What `partial-export` carries, counted from the body

### 1.1 The whole of it in one sentence

**`partial-export` is `GET /admin/realms/{realm}` with sixteen keys spliced into
it, and every key the two bodies share holds a byte-identical value.**

That is not a paraphrase, it is the measurement. On master:

```
GET  /admin/realms/master               106 keys   4477 bytes
POST /admin/realms/master/partial-export
        no parameters                   118 keys  40509 bytes
        ?exportClients=true             120 keys  46595 bytes
        ?exportGroupsAndRoles=true      120 keys  42162 bytes
        both                            122 keys  55118 bytes
```

Computed over the bodies rather than asserted:

- the export's key set is a strict **superset** of the realm representation's -
  nothing is dropped, on any of the four settings;
- the shared keys come back **in the realm representation's own order**;
- **no shared key's value differs**, on any of the four settings.

So the realm-representation half needs no second truth in Gloak. The export is
that body with blocks inserted.

### 1.2 The twelve export-only blocks, counted from the body

The count in the observed document is right, and it is written here **beside the
list**, from a set difference over the parsed bodies rather than by hand:

```
 #  key                          type   on master        index in the 122-key body
 1  localizationTexts            object {}                       61
 2  scopeMappings                array  1 entry                  86
 3  clientScopes                 array  15 entries               89
 4  defaultDefaultClientScopes   array  9 names                   90
 5  defaultOptionalClientScopes  array  5 names                   91
 6  identityProviders            array  []                        99
 7  identityProviderMappers      array  []                       100
 8  components                   object 3 provider types         101
 9  authenticationFlows          array  18 entries               103
10  authenticatorConfig          array  4 entries                104
11  requiredActions              array  14 entries               105
12  keycloakVersion              string "26.7.1"                 114
```

**A default realm populates ten of the twelve.** Only `localizationTexts`,
`identityProviders` and `identityProviderMappers` are empty, and
`localizationTexts` is `{}` rather than `[]`. This is not a body of empty
arrays: `clientScopes` alone is 17105 bytes and `authenticationFlows` 13061,
which together are three quarters of the 40 kB.

The twelve are **unconditional** - they are in the no-parameter body, and the
two booleans neither add to them nor take from them.

### 1.3 What each of the two booleans adds

Both default to **false**. `?exportClients=false` and
`?exportGroupsAndRoles=false` gave bodies byte-identical to the no-parameter
one, and so did both together.

```
exportGroupsAndRoles=true   adds  roles   (index 49)   groups  (index 50)
exportClients=true          adds  clientScopeMappings (87)  clients (88)  users (82/84)
```

Three things here are not what the names say, and each is a thing a plan written
from the parameter names would have got wrong.

**(a) `exportClients` adds a third key, and master cannot show it.** `users` is
present only when the realm holds a **service account user**, and it holds
nothing else: on `gloak-pi`, after one client with `serviceAccountsEnabled` was
created, `?exportClients=true` answered with
`users: [{"username":"service-account-conf-client", ...}]` and
`?exportGroupsAndRoles=true` answered with no `users` key at all. None of the six
clients a default master bootstraps has service accounts enabled, so on master
`exportClients` looks like it adds exactly two keys. **It adds three, and the
third is gated on realm state rather than on the request.** This is why the
measurement was repeated in a created realm carrying data, and it is the reason
the brief's warning about two-condition rules is quoted in the case comments.

**(b) The two booleans are not independent.** `roles` is an object, and its
`client` half appears **only when both flags are true**:

```
?exportGroupsAndRoles=true            roles = {realm:[5]}                  1736 bytes
?exportClients=true&...GroupsAndRoles roles = {realm:[5], client:{6 clients}} 9057 bytes
```

`roles.realm` is identical between the two. So `roles.client` is a cell only a
request supplying **both** conditions reaches, and a test sending one flag at a
time pins nothing about it. This is also why the byte counts do not add up:
46595 + 42162 - 40509 = 48248 against a measured 55118, and the 6870-byte
difference is exactly `roles.client`.

**(c) The booleans are `Boolean.parseBoolean`, and a repeat takes the first.**
Measured across ten spellings:

```
true TRUE True   ->  clients exported
false 1 0 yes on "" bogus  ->  not
?exportClients=true&exportClients=false   ->  exported     (first wins)
?exportClients=false&exportClients=true   ->  not exported (first wins)
```

`1` is false. An unknown parameter name is ignored.

### 1.4 The response, and where it breaks the Admin API's rule

```
HTTP/1.1 200 OK
transfer-encoding: chunked
Content-Type: application/json          <- no charset
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Robots-Tag: none
```

**No `Cache-Control` at all** and **no charset**, both against a control taken in
the same script: `GET /admin/realms/master` on the same container answered
`content-length: 4477`, `Cache-Control: no-cache` and
`application/json;charset=UTF-8`. AGENTS.md already records `partial-export` as
one of the charset rule's three counterexamples, and this measurement confirms
it rather than inheriting it. The absent `Cache-Control` is new here and is the
realm's own reads' opposite, one path segment away.

The five security headers are all present, which agrees with the media-type rule
in AGENTS.md: this is an `application/json` 2xx.

### 1.5 The guard, and the two-condition rule inside it

Swept one `realm-management` role at a time over all 22, plus a caller holding
none, in a realm created for the sweep, against the four parameter settings.
Then swept again with `manage-realm` plus each of the other 21.

```
                         none  ?clients  ?g+r   both
manage-realm alone       200   403       403    403
view-realm alone         403   403       403    403
every other role alone   403   403       403    403
realm-admin              200   200       200    200
manage-realm+view-clients   200  200     403    403
manage-realm+manage-clients 200  200     403    403
manage-realm+query-groups   200  403     200    403
manage-realm+view-users     200  403     200    403
manage-realm+manage-users   200  403     200    403
manage-realm+view-clients+query-groups  200  200  200  200
view-realm+view-clients+query-groups+manage-users  403 403 403 403
```

**`view-realm` is refused**, which is the surprise: every other realm-shaped read
in this API takes `view-realm` or `manage-realm`, and `realmConfigReadRoles`
already exists for exactly that pair. Using it here would open a whole-realm
export to a read-only caller.

The rule is a conjunction whose second and third halves are switched on **by the
request**:

```
always                       manage-realm
if exportClients=true      + view-clients or manage-clients
if exportGroupsAndRoles    + query-groups or view-users or manage-users
```

`query-clients` and `create-client` do not open the clients half; `query-users`
does not open the other one, although `view-users` and `manage-users` do. The
triple confirms it is a plain conjunction and the `view-realm` quadruple confirms
`manage-realm` is not substitutable.

### 1.6 Is the export reproducible?

Two calls minutes apart on one container were **byte-identical**, with a control
in the same script that was known to differ and did. AGENTS.md is explicit that
two agreeing recordings are not evidence, so the answer rests on arithmetic
instead: the body carries **168 UUID-valued fields across 20 distinct paths**,
enumerated from the parsed body -

```
/id                                          1
/defaultRole/id  /defaultRole/containerId    1 each
/clientScopes/*/id                          15
/clientScopes/*/protocolMappers/*/id        35
/authenticationFlows/*/id                   18
/authenticatorConfig/*/id                    4
/components/<3 provider types>/*/id      4+10+1
/clients/*/id                                6
/clients/*/protocolMappers/*/id              2
/roles/{realm,client/*}/*/id and containerId 2x35
```

and every one of them is minted at bootstrap. **So the golden is masks, and they
are not inert**: each of those twenty paths changes on every container.

It carries **no timestamp** and **no key material**. The four `KeyProvider`
components come back as `id, name, providerId, subComponents, config` with
`config` holding only `priority` and sometimes `algorithm` - no `privateKey`, no
`certificate`, no `secret`. A confidential client's secret is present and is
**exactly ten asterisks**, `"**********"`, not the stored value. That was
measured rather than assumed; the first reading of the key set said "the secret
is exported" and it is not.

`keycloakVersion` is the constant `"26.7.1"`.

### 1.7 The nested shapes, transcribed

Key orders taken from the parsed body, one line per distinct shape.

```
clientScopes/*        id name description protocol attributes [protocolMappers]
  protocolMappers/*   id name protocol protocolMapper consentRequired config
components/<type>/*   id [name] providerId [subType] subComponents config
authenticationFlows/* id alias description providerId topLevel builtIn authenticationExecutions
  executions/*        [authenticatorConfig] [authenticator] authenticatorFlow
                      requirement priority autheticatorFlow [flowAlias] userSetupAllowed
authenticatorConfig/* id alias config
requiredActions/*     alias name providerId enabled defaultAction priority config
scopeMappings/*       clientScope roles
clientScopeMappings   {clientId: [{client, roles}]}
roles/realm/*         id name description composite [composites] clientRole containerId attributes
roles/client/{id}/*   same
groups/*              id name path [parentId] subGroups attributes realmRoles clientRoles
clients/*             the client representation, secret masked
users/*               service accounts only
```

Two of these are Keycloak defects reproduced rather than tidied:

- **`autheticatorFlow`**, spelled without its `n`, is emitted **beside**
  `authenticatorFlow` on every execution. Both keys, both booleans, same value.
- The **export's group shape is a seventh representation of a group**, and
  AGENTS.md says there are six. It has no `access` and no `subGroupCount`, and it
  alone carries `realmRoles` and `clientRoles`. A child carries `parentId` where
  a top-level group does not.

---

## 2. What `partialImport` accepts and what it answers

### 2.1 The result body

```json
{"overwritten":0,"added":1,"skipped":0,
 "results":[{"action":"ADDED","resourceType":"USER","resourceName":"u1",
             "id":"ba3d3d6a-c8a7-4de0-88b8-404a1094641d"}]}
```

Four keys in that order, three counts and an array; each result four keys in that
order. The success is `200 application/json;charset=UTF-8` - **the import obeys
the Admin API's charset rule that the export beside it breaks.**

`action` is `ADDED`, `SKIPPED` or `OVERWRITTEN`. `resourceType` is `USER`,
`GROUP`, `CLIENT`, `REALM_ROLE`, `CLIENT_ROLE` or **`IDP`** - the last is not
spelled `IDENTITY_PROVIDER`.

A client role's `resourceName` is `"<clientId>-->,<roleName>"` without the comma:
`"pi-client-a-->pi-crole-a"`, and **its `id` is the client's uuid, not the
role's**. Measured twice on two different clients.

### 2.2 `results` has no reproducible order

Five runs of one identical body against identical state, under `SKIP` so every
id was an existing resource's and therefore fixed:

```
run 1  GROUP USER:mu2 CLIENT_ROLE IDP USER:mu1 CLIENT REALM_ROLE
run 2  IDP CLIENT REALM_ROLE USER:mu1 CLIENT_ROLE GROUP USER:mu2
run 3  CLIENT_ROLE GROUP REALM_ROLE USER:mu1 CLIENT IDP USER:mu2
run 4  REALM_ROLE IDP USER:mu2 CLIENT CLIENT_ROLE USER:mu1 GROUP
run 5  CLIENT USER:mu1 GROUP IDP REALM_ROLE CLIENT_ROLE USER:mu2
```

Five orders. It is not input order, it is not grouped by type - the two users
land apart in every run - and it is not stable within one container. `Keycloak`
collects the results in a `HashSet` whose element has no `hashCode`, so the order
is an identity hash. **`Case.Unordered` on `/results` is mandatory here and it is
the opposite of inert**: it is the only thing that lets a multi-result case be
asserted at all.

### 2.3 The policy: `ifResourceExists`, on a resource that already exists

The field is spelled `ifResourceExists`. `policy` is not read - a body naming
`policy` behaves exactly as one naming nothing.

```
FAIL       409  {"errorMessage":"Group '/g4' already exists"}
                {"errorMessage":"User with user name u1 already exists."}
SKIP       200  skipped 1, action SKIPPED,    id = the existing resource's
OVERWRITE  200  overwritten 1, action OVERWRITTEN, id = a NEW uuid
absent     409  identical to FAIL
```

Three things worth having in front of you before writing the handler:

- **`FAIL` is the default.** A body with no `ifResourceExists` answers the 409.
- **`OVERWRITE` mints a new id.** `g4` went in as `dd49df34-...` and came back
  `4d47fb3d-...`; it is a delete and a recreate, not an update.
- The two 409 spellings differ: the group's has **no** full stop and interpolates
  the path, the user's has one and interpolates the username. Both are the
  `errorMessage` family, `application/json` with no charset, and both carry the
  five security headers.

On a resource that does **not** exist, all three policies answer the same 200
`ADDED`.

### 2.4 An unknown policy value

```
"BOGUS"   500  {"error":"unknown_error","error_description":"Cannot parse the JSON"}
"skip"    500  the same - the enum is case-sensitive
""        500  the same
null      500  {"error":"unknown_error","error_description":"For more on this error consult the server log."}
5         500  {"error":"unknown_error","error_description":"Cannot parse the JSON"}
```

**Two different 500s on one field.** An unknown *string* fails to bind and
answers `Cannot parse the JSON`; an explicit `null` binds and then dereferences,
answering the generic description. And the unknown value is rejected **before any
resource is looked at**: `BOGUS` with a resource that does not exist is the same
500, so this is not a per-resource failure.

### 2.5 The other body shapes, and F163

This endpoint answers **both** codes AGENTS.md records as belonging to different
endpoint families, and the split is visible on one route:

```
{            500  invalid_request  Cannot parse the JSON     <- a syntax error
{"users":[],} 500 invalid_request  Cannot parse the JSON
{users:[]}   500  invalid_request  Cannot parse the JSON
nul          500  invalid_request  Cannot parse the JSON
[            500  unknown_error    Cannot parse the JSON     <- binds wrong at token 1
[]           500  unknown_error    Cannot parse the JSON
"x"          500  unknown_error    Cannot parse the JSON
true         500  unknown_error    Cannot parse the JSON
7            500  unknown_error    Cannot parse the JSON
(empty)      500  unknown_error    Cannot parse the JSON
{"users":"nope"}  500 unknown_error Cannot parse the JSON
```

**A JSON *syntax* error answers `invalid_request`; syntactically valid JSON that
will not bind answers `unknown_error`.** Both are 500 here, where every other
`Cannot parse the JSON` in this repository is a 400.

That is exactly the request F163 asked for and could not get from one endpoint:
"a body of the **right** shape carrying a value of the wrong type." `{"users":"nope"}`
is that request, and it answers `unknown_error`, on the same route where `{`
answers `invalid_request`. **The description is shared and the code is not**, and
what decides the code is where the failure happened - the parser or the binder -
not the body's shape. See §3.

Two more measured shapes:

```
{"nosuchkey":[1,2,3]}       200 {"overwritten":0,"added":0,"skipped":0,"results":[]}
{"users":[{"username":7}]}  200 ADDED, resourceName "7"
{} and {"ifResourceExists":"FAIL"}  200 with an empty results array
{} {}  (two documents)      200 with an empty results array
```

An unknown key is ignored, and Jackson coerces a number to a string rather than
refusing it, so "wrong type" is narrower than it sounds.

### 2.6 The groups defect

**A group with no `path` is a 500**, on every policy value:

```
{"groups":[{"name":"g1"}]}                500 unknown_error / consult the server log
{"groups":[{"name":"g4","path":"/g4"}]}   200 ADDED
```

The server log names it: `GroupsPartialImport.getModelId` NPEs because
`findGroupModel` returns null - Keycloak creates the group and then looks it up by
a path the representation never carried. **The realm was `[]` afterwards**, so the
whole import rolls back; the 500 leaves nothing behind. Reproduced on three
bodies.

And **the body's `id` wins on a group import**: a group sent with
`"id":"11111111-1111-1111-1111-111111111111"` came back with exactly that id and
holds it in the realm. AGENTS.md records that rule for `POST /client-scopes` and
`POST /clients`; this is a third endpoint on the same side of it.

### 2.7 The guard, and where it does not follow the body

```
manage-realm alone       200 on an empty body, a user, a client and a group
realm-admin              200 on all four
every other role alone   403
view-realm+view-clients+query-groups+manage-users  403
```

**`manage-realm` alone opens every resource type.** The import's guard does *not*
follow what the body asks for, where the export's guard does follow what the
query asks for - two neighbouring operations, one tag, opposite answers to the
same question. A `manage-realm` caller holding no `manage-users` creates users
through it.

### 2.8 The rest of the surface, both operations

```
no token                 401 {"error":"HTTP 401 Unauthorized"}       both
unknown realm            404 {"error":"Realm not found."}            both
GET PUT DELETE PATCH     404 {"error":"HTTP 404 Not Found"}          both
```

The wrong-method 404 is the generic one, so both routes are in the majority that
AGENTS.md's fallback bullet describes and neither is one of its 405 exceptions.

---

## 3. What this contradicts, and what it adds

Recorded here and repeated in the handover, because the brief asks for any line
in AGENTS.md or the observed document a measurement contradicts.

1. **The observed document's `### partial-export` entry is right and
   incomplete.** "The realm representation plus twelve export-only blocks: 40 kB,
   chunked, `application/json` with no charset" - all four claims check out,
   including the twelve, counted from the body. What it does not say is that the
   40 kB is the **no-parameter** body, that the parameters add five more keys,
   and that `Cache-Control` is absent.
2. **AGENTS.md's charset bullet is confirmed**, not contradicted:
   `POST /partial-export` is a 2xx with a body and no charset. `partialImport`'s
   200 does carry the charset, so the pair does not both belong on that list.
3. **AGENTS.md says a group has six representations. There is a seventh** - the
   export's, with `realmRoles` and `clientRoles` and no `access`.
4. **AGENTS.md pairs `Cannot parse the JSON` with a 400 in two error codes split
   by endpoint family.** `partialImport` answers it with a **500** in both codes,
   split by *where the failure happened* on one route. This is F163's discriminating
   request and it is now available.
5. **`resourceType` for an identity provider is `IDP`.** Nothing in this
   repository would have guessed the abbreviation.

---

## 4. The build

### 4.1 `partial-export`

`internal/admin/partialexport.go`.

The realm-representation half is not re-declared. `realmrep.go` is the one truth
for those 106 fields and the measurement in §1.1 says the export's shared values
are byte-identical, so the handler marshals `realmRepresentation` and **splices**
the export blocks in at their measured anchors. A struct carrying 122 fields
would be a second copy of a body whose order is already asserted by
`realmrep_test.go`, and AGENTS.md's warning about a second truth applies exactly.

The splice is by anchor key, not by index: each block names the realm-representation
key it follows. A test asserts the resulting 122-key list, so a moved anchor is a
red test rather than a silent divergence.

Blocks, each read through the store the way its own endpoint already reads it:

| block | source |
| --- | --- |
| `localizationTexts` | always `{}`; Gloak stores texts per locale and the export's shape is a flat object, unmeasured on a populated realm |
| `scopeMappings` | `scopemappings.go`'s realm-level view |
| `clientScopes` | `clientScopeRepresentationOf`, unchanged - the export shape and the endpoint shape are the same six keys |
| `defaultDefaultClientScopes`, `defaultOptionalClientScopes` | name lists |
| `identityProviders`, `identityProviderMappers` | `identityproviders.go` |
| `components` | a new export shape: `providerType` and `parentId` dropped, `subComponents` added |
| `authenticationFlows`, `authenticatorConfig` | a new export shape nesting `authenticationExecutions`, with `autheticatorFlow` beside `authenticatorFlow` |
| `requiredActions` | the endpoint shape plus `config` |
| `keycloakVersion` | the constant |
| `roles`, `groups` | behind `exportGroupsAndRoles`, with `roles.client` behind **both** |
| `clientScopeMappings`, `clients`, `users` | behind `exportClients` |

Guard: a new one. `realmConfigReadRoles` is wrong here - `view-realm` is refused -
and the conditional halves cannot be expressed by `guardAny`, so the parameters
are parsed first and the role check is assembled from them.

Response: `httpx` must write `application/json` with **no** charset and no
`Cache-Control`. `writeAdminJSON` sets the charset, so this uses the plain writer.

### 4.2 `partialImport`

`internal/admin/partialimport.go`.

Guard `realmWriteRoles` - `manage-realm`, measured, and not conditional on the
body.

Decode in two stages so the two 500s in §2.4 and §2.5 can be told apart: a
syntax failure answers `invalid_request`, a bind failure answers `unknown_error`,
and both send `Cannot parse the JSON` with a 500.

Five resource types in one pass, each: look up by its natural key, then apply the
policy. `FAIL` is the zero value. The whole import is one unit - a failure leaves
nothing behind, measured on the groups defect.

`results` is emitted in a deterministic order because Gloak's own goldens have to
be reproducible; the case carries `Unordered` on `/results` because Keycloak's is
not.

### 4.3 What is deliberately not built

- **A group with no `path`** is Keycloak's NPE. Gloak reproduces the 500 and the
  rollback, and does not invent a working import.
- **The export's `localizationTexts` on a realm that has texts** was not
  measured. The block is emitted as `{}`, which is what every measured body
  holds, and the gap is a follow-up rather than a guess.

### 4.4 Cases

Appended at the very end of `catalog_admin.go`, with fixtures appended at the
very end of `fixture.go`'s map and after its last helper. Every id-bearing path
in §1.6 carries a `Volatile` mask; none of them is inert, and
`TestNoMaskIsInertOnItsGolden` is the ratchet that says so.
