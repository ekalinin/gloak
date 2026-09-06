# `partial-export` and `partialImport`

Date: 2026-09-06
Branch: `feat/partial-export-import`
Plan: `docs/superpowers/plans/2026-09-06-partial-export-import.md`

Everything below was measured against a live Keycloak 26.7.1 on `:8176` on
2026-09-06, in containers this cut started and removed. Every destructive probe
ran in a realm created for it - `gloak-pi` for the import and `gloak-guard` for
the role sweeps. **`master` received exactly one thing**: one user holding no
admin role, needed for the cell where an unknown realm is answered to a caller
that holds nothing. Nothing was imported into `master` and no user profile was
written, which are the two mistakes that have cost this project a container.

The brief's pair was checked against the vendored description before anything
was planned. It is right: both paths exist, both take the single `POST`, both
carry the `Realms Admin` tag, and that tag holds **45** operations. One hint was
wrong - `docs/superpowers/handover/scattered-remainder.md` does not exist, and
the inheritance is in `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`
under `### partial-export` and in AGENTS.md's charset bullet instead.

---

## 1. Measurements

### 1.1 `partial-export` is the realm representation with sixteen keys spliced in

The inherited sentence - "the realm representation plus twelve export-only
blocks, 40 kB, chunked, `application/json` with no charset" - is right on all
four counts, and the twelve was counted out of the body rather than trusted.

```
GET  /admin/realms/master                        106 keys   4477 bytes
POST .../partial-export                          118 keys  40509 bytes
POST .../partial-export?exportClients=true       120 keys  46595 bytes
POST .../partial-export?exportGroupsAndRoles     120 keys  42162 bytes
POST .../partial-export?both                     122 keys  55118 bytes
```

Computed over the parsed bodies, not read off:

- the export's key set is a **strict superset** of the realm representation's on
  all four settings - nothing is dropped;
- the shared keys come back in the realm representation's **own order**;
- **no shared key's value differs**, on any setting.

That is why `internal/admin/partialexport.go` splices rather than declaring a
122-field struct: `realmrep.go` stays the one truth for those 106 fields, and
the anchors are key names so that a field moved there is a red test rather than
a block that lands somewhere else.

The twelve, with the index each occupies in the 122-key body:

```
 1 localizationTexts  61      7 identityProviderMappers 100
 2 scopeMappings      86      8 components              101
 3 clientScopes       89      9 authenticationFlows     103
 4 defaultDefaultClientScopes  90  10 authenticatorConfig 104
 5 defaultOptionalClientScopes 91  11 requiredActions     105
 6 identityProviders  99     12 keycloakVersion         114
```

**Ten of the twelve are populated on a default realm.** Only
`localizationTexts` (`{}`, not `[]`), `identityProviders` and
`identityProviderMappers` are empty. `clientScopes` alone is 17105 bytes and
`authenticationFlows` 13061, so this is not a body of empty arrays.

### 1.2 What the two booleans add, and the two places the names mislead

Both default to **false**: `?exportClients=false`, `?exportGroupsAndRoles=false`
and both together each gave a body byte-identical to the no-parameter one.

```
exportGroupsAndRoles=true   adds  roles (49)  groups (50)
exportClients=true          adds  clientScopeMappings (87)  clients (88)  users (84)
```

**`exportClients` adds three keys, not two, and master cannot show the third.**
`users` is present only when the realm holds a **service account user**, and it
holds nothing else - not one of the realm's ordinary users. None of master's six
bootstrapped clients has service accounts enabled, so on master the flag looks
like it adds two keys; in `gloak-pi`, after one client with
`serviceAccountsEnabled`, `?exportClients=true` answered with
`users: [{"username":"service-account-conf-client", ...}]` and
`?exportGroupsAndRoles=true` answered with no `users` key at all.

**The two booleans are not independent.** `roles.client` appears only when both
are true:

```
?exportGroupsAndRoles=true   roles = {realm:[5]}                     1736 bytes
?both                        roles = {realm:[5], client:{6 clients}} 9057 bytes
```

The realm halves are identical. So `roles.client` is a cell only a request
supplying **both** conditions reaches, and the byte counts do not add up for
exactly that reason: 46595 + 42162 - 40509 = 48248 against a measured 55118, and
the 6870-byte difference is that key.

**Every client gets an entry in `roles.client`, including one with no roles.**
Three of master's six - `security-admin-console`, `admin-cli` and
`account-console` - come back as empty arrays. Skipping them is the obvious
implementation and it drops half the block's keys; it was found by the
key-order assertion rather than by a count.

The flags are `Boolean.parseBoolean` over the **first** occurrence:

```
true TRUE True             export
false 1 0 yes on "" bogus  do not          - `1` is false
?exportClients=true&exportClients=false    exports      (first wins)
?exportClients=false&exportClients=true    does not
```

### 1.3 The response, and the two headers

```
HTTP/1.1 200 OK
transfer-encoding: chunked
Content-Type: application/json        <- no charset
Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options,
X-Frame-Options, X-Robots-Tag         <- all five
                                      <- no Cache-Control at all
```

Against a control taken in the same script: `GET /admin/realms/master` answered
`content-length: 4477`, `Cache-Control: no-cache` and
`application/json;charset=UTF-8`. AGENTS.md already records this route as one of
the charset rule's three counterexamples and that is **confirmed** rather than
inherited. The absent `Cache-Control` is new here.

### 1.4 The export's guard, and the conditional halves

Swept one `realm-management` role at a time over all 22 plus a caller holding
none, on four parameter settings; then again with `manage-realm` plus each of
the other 21; then two triples.

```
                                            none  ?cli  ?g+r  both
manage-realm alone                          200   403   403   403
view-realm alone                            403   403   403   403
every other role alone                      403   403   403   403
realm-admin                                 200   200   200   200
manage-realm + view-clients                 200   200   403   403
manage-realm + manage-clients               200   200   403   403
manage-realm + query-clients                200   403   403   403
manage-realm + create-client                200   403   403   403
manage-realm + query-groups                 200   403   200   403
manage-realm + view-users                   200   403   200   403
manage-realm + manage-users                 200   403   200   403
manage-realm + query-users                  200   403   403   403
manage-realm + view-clients + query-groups  200   200   200   200
view-realm + view-clients + query-groups + manage-users   403 403 403 403
```

```
always                     manage-realm
if exportClients           + view-clients or manage-clients
if exportGroupsAndRoles    + query-groups or view-users or manage-users
```

**`view-realm` is refused**, which is the surprise: it opens the realm read, the
key set, the default-groups listing and both client-policy reads.
`realmConfigReadRoles` is therefore the wrong set here, and reusing it would open
a whole-realm export to a read-only caller.

Order: the realm, then `manage-realm`, then the parameters. An unknown realm is
`404 {"error":"Realm not found."}` to a caller holding nothing; a known realm is
`403 {"error":"HTTP 403 Forbidden"}` to the same caller; and a `manage-realm`
caller sending `exportClients=true` at an unknown realm gets the 404.

### 1.5 Is the export reproducible? Masks, and the two orders that are not

Two calls minutes apart on one container were byte-identical, with a control in
the same script that was known to differ and did. AGENTS.md is explicit that two
agreeing recordings are not evidence, so the answer rests on arithmetic: the
body carries **168 UUID-valued fields across 20 distinct paths**, every one
minted at bootstrap. The masks are therefore not inert; each of those paths
changes on every container.

It carries **no timestamp** and **no key material**. The four `KeyProvider`
components come back `id, name, providerId, subComponents, config` with `config`
holding only `priority` and sometimes `algorithm` - no `privateKey`, no
`certificate`, no `secret`.

**A confidential client's `secret` is exactly ten asterisks**, `"**********"`,
not the stored value. The first reading of the key set had this the wrong way
round: the probe reported that `secret` was present and it took printing the
value to see that it was masked. A mask derived from the secret's own length
would leak it, which is why the constant is ten asterisks rather than a
computation.

Two array orders are the export's own and neither is the order the endpoint
beside it serves:

```
authenticationFlows   sorted by alias, byte order, capitals first
authenticatorConfig   sorted by alias
```

`GET /authentication/flows` serves seven flows in seed order and the export
serves eighteen sorted. Serving the store's order is what the first comparison
of this body caught.

Two Java maps are in `javamap.KeyOrder`, and **both are discriminating vectors**
- `javamap.SizedKeyOrder` gets both wrong and so does sorting:

```
components' three provider types
  ClientRegistrationPolicy, UserProfileProvider, KeyProvider
roles.client's six containers
  security-admin-console, admin-cli, account-console, broker, master-realm, account
```

`internal/javamap` is another stream's this round, so those two vectors are
recorded here rather than added to its tests. See §3.

### 1.6 `saml ecp` is top-level in the export and hidden from the listing

The export is the first body in this repository that enumerates every flow, and
it immediately disagreed with `GET .../flows`:

```
GET .../authentication/flows            7 flows,  master and a created realm alike
POST .../partial-export                18 flows on master, 21 on a created realm
                                       8 of them topLevel, including `saml ecp`
GET .../flows/saml%20ecp/executions    200, its one execution
```

So the flow exists, is addressable by its own route, says it is top-level, and
is filtered out of the one read whose job is to enumerate top-level flows.
Gloak's bootstrap did not have it at all; it does now, and `listFlows` filters
it, which is what keeps the seven-flow golden beside it unchanged.

### 1.7 `partialImport`'s result shape

```json
{"overwritten":0,"added":1,"skipped":0,
 "results":[{"action":"ADDED","resourceType":"USER","resourceName":"u1","id":"..."}]}
```

Four keys in that order; each row four keys in that order.

**The success carries `;charset=UTF-8` and no `Cache-Control` at all**, and its
409 and its 500 carry neither. So this response is the export's twin on one
header and its opposite on the other, one path segment away. The
`Cache-Control` half is a **hand probe this cut got wrong**: the first sweep
never looked at the header, the case asserted its presence out of habit, and the
golden recorded from Keycloak refuted it. `GET /admin/realms/master` was the
control both times and carries both headers.

`action` is `ADDED`, `SKIPPED` or `OVERWRITTEN`. `resourceType` is `USER`,
`GROUP`, `CLIENT`, `REALM_ROLE`, `CLIENT_ROLE` or **`IDP`** - not
`IDENTITY_PROVIDER`.

A client role's row is not shaped like the others: its `resourceName` is
`"<clientId>-->" + roleName`, and its **`id` is the client's uuid, not the
role's**. Measured twice on two clients.

**`results` has no reproducible order.** Five runs of one identical body against
identical state, under `SKIP` so every id was fixed:

```
run 1  GROUP USER:mu2 CLIENT_ROLE IDP USER:mu1 CLIENT REALM_ROLE
run 2  IDP CLIENT REALM_ROLE USER:mu1 CLIENT_ROLE GROUP USER:mu2
run 3  CLIENT_ROLE GROUP REALM_ROLE USER:mu1 CLIENT IDP USER:mu2
run 4  REALM_ROLE IDP USER:mu2 CLIENT CLIENT_ROLE USER:mu1 GROUP
run 5  CLIENT USER:mu1 GROUP IDP REALM_ROLE CLIENT_ROLE USER:mu2
```

Five orders. Not input order, not grouped by type - the two users land apart
every time - and not stable within one container. Keycloak collects them in a
`HashSet` whose element has no `hashCode`. Gloak emits a deterministic order
because its own goldens have to be reproducible, and **no golden in this cut
asserts a multi-row order**: every import case is a single row, so no
`Unordered` mask was added that sorting would make inert.

### 1.8 `ifResourceExists`, including an unknown one

The field is spelled `ifResourceExists`; **`policy` is not read** - a body naming
it behaves exactly as one naming nothing.

On a resource that already exists:

```
FAIL        409 {"errorMessage":"..."}          see the six spellings below
absent      409 identical to FAIL               so FAIL is the default
SKIP        200 skipped 1, SKIPPED, id = the existing resource's
OVERWRITE   200 overwritten 1, OVERWRITTEN, id = a NEW uuid
```

**`OVERWRITE` mints a new id** - measured on a user, a group and a client. It is
a delete and a recreate, not an update. On a resource that does not exist, all
three answer the identical 200 `ADDED`.

An unknown value is two different answers, and **the second one is a
two-condition rule this cut got wrong the first time**:

```
                        resource absent          resource present
"BOGUS" "skip" "" 5     500 Cannot parse the JSON  500 Cannot parse the JSON
null                    200 ADDED                  500 consult the server log
absent                  200 ADDED                  409 already exists
```

An unknown *string* fails to **bind**, and it fails before any resource is
looked at, which is why both of its cells are the same 500. An explicit `null`
**binds** and is dereferenced only in the branch that finds a resource, so it is
an ordinary 200 when there is nothing to collide with.

The first hand probe sent `null` only against a resource that already existed
and wrote the 500 down as the whole answer. The golden recorded from Keycloak
refuted it - which is the shape the brief warns about, a two-condition rule
whose probe supplied one condition. It was re-measured with both supplied, on a
user and on a group, in both directions.

The enum is case-sensitive. Absent and `null` are two different answers on the
"present" column, which a Go `*string` cannot tell apart; the handler reads the
raw bytes for that reason alone.

The six FAIL spellings, and **three of them end in a full stop where three do
not**:

```
User with user name u1 already exists.
Group '/g4' already exists
Client id 'pi-client-a' already exists
Realm role 'pi-role-a' already exists.
Client role 'pi-crole-a' for client 'pi-client-a' already exists.
Identity Provider 'idp-a' already exists.
```

A seventh appears when one body names the same resource **twice**, and it fires
under `SKIP` as well as `FAIL` - the policy is about resources that existed
before the import, not about the body's own repeats:

```
409 {"errorMessage":"Duplicate resource error"}
```

**A 409 rolls the whole import back.** A body naming a new user and then an
existing one under FAIL answered the 409 and left the new user uncreated.

### 1.9 The decode, and F163's discriminating request

One route answers **both** of the codes AGENTS.md records as belonging to
different endpoint families:

```
{              500  invalid_request  Cannot parse the JSON
{"users":[],}  500  invalid_request  Cannot parse the JSON
{users:[]}     500  invalid_request  Cannot parse the JSON
nul            500  invalid_request  Cannot parse the JSON
[              500  unknown_error    Cannot parse the JSON
[]  "x"  true  7    500  unknown_error    Cannot parse the JSON
(empty body)   500  unknown_error    Cannot parse the JSON
{"users":"nope"}    500  unknown_error    Cannot parse the JSON
```

**A JSON syntax error answers `invalid_request`; syntactically valid JSON that
will not bind answers `unknown_error`.** Both are 500 here, where every other
`Cannot parse the JSON` in this repository is a 400. The discriminator is the
**first token**: a body opening with a complete JSON value that is not an object
has already failed to bind before truncation could be noticed, which is why a
bare `[` is `unknown_error` and a bare `{` is `invalid_request`.

Three bodies that are accepted rather than refused:

```
{"nosuchkey":[1,2,3]}         200, an empty result set - unknown keys are ignored
{} {}                         200 - Jackson reads the first document and stops
{"users":[{"username":7}]}    200, ADDED, resourceName "7" - a number is coerced
```

### 1.10 The groups defect, and the body's id

**A group with no `path` is a 500**, on every policy value:

```
{"groups":[{"name":"g1"}]}                 500 unknown_error / consult the server log
{"groups":[{"name":"g4","path":"/g4"}]}    200 ADDED
```

The container log names it: `GroupsPartialImport.getModelId` dereferences a null
from `findGroupModel`, because Keycloak creates the group and then looks it up by
a path the representation never carried. **The realm was `[]` afterwards** on
three such bodies, so the 500 leaves nothing behind.

And **the body's `id` wins on a group import**: a group sent with
`"id":"11111111-1111-1111-1111-111111111111"` came back with exactly that id and
holds it in the realm. AGENTS.md records that rule for `POST /client-scopes` and
`POST /clients`; this is a third endpoint on the same side of it.

### 1.11 `partialImport`'s guard does not follow its body

```
manage-realm alone        200 on an empty body, a user, a client and a group
realm-admin               200 on all four
every other role alone    403
view-realm + view-clients + query-groups + manage-users   403
```

**`manage-realm` alone opens every resource type.** A caller holding no
`manage-users` creates users through it. That is the opposite of the export next
door, whose guard grows with its query - two neighbouring operations, one tag,
opposite answers to the same question.

Order: the realm, then the caller, then the body. A weak caller sending `{`
against a realm that does not exist gets the 404; against one that does, the 403.

### 1.12 The rest of the surface, both operations

```
no token                 401 {"error":"HTTP 401 Unauthorized"}   both
unknown realm            404 {"error":"Realm not found."}        both
GET PUT DELETE PATCH     404 {"error":"HTTP 404 Not Found"}      both
```

Neither route is one of AGENTS.md's 405 exceptions.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds them in. This branch does not
edit AGENTS.md.

- **`partial-export` is `GET /admin/realms/{realm}` with sixteen keys spliced
  into it, and the two bodies never disagree about a shared key.** Twelve are
  unconditional, two follow `exportGroupsAndRoles` and **three** follow
  `exportClients` - `clientScopeMappings`, `clients` and `users`. The third is
  invisible on master, because `users` holds **service accounts only** and none
  of the six bootstrapped clients has one; it appears the moment a client with
  `serviceAccountsEnabled` exists. Counting the flag's keys on master gives two
  and is wrong. And **the two flags are not independent**: `roles.client`
  appears only when both are set, so a test sending one flag at a time pins
  nothing about it. Both booleans are `Boolean.parseBoolean` over the **first**
  occurrence of a repeated parameter, so `1` is false and
  `?exportClients=true&exportClients=false` exports.

- **Neither `partial-export` nor `partialImport` sends `Cache-Control`, and only
  one of them sends the charset.** The export's 200 is `application/json` with
  no charset - the third of the charset rule's counterexamples - and the
  import's is `application/json;charset=UTF-8`; both omit `Cache-Control`
  entirely, and so do the import's 409 and its 500. Two operations, one tag,
  agreeing on one header and disagreeing on the other, with
  `GET /admin/realms/master` as the control, which carries both. The
  `Cache-Control` half was got wrong first by a hand probe that never looked at
  the header and was refuted by the recorded golden.

- **The export's guard is a conjunction the *query* switches on, and
  `view-realm` opens none of it.** `manage-realm` always, plus a
  `view-clients`/`manage-clients` when `exportClients` is set, plus a
  `query-groups`/`view-users`/`manage-users` when `exportGroupsAndRoles` is.
  `query-clients`, `create-client` and `query-users` open nothing, although the
  first two are in `clientsReadRoles` and the third is in `usersReadRoles`. And
  `partialImport` one path segment away takes `manage-realm` alone **whatever
  its body asks for**, so a caller holding no `manage-users` creates users
  through it. One tag, two operations, opposite shapes.

- **`saml ecp` is `topLevel: true` and `GET .../authentication/flows` does not
  list it.** Both reads were measured on master and on a created realm: the
  listing answers seven flows in each, the export answers eighteen and
  twenty-one with `saml ecp` among them, and
  `GET .../flows/saml%20ecp/executions` serves its one execution. The flow
  exists, is addressable and is filtered out of the one read whose whole job is
  to enumerate top-level flows. It became visible only when `partial-export` was
  built, because that is the first body enumerating every flow rather than the
  top-level seven.

- **The export sorts two arrays that the endpoints beside them do not.**
  `authenticationFlows` and `authenticatorConfig` come back sorted by alias, in
  byte order with capitals first, where `GET .../flows` serves seven in seed
  order. Serving the store's order here is the mistake, and it is invisible
  until a body enumerates more than the seven.

- **A `partialImport` result array has no reproducible order at all.** Five runs
  of one identical body against identical state gave five different orders - not
  input order, not grouped by type, with two users landing apart every time.
  Keycloak collects the rows in a `HashSet` whose element has no `hashCode`, so
  the order is an identity hash and is not stable inside one container, let
  alone across two. A golden that asserts a multi-row order here is asserting
  a coin toss.

- **An unknown `ifResourceExists` and an explicit `null` fail in different
  places, and only one of them needs a resource.** An unknown string, a
  lower-case one, an empty one and a number all answer
  `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`
  whether or not the resource exists, because they never bind. An explicit
  `null` **binds** and is dereferenced only in the branch that finds a resource,
  so it is a plain 200 `ADDED` on a resource that does not exist and
  `"For more on this error consult the server log."` on one that does.
  **Absent is a third answer again** - 200 then 409 - so a Go `*string`
  collapses two measured cases and the field has to be decoded as raw bytes.
  A probe that sends `null` only at a resource that already exists reports the
  500 as the whole rule and is wrong; that is how this cut first recorded it.

- **On `partialImport` the `Cannot parse the JSON` description carries two
  different codes, decided by where the failure happened rather than by the
  endpoint.** A JSON *syntax* error is `invalid_request`; syntactically valid
  JSON that will not bind is `unknown_error`. `{` is the first, `[` and `[]` and
  `"x"` and `7` and an empty body and `{"users":"nope"}` are the second. Both
  are **500**, where every other `Cannot parse the JSON` in this repository is a
  400. See F163: this is the discriminating request that follow-up asked for.

- **A `partialImport` group carrying no `path` is a 500 and the realm keeps
  nothing.** `GroupsPartialImport` creates the group and then looks it up by the
  representation's `path`, which is null, and dereferences the result. It fires
  on every policy value. Reproduced rather than fixed: a group import that
  worked without a path would be the divergence.

- **A `partialImport` body naming one resource twice is
  `{"errorMessage":"Duplicate resource error"}` with a 409, under `SKIP` as well
  as `FAIL`.** The policy is about resources that existed before the import, not
  about the body's own repeats. And a 409 of any kind **rolls the whole import
  back** - a body naming a new user and then an existing one left the new user
  uncreated.

- **`OVERWRITE` mints a new id.** Measured on a user, a group and a client: the
  row that comes back is not the row that went in, so the disposition is a
  delete and a recreate. `SKIP` answers with the **existing** resource's id, so
  the two are told apart by the id and not only by the action.

- **A `partialImport` client role's result row is shaped differently from every
  other.** Its `resourceName` is `<clientId>-->` followed by the role name, and
  its `id` is the **client's** uuid rather than the role's. And the identity
  provider's `resourceType` is `IDP`, not `IDENTITY_PROVIDER`.

- **"Already exists" has six spellings and three of them have a full stop.** The
  user's, the realm role's, the client role's and the identity provider's end in
  one; the group's and the client's do not. Same family, same verb, one
  operation.

- **The export's group shape is a seventh representation of a group.** No
  `access`, no `subGroupCount`, and it alone carries `realmRoles` and
  `clientRoles`. A child carries `parentId` where a group at the top of the realm
  does not. The bullet above that says there are six is now short by one.

- **The export's `components` block and its `roles.client` block are Java maps,
  and `javamap.KeyOrder` places both exactly.** The three provider types come
  back `ClientRegistrationPolicy, UserProfileProvider, KeyProvider` and the six
  role containers `security-admin-console, admin-cli, account-console, broker,
  master-realm, account`. `javamap.SizedKeyOrder` gets **both** wrong and so
  does sorting, so these are two more of the few measured key sets that tell the
  two constructors apart. That takes the count in the `javamap` bullet from
  fourteen to sixteen; the two are recorded here rather than added to that
  package's tests, which another stream owns this round.

- **`partial-export` carries no key material and masks a client secret to ten
  asterisks.** The four key providers come back with `priority` and sometimes
  `algorithm` and nothing else - no `privateKey`, no `certificate`, no `secret` -
  and a confidential client's `secret` is `"**********"` rather than the stored
  value. The first reading of the key set recorded it as a disclosure and was
  wrong; only printing the value said so.

---

## 3. Follow-up dispositions

### F163 - "cannot parse the JSON" is syntax against binding - **answered**

`docs/superpowers/handover/events-family.md` proposed F163 and said what would
settle it: "one request per family: a body of the **right** shape carrying a
value of the wrong type." `partialImport` supplies it, and answers on one route
what the follow-up could only compare across two:

```
{"users":"nope"}   unknown_error     the right shape, a value of the wrong type
{                  invalid_request   a syntax error, same route, same body shape
```

So the split is **where the failure happened**, not the body's shape and not the
endpoint family. `writeCannotParseJSON`'s current rule - `unknown_error` when
the body starts with `[` - is the same answer on the bodies it has been measured
against, and it is a special case of this one: a `[` is a value that will not
bind. It is **not changed here**. Fourteen decoders share it, all of its measured
bodies are 400s where these are 500s, and one endpoint's evidence is not enough
to move a shared writer - which is what F163 itself says. `partialImport` has its
own pair of writers, `writePartialImportParseError` and
`writePartialImportBindError`, and the sweep F163 asks for now has a worked
example to copy.

### F95 - `model.StringMap` for `attributes` - **untouched, and one more caller**

The export's `attributes` needs the same `UnorderedKeys` retreat the realm read
makes, for the same measured reason: four of a realm's eight attribute keys share
bucket 0 and chain in an insertion order nothing observable reveals. This cut
adds a caller and no new argument.

### F157 and F161 - what a golden can assert about a body that is not text

The reasoning transfers and the ratchet does not have to. `partial-export` is
text, so `TestNoMaskIsInertOnItsGolden` applies to it directly, and every mask
this cut declares was checked against a real difference rather than added
defensively:

- the eight `Volatile` paths cover 168 uuid-valued fields, every one minted at
  bootstrap;
- `clientScopes/*/protocolMappers` is `Unordered` because AGENTS.md records that
  those came back differently on two container starts;
- `components/*/*/config/allowed-protocol-mapper-types` is `Unordered` because
  `admin/component/list` already declares it so;
- `attributes` is `UnorderedKeys` for the reason above.

**No `Unordered` was declared on `results`.** It is the one array in this cut
whose order is measurably random, and the mask would have been correct - but
every import case here is a single row, where sorting is the identity, and an
inert mask is worse than none. The claim lives in
`internal/admin/partialimport.go`'s doc comment and in §1.7 instead.

### New: the export's `localizationTexts` on a realm that has texts

Not measured. Every measured body carries `{}`, and Gloak emits that. What a
realm carrying texts answers - a flat object, an object per locale, something
else - is one request away and was not taken, so the block is left as the one
shape that was measured rather than guessed at.

### New: `partialImport` on a client role whose container does not exist

Not measured. Gloak answers the generic 500 there, which is the shape every
other uncaught failure on this endpoint takes, and the cell is named in the code
rather than filled in with a plausible body.

### New: `jsonScalarString` and the values other than a number

`{"username":7}` is a 200 whose resource is named `"7"`, so Jackson coerces a
number. Whether it coerces a boolean or a null in the same position was not
measured, and both are left to fail the bind rather than guessed at.

---

## 4. Parity, before and after

Read off `TestCoverage`'s own table, run once on this branch and once on a
stashed tree, rather than incremented:

```
                          served  recorded  documented
admin/realms-admin  before    42         3          45
                    after     44         4          45
total               before   498 of 541
                    after    500 of 541
```

Cases added: sixteen, of which fifteen are `Implemented` and one is `Recorded`.
The `Recorded` one is `admin/realms-admin/partial-export-clients`, and its reason
is not this operation's: the body carries the six bootstrapped clients, and
`admin/clients/list-all` has been `Recorded` since P1 for the same three
differences - `master-realm` has no name and neither client-scope list, and
`account-console`'s `audience resolve` serves a populated config where the
listing measures an empty one. Those are Gloak's bootstrap rather than its
handlers. Serving the export's clients body as `Implemented` would mean either
changing the bootstrap under a case that already declares the gap, or masking
three real divergences.

**No committed golden of this cut's moved.** The `saml ecp` addition leaves
`admin/authentication-management/list` at seven flows, because `listFlows`
filters the alias exactly as Keycloak does.

One committed golden *not* of this cut's moved under `make record`, twice,
reproducibly, and was **reverted both times**:
`admin/clients/evaluate-scope-mappings-not-granted`. It enumerates the realm's
realm roles and is **not** marked `PristineRealm`, so the recorder - which
accumulates state across the shared container in catalogue order - now records
twenty-one roles where the committed golden holds five, the extra sixteen all
being `gloak-probe-*` roles other fixtures create. The verifier does not
accumulate: it builds a fresh Gloak per case from that case's own fixture, so
Gloak answers five and the committed golden is the one that matches. Reverting
it leaves the suite green. It is a **pre-existing catalogue defect** - a
realm-enumerating case missing the flag `Case.PristineRealm` exists for - and it
is reported rather than fixed here, because the case belongs to the client
chapter and nothing in this branch touches it. Whoever runs `make record` next
will meet it again.

### A third hand probe the goldens refuted

Beside the two in §1, the first recording caught a divergence no probe had
looked for at all: **Gloak's export escaped `<` and `>`**. `httpx.WriteJSON`
turns `SetEscapeHTML` off for the body it encodes, but this handler hands it a
`json.RawMessage`, which is copied through verbatim - so every fragment
marshalled with `json.Marshal` arrived pre-escaped and survived. master's
`displayNameHtml` is `<div class="kc-logo-text"><span>Keycloak</span></div>`, so
it was the first block of the first golden that said so. Every fragment in
`partialexport.go` now goes through `marshalOrderedValue`, which exists for
exactly this and whose doc comment records the last time this bit somebody.

### The mutation pass

Thirty-four mutations, one per claim, each naming the test that had to fail,
against a `git clone --no-local` so that no revert could reach the worktree. The
harness ran the named test on a clean tree **first** as a control, refused a
selector that matched nothing, read `go test`'s exit code rather than its
output, and checked every revert with `git diff --quiet`. It reported
`CONTROL_FAILED`, `SELECTOR_MATCHED_NOTHING`, `NOT_APPLIED`, `BUILD_FAILED`,
`SURVIVED` and `KILLED` as separate outcomes.

**All thirty-four were killed, and three of them only after something was
repaired** - which is what the extra outcomes are for.

Two were `BUILD_FAILED` and the mutation was the thing at fault:

- deleting the `clientScopeMappings` block left `mappings` declared and not
  used. Replaced with a rename of the key, which is the same claim and compiles,
  and is killed.
- swapping `strings.EqualFold` for `strconv.ParseBool` needed an import the file
  does not have. Replaced with `values[0] == "true"` - dropping the fold, which
  is the mistake a reader would actually make - and it is killed by the `TRUE`
  and `True` rows.

**One `SURVIVED`, and the mutation was right: the assertion was weak.** Dropping
`imp.rollback` from the conflict path left the half-imported user in the realm,
and `TestPartialImportRollsBackOnAConflict` passed anyway, because it searched
the listing for the substring `[]` - and a user representation carries
`"disableableCredentialTypes":[]` and `"requiredActions":[]` in its own body. So
the check was satisfied by the very row it was asserting was absent. The test
now parses the listing and counts, with the user the fixture did create as a
control, and the same mutation is killed. That is one commit of its own, made
before the re-run, so the diff shows the assertion changing and not the claim.

Four of the thirty-four are killed by conformance goldens and thirty by package
tests.

Two hand-written counts in `internal/admin/flows_test.go` moved, from 17 to 18
flows and 48 to 49 execution rows on master, and 20 to 21 and 55 to 56 on a
created realm. **They were not relaxed to make a failure go away**: they were
derived from `GET .../flows`, which hides `saml ecp`, and the export is the
measurement that says what the realm actually holds.
