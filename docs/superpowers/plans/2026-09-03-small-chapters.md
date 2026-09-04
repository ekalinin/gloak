# Three small chapters and the component remainder

Date: 2026-09-03
Status: accepted
Branch: `feat/small-chapters`

## 1. The count, taken from the description and checked against the catalogue

Every number below is computed, not carried in from the brief. The tag's
operations come out of
`internal/conformance/testdata/openapi/keycloak-26.7.1.json`; the served set is
the distinct `Case.Operation` of every `Implemented` case, which is exactly what
`servedOperations` counts and what `TestCoverage` prints.

```
chapter                              served  documented   unserved
admin/attack-detection                    0           3          3
admin/client-initial-access               0           3          3
admin/component                           2           6          4
admin/client-attribute-certificate        0           7          7
```

### 1.1 `Attack Detection` - 3 of 3 unserved

```
GET    /admin/realms/{realm}/attack-detection/brute-force/users/{userId}
DELETE /admin/realms/{realm}/attack-detection/brute-force/users/{userId}
DELETE /admin/realms/{realm}/attack-detection/brute-force/users
```

### 1.2 `Client Initial Access` - 3 of 3 unserved

```
GET    /admin/realms/{realm}/clients-initial-access
POST   /admin/realms/{realm}/clients-initial-access
DELETE /admin/realms/{realm}/clients-initial-access/{id}
```

### 1.3 `Component` - 4 of 6 unserved

```
served    GET    /admin/realms/{realm}/components
served    GET    /admin/realms/{realm}/components/{id}
unserved  POST   /admin/realms/{realm}/components
unserved  PUT    /admin/realms/{realm}/components/{id}
unserved  DELETE /admin/realms/{realm}/components/{id}
unserved  GET    /admin/realms/{realm}/components/{id}/sub-component-types
```

### 1.4 `Client Attribute Certificate` - 7 of 7 unserved, and it is not in this cut

```
GET  /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/download
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/generate
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/generate-and-download
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/upload
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/upload-certificate
POST /admin/realms/{realm}/identity-provider/upload-certificate
```

Two things the tag's name does not say, both read off the description:

- **The seventh operation is not under `/clients` at all.**
  `POST /admin/realms/{realm}/identity-provider/upload-certificate` carries the
  `Client Attribute Certificate` tag and lives one path segment from the
  identity provider family. A cut scoped by path would take six and report
  seven.
- **Three of the seven are `multipart/form-data` uploads and two answer a
  binary keystore.** `.../download` and `.../generate-and-download` return a JKS
  or PKCS12 byte stream chosen by a `format` field in the request body. **No
  golden in this repository holds a non-text body**, and none of the harness's
  masks - `ReplaceCaptured`, `Volatile`, `UnorderedKeys` - can reach bytes that
  are not JSON or HTML. A generated keystore is also different on every request,
  so even a byte-holding golden could assert nothing but the length.

It is therefore a decision about the harness before it is seven handlers, and
it is left where it is. See §7.

## 2. What `attack-detection` actually stores - and why this cut stores nothing

Measured on a live 26.7.1 in a created realm on 2026-09-03.

```
GET  .../attack-detection/brute-force/users/{userId}      200 application/json;charset=UTF-8
     Cache-Control: no-cache, all five security headers
{"failedLoginNotBefore":0,"numFailures":0,"numTemporaryLockouts":0,"disabled":false,
 "numSecondaryAuthFailures":0,"lastIPFailure":"n/a","lastFailure":0}
```

after three failed password grants against one user in a realm with
`bruteForceProtected` on:

```
{"failedLoginNotBefore":1788527963,"numFailures":2,"numTemporaryLockouts":0,"disabled":true,
 "numSecondaryAuthFailures":0,"lastIPFailure":"172.17.0.1","lastFailure":1788527903483}
```

So it is **a row per (realm, user) written by the login path**, not a counter
and not a table this API can write. Six of its seven values move, and every one
of them is set by a failed *authentication*: the two `DELETE`s are the only
writes the Admin API has, and both only ever clear.

**Gloak has no brute-force detector.** `bruteForceProtected` and the eleven
tuning fields beside it are served in the realm representation and nothing reads
them; no code path anywhere in the tree counts a failed login. The zero record
above is therefore not a default this cut chooses - it is **the only state Gloak
can reach**, for every request the Admin API or the conformance harness can
send.

That decides the cut's shape, and the answer is neither a table nor a counter:

- The `GET` serves the seven-key zero record. It is byte-exact for every input
  Gloak can be given, and it is measured to be what Keycloak answers for **a
  user id that does not exist** as well as for a clean one - see §3.1 - so there
  is no 404 branch to get wrong either.
- Both `DELETE`s are 204 and clear nothing, which is what Keycloak answers for a
  user with no record and for an unknown id alike.
- **No migration, no table, no `model` type.** A column nothing writes is a
  claim about the model that is not true, and it is the storage equivalent of
  the inert masks AGENTS.md removed 116 of. The table arrives with the detector
  that fills it. Filed as F157.

The one thing that is stored is therefore the guard's shape, and that is
measured rather than assumed - §3.1.

## 3. The measurements this cut is built on

All against `quay.io/keycloak/keycloak:26.7.1` on port 8165, 2026-09-03, with
the destructive half in created realms `probe-small`, `probe-comp` and
`probe-keys`.

### 3.1 The three guards, swept one role at a time

Nine callers, each holding exactly one `realm-management` client role in the
realm under test, plus one holding none.

```
route                                        none  view-r manage-r view-u manage-u query-u view-c manage-c realm-admin
GET  attack-detection/brute-force/users/{id}  403    403     403     200     200     403    403     403      200
DEL  attack-detection/brute-force/users/{id}  403    403     403     403     204     403    403     403      204
DEL  attack-detection/brute-force/users       403    403     403     403     204     403    403     403      204
GET  clients-initial-access                   403    403     403     403     403     403    200     200      200
POST clients-initial-access                   403    403     403     403     403     403    403     201      201
DEL  clients-initial-access/{id}              403    403     403     403     403     403    403     204      204
GET  components                               403    200     200     403     403     403    403     403      200
GET  components/{id}                          403    200     200     403     403     403    403     403      200
GET  components/{id}/sub-component-types      403    200     200     403     403     403    403     403      200
POST components                               403    403     201     403     403     403    403     403      201
PUT  components/{id}                          403    403     204     403     403     403    403     403      204
DEL  components/{id}                          403    403     204     403     403     403    403     403      204
```

Three chapters, three different role pairs:

- **`Attack Detection` is authorised out of the *users* pair**, and it is the
  role-mapping family's shape exactly: the read takes `view-users` **or**
  `manage-users`, the writes take `manage-users` alone, and `query-users` -
  which opens `GET /users` - opens neither. Nothing in the path or the tag says
  "users".
- **`Client Initial Access` is authorised out of the *clients* pair**, read
  `view-clients`/`manage-clients`, write `manage-clients` alone. `view-realm`
  and `manage-realm` are 403 on all three, which is the client-scope family's
  answer and not this path's neighbourhood: `/clients-initial-access` sits
  beside `/clients`, and its tokens register clients, so the pair is at least
  predictable here - unlike `default-default-client-scopes`.
- **`Component` is the realm pair**, confirming what AGENTS.md already records,
  and the four new operations answer it identically to the two served ones.

### 3.2 Resolution order, measured with an unknown id per route

```
caller        route                                  answer
none          GET/PUT/DELETE components/nope         403 {"error":"HTTP 403 Forbidden"}
view-realm    GET    components/nope                 404 {"error":"Could not find component"}
view-realm    PUT    components/nope                 403
view-realm    DELETE components/nope                 403
manage-realm  GET/PUT/DELETE components/nope         404 {"error":"Could not find component"}
```

The role is judged first and the component second, per verb - which is what
AGENTS.md's `Component` bullet already says for the identity provider family's
neighbour, now measured on the two verbs that did not exist when it was written.

### 3.3 `sub-component-types` is a constant of the version

`GET .../components/{id}/sub-component-types?type=X` for the 18 provider types
`GET /admin/serverinfo` lists:

```
type                                             entries  properties  bytes
org.keycloak.keys.KeyProvider                         10          56  12488
...clientregistration.policy.ClientRegistrationPolicy  8           8   4210
org.keycloak.storage.UserStorageProvider               2          42   4868
org.keycloak.storage.ldap.mappers.LDAPStorageMapper   12          61  25921
org.keycloak.userprofile.UserProfileProvider           1           1    163
the other thirteen                                     0           0      2   ([])
```

33 entries, 168 properties, 47650 bytes. **Byte-identical across three different
parent components, two realms and two container starts**, which is what makes a
table the right shape and lets the golden assert the array in order rather than
masking it.

The parent is read only to decide whether the request is a 404:

```
unknown parent id           404 {"error":"Could not find parent component"}
the realm's own id          404 {"error":"Could not find parent component"}
no ?type= at all            400 {"error":"must specify a subtype"}
?type=                      400 {"error":"must specify a subtype"}
?type=bogus                 500 unknown_error
?type=a&type=b              the first value wins
```

The entry shape is `{id, helpText, properties, metadata}` where `metadata` is
`{}` on all 33 and `helpText` is **absent** on `declarative-user-profile` alone.
The property shape is `ProviderProperty`'s, already in `internal/model`, with
`label` and `helpText` **absent** on that same one property - the identity
provider tables have no such row, so the two fields need `omitempty` that the
existing serialiser does not give them.

### 3.4 `POST /components`

```
201  Location: .../components/<id>, empty body, content-length: 0, no Cache-Control
```

- The config is **filtered to the provider's declared properties**; an
  undeclared key is dropped silently.
- **The body's `id` wins** and goes into `Location` - `POST /clients`' rule, and
  a second create naming a taken id is
  `409 {"error":"conflict","error_description":"Duplicate resource error"}`
  carrying **none of the five security headers**.
- A **duplicate `name` is a 201**: components have no name uniqueness at all.
- An absent `parentId` **defaults to the realm's own id**; a `parentId` naming
  nothing is a 201 and is stored raw.
- An absent `name` is a 201 and the row reads back with no `name` key; an absent
  `subType` likewise; an absent `config` reads back `{}`.
- The strict decoder reports a line and column:
  `Invalid json representation for ComponentRepresentation. Unrecognized field "zz" at line 1 column 169.`
- An empty body is a 500, `{` is `invalid_request`/`Cannot parse the JSON`, and
  `{}` is `400 {"error":"Invalid provider type or no such provider"}`.

The provider sweep over the 33 entries of §3.3:

```
201  18   KeyProvider 7, ClientRegistrationPolicy 6, LDAPStorageMapper 3,
          UserStorageProvider 1, UserProfileProvider 1
400  15   {"errorMessage": ...}, one sentence per provider
```

and, over the 13 provider types `sub-component-types` answers `[]` for:

```
403  the two Workflow types  {"error":"Components managed through internal APIs
                              cannot be managed through the component endpoint"}
500  the other eleven        unknown_error
400  an unknown providerId   {"error":"Invalid provider type or no such provider"}
400  an unknown providerType {"error":"Invalid provider type or no such provider"}
```

### 3.5 The refusals are a message bundle, not the catalogue

**The `required` flag in the catalogue is not the validator**, and the sentence
interpolates a label the catalogue does not carry: the property serves
`"label":"max-clients.label"` and the refusal says
`'Max Clients Per Realm' is required`. Twelve of the fifteen refusals name no
catalogue label at all.

The refusals are also a **sequence** rather than a set, and the tail of each
sequence leaves what this project can reach:

```
max-clients     'Max Clients Per Realm' is required
                'Max Clients Per Realm' should be a number          (max-clients=4.5)
                'Max Clients Per Realm' should be a single entry    (two array entries)
trusted-hosts   'Host Sending Client Registration Request Must Match' is required
                'Client URIs Must Match' is required
                '<either>' should be 'true' or 'false'              (and "TRUE" is refused)
java-keystore   'Keystore' is required -> 'Keystore Password' -> 'Key Alias' -> 'Key Password'
                then Failed to load keys. File not found on server. ...
rsa / rsa-enc   'Private RSA Key' is required  then  Failed to decode private key
ldap            Edit Mode is mandatory  then, for five more keys,
                {"error":"Invalid provider type or no such provider"} - the same
                sentence an unknown provider gets, for a provider that exists
nine LDAP mappers   one sentence each, then a second, then a real LDAP connection
every key provider  'Priority' should be a number
                    'Key size' should be 1024, 2048, 3072 or 4096
                    'Secret size' should be 16, 24, 32, 64, 128, 256 or 512
```

**This cut reproduces the first refusal of each of the fifteen, plus the value
validators above, and stops there.** What is past that line needs a real LDAP
server, a PEM private key parser and a keystore file, which is Keycloak's
provider implementations rather than a table. Filed as F158.

### 3.6 `PUT /components/{id}`

- **204, and it writes the *path's* component**, not the body's: a PUT addressed
  to one real component and carrying another real component's `id` changed the
  addressed one and left the other exactly as it was. That is the **opposite**
  of `PUT .../protocol-mappers/models/{id}` and of
  `PUT .../identity-provider/instances/{alias}/mappers/{id}`, both of which
  write the body's.
- **The config merges and is re-filtered.** A PUT naming
  `{priority, junk, algorithm}` on a component holding
  `{keySize, priority, algorithm}` left `keySize`, dropped `junk` and moved the
  other two. `{"config":{}}` and an absent `config` **change nothing**, so the
  config cannot be cleared through this endpoint at all.
- **Changing `providerId` re-filters against the new provider**: moving to
  `hmac-generated`, which does not declare `keySize`, dropped that key.
- **`providerId` and `providerType` are both required in the body**; either one
  alone is a `500 unknown_error`, and so are `{}` and an empty body. `{` is
  `invalid_request`. An unknown field is the 400 strict decode **before** the
  path's id is resolved, so a PUT to a component that does not exist carrying an
  unknown field answers 400 and one carrying a good body answers
  `404 {"error":"Could not find component"}` - which AGENTS.md already records.
- Two of Keycloak's own defects on this route, measured and **not** reproduced:
  a body carrying a `config` and no `providerId` **writes the config and then
  answers 500**, and a PUT naming an unknown `providerId` writes it and leaves
  the component unreadable for ever - `GET /components/{id}` on it is a 500.
  Filed as F159.

### 3.7 `DELETE /components/{id}` and F145

204, no `Cache-Control`, `X-Frame-Options` only when the request declared an
`application/*` `Content-Type` - rule (3) of AGENTS.md's header bullet,
confirmed on both this delete and the two `attack-detection` ones. A second
delete of the same id is `404 {"error":"Could not find component"}`.

The measurement F145 did not have:

```
GET /admin/realms/{r}/keys      keys[].providerId   f6cd89b4  85bc7abd  7fae871c  8a07527a
GET /admin/realms/{r}/components?type=…KeyProvider  id        f6cd89b4  85bc7abd  7fae871c  8a07527a
```

**A key's `providerId` *is* the key-provider component's id**, one to one on all
four, so the two are not merely unwired - they are the same value under two
names. And deleting the component removes the key from `GET /keys` **and** from
the JWKS: deleting `rsa-enc-generated` left three keys and a one-key JWKS,
deleting `rsa-generated` left three keys and a JWKS holding only the enc key.

F145's argument therefore holds - but it is **symmetric with `POST`**, which
this cut builds: creating an `rsa-generated` component in Keycloak adds a key,
and Gloak's `GET /keys` would not see it either. Blocking the delete on that
argument blocks the create on the same one. See §6 for the disposition.

### 3.8 `Client Initial Access`

```
POST 201  Location .../clients-initial-access/<uuid>, no Cache-Control
{"id":"…","token":"eyJ…","timestamp":1788528086,"expiration":0,"count":1,"remainingCount":1}
GET  200  [{"id":"…","timestamp":…,"expiration":…,"count":…,"remainingCount":…}, …]
```

- **The `token` is on the create and nowhere else.** Six keys on the 201, five
  in the listing. One resource, two serialisations, and the one that is missing
  is the only thing the resource is for.
- **The request shape is not the response shape.** The decoder is
  `ClientInitialAccessCreatePresentation`, which has `count` and `expiration`
  and nothing else: `{"id":…}`, `{"token":…}`, `{"timestamp":…}` and
  `{"remainingCount":…}` are each
  `400 Invalid json representation for ClientInitialAccessCreatePresentation. Unrecognized field "…" at line 1 column N.`
  Four of the six keys the response carries are refused on the way in.
- `{}` is a 201 with `count: 1`, `expiration: 0`. `{"count":0}` is a 201 that
  can never be used. A negative `count` and a negative `expiration` are two
  distinct 400s in the RFC 6749 shape:
  `{"error":"Invalid value for count","error_description":"The count cannot be less than 0"}`
  and
  `{"error":"Invalid value for expiration","error_description":"The expiration time interval cannot be less than 0"}`.
- An empty body is a 500, `{` is `invalid_request`/`Cannot parse the JSON`.
- **`DELETE` of an id that does not exist is a 204**, and so is deleting the
  same one twice. The chapter adds no spelling of not-found.
- The listing is **insertion order**, measured on two containers with three rows
  each and two reads apiece; the ids are random UUIDs and did not sort, so the
  order can be asserted rather than masked.
- The token is HS512 with the realm's HMAC kid and the payload
  `{"exp","iat","jti","iss","aud","typ"}`, `typ` = `InitialAccessToken`, `aud`
  = `iss`, and **`exp` is the literal 0** when `expiration` is 0. `jti` is the
  row's id. It really registers clients: `remainingCount` decrements per use,
  the exhausted row **stays in the listing** at 0, and a further use is
  `{"error":"invalid_token","error_description":"No remaining count on initial access token"}`.

## 4. What this cut builds

### 4.1 `internal/model`

- `ClientInitialAccess` - id, realm, timestamp, expiration, count,
  remainingCount.
- `componentcatalogue.go` plus a generated `componentcatalogue_data.go`: the 33
  entries of §3.3, keyed `providerType -> []ComponentTypeEntry`, reusing
  `ProviderProperty`. `ProviderProperty` gains nothing; the two `omitempty`
  cases live in the serialiser.
- `componentvalidation.go`: the fifteen first-refusal rules and the value
  validators of §3.5, as a table.

### 4.2 `internal/store`

`ClientInitialAccessRepo` - `Create`, `List`, `Delete`. Migration `0028_*` in
both drivers, one table. `ComponentRepo` gains `Update` and `Delete`.

### 4.3 `internal/admin`

- `attackdetection.go` - three handlers, no store.
- `clientinitialaccess.go` - three handlers, the HS512 mint.
- `components.go` - `POST`, `PUT`, `DELETE`.
- `subcomponenttypes.go` - the catalogue serialiser.
- routes and guards in `router.go`.

The mint is in `internal/admin` and not in `internal/token`, which this branch
may not touch. Filed as F160 with the registration-side half.

### 4.4 `internal/conformance`

New cases appended at the very end of `adminCases`, new fixtures at the very end
of `fixture.go`, goldens under `testdata/golden/admin/{attack-detection,
client-initial-access,component}/`.

## 5. Order of work

1. The catalogue generator and `internal/model` (no behaviour).
2. Migration 0028 and the store in both drivers.
3. `attack-detection` - the cheapest chapter, and it proves the guard shape.
4. `client-initial-access`.
5. The three component writes and `sub-component-types`.
6. Record, then the mutation pass, then `make lint` and the Postgres suite.

## 6. Follow-up dispositions

- **F145** - disagreed with, on a measurement it did not have. §3.7.
- **F155** - not taken. §7.
- **F134** - unmoved and re-confirmed: `/components` ignores its bounds, and
  `sub-component-types` has no bounds to ignore.
- **F95** - untouched, deliberately. It lives in `clients.go`.
- New: **F157** the brute-force detector, **F158** the deep provider
  validators, **F159** two `PUT /components/{id}` defects not reproduced,
  **F160** the initial access token is minted in `internal/admin` and its own
  registration endpoint refuses it.

## 7. What this cut does not take, and why

- **`admin/client-attribute-certificate`, all seven.** §1.4.
- **F155's `Accept` sweep.** It is one predicate over the whole API and it moves
  every chapter's goldens at once; a family cut is the wrong branch for it, and
  F155 says so itself.
- **Wiring `GET /keys` to the components table.** It is inside `keys.go`, which
  this branch owns, and it would re-record `admin/key`'s golden - but the other
  half of the same behaviour is the JWKS, which lives in `internal/oidc`, which
  this branch may not touch. Half of it is worse than none: `/keys` losing a key
  the JWKS still publishes is a state Keycloak cannot reach either. F145 stays
  open with the measurement in it.
