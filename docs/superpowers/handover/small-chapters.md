# Three small chapters and the component remainder

Branch: `feat/small-chapters`
Date: 2026-09-03
Reference: `quay.io/keycloak/keycloak:26.7.1`, container `kc-small` on port 8165,
removed at the end. The destructive half ran in created realms - `probe-small`,
`probe-comp`, `probe-keys`, `probe-409*`, `probe-gr*` - because a second
`declarative-user-profile` breaks every login in whatever realm it lands in, and
the provider sweep of §1.4 creates one deliberately.

Ten operations. `admin/attack-detection` 3, `admin/client-initial-access` 3, and
the four `admin/component` had left.

---

## 1. Measurements

### 1.0 The count, and what `attack-detection` stores

```
chapter                              served before  documented  unserved before
admin/attack-detection                           0           3                3
admin/client-initial-access                      0           3                3
admin/component                                  2           6                4
admin/client-attribute-certificate               0           7                7
```

Computed from the vendored description and the catalogue, not from the brief;
the brief's four numbers were all correct this time.

**`attack-detection` stores a row per (realm, user) written by the login path**,
and it is neither a table this cut wants nor a counter:

```
GET .../attack-detection/brute-force/users/{id}      200 application/json;charset=UTF-8
                                                     Cache-Control: no-cache, all five headers
{"failedLoginNotBefore":0,"numFailures":0,"numTemporaryLockouts":0,"disabled":false,
 "numSecondaryAuthFailures":0,"lastIPFailure":"n/a","lastFailure":0}
```

and after three failed password grants at one user in a realm with
`bruteForceProtected` on:

```
{"failedLoginNotBefore":1788527963,"numFailures":2,"numTemporaryLockouts":0,"disabled":true,
 "numSecondaryAuthFailures":0,"lastIPFailure":"172.17.0.1","lastFailure":1788527903483}
```

Six of the seven values move and every one is set by a failed *authentication*.
**Gloak has no brute-force detector** - `bruteForceProtected` and its eleven
tuning fields are served in the realm representation and nothing reads them - so
the zero record is the only state Gloak can reach, and it is byte-exact for
every request the Admin API can be given. **No migration, no table, no model
type**: a column nothing writes is a claim about the model that is not true.
Filed as F157.

Three further measurements decide the shape:

- **The read never 404s.** A user id that names nothing, and the realm's own id,
  answer the same zero record a real user does. So the route does not resolve
  the user at all, and the lookup anybody would add "to be safe" invents a
  status Keycloak does not send.
- **Both deletes are 204 for an id that never existed**, so neither has a
  not-found branch either.
- **The key order is `javamap.KeyOrder`'s** over the seven names, which returns
  `failedLoginNotBefore, numFailures, numTemporaryLockouts, disabled,
  numSecondaryAuthFailures, lastIPFailure, lastFailure` - the measured body byte
  for byte. It is the fifteenth measured key set for that function and it
  discriminates nothing: no bucket collides and `SizedKeyOrder` agrees, so it is
  recorded here rather than added as a vector.
- **The two time fields are in different units on one body.**
  `failedLoginNotBefore` is seconds and `lastFailure` is milliseconds -
  1788527963 against 1788527903483, the same instant plus the sixty-second
  quick-login wait. One clock helper for both is wrong by a factor of a thousand
  on one of them.

### 1.1 The three guards, one role at a time

Nine callers, each holding exactly one `realm-management` role in the realm
under test, plus one holding none.

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

**Three chapters, three different role pairs, and the description's tag predicts
none of them.**

- **`Attack Detection` is authorised out of the *users* pair**, and it is the
  role-mapping family's shape exactly: view **or** manage on the read, manage
  alone on the writes, and `query-users` - which opens `GET /users` - opens
  neither. Nothing in the path or the tag says users.
- **`Client Initial Access` is the *clients* pair**, read
  `view-clients`/`manage-clients`, write `manage-clients` alone. `view-realm`
  and `manage-realm` are 403 on all three.
- **`Component` is the *realm* pair**, which the two served reads already
  record; the four new operations answer it identically, so the family's
  read/write split lives inside one pair rather than across two.

The resolution order, with an unknown id per route:

```
none          GET/PUT/DELETE components/nope   403 {"error":"HTTP 403 Forbidden"}
view-realm    GET    components/nope           404 {"error":"Could not find component"}
view-realm    PUT/DELETE components/nope       403
manage-realm  GET/PUT/DELETE components/nope   404 {"error":"Could not find component"}
```

The role is judged first and the component second, per verb - which extends what
AGENTS.md already records for this family to the two verbs that did not exist
when it was written.

### 1.2 `sub-component-types` is a constant of the version

`GET .../components/{id}/sub-component-types?type=X`, over the eighteen provider
types `GET /admin/serverinfo` registers:

```
type                                                   entries  properties  bytes
org.keycloak.keys.KeyProvider                               10          56  12488
...clientregistration.policy.ClientRegistrationPolicy        8           8   4210
org.keycloak.storage.UserStorageProvider                     2          42   4868
org.keycloak.storage.ldap.mappers.LDAPStorageMapper         12          61  25921
org.keycloak.userprofile.UserProfileProvider                 1           1    163
the other thirteen                                           0           0      2   ([])
```

33 entries, 168 properties, 47650 bytes. **Byte-identical across three different
parent components, two realms and two container starts** - 25 comparisons - so
the array is asserted in order rather than masked, and the table is right for it
in the way the identity provider tables are.

The parent is read only to decide whether the request is a 404:

```
no ?type= at all, or ?type=              400 {"error":"must specify a subtype"}
a parent id that resolves to nothing     404 {"error":"Could not find parent component"}
the realm's own id as the parent         404 the same
?type=bogus, and any name upper-cased    500 unknown_error
?type=a&type=b                           the first value wins
```

The missing-type 400 beats the parent's 404, measured with a request wrong both
ways.

Two shapes inside the body:

- **The entry's `helpText` has three states, not two.** Thirty of the
  thirty-three carry a sentence, **`ldap` and `kerberos` carry the empty
  string**, and `declarative-user-profile` has no `helpText` key at all. A
  string with `omitempty` loses two real values; one without loses the third
  state.
- **36 of the 168 properties carry neither a `label` nor a `helpText`** - all 35
  of `ldap`'s and `declarative-user-profile`'s one - where every property of the
  two identity provider tables carries both. No property here carries an
  empty-string one, so `omitempty` is exact for these and would be a guess on
  the shared struct.
- **`metadata` is not always `{}`.** Thirteen entries carry a small Java map,
  and `group-ldap-mapper`'s four keys come back
  `fedToKeycloakSyncSupported, keycloakToFedSyncSupported,
  fedToKeycloakSyncMessage, keycloakToFedSyncMessage` - which sorting reverses,
  so it needs a marshaller of its own.

### 1.3 `POST /components`

```
201  Location: .../components/<id>, empty body, content-length: 0, no Cache-Control
```

- **The config is filtered to the provider's declared properties**, an
  undeclared key dropped silently, and the survivors come back in
  `javamap.KeyOrder`: a create sending `priority, zzzUndeclared, keySize,
  algorithm` reads back `keySize, priority, algorithm`.
- **The body's `id` wins** and goes into `Location` - `POST /clients`' rule - and
  a create naming a taken id is
  `409 {"error":"conflict","error_description":"Duplicate resource error"}`.
- **A duplicate `name` is a 201.** This family has no name uniqueness at all,
  which is how a default realm holds two rows called `Allowed Client Scopes`.
- **An absent `parentId` defaults to the realm's own id**; a `parentId` naming
  nothing is a 201 and is stored raw.
- An absent `name` is a 201 reading back with no `name` key, an absent `subType`
  likewise, an absent `config` reads back `{}`.
- Strict decoder: `Invalid json representation for ComponentRepresentation.
  Unrecognized field "zz" at line 1 column 169.`
- An empty body and a literal `null` are 500s; `{` is
  `invalid_request`/`Cannot parse the JSON` and `[` is the same sentence with
  `unknown_error`; `{}` is the provider 400; `text/plain` is 415 and an absent
  `Content-Type` is accepted.

### 1.4 The three provider refusals are decided by the *pair*

Swept over all 245 `(providerType, providerId)` pairs `GET /admin/serverinfo`
registers, and over all eighteen types with a provider id nobody registers:

```
201  18   the five types sub-component-types answers non-empty for
400  15   {"errorMessage": ...}, one sentence per provider
400       {"error":"Invalid provider type or no such provider"} - for an unknown
          providerId under a **known** type, for a known id under an unknown
          type, and for a known id under the **wrong** known type
403       the two Workflow types, for a provider they really register
500       any other registered pair - `oidc-sub-mapper` under ProtocolMapper,
          `length` under Validator, `oidc` under IdentityProvider
```

So the sentence "Invalid provider type or no such provider" is about the pair
and not about either half, whatever its wording suggests - and **only a registry
of all 245 pairs tells the three answers apart.** A handler holding just the 33
providers with declared properties answers 400 where Keycloak answers 403 and
500, on 212 pairs.

### 1.5 The config refusals are a message bundle and a sequence

**The catalogue's `required` flag is not the validator**: fifteen of the
thirty-three providers refuse a bare create and only eight of those declare a
required property. **And the sentence interpolates a label the catalogue does
not carry** - the property serves `"label":"max-clients.label"` and the refusal
says `'Max Clients Per Realm'`.

**The rules run in the provider's declared property order**, measured with
requests wrong in two ways at once: a `rsa` create carrying a bad `priority` and
no private key answers about the priority; `rsa-generated` with a bad `priority`
and a bad `keySize` answers about the priority; `enabled` beats `active`;
`java-keystore` with a bad `priority` and a valid `keystore` answers about the
priority. `priority`, `enabled` and `active` are the first three properties
every key provider declares.

Three value validators beside the presence ones, each measured:

```
'Priority' should be a number                                  ("" passes, "-3" passes)
'Max Clients Per Realm' should be a number                     ("" and absent are the required 400)
'Max Clients Per Realm' should be a single entry               (a two-element array)
'Enabled' / 'Active' / the two trusted-hosts booleans
                       should be 'true' or 'false'             ("TRUE" is refused)
'Key size' should be 1024, 2048, 3072 or 4096
'Secret size' should be 16, 24, 32, 64, 128, 256 or 512
'Elliptic Curve' should be P-256, P-384 or P-521 / Ed25519 or Ed448
```

The two-element list is what says there is no comma before the `or`.
`{"algorithm":["nope"]}` on a key provider is a **201**, so the `options` array
is not a validator on every typed property, and `allow-default-scopes` on a
policy takes any value at all.

**Past the first refusal the sequence needs things this project cannot have.**
`java-keystore` walks `'Keystore'` → `'Keystore Password'` → `'Key Alias'` →
`'Key Password'` and then wants a file on disk; `rsa` wants a PEM it can decode;
`ldap` and its nine refusing mappers want a real directory; and `ldap` with a
partial config answers `{"error":"Invalid provider type or no such provider"}` -
the unknown-provider sentence, for a provider that plainly exists. This cut
reproduces **the first refusal of each of the fifteen** plus the value
validators, and stops there. F158.

### 1.6 `PUT /components/{id}`

- **It writes the component the *path* names.** A PUT addressed to one real
  component and carrying another real component's `id` changed the addressed one
  and left the other exactly as it was - the **opposite** of
  `PUT .../protocol-mappers/models/{id}` and of
  `PUT .../identity-provider/instances/{alias}/mappers/{id}`, which both write
  the body's. Three routes that look alike, two answers.
- **The config merges and is then re-filtered against the body's `providerId`.**
  `{priority, junk, algorithm}` over `{keySize, priority, algorithm}` left
  `keySize`, dropped `junk` and moved the other two; moving the row to
  `hmac-generated`, which does not declare `keySize`, dropped that key. So
  `{"config":{}}` and an absent `config` change nothing and **the config cannot
  be cleared through this endpoint at all**.
- **`providerId` and `providerType` are both required in the body**: either
  alone is a 500, and so are `{}`, an empty body and `null`. The strict decode
  runs **before** the path's id is resolved.
- 204 with no `Cache-Control`, `X-Frame-Options` present because the request
  declares `application/json`.

### 1.7 `DELETE /components/{id}`, and what F145 did not have

204, no `Cache-Control`, `X-Frame-Options` only when the request declared an
`application/*` `Content-Type`. **A second delete of the same id is a 404**,
where a second delete of an initial access token one route family away is a 204.

```
GET /admin/realms/{r}/keys      keys[].providerId   f6cd89b4  85bc7abd  7fae871c  8a07527a
GET .../components?type=…KeyProvider  id            f6cd89b4  85bc7abd  7fae871c  8a07527a
```

**A key's `providerId` *is* its key-provider component's id**, one to one on all
four - so the two are not merely unwired, they are one value under two names.
And the delete is observable on both endpoints: deleting `rsa-enc-generated`
left `GET /keys` with three keys and the JWKS with one, and deleting
`rsa-generated` left three keys and a JWKS holding only the encryption key. The
realm still issued tokens either way.

### 1.8 `Client Initial Access`

```
POST 201  Location .../clients-initial-access/<uuid>, no Cache-Control
{"id":"…","token":"eyJ…","timestamp":1788528086,"expiration":0,"count":1,"remainingCount":1}
GET  200  [{"id":…,"timestamp":…,"expiration":…,"count":…,"remainingCount":…}, …]
```

- **The `token` is on the create and nowhere else.** Six keys on the 201 and
  five in the listing, and the missing one is the only thing the resource is
  for.
- **The request shape is not the response shape.** The decoder is
  `ClientInitialAccessCreatePresentation`, which declares `count` and
  `expiration` and nothing else: `id`, `token`, `timestamp` and `remainingCount`
  are each `400 … Unrecognized field "…" at line 1 column N.` Four of the six
  keys the 201 serves are refused on the way in, so a caller cannot round-trip a
  row.
- `{}` is a 201 with `count: 1`, `expiration: 0`. `{"count":0}` is a 201
  creating a token that can never be used, so the count check is a **sign** test.
  A negative count and a negative expiration are two distinct 400s in the RFC
  6749 shape, and their descriptions differ in more than the field name - "The
  count cannot be less than 0" against "The expiration time interval cannot be
  less than 0".
- **`DELETE` of an id that never existed is a 204**, and so is deleting the same
  one twice. This chapter adds no spelling of not-found.
- **The listing is insertion order**, measured on two containers with three rows
  each and two reads apiece, with ids that are random UUIDs and do not sort that
  way.
- **No `Cache-Control` on any 2xx of the family**, listing and creates alike,
  where nearly every other Admin API read sends `no-cache`. This is the one my
  hand probe had transcribed wrong and the recorded golden refuted; see §5.
- The token is HS512 with the realm's HMAC kid over
  `{exp, iat, jti, iss, aud, typ}`, `typ` = `InitialAccessToken`, `aud` = `iss`,
  `jti` = the row's id, and **`exp` is the literal 0** when `expiration` is 0.
  It really registers clients: `remainingCount` decrements per use, the
  exhausted row **stays in the listing** at 0, and a further use is
  `{"error":"invalid_token","error_description":"No remaining count on initial
  access token"}`.

### 1.9 `admin/client-attribute-certificate` is not in this cut

Seven operations, and two things the tag's name does not say, both read off the
description:

- **The seventh is not under `/clients`.**
  `POST /admin/realms/{realm}/identity-provider/upload-certificate` carries this
  tag and lives one path segment from the identity provider family. A cut scoped
  by path takes six and reports seven.
- **Two of the seven answer a binary keystore** - `.../download` and
  `.../generate-and-download` return JKS or PKCS12 bytes chosen by a `format`
  field - and three are `multipart/form-data` uploads. **No golden in this
  repository holds a non-text body**, and none of the harness's masks reaches
  bytes that are not JSON or HTML. A generated keystore also differs on every
  request, so even a byte-holding golden could assert nothing but a length.

It is a decision about the harness before it is seven handlers, and it is left
where it is.

### 1.10 The `Duplicate resource error` split, measured moving

This is the sharpest thing the cut found and it bears directly on F147.

A hand probe of `POST /components` with a taken id recorded the 409 carrying
**none** of the five security headers. The recorded golden of the same shape
carried **all five**. Both were right:

```
four identical duplicate-id creates against an untouched row, probe-409a
   none of five, all five, all five, all five
the same four in a second fresh realm, probe-409b
   none of five, all five, all five, all five
twenty repeats after the first, probe-409
   all five, twenty times
```

**The same request answers both ways, and which way is decided by whether that
failure has happened before.** Nothing about the request or the response
distinguishes them, which is what F147 already says; what is new is that the
request does not even have to change. A first sweep also fitted "a row this run
created against an untouched one", and a fifth probe refuted it - and that probe
is confounded, because a component id is unique across realms and the second
realm's create of the same id was itself a collision.

The conformance fixture therefore performs one collision itself, so the case's
own request is never the first occurrence and the golden is reproducible.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, to be folded by hand.

- **A brute-force status is 200 for a user that does not exist**, with the same
  seven-key zero record a real user with no failures gets - and so is the realm's
  own id. The route does not resolve the user at all, so the 404 anybody would
  add here is a status Keycloak does not send. Both `DELETE`s answer 204 for the
  same unknown id, so the whole `Attack Detection` tag has no not-found branch.
  **Its two time fields are in different units on one body**:
  `failedLoginNotBefore` is seconds and `lastFailure` is milliseconds, measured
  as 1788527963 against 1788527903483 - the same instant plus the sixty-second
  quick-login wait. One clock helper for both is wrong by a factor of a thousand
  on one of them.
- **Three chapters landed in one branch and no two share a role pair, and the
  description's tag predicts none of them.** `Attack Detection` is authorised
  out of the **users** pair - view or manage on the read, manage alone on the
  two deletes, and `query-users`, which opens `GET /users`, opens neither -
  although nothing in its path or its tag says users. `Client Initial Access` is
  the **clients** pair. `Component` is the **realm** pair, which this file
  already records. That is the fourth, fifth and sixth time the tag has failed
  to predict the guard.
- **`POST /components` has three refusals for a provider it will not create and
  only a registry of all 245 registered pairs tells them apart.** A pair that
  does not resolve is `400 {"error":"Invalid provider type or no such
  provider"}` - **for an unknown providerId under a known type, for a known id
  under an unknown type, and for a known id under the wrong known type alike**,
  so the sentence is about the pair and not about either half. A registered
  Workflow pair is a **403** with a sentence of its own; any other registered
  pair is a **500**. Measured over every pair `GET /admin/serverinfo` lists.
- **The provider catalogue's `required` flag is not the validator, and the
  refusal names a label the catalogue does not carry.** Fifteen of the
  thirty-three component providers refuse a bare create and only eight of those
  declare a required property; `max-clients` declares its one property
  `required:false`, refuses a bare create anyway, and says `'Max Clients Per
  Realm'` where the property's own `label` is `max-clients.label`. So the
  sentences are a message bundle rather than anything the API serves. **The
  checks run in the provider's declared property order** - `priority`, `enabled`
  and `active` come first on every key provider and beat every provider-specific
  one, measured with requests wrong two ways at once - and past the first
  refusal the sequence wants a keystore file, a decodable PEM or a real LDAP
  server.
- **`PUT /components/{id}` writes the component the path names, where the two
  routes that look identical write the body's.**
  `PUT .../protocol-mappers/models/{id}` and
  `PUT .../identity-provider/instances/{alias}/mappers/{id}` both follow the
  body's `id`; this one ignores it. **Its config merges and is then re-filtered
  against the body's `providerId`**, so `{"config":{}}` and an absent `config`
  change nothing and the config cannot be cleared through the endpoint at all -
  and moving a row to a provider that declares fewer properties silently drops
  the rest. **Both `providerId` and `providerType` are required in the body**:
  either alone is a 500, and so is a body a caller would think of as a partial
  update.
- **A component's name is not unique and its id is.** A create repeating a name
  is a 201 - which is how a default realm holds two rows called `Allowed Client
  Scopes` - and a create repeating an id is the 409 `Duplicate resource error`.
  An absent `parentId` defaults to the realm's own id and a `parentId` naming
  nothing at all is a 201 that stores it raw.
- **`GET .../components/{id}/sub-component-types` is a constant of the Keycloak
  version and its parent is read only to decide the 404.** 33 entries, 168
  properties and 47650 bytes came back byte-identical through three different
  parent components, on two realms and across two container starts. Thirteen of
  the eighteen registered provider types answer `[]` and a type nobody registers
  answers a 500, so "no entries" and "no such type" are two answers rather than
  one; the comparison is case-sensitive. Its entry `helpText` has **three**
  states - absent on `declarative-user-profile`, the empty string on `ldap` and
  `kerberos`, a sentence on the other thirty - and 36 of its 168 properties
  carry neither a `label` nor a `helpText` where every property of the two
  identity provider tables carries both.
- **An initial access token is on its create and on nothing else.** `POST
  /clients-initial-access` answers six keys and the listing beside it answers
  five, because the token is minted once and never stored - so the one thing the
  resource exists for is the one thing only the 201 carries. **The request shape
  is not the response shape either**: the create decodes
  `ClientInitialAccessCreatePresentation`, which has `count` and `expiration`
  alone, and refuses `id`, `token`, `timestamp` and `remainingCount` with the
  strict decoder's 400 - so a caller cannot round-trip a row. `{"count":0}` is a
  201 creating a token that can never be used, which makes the count check a
  sign test; a negative count and a negative expiration are two distinct
  sentences rather than one with a substitution. **The whole family sends no
  `Cache-Control` on any 2xx**, where nearly every other Admin API read sends
  `no-cache`.
- **`DELETE /clients-initial-access/{id}` is 204 for an id that never existed
  and `DELETE /components/{id}` is 404 for one that has just gone.** Two
  neighbouring families, one verb, opposite answers to the same repeat - which
  is why the two chapters cannot share a delete helper.
- **The `Duplicate resource error` split is not a function of the request at
  all: the same request answers both ways.** Four identical duplicate-id creates
  against an untouched component answered **none of the five security headers,
  then all five, all five, all five**, and that reproduced in each of two fresh
  realms; twenty repeats after the first were all five every time. So the split
  this file and F147 leave unexplained is not something a request can be written
  to pin, and a golden that records it has to be given a fixture that has
  already made the failure once. A hand probe that saw none of the five was
  measuring its own first occurrence, which is the sixth time a probe of this
  family has measured itself.
- **A key's `providerId` in `GET /admin/realms/{realm}/keys` is its key-provider
  component's id, one to one.** This file says the two are different values and
  that Gloak derives one from the `kid`; on the server they are one value under
  two names, measured on all four key providers. Deleting the component removes
  the key from `GET /keys` **and** from the JWKS - the encryption provider's
  delete left three keys and a one-key JWKS, the signing provider's left three
  keys and a JWKS holding only the encryption key - and the realm still issues
  tokens either way. Gloak's `/keys` is not backed by that table, so its delete
  and its create both diverge on the four key-provider rows. See F145.
- **An organization group's `realmRoles` order is not reproducible, and the
  golden that pinned it was recorded from one container.** Six fresh realms
  given the same two roles in the same order answered two different orders, and
  four fresh realms given four roles answered four different orders - matching
  neither name order, assignment order, reverse assignment order, nor the role
  ids ascending or descending. The two-role sample fits "descending role id" and
  the four-role sample refutes it, which is what a coincidence over two elements
  looks like. Five goldens asserted that order until 2026-09-03 and they are
  `Unordered` now.

---

## 3. Follow-up dispositions

### F145 - disagreed with, on a measurement it did not have

F145 left `DELETE /components/{id}` unbuilt because "Gloak's `GET /keys` is not
backed by this table, so the delete would leave a realm in a state Keycloak
cannot reach". **The delete is built.** Three things say so:

1. **The premise is confirmed and sharper than the entry states.** A key's
   `providerId` *is* its component's id, one to one on all four; the delete
   removes the key from `GET /keys` and from the JWKS alike (§1.7).
2. **The argument is symmetric with `POST /components`**, which this cut builds
   and the brief asked for: creating an `rsa-generated` component in Keycloak
   adds a key that Gloak's `/keys` would not see either. An argument that blocks
   the delete blocks the create on identical grounds, so keeping one and
   building the other is incoherent.
3. **Eleven of a realm's fourteen or fifteen components have no key behind
   them**, and the delete is faithful on every one of them. Refusing the four
   that do would invent a refusal Keycloak does not have, which is the mistake
   this project has already made once with a 405.

**What is left open is the wiring, and F145 keeps it.** Half of it is inside
`internal/admin/keys.go`, which this branch owns; the other half is the JWKS,
which lives in `internal/oidc`, which it does not. Doing half is worse than
none - `/keys` losing a key the JWKS still publishes is a state Keycloak cannot
reach either - so nothing was moved and the measurement above is added to the
entry instead.

### F155 - not taken

A mismatched `Accept` is a 406 across the whole Admin API and Gloak implements
it nowhere. It is one predicate over every route and it would move every
chapter's goldens at once; a family cut is the wrong branch for it, and F155
says so itself. Nothing in this cut probed `Accept`, deliberately: F155's own
warning is that an `Accept` header is exactly what a convenience library fills
in, and the three chapters here had no reason to send one.

### F95 - untouched, deliberately

A client's `attributes` is still serialised from a Go map. It lives in
`clients.go` and moving it re-records five goldens in another chapter, which is
the argument the entry itself makes for keeping it on its own branch. **This cut
adds a sixth family that serialises a Java map from an ordered slice with a
marshaller of its own** - `componentTypeMetadata` - so the pattern F95 asks for
is now the majority by a wider margin and the client is more of a holdout than
before.

### F134 - unmoved and re-confirmed

`/components` still ignores its integer bounds outright, which is what the entry
records; `sub-component-types` has no bounds to ignore. The four listings F134
names are untouched.

### F147 - the first measurement that bears on it

See §1.10 and the header bullet in §2. The entry says "nothing about the request
or the response distinguishes the two"; what is new is that **the request does
not have to change at all**, so no probe can settle it on the wire and the
entry's own conclusion - that it needs somebody reading Keycloak's exception
paths - is strengthened rather than replaced.

### New entries to file

- **F157: `attack-detection` has no detector behind it.** The three routes serve
  the zero record because nothing in this tree counts a failed login. Every
  request the Admin API can send gets Keycloak's byte-exact answer; what is
  missing is the counter, and it belongs on the login path in `internal/oidc`
  rather than here. The table arrives with the thing that fills it.
- **F158: the component config validators stop at the first refusal.** Fifteen
  providers refuse a bare create and this cut reproduces all fifteen sentences
  plus the seven value validators. Past that, `java-keystore` wants a file,
  `rsa` a decodable PEM and `ldap` and its nine mappers a real directory - and
  `ldap` with a partial config answers the *unknown provider* sentence, which is
  its own oddity.
- **F159: two `PUT /components/{id}` defects are measured and not reproduced.**
  A body carrying a `config` and no `providerId` **writes the config and then
  answers 500**; a `PUT` naming an unknown `providerId` writes it and leaves the
  component unreadable for ever - `GET /components/{id}` on it is a 500
  afterwards. The observed document already records the first as "a 500 that has
  already written the name … not reproduced; recorded for the cut that builds
  that endpoint". This is that cut, and the decision is still not to reproduce
  it: Gloak's 500 writes nothing. Reproducing the second means storing a row
  whose read then has to fail, which is a poisoned-row mechanism this project
  has only ever built once, for the localization family, where the defect is
  reachable by an ordinary caller and the golden proves it.
- **F160: the initial access token is minted in `internal/admin` and Gloak's own
  registration endpoint refuses it.** Both halves are one boundary: this branch
  may not touch `internal/token`, where every other token in the project is
  built, nor `internal/oidc`, where `POST
  /realms/{r}/clients-registrations/openid-connect` checks the bearer's `typ`.
  So Gloak mints a faithful `InitialAccessToken` that its own registration
  endpoint answers `Invalid type of token`. On the server the token registers
  clients, `remainingCount` decrements per use and the exhausted row stays in
  the listing at 0 - all measured, none of it served. The cut that opens either
  package should take both.
- **F161: `admin/client-attribute-certificate` needs a harness decision first.**
  §1.9. Two of its seven answer a binary keystore, three take
  `multipart/form-data`, and no golden in this repository holds a non-text body.

---

## 4. Parity, before and after

```
chapter                              before        after
admin/attack-detection                0 of 3       3 of 3
admin/client-initial-access           0 of 3       3 of 3
admin/component                       2 of 6       6 of 6
admin/client-attribute-certificate    0 of 7       0 of 7   (not taken, §1.9)

total                                430 of 541   440 of 541
```

Three chapters complete, +10 operations, no chapter's denominator moved. 38 new
conformance cases, 38 new goldens, and five existing goldens re-recorded with a
mask over what the re-recording proved unstable.

---

## 5. What was fixed or decided on the branch

- **`GET /clients-initial-access` sends no `Cache-Control`, and my hand probe
  had it wrong.** The first version of the case asserted `Cache-Control` present
  because I transcribed the endpoint's header block from a probe carelessly;
  the handler used `writeAdminJSON`, which sets it. The recorded golden refuted
  both. The handler writes through `httpx.WriteJSONCharset` now and a test
  asserts the absence on the listing and the create.
- **The `create-duplicate-id` case's fixture makes the collision once.** The
  first recording of that case disagreed with my hand probe about the five
  security headers, and chasing it produced §1.10. The case would otherwise have
  recorded whichever answer its first occurrence gave.
- **Five goldens in two other chapters were re-recorded and masked.** The
  recording flipped `admin/organizations/groups-read`,
  `groups-list-full`, `admin/role-mapper/org-group-all`, `org-group-realm` and
  `org-group-realm-composite`, all in the `realmRoles` / `realmMappings` array
  the cut before this one had just made an assertion. Ten fresh realms said the
  order is not reproducible (§2); the five cases carry `Unordered` now and the
  goldens are back to the bytes `main` had, because the mask sorts both sides to
  the same order. **This is the one place I edited cases another chapter owns**,
  and it is a mask rather than a body: nothing about what those routes serve
  changed.
- **`TestInitialAccessListingIsInsertionOrder` asserted counts and not ids**,
  which made it a one-in-six coin against a driver ordering by the random UUID.
  The mutation pass is what found it - the mutation survived once and then died
  eight times in ten. It asserts the ids now and the same mutation dies ten
  times in ten.
- **The migration's columns are `created_timestamp` and `total_count`.** The
  wire spells them `timestamp` and `count`; both are keywords Postgres reads in
  more than one way, and a column name that needs quoting in one driver and not
  the other is the divergence the two-driver rule exists to prevent.

### Lines in AGENTS.md or the observed document these measurements contradict

1. **AGENTS.md's `Location` bullet lists `POST /components` among the eleven
   server-minted uuid tails** without the qualifier it gives
   `POST .../identity-provider/instances/{alias}/mappers`. Measured: the tail is
   the **body's own id when the body names one**, exactly as on `POST /clients`.
   The split "server-minted against caller-chosen" survives; the list is one
   entry short of saying so.
2. **AGENTS.md's "The body's `id` wins on create on two endpoints and loses on a
   third"** names `POST /client-scopes` and `POST /clients`. It is at least four
   now: the identity provider mapper create already does it - the file says so
   elsewhere - and `POST /components` does too.
3. **AGENTS.md's realm-keys bullet says `providerId` "is the id of the key
   *provider component*, a different value from the `kid` on every measured
   key; Gloak has no component table and derives it from the `kid` by a fixed
   hash".** The first half is right and the middle is now stale: Gloak has had a
   component table since P9, and the value `GET /keys` serves **is** that
   component's id on the server, one to one on all four. F145 carries the
   measurement.
4. **AGENTS.md's fourteen strict JSON decoders** does not name
   `POST /clients-initial-access`, which is a fifteenth and reports a line and a
   column. `POST` and `PUT /components` are already in the list and both report
   a position, which the bullet says is measured for the last four; it is
   measured for these too.
5. **AGENTS.md's `Cache-Control` bullet** - "pinned per endpoint" - gains three
   members: every 2xx of `Client Initial Access` omits it, where the two
   component reads beside them send `no-cache`.
6. **The observed document's component section says
   `PUT /components/{id}` with a partial body is "a 500 that has already written
   the name … Not reproduced; recorded for the cut that builds that
   endpoint".** This is that cut and the decision is unchanged, so the sentence
   should become a filed divergence rather than a note for a future reader.
   F159.
7. **The observed document's "The initial access token is not on the path"**
   says a fixture minting one "would have depended on
   `POST /admin/realms/{r}/clients-initial-access`, which Gloak does not serve".
   Gloak serves it now; the sentence's conclusion - that the registration
   fixtures do not need one - still holds, and the reason it holds is now F160
   rather than the route being absent.
8. **The five organization group goldens** the cut before this one recorded as
   an order assertion. §2's last bullet and §5.

---

## 6. The mutation pass

Twenty-three mutations, one per claim, each reverted and each revert verified
with `git diff --quiet` on the file. Twenty-two killed the test named beside
them. One survived and was a finding about the test rather than about the code:

```
the zero record's lastIPFailure                 killed  TestBruteForceStatusIsTheSameForEveryUser
the brute-force key order                       killed  TestBruteForceKeyOrderIsTheJavaMapOrder
the brute-force read guard                      killed  TestBruteForceGuardIsTheUsersPair
the token is only on the create                 killed  TestInitialAccessTokenIsOnTheCreateAndNowhereElse
exp is the literal zero                         killed  TestInitialAccessTokenClaims
count zero is accepted                          killed  TestInitialAccessCreateRefusals
the listing sends no Cache-Control              killed  TestInitialAccessSends2xxWithNoCacheControl
the listing is insertion order                  SURVIVED, then fixed - see below
the create filters the config                   killed  TestComponentCreateFiltersTheConfig…
the create honours the body id                  killed  TestComponentCreateFiltersTheConfig…
an absent parentId defaults to the realm        killed  TestComponentCreateDefaultsAndOmissions
the PUT writes the path's component             killed  TestComponentUpdateWritesThePathsComponent
the PUT merges the config                       killed  TestComponentUpdateMergesAndRefilters
the PUT needs both provider fields              killed  TestComponentUpdateNeedsBothProviderFields
the delete reports a missing row                killed  TestComponentDeleteRepeatIs404
the three create outcomes                       killed  TestComponentCreateOutcomes
the option list has no comma before or          killed  TestComponentRuleSentences
an empty value passes the number check          killed  TestComponentRuleSentences
the key providers' common rules run first       killed  TestComponentConfigRulesRunInDeclared…
the whole sub-component-types array             killed  TestConformance
the entry helpText pointer                      killed  TestConformance
the property label omitempty                    killed  TestConformance
the metadata key order                          killed  TestConformance
```

**The survivor.** Swapping `ORDER BY ordinal` for `ORDER BY id` in the sqlite
driver's initial-access listing did not fail
`TestInitialAccessListingIsInsertionOrder`. Run ten times under the same
mutation it failed eight, because the test asserted the three rows' **counts**
and a random UUID order matches the right permutation one time in six. The
store suite killed it ten times in ten, since it asserts the ids. The admin test
asserts the ids now and the mutation dies every time.

`internal/store/storetest` exercises `ComponentRepo.Update` and `Delete` and all
three `ClientInitialAccessRepo` methods, called from `RunConformance` rather
than from the two driver tests - a second exported entry point is a thing one
driver can forget to call. Both drivers were run:
`go test -tags docker ./internal/store/postgres/ -v` is green.
