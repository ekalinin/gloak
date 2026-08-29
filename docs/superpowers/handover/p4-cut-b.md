# P4 cut B: what belongs in the documents this branch may not edit

Date: 2026-08-29
Branch: `feat/p4-cut-b`
Plan: `docs/superpowers/plans/2026-08-29-p4-cut-b.md`

Everything below was measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8086 on 2026-08-29, with
every transcript printed from the argv that was executed. This branch does not
touch `AGENTS.md`, `README.md` or the three spec documents, so what is owed to
them is written out here instead.

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

### 1.1 Realm keys - `GET /admin/realms/{realm}/keys`

200, `Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`,
the five security headers. Measured identically on `master` and on a realm
created through `POST /admin/realms`.

```
{"active":{"RSA-OAEP":"<kid>","HS512":"<kid>","RS256":"<kid>","AES":"<kid>"},
 "keys":[ ...four... ]}
```

One key entry, keys in this declared order:

```
providerId, providerPriority, kid, status, type, algorithm,
publicKey, certificate, use, validTo
```

| type | algorithm | use | publicKey / certificate / validTo | kid |
|---|---|---|---|---|
| RSA | RS256 | SIG | present | 43-char base64url |
| RSA | RSA-OAEP | ENC | present | 43-char base64url |
| OCT | HS512 | SIG | **absent** | UUID |
| OCT | AES | ENC | **absent** | UUID |

`providerPriority` is 100 and `status` is `ACTIVE` on all four. `validTo` is the
certificate's `notAfter` in milliseconds. **`use` is upper case on this endpoint
and lower case in the JWKS** for the same two keys.

**The RSA `kid` is `base64url(sha256(SubjectPublicKeyInfo))`, unpadded.** Master's
recorded `publicKey`

```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZf5VMa5NxHtHj7d7n5p6bMbsiQwg6FEW75o9QhDIGPJAXP3TUOuKyy65Ww+wHLWiF8rzj2XbZO9coUBu5wD8KTjm2/KKgne2pVcEk4XRFEcLrlrZmqmIybXDfUREbWrpVBRB1F1R6R3G89swrw7Gm10CS4qOsg/RLAD0QAVp/86LatxutvHsCGS62EK9uBoruylAdMUKk7DvLyMw2TPCd6Lc8EXkz13zNgzf+8aL/m7t7eYA4nKAgMPoG86jT7b23KvECYw0Q1yYGBcCiarHDLEkFogIejZGw7KT6+FHS7fCKsKbAPZ+wIvLcoYtEvvgasV3DRXtvuYynWm00665wIDAQAB
```

digests to its recorded `kid` `Q80zap21IG6Jjn3zecYt3iXqDNthWiPlL4dNVvQGkyw`.
**It is not the RFC 7638 JWK thumbprint**, which was computed first over the
same key and gives `RI0Cq8BR5aI1Km8s8ioVX63uTGMEWZOCfyf1NN6jy7I`. The pair is
now a vector in `internal/keys/keys_test.go`.

**`active` is a Java map and `internal/javamap` reproduces it.** Measured
`RSA-OAEP, HS512, RS256, AES` on both realms; `javamap.KeyOrder` returns exactly
that. This is its **fifth** confirmed vector and the first with no bucket
collision, so the count in the javamap package comment and in AGENTS.md moves
from four to five.

**The `keys` array is ordered by `providerId`, which is a random UUID.** master
came back `501bb07d, c64d81a4, c801ee0a, cdaa5860` and a created realm
`3a8bb3b7, 5ab0fbec, bf17f8cb, df836b05`, both ascending, with different
algorithm orders. `providerId` is the id of the key *provider component*, a
different value from the `kid` on every measured key.

Guard: `view-realm` or `manage-realm`, measured across all 22
`realm-management` roles and a caller holding none. An unknown realm is 404
`{"error":"Realm not found."}`; no token is 401.

### 1.2 Default groups

```
GET    /admin/realms/{r}/default-groups            -> 200, application/json;charset=UTF-8, no-cache
PUT    /admin/realms/{r}/default-groups/{groupId}  -> 204, Cache-Control: no-cache, no X-Frame-Options
DELETE /admin/realms/{r}/default-groups/{groupId}  -> 204, same headers
PUT|DELETE with an unknown group id                -> 404 {"error":"Group not found"}
```

The listing entry is `{"id","name","path",["parentId"],"subGroups":[]}` - the
same shape a user's group listing sends. **No `subGroupCount`, no `attributes`,
no `access`**, and `briefRepresentation=false` gives a byte-identical body.

`PUT` is idempotent (204 twice, one entry). `DELETE` of a group that is not a
default group is 204, not 404. Deleting the group itself removes it from the
listing.

**The listing has no reproducible order.** Three groups added `zzz, aaa, mmm`
came back in that order; in another realm a parent added first and a child added
second came back child first. Neither insertion order, name, id nor path
explains both.

Guard: `view-realm` or `manage-realm` to read, `manage-realm` to write.

### 1.3 `GET /admin/realms/{realm}/group-by-path/{path}`

200, `application/json;charset=UTF-8`, `Cache-Control: no-cache`. The body is
the single group read **minus its `access` block** and identical otherwise,
measured side by side on the same group:

```
GET /groups/{id}      {"id","name","path","subGroupCount":1,"subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{},"access":{...}}
GET /group-by-path/g1 {"id","name","path","subGroupCount":1,"subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{}}
```

That is a **sixth** representation of one group. `briefRepresentation` does
nothing to it.

A leading slash is optional: `/group-by-path/g1` and `/group-by-path/%2Fg1` both
answer 200 for the same group. A nested path walks down. A path that resolves to
nothing - including the empty one - is

```
404 {"error":"Group path does not exist"}   Content-Type: application/json, no Cache-Control
```

which is a **twelfth** spelling of not-found on the admin API and the **third**
for a group.

Guard: `view-users` or `manage-users`. **`query-groups` does not open it**,
although it opens the group listing; `manage-realm`, which opens the default
groups next door, is 403.

### 1.4 Client policies and client profiles

```
GET  /admin/realms/{r}/client-policies/policies                             -> {"policies":[]}
GET  /admin/realms/{r}/client-policies/policies?include-global-policies=true -> {"policies":[],"globalPolicies":[]}
GET  /admin/realms/{r}/client-policies/profiles                             -> {"profiles":[]}
GET  /admin/realms/{r}/client-policies/profiles?include-global-profiles=true -> {"profiles":[],"globalProfiles":[ ...ten... ]}
PUT  either                                                                 -> 204, X-Frame-Options, and NO Cache-Control
```

The ten global profiles are `fapi-1-baseline`, `fapi-1-advanced`, `fapi-ciba`,
`fapi-2-security-profile`, `fapi-2-message-signing`,
`oauth-2-1-for-confidential-client`, `oauth-2-1-for-public-client`,
`fapi-2-dpop-security-profile`, `fapi-2-dpop-message-signing`,
`saml-security-profile`, 9286 bytes in total. They are recorded verbatim at
`internal/admin/globalclientprofiles.json`; several of their `configuration`
objects have keys that are not in alphabetical order, so they are served as
bytes rather than marshalled from Go. 26.7.1 ships **no** global policies.

Shapes:

```
profile  {"name","description"?,"executors":[{"executor","configuration"}]}
policy   {"name","description"?,"enabled"?,"conditions":[{"condition","configuration"}],"profiles":[...]}
```

A profile written without a description comes back without the key; a policy
written without `enabled` comes back without it.

Errors - **three families on one endpoint**:

```
malformed body    -> 400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
no body at all    -> 400 {"errorMessage":"Passing null clientProfiles not allowed"}
unknown field     -> 400 {"error":"Invalid json representation for ClientProfilesRepresentation. Unrecognized field \"nosuchfield\" at line 1 column 20."}
unknown executor  -> 400 {"errorMessage":"proposed client profile contains the executor, which does not have valid provider, or has invalid configuration."}
policy naming an
unknown profile   -> 400 {"errorMessage":"Policy pol-b contains invalid profile nope"}
```

Guard: `view-realm` or `manage-realm` to read, `manage-realm` to write.

**They are the realm representation's own `clientProfiles` and
`clientPolicies`**, measured in both directions: a `PUT` here changes what
`GET /admin/realms/{realm}` answers, and `PUT /admin/realms/{realm}` carrying
`clientProfiles` changes what this route answers. `PUT /admin/realms/{r}` with
`{"clientProfiles":{}}` **clears** them to `[]`.

### 1.5 Client types

```
GET|PUT /admin/realms/{realm}/client-types
501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
Content-Type: application/json, no Cache-Control
```

`CLIENT_TYPES` is a disabled preview feature on a default 26.7.1. The ordering
is measured on four callers: **no token is 401, a bad token is 401, an unknown
realm with a valid token is 404 `Realm not found.`, and then every
authenticated caller gets the 501 - including one holding no admin role at
all.** So the feature check sits between the realm and the authorization check.

### 1.6 A created realm's users join its default groups

`POST /users` in a realm holding two default groups answered 201, and
`GET /users/{id}/groups` came back with both. Gloak does not do this; see
follow-up 3.4.

### 1.7 Incidental, and not chased

A double slash in an admin path answers
`{"error":"missingNormalization","error_description":"Request path not normalized"}`.
Found while a probe built a path from an empty variable. Nothing in this cut
depends on it and it is not in the observed document.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

**`Cache-Control` on a 204 does not follow the method, and the rule as written
is wrong in one direction.** AGENTS.md says "Four of the five measured deletes
carry `no-cache` and `DELETE .../client-secret/rotated` does not; **no `PUT`
carries it**." `PUT /admin/realms/{r}/default-groups/{groupId}` carries
`Cache-Control: no-cache`. Its `DELETE` sibling carries it too, and the two
client-policy `PUT`s carry none at all - so this cut adds a `PUT` that has it
and a `PUT` that does not, in the same commit. The clause "no `PUT` carries it"
has to go; "it is pinned per endpoint" survives unchanged.

**A group is resolved before the caller is judged - except on the two routes
the description tags Realms Admin.** AGENTS.md records "Every route naming a
`{groupID}` answers 404 for a group that does not exist to **every** caller,
including one holding no admin role." `PUT` and `DELETE
/admin/realms/{realm}/default-groups/{groupId}` answer **403** to a caller
holding `view-realm` - which may read the listing but not write it - and 403 to
a caller holding nothing. Measured on both verbs. `GET .../group-by-path/{path}`
is the other way round and matches the Groups family. So the ordering follows
the tag rather than the presence of a group in the path, which is the third
time this project has met a rule that is right on one family and inverted on
its neighbour.

**There are twelve spellings of not-found on the admin API now, and three of
them are for a group.** `Could not find group by id` on the Groups routes,
`Group not found` on the user-membership routes **and on the default-groups
writes**, and `Group path does not exist` on `group-by-path`. One missing
group, three answers, decided by which route went looking.

**One group has six representations.** The fifth was
`groupMembershipFull`; the sixth is `group-by-path`, which is the single group
read **minus its `access` block** and identical otherwise. A `default-groups`
entry is the membership shape and not a seventh. `briefRepresentation` does
nothing to either.

**A realm's key set is four keys and the JWKS beside it publishes two.** The
HMAC key that signs refresh tokens and an AES key that signs and encrypts
nothing appear in `GET /admin/realms/{realm}/keys` as bare kids with no
material. Serving three is a divergence on that endpoint alone.

**An RSA key's `kid` is the digest of the key and an OCT key's is a UUID.**
`base64url(sha256(SubjectPublicKeyInfo))`, and not the RFC 7638 JWK thumbprint,
which is the obvious guess and gives a different value. There is no "the kid
rule" to share between the two key types.

**`use` is `SIG`/`ENC` on the Admin API's key listing and `sig`/`enc` in the
JWKS**, for the same two keys. One constant shared between them is wrong on one.

**`client-types` answers 501 to every authenticated caller and that is the
contract.** `CLIENT_TYPES` is a disabled preview feature, the same situation as
`GET .../client-secret/rotated`'s permanent 404. The feature check runs after
the realm is resolved and **before** the authorization check, so a caller
holding no admin role gets the 501 rather than a 403 - the only route in P4
whose guard has no role list at all.

**A `PUT` with no body is a 400 on the client-policy routes and a 500 on
`PUT /admin/realms/{realm}`.** Same verb, neighbouring routes on one resource,
two answers. A shared decoder gets one of them wrong, which is the fourth time
this API has punished sharing one.

**A `PUT` on a realm replaces `clientProfiles` rather than merging into it.**
Sending a profile that omits a field the stored one had leaves the field gone.
Go's `encoding/json` does the opposite by default - it unmarshals an array into
an existing slice element by element and keeps whatever the new element does not
name - so the two arrays have to be emptied before the merge. Every other slice
in that 104-key representation holds strings, where the reuse is invisible;
these two hold structs, where it is not.

**Client policies and client profiles are the realm representation's own
state.** Two endpoints and one storage location, measured in both directions.
Giving them a table of their own would create a second truth.

## 3. Follow-ups to file or close

### 3.1 File: a golden that enumerates a realm-wide set without `PristineRealm`

`admin/role-mapper/group-realm-available` lists every realm role a group could
be given. It is **not** `PristineRealm`, so a full `make record` run records it
after fifteen other fixtures have created realm roles, and the recorded body
then carries all of them. The verifier serves each case against a fresh store
and can never match it, so the re-recording fails the suite.

This branch reverted that file rather than committing the polluted version, and
the fix is one field. `TestPristineRealmGoldensAreNotPolluted` does not catch it
because the case does not claim the flag. Worth a sweep: any case whose body
enumerates a realm-wide set needs the flag, and this one shows the catalogue has
at least one that does not have it.

### 3.2 Close: Gloak's 204 carried a `Date` header

AGENTS.md says "Gloak deletes the `Date` header on every response". It did not:
`httpx.WriteNoContent` was the one writer that never called `suppressDate`, so
every 204 - the deletes, the client and user updates, the credential moves, the
group joins - carried one. Both existing guards go through `WriteJSON`, and the
conformance harness serves through `httptest.ResponseRecorder`, which adds no
`Date` either. Found by reading a live 204 off the wire while measuring this
cut. **Fixed on this branch**, with a third real-server test beside the two
that already existed.

### 3.3 File: two error bodies this cut serves differently from Keycloak

- An unrecognised field in a `client-policies` body answers 400 `Invalid json
  representation for ClientProfilesRepresentation. Unrecognized field
  "nosuchfield" at line 1 column 20.` The column is a function of the request
  body, so reproducing it means reproducing Jackson's parser positions. Gloak
  ignores the field and answers 204. `PUT /admin/realms/{realm}` has the same
  gap for its own copy of that error, so this is one follow-up covering two
  endpoints. The conformance case is `Recorded`.
- A profile naming an executor that is not a registered provider answers 400
  `proposed client profile contains the executor, which does not have valid
  provider, or has invalid configuration.` Gloak accepts it: the executor and
  condition inventories belong to engines it has not built.

### 3.4 File: a new user does not join the realm's default groups

Measured on Keycloak: `POST /users` in a realm holding two default groups
produced a user who was a member of both. Gloak's `POST /users` does not join
any. No existing golden changes, because `master` has no default groups and
nothing else creates one - but the moment an operator sets a default group,
Gloak and Keycloak disagree about every user created afterwards. It is `POST
/users`' behaviour, P2's, and this cut deliberately did not reach into it.

### 3.5 Note, not a follow-up: nothing enforces a client policy

Gloak stores client profiles and policies and serves them back. No client
request is evaluated against them. Serving a field is not implementing it, as
the design's section 10 says of the realm's other 104.

### 3.6 Note: `providerId` is derived rather than stored

Keycloak's `providerId` is the id of a key provider *component*, an object Gloak
does not model. Each of the four keys comes from exactly one provider, so Gloak
derives the value from the `kid` by a fixed hash: stable across restarts,
distinct from the `kid` as measured, and no table for a concept nothing else
uses. If a later cut models components, this is where the real id would come
from. `internal/admin/keys.go`'s `providerIDOf` says so at the call site.

## 4. Parity before and after

```
before   129 of 485 enumerated behaviours served
after    140 of 485
```

`+11`, one per operation:

| chapter | before | after | denominator |
|---|---|---|---|
| `admin/key` | 0 | **1** | 1 |
| `admin/realms-admin` | 5 | **15** | 45 |

That completes P4's sixteen operations. The `Realms Admin` tag stays at 15 of
45 because the other 30 belong to P5, P6, P8, P10, P13 and P14, which section 2
of the design works out per operation.

## 5. The roadmap line

`docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md` marks P4 as
"Realms Admin 45, Key 1". Both cuts are now done and the sub-project is
complete at **16 operations built of the 46 the two tags hold**. The remaining
30 are counted under those tags because the description files them there, and
are built by six other sub-projects.
