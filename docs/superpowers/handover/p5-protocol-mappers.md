# P5 cut B: what belongs in the documents this branch may not edit

Date: 2026-08-30
Branch: `feat/p5-protocol-mappers`
Plan: `docs/superpowers/plans/2026-08-30-p5-protocol-mappers.md`

Everything below was measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8095 (`kc-p5b`, removed at
the end of the session), on 2026-08-30. Gloak was then compared against the same
requests through the conformance recorder and verifier.

This branch does not touch `AGENTS.md`, `README.md` or the three spec documents,
so what is owed to them is written out here.

---

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

### 1.1 The tag is 21 operations and the alias holds on all seven

Three families of seven: `client-scopes/{id}/protocol-mappers/...`,
`client-templates/{id}/protocol-mappers/...` and
`clients/{uuid}/protocol-mappers/...`, each with `models` (GET, POST),
`models/{id}` (GET, PUT, DELETE), `protocol/{protocol}` (GET) and `add-models`
(POST).

`client-templates` serves what `client-scopes` serves **byte for byte, headers
included**, on every one of the seven, with the one exception its parent family
has: `POST` answers a `Location` under the path it was called on. The error
bodies come through unchanged too. Verified operation by operation rather than
inferred from the first cut having measured the parent.

`GET .../protocol-mappers` with no sub-path is a 404
`{"error":"HTTP 404 Not Found"}` on all three families. There is no bare
collection the description omits.

### 1.2 The representation

```
id, name, protocol, protocolMapper, consentRequired, config
```

200, `Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`,
the five security headers. Nothing is omitted: `config` is present and `{}` when
empty.

**`consentRequired` is always `false`.** A create sending `true` reads back
`false`, on every provider tried and on both containers. It is dead surface.

The array's order inside a container is **not reproducible**, so a case
comparing it needs `Case.Unordered` at the root.

### 1.3 `PUT` writes the mapper the body names, and only two of its fields

Two separate defects on one route, both reproduced.

- **The path names which mapper must exist; the body's `id` names which mapper
  is written.** A `PUT` addressed to mapper A carrying B's `id` answered 204 and
  changed **B**, leaving A untouched. An unknown path id is 404 *before* that,
  so the path is a precondition and the body is the target. A body with **no
  `id`**, or one naming a mapper that does not exist, is a **500**
  `unknown_error`.
- **It writes `protocolMapper` and `config` and nothing else.** `name`,
  `protocol` and `consentRequired` are read and discarded: a `PUT` renaming a
  mapper answers 204 and does not rename it, and one moving it to `saml` leaves
  its protocol alone. `config` is **replaced**, not merged.

### 1.4 The create fills in config keys, per provider

A create mirrors `access.token.claim` into `introspection.token.claim` and
`id.token.claim` into `userinfo.token.claim` - **the value, not a constant
`"true"`**: `access.token.claim: "false"` produced
`introspection.token.claim: "false"`. The mirror is **appended**, and a key the
body already carries is left alone.

Whether it happens is decided by the **`protocolMapper` provider**, not by the
mapper's `protocol`. Measured both ways round:
`oidc-usermodel-attribute-mapper` declared `"protocol":"saml"` gets the mirrors;
`saml-user-property-mapper` declared `"protocol":"openid-connect"` does not.

Measured across all 39 providers `GET /admin/serverinfo` reports:

| Providers | introspection | userinfo |
|---|---|---|
| 20 of the 24 `oidc-*` | yes | yes |
| `oidc-allowed-origins-mapper`, `oidc-audience-resolve-mapper` | yes | **no** |
| `oidc-nonce-backwards-compatible-mapper`, `oidc-organization-membership-mapper` | no | no |
| all 14 `saml-*`, `docker-v2-allow-all-mapper` | no | no |

`strings.HasPrefix(id, "oidc-")` is right 20 times out of 39 and wrong on the
four exceptions.

**Two providers also seed config keys of their own, and Gloak does not
reproduce them**: `oidc-organization-membership-mapper` adds
`addOrganizationAttributes`, `addOrganizationId`, `claim.name`,
`jsonType.label` and `multivalued`; `oidc-sha256-pairwise-sub-mapper` adds a
random `pairwiseSubAlgorithmSalt`. See the follow-up.

**Config entries whose value is `""` or `null` are dropped**, before the
mirroring reads them: `{"access.token.claim":""}` produced `{}` and no mirrored
key. `"config":null` produces `{}`.

### 1.5 Every status on the tag

| Request | Status | Body |
|---|---|---|
| `POST models`, good | 201 | empty, absolute `Location`, `Cache-Control: no-cache`, **no `Content-Type`** |
| `protocolMapper` absent or unknown | **404** | `{"error":"ProtocolMapper provider not found"}` |
| `name` absent or `null` | **409** | `{"error":"conflict","error_description":"Duplicate resource error"}` |
| `protocol` absent | **409** | the same |
| `name` already held | 409 | `{"errorMessage":"Protocol mapper exists with same name"}` |
| `name: ""` | **201** | accepted; the *second* empty name is the 409 above |
| empty body, or `null` | 500 | `{"error":"unknown_error","error_description":"For more on this error consult the server log."}` |
| `GET`/`PUT`/`DELETE models/{id}`, unknown or non-UUID id | 404 | `{"error":"Model not found"}` |
| unknown scope, any of the seven | 404 | `{"error":"Could not find client scope"}` |
| unknown client, any of the seven | 404 | `{"error":"Could not find client"}` |
| `PUT models/{id}`, 204 | 204 | `Cache-Control: no-cache`, all five security headers |
| `DELETE models/{id}`, 204 | 204 | `Cache-Control: no-cache`, **no `X-Frame-Options`** (no request `Content-Type`) |
| `POST add-models`, good | **204** | no `Location` |
| `POST add-models`, duplicate name | 409 | `{"error":"conflict","error_description":"Protocol mapper name must be unique per protocol"}` |
| `GET protocol/{protocol}`, unknown protocol | 200 | `[]` |

Three 409s on one family in three shapes, and a **404 on a create**.

**The `Duplicate resource error` 409 carries none of the five security
headers.** Measured on three bodies, side by side with the `errorMessage` 409 on
the same route, which carries all five. It is the only response on the family
that does not reach the filter chain. The message is about a duplicate and the
request contains none: it is a NOT NULL violation surfaced through the exception
mapper Keycloak installs for every constraint violation.

`Model not found` is a **fifteenth** spelling of not-found on the admin API, and
the least specific of the fifteen - it names neither the resource nor the key.

### 1.6 A mapper's protocol is not validated and its provider is

`{"protocol":"bogus", "protocolMapper":"oidc-usermodel-attribute-mapper"}` is a
**201**, and `.../protocol/bogus` returns it. A `protocolMapper` outside the 39
registered ids is a 404, whatever `protocol` says - the two are independent.

`GET .../protocol/{protocol}` filters on the **mapper's own** `protocol`, not
the container's: an `openid-connect` client scope holding one `saml` mapper
answers that mapper for `saml` and the others for `openid-connect`.

### 1.7 A mapper id is unique across the realm, not within its container

A second client scope created with a mapper id already in use is
**409 `Duplicate resource error`** and is **not created**. A client created the
same way answers **`{"errorMessage":"Client <clientId> already exists"}`** - a
message about the client, for a conflict on the mapper's id. And
`POST .../protocol-mappers/models` with a duplicate id answers
`{"errorMessage":"Protocol mapper exists with same name"}` - a message about the
name, for a conflict on the id.

Gloak does **not** reproduce this: it stores mappers per container and has no
realm-wide id index. See the follow-up.

### 1.8 The guards, and a resolution order that needed two sweeps

Swept one role at a time over eight candidates, on ten routes.

```
role             badScope  realScope  badClient  realClient  write
<none>              403       403        403        403       403
query-clients       404       403        404        403       404
view-clients        404       200        404        200       403
manage-clients      404       200        404        200       201
create-client       403       403        403        403       403
```

So the order is:

```
realm -> coarse gate {view,query,manage}-clients (403)
      -> the container: scope or client (404)
      -> the fine check: read view|manage, write manage (403)
      -> reads: the mapper (404)
      -> writes: the provider (404), then the mapper (404)
```

**The `query-clients` row is the one that needed measuring twice.** The first
sweep asked only what it gets on a scope that **exists** - 403 - and that
answer is the same whether it is refused at the gate or admitted and refused
after. The scope that does **not** exist is what tells them apart, and it says
admitted-then-refused. Gloak shipped the wrong one until a golden recorded a 404
where it served a 403; the branch fixes it.

`GET /client-scopes` one level up admits `query-clients` too, and answers it
`200 []` rather than a 403 - so the *gate* is shared with the parent family and
only the fine check differs. Nothing on the protocol-mapper family answers
`query-clients` 200 at all.

### 1.9 The wrong-method answer is `PATCH`-only here, and the parent family's is not

```
PATCH  .../protocol-mappers/models          405 {"error":"HTTP 405 Method Not Allowed"}
PATCH  .../protocol-mappers/models/{id}     405
PATCH  .../protocol-mappers/add-models      405
PUT    .../protocol-mappers/models          404 {"error":"HTTP 404 Not Found"}
DELETE .../protocol-mappers/models          404
POST   .../protocol-mappers/models/{id}     404
GET    .../protocol-mappers/add-models      404
POST   .../protocol-mappers/protocol/{p}    404
```

`application/json`, all five security headers, no `Allow`, no `Cache-Control`.
Measured on all three families, the alias included.

The **parent** family, measured hours earlier by the first cut, answers `PUT`
and `DELETE` on `/client-scopes` with a real 405. So a route family and its
child disagree, on the Admin API, three path segments apart. This is F31's sixth
data point.

### 1.10 The 400 "Cannot parse the JSON" has three codes and the **body** decides

This is the finding that contradicts an existing bullet; see section 2.1.

Swept across `POST .../protocol-mappers/models` (object target),
`POST .../protocol-mappers/add-models` (array target), `POST /users` (object)
and `POST .../role-mappings/realm` and `POST /roles-by-id/{id}/composites`
(arrays), on one container in one session:

| Body | object endpoint | array endpoint |
|---|---|---|
| `{` | `invalid_request` | `unknown_error` |
| `{"name":` | `invalid_request` | - |
| `[` | `unknown_error` | `invalid_request` |
| `[]` | `unknown_error` | (accepted) |
| `[{` | - | **`HTTP 400 Bad Request`** |
| `"x"`, `1`, `true` | `unknown_error` | `unknown_error` |
| `null` | 500 `unknown_error` | 500 `unknown_error` |

All the 400s carry `"error_description":"Cannot parse the JSON"`.

The rule: the body's **first token** decides. Right shape and then truncated is
`invalid_request`; wrong shape is `unknown_error`; and on an array endpoint an
element that is itself truncated is a third code, `HTTP 400 Bad Request`.

### 1.11 `protocolMappers` on the two representations that carry it

`GET /clients` and `GET /clients/{uuid}` carry `protocolMappers` between
`nodeReRegistrationTimeout` and `defaultClientScopes`, and the key is **absent**
when there are none - four of the six bootstrapped clients have no such key.
`account-console` carries `audience resolve` and `security-admin-console`
carries `locale`.

**`POST /clients` and `POST /client-scopes` accept `protocolMappers` at create
time and keep the ids inside them**, the way they keep the object's own id. The
same config transformations apply (empty values dropped, mirrors appended,
`consentRequired` forced false).

**`PUT /clients/{uuid}` replaces them; `PUT /client-scopes/{id}` ignores them.**
Measured in both directions: on a client, an absent key keeps the set, `[]`
empties it, and an array replaces it; on a client scope, an array answers 204
and changes nothing. Two neighbouring updates on one API, opposite answers - and
on the client it is the opposite of the two client-scope **name** lists, which
that same `PUT` ignores outright.

**Neither create nor `PUT /clients/{uuid}` checks the provider.**
`"protocolMapper":"gloak-no-such-provider"` is a 201 and a 204 there, and a 404
on the dedicated routes. One field, validated on one route and stored blindly on
its neighbour.

A duplicate name **inside** a `PUT /clients/{uuid}` array is a **400**
`{"error":"invalid_input","error_description":"Cannot add protocol mapper 'pD'. Protocol mapper name must be unique per protocol"}` -
a fourth conflict spelling on this resource, and the only one that is not a 409.

### 1.12 One mapper, two configs, decided by which route serves it

`account-console`'s `audience resolve` reads back:

```
GET /clients                              "config":{}
GET /clients/{uuid}                       "config":{}
GET /clients/{uuid}/protocol-mappers/...  "config":{"introspection.token.claim":"true","access.token.claim":"true"}
```

Measured on one container, minutes apart, with only reads in between, and
independently confirmed by the recorder: `admin/clients/list-all`'s golden holds
`"config":{}` for that mapper. `security-admin-console`'s `locale` is identical
in all three views, and a **client scope**'s `audience resolve` is populated in
both of its views - so it is not "the client listing empties config" and not
"the mapper route fills it in".

Gloak has one stored value and serves it in both places, so it can match only
one. It stores the dedicated route's, because that is the route this cut owns
and the one under a golden. See the follow-up.

### 1.13 The mapper `config`'s key order is a sized `HashMap`, and the model is known

A created mapper's `config` comes back in Java `HashMap` iteration order.
The model that reproduces it was found and checked against **fourteen** measured
(insertion order, served order) pairs, all fourteen fitting:

```
capacity = tableSizeFor(n)          // the next power of two >= n
if n*4 > capacity*3 { capacity *= 2 }   // one load-factor doubling
buckets ascending; keys colliding in a bucket in INSERTION order
```

That is **not** `internal/javamap`'s model, and two measured pairs say why:

- `{user.attribute, claim.name}` inserted in **either** order comes back
  `claim.name, user.attribute`. So it is hash order, not insertion order - and
  `javamap.KeyOrder` puts `user.attribute` first, because `capacityFor` gives a
  two-key map a table of **16** where this one has a table of **4**.
- `{zz, aa, mm}` comes back `zz, aa, mm` when inserted that way and
  `mm, zz, aa` when inserted that way. All three collide, chains are insertion
  order, and `javamap`'s alphabetical tie-break is a coin flip it loses here.

`javamap.KeyOrder` gets 6 of the 14 wrong. Its own doc comment predicted the
second failure and not the first.

The 12-key vector is the sharpest: inserted `k12..k01`, served
`k06 k05 k08 k07 k09 k11 k10 k02 k12 k01 k04 k03`. A table of 16 predicts that
exactly, including `k12` before `k01` where they collide in bucket 13 and `k12`
went in first.

This cut does **not** extend `javamap`. Instead its conformance cases use config
key sets measured to be order-stable - where the request order and the served
order coincide, which is true of every realistic mapper config including the
ones that gain a mirrored key - so the goldens assert config bytes with no
`UnorderedKeys` mask. **No second retreat was added**; AGENTS.md's "`attributes`
key order is the one thing the conformance suite does not compare" stays a set
of one.

### 1.14 The scope-to-mapper-to-claim table, for F63

The six client scopes a bootstrapped `openid-connect` client carries by default,
and the mappers inside them, with the config keys a token engine reads:

| Scope | Mapper | Provider | `claim.name` | access | id |
|---|---|---|---|---|---|
| basic | auth_time | `oidc-usersessionmodel-note-mapper` | `auth_time` | true | true |
| basic | sub | `oidc-sub-mapper` | - | true | - |
| acr | acr loa level | `oidc-acr-mapper` | - | true | true |
| roles | audience resolve | `oidc-audience-resolve-mapper` | - | true | - |
| roles | client roles | `oidc-usermodel-client-role-mapper` | `resource_access.${client_id}.roles` | true | - |
| roles | realm roles | `oidc-usermodel-realm-role-mapper` | `realm_access.roles` | true | - |
| web-origins | allowed web origins | `oidc-allowed-origins-mapper` | - | true | - |
| email | email | `oidc-usermodel-attribute-mapper` | `email` | true | true |
| email | email verified | `oidc-usermodel-property-mapper` | `email_verified` | true | true |
| profile | 14 mappers | mostly `oidc-usermodel-attribute-mapper` | `profile`, `picture`, `birthdate`, `zoneinfo`, `preferred_username`, `middle_name`, `website`, `gender`, `updated_at`, `family_name`, `given_name`, `locale`, `nickname`, and `full name` with none | true | true |

`service_account`, which a service-account client also carries, holds
`clientHost`, `clientAddress` and `client_id`, all
`oidc-usersessionmodel-note-mapper`.

Every claim AGENTS.md's "four token claims are absent rather than empty" bullet
names is on this table: `realm_access` and `resource_access` come from the two
role mappers in `roles`, `aud` from `audience resolve`, `allowed-origins` from
`allowed web origins`.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Ready to paste, in that file's voice.

- **`PUT` on a protocol mapper writes the mapper the *body* names and only two
  of its fields.** The path id is a precondition - an unknown one is 404 - and
  then the body's `id` decides what is written: a `PUT` addressed to mapper A
  carrying B's id answered 204 and changed **B**. A body with no `id`, or one
  naming a mapper that does not exist, is a **500**. And it writes
  `protocolMapper` and `config` and nothing else: a `PUT` renaming a mapper
  answers 204 and does not rename it, one moving it to `saml` leaves its
  protocol alone, and `consentRequired` is discarded. `config` is **replaced**,
  not merged. Writing the whole representation back is the obvious
  implementation and it is wrong on three fields and on which row it writes.
- **`consentRequired` on a protocol mapper is always `false`.** A create sending
  `true` reads back `false`, on every provider tried and on both containers. It
  is a field in the representation and dead surface in the server.
- **A create fills in two config keys for itself, and the *provider* decides
  whether it does.** `access.token.claim` is mirrored into
  `introspection.token.claim` and `id.token.claim` into
  `userinfo.token.claim` - the **value**, not a constant `"true"` - appended
  rather than inserted, and skipped when the body already carries the key.
  Whether it happens follows the `protocolMapper`, **not** the mapper's own
  `protocol`: an `oidc-*` provider declared `"protocol":"saml"` gets the
  mirrors and a `saml-*` provider declared `"protocol":"openid-connect"` does
  not. Measured across all 39 registered providers: 20 of the 24 `oidc-*` do
  both, `oidc-allowed-origins-mapper` and `oidc-audience-resolve-mapper` mirror
  introspection only, `oidc-nonce-backwards-compatible-mapper` and
  `oidc-organization-membership-mapper` mirror neither, and all fourteen
  `saml-*` and `docker-v2-allow-all-mapper` mirror neither.
  `strings.HasPrefix(id, "oidc-")` is right 20 times out of 39.
- **A config entry whose value is `""` or `null` is dropped, and takes its
  mirror with it.** `{"access.token.claim":""}` produced `{}`, not
  `{"access.token.claim":"","introspection.token.claim":""}`, so the removal
  runs first and the mirroring reads what survives.
- **A mapper's `protocol` is not validated and its `protocolMapper` is.**
  `"protocol":"bogus"` is a 201 and `.../protocol/bogus` returns the mapper. A
  `protocolMapper` outside the 39 ids `GET /admin/serverinfo` reports is a
  **404 on a create**, `{"error":"ProtocolMapper provider not found"}`, checked
  **before** the name and before the protocol - which is why `{}` answers about
  the provider where `POST /client-scopes` answers about the name.
- **Three 409s on one route family, in three shapes, and one of them ships
  without the security headers.** A name the container already holds is
  `{"errorMessage":"Protocol mapper exists with same name"}` with all five; an
  **absent** `name` or an absent `protocol` is
  `{"error":"conflict","error_description":"Duplicate resource error"}` with
  **none** of the five, because it is a NOT NULL violation surfaced through an
  exception mapper that never reaches the filter chain; and `add-models` with a
  duplicate is
  `{"error":"conflict","error_description":"Protocol mapper name must be unique per protocol"}`.
  A fourth spelling lives on `PUT /clients/{uuid}`, is a **400** rather than a
  409, and names the mapper: `{"error":"invalid_input","error_description":"Cannot add protocol mapper 'x'. Protocol mapper name must be unique per protocol"}`.
- **An empty mapper name is legal.** `{"name":""}` with a registered provider is
  a 201, and the *second* empty name is the duplicate 409 - the opposite of a
  client scope, whose empty name is a 400 naming the empty string.
- **A protocol mapper id is unique across the whole realm, not within its
  container.** A second client scope created with a mapper id already in use is
  409 `Duplicate resource error` **and is not created**; a client created the
  same way answers `Client <clientId> already exists`, a message about the
  client for a conflict on the mapper; and a `POST .../models` with a duplicate
  id answers `Protocol mapper exists with same name`, a message about the name
  for a conflict on the id. Three routes, three messages, none about what
  actually collided.
- **`protocolMappers` is honoured by `POST /clients`, `POST /client-scopes` and
  `PUT /clients/{uuid}`, and ignored by `PUT /client-scopes/{id}`.** On the
  client it replaces: an absent key keeps the set, `[]` empties it, an array
  replaces it. That is the opposite of the two client-scope **name** lists,
  which the same `PUT` ignores outright, so one body has two arrays with
  opposite update rules. Go's `encoding/json` unmarshals an array into an
  existing slice element by element, so the slice has to be emptied before the
  merge - the trap the realm's `clientProfiles` pair already records.
- **The provider is checked on the dedicated routes and not on the three that
  carry `protocolMappers` inline.** `"protocolMapper":"gloak-no-such-provider"`
  is a 404 on `POST .../protocol-mappers/models` and a 201 on `POST /clients`,
  a 201 on `POST /client-scopes` and a 204 on `PUT /clients/{uuid}`.
- **One mapper serialises two ways and the route decides.**
  `account-console`'s `audience resolve` reads `"config":{}` from `GET /clients`
  and from `GET /clients/{uuid}`, and
  `{"introspection.token.claim":"true","access.token.claim":"true"}` from
  `.../protocol-mappers/models`. Measured on one container minutes apart and
  confirmed by the recorder. It is not "the client listing empties config":
  `security-admin-console`'s `locale` is identical in all three views, and a
  client **scope**'s `audience resolve` is populated in both of its views.
- **The coarse gate on the protocol-mapper routes is the client-scope family's
  three roles and the fine check is two.** `query-clients` is admitted - a scope
  that does not exist answers it **404** - and then refused, so a scope that
  does exist answers 403. Asking only what it gets on a scope that exists cannot
  tell the two arrangements apart, and this project shipped the wrong one on the
  strength of exactly that. `create-client` and a caller holding nothing are 403
  even for a scope that does not exist.
- **`GET .../protocol-mappers/protocol/{protocol}` filters on the mapper's own
  protocol, not the container's, and never validates the segment.** An
  `openid-connect` client scope holding one `saml` mapper answers that mapper
  for `saml`; an unknown protocol is 200 and `[]`, not a 400.
- **`add-models` is a 204 with no `Location` where the create beside it is a 201
  with one**, and **it validates the whole array before it applies any of it**:
  an array whose second entry duplicates a held name left the first entry
  unwritten. Its 409 alone cannot tell a rejected batch from a half-applied one.
- **A mapper's `config` key order is a Java `HashMap` sized to its entry
  count**, which is a different table size from the one `internal/javamap`
  models. `{user.attribute, claim.name}` comes back `claim.name, user.attribute`
  whichever order it went in - so it is hash order - and `javamap` puts them the
  other way because it gives a two-key map a table of 16 where this one has 4.
  `{zz, aa, mm}` comes back in whichever order it went in, because all three
  collide and chains are insertion order, where `javamap` breaks ties
  alphabetically. The full model is
  `capacity = tableSizeFor(n)`, doubled once if `n*4 > capacity*3`, buckets
  ascending, collisions in insertion order; it fits all fourteen measured
  vectors including a twelve-key one.

### 2.1 Lines these measurements contradict

**Three, and the first is the one that has been believed longest.**

1. **"The endpoints taking a role *array* answer a malformed body
   `unknown_error`, where `POST /users` answers `invalid_request` ... so the
   difference is per endpoint and not a change of version."** It is **not per
   endpoint. It is per body shape.** `POST /users` answers **`unknown_error`**
   for `[`, and `POST .../role-mappings/realm` answers **`invalid_request`** for
   `[` - each the opposite of what the bullet predicts. The bullet's own
   sentence says how it went wrong: "measured on all ten registrations that
   decode a role array ... with `POST /users` re-measured alongside as the
   control". Every one of those eleven probes sent `{`, which is the right shape
   for the object endpoint and the wrong shape for the ten array ones, so the
   result looked like a property of the endpoint. The rule is: right shape then
   truncated is `invalid_request`, wrong shape is `unknown_error`, and on an
   array endpoint a truncated **element** is a third code,
   `{"error":"HTTP 400 Bad Request"}`. `null` is a 500 on both.
   This is the same failure mode the "role listing pages when `search` is
   non-empty" bullet already records having made: a generalisation from probes
   that each varied only one thing, with the central case never issued.
   **Gloak's ten role-array endpoints still answer per endpoint**; this cut's
   own three decoders implement the shape rule, and the difference is visible
   only on bodies no case sends. See the follow-up.

2. **"A wrong method on a known path returns 404, not 405"** and its "five data
   points that disagree" qualifier both gain a **sixth**, and this one is
   inside the family the fifth came from. On every protocol-mapper path,
   **`PATCH` alone** is a real 405 and `PUT`, `POST`, `DELETE` and `GET` are the
   404. The parent family - `/client-scopes` and `/client-scopes/{id}`, measured
   hours earlier - answers `PUT`, `DELETE`, `POST` and `PATCH` all four with a
   405. So a route family and its child, three path segments apart on the Admin
   API, disagree. The count in that sentence needs updating; the conclusion does
   not, and nothing was changed on the strength of it.

3. **"`attributes` key order is the one thing the conformance suite does not
   compare ... This is the only such retreat - do not add a second without
   writing down why."** No second retreat was added, and the reason is worth
   recording because it nearly was: a mapper's `config` is the same kind of Java
   map and **is** reproducible, by a model this cut found and verified against
   fourteen vectors (§1.13). What that model shows is that `internal/javamap`'s
   `capacityFor` - 16 and doubling, the no-argument constructor's rule - is
   wrong for any map Keycloak builds with an explicit size, which is this one.
   So the existing retreat may be narrower than it looks: `attributes` was never
   re-examined against a sized-constructor model.

**A fourth line, not contradicted but incomplete.** `admin/clients/list-all`'s
`Reason` is "two bootstrapped clients carry protocolMappers, which is P5". There
are **three** blockers, not one, and two of them are not protocol mappers:
`master-realm` is served with no `name` where Keycloak sends `"master Realm"`,
and with both client-scope lists **empty** where Keycloak sends the same six and
five every other client gets. The mapper blocker is now §1.12's disagreement
rather than an absence. The case stays `Recorded`; its Reason should name all
three.

---

## 3. Follow-ups to file or close

### F63: stated plainly

**F63 is not paid on this branch, and here is the reason.** Paying it means
token issuance deriving its claims from the stored mappers rather than
reproducing the measured claim set directly, and that code is in
`internal/token`, which this cut may not touch. A derivation built in a package
this cut does own and not wired into issuance would be a second truth about what
a token contains, sitting beside the first, untested against a live server -
which is the failure the boundary table records having already happened twice.

**What changed is that the note may no longer say the prerequisite is in
place.** Two things:

1. **The engine's input was incomplete and nobody had looked.** F63 says the
   thirty-five client-scope mappers are stored, and they are - but a **client**
   carries mappers of its own and Gloak stored none. `account-console` carries
   `audience resolve` and `security-admin-console` carries `locale` on a live
   26.7.1. A derivation over client scopes alone would have produced the wrong
   claim set for two of the six bootstrapped clients, and the fault would have
   looked like an engine bug. Both are now bootstrapped and pinned by
   `TestBootstrappedClientMappers`.
2. **The correspondence is measured.** §1.14 is the scope-to-mapper-to-claim
   table for all six default scopes plus `service_account`, with `claim.name`,
   `access.token.claim` and `id.token.claim` per mapper. Every claim in the
   "four token claims are absent rather than empty" bullet is on it.

**Suggested replacement text for F63:** *the protocol mapper engine is staged.
All thirty-five client-scope mappers and both client mappers are stored, served
by all 21 operations of the Protocol Mappers tag, and writable; the
scope-to-mapper-to-claim correspondence is measured and recorded in
`docs/superpowers/handover/p5-protocol-mappers.md` §1.14. What remains is
`internal/token` consulting them instead of the constant claim set, which is a
substitution against that table rather than a research task.*

### New follow-ups, to file

- **F64: the "Cannot parse the JSON" code is per body shape, not per
  endpoint.** §2.1.1. Gloak's ten role-array endpoints and `POST /users` each
  pin one code per endpoint, which is right for the one body each case sends and
  wrong for the other shapes. The fix is one shared classifier -
  `internal/admin`'s `decodeMapperBody` is it, written on this branch - plus a
  case per shape on one endpoint of each family. The third code,
  `{"error":"HTTP 400 Bad Request"}` for a truncated array *element*, is not
  implemented anywhere and needs the decoder to report where it stopped.
- **F65: one protocol mapper serialises two ways and Gloak can serve one.**
  §1.12. `account-console`'s `audience resolve` is `"config":{}` in the client
  representation and populated on the dedicated mapper route. Gloak stores the
  populated one, so `admin/clients/list-all` still differs there. The mechanism
  is not known; a third view (a client **scope**'s, populated in both) rules out
  the two obvious explanations.
- **F66: a protocol mapper id is not realm-unique in Gloak.** §1.7. Keycloak
  refuses a mapper id already in use anywhere in the realm, with three different
  messages depending on the route; Gloak stores mappers per container and would
  accept it. Reproducing it needs a realm-wide index, and the three messages
  need reproducing with it. It bit this branch: three conformance fixtures
  shared a mapper id, three scopes were silently never created, and
  `idempotentCreate` swallowed the 409 that said so.
- **F67: two providers seed config keys of their own.** §1.4.
  `oidc-organization-membership-mapper` adds five and
  `oidc-sha256-pairwise-sub-mapper` adds a random `pairwiseSubAlgorithmSalt`.
  Gloak reproduces neither. The salt cannot go under a golden as it stands.
- **F68: `internal/javamap` models the wrong constructor for a sized map.**
  §1.13. `capacityFor` is the no-argument constructor's 16-and-double; a map
  Keycloak builds with an explicit size has `tableSizeFor(n)` doubled once past
  the load factor, and its collisions chain in insertion order rather than
  alphabetically. The full model and fourteen vectors are in §1.13 and were not
  folded in because `javamap` is outside this cut's file set. Folding them in
  would let the mapper `config` order be asserted from any insertion order, and
  is worth re-checking `attributes` against.
- **F69 (existing) unchanged**: the four `Pending` theme-page goldens churned on
  all three `make record` runs and none of that churn is committed.

### Bearing on existing follow-ups

- **F31** gains its sixth data point, §1.9, and this one is a parent and child
  family disagreeing rather than one family being mixed. Nothing was changed.
- **F59 is not needed by this cut and is not closed by it.** Every array these
  cases assert is at the **root** of its body, where `Case.Unordered`'s `"."`
  works, so no case here needs the nested-sort fix. The hole F59 describes is
  still open: `admin/client-scopes/list` still masks `*/protocolMappers` whole,
  and the thirty-five bootstrapped mappers are still under no golden.
  `TestBootstrappedClientScopeMappers` closes it for one scope and
  `TestBootstrappedClientMappers`, added here, closes the same kind of hole for
  the two client mappers - which no golden reaches either, because a
  bootstrapped client's UUID is minted at bootstrap and no case can name it.
  **`normalize.go` was not touched.**
- **F61** is unchanged and now half wrong in a new way: it says
  `PUT /clients/{uuid}` accepting `defaultClientScopes` is unguarded. It still
  is. But the same `PUT` **does** honour `protocolMappers`, which this cut
  implements and pins, so the two arrays on that body are no longer symmetric
  and the follow-up should say which one it means.

### Mutation survivors reported

Fourteen mutations, one per claim, each confirmed to fail the *named* test and
reverted. **Four survived on the first pass and all four are now closed**:

1. and 2. **The mirroring rule as one flag, and as "every `oidc-*` provider".**
   Both survived `admin/protocol-mappers/read-created`, whose comment claimed to
   catch them. The fixture's second mapper sent only `access.token.claim`, so
   with no `id.token.claim` to mirror both mutations produce exactly the right
   bytes. One fixture line - adding `id.token.claim` to that mapper - closed
   both. **The case was wrong, not the code.**
3. **`query-clients` refused at the gate rather than after the container.** No
   case covered it, because the guard sweep had only asked about a scope that
   exists. Closed by `admin/protocol-mappers/list-to-a-query-clients-caller`,
   and recording it is what revealed that **Gloak's guard was wrong**, not just
   untested. Fixed on the branch.
4. **The provider check deleted from `add-models`.** No case sent an unregistered
   provider to the batch route. Closed by
   `admin/protocol-mappers/add-models-unknown-provider`.

A fifth mutation turned out not to be one: replacing `protocolMapperListOrNil`
with `protocolMapperListOf` changed nothing, because `omitempty` on a slice
already drops an empty one. The helper was dead and is gone; the absent-key rule
is pinned by mutating the struct tag instead, which
`admin/clients/list` catches.

---

## 4. Parity before and after

`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1 -v`

The branch's merge base is `4419956`, which is `main` unchanged, so the number
is reported once.

| | before | after | delta |
|---|---|---|---|
| total | **179 of 498** | **200 of 498** | **+21** |

```
chapter                         before  after  delta
admin/protocol-mappers               0     21    +21
```

`admin/protocol-mappers` closes its tag outright: **21 of 21**. No other chapter
moved - `admin/clients` and `admin/client-scopes` are unchanged at 16 of 35 and
10 of 10, because everything this cut added to them is behaviour under
operations they already claim.

+21 is exactly what the plan predicted before any code was written, and the
allocation held to the operation.

Also run and green: `CGO_ENABLED=0 go test ./...`, `make lint` (both `vet`
invocations), `make oracle`, and
`go test -tags docker ./internal/store/postgres/`.
