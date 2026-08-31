# P10 first cut: authorization services

Branch `feat/p10-authz-services`. Everything below was measured against a live
Keycloak 26.7.1 on 2026-08-31, container `kc-authz` on port 8131, removed when
the cut finished. `kc-logout` and `kc-listener` were other streams' and were not
touched.

Plan: `docs/superpowers/plans/2026-08-31-p10-authz-services.md`.

## 1. Measurements

### 1.1 The question the cut had to answer first

**Authorization services are reachable on a default container, and the gate is a
fourth shape.** `AUTHORIZATION` is a `DEFAULT` feature, `"enabled": true` in
`GET /admin/serverinfo`, and absent from `disabledFeatures` where `CLIENT_TYPES`
and `CLIENT_SECRET_ROTATION` sit. No preview gate and no realm flag.

What gates it is the client's own `authorizationServicesEnabled`. On a client
without it every path under `authz/resource-server` answers

```
404 {"error":"HTTP 404 Not Found"}   Content-Type: application/json, no Cache-Control
```

measured on eight paths and on four callers including one holding no admin role.
**The gate runs before authorization**, which is `client-types`' order and not
organizations'. Neither existing gate could be reused: `guardRealmFeature` has
no client, and `guardOrganizations` puts its check after the roles.

`POST /clients` with the flag and a `PUT` turning it on afterwards both produce a
resource server with `resources`, `policies` and `scopes` empty. **There is no
Default Resource, Default Policy or Default Permission** on one the Admin API
made.

### 1.2 The twelve `management/permissions` operations

The description holds **twelve**, not eight. The brief's eight is the count in
the three chapters it named, and that count is right - `Roles`' four,
`Roles (by ID)`' two and `Groups`' two were exactly the unserved remainder of
those three. Two more are tagged `Clients` and two `Identity Providers`.

**All twelve are one measured refusal each.** `ADMIN_FINE_GRAINED_AUTHZ` is a
`DEPRECATED` feature and is disabled on a default 26.7.1; `ADMIN_FINE_GRAINED_AUTHZ_V2`
is `DEFAULT` and enabled and does **not** open them. Both verbs on all six paths
answer

```
501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
```

byte for byte what `client-types` answers. The refusal precedes authorization on
all twelve - a caller holding no admin role gets the 501.

**Where it sits relative to the path's own resource is not uniform, and that is
the finding.** On an id, name or alias that resolves to nothing:

| route | answer |
|---|---|
| `/roles/{name}/management/permissions` | **501** - the role is never looked up |
| `/roles-by-id/{id}/management/permissions` | **501** - nor is it here |
| `/identity-provider/instances/{alias}/management/permissions` | **501** - nor here |
| `/groups/{id}/management/permissions` | **404** `Could not find group by id`, to every caller |
| `/clients/{uuid}/management/permissions` | **404** `Could not find client` to a client-lister, **403** to anyone else |
| `/clients/{uuid}/roles/{name}/management/permissions` | **404** for the client, **501** for the role |

Five orders on one refusal. The realm precedes all of them
(`404 {"error":"Realm not found."}`). The description's **tag** predicts it where
the path's shape does not: the two families that resolve first are tagged
`Groups` and `Clients`, which are exactly the two AGENTS.md already records as
resolving their resource before the caller.

### 1.3 `GET .../authz/resource-server`

```
200  Content-Type: application/json;charset=UTF-8   no Cache-Control
{"id":"<client uuid>","clientId":"<client uuid>","name":"<clientId string>",
 "allowRemoteResourceManagement":true,"policyEnforcementMode":"ENFORCING",
 "resources":[],"policies":[],"scopes":[],"decisionStrategy":"UNANIMOUS"}
```

- **`id` and `clientId` are both the client's internal UUID** and `name` is the
  client's `clientId` string. The representation's `clientId` is not the client's
  `clientId`.
- **The three arrays are always empty on this read**, measured against a resource
  server holding four scopes.
- No `Cache-Control`, where every sub-resource read on the family carries
  `no-cache`.

### 1.4 `GET .../settings` is a different body

- It **omits** `id`, `clientId` and `name`.
- Its `scopes` **is** populated, and each entry is stripped of its `id`. It is
  the export shape. Its order is neither name order nor insertion order and was
  not pinned.
- **It needs `manage-authorization`.** `view-authorization` and `view-clients`
  both read `.../resource-server` beside it and are **403** here. A read that
  refuses the view role.
- No `Cache-Control`.

### 1.5 `PUT .../authz/resource-server`

**`decisionStrategy` is the gate and nothing else is.** A body that does not
carry it, or carries it as `null`, answers
`409 {"error":"conflict","error_description":"Duplicate resource error"}` and
changes nothing - whatever else it holds. Measured across ten bodies: `{}`,
`{"name":"x"}`, `{"allowRemoteResourceManagement":false}`,
`{"policyEnforcementMode":"PERMISSIVE"}`, `{"id":...}` and `{"clientId":...}` are
all 409, and `{"decisionStrategy":"AFFIRMATIVE"}` **alone** is 204.

**The write replaces, and an absent field does not take the Go zero value.**
`{"decisionStrategy":"UNANIMOUS"}` against a stored `false / PERMISSIVE /
AFFIRMATIVE` produced `true / ENFORCING / UNANIMOUS`: the two absent fields went
to the Java representation's own field initialisers. Measured twice, from
`PERMISSIVE` and from `DISABLED`. Neither a merge nor a zero-value replace is
right, and the two are wrong in opposite directions on
`allowRemoteResourceManagement`.

Four refusals, four shapes:

| body | answer |
|---|---|
| no `decisionStrategy` | 409 `Duplicate resource error`, **and the five security headers are gone** |
| `"decisionStrategy":"CONSENSUS"` | **500** `unknown_error` / "For more on this error consult the server log." |
| `"decisionStrategy":"NOPE"` or `""` | 400 `unknown_error` / "Cannot parse the JSON" |
| an unknown field | 400 `Invalid json representation for ResourceServerRepresentation. Unrecognized field "zzz" at line 1 column 9.` |
| no body at all | 500 `unknown_error` |

`CONSENSUS` is a documented `decisionStrategy` and a 500. The strict decode runs
**before** the 409 gate; the 409 gate runs **before** both enum checks.

### 1.6 The two provider catalogues are byte-identical

`GET .../policy/providers` and `GET .../permission/providers` are the same 588
bytes, compared with `cmp`. The permission catalogue is **not** filtered to the
two providers whose group is `Permission`.

Ten entries where the `policy` SPI registers eleven: **`uma` is registered and is
not offered**, and `js` is absent because `SCRIPTS` is disabled.

The order is `regex, role, resource, scope, client, time, user, client-scope,
group, aggregate`. **`javamap.KeyOrder` gets it wrong** - it places `client-scope`
before `user` and `aggregate` before `group`. `javamap.SizedKeyOrder(n, ...)`
for any n up to 9 reproduces it exactly, and n>=10 does not. That makes it a
fifteenth measured key set for the package and a `SizedKeyOrder` one. Its two
collision chains, `{user, client-scope}` and `{group, aggregate}`, both come back
in **descending** alphabetical order, which is now five such chains and still not
a rule - AGENTS.md's warning that reversing the sort "would pass every vector and
still be a guess" stands, with two more vectors behind it.

It ships as a constant, for the reason the argon2 keys are a constant.

### 1.7 The role sets, swept one single role at a time

Seven callers - none, `view-authorization`, `manage-authorization`,
`view-clients`, `query-clients`, `manage-clients`, `manage-realm` - on four
routes and two verbs.

| route | opened by |
|---|---|
| `GET .../resource-server`, both provider catalogues | `view-authorization`, `manage-authorization`, `view-clients`, `manage-clients` |
| `GET .../settings`, `PUT .../resource-server` | `manage-authorization`, `manage-clients` |

Three cells surprise and none follows from a role's name:

- **`query-clients` is 403 on every one of them**, although it is in
  `clientsReadRoles` and although it *is* admitted by the client lookup on these
  very paths. The caller who may learn a client does not exist may not read its
  resource server.
- **`manage-realm` is 403 on every one of them.**
- **`manage-clients` is in both sets and `view-clients` in only the read one**,
  so the clients family and the authorization family both open this surface with
  different halves of themselves.

**The unknown client is Keycloak's id-phishing branch**, and it is caller
dependent: `view-clients`, `query-clients` and `manage-clients` see
`Could not find client`; everyone else, `manage-authorization` included, sees
403. The role-mapping routes were re-measured on the same container as a control
and still answer `Client not found` to a caller holding nothing, so AGENTS.md's
claim about those twelve routes stands and this is a neighbouring family that
inverts it.

### 1.8 `authorizationServicesEnabled` on a client

- **Absent rather than `false`** on all six bootstrapped clients. It carries
  `omitempty`, and `make record` confirmed it: no existing golden moved.
- It sits between `serviceAccountsEnabled` and `publicClient`.
- **Turning it off destroys the settings.** A resource server PUT to
  `false / PERMISSIVE / AFFIRMATIVE`, with the flag turned off and back on, came
  back `true / ENFORCING / UNANIMOUS`.

### 1.9 Measured and not built - the second cut's head start

The scope family was swept in full before the cut was scoped down. Recording it
here so the next one does not have to re-measure.

- `POST .../scope` **with a duplicate name is 201 and returns the existing
  scope**, same id. An idempotent upsert-by-name, not a conflict.
- `POST .../scope` with **no name is a 409** `Duplicate resource error` - the
  same answer the resource-server PUT gives a body with no `decisionStrategy`.
  `{"name":""}` is a **201** creating a scope named the empty string.
- **The body's `id` wins**, a third endpoint after `POST /client-scopes` and
  `POST /clients`.
- The 201 carries **no `Location`**.
- Field order is `id, name, iconUri, displayName` - not the order a create sends
  them in.
- `{` is `invalid_request` / "Cannot parse the JSON"; an empty body is a 500
  `unknown_error`; an unknown field is the strict prose shape.
- **`GET .../scope/{unknown}` is a 404 with an empty body and no `Content-Type`**,
  which is not one of the twenty-one spellings of not-found but the absence of
  one. It carries `Cache-Control: no-cache`; the `PUT` and `DELETE` 404s on the
  same path carry none. **Two 404s on one resource differing only in
  `Cache-Control`, and there the method does decide it.**
- `.../scope/search?name=` is **exact and returns a bare object**, 204 on a miss
  and 400 with an empty body when `name` is absent or empty. The listing's
  `?name=` beside it is a **case-insensitive substring**. Two `name` parameters
  on one family, two meanings.
- The listing is **sorted by name** and pages on `first`+`max`.
- **`PUT` on a scope replaces** - a body omitting `displayName` drops it - and
  **ignores the body's `id`**: a PUT addressed to scope A carrying scope B's id
  changed A and left B alone. That is the **opposite** of
  `PUT .../protocol-mappers/models/{id}`, which writes the body's id.
- `DELETE` success is 204 with **no `Cache-Control`**, a seventh measured delete.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **Authorization services are a per-*client* gate that runs before
  authorization, and that is a fourth shape.** A client without
  `authorizationServicesEnabled` answers `404 {"error":"HTTP 404 Not Found"}` on
  every path under `authz/resource-server`, to every caller including one holding
  no admin role. `AUTHORIZATION` itself is a `DEFAULT` enabled feature, so this
  is not `client-types`' disabled preview and not organizations' realm flag -
  which is measured rather than inferred, because the two existing gates
  disagree about the very thing this one had to settle. The body is the one this
  file already attributes to a wrong method on a known path, so **that bullet's
  two producers are three**: an unmatched path, a wrong verb, and a correct
  request to a resource that is switched off. A shared helper reading the body
  as "you sent the wrong verb" is wrong here.
- **All twelve `management/permissions` operations are a 501 and that is the
  contract.** `ADMIN_FINE_GRAINED_AUTHZ` is a `DEPRECATED` feature and is
  disabled on a default 26.7.1. `ADMIN_FINE_GRAINED_AUTHZ_V2` is enabled,
  `DEFAULT`, and does **not** open them - so `GET /admin/serverinfo` reports one
  of the pair enabled and the endpoints follow the other. The body is
  byte-identical to `client-types`', and like it the refusal precedes
  authorization. Twelve operations across five tags, and nothing in any of them
  will ever be implemented on a default container.
- **The 501 sits in five different places, and the description's tag is what
  predicts it.** `roles`, `roles-by-id` and `identity-provider/instances` never
  look their resource up at all; `groups` answers `Could not find group by id`
  first, to every caller; `clients` answers `Could not find client` first, but
  only to a caller who may list clients, and 403 to everyone else; and
  `clients/{uuid}/roles/{name}` resolves the client and **not** the role. One
  refusal, one API, five orders. **That is the fifth time a rule stated over
  "every route naming a `{something}`" has broken on a neighbouring family**, and
  the third time the tag rather than the path shape has been the thing that
  predicts it - the two that resolve first are tagged `Groups` and `Clients`,
  which this file already records as the families that resolve before the caller.
  Writing one combinator for the twelve is the saving, and it is wrong on six of
  them whichever ordering it picks.
- **A read that refuses the view role.**
  `GET .../authz/resource-server/settings` needs `manage-authorization` or
  `manage-clients`; `view-authorization` and `view-clients` read
  `GET .../authz/resource-server` immediately beside it and are 403 on this one.
  This file's "Reads accept the manage role, not just the view role" describes
  the plain reads correctly and does not reach here, and the two routes are one
  path segment apart. Sharing a role list between them is the tidy-up that opens
  a settings export to a read-only caller.
- **`query-clients` may learn a client does not exist and may not read it.** On
  `/clients/{uuid}/authz/...` an unknown client is `Could not find client` to
  `view-clients`, `query-clients` and `manage-clients` and a bare 403 to everyone
  else - Keycloak's id-phishing branch, and the one place in `internal/admin`
  where a 404's *body* depends on the caller. But `query-clients` is then 403 on
  the resource server of a client that does exist. So the coarse gate that
  decides the 404 is **not** the role set that opens the route, although both
  hang off the same path. `manage-realm` opens neither.
- **`PUT /clients/{uuid}` merges every field except
  `authorizationServicesEnabled`.** Measured on a client carrying six non-default
  values: `PUT {"description":"touched"}` left `serviceAccountsEnabled`,
  `implicitFlowEnabled`, `consentRequired`, `fullScopeAllowed`, `publicClient`,
  `webOrigins` and `attributes` exactly as they were and **turned this one flag
  off**, destroying the resource server with it. So this file's "`PUT` on a
  client or a user merges" is true of the other hundred fields and false of this
  one, and an omitted value means `false` here and "unchanged" everywhere else on
  the same body. The reason is that the flag is not a field at all: it is whether
  the client has a resource server. Leaving it in the merge is the obvious
  implementation and it makes the flag impossible to turn off.
- **`authorizationServicesEnabled` is absent rather than `false`**, on all six
  bootstrapped clients - the same rule `protocolMappers` follows and the opposite
  of every boolean around it, which all appear as `false`. Emitting it for
  symmetry with `serviceAccountsEnabled` beside it moves every client golden in
  the repository.
- **`PUT .../authz/resource-server` is gated by `decisionStrategy`, replaces
  rather than merges, and an absent field takes the Java representation's own
  initialiser.** A body without `decisionStrategy` - or with it `null` - is a
  409 `Duplicate resource error` and changes nothing, whatever else it holds;
  `{"decisionStrategy":"AFFIRMATIVE"}` alone is a 204. And
  `{"decisionStrategy":"UNANIMOUS"}` against a stored
  `false / PERMISSIVE / AFFIRMATIVE` produces `true / ENFORCING / UNANIMOUS`.
  A merge keeps `false / PERMISSIVE`; a Go zero-value replace produces
  `false / ""`. Both are wrong, and they are wrong in **opposite directions** on
  `allowRemoteResourceManagement`, so a test checking one field passes one of
  them.
- **`CONSENSUS` is a documented `decisionStrategy` and a 500.** `AFFIRMATIVE` and
  `UNANIMOUS` answer 204; `CONSENSUS` answers `500 unknown_error`, measured three
  times. An *unknown* value is a 400 whose description is "Cannot parse the JSON"
  for a body that parses. Three answers to one field, and the middle one is
  Keycloak's own defect - the same family as `POST /users` with an empty body.
- **The two reads of a resource server are two bodies.**
  `GET .../authz/resource-server` carries `id`, `clientId` and `name` and its
  `resources`, `policies` and `scopes` are **always empty** - measured against a
  resource server holding four scopes. `GET .../settings` carries none of the
  three keys and its `scopes` is populated, with each entry stripped of its `id`.
  On an empty resource server the two differ only in the three leading keys,
  which is exactly what makes one serialiser with `omitempty` look right.
  And **neither carries `Cache-Control`** where every sub-resource read on the
  family carries `no-cache`, so "the authz family caches nothing" is a claim two
  routes falsify.
- **Neither `id` nor `clientId` on a resource server means what it says.** Both
  are the client's internal UUID, the same value twice, and `name` is the
  client's `clientId` string. Filling `clientId` from `model.Client.ClientID`
  produces a body that reads correctly and is wrong.
- **`permission/providers` is not filtered to permission providers.** It is
  byte-identical to `policy/providers`, 588 bytes, compared with `cmp` - `regex`,
  `role`, `time` and the rest included. Ten providers where the `policy` SPI
  registers eleven: **`uma` is registered and never offered**, and `js` is absent
  because `SCRIPTS` is disabled. The order is a Java map's and
  **`javamap.KeyOrder` gets it wrong**; `SizedKeyOrder` at any table asked for
  nine entries or fewer places it exactly. Its two collision chains are the fifth
  and sixth measured to come back in descending alphabetical order, which still
  is not a rule - a realm's `attributes` has one that goes the other way.
- **A 409 `Duplicate resource error` sends none of the five security headers.**
  Measured on `PUT .../authz/resource-server` and already recorded on the
  protocol mappers' create, and the three *other* refusals on that same authz
  route - the strict 400, the bad-enum 400 and the `CONSENSUS` 500 - all carry
  the five. So the omission belongs to that response shape rather than to the
  endpoint, the status class or the verb. It is a fifth exception and the
  security-header bullet lists four.

## 3. Follow-up dispositions

- **F95 - a client's `attributes` is serialised from a Go map. Not closed, and
  not touched.** It was in scope to close in passing and this cut did not: the
  `model.StringMap` move changes what five `admin/clients/*` goldens assert, and
  those five goldens are the ones this cut had to prove it had **not** moved when
  it added `authorizationServicesEnabled` to the same representation. Doing both
  in one branch would have made "`make record` moved no existing golden" - the
  evidence that the `omitempty` is right - unavailable. F95 stays open and is a
  one-file change on a branch of its own.
- **F110 - "in memory" elsewhere.** Read for the precedent and it does not apply.
  A resource server is persisted by Keycloak and exposed through the Admin API,
  which is F110's own test for "this is a divergence rather than a faithful
  copy", so this cut gave it a table (`0019_authz_resource_server.sql`) rather
  than a map. No new entry.
- **New: `internal/httpx`'s `WriteJSONCharset` doc comment** still repeats the
  corrected charset reason. That is F111 and this cut did not touch it.
- **New, worth filing: `GET .../authz/resource-server/settings` exports scopes in
  an order nothing explains.** Neither name order, insertion order nor id order
  fitted the four measured. It is not reachable from anything this cut serves -
  Gloak has no route that creates a scope - so it is a measurement the second cut
  inherits rather than a gap.
- **New, worth filing: `CONSENSUS`'s 500 is reproduced from three probes and no
  mechanism.** It behaves like a persister that cannot store the third enum
  value, and nothing was found that says so. It is pinned as a measurement.

## 4. Parity, before and after

| chapter | before | after |
|---|---|---|
| `admin/authz-resource-server` | 0 of 31 | **5 of 31** |
| `admin/roles` | 24 of 28 | **28 of 28 - closed** |
| `admin/roles-by-id` | 8 of 10 | **10 of 10 - closed** |
| `admin/groups` | 9 of 11 | **11 of 11 - closed** |
| `admin/clients` | 17 of 35 (16 served, 1 recorded) | **19 of 35** |
| `admin/identity-providers` | 0 of 17 | **2 of 17** |
| **total** | **294 of 526** | **311 of 526** |

Three chapters closed outright. The 26 operations of the authz surface this cut
leaves are the resource, scope, policy and permission families, `import` and the
two `evaluate` routes; §1.9 above is the scope family already measured for them.
