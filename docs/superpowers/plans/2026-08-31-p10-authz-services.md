# P10 first cut: authorization services

Measured against a live Keycloak 26.7.1 on 2026-08-31, container `kc-authz`
on port 8131, removed afterwards. Every value below came off that container.

## 1. What a default container answers

This is the question the cut had to settle before anything could be planned,
because it decides whether P10 is thirty-one operations or one refusal. It is
neither of the two shapes already in the repository.

**Authorization services are reachable on a default container.** `AUTHORIZATION`
is a `DEFAULT` feature, `"enabled": true` in `GET /admin/serverinfo`, and it is
absent from `disabledFeatures`, where `CLIENT_TYPES` and
`CLIENT_SECRET_ROTATION` sit. There is no preview gate and no realm flag.

**The gate is per client, it is `authorizationServicesEnabled`, and it answers
404.** On a client without it - `account`, and every other bootstrapped client -
every path under `authz/resource-server` answers

```
404 {"error":"HTTP 404 Not Found"}    Content-Type: application/json, no Cache-Control
```

measured on eight paths: the resource server, `settings`, the four listings,
`policy/providers` and a `search`. **It runs before authorization**: a caller
holding no admin role at all gets the same 404, as do `view-authorization`,
`view-clients` and `manage-authorization`. So the ordering is `client-types`'
and not organizations'.

The flag is settable both ways and neither path seeds anything:
`POST /clients` with `"authorizationServicesEnabled": true` and a `PUT` turning
it on afterwards both produce a resource server whose `resources`, `policies`
and `scopes` are empty. There is no Default Resource, no Default Policy and no
Default Permission on a resource server the Admin API created.

So this cut is thirty-one operations, not one refusal, and the gate is a fourth
distinct shape after `client-types`' 501, organizations' realm flag and
`client-secret/rotated`'s permanent 404.

## 2. The allocation exercise

### 2.1 The description's 31

Confirmed against `internal/conformance/testdata/openapi/keycloak-26.7.1.json`:
exactly 31 operations carry no tag, and all 31 are under
`/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server`. The count
in `chapters.go` is right.

### 2.2 The stranded `management/permissions` operations are twelve, not eight

The brief named eight and the description holds **twelve**:

| operations | tag | chapter today |
|---|---|---|
| `roles/{role-name}/management/permissions` GET, PUT | `Roles` | 24 of 28 |
| `clients/{uuid}/roles/{role-name}/management/permissions` GET, PUT | `Roles` | (same row) |
| `roles-by-id/{role-id}/management/permissions` GET, PUT | `Roles (by ID)` | 8 of 10 |
| `groups/{group-id}/management/permissions` GET, PUT | `Groups` | 9 of 11 |
| `clients/{uuid}/management/permissions` GET, PUT | `Clients` | 16 of 35 |
| `identity-provider/instances/{alias}/management/permissions` GET, PUT | `Identity Providers` | 0 of 17 |

The brief's eight is the count in the three chapters it named, and that count is
right: `Roles`' four, `Roles (by ID)`' two and `Groups`' two are exactly the
unserved remainder of those three chapters. Two more are in `Clients` and two in
`Identity Providers`.

**All twelve are one measured refusal each.** `ADMIN_FINE_GRAINED_AUTHZ` is a
`DEPRECATED` feature and is disabled on a default 26.7.1 - `ADMIN_FINE_GRAINED_AUTHZ_V2`
is enabled and does not open these endpoints - so every one of the twelve
answers, on both verbs:

```
501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
```

That is byte-for-byte `client-types`' body, which `writeFeatureNotEnabled`
already emits. **They belong in this cut**: they are authorization services
wearing another tag, they need no storage, and they close three chapters.

### 2.3 The 501 does not sit in one place, and that is the finding

The refusal runs before authorization on all twelve - a caller holding no admin
role gets the 501. It does **not** run at the same point relative to the
resource the path names. Measured on an id or name that resolves to nothing:

| route | unknown resource answers |
|---|---|
| `roles/{name}/management/permissions` | **501** - the role is never looked up |
| `roles-by-id/{id}/management/permissions` | **501** - nor is it here |
| `identity-provider/instances/{alias}/management/permissions` | **501** - nor here |
| `groups/{id}/management/permissions` | **404** `Could not find group by id`, to every caller |
| `clients/{uuid}/management/permissions` | **404** `Could not find client` to a client-lister, **403** to anyone else |
| `clients/{uuid}/roles/{name}/management/permissions` | **404** `Could not find client` for the client; **501** for the role |

Five orders on one refusal, and the realm precedes all of them
(`404 {"error":"Realm not found."}`). That is the fifth time a rule stated over
"every route naming a `{something}`" has broken on a neighbouring family, and
the third time the description's tag predicts it where the path shape does not.

### 2.4 What this cut builds: 17 operations

| chapter | before | after |
|---|---|---|
| `admin/authz-resource-server` | 0 of 31 | **5 of 31** |
| `admin/roles` | 24 of 28 | **28 of 28 - closed** |
| `admin/roles-by-id` | 8 of 10 | **10 of 10 - closed** |
| `admin/groups` | 9 of 11 | **11 of 11 - closed** |
| `admin/clients` | 16 of 35 | **18 of 35** |
| `admin/identity-providers` | 0 of 17 | **2 of 17** |
| total | 294 of 526 | **311 of 526** |

The five authz operations are the resource server as a resource and the two
provider catalogues:

- `GET  .../authz/resource-server`
- `PUT  .../authz/resource-server`
- `GET  .../authz/resource-server/settings`
- `GET  .../authz/resource-server/policy/providers`
- `GET  .../authz/resource-server/permission/providers`

### 2.5 What it deliberately leaves, and why

The other 26 are the four sub-resource families - resource, scope, policy,
permission - plus `import` and the two `evaluate` endpoints. They need a store
family each and they are a second cut. The scope family was measured in full
during this cut anyway, so the next one does not have to re-measure it; the
measurements are in the handover under "measured but not built".

Serving the four listings as `[]` without the creates that fill them was
considered and rejected: it is four operations of parity for a resource server
that can never hold anything, and the listing that says `[]` would be a claim
nobody could falsify.

## 3. The measured contract this cut implements

### 3.1 `GET .../authz/resource-server`

```
200  Content-Type: application/json;charset=UTF-8   no Cache-Control
{"id":"<client uuid>","clientId":"<client uuid>","name":"<clientId string>",
 "allowRemoteResourceManagement":true,"policyEnforcementMode":"ENFORCING",
 "resources":[],"policies":[],"scopes":[],"decisionStrategy":"UNANIMOUS"}
```

- `id` and `clientId` are **both the client's internal UUID**; `name` is the
  client's `clientId` string. The representation's `clientId` is not the
  client's `clientId`.
- **The three arrays are always empty on this read**, measured with four scopes
  in the resource server. They are not a view of anything.
- No `Cache-Control`, where every sub-resource read carries `no-cache`.

### 3.2 `GET .../authz/resource-server/settings`

A different body, not a synonym:

```
200  {"allowRemoteResourceManagement":false,"policyEnforcementMode":"PERMISSIVE",
      "resources":[],"policies":[],"scopes":[{"name":"..."},...],"decisionStrategy":"AFFIRMATIVE"}
```

- It **omits** `id`, `clientId` and `name`.
- Its `scopes` **is** populated, and each entry is stripped of its `id`. It is
  the export shape.
- It needs `manage-authorization`. `view-authorization` and `view-clients` both
  read `.../resource-server` beside it and are **403** here. A read that refuses
  the view role.
- No `Cache-Control`.

On a resource server holding nothing the two bodies differ only in the three
leading keys, which is what the golden asserts.

### 3.3 `PUT .../authz/resource-server`

- Success is **204**, no body, no `Cache-Control`, no `Content-Type`.
- It writes `allowRemoteResourceManagement`, `policyEnforcementMode` and
  `decisionStrategy`.
- **`{}` is a 409** `{"error":"conflict","error_description":"Duplicate resource error"}`
  and changes nothing. A missing name on this family is a 409, not a 400 - the
  same answer `POST .../scope` gives a body with no `name`.
- An unknown field is the strict-decoder prose shape naming the class:
  `400 {"error":"Invalid json representation for ResourceServerRepresentation. Unrecognized field \"zzz\" at line 1 column 9."}`
  This is the **fifth and sixth** strict decoder, after the two required-action
  PUTs and the two organization writes.
- An **invalid enum value** is `400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}` -
  reported as a parse failure although the JSON parses.
- **No body is a 500** `unknown_error`, agreeing with `PUT /admin/realms/{realm}`
  and disagreeing with the client-policy routes' 400.

### 3.4 The two provider catalogues

`GET .../policy/providers` and `GET .../permission/providers` are
**byte-identical**, 588 bytes, verified with `cmp`. The permission catalogue is
not filtered to permission providers - it carries `regex`, `role`, `time` and
the rest.

```
[{"type":"regex","name":"Regex","group":"Identity Based"},
 {"type":"role","name":"Role","group":"Identity Based"},
 {"type":"resource","name":"Resource-Based","group":"Permission"},
 {"type":"scope","name":"Scope-Based","group":"Permission"},
 {"type":"client","name":"Client","group":"Identity Based"},
 {"type":"time","name":"Time","group":"Time Based"},
 {"type":"user","name":"User","group":"Identity Based"},
 {"type":"client-scope","name":"Client Scope","group":"Identity Based"},
 {"type":"group","name":"Group","group":"Identity Based"},
 {"type":"aggregate","name":"Aggregated","group":"Others"}]
```

Ten, where the `policy` SPI registers eleven: **`uma` is registered and is not
offered**, and `js` is absent because `SCRIPTS` is disabled. Both carry
`Cache-Control: no-cache`.

The order is a Java map's and is written out as a constant rather than computed.
`javamap.KeyOrder` gets it **wrong** - it places `client-scope` before `user` and
`aggregate` before `group`. `javamap.SizedKeyOrder(n<=9, ...)` reproduces it
exactly, so the list is a fifteenth measured key set and it is a `SizedKeyOrder`
one; the two collision chains both come back in descending alphabetical order,
which is now five such chains and still not a rule. A constant is what ships,
for the reason the argon2 keys are a constant.

### 3.5 The role sets

Measured one single role at a time on four callers - none, `view-authorization`,
`view-clients`, `manage-authorization`:

| route | opened by |
|---|---|
| `GET .../resource-server` | `view-authorization`, `view-clients`, `manage-authorization` |
| `GET .../settings` | `manage-authorization` alone |
| `PUT .../resource-server` | `manage-authorization` |
| `GET .../policy/providers`, `.../permission/providers` | as the resource-server read |

An unknown client under `authz/` is **404 `Could not find client` to a caller
who may list clients and 403 to one who may not** - Keycloak's id-phishing
branch. That is not the role-mapping routes' rule, which was re-measured
alongside as a control and still answers `Client not found` to a caller holding
nothing.

## 4. Implementation

### 4.1 Migration `0019_authz_resource_server.sql`, byte-identical in both drivers

One table. The resource server has exactly three settable fields and its
identity is the client's.

```sql
CREATE TABLE authz_resource_server (
    client_id                        TEXT PRIMARY KEY REFERENCES client(id) ON DELETE CASCADE,
    allow_remote_resource_management INTEGER NOT NULL,
    policy_enforcement_mode          TEXT NOT NULL,
    decision_strategy                TEXT NOT NULL
);
```

A row exists exactly when the client's `authorizationServicesEnabled` is on. The
flag stays on the client where it already lives; this table is the settings the
flag makes reachable, and creating the row is what turning the flag on does.

### 4.2 `internal/model`

`model.AuthzResourceServer` with the three fields and the client id.

### 4.3 `internal/store`

`AuthzRepo` with `Upsert`, `ByClientID`, `DeleteByClientID`. Both drivers, and
a `storetest` block - CI does not run the Postgres suite, and a suite that
exercises none of a cut's new code has passed here before.

### 4.4 `internal/admin/authz.go`

- `guardAuthz(roles, next)`: realm, caller, client, **the flag check**, then the
  roles. The flag check before the roles is the measured order and is
  `guardRealmFeature`'s shape rather than `guardOrganizations`'.
- The client lookup uses the phishing branch: `Could not find client` when the
  caller may list clients, 403 otherwise. That predicate is new; nothing in the
  package expresses it yet.
- `readResourceServer`, `updateResourceServer`, `readResourceServerSettings`,
  `listPolicyProviders` - and the permission catalogue is the same handler
  registered twice, which is what byte-identical means.

### 4.5 `internal/admin/managementpermissions.go`

Twelve routes, three orderings, one handler. `guardRealmFeature` already
expresses "realm, caller, then the feature refusal" and `writeFeatureNotEnabled`
already writes the body, so the roles routes and the identity-provider routes
are that combinator directly. The group and client routes need the resource
resolved first, which is `guardGroup`'s and the client lookup's existing
ordering with `writeFeatureNotEnabled` as the terminal.

### 4.6 `internal/bootstrap`

Nothing. No bootstrapped client has `authorizationServicesEnabled`, measured -
all six answer the gate's 404.

### 4.7 Conformance

Cases appended at the very end of `adminCases` and nowhere else; one fixture
appended at the very end of the map and after the last helper, creating an
authorization-services client. `PristineRealm` is not needed - none of these
bodies is a function of the whole realm.

No golden here carries a per-request value, so every case can be `Implemented`.

## 5. Discipline

- Commit before mutating. Mutation-test every claim, a different mutation per
  claim, confirm the **named** test fails, revert. A survivor is a finding about
  the test.
- The suite must break **two** parameters at once somewhere: the five orderings
  in §2.3 are exactly the shape that a one-fault-at-a-time case set passes while
  wrong.
- `make lint`, `CGO_ENABLED=0 go test ./...`, and the Postgres suite by hand.
- `make record` must move no golden that this cut did not add.
