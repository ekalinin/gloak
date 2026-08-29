# P5, first cut: client scopes

Date: 2026-08-29
Status: complete
Branch: `feat/p5-client-scopes`
Reference container: `kc-p5`, `quay.io/keycloak/keycloak:26.7.1`, port 8091

## 1. What P5 actually builds

The roadmap allocates P5 six OpenAPI tags totalling 75 operations. Those six tag
counts were re-derived from
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and they hold
exactly:

```
Client Scopes                  10
Protocol Mappers               21
Scope Mappings                 33
Client Attribute Certificate    7
Client Initial Access           3
Client Registration Policy      1
                               --
                               75
```

P4's row said "Realms Admin 45" and the real answer was 16. The same exercise
here gives a different shape of answer: **P5's 75 is very nearly right as a
denominator, but it is not 75 distinct behaviours, and it is not the whole of
what P5 builds.** Three separate corrections, worked out per operation below.

### 1.1 Forty-three of the 75 are the same routes spelled twice

`client-templates` is a deprecated path alias for `client-scopes`. The
description lists both spellings as separate operations, and the vendored file
therefore double-counts three tags:

| Tag | Distinct behaviours | Alias duplicates | Tag total |
|---|---|---|---|
| Client Scopes | 5 | 5 | 10 |
| Protocol Mappers | 14 (7 shapes on two locators) | 7 | 21 |
| Scope Mappings | 22 (11 shapes on two locators) | 11 | 33 |

Measured, not assumed. On the live container:

```
GET    /admin/realms/master/client-templates            -> 200, the same 15 scopes
GET    /admin/realms/master/client-templates/{id}       -> 200, byte-identical body
DELETE /admin/realms/master/client-templates/{id}       -> 204, the scope is gone
```

This does not reduce the denominator - the meter counts operations the
description names, and it names them - but it changes what the number means.
Twenty-three of P5's 75 operations are five `mux.HandleFunc` lines pointing at
handlers that already exist. **The Size column overstates P5's work by about a
third.** Nothing needs changing in the roadmap's arithmetic; it needs saying in
the roadmap's prose, and it is in the handover.

### 1.2 One operation belongs to P9, not P5

`POST /admin/realms/{realm}/identity-provider/upload-certificate` carries the
tag `Client Attribute Certificate`. It is not a client attribute certificate. It
is an identity-provider operation that shares a Java resource class with the
client keystore endpoints, and it has no `{client-uuid}` in its path. It belongs
with `Identity Providers` in **P9**.

The remaining six of that tag are the client keystore: generate, download,
upload, upload-certificate, generate-and-download and the read, all under
`/clients/{client-uuid}/certificates/{attr}`. The two `attr` values that exist
are `jwt.credential` (private-key-JWT client authentication, which is **P7**'s
grant) and `saml.signing` (**P11**). They are counted in P5 because P5 owns the
client's key material; nothing in this cut reaches them.

### 1.3 Twelve operations P5 builds are counted in other tags

The reverse of the P4 exercise. These are client-scope behaviour under tags
already allocated elsewhere:

| Operation | Tag | Counted in | Built by |
|---|---|---|---|
| `GET /admin/realms/{realm}/default-default-client-scopes` | Realms Admin | P4 | **P5** |
| `PUT /admin/realms/{realm}/default-default-client-scopes/{clientScopeId}` | Realms Admin | P4 | **P5** |
| `DELETE /admin/realms/{realm}/default-default-client-scopes/{clientScopeId}` | Realms Admin | P4 | **P5** |
| `GET /admin/realms/{realm}/default-optional-client-scopes` | Realms Admin | P4 | **P5** |
| `PUT /admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}` | Realms Admin | P4 | **P5** |
| `DELETE /admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}` | Realms Admin | P4 | **P5** |
| `GET /admin/realms/{realm}/clients/{client-uuid}/default-client-scopes` | Clients | P2 | **P5** |
| `PUT .../clients/{client-uuid}/default-client-scopes/{clientScopeId}` | Clients | P2 | **P5** |
| `DELETE .../clients/{client-uuid}/default-client-scopes/{clientScopeId}` | Clients | P2 | **P5** |
| `GET /admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes` | Clients | P2 | **P5** |
| `PUT .../clients/{client-uuid}/optional-client-scopes/{clientScopeId}` | Clients | P2 | **P5** |
| `DELETE .../clients/{client-uuid}/optional-client-scopes/{clientScopeId}` | Clients | P2 | **P5** |

The roadmap already says the first six: P4's row reads "the rest is P5's client
scopes". The `Clients` six were not called out anywhere and are the discovery.
`2026-08-22-p2-admin-api-core-design.md` §1.1 allocated 45 of the `Clients`
tag's 69 elsewhere without naming these individually.

A further seven `Clients` operations - the `evaluate-scopes/*` family - are
scope evaluation and are P5's too, but they need the protocol-mapper engine and
so belong to a later cut. They are named here so the next cut does not have to
re-derive them.

### 1.4 The allocation, stated

P5 **builds** 75 + 12 = **87 operations**, of which 23 are path aliases over
handlers it already wrote and one (`identity-provider/upload-certificate`)
should move to P9. Working behaviours: 63.

## 2. The cut

Three cuts are visible. This branch is cut A.

| Cut | Contents | Ops |
|---|---|---|
| **A (this branch)** | The `Client Scopes` tag, the realm's two default sets, the client's two scope sets, and F49 | **22** |
| B | Protocol Mappers 21 - which needs the mapper *engine*, because roadmap §6's staged token claims land here | 21 |
| C | Scope Mappings 33, then certificates 7, initial access 3, registration policy 1 | 44 |

Cut A is 22 operations: `Client Scopes` 10, `Realms Admin` 6, `Clients` 6. It is
the coherent slice because it is the one that is **closed**: nothing in it needs
an endpoint outside it, and everything outside it needs something in it. A
protocol mapper hangs off a client scope; a scope mapping hangs off a client
scope; `evaluate-scopes` needs both. The client scope is the object all of P5
stands on.

It is also where F49 is, which is the part of P5 already observable from
endpoints that already ship.

The brief's guess was "the `Client Scopes` tag plus the realm-level
default/optional scope routes". The allocation exercise adds the six
client-level routes to that, for one reason: F49's fix makes a created client
inherit the realm's default scopes, and **the client-level routes are the only
way to observe what it inherited** other than the client representation itself.
Shipping the inheritance without the routes that read and write it would be a
half-built resource.

## 3. What was measured

Every value below came off `kc-p5` on 2026-08-29. Full transcripts are in the
handover; this section is the part that decides the design.

### 3.1 The representation

Listing and single read return the same body. Key order:

```
id, name, description, protocol, attributes, protocolMappers
```

- `description` is **absent** when unset, not `""`.
- `attributes` is **always present**, `{}` when empty.
- `protocolMappers` is **absent** when the scope has none. `offline_access` is
  the one bootstrapped scope with no mappers and its body has five keys, not six.

A protocol mapper's key order is `id, name, protocol, protocolMapper,
consentRequired, config`. `config` is a Java map.

The realm's two default listings use a **different, briefer** shape:
`id, name, protocol` - three keys, no attributes, no mappers. The client's two
listings use a **third**: `id, name` - two keys, no protocol. Three shapes of one
object, and a shared serialiser would be wrong on two of them.

### 3.2 Every measured status on the cut's routes

`POST /client-scopes`:

| Body | Status | Body |
|---|---|---|
| `{"name":"x","protocol":"openid-connect"}` | 201 | empty, absolute `Location`, `Cache-Control: no-cache` |
| `{"name":"x"}` | 400 | `{"errorMessage":"Unexpected protocol"}` |
| `{"name":"x","protocol":"bogus"}` | 400 | `{"errorMessage":"Unexpected protocol"}` |
| `{"protocol":"openid-connect"}` | **500** | `{"error":"unknown_error",...}` |
| `{}` | **500** | same |
| `""` / `null` | **500** | same |
| `{"name":"","protocol":"openid-connect"}` | 400 | `{"errorMessage":"Unexpected name \"\" for ClientScope"}` |
| `{` | 400 | `{"error":"invalid_request","error_description":"Cannot parse the JSON"}` |
| duplicate name | 409 | `{"errorMessage":"Client Scope x already exists"}` |

An absent `protocol` and an invalid one give the identical message. A missing
`name` is a 500 - Keycloak's own defect, the same family as `POST /users` with
an empty body.

`PUT /client-scopes/{id}`: 204 on success (no `Cache-Control`), 404
`{"error":"Could not find client scope"}` on an unknown id, 409 on a taken name,
400 on a malformed body, **500 when the body omits `name`**.

`DELETE /client-scopes/{id}`: 204 with `Cache-Control: no-cache`, 404
`Could not find client scope` on an unknown or already-deleted id.

`GET /client-scopes/{id}`: 200 `application/json;charset=UTF-8` +
`Cache-Control: no-cache`; 404 `Could not find client scope` for an unknown id
**and for a non-UUID id**.

Realm default sets: `PUT` 204 first time, **409
`{"error":"conflict","error_description":"Duplicate resource error"}` the second**
- and also 409 for putting into the *other* list a scope already in one of them.
`DELETE` 204 whether or not the scope was in the list, 404
`{"error":"Client scope not found"}` for an unknown scope id.

Client scope sets: `PUT` 204 always, including the second time; `DELETE` 204
always; 404 `{"error":"Client scope not found"}` for an unknown scope id, 404
`{"error":"Could not find client"}` for an unknown client.

### 3.3 The four behaviours that decide the model

**A client's default and optional lists are one attachment carrying a flag.**
`PUT default-client-scopes/{phone}` when `phone` is already the client's
*optional* scope answers 204 and changes nothing. To move a scope you must
`DELETE` it from one list and `PUT` it into the other.

**The `DELETE` ignores which list its path names.** `DELETE
default-client-scopes/{organization}` removed `organization` from the client's
**optional** list. The same holds on the realm routes. So the `PUT` is
list-specific and the `DELETE` is not.

**Attachment is filtered by protocol, silently.** `PUT
default-client-scopes/{role_list}` - a `saml` scope - onto an `openid-connect`
client answers 204 and attaches nothing; the client representation confirms it.
A `saml` client created bare inherits `AuthnContextClassRef, role_list,
saml_organization` and no optionals, where an `openid-connect` client inherits
the six and the five.

**Deleting a client scope cascades**: it leaves every client's lists and both
realm lists. A built-in scope can be deleted with no protection at all.

### 3.4 The guards, and the ordering, which are not what they look like

Swept one role at a time over a probe user holding exactly one `master-realm`
role, across eight candidate roles.

| Route | Read | Write |
|---|---|---|
| `GET /client-scopes` | `view-clients`, `manage-clients`; `query-clients` gets **200 and an empty array** | - |
| `GET /client-scopes/{id}` | `view-clients`, `manage-clients` | - |
| `POST`/`PUT`/`DELETE /client-scopes[/{id}]` | - | `manage-clients` alone |
| `GET /default-{default,optional}-client-scopes` | `view-clients`, `manage-clients` | - |
| `PUT`/`DELETE /default-*-client-scopes/{id}` | - | `manage-clients` alone |
| `GET /clients/{u}/{default,optional}-client-scopes` | `view-clients`, `manage-clients` | - |
| `PUT`/`DELETE /clients/{u}/*-client-scopes/{s}` | - | `manage-clients` alone |

Two findings in that table.

**The `Realms Admin` routes are guarded by the clients family.** `view-realm`
and `manage-realm` are 403 on `default-default-client-scopes`, both verbs, both
lists. The tag says Realms Admin and the guard says clients.

**`query-clients` gets a filtered listing, not a refusal.** 200 with `[]` where
`view-clients` gets 200 with 15. That is the third instance of the
"200 with a shorter list to a weaker caller" shape this project has met.

The **ordering** differs between the two families, on the same missing object:

```
/client-scopes/{id}                       realm -> coarse gate -> SCOPE (404) -> fine role (403)
/clients/{u}/*-client-scopes/{s}          realm -> coarse gate -> CLIENT (404) -> fine role (403) -> SCOPE (404)
/default-*-client-scopes/{id}             realm -> fine role (403) -> SCOPE (404)
```

Measured directly: `view-clients` + an unknown scope id on `DELETE
/client-scopes/{id}` is **404**, and the same caller on an **existing** scope is
403. On `/clients/{u}/default-client-scopes/{s}` the same caller gets 403 for an
unknown scope and 404 for an unknown client. On
`/default-default-client-scopes/{id}` it gets 403 for an unknown scope where
`manage-clients` gets 404.

The coarse gate is `{view-clients, query-clients, manage-clients}`.
`create-client` is **not** in it: it answers 403 to everything including the
paths where `query-clients` gets a 404.

And the missing scope has **two spellings**: `Could not find client scope` from
`/client-scopes/{id}`, `Client scope not found` from both the realm routes and
the client routes. One object, two answers, decided by which route went looking.

### 3.5 The 405 that is real

Four verbs on two paths, all four a genuine 405:

```
PUT    /admin/realms/master/client-scopes        405 {"error":"HTTP 405 Method Not Allowed"}
DELETE /admin/realms/master/client-scopes        405 same
POST   /admin/realms/master/client-scopes/{id}   405 same
PATCH  /admin/realms/master/client-scopes/{id}   405 same
```

`application/json`, all five security headers, no `Allow`, no `Cache-Control`.
This is a fourth data point for F31 and the first where a whole route family
answers 405 uniformly. Nothing is changed on the strength of it; it goes in the
handover.

### 3.6 The bootstrap data

A realm created through the API has the **same 15 client scopes as master,
byte-identical modulo the UUIDs**, with the same protocol-mapper sets, the same
attributes and the same two default lists. Verified by dumping both and
comparing after stripping ids and sorting mappers by name: zero differences
across all 15.

So one vendored file serves every realm. The realm's own default membership:

```
default   role_list, saml_organization, AuthnContextClassRef,
          profile, email, roles, web-origins, acr, basic          (9)
optional  offline_access, address, phone, microprofile-jwt,
          organization                                            (5)
```

**Nine, not six.** The six in `bootstrap.defaultScopeNames` are the six
`openid-connect` ones; the three SAML ones are in the realm's default set and
are filtered out when an `openid-connect` client inherits.

## 4. F49

**Closed in this cut.** Keycloak fills a client's two scope lists from the
realm's default sets, filtered by the client's protocol, when the request body
does not name them. Measured in all three directions:

```
{"clientId":"x"}                            -> the realm's 6 openid-connect defaults + 5 optionals
{"clientId":"x","defaultClientScopes":[]}   -> []      an explicit empty list is honoured
{"clientId":"x","defaultClientScopes":["email"]} -> ["email"]   nothing is added
{"clientId":"x","protocol":"saml"}          -> the realm's 3 saml defaults, no optionals
```

So `null` means "inherit" and `[]` means "none". Go's `encoding/json` gives a
`[]string` field `nil` for both an absent key and `null`, and a non-nil empty
slice for `[]`, so the distinction survives without a pointer - but `nonNil()`
in `newClientFrom` destroys it today and has to move after the inheritance
decision.

An unknown scope name in the body is accepted with 201 and silently dropped.
Naming an *optional* scope as a default is accepted and it becomes a default.

Closing F49 makes `admin/clients/read-created` and `admin/clients/read-described`
start matching their goldens. Both are `Recorded`, and a `Recorded` case that
matches is a hard failure, so **both must flip to `Implemented` and lose their
`Reason` in the same commit.** That is a mid-file edit to `catalog_admin.go`,
which this brief otherwise forbids; it is unavoidable and is flagged in the
handover.

## 5. Tasks

Each task ends green. Commit before mutating anything.

**T1 - store: the client scope model.**
`model.ClientScope`, `model.ProtocolMapper`. `0014_client_scope.sql` in both
migration dirs: `client_scope` (id, realm_id, name, description, protocol,
attributes JSON, protocol_mappers JSON, unique on (realm_id, name)),
`realm_default_client_scope` (realm_id, client_scope_id, default_scope BOOL),
`client_client_scope` (client_id, client_scope_id, default_scope BOOL).
`store.ClientScopeRepo` on `store.Store`; both drivers; `storetest` subtests.

Protocol mappers are a JSON column in this cut, not a table. They are read-only
until cut B builds their CRUD, and a column is the smallest thing that lets the
representation be reproduced from stored state. Cut B replaces it or keeps it.

**T2 - bootstrap the 15 scopes.**
`internal/bootstrap/clientscopes.json`, embedded, holding the measured 15 with
their mappers and attributes in Keycloak's key order and the two default name
lists. `CreateRealm` creates them and the realm's default membership. The
`attributes` and `config` maps are stored and emitted as **ordered pairs**, not
Go maps, so no `UnorderedKeys` mask is needed on the bootstrapped bodies - the
same technique `internal/admin` already uses for the five argon2 keys.

**T3 - `internal/admin/clientscopes.go`: the `Client Scopes` tag.**
Five handlers, ten routes (both path spellings). The coarse gate then the scope
resolution then the fine role, in that order, because §3.4 measured it.

**T4 - the realm's two default sets.** Six routes. Role first, scope second.

**T5 - the client's two scope sets.** Six routes. Client first, role second,
scope third. The `DELETE` ignores its own list, per §3.3.

**T6 - F49.** `newClientFrom` inherits when the body's list is nil, filtered by
protocol. Flip the two `Recorded` client cases.

**T7 - conformance cases and goldens.** Appended at the end of `adminCases`.
`make record`; never hand-edited.

**T8 - handover and PR.** Done: `docs/superpowers/handover/p5-client-scopes.md`.

## 7. What it cost, against what the plan said

All eight tasks landed and the cut is 22 operations, 147 -> 169 of 489. Three
things the plan did not foresee:

- **F49 was six defects, not one.** A client created through the Admin API had
  the wrong `standardFlowEnabled`, `fullScopeAllowed`, `protocol`,
  `nodeReRegistrationTimeout` and `name`, and gave a public client a
  `client.secret.creation.time`. The scopes could not be fixed without the
  protocol, because the inheritance filter matches on it.
- **Inheritance is all-or-nothing across the two lists**, not per list. Section
  1.7 of the handover has the nine bodies that say so.
- **`Case.Unordered` cannot sort a nested array inside one it sorts at the
  root**, silently. The listing case masks the protocol mappers and a Go test
  in `internal/admin` asserts one scope's directly. Filed as F58.

## 6. What this cut deliberately does not do

- **No protocol mapper CRUD.** The mappers are stored and served as part of the
  scope, and no endpoint writes them. Cut B.
- **No mapper engine.** Roadmap §6's staged token claims stay staged: token
  issuance still reproduces the measured claim set directly and does not derive
  it from the mappers this cut stores. Storing them is the prerequisite, not the
  work.
- **`scopes_supported` stays a constant.** Roadmap §6's second debt. It should
  be derived from the realm's client scopes and now could be; it is not in this
  cut because it is an `oidc` change and `internal/oidc` is another agent's file
  this session.
- **No scope mappings, certificates, initial access or registration policy.**
- **`evaluate-scopes` is not touched.**
