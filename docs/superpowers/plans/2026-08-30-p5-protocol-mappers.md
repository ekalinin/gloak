# P5 cut B: protocol mappers

Date: 2026-08-30
Branch: `feat/p5-protocol-mappers`
Reference container: `kc-p5b`, `quay.io/keycloak/keycloak:26.7.1 start-dev`, port 8095.

The first cut (`docs/superpowers/plans/2026-08-29-p5-client-scopes.md`) built the
client scopes these mappers hang off. It stores all thirty-five bootstrapped
mappers in `internal/bootstrap/clientscopes.json` and serves them inside the
client scope representation. This cut makes them a resource: addressable,
writable, and served by the twenty-one operations the `Protocol Mappers` tag
names.

## 1. The allocation exercise

### 1.1 What the description says

`Protocol Mappers` holds **21** operations, and they are three identical
families of seven:

```
/admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/...     7
/admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/...  7
/admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/...               7
```

each with `models` (GET, POST), `models/{id}` (GET, PUT, DELETE),
`protocol/{protocol}` (GET) and `add-models` (POST).

### 1.2 What the server says

The brief said seven of the twenty-one are the deprecated `client-templates`
alias and told me to verify that rather than take it. I did, against the
container, and the answer is **yes on all seven and with the same single
exception the first cut found on the parent family**:

| Operation | `client-scopes` vs `client-templates` |
|---|---|
| `GET .../models` | body **and every header** byte-identical |
| `GET .../models/{id}` | byte-identical |
| `GET .../protocol/{protocol}` | byte-identical |
| `POST .../models` | 201, and **`Location` echoes `/client-templates`** |
| `PUT .../models/{id}` | 204, writes the same row |
| `DELETE .../models/{id}` | 204, same headers |
| `POST .../add-models` | 204, same headers |

The error bodies come through the alias unchanged too: an unknown scope is
`Could not find client scope`, an unknown mapper is `Model not found`, a
duplicate name is `Protocol mapper exists with same name`.

So the alias holds on this family. It does **not** follow from the first cut
having measured it on the parent - `POST /client-templates` was the one place
the two spellings were distinguishable there, and it is the one place here too,
which is a fact about how Keycloak builds `Location` from `UriInfo` rather than
a fact about either family.

I also checked the description against the server in the other direction, which
is the check the brief says neither of this week's wrong estimates had done:

- `GET .../protocol-mappers` with no sub-path is **404**
  `{"error":"HTTP 404 Not Found"}` on all three families. There is no bare
  collection the description is missing.
- Every one of the 21 the description names answers. None is a 404, none is a
  501, and none is a preview feature the way `client-types` was.

### 1.3 The allocation

**All 21.** Fourteen of them are one handler set registered under two base
paths, which is what the first cut's `for _, base := range []string{...}` loop
already does for the parent; the remaining seven are the same handlers over a
different container. The cost is one handler set, one container abstraction and
one store column, not three of anything.

Predicted parity delta: **+21**, all in `admin/protocol-mappers`.

## 2. The F63 decision, before any code

**F63 is not paid in this cut. It is sharpened, and here is the reason.**

Paying F63 means token issuance deriving its claims from the stored mappers
instead of reproducing the measured claim set directly. That code is in
`internal/token`, which is on this cut's *do not touch* list. Building a
derivation somewhere I do own and not wiring it into issuance would not be a
demonstration of anything - it would be a second truth about what a token
contains, sitting beside the first one, untested against a live server, which is
exactly the failure mode `AGENTS.md`'s boundary table records having already
happened twice in this repository.

So this is outcome (a): build the CRUD, leave the engine staged. What makes the
follow-up sharper rather than identical is two things this cut does that F63's
current text says nobody has done:

1. **The engine's input was incomplete and nobody had noticed.** F63 says the
   thirty-five client-scope mappers are stored. They are. But a **client**
   carries mappers of its own, and Gloak stores none: measured, `account-console`
   carries `audience resolve` and `security-admin-console` carries `locale` on a
   live 26.7.1, and Gloak's bootstrap creates both clients with an empty set. A
   derivation over client scopes alone would have produced the wrong claim set
   for two of the six bootstrapped clients and the fault would have looked like
   an engine bug. This cut stores them.
2. **The scope-to-mapper-to-claim correspondence is measured and written down.**
   Section 1 of the handover carries the table for all six of the default client
   scopes: which mapper produces which claim, with `claim.name`,
   `access.token.claim` and `id.token.claim` per mapper. F63 becomes a
   substitution against a table rather than a research task.

F63's text is rewritten in the handover to say both.

## 3. What was measured

Everything below came off `kc-p5b` on 2026-08-30. The full detail goes to
`docs/superpowers/handover/p5-protocol-mappers.md`; this section is the part
that decides the design.

### 3.1 The representation

`id, name, protocol, protocolMapper, consentRequired, config` - the order the
first cut already recorded from inside the client scope body, confirmed on the
dedicated routes. `config` is always present, `{}` when empty. There is no
`omitempty` anywhere on it.

### 3.2 Five things that are not what they look like

1. **`PUT .../models/{id}` writes the mapper the *body's* `id` names, not the
   one the path names.** The path id is resolved first - an unknown one is 404 -
   and then the body's id decides what is written. A PUT to mapper A carrying
   B's id answered 204 and changed **B**. A body with no `id`, or one naming a
   mapper that does not exist, is a **500**.
2. **`PUT` writes `protocolMapper` and `config` and nothing else.** `name`,
   `protocol` and `consentRequired` are read off the wire and discarded. A PUT
   renaming a mapper answers 204 and does not rename it. `config` is **replaced**,
   not merged.
3. **`consentRequired` is always `false`.** A create sending `true` reads back
   `false`. It is dead surface, not a field.
4. **The create fills in config keys the request did not send**, mirroring
   `access.token.claim` into `introspection.token.claim` and `id.token.claim`
   into `userinfo.token.claim` - the *value*, not `"true"` - and appending them.
   Whether it does so is decided by the **`protocolMapper` provider**, not by
   the mapper's `protocol`: an `oidc-*` provider declared `"protocol":"saml"`
   gets the mirrors and a `saml-*` provider declared `"protocol":"openid-connect"`
   does not. Measured across all 39 registered providers - the table is in the
   handover. Config values that are `""` or `null` are dropped before any of it.
5. **A mapper's `protocol` is not validated and its `protocolMapper` is.**
   `"protocol":"bogus"` is a 201. A `protocolMapper` outside the 39 registered
   provider ids is **404 `{"error":"ProtocolMapper provider not found"}`** - a
   404 on a create, checked before everything else including the name.

### 3.3 The error table

| Request | Status | Body |
|---|---|---|
| `POST models`, good | 201 | empty, `Location`, `Cache-Control: no-cache`, no `Content-Type` |
| `protocolMapper` absent or unknown | **404** | `{"error":"ProtocolMapper provider not found"}` |
| `name` absent or `null` | **409** | `{"error":"conflict","error_description":"Duplicate resource error"}` **and none of the five security headers** |
| `protocol` absent | **409** | the same, headers and all |
| `name` taken | 409 | `{"errorMessage":"Protocol mapper exists with same name"}`, all five headers |
| `name: ""` | 201 | accepted; the *second* empty name is the 409 above |
| empty body | 500 | `unknown_error` |
| `GET`/`PUT`/`DELETE models/{id}`, unknown id | 404 | `{"error":"Model not found"}` |
| unknown scope, any of the seven | 404 | `{"error":"Could not find client scope"}` |
| unknown client, any of the seven | 404 | `{"error":"Could not find client"}` |
| `POST add-models`, duplicate | 409 | `{"error":"conflict","error_description":"Protocol mapper name must be unique per protocol"}` |

Three 409s on one family, in three different shapes, and one of them ships
without the security headers every other response on the route carries.

`Model not found` is a **fifteenth** spelling of not-found on the admin API.

### 3.4 The guards and the resolution order

Swept one role at a time over eight candidates on ten routes.

```
read   view-clients, manage-clients        query-clients is 403
write  manage-clients
```

`query-clients` being **refused** is the finding: on `GET /client-scopes` next
door it is admitted and answered `200 []`. Same resource, one level down,
opposite treatment.

The order, measured by giving one caller one role and varying which id is bad:

```
realm -> coarse gate {view,manage}-clients (403)
      -> the container: scope or client (404)
      -> reads:  the mapper (404)
      -> writes: manage-clients (403) -> the provider (404) -> the mapper (404)
```

A caller holding nothing gets 403 even for a scope that does not exist, so the
existence leak is to a client-reading caller only - the parent family's shape.

### 3.5 The method fallback, and why it is not the parent's

`PATCH` on every protocol-mapper path answers a real **405**
`{"error":"HTTP 405 Method Not Allowed"}` with all five security headers and no
`Allow`. `PUT`, `POST`, `DELETE` and `GET` on paths that do not serve them
answer the **404** `{"error":"HTTP 404 Not Found"}`.

The parent family, measured hours ago by the first cut, answers `PUT` and
`DELETE` on `/client-scopes` with a 405. So a route family and its child
disagree, on the Admin API, three path segments apart. That is F31's sixth data
point and nothing is changed on the strength of it.

## 4. Design

### 4.1 Storage: a JSON column, and why not a table

`client_scope.protocol_mappers` is already a JSON column (migration 0014) and
`ClientScopeRepo.Update` already writes it. Migration **0015** adds the same
column to `client`. No new table.

The reason is the served order. Keycloak's mapper order inside a container is
**not reproducible across container starts** - the first cut measured six of the
fifteen scopes coming back differently - so `internal/bootstrap/clientscopes.json`
holds the recorded order and Gloak serves it verbatim, and
`admin/client-scopes/list`'s golden compares those arrays raw because F59 means
its `*/protocolMappers` mask does nothing. A normalised table would replace that
order with an `ORDER BY` and break a green golden for no gain. A column keeps the
order by construction and a mapper set is at most fourteen rows, so uniqueness
and id lookup are handler-level work over a slice rather than a query.

### 4.2 The container abstraction

One interface over "a thing that holds mappers":

```go
type mapperHolder interface {
    mappers() []model.ProtocolMapper
    setMappers([]model.ProtocolMapper)
    save(ctx) error
}
```

with a client-scope and a client implementation. Every handler is written once.
The two families differ in exactly two observable ways - the 404 for a missing
container, and the path `Location` is built from - and both are already
available to the handler (`writeClientScopeNotFound` / `writeClientNotFound`,
and `r.URL.Path`).

### 4.3 The config rules

`internal/admin/protocolmappers.go` carries the measured provider table: 39 ids
with two booleans, "mirrors access into introspection" and "mirrors id into
userinfo". Twenty-one of the twenty-four `oidc-*` providers do both;
`oidc-allowed-origins-mapper` and `oidc-audience-resolve-mapper` do the first
only; `oidc-nonce-backwards-compatible-mapper` and
`oidc-organization-membership-mapper` do neither; all fourteen `saml-*` and
`docker-v2-allow-all-mapper` do neither. The same table is the membership test
behind `ProtocolMapper provider not found`, so it is one table serving two
measured behaviours rather than a list written twice.

**Two providers seed extra config keys of their own and this cut does not
reproduce them**: `oidc-organization-membership-mapper` adds five, and
`oidc-sha256-pairwise-sub-mapper` adds a random `pairwiseSubAlgorithmSalt` that
no golden could hold anyway. Follow-up, stated in the handover.

### 4.4 Config key order: measured, reproducible, and deliberately not
reproduced here

A created mapper's `config` comes back in **Java `HashMap` order**, and the
model that reproduces it was found and verified against fourteen measured
(insertion order, served order) pairs:

```
capacity = tableSizeFor(n); if n*4 > capacity*3 { capacity *= 2 }
buckets ascending; keys colliding in a bucket in *insertion* order
```

That is **not** `internal/javamap`'s model. `javamap.capacityFor` starts at 16
and doubles, which is the no-argument constructor's behaviour and is right for
the maps it was built for; this map is constructed with an explicit size, so a
two-key config sits in a table of **four**, not sixteen. `javamap.KeyOrder`
gets 6 of these 14 vectors wrong, and both reasons are visible in one pair:
`{user.attribute, claim.name}` inserted in either order comes back
`claim.name, user.attribute` (so it is hash order, not insertion order) while
`{zz, aa, mm}` comes back in whichever order it was inserted (so a collision
chains, and javamap's alphabetical tie-break is a coin flip it loses here).

This cut does not extend `javamap`: it is outside the file set this cut owns and
a change to it reaches every recorded body that carries a Java map. Instead the
conformance cases are given config key sets **measured to be order-stable** -
where the request order and the served order coincide, which is true of every
realistic mapper config including the ones that gain a mirrored key - so the
goldens assert real bytes with no `UnorderedKeys` mask and no ordering code.
The model goes to the handover as the cut's headline measurement, with a
follow-up to fold it into `javamap` where the whole vector set can be pinned.

**No second retreat is added.** `AGENTS.md`'s "`attributes` key order is the one
thing the conformance suite does not compare" stays a set of one.

### 4.5 Adjacent surface this cut closes

- **Bootstrap**: `account-console` gains `audience resolve`,
  `security-admin-console` gains `locale`, both verbatim from the container.
- **`POST /clients` and `POST /client-scopes` accept `protocolMappers` at create
  time** and store them, ids and all - the body's mapper id wins the way the
  body's object id does. This is what lets a fixture create a scope with a
  mapper at a known id in one request.
- **`PUT /clients/{uuid}` replaces `protocolMappers`; `PUT /client-scopes/{id}`
  ignores them.** Two neighbouring updates on one API, opposite answers,
  measured in both directions. It is the third rule on `PUT /clients/{uuid}`
  that does not match its neighbour, after the two client-scope name lists it
  ignores outright.

## 5. Tasks

1. `internal/store`: migration 0015 in both drivers, `client.protocol_mappers`;
   `model.Client.ProtocolMappers`; both drivers read and write it. Run the
   Postgres suite.
2. `internal/bootstrap`: the two client mappers; seed them through the same
   path a client create uses.
3. `internal/admin/protocolmappers.go`: the container abstraction, the provider
   table, the seven handlers.
4. `internal/admin/router.go`: 21 routes, two loops.
5. `internal/admin/clients.go` / `clientscopes.go`: `protocolMappers` on the two
   creates and on `PUT /clients/{uuid}`.
6. `internal/conformance/catalog_admin.go`: the cases, appended at the end of
   `adminCases` and nowhere else.
7. `internal/conformance/fixture.go`: new fixtures at the very end of the map
   and after the last helper. Flagged in the report - the file belongs to P13
   this session.
8. `make record`, `make test`, `make lint`, `make oracle`, the Postgres suite,
   parity before and after.
9. Mutation-test every claim that a case now catches something.

## 6. What this cut does not do

- The mapper engine. Section 2.
- `javamap`'s sized-constructor model. Section 4.4.
- The two providers that seed their own config defaults. Section 4.3.
- F59's `normalize.go` fix. Another agent's file; the cases here are written so
  they do not need it - every array this cut asserts is at the root of its body,
  where `Case.Unordered` works.
