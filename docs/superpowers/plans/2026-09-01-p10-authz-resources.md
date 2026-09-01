# P10 third cut: the authorization-services resource family

Branch `feat/p10-authz-resources`, off `main` at 94f0d20. Every value below was
measured against a live Keycloak 26.7.1 on 2026-09-01, container `kc-authz` on
port 8154, removed when the cut finishes. Port 8155 belongs to another stream
and was not touched. The container answering 8154 was confirmed to be this one
before any probe was believed: `GET /admin/serverinfo` reported 26.7.1 at 27
seconds of uptime, which is the check five cuts have lost probes to skipping.

Previous cuts: `docs/superpowers/handover/p10-authz-services.md` (thirteen
operations), `docs/superpowers/handover/p10-authz-cut-b.md` (the scope family,
eight).

## 1. What a policy and a permission actually require on a default container

This is the question the brief asks first, because F129 asserts that policy and
permission "need a provider model before `POST` means anything" and whether that
is one provider type or several decides the size of this cut.

**F129 is wrong about that, and the answer is smaller than it says.** A policy
and a permission need exactly one thing: a `type` naming an accepted provider.
Nothing else is required and no provider model has to exist first.

```
POST .../policy      {}                          409 Duplicate resource error
POST .../policy      {"name":"p1"}               409 Duplicate resource error
POST .../policy      {"name":"p2","type":"role"} 201
POST .../permission  {"name":"x","type":"resource"} 201
```

`type` is the gate on both endpoints, exactly the way `decisionStrategy` is the
gate on `PUT .../authz/resource-server`. A body with no `type` is the 409
whatever else it holds, including a name.

**The accepted type set is nine and it is not the provider catalogue's ten.**
Swept one type at a time on both endpoints, with identical answers on each:

```
regex role resource scope client time group aggregate uma   201
user client-scope js <unknown> ""                           500 unknown_error /
                                                            "For more on this error
                                                             consult the server log."
```

So `uma` is accepted and is **not** offered by `GET .../policy/providers`, while
`user` and `client-scope` **are** offered there and answer a 500. The catalogue
this repository already ships as a constant is therefore not the accepted set in
either direction, and a validator built from it would refuse one working type and
admit two that fail.

That makes the policy and permission families cheap in the sense F129 was worried
about - but three other measurements make them expensive again, and they are the
reason this cut does not take them:

- **One row serialises two ways and the path decides.** `GET .../policy` carries
  `config`; `GET .../permission` does not and carries the provider's own typed
  fields instead. `GET .../permission/search?name=<a role policy>` answers
  `"roles":[]` where `GET .../policy/search` on the same row answers
  `"config":{"roles":"[]"}`. Reproducing that needs a typed representation per
  provider - nine of them - which is the provider model F129 asked about, sitting
  one layer further out than it thought.
- **`GET .../policy` and `GET .../permission` are not permanently `[]`.** They
  are ordinary listings, empty on a fresh resource server only because nothing has
  been created. The premise the second cut declined them on does not hold.
- **The two `evaluate` operations mint an RPT.** `POST .../policy/evaluate`
  answers 200 with a whole access token inside it - `exp`, `iat`, `jti`, `sid`,
  the caller's realm and client roles - so it is the authorization engine, not a
  representation. It cannot be `Recorded` without masking four per-request values,
  and it cannot be served without evaluating policies.

**Decision: this cut takes the resource family's nine operations and stops
there.** Policy 4, permission 4 and import 1 are deferred with their measurements
banked in the handover, which is the rhythm the first two cuts already
established - the first cut swept the scope family in full and the second started
from measurements rather than from the tag.

## 2. Scope

Nine operations, all under
`/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server`:

```
GET    /resource
POST   /resource
GET    /resource/search
GET    /resource/{resource-id}
PUT    /resource/{resource-id}
DELETE /resource/{resource-id}
GET    /resource/{resource-id}/attributes
GET    /resource/{resource-id}/permissions
GET    /resource/{resource-id}/scopes
```

And two already-served routes that this cut's own data makes wrong, both fixed
here rather than filed:

- **`GET .../settings` serves `"resources":[]` unconditionally** and Keycloak
  populates it. Nothing caught it because no fixture had a resource to put in it.
- **`GET .../scope/{id}/resources` serves `[]` unconditionally** and Keycloak
  lists the resources naming that scope. Same reason.

Not taken, with the reason each: `GET`/`POST .../policy`, `.../policy/search`,
`GET`/`POST .../permission`, `.../permission/search` (the typed representation
per provider, §1); `POST .../policy/evaluate`, `POST .../permission/evaluate`
(the engine, §1); `POST .../import` (a 204 that replaces the settings and adds
rows from all four families, so it is meaningless before policies exist).

## 3. Measurements this cut implements

### 3.1 The representation

```
POST .../resource {"name":"r2","displayName":"R Two","type":"urn:t",
                   "uris":["/a","/b"],"icon_uri":"http://i",
                   "ownerManagedAccess":true,"attributes":{"k1":["v1"],"k2":["v2"]},
                   "scopes":[{"name":"s1"}]}

201 {"name":"r2","type":"urn:t",
     "owner":{"id":"<client uuid>","name":"<client's clientId>"},
     "ownerManagedAccess":true,"displayName":"R Two",
     "attributes":{"k1":["v1"],"k2":["v2"]},
     "_id":"<uuid>","uris":["/a","/b"],
     "scopes":[{"id":"<uuid>","name":"s1"}],"icon_uri":"http://i"}
```

The field order is `name type owner ownerManagedAccess displayName attributes
_id uris scopes icon_uri`. **`_id` is in the middle**, which is why this is a
struct with fields in that order and not a tidy id-first one.

Present-or-absent, measured on a resource carrying none of them:

```
always present   name owner ownerManagedAccess attributes uris   ("attributes":{}, "uris":[])
omitted when set to nothing   type displayName scopes icon_uri
```

`owner` is an object, `{id, name}`, and both halves come from the **client**: the
id is the client's internal UUID and the name is the client's `clientId` string -
the same inversion `resourceServerRepresentation` already records. **`owner` is
not settable**: `{"owner":"o"}` and `{"owner":{"id":..,"name":..}}` are both a 500.

The accepted field set, read off the strict decoder one field at a time:

```
accepted   _id name displayName type icon_uri uris uri owner ownerManagedAccess
           attributes scopes resource_scopes
refused    id iconUri policies typedScopes
```

`uri` (singular) is a legacy alias that becomes a one-element `uris`.
`resource_scopes` is an accepted alias for `scopes`. `iconUri` - the spelling
every other object in this API uses - is refused; the wire name here is
`icon_uri`.

### 3.2 Three collections, three different orderings

This is the part that decides the model, and it took three probes to separate.

**`uris` is a `HashSet<String>`.** `["/z","/a","/m"]` comes back `["/a","/z","/m"]`
and a repeated entry collapses. `javamap.KeyOrder` places it exactly: the three
strings hash to buckets 2, 11 and 14 at capacity 16. When two uris **do** collide
they chain in **request order**: `["aa","bb","zz"]` came back `aa,bb,zz` and
`["zz","bb","aa"]` came back `zz,bb,aa`.

**`attributes` is a `HashMap<String,List<String>>` whose chain runs the other
way.** Same container, same request, one key apart:

```
attributes {"aa":..,"bb":..,"zz":..}   ->  zz, bb, aa
attributes {"zz":..,"bb":..,"aa":..}   ->  aa, bb, zz
uris       ["aa","bb","zz"]            ->  aa, bb, zz
uris       ["zz","bb","aa"]            ->  zz, bb, aa
```

All six of those keys hash to bucket 0 at every table size, because a two-letter
string of one repeated character has a `hashCode` that is a multiple of 32. So
the bucket order says nothing and the chain says everything: **the attribute
chain is reverse request order and the uri chain is request order.** Two Java
collections on one body, opposite directions.

`javamap.KeyOrder` sorts before bucketing, so it is exact on any key set with no
collision and wrong on both of these chains. This cut does **not** touch
`internal/javamap` - another stream owns its tests this round - so it uses
`javamap.KeyOrder` for both, keeps the request order in the store the way
`orderOrganizationAttributes` already does, and the two chain rules go into the
handover as vectors for the package.

Every key set the goldens use is chosen to have no bucket collision, so the
goldens assert real bytes with no `UnorderedKeys` retreat - the same sidestep the
protocol mapper configs take.

**`scopes` is a set keyed on the scope's name, in bucket order, and a colliding
set is not reproducible.** `[{"/m"},{"/z"},{"/a"}]` came back `/a, /z, /m` on two
different resource servers with different scope ids, so the order follows the
name and not the id. Three names all in bucket 0 came back in two different
orders from two requests, so the chain there is decided by something not on the
wire. Goldens use a non-colliding set.

### 3.3 The listing and its eleven query parameters

**F129 says eight. The description declares eleven and the server reads ten of
them.** Counted from the description's list rather than incremented:
`_id`, `deep`, `exactName`, `first`, `matchingUri`, `max`, `name`, `owner`,
`scope`, `type`, `uri`. Every one is read except that `exactName` and
`matchingUri` are modifiers rather than filters, and an unknown parameter is
ignored.

```
name          case-insensitive substring; `exactName=true` makes it exact,
              and `exactName` with no `name` does nothing
_id           exact
type          case-insensitive substring
scope         case-insensitive substring over the resource's scope names
owner         exact, against the client's clientId string **or** its UUID -
              both work, and neither is a substring or case-folded
uri           exact against one of the resource's uris; `matchingUri=true`
              turns it into a best-match, where `/deep/*` catches `/deep/x`
              and an exact `/deep/a/b` beats it for `/deep/a/b`
deep          `false` drops **two** keys, `attributes` and `scopes`; the
              default is true; the single read and the search ignore it
first, max    either bound alone pages, as on the scope family
```

The row order is **sorted by name**, and `GET .../settings` serves the same rows
in **creation order** - the scope family's two-orders rule, on a second family.

`?first=abc` is `404 {"error":"HTTP 404 Not Found"}`, which is `authzIntBound`'s
rule and a sixth listing measured answering it.

### 3.4 The four write and read answers

```
POST   201, Cache-Control: no-cache, charset, **no Location**
       {} - a body with no name - is 409 Duplicate resource error
       a duplicate name is 409 {"error":"invalid_request",
                                "error_description":"Resource with name [r1] already exists."}
       the body's `_id` wins, and a second create on the same `_id` overwrites
GET    200 charset no-cache
       an unknown id is 404 {"error":"HTTP 404 Not Found"}, application/json,
       and **no Cache-Control**
PUT    204, no Cache-Control, no body
       replaces every field **except `attributes`**, which is kept when absent
       and replaced when present, `{}` included
       {} - no name - is a **500**, not the POST's 409
       an unknown id is the same JSON 404 as the GET's
       the body's `_id` is ignored; the path decides
DELETE 204, no Cache-Control, empty body
       an unknown id is the same JSON 404
```

The three sub-routes answer `[]`, `{}` and `[]` on a bare resource, and their
404 for an unknown resource is an **empty body with `Cache-Control: no-cache`** -
the opposite of the single read's JSON 404 with no `Cache-Control`, one path
segment apart.

`GET .../resource/{id}/scopes` serves the resource's scopes as `{id, name}`.
`GET .../resource/{id}/attributes` serves the attribute map alone.
`GET .../resource/{id}/permissions` is `[]` until a permission names the
resource, and Gloak has no permissions, so `[]` is complete rather than a stub.

### 3.5 The decode order

The strict decoder runs **first**, ahead of the name gate, ahead of the duplicate
check and ahead of the path's id:

```
POST {"zzz":1}                         the strict 400, not the no-name 409
POST {"name":<taken>,"zzz":1}          the strict 400, not the duplicate 409
PUT  /resource/<unknown> {"name":"x","zzz":1}   the strict 400, not the 404
PUT  /resource/<unknown> {}            the 404 - so the 404 precedes the 500
```

That is the required-action `PUT`'s order and the identity-provider `PUT`'s, and
the opposite of the organization `PUT`'s. It makes `ResourceRepresentation` the
**tenth** strict decoder in this API.

The malformed-body family has four answers here, and they are not the scope
family's:

```
{       400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
[       400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
empty   400 with an **empty body**, Cache-Control: no-cache
null    the same 400 with an empty body
```

The scope family answers an empty body with a **500**. Two families on one
resource server, opposite answers to no body at all.

### 3.6 The gate and the roles

The gate is `guardAuthz`, unchanged: a client without
`authorizationServicesEnabled` answers `404 {"error":"HTTP 404 Not Found"}` on
all nine routes, measured on each, to every caller.

The role sets are the first cut's, re-measured on this family one single role at
a time over eight callers (`none`, `view-authorization`, `manage-authorization`,
`view-clients`, `query-clients`, `manage-clients`, `manage-realm`, `view-users`):

| | opened by |
|---|---|
| the six reads | `view-authorization`, `manage-authorization`, `view-clients`, `manage-clients` |
| `POST`, `PUT`, `DELETE` | `manage-authorization`, `manage-clients` |

`query-clients`, `manage-realm` and `view-users` are 403 on every one. **The role
check precedes the resource lookup**: `DELETE .../resource/<unknown>` is 403 to a
`view-authorization` caller and 404 to a `manage-authorization` one - the scope
family's order, re-measured rather than carried over.

### 3.7 F131 does not reproduce on this family

A resource `_id` is global the way a scope id is: `POST .../resource` naming an
id another resource server already holds is
`409 {"error":"conflict","error_description":"Duplicate resource error"}`, and
reading one server's resource id through another is a 404. A name is unique per
resource server - `r1` exists in two at once.

**But the other resource server is not corrupted.** After the colliding create,
the owning server's listing, its per-id read and its settings export all still
answer 200. That is the whole of F131's damage and this family does not do it.
So Gloak's deliberate divergence on the scope family needs no extension here:
the resource family's measured behaviour is already what a global primary key
produces.

## 4. Implementation

### 4.1 `internal/model`

```go
type AuthzResource struct {
    ID, ClientID, Name, DisplayName, Type, IconURI string
    OwnerManagedAccess bool
    URIs               []string
    Attributes         []AuthzResourceAttribute
    ScopeIDs           []string
    Ordinal            int
}
type AuthzResourceAttribute struct{ Name string; Values []string }
```

`Attributes` is a slice for `OrganizationAttribute`'s stated reason - the wire
order is the order it arrived in and a Go map would sort it - and `URIs` is a
slice for the same reason one segment along. `Ordinal` is creation order, which
is what the settings export serves; the listing sorts in `internal/admin`.

### 4.2 `internal/store`

Six methods on `AuthzRepo`, all keyed by the client UUID because a resource is
addressed within its resource server:

```go
CreateResource(ctx, *model.AuthzResource) error   // ErrConflict on a duplicate name
UpdateResource(ctx, *model.AuthzResource) error
DeleteResource(ctx, clientID, resourceID string) error
ResourceByID(ctx, clientID, resourceID string) (*model.AuthzResource, error)
ResourceByName(ctx, clientID, name string) (*model.AuthzResource, error)
ListResources(ctx, clientID string) ([]*model.AuthzResource, error)  // creation order
```

No `ListResourcesByScope`: `GET .../scope/{id}/resources` was measured serving
its rows in **creation order**, which is what `ListResources` already returns, so
the filter runs in `internal/admin` beside the six the listing already runs
there. One place per rule rather than one per driver.

Migration `0022_authz_resource.sql` in both drivers: `authz_resource` plus three
child tables (`authz_resource_uri`, `authz_resource_attribute`,
`authz_resource_scope`), each carrying an ordinal so the request order survives.
A globally unique primary key on the id, and a unique index on
`(client_id, name)` - which is the pair of constraints §3.7 measures.

### 4.3 `internal/admin/authzresource.go`

Nine handlers, and the two fixes in `authz.go` and `authzscope.go`.

### 4.4 `internal/conformance`

Cases appended at the very end of `adminCases` and fixtures at the very end of
the map, with the helpers after the last one. Around twenty cases: the listing in
both orders, `deep=false`, four of the filters, the bad bound, the create, the
two 409s, the read, the JSON 404, the empty-bodied 404, the PUT's replace and its
`attributes` exception, the delete, the three sub-routes, and the settings export
that now carries resources.

## 5. Order of work

1. This plan, committed.
2. `internal/model` and `internal/store` interface, both drivers, migration 0022,
   `storetest` coverage, then the Postgres suite with `-v`.
3. `internal/admin/authzresource.go` and the router, with package tests.
4. The two fixes to `settings` and `scope/{id}/resources`.
5. Fixtures, catalogue cases, `make record`, `make test`, `make lint`.
6. Mutation pass, one mutation per claim, each confirming the **named** test.
7. Handover, then the pull request.
