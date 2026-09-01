# P10 third cut: the authorization-services resource family

Branch `feat/p10-authz-resources`, off `main` at 94f0d20. Everything below was
measured against a live Keycloak 26.7.1 on 2026-09-01, container `kc-authz` on
port 8154, removed when the cut finished. Port 8155 belonged to another stream
and was not touched. The container answering 8154 was confirmed to be this one
before any probe was believed: `GET /admin/serverinfo` reported 26.7.1 at 27
seconds of uptime, which is the check five cuts have lost probes to skipping.

Plan: `docs/superpowers/plans/2026-09-01-p10-authz-resources.md`.
First cut: `docs/superpowers/handover/p10-authz-services.md` (thirteen
operations). Second cut: `docs/superpowers/handover/p10-authz-cut-b.md` (the
scope family, eight).

**Nine operations landed**, the whole resource family: `GET`/`POST
.../resource`, `GET .../resource/search`, `GET`/`PUT`/`DELETE
.../resource/{id}`, and `.../resource/{id}/attributes`, `/permissions` and
`/scopes`. Two already-served routes were **fixed** on the branch and are marked
as such below.

Nine remain: policy 4, permission 4, import 1. Their measurements are banked in
§1.9 so the next cut starts from measurements rather than from the tag, which is
what the first cut did for the second.

## 1. Measurements

### 1.1 What F129 says about policy and permission, and what the server says

F129 asserts that policy and permission "need a provider model before `POST`
means anything". **The brief asked for this first because it decides the size of
the cut, and F129 is wrong about it in the cheap direction and right in an
expensive one it does not mention.**

A policy and a permission need exactly one thing: a `type`.

```
POST .../policy      {}                          409 Duplicate resource error
POST .../policy      {"name":"p1"}               409 Duplicate resource error
POST .../policy      {"name":"p2","type":"role"} 201
POST .../permission  {"name":"x","type":"resource"} 201
```

`type` is the gate on both endpoints, the way `decisionStrategy` is the gate on
`PUT .../authz/resource-server`. A body with no `type` is the 409 whatever else
it holds, including a name - which is the third endpoint in this family with
that exact shape.

**The accepted type set is nine and it is not the provider catalogue's ten.**
Swept one type at a time on both endpoints, with identical answers on each:

```
regex role resource scope client time group aggregate uma   201
user client-scope js <unknown> ""                           500 unknown_error /
                                                            "For more on this error
                                                             consult the server log."
```

`uma` is accepted and is **not** offered by `GET .../policy/providers`, while
`user` and `client-scope` **are** offered there and answer a 500. The catalogue
this repository already ships as a constant is therefore not the accepted set in
either direction, and a validator built from it would refuse one working type
and admit two that fail.

So the provider model is not needed for `POST` to mean something. Three other
measurements are what make the two families expensive, and they are why this cut
stopped at the resource family:

- **One row serialises two ways and the path decides.** `GET .../policy` carries
  `config` and `GET .../permission` does not, on byte-identical rows one key
  apart. `GET .../permission/search?name=<a role policy>` answers `"roles":[]`
  where `GET .../policy/search` on that same row answers
  `"config":{"roles":"[]"}`. The permission views serve the **provider's own
  typed representation** and the policy views serve the generic one. Nine
  providers, nine typed representations - which is the provider model F129 asked
  about, sitting one layer further out than it thought.
- **The two `evaluate` operations mint an RPT.** `POST .../policy/evaluate`
  answers 200 with a whole access token inside it - `exp`, `iat`, `jti`, `sid`,
  the caller's realm and client roles. It is the authorization engine, not a
  representation, and it cannot be `Recorded` without masking four per-request
  values.
- **`POST .../import` is a 204** that replaces the three settings and adds rows
  from all four families, so it asserts nothing until policies exist.

### 1.2 The representation, and where `_id` is

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

**`_id` is between `attributes` and `uris`.** Every other representation in this
API leads with its id, so a serialiser written from habit produces a body that
reads correctly and is wrong.

Present-or-absent, measured on a resource created with only a name: `name`,
`owner`, `ownerManagedAccess`, `attributes` and `uris` are always there - `{}`
and `[]` when empty - and `type`, `displayName`, `scopes` and `icon_uri` are
dropped.

`owner` is `{id, name}` and both halves come from the **client**: the id is the
client's internal UUID and the name is the client's `clientId` string. That is
`resourceServerRepresentation`'s inversion again. **`owner` is not settable**:
`{"owner":"o"}` and `{"owner":{"id":..,"name":..}}` are both a 500, and `null`
counts as absent.

The accepted field set, read off the strict decoder one field at a time:

```
accepted   _id name displayName type icon_uri uris uri owner ownerManagedAccess
           attributes scopes resource_scopes
refused    id iconUri policies typedScopes
```

Three of those are worth repeating:

- **the id's wire name is `_id` and `id` is refused**, which is the opposite of
  every other create in this API;
- **`iconUri` is refused and `icon_uri` is the spelling**, which is the opposite
  of the scope family one path segment away, where a resource's inline copy of a
  scope spells the very same concept `iconUri`;
- **`uri` (singular) is a legacy alias** that folds into `uris`, and
  `resource_scopes` is an alias for `scopes` that **wins** when both are sent -
  measured with a different scope in each.

### 1.3 Three collections, three orderings, and two of them chain in opposite
directions

This is the finding of the cut and it took three probes to separate.

**`uris` is a Java `HashSet<String>`.** `["/z","/a","/m"]` comes back
`["/a","/z","/m"]` and a repeated entry collapses. `javamap.KeyOrder` places it
exactly: those three hash to buckets 2, 11 and 14 at capacity 16.

**`attributes` is a Java `HashMap` whose chain runs the other way.** Same
container, same body, one field apart:

```
attributes {"aa":..,"bb":..,"zz":..}   ->  zz, bb, aa
attributes {"zz":..,"bb":..,"aa":..}   ->  aa, bb, zz
uris       ["aa","bb","zz"]            ->  aa, bb, zz
uris       ["zz","bb","aa"]            ->  zz, bb, aa
```

All six of those keys hash to bucket 0 at every table size, because a two-letter
string of one repeated character has a `hashCode` that is a multiple of 32. So
the bucket order says nothing there and the chain says everything: **the
attribute chain is reverse request order and the uri chain is request order.**
Four more insertion orders of a three-key colliding set were sent and all four
came back reversed, so the attribute rule is pinned by six requests rather than
by two.

**`scopes` inside a resource is a set keyed on the scope's name.** The same
three names came back in the same order from two resource servers holding
different scope ids, so the order follows the name and not the id.
`javamap.KeyOrder` places a collision-free set exactly. **A colliding set is not
reproducible**: `aa, bb, zz` came back `aa, bb, zz` and `zz, bb, aa` came back
`bb, aa, zz`, which is neither direction, so nothing observable says what that
chain was.

**These are two vectors for `internal/javamap` and this branch did not add
them**, because that package's tests are another stream's this round. What is
there now is `javamap.KeyOrder` used for all three, which is exact on any key set
with no bucket collision and wrong on both chains. Every key set the goldens use
is measured collision-free, so they assert real bytes with no `UnorderedKeys`
retreat - the protocol mappers' sidestep, applied twice.

### 1.4 The listing reads ten of the description's eleven query parameters

**F129 says eight.** Counted from the description's list rather than
incremented, it declares eleven - `_id`, `deep`, `exactName`, `first`,
`matchingUri`, `max`, `name`, `owner`, `scope`, `type`, `uri` - and every one is
read, with `exactName` and `matchingUri` modifying `name` and `uri` rather than
filtering on their own. `fields` is not on this operation at all; it is on
`GET .../policy`, where it **is** declared and **is** ignored, which is where the
"one is not read" belongs.

Six comparisons, each probed on its own, and no two are the same rule:

```
name       case-insensitive substring; ?exactName=true makes it exact, and
           ?exactName=true with no name does nothing at all
_id        exact
type       case-insensitive substring - `urn:tt` and `TT` both find `urn:TT`
scope      case-insensitive substring over the resource's scope names
owner      exact, against the client's clientId string **or** its UUID. Both
           work; neither folds case and neither matches a prefix. It is the one
           filter on the family that is not a substring of something.
uri        exact against one of the resource's uris
```

**`matchingUri=true` is a best match rather than a filter.** Measured on two
resources, `/deep/*` and `/deep/a/b`:

```
?uri=/deep/a/b/c&matchingUri=true     the wildcard one
?uri=/deep/a/b&matchingUri=true       the exact one, which beats the wildcard
?uri=/deep/x&matchingUri=true         the wildcard one
?uri=/one/two/three&matchingUri=true  nothing - `/one/two` is not a pattern
?uri=/deep/a/b/c                      nothing, without the modifier
```

`matchingUri=true` with **no** `uri` is ignored outright rather than emptying the
set.

The row order is **sorted by name, byte-wise** and `GET .../settings` serves the
same rows in **creation order** - the scope family's two-orders rule, holding on
a second family and re-measured rather than inherited. Either bound alone pages.
`?first=abc` is `authzIntBound`'s 404, which makes this the **sixth** listing
measured answering it.

**`?deep=false` drops two keys, not one**: `attributes` and `scopes`. The default
is true and anything that is not the literal `false` is true. The single read and
the search **ignore it entirely**, measured on both.

### 1.5 The write answers, and where they disagree with the scope family

```
POST   201, Cache-Control: no-cache, charset, **no Location**
GET    200 charset no-cache
PUT    204, no Cache-Control, no body
DELETE 204, no Cache-Control, empty body        - a ninth measured delete
```

**`POST` is an upsert on `_id` and not on the name.** Two creates naming the
same `_id` left one row holding the second body; two creates naming the same
**name** are a 409. That is the inverse of the scope family, where the name
upserts and the id wins.

Five refusals, in the order they were measured to run:

```
{"zzz":1}                    the strict 400, ahead of everything below
{"owner":"o"}                500, ahead of the name - measured beside no name
                             and beside a taken name, and both answer about the
                             owner
empty body or `null`         **400 with an empty body**, Cache-Control: no-cache
{} or {"name":null}          409 Duplicate resource error
{"name":<taken>}             409 {"error":"invalid_request",
                                  "error_description":"Resource with name [r1]
                                                       already exists."}
```

That last one is the **only refusal in the whole authorization-services surface
that repeats its input back**, and it is a twenty-fourth spelling of not-found's
sibling: a spelling of *conflict* this API did not have.

**The PUT disagrees with the POST on four of those five.**

```
{"zzz":1} to an id that does not exist   the strict 400 - the decode is ahead of
                                         the path
{} to an id that does not exist          the JSON 404 - the path is ahead of the
                                         name check
{}, {"name":null}, empty body, `null`    500 unknown_error, where the create
                                         answers 409 for the first two and a 400
                                         with an empty body for the last two
{"name":<taken>}                         409 `Duplicate resource error`, where
                                         the create names the resource
```

**And the two 409s disagree about the five security headers.** The create's
carries all five and the update's carries none, measured on identical requests
one path segment apart. That is the scope family's split exactly, on a second
family - the second time this API has been measured doing it, and the second
piece of evidence against AGENTS.md's fifth security-header exception.

**The PUT replaces every field except `attributes`.** A PUT carrying only a name
against a resource holding a type, a displayName, an icon_uri, two uris, a scope
and `ownerManagedAccess: true` cleared all six and left the attributes exactly as
they were. `{"attributes":{}}` **does** clear them, so the exception is about
absence and not about the field. That is AGENTS.md's "PUT replaces / PUT merges -
except for one field" a third time, pointing the other way: this verb replaces,
and one field merges.

The body's `_id` is read and discarded; the path decides which row moves. Same
as the scope PUT, opposite to `PUT .../protocol-mappers/models/{id}`.

### 1.6 Two 404s one path segment apart, and they invert the scope family's

```
GET/PUT/DELETE .../resource/{unknown}     404 {"error":"HTTP 404 Not Found"}
                                          application/json, **no Cache-Control**
GET .../resource/{unknown}/attributes     404, **empty body**, no Content-Type,
GET .../resource/{unknown}/permissions    **with** Cache-Control: no-cache, and
GET .../resource/{unknown}/scopes         no X-Frame-Options
```

The scope family answers its own single read the **second** way. So the two
families invert each other on both halves, and the resource family also inverts
itself one path segment down. A helper that picked one shape would be wrong on
three routes out of six.

The JSON one is a **fifth producer** of `{"error":"HTTP 404 Not Found"}`, after
an unmatched path, a wrong verb on a known path, a switched-off resource and an
unparseable integer bound - and the first that is an ordinary missing row on a
route the caller may use.

### 1.7 One scope, five views

Measured on a scope carrying both an `iconUri` and a `displayName`, and
confirmed against a second scope carrying only a `displayName`:

```
GET .../scope/{id}                    {id, name, iconUri, displayName}
inside a resource                     {id, name, iconUri}        - no displayName
GET .../resource/{id}/scopes          {id, name}                 - no iconUri
inside a resource in the export       {name}                     - and no id
the export's own `scopes` array       {name, iconUri, displayName} - no id
```

Five shapes of one object in one API, and four of them are on this cut's
surface. A shared serialiser emits a key Keycloak does not, in three places at
once.

`GET .../scope/{id}/resources` is a sixth shape of a different object:
**`{"name":..., "_id":...}`, with the name first.** It is the only body measured
in this API that puts a name ahead of an id.

### 1.8 F131 does not reproduce on this family

A resource `_id` is global the way a scope id is: `POST .../resource` naming an
id another resource server already holds is
`409 {"error":"conflict","error_description":"Duplicate resource error"}`, and
reading one server's resource id through another is a 404. A **name** is unique
per resource server - `r1` exists in two at once.

**But the other resource server is not corrupted.** After the colliding create,
the owning server's listing, its per-id read and its settings export all still
answered 200 - measured on a seven-row resource server. That is the whole of
F131's damage and this family does not do it. So Gloak's deliberate divergence
on the scope family needs no extension here: the resource family's measured
behaviour is already what a global primary key produces, and this cut neither
reproduces the corruption nor diverges from anything.

The one qualification worth writing down: the scope-side reproduction broke on
the eighth of sixteen rows, and the resource-side control had seven rows. A
larger set was not tried, so "does not corrupt" is measured at that size rather
than proved at every size.

### 1.9 Measured and not built - the fourth cut's head start

The policy and permission families were swept far enough to scope them. Recording
it here so the next cut does not have to re-measure.

- **`type` is the gate on both `POST`s** and the accepted set is the nine of
  §1.1. A body with no `type` is `409 Duplicate resource error`.
- **The response field order is `id, name, description, type, logic,
  decisionStrategy, owner, config`.** `description` and `owner` are dropped when
  empty; `logic` defaults `POSITIVE` and `decisionStrategy` `UNANIMOUS`.
- **The body's `id` wins**, a sixth endpoint after `POST /clients`,
  `/client-scopes`, `.../scope`, `.../identity-provider/instances` and
  `.../resource`.
- **The untyped `POST .../policy` is strict and its unknown-field answer is a
  500, not the prose 400**: `{"name":"x","type":"role","zzz":1}` is
  `500 unknown_error / "Cannot parse the JSON"`. So is any typed field -
  `roles`, `clients`, `users`, `clientScopes` - because the untyped route binds
  `PolicyRepresentation`, whose only free-form field is `config`.
  `{"config":{"roles":"[...]"}}` is a 201.
- **`{"scopes":["<unknown>"]}` is a `400 {"error":"unknown_error"}` with no
  `error_description` at all** - an error shape this API has not been measured
  producing anywhere else. `{"policies":[...]}` and `{"resources":[...]}` naming
  unknown ids are the 500 instead.
- **`POST .../policy/{type}` exists and is not in the description.** It decodes
  the provider's **typed** representation - `POST .../policy/role`
  `{"name":"p","roles":[{"id":"admin"}]}` is a 201 echoing
  `"roles":[{"id":"<uuid>","required":false}]` - and its 201 carries no `config`
  key. `POST .../policy/nope` is a 404. The body's own `type` is ignored: a
  `POST .../policy/role` carrying `"type":"client"` created a role policy.
- **`GET .../permission` is `GET .../policy?permission=true`** filtered to
  `{resource, scope, uma}`, and `permission=false` on the `/permission` path is
  ignored - the route pins it.
- **The two listings serialise differently.** `/policy` entries carry `config`
  and `/permission` entries carry the typed fields instead. `/policy?permission=true`
  and `/permission` returned the same row one key apart, which is the probe that
  separates "the filter" from "the serialisation".
- The listing reads `first`, `max`, `name` (case-insensitive substring),
  `owner`, `permission`, `policyId` (exact), `resource`, `resourceType`, `scope`
  and `type` (exact); **`fields` is declared and ignored**. `?first=abc` is the
  404. Sorted by name.
- **`GET .../policy/search` and `.../permission/search` are the scope search's
  shape**: exact name, a bare object, 204 on a miss, 400 with an empty body when
  `name` is absent or empty - and **neither is filtered by family**.
  `/permission/search?name=<a role policy>` found it, and served it in the typed
  shape.
- **`POST .../import` is a 204** on `{}` and on a full body alike. A full body
  replaces the three settings and does **not** delete the existing resources.
- **`POST .../policy/evaluate` with `{}` is a 500**; with
  `{"resources":[{"name":"r1"}],"clientId":"<uuid>","userId":"<username>",`
  `"entitlements":false,"context":{"attributes":{}}}` it is a 200 carrying
  `{"results":[],"entitlements":false,"status":"PERMIT","rpt":{...}}`, where the
  `rpt` is a full access token with `exp`, `iat`, `jti` and `sid` in it.
  `POST .../permission/evaluate` answers the same 500 on `{}`.
- The role sets and the gate are the resource family's - swept on all nine
  policy, permission and import routes at the same time as the resource ones
  (§2, last bullet).
- **A fresh resource server is empty.** A client created with
  `authorizationServicesEnabled: true` through `POST /clients` has no resources,
  no policies, no permissions and no scopes - the admin console's "Default
  Resource"/"Default Policy"/"Default Permission" trio is not created on this
  path. Measured on two fresh clients.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **Two Java collections on one body chain in opposite directions.** A
  resource's `uris` is a `HashSet<String>` and its `attributes` a
  `HashMap<String,List<String>>`, and when their keys share a bucket the uris
  chain in **request** order and the attributes in **reverse** request order.
  Measured on one container with six keys that all hash to bucket 0 - a
  two-letter string of one repeated character has a `hashCode` that is a
  multiple of 32 - so the bucket order says nothing and the chain says
  everything, and the two fields sit one key apart on the same request.
  `javamap.KeyOrder` sorts before bucketing and is therefore exact on any key
  set with **no** collision and wrong on both chains; both goldens and both
  package tests use collision-free sets, which is the protocol mappers'
  sidestep applied twice. A resource's `scopes` is a third set, keyed on the
  scope's **name** - the same three names came back in the same order from two
  resource servers holding different ids - and its colliding chain is
  reproducible from nothing on the wire: `aa, bb, zz` came back unchanged and
  `zz, bb, aa` came back `bb, aa, zz`, which is neither direction.
- **One scope has five serialisations and the route decides.**
  `{id, name, iconUri, displayName}` from the scope family's own reads;
  `{id, name, iconUri}` inline in a resource; `{id, name}` from
  `GET .../resource/{id}/scopes`; `{name}` inline in a resource in the settings
  export; and `{name, iconUri, displayName}` from the export's own `scopes`
  array. Measured on one scope carrying an iconUri and a displayName and
  confirmed on a second carrying only a displayName, so the missing keys are
  dropped rather than merely empty. A sixth body on the same surface,
  `GET .../scope/{id}/resources`, serves `{"name":..., "_id":...}` - **the only
  response in this API measured putting a name ahead of an id**.
- **`_id` is the resource's wire name and `id` is refused.** Every other create
  in this API takes `id`; this one answers `Unrecognized field "id"` for it, and
  the same body spells the icon `icon_uri` where the scope family one path
  segment away spells it `iconUri` - and where a resource's own inline copy of a
  scope spells it `iconUri` too. Two spellings of one concept inside one
  response.
- **A resource `PUT` replaces everything except `attributes`.** A body naming
  only the name cleared the type, the displayName, the icon_uri, the uris, the
  scopes and `ownerManagedAccess`, and left the attributes untouched;
  `{"attributes":{}}` cleared them, so the exception is about absence and not
  about the field. That is the third variation of this file's "`PUT` replaces /
  `PUT` merges - except for one field", and the first that points this way: the
  verb replaces and one field merges. The other two are a role's `PUT`, which
  replaces outright, and a client's, whose one exception is
  `authorizationServicesEnabled`.
- **One duplicate name, two verbs, two 409 bodies and two header sets.**
  `POST .../resource` with a taken name is
  `{"error":"invalid_request","error_description":"Resource with name [r1] already exists."}`
  and carries the five security headers; `PUT .../resource/{id}` onto the same
  taken name is `{"error":"conflict","error_description":"Duplicate resource error"}`
  and carries none of them. That is the scope family's header split on a second
  family and it is the second measurement contradicting this file's fifth
  security-header exception, which says a 409 of that shape sends none. The
  create's message is also the only refusal on the whole authorization-services
  surface that repeats its input back. **And the "empty body" reason this file
  gives for the scope family's version of that split is wrong**: both 409s carry
  a 67-byte body, so emptiness cannot be what separates them - see §1.10 of
  `docs/superpowers/handover/p10-authz-resources.md`.
- **Two 404s on one resource, one path segment apart, and neither is the scope
  family's.** `GET`, `PUT` and `DELETE .../resource/{unknown}` answer
  `{"error":"HTTP 404 Not Found"}` with `application/json` and **no
  `Cache-Control`**; `.../resource/{unknown}/attributes`, `/permissions` and
  `/scopes` answer an **empty body with `Cache-Control: no-cache`**. The scope
  family's single read answers its own missing scope the second way, so the two
  families invert each other and the resource family inverts itself. The JSON
  one is a **fifth producer** of that body, after an unmatched path, a wrong
  verb, a switched-off resource and an unparseable integer bound - and the first
  that is an ordinary missing row.
- **`POST` and `PUT` on one resource disagree about a body that is not there.**
  An empty request body and a literal `null` are a **400 with an empty body** on
  the create and a **500 `unknown_error`** on the update. The scope family
  answers the create's bytes with the update's status, so three writes on one
  resource server give two answers split along no line either family shares.
- **A resource create is an upsert on `_id` and a scope create is an upsert on
  the name.** Two resource creates naming one `_id` leave one row holding the
  second body; two naming one **name** are a 409. On the scope family it is the
  other way round. Reusing either family's upsert helper is wrong in both
  directions at once.
- **`GET .../authz/resource-server`'s three arrays really are always empty.**
  The first cut measured it against a resource server holding four scopes; it was
  re-measured here against one holding seven resources and thirty-three policies
  and still answered `"resources":[],"policies":[],"scopes":[]`. The settings
  export beside it populates all three. This is the one claim in the family that
  a bigger sample confirmed rather than refuted.
- **A `type` is what a policy and a permission need, and the accepted set is not
  the provider catalogue.** `POST .../policy` and `POST .../permission` answer a
  body with no `type` with `409 Duplicate resource error`, and accept
  `regex role resource scope client time group aggregate uma` - nine. `uma` is
  accepted and is absent from `GET .../policy/providers`; `user` and
  `client-scope` are in that catalogue and answer a **500**. Validating against
  the catalogue this repository already ships would refuse one working type and
  admit two that fail.

### 1.10 Lines in AGENTS.md and the observed document these measurements
contradict

**AGENTS.md's fifth security-header exception is wrong, and this repository's
own committed goldens have refuted it since the second cut.** The bullet reads:

> **The fifth, corrected 2026-09-01: an empty response body sends none of the
> five** ... `POST .../authz/resource-server/scope` with `{}` sends all five;
> `PUT .../scope/{id}` with `{}` sends none - byte-identical bodies, identical
> requests, one path segment apart, and the difference is that the second
> answers with nothing in it.

**The second does not answer with nothing in it.**
`internal/conformance/testdata/golden/admin/authz-resource-server/scope-put-conflict.http`
is a committed 409 carrying
`{"error":"conflict","error_description":"Duplicate resource error"}` - 67
bytes - and none of the five headers. The golden was recorded by the cut that
wrote the sentence, and the sentence's own citation is what refutes it.

This cut recorded a second, independent instance: `resource-put-conflict.http`
is the same 67 bytes with the same header set, from a different verb-and-body
combination on a different family, and `resource-create-conflict.http` beside it
is a 102-byte 409 carrying **all five**. So three committed goldens now say the
same thing.

What survives is that an **empty** body sends none - every 204, every empty 404
and the search's empty 400 on this family agree. What is refuted is that
emptiness **explains** these two 409s, because neither of them is empty. The
variable there is the endpoint, and the pattern across the two families is that
a `POST`'s 409 keeps the five and a `PUT`'s drops them - which is a claim about
the verb, and this cut has two data points for it rather than a rule.

**This is the fourth time in two weeks a claim in that bullet has been refuted by
this repository's own goldens, and the second time by the very golden the claim
cites.** The bullet's own closing sentence - "Before writing a rule about
headers, grep the goldens for a case that would break it" - was written in the
same commit as the golden that breaks it.

Nothing else in AGENTS.md or the observed document was contradicted. Two things
were **confirmed** against a bigger sample rather than refuted, which is worth
recording because both were single-measurement claims:
`GET .../authz/resource-server`'s three empty arrays (§2) and `authzIntBound`'s
404 for an unparseable bound, now on a sixth listing.

## 3. Follow-up dispositions

**F129 - the other twenty-six authorization-services operations.** Nine more
landed, which leaves nine: policy 4, permission 4, import 1. Three of its
statements are wrong and are corrected by measurement:

- *"the resource family ... takes eight query parameters"* - **the description
  declares eleven and the server reads all eleven**, with `exactName` and
  `matchingUri` as modifiers. Counted from the description's list. `fields` is
  not on this operation; it is on `GET .../policy`, where it is declared and
  ignored.
- *"policy and permission need a provider model before `POST` means anything"* -
  **they need a `type` and nothing else** (§1.1). The provider model is needed
  one layer out, for the typed serialisation the `/permission` reads use, and
  F129 does not mention that.
- *"the three permanently-`[]` listings (`GET /resource`, `/policy`,
  `/permission`)"* - **none of the three is permanently `[]`.** They are ordinary
  listings, empty on a fresh resource server only because nothing has been
  created. `GET /resource` is built here, served by the real store, with a
  fixture that puts four rows in it - which is the condition the brief set for
  taking it. `/policy` and `/permission` are unbuilt, and the reason is now the
  typed representation rather than the emptiness.

The brief's own restatement of the second and third points inherited them from
F129 and is wrong the same way. The premise this cut kept is the fourth:
`import` genuinely does need the other families first.

**F131 - a cross-resource-server scope id collision corrupts the other resource
server.** Unchanged and **not extended**. The resource family carries the same
global-id constraint and was measured **not** corrupting: after the colliding
create the other resource server's listing, per-id read and settings export all
answered 200. So this cut neither reproduces F131's damage nor diverges from
anything - the divergence stays a statement about the scope family alone. §1.8
records the one qualification: the scope-side reproduction broke on the eighth of
sixteen rows and the resource-side control had seven, so the claim is measured at
that size rather than at every size.

**F95 - a client's `attributes` is serialised from a Go map.** Untouched, and
the pattern it asks for is now the majority by a wider margin: this cut adds a
fifth family serialising a Java map from an ordered slice with a marshaller of
its own (`authzResourceAttributes`), after `identityProviderConfig`,
`componentConfig`, an organization's attributes and a protocol mapper's config.
The client is still the holdout and it still lives in `clients.go`, whose fix
re-records five goldens in another chapter.

**F134 - four listings still treat an unparseable bound as no bound.** Unchanged.
The resource listing is the **sixth** measured answering the 404 and it uses
`authzIntBound`, so the four are unmoved and the count of listings that agree
with each other has grown.

**F133 - `writeEmptyStatus` lives in `internal/admin`.** Unchanged and now used
by a second family, which strengthens the case for the move rather than the case
against it. Six of this cut's nine routes reach it.

## 3a. The mutation pass, and the three survivors

Twenty-four mutations, one per claim, each confirming the **named** test fails
and each reverted. Twenty-one were killed on the first pass. The three that
survived are below, and two of them were holes in a test rather than in the
mutation.

**Survivor 1 - a badly chosen mutation, not a hole.** Adding a `displayName`
field to `authzInlineScope` left `TestResourceInlineScopeHasThreeShapes` green,
because nothing fills it: the claim "a resource's inline scope drops the
displayName" is carried by a **struct that has no such field**, and there is no
statement to mutate. Re-run as what a careless implementer actually writes - the
composite literal filling it from the scope - it was killed. The lesson is the
one this project keeps meeting from the other side: a mutation that changes no
reachable behaviour proves nothing about the test, and reading it as a survivor
would have sent somebody looking for a hole that is not there.

**Survivor 2 - a real hole, fixed on the branch.** Folding case in the listing's
comparator left `TestResourceListingFiltersAndOrders` green. The test's three
resources were `zulu`, `yankee` and `Xray`, and **`Xray` cannot tell a byte-wise
sort from a case-folded one** - it leads under both. The golden's set can,
because the fixture uses `Zebra`, which byte-wise leads and case-folded comes
second; the package test had been written with a different capital and the
difference is invisible until somebody mutates the comparator. The test now uses
`Zebra` and the mutation is killed. **The conformance golden was already right**,
so nothing shipped wrong - what was wrong is that the package test claimed to
assert something it could not see.

**Survivor 3 - a real hole, fixed on the branch.** Swapping the create's no-name
409 writer for the update's left `TestResourceWriteRefusalsAndTheirTwo409s`
green, because that assertion read the body and the two writers spell the same
body. What separates them is the five security headers. The test now asserts
`X-Frame-Options` on that 409 as well, and the mutation is killed. The golden
`resource-create-no-name.http` had `AssertHeaders: X-Frame-Options` from the
start, so again nothing shipped wrong and again a package test was asserting less
than it said.

Both real survivors are the same shape - **a claim about a pair asserted on the
half the two halves agree about** - and both were invisible to every green run.

## 4. Parity, before and after

```
Parity: 352 -> 361 of 535 (+9)

chapter                         before  after  delta
admin/authz-resource-server         13     22     +9
```

The chapter's denominator is thirty-one. Twenty-two are served after this cut -
the resource server as a resource, the two provider catalogues, the scope
family's eight and the resource family's nine - and nine are left: policy 4,
permission 4, import 1.

Two of the twenty-two moved without moving the total, and they are the fixes
rather than the additions: `GET .../settings` and `GET .../scope/{id}/resources`
were already counted as served and were already wrong in a way no golden could
see, because nothing could create a resource to put in either of them. They are
the reason this cut's diff touches `authz.go` and `authzscope.go` at all.

Twenty-five goldens were recorded and **no existing golden moved**, on a clean
checkout, twice - once before an id typo in seven case paths was found and once
after.
