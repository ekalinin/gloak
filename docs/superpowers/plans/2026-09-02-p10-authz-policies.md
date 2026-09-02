# P10 fourth cut: policy, permission and import

Branch `feat/p10-authz-policies`, off `main` at afdd00d. Everything below was
measured against a live Keycloak 26.7.1 on 2026-09-02, container `kc-policy` on
port 8156, removed when the cut finishes. Port 8157 belongs to another stream and
was not touched. The container answering 8156 was confirmed to be this one before
any probe was believed: `GET /admin/serverinfo` reported 26.7.1 at 34 seconds of
uptime.

Previous cuts: `docs/superpowers/handover/p10-authz-services.md` (thirteen
operations), `p10-authz-cut-b.md` (the scope family, eight),
`p10-authz-resources.md` (the resource family, nine, with §1.9 banking the
measurements this cut starts from).

## 0. How many distinct representations do the nine policy types actually have?

**Eight, and the number that decides the cut's shape is one.**

§1.9 does not answer this and the roadmap's guess - "nine providers, nine typed
representations" - is wrong in the direction that matters. One probe settles it:
send **one config carrying every provider's keys at once** to **all nine types**,
then read each row through both views.

```
config sent to all nine, identical:
  defaultResourceType roles clients groups groupsClaim nbf hour
  targetClaim pattern targetContextAttributes fetchRoles code users
```

The generic view (`GET .../policy`, `GET .../policy/search`) came back
**byte-identical on all nine** - the same thirteen keys in the same order. The
typed view (`GET .../permission`, `GET .../permission/search`) projected exactly
the keys the type owns and nothing else:

```
regex      targetClaim, pattern, targetContextAttributes
role       roles, fetchRoles
resource   resourceType          <- from config.defaultResourceType
scope      resourceType          <- the same, so these two share a shape
client     clients
time       notBefore, notOnOrAfter, dayMonth, dayMonthEnd, month, monthEnd,
           year, yearEnd, hour, hourEnd, minute, minuteEnd
group      groupsClaim, groups
aggregate  -- nothing --
uma        scopes                <- always present, and not from config at all
```

So there are **eight distinct field sets over nine types**, `resource` and
`scope` being the only pair that shares one - and they are **not eight
structures**. They are one stored `config` map read through a nine-row table of
per-type key mappings, plus one association read for `uma`. `resourceType` is
**not** a shared base field on the read: a `role` policy carrying
`defaultResourceType` in its config serves it in the generic view and does
**not** project it.

That is what sizes the cut. The provider model F129 asked for is a table, and
the expensive part is elsewhere - see §5.

## 1. What the nine operations are

The vendored description's untagged set is 31; 22 are served. The nine left,
read off `testdata/openapi/keycloak-26.7.1.json` rather than off the roadmap:

```
GET    .../policy                    GET    .../permission
POST   .../policy                    POST   .../permission
GET    .../policy/search             GET    .../permission/search
POST   .../policy/evaluate           POST   .../permission/evaluate
POST   .../import
```

There is no documented `GET`/`PUT`/`DELETE .../policy/{id}` and no
`POST .../policy/{type}`. All four exist on the server and none is in the
denominator; they were probed because they are the only way to see the typed
representation of a type the `/permission` listing filters out, and
`GET .../permission/search` turned out to serve the same thing without leaving
the description.

## 2. Measurements this cut is built from

### 2.1 The two views of one row

`GET .../policy` and `GET .../permission` serve the same rows one key apart. The
generic view is
`{id, name, description?, type, logic, decisionStrategy, config}`; the typed view
replaces `config` with the projection of §0, in the field order of Keycloak's
`AbstractPolicyRepresentation`:

```
id name description type policies resources scopes logic decisionStrategy
owner resourceType <the provider's own fields>
```

Measured consequences that are not guessable from that order:

- **`uma`'s `scopes` sits between `type` and `logic`** and every other type's
  extra fields sit after `decisionStrategy`, because `scopes` is a base field and
  the rest are the subclass's.
- **`uma`'s `scopes` is always present**, `[]` when empty, where every other
  type omits the key. It is read from the **association** table and served **by
  name**, while the create that set it echoed the scope's **id**.
- **`policies`, `resources` and `owner` are never served on a read.** They are
  echoed by the create and dropped by every view afterwards.

### 2.2 The create is the request echoed

`POST .../policy` and `POST .../permission` are one handler: identical 201s,
identical refusals, and **neither restricts the type** - `POST .../permission`
with `type: role` is a 201. Only the `GET .../permission` listing filters.

The 201's field order is the base order above with `config` appended, and it is
**the request echoed** rather than a read of what was written:

```
POST {"name":"c1","type":"role","config":{"roles":"[{\"id\":\"admin\"}]"}}
201  ... "config":{"roles":"[{\"id\":\"admin\"}]"}      <- verbatim
GET  ... "config":{"roles":"[{\"id\":\"175a47fb-...\",\"required\":false}]"}
```

Three normalisations happen on the way in and none of them shows in the 201:

```
role    a role name becomes the role's uuid; `required` defaults to false;
        an **unknown role is silently dropped** - `[{"id":"nosuchrole"}]`
        stored as `[]`
client  a clientId becomes the client's uuid
group   a `path` becomes the group's `id`; `extendChildren` defaults to false
```

and one **addition**: a `role`, `client` or `group` policy created with no
config at all reads back with `{"roles":"[]"}`, `{"clients":"[]"}` or
`{"groups":"[]"}`, while its own 201 said `config:{}`. `aggregate` goes the
other way - `config.applyPolicies` is consumed into the association table and
**removed** from the config, so its read is `config:{}`.

### 2.3 The refusals, in the order they were measured to run

```
1  unknown field, or a bad `logic`/`decisionStrategy` enum
       500 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
2  a taken name
       409 {"error":"Policy with name [taken] already exists",
            "error_description":"Conflicting policy"}
3  an absent or null `name` **or** an absent or null `type`
       409 {"error":"conflict","error_description":"Duplicate resource error"}
4  a `type` outside the nine
       500 {"error":"unknown_error",
            "error_description":"For more on this error consult the server log."}
5  an `id` any resource server already holds
       409 {"error":"conflict","error_description":"Duplicate resource error"}
```

Each adjacency was pinned by a body wrong in two ways at once: `{"type":"nope"}`
with no name answers about the presence (3 before 4); `{"name":"taken",
"type":"nope"}` answers about the name (2 before 4); `{"name":"taken","zzz":1}`
answers about the field (1 before 2).

**§1.9 and AGENTS.md are both wrong that `type` is the gate.** It is one of two:
`{"type":"role"}` with no name is the same 409. The correct statement is that a
policy needs a **name and a type**.

Four more, measured on the body rather than on its contents, and there are
**four distinct 500 bodies for four kinds of unusable body**:

```
empty body   500 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
null         500 {"error":"unknown_error",
                  "error_description":"For more on this error consult the server log."}
`{`          500 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
`[`          500 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
```

`invalid_request` on a **500** is a shape this API has not been measured
producing anywhere else.

`{"name":""}` is a 201 and `{"name":null}` is the 409, so absent and empty are
two states - the resource family's rule on a third family.

Three more that are not about the body's shape:

```
{"scopes":["<unknown>"]}     400 {"error":"unknown_error"} - no error_description
{"resources":["<unknown>"]}  500 consult-log
{"policies":["<unknown>"]}   500 consult-log
{"decisionStrategy":"CONSENSUS"}  **201**
{"type":"ROLE"}              500 consult-log - the type is case-sensitive here
```

**`CONSENSUS` is a 201 here and a 500 on `PUT .../authz/resource-server`.** One
enum, two endpoints on one resource server, opposite answers.

### 2.4 The two listings

Both read ten of the description's eleven query parameters; `fields` is declared
and ignored on both. Counted from the description's list rather than incremented:
`fields, first, max, name, owner, permission, policyId, resource, resourceType,
scope, type`.

```
name          case-insensitive substring
type          case-insensitive **substring** - `type=gg` finds `aggregate`,
              `type=e` finds seven types.  §1.9 says "exact" and is wrong.
policyId      exact
resource      exact, against a resource's **name or its id** - both work
scope         exact, against a scope's **name or its id** - both work
resourceType  exact and case-**sensitive** - `urn:X` finds nothing where
              `urn:x` finds the row
owner         exact; every measured row has no owner, so every value is []
permission    Boolean.parseBoolean: `true` keeps {resource, scope, uma},
              anything else keeps the other six.  On the `/permission` path it
              is ignored - the route pins it true.
first, max    either bound alone pages; a negative bound means "no bound"
              (`first=-1&max=-1` returned all 41 rows)
```

Sorted **by name, byte-wise**: `Zebra, aaa, f147-a, ...`. `?first=abc` is
`authzIntBound`'s 404, which makes these the **seventh and eighth** listings
measured answering it.

`GET .../permission` is `GET .../policy?permission=true` with the typed
serialisation, confirmed one key apart on one row.

### 2.5 The two searches

The scope and resource searches' shape exactly, re-measured rather than
inherited: an **exact, case-sensitive** name; a bare object on a hit; **204 with
an empty body** on a miss; **400 with an empty body** when `name` is absent or
empty. All four answers carry `Cache-Control: no-cache`, and the two empty ones
drop `X-Frame-Options`.

**Neither search is filtered by family.** `permission/search?name=<a role
policy>` finds it and serves it in the typed shape, which is the only route in
the description that shows the typed representation of the six types the
`/permission` listing hides.

### 2.6 `POST .../import`

```
{}            204, no Cache-Control, no body
zzz           400 Invalid json representation for ResourceServerRepresentation.
                  Unrecognized field "zzz" at line 1 column 9.
empty, null   500 consult-log
no Content-Type  415
```

So it is a **strict** decoder where `POST .../policy` beside it answers a 500 -
two writes on one resource server, two answers to an unknown field. It is the
ninth strict decoder.

What it does, measured on a resource server holding a policy and a resource:

- **It resets the three settings to the representation's own initialisers and
  then overwrites what the body names** - `PUT .../authz/resource-server`'s rule
  exactly. `{}` against `false/PERMISSIVE/AFFIRMATIVE` produced
  `true/ENFORCING/UNANIMOUS`; `{"decisionStrategy":"AFFIRMATIVE"}` produced
  `true/ENFORCING/AFFIRMATIVE`.
- **It deletes nothing.** A pre-existing scope, resource and policy all survived.
- **A name it already holds is merged into, not replaced.** Importing
  `{"name":"keep","type":"regex","config":{"pattern":"^z$"}}` over a `role`
  policy named `keep` left the type `role` and the config
  `{"pattern":"^z$","roles":"[]"}`.

### 2.7 The settings export gains `policies`, and it is a third serialisation

`GET .../settings` is already `Implemented` and its `policies` is
`[]struct{}{}` - true only because nothing could create one. It is the resource
family's situation one cut later, and it is a fix rather than a new operation.

Its entry is `{name, type, logic, decisionStrategy, config}` - the id, the
description and the owner dropped - and **its config is denormalised back to
names** where the live read serves ids:

```
live   config {"roles":"[{\"id\":\"175a47fb-...\",\"required\":false}]"}
export config {"roles":"[{\"id\":\"admin\",\"required\":false}]"}
live   config {"clients":"[\"ffccf4ad-...\"]"}
export config {"clients":"[\"admin-cli\"]"}
live   config {"groups":"[{\"id\":\"18e25293-...\",\"extendChildren\":false}]"}
export config {"groups":"[{\"path\":\"/g-authz\",\"extendChildren\":false}]"}
live   config {}                                     (an aggregate)
export config {"applyPolicies":"[\"c1\"]"}           synthesised from the
                                                     association, by name
```

**The export's order is not the listing's and not creation order either.** Seven
policies created `o1 role, o2 resource, o3 regex, o4 scope, o5 uma, o6 aggregate,
o7 resource` came back `o1, o3, o5, o6, o2, o4, o7` - creation order **with the
`resource` and `scope` rows moved to the end**. So `uma` counts as a policy
here and as a permission on `GET .../permission`. **Two partitions of one set,
one path segment apart.**

### 2.8 The config's key order

A policy's `config` is a Java map and `javamap.SizedKeyOrder(len(config), keys)`
places every measured key set exactly. `javamap.KeyOrder` gets two of eight
wrong - `{nbf, hour}` comes back `{hour, nbf}` and the twelve-key time set comes
back with two pairs swapped - so this family takes the protocol mappers' and
identity providers' constructor, not the components'.

**Whether the size argument is the stored count or the request's is not
pinned**, and this cut did not pin it: a role policy's config gains a `roles`
key on the way in, so the two counts differ by one on every such row, and a
search over every key set of the shape `{roles, z1..zn}` and `{roles, aa..}` for
n up to 13 found **no set where the two sizes disagree**. It is recorded as
unpinned rather than decided, and the goldens use key sets both readings agree
on.

### 2.9 A policy id is global and the loser does no damage

`POST .../policy` with an `id` another resource server already holds is
`409 Duplicate resource error`, reading it through the other server is a 404,
and the owning server's listing and settings both still answer 200. That is the
resource family's answer, not F131's. **And unlike the resource family, a repeat
of the server's own id is a 409 rather than an upsert** - `POST .../resource`
upserts on `_id` and `POST .../policy` does not.

### 2.10 F147's probe

Reported in full in the handover. The short form: **the verb is not the
variable, and one pair of committed-shape responses settles it.**

```
PUT /admin/realms/master/default-default-client-scopes/{id}  409  67 b  5 of 5
PUT /admin/realms/master/roles/{name}                        409  67 b  0 of 5
```

Byte-identical bodies, same status, same request `Content-Type` (varied over
four spellings on the first, which never moved), one verb. So the endpoint
decides. This cut writes no rule.

## 3. What gets built

### 3.1 Store

`internal/store/store.go`, `AuthzRepo`:

```go
CreatePolicy(ctx, p *model.AuthzPolicy) error
UpdatePolicy(ctx, p *model.AuthzPolicy) error
PolicyByID(ctx, clientID, policyID string) (*model.AuthzPolicy, error)
PolicyByName(ctx, clientID, name string) (*model.AuthzPolicy, error)
ListPolicies(ctx, clientID string) ([]*model.AuthzPolicy, error)
```

No delete: no route in the description removes a policy, and the resource
server's cascade already takes the rows with it.

`internal/model`:

```go
type AuthzPolicy struct {
    ID, ClientID, Name, Description, Type, Logic, DecisionStrategy string
    Config             []AuthzPolicyConfig   // ordered, as it arrived
    AssociatedPolicies []string              // policy ids
    Resources          []string              // resource ids
    Scopes             []string              // scope ids
    Ordinal            int
}
type AuthzPolicyConfig struct{ Name, Value string }
```

Migration `0023_authz_policy.sql` in both drivers: `authz_policy`,
`authz_policy_config`, `authz_policy_association`. Ordinals for the same reason
`authz_resource`'s exist - one set of rows, three orders.

### 3.2 Handlers

`internal/admin/authzpolicy.go`:

- `listAuthzPolicies` serves both listings, the view and the family filter
  decided by the route.
- `searchAuthzPolicy` serves both searches, likewise.
- `createAuthzPolicy` serves both creates - one handler, because they were
  measured identical on eight bodies.
- `importAuthzSettings` serves `POST .../import`.
- `authzPolicyTyped` is the nine-row projection table of §0.
- `authzPolicyExported` is the export's denormalisation of §2.7, and
  `readResourceServerSettings` starts serving it.

### 3.3 The two `evaluate` operations

Deliberately last, and deliberately assessed rather than assumed. A successful
`POST .../policy/evaluate` runs the whole authorization engine - nine policy
evaluators, decision-strategy aggregation, logic inversion, allowed and denied
scopes - and **mints a full RPT**, an access token with `exp`, `iat`, `jti` and
`sid` in it. Building the RPT means calling `internal/token`, which this branch
may not modify.

The decision is taken after the other seven land, and whichever way it goes it
is reported. If it does not land the two operations go in as `Recorded` with a
`Reason` and their measurements, which is what this repository's convention says
to do with an operation that is measured and not served.

## 4. The order of work

1. Commit the plan.
2. Migration `0023_*` in both drivers, the model type, the `AuthzRepo` methods,
   both driver implementations, `storetest` coverage. Run the Postgres suite
   with `-v`.
3. `internal/admin/authzpolicy.go` and the router entries.
4. `readResourceServerSettings` starts serving policies.
5. Package tests in `internal/admin`, one per measured claim.
6. Catalogue cases appended at the very end of `adminCases`, fixtures at the very
   end of the map and after the last helper, `make record`, goldens.
7. The mutation pass, one mutation per claim, each naming the test it must break.
8. `evaluate`: assess and decide.
9. `make lint`, `CGO_ENABLED=0 go test ./...`, the Postgres suite, `make oracle`.
10. Handover, PR, CI.

## 5. What is expected to be hard

- **The export's denormalisation.** It needs the role, client and group
  repositories to turn ids back into names and paths, from inside a serialiser
  that today knows only about scopes. It is the reason the export's `policies`
  is not a two-line change.
- **The two partitions.** `{resource, scope, uma}` on the listing and
  `{resource, scope}` on the export. A shared predicate is wrong on `uma` in one
  of the two places, which is exactly the shape of mistake this family has
  punished four times.
- **The config's two directions.** Names in, ids stored, ids out on one route
  and names out on another, with an unknown role silently dropped on the way in.
- **`evaluate`.** See §3.3.
