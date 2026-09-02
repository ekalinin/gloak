# P10 fourth cut: policy, permission and import

Branch `feat/p10-authz-policies`, off `main` at afdd00d. Everything below was
measured against a live Keycloak 26.7.1 on 2026-09-02, container `kc-policy` on
port 8156, removed when the cut finished. Port 8157 belonged to another stream
and was not touched. The container answering 8156 was confirmed to be this one
before any probe was believed: `GET /admin/serverinfo` reported 26.7.1 at 34
seconds of uptime, which is the check nine cuts have lost probes to skipping.

Plan: `docs/superpowers/plans/2026-09-02-p10-authz-policies.md`.
Previous cuts: `p10-authz-services.md` (thirteen operations), `p10-authz-cut-b.md`
(the scope family, eight), `p10-authz-resources.md` (the resource family, nine,
whose §1.9 banked the measurements this cut started from).

**Seven operations landed** - `GET`/`POST .../policy`, `GET .../policy/search`,
`GET`/`POST .../permission`, `GET .../permission/search` and `POST .../import`.
**Two did not**: `POST .../policy/evaluate` and `POST .../permission/evaluate`.
They are measured in full in §1.9 and filed as `Recorded` with a `Reason`, which
is what this repository's convention says to do with an operation that is
measured and not served. One already-served route was **fixed** on the branch
and is marked as such: `GET .../settings` now carries policies.

So the chapter closes at **29 of 31**, not 31 of 31. §5 says why, and it is the
one place this cut did not do what the brief asked.

## 1. Measurements

### 1.1 How many distinct representations the nine types have

**Eight, and they are one table rather than eight structures.**

The roadmap and §1.9 of the third cut's handover both guess "nine providers,
nine typed representations". One probe settles it: send **one config carrying
every provider's keys at once** to **all nine types**, then read each row back
through both views.

```
config sent to all nine, identical, nine keys:
  defaultResourceType nbf hour targetClaim pattern targetContextAttributes
  roles clients groups
```

The generic view (`GET .../policy`, `GET .../policy/search`) came back **byte-
identical on all nine**:

```
{"defaultResourceType":"urn:d","targetContextAttributes":"true",
 "nbf":"2026-01-01 00:00:00","clients":"[]","hour":"3","roles":"[]",
 "pattern":"^a$","groups":"[]","targetClaim":"tc"}
```

The typed view (`GET .../permission`, `GET .../permission/search`) projected
exactly the keys the type owns and nothing else:

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

**Eight distinct field sets over nine types**, `resource` and `scope` being the
only pair that shares one. `resourceType` is **not** a shared base field on the
read: a `role` policy carrying `defaultResourceType` serves it in the generic
view and does not project it, so the projection is per type rather than a
filter over one list.

Three placements in that table are not guessable from the field names:

- **`uma`'s `scopes` sits between `type` and `logic`** and everything else sits
  after `decisionStrategy`, because `scopes` is a field of Keycloak's
  `AbstractPolicyRepresentation` and the rest belong to the subclass.
- **`resourceType` sits after `decisionStrategy`** for its two types, which is
  the base class's position too - `owner` would be between them and is never
  served.
- **`uma`'s `scopes` is always present**, `[]` when empty, where every other
  type omits its collection when the config has no key. It is read from the
  **association** table rather than from the config, and served **by name**
  where the create that set it echoed the scope's **id**.

### 1.2 The create is the request echoed, and the read is not

`POST .../policy` and `POST .../permission` are one handler: identical 201s and
identical refusals on eight bodies, and **neither restricts the type** -
`POST .../permission` with `type: role` is a 201 and the row then appears on
`GET .../policy` and not on `GET .../permission`. Only the listing filters.

The 201's field order is `AbstractPolicyRepresentation`'s with `config`
appended:

```
id name description type policies resources scopes logic decisionStrategy
owner resourceType config
```

and it is the **request echoed** rather than a read. Four measurements say so:

```
POST {"name":"c1","type":"role","config":{"roles":"[{\"id\":\"admin\"}]"}}
201  ... "config":{"roles":"[{\"id\":\"admin\"}]"}          verbatim
GET  ... "config":{"roles":"[{\"id\":\"175a47fb-...\",\"required\":false}]"}

POST {"name":"p","type":"role"}            201 "config":{}
GET  the same row                          "config":{"roles":"[]"}

POST {... ,"owner":"o","resourceType":"urn:rt"}   both echoed
GET  the same row                                 neither served

POST {"name":"q1","type":"resource","resources":["res1"]}
201  "resources":["<res1's uuid>"]          resolved, so not a pure echo
GET  the same row                           no `resources` key at all
```

`policies`, `resources` and `owner` are echoed by the create and served by no
read. An **empty** association array is echoed - `{"policies":[]}` comes back
`"policies":[]` - where an absent one is dropped, so the three are pointers.

The create carries `Cache-Control: no-cache`, the charset and **no `Location`**.

### 1.3 The config is normalised on the way in, and three providers disagree

```
role    a role name becomes the role's uuid and `required` is filled in;
        an **unknown role is silently dropped** - [{"id":"admin"},{"id":"nope"}]
        stored as admin's uuid alone
client  a clientId becomes the client's uuid; an **unknown clientId is a 500**
group   a `path` becomes the group's `id` and `extendChildren` is filled in;
        an **unknown path is silently dropped**
```

**Three providers, three answers to an unknown reference.** A shared resolver is
wrong on one of the three whichever answer it picks.

A value under one of those keys that is not JSON is
`500 {"error":"invalid_request","error_description":"Cannot parse the JSON"}` -
`invalid_request` on a **500**, a shape this API has not been measured producing
anywhere else and which this cut met on exactly two inputs, both here.

And **three keys inside `config` are not config at all.** `applyPolicies`,
`resources` and `scopes` arrive inside the config, are consumed into the
association sets and are **gone from the stored config** - measured on four
types, so it is the family's behaviour and not the aggregate provider's. An
unknown target in any of the three is the consult-log 500, **including
`scopes`** - where the body's own top-level `scopes` array answers a bare
`400 {"error":"unknown_error"}`. One name, two positions on one request, two
refusals.

### 1.4 The refusals, in the order they were measured to run

```
1  an unknown field, or a `logic`/`decisionStrategy` outside its enum
       500 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
2  a taken name
       409 {"error":"Policy with name [taken] already exists",
            "error_description":"Conflicting policy"}
3  a `resources` or `policies` entry naming nothing
       500 consult-log
4  a `scopes` entry naming nothing
       400 {"error":"unknown_error"}          - no error_description at all
5  an absent or null `name` **or** an absent or null `type`
       409 {"error":"conflict","error_description":"Duplicate resource error"}
6  a `type` outside the nine
       500 consult-log
7  an `id` any resource server already holds
       409 {"error":"conflict","error_description":"Duplicate resource error"}
```

Every adjacency was pinned by a body wrong in **two** ways at once, because a
set that breaks one thing at a time passes an implementation with the checks in
any order:

```
{"name":"taken","type":"role","zzz":1}          answers about the field   1<2
{"name":"taken","type":"nope"}                  answers about the name    2<6
{"name":"taken","type":"uma","scopes":["nope"]} answers about the name    2<4
{"type":"uma","scopes":["nope"]}                answers about the scope   4<5
{"name":"f","type":"resource","resources":["nope"],"scopes":["nope"]}
                                                answers about the resource 3<4
{"type":"nope"}                                 answers about the presence 5<6
{"id":"taken","name":"free","type":"role"}      answers about the id       7 last
```

Two of those are the surprises. **The taken name is ahead of everything the body
says about itself**, and **the association resolution is ahead of the presence
check and ahead of the type check** - a body with no name at all answers about
its scope.

**§1.9 and AGENTS.md are both wrong that `type` is the gate.** It is one of two:
`{"type":"role"}` with no name is the same 409. §1.9's probe set left the type
out and never left the name out.

Four more, about the body rather than its contents, and there are **three
answers over nine inputs**:

```
null                             500 unknown_error / consult-log
`{`                              500 invalid_request / "Cannot parse the JSON"
empty, ` `, `[`, `[]`, `"x"`,
`5`, `true`                      500 unknown_error / "Cannot parse the JSON"
```

That predicate is the **inverse** of `writeCannotParseJSON`'s, which treats `[`
alone as `unknown_error` and everything else as `invalid_request`. The two agree
on `{` and `[` and disagree on the other seven, and the status here is 500 where
that helper's endpoints answer 400. AGENTS.md says the code follows the body's
shape rather than the endpoint; two shapes agree and seven do not, so this
family writes its own predicate.

Three more that are neither:

```
{"name":""}                       201 - so absent and empty are two states
{"decisionStrategy":"CONSENSUS"}  **201**, and it reads back carrying it
{"type":"ROLE"}                   500 consult-log - the type is case-sensitive
{"logic":"positive"}              500 parse - the enums are case-sensitive
```

**`CONSENSUS` is a 201 here and a 500 on `PUT .../authz/resource-server`.** One
enum, two endpoints on one resource server, opposite answers.

### 1.5 A null enum is a third state

`{"logic":null}` is a **201** and the row reads back with **no `logic` key at
all** - on the listing, the search and the typed view alike. So absent, null and
a value are three states, and only absent takes `POSITIVE`. A `*string` cannot
tell the first two apart and a default applied to both is right on one of them;
the body reads those two fields as `json.RawMessage` for that reason.

### 1.6 The two listings

Both read ten of the description's eleven query parameters; `fields` is declared
and ignored on both. Counted from the description's own list rather than
incremented: `fields, first, max, name, owner, permission, policyId, resource,
resourceType, scope, type`.

```
name          case-insensitive substring
type          case-insensitive **substring** - `?type=gg` finds `aggregate`,
              `?type=e` finds seven of the nine types.  §1.9 records this
              filter as exact and is wrong.  The **create's** own `type` is
              exact and case-sensitive, one field apart.
policyId      exact
resource      exact, against a resource's **name or its id** - both work
scope         exact, against a scope's **name or its id** - both work
resourceType  exact and case-**sensitive**: `urn:X` finds nothing where
              `urn:x` finds the row.  The one filter here that folds no case.
owner         exact against the stored owner, which no create can set to
              anything a read serves
permission    **three states, and only two of them filter.** Absent returns
              both families - 41 rows, where `true` returned 17 and `false`
              returned 24.  The value is Boolean.parseBoolean, so `abc` is
              `false`.  On the `/permission` path it is ignored - the route
              pins it.
first, max    either bound alone pages; a negative bound means no bound
```

Sorted **by name, byte-wise**: `Zebra, aaa, f147-a` came back in that order.
`?first=abc` is `authzIntBound`'s 404, which makes these the **seventh and
eighth** listings measured answering it.

`GET .../permission` is `GET .../policy?permission=true` with the typed
serialisation, confirmed one key apart on one row - which is the probe that
separates the filter from the serialisation.

### 1.7 The two searches

The scope and resource searches' shape exactly, re-measured rather than
inherited: **exact and case-sensitive**, a bare object on a hit, **204 with an
empty body** on a miss, and **400 with an empty body** when `name` is absent or
empty. All four carry `Cache-Control: no-cache` and the two empty ones drop
`X-Frame-Options`.

**Neither search is filtered by family.** `permission/search` naming a `role`
policy found it and served it in the typed shape, which makes that operation the
**only one in the description** that shows the typed representation of the six
types `GET .../permission` hides.

### 1.8 `POST .../import`, and the settings export it fills

```
{}            204, no Cache-Control, no body, five of five security headers
zzz           400 Invalid json representation for ResourceServerRepresentation.
                  Unrecognized field "zzz" at line 1 column 9.
empty, null   500 consult-log
no Content-Type  415
```

So `import` is a **strict** decoder where `POST .../policy` one path segment
away answers a 500 for the same fault. Two writes on one resource server, two
answers, which makes this the **ninth** strict endpoint and the first whose
immediate neighbour disagrees with it.

What it does:

- **It resets the three settings to the representation's own initialisers and
  then overwrites what the body names**, which is `PUT .../authz/resource-server`'s
  rule: `{}` against a stored `false/PERMISSIVE/AFFIRMATIVE` produced
  `true/ENFORCING/UNANIMOUS`, and `{"decisionStrategy":"AFFIRMATIVE"}` produced
  `true/ENFORCING/AFFIRMATIVE`.
- **It deletes nothing.** A pre-existing scope, resource and policy all survived
  an import that did not mention them.
- **A name it already holds is merged into rather than replaced.** Importing
  `{"name":"keep","type":"regex","config":{"pattern":"^z$"}}` over a `role`
  policy named `keep` left the type `role` and the config
  `{"pattern":"^z$","roles":"[]"}`.

**`GET .../settings` carries policies**, which it did not before this cut - not
because Keycloak changed but because no fixture had a policy to put in it. That
is the resource family's situation one cut later, in the same struct, and it is
a fix rather than a new operation.

Its entry is `{name, description?, type, logic?, decisionStrategy?, config}` -
the id and the owner dropped - and **its config is the live config denormalised**:

```
live   config {"roles":"[{\"id\":\"175a47fb-...\",\"required\":false}]"}
export config {"roles":"[{\"id\":\"admin\",\"required\":false}]"}
live   config {"clients":"[\"ffccf4ad-...\"]"}
export config {"clients":"[\"admin-cli\"]"}
live   config {"groups":"[{\"id\":\"18e25293-...\",\"extendChildren\":false}]"}
export config {"groups":"[{\"path\":\"/g-authz\",\"extendChildren\":false}]"}
live   config {}                    (an aggregate holding one associated policy)
export config {"applyPolicies":"[\"c1\"]"}   synthesised from the association
```

**And the export's partition is not `GET .../permission`'s.** Seven policies
created `o1 role, o2 resource, o3 regex, o4 scope, o5 uma, o6 aggregate,
o7 resource` came back `o1, o3, o5, o6, o2, o4, o7` - creation order with the
`resource` and `scope` rows moved to the end, and **`uma` left among the
policies**. Two notions of "permission" in one API one path segment apart, and
reusing the listing's predicate here moves a uma row to the wrong half.

### 1.9 Measured and not built - the two `evaluate` operations

Recorded here so the next cut starts from measurements rather than from the tag,
which is what §1.9 of the previous handover did for this one.

- **`userId` is the gate.** A body without one - including `{}` and an empty
  body - is `500 {"error":"unknown_error","error_description":"For more on this
  error consult the server log."}`. A body with one runs the engine.
- **The two spellings answer identically**, measured side by side on the gate
  and on the 200.
- **The strict decoder names `PolicyEvaluationRequest`**: `{"zzz":1}` is
  `400 Invalid json representation for PolicyEvaluationRequest. Unrecognized
  field "zzz" at line 1 column 9.` So this is the tenth and eleventh strict
  endpoint, and the second and third in this family after `import` - while the
  two creates beside them are not.
- The accepted field set is `resources, context, roleIds, clientId, userId,
  entitlements`.
- **Both take the read role set**, not the write one - swept one single role at
  a time over seven callers. `view-authorization` and `view-clients` reach the
  500; `query-clients` and `manage-realm` are 403. A POST that runs the
  authorization engine reads as a write and is guarded as a read.
- The 200's shape, on a resource server holding one resource `er1` with one
  scope `es1`, one `role` policy `ep1` and one `resource` permission `epm1`
  naming both:

```json
{"results":[{"resource":{"name":"er1 with scopes [es1]","_id":"<uuid>"},
  "scopes":[{"id":"<uuid>","name":"es1"}],
  "policies":[{"policy":{"id":"<uuid>","name":"epm1","type":"resource",
      "resources":["er1"],"scopes":["es1"],"logic":"POSITIVE",
      "decisionStrategy":"UNANIMOUS","config":{}},
    "status":"PERMIT",
    "associatedPolicies":[{"policy":{...ep1...},"status":"PERMIT",
      "associatedPolicies":[],"scopes":[]}],
    "scopes":[]}],
  "status":"PERMIT","allowedScopes":[{"id":"<uuid>","name":"es1"}],
  "deniedScopes":[]}],
 "entitlements":false,"status":"PERMIT",
 "rpt":{"exp":...,"iat":...,"jti":...,"aud":...,"sub":...,"typ":"Bearer",
        "azp":...,"sid":...,"acr":"1","realm_access":{...},
        "resource_access":{...},
        "authorization":{"permissions":[{"scopes":["es1"],"rsid":"<uuid>",
                                         "rsname":"er1"}]},
        "scope":...,"email_verified":false,"preferred_username":"admin"}}
```

  Three details in that body are not guessable. The nested `policy` objects are
  a **fourth** serialisation of a policy - `resources` and `scopes` populated
  **by name**, `config` present and empty - which is neither the generic view
  nor the typed one. `resource.name` is a **synthesised display string**,
  `"er1 with scopes [es1]"`, and not the resource's name. And **`entitlements`
  comes back `false` even when the request sent `true`**, which looks like a
  defect and is measured on one input.

- **`entitlements: true` and a request naming no resources still evaluate every
  resource.** Both answered the same body on the fixture above.

### 1.10 A policy id is global and the loser does no damage

`POST .../policy` with an `id` another resource server already holds is
`409 Duplicate resource error`, reading it through the other server is a 404,
and the owning server's listing and settings both still answered 200. That is
the resource family's answer, not F131's scope-family corruption.

**And unlike the resource family, a repeat of the server's own id is a 409
rather than an upsert.** `POST .../resource` upserts on `_id`; `POST .../policy`
does not. Three families on one resource server, three upsert rules: the scope
create upserts on the **name**, the resource create on the **id**, and the
policy create on neither.

### 1.11 The config's key order, and the size argument

A policy's `config` is a Java map and **`javamap.SizedKeyOrder` places every
measured key set exactly** while `javamap.KeyOrder` gets two of eight wrong -
`{nbf, hour}` comes back `{hour, nbf}`, and the twelve-key time set comes back
with two pairs swapped. So this family takes the protocol mappers' and identity
providers' constructor, not the components'.

**The size argument is the count of what is stored, not of what the request
sent**, and that is pinned rather than assumed. The vector fell out of a package
test that failed:

```
uma  6 keys sent, 6 stored   defaultResourceType targetContextAttributes
                             pattern targetClaim nbf hour
role 6 keys sent, 7 stored   defaultResourceType targetContextAttributes
                             nbf hour roles pattern targetClaim
uma  7 keys sent, 7 stored   the row above, byte for byte
```

The role policy's six-key request came back in the **seven**-key order, and the
two orders differ, so the request's count is refuted rather than merely
unpinned. **That is the opposite of what AGENTS.md's protocol mapper bullet says
about its own family** - "a config the create grew was built for the request's
key count and serialised at a larger one". Two families, two answers; see §3.

**And one measured key set `SizedKeyOrder` places wrongly**, which is a vector
for `internal/javamap` and this branch did not add it there, because that
package's tests are another stream's this round:

```
{roles, zzz}   sent to a uma policy as {"roles":"[]","zzz":"1"}   -> roles, zzz
               sent to a uma policy as {"zzz":"1","roles":"[]"}   -> roles, zzz
               SizedKeyOrder answers whichever order it was handed
```

The two keys collide in the model at both table sizes - `roles` and `zzz` share
a bucket at capacity 2 and at capacity 4 - so the model preserves the insertion
order, and the server does not. Every other measured set is placed exactly,
including `{aa, bb, roles}`, `{pattern, roles}`, `{yyy, zzz, roles}`, the
six-key, seven-key, nine-key and twelve-key sets and the two-key `{nbf, hour}`.
Every key set the goldens use is one of those, which is the protocol mappers'
sidestep applied a third time, and the package test that needed a colliding pair
uses `{aa, bb, roles}` instead with a comment saying why.

### 1.12 F147's probe

The brief asked for two probes and both were sent. **The result is a refutation
rather than an explanation, and it is stronger than the brief expected: the verb
is not the variable either.**

#### Probe one - a third family's `POST` and `PUT` duplicate-name conflict

The policy family, on `kc-policy`, two policies `f147-a` and `f147-b`:

```
POST .../policy          name f147-a taken   409   93 bytes  5 of 5
     {"error":"Policy with name [f147-a] already exists",
      "error_description":"Conflicting policy"}
PUT  .../policy/{id}     onto f147-a         409   67 bytes  0 of 5
     {"error":"conflict","error_description":"Duplicate resource error"}
POST .../permission      name f147-a taken   409   93 bytes  5 of 5
PUT  .../permission/{id} onto f147-a         409   67 bytes  0 of 5
PUT  .../policy/role/{id} onto f147-a        409   67 bytes  0 of 5
```

So a third family reproduces the split, on five requests rather than two.

#### Probe two - a `PUT` answering 409 where the `POST` answers 409 for a different reason

```
POST .../policy   {"name":"f147-c"}   no type     409  67 bytes  5 of 5
     {"error":"conflict","error_description":"Duplicate resource error"}
PUT  .../authz/resource-server  {}  no strategy   409  67 bytes  0 of 5
     the identical body
POST .../scope    {}   no name                    409  67 bytes  5 of 5
POST .../resource {}   no name                    409  67 bytes  5 of 5
```

**Byte-identical bodies, identical statuses, identical request `Content-Type`s,
opposite header sets, one verb apart.** That is the sharpest pair the question
has had.

#### And then the one that refutes the verb

The probe was widened to every 409 reachable on the API, on both verbs:

```
POST /users              duplicate username   409   49 b  5/5  errorMessage
POST /groups             duplicate name       409   67 b  5/5  errorMessage
POST /roles              duplicate name       409   56 b  5/5  errorMessage
POST /client-scopes      duplicate name       409   55 b  5/5  errorMessage
POST /admin/realms       duplicate realm      409   48 b  5/5  errorMessage
POST /clients            duplicate clientId   409   48 b  5/5  errorMessage
POST /clients/{u}/roles  duplicate name       409   51 b  5/5  errorMessage
POST /groups/{id}/children duplicate name     409   60 b  5/5  errorMessage

PUT  /users/{id}         onto a taken name    409   49 b  **5/5**
PUT  /client-scopes/{id} onto a taken name    409   54 b  **5/5**
PUT  /default-default-client-scopes/{id} repeat 409  67 b  **5/5**
     {"error":"conflict","error_description":"Duplicate resource error"}
PUT  /default-optional-client-scopes/{id} repeat 409 67 b  **5/5**
PUT  /roles/{name}       onto a taken name    409   67 b  **0/5**
     {"error":"conflict","error_description":"Duplicate resource error"}
```

**Those last two are the finding.** Two `PUT`s, same status, **byte-identical
67-byte bodies**, and one carries all five and the other carries none. The
request `Content-Type` was varied over four spellings on the first - absent,
`application/json`, `application/json` with a body, `text/plain` - and it never
moved off 5 of 5.

So the variable is not the status, not the body, not the body's length, not
emptiness, not the request's `Content-Type` and **not the verb**. Across
everything measured it tracks the **endpoint**, and no smaller description of it
survives.

**No rule is written.** The honest entry stays "not explained", and what the
bullet may now say that it could not before is that **the two-data-point lead
about the verb is dead**: `PUT /default-default-client-scopes/{id}` and
`PUT /roles/{name}` answer the same bytes and disagree, on one container, in one
sweep.

One lead is recorded as a lead and nothing more, because nothing here tests it:
every 0-of-5 response measured is one whose resource method could have returned
successfully - a `PUT` answering 204, a `PUT .../authz/resource-server` whose
own body is empty - and every 5-of-5 one is a refusal raised while a
representation was being built. If somebody wants to settle this, that is the
shape to look for, and it needs the server's source rather than another probe.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **The nine policy types have eight representations and one storage.** One
  config carrying every provider's keys at once was sent to all nine types: the
  generic view came back **byte-identical on all nine** and the typed view
  served exactly the keys the type owns - `resource` and `scope` sharing one
  shape and the other seven each having their own. `resourceType` is not a
  shared base field on the read: a `role` policy carrying
  `defaultResourceType` serves it in the generic view and does not project it.
  So the provider model this family needs is a table over one stored map, not
  nine structures, and `uma`'s `scopes` is the one projected field that does not
  come from the config at all - it is read from the association set, always
  present, and served **by name** where the create that set it echoed the id.
- **A policy needs a name *and* a type**, and missing either is
  `409 Duplicate resource error`. This file and F129 both say `type` is the
  gate, from a probe set that left the type out and never left the name out;
  `{"type":"role"}` with no name is the same 409. The accepted type set is
  still the nine of the previous entry and still not the provider catalogue.
- **A policy create's 201 is the request echoed and its read is not**, which is
  the opposite of the resource create two path segments away. The config comes
  back exactly as it was sent where the read has role names resolved to uuids
  and `required` filled in; `owner` and `resourceType` are echoed and no read
  serves either; and a `role` create with no config answers `config:{}` where
  its own read answers `{"roles":"[]"}`, because the provider's key is written
  after the response representation is built.
- **Three providers resolve a reference and all three answer an unknown one
  differently.** An unknown role in `config.roles` is silently dropped, an
  unknown group path in `config.groups` is silently dropped, and an unknown
  clientId in `config.clients` is a 500. A shared resolver is wrong on one of
  the three whichever answer it picks. And three keys inside `config` are not
  config at all: `applyPolicies`, `resources` and `scopes` are consumed into
  the association sets and vanish from the stored config, on every type - where
  an unknown target is the consult-log 500 for all three, **including
  `scopes`**, which the body's own top-level `scopes` array answers with a bare
  `400 {"error":"unknown_error"}` carrying no description at all.
- **`GET .../settings` and `GET .../permission` partition the same rows
  differently.** The listing counts `resource`, `scope` and `uma` as
  permissions; the export moves `resource` and `scope` to the end of its
  `policies` array and leaves `uma` among the policies. Measured on seven
  policies created with the two families interleaved. A shared predicate is
  wrong on `uma` in one of the two places, which is the fifth time this API has
  had a rule that is right on one family and inverted on its neighbour.
  The export also **denormalises**: a role's uuids go back to names, a client's
  to clientIds, a group's to paths, and the three association sets are
  synthesised back into `applyPolicies`, `resources` and `scopes` by name - so
  a policy whose live read answers `config:{}` exports a config with three keys
  in it.
- **A null enum is a third state.** `{"logic":null}` is a 201 and the row reads
  back with no `logic` key at all, on the listing, the search and the typed view
  alike, where an absent `logic` gets `POSITIVE`. A plain string field with a
  default is right on one of the two and cannot express the other.
- **`CONSENSUS` is a 201 on `POST .../policy` and a 500 on
  `PUT .../authz/resource-server`.** One enum value, two endpoints on one
  resource server, opposite answers - so the two accepted lists are two lists.
- **A policy's `config` is a Java map placed by `javamap.SizedKeyOrder`, and its
  size argument is the count of what is **stored**.** A six-key config sent to a
  `role` policy - which adds `roles`, making seven - came back in the seven-key
  order, byte for byte the same as a `uma` policy sent all seven outright, and
  the six-key order is different. That is the opposite of what this file says
  about the **protocol mappers**, where a config the create grew "was built for
  the request's key count and serialised at a larger one". Two families, two
  answers, and neither can be read off the other.
- **Three families on one resource server, three upsert rules.** The scope
  create upserts on the **name**, the resource create on the **`_id`**, and the
  policy create on **neither** - a repeat of either is a 409. A policy id is
  global the way a resource id is, and the losing create does the other resource
  server no damage.
- **`POST .../import` is strict where the two creates beside it are not.** The
  same unknown field is `400 Invalid json representation for
  ResourceServerRepresentation` there and a 500 `Cannot parse the JSON` on
  `POST .../policy`, on one resource server. It **deletes nothing**, it
  **resets the three settings to the representation's own initialisers and then
  overwrites what the body names**, and a name it already holds it **merges
  into** rather than replaces - a `regex` body imported over a `role` policy
  left the type alone and grew the config.
- **The unusable-body predicate on `POST .../policy` is the inverse of the one
  this repository already had.** `null` is the consult-log 500, a body
  beginning `{` is `invalid_request` / "Cannot parse the JSON", and everything
  else - empty, whitespace, `[`, `[]`, a string, a number, a literal - is
  `unknown_error` / "Cannot parse the JSON". `writeCannotParseJSON` treats `[`
  alone as `unknown_error`; the two agree on two shapes and disagree on seven,
  and the status is 500 here where that helper's endpoints answer 400.
- **The fifth security-header exception is not the verb either, and one pair of
  responses says so.** `PUT /admin/realms/{r}/default-default-client-scopes/{id}`
  on the repeat and `PUT /admin/realms/{r}/roles/{name}` onto a taken name both
  answer 409 with the identical 67-byte
  `{"error":"conflict","error_description":"Duplicate resource error"}`; the
  first carries all five security headers and the second carries none. The
  request `Content-Type` was varied over four spellings on the first and never
  moved it. So after the status, the body, the body's length, emptiness and the
  request's `Content-Type`, the **verb** is refuted too - which was the lead
  this bullet carried. Fourteen 409s were measured on both verbs in one sweep
  and the only description that survives all of them is "the endpoint decides".
  This is the fifth thing that bullet has been wrong about and the first
  correction that removes a claim without adding one.

## 3. Lines in AGENTS.md and the observed document these measurements contradict

Five, and one of them is this cut's own predecessor.

1. **AGENTS.md, the authorization bullet: "A `type` is what a policy and a
   permission need".** It needs a name and a type. `{"type":"role"}` with no
   name is the same 409 the empty body gets. The rest of that bullet - the nine
   accepted types, `uma` accepted and absent from the catalogue, `user` and
   `client-scope` offered and refused - was re-measured and holds.

2. **AGENTS.md's fifth security-header exception, the lead it carries.** "Across
   the two families a `POST`'s 409 keeps the five and a `PUT`'s drops them; that
   is two data points, not a rule." It is now a refuted lead rather than a weak
   one: two `PUT`s answering byte-identical 409s disagree with each other. §1.12
   has the fourteen rows.

3. **AGENTS.md's protocol-mapper bullet, generalised beyond its family.** "A
   create that appends a key of its own appends it after the first table, so a
   config the create grew was built for the request's key count and serialised
   at a larger one." A policy's config does the opposite - the stored count
   decides - and the vector that shows it is in `internal/admin`'s own tests.
   The bullet is about protocol mappers and is not wrong about them; what is
   new is that it does not generalise, and this is the second family measured
   for it.

4. **`docs/superpowers/handover/p10-authz-resources.md` §1.9, twice.** It records
   the policy listing's `type` filter as exact - it is a case-insensitive
   substring, `?type=gg` finds `aggregate` - and it records `type` as the create's
   only gate. Both were fixed by measurement rather than inherited, which is the
   check the brief asked for and which paid twice.

5. **`internal/javamap`'s `SizedKeyOrder` is wrong on one measured key set**, and
   nothing in the package's own tests says so because the vector is new.
   `{roles, zzz}` comes back `[roles, zzz]` from **both** request orders and the
   model answers whichever order it was handed - the two keys share a bucket at
   both table sizes, so the model preserves an insertion order the server does
   not. It is a vector rather than a contradiction of anything written down, and
   it is not fixed here because that package's tests belong to another stream
   this round. §1.11 has it.

Two things were **confirmed** against a bigger sample rather than refuted, and
both were single-measurement claims: `authzIntBound`'s 404 for an unparseable
bound, now on a seventh and eighth listing, and the resource family's finding
that a global-id collision leaves the other resource server undamaged, now on a
third id space.

## 4. Follow-up dispositions

**F129 - the other authorization-services operations.** Seven more landed, which
leaves **two**: `POST .../policy/evaluate` and `POST .../permission/evaluate`.
Their measurements are in §1.9 and their cases are in the catalogue as
`Recorded`, so the next cut starts from measurements rather than from the tag -
which is what the third cut did for this one and the second for the third. Two
of this entry's statements were already corrected by the third cut; a third is
corrected here, which is the one the third cut wrote: policy and permission need
a name **and** a type.

**F131 - a cross-resource-server scope id collision corrupts the other resource
server.** Unchanged and **not extended**. A policy id carries the same global
constraint and was measured **not** corrupting: after the colliding create the
other resource server's listing and settings both answered 200. That is the
resource family's answer on a third id space, so the entry stays a statement
about the scope family alone and Gloak's divergence needs no extension here.

**F147 - the fifth security-header exception is a measured split nobody has
explained.** **The probe this entry names was sent, and both halves of it hold**
- a third family reproduces the split on five requests, and a `PUT` and a `POST`
answering the identical 67-byte body one verb apart disagree. But the sweep that
went with them **refutes the entry's own lead**: two `PUT`s answering
byte-identical 409s, `default-default-client-scopes` and `roles/{name}`,
disagree about the five. So the entry can be shortened rather than extended -
the verb is out, and "the endpoint decides" is what fourteen measured 409s
leave. §1.12 has the table. No rule was written and none should be.

**F95 - a client's `attributes` is serialised from a Go map.** Untouched, and
the pattern it asks for is now the majority by a wider margin: this cut adds a
sixth family serialising a Java map from an ordered slice with a marshaller of
its own (`authzPolicyConfigMap`), after `identityProviderConfig`,
`componentConfig`, an organization's attributes, a protocol mapper's config and
`authzResourceAttributes`. The client is still the holdout and it still lives in
`clients.go`, whose fix re-records five goldens in another chapter.

**F133 - `writeEmptyStatus` lives in `internal/admin`.** Unchanged and now used
by a third family: the two searches' 204 and 400 reach it. That strengthens the
case for the move rather than the case against it.

**F134 - four listings still treat an unparseable bound as no bound.**
Unchanged. The two new listings are the seventh and eighth measured answering
the 404 and they use `authzIntBound`, so the four this entry names are unmoved.

**New, and filed here because the follow-ups list is not this branch's to
edit: `requireJSONBody` accepts an absent `Content-Type` and Keycloak does
not.** Measured on nine endpoints across four chapters - `POST /users`,
`/roles`, `/groups`, `/client-scopes`, `/components`, `PUT /admin/realms/{r}`,
`POST .../authz/resource-server/scope`, `/resource` and `/policy` - all nine
answer `415 {"error":"The content-type header value did not match the value in
@Consumes"}` for a body sent with no `Content-Type` at all, where
`internal/admin/scopemappings.go`'s `requireJSONBody` returns true for the empty
string. It is pre-existing, it is API-wide rather than this family's, no golden
covers it because no case sends a body without the header, and fixing it here
would put a change to every write in the Admin API inside a branch about
policies. It is a one-line change with a wide blast radius and it should be its
own cut, with a case per chapter.

**New: the two `evaluate` operations.** §1.9 has the whole measurement. What
stops them is not the engine alone: the 200's `rpt` is an access token's claim
set, which lives in `internal/token`, and reproducing it in `internal/admin`
would be the second truth the boundary table exists to prevent. The next cut
should either export a claims builder from `internal/token` or take those two
operations together with a change there.

## 5. The mutation pass, and the four survivors

**Forty mutations**, one per claim, each naming the test it had to break and each
reverted. Thirty-five were killed on the first pass. The five that survived are
below; **four were holes in a test and one was a claim no test made at all**, so
this pass found more than the previous cut's did.

**Survivor 1 - a real hole. The create's echo was asserted only where the two
sources agree.** Building `authzPolicyCreated.Config` from the **stored** config
rather than the request's left `TestPolicyCreateIsTheRequestEchoed` green,
because its create was a `uma` policy: uma adds no provider key and consumes no
association key, so its stored config *is* its request's. A body with no config
at all cannot see it either - both sources marshal to `{}`. The one body that
separates them is a **role** create carrying a config, where the request says
two keys and the read says three. The test uses one now and the mutation dies.

**Survivor 2 - a real hole. Three states, and only two were ever asked for.**
Replacing the `permission` partition's three-state check with a two-way one left
`TestPolicyAndPermissionAreOneListingWithTwoViews` green, because every request
in it named a half: `?permission=true`, `?permission=false` and the `/permission`
path. The **bare** listing - the commonest request there is - was never sent, and
it is the only one a two-way predicate gets wrong. It is sent now.

**Survivor 3 - a real hole, and it is the third cut's `Zebra` again.** Deleting
the name branch from `?resource=` and from `?scope=` left
`TestPolicyListingFiltersAndOrders` green, because the fixture created its
resource as `{"_id":"lres","name":"lres"}` and its scope as
`{"id":"lsc","name":"lsc"}`. **A row whose id and name are the same string
cannot tell a name match from an id match.** The ids and the names differ now,
and a third mutation was added for the other direction - dropping the *id*
branch - which the old fixture could not see either. All three die.

**Survivor 4 - a claim with no test.** Disabling the block that consumes
`applyPolicies`, `resources` and `scopes` out of the config changed no golden,
because every fixture in the catalogue names its associations through the
**body's** three arrays rather than through the config. The path was reachable
and unasserted, which is worse than a hole in an assertion: nothing claimed to
cover it. `TestConfigAssociationKeysAreConsumed` covers it now, on four types,
in both directions, with the two different refusals an unknown target gets.

One mutation was **badly written rather than informative** and is recorded so it
is not read as a fifth survivor: replacing the settings export's `Policies` with
an empty literal left an unused variable and broke the build. Rewritten as
`exportedPolicies[:0]` it dies on the golden, which is what it should always
have been.

**A note on what the pass cannot reach.** Every case in this cut runs against
`master`, and none of this family's responses derives from the realm name - no
body carries it, the export does not, and the two ids in play are the client's
and the policy's. So there is nothing here for `SecondRealm` to pin, and saying
so is the answer to "what do your tests not cover" rather than an omission.

## 6. Parity, before and after

```
Parity: 361 -> 368 of 535 (+7)

chapter                         before  after  delta
admin/authz-resource-server         22     29     +7
```

The chapter's denominator is thirty-one. **Twenty-nine are served and two are
not**: `POST .../policy/evaluate` and `POST .../permission/evaluate`, which are
in the catalogue as `Recorded` with a `Reason` and are measured in full in §1.9.

One of the twenty-nine moved without moving the total, and it is a fix rather
than an addition: `GET .../settings` was already counted as served and was
already wrong in a way no golden could see, because nothing could create a
policy to put in it. It is the reason this cut's diff touches `authz.go`, and it
is the second time that one struct has held an always-empty key for exactly that
reason - `resources` was the first, one cut ago.

Twenty-four goldens were recorded and **no existing golden moved**, on a clean
checkout. The first recording pass failed two cases and the reason is worth
keeping: **the two `evaluate` cases shared a fixture with two others**, and the
recorder shares one container, so the second client create answered 409 with no
`Location` and the capture came back empty. `userFixture`'s doc comment says so
in as many words and the convention is one fixture per case; they have their own
now.
