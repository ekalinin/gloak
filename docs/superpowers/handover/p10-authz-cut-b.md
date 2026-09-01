# P10 second cut: the authorization-services scope family

Branch `feat/p10-authz-cut-b`, off `main` at 969fcc7. Everything below was
measured against a live Keycloak 26.7.1 on 2026-09-01, container `kc-authzb` on
port 8141, removed when the cut finished. `kc-reg` was another stream's on 8142
and was not touched. The container answering 8141 was confirmed to be this one
before any probe was believed: `GET /admin/serverinfo` reported 26.7.1 at two
minutes of uptime, which is the check five cuts have lost probes to skipping.

Plan: `docs/superpowers/plans/2026-08-31-p10-authz-cut-b.md`.
First cut: `docs/superpowers/handover/p10-authz-services.md`.

**Eight operations landed**, the whole scope family:
`GET`/`POST .../scope`, `GET .../scope/search`, `GET`/`PUT`/`DELETE
.../scope/{id}`, and `.../scope/{id}/permissions` and `.../scope/{id}/resources`.

## 1. Measurements

### 1.1 What §1.9 of the first cut's handover survived

Twelve claims, re-measured one at a time rather than transcribed. **Ten stood,
one was true and incomplete, one was under-specified in a way that decided an
implementation.** A thirteenth, from §1.4, was wrong.

| §1.9 claim | verdict |
|---|---|
| a duplicate name is 201 returning the existing scope, same id | **true and incomplete.** It also *writes* the body's other fields onto the row it found: `{"name":"alpha","displayName":"changed","iconUri":"http://i"}` against a bare `alpha` came back, and read back, with both. It is an upsert, not a lookup-and-echo. |
| no name is a 409 `Duplicate resource error`; `{"name":""}` is a 201 | stands |
| the body's `id` wins | stands, **and the id is resolved first and alone**: an id that names nothing plus a name that is taken is a 409, not an upsert onto the name. That is the probe that tells "id wins" from "id or name, whichever matches". |
| the 201 carries no `Location` | stands |
| field order `id, name, iconUri, displayName` | stands, **and it is six fields on the create** - see §1.3 |
| `{` is `invalid_request`; an empty body is a 500; an unknown field is the strict prose shape | stands. `[` is a fourth answer, `unknown_error` / "Cannot parse the JSON", which is the per-body-shape rule holding. `null` is the same 500 as an empty body, on both verbs. |
| `GET .../scope/{unknown}` is a 404 with an empty body and no `Content-Type`, `Cache-Control: no-cache`; the `PUT` and `DELETE` 404s carry none | stands, **and it omits `X-Frame-Options` too** - see §1.4 |
| `search?name=` is exact, a bare object, 204 on a miss, 400 with an empty body when `name` is absent or empty | stands, **and it is case-sensitive**: `CaseTest` and `casetest` coexist and each is found only by its own spelling |
| the listing's `?name=` is a case-insensitive substring | stands |
| the listing is sorted by name and pages on `first`+`max` | stands, **and both halves were under-specified**: the sort is byte-wise, not case-folded, and **either bound alone pages** |
| `PUT` replaces and ignores the body's `id` | stands, both halves |
| `DELETE` success is 204 with no `Cache-Control` | stands |

**The one that was wrong is §1.4's**, and it is the reason this cut needed a
column: "`GET .../settings` exports scopes in an order nothing explains -
neither name order, insertion order nor id order". **It is insertion order.**
Four scopes created `zulu, yankee, xray, whiskey` - deliberately the reverse of
name order - came back in exactly that order from the export and in the other
order from the listing beside it, and deleting `xray` and recreating it moved it
to the **end**. The first cut had four scopes and no record of what order they
were made in, so nothing in its data could have shown this; the fix is to build
the set for the question rather than to look harder at the set you have.

A second §1.4 claim needed two goes and ended up standing as written. "Each
entry is stripped of its `id`" is right. An early probe in this cut suggested
the export was name-only, and it was wrong: the scopes it looked at had had
`iconUri` and `displayName` removed by an upsert two probes earlier. Re-measured
on scopes built for the question, the export carries all three and drops only
the id. **A measurement taken on state some other probe moved is not a
measurement**, and this one nearly went into the code.

### 1.2 The 409 `Duplicate resource error` does not decide the security headers

AGENTS.md's newest security-header exception reads **"a 409 `Duplicate resource
error` sends none of the five."** It is false, and the counterexample has been
committed in this repository since P5.

Measured on one container in one sweep:

| response | five security headers |
|---|---|
| `PUT .../authz/resource-server`, no `decisionStrategy` | **none** |
| `POST .../authz/resource-server/scope`, no `name` | **all five** |
| `PUT .../authz/resource-server/scope/{id}`, no `name` | **none** |
| `PUT /default-default-client-scopes/{id}` repeated | **all five** |
| `POST .../protocol-mappers/models`, no `name` | **none** |
| `POST .../protocol-mappers/models`, duplicate name (`errorMessage` shape) | all five |
| `POST /clients`, `/users`, `/client-scopes`, `/groups`, `/roles` duplicates | all five |

`internal/conformance/testdata/golden/admin/realms-admin/default-default-client-scope-duplicate.http`
is a 409 `Duplicate resource error` carrying all five and it predates the bullet
that says none do. The bullet was written from two endpoints that agree and one
golden that disagrees, and nobody looked at the third.

**The sharpest pair is one verb and one path segment apart.** `POST .../scope`
with `{}` and `PUT .../scope/{id}` with `{}` produce byte-identical bodies from
identical requests - same `Content-Type`, same realm, same resource server - and
disagree on all five headers. Both causes of the `PUT`'s 409 agree with each
other (an absent name, and a name another scope holds) and both causes of the
`POST`'s do too, so it is decided per **verb on an endpoint** and not by the
body, the cause, or the status.

The first cut's explanation - "the omission belongs to that response shape" - is
the expensive kind: a correct observation about two endpoints with a wrong rule
attached. `writeDuplicateResource`, which deletes the five, is right for the two
call sites it had and now has a third that must not use it.

### 1.3 The create's 201 is the request echoed, not a read

`ScopeRepresentation` declares **six** fields, and the strict decoder is what
says which: `type`, `owner`, `uris`, `attributes` and `scopes` all answer
`Invalid json representation for ScopeRepresentation. Unrecognized field ...`,
and `policies` and `resources` do not.

Those last two are **echoed back and stored nowhere**. A create carrying
`"policies":[]` and `"resources":[]` answers with both, and the read, the
listing, the search and the settings export all answer four keys - while
`GET .../resource` and `GET .../policy` beside them stay `[]`. Field order,
from a create that sent all six in reverse:

```
id, name, iconUri, policies, resources, displayName
```

`displayName` is **last**, after the two echoed arrays. `{"policies":null}` is
not `{"policies":[]}` - the key is absent from the response for `null` and
present for `[]`.

Two things about the echo are measured and not reproduced, and the follow-up
says so: a non-empty `resources` is echoed verbatim
(`[{"name":"r"}]` in, `[{"name":"r"}]` out), while a non-empty `policies` gains
three Java defaults on the way out (`logic: POSITIVE`,
`decisionStrategy: UNANIMOUS`, `config: {}`). A `policies` array holding a
**string** is a 400 `unknown_error` / "Cannot parse the JSON". Gloak echoes both
verbatim, which is exact for `[]` - the only value any resource server it can
build will ever hold - and one Java default short for a non-empty `policies`.

### 1.4 `X-Frame-Options` on an empty body follows the request's `Content-Type`

AGENTS.md records this rule for a **204**, measured across seven Content-Type
values on one endpoint, and names `httpx.WriteNoContent` as the one place that
decides it. The scope family has empty-bodied **404**s, a **400** and a
**204** that all follow the same rule:

```
GET    /scope/{unknown}   no Content-Type            no X-Frame-Options
GET    /scope/{unknown}   Content-Type: text/plain   no X-Frame-Options
GET    /scope/{unknown}   application/json           X-Frame-Options
DELETE /scope/{unknown}   no Content-Type            no X-Frame-Options
DELETE /scope/{unknown}   application/json           X-Frame-Options
GET    /scope/search      no name, no Content-Type   no X-Frame-Options
```

So the variable is the **empty body**, not the 204. The gate's own 404 and every
JSON error on the family carry all five whatever the request declared, because
they have bodies. That does not remove the exception, it widens it - from "a
204" to "a response with no body", which is a bigger claim and a falsifiable
one.

### 1.5 The gate covers all eight scope routes, and a bad `first` is a fourth producer of that 404

The brief's open question. Measured on a client without
`authorizationServicesEnabled`, on all eight scope routes, with a caller holding
`manage-authorization` and one holding no admin role: every one is
`404 {"error":"HTTP 404 Not Found"}`, identically. The family shares one gate
and it runs before authorization, exactly as the first cut measured on the
resource server. So on this family the tag predicted it and the rule held - the
first time in this API that a rule stated over a route family has generalised to
its neighbours rather than inverting.

**New, and general: a query parameter the description types as `integer` that
does not parse makes the route not match.**

```
GET .../authz/resource-server/scope?first=abc   404 {"error":"HTTP 404 Not Found"}
GET /admin/realms/master/roles?first=abc        404 {"error":"HTTP 404 Not Found"}
GET /admin/realms/master/users?first=abc        404
GET /admin/realms/master/groups?first=abc       404
GET /admin/realms/master/clients?first=abc      404
GET /admin/realms/master/client-scopes?first=abc  200 - no such parameter, ignored
```

`?first=1.5` and a value that overflows an int are the same 404. `?first=` is
200 and pages nothing, so an empty value counts as absent rather than as
unparseable. That body already had three producers - an unmatched path, a wrong
verb on a known path, and a switched-off resource; this is a **fourth**, and the
only one that reaches a route the caller may use on a resource that exists.

**`pageRoles`'s own comment said this had never been probed.** It is corrected on
this branch to record the measurement, and the four older listings still treat an
unparseable bound as no bound - a divergence this cut files rather than fixes,
because four listings in three other chapters are not one branch's to move.

### 1.6 The role sets are the first cut's, re-measured rather than carried over

Seven callers, one single role each, over eleven routes:

| | opened by |
|---|---|
| the five reads | `view-authorization`, `manage-authorization`, `view-clients`, `manage-clients` |
| `POST`, `PUT`, `DELETE` | `manage-authorization`, `manage-clients` |

`query-clients` and `manage-realm` are 403 on every one. **The role check
precedes the scope lookup**: a `view-authorization` caller deleting a scope that
does not exist gets 403 where a `manage-authorization` caller gets 404.

Agreeing was the finding rather than the assumption - a role set carried over
from a neighbouring family has been wrong four times in this repository.

### 1.7 A cross-resource-server scope id collides, and it corrupts the other server

**A scope id is global, not per resource server.** Creating a scope with an id
another resource server already holds is a
`409 {"error":"conflict","error_description":"Duplicate resource error"}` with
all five headers, and reading one server's scope id through another is a 404. So
the id is unique globally and the *name* is unique per resource server -
`alpha` exists in two at once.

**And the 409 leaves the owning resource server's listing broken.** Reproduced
on a fresh pair of clients built for the question:

```
POST rs-a/scope {"id":"dup","name":"n-a"}   201
POST rs-b/scope {"id":"dup","name":"n-b"}   409
GET  rs-a/scope                             400 {"error":"unknown_error",
                                                 "error_description":"Cannot parse the JSON"}
GET  rs-a/scope/dup                         404
GET  rs-a/settings                          500
```

The row is still there - the listing serves the first seven of sixteen rows and
breaks on the eighth, which is where that name sorts. A control says the damage
to the listing happens either way and the per-id read is spared if the scope was
read once before the collision, which is a cache effect rather than a rule.

This is Keycloak's own defect and **Gloak does not reproduce it**: a global
primary key makes the colliding create a clean `ErrConflict` and touches no
other resource server's rows. That is a deliberate divergence, filed as one.

### 1.8 The rest of what the family answers

```
GET  /scope                200 application/json;charset=UTF-8, Cache-Control: no-cache
                           sorted by name **byte-wise** - ALPHAX, Bravo, brand-new,
                           charlie - so an uppercase name sorts before every
                           lowercase one; ?name= is a case-insensitive substring;
                           ?scopeId= is exact and ANDed with ?name=; ?first= and
                           ?max= each page alone, unlike the role listings;
                           ?first=100 and ?max=0 are []; the filter runs before
                           the page
POST /scope                201, Cache-Control: no-cache, charset, no Location;
                           Content-Type: text/plain is 415, none at all is 201
GET  /scope/search?name=   200 bare object / 204 miss / 400 empty body, all three
                           Cache-Control: no-cache
GET  /scope/{id}           200 charset no-cache; 404 empty body no Content-Type,
                           **with** no-cache
PUT  /scope/{id}           204 no Cache-Control; 404 empty body **without**
                           no-cache; 409 with no security headers; replaces;
                           ignores the body's id; renaming to its own name is 204
DELETE /scope/{id}         204 no Cache-Control; 404 empty body no Cache-Control
GET  /scope/{id}/permissions   200 [] charset no-cache; 404 empty for an unknown scope
GET  /scope/{id}/resources     the same
```

Orderings, each with the probe that decides it:

- `PUT`: strict decode, then the scope lookup, then the name. An unknown field
  addressed to a scope that does not exist is the strict 400; a good body
  addressed to it is the empty 404; `{}` addressed to one that exists is the 409.
- `POST`: strict decode, then the id, then the name. `{"zzz":1}` - unknown field
  and no name at once - is the strict 400.
- A scope id is a free string: `{"id":"zzz"}` is a 201 creating a scope whose id
  is three bytes.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **A 409 `Duplicate resource error` sends the five security headers on two
  endpoints and not on two others, and the body is not what decides.** This
  file's fifth exception says a 409 of that shape sends none of them; it is
  false in both directions. `POST .../authz/resource-server/scope` with `{}` and
  `PUT .../authz/resource-server/scope/{id}` with `{}` answer byte-identical
  bodies to identical requests one path segment apart and disagree on all five.
  `PUT /default-default-client-scopes/{id}` repeated sends all five, and **the
  repository's own golden has said so since P5** - the bullet was written from
  two endpoints that agree and a committed measurement nobody went behind, which
  is the second time a contract line has been refuted by this repository's own
  goldens after the charset split. Both causes of each verb's 409 agree with
  each other, so the variable is the **verb on the endpoint**. That makes the
  security headers decided by the path, the endpoint, the request's
  `Content-Type`, the method, the status and now the verb-endpoint pair - six
  rules, no two alike, and `writeDuplicateResource` is correct for its two call
  sites and must not grow a third.
- **The `X-Frame-Options` rule is about the empty body, not about the 204.**
  This file records it as "a 204 carries `X-Frame-Options` only when the request
  declared an `application/*` `Content-Type`", measured across seven values on
  one endpoint, and names `httpx.WriteNoContent` as the one place that decides
  it. The authorization scopes answer empty-bodied **404**s and a **400**, and
  all of them follow the same rule: `GET .../scope/{unknown}` with
  `application/json` carries the header, with `text/plain` or with nothing does
  not, and the `DELETE`'s 404 agrees. So `WriteNoContent` is one of two places
  that decide it, the second is `internal/admin`'s `writeEmptyStatus`, and any
  future empty-bodied response needs the same branch. Nothing about the status
  is doing the work.
- **A query parameter the description types as `integer` that does not parse is
  `404 {"error":"HTTP 404 Not Found"}`.** Measured on five listings across four
  families - the authorization scopes, `/roles`, `/users`, `/groups` and
  `/clients` - all alike, and on `?first=1.5` and a value that overflows an int
  as well as on `?first=abc`. `?first=` is 200 and counts as absent. That body
  had three producers and this is a **fourth**: unlike the other three it
  reaches a route the caller may use, on a resource that exists, and refuses it
  because a parameter could not bind. `pageRoles` treats it as no bound and its
  comment said the case had never been probed; it has, the comment is corrected,
  and the four older listings are a follow-up rather than a fix, because the
  measurement arrived in a branch that owns none of them.
- **A create's response body is not always a read of what it wrote.**
  `POST .../authz/resource-server/scope` echoes the request's `policies` and
  `resources` back, and no other view of the same scope carries either key -
  the read, the listing, the search and the settings export all answer four -
  while `GET .../resource` and `GET .../policy` stay `[]`, so nothing was
  stored. The field order puts `displayName` **after** both echoed arrays.
  Answering the create with the same serialiser the read uses is the obvious
  implementation, it agrees on every body that omits the pair, and it is wrong
  on the one that does not.
- **One set of authorization scopes has two reads and two orders, and both are
  reproducible.** `GET .../scope` is sorted by name **byte-wise** - an uppercase
  name sorts before every lowercase one, so `ALPHAX, Bravo, brand-new` - and
  `GET .../authz/resource-server/settings` serves the same set in **creation
  order**, with a scope deleted and recreated moving to the end. Four scopes
  built `zulu, yankee, xray, whiskey` are what say so; a set created
  alphabetically records the same bytes for both and lets a store that sorts in
  SQL pass. The first cut recorded the export's order as "neither name order nor
  insertion order and not pinned", from four scopes whose creation order nobody
  had written down.
- **The scope family's `name` means two things one path segment apart.** The
  listing's `?name=` is a case-insensitive **substring** and
  `.../scope/search?name=` is **exact and case-sensitive**: two scopes named
  `CaseTest` and `casetest` coexist and each is found only by its own spelling,
  while the listing's `?name=lph` returns two rows. One matcher shared between
  them is wrong on one of them.
- **`POST .../scope` is an upsert whose key is the body's id when it has one.**
  A duplicate name returns the existing scope's id **and writes the body's other
  fields onto it**; an id that names a scope renames that scope; an id that
  names *nothing* creates with it and then meets the name's uniqueness, so
  `{"id":<unknown>,"name":<taken>}` is a 409 rather than an upsert onto the
  name. "Resolve by id or by name, whichever matches" passes every other body
  and gets that one wrong.
- **A scope id is unique globally and a scope name is unique per resource
  server**, and colliding on the id corrupts the *other* resource server.
  Creating a scope with an id another resource server holds is a 409, and
  afterwards that other server answers `GET .../scope` with
  `400 "Cannot parse the JSON"`, `GET .../settings` with a 500, and
  `GET .../scope/{that id}` with a 404 - for a row still in its listing.
  Reproduced on a fresh pair of clients. This is one of the few measured
  behaviours Gloak deliberately does **not** reproduce: a global primary key
  makes the colliding create a clean 409 and touches nothing else. A handler
  that corrupted its own store to match would be indefensible, and the
  divergence is filed rather than hidden.
- **Two 404s on one path differ only in `Cache-Control`, and here the method
  decides it.** `GET .../scope/{unknown}` carries `no-cache`; the `PUT`'s and
  the `DELETE`'s on the same path carry none. That is the opposite of what this
  file concludes about the six measured deletes, where every generalisation over
  the method has failed twice and "pinned per endpoint" is all that survives -
  so the two claims are not in tension, they are both "it is pinned", measured
  per response.
- **The scope family's 404 for a scope that does not exist is not one of the
  twenty-one spellings. It is the absence of one**: `Content-Length: 0`, no
  body, and no `Content-Type` at all. Measured on the `GET`, the `PUT`, the
  `DELETE` and the two sub-listings, and for an id belonging to another resource
  server. The search's 400 and its 204 miss are the same shape. So the count of
  not-found spellings does not move, and a handler reaching for
  `httpx.WriteMessageError` here is wrong in a way no error-string list catches.
- **The authorization-services gate covers every route under
  `authz/resource-server`, and this is the first rule in this API that
  generalised to a neighbouring family rather than inverting.** All eight scope
  routes answer `404 {"error":"HTTP 404 Not Found"}` for a client without
  `authorizationServicesEnabled`, to a caller holding `manage-authorization` and
  to one holding no admin role alike - the same shape the first cut measured on
  the resource server itself. It was still measured on all eight rather than
  assumed from three, because the alternative has been wrong five times.

## 3. Follow-up dispositions

- **F129 - the other twenty-six authorization-services operations. Partly
  closed.** Eight of the twenty-six are served: the whole scope family. The
  eighteen left are the resource family's nine, the policy and permission
  families' four each, and `import`. **The count in F129 is right and this
  cut's own plan first got it wrong**, dropping `GET /policy/search` and
  `GET /permission/search` from a table it built by hand - a count re-derived
  from a summary inside the paragraph that quotes "count from the list, never
  increment". The list is now generated from the vendored description and the
  plan says so. F129 should be updated to name the eighteen.
- **F122 - the two admin logout triggers notify nobody. Not taken, and it
  belongs in its own branch.** The brief offered it as "two call sites"; it is
  a package boundary. `notifyBackchannel` is a method on `internal/oidc`'s
  unexported `handler` and needs `token.Issuer`, the realm's `keys.RealmKeys`,
  `h.realmIssuer` and `h.httpClient`. `internal/admin` cannot reach it without
  either exporting a seam in `internal/oidc` or extracting the notifier into a
  package both can see, and `internal/oidc`, `internal/token` and
  `internal/httpx` were all on this branch's do-not-touch list. The decision is
  which package owns "tell the other clients", which is a `Boundaries` table
  change and deserves to be read on its own rather than inside an
  authorization-services diff. Its urgency is unchanged.
- **F126 - `permission/providers` is not filtered. Unchanged and re-confirmed
  in passing.** Nothing this cut touched goes near it; the two catalogues are
  still one handler registered twice.
- **F127 - `javamap.KeyOrder` is wrong where `SizedKeyOrder` is right, on a
  served body. Unchanged.** The scope family has no Java map in it - the
  representation is four flat fields - so nothing here bears on it. Worth
  saying because it is the obvious guess: a scope has no `attributes`, and the
  strict decoder proves it, refusing the key by name.
- **F128 - `CONSENSUS` is a documented `decisionStrategy` and a 500.
  Unchanged, and not disturbed.** No mutation in this cut's pass touched it and
  no new code path reaches it.
- **F95 - a client's `attributes` is serialised from a Go map. Not closed, and
  not touched, for the first cut's reason plus one of this cut's.** The
  `model.StringMap` move changes what five `admin/clients/*` goldens assert, and
  "`make record` moved no existing golden" is again this branch's evidence that
  the new representations displaced nothing. It stays a one-file change on a
  branch of its own.
- **New: an empty-bodied response writer lives in `internal/admin`.**
  `writeEmptyStatus` suppresses `Date` and applies the `X-Frame-Options` rule,
  which is `internal/httpx`'s job, and it is where it is because that package
  was not this branch's to change. It writes no body, so the divergence
  `internal/httpx`'s boundary rule exists to prevent - a second marshaller
  drifting on the bytes - is not reachable through it. Moving it is a rename
  plus one call site per user.
- **New: nine `w.WriteHeader(http.StatusCreated)` call sites in `internal/admin`
  send a `Date` header.** `clients.go`, `clientscopes.go`, `groups.go`,
  `organizations.go`, `protocolmappers.go`, `realms.go`, `roles.go` twice and
  `users.go` all write a 201 with an empty body directly, and none of them
  suppresses `Date`. Keycloak sends none on any response. This is F54's exact
  shape - a writer outside `internal/httpx` that nothing in the suite can see,
  because `httptest.ResponseRecorder` adds no `Date` either - and it is
  pre-existing, found by reading the writers rather than by running anything.
  Not fixed here: the fix belongs in `internal/httpx` as a `WriteCreated`.
- **New: `pageRoles` and three sibling listings treat an unparseable `first` or
  `max` as no bound, and Keycloak answers 404.** Measured on all four plus this
  cut's own listing. `pageRoles`'s comment claimed the case had never been
  probed and is corrected on this branch; the behaviour of the four is not, for
  the reason §1.5 gives. `authzIntBound` is the one function that reproduces it
  and wiring it into them is a call-site change plus four conformance cases.
- **New: a cross-resource-server scope id collision corrupts the other resource
  server on 26.7.1**, and Gloak deliberately does not reproduce it. §1.7 has the
  reproduction. Filed as a divergence rather than a gap, so that a later reader
  does not "fix" Gloak into corrupting itself.
- **New: `POST .../scope`'s echo of a non-empty `policies` is one Java default
  short.** Keycloak fills `logic: POSITIVE`, `decisionStrategy: UNANIMOUS` and
  `config: {}` into each entry on the way out; Gloak echoes the caller's bytes.
  For `resources` the verbatim echo is exact, measured. `[]` - the only value a
  resource server Gloak can build will hold, since there is no route that
  creates a policy - is exact for both. It becomes reachable when the policy
  family lands and belongs to that cut.

## 3a. The mutation pass, and the one survivor

Thirty-seven mutations, one per claim, each run against the **named** test and
reverted. The working tree was committed before the first one and verified clean
after the last.

**Three were discarded rather than counted**, and two of them looked like
survivors first:

- "a scope name is unique realm-wide" added `OR 1=1` to the *ordinal* subquery,
  which is not where uniqueness lives - and is inert besides, since a globally
  increasing ordinal keeps the same relative order inside one resource server.
  Redone against the `UNIQUE (resource_server_id, name)` constraint: killed.
- "the flag going off leaves the scopes behind" added a dead assignment. The
  cascade is in the schema. Redone by removing `ON DELETE CASCADE`: killed, by
  the handler test and by the store suite independently.
- "an empty body is a 400" left an unused variable and did not compile. Redone
  as a disabled condition: killed.

A mutation that does not change behaviour reports whatever the suite already
said. Both false survivors would have gone into this report as findings about
the tests if the mutation had not been read back.

**One genuine survivor: `writeEmptyStatus` no longer suppressing `Date`.**
Deleting `w.Header()["Date"] = nil` passed **every test in `internal/admin`**
and **every conformance case in the authz chapter**. It is F54's blind spot on a
fourth writer: `httptest.ResponseRecorder` never adds a `Date` header, so it
cannot tell a suppressed one from one `net/http` would have added, and the
conformance harness serves through a recorder. `internal/httpx` has three tests
for this, one per writer, each using a real `httptest.NewServer`;
`writeEmptyStatus` is the fourth writer and had none.

**Fixed on the branch.** `TestWriteEmptyStatusOmitsDateHeader` serves through a
real server and the mutation dies. The nine pre-existing 201 writers in
`internal/admin` have the same hole and are §3's new follow-up - found by the
same reading, not by any test.

The thirty-three killed, in full: `ListScopes` ordered by name; the listing's
sort folding case; the create's 409 dropping the five headers; the update's 409
keeping them; an unparseable bound meaning no bound; the settings export keeping
the id; the upsert falling back to the name when the id misses; a duplicate name
echoing without writing; the search folding case; the listing's `name` matching
exactly; empty bodies always keeping `X-Frame-Options`; the read's 404 losing
its `Cache-Control`; the `PUT` merging; the `PUT` writing the body's id; an
empty body answering 400; the `PUT` looking the scope up before decoding; the
create echoing nothing; the scope writes taking the read role set; the
sub-listings not resolving their scope; `ScopeByID` and `ScopeByName` ignoring
the resource server; either bound alone stopping paging; `CreateScope` always
writing ordinal 0; `DeleteScope` being idempotent; the search's 400 answering a
body; `UpdateScope` moving the ordinal; the create's 201 losing its
`Cache-Control`; the create answering the plain representation; the name's
uniqueness going realm-wide; the cascade going away, twice; and five of those
re-run against the **goldens** rather than the unit tests - the two orders, the
byte-wise sort, the 409 header pair, `X-Frame-Options` on the empty 404, and the
404 gaining a body - all five killed there too, so the goldens are load-bearing
for the claims they were recorded for and not only decoration beside a unit
test.

## 4. Parity, before and after

| chapter | before | after |
|---|---|---|
| `admin/authz-resource-server` | 5 of 31 | **13 of 31** |
| **total** | **311 of 526** | **319 of 526** |

No other chapter moved. `make record` created nineteen goldens and moved none of
the 526 that were already there - counted with `git ls-tree`, 526 before and 545
after, which is what says the new representations displaced nothing.
`settingsRepresentation`'s `scopes` is the one that could have: it went from a
hard-coded empty array to a store read, and `admin/authz-resource-server/
settings` - the first cut's case, on an empty resource server - is byte for byte
what it was.

The eighteen operations left in the chapter are the resource family's nine, the
policy and permission families' four each, and `import`. The resource family is
the next natural cut and the plan's §1 says why it was not this one: its
representation is keyed `_id`, it carries an `attributes` Java map - so
`internal/javamap` and F95 are both in play - and its listing takes eight query
parameters where the scope listing takes four.
