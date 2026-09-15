# What an authorization-services create does when you send it twice

F237, F238 and F239 as one cut. Three follow-ups, one subject: the resource
server has more create routes than the three they name, and what a repeat does
on each of them had been measured on three.

The short version, and each half is a correction to the entry that asked for it:

- **There are eight authz create routes, not three.** `POST .../policy/{type}`
  and `POST .../permission/{type}` are real routes with their own response
  shape, and Gloak serves neither.
- **Two of the eight overwrite on a repeat and six refuse.** F237's reading was
  right about which two, and its framing - "a repeat" - is one input out of four
  that matter. The key is the **body's id**, and the four cells do not agree.
- **Gloak had already implemented both upserts**, contrary to F237's "Gloak's
  behaviour on that input is unknown". Every status matched on the first run.
  One field did not, and it was worth the cut on its own.
- **F238's explanation is wrong in its load-bearing half.** The realm boundary
  has nothing to do with it; a container restart clears the whole thing; the row
  is never lost. What decides it is whether the row was **read before** the
  collision, which no probe had varied.
- **F239 is closed with a column, a second declaration and four tests** rather
  than a comment, and the constant is not widened.
- **The mutation pass found the gap rather than confirming the work.** One
  survivor, and it was the shape this project has a name for: three cases that
  an implementation with the rule backwards satisfies entirely. Closed with a
  fourth case before reporting.

## 1. Every authz create route, and what a repeat does

### 1.1 The routes

Measured on a clean resource server, one create each, fresh ids:

```
POST .../authz/resource-server/resource              201
POST .../authz/resource-server/scope                 201
POST .../authz/resource-server/policy                201
POST .../authz/resource-server/permission            201
POST .../authz/resource-server/policy/role           201
POST .../authz/resource-server/policy/time           201
POST .../authz/resource-server/permission/resource   201
POST .../authz/resource-server/permission/scope      201
POST .../authz/resource-server/import                204
POST .../authz/resource-server/policy/js             404 HTTP 404 Not Found
```

**The typed creates are not the untyped one with a path parameter.** Their 201
carries **no `config` key** where `POST .../policy`'s does, on bodies that are
otherwise identical - so they are a ninth and tenth response shape on this
surface, not two more spellings. `js` is absent because the provider is not
registered, which is `policy/providers`' catalogue question and not this cut's.

Gloak serves `resource`, `scope`, `policy`, `permission` and `import`. The four
typed routes are unserved and unrecorded; see F240.

### 1.2 The repeat matrix

Four inputs, because "a repeat" is ambiguous and the ambiguity is where the
behaviour lives. One **fresh resource server per cell**, and a fresh pair of ids
per cell - see §1.3 for why that is not fussiness.

| route | same id, new name | new id, same name | no id, same name | identical |
|---|---|---|---|---|
| `resource` | **201, renamed** | 409 `Resource with name [one] already exists.` | 409 same | 409 same |
| `scope` | **201, renamed** | 409 `Duplicate resource error` | **201, no-op** | **201, no-op** |
| `policy` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `permission` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `policy/role` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `policy/time` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `permission/resource` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `permission/scope` | 409 `Duplicate resource error` | 409 `Policy with name [one] already exists` | 409 same | 409 same |
| `import` | 204, and nothing moves | - | - | 204, ids unchanged |

Four things in that table are worth saying in words.

**The two upserts key on different things and the table is the proof.** The
resource upserts on `_id` and the scope on `id`-or-`name`: a scope create with
no id and a taken name is a **201 returning the row that was already there**,
where the resource answers 409. That is AGENTS.md's existing sentence - "the
scope create upserts on the name, the resource create on the `_id`" - measured
on the cell that separates them rather than inferred.

**`Policy with name [one] already exists` is a fifth error shape on this API**,
and it is the four-key shape **inverted**: prose in `error`, a category in
`error_description`. AGENTS.md's error-shapes bullet lists four and this is not
one of them. Its neighbour on the same route, `Duplicate resource error`, is the
ordinary way round - so one route answers two 409s whose two keys mean opposite
things depending on which check refused.

**The six refusing routes are one store.** `policy`, `permission` and the four
typed routes all write the policy table, so an id taken by any of them is taken
for all six. That is not a guess: it is what made the first run of this matrix
unreadable, and it is measurable directly - a `policy` create at id X makes a
`permission` create at id X a 409 on a different resource server.

**`import` is genuinely idempotent.** Two identical imports, 204 twice, and the
resource, scope and policy all came back with the **same minted ids**. It is the
only create-shaped route here that is safe to repeat in the sense
`idempotentCreate`'s name claims.

### 1.3 Two probe defects, recorded because both produced confident wrong tables

Neither is about Keycloak, and both would have been written up as findings.

**The ids are global, so a shared id constant contaminates later cells.** The
first matrix reused two id constants across all cells. `policy` took id X on
cell 3 and every policy-family cell after it answered 409 on a *fresh* resource
server - which reads exactly like "the policy family refuses everything". It is
not; it is the probe. Every cell gets its own ids now.

**And they are global across realms.** The resource cell of the second matrix
answered 409 on a brand-new realm because probe 1, in a different realm, had
used that id twenty minutes earlier. A cross-realm authz id collision is a 409,
measured directly in §3.1.

**`fresh()` assigned its ids inside a command substitution.** `P="$(fresh)"`
runs the function in a subshell, so the globals it set never came back and every
body went out with `"_id":""`. The run looked plausible - 201s and 409s in a
pattern - and was entirely an artifact. What it did establish, by accident:
**Keycloak accepts an empty-string id, stores it, and it then collides globally
like any other.** Not chased; F242.

The lesson that generalises: this matrix's cells are only independent if the
**ids** are fresh as well as the resource server, and three separate runs were
wasted before that was true. A probe over a global id space needs a counter, not
a constant.

## 2. What Gloak does on the same inputs

The whole matrix was run against a live Gloak on port 18092 and diffed against
the Keycloak transcript. **Every status matched on the first run**, on all four
input shapes and all four served routes, including both prose 409 bodies.

F237 says this is a divergence "nobody has asked Gloak about". Asked: Gloak's
`createAuthzScope` and `createAuthzResource` both implement the upsert, and both
carry the measurement in their doc comments - `createAuthzScope`'s spells out
five bodies and their answers. The gap was never the implementation. **It was
that no golden recorded the destructive branch**, so the behaviour was served,
documented and unpinned.

Per route, on a repeat:

| route | Keycloak | Gloak |
|---|---|---|
| `resource` | 201, renamed, `attributes` kept | same - **`attributes` were cleared until this cut** |
| `scope` | 201, renamed, `iconUri`/`displayName` dropped | same |
| `policy` | 409 `Duplicate resource error` | same |
| `permission` | 409 `Duplicate resource error` | same |
| `policy/role` | 409 | **404** - route not served |
| `policy/time` | 409 | **404** - route not served |
| `permission/resource` | 409 | **404** - route not served |
| `permission/scope` | 409 | **404** - route not served |
| `import` | 204, ids unchanged | same |

Both prose 409 bodies match, including
`{"error":"Policy with name [one] already exists","error_description":"Conflicting policy"}`
with its inverted keys.

**The four unserved rows are a 404 of the wrong kind**, which is worth more than
"not served": Gloak answers
`{"error":"Unable to find matching target resource method"}`, the **unmatched
path** body, because its mux has no such route. Keycloak's own 404 on the one
type it does not register - `policy/js` - is `{"error":"HTTP 404 Not Found"}`,
the body AGENTS.md attributes to a route that was found and could not run. So
the two servers answer the same status with different bodies on a request a
client can send today. F240.

### 2.1 The one divergence, and it is one field

```
POST .../resource {"_id":R,"name":"one","type":"t","uris":["/u"],
                   "displayName":"D","attributes":{"k":["v1"]},
                   "ownerManagedAccess":true}                        201
POST .../resource {"_id":R,"name":"two"}                             201

Keycloak: {"name":"two", ... ,"attributes":{"k":["v1"]},"uris":[]}
Gloak:    {"name":"two", ... ,"attributes":{},          "uris":[]}
```

The repeat replaces every field the second body does not name - `type`,
`displayName`, `icon_uri`, `uris`, `scopes` gone, `ownerManagedAccess` back to
`false` - **except `attributes`, which survives**. Gloak cleared them.

And the discriminator is absence, not the field: `{"attributes":{}}` clears them
on both servers, `{"attributes":{"k2":["v2"]}}` replaces them on both. Measured
across six cells, three per verb.

**The rule was already implemented one function away.** `updateAuthzResource`
has it, with a comment saying so in as many words - "`attributes` is the one
field where absent means unchanged" - and the PUT rows of the six-cell probe are
byte-identical between the two servers. The create built a fresh row and wrote
it wholesale.

This is the shape AGENTS.md keeps meeting from a new angle: a rule discovered on
one verb and implemented on that verb. The two functions are ninety lines apart
in one file and only one of them knew.

### 2.2 The decision, and what was rejected

**Decided: fix it. Gloak now keeps `attributes` on the create's upsert.**

This is not the "faithful and unpleasant versus divergent and clean" choice the
brief anticipated, and saying why matters, because that choice was available and
is the one I would have had to argue:

- *Reproduce the destructive 201 faithfully* - already done, and not in
  question. Gloak answers 201 and overwrites, exactly as Keycloak does. Nothing
  here proposes refusing where Keycloak overwrites.
- *Rejected: leave `attributes` cleared and file it as a divergence.* It has
  nothing to recommend it. It is not a simplification - the fix is four lines and
  removes an inconsistency rather than adding one - and it is not a case of
  Keycloak doing something indefensible that Gloak should decline. It is Gloak
  being wrong about a rule this repository had already measured, written down and
  implemented on the neighbouring verb.

There is a **second** divergence on these routes and it is deliberate and
pre-existing: Gloak's authz id spaces are **per resource server**, where
Keycloak's are global. AGENTS.md already records it as "the first measured
behaviour this project has declined to reproduce". This cut leaves it alone and
did not re-open it, but §3 is the evidence that the decision was right for a
reason nobody had yet written down: the global id space is not only a collision,
it is a **corruption**, and declining it declines that too.

### 2.3 What was checked and did not diverge

Worth recording, because each was a plausible second bug:

- **The upsert keeps the row's place in the settings export.** Three resources
  `aaa, bbb, ccc`, rename the middle one to `zzz`: the export stays
  `aaa, zzz, ccc` on both servers and the listing sorts on both. Gloak's create
  does not carry `Ordinal` the way its PUT does, and it still agreed - so the
  store preserves it. Identical output, both families.
- **`PUT` on the same row does the same damage**, on both servers, with a 204.
  F237 asked. The answer is that the PUT is a replace by definition and the
  surprise is entirely the POST's.
- **The 201 body's provenance differs per family and both are already right.**
  The resource create's 201 is a read of what it wrote; the scope create's is
  the request echoed. That is why the resource needed one golden here and the
  scope needed two.

## 3. F238: what is poisoned, and what nothing in the corpus can reach

### 3.1 The reproduction, and the variable is not the one in the entry

F238 says the poison survives a fresh realm "because what is poisoned is a
resource-server cache entry that outlived the realm boundary". A clean 2x2 -
`{same realm, other realm}` x `{read the row before the collision, do not}` -
says the realm is not a variable at all:

```
kind      far realm  read before   near listing after the far 409
--------  ---------  -----------   ------------------------------
scope     same       yes           clean
scope     same       no            400 unknown_error / Cannot parse the JSON
scope     other      yes           clean
scope     other      no            400 unknown_error / Cannot parse the JSON
resource  same       yes           clean
resource  same       no            200 []           <- the row is invisible
resource  other      yes           clean
resource  other      no            200 []
policy    either     either        clean, every cell
```

**Reading the row before the collision prevents it entirely, and that is the
whole discriminator.** F238's own probes had not varied it: the one that "did
not provoke it" read the scopes on the way through and the ones that did, did
not. Two probes, one uncontrolled variable, and the realm got the blame because
it was the thing that happened to differ.

`policy` never poisons anything, in any cell. The family that refuses its own
repeat is also the family a far collision cannot hurt.

### 3.2 What is actually poisoned, and the row is fine

On the poisoned scope server:

```
GET .../scope                200 -> 400 unknown_error / Cannot parse the JSON
GET .../scope/{id}           404, empty body
GET .../scope/search?name=   204, empty body
GET .../settings             500 unknown_error / consult the server log
GET .../authz/resource-server  200, fine
```

On the poisoned resource server:

```
GET .../resource             200 []          <- the row is gone from the listing
GET .../resource/{id}        404 HTTP 404 Not Found
GET .../resource/search      200 and THE ROW IS THERE
GET .../settings             200, "resources":[]
```

**`/resource/search` returns the row that `/resource` and `/resource/{id}` both
deny.** One row, three reads, two answers. That is the finding that settles what
this is: the row was never deleted.

**A container restart clears all of it.** Every read above went back to 200 with
the correct row after `docker restart`, with no other action. So it is an
in-process cache, nothing is persisted, and "a fresh realm does not clear it" is
true only in the trivial sense that a fresh realm is not the poisoned one.

This makes F238 **milder than filed and stranger than filed**. Milder: no data
loss, cleared by any restart, confined to the one resource server that holds the
winner. Stranger: a request that was *refused* damages a server it did not
address, and the damage is invisible to the caller who caused it.

### 3.3 Can anything in the corpus reach it

**No, and it is now a test rather than an argument.**

Reaching it needs one id minted on **two different resource servers**. Every
authz create path in the tree is
`.../clients/{{client_uuid}}/authz/resource-server/...`, and `containerOf`
treats a `{{capture}}` in a path as fixture-local, so two fixtures are always two
containers and any shared authz id is already reported by
`TestNoTwoFixturesMintOneObjectID`. Every authz fixture builds exactly one
client, so no single fixture can do it either.

That was true before this cut and it was an argument. It is now
`TestNoAuthzIDReachesTwoResourceServers`, and it is deliberately **not** the
existing sweep: that one keys on the object and skips any step declaring
`ExpectStatus` or `Overwrites`, and both exemptions are correct there because a
declared loss and a declared overwrite are each harmless *on one server*.
Neither is harmless across two. So the new test walks every step including the
exempted ones, keys on the fixture alone, and carries a floor of 131 mints.

It also documents the assumption it rests on: "two fixtures" and "two resource
servers" are the same statement **only while every authz fixture builds one
client**. The day one builds two, that test is the thing to reconsider rather
than to satisfy.

So: the trap exists, it is Keycloak's, nothing in the corpus can spring it, and
the guard that keeps it that way now fails loudly instead of holding by
coincidence. That is the third time this shape has been the result.

## 4. F239: the constant's claim, made checkable

**`idempotentCreate` is not widened.** It is still `{201, 409}`. AGENTS.md's
warning about widening stands and nothing here goes near it.

What was wrong is that its name is a promise and the two spaces where the
promise is false were recorded only in prose - in `Collision`, a field nothing
compares to anything. Four things now:

1. **`idSpace.RepeatIsHarmless`**, a measured column per space. False in exactly
   two: `authz resource` and `authz scope`.
2. **`TestIdempotentCreateNamesTheSpacesItLiesAbout`** pins that the false ones
   are exactly those two, by name rather than by count - a count passes when one
   flips false and another flips true. It opens by asserting that
   `idempotentCreate` still accepts a 201, because that is the entire mechanism
   by which a destructive repeat is silent; if it ever stops, the test is
   measuring nothing and says so with a `Fatalf` rather than passing.
3. **`Step.Overwrites`**, and this is the part that turned out to matter.
4. **`onAnOverwritingRoute` and its positive control**, because the floor over
   the steps that declare the flag is satisfied by a predicate that permits
   everything - proved by M5, which exactly one test in the tree can see.

### 4.1 `Overwrites` exists because the sweep caught my own fixture

The scope needs a fixture that creates a row and then repeats the create, so a
case can read the wreckage. The id-space sweep reported it immediately: one id,
two objects, in one fixture. Correct - that is exactly the accident it is for.

The existing escape hatch is `ExpectStatus` declaring a loss, and it is **the
wrong declaration here and the new test forbids it**: a repeat on these two
routes does not lose, it wins, so the step would fail on its own status. And
worse, `mintsIn` skips any step that `expectsFailure`, so the declaration would
have hidden a real mint while being false.

So the two declarations are now a pair, and each is illegal in the other's
spaces:

| a fixture that means to | declares | legal where |
|---|---|---|
| lose a collision | `ExpectStatus` excluding 2xx | a repeat is refused |
| overwrite a row | `Overwrites: true` | a repeat wins |

`TestNoStepDeclaresALossWhereARepeatWins` and
`TestOverwritesIsOnlyDeclaredWhereARepeatWins` are the two halves, each with its
own floor. The second matters more than it looks: `Overwrites` **exempts a step
from the collision sweep**, so a stray one is a hole rather than a mistake, and
it is one copy-paste away - the two declared losses in this tree are both
creates and both look exactly like an authz create.

This is the F234 lesson applied without being told: a field the sweep reads is a
declaration, a sentence beside it is not, and a column nothing compares is a
comment with a colon in it.

## 5. What was added, and the record diff read file by file

### 5.1 Three cases and three goldens

`admin/authz-resource-server/resource-create-repeat` - POST a taken `_id` with
only a new name. 201.

```json
{"name":"gloak-probe-repeated","owner":{...},"ownerManagedAccess":false,
 "attributes":{"k1":["a"],"k2":["b1","b2"]},
 "_id":"5e50a5ce-0000-4000-8000-00000000e301","uris":[]}
```

One case covers both halves here because this create's 201 **is** a read: the
rename, the five cleared fields, and the surviving `attributes` are all in it.
**This is the golden that would have failed before the fix** - it would have
recorded `"attributes":{}`.

`admin/authz-resource-server/scope-create-repeat` - the same request on the
scope. 201, and the body is the request echoed:
`{"id":"...e401","name":"gloak-probe-repeated"}`. It says nothing about the
`iconUri` and `displayName` it has just destroyed, which is why there is a third
case. A handler answering this route with a read of its own write passes the
resource case and fails this one.

`admin/authz-resource-server/scope-create-repeat-read` - GET the scope the
fixture has already overwritten. 200,
`{"id":"...e501","name":"gloak-probe-repeated"}`: **`iconUri` and `displayName`
are gone.** It is `scope-put-replaced`'s shape with the other verb, and the two
side by side are the point - a POST and a PUT leave the same wreckage and only
one of them is called a replace.

All three carry `Cache-Control: no-cache`, the charset, all five security
headers, and the two creates assert `Location` absent.

### 5.2 The fourth case, added because a mutation survived

`admin/authz-resource-server/resource-create-repeat-attributes` - the same
repeat, but naming attributes. 201, and they **replace**:

```json
{"name":"gloak-probe-repeated", ... ,"attributes":{"k3":["c"]},
 "_id":"5e50a5ce-0000-4000-8000-00000000e601","uris":[]}
```

The fixture's resource was seeded with `{"k1":["a"],"k2":["b1","b2"]}` and none
of it survives. Put beside the case above, the pair says the rule exactly:
absent means unchanged, named means replaced. Either case alone is satisfied by
a handler that gets the rule wrong in one direction. See §9.1.

### 5.3 The rest of the diff: there is none, twice

Two full `make record` runs, one per batch of cases. Each left the working tree
holding **only the new files and zero modified ones**:

```
run 1:  ?? .../authz-resource-server/resource-create-repeat.http
        ?? .../authz-resource-server/scope-create-repeat.http
        ?? .../authz-resource-server/scope-create-repeat-read.http
run 2:  ?? .../authz-resource-server/resource-create-repeat-attributes.http
```

Read file by file, which for four files is quick, and each is quoted in full
above. **Nothing existing moved, either time**, which is the outcome worth
stating rather than passing over: the `attributes` fix changes a response Gloak
serves, and the only golden that could have noticed is one recording that
response - which did not exist until this cut created it. So the fix is
invisible to the 1089 goldens that were already here, and the four new ones are
the entire evidence that it happened. There was no churn to read.

Two independent record runs leaving 1089 goldens byte-identical is also the
strongest statement available that this cut moved nothing it did not mean to.

## 6. Containers

- **One long-lived reference container** (`gloak-ref`, `quay.io/keycloak/keycloak:26.7.1`,
  port 18091) for all eleven probe scripts. **Started once, restarted once** -
  the restart is itself a measurement (§3.2), not a recovery, and every reading
  before it is from the first start.
- **One Gloak process** on port 18092 over a file-backed SQLite, restarted once
  after the fix and re-diffed.
- **Each record run is 41 container starts**: one shared, plus one fresh per
  `PristineRealm` case, of which there are 40. That is the harness's own
  arithmetic, not a count of what I watched. **Two runs, so 82 starts**, and the
  second was needed because the mutation pass added a case.

**Two starts of one container, not two containers.** The §3.2 restart finding
rests on the *same* database coming back clean, which is what makes it evidence
about a cache; a second container would have proved nothing there. The
independent-container confirmation of the repeat matrix is §7.

## 7. A second container, because two starts of one is not two containers

`gloak-ref2`, a separate `docker run` of the same image on port 18093, never
touched by any earlier probe.

**The repeat matrix reproduces in every cell**, including the one cell container
1 could not answer cleanly: cell A/resource had been contaminated there by an id
probe 1 used twenty minutes earlier in another realm, and had to be re-measured
on a new id. On container 2 it came back `first=201 repeat=201` first time. That
is the F237 cell, and it is now measured on two independently started
containers.

**The F238 2x2 reproduces byte for byte**: `readbefore=yes` clean in both
realms, `readbefore=no` giving `400 Cannot parse the JSON` for the scope and a
`[]` listing with a 404 by-id for the resource, in both realms, and `policy`
clean in every cell. The discriminator is not an artifact of one container's
history.

The distinction the brief asks for, stated plainly: **two containers, and one of
them started twice.** The restart in §3.2 is a *measurement* on container 1 -
the whole point is that the same database came back clean, which a second
container could not have shown. The independence claims in §1 and §3.1 rest on
container 2, which shares nothing with it.

Nothing here reaches outside the container. The question is worth asking after
F230, and the answer is that every route in this cut is an Admin API write and
read against local storage; the one thing that looked like an external effect -
a create damaging a server it did not address - is an in-process cache, proved
by the restart.

## 8. Parity

```
admin/authz-resource-server               29         2          31  openapi 26.7.1
total: 598 of 644 enumerated behaviours served; 2 chapters not enumerated
```

**Unchanged, and deliberately so. The total did not fall.**

The chapter is 29 `Implemented` plus 2 `Recorded`, which is all 31 accounted
for, and the three new cases add no operation: they are new *behaviours* on
`POST .../resource`, `POST .../scope` and `GET .../scope/{id}`, all three of
which were already served and already counted. The meter counts operations, so
three goldens that pin a branch of an operation move it by zero.

That is the right answer rather than a disappointing one, and it is worth being
explicit because "29 of 31" is what the brief cited as the reason this surface
looked finished. It was finished by the meter's definition and had the
destructive branch of its only two upserts unrecorded. **A chapter at 100% of
its operations can still have a served, undocumented, unmeasured behaviour in
it** - and in this case it had three, plus the four routes in F240 that the
meter cannot see at all.

## 9. The mutation pass

Seven mutations, each applied alone, reverted from a `trap ... EXIT`, with the
dirty check scoped to the package being mutated and **each package run
separately, no `-run` filter**. The failure message was read every time, not the
verdict line.

| # | mutation | kind | result |
|---|---|---|---|
| M1 | a repeat clears `attributes` - the code as it shipped | coherent | killed by `resource-create-repeat`; **survived `internal/admin`** |
| M2 | an upsert always keeps `attributes`, body ignored | coherent | **SURVIVED both packages**; closed, now killed by `resource-create-repeat-attributes` |
| M3 | `authz policy` declared as overwriting | coherent table | killed by `TestIdempotentCreateNamesTheSpacesItLiesAbout` + 2 |
| M4 | `authz scope` declared harmless | coherent table | killed by the same + 2 |
| M5 | `onAnOverwritingRoute` permits every route | coherent predicate | killed by **one** test, the positive control |
| M6 | `mintsIn` stops honouring `Overwrites` | mechanism | killed by `TestNoTwoFixturesMintOneObjectID/authz-scope` |
| M7 | `Overwrites` declared on the policy create | **additive** | killed by `TestOverwritesIsOnlyDeclaredWhereARepeatWins` |

### 9.1 M2, the survivor that was closed before reporting

**The one real survivor.** Swapping the two branches of the create's switch so
that an existing row's attributes always win - and the body's are silently
ignored on every upsert - passed `internal/admin` **and**
`internal/conformance`.

It is a coherent wrong implementation, not a broken function: "attributes are
immutable once set" is a rule somebody could hold. And the reason nothing saw it
is exactly this project's named failure shape: **"absent means unchanged" and
"the body cannot change them" agree on every request the corpus contained**,
because no case sent `attributes` on a repeat. Three cases pinned that the old
attributes survive; all three are satisfied by a handler that can never change
them.

The mutated code was read before this was believed, per the rule - the two
branches really had swapped, and the diff display was misleading because both
branches contain similar text.

Closed with `admin/authz-resource-server/resource-create-repeat-attributes`: a
repeat that *does* name attributes, which must replace. Measured first, then
recorded. M2 now dies there.

### 9.2 M1's first form was a build failure, and the verdict line said "not ok"

Written as a pure deletion of the preserve branch, it left `current` declared and
unused. `go test` reported `FAIL ... [build failed]`, and a harness that reads
"did the output start with `ok`" calls that a kill. It is not one: it proves
nothing about any assertion.

This is the rule that says read the failure message and not the test name,
arriving from the direction the rule does not mention - not a vacuity floor
firing early, but the compiler refusing before any test ran. Re-formed as
`stored.Attributes = nil`, which compiles, keeps `current` used, and is exactly
the behaviour that shipped.

### 9.3 M1 survives `internal/admin`, and that is a finding rather than a nuisance

Every production mutation in this cut was killed **only** by
`internal/conformance`. `internal/admin` has no unit test that exercises the
create's upsert at all, so the entire attributes rule - on the verb where it was
missing - rests on one golden.

Not fixed here, and the reason is F236's: `internal/admin`'s tests are for the
things a golden cannot reach, and this one can. But it is worth knowing that the
package owning the handler cannot tell the shipped bug from the fix.

### 9.4 M5 is why the positive control was added

M5 makes `onAnOverwritingRoute` return true for everything. Every floor in the
file is still satisfied - the steps that declare `Overwrites` are still counted,
the nine spaces are still swept, every id is still pooled - and **exactly one
test in the whole tree fails**, checked by listing every failure rather than the
first six.

That is AGENTS.md's "a vacuity guard covers the traversal; the comparison needs
its own" reproduced on a new guard, and it is the reason the predicate was pulled
out of the test body and given seven known inputs. Without the control this cut
would have shipped a legality check that permits everything, with every test
green - which is precisely what F234 shipped and had to come back for.

### 9.5 M7 was made additive on purpose

`Overwrites` declared on the policy create, **added** as an extra step rather
than moved from an existing one. No id leaves any space, so no floor can fire and
the collision message is the only thing that can kill it. It was, and by the
right test.

## 10. What belongs in AGENTS.md

Phrased as I would want it folded, for whoever does the fold.

**Into the authorization-services run of bullets**, replacing nothing:

- **There are eight authz create routes and two of them overwrite.**
  `POST .../policy/{type}` and `POST .../permission/{type}` are real routes with
  their own 201 shape - **no `config` key**, where the untyped creates have one -
  and Gloak serves neither. The overwriting pair is `resource` and `scope`; the
  other six are one store behind four paths, so an id taken by `policy` is taken
  for `permission` and both typed families too.
- **"A repeat" is four different requests and the answers do not agree.** The
  key is the body's id. A scope create with **no** id and a taken name is a
  **201 returning the row that already existed**; the same body on `resource` is
  a 409. Same question, one path segment apart, opposite answers - which is the
  existing "the scope upserts on the name, the resource on the `_id`" bullet
  measured on the cell that separates the two rather than inferred from the
  cells that do not.
- **The overwriting repeat replaces every field except `attributes`.** Absence
  means unchanged for that one field and `{"attributes":{}}` still clears it, so
  it is about absence and not about the field - **on the POST as well as the
  PUT**. Gloak had it on the PUT alone until 2026-09-14, in a file where the two
  functions are ninety lines apart.
- **A fifth error shape, and it is the four-key shape inverted.**
  `{"error":"Policy with name [x] already exists","error_description":"Conflicting
  policy"}` - prose in `error`, a category in `error_description`. Its neighbour
  on the same route is the ordinary way round, so **one route answers two 409s
  whose keys mean opposite things** depending on which check refused. The
  error-shapes bullet says four; this is a fifth.

**Into "things that look like bugs and are not"**, and it is the sharpest
instance of the existing "two recordings agreeing is never evidence" rule
arriving from a new direction:

- **A refused authz create damages the resource server it did not address, and
  what decides it is whether the row was read first.** A colliding create on
  another resource server answers 409 and leaves the *winner's* server unable to
  serve it: the scope listing answers `400 Cannot parse the JSON` and its
  settings a 500, and the resource side goes quieter - the row vanishes from the
  listing and from its own id read while **`/resource/search` still returns
  it**. One row, three reads, two answers. **A container restart clears all of
  it and the row was never lost**, so it is an in-process cache. The realm
  boundary is not the variable and was blamed for a fortnight because two probes
  differed in the realm *and* in whether they read the row on the way through.
  Gloak's per-resource-server id spaces mean it cannot reproduce any of this,
  which is the existing declined divergence earning its keep.

**Into the mutation-discipline paragraphs**, two lines:

- **A mutation that does not compile is not a kill, and the verdict line cannot
  tell you.** A deletion that left a variable declared and unused produced
  `FAIL ... [build failed]`, which a harness testing "did the output start with
  `ok`" records as killed. It proves nothing about any assertion. The existing
  rule says to read the failure message rather than the test name; this is the
  case where there is no test name at all, because nothing ran. Re-form the
  mutation so it compiles - usually by changing what a branch assigns rather
  than removing the branch.
- **A production mutation has to be run against the package that can kill it,
  which is usually not the package it lives in.** Every production mutation in
  this cut survived `internal/admin` and died in `internal/conformance`, because
  the contract lives in goldens and not in the handler's own tests. "Run each
  package separately" already says how to run them; it does not say that a
  mutation in `internal/admin` scored against `internal/admin` alone reports a
  survivor every time.

## 11. Follow-ups

### F240: four authz create routes are served by Keycloak and are in no document

`POST .../authz/resource-server/policy/{type}` and `.../permission/{type}` are
real routes - `policy/role`, `policy/time`, `permission/resource` and
`permission/scope` all answer 201 on a default 26.7.1 - and they are **not in
`keycloak-26.7.1.json` at all.** The description's twenty-two authz paths are
listed in this repository's own vendored copy and none of them takes a type
segment.

So the parity cost is **zero**, and that is the interesting part rather than a
let-off. The meter measures the description, the description does not know these
routes exist, and the chapter therefore reads 31 of 31 accounted for while four
served creates sit outside the count. Every other gap this project has found was
a described operation with no case; this is the first case of the opposite, and
the meter is structurally unable to report it.

They are not the untyped creates with a path parameter, which is what makes them
worth serving rather than aliasing: their 201 carries **no `config` key** where
the untyped ones do, on otherwise identical bodies.

**And Gloak's 404 on them is the wrong one of the two.** Measured side by side:
Gloak answers `{"error":"Unable to find matching target resource method"}` -
the unmatched-path body, because its mux has no such route - while Keycloak's
own 404 on the one type it does not register, `policy/js`, is
`{"error":"HTTP 404 Not Found"}`. So even declining to serve these routes is
observably wrong today, and it is wrong in the direction AGENTS.md's
four-producers bullet is about. That is the cheapest half of this entry and it
does not require building the family: four routes registered to the existing
`createAuthzPolicy` would answer the right 404 for the unregistered type and the
right 201 for the rest, and the `config` difference is what says they still need
their own response shape.

What is not known is how wide the family is. `policy/js` is a 404 because the
provider is not registered, and AGENTS.md already records that the accepted type
set on `POST .../policy` is nine and is **not** `policy/providers`' catalogue -
so whether the typed route's accepted set is that same nine, the catalogue, or a
third list is an open question with a cheap answer. The first thing to measure
is whether `POST .../policy/uma` exists, since `uma` is the type that is
accepted by the untyped create and absent from the catalogue.

### F241: `Overwrites` is a second exemption from the collision sweep and nothing ranks them

`Step.ExpectStatus` and `Step.Overwrites` both take a step out of `mintsIn`, for
opposite reasons, and each now has a test saying where it is legal. That is two
guards that know about each other because one cut wrote both.

The observation is the one F236 already made about a different pair: this
repository now has several "a declaration the sweep reads" mechanisms -
`PristineRealm`, `Mutates`, `ExpectStatus`, `Overwrites`, `parkedGoldens` - and
none of them knows the others exist. A third exemption from this particular
sweep will be built from scratch and will not come with its own legality test
unless somebody remembers to ask for one. Nothing is proposed; the note is that
the count is now five and the next one is the one to worry about.

### F242: Keycloak stores an empty-string authz id and it then collides globally

Found by a probe defect, not by design: a body carrying `{"_id":"","name":"one"}`
is a **201**, and the row is stored with an id of the empty string. A second
such create anywhere on the server - any realm, any resource server - then
collides with it in exactly the way a real id does.

Not chased and deliberately so: nothing in Gloak or in the corpus sends one, and
it is Keycloak's own defect rather than a contract anybody depends on. It is
filed because it is the cheapest possible reproduction of the §3 poisoning - two
requests, no ids to keep track of - and because "the empty string is an id" is
the sort of thing a validation tidy-up would close without realising it was
observable.

### F243: no probe script in this repository survives its own cut

Eleven scripts were written for this cut and all eleven are deleted with it.
Three of them encoded corrections that cost a run each to find - per-cell ids,
per-cell resource servers, and `fresh()` not being called in a command
substitution - and the next person measuring anything over a global id space
will rediscover all three.

F235 asks the same question from the recorder's side: information that would
have saved the next cut existed in the previous one's working tree. This is that
shape for probes rather than goldens. Nothing is proposed - a directory of
one-off shell scripts is its own liability, and the measurements themselves
belong in the spec and the goldens, which is where they went. The observation is
only that the **method** has no home, and this cut's method was wrong three
times before it was right.
