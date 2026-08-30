# fix/admin-defects: what belongs in the documents this branch may not edit

Date: 2026-08-30
Branch: `fix/admin-defects`
Follow-ups closed: F78, F84, F89. Not touched: F85.

Everything below was measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8102 (`kc-defect`, removed
at the end of the session) on 2026-08-30, and then compared against Gloak
through the conformance recorder and verifier. Nothing here was written from
memory or inferred from the documentation.

This branch does not touch `AGENTS.md`, `README.md`, the parity roadmap, the
observed spec or the follow-up list, so what is owed to them is written out
here.

---

## 1. Measurements

### 1.1 F84 was filed as one defect and is six

`POST /users` ignoring an inline `credentials` array is the headline and it is
not the whole of it. Measured one body at a time:

| # | What | Keycloak | Gloak before |
|---|---|---|---|
| 1 | `POST /users` with `credentials` | stores the credential, the password grant works at once | 201, nothing stored |
| 2 | `PUT /users/{id}` with `credentials` | 204, the password grant works at once | 204, nothing stored |
| 3 | an entry with no `value`, or `value:null` | **500** `unknown_error` on the create, **400** `{"errorMessage":"Could not update user!"}` on the update, and the whole request rolled back | 201/204, nothing stored |
| 4 | an entry with `value:""` | 201, and a credential with **no `credentialData` key at all** | 201, nothing stored |
| 5 | `{"credentials":"nonsense"}`, `{"enabled":"yes"}`, `[` | 400 `unknown_error` | 400 `invalid_request` (and 201 for the first, since the field did not exist) |
| 6 | an empty or `null` body on `PUT /users/{id}` | **400** `{"errorMessage":"Could not update user!"}` | 500 `unknown_error`, shared with the create |

Rows 5 and 6 are not incidental. Adding the field is what makes row 5
*reachable*: before it, `{"credentials":"nonsense"}` was an unknown key that Go's
decoder ignored and the create answered 201. Row 6 was already wrong and nothing
had asked.

#### What an entry means

`CredentialRepresentation` has more fields than `type` and `value` and almost
none of them survives:

- **`type` is ignored.** `"otp"`, `"nonsense"` and an absent type each produced
  a `password` credential the password grant then accepted. Same behaviour
  `reset-password` was already measured with, arriving on a second route.
- **`userLabel` is dropped.** A create naming one answers 201 and the credential
  reads back with no `userLabel`. This is **not** reset-password's rule:
  reset-password *clears* a label, this never reads one.
- **`id`, `createdDate` and `priority` are dropped.** The server mints its own
  id and stamps its own date - the opposite of `POST /clients` and
  `POST /client-scopes`, where the body's `id` wins.
- **`secretData` and `credentialData` are dropped.** A body carrying either
  still gets a freshly hashed argon2 credential, so this is not an import path.
- **`temporary` is a disjunction over the array and it only ever adds.**
  `[true, false]` and `[false, true]` both leave `UPDATE_PASSWORD` on the user,
  so it is not last-wins; and a non-temporary inline credential put over a user
  that already carries the action **leaves it there**, where `reset-password`
  with `temporary:false` removes it. Reusing `resetPassword`'s `withAction` call
  is one line and it is wrong on that second measurement.
- **Each entry replaces the one before it.** An array of two passwords leaves
  one credential holding the **second** value; the first no longer grants.

#### Ordering

- The username-missing check and the username conflict are both decided
  **before** the credentials, on the create and on the update. A taken username
  plus a valueless credential answers about the username on both.
- A rejected create leaves **no user**. Keycloak rolls a transaction back; Gloak
  has no transaction and deletes what it just made, which is the same
  observable.

#### The empty value

`{"type":"password","value":""}` is a 201 and produces a credential of three
keys - `id`, `type`, `createdDate` - with no `credentialData`. The password
grant against that user is then a **500**. It is Keycloak's own defect and it is
reproduced as far as the admin API reaches: a later `reset-password` over it
fixes it up and **keeps the id**.

#### The parse codes are per failure kind, not per shape

Measured on `POST /users` and re-measured on `PUT /users/{id}`, which agrees:

```
{                            400 invalid_request   syntax error, right shape
[                            400 unknown_error     wrong shape
{"credentials":"nonsense"}   400 unknown_error     right shape, wrong type
{"enabled":"yes"}            400 unknown_error     right shape, wrong type
```

The two type-mismatch rows are new. Every earlier probe of this endpoint sent a
truncated document, which is why `invalid_request` looked like the answer to "a
malformed body". It is the answer to malformed *JSON*; a well-formed document
whose field will not bind is the other family. **`invalid_request` is a syntax
failure and `unknown_error` is a binding failure**, and the shape rule already
written down is the special case of binding where nothing binds at all.

### 1.2 F78: a protocol mapper id is unique across the server, on five routes, with three local answers

The follow-up's correction was itself one step past its evidence. Measured as a
2x2 over route and location:

|  | id in the container being written | id anywhere else on the server |
|---|---|---|
| `POST .../protocol-mappers/models` | 409 `{"errorMessage":"Protocol mapper exists with same name"}` | 409 `{"error":"conflict","error_description":"Duplicate resource error"}` |
| `POST .../protocol-mappers/add-models` | 409 `Duplicate resource error` | 409 `Duplicate resource error` |
| `POST /clients` | 409 `{"errorMessage":"Client <clientId> already exists"}` | 409 `Duplicate resource error` |
| `POST /client-scopes` | 409 `{"errorMessage":"Client Scope <name> already exists"}` | 409 `Duplicate resource error` |
| `PUT /clients/{uuid}` | **400** `{"error":"invalid_input","error_description":"Cannot add protocol mapper '<name>'. Duplicate resource error"}` | 409 `Duplicate resource error` |

So the location decides on `models` and decides **nothing** on `add-models`,
whose two cells are the same body. The rule the left-hand column shares is that
a collision the route can see in the object it is building gets that route's
**own** conflict, and one only the rest of the server knows about gets the
generic one. That reads as Keycloak catching a duplicate in the persistence
context and letting a database constraint through at flush.

Three further measurements:

- **Server-wide is server-wide.** A client scope created in a *different realm*
  carrying a mapper id already in use in master is a 409. A realm-wide index
  answers that one 201 and passes every other cell.
- **The order on the two mapper routes is provider, then name, then id.** An id
  held elsewhere plus a name held here answers about the **name** on both
  routes; an id held here plus an unknown provider answers about the
  **provider**.
- **The clientId and scope-name conflicts win.** A create naming a taken
  clientId and a taken mapper id answers about the client.

#### `PUT /clients/{uuid}` matches its mappers by name

This had to be measured before the fifth route's check could go anywhere, and
nothing in the documents said it. Measured on one client, one step at a time:

```
same name, different id     204, and the mapper KEEPS ITS OWN ID
same name, no id            204, same
same name, other protocol   204, the old mapper is gone and a new id appears
a name the client lacks     added
a mapper the body omits     removed
protocolMappers: []         all removed
no protocolMappers key      untouched
```

So the body is matched onto the client's current mappers by **(protocol,
name)**, a match is updated in place - `protocolMapper` and `config` only, the
same pair `PUT .../protocol-mappers/models` writes - and only the **add** path
can collide. That is what makes a client's own representation put straight back
a 204 rather than a 400, which a naive "an id in use is refused" check would
break. Gloak replaced the list wholesale and let the body's id win.

#### Two entries in one body sharing an id

A third family again: `POST /clients` and `POST /client-scopes` answer their own
resource-already-exists message for a name nobody has taken, `add-models`
answers the generic duplicate, and `PUT /clients/{uuid}` answers its 400 naming
the **second** mapper.

### 1.3 F89: the config key order is a sized Java map and Gloak was not ordering at all

Measured on `oidc-usermodel-attribute-mapper` with a four-key config that the
create grows to six:

```
request     claim.name, jsonType.label, access.token.claim, id.token.claim
served      id.token.claim, access.token.claim, introspection.token.claim,
            claim.name, jsonType.label, userinfo.token.claim
```

That is `javamap.SizedKeyOrder(4, ...)` exactly. `SizedKeyOrder(6, ...)` puts
`introspection.token.claim` second and the request's own order puts `claim.name`
first, so **one body separates all three candidates**: no ordering, ordering
with the grown count, and the answer.

And with the count out of the way, on `oidc-nonce-backwards-compatible-mapper`,
which mirrors nothing:

```
request     claim.name, jsonType.label, user.attribute
served      claim.name, user.attribute, jsonType.label
```

**Whether a key dropped for an empty value still counts towards the map's size
appears not to be measurable.** No subset of a twelve-key pool of realistic
config keys has `SizedKeyOrder` disagreeing between *n* and *n+1*, so no request
can tell the two readings apart. The implementation counts the survivors, which
is what "the removal happens first" implies, and that choice is unpinned by
anything.

---

## 2. Entries for `AGENTS.md`, in its voice

For "Things that look like bugs and are not":

- **The `credentials` array on a user write is not `reset-password`'s body
  under another name.** Both routes honour it and both ignore the entry's
  `type`, exactly as `reset-password` does - but `userLabel`, `id`,
  `createdDate`, `priority`, `secretData` and `credentialData` are read and
  dropped, each entry replaces the one before it so an array of two passwords
  leaves one credential holding the second, and `temporary` is a **disjunction**
  over the array that only ever **adds** `UPDATE_PASSWORD`. `reset-password`
  with `temporary:false` removes that action; an inline credential with
  `temporary:false` leaves it. Sharing `withAction`'s third argument between the
  two is one line and it is wrong on that one measurement.

- **One missing password, three answers.** `reset-password` says 400
  `{"error":"No password provided"}`, `POST /users` says **500**
  `unknown_error` and rolls the user back, and `PUT /users/{id}` says **400**
  `{"errorMessage":"Could not update user!"}`. The last is also the update's
  answer to an empty or `null` body, where the create's is the 500 the observed
  document records - so `decodeInto` takes that answer as an argument. Sixth
  time this API has punished one decoder shared by a pair of routes.

- **An inline credential with an empty value is a 201 that stores a credential
  describing no hash** - three keys, no `credentialData` - and the password
  grant against that user is then a 500. Keycloak's own defect. A later
  `reset-password` repairs it in place and keeps the id.

- **`invalid_request` is a syntax failure and `unknown_error` is a binding
  failure.** The "cannot parse the JSON" code is not per endpoint, and not
  per body *shape* either: a well-formed object whose field will not bind -
  `{"credentials":"nonsense"}`, `{"enabled":"yes"}` - answers `unknown_error`
  on `POST /users`, where a truncated object answers `invalid_request`. The
  shape rule is the special case where nothing binds at all. Every earlier probe
  of this endpoint sent a truncated document, which is what made the narrower
  rule look complete.

- **A protocol mapper id is unique across the server, and five routes answer a
  collision in three different ways.** Which body a caller gets is decided by
  the route **and** by where the colliding mapper is - the follow-up said the
  location alone decides, and `add-models` refutes it by answering the generic
  `Duplicate resource error` to both of its cells where `POST .../models` beside
  it answers `Protocol mapper exists with same name` to the near one. The rule
  the local column shares is that a collision the route can see in the object it
  is building gets that route's own conflict and one only the rest of the server
  knows about gets the generic duplicate. `PUT /clients/{uuid}` is not even a
  409: it answers 400 `invalid_input` naming the mapper.

- **`PUT /clients/{uuid}` matches the body's protocol mappers by (protocol,
  name), not by id.** A match is updated in place and keeps the id it already
  had, whatever the body says; the body's id is read only on the add path.
  A name under a different protocol does not match, so the old mapper goes and a
  new id appears. That is why a client's own representation put straight back is
  a 204, and why an uniqueness check written as "an id already in use is
  refused" turns every read-modify-write into a 400.

- **A protocol mapper's `config` is served in `javamap.SizedKeyOrder` and the
  count is the request's, not the stored one.** A create that mirrors
  `access.token.claim` or `id.token.claim` grows the map after it has been
  through the first table, so a four-key request serialised at six keys is
  `SizedKeyOrder(4, ...)`. The line in this file saying a mapper's config key
  order "is reproduced exactly" was true only because every case in the
  catalogue used a key set whose hash order is its insertion order - the handler
  was not ordering at all. `admin/protocol-mappers/config-key-order-grown` is
  the case that separates the three candidates.

For "Build and test":

- **`make record` is silent on a clean checkout and stayed silent through this
  branch.** Thirty-two new goldens arrived and no existing one moved.

---

## 3. Follow-up dispositions

### F78 - closed, and the entry was wrong a fourth way

Corrected in place by the previous cut on three counts, all three of which hold:
server-wide, five routes, and two 409 messages. The fourth is that the location
does **not** decide alone - see §1.2's 2x2. `add-models` is the counter-example
and it is one route away from the one the correction was measured on.

**No migration, and `0017_*` is unused.** A container's protocol mappers are a
JSON column on `client` and `client_scope`, deliberately - `0015`'s own comment
says why - so there is no row for a `UNIQUE` index to sit on. A second table
holding the ids would be a second truth with no transaction to keep it in step
(nothing in this store writes transactionally), no foreign key to cascade it
when a realm is deleted, and therefore a new failure of its own: an orphaned
index row answering 409 for an id that is free. It would also need a backfill
written in each dialect's JSON functions, which is the driver-specific SQL the
scan was meant to avoid. The enforcement is server-wide either way, which is the
part the follow-up was actually about.

What went in instead is one store method per container repo -
`ProtocolMapperOwner(ctx, mapperID)` with **no realm argument**, because the
absence of the realm is the measurement - each scanning its table through the
shared `store.HoldsProtocolMapper` so the two drivers cannot come to read the
same bytes differently. `storetest` covers it, so the Postgres suite is the
evidence they agree.

### F84 - closed, and it is six defects

See §1.1. The four beyond "the array is ignored" are: the update route ignores
it too; the three answers to a missing value; the empty value's hashless
credential; and the two decode rules the field made reachable. The fifth and
sixth (`PUT`'s empty-body 400, the binding/syntax split) were already wrong and
nothing had asked.

The case that would have found it is `admin/users/inline-credential`, whose
**fixture logs in as the user it created**. `POST /users` answers 201 with an
empty body whether the array was honoured or dropped, so no case for
`POST /users` can see this; the observable is a grant two steps later, which is
exactly how the defect surfaced.

### F85 - not touched, deliberately

`auth_time` surviving a refresh needs a column in `internal/store` **and** a
change in `internal/token`, and `internal/token` belongs to the device-grant
stream this session. Left open and unstarted. It is not forgotten and nothing in
this branch makes it harder: no session column was added or renamed.

### F89 - closed, with the case that makes it observable

The follow-up asked whether a correctness fix with no failing test could be
justified. It could: `admin/protocol-mappers/config-key-order-grown` separates
"no ordering", "ordering at the grown count" and the measured answer with one
body, and `admin/protocol-mappers/config-key-order` separates the ordering from
the count. Both were measured against 26.7.1 before either was implemented.

One thing the fix does **not** pin, and cannot: whether a key dropped for an
empty value counts towards the size. See §1.3.

### New follow-ups this branch found and did not fix

- **F92: `POST /users` drops `requiredActions`.** Measured:
  `{"username":"x","requiredActions":["VERIFY_EMAIL"]}` reads back with that
  action, and with `UPDATE_PASSWORD` appended after it when a temporary inline
  credential is in the same body. Gloak stores none of it, so a create that
  sends both answers `["UPDATE_PASSWORD"]` where Keycloak answers
  `["VERIFY_EMAIL","UPDATE_PASSWORD"]`. Whether an unknown action is validated
  is unmeasured.
- **F93: `{"username":123}` is a 201.** Jackson coerces a JSON number into a
  `String`, so a create naming a numeric username succeeds and the user is
  called `123`. Go's decoder reports a binding failure, so Gloak answers the
  400 `unknown_error` the rest of that family gets. Reproducing it means a
  custom unmarshaller for every string field on the representation.
- **F94: the hashless credential's grant differs in the body.** The password
  grant against a user whose credential describes no hash is 500 on both, and
  Keycloak's body is `{"error":"unknown_error","error_description":"For more on
  this error consult the server log."}` where Gloak's is
  `{"errorMessage":"Internal Server Error"}`. `internal/oidc` was not this
  branch's to change; the status matching is an accident of
  `auth.VerifyPassword` refusing an unknown algorithm.
- **F95: `internal/oidc/token.go` is not `gofmt`-clean on `main`.** It was
  already so before this branch; `make lint` runs `vet` and not `gofmt`, so
  nothing catches it.

### The observed document's Shape 4 section is stale

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` still says the
`invalid_request`/`unknown_error` split "is not a parse-versus-shape
distinction" and belongs to the endpoint. The protocol-mapper cut already
corrected that to a shape rule in `AGENTS.md` without reaching the spec, and
§1.1 refines it again to syntax-versus-binding. Two documents now disagree with
each other and both are behind the measurements.

---

## 4. Parity

Measured by hand exactly the way CI does it, against the merge base `db9f4f3`:

```
before   242 of 500
after    242 of 500        no change
```

**Nothing moved, and that is the right answer.** Every one of the thirty-two
new cases sits on an operation the catalogue already claims - `POST /users`,
`PUT /users/{id}`, `GET .../credentials`, `POST /clients`,
`PUT /clients/{uuid}`, `POST /client-scopes`,
`POST .../protocol-mappers/models`, `POST .../protocol-mappers/add-models` and
`GET .../protocol-mappers/models/{id}` - so none of them carries an
`Operation`, and none can move a row. This branch fixes what those operations
*serve*; it does not add surface.

`cmd/parity` prints `no change` rather than `total unchanged` here, which is the
stronger of the two: not one row moved, so the flat total is not hiding a
chapter with no denominator.

The size of the change, for the record: 43 files, +2305/-15, of which 32 files
and +334 are goldens.

---

## 5. Mutation testing

Every claim that a case now catches something was checked by breaking the
implementation one way at a time, confirming the **named** case fails, and
reverting. A different mutation per claim; twenty-five in all, no survivors
except one that was a bad mutation and is recorded as such.

### F84

| mutation | case that failed |
|---|---|
| the create passes `nil` credentials on | `admin/users/inline-credential` |
| the update passes `nil` credentials on | `admin/users/update-inline-credential` |
| the entry's `userLabel` is written onto the credential | `admin/users/inline-credential-ignores-type-and-label` |
| the entry's `type` is written onto the credential | `admin/users/inline-credential-ignores-type-and-label` |
| only the first entry of the array is applied | `admin/users/inline-credential-twice` |
| an empty value is hashed like any other | `admin/users/inline-credential-empty-value` |
| `credentialData` is emitted for a hashless credential | `admin/users/inline-credential-empty-value` |
| `temporary` is last-wins rather than a disjunction | `admin/users/inline-credential-temporary-then-not` |
| `withAction` is reused with `temporary` as its third argument | `admin/users/inline-credential-keeps-temporary` |
| the rejected create is not rolled back | `admin/users/create-credential-without-value-rolled-back` |
| the update answers the create's 500 for a valueless credential | `admin/users/update-credential-without-value` |
| the two routes share one empty-body answer | `admin/users/update-null-body` |
| a binding failure answers `invalid_request` | `admin/users/create-credentials-wrong-type` |
| the leading-token shape check is removed | `admin/users/create-array-body` |
| a syntax failure answers `unknown_error` | `admin/users/create-malformed` (existing) |

### F78

| mutation | case that failed |
|---|---|
| `add-models` answers the near collision with the name conflict | `admin/protocol-mappers/add-models-duplicate-id-same-container` |
| `POST .../models` answers the near collision with the generic duplicate | `admin/protocol-mappers/duplicate-id-same-container` |
| the id check runs before the name check on `add-models` | `admin/protocol-mappers/add-models-duplicate-id-and-name` |
| the scope create's mappers are not checked | `admin/client-scopes/create-duplicate-mapper-id-across-realms` |
| the refused scope create is not rolled back | `admin/client-scopes/create-duplicate-mapper-id-rolled-back` |
| an in-body duplicate answers the generic 409 | `admin/client-scopes/create-duplicate-mapper-id-in-body` |
| the client create uses the scope's local message | `admin/clients/create-duplicate-mapper-id-in-body` |
| `PUT` matches its mappers by id | `admin/clients/update-mapper-keeps-its-id` |
| `PUT` replaces its mappers wholesale | `admin/clients/update-mapper-keeps-its-id` |
| `PUT`'s local duplicate answers the generic 409 | `admin/clients/update-duplicate-mapper-id-in-body` |
| `PUT` skips the server-wide check | `admin/clients/update-duplicate-mapper-id` |
| the client-scope lookup is realm-scoped | `storetest` `a protocol mapper id is found across realms and across containers` |
| the client lookup is realm-scoped | the same |
| `HoldsProtocolMapper` matches any id | the same |

### F89

| mutation | case that failed |
|---|---|
| the config is returned in the request's order | `admin/protocol-mappers/config-key-order` |
| the config is ordered at the grown count | `admin/protocol-mappers/config-key-order-grown` |
| `javamap.KeyOrder` in place of `SizedKeyOrder` | `admin/protocol-mappers/config-key-order` |

### The one survivor, and it was the mutation's fault

Writing `cred.Label = c.UserLabel` **after** `SetCredential` had already run
left `admin/users/inline-credential-ignores-type-and-label` passing. The
credential had been stored before the mutation touched it, so the mutation
changed nothing observable. Repeated on the other side of the write, it was
killed. Worth writing down because it is the failure mode of mutation testing
itself: a mutation that does nothing looks exactly like a test that misses
something.

### What these cases still do not pin

- Whether a key dropped for an empty value counts towards a config's map size.
  §1.3 - not measurable with any realistic key set.
- Whether `PUT /clients/{uuid}` with `"protocolMappers":null` leaves the
  mappers alone. The implementation treats it as absent; only absent and `[]`
  were measured.
- Whether `PUT /users/{id}` with a taken username **and** a wrong-typed field
  answers about the username. The two username cells were measured against a
  valueless credential and the parse cells against a valid username.
- Whether the name check precedes the id check on `POST /clients` and
  `POST /client-scopes`. Both cells answer the same message there, as they do
  on `POST .../models`, and unlike `POST .../models` there is no third body
  that separates them.
