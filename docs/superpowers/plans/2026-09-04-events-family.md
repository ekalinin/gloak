# The events family

Branch: `feat/events-family`
Date: 2026-09-04
Reference: `quay.io/keycloak/keycloak:26.7.1`, container `kc-events` on port 8171,
removed at the end. Every destructive probe ran in a created realm (`ev1`..`ev12`,
`evg2`), never in `master`, because turning `adminEventsEnabled` on in a realm
changes what every later request to that realm records.

Six operations, computed from the vendored description rather than from the
brief:

```
GET    /admin/realms/{realm}/events
DELETE /admin/realms/{realm}/events
GET    /admin/realms/{realm}/admin-events
DELETE /admin/realms/{realm}/admin-events
GET    /admin/realms/{realm}/events/config
PUT    /admin/realms/{realm}/events/config
```

All six are tagged `Realms Admin`; three paths carry them; the description has no
other path matching `event` in any case. All six are unserved today. The brief's
list was right this time, and it was checked rather than trusted.

---

## 1. Which shape this cut takes, and why the other two are worse here

**Shape 1: serve all six, and record nothing.** The config pair is real state and
is served from the state Gloak already keeps. The two listings validate their
parameters and answer `[]`. The two deletes answer 204. Nothing is emitted and no
table is added.

The two rejected shapes, and the measurements that reject them:

### Shape 2 - emit events too - is refused by a measurement, not by taste

The brief's premise is right and this cut confirmed it directly: **an Admin API
write Gloak already serves does produce an admin event on Keycloak.** With
`adminEventsEnabled` on, `POST /clients`, `POST /roles`, `POST /users` and
`DELETE /roles/{name}` each wrote one, and `GET /clients` beside them wrote none.
So unlike F157's brute-force record, the non-zero state here *is* reachable from
code this project owns. That is established rather than assumed, and it is the
first thing that separates this chapter from `attack-detection`.

What refuses the shape is the *shape of an admin event*, measured over twelve
diverse writes in one realm in one sweep (§2.6). An admin event carries a
`(operationType, resourceType, resourcePath, representation)` quadruple, and not
one of the four is derivable:

- **`resourceType` is not in the path.** Ten distinct values over twelve writes,
  and three of them name a *relation* that appears nowhere in the URL:
  `users/{id}/groups/{g}` is `GROUP_MEMBERSHIP`, `users/{id}/role-mappings/realm`
  is `REALM_ROLE_MAPPING`, `clients/{u}/default-client-scopes/{s}` is
  `CLIENT_SCOPE_CLIENT_MAPPING`. The enum has 39 members.
- **`resourcePath` is not the request path.** A child group create records
  `groups/{parent}/children` - the **parent's** id, where the same request's
  `Location` carries the **child's**, which AGENTS.md already records from the
  other side. And `PUT /admin/realms/{realm}` records an event with **no
  `resourcePath` key at all**.
- **`representation` is not the request body.** `POST /clients` records the body
  with the minted id added; `POST /client-scopes` one path segment away records
  the body **without** one; `PUT /clients/{uuid}` records the bare body; the
  realm role mapping records a JSON **array**; `PUT .../default-client-scopes/{s}`
  records **nothing** even with `adminEventsDetailsEnabled` on; a `DELETE`
  records the object as it was before it was deleted.
- **`operationType` is not the verb.** `PUT .../reset-password` and
  `POST .../logout` are both `ACTION` where other `PUT`s are `UPDATE`.

`internal/admin` registers **152 write routes** (51 `DELETE`, 61 `POST`, 40
`PUT`). Shape 2 restricted to the one package this branch owns is therefore 152
quadruples, every one of which has to be measured against the reference container
because none of the four can be computed. A quadruple written from the route
instead is a claim about Keycloak that is not true - the same failure F157 names
from the other direction, and the one this repository has paid for repeatedly.
That is a chapter of its own, and a large one; it is not a cut that also has to
build a store, twelve query parameters and six goldens.

The user half is unavailable for a second, independent reason. **Every user event
this cut could find is written by the login path.** Three Admin API writes that
look most likely to write one - `POST /users`, `PUT .../reset-password` and
`POST .../logout` - wrote an admin event each and **no user event at all**, while
two password grants at the token endpoint wrote two. The token endpoint is
`internal/oidc`'s, which this branch may not touch. So the user-event half is
F122's and F148's shape exactly: a boundary wearing the clothes of a bug.

### Shape 3 - a defensible middle - was looked for and is worse than either end

The narrowest honest middle available is: add the table, and emit from the one
write this cut owns, `PUT /events/config`, which is measured to record itself
(§2.4). It is rejected for three reasons.

1. **It makes the listing lie in a new way.** An empty `/admin-events` says
   "Gloak records nothing", which is checkable and true. A listing holding one
   row type out of 152 says "these are the admin writes that happened" and is
   false for 151 of them. A reader believes the second and goes behind the first.
2. **The golden that would assert it is only correct while nothing is added to
   its fixture.** Keycloak records every write after the flag goes on; Gloak
   would record one. Any step appended to that fixture diverges silently. That is
   the "one thing playing two roles" fragility that has produced seven of seven
   surviving mutations in this project.
3. **The cost is the whole of shape 2's storage for one row type**: migration
   0032, both drivers, a repo, a model type and twelve query parameters, holding
   `UPDATE REALM events/config` and nothing else.

### So: F157's answer, for a reason F157 does not have

This matters for whoever closes F157. F157's reason is *"nothing in this project
counts a failed authentication"* - one missing mechanism, and building it closes
the chapter. **Neither half of this chapter closes that way.** `/events` waits on
a package boundary; `/admin-events` waits on 152 measured quadruples. A cut that
builds a brute-force detector and then reaches for this chapter expecting the
same one-mechanism fix will find two different walls. The follow-up says so.

What shape 1 buys, and it is not nothing: **four of the six operations carry real
measured behaviour** - the config pair is rich (§2.1-2.5) and the two listings
have a parameter-validation surface with four distinct rejections across three
status classes (§2.7), all of which are statements about the *request* and need
no stored event to be true.

---

## 2. What a fresh realm holds, what the flags gate, and the decisive write

### 2.1 A fresh realm's `events/config`

Byte-identical on `master` and on a realm created through `POST /admin/realms` -
2739 bytes, `cmp`-verified:

```
GET /admin/realms/{realm}/events/config
200  Content-Type: application/json;charset=UTF-8   Cache-Control: no-cache
     all five security headers

{"eventsEnabled":false,"eventsListeners":["jboss-logging"],
 "enabledEventTypes":[ ...103 names... ],
 "adminEventsEnabled":false,"adminEventsDetailsEnabled":false}
```

Five keys in that fixed order, and a **sixth**, `eventsExpiration`, which sits
between `eventsEnabled` and `eventsListeners` and is **absent exactly when it is
zero**: set to `900` it appears, set to `0` it disappears, set to `-5` it appears
as `-5`. So the omission rule is `== 0`, not `<= 0`.

`enabledEventTypes` holds **103** names. The `eventType` enum has 132, so 29
exist that a default realm does not enable.

### 2.2 One stored state, two views, and they disagree in exactly one cell

`events/config` is the realm representation's own state - the same relationship
`client-policies/profiles` already has, and measured in both directions:

- `PUT .../events/config` changes what `GET /admin/realms/{realm}` answers.
- `PUT /admin/realms/{realm}` changes what `GET .../events/config` answers.

They agree on every field and every value **except one**: when
`enabledEventTypes` is stored **empty**, the realm representation serves `[]` and
`events/config` serves the 103 defaults. Set a non-empty list through either
route and both serve the same list. So the disagreement is exactly the state
every default realm is in, and the two reads have been contradicting each other
on `master` since the first day either was recorded.

### 2.3 `PUT /events/config` replaces two fields and merges four

Measured one field at a time against a realm carrying six non-default values.
`PUT {}` answered 204 and:

```
eventsEnabled              true  -> false      reset by an omitted value
eventsExpiration            900  -> absent     reset by an omitted value
eventsListeners      [jboss..]   -> unchanged  merged
enabledEventTypes  [LOGOUT,LOGIN]-> unchanged  merged
adminEventsEnabled         true  -> unchanged  merged
adminEventsDetailsEnabled  true  -> unchanged  merged
```

Two booleans reset and two booleans on the same body left alone. A decoder that
treats the six alike is wrong on two of them whichever way it is written.

`PUT /admin/realms/{realm}` writing the *same* state merges all six: a `{}` body
there left every one of them as it was. **Two writes onto one storage location,
two merge rules.**

### 2.4 What the two flags gate

**`adminEventsEnabled` gates recording, never reading.** On a clean realm, one
request at a time, counting the listing after each:

```
step 0  fresh, flag off                          0
step 1  PUT config {"adminEventsEnabled":true}   1   <- the switch-on records itself
step 2  POST /roles                              2
step 3  PUT config {"adminEventsEnabled":false}  3   <- the switch-off records itself too
step 4  POST /roles                              3   <- the first request not recorded
```

Reproduced on three realms. The rows recorded while the flag was on are still
served after it goes off, so the flag never touches the read.

**A `PUT` that leaves the flag off is not recorded.** Steps 5 and 6 - a
`{"adminEventsEnabled":false}` on a realm already off, and a
`{"eventsEnabled":true}` naming the admin flag not at all - both left the count
at 3. So the rule is not "the config write is always recorded" and it is not "any
change is recorded": **the write is recorded when `adminEventsEnabled` is true
either before the request or after it.** The set of listeners is the union of the
two configs.

**`adminEventsDetailsEnabled` is read at the new value on that same request.**
Turning details on records the switch-on **with** its `representation`; turning
details off records the switch-off **without** one. So the two flags on one
request are read at opposite ends of it, and an implementation that reads the
realm once gets one of them wrong.

**`eventsEnabled` gates the user listing the same way**, and only the login path
writes into it (§2.6).

### 2.5 The two array fields read `[]` in opposite directions

- `enabledEventTypes: []` means **all of them**: the read-back is the 103-name
  default list.
- `eventsListeners: []` means **none of them**: the read-back is `[]`.

And they validate differently too. An unknown **event type** is accepted and
stored - `{"enabledEventTypes":["NOT_A_TYPE"]}` is a 204 and reads back
`["NOT_A_TYPE"]`. An unknown **listener** is `400 {"error":"Unknown event
listener"}`. Two neighbouring array fields, opposite readings of empty and
opposite validation.

**The listener field has two different 400s.** `workflow-event-listener` is one
of the three `eventsListener` providers `GET /admin/serverinfo` reports, so it is
not the unknown-name sentence; it is
`400 {"error":"Global event listeners not allowed in realm specific
configuration"}`. Only `email` and `jboss-logging` can be stored. A list holding
both an unknown name and the global one answers about **whichever comes first in
the array**, so it is one pass with two tests. Measured on a created realm and on
`master`, which agree.

**This bullet said the global listener was "accepted and silently dropped" for
most of this cut, and it was wrong.** The probe that said so ran
`curl -o /dev/null` with no `-w`, so it never saw the 400 and read the unchanged
config as evidence of a drop. It was caught by the conformance fixture refusing
to take, three steps later. **A probe that does not read its own status code is
the `go test` rule wearing different clothes**, and this is the second time in
one cut that a `curl` default has been the variable rather than the server.

**Both lists come back in `javamap.KeyOrder`'s order and it is reproducible.**
Every set was written in both of two insertion orders and read back identically:
`{LOGIN,LOGOUT}` as `LOGOUT, LOGIN`; `{LOGIN,LOGOUT,REGISTER}` as
`LOGOUT, REGISTER, LOGIN`; a five-name set as
`REVOKE_GRANT, CLIENT_LOGIN, IMPERSONATE, CODE_TO_TOKEN, UPDATE_PASSWORD`;
`{jboss-logging,email}` as `jboss-logging, email`. `javamap.KeyOrder` places all
four exactly and `javamap.SizedKeyOrder` gets **two of the four wrong**, so these
sets discriminate between the two constructors - unlike the brute-force key set,
which discriminated nothing.

### 2.6 The decisive write, and the sweep that sizes shape 2

With `adminEventsEnabled` and `adminEventsDetailsEnabled` on, twelve writes in
one realm. The `resourcePath` column is the whole argument:

```
op      resourceType                 resourcePath                              representation
CREATE  CLIENT                       clients/{uuid}                            body + minted id
UPDATE  CLIENT                       clients/{uuid}                            body
CREATE  CLIENT_ROLE                  clients/{uuid}/roles/cr1                  stored role
CREATE  GROUP                        groups/{uuid}                             stored group
CREATE  GROUP                        groups/{PARENT uuid}/children             stored child
CREATE  CLIENT_SCOPE                 client-scopes/{uuid}                      body, no id
CREATE  USER                         users/{uuid}                              body
UPDATE  USER                         users/{uuid}                              body
CREATE  GROUP_MEMBERSHIP             users/{uuid}/groups/{uuid}                the group
CREATE  REALM_ROLE_MAPPING           users/{uuid}/role-mappings/realm          a JSON array
CREATE  CLIENT_SCOPE_CLIENT_MAPPING  clients/{uuid}/default-client-scopes/{s}  <absent>
CREATE  COMPONENT                    components/{uuid}                         body
UPDATE  REALM                        <no resourcePath key>                     body
DELETE  CLIENT                       clients/{uuid}                            the deleted object
ACTION  USER                         users/{uuid}/reset-password               <absent>
ACTION  USER                         users/{uuid}/logout                       <absent>
```

An admin event's key order is fixed:
`id, time, realmId, authDetails{realmId, clientId, userId, ipAddress},
operationType, resourceType, resourcePath, representation`. `realmId` is the
**target** realm's uuid and `authDetails.realmId` the **calling** realm's;
`authDetails.clientId` is the client's internal uuid, not `admin-cli`.
`representation` is a JSON **string**, the shape `credentialData` already has.
Both listings are newest-first.

A user event is a different body -
`{id, time, type, realmId, clientId, userId?, ipAddress, error?, details{}}` -
`userId` present only when the user resolved, `error` only on a failure, and
`details` a Java map in hash order.

**Every value that identifies an event is per request**: `id` is a fresh uuid,
`time` is epoch milliseconds, and `realmId` and the three `authDetails` ids are
uuids. A golden holding one asserts four fields and masks six.

### 2.7 The guards, one role at a time

Eleven callers, each holding exactly one `realm-management` role in the realm
under test plus one holding none. A created realm has `VERIFY_PROFILE` on, so
every probe user needs `email`, `firstName` and `lastName` or the password grant
answers `Account is not fully set up` for all of them - which is what a sweep
measuring itself looks like, and the first attempt did exactly that.

```
route                  none view-ev manage-ev view-r manage-r view-u manage-u query-u view-c manage-c realm-admin
GET    /events          403   200     200      403     403     403    403      403     403    403       200
DELETE /events          403   403     204      403     403     403    403      403     403    403       204
GET    /admin-events    403   200     200      403     403     403    403      403     403    403       200
DELETE /admin-events    403   403     204      403     403     403    403      403     403    403       204
GET    /events/config   403   200     200      403     403     403    403      403     403    403       200
PUT    /events/config   403   403     204      403     403     403    403      403     403    403       204
```

**The family is authorised out of its own dedicated pair**, `view-events` and
`manage-events`: read on view **or** manage, write on manage alone. `view-realm`
and `manage-realm` are 403 on all six although the description tags every one of
them `Realms Admin`. That is the **third** family where the tag fails to predict
the guard, after the client-scope defaults and the two chapters `small-chapters`
measured. These are also the first two of `realm-management`'s 21 roles this
project has had any use for; `bootstrap` already creates both and nothing has
read either.

### 2.8 The rejection surface

`PUT /events/config`:

```
valid                          204, no body
empty body                     500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
literal null                   500  same
absent Content-Type            204  accepted
Content-Type: text/plain       415 {"error":"The content-type header value did not match the value in @Consumes"}
Content-Type: application/xml  415  same
Content-Type: x-www-form-urlencoded  415  same
malformed  {                   400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
an array   []                  400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
unknown field                  400 {"error":"Invalid json representation for RealmEventsConfigRepresentation. Unrecognized field \"zz\" at line 1 column 8."}
wrong JSON type for a value    400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
unregistered eventsListeners entry
                               400 {"error":"Unknown event listener"}
a global eventsListeners entry 400 {"error":"Global event listeners not allowed in realm specific configuration"}
unknown enabledEventTypes entry 204, stored
```

The `{` / `[]` split is the existing rule confirmed on a new endpoint: the code is
per **body shape**, not per endpoint - the right shape truncated is
`invalid_request`, the wrong shape is `unknown_error`. And the unknown-field
message makes this a **fifteenth** strict JSON decoder, reporting a line and a
column.

Both listings:

```
first=abc  or  max=abc         404 {"error":"HTTP 404 Not Found"}
first=-1&max=-1                200 []
dateFrom=x                     400 {"error":"Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp"}
direction=x                    400 {"error":"Invalid value for sortDirection, expected value is asc or desc"}
type=NOPE / operationTypes=NOPE / resourceTypes=NOPE
                               500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
an unknown query key           ignored, 200
```

`direction`'s rejection **names a parameter that does not exist**: the query key
is `direction` and the sentence says `sortDirection`. And a malformed integer
bound is the generic 404 here, which is the fourth producer AGENTS.md records,
confirmed on two more listings.

Realm and caller failures: an unknown realm is `404 {"error":"Realm not found."}`
with its full stop, to every caller; no bearer and a garbage bearer are both
`401 {"error":"HTTP 401 Unauthorized"}`; a caller holding nothing is
`403 {"error":"HTTP 403 Forbidden"}`. A wrong verb on any of the three paths is
the generic `404 {"error":"HTTP 404 Not Found"}`.

### 2.9 Headers

Every response obeys the rules already written down, and two of them are
confirmed on new endpoints:

```
GET  /events, /admin-events, /events/config   200  application/json;charset=UTF-8  Cache-Control: no-cache  five headers
every error on all six                             application/json (no charset)   no Cache-Control          five headers
PUT  /events/config                           204  -                                no Cache-Control          five headers
DELETE /events, /admin-events                 204  -                                no Cache-Control          FOUR headers
```

The 204 split is rule (3) exactly: the `PUT`'s request declares
`application/json` so its 204 carries `X-Frame-Options`, and the deletes send no
`Content-Type` so theirs do not. Measured on the same `DELETE` under three
request `Content-Type`s - absent 0, `application/json` 1, `text/plain` 0 - so the
rule is re-derived here rather than inherited.

**One probe in this file was wrong the first time and is corrected here.** The
"no `Content-Type`" row above was measured with `curl -d`, which sets
`application/x-www-form-urlencoded` of its own accord, so it measured that value
and reported it as absence. A genuinely absent `Content-Type` is **accepted**,
204, which is what `requireJSONBody` already implements. Every `-d` in a
`Content-Type` probe is measuring curl.

`Cache-Control: no-cache` is on the three reads and on none of the three writes,
which is "pinned per endpoint" again.

---

## 3. What gets built

| operation | status | what it does |
| --- | --- | --- |
| `GET /events/config` | Implemented | serves the six-key body from the realm's stored settings, `enabledEventTypes` expanded to the 103 defaults when empty, both lists in `javamap.KeyOrder` |
| `PUT /events/config` | Implemented | the 415, the strict decode, the unknown-listener 400, the two-replace/four-merge split, the two `[]` readings, the listener drop |
| `GET /events` | Implemented | validates all nine parameters, then `[]` |
| `GET /admin-events` | Implemented | validates all twelve parameters, then `[]` |
| `DELETE /events` | Implemented | 204 |
| `DELETE /admin-events` | Implemented | 204 |

No migration, no table, no store method, no model type. `events/config` is
`model.Realm.Settings`, which already persists the representation as JSON and
already round-trips five of the six fields through `PUT /admin/realms/{realm}`.
The sixth, `eventsExpiration`, is added to `realmRepresentation` as a `*int` with
`omitempty` - absent on both measured realms, so no committed golden moves.

### Files

- `internal/admin/events.go` - the six handlers, the parameter validators, the
  103-name default list, and the `RealmEventsConfigRepresentation` decode.
- `internal/admin/events_test.go` - the merge/replace split, the two `[]`
  readings, the listener trio, the guard split, the parameter rejections.
- `internal/admin/realmrep.go` - `EventsExpiration *int` only.
- `internal/admin/router.go` - six registrations behind a `guardEvents` pair.
- `internal/conformance/catalog_admin.go` - appended at the very end.
- `internal/conformance/fixture.go` - appended at the very end.
- new goldens under `internal/conformance/testdata/golden/admin/realms-admin/`.

### The cases

Recorded against `master` where the state is the default one (the two listings
and the config read), and against a realm of the fixture's own where a write
happens - so that no case can turn a flag on in a realm another case reads.
**No case turns `adminEventsEnabled` on**, because a realm with it on records
every later write in that realm on Keycloak and none on Gloak, and that is the
divergence this cut is declaring rather than hiding.

### Parity

`admin/realms-admin` 33 of 45 served today, 12 unserved, of which these are six.
Expected after: 39 of 45, total 477 -> 483 of 541.

---

## 4. What is left undone, and filed

- Admin events are not recorded. 152 write routes, an unguessable quadruple each.
- User events are not recorded. The writer is `internal/oidc`'s.
- `enabledEventTypes` and `eventsListeners` are two more measured `javamap`
  key sets that discriminate `KeyOrder` from `SizedKeyOrder`; the vectors belong
  in `internal/javamap`, which this branch may not touch.
