# The events family

Branch: `feat/events-family`
Date: 2026-09-04
Reference: `quay.io/keycloak/keycloak:26.7.1`, container `kc-events` on port
8171, removed at the end. Every destructive probe ran in a created realm -
`ev1`..`ev13`, `evg2`, `gloak-probe-events*` - never in `master`, whose
`events/config` was `cmp`-verified byte-identical before and after the whole
session.

Six operations, computed from the vendored description rather than from the
brief and then checked against the catalogue:

```
GET    /admin/realms/{realm}/events
DELETE /admin/realms/{realm}/events
GET    /admin/realms/{realm}/admin-events
DELETE /admin/realms/{realm}/admin-events
GET    /admin/realms/{realm}/events/config
PUT    /admin/realms/{realm}/events/config
```

Three paths, and the description has no other path matching `event` in any
casing. All six were unserved and all six are served now.

The plan, with the twelve-write sweep and the guard table in full, is
`docs/superpowers/plans/2026-09-04-events-family.md`.

---

## 1. Measurements

### 1.1 The shape this cut took, and why it is F157's answer for a reason F157 does not have

**Shape 1: serve all six and record nothing.** The config pair is real state
served from real storage; the two listings validate their parameters and answer
`[]`; the two deletes answer 204. No table, no migration, no store method, no
model type.

The brief's premise was right and was confirmed rather than assumed: with
`adminEventsEnabled` on, **an Admin API write Gloak already serves does produce
an admin event.** `POST /clients`, `POST /roles`, `POST /users` and
`DELETE /roles/{name}` each wrote one; `GET /clients` beside them wrote none. So
unlike a brute-force record, the non-zero state here is reachable from code this
project owns, and this chapter is **not** `attack-detection` with different
nouns.

What refuses shape 2 is the *content* of an admin event. Twelve diverse writes in
one realm in one sweep, and none of the four fields follows from the route:

- **`resourceType` is not in the path.** Ten distinct values over twelve writes,
  three of them naming a relation that appears nowhere in the URL -
  `users/{id}/groups/{g}` is `GROUP_MEMBERSHIP`,
  `users/{id}/role-mappings/realm` is `REALM_ROLE_MAPPING`,
  `clients/{u}/default-client-scopes/{s}` is `CLIENT_SCOPE_CLIENT_MAPPING`. The
  enumeration has 39 members.
- **`resourcePath` is not the request path.** A child group create records
  `groups/{PARENT uuid}/children` where the same request's `Location` carries the
  **child's** id, and `PUT /admin/realms/{realm}` records an event with **no
  `resourcePath` key at all**.
- **`representation` is not the request body.** `POST /clients` records the body
  plus the minted id; `POST /client-scopes` one path segment away records the
  body **without** one; `PUT /clients/{uuid}` records the bare body; the realm
  role mapping records a JSON **array**; `PUT .../default-client-scopes/{s}`
  records nothing even with details on; a `DELETE` records the object as it was
  before it was deleted.
- **`operationType` is not the verb.** `PUT .../reset-password` and
  `POST .../logout` are both `ACTION` where other `PUT`s are `UPDATE`.

`internal/admin` registers **152 write routes** (51 `DELETE`, 61 `POST`, 40
`PUT`). Shape 2 restricted to the one package this branch owns is 152 measured
quadruples, which is a chapter and a large one. A quadruple written from the
route instead is a claim about Keycloak that is not true.

The user half is refused for a second, independent reason. **Every user event
this cut could find is written by the login path.** Three Admin API writes that
look most likely to write one - `POST /users`, `PUT .../reset-password` and
`POST .../logout` - wrote an admin event each and **no user event at all**, while
two password grants at the token endpoint wrote two. That path is
`internal/oidc`'s, which this branch may not touch: F122's and F148's shape, a
boundary wearing the clothes of a bug.

The middle shape was looked for and is worse than either end. The narrowest
honest one - add the table and emit from the single write this cut owns,
`PUT /events/config`, which is measured to record itself - makes the listing lie
in a *new* way (a listing complete for one route out of 152 says "these are the
admin writes that happened" and is false for 151), needs a fixture that is
correct only while nothing is appended to it, and costs shape 2's whole storage
for one row type.

**Why this matters to whoever closes F157:** F157's reason is one missing
mechanism - nothing counts a failed authentication - and building the detector
closes it. Neither half of this chapter closes that way. `/events` waits on a
package boundary and `/admin-events` waits on 152 measured quadruples. A cut that
builds a brute-force detector and reaches for this chapter expecting the same
one-mechanism fix will meet two different walls.

### 1.2 What a fresh realm's `events/config` holds

Byte-identical on `master` and on a realm created through `POST /admin/realms`:
2739 bytes, `cmp`-verified.

```
{"eventsEnabled":false,"eventsListeners":["jboss-logging"],
 "enabledEventTypes":[ ...103 names... ],
 "adminEventsEnabled":false,"adminEventsDetailsEnabled":false}
```

Five keys in that fixed order, and a **sixth**, `eventsExpiration`, between
`eventsEnabled` and `eventsListeners`, which is **absent exactly when it is
zero**: 900 appears, 0 disappears, and **-5 appears as -5**. The rule is `== 0`
and not `<= 0`, which is why the field is a pointer rather than an int with
omitempty.

`enabledEventTypes` holds 103 names in the enumeration's **declaration** order.
The `eventType` enumeration has 132, so 29 exist that no realm enables by
default. `operationType` has 4 and `resourceType` 39.

### 1.3 One stored state, two views, disagreeing in exactly one cell

`events/config` is the realm representation's own state, measured in both
directions - the relationship `client-policies/profiles` already has:

- `PUT .../events/config` changes what `GET /admin/realms/{realm}` answers.
- `PUT /admin/realms/{realm}` changes what `GET .../events/config` answers.

They agree on every field and every value **except one**: when
`enabledEventTypes` is stored **empty**, the realm representation serves `[]` and
`events/config` serves the 103 defaults. Store a non-empty list through either
route and both views serve the same list, in the same order. So the disagreement
is exactly the state every default realm is in, and the two reads have been
contradicting each other on `master` since the first day either was recorded.

### 1.4 What the two flags gate

**`adminEventsEnabled` gates recording, never reading.** One request at a time on
a clean realm, counting after each, reproduced on three realms:

```
step 0  fresh, flag off                          0
step 1  PUT config {"adminEventsEnabled":true}   1   the switch-on records itself
step 2  POST /roles                              2
step 3  PUT config {"adminEventsEnabled":false}  3   the switch-off records itself too
step 4  POST /roles                              3   the first request not recorded
```

Rows recorded while it was on are still served after it goes off.

**A `PUT` that leaves the flag off is not recorded.** A
`{"adminEventsEnabled":false}` on a realm already off, and a
`{"eventsEnabled":true}` naming the admin flag not at all, both left the count
at 3. So the rule is neither "the config write is always recorded" nor "any
change is recorded": **the write is recorded when `adminEventsEnabled` is true
either before the request or after it** - the union of the two configs.

**`adminEventsDetailsEnabled` is read at the new value on that same request.**
Turning details on records the switch-on **with** its `representation`; turning
details off records the switch-off **without** one. Two flags on one request read
at opposite ends of it.

**`eventsEnabled` gates the user listing the same way**, and only the login path
writes into it.

### 1.5 `PUT /events/config` replaces two fields and merges four

`PUT {}` on a realm carrying six non-default values, 204:

```
eventsEnabled              true   -> false      an omitted value replaces
eventsExpiration            900   -> absent     an omitted value replaces
eventsListeners       [jboss..]   -> unchanged  an omitted value merges
enabledEventTypes  [LOGOUT,LOGIN] -> unchanged  an omitted value merges
adminEventsEnabled         true   -> unchanged  an omitted value merges
adminEventsDetailsEnabled  true   -> unchanged  an omitted value merges
```

`PUT /admin/realms/{realm}` writing the same state merges all six - a `{}` body
there left every one of them alone. **One state, two writers, two merge rules.**

### 1.6 The two array fields read `[]` in opposite directions and validate differently

- `enabledEventTypes: []` means **all of them** and reads back as the 103
  defaults.
- `eventsListeners: []` means **none of them** and reads back as `[]`.

An unknown **event type** is accepted and stored -
`{"enabledEventTypes":["NOT_A_TYPE"]}` is a 204 and reads back holding it. The
listener list has **two different 400s**: an unregistered name is
`{"error":"Unknown event listener"}`, and `workflow-event-listener` - which
`GET /admin/serverinfo` does report as one of the three `eventsListener`
providers - is
`{"error":"Global event listeners not allowed in realm specific configuration"}`.
A list holding both answers about whichever comes first in the array, so it is
one pass with two tests. Only `email` and `jboss-logging` can be stored, and a
repeated name collapses.

**Neither refusal writes anything**:
`{"eventsEnabled":true,"eventsListeners":["nope"]}` on a realm with events off
answered 400 and left it off, where the same body without the listener answered
204 and turned it on.

**Both lists come back in `javamap.KeyOrder`'s order and it is reproducible.**
Every set was written in both of two insertion orders and read back identically:
`{LOGIN,LOGOUT}` as `LOGOUT, LOGIN`; `{LOGIN,LOGOUT,REGISTER}` as
`LOGOUT, REGISTER, LOGIN`; a five-name set as
`REVOKE_GRANT, CLIENT_LOGIN, IMPERSONATE, CODE_TO_TOKEN, UPDATE_PASSWORD`;
`{jboss-logging,email}` as `jboss-logging, email`. **`javamap.KeyOrder` places
all four and `javamap.SizedKeyOrder` gets two of the four wrong**, so these two
sets discriminate between the constructors where the brute-force key set
discriminated nothing. The vectors belong in `internal/javamap`, which this
branch may not touch; the ordering is applied in `decodeRealmSettings` so that
both readers of this state get it, and the mutation pass kills the sized
constructor on a committed golden.

### 1.7 The guards

Eleven callers, each holding exactly one `realm-management` role in the realm
under test plus one holding none:

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
them `Realms Admin`. These are also the first two of `realm-management`'s 21
roles this project has had a use for; `internal/bootstrap` has been creating both
since P2 and nothing had read either.

This agrees, from the other side, with the conferral table in the observed
document: it already records that "the events pair ... each need themselves".

**The first attempt at this sweep answered `NOTOKEN` for all sixty-six cells.** A
created realm has `VERIFY_PROFILE` enabled, so a probe user without `email`,
`firstName` and `lastName` cannot complete a password grant and every caller
looks identical. The `none` column is the control that says a sweep is measuring
the server.

### 1.8 The rejection surface, and the order it resolves in

`PUT /events/config`:

```
valid                                204, no body
absent Content-Type                  204, accepted
Content-Type text/plain / xml / form 415 The content-type header value did not match the value in @Consumes
empty body, literal null             500 unknown_error / For more on this error consult the server log.
truncated {                          400 invalid_request / Cannot parse the JSON
an array []                          400 unknown_error   / Cannot parse the JSON
a value of the wrong type            400 unknown_error   / Cannot parse the JSON
an unknown field                     400 Invalid json representation for RealmEventsConfigRepresentation. Unrecognized field "zz" at line 1 column 8.
an unregistered listener             400 Unknown event listener
a global listener                    400 Global event listeners not allowed in realm specific configuration
an unknown enabledEventTypes name    204, stored
```

The unknown-field check beats both listener refusals and so does the wrong-type
check, so the listener validation is last of the three.

Both listings, and the order is **three stages with the caller in the middle**:

```
1  the realm            404 {"error":"Realm not found."}                 to every caller
2  first / max          404 {"error":"HTTP 404 Not Found"}               to every caller that authenticated
3  the caller's role    403 {"error":"HTTP 403 Forbidden"}
4  type / operationTypes / resourceTypes   500 unknown_error
5  dateFrom then dateTo 400 Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp
6  direction            400 Invalid value for sortDirection, expected value is asc or desc
```

Every adjacency was measured with both faults sent together.

**Row 2's qualifier is a correction, and it was earned by a mutation.** This table
said "to every caller" for row 2 as well, from a sweep whose weakest caller was
`probe-none` - a user who held no admin role and whose **bearer verified**. The
adjacency between the bound and *authentication* was never measured: the request
that would settle it is a garbage or absent bearer sent with `?first=abc`, whose
answer is 401 if the caller is resolved first and this 404 if the bound is bound
first. Nothing in this repository has sent it - not on these two listings and not
on any of the seven other families that answer the same 404, every one of which
was measured with a good admin token. Gloak binds the bound first, which is a
guess, and it is flagged as one at `guardEventsListing` and in
`TestMalformedBoundBeatsTheRoleCheck`. **"To every caller" written from a sweep
of authenticated callers is a claim about the sample**, which is the failure mode
this file records four other bullets for. `first=-1&max=-1`
is a 200, an empty value on any parameter is ignored, an unknown query key is
ignored, and `type` may repeat.

The dates accept `yyyy-MM-dd` **strictly** - `2020-1-1`, `2020-13-01` and
`2020-01-32` are all the 400 - or a run of digits: `1700000000`, `20200101` and
`0` are 200 where `-1` and `1.5` are not. `direction` is case-sensitive, `DESC`
and `Asc` alike. The enumerations are case-sensitive too: `type=login` and
`operationTypes=create` are the 500.

### 1.9 Headers

```
GET  /events, /admin-events, /events/config   200  application/json;charset=UTF-8  Cache-Control: no-cache  five headers
every error on all six                             application/json (no charset)   no Cache-Control          five headers
PUT  /events/config                           204  -                                no Cache-Control          five headers
DELETE /events, /admin-events                 204  -                                no Cache-Control          FOUR headers
```

The 204 split is exception (3) re-derived rather than inherited: the same
`DELETE` under three request `Content-Type`s gave absent 0, `application/json` 1,
`text/plain` 0. `Cache-Control: no-cache` is on the three reads and none of the
three writes - "pinned per endpoint" again.

All nineteen committed goldens obey the media-type rule: seventeen
`application/json` responses carrying all five, and two bodyless 204s carrying
four.

### 1.10 Two probes in this cut were measuring the tooling

Recorded because the brief asked and because both are cheap to repeat.

- **`curl -d` sets `application/x-www-form-urlencoded`.** The first
  `Content-Type` sweep reported "no Content-Type is a 415" and had measured that
  value under the name of absence. A genuinely absent header is a 204.
- **A probe that discards its status code cannot see a 400.** The listener sweep
  ran `curl -o /dev/null` with no `-w`, saw the config unchanged after naming
  `workflow-event-listener`, and reported it "accepted and silently dropped". It
  is a 400 with its own sentence. The conformance fixture found it three steps
  later by refusing to take. **Never pipe a probe anywhere without reading its
  own exit code** is the same rule this repository already has for `go test`.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for folding in. This branch may not edit that file.

- **`events/config` and the realm representation are one state with two views,
  and they disagree in exactly one cell.** Measured in both directions, the way
  client policies already are: a `PUT` on either changes what the other answers.
  What differs is the empty case - a realm with no stored `enabledEventTypes`
  answers `[]` from `GET /admin/realms/{realm}` and the **103 defaults** from
  `GET .../events/config`, one path segment apart, and that is the state every
  realm a default install has is in. Store a non-empty list through either route
  and both views agree again, so the expansion is the read's and not the store's.
  Giving the two reads one serialiser is wrong on every default realm.

- **`PUT .../events/config` replaces two of its six fields and merges four, and
  `PUT /admin/realms/{realm}` merges all six.** A `PUT {}` on the events route
  resets `eventsEnabled` to false and clears `eventsExpiration` while leaving
  `eventsListeners`, `enabledEventTypes`, `adminEventsEnabled` and
  `adminEventsDetailsEnabled` exactly as they were; the same empty body on the
  realm route changes none of them. Two booleans reset and two booleans on the
  same body left alone, and one storage location with two merge rules - which is
  the fifth time sharing a decoder on this API has been the mistake.

- **`eventsExpiration` is absent exactly when it is zero, not when it is
  non-positive.** 900 appears, 0 disappears from both reads, and **-5 appears as
  -5**. `omitempty` on an int drops the value the server keeps.

- **The two array fields on `events/config` read `[]` in opposite directions and
  validate in opposite directions.** `enabledEventTypes: []` means all of them
  and reads back as the 103 defaults; `eventsListeners: []` means none and reads
  back empty. An unknown **event type** is stored without a murmur; an unknown
  **listener** is a 400. Two neighbouring keys on one body, four opposite rules.

- **The listener field has two different 400s, decided per entry in array
  order.** An unregistered name is `Unknown event listener`;
  `workflow-event-listener`, which `GET /admin/serverinfo` does report as a
  provider, is `Global event listeners not allowed in realm specific
  configuration`. A list holding both answers about whichever comes first. This
  bullet said the global one was "accepted and silently dropped" for most of one
  cut, because the probe that measured it discarded its status code and read an
  unchanged config as a drop.

- **`adminEventsEnabled` gates recording and never reading, and the `PUT` that
  moves it is recorded in both directions.** Turning it on records the switch-on
  as the realm's first admin event; turning it off records the switch-off as its
  last; a `PUT` that leaves it off records nothing. So the rule is the **union**
  of the flag before the request and after it. `adminEventsDetailsEnabled` on the
  same request is read at the **new** value: turning details off records the
  switch-off *without* a `representation`. Two flags on one request read at
  opposite ends of it, and an implementation that reads the realm once gets one
  of them wrong.

- **The events family is authorised out of `view-events` and `manage-events`**,
  read on either and write on manage alone, although the description tags all six
  operations `Realms Admin`. `view-realm` and `manage-realm` are 403 on every one
  of them. That is the fourth family whose guard the tag fails to predict, after
  the realm-level client-scope listings and the two chapters `small-chapters`
  measured, and these are the first two of `realm-management`'s roles this
  project has had a use for.

- **On the two event listings a malformed integer bound is answered before the
  caller's role and every other bad parameter after it.** A caller that
  authenticated and holds no admin role gets `404 {"error":"HTTP 404 Not Found"}`
  for `?first=abc` and a 403 for the same request without it, while `?type=NOPE`,
  `?dateFrom=x` and `?direction=y` all answer that caller 403. One parameter
  binds ahead of authorization and seven do not, which is why these routes cannot
  use the ordinary guard. The full order is realm, the bounds, the role, the
  enumerations, `dateFrom` then `dateTo`, `direction` - measured with both faults
  sent together at every adjacency.
  **Where the bound sits against *authentication* is not measured** - here or on
  any of the seven other families answering this 404, all of which were measured
  with a bearer that verifies. The one request that settles it is a garbage
  bearer with `?first=abc`: 401 if the caller is resolved first, this 404 if the
  bound is. Do not write that cell down until somebody sends it.

- **An unknown enumeration member on either listing is a 500.** `?type=NOPE`,
  `?operationTypes=NOPE` and `?resourceTypes=NOPE` answer
  `500 unknown_error` where every other bad parameter on the same routes answers
  a 400 or a 404, and the comparison is case-sensitive - `type=login` is the 500
  and `type=LOGIN` a 200. Reproducing it needs all three enumerations, 132, 39 and
  4 names, read off `GET /admin/serverinfo`.

- **`direction`'s rejection names a parameter that does not exist.** The query key
  is `direction` and the sentence is `Invalid value for sortDirection, expected
  value is asc or desc`. Building the message from the key is the tidy-up that
  breaks it.

- **A user event is written by the login path and never by the Admin API.**
  `POST /users`, `PUT .../reset-password` and `POST .../logout` each wrote an
  **admin** event and no user event at all, while two password grants at the
  token endpoint wrote two. Hanging a user event off an admin write is the
  obvious implementation and it fires where Keycloak does not.

- **An admin event's four fields are per route and none follows from the route.**
  Measured over twelve writes: `resourceType` took ten values and three of them
  name a relation the URL does not (`GROUP_MEMBERSHIP`, `REALM_ROLE_MAPPING`,
  `CLIENT_SCOPE_CLIENT_MAPPING`); a child group create's `resourcePath` carries
  its **parent's** id where the same request's `Location` carries the child's;
  `PUT /admin/realms/{realm}` records no `resourcePath` key at all;
  `representation` is the request body on one route, the body plus a minted id on
  the next, a JSON array on a third and absent on a fourth; and `ACTION` is not
  predictable from the verb. Deriving any of the four is a claim about Keycloak
  that is not true.

### Two lines this cut contradicts

- **"The 'cannot parse the JSON' code is per body *shape*, not per endpoint" is
  refuted by one measured body.** `{"eventsEnabled":"yes"}` on
  `PUT .../events/config` is the **right** shape for an object endpoint and
  answers `unknown_error`, where the shape rule predicts `invalid_request`. What
  fits this and the three data points the bullet already carries is **syntax
  against binding**: a truncated document is `invalid_request` and a
  type-mismatch is `unknown_error`, on either shape of endpoint. `{` on an object
  endpoint is truncated, `[` on an object endpoint is a mismatch, `[` on an array
  endpoint is truncated - all three come out right, and the shape test agrees
  with all three by coincidence. **The fourth data point in that bullet is still
  unexplained**: a truncated array *element* answers `HTTP 400 Bad Request`, which
  neither reading produces. Nothing shared was changed on the strength of one
  endpoint; `writeCannotParseJSON` keeps its prefix test and `internal/admin/events.go`
  separates the two locally. See F163.

- **"Fourteen strict JSON decoders" is fifteen**, and the new one reports a line
  and a column: `PUT .../events/config` answers an unknown field
  `Invalid json representation for RealmEventsConfigRepresentation. Unrecognized
  field "zz" at line 1 column 8.` That is a third family answering the position
  question the bullet leaves open, and the decode runs **after** the path's realm
  is resolved.

Two counts in that file have also drifted past this cut, and both are the kind it
already warns about:

- **"a malformed integer query parameter, measured on five listings across four
  families"** is now seven listings across five - `GET .../events` and
  `GET .../admin-events` answer it the same way.
- **the header bullet's tally, "application/json 556 carry them, 13 do not",
  computed 2026-09-03**, is 667 and 14 over the tree as it now stands. Fourteen,
  not thirteen, and none of the fourteen is from this branch: all nineteen of its
  goldens carry the five or are bodyless 204s carrying four. The bullet says its
  own test computes the tally, which is exactly why the prose beside it drifted.

---

## 3. Follow-up dispositions

### F157 - `attack-detection` stores nothing: unchanged, and now has a sibling that is not it

**Not closed and not affected.** Its reason is one missing mechanism: nothing in
this project counts a failed authentication, and building the detector closes the
chapter.

What this cut adds is a warning next to it. The events chapter reaches the same
answer - serve it, store nothing - **for two different reasons, neither of which
is F157's**, and it was established by measurement rather than assumed: an Admin
API write Gloak already serves *does* produce an admin event, so the zero record
is not the whole reachable state here. A cut that closes F157 by building a
brute-force detector and then reaches for `/events` expecting the same shape will
find a package boundary; reaching for `/admin-events` it will find 152 measured
quadruples.

### F121 - the `Workflows` tag needs a YAML writer: the neighbour that stayed unbuilt, and the comparison holds

**Unchanged.** It is the closest precedent for "a decision about another package
before it is N handlers", and this cut is the same judgement reached twice more:
the user listing is `internal/oidc`'s to fill and `internal/httpx` has no YAML
path. The difference worth recording is that F121 blocks on **one** decision in
one package, where `/admin-events` blocks on a measurement per route - so F121 is
a smaller thing wearing a bigger number.

`workflow-event-listener` turning up here as a refused `eventsListeners` value is
the first time the `Workflows` tag has been observable from outside its own
chapter, and it is observable only as a 400.

### F95 - a client's `attributes` is serialised from a Go map: unchanged, and one more entry on the pattern's side

**Unchanged, and not touched here.** This cut adds a sixth family that serialises
a Java collection from an ordered slice rather than a Go map - `eventsListeners`
and `enabledEventTypes`, ordered by `javamap.KeyOrder` in `decodeRealmSettings`
and asserted with **no `UnorderedKeys` retreat** on the golden. The client is
still the holdout, and the arithmetic in F95 is unchanged by this.

### F162 (proposed) - the events family records nothing, and the two halves are blocked differently

All six operations are served and every one is byte-exact for every request a
default install's realm can be given, because a default realm has both flags off
and both listings are empty on Keycloak too. What is missing is the recording,
and it is two different problems:

- **User events** are written by the login path, which is `internal/oidc`'s. This
  branch may not touch it. Three admin writes that might plausibly have written
  one were measured writing none, so nothing in `internal/admin` is a candidate.
  It is F122's shape.
- **Admin events** are written by requests `internal/admin` serves, so this is
  reachable - but each of the 152 write routes needs a measured
  `(operationType, resourceType, resourcePath, representation)` and none of the
  four can be derived from the route. That is a chapter of its own, and it should
  begin by settling `resourcePath`'s rule the way the `Location` rule was
  settled: server-minted against caller-chosen, over all 152, in one sweep.

Until it lands, a caller may turn `adminEventsEnabled` on through
`PUT .../events/config` and get an empty listing where Keycloak would have rows.
That is the divergence, it is declared rather than hidden, and no conformance
case turns the flag on in a realm it then reads.

### F163 (proposed) - "cannot parse the JSON" is syntax against binding, not body shape

See the contradiction in §2. One endpoint's measurement is not enough to change
`writeCannotParseJSON`, which fourteen other decoders share and whose current
prefix test agrees with every body measured before this cut. What would settle it
is one request per family: a body of the **right** shape carrying a value of the
wrong type. `internal/admin/events.go` separates the two locally with
`*json.UnmarshalTypeError`, which is exactly the distinction, so the fix is a
sweep and then a one-line change at the shared call site.

---

## 4. Parity, before and after

```
                             before        after
admin/realms-admin        33 of 45      39 of 45
total                    477 of 541    483 of 541
```

Computed with `cmd/parity` over two `GLOAK_PARITY_REPORT` runs, not by hand. The
twelve `Realms Admin` operations that were unserved before this cut were, in
full: the six here, `GET /credential-registrators`,
`GET`/`PUT /users-management-permissions`, `POST /partial-export`,
`POST /partialImport` and `POST /testSMTPConnection`. Six remain.

Nineteen goldens were recorded, no committed golden changed, and the catalogue
gained nineteen `Implemented` cases and no `Pending` one.

### The mutation pass

Twenty-two mutations, one per claim, each naming the test that had to fail,
against a `git clone --no-local` so that no revert could reach the worktree. The
harness ran the named test on a clean tree first and refused a selector that
matched nothing, and it reported `BUILD_FAILED`, `NOT_APPLIED`, `KILLED` and
`SURVIVED` as four separate outcomes.

**All twenty-two were killed, and two of them only after the mutation itself was
repaired** - which is what the four outcomes are for:

- One `SURVIVED` and was **inert**: it swapped `listeners == nil` for
  `len(listeners) == 0` where both branches assigned the same `[]string{}`, so it
  changed no byte. Replaced with the tidy-up somebody would actually make - give
  the listener list the type list's "empty means the default" reading - which is
  killed.
- One `BUILD_FAILED`: it removed both `javamap.KeyOrder` calls and left the
  import unused. Replaced with `javamap.SizedKeyOrder`, which is the mistake this
  project keeps meeting, and it is killed by a **committed golden** -
  `admin/realms-admin/events-config-written` - rather than by a package test.

Two of the twenty-two are killed by conformance cases and twenty by
`internal/admin/events_test.go`. Both the clone and the worktree were verified
clean afterwards.

### The eighth and ninth survivors, and the shape is now a rule

Two mutations from a second reviewer survived that pass. Both are the shape this
project has now met nine times, and at nine it is worth stating as a rule rather
than a tally.

**The rule: a test pins a two-condition rule only if its *starting state* or its
*request* supplies both conditions. Whichever of the two the fixture supplies for
free is the one the test is not testing.**

- **Eighth: the replace half of "replaces two, merges four" was pinned by
  nothing.** `TestEventsConfigPutReplacesTwoAndMergesFour` writes each list once
  onto the empty default, and **a merge and a replace agree on the first write**,
  so it pinned the merge half and said nothing about the replace half. The
  conformance fixture had the same blind spot for the same reason: it writes
  `["LOGIN","LOGOUT","REGISTER"]` onto an empty field. Turning the write into an
  `append` passed both packages.
  The missing condition was in the **state**: a second `PUT` carrying a list that
  is not a superset of the one already stored. `TestEventsConfigPutReplacesAPopulatedList`
  supplies it, with the two vectors that were already measured and never
  asserted - a disjoint five-name set onto three (five back, not eight) and
  `["email"]` onto `["jboss-logging"]` (one back, not two) - plus the empty list
  onto a populated one, which is the sharpest form. The mutation now fails by
  name with `got [LOGOUT REGISTER REVOKE_GRANT CLIENT_LOGIN IMPERSONATE
  CODE_TO_TOKEN LOGIN UPDATE_PASSWORD]`, which is the eight a merge leaves.
  **The same rule on the field beside it was already killed** - `eventsListeners`
  is covered by two tests - so one rule was pinned on one of its two fields and
  not the other, and nothing said which.

- **Ninth: the guard's order has two readings and only one of them was pinned.**
  The mutation was described as moving the caller above the bounds, and that is
  two different edits:

  ```
  B  the whole caller-and-role block moves above the bounds   KILLED
  A  resolveCaller alone moves, the role check stays below    SURVIVED
  ```

  B was mutation 11 of the original pass and is killed by
  `TestMalformedBoundBeatsTheRoleCheck` **on the status line first** - `got 403
  {"error":"HTTP 403 Forbidden"}, want 404 before the role check` - not only on
  the body. That test does send both conditions in one request, so the reviewer's
  diagnosis of *why* A survived does not hold; what holds is that A is a
  different claim.
  A changes exactly one cell: a **garbage or absent bearer** sent with a
  malformed bound, 401 against 404. **That cell has never been measured**, here or
  in any of the seven other families answering this 404. A is therefore left
  alive deliberately: killing it means asserting a value nobody has seen, which
  is the one thing this repository forbids outright. What was done instead is to
  widen the measured half - the test now runs both a caller holding one unrelated
  role and a caller holding **none at all**, because one caller cannot separate
  "before this role" from "before authorization" - and to correct the handover's
  "to every caller", which was written from a sweep of authenticated callers and
  was over-broad in exactly the direction the mutation found.

  **This is a survivor that is a finding about the documentation rather than
  about the code**, and it stays open until somebody sends
  `curl -H 'Authorization: Bearer xyz' '.../events?first=abc'`.

### What is left undone

- Neither listing records anything. F162.
- **One measurement is owed and is one request**: a garbage bearer with
  `?first=abc` on either listing, which decides whether the malformed bound is
  bound before or after authentication. Gloak guesses "before" and the ninth
  survivor above is that guess left visible rather than papered over. The answer
  probably generalises to the seven other families that answer this 404, none of
  which measured it either.
- **The two new assertions are package tests and both would be better as
  goldens.** Each is expressible in this harness - the replace needs a fixture
  with two `PUT` steps and a `GET` case, and the guard order needs the
  `caller_token` convention the catalogue already has - but a new `Implemented`
  case needs a recorded golden, and recording needs the reference container. They
  should be promoted on the next pass that starts one.
- The two `javamap` vectors this cut measured -
  `{LOGIN,LOGOUT,REGISTER}` and `{jboss-logging,email}`, which discriminate
  `KeyOrder` from `SizedKeyOrder` - are recorded here rather than added to
  `internal/javamap`'s tests, which this branch may not touch.
- `internal/store` and `internal/model` were not touched at all, and migration
  `0032_` was not needed.
