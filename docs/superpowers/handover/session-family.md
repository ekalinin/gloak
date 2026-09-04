# The session family

Branch `feat/session-family`. Eleven operations across `Clients`, `Users` and
`Realms Admin`, counted from the vendored description rather than from the
brief: it holds twelve operations whose path, `operationId` or summary names a
session, a logout or a revocation, and `POST /users/{user-id}/logout` was
already catalogued.

Everything below was measured on 2026-09-03 against a live Keycloak 26.7.1 -
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8168, container removed at
the end - at socket level through Python's `http.client`, which adds no
`Content-Type` a probe would then measure.

## Measurements

### What creates a session, and what the eleven answer when none exists

**The recorder's own admin token is a session.** The first `admin-cli` password
grant of any probe run puts one in `master`, so the empty state cannot be
measured there at all. Every empty-state number below comes from a realm created
through `POST /admin/realms`.

**A password grant in a created realm needs a user carrying an email, a
firstName *and* a lastName**; the same user in `master` needs none of the three.
Measured as a 2x6 matrix - six users in a created realm differing only in which
profile fields they carry, and the same six in master as the control. Only the
full three grants in the created realm; all six grant in master. Everything
short of it answers
`{"error":"invalid_grant","error_description":"Account is not fully set up"}`,
which names neither the realm nor the profile. It cost an hour to find and it is
the first thing a fixture in this family gets wrong.

**An offline session is a second, disjoint session, not a flavour of the first.**

```
after a plain password grant                    session-count 1  offline-session-count 0
after an offline grant at the same client       session-count 1  offline-session-count 1
after an offline grant and nothing else         session-count 0  offline-session-count 1
```

The third row decides the model: an offline grant leaves **no** online session
behind, the ids differ, and `GET /users/{id}/sessions` never shows an offline
one. `refresh_expires_in` is `0` on the offline grant.

The empty answers, on a realm holding a client and a user that have never been
used:

```
GET  clients/{uuid}/session-count             200  {"count":0}
GET  clients/{uuid}/user-sessions             200  []
GET  clients/{uuid}/offline-session-count     200  {"count":0}
GET  clients/{uuid}/offline-sessions          200  []
POST clients/{uuid}/push-revocation           200  {}
GET  users/{id}/sessions                      200  []
GET  users/{id}/offline-sessions/{clientUuid} 200  []
GET  client-session-stats                     200  []
POST push-revocation                          200  {}
POST logout-all                               200  {}
DELETE sessions/{session}                     404  {"error":"Sesssion not found"}
```

Ten of the eleven answer 200 with an empty shape and the eleventh is the only
one naming a session in its path. `{}` is a `GlobalRequestResult` whose two
arrays are **omitted** rather than emitted empty.

### The session representation

```json
{"id":"…","username":"…","userId":"…","ipAddress":"172.17.0.1",
 "start":1788546760000,"lastAccess":1788546760000,"rememberMe":false,
 "clients":{"<client uuid>":"<clientId>"},"transientUser":false}
```

Nine keys, one order, and the same nine for an online session and an offline
one. `start` and `lastAccess` are Unix milliseconds **truncated to the second** -
every measured value ends in three zeros; `lastAccess` moves on a refresh and
`start` does not, measured three seconds apart. It is **not** a Java map:
`javamap.KeyOrder` over those nine names returns a completely different order,
so it is a POJO.

### `client-session-stats` is two Java maps, and `KeyOrder` places both

```json
[{"offline":"0","clientId":"gloak-probe-sy-app","active":"1","id":"e41a45d6-…"}]
```

- The four keys are `HashMap` order and the counts are **strings**. The
  description's schema says `additionalProperties: {"type":"string"}` and
  `javamap.KeyOrder(["offline","clientId","active","id"])` returns exactly that
  order. Two independent sources agreeing.
- The array is a `HashMap` keyed on the client UUID: six clients came back
  `cc mm dd bb zz aa` from an insertion order of `aa bb cc dd zz mm`, and
  `KeyOrder` over those six UUIDs returns exactly that. **A fifteenth measured
  key set for that function.**
- The `clients` map inside a session is a `HashMap` too and `KeyOrder` is
  measured **wrong** on it: the same six UUIDs came back `cc dd mm …` where
  `KeyOrder` says `cc mm dd …`. `dd` and `mm` collide and chain in insertion
  order, which is precisely the limit the package documents. **A sixteenth
  measured key set, and the second that its tie-break loses.**

It is also the one read of the eleven that sees something the other ten do not:
**a client with zero active sessions and one offline session still gets a row**,
`{"offline":"1","active":"0"}`. A client with neither gets no row.

### Two paging rules inside one family

`GET /clients/{uuid}/user-sessions` and `.../offline-sessions` declare `first`
and `max`. Over four sessions:

```
no bounds        4      max=0            0
max=2            2      first=abc        404 {"error":"HTTP 404 Not Found"}
first=1          3      max=abc          404
first=1&max=2    2
first=-1&max=-1  4      a negative bound means "no bound"
```

Either bound alone pages - the group listing's rule, and neither the role
listings' nor the user listing's. Rows come back **sorted by session id,
byte-ascending**, confirmed on a four-id set and a six-id set.

`GET /users/{id}/sessions` declares no parameters and **reads none**: with six
sessions, `max=1`, `first=1`, `first=1&max=1`, `max=0`, `first=abc` and
`max=abc` all answered all six with a 200. `client-session-stats` behaves the
same way. **So one family holds both answers to a malformed integer bound** -
the generic 404 on the two client listings and 200 with everything on the other
two.

**The first reading of this was wrong and the probe was measuring itself**: a
single `?max=1` against a user holding one session answered one row and looked
like paging. Six sessions is what separates the readings.

### Four spellings of not-found, and one of them is misspelled

```
the five /clients/{uuid}/… routes         {"error":"Could not find client"}
GET users/{unknown}/sessions              {"error":"User not found"}
GET users/{unknown}/offline-sessions/{c}  {"error":"User not found"}
GET users/{u}/offline-sessions/{unknown}  {"error":"Client not found"}
DELETE sessions/{unknown}                 {"error":"Sesssion not found"}
```

The user is resolved before the client on the one route naming both: an unknown
user with a real client answers about the user, and so does a request whose ids
are both unknown.

### `isOffline` partitions the id space, and a malformed boolean is not a malformed integer

```
DELETE sessions/{online id}                    204
DELETE sessions/{same id again}                404 Sesssion not found
DELETE sessions/{offline id}                   404 Sesssion not found
DELETE sessions/{offline id}?isOffline=true    204
DELETE sessions/{online id}?isOffline=true     404 Sesssion not found
DELETE sessions/{online id}?isOffline=bogus    204
```

### The two logouts reach different sets

```
                              online   offline
after one grant of each          1         1
POST /logout-all                 0         0
POST /users/{id}/logout          0         1
```

Measured twice with the state rebuilt in between. `logout-all` also **stamps the
realm's `notBefore`** with the second it happened and leaves every user's and
every client's alone; **neither push-revocation stamps anything**, measured on
three fresh realms one write at a time, reading the realm and the client before
and after.

`logout-all` also ends **the caller's own session**, which is why the
conformance case for it addresses a created realm: on master it would end the
recorder's session and break every case after it.

### push-revocation calls out; logout-all reports success without checking

With a container on the same Docker bridge answering 204 and an unroutable
address as the control:

```
POST clients/{good}/push-revocation  {"successRequests":["http://172.17.0.5:9977/adm"]}
POST clients/{bad}/push-revocation   {"failedRequests":["http://172.17.0.99:9/nowhere"]}
POST push-revocation (one of each)   {"successRequests":[good],"failedRequests":[bad]}
POST logout-all                      {"successRequests":[bad, good]}
```

`logout-all` reports the unroutable client a **success**, with a session at it
and without one, on both of two runs, where `push-revocation` on the same client
and the same address reports a failure. Keycloak's own defect, and the reason
`logout-all`'s body needs no outbound call at all.

**The first run of this had no control** - a listener on the macOS host that the
container could never reach - and reported the same two verdicts, which looked
like the same finding and was evidence of nothing. A probe with no reachable arm
cannot tell "the call failed" from "no call was made".

What leaves the server, captured off the socket:

```
POST {adminUrl}/k_push_not_before HTTP/1.1
Content-Type: text/plain; charset=ISO-8859-1
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.12)

<a bare RS256 JWT signed with the realm's active RSA key>
  {"id":"<uuid>-<epoch millis>","expiration":<iat+30>,
   "resource":"<clientId>","action":"PUSH_NOT_BEFORE","notBefore":<realm notBefore>}
```

`logout-all` posts the same shape to `{adminUrl}/k_logout` with
`"action":"LOGOUT"`. **This is not `notifyBackchannel`'s machinery**: different
path, different claims, different action, `text/plain` rather than a
`logout_token` form key, and no `sid`.

### The guards: one tag, three answers

```
                                    view-  manage- view- manage- view- manage-
                                    clnts  clnts   usrs  usrs    realm realm  none
clients/session-count                200    200    403   403     403   403    403
clients/user-sessions                200    200    403   403     403   403    403
clients/offline-session-count        200    200    403   403     403   403    403
clients/offline-sessions             200    200    403   403     403   403    403
clients/push-revocation              403    200    403   403     403   403    403
users/{id}/sessions                  403    403    200   200     403   403    403
users/{id}/offline-sessions/{cu}     403    403    200   200     403   403    403
client-session-stats                 403    403    403   403     200   200    403
push-revocation                      403    403    403   403     403   200    403
logout-all                           403    403    403   200     403   403    403
DELETE sessions/{session}            403    403    403   404     403   403    403
```

`query-clients` and `query-users` open nothing. The `manage-users` 404 on the
delete is what says the role is checked before the session is resolved.

### Headers

```
                          status  Content-Type                     Cache-Control
the seven reads           200     application/json;charset=UTF-8   no-cache
the three 200 writes      200     application/json;charset=UTF-8   (none)
DELETE sessions/{id}      204     (none)                           (none)
DELETE sessions/{unknown} 404     application/json                 (none)
```

Every 200 and the 404 carry all five security headers. The 204 carries
`X-Frame-Options` only when the request declared `application/json`. Nothing
here contradicts the charset rule, the security-header rule or the
"`Cache-Control` is pinned per endpoint" rule.

## Entries for AGENTS.md's "Things that look like bugs and are not"

- **`Sesssion not found` has three `s`s, and it is the twenty-eighth spelling.**
  `DELETE /admin/realms/{realm}/sessions/{session}` answers it for an id that
  names nothing and for one that is not a UUID alike. It is the first spelling
  in that list that is **misspelled**, and correcting it is the tidy-up that
  breaks the one thing this project exists to do. The chapter adds one entry to
  the list and not three: the five `/clients/{uuid}/…` session routes answer
  `Could not find client` and the `{clientUuid}` of
  `/users/{id}/offline-sessions/{clientUuid}` answers `Client not found`, which
  are already (1) and (2) - so **one missing client, two spellings, one route
  family apart**, and the user is resolved first on the route naming both.

- **A malformed boolean is not a malformed integer, and one family holds both.**
  `?isOffline=bogus` deletes an online session - it parses leniently and falls
  back to false - where `?first=abc` on the listing one path segment away is the
  generic `{"error":"HTTP 404 Not Found"}`. And `isOffline` is not a filter over
  one namespace: it **selects which of two disjoint id spaces** the path segment
  is looked up in, so an online id with `isOffline=true` is a 404 and an offline
  id without it is a 404 too.

- **Two session listings in one family, two paging rules and two answers to a
  malformed bound.** `GET /clients/{uuid}/user-sessions` and
  `.../offline-sessions` page on either bound alone, treat a negative bound as
  no bound, answer `max=0` with zero rows and answer `first=abc` with the
  generic 404. `GET /users/{id}/sessions` and `GET /client-session-stats`
  **read no bounds at all** and answer 200 with everything, malformed ones
  included. Both listings are sorted by session id, byte-ascending. That is the
  identity-provider/component split reproduced inside one chapter, and the first
  reading of it was a `?max=1` against a user holding one session - a probe
  whose input could not change its output.

- **`logout-all` ends the offline sessions and `POST /users/{id}/logout` does
  not**, measured on one realm with the state rebuilt in between. `logout-all`
  stamps the **realm's** `notBefore` where the user logout stamps the user's,
  and **neither push-revocation stamps anything** - a push sends the policy the
  logout sets, and reading the pair the other way round is wrong on both.
  `logout-all` also ends the **caller's own** session, so a conformance case for
  it cannot address master.

- **`logout-all`'s `GlobalRequestResult` reports an unreachable client a
  success and `push-revocation`'s reports it a failure.** Measured against an
  unroutable `adminUrl`, with a session at that client and without one, where
  the same client and the same address are `failedRequests` from
  `push-revocation`. So `logout-all`'s body is a pure function of the realm's
  clients and needs no outbound call, while `push-revocation`'s does not exist
  without one. An empty `GlobalRequestResult` is `{}`: both arrays are omitted
  rather than emitted empty.

- **A password grant in a realm created through `POST /admin/realms` needs an
  email, a firstName and a lastName, and the same user in `master` needs none of
  them.** Measured as a 2x6 matrix with master as the control. The refusal is
  `invalid_grant` / `Account is not fully set up`, which names neither the realm
  nor the profile - so a fixture that drops one of the three fails with a
  message about the account.

- **`client-session-stats` is a `Map<String,String>` twice over and
  `javamap.KeyOrder` places both.** Its four keys come back
  `offline, clientId, active, id`, which is `KeyOrder`'s order over those names,
  and both counts are **quoted** - the description's schema says
  `additionalProperties: {"type":"string"}`, so two independent sources agree.
  Its array is a map keyed on the client UUID and `KeyOrder` places six of them
  exactly. The `clients` map inside a session representation is the same kind of
  map and `KeyOrder` gets it **wrong**, by one colliding pair chaining in
  insertion order - two more measured key sets, and the second of them is the
  third to lose the tie-break.

- **An offline session is a second session and not a flag on the first.** An
  offline grant leaves no online session at all - `session-count` 0,
  `offline-session-count` 1 - the two sets never share an id, and
  `GET /users/{id}/sessions` never shows an offline one.
  `client-session-stats` is the only read that sees both, and **its row survives
  an active count of zero**.

## What my measurements contradict

**Nothing in AGENTS.md or the observed document is contradicted by anything
here**, and one line came close enough to be worth writing down.

`AGENTS.md:1087` and the observed document's line 7873 both say
`POST .../logout-all` "ended two sessions and **made zero calls**". That is
about the OIDC back-channel notification and it is still exactly right:
`logout-all` fires no `logout_token`. It does fire a `k_logout` to a client's
`adminUrl`, which is a **different outbound mechanism** that the sweep behind
that line was not looking for - different path, different claim set, different
content type. Both sentences are true of what they measured, and this handover
is the first place they appear side by side.

`AGENTS.md`'s twenty-seven-spellings bullet needs the twenty-eighth added, and
the entry above says so; that is an extension rather than a contradiction.

## Follow-up dispositions

### F130 - `SessionRepo` cannot list a realm's sessions: **closed on this branch**

Not stale. The interface really had no listing method and
`channelLogoutTargets` really was still walking `ListByRealm` asking
`ClientSession` per candidate. This is the third cut to meet it and the entry
asked the third to add the methods rather than route again, so it did:

```go
ListUserSessionsByRealm(ctx, realmID)
ListUserSessionsByUser(ctx, realmID, userID)
ListUserSessionsByClient(ctx, realmID, clientID)
ListClientSessions(ctx, userSessionID)
```

All four in both drivers, all four sorted by session id, all four with a caller
in this cut, and exercised by a new `storetest` subtest that pins the sort and
the realm scoping in both directions. **The half that is left is one line in
`internal/oidc`**: `channelLogoutTargets` can now call `ListClientSessions`
instead of scanning the realm's clients, and that file is not this cut's. F130
should stay open **only** for that line, with the workaround it describes now
optional rather than forced.

### F122 - the two admin logout triggers notify nobody: **still open, and now measured**

`POST /users/{id}/logout` and `DELETE /sessions/{sid}` still fire no
notification, and this cut did not change that. What it adds is the measurement
that decides the boundary:

- `push-revocation` wants a **different** poster from `notifyBackchannel`, not
  the same one. The back-channel logout posts a `logout_token` form key to
  `backchannel.logout.url` with `typ: logout+jwt` and a `sid`;
  `push-revocation` posts a bare JWT as `text/plain` to
  `{adminUrl}/k_push_not_before` with `action: PUSH_NOT_BEFORE` and no `sid`.
  Three endpoints - the two push-revocations and `logout-all`'s `k_logout` -
  want one **new** poster with a shape of its own.
- So the honest fix is one outbound signed-JWT poster shared by
  `notifyBackchannel` and the adapter push, living where `notifyBackchannel`
  lives. Building a second one in `internal/admin` would be exactly the half a
  package boundary that F122 names.
- **This cut therefore serves the reachable state and nothing else.** Both
  push-revocations answer `{}`, which is byte-exact on every default install and
  every state a conformance fixture can reach, and diverges only on a realm
  whose client carries an `adminUrl` - which Gloak cannot even represent (see
  below). `logout-all` needs no poster at all, because its body reports every
  `adminUrl` a success regardless.

F122 should gain a line: `POST /push-revocation` and
`POST /clients/{uuid}/push-revocation` are served and their bodies are correct
for the reachable state, and they join the two triggers waiting on one poster.

### F157 - a table nothing writes is a claim about the model that is not true: **applied, and it is the cut's largest decision**

Four of the eleven read offline sessions and Gloak has none, because
`grantedScope` in `internal/oidc/token.go` drops `offline_access` before
anything is stored. **No `offline_session` table was added**, and the brief's
reserved migration slot `0029_` is unused: everything the eleven read is already
in `0003_session.sql`, and everything that is not - `ipAddress`, `rememberMe`,
the offline side - has its only possible writer inside a package this cut does
not own.

The same rule removed a helper. `logout-all`'s success list is every non-empty
`adminUrl` in the realm, and **Gloak has no `adminUrl` at all** - the field is
absent from `model.Client` and from the client representation. A function
computing that list could only ever return nil, which is a mask that changes
nothing wearing a different hat, so it is a sentence in `logoutAll` rather than
a function.

`attack-detection` is the precedent and this chapter is its shape twice over:
the offline half's whole reachable state is the empty one, the reads answer what
Keycloak answers for it, and the absence is written down rather than papered
over with a column.

### F95 - a client's `attributes` is serialised from a Go map: **untouched, and this cut adds no sixth holdout**

Nothing here marshals a Go map into a response. The two Java maps this chapter
serves both go through an ordered marshaller: `clientSessionStatsRow` is a
struct whose field order is asserted against `javamap.KeyOrder` by a test that
**computes** the order rather than transcribing it, and the session's `clients`
map is `orderedStringMap`, which sorts by `KeyOrder` and marshals through
`marshalOrderedValue` - so it inherits `SetEscapeHTML(false)` the way the other
four ordered marshallers do. F95's count of five families that do it properly
becomes six, and the client is still the holdout.

## Two things found on the branch and not fixed

- **`GET /clients/{uuid}` and `GET .../client-secret` refuse `manage-clients`
  and Keycloak answers them 200.** Measured side by side with `view-clients` on
  the container. Gloak guards both with `h.guard("view-clients", …)`, a
  single-role check, and AGENTS.md's own rule already says "reads accept the
  manage role, not just the view role ... `view-clients` or `manage-clients` for
  client roles". `GET .../client-secret/rotated` and
  `.../service-account-user` take the same single-role form and are presumably
  the same. **The four session reads this cut adds use `clientRolesReadRoles`
  and are correct**; the four pre-existing ones were left alone because they
  belong to the client chapter, no case pins either behaviour, and a guard
  change with no golden under it is the arrangement this project has twice
  found to pin nothing. It is a four-word fix plus four cases.
- **`adminUrl` is not modelled anywhere in Gloak.** Absent from
  `model.Client` and from the client representation, so a create carrying one
  drops it and the read comes back without it. That is a client-chapter
  divergence rather than a session one, but this family is where it becomes
  observable: `push-revocation`'s and `logout-all`'s bodies are functions of it.

## The mutation pass

Twenty-seven mutations, one per claim, each confirming a **named** test and each
reverted with the revert verified by file hash rather than by `git checkout`
having been typed.

**Twenty-six were killed. One survived, and it was a finding.**

Replacing `ListUserSessionsByClient` with `ListUserSessionsByRealm` in
`clientSessionCount` left the whole `internal/admin` package **and** the whole
conformance suite green. Every fixture in this family has exactly one client
with sessions in its realm, so realm-wide and client-wide agree on all of them;
the distinguishing input is a second client in the same realm that nobody has
logged into, which master has five of and no case had asked about.
`TestTheClientReadsCountTheClientAndNotTheRealm` asks now, for the count and the
listing both, with the used client as the control - and the mutation is killed.

One further trap is worth recording because it wasted a run: the survivor's
first report was `[no tests to run]`, because the mutation named a test in the
wrong package. **A test selector that matches nothing reports the same answer
for every mutation**, which is the third shape of "a probe measuring itself"
this project has met.

## Parity, before and after

```
chapter              before   after   documented
admin/clients          18      23        35
admin/users            18      20        34
admin/realms-admin     29      33        45

total                 440     451       541
```

+11, exactly the eleven operations, with no other chapter moved. Thirteen cases
were added: the eleven operations plus two that pin behaviours the eleven do not
reach on their own - `admin/clients/session-count-empty`, which is the
none-exists answer, and `admin/realms-admin/delete-session-unknown`, which is
the misspelled 404.

## Notes for the next cut

- **`TestNoVolatileMaskCoversACapturedValue` earned its keep.** Both session
  listings were first written with `Volatile: "*/id"`, and the ratchet refused
  it: the fixture captures `session_state` from its own grant, so the row's id
  is `{{session_id}}` already and the mask asserted nothing. The goldens now say
  **which** session the row is, not that there is one.
- **The fixtures run `logout-all` before their grant**, and that is what makes
  them order-independent. The recorder shares one container and a fixture named
  by several cases runs its steps several times; a create answers 409 and
  changes nothing, but a password grant mints another session every time.
  Clearing the realm first is what makes "exactly one session" true on the
  eighth run as well as the first. **Any future fixture that logs in needs the
  same sweep**, and nothing in the harness enforces it - a count that drifts
  with catalogue position is the failure F40 already describes.
- **`ipAddress` is served empty and no golden can see it.** The recorded value
  is the container's view of the recorder's address and the served one is
  whatever the process has, so the field is masked on both goldens either way.
  The gap is real and the suite is structurally blind to it - F123's shape - and
  it closes when `internal/oidc`'s `startSession` can write the address, which
  is also when a column for it stops being a claim that is not true.
- **`max`'s documented default of 100 is unmeasured.** Separating "no bound"
  from "100" needs more than a hundred sessions. Gloak applies no default, which
  agrees with every measured input and is a guess on the hundred-and-first.
