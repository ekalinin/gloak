# The session family

Date: 2026-09-03
Branch: `feat/session-family`
Reference: Keycloak 26.7.1, `docker run … -p 8168:8080 … start-dev`, container `kc-sess`

Eleven operations across three tags, counted from the vendored description
rather than from the brief. The description holds **twelve** operations whose
path, `operationId` or summary names a session, a logout or a revocation; one of
them, `POST /admin/realms/{realm}/users/{user-id}/logout`, is already in
`adminCases`. The remaining eleven are this cut, and they are exactly the eleven
the brief lists.

```
Clients        GET  .../clients/{uuid}/session-count
               GET  .../clients/{uuid}/user-sessions
               GET  .../clients/{uuid}/offline-session-count
               GET  .../clients/{uuid}/offline-sessions
               POST .../clients/{uuid}/push-revocation
Users          GET  .../users/{id}/sessions
               GET  .../users/{id}/offline-sessions/{clientUuid}
Realms Admin   GET    .../client-session-stats
               DELETE .../sessions/{session}
               POST   .../logout-all
               POST   .../push-revocation
```

## What creates a session, what creates an offline one, and what the eleven answer when neither exists

This is the cut's real question, and all three parts are measured.

### What creates a session

On Keycloak: any grant that mints a refresh token. A password grant creates one;
so does the browser login; so does `client_credentials` for a service account.
**The recorder's own admin token creates one**, which is why the empty state
cannot be measured on `master` at all - the first `admin-cli` password grant of
any probe run puts a session in it.

On Gloak the same three paths exist and are already built:
`startSession` (`internal/oidc/token.go:553`) for the direct grant and
`client_credentials`, `startSessionWithID` (`internal/oidc/loginactions.go:657`)
for the browser and device logins, and `attachClientSession`
(`internal/oidc/sso.go:439`) for a second client joining one that exists. Both
`user_session` and `client_session` are real tables, migration `0003_session.sql`,
in both drivers.

**A password grant in a realm created through `POST /admin/realms` needs a user
carrying an email, a firstName *and* a lastName**, and the same user in `master`
needs none of the three. Measured as a 2x6 matrix on 2026-09-03: six users in a
created realm differing only in which profile fields they carry, and the same six
in master as the control. Only `{email, firstName, lastName}` together grants in
the created realm; all six grant in master. Everything short of the full three
answers
`{"error":"invalid_grant","error_description":"Account is not fully set up"}`.
That is the fixture's first constraint and it cost an hour to find, because the
obvious fixture - realm, client, user, grant - fails with an error that names
neither the realm nor the profile.

### What creates an offline session

`scope=openid offline_access` on a real grant, and it is **not** a flavour of the
online session - it is a **second, disjoint** one:

```
after a plain password grant          session-count 1   offline-session-count 0
after an offline grant at the same client
                                      session-count 1   offline-session-count 1
after an offline grant and nothing else
                                      session-count 0   offline-session-count 1
```

The third row is the one that decides the model. An offline grant leaves **no**
online session behind: the two counts are over two sets, the session ids differ,
and `GET /users/{id}/sessions` never shows an offline session. The offline
grant's `refresh_expires_in` is `0`.

**Gloak cannot reach that state, and the reason is one line in a file this cut
does not own.** `grantedScope` (`internal/oidc/token.go:667`) drops every scope
it is given except `openid` and the two default ones, so a request asking for
`offline_access` is answered with a `ClientSession.Scope` of
`"openid profile email"` - not refused, just silently without it. There is no
offline session table, no model type and no repository method anywhere in the
tree.

### What the eleven answer when neither exists

Measured on a realm created through `POST /admin/realms` holding one client and
one user that has never logged in - which is the only way to see the empty state,
since master always holds the prober's own session.

```
GET  clients/{uuid}/session-count            200  {"count":0}
GET  clients/{uuid}/user-sessions            200  []
GET  clients/{uuid}/offline-session-count    200  {"count":0}
GET  clients/{uuid}/offline-sessions         200  []
POST clients/{uuid}/push-revocation          200  {}
GET  users/{id}/sessions                     200  []
GET  users/{id}/offline-sessions/{clientUuid} 200 []
GET  client-session-stats                    200  []
POST push-revocation                         200  {}
POST logout-all                              200  {}
DELETE sessions/{session}                    404  {"error":"Sesssion not found"}
```

**Ten of the eleven have a 200 empty answer and none of them is a 404.** The one
that is not is the only operation of the eleven that names a session in its path.
That is `attack-detection`'s shape again - a whole chapter whose reachable state
is the empty one - and it is why this cut can serve eight operations byte-exactly
without storing anything new.

`{}` is `GlobalRequestResult` with both its arrays empty: they are omitted rather
than emitted as `[]`.

## What was measured

All of it on 2026-09-03 against `kc-sess`, at socket level through
`http.client` - which, unlike `urllib`, adds no `Content-Type` a probe would then
measure.

### The session representation

Nine keys, one order, and the same nine for an online session and an offline one:

```json
{"id":"…","username":"…","userId":"…","ipAddress":"172.17.0.1",
 "start":1788546760000,"lastAccess":1788546760000,"rememberMe":false,
 "clients":{"<client uuid>":"<clientId>"},"transientUser":false}
```

- `start` and `lastAccess` are Unix **milliseconds truncated to the second** -
  every measured value ends in `000`. `lastAccess` moves on a refresh and `start`
  does not, measured three seconds apart.
- `clients` maps the client's **internal UUID** to its `clientId`.
- `ipAddress` is the address the login came from.
- `rememberMe` and `transientUser` were `false` on every measured session.
- It is **not** a Java map: `javamap.KeyOrder` over those nine keys gives
  `clients ipAddress start lastAccess transientUser id rememberMe userId username`,
  which is not what the wire says. It is a POJO, so a Go struct in declaration
  order is the right model.

### `client-session-stats` is a Java map, and `javamap.KeyOrder` places it twice

```json
[{"offline":"0","clientId":"gloak-probe-sy-app","active":"1","id":"e41a45d6-…"}]
```

Two things are true of it and both are checkable:

- **The four keys are `HashMap` order, and the counts are strings.** The
  description's schema says `additionalProperties: {"type":"string"}` - it is a
  `Map<String,String>` - and `javamap.KeyOrder(["offline","clientId","active","id"])`
  returns exactly `offline clientId active id`. Two independent sources agreeing,
  and the key set is constant, so the order is a constant too.
- **The array itself is a `HashMap` keyed on the client UUID.** Six clients with
  one session each came back `cc mm dd bb zz aa` from an insertion order of
  `aa bb cc dd zz mm`, and `javamap.KeyOrder` over those six UUIDs returns
  `cc mm dd bb zz aa` - exact. That is a fifteenth measured key set for that
  function.

It is also the one read of the eleven that sees something the other ten do not:
**a client with zero active sessions and one offline session still gets a row**,
`{"offline":"1","clientId":…,"active":"0"}`. Every other read partitions online
from offline; this one reports both counts side by side, and its row survives an
active count of zero. A client with neither gets no row at all.

The `clients` map inside a session representation is a `HashMap` too and
`javamap.KeyOrder` gets it **wrong**: the same six UUIDs came back `cc dd mm …`
where `KeyOrder` says `cc mm dd …`. `dd` and `mm` collide and chain in insertion
order, which is precisely the limit the package documents. With one client in a
session - which is every case this cut records - the question does not arise.

### The two paging rules, one family

`GET /clients/{uuid}/user-sessions` and `.../offline-sessions` declare `first`
and `max`. Measured over four sessions:

```
no bounds        4 rows
max=2            2 rows      either bound alone pages
first=1          3 rows
first=1&max=2    2 rows
first=-1&max=-1  4 rows      a negative bound means "no bound"
max=0            0 rows
first=abc        404 {"error":"HTTP 404 Not Found"}
```

Either bound alone pages, which is the group listing's rule and neither the role
listings' nor the user listing's. The rows come back **sorted by session id,
byte-ascending** - confirmed on a four-id set and a six-id set.

`GET /users/{id}/sessions` declares no parameters and **reads none**. Six
sessions, and `max=1`, `first=1`, `first=1&max=1`, `max=0`, `first=abc` and
`max=abc` all answered all six with a 200. `client-session-stats` behaves the
same way. So one family holds both answers to a malformed integer bound - a
generic 404 on the two client listings and a 200 with everything on the two
realm- and user-scoped ones - which is the identity-provider/component split
reproduced inside one chapter.

**The first reading of this was wrong and the probe was measuring itself.** A
single `?max=1` against a user holding one session answered one row and looked
like paging. Six sessions is what separates the readings.

### Four spellings of not-found, and one of them is a typo

```
GET  clients/{unknown}/session-count            404 {"error":"Could not find client"}
GET  clients/{unknown}/user-sessions            404 {"error":"Could not find client"}
GET  clients/{unknown}/offline-session-count    404 {"error":"Could not find client"}
GET  clients/{unknown}/offline-sessions         404 {"error":"Could not find client"}
POST clients/{unknown}/push-revocation          404 {"error":"Could not find client"}
GET  users/{unknown}/sessions                   404 {"error":"User not found"}
GET  users/{unknown}/offline-sessions/{client}  404 {"error":"User not found"}
GET  users/{user}/offline-sessions/{unknown}    404 {"error":"Client not found"}
DELETE sessions/{unknown}                       404 {"error":"Sesssion not found"}
```

- **`Sesssion not found` has three `s`s.** Keycloak's own typo, and it is the
  same body for an id that is not a UUID at all. It is a twenty-eighth spelling
  for AGENTS.md's list and the first one in it that is misspelled.
- **One missing client, two spellings, one route family apart.** The five
  `/clients/{uuid}/…` routes answer `Could not find client`; the `{clientUuid}`
  of `/users/{id}/offline-sessions/{clientUuid}` answers `Client not found`.
  Both spellings are already in AGENTS.md's list, at (1) and (2), so the chapter
  adds one entry to it and not three.
- **The user is resolved before the client** on the one route naming both: an
  unknown user with a real client answers about the user, and both unknown
  answers about the user too.

### The guards: three tags, four role families, and the tag predicts nothing

One master user per role, holding exactly that role on the target realm's own
admin client, plus a caller holding none.

```
                                        view-  manage- view- manage- view- manage-
                                        clients clients users users   realm realm  none
GET  clients/{uuid}/session-count         200    200    403   403     403   403    403
GET  clients/{uuid}/user-sessions         200    200    403   403     403   403    403
GET  clients/{uuid}/offline-session-count 200    200    403   403     403   403    403
GET  clients/{uuid}/offline-sessions      200    200    403   403     403   403    403
POST clients/{uuid}/push-revocation       403    200    403   403     403   403    403
GET  users/{id}/sessions                  403    403    200   200     403   403    403
GET  users/{id}/offline-sessions/{cu}     403    403    200   200     403   403    403
GET  client-session-stats                 403    403    403   403     200   200    403
POST push-revocation                      403    403    403   403     403   200    403
POST logout-all                           403    403    403   200     403   403    403
DELETE sessions/{session}                 403    403    403   404     403   403    403
```

`query-clients` and `query-users` open nothing - not even the coarse gate that
lets them see a 404 elsewhere.

**The `Realms Admin` tag's four operations take three different guards.**
`client-session-stats` is the realm read pair, `push-revocation` is
`manage-realm` alone, and `logout-all` and `DELETE /sessions/{session}` are
`manage-users` alone. That is the third time the description's tag has failed to
predict the guard, and the first time one tag has answered three ways at once.
`manage-users` getting a 404 rather than a 403 on the delete is what says the
role is checked before the session is resolved.

### `isOffline` partitions the id space, and a malformed boolean is not a malformed integer

`DELETE /sessions/{session}` takes an undocumented-in-the-brief `isOffline`
query parameter, default `false`.

```
DELETE sessions/{online id}                    204
DELETE sessions/{same id again}                404 Sesssion not found
DELETE sessions/{offline id}                   404 Sesssion not found
DELETE sessions/{offline id}?isOffline=true    204
DELETE sessions/{online id}?isOffline=true     404 Sesssion not found
DELETE sessions/{online id}?isOffline=bogus    204
```

So the parameter selects **which of two disjoint id spaces** the path segment is
looked up in, and an id from the wrong one is as absent as one that never
existed. `isOffline=bogus` behaves as `false` - it is parsed leniently and
ignored when it does not parse - where `first=abc` on the sibling listing one
path segment away is a 404. One family, one malformed value, two answers,
decided by the type of the parameter.

### The two logouts reach different sets

```
                              online   offline
after one grant of each          1         1
POST /logout-all                 0         0
POST /users/{id}/logout          0         1
```

**`logout-all` removes offline sessions and `POST /users/{id}/logout` does not.**
Measured twice on one realm with the state rebuilt in between.

`logout-all` also **stamps the realm's `notBefore`** with the second it happened,
and leaves every user's and every client's alone - which is the realm-level twin
of the user logout's stamp AGENTS.md already records. Neither push-revocation
stamps anything: measured on three fresh realms, one per write, reading the realm
and the client before and after.

### push-revocation really calls out, and logout-all reports success without checking

With a container on the same bridge answering 204, and an unroutable address as
the control:

```
POST clients/{good}/push-revocation  {"successRequests":["http://172.17.0.5:9977/adm"]}
POST clients/{bad}/push-revocation   {"failedRequests":["http://172.17.0.99:9/nowhere"]}
POST push-revocation (one of each)   {"successRequests":[good],"failedRequests":[bad]}
POST logout-all                      {"successRequests":[bad, good]}
```

**`logout-all` reports the unroutable client as a success**, with a session at it
and without one, on both of two runs. `push-revocation` on the same client with
the same URL reports it a failure. Two neighbouring endpoints, one client, one
address, opposite verdicts - Keycloak's own defect, and the reason `logout-all`
is implementable here with no outbound call at all.

The first run of this measurement had **no control** and reported
`failedRequests` for push-revocation and `successRequests` for logout-all against
a host listener the container could never reach, which looked like the same
finding and was not evidence of anything. A probe with no reachable arm cannot
tell "the call failed" from "no call was made".

What actually leaves the server, captured off the socket:

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
path, different claim set, different action, `text/plain` rather than a
`logout_token` form key, and no `sid`. It is the legacy adapter push, a second
outbound mechanism beside the OIDC back-channel one.

That does **not** contradict the observed document's "POST /logout-all … made
zero calls". That line is about the OIDC back-channel notification, and it is
still right: `logout-all` fires no `logout_token`. It fires a `k_logout`, which
that measurement was not looking for.

### Headers

```
                                   status  Content-Type                     Cache-Control
the seven reads                    200     application/json;charset=UTF-8   no-cache
the three 200 writes               200     application/json;charset=UTF-8   (none)
DELETE sessions/{session}          204     (none)                           (none)
DELETE sessions/{unknown}          404     application/json                 (none)
```

Every 200 and the 404 carry all five security headers. The 204 carries
`X-Frame-Options` only when the request declared `application/json` - the third
confirmation of that rule on a delete. Nothing here contradicts the charset rule,
the security-header rule or the "`Cache-Control` is pinned per endpoint" rule;
the seven reads and the three writes disagreeing about `Cache-Control` is one
more instance of it rather than a new axis.

## The design

### `internal/store`: F130 is live, and this is the cut that stops routing around it

F130 says `SessionRepo` cannot list a realm's sessions and that the third cut to
meet it should add the methods rather than route again. It is **not stale**: the
interface has `CreateUserSession`, `UserSessionByID`, `TouchUserSession`,
`DeleteUserSession`, `DeleteUserSessions`, `CreateClientSession` and
`ClientSession`, and nothing that lists. `channelLogoutTargets` still walks
`ListByRealm` asking `ClientSession` per candidate, and says so in its own doc
comment.

Four methods, all with a caller in this cut:

```go
ListUserSessionsByRealm(ctx, realmID) ([]*model.UserSession, error)
ListUserSessionsByUser(ctx, realmID, userID) ([]*model.UserSession, error)
ListUserSessionsByClient(ctx, realmID, clientID string) ([]*model.UserSession, error)
ListClientSessions(ctx, userSessionID string) ([]*model.ClientSession, error)
```

All four sort by session id ascending, which is measured. `first`/`max` are
applied in `internal/admin` rather than in SQL: two of the four listings ignore
them entirely and a repository that took bounds would have to be told to ignore
them, which is a worse place for that fact than the handler that measured it.

`ListUserSessionsByClient` needs the join through `client_session`;
`ListClientSessions` is what serves the `clients` map, and it is the method
`channelLogoutTargets` has been working around. Pointing that function at it is a
one-line change in `internal/oidc`, which this cut does not own - so the method
lands with its own caller and F130's other half is left for the cut that owns
that file.

### There is no migration `0029`

The brief reserved the slot. Nothing needs it, and F157 is why the fields that
would have wanted one do not get one.

Everything the eleven read is already stored: `user_session` carries the id, the
realm, the user, the username, `started_at` and `last_refresh`; `client_session`
carries the pair that makes the `clients` map. What is **not** stored is
`ipAddress`, `rememberMe` and the whole offline side - and every one of those has
its only possible writer inside `internal/oidc`, which this cut may not touch. A
column with no writer is a claim about the model that is not true, so none is
added.

That is the cut's largest single decision and it is F157's rule applied verbatim.

### Offline sessions are served from the empty set, and that is exact

Four of the eleven read the offline side, and Gloak has no offline session and no
way to make one:

```
GET  clients/{uuid}/offline-session-count      {"count":0}   always
GET  clients/{uuid}/offline-sessions           []            always
GET  users/{id}/offline-sessions/{clientUuid}  []            always
GET  client-session-stats  → the "offline" column            "0" always
DELETE sessions/{sid}?isOffline=true           404           always
```

Every one of those is **byte-exact for every state Gloak can reach**, because the
state that would make them differ is unreachable: `grantedScope` drops
`offline_access` before anything is stored. This is `attack-detection`'s
arrangement exactly - the whole reachable state of the offline half is the empty
one, the reads answer what Keycloak answers for it, and the table a reader would
expect is deliberately absent.

The guards, the 404s, the paging and the resolution order on those four are
measured and served in full. It is the rows that are empty, not the endpoint.

### push-revocation: the boundary decision, stated rather than half-built

`POST /push-revocation` and `POST /clients/{uuid}/push-revocation` answer `{}`
when no client in scope carries an `adminUrl`, which is every default install and
every state a conformance fixture reaches. That is what Gloak serves, exactly.

When a client does carry one, the body is a function of an outbound HTTP call
Gloak does not make. Building that in `internal/admin` would mean a second signed
JWT poster beside `notifyBackchannel` - and the measurement says it is not even
the same poster: different path, different claims, different content type. The
honest shape is one outbound poster shared by `notifyBackchannel` and both
push-revocations, and it belongs to a cut that owns `internal/oidc`. So this cut
serves the reachable state, and files the rest beside F122 rather than building
half of it here.

`logout-all` is the opposite case and it is served in full: its body reports
every client with an `adminUrl` as a success **whether or not it is reachable**,
so it is a pure function of the realm's clients and needs no call at all.

### `internal/admin`

One new file, `sessions.go`, plus routes and role sets in `router.go`.

- `userSessionRepresentation` - a struct with the nine fields in the measured
  order. `start`/`lastAccess` are truncated to the second on the way out, because
  Keycloak stores seconds and multiplies; `ipAddress` is `""` and `rememberMe`
  and `transientUser` are `false`, each with the reason written above it.
- `clientSessionStatsRow` - the four fields in `javamap.KeyOrder`'s order, with
  the counts as strings. A test asserts the field order **is** what `KeyOrder`
  returns, so the claim is computed rather than transcribed.
- The stats array is ordered by `javamap.KeyOrder` over the client UUIDs.
- `globalRequestResult` - `successRequests` then `failedRequests`, both
  `omitempty`, so the empty result marshals to `{}`.
- `logout-all` deletes every session in the realm and stamps the realm's
  `notBefore` through `decodeRealmSettings`/`marshalRealmSettings`, which is
  where the realm representation's 104 keys already live.
- `parseSessionBounds` - the client listings' rule: either bound alone pages, a
  negative bound is no bound, `max=0` is zero rows, a malformed integer is the
  generic 404. The two listings that ignore bounds do not call it.

### `internal/conformance`

Fixtures build a created realm - master cannot show an empty session listing and
its counts would move under every other case. A `sessionFixture` makes the realm,
a client, a fully-profiled user, and password-grants it; an `emptySessionFixture`
stops before the grant.

Goldens keep to **one** session at **one** client, which keeps every ordering
question out of them: a one-element array has no order, a one-key map has no key
order, and a mask over either would be inert.

Volatile: the session `id`, `start`, `lastAccess`, `ipAddress` and the `clients`
map's single key are per-run or per-environment and are masked. `userId` and the
`clients` map's value are captured by the fixture and rewritten, so they stay
asserted.

## Order of work

1. Commit the plan.
2. `internal/store`: the four methods, both drivers, `storetest` coverage.
   Postgres suite with `-v`.
3. `internal/admin`: `sessions.go`, routes, role sets, package tests.
4. `internal/conformance`: fixtures, eleven cases, record, verify.
5. Mutation pass, one mutation per claim, each confirming a **named** test.
6. Handover, PR, CI.

## What this cut does not do

- No offline session model. F157.
- No outbound revocation push. The boundary, stated above.
- No change to `channelLogoutTargets`, although `ListClientSessions` now exists
  for it. `internal/oidc` is not this cut's.
- `max`'s documented default of 100 on the two paged listings is **not
  measured** - separating "no bound" from "100" needs more than a hundred
  sessions. Gloak applies no default, which agrees with every measured input and
  is a guess on the hundred-and-first.
