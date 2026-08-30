# P7 cut A: the device authorization grant, and CIBA's refusals

Branch `feat/p7-device-grant`. Measured against a live Keycloak 26.7.1 on
2026-08-30, container `kc-device` on port 8101, checked to be answering on
127.0.0.1 before any probe was trusted.

The plan, with the "refusals or the flow" argument, is
`docs/superpowers/plans/2026-08-30-p7-device-grant.md`. The short answer: **the
flow for the device grant, refusals for CIBA** - and the second half is a
measurement rather than a preference, because CIBA's happy path is a 503 on a
default 26.7.1.

## 1. Measurements

### 1.1 `POST /realms/{realm}/protocol/openid-connect/auth/device`

The 200, on a client carrying `oauth2.device.authorization.grant.enabled`:

```
HTTP/1.1 200 OK
Cache-Control: no-store, must-revalidate, max-age=0
Content-Type: application/json
the five security headers, no Pragma
{"device_code":"…43 chars…","user_code":"DDNT-BYDP",
 "verification_uri":"{issuer}/realms/master/device",
 "verification_uri_complete":"{issuer}/realms/master/device?user_code=DDNT-BYDP",
 "expires_in":600,"interval":5}
```

Six keys in that order.

- `device_code` is 43 characters of base64url over sixty mints: 32 bytes,
  unpadded, and the alphabet came out as exactly base64url's 64 symbols.
- `user_code` is `XXXX-XXXX`, nine characters, **upper-case ASCII letters
  only**. Sixty mints produced 480 code characters, every one of the 26 letters
  appeared and **no digit ever did**. That rules out the obvious guess of an
  alphanumeric alphabet: with 36 symbols the chance of 480 draws avoiding all
  ten digits is about e^-156.
- **The success carries `Cache-Control` and every rejection carries none**, and
  no response carries `Pragma`. That is the opposite way round from the token
  endpoint beside it, which sends `no-store` and `Pragma: no-cache` on
  everything including its rejections.

Five refusals, in the measured order, each adjacency driven by a request wrong
in two ways at once:

| # | Request | Status | Body |
|---|---|---|---|
| 1 | unknown realm | 404 | `{"error":"Realm does not exist"}` |
| 2 | unknown, absent, empty or **disabled** `client_id` | 401 | `invalid_client` / `Invalid client or Invalid client credentials` |
| 3 | confidential client, no secret or a wrong one | 401 | `unauthorized_client` / same description |
| 4 | any **form** key sent twice | 400 | `invalid_grant` / `duplicated parameter` |
| 5 | the device grant disabled on the client | 400 | `unauthorized_client` / `Client is not allowed to initiate OAuth 2.0 Device Authorization Grant. The flow is disabled for the client.` |

Two things this endpoint does **not** check: `scope` is not validated at all
(`scope=bogus-scope` and an empty `scope=` both answer 200, where `GET /auth`
refuses both), and a duplicated key on the **query** is ignored.

### 1.2 The `urn:ietf:params:oauth:grant-type:device_code` grant

Every response carries `Cache-Control: no-store` and `Pragma: no-cache`.

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | `grant_type` absent / unknown | 400 | the endpoint's existing two |
| 2 | client authentication | 401 | as elsewhere |
| 3 | a repeated **form** key | 400 | `invalid_request` / `duplicated parameter` |
| 4 | the device grant disabled | 400 | `invalid_grant` / `Client not allowed OAuth 2.0 Device Authorization Grant` |
| 5 | `device_code` absent | 400 | `invalid_request` / `Missing parameter: device_code` |
| 6 | `device_code` empty, unknown or already spent | 400 | `invalid_grant` / `Device code not valid` |
| 7 | the code has expired | 400 | `expired_token` / `Device code is expired` |
| 8 | another client's code | 400 | `invalid_grant` / `unauthorized client` |
| 9 | polled again inside `interval` | 400 | `slow_down` / `Slow down` |
| 10 | the user denied it | 400 | `access_denied` / `The end user denied the authorization request` |
| 11 | nobody has answered yet | 400 | `authorization_pending` / `The authorization request is still pending` |
| 12 | approved | 200 | the ordinary nine keys, `scope: openid email profile` |

Six of those adjacencies are not where they look:

- **Row 4 and row 5 of section 1.1 are the same condition with a different code
  and a different sentence.** One shared constant is the obvious saving and gets
  both rejections wrong.
- **`duplicated parameter` is `invalid_grant` at the device endpoint and
  `invalid_request` at the token endpoint.** Same description, same status, two
  codes, two endpoints in one flow, measured side by side.
- **The client mismatch (8) precedes the poll interval (9) and does not stamp
  the poll clock.** Three wrong-client polls in a row, then the right client
  immediately, answered `authorization_pending` rather than `slow_down`.
- **Expiry (7) precedes the poll interval (9).** An expired code polled twice in
  a row inside a ten-second interval answered `expired_token` both times, where
  a pending code answers `slow_down` on the second.
- **`slow_down` does not re-stamp the clock.** Polls at t=0, t=3 and t=6 with
  `interval` 5 answered pending, `slow_down`, pending. The naive implementation
  stamps every poll and answers `slow_down` at t=6.
- **A denied code is not consumed and answers `access_denied` for ever**, and
  the poll interval still runs in front of it: the poll immediately after a
  denial answered `slow_down`, and two later ones answered `access_denied`
  again.

Also: **a `device_code` is single-use on success** - the poll after a successful
exchange answers `Device code not valid`, so a spent code is indistinguishable
from one that never existed. And **an unknown `device_code` is not
rate-limited**: two bogus polls back to back both answered `Device code not
valid`, because the clock belongs to the code and a code that does not exist
has none.

### 1.3 `expired_token` is a window, not a state

This is the finding nobody had, and both obvious implementations get it wrong.

An expired device code answers `expired_token` for some seconds and then stops
being found at all, after which the answer collapses onto `Device code not
valid` - the one a code that never existed gets. Measured at three client
lifespans, and the lifespan-1 boundary reproduced exactly across two runs at
one-second granularity:

| `oauth2.device.code.lifespan` | last `expired_token` | first `Device code not valid` |
|---|---|---|
| 1 | mint+16s (expiry+15s) | mint+17s (expiry+16s) |
| 5 | mint+18s (expiry+13s) | mint+21s (expiry+16s) |
| 20 | mint+30s (expiry+10s) | mint+35s (expiry+15s) |

Fifteen seconds is inside all three brackets and no formula fits them tighter
than that. **No mechanism for the number has been found**, in Keycloak or
anywhere else, so it is a measured approximation rather than an understanding -
the same shape as F91's `7n/4`. Gloak uses `deviceCodeGrace = 15 * time.Second`
and says so in the constant's comment. Filed as a follow-up.

### 1.4 Two client attributes nobody had written down

| Attribute | On | Effect |
|---|---|---|
| `oauth2.device.authorization.grant.enabled` | client | opens the grant at both endpoints |
| `oauth2.device.code.lifespan` | client | `expires_in`, overriding the realm |
| `oauth2.device.polling.interval` | client | `interval`, overriding the realm |
| `oauth2DeviceCodeLifespan` | realm | default `expires_in`, 600 on master |
| `oauth2DevicePollingInterval` | realm | default `interval`, 5 on master |

`oauth2DeviceCodeLifespan` - the realm field's own spelling - does nothing as a
client attribute, measured, because it is the obvious wrong guess.

The two client overrides are what make `oidc/device/poll-expired-token` and
`oidc/device/poll-slow-down` recordable at all. Without them, reaching an
expired device code means a `PUT /admin/realms/master`, which would move
`oauth2DeviceCodeLifespan` for every case recorded after it in a
shared-container run - and, per section 2 below, would silently add two keys to
master's `attributes`.

### 1.5 CIBA

`POST /realms/{realm}/protocol/openid-connect/ext/ciba/auth`, in the measured
order:

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | the realm | 404 | `{"error":"Realm does not exist"}` |
| 2 | client authentication | 401 | as elsewhere |
| 3 | the CIBA grant disabled | **401** | `invalid_grant` / `Client not allowed OIDC CIBA Grant` |
| 4 | `login_hint` **absent** | 400 | `invalid_request` / `missing parameter : login_hint` |
| 5 | `scope` **absent** | 400 | `invalid_request` / `missing parameter : scope` |
| 6 | `login_hint` resolves to no user | 400 | `invalid_request` / `invalid_user` |
| 7 | `scope` invalid | 400 | `invalid_scope` / `Invalid scopes: <raw>` |
| 8 | everything valid | **503** | `server_error` / `Failed to send authentication request` |

- **`login_hint` is checked before `scope`.** A request missing both is told
  about the hint. The obvious order is the one the parameters are listed in and
  it is the wrong one - this cut shipped it wrong on the first attempt and every
  catalogue case passed, because each of them breaks exactly one parameter.
- **Presence and value are two steps with two answers, and they interleave.** An
  empty `scope=` is not "missing parameter": it passes step 5 and fails step 7
  with `Invalid scopes: ` and its trailing space. An empty `login_hint=` passes
  step 4 and fails step 6, giving the identical `invalid_user` a hint naming
  nobody gets. And step 6 sits *between* them, so an empty scope with an
  unresolvable hint answers about the hint. A single `Get(...) == ""` per
  parameter gets all four wrong.
- **`missing parameter : scope` and `missing parameter : login_hint`** are lower
  case with a space on **both** sides of the colon, where every other
  missing-parameter description on the protocol side is `Missing parameter: x` -
  including the CIBA grant's own `Missing parameter: auth_req_id` one endpoint
  away.
- **There is no duplicated-parameter check on this endpoint at all.** `zz` twice
  and `login_hint` twice both reach the 503 on an otherwise valid request.
- `scope=profile` with no `openid` reaches the 503, so `openid` is not required;
  validity is membership in the client's scope lists, which is `/auth`'s own
  predicate.

The token endpoint's `urn:openid:params:grant-type:ciba`:

| Condition | Status | Body |
|---|---|---|
| the CIBA grant disabled | **400** | `invalid_grant` / `Client not allowed OIDC CIBA Grant` |
| `auth_req_id` absent | 400 | `invalid_request` / `Missing parameter: auth_req_id` |
| `auth_req_id` empty or unparseable | 400 | `invalid_grant` / `Invalid Auth Req ID` |

**One description, two statuses**, 401 at the backchannel endpoint and 400 here.
That is the mirror image of the device grant's pair, which shares neither the
code nor the sentence. Two families, two different ways of disagreeing, and one
shared constant is right for one and wrong for the other.

### 1.6 Why CIBA cannot complete, and what that means for two cases

A client with `oidc.ciba.grant.enabled` sending a well-formed request answers
503, and the container log says why:

```
java.lang.RuntimeException: Authentication Channel Request URI not set properly.
  at ...ciba.channel.HttpAuthenticationChannelProvider.checkAuthenticationChannel
```

The default `ciba-http-auth-channel` provider needs
`spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri`,
an external HTTP endpoint `start-dev` does not configure. So a default container
mints **no `auth_req_id` at all**, and `oidc/ciba/poll-pending` and
`oidc/ciba/poll-complete` are not unimplemented - they are **unmeasurable in
this project's container regime**. Their `Reason` now says so.

That also makes the 503 a contract rather than a stub, the same shape as
`client-types` answering 501 and `.../client-secret/rotated` answering a
permanent 404. `oidc/ciba/channel-unavailable` records it.

### 1.7 The device endpoint's other verbs

For follow-up F31's file. **`GET` is not a wrong method here** - it serves the
device verification page, `data-page-id="login-login-oauth2-device-verify-user-code"`,
200, `text/html;charset=utf-8`. `HEAD` is 200 with that page's headers.
`PUT`, `DELETE` and `PATCH` answer a real 405 with
`{"error":"HTTP 405 Method Not Allowed"}`. `OPTIONS` answers 200 with **no
`Allow` header**, which is `/logout`'s answer and not `/auth`'s.

Nothing was changed on the strength of any of it. Gloak registers `POST` alone,
so `GET` falls through `WithKeycloakFallbacks` to a 404 - a real divergence, and
it belongs with the verification page in cut B.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for folding in.

- **One condition, two endpoints, and the device grant and CIBA disagree in
  opposite ways.** "This client may not use this grant" is
  `unauthorized_client` / `Client is not allowed to initiate OAuth 2.0 Device
  Authorization Grant. The flow is disabled for the client.` at
  `/auth/device` and `invalid_grant` / `Client not allowed OAuth 2.0 Device
  Authorization Grant` at the token endpoint - a different code and a different
  sentence. CIBA's pair share the sentence *and* the code and differ on the
  **status**: 401 at `ext/ciba/auth`, 400 at the token endpoint. So there are
  three constants across two files and not two, and the saving that collapses
  either pair is wrong in a different way each time.

- **`duplicated parameter` now has two codes and three endpoints that do not
  agree about whether it exists.** `/auth` and the token endpoint answer
  `invalid_request`; `/auth/device` answers **`invalid_grant`** for the
  identical description and status; `ext/ciba/auth` does not check at all - `zz`
  twice and `login_hint` twice both reach its 503. Five endpoints have now been
  measured for this one rule and they split three ways.

- **`expired_token` is a window, not a state.** A device code past its expiry
  answers `expired_token` for roughly fifteen seconds and then stops being found
  at all, after which it answers `Device code not valid` - the same answer a code
  that never existed gets. Measured at three client lifespans; fifteen seconds is
  inside all three brackets and **no mechanism for the number has been found**.
  Both obvious implementations are wrong: sweeping at expiry loses the
  `expired_token` answer the catalogue records, and never sweeping answers
  `expired_token` for ever.

- **The device grant's poll clock is stamped by some answers and not others, and
  which is not guessable.** A wrong-client poll and a `slow_down` both leave it
  alone; `authorization_pending` and `access_denied` both move it; an expired
  code never reaches it. So polls at t=0, t=3 and t=6 with `interval` 5 answer
  pending, `slow_down`, pending - and an implementation that stamps every poll
  answers `slow_down` at t=6 while passing every single-request golden in the
  catalogue.

- **A denied device code is not consumed and a redeemed one is.** A denial
  answers `access_denied` on every later poll; a success makes the next poll
  answer `Device code not valid`. That is the only thing distinguishing the two
  terminal states from outside.

- **The device authorization endpoint's success carries a `Cache-Control` and
  every one of its rejections carries none, and it sends no `Pragma` at all.**
  The token endpoint one path away sends `no-store` and `Pragma: no-cache` on
  every response including every rejection. Neither absence is a default.

- **The device endpoint does not validate `scope`.** `scope=bogus-scope` and an
  empty `scope=` both answer 200, where `GET /auth` refuses both with
  `Invalid scopes: <raw>`. CIBA's endpoint *does* validate it, with `/auth`'s own
  predicate and `/auth`'s raw echo. Three endpoints in one protocol, two rules.

- **CIBA checks `login_hint` before `scope`, and checks presence and value in
  four separate places that interleave.** A request missing both is told about
  the hint. An empty `scope=` is `Invalid scopes: ` and not "missing parameter";
  an empty `login_hint=` is `invalid_user`, the same answer a hint naming nobody
  gets. And the hint's *lookup* sits between the scope's presence check and the
  scope's validity check, so an empty scope with an unresolvable hint answers
  about the hint. One `Get(...) == ""` per parameter gets all four wrong, and it
  is what this cut shipped first - every catalogue case passed, because each of
  them breaks exactly one parameter.

- **CIBA cannot complete on a default 26.7.1 and its 503 is the contract.** A
  fully valid backchannel authentication request answers `server_error` /
  `Failed to send authentication request`, because the default
  `ciba-http-auth-channel` provider needs an external endpoint `start-dev` does
  not configure. So no default container mints an `auth_req_id`, and the two
  CIBA poll cases are **unmeasurable** rather than unimplemented.

## 3. Lines in AGENTS.md and the observed document these measurements contradict

Six, and one of them is about surface Gloak already ships.

1. **AGENTS.md, the security-headers bullet: "The five security headers have
   three exceptions, not one."** There is a fourth, and unlike the other three it
   is decided by the **verb**. **An `OPTIONS` 200 sends four of the five,
   omitting `X-Frame-Options`** - measured on `/auth/device`, `/auth`,
   `/logout` and `/token`, all four on one container, all four the same. Three
   of those four are surface this project has served since P1 and P3. The
   bullet's three exceptions are a path matching no route, `userinfo`'s
   rejections and a 204 without an `application/*` `Content-Type`; none covers
   this, and the 204 one is the closest and is about a request header rather
   than a method.
   Not changed on the branch: Gloak answers `OPTIONS` through
   `WithKeycloakFallbacks` and the whole 404-versus-405 question is F31's. The
   same sweep says something for F31's file too - **`/auth` is the only one of
   the four whose `OPTIONS` carries an `Allow` header**; `/logout`, `/token` and
   `/auth/device` send none.

2. **F86: "`onrtac:`, `onrtro:`, `onrtrt:`, `onltac:` - measured on all four
   grants."** There are five. The device grant's access token carries
   **`onrtdg:`**, measured on a completed device login. "All four grants" was
   also a count of the grants that existed when it was written.

3. **The observed document, section on `POST /admin/realms`: "`master`'s
   `attributes` has six keys and a created realm's has eight: a created realm
   carries `oauth2DeviceCodeLifespan` and `oauth2DevicePollingInterval` as string
   attributes as well as as top-level integers."** The two keys are not a
   property of *creation*. A single `PUT /admin/realms/master` naming either of
   them adds **both** to master's `attributes`, taking it from six keys to the
   same eight - measured, with the resulting key set byte-identical to the
   created realm's recorded one. So the property is "written through the API",
   and "master has six" is true of a *pristine* master only. That matters to
   anybody who reaches for the realm knob to shorten a device code: it moves a
   104-key representation that admin goldens read.
   It also touches work that landed on main the same day.
   `docs/superpowers/handover/harness-claims.md` restates the claim as
   "`master`: the same, minus the two `oauth2Device*` keys" and computes
   `KeyOrder`'s buckets for both sets. Both computations stand; what moves is
   which of them describes master, and the answer is "whichever was last written
   to it". This is not a correction of that handover - it is measured on a realm
   that handover would have had no reason to touch.

4. **Five catalogue `Reason` strings said "the token endpoint is not
   implemented"**, false since P1. Found here independently of
   `TestNoReasonClaimsAServedEndpointIsUnserved`, which landed on main hours
   later and found the same five; this branch merged that guard and **fixed all
   five and emptied `staleReasonsOwnedElsewhere`**, which is what the guard's
   own doc comment asks the owning stream to do.
   Two of the five did **not** take the replacement text the hand-off suggested.
   "the `device_code` grant is not implemented" and "the CIBA grant is not
   implemented" were already stale when they were written, because both grants
   landed the same day; what is actually missing is the consent pages for one
   and an authentication channel for the other. A hand-off's suggested text is a
   hand-off, not a measurement, and the note is now on the emptied map.
   All five also named `admin-cli`, which has both grants disabled and so could
   never have reached the body two of them claimed to measure.

5. **AGENTS.md: "A repeated parameter is an error at `/auth` and at neither of
   its neighbours … `/auth` is the odd one of the three, not the rule."** True
   as stated about the browser trio, and no longer a fair summary: five
   endpoints have now been measured and they split three ways - `/auth`,
   `/auth/device` and the token endpoint check it (with two different codes),
   `/logout`, `/login-actions/authenticate` and `ext/ciba/auth` do not.

6. **The `parkedGoldens` entry for `oidc/ciba/authentication-request` called it
   "the one record of CIBA answering 401 where the device endpoint beside it
   answers 400".** Correct, and it is now a compared contract rather than a
   parked measurement, so the entry is gone rather than moved. Same for the
   device one, whose *request* moved as well: it measured the refusal on
   `admin-cli`, which is now `oidc/device/grant-disabled`'s. Seven parked
   goldens are five.

7. **`docs/superpowers/handover/harness-claims.md`, merged mid-flight, lists
   "the five device cases, the three CIBA cases" as checked and accurate, and
   says Gloak "answers `/auth/device`, `/ext/ciba/auth` … with the
   unmatched-path 404".** Both were true when written and both stop being true
   with this branch. Recorded because the brief asks for every claim re-checked
   against a mid-flight merge, and this is the one that moved.

## 4. Follow-up dispositions

**Closed on this branch**

- Nothing in the numbered list. The device grant had no follow-up of its own;
  it had five catalogue cases and a parked golden.

**Extended rather than filed anew**

- **F75, the in-memory authentication session and authorization code.** The
  device store is a third such object, in memory for the same reason and at the
  same cost - Keycloak keeps device codes in Infinispan, not in its schema, and
  Gloak stays single-process. `internal/store` belongs to another agent this
  session, so it was built in memory deliberately; `internal/oidc/devicestore.go`
  says so at the top.

**Corrected**

- **F86** is five prefixes, not four. See section 3.2.

**New, and each reproduced rather than theorised**

- **The `expired_token` grace window has no mechanism.** Fifteen seconds is
  bracketed by three lifespans and nothing explains it. Same shape as F91.
- **`Request.Form` cannot express a repeated form key.** F48 gave the query
  `RawQuery` and left the body alone. `oidc/device/duplicated-parameter` works
  around it with `Body` plus an explicit `Content-Type`, which works only
  because `buildRequest` uses `Body` when `Form` is empty and sets the form
  `Content-Type` only when it is not - two behaviours that have to stay
  coupled. A `RawForm` would be the honest fix.
- **`GET /realms/{realm}/protocol/openid-connect/auth/device` is a page Gloak
  answers 404.** With the `OAUTH_GRANT` consent page, `POST
  /login-actions/consent` and `/realms/{realm}/device/status`, that is cut B and
  the whole of what stands between this cut and `access_denied` and a device
  grant a user can actually complete.
- **The `user_code` alphabet is unbiased by rejection sampling and nothing
  tests it.** 256 is not a multiple of 26, so a plain modulo would favour the
  first four letters; the draw rejects the biased tail. That is a statistical
  property no unit test in this repository's style can catch, and it is written
  down rather than tested.
- **The `deviceCodeGrace` *value* is not pinned by any test.** The tests use the
  constant symbolically, so changing 15s to 60s fails nothing. That is honest -
  the measurement brackets the number rather than fixing it - but it means the
  constant is a comment's worth of evidence and not a test's.

## 5. Parity, before and after

Measured with `TestCoverage` on the branch point (`db9f4f3`) and on the branch
after merging `500248d`:

```
                                        before            after
oidc/device                              0 of 5          11 of 12
oidc/ciba                                0 of 3          10 of 12
total                             242 of 500        263 of 516
```

+21 behaviours served, +16 denominator. Three cases stay `Pending`, all three
for reasons that are now measurements rather than to-do notes:
`oidc/device/poll-access-denied` needs the browser approval pages;
`oidc/ciba/poll-pending` and `oidc/ciba/poll-complete` need an authentication
channel a default 26.7.1 does not have.

Five cases outside these chapters had their `Reason` corrected without changing
status: `oidc/token/device-code-grant`, `ciba-grant`, `token-exchange`,
`jwt-authorization-grant` and `dpop-bound-token`. None moves a number.

**`internal/conformance/catalog_test.go` is edited on this branch**, which is
outside the files this cut owns. The edit is emptying
`staleReasonsOwnedElsewhere`, which is exactly what that map's own doc comment
asks the owning stream to do once it has corrected the five Reasons - and the
guard fails if an entry stops being stale and stays listed, so leaving it would
have been red. Nothing else in that file is touched.

## 6. Mutation testing

Twenty mutations, one per claim, each run against the single named test and
reverted from a copy rather than with `git checkout` - the whole set re-run
after merging `main`. Nineteen were killed on the first run.

**One survived, and it is a finding about the test.**
`TestAnExpiredCodeStopsBeingFound` passed with `deviceCodeGrace` removed
entirely. It expired a code, asserted `expired_token`, then pushed the expiry
past the window, swept and asserted `Device code not valid` - and **both halves
held for a reason that had nothing to do with the window**, because a poll is a
read and reads never sweep. Pinning the window needs a sweep run *inside* it.
The test now drives the sweep three times, at just-expired, one second inside
the far edge and one second past it; the mutation is killed. **Fixed on the
branch**, and reported here because a survivor is a finding about the test
first.

The sharper version of the same question - "what do these tests not pin?" -
found two more things, both in section 4: the grace window's *number* and the
`user_code` alphabet's lack of bias. Neither is testable in this repository's
style and both are written down instead.

## 7. Two things that would have gone wrong quietly

- **The catalogue's five device cases would have been served as refusals.**
  They named `admin-cli` on the `bootstrap` fixture, and the grant is off on
  every client of a default 26.7.1, so serving them "correctly" costs about
  forty lines and leaves the endpoint unable to do the one thing it exists for.
  Measuring the two endpoints found twenty-two distinct answers against the five
  the catalogue named.
- **CIBA's parameter order passed every case in the catalogue while being
  wrong.** Each case breaks one parameter; only a request missing both says
  which check wins. The catalogue cannot find an adjacency, by construction, and
  `internal/oidc`'s own tests are where every one of them lives.
