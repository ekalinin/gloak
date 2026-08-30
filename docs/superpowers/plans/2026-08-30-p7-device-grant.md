# P7 cut A: the device authorization grant

Measured against a live Keycloak 26.7.1 on 2026-08-30, container `kc-device`
(`quay.io/keycloak/keycloak:26.7.1 start-dev`, port 8101, verified answering on
127.0.0.1 before any probe was trusted).

## Refusals or the flow, and why

**The flow, for the device grant. Refusals only for CIBA, and that is a
measurement rather than a preference.**

The brief offered two honest options and named the trap in the second one: the
five `oidc/device/*` cases in the catalogue all name `admin-cli` on the
`bootstrap` fixture, and the device grant is off on every client of a default
26.7.1, so as written they measure a refusal. Serving that refusal is about
forty lines and makes five cases assertable while leaving the endpoint unable
to do the one thing it exists for.

Three measurements decided it the other way.

1. **The grant-on half is reachable from the harness as it stands.** A client
   carrying `oauth2.device.authorization.grant.enabled` is one
   `POST /admin/realms/master/clients` away, which is exactly what
   `browserClientSteps` already does for the browser flow. No new fixture
   machinery.
2. **Two client-level attributes make the awkward cases recordable without
   touching the realm.** `oauth2.device.code.lifespan` sets `expires_in` per
   client (measured: `"1"` gives `expires_in: 1`) and
   `oauth2.device.polling.interval` sets `interval`. So `poll-expired-token`
   is a one-second lifespan plus the `Delay` the fixture type already has, and
   not a `PUT /admin/realms/master` that would pollute every later golden in a
   shared-container run. Neither attribute is written down anywhere in this
   repository.
3. **The catalogue's five cases are not the surface.** Measuring the two
   endpoints found **twenty-two** distinct answers, against the five the
   catalogue names and the "eight" a reader would have estimated. The brief
   warned that estimates scoped from case counts have been wrong twice this
   week; this one would have been wrong by a factor of four.

**CIBA is a refusal endpoint on a default 26.7.1 and cannot be anything else
here.** A client with `oidc.ciba.grant.enabled` sending a well-formed
authentication request answers **503**
`{"error":"server_error","error_description":"Failed to send authentication request"}`,
and the container log says why:

```
java.lang.RuntimeException: Authentication Channel Request URI not set properly.
  at org.keycloak.protocol.oidc.grants.ciba.channel.HttpAuthenticationChannelProvider.checkAuthenticationChannel
```

The default `ciba-http-auth-channel` provider needs
`spi-ciba-auth-channel-ciba-http-auth-channel-http-authentication-channel-uri`,
which `start-dev` does not set. So there is no `auth_req_id` to be had from a
default container, and `oidc/ciba/poll-pending` and `oidc/ciba/poll-complete`
are **not measurable in this project's container regime** - not merely
unimplemented. That is the same shape as `client-types`' 501 and
`client-secret/rotated`'s permanent 404: the refusal *is* the contract for a
default deployment. CIBA therefore ships as its five measured answers,
including the 503, and the two poll cases stay `Pending` with their reason
corrected from "not implemented" to "not reachable".

**The browser approval half is cut B, not this cut.** Approving a device code
needs five page endpoints - `GET`/`POST /realms/{realm}/device`, the
`OAUTH_GRANT` required action, `POST /login-actions/consent` and
`/realms/{realm}/device/status` - all of which serve keycloak.v2 Freemarker
bodies that this project deliberately does not reproduce (the four parked
theme-page goldens are the precedent). That half is where
`oidc/device/poll-access-denied` and a device-grant success body live. It is
filed, sized and measured below so cut B starts from measurements rather than
from a guess.

## 1. What was measured

### 1.1 `POST /realms/{realm}/protocol/openid-connect/auth/device`

Success, on a client carrying `oauth2.device.authorization.grant.enabled`:

```
HTTP/1.1 200 OK
Cache-Control: no-store, must-revalidate, max-age=0
Content-Type: application/json
the five security headers
{"device_code":"AslvWKmKRvs81-88LjDvKDNIh8m8lYEeAjFiTDVEFPY","user_code":"DDNT-BYDP",
 "verification_uri":"http://localhost:8101/realms/master/device",
 "verification_uri_complete":"http://localhost:8101/realms/master/device?user_code=DDNT-BYDP",
 "expires_in":600,"interval":5}
```

Six keys in that order. `device_code` is 43 characters of base64url - 32 bytes,
unpadded - over eight mints. `user_code` is nine characters, `XXXX-XXXX`,
upper-case ASCII letters only over eight mints; no digits appeared.

**The success carries `Cache-Control` and every rejection carries none.** That
is the opposite way round from the token endpoint, where every response
including the success carries `no-store` and `Pragma: no-cache`. This endpoint
sends **no `Pragma` at all**, on any response.

The refusals, in the order they are reached. Each pair below was driven with two
faults at once, one pair per adjacency:

| # | Request | Status | Body |
|---|---|---|---|
| 1 | unknown realm | 404 | `{"error":"Realm does not exist"}` |
| 2 | unknown, absent, empty or **disabled** `client_id` | 401 | `{"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}` |
| 3 | confidential client, no secret or a wrong one | 401 | `{"error":"unauthorized_client","error_description":"Invalid client or Invalid client credentials"}` |
| 4 | any form key sent twice | 400 | `{"error":"invalid_grant","error_description":"duplicated parameter"}` |
| 5 | the device grant disabled on the client | 400 | `{"error":"unauthorized_client","error_description":"Client is not allowed to initiate OAuth 2.0 Device Authorization Grant. The flow is disabled for the client."}` |

And what is **not** checked: `scope` is not validated at all. `scope=bogus-scope`
and `scope=` both answer 200, where `GET /auth` refuses both. A duplicated key
on the **query** is ignored; only the body is read.

Wrong methods, for follow-up F31's file: `GET` is **not** a wrong method - it
serves the device verification page, `data-page-id="login-login-oauth2-device-verify-user-code"`,
200, `text/html;charset=utf-8`. `HEAD` is 200 with that page's headers. `PUT`,
`DELETE` and `PATCH` are a real 405 with `{"error":"HTTP 405 Method Not Allowed"}`.
`OPTIONS` is 200 with **no `Allow` header**, matching `/logout` and not `/auth`.

### 1.2 The `urn:ietf:params:oauth:grant-type:device_code` grant

Every response carries `Cache-Control: no-store` and `Pragma: no-cache`, like
every other grant. Eleven answers, in the measured order:

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | `grant_type` absent / unknown | 400 | the endpoint's existing two |
| 2 | client authentication | 401 | `invalid_client` / `unauthorized_client`, as elsewhere |
| 3 | a repeated **form** key | 400 | `{"error":"invalid_request","error_description":"duplicated parameter"}` |
| 4 | the device grant disabled on the client | 400 | `{"error":"invalid_grant","error_description":"Client not allowed OAuth 2.0 Device Authorization Grant"}` |
| 5 | `device_code` absent | 400 | `{"error":"invalid_request","error_description":"Missing parameter: device_code"}` |
| 6 | `device_code` empty, unknown, or already spent | 400 | `{"error":"invalid_grant","error_description":"Device code not valid"}` |
| 7 | the code has expired | 400 | `{"error":"expired_token","error_description":"Device code is expired"}` |
| 8 | another client's code | 400 | `{"error":"invalid_grant","error_description":"unauthorized client"}` |
| 9 | polled again inside `interval` | 400 | `{"error":"slow_down","error_description":"Slow down"}` |
| 10 | the user denied it | 400 | `{"error":"access_denied","error_description":"The end user denied the authorization request"}` |
| 11 | nobody has answered yet | 400 | `{"error":"authorization_pending","error_description":"The authorization request is still pending"}` |
| 12 | approved | 200 | the ordinary nine-key token body |

Six of those adjacencies are not where a reader would put them, and each was
measured by driving two faults at once:

- **Row 4's description is not row 5 of the device endpoint's table**, and its
  code is not either. One condition - this client may not use this grant -
  spelled `invalid_grant` / `Client not allowed OAuth 2.0 Device Authorization
  Grant` here and `unauthorized_client` / `Client is not allowed to initiate
  OAuth 2.0 Device Authorization Grant. The flow is disabled for the client.`
  one endpoint away. Sharing one constant between the two is the obvious saving
  and it is wrong twice.
- **`duplicated parameter` is `invalid_request` here and `invalid_grant` at the
  device endpoint.** Same description, same status, different code, two
  endpoints in one flow. Measured side by side on one container.
- **The client mismatch (8) precedes the poll interval (9), and it does not
  stamp the poll clock.** Three wrong-client polls in a row, then the right
  client immediately, answered `authorization_pending` rather than `slow_down`.
- **Expiry (7) precedes the poll interval (9).** An expired code polled twice
  in a row inside a ten-second interval answered `expired_token` both times,
  where a pending code answers `slow_down` on the second.
- **`slow_down` does not re-stamp the clock.** Polls at t=0, t=3 and t=6 with
  `interval` 5 answered pending, `slow_down`, pending. The naive implementation
  stamps every poll and answers `slow_down` at t=6.
- **A denied code is not consumed and answers `access_denied` for ever**, and
  the poll interval still runs in front of it: the poll immediately after a
  denial answered `slow_down`, and the two after that, six seconds apart,
  answered `access_denied` again.

**A `device_code` is single-use on success.** The poll after a successful
exchange answers `Device code not valid`, so a spent code is indistinguishable
from a code that never existed - the same collapse the authorization code makes.

**An unknown `device_code` is not rate-limited.** Two bogus polls back to back
both answered `Device code not valid`; the clock belongs to the code, and a code
that does not exist has none.

The success body is the ordinary nine keys with `scope: "openid email profile"`,
`auth_time` and `acr` present in the access and ID tokens. Its `jti` prefix is
**`onrtdg:`**, which is a fifth prefix where follow-up F86 records four.

### 1.3 The two client attributes, and the realm's two knobs

| Attribute | On | Effect |
|---|---|---|
| `oauth2.device.authorization.grant.enabled` | client | opens the grant at both endpoints |
| `oauth2.device.code.lifespan` | client | `expires_in`, overriding the realm |
| `oauth2.device.polling.interval` | client | `interval`, overriding the realm |
| `oauth2DeviceCodeLifespan` | realm | default `expires_in`, 600 on master |
| `oauth2DevicePollingInterval` | realm | default `interval`, 5 on master |

`oauth2DeviceCodeLifespan` as a *client* attribute spelling does nothing -
measured, because it is the obvious wrong guess.

The two realm knobs are top-level integers on master and **absent from master's
`attributes` map** until a `PUT /admin/realms/master` writes them, after which
they appear in both places. The observed document records the created-realm half
of that ("a created realm carries them as string attributes as well as as
top-level integers") and not master's.

### 1.4 CIBA

**This section was written from four probes and was wrong about the order and
about two of the checks. Corrected in place, with what it said kept below**, in
this repository's convention for a measurement that turned out to be one step
past its evidence.

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | unknown client | 401 | `{"error":"invalid_client","error_description":"Invalid client or Invalid client credentials"}` |
| 2 | the grant disabled on the client | 401 | `{"error":"invalid_grant","error_description":"Client not allowed OIDC CIBA Grant"}` |
| 3 | `login_hint` **absent** | 400 | `{"error":"invalid_request","error_description":"missing parameter : login_hint"}` |
| 4 | `scope` **absent** | 400 | `{"error":"invalid_request","error_description":"missing parameter : scope"}` |
| 5 | `login_hint` resolves to nobody | 400 | `{"error":"invalid_request","error_description":"invalid_user"}` |
| 6 | `scope` invalid | 400 | `{"error":"invalid_scope","error_description":"Invalid scopes: <raw>"}` |
| 7 | everything valid | **503** | `{"error":"server_error","error_description":"Failed to send authentication request"}` |

Three things the first four probes could not see:

- **`login_hint` is checked before `scope`.** A request missing both is told
  about the hint. Only a request missing both says so, and the four probes each
  broke one parameter.
- **Presence and value are separate steps that interleave.** An empty `scope=`
  passes step 4 and fails step 6 with `Invalid scopes: ` and its trailing space;
  an empty `login_hint=` passes step 3 and fails step 5 with the identical
  `invalid_user` a hint naming nobody gets. And step 5 sits *between* them, so
  an empty scope with an unresolvable hint answers about the hint.
- **There is no duplicated-parameter check on this endpoint at all.** `zz` twice
  and `login_hint` twice both reach the 503.

`missing parameter : scope` has a space on both sides of the colon and is lower
case, where every other missing-parameter description on the protocol side is
`Missing parameter: x` - including the CIBA grant's own `Missing parameter:
auth_req_id` one endpoint away. It is not a typo in this document.

What this section said before the re-measurement, kept for the record: a
five-row table with `scope` above `login_hint` and no `invalid_user` or
`invalid_scope` row at all. The implementation was written from it, shipped
checking `scope` first, and **passed every case in the catalogue**, because
each case breaks exactly one parameter.

At the token endpoint, `urn:openid:params:grant-type:ciba`:

| Request | Status | Body |
|---|---|---|
| the grant disabled on the client | 400 | `{"error":"invalid_grant","error_description":"Client not allowed OIDC CIBA Grant"}` |
| `auth_req_id` absent | 400 | `{"error":"invalid_request","error_description":"Missing parameter: auth_req_id"}` |
| `auth_req_id` unparseable | 400 | `{"error":"invalid_grant","error_description":"Invalid Auth Req ID"}` |

The grant-disabled description is the *same string* at both CIBA endpoints and
the *status differs*: 401 at `ext/ciba/auth`, 400 at the token endpoint. The
device grant's pair differ in the string and agree on nothing. Two families,
two different ways of not agreeing.

## 2. What this cut builds

`internal/oidc/device.go`, `internal/oidc/devicestore.go`, additions to
`internal/oidc/token.go` and `internal/oidc/router.go`, and CIBA's refusals in
`internal/oidc/ciba.go`.

1. **`deviceStore`**, in memory, beside `authStore`. A device code is the same
   kind of object as an authentication session and an authorization code:
   short-lived, Infinispan-backed upstream, never in Keycloak's schema. F75
   already records that this makes Gloak single-process and `internal/store`
   belongs to another agent this session, so it is built in memory and the
   follow-up is extended rather than filed anew.
2. **`POST .../auth/device`**, serving section 1.1's 200 and its five refusals
   in the measured order.
3. **The `device_code` grant** at the token endpoint, serving rows 1 to 9 and 11
   of section 1.2. Rows 10 and 12 need an approval and are cut B.
4. **`POST .../ext/ciba/auth` and the CIBA grant**, serving section 1.4 - every
   answer including the 503, which is what a default deployment's contract is.
5. **Discovery** already lists both endpoints and both grant types; the
   `discovery-26.7.1.json` fixture is unchanged and nothing here touches it.

Not built, and each with a follow-up: the browser approval pages, the
`X-Frame-Options` question in section 4, and the `onrtdg:` prefix (F86's).

## 3. Cases

Rewritten, from `bootstrap`+`admin-cli` to a grant-enabled client:

- `oidc/device/authorization-request` - the 200. `device_code`, `user_code`,
  `verification_uri_complete` volatile; `verification_uri`, `expires_in` and
  `interval` are **not**, because they are a function of the realm and the
  client and asserting them is the point.
- `oidc/device/poll-authorization-pending`, `oidc/device/poll-slow-down`,
  `oidc/device/poll-expired-token` - each on its own fixture, each with the
  `device_code` captured by the fixture.

New, because the measurement found them:

- `oidc/device/grant-disabled` - the parked golden's refusal, promoted to a
  contract and given the `bootstrap`+`admin-cli` request the five cases used to
  share.
- `oidc/device/duplicated-parameter` - the `invalid_grant` spelling.
- `oidc/device/confidential-no-secret`, `oidc/device/unknown-client`.
- `oidc/token/device-code-not-valid`, `oidc/token/device-code-missing`,
  `oidc/token/device-grant-disabled`, `oidc/token/device-code-wrong-client`.

Left `Pending`, with the reason corrected:

- `oidc/device/poll-access-denied` - needs the browser approval, which is cut B.
- `oidc/ciba/poll-pending`, `oidc/ciba/poll-complete` - **not reachable on a
  default 26.7.1**, per section 1.4. Their current reason, "the backchannel
  authentication endpoint is not implemented", will be false the moment this
  cut lands and would then read as a to-do that somebody could close.
- `oidc/ciba/authentication-request` - promoted to `Implemented`; its parked
  golden becomes a contract and leaves `parkedGoldens`.

New CIBA cases: `oidc/ciba/missing-scope`, `oidc/ciba/missing-login-hint`,
`oidc/ciba/channel-unavailable` (the 503), `oidc/ciba/poll-invalid-auth-req-id`,
`oidc/ciba/poll-missing-auth-req-id`, `oidc/ciba/poll-grant-disabled`.

## 4. What the tests must pin that a golden cannot

Every one of these passed a green suite in an earlier form of this plan and is
here because asking "what does this not pin?" found it.

- **The six adjacencies of section 1.2.** A golden per answer proves each answer
  exists; none of them proves the *order*, because each golden's request is
  wrong in one way only. `internal/oidc`'s own tests drive two faults at once,
  one test per adjacency.
- **`slow_down` not re-stamping the clock.** No golden can express three
  requests at three times.
- **The two grant-disabled spellings.** Two goldens hold two strings; nothing
  stops a later refactor from making them one constant and re-recording. A unit
  test naming both literals is what refuses that.
- **The device endpoint sending no `Pragma`.** A golden asserts the headers that
  are there. Absence is asserted by the golden comparison being exact, which it
  is - but only while the case is `Implemented`, so this is a note rather than a
  test.

## 5. Open, and filed rather than guessed

- **`OPTIONS` omits `X-Frame-Options` on `/auth` as well as on `/auth/device`** -
  four of the five security headers, measured on both. AGENTS.md's five-header
  bullet lists three exceptions and this is a fourth, on surface Gloak already
  ships. Nothing is changed on the strength of it, because Gloak answers
  `OPTIONS` through `WithKeycloakFallbacks` and the whole 404-versus-405
  question is F31's.
- **`onrtdg:`** is F86's fifth prefix.
- **The browser approval half**, five page endpoints, measured in section 1 down
  to the redirect targets (`/realms/master/device/status` and
  `.../device/status?error=access_denied`).
