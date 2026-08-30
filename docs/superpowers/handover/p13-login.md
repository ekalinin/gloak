# P13, first cut: handover

Everything below was measured on 2026-08-30 against a plain `docker run` of
`quay.io/keycloak/keycloak:26.7.1`, container `kc-p13`, on port **18194**, with
two public clients (`p13-a`, `p13-b`) registering
`http://localhost:9999/callback` and a second user `p13user`. The container was
removed at the end of the cut.

> **The port is worth one sentence.** The brief named 8094. A parallel stream's
> `gloak` process was bound to `*:8094` on IPv6, `localhost` resolved there
> first, and the first probe run measured **that process** rather than Keycloak -
> it answered `GET /auth` with the unmatched-path 404, which is what gave it
> away. Every number here is from 18194, whose listener was confirmed to be
> colima's forwarder before anything was measured. The warning in the brief was
> not theoretical and it cost a run.

---

## 1. Measurements to fold into the observed document

The natural home is a new section after "The credential POST, and what the
redirect carries", plus the corrections in §2.

### 1.1 The root authentication session id **is** the `session_state`

This is the load-bearing one, and it is measured four ways on one login:

```
AUTH_SESSION_ID   base64url-decodes to  QTmg9gDxlnuFEYSwm6NU0pGO.xT7P9CHNSywfsXif3rv9Lu...(86 chars)
login redirect    session_state=        QTmg9gDxlnuFEYSwm6NU0pGO
KEYCLOAK_IDENTITY "sid":                QTmg9gDxlnuFEYSwm6NU0pGO
authorization code, second part:        QTmg9gDxlnuFEYSwm6NU0pGO
```

So `session_state` is decided at `GET /auth`, **before any credential is seen**.
The observed document records the code's second part as "the session_state" and
does not say where that value comes from; it comes from the cookie the login
page already set.

Measured lengths, every one of them a value a client sees:

| Value | Length | Alphabet |
|---|---|---|
| the root id / `session_state` | 24 chars (18 bytes) | base64url |
| `AUTH_SESSION_ID`'s second part | 86 chars | opaque |
| `AUTH_SESSION_ID` whole | 148 chars, decodes to 111 bytes | base64url |
| `tab_id` | 11 chars (8 bytes) | base64url |
| `session_code` | 43 chars (32 bytes) | base64url |
| `KC_AUTH_SESSION_HASH` | 64 chars (48 bytes), **quoted** | **standard** base64 |

`KEYCLOAK_IDENTITY`'s payload is eight keys in the order
`exp iat jti iss sub typ sid state_checker`, `typ` is `Serialized-ID`, `exp -
iat` is 36000, and its JOSE header is `{"alg":"HS512","typ":"JWT","kid":<the
realm's HMAC kid>}`.

### 1.2 `client_data` is parsed and then ignored

Measured three ways on a login that then succeeded anyway:

| `client_data` | Result |
|---|---|
| `{"ru":"http://evil.example/cb",...}` | still redirects to the **registered** URI |
| `{"st":"TAMPERED",...}` | still echoes the original `state=xyz123` |
| `{"rm":"fragment",...}` on a tab that asked for none | still puts the parameters in the **query** |
| dropped entirely | **succeeds** |
| `client_data=!!!!` | **400**, `Invalid Request` |

So it is parsed but is never the authority: the authentication session is. A
handler that read the redirect URI out of it would let a forged one steer a
browser. Its own shape is:

```
{"ru":"<redirect uri>","rt":"code","st":"<state>"}
{"ru":...,"rt":"code","rm":"fragment","st":"xyz123"}     when a response_mode was sent
{"ru":...,"rt":"code"}                                   when no state was sent
{"ru":...,"rt":"code","st":""}                           when state= was sent
```

Key order `ru, rt, rm, st`; `rm` only when a `response_mode` was named; and `st`
follows `/auth`'s own state rule exactly - absent when absent, present and empty
when empty.

### 1.3 The three answers to an unusable authentication session

Measured as a clean grid: the session code was spent by completing a login, and
the three cookies were then varied independently.

```
AUTH_SESSION_ID  KC_RESTART  KEYCLOAK_IDENTITY  -> outcome
       -              -              -           400 page, "Restart login cookie not found"
       -              -              Y           302 to the client, temporarily_unavailable
       -              Y              -           302 restart
       -              Y              Y           302 restart
       Y              -              -           400 page, "Restart login cookie not found"
       Y              -              Y           302 to the client, temporarily_unavailable
       Y              Y              -           302 restart
       Y              Y              Y           302 restart
```

and with a **valid** session code, `AUTH_SESSION_ID` alone is sufficient and
`KC_RESTART` is irrelevant:

```
AUTH_SESSION_ID=Y KC_RESTART=-  -> the code
AUTH_SESSION_ID=- KC_RESTART=Y  -> 302 restart
AUTH_SESSION_ID=- KC_RESTART=-  -> 400 page
```

In order: `KC_RESTART` present wins; else `KEYCLOAK_IDENTITY` present is the
client redirect; else the page. **An empty `KC_RESTART` counts as absent**,
which is the state the successful login itself leaves behind - it clears the
cookie with `Max-Age=0`.

The restart 302 goes to
`/realms/{realm}/login-actions/authenticate?client_id&tab_id&client_data` with a
**freshly minted `tab_id`** and **no `session_code`**, and following it serves
the login page with `Your login attempt timed out. Login will start from the
beginning.` It carries `Content-Security-Policy` and `X-Frame-Options`.

The client redirect is
`?error=temporarily_unavailable&error_description=authentication_expired&state=…&iss=…`,
that key order, and it sets **no cookies at all**.

An **expired** session code - measured by setting the realm's
`accessCodeLifespanLogin` to 1 and waiting three seconds - takes the identical
three-way branch. Expiry and replay are one case, not two.

### 1.4 The rejection order at `/login-actions/authenticate`

Driven with two faults at once, one pair per adjacency:

```
no client_id     + bad client_data  -> Invalid Request         client_data is first
bad client_data  + no cookies       -> Invalid Request
bad client_data  + bad session_code -> Invalid Request
unknown client_id+ no cookies       -> Restart login cookie…   cookies before client_id
no client_id     + no cookies       -> Restart login cookie…
no client_id     + bad session_code -> An error occurred…      client_id before session_code
unknown client_id+ bad session_code -> An error occurred…
bad session_code + wrong password   -> the restart family      session_code before credentials
bad execution    + wrong password   -> Page has expired        execution before credentials
no cookies       + wrong password   -> Restart login cookie…
```

Order: **client_data, cookies, client_id, session_code, execution,
credentials.**

One adjacency is recorded and not explained: `bad session_code + bad execution`
answers the `Page has expired` page (4604 bytes) rather than the restart 302 a
bad session code alone gets.

### 1.5 The three page families this endpoint serves

All three carry `Cache-Control: no-store, must-revalidate, max-age=0`,
`Content-Language: en`, `Content-Security-Policy`, `text/html;charset=utf-8` and
the five security headers. `<title>` is `Sign in to Keycloak` on every one; the
`kc-page-title` heading is what differs.

| Trigger | Status | Heading | Instruction |
|---|---|---|---|
| the login page, and every credential failure | 200 | `Sign in to your account` | - |
| absent or unknown `execution` | **200** | `Page has expired` | `To restart the login process` |
| absent, empty, unknown, disabled or **wrong** `client_id` | 400 | `We are sorry...` | `An error occurred, please login again through your application.` |
| unparseable `client_data` | 400 | `We are sorry...` | `Invalid Request` |
| no usable cookie at all | 400 | `We are sorry...` | `Restart login cookie not found. It may have expired; it may have been deleted or cookies are disabled in your browser. If cookies are disabled then enable them. Click Back to Application to login again.` |

`client_id` naming a **different real client** than the tab's is the same 400
page as an unknown one (3636 bytes against 3620 - the pages differ only in the
"Back to Application" link).

### 1.6 The credential outcomes

All 200, page re-served, with a **rotated `session_code`** while `execution`,
`tab_id` and `client_data` stay the same. The retry with the rotated code
succeeds; the old one does not.

| Request | Message |
|---|---|
| wrong password, unknown username, empty/absent username, empty/absent password, no form fields at all | `Invalid username or password.` |
| a disabled user **with the right password** | `Account is disabled, contact your administrator.` |
| a disabled user with a **wrong** password | `Invalid username or password.` |

That last pair is the ordering: **the disabled check runs after the password
verifies**, so it is not an enumeration oracle either. The username is echoed
back into the form's `value` when one was sent, and matching is
case-insensitive (`ADMIN` logs in). `credentialId` is not required.

A user carrying a required action answers a **302** to
`/realms/{realm}/login-actions/required-action?execution=UPDATE_PASSWORD&client_id&tab_id&client_data`
- a fourth endpoint nobody has measured.

### 1.7 Where the parameters come from, and duplicates

**`/login-actions/authenticate` reads its five parameters from the query string
and its credentials from the body.** All five in the body with an empty query is
the 400 client page; `session_code` in the body alone answers as though none was
sent; a `text/plain` body and an empty body both behave as empty credentials.

That is the exact mirror of `/auth`, re-measured today as the control: `POST
/auth` with the parameters on the **query** is a 400 (3572 bytes) and with the
same parameters in the **body** is the 200 login page (6833 bytes).

**A repeated query parameter is not an error here.** `zz` twice, `tab_id` twice,
and `session_code` twice with the second value garbage all succeed, first value
winning - where `/auth` answers `duplicated parameter` for any key sent twice.

### 1.8 `GET /login-actions/authenticate` is not a read

A GET carrying the right parameters and no body **attempts the login**: 200, the
page re-served with `Invalid username or password.`, and the `session_code`
rotated. It behaves exactly as a POST with empty credentials.

### 1.9 The cookies a request actually moves

Not "always three":

| Request | Set-Cookie |
|---|---|
| `GET /auth`, first request on a jar | `AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH`, `KC_RESTART` |
| `GET /auth`, **second tab, same jar** | `KC_RESTART` **alone** |
| the successful login | `KC_RESTART` cleared, `KEYCLOAK_IDENTITY`, `KEYCLOAK_SESSION` |
| the restart 302, live auth session | **none** |
| the restart 302, no live auth session | `AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH` |
| the `temporarily_unavailable` redirect | **none** |

Two browser tabs therefore share one root id, and **both logins succeed
reporting the same `session_state`**. A design that minted a session per
authorization request would move `AUTH_SESSION_ID` on every one.

`KC_RESTART`'s clear is `KC_RESTART=;Version=1;Path=/realms/master/;Max-Age=0` -
neither `Secure` nor `HttpOnly`, where the cookie it clears carries both.

### 1.10 The verbs

```
                                    HEAD  OPTIONS  PUT  DELETE  PATCH
/protocol/openid-connect/auth        200    200    405   405     405
/login-actions/authenticate          404    200    405   405     405
```

Both `OPTIONS` answer `Allow: HEAD, POST, GET, OPTIONS`; the 405 body is
`{"error":"HTTP 405 Method Not Allowed"}` with no `Allow`. An unknown realm is
`{"error":"Realm does not exist"}`, the protocol side's spelling.

### 1.11 Small confirmations

- The action's five parameters are in the order `session_code`, `execution`,
  `client_id`, `tab_id`, `client_data`. Confirmed.
- `execution` is stable across logins in one container. Confirmed.
- `KEYCLOAK_SESSION` is `KC_AUTH_SESSION_HASH`'s value with `+/` rewritten to
  `-_`. Confirmed on a fresh pair.
- The code's first part is UUID-shaped and is not a UUID: two fresh samples
  carried version/variant nibbles `d`/`f` and `2`/`7`.
- The login redirect's key order is `state, session_state, iss, code`; the
  `form_post` body's is `code, iss, state, session_state`. Both confirmed.
- The login form's `username` and `password` inputs carry an explicit
  `value=""`; only `credentialId` has no `value` attribute. The observed
  document says "no value" of `credentialId` alone, which is right, but a
  byte-exact theme will need the other two.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, ready to paste.

### 2.1 New bullets

- **`session_state` is minted by the login page, not by the login.** The
  authentication session's root id is created at `GET /auth`, goes out inside
  `AUTH_SESSION_ID`, and is then the redirect's `session_state`, the
  `KEYCLOAK_IDENTITY` cookie's `sid` and the authorization code's second part -
  four observables carrying one 24-character value that was decided before any
  credential was seen. Minting it when the password verifies is the obvious
  implementation and it gets all four wrong at once, and no conformance case
  would see it: every case in this flow masks `Location` and `Set-Cookie` as
  volatile.

- **`client_data` is parsed and then ignored.** The login form's fifth
  parameter carries the redirect URI, the response type, the response mode and
  the state - and none of them is used. A `client_data` naming another redirect
  URI still redirects to the registered one, one naming another state still
  echoes the original, one adding `rm=fragment` still answers in the query, and
  dropping it entirely succeeds. But `client_data=!!!!` is a 400 `Invalid
  Request`, so it *is* parsed. It is a restart hint the browser carries, never
  an authority. Reading the redirect URI out of it is the tidy-up that lets a
  forged one steer a browser.

- **A replayed `session_code` has three answers and the cookies pick.**
  `KC_RESTART` present is a 302 **restart** to `/login-actions/authenticate`
  with a fresh `tab_id` and no `session_code`; otherwise `KEYCLOAK_IDENTITY`
  present is a 302 to the **client** carrying `temporarily_unavailable` /
  `authentication_expired`; otherwise it is a 400 page, `Restart login cookie
  not found`. Measured as an eight-cell grid. **An empty `KC_RESTART` counts as
  absent**, which is what the successful login leaves behind - it clears the
  cookie with `Max-Age=0` - so a real browser gets the middle branch and a
  client that keeps the cookie gets the first. An **expired** session code takes
  the identical branch, so expiry and replay are one case and not two.

- **`/login-actions/authenticate` reads its parameters from the query and its
  credentials from the body, and `/auth` does the opposite.** All five
  parameters in the body with an empty query answers the client error page; the
  same five on `POST /auth`'s query answers the error page while the body works.
  Two endpoints in one flow, mirror-image rules, and `r.Form` merges the two and
  hides both.

- **A repeated parameter is an error at `/auth` and at neither of its
  neighbours.** `/logout` takes the first value, and so does
  `/login-actions/authenticate` - `zz` twice, `tab_id` twice, and even
  `session_code` twice with the second value garbage all log in. `/auth` is the
  odd one of the three, not the rule.

- **`GET /login-actions/authenticate` is not a read.** It attempts the login
  with whatever credentials the body carries - none, for a GET - and answers
  200 with the page re-served, `Invalid username or password.`, and the
  `session_code` **rotated**. A handler that made GET serve the form without
  spending the code would look more correct and would diverge.

- **A failed credential rotates the `session_code` and nothing else.**
  `execution`, `tab_id` and `client_data` are unchanged, the username is echoed
  back into the input, and the retry with the rotated code succeeds while the
  old one takes the restart branch.

- **The disabled-account message is checked after the password.** A disabled
  user with the right password gets `Account is disabled, contact your
  administrator.`; the same user with a wrong password gets `Invalid username or
  password.`, like everybody else. Checking `enabled` first is the obvious order
  and it turns the login form into an account-enumeration oracle.

- **A second `GET /auth` on one browser sets one cookie, not three.** The
  authentication session is reused and only `KC_RESTART` moves, so two tabs
  share one root id - and both then log in reporting the **same**
  `session_state`. The restart 302 goes further and sets *no* cookie at all
  when the browser still has a live authentication session, and two when it does
  not.

### 2.2 Lines these measurements contradict

**In the observed document**, "The login form's own rejections":

> Replaying a spent `session_code` does not re-serve anything: it redirects.
> `Location: …error=temporarily_unavailable&error_description=authentication_expired…`

That is **one of three answers, stated unconditionally**. It is right for a
browser, because the login clears `KC_RESTART`; it is wrong for any client that
still holds one, which restarts and *does* re-serve the login page. The grid in
§1.3 is the replacement. This is the same failure mode AGENTS.md already records
twice - a measurement taken through one cookie jar, written up as though the jar
were not the variable.

**In the observed document**, "RP-initiated logout", two sentences that are
still there and that AGENTS.md's own bullets already correct - re-measured today
on my container so this is a measurement and not an inference:

> **Without an `id_token_hint` there is no redirect at all**

Measured: a hintless `GET /logout` with `client_id` and a registered target, on
a browser with **no** session, is a **302** to that target. AGENTS.md's
"Whether a hintless logout redirects is decided by the browser session, not by
the hint" bullet is right and this sentence is the superseded text.

> `post.logout.redirect.uris` is a client attribute and has to be registered for
> the redirect to validate; it is not derived from `redirectUris`.

Measured: the client above carries **no such attribute** and redirects to its
registered `redirect_uri` anyway. AGENTS.md's "`post.logout.redirect.uris` is a
filter over `redirectUris`" bullet is right and this sentence is its exact
negation. Both were falsified on 2026-08-29 and both are still in the observed
document; the correction landed in AGENTS.md and not here.

**In AGENTS.md**, the theme-error-page bullet:

> `/logout`'s 400 page carries `Cache-Control: no-cache` where `/auth`'s 400 and
> 403 pages carry none … `httpx.WriteThemeErrorPage` takes the value as an
> argument for exactly this reason.

Still true, and now a **third** value exists. Measured side by side on one
container:

```
GET  /auth                        400 and 403 pages   no Cache-Control at all
GET  /logout                      400 page            no-cache
POST /login-actions/authenticate  400 pages           no-store, must-revalidate, max-age=0
```

One page, three endpoints, three answers. Suggested amendment: change "Two
endpoints that look like one endpoint twice" to "Three endpoints that look like
one endpoint three times", and add the third row.

**In AGENTS.md**, the F31 verb bullet ("Five data points that disagree still do
not say what the rule is"). There is now a **sixth**, and it is the sharpest
one, because both endpoints are in one flow on one container:

> And `HEAD` is 200 on `/auth` and **404** on `/login-actions/authenticate`,
> which answers the other four verbs identically to it - `PUT`, `DELETE` and
> `PATCH` a real 405, `OPTIONS` 200 with `Allow: HEAD, POST, GET, OPTIONS`. So
> the two endpoints agree on four verbs and disagree on the fifth.

Gloak sends the generic 404 to all of them, unchanged.

**Confirmed rather than contradicted**, and worth saying because the brief asked
for each claim to be re-verified rather than inherited:

- "The authorization code's third part is the client's own internal UUID … The
  first is laid out like a UUID and is not one." Confirmed on fresh samples;
  the two new samples' version/variant nibbles are `d`/`f` and `2`/`7`.
- "`GET /auth`'s redirect back to the client is the one response in the browser
  flow that omits `X-Frame-Options` … `POST /login-actions/authenticate`'s
  *error* redirect, to the same URI with the same status, carries all six."
  Confirmed - **and it is now asserted by a conformance case**, where before
  this cut it was asserted by nothing at all.
- The header sweep table in "The two header sets, swept across eleven
  responses". Confirmed for every row this cut touches.

---

## 3. Follow-ups to file or close

### Close

- **F50 - `GET /auth` answers a fully valid request with the page family's
  400.** **Closed.** The endpoint opens an authentication session and serves the
  login page. The four `Recorded` cases it blocked are `Implemented` and a fifth
  case was added.

- **F64 - Gloak issues no `AUTH_SESSION_ID`.** **Closed.** `GET /auth` issues
  one, in the measured shape - 148 characters, decoding to
  `<24-char root id>.<86 chars>` - along with `KC_AUTH_SESSION_HASH` and
  `KC_RESTART`, and the login issues `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION`.
  The note that "the conformance cases mask `Set-Cookie` as volatile, so nothing
  catches this" is still true of the cookies' *values*; `internal/oidc`'s own
  tests now pin the attribute spelling, the ordering and the count, because
  `http.SetCookie` cannot produce Keycloak's spelling and no golden would have
  noticed.

### Move, and say what changed

- **F65 - the browser-session branch of the logout confirmation page is
  unmodelled.** **Still open, and now a real divergence rather than a latent
  one.** F65 said it "becomes a divergence the moment P13 sets one". P13 has set
  one: Gloak now issues `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION`, and
  `internal/oidc/logout.go` does not read either, so a hintless logout on a live
  browser session still takes the no-session branch where Keycloak serves
  `Logging out`. The follow-up should be re-worded from "becomes" to "is".

- **F67 - the logout page's three instructions are one placeholder.** **Still
  open and now larger.** The same shape has appeared on a second endpoint:
  `/login-actions/authenticate` has three 400 pages differing only in prose
  (`Invalid Request`, `An error occurred, please login again through your
  application.`, `Restart login cookie not found. …`) plus a 200 `Page has
  expired` page and the login page's two feedback messages. Gloak serves the
  envelope and the branch, and `internal/oidc`'s tests guard which branch was
  taken. All the prose is P13's later work. Suggest widening F67 from "the
  logout page's three instructions" to "the theme's page prose, on `/logout` and
  `/login-actions/authenticate`".

- **F69 - `make record` rewrites `Pending` theme-page goldens on every run.**
  **Untouched, and worked around rather than triggered.** This cut recorded one
  new golden with
  `-run 'TestRecordGoldens/oidc/authorization/replayed-session-code'`, so the
  four churners were never written and there was no churn to revert. Worth
  adding to F69 as the cheap mitigation: **a single-case `-run` is the way to
  record a new golden without touching the four**, and it works because the
  recorder runs one subtest per case.

### File

- **The authentication session and the authorization code are in memory, so
  Gloak is single-process for the browser flow.** This is the faithful model -
  Keycloak keeps both in Infinispan rather than in the database, because both
  are short-lived, and neither is in its schema - but two Gloak replicas behind
  a load balancer will not share them, where they *do* share realm signing keys
  precisely so that they agree. A login begun on one replica and finished on
  another restarts; a code minted on one cannot be redeemed on the other.
  The design if it needs fixing: the same `store.Store` interface pattern the
  sessions already use, with a `store.AuthSessions()` repository holding the
  root session, its tabs and the codes, and a sweep on write. It was **not**
  taken in this cut because `internal/store` belonged to another agent this
  session, and because the in-memory version is what Keycloak actually does.

- **`KC_RESTART` is a handle, where Keycloak's is a self-contained JWE.**
  Keycloak's `KC_RESTART` is a `dir`/`A256GCM` JWE carrying the original
  authorization request, so it survives without server state. Gloak's cookie
  value is an opaque handle into the same in-memory map. Not observable - the
  value is opaque to the client either way, and every case masks `Set-Cookie` -
  but it is the second thing two replicas would not share, and it is why the
  restart branch fails across a restart of the process where Keycloak's does
  not.

- **`AUTH_SESSION_ID`'s second half is a stored random string, not a
  signature.** Keycloak's is 86 characters that look like a MAC; nothing
  observable says over what. Gloak mints 64 random bytes, stores them beside the
  session and compares. The shape is measured; the contents are not observable.
  Filed so that nobody later "fixes" it into a signature and claims parity for
  it.

- **The `authorization_code` grant is still not served at the token endpoint.**
  The code is minted, stored with the redirect URI, the user, the session and
  the scope, and spent on first use - `spendCode` is tested directly, including
  that a **rejected** attempt still burns the code, which is the measured "single
  use means single attempt". What is missing is the redemption: eight measured
  rejections and a success body, all already in the observed document under "The
  token endpoint's answers to an authorization code".
  `oidc/token/authorization-code-grant`, `oidc/token/replayed-code` and
  `oidc/token/pkce-verifier-mismatch` stay `Recorded` with an accurate reason,
  and their fixtures now run end to end against Gloak, which they could not
  before.

- **PKCE is carried nowhere yet.** `/auth` validates `code_challenge` and
  `code_challenge_method` and the login mints a code without storing either, so
  the verifier check has nothing to check against when the grant lands. The
  `authCode` struct has the two fields and nothing populates them. Named
  separately from the grant because it is a change to *this* cut's code, not to
  the token endpoint's.

- **SSO is not recognised.** Gloak sets `KEYCLOAK_IDENTITY` and never reads it,
  so a second authorization request on a live browser session serves the login
  form again where Keycloak redirects straight back with a code, and
  `prompt=none` still answers `login_required` where Keycloak answers a code.
  Measured today: the second `GET /auth` on a signed-in jar is a 302 carrying a
  real code and no login page, and it omits `X-Frame-Options` and
  `Content-Security-Policy` like every other `/auth` redirect.

- **`/realms/{realm}/login-actions/required-action` is unmeasured and
  unserved.** A user carrying a required action redirects there rather than to
  the client. Gloak has no required-action model, so it logs such a user in.

---

## 4. Parity before and after

`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1 -v`,
on the merge base (`4419956`) and on `feat/p13-login`.

```
Parity: 179 -> 184 of 499 (+5)

chapter                         before  after  delta
oidc/authorization                   7     12     +5
```

Per-chapter detail for the one chapter that moved:

| | served | recorded | documented |
|---|---|---|---|
| base | 7 | **4** | 15 |
| head | **12** | **0** | 16 |

The denominator moves 498 → 499 because this cut adds one case
(`oidc/authorization/replayed-session-code`). The `recorded` column going 4 → 0
is the part worth reading: `oidc/authorization` now has **no** case waiting on
an unimplemented endpoint.

The five:

- `oidc/authorization/code-flow-redirect` - promoted
- `oidc/authorization/pkce-s256` - promoted
- `oidc/authorization/pkce-plain` - promoted
- `oidc/authorization/response-mode-fragment` - promoted
- `oidc/authorization/replayed-session-code` - **new**, and the only case in this
  family whose `Location` is asserted **by value** rather than masked: its
  redirect carries `error`, `error_description`, `state` and `iss` and nothing
  per-request, so both strings and the key order are pinned exactly.

The four promoted cases also gained assertions they never had. They asserted
`Location` (volatile, so presence only) and `Cache-Control`; they now assert
`Content-Security-Policy`, `X-Frame-Options` and the other four security headers
as well. Nothing was re-recorded to claim that - the goldens already held those
values and no case had ever compared them. `X-Frame-Options` is the one that
matters: it is the measured difference between this endpoint's 302 and `/auth`'s
302 to the very same URI, a difference AGENTS.md warns about and that no test
guarded until now.
