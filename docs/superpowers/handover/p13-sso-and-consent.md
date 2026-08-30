# P13, second cut: SSO, consent, and the device grant's browser half

Everything below was measured on 2026-08-30 against a plain `docker run` of
`quay.io/keycloak/keycloak:26.7.1`, container `kc-browser`, on port **8112**.
The port was confirmed free before anything was measured - `lsof -nP
-iTCP:8112 -sTCP:LISTEN` empty, a `curl` to it answering nothing - and the
container was removed at the end. Four probe clients (`sso-a`, `sso-b`,
`dev-a`, `con-a`) and one user (`ssouser`).

The full probe grids are in
`docs/superpowers/plans/2026-08-30-p13-sso-and-consent.md`. What is here is
what the next reader owes the other documents.

---

## 1. Measurements to fold into the observed document

The natural home is a new section after "The credential POST, and what the
redirect carries", plus the corrections in §2.

### 1.1 `KEYCLOAK_IDENTITY` is the only cookie that decides SSO

Replaying `GET /auth` with each subset of the four cookies a completed login
leaves:

```
KEYCLOAK_IDENTITY KEYCLOAK_SESSION AUTH_SESSION_ID KC_AUTH_SESSION_HASH   302 with a code
KEYCLOAK_IDENTITY                                                          302 with a code
KEYCLOAK_IDENTITY AUTH_SESSION_ID                                          302 with a code
                  KEYCLOAK_SESSION                                         200 login page
                                  AUTH_SESSION_ID                          200 login page
                                                  KC_AUTH_SESSION_HASH     200 login page
                  KEYCLOAK_SESSION AUTH_SESSION_ID                         200 login page
(none)                                                                     200 login page
```

`AUTH_SESSION_ID` is the one a reader of the login cut reaches for, because it
is the cookie that names the authentication session, and it decides nothing.

A `KEYCLOAK_IDENTITY` that does not verify is **cleared together with
`KEYCLOAK_SESSION`** and the request is then served as an anonymous one.
Measured on three ways of failing: a value that is not a JWT, a valid one with
three signature bytes rewritten, and a correctly signed one naming a session an
admin had ended.

### 1.2 The three values carried out of the original login

```
first login    session_state=g7h_qqxBbCPdvNFDGdOJyFiB   auth_time=1788113847
SSO redirect   session_state=g7h_qqxBbCPdvNFDGdOJyFiB   auth_time=1788113847  iat=1788113850
```

- The `session_state` is the **original user session id**.
- `AUTH_SESSION_ID` on the SSO redirect decodes to `<that id>.<86 chars>` - the
  original id inside a **fresh** cookie.
- The access token's `auth_time` is the **original login's**, with a later `iat`.
- The `sid` is unchanged, so no second user session exists, and the first
  login's **refresh token still works** afterwards.
- The same holds at a **different client**: `sso-b` on `sso-a`'s jar answers a
  code whose token carries the same `sid` and the same `auth_time`.

`KC_AUTH_SESSION_HASH` and `KEYCLOAK_SESSION` are **stable for the life of a
user session** - three SSO redirects on a jar holding `KEYCLOAK_IDENTITY` alone
re-emitted the value the original login set, and a second independent login
emitted a different one.

### 1.3 `prompt`, read as a set and compared case-sensitively

| `prompt` | already signed in | not signed in |
|---|---|---|
| absent, empty, `bogus`, `NONE`, `select_account` | 302 code | 200 login page |
| `none` | 302 code | 302 `login_required` |
| `login` | 200 re-authentication page | 200 login page |
| `consent` | 302 code, or the consent page on a `consentRequired` client | 200 login page |
| `create` | 400 page, `Registration not allowed` | 400 page, same |
| `none login` | 302 `login_required` | 302 `login_required` |
| `none consent` | 302 code | 302 `login_required` |
| `none create`, `create none` | as `none` alone | as `none` alone |
| `login create`, `create login` | as `login` alone | as `login` alone |

Four things a reader gets wrong:

1. **An unrecognised value is ignored, not refused.** Only `create` is a
   rejection, and only because registration is disabled.
2. **`none` is not "must be the only value".** `none login` is `login_required`
   and `none consent` is a code: `none` forbids interaction, `login` always
   demands it, `consent` demands it only when consent is needed.
3. **`create` fires only as the sole token.** Combined with anything it behaves
   as though absent, which is why it sits behind `none` and `login` in the
   order rather than in front of them.
4. `prompt=none` on a `consentRequired` client with no grant answers
   **`interaction_required`**, not `consent_required`.

### 1.4 `max_age`

`now - auth_time > max_age` forces re-authentication, strictly - `max_age=0` on
a session created in the same second is a code. A **non-numeric or empty**
`max_age` is a 400 page, which is the opposite of `prompt=`, where empty means
absent. Combined with `prompt=none`, a failed freshness check is
`login_required`.

Its check sits at a place nobody would guess: **after the bearer-only check and
before the redirect URI**, six pairs deep. It loses to an unknown `client_id`
and to a bearer-only client and beats the redirect URI, a missing
`response_type`, a bad scope and `prompt=none`.

### 1.5 A response can set `KC_RESTART` twice, in opposite directions

The strangest thing in the cut. **A `KC_RESTART` the request presented is
cleared on the way out**, so the SSO redirect sets a fresh one and then clears
it - six `Set-Cookie` headers with one name twice. The clear is last, so a
browser that arrives holding one **leaves without it**, and a browser that
arrives without one leaves holding a fresh one.

Measured with an empty `KC_RESTART`, a live one and the literal `junk` - all
three produce it - and across six branches with the same cookie present:

```
SSO code                    sets one and clears it        6 cookies
SSO code under prompt=none  clears it, sets none          5 cookies
login_required              clears it, sets none          3 cookies
prompt=create's 400 page    does **not** clear it         2 cookies
the login page              sets a fresh one, no clear    3 cookies
max_age's 400 page          no cookies at all             0
```

So the clear happens exactly when the authorization request is **finished** -
with a code or with `login_required` - and not when it is refused or continued.

It was found by **recording a golden**, not by probing: `oidc/authorization/sso-redirect`
came back with six `Set-Cookie` lines where every hand-driven probe had shown
five, because `curl` drops a `Max-Age=0` cookie from its jar and the conformance
harness keeps it as an empty value.

### 1.6 The two rejections at step 10 still open an authentication session

`login_required` and `prompt=create`'s page both set `AUTH_SESSION_ID` and
`KC_AUTH_SESSION_HASH`. `max_age`'s rejection at step 2c sends **no cookies at
all**, which is what says the two checks are in different places.

### 1.7 `/realms/{realm}/device` and `/protocol/openid-connect/auth/device` are one endpoint at two paths

Measured in both directions on both verbs, four probes per path, identical
answers: `POST` on either mints a device code, `GET` on either serves the
verification page, and `GET .../auth/device?user_code=<live>` 302s to the login
action exactly as `/device` does.

### 1.8 The device grant's browser half, end to end

```
GET  /realms/master/device?user_code=GOUN-RIRO
  302 -> /realms/master/login-actions/authenticate?client_id=dev-a&tab_id=<new>&client_data=e30
  Set-Cookie: AUTH_SESSION_ID, KC_AUTH_SESSION_HASH, KC_RESTART
  no X-Frame-Options, no Content-Security-Policy

POST the login form
  302 -> /realms/master/login-actions/required-action?execution=OAUTH_GRANT&client_id&tab_id&client_data
  **no cookies at all** - the session is established by the consent, not the login

GET  that location
  200, data-page-id="login-login-oauth-grant", heading "Grant Access to dev-a"
  <form method="POST" action="/realms/master/login-actions/consent?client_id&tab_id&client_data">
    <input type="hidden" name="code"> <button name="accept"> <button name="cancel">

POST accept  302 -> http://…/realms/master/device/status
             Set-Cookie: KC_RESTART cleared, KEYCLOAK_IDENTITY, KEYCLOAK_SESSION
POST cancel  302 -> http://…/realms/master/device/status?error=access_denied
             no cookies
```

`client_data` is the literal `e30` - base64url of `{}` - on all three of the
places it appears in a device login, because the flow has no redirect URI, no
response type and no state.

### 1.9 `POST /login-actions/consent`

| request | answer |
|---|---|
| `accept` | 302 to the flow's target, session cookies set |
| `cancel` | 302 with `error=access_denied` |
| **neither** button | 302 as though `accept` |
| `accept` **and** `cancel` | 302 as though `cancel` |
| a **wrong** `code` with either button | as that button - the code is not checked |
| **no** `code` at all | the same |
| no cookies | 400 page, `Restart login cookie not found. …` |
| the accept replayed | 302 restart to `/login-actions/authenticate` |
| `GET` on the path | 404 `{"error":"HTTP 404 Not Found"}` |

The browser flow's cancel redirects to the client with
`error=access_denied&state=…&iss=…` - **three keys and no
`error_description`**, where the device grant's poll answers the same code with
a sentence.

### 1.10 `/realms/{realm}/device/status`

200 on every input, `data-page-id="login-info"`, **no `Cache-Control` at all**,
two headings and three bodies:

```
(no query)            3616 bytes  Device Login Successful  You may close this browser window…
?error=               3616 bytes  the same
?error=access_denied  3697 bytes  Device Login Failed      Consent denied for connecting the device.
?error=bogus          3742 bytes  Device Login Failed      …and try connecting again.
```

An empty `error=` is the success page; **any** non-empty value is the failure
heading, including one Keycloak does not recognise.

### 1.11 The logout grid, and F65's one cell

Each row on its own fresh login:

| browser session | `id_token_hint` | target | answer |
|---|---|---|---|
| live | no | no | 200 `Logging out` |
| live | no | **yes** | **200 `Logging out`** |
| live | yes | no | 200 `You are logged out` |
| live | yes | yes | 302 |
| none | no | no | 200 `Logging out` |
| none | no | yes | **302** |
| none | yes | no | 200 `You are logged out` |

**The browser session changes exactly one cell.** The confirmation page ends
nothing - `GET /auth` immediately afterwards still answers a code - and it
renders a form posting to
`POST /realms/{realm}/protocol/openid-connect/logout/logout-confirm?client_id&tab_id`
with a hidden `session_code` and `confirmLogout=Logout`, which answers 302 to
the target carrying `state` and clears `KEYCLOAK_IDENTITY` and
`KEYCLOAK_SESSION`.

### 1.12 Two more endpoints named and not built

`prompt=login` on a signed-in browser serves a **re-authentication** page - 7975
bytes against the anonymous 6824, both `data-page-id="login-login"` - carrying a
readonly `kc-attempted-username`, a `Please re-authenticate to continue` alert
and a `Restart login` button pointing at
`/realms/{realm}/login-actions/restart?client_id&tab_id&client_data&skip_logout=false`.
That endpoint and `logout/logout-confirm` are both unmeasured beyond their form
markup.

### 1.13 The error pages' instructions, now visible

Driving two faults at once made the page family's prose readable, and it is the
prose F67 records as missing:

```
Client not found.                                                unknown client_id
Invalid parameter: redirect_uri                                  an unregistered redirect URI
Bearer-only applications are not allowed to initiate browser login   403
Invalid Request                                                  max_age unparseable
Registration not allowed                                         prompt=create
invalid_request                                                  an unknown execution
```

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, ready to paste.

- **The device verification page cannot be submitted, and that is measured.**
  `/realms/{realm}/device` and
  `/realms/{realm}/protocol/openid-connect/auth/device` are one JAX-RS resource
  mounted twice - four probes on each path, identical answers on both verbs -
  so the `POST` on either is the RFC 8628 device *authorization request*. The
  theme's own verification form posts `device_user_code` with no `client_id` to
  `/realms/{realm}/device` and gets **401
  `{"error":"invalid_client","error_description":"Invalid client or Invalid
  client credentials"}`**, measured six ways: with the page's own cookies, with
  none, with a valid code, with an invalid one, with the code renamed and with
  it on the query. `verification_uri_complete` - the `GET` - is the only route
  through a device login. Making the form work is the fix that diverges.

- **A response can set one cookie twice, in opposite directions.** A
  `KC_RESTART` the request presented is cleared on the way out, so the SSO
  redirect sets a fresh one and then clears it: six `Set-Cookie` headers, one
  name twice, and the clear last - so a browser that arrives holding one leaves
  without it and a browser that arrives without one leaves holding a fresh one.
  It is not a property of the endpoint: measured on six branches with the same
  cookie present, the code and `login_required` clear it and `prompt=create`'s
  page, the login page and `max_age`'s page do not. The clear happens exactly
  when the authorization request is **finished**. It was found by recording a
  golden rather than by probing, because `curl` drops a `Max-Age=0` cookie from
  its jar and the conformance harness keeps it as an empty value - so every
  hand-driven probe had shown five cookies and the recorder showed six.

- **`prompt` is a set of tokens, an unknown one is ignored, and `none` is not
  "the only value".** `prompt=bogus` and `prompt=NONE` behave exactly as an
  absent `prompt`, so the comparison is case-sensitive and membership rather
  than validation. `none login` answers `login_required` on a browser that
  `none` alone answers a code for, and `none consent` answers a code - so the
  rule is that `none` forbids interaction and the other tokens say whether any
  is needed. `create` is the odd one: it fires **only as the sole token**, and
  `none create`, `create none`, `login create` and `create login` all behave as
  though it were absent.

- **`GET /auth`'s page family has two `Cache-Control` values, not none.** The
  three-endpoint table records this endpoint's 400 and 403 pages as carrying
  none at all, which is true of the six rejections it was measured on and false
  of a seventh: `prompt=create` answers a 400 page carrying
  `no-store, must-revalidate, max-age=0`, measured side by side with
  `max_age=abc`'s page, which carries none. The predictor is not the endpoint
  but how far the request got - `max_age` fails while the parameters are being
  read and `prompt=create` fails inside the authentication flow, after an
  authentication session exists. `oidc/authorization/prompt-create` and
  `oidc/authorization/max-age-invalid` are recorded next to each other so the
  pair is a diff away.

- **The consent endpoint reads `cancel` and nothing else.** Measured six ways:
  `cancel` alone denies, `accept` and `cancel` together deny - `cancel` wins -
  and `accept` alone, **neither button**, a **wrong** `code` and **no** `code`
  all approve. So the absence of both buttons is an approval and the hidden
  `code` the page renders is not validated: `code=BOGUS` with `accept` granted a
  consent that had been revoked immediately before and redirected with a real
  authorization code. The authentication session cookie and the `tab_id` are the
  whole of the authority. Requiring `accept` refuses two requests Keycloak
  accepts and checking the `code` refuses two more.

- **The device grant asks for consent every time and the browser flow
  remembers.** Three device logins in a row, on one user, on a client whose
  `consentRequired` is false, all served the `OAUTH_GRANT` page - and a consent
  record **is** written, so the user's `/consents` listing holds the client
  afterwards. It is an endpoint recording a grant it then ignores. A
  `consentRequired` browser client goes the other way: after one accept, later
  logins there go straight to the client. One consent store, two endpoints, and
  only one of them reads it.

- **A browser session changes exactly one cell of the logout grid.** With a live
  `KEYCLOAK_IDENTITY`, no `id_token_hint` and a registered
  `post_logout_redirect_uri`, the answer is the `Logging out` confirmation page
  where the same request without a session is a 302. A **valid hint still
  redirects** on a signed-in browser, so this is not "a live session means the
  page". The page ends nothing: `GET /auth` immediately afterwards still answers
  a code.

- **The user session survives the consent page, and `prompt=consent` proves
  it.** A signed-in browser sent through the consent page by `prompt=consent`
  comes back with the `session_state` its first login had. So the authentication
  session that the consent completes into is rooted at a user session that
  already exists, and a handler that created one there would start a second
  session for a browser that never logged in twice.

---

## 3. Lines in AGENTS.md and the observed document these measurements contradict

1. **"`GET /auth` 400 and 403 pages: no `Cache-Control` at all."** Refuted by
   `prompt=create`. See the bullet above. **Fixed on the branch** in the sense
   that `httpx.WriteThemeErrorPage` already took the value as an argument, so
   Gloak serves both; the AGENTS.md table is what needs the correction.

2. **`internal/oidc/authorize.go`'s "Gloak has no browser session, so
   prompt=none is always the no-session case."** Gone: the endpoint reads
   `KEYCLOAK_IDENTITY`. **Fixed on the branch.**

3. **`internal/oidc/logout.go`'s "Gloak has no browser session cookie, so it
   always takes the second branch - which is the correct answer for every
   request Gloak can receive today."** That sentence was already false when it
   was written down, because the login cut had set the cookie the same day; F65
   said so. **Fixed on the branch.**

4. **`internal/oidc/router.go`'s "Gloak does not build either yet, so both fall
   through `WithKeycloakFallbacks` to a 404; the page is cut B's."** Both are
   built. **Fixed on the branch.**

5. **The brief's own description of `p13-login.md` §3 is richer than §3 is.**
   The brief says F77 was measured there down to "five cookies, the *original*
   user session id carried into a fresh `AUTH_SESSION_ID`, the original
   `auth_time`, the first session still refreshable, `prompt=none` clearing
   `KC_RESTART`". §3 records only that the second `GET /auth` is "a 302 carrying
   a real code and no login page" and that it omits two headers. Everything else
   in that list was re-measured here rather than inherited - which is what the
   brief asked for, and just as well: **one item of it is wrong.**
   `prompt=none` does not *clear* `KC_RESTART`; it does not set one. The clear
   exists but it is conditional on the request having presented one, and it is
   on the `prompt=none` path and the ordinary code path alike.

6. **`p7-device-grant.md`'s "the browser approval half, five page endpoints,
   measured in section 1 down to the redirect targets".** Section 1 of that plan
   names the two redirect targets in its section 5 and measures nothing else
   about the five pages - not the verification page's form, not the consent
   page's buttons, not `/device/status`'s two headings, not that the two device
   paths are one endpoint. The claim is a fair summary of what the cut *knew*
   and reads as a claim about what it *recorded*. This cut started from probes
   rather than from that sentence.

7. **The observed document's device-grant section says `verification_uri` is
   "the page a user enters the code on".** It is, and the page's form does not
   work; see the first bullet of §2. Nothing in the document says a device login
   can only be completed through `verification_uri_complete`, and it can only be
   completed through `verification_uri_complete`.

Two things that were **checked and held**, and are worth recording as such
because both were candidates for a correction: `GET /auth`'s redirect omitting
`X-Frame-Options` and `Content-Security-Policy` is true of the SSO redirect too
(a success, not a failure - which the AGENTS.md bullet already predicted), and
the authorization code's second part being the `session_state` survives SSO
intact.

---

## 4. Follow-up dispositions

### Closed

- **F77 - SSO is not recognised.** **Closed.** `GET /auth` reads
  `KEYCLOAK_IDENTITY`, reuses the user session, carries the original
  `auth_time` and `session_state`, and leaves the first login's refresh token
  working. `prompt` and `max_age` are served with it.

- **F65 - the browser-session branch of the logout confirmation page is
  unmodelled.** **Closed.** The one cell the browser session changes is served.
  What is *not* built is
  `POST /realms/{realm}/protocol/openid-connect/logout/logout-confirm`, and that
  is filed below rather than left inside F65: the confirmation page Gloak serves
  is a placeholder with no form, so there is nothing pointing at a route that
  does not exist.

- **F101 - the device grant's browser half is unbuilt.** **Closed.**
  `GET`/`POST` on both device paths, `GET /login-actions/required-action`,
  `POST /login-actions/consent` and `/realms/{realm}/device/status` are all
  served, and **a user can complete a device login**.

- **`oidc/device/poll-access-denied`.** **Promoted to `Implemented`** with
  `deviceDeniedFixture`, which drives a whole device authorization through the
  verification page, the login page and the consent page and cancels it. It is
  the first fixture in the file that walks two endpoints' worth of pages. **It
  never carried a golden**, so nothing left `parkedGoldens` - the brief expected
  an entry to remove and there was none.

### Extended

- **F67 - the theme's page prose.** Larger again, and now with the prose itself
  written down: §1.13 lists six instructions this cut made readable, and three
  more pages joined the family (the consent page, the device verification page
  and `/device/status`, which has two headings and three bodies).

- **F75 - the in-memory authentication session and authorization code.** A
  fourth object joins it, and **for a different reason**, which is why it is
  named separately below.

### New, each reproduced rather than theorised

- **Consent grants are in memory, and unlike F75's three that is a real
  divergence.** Keycloak persists a consent: it is a row a user can read and
  revoke through `GET`/`DELETE
  /admin/realms/{realm}/users/{id}/consents/{clientId}`, and it survives a
  restart. F75's three objects are short-lived by design and in Infinispan
  rather than in the schema; this one is not. Gloak keeps it in memory only
  because `internal/store` and `internal/model` belong to another stream, so a
  restart forgets every grant and asks again. `internal/oidc/authsession.go`
  says so at the top of `consentStore`.

- **`POST /realms/{realm}/protocol/openid-connect/logout/logout-confirm` is
  measured and unbuilt.** 302 to the target carrying `state` and nothing else,
  `Cache-Control: no-cache`, clearing `KEYCLOAK_IDENTITY` and
  `KEYCLOAK_SESSION`. Building it means the confirmation page growing a real
  form, which is F67's work.

- **`/realms/{realm}/login-actions/restart` is unmeasured and unserved.** The
  re-authentication page `prompt=login` serves points at it with
  `?client_id&tab_id&client_data&skip_logout=false`. A seventh browser endpoint.

- **`prompt=login`'s page is the ordinary login page in Gloak.** Keycloak serves
  1151 bytes more - a readonly `kc-attempted-username`, a `Please
  re-authenticate to continue` alert and the restart button. The branch is
  right and the markup is F67's.

- **`registrationAllowed` is not modelled, so `prompt=create` is always the
  refusal.** It is false on every realm a default 26.7.1 has, so this is the
  measured answer for every realm Gloak can serve today - but a realm that
  enabled it would still get the page. `internal/model` is another stream's.

- **The adjacency between `max_age` and the redirect URI cannot be observed on
  Gloak.** Both rejections are the same placeholder page; Keycloak distinguishes
  them in prose. The order in the code follows the measurement and no test can
  hold it there until F67 lands. Found by mutation testing, and
  `TestMaxAgeIsRefusedBeforeTheRedirectURI` now says so in its own doc comment
  rather than implying it pins six adjacencies when it pins four.

- **A masked header is asserted on presence, so a cookie *count* is never
  pinned by a golden.** `oidc/authorization/sso-redirect`'s golden holds six
  `Set-Cookie` lines and would pass with one. The count is pinned by
  `internal/oidc`'s own tests and nowhere else. That is not new machinery - it
  is `conformance_test.go`'s documented behaviour - but this is the first case
  whose contract is mostly *in* that header.

---

## 5. Mutation testing

Twenty-two mutations, one per claim, each applied to a copy, run against its own
named test and restored from that copy rather than with `git checkout`.
**Eighteen were killed on the first run. Four survived**, and they were four
different things:

- **Two were real gaps in the tests, and both are fixed on the branch.**
  `TestAPresentedRestartCookieIsClearedOnTheWayOut` presented the cookie on
  every row, so making the clear unconditional changed nothing it looked at; it
  now has a row that sends none. And `TestRequiredActionRefusesAnUnknownExecution`
  drove a request with **no cookies**, where deleting the execution check
  answers the identical 400 by the other route; it now runs on a browser that
  would otherwise have been served the consent page. Both mutations die now.

- **One was my mutation aimed at the wrong function** - the `writeUnusableSession`
  call it replaced was `requiredAction`'s, not `consent`'s. Retargeted, it dies.
  Worth writing down because a survivor that is really a mis-aimed mutation
  looks exactly like a test gap in the output.

- **One is a real limit and is reported rather than patched**: reordering
  `max_age` past the redirect URI leaves its test green, because Gloak answers
  both with the same placeholder page. Removing the check entirely is killed, so
  what the test pins is "`max_age` is checked and beats the 302 family", not
  "it is checked *there*". See §4.

The sharper question - what do these tests not pin? - found two more, both in
§4: the golden cannot see a cookie count, and `registrationAllowed` is
unmodelled so `prompt=create` cannot be tested both ways.

---

## 6. Parity, before and after

Measured with `TestCoverage` on the merge base (`0d6d993`) and on the branch:

```
Parity: 263 -> 267 of 523 (+4)

chapter                         before  after  delta
oidc/authorization                  12     14     +2
oidc/device                         11     13     +2
```

The denominator moves 516 → 523 because this cut adds seven cases. The four
that moved the numerator are the ones whose bodies are **empty** or JSON:

- `oidc/authorization/sso-redirect` - **new**, the headline
- `oidc/authorization/prompt-none-login-required` - **new**, and its `Location`
  is asserted **by value**: with nobody signed in there is no code in it, so
  the error, the state and their order are pinned exactly
- `oidc/device/verification-redirect` - **new**
- `oidc/device/poll-access-denied` - **promoted** out of `Pending`

Four more are **new and `Recorded`**, because they are keycloak.v2 theme pages
Gloak serves as envelopes: `oidc/device/verification-page`,
`oidc/device/status-page`, `oidc/authorization/prompt-create` and
`oidc/authorization/max-age-invalid`. The last two are the pair that refutes
AGENTS.md's `Cache-Control` line and they are recorded side by side on purpose.

The `Recorded` four are worth one sentence for whoever builds the theme: the
moment a real body lands they become `Implemented` by deleting a `Reason`, and
`TestConformance`'s "already matches" is what will say when.

---

## 7. Files touched outside this cut's own

`internal/conformance/fixture.go` is shared. The new fixture function
(`deviceDeniedFixture`) is **appended at the very end of the file**, as the
brief asked. The one exception is its entry in the `fixtures` map, which has to
sit in that map - three lines beside the other device entries, at line ~396.
Nothing else in the file moved.

`internal/oidc/authorize_test.go` gained two probe clients (`probe-device`,
`probe-consent`) in the shared `authServerAndStore` list, because the device
grant is off on every client a default 26.7.1 bootstraps and the consent page
needs a client that asks for one.

`internal/token/identity.go` gained `ParseIdentityCookie`. It is the mirror of
`IssueIdentityCookie` and it asserts `typ=Serialized-ID`, which is the whole of
what stops a refresh token standing in for a browser session cookie: the two
share a key and an algorithm.
