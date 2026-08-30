# P13, second cut: SSO, consent, and the device grant's browser half

Two half-built things finished: `GET /auth` recognising a browser that is already
signed in (F77), and the pages that let a person approve a device authorization
(F101). F65 closes with the first, `oidc/device/poll-access-denied` with the
second.

Everything below was measured on 2026-08-30 against a plain `docker run` of
`quay.io/keycloak/keycloak:26.7.1`, container `kc-browser`, on port **8112**.
Before anything was measured, `lsof -nP -iTCP:8112 -sTCP:LISTEN` was empty and a
`curl` to the port answered nothing, so the port was confirmed free rather than
assumed; `kc-auth` was alive on 8111 throughout and was not touched. The probe
objects were four clients - `sso-a`, `sso-b` (public, standard flow),
`dev-a` (public, device grant enabled), `con-a` (public, `consentRequired`) -
and one user, `ssouser`.

---

## 0. The measured state machine

This is the section the rest of the cut is written against: **what decides each
branch of `GET /auth`, and what a browser that is already signed in gets.**

### 0.1 One cookie decides, and it is `KEYCLOAK_IDENTITY`

Measured by taking a jar that had completed a login and replaying `GET /auth`
with each subset of the four cookies it held:

```
cookies present                          answer
KEYCLOAK_IDENTITY KEYCLOAK_SESSION AUTH_SESSION_ID KC_AUTH_SESSION_HASH   302 with a code
KEYCLOAK_IDENTITY                                                          302 with a code
KEYCLOAK_IDENTITY AUTH_SESSION_ID                                          302 with a code
                  KEYCLOAK_SESSION                                         200 login page
                                    AUTH_SESSION_ID                        200 login page
                                                    KC_AUTH_SESSION_HASH   200 login page
                  KEYCLOAK_SESSION  AUTH_SESSION_ID                        200 login page
(none)                                                                     200 login page
```

`KEYCLOAK_IDENTITY` alone is necessary and sufficient. `AUTH_SESSION_ID` -
which is what a reader of the login cut would reach for, because it is the
cookie that names the authentication session - decides nothing here.

A `KEYCLOAK_IDENTITY` that does not verify is **cleared**, together with
`KEYCLOAK_SESSION`, and the request then behaves as an anonymous one. Measured
on three ways of failing: a value that is not a JWT at all, a valid JWT with
three bytes of its signature rewritten, and a correctly signed one naming a
session an admin had ended through `POST /users/{id}/logout`. All three answer
`Set-Cookie: KEYCLOAK_IDENTITY=;…;Max-Age=0` and
`Set-Cookie: KEYCLOAK_SESSION=;…;Max-Age=0`, then the login page (or
`login_required` under `prompt=none`).

### 0.2 What the SSO redirect carries

```
HTTP/1.1 302 Found
Set-Cookie: AUTH_SESSION_ID=…
Set-Cookie: KC_AUTH_SESSION_HASH="…";Max-Age=60
Cache-Control: no-store, must-revalidate, max-age=0
Set-Cookie: KC_RESTART=…
Set-Cookie: KEYCLOAK_IDENTITY=…
Set-Cookie: KEYCLOAK_SESSION=…;Max-Age=36000
Location: <redirect_uri>?state=…&session_state=…&iss=…&code=…
Referrer-Policy / Strict-Transport-Security / X-Content-Type-Options / X-Robots-Tag
content-length: 0
```

**Five cookies, always** - measured on a jar holding all four, on a jar holding
`KEYCLOAK_IDENTITY` alone, and on three consecutive requests. There is no
"only the ones that moved" rule here, unlike the first `GET /auth`.

`X-Frame-Options` and `Content-Security-Policy` are absent, which is what
`httpx.WriteAuthorizationRedirect` already writes, and the `Location` key order
is `state, session_state, iss, code`, which is what
`authorizationCodeLocation` already builds. Both are re-confirmed here rather
than inherited.

### 0.3 The three values carried out of the original login

```
first login    session_state=g7h_qqxBbCPdvNFDGdOJyFiB   auth_time=1788113847
SSO redirect   session_state=g7h_qqxBbCPdvNFDGdOJyFiB   auth_time=1788113847  iat=1788113850
```

- The **`session_state` is the original user session id**, three seconds later
  and with a different `iat`.
- `AUTH_SESSION_ID` on the SSO redirect base64url-decodes to
  `g7h_qqxBbCPdvNFDGdOJyFiB.<86 chars>`: **the original session id inside a
  fresh `AUTH_SESSION_ID`**, with a new opaque half.
- The access token's **`auth_time` is the original login's**, not the SSO
  request's.
- The `sid` is the same, so **no second user session is created**, and the
  **first login's refresh token still works** afterwards - measured directly.
- The same holds at a **different client**: `sso-b` on `sso-a`'s jar answered a
  code whose token carries the same `sid` and the same `auth_time`.

`KC_AUTH_SESSION_HASH` and `KEYCLOAK_SESSION` are **stable for the life of a
user session**: three SSO redirects on a jar holding `KEYCLOAK_IDENTITY` alone
all emitted the value the original login had set, and a second, independent
login emitted a different one.

### 0.4 `prompt`

Read as a **set of space-separated tokens**, compared **case-sensitively**.
Measured against a signed-in jar and an empty one:

| `prompt` | already signed in | not signed in |
|---|---|---|
| absent | 302 code | 200 login page |
| `none` | **302 code** | 302 `error=login_required` |
| `login` | 200 **re-authentication** page | 200 login page |
| `consent` | 302 code (client not `consentRequired`) | 200 login page |
| `select_account` | 302 code | 200 login page |
| `create` | **400 page, `Registration not allowed`** | 400 page, same |
| `bogus` | 302 code | 200 login page |
| `NONE` | 302 code | 200 login page |
| `` (empty) | 302 code | 200 login page |
| `none login` | **302 `login_required`** | 302 `login_required` |
| `none consent` | 302 code | 302 `login_required` |
| `login consent` | 200 re-authentication page | 200 login page |

Four things a reader would get wrong:

1. **An unrecognised value is ignored, not an error.** `prompt=bogus` and
   `prompt=NONE` behave exactly as an absent `prompt`. Only `create` is a
   rejection, and only because registration is disabled on `master`.
2. **`none` is not "must be the only value".** `none login` is
   `login_required` and `none consent` is a code. The rule is that `none`
   forbids interaction and `login` always demands it, so the two conflict;
   `consent` demands it only when consent is actually needed.
3. **`prompt=login` on a signed-in browser serves a different page from the
   anonymous login page** - 7975 bytes against 6824, `data-page-id="login-login"`
   on both. The difference is a readonly `kc-attempted-username` holding the
   signed-in user, a `Please re-authenticate to continue` alert, and a
   `Restart login` button pointing at
   `/realms/{realm}/login-actions/restart?client_id&tab_id&client_data&skip_logout=false`
   - a seventh browser endpoint nobody has measured.
4. **`prompt=consent` on a `consentRequired` client whose consent is already
   granted re-asks**: 302 to
   `/login-actions/required-action?execution=OAUTH_GRANT&…`, skipping the login
   because the session is live. Without `prompt=consent` the same request is a
   code.

`prompt=none` on a `consentRequired` client whose consent has been revoked
answers **`error=interaction_required`**, not `consent_required`.

**`prompt=none` sets no `KC_RESTART`.** Every other path through `/auth` sets
one; the `prompt=none` paths - the code and the `login_required` rejection alike
- emit four cookies and two cookies respectively, and neither includes
`KC_RESTART`. It is *never set*, not *cleared*: there is no `Max-Age=0`
`KC_RESTART` on any `prompt=none` response.

### 0.5 `max_age`

| `max_age` | signed in, session 0s old | signed in, session minutes old | not signed in |
|---|---|---|---|
| `0` | 302 code | 200 re-authentication page | 200 login page |
| `1` | 302 code | 200 re-authentication page | 200 login page |
| `3600` | 302 code | 302 code | 200 login page |
| `-1` | 200 re-auth page | 200 re-auth page | 200 login page |
| `abc` | **400 page, `Invalid Request`** | same | same |
| `` (empty) | **400 page, `Invalid Request`** | same | same |

So it is a freshness comparison, `now - auth_time > max_age` forces
re-authentication, and `max_age=0` on a session created in the same second is a
code. Combined with `prompt=none`, a failed freshness check is
`error=login_required`.

### 0.6 The rejection order, with the two new checks placed

The ten steps `authorize.go` already documents, with `max_age`'s parse inserted
between the bearer-only check and the redirect URI, and `prompt` at the end
beside `prompt=none`. Each adjacency was driven with two faults at once:

```
 1. realm                       404 {"error":"Realm does not exist"}
 2. client                      400 page "Client not found."
 2b. bearer-only                403 page "Bearer-only applications are not allowed…"
 2c. max_age unparseable        400 page "Invalid Request"      <- NEW
 3. redirect_uri                400 page "Invalid parameter: redirect_uri"
    --- everything below is a 302 to the redirect URI ---
 4..9  unchanged
 10. prompt=create              400 page "Registration not allowed"   <- NEW
 10. prompt=none, no session    login_required
```

The pairs that place `max_age`:

```
max_age=abc + unknown client_id   -> "Client not found."     client wins
max_age=abc + bearer-only client  -> the 403 page            bearer-only wins
max_age=abc + bad redirect_uri    -> "Invalid Request"       max_age wins
max_age=abc + no response_type    -> "Invalid Request"       max_age wins
max_age=abc + bad scope           -> "Invalid Request"       max_age wins
max_age=abc + prompt=none         -> "Invalid Request"       max_age wins
```

and the pairs that place `prompt=create`:

```
prompt=create + bad redirect_uri     -> "Invalid parameter: redirect_uri"
prompt=create + no response_type     -> 302 invalid_request
prompt=create + duplicated zz        -> 302 duplicated parameter
prompt=create + missing challenge    -> 302 Missing parameter: code_challenge
prompt=create alone                  -> 400 page "Registration not allowed"
```

**The two new pages do not agree about `Cache-Control`**, and that refutes a
line in AGENTS.md. Measured side by side on one container:

```
GET /auth  max_age=abc     400 page   no Cache-Control at all
GET /auth  prompt=create   400 page   Cache-Control: no-store, must-revalidate, max-age=0
```

AGENTS.md's three-endpoint table says `/auth`'s 400 and 403 pages carry no
`Cache-Control`. That is true of the six rejections it was measured on and false
of a seventh. The predictor is not the endpoint: it is **how far the request
got**. `max_age` fails during parameter parsing; `prompt=create` fails inside
the authentication flow, after an authentication session exists, and picks up
the flow's `Cache-Control` on the way out.

---

## 1. The device grant's browser half

### 1.1 `/realms/{realm}/device` and `/protocol/openid-connect/auth/device` are one endpoint at two paths

Measured in both directions:

```
POST /realms/master/device                        + client_id=dev-a   200, mints a device_code
POST /protocol/openid-connect/auth/device         + client_id=dev-a   200, mints a device_code
POST /realms/master/device                        + device_user_code  401 invalid_client
POST /protocol/openid-connect/auth/device         + device_user_code  401 invalid_client
GET  /realms/master/device                                            200 verification page
GET  /protocol/openid-connect/auth/device                             200 verification page
GET  /realms/master/device?user_code=<valid>                          302 to login-actions
GET  /protocol/openid-connect/auth/device?user_code=<valid>           302 to login-actions
```

Four probes on each path, identical answers. So this is not two endpoints that
resemble each other: it is one JAX-RS resource mounted twice.

**And that makes the theme's own verification form unusable.** The page at
`GET /realms/{realm}/device` renders

```html
<form id="kc-user-verify-device-user-code-form" action="/realms/master/device" method="post">
  <input id="device_user_code" name="device_user_code" value="" type="text">
```

and submitting it - with the page's own cookies, with no cookies, with a valid
user code, with an invalid one, with the code under a different parameter name
and with the code on the query - answers **401
`{"error":"invalid_client","error_description":"Invalid client or Invalid client
credentials"}`** every time, because the POST is the device *authorization
request* and no `client_id` was sent. Six probes. A user who types the code into
the page cannot approve anything; the only route through is
`verification_uri_complete`, the GET.

### 1.2 The route a user code actually takes

```
GET  /realms/master/device?user_code=GOUN-RIRO
  302 -> /realms/master/login-actions/authenticate?client_id=dev-a&tab_id=<new>&client_data=e30
  Cache-Control: no-store, must-revalidate, max-age=0
  Set-Cookie: AUTH_SESSION_ID, KC_AUTH_SESSION_HASH, KC_RESTART
  no X-Frame-Options, no Content-Security-Policy

GET  that location
  200 login page, data-page-id="login-login", 6664 bytes

POST it with credentials
  302 -> /realms/master/login-actions/required-action?execution=OAUTH_GRANT&client_id=dev-a&tab_id=…&client_data=e30
  no cookies at all

GET  that location
  200 consent page, data-page-id="login-login-oauth-grant", 5276 bytes
  <form method="POST" action="/realms/master/login-actions/consent?client_id=dev-a&tab_id=…&client_data=e30">
    <input type="hidden" name="code" value="<43-char session code>">
    <button name="accept">  <button name="cancel">

POST accept
  302 -> http://localhost:8112/realms/master/device/status      (absolute)
  Set-Cookie: KC_RESTART cleared, KEYCLOAK_IDENTITY, KEYCLOAK_SESSION
POST cancel
  302 -> http://localhost:8112/realms/master/device/status?error=access_denied
  no cookies at all
```

`client_data=e30` is `{}` - the device flow has no redirect URI, no response type
and no state, so the browser's restart hint is an empty object rather than
absent.

Polling after accept returns a token set; polling after cancel returns
`{"error":"access_denied","error_description":"The end user denied the
authorization request"}`, which is the string `device.go` already carries.

### 1.3 `POST /login-actions/consent`

| request | answer |
|---|---|
| `accept` | 302 to the flow's target, session cookies set |
| `cancel` | 302 with `error=access_denied` |
| **neither** `accept` nor `cancel` | 302 as though `accept` |
| `accept` **and** `cancel` together | 302 as though `cancel` |
| a **wrong** `code` with `accept` | 302 as though `accept` - the code is not checked |
| **no** `code` at all with `accept` | 302 as though `accept` |
| no cookies | 400 page, `Restart login cookie not found. …` |
| the same accept replayed | 302 **restart** to `/login-actions/authenticate` |
| `GET` on the path | 404 `{"error":"HTTP 404 Not Found"}` |

Two of those look like defects and are the contract. **`cancel` wins over
`accept`** when both are present, and **the absence of both is an approval** -
so the endpoint decides on `cancel` alone and treats everything else as consent.
And the hidden `code` the page renders is **not validated**: `code=BOGUS` with
`accept` granted the consent and redirected with a real authorization code, on a
flow whose consent had been revoked immediately before. The authentication
session cookie and the `tab_id` are the whole of the authority.

### 1.4 The browser flow's consent, and where it is stored

`con-a` is `consentRequired`. Its login redirects to the same
`required-action?execution=OAUTH_GRANT` page, and `accept` redirects **to the
client** with `state, session_state, iss, code` and the three login cookies;
`cancel` redirects to the client with `error=access_denied&state=…&iss=…` -
three keys, **no `error_description`**.

The grant is **remembered per (user, client)**: after one `accept`, later logins
at that client skip the consent page entirely. `DELETE
/admin/realms/{realm}/users/{id}/consents/{clientId}` answers 204 when one
exists and 404 when it does not, which is how each probe above was given a fresh
consent.

### 1.5 `/realms/{realm}/device/status`

200 on every input, `data-page-id="login-info"`, **no `Cache-Control` at all**,
and the instruction is the only thing that moves:

```
(no query)          3616 bytes  You may close this browser window and go back to your device.
?error=             3616 bytes  (the same)
?error=access_denied 3697 bytes Consent denied for connecting the device.
?error=bogus        3742 bytes  You may close this browser window and go back to your device and try connecting again.
```

An empty `error=` is the no-error page, and an unrecognised value is its own
third page rather than either of the other two.

### 1.6 `/login-actions/required-action`

`execution=OAUTH_GRANT` is the consent page. An unknown execution is **400**,
`data-page-id="login-error"`, instruction `invalid_request`, with
`Cache-Control: no-store, must-revalidate, max-age=0`.

---

## 2. F65: the logout confirmation page

The full grid, each row on its own fresh login:

| browser session | `id_token_hint` | `post_logout_redirect_uri` | answer |
|---|---|---|---|
| live | no | no | 200 `Logging out` |
| live | no | **yes** | **200 `Logging out`** |
| live | yes | no | 200 `You are logged out` |
| live | yes | yes | 302 |
| none | no | no | 200 `Logging out` |
| none | no | yes | **302** |
| none | yes | no | 200 `You are logged out` |

**The browser session changes exactly one cell**: no hint plus a target. Gloak
serves the 302 there unconditionally today, which is the divergence F65
describes. Everything else Gloak already answers correctly.

The confirmation page is 200, `Cache-Control: no-cache`,
`data-page-id="login-logout-confirm"`, heading `Logging out`, and it **ends
nothing** - `GET /auth` immediately afterwards still answers a code. It sets one
cookie, `AUTH_SESSION_ID`, and renders

```html
<form method="POST" action="/realms/master/protocol/openid-connect/logout/logout-confirm?client_id=sso-a&tab_id=…">
  <input name="session_code" value="…"> <input name="confirmLogout" value="Logout">
```

`POST` to that path answers **302 to the target carrying `state` and nothing
else**, `Cache-Control: no-cache`, clearing `KEYCLOAK_IDENTITY` and
`KEYCLOAK_SESSION`.

---

## 3. What this cut builds

`internal/oidc` only, plus the catalogue and its goldens.

1. **`authsession.go`** gains the session hash derivation and the consent store.
   `KC_AUTH_SESSION_HASH` stops being a random value minted per authentication
   session and becomes `base64std(HMAC-SHA512(realm HMAC key, sessionID))`
   truncated to 48 bytes. That makes the measured invariant - one user session,
   one stable value, re-emitted on every SSO redirect - hold by construction
   rather than by storing a string that has to outlive the authentication
   session that minted it. The value is opaque to a client either way; what is
   measured is its length, its alphabet and its stability, and all three hold.
2. **`sso.go`**, new: reading `KEYCLOAK_IDENTITY`, the `prompt` set, the
   `max_age` comparison, and the redirect that reuses the session.
3. **`authorize.go`**: `max_age`'s parse at step 2c, `prompt=create` and the SSO
   branch at step 10, and `beginLogin` learning to skip `KC_RESTART`.
4. **`consent.go`**, new: `GET /login-actions/required-action`,
   `POST /login-actions/consent`, and the in-memory consent grants.
5. **`device.go` / `devicestore.go`**: `GET` on both device paths, `POST` on
   `/realms/{realm}/device`, `/device/status`, and the approval wiring into the
   authentication session.
6. **`logout.go`**: the one cell F65 names.
7. **`httpx`**: `WriteThemeConsentPage`, `WriteThemeDeviceCodePage`, and a
   `Cache-Control`-less variant of the redirect writer where one is measured.

**What it does not build**: the theme's markup. Every page here is served as its
measured envelope with Gloak's placeholder body and a real `<form>` where a
fixture has to read one, which is the line the login cut drew. `prompt=login`'s
re-authentication page is served as the ordinary login page - the branch is
right, the 1151 bytes of difference are not reproduced - and
`/login-actions/restart` is filed rather than built.

## 4. Cases

New `Implemented` cases under `oidc/authorization`, `oidc/device` and
`oidc/logout`, plus the promotion of `oidc/device/poll-access-denied` out of
`Pending` and out of `parkedGoldens`.

## 5. What the tests must pin that a golden cannot

- That `KEYCLOAK_IDENTITY` alone decides, and the other three cookies do not.
- That the SSO redirect's `session_state` is the **original** session id and its
  `auth_time` the original login's.
- That the first login's refresh token still works afterwards.
- That `prompt=none login` is `login_required` on a live session - a golden
  cannot express "two tokens in one parameter" against a signed-in jar.
- That `cancel` beats `accept` and that the absence of both is an approval.
- That `max_age`'s page carries no `Cache-Control` and `prompt=create`'s does.
