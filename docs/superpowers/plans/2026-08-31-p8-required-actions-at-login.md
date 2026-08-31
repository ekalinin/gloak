# P8: required actions at login

Measured 2026-08-31 against a live Keycloak 26.7.1, container `kc-reqact` on
8121, realm `probe`, public standard-flow client `pc`. Every value below came off
that container; nothing here is written from memory or from the follow-up's
description.

The port was checked before any probe was trusted: `docker ps` showed `kc-reqact`
alone on 8121 and `GET /realms/master` answered a Keycloak 26.7.1 realm
representation, with the container log confirming `Keycloak 26.7.1 on JVM`.

## 0. Why this cut exists, restated from the measurement rather than the follow-up

F104 says `enabled` and `defaultAction` on a required action "are consumed by
nothing". That is true and it is the smaller half. The larger half is that
**`internal/oidc` never reads a user's `requiredActions` either**, on any
endpoint. Measured against Gloak today:

- a user carrying `UPDATE_PASSWORD` logs in through the browser flow and gets a
  code;
- the same user gets tokens from the direct grant.

Keycloak refuses both. So a temporary password in Gloak is an ordinary password
on **two** endpoints, not one, and the token endpoint is the one no reading of
F104 would have predicted.

## 1. The measured state machine

### 1.1 What decides that an action is served at all

A user's `requiredActions` is intersected with the realm's **enabled** registered
providers, and the survivors are served in the provider's **priority** order.

Measured on the realm's own registry (`GET /authentication/required-actions`):

```
UPDATE_PROFILE                 enabled  prio  40
VERIFY_EMAIL                   enabled  prio  50
CONFIGURE_TOTP                 enabled  prio  54
UPDATE_PASSWORD                enabled  prio  57
TERMS_AND_CONDITIONS           disabled prio  20
delete_account                 disabled prio  60
UPDATE_EMAIL                   disabled prio  70
webauthn-register              enabled  prio  80
webauthn-register-passwordless enabled  prio  90
VERIFY_PROFILE                 enabled  prio 100
delete_credential              enabled  prio 110
idp_link                       enabled  prio 120
CONFIGURE_RECOVERY_AUTHN_CODES enabled  prio 130
update_user_locale             enabled  prio 1000
```

**Priority decides, not the array order.** A user written
`["UPDATE_PASSWORD","UPDATE_PROFILE"]` and a user written
`["UPDATE_PROFILE","UPDATE_PASSWORD"]` were both served `UPDATE_PROFILE` first.
Both readings of the array are therefore refuted at once - and the array order is
not even preserved by the admin API, which stored both writes as
`["UPDATE_PASSWORD","UPDATE_PROFILE"]`.

**A disabled provider is skipped and the action is left on the user.** A user
carrying only `TERMS_AND_CONDITIONS` completed the login, and the admin
representation still showed `["TERMS_AND_CONDITIONS"]` afterwards. So `enabled`
is consumed exactly here: it decides whether the action is served, never whether
it is stored.

**An alias no provider is registered under is dropped at the admin write.**
`PUT` with `["NOT_A_REAL_ACTION"]` answered 204 and the representation came back
`[]`. `TERMS_AND_CONDITIONS` stored fine, so the filter is "registered", not
"enabled".

### 1.2 What a login answers for each of the fourteen

One user, one action at a time, `emailVerified` true, profile complete:

| alias | login answers |
|---|---|
| `UPDATE_PROFILE` | 302 to the action, 200 page `Update Account Information`, inputs `email`, `firstName`, `lastName` |
| `VERIFY_EMAIL` | see 1.6 - it depends on `emailVerified`, and on SMTP |
| `CONFIGURE_TOTP` | 302 to the action, 200 page `Mobile Authenticator Setup`, inputs `totp`, `totpSecret`, `userLabel`, `logout-sessions` |
| `UPDATE_PASSWORD` | 302 to the action, 200 page `Update password`, inputs `password-new`, `password-confirm`, `logout-sessions` |
| `webauthn-register` | 302, 200 page `Passkey Registration` |
| `webauthn-register-passwordless` | 302, 200 page `Passkey Registration` - the **same heading** as the one above |
| `CONFIGURE_RECOVERY_AUTHN_CODES` | 302, 200 page `Recovery Authentication Codes` |
| `VERIFY_PROFILE` | login completes, and the action **is cleared** |
| `delete_credential` | 302 to the action, whose landing 302s straight to the client with a code; the action **stays on the user** |
| `idp_link` | as `delete_credential` |
| `update_user_locale` | as `delete_credential` |
| `TERMS_AND_CONDITIONS` | disabled: login completes, action stays |
| `delete_account` | disabled: login completes, action stays |
| `UPDATE_EMAIL` | disabled: login completes, action stays |

So there are four outcomes, not two: a page that must be completed, a landing
that completes itself and clears the action, a landing that completes itself and
leaves it, and a skip that never reaches the endpoint at all.

### 1.3 The redirect, and where the credentials go

```
POST /realms/probe/login-actions/authenticate?session_code&execution&client_id&tab_id&client_data
  -> 302 Location: http://localhost:8121/realms/probe/login-actions/required-action
                   ?execution=UPDATE_PASSWORD&client_id=pc&tab_id=…&client_data=…
     Cache-Control: no-store, must-revalidate, max-age=0
     Content-Security-Policy, and the five security headers
     **no Set-Cookie at all**
```

Key order `execution, client_id, tab_id, client_data`; the location is absolute.
That is byte for byte the shape the consent redirect already has, with the alias
where `OAUTH_GRANT` stands - so `writeRequiredActionRedirect` gains an argument
and nothing else.

The action's own form posts back to **`/login-actions/required-action` itself**,
not to a sibling path the way the consent page posts to `/login-actions/consent`.
Its query is `session_code, execution, client_id, tab_id, client_data` - the login
form's five with the alias in `execution`.

### 1.4 The six-cell grid: the session_code decides, not the verb

Measured on a live `UPDATE_PASSWORD` tab, twelve requests, `GET` and `POST` for
each cell:

```
session_code  execution   answer
present       matches     the action runs
present       mismatched  302 -> required-action?execution=<the current one>
present       absent      302 -> required-action?execution=<the current one>
absent        matches     200, the action's page
absent        mismatched  200, "Page has expired"
absent        absent      200, the action's page
```

`GET` and `POST` agree on all six rows. A `GET` carrying a session code
**submits** the action with whatever the body holds - which for a `GET` is
nothing, so it answers the page with `Please specify password.` That is the same
rule `GET /login-actions/authenticate` already follows, and it is the reason the
grid is drawn over the session code rather than over the method: a matrix that
varied the verb alone would have found the two endpoints agreeing and concluded
the verb was the variable.

**This refutes what `internal/oidc/consent.go` says today.** Its comment records
"a bogus execution on a jar holding a live authentication session: 400, the theme
error page, `invalid_request`", and the code 400s anything that is not exactly
`OAUTH_GRANT`. Re-measured on a consent-only tab, `execution=BOGUS` answers
**200 "Page has expired"**, and an **absent** execution answers the consent page.
Gloak is wrong on five of the six rows above.

### 1.5 Where the required action sits relative to everything else

- **Before the consent.** A `consentRequired` client with a user carrying
  `UPDATE_PASSWORD` redirects to `execution=UPDATE_PASSWORD`; completing it then
  answers **200 with the consent page**, whose form posts to
  `/login-actions/consent`. So `OAUTH_GRANT` is the last member of the same
  queue, not a separate stage.
- **After the disabled-account check.** A disabled user carrying
  `UPDATE_PASSWORD` gets `Account is disabled, contact your administrator.` on
  the re-served login page, not the action.
- **On the SSO path too.** A browser holding a live `KEYCLOAK_IDENTITY` whose
  user acquires an action between two `GET /auth`s is 302'd straight to
  `/login-actions/required-action` with no login page in between.
- **`prompt=none` answers `interaction_required`** for a pending action, which is
  the same code a pending consent gets.

### 1.6 Which actions this container regime can reach

- `UPDATE_PASSWORD` - **fully reachable and completable.** Submitting
  `password-new` and `password-confirm` answers the ordinary 302 to the client
  with a code and the three cookies (`KC_RESTART` cleared, `KEYCLOAK_IDENTITY`,
  `KEYCLOAK_SESSION`) - byte for byte the ending a consent accept has.
- `UPDATE_PROFILE` - **fully reachable and completable.** The three fields are
  written and visible in the admin representation immediately.
- `CONFIGURE_TOTP` - **reachable and completable with no device.** The page
  carries `totpSecret` in a hidden input, and the HMAC key is that secret's raw
  ASCII bytes rather than a base32 decoding of it - so a six-digit code computed
  in three lines of Python completes it, creating an `otp` credential carrying
  the submitted `userLabel`. "Needs a device" is false; what it needs is a
  credential type Gloak does not model.
- `VERIFY_EMAIL` - **two outcomes, one of them unreachable.** With
  `emailVerified` already true the landing 302s to the client with a code and
  **clears the action**. With `emailVerified` false it is
  **500, the theme error page, `Failed to send email, please try again later.`**,
  `Cache-Control: no-store, must-revalidate, max-age=0`, because `start-dev`
  configures no SMTP. That 500 is the contract for every realm this project can
  serve, in exactly the sense CIBA's 503 is: not a stub, and not evidence of
  anything missing.
- `webauthn-register`, `webauthn-register-passwordless`,
  `CONFIGURE_RECOVERY_AUTHN_CODES` - pages are reachable; completion needs a
  credential type Gloak does not model.
- `TERMS_AND_CONDITIONS`, `delete_account`, `UPDATE_EMAIL` - **not reachable at
  all on a default realm**, because their providers are disabled.

### 1.7 The direct grant, and the finding no reading of F104 would have produced

```
POST /realms/probe/protocol/openid-connect/token
  grant_type=password, a user carrying any non-empty requiredActions
  -> 400 application/json Cache-Control: no-store
     {"error":"invalid_grant","error_description":"Account is not fully set up"}
```

Three things about it are measured rather than assumed:

1. **It is checked after the password.** The same user with a wrong password
   answers `Invalid user credentials`, so it is not an enumeration oracle.
2. **It does not apply the enabled filter.** A user carrying only the *disabled*
   `TERMS_AND_CONDITIONS` **completes** the browser login and is **refused** the
   direct grant. So do `delete_account`, `UPDATE_EMAIL`, `delete_credential`,
   `idp_link` and `update_user_locale` - seven aliases where the two endpoints
   disagree about one user. The browser flow asks "is there an enabled action
   with something left to do"; the direct grant asks "is `requiredActions`
   empty".
3. **`Account disabled` outranks it**, and `Account disabled` is itself checked
   after the password.

That third point is a second divergence found on the way: Gloak's `passwordGrant`
answers `Invalid user credentials` for a disabled user, and checks `enabled`
*before* the password. Two things wrong in one branch, in a file this cut owns.

### 1.8 `kc_action` on `/auth`

It exists.

```
GET /auth?…&kc_action=UPDATE_PASSWORD    forces the action for a user carrying none
GET /auth?…&kc_action=CONFIGURE_TOTP     with UPDATE_PROFILE queued -> UPDATE_PROFILE first
GET /auth?…&kc_action=BOGUS              login completes
GET /auth?…&kc_action=                   login completes
GET /auth?…&kc_action=terms_and_conditions   login completes (case-sensitive)
GET /auth?…&kc_action=TERMS_AND_CONDITIONS   login completes (the provider is disabled)
GET /auth?…&kc_action=A&kc_action=B      302, error=invalid_request, duplicated parameter
```

Two measurements make it worth writing down:

- **The completed redirect gains two parameters, between `iss` and `code`**:
  `state, session_state, iss, kc_action, kc_action_status, code`.
- **`kc_action`'s echoed value is not the same kind of thing in the two
  outcomes.** On success it is the alias -
  `kc_action=UPDATE_PASSWORD&kc_action_status=success`. On failure it is the
  **realm's username-password-form execution id** - the very UUID the login
  form's own `execution` parameter carries -
  `kc_action=3e1b357a-…&kc_action_status=error`. One parameter name, an alias in
  one branch and a flow execution id in the other.

It joins the queue rather than jumping it, it works on the SSO path, and an
abandoned one leaves **nothing** on the user: the representation is still `[]`
and the direct grant still works. It is per authentication session.

## 2. What this cut builds

The **execution** of the queue, not the flow model. F103's twenty-one operations
stay deferred; nothing here registers, edits or reorders a provider. What changes
is that the data those operations already write starts deciding a login.

1. `internal/oidc/requiredactions.go` (new): the queue - a user's
   `requiredActions` intersected with the realm's enabled providers in priority
   order - and the per-alias table saying what Gloak does with each of the
   fourteen.
2. `internal/oidc/loginactions.go`: `attemptLogin` consults the queue before the
   consent.
3. `internal/oidc/consent.go`: `requiredAction` becomes the six-cell grid of 1.4
   and dispatches on the tab's current action, with `OAUTH_GRANT` as the last
   member of the queue rather than the only value the endpoint knows.
4. `internal/oidc/sso.go`: a pending action outranks the consent on the SSO path,
   and answers `interaction_required` under `prompt=none`.
5. `internal/oidc/token.go`: the direct grant refuses `Account is not fully set
   up` after the password, and the disabled user's `Account disabled` is
   corrected with it.
6. `internal/httpx`: two page writers with real forms (`Update password`,
   `Update Account Information`) and the measured headings for the four pages
   Gloak can only place an envelope under.

Three aliases execute for real: `UPDATE_PASSWORD` writes the credential,
`UPDATE_PROFILE` writes the three fields, `VERIFY_EMAIL` self-clears or answers
the measured 500. Four serve a measured heading and cannot be completed, which is
the same debt every theme page in this repository already carries. Four are
skipped, which is measured. `VERIFY_PROFILE` self-clears, which is measured.

**`kc_action` is measured here and deliberately not built.** It is an authority a
*client* asserts over a login, where F104 is about data an *administrator* has
already written; it changes the key order of the one redirect every completed
login case asserts; and its error branch echoes an execution id that only means
something inside the flow model F103 deferred. It goes in as a follow-up with the
measurements above attached, so the next cut inherits the table rather than the
question.

## 3. Tests

- `internal/oidc`: the queue's order under both array orders, the enabled filter,
  the six-cell grid, the chain to a second action, the chain to the consent, the
  per-action clear, the SSO path, `prompt=none`, and the direct grant's two
  messages and their order against the password.
- `internal/conformance`: a fixture creating a user with `UPDATE_PASSWORD`, and
  cases for the login's 302 and for the action's own 302.
- Every claim that a test now catches something is mutation-tested with a
  different mutation per claim.
