# P8: required actions at login

Branch `feat/p8-required-actions-at-login`. Measured 2026-08-31 against a live
Keycloak 26.7.1, container `kc-reqact` on 8121, checked before any probe was
trusted: `docker ps` showed that container alone on the port and the container
log said `Keycloak 26.7.1 on JVM`. Removed afterwards.

The plan, with the full state machine, is
`docs/superpowers/plans/2026-08-31-p8-required-actions-at-login.md`.

`main` was merged mid-flight, after the javamap-vectors-and-prefix-masks round
landed. It merged clean and touched `internal/javamap`, `catalog_test.go` and one
handover. Every finding below was re-checked against the merged tree: findings 3
and 4 still hold - `oidc/authorization/max-age-invalid` is still `Recorded` and
its committed golden still holds the `ynxld` hash a fresh `make record`
overwrites - and the parity delta is the same +3 against the new merge base.
`catalog_test.go`'s new prefix-mask ratchet passes on this branch's one new
`VolatileHeaders` entry.

## Measurements

### The queue

A user's `requiredActions` is intersected with the realm's **enabled**
registered providers and served in the provider's **priority** order.

- **Priority decides, not the array order.** `["UPDATE_PASSWORD","UPDATE_PROFILE"]`
  and `["UPDATE_PROFILE","UPDATE_PASSWORD"]` were both served `UPDATE_PROFILE`
  first (priority 40 against 57). The admin API does not even preserve the array
  order - both writes read back the same way round.
- **A disabled provider is skipped and its alias is left on the user.**
  `TERMS_AND_CONDITIONS` completes the login and is still in the representation
  afterwards. That is where `enabled` is consumed: it decides whether the action
  is served, never whether it is stored.
- **An alias no provider is registered under is dropped at the admin write.**
  `PUT` with `["NOT_A_REAL_ACTION"]` answers 204 and reads back `[]`.
- **The action outranks the consent.** A `consentRequired` client whose user
  carries `UPDATE_PASSWORD` is sent to `execution=UPDATE_PASSWORD`, and
  completing it answers 200 with the consent page. `OAUTH_GRANT` is the last
  member of one queue, not a stage beside it.
- **The clear is per action, at the moment that action succeeds.** With
  `UPDATE_PROFILE` and `UPDATE_PASSWORD` queued, the representation already read
  `["UPDATE_PASSWORD"]` and the new names were already stored while the password
  page was still on screen.

### What a login answers

Tokens are **withheld, not issued and then restricted**. No code is minted until
the queue is empty; the 302 to the action sets **no cookies at all**, and the
three cookies (`KC_RESTART` cleared, `KEYCLOAK_IDENTITY`, `KEYCLOAK_SESSION`)
arrive from whatever finishes the flow. The redirect's key order is
`execution, client_id, tab_id, client_data`, absolute, identical to the consent
redirect with the alias in place of `OAUTH_GRANT`.

A **second** action is served **in place**: submitting the first answers 200 with
the next action's page, not a 302 to it. Only the end of the queue redirects.

### The six-cell grid on `/login-actions/required-action`

Twelve requests, `GET` and `POST` for each cell, on a live `UPDATE_PASSWORD` tab.
The two verbs agree on all six rows:

```
session_code  execution   answer
present       matches     the action runs
present       mismatched  302 -> required-action?execution=<the tab's own>
present       absent      302 -> required-action?execution=<the tab's own>
absent        matches     200, the step's page
absent        mismatched  200, "Page has expired"
absent        absent      200, the step's page
```

A stale session code takes the same 302 a mismatched execution takes. A `GET`
carrying a session code **submits**, with whatever the body holds - nothing, for
a `GET` - which is the rule `GET /login-actions/authenticate` already follows.

### The direct grant

```
400 application/json Cache-Control: no-store
{"error":"invalid_grant","error_description":"Account is not fully set up"}
```

- **Checked after the password.** The same user with a wrong password answers
  `Invalid user credentials`, so it is not an enumeration oracle.
- **It reads `requiredActions` raw.** No enabled filter, no provider consulted.
  A user carrying only the *disabled* `TERMS_AND_CONDITIONS` completes the
  browser login and is refused tokens, and so do `delete_account`,
  `UPDATE_EMAIL`, `delete_credential`, `idp_link` and `update_user_locale` -
  **seven aliases on which the two endpoints disagree about one user.**
- **`Account disabled` outranks it**, and is itself checked after the password.

### Which actions this container regime can reach

| alias | reachable | completable |
|---|---|---|
| `UPDATE_PASSWORD` | yes | yes |
| `UPDATE_PROFILE` | yes | yes |
| `CONFIGURE_TOTP` | yes | **yes, with no device** |
| `VERIFY_EMAIL` | only when `emailVerified` is false | **no - 500, no SMTP** |
| `webauthn-register`, `webauthn-register-passwordless` | yes | no |
| `CONFIGURE_RECOVERY_AUTHN_CODES` | yes | no |
| `VERIFY_PROFILE` | self-satisfied on a complete profile, and clears | n/a |
| `delete_credential`, `idp_link`, `update_user_locale` | landing self-completes, alias stays | n/a |
| `TERMS_AND_CONDITIONS`, `delete_account`, `UPDATE_EMAIL` | no - disabled | n/a |

**`CONFIGURE_TOTP` needing a device is false.** The page carries `totpSecret` in
a hidden input and the HMAC key is that secret's **raw ASCII bytes**, not a
base32 decoding of it - which is why the first attempt failed and the second
succeeded. Three lines of Python complete it, creating an `otp` credential with
the submitted `userLabel`. What it needs is a credential type Gloak does not
model, which is a different reason from "a device".

**`VERIFY_EMAIL` without SMTP is the unmeasurable one, and its refusal is the
contract**, exactly as CIBA's 503 is: 500, the theme error page,
`Failed to send email, please try again later.`,
`Cache-Control: no-store, must-revalidate, max-age=0`. `start-dev` configures no
SMTP and neither does Gloak, so this is the answer for every realm this project
can serve.

### `kc_action` on `/auth`

It exists, and it is measured and deliberately not built - see the dispositions.

- forces an action on a user carrying none, on the credential path and on the
  SSO path alike;
- **joins the queue rather than jumping it**: `kc_action=CONFIGURE_TOTP` (54)
  with `UPDATE_PROFILE` (40) queued served `UPDATE_PROFILE` first;
- **leaves nothing on the user** when abandoned - the representation is still
  `[]` and the direct grant still works, so it is per authentication session;
- the completed redirect gains **two parameters between `iss` and `code`**:
  `state, session_state, iss, kc_action, kc_action_status, code`;
- **`kc_action`'s echoed value is not the same kind of thing in the two
  outcomes.** On success it is the alias
  (`kc_action=UPDATE_PASSWORD&kc_action_status=success`); on failure it is the
  **realm's username-password-form execution id** - the very UUID the login
  form's own `execution` carries -
  (`kc_action=3e1b357a-…&kc_action_status=error`). An unknown value, an empty
  one, a lower-cased one and a **disabled** provider's alias all take the failure
  branch, and the login completes;
- repeated, it is `/auth`'s ordinary `duplicated parameter`.

## Entries for AGENTS.md's "Things that look like bugs and are not"

- **A required action is a queue in the *provider's* priority order, and the
  user's array order is not even kept.** A user written
  `["UPDATE_PASSWORD","UPDATE_PROFILE"]` and one written the other way round are
  both served `UPDATE_PROFILE` first, because its provider is priority 40 against
  57 - and the admin API reads both writes back the same way round, so the array
  is a set that happens to be serialised in some order. Reading it in order is
  the obvious implementation and it is reading something Keycloak does not store.
  The consent is the **last member of that queue**, not a stage beside it: a
  `consentRequired` client whose user carries `UPDATE_PASSWORD` is sent to the
  action first, and completing the action answers 200 with the consent page.
- **`enabled` on a required action means "not served", never "not stored".** A
  user carrying only the disabled `TERMS_AND_CONDITIONS` completes the browser
  login and the representation still shows the alias afterwards. Two neighbouring
  providers express "nothing to do" two different ways as well: `VERIFY_PROFILE`
  is **removed** from the user by a login that never redirected, while
  `delete_credential`, `idp_link` and `update_user_locale` are left on it.
  Clearing all four would make an administrator's `idp_link` vanish on first
  login.
- **The browser login and the direct grant disagree about what "not fully set up"
  means, on seven aliases.** The browser flow asks "is there an enabled provider
  with something left to do"; the direct grant reads `requiredActions` **raw** -
  no enabled filter, no provider consulted. So one user carrying only the
  *disabled* `TERMS_AND_CONDITIONS` logs in through the browser and is refused
  `{"error":"invalid_grant","error_description":"Account is not fully set up"}`
  at the token endpoint, and the same holds for `delete_account`,
  `UPDATE_EMAIL`, `delete_credential`, `idp_link` and `update_user_locale`.
  Sharing one predicate between the two endpoints is the obvious saving and it is
  wrong on all seven.
- **The direct grant's two account refusals are both checked *after* the
  password.** A disabled user with the right password answers `Account disabled`
  and with a wrong one answers `Invalid user credentials`; a user with a pending
  action answers `Account is not fully set up` with the right password and
  `Invalid user credentials` with a wrong one. Checking either in front of the
  credential is the obvious order and it turns the token endpoint into an
  account-enumeration oracle. Gloak answered `Invalid user credentials` for a
  disabled user until 2026-08-31, from a check that ran before the password.
- **On `/login-actions/required-action` the session_code decides and the verb
  decides nothing.** Measured as a twelve-cell grid, `GET` and `POST` for each of
  six combinations, and the two verbs agree on every row: with a session code a
  matching execution runs the action and a mismatched or absent one is a **302
  re-issuing the landing**; without one a matching or absent execution serves the
  page and a mismatched one is **200 "Page has expired"**. A stale session code
  takes the mismatched-execution branch rather than the restart branch. So a
  `GET` carrying a session code *submits* - the rule
  `GET /login-actions/authenticate` already follows - and a matrix that varied the
  verb alone would have found the two agreeing and concluded the verb was the
  variable. Gloak answered a 400 to any execution that was not `OAUTH_GRANT`
  until this was measured, which was wrong on five of the six rows.
- **`kc_action`'s echoed value is an alias on success and a flow execution id on
  failure.** `kc_action=UPDATE_PASSWORD` completed answers
  `kc_action=UPDATE_PASSWORD&kc_action_status=success`; anything unusable -
  unknown, empty, wrong case, or a **disabled** provider's alias - completes the
  login and answers `kc_action=<the realm's username-password-form execution
  id>&kc_action_status=error`, the same UUID the login form's own `execution`
  carries. One parameter name, two kinds of value, decided by the outcome. Both
  add **two** parameters between `iss` and `code`, so the code-carrying
  redirect's key order is not fixed either.
- **`CONFIGURE_TOTP` does not need a device and `VERIFY_EMAIL` does need SMTP.**
  The TOTP page carries `totpSecret` in a hidden input and the HMAC key is that
  secret's **raw ASCII bytes**, not a base32 decoding of it - the obvious reading
  is base32 and it produces a code the server rejects. So the action is
  completable from a shell, and what stops Gloak is a credential type it does not
  model. `VERIFY_EMAIL` with `emailVerified` false is **500, the theme error page,
  "Failed to send email, please try again later."** on a default `start-dev`, and
  that refusal is the contract in the same sense CIBA's 503 is. With
  `emailVerified` true the same landing 302s to the client and **clears the
  action**, so one alias has two measured outcomes and neither is a stub.
- **`Account is not fully set up` has a second cause that has nothing to do with
  `requiredActions`, and it is a property of the *realm*.** A user with no
  `email`, no `firstName` and no `lastName` and an **empty** `requiredActions` is
  refused it in a realm created through `POST /admin/realms` and is served a
  token in `master`. The difference is
  `GET /admin/realms/{realm}/users/profile`: a created realm declares
  `"required":{"roles":["user"]}` on those three attributes and `master` declares
  no `required` key at all. Editing master's configuration to add it makes master
  refuse, including its own administrator. Each of the three fields alone is
  enough; `emailVerified` is not one of them.

## Findings that contradict a document, and what happened to each

1. **`internal/oidc/consent.go`'s own comment and code.** It recorded "a bogus
   execution on a jar holding a live authentication session: 400, the theme error
   page, `invalid_request`". Re-measured on a consent-only tab: **200 "Page has
   expired"**, and an *absent* execution serves the consent page rather than
   being refused. **Fixed on this branch**, along with the test that asserted it
   (`TestRequiredActionRefusesAnUnknownExecution`, now
   `TestRequiredActionAnswersAnUnknownExecutionTheExpiredPage`). The old probe
   was not careless - it drove a browser mid-flow, which an earlier mutation had
   forced - but it never sent an execution that was *absent* rather than wrong,
   and that unbroken request is the one that told the two rules apart.

2. **The observed document's "A user in a created realm cannot log in without a
   full profile".** It explains the split as "what differs is the user, not the
   realm: `master`'s bootstrapped administrator carries `is_temporary_admin`".
   **Both halves are false.** A user in a created realm carrying
   `is_temporary_admin` is still refused, so the attribute exempts nothing; and
   master's own `admin`, attribute and all, is refused the moment master's
   user-profile configuration marks the three attributes required. The cause is
   the realm's user-profile configuration and nothing about the user. **Not
   fixed in the document** - it is one of the documents this cut may not edit -
   and pinned on the branch by
   `TestAnIncompleteProfileIsNotAnActionInMaster`, whose comment carries the
   correction so the next reader does not "fix" Gloak towards a rule master does
   not have. **This one nearly went the other way**: an earlier commit on this
   branch implemented the computed condition *with* an
   `is_temporary_admin` exemption invented from that paragraph, broke two
   existing conformance fixtures, and was reverted when master was measured
   directly. A fabricated exemption on the login path is the worst thing this cut
   could have shipped: without it, the same code locks the administrator out of
   the server on first start.

3. **AGENTS.md: "`make record` is silent on a clean checkout - 433 rewritten with
   identical bytes, none moved - so any diff is one to read."** It is not.
   `make record` on this branch's merge base rewrites **four** goldens with a
   different `/resources/<hash>/` cache-busting segment:
   `oidc/authorization/max-age-invalid`, `oidc/authorization/prompt-create`,
   `oidc/device/status-page` and `oidc/device/verification-page`. **Not fixed** -
   the fix is `case_test.go`'s `parkedGoldens`, which this cut may not edit. The
   four churned bytes were reverted rather than committed.

4. **AGENTS.md's parked-golden bullet, by implication.** It says "Four
   login-theme pages are the ones that churned" and that `GoldenIsAsserted`
   stopped it. Eight goldens in the tree carry the `/resources/<hash>/` segment
   and they split **four/four**: the four `Pending` ones are parked and untouched
   (their committed bytes still hold `l3kth` and `fl8wm`, hashes from older
   container starts), and the four above are `Recorded`, so the recorder rewrites
   them every run. The churn was half fixed, and the half that remains was
   introduced *after* F72 by the cut that added those four as `Recorded`.

5. **F104's own description.** "`enabled` and `defaultAction` on a required
   action are consumed by nothing" names the admin half. The larger half is that
   `internal/oidc` never read a user's `requiredActions` **on any endpoint**, so
   the divergence was on two: the browser login *and* the direct grant. Nothing
   in the follow-up would have led a reader to the token endpoint. The briefing
   for this cut described it the same way.

6. **A harness limit worth writing down.** A case cannot assert a header's
   *absence*: `AssertHeaders` naming a header the golden does not have fails with
   "header Set-Cookie is asserted but absent from the golden". That is exactly
   the most interesting thing about the required-action redirect - it sets no
   cookies where the credential POST that ends in a code sets three - so the
   absence is pinned by `internal/oidc`'s own test instead.

## Follow-up dispositions

- **F104 - closed.** Both halves. `internal/oidc` now reads a user's
  `requiredActions`, and `enabled` decides whether an action is served. Its
  description understated the scope: the token endpoint was diverging too, and no
  reading of the two sentences would have found it.
- **F109 (`prompt=login` serves the plain login page) - untouched and still
  open.** It is F67's family - the envelope is right and the prose is not - and
  nothing here changes which page `prompt=login` serves. This cut adds pages to
  the same family: `Update password` and `Update Account Information` have real
  forms and placeholder styling, and four more (`Mobile Authenticator Setup`,
  `Passkey Registration` twice, `Recovery Authentication Codes`) have a measured
  heading and no form at all. All six join F109's queue rather than shortening it.
- **F103 (the flow model) - deliberately still deferred**, and this cut is the
  other side of that decision rather than an argument against it. Nothing here
  registers, edits or reorders a provider; what changed is that the data those
  twenty-one operations already write now decides a login. `executionID` is still
  a fixed hash of the realm id, and the required actions are dispatched by alias
  rather than by any flow.
- **New, worth filing.**
  1. **`kc_action` is measured and unbuilt.** The table is in the plan's §1.8.
     It is a client asserting an authority over a login where F104 is about data
     an administrator wrote, it changes the key order of the one redirect every
     completed login asserts, and its error branch echoes an execution id that
     only means something inside the flow model F103 defers. Whoever builds it
     inherits the measurements rather than the question.
  2. **The `/resources/<hash>/` churn on four `Recorded` goldens** - finding 3
     above. One-line fix in `case_test.go` plus a status change, in a file this
     cut could not touch.
  3. **A third copy of the argon2 creation parameters.** `internal/bootstrap`
     and `internal/admin` each already had one; `internal/oidc` now has a third,
     because the required action writes a password and neither of the other two
     packages was this cut's to edit. `auth.VerifyPassword` reads every parameter
     off the credential, so the copies are harmless today and nothing fails if
     one drifts. `internal/auth`'s package comment says creation belongs
     elsewhere, so a shared home needs that decision revisited.
  4. **`CONFIGURE_TOTP` is completable and Gloak cannot complete it.** The
     measurement is in the plan; what is missing is an `otp` credential type in
     `internal/model`. Gloak serves the measured heading and stops the login,
     which withholds tokens - the safe direction - but a user given that action
     cannot finish logging in.
  5. **The required-action landing page has no conformance case**, on purpose:
     its body is 10776 bytes carrying the per-container `/resources/<hash>/`
     segment, so a golden of it would churn on every run. It needs the same
     `Pending` + `parkedGoldens` treatment the four theme pages have.
  6. **An empty `email` on the profile form carries two sentences.** Measured
     `Please specify email. Please specify this field.` where an empty first or
     last name carries only the second. Gloak's placeholder page carries one
     feedback line and serves the second sentence for all three fields.
  7. **`delete_credential`, `idp_link` and `update_user_locale` lose one 302.**
     Measured, the login redirects to the action and the *landing* redirects on
     to the client, leaving the alias on the user; Gloak skips them at the login
     and reaches the identical end state one hop sooner.

## Parity before and after

```
Parity: 285 -> 288 of 526 (+3)

chapter                         before  after  delta
oidc/authorization                  14     15     +1
oidc/token                          14     16     +2
```

Three cases, all `Implemented`: the direct grant's two refusals of an account
that authenticated correctly, and the browser login's 302 to the action.
`/login-actions/*` is on no tag's operation list - F108 - so the endpoint this
cut mostly changed moves no number, and the +3 is the token and authorization
endpoints reporting what the login now does.

## Mutation testing

Twenty-three mutations, a different one per claim, each run against the *named*
test and reverted. Twenty-two were killed on the first attempt.

**One survived**, and it is a finding about the test rather than about the code.
Deleting the `!provider.Enabled` clause from `nextRequiredAction` did not fail
`TestADisabledProviderIsSkippedAndLeftOnTheUser`, because that test used
`TERMS_AND_CONDITIONS` - an alias with **no row** in `requiredActionTable`, whose
absent row already reads as "skipped". The alias was skipped for the wrong reason
and the answer never moved. The test now has a first subtest that disables
`UPDATE_PASSWORD`, a provider Gloak would otherwise serve, and the mutation dies.

One more mutation broke the build rather than failing (removing the only use of
`slices`) and was rewritten before it counted as either.
