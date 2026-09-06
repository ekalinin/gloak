# The protocol remainder: ten reasons re-checked

Ten cases in `internal/conformance`'s OIDC chapters carried a written reason for
not being built. **Four of the reasons had expired, six held**, and the unit of
work here was the re-check rather than the promotion - so this document leads
with what was measured and ends with one row per reason.

Everything below was measured against a live Keycloak 26.7.1 on 2026-09-06, in a
container started for this cut and removed at the end of it.

## 1. What was measured

### 1.1 A fixture *can* put the introspecting client in an access token's audience

The reason said it could not, and it had said so since P1. Everything it said
about the rule was right - an access token's `aud` holds the clients the *user*
holds roles on **minus the issuing client** - and the conclusion did not follow.
One client cannot be both ends of that; **two can**:

```
gloak-probe-aud-introspect   confidential, owns a role, does the asking
gloak-probe-aud-issuer       confidential, direct access grants, mints the token
gloak-probe-aud-user         holds a role on each
```

```
aud                  ["gloak-probe-aud-introspect","account"]
azp                  "gloak-probe-aud-issuer"
introspection        200, "active":true, the same nineteen keys a refresh token gets
```

F18 named both routes to this - "a role on the caller assigned to the user
(P2's second cut) or an audience protocol mapper (P5)" - and the first of them
landed on 2026-08-23. Nobody came back.

### 1.2 The exclusion was not pinned by any case, and a mutation proved it

`oidc/introspection/access-token-outside-audience` looks like the case that pins
"aud excludes the issuing client". It does not. Its subject is `admin`, who holds
no role on `gloak-confidential`, so the issuer was never in the role map and
excluding it changes no byte. A mutation replacing `if c != issuingClient` with
`if c != ""` in `token.Audience` **passed that case** and was killed only by
`internal/token`'s own `TestAudienceExcludesTheIssuingClient`.

The new fixture supplies the missing input - a role on the issuing client too -
and the golden now carries both halves:

```
resource_access   gloak-probe-aud-introspect, gloak-probe-aud-issuer, account
aud               gloak-probe-aud-introspect, account
```

which is AGENTS.md's own sentence about `resource_access` and `aud` disagreeing,
asserted by a golden for the first time. `javamap.KeyOrder` places that
three-key set exactly, so no key-order retreat was needed.

### 1.3 Naming an empty `defaultClientScopes` at create empties `aud`

The first recording of the case above wrote `{"active":false}` into a file called
`active-access-token`. The cause was one field on the **issuing** client's create
body. Measured on two clients differing in that one field:

```
"defaultClientScopes":[]   scope: openid                 aud absent, resource_access absent
omitted                    scope: openid email profile   aud ["gloak-probe-aud-introspect","account"]
```

A client inherits the realm's client scopes only when it names *neither* list, so
naming an empty one takes the `roles` scope away and with it the mappers that
write `aud` and `resource_access`. Writing `"defaultClientScopes":[]` to keep a
create explicit is the tidy-up that does this, and it is silent: the token is
issued, the grant succeeds, and four claims are simply not there.

### 1.4 The implicit flow's refusal is a case, and it is an eighth data point

```
response_type=id_token token   302, error in the fragment
response_type=token            302, the same sentence
response_type=code             200, the login page          <- the control
```

The 302 carries `unauthorized_client`, the Implicit sentence, `state` and `iss`,
and **no `X-Frame-Options` and no `Content-Security-Policy`** - which is
`/auth`'s redirect-to-client rule, measured for an eighth time and now asserted
by `AssertAbsentHeaders` on a rejection carrying no cookies.

### 1.5 The front-channel logout page has a second condition, and it is the browser's cookies

The p6 handover records the condition as "a session holding a client with
`frontchannelLogout: true` **and** a `frontchannel.logout.url`". That is measured
too narrow. With exactly that client and a live browser session, six cookie
subsets, one fresh login each:

```
                                                       status  bytes
no cookies                                              302      0
KEYCLOAK_IDENTITY of the hint's own session             200   4348
KEYCLOAK_IDENTITY of another live session               200   4679
KEYCLOAK_SESSION  of the hint's own session             200   4348
KEYCLOAK_SESSION  of another live session               302      0
AUTH_SESSION_ID only                                    302      0
```

So the **request** has to identify a browser session, and the p6 sweep drove a
cookie jar throughout without ever sending the request without one - the same
shape as the hintless-logout bullet AGENTS.md already carries, where "the jar was
the variable and the hint was not", in the opposite direction.

**Gloak's gate is `len(targets.front) > 0` and has no cookie condition**, so it
serves the page where Keycloak sends a 302. That is a divergence this cut files
rather than fixes; it is the second of the two reasons the case is `Recorded`
rather than `Implemented`.

### 1.6 A probe of that page got the `tab_id` backwards, and `make record` refuted it

The page's chrome carries a `tab_id` in its `startSessionPolling` restart URL. A
probe said it was the login's tab; it is minted by the logout request:

```
login action tab_id : 1m39AiCAYRY
logout page  tab_id : BU4U7PKXZbk
```

The wrong probe grepped a whole script's output for `tab_id=`, and the only place
that string occurs in that output is the logout page itself - so it compared the
body with itself and reported a match. **What caught it was two `make record`
runs disagreeing on that one substring** while every other byte held still. A
probe that reports the same answer for every input is measuring itself, and this
one was measuring its own output twice.

### 1.7 `form_post`'s two bodies, and the `<SCRIPT>` that is on one cell of four

```
rejection   200, text/html (no charset), Cache-Control: no-store, must-revalidate, max-age=0
            694 bytes, inputs error_description, iss, state, error, no <SCRIPT>
success     200, the same envelope, 1112 bytes
            inputs code, iss, state, session_state, and a <SCRIPT>
```

The script follows neither the endpoint nor the status. Measured as a 2x2:

```
                                                  SCRIPT
GET  /auth                        rejection        no
GET  /auth                        SSO success      no
POST /login-actions/authenticate  rejection        no
POST /login-actions/authenticate  success         yes
```

Both `/auth` cells are 200s under `form_post` and disagree with the
`/login-actions` success; the `/login-actions` rejection has the same endpoint
and the same status as that success and disagrees with it. One cell of four.

Neither the login-actions success's replaceState URL nor the action it was
posted to is the other: it keeps `client_id`, `tab_id` and `client_data` and
drops the `session_code` and the `execution`.

### 1.8 The form's input order is a Java map's, and it is not the query's

`javamap.KeyOrder` places every set measured:

```
{code, iss, state, session_state}          code, iss, state, session_state
{error, error_description, state, iss}     error_description, iss, state, error
drop state                                 error_description, iss, error
drop error_description                     iss, state, error
drop both                                  iss, error
```

The query redirect emits the same four success parameters as
`state, session_state, iss, code` and the same four error parameters as
`error, error_description, state, iss`, so one response mode's order is no guide
to the other's. The three shorter sets are what make this a rule rather than two
coincidences: a hard-coded four-name order passes the first two rows and fails
the last three.

### 1.9 One response, three escapings, and a third spelling for this repository

Measured with a `state` of `a"b<c>d&e'f`:

```
form_post INPUT VALUE   a&quot;b&lt;c&gt;d&amp;e&apos;f
theme page title        a&quot;b&lt;c&gt;d&amp;e&#39;f    (Freemarker's)
html.EscapeString       a&#34;b&lt;c&gt;d&amp;e&#39;f
```

The single quote is where all three part company. And **within one response the
escaping is not uniform**: the `<FORM>`'s `ACTION` is escaped - a registered
redirect URI of `http://localhost:9999/cb?a=1&b=2` comes back with `&amp;` - and
the `<SCRIPT>`'s `history.replaceState` URL a few bytes above it is not, its `&`
separators arriving raw.

### 1.10 CIBA, re-measured

```
POST /realms/master/protocol/openid-connect/ext/ciba/auth   503
{"error":"server_error","error_description":"Failed to send authentication request"}
```

on a client carrying `oidc.ciba.grant.enabled`. `GET /admin/serverinfo` reports
`CIBA` as `"type":"DEFAULT","enabled":true`, so the feature is on and the
**channel** is what a default container has not got. All three CIBA reasons hold
exactly as written.

(The first attempt sent `/realms/master/ext/ciba/auth` and got the generic 404.
The endpoint is under `protocol/openid-connect/`. A 404 from a wrong path
measures the path.)

### 1.11 F88 is answerable now, and the answer is "the token decides"

F88 reads: "whether introspection carries `auth_time` is unmeasured - it could
not be measured from the outside: a client cannot introspect a token whose `aud`
excludes it." The two-client arrangement lifts that, and the answer is that
introspection passes the token's own claim set through:

```
password-grant access token      token has no auth_time   body has none
browser-login access token       token auth_time 1788675448   body auth_time 1788675448, third key
```

So `auth_time` is neither added nor dropped by introspection. No case was added
for it: a golden would need a browser login at the issuing client, which is a
fixture nothing else wants today.

### 1.12 One admin golden `make record` does not reproduce, and it is not this cut's

`admin/clients/evaluate-scope-mappings-not-granted`'s committed golden holds the
realm's five bootstrapped roles. Four `make record` runs on this branch all
produced **twenty-one**, adding every `gloak-probe-*` realm role earlier admin
fixtures create. The case is not `PristineRealm`, and the recorder reaches it at
position 2086 of the run where `admin/roles/create` is at position 474, so the
pollution is structural rather than anything this branch did - none of its
fixtures creates a realm role. The golden is reverted on every run here and the
file is left exactly as `main` has it.

`TestConformance` passes because the *verifier* rebuilds bootstrap plus the
case's own fixture and sees five. So the committed bytes are the verifier's
answer and not the recorder's, which is F40's shape: the case wants
`PristineRealm`. It lives in `catalog_admin.go`, which this branch may not touch.

## 2. Entries for AGENTS.md

- **Front-channel logout needs a browser, and the client's two settings are only
  half of it.** A session holding a client with `frontchannelLogout: true` and a
  `frontchannel.logout.url` answers the 200 page **only when the request carries
  the browser's own session cookies**; without them it is the ordinary 302, on
  identical inputs. Measured over six cookie subsets with a fresh login each:
  `KEYCLOAK_IDENTITY` opens it whether or not it names the session being ended,
  `KEYCLOAK_SESSION` opens it only when it does, and `AUTH_SESSION_ID` alone does
  not. The p6 sweep recorded the client's two settings as the whole condition
  because it drove a cookie jar throughout and never sent the request without
  one - the hintless-logout bullet's failure in the opposite direction. Gloak
  answers the page on the client's settings alone, which is a divergence and is
  why `oidc/logout/frontchannel` is `Recorded`.
- **`response_mode=form_post`'s parameter order is a Java `HashMap`'s, and it is
  not the query's.** The same four success parameters are `code, iss, state,
  session_state` in the form and `state, session_state, iss, code` in the query;
  the same four error parameters are `error_description, iss, state, error` in
  the form and `error, error_description, state, iss` in the query.
  `javamap.KeyOrder` places all five measured sets, including the three shorter
  ones an absent `state` or an absent `error_description` produce - which is what
  makes it a rule rather than two coincidences, since a hard-coded order passes
  the four-key rows and fails every shorter one.
- **The form_post `<SCRIPT>` is on one cell of a 2x2 and follows neither the
  endpoint nor the status.** `GET /auth`'s rejection, `GET /auth`'s SSO success
  and `POST /login-actions/authenticate`'s rejection all answer the same form
  without it; only the successful credential POST scrubs its own URL out of the
  browser's history. The URL it scrubs to is not the action it was posted to: it
  keeps `client_id`, `tab_id` and `client_data` and drops the `session_code` and
  the `execution`.
- **One response escapes two ways a few bytes apart, and this is the third
  escaper in the repository.** A form_post `INPUT`'s `VALUE` spells a single
  quote `&apos;` where the theme's Freemarker spells it `&#39;` and
  `html.EscapeString` spells it `&#39;` and a double quote `&#34;`; the
  `<FORM>`'s `ACTION` is escaped the same way as the values, and the
  `<SCRIPT>`'s `history.replaceState` URL immediately above it is **not** escaped
  at all. A shared helper is wrong on one of the three whichever spelling it
  picks.
- **A client cannot introspect its own access token, and two clients can arrange
  the rest.** Give the user a role on the introspecting client and mint the token
  at a **different** client, and the introspecting client is in `aud` and the
  introspection is `"active":true`. The catalogue records this now, and it
  records the exclusion with it: with the user also holding a role on the
  *issuing* client, `resource_access` carries that client and `aud` does not. No
  case supplied that second condition until 2026-09-06, and a mutation dropping
  the exclusion passed `access-token-outside-audience`, whose subject holds no
  role on the client that mints its token.
- **A create naming an empty `defaultClientScopes` issues tokens with no `aud`
  and no `resource_access`.** A client inherits the realm's client scopes only
  when it names *neither* list, so `"defaultClientScopes":[]` - the obvious way
  to keep a create explicit - removes the `roles` scope and with it the mappers
  that write both claims. Measured on two clients differing in that field alone:
  `scope: openid` against `scope: openid email profile`, and four claims absent
  rather than empty.
- **Introspection passes `auth_time` through rather than deciding it.** A
  browser-login access token carries one and its introspection body carries the
  same value as its third key; a password-grant token carries none and neither
  does its body. That closes the question F88 filed as unmeasurable, and what
  made it measurable is the two-client audience arrangement above.

## 3. Follow-up dispositions

| Entry | Disposition |
|---|---|
| **F51** - five response modes accepted and not transported | **Half closed.** `form_post` is transported on all four measured cells. The four remaining are `form_post.jwt`, `jwt`, `query.jwt` and `fragment.jwt`, and all four are JARM: the parameters are replaced by a signed assertion, which is a different piece of work from a transport. The entry should say four rather than five. |
| **F52** - the two disabled-flow rejections are served and under no golden | **Half closed.** `oidc/authorization/implicit-flow` is `Implemented` and covers the implicit half. The standard-flow twin still has no case, and its "a fixture client with the flag off, which is a fixture nothing else needs" is still true - `browser-client` has the implicit flow off by default and the standard flow **on**. |
| **F94** - a `Reason` naming a plan phase expires when the phase closes | **Closed.** The `Reason` it names is gone. The entry's other half stands and is worth keeping: no mechanical check reaches this, and a `\bP\d+\b` rule would cry wolf. |
| **F88** - whether introspection carries `auth_time` is unmeasured | **Closed by measurement**, §1.11. The premise - "it could not be measured from the outside" - was true of one client and false of two. |
| **F21** - introspection does not accept an ID token | **Its stated blocker is gone.** It reads "no conformance case yet, because a fixture needs the same role assignment `active-access-token` is waiting for"; `introspect-in-audience` is that fixture. What is left is the code change the entry describes, and the unmeasured question inside it - whether the audience check applies to an ID token at all - which the same fixture can now answer. |
| **F14** - the access token's `jti` prefix is measured and not reproduced | **Unchanged, and now visible.** The entry says the prefix "is invisible today ... the one endpoint that would expose a `jti` cannot be recorded yet (F15)". Two introspection goldens mask `jti` explicitly, so it is still invisible, but by a mask rather than by absence. |
| **F135** - DPoP is measured in full and not implemented | **Re-checked, unchanged.** `grep -i dpop internal/` finds a client attribute, a discovery list and a converter field, and no proof verification. |
| **F122** - the two admin logout triggers notify nobody | **Untouched.** `oidc/logout/backchannel`'s reason was re-read and holds for its own reason, which is the harness rather than the boundary. |
| **F125** - `frontchannel.logout.session.required` is measured and unread | **Still open, and now cheaper.** It says what the attribute decides "lives in the page body, which is P13's". The page body is measured and committed as a golden here, so whoever serves the markup reads the attribute in the same change. |
| **F38** - a golden cannot mask a per-request value inside an HTML body | **Extended rather than reopened.** `Case.VolatileHTMLInput` is a third frame of the same shape, with four consumers - this cut's `response-mode-form-post` and three of F146's theme pages. **One thing a note about this entry got wrong is worth recording**: `prefixMasksLeftInPlace` does **not** name `oidc/authorization/response-mode-form-post` and never did. Its two entries are `oidc/device/authorization-request` and `oidc/registration/create-client`, and both want a body-side `VolatileTail`, which is a different mechanism. Nothing came off that ratchet here. |
| **F107** - seven masks in `catalog_oidc_pending.go` were not examined | **One fewer to examine.** `active-access-token`'s first `Volatile` list copied `active-refresh-token`'s and masked `sub` over a value the fixture captures; `TestNoVolatileMaskCoversACapturedValue` reported it and the mask is gone, so the golden asserts which user the token belongs to. |
| **F40 / F53** - a golden that holds only while the catalogue's order holds | **A new instance, in another stream's file.** §1.12. `admin/clients/evaluate-scope-mappings-not-granted` wants `PristineRealm`; four recordings here disagree with its committed bytes and this branch may not edit `catalog_admin.go`. |

## 4. Parity, one row per reason re-checked

Baseline is `main` at 087053c; head is this branch.

```
chapter                before          after
oidc/authorization     25 of 27        27 of 27
oidc/ciba              10 of 12        10 of 12
oidc/introspection      4 of 5          5 of 5
oidc/logout            12 of 14        12 of 14, one Recorded
oidc/token             19 of 22        19 of 22, one Recorded
total                 498 of 541      501 of 541
```

A protocol chapter's numerator is `Implemented` and its denominator is
`Implemented + Recorded + Pending`, so promoting `oidc/logout/frontchannel` from
`Pending` to `Recorded` moves the recorded column and not the total. That is the
honest reading: the contract is in the repository and the behaviour is not
served.

| Case | Reason | Held or expired | What moved |
|---|---|---|---|
| `oidc/authorization/implicit-flow` | "the implicit flow is out of P3's scope" | **expired** - a claim about a plan phase, and F94 said so | `Pending` → `Implemented`, +1 |
| `oidc/authorization/response-mode-form-post` | F51's transport, and a missing `INPUT VALUE` frame | **held, and both halves lifted** | `Pending` → `Implemented`, +1 |
| `oidc/introspection/active-access-token` | "no fixture can put the introspecting client in an access token's audience" | **expired** - true of one client, false of two | `Pending` → `Implemented`, +1 |
| `oidc/logout/frontchannel` | "the login theme is P13, and this response is a theme page" | **expired in its wording, and a second blocker is new** | `Pending` → `Recorded` |
| `oidc/logout/backchannel` | "the harness holds one request and one response" | **held** - `Step` is a request and every capture reads a response | `Reason` dated |
| `oidc/ciba/poll-pending` | no CIBA authentication channel | **held** - re-measured, 503 | `Reason` dated |
| `oidc/ciba/poll-complete` | the same | **held** | `Reason` dated |
| `oidc/token/ciba-grant` | the same | **held** | `Reason` dated |
| `oidc/token/dpop-bound-token` | "a proof carries a per-request `iat` and a single-use `jti`" | **held, and sharpened** - the harness has no computed value at all | `Reason` gains the half it was missing |
| `oidc/token/dpop-header-invalid` | "DPoP is not implemented" | **held** | stays `Recorded`, `Reason` dated |

## 5. The mutation pass

Each mutation was applied to a clean tree, run against a **named** test, reverted,
and the revert checked with `git status`.

| Mutation | Named test | Result |
|---|---|---|
| `classifyResponseType` returns `flowStandard` for a response type naming `token` | `TestConformance/oidc/authorization/implicit-flow` | killed |
| the introspection audience guard inverted | `TestConformance/oidc/introspection/active-access-token` | killed |
| `token.Audience` keeps the issuing client | `TestConformance/oidc/introspection/access-token-outside-audience` | **survived**, and is why the fixture grew a role on the issuing client |
| `token.Audience` keeps the issuing client | `TestConformance/oidc/introspection/active-access-token` | killed, after the fixture change |
| `WriteFormPost` sorts its names instead of bucketing them | `TestAuthorizeFormPostDropsAnAbsentParameterAndReordersTheRest` | killed |
| the form_post `Content-Type` gains a charset | `TestConformance/oidc/authorization/response-mode-form-post` | killed |
| the SSO short circuit passes a replaceState URL | `TestFormPostScriptFollowsTheSuccessfulLoginAlone` | killed |
| `htmlInputMatches` drops its tag boundary | `TestHTMLInputMaskRefusesAnInputWithNoValue` | killed |
| `WriteAuthorizationRedirect` sets `X-Frame-Options` | `TestConformance/oidc/authorization/implicit-flow` | killed |

## 6. What surprised me

**That a probe of my own read its own output.** §1.6. The question was whether
the logout page's `tab_id` is the login's, and the shell one-liner that answered
it grepped a stream in which the only occurrence of that string is the page
itself. It reported a match, I believed it, and `make record` refuted it by
producing two goldens that disagreed on exactly that substring and nowhere else.
The recorder is a better probe than a probe.

**That the case which looks like it pins the audience rule does not.** §1.2.
`access-token-outside-audience` is named for the exclusion and its state cannot
express it, because its subject holds no role on the client that mints its token.
The rule has two conditions and the case supplied one; `internal/token`'s own
test is what has been holding it up.

**That one field on a fixture's create body decided whether a case measured
anything.** §1.3. `"defaultClientScopes":[]` is the kind of thing one copies from
a neighbouring fixture to keep a create explicit, and it silently removed the two
claims the case exists to assert. The first recording said `{"active":false}` and
the file was named `active-access-token`.

**That `form_post`'s parameter order was already in this repository.**
`javamap.KeyOrder` placed both measured sets on the first try and then placed
three shorter ones that were sent to test it. The order that looks arbitrary in
the observed spec - `error_description, iss, state, error` - is the same Java map
this project has been modelling since P2.

## 7. What is left

- **The front-channel logout page's markup and its cookie gate.** Both measured
  here, both unserved. The gate is two branches and the markup is one
  `themeShell` call away; the case is `Recorded` and will demand promotion the
  moment they land, because a `Recorded` case that matches is a hard failure.
- **The four JARM response modes.** F51's remainder, and a different piece of
  work from this one.
- **`admin/clients/evaluate-scope-mappings-not-granted` wants `PristineRealm`.**
  §1.12, and it is another stream's file.
- **`oidc/authorization`'s standard-flow refusal has no case**, F52's other half.
- **The consent denial's `form_post` cell is unmeasured.** It goes through the
  same transport as the three cells that were measured, because the rule is about
  the response mode rather than the endpoint, and reaching it needs a
  consent-required client under `response_mode=form_post` - one fixture nothing
  else in the catalogue wants. Recorded as unmeasured at the call site rather
  than left to look measured.
