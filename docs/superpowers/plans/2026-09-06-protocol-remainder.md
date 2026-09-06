# The protocol remainder: ten unserved cases, and what their reasons are worth

Ten cases in `internal/conformance`'s OIDC chapters carry a written reason for
not being built. Several of those reasons predate the mechanisms that would lift
them. **The unit of work here is a reason re-checked, not an operation**, so the
first section is the deliverable and the rest is how it gets done.

Everything in the "measured" column was read off a live Keycloak 26.7.1 on
2026-09-06, in a container started for this cut and removed at the end of it.

## 1. One row per case

| # | Case | Recorded reason | Holds? | What this cut does |
|---|---|---|---|---|
| 1 | `oidc/authorization/implicit-flow` | "the implicit flow is out of P3's scope" | **expired** | Promote to `Implemented`. It is a scope statement about a plan phase that closed, and F94 already says so. The behaviour the case measures is a **refusal** - a client with the implicit flow off answers 302 with the error in the fragment - which Gloak has served and unit-tested since P3. Fixture `browser-client` exists. |
| 2 | `oidc/authorization/response-mode-form-post` | Gloak answers the 400 page; `form_post` is in `responseModes` and not in `servableResponseModes` (F51); the missing mask is an `INPUT VALUE` frame | **holds, and both halves are liftable** | Build both. Serve `form_post` in `internal/oidc` on the success **and** the rejection path, add `Case.VolatileHTMLInput`, promote to `Implemented`. |
| 3 | `oidc/logout/frontchannel` | "the login theme is P13, and this response is a theme page" | **expired in its wording, holds in substance, and a second blocker is new** | Promote to `Recorded`. P13 closed and this page is not one it built - it is a tenth theme page. And Gloak has a **measured divergence** here beyond the body: it serves the page to a request carrying no browser cookies, where Keycloak answers a 302. |
| 4 | `oidc/introspection/active-access-token` | "no fixture can put the introspecting client in an access token's audience" | **expired** | Promote to `Implemented`. Measured: give the user a role on the introspecting client and issue the token from a **different** client, and the introspecting client is in `aud`. `active:true` with the nineteen-key body. |
| 5 | `oidc/logout/backchannel` | "the harness holds one request and one response, and this is a request Keycloak makes" | **holds** | Re-checked and confirmed; the `Reason` gains the date it was re-read. |
| 6 | `oidc/ciba/poll-pending` | no CIBA authentication channel on a default 26.7.1 | **holds** | Re-measured 2026-09-06: a valid CIBA authentication request answers 503 `server_error` / "Failed to send authentication request". No `auth_req_id` exists to poll with. |
| 7 | `oidc/ciba/poll-complete` | the same | **holds** | The same measurement. |
| 8 | `oidc/token/ciba-grant` | the same | **holds** | The same measurement. |
| 9 | `oidc/token/dpop-bound-token` | "a DPoP proof carries a per-request `iat` and a single-use `jti`, so no literal proof can be recorded and replayed" | **holds, and is sharpened** | The reason as written explains why no *literal* works. What it does not say is why no *computed* one is available either: a `Step` is a request, and every capture reads a response - `Capture`, `CaptureHeader`, `CaptureForm`, `CaptureQuery`. The harness has no computed value at all. |
| 10 | `oidc/token/dpop-header-invalid` | "DPoP is not implemented; Gloak ignores the header" | **holds** | `grep -i dpop internal/` finds a client attribute, a registration field and a discovery list, and no proof verification. F135 says so deliberately. Stays `Recorded`. |

Three of the four expired reasons were predicted by the brief that
commissioned this cut. **One of the brief's own claims is wrong and is worth
recording**: `prefixMasksLeftInPlace` in `catalog_test.go` does **not** name
`oidc/authorization/response-mode-form-post`. It holds two entries -
`oidc/device/authorization-request` and `oidc/registration/create-client` - and
both want a body-side `VolatileTail`, which is a different mechanism from the
one this case wants. Nothing comes off that ratchet here.

## 2. What was measured, and the probes that could have lied

Each probe below has a control known to differ, because a probe that reports the
same answer for every input is measuring itself.

### 2.1 The introspection audience (row 4)

Reason under test: *no fixture can put the introspecting client in an access
token's audience.*

`aud` is the clients the user holds roles on, minus the issuing client. So the
fixture needs **two** clients:

```
gloak-probe-aud-introspect   confidential, owns a role, does the introspecting
gloak-probe-aud-issuer       confidential, direct access grants, mints the token
gloak-probe-aud-user         holds gloak-probe-aud-introspect's role
```

Measured: the access token's `aud` is
`["gloak-probe-aud-introspect","account"]`, its `azp` is the issuer, and the
introspection answers 200 with `active:true` and nineteen keys.

The control that says the exclusion is real is already in the catalogue:
`oidc/introspection/access-token-outside-audience` introspects a token the
caller minted for itself and gets `{"active":false}`.

### 2.2 The implicit flow's refusal (row 1)

```
response_type=id_token token   302, error in the fragment
response_type=token            302, the same
response_type=code             200, the login page          <- the control
```

The 302 carries `error=unauthorized_client`, the Implicit sentence, `state` and
`iss`, and it carries **no `X-Frame-Options` and no `Content-Security-Policy`** -
which is `/auth`'s redirect-to-client rule, and an eighth data point for it. The
case gains an `AssertAbsentHeaders` for both.

### 2.3 The front-channel logout page (row 3)

The p6 handover records the condition as "a session holding a client with
`frontchannelLogout: true` **and** a `frontchannel.logout.url`". **That is
measured too narrow.** With exactly that client configuration and a live session,
a request carrying no browser cookies answers a **302**:

```
                                                       status  bytes
no cookies                                              302      0
KEYCLOAK_IDENTITY of the hint's own session             200   4348
KEYCLOAK_IDENTITY of another live session               200   4679
KEYCLOAK_SESSION  of the hint's own session             200   4348
KEYCLOAK_SESSION  of another live session               302      0
AUTH_SESSION_ID only                                    302      0
```

So the page is served when the **request** identifies a browser session, and the
p6 sweep measured through a cookie jar without isolating it - the same shape as
the hintless-logout bullet AGENTS.md already carries, where "the jar was the
variable and the hint was not", in the opposite direction.

**A probe of this got it wrong once and the wrong answer is instructive.** An
earlier grid ran two rows against one `id_token_hint`; the first row spent it,
so the second measured a session its own predecessor had ended, and reported
`KEYCLOAK_SESSION` as a 302 where a fresh login says 200. A hint is spent by the
probe that uses it. Every row above has its own login.

Gloak's gate is `len(targets.front) > 0` with no cookie condition, so it serves
the page where Keycloak sends a 302. That is a divergence this cut files rather
than fixes.

### 2.4 `form_post`'s two bodies (row 2)

Both measured, both small, and the rejection body carries **nothing** per
request:

```
rejection   200, text/html (no charset), Cache-Control: no-store, must-revalidate, max-age=0
            694 bytes, four INPUTs: error_description, iss, state, error
            no <SCRIPT>
success     200, the same envelope, 1112 bytes
            a <SCRIPT> whose history.replaceState URL carries client_id, tab_id, client_data
            four INPUTs: code, iss, state, session_state
```

Of the success body's per-request values, `tab_id` and `client_data` are minted
by the **fixture's** `GET /auth` and are reachable through `CaptureForm`'s
`query:` form, which `browser-page-expired` already uses. `code` and
`session_state` are minted by the **case's own** request and are `INPUT VALUE`s,
which is the frame the theme-html-masking cut described and did not build
because it had no consumer.

### 2.5 CIBA (rows 6-8)

```
POST /realms/master/protocol/openid-connect/ext/ciba/auth   503
{"error":"server_error","error_description":"Failed to send authentication request"}
```

on a client carrying `oidc.ciba.grant.enabled`. `GET /admin/serverinfo` reports
`CIBA` as `"type":"DEFAULT","enabled":true`, so the feature is on and the
**channel** is what a default container has not got. The reason holds exactly as
written.

(The first attempt sent `/realms/master/ext/ciba/auth` and got the generic 404.
The path is under `protocol/openid-connect/`. A 404 from a wrong path is not a
measurement of anything.)

## 3. The work

### Task 1 - `oidc/authorization/implicit-flow` to `Implemented`

`catalog_oidc_pending.go` only: drop the `Reason`, name `browser-client` as the
`Fixture`, add `AssertAbsentHeaders`. Record. The golden is fully literal once
`ReplaceIssuer` has run.

Mutation: make `classifyResponseType` return `flowStandard` for a response type
naming `token`, and confirm the named case fails.

### Task 2 - `oidc/introspection/active-access-token` to `Implemented`

A new fixture at the end of `Fixtures`, built from the pieces already there:
`adminTokenStep`, a client create, a client-role create, a user create with an
inline credentials array, a role-mapping write, and a password grant at the
second client. `Volatile` and `Unordered` follow `active-refresh-token`'s.

It does **not** carry `PristineRealm`: its subject is a probe user holding one
client role and `default-roles-master`, so unlike `active-refresh-token`'s
administrator it enumerates nothing realm-wide.

Mutation: drop the `slices.Contains(parsed.Audience, ...)` guard in
`introspect.go` and confirm `access-token-outside-audience` fails; then invert it
and confirm **this** case fails. Two mutations, because one guard with two sides
is exactly the two-condition shape that survives.

### Task 3 - `oidc/logout/frontchannel` to `Recorded`

A fixture that logs in through the browser at a front-channel client and carries
its jar into the case's own request. The `Reason` is rewritten to name the two
measured blockers rather than P13.

`Recorded` requires the case **not** to match, and it cannot: the body is
`themePageBody`'s placeholder.

### Task 4 - `form_post`, and `Case.VolatileHTMLInput`

Three pieces:

1. `internal/oidc`: `form_post` moves into `servableResponseModes` and both the
   rejection path and the code-carrying success path learn to write the form.
   The four `jwt` spellings stay unservable, so F51 is half closed rather than
   closed.
2. `internal/httpx`: one writer for the form, because `internal/httpx` is the
   only place a response body is formatted.
3. `internal/conformance`: `Case.VolatileHTMLInput` masks
   `<INPUT ... NAME="x" ... VALUE="...">` by name, in `normalize.go` beside
   `ReplaceHTMLValues`, so the recorder and the verifier share one pass. Its
   consumers are this case now and three theme pages later.

Mutations: reorder the form's four inputs; drop the `<SCRIPT>`; and change the
`Content-Type` to carry a charset. Each must fail the named case.

### Task 5 - the six reasons that hold

`Reason` strings re-worded only where a measurement sharpens them, each saying
when it was re-read. No status moves.

### Task 6 - the documents

`docs/superpowers/handover/protocol-remainder.md`, four headed sections:
measurements, entries for AGENTS.md in that file's voice, follow-up
dispositions, and parity before and after with one row per reason re-checked.

## 4. Parity

Baseline, `GLOAK_PARITY_REPORT` on `main` at 087053c:

```
oidc/authorization   25  0  27
oidc/ciba            10  0  12
oidc/introspection    4  0   5
oidc/logout          12  0  14
oidc/token           19  1  22
total               498    541
```

A protocol chapter's numerator is `Implemented` and its denominator is
`Implemented + Recorded + Pending`, so a `Pending` to `Recorded` promotion moves
the recorded column and not the total. Expected after: `oidc/authorization` 27 of
27, `oidc/introspection` 5 of 5, `oidc/logout` 12 of 14 with one `Recorded`,
total 501 of 541.

## 5. What could go wrong

- **`form_post` governs every rejection from step 3 onwards.** Serving it on the
  success path alone would leave a request that is wrong in two ways answering
  the wrong family. The `reject` closure is the one place to change.
- **A `Recorded` case that matches is a hard failure.** Task 3's golden must
  differ from what Gloak serves, and it does for two reasons rather than one, so
  fixing either alone will not turn the case green by accident.
- **`TestNoHTMLMaskVariesNothing` serves each case twice and refuses a mask whose
  covered bytes do not move.** `VolatileHTMLInput` has to be wired into that
  guard or it is a place to hide a diff.
- **`make record` rewrites every golden.** Read the diff: anything moving outside
  the four cases this cut names is a finding, not noise.
