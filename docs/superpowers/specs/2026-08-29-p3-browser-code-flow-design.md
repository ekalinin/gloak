# P3: the browser code flow, measured

Date: 2026-08-29
Status: accepted
Roadmap: `2026-08-21-gloak-parity-roadmap.md`
Supersedes: `2026-08-22-p3-browser-code-flow-design.md`
Depends on: P1 (token foundation), P2 (client management, complete 2026-08-28)

## 1. What this is

The 2026-08-22 document was written while P1 was fresh and P2 had not started.
It says so about itself, and it was right to be written: it fixed the
boundaries. But it was written **before anyone drove the endpoint**, so its
claims are hypotheses. This document is the same scope with the measurement
behind it, taken 2026-08-29 against a live `quay.io/keycloak/keycloak:26.7.1`
on port 8083. The transcript is in the "The browser authorization code flow"
section of `2026-08-18-keycloak-26.7.1-observed.md`, printed from the same argv
that was executed.

Section 2 is the scorecard: what the measurement confirmed and what it
falsified. Falsifying three claims is the useful part of the exercise, not a
failure of the earlier document.

## 2. The 2026-08-22 document, checked line by line

### Confirmed

**The cookie table in its section 3, exactly.** `AUTH_SESSION_ID`,
`KC_AUTH_SESSION_HASH` with its quoted value and `Max-Age=60`, `KC_RESTART` as
a `dir`/`A256GCM` JWE, and after login `KEYCLOAK_IDENTITY` as an HS512 JWT with
`typ: Serialized-ID`, `KEYCLOAK_SESSION` with `Max-Age=36000`, `KC_RESTART`
cleared. Every cookie carries `Version=1` and `Path=/realms/master/`. Seven
attributes across six cookies and not one of them was wrong.

**That the recorder needs a small browser**, and every one of the four
consequences it drew: cookies across steps, HTML parsing rather than a regular
expression, both halves of F12, and masking the parsed values out of the
golden.

**That the three theme-HTML cases must stay deferred.** The error page is
byte-identical on two recordings from one container and carries a
`/resources/<hash>/` segment regenerated per container start. The churn is
real and was measured rather than assumed.

**That the recordings need P2's client management.** The measurement makes this
sharper than the original argument, which is section 3.

**The first two parts of the authorization code**, `code UUID` and
`session_state`. `part[1] == session_state` is checked directly.

### Falsified

**The code's third part is not a client session UUID. It is the client's own
internal UUID** - the `id` the Admin API addresses the client by, identical on
every login by any user at that client. Measured by comparing it against
`GET /clients?clientId=...`'s `id`.

**The form's hidden parameters are five, not three.** `session_code`,
`execution`, `tab_id` **and** `client_id` and `client_data`, all on the action
URL's query rather than in the form body. `client_data` is unpadded base64 of
`{"ru":...,"rt":...,"st":...}`, gaining `"rm"` when a response mode was asked
for. The document listed three and said "and whatever else the form carries",
which is the right way to have been wrong.

**Logout without an `id_token_hint` does not redirect.** It serves the theme's
`Logging out` confirmation page, 200, `Do you want to log out?`. The catalogue's
`oidc/logout/rp-initiated-without-id-token-hint` asserts a `Location` that does
not exist. It is a theme HTML case and it moves to P13, so P3's logout share is
one case, not two.

**The reason the four "recorded once and produced the wrong page" cases failed
is only half what their comments say.** The comments blame the run-time port,
and the port is genuinely fatal - `security-admin-console`'s `redirectUris` is
the host-relative `/admin/master/console/*`, so no absolute literal matches a
container on an arbitrary port. But fixing only that would still have failed
nine cases, because the same client pins `pkce.code.challenge.method` to
`S256` and rejects a request without `code_challenge_method` before looking at
anything else. Section 3.

### Not decided either way, and now decided

The document's section 8 named three things it deliberately did not decide: the
hidden form parameters, the wrong-password response and the replayed code.
All three are measured. Wrong password: 200, the login page re-served with
`Invalid username or password.`, a rotated `session_code` and the username
pre-filled. Replayed code: 400
`{"error":"invalid_grant","error_description":"Code not valid"}`.

## 3. `security-admin-console` cannot serve nine of the eleven cases

Every `oidc/authorization` case in the catalogue names
`security-admin-console`, and the reasoning was sound: it is the one
bootstrapped public client with the standard flow enabled. `admin-cli` has the
standard flow off, `account` and `account-console` redirect only into
`/realms/master/account/*`, `broker` and `master-realm` are confidential.

Two of its properties defeat the cases anyway.

**`pkce.code.challenge.method` is `S256`.** Nine of the eleven cases send no
`code_challenge_method` at all, so every one of them measures the same
redirect:

```
error=invalid_request&error_description=Missing+parameter%3A+code_challenge_method
```

`oidc/authorization/pkce-plain` is not merely mismeasured but impossible: it
sends `plain` to a client pinned to `S256`, which answers
`Invalid parameter: code challenge method is not matching the configured one`.

**`redirectUris` is `/admin/master/console/*`, host-relative.** It is resolved
against the host and port the request arrived on, so a literal
`http://localhost:8080/...` fails on a container listening anywhere else.

The way out is not a different literal, and the 2026-08-22 document guessed it
correctly: **register a client whose redirect pattern is an absolute URI the
catalogue chooses.** The recorder never follows the redirect - `TestRecordGoldens`
sets `CheckRedirect` to `ErrUseLastResponse` precisely so it does not - so the
URI never has to resolve. `http://localhost:9999/callback` is what the
measurement used and what the fixtures should register.

That gives three clients, and the third is what makes `pkce-plain` reachable:

| Fixture client | Configuration | Serves |
|---|---|---|
| `gloak-probe-browser` | public, standard flow, no PKCE policy | the code flow, S256 and plain, and every error redirect |
| `gloak-probe-browser-plain` | as above, `pkce.code.challenge.method=plain` | the client-policy mismatch |
| `gloak-probe-browser-conf` | confidential, a known secret | the confidential code exchange |

## 4. Two error families, and which one you get is decided before anything else

This is the structural finding, and it is what an implementation has to be
built around rather than bolted onto.

**If the `client_id` resolves and the `redirect_uri` matches its pattern, every
subsequent rejection is a 302 to that redirect URI**, carrying `error`,
`error_description` where there is one, `state` if one was sent, and `iss`.
`Cache-Control: no-store, must-revalidate, max-age=0`, no `Content-Type`, an
empty body.

**If either does not, the answer is a 400 serving the theme's error page**,
`text/html;charset=utf-8`, **no `Cache-Control` at all**, and the five security
headers plus `Content-Security-Policy`.

An unknown realm is in neither family: it is the protocol side's usual
`404 {"error":"Realm does not exist"}`, which `internal/oidc/router.go` already
serves for its existing endpoints.

The consequence for the implementation is an ordering constraint, not a set of
checks: **resolve the realm, then the client, then the redirect URI, and only
then anything else.** Getting that order wrong does not produce a slightly
different message, it produces the wrong family, the wrong status and the wrong
`Content-Type`. The catalogue's `missing-response-type` case already carries a
comment that discovered this the hard way.

## 5. Five behaviours that look like bugs and are not

**`GET /auth`'s redirect back to the client is the one response in the flow
that omits `X-Frame-Options` and `Content-Security-Policy`.** Not "errors omit
them": `POST /login-actions/authenticate`'s **error** redirect, to the same URI
with the same status, carries all six headers. Not "302s omit them", for the
same reason. Not "failures omit them": `prompt=none` with a live session
redirects with a real code and omits them too. It is that endpoint's redirect,
and RP-initiated logout's redirect behaves the same way. The full sweep is in
the observed document.

This also falsifies a line in `AGENTS.md`: the revocation success is not the
only response carrying `Content-Security-Policy`. Six of the seven responses in
the browser flow carry it.

**`response_mode` moves the parameters and changes the status.** `query` and
absent put them in the query, `fragment` in the fragment, and `form_post`
answers **200** with an auto-submitting HTML form. A handler that treats
response mode as "which separator" produces a 302 where Keycloak sends a 200.

**`form_post` orders the four parameters differently from the query
redirect.** The form emits `code`, `iss`, `state`, `session_state`; the query
emits `state`, `session_state`, `iss`, `code`. One response, two orderings,
decided by a request parameter. Writing one ordered list and reusing it is the
tidy-up that breaks one of the two.

**`form_post`'s `Content-Type` is `text/html` with no charset**, where the
login page's is `text/html;charset=utf-8`. Two HTML bodies from one endpoint,
one with a charset and one without.

**A missing `redirect_uri` at the token endpoint answers `Incorrect
redirect_uri`, not a missing-parameter error.** Every other missing parameter
on that endpoint says `Missing parameter: <name>`; `code` does. `redirect_uri`
does not, because it is compared against what the authorization request stored
and absent compares unequal rather than being caught by a presence check.

**A code is spent by a failed exchange.** A wrong `code_verifier` answers
`PKCE verification failed: Code mismatch`, and the immediate retry with no
verifier answers `Code not valid` rather than repeating the PKCE failure. So
"single use" means single *attempt*, and a case measuring the PKCE failure
cannot reuse its code for anything afterwards.

## 6. The recorder has to become a small browser, and that is this cut

`RunFixture` today issues one request per step through a `Do` func, threads
JSON captures and `Location` path segments between them, and knows nothing
about cookies or HTML. A login needs three things it does not have.

**A cookie jar, inside `RunFixture`.** Not on the recorder's `http.Client`.
The recorder would get one free from `http.Client.Jar`, and the verifier -
which calls `h.ServeHTTP` into an `httptest.ResponseRecorder` - would get
nothing, so the two sides would obtain their responses differently. AGENTS.md
names that as the one thing this suite cannot afford. The jar goes in the one
place both sides share.

**The form's action URL, parsed out of HTML.** `golang.org/x/net/html`, already
an indirect dependency, finds a form and reads its attributes without a regular
expression. The measurement says the action is the *only* thing worth
capturing: the form's three inputs are `username`, `password` and a
value-less hidden `credentialId`, so nothing in the body is volatile. Capturing
inputs is still worth supporting, because the next flow that adds a valued
hidden field should not need a second mechanism, but the login itself needs one
capture.

**A query parameter out of the `Location` header.** `captureFromHeader` returns
a URL's last path segment, which is what a 201's `Location` carries and is
useless for a redirect carrying `code` in its query.

All three are additions to the shared declaration in `fixture.go`, so the same
`Fixture` value drives the container and the handler. That is the property that
makes the harness worth having and it is not weakened here.

## 7. What is masked, and what is asserted

A recorded browser case has four volatile values and they are not all handled
the same way.

`session_code`, `execution`, `tab_id` and `client_data` never reach a golden:
they live in the action URL of a *step*, and steps are never recorded.

The `code`, the `session_state` and the client UUID inside the code do reach
one, in the `Location` of the case's own response. `ReplaceCaptured` already
masks any value a step captured, so capturing them names them.

`iss` inside the `Location` is the trap. `recordedHeaders` runs `ReplaceIssuer`
over each header value, but `iss` is **percent-encoded** in the query, so the
raw base URL never appears and the substitution misses it. A `Location` golden
recorded on port 8083 and verified against the harness's issuer would differ on
that parameter alone. Two ways out - decode before replacing, or mask the whole
header with `VolatileHeaders` - and they are not equivalent: masking the whole
header throws away the query key order and the error code, which for the error
cases is the entire contract. The plan takes the first and says why.

## 8. Scope

In, and unchanged from 2026-08-22 except where the measurement moved it:

- `GET` and `POST /auth`: realm, client and redirect URI resolution in that
  order, response type, scope and PKCE validation, the login page, the three
  response modes
- `POST /login-actions/authenticate`: credential verification, session
  creation, code issuance, the wrong-password re-serve
- the `authorization_code` grant, including PKCE verification and the
  single-attempt code
- RP-initiated logout **with** an `id_token_hint`
- the cookies in section 2

Out:

- themes, i18n and the page's appearance, and with them the three 400 error
  pages, the logout confirmation page and the wrong-password re-serve as a
  *golden* - P13
- back-channel and front-channel logout, the session iframe, offline sessions -
  P6
- required actions, OTP, WebAuthn, brute force and the flow engine - P8
- consent screens, the implicit and hybrid flows

## 9. Cases this closes, corrected

`oidc/authorization`, 8 of 11, the same eight the 2026-08-22 document named -
but seven of them need their `client_id` and `redirect_uri` changed first, and
`pkce-plain` needs a client that does not exist yet.

`oidc/token`, 3 more: `authorization-code-grant`, `replayed-code`,
`pkce-verifier-mismatch`.

`oidc/logout`, **1** of 5, not 2. `rp-initiated-with-id-token-hint`.
`rp-initiated-without-id-token-hint` is a theme page and moves to P13 with
`invalid-post-logout-redirect-uri`.

Twelve cases, against a hand-kept chapter denominator.

The measurement also names surface the catalogue does not cover at all: the
`form_post` 200, the `response_type=token` fragment error, the code-verifier
mismatch's effect on a later exchange, the cross-client code, and the login
POST replay. Those are candidates for cases, not cases; nothing counts them
until they are written.

## 10. Debt this knowingly takes on

**One authentication step, hardcoded**, unchanged from 2026-08-22. P8 replaces
it.

**`KC_RESTART`'s contents are opaque**, unchanged. Its *shape* is now confirmed
rather than assumed.

**Gloak's login page will not be Keycloak's.** Stated in 2026-08-22 and worth
restating with a number: the measured page is 6900 bytes of `keycloak.v2`
Freemarker output with a per-container resource hash in it. No case should
compare it before P13.

## 11. What this document deliberately does not decide

**How an authorization code is stored.** Whether the three parts are a
composite key, whether the code row carries the PKCE challenge or the auth
session does, and what expires it. Nothing observable depends on the answer
except that the third part must be the client's UUID, which section 2 measured.

**The exact `Location` on a `prompt=none` success.** Measured to carry a real
code with the same four keys, but not measured against a session created any
way other than a login in the same jar.

**Whether `execution`'s stability is a contract.** It was the same UUID across
every login in one container and nothing says whether it survives a restart.
It is a step value and never reaches a golden, so P3 does not need to know.
