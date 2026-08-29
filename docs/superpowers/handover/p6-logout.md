# Handover: P6's first cut, the RP-initiated logout endpoint

Date: 2026-08-29
Branch: `feat/p6-logout`
Plan: `docs/superpowers/plans/2026-08-29-p6-logout.md`

Five files were off limits because three other agents were working in parallel:
`AGENTS.md`, `README.md`, the parity roadmap, the observed document and the
follow-ups list. Everything this cut owes them is below.

Every value here was measured against `quay.io/keycloak/keycloak:26.7.1`, a
plain `docker run` as `kc-p6` on port 8092, on 2026-08-29. Thirteen probe
scripts, each printing the argv it then executed, with JWTs masked in the
printed line only.

**One transport caveat, and it is the reason two probes in the middle of the run
were thrown away.** Another stream's `gloak serve` bound `*:8092` on IPv6 partway
through, and `localhost` resolves to `::1` first, so those requests reached a
Gloak that has no logout route and answered
`{"error":"Unable to find matching target resource method"}` with a Go-shaped
`Content-Length`. Every claim below was either taken before that or re-taken
against `127.0.0.1:8092` afterwards, and the ten goldens are independent
evidence besides: `make record` runs its own container on a testcontainers port
and confirms the two headline corrections on its own.

---

## 1. Measurements to fold into the observed document

These replace the "RP-initiated logout" subsection of
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`, which is five
table rows and three sentences, two of which are wrong.

### 1.1 Correction: the hintless logout **does** redirect, and the session is the variable

The section says:

> **Without an `id_token_hint` there is no redirect at all**, which falsifies the
> catalogue's `oidc/logout/rp-initiated-without-id-token-hint` expectation of a
> `Location`. It is a consent page.

Measured, the same request twice, differing only in whether a cookie jar was
attached:

```
$ curl -s -D /dev/stderr -o /dev/stdout --no-location -X GET \
    'http://127.0.0.1:8092/realms/master/protocol/openid-connect/logout?client_id=p6-a&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback'

HTTP/1.1 302
Location: http://localhost:9999/callback
Cache-Control: no-cache

$ ... the same URL, with -b /tmp/p6/jar-b.txt after a browser login

HTTP/1.1 200
Content-Type: text/html;charset=utf-8
    <title>Logging out</title>   "Do you want to log out?"
```

**The confirmation page is what a logout serves when it has a browser session to
end and no authority to end it without asking.** With no session there is
nothing to confirm and it redirects. The earlier measurement was taken through a
jar and read the session for the parameter.

Two further measurements that follow from it and are worth writing down beside it:

- The confirmation page **does not end the session**. The refresh token still
  works after it. So it really is a question, not a logout.
- A valid `id_token_hint` **with no `post_logout_redirect_uri`** serves a
  different 200 page - `<title>You are logged out</title>`, 3602 bytes, where
  the confirmation page is 4645 - and it **does** end the session.

So the endpoint has four page/redirect outcomes where the section records two.

### 1.2 Correction: `post.logout.redirect.uris` is a filter over `redirectUris`, not a separate registration

The section says:

> `post.logout.redirect.uris` is a client attribute and has to be registered for
> the redirect to validate; it is not derived from `redirectUris`.

Measured across six clients differing only in that attribute:

| Attribute value | Accepted targets |
|---|---|
| absent | the client's `redirectUris` |
| `""` | the client's `redirectUris` |
| `"+"` | the client's `redirectUris` |
| `"-"` | **nothing**, including its own `redirectUris` and the literal `-` |
| a `##`-separated list | that list, and **not** `redirectUris` |

```
p6-b   no attribute at all, target = its redirectUris entry      302
p6-c   "+",                 target = its redirectUris entry      302
p6-c   "+",                 target = a sibling path              400 Invalid redirect uri
p6-minus "-",               target = its redirectUris entry      400 Invalid redirect uri
p6-empty "",                target = its redirectUris entry      302
p6-e   "…/cb*##…/exact",    targets /cb /cbxyz /cb?x=1 /exact    302
p6-e   the same client,     target = its redirectUris entry      400 Invalid redirect uri
```

`"-"` is a marker for the **whole** attribute and not for an entry: a client
whose attribute is exactly `-` refuses the literal `-` as a target, and a client
whose attribute is `http://localhost:9987/cb##-` **accepts** it - and resolves it
against the server's own base URL, answering
`Location: http://127.0.0.1:8092/-`. One string, two meanings, decided by
whether it stands alone.

The pattern comparison itself is `/auth`'s, re-measured rather than assumed:
exact and non-normalised, case-sensitive, `*` only as a suffix, and the query
and fragment cut in the wildcard branch alone. `/callback/`, `HTTP://…`,
`…#f`, `…?a=1`, `/callback` on a `/cb*` client and a host-relative `/callback`
are all refused.

### 1.3 The redirect's `state`, and the one place it disagrees with `/auth`

"The successful logout redirect carries `state` and nothing else. No `iss`" is
confirmed, on both a browser session and a direct grant. One thing to add:

```
/auth    state=   ->  Location carries state=          (an empty value is echoed)
/logout  state=   ->  Location carries no state at all
```

`ui_locales` is not echoed. A `state` sent without a `post_logout_redirect_uri`
is dropped with the redirect.

### 1.4 The rejection order, twelve paired requests

```
1  realm                     404 {"error":"Realm does not exist"}   JSON, not a page
2  id_token_hint             400 page "Invalid parameter: id_token_hint"
3  post_logout_redirect_uri  400 page "Invalid redirect uri"
   ...or                     400 page "Missing parameters: id_token_hint"
                                 when neither a hint nor a client_id was sent
--- everything below succeeds ---
4  a redirect target         302
5  no redirect target        200 page
```

Step 2 before step 3 is measured both ways round: a garbage hint with an
unregistered URI answers about the hint, and a **good** hint with an
unregistered URI answers about the URI.

Everything that is `Invalid parameter: id_token_hint`:

- rubbish that is not a JWT
- an access token or a refresh token in the hint's place
- a valid header and payload with the signature overwritten
- a payload rewritten to name another client, keeping the original signature
- another realm's ID token, at this realm's endpoint
- **a hint whose `azp` disagrees with the `client_id` parameter sent beside it**

Everything that is **not** a rejection, and each is a surprise:

- **An expired `id_token_hint` is accepted.** A client pinned to
  `access.token.lifespan=1`, whose ID token's `exp - iat` is 1, waited out three
  seconds: still 302, and the session ended.
- **A hint naming an already-ended session is accepted.** The same hint twice is
  302 twice.
- **A disabled client is accepted.** `p6-f` is `"enabled": false` and its
  `client_id` plus its registered target answers 302, where `/auth` answers the
  same client a 400 page.
- **A duplicated parameter is not an error.** `/auth` answers
  `duplicated parameter` to any key sent twice; `/logout` takes the first value.
  Measured with a good and a bad `post_logout_redirect_uri` together (redirects
  to the good one), `state` twice (`state=a`), `id_token_hint` twice
  (good-then-garbage succeeds) and an unread `zz` twice.

A hint whose client has since been **deleted** is `Invalid redirect uri`, not
`Invalid parameter: id_token_hint`: the token still verifies against the realm's
key, and it is the target that then has no client to validate against.

**A rejected logout ends nothing.** After every 400 above the session's refresh
token still works.

### 1.5 The `POST` family

`POST` reads the **body and not the query**, the same asymmetry `/auth` has: the
same parameters on a `POST`'s query string answer the confirmation page.

**The `refresh_token` decides which family a `POST` is in**, not the method: a
`POST` without one answers the `GET` families, and a `POST` carrying both a
`refresh_token` and an `id_token_hint` answers 204.

```
POST client_id + refresh_token                204, empty, Cache-Control: no-cache
POST the same refresh_token again             204                (idempotent)
POST + a post_logout_redirect_uri too         204                (the target is ignored)
POST client_id, no refresh_token              200 confirmation page
POST client_id + a target, no refresh_token   302
POST garbage refresh_token                    400 {"error":"invalid_grant",
                                                   "error_description":"Invalid refresh token"}
POST an access token as the refresh_token     400 the same
POST an ID token as the refresh_token         400 the same
POST another client's refresh token           400 {"error":"invalid_grant",
                                                   "error_description":"Invalid refresh token. Token
                                                    client and authorized client don't match"}
POST refresh_token, no client_id              401 {"error":"invalid_client", ...}
POST confidential client, no secret           401 {"error":"unauthorized_client", ...}
POST confidential client with the secret      204
```

The `GET` family authenticates no client at all: the same confidential client
redirects with an `id_token_hint` and no secret.

`Invalid refresh token. Token client and authorized client don't match` is a
spelling this project has not recorded before.

### 1.6 Header sets, per response family

```
                          CC          RP HS XC XF XR CSP  Content-Type      Set-Cookie
302 redirect              no-cache     Y  Y  Y  .  Y  .   none              AUTH_SESSION_ID
400 theme error page      no-cache     Y  Y  Y  Y  Y  Y   text/html;utf-8   none
200 theme page (both)     no-cache     Y  Y  Y  Y  Y  Y   text/html;utf-8   AUTH_SESSION_ID
204 POST success          no-cache     Y  Y  Y  Y  Y  Y   none              none
400/401 POST JSON         none         Y  Y  Y  Y  Y  .   application/json  none
404 realm                 none         -  -  -  -  -  -   application/json  none
```

Three of these are worth stating on their own.

**`/logout`'s theme pages carry `Cache-Control: no-cache`; `/auth`'s carry none.**
Measured side by side in one script on one container:

```
GET /logout  400 page   Cache-Control: no-cache
GET /auth    400 page   (no Cache-Control)
GET /auth    403 page   (no Cache-Control)
GET /logout  200 page   Cache-Control: no-cache
```

So "the theme error page sends no `Cache-Control`" is a fact about `/auth` and
not about the page.

**The 302 omits `X-Frame-Options` and `Content-Security-Policy`**, confirming on
a second endpoint what the observed document already predicted from `/auth`'s.

**The 204 carries `Content-Security-Policy`**, a second protocol response beside
revocation's success. It also carries `X-Frame-Options`, which is
`WriteNoContent`'s measured rule holding again: the request declared
`application/x-www-form-urlencoded`.

A browser session's `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION` are cleared with
`Max-Age=0` on the 302 **only when they were sent**. A direct-grant logout sets
`AUTH_SESSION_ID` alone.

### 1.7 The verbs, and a fourth data point for F31

```
HEAD     behaves as GET: 302 with the Location, or 200 with the page's headers
OPTIONS  200, empty, and **no Allow header**
PUT      405 {"error":"HTTP 405 Method Not Allowed"}, no Allow header
DELETE   405 the same
PATCH    405 the same
```

Two additions here.

**The 405 body is measured for the first time.** The observed document records
that `/auth` answers `PUT`, `DELETE` and `PATCH` with "a real 405 with
`application/json`" and never says what is in it. It is
`{"error":"HTTP 405 Method Not Allowed"}`, on both endpoints, re-measured side
by side. That is a fifth spelling in the fallback family.

**`OPTIONS` disagrees between the two endpoints.** `/auth` answers
`Allow: HEAD, POST, GET, OPTIONS`; `/logout` answers 200 with no `Allow` at all.
Two neighbouring endpoints, one container, one script.

Nothing in the router was changed on the strength of either; Gloak still answers
404 to all five.

### 1.8 Discovery already advertises all of it

```
end_session_endpoint:                    …/protocol/openid-connect/logout
check_session_iframe:                    …/protocol/openid-connect/login-status-iframe.html
backchannel_logout_supported:            true
backchannel_logout_session_supported:    true
frontchannel_logout_supported:           true
frontchannel_logout_session_supported:   true
```

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

The first two **contradict** lines already in that file. Both are in the bullet
beginning "Logout without an `id_token_hint` does not redirect."

Replace that bullet and the one after it with these four.

- **Whether a hintless logout redirects is decided by the browser session, not
  by the hint.** With a live session and no `id_token_hint`, Keycloak serves the
  theme's `Logging out` confirmation page, 200, and **ends nothing** - the
  refresh token still works afterwards. With no session, the same request with a
  `client_id` and a registered target is a **302**. So "logout without an
  `id_token_hint` does not redirect" is what one measurement through a cookie jar
  looked like; the jar was the variable. There are four outcomes, not two: the
  302, the confirmation page, a `You are logged out` page (a valid hint and no
  target, 200, and the session **is** ended), and the 400 error page. Its
  successful redirect does carry `state` and nothing else - no `iss` - and
  `Cache-Control: no-cache`, and that part was right.
- **`post.logout.redirect.uris` is a filter over `redirectUris`, not a separate
  registration.** A client with no such attribute redirects to its own
  registered `redirect_uri`; so does one set to `""` or `"+"`. `"-"` refuses
  everything, including its own `redirectUris` and the literal `-`. Anything
  else is a `##`-separated pattern list that **replaces** `redirectUris` rather
  than adding to it - so setting it can only ever narrow what a client accepts.
  The sentence "a client whose `redirect_uri` validates at the authorization
  endpoint is still refused at the logout endpoint until it is set" is the
  opposite of what happens. And `-` is a marker for the whole value and not for
  an entry: inside a `##` list it is an ordinary relative pattern, accepted and
  resolved against the server's base URL.
- **`state=` is echoed at `/auth` and dropped at `/logout`.** One parameter, two
  endpoints, opposite answers to the same empty value. `/auth` comes back
  `state=`; `/logout` comes back with no `state` key at all. And the two page
  families disagree the same way: `/logout`'s 400 page carries
  `Cache-Control: no-cache` where `/auth`'s 400 and 403 pages carry none. Two
  endpoints that look like one endpoint twice, measured side by side on one
  container; `httpx.WriteThemeErrorPage` takes the value as an argument for
  exactly this reason.
- **The logout endpoint forgives four things the authorization endpoint does
  not.** An **expired** `id_token_hint` still logs out and still redirects; a
  hint naming a session that has already ended answers the same 302 rather than
  an error; a **disabled** client redirects, where `/auth` answers it the 400
  page; and a **duplicated parameter is not an error at all** - the first value
  wins, where `/auth` answers `duplicated parameter` for any key sent twice,
  including one it never reads. What it does not forgive is a `client_id` that
  disagrees with the hint's `azp`: that is `Invalid parameter: id_token_hint`,
  not a client error. And a rejected logout ends nothing - validation completes
  before anything is destroyed.
- **A `POST` to the logout endpoint is two endpoints wearing one path, and the
  `refresh_token` decides which.** With one, the request is client-authenticated
  and answers 204 with `Cache-Control: no-cache` and a
  `Content-Security-Policy`, ignoring any `post_logout_redirect_uri` it was
  given, and answering 204 again on a replay. Without one it falls through to
  the `GET` families and answers a page or a 302. The `GET` family authenticates
  no client at all, so the same confidential client that must send its secret on
  the `POST` redirects without one on the `GET`. Its rejections add a fourteenth
  not-found-shaped string: `Invalid refresh token. Token client and authorized
  client don't match`, where an unusable token is the plain `Invalid refresh
  token`.

One line to add to the F31 bullet ("That rule is measured too broad, three times
now"):

- The 405 those three verbs answer carries `{"error":"HTTP 405 Method Not
  Allowed"}` - measured for the first time, on `/auth` and `/logout` alike, so
  the fallback family has five bodies rather than four. And `OPTIONS`
  **disagrees between the two**: `/auth` answers `Allow: HEAD, POST, GET,
  OPTIONS` and `/logout` answers 200 with no `Allow` at all. That is a fourth
  data point and it does not resolve the other three.

---

## 3. Follow-ups to file or close

Nothing here was fixed on the branch unless it says so.

- **F-new-1: Gloak issues no `AUTH_SESSION_ID`.** Keycloak sets a fresh one on
  the logout 302 and on both 200 pages. Gloak has no authentication-session
  concept, and minting a cookie value would be inventing an observable, so it
  sets none. The conformance cases mask `Set-Cookie` as volatile and assert none
  of them, so nothing catches it. Closes when P13 builds authentication
  sessions.
- **F-new-2: the browser-session branch of the confirmation page is unmodelled.**
  Keycloak serves `Logging out` when a session cookie is present and redirects
  when it is not; Gloak has no session cookie and therefore always takes the
  second branch. That is the right answer for every request Gloak can receive
  today and becomes a divergence the moment P13 sets one. **Not fixed.**
- **F-new-3: nothing measures the two cookie clears any more.**
  `oidc/logout/rp-initiated-with-id-token-hint` moved off the `browser-logged-in`
  fixture, so `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION` being cleared with
  `Max-Age=0` is now recorded in this document and in no test. It was asserted by
  no test before either - `Set-Cookie` was masked - so this is a loss of a
  recording rather than of a guard. Re-earn it when P13 makes the browser
  fixture replayable.
- **F-new-4: the three 400-page instructions are one placeholder.** Keycloak
  distinguishes `Invalid parameter: id_token_hint`, `Invalid redirect uri` and
  `Missing parameters: id_token_hint`; Gloak's placeholder body says
  `We are sorry...` for all three. The envelope is served and the branch is
  guarded by `internal/oidc`'s own tests. P13.
- **F-new-5: a relative post-logout target is not resolved.** Keycloak accepts
  `post_logout_redirect_uri=-` against a `##` list containing `-` and answers
  `Location: http://127.0.0.1:8092/-`, resolving it against the server's base
  URL. Gloak's `matchRedirectURI` is a string comparison and would emit the
  relative value unchanged. This is the same unhandled case as
  `security-admin-console`'s host-relative `/admin/master/console/*` at `/auth`,
  so it is one follow-up for both endpoints rather than a new one for this cut.
  **Not fixed.**
- **F-new-6: `make record` re-records two `Pending` theme-page goldens on every
  run.** `oidc/authorization/invalid-redirect-uri` and `unknown-client-id` churn
  their whole body because the `/resources/<hash>/` segment is regenerated per
  container start. This cut reverted that churn by hand after recording, which
  works and is not a rule. A recorder that left a `Pending` golden alone unless
  asked would make `make record`'s diff readable. **Not fixed.**
- **F-new-7 (harness): `TestFixturesAreWellFormed` assumed a GET never writes.**
  `GET /logout` with a valid `id_token_hint` ends the session, so
  `logout-hint-spent`'s third step is a GET that captures nothing and changes
  everything, and the "dead weight" rule rejected it. **Fixed on the branch**:
  `Step.Mutates` declares it, and the test now also rejects `Mutates` on a step
  that does capture something and on any non-GET. Flagging it because the harness
  is shared.
- **Close nothing.** No existing follow-up was reproduced or resolved here.

---

## 4. Parity before and after

`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1 -v`

```
main         oidc/logout    0 served   1 recorded   5 documented   catalogue
             total: 147 of 489 enumerated behaviours served; 4 chapters not enumerated

feat/p6-logout
             oidc/logout   10 served   0 recorded  14 documented   catalogue
             total: 157 of 498 enumerated behaviours served; 4 chapters not enumerated
```

`cmd/parity` on the two reports, the reproducible form AGENTS.md gives:

```
Parity: 147 -> 157 of 498 (+10)

chapter                         before  after  delta
oidc/logout                          0     10    +10
```

**Delta: +10 served, and the chapter's denominator grew by 9.** No other chapter
moved.

The brief predicted +1 and asked for the honest number rather than a padded one,
so the arithmetic is worth spelling out. **Two of the ten are promotions of
cases that were already in the catalogue** and eight are new; the denominator
went up by nine rather than eight because one further addition is `Pending`:

| Case | Was | Now | What only it catches |
|---|---|---|---|
| `rp-initiated-with-id-token-hint` | `Recorded` | `Implemented` | the 302, its `state`-only Location and its two absent headers |
| `rp-initiated-without-id-token-hint` | `Pending` | `Implemented` | the 302 with no hint - section 1.1 |
| `post-logout-uri-defaults-to-redirect-uris` | - | `Implemented` | the attribute is a filter - section 1.2 |
| `spent-id-token-hint` | - | `Implemented` | a second logout is a 302, not an error |
| `unknown-realm` | - | `Implemented` | the realm 404 precedes everything |
| `post-refresh-token` | - | `Implemented` | the 204, its `Cache-Control` and its CSP |
| `post-invalid-refresh-token` | - | `Implemented` | the 400 JSON, and that it sends no `Cache-Control` |
| `post-client-mismatch` | - | `Implemented` | the fourteenth error string |
| `post-missing-client` | - | `Implemented` | 401 `invalid_client` |
| `post-confidential-no-secret` | - | `Implemented` | 401 `unauthorized_client` |
| `invalid-id-token-hint` | - | **`Pending`** | the third 400-page instruction |

The brief's "+1" was right about the catalogue and wrong about the endpoint, and
the difference is the point of section 1 of the plan: the five documented cases
describe one verb and one shape, and the endpoint has two verbs, two request
families per verb and six response shapes.

`rp-initiated-with-id-token-hint` could not have been promoted as it stood.
Its fixture drove Keycloak's login form, which Gloak does not serve, so
`TestConformance` skipped it and would have gone on skipping it with the endpoint
finished. It now mints its `id_token_hint` with a direct grant, which is measured
to produce a byte-identical response - see F-new-3 for what that costs.

`rp-initiated-without-id-token-hint` was `Pending` on `main` with the reason
"the login theme is P13, and this response is a theme page", which section 1.1
shows was the wrong diagnosis. It is a redirect and it is served.

The `Pending` addition lowers the chapter's percentage on purpose. The branch
exists, its envelope is served, and its body is P13's; leaving it out would have
read as +10 of 13 rather than +10 of 14, which is the flattering number rather
than the true one.

Four cases remain `Pending`, and two of their reasons were corrected: the
endpoint is implemented now, so `backchannel` and `frontchannel` no longer wait
on it. What they wait on is a harness that can observe Keycloak calling **out**
to a client, which the request-response shape cannot do.

---

## 5. Mutation results

Seventeen mutations, one per claim, each applied alone, the named test run, then
reverted.

**Sixteen died on the first attempt.** One survived, and it is the interesting one.

**Survivor: removing the `"-"` marker from `postLogoutPatterns`.** Deleting
`case raw == "-": return nil` makes the function fall through to
`strings.Split("-", "##")`, which is the one-element pattern list `["-"]`. Every
row in `TestPostLogoutRedirectAttribute` asked for a real URI, and `["-"]`
refuses every real URI by exact comparison, so the mutant answered the same 400
the correct code does and the test stayed green. The table proved that a client
with `-` refuses ordinary targets; it never proved that `-` is a marker rather
than a pattern that matches nothing.

The distinguishing input is the literal `-` as the target, and it was measured
rather than reasoned about:

```
attribute "-",                        target "-"   ->  400 Invalid redirect uri
attribute "http://localhost:9987/cb##-", target "-"  ->  302 Location: http://127.0.0.1:8092/-
```

so the marker really is the whole attribute value. **The row was added and the
mutation now dies**, on the named subtest `- refuses the literal - as well`.
The measurement it rests on is section 1.2's last paragraph, and it also
produced follow-up F-new-5.

The sixteen that died first time:

```
KILLED  the logout redirect's Cache-Control is no-cache          TestWriteLogoutRedirect
KILLED  the logout redirect omits X-Frame-Options                TestWriteLogoutRedirect
KILLED  the theme page's Cache-Control is the caller's           TestWriteThemePageCacheControl
KILLED  the 200 pages carry their own titles                     TestLogoutWithNoTargetServesTheRightPage
KILLED  an empty state is dropped rather than echoed             TestLogoutDropsAnEmptyState
KILLED  an absent attribute falls back to redirectUris           TestPostLogoutRedirectAttribute
KILLED  a client_id disagreeing with the hint is refused         TestLogoutRejectionEndsNothing
KILLED  an access or refresh token is not an id_token_hint       TestLogoutRejectsAnUnusableHint
KILLED  a rejected logout ends nothing                           TestLogoutRejectionEndsNothing
KILLED  an empty post_logout_redirect_uri means absent           TestLogoutTargetIsAbsentWhenEmpty
KILLED  the endpoint ignores the client's enabled flag           TestLogoutIgnoresTheClientsEnabledFlag
KILLED  the POST family is decided by the refresh_token          TestPostLogoutWithoutARefreshTokenFallsThrough
KILLED  a POST reads the body and not the query                  TestPostLogoutReadsTheBodyNotTheQuery
KILLED  another client's refresh token has its own description   TestPostLogoutFamily
KILLED  the 204 carries Cache-Control: no-cache                  TestConformance
KILLED  the redirect carries no iss                              TestConformance
```

---

## 6. Shared files touched, for the merge

**`internal/httpx` is shared with the P5 stream.** Three changes:

- `WriteThemeErrorPage` **gained a third parameter**, `cacheControl string`. The
  one existing call site, `internal/oidc/authorize.go`'s `writeErrorPage`, passes
  `""` and keeps sending no header. This is the only signature change in the cut
  and the only merge conflict worth watching for.
- `WriteLogoutRedirect` added, beside `WriteAuthorizationRedirect`. Separate
  rather than parameterised on purpose - see its doc comment.
- `WriteThemePage(w, status, cacheControl, title)` added, with
  `WriteThemeErrorPage` delegating to it, and the body constant replaced by
  `themePageBody(title)` plus an exported `ThemeErrorTitle`.

**`internal/token` gained `ParseID`**, which verifies RS256, `iss` and `typ=ID`
and deliberately does **not** check `exp`. No existing function changed.

**`internal/conformance/fixture.go` gained `Step.Mutates`**, and
`fixture_test.go`'s dead-weight rule reads it. See F-new-7.
