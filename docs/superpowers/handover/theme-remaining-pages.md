# F146's nine pages, and F109's twelve call sites

Branch `feat/theme-remaining-pages`, off `6e5a096`. Everything measured below was
taken on 2026-09-02 against a live Keycloak 26.7.1 - container `kc-pages`, port
8159, `start-dev`, bootstrap admin `admin/admin`, removed afterwards. The plan is
at `docs/superpowers/plans/2026-09-02-theme-remaining-pages.md`.

**F109 is closed. F146 serves none of its nine and measures all nine**, and the
reason is one sentence: every one of them carries a `tab_id` minted by the
request that renders it, and nothing in this harness can mask a value inside an
HTML body. That is not a page count; it is the same blocker nine times, and §1.1
is the evidence per page.

## 1. Measurements

### 1.1 The nine pages, one row each

Each page was reached, read, and then requested a second time against the same
container. "Per request" is what moved, plus what a serving implementation would
have to mint.

| page | `data-page-id` | bytes | how the request is built | per request | golden? |
|---|---|---|---|---|---|
| logout confirmation | `login-logout-confirm` | 4645 | full browser login, then `GET .../logout` with no hint | `tab_id` twice, `session_code` once | no |
| You are logged out | `login-info` | 3616-3701 | login, exchange the code, `GET .../logout?id_token_hint=<jwt>` with no target | `tab_id` | no |
| Page has expired | `login-login-page-expired` | 4624 or 4989 | `GET /auth`, then `/login-actions/authenticate` with a wrong `execution` | `tab_id` three times, the `KC_AUTH_SESSION_HASH`, and a whole `<SCRIPT>` block | no |
| consent | `login-login-oauth-grant` | 5478 | login at a `consentRequired` client | `tab_id`, the hidden `code`, the session hash | no |
| UPDATE_PASSWORD | `login-login-update-password` | 10873 | put the alias on the user, log in, follow the 302 | `tab_id`, `session_code`, the session hash | no |
| UPDATE_PROFILE | `login-login-update-profile` | 7273 | as above | the same three | no |
| CONFIGURE_TOTP | `login-login-config-totp` | 9382 | as above | the same three **and a minted TOTP secret** | no |
| Passkey | `login-webauthn-register` | 6833 / 6836 | as above, two aliases | `tab_id`, `session_code` **and a WebAuthn challenge** | no |
| recovery codes | `login-login-recovery-authn-code-config` | 12443 | as above | the same three **and twelve generated codes** | no |

The golden column is the same answer nine times and it is not an opinion.
`ReplaceCaptured` can rewrite a value a **fixture step** captured;
`ReplaceThemeResource` can rewrite an installation-wide constant. Every `tab_id`
above is minted by the **case's own request**, which is neither. So these nine
want "mask the value of this attribute at this place in the HTML", which is F38's
mechanism, closed on the ground that one case is not a mechanism's evidence.
There are eleven now: these nine, `prompt-create` and `response-mode-form-post`.

### 1.2 The logout confirmation page names a client the request never mentioned

Its restart URL and its confirm form's action both carry `client_id=account`.
Three browsers, and all three:

```
a completed gloak-probe-page login          client_id=account
a browser mid-flow at gloak-probe-consent   client_id=account
no cookies at all                           client_id=account
```

That breaks the rule the previous cut wrote down. "The theme page's chrome shows
how far the request got, not what it asked for" is true of `/auth`'s family and
of `/login-actions`'; this page shows neither. `account` is a client every realm
has and no request in this flow names.

### 1.3 One page's `<title>` is not the head template's

```
logout confirmation           <title>Logging out</title>
the other eight of the nine   <title>Sign in to Keycloak</title>
```

`themeHead` builds `Sign in to <displayName or realm name>` unconditionally, and
that is right on eight of the nine and on all eight pages already served. The
logout confirmation is the exception, and the value carries nothing realm-derived
at all, so the head has to take the title rather than compose it.

### 1.4 The `login-info` template's back link is not the `login-error` one's

```
login-info                 <p><a href="…">« Back to Application</a></p>
login-error            <p><a id="backToApplication" href="…">« Back to Application</a></p>
```

Sixteen spaces and no `id` against twenty spaces and an `id`. One link, two
templates, two spellings - and `themeInfoPageBody` reproduces the rest of the
`kc-info-message` block byte for byte already, checked against the device status
page, which is the one `login-info` page this project serves and has no link at
all. A shared link helper is wrong on one of the two.

### 1.5 "Page has expired" carries a script that comes and goes, and the rule is
the session code

Five cells, each on its own fresh tab:

```
valid session_code, wrong execution      the page, with <SCRIPT> history.replaceState   4989
the same request again                   the page, without it                           4624
no session_code, wrong execution         the page, without it                           4624
a bogus session_code, wrong execution    the page, without it                           4624
valid session_code, no execution         the page, with it                              4989
no session_code, no execution            the **login page**                             7211
```

So the script is emitted exactly when the request carried a session code the tab
still recognised, and its URL is the request's own **rebuilt** rather than
echoed: a request sending `execution=BOGUS` gets a script naming the realm's real
execution id, in the order `execution, client_id, tab_id, client_data`.

**Two things Gloak disagrees with fall out of that grid**, and neither is F109's:

- a **bogus** session code with a live authentication session is 200 "Page has
  expired" on Keycloak and a restart 302 on Gloak. Gloak's `resolveAuthTab`
  refuses a wrong code; Keycloak resolves the tab by its id and lets the code
  decide only whether the request is a submission - which is exactly what
  `/login-actions/required-action`'s own comment already says about that
  endpoint. The measured restart branch is about the **authentication session**
  being gone, not the code being wrong.
- the restart 302 carries `execution` first:
  `?execution=<uuid>&client_id=…&tab_id=…&client_data=…`. Gloak's
  `writeRestartRedirect` builds three parameters and its doc comment says the
  measured order is `client_id, tab_id, client_data`.

Both are filed rather than changed: they are one branch-order change on a handler
with a committed golden beside it, and this cut is not that.

### 1.6 The two Passkey aliases are two pages, not one heading twice

`webauthn-register` and `webauthn-register-passwordless` differ in three places
beyond the volatiles:

```
execution=webauthn-register                vs  execution=webauthn-register-passwordless
residentKey : "not specified"              vs  residentKey : "required"
userVerificationRequirement : "not specified"  vs  "required"
```

`AGENTS.md` already records that the two aliases share one heading, and
`requiredActionTable` keys on the alias for that reason. This says the sharing
stops at the heading: a body built from the title would serve one client's
policy to the other.

### 1.7 F109's twelve, measured one branch at a time

| # | site | branch | answer |
|---|---|---|---|
| 1 | `loginactions.go` | unparseable `client_data` | 400 page, `Invalid Request` |
| 2 | `loginactions.go` | the client does not resolve, or is not the tab's | 400 page, `An error occurred, please login again through your application.` |
| 3 | `loginactions.go` | nothing to restart from | 400 page, `Restart login cookie not found. …` |
| 4 | `loginactions.go` | the restart's own client does not resolve | 400 page, `An error occurred, …` |
| 5 | `loginactions.go` | the body will not form-decode | **500 `application/json`** |
| 6 | `consent.go` | unparseable `client_data` at `/required-action` | 400 page, `Invalid Request` |
| 7 | `consent.go` | the client at `/required-action` | 400 page, `An error occurred, …` |
| 8 | `consent.go` | unparseable `client_data` at `/consent` | 400 page, `Invalid Request` |
| 9 | `consent.go` | the client at `/consent` | 400 page, `An error occurred, …` |
| 10 | `consent.go` | the body at `/consent` | **500 `application/json`** |
| 11 | `requiredactions.go` | the body in `runUpdatePassword` | **500 `application/json`** |
| 12 | `requiredactions.go` | the body in `runUpdateProfile` | **500 `application/json`** |

**Twelve sites, three sentences and one non-page.** The entry said guessing
twelve sentences does not close it, and the guess a reader would make is visible
in the count: `/auth` splits the four ways a client can fail into three
sentences, and this family answers **one** for all four - unknown, absent, empty,
and a real client that is not the tab's.

### 1.8 The `/login-actions` error page is the `/auth` error page

```
$ diff login-actions-page.html auth-page.html
92c92
<             <p class="instruction">Invalid Request</p>
---
>             <p class="instruction">Invalid parameter: redirect_uri</p>
```

One changed line in 3713 bytes. `themeErrorPageBody` already produced the whole
page, so F109's eight page sites were a change of call site and not new markup.

### 1.9 That page carries nothing per request, which is why it can be a golden

Its restart URL is `?client_id=<id>&skip_logout=true` and no more. No `tab_id`,
no `session_code`, no `checkAuthSession` block - the head ends at
`const isFirefox = true;`. It is the one page in the `/login-actions` family that
is not rendered from inside the authentication flow, and three of its twelve
branches are reachable **with no cookies at all**, which is what a fixture that
only creates a client can send.

### 1.10 The page's chrome names the request's client, not the tab's

Six cells on one container:

```
client_id resolves               restart?client_id=<it>&skip_logout=true, and its Back to Application link
client_id is another real one    restart?client_id=<that other one>, and **that** client's link
client_id unknown                restart?skip_logout=true, no link
client_id empty                  restart?skip_logout=true, no link
client_id absent                 restart?skip_logout=true, no link
no cookies at all, real client   restart?client_id=<it>, and its link
```

The second cell is the one nothing had measured, and it is the cell F109 named:
"nothing has measured which client that page's restart URL names". On that cell
the page's two halves describe two different judgements - the sentence says the
client failed, the chrome names it and offers a link to it.

### 1.11 The body decode runs after the realm and before everything else

```
an unknown realm  + a bad body   404 {"error":"Realm does not exist"}
bad client_data   + a bad body   500
no cookies at all + a bad body   500
an unknown client + a bad body   500
```

Measured on all three `/login-actions` endpoints and on `POST /auth` as the
control. The realm wins and nothing else does, so the decode is not the
endpoint's own judgement. **Gloak called `ParseForm` four levels down** - inside
`attemptLogin`, `consent`, `runUpdatePassword` and `runUpdateProfile` - so the
session and client checks ran first and it answered the 400 page on three of
those four rows. That is five endpoints on one rule now, and the first time the
rule was found by measuring a branch rather than by probing an endpoint.

### 1.12 VERIFY_EMAIL's 500 is the error page with the flow's chrome

`Failed to send email, please try again later.`, and its restart URL carries
`client_id`, `tab_id` and `client_data` - `prompt=create`'s shape, because this
page too is rendered from inside the authentication flow. It served the
placeholder body under a comment saying the sentence was measured and the chrome
was not; the chrome is measured now and the page is served. It cannot carry a
golden, for the nine pages' reason, and `TestVerifyEmailIsTwoAnswers` pins it.

### 1.13 The 500 is not byte-identical after all, and the byte is a Cache-Control

```
POST /auth                        500  no Cache-Control at all
POST /login-actions/authenticate  500  no-store, must-revalidate, max-age=0
```

Same status, same 94 bytes, same `application/json`, same five security headers,
and neither sends `Content-Language` or `Content-Security-Policy`. Found by
reading a recorded golden rather than by a probe, which is the second time this
project has learnt something from the recorder that a hand probe had walked past.

### 1.14 Lines this cut contradicts

**AGENTS.md**, "Things that look like bugs and are not":

- **"An undecodable request body is a 500 with a JSON body on both browser
  endpoints … and none of `Content-Language`, `Content-Security-Policy` or
  `Cache-Control`."** True of the two endpoints it names and false of the three
  `/login-actions` ones, which send `no-store, must-revalidate, max-age=0`. It is
  also no longer "both browser endpoints": there are five.
- **The `Cache-Control` table under "`state=` is echoed at `/auth` and dropped at
  `/logout`"** reads "three values across four rows". It is still three values,
  and there is a fifth row now - the `/login-actions` 500 - which is the first
  row in that table that is not a theme page at all.
- **"The theme page's chrome shows how far the request got, not what it asked
  for."** It holds on the two endpoint families it was drawn from and does not
  generalise: the `/login-actions` page names the client the request **asked**
  for even when the rejection is that the client is wrong, and the logout
  confirmation page names `account`, which no request in that flow asks for. That
  bullet has now been drawn from the endpoints that happened to be measured
  twice.

**The observed document**, "An undecodable body": nothing in it is falsified, and
that is because of one word. It says `POST /auth` and `POST /logout` are
"byte-identical **on both**" and lists "no Cache-Control" - a claim about those
two, correctly scoped, and true. What it is now is incomplete: three more
endpoints answer the same 94 bytes and **do** send a Cache-Control, so a reader
who took that block as the rule for the family would get all three wrong. The
section wants a line naming the three and the header, which is the difference
between a claim that survives a wider measurement and one that was only ever
about its sample.

Its `/login-actions` chapter records the branch each request takes and no page
body, so the three instructions and the chrome are additions to it rather than
corrections.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds this in.

> - **Twelve call sites on one page answer three sentences, and the four ways a
>   client can fail are one of them.** `/login-actions/authenticate`,
>   `/required-action` and `/consent` share a 400 page whose instruction is
>   `Invalid Request` for an unparseable `client_data`, `Restart login cookie not
>   found. …` when there is nothing to restart from, and `An error occurred,
>   please login again through your application.` for a client that is unknown,
>   absent, empty **or real and not the tab's**. `GET /auth` splits that same
>   fourth group into three sentences, so a reader who generalised from it would
>   have written three here. Measured 2026-09-02, one branch at a time, which is
>   what F109 asked for and what closed it.
>
> - **That page's chrome names the client the request sent, not the client the
>   tab belongs to.** A request naming a real client that is not the tab's
>   answers `An error occurred, …` - the sentence for a client that failed - over
>   a restart URL carrying `client_id=<that other client>` and a Back to
>   Application link to **its** `baseUrl`. Two halves of one response describing
>   two different judgements. An unknown, empty or absent `client_id` names none
>   and offers no link. And unlike every other page in this family the page
>   carries **nothing per request** - no `tab_id`, no `session_code`, no
>   `checkAuthSession` block - which is what makes it the only one of them a
>   golden can hold.
>
> - **A body that will not form-decode is a 500 on five endpoints now, it is
>   judged after the realm and before everything else, and the five are not
>   byte-identical.** `POST /auth`, `POST /logout` and all three
>   `/login-actions` endpoints answer
>   `500 {"error":"unknown_error","error_description":"For more on this error
>   consult the server log."}` with `application/json`, the five security
>   headers, and no `Content-Language` or `Content-Security-Policy` - **and the
>   three `/login-actions` ones send `Cache-Control: no-store,
>   must-revalidate, max-age=0` where the two browser endpoints send none.**
>   Same status, same 94 bytes, same everything else. This bullet said "on both
>   browser endpoints" and "no Cache-Control" until 2026-09-02, which was a
>   correct statement about the two endpoints it had, and it is the `Cache-Control`
>   table's fifth row - the first in it that is not a theme page. Measured
>   against every later check: bad `client_data`, absent cookies and an unknown
>   client all lose to the decode, and only an unknown realm beats it, answering
>   `404 {"error":"Realm does not exist"}`. So the decode is the container's
>   judgement rather than the endpoint's. Gloak called `ParseForm` four levels
>   down and answered the **400 page** on three of those four rows.
>
> - **All nine theme pages that still serve a placeholder body carry a `tab_id`
>   minted by the request that renders them**, measured 2026-09-02 - the logout
>   confirmation, "You are logged out", "Page has expired", the consent page and
>   the five required-action pages. Six of them carry a `session_code` as well,
>   five carry the `KC_AUTH_SESSION_HASH` inside `checkAuthSession(…)`, and three
>   carry a generated secret on top: a TOTP secret, a WebAuthn challenge and
>   twelve recovery codes. **None of the nine can carry a conformance golden**,
>   because `ReplaceCaptured` reaches only what a fixture step captured and every
>   one of these values is minted by the case's own request. So what keeps them
>   placeholders is state and a masking mechanism, not an unread instruction -
>   which is the opposite of what F146 assumed, and it is why this is written
>   down rather than left as a page count.
>
> - **The logout confirmation page names the `account` client, and no request in
>   that flow mentions it.** Measured on two sessions made by two different
>   clients: its restart URL and its confirm form's action both carry
>   `client_id=account`. "The theme page's chrome shows how far the request got"
>   is a rule about `/auth`'s family and `/login-actions`'; this page shows
>   neither. Its `<title>` is the second exception on one page: `Logging out`,
>   where every other page in the theme answers `Sign in to <displayName or realm
>   name>`.
>
> - **The `login-info` template's Back to Application link is not the
>   `login-error` template's.** `<p><a href="…">« Back to Application</a></p>` at
>   sixteen spaces against `<p><a id="backToApplication" href="…">…` at twenty.
>   One link, two templates, two spellings, and the rest of `kc-info-message` is
>   byte-identical between them - which is exactly the shape that invites a
>   shared helper and gets one of the two wrong.
>
> - **"Page has expired" is served for a session code that is merely wrong, and
>   the restart is about the session being gone.** Measured as a five-cell grid:
>   a valid code with a bad `execution`, an absent code, and a **bogus** code all
>   answer the page; only a browser whose authentication session cannot be
>   resolved restarts. The page also carries a `<SCRIPT> history.replaceState`
>   block exactly when the request's code was still spendable, and the URL inside
>   it is **rebuilt** rather than echoed - a request sending `execution=BOGUS`
>   gets the realm's real execution id back. Gloak refuses a wrong code and
>   restarts instead; the restart 302 it writes also omits the `execution`
>   Keycloak puts first. Both are unbuilt rather than wrong-and-unnoticed.
>
> - **`webauthn-register` and `webauthn-register-passwordless` share a heading and
>   not a page.** Beyond the `execution` and the per-request challenge, the
>   passwordless one answers `residentKey : "required"` and
>   `userVerificationRequirement : "required"` where the other answers
>   `"not specified"` for both. The two aliases sharing "Passkey Registration" is
>   already recorded here; what is new is that the sharing stops at the heading,
>   so a body built from the title would serve one policy under the other's name.

## 3. Follow-up dispositions

### F146 - open, and it is a different entry now

The entry reads "Each is an hour with a container; the instruction and the chrome
are what have to be measured." **Both halves are done and neither was the
blocker.** Every instruction and every chrome is in §1.1 and in the entries
above. What blocks all nine is a `tab_id`, and behind it two separate pieces of
work that no page count predicts:

- **Two of the nine need state Gloak does not create.** The logout confirmation
  and "You are logged out" are rendered from an authentication session Keycloak
  makes at the logout endpoint - it sets `AUTH_SESSION_ID` on a browser that has
  none and reuses the browser's when it has one. Gloak's logout endpoint creates
  none. That is a cookie grid of its own before a byte of markup is written.
- **Three of the nine need a generated secret.** CONFIGURE_TOTP, the two Passkey
  aliases and the recovery codes cannot be served without minting the thing the
  page is about.
- **The other four are buildable today** - "Page has expired", the consent page,
  UPDATE_PASSWORD and UPDATE_PROFILE - and every value they need is in hand,
  including the `checkAuthSession` argument, which is measured to be exactly the
  `KC_AUTH_SESSION_HASH` cookie's value and is `sessionHash(k, rootID)` in Gloak.
  The consent page additionally needs the client's scope consent texts, which is
  the one of the four with a dependency outside `internal/oidc`.

The entry should also lose its second paragraph's implication that the pages are
unmeasured, and gain the sentence that matters to whoever picks it up: **none of
the nine can carry a golden, so the cut that serves them is pinned by
`internal/httpx` and `internal/oidc` tests and moves no parity number.** That is
the same answer P13's mutation 18 forced for realm-derived values.

`themePageBody`'s doc comment now carries the table, so the list is beside the
code rather than only here.

### F109 - closed

All twelve measured, all twelve served: eight through `WriteThemeErrorPage` with
the measured instruction and `loginActionChrome`, four through
`writeUnparseableBody`. Four conformance goldens compare the page for the first
time, and `TestLoginActionErrorPageInstructions`,
`TestLoginActionErrorPageNamesTheRequestsClient` and
`TestUnparseableBodyIsA500OnTheLoginActionEndpoints` pin what the goldens cannot
reach - the twelfth branch needs a live tab, and a live tab means a `tab_id` in
the page it produces on every **other** page in the family, though not on this
one.

The entry's own closing condition was "It closes when somebody measures the
twelve, not when somebody guesses them", and the guess is visible in the count:
three sentences, not twelve, and one answer that is not the page at all.

### F72 - unchanged, and this cut deliberately did not touch it

`parkedGoldens` still holds exactly one entry, `oidc/authorization/prompt-create`.
**No second parked golden was added**, and the reason is worth saying rather than
leaving as an absence: a parked golden is a measurement kept where a reader can
see it, and the nine pages' measurements are §1.1 rather than nine committed
files nobody may compare. Committing nine HTML bodies that look like contracts
and are not would be exactly what F72's question was about, and the argument that
settled F72 - "a declared exception carrying its reason" - is satisfied by a
handover section for a set this size.

`TestNoPendingGoldenIsCompared`'s "parked == 0" guard is still one promotion from
firing and still has to be deleted rather than loosened when it does.

### F113 - intact, and it is what decided §1.1's last column

"A page carrying a per-request value cannot be `Recorded`" is the rule that made
the nine pages' column an arithmetic rather than a judgement. Each was requested
twice against one container; every one moved. None of them is `Recorded`, none is
`Pending` with a golden, and the four new cases are `Implemented` precisely
because the page they compare is the one in this family that does not move.

### F38 - its reopening condition is met nine times over

F38 closed on "one case is not a mechanism's evidence" and named its reopening
condition: "reopen it against a second case that wants the same mechanism."
P13 found the second, `prompt-create`. There are **eleven** now - those two,
`response-mode-form-post`, and the nine of §1.1 - and they are not eleven
variations: nine of them want the identical thing, a `tab_id` masked wherever it
appears in an HTML body.

That is still not an argument for building it blind. What it is an argument for
is that ground 1 ("it is one `Pending` case") and ground 4 ("the natural moment
to revisit is not now") have both expired, and the next cut that wants any of the
nine has to decide the mechanism before it writes markup. Ground 2 is the live
one: the values are at several positions per page, so the shape that fits is a
whole-body substitution pass like `ReplaceThemeResource` rather than the
per-case, per-position masker F38 describes.

### F151 - not repeated, and no mask was needed

Nothing in this cut wanted a mask on `prefixMasksLeftInPlace` or anywhere else.
The four new cases carry **no** `Volatile`, `VolatileHeaders` or `Unordered`
entries at all, which is the same property the seven `/auth` rejection cases have
and for the same reason: after `ReplaceIssuer` there is nothing per-request left
in them. No case was withdrawn.

## 4. Parity before and after

Read off the meter on both sides rather than incremented, which is the only way
this number has ever been right here:

```
Parity: 368 of 535 -> 373 of 540 (+5)

chapter                       served before  served after  documented before  after
oidc/authorization                       18            23                 21     26
```

(The previous handover reported 361 of 535; the tree has moved since, and 368 is
what its own merge base answers today.)

Five cases added, all `Implemented`, all in `oidc/authorization`:

- `oidc/authorization/login-actions-invalid-client-data`
- `oidc/authorization/login-actions-restart-cookie-missing`
- `oidc/authorization/login-actions-unknown-client`
- `oidc/authorization/login-actions-unparseable-body`
- `oidc/authorization/required-action-invalid-client-data`

`make record` added exactly those five goldens and moved nothing else.

## 5. Mutations

Twelve, one per claim, each applied on its own, each confirmed against the named
test, each reverted with `git checkout -- <one file>` off a committed tree.

```
 1  client_data answers the client sentence      TestLoginActionErrorPageInstructions
                                                  /authenticate, unparseable client_data
                                                 TestConformance/oidc/authorization/login-actions-invalid-client-data
 2  the client branch answers Invalid Request    TestLoginActionErrorPageInstructions
                                                  /authenticate, a real client that is not the tab's
 3  the restart sentence loses a full stop       TestLoginActionErrorPageInstructions (3 subtests)
                                                 TestConformance/.../login-actions-restart-cookie-missing
 4  the chrome never names a client              TestLoginActionErrorPageNamesTheRequestsClient (4 subtests)
                                                 TestConformance/.../login-actions-invalid-client-data
                                                 TestConformance/.../login-actions-restart-cookie-missing
 5  the decode moves behind the endpoint's       TestUnparseableBodyIsA500OnTheLoginActionEndpoints (4 subtests)
    own checks                                   TestConformance/.../login-actions-unparseable-body
 6  the 500 loses its Cache-Control              TestUnparseableBodyIsA500OnTheLoginActionEndpoints
                                                  /the Cache-Control is this endpoint's, not /auth's
                                                 TestConformance/.../login-actions-unparseable-body
 7  /required-action stops decoding first        TestUnparseableBodyIsA500OnTheLoginActionEndpoints (4 subtests)
 8  /consent stops decoding first                TestUnparseableBodyIsA500OnTheLoginActionEndpoints (4 subtests)
 9  VERIFY_EMAIL's chrome drops the tab          TestVerifyEmailIsTwoAnswers/unverified
10  VERIFY_EMAIL loses a full stop               TestVerifyEmailIsTwoAnswers/unverified
11  a new golden's /resources/ count is wrong    TestThemeResourceAppearsOnlyInTheThemePages
12  flowChrome drops the client_data             TestVerifyEmailIsTwoAnswers/unverified
```

**No survivors, and number 12 is the one worth reading.** It is killed by a
single subtest and by nothing else - and that subtest is one this cut wrote. The
same mutation applied to the *previous* tree would have survived the whole of it:
`flowChrome`'s two arguments lived inline in `writeRegistrationPage`, whose only
case is `oidc/authorization/prompt-create`, which is `Pending` with a parked
golden, so nothing compared them. Dropping `client_data` from the registration
page's restart URL was invisible until today, and it is visible now only as a
side effect of VERIFY_EMAIL borrowing the same helper.

That is the general shape P13's mutation 18 already found once: **a value only a
parked golden would show is a value nothing guards.** The parked golden is a
measurement, and a measurement nobody compares pins nothing.

## 6. What is left undone

- **The nine pages of §1.1.** §3's F146 note splits them into the two that need
  an authentication session at the logout endpoint, the three that need a
  generated secret, and the four that are buildable today.
- **The "Page has expired" branch order** and **the restart 302's `execution`**
  (§1.5). One handler, one grid, and a committed golden beside it.
- **F38's mechanism.** Nine cases want it; the shape that fits them is a
  whole-body pass, not the per-position masker the entry describes.
- **The `<html lang="en">` attribute** is still served as a constant. Whether it
  follows the realm's locale was not measured here either.
- **`prompt=create`'s `client_data`** is still unguarded by anything but the
  helper it now shares with VERIFY_EMAIL. §5's mutation 12 is the evidence; the
  fix is a package test naming that page, not a golden, because its golden is
  parked.

## 7. What surprised me

**That the blocker was never the thing F146 said it was.** The entry reads "the
instruction and the chrome are what have to be measured", and every instruction
and every chrome on all nine pages was readable in an afternoon. What none of
them buys is a comparable response, because all nine pages carry a `tab_id`. The
cut spent its measurement budget establishing that a page count was the wrong
unit - which is exactly what the brief warned about, arriving from the other
direction: not "the estimate was too small" but "the estimate was of the wrong
thing".

**That F109's page turned out to be the one page in its own family that a golden
can hold.** Twelve call sites that nothing compared, on an endpoint whose every
other response carries a `tab_id`, a `session_code` and a session hash - and the
error page carries none of the three, because it is the only page in the family
rendered from outside the authentication flow. The follow-up that looked
hardest was the one that was already a contract waiting to be recorded.

**That the golden found the Cache-Control and the probes did not.** Five
endpoints answering the same 94 bytes, and the one difference between them
surfaced while reading a recorded file, not while running any of the forty
`curl`s that produced the measurements above.
