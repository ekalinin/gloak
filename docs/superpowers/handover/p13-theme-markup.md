# P13, first cut: the login theme's markup

Branch `feat/p13-theme-markup`. Everything below was measured on 2026-09-01
against a live Keycloak 26.7.1, container `kc-theme` on port 8152 (and a second,
`kc-theme2`, on 8153 for one question). Both are removed.

Seven of the eight parked goldens are contracts now. Parity 336 -> 343 of 535.

## 1. Measurements

### 1.1 The resource version is minted with the database, not with the process

This is the finding that matters most, because five places in this repository
say otherwise.

```
six `docker restart` of one container      t72jg t72jg t72jg t72jg t72jg t72jg
a second container from the same image     880ae
eight fresh databases in one container     ooekw oupiz 3fprx sktey foqmc k3fzh qctvi rj2lz
```

The value survives a restart. Wiping `/opt/keycloak/data/h2` and restarting
mints a new one every time, and `grep -rl t72jg /opt/keycloak/data` finds it
inside `keycloakdb.mv.db`. So the variable is the **database**, not the process
and not the container start.

Nothing in the harness changes - `make record` starts a fresh container each
time, so every recording still sees a new value - but the sentence is wrong in
`AGENTS.md`, in F23, in `themePageBody`'s doc comment, in four `parkedGoldens`
entries and in four catalogue `Reason` strings. Fixed on the branch everywhere
except `AGENTS.md` and F23, which I may not edit; section 2 has the replacement
bullet.

### 1.2 Thirteen values, all five lowercase alphanumerics

`l3kth`, `fl8wm`, `ynxld` (off the goldens), `t72jg`, `880ae`, and the eight
from the fresh databases. Sixty-five sampled characters, no upper case. A
mixed-case alphanumeric alphabet would do that with probability `(36/62)^65`,
about `1e-15`.

`ReplaceThemeResource`'s pattern is therefore `/resources/[0-9a-z]{5}/`, and
`TestReplaceThemeResourceRewritesEveryMeasuredVersion` holds all thirteen so the
evidence is beside the rule rather than in a document.

### 1.3 Seven of the eight parked pages carry one per-request value; one carries three

Each of the eight requests was issued **twice in a row against one container**
and the two bodies compared:

```
invalid-redirect-uri           identical
unknown-client-id              identical
logout/invalid-post-logout     identical
logout/invalid-id-token-hint   identical
device/verification-page       identical
device/status-page             identical
max-age-invalid                identical
prompt-create                  DIFFERS: tab_id, and checkAuthSession's argument
```

`client_data` in prompt-create's restart URL is **not** volatile - it is a
base64 of the request's own redirect URI, response type and state, and it came
back identical both times. So prompt-create carries **two** moving values in its
body, not three.

### 1.4 The error page's instructions

Swept one rejection at a time:

```
GET /auth   client_id absent            Invalid Request
GET /auth   client_id=                  Client not found.
GET /auth   client_id unknown           Client not found.
GET /auth   client disabled             Client disabled.
GET /auth   client bearer-only    403   Bearer-only applications are not allowed to initiate browser login
GET /auth   max_age=abc                 Invalid Request
GET /auth   redirect_uri unregistered   Invalid parameter: redirect_uri
GET /auth   redirect_uri absent         Invalid parameter: redirect_uri
GET /auth   prompt=create               Registration not allowed
GET /logout post_logout unregistered    Invalid redirect uri
GET /logout id_token_hint unusable      Invalid parameter: id_token_hint
GET /logout target, no client_id        Missing parameters: id_token_hint
POST /login-actions/authenticate        Restart login cookie not found. It may have expired; ...
```

**An absent `client_id` and an empty one are two different sentences.** Four
spellings collapse to three, and the split is not where `authorize.go`'s own
comment put it. A handler reading the value through `url.Values.Get`, which
cannot tell absent from empty, gets one of them wrong; the code now reads
presence off the map.

### 1.5 The logout page's grid: the variable is not whether a client resolved

Eight cells over `client_id` and the target:

```
client_id absent      Missing parameters: id_token_hint   registered target and not, alike
client_id=            Missing parameters: id_token_hint
client_id unknown     Invalid redirect uri                registered target and not, alike
client_id disabled    Invalid redirect uri
client_id known       Invalid redirect uri                when the target does not match
```

An unknown `client_id` and a real one give the same sentence; an unknown one and
an absent one do not. So the sentence turns on the request naming *something*,
and the page's chrome turns on that something resolving - two different
questions with two different answers on one response.

**An empty `client_id` counts as absent at `/logout` and as present at
`/auth`.** One parameter, two endpoints in one flow, opposite readings of
emptiness - the same shape `state=` already has across the same two endpoints.

### 1.6 The page's chrome follows the client, and the bearer-only cell is the odd one

The restart URL inside `startSessionPolling` carries `client_id=<id>` when the
page's rejection happened after a client was resolved. Two cells are not where a
reader would put them:

- a **bearer-only** client resolves - the 403 could not be decided otherwise -
  and its page names **no** client and offers no link, although `master-realm`
  has a `baseUrl`;
- `/logout`'s `id_token_hint` rejection names no client even when the request
  sent a good `client_id`, because the hint is judged first.

### 1.7 The "Back to Application" link is decided by `baseUrl` alone

Measured over five clients:

```
baseUrl absolute                    href = baseUrl
baseUrl relative, no rootUrl        href = <server base> + baseUrl
baseUrl relative, rootUrl absolute  href = rootUrl + baseUrl
rootUrl set, no baseUrl             **no link at all**
baseUrl ""                          no link
```

The fourth row is the one to keep. The admin console presents `rootUrl` and
`baseUrl` together as one "Home URL", so the obvious implementation -
concatenate whatever is there - puts a link on a client Keycloak gives none to.
`${authBaseUrl}` and `${authAdminUrl}` both expand to the server's base URL.

Measured as a 2x2 first, because two examples both using
`security-admin-console` would have said nothing: a client with a `baseUrl` gets
the link on a bad `redirect_uri` **and** on `max_age=abc`; one without gets it
on neither. **The link follows the client, not the rejection.**

### 1.8 The device verification form's action is the same on both paths

`GET /realms/master/device` and
`GET /realms/master/protocol/openid-connect/auth/device` produce
**byte-identical 4692-byte pages**, both naming `action="/realms/master/device"`,
relative. `serveDeviceCodePage`'s doc comment said the action echoed the path
the request arrived on. The code always built `/device`, so the code was right
and the sentence above it was wrong - the failure `AGENTS.md`'s charset bullet
describes. Gloak served the **absolute** form, which was a second, smaller
divergence, and both are fixed.

### 1.9 The device status page has two headings and three bodies

```
?error= (empty or absent)   Device Login Successful   You may close this browser window and go back to your device.
?error=access_denied        Device Login Failed       Consent denied for connecting the device.
?error=<anything else>      Device Login Failed       You may close this browser window and go back to your device and try connecting again.
```

The third sentence is the full one; `internal/httpx`'s constant block recorded
it as "… and try connecting again."

### 1.10 An undecodable request body is a 500, not a page

Measured on `POST /auth` and `POST /logout` with `client_id=x&%zz=1`:

```
500, Content-Type: application/json, the five security headers
{"error":"unknown_error","error_description":"For more on this error consult the server log."}
no Content-Language, no Content-Security-Policy, no Cache-Control
```

Byte-identical on both endpoints. Gloak answered the 400 error page on both -
the wrong status, the wrong `Content-Type` and the wrong family. Fixed, and
`TestUnparseableBodyIsA500` pins it.

A `POST` with an **empty** body is the 400 page with `Invalid Request`, so the
two are not one branch.

### 1.11 The device verification page's feedback alert

An unusable user code adds a `pf-v5-c-alert` block above the form: 5105 bytes
against the plain 4692, and the whole of the difference is that block, including
three runs of trailing whitespace inside the icon div where Freemarker
directives expanded to nothing.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, to be folded by hand.

- **The login theme's `/resources/<version>/` segment is minted with the
  database, not with the container start.** Six `docker restart` of one
  container gave one value; a second container gave another; wiping
  `/opt/keycloak/data/h2` and restarting gave eight more, and the value is
  inside `keycloakdb.mv.db`. This document, F23, `themePageBody`'s doc comment,
  four `parkedGoldens` entries and four catalogue `Reason` strings all said "per
  container start" until 2026-09-01, and the sentence had been copied five times
  without anybody restarting a container to check it. Nothing in the harness
  turns on it - `make record` starts a fresh container every run - which is
  exactly why it survived: a claim nothing depends on is a claim nothing
  falsifies. Thirteen values have now been measured and every one is five
  lowercase alphanumerics, which is what
  `internal/conformance.ReplaceThemeResource`'s pattern is written against.

- **An absent `client_id` and an empty one are different pages at `/auth` and
  the same page at `/logout`.** `GET /auth` with no `client_id` answers
  `Invalid Request`; with `client_id=` it answers `Client not found.`, exactly
  as an unknown one does; a disabled one answers `Client disabled.` So the four
  ways a client can fail are **three** sentences, and `authorize.go`'s own
  comment said they were four indistinguishable ones. At `/logout` the reading
  inverts: `client_id=` counts as **absent**, and an absent or empty one answers
  `Missing parameters: id_token_hint` where an unknown, disabled or real one all
  answer `Invalid redirect uri`. One parameter, two endpoints in one flow,
  opposite readings of emptiness - the third time this pair has disagreed, after
  `state=` being echoed at one and dropped at the other. A handler reading the
  value through `url.Values.Get` cannot see any of this.

- **The theme page's chrome names a client, and "the request named one" is not
  the test.** The restart URL inside `startSessionPolling` carries
  `client_id=<id>` exactly when the rejection happened *after* a client was
  resolved. Two cells break the obvious rule: a **bearer-only** client resolves,
  and its 403 page names no client and offers no Back to Application link
  although `master-realm` has a `baseUrl`; and `/logout`'s `id_token_hint`
  rejection names no client even when the request sent a good `client_id`,
  because the hint is judged first. So the page shows how far the request got,
  not what it asked for.

- **The error page's "Back to Application" link is decided by the client's
  `baseUrl` alone.** Measured over five clients: an absolute `baseUrl` is used
  as it is, a relative one is resolved against `rootUrl` or against the server's
  base URL when there is no `rootUrl`, and **a client carrying a `rootUrl` and
  no `baseUrl` gets no link at all**. The admin console presents the two
  together as one "Home URL", so concatenating whatever is there is the obvious
  implementation and it invents a link on that fourth row. `${authBaseUrl}` and
  `${authAdminUrl}` both expand to the server's base URL. The link follows the
  **client** and not the rejection: measured as a 2x2, a client with a `baseUrl`
  gets it on a bad `redirect_uri` and on `max_age=abc` alike, one without gets
  it on neither.

- **The device verification page is the same page at both its paths, action
  included.** `GET /realms/{realm}/device` and
  `GET /realms/{realm}/protocol/openid-connect/auth/device` answer
  byte-identical 4692-byte pages, and both name `action="/realms/{realm}/device"`
  - relative, and not the path the request arrived on. `serveDeviceCodePage`'s
  doc comment claimed the action echoed the arrival path and cited it as
  measured; it was not. The code had always built `/device`, so the code was
  right and the sentence above it was wrong, which is the failure mode the
  charset bullet describes and the second time it has been caught in this
  package.

- **An undecodable request body is a 500 with a JSON body, on both browser
  endpoints.** `POST /auth` and `POST /logout` carrying a bad percent escape
  answer 500 `{"error":"unknown_error","error_description":"For more on this
  error consult the server log."}` with `application/json`, the five security
  headers, and none of `Content-Language`, `Content-Security-Policy` or
  `Cache-Control` - so it is not the page family at all. A body that is merely
  **empty** is the 400 page with `Invalid Request`, so the two are separate
  branches. Gloak answered the page for both until 2026-09-01.

- **The device status page's third body is a longer sentence than it looks.**
  `?error=access_denied` is `Consent denied for connecting the device.`; every
  other non-empty value is `You may close this browser window and go back to
  your device and try connecting again.` - the success sentence with a clause
  appended, which is why it was written down truncated.

The existing bullet on `Cache-Control` across the page family ("three values
across four rows") is unchanged and was re-measured intact.

## 3. Follow-up dispositions

**F23** - *closed by this cut.* Its fix is exactly what it asked for: "a
normalisation pass replacing the resource version", now `ReplaceThemeResource`
in `internal/conformance/normalize.go`, in `normalisePasses` so it runs on both
sides. Its three named goldens are compared contracts. Its own text says the
value is "a per-container resource version" and that is the sentence section 2
corrects.

**F38** - *stays closed, and this cut is not the second case it asked for.*
Its reopening condition is "a second case that wants the same mechanism".
Seven of the eight pages wanted **no** HTML masker at all: what they wanted was
one unconditional substitution of an installation-wide constant, which is what
`ReplaceIssuer` already is and has no catalogue surface, where F38 asks for
"mask the value of this attribute at this place in the HTML", per case and per
position. `oidc/authorization/prompt-create` alone still wants F38's mechanism,
which is one case, which is what F38 closed on. Its entry should gain a line
naming prompt-create beside `response-mode-form-post` so a **third** case
completes the evidence.

The judgement F38's ground 4 anticipated is the one the previous cut got
backwards, and it is worth writing into the entry: that cut wrote the resource
pass, measured **prompt-create's** diff, found the segment was one churn source
of three, concluded "a third of the churn" and reverted. True of prompt-create,
false of the other seven, where the segment was the whole of it. A judgement
made from one example and generalised.

**F50** - *already closed; its remaining sentence is now false.* It ends "What
is still a placeholder is the page **body** - the theme's Freemarker output with
its per-container resource hash - not the flow. See F67." The body is served for
`/auth`'s whole page family now. The sentence should be replaced with a pointer
to what is still a placeholder: the login-actions family (F109's), the logout
confirmation, "You are logged out", "Page has expired", the consent page and the
five required-action pages.

**F67** - *closed by this cut.* All three logout instructions are served, each
from the branch measured producing it, and `TestLogoutPageInstructions` holds
the eight-cell grid that places them. The entry says "P13's, with F50" and both
are done.

**F69** - *unchanged, and re-verified by this cut.* `make record` moved exactly
the seven promoted goldens and left `prompt-create`'s alone, which is F69's
guarantee doing its job on a run that had every reason to disturb it.

**F72** - *unchanged in substance, smaller in scope.* `parkedGoldens` holds one
entry. `TestNoPendingGoldenIsCompared`'s "parked == 0" guard is one promotion
away from firing, and when the last one goes that test has to be deleted rather
than loosened - the comment there says so.

**F109** - *open, and now the reason is written down rather than implied.*
`writeLoginActionErrorPage` deliberately keeps the placeholder body. Twelve call
sites across three files reach it and no golden compares any of them, so mapping
each to one of the three measured sentences would be twelve unpinned judgements;
the chrome would be unpinned too, since nothing has measured which client that
page's restart URL names. It closes when somebody measures the twelve.

**F113** - *closed by this cut in the direction it pointed.* Its rule - "a page
carrying a per-request value cannot be `Recorded`" - is intact and is exactly
why prompt-create is still `Pending` rather than promoted with the rest. Its
last paragraph describes the reverted pass and calls it "machinery that fixes a
third of a problem and has no consumer"; the arithmetic in that sentence is
wrong for seven of the eight pages, and section 3's F38 note says how.

## 4. Parity before and after

```
Parity: 336 -> 343 of 535 (+7)

chapter                         before  after  delta
oidc/authorization                  15     18     +3
oidc/device                         13     15     +2
oidc/logout                         10     12     +2
```

Seven `Pending` cases became `Implemented`:
`oidc/authorization/invalid-redirect-uri`, `unknown-client-id`,
`max-age-invalid`, `oidc/logout/invalid-post-logout-redirect-uri`,
`invalid-id-token-hint`, `oidc/device/verification-page` and `status-page`.

`make record` moved exactly those seven files and nothing else, 49 lines each
way - seven `/resources/<version>/` occurrences per file becoming
`/resources/{{theme_resource}}/`. `oidc/authorization/prompt-create` did not
move, which is F69 working.

## 5. Mutations

Eighteen, one per claim, each confirmed against the named test, each reverted.

```
 1  rewrite only the first occurrence        TestReplaceThemeResourceRewritesEveryOccurrence
 2  {5} -> {4,6}                             TestReplaceThemeResourceLeavesAnUnmeasuredShapeAlone
 3  [0-9a-z] -> [0-9a-zA-Z]                  TestReplaceThemeResourceLeavesAnUnmeasuredShapeAlone
 4  one page's occurrence count              TestThemeResourceAppearsOnlyInTheThemePages
 5  drop the pass from normalisePasses       TestConformance/oidc/authorization/invalid-redirect-uri
 6  "Client not found." loses its full stop  TestConformance/oidc/authorization/unknown-client-id
 7  the link is rendered whatever the baseUrl TestConformance/oidc/authorization/max-age-invalid
                                              and TestBackToApplicationFollowsTheBaseURL
 8  the device form action goes absolute     TestConformance/oidc/device/verification-page
 9  the bearer-only page names its client    TestAuthorizePageNamesTheClientOrNothing
10  absent and empty client_id agree         TestAuthorizePageInstructions
11  the logout page turns on resolution      TestLogoutPageInstructions
12  the two device failure bodies collapse   TestDeviceStatusPageHasThreeBodies
13  the unparseable body is a 400 page again TestUnparseableBodyIsA500
14  the resource version gains a character   TestThemeResourceVersionIsTheMeasuredShape
15  the info heading loses four spaces       TestConformance/oidc/device/status-page
16  the info page uses login-error           TestConformance/oidc/device/status-page
17  the feedback alert is never rendered     TestDeviceVerifyPageCarriesTheFeedbackAlert
18  the restart URL hard-codes "master"      TestThemeErrorPageCarriesTheChrome
```

**One survived, and it is a finding about the suite rather than about the
code.** Mutation 18 - hard-coding `master` into the restart URL instead of using
the realm the page was built for - passed **the whole tree**, all seven theme
goldens included. Every conformance case in this repository runs against
`master`, so no golden here can tell a realm-derived value from that literal.
Fixed on the branch: `TestThemeErrorPageCarriesTheChrome` renders for
`gloak-probe-other` and asserts the string `/realms/master/` does not appear.
The general form is worth keeping in mind - **any** value derived from the realm
name is invisible to this catalogue, which is the same blind spot `session_state`
has and the same answer: `internal/httpx` and `internal/oidc`'s own tests.

## 6. What is left undone

- `oidc/authorization/prompt-create` is the one parked golden. Section 3's F38
  note says what it wants.
- Nine theme pages still serve the placeholder body: the logout confirmation,
  "You are logged out", "Page has expired", the consent page and the five
  required-action pages. Each is an hour with a container; the instruction and
  the chrome are what have to be measured, and `themePageBody`'s doc comment
  names the list.
- The `<html lang="en">` attribute is served as a constant. Whether it follows
  the realm's locale was not measured.
- `internal/oidc`'s `writeLoginActionErrorPage` divergence (F109) is unchanged
  and now documented at the function.
