# F38's mechanism, and the two pages it makes comparable

Branch `feat/theme-html-masking`, off `02b7a84`. Everything measured below was
taken on 2026-09-03 against a live Keycloak 26.7.1 - container `kc-mask`, port
8161, `start-dev`, bootstrap admin `admin/admin`, removed afterwards. The plan is
at `docs/superpowers/plans/2026-09-02-theme-html-masking.md`.

**F38 was reopened against eleven cases and this cut promotes two.** That is the
headline and so is the reason: **the eleven were counted from where each value is
minted, and the number that matters is how many a fixture cannot reach.** §1.2 is
the arithmetic, and it is smaller than eleven in one direction and larger in
another - two pages became contracts, six of the nine are now blocked on markup
and on nothing else, and one of the nine turns out never to have needed this
mechanism at all.

## 1. Measurements

### 1.1 The `checkAuthSession` block: which pages carry it, and what its argument is

Thirteen responses on one container, and the split is clean:

```
carries it (8 /resources/ segments)      does not (7 segments)
  GET /auth  prompt=create   400           GET /auth  bad redirect_uri   400
  the login page             200           GET /auth  unknown client     400
  Page has expired           200           GET /auth  max_age=abc        400
  the consent page           200           GET /logout bad target        400
  UPDATE_PASSWORD            200           GET /login-actions bad data   400
  UPDATE_PROFILE             200           GET /realms/master/device     200
  CONFIGURE_TOTP             200           GET .../device/status         200
  recovery codes             200
  VERIFY_EMAIL               500
```

A page rendered from **inside** an authentication flow has it and a page rendered
outside one does not. The status does not decide it - a 400, a 200 and a 500 are
all in the left column - and neither does the endpoint: `/auth` is in both.

**Its argument is the `KC_AUTH_SESSION_HASH` cookie's value, byte for byte.**
Measured on the two responses that set the cookie and carry the block in one
answer:

```
Set-Cookie: KC_AUTH_SESSION_HASH="qxQIJsm3/197eTsYFTx2C0S6h7o4jCQg0i6KMmnEpkL59tkabUw8k+5GqNVSnMTG"
     checkAuthSession("qxQIJsm3/197eTsYFTx2C0S6h7o4jCQg0i6KMmnEpkL59tkabUw8k+5GqNVSnMTG")
```

The cookie is quoted exactly when the value contains a `/`, which is the ordinary
cookie rule and is already what `httpx.SetKeycloakCookie` does.

The block itself is byte-identical on the four pages it was read off -
prompt=create's 400, "Page has expired", the consent page and UPDATE_PROFILE -
indented eight spaces where the two `<script>`s around it are indented four.

### 1.2 What a fixture can already reach, and what it cannot

This is the correction that decides everything below. F146 recorded:

> Every one of the nine carries a `tab_id` minted by the request that renders it
> … so **no golden in this harness can hold any of them**.

The first clause is about where the value comes from. The second is about what a
fixture can capture, and **it does not follow**. On every page reached by walking
the flow the `tab_id` in the markup is the tab the *fixture's own* `GET /auth`
minted, so `CaptureForm`'s `action` has always held it and `ReplaceCaptured` has
always rewritten it. Measured on the UPDATE_PROFILE walk: the login form's action
carries `tab_id=4pNpkmXtLSE` and the page it leads to carries that value and no
other.

Read per value rather than per page, the reach is:

| value | where it is minted | can a fixture capture it? |
|---|---|---|
| `tab_id` on a flow-walked page | the fixture's own `GET /auth` | **yes**, from the form action |
| `tab_id` on `prompt-create` | the case's **own** request | no - nothing precedes it |
| `execution` | the realm, at creation | **yes**, from the form action |
| `client_data` | the request's own parameters | it is a constant; a literal keeps it asserted |
| `session_code` a page rotates while rendering | the case's own request | no |
| `KC_AUTH_SESSION_HASH` | an earlier request, but it travels in a **`Set-Cookie`** | **no** - `CaptureHeader` yields the whole header line, not a cookie's value |
| a TOTP secret, a WebAuthn challenge, twelve recovery codes | the case's own request | no |

So the mechanism F38 declined is wanted by strictly fewer values than the entry
counted, and by two that nothing else in the harness can touch on **every** page
in the family: the session hash, and anything the case's own request mints.

### 1.3 The nine pages, one row each, with this cut's answer

| page | what moves | reachable by a capture | needs F38 | promoted |
|---|---|---|---|---|
| Page has expired | `tab_id` ×4, the hash, and a `<SCRIPT>` block | the `tab_id`, the `execution` | the hash | **yes** |
| consent | `tab_id` ×2, the hash, a hidden `code` | the `tab_id` | the hash, and an `INPUT VALUE` frame | no - 5486 bytes of unwritten markup |
| UPDATE_PROFILE | `tab_id` ×2, `session_code`, the hash | the `tab_id` | the hash, the `session_code` | no - 7301 bytes |
| UPDATE_PASSWORD | the same three | the same | the same | no - 10887 bytes, and **nine** `/resources/` segments where the rest have eight |
| CONFIGURE_TOTP | the same three **and** `name="totpSecret" value="tt7lKUJ6Rrm7eL1dxcwT"` | the `tab_id` | + an `INPUT VALUE` frame, + a minted secret | no |
| Passkey ×2 | the same three **and** a WebAuthn challenge | the `tab_id` | the same | no |
| recovery codes | the same three **and** `name="generatedRecoveryAuthnCodes"` holding twelve codes plus `name="generatedAt"` holding a millisecond clock | the `tab_id` | the same | no |
| logout confirmation | `tab_id` ×2, `session_code` | nothing - Gloak's `/logout` opens no authentication session | not the blocker | no |
| "You are logged out" | `tab_id` | the same | **not at all** | no |

The last row is worth reading twice. "You are logged out" carries one per-request
value and it is a `tab_id`; on a fixture that walks the flow that value is
capturable, so **that page never needed F38's mechanism**. What it needs is an
authentication session at the logout endpoint.

### 1.4 "Page has expired": three URLs to two endpoints and no two agree

```
the head's restart URL   relative,   …&client_data=…&skip_logout=true
loginRestartLink         relative,   …&client_data=…&skip_logout=false
loginContinueLink        absolute,   ?execution=…&client_id=…&tab_id=…&client_data=…
```

One page. Building any of the three from either of the others is the tidy-up that
breaks it, and mutations 12, 13 and 14 are each one of those three tidy-ups.

The `<SCRIPT> history.replaceState` block is emitted exactly when the request's
session code was still spendable, and the URL inside it is the continue link -
**rebuilt rather than echoed**. This cut's case sends
`execution=gloak-probe-not-an-execution` and the golden holds the realm's real
execution id in both places.

### 1.5 The 400 page's family is unchanged and the count is what says so

Every theme page with the block carries eight `/resources/` segments and every
page without it seven, with nothing in between.
`TestThemeResourceAppearsOnlyInTheThemePages` holds the number per golden and
gained one entry rather than a rule.

### 1.6 Lines this cut contradicts

**`internal/httpx/errors.go`**, `themePageBody`'s table, said "All nine carry a
tab_id minted by the request that renders them … none of the nine can carry a
conformance golden whatever else changes". Corrected in place: the tab_id is
capturable on eight of them, the hash was the real blocker, and the table now
names what actually stops each remaining page.

**The follow-ups list**, F146 and F38: see §3.

Nothing in AGENTS.md is falsified. Two of its bullets gain a sentence and §2 has
them.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds this in.

> - **A page rendered from inside the authentication flow carries a
>   `checkAuthSession` block and a page rendered outside one does not, and the
>   argument is the `KC_AUTH_SESSION_HASH` cookie's value byte for byte.**
>   Measured 2026-09-03 on thirteen responses on one container: `prompt=create`'s
>   400, the login page, "Page has expired", the consent page, all four
>   required-action pages and VERIFY_EMAIL's 500 have it; `/auth`'s three other
>   400 pages, `/logout`'s 400, `/login-actions`' 400 and both device pages do
>   not. The status does not decide it - a 400, a 200 and a 500 are all in the
>   first list - and neither does the endpoint, since `/auth` is in both. The
>   count says the same thing twice: **every page with the block carries eight
>   `/resources/` segments and every page without it seven**, with nothing in
>   between, which is what `TestThemeResourceAppearsOnlyInTheThemePages` holds
>   per golden.
>
> - **"A page carrying a per-request value cannot carry a golden" was a claim
>   about where the value is minted, and the harness's limit is where a fixture
>   can reach.** The two come apart. F146 counted nine theme pages as
>   ungoldenable because each carries a `tab_id` its own request minted; on eight
>   of them the tab is minted by the *fixture's* `GET /auth`, so `CaptureForm`'s
>   `action` has always held it and `ReplaceCaptured` has always rewritten it.
>   What genuinely could not be reached was smaller and is now two things: a
>   value the **case's own** request mints - `prompt-create` is that request -
>   and the `KC_AUTH_SESSION_HASH`, which travels only inside a `Set-Cookie`
>   whose whole header line is what `CaptureHeader` yields. Before writing that a
>   value cannot be compared, write down which fixture step would hold it.
>
> - **A mask over an HTML body is a mask over the value and never over its
>   frame.** `Case.VolatileHTMLQuery` masks a query parameter's value wherever a
>   URL carrying it appears in a page and leaves the path, every other parameter,
>   every other value and their order compared; `Case.VolatileHTMLCall` masks a
>   JavaScript call's one quoted argument and leaves the import above it, the
>   indentation, the parentheses and the semicolon compared. Masking
>   `startSessionPolling`'s whole argument instead of the `tab_id` inside it
>   would be the retreat this file already records for a whole `Location`:
>   presence and nothing else. **Two ratchets, because there are two ways such a
>   mask can be inert.** A name the body does not carry is refused by the pass
>   itself, on both sides; a name whose value never moves is
>   `TestNoHTMLMaskVariesNothing`, which serves the case twice and requires the
>   covered bytes to differ. That is not the forbidden inference from two
>   agreeing recordings - this is one process answering **the same request
>   twice**, and a `Case` mask is by this project's own rule for a value that is
>   per request, where an installation-wide value gets an unconditional pass
>   beside `ReplaceThemeResource`.
>
> - **"Page has expired" carries three URLs to two endpoints and no two of them
>   agree.** The head's restart URL is relative and ends `skip_logout=true`; the
>   body's `loginRestartLink` is the same path ending `skip_logout=false`; the
>   body's `loginContinueLink` is **absolute** and puts `execution` first, where
>   the login form's action puts `session_code` first. Building any of the three
>   from either of the others is the tidy-up that breaks it. The
>   `<SCRIPT> history.replaceState` block above the body is emitted exactly when
>   the request's session code was still spendable, and the URL inside it is the
>   continue link **rebuilt** rather than echoed - a request sending
>   `execution=BOGUS` gets the realm's real execution id back in both places.

## 3. Follow-up dispositions

### F38 - closed

The mechanism exists, it lives in `normalisePasses` so both sides run it, and it
has consumers: `oidc/authorization/prompt-create` uses both frames and
`oidc/authorization/session-code-wrong-execution` uses one. The three grounds
that still held are answered where the entry can be checked rather than in prose:

- *a mask per case is a per-case declaration, and there is a ratchet against
  masks that change nothing* - `ReplaceHTMLValues` refuses a mask that covers
  nothing, on both sides, and `TestNoHTMLMaskVariesNothing` refuses one that
  covers something that never moves. The headline mutation for this cut points a
  mask at `client_id` on a theme page and that test is what kills it.
- *it has to survive `make record`* - one call site, in `passes.go`. Mutation 3
  removes it and both new goldens go red.
- *it must not degrade to asserting presence and nothing else* -
  `TestHTMLMaskKeepsTheURLAroundItCompared`, and mutation 8, which widens the
  masked value to the rest of the URL.

**The third frame is deliberately not built.** An `INPUT VALUE` masker has five
would-be consumers in §1.3 and **no** consumer in this cut, because every case
those five belong to is blocked on something else. Building it would be the guess
about the next cut that F38 closed on the first time.

### F146 - open, and its blocker list is now per page

One of the nine is served. The entry should lose the sentence "none of the nine
can carry a conformance golden whatever else changes", which §1.2 refutes, and
gain the split §1.3 makes: **two need an authentication session at the logout
endpoint, three need a generated secret and an `INPUT VALUE` frame, and three
need markup and nothing else** - the consent page, UPDATE_PROFILE and
UPDATE_PASSWORD, all three of whose per-request values are in reach of what
exists today. That last group is the one to pick up next, and it is markup work
rather than harness work.

### F72 - closed, and the test it named is deleted

`parkedGoldens` is empty. `TestNoPendingGoldenIsCompared`'s own comment said
"when the last one goes, delete this test rather than loosening it", and it is
deleted; what it also asserted - that `GoldenIsAsserted` is false for `Pending` -
is `TestGoldenIsAssertedFollowsTheStatus`'s, one line above and unchanged.

`parkedGoldens` itself **stays, empty**, with `TestEveryParkedGoldenIsDeclared`.
That is the half of F72 that was never about how many there were: the next
`Pending` case that grows a golden without a reason still fails. Mutation 21 is
the proof.

### F113 - intact, and it is what this cut had to satisfy

"A page carrying a per-request value cannot be `Recorded`" is untouched. Both new
cases are `Implemented`, both are compared, and neither is `Recorded`. What
changed is not the rule but the reach: a per-request value that a **pass** can
mask on both sides stops being a reason a page cannot be compared, and the two
values this cut masks are now in that class.

### F107 - unchanged and untouched

The seven masks it lists are `Volatile` masks over JSON bodies in
`catalog_oidc_pending.go`. Nothing here narrows or widens one.

### F151 - not repeated, and `prefixMasksLeftInPlace` is unchanged

`catalog_test.go` was this cut's to edit and the ratchet needed no loosening. The
two entries on `prefixMasksLeftInPlace` are still there and still findings: both
want a **body-side `VolatileTail`** over a JSON value, which is a different
mechanism from this one - those values are JSON strings addressed by a
`Case.Volatile` path, where these are bytes inside HTML. The entries' own wording
- "narrowing it needs a body-side VolatileTail, which Case has not got" - is
still true, and this cut deliberately did not stretch the HTML masker to cover
them: it would have been one mechanism serving two grammars, and the JSON side
already has `MaskedValues` to narrow against.

What this cut adds to F151's lesson is the other direction. The new ratchet was
written **with** its exception list and its can-fail test in the same commit as
its first consumer, so the failure F151 records - a ratchet meeting a case in a
file the cut could not touch - cannot happen the same way here.

## 4. Parity before and after

Read off the meter on both sides rather than incremented:

```
Parity: 380 of 540 -> 382 of 541 (+2)

chapter                       served before  served after  documented before  after
oidc/authorization                       23            25                 26     27
```

Two cases:

- `oidc/authorization/prompt-create` - **promoted from `Pending`**, so it moves
  the numerator and not the denominator. It was the last parked golden.
- `oidc/authorization/session-code-wrong-execution` - **new**, and the first of
  F146's nine pages to be served and compared. It moves both.

`make record` moved exactly those two goldens and nothing else - and the second
full run found one thing the first could not. `prompt-create`'s two `Set-Cookie`
values churned on every re-record, because parking it had hidden the problem:
nothing rewrote the file, so nothing noticed that it holds two per-request cookie
values. It has `AssertHeaders: Set-Cookie` and `VolatileHeaders: Set-Cookie` now,
which is strictly more than it asserted before - **that the page opens an
authentication session at all** - and the churn is gone. F23 and F69 are the
entries; the lesson is that a golden's churn is invisible for exactly as long as
nobody re-records it.

## 5. Mutations

Twenty-one, one per claim, each applied on its own against a committed tree, each
confirmed against the named test, each reverted.

```
 1  a mask over a value that never varies      TestNoHTMLMaskVariesNothing
    (the headline: client_id on a theme page)   /prompt-create
 2  a mask over a value the body has not got   TestConformance/.../prompt-create
 3  normalisePasses stops running the mask     TestConformance/.../prompt-create
                                               TestConformance/.../session-code-wrong-execution
 4  a query mask fires on a longer key         TestHTMLQueryMaskDoesNotFireOnALongerParameterName
 5  a call mask fires on a longer name         TestHTMLCallMaskDoesNotFireOnALongerFunctionName
 6  a non-string call argument is masked       TestHTMLCallMaskRefusesAnArgumentThatIsNotAString
 7  an empty value is masked                   TestReplaceHTMLValuesRefusesAnEmptyValue
 8  the mask widens to the rest of the URL     TestHTMLMaskKeepsTheURLAroundItCompared
 9  the checkAuthSession rule is inverted      TestConformance, 5 subtests, both directions
10  the block is indented like its neighbours  TestTheAuthCheckBlockIsTheEighthResourceSegment
                                               TestConformance, both new cases
11  flowChrome stops filling the hash          TestConformance, both new cases
12  the body's restart link takes the head's   TestConformance/.../session-code-wrong-execution
    skip_logout
13  the continue link becomes relative         TestConformance/.../session-code-wrong-execution
14  the continue link takes the login          TestConformance/.../session-code-wrong-execution
    action's parameter order
15  the history.replaceState block is dropped  TestConformance/.../session-code-wrong-execution
16  the heading takes the info page's indent   TestConformance/.../session-code-wrong-execution
17  the links are written unescaped            TestConformance/.../session-code-wrong-execution
18  CaptureForm's query: returns the action    TestConformance/.../session-code-wrong-execution
19  the inert-mask ratchet reports nothing     TestHTMLMaskVariesGuardCanFail
20  the ratchet reads the mask's own output    TestNoHTMLMaskVariesNothing, both subtests
21  a Pending case grows an undeclared golden  TestEveryParkedGoldenIsDeclared
```

**Two survived on the first pass, both were defects in the tests rather than in
the code, and both were fixed:**

- **5** survived because its input was `preCheckAuthSession("A")`. The capital
  `C` means the needle `checkAuthSession(` never occurs in that name at all, so
  the test named a boundary rule its input could not reach. It reads
  `xcheckAuthSession` now.
- **8** survived because the test's `tab_id` was the URL's **last** parameter,
  where "mask to the next terminator" and "mask to the closing quote" cover the
  same bytes. The `tab_id` is first now, with two parameters behind it.

**And the revert of the manual re-run of 5 silently failed**, because it was
issued from inside `internal/conformance` with a path relative to the repository
root. `git checkout` reported `pathspec did not match` and the mutation stayed in
the tree; the next commit carried it, and what caught it was the strengthened
test failing one command later. This is the ninth-and-first-hundredth instance of
the hazard AGENTS.md's discipline section is about, in the direction nobody
watches: not "the revert destroyed my work" but "the revert did nothing and I did
not read its output". The fix is committed separately, one commit after the one
that carried it, so the sequence is legible in the log.

## 6. What is left undone

- **Three of F146's nine want markup and nothing else** - the consent page,
  UPDATE_PROFILE, UPDATE_PASSWORD. Every per-request value on all three is in
  reach today: the `tab_id` through a fixture capture, the `session_code` and the
  hash through this cut's two frames.
- **Three want an `INPUT VALUE` frame and a generated secret.** The frame is a
  third `Case` field of the same shape and is not built here because it would
  have no consumer.
- **Two want an authentication session at Gloak's logout endpoint**, which is a
  cookie grid before a byte of markup.
- **`oidc/authorization/response-mode-form-post` is still `Pending` and F38 is no
  longer why.** Its `Reason` says "the harness cannot mask a per-request value
  inside an HTML body", and it can now: the `tab_id` in its `history.replaceState`
  URL is `VolatileHTMLQuery`'s shape exactly. What stops it is that Gloak answers
  that request the 400 page - `form_post` is in `responseModes` and not in
  `servableResponseModes` - and its `code` and `session_state` are `INPUT VALUE`s.
  That is **F51**, and the `Reason` should be re-pointed at it.
- **The "Page has expired" cell Gloak does not serve.** A session code the tab no
  longer recognises answers this page *without* the `<SCRIPT>` block on Keycloak
  and a restart 302 on Gloak. That was filed on 2026-09-02 and is still filed; it
  is one branch-order change on a handler that now has a committed golden beside
  it, which makes it cheaper to attempt than it was.
- **The required-action landing's own expired page** keeps the placeholder,
  because its continue link would have to name an `execution` nothing has
  measured. One request would settle it.

## 7. What surprised me

**That the number in F38's reopening was counting the wrong thing.** "Eleven
cases want this mechanism" was read off where each value is minted, and the
question a harness answers is what a fixture step can hold. Reading it the second
way turned one of the nine into a page that never needed the mechanism, turned
three more into pure markup work, and left the mechanism with two consumers
instead of eleven - which is still two more than the one F38 closed on, and is a
much better description of what was built.

**That the cheapest thing to measure was the thing nobody had asked for.**
Eight `/resources/` segments against seven separates the pages with a
`checkAuthSession` block from the pages without one, exactly, on thirteen
responses - and that number was already asserted per golden by a test written for
an entirely different reason. The rule was readable off the repository's own
test table before any container was started; the container only confirmed it.

**That a failed `git checkout` looks exactly like a successful one.** §5's last
paragraph. The command printed an error, the shell moved on, and a mutated file
went into a commit. What caught it was a test written thirty seconds earlier for
an unrelated reason - which is the argument for strengthening a test the moment a
mutation survives it, rather than at the end of the pass.
