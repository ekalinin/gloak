# F142's protocol half: the realm-derived values in `internal/oidc` and `internal/httpx`

Branch `feat/oidc-realm-derived-values`, off `afdd00d`. Everything measured
below was taken on 2026-09-02 against a live Keycloak 26.7.1 - container
`kc-oidc2`, port 8157, `start-dev`, bootstrap admin `admin/admin`, removed
afterwards - or read off this repository's own catalogue and goldens. The plan
is at `docs/superpowers/plans/2026-09-02-oidc-realm-derived-values.md`.

It closes the four sites the previous cut left open on the protocol side, and
**every derivation site that remains is now in `internal/admin`**.

## 1. Measurements

### 1.1 `displayName` and `displayNameHtml`, all four states and three more

Twelve realms, each created through `POST /admin/realms`, each read back through
the Admin API, each asked for the 400 page an unknown `client_id` produces at
`GET /realms/{r}/protocol/openid-connect/auth`.

| realm | `displayName` | `displayNameHtml` | `<title>` | brand |
|---|---|---|---|---|
| `master` | `Keycloak` | `<div class="kc-logo-text"><span>Keycloak</span></div>` | `Sign in to Keycloak` | that wrapper |
| `gloak-probe-none` | absent | absent | `Sign in to gloak-probe-none` | `gloak-probe-none` |
| `gloak-probe-name` | `Probe Name` | absent | `Sign in to Probe Name` | **`Probe Name`** |
| `gloak-probe-html` | absent | `<div ...>Probe Html</div>` | `Sign in to gloak-probe-html` | that wrapper |
| `gloak-probe-both` | `Probe Both` | `<div ...>Probe Both Html</div>` | `Sign in to Probe Both` | that wrapper |
| `gloak-probe-empty` | `""` | `""` | `Sign in to gloak-probe-empty` | `gloak-probe-empty` |
| `gloak-probe-ws` | `"   "` | `"  "` | `Sign in to    ` | `  ` |
| `gloak-probe-plain` | absent | `plain no markup` | `Sign in to gloak-probe-plain` | `plain no markup` |

**The third row is the finding, and it corrects the sentence this cut inherited.**
Both AGENTS.md and the observed document say Keycloak "falls back to the realm
**name** in both". That is true of a realm carrying neither - which is the only
realm the previous cut had - and it is not the rule. Measured:

```
title  =  displayName      or  realm name
brand  =  displayNameHtml  or  displayName  or  realm name
```

The brand falls back to the **title's value**, so a realm with a plain
`displayName` and no `displayNameHtml` names it twice. One `if` more than the
sentence, and the one a created realm cannot show.

**An empty string counts as absent and whitespace does not.** Both `""` fall
back to the realm name; `"   "` renders three spaces into the title and `"  "`
two into the brand. The test is `length > 0`, not "has content".

**The `kc-logo-text` wrapper is `displayNameHtml`'s own markup, not the
template's.** `gloak-probe-plain` sets `displayNameHtml` to `plain no markup`
and the brand is exactly that, with nothing around it; every realm reaching the
brand through a fallback gets no wrapper at all. Rendering the wrapper around
whatever is there is the obvious implementation, it is right on master, and it
is wrong on every other realm on the server.

### 1.2 One page, two escapers, and the same character spelled two ways

One realm carrying every character an escaper might touch, read out of the title
and out of the brand's fallback branch:

```
displayName  a&b<c>d"e'f`g/h
<title>      a&amp;b&lt;c&gt;d&quot;e&#39;f`g/h
brand        a&amp;bd&#34;e&#39;f&#96;g/h
```

The title is Freemarker's HTML escaping, which is Go's `html.EscapeString` with
**one** difference: Go spells a double quote `&#34;` and Freemarker spells it
`&quot;`. Backtick and slash are untouched by both.

The brand is not escaped at all. It is Keycloak's HTML sanitiser and then raw
output, which is why `<c>` is gone with its angle brackets while `<b>` survives
elsewhere. Three more sanitiser measurements:

```
<b onclick="x">Bold</b>                                    ->  <b>Bold</b>
<span>ok</span><script>alert(1)</script><a href="javascript:x">l</a>
                                                           ->  <span>ok</span>l
a realm *named* gloak-probe<b>name                         ->  gloak-probe<b>name</b>
```

Event handlers stripped, `<script>` gone with its content, a `javascript:`
anchor unwrapped to its text, and an unbalanced tag in a **realm name** closed
by the parser. So the brand is
`sanitize(displayNameHtml or displayName or realm name)`, raw, and the quote is
`&#34;` there and `&quot;` eight lines higher up the same page.

**Gloak reproduces the escaping and not the sanitiser**, which is a divergence
rather than a simplification and is written into `ThemeChrome.brand`'s doc
comment as one. `html.EscapeString` is byte-exact against the sanitiser on the
fallback branch for any value carrying no markup and no backtick - the sanitiser
spells `&`, `"` and `'` the way Go does - so what diverges is a realm name or a
`displayName` that carries markup. Copying the rest means a safelisted HTML
parser and no value this project serves needs one.

### 1.3 The realm is on the page three times and no more

`diff` of the whole 400 page between two realms differing only in name and the
two display fields gives exactly three lines: the `<title>`, the restart URL
inside `startSessionPolling`, and the brand. Nothing else on the page follows the
realm, which is what makes "three times" a count rather than an estimate.

One thing fell out of it: the restart URL carries the realm **percent-encoded**
(`/realms/gloak-probe%3Cb%3Ename/login-actions/restart`) and `internal/httpx`
concatenates it raw. Recorded and not acted on - it is unobservable on any realm
name this project can produce.

### 1.4 A second realm's registration endpoint refuses master's administrator

Measured with a control, which is what makes it a finding rather than a flake:

```
master admin bearer -> POST /realms/master/clients-registrations/openid-connect            201
the same bearer     -> POST /realms/gloak-probe-second/clients-registrations/openid-connect 401
a garbage bearer    -> the same request                                                     401
```

Both 401s are
`{"error":"invalid_token","error_description":"Failed decode token"}`. The token
is verified against the realm in the **path**, so a cross-realm bearer is
indistinguishable from rubbish.

The observed document's registration chapter says "an **ordinary
administrator's access token** registers a client, and the initial access token
is not on the path". That was measured in master and is true there; it does not
generalise, and the chapter is master-only throughout.

**Gloak diverges here.** `registrationGrants` has a
`authRealm.Name == master && targetRealm != master` branch that resolves the
`<realm>-realm` admin container and lets the request through. That branch is
unreachable on Keycloak. Its own doc comment already says "only the
master-administering-master cell is measured on this endpoint"; a second cell is
measured now and it says the branch should not exist. Left alone deliberately -
it is an auth-order change on a family with fourteen goldens and it is not what
this cut is - and filed in §3.

Two consequences worth keeping:

- The only credentials that open that endpoint in a second realm are an initial
  access token, which is `POST /admin/realms/{r}/clients-initial-access` and is
  an Admin API route Gloak does not serve, and a registration access token,
  which needs a client that is already registered. That is why site 17 has a
  package test and no golden.
- An **anonymous** registration is refused identically in both realms:
  `insufficient_scope` /
  `Policy 'Trusted Hosts' rejected request to client-registration service.
  Details: Host not trusted.` So the client-registration **policies** are the
  same in a created realm as in master, which is one more thing a created realm
  does not differ in.

### 1.5 A client `baseUrl` cannot carry a double quote

`POST /admin/realms/{r}/clients` with
`"baseUrl": "https://app.example.com/x?a=1&b=\"q\"'z"` is
`400 {"error":"invalid_input","error_description":"Base URL is not a valid URL"}`.

That is what makes §1.2's escaper difference confined to one value. The theme
page's other interpolations - the instruction, the page title, the device form's
action, the "Back to Application" href - are measured constants or come from a
field Keycloak refuses to store a quote in. A realm's `displayName` is the one
value on these pages an administrator sets to anything.

### 1.6 The three survivors are survivors no longer

Each hard-coded `master` in turn, each against the whole tree:

| mutation | test that fails |
|---|---|
| `verificationURI` takes `master` | `TestDeviceAuthorizationNamesTheRequestsRealm` |
| `registrationURI` takes `master` | `TestRegistrationURINamesTheRequestsRealm` |
| `/auth`'s error-redirect `iss` takes `master` | `TestAuthorizationErrorRedirectNamesTheRequestsRealm` and `TestConformance/oidc/authorization/second-realm-error-redirect` |
| the device page's form `action` takes `master` | `TestDeviceVerificationPageNamesTheRequestsRealm` and `TestConformance/oidc/device/second-realm-verification-page` |
| the brand falls back to the realm name instead of `displayName` | `TestThemeChromeFollowsTheRealmsDisplayNames` |
| the `<title>` ignores `displayName` | `TestThemeChromeFollowsTheRealmsDisplayNames` |
| `escapeThemeTitle` becomes `html.EscapeString` | `TestThemeDisplayNamesAreEscapedByTwoDifferentRules` |
| the brand escapes `displayNameHtml` | `TestThemeDisplayNamesAreEscapedByTwoDifferentRules` |
| `realmDisplay` drops master's defaults | `TestRealmDisplayReadsTheRealmsSettings` |
| `themeChrome` stops passing the two fields | `TestConformance/oidc/device/verification-page` |

Ten mutations, ten named failures, **no survivors**. The last one is the one
worth having: it is the "before" state of this cut, and it fails on **master's**
theme goldens rather than on a second-realm one - so the two halves guard each
other.

### 1.7 The site table after this cut

Numbered as `docs/superpowers/handover/harness-second-realm.md` §1.2 numbers
them.

| state | sites |
|---|---|
| pinned by a second-realm golden | 8, 9, 11, 12, 13, 14, 18, 19 |
| pinned by a package test only | 15, 17 (and 13, 14, 19 a second time) |
| self-pinning | 16 |
| cannot be hard-coded | 20 |
| **still open** | **1-7 and 10 - every one of them in `internal/admin`** |

Zero measured survivors remain. The eight open sites are the seven admin
`Location` builders and the client `access` block, which is exactly the one
table §5.1 of the previous handover describes.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds this in. The first **replaces**
the theme bullet that is there now, because that bullet's fallback sentence is
the thing this cut corrected.

> - **A theme page names the realm three times and only one of them is the
>   restart URL.** The `<title>` is the realm's `displayName` and the header
>   brand its `displayNameHtml`, and the two fall back differently:
>   `title = displayName or the realm name`, and
>   `brand = displayNameHtml or displayName or the realm name`. **The brand
>   falls back to `displayName` and not to the name**, which is one `if` more
>   than this bullet said until 2026-09-02 - it was written from a realm
>   carrying neither, and a realm carrying neither is the one realm that cannot
>   tell the two readings apart. An **empty string counts as absent and
>   whitespace does not**: `""` renders the realm name and `"  "` renders two
>   spaces. Master's two values are `Keycloak` and
>   `<div class="kc-logo-text"><span>Keycloak</span></div>`, and that wrapper is
>   `displayNameHtml`'s **own markup** rather than the template's - a realm whose
>   `displayNameHtml` is `plain no markup` renders exactly that with nothing
>   around it. Serving master's two values as constants looks right because it
>   is right on the one realm every conformance case used to address.
>
> - **One theme page escapes the same character two ways, and which way is
>   decided by which field the value arrived in.** The `<title>` is Freemarker's
>   HTML escaping - `&amp; &lt; &gt; &quot; &#39;`, and a backtick and a slash
>   untouched - which is Go's `html.EscapeString` with `"` spelled `&quot;`
>   rather than `&#34;`. The header brand is not escaped at all: it is Keycloak's
>   HTML sanitiser and then raw output, which strips event handlers, drops a
>   `<script>` with its content, unwraps a `javascript:` anchor to its text,
>   closes an unbalanced tag - and spells a double quote `&#34;`. **Gloak
>   reproduces the escaping and not the sanitiser**, filed as a divergence; the
>   two agree on any value carrying no markup and no backtick, which is every
>   realm name and every plain display name. Only the `displayName` can reach
>   these pages carrying a quote at all: `POST /clients` answers
>   `Base URL is not a valid URL` to a `baseUrl` holding one, and every other
>   value on the page is a measured constant.
>
> - **A second realm's registration endpoint refuses master's own
>   administrator.** Measured with a control on 2026-09-02: one bearer registers
>   a client in master (201) and is refused in a created realm with
>   `401 {"error":"invalid_token","error_description":"Failed decode token"}` -
>   **the same answer a garbage bearer gets**, because the token is verified
>   against the realm in the path. "An ordinary administrator's access token
>   registers a client" is a measurement in master and does not generalise.
>   Gloak's `registrationGrants` has a master-administering-another-realm branch
>   that is unreachable on Keycloak, and it is a divergence rather than a
>   convenience. An **anonymous** registration answers the same
>   `Policy 'Trusted Hosts' rejected request` in both realms, so the
>   client-registration policies are one more thing a created realm does not
>   differ in.
>
> - **Twenty derivation sites, and every one still open is in
>   `internal/admin`.** Sites 14, 15, 17 and 19 closed on 2026-09-02 - the
>   device page's form action, the device grant's `verification_uri`,
>   `registrationURI` and `/auth`'s error-redirect `iss` - three of them the
>   measured survivors that took a hard-coded `master` with the whole tree
>   green. Two by a second-realm golden and a package test, two by a package
>   test alone: `registrationURI` cannot be reached in a second realm without a
>   credential Gloak does not mint, and the device authorization request's
>   `verification_uri_complete` cannot be masked without the body-side
>   equivalent of `VolatileTailHeaders` that F107 names. What remains is the
>   seven admin `Location` builders and the client `access` block, which one
>   table in `internal/admin` covers.

## 3. Follow-up dispositions

### F142 - the protocol half is closed; the entry should now be about `internal/admin`

The entry's "**Still open:** the seven admin `Location` sites, the `access`
block, the device page's form action, and the three **measured survivors**"
should become "the seven admin `Location` sites and the `access` block". The
three survivors are gone and the device page's action with them, each
mutation-tested (§1.6).

The general form stays and is still the point: **any value a handler derives
from the realm name is unpinned unless a second-realm case or a package test
says otherwise.** What changes is that the sentence is now true of one package
rather than three.

Two things the entry should gain, because they are the shape of what is left:

- **A second-realm case is not always available, and the reason is a mask.**
  `oidc/device/second-realm-authorization-request` was written, its fixture
  built and its golden recorded; it was then withdrawn, because masking
  `verification_uri_complete` is the mask `prefixMasksLeftInPlace` already
  records as too wide on the master sibling - `{{issuer}}` and more, thrown away
  to hide eight characters - and a second instance of a known-too-wide mask is
  not worth a second entry in a list of findings. That case is one body-side
  `VolatileTail` away.
- **A package test can close a site a golden cannot reach.** Site 17's
  credential does not exist in this project. Naming the two mechanisms as
  alternatives rather than treating the golden as the only answer is what let
  four sites close in one cut.

### F53 - followed again, and its fourth instance did not repeat

`Case.SecondRealm` stays a declaration, and this cut added one more fixture
creating a realm - `second-realm-browser`, which creates `gloak-probe-second`
idempotently rather than a realm of its own, **precisely because of F53's fourth
instance**: the bootstrapped administrator holds `create-realm`, so every realm
a fixture creates adds a `<realm>-realm` key to every realm-wide body master
serves. `oidc/introspection/active-refresh-token` carries `PristineRealm` now
and did not move on either recording.

That is the disposition: one realm shared by three fixtures rather than three
realms, chosen for F53's reason and confirmed by `make record` moving nothing.
Widening `TestNoGoldenHoldsAnObjectItDidNotCreate` to see a derived
`<realm>-realm` container is still not done and still belongs in a cut that can
afford to read what it turns up.

### F109 - untouched, and one line of it is now falsified in passing

F109 says `writeLoginActionErrorPage` keeps the placeholder body while the rest
of the page family serves markup, and that "the chrome would be unpinned too,
since nothing has measured which client that page's restart URL names".

Nothing about the login-actions family was measured here and the entry stands.
But the chrome's *other two* values are measured now, and the sentence should
say so: when those twelve call sites are measured, the page they build will
carry a `<title>` and a brand that follow the realm, and `ThemeChrome` already
has the fields for them. What is unmeasured on that page is the client in the
restart URL and the twelve sentences, not the chrome.

### F107 - the case this cut could not add is its example

F107 asks for a body-side equivalent of `VolatileTailHeaders`.
`prefixMasksLeftInPlace`'s comment already calls it "a mechanism and not an
edit". This cut is the first time the missing mechanism **cost a case** rather
than leaving an existing one wide: see §3's F142 note. The shape is a
`Volatile` entry that masks a value's tail after the last `/` and compares the
rest, and `oidc/device/authorization-request` and its second-realm sibling are
the two cases waiting for it.

### F146 - unchanged in count, smaller in scope

The nine theme pages still serving the placeholder body are unchanged. What is
smaller is what each of them will cost: the chrome is done, so a cut measuring
those pages measures instructions and headings rather than instructions,
headings and a header.

## 4. Parity

**361 of 535 before and after. No case moved in the meter.**

Three cases moved in the **catalogue** and every one of them is outside the
denominator, because `countsTowardsParity` is `!c.SecondRealm`:

- `oidc/authorization/second-realm-error-page`, `Recorded` -> `Implemented`.
  That promotion is the alarm the previous cut installed doing its job: the
  case was `Recorded` because Gloak served master's two display values as
  constants, and the moment the theme followed the realm it matched its golden
  and `TestConformance` refused to let it stay.
- `oidc/device/second-realm-verification-page`, new and `Implemented`.
- `oidc/authorization/second-realm-error-redirect`, new and `Implemented`.

Without the exclusion the total reads **367 of 541** - measured by flipping
`countsTowardsParity` to `true` and reading the meter, not computed - and all
six of those would be Gloak reading as serving more behaviours than it does,
which is the argument the flag was built on.
`TestSecondRealmCasesAreOutsideTheParityDenominator` fails on that same flip, so
the exclusion is guarded rather than assumed.

`make record` added two goldens - `oidc/device/second-realm-verification-page`
and `oidc/authorization/second-realm-error-redirect` - and moved none. Re-run on
the committed tree it moves **nothing at all**, which is the check that matters:
the first recording also built a device client in the second realm for the case
that was then withdrawn, so the two surviving goldens had to be shown
reproducible without it.

One thing about the recorder worth knowing before somebody debugs it: **`make
record` has no `-timeout` and Go's default is ten minutes per package.** A run
took 510s with one other container alive and was killed at 600s with three,
having reported nothing but a stack trace. `go test -timeout 25m -tags docker
./internal/conformance/ -run TestRecordGoldens` is the same run with room. This
is the failure AGENTS.md describes for CI and `synchronous(off)`, reappearing in
the one target that does not carry the flag.

## 5. What the next cut should do

`internal/admin`, and it is one file. `crossrealm_test.go` there already builds
a second realm through `bootstrap.CreateRealm`, so the claim is one table: a
create's `Location` names the realm the request addressed, over `POST /clients`,
`/users`, `/groups`, `/groups/{id}/children`, `/roles`, `/clients/{uuid}/roles`
and `.../identity-provider/instances`. Site 10 - the client `access` block,
decided by `isAdminContainerName` - is a separate claim in the same file,
because in a created realm the admin container is `realm-management` rather than
`<realm>-realm`.

Two smaller things, each named where it belongs rather than left implicit:

- The body-side `VolatileTail` (F107), which buys back
  `oidc/device/second-realm-authorization-request` and narrows the master
  sibling's mask at the same time. Narrowing the master one means removing
  `prefixMasksLeftInPlace`'s only entry, so that cut needs `catalog_test.go`.
- The registration endpoint's cross-realm bearer (§1.4). One branch of
  `registrationGrants`, and a case measuring the 401 in a second realm would
  pin it - which is a second-realm case that needs no client at all.

## 6. What surprised me

**That the sentence I was sent to implement was wrong, and that the realm which
found it was the one realm that could not see it.** The previous cut measured
one created realm, which carries neither display field, and wrote down "falls
back to the realm name in both". Every byte of that is what that realm answers.
The realm that separates the two readings is one with a `displayName` and no
`displayNameHtml`, and it is the third row of a table nobody had a reason to
build until the brief said "measure before you build".

**That one page spells a double quote two ways.** `&quot;` in the title and
`&#34;` in the brand, eight lines apart, because one goes through Freemarker's
escaper and the other through a sanitiser. Go's `html.EscapeString` happens to
be right for one of them and wrong for the other, and the only value that can
carry a quote to either is the one an administrator types.

**That the thing which stopped a case was a mask and not a measurement.** The
device authorization request in a second realm was measured, fixtured and
recorded, and then withdrawn because the only mask that expresses it is one the
repository already records as too wide. That is the mask ratchets working
exactly as designed - refusing a new instance of a known problem rather than
letting the exception list grow - and it is the first time one of them has cost
this project a case rather than saved it one.
