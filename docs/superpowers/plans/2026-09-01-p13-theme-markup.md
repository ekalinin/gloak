# P13, first cut: the login theme's markup

The eight parked goldens are the target. This plan says, per golden, what stands
between it and being a contract and whether this cut removes it; then what is
built; then what is deliberately not built.

Everything below the first section was measured on 2026-09-01 against a live
Keycloak 26.7.1, container `kc-theme` on port 8152, unless a line says
otherwise.

## 1. One row per parked golden

`served` is what Gloak answers today: the measured envelope with a placeholder
body. The last column is this cut's promise.

| golden | what stands between it and being a contract | removed here? |
|---|---|---|
| `oidc/authorization/invalid-redirect-uri` | the markup, and the `/resources/<version>/` segment (7 occurrences) | **yes** - markup + the substitution pass |
| `oidc/authorization/unknown-client-id` | the markup, the instruction (`Client not found.`), and the segment | **yes** |
| `oidc/authorization/max-age-invalid` | the markup, the instruction (`Invalid Request`), and the segment | **yes** |
| `oidc/logout/invalid-post-logout-redirect-uri` | the markup, the instruction (`Invalid redirect uri`), and the segment | **yes** |
| `oidc/logout/invalid-id-token-hint` | the markup, the instruction (`Invalid parameter: id_token_hint`), and the segment | **yes** |
| `oidc/device/verification-page` | the markup of a third template (`login-oauth2-device-verify-user-code.ftl`), and the segment | **yes** |
| `oidc/device/status-page` | the markup of a second template (`login-info`), and the segment | **yes** |
| `oidc/authorization/prompt-create` | the markup, the segment, **and two per-request values inside the body** - a `tab_id` in the restart URL and the authentication session's hash inside `checkAuthSession(...)` | **no** - see section 6 |

Seven of eight. The eighth is the one F38 declined a mechanism for, and this cut
does not build one; section 6 says why, and the case's `parkedGoldens` entry is
rewritten to name what is actually in it.

### The arithmetic, re-measured rather than inherited

The claim this cut rests on is "seven of the eight carry one per-request value".
It was checked directly rather than read off a diff: each of the eight requests
was issued **twice in a row against one container** and the two bodies compared.

```
invalid-redirect-uri           identical on two requests
unknown-client-id              identical
logout/invalid-post-logout     identical
logout/invalid-id-token-hint   identical
device/verification-page       identical
device/status-page             identical
max-age-invalid                identical
prompt-create                  DIFFERS - tab_id, and checkAuthSession's argument
```

`client_data` in prompt-create's restart URL is **not** volatile: it is a
base64 of the request's own redirect URI, response type and state, and it came
back identical on both requests. So prompt-create carries two moving values in
its body, not three.

## 2. What is actually in the markup

One head, three body templates. Measured byte for byte; the exact strings live
in `internal/httpx`.

The head is the same on all eight pages except for two things:

- **`/resources/<version>/`**, seven times (eight on prompt-create, whose
  `checkAuthSession` import is the extra one).
- **the restart URL** inside `startSessionPolling(...)`:
  `/realms/{realm}/login-actions/restart?<query>skip_logout=true`, where
  `<query>` is `client_id=<id>&` when the page's own rejection happened *after*
  a client was resolved, and empty otherwise.

The body varies in four things: `data-page-id`, the `kc-page-title` heading
block (with its measured leading whitespace, which is different on each of the
three templates), the main-body block, and - on the error page only - a
`backToApplication` link.

| page | `data-page-id` | heading | main body |
|---|---|---|---|
| error | `login-error` | `We are sorry...` | `<div id="kc-error-message">` + `<p class="instruction">` |
| info | `login-info` | the title, e.g. `Device Login Successful` | `<div id="kc-info-message">` + `<p class="instruction">` |
| device verify | `login-login-oauth2-device-verify-user-code` | `Device Login`, preceded by an FTL template comment | the user-code form |

### The instructions, measured one rejection at a time

The error page's instruction is the contract. Swept 2026-09-01:

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
GET /logout target with no hint         Missing parameters: id_token_hint
POST /login-actions/authenticate        Restart login cookie not found. It may have expired; it
                                        may have been deleted or cookies are disabled in your
                                        browser. If cookies are disabled then enable them. Click
                                        Back to Application to login again.
```

**An absent `client_id` and an empty one are two different sentences**, which
`authorize.go`'s own comment says they are not ("an absent, empty, unknown or
disabled `client_id` all answer the same 400, and the four pages differ only in
the prose"). Four spellings collapse to three, and the split is not where the
comment puts it: absent is `Invalid Request`, empty and unknown are both
`Client not found.`, disabled is `Client disabled.`

The device status page has two headings and three bodies, and the third body's
full sentence is longer than the constant beside it records:

```
?error= (empty or absent)   Device Login Successful   You may close this browser window and go back to your device.
?error=access_denied        Device Login Failed       Consent denied for connecting the device.
?error=<anything else>      Device Login Failed       You may close this browser window and go back to your device and try connecting again.
```

### The `backToApplication` link follows the client, not the rejection

Measured as a 2x2, because two examples both using `security-admin-console`
would have said nothing:

```
                        bad redirect_uri        max_age=abc
security-admin-console  link                    link
gloak-probe-browser     no link                 no link
```

and then the href itself, over five clients:

```
baseUrl absolute                       href = baseUrl
baseUrl relative, no rootUrl           href = <server base> + baseUrl
baseUrl relative, rootUrl absolute     href = rootUrl + baseUrl
rootUrl set, no baseUrl                **no link at all**
baseUrl ""                             no link
```

The fourth row is the one nobody would guess: a client whose only URL is a
`rootUrl` gets no link, so the link is decided by `baseUrl` alone and `rootUrl`
only supplies a prefix.

## 3. The resource version, and what it actually varies with

Every document in this repository that mentions it - `AGENTS.md`, F23,
`themePageBody`'s doc comment, four `parkedGoldens` entries and four catalogue
`Reason` strings - says it is "regenerated on every container start" or "minted
per container start". **It is not.**

```
six `docker restart` of one container        t72jg  t72jg  t72jg  t72jg  t72jg  t72jg
a second container from the same image       880ae
eight fresh databases in one container       ooekw oupiz 3fprx sktey foqmc k3fzh qctvi rj2lz
```

It survives a restart and is minted with the **database**: wiping
`/opt/keycloak/data/h2` and restarting mints a new one, and
`grep -rl t72jg /opt/keycloak/data` finds it inside `keycloakdb.mv.db`. Nothing
in the harness changes - `make record` starts a fresh container every time, so
every recording still sees a new value - but the claim in five documents is
wrong and is corrected in the handover.

### The pattern

Thirteen values have been measured: `l3kth`, `fl8wm`, `ynxld` (from the
goldens), `t72jg`, `880ae`, and the eight above. Every one is **exactly five
characters, lowercase letters and digits**. Sixty-five sampled characters with
no uppercase among them; if the alphabet were mixed-case alphanumeric that would
happen with probability `(36/62)^65`, about `10^-15`.

So the pattern is `/resources/[0-9a-z]{5}/`, written against what has been
measured and not against what a base64url token could in principle be.

**What it would do to a page that legitimately contains `/resources/` in
prose**: it would rewrite it, if and only if the very next path segment is five
lowercase alphanumerics and is followed by a `/`. Two of the shapes that hits
are worth naming because a reader would not expect either:

- **`login` is itself five lowercase alphanumerics**, so `/resources/login/x`
  is swallowed. The real theme URLs put `login` in the *second* segment
  (`/resources/<version>/login/keycloak.v2/...`), so this never fires on one -
  but a sentence naming the directory would be rewritten.
- **the pattern is not anchored to the start of a path**, so
  `/admin/resources/t72jg/x` is rewritten too.

That is a real over-reach and it is bounded by a fact rather than by a hope:
**`/resources/` appears in no golden in this repository except the eight theme
pages**, seven occurrences each and eight on prompt-create, and
`TestThemeResourceAppearsOnlyInTheThemePages` asserts that count, so the day a
ninth occurrence appears is the day somebody reads this paragraph.
`TestReplaceThemeResourceOverReachesExactlyHere` pins the two shapes above as
behaviour rather than leaving them to be discovered.

## 4. What is built

### `internal/conformance`

- `ReplaceThemeResource(raw []byte) []byte` in `normalize.go`, beside
  `ReplaceIssuer`, and called from `normalisePasses` so it runs on **both**
  sides. Unconditional, like `ReplaceIssuer`: the value is a property of the
  installation that answered, not of the case, so a per-case flag would be a
  mask somebody forgets.
- Tests in `normalize_test.go`: the thirteen measured values, a `/resources/`
  that is not followed by a five-character segment, an occurrence count over
  every committed golden, and the placeholder surviving a second pass.
- Seven cases promoted `Pending` -> `Implemented` in `catalog_oidc_pending.go`,
  their `Reason` strings dropped, and their seven entries removed from
  `parkedGoldens` in `case_test.go`.

### `internal/httpx`

- `ThemeResourceVersion`, minted once per process from `[0-9a-z]`, five
  characters - the measured shape.
- `ThemeChrome`, the two values the head varies in: the realm, and the client
  the restart URL names.
- Three page bodies: `themeErrorPageBody`, `themeInfoPageBody`,
  `themeDeviceVerifyBody`, all through the existing `writeThemeHTMLPolicy`, so
  a page gaining a real body still cannot gain a different header set.
- `WriteThemeErrorPage` grows the chrome, the instruction and the
  back-to-application href. `WriteThemeInfoPage` is new.
  `WriteThemeDeviceCodePage` gains the chrome.
- `themePageBody` **stays** for the pages this cut has not measured - the
  logout confirmation, "You are logged out", "Page has expired", the consent
  page and the five required-action pages. Giving them the real chrome under an
  invented instruction would be writing an observable value from memory, which
  is the rule this project puts above every other.

### `internal/oidc`

Each error-page call site passes the instruction its own branch was already
measured to serve, and the chrome its own branch resolved:

- `authorize.go` - five instructions across six call sites.
- `sso.go` - `Registration not allowed`.
- `logout.go` - three instructions, and the client resolved by step 3 only.
- `loginactions.go` - three instructions.
- `requiredactions.go` - `Failed to send email, please try again later.`
- `deviceverify.go` - the verify form and the info page's three bodies.

## 5. Order of work

1. Commit the plan.
2. The pass and its tests, alone, with the goldens untouched. `make test` green.
3. The markup in `internal/httpx` with its own tests. `internal/oidc` follows.
4. `make record` against a fresh container. Account for **every** file that
   moves: the expectation is exactly the seven promoted goldens and nothing
   else, because `grep -rl text/html testdata/golden/` finds only these eight
   files in the whole tree.
5. Promote the seven, drop their `parkedGoldens` entries, re-run.
6. Mutation-test every claim, one mutation at a time, each against the named
   test.

## 6. What is deliberately not built, and the F38 judgement

**Is this cut F38's "second case"?** F38 was closed as not worth building and
its own text says "if it is reopened, reopen it against a second case that wants
the same mechanism". The answer is **no**, and the reason is arithmetic rather
than taste:

- Seven of the eight pages want **no HTML masker at all.** What they wanted was
  the theme-resource pass, and that is a different shape from F38's ask. F38
  asks for "mask the value of this attribute at this place in the HTML" - per
  case, per position, declared in the catalogue. The theme-resource pass is one
  unconditional substitution of an installation-wide constant, exactly what
  `ReplaceIssuer` already is, with no catalogue surface at all.
- prompt-create alone still wants F38's mechanism, and one case is still one
  case. It is the same count F38 closed on.

So F38 stays closed, and its entry gains a line: the case that would have joined
`oidc/authorization/response-mode-form-post` is `oidc/authorization/prompt-create`,
and the two together are the evidence a third case would complete.

The judgement the previous cut got wrong is the opposite one and is worth
naming: it measured **prompt-create's** diff, found three churn sources, and
concluded the resource pass "fixes only a third of the churn". That is true of
prompt-create and false of the other seven, where the pass is the whole of it.
A judgement made from one example and generalised - the third of the three
failure modes this project keeps meeting.
