# F38: masking a per-request value inside an HTML body

Branch `feat/theme-html-masking`, off `02b7a84`. Everything measured below was taken
on 2026-09-03 against a live Keycloak 26.7.1 - container `kc-mask`, port 8161,
`start-dev`, bootstrap admin `admin/admin`, removed afterwards.

F38 closed on 2026-08-29 on four grounds and was reopened on 2026-09-02 because
eleven cases want the mechanism. Three of the four grounds still hold, and §3
answers each. The cut is not done when the mechanism compiles; it is done when
cases that could not be compared before are compared, which is §5.

## 1. Why none of the four existing mechanisms does this

The harness already has four ways to make two responses comparable. Each of them
was read before this was designed, and each fails here for a different reason.

**`Case.Volatile` cannot address anything in an HTML body at all.** It is a list
of slash-separated paths into a *JSON document*: `Normalize` calls `editPaths`,
which builds a `json.NewDecoder` over the body and walks it. A theme page is not
JSON, so with any path declared `editPaths` returns a decode error rather than a
mask. The limitation is not that the path grammar is inconvenient here - there is
no path to write. `Case.Unordered`, `UnorderedKeys` and `UnorderedWords` are the
same walk with a different `onMatch` and are out for the same reason.

**`ReplaceCaptured` reaches exactly what a fixture step captured, and this cut
found the boundary is narrower than F146 stated.** It rewrites, wherever they
appear, the values in `sess.Vars`, and a step fills those from four places:
`Capture` (a path into a JSON response body), `CaptureHeader` (a whole header, or
a URL's last path segment), `CaptureForm` (`action`, or `input:<name>`) and
`CaptureQuery` (a query parameter of a `Location`).

F146 wrote that none of the nine pages can carry a golden because "every one of
these values is minted by the case's own request". That is true of the value's
**origin** and not of the fixture's **reach**, and the two come apart on eight of
the nine. On a page reached by walking the flow, the `tab_id` in the page is the
tab minted by the fixture's own `GET /auth` step, so `CaptureForm`'s `action`
already holds it and `ReplaceCaptured` already rewrites it. Measured: the login
form's action on the UPDATE_PROFILE walk carries `tab_id=4pNpkmXtLSE` and the
page it leads to carries that same value and no other. **The blocker on those
eight is not the `tab_id`.**

What is genuinely out of reach is smaller and sharper:

- **`prompt-create`'s two movers**, because that case's own request *is* the
  `GET /auth` that mints them. No step precedes it, so nothing can capture them.
- **the `KC_AUTH_SESSION_HASH`** on every page that carries it. It reaches the
  browser only inside a `Set-Cookie`, and `CaptureHeader` yields the whole header
  line - `KC_AUTH_SESSION_HASH="qxQ…";Version=1;…` - not the cookie's value, so
  the string that appears in the body cannot be captured.
- **a `session_code` a page mints while rendering itself.** Every render rotates
  one, so the code in a required-action page's form action is not the code the
  fixture spent to reach it.

**`ReplaceIssuer` and `ReplaceThemeResource` are unconditional and must stay
so.** `ReplaceThemeResource`'s own doc comment says why it has no catalogue
surface: "the value is a property of whichever server answered rather than of the
case that asked". A `tab_id` is the opposite - it is a property of the request -
and an unconditional `tab_id` pass would rewrite the value in any body, including
`oidc/device/authorization-request`, where a `tab_id` inside a `Location` is
part of what is asserted. So this mask has to be per case, which is exactly
F38's ground 1 and is answered in §3 rather than avoided.

**`VolatileHeaders` and `VolatileTailHeaders` reach headers and nothing else.**
`VolatileTailHeaders` is nevertheless the shape to copy: it names a value, knows
its grammar, keeps everything around it asserted, and **refuses** when the
grammar does not hold.

## 2. One row per candidate case

Measured on 2026-09-03 unless the row says otherwise. "Frames" is where each
per-request value sits in the markup. "Promoted" is this cut's answer.

| case / page | what it carries per request | frames | promoted | why |
|---|---|---|---|---|
| `oidc/authorization/prompt-create` | `tab_id` ×1, the auth-session hash ×1 | query value; JS call argument | **yes** | Gloak serves the markup already; the only two movers are the two the mechanism masks, and the `checkAuthSession` block is seven lines of measured markup |
| "Page has expired" (`login-login-page-expired`) | `tab_id` ×4, the hash ×1, and a `<SCRIPT> history.replaceState` block that comes and goes | query value ×4; JS call argument | **yes** | one new body template on the existing shell; the `tab_id` is fixture-capturable but the hash is not, and the case is what proves one declaration covers four positions |
| `oidc/authorization/response-mode-form-post` | `tab_id` ×1, the `code` and `session_state` `INPUT VALUE`s | query value; **input value** | no | Gloak answers this request the 400 page - `form_post` is in `responseModes` and not in `servableResponseModes`. That is F51, not F38: the mask is the smaller half |
| consent (`login-login-oauth-grant`) | `tab_id` ×2, the hash, a hidden `code` `INPUT` | query value; **input value** | no | needs the third frame and the client's scope consent texts |
| UPDATE_PROFILE (`login-login-update-profile`) | `tab_id` ×2, `session_code` ×1, the hash | query value ×2; JS call argument | no | every value is in reach of the two frames built here; what is missing is 7301 bytes of unwritten markup, which is F146's work and not this cut's |
| UPDATE_PASSWORD (`login-login-update-password`) | the same three | the same two frames | no | 10887 bytes of unwritten markup, and it is the one page in the family carrying **nine** `/resources/` segments rather than eight |
| CONFIGURE_TOTP (`login-login-config-totp`) | the same three **and** `<input … name="totpSecret" value="tt7lKUJ6Rrm7eL1dxcwT" />` | + input value | no | needs the third frame and a minted TOTP secret |
| Passkey ×2 (`login-webauthn-register`) | `tab_id`, `session_code`, a WebAuthn challenge | + input value | no | needs a minted challenge |
| recovery codes (`login-login-recovery-authn-code-config`) | the same three **and** `name="generatedRecoveryAuthnCodes"` holding twelve codes plus `name="generatedAt"` holding a millisecond clock | + input value | no | needs twelve minted codes and a clock |
| logout confirmation (`login-logout-confirm`) | `tab_id` ×2, `session_code` ×1 | query value | no | Gloak's logout endpoint creates no authentication session, which is a cookie grid before a byte of markup |
| "You are logged out" (`login-info`) | `tab_id` | query value | no | the same missing session |

What a mask over each of the two promoted values **still asserts**:

- **a query value.** The URL's scheme and path, every other parameter *and its
  value*, the order of all of them, and that the masked parameter is present with
  a non-empty value at exactly the positions the golden holds. On the expired
  page that is four positions in three different URLs - the head's restart URL,
  the `history.replaceState` argument and two `<a href>`s - and the `client_id`,
  `client_data`, `execution` and `skip_logout` beside it stay compared.
- **a JS call argument.** The `import { checkAuthSession } from …` line above it,
  the eight-space indentation the block is served at, the parentheses, the
  semicolon, the closing `</script>`, and that the argument is a non-empty quoted
  string. The whole block is 7 lines and the mask covers 64 characters of one.

The unit is deliberately the **value** and never its frame. Masking
`startSessionPolling`'s argument instead of the `tab_id` inside it would be the
same retreat AGENTS.md records for a whole `Location`: it would throw away the
realm, the endpoint, `client_id`, `client_data` and `skip_logout` to hide eleven
characters.

## 3. The design, and the three grounds it has to answer

Two fields on `Case`, one per measured frame:

```go
VolatileHTMLQuery []string   // query parameter names
VolatileHTMLCall  []string   // JS function names whose one string argument moves
```

Each writes `{{<name>}}` in the value's place. `ReplaceHTMLValues` lives in
`normalize.go` beside the other passes and is called from `normalisePasses`.

**Ground 1 - "a mask per case and per position is a per-case declaration", and
this project has a ratchet against masks that change nothing.** Two answers,
because the two failures are different:

- A declared name that appears **nowhere** in the body is an **error** from the
  pass itself, on both sides, the way `SortUnordered` errors on a path that is
  not an array. Masking nothing while claiming to have checked is the disease
  `Normalize`'s doc comment names.
- A declared name that appears and covers something that **never varies** is
  caught by `TestNoHTMLMaskVariesNothing`, which serves the case twice and
  requires the covered value to differ. This is the check `TestNoMaskIsInertOnItsGolden`
  explicitly cannot make for `Volatile` - "Normalize has already replaced the
  value with `"{{string}}"` by the time the file is written" - and it can be made
  here because the guard reads the served body before the mask runs.

  It is **not** AGENTS.md's forbidden inference. That rule is "no mask may be
  removed on the strength of two agreeing recordings", and it is about Keycloak's
  answer being stable across *container starts*. This guard is one process
  answering the same request twice, and a `Case` mask is by this project's own
  rule for a value that is per **request**: `ReplaceThemeResource`'s doc comment
  is where the split is written down, and a value that is installation-wide gets
  an unconditional pass rather than a catalogue mask. The failure message says
  both remedies. There is an exception list with a reason per entry, keyed the
  way `inertMasksLeftInPlace` is.

**Ground 2 - it has to survive `make record`.** `ReplaceHTMLValues` is called
from `normalisePasses` and from nowhere else, which is the one place both the
recorder and the verifier read. `passes.go`'s doc comment already states why:
"a pass added to one side and not the other is a divergence no test can see".
It runs after the two unconditional passes and before `Normalize`, which keeps
`passes.go`'s stated property - the unconditional substitutions first, then every
Case-declared mask.

**Ground 3 - it must not degrade to asserting presence and nothing else.** §2's
second table is the answer, and the two frames are chosen so that the smallest
maskable unit is the scalar. `TestHTMLMaskKeepsTheURLAroundIt` pins it from the
other side: a body whose `tab_id` matches and whose `client_id` does not must
still compare unequal.

The fourth ground - "the natural moment to revisit is not now" - expired when the
resource-version pass landed and eleven cases queued up behind it.

**The third frame is not built.** An `INPUT VALUE` masker has five would-be
consumers in §2 and **no** consumer in this cut, because every case those five
belong to is blocked on something else - unwritten markup, a minted secret, or an
unserved response mode. Building it here would be machinery whose consumer is a
guess about what the next cut wants, which is the sentence F38 closed on.

## 4. The markup this cut has to serve first

A mask on a page Gloak does not serve compares nothing, so two pieces of measured
markup come before the catalogue changes.

**4.1 The `checkAuthSession` block.** Measured on eight responses on one
container: it is emitted on `prompt=create`, on the login page, on "Page has
expired", on the consent page, on all four required-action pages and on
VERIFY_EMAIL's 500 - and **not** on `/auth`'s three 400 pages, the `/logout` 400
page, the `/login-actions` 400 page, or either device page. Every page that has
it carries **eight** `/resources/` segments where every page without it carries
seven, which is the count `TestThemeResourceAppearsOnlyInTheThemePages` already
holds. Its argument is byte-for-byte the `KC_AUTH_SESSION_HASH` cookie's value,
measured on the two responses that carry both. The block is byte-identical on
all four pages it was read from:

```
        <script type="module">
            import { checkAuthSession } from "/resources/<v>/login/keycloak.v2/js/authChecker.js";

            checkAuthSession(
                "<the KC_AUTH_SESSION_HASH cookie's value>"
            );
        </script>
```

So `ThemeChrome` gains one field, `themeHead` emits the block exactly when it is
non-empty, and `flowChrome` - the chrome for the two pages rendered from inside
the authentication flow - fills it. Nothing else changes, and the seven theme
goldens that carry seven segments keep carrying seven.

**4.2 "Page has expired".** A fourth body template on the existing shell,
`data-page-id="login-login-page-expired"`, heading indented eight spaces, and a
main block of one `<p id="instruction1">` with two links - a relative
`loginRestartLink` carrying `skip_logout=false`, and an **absolute**
`loginContinueLink` carrying the realm's real `execution`. Plus the
`<SCRIPT> history.replaceState …</SCRIPT>` appended after `</head>`, which is
emitted exactly when the request's `session_code` was still spendable and whose
URL is **rebuilt** rather than echoed.

Gloak already takes the right branch for the cell this cut records - a valid
`session_code` with a wrong `execution` - and serves the placeholder body there.
The two branch disagreements the previous handover filed (a bogus code, and the
restart 302's parameter order) are **not** touched here.

## 5. What gets compared that could not be

- `oidc/authorization/prompt-create` moves from `Pending` to `Implemented`.
  **`parkedGoldens` becomes empty**, so `TestNoPendingGoldenIsCompared` is
  **deleted** rather than loosened - its own comment and F72 both say so.
- a new case for the expired page, `Implemented`, in `oidc/authorization`.

Both need a fixture change: the expired page's case needs the login form's
`session_code`, `tab_id`, `client_data` and `execution` separately, so
`CaptureForm` gains a `query:<name>` kind beside its `action` and `input:<name>`.
It has a consumer in this cut; the `execution` capture is load-bearing twice over,
because Keycloak's execution id is a per-realm UUID and Gloak derives its own, so
without the capture the two sides could not agree on the `loginContinueLink`.

## 6. Order of work

1. `internal/httpx`: `ThemeChrome.AuthSessionHash`, the block in `themeHead`,
   package tests. Commit.
2. `internal/oidc`: `flowChrome` fills it. Commit.
3. `internal/conformance`: the two fields, `ReplaceHTMLValues`, `normalisePasses`,
   unit tests, the two guards and their can-fail tests. Commit.
4. Promote `prompt-create`, empty `parkedGoldens`, delete
   `TestNoPendingGoldenIsCompared`. `make record`. Commit.
5. `internal/httpx` + `internal/oidc`: the expired page. `CaptureForm`'s
   `query:` kind, the fixture, the case. `make record`. Commit.
6. Mutations, one per claim, each on a committed tree.
7. `docs/superpowers/handover/theme-html-masking.md`.
