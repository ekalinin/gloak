# F142's protocol half: the values `internal/oidc` and `internal/httpx` derive from the realm

Branch `feat/oidc-realm-derived-values`, off `afdd00d`. Everything measured below
was taken on 2026-09-02 against a live Keycloak 26.7.1 - container `kc-oidc2`,
port 8157, `start-dev`, bootstrap admin `admin/admin`, removed afterwards.

The cut before this one is
`docs/superpowers/handover/harness-second-realm.md`; its §1.2 site table, §5.1
and §5.2 are what this plan is written against.

## 1. `displayName` and `displayNameHtml`, measured across all four states

This is the section that decides `ThemeChrome`'s shape, and it is the thing
nobody had measured. Twelve realms, each created through `POST /admin/realms`,
each read back through the Admin API, each asked for the 400 page an unknown
`client_id` produces at `GET /realms/{r}/protocol/openid-connect/auth`.

The two lines that matter on each page:

```
    <title>Sign in to ...</title>
              class="pf-v5-c-brand">...</div>
```

### 1.1 The four states, and a fifth the brief did not ask for

| realm | `displayName` | `displayNameHtml` | `<title>` | brand |
|---|---|---|---|---|
| `master` | `Keycloak` | `<div class="kc-logo-text"><span>Keycloak</span></div>` | `Sign in to Keycloak` | `<div class="kc-logo-text"><span>Keycloak</span></div>` |
| `gloak-probe-none` | absent | absent | `Sign in to gloak-probe-none` | `gloak-probe-none` |
| `gloak-probe-name` | `Probe Name` | absent | `Sign in to Probe Name` | **`Probe Name`** |
| `gloak-probe-html` | absent | `<div class="kc-logo-text"><span>Probe Html</span></div>` | `Sign in to gloak-probe-html` | that wrapper |
| `gloak-probe-both` | `Probe Both` | `<div ...>Probe Both Html</div>` | `Sign in to Probe Both` | that wrapper |
| `gloak-probe-empty` | `""` | `""` | `Sign in to gloak-probe-empty` | `gloak-probe-empty` |
| `gloak-probe-ws` | `"   "` | `"  "` | `Sign in to    ` | `  ` |
| `gloak-probe-plain` | absent | `plain no markup` | `Sign in to gloak-probe-plain` | `plain no markup` |

**Three findings, and the third refutes the handover's own sentence.**

1. **The two fields are independent inputs to two different places.** The
   `<title>` reads `displayName` and only `displayName`; the header brand reads
   `displayNameHtml` first. `gloak-probe-html` proves the title ignores the
   html field and `gloak-probe-name` proves the brand does not ignore the plain
   one.

2. **An empty string counts as absent and whitespace does not.** Both `""`
   fall back to the realm name; `"   "` renders three spaces into the title and
   `"  "` two into the brand. The test is `length > 0`, not "has content".

3. **The brand's fallback is `displayName`, not the realm name.** The handover
   says Keycloak "falls back to the realm **name** in both", measured on one
   realm that had neither - which cannot tell the two readings apart.
   `gloak-probe-name` is the realm that can, and it says the chain is:

   ```
   title  =  displayName      or  realm name
   brand  =  displayNameHtml  or  displayName  or  realm name
   ```

   The brand's fallback is the title's *value*, so a realm with a `displayName`
   and no `displayNameHtml` names it twice. That is one `if` different from what
   the handover describes and it is the `if` a created realm cannot see.

### 1.2 The `kc-logo-text` wrapper is `displayNameHtml`'s own markup

Confirmed rather than newly found: it is not chrome the template puts around
the value. `gloak-probe-plain` set `displayNameHtml` to `plain no markup` and
the brand is `plain no markup` with no wrapper at all, and every realm falling
back to `displayName` or the realm name gets none either. Master's value simply
happens to carry one.

### 1.3 The two values are escaped by two different rules

Measured with one realm carrying every character an escaper might touch.

**The title** is Freemarker's HTML escaping:

```
displayName  a&b<c>d"e'f`g/h
<title>      Sign in to a&amp;b&lt;c&gt;d&quot;e&#39;f`g/h
```

That is Go's `html.EscapeString` with **one** difference: Go spells a double
quote `&#34;` and Freemarker spells it `&quot;`. Backtick and slash are
untouched by both.

**The brand** is not escaped at all - it is passed through Keycloak's HTML
sanitiser and emitted raw. The same value, reaching the brand through the
`displayName` fallback:

```
brand        a&amp;bd&#34;e&#39;f&#96;g/h
```

`<c>` is parsed as an unknown element and dropped, its contents kept; `&`, `"`,
`'` and a backtick are re-encoded, and the encoding of the quote is `&#34;`
where the title's is `&quot;`. Two spellings of one character on one page,
decided by which of the two values it arrived in.

Three more sanitiser measurements, because "it is emitted raw" is not the whole
truth and a reader would otherwise assume it is:

```
<b onclick="x">Bold</b>                       ->  <b>Bold</b>
<span>ok</span><script>alert(1)</script>
  <a href="javascript:x">l</a>                ->  <span>ok</span>l
a realm *named* gloak-probe<b>name            ->  gloak-probe<b>name</b>
```

Event handlers are stripped, `<script>` goes with its content, a
`javascript:` anchor is unwrapped to its text, and an unbalanced tag in a
**realm name** is closed by the parser. So the brand is
`sanitize(displayNameHtml or displayName or realm name)`, raw.

### 1.4 What this cut reproduces, and what it does not

Reproduced: the fallback chain, both `if`s, the emptiness rule, the title's
escaping (with `&quot;`), and `displayNameHtml` emitted raw.

**Not reproduced, and filed rather than left implicit:** the sanitiser. It is
jsoup with a Safelist, and writing an HTML parser to copy it is a cut of its
own with no measured value in this project pointing at it - master's
`displayNameHtml` is already clean and passes through byte for byte, and a
created realm has none. The fallback branch uses `html.EscapeString`, which is
byte-exact against the sanitiser for any value carrying no markup and no
backtick - which is every realm name and every plain `displayName`. The
divergence is a realm whose `displayName` or name carries markup.

### 1.5 The realm name is on the page three times and no more

`diff` of the whole 400 page between two realms differing only in name and the
two display fields gives exactly three lines: the `<title>`, the restart URL
inside `startSessionPolling`, and the brand. Nothing else on the page follows
the realm.

One more thing that fell out of it: the restart URL carries the realm
**percent-encoded** (`/realms/gloak-probe%3Cb%3Ename/login-actions/restart`).
`internal/httpx` concatenates it raw. Recorded, not acted on - it is
unobservable on any realm name this project can produce.

## 2. The three measured survivors, and how each is closed

Sites 15, 17 and 19 of the handover's table each take a hard-coded `master`
with the whole tree green. The plan closes all three, and site 14 with them.

| site | value | closed by |
|---|---|---|
| 14 | the device page's form `action` | a conformance case **and** a package test |
| 15 | the device grant's `verification_uri` | a conformance case **and** a package test |
| 17 | `registrationURI` | a package test |
| 19 | `/auth`'s error-redirect `iss` | a conformance case **and** a package test |

**Site 17 gets no conformance case, and the reason is measured.** A second
realm's registration endpoint refuses the bootstrapped administrator's
master-issued bearer with `401 {"error":"invalid_token","error_description":
"Failed decode token"}` - the token is verified against the realm in the path.
The two remaining ways in are an initial access token, which is
`POST /admin/realms/{r}/clients-initial-access` and is an Admin API route Gloak
does not serve, and a bearer minted inside that realm, which needs a user, a
password and a role assignment there. Neither is reachable from the files this
cut owns. The package test carries the claim instead, which is what
§5.1 asks for anyway.

## 3. The work

### 3.1 `internal/httpx`

- `ThemeChrome` gains `DisplayName` and `DisplayNameHTML`, the realm's two
  values **as stored** - empty when the realm has none. The fallback chain
  lives here rather than in the caller, because it is the template's rule and
  because the zero value then renders the measured answer for a realm that has
  neither.
- `themeHead` renders the title from the chain; `themeShell` renders the brand
  from it.
- One new escaper for the title, with the measured bytes in its doc comment and
  a note on why `html.EscapeString` stays everywhere else in the file.
- `TestThemeErrorPageCarriesTheChrome`'s doc comment loses the sentence "Every
  conformance case in this repository runs against master", which was false
  when it was written and is false twice over now.
- A new test for the chain, the emptiness rule and the wrapper.

### 3.2 `internal/oidc`

- `themeChrome` and `themeChromeFor` read the two values off the realm. They
  are the only two constructors of a `ThemeChrome` in the package, so this is
  two functions and one helper.
- The helper decodes `model.Realm.Settings` and falls back to master's measured
  pair, which mirrors `internal/admin`'s `decodeRealmSettings`: `bootstrap`
  writes no settings blob at all, so master's two values live in code on both
  sides of the wall.
- A `crossrealm_test.go` covering sites 14, 15, 17 and 19 plus the chrome, on a
  handler carrying a second realm built with `bootstrap.CreateRealm`. Nothing
  in that package builds one today.

### 3.3 `internal/conformance`

- Three new `SecondRealm` cases: `oidc/device/second-realm-verification-page`,
  `oidc/device/second-realm-authorization-request` and
  `oidc/authorization/second-realm-error-redirect`.
- `oidc/certs/second-realm` is **not** added. §5.2 names it as the one to leave
  alone: every value in that response is masked, so it would pin nothing.
- `oidc/authorization/second-realm-error-page` is promoted from `Recorded` to
  `Implemented` when the theme follows the realm. That promotion is the alarm
  working, and `TestConformance` demands it.
- Two fixtures, each creating its own realm, because
  `TestSecondRealmCasesAddressARealmTheyCreate` requires the case's own fixture
  to be the creator. They go in mid-map immediately after the `oidcCore` block.

### 3.4 Order

1. Measure (done - §1 and §2).
2. `internal/httpx`: the interface change and its test.
3. `internal/oidc`: the two constructors, the helper, the package tests.
4. `internal/conformance`: the fixtures and the three cases as `Recorded`,
   `make record`, read the diff, promote what matches.
5. Mutation-test every claim, one mutation per claim, each against a named
   test.
6. `make lint`, `CGO_ENABLED=0 go test ./...`, parity, handover, PR.

## 4. What could go wrong

- **The promoted theme case starts matching for the wrong reason.** The guard
  is that the second-realm error page golden holds
  `Sign in to gloak-probe-second` and the brand `gloak-probe-second`, and a
  hard-coded `Keycloak` fails it.
- **A new fixture creating a realm moves a committed golden.** It happened last
  cut, to `oidc/introspection/active-refresh-token`, and that case carries
  `PristineRealm` now. `make record` on a clean checkout moves nothing; any
  move gets read before it is committed.
- **`secondRealmGoldenFaults` refuses the bare substring `master`.** A
  second-realm golden holding it anywhere fails, which rules out any case whose
  response echoes an issuer this cut has not checked.
