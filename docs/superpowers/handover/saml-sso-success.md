# F227, first half: the eighth rung, and the page nobody had noticed was missing

Branch `feat/saml-sso-success`, off `main` at `b1cc071`. Everything measured
below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on 2026-09-18.

P11's second cut served the SSO endpoint's whole seven-rung rejection ladder and
stopped one below the success path, because "serving the eighth rung needs an
authentication session carrying the SAML request id and a signed assertion
builder". **That sentence contains the split, and it has three parts rather than
two.** The brief guessed two; the third is what actually kept the case `Pending`
for eleven days, and nobody had filed it.

Both routes' success paths are served now. `saml/endpoint` is 19 of 21 and
`saml/idp-initiated` is 6 of 6. Parity 614 -> 618 of 684.

---

## 1. Is the split real? Yes, and it is three-way

The brief's reading was that F227 conflates **the login page**, which needs no
cryptography, with **the assertion**, which needs canonicalisation. That reading
is right, and it is incomplete. Measured:

```
rung 8   the login page appears        a 200 carrying the theme's login form
rung 9   the assertion is issued       a signed samlp:Response posted to the ACS
```

and between them sat a third thing:

**The login form's markup did not exist in Gloak, on either protocol.**
`internal/httpx.WriteThemeLoginPage` wrote a hand-rolled stub - a `<!DOCTYPE
html>`, an `<h1>` and a three-input form - and `internal/oidc`'s `/auth` success
path used the same function. So:

```
grep -rl "kc-form-login" internal/conformance/testdata/golden/   ->  nothing
```

**No login form page was a golden anywhere in this repository**, on either
protocol, before this cut. Every theme golden in the tree is an error page, a
"Page has expired", a device page or a logout page.

That is what decided the split. The tab_id and the session_code - the blocker
`saml/endpoint/login-page`'s `Reason` named, and the one F113 stands behind -
were **not** the obstacle: `Case.VolatileHTMLQuery` reaches a query parameter
wherever it appears in markup and `Case.VolatileHTMLCall` reaches the
`checkAuthSession` argument, and both frames predate P11 by a fortnight. The
obstacle was that there was nothing true to compare them against.

So this cut is:

1. **the markup** - `themeLoginPageBody`, the fifth body template in
   `internal/httpx/theme.go` beside the error, info, expired and device ones.
   No cryptography, no SAML, and it serves both protocols;
2. **the session** - `authTab` gains two SAML fields and `clientData` gains two
   shapes;
3. **rung nine is refused**, named, and filed - §3.

The brief asked to be told plainly if its reading was wrong. It was right about
the boundary it drew and wrong about where the work was: it put the login page
under "needs no cryptography at all", which is true, and assumed the page itself
existed, which it did not.

---

## 2. Measurements

Two containers. `kc-saml-f227`, fresh, on port 18091, is where §2.1 to §2.7 come
from; the recorder's own container is the second and §5 is what it says. Both
are counted in §6.

### 2.1 The eighth rung, both bindings, side by side

One client, one message, one container:

```
GET  /realms/master/protocol/saml?SAMLRequest=<deflated>&RelayState=gloak-relay
200, 6931 bytes, the login page
Cache-Control: no-store, must-revalidate, max-age=0
Content-Language: en
Content-Type: text/html;charset=utf-8
Set-Cookie x3: AUTH_SESSION_ID, KC_AUTH_SESSION_HASH, KC_RESTART
**none of the five security headers, no Content-Security-Policy**

POST /realms/master/protocol/saml   SAMLRequest=<base64>&RelayState=gloak-relay
302, **empty body**, **no Content-Type at all**
Cache-Control: no-cache
Set-Cookie x3, the same three
Location: {base}/realms/master/login-actions/authenticate
          ?client_id=…&tab_id=…&client_data=…
none of the six
```

Two things fall out and both are new.

**The "none of the five" exception is the whole route and not its error
template.** P11 measured it on six 400 pages, so a reader could take it for a
property of `WriteThemeErrorPageBare`'s output. It is on a 200 with a 6931-byte
body and on a 302 with no body at all.

**The two bindings diverge at the top of the ladder and nowhere else.** Every
rung below answers the identical sentence over either binding; the eighth
answers a page over one and a redirect over the other. P11's F227 entry recorded
this from a single draw; it is re-measured here.

### 2.2 The same page, two protocols, complementary header sets

`GET /realms/master/protocol/openid-connect/auth` with a request that survives
every check answers **the same markup**. The whole diff between the two bodies,
6861 bytes against 6931:

```
the restart URL's client_id, tab_id and client_data
the checkAuthSession argument
the form action's session_code, client_id, tab_id and client_data
```

and nothing else. One template, two protocols. The header sets are
complementary:

```
                        the five + CSP    Cache-Control    Content-Language
/protocol/openid-connect/auth   all six   no-store, …      en
/protocol/saml                  none      no-store, …      en
/protocol/saml/clients/{name}   all six   no-store, …      en
```

The third row is measured too - §2.5 - and it is the same split the two routes'
400 pages already have, met on the answer that is not a refusal.

### 2.3 `client_data` has three shapes and `rt` means two different things

`client_data` is base64url of a four-key object, and it is where the whole of
what the authentication session carries becomes observable. Decoded:

```
OIDC /auth              {"ru":<redirect_uri>,"rt":"code","st":"xyz123"}
SAML /protocol/saml     {"ru":<ACS>,"rt":<the AuthnRequest's ID>,"rm":"post","st":<RelayState>}
SAML .../clients/{name} {"ru":<ACS>,"rm":"post"}
the device flow         {}
```

**`rt` is a response type on one protocol and a request id on the other**, and
on the IdP-initiated route the key is **absent** rather than empty - there is no
request and so no id. An implementation reusing the endpoint's encoder writes
`"rt":""` and is wrong on exactly that row, which is why
`internal/oidc.clientData.ResponseType` is a pointer.

**An empty `RelayState` is absent.** Six cells, one client:

```
RelayState=gloak-relay      "st":"gloak-relay"
RelayState=                 no "st" key at all
RelayState absent           no "st" key at all
```

`/auth`'s `state=` renders `"st":""`. So one parameter name, two protocols,
opposite readings of emptiness - the **third** time this pair of endpoints has
disagreed about exactly that, after `client_id=` and `state=`.

The `rt` value is the request's own `ID` attribute and is echoed, not rebuilt: a
message with `ID="ID_second_probe"` renders `"rt":"ID_second_probe"`.

### 2.4 `rm` is F228's first half, and `HTTP-Artifact` is the cell to get wrong

Eight cells over `saml.force.post.binding` and the request's `ProtocolBinding`,
one container, one client updated between draws:

```
saml.force.post.binding   ProtocolBinding                   rm
"true"                    absent                            post
"true"                    …bindings:HTTP-Redirect           post
"true"                    …bindings:HTTP-POST               post
"true"                    …bindings:HTTP-Artifact           post
anything else             absent                            get
anything else             …bindings:HTTP-Redirect           get
anything else             …bindings:HTTP-POST               post
anything else             …bindings:HTTP-Artifact           get
```

**`HTTP-Artifact` falls back to `get`.** The descriptor advertises an artifact
binding, the request names it by its correct URI, and the answer is the default
rather than a third value or a refusal. Only one of the four spellings moves the
answer.

And the attribute is compared to the exact string `"true"`, case-sensitively -
the same sweep `saml.client.signature` got, one value at a time on one client:

```
"true"    post          "false"   get
"TRUE"    get           ""        get
"True"    get           "0"       get
" true"   get           "no"      get
```

So it is `"true".equals(value)` on a **second** attribute. That is what made the
comparison a shared `samlAttributeIsTrue` rather than a second literal - the
place a `strconv.ParseBool` creeps back in is the copy.

F228 asked for this to be measured before a builder was written against it,
because the attribute is on by default, so whatever it does is what a default
client gets. Half of F228 is closed; the response *bindings* themselves - what
actually happens to the assertion once `rm` has been decided - are rung nine's
and are still unmeasured.

### 2.5 The IdP-initiated route's fourth rung

```
GET /realms/master/protocol/saml/clients/gloak-probe-idp
200, 6825 bytes, the login page
Cache-Control: no-store, must-revalidate, max-age=0
Content-Language, Content-Type, **all five security headers and a CSP**
Set-Cookie x3
client_data: {"ru":"http://localhost:9999/acs-post","rm":"post"}
```

The client carries `saml_assertion_consumer_url_post` and **no `redirectUris` at
all**, and it reaches the login page - which is P11 §1.5's second half
re-measured from the other side: a *named* assertion consumer URL is checked
against `redirectUris` and an *absent* one falls back to the attribute, checked
against nothing.

A `RelayState` may be sent here too, as a query parameter, and it follows the
endpoint's rule exactly:

```
?RelayState=gloak-relay                  "st":"gloak-relay"
?RelayState=                             no "st"
?SAMLRequest=zzz&RelayState=r            "st":"r"   - the SAMLRequest is ignored
```

The last row is worth keeping: this route reads no message at all, so junk in
`SAMLRequest` changes nothing.

### 2.6 A second request in one cookie jar sets one cookie

```
first request, no cookies      Set-Cookie x3: AUTH_SESSION_ID, KC_AUTH_SESSION_HASH, KC_RESTART
second request, same jar       Set-Cookie x1: KC_RESTART alone
```

Identical bodies apart from the three per-request values. This is `/auth`'s
measured "second tab, same jar" cell met on the SAML endpoint, and it is why the
fixture in §4 captures the execution id off the **Admin API** rather than off a
login page.

### 2.7 The re-render after a wrong credential is a different page

Measured because this cut touches the function that serves it:

```
the first render                   6861 bytes
the re-render after a bad password 8000 bytes
```

The difference is not a feedback line. It is `pf-m-error` on both form controls,
a `pf-v5-c-form-control__utilities` icon span, a `pf-v5-c-helper-text__item`
block naming the sentence, `aria-invalid="true"`, the username echoed, **and a
`history.replaceState` `<SCRIPT>` in the head** that the first render has no
trace of.

Not built; §3 says why.

### 2.8 The execution id is minted with the database

```
container A (kc-saml-f227)   execution=8f74661e-7dd2-4988-b524-276494dc0589
container B (the recorder)   execution=931121ad-c01e-4490-a473-63a0aefeeeb5
```

Two containers, the same realm name, two values. So a golden holding it churns
on every `make record`. §4.2 is what was done about that and why a mask is the
wrong answer.

---

## 3. Decisions, each with the alternative rejected

### 3.1 The login page's markup was built, and it is not SAML's

**Rejected alternative: serve the SAML login page from the existing
placeholder.** It would have made `saml/endpoint/login-page` a 200 and left it
`Pending`, because a placeholder cannot match a recording. The case would have
gone from "answers the wrong status" to "answers the right status with the wrong
bytes", which moves nothing on the meter and loses the one thing the 404 had
going for it - that it was honest about not being built.

**Rejected alternative: build the markup in the SAML branch.** The page is
`login.ftl` and `/auth` renders it too. A login form markup living inside
`samlendpoint.go` is the shape AGENTS.md refuses under F177 and F178 - a rule of
the whole surface fixed inside one branch. It is a fifth body template in
`internal/httpx/theme.go` beside the four that were already there, and it reuses
`themeShell` unchanged.

**How it was checked.** The oracle is Keycloak, not this package.
`internal/httpx/testdata/keycloak-26.7.1-login-page.html` is the recorded
response itself, and `TestLoginPageBodyIsTheMeasuredMarkup` renders
`themeLoginPageBody` and compares byte for byte with five values substituted -
each named one at a time, because a substitution list that grows silently is the
test giving up a byte at a time. It passed on the first run, which is the only
interesting thing about it: the template is transcription and the transcription
is checkable.

### 3.2 The re-render after a bad credential keeps the placeholder

**Rejected alternative: build it too.** §2.7 is a second page, not a variant: it
adds five markup blocks and a head script. Nothing in the catalogue compares it -
the credential POST's golden is a **302**, not a page - so building it would put
6900 bytes of unmeasured transcription under a response no test reads.

**Rejected alternative: render the measured first-render markup with a feedback
line spliced in.** That is inventing markup, which is the one thing this project
does not do.

So `WriteThemeLoginPage` branches: the measured body when there is no message,
the declared placeholder when there is. That is the arrangement F109 already has
at `writeLoginActionErrorPage` - a real body where it was measured and a
declared placeholder where it was not - rather than one page half measured. F269.

### 3.3 Rung nine answers the dispatcher's 404 rather than an authorization code

This is the decision with teeth, and it is the one a reader would get wrong by
doing nothing.

A SAML tab carries a redirect URI and a state, because `client_data`'s `ru` and
`st` are exactly those fields. So **every line of the OIDC ending runs on it to
completion**: `completeLogin` would mint an authorization code, put it in a
query, and send a SAML service provider `?code=…&state=…` at its assertion
consumer URL. Nothing measures that response, no SAML client would understand
it, and it is a worse divergence than answering nothing - which is P11 §2.2's
judgement one rung further up, applied here.

`finishFlow` therefore branches on `tab.SAMLBinding` before anything else and
`completeSAMLLogin` answers `HTTP 404 Not Found`. **No golden can see this** -
reaching it needs credentials - so `TestSAMLLoginDoesNotEndInAnAuthorizationCode`
is what holds it.

**Rejected alternative: refuse to open the session at all**, which is where P11
left it. That is the position this cut exists to leave: it confines the
divergence to rung nine instead of spreading it over rung eight as well.

### 3.4 `serveLoginPage` gained a client and a bare sibling rather than a flag

The two header sets are two writers, `WriteThemeLoginPage` and
`WriteThemeLoginPageBare`, and the two callers are `serveLoginPage` and
`serveSAMLLoginPage` over a shared `loginPageAction`.

**Rejected alternative: one writer taking a boolean.** That is the argument
`WriteLogoutRedirect`'s doc comment already makes for itself and
`WriteLoginActionRedirect`'s makes again: a shared writer taking the difference
as an argument puts it one call site away from being invisible, and this
difference - all six headers or none - is the one a reader comparing the two
routes most easily assumes away.

The **IdP-initiated** route goes through the ordinary writer, which is measured
and is the whole reason `samlLogin.BareHeaders` is a field rather than "this is
SAML".

### 3.5 The four goldens are recorded in a realm of their own

This one was found by recording into `master` first and reading the diff.

The login form renders **one `<a>` per identity provider in the realm**. The
recorder's shared `master` carries fifteen, put there by the identity-provider
chapter's fixtures, so the first recording of `saml/endpoint/login-page` came
back with sixteen social-login buttons in it and 17 `tab_id` occurrences instead
of 2. A golden whose content is decided by which other fixtures happened to run
is F230's disease with a second instance.

**Rejected alternative: reproduce the identity-provider section.** It would mean
Gloak's identity-provider list matching Keycloak's on a shared container whose
identity-provider set is decided by fixture ordering. That is F230
institutionalised.

**Rejected alternative: `Case.SecondRealm`.** These are not re-measurements of a
behaviour master already covers, and that flag takes a case **out** of the
parity denominator. `realmFixture` on a realm of its own is the established
pattern - `admin-token-client-profiles` and `defaultGroupsFixture` both do it -
and it has a bonus P13's mutation 18 asked for: every conformance case in this
repository addresses `master`, so a handler hard-coding a realm-derived value
compares equal to one deriving it. These four goldens name `gloak-probe-login`.

**What that costs, named rather than hidden.** Four branches of this page go
unmeasured: the social-provider section, the registration link, the "remember
me" checkbox and the "forgot password" link. All four are off on a realm created
through `POST /admin/realms` and on a default `master` alike, and
`internal/httpx` renders none of them. F271.

### 3.6 Four cases and not one

`saml/endpoint/login-page` alone would have left three measurements with no
golden under them.

- **`saml/endpoint/post-binding-login-redirect`**, because §2.1's divergence is
  the finding and one binding cannot show it. Its `Location` is masked, which is
  a real cost - the client_id, tab_id and client_data go with it - and it is
  paid once: the same three parameters in the same order sit unmasked in the
  page beside it, and no header mask in this harness reaches inside a query
  parameter (`MaskURLTail` covers a final path segment).
- **`saml/idp-initiated/login-page`**, because its `client_data` is the shape
  with a key missing and its header set is the endpoint's complement.
- **`oidc/authorization/login-page`**, because the markup is the same markup and
  two cases turn "the two agree" into a diff rather than a claim. It is also the
  one that catches the two writers drifting, which is the failure mode §3.4's
  argument creates.

---

## 4. The record diff, file by file

`make record` was run **twice**.

### 4.1 Run 1: four new goldens, nothing else moved, and one of them was wrong

```
oidc/authorization/login-page.http                  new
saml/endpoint/login-page.http                       new
saml/endpoint/post-binding-login-redirect.http      new
saml/idp-initiated/login-page.http                  new
```

**Nothing else moved at all**, which is the half worth stating on a cut that
changed the writer every theme page in the tree goes through: the eight existing
theme goldens came back byte-identical, so `themeShell`, `themeHead` and the
four body templates are untouched by the fifth.

Three of the four were right. `saml/endpoint/login-page` and
`saml/idp-initiated/login-page` were not, and the tell was in the placeholder
count:

```
{{tab_id}}         17 occurrences
{{session_code}}   16 occurrences
```

where the page carries two and one. §3.5 is what that was and what was done.
Those two goldens were deleted rather than committed; the fixture changed and
the run was repeated.

### 4.2 The execution id, and why it is a capture

Reading the first run's `saml/endpoint/login-page` against the container in §2
also settled §2.8: `execution=931121ad-…` there, `8f74661e-…` here. Per database.

A markup mask was the obvious answer and it is the wrong one.
`TestNoHTMLMaskVariesNothing` runs a case **twice against Gloak** and requires
each masked value to move between the draws; Gloak's execution id is a stable
per-realm derivation, so the mask would land in `htmlMasksLeftInPlace`. That
list's own error message says what to do with a value belonging to the
installation rather than the request - give it an unconditional pass beside
`ReplaceThemeResource` - and there can be no unconditional pass here, because
the value is a bare UUID and UUIDs are contract in a hundred other goldens.

So it is a fixture capture, which is what `browserExpiredPageFixture` already
does with the same value for the same reason. **The capture comes off the Admin
API's flow-executions listing and not off a login page**, because §2.6: the
harness resends every cookie a step collected, so a login page in the fixture
would leave the case's own request holding a live `AUTH_SESSION_ID` and the
goldens would assert the one-cookie cell instead of the three-cookie one.

Index 8 is `auth-username-password-form`, and that is not a guess: the seeded
browser flow's fifteen rows and their order are what
`admin/authentication-management/browser-executions` pins, on a realm of exactly
this fixture's kind.

### 4.3 Runs 2 and 3: the same four, and one of them was still wrong

Run 2, after the realm change and the capture:

```
oidc/authorization/login-page.http                  new
saml/endpoint/login-page.http                       new
saml/endpoint/post-binding-login-redirect.http      new
saml/idp-initiated/login-page.http                  new
```

with the placeholder counts the page actually has - two `{{tab_id}}`, one
`{{session_code}}`, one `{{execution}}`, eight `{{theme_resource}}` and four
`{{volatile}}` - and nothing else moved.

**Two of the four still failed `TestConformance`, on one key.** The recording
said `"rm":"post"` and Gloak said `"rm":"get"`, and reading the two bodies says
why: `POST /admin/realms/{realm}/clients` with `{"protocol":"saml"}` generates
**fourteen** attributes on Keycloak, `saml.force.post.binding: "true"` among
them, and **two** on Gloak - `realm_client` and `client.secret.creation.time`.
So the fixture created a client that was configured on one server and not on the
other, and the case was measuring the generation gap rather than the rule.

The fixture now spells the attribute out. That makes the input the same on both
servers so the case can be about `rm`; the generation gap itself is F272 and is
not this cut's - closing it would move every client golden in the tree.

Run 3, after that change: **no diff at all.** The attribute Keycloak already
generated, spelled out, changes none of its bytes - so the four goldens in the
tree are run 2's and run 3 reproduced them on a different container. That is the
draw F176 asks for and it is the reason it is worth stating: two containers, two
databases, identical bytes.

---

## 5. The mutation pass

Twenty-one mutations. The tree was committed and clean before the pass began,
each mutation was applied to the tree, `go build ./...` was checked to succeed,
**the whole package was run with no `-run` filter anywhere**, the revert is on a
`trap ... EXIT INT TERM` rather than on the happy path, and `git status
--porcelain internal/` was checked after every single revert. Nothing was
written to the tree while it ran - including this document, which is the rule
P11 earned by aborting its own pass at M1.

Every production mutation was run against **both** `internal/oidc` (or
`internal/httpx`) and `internal/conformance`, because contracts live in goldens
here, and the two columns are reported separately below precisely because they
disagree six times.

**Two survived the whole tree. Both are fixed and both are now killed; there are
no standing survivors.**

### The markup

| # | Mutation | Result |
|---|---|---|
| M1 | the heading loses the blank line after its template comment | killed by `TestLoginPageBodyIsTheMeasuredMarkup` and all three page goldens |
| M2 | the trailing-whitespace run after `autofocus` is dropped | killed by the same four |
| M3 | `data-page-id="login-login"` becomes `"login"` | killed by the same four |
| M4 | the inner footer's three newlines become one - **the device page's spelling** | killed by the same four |

M4 is the one worth having. The two templates' footers differ by two newlines
and nothing but a separate reading of each finds that, so this is the mutation
that asks whether `themeDeviceVerifyBody` was copied or `login.ftl` was read.

### The header sets and the redirect

| # | Mutation | Result |
|---|---|---|
| M5 | the SAML login page keeps the five - `SetSecurityHeaders` **added after** `ClearSecurityHeaders`, so the guard is still present | killed by `saml/endpoint/login-page` and `TestLoginPageHeaderSetsAreTheTwoMeasuredOnes/saml` |
| M6 | the POST binding's 302 sends the GET verb's `Cache-Control` | killed by `saml/endpoint/post-binding-login-redirect` and `TestSAMLLoginRedirectSendsNoneOfTheSix` |
| M7 | the POST binding's 302 names a `Content-Type` | killed by the same two |
| M8 | the first render takes the placeholder branch too | **survived `internal/httpx`**; killed by `oidc/authorization/login-page` and `saml/idp-initiated/login-page` |

**M8 is the pass's clearest lesson and it is about this repository's own rule.**
Two package tests cover this page and neither catches it:
`TestLoginPageBodyIsTheMeasuredMarkup` calls `themeLoginPageBody` **directly**,
so a writer that never calls it is invisible to the test that checks it; and
`TestLoginPageHeaderSetsAreTheTwoMeasuredOnes` asks only about headers. The
goldens are what fail. That is "a production mutation has to be run against the
package that can kill it" firing on the first cut that could have hidden it.

### The session and its three shapes

| # | Mutation | Result |
|---|---|---|
| M9 | `rt` is emitted whatever `hasResponseType` says | killed by `saml/idp-initiated/login-page` and `TestSAMLLoginPageCarriesTheMeasuredClientData` |
| M10 | a SAML tab renders the OIDC shape | killed by both SAML page goldens and four subtests |
| M13 | an empty RelayState counts as present, which is `/auth`'s rule | killed by `saml/idp-initiated/login-page` and three subtests |
| M17 | `rt` carries the `Issuer` rather than the `ID` | killed by `saml/endpoint/login-page` and three subtests |
| M20 | the restart record drops the tab's SAML fields | **survived; fixed** - see §5.6 |

M17 is the additive form of "a guard written from the value the thing under test
was built from cannot catch that thing being built wrong": the Issuer is a value
the request really sends, so `rt` stays present and non-empty and only its
contents are wrong. `samlClientDataOf` reads it back out of the rendered page
rather than calling `authTab.clientData`, which is what makes that catchable.

### The binding grid

| # | Mutation | Result |
|---|---|---|
| M11 | `samlResponseBinding` always answers `post` | **survived `internal/conformance`**; killed by `TestSAMLResponseBindingIsTheMeasuredGrid` |
| M12 | `HTTP-Artifact` is read as a POST binding | **survived `internal/conformance`**; killed by the same |
| M18 | `samlAttributeIsTrue` becomes `strconv.ParseBool` | **survived `internal/conformance`**; killed by that grid **and** by `TestClientRequiresSignatureComparesTheExactString` |

**Three mutations no golden can see, and one reason for all three.** Every client
in the catalogue that reaches a login page carries
`saml.force.post.binding: "true"` and every attribute in the tree is spelled
`"true"` or `"false"`, so a catalogue cannot separate `"true".equals(value)` from
a boolean parse and cannot separate the grid from the constant `post`. That is
P11's own M14/M15/M25 shape - "every case in this chapter is a rejection" -
arriving on a chapter that now has three successes and still cannot see this.
The grid test is why it exists and §7's argument for a package test beside a
golden is exactly this.

M18 is also the one that says a shared helper pays for itself: **one edit to one
function failed two tests written for two different attributes**, which is what
the `samlAttributeIsTrue` extraction was for.

### The ladder and the ending

| # | Mutation | Result |
|---|---|---|
| M14 | both bindings render the login page | **survived `internal/oidc`**; killed by `saml/endpoint/post-binding-login-redirect` |
| M15 | both SAML routes use the bare writer | killed by `saml/idp-initiated/login-page` and `TestSAMLLoginPageSendsNoneOfTheSixAndTheIdPInitiatedOneSendsThemAll` |
| M16 | the RelayState is read from the query on both bindings | **survived; fixed** - see §5.6 |
| M19 | `finishFlow` drops the SAML branch | **survived `internal/conformance`**; killed by `TestSAMLLoginDoesNotEndInAnAuthorizationCode` |

M19's column split is the one §3.3 predicted: no golden can reach the ninth rung,
because reaching it needs credentials, so the test that holds the refusal is the
only thing standing between a SAML service provider and an OIDC authorization
code at its assertion consumer URL.

### The harness

| # | Mutation | Result |
|---|---|---|
| M21 | the fixture captures index **12** rather than 8 - a real execution id off the wrong row | killed by all three page goldens |

M21 is the one that asks whether a **capture** can be silently wrong. It yields a
well-formed UUID that `ReplaceCaptured` rewrites on both sides, so nothing about
the golden's *shape* changes - and it dies anyway, because the two sides then
disagree about which id the page carried. A capture is not a mask: it asserts
the value came from somewhere, and naming the wrong somewhere is a diff.

### 5.6 The two survivors, and what was done about each

**M16 - the HTTP-POST binding's RelayState, and a masked header is a blind
spot.** Reading it out of the query instead of the form survived
`internal/oidc` and `internal/conformance` both. Reading the mutated lines says
why: `saml/endpoint/post-binding-login-redirect` masks its `Location` **whole**,
because the header carries a freshly minted tab_id and no header mask in this
harness reaches inside a query parameter - so the client_id, the tab_id and the
client_data go with it, and the whole of what that mutation changed lives inside
the masked value. The 302's status, its `Cache-Control` and all eight absent
headers are unaffected.

That is §3.6's cost, named there as a cost and found here to be a real one.
`TestSAMLPostBindingReadsItsRelayStateFromTheForm` is the fix, and **its first
version was wrong in a way worth writing down, because it is this project's own
failure shape met on the test written to close that shape.**

### 5.7 R2: the fix was one input short, and review caught it

The first version sent **both** spellings with different values, and the
sentence beside it claimed that also covered a handler calling `r.FormValue`.
Review put that claim under a mutation - `return r.FormValue("RelayState")`,
the whole function body - and **it survived the tree**.

Go's own semantics say why, measured rather than read off the documentation:

```
body            query            FormValue         PostFormValue
from-the-form   from-the-query   "from-the-form"   "from-the-form"
from-the-form   -                "from-the-form"   "from-the-form"
-               from-the-query   "from-the-query"  ""
```

`ParseForm` fills `r.Form` with the **body's** values first and appends the
query's, and `FormValue` returns `r.Form[k][0]`. So the two readers agree on
every input where the body carries the parameter and differ on exactly one: **a
POST whose body omits it and whose query carries one.** Sending both spellings
is precisely the input that cannot separate them - a set of assertions an
incorrect implementation satisfies entirely, which is the rule the test existed
to enforce.

**And which reader is right does not follow from Go.** It was measured on a
fresh container, 2026-09-18, four inputs on one client:

```
body RelayState   query RelayState   client_data's st
from-the-form     from-the-query     "from-the-form"
from-the-form     -                  "from-the-form"
-                 from-the-query     **no st key at all**
-                 -                  no st key
```

**The HTTP-POST binding reads its RelayState from the body alone and ignores the
query.** The third row is the whole of the evidence, and it is now the third
subtest. M16 and R2 are both killed by it, and the two subtests that were there
before pass under R2 - which is what made the old version look sufficient.

**The same question one parameter along was unmeasured too**, and it is a bigger
divergence. `readSAMLRequest` has always used `PostFormValue` for the POST
binding's `SAMLRequest`, correctly, but nothing said so:

```
POST /protocol/saml ?SAMLRequest=<base64 of the XML>   400, 3572, Invalid Request
POST /protocol/saml ?SAMLRequest=<deflated, base64>    400, 3572, Invalid Request
```

3572 is the ladder's **floor** - the page a request with no parameters at all
gets - so the POST binding reads nothing from the query in either spelling. A
merged read there answers the login page's **302** where Keycloak refuses, which
is a divergence at the top of the ladder rather than the bottom.
`TestSAMLPostBindingReadsItsMessageFromTheFormToo` holds it and kills that
mutation (R3), which nothing in the tree could see before.

**M20 - nothing in the catalogue restarts a SAML login.** Dropping the tab's two
SAML fields from the `restartRecord` survived the whole tree. Every golden in
this chapter is a **first** request, so `writeRestartRedirect` is never reached
with a SAML record, and the rebuilt tab silently became an OIDC one whose
client_data says `"rt":"code"` for a login that never asked for a code.

`TestSAMLLoginSurvivesARestart` walks it: the login page's `KC_RESTART` cookie
is presented back with no `AUTH_SESSION_ID`, which is the branch
`writeUnusableSession` takes, and the restart 302's own client_data is read out
of the header. M20 is now killed by it.

The two share a shape worth keeping: **both are paths the catalogue cannot
reach**, one because a mask covers the evidence and one because no case ever
gets there. Neither is a coverage hole a golden could close.

And R2 adds a third: **a test written to close a blind spot can inherit the
blind spot's shape.** The pass found M16 and the fix for M16 was itself one
input short, and only a second mutation aimed at the fix found that. The general
form is worth the sentence: when a test is written *because* a mutation
survived, mutate the thing the test now claims to cover, not only the thing that
survived.

---

## 6. Containers

Docker through colima, `DOCKER_HOST=unix:///Users/shorrty/.colima/default/docker.sock`.

```
kc-saml-f227      one, fresh, port 18091     every measurement in section 2
make record       three runs                 sections 4.1, 4.3
```

`kc-saml-f227` was started fresh from the image, had the three probe clients and
the `nopost` client created on it by the probes themselves, and was not reused
between sections - the whole of §2 is one container, one database, which is what
lets the eight-cell `rm` grid and the eight-value attribute sweep be compared
with each other.

Each `make record` run is **many** fresh containers rather than one, and it is
worth stating exactly: the recorder starts one shared container per
`Configuration` - two, the default and `StartDevHealth` - plus one throwaway per
`PristineRealm` case, of which the catalogue declares forty. Every one of them
is created by `testcontainers.GenericContainer` and terminated on cleanup, so
none is reused across runs and none carries state from a previous one. Three
runs.

The recorder's shared default container is the one §3.5 is about: it is shared
*within* a run, in catalogue order, which is exactly why `master` on it has
fifteen identity providers.

---

## 7. Parity

Measured with `cmd/parity` **built** rather than `go run`, for the reason
AGENTS.md gives - `go run` collapses exit 2 down to 1 and would make a real
parity decrease indistinguishable from a report it could not read.

```
Parity: 614 -> 618 of 684 (+4)

chapter                         before  after  delta
oidc/authorization                  29     30     +1
saml/endpoint                       17     19     +2
saml/idp-initiated                   5      6     +1
```

The chapter table:

```
chapter                              served  recorded  documented  source
saml/descriptor                           3         1           4  catalogue
saml/endpoint                            19         2          21  catalogue
saml/idp-initiated                        6         0           6  catalogue
saml/artifact-resolution                  0         1           2  catalogue
oidc/authorization                       30         0          30  catalogue

total: 618 of 684 enumerated behaviours served; 0 chapters not enumerated
```

The arithmetic: **one promotion** from `Pending` to `Implemented`
(`saml/endpoint/login-page`), which moves the numerator alone, and **three new
served cases**, which move both. 1 + 3 = 4 on the numerator, 3 on the
denominator.

`saml/idp-initiated` is 6 of 6. `saml/endpoint` is 19 of 21, and the two left
are the LogoutRequest 500s - `Recorded` with their measurement, unchanged, and
not this cut's.

**A thing this cut adds that the meter does not count.** Three of the twenty-one
mutations - M11, M12 and M18 - are invisible to every golden in the tree, and a
fourth, M19, is invisible to any golden that could ever exist. The meter reads
618 either way. The four package tests that hold them are not parity and are the
reason the number means anything.

---

## 8. Entries for AGENTS.md

### The one to fold first, because it is about how a reason goes stale

> **A `Pending` case's stated reason is a claim like any other, and a plausible
> one stops being checked.** `saml/endpoint/login-page` said it could not be a
> golden because the page carries a per-request `tab_id` and a `session_code`.
> That was true, it was the right shape of reason, and it was **not the
> blocker**: `Case.VolatileHTMLQuery` and `Case.VolatileHTMLCall` have reached
> both since 2026-09-03, a fortnight before the sentence was last rewritten. The
> actual blocker was that `internal/httpx` served a hand-rolled placeholder for
> the login form on **both** protocols, so
> `grep -rl kc-form-login testdata/golden/` returned nothing and there was
> nothing true to compare a mask against. Eleven days and two cuts went past it
> because the reason named a real obstacle that had already been removed. **When
> a `Pending` reason names a mechanism, check the mechanism exists and does not
> already cover the case** - the cheap version of that check is the grep the
> reason implies, and it takes one command.

### A value volatile on Keycloak and stable on Gloak has to be captured

> **A markup mask requires the value to move between two draws of Gloak, so a
> value that is volatile on Keycloak and stable here cannot be masked at all.**
> `TestNoHTMLMaskVariesNothing` runs a case twice against the in-process handler
> and fails any mask whose covered bytes are equal - the login form's
> `execution` is minted with Keycloak's database and derived from the realm id in
> Gloak, so it churns every recording and never moves in a draw. Masking it lands
> in `htmlMasksLeftInPlace`, whose own message says the answer for a value
> belonging to the installation is an unconditional pass beside
> `ReplaceThemeResource` - and there can be no unconditional pass for a bare
> UUID, because UUIDs are contract in a hundred other goldens. **So it is a
> fixture capture**, which is also strictly stronger: a mask asserts a value is
> there, a capture asserts it came from somewhere named, and pointing the capture
> at the wrong row of the flow-executions listing fails all three page goldens
> although the UUID it yields is real and well formed.

### A new bullet, for the SAML endpoint's eighth rung

> **`/realms/{realm}/protocol/saml`'s two bindings diverge at the top of the
> ladder and nowhere else.** All seven rejections answer the identical sentence
> over either binding. The eighth answers **200 with the login page** over
> HTTP-Redirect and a **302 into `/login-actions/authenticate`** over HTTP-POST -
> empty body, **no `Content-Type` at all**, `Cache-Control: no-cache`, and the
> Location carrying `client_id`, `tab_id` and `client_data` in that order with no
> `session_code`. **The "none of the five security headers" exception is the
> whole route rather than its error template**: it holds on that 200 with its
> 6931-byte body and on that 302 with no body, which is more than the six 400
> pages could say. The IdP-initiated route one path segment down answers the
> **same login page** with all five and a Content-Security-Policy, which is the
> same split the two routes' 400 pages already have.

### A new bullet, for `client_data`

> **`client_data`'s `rt` means two different things and is sometimes absent.**
> The login form's `client_data` is base64url of `{ru, rt, rm, st}` in that key
> order, and there are three shapes: `/auth` writes
> `{"ru":<redirect_uri>,"rt":"code","st":<state>}`, `/protocol/saml` writes
> `{"ru":<ACS>,"rt":<the AuthnRequest's ID>,"rm":"post","st":<RelayState>}`, and
> `/protocol/saml/clients/{name}` writes `{"ru":<ACS>,"rm":"post"}` with **no
> `rt` at all**, because there is no request to have an id. An implementation
> reusing one encoder emits `"rt":""` on that third row. **An empty `RelayState`
> counts as absent** - `RelayState=` renders no `st` key - where `/auth`'s
> `state=` renders `"st":""`. That is the third time these two endpoints have
> disagreed about emptiness in one parameter, after `client_id=` and `state=`.

### A new bullet, for the response binding

> **`client_data`'s `rm` on a SAML tab is `post` or `get`, and `HTTP-Artifact`
> falls back to `get`.** It is `post` when `saml.force.post.binding` is the exact
> string `"true"` **or** the `AuthnRequest` names
> `ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`, and `get`
> otherwise. Measured as a 2x4 on one container: `HTTP-Redirect` and an absent
> attribute are `get` as expected, and so is **`HTTP-Artifact`**, whose URI is
> correct and whose binding the descriptor advertises - the answer is the default
> rather than a third value or a refusal. **`saml.force.post.binding` is compared
> to the exact string `"true"`, case-sensitively**, exactly as
> `saml.client.signature` is: `"TRUE"`, `"True"`, `" true"`, `"0"`, `"no"`, `""`
> and absent are all off. That is the second attribute measured with that rule,
> so it is `samlAttributeIsTrue` rather than the literal twice - and the mutation
> that turns it into `strconv.ParseBool` fails two tests written for two
> different attributes, which is what a shared comparison buys.

### For the "things that look like bugs" list

> **The login form page renders one `<a>` per identity provider in the realm**,
> so its bytes depend on the realm's identity providers rather than on the
> request. That is not a bug and it is a trap for the recorder: `master` on the
> shared container accumulates every identity provider the catalogue's fixtures
> create, so the first recording of `saml/endpoint/login-page` came back with
> **sixteen** social-login buttons in it and seventeen `tab_id` occurrences
> instead of two. Every case whose golden is a login form page is recorded
> against a realm of its own for that reason - see `loginPageRealm`. Four
> branches of the page go unmeasured as a result and are named rather than
> hidden: the social-provider section, the registration link, remember-me and
> forgot-password. F271.

### For the build section, extending the theme-page bullet

> **The login theme has five body templates in this repository and the fifth is
> `login.ftl`.** It arrived on 2026-09-18 and it is the first one any protocol's
> **success** path reaches. The OIDC authorization endpoint's login page and the
> SAML endpoint's are **byte-identical** apart from the `client_id`, `tab_id`,
> `client_data`, `session_code` and authentication session hash - one template,
> two protocols - which is why building it was not SAML's work and why there is a
> case per protocol: two goldens make "the two agree" a diff rather than a claim.
> The page carries **eight** `/resources/` segments where the four error-shaped
> templates carry seven, because it is rendered from inside an authentication
> flow and therefore has a session to poll. **The page a credential failure
> re-serves is a different page** - 8000 bytes against 6861, with `pf-m-error` on
> both form controls, a status icon span, a helper-text block and a
> `history.replaceState` in the head - and it is deliberately still a
> placeholder. F269.

### For the mutation-discipline paragraph

> **A masked header is a blind spot with a shape, and the shape is "everything
> inside the value".** `saml/endpoint/post-binding-login-redirect` masks its
> `Location` whole, because the header carries a per-request `tab_id` and no
> header mask in this harness reaches inside a query parameter - `MaskURLTail`
> covers a final path segment. A mutation changing which parameter the handler
> read the RelayState from therefore survived the entire tree: the status, the
> `Cache-Control` and all eight absent headers were unchanged and the whole of
> what moved was inside the mask. Before accepting a whole-header mask, ask what
> a package test has to assert in its place, and write that test in the same
> cut - `TestSAMLPostBindingReadsItsRelayStateFromTheForm` is what that looks
> like, and it sends **both** spellings with different values so that a merged
> read fails too.

> **A capture can be named wrong and it still dies, which is the difference
> between a capture and a mask.** Pointing the login-page fixture's `execution`
> capture at index 12 rather than 8 yields a real, well-formed UUID off a real
> row, `ReplaceCaptured` rewrites it on both sides, and nothing about the
> golden's shape changes - and all three page goldens fail anyway, because the
> two sides then disagree about which id the page carried. A mask asserts a value
> is there; a capture asserts it came from somewhere named.

> **Mutate the test a mutation asked for, not only the code it survived in.**
> The pass found a handler reading the HTTP-POST binding's `RelayState` from the
> query; the test written to kill it sent the parameter in **both** the query and
> the body with different values, and the sentence beside it claimed that also
> covered a merged `r.FormValue` read. It did not. `ParseForm` fills `r.Form`
> with the body's values first and appends the query's, so `FormValue` and
> `PostFormValue` agree on every input where the body carries the parameter and
> differ on exactly one - a POST whose **body omits it and whose query carries
> one**. The fix was one input short, and the input it was short of is the only
> one that discriminates: "a set of assertions an incorrect implementation
> satisfies entirely" arriving on the test written to enforce that rule. It was
> found by review mutating the fix rather than by the pass, which is the general
> lesson: a test born from a survivor inherits the survivor's blind spot unless
> somebody aims a mutation at the test's own claim.

### A correction to the SAML client bullet, and a new one beside it

> `POST /admin/realms/{realm}/clients` with `{"protocol":"saml"}` generates
> fourteen attributes on Keycloak and **two on Gloak** - `realm_client` and
> `client.secret.creation.time`. The twelve SAML ones, `saml.client.signature`
> and `saml.force.post.binding` among them, are not generated at all, so a client
> created identically on the two servers is configured on one and not on the
> other. That is F272, and it is why the login-page fixture spells
> `saml.force.post.binding` out: the second recording of two of its goldens
> failed on `"rm":"post"` against `"rm":"get"` and the difference was the
> fixture's client, not the rule the case is about.

---

## 9. Follow-ups, numbered from F268

### F268 - the ninth rung: the assertion, and exclusive canonicalisation

This is what is left of F227 and it is the whole of it. Gloak can now read a
SAML request, refuse it correctly on seven rungs, ask for credentials on the
eighth, and **cannot answer the ninth**: Keycloak's answer is a signed
`samlp:Response` carrying an assertion, posted back to the assertion consumer
URL, and that is an enveloped XML signature over a canonicalised document.

`completeSAMLLogin` answers the dispatcher's `HTTP 404 Not Found` there rather
than minting an authorization code, which is what `completeLogin` beside it
would otherwise do - see §3.3.

The gap is the same one F229 records on the way **in**, and the rule at the top
of AGENTS.md applies the way the first cut applied it to `encoding/xml`: **prove
with bytes** that the standard library cannot do exclusive c14n, and make the
refutation a test, in the shape of `TestEncodingXMLCannotEmitTheDescriptor`.
Nothing in this cut reached that question, so nothing in this cut has an opinion
about it.

What has to be measured before a line of it is written, because none of it is:

- what the `samlp:Response` actually contains - the `Conditions`, the
  `AudienceRestriction`, the `AuthnStatement`, the `NameID` format, the
  `SessionIndex`, and which of them move per request;
- **what `rm` actually does with it.** §2.4 measured which value the session
  carries and nothing measured what `post` and `get` then produce - the POST one
  is presumably an auto-submitting form and the other a redirect, and
  "presumably" is the word this project does not accept. That is the second half
  of F228 and it stays open.
- whether the assertion is signed when `saml.server.signature` is off, which is
  an attribute every created client carries and nothing here sent a request to.

### F269 - the login page a credential failure re-serves

Measured 2026-09-18 and deliberately not built: 8000 bytes against the first
render's 6861, adding `pf-m-error` to both form controls, a
`pf-v5-c-form-control__utilities` icon span, a `pf-v5-c-helper-text__item` block
carrying the sentence, `aria-invalid="true"`, the username echoed, and a
`history.replaceState` `<SCRIPT>` in the head the first render has no trace of.

`WriteThemeLoginPage` keeps the placeholder for that one branch, which is F109's
arrangement at `writeLoginActionErrorPage`. It closes when somebody records it,
and the reason it is worth doing is that **nothing in the catalogue compares it
today** - the credential POST's golden is a 302 - so closing it means a case as
well as markup. The case is the interesting half: a fixture that reaches the
page needs a wrong credential, and the page then carries the same three
per-request values this cut's three goldens already mask.

### F270 - a SAML tab's route through the required actions and the consent

`beginSAMLLogin` opens an ordinary authentication session, so a SAML login whose
user carries `UPDATE_PASSWORD`, or whose client is `consentRequired`, goes
through `/login-actions/required-action` and `/login-actions/consent` exactly as
an OIDC one does. `writeRequiredActionRedirect` builds its `client_data` from
the tab, so the SAML shape survives - which is measured on Gloak and **not
measured on Keycloak at all**.

Nothing here sent a SAML request for a user with a required action or a client
requiring consent. Both are one container away, both are reachable today, and
both are ahead of F268 in the sense that a flow that ends wrongly is worse than
one that ends nowhere.

### F271 - the login page's four unrendered branches

The page renders a social-provider section when the realm has identity
providers, a registration link when registration is on, a "remember me" checkbox
when it is enabled, and a "forgot password" link when password reset is. All
four are off on a realm created through `POST /admin/realms` and on a default
`master` alike, `internal/httpx` renders none of them, and the three login-page
goldens are recorded against a realm that has none of them on.

The first is the one with a consumer: `GET /realms/{realm}/broker/{alias}/login`
is the href each button points at, and the identity-provider chapter is
otherwise complete. The other three are realm flags nothing in this repository
sets.

What to measure first is the **order** the buttons come in and whether the list
is deduplicated, because that is the cell §3.5's first recording accidentally
showed and nobody read: sixteen buttons for fifteen providers.

### F272 - Gloak generates two client attributes where Keycloak generates fourteen

`POST /admin/realms/{realm}/clients` with `{"protocol":"saml"}` answers with
fourteen generated attributes on Keycloak - P11 §1.12 counted them - and Gloak's
`createClient` generates `realm_client` and, for a confidential client,
`client.secret.creation.time`. Nothing else.

**No golden sees it**, which is why it survived until a case needed one of the
twelve. The login-page fixture now spells `saml.force.post.binding` out, so the
gap is worked around rather than closed.

It is filed rather than fixed here because closing it moves every client golden
in the tree at once: the twelve include `saml.signing.certificate` and
`saml.signing.private.key`, which are **generated key material** and therefore a
new volatile value in every SAML client's create response. That is a cut of its
own and it should be taken with the certificate endpoints, not beside a login
page.

### F273 - every SAML client that reaches a login page has `saml.force.post.binding` true

**A corpus gap with a named cause**, which is the shape F234 and F256 already
have.

Three of this cut's twenty-one mutations are invisible to **every golden in the
tree**, and one reason covers all three: `samlResponseBinding` always answering
`post` (M11), `HTTP-Artifact` read as a POST binding (M12), and
`samlAttributeIsTrue` becoming `strconv.ParseBool` (M18). Each of them died only
in `internal/oidc`.

The cause is the corpus rather than the code. Every client in the catalogue that
walks as far as a login page carries `saml.force.post.binding: "true"` - the
value Keycloak generates and the value `loginPagesFixture` now spells out - and
every SAML attribute written anywhere in the fixtures is spelled `"true"` or
`"false"`. So no case can separate `"true".equals(value)` from a boolean parse,
no case can separate the measured grid from the constant `post`, and no case
sends a `ProtocolBinding` at all.

`TestSAMLResponseBindingIsTheMeasuredGrid` is what holds all three today, and a
package test is the right home for the eight-cell grid: a golden per cell would
be eight 6900-byte login pages differing in one key.

What would close the corpus half, in order of what it buys:

- **a case on a client with `saml.force.post.binding: "false"`**, which is the
  one cell that changes an observable byte in `client_data` and is one fixture
  client away. Its login page is 6875 bytes against 6877, and the diff is
  `"rm":"get"`;
- **a case whose `AuthnRequest` names `ProtocolBinding=HTTP-POST`** against that
  same client, which is the cell where the *request* overrides the client and is
  the only reason `samlMessage.ProtocolBinding` exists;
- `HTTP-Artifact` against it, which is the cell a reader gets wrong.

Three cases, one new fixture client, two new literals. It was not done here
because this cut already added four goldens and a realm, and because the grid is
measured and held - but the entry should say plainly that **the meter reads 618
whether those three mutations are alive or dead**, and that is what makes it
worth filing rather than shrugging at.

### F228 - half closed

§2.4 is the measurement F228 asked for: `saml.force.post.binding`'s comparison
and its effect on the session, as a 2x4 plus an eight-value attribute sweep. It
was filed because "the attribute is on by default, so whatever it does is what a
default client gets", and that is now measured and served.

**The other half is untouched and belongs to F268**: what the response binding
does once it has been chosen. The descriptor advertises four
`SingleSignOnService` bindings and nothing here sent a request that reaches the
point where one is used, because that point is past the ninth rung.

### F229 - unchanged, and its measured input is still missing

The HTTP-POST binding's XML signature is still unverified and still not refused.
Nothing in this cut signed a POST-binding `AuthnRequest`, so what Keycloak
answers a correctly signed one is still inference rather than measurement -
which is the sentence F229 already carries, re-checked rather than restated.

This cut does move one thing next to it: the POST binding now has a **measured
success path**, so a signed POST from a signature-requiring client has somewhere
to arrive if the verification ever exists. Before this it would have had nowhere
to go but the 404 either way.

### F113 - narrowed, and the narrowing is the finding

F113 says a page carrying a per-request value cannot be `Recorded`. That is
still true and it is **not** what kept `saml/endpoint/login-page` `Pending`.

The page's three per-request values - `tab_id`, `session_code` and the
`checkAuthSession` argument - are reached by `Case.VolatileHTMLQuery` and
`Case.VolatileHTMLCall`, both of which have existed since 2026-09-03. The case's
own `Reason` named them as the blocker for eleven days and they were not one.
What was missing was a login form markup to compare against.

The entry should gain the distinction rather than a closure: **a per-request
value bars a golden only when no frame reaches it**, and three frames now do.
The values that still bar one are the ones inside a JSON string (F38's
neighbourhood), the ones inside a `Set-Cookie` that nothing can capture out of,
and an XML attribute, for which no frame is built because none has a consumer.

### F230 - a second instance, and it is not the recorder's instability

F230 is about a golden that moved between recorder runs and a shared
`internalId` space. §3.5 is a different mechanism with the same symptom: a
golden whose **content** is decided by which other fixtures ran on the shared
container, because the login page renders one element per identity provider and
the identity-provider chapter creates fifteen of them in `master`.

The cure here was a realm of its own, which is cheap and complete. The entry is
worth extending with the general form, because it is the question to ask of any
new golden: **does this response enumerate anything the realm accumulates?** A
listing does obviously; a login page does not obviously, and that is why it
took a recording to find.

### F175 - still refuted, and this cut needed nothing it offered

P11 closed F175 with the measurement that an `AuthnRequest` needs no
`Destination`. This cut is the first to walk past the `Destination` rung to the
top of the ladder, which is where P11 said the argument for a run-time signer
would have to be made if it were ever made - and it is still not needed. The
request that reaches the eighth rung is unsigned, so the `Destination` is never
compared and the literal works on whatever port testcontainers maps.

A signed message that walks past the `Destination` rung remains unsent and
remains without a consumer.
