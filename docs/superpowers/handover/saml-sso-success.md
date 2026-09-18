# F227, first half: the eighth rung, and the page nobody had noticed was missing

Branch `feat/saml-sso-success`, off `main` at `b1cc071`. Everything measured
below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on 2026-09-18.

P11's second cut served the SSO endpoint's whole seven-rung rejection ladder and
stopped one below the success path, because "serving the eighth rung needs an
authentication session carrying the SAML request id and a signed assertion
builder". **That sentence contains the split, and it has three parts rather than
two.** The brief guessed two; the third is what actually kept the case `Pending`
for eleven days, and nobody had filed it.

Both routes' success paths are served now. `saml/endpoint` is 20 of 22 and
`saml/idp-initiated` is 6 of 6.

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

### 4.3 Run 2

<!-- RUN2 -->

---

## 5. The mutation pass

<!-- MUTATIONS -->

---

## 6. Containers

<!-- CONTAINERS -->

---

## 7. Parity

<!-- PARITY -->

---

## 8. Entries for AGENTS.md

<!-- AGENTS -->

---

## 9. Follow-ups, numbered from F268

<!-- FOLLOWUPS -->
