# P3's second cut: serving the browser authorization endpoint's validation half

Date: 2026-08-29
Spec: `docs/superpowers/specs/2026-08-29-p3-browser-code-flow-design.md`
Follows: `docs/superpowers/plans/2026-08-29-p3-recorder-login.md`

The first cut built the recorder's browser machinery and parked eleven
`oidc/authorization` cases as `Recorded` - measured, not served. It moved parity
by zero on purpose. This cut is where the number moves: `GET`/`POST /auth`
becomes a route, and every rejection that never reaches a login form is served
byte-exactly.

It stops short of the success path, and section 8 says why that is a whole
deliverable rather than half of one.

## 1. The client question, decided before any code

The design document says nine of the eleven cases were written against
`security-admin-console`, which pins `pkce.code.challenge.method=S256` and
registers the host-relative `/admin/master/console/*`. **That is already fixed
and nothing here re-opens it.** The first cut's Task 6 moved every browser case
onto a client the fixture registers itself - `browserClientSteps` in
`internal/conformance/fixture.go`, with `browserRedirectURI` as an absolute
`http://localhost:9999/callback` that never has to resolve.

What that decision changes is *which* cases are reachable in this cut, and the
answer is read off the fixture each case names:

| Case | Fixture | Reaches a login form? | This cut |
|---|---|---|---|
| `missing-response-type` | `browser-client` | no | **serve** |
| `unsupported-scope` | `browser-client` | no | **serve** |
| `prompt-none-no-session` | `browser-client` | no | **serve** |
| `code-flow-redirect` | `browser-login` | yes, and posts the form | leave `Recorded` |
| `pkce-s256` | `browser-login-s256` | yes | leave `Recorded` |
| `pkce-plain` | `browser-login-plain` | yes | leave `Recorded` |
| `response-mode-fragment` | `browser-login-frag` | yes | leave `Recorded` |
| `invalid-redirect-uri` | `bootstrap` | 400 theme page | leave `Pending`, P13 |
| `unknown-client-id` | `bootstrap` | 400 theme page | leave `Pending`, P13 |
| `response-mode-form-post` | none | 200 HTML form | leave `Pending` |
| `implicit-flow` | none | out of P3's scope | leave `Pending` |

Three cases are the whole of what the existing catalogue can gain. Task 6 adds
five more from what was measured for this cut, because the order the checks run
in is now known and none of it was pinned by anything.

## 2. What was measured, 2026-08-29, container `kc-p3b` on 8085

Seven probes, each printing the argv it then executed. The full transcript goes
into `docs/superpowers/handover/p3-serve-auth.md` for folding into the observed
document; the parts the implementation is built on are here.

### 2.1 The rejection order, pinned by driving two faults at once

The design's section 4 gives the two families and says the redirect URI decides
which. It does not say what happens inside the redirect family when a request is
wrong in two ways at once. Twenty-nine paired requests say this, and every step
is a measurement rather than an inference from its neighbour:

```
1  realm                     404 {"error":"Realm does not exist"}   (JSON, not a page)
2  client                    400 theme page   - absent, empty, unknown, disabled
2b bearer-only client        403 theme page   - before the redirect URI, not after
3  redirect_uri              400 theme page
--- everything below is a 302 to the redirect URI ---
4  response_type absent      invalid_request  "Missing parameter: response_type"
4b response_type unusable    unsupported_response_type, and no error_description key
5  response_mode invalid     invalid_request  "Invalid parameter: response_mode"
6  flow disabled             unauthorized_client, "... Standard flow is disabled for the client."
                                               "... Implicit flow is disabled for the client."
7  a repeated parameter      invalid_request  "duplicated parameter"   (lower case)
8  scope                     invalid_scope    "Invalid scopes: <the raw scope string>"
9  code_challenge absent     invalid_request  "Missing parameter: code_challenge"
9b code_challenge_method bad invalid_request  "Invalid parameter: code_challenge_method"
9c code_challenge malformed  invalid_request  "Invalid parameter: code_challenge"
10 prompt=none, no session   login_required
```

Each adjacent pair was driven together and the earlier one won: no
`response_type` beats a bad scope, a bad scope beats a missing `code_challenge`,
a missing `code_challenge` beats `prompt=none`, and so on. **Two of the steps
would have been placed wrongly by any reasonable guess:**

- **7 sits between the flow check and the scope check.** A duplicated parameter
  on a client with the standard flow disabled answers "Standard flow is
  disabled", and a duplicated parameter with an invalid scope answers
  "duplicated parameter". So it is neither first (the obvious place for a
  request-shape check) nor last.
- **9 is not one check but three, and the absent-challenge one runs first.**
  `code_challenge_method=bogus` with **no** challenge answers "Missing
  parameter: code_challenge", not "Invalid parameter: code_challenge_method".
  Only when a challenge is present does the method's own validity get looked at.

### 2.2 Three things the observed document has slightly wrong

- **"`client_id=admin-cli`, standard flow off → 400"** is not a standard-flow
  measurement. `admin-cli` has no registered redirect URI, so it fails step 3.
  A client with the standard flow off **and a registered redirect URI** answers
  a **302** carrying `unauthorized_client`. The 400 row measured the wrong
  thing.
- **"`POST /auth` ... serves the login page, 200, exactly as `GET` does"** is
  true only when the parameters are in the request **body**. `POST` with the
  parameters on the query string and no body answers 400: it reads the form,
  not the query.
- **A wrong method on `/auth` is a 405**, `application/json`, for `PUT`,
  `DELETE` and `PATCH`. `OPTIONS` answers 200 with
  `Allow: HEAD, POST, GET, OPTIONS`, and `HEAD` answers 200. That is the third
  data point for follow-up F31 and nothing here acts on it - see section 7.

### 2.3 The redirect URI match is a literal string comparison

Against a client registering exactly `http://localhost:9999/callback`, every one
of these is a 400: a trailing slash, an added query string, an added fragment,
an uppercased scheme or host, an uppercased path, a `..` segment, a
percent-encoded path character, a sub-path, `127.0.0.1` for `localhost`, and
`https` for `http`. Nothing is normalised. Against a client registering
`http://localhost:9998/*`, the `*` matches the empty string and everything else:
`http://localhost:9998`, `.../`, `.../cb`, `.../a/b`, `.../cb?x=1` all pass, and
another port does not.

So: **equality, or - when the pattern ends in `*` - a prefix match on everything
before the `*`.** That is the whole rule and it is measured rather than taken
from `RedirectUtils`.

### 2.4 The valid scope set is the client's own, not the realm's

`scope=X` is accepted when `X` is `openid` or one of the **client's**
`defaultClientScopes` ∪ `optionalClientScopes`. Measured on a client the fixture
created: the eleven names in its two lists all pass, and `service_account`,
`role_list`, `AuthnContextClassRef` and `saml_organization` - all client scopes
*of the realm*, none of them assigned to that client - all fail. An absent
`scope` passes; an empty `scope=` fails with `Invalid scopes: ` and a trailing
space. The description echoes the **raw** parameter, so `openid  nosuchscope`
with two spaces comes back with two spaces.

### 2.5 The two header sets, confirmed on every rejection

```
302 error redirect  Cache-Control: no-store, must-revalidate, max-age=0
                    Referrer-Policy, Strict-Transport-Security,
                    X-Content-Type-Options, X-Robots-Tag, content-length: 0
                    NO Content-Type, NO X-Frame-Options, NO Content-Security-Policy
400/403 page        Content-Language: en, Content-Security-Policy,
                    Content-Type: text/html;charset=utf-8,
                    all five security headers
                    NO Cache-Control at all
```

Swept over seven different 302 rejections and three page responses, so the
missing `X-Frame-Options` really is the endpoint's and not one error's.

## 3. Files

| File | Why |
|---|---|
| `internal/oidc/authorize.go` | new: the endpoint |
| `internal/oidc/authorize_test.go` | new: the order, the matcher, the header sets |
| `internal/oidc/router.go` | two registrations, and the header exception |
| `internal/httpx/errors.go` | the redirect family's header set |
| `internal/conformance/catalog_oidc.go` | the served cases move here |
| `internal/conformance/catalog_oidc_pending.go` | the three leave, the new ones arrive |
| `internal/conformance/testdata/golden/oidc/authorization/` | five new goldens |
| `docs/superpowers/handover/p3-serve-auth.md` | everything owed to the four files this cut may not touch |

`internal/conformance/fixture.go` needs **no change**: `browser-client` already
registers the client every new case wants.

## 4. Task 1: the redirect family's response writer

`internal/httpx` owns every response body, and this family has none - it is a
`Location` and five headers. It still belongs there, because the thing that is
easy to get wrong is the header set and that is what `httpx` exists to keep in
one place.

```go
// WriteAuthorizationRedirect writes GET /auth's 302 back to a client's own
// registered redirect URI.
func WriteAuthorizationRedirect(w http.ResponseWriter, location string)
```

It sets the five security headers, **deletes `X-Frame-Options`**, sets
`Cache-Control: no-store, must-revalidate, max-age=0`, sets `Location`, and
writes a 302 with an empty body. It never sets `Content-Security-Policy`; the
router does not set it either, so nothing has to be deleted.

`SetUserinfoSecurityHeaders` is the existing precedent for deleting one of the
five, and its comment says why deleting beats setting a smaller set: the router
sets all five before the mux runs.

Verify: a test asserting the exact header set present and the exact set absent.

Mutation: make it set `X-Frame-Options` like everything else. The absent-header
test must fail.

Commit: `feat(httpx): the authorization redirect's header set`

## 5. Task 2: `authorize`, the two families and the measured order

One file, one exported route handler, and a validation sequence written in the
order of section 2.1 with a comment per step naming what it beats.

Three decisions inside it are worth writing down before the code exists.

**The redirect URI matcher is its own function and takes the pattern list.**
`matchRedirectURI(patterns []string, uri string) bool`: equality, or a prefix
match when the pattern ends in `*`. Section 2.3 measured that nothing is
normalised, so the implementation must resist the urge to parse either side as
a URL - parsing is how a trailing slash or a percent-encoded character starts
comparing equal when Keycloak says it does not.

**The scope check reads the client's own two lists.** `openid`, plus
`DefaultClientScopes` ∪ `OptionalClientScopes`, which `model.Client` already
carries and both store drivers already persist. It is *not* a constant list
like `token.go`'s `defaultClientScopes`, because section 2.4 measured that the
answer follows the client.

There is a known consequence and it is recorded rather than papered over:
`internal/admin`'s client create does not default the two lists the way Keycloak
does, so a client created through Gloak's admin API carries empty lists and will
refuse `scope=profile` where Keycloak accepts it. That is P5's surface -
`internal/admin` is another agent's file this cut may not touch - and it goes in
the handover as a follow-up. It does not affect any case: every browser case
sends `openid` or a name that is invalid on both sides.

**A repeated parameter is detected on the parsed values, not the raw query.**
`url.Values` already groups them; any key with more than one value trips step 7.
Measured: it applies to every key including ones Keycloak does not otherwise
read, and a repeated `client_id` never gets that far because step 2 cannot
resolve it.

Verify: one test per step of section 2.1, each sending a request that is wrong
in **two** ways and asserting the earlier one wins - which is what the
measurement did, and a test that sends one fault at a time cannot tell an order
from a set.

Mutation, one per claim and a different one each time:
- swap steps 4 and 5 - the response-mode-beaten-by-response-type test fails
- swap 7 and 8 - the duplicate-beats-scope test fails
- make step 9 check the method before the challenge's presence - the
  bogus-method-no-challenge test fails
- make `matchRedirectURI` compare parsed URLs - the trailing-slash test fails
- make the scope check read a realm-wide list - the `service_account` test fails

Commit: `feat(oidc): the authorization endpoint's validation half`

## 6. Task 3: the routes, and what a valid request gets

```go
mux.HandleFunc("GET /realms/{realm}/protocol/openid-connect/auth", h.authorize)
mux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/auth", h.authorize)
```

`POST` reads its parameters from the form body and **not** from the query
(section 2.2). `r.ParseForm` merges both, so the handler reads `r.PostForm` on a
`POST` and `r.URL.Query()` on a `GET` rather than using `r.Form`.

**A request that passes every check gets the page family's 400.** This is the
cut's one deliberate divergence and it is a choice between two bad options, so
it is argued rather than asserted:

- Gloak has no login page. P13 owns the theme, and the design's section 10
  already accepts "Gloak's login page will not be Keycloak's".
- Serving a login form whose `POST` target does not exist would be the
  half-served success path this cut is told not to build, and it would make
  `browser-login`'s fixture *succeed* at the authorize step and fail one request
  later with a message about HTML.
- Inventing a 501 or a JSON error would put a shape on the wire that no
  measurement supports.

So the valid branch joins the 400 page family, whose envelope is measured and
which Gloak has to serve anyway for the two `Pending` theme cases. The body of
every page response is Gloak's own placeholder until P13; no case compares it,
both theme cases stay `Pending`, and the `browser-login*` fixtures keep failing
at their `ExpectStatus: 200` step, which is exactly the state
`TestConformance` expects of a `Recorded` case.

It is a divergence a person driving Gloak by hand would notice, so it is named
in the handover as a follow-up and in the handler's own doc comment, not left
for someone to find.

Verify: a router test that a valid request answers the page family, and that
`GET` and `POST` disagree about where the parameters come from.

Mutation: make `POST` read the query. The POST test fails.

Commit: `feat(oidc): route the authorization endpoint`

## 7. Task 4: what is deliberately not changed

`WithKeycloakFallbacks` answers 404 for a known path hit with the wrong method.
Keycloak answers `/auth` with **405**. Registering the route therefore creates a
third counter-example to the "a wrong method is not always 404" rule, alongside
the role-mapping paths and `PATCH /admin/realms/{realm}`.

**Nothing is changed on the strength of it.** F31 exists for exactly this and
AGENTS.md says so: "See F31 before adding a 405 or defending the 404." The
counter-example is recorded in the handover and the rule stays as it is, because
three data points that disagree still do not say what the rule *is*.

## 8. Task 5: the catalogue

Three cases move from `catalog_oidc_pending.go` to `catalog_oidc.go` as
`Implemented`, losing their `Reason` - `catalog_test.go` requires that, and it
is a separate rule from the one that fails a matching `Recorded` case.

Five cases are added, all `browser-client`, all recorded before being marked
`Implemented`:

| New case | What it pins |
|---|---|
| `unsupported-response-type` | the second `response_type` shape: no `error_description` key at all |
| `invalid-response-mode` | `response_mode` has its own validity check, between `response_type` and the flow check |
| `duplicated-parameter` | a whole error family nobody had measured |
| `pkce-missing-challenge` | the first of the PKCE trio, and that scope precedes it |
| `pkce-invalid-challenge-method` | the second, reachable only with a challenge present |

Each asserts `Location` and `Cache-Control` and pins `X-Frame-Options` and
`Content-Security-Policy` **absent** - the same shape the three existing served
cases carry. None is masked: after `ReplaceIssuer` an error redirect holds
nothing per-request, so the error code, the description and the query key order
are all compared byte for byte.

Recorded with `-run 'TestRecordGoldens/oidc/authorization'` rather than a full
`make record`, so no golden outside this chapter can move. Read the diff.

Commit: `test(conformance): the authorization endpoint's rejections`

## 9. Task 6: the handover

`docs/superpowers/handover/p3-serve-auth.md`, four headed sections: the
measurements for the observed document, the entries for AGENTS.md's "Things that
look like bugs and are not", the follow-ups, and the parity number before and
after. Four files this cut may not touch are the reason it exists.

Commit: `docs(p3): hand over the authorization endpoint's measurements`

## 10. What this plan deliberately does not do

**No login page, no session, no authorization code.** The success path needs a
form, a cookie, an auth session, a code store and a code exchange, and half of
those are visible to a client. Serving three of the five is worse than serving
none.

**No `form_post` and no fragment response mode on the success path.** The error
redirect honours `response_mode=fragment` - measured - and that is served,
because it is a rejection. `form_post` answers 200 with an HTML form even for an
error, which is a body Gloak cannot yet produce; a `response_mode=form_post`
request that would be rejected therefore gets the page family, and that is
written down in the handler.

**No change to `internal/admin`'s client scope defaulting**, though section 5
measured that it diverges. It is another agent's file this week and P5's work
besides.

**No 405 for a wrong method on `/auth`.** Section 7.

**Parity: 129 → 137.** Eight cases served, five of them new, so the chapter
denominator moves from 11 to 16 and the total from 485 to 490. Stated here so
that a number that does not move is a failure rather than a surprise.
