# Handover: P3's second cut, serving `/auth`'s validation half

Date: 2026-08-29
Branch: `feat/p3-serve-auth`
Plan: `docs/superpowers/plans/2026-08-29-p3-serve-auth.md`

Four files were off limits to this cut because three other agents were working
in parallel: `AGENTS.md`, `README.md`, the parity roadmap, the observed document
and the follow-ups list. Everything this cut owes them is below, in four
sections, ready to be folded in.

Every value here was measured against `quay.io/keycloak/keycloak:26.7.1`, a
plain `docker run` on port 8085, on 2026-08-29. Nine probes, each printing the
argv it then executed.

---

## 1. Measurements to fold into the observed document

These go into the "The browser authorization code flow" section of
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md`. The first three
are **corrections** to what is already there.

### 1.1 Correction: "standard flow off" was measured on the wrong client

The section's table of the 400 page family has a row reading

```
| `client_id=admin-cli`, standard flow off | 3608 | |
```

That row does not measure the standard flow. `admin-cli` registers **no**
redirect URI at all, so it fails the redirect-URI check first and never reaches
the flow check. A client with `standardFlowEnabled: false` **and a registered
redirect URI** answers a **302**:

```
$ curl -s -D /dev/stderr -o /dev/null -X GET --no-location 'http://localhost:8085/realms/master/protocol/openid-connect/auth?response_type=code&client_id=p3b-noflow&redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcallback&scope=openid&state=xyz123'

HTTP/1.1 302
Location: http://localhost:9999/callback?error=unauthorized_client&error_description=Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Standard+flow+is+disabled+for+the+client.&state=xyz123&iss=...
```

The same client with `response_type=none` answers identically, and with a
**bad** redirect URI answers the 400 page - which is the row that was actually
being measured. Suggested replacement for the row: move it out of the page table
and into the redirect table, with the qualification that `admin-cli` reaches the
page only because it registers no redirect URI.

### 1.2 Correction: `POST /auth` reads the body, not the query

The section says `POST /auth` "serves the login page, 200,
`text/html;charset=utf-8`, exactly as `GET` does". That is true only when the
parameters are in the **request body**:

```
POST, parameters on the query string, no body        -> 400 (the page)
POST, parameters in an urlencoded body               -> 200 (the login page)
POST, parameters in the body, no response_type       -> 302 (the error redirect)
```

So `POST` is a real second entry point with a different parameter source, and an
implementation reading `r.Form` - which merges query and body - would accept the
first row and diverge.

### 1.3 A wrong method on `/auth` is a 405, and `OPTIONS` answers 200

```
GET      200 text/html;charset=utf-8
POST     400 text/html;charset=utf-8    (no body; see 1.2)
PUT      405 application/json
DELETE   405 application/json
PATCH    405 application/json
HEAD     200 text/html;charset=utf-8
OPTIONS  200, Allow: HEAD, POST, GET, OPTIONS
```

This is the **third** counter-example to "a wrong method on a known path returns
404". The role-mapping paths gave `PUT`/`PATCH` 405 and `POST`/`DELETE` 404;
`/admin/realms` gave `DELETE` 405, refuting "the verb decides"; and here
`DELETE` is 405 again while `POST` is a real route. Nothing was changed in Gloak
on the strength of it - see F31 and section 3 below.

### 1.4 The order the rejections run in, pinned by driving two faults at once

The section gives the two families and the design gives the rule that the
redirect URI decides which. Neither says what happens when a request is wrong in
two ways. Twenty-nine paired requests, each pair deciding one adjacency:

```
 1  realm                     404 {"error":"Realm does not exist"}   JSON, not a page
 2  client                    400 page   - absent, empty, unknown, disabled client_id
 2b bearer-only client        403 page   - and before the redirect URI, not after
 3  redirect_uri              400 page
 --- everything below is a 302 to the redirect URI ---
 4  response_type absent      invalid_request  "Missing parameter: response_type"
 4b response_type unusable    unsupported_response_type, and no error_description key
 5  response_mode invalid     invalid_request  "Invalid parameter: response_mode"
 6  flow disabled             unauthorized_client + "... Standard flow is disabled for the client."
                                                   "... Implicit flow is disabled for the client."
 7  a repeated parameter      invalid_request  "duplicated parameter"      (lower case)
 8  scope                     invalid_scope    "Invalid scopes: <the raw scope string>"
 9  code_challenge absent     invalid_request  "Missing parameter: code_challenge"
 9b method invalid            invalid_request  "Invalid parameter: code_challenge_method"
 9c challenge malformed       invalid_request  "Invalid parameter: code_challenge"
10  prompt=none, no session   login_required
```

The evidence, one row per adjacency:

```
no response_type + bad scope                   -> Missing parameter: response_type
response_type=foo + bad scope                  -> unsupported_response_type
response_type=foo + response_mode=bogus        -> unsupported_response_type
response_type=token + response_mode=bogus      -> Invalid parameter: response_mode
flow off + duplicated nonce                    -> Standard flow is disabled
duplicated nonce + bad scope                   -> duplicated parameter
bad scope + code_challenge_method=S256         -> Invalid scopes: ...
code_challenge_method=bogus, no challenge      -> Missing parameter: code_challenge
code_challenge_method=bogus, with a challenge  -> Invalid parameter: code_challenge_method
code_challenge_method=S256 + prompt=none       -> Missing parameter: code_challenge
```

**Two of these are where nobody would have put them.** Step 7 sits between the
flow check and the scope check, so a request-shape check is neither first nor
last. And step 9 is three checks whose *first* is the absent challenge, so a
bogus method with no challenge answers about the challenge.

### 1.5 A bearer-only client is a 403, a third status in the page family

```
client_id=master-realm, good redirect_uri      -> 403, 3623 bytes
client_id=master-realm, bad redirect_uri       -> 403
client_id=master-realm, no redirect_uri        -> 403
client_id=master-realm, no response_type       -> 403
```

Same `Content-Type`, same `Content-Language: en`, same six headers, same absence
of `Cache-Control` as the 400. The page family is not "the 400 family".

### 1.6 The redirect URI comparison is a string comparison

Against a client registering exactly `http://localhost:9999/callback`, every one
of these is a 400:

```
http://localhost:9999/callback/       trailing slash
http://localhost:9999/callback?x=1    added query
http://localhost:9999/callback#f      added fragment
HTTP://LOCALHOST:9999/callback        uppercased scheme and host
http://localhost:9999/Callback        uppercased path
http://localhost:9999/x/../callback   a ".." segment
http://localhost:9999/%63allback      a percent-encoded path character
http://localhost:9999/callback/more   a sub-path
http://127.0.0.1:9999/callback        the address rather than the name
https://localhost:9999/callback       a different scheme
(empty)                               no redirect_uri at all
```

Nothing is normalised. And the empty-path case is not normalised either: a
client registering `http://localhost:9996` refuses `http://localhost:9996/`, and
one registering `http://localhost:9995/` refuses `http://localhost:9995`.

**The wildcard is not a bare prefix.** Against `http://localhost:9998/*`:

```
http://localhost:9998        200   the prefix with its trailing / removed
http://localhost:9998/       200
http://localhost:9998/cb     200
http://localhost:9998/a/b    200
http://localhost:9998?x=1    200   the query is cut before comparing
http://localhost:9998#f      200   and so is the fragment
http://localhost:9998?x=1#f  200
http://localhost:99980/evil  400   so it is not startsWith("http://localhost:9998")
http://localhost:9998x/evil  400
http://localhost:9997/cb     400
```

and against `http://localhost:9994/cb*`, whose prefix does not end in a slash,
`/cb`, `/cbx` and `/cb/y` are accepted and a bare `/` is not - so the second
chance exists only when the `*` was preceded by a slash. Two more
qualifications: a pattern **containing a `?` is never a wildcard** even when it
ends in one (`http://localhost:9993/cb?a=*` matches only itself and refuses
`?a=1`), and the `*` has to be **last** (`http://localhost:9992/*/cb` matches
nothing, not even `/x/cb`).

The query and fragment are cut in the wildcard branch **only**, which is why the
exact registration above refuses `?x=1` and `#f`.

### 1.7 The accepted scope set follows the client, not the realm

Master's `client-scopes` listing holds fifteen names. A client created through
the API carries eleven of them:

```
defaultClientScopes   acr, basic, email, profile, roles, web-origins
optionalClientScopes  address, microprofile-jwt, offline_access, organization, phone
```

All eleven are accepted at `/auth`, and so is `openid`, which is not a client
scope at all. The four the realm has and this client does not - `service_account`,
`role_list`, `AuthnContextClassRef`, `saml_organization` - are all refused with
`invalid_scope`. So the set is the client's two lists plus `openid`.

An **absent** `scope` is accepted. An **empty** `scope=` is refused with
`Invalid scopes: ` and nothing after it. The description echoes the parameter
**raw**: `scope=openid  nosuchscope` with two spaces answers
`error_description=Invalid+scopes%3A+openid++nosuchscope`, so it cannot be
rebuilt by joining the parsed words.

### 1.8 `response_type` and `response_mode`, the accepted sets

```
response_type   code           200
                none           200
                code code      200      it is read as a set of tokens
                code none      302 unsupported_response_type
                CODE, None     302 unsupported_response_type   case-sensitive
                (empty)        302 unsupported_response_type   not "Missing parameter"
                token, id_token, code token, id_token code
                               302 unauthorized_client, in the **fragment**

response_mode   query, fragment, form_post          accepted
                jwt, query.jwt, fragment.jwt, form_post.jwt   accepted
                QUERY, Query, FRAGMENT, FORM_POST   302 Invalid parameter: response_mode
                web_message, direct_post, (empty)   302 Invalid parameter: response_mode
```

So the accepted mode set is **seven**, not the three the design named.

**The response mode governs a rejection exactly as it governs a success, and
the four `jwt` spellings are real JARM.** Measured on a request with no
`response_type`, so this is the error path and not an extrapolation:

```
response_mode=query          302  ?error=invalid_request&error_description=Missing+parameter...
response_mode=fragment       302  #error=invalid_request&...
response_mode=form_post      200  text/html, an auto-submitting form
response_mode=jwt            302  ?response=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6...
response_mode=query.jwt      302  ?response=<the same signed JWT>
response_mode=fragment.jwt   302  #response=<the same signed JWT>
response_mode=form_post.jwt  200  text/html, the form
```

The `jwt` modes replace every parameter with one signed assertion, so a client
asking for one and given the plain parameters has been handed an unsigned error.
Nothing about JARM appears anywhere else in the observed document; this is the
first sighting.

**The invalid-`response_mode` rejection itself always goes to the query**, even
for `response_type=token`, whose every other rejection lands in the fragment.

### 1.9 A repeated parameter is its own error family

```
response_type twice   -> error=invalid_request&error_description=duplicated+parameter
state twice           -> ... &state=one&...        the first value is used
redirect_uri twice    -> 302 to the **first** URI, carrying "duplicated parameter"
nonce twice           -> duplicated parameter
prompt twice          -> duplicated parameter
zz twice (unknown)    -> duplicated parameter
client_id twice       -> 400, the page family
```

The description is lower case, unlike every other one on this endpoint. It
applies to keys Keycloak never reads. A repeated `client_id` never reaches the
check, because the client cannot be resolved and the answer is the page family.

### 1.10 `state` is echoed when it was sent, empty or not

```
state=xyz123   -> ...&state=xyz123&iss=...
state=         -> ...&state=&iss=...       three keys plus an empty one
(absent)       -> ...&iss=...              three keys, no empty fourth
```

`nonce`, `login_hint` and `ui_locales` are not echoed.

### 1.11 The two header sets, swept

```
                                      status  CC  RP HS XC XF XR CSP CL Set-Cookie
302 missing response_type                302   Y   Y  Y  Y  .  Y   .   Y     .
302 unsupported response_type            302   Y   Y  Y  Y  .  Y   .   Y     .
302 invalid scope                        302   Y   Y  Y  Y  .  Y   .   Y     .
302 invalid response_mode                302   Y   Y  Y  Y  .  Y   .   Y     .
302 implicit, in the fragment            302   Y   Y  Y  Y  .  Y   .   Y     .
302 pkce missing challenge               302   Y   Y  Y  Y  .  Y   .   Y     .
302 prompt=none                          302   Y   Y  Y  Y  .  Y   .   Y     Y
400 bad redirect_uri                     400   .   Y  Y  Y  Y  Y   Y   Y     .
400 unknown client                       400   .   Y  Y  Y  Y  Y   Y   Y     .
403 bearer-only client                   403   .   Y  Y  Y  Y  Y   Y   Y     .
200 login page                           200   Y   Y  Y  Y  Y  Y   Y   .     Y
```

`CC` is `no-store, must-revalidate, max-age=0` wherever it appears. The page
family also carries `Content-Language: en`, which the redirect family does not.
The redirect family carries `content-length: 0` and no `Content-Type` at all.

**`prompt=none` is the only rejection in the redirect family that sets
cookies**, because it is checked after the authentication session already
exists. The other six set none.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Suggested wording, in the file's own voice. The first replaces nothing; the rest
are additions.

- **The authorization endpoint's rejection order is measured, ten steps deep,
  and two of them are not where they look.** A duplicated parameter is checked
  **seventh** - after the client's flow flags and before the scope - so a
  request with a repeated `nonce` on a client with the standard flow off answers
  about the flow. And the PKCE check is three checks whose **first** is the
  absent `code_challenge`: `code_challenge_method=bogus` with no challenge
  answers `Missing parameter: code_challenge`, never
  `Invalid parameter: code_challenge_method`. Reordering either "because a
  request-shape check should come first" changes the answer to a request that
  is wrong in two ways, which is most of them.

- **`/auth`'s page family has three statuses, not one.** An unknown, absent or
  disabled `client_id` and an unregistered `redirect_uri` are 400; a
  **bearer-only** client is **403**, and its check runs before the redirect URI
  rather than after. All three carry `Content-Language: en`,
  `Content-Security-Policy`, the five security headers, and **no
  `Cache-Control` at all** - where the 302 beside them and the 200 login page
  both send `no-store, must-revalidate, max-age=0`.

- **A redirect URI is compared as a string and nothing about it is
  normalised.** A trailing slash, an added query, an added fragment, an
  uppercased scheme, host or path, a `..` segment, a percent-encoded character
  and `127.0.0.1` for `localhost` are all refused by a client registering the
  literal. And a wildcard is **not** a bare prefix: `http://localhost:9998/*`
  accepts `http://localhost:9998` and refuses `http://localhost:99980/evil`, so
  it is a prefix match on the pattern minus its `*`, plus an equality check
  against that with a trailing slash removed, with the query and fragment cut
  first. A pattern containing a `?` is not a wildcard even ending in one, and a
  `*` that is not last matches nothing.

- **The scope a request may ask for follows the client, not the realm.**
  `openid` plus the client's own `defaultClientScopes` and
  `optionalClientScopes`; `service_account`, `role_list`,
  `AuthnContextClassRef` and `saml_organization` are client scopes **of master**
  that a normal client does not carry and every one of them is refused. The
  description echoes the parameter raw, doubled spaces and all, so it cannot be
  rebuilt from the parsed words.

- **`POST /auth` reads the request body and ignores the query string.** The same
  parameters that work on a `GET`'s query answer the 400 page on a `POST` that
  puts them there. `r.Form` merges the two and would hide it.

- **A wrong method on `/auth` is a real 405.** Third counter-example to the
  404 rule, after the role-mapping paths and `PATCH /admin/realms/{realm}`.
  `PUT`, `DELETE` and `PATCH` all answer 405 with `application/json`, `HEAD`
  answers 200 and `OPTIONS` answers 200 with
  `Allow: HEAD, POST, GET, OPTIONS`. Gloak sends its usual 404. See F31; three
  data points that disagree still do not say what the rule is.

- **A repeated query parameter is its own error, and its description is lower
  case.** `duplicated parameter`, where every other description on this endpoint
  is capitalised. It applies to keys the endpoint never reads.

- **The response mode decides how a *rejection* travels, not only a success,
  and two of the seven modes are not a redirect at all.** `form_post` and
  `form_post.jwt` answer 200 with an auto-submitting form even for a missing
  `response_type`, and `jwt`, `query.jwt` and `fragment.jwt` replace every
  parameter with one signed JARM assertion in `response`. Reading response mode
  as "which separator" produces a 302 where Keycloak sends a 200, and plain
  parameters where it sends a signature.

The existing line about `Content-Security-Policy` is already corrected in
`AGENTS.md` by the first cut and needs no further change. One line **is** now
slightly wrong: the entry beginning "`GET /auth`'s redirect back to the client
is the one response in the browser flow that omits `X-Frame-Options`" is
confirmed and can gain "measured across seven different rejections, including
the one that sets cookies".

---

## 3. Follow-ups to file or close

### To file

**F: `internal/admin`'s client create does not default the client scopes.**
Keycloak gives a client created with no `defaultClientScopes` the realm's six
defaults and five optionals; Gloak's `POST /admin/realms/{realm}/clients` writes
`[]` for both. Nothing noticed until `/auth` started validating `scope` against
them, and the consequence is measurable: Gloak refuses `scope=profile` on a
client created through its own admin API, where Keycloak accepts it. The
constants already exist as `defaultScopeNames` and `optionalScopeNames` in
`internal/bootstrap`. Client scopes are P5's; this is the part of them that is
already observable.

**F: the conformance harness cannot express a repeated query parameter.**
`Request.Query` is a `map[string]string` and `buildRequest` writes it with
`url.Values.Set`, so no case can send one key twice. That leaves the whole
`duplicated parameter` family served, unit-tested in `internal/oidc` and under
no golden. A `[]string` variant, or a raw query string field, would close it.
`case.go` was another agent's file this week.

**F: `GET /auth` answers a fully valid request with the page family's 400.**
Deliberate and documented in the handler, and it is the shape of "Gloak has no
login page yet": the alternatives were a login form whose `POST` target does not
exist, or a status no measurement supports. It closes when the success path
lands. Anyone driving Gloak by hand will see it, which is why it is filed rather
than only commented.

**F: five of the seven response modes are accepted and not transported.**
`form_post` and `form_post.jwt` answer 200 with an auto-submitting HTML form;
`jwt`, `query.jwt` and `fragment.jwt` answer with a signed JARM assertion in a
`response` parameter. Gloak recognises all five as valid - refusing them would
contradict a measurement - and answers the page family, because emitting the
plain parameters would hand a JARM client an unsigned error where it asked for
a signed one. Measured 2026-08-29 on the **error** path; the observed document
records `form_post` only on the success path and records JARM nowhere.

**F: the `unauthorized_client` rejections for a disabled flow are served and
not under a golden.** Both spellings ("Standard flow is disabled for the
client.", "Implicit flow is disabled for the client.") are implemented and
unit-tested. No case covers them: `oidc/authorization/implicit-flow` is
deliberately `Pending` as out of P3's scope, and there is no case for the
standard-flow one. Adding either means adding a fixture client with the flag
off, which is a fixture nothing else needs.

### To close

**Nothing.** F31 is explicitly *not* closed by section 1.3: a third
counter-example narrows nothing.

---

## 4. Parity before and after

```
before   129 of 485 enumerated behaviours served
after    136 of 489
```

The chapter:

```
before   oidc/authorization    served 0   recorded 7   documented 11
after    oidc/authorization    served 7   recorded 4   documented 15
```

Seven cases served. Three were already `Recorded` and were promoted -
`missing-response-type`, `unsupported-scope`, `prompt-none-no-session`. Four are
new and were recorded against the reference container before being marked
`Implemented`: `unsupported-response-type`, `invalid-response-mode`,
`pkce-missing-challenge`, `pkce-invalid-challenge-method`. The denominator moves
by those four.

The four cases still `Recorded` are the success path - `code-flow-redirect`,
`pkce-s256`, `pkce-plain`, `response-mode-fragment` - and all four still fail
their fixture's `ExpectStatus: 200` at the authorization step, which is the
state `TestConformance` expects of a `Recorded` case and the honest report that
the login page is not built.

For the roadmap: P3's second cut serves `GET`/`POST /auth`'s two error families
and no part of the success path.
