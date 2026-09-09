# The realm resource's own 404

F184, deferred three times and the fourth family of one shape. The three before
it are `/organizations`, the group tree and `/account`; each was resolved where
it was found, and the dispatch cut stopped at `/protocol` on purpose, writing
that the shape was "worth doing once rather than three more times". This is that
once.

Everything below was measured on **2026-09-09** against
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 18091, with
`curl --path-as-is`, because curl normalises a path before sending it and a
probe written without that flag measures curl. Header counts are of the five
security headers - `Referrer-Policy`, `Strict-Transport-Security`,
`X-Content-Type-Options`, `X-Frame-Options`, `X-Robots-Tag` - counted by the
probe script rather than by eye.

## 1. The shape, re-measured

F184's five rows reproduce exactly:

```
GET /realms/master                          200 5/5  the realm info document
GET /realms/master/nosuchthing              404 5/5  {"error":"HTTP 404 Not Found"}
GET /realms/master/nosuchthing/deeper       404 5/5  {"error":"HTTP 404 Not Found"}
GET /realms/nosuchrealm/nosuchthing         404 5/5  {"error":"Realm does not exist"}
GET /realms                                 404 0/5  {"error":"Unable to find matching target resource method"}
GET /realms/                                404 0/5  the same 58 bytes
```

`Content-Type` is a bare `application/json` on all of them, there is no
`Cache-Control` and no `Date`. Gloak answered the header-less unmatched-path
body for the first three.

### 1.1 Depth changes nothing, and neither does a trailing slash

```
GET /realms/master/                            200 5/5  the realm info document
GET /realms/master/nosuchthing/                404 5/5  {"error":"HTTP 404 Not Found"}
GET /realms/master/nosuchthing/deeper/deepest  404 5/5  {"error":"HTTP 404 Not Found"}
GET /realms/master/nosuchthing/a/b/c/d/e       404 5/5  {"error":"HTTP 404 Not Found"}
GET /realms/nosuchrealm                        404 5/5  {"error":"Realm does not exist"}
GET /realms/nosuchrealm/                       404 5/5  {"error":"Realm does not exist"}
GET /realms/nosuchrealm/nosuchthing/           404 5/5  {"error":"Realm does not exist"}
GET /realms/nosuchrealm/nosuchthing/deeper     404 5/5  {"error":"Realm does not exist"}
```

Six segments answer what one does, so **one `{rest...}` pattern is the whole
tree** rather than a pattern per depth. The trailing slash is F177's strip
running ahead of routing, which is why none of the slashed rows needs a sibling
pattern.

### 1.2 All seven verbs, one answer

```
GET     /realms/master/nosuchthing   404 5/5  {"error":"HTTP 404 Not Found"}
POST    /realms/master/nosuchthing   404 5/5  the same 30 bytes
PUT     /realms/master/nosuchthing   404 5/5
DELETE  /realms/master/nosuchthing   404 5/5
PATCH   /realms/master/nosuchthing   404 5/5
OPTIONS /realms/master/nosuchthing   404 5/5
HEAD    /realms/master/nosuchthing   404 5/5   (sent with curl -I)
```

and five verbs on an unknown realm all answer `Realm does not exist` with all
five. So this joins `Protocol not found` as a route that answers every method
identically - no 405, no `Allow`, no `OPTIONS` 200 - which is why both patterns
are registered with no method.

### 1.3 The realm is resolved before the **method** is dispatched

This is the sharpest row in the cut, and it is stronger than the dispatch cut's
"the realm is resolved first". These paths **are** routes; they are hit with a
method they do not serve:

```
POST /realms/master/.well-known/openid-configuration       404 5/5  {"error":"HTTP 404 Not Found"}
POST /realms/nosuchrealm/.well-known/openid-configuration  404 5/5  {"error":"Realm does not exist"}
GET  /realms/nosuchrealm/.well-known/openid-configuration  404 5/5  {"error":"Realm does not exist"}
POST /realms/nosuchrealm/account/groups                    404 5/5  {"error":"Realm does not exist"}
GET  /realms/nosuchrealm/account/groups                    404 5/5  {"error":"Realm does not exist"}
POST /realms/nosuchrealm/protocol/openid-connect/certs     404 5/5  {"error":"Realm does not exist"}
POST /realms/nosuchrealm                                   404 5/5  {"error":"Realm does not exist"}
PUT  /realms/nosuchrealm                                   404 5/5  {"error":"Realm does not exist"}
DELETE /realms/nosuchrealm                                 404 5/5  {"error":"Realm does not exist"}
OPTIONS /realms/nosuchrealm                                404 5/5  {"error":"Realm does not exist"}
```

One row on the other side of the boundary, and it is F31's:

```
POST    /realms/master   405 5/5  {"error":"HTTP 405 Method Not Allowed"}
PUT     /realms/master   405 5/5  the same 39 bytes
DELETE  /realms/master   405 5/5
OPTIONS /realms/master   200 4/5  no body, no Content-Type
```

So on a **known** realm the realm root is a real 405 and Gloak still answers
404. Nothing here changes that, and the divergence is unchanged in either
direction: the wrong-method fallback and the dispatcher write the same thirty
bytes.

### 1.4 `/realms` and `/realms/` are one cell, and the strip is why

The brief asked whether they are one cell or two. They are one, and the second
row is F177's rule rather than a fact about `/realms`:

```
GET  /realms    404 0/5  {"error":"Unable to find matching target resource method"}
GET  /realms/   404 0/5  the same 58 bytes
POST /realms    404 0/5  the same 58 bytes
GET  /realms//  400 0/5  {"error":"missingNormalization", ...}
```

The strip turns `/realms/` into `/realms` before any route is consulted, so
there is one routing decision and two spellings of it. What makes it worth a
conformance case anyway is that **it is the only measured place in this server
where a shorter path is less reachable than a longer one**, and that is a
constraint on the fix rather than a curiosity: a catch-all registered at
`/realms/{rest...}`, or as a `/realms/` subtree, serves both of these and
passes every other case in the group. `http/fallback/realms-collection` is what
fails.

### 1.5 The 404 is content-negotiated, and negotiation erases the realm

Nobody had sent this request. With `Accept: text/html` the same paths answer a
**3574-byte "Page not found" login theme page**, 404, all five headers:

```
GET /realms/master/nosuchthing       Accept: application/json  404 5/5   30 bytes  {"error":"HTTP 404 Not Found"}
GET /realms/master/nosuchthing       Accept: text/html         404 5/5 3574 bytes  the theme page
GET /realms/nosuchrealm/nosuchthing  Accept: text/html         404 5/5 3574 bytes  byte-identical to the row above
GET /realms/master/nosuchthing/      Accept: text/html         404 5/5 3574 bytes
```

The third row is the one to keep: **the two JSON sentences collapse into one
HTML page**, so `Accept` decides not only the media type but whether the answer
distinguishes a realm that exists from one that does not. `cmp` on the two
bodies reports them identical. Gloak parses no `Accept` on this surface and
answers the JSON branch always. Filed as F210.

## 2. The precedence question, answered rather than assumed

Two catch-alls now exist, one nested inside the other's tree, and they answer
**different sentences at the same status**. If the wider one won,
`Protocol not found` would leave the server and every test asserting it would
still pass on the narrower paths, because the narrower paths are the ones a
reader probes.

The route table was run rather than read. `/tmp` scratch program, a mux carrying
the real patterns, `mux.Handler` asked for the matched pattern:

```
GET /realms/master/protocol                        -> /realms/{realm}/protocol
GET /realms/master/protocol/nosuchproto            -> /realms/{realm}/protocol/{protocol}
GET /realms/master/protocol/nosuchproto/deep       -> /realms/{realm}/protocol/{protocol}/{rest...}
GET /realms/master/protocol/openid-connect/certs   -> GET /realms/{realm}/protocol/openid-connect/certs
GET /realms/master/protocol/openid-connect/nosuchsub -> /realms/{realm}/protocol/{protocol}/{rest...}
GET /realms/master/nosuchthing                     -> /realms/{realm}/{rest...}
GET /realms/master/account/nosuchsub               -> /realms/{realm}/{rest...}
GET /realms                                        -> ""
GET /realms/                                       -> ""
```

`/realms/{realm}/protocol/{protocol}/{rest...}` matches a strict subset of
`/realms/{realm}/{rest...}`, so Go gives it the request; none of the five
patterns overlaps another, so the tie-break never has to be made and nothing
panics at registration. Against a live 26.7.1 the answers agree:

```
GET /realms/master/protocol                          404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/protocol/openid-connect           404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/protocol/openid-connect/nosuchsub 404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/protocol/saml/nosuchsub           404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/protocol/nosuchproto              404 5/5 {"error":"Protocol not found"}
GET /realms/master/protocol/nosuchproto/deeper       404 5/5 {"error":"Protocol not found"}
GET /realms/nosuchrealm/protocol/nosuchproto         404 5/5 {"error":"Realm does not exist"}
```

**So the precedence is: realm, then protocol map, then the realm resource's own
404 - and the protocol dispatcher is not a special case of the wider one.** It
answers `HTTP 404 Not Found` for a registered protocol at any depth, which is
what the wider dispatcher would have answered anyway, and `Protocol not found`
for an unregistered one, which the wider dispatcher would have got wrong on
every mistyped protocol name.

`TestTheProtocolDispatcherBeatsTheRealmResourceDispatcher` is the assertion, and
it is not redundant with `TestProtocolNotFound`: that test would still pass if
the protocol patterns were deleted and the realm catch-all took over, because
the mutation that proves it - pointing
`/realms/{realm}/protocol/{protocol}` at `realmResourceDispatch` - is M5 in
section 6 and it is killed by this test alone.

### 2.1 The trailing slash still composes in one direction

§2.4 of `protocol-dispatch-rules.md` is about exactly this. The strip runs in
`WithKeycloakFallbacks` before `mux.Handler` is asked anything, so
`/realms/master/nosuchthing/` arrives as `/realms/master/nosuchthing` and
`/realms/master/` arrives as `/realms/master`. That is why:

- the `{rest...}` pattern needs no trailing-slash sibling;
- the bare `/realms/{realm}` pattern also covers `/realms/{realm}/`;
- `/realms/` cannot reach the catch-all, because it is `/realms` by then and a
  ServeMux wildcard does not match an empty segment.

**And one hazard the strip does not remove.** `WithKeycloakFallbacks` treats a
non-empty pattern from `mux.Handler` as "a real route matched", which is F11's
old failure mode. Section 4.2 is where that bit.

## 3. What the catch-all does **not** swallow, proved

The risk F184 names grew when the account chapter landed, so this was
enumerated rather than hoped. Every pattern registered under `/realms/{realm}`
by any package, from `grep` over `internal/oidc`, `internal/account` and
`internal/admin`:

```
GET    /realms/{realm}
GET    /realms/{realm}/.well-known/openid-configuration
GET,POST /realms/{realm}/protocol/openid-connect/auth
GET,POST /realms/{realm}/protocol/openid-connect/auth/device
GET,POST /realms/{realm}/protocol/openid-connect/logout
GET,POST /realms/{realm}/protocol/openid-connect/userinfo
GET      /realms/{realm}/protocol/openid-connect/certs
POST     /realms/{realm}/protocol/openid-connect/token
POST     /realms/{realm}/protocol/openid-connect/token/introspect
POST     /realms/{realm}/protocol/openid-connect/revoke
POST     /realms/{realm}/protocol/openid-connect/ext/ciba/auth
GET      /realms/{realm}/protocol/saml/descriptor
         /realms/{realm}/protocol, /protocol/{protocol}, /protocol/{protocol}/{rest...}
GET,POST /realms/{realm}/login-actions/authenticate
GET,POST /realms/{realm}/login-actions/required-action
POST     /realms/{realm}/login-actions/consent
GET,POST /realms/{realm}/device
GET      /realms/{realm}/device/status
POST     /realms/{realm}/clients-registrations/openid-connect
GET,PUT,DELETE /realms/{realm}/clients-registrations/openid-connect/{clientId}
GET      /realms/{realm}/account/groups            (internal/account)
GET      /realms/{realm}/account/linked-accounts   (internal/account)
```

Three things prove none of them moved.

1. **`TestTheRealmResourceDispatcherDoesNotSwallowAServedRoute`** asks for
   eleven of them, bare and slashed, on a mux carrying **both** `oidc.Register`
   and `account.Register`, and requires none to answer either 404 sentence. The
   two account routes are in the list precisely because they belong to another
   package: the two are combined only in `cmd/gloak` and in the conformance
   server, so neither package's own tests would otherwise see the composition.
   `newServerWithAccount` exists for that one test.
2. **`make record` moved no committed golden.** Section 5.
3. **The golden corpus is the ratchet, and it ran.** 1087 `.http` files under
   `internal/conformance/testdata/golden` after this cut, 1080 before it -
   counted rather than taken from AGENTS.md, whose 921 is from 2026-09-06. R2
   and R3 in section 6 are the routing mutations run against the whole
   `internal/conformance` package unfiltered; both are killed by
   `TestConformance`.

### 3.1 What it swallows that Keycloak does route

These are paths a live 26.7.1 answers with something other than this 404, and
which Gloak serves no handler for. Every one of them was **already** a
divergence: Gloak answered the unmatched-path body with none of the five
headers. The cut replaces one wrong answer with another wrong answer that at
least carries the right headers and sits in the right family.

```
GET /realms/master/account                          200 5/5 text/html  the account console
GET /realms/master/account/                         200 5/5 text/html  the same page
GET /realms/master/account          + user token    200 5/5 the profile resource
GET /realms/master/account/nosuchsub                401 5/5 {"error":"HTTP 401 Unauthorized"}
GET /realms/master/login-actions/registration       400 5/5 text/html  a theme page
GET /realms/master/login-actions/reset-credentials  400 5/5 text/html
GET /realms/master/login-actions/first-broker-login 400 5/5 text/html
GET /realms/master/broker/nosuchalias/endpoint      404 5/5 {"error":"Identity Provider [nosuchalias] not found."}
GET /realms/master/clients-registrations            405 5/5 {"error":"HTTP 405 Method Not Allowed"}
GET /realms/master/clients-registrations/nosuchprovider 404 5/5 {"error":"Client registration provider not found"}
```

Two of them are recorded in the catalogue already and stay `Recorded`:
`account/console/accept-html` and `account/console/unknown-subpath`. One is new
and is section 4.4. The broker sentence is a spelling nothing in this repository
had (F211), and the last two are named in `router.go`'s own comment as declared
divergences.

### 3.2 What it swallows that Keycloak answers exactly this way

The other side, and it is the argument for the cut being one dispatcher rather
than four. These are neighbours of routes Gloak serves, and the catch-all is
byte-correct on all of them:

```
GET /realms/master/login-actions              404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/login-actions/nosuchaction 404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/device/nosuchsub           404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/.well-known/nosuchdoc      404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/account/nosuchsub  + token 404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/clients-registrations/default 404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/clients-registrations/install 404 5/5 {"error":"HTTP 404 Not Found"}
```

Three of those - `login-actions`, `device` and `.well-known` - are in
`TestARealmResourceThatNoRouteServes` for that reason: they are the cells that
would have needed three more dispatchers if this had been done per family.

### 3.3 The one family with a gate in front of its routing

`/account` is the exception and it is the only one. Measured on one container,
minutes apart, with a real account user created for the purpose:

```
GET /realms/nosuchrealm/account/nosuchsub               404 5/5 {"error":"Realm does not exist"}
GET /realms/master/account/nosuchsub    no token        401 5/5 {"error":"HTTP 401 Unauthorized"}
GET /realms/master/account/nosuchsub    + user token    404 5/5 {"error":"HTTP 404 Not Found"}
GET /realms/master/account/nosuchsub/deeper + token     404 5/5 {"error":"HTTP 404 Not Found"}
POST /realms/master/account/groups      + user token    404 5/5 {"error":"HTTP 404 Not Found"}
```

So the account resource's order is **realm, gate, route**, where every other
family under `/realms/{realm}` is **realm, route**. `realmResourceDispatch`
resolves the realm and stops, so it is right on the authenticated cell - which
is why `account/dispatch/unknown-subpath-json` is promoted - and wrong on the
anonymous one. `account/dispatch/unknown-subpath-unauthenticated` is a new
`Recorded` case holding that, and F209 is the cut that would close it.

The measurement that decides this is worth naming: the two rows differ **only**
in the `Authorization` header, on one path, on one container. A reader who
probes with a token concludes the catch-all is right; a reader who probes
without one concludes it is wrong. Both probes were sent.

## 4. Does the shape reach `/admin/`? Yes, and it is deeper there

The dispatch cut measured the trailing-slash rule reaching the Admin API. The
realm-resource 404 does too, and one row shows why the admin side is a cut of
its own rather than the same two patterns:

```
GET /admin/realms/master/nosuchthing                    401 5/5  no token
GET /admin/realms/master/nosuchthing        + admin tok 404 5/5  {"error":"HTTP 404 Not Found"}
GET /admin/realms/master/nosuchthing/deeper + admin tok 404 5/5  {"error":"HTTP 404 Not Found"}
GET /admin/realms/nosuchrealm/nosuchthing   + admin tok 404 5/5  {"error":"Realm not found."}
GET /admin/realms/nosuchrealm               + admin tok 404 5/5  {"error":"Realm not found."}
GET /admin/realms/master/clients/nosuchuuid/nosuchsub
                                            + admin tok 404 5/5  {"error":"Could not find client"}
GET /admin/nosuchthing                                  405 0/5  {"error":"HTTP 405 Method Not Allowed"}
```

Four findings, none of them acted on here:

- the shape is the same and the **sentence is not**: `Realm not found.` with
  the full stop, which is AGENTS.md's recorded split between the two APIs;
- the realm sentence sits **behind** the bearer gate, unlike the protocol side,
  so an admin catch-all would have to run `internal/admin`'s authentication
  first;
- the client locator resolves **before** the 404, so the admin side is not one
  dispatcher but a chain of sub-resource locators - the `Could not find client`
  row is what says a single `/admin/realms/{realm}/{rest...}` pattern would be
  wrong;
- **`/admin/nosuchthing` is a 405 with none of the five**, which is a fallback
  cell nothing in this repository records and is neither of the two known
  bodies for an unrouted path.

Filed as F211.

## 5. The `make record` diff, read file by file

`make record` created **seven** goldens and moved **none**. The brief's worry -
that a catch-all one level up churns the corpus - does not happen, and the
reason is section 3: every path an existing case sends is either a served route
or already one of the two bodies the dispatcher writes.

```
A internal/conformance/testdata/golden/http/fallback/realm-resource.http
A internal/conformance/testdata/golden/http/fallback/realm-resource-deep.http
A internal/conformance/testdata/golden/http/fallback/realm-resource-unknown-realm.http
A internal/conformance/testdata/golden/http/fallback/method-not-allowed-unknown-realm.http
A internal/conformance/testdata/golden/http/fallback/realm-root-unknown-realm.http
A internal/conformance/testdata/golden/http/fallback/realms-collection.http
A internal/conformance/testdata/golden/account/dispatch/unknown-subpath-unauthenticated.http
M -- none
```

Each read against the hand-measurement that motivated it:

- **`realm-resource.http`** - `GET /realms/master/nosuchthing`, 404,
  `application/json`, five headers, `{"error":"HTTP 404 Not Found"}`. This is
  §1's first row byte for byte. No `Cache-Control` in the file, which is why the
  case declares it absent.
- **`realm-resource-deep.http`** - the same response one segment deeper. It
  duplicates the body on purpose: the behaviour being pinned is the depth of the
  pattern, and the only way a golden can say "two segments reached the same
  handler" is to hold what that handler answers.
- **`realm-resource-unknown-realm.http`** - `{"error":"Realm does not exist"}`,
  five headers. §1's third row. The discriminating half of the pair above.
- **`method-not-allowed-unknown-realm.http`** -
  `POST /realms/nosuchrealm/.well-known/openid-configuration`,
  `{"error":"Realm does not exist"}`. §1.3's second row, and the golden that
  says the catch-all carries no method.
- **`realm-root-unknown-realm.http`** - `POST /realms/nosuchrealm`, the same
  sentence. §1.3's seventh row, and the golden that pins the bare pattern
  against §4.2's redirect.
- **`realms-collection.http`** - `GET /realms`, 404, `application/json`,
  `{"error":"Unable to find matching target resource method"}`, and **no
  security headers in the file at all**. §1.4's first row. The absence is the
  assertion, so the case declares all five absent rather than relying on the
  bytes.
- **`unknown-subpath-unauthenticated.http`** - `GET /realms/master/account/nosuchsub`
  with no `Authorization`, **401**, `{"error":"HTTP 401 Unauthorized"}`, five
  headers. §3.3's second row. It is the one golden here Gloak does not match,
  and it is `Recorded` for that reason.

Nothing else in the tree moved, so there is no file whose movement needs
explaining.

## 6. The mutation pass

Twenty mutations across two rounds, by a harness that copies the original aside
and installs the revert on a `trap ... EXIT` **before** anything can fail,
counts the target as a substring rather than as grep's matching lines, refuses a
target that does not appear exactly once, refuses one that does not build,
refuses one whose `-run` selected no test, and re-hashes the file after
reverting. The tree was committed before the pass and nothing was staged during
it. `git status` was read after every group and was clean every time.

**Twenty applied, nineteen killed, one survivor - and the survivor is F181's,
not a new one.**

The harness's substring count earned itself twice. `grep -c` counts matching
*lines*, so a multi-line target came back as 624 occurrences and the mutation
was refused rather than applied to the wrong place; and a target pasted from a
draft rather than from the file came back as 0, because `gofmt` had realigned
the struct literal. Both refusals are the harness working: **a mutation whose
target it cannot find exactly once is not a mutation**.

```
     the route table
M1   drop the {rest...} pattern                          KILLED  TestARealmResourceThatNoRouteServes
M2   drop the bare /realms/{realm} pattern               KILLED  TestTheRealmResourceDispatcherNeverRedirects
M3   register the catch-all as GET only                  KILLED  TestTheRealmIsResolvedBeforeTheMethodIsDispatched
M4   register it one segment higher, /realms/{rest...}   KILLED  TestTheRealmCollectionStaysOffTheRouteTable
M5   point /protocol/{protocol} at the wider dispatcher  KILLED  TestTheProtocolDispatcherBeatsTheRealmResourceDispatcher
     the handler
M6   answer without resolving the realm                  KILLED  TestTheRealmResourceDispatcherResolvesTheRealmFirst
M7   write the unmatched-path sentence instead           KILLED  TestARealmResourceThatNoRouteServes
M8   answer 405 rather than 404                          KILLED  TestARealmResourceThatNoRouteServes
M9   write `Protocol not found` instead                  KILLED  TestARealmResourceThatNoRouteServes
     the wrapper the cut made load-bearing again
M10  invert the Allow probe                              KILLED  TestWrongMethodReturnsKeycloakShapedNotFound
M11  drop the headers from the wrong-method branch       KILLED  TestWrongMethodReturnsKeycloakShapedNotFound
M12  add headers to the unmatched-path branch            KILLED  TestTheRealmCollectionStaysOffTheRouteTable
     the conformance probe the cut had to rewrite
M13  treat any non-empty pattern as routed               KILLED  TestNoReasonClaimsAServedEndpointIsUnserved
M14  probe with GET alone                                KILLED  TestNoReasonClaimsAServedEndpointIsUnserved
M15  never report a path as routed                       KILLED  TestNoReasonClaimsAServedEndpointIsUnserved
     round two, whole packages, no -run filter
R1   M6 against all of internal/oidc                     KILLED  TestTheRealmResourceDispatcherResolvesTheRealmFirst
R2   M1 against all of internal/conformance              KILLED  TestConformance
R3   M2 against all of internal/conformance              KILLED  TestConformance
     round two, the catalogue's own declarations
R4   drop realms-collection's AssertAbsentHeaders        SURVIVED  see 6.2
R5   demote account/dispatch/unknown-subpath-json        KILLED  TestConformance
```

The `-run` filter on M1-M15 is the thing this project has been bitten by, so
every mutation that touches routing or the handler was re-run in round two
against the **whole** package with no filter: R1 for `internal/oidc`, R2 and R3
for `internal/conformance`, R4 and R5 for the catalogue. The verdicts agree with
round one, and R1 is worth noting for a different reason - unfiltered, M6 is
killed first by `TestTheRealmResourceDispatcherResolvesTheRealmFirst` rather
than by the test M6 was aimed at, which is the right test failing for the right
reason.

### 6.1 Three of them are the ones worth reporting

**M2 is the finding this cut nearly shipped without.** Registering
`/realms/{realm}/{rest...}` alone makes Go's `ServeMux` add an implicit redirect
at the root of the subtree, and `POST /realms/master` then answers a **307 to
`/realms/master/`** - with `mux.Handler` reporting a **non-empty pattern** for
it, so `WithKeycloakFallbacks` hands the request straight to `mux.ServeHTTP` and
`net/http` writes a body this project never produces. That is §3.1's 301 hazard
of the dispatch cut and F153's shape, and it was found by running the route
table rather than by reading the documentation - which is what F178 told the
previous cut to do and the reason it is written down again here. The redirect
only fires for methods `GET /realms/{realm}` does not cover, which is why a
`GET` probe misses it entirely.

**M3 is the mutation that a reader's test would not have caught.** A catch-all
registered `GET /realms/{realm}/{rest...}` answers every row of §1 correctly and
gets §1.3 wrong: the wrong-method requests fall through to
`WithKeycloakFallbacks`, which holds no store and cannot resolve a realm, so
`POST /realms/nosuchrealm/...` answers `HTTP 404 Not Found` where Keycloak
answers about the realm. The case that kills it,
`http/fallback/method-not-allowed-unknown-realm`, exists because that cell was
measured before the patterns were written.

**M5 is the precedence question turned into a test.** Pointing
`/realms/{realm}/protocol/{protocol}` at `realmResourceDispatch` is what "the
wider dispatcher won" looks like, and it is a *coherent wrong implementation*:
one catch-all for the whole realm tree, answering `HTTP 404 Not Found`
everywhere. It passes `TestProtocolNotFound`'s siblings on every path with a
registered protocol in it and fails only where the sentences differ.

### 6.2 The two catalogue mutations, and what they are worth

R4 and R5 are mutations of the *catalogue*, not of the server, and they were run
because the cut's diff is half catalogue.

R5 - demoting `account/dispatch/unknown-subpath-json` back to `Recorded` - is
killed by `TestConformance`, which refuses a `Recorded` case that matches. That
is the harness working as designed and it is what made the promotion necessary
in the first place.

R4 - deleting `realms-collection`'s five-header `AssertAbsentHeaders` block -
**survived all 1462 tests in `internal/conformance`, and it is F181 rather than
a new finding.** F181 records that
`TestAssertAbsentHeadersAgreeWithTheGolden` cannot catch a declaration being
deleted, because a smaller set of true claims is still true, and that the rule
which would catch it is the mirror - every golden missing a security header must
have a case declaring it absent - which fires on eighty-odd committed goldens
today and is therefore a sweep rather than a ratchet.

The mutated line was read before this was written, and the coherent wrong
implementation it permits is a concrete one rather than a shrug: **it is M12.**
With the declaration gone, a `WithKeycloakFallbacks` that called
`httpx.SetSecurityHeaders(w)` on the unmatched-path branch as well - one line,
and the tidy-up somebody will propose the first time the two branches are read
side by side - sends five headers on `/realms` where Keycloak sends none, the
golden still holds none, and `AssertHeaders` only ever compares the header it
names. The corpus would be green.

What stops it is not the corpus. M12 is killed by
`TestTheRealmCollectionStaysOffTheRouteTable` in `internal/oidc`, which asserts
the whole set absent. So the guard exists and lives in a different package from
the case that looks like it holds it - which is the shape of F181 rather than a
hole this cut opened, and it is a fifth consumer for that follow-up's argument.

## 7. What moved on the meter

`make conformance`, before and after, with the base taken from the brief and
re-measured on the merge base:

```
                       base            head
http/fallback           6 of  6        12 of 12
account/dispatch        0 of  3         1 of  4
total                 570 of 622      577 of 629
```

Seven behaviours served where none was served before: six new `Implemented`
cases and one promotion. One new `Recorded` case, which is the cell the cut gets
wrong and now records. **The parity total does not fall**, and the two chapters
that are not enumerated are still two.

The promotion is `account/dispatch/unknown-subpath-json`. Its `Reason` said the
shape "is fixed by a wildcard dispatcher under `/account`, which is a cut of its
own"; that turned out to be one level too low - the fix is a dispatcher under
`/realms/{realm}`, and the account chapter gets it for free. The case is
`Implemented` rather than left to pass as "already matches", which is what the
harness insists on.

## 8. Decisions, with the alternative rejected

### 8.1 A route, not a branch in `WithKeycloakFallbacks`

**Rejected: parse the path in the wrapper** and answer there when nothing
matched. Two reasons, and the second is the one that decides it:

- the wrapper takes a mux and nothing else. It **has no store**, so it cannot
  resolve a realm, and every row of §1 needs one resolved;
- the wrapper's fallback only runs when **no route matched at all**, and §1.3 is
  a set of requests where a route *did* match the path. A wrong method on a
  known path under an unknown realm answers about the realm, and a branch in the
  wrapper reached only through the no-match path can never produce it. A
  method-less route catches both.

### 8.2 Two patterns, not one, and not three

**Rejected: `/realms/{realm}/{rest...}` alone.** Section 6.1's M2: it leaves an
implicit `ServeMux` redirect at `/realms/{realm}` that answers a 307 Keycloak
does not send, through a code path `WithKeycloakFallbacks` cannot see.

**Rejected: mirroring the protocol dispatcher's three patterns**
(`/realms/{realm}`, `/realms/{realm}/{resource}`,
`/realms/{realm}/{resource}/{rest...}`). The middle one is redundant here
because nothing in the handler reads a `{resource}` value - the protocol
dispatcher needs its middle pattern only because `protocolDispatch` reads
`r.PathValue("protocol")` and a `{rest...}` wildcard would not give it one. A
third pattern that changes no answer is a line a reader has to justify.

### 8.3 The catch-all lives in `internal/oidc`

**Rejected: a package of its own, or `internal/account` registering its own.**
The realm resource's 404 is answered by one handler for the whole tree, and the
handler it is closest to is `protocolDispatch`, one segment down, with the same
`resolveRealm` in front of it. Splitting it per package would put four copies of
one measured sentence in four files, which is the thing F184 was filed to stop.

`internal/account` **would** be the right owner of a *second*, narrower
dispatcher, because §3.3 shows its order is realm-gate-route rather than
realm-route. That is F209 and deliberately not this cut: it needs the account
gate to run for every unrouted path under `/account`, which is a behaviour
change to a chapter with eleven open cuts of its own (F194).

### 8.4 The realm-resource cases live in `http/fallback`

**Rejected: a chapter of their own**, the way the dispatch cut gave
`Protocol not found` an `oidc/protocol` chapter. That chapter exists because
`Protocol not found` is a **sentence of Keycloak's own**, produced by its
protocol map rather than by its router. This 404 is the router's generic body -
the same thirty bytes `http/fallback/method-not-allowed` already holds - so the
cells belong beside it. `http/fallback` doubling from six to twelve is the
honest shape of that.

### 8.5 The conformance probe now reads the route table

`TestNoReasonClaimsAServedEndpointIsUnserved` sent `TRACE` and separated
Keycloak's two fallback bodies to decide whether a path was routed. The catch-all
makes every path under a realm answer the wrong-method body, so **every path in
its table read as routed** - and the test said so itself, through the negative
control it carries for exactly this reason. It would otherwise have flagged every
non-`Implemented` case in the catalogue.

**Rejected: moving the negative control outside `/realms`.** That fixes the
symptom and leaves the probe unable to see anything, because every path it
actually asks about is under a realm.

**Rejected: probing with each route's own method.** It runs handlers, which the
test exists not to do, and the table holds paths served by four different verbs.

What replaces it asks the mux instead of the response: a path is served when
**some** method matches a pattern that carries a method. Every route the three
packages register carries one; the only method-less patterns in the server are
the two dispatchers. `newFixtureMux` is split out of `newFixture` for it, and
the test's two controls check the invariant rather than assuming it - M13, M14
and M15 are the three ways of getting it wrong and all three are killed.

### 8.6 One test is retargeted rather than deleted

`TestWrongMethodReturnsKeycloakShapedNotFound` sent `POST /realms/master`, which
now reaches the dispatcher and answers **the same thirty bytes** for a different
reason. Left alone it would have passed while testing nothing. It now builds a
mux of its own with a route outside `/realms`, which is `WithKeycloakFallbacks`'
real input, and asserts the five headers as well as the body - the half that
tells the wrong-method branch from the unmatched-path one.

That is a fact worth carrying forward on its own: **within `internal/oidc`'s
route table the wrong-method probe is now unreachable.** Every path under a
realm matches a method-less pattern. The branch is still live for
`internal/admin`'s routes, which this package cannot see. F212.

`TestUnknownPathReturnsKeycloakShapedNotFound` moved from
`/realms/master/nope` to `/nosuchpath` for the same reason, and the old path was
never an unmatched path on a live 26.7.1 at all.

## 9. For AGENTS.md, phrased as I would want it folded

Under **"Things that look like bugs and are not"**, a new bullet after the
`/realms/{realm}/protocol/{name}` one:

> - **Everything under `/realms/{realm}` that no route serves is the router's
>   generic `404 {"error":"HTTP 404 Not Found"}` with all five security
>   headers**, and an unknown realm is `Realm does not exist` with all five -
>   at any depth, on all seven verbs, and **whether or not the path is a route
>   hit with the wrong method**. That last clause is the sharp one:
>   `POST /realms/nosuchrealm/.well-known/openid-configuration` answers about
>   the realm, not about the method, so the realm is resolved **before the
>   method is dispatched** rather than merely first. `/realms` and `/realms/`
>   are the exception and they go the other way - both fall off the route table
>   entirely and answer the unmatched-path body with **none** of the five, which
>   is the only measured place in this server where a **shorter** path is less
>   reachable than a longer one. On the Admin API the same shape carries the
>   other spelling, `Realm not found.` with its full stop, behind the bearer
>   gate and behind each sub-resource locator - `/admin/realms/master/clients/{unknown}/nosuchsub`
>   is `Could not find client` - so that side is a chain rather than one
>   catch-all. `/admin/nosuchthing` is a **405 with none of the five**, which is
>   neither known unrouted body.
>
> - **`/realms/{realm}/account` runs its gate before it routes, and it is the
>   only family under a realm that does.** One path, one container, two probes
>   differing only in the `Authorization` header: with no token
>   `/realms/master/account/nosuchsub` is `401 {"error":"HTTP 401
>   Unauthorized"}` and with a valid one it is the generic 404 above. Everything
>   else under a realm - `login-actions`, `device`, `.well-known`,
>   `clients-registrations/default` - answers the 404 to a caller holding
>   nothing.

Under the security-header bullet, extending the "a path matching no route gets
none of them" exception:

> The exception is about the **route table**, not about the path's shape, and
> the realm tree is where that bites: `/realms/master/nosuchthing` sends all
> five because the realm resource's own locator resolved and the request is
> inside the filter chain, while `/realms` - two segments shorter - sends none
> because nothing resolved at all. A rule phrased as "an unknown path gets no
> headers" is wrong on the first and right on the second.

And a sentence for the "wrong method on a known path" bullet, which now has a
fifth producer of the `HTTP 404 Not Found` body:

> **There are five producers of that second body, not four.** The fifth is a
> path under a realm that resolves and that no route serves - which is the first
> producer that is neither a wrong method, a switched-off resource, nor a
> malformed parameter. It confirms rather than complicates the reading the
> fourth producer forced: the body does not mean "wrong method", it means "the
> router found nothing to run".

## 10. Follow-ups

### F209: the account gate runs before the account routing, and the realm catch-all does not

Measured 2026-09-09, one container, one path, two probes differing only in the
`Authorization` header:

```
GET /realms/master/account/nosuchsub                  401 {"error":"HTTP 401 Unauthorized"} 5 of 5
GET /realms/master/account/nosuchsub  + a user token   404 {"error":"HTTP 404 Not Found"}    5 of 5
```

So `/account`'s order is realm, gate, route, where every other family under
`/realms/{realm}` is realm, route. `realmResourceDispatch` answers the 404 to
both, so it is right on the second row and wrong on the first.

The fix is a second dispatcher registered by `internal/account` -
`/realms/{realm}/account` and `/realms/{realm}/account/{rest...}`, calling
`h.resolve` and then writing the 404 - which `ServeMux` gives precedence over
the wider one for the same reason the protocol dispatcher wins. It is small.
What makes it a cut rather than a line is that it changes what
`GET /realms/{realm}/account` answers for a caller **past** the gate, where
Keycloak serves the profile resource, and the account chapter has eleven open
cuts (F194) that should decide the order they land in.

Pinned by `account/dispatch/unknown-subpath-unauthenticated`, which is
`Recorded` and must not start matching until this is done deliberately.

### F210: the realm resource 404 is content-negotiated, and negotiation erases the realm

```
GET /realms/master/nosuchthing       Accept: application/json  404   30 bytes  {"error":"HTTP 404 Not Found"}
GET /realms/master/nosuchthing       Accept: text/html         404 3574 bytes  a "Page not found" theme page
GET /realms/nosuchrealm/nosuchthing  Accept: text/html         404 3574 bytes  byte-identical to the row above
```

The third row is the finding: the HTML branch does not distinguish a realm that
exists from one that does not, so `Accept` decides more than the media type.
Both pages carry all five security headers and `Content-Type:
text/html;charset=utf-8`.

Gloak parses no `Accept` here and answers the JSON branch always. Reproducing it
needs a media-type parser - whose only other consumer today is
`account/dispatch/accept-unparseable`, itself `Recorded` for the same reason -
and the login theme's error page, which the themes chapter does not enumerate.
Two blockers, neither this cut's.

### F211: the Admin API has the same shape, a different sentence, and a chain rather than a catch-all

```
GET /admin/realms/master/nosuchthing        + admin token 404 {"error":"HTTP 404 Not Found"}   5 of 5
GET /admin/realms/master/nosuchthing/deeper + admin token 404 {"error":"HTTP 404 Not Found"}   5 of 5
GET /admin/realms/nosuchrealm/nosuchthing   + admin token 404 {"error":"Realm not found."}     5 of 5
GET /admin/realms/master/clients/nosuchuuid/nosuchsub
                                            + admin token 404 {"error":"Could not find client"} 5 of 5
GET /admin/realms/master/nosuchthing          no token     401 {"error":"HTTP 401 Unauthorized"} 5 of 5
GET /admin/nosuchthing                        either       405 {"error":"HTTP 405 Method Not Allowed"} 0 of 5
```

Three things make it a separate cut rather than the same two patterns one prefix
over. The sentence is the Admin API's, with its full stop. The refusal sits
behind the bearer gate, so the catch-all would have to run `internal/admin`'s
authentication first. And the **client locator resolves before the 404**, so a
single `/admin/realms/{realm}/{rest...}` pattern is measurably wrong - it would
answer `HTTP 404 Not Found` where Keycloak answers `Could not find client`. How
many locators do that is unmeasured; the client is one, and users, groups,
roles, organizations and components each need the same probe.

`GET /admin/nosuchthing` is separate and unrecorded: a **405 with none of the
five**, which is neither of the two bodies an unrouted path is supposed to
produce and is the eighth body in the fallback family.

### F212: the wrong-method probe is unreachable through `internal/oidc`'s route table

`WithKeycloakFallbacks` distinguishes "no route matched" from "a route matched
the path but not the method" by running a throwaway probe and looking for an
`Allow` header. Since F184 every path under `/realms/{realm}` matches a
method-less pattern, so **nothing in `internal/oidc` can reach the second
branch**, and the one conformance case that used to -
`http/fallback/method-not-allowed` - now goes through the dispatcher and answers
the same bytes for a different reason.

The branch is still live for `internal/admin`'s routes. Its only in-package
guard is now `TestWrongMethodReturnsKeycloakShapedNotFound`, which builds a mux
of its own. What is missing is a conformance case on an admin path -
`PATCH /admin/realms/master/keys`, say - so the corpus covers the branch rather
than a unit test alone. It is one case and a `make record`.

### F213: two sentences the catch-all now answers plausibly and wrongly

`router.go` already records that the three unregistered client-registration
providers fall through, and that an unknown identity provider is not served.
Both are now answered by `realmResourceDispatch` with a body that **looks
considered**, which is worse than the unmatched-path body it replaces in exactly
one way: it no longer reads as "Gloak has no idea about this path".

```
GET /realms/master/clients-registrations/nosuchprovider 404 {"error":"Client registration provider not found"}
GET /realms/master/clients-registrations                405 {"error":"HTTP 405 Method Not Allowed"}
GET /realms/master/broker/nosuchalias/endpoint          404 {"error":"Identity Provider [nosuchalias] not found."}
```

The third is a spelling of not-found nothing in this repository has, and it is
on the **protocol** side where AGENTS.md's list of thirty-six is entirely the
Admin API's. It interpolates the caller's own alias, so by that list's own rule
it is a sentence template rather than a spelling - the second one after
`Requested audience not available: <name>`, and the first outside the Admin API.
Recording it needs the broker chapter, which is not enumerated.

### F214: the realm root is a real 405 and this cut measured three more of them

For F31's tally, measured 2026-09-09 and changed on the strength of none of
them:

```
POST    /realms/master                    405 {"error":"HTTP 405 Method Not Allowed"} 5 of 5
PUT     /realms/master                    405 the same 39 bytes
DELETE  /realms/master                    405
OPTIONS /realms/master                    200 no body, no Content-Type, 4 of 5
GET     /realms/master/clients-registrations 405 5 of 5
GET     /admin/nosuchthing                405 0 of 5
```

The realm root is the sharpest: `GET /realms/master` is a served 200 and the
other three verbs are a real 405, on the one path in this project that every
client hits. Gloak answers 404 to all of them, before and after this cut. The
`OPTIONS` 200 with four of the five is the header rule's `OPTIONS` cell, which
AGENTS.md records as measured on four endpoints with no golden; this is a fifth.
