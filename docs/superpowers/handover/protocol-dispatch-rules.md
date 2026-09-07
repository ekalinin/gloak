# The protocol surface's two dispatch rules

F177 and F178 were filed as one cut and one name, because both are general rules
Gloak got wrong on **every** protocol path it served, and both were found by the
SAML sweep without being SAML's. F179 rides along: it is small, independent, and
it was a live hazard - every `make record` was a coin flip on one committed
golden.

All three are closed. So is F11, which had been waiting since 2026-08-20 for
exactly the measurement F177's first question asks for.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1
start-dev` on 2026-09-07. Where a path is deliberately malformed the request was
sent with `curl --path-as-is` or written onto a socket by hand, because **curl
normalises a path before sending it** and a probe written without that flag
measures curl rather than Keycloak - which is AGENTS.md's rule about probing an
absence, met on the request side.

## 1. F177's two questions

The follow-up named two things that had to be measured before anything was
built. Both have answers, and both changed the shape of the fix.

### 1.1 One trailing slash, and only one

```
GET /realms/master/protocol/openid-connect/certs      200  2917 bytes  application/json
GET /realms/master/protocol/openid-connect/certs/     200  2917 bytes  application/json
GET /realms/master/protocol/openid-connect/certs//    400    82 bytes  application/json; charset=UTF-8
GET /realms/master/protocol/openid-connect/certs///   400    82 bytes  the same 82 bytes
GET /realms/master/protocol/openid-connect/certs////  400    82 bytes  the same 82 bytes
```

The same shape on the descriptor, on `/auth`, on the realm root and on
discovery: one slash is the endpoint's own answer, two or more is

```
400 {"error":"missingNormalization","error_description":"Request path not normalized"}
```

**with none of the five security headers, no `Cache-Control`, and no `Date`.**

So the question "one or many" has an answer sharper than either option: **one is
stripped, and many never reach a route at all.** The 400 is a body nobody in
this repository had recorded, and three things about it are what a reader gets
wrong:

- it is a **400**, not a 404;
- its `Content-Type` is `application/json; charset=UTF-8` **with a space** after
  the semicolon. That is a **third** spelling in this server: the Admin API
  writes `application/json;charset=UTF-8` without one and the protocol side
  writes a bare `application/json`. It is why `httpx.WriteNotNormalized` does not
  go through `WriteJSON` or `WriteJSONCharset`;
- it carries **none** of the five security headers, which is that rule's "never
  reached the filter chain" exception met on a request that is *refused* rather
  than merely unrouted.

The check is on the **decoded** path and it runs **before** the route table:

```
GET //realms/master                    the same 82 bytes
GET /realms//master                    the same 82 bytes
GET /realms/master/%2e/protocol        the same 82 bytes
GET /realms/master/%2e%2e/master       the same 82 bytes
GET /realms/master/protocol/openid-connect/certs/.    the same 82 bytes
GET /realms/master/protocol/openid-connect/certs/..   the same 82 bytes
GET /nosuchthing//                     the same 82 bytes
```

The last one is the one that settles the ordering: a path no route could ever
match answers this rather than the unmatched-path 404, so normalisation is ahead
of routing. `%2e` firing is what says the check reads the decoded form, which is
what `r.URL.Path` already holds in Go.

**One cell is not reproduced.** The request target `//` on its own answers
`400` with **no body and no `Content-Type` at all** - a different producer, the
HTTP layer refusing an authority-form request line rather than the application
refusing a path. Gloak answers `missingNormalization` there. Filed as F182.

### 1.2 Yes, the rule reaches the Admin API

```
GET /admin/realms/                                   200  the realm listing
GET /admin/realms/master/                            200  the realm representation
GET /admin/realms/master/clients/                    200  the client listing
GET /admin/realms/master/roles/                      200  the role listing
GET /admin/realms/master/groups/count/               200  {"count":0}
GET /admin/realms/master/users/count/                200  1
GET /admin/serverinfo/                               200  300349 bytes
GET /admin/realms/master/nosuchthing/                404  {"error":"HTTP 404 Not Found"}
```

And it reaches the two fallback shapes too, which is what makes it a **strip**
rather than a route:

```
GET  /nosuchpath/                                          404  Unable to find matching…  0 of 5 headers
GET  /nosuchpath/deeper                                    404  Unable to find matching…  0 of 5 headers
POST /realms/master/.well-known/openid-configuration/       404  HTTP 404 Not Found        5 of 5 headers
```

Nothing downstream of the strip has to know the slash was there. That is what
decided the fix: **one strip in `WithKeycloakFallbacks`, ahead of the mux**,
rather than a second `ServeMux` pattern per endpoint. See section 3.1 for the
alternative and why it is worse than it looks.

## 2. F178: `Protocol not found`, and what the dispatcher refuses to do

### 2.1 The measurement

Every row below carries **all five** security headers and **no**
`Cache-Control`, `application/json`:

```
/realms/nosuchrealm/protocol                       404 {"error":"Realm does not exist"}
/realms/nosuchrealm/protocol/nosuchproto           404 {"error":"Realm does not exist"}
/realms/nosuchrealm/protocol/nosuchproto/descriptor 404 {"error":"Realm does not exist"}
/realms/nosuchrealm/protocol/openid-connect/certs  404 {"error":"Realm does not exist"}
/realms/master/protocol                            404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/                           404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/openid-connect             404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/openid-connect/nosuchsub   404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/openid-connect/nosuchsub/deeper 404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/openid-connect/certs/extra 404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/openid-connect/auth/nosuch 404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/saml/nosuchsubpath         404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/saml/descriptor/extra      404 {"error":"HTTP 404 Not Found"}
/realms/master/protocol/nosuchproto                404 {"error":"Protocol not found"}
/realms/master/protocol/nosuchproto/descriptor     404 {"error":"Protocol not found"}
/realms/master/protocol/nosuchproto/certs          404 {"error":"Protocol not found"}
/realms/master/protocol/x/a/b/c/d                  404 {"error":"Protocol not found"}
/realms/master/protocol/saml-ecp                   404 {"error":"Protocol not found"}
/realms/master/protocol/docker-v2                  404 {"error":"Protocol not found"}
/realms/master/protocol/docker-v2/auth             404 {"error":"Protocol not found"}
/realms/master/protocol/oidc                       404 {"error":"Protocol not found"}
/realms/master/protocol/openid_connect             404 {"error":"Protocol not found"}
/realms/master/protocol/SAML                       404 {"error":"Protocol not found"}
/realms/master/protocol/OPENID-CONNECT             404 {"error":"Protocol not found"}
```

Three findings in that table, and each of them is one probe away from an
implementation that looks right:

1. **The realm is resolved first.** An unknown realm answers about the realm
   even when the protocol is unknown too. A dispatcher that reads its map first
   is right on every request that gets *one* thing wrong - which is every probe
   a reader writes - and wrong on every request that gets both wrong.
2. **A registered protocol stops the dispatch**, at any depth. So the map is
   load-bearing: a catch-all answering one sentence for everything under
   `/protocol/` would be wrong on every mistyped OIDC path there is.
3. **The bare `/protocol` segment is not a protocol.** It answers
   `HTTP 404 Not Found` where a one-character name answers `Protocol not found`,
   so the empty name is a third answer rather than the unregistered case with
   nothing in it.

**The comparison is case-sensitive** and the registered set on a default
`start-dev` is exactly two names. `docker-v2` is a protocol Keycloak has and
whose feature is off, which is `CLIENT_TYPES`' situation: the constant is the
contract, not a stub.

**`Protocol not found` answers every verb.** GET, POST, PUT, DELETE, OPTIONS and
HEAD all give the identical 404 with all five headers - no 405, no `Allow`, no
`OPTIONS` 200. That is the one route in `internal/oidc` that really does answer
every method the same way, and it is why the three patterns are registered with
no method.

### 2.2 What the dispatcher does

`internal/oidc/router.go`, three patterns and one handler:

```go
mux.HandleFunc("/realms/{realm}/protocol", h.protocolDispatch)
mux.HandleFunc("/realms/{realm}/protocol/{protocol}", h.protocolDispatch)
mux.HandleFunc("/realms/{realm}/protocol/{protocol}/{rest...}", h.protocolDispatch)
```

```go
realm := h.resolveRealm(w, r)          // the realm first, always
if realm == nil { return }
protocol := r.PathValue("protocol")
if protocol == "" || registeredProtocols[protocol] {
    httpx.WriteMessageError(w, http.StatusNotFound, "HTTP 404 Not Found")
    return
}
httpx.WriteMessageError(w, http.StatusNotFound, "Protocol not found")
```

`registeredProtocols` is `{openid-connect, saml}`, and it is **a statement about
Keycloak rather than about Gloak**: `saml` is in it although Gloak serves one
SAML endpoint, because what decides the answer is whether Keycloak's protocol
map has the key, not whether anything is mounted under it.

### 2.3 What it refuses to do

- **It does not answer `Protocol not found` under a registered protocol.**
  Measured on eight paths under `openid-connect` and `saml`, at three depths.
- **It does not answer `Protocol not found` for the bare `/protocol` segment.**
- **It does not fold the protocol name's case.** `SAML` and `OPENID-CONNECT` are
  both `Protocol not found` on a live 26.7.1, so a fold would send the wrong body
  for two spellings a caller really sends.
- **It does not know about `docker-v2`.** Measured `Protocol not found` on a
  default container, and Gloak has no feature-flag model to make it conditional.
  Filed as F187.
- **It does not answer a 405 or an `OPTIONS` 200** on any of these paths. All six
  verbs were measured and all six give the same 404, so there was nothing to
  refuse here - but the neighbouring real routes still answer F31's standing
  divergence and this cut changes none of it.
- **It does not reach outside `/realms/{realm}/protocol`.** The same shape is
  measurably true one level up - `/realms/master/nosuchthing` answers
  `HTTP 404 Not Found` with all five headers where Gloak answers the
  unmatched-path body with none - and that is deliberately not this cut's. Filed
  as F184.

### 2.4 The composition F178 warned about

> The two rules interact: a catch-all registered under
> `/realms/{realm}/protocol/` changes what a trailing slash matches.

They compose in one direction only, and it is Keycloak's: **normalise, then
route.** The strip runs in `WithKeycloakFallbacks` before `mux.Handler` is asked
anything, so `/protocol/x/` arrives at the mux as `/protocol/x` and
`/protocol/openid-connect/certs/` arrives as `/protocol/openid-connect/certs`.
That is why the `{rest...}` pattern needs no trailing-slash sibling and why the
bare `/realms/{realm}/protocol` pattern also covers `/realms/{realm}/protocol/`.

`TestTheDispatcherDoesNotSwallowAServedRoute` asks for every route this package
serves under `/protocol`, bare and slashed, and requires none of them to answer
any of the three 404 sentences. A dispatcher registered too broadly, or a strip
running after the mux instead of before it, fails there.

**F178 said Go's `ServeMux` lets a specific pattern beat a catch-all, and told
this cut to verify it rather than trust it, because F153 is in this repository
precisely because a `ServeMux` assumption was wrong once.** It is true here, and
it was checked by running the routes rather than by reading the documentation:
`GET /realms/{realm}/protocol/openid-connect/certs` matches a strict subset of
`/realms/{realm}/protocol/{protocol}/{rest...}`, so it is more specific, so it
wins, and no registration panics. What is *not* the same as F153's case is that
none of the three patterns overlaps another, so the tie-break never has to be
made: the bare segment, one segment and two-or-more segments are disjoint sets
of paths.

## 3. Decisions, with the alternative rejected

### 3.1 The strip goes in the wrapper, not in the route table

**Rejected: a `ServeMux` subtree pattern per endpoint**, or a
`/realms/{realm}/protocol/` subtree that swallows the slash. Two reasons, and
the second is the one that would have bitten:

- the rule is measured **server-wide**, including the Admin API and both
  fallback shapes (section 1.2). A per-route fix would be a fix aimed at one
  instance of a general rule, which F177 names as the thing to avoid;
- Go's `ServeMux` **redirects the bare path to a registered subtree**: with
  `/realms/{realm}/protocol/` registered, `GET /realms/master/protocol` gets a
  301 that Keycloak does not send, and `WithKeycloakFallbacks` would hand it
  straight to `mux.ServeHTTP` because `mux.Handler` reports a non-empty pattern
  for the redirect handler. That is F11's failure mode reappearing through the
  fix for F177.

### 3.2 The `missingNormalization` 400 is served rather than left to fall through

**Rejected: strip one slash and let `//` reach the unmatched-path 404.** That
would have been a smaller diff and it would have left F11 open with the
measurement now in hand:

> Once measured, the fix is presumably to have `withKeycloakFallbacks` check
> `r.URL.Path` against its cleaned form itself, ahead of the `mux.Handler`
> probe, rather than trusting "non-empty pattern" to mean "real route".

That is exactly what the guard does. Without it, `//realms/master` and
`/realms/master/../master` still reach net/http's own 307 with an HTML body - a
response `internal/httpx` never produces - so the trailing-slash fix would have
sat on top of a live divergence in the same three lines. It also makes the "one
slash and only one" boundary a **behaviour** rather than an implementation
detail: `TestASecondTrailingSlashIsNotStripped` has something to assert.

### 3.3 The dispatcher's protocol set is a constant

**Rejected: deriving it from what Gloak serves.** The answer follows Keycloak's
protocol map. Deriving it would make Gloak answer `Protocol not found` for
`saml` the day the SAML endpoints are removed from the router, and
`HTTP 404 Not Found` for `docker-v2` the day somebody adds a docker handler -
both of which are the wrong body for the condition.

### 3.4 F179: a new mask, not `Volatile` and not `Pending`

Section 4 is the measurement. Three options existed and F179 names all three.

- **`Volatile` over the whole `error` value** would have stopped the golden
  moving and given up the sentence with it. That is not a tidy loss: F171 records
  that the refusal lists **BCFKS** although Gloak serves no such keystore, and
  this golden is the only thing in the repository asserting that name appears at
  all. A `Volatile` would have retired that assertion silently, which is exactly
  what AGENTS.md's mask bullet is about.
- **`Pending`** gives up the case, its headers and its status as well.
- **Computing the order** is refuted by section 4.

So: `Case.UnorderedBracketed`, which sorts the items inside the one `[...]` run
of a string and leaves every byte outside the brackets compared. The sentence,
the three names, the status, the media type and the header set all stay
asserted; only the order goes.

**`UnorderedWords` cannot do this job and the reason is worth keeping.** The
brackets attach to whichever item happens to be first and last, so sorting the
whole string's words leaves the two draws with *different word multisets* -
`[PKCS12,` against `[BCFKS,` - and they still compare unequal.
`TestSortUnorderedBracketedSeparatesTheSentenceFromTheList` runs both masks over
both draws and asserts that, so the claim is checked rather than argued.

**It has exactly one consumer, and that is a measurement rather than an
assumption**: grepping all 900-odd committed goldens for a bracketed,
comma-separated run inside a string value returns that one file.
`VolatileXMLText` was built for one consumer on 2026-09-07 too, so this is the
house precedent rather than a new bargain - and unlike F176's refused frame,
this one's consumer exists today and fails at random without it.

## 4. F179: what varies, measured

The brief supplied a hypothesis and asked for it to be tested rather than
believed:

> Java's `String.hashCode` is deterministic, so a `HashSet` of three fixed
> strings would iterate identically on every JVM run. If that holds, the
> variation cannot be a plain `HashSet` of literals.

It holds, and the variation is not a `HashSet` of literals.

### 4.1 One container, one image, one database, seven JVM starts

`docker restart` on a single container, three requests per start:

```
start       order                     three requests
initial     [PKCS12, BCFKS, JKS]      identical
restart 1   [PKCS12, BCFKS, JKS]      identical
restart 2   [PKCS12, BCFKS, JKS]      identical
restart 3   [JKS, BCFKS, PKCS12]      identical
restart 4   [PKCS12, JKS, BCFKS]      identical
restart 5   [PKCS12, JKS, BCFKS]      identical
restart 6   [PKCS12, JKS, BCFKS]      identical
```

Nothing changed between those seven but the JVM. **Stable within a run,
redrawn across runs.** Three distinct orders in seven starts here, and with the
project's three earlier recordings that is **four of the six permutations**:

```
2026-09-05  [BCFKS, PKCS12, JKS]   reported as wrong
2026-09-06  [PKCS12, JKS, BCFKS]   recorded as a correction, and committed
2026-09-07  [BCFKS, PKCS12, JKS]   the SAML cut, reverted by hand
2026-09-07  [PKCS12, BCFKS, JKS]   this cut, first draw
2026-09-07  [JKS, BCFKS, PKCS12]   this cut, restart 3
```

**The runs of repeats are the interesting part.** Three consecutive starts gave
one order and the next three gave another. That is why the number looked stable
for a day at a time and why the 09-06 recording was written up as a correction:
a value that changes on some restarts and not others is the shape that defeats
"measure it twice". AGENTS.md already records the obverse - "two recordings
agreeing is never evidence of stability" - and this is the same rule from the
other side, which is what F179 asked to have written down.

### 4.2 The decisive test: neutralise the identity hash

`JAVA_OPTS_APPEND="-XX:+UnlockExperimentalVMOptions -XX:hashCode=2"` makes
HotSpot's `Object.hashCode()` a constant. Four fresh containers, three requests
each:

```
hashCode=2, start 1..4    [JKS, PKCS12, BCFKS]   all twelve requests identical
```

**The order stops moving.** So the collection is keyed on values whose
`hashCode()` is `Object.hashCode()` - the JVM's identity hash, drawn per object
per run - and not on strings. That is consistent with a `HashSet` of the
`KeystoreFormat` **enum constants**: `Enum` does not override `hashCode`, so the
identity hash is what buckets them. With every element hashing to one bucket
they chain in insertion order, and `[JKS, PKCS12, BCFKS]` is presumably the
order the set is built in; nothing measured here confirms which order that is,
only that the hash is the variable.

### 4.3 A second image

`quay.io/keycloak/keycloak:26.7.2`, default flags, four fresh containers:

```
start 1   [JKS, BCFKS, PKCS12]
start 2   [PKCS12, JKS, BCFKS]
start 3   [PKCS12, JKS, BCFKS]
start 4   [PKCS12, JKS, BCFKS]
```

Same behaviour, so it is not a 26.7.1 defect and it will not be fixed by moving
the pin.

### 4.4 `internal/javamap` does not apply, and the check is arithmetic

The brief asked whether `javamap` applies rather than assuming either way. It
does not, and the argument does not need a run: `javamap.KeyOrder` and
`SizedKeyOrder` are **pure functions of a key set**. The key set here is
`{PKCS12, JKS, BCFKS}` on every single draw. A pure function of a constant is a
constant, and the observed value takes four values, so no function of that shape
can produce it. `javamap` models `String.hashCode`; the variable here is
`Object.hashCode`, which no library can model because the JVM redraws it.

**This is the first value in this project measured to be undecidable in
principle**, as against the two AGENTS.md already records as undecidable *from
what is on the wire* - a realm's colliding `attributes` and the two colliding
pairs in the 21 admin role names. Those chain in an insertion order nothing
observable reveals; this one has no fixed answer to reveal.

## 5. The mutation pass

Twenty-five mutations, run by a harness that reads `go test`'s exit code before
anything else, refuses a mutation whose target does not appear exactly once
(an empty or ambiguous diff is not a mutation), refuses one that fails to build,
refuses one whose `-run` pattern selected no test, and re-hashes the file after
reverting.

**First round: 23 killed, 2 survived. Second round: 25 killed, 0 survived.**
The two survivors are the finding and they are the same finding twice.

```
M1   stop refusing a doubled slash                       KILLED
M2   stop refusing a dot segment                         KILLED
M3   match a dot anywhere in a segment, not the whole    KILLED
M4   drop the space from the Content-Type parameter      KILLED
M5   send the five security headers with the refusal     KILLED
M6   stop stripping the trailing slash                   KILLED
M7   trim the leading slash instead of the trailing one  KILLED
M7b  strip the slash before checking normalisation       KILLED
M8   strip the root path to nothing                      SURVIVED, then KILLED
M9   leave RawPath untrimmed                             SURVIVED, then KILLED
M10  forget that saml is registered                      KILLED
M11  forget that openid-connect is registered            KILLED
M12  register docker-v2                                  KILLED
M13  fold the protocol name's case                       KILLED
M14  treat the bare /protocol segment as unregistered    KILLED
M15  read the protocol map before resolving the realm    KILLED
M16  swap the two sentences                              KILLED
M17  drop the deep-path pattern                          KILLED
M18  drop the bare-segment pattern                       KILLED
M19  drop the single-segment pattern                     KILLED
M20  stop sorting the bracketed items                    KILLED
M21  split on a bare comma, not Java's ", "              KILLED
M22  accept a string carrying two bracketed lists        KILLED
M23  accept a value that is not a string                 KILLED
M24  stop running the bracket pass at all                KILLED
```

### 5.1 The two survivors, and what they have in common

Both tests asserted **the status and the body**, and neither mutation moved
either. That is the first of the two failure shapes AGENTS.md names - a set of
assertions an incorrect implementation satisfies entirely - and it arrived twice
in one file from writing the assertion a reader writes first.

**M8, the root-path guard, was an *equivalent* mutation against the real route
table.** Gloak serves nothing at `/`, so removing `len(p) > 1` turns `/` into
the empty path, `ServeMux` matches neither spelling, and both answer the same
unmatched-path 404. There is no input that separates them. The test now wraps a
mux of its own that *does* serve the root - `WithKeycloakFallbacks` takes any
mux, so that is the wrapper's real input rather than a stand-in - and the guard
is pinned against the day Gloak answers `/` the way Keycloak does, which is
F183.

**M9, the `RawPath` trim, moves nothing a status or a body can see.** `url.URL`
carries the path twice, decoded in `Path` and raw in `RawPath`, and when the two
disagree `EscapedPath` quietly discards the raw form and re-escapes the decoded
one. So an untrimmed `RawPath` is harmless *today* and leaves the two fields
inconsistent for whoever next reads them. The test asserts `EscapedPath` through
a handler instead, which is the only observable the mutation touches.

Both are worth reporting rather than hiding because the general lesson is the
same one: **on a routing change, the assertion that catches a mutation is
usually not the response's status or body.** It is which handler ran, or what
the handler was handed.

## 6. What moved on the meter

`make conformance`, before and after, with the base taken from the merge base
(`main` at `8806923`) rather than computed:

```
                       base            head
http/fallback           2 of  2         6 of  6
oidc/protocol           -               4 of  4     (new chapter)
saml/descriptor         2 of  4         3 of  4
saml/endpoint           0 of  9         2 of  9
total                 538 of 572      549 of 580
```

Eleven behaviours served where none was served before, on eight new cases and
three promotions. **The parity total does not fall.**

The three promotions are `Recorded` cases the dispatcher made pass, so they were
promoted to `Implemented` rather than left to fail as "already matches":
`saml/descriptor/unknown-protocol`, `saml/endpoint/unknown-realm` and
`saml/endpoint/unknown-subpath`. Five other SAML `Reason` strings said "Gloak has
no route here", which stopped being true the moment the dispatcher landed; they
now say "Gloak serves nothing here", which is what was meant and is still true.

**`make record` moved exactly one committed golden**, and it is F179's:

```
- Supported keystore formats: [PKCS12, JKS, BCFKS]
+ Supported keystore formats: [BCFKS, JKS, PKCS12]
```

That is the sorted form, which is what the mask produces from any draw, so the
file will not move again. **No other golden moved**, which answers the brief's
worry directly: a dispatcher under `/realms/{realm}/protocol/` changes what none
of the existing cases answers.

## 7. For AGENTS.md, phrased as I would want it folded

Under **"Things that look like bugs and are not"**:

> - **A trailing slash is stripped, and exactly one of them.**
>   `/realms/{realm}/protocol/openid-connect/certs/` is the endpoint's own 200,
>   `/admin/serverinfo/` is `serverinfo`'s, `/nosuchpath/` is the unmatched-path
>   404 and `POST /realms/{realm}/.well-known/openid-configuration/` is the
>   wrong-method one. It is not a protocol rule and not a JAX-RS rule about
>   resources: it runs ahead of the route table, across the whole server, and
>   both fallback shapes obey it. **Two slashes are not a second strip.** A
>   doubled slash, a `.` segment or a `..` segment - in the **decoded** path, so
>   `%2e` counts - is `400
>   {"error":"missingNormalization","error_description":"Request path not
>   normalized"}` with **none** of the five security headers and a
>   `Content-Type` of `application/json; charset=UTF-8`, **with a space**: a
>   third spelling of that parameter, after the Admin API's without one and the
>   protocol side's bare `application/json`. Measured with raw sockets, because
>   **curl normalises a path before sending it** and a probe of a malformed path
>   written without `--path-as-is` measures curl. It is also the **seventh** body
>   in the fallback family this file counts as six, and the first that is not a
>   404, a 405 or a 406: it is the RFC 6749 two-key shape on a status the family
>   has not had.
>
> - **`/realms/{realm}/protocol/{name}` is decided by Keycloak's protocol map,
>   not by its route table.** An unregistered name is `404 {"error":"Protocol not
>   found"}` with all five security headers, at any depth and on **all six
>   verbs** - the one route in this project that answers every method
>   identically. Three cells around it are each one probe away from an
>   implementation that looks right: the **realm is resolved first**, so an
>   unknown realm answers `Realm does not exist` even when the protocol is
>   unknown too; a **registered** protocol stops the dispatch and answers
>   `HTTP 404 Not Found` instead, at any depth; and the **bare `/protocol`
>   segment is not a protocol name** and answers `HTTP 404 Not Found` as well.
>   The registered set is exactly `openid-connect` and `saml`, compared
>   **case-sensitively** - `SAML` is `Protocol not found` - and `docker-v2` is a
>   protocol Keycloak has with its feature off, which is `CLIENT_TYPES`'
>   situation: the constant is the contract.

Replacing the second half of the certificate bullet's "the list's order is not a
contract and the golden that holds it is a coin flip":

> **The list's order is redrawn on every JVM start.** One container restarted
> seven times against one database gave three orders, each stable across three
> requests inside its own run; with the project's three earlier recordings that
> is four of the six permutations, and 26.7.2 behaves the same way. Under
> `-XX:hashCode=2`, which makes HotSpot's identity hash a constant, it stops
> moving over four starts - so the set is keyed on values whose `hashCode` is
> `Object.hashCode()` rather than on strings, which is what a `HashSet` of enum
> constants gives. **`internal/javamap` cannot reach it**, and the argument is
> arithmetic rather than a run: both its functions are pure functions of a key
> set, the key set here never changes, and the value takes four values.
> `Case.UnorderedBracketed` gives up the order and keeps the sentence and the
> membership - including BCFKS, which F171 records as listed although Gloak
> serves no such keystore and which a `Volatile` over the whole message would
> have stopped asserting.
> **The runs of repeats are what made this hard.** Three consecutive starts gave
> one order and the next three another, which is why the number looked stable
> for a day at a time and why the 09-06 recording was written up as a correction
> it was not. "Two recordings agreeing is never evidence of stability" is
> already here; its other side is that **a recording that disagrees with a
> golden is not evidence that the golden was wrong**, and telling the two apart
> needs a third draw.

Under **"A mask is a path"**, one sentence:

> **A fifth kind of mask exists and it reaches inside a string.**
> `Case.UnorderedBracketed` sorts the items of a Java collection rendered by
> `Collection.toString()` inside a JSON string, and leaves every byte outside
> the brackets compared. It has one consumer, and that is grepped rather than
> assumed: one golden in the tree carries such a run. `UnorderedWords` cannot
> substitute, because the brackets attach to whichever item is first and last,
> so two draws sort to different word multisets.

## 8. Follow-ups

### F182: the request target `//` is a 400 with no body, and Gloak answers a body

`GET //` on a live 26.7.1 is `400` with `content-length: 0` and **no
`Content-Type` at all**, where `GET ///` and `GET //a` are the ordinary
`missingNormalization` 82 bytes. Read off a socket on 2026-09-07, because curl
rewrites the target.

It is a different producer: `//` alone is an authority-form request target and
the HTTP layer refuses the request line before the application sees a path.
Gloak's guard answers `missingNormalization`. One cell, one path, and
reproducing it means a special case for a literal path in
`WithKeycloakFallbacks` - which is why it is filed rather than done. What is
**not** measured is whether Go's own `http.Server` even delivers that target to a
handler, or rejects it first; `httptest.NewRequest` accepts it, and a real
socket has not been tried.

### F183: `GET /` is a 302 to `/admin/` with four of the five security headers

```
GET /   302  Location: http://localhost:18091/admin/
        Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options,
        X-Robots-Tag       - and no X-Frame-Options
        content-length: 0
```

Gloak answers the unmatched-path 404. A sixth media-type-free response missing
`X-Frame-Options` for that rule's tally, and the first **redirect** in this
project measured missing it outside `/auth`'s.

It matters beyond one path: `TestTheRootPathIsNotStrippedToNothing` currently
has to build its own mux, because against the real route table the strip's
`len(p) > 1` guard is an equivalent mutation. Serving `/` makes that guard carry
a real request.

### F184: the realm resource's own 404 is the unmatched-path body, everywhere but `/protocol`

```
GET /realms/master/nosuchthing          404 {"error":"HTTP 404 Not Found"}  5 of 5
GET /realms/master/nosuchthing/deeper   404 {"error":"HTTP 404 Not Found"}  5 of 5
GET /realms/nosuchrealm/nosuchthing     404 {"error":"Realm does not exist"} 5 of 5
GET /realms                             404 Unable to find matching…        0 of 5
GET /realms/                            404 Unable to find matching…        0 of 5
```

So **everything under `/realms/{realm}/` that no route serves reaches the filter
chain**, resolves the realm and answers the generic 404 with all five headers,
while `/realms` itself falls off the route table. Gloak answers the header-less
unmatched-path body for all of the first three.

This cut fixed that shape for `/protocol` and deliberately went no further: the
same catch-all one level up would need the realm resolved for every unmatched
path in the tree, and would swallow `/realms/{realm}/account`, `/device` and the
login-action paths on their way. It is the third family of this shape after
`/organizations` (F153's note) and the group tree, and the pattern is now clear
enough to be worth doing once rather than three more times.

### F185: nothing counts the spellings of `application/json`

There are now **three**: the protocol side's bare `application/json`, the Admin
API's `application/json;charset=UTF-8`, and Quarkus's
`application/json; charset=UTF-8` with a space. AGENTS.md's charset bullet has
been wrong six times, twice refuted by the golden it cited, and it is prose. The
tally it needs is the one
`TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb` already does for one
family: compute the spellings over the committed goldens and fail when a fourth
appears undeclared.

### F186: `UnorderedBracketed` has one refusal it cannot check

The mask requires exactly one `[...]` run and splits it on `", "`. A run whose
items are joined some other way - a Java `Arrays.toString` of an empty-element
array, or a collection whose elements contain `", "` - is split wrongly and
sorted anyway, with no error. The two shapes it does refuse (no run, two runs)
are the ones a wrong path produces; this one is a wrong *separator*, and the
only defence today is that the single consumer's separator is measured.

It becomes worth building when a second consumer arrives. Until then this entry
is what stops the next cut assuming the mask is safe on any bracketed string.

### F187: `registeredProtocols` is a constant and the docker feature has no model

`docker-v2` is `Protocol not found` on a default container and would be a real
protocol on one started with `--features=docker`. Gloak has no feature-flag
model at all - `CLIENT_TYPES`, `CLIENT_SECRET_ROTATION` and `ORGANIZATION` are
each handled as a constant at their own call site - so this is the fourth
feature-shaped constant rather than a new problem. Filing it names the place a
feature model would have to reach if one is ever built.

### F188: nothing sweeps the goldens for a second undecidable Java collection

F179 turned out to be a `HashSet` of values hashed by **identity**, which no
amount of `javamap` can compute. The sweep that would find the next one is:
every golden carrying a `[a, b, c]` run inside a string, or a JSON array whose
order comes from a Java `Set`, checked against a container restarted rather than
against a second container.

Today the first half of that returns exactly one file, which is how this cut
knows the mask has one consumer. The second half has never been run: the project
has one recorded instance of "restart the same container" as a technique - F23's
theme-resource investigation - and it found the previous claim wrong too.

### F189: no case sends a second verb to the protocol dispatcher

`Protocol not found` is byte-identical on GET, POST, PUT, DELETE, OPTIONS and
HEAD, measured. Only the GET has a golden, because a golden per verb would
report one behaviour six times in a chapter whose denominator is its case count.
`internal/oidc`'s `TestProtocolNotFoundAnswersEveryVerb` carries the other five,
which is a package test comparing against what this project believes rather than
against a recording - AGENTS.md's `TestKeystoreDownloadHeaders` bargain, met a
second time.

What would close it properly is a way for the catalogue to say "the same
behaviour, another verb" the way `Case.SecondRealm` says "another realm": kept
out of the denominator, with the golden still recorded and compared. That is a
harness change with one consumer today and F180's `HEAD` problem sitting behind
it, so it is filed rather than built.
