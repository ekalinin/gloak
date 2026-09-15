# The management port enumerated, and the harness taught a second socket

The `management` chapter had no denominator. Its declared reason was *"the
management port's health and metrics endpoints are not in the Admin API
document"*, and that sentence had been true since the parity meter was built.

This cut removes it. The surface is enumerated against a live Keycloak 26.7.1 -
**ten route shapes, 77 verb cells, 16 catalogued behaviours** - and **nothing in
it is served**, which is a statement about the verifier and not a shrug: the
verifier has one handler and one base URL, so it cannot ask this port a
question at all. Section 2.2 is that argument and section 3 is the refusal it
became.

The first question was not what the port serves. It was whether it exists, and
on a default container it does not: **a default `start-dev` has no listener on
9000 at all**. F169 is the precedent for what happens when that is not checked -
CIBA's 503 was read as a missing feature for weeks and was an artefact of a
startup option - and section 2.1 is why this chapter enumerates the enabled
surface rather than the default one.

## 1. Measurements

Every value below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on
2026-09-15, on containers started clean for this session. Where a header set is
claimed present or absent, the bytes were read off a socket rather than through
`curl`, following AGENTS.md's rule that a probe of an absence measures the
probe. Where a path is deliberately malformed it was sent with
`curl --path-as-is`, because curl normalises a path before sending it.

Five containers were used for the measurements and all five were fresh. Their
configurations are in 1.2, and they are the variable: the same image, four
option combinations, and one duplicate of the fourth to answer a question about
stability across container starts.

### 1.1 A default container answers nothing, because it is not listening

```
docker run -d -p 18091:8080 -p 18092:9000 ... quay.io/keycloak/keycloak:26.7.1 start-dev
```

The startup line names one address:

```
Keycloak 26.7.1 on JVM (powered by Quarkus 3.33.2.1) started in 7.463s.
Listening on: http://0.0.0.0:8080
```

and `/proc/net/tcp6` inside the container holds one listening socket on a
routable address - `0000...0000:1F90`, which is 8080. The second listener in the
table is on `127.0.0.1` at an ephemeral port and is Quarkus's own.

A request to the mapped 9000 connects to the Docker proxy and then gets an empty
reply, which is what a refused backend looks like from outside and is exactly
the shape that would be misread as "the server answered nothing".

The endpoints are not on 8080 either. All eight candidates answer the ordinary
unmatched-path 404:

```
GET /health           404  {"error":"Unable to find matching target resource method"}
GET /health/live      404  the same
GET /health/ready     404  the same
GET /health/started   404  the same
GET /metrics          404  the same
GET /q/health         404  the same
GET /q/metrics        404  the same
GET /management/health 404 the same
```

That body is `http/fallback`'s, counted once for the whole API, and it is **not**
counted again here for the same reason the SAML cut did not count 22 cells of
its grid.

### 1.2 The options, and what each one alone gives

`--health-enabled` and `--metrics-enabled` - `KC_HEALTH_ENABLED` and
`KC_METRICS_ENABLED` as environment variables - are the two. Either one brings
the interface up, with only its own endpoints on it. Four containers, one image:

| container | options | startup line | `/health` | `/metrics` | `/` |
|---|---|---|---|---|---|
| default | none | `Listening on: http://0.0.0.0:8080` | no listener | no listener | no listener |
| health only | `KC_HEALTH_ENABLED` | `… Management interface listening on http://0.0.0.0:9000.` | 200, **225 bytes** | 404 | 200, **120 bytes** |
| metrics only | `KC_METRICS_ENABLED` | the same | 404 | 200 | 200, **123 bytes** |
| both | both | the same | 200, **345 bytes** | 200 | 200, **180 bytes** |

Two of those cells are the finding rather than the plumbing:

- **The index page lists exactly the endpoints that are on**, which is why its
  length moves across three of the four rows.
- **`/health`'s check list is a function of `--metrics-enabled`.** With health
  alone the document holds two checks; enabling metrics adds
  `Keycloak database connections async health check` between them. So a
  recording of `/health` is a recording of an option set, not of a version.

They are build-time options, so `start-dev` re-augments on startup. That costs
about a second on top of a seven-second start, measured, which is why the
recorder sets both on one image rather than keeping two.

### 1.3 The discriminator: neither precedent's transfers, and a third one does

`p11-saml-descriptor.md` swept candidate paths against Keycloak's pair of 404s -
an unmatched path answering `Unable to find matching target resource method`
with none of the five security headers, a path the router knows answering
`HTTP 404 Not Found` with all five. **The management port has neither body.** Its
only 404 is 53 bytes of HTML from Quarkus's own management router, which never
reaches Keycloak's JAX-RS application.

`account-api.md` recorded why the SAML method did not transfer to its surface,
and fell back to a weaker test: *"a route exists when at least one verb answers
outside the generic fallback family"*, with `OPTIONS` excluded because *"it
answers 200 with an empty body on every path, including
`/account/nosuchthing`"*. **That does not transfer either, and it fails harder
here**: on this port every verb answers 200 on every path that is a route, so
the test would have accepted nothing it was not already sure of. `OPTIONS` is not
the exception here; it is one of seven verbs that all behave the same way.

What enumerates this one is simpler than both, and it was validated in both
directions on one container before it was used:

```
a route        answers its own 200 on all seven verbs
not a route    answers 404 <html><body><h1>Resource not found</h1></body></html>
               text/html; charset=utf-8, 53 bytes, on all seven
```

### 1.4 The verb sweep: 77 cells, and only two answers in them

Eleven paths by seven verbs. The cell is `status/body-length`.

```
path                      GET      POST     PUT      DELETE   PATCH    HEAD     OPTIONS
/                         200/180  200/180  200/180  200/180  200/180  200/0    200/180
/health                   200/345  200/345  200/345  200/345  200/345  200/0    200/345
/health/live              200/45   200/45   200/45   200/45   200/45   200/0    200/45
/health/ready             200/345  200/345  200/345  200/345  200/345  200/0    200/345
/health/started           200/45   200/45   200/45   200/45   200/45   200/0    200/45
/health/well              200/45   200/45   200/45   200/45   200/45   200/0    200/45
/health/group             200/45   200/45   200/45   200/45   200/45   200/0    200/45
/health/group/nosuch      200/45   200/45   200/45   200/45   200/45   200/0    200/45
/metrics                  200/~150k … rising with every request …       200/0    200/~150k
/metrics/nosuch           200/~150k … rising with every request …       200/0    200/~150k
/nosuchpath               404/53   404/53   404/53   404/53   404/53   404/0    404/53
```

Seventy cells are a route's own 200 and seven are the fallback. **There is no
third answer, and there is no 405 anywhere on this port.**

Negative candidates were tried and named rather than left out. All of these
answer the 53-byte 404: `/q/health`, `/q/metrics`, `/q/dev`, `/q/info`,
`/q/health-ui`, `/info`, `/status`, `/prometheus`, `/management`, `/openapi`,
`/swagger-ui`, `/health/up`, `/favicon.ico`, `/index.html`, `/robots.txt`,
`/health/x`, `/health/wel`, `/health/wellness`, `/health/liv`, `/health/read`,
`/health/start`, `/metricsx`, `/metric`, `/x`, `/x/y`.

`/HEALTH` and `/Health` are the fallback too, and they are counted with the
variants in 1.5 rather than here: **the path is compared case-sensitively.**

`/health/well` and `/health/group` are routes and are not in Keycloak's
documentation - they are SmallRye Health's wellness and health-group endpoints.
`/health/group/nosuchgroup` is a route too, and section 1.6 says what it
answers.

### 1.5 The count: 16 behaviours

```
 77   eleven paths x seven verbs, on the both-options container
 25   further candidate paths on that container, every one the fallback
 11   path normalisation, trailing slash, query and case variants
 13   Accept values on /metrics
  3   Accept values on /health
 12   repeat draws of /health and /health/live, for stability within a container
  9   the default container: eight paths on 8080 and one on 9000
 12   the health-only and metrics-only containers, six paths each
 10   a second both-options container: cross-container draws, and the write test
 ---
172   request/response pairs issued
```

and **16 catalogued behaviours**, which is this chapter's denominator. It is
pinned as `managementChapterCases` in `internal/conformance/management_test.go`
and asserted by `TestManagementChapterCountIsThePinnedNumber`, so the number in
this heading is checked rather than trusted. account-api.md is why: three
numbers disagreed inside one chapter there before anybody had merged it.

The arithmetic from cells to cases:

- **The verb dimension collapses to one case.** Seventy of the 77 cells say the
  same thing. `management/health/wrong-verb` is it, and counting it per path
  would report one behaviour seventy times - the SAML cut's decision about the
  fallback family, and the one part of its method that transfers.
- **The seven control cells are one case**, `management/fallback/unknown-path`,
  and it is a chapter of its own rather than rows in `http/fallback`: that
  chapter counts the two bodies Keycloak's application serves, and this is a
  third body the application never sees.
- **Ten route shapes give twelve cases**, because `/metrics` carries three: the
  dump, the Prometheus-text dump, and the 406 that is the only recordable
  response it has.
- **Three cross-cutting cases**, each sending a request no other case sends:
  `Accept` is ignored, the verb decides nothing, the path is not normalised.

1 + 10 + 3 + 1 + 1 = 16. Section 2.5 answers the objection that eight of the
sixteen goldens hold bytes another golden already holds.

### 1.6 Four `/health` paths, two documents, and one of them has no stable order

```
/health          the aggregate: three checks
/health/ready    the aggregate, byte-identical to /health
/health/live     empty checks
/health/started  empty checks
/health/well     empty checks
/health/group    empty checks
/health/group/nosuchgroup   empty checks
```

Two facts in that table are traps.

**`/health/started` answers the empty document, not the aggregate.** Which of
the two documents a path gets is not guessable from its name, and a server
answering the aggregate to `/health/live` would look correct to a reader.

**A health group that was never defined answers 200 `UP`.** Its sibling one
segment up, `/health/x`, is the 404. So a deployment polling
`/health/group/<typo>` is told the server is healthy by a route that ran no
checks at all.

The aggregate's `checks` array has **no reproducible order across container
starts**. Two containers from one image, both options set:

```
container A   Graceful Shutdown, Keycloak database connections…, Keycloak Initialized
container B   Graceful Shutdown, Keycloak Initialized, Keycloak database connections…
```

`Graceful Shutdown` was first in both and the other two swapped. AGENTS.md's
rule is that two recordings agreeing is never evidence of stability; this is its
obverse, which is valid - two recordings **disagreeing** is evidence of
instability. The five aggregate cases carry `Unordered: []string{"checks"}` for
it. The array has three elements, so the mask is not the inert kind the ratchet
refuses.

Within one container the document is stable: eight requests, one md5.
`/health/live` and `/` were byte-identical across the two containers, so nothing
there needs a mask.

### 1.7 None of the five security headers, on anything

Read off a socket, on every route shape and on the fallback:

```
GET /health      200  content-type: application/json; charset=UTF-8
                      cache-control: no-store
GET /metrics     200  Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
GET /            200  (no Content-Type at all)
GET /nosuchpath  404  content-type: text/html; charset=utf-8
```

That is the whole header set in each case, `Content-Length` aside. **Not one
response on this port carries `Referrer-Policy`, `Strict-Transport-Security`,
`X-Content-Type-Options`, `X-Frame-Options` or `X-Robots-Tag`**, and none carries
`Date` either, which agrees with the main port.

AGENTS.md's bullet records three exceptions to "the four are on everything". This
is a fourth and it is the widest: a whole listener rather than a route, a family
or a media type. Every case in this chapter declares the five absent, and the
declaration is compared against the recorded bytes by
`TestAssertAbsentHeadersAgreeWithTheGolden` - which is the half of F177 that
works on a `Recorded` case, where `diff`'s "these differ" verdict is satisfied by
any one difference and therefore asserts nothing on its own.

**`GET /` serves a 180-byte HTML body with no `Content-Type` header at all.** It
is the only response in this repository that does.

### 1.8 The path is not normalised on this port

One container, one path, two ports:

```
GET //health            on 8080   400 {"error":"missingNormalization","error_description":"Request path not normalized"}
GET //health            on 9000   200 with the aggregate health document
GET /health/../health   on 8080   400 the same
GET /health/../health   on 9000   200
GET /%2e%2e/health      on 9000   200
GET /health/            on 9000   200
GET /metrics/           on 9000   200
```

AGENTS.md describes the normalisation rule as running *"ahead of the route
table, across the whole server"*. It runs ahead of **one** route table. This is
the sharpest data point the chapter has, because both requests were issued to
one container seconds apart and the only variable is the socket.

### 1.9 `/metrics` negotiates on `Accept` and `/health` ignores it

```
Accept on /metrics                                          answer
(none)                                          200  application/openmetrics-text; version=1.0.0; charset=utf-8
*/*                                             200  the same
text/*                                          200  the same
text/plain                                      200  text/plain; version=0.0.4; charset=utf-8
text/plain;version=0.0.4                        200  the same
application/json                                406
application/openmetrics-text                    406
application/openmetrics-text;q=0.9              406
application/openmetrics-text;q=1                406
application/openmetrics-text;charset=utf-8      406
application/openmetrics-text;version=1.0.0      406
application/openmetrics-text;version=1.0.0;charset=utf-8    200
application/openmetrics-text; version=1.0.0; charset=utf-8  200
```

**Asking for the media type the endpoint serves by default is a 406.** Both
parameters are needed and either alone is refused, so the accept value has to be
the produced media type spelled out in full; the space after the semicolon does
not matter. Bare `text/plain` is enough, so the two media types this endpoint
produces do not follow one rule.

`/health` ignores the header entirely: `text/plain`, `text/html` and
`application/xml` all get the JSON document, byte for byte.

The 406's status line carries a **non-standard reason phrase**:

```
HTTP/1.1 406 Micrometer prometheus endpoint does not support application/openmetrics-text
content-length: 0
```

No golden can hold it - `FormatGolden` writes `http.StatusText(406)`, so the
committed file says `406 Not Acceptable`. See F246.

**`/metrics` is a prefix route and `/health` is not.** `/metrics/nosuch` and
`/metrics/nosuch/deeper` both answer the dump, where any unnamed suffix under
`/health` is the 404. Two sibling families on one port, opposite answers.

### 1.10 The metrics dump cannot be a golden, and it is not close

| draw | lines | changed lines vs the first |
|---|---|---|
| one container, request 1 | 1326 | - |
| one container, request 2, three seconds later | 1326 | 116 |
| a second container from the same image | 1224 | 2156 |

`agroal_acquire_count_total` rises with every request the container has served,
including the recorder's own; the response grew from 122635 to 137268 bytes over
one session's probing. Every sample carries a `node="<container id>-<port>"`
label minted with the container. The `# TYPE` and `# HELP` lines are interleaved
with the samples rather than grouped, so there is no stable prefix to record.

F113's rule reaches this without argument: a body carrying a per-request value
cannot be `Recorded`, whatever else is true of it. **No mask was built to try.**

### 1.11 Nothing a fixture can do reaches this port

A realm, a client, a user and a group created on 8080 - all four 201 - left
`/health`, `/health/live` and `/` byte-identical on 9000 of the same container.
This is the measurement behind the third refusal in section 3.

## 2. Decisions, each with the alternative rejected

### 2.1 The chapter enumerates the enabled surface, not the default container's

**Rejected alternative: enumerate what a default `start-dev` answers.** There is
nothing to enumerate. A default container has no listener on 9000, so "the
default surface" is not a surface with zero endpoints on it - it is the absence
of a server, and a golden cannot hold a connection that was refused. A chapter
built that way would consist of the sentence "this feature is off", recorded as
though it were a contract, which is the mistake the brief names and F169 is the
precedent for: CIBA's 503 was written up as a missing feature for weeks and was
an artefact of a startup option, with the flow working perfectly once the option
was set.

The reasoning F169 wrote down is the one followed here, and it has three parts.
The option is **not settable on a running server** - it is build-time, so
nothing in the catalogue can reach it. The behaviour behind it is **real and
complete** - the endpoints work, and this cut drove all ten of them. And the
thing standing between the behaviour and a recording was **the recorder**, which
is where the fix belongs. CIBA's third blocker was a shape the harness has not
got, an inbound callout; this one's was a port mapping, which is twenty lines.

**Rejected alternative: enumerate both, with the default container's answers as
cases of their own.** The default container's answers on 8080 are
`http/fallback`'s unmatched-path 404, already counted once for the whole API.
Counting them again under this heading is the repetition both precedents refused.
The fact is recorded in 1.1 and in the AGENTS.md entry rather than as cases.

The cost of the choice is stated rather than hidden: **the goldens in this
chapter are a function of the recorder's startup options**, which no other
golden in this tree is, and nothing in the file records which options it was
recorded under. That is F245.

### 2.2 `Case.ManagementPort`, and what the verifier does with it

The recorder reached one port. `startKeycloak` exposed `8080/tcp` and returned
one base URL, and `Case` had no way to say a request goes elsewhere.

`startKeycloak` now exposes both ports, sets both options, and returns two URLs.
The case's own request goes to `RecordTarget(base, management, c)`; **the
fixture's steps always go to the main port**, which is what the third refusal
rests on. Everything downstream of the response - `normalisePasses`,
`recordedHeaders` - uses the base the response came from, so a body or header
carrying the server's own URL would be masked against the right one. No
management body carries an absolute URL today, measured: the index page's two
links are relative and the health documents hold none. The symmetry is what
matters rather than the current inertness, because the verifier normalises
against the one base it has.

**A port mapping is per container and this needed no third container regime.**
Both options are set on every container `startKeycloak` starts, so the shared
container and each `PristineRealm` container carry the same two ports without
this function knowing which case asked.

**Rejected alternative: a path prefix instead of a field.** A case could have
declared `Path: "management://health"` and the recorder could have split it.
That puts a routing decision inside a string the catalogue's own
well-formedness test validates as a slug, makes `Expand` and `buildRequest` both
places where it could be got wrong, and gives the reader no place to write down
what the port means. `Case.SecondRealm`'s doc comment makes the same argument
about deriving a flag from a path.

**Rejected alternative: a second container regime, like `PristineRealm`'s.** A
management case does not need a container to itself - 1.11 measured that nothing
in a realm reaches this port - so a regime would cost one Keycloak start per
case and buy nothing.

**What the verifier does, which is the question most likely to be answered
wrongly.** It serves a management case's request to the same handler it serves
every other case to, because it has exactly one, and that handler is Gloak's
main mux. The golden beside it was recorded from port 9000. **Those are two
different servers, measured disagreeing about the same request** - `GET //health`
is a 400 on one and a 200 on the other - so the verifier is **not** answering the
question the golden asks.

`Recorded` is honest about that as far as it goes: it asserts only "these
differ", which is satisfied by Gloak having no `/health` at all. What it cannot
survive is anything claiming more, and section 3's first refusal is what stops
that.

**Rejected alternative: make the verifier serve a purpose-built empty handler
for management cases.** That would answer the right question - "what does
Gloak's management port serve?" - with the right answer today, and it would
break the one mechanism `Recorded` exists for. The status is a list that clears
itself: when Gloak serves the thing, the case matches and the suite says so. A
hardcoded empty handler can never match, so the alarm could never fire and the
machinery would be defeated rather than used.

**Rejected alternative: make `serve` return an error for a management case**, so
the verifier says "I cannot serve this" rather than comparing against the wrong
port. `TestConformance`'s `Recorded` branch already skips on a `serve` error, so
this works. It has the same defect as the alternative above and one more: it
would make the case permanently unverifiable by anything, where the refusal in
section 3 makes it verifiable the moment somebody gives the verifier a second
handler.

### 2.3 Four chapters, and the old `management` row removed

`chapterOf` groups a case by its first two slug segments, so a one-segment
chapter name can hold no cases at all. The chapter is split the way the SAML row
was split into four: `management/index`, `management/health`,
`management/metrics`, `management/fallback`. One chapter per route family, which
is how the OIDC, SAML and account sides are split.

`management/fallback` is a chapter rather than rows in `http/fallback` on the
same ground the chapter list already states for `oidc/protocol`: what decides
the answer is a different router, not a route that failed to match.

### 2.4 The 406 is the metrics endpoint's witness

**Rejected alternative: leave `/metrics` represented by `Pending` cases alone.**
p11 states the rule and it applies: *"A chapter whose only evidence is a `Reason`
string is a chapter nobody can check."* The dump cannot be a golden (1.10) and
neither can its Prometheus-text form, so without a third case the whole metrics
family would be two `Reason` strings.

The 406 is recordable and it is the same endpoint answering from the same place:
an empty body, so F113 does not reach it, identical across three requests to one
container and to a request on a second.

`management/metrics/prefix-match` uses it as an instrument rather than
re-measuring it. The claim is that any suffix under `/metrics` reaches
Micrometer, and the golden pins exactly that: a path that had **not** reached it
would be the 53-byte 404, not a 406.

### 2.5 Eight goldens hold bytes another golden already holds, and that is not padding

Five hold the empty-checks document and three more hold the aggregate. The
objection is that the chapter's denominator is inflated by counting one answer
eight times, and the answer is that **a behaviour is a request and its answer,
not an answer**.

`/health/well` being a route at all, and `/health/group/{name}` answering `UP`
for a group that was never defined, are separately falsifiable claims about
Keycloak that happen to share a response body. So are the three cross-cutting
cases, each of which sends a request no other case sends: without
`management/health/unnormalised-path` nothing in this repository records that
the normalisation rule does not run here, and that rule's own bullet in AGENTS.md
is currently too broad because of it.

The identity is not left as an observation either. Section 4 records a mutation
that changed a byte inside one of these goldens and killed nothing, and
`TestManagementHealthGoldensHoldTheDocumentTheyWereMeasuredTo` is what the
duplication bought: ten goldens, two documents, and the equalities asserted.

### 2.6 `Unordered` on `checks`, rather than `Volatile` over the array

`Volatile` over `checks` would assert that the key is present and give up the
three check names, which is F46's retreat. The order is what moves and the
membership is not, measured on two containers, so the mask that fits is the one
that sorts.

## 3. Refusals, each with the measurement behind it

| What | Measurement | Status |
|---|---|---|
| A `ManagementPort` case may not be `Implemented` | The verifier has one handler and it is Gloak's main mux. `GET //health` is 400 on 8080 and 200 on 9000 on one container, so the two are different servers | `managementDefects`, killed by M3 |
| A `ManagementPort` case must report under a `management/` chapter, and a `management/` case must declare the flag | A management-port measurement filed elsewhere is counted as that chapter's behaviour; a management case without the flag is recorded from port 8080 | `managementDefects`, killed by M5 and M16 |
| A `ManagementPort` case may not name a fixture that runs steps | A realm, a client, a user and a group created on 8080 left `/health`, `/health/live` and `/` byte-identical on 9000 | `managementDefects`, 1.11 |
| Every management case with a golden declares the five security headers absent | Not one response on this port carries any of them, read at socket level | `TestManagementCasesDeclareTheSecurityHeadersAbsent`, killed by M2 |
| `/metrics` and `/metrics/{suffix}` may not be `Recorded` | 116 lines move between two requests three seconds apart; 2156 between two containers - F113 | `Pending`, 1.10 |
| The 406's reason phrase is not asserted | `FormatGolden` writes `http.StatusText(406)` | not a case; F246 |
| The absent default listener is not a case | A golden cannot hold a refused connection | not a case; F249 |
| `Case.ManagementPort` needs no refusal against `Operation` | `management/*` has no `OpenAPITag`, so `TestProtocolCasesNameNoOperation` already refuses one | no new guard, deliberately |

## 4. The mutation pass

Every mutation was applied to a committed tree, the **build** run before the
tests so that a compile error could not be read as a failing assertion, the
named test run, its **failure message** read rather than its name, and the
revert verified against a dirty check scoped to `internal/conformance`. The
revert is on a `trap ... EXIT`, so an interrupted run leaves no mutation behind.

**The harness earned two refusals during the pass.** A `-run` pattern naming no
test runs nothing and exits 0, which reads exactly like a survivor: the first
verdict of the pass was produced that way and was wrong. The runner now counts
`=== RUN` lines and refuses a verdict when none appeared. And M4 is a **control**
rather than a finding - a comment added to a line, semantically null, which
survived as it must; a mutation only a reader can rule out is one the verdict
line cannot judge.

| # | Mutation | Result |
|---|---|---|
| M1 | `managementChapterCases` 16 → 15 | KILLED - the count test names both numbers |
| M2 | drop `Referrer-Policy` from `managementSecurityHeaders` | KILLED - after the fix below; see the note |
| M3 | `management/health/live` → `Implemented` | KILLED - "the verifier has one handler" |
| M4 | add a comment to a case's `Request` line (control) | SURVIVED, correctly |
| M5 | drop `ManagementPort: true` from `management/health/well` | KILLED - "record the wrong server" |
| M6 | `managementDefects` returns before its loop | KILLED by the can-fail guard |
| M7 | `inManagementChapter` matches a prefix nothing has | KILLED - "holds 0 cases and says 16" |
| M8 | add `Referrer-Policy: no-referrer` to a committed golden | KILLED - "the declaration contradicts the measurement" |
| M9 | `Graceful Shutdown` → `Graceless Shutdown` inside a golden | **SURVIVED**; fixed; M9b KILLED |
| M10 | remove `management/health/started` from its document group | **SURVIVED**; fixed; M10b KILLED |
| M11 | `management/health` → `Enumerated: false` with a reason | **SURVIVED, and stands** |
| M12 | the recorder's port choice collapsed to `return base` | **SURVIVED**; fixed; M12b KILLED |
| M14 | drop the live `Unordered` mask from `management/health/check` | **SURVIVED, and stands** |
| M15 | delete a `Recorded` case's `Reason` | KILLED - "must say why it is not served yet" |
| M16 | disable the chapter-without-the-flag arm | KILLED by the can-fail guard |
| M17 | disable the golden equality comparison | not a kill (did not compile); M17b **SURVIVED**; fixed; M17c KILLED |

### M2 was a tautology before it was a kill

`TestManagementCasesDeclareTheSecurityHeadersAbsent` first compared the cases'
declarations against `managementSecurityHeaders` - **the very slice the cases
are spread from**. Dropping a name from it would drop the name from all fourteen
declarations and from the expectation in one edit, and pass: `count(x) ==
count(x)`, which is p11's M18 in a new place. It now reads
`theFiveSecurityHeaders`, declared in `headersplit_test.go` for a different
test, and M2 kills.

The fix was found by asking what the mutation would do before running it, which
is the one part of this pass that did not need a container.

### M9 survived, and it is this chapter's shape rather than its defect

A byte changed inside `management/health/check.http` compiled, ran the whole
management chapter through `TestConformance` - seventeen subtests, including the
case whose golden it corrupted - and killed nothing. **Every case in this
chapter is `Recorded`**, and a
`Recorded` case is required *not* to match, so a corrupted golden does not match
either way. account-api.md states the rule; this is it met on a surface where it
covers the whole chapter rather than one case.

What closed it is not a copy of the bytes, which would be a golden checked
against a golden somebody typed. It is the **relations the chapter already
claims**: ten goldens were measured answering two documents, and those
equalities are assertions no single case can make.
`TestManagementHealthGoldensHoldTheDocumentTheyWereMeasuredTo` is the guard, and
it fails on any byte moving in any of the ten.

### M10 and M17b are the same lesson twice, in one afternoon

M10 removed a golden from its group and survived, because the test checked the
claims that were made and **a smaller set of true claims is still true** -
F181's shape on a new pair of lists. The groups are now joined against the
catalogue, so a deletion is visible and a new `management/health` case with no
group is refused.

M17b disabled the equality comparison itself and survived, because the test's
vacuity guards covered the **traversal** - both groups non-empty, the two
documents differing - and not the **comparison**. That is AGENTS.md's rule met on
a test written the same afternoon it was quoted. The comparison is now
`goldensThatDisagree`, a function taking a reader, with a guard that hands it
bodies known to differ.

### M12 survived because the recorder is not compiled in CI

The port choice was three lines inside `record_test.go`, which carries the
`docker` build tag. Collapsing it to "always the main port" survived **1147
tests**, none of which the build compiles that file for. The only thing that
could have caught it is running `make record` and reading fourteen goldens.

It is now `RecordTarget` in `case.go`, which is the move `recordedHeaders`' own
doc comment already argues for in this package: *"logic nothing can test without
Docker is logic nothing tests."* Its third test case is the one worth having - an
ordinary case must go to the main port **even when a management URL was
supplied**, which is what stops the routing being "whichever URL is non-empty".

### The two survivors that stand

**M11: a chapter can be un-enumerated and nothing notices.** Setting
`management/health` to `Enumerated: false` with a reason passes the whole suite.
`TestCoverage` is a reporter and says so; the gate is `cmd/parity`, and
`Diff.Decreased` gates the **served** total alone. So a denominator can shrink
with a flat numerator and no test, and no gate, will say anything - which is
exactly the inflation `Chapter`'s own doc comment says leaving chapters out
silently would cause. It is not this chapter's defect: the same mutation on
`saml/descriptor` survives identically. F247.

**M14: removing a live mask is caught by nothing.** `TestNoMaskIsInertOnItsGolden`
catches masks that change nothing; nothing catches a mask that was doing
something being deleted. The mask's real consumer is the **next** recording - the
check order moves across containers, so without it a re-record produces a
five-file diff about half the time - and "the next recording's diff" is the same
guard M12 had before it was fixed. Also not this chapter's defect, and it
applies to all 293-odd masks. F248.

## 5. Parity

Measured with two `GLOAK_PARITY_REPORT` runs, base `f63a650` on `main`.

```
base   598 of 644 enumerated behaviours served; 2 chapters not enumerated
head   598 of 660 enumerated behaviours served; 1 chapters not enumerated
```

```
management/index       0 served   1 recorded    1 documented   catalogue
management/health      0 served  10 recorded   10 documented   catalogue
management/metrics     0 served   2 recorded    4 documented   catalogue
management/fallback    0 served   1 recorded    1 documented   catalogue
```

**The denominator moves by exactly 16 and the numerator does not move at all.**
Those are the same fact counted twice and it is the check worth doing: a
numerator that moved would mean a case outside this chapter had changed status,
and a denominator that moved by anything other than 16 would mean a case had
been added or lost somewhere else.

**The parity total does not fall.** Nothing here is `Implemented`, by refusal,
and section 2.2 is why that is the honest state rather than a gap.

`themes` is the one chapter left with no denominator.

## 6. What belongs in AGENTS.md

Phrased as it would be folded.

### For the security-headers bullet, as a fourth exception

> - **the whole management port** carries none of them, and it is the widest
>   exception on this list: a listener rather than a route, a family or a media
>   type. `GET /health`, `GET /metrics`, `GET /` and the unmatched-path 404 on
>   port 9000 were read off a socket and carry `Content-Type` (except `/`, which
>   carries none at all), `Cache-Control` on the health family, and nothing
>   else - no `Date` either. Fourteen goldens declare the five absent, and
>   `TestManagementCasesDeclareTheSecurityHeadersAbsent` requires the next one
>   to. This is the eighth correction to this bullet and the first that is about
>   a **port** rather than about a response.

### For the normalisation bullet

> **The normalisation rule runs ahead of one route table, not across the whole
> server.** `GET //health` answers `400 missingNormalization` on 8080 and `200`
> with the health document on 9000, measured on one container seconds apart;
> `/health/../health` and `/%2e%2e/health` do the same. The sentence "it runs
> ahead of the route table, across the whole server" was drawn from the only
> server that had been probed. Pinned by
> `management/health/unnormalised-path`.

### For the wrong-method bullet

> **An eighth data point, and the first outside the 404/405/406 family
> altogether.** On the management port **every verb answers the route's own
> 200** - seventy cells over ten route shapes - and every verb on a path that is
> not a route answers one 404. There is no 405 anywhere on that port and no
> `Allow` header. So "the rule" is not a rule of the API; it is a rule of one
> JAX-RS application, and the second server in the same process does not have
> it.

### A new bullet, for the management port

> - **A default `start-dev` has no management port.** Port 9000 does not listen
>   at all: the startup line names one address and `/proc/net/tcp6` holds one
>   routable listening socket. `--health-enabled` or `--metrics-enabled` brings
>   it up, with only its own endpoints on it. **The endpoints are not on 8080
>   either** - `/health` and `/metrics` there are the ordinary unmatched-path
>   404. `internal/conformance`'s recorder sets both options on every container
>   it starts, which is what makes the management chapter recordable, and the
>   options are transparent to 8080: the run that introduced them moved no
>   golden outside the new chapter.
> - **Two of that port's responses are a function of the options rather than of
>   the version.** The index page at `/` lists exactly the endpoints that are
>   switched on - 180 bytes with both, 120 with health alone, 123 with metrics
>   alone - and `/health`'s check list gains
>   `Keycloak database connections async health check` only when metrics is on.
>   A golden of either is a recording of an option set. See F245.
> - **Four `/health` paths, two documents, and the split is not guessable.**
>   `/health` and `/health/ready` answer the aggregate; `/health/live`,
>   `/health/started`, SmallRye's `/health/well`, `/health/group` and
>   `/health/group/{anything}` answer an empty check list. **A health group that
>   was never defined answers 200 `UP`** where `/health/x` is a 404, so polling
>   a mistyped group name reports healthy. The aggregate's `checks` array has no
>   reproducible order across container starts.
> - **`/metrics` refuses the media type it serves.**
>   `Accept: application/openmetrics-text` is a 406 where no `Accept` at all is a
>   200 with `application/openmetrics-text; version=1.0.0; charset=utf-8`; both
>   parameters have to be spelled out for the 200. Bare `text/plain` is enough
>   and gives Prometheus 0.0.4. `/health` beside it ignores `Accept` entirely.
>   The 406's status line carries a **non-standard reason phrase**, `406
>   Micrometer prometheus endpoint does not support application/openmetrics-text`,
>   which no golden can hold. And `/metrics` is a **prefix** route where
>   `/health` is exact: `/metrics/anything` is the dump, `/health/anything` is
>   the 404.

### For the not-found list, or beside it

> **A third 404 body, and it is not in the numbered list because it is not the
> Admin API's.** The management port answers every unmatched path, on all seven
> verbs, with 53 bytes of HTML - `<html><body><h1>Resource not found</h1></body>
> </html>`, `text/html; charset=utf-8` - from Quarkus's own management router,
> which never reaches Keycloak's application. `management/fallback/unknown-path`
> is the golden.

### For the build section

> **Two enumeration discriminators are published in this repository and neither
> is general.** p11's pair of 404s does not work under `/realms/{realm}/`;
> account-api's "at least one verb answers outside the fallback family, with
> OPTIONS excluded" does not work on the management port, where **every** verb
> answers 200 on every route. A third surface needed a third discriminator, and
> what every one of them has in common is that it was **validated in both
> directions on one container before it was used**. That is the transferable
> part. The other transferable part is the SAML cut's: the generic fallback
> family is counted once for the whole API and never per path.

### For the masks section

> `Case.Unordered` has a consumer outside the Admin API's listings: the
> management port's `/health` `checks` array, whose three entries come back in
> different orders on two containers from one image. The array is the whole
> reason the mask is not the inert kind - it holds three elements, where the 116
> masks removed on 2026-08-30 covered arrays of one or none.

## 7. Follow-ups, numbered from F244

F171-F243 are taken.

### F244 - the verifier has one handler, and a management case is served to the wrong server

`serve` builds one handler and one base URL. A management case's request goes to
Gloak's main mux and its golden came from port 9000, and section 2.2 measured
that those are different servers. `Recorded` tolerates it because it asserts only
"these differ"; `Case.ManagementPort` refuses `Implemented` so that nothing
claims more.

What closes it is a second handler on the verifier's side and a second base URL
for it, which is the shape `startKeycloak` now has on the recorder's side.
Whoever builds Gloak's management interface does both and lifts the refusal in
the same commit. Filed so that the refusal is met as a decision rather than as
an obstacle.

### F245 - a golden whose bytes are a function of a startup option, and nothing records which

`management/index/root` and the five aggregate health goldens are recordings of
an **option set**: the index page lists the endpoints that are on, and the check
list gains an entry when metrics is on. The golden file says nothing about this,
and neither does anything a reader of the diff would see.

It is a new kind of dependency in this tree. Every other golden is a function of
the image, the fixture and the realm, all three of which the catalogue names.
The options are named in `startKeycloak`'s doc comment and in this document, and
a second option combination would need a second container regime to record - so
the cheap fix is not a regime but a line in the golden, and that is a change to
`FormatGolden` and `ParseGolden` that every one of the 1119 files would take.
Filed rather than done, with the cost stated.

### F246 - a non-standard reason phrase cannot be held by a golden

`FormatGolden` writes `HTTP/1.1 %d %s` with `http.StatusText(g.Status)`, so the
committed file says `406 Not Acceptable` where the wire said `406 Micrometer
prometheus endpoint does not support application/openmetrics-text`. `ParseGolden`
reads the status number and discards the rest, so the round trip is lossy in a
way nothing reports.

It is the first measured non-standard reason phrase in this project, which is why
this has not bitten before. The fix is to record `resp.Status` rather than
recompute it, and the reason to hesitate is that `httptest.ResponseRecorder` on
the verifier's side has no reason phrase at all - so asserting one would need a
mask, and a mask over the only value it covers is the shape AGENTS.md warns
about. Measured, filed, and not built.

### F247 - a chapter can be un-enumerated and no gate says so

Setting a chapter to `Enumerated: false` with a reason passes the whole suite and
the parity gate: `TestCoverage` is a reporter, and `Diff.Decreased` gates the
served total alone. A denominator can therefore shrink with a flat numerator and
the percentage rises, which is exactly the inflation `Chapter`'s doc comment says
leaving chapters out silently would cause.

`Diff` already has `MovedOutsideTheTotal` for the adjacent concern, so the place
to put it is clear. What is not clear is whether it should **gate** or only
**report**: a chapter genuinely going unenumerated is a thing that has never
happened, and a gate nobody can trip is one nobody maintains. Filed with the
question rather than answered.

### F248 - removing a live mask is caught by nothing

`TestNoMaskIsInertOnItsGolden` catches a mask that does nothing. Nothing catches
a mask that was doing something being deleted, and the consequence is not visible
until a `make record` on a container that happens to disagree. Measured here on
`Unordered "checks"`, and it applies to every mask in the catalogue.

The mirror rule is the one `TestEveryGoldenMissingASecurityHeaderDeclaresItAbsent`
built for `AssertAbsentHeaders` after F181: read the **bytes** and check each
against the catalogue, rather than reading the catalogue and checking each
against the bytes. For a mask that means recording, per golden, that a mask ran
on it - which is a change to the recorder, not to a test, and is why this is
filed rather than done.

### F249 - the absent default listener is not expressible, and nothing says so

The single most load-bearing fact in this chapter - that a default `start-dev`
has no management port - is in a comment, in this document, and in the AGENTS.md
entry above. It is in no golden and no test, because a golden cannot hold a
refused connection and the recorder starts containers with the options on.

It is the same shape as F233's "a case whose status depends on the public
internet has no disposition": a measurement this harness can make once and never
re-check.

Worth a number because the next person to read `startKeycloak`'s two environment
variables may reasonably wonder whether they can be dropped. What happens if
they are was measured rather than guessed, and it is **loud rather than silent**:
Docker maps an exposed port whether or not anything listens behind it, so the
mapping still succeeds and the first management request gets an empty reply,
which `client.Do` returns as an error and the recorder turns into
`t.Fatalf("request: %v")`. So the options cannot be dropped by accident. What
is unrecorded is the **reason** they are there, and that lives only in prose.

### F113 - unchanged, and applied twice more

`/metrics` and its Prometheus-text form. The rule needed no argument: 116 lines
move between two requests to one container three seconds apart, and the counter
that moves is incremented by the recorder's own request. No mask was built to
reach it, which is F38's rule applied rather than reasoned about again.

### F161 - unchanged

Every management body is text and `RefuseNonTextBody` passed all fourteen.

### F169 - the model this cut followed

Its entry names three things standing between CIBA and a recording, of which the
first is *"`startKeycloak` in `record_test.go` would have to pass the option"*.
That is the whole of this cut's blocker, and the entry's real contribution was
the discipline of measuring the option before believing the symptom.

### F177 / F181 - the half-fix carried the weight

`AssertAbsentHeaders` on a `Recorded` case asserts nothing through `diff`, which
is every case in this chapter. `TestAssertAbsentHeadersAgreeWithTheGolden` is
what makes the fourteen declarations mean something, and M8 confirms it fires.

## 8. What is left

- **Nothing is served.** Gloak has no management interface at all - no `/health`,
  no `/metrics`, nothing on a second port. F244 is what building one has to do to
  the harness first.
- **The option matrix is enumerated in prose and not in cases.** Four
  combinations were measured; one is recorded. F245.
- **`/metrics` has one golden out of three cases**, and the two without one are
  barred by F113 rather than unmeasured. The measurements are in 1.10.
- **`HEAD` was measured and cannot be cased**, for F175's reason rather than a
  new one: the verifier serves through `httptest.ResponseRecorder`, which does
  not strip a body for a `HEAD` where `http.Server` does. All ten route shapes
  answer `HEAD` with the route's status and an empty body, which is in the grid
  in 1.4 and in no case.
- **The five containers of section 1 are gone.** Anybody re-measuring starts
  fresh, which is what account-api.md's rule asks for: a container written to by
  an unknown sequence of probes is not a clean measurement surface.

### Containers

- **Five for the measurements**, all fresh: one default, one with both options,
  one with health alone, one with metrics alone, and a second with both options
  to answer the cross-container stability question. The second both-options
  container is the one that found the unstable check order, and one container
  could not have.
- **Forty for the recording**, all fresh: one shared, in catalogue order, and one
  per `PristineRealm` case. Every management case runs against the shared one -
  none is `PristineRealm`, because 1.11 measured that nothing in a realm reaches
  this port.
- **Forty-five in total**, every one of them fresh.
