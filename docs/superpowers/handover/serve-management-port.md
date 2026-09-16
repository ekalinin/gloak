# Serving the management port, and the option set that is the whole answer

The `management` chapter was enumerated a week ago: sixteen behaviours, all
measured, none served. Gloak had no second listener at all, and
`Case.ManagementPort` refused `Implemented` because the verifier had one handler
and would have compared bytes from port 9000 against Gloak's main mux.

This cut serves the port. **Six cases move to `Implemented` and the parity total
goes from 598 to 604 of 677**, the denominator does not move, and the refusal is
narrowed rather than lifted.

The first decision was not "how". It was whether a health endpoint Gloak can
serve honestly exists at all, and the brief was right that the shape is easy and
the content is not. What resolved it was a measurement nobody had taken: **what
Keycloak's management port answers when only `--health-enabled` is set.** That
option set publishes two checks rather than three, serves a 120-byte index page
rather than a 180-byte one, and answers `/metrics` with the ordinary 53-byte 404.
It is an option set Gloak can reproduce byte for byte, without a counter, without
a database ping, and without inventing anything - and section 2.1 is the
argument.

## 1. Measurements

Every value below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on
2026-09-16, on containers started clean for this session. Header sets were read
off a socket rather than through `curl`, following AGENTS.md's rule that a probe
of an absence measures the probe. **Six containers, all fresh**; section 8 lists
them.

The handover this cut follows, `management-port.md`, carries the both-options
contract and it was not re-measured. What is below is what that document did not
carry.

### 1.1 The health-only option set, which is the one Gloak can serve

One container, `KC_HEALTH_ENABLED=true` and nothing else:

```
GET /             200  120 bytes, no Content-Type at all
GET /health       200  225 bytes, two checks
GET /health/live  200   45 bytes, empty check list
GET /metrics      404   53 bytes, text/html; charset=utf-8
```

The index page is the both-options page with one line removed:

```
<html>
<h2>Keycloak Management Interface</h2>
<ul><li><a href="/health">/health</a> - Health endpoint</li></ul>
</html>
```

and `/health` is the aggregate without the database entry:

```
{
    "status": "UP",
    "checks": [
        {
            "name": "Graceful Shutdown",
            "status": "UP"
        },
        {
            "name": "Keycloak Initialized",
            "status": "UP"
        }
    ]
}
```

**`GET /metrics` is the plain 53-byte fallback 404.** Not a 404 saying the
endpoint is disabled, not a 503, not anything that distinguishes a switched-off
endpoint from a path that was never a route. That single cell is what makes this
cut possible: a server with no metrics endpoint is not diverging from Keycloak
when it answers `/metrics` with the fallback - it is answering exactly what
Keycloak answers under the same configuration.

### 1.2 The DOWN document, caught twice and in two shapes

Nothing in the tree had ever measured a health check failing. Two were caught.

**A stopped database**, on a Postgres-backed container whose Postgres was
`docker stop`ped under it:

```
HTTP/1.1 503 Service Unavailable
content-type: application/json; charset=UTF-8
cache-control: no-store

{
    "status": "DOWN",
    "checks": [
        { "name": "Graceful Shutdown", "status": "UP" },
        { "name": "Keycloak Initialized", "status": "UP" },
        {
            "name": "Keycloak database connections async health check",
            "status": "DOWN",
            "data": { "Failing since": "2026-09-16 13:23:18,757" }
        }
    ]
}
```

(reindented here; the wire form is SmallRye's four-space rendering.)
`/health/ready` mirrored it and **`/health/live` stayed 200** throughout.

**A real drain**, by polling a health-only container through
`docker kill -s TERM` - 799511 polls, three distinct answers:

```
HTTP/1.1 503 Service Unavailable
content-length: 229

{
    "status": "DOWN",
    "checks": [
        {
            "name": "Graceful Shutdown",
            "status": "DOWN"
        },
        {
            "name": "Keycloak Initialized",
            "status": "UP"
        }
    ]
}
```

Two facts separate the two, and both are load-bearing:

- **A DOWN check is not always a bare status.** The datasource check gains a
  `data` object carrying `Failing since` in Java's `yyyy-MM-dd HH:mm:ss,SSS`.
  The graceful-shutdown check does not - its DOWN carries `status` alone. So
  there is no `Data` field on `httpx.HealthCheck`: no check this project
  publishes has ever been measured with one, and a field with no consumer is a
  claim about the shape that is not true.
- **A `Failing since` timestamp is a per-request value**, so the database
  check's DOWN is barred from any golden by F113 - which is a second, independent
  reason not to publish that check.

### 1.3 `Keycloak Initialized` is never observably DOWN

A fresh container was polled on `/health` from the instant `docker run`
returned. **73395 polls, exactly two distinct answers**: no connection at all,
and the document with the check already UP.

The management listener does not accept a connection until the check holds. So
`DOWN` is not an observable state of this check on this port, on a
`start-dev` container. That is the measurement that makes it a defensible
constant rather than a variable with one reachable value - section 2.3.

### 1.4 The drain, path by path

The same container, polled on five paths concurrently through a real SIGTERM:

| path | before | during the drain |
|---|---|---|
| `/health` | 200, 225 bytes | **503, 229 bytes** |
| `/health/ready` | 200, 225 bytes | **503, 229 bytes** |
| `/health/live` | 200, 45 bytes | 200, unchanged |
| `/health/started` | 200, 45 bytes | 200, unchanged |
| `/` | 200, 120 bytes | 200, unchanged |

That asymmetry is the endpoint's whole purpose and it is the contract an
orchestrator relies on: readiness fails so traffic stops arriving, liveness holds
so the process is not killed mid-drain. **The port kept answering until the
process went**, which is what says the management listener is stopped last.

### 1.5 The route table: the path is cleaned, never refused

`management-port.md` measured `//health` and `/health/../health` answering 200.
What it did not measure is the rule behind them. One container:

```
//health   ///health   /./health   /foo/../health   /%2e%2e/health   ->  /health
/health/   /health/./  /health/ready/   /health/group/               ->  the route
/health/.. /..  //                                                   ->  /
/health%2Flive                                                       ->  404
/HEALTH    /Health                                                   ->  404
/health/x  /health/wel  /health/wellness                             ->  404
```

That is `path.Clean` on the decoded path, with one exception: **`%2F` is not
decoded into a separator.** `/%2e%2e/health` is 200 and `/health%2Flive` is 404,
so the decode covers `%2E` and not `%2F`. Gloak routes on `r.URL.Path`, which Go
has already decoded, so it answers the liveness document to `/health%2Flive`
where Keycloak answers 404. No case sends it; it is named as a divergence rather
than built around. F259.

Two further routing facts, both new:

- **`/health/group/` is a prefix at any depth.** `/health/group/a/b` and
  `/health/group/a%20b` are both the 200 empty document.
- **Every verb, and there are more than seven.** `TRACE /health/live` is the
  route's own 200 too, so the eleven-by-seven grid understated it: it is not
  "seven verbs", it is "the verb is not read".

`HEAD` was measured and cannot be cased, for F175's reason. Worth recording
anyway: `HEAD /health/live` keeps `Content-Type` and `Cache-Control`, and
`HEAD /nosuchpath` sends **no `Content-Type` at all** where its GET does.

## 2. Decisions, each with the alternative rejected

### 2.1 The first decision: serve the port, as one option set, and serve no metrics

**The question the brief poses is whether a health endpoint that always answers
`UP` because nothing computes anything is a lie in the shape of a contract. It
is. The answer is not to skip the endpoint; it is to serve an option set whose
contents Gloak actually has.**

The argument, in the order it was made.

**`/metrics` is refused, and that refusal is F38 applied rather than reasoned
about again.** Gloak keeps no counters. The dump cannot be `Recorded` - 116 lines
move between two requests three seconds apart - so nothing on that endpoint could
ever be compared against anything. The only two recordable behaviours there are
Micrometer's 406s, and an endpoint that produced them would need a success
branch, which could only be a fabricated dump. And a fabricated dump is worse
than a 404 in a way that is specific rather than aesthetic: **a Prometheus
scraper pointed at a Gloak serving 200 with no `keycloak_*` series reads as
healthy and charts nothing**, where a 404 is a configuration error somebody
fixes.

A real-but-different dump - Go runtime metrics, say - was considered and is the
same objection with extra steps. It is not Keycloak's series set, no golden could
hold it, and it would require either a new module dependency or a hand-rolled
exposition writer for a document nothing can check.

**Given no `/metrics`, Gloak has no `--metrics-enabled`. And that decides the
rest of the surface, because two of this port's responses are functions of the
option set rather than of the version.** The index page lists exactly the
endpoints that are on. `/health`'s check list gains the database entry only when
metrics is on. So a Gloak with health alone serves the 120-byte index and the
two-check aggregate - and 1.1 measured that those are precisely what a Keycloak
started the same way serves.

**That is the move that turns "serve a subset" into "serve an option set".** The
distinction is the whole of section 2's argument: Gloak is not answering some of
Keycloak's management port and skipping the rest. It is answering all of
Keycloak's management port for one configuration, byte for byte, including the
part of that configuration that is an absence.

**Rejected alternative: serve the three-check document so the five aggregate
goldens match.** Gloak has a store and a `*sql.DB` behind it, so a database check
is genuinely computable, and doing it would have moved the meter by eleven rather
than six. It is refused on two grounds and either would be enough.

The first is that the coupling is a measured quirk. The database health check
appears only under `--metrics-enabled`; that is an artefact of how Quarkus
registers the Agroal binding, it looks like a bug, and AGENTS.md's governing rule
is that tidying one of those up breaks the one thing this project exists to do.
A Gloak whose index page lists only `/health` while its `/health` carries the
metrics-on check list would be **a pair of responses no Keycloak can produce** -
a divergence introduced to make a golden match, which is the worst available
reason to introduce one.

The second is that the check's failure branch could not be served honestly. 1.2
measured it: a `data` object carrying a wall-clock `Failing since`, which F113
bars from any golden. The UP branch would be checkable and the DOWN branch would
be bytes nobody had compared to anything.

`internal/management`'s `TestGloakPublishesNoDatabaseCheck` is that refusal made
into a test, because it is the one a later reader will most reasonably try to
"fix".

**Rejected alternative: re-record the chapter with `--health-enabled` alone**, so
the goldens become the ones Gloak serves and eleven cases go green. This is the
implementation moving the contract to fit itself. It would also discard the
three-check document, which is a real measurement of a real configuration, in
favour of a weaker one. The recorder keeps both options, and the eight cases
whose goldens hold the other set's bytes say so in their `Reason`.

**Rejected alternative: serve nothing and rewrite the reasons.** This was a
permitted outcome and it was live until 1.1 was measured. What killed it is that
the endpoint has a real consumer that is not speculative: a Gloak in Kubernetes
with `livenessProbe: :9000/health/live` gets a refused connection today. F38 asks
whether a mechanism has a consumer, and a deployment contract is one. What was
genuinely in doubt was whether Gloak could serve it truthfully - and 1.1, 1.3 and
1.4 answer that.

### 2.2 What is computed

**`Graceful Shutdown` is computed, and it is the only computed value on this
port.** It is UP until `gloak serve` receives SIGINT or SIGTERM and DOWN from
then until the process exits. Both of its documents are recordings rather than
inferences: the 200 in the ordinary state, and the 503 caught by polling a
Keycloak container through a real drain (1.2, 1.4).

It is a real predicate because `gloak serve` now really drains. The ordering in
`cmd/gloak` is the contract the check exists to publish and it is three
statements in one place: readiness goes DOWN first, the main server drains next,
the management interface is stopped **last** so `/health` answers 503 for the
whole drain rather than the probe's connection being refused. That is Keycloak's
order, measured.

The empty check lists on `/health/live`, `/health/started`, `/health/well`,
`/health/group` and `/health/group/{anything}` are **not constants and not
stubs**. Those documents are empty because no check is registered in those
groups, which is exactly why Keycloak's are: liveness, startup, wellness and the
health groups each have their own registry and Keycloak puts nothing in any of
them. Gloak putting nothing in them is the same statement, not a placeholder for
one - and 1.4 measured that they do not move during a drain either, which a stub
would have had no reason to get right.

### 2.3 What is a constant, and why this one is defensible

**`Keycloak Initialized` is a constant.** Its defence is that the constant was
measured rather than assumed, and the measurement is 1.3: 73395 polls across a
fresh container's entire startup produced two answers, and neither of them was
this check reporting DOWN. The management listener does not accept a connection
until it holds.

So `DOWN` is not an observable state of this check on this port. Gloak reproduces
that structurally rather than by luck: `cmd/gloak` opens the store and bootstraps
the master realm **before either listener starts**, so there is no instant at
which port 9000 answers and the realm is missing.

The alternative was a flag set after bootstrap, read on every request. That would
be a variable with one reachable value dressed as a predicate, and it would read
to the next person as though the DOWN branch had been thought about. A constant
with the measurement beside it says the true thing: this check has one observable
value, and here is the probe that says so.

**What would change it.** If Gloak ever brought the management listener up before
bootstrapping - which is a defensible design, and is why the check exists at all -
this becomes computed and needs the DOWN document for *this* check, which 1.2
does not carry. That is F257.

### 2.4 `internal/httpx` owns the bytes and `internal/management` owns the routing

The Boundaries table says `internal/httpx` owns **all** response body
formatting, and the one time a second writer appeared outside it the two diverged
on a trailing newline with no test noticing. So the three documents are written
there and the route table is in `internal/management`, which mirrors how
`internal/oidc` routes and `httpx` writes.

It matters more than usual here because the health document is **not** what
`encoding/json` produces. SmallRye renders an empty array as `[` newline four
spaces `]`, which is why five paths answer 45 bytes, and there is no trailing
newline. `MarshalIndent` gets both wrong. The writer is a template, and the check
name is still marshalled through `encoding/json` so a name holding a quote could
not break the document.

**Rejected alternative: one package.** The whole thing is about 130 lines and two
packages for 130 lines is a fair objection. It is refused because the boundary
rule is explicit and breaking it silently is how it got broken last time.

### 2.5 `Interface` holds the draining flag, not `cmd/gloak`

The Boundaries table says `cmd/gloak` must not contain logic worth testing on its
own, and "which check is DOWN while the process drains" is exactly that. So the
state is a `sync/atomic.Bool` on `management.Interface`, `cmd/gloak` wires a
signal to `BeginDraining` and nothing else, and the asymmetry in 1.4 is asserted
in a package test rather than by starting a process.

`BeginDraining` is idempotent, because a second signal during a drain must not
restart anything.

### 2.6 A management socket that cannot be bound stops the server

`gloak serve -health-enabled` takes the management socket with a synchronous
`net.Listen` before the main server starts, and a failure is returned rather than
logged.

Both halves were got wrong first and are worth recording. Logging and carrying on
leaves an operator who asked for a health endpoint without one - **and a
readiness probe aimed at a port nothing listens on is the exact failure this
endpoint exists to prevent**, so producing it silently is worse than not offering
the option. And binding inside the goroutine made the `management interface
listening` line print before the bind was known, so the log asserted something
hopeful; the first version of this code printed that line and then exited with
`address already in use` two lines later.

Verified against the built binary with a port held by another process: exit 1,
`gloak: management interface: listen tcp 127.0.0.1:19102: bind: address already
in use`, and no misleading log line.

## 3. The harness: what happened to the refusal, and what the verifier does

### 3.1 What the verifier does now

`serve` builds **both** of Gloak's servers for every case and the case decides
which its own request reaches:

```go
main := newFixture(t, f.State)
mgmt := newManagementFixture(t, f.State)
...
Target(main, mgmt, c).ServeHTTP(w, req)
```

Three properties, each deliberate.

**What starts it.** `newManagementFixture` builds `management.New().Handler()`.
It takes the fixture state and reads nothing from it, and that is measured rather
than lazy: Gloak's management interface reads no store, and nothing a fixture can
do reaches it - which is the same fact `Case.ManagementPort`'s third refusal
rests on from the recorder's side. The state is still validated, so an unknown
fixture is a failure here exactly as it is next door.

**What the case addresses.** `RecordTarget` is now `Target`, and it is generic:

```go
func Target[T any](main, management T, c Case) T
```

The recorder picks between two base URLs and the verifier picks between two
`http.Handler`s, and that is **one decision**, so it is one function. Written
twice it is two predicates that can drift, and the drift is silent in the worst
direction. The name changed because `RecordTarget` had come to name half of its
callers.

**How a case cannot be pointed at the wrong one.** Both handlers are built
unconditionally, for every case, so the branch inside `Target` is the only thing
that decides - building the management handler inside an `if c.ManagementPort`
would write the predicate a second time in the one place a second copy could be
wrong without anything failing. And three guards sit on it:

- `TestTargetFollowsTheFlag` runs the predicate over both instantiations, strings
  and handlers, including the row that stops it being "whichever value is
  non-empty", and over all three statuses - see 5.1, which is why that last set
  exists.
- `TestTheVerifierAnswersAManagementCaseFromTheManagementServer` sends
  `GET //health` to each handler and requires 400 `missingNormalization` from one
  and 200 with the health document from the other. **That is the same request,
  and the same disagreement, that made the old refusal true on Keycloak's two
  ports**, taken on Gloak's pair. A guard that only asked "are there two
  handlers?" would be satisfied by two handlers that are the same server; this is
  satisfied only by two that disagree the way the reference pair does.
- `TestServeSendsACaseToTheHandlerItsFlagNames` sends one path twice, differing
  only in the flag, and requires 200 from the management side and the main
  server's 404 from the other. It is the join the two tests above do not cover:
  dropping the branch from `serve` would leave both of them green.

### 3.2 The refusal was narrowed, not deleted, and here is what still refuses

`Case.ManagementPort`'s first refusal read: a management case may not be
`Implemented`, because the verifier has one handler and serves it to Gloak's main
mux. **Its ground is gone** - the verifier has two - so keeping it unchanged
would have been keeping a guard whose stated reason is false, which is how a
guard becomes furniture.

It was not deleted either. It now reads: **a `management/metrics` case may not be
`Implemented`**, with the measurement in the message - Gloak keeps no counters,
the only recordable responses are Micrometer's 406s whose success branch could
only be fabricated, and the dump moves 116 lines in three seconds so nothing on
it can be compared at all. That premise is true today and stays true until
somebody builds the counters.

**Both halves are asserted, which is the part that would otherwise be a claim in
a comment.** `TestManagementRefusalGuardCanFail` has a row for the metrics case
still being refused, a row for an `Implemented` health case now being allowed -
the lift - and a row proving the narrowing is to the **chapter** and not to one
case, which refuses a refusal keyed on a single id. M9 and M10 kill on those.

The two other refusals are unchanged, and one of them got heavier as this one got
lighter: a management case that does not declare the flag is now recorded from
the wrong server **and** verified against the wrong handler. Its message says so.

| What | Measurement | Status |
|---|---|---|
| A `management/metrics` case may not be `Implemented` | Gloak keeps no counters; the dump moves 116 lines in three seconds (F113); the 406's success branch could only be a fabricated dump | `managementDefects`, killed by M9 and M10 |
| A `ManagementPort` case must report under a `management/` chapter, and a `management/` case must declare the flag | Unchanged, and now covers the verifier as well as the recorder | `managementDefects`, killed by M16 |
| A `ManagementPort` case may not name a fixture that runs steps | Unchanged; nothing a step can do reaches this port | `managementDefects` |
| `Target` may not read a case's `Status` | Narrowing it to `Implemented` survived 26 subtests and would have had `make record` rewrite eight goldens from port 8080 | `TestTargetFollowsTheFlag`, killed by M8b - see 5.1 |
| Gloak may not publish a database health check | It is a function of `--metrics-enabled`, which Gloak does not have; and its DOWN carries a wall-clock `Failing since` | `TestGloakPublishesNoDatabaseCheck` |
| `gloak serve` may not accept `-metrics-enabled` | The same | `TestThereIsNoMetricsFlag` |
| `/metrics` and `/metrics/{suffix}` may not be `Recorded` | Unchanged - F113 | `Pending` |

## 4. The record diff, read file by file

`make record` was run because `record_test.go` carries the `docker` build tag and
`Target`'s one call site there is compiled by nothing in `make test`. That is M12
from the previous cut: a recorder change nothing can catch except a recording.

**The diff is empty. Zero files changed, out of 1135 rewritten.**

```
$ git status --porcelain -- internal/conformance/testdata | wc -l
0
```

Read file by file, which for an empty diff means reading what the run *did*
rather than what it left:

- **All fourteen management goldens were rewritten and all fourteen came back
  byte-identical.** The log names each one -
  `management/index/root.http` through `management/fallback/unknown-path.http` -
  so none of them was skipped into looking unchanged. This is the assertion the
  run exists to make: if `Target` had lost the management branch, those fourteen
  would have been re-recorded from port 8080 and the diff would have held
  fourteen files turning into the main port's unmatched-path 404.
- **The eight `Recorded` ones are the load-bearing half.** A `Recorded` case is
  required not to match, so nothing in `make test` can tell where its golden came
  from; these eight are the only evidence that the recorder still reaches port
  9000 for a case Gloak does not serve byte for byte. They are also exactly the
  eight M8 would have corrupted (5.1).
- **The six now `Implemented` were rewritten too**, because `GoldenIsAsserted` is
  true for both statuses, and came back identical - so the promotion moved no
  byte.
- **The 1121 goldens outside this chapter did not move**, which is the control.
  The only production change that could have reached them is `internal/httpx`
  gaining a file, and it gained functions rather than changing one; an empty diff
  across the rest of the tree is what says so.
- **Six cases were skipped for having no fixture** and twelve `Pending` goldens
  were left alone, both unchanged from the previous run's counts.

Forty containers, all fresh: one shared and one per `PristineRealm` case. The run
took 833 seconds and exited 0.

## 5. The mutation pass

Every mutation was applied to a committed tree, the **build** and `vet` run
before the tests so a compile error could not be read as a failing assertion, the
named test run, its **failure message** read rather than its name, and the revert
verified against a dirty check scoped to the package it mutates. The revert is on
a `trap ... EXIT`. The runner counts `=== RUN` lines and refuses a verdict when
none appeared, which it needed: M1c's first run named a test pattern the package
under `-run` did not hold and exited 0, which reads exactly like a survivor.

A production mutation was run against **the package that can kill it**, and for
this chapter that is usually `internal/conformance`, because the contracts are
goldens rather than handler tests. Where a mutation was run against both, both
verdicts are recorded, because they are not the same question.

| # | Mutation | Run against | Result |
|---|---|---|---|
| M1 | `/health/started` dropped from its group | `internal/management` | KILLED, but it **deletes a predicate**; redone as M1b |
| M1b | `/health/started` answers the **aggregate** | `internal/management` | KILLED - "body does not hold the empty document" |
| M1c | the same | `internal/conformance` | KILLED by the golden |
| M2 | `routePath` returns `p` | - | **not a kill** - did not compile, `path` unused |
| M2c | `routePath` computes the clean path and discards it | `internal/management` | KILLED - five routing rows |
| M2d | the same | `internal/conformance` | **SURVIVED, and stands** - 5.2 |
| M3 | `groupPrefix` is `/health/groups/` | `internal/conformance` | KILLED - "status: want 200, got 404" |
| M4 | one byte in the 53-byte 404 body | `internal/conformance` | KILLED - `management/fallback/unknown-path` |
| M5 | `WriteHealthDocument` never answers 503 | `internal/httpx` | KILLED - both the table and the direct test |
| M6 | the index page stops suppressing `Content-Type` | `internal/httpx` | KILLED - "sent `text/html; charset=utf-8`" |
| M7 | `BeginDraining` is a no-op | `internal/management` | KILLED - two tests |
| M8 | `Target` reads the case's `Status` | `internal/conformance` | **SURVIVED**; fixed; M8b KILLED - 5.1 |
| M9 | the metrics refusal inverted | `internal/conformance` | KILLED - three subtests |
| M10 | the refusal keyed on one case id | `internal/conformance` | KILLED - "prefix-match got 0 complaints" |
| M11 | the second fixture returns the first | - | **not a kill** - did not vet, import unused |
| M11b | the second fixture is built and discarded | `internal/conformance` | KILLED - all five Implemented health cases |
| M12 | a comment added to a route line (**control**) | `internal/management` | SURVIVED, correctly |
| M13 | `-health-enabled` defaults to on | `cmd/gloak` | KILLED - three subtests |
| M14 | the two checks swapped | `internal/management` | **SURVIVED, and stands** - 5.3 |
| M15 | `serve` ignores the flag | `internal/conformance` | KILLED - all five Implemented health cases |
| M16 | the chapter-without-the-flag arm disabled | `internal/conformance` | KILLED by the can-fail guard |
| M17 | both checks read the draining flag | `internal/management` | KILLED - "took the other check down too" |
| M18 | the health document's separator inverted | `internal/httpx` | KILLED - the byte table and the arity guard both |
| M19 | the health writer **adds** `X-Frame-Options` (additive) | `internal/conformance` | KILLED - all five Implemented health cases; see 5.5 |

### 5.1 M8 is the finding, and it would have corrupted eight goldens

Narrowing `Target` to `c.ManagementPort && c.Status == Implemented` compiled and
**survived 26 subtests, including the whole management chapter of
`TestConformance`**. It is the shape the brief named: a guard made silently wrong
while still appearing present.

Two things made it invisible, and both are worth writing down.

**`Implemented` is `iota`, so it is `Status`'s zero value.** Every row of
`TestTargetFollowsTheFlag` and the integration test beside it built a `Case`
without naming a status, so all of them went through the mutated branch
unchanged.

**A `Recorded` case is required *not* to match**, so the eight management cases
that the mutation sent to the main mux failed to match for entirely the wrong
reason and skipped exactly as they should. That is `account-api.md`'s rule -
a `Recorded` golden that is wrong is invisible - arriving on the *routing* rather
than on the bytes.

The consequence is not confined to the verifier. **The recorder reads the same
function.** With that mutation in the tree, `make record` would have re-recorded
those eight goldens from port 8080, and the diff would have looked like Keycloak
changing its mind about `/health`.

What closes it is a set of rows asserting that `Target`'s answer **does not
depend on the status**, run over all three, plus `Status: Recorded` written
explicitly on the integration test's management case. M8b kills on both.

### 5.2 M2d survived, and it is this chapter's shape rather than a defect

Making `routePath` compute the cleaned path and throw it away is killed by
`internal/management`'s route table and by **nothing in the conformance suite**.

The reason is structural. The one case that sends an unnormalised path,
`management/health/unnormalised-path`, is `Recorded` because its golden holds the
both-options document - so it is required not to match, and a Gloak that answered
`//health` with a 404 fails to match just as thoroughly as one that answers it
correctly.

**So three of this chapter's cross-cutting behaviours - the verb decides nothing,
`Accept` decides nothing, the path is not normalised - are served correctly by
Gloak and guarded only by a package test, not by a golden.** They would be
guarded by goldens if the recorder recorded the option set Gloak serves. That is
a concrete cost of F245 going unfixed, and it is F256.

### 5.3 M14 survived, and there is nothing to assert

Swapping the two checks changes the bytes Gloak serves and kills nothing.

It stands, and it stands on a measurement rather than on convenience.
`management-port.md` established that the aggregate's `checks` array has **no
reproducible order across container starts**: two containers from one image
returned the three entries two different ways. Pinning Gloak's order would assert
something Keycloak does not guarantee, which is why the five aggregate cases
carry `Unordered: []string{"checks"}` in the first place.

The split is where it should be: `internal/httpx` pins the **rendering** for a
given list, byte for byte and length for length, and `internal/management`
chooses the list - and what it chooses has no measured contract to be checked
against.

### 5.4 One arity has no recording, so it is asserted as a property

The byte table holds two checks and none, which are the two a `--health-enabled`
Keycloak serves. **One is the arity a separator gets wrong** and nothing measured
it. `TestHealthDocumentIsAlwaysJSON` walks zero to three and asserts that the
document parses and holds the entries it was given - a property rather than
bytes, because claiming bytes for an arity nobody recorded would be inventing a
contract, and claiming the output is JSON is not.

M18 inverted the separator and is killed by both, which is the point: the byte
table catches it at the arity that has a recording and the property catches it at
the arity that does not.

### 5.5 What the promotion bought, measured by an additive mutation

`AssertAbsentHeaders` on a `Recorded` case asserts nothing through `diff` - the
verdict is "these differ" and any one difference satisfies it - which is F177's
half-fix and is why `TestAssertAbsentHeadersAgreeWithTheGolden` exists at all.
All fourteen management cases sat in that hole before this cut.

M19 **adds** `X-Frame-Options` to the health writer, which is the additive shape
this project prefers because it cannot be mistaken for a deletion, and it is
killed by all five promoted health cases. So the six declarations that moved to
`Implemented` are now compared against **Gloak's own response** as well as
against the golden, and the widest security-header exception in this repository -
a whole listener carrying none of the five - is asserted on the served side for
the first time.

The eight still `Recorded` are not: their declarations are still checked against
the recorded bytes alone. That is another instance of F256 and it is the same
sentence twice, so it is counted once there.

## 6. Parity

```
base   598 of 677 enumerated behaviours served; 0 chapters not enumerated
head   604 of 677 enumerated behaviours served; 0 chapters not enumerated
```

```
management/index       0 served   1 recorded    1 documented   catalogue
management/health      5 served   5 recorded   10 documented   catalogue
management/metrics     0 served   2 recorded    4 documented   catalogue
management/fallback    1 served   0 recorded    1 documented   catalogue
```

**The numerator moves by exactly six and the denominator does not move at all.**
Those are the same fact counted twice and it is the check worth doing: a
denominator that moved would mean a case had been added or lost, and a numerator
moving by anything but six would mean something outside this chapter changed
status.

The six are the five health paths that answer the empty check list -
`live`, `started`, `well`, `group`, `group-unknown` - and
`management/fallback/unknown-path`. **The parity total does not fall.**

The eight that stay `Recorded` are not eight unserved behaviours. Gloak answers
every one of those paths, and correctly; the goldens hold the both-options
bytes. Each `Reason` now says which, and they read as measurements rather than as
"Gloak has no management interface", which is the sentence all fourteen carried
before this cut and which is no longer true of any of them.

## 7. What belongs in AGENTS.md

Phrased as it would be folded.

### Replacing the fourth bullet of the management-port block

> - **Gloak serves this port as a `--health-enabled`-only Keycloak serves it,
>   and that is one decision rather than a list of exceptions.** Gloak keeps no
>   counters, so it has no `--metrics-enabled`; a metrics-disabled container
>   answers `/metrics` with the ordinary 53-byte 404, serves a **120-byte** index
>   page listing `/health` alone, and answers `/health` with **two** checks
>   rather than three. All three were measured on 2026-09-16 and Gloak
>   reproduces all three. So eight of the fourteen management goldens hold the
>   other option set's bytes and stay `Recorded` - not because the path is
>   unserved, but because the recorder sets both options. See F245 and F256.

### A new bullet, beside the four `/health` paths

> - **A DOWN health check is not always a bare status, and the two measured
>   shapes disagree.** The datasource check gains
>   `"data": {"Failing since": "<yyyy-MM-dd HH:mm:ss,SSS>"}` when it fails -
>   measured by stopping the Postgres under a container - which is a per-request
>   value and therefore F113. The graceful-shutdown check's DOWN carries `status`
>   alone, measured by polling a container through `docker kill -s TERM`. The
>   aggregate answers **503** when any check is DOWN and `/health/live` stays
>   **200** through both, which is the split an orchestrator relies on.
>   **`Keycloak Initialized` is never observably DOWN**: 73395 polls across a
>   fresh container's whole startup gave two answers, no connection and the check
>   already UP, because the listener does not accept until it holds.

### For the management port's routing

> - **The path is cleaned on this port and never refused, and the rule is
>   `path.Clean` on the decoded path with `%2F` excepted.** `//health`,
>   `///health`, `/./health`, `/foo/../health` and `/%2e%2e/health` all answer
>   `/health`; `/health/..`, `/..` and `//` all answer the index; `/health%2Flive`
>   is a **404**, so the decode covers `%2E` and not `%2F`. `/health/group/` is a
>   prefix at any depth - `/health/group/a/b` is the 200 empty document where
>   `/health/x` one segment up is the 404. And the verb sweep understated
>   itself: `TRACE` answers the route's own 200 too, so the rule is not "seven
>   verbs" but "the verb is not read".

### For the Boundaries table

> | `internal/management` | the management interface's route table and its one piece of state | know about SQL, or write a response body itself |

> - **`internal/management` is a second server and deliberately shares no
>   middleware with the first.** It does not go through `WithKeycloakFallbacks`,
>   because every rule that wrapper applies - the normalisation 400, the five
>   security headers, the two fallback bodies - is a rule of one JAX-RS
>   application, and this is the other server in the same process. `GET //health`
>   is 400 on 8080 and 200 on 9000 of one container, and the verifier now
>   reproduces that pair on Gloak:
>   `TestTheVerifierAnswersAManagementCaseFromTheManagementServer`.

### For the build section, beside `make record`

> - **The verifier builds two handlers and `Target` decides which a case's own
>   request reaches.** It is the same generic function the recorder picks a base
>   URL with, so the two sides cannot come to disagree about which server a case
>   addresses, and it **must not read the case's `Status`** - narrowing it to
>   `Implemented` survived 26 subtests, because `Implemented` is `iota` and a
>   `Recorded` case is required not to match anyway, and it would have had
>   `make record` rewrite eight goldens from the wrong port.

### For the statuses section

> - **A `Recorded` case cannot guard the behaviour it records, on the routing as
>   well as on the bytes.** Three of the management chapter's cross-cutting
>   behaviours are served correctly by Gloak and caught by no golden, because
>   their goldens hold a different option set's document and so a Gloak that
>   answered them *wrongly* would fail to match just as thoroughly as one that
>   answers them right. A mutation disabling path cleaning survived the whole
>   conformance suite and was killed only by the package test. F256.

## 8. Containers

**Six, every one of them fresh**, all started for this session and all removed
after it.

| container | image | configuration | what it answered |
|---|---|---|---|
| 1 | keycloak:26.7.1 | both options | the both-options baseline, re-checked against the committed goldens |
| 2 | keycloak:26.7.1 | `KC_HEALTH_ENABLED` alone | **the option set this cut serves**: 1.1, 1.5, and the verb and route sweeps |
| 3 | postgres:16 | - | the database under container 4 |
| 4 | keycloak:26.7.1 | both options, `KC_DB=postgres` | the datasource check's DOWN document, by stopping container 3 |
| 5 | keycloak:26.7.1 | `KC_HEALTH_ENABLED` alone | the startup poll: 73395 polls, two answers (1.3) |
| 6 | keycloak:26.7.1 | `KC_HEALTH_ENABLED` alone | the drain poll across five paths (1.4) |

Containers 5 and 6 are separate because the startup question and the drain
question are different phases and the first one has to be asked from `docker
run` onwards. Container 6 is fresh rather than reusing 5 because 5 had been
terminated to answer its own question.

`make record` ran forty more, all fresh: one shared and one per `PristineRealm`
case. **Forty-six in total.**

## 9. Follow-ups, numbered from F256

F171-F255 are taken.

### F256 - a `Recorded` case cannot guard the routing it records

Three of this chapter's behaviours - the verb decides nothing, `Accept` decides
nothing, the path is not normalised - are served correctly and are guarded by
`internal/management`'s route table and by no golden. A mutation disabling path
cleaning survived the whole conformance suite (5.2).

The cause is that their goldens hold the both-options document, so the cases are
`Recorded`, so a wrong answer and a right one both fail to match. It is
`account-api.md`'s "a `Recorded` golden that is wrong is invisible" on a new axis:
here the *golden* is right and the **case** cannot see the difference either way.

What closes it is whatever closes F245 - a recorder that can record more than one
option set, or a line in the golden naming the configuration. Filed here rather
than folded into F245 because this is the first measured **consequence** of it,
and F245 has been filed as a cost with no instance since 2026-09-15.

### F257 - `Keycloak Initialized` is a constant because of a startup ordering choice

Gloak's management listener starts after the store is open and the master realm
is bootstrapped, which is what makes the check unfalsifiable and what makes the
constant honest (2.3). Keycloak's port behaves the same way, measured.

Bringing the listener up **first** is a defensible design and is arguably why the
check exists: a `gloak serve` against a slow database would then genuinely report
DOWN while it bootstrapped, and `/health/started` would mean something. Doing it
needs the DOWN document for **this** check, which 1.2 does not carry - only the
datasource check's DOWN was measured, and that one carries a `data` block this
one may or may not have.

So it is one measurement away rather than a design question, and the measurement
is awkward: it needs a Keycloak whose initialization is slow enough to poll, which
no container regime here produces.

### F258 - the drain window is as long as the drain and that may be too short to observe

Gloak's `Graceful Shutdown` check goes DOWN and the process exits as soon as the
main server has no work, which on an idle server is microseconds. Verified
against the built binary: one poll in several thousand caught the 503.

That is honest - the window is the drain - and it may be useless. Keycloak's
window is however long Quarkus takes to stop, which is seconds. Kubernetes reads
the readiness probe on an interval measured in seconds, so a Gloak that drains
instantly will never be observed draining.

Measured twice against the binary, and the two runs disagree in the way that
makes the point: the first caught the 503 once in several thousand polls, and the
second caught it **not at all** before the process was gone.

The fix is a minimum drain period before the main server is shut down, and the
reason to hesitate is that it is a number nobody has measured on Keycloak and a
server that refuses to exit promptly is its own problem. Filed with the question
rather than answered.

### F259 - `%2F` in a management path is decoded and Keycloak does not decode it

`/health%2Flive` is a **404** on Keycloak and the liveness document on Gloak,
measured. Keycloak's management router decodes `%2E` - `/%2e%2e/health` is the
health document - and does not decode `%2F` into a separator; Gloak routes on
`r.URL.Path`, which Go has already decoded fully.

No case sends it and nothing in the catalogue can. Closing it means routing on
`EscapedPath` with a per-segment unescape that leaves `%2F` alone, which is about
eight lines for a path nobody sends - so it is filed as a named divergence rather
than built, which is F38's rule applied. The neighbouring spellings are
unmeasured: `/health%2F` and `/%2Fhealth` were not probed.

### F260 - `HEAD` drops `Content-Type` on the 404 and keeps it on a route

`HEAD /health/live` carries `Content-Type` and `Cache-Control`; `HEAD
/nosuchpath` carries **no `Content-Type` at all**, where its own `GET` carries
`text/html; charset=utf-8`. Measured on the health-only container.

It cannot be cased, for F175's reason: the verifier serves through
`httptest.ResponseRecorder`, which does not strip a body for a `HEAD` where
`http.Server` does. Gloak's own behaviour here is net/http's and has not been
compared. Recorded so that the next person to look at `HEAD` on this port has the
measurement.

### F38 - the model this cut followed, and the one place it was argued rather than applied

`/metrics` is F38 applied without argument: no counters, no consumer, and a body
no golden can hold. What needed arguing is the other direction - `/health` has a
consumer that is not speculative, a deployment's liveness probe, and "we answer
nothing" there is a divergence rather than restraint. The entry's grounds hold in
both directions and this cut is the first to use the second one.

### F113 - unchanged, and reached from a new side

`/metrics` and its Prometheus-text form, as before. New: the **datasource health
check's DOWN document** carries a wall-clock `Failing since`, so even a health
document can be barred by this rule. It is the second reason Gloak publishes no
database check, and the first that is about a body rather than about an option.

### F169 - unchanged, and the precedent held a second time

The management port exists only under a startup option, and this cut's whole
answer turned on measuring **a second option set** rather than assuming the
recorded one was the only one. Reading "the goldens hold three checks" as "the
product has three checks" would have been F169's mistake exactly.

### F244 - closed

The verifier has two handlers, `serve` picks between them with the same predicate
the recorder uses, and `Case.ManagementPort`'s first refusal is narrowed to the
metrics chapter with the measurement that keeps it true. Section 3.

### F245 - unchanged, and now with a measured cost

Still filed, still not built. What this cut adds is that the cost is no longer
hypothetical: eight cases are `Recorded` purely because the recorder ran one
option set, three behaviours are guarded by no golden as a result (F256), and the
`Reason` strings now have to carry the explanation in prose.

### F246 - unchanged

The 406's non-standard reason phrase. Gloak serves no 406 on this port, so
nothing here touches it.

### F247, F248 - unchanged

Neither was re-tested and neither moved.

## 10. What is left

- **`/metrics` is not served and the decision is recorded rather than deferred.**
  Building it means building counters first; the two `Pending` cases stay barred
  by F113 whatever is built, and the two `Recorded` ones need an endpoint whose
  success branch is real.
- **The index page and the four aggregate documents cannot be `Implemented`
  without a second recorder configuration.** That is F245 and F256 and it is one
  problem, not five.
- **The six containers of section 1 are gone.** Anybody re-measuring starts
  fresh.
- **`internal/management` reads no store**, so if a later cut adds a check that
  does, `newManagementFixture` has to start sharing the fixture's store and its
  doc comment says so.
- **README.md's flag table is now incomplete and this branch may not edit it.**
  It lists six rows at lines 171-176 and `gloak serve` now takes eight. The two
  missing rows, phrased as the table phrases the rest:

  | flag | env | default | meaning |
  |---|---|---|---|
  | `-health-enabled` | `GLOAK_HEALTH_ENABLED` | off | serve the management interface, as Keycloak's `--health-enabled` does |
  | `-management-addr` | `GLOAK_MANAGEMENT_ADDR` | `:9000` | address the management interface listens on |

  Worth a sentence beside them that **off is Keycloak's default too**, and that
  there is deliberately no `-metrics-enabled` - `gloak serve -metrics-enabled` is
  a usage error, and `TestThereIsNoMetricsFlag` is what keeps it one.
