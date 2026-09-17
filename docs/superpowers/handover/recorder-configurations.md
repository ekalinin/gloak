# Recorder configurations, and the six goldens that were recordings of the wrong container

F245 and F256 are one problem and this cut takes them as one. The recorder
started every container with `--health-enabled` **and** `--metrics-enabled`;
Gloak serves the management port as a `--health-enabled`-only Keycloak serves
it; so eight goldens held the other option set's bytes, eight cases stayed
`Recorded`, and three cross-cutting behaviours Gloak answers correctly were
guarded by no golden at all.

**Six cases move to `Implemented`, the parity total goes from 604 to 610 of 677,
and the denominator does not move.** The other two of the eight are the metrics
family and they stay `Recorded` deliberately - section 5 is that measurement,
and it points the opposite way to what the arithmetic suggests.

Every golden in the tree now carries the command line it was recorded under.

## 1. The decision, and the alternatives in the terms they were offered

The brief offered three and asked which was taken and why. The answer is **the
first and the third together, with the third amended**, and the amendment is the
part worth arguing.

### 1.1 What was built

Three pieces, and they are one decision:

- **`Case.Configuration`** names the way the reference container is started.
  Empty means `DefaultConfiguration`, which is the both-options set every golden
  was already recorded under, so 1130 of the 1136 declare nothing.
- **The recorder keeps one container per configuration in use**, not one per
  case. `startKeycloak` takes a configuration and looks its environment up in
  `configurationEnv`; the shared pool is a `map[Configuration]ports` filled
  lazily, so a configuration nothing declares costs nothing. A `PristineRealm`
  case still gets its own container, started with its own configuration, so the
  two regimes compose.
- **`FormatGolden` writes the configuration into the file**, as a second comment
  line spelled the way a person would type the command:

  ```
  # GET /health
  # recorded-with: start-dev --health-enabled
  HTTP/1.1 200 OK
  ```

### 1.2 Rejected: the configuration on the `Case` and not in the file

The brief's option 2, and it is cheaper by 1136 lines. Refused on two grounds,
and the second is what decides it.

**The file is what the reviewer reads.** This project's central discipline is
that somebody reads the `make record` diff before it is committed - "that
reading is the last thing standing between a wrong contract and the
repository". This cut's own diff is the demonstration. Each of the six moved
goldens reads:

```
-# recorded-with: start-dev --health-enabled --metrics-enabled
+# recorded-with: start-dev --health-enabled
```

immediately above the bytes that moved. Without the line the reviewer sees six
bodies change and has to already know why. **A fact that decides a golden's
bytes and is not in the diff is a fact that discipline cannot use.**

**F250 is the half a `Case` field does not reach.** The management port's
dependency is visible - nothing on port 9000 exists without the option, so a
reader who wonders knows to ask. The theme resource route's `Cache-Control` is
not: `no-cache` on a static file reads as a property of the product, and a
reader has no reason to wonder at all. A field in `catalog_themes.go` answers
the question for somebody who has already asked it; the line answers the person
who has not, and that person is who F250 is about.

`themes/resource/served-file.http` now opens `# recorded-with: start-dev
--health-enabled --metrics-enabled`, so **F250's proposed fix is built**, even
though no `start` configuration is declared - nothing records anything under one
yet, and `TestTheTreeHoldsMoreThanOneConfiguration` refuses a declared
configuration no golden uses.

### 1.3 Rejected as insufficient on its own: a case gets a container started differently

The brief's option 3. It is the mechanism that was taken, with one amendment and
one addition.

**The amendment is the thing the brief said to check hardest.**
`PristineRealm` costs one container start per case, and the brief's fear was
that this would too. **It does not, and the reason is structural rather than an
optimisation.** `PristineRealm` needs a container per *case* because what it
guarantees is a realm nothing else has touched; two cases sharing one would
pollute each other, which is the defect F40 recorded. A configuration is a
property of the container that any number of cases can share - six cases
declaring `start-dev --health-enabled` want the same container, not six
identical ones. So the pool is keyed on the configuration, and the measured
cost of this cut is **one extra container start for the whole run**: 41 rather
than 40 (section 6).

The addition is 1.2: option 3 alone leaves the file silent, which is option 2's
defect with a container regime attached.

### 1.4 The fourth: the configuration belongs to the chapter

Worth stating because it is the shape a reader reaches for first, and it fails
inside the one chapter it would be written for. The management chapter's health
half must be recorded **without** `--metrics-enabled`, because that is the
option set Gloak serves; its metrics half must be recorded **with** it, because
Micrometer's content negotiation does not exist otherwise. A rule reading "all
the management cases go together" gets one of the two halves wrong, and it is
the half that looks most obviously right.

`TestConfigurationOfFollowsTheDeclaration` carries a row for exactly this: the
health and metrics ends of one chapter must not come back on one configuration.

### 1.5 The fifth: change the default to the option set Gloak serves

This is "re-record the chapter with `--health-enabled` alone", which
`serve-management-port.md` §2.1 already rejected as the implementation moving
the contract to fit itself. At the scale of a default it is worse: it moves 1136
goldens to answer a question six of them ask, and **a default that moves the
whole tree is a default nobody can review.** `DefaultConfiguration` is the
both-options set for that reason and the constant says so.

### 1.6 The sixth: record every case under every configuration

Two goldens per case, 1130 of them byte-identical pairs, and a denominator
question - is one behaviour measured twice one behaviour or two? - imported into
every chapter to settle a disagreement that exists in one.

### 1.7 The rule the declarations follow

A case is recorded under **the configuration in which the behaviour it documents
is observable, and where more than one qualifies, under the one Gloak serves.**
Both halves bite in the management chapter, and section 5 is where the second
half carries the whole argument.

### 1.8 One thing learned that is not about configurations

**A format change to every golden and a re-record must not be the same commit.**
The brief's own risk instruction is to read the whole `make record` diff file by
file, and a 1136-file format change makes that impossible on exactly the cut
that most needs it. So the branch is split:

- `8717f44` is the format change and the mechanism. **1136 files changed, 1136
  insertions, 0 deletions** - not one recorded byte moved, which is arithmetic
  rather than a claim.
- `aa6cbdd` is the re-record, and its golden diff is six files.

The rewrite in the first was mechanical rather than a recording, deliberately: a
re-record to change a format would have mixed the format's diff with whatever a
fresh container happened to disagree about. What proves the mechanical rewrite
produced exactly what the recorder would write is
`TestEveryGoldenRoundTripsThroughParseAndFormat`, which reads every committed
file, runs `ParseGolden` then `FormatGolden`, and requires the bytes back. That
test is worth more than the line it was built for: it also fences F246, because
a non-standard reason phrase cannot round-trip.

## 2. The guard the brief asked for, and what proves it bites

> Anything you build that decides *which container* a case is recorded against
> has [`Target`'s] shape, and it needs the same kind of guard.

`ConfigurationOf(c Case) Configuration` is that predicate. `Target`'s failure
mode was that narrowing it to `c.ManagementPort && c.Status == Implemented`
compiled, survived 26 subtests because `Implemented` is `Status`'s zero value
and a `Recorded` case is required not to match anyway, and would have had
`make record` rewrite eight goldens from the wrong port. The same narrowing is
available here and it is **worse**: a wrong answer starts a differently
configured container rather than connecting to the wrong socket of the right
one.

| Guard | What it refuses | Killed by |
|---|---|---|
| `TestConfigurationOfFollowsTheDeclaration` | the predicate reading `ManagementPort`, `Status` or the chapter - every combination of both flags and all three statuses, plus the health/metrics row | M1, M2 |
| `TestEveryGoldenNamesTheConfigurationItsCaseDeclares` | a file whose line disagrees with its case | M1, M3 |
| `TestGoldenConfigurationComparisonCanFail` | that comparison made silently wrong while still appearing present | M7 |
| `TestConfigurationEnvironmentsArePinned` | an entry added to or taken out of the environment table | M5 |
| `TestTheTreeHoldsMoreThanOneConfiguration` | a recorder that ignores the field and writes a constant; a declared configuration no golden uses | - |
| `TestTheIndexGoldenIsTheHealthOnlyPage`, `TestTheAggregateGoldenIsTheWireBytesAfterTheMask` | a golden whose **bytes** came from a container other than the one it names | M14, M15 |

The last row is the one that needed thinking about, and it is where the analogy
with `Target` stops being exact. The first two guards are both written from the
same value inside one run - the recorder starts the container from `cfg` and
writes `cfg` into the file - so between them they catch a declaration that moved
without a re-record and **not** a recorder that started the wrong container and
wrote the right line. What catches that is the content of the two
option-dependent responses: the index page lists exactly the endpoints that are
switched on, and the aggregate's check list gains an entry only when metrics is
on. Both are pinned against bytes read off a socket, with the socket's own
`content-length` as the guard that the transcription has not drifted.

**That pair is not hypothetical and it was observed firing twice.** Between the
catalogue change and the re-record the tree was in exactly the state a
wrong-container recording leaves behind, and both tests failed with the right
messages - the index golden reported *"lists /metrics ... while its case declares
start-dev --health-enabled"*, and the aggregate reported a 202-byte
normalisation against a 313-byte golden. M14 and M15 then put that state back
deliberately, one golden at a time, and both died.

**The honest limit**, stated here rather than left for a reader to find: the
recorder's own pool is in `record_test.go`, which carries the `docker` build tag,
so `make test` compiles none of it. M12 is that survivor and section 8.3 is what
it does and does not mean.

## 3. What the eight goldens became

| golden | before | after | why |
|---|---|---|---|
| `management/index/root` | `Recorded`, 180-byte both-options page | **`Implemented`**, 120-byte health-only page | recorded under `start-dev --health-enabled` |
| `management/health/check` | `Recorded`, three checks | **`Implemented`**, two checks | the same |
| `management/health/ready` | `Recorded`, three checks | **`Implemented`**, two checks | the same |
| `management/health/accept-ignored` | `Recorded`, three checks | **`Implemented`**, two checks | the same, and F256 |
| `management/health/wrong-verb` | `Recorded`, three checks | **`Implemented`**, two checks | the same, and F256 |
| `management/health/unnormalised-path` | `Recorded`, three checks | **`Implemented`**, two checks | the same, and F256 |
| `management/metrics/openmetrics-refused` | `Recorded`, Micrometer's 406 | **`Recorded`**, unchanged | section 5 |
| `management/metrics/prefix-match` | `Recorded`, Micrometer's 406 | **`Recorded`**, unchanged | section 5 |

**Checked rather than assumed.** `TestConformance` was run over the chapter
after the recording and all twelve non-metrics cases PASS - which for an
`Implemented` case means the bytes Gloak serves equal the bytes the golden
holds, header for header and body for body, under the case's masks. The four
metrics cases skip, two as `Recorded` and two as `Pending`.

```
--- PASS: TestConformance/management/index/root
--- PASS: TestConformance/management/health/check
--- PASS: TestConformance/management/health/ready
--- PASS: TestConformance/management/health/accept-ignored
--- PASS: TestConformance/management/health/wrong-verb
--- PASS: TestConformance/management/health/unnormalised-path
--- SKIP: TestConformance/management/metrics/openmetrics-refused
--- SKIP: TestConformance/management/metrics/prefix-match
```

**What the aggregate goldens lost.** The three-check document is no longer in
the golden tree, and that is a real loss rather than a tidy-up: it was the only
place in this repository where the option coupling - *a metrics flag decides
whether a health check exists* - was asserted rather than written in prose. It
is kept as a relation between two transcriptions instead, in
`TestTheTwoAggregateDocumentsDifferByTheMetricsCheck`: the 345-byte both-options
wire body and the 225-byte health-only one, each pinned to its socket-reported
length, with the assertion that the first is the second plus exactly the
`Keycloak database connections async health check` entry.

**A second case was considered and rejected.** `management/health/check-metrics-enabled`,
`Recorded` under the default configuration, would have kept the document as a
golden. It was refused because `Recorded` means *measured but not served yet*
and is a list that exists to empty itself, and Gloak will never serve this -
`TestGloakPublishesNoDatabaseCheck` is the assertion that it must not. A case
that can never clear is not `Recorded`'s shape, and it would have put a
behaviour nobody will ever serve into the chapter's denominator. The claim is
also not a response at all: it is the *difference* between two responses, which
no single golden can hold.

## 4. F256's three behaviours

F256 says three of this chapter's behaviours - the verb decides nothing,
`Accept` decides nothing, the path is not normalised - are served correctly and
guarded by `internal/management`'s route table and by no golden, because their
goldens held the both-options document and a `Recorded` case is required *not*
to match. A Gloak that answered them wrongly failed to match exactly as
thoroughly as one that answers them right.

**All three are guarded by a golden now**, because all three cases are
`Implemented`:

| behaviour | case | mutation that used to survive |
|---|---|---|
| the verb is not read | `management/health/wrong-verb` | M10 |
| `Accept` is not read | `management/health/accept-ignored` | M11 |
| the path is cleaned, never refused | `management/health/unnormalised-path` | M9b, which is the previous cut's M2d |

M9b is the one that closes the entry. `serve-management-port.md` §5.2 records
that making `routePath` compute the cleaned path and throw it away was killed by
`internal/management`'s route table and by **nothing in the conformance suite**.
The same mutation is run in section 8 and the verdict has changed.

F256 closes.

## 5. The metrics refusal: the measurement points the other way

The brief asked whether `Case.ManagementPort`'s remaining refusal - a
`management/metrics` case may not be `Implemented` - still holds under a
health-only recording, "rather than assuming either way".

**Measured, on a container started with `KC_HEALTH_ENABLED` alone, read off a
socket on 2026-09-17:**

```
GET /metrics
Accept: application/openmetrics-text

HTTP/1.1 404 Not Found
content-type: text/html; charset=utf-8
content-length: 53

<html><body><h1>Resource not found</h1></body></html>
```

So the arithmetic says the refusal should go: under `start-dev --health-enabled`
those two cases would record the ordinary 53-byte 404, Gloak answers exactly
that 404, the goldens would match, `TestConformance` would fail with *"already
matches the recorded Keycloak response - promote it"*, and two more cases would
go `Implemented`. That is 612 rather than 610.

**It would be false, and the refusal holds.** `management/metrics/openmetrics-refused`
documents that asking for the media type the endpoint serves by default is a
406, and `management/metrics/prefix-match` documents that `/metrics` is a prefix
route where `/health` is exact. Neither behaviour *exists* under the option set
Gloak serves. Recording them there does not measure them; it replaces them with
the fallback 404 that `management/fallback/unknown-path` already holds, and then
reports two behaviours served that nothing serves. The chapter's denominator
counts Keycloak's surface, not Gloak's ambition, and two rows of it would have
become a duplicate of a third row that is already green.

That is the implementation moving the contract to fit itself - the same
alternative `serve-management-port.md` §2.1 rejected, arriving through a new
door and looking like finishing the job rather than like giving up.

**So the refusal's premise is unchanged and a second refusal is added beside
it.** `managementDefects` gains a fourth arm: **a `management/metrics` case may
not be recorded under a configuration with no metrics endpoint.** It is keyed on
the container's *environment* rather than on the configuration's name, because
what the behaviour needs is the endpoint and not a spelling - a third
configuration switching metrics on under another name is served by this refusal
without anybody editing it. `TestManagementRefusalGuardCanFail` has a row for it
firing and two rows for it staying quiet, which is the half that a refusal keyed
on "any declared configuration" would get wrong.

The four refusals as they now stand:

| What | Measurement | Killed by |
|---|---|---|
| A `management/metrics` case may not be `Implemented` | Gloak keeps no counters; the dump moves 116 lines in three seconds (F113); the 406's success branch could only be a fabricated dump | M9 of the previous cut |
| A `management/metrics` case may not be recorded without `--metrics-enabled` | `/metrics` there is the 53-byte 404, measured 2026-09-17; the golden would hold the fallback and the case would match | M6 |
| A `ManagementPort` case must report under a `management/` chapter and vice versa | unchanged | M16 of the previous cut |
| A `ManagementPort` case may not name a fixture that runs steps | unchanged | - |

## 6. Containers

**Forty-two whose count is known, every one of them fresh**, and an interrupted
run whose count is not recoverable. Both halves are stated because the second is
the more useful entry.

| # | image | configuration | what it was for |
|---|---|---|---|
| 1 | keycloak:26.7.1 | `KC_HEALTH_ENABLED` alone | the measurements in 1.1 and section 5: the index page, the aggregate, `PUT /health`, `GET /health` with an `Accept`, `//health`, `/health/ready`, `/health/live` and `/metrics`, all read off a raw socket rather than through curl |
| 2-42 | keycloak:26.7.1 | 40 both-options, 1 health-only | `make record` |

Container 1 was started for the socket probes and removed. Containers 2-42 are
`make record`'s, counted from its own log: **41 starts, of which 40 are
`start-dev --health-enabled --metrics-enabled`** - one shared and 39
`PristineRealm` - **and exactly one is `start-dev --health-enabled`**, shared by
all six cases that declare it. The previous cut's run was 40, so the second
configuration cost one start for the whole run.

**An earlier `make record` was interrupted after 453 goldens and its log did not
survive, so how many containers it started cannot be stated and is not
guessed.** Two of them were still running when work resumed. They had served
those 453 cases' fixtures, so they were a written-to surface rather than a saved
start, and they were removed rather than reused - a container a partial run has
written to is not a clean measurement surface, and reusing one to save eight
minutes is how F40's shape arrives. **Nothing in this document rests on anything
that run produced**: the completed run rewrote all 1135 goldens from containers
it started itself, and section 7's diff is against the committed tree rather
than against that run's output.

## 7. The record diff, read file by file

`make record` exited 0 in 976.817 seconds. 1135 goldens were rewritten, 6 cases
were skipped for having no fixture and 12 `Pending` goldens were left alone -
the last two counts unchanged from the previous run.

**Six files moved, out of 1136.** Every one is explained by the configuration
and none by breakage.

| file | what moved | configuration or breakage |
|---|---|---|
| `management/index/root.http` | `# recorded-with:` line; the `<li>` naming `/metrics` leaves; body 180 → 120 bytes | **configuration.** The page lists exactly the endpoints that are switched on. The 120-byte body is byte-identical to what container 1 sent for `GET /` on a separate machine-start, so two independent containers agree. |
| `management/health/check.http` | `# recorded-with:` line; the `Keycloak database connections async health check` entry leaves; body 313 → 202 bytes | **configuration.** The socket sent 225 bytes and the `Unordered: ["checks"]` mask re-renders them to 202; container 1's `GET /health` sent exactly those 225 bytes. |
| `management/health/ready.http` | the same three lines | **configuration.** Readiness *is* the aggregate, which is this case's whole claim, so it had to move with it and did. |
| `management/health/accept-ignored.http` | the same three lines | **configuration.** `Accept: text/plain` is ignored under both option sets, so the body moved for the option set and not for the header - container 1 answered this request with the identical 225 bytes. |
| `management/health/wrong-verb.http` | the same three lines | **configuration.** `PUT /health` answers `/health`'s own 200 under both option sets; container 1 answered `PUT /health` with the identical 225 bytes. |
| `management/health/unnormalised-path.http` | the same three lines | **configuration.** `GET //health` answers `/health`'s 200 under both; container 1 answered it with the identical 225 bytes. |

Four things the diff says by **not** moving, and each is a control:

- **The two metrics goldens did not move.** They are the only management cases
  left on the default configuration, so an unchanged
  `management/metrics/openmetrics-refused` is the evidence that the pool really
  is keyed per case's declaration rather than switched globally. Had the
  recorder simply changed its options, those two would have become the 53-byte
  404 and the diff would have held eight files.
- **`management/health/live`, `started`, `well`, `group`, `group-unknown` and
  `fallback/unknown-path` did not move.** They were already `Implemented` under
  the old recording, which is the measured statement that those six responses
  are not functions of the option set. Six goldens agreeing across two
  configurations is worth more than the sentence saying so.
- **The 1130 goldens outside this chapter did not move.** The only thing that
  could have reached them is the format change, and that landed in its own
  commit with 1136 insertions and no deletions.
- **No `# recorded-with:` line moved except on those six.** The line is written
  from the same value the container was started with, so a line moving where a
  body did not - or the reverse - would be the first sign that the two had come
  apart.

## 8. The mutation pass

Every mutation was applied to a committed tree; the **build** and `vet` ran
before the tests so a compile error could not be read as a failing assertion;
the whole package was run rather than a filtered `-run`; the runner counted
`=== RUN` lines and refuses a verdict when none appeared; the **failure
message** was read rather than the test name; and the revert is on a
`trap ... EXIT` with a dirty check scoped to the package the mutation lives in.

A production mutation was run against the package that can kill it, and where
two packages could, both verdicts are recorded, because they are not the same
question.

| # | Mutation | Run against | Result |
|---|---|---|---|
| M1 | `ConfigurationOf` reads `ManagementPort` instead of the field | `internal/conformance` | KILLED - all six rows of `TestConfigurationOfFollowsTheDeclaration`, and the golden sweep |
| M2 | `ConfigurationOf` reads `Status` - the `Target` narrowing's exact shape | `internal/conformance` | KILLED - the `Recorded` and `Pending` rows, and `TestManagementRefusalGuardCanFail` |
| M3 | `FormatGolden` writes `DefaultConfiguration` rather than the golden's value | `internal/conformance` | KILLED |
| M4 | `ParseGolden` defaults a missing line to `DefaultConfiguration` (**additive**) | `internal/conformance` | KILLED - `TestGoldenConfigurationComparisonCanFail`'s silent-file row |
| M5 | `configurationEnv[StartDevHealth]` gains `KC_METRICS_ENABLED` (**additive**) | `internal/conformance` | KILLED - `TestConfigurationEnvironmentsArePinned` |
| M6 | the metrics refusal's environment lookup replaced outright | `internal/conformance` | KILLED, and **it proved nothing** - see below; re-formed as M6b |
| M6b | the metrics refusal keyed on the configuration's **name** rather than its environment | `internal/conformance` | **SURVIVED, and stands** - F262 |
| M7 | `goldenConfigurationFaults`' comparison made a no-op while still appearing present | `internal/conformance` | KILLED - `TestGoldenConfigurationComparisonCanFail` |
| M8a | `httpx.managementIndex` gains the `/metrics` line (**additive**) | `internal/httpx` | KILLED - the byte table |
| M8b | the same | `internal/conformance` | KILLED - `TestConformance/management/index/root` |
| M9a | `routePath` computes the clean path and discards it | `internal/management` | KILLED - the routing rows |
| M9b | the same - **the previous cut's M2d, which survived** | `internal/conformance` | **KILLED - `TestConformance/management/health/unnormalised-path`** |
| M10 | the health route answers the 404 to a verb that is not `GET` | `internal/conformance` | KILLED - `TestConformance/management/health/wrong-verb` |
| M11 | the health route reads `Accept` and answers the empty document | `internal/conformance` | KILLED - `TestConformance/management/health/accept-ignored` |
| M12 | the recorder's pool starts `DefaultConfiguration` whatever the case declares | `internal/conformance` | **SURVIVED** - the file carries the `docker` tag |
| M13 | a comment added to `configuration.go` (**control**) | `internal/conformance` | SURVIVED, correctly |
| M14 | `management/index/root.http` given the both-options body under the health-only line | `internal/conformance` | KILLED - `TestTheIndexGoldenIsTheHealthOnlyPage` and `TestConformance` |
| M15 | `management/health/check.http` given the three-check body under the health-only line | `internal/conformance` | KILLED - `TestTheAggregateGoldenIsTheWireBytesAfterTheMask`, `TestManagementHealthGoldensHoldTheDocumentTheyWereMeasuredTo` and `TestConformance` |

### 8.1 M9b, M10 and M11 are what close F256

Each dies on **its own case**, which is the whole of the entry. M9b is the one
worth naming: `serve-management-port.md` §5.2 recorded it as surviving the whole
conformance suite six days ago, with the reason - the case was `Recorded`, so it
was required not to match, so a Gloak answering `//health` with a 404 failed to
match exactly as thoroughly as one answering it correctly. The mutation is
byte-identical and the verdict has changed, because the case is `Implemented`
now.

### 8.2 M6 was a kill that proved nothing, and M6b is the finding

M6 replaced the refusal's `keycloakEnv` lookup outright, and the runner
reported KILLED. **Reading the failure message rather than the verdict is what
caught it**: the test that failed was the can-fail row, and it failed because the
mutation made a *different* complaint fire - the "no container environment is
declared" arm rather than the metrics one. That is a kill of "the mechanism
runs", which is the tautology AGENTS.md names, and it says nothing about the
rule.

M6b is the coherent wrong implementation: the refusal keyed on
`ConfigurationOf(c) == StartDevHealth` rather than on the container's
`KC_METRICS_ENABLED`, with the same message and the same behaviour on every
input that can be constructed today. It **survived**, and it stands, because the
two spellings can only be separated by a third configuration and
`TestTheTreeHoldsMoreThanOneConfiguration` refuses a configuration no golden
uses. F262 is the entry and it names the seam that would close it.

### 8.3 M12 survived and it is this harness's known shape

`sharedPorts` and `startKeycloak` live in `record_test.go`, which carries the
`docker` build tag, so **no test in `make test` compiles the file** - which is
exactly why `ConfigurationOf` and `configurationEnv` are outside it. It is the
previous cut's M12 arriving on a new function, and the remedy is the same: the
only thing that catches a recorder starting the wrong container is a recording,
read.

**What makes it narrower than it was** is M14 and M15. Those two put a
wrong-container body under a right-container line - which is exactly the file a
recorder with M12 applied would write - and both die, on three tests between
them. So M12 survives `make test` and cannot survive `make record` followed by
`make test`, which is the sequence a pull request runs anyway.

### 8.4 One mutation was refused before it was run

`routePath` returning `p` outright does not compile - `path` becomes an unused
import - which is the previous cut's M2 and is not a kill. M9 assigns the clean
path to `_` for that reason.

## 9. Parity

Reproduced by hand with the procedure AGENTS.md gives - two reports and
`cmd/parity`, the base taken from a worktree at `git merge-base main HEAD`:

```
base   604 of 677 enumerated behaviours served; 0 chapters not enumerated
head   610 of 677 enumerated behaviours served; 0 chapters not enumerated

Parity: 604 -> 610 of 677 (+6)

chapter                         before  after  delta
management/health                    5     10     +5
management/index                     0      1     +1
```

`cmd/parity` exited 0. **No other chapter moved**, which is the check that says
the six are the six and nothing else changed status on the way past.

```
management/index       1 served   0 recorded    1 documented   catalogue
management/health     10 served   0 recorded   10 documented   catalogue
management/metrics     0 served   2 recorded    4 documented   catalogue
management/fallback    1 served   0 recorded    1 documented   catalogue
```

**The numerator moves by exactly six and the denominator does not move at all**,
which are the same fact counted twice and the check worth doing: a denominator
that moved would mean a case was added or lost, and a numerator moving by
anything but six would mean something outside this chapter changed status.

**The rise is real rather than a relabelling**, and the distinction is worth
being explicit about because this cut is exactly the kind that could fake it.
Six cases went from `Recorded` to `Implemented` without a line of Gloak's
production code changing, which is what a relabelling looks like. What makes it
real is that a `Recorded` case is compared against nothing - the verifier
requires it *not* to match and any single difference satisfies that - while an
`Implemented` case is compared byte for byte. Before this cut those six goldens
held bytes no Gloak could ever serve, so the six cases asserted nothing about
Gloak in either direction; they assert the whole response now, and section 8's
M8b, M9b, M10 and M11 are four mutations that survived the suite before and die
in it after.

`management/health` reaching 10 of 10 is the whole chapter's health family
served and asserted. `management/metrics` stays 0 of 4 and section 5 is why.

## 10. What belongs in AGENTS.md

Phrased as it would be folded. Nothing here edits that file.

### Replacing the "this recorder's goldens are a function of how the container was started" bullet

> - **This recorder's goldens are a function of how the container was started,
>   and the golden now says how.** Two measured instances a week apart: the
>   whole `management` chapter exists only under `--health-enabled` or
>   `--metrics-enabled`, and the theme resource route's `Cache-Control` is
>   `no-cache` under `start-dev` and `max-age=2592000` under `start`. The first
>   is visible - nothing on port 9000 exists without the option - and **the
>   second is not**, because a `Cache-Control` header on a static file reads as
>   a property of the product. `Case.Configuration` names the container and
>   `FormatGolden` writes it into the file as `# recorded-with: <the command
>   line>`, so a golden says what it is a recording of and a re-record's diff
>   shows the configuration changing beside the bytes that changed with it.
>   1130 of the 1136 declare nothing and take the default, which is the
>   both-options set: **a default that moves the whole tree is a default nobody
>   can review.** F245 and F250.

### Replacing the fourth bullet of the management-port block

> - **Gloak serves this port as a `--health-enabled`-only Keycloak serves it,
>   and the recorder records it that way.** Gloak keeps no counters, so it has
>   no `--metrics-enabled`; a metrics-disabled container answers `/metrics` with
>   the ordinary 53-byte 404, serves a **120-byte** index page listing `/health`
>   alone, and answers `/health` with **two** checks rather than three.
>   Six of the fourteen management goldens are recordings of that option set and
>   all six cases are `Implemented`. The **two** that are not are the metrics
>   family, and they keep the both-options configuration on purpose: Micrometer's
>   content negotiation does not exist without the option, so recording them
>   where Gloak lives would replace a 406 with a 404 Gloak answers and report two
>   behaviours served that nothing serves.

### For the recorder's container regimes, beside `make record`

> - **`make record` runs one container per configuration and one per
>   `PristineRealm` case, and the two are different kinds of thing.** A pristine
>   container exists so that **no other case** has touched the realm, so it
>   cannot be shared; a configuration is a property of the container that any
>   number of cases share, so it is pooled. Forty-one starts for 1135 goldens:
>   one shared per configuration in use, thirty-nine pristine. Adding a
>   configuration costs one start for the whole run, not one per case.

### For the statuses section, replacing the `Recorded`-cannot-guard bullet

> - **A `Recorded` case cannot guard the behaviour it records, and the remedy is
>   usually a configuration rather than a mask.** Three of the management
>   chapter's cross-cutting behaviours - the verb decides nothing, `Accept`
>   decides nothing, the path is cleaned - were served correctly and caught by no
>   golden, because their goldens held a different option set's document and a
>   Gloak answering them *wrongly* failed to match just as thoroughly as one
>   answering them right. A mutation disabling path cleaning survived the whole
>   conformance suite. All three are `Implemented` now and all three mutations
>   die, because the cases were re-recorded against the container Gloak is
>   configured like. F256, closed.

### For the mutation section

> - **A guard written from the value the thing under test was built from cannot
>   catch that thing being built wrong.** The recorder starts a container from
>   `ConfigurationOf(c)` and writes `ConfigurationOf(c)` into the golden, so a
>   test comparing the file's line against the case catches a declaration that
>   moved without a re-record and **not** a recorder that started the wrong
>   container. What catches that is content that differs between the two
>   configurations - the index page's list of enabled endpoints, the aggregate's
>   check count - pinned against socket-read bytes with the socket's own
>   `content-length`. Ask of any declaration-versus-declaration test which of the
>   two it would notice being wrong.

### For the golden format

> - **A golden is a recording of a container, and the file names it.**
>   `FormatGolden` writes `# recorded-with: <command line>` as the second line
>   and `ParseGolden` reads it; a file carrying no such line parses with the
>   value **empty**, which is not a configuration any case can declare, so a
>   golden that predates the line reads as disagreeing rather than as agreeing by
>   default. `TestEveryGoldenRoundTripsThroughParseAndFormat` is what makes the
>   line mandatory without `ParseGolden` having to refuse one: every committed
>   file is re-formatted and the bytes are required back, which also fences F246
>   - a non-standard reason phrase cannot survive the round trip.

## 11. Follow-ups, numbered from F261

F171-F260 are taken.

### F261 - the configuration line is written from the value the container was started with, and nothing compares it to the container

`startKeycloak` takes `cfg`, and the recorder writes that same `cfg` into the
golden. If the environment table said something other than what the
configuration's name claims - `StartDevHealth` mapped to `KC_METRICS_ENABLED`,
say - every file would carry an honest-looking line naming a command line
nobody ran, and `TestEveryGoldenNamesTheConfigurationItsCaseDeclares` would be
green.

`TestConfigurationEnvironmentsArePinned` closes the table (M5 kills on it) and
the two content tests close the two responses that differ between the option
sets (section 2). What is **not** closed is the general case: a third
configuration whose responses happen not to differ anywhere a golden reaches
would be unfalsifiable, and a configuration's *name* is prose.

What would close it is the container answering for itself - Keycloak publishes
its build options on `/admin/serverinfo`, and `KC_METRICS_ENABLED` is observable
there. The recorder could assert the container it started matches the
configuration it was asked for, once per start. About fifteen lines, behind the
`docker` tag, and therefore untestable without Docker, which is the reason it is
filed rather than built.

### F262 - the metrics refusal is keyed on one environment variable name

The fourth arm of `managementDefects` reads `env["KC_METRICS_ENABLED"] != "true"`.
That is the right shape - the behaviour needs the endpoint, not a spelling - and
it is one string literal away from being wrong, because nothing compares that
literal to the one `configurationEnv` writes.

Measured by M6, which is the survivor in section 8: rewriting the refusal to key
on the configuration's **name** instead is observationally identical while only
two configurations exist, and it passes every row of
`TestManagementRefusalGuardCanFail`. The two spellings can only be separated by
a third configuration, and `TestTheTreeHoldsMoreThanOneConfiguration` refuses one
that no golden uses - so the input that would tell them apart cannot be
constructed without recording something.

A seam would close it: `managementDefects` taking the environment lookup as an
argument, the way it already takes the fixtures map for exactly this reason. It
is four lines and it was not done, because the refusal it protects has one
consumer and inventing a seam for a guard is how a guard becomes furniture.
Filed with the question rather than answered.

### F263 - no configuration is declared for `start`, so F250 is half-closed

`themes/resource/served-file` now says `# recorded-with: start-dev
--health-enabled --metrics-enabled`, which is what F250 asked for: the reader
who meets `Cache-Control: no-cache` on a static file is one line from the reason.
What is still true is that **only one of the two measured profiles is in the
tree.** `max-age=2592000` is a real contract of a real configuration and no
golden holds it.

Declaring `start` is not free the way `start-dev --health-enabled` was. A
production-mode container needs a database and a hostname, takes longer to
start, and every theme case that declared it would need its fixture to work
there. And `TestTheTreeHoldsMoreThanOneConfiguration` refuses a configuration no
golden uses, so it cannot be declared in advance of a case that wants it.

The question this leaves is whether the six theme 200s should move to `start` -
the profile a deployment runs - or stay on `start-dev` - the profile the rest of
the tree is recorded under. This cut has no opinion worth acting on and the
measurement is in F250.

### F264 - a configuration is a container's command line, and a container has more state than that

`Configuration` names `start-dev` plus two options. Three other things about the
recorder's container decide bytes and none of them is in the value:
`KC_BOOTSTRAP_ADMIN_USERNAME` and its password, which F252 records as the reason
the welcome page cannot be recorded at all; the image tag, which is pinned in
`startKeycloak` and not in the configuration; and the database, which is the
container's own H2 and is what mints the theme version segment (F23).

None of the three varies today, so widening the value would be a mask over
something that does not move - which is the inert-declaration shape this project
refuses. It is filed because the *next* configuration is quite likely to vary
one of them: a `start` container needs a real database, and at that point the
value has to say so or two goldens will name one configuration and come from two
different containers.

### F245 - closed

A golden says which configuration produced it, on every one of the 1136 files,
and the recorder can record more than one. The entry's stated cost - "a change
to `FormatGolden` and `ParseGolden` that every one of the 1119 files would take"
- was paid, and the arithmetic that made it worth paying is the one the entry
itself named: two chapters rather than one, and eight behaviours.

### F256 - closed

Section 4. All three behaviours carry `Implemented` cases, and the three
mutations that used to survive the conformance suite die in it.

### F250 - half-closed, see F263

The line names `start-dev`, so the profile is no longer invisible. The `start`
profile's bytes are still in no golden.

### F246 - fenced rather than fixed, and now it fails loudly

`FormatGolden` still writes `http.StatusText(g.Status)` and still loses a
non-standard reason phrase. What changed is that
`TestEveryGoldenRoundTripsThroughParseAndFormat` would now **fail** on a
committed golden carrying one, rather than the loss being silent. Nothing in the
tree carries one: `management/metrics/openmetrics-refused` is the one measured
instance and its golden holds `406 Not Acceptable`, which is the loss the entry
describes, committed before the round-trip test existed and passing it because
the file holds the recomputed phrase rather than the measured one.

### F249 - unchanged, and now refused rather than merely unlikely

The absent default listener is still expressible in no golden. What is new is
that a configuration with neither option **cannot be declared**: `startKeycloak`
refuses a configuration `configurationEnv` has no entry for, and
`TestConfigurationEnvironmentsArePinned` refuses `start-dev` with no options as
a declared one, with the measurement in its message.

### F40, F47 - unchanged, and the regimes compose

`PristineRealm` still gets a container per case and the configuration pool does
not touch it. A pristine case that declares a configuration gets a fresh
container started that way, which is one line in the recorder and is exercised
by nothing today - no `PristineRealm` case declares a configuration.

### F113 - unchanged, and it is the reason section 3's second case was not written

A `Failing since` timestamp keeps the datasource check's DOWN document out of
any golden, and the counter dump out of `/metrics`. It is also half the argument
against a `management/health/check-metrics-enabled` case: the three-check
document's UP branch is recordable and its DOWN branch is not, so a case for it
would be a contract for one of its two states.

### F247, F248, F251, F252, F253, F254, F255 - unchanged

None was re-tested and none moved.

## 12. What is left

- **`management/metrics` is 0 of 4 and stays there** until somebody builds
  counters. Two of the four are barred by F113 whatever is built.
- **The three-check aggregate is in no golden.** Section 3 says why and where the
  measurement went instead.
- **Every container of this cut is gone.** Anybody re-measuring starts fresh.
- **`README.md`'s flag table is still incomplete** and this branch may not edit
  it. `serve-management-port.md` §10 carries the two missing rows and they are
  unchanged.
- **Nothing declares `start`**, so the theme chapter's production-profile bytes
  are still unrecorded. F263.
