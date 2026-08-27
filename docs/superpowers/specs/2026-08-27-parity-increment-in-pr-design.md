# Reporting a pull request's parity increment

Date: 2026-08-27
Status: accepted

## 1. What this is

`make conformance` prints how much of Keycloak 26.7.1 Gloak serves. What it does
not say is how much a given change **moved** that number, and there is no way to
find out except running the meter on both sides and comparing by eye.

So the increment reaches a pull request the one way this project forbids
everywhere else: somebody types it. The last two pull requests both carried
hand-written parity numbers in their descriptions. Neither was wrong, and
neither was checked.

This document specifies a CI workflow that computes the increment and posts it,
and fails the build when the number goes down.

It is not an implementation plan; that follows.

## 2. What the meter does today

Measured by reading `internal/conformance/coverage_test.go` at `ecc2f0f`.

`TestCoverage` prints one row per chapter and a total line:

```
chapter                              served  recorded  documented  source
admin/role-mapper                         6         1          18  openapi 26.7.1
...
total: 100 of 485 enumerated behaviours served; 4 chapters not enumerated
```

Three properties of it constrain everything below.

**`served` is not one number's worth of arithmetic.** For a chapter with an
`OpenAPITag` it is `servedOperations(cases)`, distinct operations rather than
cases, so several cases on one endpoint do not read as several operations. For a
catalogue chapter it is the `Implemented` count. The comparison must therefore
compare the meter's own output, not recompute anything.

**Chapters nobody has counted print `?` and stay out of the total**, and the
total line says how many were left out. A comparison that summed rows would
silently include them.

**`TestCoverage` always passes.** Its doc comment says so: it exists to print,
so that a pending count which never moves is visible rather than buried. The
gate this document adds must therefore live outside it. Making the test fail on
a decrease would change a reporter into a guard and break the contract its own
comment states.

The output is `t.Logf`, visible only under `-v`, and every line carries a
`coverage_test.go:NN:` prefix whose numbers move when the file is edited. It is
a human table, and parsing it in a workflow would be building CI on prose.

## 3. Why not a checked-in report

The obvious alternative is to regenerate a report file, commit it, and let the
pull request's own diff show the movement. That option is closed, and closed on
purpose: `coverage_test.go`'s doc comment says the meter "prints rather than
writing a checked-in file: a generated file drifts from the tests that generate
it."

This design does not reopen it. The report it introduces is a **transient
artifact**, written to a path the caller names, never committed, and produced
twice within a single workflow run for the sole purpose of being compared. No
file in the repository claims to describe the meter's output. The rule stands.

That distinction is worth stating plainly, because the next reader will see
`TestCoverage` acquiring the ability to write a file and reasonably suspect the
rule was quietly dropped.

## 4. The machine-readable report

`TestCoverage` gains one behaviour: when `GLOAK_PARITY_REPORT` names a path, it
writes the same tally it prints, as tab-separated values, and continues to print
and to pass exactly as before. Unset, nothing changes.

The format is one row per chapter, then a total row:

```
chapter	served	recorded	documented	enumerated
admin/role-mapper	6	1	18	true
saml	0	0	0	false
total	100	485	4
```

`documented` is `0` for an unenumerated chapter and `enumerated` says which,
rather than writing `?` into a numeric column. The total row carries served,
documented, and the count of unenumerated chapters, taken from the same
variables the printed total line uses.

The report lives inside the test package because `internal/conformance` is
test-only and `AGENTS.md` forbids production code importing it. A `cmd/`
binary would have been more convenient to run and would have collided with that
boundary for the sake of convenience.

## 5. Comparing two reports

A new package, `internal/parity`, reads two reports and produces the difference.
It is ordinary Go with unit tests, and it knows nothing about GitHub.

Its input is two parsed reports; its output is a total delta, a per-chapter
delta for chapters that moved, and the lists of chapters that appeared or
disappeared. Chapters that did not move are not in the output, because a
comment carrying twenty-six unchanged rows in every pull request is a comment
nobody reads.

`internal/parity` does not import `internal/conformance`. It parses the report
format, which is the interface between them. That keeps the test-only boundary
intact and makes the comparison testable without a catalogue.

## 6. The workflow

One workflow on `pull_request`, one job, in this order:

1. `go build ./...`
2. `go vet ./...`
3. `CGO_ENABLED=0 go test ./...`
4. the meter on `HEAD`, into a report
5. the meter on the merge base with `main`, into a second report
6. compare, render, post

Steps 4 and 5 are the same invocation against two checkouts:

```
GLOAK_PARITY_REPORT=<path> CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage
```

No `-v`: the report goes to the file, and the printed table is not what is read.

Steps 1 to 3 are what the repository already requires of a contributor and
nothing more. **Nothing behind the `docker` build tag runs**: not the Postgres
driver suite, not `make oracle`, not `make record`. Those stay local, and this
document says so explicitly because the absence is the kind of thing a reader
infers wrongly. A green run does **not** mean the two store drivers agree; that
evidence still comes from running the Postgres suite by hand, as `AGENTS.md`
requires after touching either driver.

The base report comes from checking out the merge base and running the meter
there, rather than from a stored number. A stored number can go stale; a
checkout cannot.

## 7. The comment

One comment per pull request, updated in place on every push rather than
appended. It is found by a marker line so that a rewritten body cannot orphan
it.

It carries the total, the delta, and only the chapters that moved:

```
Parity: 100 -> 111 of 485 (+11)

chapter                        before  after  delta
admin/groups                        0      9     +9
admin/role-mapper                   6      8     +2
```

The numbers above are an illustration of the format, not a prediction.

A pull request that moves nothing gets a comment saying so in one line. That is
information: a change that was expected to move the meter and did not is worth
seeing.

## 8. The gate

The job fails when the total `served` **decreases**.

A decrease is either a regression or a decision, and this repository's standing
rule is that decisions get written down. The escape hatch is therefore a line in
the pull request body:

```
Parity-decrease: <reason>
```

When it is present the job passes and the comment quotes the reason, so the
justification lands beside the number rather than in a chat log. A label would
have been easier to apply and would have left nothing behind.

Only the total is gated. A per-chapter fall with a flat total is what moving a
case between chapters looks like, and gating it would fail honest
rearrangements.

## 9. What this deliberately does not do

**It does not list which operations were added.** The increment is the number
and the per-chapter breakdown; naming the operations was considered and dropped
as more text in every pull request than it earns. `Case.Operation` is already in
the catalogue if that changes.

**It does not gate `recorded`.** A case moving from `Recorded` to `Implemented`
raises `served`, which the total already shows.

**It does not touch the numbers stated by hand in `README.md` and the roadmap.**
Those are prose about a moment, and the roadmap's are deliberately a history.
Whether the README's should be generated is a separate question this document
does not answer.

## 10. Testing

`internal/parity` is unit-tested over the cases that matter: a rise, a fall, a
chapter appearing, a chapter disappearing, an unenumerated chapter staying `?`,
and two identical reports producing an empty diff. Its report parser is tested
against a malformed file, because a parser that silently returns zero would
turn a broken run into a reported parity of nothing.

The workflow stays a thin shell over that package. YAML is not tested, so as
little as possible should live in it: the workflow checks out, runs, and calls.
Every decision it makes is a decision that cannot be unit-tested.
