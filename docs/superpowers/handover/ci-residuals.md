# Handover: four residuals in the parity CI

Date: 2026-08-29
Branch: `fix/ci-residuals`
Owner of the files touched: `.github/workflows/ci.yml`, `internal/parity/`,
`cmd/parity/`, `Makefile`

Four things were left behind by the pull request that built the parity gate
(`docs/superpowers/specs/2026-08-27-parity-increment-in-pr-design.md`). None had
ever been filed; they existed only in a brief. This file exists so they are in
writing whatever was decided about them, and so the entries can be folded into
the documents this branch is not allowed to touch.

Three were fixed. One was **declined as stated** and the hazard underneath it
fixed instead - see F42, which is the one to read.

---

## Parity, before and after

| | served | documented | unenumerated chapters |
|---|---|---|---|
| before (`main`, `da212c4`) | 129 | 485 | 4 |
| after (this branch) | 129 | 485 | 4 |

Unchanged, and it has to be: nothing here touches `internal/conformance`, the
catalogue or any handler. The measurement is
`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -v -count=1`.

---

## The four follow-ups, ready to file

These continue the numbering in
`docs/superpowers/specs/2026-08-18-gloak-followups.md`, whose last entry is F40.

### F41: the parity comment's 403 tolerance identified the wrong thing (closed)

Found 2026-08-29, reading the workflow rather than a failing run.

The "Compare and comment" step grepped `gh`'s stderr for `HTTP 403` and, on a
match, wrote the comment to the run summary and let the job pass. The message it
wrote asserted the cause:

> The comment could not be posted: a pull request from a fork gets a read-only
> token, so the API answered 403.

Nothing had checked that. A fork's read-only `GITHUB_TOKEN` is one cause of a
403; a secondary rate limit is another, and a permission revoked at the
repository or organisation level is a third. Both of the other two are failures
of this repository's own configuration, both are worth a red build, and both
were swallowed under a sentence naming a cause that had not been established.
The failure mode is the bad one: the job goes green, the comment is not on the
pull request, and the summary explains it with a fact that is false.

Fixed by requiring `github.event.pull_request.head.repo.fork` as well, passed in
as `IS_FORK`, and by rewriting the message to say only what the two conditions
together establish. A 403 on a branch inside this repository now fails the job,
which is what a revoked permission should do.

Two things a later reader should know. `head.repo` is `null` when the fork has
been deleted, so `IS_FORK` arrives as the empty string and the tolerance does
not fire - the job goes red, which is the safe direction, but the message will
not say why. And the tolerance now also covers a refused **lookup**, not only a
refused post, because F42 routed both through one status.

Untested. It is YAML, and the design document (§10) says YAML is not tested.
What exists instead is a local simulation with `gh` and `cmd/parity` stubbed,
run against the old script and the new one; it is described under "What is
covered" below and it is not in the repository.

### F42: `set -o pipefail` was read as missing its `set -e`, and the real hazard was the opposite one (declined as stated, hazard fixed)

Found 2026-08-29.

**The claim, and why it is wrong.** The step opens `set -o pipefail` with no
`set -e`, which reads as half a pair. Adding `set -e` would have been a no-op
that misinforms: GitHub runs a `run:` step with no `shell:` key as
`bash -e {0}`, so `-e` is already on. (`shell: bash` written explicitly is
`bash --noprofile --norc -eo pipefail {0}` - a different command, which is why
the two are worth telling apart.) Writing `set -e` into the script would tell
the next reader that the line turned something on. It did not.

**The real hazard, which runs the other way.** With `-e` already on, `pipefail`
made the one pipeline in the step fatal:

```bash
id=$(gh pr view "$PR_NUMBER" --json comments --jq '...' | sed 's/.*#issuecomment-//')
```

That is a plain assignment, not part of an `||` list and not an `if` condition,
so `-e` applies to it. Without `pipefail` its status is `sed`'s, which always
succeeds. With `pipefail` it is `gh`'s. So a transient `gh pr view` failure
killed the step at that line - before the 403 fallback, before the
`status`-versus-`gh_status` precedence, and before `exit $status`. The parity
verdict the step exists to deliver was never reached.

And the other way round is worse. If `pipefail` were ever removed - or the step
moved somewhere `-e` is not set - the failed lookup yields an **empty** `id`,
which is also exactly what "no comment has been posted yet" yields. The two are
indistinguishable, so the step posts a second comment beside the one it could
not see and exits 0, against the design's "one comment per pull request, updated
in place" (§7). Measured on the old script under plain `bash`: exit 0, one
`POST` issued.

**Fixed** by guarding the lookup with its own `|| gh_status=$?`, sending its
stderr to the same `gh-err.txt` the post uses, and skipping the post when the
lookup failed. The failure now goes through the same handling as a refused post:
printed, tolerated on a fork's 403, fatal otherwise. The step's behaviour no
longer depends on which flags the platform happens to set, which is the property
a script wants when it does not set them itself.

`set -o pipefail` stays, and it is now load-bearing rather than inert: it is
what makes `gh`'s failure reach `gh_status` through `sed`.

### F43: `make lint` was weaker than the gate it stands in for (closed)

Found 2026-08-29.

`make lint` ran `go vet ./...`. CI runs that **and** `go vet -tags docker
./...`, because without a tag the docker-tagged files are not compiled at all
and `make record`, `make oracle` and the Postgres driver suite can stop building
unnoticed. So a contributor could run the target the repository offers, get
silence, and be broken by CI anyway - which is the specific way a local target
is worse than no target.

Fixed: `lint` runs both invocations, in CI's order.

Covered by nothing automated; it is a Makefile. It was run: `make lint` executes
both lines and exits 0 on this branch.

### F44: the parity comment said "no change" for work that changed something (closed)

Found 2026-08-29.

`internal/parity.Render` printed `Parity: N of M, no change.` whenever the
served total was equal, and then printed the table of chapters that moved
directly underneath it. For most pull requests those two never co-occur. For one
kind they always do.

Four chapters are **unenumerated**: nobody has counted their surface, they have
no denominator, and `TestCoverage` deliberately leaves them out of the total
rather than inflating the percentage by hiding the parts nobody has looked at.
Their `served` column is still written to the report and still compared. So a
pull request that serves new behaviour in one of them moves that chapter's row,
moves nothing in the total, and got a comment that read:

```
Parity: 129 of 485, no change.

chapter                         before  after  delta
saml                                 0      3     +3
```

Arithmetically right, and a contradiction on the page. The reader is left to
reconcile it alone, and the likeliest reconciliation - "the meter is broken" -
is wrong.

Fixed in `internal/parity`, which is ordinary Go with unit tests. `Compare` now
carries each moved chapter's `Enumerated` flag into `ChapterDelta`, taken from
the after side (the side the total was measured on) and from the before side for
a chapter that disappeared. `Diff.MovedOutsideTheTotal` reports whether every
chapter that moved is unenumerated. `Render` distinguishes three cases where
there was one:

- nothing moved: `Parity: 129 of 485, no change.` - unchanged wording, and it
  is now the only place it appears.
- a flat total with enumerated chapters moving, which is a rearrangement:
  `Parity: 129 of 485, total unchanged.` and the table.
- a flat total with only unenumerated chapters moving:
  `Parity: 129 of 485, total unchanged.`, the table, and a paragraph saying the
  work landed where the meter does not count.

The middle case matters as much as the third. Blaming the unenumerated chapters
for a rearrangement would replace one false statement with another, and a test
pins that it does not happen.

Covered by unit tests and mutation-tested: ten mutations of the new code, ten
killed. The list is under "What is covered" below.

---

## Proposed entries for `AGENTS.md`

Three edits, all in files this branch may not touch. They are written out so
they can be applied verbatim.

**1. In "Build and test", the `make lint` line.** The block near the top of the
section lists the targets. Nothing there says what `lint` runs, so nothing
drifted; the change is that the target is now the gate. Add to the CI bullet
(the one beginning "CI runs `build`, `vet` and `CGO_ENABLED=0 go test ./...`"),
after its second sentence:

> `make lint` runs both invocations too, so the local target and the gate are
> the same check. They were not, and a contributor who ran `make lint` and got
> silence could still be broken by CI.

**2. In the same CI bullet, on the comment.** Append:

> The comment is posted with the job's own token. A failure to post fails the
> job, with one exception: a 403 **on a pull request from a fork**, where the
> token is read-only whatever the workflow's `permissions` block says. That case
> falls back to the run summary and passes. The fork is read from
> `github.event.pull_request.head.repo.fork`, not inferred from the error text -
> a rate limit and a revoked permission are also 403s, they are this
> repository's own problem, and they go red.

**3. A new bullet, or a sentence on the reproduce-by-hand bullet.** The parity
comment's wording is a contract in the same weak sense the error strings are:

> **A flat parity total is not the same claim as "no change".** Four chapters
> have no denominator and are excluded from the total, so behaviour served in
> one of them moves a row and cannot move the total. The comment says
> "total unchanged" and names the reason for those, and reserves "no change"
> for a diff where nothing moved at all. `internal/parity`'s tests pin all
> three shapes.

Nothing in `README.md` or the roadmap needs a change: no number moved.

---

## What is covered by a test, and what is not

Stated plainly, because two of the four are in YAML and the design document says
YAML is not tested.

**Covered (F44).** `internal/parity` gained five tests -
`TestCompareCarriesWhetherAMovedChapterIsEnumerated`,
`TestCompareMixedMovesAreNotAllOutsideTheTotal`,
`TestCompareNothingMovedIsNotOutsideTheTotal`,
`TestRenderExplainsAFlatTotalWhenTheWorkIsUnenumerated`,
`TestRenderDoesNotBlameUnenumeratedChaptersForARearrangement` - and five
existing `ChapterDelta` literals gained the new field.

Mutation-tested, one mutation at a time against a committed tree, all ten
killed:

| mutation | result |
|---|---|
| `Compare` drops `Enumerated` on a chapter present on both sides | killed |
| `Compare` drops `Enumerated` on a disappeared chapter | killed |
| `MovedOutsideTheTotal` returns true for an empty diff | killed |
| `MovedOutsideTheTotal` ignores the flag it reads | killed |
| `MovedOutsideTheTotal` always false | killed |
| `MovedOutsideTheTotal` always true | killed |
| `Render` takes the "no change" branch again whenever the total is flat (the original defect, restored) | killed |
| `Render` drops the unenumerated explanation | killed |
| `Render` gives the unenumerated explanation for a rearrangement too | killed |
| `Render` never takes the arrow branch | killed |

**Not covered (F41, F42).** Both are shell inside `.github/workflows/ci.yml`.
Nothing in the repository executes them, and this branch does not claim they
work in CI.

What was done instead is a **local simulation**, in `/tmp` and not committed:
the step's `run:` block extracted from the YAML, `gh` and the `parity` binary
replaced with stubs, and the script run under `bash -e` the way GitHub runs it.
Eight scenarios, old script and new:

| scenario | old | new |
|---|---|---|
| existing comment, all good | exit 0, `PATCH` | exit 0, `PATCH` |
| no existing comment, all good | exit 0, `POST` | exit 0, `POST` |
| lookup fails 500, not a fork | exit 1 (script died at the assignment) | exit 1, error printed, no post |
| lookup 403 on a fork | **exit 1** (died before the fallback) | **exit 0**, summary fallback |
| post 403, **not** a fork | **exit 0**, summary asserting a fork | **exit 1** |
| post 403 on a fork | exit 0, summary | exit 0, summary |
| post fails 500 on a fork | exit 1 | exit 1 |
| parity exits 1, post succeeds | exit 1 | exit 1 |

And one run without `-e`, which is the world the residual assumed: the old
script exits **0** and posts a duplicate; the new one exits 1 and posts nothing.

That simulation is evidence about `bash`, not about GitHub Actions. It does not
prove the `IS_FORK` expression resolves, that `RUNNER_TEMP` is what is assumed,
or that a real `gh` spells a refusal `HTTP 403` on both API paths. The last of
those is the assumption the whole tolerance rests on and it is the one still
unverified; the previous pull request's comment on it is the only source.

**F43** is a Makefile. It was run and both lines execute.

---

## Anything left open

**The `HTTP 403` string match.** F41 gated the tolerance on the fork flag, which
is the part that was assertable. The other half of the condition is still a grep
for a substring of `gh`'s human-readable stderr, which is not a documented
interface. If a `gh` release rewords it, the tolerance stops firing and every
fork pull request goes red on a comment it was never able to post. Nothing
detects that. `gh api` does have `--include`, and a status line could be parsed
out of a header dump rather than out of prose; it was not done here because it
changes what the step captures on the success path too, and that is a bigger
change than a residual sweep should carry.

**Nothing was moved from YAML into Go.** The design document (§10) says as
little as possible should live in the workflow. The remaining decision in it is
`gh failed && is a fork && the error says 403`, three inputs and one boolean.
Moving that into a tested Go helper needs a second binary or a mode on
`cmd/parity`, whose own doc comment says it holds no logic of its own - and the
YAML would still have to marshal the three inputs into it correctly, untested.
That trades an untested predicate for an untested argument list plus a binary.
The judgement here was that it does not pay; it is recorded rather than assumed,
because the next person to look will have the same idea.
