# Reporting a pull request's parity increment: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compute the parity increment a pull request delivers, post it as a comment, and fail the build when the total falls.

**Architecture:** `TestCoverage` gains one behaviour: when `GLOAK_PARITY_REPORT` names a path it writes its tally as TSV, a transient artifact that is never committed. A new package `internal/parity` parses two such reports and diffs them, knowing nothing about GitHub and importing nothing from `internal/conformance`. One GitHub Actions workflow runs build, vet and the offline suite, then runs the meter against `HEAD` and against the merge base and posts the comparison.

**Tech Stack:** Go 1.26, `CGO_ENABLED=0`, GitHub Actions, `gh` CLI for the comment.

## Global constraints

From the spec `docs/superpowers/specs/2026-08-27-parity-increment-in-pr-design.md` and from `AGENTS.md`, which applies in full:

- **`TestCoverage` always passes.** Its doc comment says it exists to print so a pending count which never moves is visible rather than buried. The gate lives outside it; making the test fail on a decrease would break the contract its own comment states.
- **The report is transient.** `coverage_test.go`'s doc comment says the meter "prints rather than writing a checked-in file: a generated file drifts from the tests that generate it." Nothing this plan produces is committed, and `.gitignore` says so.
- **`internal/conformance` is test-only.** Production code must not import it. `internal/parity` parses the report format instead, and imports nothing from it.
- **Only the total is gated**, and only on a decrease. A per-chapter fall with a flat total is a case moving between chapters.
- **Nothing behind the `docker` build tag runs in CI**: not the Postgres driver suite, not `make oracle`, not `make record`.
- `CGO_ENABLED=0 go test ./...` must never need Docker or the network.
- `make test` is clean when each task finishes. Any failure is a real regression.
- Code comments in English. Minimal diff, existing names preserved.
- Commit messages `type(scope): subject`, type one of `feat`, `fix`, `docs`, `refactor`, `perf`, `chore`, `test`. No `Co-Authored-By`. No mention of any AI tool. Never an em dash; use a spaced hyphen.
- Never `git add -A`.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/conformance/coverage_test.go` | writes the TSV report when `GLOAK_PARITY_REPORT` is set; unchanged otherwise |
| `internal/parity/report.go` | **new** - the report format: the `Report` type and its parser |
| `internal/parity/report_test.go` | **new** - parser tests, including malformed input |
| `internal/parity/diff.go` | **new** - comparing two reports |
| `internal/parity/diff_test.go` | **new** - diff tests |
| `internal/parity/render.go` | **new** - rendering a diff as the comment body |
| `internal/parity/render_test.go` | **new** - render tests |
| `cmd/parity/main.go` | **new** - the CLI the workflow calls: parse two reports, render, set the exit code |
| `.github/workflows/ci.yml` | **new** - the workflow |
| `.gitignore` | keep report artifacts out of the repository |

`internal/parity` is split three ways because the three have different reasons to change: the format, the comparison, and the presentation. `cmd/parity` is a thin shell over them and holds no logic worth testing on its own, which is the same rule `AGENTS.md` states for `cmd/gloak`.

`cmd/parity` importing `internal/parity` is not the boundary `AGENTS.md` forbids. The forbidden import is production code importing `internal/conformance`; `internal/parity` does not import it, and neither does the command.

---

### Task 1: The report format and its parser

**Files:**
- Create: `internal/parity/report.go`
- Create: `internal/parity/report_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Chapter struct { Name string; Served, Recorded, Documented int; Enumerated bool }`
  - `type Report struct { Chapters []Chapter; Served, Documented, Unenumerated int }`
  - `func Parse(r io.Reader) (Report, error)`

The format is one header line, one row per chapter, then a `total` row:

```
chapter	served	recorded	documented	enumerated
admin/role-mapper	6	1	18	true
saml	0	0	0	false
total	100	485	4
```

Tabs separate fields. `documented` is `0` for an unenumerated chapter and `enumerated` says which, so no numeric column ever holds `?`.

- [ ] **Step 1: Write the failing test**

Create `internal/parity/report_test.go`:

```go
package parity

import (
	"strings"
	"testing"
)

const sample = "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
	"admin/role-mapper\t6\t1\t18\ttrue\n" +
	"saml\t0\t0\t0\tfalse\n" +
	"total\t100\t485\t4\n"

func TestParseReadsChaptersAndTotal(t *testing.T) {
	got, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Chapters) != 2 {
		t.Fatalf("want 2 chapters, got %d: %+v", len(got.Chapters), got.Chapters)
	}
	first := got.Chapters[0]
	if first.Name != "admin/role-mapper" || first.Served != 6 || first.Recorded != 1 ||
		first.Documented != 18 || !first.Enumerated {
		t.Fatalf("first chapter: %+v", first)
	}
	if second := got.Chapters[1]; second.Name != "saml" || second.Enumerated {
		t.Fatalf("second chapter: %+v", second)
	}
	if got.Served != 100 || got.Documented != 485 || got.Unenumerated != 4 {
		t.Fatalf("total: served %d, documented %d, unenumerated %d",
			got.Served, got.Documented, got.Unenumerated)
	}
}

// A parser that silently returns zero would turn a broken run into a reported
// parity of nothing, which is worse than a failure because it looks like data.
func TestParseRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name, in string
	}{
		{"empty", ""},
		{"header only", "chapter\tserved\trecorded\tdocumented\tenumerated\n"},
		{"no total row", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\t2\ttrue\n"},
		{"chapter row too short", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\ttrue\n" +
			"total\t1\t2\t0\n"},
		{"served not a number", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\tx\t0\t2\ttrue\n" +
			"total\t1\t2\t0\n"},
		{"enumerated not a bool", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\t2\tyes\n" +
			"total\t1\t2\t0\n"},
		{"total row too short", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\t2\ttrue\n" +
			"total\t1\t2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.in)); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestParse`
Expected: FAIL to build, `undefined: Parse`.

- [ ] **Step 3: Write the parser**

Create `internal/parity/report.go`:

```go
// Package parity compares two parity reports written by the conformance
// meter and renders the difference.
//
// It does not import internal/conformance. The report format is the interface
// between the two, which keeps the meter's test-only boundary intact and makes
// the comparison testable without a catalogue.
package parity

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Chapter is one row of a report.
type Chapter struct {
	Name       string
	Served     int
	Recorded   int
	Documented int
	// Enumerated is false for a chapter whose surface nobody has counted.
	// Documented is 0 for those, and they are excluded from the total.
	Enumerated bool
}

// Report is one run of the meter.
type Report struct {
	Chapters []Chapter
	// Served and Documented are the totals the meter prints, not a sum of
	// the rows: an unenumerated chapter contributes to neither.
	Served       int
	Documented   int
	Unenumerated int
}

const header = "chapter\tserved\trecorded\tdocumented\tenumerated"

// Parse reads a report. Every malformed shape is an error rather than a zero
// value, because a zero report is indistinguishable from a real one that
// happens to serve nothing.
func Parse(r io.Reader) (Report, error) {
	var out Report
	sc := bufio.NewScanner(r)

	if !sc.Scan() {
		return Report{}, fmt.Errorf("parity: empty report")
	}
	if line := sc.Text(); line != header {
		return Report{}, fmt.Errorf("parity: want header %q, got %q", header, line)
	}

	seenTotal := false
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if fields[0] == "total" {
			if len(fields) != 4 {
				return Report{}, fmt.Errorf("parity: total row has %d fields, want 4", len(fields))
			}
			var err error
			if out.Served, err = strconv.Atoi(fields[1]); err != nil {
				return Report{}, fmt.Errorf("parity: total served: %w", err)
			}
			if out.Documented, err = strconv.Atoi(fields[2]); err != nil {
				return Report{}, fmt.Errorf("parity: total documented: %w", err)
			}
			if out.Unenumerated, err = strconv.Atoi(fields[3]); err != nil {
				return Report{}, fmt.Errorf("parity: total unenumerated: %w", err)
			}
			seenTotal = true
			continue
		}
		if len(fields) != 5 {
			return Report{}, fmt.Errorf("parity: chapter %q has %d fields, want 5", fields[0], len(fields))
		}
		ch := Chapter{Name: fields[0]}
		var err error
		if ch.Served, err = strconv.Atoi(fields[1]); err != nil {
			return Report{}, fmt.Errorf("parity: %s served: %w", ch.Name, err)
		}
		if ch.Recorded, err = strconv.Atoi(fields[2]); err != nil {
			return Report{}, fmt.Errorf("parity: %s recorded: %w", ch.Name, err)
		}
		if ch.Documented, err = strconv.Atoi(fields[3]); err != nil {
			return Report{}, fmt.Errorf("parity: %s documented: %w", ch.Name, err)
		}
		if ch.Enumerated, err = strconv.ParseBool(fields[4]); err != nil {
			return Report{}, fmt.Errorf("parity: %s enumerated: %w", ch.Name, err)
		}
		out.Chapters = append(out.Chapters, ch)
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("parity: read report: %w", err)
	}
	if len(out.Chapters) == 0 {
		return Report{}, fmt.Errorf("parity: report has no chapters")
	}
	if !seenTotal {
		return Report{}, fmt.Errorf("parity: report has no total row")
	}
	return out, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestParse -v`
Expected: PASS, both tests and all seven malformed sub-cases.

- [ ] **Step 5: Commit**

```bash
git add internal/parity/report.go internal/parity/report_test.go
git commit -m "feat(parity): the report format and its parser"
```

---

### Task 2: Diffing two reports

**Files:**
- Create: `internal/parity/diff.go`
- Create: `internal/parity/diff_test.go`

**Interfaces:**
- Consumes: `Report` and `Chapter` from Task 1.
- Produces:
  - `type ChapterDelta struct { Name string; Before, After int }`
  - `type Diff struct { BeforeServed, AfterServed, Documented int; Moved []ChapterDelta; Appeared, Disappeared []string }`
  - `func Compare(before, after Report) Diff`
  - `func (d Diff) Delta() int`
  - `func (d Diff) Decreased() bool`

Only chapters whose `Served` changed appear in `Moved`, sorted by name. A comment carrying twenty-six unchanged rows in every pull request is a comment nobody reads.

- [ ] **Step 1: Write the failing test**

Create `internal/parity/diff_test.go`:

```go
package parity

import (
	"slices"
	"testing"
)

func report(served, documented int, chapters ...Chapter) Report {
	return Report{Chapters: chapters, Served: served, Documented: documented}
}

func chapter(name string, served int) Chapter {
	return Chapter{Name: name, Served: served, Documented: 20, Enumerated: true}
}

func TestCompareReportsOnlyChaptersThatMoved(t *testing.T) {
	before := report(6, 485, chapter("admin/roles", 6), chapter("admin/users", 14))
	after := report(15, 485, chapter("admin/roles", 6), chapter("admin/users", 23))

	got := Compare(before, after)

	if got.BeforeServed != 6 || got.AfterServed != 15 || got.Delta() != 9 {
		t.Fatalf("totals: before %d, after %d, delta %d", got.BeforeServed, got.AfterServed, got.Delta())
	}
	want := []ChapterDelta{{Name: "admin/users", Before: 14, After: 23}}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}

func TestCompareIdenticalReportsMovesNothing(t *testing.T) {
	r := report(6, 485, chapter("admin/roles", 6))

	got := Compare(r, r)

	if got.Delta() != 0 {
		t.Fatalf("want delta 0, got %d", got.Delta())
	}
	if len(got.Moved) != 0 || len(got.Appeared) != 0 || len(got.Disappeared) != 0 {
		t.Fatalf("want an empty diff, got %+v", got)
	}
	if got.Decreased() {
		t.Fatal("an unchanged total is not a decrease")
	}
}

func TestCompareNamesChaptersThatAppearedAndDisappeared(t *testing.T) {
	before := report(6, 485, chapter("admin/roles", 6), chapter("admin/gone", 0))
	after := report(6, 500, chapter("admin/roles", 6), chapter("admin/new", 0))

	got := Compare(before, after)

	if want := []string{"admin/new"}; !slices.Equal(got.Appeared, want) {
		t.Fatalf("appeared: want %v, got %v", want, got.Appeared)
	}
	if want := []string{"admin/gone"}; !slices.Equal(got.Disappeared, want) {
		t.Fatalf("disappeared: want %v, got %v", want, got.Disappeared)
	}
	// A chapter that appeared serving nothing has not moved.
	if len(got.Moved) != 0 {
		t.Fatalf("moved: want none, got %+v", got.Moved)
	}
}

// A chapter appearing with a non-zero served count is both new and a move, and
// the comment has to show the number rather than only the name.
func TestCompareCountsAnAppearingChapterThatAlreadyServes(t *testing.T) {
	before := report(0, 485, chapter("admin/roles", 0))
	after := report(9, 505, chapter("admin/roles", 0), chapter("admin/groups", 9))

	got := Compare(before, after)

	want := []ChapterDelta{{Name: "admin/groups", Before: 0, After: 9}}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}

func TestCompareDetectsADecrease(t *testing.T) {
	before := report(15, 485, chapter("admin/users", 15))
	after := report(12, 485, chapter("admin/users", 12))

	got := Compare(before, after)

	if !got.Decreased() {
		t.Fatal("want a decrease")
	}
	if got.Delta() != -3 {
		t.Fatalf("want delta -3, got %d", got.Delta())
	}
}

// An unenumerated chapter has no denominator and contributes to no total; it
// must not appear as a move when its served count is unchanged.
func TestCompareIgnoresAnUnchangedUnenumeratedChapter(t *testing.T) {
	saml := Chapter{Name: "saml", Served: 0, Documented: 0, Enumerated: false}
	before := report(6, 485, chapter("admin/roles", 6), saml)
	after := report(6, 485, chapter("admin/roles", 6), saml)

	if got := Compare(before, after); len(got.Moved) != 0 {
		t.Fatalf("moved: want none, got %+v", got.Moved)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestCompare`
Expected: FAIL to build, `undefined: Compare`.

- [ ] **Step 3: Write the comparison**

Create `internal/parity/diff.go`:

```go
package parity

import (
	"cmp"
	"slices"
)

// ChapterDelta is one chapter whose served count changed.
type ChapterDelta struct {
	Name   string
	Before int
	After  int
}

// Diff is what changed between two runs of the meter.
type Diff struct {
	BeforeServed int
	AfterServed  int
	// Documented is the after side's denominator. It moves when a chapter is
	// added to the catalogue, which is why the comment prints it rather than
	// assuming it is constant.
	Documented int

	// Moved holds only the chapters whose served count changed, sorted by
	// name. Chapters that did not move are left out: a comment carrying
	// every unchanged row in every pull request is one nobody reads.
	Moved []ChapterDelta

	Appeared    []string
	Disappeared []string
}

// Delta is the change in the total served count.
func (d Diff) Delta() int { return d.AfterServed - d.BeforeServed }

// Decreased reports whether the total fell. It is the only gated condition:
// a per-chapter fall with a flat total is what moving a case between chapters
// looks like, and gating that would fail honest rearrangements.
func (d Diff) Decreased() bool { return d.Delta() < 0 }

// Compare diffs two reports. A chapter present on only one side is named in
// Appeared or Disappeared, and also counts as a move when its served count
// differs from the zero it implicitly had on the other side.
func Compare(before, after Report) Diff {
	out := Diff{
		BeforeServed: before.Served,
		AfterServed:  after.Served,
		Documented:   after.Documented,
	}

	was := make(map[string]Chapter, len(before.Chapters))
	for _, ch := range before.Chapters {
		was[ch.Name] = ch
	}
	is := make(map[string]Chapter, len(after.Chapters))
	for _, ch := range after.Chapters {
		is[ch.Name] = ch
	}

	for _, ch := range after.Chapters {
		old, existed := was[ch.Name]
		if !existed {
			out.Appeared = append(out.Appeared, ch.Name)
		}
		if old.Served != ch.Served {
			out.Moved = append(out.Moved, ChapterDelta{
				Name:   ch.Name,
				Before: old.Served,
				After:  ch.Served,
			})
		}
	}
	for _, ch := range before.Chapters {
		if _, still := is[ch.Name]; !still {
			out.Disappeared = append(out.Disappeared, ch.Name)
		}
	}

	slices.SortFunc(out.Moved, func(a, b ChapterDelta) int { return cmp.Compare(a.Name, b.Name) })
	slices.Sort(out.Appeared)
	slices.Sort(out.Disappeared)
	return out
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestCompare -v`
Expected: PASS, all six tests.

- [ ] **Step 5: Commit**

```bash
git add internal/parity/diff.go internal/parity/diff_test.go
git commit -m "feat(parity): compare two reports"
```

---

### Task 3: Rendering the comment

**Files:**
- Create: `internal/parity/render.go`
- Create: `internal/parity/render_test.go`

**Interfaces:**
- Consumes: `Diff`, `ChapterDelta` from Task 2.
- Produces:
  - `const Marker = "<!-- gloak-parity -->"`
  - `func Render(d Diff, decreaseReason string) string`

`decreaseReason` is empty unless the pull request body carried a `Parity-decrease:` line. When the total fell and a reason was given, the comment quotes it, so the justification lands beside the number.

- [ ] **Step 1: Write the failing test**

Create `internal/parity/render_test.go`:

```go
package parity

import (
	"strings"
	"testing"
)

func TestRenderCarriesTheMarkerAndTheTotals(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 111, Documented: 485,
		Moved: []ChapterDelta{{Name: "admin/groups", Before: 0, After: 9}}}

	got := Render(d, "")

	if !strings.HasPrefix(got, Marker) {
		t.Fatalf("want the marker first so the comment can be found again:\n%s", got)
	}
	if !strings.Contains(got, "100 -> 111 of 485 (+11)") {
		t.Fatalf("want the totals line:\n%s", got)
	}
	if !strings.Contains(got, "admin/groups") {
		t.Fatalf("want the moved chapter:\n%s", got)
	}
}

func TestRenderSaysSoWhenNothingMoved(t *testing.T) {
	got := Render(Diff{BeforeServed: 100, AfterServed: 100, Documented: 485}, "")

	if !strings.Contains(got, "no change") {
		t.Fatalf("want an explicit no-change line:\n%s", got)
	}
	// A change expected to move the meter and did not is worth seeing, so the
	// totals still appear.
	if !strings.Contains(got, "100 of 485") {
		t.Fatalf("want the total even when flat:\n%s", got)
	}
}

func TestRenderShowsADecreaseAndItsReason(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 97, Documented: 485,
		Moved: []ChapterDelta{{Name: "admin/users", Before: 14, After: 11}}}

	got := Render(d, "the users listing moved behind P4")

	if !strings.Contains(got, "(-3)") {
		t.Fatalf("want a signed delta:\n%s", got)
	}
	if !strings.Contains(got, "the users listing moved behind P4") {
		t.Fatalf("want the reason quoted:\n%s", got)
	}
}

func TestRenderNamesChaptersThatAppearedAndDisappeared(t *testing.T) {
	d := Diff{BeforeServed: 6, AfterServed: 6, Documented: 500,
		Appeared: []string{"admin/new"}, Disappeared: []string{"admin/gone"}}

	got := Render(d, "")

	if !strings.Contains(got, "admin/new") || !strings.Contains(got, "admin/gone") {
		t.Fatalf("want both named:\n%s", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestRender`
Expected: FAIL to build, `undefined: Render`.

- [ ] **Step 3: Write the renderer**

Create `internal/parity/render.go`:

```go
package parity

import (
	"fmt"
	"strings"
)

// Marker leads every comment this renders, so the workflow can find the one it
// posted before and update it rather than appending a second.
const Marker = "<!-- gloak-parity -->"

// Render turns a diff into the comment body. decreaseReason is the text of the
// pull request's Parity-decrease line, empty when there is none.
func Render(d Diff, decreaseReason string) string {
	var b strings.Builder
	b.WriteString(Marker)
	b.WriteString("\n\n")

	switch {
	case d.Delta() == 0:
		fmt.Fprintf(&b, "Parity: %d of %d, no change.\n", d.AfterServed, d.Documented)
	default:
		fmt.Fprintf(&b, "Parity: %d -> %d of %d (%+d)\n",
			d.BeforeServed, d.AfterServed, d.Documented, d.Delta())
	}

	if len(d.Moved) > 0 {
		b.WriteString("\n```\n")
		fmt.Fprintf(&b, "%-30s  %6s  %5s  %5s\n", "chapter", "before", "after", "delta")
		for _, m := range d.Moved {
			fmt.Fprintf(&b, "%-30s  %6d  %5d  %+5d\n",
				m.Name, m.Before, m.After, m.After-m.Before)
		}
		b.WriteString("```\n")
	}

	if len(d.Appeared) > 0 {
		fmt.Fprintf(&b, "\nNew chapters: %s\n", strings.Join(d.Appeared, ", "))
	}
	if len(d.Disappeared) > 0 {
		fmt.Fprintf(&b, "\nChapters gone: %s\n", strings.Join(d.Disappeared, ", "))
	}

	if d.Decreased() {
		if decreaseReason != "" {
			fmt.Fprintf(&b, "\nThe total fell, and the pull request gives a reason:\n\n> %s\n",
				decreaseReason)
		} else {
			b.WriteString("\nThe total fell and no reason was given. " +
				"Add a `Parity-decrease: <reason>` line to the description.\n")
		}
	}

	return b.String()
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/parity/ -run TestRender -v`
Expected: PASS, all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/parity/render.go internal/parity/render_test.go
git commit -m "feat(parity): render a diff as the pull request comment"
```

---

### Task 4: The meter writes a report

**Files:**
- Modify: `internal/conformance/coverage_test.go`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing from earlier tasks. The format it writes is the one Task 1's `Parse` reads, which is why this task's test asserts the exact bytes rather than round-tripping through `internal/parity` - that package is not importable from a test in `internal/conformance` without coupling the two, and the format is the interface.
- Produces: a TSV report at `$GLOAK_PARITY_REPORT` when that variable is set.

**`TestCoverage` must still always pass, and must still print.** This adds a side effect, not a verdict.

- [ ] **Step 1: Write the failing test**

Add to `internal/conformance/coverage_test.go`:

```go
// TestCoverageWritesAReportWhenAsked pins the format internal/parity parses.
// The two packages are deliberately not coupled: this file writes the format
// and that one reads it, and this test is what keeps them agreeing.
func TestCoverageWritesAReportWhenAsked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parity.tsv")
	t.Setenv("GLOAK_PARITY_REPORT", path)

	// Run the meter itself, so the report is the real tally rather than a
	// fixture that could drift from it.
	t.Run("meter", TestCoverage)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	if lines[0] != "chapter\tserved\trecorded\tdocumented\tenumerated" {
		t.Fatalf("header: %q", lines[0])
	}
	if len(lines) != len(Chapters)+2 {
		t.Fatalf("want %d lines for %d chapters plus header and total, got %d",
			len(Chapters)+2, len(Chapters), len(lines))
	}

	total := lines[len(lines)-1]
	fields := strings.Split(total, "\t")
	if len(fields) != 4 || fields[0] != "total" {
		t.Fatalf("total row: %q", total)
	}

	// An unenumerated chapter writes 0 in the numeric column and says so in
	// the last, rather than writing "?" where a number belongs.
	var sawUnenumerated bool
	for _, line := range lines[1 : len(lines)-1] {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			t.Fatalf("chapter row has %d fields: %q", len(f), line)
		}
		if f[4] == "false" {
			sawUnenumerated = true
			if f[3] != "0" {
				t.Fatalf("unenumerated chapter %q has documented %q, want 0", f[0], f[3])
			}
		}
	}
	if !sawUnenumerated {
		t.Fatal("no unenumerated chapter in the report; the catalogue has four")
	}
}

// TestParityReportVariableDoesNotLeak guards the one way the test above can
// corrupt the rest of the package: t.Setenv restores on return, and if it ever
// stopped doing so every later TestCoverage run would silently overwrite a
// report. It asserts the restoration, not the meter.
func TestParityReportVariableDoesNotLeak(t *testing.T) {
	if got := os.Getenv("GLOAK_PARITY_REPORT"); got != "" {
		t.Fatalf("GLOAK_PARITY_REPORT leaked from another test: %q", got)
	}
}
```

Add `os`, `path/filepath` and `strings` to the file's import block if they are not already there. `os` and `strings` are; check `path/filepath` before adding it.

- [ ] **Step 2: Run it to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverageWrites -v`
Expected: FAIL, `read report: open ...: no such file or directory`.

- [ ] **Step 3: Write the report**

In `internal/conformance/coverage_test.go`, collect the rows as the existing loop prints them, then write the file at the end of `TestCoverage`.

Inside the chapter loop, alongside each `t.Logf`, append to a slice declared before the loop:

```go
	var rows []string
```

In the `!ch.Enumerated` branch, after its `t.Logf`:

```go
		rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t0\tfalse",
			ch.Name, tl.implemented, tl.recorded))
```

In the `ch.OpenAPITag != ""` branch, after its `t.Logf`:

```go
		rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t%d\ttrue", ch.Name, ops, tl.recorded, n))
```

In the `default` branch, after its `t.Logf`:

```go
		rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t%d\ttrue",
			ch.Name, tl.implemented, tl.recorded, n))
```

After the total `t.Logf`, before the pending listing:

```go
	writeParityReport(t, rows, served, documented, unenumerated)
```

Add the helper at the end of the file:

```go
// writeParityReport writes the tally as tab-separated values when
// GLOAK_PARITY_REPORT names a path, and does nothing otherwise.
//
// This is a transient artifact, never committed: see .gitignore, and see this
// file's own note that the meter prints rather than writing a checked-in file
// because a generated file drifts from the tests that generate it. Two of
// these are produced inside one CI run, compared, and thrown away.
//
// It is a side effect, not a verdict. TestCoverage always passes, and a
// failure to write is reported through t.Errorf rather than by changing what
// the meter concludes.
func writeParityReport(t *testing.T, rows []string, served, documented, unenumerated int) {
	t.Helper()
	path := os.Getenv("GLOAK_PARITY_REPORT")
	if path == "" {
		return
	}
	var b strings.Builder
	b.WriteString("chapter\tserved\trecorded\tdocumented\tenumerated\n")
	for _, row := range rows {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "total\t%d\t%d\t%d\n", served, documented, unenumerated)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Errorf("write parity report: %v", err)
	}
}
```

Add `fmt` to the import block if it is not there.

- [ ] **Step 4: Run it to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage -v`
Expected: PASS. The meter still prints its table, and the new tests pass.

- [ ] **Step 5: Ignore the artifact**

Add to `.gitignore`, after the existing entries:

```gitignore
/parity-*.tsv
```

- [ ] **Step 6: Verify the two packages agree on the format**

Run:

```bash
GLOAK_PARITY_REPORT=/tmp/parity-head.tsv CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage
cat > /tmp/parity_roundtrip_test.go <<'EOF'
package parity

import (
	"os"
	"testing"
)

func TestRoundTripARealReport(t *testing.T) {
	f, err := os.Open("/tmp/parity-head.tsv")
	if err != nil {
		t.Skip("no report")
	}
	defer f.Close()
	r, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Documented == 0 {
		t.Fatal("parsed a report with no denominator")
	}
	t.Logf("parsed %d chapters, total %d of %d", len(r.Chapters), r.Served, r.Documented)
}
EOF
cp /tmp/parity_roundtrip_test.go internal/parity/zz_roundtrip_test.go
CGO_ENABLED=0 go test ./internal/parity/ -run TestRoundTrip -v
rm internal/parity/zz_roundtrip_test.go
```

Expected: it parses the real report and logs a non-zero total. **Remove the temporary file as shown**; it must not be committed. Confirm with `git status --short` that it is gone.

- [ ] **Step 7: Run the whole suite**

Run: `make test`
Expected: PASS, unchanged.

- [ ] **Step 8: Commit**

```bash
git add internal/conformance/coverage_test.go .gitignore
git commit -m "test(conformance): write the tally as a report when asked"
```

---

### Task 5: The command the workflow calls

**Files:**
- Create: `cmd/parity/main.go`

**Interfaces:**
- Consumes: `Parse`, `Compare`, `Render`, `Marker` from Tasks 1 to 3.
- Produces: a binary invoked as `parity <before.tsv> <after.tsv>`, which prints the comment body on stdout and exits 1 when the total fell without a reason.

The reason comes from the environment rather than a flag, because the workflow already has the pull request body in one: `PR_BODY`.

`cmd/parity` holds no logic worth testing on its own, which is the rule `AGENTS.md` states for `cmd/gloak`. Everything it does beyond argument handling is in `internal/parity`, which is tested.

- [ ] **Step 1: Write the command**

Create `cmd/parity/main.go`:

```go
// Command parity compares two conformance reports and prints the pull request
// comment. It exits non-zero when the total served count fell and the pull
// request body carries no Parity-decrease line.
//
// It holds no logic of its own: the format, the comparison and the rendering
// are in internal/parity, which is tested.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ekalinin/gloak/internal/parity"
)

// decreaseLine matches the escape hatch a pull request body may carry.
var decreaseLine = regexp.MustCompile(`(?mi)^\s*Parity-decrease:\s*(.+?)\s*$`)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: parity <before.tsv> <after.tsv>")
		os.Exit(2)
	}

	before, err := read(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	after, err := read(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var reason string
	if m := decreaseLine.FindStringSubmatch(os.Getenv("PR_BODY")); m != nil {
		reason = strings.TrimSpace(m[1])
	}

	d := parity.Compare(before, after)
	fmt.Print(parity.Render(d, reason))

	if d.Decreased() && reason == "" {
		fmt.Fprintf(os.Stderr, "parity: total fell from %d to %d and no Parity-decrease reason was given\n",
			d.BeforeServed, d.AfterServed)
		os.Exit(1)
	}
}

func read(path string) (parity.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return parity.Report{}, fmt.Errorf("parity: open %s: %w", path, err)
	}
	defer f.Close()
	return parity.Parse(f)
}
```

- [ ] **Step 2: Build it**

Run: `CGO_ENABLED=0 go build ./cmd/parity/`
Expected: no output.

- [ ] **Step 3: Exercise it end to end**

```bash
GLOAK_PARITY_REPORT=/tmp/parity-a.tsv CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage
cp /tmp/parity-a.tsv /tmp/parity-b.tsv
CGO_ENABLED=0 go run ./cmd/parity /tmp/parity-a.tsv /tmp/parity-b.tsv; echo "exit=$?"
```

Expected: a comment saying "no change", `exit=0`.

Then force a decrease and confirm the gate and the escape hatch:

```bash
sed 's/^total\t\([0-9]*\)/total\t999/' /tmp/parity-a.tsv > /tmp/parity-high.tsv
CGO_ENABLED=0 go run ./cmd/parity /tmp/parity-high.tsv /tmp/parity-a.tsv; echo "exit=$?"
PR_BODY='Parity-decrease: moved behind P4' CGO_ENABLED=0 go run ./cmd/parity /tmp/parity-high.tsv /tmp/parity-a.tsv; echo "exit=$?"
```

Expected: the first prints a signed negative delta and `exit=1`; the second quotes the reason and `exit=0`.

- [ ] **Step 4: Clean up and check the tree**

```bash
rm -f /tmp/parity-*.tsv ./parity
git status --short
```

Expected: only the new `cmd/parity/main.go` is untracked. The `parity` binary from step 2 must not be there; `/gloak` is ignored but `parity` is not.

- [ ] **Step 5: Run the whole suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/parity/main.go
git commit -m "feat(parity): the command the workflow calls"
```

---

### Task 6: The workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `cmd/parity` from Task 5 and the `GLOAK_PARITY_REPORT` mode from Task 4.
- Produces: the repository's first CI.

This is the repository's first workflow. Keep it thin: it checks out, runs, and calls. Every decision it makes is a decision that cannot be unit-tested.

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          # The parity step needs the merge base, so the shallow default
          # clone is not enough.
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build
        run: CGO_ENABLED=0 go build ./...

      - name: Vet
        run: go vet ./...

      # Nothing behind the docker build tag runs here: not the Postgres driver
      # suite, not make oracle, not make record. A green run does NOT mean the
      # two store drivers agree; that evidence still comes from running the
      # Postgres suite by hand, as AGENTS.md requires.
      - name: Test
        run: CGO_ENABLED=0 go test ./...

      - name: Parity report for this branch
        run: |
          GLOAK_PARITY_REPORT="$RUNNER_TEMP/parity-head.tsv" \
            CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage

      - name: Parity report for the merge base
        run: |
          base=$(git merge-base "origin/${{ github.base_ref }}" HEAD)
          git worktree add "$RUNNER_TEMP/base" "$base"
          cd "$RUNNER_TEMP/base"
          GLOAK_PARITY_REPORT="$RUNNER_TEMP/parity-base.tsv" \
            CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage

      - name: Compare and comment
        env:
          GH_TOKEN: ${{ github.token }}
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          set -o pipefail
          status=0
          CGO_ENABLED=0 go run ./cmd/parity \
            "$RUNNER_TEMP/parity-base.tsv" "$RUNNER_TEMP/parity-head.tsv" \
            > "$RUNNER_TEMP/comment.md" || status=$?

          existing=$(gh pr view "${{ github.event.pull_request.number }}" \
            --json comments \
            --jq '.comments[] | select(.body | startswith("<!-- gloak-parity -->")) | .url' \
            | tail -1)
          if [ -n "$existing" ]; then
            gh api --method PATCH "${existing/https:\/\/github.com\/*#issuecomment-/repos/${{ github.repository }}/issues/comments/}" \
              -f body@"$RUNNER_TEMP/comment.md" >/dev/null
          else
            gh pr comment "${{ github.event.pull_request.number }}" \
              --body-file "$RUNNER_TEMP/comment.md"
          fi

          exit $status
```

**The comment-update expression above is the fragile part of this file.** Before committing, run step 2 and replace it with whatever actually works; do not commit a line you have not seen succeed.

- [ ] **Step 2: Replace the update expression with one that works**

`gh pr view --json comments` returns comment URLs of the form
`https://github.com/OWNER/REPO/pull/N#issuecomment-ID`. The API path needs the
bare `ID`. Extract it with a tool rather than shell parameter substitution:

```yaml
          id=$(gh pr view "${{ github.event.pull_request.number }}" \
            --json comments \
            --jq '[.comments[] | select(.body | startswith("<!-- gloak-parity -->")) | .url] | last // ""' \
            | sed 's/.*#issuecomment-//')
          if [ -n "$id" ]; then
            gh api --method PATCH "repos/${{ github.repository }}/issues/comments/$id" \
              -F body=@"$RUNNER_TEMP/comment.md" >/dev/null
          else
            gh pr comment "${{ github.event.pull_request.number }}" \
              --body-file "$RUNNER_TEMP/comment.md"
          fi
```

Use this form. It is the one to commit.

- [ ] **Step 3: Check the YAML parses**

Run:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"
```

Expected: `ok`.

- [ ] **Step 4: Rehearse the parity steps locally**

The workflow's Go steps can be run without GitHub. Confirm the merge-base worktree trick works in this repository:

```bash
base=$(git merge-base main HEAD)
rm -rf /tmp/parity-base-wt
git worktree add /tmp/parity-base-wt "$base"
(cd /tmp/parity-base-wt && GLOAK_PARITY_REPORT=/tmp/parity-base.tsv CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage)
GLOAK_PARITY_REPORT=/tmp/parity-head.tsv CGO_ENABLED=0 go test ./internal/conformance/ -run TestCoverage
CGO_ENABLED=0 go run ./cmd/parity /tmp/parity-base.tsv /tmp/parity-head.tsv; echo "exit=$?"
git worktree remove /tmp/parity-base-wt
rm -f /tmp/parity-*.tsv
```

Expected: it prints a comment and exits 0. On this branch the meter has not moved, so expect "no change".

**If the base checkout predates Task 4**, its `TestCoverage` does not honour `GLOAK_PARITY_REPORT` and writes nothing. That is the real first-run condition and the workflow must not crash on it: the compare step will fail to open the base report and exit 2. Note it in the report; it resolves itself once this plan's commits are on `main`, and the first pull request after that is the one that proves the workflow end to end.

- [ ] **Step 5: Run the whole suite**

Run: `make test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "chore(ci): build, vet, test, and report the parity increment"
```

---

### Task 7: Write it down

**Files:**
- Modify: `AGENTS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the two sentences a contributor needs, in the file they already read.

- [ ] **Step 1: Add the CI note to AGENTS.md**

In the "Build and test" section, after the existing bullets, add:

```markdown
- **CI runs `build`, `vet` and `CGO_ENABLED=0 go test ./...` on every pull
  request, and nothing behind the `docker` tag.** A green run does not mean the
  two store drivers agree: that is still the Postgres suite, run by hand, as the
  bullet above says. CI also posts the pull request's parity increment and fails
  when the total falls. A deliberate fall is declared with a
  `Parity-decrease: <reason>` line in the pull request description, which is
  where the reason belongs rather than in a chat log.
```

- [ ] **Step 2: Check the README's meter section**

Read `README.md` around the parity numbers it states. If it describes how to obtain them, add one line naming `make conformance` and the fact that CI reports the increment per pull request. If it only states numbers, leave it alone: this plan deliberately does not touch the hand-written numbers there, and the spec says so.

Say in the report which of the two you found and what you did.

- [ ] **Step 3: Verify every claim you just wrote**

Run:

```bash
make test
CGO_ENABLED=0 go test ./internal/parity/ -count=1
grep -n "docker" .github/workflows/ci.yml
```

Expected: the suite passes, the parity package passes, and the only `docker` in the workflow is the comment saying it is not used. If that grep finds a step that runs one, the AGENTS.md bullet you just wrote is false.

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md README.md
git commit -m "docs(ci): what the workflow runs, and what it does not"
```

---

## Self-review

**Spec coverage.** Section 2's three constraints are honoured: Task 4 keeps `TestCoverage` always passing and prints as before, the gate lives in `cmd/parity` (Task 5), and nothing recomputes `served`. Section 3's transient-artifact rule is Task 4 steps 3 and 5. Section 4's format is Task 1 and Task 4. Section 5's `internal/parity` is Tasks 1 to 3, and it imports nothing from `internal/conformance`. Section 6's workflow is Task 6, with the docker exclusion stated in the file itself and in `AGENTS.md` (Task 7). Section 7's comment is Task 3. Section 8's gate and escape hatch are Task 5. Section 9's exclusions are respected: no operation list, no `recorded` gate, and Task 7 step 2 explicitly leaves the hand-written numbers alone. Section 10's testing is Tasks 1 to 3.

**Placeholders.** None. The one branch is Task 7 step 2, where the README's current content decides between two stated actions, and both are specified.

**Type consistency.** `Report`, `Chapter`, `Diff`, `ChapterDelta`, `Parse`, `Compare`, `Render`, `Marker` and `Delta`/`Decreased` are defined in Tasks 1 to 3 and used with those exact names and signatures in Tasks 4 and 5. The TSV field order `chapter, served, recorded, documented, enumerated` and the total row `total, served, documented, unenumerated` are identical in Task 1's parser, Task 1's test, Task 4's writer and Task 4's test.

**One risk worth restating.** Task 6 step 4 will fail on the first run, because the merge base predates the report mode. That is the expected first-run condition rather than a defect, and the step says so. The workflow proves itself on the first pull request opened after this lands on `main`.
