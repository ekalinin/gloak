package conformance

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestCoverage always passes. It exists to print how much of the documented
// surface is served, so that a pending count which never moves is visible
// rather than buried. `make conformance` runs it.
//
// It prints rather than writing a checked-in file: a generated file drifts
// from the tests that generate it.
//
// The denominator comes from two sources, and the report names which one each
// row used. A hand-kept case count measures diligence as much as coverage, so
// it is never silently mixed with the operation counts taken from Keycloak's
// own API description. Chapters nobody has counted are printed with "?" and
// excluded from the total, which is then reported alongside how many chapters
// it left out - leaving them out silently would inflate the percentage by
// hiding exactly the parts nobody has looked at.
func TestCoverage(t *testing.T) {
	type tally struct {
		implemented, recorded, pending, hasGolden, inventoryOnly int
		pendingIDs                                               []string
		cases                                                    []Case
	}
	tallies := map[string]*tally{}
	for _, ch := range Chapters {
		tallies[ch.Name] = &tally{}
	}

	for _, c := range Catalog {
		tl, ok := tallies[chapterOf(c.ID)]
		if !ok {
			t.Errorf("%q reports under chapter %q, which is not declared", c.ID, chapterOf(c.ID))
			continue
		}
		tl.cases = append(tl.cases, c)
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); !errors.Is(err, fs.ErrNotExist) {
			tl.hasGolden++
		}
		switch c.Status {
		case Implemented:
			tl.implemented++
		case Recorded:
			tl.recorded++
		case Pending:
			tl.pending++
			tl.pendingIDs = append(tl.pendingIDs, c.ID)
			if c.Fixture == "" {
				tl.inventoryOnly++
			}
		}
	}

	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}

	var served, documented, unenumerated int
	var rows []string
	t.Log("chapter                              served  recorded  documented  source")
	for _, ch := range Chapters {
		tl := tallies[ch.Name]
		switch {
		case !ch.Enumerated:
			unenumerated++
			t.Logf("%-36s  %6d  %8d  %10s  not enumerated: %s",
				ch.Name, tl.implemented, tl.recorded, "?", ch.Reason)
			rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t0\tfalse",
				ch.Name, tl.implemented, tl.recorded))
		case ch.OpenAPITag != "":
			// Distinct operations, not cases: the denominator counts
			// operations, so several cases on one endpoint must not read as
			// several operations served. See servedOperations in openapi.go.
			n := byTag[ch.OpenAPITag]
			ops := servedOperations(tl.cases)
			documented += n
			served += ops
			t.Logf("%-36s  %6d  %8d  %10d  openapi 26.7.1",
				ch.Name, ops, tl.recorded, n)
			rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t%d\ttrue", ch.Name, ops, tl.recorded, n))
		default:
			n := tl.implemented + tl.recorded + tl.pending
			documented += n
			served += tl.implemented
			t.Logf("%-36s  %6d  %8d  %10d  catalogue",
				ch.Name, tl.implemented, tl.recorded, n)
			rows = append(rows, fmt.Sprintf("%s\t%d\t%d\t%d\ttrue",
				ch.Name, tl.implemented, tl.recorded, n))
		}
	}
	t.Logf("total: %d of %d enumerated behaviours served; %d chapters not enumerated",
		served, documented, unenumerated)
	writeParityReport(t, rows, served, documented, unenumerated)

	for _, ch := range Chapters {
		tl := tallies[ch.Name]
		if len(tl.pendingIDs) == 0 {
			continue
		}
		sort.Strings(tl.pendingIDs)
		t.Logf("pending in %s:\n  %s", ch.Name, strings.Join(tl.pendingIDs, "\n  "))
	}
}

// chapterOf groups a case ID by its first two slug segments, so
// "oidc/token/password-grant" reports under "oidc/token".
func chapterOf(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) < 2 {
		return id
	}
	return parts[0] + "/" + parts[1]
}

// TestCoverageWritesAReportWhenAsked pins the format internal/parity parses -
// the header, the row and field counts, and which number goes in which column.
// The two packages are deliberately not coupled: this file writes the format
// and that one reads it, and this test is what keeps them agreeing.
//
// The column check is the one that earns its keep. Shape alone passes just as
// well when two columns are transposed, and a transposed report is not a
// broken run: it is a wrong parity number posted to a pull request as fact.
// So the rows are summed and reconciled against the total row, which no
// transposition survives.
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
	// the last, rather than writing "?" where a number belongs. The enumerated
	// rows are summed as they go: the total row is the meter's own served and
	// documented, so the sums agreeing with it is what pins the columns.
	var sumServed, sumDocumented, unenumerated int
	for _, line := range lines[1 : len(lines)-1] {
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			t.Fatalf("chapter row has %d fields: %q", len(f), line)
		}
		if f[4] == "false" {
			unenumerated++
			if f[3] != "0" {
				t.Fatalf("unenumerated chapter %q has documented %q, want 0", f[0], f[3])
			}
			continue
		}
		served, err := strconv.Atoi(f[1])
		if err != nil {
			t.Fatalf("chapter %q served %q: %v", f[0], f[1], err)
		}
		documented, err := strconv.Atoi(f[3])
		if err != nil {
			t.Fatalf("chapter %q documented %q: %v", f[0], f[3], err)
		}
		sumServed += served
		sumDocumented += documented
	}
	if unenumerated == 0 {
		t.Fatal("no unenumerated chapter in the report; the catalogue has four")
	}

	if got := fmt.Sprint(sumServed); got != fields[1] {
		t.Fatalf("enumerated rows serve %s, total row says %s", got, fields[1])
	}
	if got := fmt.Sprint(sumDocumented); got != fields[2] {
		t.Fatalf("enumerated rows document %s, total row says %s", got, fields[2])
	}
	if got := fmt.Sprint(unenumerated); got != fields[3] {
		t.Fatalf("%s unenumerated chapters in the rows, total row says %s", got, fields[3])
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
