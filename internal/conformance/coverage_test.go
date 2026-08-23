package conformance

import (
	"errors"
	"io/fs"
	"os"
	"sort"
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
	t.Log("chapter                              served  recorded  documented  source")
	for _, ch := range Chapters {
		tl := tallies[ch.Name]
		switch {
		case !ch.Enumerated:
			unenumerated++
			t.Logf("%-36s  %6d  %8d  %10s  not enumerated: %s",
				ch.Name, tl.implemented, tl.recorded, "?", ch.Reason)
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
		default:
			n := tl.implemented + tl.recorded + tl.pending
			documented += n
			served += tl.implemented
			t.Logf("%-36s  %6d  %8d  %10d  catalogue",
				ch.Name, tl.implemented, tl.recorded, n)
		}
	}
	t.Logf("total: %d of %d enumerated behaviours served; %d chapters not enumerated",
		served, documented, unenumerated)

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
