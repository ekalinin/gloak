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
func TestCoverage(t *testing.T) {
	type tally struct {
		implemented, pending, recorded, inventoryOnly int
		pendingIDs                                    []string
	}
	chapters := map[string]*tally{}
	var order []string

	for _, c := range Catalog {
		name := chapterOf(c.ID)
		tl, ok := chapters[name]
		if !ok {
			tl = &tally{}
			chapters[name] = tl
			order = append(order, name)
		}
		_, err := os.Stat(GoldenPath(goldenDir, c.ID))
		hasGolden := !errors.Is(err, fs.ErrNotExist)
		if hasGolden {
			tl.recorded++
		}
		switch c.Status {
		case Implemented:
			tl.implemented++
		case Pending:
			tl.pending++
			tl.pendingIDs = append(tl.pendingIDs, c.ID)
			if c.Fixture == "" {
				tl.inventoryOnly++
			}
		}
	}
	sort.Strings(order)

	var total, done int
	t.Log("chapter                     implemented  pending  recorded  inventory-only")
	for _, name := range order {
		tl := chapters[name]
		total += tl.implemented + tl.pending
		done += tl.implemented
		t.Logf("%-26s  %11d  %7d  %8d  %14d",
			name, tl.implemented, tl.pending, tl.recorded, tl.inventoryOnly)
	}
	t.Logf("total: %d of %d documented behaviours served", done, total)

	for _, name := range order {
		tl := chapters[name]
		if len(tl.pendingIDs) == 0 {
			continue
		}
		sort.Strings(tl.pendingIDs)
		t.Logf("pending in %s:\n  %s", name, strings.Join(tl.pendingIDs, "\n  "))
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
