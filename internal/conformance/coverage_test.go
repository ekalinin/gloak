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
		implemented, recorded, pending, hasGolden, inventoryOnly int
		pendingIDs                                               []string
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
		if !errors.Is(err, fs.ErrNotExist) {
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
	sort.Strings(order)

	var total, done int
	t.Log("chapter                     implemented  recorded  pending  golden  inventory-only")
	for _, name := range order {
		tl := chapters[name]
		total += tl.implemented + tl.recorded + tl.pending
		done += tl.implemented
		t.Logf("%-26s  %11d  %8d  %7d  %6d  %14d",
			name, tl.implemented, tl.recorded, tl.pending, tl.hasGolden, tl.inventoryOnly)
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
