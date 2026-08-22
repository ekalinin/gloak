package conformance

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"testing"
)

// idPattern keeps IDs safe to use as file paths: lowercase slug segments
// separated by slashes, nothing that could escape testdata/golden.
var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)*$`)

func TestCatalogIsWellFormed(t *testing.T) {
	if len(Catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := make(map[string]bool, len(Catalog))
	for _, c := range Catalog {
		if !idPattern.MatchString(c.ID) {
			t.Errorf("%q: ID is not a slug path", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("%q: duplicate ID", c.ID)
		}
		seen[c.ID] = true

		if c.Doc.URL == "" || c.Doc.Section == "" || c.Doc.Retrieved == "" {
			t.Errorf("%q: Doc must carry URL, Section and Retrieved", c.ID)
		}
		if c.Request.Method == "" || c.Request.Path == "" {
			t.Errorf("%q: Request needs a method and a path", c.ID)
		}
		switch c.Status {
		case Pending:
			if c.Reason == "" {
				t.Errorf("%q: a Pending case must say why", c.ID)
			}
		case Implemented:
			if c.Fixture == "" {
				t.Errorf("%q: an Implemented case needs a fixture", c.ID)
			}
			if c.Reason != "" {
				t.Errorf("%q: Reason belongs to Pending cases only", c.ID)
			}
		default:
			t.Errorf("%q: unknown status %d", c.ID, c.Status)
		}
	}
}

// TestRecordedCaseRules pins the two rules that make Recorded different from
// Pending: the golden is mandatory, and the case must say why it is not
// served yet.
func TestRecordedCaseRules(t *testing.T) {
	for _, c := range Catalog {
		if c.Status != Recorded {
			continue
		}
		if c.Reason == "" {
			t.Errorf("%q: a Recorded case must say why it is not served yet", c.ID)
		}
		if c.Fixture == "" {
			t.Errorf("%q: a Recorded case is served, so it needs a fixture", c.ID)
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%q: Recorded means the golden was measured, but none exists", c.ID)
		}
	}
}
