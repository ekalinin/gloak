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
		// The total is the last row. A chapter after it was counted into no
		// total, and a second total silently replaced the first: fed a report
		// whose real total was 100, the scan used to answer 0.
		{"chapter row after the total", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\t2\ttrue\n" +
			"total\t1\t2\t0\n" +
			"admin/users\t9\t0\t20\ttrue\n"},
		{"a second total row", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t1\t0\t2\ttrue\n" +
			"total\t100\t485\t4\n" +
			"total\t0\t0\t0\n"},
		// Compare keys chapters by name, so a repeated one makes Compare(r, r)
		// report a move: the map keeps the last row and the loop sees both.
		{"a chapter listed twice", "chapter\tserved\trecorded\tdocumented\tenumerated\n" +
			"admin/roles\t2\t0\t24\ttrue\n" +
			"admin/roles\t24\t0\t24\ttrue\n" +
			"total\t26\t48\t0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.in)); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}
