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

// The table is fixed-width text inside a code fence, so its header is the only
// thing saying which column is which. Nothing else pins it: reversed labels or
// widths that no longer line up with the rows are invisible to every other
// assertion here, and the reader has no second source to check against.
func TestRenderPinsTheTableHeaderAndColumnWidths(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 109, Documented: 485,
		Moved: []ChapterDelta{{Name: "admin/groups", Before: 0, After: 9}}}

	got := Render(d, "")

	const header = "chapter                         before  after  delta"
	const row = "admin/groups                         0      9     +9"
	if !strings.Contains(got, header+"\n"+row+"\n") {
		t.Fatalf("want the header and a row aligned under it:\nwant\n%s\n%s\ngot\n%s",
			header, row, got)
	}
}

func TestRenderSaysSoWhenNothingMoved(t *testing.T) {
	got := Render(Diff{BeforeServed: 100, AfterServed: 100, Documented: 485}, "")

	if !strings.Contains(got, "no change") {
		t.Fatalf("want an explicit no-change line:\n%s", got)
	}
	// A change expected to move the meter and did not is worth seeing, so the
	// totals still appear. Assert the exact format to discriminate against an
	// arrow-form "(+0)" that would appear if the no-change branch was dropped.
	if !strings.Contains(got, "100 of 485, no change") {
		t.Fatalf("want the no-change format, not an arrow:\n%s", got)
	}
}

// Four chapters have no denominator, so a pull request that served new
// behaviour in one of them leaves the total where it was. "no change" is
// arithmetically right and reads as a contradiction against the table of work
// printed directly underneath it, so the flat total has to be said differently
// and the reason given.
func TestRenderExplainsAFlatTotalWhenTheWorkIsUnenumerated(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 100, Documented: 485,
		Moved: []ChapterDelta{{Name: "saml", Before: 0, After: 3, Enumerated: false}}}

	got := Render(d, "")

	if strings.Contains(got, "no change") {
		t.Fatalf("three behaviours were served; that is not no change:\n%s", got)
	}
	if !strings.Contains(got, "100 of 485, total unchanged") {
		t.Fatalf("want the flat total still stated:\n%s", got)
	}
	if !strings.Contains(got, "saml") {
		t.Fatalf("want the chapter that moved:\n%s", got)
	}
	if !strings.Contains(got, "unenumerated") {
		t.Fatalf("want the reason the total did not move:\n%s", got)
	}
}

// A flat total with an enumerated chapter moving is a rearrangement, not
// uncounted work. It still must not say "no change" - the table says otherwise
// - but blaming the unenumerated chapters for it would be a second false
// statement in place of the first.
func TestRenderDoesNotBlameUnenumeratedChaptersForARearrangement(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 100, Documented: 485,
		Moved: []ChapterDelta{
			{Name: "admin/new", Before: 3, After: 8, Enumerated: true},
			{Name: "admin/old", Before: 7, After: 2, Enumerated: true},
		}}

	got := Render(d, "")

	if strings.Contains(got, "no change") {
		t.Fatalf("two chapters moved; that is not no change:\n%s", got)
	}
	if !strings.Contains(got, "100 of 485, total unchanged") {
		t.Fatalf("want the flat total stated:\n%s", got)
	}
	if strings.Contains(got, "unenumerated") {
		t.Fatalf("both chapters are enumerated, so the total is flat for another reason:\n%s", got)
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

func TestRenderSaysSoWhenDecreaseHasNoReason(t *testing.T) {
	d := Diff{BeforeServed: 100, AfterServed: 97, Documented: 485,
		Moved: []ChapterDelta{{Name: "admin/users", Before: 14, After: 11}}}

	got := Render(d, "")

	if !strings.Contains(got, "no reason was given") {
		t.Fatalf("want the no-reason message:\n%s", got)
	}
	// Ensure the reason-quoting format is not present: the pattern is the
	// specific message followed by the markdown quote block.
	if strings.Contains(got, "The total fell, and the pull request gives a reason") {
		t.Fatalf("want no reason-quoting block when reason is empty:\n%s", got)
	}
}
