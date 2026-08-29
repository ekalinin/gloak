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
	want := []ChapterDelta{{Name: "admin/users", Before: 14, After: 23, Enumerated: true}}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}

// Appeared and Disappeared are sorted for the same reason Moved is: the comment
// is rewritten on every push, and an unsorted list reorders itself between two
// runs that found the same chapters. Both need more than one element and an
// input order that is not already the answer.
func TestCompareSortsAppearedAndDisappeared(t *testing.T) {
	before := report(0, 485,
		chapter("zzz/gone", 0),
		chapter("aaa/gone", 0),
		chapter("mmm/gone", 0),
	)
	after := report(0, 485,
		chapter("zzz/new", 0),
		chapter("aaa/new", 0),
		chapter("mmm/new", 0),
	)

	got := Compare(before, after)

	if want := []string{"aaa/new", "mmm/new", "zzz/new"}; !slices.Equal(got.Appeared, want) {
		t.Fatalf("appeared: want %v, got %v", want, got.Appeared)
	}
	if want := []string{"aaa/gone", "mmm/gone", "zzz/gone"}; !slices.Equal(got.Disappeared, want) {
		t.Fatalf("disappeared: want %v, got %v", want, got.Disappeared)
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

	want := []ChapterDelta{{Name: "admin/groups", Before: 0, After: 9, Enumerated: true}}
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

// An unenumerated chapter whose served count moved is a move like any other,
// and the flag saying it has no denominator has to survive the comparison:
// Render is what needs it, and Render is not given the reports.
func TestCompareCarriesWhetherAMovedChapterIsEnumerated(t *testing.T) {
	before := report(6, 485,
		chapter("admin/roles", 6),
		Chapter{Name: "saml", Served: 0, Enumerated: false},
	)
	after := report(6, 485,
		chapter("admin/roles", 6),
		Chapter{Name: "saml", Served: 3, Enumerated: false},
	)

	got := Compare(before, after)

	want := []ChapterDelta{{Name: "saml", Before: 0, After: 3, Enumerated: false}}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
	// The total cannot move for work in a chapter with no denominator, so a
	// flat total here is the arithmetic being right rather than nothing having
	// happened.
	if got.Delta() != 0 {
		t.Fatalf("want delta 0, got %d", got.Delta())
	}
	if !got.MovedOutsideTheTotal() {
		t.Fatal("want the move reported as outside the total")
	}
}

// One enumerated chapter moving is enough to make a flat total a rearrangement
// rather than uncounted work, so the unenumerated explanation must not fire.
func TestCompareMixedMovesAreNotAllOutsideTheTotal(t *testing.T) {
	before := report(6, 485,
		chapter("admin/roles", 6),
		Chapter{Name: "saml", Served: 0, Enumerated: false},
	)
	after := report(6, 485,
		chapter("admin/roles", 8),
		Chapter{Name: "saml", Served: 3, Enumerated: false},
	)

	if got := Compare(before, after); got.MovedOutsideTheTotal() {
		t.Fatalf("an enumerated chapter moved, so this is not outside the total: %+v", got.Moved)
	}
}

// Nothing moved is not "the work is uncounted"; it is nothing happening, and
// the two get different sentences.
func TestCompareNothingMovedIsNotOutsideTheTotal(t *testing.T) {
	r := report(6, 485, chapter("admin/roles", 6))

	if Compare(r, r).MovedOutsideTheTotal() {
		t.Fatal("an empty diff has nothing outside the total to report")
	}
}

// A chapter disappearing with a non-zero served count is both gone and a move, and
// the comment has to show the regression number rather than only the name.
func TestCompareCountsADisappearedChapterThatServed(t *testing.T) {
	before := report(15, 505, chapter("admin/roles", 6), chapter("admin/legacy", 9))
	after := report(6, 485, chapter("admin/roles", 6))

	got := Compare(before, after)

	if want := []string{"admin/legacy"}; !slices.Equal(got.Disappeared, want) {
		t.Fatalf("disappeared: want %v, got %v", want, got.Disappeared)
	}
	want := []ChapterDelta{{Name: "admin/legacy", Before: 9, After: 0, Enumerated: true}}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}

// A per-chapter fall with a flat or rising total is an honest rearrangement
// and must not gate. Decreased must report only the total falling, not any
// chapter falling.
func TestCompareRearrangementWithoutDecreaseIsAllowed(t *testing.T) {
	before := report(10, 485, chapter("admin/old", 7), chapter("admin/new", 3))
	after := report(10, 485, chapter("admin/old", 2), chapter("admin/new", 8))

	got := Compare(before, after)

	if got.Decreased() {
		t.Fatal("want false; rearrangement with flat total is not a decrease")
	}
	if got.Delta() != 0 {
		t.Fatalf("want delta 0, got %d", got.Delta())
	}
	want := []ChapterDelta{
		{Name: "admin/new", Before: 3, After: 8, Enumerated: true},
		{Name: "admin/old", Before: 7, After: 2, Enumerated: true},
	}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}

// Sort order must be enforced. Chapters in Moved are returned sorted by name,
// not in iteration order.
func TestCompareSortsMoved(t *testing.T) {
	before := report(8, 485,
		chapter("zzz/last", 2),
		chapter("aaa/first", 3),
		chapter("mmm/middle", 3),
	)
	after := report(15, 485,
		chapter("zzz/last", 4),
		chapter("aaa/first", 5),
		chapter("mmm/middle", 6),
	)

	got := Compare(before, after)

	// All three should be in Moved, sorted alphabetically.
	want := []ChapterDelta{
		{Name: "aaa/first", Before: 3, After: 5, Enumerated: true},
		{Name: "mmm/middle", Before: 3, After: 6, Enumerated: true},
		{Name: "zzz/last", Before: 2, After: 4, Enumerated: true},
	}
	if !slices.Equal(got.Moved, want) {
		t.Fatalf("moved: want %+v, got %+v", want, got.Moved)
	}
}
