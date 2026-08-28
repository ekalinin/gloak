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
			// A chapter that disappears with non-zero served is also a move.
			if ch.Served != 0 {
				out.Moved = append(out.Moved, ChapterDelta{
					Name:   ch.Name,
					Before: ch.Served,
					After:  0,
				})
			}
		}
	}

	slices.SortFunc(out.Moved, func(a, b ChapterDelta) int { return cmp.Compare(a.Name, b.Name) })
	slices.Sort(out.Appeared)
	slices.Sort(out.Disappeared)
	return out
}
