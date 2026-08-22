package conformance

import "testing"

// The counts below are the vendored description's own. They are checked so
// that swapping in another version cannot change the denominator silently: a
// version bump is meant to be a deliberate act with a re-record beside it.
func TestOperationsByTag(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}

	total := 0
	for _, n := range byTag {
		total += n
	}
	if total != 413 {
		t.Errorf("total operations: want 413, got %d", total)
	}
	if len(byTag) != 22 {
		t.Errorf("tags: want 22, got %d", len(byTag))
	}

	for tag, want := range map[string]int{
		"Users":        34,
		"Clients":      35,
		"Realms Admin": 45,
		untaggedTag:    31,
	} {
		if got := byTag[tag]; got != want {
			t.Errorf("tag %q: want %d operations, got %d", tag, want, got)
		}
	}
}

// Every chapter that claims an OpenAPI tag must name one the description
// actually has. A typo would otherwise give that chapter a denominator of
// zero, which reads as "fully covered".
func TestChaptersReferenceRealTags(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}
	for _, ch := range Chapters {
		if ch.OpenAPITag == "" {
			continue
		}
		if _, ok := byTag[ch.OpenAPITag]; !ok {
			t.Errorf("chapter %q names tag %q, which the description does not have", ch.Name, ch.OpenAPITag)
		}
	}
}

// Every tag in the description belongs to exactly one chapter. A tag nobody
// claims is surface silently missing from the denominator.
func TestEveryTagIsClaimedOnce(t *testing.T) {
	byTag, err := OperationsByTag()
	if err != nil {
		t.Fatalf("OperationsByTag: %v", err)
	}
	claimed := map[string]string{}
	for _, ch := range Chapters {
		if ch.OpenAPITag == "" {
			continue
		}
		if prev, ok := claimed[ch.OpenAPITag]; ok {
			t.Errorf("tag %q is claimed by both %q and %q", ch.OpenAPITag, prev, ch.Name)
		}
		claimed[ch.OpenAPITag] = ch.Name
	}
	for tag := range byTag {
		if _, ok := claimed[tag]; !ok {
			t.Errorf("tag %q is in the description but no chapter claims it", tag)
		}
	}
}

// A chapter whose surface nobody has counted has to say so, or the total
// silently treats it as empty.
func TestUnenumeratedChaptersCarryAReason(t *testing.T) {
	for _, ch := range Chapters {
		if !ch.Enumerated && ch.Reason == "" {
			t.Errorf("chapter %q is not enumerated and does not say why", ch.Name)
		}
		if ch.Enumerated && ch.Reason != "" {
			t.Errorf("chapter %q is enumerated; Reason belongs to the ones that are not", ch.Name)
		}
	}
}

// Every catalogue case reports under some chapter. A case whose chapter is
// undeclared would vanish from the report entirely.
func TestEveryCaseHasAChapter(t *testing.T) {
	declared := map[string]bool{}
	for _, ch := range Chapters {
		declared[ch.Name] = true
	}
	for _, c := range Catalog {
		if !declared[chapterOf(c.ID)] {
			t.Errorf("%q reports under chapter %q, which is not declared", c.ID, chapterOf(c.ID))
		}
	}
}

// Chapter names are unique. Two rows with one name would double-count.
func TestChapterNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, ch := range Chapters {
		if seen[ch.Name] {
			t.Errorf("chapter %q is declared twice", ch.Name)
		}
		seen[ch.Name] = true
	}
}
