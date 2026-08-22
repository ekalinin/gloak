package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOperationsAreKeyedByMethodAndPath(t *testing.T) {
	// The key is "METHOD path" because the vendored description carries no
	// operationId - zero of its 413 operations have one, and the fields an
	// operation does have are description, parameters, responses, summary and
	// tags. Method and path together are unique, are in the document, and come
	// from outside this project, which is the whole requirement.
	ops, err := Operations()

	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	if len(ops) != 413 {
		t.Fatalf("want 413 operations, got %d", len(ops))
	}
	for _, want := range []string{
		"GET /admin/realms/{realm}/clients",
		"POST /admin/realms/{realm}/clients",
		"GET /admin/realms/{realm}/users/{user-id}",
	} {
		if !ops[want] {
			t.Errorf("%q is not in the description", want)
		}
	}
	if ops["GET /admin/realms/{realm}/clients/{client-uuid}/parameters"] {
		t.Error("a path item's parameters key was counted as an operation")
	}
}

func TestNoOperationCarriesAnOperationID(t *testing.T) {
	// Pinning the absence, because an earlier draft of P2's spec specified the
	// meter around operationId and had to be corrected. If a future vendored
	// version does carry them, this fails and that decision gets revisited
	// deliberately rather than by accident.
	raw, err := os.ReadFile(filepath.FromSlash(openapiPath))
	if err != nil {
		t.Fatalf("read description: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse description: %v", err)
	}
	for path, item := range doc.Paths {
		for method, rawOp := range item {
			if !httpMethods[method] {
				continue
			}
			var op struct {
				OperationID string `json:"operationId"`
			}
			if err := json.Unmarshal(rawOp, &op); err != nil {
				t.Fatalf("parse %s %s: %v", method, path, err)
			}
			if op.OperationID != "" {
				t.Fatalf("%s %s carries operationId %q; the meter's key can be revisited",
					method, path, op.OperationID)
			}
		}
	}
}

func TestAdminCasesNameARealOperation(t *testing.T) {
	ops, err := Operations()
	if err != nil {
		t.Fatalf("Operations: %v", err)
	}
	byName := make(map[string]Chapter, len(Chapters))
	for _, ch := range Chapters {
		byName[ch.Name] = ch
	}

	for _, c := range Catalog {
		// Protocol chapters have no operation list, which is what
		// "source: catalogue" in the coverage report already says.
		if byName[chapterOf(c.ID)].OpenAPITag == "" {
			continue
		}
		if c.Operation == "" {
			t.Errorf("%q is in an OpenAPI-counted chapter and names no operation", c.ID)
			continue
		}
		if !ops[c.Operation] {
			t.Errorf("%q names operation %q, which is not in the description", c.ID, c.Operation)
		}
	}
}

func TestServedOperationsCountsEachOperationOnce(t *testing.T) {
	// Two Implemented cases on one operation count once. Without this the
	// meter rewards writing more error cases for an endpoint already served,
	// and would report "3 of 34" where one operation of 34 is implemented.
	cases := []Case{
		{ID: "admin/users/list", Status: Implemented, Operation: "GET /admin/realms/{realm}/users"},
		{ID: "admin/users/list-forbidden", Status: Implemented, Operation: "GET /admin/realms/{realm}/users"},
		{ID: "admin/users/read", Status: Implemented, Operation: "GET /admin/realms/{realm}/users/{user-id}"},
		{ID: "admin/users/create", Status: Pending, Operation: "POST /admin/realms/{realm}/users"},
	}

	if got := servedOperations(cases); got != 2 {
		t.Fatalf("want 2 distinct served operations, got %d", got)
	}
}

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
