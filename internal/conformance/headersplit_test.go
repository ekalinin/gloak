package conformance

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// duplicateResourceErrorBody is the 67-byte body at the centre of AGENTS.md's
// fifth security-header exception.
const duplicateResourceErrorBody = `{"error":"conflict","error_description":"Duplicate resource error"}`

// theFiveSecurityHeaders is the set the exception is about.
var theFiveSecurityHeaders = []string{
	"Referrer-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-Robots-Tag",
}

// TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb computes AGENTS.md's
// header tally instead of trusting the number written beside it.
//
// **This test exists because that number drifted three times, and the last time
// it drifted inside a single commit.** The bullet read "fifteen committed
// goldens" while the tree held sixteen: a sixteenth arrived from P10's
// authorization work in the very fold that wrote "fifteen". The paragraph's
// conclusion survived and its arithmetic did not, and the arithmetic is what the
// paragraph offers as evidence. AGENTS.md's own advice - a count written in
// prose beside the list it counts will rot, so the list is the answer - applies
// to itself here, and a list this repository can compute is better than a list
// a person maintains.
//
// So the bullet no longer carries numbers. It points at this test, which asserts
// the **claim** rather than the count: both verbs answer this one body both
// ways, so neither the verb nor the status nor the body decides the header set.
// A cut that adds another such golden moves the counts and leaves the claim
// standing, which is exactly the change that should not need a documentation
// edit. A cut that makes one verb consistent breaks this test, which is exactly
// the change that should.
//
// See F147, which records what else has been ruled out and what would settle it.
func TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb(t *testing.T) {
	t.Parallel()

	type tally struct{ with, without []string }
	byVerb := map[string]*tally{}

	root := filepath.Join(goldenDir)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".http") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Contains(raw, []byte(duplicateResourceErrorBody)) {
			return nil
		}
		// The first line is the recorded request, `# VERB /path`.
		first, rest, ok := bytes.Cut(raw, []byte("\n"))
		if !ok {
			return nil
		}
		fields := strings.Fields(string(first))
		if len(fields) < 2 {
			return nil
		}
		verb := fields[1]

		// Count a header only in the head, so a body that happens to quote one
		// cannot be mistaken for it.
		head, _, _ := bytes.Cut(rest, []byte("\n\n"))
		n := 0
		for _, h := range theFiveSecurityHeaders {
			for line := range strings.SplitSeq(string(head), "\n") {
				if strings.HasPrefix(strings.ToLower(line), strings.ToLower(h)+":") {
					n++
					break
				}
			}
		}
		if byVerb[verb] == nil {
			byVerb[verb] = &tally{}
		}
		rel := strings.TrimPrefix(path, root+"/")
		switch n {
		case 0:
			byVerb[verb].without = append(byVerb[verb].without, rel)
		case len(theFiveSecurityHeaders):
			byVerb[verb].with = append(byVerb[verb].with, rel)
		default:
			t.Errorf("%s answers %s with %d of the five security headers.\n"+
				"Every measured response carrying this body sends all five or none, and a\n"+
				"partial set would be a sixth exception rather than a variation of the fifth.",
				rel, duplicateResourceErrorBody, n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	if len(byVerb) == 0 {
		t.Fatal("no golden carries the Duplicate resource error body; either the goldens moved " +
			"or this test's body constant is stale, and both are worth knowing")
	}

	// The claim: at least two verbs answer this one body both ways. If a verb
	// ever became consistent, the split would have a candidate explanation again
	// and F147 would be worth reopening - so failing here is the useful outcome,
	// not a regression.
	split := 0
	verbs := make([]string, 0, len(byVerb))
	for verb := range byVerb {
		verbs = append(verbs, verb)
	}
	sort.Strings(verbs)
	for _, verb := range verbs {
		got := byVerb[verb]
		t.Logf("%-6s %d send none of the five, %d send all five", verb, len(got.without), len(got.with))
		if len(got.with) > 0 && len(got.without) > 0 {
			split++
		}
	}
	if split < 2 {
		t.Errorf("only %d verb answers %s both ways; AGENTS.md's fifth security-header\n"+
			"exception rests on at least two doing so, and F147 should be reopened rather\n"+
			"than this test relaxed.", split, duplicateResourceErrorBody)
	}
}
