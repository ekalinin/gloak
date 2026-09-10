package conformance

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// TestEveryGoldenMissingASecurityHeaderDeclaresItAbsent is the mirror of
// TestAssertAbsentHeadersAgreeWithTheGolden, and it exists because that test
// cannot catch a declaration being deleted.
//
// That one reads the catalogue and checks each declaration against the bytes:
// a case saying `X-Frame-Options` is absent fails if its golden carries one. It
// is a check on the claims that are made. **A smaller set of true claims is
// still true**, so removing an entry - or never writing one - passes it, and
// F181 records that as a surviving mutation only half closed.
//
// This test reads the bytes and checks each *omission* against the catalogue,
// which is the other direction: every golden that does not carry one of the
// five security headers must have a case declaring that header absent. The two
// together make the declarations a catalogue of the omissions rather than a
// sample of them, and that is what turns AGENTS.md's security-header bullet
// from a paragraph carrying a tally into a list this repository computes -
// which is what TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb already
// does for the fifth exception.
//
// **The bullet is the passage AGENTS.md records as having been wrong seven
// times**, twice refuted by the very golden it cited. A rule that makes every
// omission a declaration puts the next correction in the diff of the catalogue,
// where a reviewer sees it, instead of in a sentence somebody has to re-derive.
//
// It walks the committed tree rather than the catalogue, for the reason
// TestEveryGoldenBodyIsText gives: a golden the catalogue no longer names is
// still a file somebody will read as a contract, and it can declare nothing at
// all. Joining by GoldenPath means such a file reports every header it omits.
//
// The five are AGENTS.md's set and no more. A rule over every header a response
// might omit is not a rule - Keycloak omits an unbounded number of headers from
// every response - and the security headers are the only set this project has a
// measured rule for.
func TestEveryGoldenMissingASecurityHeaderDeclaresItAbsent(t *testing.T) {
	t.Parallel()

	corpus, err := goldenCorpus()
	if err != nil {
		t.Fatalf("walking %s: %v", goldenDir, err)
	}
	declared := map[string][]string{}
	for _, c := range Catalog {
		declared[GoldenPath(goldenDir, c.ID)] = c.AssertAbsentHeaders
	}

	read, findings, err := undeclaredSecurityHeaderOmissions(corpus, declared)
	if err != nil {
		t.Fatalf("reading the corpus: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s does not carry %s and no case declares %s absent.\n"+
			"Every golden missing one of the five security headers must say so in\n"+
			"AssertAbsentHeaders, with a comment naming which of AGENTS.md's measured\n"+
			"omissions it is. A golden that fits none of them is a finding rather than\n"+
			"an entry to paste: see docs/superpowers/handover/mirror-header-rule.md.",
			f.path, strings.Join(f.undeclared, ", "), plural(len(f.undeclared)))
	}

	// A sweep that read nothing and a sweep that found nothing are the same
	// colour otherwise, and a -run selector naming the wrong package has already
	// produced the first one in this project.
	if read == 0 {
		t.Fatal("read no goldens at all, so this test asserted nothing")
	}
	t.Logf("checked %d goldens", read)
}

// securityHeaderOmission is one golden that omits a security header its case
// does not declare absent.
type securityHeaderOmission struct {
	path       string
	undeclared []string
}

// undeclaredSecurityHeaderOmissions is the sweep, taking its corpus and its
// declarations as arguments so the guard below can hand it a tree it built.
//
// It returns how many goldens it read as well as what it found, and it reads
// the head alone: a body quoting a header name is not a header, which is the
// distinction TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb draws
// beside it.
func undeclaredSecurityHeaderOmissions(corpus map[string][]byte, declared map[string][]string) (int, []securityHeaderOmission, error) {
	paths := make([]string, 0, len(corpus))
	for p := range corpus {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	read := 0
	var findings []securityHeaderOmission
	for _, p := range paths {
		g, err := ParseGolden(corpus[p])
		if err != nil {
			return read, nil, fmt.Errorf("%s: %w", p, err)
		}
		read++

		present := map[string]bool{}
		for _, h := range g.Headers {
			present[http.CanonicalHeaderKey(h.Name)] = true
		}
		excused := map[string]bool{}
		for _, name := range declared[p] {
			excused[http.CanonicalHeaderKey(name)] = true
		}

		var undeclared []string
		for _, name := range theFiveSecurityHeaders {
			canonical := http.CanonicalHeaderKey(name)
			if !present[canonical] && !excused[canonical] {
				undeclared = append(undeclared, name)
			}
		}
		if len(undeclared) > 0 {
			findings = append(findings, securityHeaderOmission{path: p, undeclared: undeclared})
		}
	}
	return read, findings, nil
}

// plural keeps the failure message readable when a golden omits four of the
// five, which is the shape a half-written declaration leaves behind.
func plural(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// TestTheMirrorHeaderRuleCanFail is the first thing to read in this file,
// because the rule above is green with 134 goldens excused by a declaration and
// that is the same colour a rule watching nothing comes in.
//
// **A rule with an exemption per finding is indistinguishable from no rule**
// unless something shows it still bites. Four cells are exercised here and each
// is a way this could have been written to pass everything: a golden that omits
// a header nobody declared is reported; the same golden with the declaration is
// not; a partial declaration reports the remainder rather than being satisfied
// by its first entry; and a case declaring a header its golden carries is left
// to TestAssertAbsentHeadersAgreeWithTheGolden rather than reported twice.
//
// The last cell is the one that matters most for the mutation F181 is about.
// Deleting an entry from a case's AssertAbsentHeaders is exactly cell one, and
// the rule reports it.
func TestTheMirrorHeaderRuleCanFail(t *testing.T) {
	t.Parallel()

	// A response carrying four of the five, which is the commonest shape in the
	// tree: everything but X-Frame-Options.
	fourOfFive := []byte("# GET /probe\n" +
		"HTTP/1.1 204 No Content\n" +
		"Referrer-Policy: no-referrer\n" +
		"Strict-Transport-Security: max-age=31536000; includeSubDomains\n" +
		"X-Content-Type-Options: nosniff\n" +
		"X-Robots-Tag: none\n" +
		"\n")
	none := []byte("# GET /probe\n" +
		"HTTP/1.1 404 Not Found\n" +
		"Content-Type: application/json\n" +
		"\n" +
		`{"error":"Unable to find matching target resource method"}`)

	corpus := map[string][]byte{"a.http": fourOfFive}

	read, got, err := undeclaredSecurityHeaderOmissions(corpus, nil)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if read != 1 {
		t.Errorf("read %d goldens, want 1", read)
	}
	if len(got) != 1 || len(got[0].undeclared) != 1 || got[0].undeclared[0] != "X-Frame-Options" {
		t.Errorf("an undeclared omission went unreported: %+v", got)
	}

	declared := map[string][]string{"a.http": {"X-Frame-Options"}}
	if _, got, _ := undeclaredSecurityHeaderOmissions(corpus, declared); len(got) != 0 {
		t.Errorf("a declared omission was reported anyway: %+v", got)
	}

	// A declaration covering some of what is missing leaves the rest reported.
	// Two committed cases were in exactly this state - one declaring two of the
	// five and one declaring one of them - and a rule satisfied by the first
	// entry would have called both of them done.
	part := map[string][]byte{"b.http": none}
	partial := map[string][]string{"b.http": {"X-Frame-Options", "Referrer-Policy"}}
	_, got, _ = undeclaredSecurityHeaderOmissions(part, partial)
	if len(got) != 1 || len(got[0].undeclared) != 3 {
		t.Errorf("a partial declaration was taken for a whole one: %+v", got)
	}

	// A header the golden carries is nobody's finding here. Declaring it absent
	// is a contradiction, and the test on the other side of the mirror is the
	// one that says so.
	over := map[string][]string{"a.http": {"X-Frame-Options", "Referrer-Policy"}}
	if _, got, _ := undeclaredSecurityHeaderOmissions(corpus, over); len(got) != 0 {
		t.Errorf("an over-broad declaration was reported by the wrong test: %+v", got)
	}

	// A golden no case names declares nothing, so every header it omits is
	// reported. That is the join being real rather than a lookup that silently
	// misses.
	if _, got, _ := undeclaredSecurityHeaderOmissions(part, declared); len(got) != 1 || len(got[0].undeclared) != 5 {
		t.Errorf("a golden the catalogue does not name was excused: %+v", got)
	}
}
