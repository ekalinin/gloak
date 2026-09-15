package conformance

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// managementChapterCases is the chapter's count, pinned where a test can read
// it rather than left in a comment beside the slice it counts.
//
// account-api.md records what happens without this: "the commit subject said
// 36, the file's own heading said 41, the slice held 39, and a paragraph said
// seventeen paths where the list above it had sixteen", all inside one chapter
// before anybody had merged it. The number in docs/superpowers/handover/
// management-port.md and the number in chapters.go are both this one.
const managementChapterCases = 16

// inManagementChapter reports whether c reports under one of the four chapters
// the management interface is split across. The split is route families, the
// way the OIDC, SAML and account sides are split, so there is no single
// chapter name to compare against - chapterOf groups by two slug segments.
func inManagementChapter(c Case) bool {
	return strings.HasPrefix(chapterOf(c.ID), "management/")
}

func TestManagementChapterCountIsThePinnedNumber(t *testing.T) {
	n := 0
	for _, c := range Catalog {
		if inManagementChapter(c) {
			n++
		}
	}
	if n != managementChapterCases {
		t.Errorf("the management chapter holds %d cases and managementChapterCases says %d; "+
			"the handover and chapters.go both quote this number", n, managementChapterCases)
	}
}

// managementDefects returns one complaint per way cases break
// Case.ManagementPort's three refusals, and no complaints when they hold.
//
// It takes a slice rather than reading Catalog so the guard below can be run on
// inputs that break each rule. A guard that can only be run on a catalogue
// written to satisfy it is green for two reasons and cannot tell them apart.
func managementDefects(cases []Case, fixtures map[string]Fixture) []string {
	var out []string
	for _, c := range cases {
		inChapter := inManagementChapter(c)
		if !c.ManagementPort && !inChapter {
			continue
		}

		// Refusal one: the verifier has one handler and it is Gloak's main mux,
		// so an Implemented management case asserts that the main port
		// reproduces bytes recorded from the management port. Keycloak's own
		// main port answers /health with the unmatched-path 404, so that is a
		// contract nobody wants met.
		if c.ManagementPort && c.Status == Implemented {
			out = append(out, fmt.Sprintf(
				"%s is Implemented and goes to the management port, but the verifier has one "+
					"handler and serves it to Gloak's main mux - a different server from the one "+
					"its golden was recorded against. Give the verifier a management handler and "+
					"lift this refusal in the same commit.", c.ID))
		}

		// Refusal two, in both directions. The flag decides which socket the
		// recorder connects to and the chapter decides which row of the meter
		// the case lands in; one without the other files a measurement of one
		// server under another's heading.
		switch {
		case c.ManagementPort && !inChapter:
			out = append(out, fmt.Sprintf(
				"%s sends its request to the management port and reports under %s; a "+
					"management-port measurement filed under another chapter is counted as "+
					"that chapter's behaviour", c.ID, chapterOf(c.ID)))
		case inChapter && !c.ManagementPort:
			out = append(out, fmt.Sprintf(
				"%s is in the management chapter and does not declare ManagementPort, so the "+
					"recorder will send it to port 8080 and record the wrong server", c.ID))
		}

		// Refusal three: a fixture's steps run against the main port, and
		// nothing they can do reaches this one.
		if c.ManagementPort && c.Fixture != "" {
			if f, ok := fixtures[c.Fixture]; ok && len(f.Steps) > 0 {
				out = append(out, fmt.Sprintf(
					"%s goes to the management port and names fixture %s, which runs %d step(s) "+
						"against the main port; nothing a step can do reaches port 9000",
					c.ID, c.Fixture, len(f.Steps)))
			}
		}
	}
	return out
}

// TestManagementRefusals runs the three refusals over the catalogue.
//
// The first is the one that answers "what does the verifier serve for a
// management-port case". It serves the request to the same handler it serves
// every other case to, because it has exactly one, and that handler is Gloak's
// main mux. The golden beside it was recorded from port 9000. Those are two
// different servers on one container, measured disagreeing about the same
// request: `GET //health` is a 400 on 8080 and a 200 on 9000.
//
// So the verifier is not answering the question the golden asks. Recorded is
// honest about that - it asserts only "these differ" - and the refusal is what
// stops anything claiming more. When Gloak grows a management interface,
// whoever builds it gives the verifier a second handler and lifts this in the
// same commit, which a reviewer sees.
func TestManagementRefusals(t *testing.T) {
	declared := 0
	for _, c := range Catalog {
		if c.ManagementPort {
			declared++
		}
	}
	if declared == 0 {
		t.Fatal("no case declares ManagementPort, so these refusals have nothing to refuse")
	}
	for _, d := range managementDefects(Catalog, Fixtures) {
		t.Error(d)
	}
}

// TestManagementRefusalGuardCanFail proves each refusal fires, on the exact
// mistake its message describes. All three are green on a catalogue written to
// satisfy them, which is the same colour a guard watching nothing comes in.
func TestManagementRefusalGuardCanFail(t *testing.T) {
	stepped := map[string]Fixture{
		"bootstrap":   {State: "bootstrap"},
		"admin-token": {State: "bootstrap", Steps: []Step{{Request: Request{Method: "POST", Path: "/x"}}}},
	}
	for _, tc := range []struct {
		name  string
		cases []Case
		want  string
	}{
		{
			name:  "implemented",
			cases: []Case{{ID: "management/health/check", Status: Implemented, ManagementPort: true, Fixture: "bootstrap"}},
			want:  "Give the verifier a management handler",
		},
		{
			name:  "flag outside the chapter",
			cases: []Case{{ID: "http/fallback/unmatched", Status: Recorded, ManagementPort: true, Fixture: "bootstrap"}},
			want:  "filed under another chapter",
		},
		{
			name:  "chapter without the flag",
			cases: []Case{{ID: "management/health/check", Status: Recorded, Fixture: "bootstrap"}},
			want:  "record the wrong server",
		},
		{
			name:  "fixture with steps",
			cases: []Case{{ID: "management/health/check", Status: Recorded, ManagementPort: true, Fixture: "admin-token"}},
			want:  "nothing a step can do reaches port 9000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := managementDefects(tc.cases, stepped)
			if len(got) != 1 {
				t.Fatalf("want exactly one complaint, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0], tc.want) {
				t.Errorf("complaint does not name the mistake: want it to mention %q, got %q",
					tc.want, got[0])
			}
		})
	}

	t.Run("a well-formed case is not complained about", func(t *testing.T) {
		ok := []Case{{ID: "management/health/check", Status: Recorded, ManagementPort: true, Fixture: "bootstrap"}}
		if got := managementDefects(ok, stepped); len(got) != 0 {
			t.Errorf("a case that breaks no refusal was complained about: %v", got)
		}
	})
}

// The two documents the eleven health and cross-cutting goldens hold between
// them, named by the cases that hold them.
//
// managementAggregateGoldens all answer /health's three-check document, and the
// last three are the chapter's cross-cutting claims: the verb decides nothing,
// `Accept` decides nothing, and the path is not normalised. Each of those is a
// claim that **this request gets that same document**, and a claim of that
// shape is a relation between two goldens rather than a property of one.
//
// managementEmptyGoldens all answer the empty-checks document. /health/started
// being in this group and not the one above is the finding that the four
// MicroProfile paths are two documents rather than four, and that which path
// gets which is not guessable from the names.
var managementAggregateGoldens = []string{
	"management/health/check",
	"management/health/ready",
	"management/health/accept-ignored",
	"management/health/wrong-verb",
	"management/health/unnormalised-path",
}

var managementEmptyGoldens = []string{
	"management/health/live",
	"management/health/started",
	"management/health/well",
	"management/health/group",
	"management/health/group-unknown",
}

// goldensThatDisagree returns one complaint per golden in group whose body
// differs from the first's, and no complaints when they all hold one document.
//
// It takes a reader rather than reading files so the comparison can be run on
// bodies known to differ. **The traversal's vacuity guard does not cover the
// comparison**, which was measured: disabling the equality left the partition
// check, the non-empty check and the two-documents-differ check all passing,
// and the test went green having compared nothing. That is AGENTS.md's rule met
// on a test written the same afternoon it was quoted.
func goldensThatDisagree(group []string, body func(string) []byte) []string {
	var out []string
	if len(group) < 2 {
		return out
	}
	first := body(group[0])
	for _, id := range group[1:] {
		if got := body(id); !bytes.Equal(got, first) {
			out = append(out, fmt.Sprintf(
				"%s and %s were measured answering the same document and their goldens "+
					"differ.\n%s: %s\n%s: %s", group[0], id, group[0], first, id, got))
		}
	}
	return out
}

// TestManagementHealthGoldenComparisonCanFail is that comparison's own guard.
func TestManagementHealthGoldenComparisonCanFail(t *testing.T) {
	bodies := map[string][]byte{
		"a": []byte(`{"status":"UP"}`),
		"b": []byte(`{"status":"UP"}`),
		"c": []byte(`{"status":"DOWN"}`),
	}
	read := func(id string) []byte { return bodies[id] }

	if got := goldensThatDisagree([]string{"a", "b"}, read); len(got) != 0 {
		t.Errorf("two identical bodies were reported as disagreeing: %v", got)
	}
	got := goldensThatDisagree([]string{"a", "b", "c"}, read)
	if len(got) != 1 {
		t.Fatalf("want one complaint about the body that differs, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "DOWN") {
		t.Errorf("the complaint does not show the body that differs: %q", got[0])
	}
}

// TestManagementHealthGoldensHoldTheDocumentTheyWereMeasuredTo is this
// chapter's answer to a surviving mutation.
//
// Changing `Graceful Shutdown` to `Graceless Shutdown` inside
// management/health/check's golden was applied, compiled and run against the
// whole package, and **nothing failed**. That is not a defect in this chapter:
// it is account-api.md's rule met on a fresh surface - a Recorded golden that
// is wrong is invisible, because the verifier requires the served response
// *not* to match and a corrupted golden does not match either way. Every case
// here is Recorded, so every body in this chapter sat in that hole.
//
// What closes it is not a copy of the bytes, which would be a golden checked
// against a second golden somebody typed. It is the **relations the chapter
// claims**: five of these requests were measured answering one document and
// five answering another, and those equalities are assertions no single case
// can make. A byte changed in any one of the ten now disagrees with four
// siblings.
//
// The vacuity guards are two, because the traversal and the comparison need
// their own. The first is that both groups are non-empty and every named golden
// was read. The second is that the two documents **differ from each other**: a
// bug that made every golden read as empty bytes would satisfy ten equalities
// and say nothing, and it is the comparison rather than the walk that would be
// hollow.
func TestManagementHealthGoldensHoldTheDocumentTheyWereMeasuredTo(t *testing.T) {
	read := func(id string) []byte {
		t.Helper()
		raw, err := os.ReadFile(GoldenPath(goldenDir, id))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		g, err := ParseGolden(raw)
		if err != nil {
			t.Fatalf("%s: parse golden: %v", id, err)
		}
		return g.Body
	}

	agree := func(group []string) []byte {
		t.Helper()
		if len(group) < 2 {
			t.Fatalf("a group of %d goldens asserts no equality", len(group))
		}
		for _, d := range goldensThatDisagree(group, read) {
			t.Error(d)
		}
		return read(group[0])
	}

	// The mirror, and it is the reason the two lists are a partition rather
	// than a sample. Removing management/health/started from its group was
	// applied and survived: the test checked the claims that were made, and a
	// smaller set of true claims is still true - which is F181's shape on a new
	// pair of lists. Joining against the catalogue is what makes a deletion
	// visible, and it is also what refuses the next health case being added
	// without a group.
	grouped := map[string]int{}
	for _, id := range append(append([]string{}, managementAggregateGoldens...), managementEmptyGoldens...) {
		grouped[id]++
	}
	for _, c := range Catalog {
		if chapterOf(c.ID) != "management/health" {
			continue
		}
		switch grouped[c.ID] {
		case 1:
			delete(grouped, c.ID)
		case 0:
			t.Errorf("%s is a management/health case and is in neither document group, "+
				"so no golden is compared against its bytes", c.ID)
		default:
			t.Errorf("%s is in both document groups, which would assert the two documents "+
				"are the same", c.ID)
		}
	}
	for id := range grouped {
		t.Errorf("%s is named in a document group and is not a management/health case", id)
	}

	aggregate := agree(managementAggregateGoldens)
	empty := agree(managementEmptyGoldens)

	if len(aggregate) == 0 || len(empty) == 0 {
		t.Fatal("a group's document is empty, so its equalities compare nothing")
	}
	if bytes.Equal(aggregate, empty) {
		t.Fatal("the aggregate document and the empty one are the same bytes, so the split " +
			"this chapter records - four /health paths, two documents - is asserted by nothing")
	}
}

// TestRecordTargetFollowsTheFlag is the recorder's routing decision, tested
// where a build without Docker can reach it.
//
// The decision used to be three lines inside record_test.go, which carries the
// `docker` build tag. A mutation collapsing it to "always the main port" was
// applied and survived the whole package - 1147 tests, none of which the build
// even compiles that file for. The only thing that could have caught it is
// running `make record` and reading fourteen goldens, which is not a guard a
// pull request can rely on.
//
// The third case is the one worth having: a case that does not declare the flag
// must go to the main port **even when a management URL was supplied**, which
// is what stops the routing being "whichever URL is non-empty".
func TestRecordTargetFollowsTheFlag(t *testing.T) {
	const main, mgmt = "http://host:8080", "http://host:9000"
	for _, tc := range []struct {
		name string
		c    Case
		want string
	}{
		{"a management case goes to the management port", Case{ManagementPort: true}, mgmt},
		{"an ordinary case goes to the main port", Case{}, main},
		{"an ordinary case ignores the management URL it was given", Case{ID: "admin/users/read"}, main},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RecordTarget(main, mgmt, tc.c); got != tc.want {
				t.Errorf("RecordTarget = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestManagementCasesDeclareTheSecurityHeadersAbsent is the finding made into
// an assertion.
//
// Not one response on port 9000 carries any of the five, measured at socket
// level on every route shape and on the fallback. AGENTS.md's rule is that a
// comment claiming a header is absent is not an assertion - four cases in this
// repository carried such a sentence while declaring one or two of the headers
// present, and nothing compared the sentence to the list.
//
// This is the sweep over the chapter rather than a per-case check, because the
// mistake worth catching is the **next** management case being written without
// the declaration. TestAssertAbsentHeadersAgreeWithTheGolden is what compares
// each declaration against the recorded bytes; this is what says every case
// that has bytes has to make one.
//
// **It reads theFiveSecurityHeaders and not managementSecurityHeaders**, and
// that is the whole difference between a guard and a tautology. The cases
// spread managementSecurityHeaders into their declarations, so a guard reading
// the same slice would compare a list against itself: dropping a name from it
// would drop the name from all fourteen declarations and from the guard's
// expectation in one edit, and pass. theFiveSecurityHeaders is the set
// AGENTS.md's bullet is about, declared for a different test in
// headersplit_test.go, and it is the independent source this needs.
func TestManagementCasesDeclareTheSecurityHeadersAbsent(t *testing.T) {
	checked := 0
	for _, c := range Catalog {
		if !c.ManagementPort || c.Status == Pending {
			continue // a Pending case has no golden to declare anything about
		}
		checked++
		declared := map[string]bool{}
		for _, name := range c.AssertAbsentHeaders {
			declared[name] = true
		}
		var missing []string
		for _, name := range theFiveSecurityHeaders {
			if !declared[name] {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%q does not declare %s absent; no management-port response carries "+
				"any of the five, and an undeclared absence is asserted by nothing",
				c.ID, strings.Join(missing, ", "))
		}
	}
	if checked == 0 {
		t.Fatal("no management case carries a golden, so this guard checked nothing")
	}
}
