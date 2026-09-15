package conformance

import (
	"fmt"
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
