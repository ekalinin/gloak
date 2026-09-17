package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
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

// metricsChapter is the one management chapter that may still hold no
// Implemented case. It is a constant rather than a literal inside the refusal
// because the refusal's message names it and the two must agree.
const metricsChapter = "management/metrics"

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

		// Refusal one, **narrowed on 2026-09-16 rather than removed**.
		//
		// It used to refuse Implemented for every management case, and its
		// ground was measured: the verifier had one handler, so a management
		// case's request went to Gloak's main mux while its golden had been
		// recorded from port 9000 - two servers that disagree about the same
		// request, `GET //health` being 400 on one and 200 on the other. That
		// ground is gone. newManagementFixture builds the second handler, serve
		// routes to it through Target, and
		// TestTheVerifierAnswersAManagementCaseFromTheManagementServer
		// reproduces the very disagreement that made the refusal true - on
		// Gloak, on the two handlers the verifier now holds.
		//
		// What is left is narrower and is still measured. **A metrics case may
		// not be Implemented.** Gloak keeps no counters, so it has no
		// --metrics-enabled and serves no /metrics - which is not a gap but the
		// measured answer for that option set, since a metrics-disabled
		// Keycloak answers /metrics with the ordinary 53-byte 404. The two
		// recordable cases in that family are 406s out of Micrometer's content
		// negotiation, and an endpoint that produced them would need a success
		// branch, which could only be a fabricated dump. The dump cannot be
		// compared against anything either: 116 lines move between two requests
		// three seconds apart and 2156 between two containers, which is F113.
		// So there is nothing on that endpoint an Implemented case could
		// truthfully claim.
		if c.ManagementPort && c.Status == Implemented && chapterOf(c.ID) == metricsChapter {
			out = append(out, fmt.Sprintf(
				"%s is Implemented and is in %s. Gloak keeps no counters, so it has no "+
					"--metrics-enabled and no metrics endpoint; the only recordable responses "+
					"there are Micrometer's 406s, whose success branch would have to be a "+
					"fabricated dump, and the dump moves 116 lines in three seconds so nothing "+
					"on it can be compared. Serving one means building the counters first.",
				c.ID, metricsChapter))
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

		// Refusal four, added 2026-09-16 with Case.Configuration.
		//
		// **A metrics case has to be recorded under a configuration that has a
		// metrics endpoint**, and the mistake it refuses is the one this cut's
		// own mechanism invites. Every other case in this chapter declares
		// StartDevHealth, because that is the option set Gloak serves and
		// recording there is what took six cases from Recorded to Implemented.
		// Doing the same to these two would look like finishing the job and
		// would destroy them: `/metrics` under health alone is the ordinary
		// 53-byte 404, measured, so the golden would stop holding Micrometer's
		// 406 and start holding the fallback - which Gloak answers, so the case
		// would match, so it would have to be promoted, and the chapter would
		// report a behaviour served that nothing serves.
		//
		// It is keyed on the **environment** rather than on the configuration's
		// name, because what the behaviour needs is the endpoint and not a
		// spelling: a third configuration switching metrics on under another
		// name is served by this refusal without anybody editing it.
		if inChapter && chapterOf(c.ID) == metricsChapter {
			env, ok := keycloakEnv(ConfigurationOf(c))
			if !ok {
				out = append(out, fmt.Sprintf(
					"%s is recorded under %q, for which no container environment is declared",
					c.ID, ConfigurationOf(c)))
			} else if env["KC_METRICS_ENABLED"] != "true" {
				out = append(out, fmt.Sprintf(
					"%s is in %s and is recorded under %q, which has no metrics endpoint. "+
						"/metrics there is the ordinary 53-byte 404, so the golden would hold "+
						"the fallback rather than Micrometer's 406 - and Gloak answers that "+
						"404, so the case would match and read as served while the behaviour "+
						"it names is served by nothing.",
					c.ID, metricsChapter, ConfigurationOf(c)))
			}
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
// The first used to answer "what does the verifier serve for a management-port
// case" with "the main mux, because it has only one handler". It now has two:
// newManagementFixture builds Gloak's management interface and serve picks
// between them with Target, the same predicate the recorder picks a base URL
// with. So the refusal is narrowed to the one family whose ground survives -
// the metrics endpoint, which Gloak does not serve and whose only recordable
// responses could not be produced honestly.
//
// The other two are unchanged and both still matter, one of them more than
// before: a management case that does not declare the flag is now recorded from
// the wrong server **and** verified against the wrong handler.
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
			name:  "an implemented metrics case",
			cases: []Case{{ID: "management/metrics/dump", Status: Implemented, ManagementPort: true, Fixture: "bootstrap"}},
			want:  "Gloak keeps no counters",
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
		{
			name: "a metrics case recorded without the metrics endpoint",
			cases: []Case{{
				ID: "management/metrics/openmetrics-refused", Status: Recorded,
				ManagementPort: true, Fixture: "bootstrap", Configuration: StartDevHealth,
			}},
			want: "which has no metrics endpoint",
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

	// The configuration refusal from the side that must stay quiet, which is
	// the half a refusal keyed on "any declared configuration" would get wrong.
	// Two rows, because the two families take opposite values: the metrics
	// family needs the option and everything else in the chapter needs it off.
	t.Run("the configuration refusal is about the metrics endpoint and not about declaring one", func(t *testing.T) {
		metricsOnTheDefault := []Case{{
			ID: "management/metrics/prefix-match", Status: Recorded,
			ManagementPort: true, Fixture: "bootstrap",
		}}
		if got := managementDefects(metricsOnTheDefault, stepped); len(got) != 0 {
			t.Errorf("a metrics case on the default configuration was complained about: %v", got)
		}
		healthWithoutMetrics := []Case{{
			ID: "management/health/check", Status: Implemented,
			ManagementPort: true, Fixture: "bootstrap", Configuration: StartDevHealth,
		}}
		if got := managementDefects(healthWithoutMetrics, stepped); len(got) != 0 {
			t.Errorf("a health case recorded under the option set Gloak serves was "+
				"complained about: %v", got)
		}
	})

	// The lift, asserted rather than assumed. A refusal that was narrowed and a
	// refusal that was deleted look identical from the side that still fires;
	// this is the side that stopped firing, and it has to be checked or the
	// narrowing is a claim in a comment.
	t.Run("an implemented health case is allowed, which is the lift", func(t *testing.T) {
		lifted := []Case{{ID: "management/health/live", Status: Implemented, ManagementPort: true, Fixture: "bootstrap"}}
		if got := managementDefects(lifted, stepped); len(got) != 0 {
			t.Errorf("the verifier has a management handler and this is still refused: %v", got)
		}
	})

	// And the two families are told apart by the chapter rather than by the
	// status, so an Implemented index or fallback case is allowed too. Without
	// this row, a refusal reading "any Implemented case outside management/health"
	// would pass every row above.
	t.Run("the narrowing is to the metrics chapter and not to one case", func(t *testing.T) {
		for _, id := range []string{"management/index/root", "management/fallback/unknown-path"} {
			allowed := []Case{{ID: id, Status: Implemented, ManagementPort: true, Fixture: "bootstrap"}}
			if got := managementDefects(allowed, stepped); len(got) != 0 {
				t.Errorf("%s is Implemented and was refused: %v", id, got)
			}
		}
		for _, id := range []string{"management/metrics/dump", "management/metrics/prefix-match"} {
			refused := []Case{{ID: id, Status: Implemented, ManagementPort: true, Fixture: "bootstrap"}}
			if got := managementDefects(refused, stepped); len(got) != 1 {
				t.Errorf("%s is Implemented and got %d complaints, want exactly one: %v",
					id, len(got), got)
			}
		}
	})
}

// The two documents the eleven health and cross-cutting goldens hold between
// them, named by the cases that hold them.
//
// managementAggregateGoldens all answer /health's aggregate document - two
// checks, since all five are recorded under StartDevHealth - and the last three
// are the chapter's cross-cutting claims: the verb decides nothing, `Accept`
// decides nothing, and the path is not normalised. Each of those is a claim that
// **this request gets that same document**, and a claim of that shape is a
// relation between two goldens rather than a property of one.
//
// Those five must stay on one configuration or the equalities below stop
// meaning what they say: two of them recorded under different containers would
// disagree for a reason that is not the server's. TestTheFiveAggregateCasesAreOnOneConfiguration
// is what says so.
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

// TestTheFiveAggregateCasesAreOnOneConfiguration is the premise the equalities
// above rest on, made into an assertion.
//
// Five requests were measured answering one document, and the goldens are
// compared against each other to say so. A configuration is what decides how
// many checks that document holds, so moving one of the five to another
// container would make them disagree for a reason that has nothing to do with
// the server - and the failure would read as Keycloak changing its mind about
// /health. The same holds for the empty group, whose document is the same under
// both configurations today and need not stay so.
func TestTheFiveAggregateCasesAreOnOneConfiguration(t *testing.T) {
	for _, group := range [][]string{managementAggregateGoldens, managementEmptyGoldens} {
		var first Configuration
		for i, id := range group {
			var c Case
			for _, cc := range Catalog {
				if cc.ID == id {
					c = cc
				}
			}
			if c.ID == "" {
				t.Errorf("%s is named in a document group and is not in the catalogue", id)
				continue
			}
			cfg := ConfigurationOf(c)
			if i == 0 {
				first = cfg
				continue
			}
			if cfg != first {
				t.Errorf("%s is recorded under %q and %s under %q; these goldens are "+
					"compared against each other, so two containers would make them "+
					"disagree for a reason that is not the server's",
					group[0], first, id, cfg)
			}
		}
	}
}

// TestTargetFollowsTheFlag is the routing decision **both** sides make, tested
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
// must go to the main side **even when a management value was supplied**, which
// is what stops the routing being "whichever value is non-empty".
//
// The second half of the table is the same three rows over http.Handlers rather
// than strings, and it is not decoration. Target is generic precisely so the
// recorder and the verifier cannot come to disagree about which socket or which
// handler a case addresses, and a test that only ever instantiated it at one
// type would leave the other instantiation asserted by nothing.
func TestTargetFollowsTheFlag(t *testing.T) {
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
			if got := Target(main, mgmt, tc.c); got != tc.want {
				t.Errorf("Target = %q, want %q", got, tc.want)
			}
		})
	}

	// **Target must not read Status, and that had to be found by mutation.**
	// Narrowing the predicate to `c.ManagementPort && c.Status == Implemented`
	// was applied, compiled, and survived 26 subtests including the whole
	// management chapter of TestConformance. It is not a harmless narrowing: a
	// Recorded case is required *not* to match, so eight cases sent to the main
	// mux fail to match for the wrong reason and skip exactly as they should -
	// and the **recorder** reads this same function, so `make record` would have
	// rewritten those eight goldens from port 8080 and the diff would have looked
	// like Keycloak changing its mind.
	//
	// Implemented is iota, so it is Status's zero value, which is why every
	// table row above and the integration test below went through the mutated
	// branch without noticing. The rows here are the ones that do not: the
	// answer is the same for all three statuses, so a predicate that reads one
	// fails.
	for _, status := range []Status{Implemented, Recorded, Pending} {
		t.Run(fmt.Sprintf("the port does not depend on the status (%d)", status), func(t *testing.T) {
			if got := Target(main, mgmt, Case{ManagementPort: true, Status: status}); got != mgmt {
				t.Errorf("a management case with status %d went to %q; Target decides on "+
					"the socket a case addresses and a status is not one", status, got)
			}
			if got := Target(main, mgmt, Case{Status: status}); got != main {
				t.Errorf("an ordinary case with status %d went to %q", status, got)
			}
		})
	}

	named := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(name))
		})
	}
	mainH, mgmtH := named("main"), named("management")
	for _, tc := range []struct {
		name string
		c    Case
		want string
	}{
		{"a management case goes to the management handler", Case{ManagementPort: true}, "management"},
		{"an ordinary case goes to the main handler", Case{}, "main"},
		{"an ordinary case ignores the management handler it was given", Case{ID: "admin/users/read"}, "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			Target(mainH, mgmtH, tc.c).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := w.Body.String(); got != tc.want {
				t.Errorf("Target served %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTheVerifierAnswersAManagementCaseFromTheManagementServer is what replaces
// Case.ManagementPort's first refusal, and it is the same measurement that made
// that refusal true, taken on Gloak instead of on Keycloak.
//
// The refusal's ground was that the verifier had one handler while the goldens
// came from a second server, and the evidence was one request answered two ways
// on one Keycloak container:
//
//	GET //health  on 8080  400 {"error":"missingNormalization",...}
//	GET //health  on 9000  200 with the health document
//
// This sends that request to each of the two handlers the verifier now builds
// and requires the same two answers. **A guard that only checked "there are two
// handlers" could be satisfied by two handlers that are the same server**; this
// is satisfied only by two that disagree the way the reference pair disagrees,
// and it is the one request in this repository measured to tell them apart.
func TestTheVerifierAnswersAManagementCaseFromTheManagementServer(t *testing.T) {
	mainHandler := newFixture(t, "bootstrap")
	mgmtHandler := newManagementFixture(t)

	ask := func(h http.Handler) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost:8080//health", nil))
		return w
	}

	onMain := ask(mainHandler)
	if onMain.Code != http.StatusBadRequest {
		t.Errorf("the main handler answered GET //health with %d, want the 400 the "+
			"normalisation rule gives: %s", onMain.Code, onMain.Body)
	}
	if !strings.Contains(onMain.Body.String(), "missingNormalization") {
		t.Errorf("the main handler's GET //health is not missingNormalization: %s", onMain.Body)
	}

	onManagement := ask(mgmtHandler)
	if onManagement.Code != http.StatusOK {
		t.Errorf("the management handler answered GET //health with %d, want 200; "+
			"this port does not normalise, measured", onManagement.Code)
	}
	if !strings.Contains(onManagement.Body.String(), `"status": "UP"`) {
		t.Errorf("the management handler's GET //health is not the health document: %s",
			onManagement.Body)
	}
}

// TestServeSendsACaseToTheHandlerItsFlagNames closes the gap between "the
// verifier has two handlers" and "a case reaches the right one".
//
// Target is tested above on values, and the handlers are tested above as two
// servers. Neither says that serve wires the one to the other, and that is the
// join a later edit could break silently: dropping the branch from serve would
// leave every test above green while every management case was compared against
// the main mux again.
//
// It sends **one path, twice, differing only in the flag** - which is the same
// shape as the measurement on the reference container, and the reason it is one
// path rather than two cases is that two paths could differ for two reasons.
func TestServeSendsACaseToTheHandlerItsFlagNames(t *testing.T) {
	live := Request{Method: http.MethodGet, Path: "/health/live"}

	// **Status: Recorded, deliberately.** Implemented is Status's zero value, so
	// a case written without one goes through any predicate that reads the
	// status as though it were Implemented - which is how a narrowed Target
	// survived this test once. A Recorded management case is the one that has to
	// reach the management handler and the one nothing else here would notice
	// missing, because a Recorded case is required not to match anyway.
	onManagement, _, err := serve(t, Case{
		ID: "management/health/live", Status: Recorded, Fixture: "bootstrap",
		ManagementPort: true, Request: live,
	})
	if err != nil {
		t.Fatalf("serve the management case: %v", err)
	}
	if onManagement.Code != http.StatusOK {
		t.Errorf("a ManagementPort case got %d for /health/live, want the management "+
			"interface's 200: %s", onManagement.Code, onManagement.Body)
	}

	onMain, _, err := serve(t, Case{
		ID: "management/health/live", Fixture: "bootstrap", Request: live,
	})
	if err != nil {
		t.Fatalf("serve the same request without the flag: %v", err)
	}
	if onMain.Code != http.StatusNotFound {
		t.Errorf("the same request without the flag got %d, want the main server's 404; "+
			"if these two agree, serve is not reading the flag at all", onMain.Code)
	}
}

// theAggregateOnTheWire is what port 9000 actually sent for GET /health on a
// **both-options** container, read off a socket on 2026-09-16: 345 bytes, with
// the `checks` array opened on its own line.
//
// **No golden holds this document any more.** management/health/check is
// recorded under StartDevHealth since Case.Configuration existed, so the
// committed bytes are the two-check document Gloak serves. This constant is the
// three-check measurement kept where something still reads it: the option
// coupling - that `--metrics-enabled` adds a *health* check - is a fact about
// Keycloak that was previously asserted by a golden, and
// TestTheTwoAggregateDocumentsDifferByTheMetricsCheck is what asserts it now.
const theAggregateOnTheWire = "{\n" +
	"    \"status\": \"UP\",\n" +
	"    \"checks\": [\n" +
	"        {\n" +
	"            \"name\": \"Graceful Shutdown\",\n" +
	"            \"status\": \"UP\"\n" +
	"        },\n" +
	"        {\n" +
	"            \"name\": \"Keycloak Initialized\",\n" +
	"            \"status\": \"UP\"\n" +
	"        },\n" +
	"        {\n" +
	"            \"name\": \"Keycloak database connections async health check\",\n" +
	"            \"status\": \"UP\"\n" +
	"        }\n" +
	"    ]\n" +
	"}"

// theHealthOnlyAggregateOnTheWire is the same request on a container started
// with `--health-enabled` alone, read off a socket on 2026-09-16: 225 bytes,
// the same layout, two checks.
//
// **This is the document management/health/check's golden is a recording of**,
// and it is what Gloak serves.
const theHealthOnlyAggregateOnTheWire = "{\n" +
	"    \"status\": \"UP\",\n" +
	"    \"checks\": [\n" +
	"        {\n" +
	"            \"name\": \"Graceful Shutdown\",\n" +
	"            \"status\": \"UP\"\n" +
	"        },\n" +
	"        {\n" +
	"            \"name\": \"Keycloak Initialized\",\n" +
	"            \"status\": \"UP\"\n" +
	"        }\n" +
	"    ]\n" +
	"}"

// theDatabaseCheck is the entry `--metrics-enabled` adds, and the name is the
// contract: it is a **health** check whose presence a *metrics* flag decides,
// which looks like a bug and is measured.
const theDatabaseCheck = "Keycloak database connections async health check"

// aggregateCase returns management/health/check out of the catalogue, with the
// mask this pair of tests is about confirmed present.
func aggregateCase(t *testing.T) Case {
	t.Helper()
	var c Case
	for _, cc := range Catalog {
		if cc.ID == "management/health/check" {
			c = cc
		}
	}
	if len(c.Unordered) == 0 {
		t.Fatal("management/health/check carries no Unordered mask, so these tests are " +
			"about a normalisation that no longer happens")
	}
	return c
}

// TestTheAggregateGoldenIsTheWireBytesAfterTheMask is a trap defused.
//
// `management/health/check`'s golden holds **202** bytes and opens its array
// `[{`; the socket sent **225** and opened it `[` newline eight spaces `{`. A
// reader comparing the committed file against a `curl` would conclude that Gloak
// serves a body no Keycloak has produced, and a code review of this chapter did
// conclude exactly that, when the numbers were 313 and 345.
//
// It is the `Unordered: []string{"checks"}` mask. Sorting an array means parsing
// and re-rendering it, and the re-rendering is not the wire's layout - so **the
// golden is the normalised form of the response, not the response**. The
// comparison is sound because `normalisePasses` runs on both sides: the recorder
// applies it before writing (`record_test.go`) and `diff` applies it to what
// Gloak served (`conformance_test.go`). Nothing ever compares a golden to a
// socket.
//
// This pins the relationship so the next reader finds it asserted rather than
// having to rediscover it, and so that a change to the sort's rendering is a
// failing test rather than 202 bytes quietly becoming something else.
//
// **The transcription moved with the case's configuration and that is the whole
// change here.** It held the both-options wire until 2026-09-16, because the
// recorder ran one configuration; it holds the health-only wire now, because the
// case declares StartDevHealth and the golden is a recording of that container.
// A test comparing one configuration's bytes against another's golden would have
// been the most confusing possible failure, which is why the two constants are
// named for their configurations rather than for their sizes.
func TestTheAggregateGoldenIsTheWireBytesAfterTheMask(t *testing.T) {
	c := aggregateCase(t)
	if got := ConfigurationOf(c); got != StartDevHealth {
		t.Fatalf("management/health/check is recorded under %q and this test holds the "+
			"wire bytes of %q; the transcription and the case have to name one container",
			got, StartDevHealth)
	}

	wire := []byte(theHealthOnlyAggregateOnTheWire)
	// **The length is what makes the constant above a transcription.** 225 is
	// the `content-length` the socket reported; it is the one number here that
	// was read rather than typed. Without it the constant's *layout* is pinned
	// by nothing: a mutation collapsing its array opener to the golden's `[{`
	// survived, because the mask re-renders either form to the same bytes and
	// the equality below held for the wrong reason.
	if len(wire) != 225 {
		t.Fatalf("the transcribed wire body is %d bytes and the socket reported 225; "+
			"this test is about the difference between that layout and the golden's, "+
			"so a transcription that has drifted towards the golden records nothing",
			len(wire))
	}
	normalised, err := normalisePasses(wire, testIssuer, c, nil)
	if err != nil {
		t.Fatalf("normalise the wire bytes: %v", err)
	}

	raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	g, err := ParseGolden(raw)
	if err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	if string(normalised) != string(g.Body) {
		t.Errorf("the measured wire bytes do not normalise to the committed golden.\n"+
			"wire (%d bytes):       %q\nnormalised (%d bytes): %q\ngolden (%d bytes):     %q",
			len(wire), wire, len(normalised), normalised, len(g.Body), g.Body)
	}
	// The vacuity guard, and it is the whole reason this test says anything: if
	// the mask stopped re-rendering, the wire and the golden would be equal and
	// the equality above would hold for a different reason.
	if string(wire) == string(g.Body) {
		t.Error("the wire bytes and the golden are identical, so this test no longer " +
			"records that the mask re-renders the array")
	}
}

// TestTheTwoAggregateDocumentsDifferByTheMetricsCheck is what the three-check
// document left behind when it left the golden tree.
//
// Until 2026-09-16 `management/health/check`'s golden held the both-options
// document, and that recording was the only place in this repository where the
// option coupling - **a metrics flag decides whether a health check exists** -
// was asserted rather than written in prose. Re-recording the case under the
// configuration Gloak serves is what took it from Recorded to Implemented and
// what would have quietly discarded that.
//
// It is kept as a **relation between two transcriptions** rather than as a
// second case, for two reasons. A case would go into the chapter's denominator
// as a behaviour Gloak will never serve - `TestGloakPublishesNoDatabaseCheck`
// is the assertion that it must not - where `Recorded` means "not built yet"
// and is a list that exists to empty itself. And the claim is not a response: it
// is the difference between two responses, which no single golden can hold.
//
// Both lengths were read off sockets on containers started for the purpose, and
// they are the vacuity guard: a transcription edited to agree with its
// neighbour would satisfy the subtraction below and record nothing.
func TestTheTwoAggregateDocumentsDifferByTheMetricsCheck(t *testing.T) {
	both, health := theAggregateOnTheWire, theHealthOnlyAggregateOnTheWire
	if len(both) != 345 {
		t.Fatalf("the both-options transcription is %d bytes and the socket reported 345", len(both))
	}
	if len(health) != 225 {
		t.Fatalf("the health-only transcription is %d bytes and the socket reported 225", len(health))
	}
	if !strings.Contains(both, theDatabaseCheck) {
		t.Fatalf("the both-options document does not name %q, so it is not the "+
			"metrics-on recording", theDatabaseCheck)
	}
	if strings.Contains(health, theDatabaseCheck) {
		t.Fatalf("the health-only document names %q; the whole coupling is that it does "+
			"not", theDatabaseCheck)
	}

	// The two are the same document with one entry added, which is the claim.
	// Comparing the parsed check lists rather than the bytes is deliberate: the
	// entry arrives with its own indentation and a comma on the entry before
	// it, so a byte-level subtraction would be asserting SmallRye's layout a
	// third time - the byte table in internal/httpx already does that twice.
	names := func(doc string) []string {
		t.Helper()
		var parsed struct {
			Checks []struct{ Name string } `json:"checks"`
		}
		if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
			t.Fatalf("parse %q: %v", doc, err)
		}
		out := make([]string, 0, len(parsed.Checks))
		for _, e := range parsed.Checks {
			out = append(out, e.Name)
		}
		return out
	}
	withMetrics, withoutMetrics := names(both), names(health)
	var remainder []string
	for _, n := range withMetrics {
		if n != theDatabaseCheck {
			remainder = append(remainder, n)
		}
	}
	if !slices.Equal(remainder, withoutMetrics) {
		t.Errorf("the two configurations' check lists differ by more than the database "+
			"check.\nwith metrics:    %v\nwithout metrics: %v", withMetrics, withoutMetrics)
	}
	if len(withoutMetrics) != 2 || len(withMetrics) != 3 {
		t.Errorf("the documents hold %d and %d checks, and the measurement is two and three",
			len(withoutMetrics), len(withMetrics))
	}
}

// TestTheIndexGoldenIsTheHealthOnlyPage is the positive control for the
// recorder actually starting the container the catalogue names.
//
// `TestEveryGoldenNamesTheConfigurationItsCaseDeclares` compares the file's line
// against the case's declaration, and both of those are written from the same
// value in one run - so it catches a declaration that moved without a re-record
// and **not** a recorder that started the wrong container and wrote the right
// line. This is the other half, and the index page is where it is cheapest: its
// body is a list of the endpoints that are switched on, so a golden recorded
// with metrics on names `/metrics` and one recorded without it cannot.
//
// The aggregate has the same property and is covered by
// TestTheAggregateGoldenIsTheWireBytesAfterTheMask, which compares it against a
// transcription of the health-only wire. Between them the two option-dependent
// responses in this chapter are both pinned to the configuration they claim.
func TestTheIndexGoldenIsTheHealthOnlyPage(t *testing.T) {
	var c Case
	for _, cc := range Catalog {
		if cc.ID == "management/index/root" {
			c = cc
		}
	}
	if got := ConfigurationOf(c); got != StartDevHealth {
		t.Fatalf("management/index/root is recorded under %q and this test is about the "+
			"health-only page", got)
	}

	raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	g, err := ParseGolden(raw)
	if err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	body := string(g.Body)
	if !strings.Contains(body, `<a href="/health">/health</a>`) {
		t.Errorf("the index golden does not list /health, so it is not this port's index "+
			"page at all: %q", body)
	}
	if strings.Contains(body, "/metrics") {
		t.Errorf("the index golden lists /metrics, so it was recorded against a container "+
			"started with --metrics-enabled while its case declares %q. The page lists "+
			"exactly the endpoints that are on, which is what makes it the cheapest check "+
			"that the recorder started the container the catalogue named: %q",
			StartDevHealth, body)
	}
	// The length is the measurement: 120 bytes with health alone, 180 with both
	// and 123 with metrics alone, read off sockets. Without it, a page listing
	// /health and nothing else could still have drifted.
	if len(g.Body) != 120 {
		t.Errorf("the index golden is %d bytes and a --health-enabled container sent 120",
			len(g.Body))
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
