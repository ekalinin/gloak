package conformance

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestConfigurationEnvironmentsArePinned reads the declared table whole rather
// than checking one entry against the code that uses it.
//
// **A table pinned entry by entry is a table an entry can be added to or taken
// out of silently**, which is AGENTS.md's rule about a vacuity guard covering
// the traversal and not the claim, and it is the shape internal/model uses for
// the providers with no mapper set. An entry arriving and an entry leaving each
// fail here on their own.
//
// The environment spellings matter and cannot be inferred from the
// configuration's own name: Keycloak's CLI flag is `--health-enabled` and the
// container variable is `KC_HEALTH_ENABLED`, and AGENTS.md's convention is that
// Gloak's own variables carry the `GLOAK_` prefix and never `KC_`. These are
// Keycloak's, on Keycloak's container, so they are the ones that would be got
// wrong by somebody applying that rule without reading it.
func TestConfigurationEnvironmentsArePinned(t *testing.T) {
	want := map[Configuration]map[string]string{
		"start-dev --health-enabled --metrics-enabled": {
			"KC_HEALTH_ENABLED":  "true",
			"KC_METRICS_ENABLED": "true",
		},
		"start-dev --health-enabled": {
			"KC_HEALTH_ENABLED": "true",
		},
	}
	if len(configurationEnv) != len(want) {
		t.Fatalf("the catalogue declares %d configurations and this test pins %d; "+
			"a configuration arriving or leaving is a change to what `make record` starts",
			len(configurationEnv), len(want))
	}
	for cfg, env := range want {
		got, ok := keycloakEnv(cfg)
		if !ok {
			t.Errorf("configuration %q is pinned here and not declared", cfg)
			continue
		}
		if len(got) != len(env) {
			t.Errorf("configuration %q is started with %v, want %v", cfg, got, env)
			continue
		}
		for k, v := range env {
			if got[k] != v {
				t.Errorf("configuration %q sets %s=%q, want %q", cfg, k, got[k], v)
			}
		}
	}

	// The default is a value in this table rather than a fourth state, and it
	// is the both-options one on purpose: making the option set Gloak serves
	// the default would re-record 1130 goldens to answer a question six of them
	// ask.
	if _, ok := keycloakEnv(DefaultConfiguration); !ok {
		t.Errorf("DefaultConfiguration is %q and no container environment is declared for it",
			DefaultConfiguration)
	}
	if _, ok := keycloakEnv("start-dev"); ok {
		t.Error("a configuration with no health or metrics option is declared; such a " +
			"container has no listener on 9000 at all and the first management request " +
			"gets an empty reply - F249")
	}
}

// TestConfigurationsIsEveryDeclaredOne keeps the sorted accessor honest, since
// it is what a report or a log over the configurations would walk.
func TestConfigurationsIsEveryDeclaredOne(t *testing.T) {
	got := Configurations()
	if len(got) != len(configurationEnv) {
		t.Fatalf("Configurations() lists %d of %d declared", len(got), len(configurationEnv))
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
		t.Errorf("Configurations() is not sorted: %v", got)
	}
	for _, cfg := range got {
		if _, ok := keycloakEnv(cfg); !ok {
			t.Errorf("Configurations() lists %q, which is not declared", cfg)
		}
	}
}

// TestConfigurationOfFollowsTheDeclaration is the guard this cut's own
// predicate needs, and its shape is borrowed from the mutation that nearly cost
// eight goldens.
//
// Target was narrowed to `c.ManagementPort && c.Status == Implemented`, which
// compiled and survived 26 subtests because Implemented is Status's zero value
// and a Recorded case is required not to match anyway. ConfigurationOf decides
// something strictly larger - not which socket of a container, but which
// container - so the same narrowing here would have `make record` start the
// wrong server rather than connect to the wrong port of the right one.
//
// The rows below are what makes the predicate unable to read anything but the
// one field: every status, both values of ManagementPort, and an ID that names
// the management chapter. A predicate keyed on any of those passes a catalogue
// written to satisfy it and fails here.
func TestConfigurationOfFollowsTheDeclaration(t *testing.T) {
	for _, status := range []Status{Implemented, Recorded, Pending} {
		for _, mgmt := range []bool{false, true} {
			name := fmt.Sprintf("status %d management %v", status, mgmt)
			t.Run(name, func(t *testing.T) {
				undeclared := Case{ID: "management/health/check", Status: status, ManagementPort: mgmt}
				if got := ConfigurationOf(undeclared); got != DefaultConfiguration {
					t.Errorf("a case declaring nothing is recorded under %q, want the default %q",
						got, DefaultConfiguration)
				}
				declared := Case{
					ID: "management/health/check", Status: status, ManagementPort: mgmt,
					Configuration: StartDevHealth,
				}
				if got := ConfigurationOf(declared); got != StartDevHealth {
					t.Errorf("a case declaring %q is recorded under %q", StartDevHealth, got)
				}
			})
		}
	}

	// The two ends of the management chapter, which is the one place a reader
	// would guess the chapter decides. It does not: the health half is recorded
	// without metrics and the metrics half cannot be.
	health := Case{ID: "management/health/check", ManagementPort: true, Configuration: StartDevHealth}
	metrics := Case{ID: "management/metrics/prefix-match", ManagementPort: true}
	if ConfigurationOf(health) == ConfigurationOf(metrics) {
		t.Error("the health and metrics halves of one chapter came back on one configuration; " +
			"a predicate reading ManagementPort or the chapter would do exactly that, and " +
			"recording the metrics cases without --metrics-enabled replaces their 406 with " +
			"the fallback 404")
	}
}

// goldenConfigurationFaults returns one complaint per golden in corpus whose
// configuration line disagrees with what its case declares, and no complaints
// when they all agree.
//
// It takes a map and a lookup rather than reading the tree so the **comparison**
// can be given inputs it must report. AGENTS.md's rule is that a vacuity guard
// covers the traversal and the comparison needs its own, and the traversal's
// floor cannot stand in for it: a comparison edited into reading the same value
// on both sides visits every file, counts every one, and asserts nothing.
func goldenConfigurationFaults(corpus map[string][]byte, declared map[string]Configuration) []string {
	paths := make([]string, 0, len(corpus))
	for p := range corpus {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []string
	for _, p := range paths {
		g, err := ParseGolden(corpus[p])
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		want, ok := declared[p]
		if !ok {
			out = append(out, fmt.Sprintf("%s: no case in the catalogue names this golden, "+
				"so nothing says which container it was recorded against", p))
			continue
		}
		if g.Configuration != want {
			out = append(out, fmt.Sprintf(
				"%s says it was recorded with %q and its case declares %q; one of the two is "+
					"wrong, and a golden recorded under the wrong container is a contract for a "+
					"server nobody runs", p, g.Configuration, want))
		}
	}
	return out
}

// TestGoldenConfigurationComparisonCanFail is that comparison's own control.
//
// Three inputs, because three things can go wrong and a guard that only reports
// one of them is a guard people learn to trust for the wrong reason: a file
// whose line disagrees with its case, a file carrying no line at all - which is
// every golden in this tree before 2026-09-16 - and a file no case names.
func TestGoldenConfigurationComparisonCanFail(t *testing.T) {
	head := func(line string) []byte {
		return []byte("# GET /health\n" + line + "HTTP/1.1 200 OK\n\n{}")
	}
	agreeing := head("# recorded-with: start-dev --health-enabled\n")
	disagreeing := head("# recorded-with: start-dev --health-enabled --metrics-enabled\n")
	silent := head("")

	declared := map[string]Configuration{
		"a.http": StartDevHealth,
		"b.http": StartDevHealth,
		"c.http": StartDevHealth,
	}

	if got := goldenConfigurationFaults(map[string][]byte{"a.http": agreeing}, declared); len(got) != 0 {
		t.Errorf("a golden agreeing with its case was reported: %v", got)
	}
	got := goldenConfigurationFaults(map[string][]byte{"b.http": disagreeing}, declared)
	if len(got) != 1 || !strings.Contains(got[0], "--metrics-enabled") {
		t.Errorf("a golden recorded under another configuration went unreported: %v", got)
	}
	got = goldenConfigurationFaults(map[string][]byte{"c.http": silent}, declared)
	if len(got) != 1 || !strings.Contains(got[0], `says it was recorded with ""`) {
		t.Errorf("a golden carrying no configuration line went unreported: %v", got)
	}
	got = goldenConfigurationFaults(map[string][]byte{"d.http": agreeing}, declared)
	if len(got) != 1 || !strings.Contains(got[0], "no case in the catalogue") {
		t.Errorf("a golden no case names went unreported: %v", got)
	}
}

// TestEveryGoldenNamesTheConfigurationItsCaseDeclares is the sweep over the
// tree, and it is the half of this mechanism that a pull request can run.
//
// The recorder writes the line from the same value it started the container
// with, so the file and the container cannot disagree inside one run. What this
// catches is the run after: a case whose declaration moved without a re-record,
// and a re-record made with a case's declaration not yet changed. Both look
// identical in a diff - a golden whose bytes moved - and only the line says
// which.
func TestEveryGoldenNamesTheConfigurationItsCaseDeclares(t *testing.T) {
	corpus := map[string][]byte{}
	declared := map[string]Configuration{}
	for _, c := range Catalog {
		path := GoldenPath(goldenDir, c.ID)
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // a Pending case with no golden; TestConformance judges that
		}
		corpus[path] = raw
		declared[path] = ConfigurationOf(c)
	}
	if len(corpus) < 1000 {
		t.Fatalf("read %d goldens; the tree holds over a thousand, so this sweep is not "+
			"looking at the catalogue", len(corpus))
	}
	for _, fault := range goldenConfigurationFaults(corpus, declared) {
		t.Error(fault)
	}
}

// TestEveryGoldenRoundTripsThroughParseAndFormat is the format's own guard, and
// it is what makes the configuration line mandatory on a committed file without
// ParseGolden having to refuse one.
//
// Every golden in this tree was written by FormatGolden, so re-formatting what
// ParseGolden read has to give the bytes back. A file that has been hand-edited
// into a shape the recorder would not write - a missing configuration line, a
// header the parser folds differently, a status line whose reason phrase has
// drifted from http.StatusText - fails here as a difference rather than
// surviving as a silent default.
//
// It is also F246 fenced rather than fixed: the round trip is lossy on a
// non-standard reason phrase, and this test says so at the one place the loss
// would be committed. Nothing in the tree carries one today.
func TestEveryGoldenRoundTripsThroughParseAndFormat(t *testing.T) {
	read := 0
	err := filepath.WalkDir(goldenDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".http") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		read++
		g, pErr := ParseGolden(raw)
		if pErr != nil {
			t.Errorf("%s: %v", path, pErr)
			return nil
		}
		if again := FormatGolden(g); string(again) != string(raw) {
			t.Errorf("%s does not survive ParseGolden followed by FormatGolden, so it is "+
				"not what the recorder would write.\nwant: %q\ngot:  %q",
				path, firstLines(raw), firstLines(again))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", goldenDir, err)
	}
	if read < 1000 {
		t.Fatalf("read %d goldens; the tree holds over a thousand", read)
	}
}

// firstLines keeps a round-trip failure readable: the head is where every
// difference this test can find lives, and a body of several kilobytes printed
// twice buries it.
func firstLines(raw []byte) string {
	head, _, _ := strings.Cut(string(raw), "\n\n")
	return head
}
