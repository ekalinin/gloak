package conformance

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// idPattern keeps IDs safe to use as file paths: lowercase slug segments
// separated by slashes, nothing that could escape testdata/golden.
var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)*$`)

func TestCatalogIsWellFormed(t *testing.T) {
	if len(Catalog) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := make(map[string]bool, len(Catalog))
	for _, c := range Catalog {
		if !idPattern.MatchString(c.ID) {
			t.Errorf("%q: ID is not a slug path", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("%q: duplicate ID", c.ID)
		}
		seen[c.ID] = true

		if c.Doc.URL == "" || c.Doc.Section == "" || c.Doc.Retrieved == "" {
			t.Errorf("%q: Doc must carry URL, Section and Retrieved", c.ID)
		}
		if c.Request.Method == "" || c.Request.Path == "" {
			t.Errorf("%q: Request needs a method and a path", c.ID)
		}
		switch c.Status {
		case Pending:
			if c.Reason == "" {
				t.Errorf("%q: a Pending case must say why", c.ID)
			}
		case Recorded:
			// The rules unique to Recorded - a mandatory golden, and a
			// fixture, since the verifier serves it - are in
			// TestRecordedCaseRules. What it shares with Pending is having
			// to say why it is not served yet.
			if c.Reason == "" {
				t.Errorf("%q: a Recorded case must say why it is not served yet", c.ID)
			}
		case Implemented:
			if c.Fixture == "" {
				t.Errorf("%q: an Implemented case needs a fixture", c.ID)
			}
			if c.Reason != "" {
				t.Errorf("%q: Reason belongs to cases that are not served yet", c.ID)
			}
		default:
			t.Errorf("%q: unknown status %d", c.ID, c.Status)
		}
	}
}

// TestRecordedCaseRules pins the two rules that make Recorded different from
// Pending: the golden is mandatory, and the case must say why it is not
// served yet.
func TestRecordedCaseRules(t *testing.T) {
	for _, c := range Catalog {
		if c.Status != Recorded {
			continue
		}
		if c.Reason == "" {
			t.Errorf("%q: a Recorded case must say why it is not served yet", c.ID)
		}
		if c.Fixture == "" {
			t.Errorf("%q: a Recorded case is served, so it needs a fixture", c.ID)
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%q: Recorded means the golden was measured, but none exists", c.ID)
		}
	}
}

// createdKeys are the JSON keys a creation body names its object by, and the
// same keys the object comes back under when a listing enumerates it.
//
// One key per resource family a fixture creates: clients by clientId, users by
// username, realms by realm, and roles and groups both by name. Reading the
// pair rather than the bare value is what keeps "gloak-probe-group" from
// matching the "gloak-probe-group-mapped" a sibling fixture creates, and what
// keeps a name from matching inside a description.
var createdKeys = []string{"clientId", "username", "realm", "name"}

// createdObject is one object some fixture creates: the key its creation body
// named it by, its name, and the fixture that made it.
type createdObject struct {
	key     string
	name    string
	fixture string
}

// TestPristineRealmGoldensAreNotPolluted checks the result of the recorder's
// ordering rather than the ordering itself.
//
// A case marked PristineRealm enumerates the realm, so its golden must hold
// nothing another fixture created. Three clients did once - gloak-confidential
// and its two siblings, created by the OIDC fixtures that run earlier - and
// were recorded into the unfiltered client list as though Keycloak
// bootstrapped them. Checking the bytes catches that whatever the recorder's
// order happens to be.
//
// It checked clients alone until 2026-08-29, and that is how F40 got past it:
// admin/role-mapper/group-realm-available enumerates the realm's **roles**, a
// fresh whole-catalogue recording put thirteen gloak-probe-* roles in its body,
// and a guard looking for `"clientId":"..."` saw a clean golden. Fixtures
// create roles, groups, users and - since P4's first cut - realms too, so the
// blind spot was four times the size of the one thing being watched.
//
// The case's **own** fixture is exempt. Its steps run on both sides of the
// comparison - the recorder's container and the verifier's fresh handler - so
// what they create belongs in the golden. Only what some *other* fixture made
// is pollution, and only the recorder's shared container can put it there. The
// exemption is load-bearing today: admin/groups/list's golden holds the
// gloak-probe-group its own fixture creates, and without it this test would
// fail on a correct golden.
func TestPristineRealmGoldensAreNotPolluted(t *testing.T) {
	created := fixtureCreatedObjects()
	byKey := map[string]int{}
	for _, o := range created {
		byKey[o.key]++
	}
	for _, key := range createdKeys {
		if byKey[key] == 0 {
			t.Fatalf("no fixture creates an object named by %q; "+
				"this test has stopped checking that family", key)
		}
	}

	for _, c := range Catalog {
		if !c.PristineRealm {
			continue
		}
		raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
		if err != nil {
			t.Errorf("%q: %v", c.ID, err)
			continue
		}
		for _, o := range pollution(raw, created, c.Fixture) {
			t.Errorf("%q: golden holds %s %q, which fixture %q created - "+
				"this case has to be recorded against a realm no other fixture has touched",
				c.ID, o.key, o.name, o.fixture)
		}
	}
}

// pollution is every object in created that raw mentions and that some fixture
// other than own made.
//
// A name is matched against the key its creation body used, not on its own:
// "gloak-probe-group" as a bare substring also matches the
// "gloak-probe-group-mapped" a sibling fixture creates, and would report a
// group that is not there.
//
// It is a function rather than a loop inside the test so that
// TestPollutionGuardSeesEveryCreatedFamily can feed it a body known to be
// polluted. A guard nothing can make fail is the failure mode this whole file
// exists to prevent.
func pollution(raw []byte, created []createdObject, own string) []createdObject {
	mine := map[createdObject]bool{}
	for _, o := range created {
		if o.fixture == own {
			mine[createdObject{key: o.key, name: o.name}] = true
		}
	}
	var out []createdObject
	for _, o := range created {
		if mine[createdObject{key: o.key, name: o.name}] {
			continue
		}
		if bytes.Contains(raw, []byte(`"`+o.key+`":"`+o.name+`"`)) {
			out = append(out, o)
		}
	}
	return out
}

// TestPollutionGuardSeesEveryCreatedFamily proves the guard above can fail, in
// each of the four families separately.
//
// The guard watched clients alone for months and was blind to the other three
// while looking exactly as green as it does now. So each family gets a body
// that a polluted recording would produce - the object spelled the way a
// listing spells it - and the guard has to report it. A family that stops
// being watched fails here rather than going quiet.
func TestPollutionGuardSeesEveryCreatedFamily(t *testing.T) {
	created := fixtureCreatedObjects()
	for _, key := range createdKeys {
		var victim createdObject
		for _, o := range created {
			if o.key == key {
				victim = o
				break
			}
		}
		if victim.name == "" {
			t.Fatalf("no fixture creates an object named by %q", key)
		}

		polluted := []byte(`[{"id":"x","` + victim.key + `":"` + victim.name + `","enabled":true}]`)
		if got := pollution(polluted, created, ""); len(got) == 0 {
			t.Errorf("%s: a golden holding %q went unreported", key, victim.name)
		}
		// The same body is clean for the case whose own fixture made it.
		if got := pollution(polluted, created, victim.fixture); len(got) != 0 {
			t.Errorf("%s: %q is the case's own fixture's and was reported anyway: %v",
				key, victim.name, got)
		}
	}
}

// fixtureCreatedObjects is every object a fixture creates, read out of the
// creation bodies themselves so that a new fixture is covered without anyone
// remembering to list it here.
//
// A value holding "{{" is skipped: it is a reference to something a step
// captured, so no golden can hold it literally.
//
// Only a POST whose body is a JSON **object** counts. The role-mapping and
// composite writes are POSTs too, and their bodies are arrays naming roles
// that already exist - `[{"id":"...","name":"manage-users"}]`. Reading those as
// creations would put six bootstrapped admin role names into the set and make
// this test fail on any golden that legitimately lists one.
func fixtureCreatedObjects() []createdObject {
	pattern := regexp.MustCompile(`"(` + strings.Join(createdKeys, "|") + `)":"([^"]+)"`)
	seen := map[createdObject]bool{}
	var out []createdObject
	for name, f := range Fixtures {
		for _, s := range f.Steps {
			body := bytes.TrimSpace(s.Request.Body)
			if s.Request.Method != http.MethodPost || len(body) == 0 || body[0] != '{' {
				continue
			}
			for _, m := range pattern.FindAllSubmatch(body, -1) {
				o := createdObject{key: string(m[1]), name: string(m[2]), fixture: name}
				if strings.Contains(o.name, "{{") || seen[o] {
					continue
				}
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	// Fixtures is a map, so the order it ranges in is not stable and neither
	// is which fixture a shared name is attributed to. Sorting makes the
	// failure message the same on every run.
	sort.Slice(out, func(i, j int) bool {
		if out[i].key != out[j].key {
			return out[i].key < out[j].key
		}
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].fixture < out[j].fixture
	})
	return out
}
