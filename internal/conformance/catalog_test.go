package conformance

import (
	"bytes"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"slices"
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

// createdObject is one object the recording creates: the key its creation body
// named it by, its name, and what made it - a fixture, or the case whose own
// request is the create.
type createdObject struct {
	key     string
	name    string
	creator string
}

// TestPristineRealmGoldensAreNotPolluted checks the result of the recorder's
// ordering rather than the ordering itself.
//
// A case marked PristineRealm enumerates the realm, so its golden must hold
// nothing another case or fixture created. Three clients did once - gloak-confidential
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
// The case's **own** fixture is exempt, and so is the case itself. Both run on
// both sides of the comparison - the recorder's container and the verifier's
// fresh handler - so what they create belongs in the golden. Only what
// something else made is pollution, and only the recorder's shared container
// can put it there. The exemption is load-bearing today: admin/groups/list's
// golden holds the gloak-probe-group its own fixture creates, and without it
// this test would fail on a correct golden.
func TestPristineRealmGoldensAreNotPolluted(t *testing.T) {
	created := createdObjects()
	byKey := map[string]int{}
	for _, o := range created {
		byKey[o.key]++
	}
	for _, key := range createdKeys {
		if byKey[key] == 0 {
			t.Fatalf("nothing in the recording creates an object named by %q; "+
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
		for _, o := range pollution(raw, created, c.Fixture, c.ID) {
			t.Errorf("%q: golden holds %s %q, which %q created - "+
				"this case has to be recorded against a realm nothing else has touched",
				c.ID, o.key, o.name, o.creator)
		}
	}
}

// pollution is every object in created that raw mentions and that something
// other than the named owners made. The owners are a case's own fixture and the
// case itself, which are the two things whose creates the verifier repeats.
//
// A name is matched against the key its creation body used, not on its own:
// "gloak-probe-group" as a bare substring also matches the
// "gloak-probe-group-mapped" a sibling fixture creates, and would report a
// group that is not there.
//
// One entry per creator, so a name two of them create is reported twice -
// gloak-probe-role is made by a fixture and again by admin/roles/create-duplicate,
// and both are places to look.
//
// It is a function rather than a loop inside the test so that
// TestPollutionGuardSeesEveryCreatedFamily can feed it a body known to be
// polluted. A guard nothing can make fail is the failure mode this whole file
// exists to prevent.
func pollution(raw []byte, created []createdObject, owners ...string) []createdObject {
	mine := map[createdObject]bool{}
	for _, o := range created {
		if slices.Contains(owners, o.creator) {
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
	created := createdObjects()
	for _, key := range createdKeys {
		var victim createdObject
		for _, o := range created {
			if o.key == key {
				victim = o
				break
			}
		}
		if victim.name == "" {
			t.Fatalf("nothing in the recording creates an object named by %q", key)
		}

		polluted := []byte(`[{"id":"x","` + victim.key + `":"` + victim.name + `","enabled":true}]`)
		if got := pollution(polluted, created); len(got) == 0 {
			t.Errorf("%s: a golden holding %q went unreported", key, victim.name)
		}
		// The same body is clean for the case that owns the creator.
		if got := pollution(polluted, created, victim.creator); len(got) != 0 {
			t.Errorf("%s: %q is the case's own and was reported anyway: %v",
				key, victim.name, got)
		}
	}
}

// TestPollutionGuardReadsTheCataloguesOwnCreates proves the second of
// createdObjects' two sources is wired.
//
// Deleting the loop over Catalog leaves every test above green, because each
// of the four families is also created by some fixture and the tests only ask
// for one victim per family. The source that was missing when F40 slipped
// through is the case's own request - gloak-probe-role-create is POSTed by
// admin/roles/create-realm and by nothing else - so it is asserted on its own
// rather than left to be implied.
func TestPollutionGuardReadsTheCataloguesOwnCreates(t *testing.T) {
	byID := map[string]bool{}
	for _, c := range Catalog {
		byID[c.ID] = true
	}
	for _, o := range createdObjects() {
		if byID[o.creator] {
			return
		}
	}
	t.Error("no created object is attributed to a case's own request; " +
		"createdObjects has stopped reading the catalogue and only fixtures are watched")
}

// createdObjects is every object a recording creates, read out of the creation
// bodies themselves so that a new fixture is covered without anyone
// remembering to list it here.
//
// Two sources, because the shared container cannot tell them apart. A fixture's
// steps are one. The other is a **case's own request**: admin/roles/create-realm
// POSTs `{"name":"gloak-probe-role-create"}` and that role outlives the case
// exactly as a fixture's does. It was the thirteenth role in the recording that
// produced F40, and reading fixtures alone was the reason the guard named
// twelve of the thirteen.
//
// A value holding "{{" is skipped: it is a reference to something a step
// captured, so no golden can hold it literally.
//
// Only a POST whose body is a JSON **object** counts. The role-mapping and
// composite writes are POSTs too, and their bodies are arrays naming roles
// that already exist - `[{"id":"...","name":"manage-users"}]`. Reading those as
// creations would put six bootstrapped admin role names into the set and make
// this test fail on any golden that legitimately lists one.
func createdObjects() []createdObject {
	pattern := regexp.MustCompile(`"(` + strings.Join(createdKeys, "|") + `)":"([^"]+)"`)
	seen := map[createdObject]bool{}
	var out []createdObject
	collect := func(r Request, creator string) {
		body := bytes.TrimSpace(r.Body)
		if r.Method != http.MethodPost || len(body) == 0 || body[0] != '{' {
			return
		}
		for _, m := range pattern.FindAllSubmatch(body, -1) {
			o := createdObject{key: string(m[1]), name: string(m[2]), creator: creator}
			if strings.Contains(o.name, "{{") || seen[o] {
				continue
			}
			seen[o] = true
			out = append(out, o)
		}
	}
	for name, f := range Fixtures {
		for _, s := range f.Steps {
			collect(s.Request, name)
		}
	}
	for _, c := range Catalog {
		collect(c.Request, c.ID)
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
		return out[i].creator < out[j].creator
	})
	return out
}
