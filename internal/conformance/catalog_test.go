package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
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
		// Expand does not reach RawQuery - it lives in fixture.go and rewrites
		// Path, Query, Headers, Form and Body. A {{name}} left in here would be
		// sent to the server with its braces on, and the case would measure a
		// request nobody meant to make.
		if strings.Contains(c.Request.RawQuery, "{{") {
			t.Errorf("%q: RawQuery is not expanded, so it cannot refer to %q",
				c.ID, c.Request.RawQuery)
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

		// A volatile tail is only a mask; diff compares nothing a case does not
		// assert, so declaring one without asserting the header masks a value
		// nobody looks at. That is the shape of hole F46 is about, one level up.
		asserted := map[string]bool{}
		for _, name := range c.AssertHeaders {
			asserted[http.CanonicalHeaderKey(name)] = true
		}
		blanked := map[string]bool{}
		for _, name := range c.VolatileHeaders {
			blanked[http.CanonicalHeaderKey(name)] = true
		}
		for _, name := range c.VolatileTailHeaders {
			canonical := http.CanonicalHeaderKey(name)
			if !asserted[canonical] {
				t.Errorf("%q: %s is a volatile tail and is not asserted, so nothing compares it",
					c.ID, name)
			}
			// Both masks on one header would be decided by whichever branch
			// recordedHeaders and diff happen to test first, in two files.
			if blanked[canonical] {
				t.Errorf("%q: %s is masked whole and by its tail; the two disagree about what is compared",
					c.ID, name)
			}
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

// unservedEndpointPhrases maps a phrase a Reason uses to claim an endpoint has
// not been built to the path that claim is about.
//
// **It is a table of literal phrases on purpose.** The obvious guard here is a
// heuristic - a Reason mentioning an endpoint the router serves is suspicious -
// and it cries wolf on the first case it meets: five device-grant cases POST to
// the token endpoint and say "the device authorization endpoint is not
// implemented", which is a true sentence about an endpoint that is not the one
// the case requests. Reading the subject out of English is what that guard
// would have to do, and it would be wrong on seven of the thirty-one Reasons in
// the catalogue today. Matching a written-down phrase is wrong on none of them.
//
// The cost is that it is a ratchet: a Reason phrased some other way is
// unchecked until somebody adds the phrasing. That is the same bargain
// namedOutsideTheConvention and parkedGoldens take, and it buys the same thing -
// every line here was checked once, by a person, against the router.
//
// The path is spelled for the master realm because that is what every case in
// the catalogue addresses, and because the probe needs a literal path rather
// than a pattern.
var unservedEndpointPhrases = map[string]string{
	"the token endpoint is not implemented":                      "/realms/master/protocol/openid-connect/token",
	"the authorization endpoint is not implemented":              "/realms/master/protocol/openid-connect/auth",
	"the device authorization endpoint is not implemented":       "/realms/master/protocol/openid-connect/auth/device",
	"the backchannel authentication endpoint is not implemented": "/realms/master/protocol/openid-connect/ext/ciba/auth",
	"dynamic client registration is not implemented":             "/realms/master/clients-registrations/openid-connect",
	"the userinfo endpoint is not implemented":                   "/realms/master/protocol/openid-connect/userinfo",
	"the introspection endpoint is not implemented":              "/realms/master/protocol/openid-connect/token/introspect",
	"the revocation endpoint is not implemented":                 "/realms/master/protocol/openid-connect/revoke",
	"the logout endpoint is not implemented":                     "/realms/master/protocol/openid-connect/logout",
}

// staleReasonsOwnedElsewhere are the cases whose Reason this guard finds false
// and whose file this cut does not own.
//
// catalog_oidc_pending.go is the device-grant stream's while that work is in
// flight, so the five entries below are reported rather than edited. Each value
// is what the Reason should say instead, so correcting it is a copy.
//
// It is not an amnesty. An entry whose Reason has stopped being stale fails
// here, which is what makes the list shrink to nothing rather than becoming
// somewhere findings go to be forgotten.
//
// **It shrank to nothing on 2026-08-30**, the day it was written, when the
// device-grant stream merged this guard and corrected all five Reasons. Three
// took the text suggested here verbatim. Two did not, and the reason is worth
// keeping: the suggestions for `oidc/token/device-code-grant` and
// `oidc/token/ciba-grant` - "the device_code grant is not implemented" and "the
// CIBA grant is not implemented" - were already stale when they were written,
// because both grants landed the same day. What is actually missing for one is
// the device verification and consent pages, and for the other an
// authentication channel a default 26.7.1 does not configure. A hand-off's
// suggested text is a hand-off, not a measurement.
//
// The map is deliberately left rather than deleted: it is what a future cut
// finding a stale Reason in somebody else's file writes into.
var staleReasonsOwnedElsewhere = map[string]string{}

// TestNoReasonClaimsAServedEndpointIsUnserved is the sweep this file could not
// do by reading.
//
// A Reason is not a comment. It is what the next person reads when deciding
// what to work on, and a stale one sends them past work that is already
// possible or towards work that is already done. Two families were found stale
// this week and both by accident: four authorization cases said "the
// authorization endpoint is not implemented" the day after it was implemented,
// and five token cases still say "the token endpoint is not implemented" while
// it serves four grants.
//
// Both are the same claim - a named endpoint is not built - and both are
// falsifiable against the router without serving the case, which matters
// because 21 of the 28 Pending cases carry no fixture and cannot be served at
// all. The probe is a method no route registers: Gloak answers a **known** path
// with the wrong method 404 `{"error":"HTTP 404 Not Found"}` and an unrouted
// path with 404 `{"error":"Unable to find matching target resource method"}`,
// which is Keycloak's measured pair and the thing withKeycloakFallbacks exists
// to tell apart. So a routed path is visible without authenticating, without a
// fixture, and without running a handler that could change anything.
func TestNoReasonClaimsAServedEndpointIsUnserved(t *testing.T) {
	h := newFixture(t, "bootstrap")
	routed := func(path string) bool {
		// TRACE is registered by nothing, so this reaches the fallback either
		// way and never runs a handler.
		req := httptest.NewRequest(http.MethodTrace, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return !bytes.Contains(w.Body.Bytes(), []byte("Unable to find matching target resource method"))
	}

	// A guard whose probe cannot tell the two apart passes everything. Both
	// directions are asserted against a path that is certainly routed and one
	// that certainly is not, so a fallback that stopped distinguishing them
	// fails here rather than making every case below vacuous.
	if !routed("/realms/master/protocol/openid-connect/token") {
		t.Fatal("the token endpoint reads as unrouted, so this test cannot see a served endpoint")
	}
	if routed("/realms/master/no/such/path") {
		t.Fatal("an invented path reads as routed, so this test would report every case")
	}

	flagged := map[string]bool{}
	for _, c := range Catalog {
		if c.Status == Implemented {
			continue
		}
		for phrase, path := range unservedEndpointPhrases {
			if !strings.Contains(c.Reason, phrase) || !routed(path) {
				continue
			}
			flagged[c.ID] = true
			if want, listed := staleReasonsOwnedElsewhere[c.ID]; listed {
				t.Logf("%q: known stale, owned elsewhere; the Reason should say %q", c.ID, want)
				continue
			}
			t.Errorf("%q says %q and %s is served - a Reason that names built work "+
				"sends the next reader past it. Say what is actually missing.",
				c.ID, phrase, path)
		}
	}

	for id, want := range staleReasonsOwnedElsewhere {
		if !flagged[id] {
			t.Errorf("%q is declared stale here and its Reason no longer is - "+
				"drop the entry rather than leaving a hand-off nobody has re-read "+
				"(it was to become %q)", id, want)
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
//
// **The order is the precedence, not decoration.** A creation body names its
// object once, and `name` is last because it is the fallback for the three
// families that have no key of their own - roles, groups and client scopes.
// A body carrying one of the first three carries `name` in some other sense:
// `{"clientId":"gloak-probe-described","name":"A name",...}` creates a client
// whose display name is "A name", and reading that as a role called "A name"
// is a phantom object in a guard that exists to name real ones. See
// createdObjects.
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

// TestNoGoldenHoldsAnObjectItDidNotCreate is the test above, applied to the
// 260-odd cases that are not PristineRealm.
//
// The invariant is the whole harness's, not the pristine group's: a golden may
// hold only what bootstrap, the case's own fixture and the case's own request
// produced, because those three are exactly what the verifier reproduces. A
// non-pristine golden holding a sibling fixture's object is order-dependent
// whether or not it enumerates anything, and it says so in bytes a reviewer can
// read.
//
// It is separate from the pristine test rather than a widening of it because
// the two say different things when they fail. The pristine one names its
// remedy - record against a realm nothing else has touched - and this one has
// no single remedy: the case may need the flag, or a narrower fixture, or it
// may be reading state it never meant to.
//
// **It is a ratchet, not a finder.** Every golden in the repository passes it
// today, which is the point: F53's set is the cases that are order-dependent
// and *currently clean*, and no test that reads committed bytes can see those.
// This one fires the moment a re-record puts a new fixture's object in a
// golden, which is one step earlier than TestConformance noticing that the
// verifier cannot reproduce it.
func TestNoGoldenHoldsAnObjectItDidNotCreate(t *testing.T) {
	created := createdObjects()
	for _, c := range Catalog {
		if c.PristineRealm {
			continue // covered above, with a sharper message
		}
		raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
		if err != nil {
			continue // Pending cases have no golden, and that is not a failure here
		}
		for _, o := range pollution(raw, created, c.Fixture, c.ID) {
			t.Errorf("%q: golden holds %s %q, which %q created - "+
				"neither this case's fixture nor its own request makes it, so the "+
				"verifier cannot reproduce this body",
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

// probePrefix is what every object a fixture or a case creates is supposed to
// be called, and what six goldens' windows rest on without anything having
// checked it until now.
const probePrefix = "gloak-probe-"

// namedOutsideTheConvention is every created object that does not carry
// probePrefix, keyed "<key> <name>", with the reason it does not.
//
// It is a ratchet and not an amnesty. Each entry was read off the fixture that
// makes it, and two of the three groups are the kind of name F58 warns about -
// `aa-gloak-srch-kid` sorts before every bootstrapped name in the realm - so
// the list is also the answer to "which of these could take a golden's window",
// which is a question a reviewer can now ask of seven lines rather than of
// fixture.go.
//
// Nothing here was renamed. Every one of them is load-bearing where it stands,
// and renaming an object a golden was recorded against means re-recording the
// golden; the entries say which.
var namedOutsideTheConvention = map[string]string{
	// P1's confidential-client fixtures, which predate the convention. Safe
	// where they are: no golden pages or filters a client listing, and
	// admin/clients/list is PristineRealm, so it is recorded against a realm
	// these never reach.
	"clientId gloak-confidential":          "confidential-user-token, named before the convention existed",
	"clientId gloak-confidential-expiring": "confidential-expired-token, named before the convention existed",
	"clientId gloak-confidential-sa":       "confidential-service-account, named before the convention existed",

	// The group-search fixture's three names *are* its measurement.
	// admin/groups/search-pages-the-matches sends search=gloak-srch&max=1 and
	// the answer turns on aa-gloak-srch-kid sorting first of the three; a
	// shared gloak-probe- prefix would sort them together and change which
	// group the page returns. They are groups, and no golden pages a group
	// listing by first/max without a search, so they cannot reach the windows
	// F58 is about - but aa- sorting before everything is exactly the shape
	// that would, one resource family over.
	"name aa-gloak-srch-kid": "admin-token-group-search: sorts first on purpose, which is what max=1 measures",
	"name gloak-srch-one":    "admin-token-group-search: matched by search=gloak-srch, which a probe prefix would not be",
	"name zz-gloak-srch":     "admin-token-group-search: sorts last on purpose, for the same measurement",

	// The impostor's whole point is a role on a client of its own carrying a
	// real admin role's name, so that the caller holding it is refused. Renaming
	// it to gloak-probe-manage-realm builds a different fixture. See
	// callerFixture: "the roles come from master-realm by container, not by
	// name".
	"name manage-realm": "narrow-caller-impostor: a client role deliberately named after an admin role",
}

// TestEveryCreatedObjectCarriesTheProbePrefix turns six written arguments into
// one checked one. F58.
//
// admin/roles/list-realm-page-no-search sends first=1&max=2 with no search and
// its golden holds create-realm and default-roles-master. The case's comment
// argues, correctly, that every realm role a fixture creates is named
// gloak-probe-..., sorts after default-roles-master and cannot enter the window.
// Six user listings rest on the same kind of argument: ?username=admin is a
// substring filter no gloak-probe-* username matches.
//
// Every one of those arguments is about names, and nothing enforced the
// convention they rest on. A fixture creating a realm role called a-probe-role,
// or a user called admin-probe, breaks several goldens at once - loudly, which
// is the good case, but in cases whose comments then read as though they had
// been checked.
//
// The exceptions are declared rather than tolerated, and a stale one fails:
// an entry naming an object nothing creates any more is a reason nobody has
// re-read, and the whole value of the list is that each line was checked once.
func TestEveryCreatedObjectCarriesTheProbePrefix(t *testing.T) {
	created := createdObjects()
	// A convention asserted over an empty set asserts nothing, the way the
	// pollution guard fails when a family stops being created at all.
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

	matched := map[string]bool{}
	for _, o := range created {
		entry := o.key + " " + o.name
		if _, listed := namedOutsideTheConvention[entry]; listed {
			matched[entry] = true
			continue
		}
		if !strings.HasPrefix(o.name, probePrefix) {
			t.Errorf("%q creates %s %q, which does not start with %q - "+
				"six goldens hold a page or a filtered listing that only excludes "+
				"what a fixture makes because of that prefix, so either rename it or "+
				"add it to namedOutsideTheConvention with the reason",
				o.creator, o.key, o.name, probePrefix)
		}
	}

	stale := make([]string, 0, len(namedOutsideTheConvention))
	for entry := range namedOutsideTheConvention {
		if !matched[entry] {
			stale = append(stale, entry)
		}
	}
	sort.Strings(stale)
	for _, entry := range stale {
		t.Errorf("namedOutsideTheConvention excuses %q and nothing creates it any more; "+
			"drop the entry rather than leaving a reason nobody has re-read", entry)
	}
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
//
// **One JSON object names one object**, so the most specific key in createdKeys
// that an object carries is the one read, and the rest of that object's keys are
// its properties. Reading all four keys of a body invented an object: the client
// created with `{"clientId":"gloak-probe-described","name":"A name",...}` was
// reported as a role called "A name", which is `ClientRepresentation.name` - a
// display name, not the key anything is addressed by.
//
// The rule is per object rather than per **body**, and the difference is not
// pedantic. A create can carry objects nested inside it:
// `POST /clients` with `{"clientId":"...","protocolMappers":[{"name":"..."}]}`
// creates a client *and* two protocol mappers, and they outlive the request the
// same way. Applied per body, the client's `clientId` won and the nested mappers
// were never recorded - which both lost them from the guard and made the guard
// report a false positive on the case whose own fixture had created them,
// because the exemption reads this same set. Two cuts landed green on their own
// and failed together on exactly that.
func createdObjects() []createdObject {
	seen := map[createdObject]bool{}
	var out []createdObject
	// walk records every JSON object in v, most-specific-key-first, and
	// recurses into nested objects and arrays.
	var walk func(v any, creator string)
	walk = func(v any, creator string) {
		switch t := v.(type) {
		case map[string]any:
			for _, key := range createdKeys {
				name, ok := t[key].(string)
				if !ok {
					continue
				}
				// An empty name creates nothing - admin/client-scopes/create-empty-name
				// sends one on purpose and is measured answering 400 - and a
				// {{name}} is a reference a step captures, so no golden holds it
				// literally. Neither is an object anything could later find.
				o := createdObject{key: key, name: name, creator: creator}
				if name != "" && !strings.Contains(name, "{{") && !seen[o] {
					seen[o] = true
					out = append(out, o)
				}
				break
			}
			for _, nested := range t {
				walk(nested, creator)
			}
		case []any:
			for _, nested := range t {
				walk(nested, creator)
			}
		}
	}
	collect := func(r Request, creator string) {
		body := bytes.TrimSpace(r.Body)
		if r.Method != http.MethodPost || len(body) == 0 || body[0] != '{' {
			return
		}
		var doc any
		if err := json.Unmarshal(body, &doc); err != nil {
			// A body that does not parse creates nothing, and that is a
			// measurement rather than a gap: admin/users/create-malformed sends
			// one on purpose and Keycloak answers 400. Skipping it is the true
			// answer, not a guard quietly looking away.
			return
		}
		walk(doc, creator)
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

// bodyMask is one of the four masks a Case declares over its body, paired with
// the question "does this change the value it covers?".
//
// Three of the four can answer it from the recorded bytes, because what they
// give up is an *order* and an order needs two of something: sorting an array
// of one, an object of one key or a string of one word is the identity, and the
// golden holds the array, the object and the string. Volatile cannot, and the
// reason is structural rather than an omission - see inertMasks.
type bodyMask struct {
	name  string
	paths func(Case) []string
	// changes reports whether sorting this one value can produce different
	// bytes. It is nil for the mask that cannot be asked.
	changes func(raw []byte) (bool, error)
}

var bodyMasks = []bodyMask{
	{
		name:    "Volatile",
		paths:   func(c Case) []string { return c.Volatile },
		changes: nil,
	},
	{
		name:  "Unordered",
		paths: func(c Case) []string { return c.Unordered },
		changes: func(raw []byte) (bool, error) {
			var elems []json.RawMessage
			if err := json.Unmarshal(raw, &elems); err != nil {
				return false, fmt.Errorf("not an array: %s", raw)
			}
			return len(elems) > 1, nil
		},
	},
	{
		name:  "UnorderedKeys",
		paths: func(c Case) []string { return c.UnorderedKeys },
		changes: func(raw []byte) (bool, error) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return false, fmt.Errorf("not an object: %s", raw)
			}
			return len(fields) > 1, nil
		},
	},
	{
		name:  "UnorderedWords",
		paths: func(c Case) []string { return c.UnorderedWords },
		changes: func(raw []byte) (bool, error) {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return false, fmt.Errorf("not a string: %s", raw)
			}
			return len(strings.Fields(s)) > 1, nil
		},
	},
}

// inertMasks is every mask on c that the recorded body proves does nothing, one
// message per declared path.
//
// Two shapes of inert, and the first applies to all four masks. A path that
// addresses **no value at all** is silently a no-op: Normalize and SortUnordered
// walk the body looking for it, find nothing and edit nothing, with no error.
// Five admin cases whose listing is `[]` declared `*/id` and `*/containerId`
// over rows that are not there.
//
// The second is order given up where there is no order: an array of one element,
// an object of one key, a string of one word. AGENTS.md already records one of
// these - `admin/roles/list-realm-full` masked a one-key `attributes` - and it
// was found by somebody reading a golden while answering a different question.
//
// **Volatile gets the first check and cannot get the second**, and that is a
// property of the golden rather than a gap here. Normalize has already replaced
// the value with `"{{string}}"` by the time the file is written, so the golden
// physically cannot say whether what was there varied. What can answer that is
// TestNoVolatileMaskCoversACapturedValue, which asks the served body instead,
// before the mask runs.
//
// It is a function taking a body rather than a loop inside the test so that
// TestInertMaskGuardSeesEveryKind can hand it bodies known to be inert. A guard
// nothing can make fail is the failure mode this file exists to prevent.
func inertMasks(c Case, body []byte) ([]maskFinding, error) {
	var out []maskFinding
	for _, m := range bodyMasks {
		for _, p := range m.paths(c) {
			values, err := MaskedValues(body, []string{p})
			if err != nil {
				return nil, fmt.Errorf("%s %q: %w", m.name, p, err)
			}
			if len(values) == 0 {
				out = append(out, maskFinding{m.name, p, "addresses nothing in the recorded body"})
				continue
			}
			if m.changes == nil {
				continue
			}
			// One value the mask can change is enough to earn it. A wildcard
			// over fifteen client scopes is doing its job when one of them has
			// two protocol mappers, whatever the other fourteen hold.
			live := false
			for _, v := range values {
				ok, err := m.changes(v)
				if err != nil {
					return nil, fmt.Errorf("%s %q: %w", m.name, p, err)
				}
				if ok {
					live = true
					break
				}
			}
			if !live {
				out = append(out, maskFinding{m.name, p, fmt.Sprintf(
					"covers %d value(s) and sorting every one of them is the identity", len(values))})
			}
		}
	}
	return out, nil
}

// maskFinding is one mask a body proves is doing less than it claims. It is a
// struct rather than a message so that the declared-exception lists can be keyed
// on the mask being named rather than on the wording that describes it.
type maskFinding struct {
	mask string
	path string
	why  string
}

func (m maskFinding) String() string { return fmt.Sprintf("%s %q %s", m.mask, m.path, m.why) }

// key spells an entry of inertMasksLeftInPlace or capturedMasksLeftInPlace.
func (m maskFinding) key(id string) string { return fmt.Sprintf("%s %s %q", id, m.mask, m.path) }

// inertMasksLeftInPlace is every mask the guard below reports that is still in
// the catalogue, keyed "<case ID> <mask> <path>", with the reason it is still
// there.
//
// It is a ratchet and not an amnesty, and it is deliberately not a way to
// silence the guard: both entries are inert, both were measured so, and both
// live in catalog_oidc_pending.go, which belonged to another stream the week
// this sweep ran. A stale entry fails, so the day that stream drops the mask
// this list says so rather than quietly keeping a reason nobody re-read.
var inertMasksLeftInPlace = map[string]string{
	`oidc/token/password-grant-admin-cli Volatile "id_token"`: "no id_token in the body: the golden's scope is " +
		"`email profile`, with no openid, so the grant returns none. catalog_oidc_pending.go is another stream's.",
	`oidc/token/refresh-token-grant Volatile "id_token"`: "the same absence, for the same reason, on the refresh " +
		"of the same session. catalog_oidc_pending.go is another stream's.",
}

// TestNoMaskIsInertOnItsGolden is the answer to "what stops the next inert mask
// arriving?", for the three masks a committed golden can be asked about.
//
// A mask that changes nothing is worse than no mask. It reads as "this varies",
// which is a claim about Keycloak, and the next person to touch the case
// believes it: they will not assert an order the suite appears to have measured
// as unstable. Forty of them said that about arrays of one element, and one -
// found by accident, not by anything here - said it about a one-key object.
//
// This fires on the catalogue as it stands rather than only on what changes,
// so a case copied from a neighbour with the neighbour's masks attached is
// caught on the first run rather than at the next sweep. That is the lesson of
// F53, which was swept clean and grew a new instance three commits later.
func TestNoMaskIsInertOnItsGolden(t *testing.T) {
	matched := map[string]bool{}
	for _, c := range Catalog {
		raw, err := os.ReadFile(GoldenPath(goldenDir, c.ID))
		if err != nil {
			// A case with no golden has no bytes to be judged against. That it
			// may have one is TestConformance's business, not this test's.
			continue
		}
		g, err := ParseGolden(raw)
		if err != nil {
			t.Errorf("%q: parse golden: %v", c.ID, err)
			continue
		}
		found, err := inertMasks(c, g.Body)
		if err != nil {
			t.Errorf("%q: %v", c.ID, err)
			continue
		}
		for _, m := range found {
			if _, listed := inertMasksLeftInPlace[m.key(c.ID)]; listed {
				matched[m.key(c.ID)] = true
				continue
			}
			t.Errorf("%q: %s - drop the mask, or say in the case why it is declared "+
				"over a value it cannot affect", c.ID, m)
		}
	}

	stale := make([]string, 0, len(inertMasksLeftInPlace))
	for entry := range inertMasksLeftInPlace {
		if !matched[entry] {
			stale = append(stale, entry)
		}
	}
	sort.Strings(stale)
	for _, entry := range stale {
		t.Errorf("inertMasksLeftInPlace excuses %q and it is not inert any more; "+
			"drop the entry rather than leaving a reason nobody has re-read", entry)
	}
}

// capturedValue matches a value ReplaceCaptured has already rewritten: the
// whole string, and nothing but the placeholder.
var capturedValue = regexp.MustCompile(`^"\{\{([a-z_0-9]+)\}\}"$`)

// volatileMasksOverCaptures is every Volatile path whose values are, by the
// time Normalize runs, already the placeholder a fixture capture put there.
//
// This is F46 one level down, in the body instead of the header. A mask over a
// whole value asserts nothing about it, and here there was something to assert:
// ReplaceCaptured has already turned the server-minted id into `{{group_id}}`,
// which is stable, identical on both sides, and says *which object this is*.
// Normalize then replaces it with `"{{string}}"` and that sentence is gone.
//
// The assertion lost is not decoration. admin/groups/children-list masked both
// `*/id` and `*/parentId`; a handler answering with the child's own id in
// `parentId` compared equal to one answering with the parent's, because both
// sides read `"{{string}}"`. The same shape covers eleven `containerId`s, every
// role-mapping listing and every group read.
//
// A path whose values are only *partly* captured is left alone and must be: the
// realm's own id is in a `containerId` beside a client's and nothing captures
// it, so the mask is still earning its place on the other element.
func volatileMasksOverCaptures(paths []string, body []byte, vars map[string]string) ([]maskFinding, error) {
	var out []maskFinding
	for _, p := range paths {
		values, err := MaskedValues(body, []string{p})
		if err != nil {
			return nil, fmt.Errorf("Volatile %q: %w", p, err)
		}
		if len(values) == 0 {
			continue // addressing nothing is TestNoMaskIsInertOnItsGolden's finding
		}
		captured := true
		for _, v := range values {
			m := capturedValue.FindSubmatch(bytes.TrimSpace(v))
			if m == nil {
				captured = false
				break
			}
			if _, ok := vars[string(m[1])]; !ok {
				captured = false
				break
			}
		}
		if captured {
			out = append(out, maskFinding{"Volatile", p, fmt.Sprintf(
				"covers %d value(s), every one of them already {{captured}} by the fixture", len(values))})
		}
	}
	return out, nil
}

// TestNoVolatileMaskCoversACapturedValue is the half of the sweep a committed
// golden cannot answer, asked of the served body instead.
//
// By the time a golden is written the value is `"{{string}}"`, so the file
// cannot say what was masked. One question can still be asked, and it is the
// one that matters: was the value *already* deterministic when Normalize
// reached it? ReplaceCaptured runs first and rewrites every id a fixture step
// captured, so a `Volatile` sitting on one of those is masking a value that was
// stable, comparable and identical on both sides - the widest possible mask
// over the narrowest possible thing.
//
// It runs against Gloak rather than against Keycloak, which is the right oracle
// for this question and not a compromise: what it inspects is the harness's own
// ReplaceCaptured pass, which both sides run, on a body whose shape TestConformance
// has already proved matches the reference byte for byte.
//
// If a case ever legitimately needs a mask this reports - a value Gloak pins and
// Keycloak does not - the way to say so is a comment in the case and an entry in
// capturedMasksLeftInPlace, the way inertMasksLeftInPlace does it.
func TestNoVolatileMaskCoversACapturedValue(t *testing.T) {
	matched := map[string]bool{}
	visited := map[string]bool{}
	for _, c := range Catalog {
		if c.Status != Implemented || len(c.Volatile) == 0 {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			// go test -run selects subtests, so a run narrowed to one case
			// visits one case. The stale check below can only speak for the
			// cases that actually ran; without this it reports every other
			// entry as stale, which is a guard crying wolf at whoever is
			// debugging a single case.
			visited[c.ID] = true
			got, vars, err := serve(t, c)
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
			// The two passes that run before Normalize, in passes.go's order.
			// Anything after Normalize would be looking at the mask's own output.
			body := ReplaceIssuer(ReplaceCaptured(got.Body.Bytes(), vars), testIssuer)
			if len(bytes.TrimSpace(body)) == 0 || !json.Valid(body) {
				return
			}
			found, err := volatileMasksOverCaptures(c.Volatile, body, vars)
			if err != nil {
				t.Fatalf("%v", err)
			}
			for _, m := range found {
				if _, listed := capturedMasksLeftInPlace[m.key(c.ID)]; listed {
					matched[m.key(c.ID)] = true
					continue
				}
				t.Errorf("%s - drop the mask and let the golden assert which object this is", m)
			}
		})
	}

	stale := make([]string, 0, len(capturedMasksLeftInPlace))
	for entry := range capturedMasksLeftInPlace {
		id, _, _ := strings.Cut(entry, " ")
		if visited[id] && !matched[entry] {
			stale = append(stale, entry)
		}
	}
	sort.Strings(stale)
	for _, entry := range stale {
		t.Errorf("capturedMasksLeftInPlace excuses %q and it no longer covers a capture; "+
			"drop the entry rather than leaving a reason nobody has re-read", entry)
	}
}

// capturedMasksLeftInPlace is every mask the guard above reports that is still
// in the catalogue, keyed the way inertMasksLeftInPlace is, with the reason.
//
// One entry, and it is a finding rather than an exemption: the mask is too wide
// and the file it lives in belonged to another stream the week this sweep ran.
// A stale entry fails, so the day that stream narrows it this list says so.
var capturedMasksLeftInPlace = map[string]string{
	`oidc/token/authorization-code-grant Volatile "session_state"`: "the token response's session_state is the " +
		"one the authorization redirect handed back, captured as {{session_state}} - so masking it drops the " +
		"assertion that the token belongs to the browser session that authorised it. " +
		"catalog_oidc_pending.go is another stream's.",
}

// TestVolatileCaptureGuardCanFail proves the guard above can fail, and that it
// leaves the two shapes of mask that are earning their place alone.
func TestVolatileCaptureGuardCanFail(t *testing.T) {
	vars := map[string]string{"group_id": "0f8f1f52-0000-0000-0000-000000000001"}
	body := []byte(`{"id":"{{group_id}}","mixed":[{"c":"{{group_id}}"},{"c":"7b712638"}],` +
		`"minted":"7b712638","absent":null}`)

	for _, tc := range []struct {
		name   string
		paths  []string
		report bool
	}{
		{"a captured value", []string{"id"}, true},
		{"a minted value", []string{"minted"}, false},
		// The realm's own id beside a captured client's: the mask is still
		// earning its place on the element nothing captured.
		{"one captured element of two", []string{"mixed/*/c"}, false},
		// A placeholder no fixture captured is not a capture. Nothing writes one
		// today, and a guard that reads any {{...}} as one would be trusting the
		// spelling rather than the session.
		{"an uncaptured placeholder", []string{"id"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := vars
			if tc.name == "an uncaptured placeholder" {
				v = map[string]string{}
			}
			got, err := volatileMasksOverCaptures(tc.paths, body, v)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if tc.report && len(got) == 0 {
				t.Errorf("%v went unreported", tc.paths)
			}
			if !tc.report && len(got) != 0 {
				t.Errorf("%v was reported anyway: %v", tc.paths, got)
			}
		})
	}
}

// TestInertMaskGuardSeesEveryKind proves the guard above can fail, in each of
// the four masks separately and in both shapes of inert.
//
// The guard is green on the whole catalogue, which is exactly the state a guard
// watching nothing is also in. Each mask therefore gets a body it must report
// and a body it must not, so a kind that stops being watched fails here instead
// of going quiet - the way the pollution guard watched clients alone for months
// while looking as green as it does now.
func TestInertMaskGuardSeesEveryKind(t *testing.T) {
	// One body carrying, for every mask, a value sorting cannot change and a
	// value it can.
	body := []byte(`{"one":[1],"two":[1,2],"oneKey":{"a":1},"twoKeys":{"a":1,"b":2},` +
		`"oneWord":"a","twoWords":"a b"}`)

	for _, tc := range []struct {
		name  string
		inert Case
		live  Case
	}{
		{"Unordered", Case{Unordered: []string{"one"}}, Case{Unordered: []string{"two"}}},
		{"UnorderedKeys", Case{UnorderedKeys: []string{"oneKey"}}, Case{UnorderedKeys: []string{"twoKeys"}}},
		{"UnorderedWords", Case{UnorderedWords: []string{"oneWord"}}, Case{UnorderedWords: []string{"twoWords"}}},
		// Volatile has no second shape: a golden cannot say whether a masked
		// value varied. Absence is the one thing it can say.
		{"Volatile", Case{Volatile: []string{"absent"}}, Case{Volatile: []string{"one"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inertMasks(tc.inert, body)
			if err != nil {
				t.Fatalf("inert case: %v", err)
			}
			if len(got) == 0 {
				t.Errorf("%s: an inert mask went unreported", tc.name)
			}
			got, err = inertMasks(tc.live, body)
			if err != nil {
				t.Fatalf("live case: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("%s: a mask that does something was reported anyway: %v", tc.name, got)
			}
		})
	}

	// Every mask a Case can declare over its body is watched. A fifth added to
	// case.go and not to bodyMasks would be unwatched and this test would still
	// pass, so the count is asserted rather than assumed.
	if len(bodyMasks) != 4 {
		t.Errorf("bodyMasks watches %d masks; Case declares four over its body", len(bodyMasks))
	}
}
