package conformance

import (
	"net/http"
	"strings"
	"testing"
)

// themesChapterCases is the number of behaviours the themes surface was counted
// to have on 2026-09-15, pinned so that the number in
// docs/superpowers/handover/themes-chapter.md is checked rather than trusted.
//
// account-api.md is why this exists: three numbers disagreed inside one chapter
// there before anybody had merged it. The management cut copied it and so does
// this one.
const themesChapterCases = 17

// themesChapterPrefix is what makes a case one of this chapter's, used by every
// test below so that the set is decided once.
const themesChapterPrefix = "themes/"

// themeCases is every catalogue case in the themes chapters.
func themeCases() []Case {
	var out []Case
	for _, c := range Catalog {
		if strings.HasPrefix(c.ID, themesChapterPrefix) {
			out = append(out, c)
		}
	}
	return out
}

// TestThemesChapterCountIsThePinnedNumber joins the catalogue to the number
// written down, so that a case added or removed makes the handover document
// wrong in a test rather than in a reader's head.
func TestThemesChapterCountIsThePinnedNumber(t *testing.T) {
	got := len(themeCases())
	if got != themesChapterCases {
		t.Errorf("the themes chapters hold %d cases and this file says %d; "+
			"if the surface really changed, change the number here and in "+
			"docs/superpowers/handover/themes-chapter.md together", got, themesChapterCases)
	}
	// A prefix nothing matches would make every test in this file vacuous, and
	// the count above would be the only thing that noticed - which is the shape
	// of the management cut's M7.
	if got == 0 {
		t.Fatal("no case matches the themes prefix, so every test in this file is vacuous")
	}
}

// TestThemeCasesReportUnderAThemesChapter refuses a themes case filed anywhere
// else and a themes chapter that is not declared.
//
// The mistake it catches is a measurement of the resource route filed under
// oidc/authorization, where the thirty-eight theme **pages** live. The two are
// one path family apart and the whole boundary this chapter draws is between
// them, so a case on the wrong side of it would be counted as the other
// chapter's behaviour and the boundary would be prose again.
func TestThemeCasesReportUnderAThemesChapter(t *testing.T) {
	declared := map[string]bool{}
	for _, ch := range Chapters {
		if strings.HasPrefix(ch.Name, themesChapterPrefix) {
			declared[ch.Name] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("no themes chapter is declared, so this test asserts nothing")
	}
	for _, c := range themeCases() {
		if !declared[chapterOf(c.ID)] {
			t.Errorf("%s reports under %q, which is not a declared themes chapter",
				c.ID, chapterOf(c.ID))
		}
	}
	// And the other direction: a declared themes chapter holding no case is a
	// row in the report with a denominator of zero.
	holds := map[string]int{}
	for _, c := range themeCases() {
		holds[chapterOf(c.ID)]++
	}
	for name := range declared {
		if holds[name] == 0 {
			t.Errorf("chapter %q is declared and holds no case", name)
		}
	}
}

// TestThemeCasesDeclareXFrameOptionsAbsent is the fifth exception to AGENTS.md's
// security-header bullet, asserted rather than described.
//
// Every response this route serves - the 200s, the empty 404, the 307 and the
// empty-bodied theme root - carries four of the five headers and not
// `X-Frame-Options`, read off a socket rather than through curl, because a probe
// of an absence otherwise measures the probe. A theme **page** one path family
// away carries all five, measured on the same container seconds apart.
//
// The list is `theFiveSecurityHeaders` from headersplit_test.go rather than the
// slice the cases are spread from. That is the management cut's M2: comparing a
// declaration against the very slice it was built from is `count(x) == count(x)`,
// and the one edit that breaks it passes.
func TestThemeCasesDeclareXFrameOptionsAbsent(t *testing.T) {
	var frameOptions string
	for _, h := range theFiveSecurityHeaders {
		if http.CanonicalHeaderKey(h) == "X-Frame-Options" {
			frameOptions = h
		}
	}
	if frameOptions == "" {
		t.Fatal("X-Frame-Options is not one of the five security headers any more, " +
			"so this chapter's exception is about a header that no longer exists")
	}
	for _, c := range themeCases() {
		if c.Status == Pending {
			continue // no golden, so nothing to declare against
		}
		found := false
		for _, h := range c.AssertAbsentHeaders {
			if http.CanonicalHeaderKey(h) == http.CanonicalHeaderKey(frameOptions) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not declare %s absent, and every response on this "+
				"route was measured without it", c.ID, frameOptions)
		}
	}
}

// TestThemeCasesNameTheThemePageFixture refuses a themes case with any other
// fixture, and the reason is mechanical rather than tidy.
//
// A case's own path is expanded from the fixture's variables, so a case without
// theme-page cannot write {{theme_resource}} and would have to hard-code a
// version that is minted per database - a golden that is wrong on the next
// recording. The four themes/version cases send a literal stale version and do
// not need the expansion, and they need the fixture anyway: their 307's Location
// carries the **live** version, recordedHeaders runs ReplaceCaptured over every
// header value, and without the capture that header churns on every run.
//
// So both halves of the chapter need the same fixture for two different reasons,
// which is why the rule is "this fixture" rather than "a fixture".
func TestThemeCasesNameTheThemePageFixture(t *testing.T) {
	const want = "theme-page"
	if _, ok := Fixtures[want]; !ok {
		t.Fatalf("fixture %q does not exist, so this test asserts nothing", want)
	}
	for _, c := range themeCases() {
		if c.Fixture != want {
			t.Errorf("%s names fixture %q; a themes case needs %q, either to expand "+
				"{{theme_resource}} into its path or to mask it out of a Location",
				c.ID, c.Fixture, want)
		}
	}
}

// TestThemeResourceCasesAddressTheResourceRoute refuses a themes case whose
// path is not under /resources, which is what stops this chapter from becoming
// a place to file anything theme-shaped.
//
// The boundary is the point of the chapter: a page rendered *from* a theme is
// counted under the endpoint that renders it - account/console is the precedent
// - and the machinery a theme is served *by* is counted here. A case for
// `GET /` or `GET /admin/{realm}/console/` filed under this heading would put a
// page in the machinery's chapter and lose the distinction the whole cut rests
// on. See F252 for the two pages that are counted in neither place.
func TestThemeResourceCasesAddressTheResourceRoute(t *testing.T) {
	for _, c := range themeCases() {
		if !strings.HasPrefix(c.Request.Path, "/resources/") {
			t.Errorf("%s asks for %q, which is not the resource route; a theme page is "+
				"counted where it is served", c.ID, c.Request.Path)
		}
	}
}

// TestThemeContentTypesAreTheMeasuredMapping holds the whole media-type table,
// including the two rows no golden can.
//
// Three of the six extensions this route serves have bodies a golden can hold
// and three do not, so a reader checking the mapping from the goldens alone
// would see half of it - and the interesting half is the half that is missing.
// `.ico` and `.woff2` are **not** their registered media types: both are
// `application/octet-stream`, where `image/vnd.microsoft.icon` and `font/woff2`
// are what a reader would predict. So the mapping is a table Keycloak keeps
// rather than a rule, which is the reason the three recordable rows are three
// cases and not one.
//
// Measured on 2026-09-15 against quay.io/keycloak/keycloak:26.7.1, one file per
// extension, on a start-dev container and again on a production-mode one.
func TestThemeContentTypesAreTheMeasuredMapping(t *testing.T) {
	measured := map[string]string{
		".css":   "text/css",
		".js":    "text/javascript",
		".svg":   "image/svg+xml",
		".png":   "image/png",
		".ico":   "application/octet-stream",
		".woff2": "application/octet-stream",
	}
	// The two rows that are the finding, named rather than left to a reader to
	// spot among the six. A mapping that had quietly become the registered one
	// would pass the map above only if somebody had edited it, and would pass
	// nothing here.
	for _, ext := range []string{".ico", ".woff2"} {
		if measured[ext] != "application/octet-stream" {
			t.Errorf("%s is recorded as %q; the measurement is application/octet-stream, "+
				"and it being the registered type instead is the thing this test exists to say",
				ext, measured[ext])
		}
	}
	// And the vacuity guard the comparison needs of its own: a table where every
	// row agreed would carry no finding at all.
	distinct := map[string]bool{}
	for _, v := range measured {
		distinct[v] = true
	}
	if len(distinct) < 4 {
		t.Errorf("the media-type table holds %d distinct values; it was measured with "+
			"five over six extensions, so this table has been flattened", len(distinct))
	}
}

// TestCaptureThemeResourceAgreesWithTheUnconditionalPass is the equality
// Step.CaptureThemeResource's doc comment claims, asserted rather than written.
//
// A captured variable is masked by ReplaceCaptured as `{{name}}`; a body's
// `/resources/<version>/` is masked by ReplaceThemeResource as
// `/resources/{{theme_resource}}/`. The two have to produce the same bytes,
// because a 307's Location goes through the first and a page's markup goes
// through the second, and a golden holding both would otherwise spell one value
// two ways.
//
// The guard is that the two masks are applied to the **same** input and compared,
// rather than each being checked against a string written here - which would be
// a golden checked against a golden somebody typed.
func TestCaptureThemeResourceAgreesWithTheUnconditionalPass(t *testing.T) {
	const version = "t72jg" // one of the thirteen measured values
	body := []byte(`<link href="/resources/` + version + `/login/keycloak.v2/css/styles.css">`)

	got, err := CaptureThemeResourceFrom(body)
	if err != nil {
		t.Fatalf("CaptureThemeResourceFrom: %v", err)
	}
	if got != version {
		t.Fatalf("captured %q, want %q", got, version)
	}

	viaCapture := string(ReplaceCaptured(body, map[string]string{"theme_resource": got}))
	viaPass := string(ReplaceThemeResource(body))
	if viaCapture != viaPass {
		t.Errorf("the capture and the unconditional pass spell the same value two ways:\n"+
			"  ReplaceCaptured:      %s\n  ReplaceThemeResource: %s", viaCapture, viaPass)
	}
	// Vacuity: both sides leaving the input alone would also be equal.
	if viaPass == string(body) {
		t.Fatal("neither mask changed the input, so the equality above is between two copies of it")
	}
}

// TestCaptureThemeResourceRefusesAPageWithoutOne is the failure path, because
// the fixture's whole job is to fail loudly when the page it reads stops being
// a theme page. A capture that silently yielded "" would expand every case's
// path to `/resources//login/...`, which is the normalisation 400 - eighteen
// goldens quietly recording the wrong behaviour.
func TestCaptureThemeResourceRefusesAPageWithoutOne(t *testing.T) {
	for _, body := range []string{
		"",
		`{"error":"invalid_client"}`,
		// The near miss: the right prefix with a version of the wrong shape.
		// Six characters, which the route itself answers with a 404.
		`<link href="/resources/aaaaaa/login/keycloak.v2/css/styles.css">`,
	} {
		if v, err := CaptureThemeResourceFrom([]byte(body)); err == nil {
			t.Errorf("captured %q from %q, want an error", v, body)
		}
	}
}

// TestChapterRowLeavesAnUnenumeratedChapterOutOfTheTotals is the witness the
// report's unenumerated branch needed once the catalogue stopped providing one.
//
// Until 2026-09-15 that branch was covered by "some chapter happens to be
// uncounted today", and enumerating themes took the last one away. The branch is
// not dead: Chapter.Enumerated is how the next chapter added to this project
// says nobody has counted it, and a chapter left silently out of the total is
// the inflation the field exists to prevent. So the coverage it lost is given
// back here, against a chapter this test constructs.
//
// What it pins is the part that matters to a percentage: an unenumerated chapter
// contributes **nothing to either total** while still appearing as a row.
func TestChapterRowLeavesAnUnenumeratedChapterOutOfTheTotals(t *testing.T) {
	tl := chapterTally{implemented: 3, recorded: 4, pending: 5, operations: 3, documentedOps: 9}

	uncounted := chapterRow(Chapter{Name: "gloak/uncounted", Reason: "nobody has counted it"}, tl)
	if uncounted.served != 0 || uncounted.documented != 0 {
		t.Errorf("an unenumerated chapter contributed %d served and %d documented to the "+
			"totals; it must contribute neither, or the percentage counts a surface "+
			"nobody measured", uncounted.served, uncounted.documented)
	}
	if got, want := uncounted.row, "gloak/uncounted\t3\t4\t0\tfalse"; got != want {
		t.Errorf("row = %q, want %q", got, want)
	}
	if !strings.Contains(uncounted.log, "nobody has counted it") {
		t.Errorf("the logged line does not carry the Reason: %q", uncounted.log)
	}

	// The control, without which the assertion above is satisfied by chapterRow
	// returning a zero value for every chapter. Same tally, enumerated, and it
	// must contribute.
	counted := chapterRow(Chapter{Name: "gloak/counted", Enumerated: true}, tl)
	if counted.served == 0 || counted.documented == 0 {
		t.Fatalf("an enumerated chapter with the same tally contributed %d served and "+
			"%d documented; the comparison above is vacuous",
			counted.served, counted.documented)
	}
	// And the tag arm, which takes its denominator from the description rather
	// than from the case count - the two are deliberately different numbers in
	// this tally so that one standing in for the other is visible.
	tagged := chapterRow(Chapter{Name: "gloak/tagged", OpenAPITag: "Some Tag", Enumerated: true}, tl)
	if tagged.documented != tl.documentedOps {
		t.Errorf("a tagged chapter documented %d, want the tag's %d",
			tagged.documented, tl.documentedOps)
	}
	if counted.documented == tagged.documented {
		t.Fatal("the catalogue and tag denominators are the same number in this tally, " +
			"so the check above cannot tell them apart")
	}
}
