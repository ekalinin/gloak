package conformance

import (
	"bytes"
	"net/http"
	"os"
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

// themeMediaTypes is what the resource route answers for each extension it
// serves, measured 2026-09-15 against quay.io/keycloak/keycloak:26.7.1.
//
// Eighteen extensions appear among the 1234 servable files, one file per
// extension was requested, and **nine of the eighteen are
// `application/octet-stream`**. Only three of the eighteen have bodies a golden
// can hold, so a reader checking the mapping from the goldens alone would see a
// sixth of it - and the interesting five sixths are the part that is missing.
// This is where the rest lives, which is where management-port.md put the
// metrics dump it could not record either.
var themeMediaTypes = map[string]string{
	".css":   "text/css",
	".gif":   "image/gif",
	".html":  "text/html",
	".jpg":   "image/jpeg",
	".js":    "text/javascript",
	".json":  "application/json",
	".png":   "image/png",
	".svg":   "image/svg+xml",
	".txt":   "text/plain",
	".eot":   "application/octet-stream",
	".hbs":   "application/octet-stream",
	".ico":   "application/octet-stream",
	".map":   "application/octet-stream",
	".otf":   "application/octet-stream",
	".scss":  "application/octet-stream",
	".ttf":   "application/octet-stream",
	".woff":  "application/octet-stream",
	".woff2": "application/octet-stream",
}

// TestThemeContentTypesAreTheMeasuredMapping holds the whole media-type table,
// including the fifteen rows no golden can.
//
// The mapping is a table Keycloak keeps and not a rule a reader can derive,
// which is why the three recordable rows are three cases and not one. Two
// groups of rows say so:
//
//   - **Every font format is `application/octet-stream`**: `.woff2`, `.woff`,
//     `.ttf`, `.otf` and `.eot`, where `font/woff2`, `font/woff`, `font/ttf`
//     and `font/otf` are registered and are what a reader would predict.
//   - **`.ico` is too**, where `image/vnd.microsoft.icon` is registered - and
//     `.gif`, `.jpg`, `.png` and `.svg` beside it are all their registered
//     image types. So "images get an image type" is a rule with one exception
//     and it is the commonest favicon extension on the web.
//
// Source maps are in the table because they are **served**:
// `/resources/{version}/admin/keycloak.v2/assets/*.js.map` answers 200. So is
// `robots.txt` under the admin theme, as `text/plain`.
func TestThemeContentTypesAreTheMeasuredMapping(t *testing.T) {
	// The rows that are the finding, named rather than left to a reader to spot
	// among eighteen. A table that had quietly become the registered mapping
	// would satisfy itself; this does not.
	for _, ext := range []string{".eot", ".ico", ".map", ".otf", ".ttf", ".woff", ".woff2"} {
		if got := themeMediaTypes[ext]; got != "application/octet-stream" {
			t.Errorf("%s is recorded as %q; it was measured application/octet-stream, "+
				"and it being the registered type instead is the thing this table exists to say",
				ext, got)
		}
	}
	// The other direction, without which the check above is satisfied by a table
	// where everything is octet-stream.
	for ext, want := range map[string]string{
		".gif": "image/gif", ".jpg": "image/jpeg", ".png": "image/png", ".svg": "image/svg+xml",
	} {
		if got := themeMediaTypes[ext]; got != want {
			t.Errorf("%s is recorded as %q, want %q - the image rows are what make "+
				"the .ico row a finding rather than a policy", ext, got, want)
		}
	}
	// And the vacuity guard the traversal needs of its own: a table one row
	// long, or one with a single value in it, would pass both loops above.
	distinct := map[string]bool{}
	for _, v := range themeMediaTypes {
		distinct[v] = true
	}
	if len(themeMediaTypes) != 18 || len(distinct) != 10 {
		t.Errorf("the table holds %d extensions over %d media types; it was measured "+
			"with 18 over 10, so a row has been added or lost without a measurement",
			len(themeMediaTypes), len(distinct))
	}
	// Every case in the chapter that asserts Content-Type must be asking for an
	// extension this table knows, or the table and the goldens are two
	// unconnected lists of the same thing.
	for _, c := range themeCases() {
		asserts := false
		for _, h := range c.AssertHeaders {
			if http.CanonicalHeaderKey(h) == "Content-Type" {
				asserts = true
			}
		}
		if !asserts || strings.HasSuffix(c.Request.Path, "/") {
			continue
		}
		leaf := c.Request.Path[strings.LastIndexByte(c.Request.Path, '/')+1:]
		i := strings.LastIndexByte(leaf, '.')
		if i < 0 {
			continue
		}
		if _, ok := themeMediaTypes[leaf[i:]]; !ok {
			t.Errorf("%s asserts Content-Type for a %q file and the table has no such row",
				c.ID, leaf[i:])
		}
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

// themeGoldenGroups are the goldens measured answering the same bytes, and the
// test below is what the duplication bought.
//
// Five of the sixteen hold the same 3182-byte stylesheet and six more hold the
// same empty 404. The objection is that the denominator counts one answer
// eleven times, and the answer is management-port.md section 2.5's: **a
// behaviour is a request and its answer, not an answer**. That an unknown theme
// name serves the default theme's file, that the theme type ignores case, and
// that a stale version does *not* redirect on the fallback path are three
// separately falsifiable claims about Keycloak that happen to share a body.
//
// What makes them mean something is that the identity is asserted. Every case
// in this chapter is Recorded, and a Recorded case is required *not* to match,
// so a byte changed inside any one of these goldens is absorbed by `diff`
// saying "these differ" - which it would say anyway. That is the management
// cut's M9, met here on a chapter where it covers eleven of sixteen goldens.
//
// The relations are what closes it, and they are relations no single case can
// state: eleven goldens were measured answering two bodies, and this is where
// the equalities live.
var themeGoldenGroups = map[string][]string{
	"the login theme's styles.css": {
		"themes/resource/served-file",
		"themes/resource/type-ignores-case",
		"themes/resource/unknown-theme-name",
		"themes/resource/conditional-request",
		"themes/version/stale-fallback-theme",
	},
	"this route's empty 404": {
		"themes/resource/unknown-file",
		"themes/resource/unknown-type",
		"themes/resource/template-not-served",
		"themes/resource/messages-not-served",
		"themes/version/wrong-shape",
		"themes/version/stale-unknown-file",
	},
}

// themeGoldensThatStandAlone are the cases deliberately in no group: each was
// measured answering bytes no other case in this chapter shares. Named here so
// that a new case with a golden and no group fails rather than passing by
// default, which is the management cut's M10 - a smaller set of true claims is
// still true.
var themeGoldensThatStandAlone = map[string]bool{
	"themes/resource/javascript":  true,
	"themes/resource/svg":         true,
	"themes/resource/common-type": true,
	"themes/resource/theme-root":  true,
	"themes/version/stale":        true,
}

// TestThemeGoldensHoldTheAnswerTheyWereMeasuredTo asserts the equalities above
// and the one inequality that keeps them from being vacuous.
//
// The groups are joined against the catalogue in both directions: a named case
// that does not exist fails, and a themes case with a golden that is in no group
// and is not named as standing alone fails too.
func TestThemeGoldensHoldTheAnswerTheyWereMeasuredTo(t *testing.T) {
	read := func(id string) []byte {
		t.Helper()
		raw, err := os.ReadFile(GoldenPath(goldenDir, id))
		if err != nil {
			t.Fatalf("read golden for %s: %v", id, err)
		}
		g, err := ParseGolden(raw)
		if err != nil {
			t.Fatalf("parse golden for %s: %v", id, err)
		}
		return g.Body
	}

	known := map[string]bool{}
	for _, c := range themeCases() {
		known[c.ID] = true
	}
	grouped := map[string]bool{}
	for name, group := range themeGoldenGroups {
		if len(group) < 2 {
			t.Errorf("group %q holds %d case(s); a group of one asserts nothing",
				name, len(group))
		}
		for _, id := range group {
			if !known[id] {
				t.Errorf("group %q names %s, which is not a case in this chapter", name, id)
			}
			if grouped[id] {
				t.Errorf("%s is in two groups, so it was measured answering two bodies", id)
			}
			grouped[id] = true
		}
		for _, complaint := range goldensThatDisagree(group, read) {
			t.Error(complaint)
		}
	}

	// The other direction. A themes case with a golden and no group is a golden
	// nothing but `diff` looks at, and `diff` is satisfied by any difference.
	for _, c := range themeCases() {
		if c.Status == Pending || grouped[c.ID] || themeGoldensThatStandAlone[c.ID] {
			continue
		}
		if _, err := os.Stat(GoldenPath(goldenDir, c.ID)); err != nil {
			continue
		}
		t.Errorf("%s has a golden and is in no group, so nothing asserts what it holds; "+
			"put it in a group or name it in themeGoldensThatStandAlone", c.ID)
	}
	for id := range themeGoldensThatStandAlone {
		if !known[id] {
			t.Errorf("%s stands alone and is not a case in this chapter", id)
		}
		if grouped[id] {
			t.Errorf("%s is named as standing alone and is also in a group", id)
		}
	}

	// The inequality, without which two groups of identical empty bodies would
	// satisfy every comparison above.
	a := read(themeGoldenGroups["the login theme's styles.css"][0])
	b := read(themeGoldenGroups["this route's empty 404"][0])
	if bytes.Equal(a, b) {
		t.Fatal("the two groups hold the same body, so the equalities above are one claim")
	}
	if len(a) == 0 {
		t.Fatal("the stylesheet group holds an empty body, so its equality is between two nothings")
	}
}
