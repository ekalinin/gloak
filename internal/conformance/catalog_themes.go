package conformance

import "net/http"

// themesDoc is where the theme resource route is described. Keycloak's theme
// guide documents how a theme is written and deployed; it does not describe
// what the route answers, which is why this chapter's denominator is a case
// count. See chapters.go for how the sweep behind that count was run.
var themesDoc = Doc{
	URL:       "https://www.keycloak.org/docs/26.7.1/server_development/#_themes",
	Section:   "Themes: the /resources/{version}/{themeType}/{themeName}/{path} route",
	Retrieved: "2026-09-15",
}

// themeResourceAbsentHeaders is what a theme resource does **not** carry, and
// the first name on the list is the finding.
//
// AGENTS.md describes five security headers as present on everything Keycloak
// serves, with a list of exceptions. This is another: read at socket level, a
// 200 from this route carries `Referrer-Policy`,
// `Strict-Transport-Security`, `X-Content-Type-Options` and `X-Robots-Tag` -
// four of the five - and **no `X-Frame-Options`**. A theme *page* one path
// family away carries all five plus `Content-Security-Policy` and
// `Content-Language`, measured on one container seconds apart, so the
// difference is the route and not the server.
//
// The other two names are what makes the boundary with P13 assertable rather
// than described: `Content-Security-Policy` and `Content-Language` are on every
// theme page this repository already records and on nothing this route serves.
//
// The declaration is compared against the recorded bytes by
// TestAssertAbsentHeadersAgreeWithTheGolden, which is the half of F177 that
// works on a Recorded case - where diff's "these differ" verdict is satisfied
// by any one difference and therefore asserts nothing on its own.
var themeResourceAbsentHeaders = []string{
	"X-Frame-Options",
	"Content-Security-Policy",
	"Content-Language",
}

// themeStyles is the file this chapter uses as its instrument, and the reason
// it is one file rather than a sample is that **the theme tree does not move**.
// `css/styles.css` came back byte-identical - one md5 - from a start-dev
// container, a second start-dev container with a different database, and a
// production-mode container; the content-hashed asset names the two consoles
// import (`main-BbID33M6.js`, `main-DmoViYol.css`) were identical across all
// three too. The only part of a theme URL that moves is the version segment,
// which is what Step.CaptureThemeResource exists for.
//
// So a second file would re-measure the first. Where a case below names a
// different file it is because the case is about something else - the content
// type, the theme type, or the confinement to `resources/`.
const themeStyles = "/css/styles.css"

// themeResourceCases is the theme surface: one route,
// `/resources/{version}/{themeType}/{themeName}/{path}`, and what it answers.
//
// **This is the other end of the URLs the theme pages mint**, and that is the
// boundary with P13. Thirty-eight goldens in this repository hold
// `/resources/{{theme_resource}}/` inside a body - the error page, the info
// page, the device pages, the SAML login pages, the account console - and every
// one of them is counted under the endpoint that rendered it, which is what
// TestThemeResourceAppearsOnlyInTheThemePages already enumerates. None of them
// asks the route a question. These cases are the requests those URLs describe.
//
// The unit is **an answer the route gives that a request can distinguish
// without knowing which file it named**. Keycloak's themes hold about twelve
// hundred servable files and they say one thing between them - a file that is
// there is served with its bytes - so counting them per file would report one
// behaviour twelve hundred times. That is the SAML cut's decision about the
// fallback family and the management cut's about the verb dimension, applied to
// the dimension this surface has: the file. What does not collapse is in the
// cases below.
//
// **Nothing here is Implemented.** Gloak registers no route under /resources at
// all: it mints the version into its pages, seven times per page, and serves
// nothing at the other end. Every case is Recorded, which is the status that
// says measured and deliberately not served, and the list clears itself when
// somebody serves the route.
var themeResourceCases = []Case{
	{
		// The primary witness: a file that exists is served with its bytes.
		//
		// **Cache-Control on this route is a function of how the server was
		// started, not of its version.** `no-cache` under `start-dev` and
		// `max-age=2592000` under `start`, measured on two containers from one
		// image on 2026-09-15. This golden holds the development value, and that
		// is the only golden-bearing header in this repository whose value is a
		// startup mode rather than an image. F250 is the entry; F245 is the
		// same shape one option set along.
		//
		// **The golden now says so.** Its `# recorded-with:` line names
		// `start-dev`, which is what F250 asked for: the header can still be
		// read as a property of the product, and the file one line above it
		// says which command line produced it. A `start` configuration is not
		// declared, because nothing yet records anything under one - see
		// configuration.go.
		//
		// It is asserted rather than left off precisely because of that. A
		// header measured to move on a variable the catalogue does not name is
		// worth pinning to the variable it *was* recorded under, so the next
		// person to change the recorder's command line finds out from a red
		// test instead of from a re-record diff.
		ID:                  "themes/resource/served-file",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "Gloak serves no /resources route at all - it mints the version into its pages and serves nothing at the other end",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2" + themeStyles},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// `.js` is `text/javascript`. One of the three rows of the content-type
		// mapping a golden can hold; TestThemeContentTypesAreTheMeasuredMapping
		// holds the whole six-row table, including the two rows no golden can.
		ID:                  "themes/resource/javascript",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route, and this case is here for the media type rather than for the bytes",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2/js/passwordVisibility.js"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// `.svg` is `image/svg+xml`, and it is the one image type this route
		// serves that a golden can hold: SVG is text where png, ico and woff2
		// are not. See themes/resource/binary-media-type for the two that are
		// not, and F161 for why a golden over a binary body asserts nothing.
		ID:                  "themes/resource/svg",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route, and the only image media type on this surface whose body is text",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/admin/keycloak.v2/favicon.svg"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// **Two media types on this route are not the registered ones.** `.ico`
		// and `.woff2` are both `application/octet-stream`, where the registered
		// values are `image/vnd.microsoft.icon` and `font/woff2` - so the
		// mapping is a table Keycloak keeps and not a rule a reader can derive,
		// which is why the three rows above are three cases and not one.
		//
		// It is Pending rather than Recorded because the body is binary and
		// RefuseNonTextBody would reject it. The header alone cannot be
		// recorded without the body: FormatGolden writes both. The measurement
		// is in the handover document and in
		// TestThemeContentTypesAreTheMeasuredMapping, which is the same place
		// management/metrics' undrawable dump ended up.
		ID:      "themes/resource/binary-media-type",
		Doc:     themesDoc,
		Status:  Pending,
		Reason:  "measured and unrecordable: `.woff2` answers 200 `application/octet-stream` with 16296 bytes of font, and RefuseNonTextBody refuses a golden over a binary body - F161. The media type is pinned by TestThemeContentTypesAreTheMeasuredMapping instead",
		Fixture: "theme-page",
		Request: Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/common/keycloak/lib/pficon/pficon.woff2"},
	},
	{
		// `common` is a theme type of its own, and its theme is named
		// `keycloak` rather than `keycloak.v2`. It is the type both consoles and
		// the login pages import their vendored modules from, which is why the
		// same `/resources/` prefix reaches three unrelated front ends.
		//
		// The case is here for the type rather than for the file: without it
		// nothing in this repository records that the segment after the version
		// is a closed set rather than a directory name.
		ID:                  "themes/resource/common-type",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route, and this case is here for the theme type rather than for the bytes",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/common/keycloak/lib/pficon/pficon.css"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// **A fourth 404 body, and it is the emptiest one this project has
		// measured.** The three already recorded are the Admin API's
		// `Unable to find matching target resource method` with none of the
		// security headers, `HTTP 404 Not Found` with all five, and the
		// management port's 53 bytes of HTML with none. This one is **zero
		// bytes with no Content-Type at all** and four of the five security
		// headers, which is a combination none of the other three has.
		//
		// It is not counted under http/fallback for the reason oidc/protocol
		// and management/fallback are not: what decides the answer is this
		// route reading its own theme tree, not a route table that failed to
		// match. A path one segment shorter - /resources/{version}/login - is
		// the Admin API's body, and that one **is** http/fallback's and is not
		// counted here.
		ID:                  "themes/resource/unknown-file",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "Gloak serves no /resources route, so it answers the realm-tree fallback rather than this route's own empty 404",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2/css/gloak-nosuch.css"},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// An unknown theme **type** is refused. Paired with
		// themes/resource/unknown-theme-name, which is not: the two together
		// are the measurement, and either alone reads as a rule the other
		// breaks.
		//
		// The type is also matched **case-insensitively** - see
		// themes/resource/type-ignores-case - so this segment is neither a
		// directory name nor an exact enum spelling.
		ID:                  "themes/resource/unknown-type",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; the pair with unknown-theme-name is what says the type is closed and the name is not",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/gloak-nosuchtype/keycloak.v2" + themeStyles},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// **An unknown theme name is not an error: it falls back to the type's
		// default theme and serves its bytes.** `gloak-nosuchtheme` answers
		// `css/styles.css` byte for byte as `keycloak.v2` does - one md5 over
		// three spellings - and answers 404 for `css/login.css`, which is the
		// v1 `keycloak` theme's file and not the default's. So the fallback is
		// to the default theme rather than to a search of every theme.
		//
		// This is the sharpest claim on the surface and the one a reimplementation
		// is most likely to get wrong in the safe-looking direction, by
		// answering 404 for a theme nobody installed.
		ID:                  "themes/resource/unknown-theme-name",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route, and the one case here whose answer is a 200 for a theme that does not exist",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/gloak-nosuchtheme" + themeStyles},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// The theme type is compared case-insensitively: `LOGIN` and `Login`
		// both answer what `login` answers. The theme **name** is not - it has
		// no exact match to be insensitive about, since any unmatched name
		// reaches the default theme - and the version segment is not either:
		// `AAAAA` is a 404 where `aaaaa` is a 307, which is
		// themes/version/wrong-shape.
		//
		// Three segments of one path, three different rules about case.
		ID:                  "themes/resource/type-ignores-case",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; one of three segments on this path and the only one that ignores case",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/LOGIN/keycloak.v2" + themeStyles},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// **A theme's root directory answers 200 with an empty body and
		// `application/octet-stream`.** Not a listing, not a 403 and not a 404:
		// the route opens a stream for the directory entry and gets nothing out
		// of it.
		//
		// The path one byte shorter, without the trailing slash, is this route's
		// own 404, and the path one segment deeper - `/css/` - is the same empty
		// 200. So the answer follows whether the entry exists, not whether it is
		// a file.
		//
		// It is a case rather than a curiosity because a reimplementation
		// serving a listing here would leak the theme's file names, and one
		// serving a 404 would look correct to every reader.
		ID:                  "themes/resource/theme-root",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route, and the only 200 on this surface with no bytes behind it",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2/"},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
	{
		// **Only `resources/` inside a theme is reachable.** A theme directory
		// holds `theme.properties`, its Freemarker templates and its message
		// bundles beside `resources/`, and the route serves none of them: the
		// URL `/resources/{version}/{type}/{name}/{path}` resolves to
		// `theme/{name}/{type}/resources/{path}` and cannot address a sibling.
		//
		// This is the confinement claim, and it is the one whose absence would
		// be a disclosure rather than a divergence: `template.ftl` is the login
		// theme's whole page structure and `theme.properties` names the parent
		// theme and every style the deployment imports.
		ID:                  "themes/resource/template-not-served",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; this is the confinement claim and it is why the chapter is the route rather than the theme tree",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2/template.ftl"},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// **The i18n message bundles are not on this surface.** Every theme
		// carries `messages/messages_en.properties` beside `resources/`, and
		// this route answers 404 for all of them - base, keycloak, keycloak.v2
		// and the fallback theme alike.
		//
		// It is a case because it is the sentence this chapter's old Reason got
		// wrong. That Reason said "themes **and i18n** are served as resources,
		// not as an API"; i18n is served as an API, by nineteen Implemented
		// cases under admin/realms-admin/localization-* and two Recorded ones
		// under account/supported-locales, and the part of i18n that *is* a
		// theme resource is the part this route refuses to serve.
		ID:                  "themes/resource/messages-not-served",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; recorded so that the claim 'i18n is served as a resource' has a measurement against it rather than a sentence",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/{{theme_resource}}/login/keycloak.v2/messages/messages_en.properties"},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// **A cache-busted static route with no revalidation at all.** No
		// `ETag`, no `Last-Modified`, no `Accept-Ranges`, no `Vary`, and both
		// `If-None-Match` and `If-Modified-Since` answered with the full body
		// and a 200. `Accept-Encoding: gzip` is answered uncompressed with no
		// `Content-Encoding`, and `Accept: application/json` is answered
		// `text/css` - the header is ignored, where one port along /metrics
		// refuses the very media type it produces.
		//
		// The request sends both conditional headers so that one case covers
		// both, which is the one place in this chapter a case carries two
		// questions: neither header alone would distinguish "not supported"
		// from "supported and the precondition failed", and together they do,
		// because a server honouring either would have answered 304 to the
		// second.
		ID:      "themes/resource/conditional-request",
		Doc:     themesDoc,
		Status:  Recorded,
		Reason:  "the same absent route; this case sends a request no other case here sends and is what records that the route has no validators",
		Fixture: "theme-page",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/resources/{{theme_resource}}/login/keycloak.v2" + themeStyles,
			Headers: map[string]string{
				"If-None-Match":     `"gloak-probe"`,
				"If-Modified-Since": "Wed, 21 Oct 2099 07:28:00 GMT",
				"Accept":            "application/json",
				"Accept-Encoding":   "gzip",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: append([]string{
			"ETag", "Last-Modified", "Accept-Ranges", "Vary", "Content-Encoding",
		}, themeResourceAbsentHeaders...),
	},
	// **The normalisation rule runs ahead of this route, and that is not a case
	// here.** `//` inside a resource path answers
	// `400 {"error":"missingNormalization",...}` with no security headers at
	// all, and so do `/../` and `%2e%2e` - so the decoding happens before the
	// check. It is worth knowing because the management port was measured the
	// week before answering the same request with a 200, which narrowed
	// AGENTS.md's "ahead of the route table, across the whole server" to one
	// route table; this route is inside that one although it serves no JSON and
	// none of the application's error shapes.
	//
	// It is **not counted** because http/fallback/path-not-normalized already
	// holds those 82 bytes, and they are byte-identical here. That is the SAML
	// cut's rule - the generic fallback family is counted once for the whole API
	// and never per path - and the contrast with management/health/unnormalised-path
	// is exactly the test it asks for: that case is counted because its answer
	// is a **200**, a different behaviour wearing the same request.
	//
	// The same rule disposes of two more answers this route gives. Every verb
	// but GET and HEAD is `{"error":"HTTP 405 Method Not Allowed"}`, and a path
	// with fewer than four segments under /resources is
	// `{"error":"Unable to find matching target resource method"}`. Both are
	// http/fallback's and neither is counted again.
}

// themeVersionCases are what the cache-busting segment decides.
//
// They are a chapter of their own because the segment is the only part of a
// theme URL that belongs to the installation rather than to the theme tree:
// the files behind it were measured byte-identical across three containers and
// two startup modes, and the segment was different in all three. It is the
// value ReplaceThemeResource exists to mask, the value
// Step.CaptureThemeResource exists to read, and the one thing on this surface a
// reimplementation has to mint rather than copy.
//
// **None of these four writes the version as {{theme_resource}}.** They send a
// literal `aaaaa` or `aaaaaa`, which is the point: a case that asked at the
// current version could not measure what a stale one does.
var themeVersionCases = []Case{
	{
		// **A stale version is a 307 to the current one, with the rest of the
		// path preserved and the query dropped.** So a browser holding a cached
		// page from before a redeploy is walked to the new URL rather than shown
		// a 404, and the redirect is `307` rather than `301` or `308` - the one
		// status in this family that neither caches nor permits the method to
		// change.
		//
		// The Location carries the live version, which is why this case needs
		// the fixture although its own path does not: recordedHeaders runs
		// ReplaceCaptured over every header value, so the capture masks the
		// header to the same {{theme_resource}} spelling ReplaceThemeResource
		// gives a body. Without the capture this golden would churn on every
		// recording.
		ID:                  "themes/version/stale",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "Gloak serves no /resources route and mints no redirect to one; it has a version of its own and nothing that answers at it",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/aaaaa/login/keycloak.v2" + themeStyles, Query: map[string]string{"gloak": "probe"}},
		AssertHeaders:       []string{"Location"},
		AssertAbsentHeaders: append([]string{"Content-Type", "Cache-Control"}, themeResourceAbsentHeaders...),
	},
	{
		// **The route validates the version segment against `[0-9a-z]{5}` before
		// it looks at anything else.** Six characters is a 404 where five is a
		// 307, and so are four, `AAAAA`, `Aaaaa`, `aaaaA`, `aa-aa`, `aa_aa` and
		// `aa.aa`; `12345`, `00000`, `zzzzz`, `aaaa1` and `1aaaa` are all 307.
		//
		// This is the case that turns ReplaceThemeResource's pattern from an
		// inference into a measurement. That regexp was written from 65 sampled
		// characters and a probability of about 1e-15 that the alphabet had
		// upper case in it; the route decides the same alphabet, and now says so
		// where a test can read it.
		ID:                  "themes/version/wrong-shape",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; recorded because it is the server's own statement of the alphabet ReplaceThemeResource was written against",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/aaaaaa/login/keycloak.v2" + themeStyles},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// **The redirect fires only after the resource resolves.** A stale
		// version on a file that is not there is this route's empty 404, not a
		// 307 to a URL that would also be a 404.
		//
		// So the order is: validate the segment's shape, resolve the theme and
		// the file, and only then compare the version. A reimplementation that
		// redirected on the version alone - the obvious order, and the cheap one
		// - would answer 307 here and a client following it would get the 404
		// one request later.
		ID:                  "themes/version/stale-unknown-file",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; this case and stale are the pair that places the version check after the lookup rather than before it",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/aaaaa/login/keycloak.v2/css/gloak-nosuch.css"},
		AssertAbsentHeaders: append([]string{"Content-Type"}, themeResourceAbsentHeaders...),
	},
	{
		// **A stale version on an unknown theme name serves the bytes and does
		// not redirect.** `/resources/aaaaa/login/gloak-nosuchtheme/css/styles.css`
		// is a 200 where the same request naming `keycloak.v2` is a 307, and the
		// body is the default theme's file either way.
		//
		// That is the cell that makes the version check conditional on more than
		// the file resolving: it resolves here too. The two answers differ on
		// whether the **name** matched a theme, so the redirect is minted on the
		// exact-match path and the fallback path returns before reaching it.
		//
		// It is the last cell of the grid and the one no reader would predict,
		// which is the only reason it is a case: without it the chapter would
		// state a rule with three supporting cells and one silent exception.
		ID:                  "themes/version/stale-fallback-theme",
		Doc:                 themesDoc,
		Status:              Recorded,
		Reason:              "the same absent route; the fourth cell of the version grid and the one that contradicts the rule the other three suggest",
		Fixture:             "theme-page",
		Request:             Request{Method: http.MethodGet, Path: "/resources/aaaaa/login/gloak-nosuchtheme" + themeStyles},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: themeResourceAbsentHeaders,
	},
}
