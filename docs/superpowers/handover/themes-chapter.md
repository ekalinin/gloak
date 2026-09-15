# The themes chapter enumerated, and the last "?" removed from the report

`themes` was the last chapter with no denominator. Its declared reason was
*"themes and i18n are served as resources, not as an API; no operation list
exists"*, and **two of those three clauses do not survive being measured**.

This cut removes it. The surface is enumerated against a live Keycloak 26.7.1 -
**one route, 1234 servable files, seventeen catalogued behaviours** - and
nothing in it is served, because Gloak registers no route under `/resources` at
all: it mints the version into its own pages, seven times per page, and serves
nothing at the other end.

The report now prints no "chapters not enumerated" line with a number in it.
Every percentage after this one is honest in the way the field was built for.

## 1. Measurements

Every value below came from `quay.io/keycloak/keycloak:26.7.1` on 2026-09-15,
on containers started clean for this session. Where a header set is claimed
present or absent the bytes were read off a socket rather than through `curl`,
following AGENTS.md's rule that a probe of an absence measures the probe. Where
a path is deliberately malformed it was sent with `curl --path-as-is`.

Three containers were used for the measurements and all three were fresh. Their
configurations are the variable: `start-dev` with a bootstrap admin, `start`
with one, and `start-dev` with **none**. Section 1.9 is what the third answered
and section 2.4 is why it is not a case.

### 1.1 The route, and the four segments it reads

```
/resources/{version}/{themeType}/{themeName}/{path...}
```

It resolves to `theme/{themeName}/{themeType}/resources/{path}` inside a jar -
note the first two segments swap - and **it cannot address a sibling of
`resources/`**. That confinement is section 1.6.

The five theme types with files behind them, and the 1234 files, counted out of
the four jars the image ships:

| type | theme | files |
|---|---|---|
| `common` | `keycloak` | 424 |
| `admin` | `keycloak.v2` | 408 |
| `account` | `keycloak.v3` | 223 |
| `login` | `base` | 160 |
| `login` | `keycloak` | 10 |
| `login` | `keycloak.v2` | 6 |
| `welcome` | `keycloak` | 3 |

`email` is a sixth type and has **no** `resources/` directory in any theme, so
every path under it is a 404 indistinguishable from an unknown type's. That is
in this table and in no case, for the reason in 2.3.

### 1.2 The version segment is the only volatile part, and the files do not move

The brief asked whether the files themselves move between containers or
versions. They do not, and this is the measurement the whole unit rests on.

```
                                     start-dev A   start-dev B   start (prod)
resource version                     76sbe         swojn         gb2bn
md5 of login/keycloak.v2/css/styles.css    ed613f09…    ed613f09…     ed613f09…
admin console asset name             main-BbID33M6.js   identical    identical
admin console stylesheet name        main-DmoViYol.css  identical    identical
```

The consoles' asset names are content hashes baked into the image at build
time, so they are a function of the version tag and not of the installation.
**The only part of a theme URL that moves is the version segment**, which is
what `ReplaceThemeResource` already masks and what `Step.CaptureThemeResource`
now reads.

p13-theme-markup.md had already established where that segment comes from - it
is minted with the **database**, not with the container start - and nothing
here contradicts it.

### 1.3 The unknown theme, the unknown type and the unknown file are three answers, not one

The brief asked whether these are three answers or one. They are three, and the
middle one is the finding.

```
/resources/76sbe/login/keycloak.v2/css/styles.css      200  3182  text/css
/resources/76sbe/login/keycloak.v2/css/nosuch.css      404     0  (no Content-Type)
/resources/76sbe/gloak-nosuchtype/keycloak.v2/…        404     0  (no Content-Type)
/resources/76sbe/login/gloak-nosuchtheme/css/styles.css  200  3182  text/css
```

**An unknown theme name is not an error.** It falls back to the type's default
theme and serves its bytes: `gloak-nosuchtheme`, `nosuchtheme` and `zzz` all
answer `css/styles.css` with one md5, `keycloak.v2`'s. The fallback is to the
**default** theme and not to a search of every theme, which
`css/login.css` settles - that file is the v1 `keycloak` theme's, and
`gloak-nosuchtheme/css/login.css` is a 404.

An unknown theme **type** is refused. So one segment of the path is a closed set
and the next is not, and either one measured alone reads as a rule the other
breaks.

**The type is matched case-insensitively.** `LOGIN` and `Login` both answer what
`login` answers. The version segment is not (1.4) and the name has no exact
match to be insensitive about. Three segments of one path, three rules about
case.

### 1.4 The version segment is validated against `[0-9a-z]{5}`, by the route

```
version     answer
76sbe       200  the file
aaaaa       307  → /resources/76sbe/login/keycloak.v2/css/styles.css
12345       307   the same
aaaa1       307   the same
1aaaa       307   the same
00000       307   the same
zzzzz       307   the same
aaaaA       404
Aaaaa       404
ZZZZZ       404
aaaa        404
aaaaaa      404
aa-aa       404
aa_aa       404
aa.aa       404
%61aaaa     400  missingNormalization
```

**This turns `ReplaceThemeResource`'s pattern from an inference into a
measurement.** That regexp was written from thirteen observed values, 65 sampled
characters and a probability of about `1e-15` that the alphabet had upper case
in it. The route decides the same alphabet, and `themes/version/wrong-shape` is
now where it says so.

The 307 itself is worth three sentences.

- **It preserves the path and drops the query.** `?gloak=probe` is not on the
  `Location`.
- **It is `307` and not `301` or `308`** - the one status in the family that
  neither caches nor permits the method to change.
- **It carries no `Cache-Control` and no `Content-Type`**, and four of the five
  security headers.

### 1.5 The redirect fires after the lookup, and not on the fallback path

The grid that places the version check, and its fourth cell is the one no
reader would predict:

```
version   theme name          file            answer
aaaaa     keycloak.v2         css/styles.css  307 → the current version
aaaaa     keycloak.v2         css/nosuch.css  404
aaaaa     gloak-nosuchtheme   css/styles.css  200  the bytes, at the stale version
aaaaa     gloak-nosuchtheme   css/nosuch.css  404
```

So the order is: validate the segment's shape, resolve the theme and the file,
and **only then** compare the version - and the comparison is reached only on
the exact-match path. A reimplementation redirecting on the version alone, which
is the obvious order and the cheap one, would answer 307 on row two and hand the
client a 404 one request later.

Row three is the cell that makes the rule conditional on more than the file
resolving: it resolves there too.

### 1.6 Only `resources/` inside a theme is reachable

A theme directory holds its Freemarker templates, its `theme.properties` and its
message bundles beside `resources/`, and the route serves none of them:

```
/resources/76sbe/login/keycloak.v2/template.ftl                    404
/resources/76sbe/login/keycloak.v2/login.ftl                       404
/resources/76sbe/login/keycloak.v2/theme.properties                404
/resources/76sbe/login/keycloak.v2/messages/messages_en.properties 404
/resources/76sbe/login/keycloak/messages/messages_en.properties    404
/resources/76sbe/login/base/messages/messages_en.properties        404
/resources/76sbe/email/keycloak/html/template.ftl                  404
/resources/76sbe/welcome/keycloak/index.ftl                        404
```

**This is where the chapter's old Reason breaks.** It said "themes **and i18n**
are served as resources, not as an API". The part of i18n that genuinely is a
theme resource - every theme's `messages/messages_*.properties` - is the part
this route refuses to serve. And i18n *is* served as an API, and is already
enumerated: nineteen Implemented cases under `admin/realms-admin/localization-*`
and two Recorded ones under `account/supported-locales`. There is no i18n
surface left over for this chapter to be excused by.

`GET /realms/master/localization/en` is `{"error":"HTTP 404 Not Found"}` - p11's
second 404 body, which is what a path the router knows answers. The localization
resource is on the admin API and nowhere else.

### 1.7 A theme's root directory is a 200 with no bytes

```
/resources/76sbe/login/keycloak.v2/         200  0 bytes  application/octet-stream
/resources/76sbe/login/keycloak.v2/css/     200  0 bytes  application/octet-stream
/resources/76sbe/login/gloak-nosuchtheme/   200  0 bytes  application/octet-stream
/resources/76sbe/login/keycloak.v2          404  0 bytes  (no Content-Type)
/resources/76sbe/gloak-nosuchtype/gloak-x/  404  0 bytes  (no Content-Type)
```

Not a listing, not a 403 and not a 404: the route opens a stream for the
directory entry and gets nothing out of it. The answer follows whether the entry
**exists**, not whether it is a file - which is why the last two rows are 404s
and the third is not.

A reimplementation serving a listing here would leak the theme's file names, and
one serving a 404 would look correct to every reader.

### 1.8 Four of the five security headers, and the `Cache-Control` is a startup mode

Read off a socket:

```
GET /resources/76sbe/login/keycloak.v2/css/styles.css
    200  Cache-Control: no-cache
         Content-Type: text/css
         Referrer-Policy: no-referrer
         Strict-Transport-Security: max-age=31536000; includeSubDomains
         X-Content-Type-Options: nosniff
         X-Robots-Tag: none

GET /realms/master/protocol/openid-connect/auth?client_id=nosuch      (a theme page)
    400  Content-Language: en
         Content-Security-Policy: frame-src 'self'; frame-ancestors 'self'; object-src 'none';
         Content-Type: text/html;charset=utf-8
         Referrer-Policy: no-referrer
         Strict-Transport-Security: max-age=31536000; includeSubDomains
         X-Content-Type-Options: nosniff
         X-Frame-Options: SAMEORIGIN
         X-Robots-Tag: none
```

**No `X-Frame-Options` on anything this route serves** - the 200s, the empty
404, the 307 and the empty-bodied theme root alike - where the page one path
family away carries it, measured on one container seconds apart. That is a
fifth exception to AGENTS.md's bullet and the first that is about **one header
on a whole route** rather than about all five.

And the header that matters most on a static surface is not a property of the
version at all:

| container | command | `Cache-Control` on a theme resource |
|---|---|---|
| A | `start-dev` | `no-cache` |
| B | `start --db=dev-file --http-enabled=true --hostname-strict=false` | `max-age=2592000` |

**One image, two startup modes, two contracts.** The recorder runs `start-dev`,
so `themes/resource/served-file` holds the development value, and it is the only
golden-bearing header in this repository whose value is a startup mode rather
than an image. It is asserted rather than left off precisely because of that:
the next person to change the recorder's command line finds out from a red test
rather than from a re-record diff. F250.

This is F245's shape one variable along. The management port's index page and
health document are a function of an **option set**; this is a function of the
**profile**, which is a coarser thing and reaches a route nobody would think to
check.

### 1.9 No validators, no negotiation, no compression, no ranges

```
request                                         answer
If-None-Match: "gloak-probe"                    200, the full body
If-Modified-Since: Wed, 21 Oct 2099 07:28:00 GMT  200, the full body
Range: bytes=0-9                                200, the full body
Accept-Encoding: gzip                           200, 3182 bytes, no Content-Encoding
Accept: application/json                        200, text/css
```

No `ETag`, no `Last-Modified`, no `Accept-Ranges`, no `Vary`. **A cache-busted
static route with no revalidation of any kind**, and under `start-dev` with
`no-cache` on top of it, so a development server refetches every one of the
admin console's 408 assets on every page load.

`Accept` is ignored entirely, which is worth putting beside the management
port's `/metrics` refusing the very media type it produces. Two static-ish
surfaces in one product, opposite policies.

### 1.10 The media types: nine of eighteen are `application/octet-stream`

One file per extension, over all 1234:

```
.css   text/css              .eot    application/octet-stream
.gif   image/gif             .hbs    application/octet-stream
.html  text/html             .ico    application/octet-stream
.jpg   image/jpeg            .map    application/octet-stream
.js    text/javascript       .otf    application/octet-stream
.json  application/json      .scss   application/octet-stream
.png   image/png             .ttf    application/octet-stream
.svg   image/svg+xml         .woff   application/octet-stream
.txt   text/plain            .woff2  application/octet-stream
```

Two groups say the mapping is a table Keycloak keeps and not a rule:

- **Every font format is `application/octet-stream`** - `.woff2`, `.woff`,
  `.ttf`, `.otf`, `.eot` - where `font/woff2`, `font/woff`, `font/ttf` and
  `font/otf` are registered.
- **`.ico` is too**, where `.gif`, `.jpg`, `.png` and `.svg` beside it are all
  their registered image types. So "an image gets an image type" is a rule with
  exactly one exception and it is the commonest favicon extension on the web.

Two rows are facts about the deployment rather than about the mapping.
**Source maps are served**: `/resources/{version}/admin/keycloak.v2/assets/*.js.map`
answers 200 with 2248 bytes. And `robots.txt` exists under the admin theme, as
`text/plain`.

Only three of the eighteen rows have bodies a golden can hold - `.css`, `.js`
and `.svg`. The rest are in `themeMediaTypes` in `internal/conformance/themes_test.go`,
which is where management-port.md put the metrics dump it could not record
either.

### 1.11 The verb dimension, and what it is not counted as

```
path                                       GET   HEAD  POST/PUT/DELETE/PATCH  OPTIONS
/resources/76sbe/login/keycloak.v2/…css    200   200/0  405                   405
/resources/76sbe/login/keycloak.v2/…nosuch 404   404/0  405                   405
/resources/aaaaa/login/keycloak.v2/…css    307   307/0  405                   405
/resources/76sbe/login/keycloak.v2/        200/0 200/0  405                   200/0
```

Every verb but `GET` and `HEAD` is `{"error":"HTTP 405 Method Not Allowed"}`,
39 bytes, with **none** of the five security headers. That is http/fallback's
family, counted once for the whole API, and it is **not** counted again here -
the SAML cut's decision, and the part of its method that transfers.

`OPTIONS` on the theme root is the one cell outside the pattern: 200 with no
body, four security headers and no `Allow`. It is measured, it is in this table,
and it is in no case, because the case it would be is
`themes/resource/theme-root` sent with a different verb - and the verb dimension
was already collapsed.

### 1.12 The path is normalised here, unlike one port along

```
/resources/76sbe/login//keycloak.v2/css/styles.css        400 missingNormalization
/resources/76sbe/login/keycloak.v2/css/../css/styles.css  400 the same
/resources/76sbe/login/keycloak.v2/%2e%2e/theme.properties 400 the same
/resources/76sbe/login/keycloak.v2/css/styles.css/        200 the file
/resources/76sbe/login/keycloak.v2/css/styles.css?v=1     200 the file
```

The percent-decoding happens before the check. **A trailing slash on a file is
ignored** and so is a query string.

The 400 carries **no security headers at all** and 82 bytes of JSON, which is
`http/fallback/path-not-normalized`'s body byte for byte - so it is not counted
here. The contrast that makes that decision checkable is
`management/health/unnormalised-path`, which **is** counted, because its answer
is a 200: a different behaviour wearing the same request.

The week before, the management port narrowed AGENTS.md's "the normalisation
rule runs ahead of the route table, across the whole server" to one route table.
This route is inside that one, although it serves no JSON and answers none of
the application's error shapes.

### 1.13 The count: seventeen behaviours

```
 18   version-segment shapes, on one container
 19   one file per extension, for the media-type table
 16   theme types, theme names and their case variants
 12   the confinement probes: templates, properties, message bundles
 10   path normalisation, trailing slash, query and directory variants
  9   the version grid of 1.5, with its negative cells
  7   conditional, range, encoding and negotiation requests
 42   the verb sweep: six paths by seven verbs
  6   socket-level header reads
  8   cross-container draws: two more containers, the stable-file question
  4   the welcome page and the two console index pages
 ---
151   request/response pairs issued
```

and **17 catalogued behaviours**, which is this chapter's denominator. It is
pinned as `themesChapterCases` in `internal/conformance/themes_test.go` and
asserted by `TestThemesChapterCountIsThePinnedNumber`, so the number in this
heading is checked rather than trusted.

The arithmetic from cells to cases:

- **The file dimension collapses to one case.** 1234 files say one thing between
  them, measured: the tree is byte-identical across three containers and two
  startup modes. `themes/resource/served-file` is it. Counting them per file
  would report one behaviour 1234 times, which is what the brief refuses and
  what the SAML and management cuts refused before it.
- **The verb dimension collapses to nothing at all**, because what it collapses
  to is already counted: 405 is http/fallback's.
- **The media type does not collapse**, because the mapping is a table with two
  groups of rows nobody would predict. Three of its eighteen rows are cases and
  the other fifteen are in a test, which is the same split
  `management/metrics` made between its 406 and its undrawable dump.
- **Thirteen `themes/resource` cases and four `themes/version` ones.**

## 2. Decisions, each with the alternative rejected

### 2.1 A denominator, and the unit is an answer rather than a file

**Rejected alternative: rewrite the Reason and leave the chapter uncounted.**
This was the brief's other honest outcome and it was live until section 1.2 came
back. The argument for it is real: a theme is hundreds of static files, and a
denominator that counted them would be a number nobody can read.

What decided against it is that **the file dimension was measured collapsing**.
`css/styles.css` is one md5 across two `start-dev` containers with different
databases and a production-mode container, and the two consoles' content-hashed
asset names are identical across all three. So "a file that is there is served
with its bytes" is one fact, not 1234, and the surface underneath it has a
route with answers a request can tell apart. A rewritten reason would have had
to say "there is no unit here", and there is one.

The unit, stated as the deliverable it is:

> **A behaviour of the themes chapter is an answer the resource route gives that
> a request can distinguish without knowing which file it named.**

That is the same shape as every other chapter in `chapters.go` -
`saml/endpoint` is one path with six distinct answers over two verbs - and the
dimension it collapses is the one this surface has, the way SAML collapsed the
fallback family and the management port collapsed the verb.

**The cost of the choice is stated rather than hidden.** One case,
`themes/resource/served-file`, stands for the whole asset tree, and it goes
green the moment Gloak serves one file at the right URL with the right media
type. A reader who takes "themes: 17 documented" to mean "Gloak is seventeen
behaviours from shipping Keycloak's themes" is wrong, and would be equally
wrong about `admin/users`, whose denominator is operations rather than the query
parameters each one honours. A chapter's number has never meant how much work is
left; it means how many distinguishable behaviours have been enumerated. F253 is
the entry that says so where a reader of the report can find it.

**Rejected alternative: count one behaviour per theme type**, so that the seven
(type, name) pairs of 1.1 are seven cases. It is defensible - each pair is a
separately falsifiable claim that the pair exists - but it buys seven numbers
for one fact, and the fact is already in `themes/resource/common-type`, which is
the only pair whose existence a reader would not predict.

### 2.2 The boundary with P13, and the two pages that fall between

**This chapter is the other end of the URLs P13's pages mint.** Thirty-eight
goldens in this repository hold `/resources/{{theme_resource}}/` inside a body -
the error page, the info page, the two device pages, fifteen SAML endpoint
pages, five IdP-initiated ones, the account console - and every one is counted
under the endpoint that rendered it.
`TestThemeResourceAppearsOnlyInTheThemePages` already enumerates that list and
counts the occurrences, seven per page and eight inside an auth flow. **None of
those thirty-eight asks the route a question.** These seventeen cases are the
requests those URLs describe.

The principle, stated so the next case can be filed without re-deriving it:

> A page rendered **from** a theme is counted under the endpoint that serves it.
> The machinery a theme is served **by** is counted under `themes`.

`account/console` is the precedent and it is the one that settles it: the
account console's index page is markup rendered from the `account` theme, and it
is filed under the API whose path it lives on, not here. Its Reason called it
"a theme resource … and the themes chapter is not enumerated", which was loose
in the first clause and is now false in the second; this cut corrects the
sentence and changes nothing else about the case.

`TestThemeResourceCasesAddressTheResourceRoute` is the boundary as a refusal: a
themes case whose path is not under `/resources/` fails.

**Two theme-rendered pages are counted in neither place, and they are named
rather than quietly absorbed.** `GET /` and `GET /admin/{realm}/console/` are
measured in 2.4 and filed as F252.

### 2.3 What was measured and is deliberately not a case

Each of these is a real answer with a real measurement, refused for a stated
reason rather than left out.

| What | Measurement | Why not |
|---|---|---|
| Every verb but GET and HEAD | `{"error":"HTTP 405 Method Not Allowed"}`, 39 bytes, no security headers | http/fallback's, counted once for the whole API |
| Fewer than four segments under `/resources` | `{"error":"Unable to find matching target resource method"}`, 58 bytes | the same |
| `//`, `/../` and `%2e%2e` inside the path | `400 missingNormalization`, 82 bytes | `http/fallback/path-not-normalized` holds those bytes already |
| The `email` theme type | 404 for every path, because no theme has `email/resources` | indistinguishable on the wire from `themes/resource/unknown-type` |
| `OPTIONS` on the theme root | 200, empty, four security headers, no `Allow` | the verb dimension is collapsed; it is in 1.11 |
| `HEAD` on every route shape | the route's status with an empty body | F175's reason: the verifier serves through `httptest.ResponseRecorder`, which does not strip a body for a HEAD where `http.Server` does |
| The 200's `Content-Length` | present and correct on every file | masked package-wide, so a declaration would assert that a response has a length |
| Fifteen of the eighteen media types | 1.10 | RefuseNonTextBody; they are in `themeMediaTypes` |
| The welcome page and the two console index pages | 2.4 | pages, not machinery - 2.2's principle. F252 |

### 2.4 The welcome page, and why a third container did not make it a case

A default `start-dev` **with no bootstrap admin** serves a welcome page at `/`:

```
200  2397 bytes  Content-Type: text/html;charset=utf-8
     Cache-Control: no-cache, must-revalidate, no-transform, no-store
     Content-Security-Policy, Content-Language, and all five security headers
     <title>Welcome to Keycloak</title>
```

With a bootstrap admin - which is what `startKeycloak` sets on every container
it starts - the same path is a `302` to `/admin/`, and `/admin/` is a `302` to
`/admin/{realm}/console/`, which is 3694 bytes of the admin theme's index page
carrying an absolute-URL environment block.

**None of the three is a case here**, for two reasons that stack.

The first is 2.2's principle: all three are pages, and a page is counted where
it is served. The second is that the welcome page in particular is **invisible
to this harness by construction** - the recorder sets `KC_BOOTSTRAP_ADMIN_*` on
every container, so the only container that could record it is one the recorder
will never start. That is F169's shape with the polarity reversed: there the
feature was off by default and the recorder had to switch it on; here the
feature is on by default and the recorder switches it off, to get an admin
token every other fixture needs.

**Rejected alternative: a third container regime that boots without a bootstrap
admin.** It would cost one Keycloak start per case and the only thing on it that
no other container can answer is one page - and that page is P13's kind of
thing, not this chapter's.

One detail is worth carrying forward on its own, because it is a live gap rather
than a scoping decision. The welcome page's asset URL is **relative** -
`resources/swojn/common/keycloak/img/favicon.ico`, with no leading slash - and
`ReplaceThemeResource`'s pattern requires one. So the one page in this product
that spells the segment differently is the one page the mask would not rewrite.
Nothing records that page today, so nothing is broken; F254 is the entry.

### 2.5 `Step.CaptureThemeResource`, and why the four existing captures cannot do it

The chapter's route carries the version in its **path**, the version is minted
with the database, and `Expand` substitutes `{{name}}` into a case's path. So
without a capture no case could ask for a resource at the version the server it
is talking to actually serves, and the chapter would consist of whatever can be
measured with a deliberately stale version.

None of the four existing captures reaches it. `Capture` decodes JSON and a
theme page is HTML; `CaptureHeader` and `CaptureQuery` read a response header
and this is in the body; `CaptureForm` reads the first HTML **form** and this is
in a `<link>` and a `<script src>`.

**Naming the variable `theme_resource` makes the two halves line up.**
`ReplaceCaptured` masks a captured value as `{{name}}` and
`ReplaceThemeResource` already rewrites `/resources/<version>/` to
`/resources/{{theme_resource}}/` unconditionally on both sides. Under that name
the two produce identical bytes, which matters because `recordedHeaders` runs
`ReplaceCaptured` over every header value and **not** `ReplaceThemeResource` -
so the 307's `Location`, which carries the live version, comes out spelled
exactly as a body would. `TestCaptureThemeResourceAgreesWithTheUnconditionalPass`
applies both masks to one input and compares, rather than checking each against
a string somebody typed.

**Rejected alternative: add `ReplaceThemeResource` to `recordedHeaders`.** It
would fix the `Location` and nothing else, and the request path would still need
a capture - so it is the same work plus a second mechanism. The capture is
strictly more useful and is needed either way.

**Rejected alternative: build the chapter out of stale-version requests only**,
so that no capture is needed at all. `/resources/aaaaa/login/gloak-nosuchtheme/css/styles.css`
serves the real bytes with a literal path (1.5, row three), so "a file is
served" could have been witnessed without any harness change. It was rejected
because that witness conflates two behaviours in the one case that ought to
carry neither: a chapter whose primary fact can only be stated through an
exception to its own rule has not been enumerated, it has been worked around.

**Rejected alternative: a general `CapturePattern` taking a regexp.** It puts a
pattern in the catalogue where the catalogue's own well-formedness test cannot
judge it, and the one pattern it would ever hold is the one
`themeResourcePattern` already is. The field is a variable name rather than a
map, unlike its four neighbours, because there is exactly one thing to take and
a map would have to invent a vocabulary whose only member is the field's own
name.

The pattern grew a submatch group rather than gaining a sibling, so the mask and
the capture cannot drift: two regexps agreeing today is not a guarantee, and the
first sign of disagreement would be a golden whose `Location` churns on every
recording while its body does not.

### 2.6 The report's unenumerated branch lost its witness, and was not deleted

Enumerating this chapter made `TestCoverageWritesAReportWhenAsked` fail, with a
message its own author left for exactly this moment:

```
no unenumerated chapter in the report, so this half of the format has
no consumer; drop the Enumerated field rather than leaving a branch nothing takes
```

**That advice was not followed**, and the disagreement is recorded rather than
hidden. `Chapter`'s own doc comment says the field exists so that a chapter
nobody has counted says so rather than being quietly left out of the total, and
the next chapter added to this project arrives uncounted like every one of the
five before it. Deleting the only way to say "not counted" would leave that
chapter's author choosing between a wrong number and silence, and silence
inflates the percentage - the disease the field was built for.

What the failure did reveal is that the branch had never had a test. Its only
witness was "some chapter happens to be uncounted today", which passed for a
year because the catalogue was incomplete and went red the moment it was
finished. The row builder is now `chapterRow` over an explicit `chapterTally`,
and `TestChapterRowLeavesAnUnenumeratedChapterOutOfTheTotals` drives it with a
chapter it constructs - with the enumerated arm beside it as the control,
without which "contributes zero" is satisfied by a function that returns zero
for everything. F251.

### 2.7 Nothing is Implemented, and that is a measurement rather than a shrug

Gloak has no route under `/resources` at all - no `http.FileServer`, no
`go:embed` of any asset, no handler matching the prefix. It mints a version of
its own, in `internal/httpx`, and writes it into its pages seven times each; the
other end of every one of those URLs is its realm-tree 404.

So every case here is `Recorded`, which is the status that means measured and
deliberately not served. The list clears itself: when somebody serves the route,
the case matches and the suite says so.

## 3. Refusals, each with the measurement behind it

| What | Measurement | Status |
|---|---|---|
| A themes case must report under a declared `themes/` chapter, and every declared one must hold a case | A themes measurement filed under `oidc/authorization` is counted as that chapter's behaviour; a declared chapter with no case is a row with a denominator of zero | `TestThemeCasesReportUnderAThemesChapter` |
| A themes case's path must be under `/resources/` | 2.2's principle; a page is counted where it is served | `TestThemeResourceCasesAddressTheResourceRoute` |
| Every themes case with a golden declares `X-Frame-Options` absent | Not one response on this route carries it, read at socket level; the theme page one family away carries it | `TestThemeCasesDeclareXFrameOptionsAbsent` |
| Every themes case names the `theme-page` fixture | Without it a case cannot expand `{{theme_resource}}` into its path, and a 307's `Location` churns on every recording | `TestThemeCasesNameTheThemePageFixture` |
| A case asserting `Content-Type` must name an extension the measured table knows | Otherwise the table and the goldens are two unconnected lists of the same thing | `TestThemeContentTypesAreTheMeasuredMapping` |
| `.woff2` and the other binary media types may not be `Recorded` | The bodies are not UTF-8 - F161 | `Pending`, 1.10 |
| The welcome page is not a case | The recorder sets a bootstrap admin on every container it starts, so the page is unreachable from this harness | not a case; F252 |
| The 405, the short-path 404 and the normalisation 400 are not cases | byte-identical to http/fallback's | not cases; 2.3 |

## 4. The mutation pass

Every mutation was applied to a committed tree, the **build** run before the
tests so a compile error could not be read as a failing assertion, the named
test run, its **failure message** read rather than its name, and the revert
verified against a dirty check scoped to `internal/conformance`. The revert is
on a `trap ... EXIT`, so an interrupted run leaves no mutation behind.

<!-- MUTATION TABLE -->

## 5. Parity

<!-- PARITY -->

## 6. What belongs in AGENTS.md

Phrased as it would be folded.

### For the security-headers bullet, as a fifth exception

> - **the theme resource route carries four of the five**, and it is the first
>   exception on this list that is about **one** header rather than about all of
>   them. `GET /resources/{version}/{themeType}/{themeName}/{path}` answers with
>   `Referrer-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options` and
>   `X-Robots-Tag` and **no `X-Frame-Options`**, on its 200s, on its empty 404,
>   on its 307 and on the empty-bodied theme root alike, read off a socket. The
>   theme **page** one path family away carries all five plus
>   `Content-Security-Policy` and `Content-Language`, measured on one container
>   seconds apart, so the difference is the route and not the server. Sixteen
>   goldens declare it absent and
>   `TestThemeCasesDeclareXFrameOptionsAbsent` requires the next one to.

### A new bullet, for the theme resource route

> - **The theme resource route's `Cache-Control` is a function of the startup
>   mode, not of the version.** `no-cache` under `start-dev` and
>   `max-age=2592000` under `start`, one image, measured on two containers on
>   2026-09-15. It is the only golden-bearing header in this repository whose
>   value is a profile rather than an image, and `internal/conformance`'s
>   recorder runs `start-dev`, so the committed value is the development one.
>   See F250. The route has **no `ETag`, no `Last-Modified`, no `Accept-Ranges`
>   and no `Vary`** either: `If-None-Match` and `If-Modified-Since` both answer
>   the full body with a 200, `Accept-Encoding: gzip` answers uncompressed, and
>   `Accept` is ignored - so a development server refetches all 408 admin
>   console assets on every page load.
> - **An unknown theme *name* is not an error and an unknown theme *type* is.**
>   `/resources/{version}/login/anything-at-all/css/styles.css` answers
>   `keycloak.v2`'s bytes, one md5 over three spellings, because the name falls
>   back to the type's **default** theme; `css/login.css` under the same name is
>   a 404, which is what says the fallback is to the default rather than a search
>   of every theme. An unknown **type** is a 404. And the type is matched
>   **case-insensitively** where the version segment is not - three segments of
>   one path, three rules about case.
> - **A stale version segment is a 307, but only after the lookup succeeds and
>   only on the exact-match path.** `/resources/aaaaa/login/keycloak.v2/css/styles.css`
>   redirects to the current version with the path preserved and the query
>   dropped; the same request for a file that does not exist is the 404, and the
>   same request naming a theme that does not exist serves the bytes at the
>   stale version without redirecting. The segment itself is validated against
>   **exactly `[0-9a-z]{5}`** - `aaaa`, `aaaaaa`, `AAAAA` and `aa-aa` are all
>   404 where `aaaaa`, `12345` and `00000` are 307 - which is the route deciding
>   the alphabet `ReplaceThemeResource`'s pattern was inferred to have.
> - **Only `resources/` inside a theme is reachable.** `template.ftl`,
>   `theme.properties` and every `messages/messages_*.properties` are 404 on
>   this route, so the message bundles - the part of i18n that genuinely is a
>   theme resource - are the part it refuses to serve. A theme's root directory
>   is a **200 with zero bytes and `application/octet-stream`**, not a listing
>   and not a 404, and so is any directory under it; the same path without the
>   trailing slash is the 404. The answer follows whether the entry exists, not
>   whether it is a file.
> - **Nine of the eighteen media types this route serves are
>   `application/octet-stream`.** Every font format is - `.woff2`, `.woff`,
>   `.ttf`, `.otf`, `.eot` - and so is `.ico`, where `.gif`, `.jpg`, `.png` and
>   `.svg` beside it are all their registered types. Source maps under
>   `/resources/{version}/admin/keycloak.v2/assets/` are served, and so is a
>   `robots.txt` under the same theme. The table is `themeMediaTypes` in
>   `internal/conformance/themes_test.go`.

### For the not-found list, or beside it

> **A fourth 404 body, and it is the emptiest one measured.** The theme resource
> route answers an unknown file, and an unknown theme type, with **zero bytes,
> no `Content-Type` at all** and four of the five security headers. The three
> already listed are the Admin API's `Unable to find matching target resource
> method` with none of the five, `HTTP 404 Not Found` with all five, and the
> management port's 53 bytes of HTML with none. This one shares its status code
> with all three and its shape with none. `themes/resource/unknown-file` is the
> golden.

### For the normalisation bullet, as the other end of the management narrowing

> The management port narrowed this rule to one route table on 2026-09-15. The
> theme resource route is **inside** that one: `//`, `/../` and `%2e%2e` in a
> resource path all answer `400 missingNormalization` with none of the five
> security headers, although the route serves no JSON and answers none of the
> application's error shapes. A trailing slash on a file and a query string are
> both ignored. So the boundary is the JAX-RS application and not the media type
> or the handler style.

### For the build section

> **Three enumeration discriminators were published here and a fourth was
> needed.** p11's pair of 404 bodies needs two distinct ones and this route has
> one; account-api's "at least one verb answers outside the fallback family"
> cannot separate a file that exists from one that does not, since both are
> GET-only; the management port's "a route answers its own 200 on all seven
> verbs" is false here, where GET and HEAD answer and the other five are 405.
> The fourth is **a request naming a resource that resolves answers 200 with its
> bytes and a media type; one that does not answers 404 with no body and no
> `Content-Type`** - validated in both directions on one container before it was
> used, which is the only part any of the four has in common and the only part
> that transfers.
>
> **And a fourth dimension has now been collapsed.** SAML collapsed the fallback
> family, account-api collapsed `OPTIONS`, the management port collapsed the
> verb, and themes collapsed **the file**: 1234 servable assets, measured
> byte-identical across three containers and two startup modes, counted as one
> behaviour. The test is always the same - if the dimension were counted, how
> many times would one fact be reported?

### For the masks section

> `ReplaceThemeResource`'s `[0-9a-z]{5}` is no longer an inference from thirteen
> sampled values. The route validates the segment against exactly that, measured
> as a sixteen-row grid, so the mask and the server agree by measurement rather
> than by luck. The pattern now carries a submatch group for
> `Step.CaptureThemeResource`, deliberately one pattern rather than two: the
> mask and the capture must agree on what a version is, and the first sign of
> drift would be a golden whose `Location` churns while its body does not.

## 7. Follow-ups, numbered from F250

F171-F249 are taken.

### F250 - a golden whose header is a function of the startup profile

`themes/resource/served-file` and the five other 200s in this chapter hold
`Cache-Control: no-cache`, which is what `start-dev` serves. A production
Keycloak serves `max-age=2592000` from the same image, measured. So six goldens
pin a **profile** rather than a version.

It is F245's shape one variable coarser. That entry is about an **option set** -
the management port's index page lists the endpoints that are switched on - and
the fix it proposed, a line in the golden naming the recorder's configuration,
would cover this too and would still be a change to `FormatGolden` and
`ParseGolden` that all 1136 files take.

What is different here, and why this gets its own number rather than a line on
F245, is that the management port's dependency is **visible**: nothing on port
9000 exists without the option, so a reader who wonders knows to ask. A
`Cache-Control` header on a static file looks like a property of the product.
The mitigation shipped is smaller than a fix: the header is asserted, so
changing the recorder's command line is a red test rather than a re-record diff.

### F251 - the report's unenumerated branch had never had a test

Enumerating this chapter took away the branch's only witness, which was that
some chapter happened to be uncounted. `chapterRow` and
`TestChapterRowLeavesAnUnenumeratedChapterOutOfTheTotals` give it one that does
not depend on the catalogue being unfinished.

The entry exists for the decision rather than the fix. The failing assertion's
own message advised deleting `Chapter.Enumerated` once nothing took the branch,
and that advice was **not** followed, for the reason in 2.6: the next chapter
added to this project arrives uncounted, and deleting the only way to say so
leaves its author choosing between a wrong number and silence.

Whoever disagrees should read F247 first. It already notes that a chapter can be
set back to `Enumerated: false` and no gate says anything - so the field is
currently a promise with no enforcement behind it, and "delete it" and "gate it"
are the two coherent answers. This cut took neither and said why.

### F252 - two theme-rendered pages are counted in no chapter

`GET /` and `GET /admin/{realm}/console/` are rendered from the `welcome` and
`admin` themes and appear in no chapter's denominator. Measured in 2.4: `/` is a
302 to `/admin/` with a bootstrap admin and a 2397-byte welcome page without
one; `/admin/` is a 302 to `/admin/{realm}/console/`; that is 3694 bytes of
markup with an absolute-URL environment block, which `ReplaceIssuer` already
handles.

They are not in `themes` because 2.2's principle files a page where it is
served, and they are not under `admin/` because every chapter there is an
OpenAPI tag and the console is not an operation. So the honest statement is that
they need a chapter of their own - `admin/console` beside `account/console` is
the shape the precedent suggests - and that is a decision about the admin
sub-project rather than about themes.

The welcome page has a second obstacle on top of the first, and it is the
harness's: the recorder sets `KC_BOOTSTRAP_ADMIN_*` on every container, so the
only container that could record it is one the recorder will never start.
Whoever takes this decides whether one page is worth a third container regime.

### F253 - a chapter's number does not mean how much work is left, and nothing says so

`themes/resource` reports 13 documented behaviours and one of them,
`served-file`, stands for 1234 files. `admin/users` reports its tag's operation
count and one operation stands for every query parameter it honours. Both are
correct under `Chapter`'s definition and both invite the same misreading, which
is that the denominator estimates remaining work.

There is no dishonesty in either number and no fix is proposed to either. What
is missing is a sentence where a reader of the report meets it - in
`internal/parity/render.go`'s output, which is what lands on a pull request -
saying what the denominator counts and what it does not. Filed as a
documentation change with the place named, because the alternative is that every
chapter's handover document argues the point again, which is how this one spent
half of section 2.1.

### F254 - the one page that spells the resource segment relatively is the one the mask would miss

The welcome page's asset URL is `resources/{version}/common/keycloak/img/favicon.ico`,
with **no leading slash**, where every other page in this product writes
`/resources/...`. `ReplaceThemeResource`'s pattern requires the leading slash, so
that page's version would survive into a golden and churn on every recording.

Nothing records the welcome page today, so nothing is broken - which is exactly
the shape p13-theme-markup.md warned about when it found "per container start"
copied through five documents: a claim nothing depends on is a claim nothing
falsifies. Filed with the measurement so that whoever closes F252 finds it
before the recording rather than after.

Loosening the pattern is **not** the obvious fix and should not be done without
re-running `TestThemeResourceAppearsOnlyInTheThemePages`. That test is what
bounds the pass's over-reach, and dropping the leading slash widens it from
"`/resources/` followed by five characters" to "the word resources followed by
five characters", which would fire inside ordinary prose.

### F113 - unchanged, and not reached

No body on this route carries a per-request value. Six requests to one container
and one to a second gave one md5 for `css/styles.css`, and the 307's `Location`
carries the installation's version rather than the request's - which is what the
capture masks. The rule was not needed here and no mask was built to reach it.

### F161 - applied to fifteen of eighteen media types

`RefuseNonTextBody` is why `themes/resource/binary-media-type` is `Pending` and
why the media-type table lives in a test. The three recordable rows are `.css`,
`.js` and `.svg`; the other fifteen are `.png`, `.ico`, `.woff2` and their
kind, and a golden over any of them would assert nothing.

### F169 - the model, with the polarity reversed

Its discipline is measuring the option before believing the symptom, and this
cut needed it twice. `Cache-Control: no-cache` on a cache-busted URL looks like
a Keycloak decision and is a `start-dev` artefact (1.8). The absence of a
welcome page looks like a Keycloak decision and is an artefact of the bootstrap
admin the recorder sets (2.4). Both were caught by starting a second container
with the variable moved, which is the whole of F169's method.

### F175 - unchanged

`HEAD` answers every route shape here with the route's status and an empty body,
and cannot be cased for the reason that entry gives: the verifier serves through
`httptest.ResponseRecorder`, which does not strip a body for a HEAD where
`http.Server` does.

### F177 / F181 - carrying the weight again

Every case in this chapter is `Recorded`, so `diff`'s "these differ" verdict is
satisfied by Gloak having no `/resources` route at all, and
`AssertAbsentHeaders` through `diff` asserts nothing.
`TestAssertAbsentHeadersAgreeWithTheGolden` is what makes the sixteen
`X-Frame-Options` declarations mean something.

## 8. What is left

- **Nothing is served.** Gloak has no route under `/resources` at all. Serving
  one means shipping or generating Keycloak's asset tree, which is a question
  about vendoring rather than about this harness.
- **The media-type table is in a test and not in cases**, fifteen rows of it,
  barred by F161 rather than unmeasured.
- **Two theme-rendered pages have no chapter**, F252, and one of them has no
  container regime either.
- **Six goldens hold a startup profile**, F250, mitigated by being asserted
  rather than fixed.
- **The three containers of section 1 are gone.** Anybody re-measuring starts
  fresh, which is what account-api.md's rule asks for: a container written to by
  an unknown sequence of probes is not a clean measurement surface.

### Containers

<!-- CONTAINERS -->
