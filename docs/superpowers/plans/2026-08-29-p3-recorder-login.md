# P3's first cut: the recorder learns to log in

Date: 2026-08-29
Spec: `docs/superpowers/specs/2026-08-29-p3-browser-code-flow-design.md`

The roadmap's argument for putting P2 first was that **P3's fixtures are the
hardest machinery in the harness**. This cut builds exactly that machinery and
nothing else, and it ends with every P3 case `Recorded` - the measured contract
parked in the repository before any code exists to satisfy it, which is the
shape §3.3 and §3.4 of the roadmap describe.

**It moves parity by zero, on purpose.** `Recorded` means measured and not
served; the meter counts served. The next cut opens with byte-exact goldens as
its brief and is where the number moves.

Later cuts get their own plans when this one lands, for the reason the roadmap
gives: a plan written before anyone reaches the work has the appearance of
accuracy without the measurement behind it.

## Files

| File | Why |
|---|---|
| `go.mod`, `go.sum` | `golang.org/x/net/html`, the form parser |
| `internal/conformance/fixture.go` | the cookie jar, `CaptureForm`, `CaptureQuery`, the browser fixtures |
| `internal/conformance/fixture_test.go` | one test per mechanism |
| `internal/conformance/normalize.go` | the issuer inside a percent-encoded query |
| `internal/conformance/normalize_test.go` | |
| `internal/conformance/golden.go` | header values get the same pass |
| `internal/conformance/catalog_oidc_pending.go` | the cases, re-pointed at clients that can serve them |
| `internal/conformance/testdata/golden/oidc/...` | recorded |
| `AGENTS.md`, the roadmap, the two P3 specs | |

## Task 1: the measurement that decides everything else

**Done, commit `a6d93f1`.** It is Task 1 because its answer decides whether the
cases can be recorded at all, and the answer was no: `security-admin-console`
pins `pkce.code.challenge.method=S256` and registers a host-relative redirect
pattern, so nine of the eleven `oidc/authorization` cases measure one
"Missing parameter: code_challenge_method" redirect and `pkce-plain` cannot
succeed on it at any port.

Had this been taken after the fixture was built, the fixture would have been
built against a client that cannot drive it, and the failure would have looked
like a bug in the fixture.

Recorded in the "The browser authorization code flow" section of
`2026-08-18-keycloak-26.7.1-observed.md`.

Commit: `docs(oidc): measure the browser authorization code flow`

## Task 2: a cookie jar inside `RunFixture`

A login is a session and every step today is an independent request.

The jar goes in `RunFixture`, **not** on the recorder's `http.Client`. The
recorder would get one free from `http.Client.Jar`; the verifier calls
`h.ServeHTTP` into an `httptest.ResponseRecorder` and would get nothing. Two
sides obtaining their responses differently is the one thing AGENTS.md says
this suite cannot afford, so the jar goes in the single place both sides run
through.

`net/http/cookiejar` needs a `*url.URL` per call and a public-suffix list to
behave; the fixtures address one host and never test cookie scoping. A plain
`map[string]string` of name to value, resent on every step, is what the flow
needs. Write down that this is deliberately not a cookie jar's semantics: no
`Path`, no `Domain`, no `Max-Age`. A cookie cleared with `Max-Age=0` and an
empty value is still stored and resent as an empty value, and Keycloak accepts
that, because it is what a browser sends for a cookie it has not yet expired.

Verify: a fixture test whose two steps run against an `httptest` handler that
sets a cookie on the first and asserts it on the second.

Mutation: drop the `Set-Cookie` read. The named test must fail.

Commit: `feat(conformance): thread cookies through a fixture's steps`

## Task 3: `CaptureForm`, and no regular expression

`golang.org/x/net/html` finds the first `<form>`, reads its `action`, and reads
each `<input>`'s `name` and `value`. It is a new direct dependency and it is
the smallest honest one: a regular expression over HTML is the classic mistake
and the 2026-08-22 design already named the alternative.

```go
CaptureForm map[string]string // variable -> "action" or "input:<name>"
```

`action` is captured **relative to the base URL**, so it drops straight into a
following step's `Path`. `buildRequest` appends `?` + `Query` only when `Query`
is non-empty, so an action carrying its own query string works as a `Path` with
no change there - and the plan says so rather than leaving the next reader to
find out by breaking it.

The measurement says the action is the only thing the login needs:
`session_code`, `execution`, `client_id`, `tab_id` and `client_data` are all
in its query, and the form's three inputs are `username`, `password` and a
value-less hidden `credentialId`. `input:` is supported anyway, because the
next flow with a valued hidden field should not need a second mechanism, and
its test uses a form that has one.

An absent form, or an absent named input, is an error and not an empty string -
the same rule `captureFrom` and `captureFromHeader` already state, for the same
reason.

Verify: a test per capture, plus one for each failure.

Mutation: make the parser return the *last* form instead of the first. The
first-form test must fail.

Commit: `feat(conformance): capture a login form's action from HTML`

## Task 4: `CaptureQuery`

`captureFromHeader` returns an absolute URL's last path segment, which is what a
201's `Location` carries and is useless for a redirect carrying `code` in its
query.

```go
CaptureQuery map[string]string // variable -> query parameter of Location
```

Reads the `Location` header's **query**. The fragment is deliberately not
supported: `response-mode-fragment` needs the redirect recorded, not a capture
out of it, and supporting a thing no case uses is a guess about the next cut.

Verify: a capture, a missing parameter, a missing header.

Mutation: return the first query parameter regardless of name. The
named-parameter test must fail.

Commit: `feat(conformance): capture a query parameter from a redirect`

## Task 5: the issuer inside a percent-encoded query

`recordedHeaders` runs `ReplaceIssuer` over each header value, and the
authorization redirect's `Location` carries
`iss=http%3A%2F%2Flocalhost%3A8083%2Frealms%2Fmaster`. The raw base URL is not
in that string, so the substitution misses it and a golden recorded on one port
would differ from the handler's on that parameter alone.

Two ways out and they are not equivalent. Masking the whole header with
`VolatileHeaders` also throws away the query key order, the `error` code and
the `error_description` - which for the seven error cases **is** the contract.
So: `ReplaceIssuer` also replaces the percent-encoded spelling.

It replaces the raw form first. Doing it the other way round would leave the
encoded occurrence untouched inside a value that also holds a raw one.

Verify: a test with both spellings in one string, and one asserting the raw
substitution still works alone.

Mutation: drop the encoded replacement. The mixed test must fail.

Commit: `fix(conformance): normalise a percent-encoded issuer in a header`

## Task 6: the browser fixtures, and the cases that can finally be recorded

Three clients, from §3 of the spec:

| Fixture client | Configuration |
|---|---|
| `gloak-probe-browser` | public, standard flow, `redirectUris: ["http://localhost:9999/callback"]`, no PKCE policy |
| `gloak-probe-browser-plain` | as above, `pkce.code.challenge.method=plain` |
| `gloak-probe-browser-conf` | confidential, a known secret |

`http://localhost:9999/callback` never has to resolve: `TestRecordGoldens` sets
`CheckRedirect` to `ErrUseLastResponse` and never follows it.

`browserLoginFixture` is the four steps: admin token, create the client,
`GET /auth`, `POST` the form's action. Cases that measure the redirect stop
there; `oidc/token/*` add a `CaptureQuery` for `code` and exchange it.

Then the eleven `oidc/authorization` cases get their `client_id` and
`redirect_uri` changed, `pkce-plain` gets the plain-pinned client, and the
three `oidc/token` cases and `oidc/logout/rp-initiated-with-id-token-hint` get
fixtures. `oidc/logout/rp-initiated-without-id-token-hint` moves to `Pending`
against a theme page with the measurement as its reason: it does not redirect.

**A code is spent by a failed exchange** (§5 of the spec), so
`pkce-verifier-mismatch` and `replayed-code` each need their own login. One
fixture per case, which is the uniqueness rule `clientFixture` and
`userFixture` already carry.

Verify: `CGO_ENABLED=0 go test ./internal/conformance/`, both vets.

Commit: `test(conformance): fixtures that drive a browser login`

## Task 7: record, and read the diff

`make record` against the container, then flip every case whose golden landed
to `Recorded`.

**Read the diff before committing.** An unreviewed re-record pins a regression
as the contract, and this cut re-records nothing else - any golden outside
`oidc/authorization`, `oidc/token` and `oidc/logout` that moves is a bug in
Task 2's jar leaking cookies between cases, not a Keycloak change.

`Recorded` is checked in two places that do not follow from each other: a
`Recorded` case with no golden fails, and a `Recorded` case that **matches**
fails with "promote this to Implemented". The second is the one that matters
here - it says the endpoint really is unbuilt.

Three cases stay `Pending`: the two 400 theme pages and
`oidc/logout/invalid-post-logout-redirect-uri`, all P13, plus
`implicit-flow` which is out of scope, plus the logout consent page Task 6
moved.

Then `make conformance` and state the number in the commit body. **It will not
move**, and that is the check that the cases went in as `Recorded` and not as
`Implemented`.

Commit: `test(conformance): record the browser code flow`

## Task 8: the documents

`AGENTS.md`: the five behaviours in §5 of the spec join the list of things that
must not be tidied up, and the `Content-Security-Policy` line is corrected -
the browser flow carries it on six responses of seven, so revocation is not
the only one.

The roadmap: P3's first cut named, with the parity number unchanged and the
reason.

`README.md` if it carries a parity number.

Commit: `docs(p3): record the browser flow's first cut`

## What this plan deliberately does not do

**No production code.** `GET /auth` is not registered, no login page is served,
no code is issued. Serving the validation half alone would mean answering
something for a request that passes validation, and that something would be a
stub - which is the half-implementation this cut exists to avoid.

**No `Implemented` case, so no parity movement.** Stated in the PR rather than
left to be noticed.

**No fragment capture, no `form_post` parsing.** Neither is needed by a case in
this cut and both are guesses about the next one.

**No cookie `Path`, `Domain` or expiry semantics.** Task 2 says why: the
fixtures address one host and no case tests scoping.
