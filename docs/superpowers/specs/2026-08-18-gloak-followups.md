# Gloak: tracked follow-ups after the foundation slice

Date: 2026-08-18
Source: the final whole-branch review of `feat/foundation`

Six findings from that review were fixed in the branch. These were deliberately
not fixed, because each needs a design decision rather than a local edit. They are
recorded here so the next plan starts from them rather than rediscovering them.

Each was reproduced, not theorised.

**Status, 2026-08-23.** P2's first cut closed F15 and the
`service-account-<clientId>` half of F14's neighbour, and opened F16 through
F19. F18 was then closed the same day and opened F20 through F23. Closed
entries keep their text: the reasoning that turned out to be wrong is worth
more than a tidy list.

**Status, 2026-08-25.** The roles half of P2's second cut opened F24: a
measured divergence between Gloak and Keycloak, left unfixed on purpose and
scoped to its own task. Its final whole-branch review then **closed F24** -
the divergence turned out to be a privilege-escalation path, and its recorded
fix location turned out to be wrong - and opened F25 through F29. **F28 is the
one to read first**: it is a second escalation path, measured on the same day,
and left open because the naive fix is falsified by the measurement.

**Status, 2026-08-26.** The role-mappings cut opened F30 and made F28
reachable: Task 3 shipped `POST`/`DELETE /users/{id}/role-mappings/realm`, so
the escalation F28 describes is no longer theoretical. F28 gained the write-side
measurement Task 7 needs; it is still open. Task 5 then shipped the client pair
and measured it filtered as well, taking F28 from four measured surfaces to
five - four places in the code, since the two write pairs share one helper.

**Status, 2026-08-27.** Task 7 **closed F28** on all three call sites - the four
surfaces above, with the write pair sharing `eachMapping` and the two
`available` reads sharing `grantable`. The rule
it needed - the one this list has been calling "not in this repository" since
2026-08-25 - was derived by sweeping 22 admin roles against 27 children on four
different surfaces, and the read filter and the write check turned out to be one
predicate rather than two that resemble each other. Writing it opened **F32**:
Gloak keys the caller's roles on the name alone, so an ordinary client role
called `manage-realm` is indistinguishable from the real one. That is older and
wider than F28 - it is the whole guard layer - and measured diverging from
Keycloak on both sides.

**Status, 2026-08-29.** Four cuts ran in parallel, each in its own worktree
against its own reference container, and each was forbidden this file so that
the entries below could be written once rather than three times in conflict.
They **closed F38 and F40**, corrected the design inside **F39**, and opened
**F41 through F57**.

Two of those are worth reading before the rest. **F40** was not fixed where it
was found: the entry proposed marking one case `PristineRealm`, and the
measurement showed that marking is what cannot carry the property - the pristine
group pollutes itself, and `admin/groups/count` is the same defect already
realised and already papered over with a mask. The fix moved into the recorder.
And **F41 through F44** are the first entries in this list that are about the CI
workflow rather than about Keycloak; F42 is the one to read, because the finding
as filed was wrong in a way that would have made the fix a no-op, and the hazard
underneath it ran the other way.

**Status, 2026-08-30.** Three more cuts ran in parallel the next day, under the
same rule, and **closed F46, F47, F48, F49 and F53** and opened **F58 through
F70**. The pattern of the previous day repeated exactly once more: the most
valuable thing each stream produced was a line in `AGENTS.md` its measurements
refuted, and there were four.

Two are worth reading before the rest. **F49** was filed as one defect - a
client created through the Admin API gets no client scopes - and turned out to
be six: the scopes could not be fixed without also fixing `standardFlowEnabled`,
`fullScopeAllowed`, `protocol`, `nodeReRegistrationTimeout` and `name`, because
with no `protocol` default the scope-inheritance filter matches nothing. And
**F53** was closed by a sweep that found three cases, then reopened in spirit
three commits later when the next cut produced a fourth instance of the same
problem - which is recorded at F53 rather than hidden, because a follow-up that
closes and immediately recurs is saying something about the check, not about the
cases.

**Status, 2026-08-30 (second fold).** Three more cuts - the browser login, the
protocol mappers and the recorder's own debt - **closed F49's neighbours F58,
F59, F63's prerequisite, F69 and F70**, and opened **F71 through F80**. Parity
reached 205 of 499, and `oidc/authorization`'s `recorded` column reached **zero**:
the chapter no longer holds a case waiting on an endpoint nobody built.

The pattern held for a third day and produced its sharpest example. Two cuts
were green on their own and **failed together**: the pollution guard's rule
"one body names one object" was applied per *body*, and a `POST /clients`
carrying `protocolMappers` creates a client and two mappers. The nested mappers
were never recorded, which lost them from the guard and made it report a false
positive against the very case whose own fixture had made them. Neither author
could have seen it; it is filed at F71 with the fix.

Two sentences in the observed document were **still false on 2026-08-30**,
having been corrected in `AGENTS.md` on 2026-08-29 and nowhere else - the
hintless logout and `post.logout.redirect.uris`. They were re-measured
independently rather than copied across, and the observed document now carries
both corrections with the reason. That a correction can land in one of two
documents and sit unnoticed for a day is worth more attention than either
sentence.

**Status, 2026-08-30 (third fold).** Three more cuts closed **F72, F76 and
F80** and opened **F84 through F91**, taking parity to 242 of 500. **Gloak can
complete a browser OAuth flow for the first time.**

Two entries in this very list were **wrong when the cut arrived to close them**,
which is worth more than either fix. **F80** named a model that fits 13 of 14
vectors; the fourteenth proves one table cannot be right, and the answer is two.
**F78** was wrong three ways at once - server-wide rather than realm-wide, five
routes rather than three, and a message rule that was an artefact of the probes.
Both were written by cuts that had measured carefully and generalised one step
past their evidence.

The sharpest finding is about tests rather than about Keycloak. F80's fourteen
vectors **do not pin the rounding rule**: the mutation that breaks it passes all
fourteen and fails only the boundary probes. A cut that added the vectors and
stopped would have shipped an unpinned rule that looked measured. It was found
by asking what the vectors did *not* pin, which is not a question a passing
suite ever prompts.

**Status, 2026-08-30 (fourth fold).** Three cuts and a gate fix took parity to
**263 of 516**, closed **F84, F89 and F90**, corrected **F78** for the second
time, and opened **F92 through F102**.

Three things are worth reading before the list.

**F84 was filed as one defect and shipped as six**, which is exactly what
happened to F49 a week earlier. The pattern is now established well enough to
state: a field the admin API ignores is rarely alone, because whatever review
missed it missed its neighbours too.

**F78's *corrected* entry was wrong a fourth way.** It had already been rewritten
once by the cut that found it wrong; the cut that went to close it found that
"the location decides, not the route" is half right - the location decides on
one route and decides nothing on the other - and that a fifth route answers 400
rather than 409 at all.

**Nothing in the gate checked `gofmt`.** Three files reached `main` unformatted
and were found by somebody reading a diff. `vet` is a correctness tool and says
nothing about layout, so no step existed that could have caught it. Fixed in
both the Makefile and the workflow, and verified failing before verified
passing.

**Status, 2026-08-30 (fifth fold).** Three cuts took parity to **285 of 523**,
closed **F65, F77 and F101** - so the browser flow is complete, including a
device login a user can finish - and opened **F103 through F112**.

The round's most useful result is not a feature. **116 of the catalogue's 293
masks were doing nothing**, and they were found by asking a question nobody had
asked: which of these change no byte? Forty sat on arrays of one element or
none. Sixty-six masked a value `ReplaceCaptured` had already rewritten. Three
contradicted a measurement the case beside them asserts. Every one of them read
as "this varies", which is a claim about Keycloak the next reader believes and
does not go behind - and the proof that they were inert is that removing all
fifty inert ones moved **zero** goldens.

Two documents were wrong in ways the repository itself had already contradicted.
**AGENTS.md said the `;charset=UTF-8` split was "only on this one endpoint"**,
and 438 committed goldens had said otherwise since P2 - as had a doc comment in
`internal/admin`. The code knew and the contract document did not. And
**`/auth`'s page family disagrees with itself** about `Cache-Control`, so the
three-endpoint table describing it was a claim about the rejections that had
been measured.

**Status, 2026-08-31 (sixth fold).** Three cuts and two gate fixes took parity
to **294 of 526**, closed **F104, F105 and F106**, and opened **F113 through
F121**. A temporary password is now actually temporary.

Three things about how the round found what it found.

**Two entries named the smaller half of their own subject.** F104 said an admin
field was "consumed by nothing" - the larger half was that the *token endpoint*
never read a user's `requiredActions` either, and nothing in the entry would
have led a reader there. F105 said "six to nine" and the base was wrong: the
tests already held nine. Both understatements had already propagated into a
briefing before a measurement caught them.

**A wrong explanation attached to a correct observation is the most expensive
thing these documents carry.** The observed spec explained an incomplete-profile
refusal by an attribute that exempts nothing. A cut implemented the exemption
from that paragraph, broke two fixtures, and reverted it after measuring - and
without the fabrication, the same code **locks the administrator out of the
server on first start**. The observation was right the whole time, which is
exactly what kept the explanation looking checked.

**Three independent cuts refuted the same line**, "`make record` is silent on a
clean checkout". None was looking for it. See F113.

**Status, 2026-08-31 (seventh fold).** Two cuts took parity to **311 of 526**
and **closed three chapters outright** - `admin/roles` 28/28, `admin/roles-by-id`
10/10, `admin/groups` 11/11. **F122 through F130** are opened.

Two things about the round.

**A fourth gate shape, in four families, and no two share an implementation.**
`client-types` refuses before authorization with a 501; organizations refuse
after it with a 404 on a realm flag; authorization services refuse before it
with a 404 on a *client* flag; and required actions are not a gate at all. Every
one of the four was measured because the cut was told not to assume which shape
it was, and every one would have been got wrong by reusing the last.

**A wrong explanation was killed before it shipped**, for the first time rather
than after. The `PUT .../authz/resource-server` rule was first read as "a body
with no name is a 409", from `{}` and `{"name":"x"}` - and the second of those
is a 409 *with* a name. The distinguishing probe was sent by accident, by a role
sweep that happened to use that body. The pattern this list has recorded twice
as expensive was caught by luck this time, which is not a method.

**Status, 2026-09-01 (eighth fold).** Two cuts took parity to **336 of 535** and
closed `oidc/registration` outright, 14 of 14. **F131 through F141** are opened.

The round's lesson is about this list and the document beside it, not about
Keycloak. **Six counted claims were re-counted and five were wrong**: the
security-header exceptions, the generic-404 producers, the `Location` tails, the
strict decoders, the `jti` prefixes and the parked-golden total - which said
*nine, seven and eight in one paragraph*, because each cut that moved the number
edited a different sentence of it.

**One of those was refuted by this repository's own committed goldens**, for the
third time in a week. A cut measured a 409 sending no security headers, wrote
"a 409 sends none of the five", and the fold carried it -
`admin/realms-admin/default-default-client-scope-duplicate.http` had been a
committed 409 carrying all five since P5. The real rule is about the **empty
body**.

The habit that follows is small and specific: **before writing a rule about
headers or shapes, grep the goldens for a case that would break it.** The
evidence is already in the repository and it is cheaper to read than to measure.

One thing that is deliberately **not** filed. P4's handover proposes an entry
for "a golden that enumerates a realm-wide set without `PristineRealm`", naming
`admin/role-mapper/group-realm-available`. That case gained the flag in
`9732342`, which P4's own branch had merged by the time it was written; the
finding was true when it was measured and was already fixed when it was handed
over. The sweep it asks for - which other cases enumerate a realm-wide set
without claiming the flag - is real and is filed as **F53**.

## F3: two shipped endpoints have no measured contract (closed)

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` records the token
endpoint, the error shapes, the cookies, the discovery document and the bootstrap.
It had no section for `/protocol/openid-connect/certs` or for `GET /realms/{realm}`.

**`/protocol/openid-connect/certs` is now measured and closed** (conformance
harness task 7): the JWKS field set, order and base64 variants are recorded in the
"Certificate endpoint" section of the observed-behaviour document, and
`internal/oidc/discovery.go`'s `jwksDocument`/`jwksFor` marshal in that order with
`x5c`, `x5t` and `x5t#S256` populated from a real self-signed certificate.

**`GET /realms/{realm}` is now measured and closed** too (conformance harness
task 8): the field order is recorded in the "Realm info endpoint" section of the
observed-behaviour document, and `internal/oidc/router.go`'s `realmInfoDocument`
carries that order (it turned out to match the guess already in place, but was a
guess until this recording). The one surprise was `Content-Type`: the success
response carries `;charset=UTF-8`, unlike every other endpoint measured so far,
which `internal/httpx.WriteJSONCharset` now accounts for.

Both endpoints now have `Implemented` cases in `internal/conformance`, so the
conformance verifier enforces this rule - measured, never remembered - for them
on every test run, and for every endpoint added after them.

## F4: the two store drivers are not behaviourally identical under concurrency

The SQLite driver opens with no `busy_timeout`, no WAL mode and an unbounded
connection pool. Under 32 concurrent inserts, 31 failed with `SQLITE_BUSY`, and the
error surfaced raw rather than as `store.ErrConflict` or `store.ErrNotFound`, so a
handler cannot map it to a response. Postgres has no equivalent failure.

The conformance suite runs single-goroutine, so it can never show this. Whatever
fixes it should also add a concurrent case to the suite.

## F5: realm signing keys are generated per process and never persisted (closed)

**Closed by P1, task 2** (`docs/superpowers/plans/2026-08-22-p1-token-foundation.md`).
A realm's three keys - RS256 for signing, RSA-OAEP for encryption, HS512 for
refresh tokens - are now rows in `realm_key`, resolved through `keys.Manager` and
cached per realm. `TestManagerKeepsKidAcrossRestarts` and
`TestManagerRestoresUsableKeyMaterial` guard the `kid` and the key bytes across a
restart, `TestManagerIsolatesRealms` guards the per-realm split, and
`TestConformance/oidc/certs/master` - the project's one sanctioned red test -
passes, so `make test` is clean.

What the finding said, kept for the record:

`keys.Generate()` ran at startup and the result lives only in memory. The `kid`
therefore changes on every restart, invalidating every cached JWKS a client holds,
and two replicas publish different keys for the same realm. Keycloak persists realm
keys.

The same single `RealmKeys` value also serves every realm the router resolves,
which stops being correct as soon as a second realm exists.

A live `master` realm's `/protocol/openid-connect/certs` publishes **two** keys,
not one: an RS256 key with `use: sig` and a separate RSA-OAEP key with
`use: enc` (measured while recording `oidc/certs/master` for the conformance
harness, task 7 - see the "Certificate endpoint" section of the
observed-behaviour document). `keys.Generate` only ever produces the signing
key, so the `oidc/certs/master` conformance case cannot pass byte-for-byte
until Gloak also generates and persists an encryption key: it is one more
symptom of this finding, not a separate one, since both come down to realm
keys not being modelled and persisted the way Keycloak models them.

## F6: migrations take no lock

Three of four concurrent `sqlite.Open` calls against one file failed at
`CREATE TABLE IF NOT EXISTS schema_migrations`. Postgres will lose the same race on
the DDL or on the `schema_migrations` primary key. Consequence: a rolling restart or
a second replica exits at startup.

## F10: operational gaps

- no graceful shutdown or signal handling, so the `ErrServerClosed` branch in
  `cmd/gloak/main.go` is unreachable
- `ORDER BY` uses SQLite's BINARY collation against Postgres's locale collation, and
  no conformance test asserts ordering, so the drivers may already disagree
- `realm.Enabled` is stored but never read, so disabling a realm does nothing
- no CI configuration and no Dockerfile. The Postgres suite is the only evidence
  that the two drivers agree, and it runs only when someone remembers to run it.
  The design spec's Docker image is undelivered.

## F11: non-clean paths escape `withKeycloakFallbacks` into net/http's own body

Reproduced 2026-08-20 while reviewing the conformance harness slice: `GET
//realms/master` and `GET /realms/master/../master` both return **307** with
net/http's own `text/html; charset=utf-8` body (`<a href="/realms/master">Temporary
Redirect</a>.`), not a response `internal/httpx` produced. `net/http.ServeMux`
resolves a "non-clean" path - a doubled slash, or a `.`/`..` element - to its own
redirect handler, and `mux.Handler(r)` reports a **non-empty** pattern for that
handler. `withKeycloakFallbacks` (`internal/oidc/router.go`) only distinguishes "no
route" from "route, wrong method" by whether the pattern is empty, so it treats this
case as an ordinary route match and hands the request straight to `mux.ServeHTTP`,
which performs the redirect itself before `internal/httpx` ever sees it.

This needs a measurement before it needs a fix: what does a live Keycloak 26.7.1
actually answer for these two paths? It may well not be a 307 with an HTML body at
all - Keycloak sits behind its own routing layer, not `net/http.ServeMux`. Guessing
the fix without that measurement would violate the one rule this project is built
on. Once measured, the fix is presumably to have `withKeycloakFallbacks` check
`r.URL.Path` against its cleaned form itself, ahead of the `mux.Handler` probe,
rather than trusting "non-empty pattern" to mean "real route".

## F12: the recorder cannot capture a multi-valued header or a volatile `Location`, together (closed)

**Both halves are closed.** P2's Task 1 added `Case.VolatileHeaders` for the
`Location` half. P2's Task 12 closed the multi-valued half, and not because
anybody planned to: `userinfo`'s 200 was measured sending `Cache-Control`
twice - `no-store` and then `no-cache` - so recording it through `Header.Get`
would have committed a one-value contract. `recordedHeaders` now emits one
golden line per value and the verifier compares the whole list, which is what
this entry asked for. The `Set-Cookie` case it was written for has still not
been recorded; when it is, the machinery is already there.

The original text follows.

## F12 (original): the recorder cannot capture a multi-valued header or a volatile `Location`, together

Two gaps in `internal/conformance` block on the same future case - the first
recorded response carrying a repeated header, most likely `Set-Cookie` on a
completed browser login - and are filed together because whichever plan adds that
fixture has to close both before recording it, not after:

- `recordedHeaders` in `record_test.go` builds each golden header from `h.Get(name)`,
  which returns only the **first** value of a multi-valued response header. A
  response that sends two `Set-Cookie` headers would have its golden capture only
  one of them, silently, at the moment `make record` writes the file - not at
  verify time. The observed-behaviour document has a whole "Cookies" section
  cataloguing three cookies on `GET /auth` alone; recording that endpoint today
  would quietly drop two-thirds of the record. Needs `Golden.Headers` (or a parallel
  structure) to hold every value for a repeated name, and `FormatGolden`/`ParseGolden`
  to round-trip them.
- `Volatile` (`internal/conformance/case.go`) only ever addresses JSON body paths. A
  header value that changes per response - `Location` on a redirect carrying a
  session-specific authorization code, for instance - has no masking mechanism at
  all; only `AssertHeaders`' exact-match or the hardcoded `VolatileHeaders` list
  (`Date`, `Content-Length`) exist today, and neither can express "present, but
  don't compare the value" for an arbitrary header. The authorization and logout
  endpoints' pending cases already assert `Location` is present via `AssertHeaders`,
  which will fail the moment they go `Implemented`, since the code/state/session
  Keycloak puts there is different on every run.

## Smaller items carried from the task reviews

- `classify` in both drivers maps only "no rows" and unique-constraint violations. A
  foreign-key violation surfaces raw. Must land before the admin API maps store
  errors to status codes.
- `broker` and `master-realm` are confidential clients created with an empty secret.
  P1 closed the dangerous half: `internal/oidc/clientauth.go` refuses a confidential
  client whose stored secret is empty, whatever is presented, and
  `TestAuthenticateClientRejectsAnEmptySecretOnAConfidentialClient` guards it. What
  remains is that bootstrap still creates two clients that can never authenticate.
  Whether it should generate real secrets is P2's question, since that is where
  client management lives.
- `WriteBearerChallenge` quotes header parameters with Go's `%q` rather than RFC 7235
  rules. Fine for ASCII without quotes, wrong once realm names are user-supplied.
- The conformance suite exercises 11 of 17 interface methods, while its doc comment
  claims it covers every one. Either widen it or correct the comment.
- The 21 client roles on the `master-realm` client are required by section 8 of the
  design spec and were deliberately deferred to the admin API plan.
- `httpx.WriteOAuthError` marshals from `map[string]string`, the pattern AGENTS.md's
  "Response bodies" section forbids for exactly this reason: Go sorts map keys
  alphabetically, and it happens that `error` sorts before `error_description`,
  which happens to be Keycloak's order too - so nothing is broken today. Nothing
  stops that from becoming false the moment a third field joins the shape (`error`,
  `error_description`, and something else in a non-alphabetical position), at which
  point the map silently reorders itself and the divergence looks like a passing
  test until someone parses the raw bytes. Should be a struct with fields declared
  in order, like every other response type, before that happens rather than after.

## F13: known gaps in the conformance harness itself

Carried out of the harness branch's task reviews and its whole-branch review. None
blocks the harness from doing its job; each is a way it could quietly do less than it
appears to.

- **`TestCatalogIsWellFormed` has no negative cases.** It validates the catalogue but
  nothing proves each rule catches the malformation it targets. Today's entries all
  pass, so the test is a guard for future entries rather than evidence about itself.
- **The catalogue does not validate `Volatile` and `Unordered` path syntax.** A
  leading slash or a typo silently matches nothing in `Normalize`, while
  `SortUnordered` errors on the same input. The asymmetry is defensible and
  undocumented.
- **Nothing detects an orphan golden.** Rename or delete a case and its `.http` file
  lingers with nothing noticing. A loop over `testdata/golden/**` asserting each file
  maps to a catalogue ID closes the other half of the verifier's state table.
- **The golden format cannot store an HTTP reason phrase.** `FormatGolden`
  regenerates it from `http.StatusText`, so a non-standard phrase could not be
  pinned. Every status recorded so far is standard, so this costs nothing yet.
- **`VolatileHeaders` lists `Date`, which Keycloak never sends.** Dead but harmless
  and self-documenting; remove it only alongside a reason.
- **The certificate validity window is held by a comment, not a test.** `selfSign`
  now matches the measured ~10-year window, but nothing pins it, so an edit back to
  the epoch would be silent. `oidc/certs/master` marks `x5c` and both thumbprints
  volatile, so the harness cannot see it either.
- **`internal/conformance`'s test-only boundary is convention, not enforcement.**
  Nothing stops production code importing it. An import-graph test is cheap
  insurance.
- **`gotByName` in `compare` folds the response's headers by iterating a map.** If two
  header names ever canonicalised to the same key, which wins would depend on map
  iteration order. Gloak sets each header once, so this is unreachable today.
- **Three goldens churn on `make record`**, all from a login-theme cache-busting
  hash. Documented in README's record section; all three cases are `Pending`, so
  nothing compares them. A fourth used to churn on the token response's `scope`
  word order and no longer does: `UnorderedWords` sorts the words inside a string.
- **`RunFixture` ignores a step's status code.** Split out as **F34** rather than
  kept here, because it is the one item on this list that has already recorded a
  wrong contract rather than merely being able to. **Closed 2026-08-27.**

One shape-level note rather than a defect:

- `internal/oidc/discovery.go` now holds the JWKS document type alongside the
  discovery document. Two unrelated response shapes in one file; a `jwks.go` would
  say what it is.

The note that `userinfo` was not wired into `oidc.NewRouter` is resolved: P1
serves it, along with the token, introspection and revocation endpoints.

## F14: the access token's `jti` prefix is measured and not reproduced

Keycloak's access-token `jti` carries a per-instance prefix - one captured
sample is `onrtro:13f91f50-6b34-71c7-6d86-d201ef27be67` - while ID and refresh
tokens use a plain UUID. See the "Claim sets" section of the observed-behaviour
document.

`internal/token` emits a plain UUID on all three. One sample says nothing
reliable about the prefix's alphabet or its length, and inventing a generator
from it would be exactly the remembered value this project forbids. It is
invisible today: every token is `Volatile` in every recorded response, and the
one endpoint that would expose a `jti` - introspection - cannot be recorded
yet (F15).

Closing it needs the prefix measured across several container starts, which is
cheap to do the next time a reference container is running.

## F15: two P1 response bodies are served but unmeasured (closed)

**Closed 2026-08-23** by Task 12 of P2. Four of the six bodies were recorded
and now match; the remaining two moved to F18 with a measured reason that is
not the one this entry gives.

- `oidc/userinfo/get-with-valid-token`, `post-with-valid-token` - recorded.
  P1's guessed shape was right in every detail.
- `oidc/token/client-credentials-grant` - recorded. P1's shape was **wrong**:
  the body carries no `refresh_token` and no `session_state`, while
  `refresh_expires_in` is present and 0.
- `oidc/introspection/inactive-token` - recorded.
- `oidc/userinfo/expired-token`, listed in the plan as a candidate rather than
  a deliverable, is recorded too.
- `oidc/introspection/active-access-token` and `active-refresh-token` are in
  F18.

The original text follows.

## F15 (original): two P1 response bodies are served but unmeasured

`userinfo`'s success body and introspection's active/inactive bodies are
emitted from shapes derived from the measured ID-token claim set and RFC 7662,
not from a recording. Both are marked as such in the code.

Neither can be recorded on a bootstrapped `master` realm. userinfo refuses
every token `admin-cli` can issue, because they are lightweight; introspection
refuses `admin-cli` outright, because it is public. Both need a confidential
client with a known secret, which is client management, which is P2.

The conformance cases stay `Pending` in the meantime -
`oidc/userinfo/get-with-valid-token`, `post-with-valid-token`,
`oidc/introspection/active-access-token`, `active-refresh-token` and
`inactive-token` - so nothing asserts these bodies. P2 must record them and
correct the code, rather than assuming the shapes were verified because the
endpoints work.

Same class, already noted where it lives: `client_credentials` returns the same
body shape as the password grant, which is also unmeasured.

The `service-account-<clientId>` username was the third item here. **Closed
2026-08-23** by Task 11 of P2, which measured it through
`GET .../clients/{uuid}/service-account-user`: the guess was right, and it now
lives in `model.ServiceAccountUsername` with the recording cited.

## F16: a client created through the admin API differs from Keycloak's in three ways

Measured 2026-08-23 by reading back a client created with
`{"clientId":"...","enabled":true}`, and recorded as
`admin/clients/read-created`, which is `Recorded` rather than `Implemented`
because of exactly this:

| Field | Keycloak | Gloak |
|---|---|---|
| `defaultClientScopes` | six names from the realm's defaults | `[]` |
| `optionalClientScopes` | five names from the realm's defaults | `[]` |
| `nodeReRegistrationTimeout` | `-1` | `0` |

The two scope lists need the realm to model a default set, which is P5. The
`-1` does not need anything and is simply not applied yet; it was noticed while
reading the recording rather than while writing the create handler.

The golden is in the repository, so the `Recorded` alarm fires the moment all
three line up.

## F17: the listings are gated where Keycloak filters (closed)

Closed 2026-08-28 on `fix/guard-sweep-users-and-listings`. Blocker 1, the one
this entry said was sufficient on its own, was the measurement; it was taken.

The user listing is filtered by what the caller may view and the count is not,
on the same realm at the same moment - so the two endpoints disagreeing is the
contract, exactly as this entry recorded. `query-users` is admitted and shown
`[]`; `view-users` and `manage-users` see everybody.

The clients half was **wrong in both directions at once** and this entry had
only half of it. `GET /clients` took `view-clients` alone, so it refused
`query-clients`, which Keycloak admits and empties, and it refused
`manage-clients`, which Keycloak serves in full. `manage-clients` is not
composite over `view-clients`, so nothing in the role graph predicted the
second; only the sweep did.

What the entry warned against - "should not be closed by wiring up a predicate
nobody measured" - is respected: the predicate is `userAccessFor(...).View` and
`clientAccessFor(...).View`, and the sweep says those two are exactly right on a
default 26.7.1. Fine-grained admin permissions can make visibility per user
rather than per caller; they are off by default, nothing here measures them, and
both call sites say so.

`admin/users/list-without-view-users` is `Implemented`, on a `query-users`
caller, 200 and `[]`.

The measurement is the "The whole users family takes the same two stages, and
the listings filter" section of `2026-08-18-keycloak-26.7.1-observed.md`.

The original entry follows.

## F17 (original): the listings are gated where Keycloak filters

Measured 2026-08-23. A caller holding only the `query-` role gets **200 and an
empty array** from a listing, even filtering to an object that exists. Keycloak
returns the objects the caller may view rather than refusing the caller.

| Listing | Gloak accepts | Gloak returns to a `query-` caller | Keycloak |
|---|---|---|---|
| `GET /clients` | `view-clients` only | 403 | 200 `[]` |
| `GET /users` | `view-users`, `query-users`, `manage-users` | every user | 200 `[]` |

The users half was half-fixed on 2026-08-23: the route now admits `query-users`
because that was measured, but nothing filters the result, so a `query-users`
caller sees everybody. Both listings need the same thing - filter by the
caller's own view permission, `clientAccessFor(...).View` and
`userAccessFor(...).View` respectively - and the clients route needs
`query-clients` admitted as well.

`GET /users/count` is **not** filtered by visibility, measured: the same caller
gets `[]` from the listing and `7` from the count. So the fix belongs in the
listing alone, and the two endpoints disagreeing is the contract.

**Updated 2026-08-27: the blocker this entry named is gone, and it is still
open.** The user halves of `Role Mapper` and `Client Role Mappings` landed with
P2's second cut, so role assignment is served on both locators and both verbs.
A fixture can now build a narrow-role caller end to end without leaving the
API - create a user, set a password on it, `POST` the one role it should hold
to `.../role-mappings/realm`, and password-grant it on `admin-cli` - and every
one of those steps is served by Gloak and recorded against Keycloak.

Two things remain, and neither is the one this entry was waiting for. Only the
first is a blocker; the second is two steps of fixture work:

1. **The filtering is not implemented, and its details are not measured.**
   What is measured is the top of this entry: a `query-` caller gets 200 and an
   empty array. What a `view-users` caller sees when it may view *some* users
   is not, and neither is `GET /clients` for a `query-clients` caller beyond
   the 200 `[]`. `clientAccessFor(...).View` and `userAccessFor(...).View` are
   Gloak's own notions; the sweep that says what Keycloak puts in those lists
   has not been run. This entry should not be closed by wiring up a predicate
   nobody measured.
2. ~~**No fixture yet captures a narrow-role caller's access token.**~~ Done
   2026-08-28: `callerFixture` in `internal/conformance/fixture.go`, registered
   as `narrow-caller-manage-users`, `narrow-caller-view-users` and
   `narrow-caller-impostor`. It creates the user, sets a password, assigns the
   named roles **from `master-realm` by container**, and password-grants it,
   capturing `caller_token`. F37 has the detail. Blocker 1 below is untouched
   and is why `admin/users/list-without-view-users` is still `Pending`. The
   original wording follows, because it is the reasoning that got here.

   This is a smaller gap than it first looks. `loggedOutUserFixture`
   (`internal/conformance/fixture.go`, registered as `logged-out-user`) already
   creates `gloak-probe-logged-out` through the API, sets a password on it and
   password-grants **that user** on `admin-cli` - so minting a token for
   somebody other than the bootstrap administrator is an established move, not
   a missing capability. Two more fixtures grant on `gloak-confidential` rather
   than `admin-cli`. What `logged-out-user` captures is
   `{"user_refresh_token": "refresh_token"}`, because a refresh token is what
   its case needs; nothing captures the **access** token, and no fixture
   assigns the user a role before minting. Those two steps are the remainder.
   The same two would serve F28's caller-relative predicate, which is pinned by
   unit tests alone and whose two `available` reads count as served on the
   strength of the administrator's answer.

So the honest statement of the remaining work is a measurement task plus two
fixture steps, where it used to be a dependency on another sub-project. Blocker
1 is sufficient on its own: even with the fixture in hand there is nothing
correct to assert until the filtering is measured and built.
`admin/users/list-without-view-users` stays `Pending` and its `Reason` now
names those rather than role assignment. `internal/admin`'s own tests still
cover what they can: TestQueryUsersOpensTheListingButNotTheRead pins the status
codes.

## F18: tokens carry no roles, so `aud` is wrong and introspection is too permissive (closed)

**Closed 2026-08-23.** Roles are resolved at issuance, `aud` is derived from
them, and introspection applies the audience check. Both cases it named came
off `Recorded`:

- `oidc/introspection/active-refresh-token` and
  `access-token-outside-audience` are `Implemented`. The `Recorded` alarm is
  what reported it: both started matching the recorded bytes in the same test
  run, before anything was promoted by hand.
- `oidc/introspection/active-access-token` stays `Pending`, for the reason this
  entry gave. The measurement that confirms it is new, though: the audience
  check is real membership, not a blanket refusal. A *second* confidential
  client named in the `aud` introspects the token successfully. Reaching that
  from a fixture still needs role assignment through the API, which is P2's
  second cut.

Six things had to be true at once, and four of them nobody had written down:

1. **`account`'s eight roles and `broker`'s one were missing from bootstrap.**
   Only `master-realm`'s 21 had ever been measured. `account` is the client
   *every* user has roles on, so without it `resource_access` was empty for
   everyone and `aud` was empty with it.
2. **`default-roles-master` was created and left hollow**, so the composite the
   administrator holds reached nothing.
3. **No user creation path assigned it.** Both do now - the admin API's and the
   service account one.
4. **`aud` excludes the issuing client**, which this entry had right, and is
   also a *string* for one audience and *absent* for none, which it did not.
   `realm_access`, `resource_access` and `allowed-origins` are absent rather
   than empty on the same terms.
5. **`resource_access`'s key order is a Java `HashMap`'s**, not sorted. That is
   `internal/javamap`, and it is confirmed against four measured key sets.
6. **The refresh token's `scope` was a wrong constant.** It is the granted
   scope plus the client's default client scopes; the recorded eight-word list
   contained `openid` and `service_account` unconditionally and neither
   belongs there.

What is deliberately still not reproduced, each with its own entry below:
the service account token's four differences (F20), ID token introspection
(F21), and `fullScopeAllowed=false` narrowing the role set (F22).

The original text follows.

## F18 (original): tokens carry no roles, so `aud` is wrong and introspection is too permissive

Measured 2026-08-23 while recording the introspection bodies.

**Gloak resolves no roles at token issuance.** `token.Request.RealmRoles` and
`ClientRoles` have no caller that sets them, so `realm_access.roles` is empty
and `resource_access` is `{}`. Keycloak's administrator token carries five
realm roles and twenty-four client roles across two clients.

**`audience()` returns the issuing client**, which is measurably wrong: an
access token's `aud` holds the clients the *user* has roles on and never the
issuer. For the administrator that is `["master-realm","account"]`. The value
is also a **string when there is one audience and an array when there are
several**.

Two things follow, and both are observable:

1. `oidc/introspection/active-refresh-token` is `Recorded`. Its body is the
   access token's whole claim set rebuilt from the refresh token, which needs
   the roles.
2. **Gloak reports an access token active where Keycloak reports it
   inactive.** Keycloak refuses to introspect an access token whose `aud`
   excludes the caller; Gloak puts the caller in `aud`, so its own check would
   pass. `oidc/introspection/access-token-outside-audience` is `Recorded` for
   exactly this.

Fixing it needs role resolution at issuance - the machinery exists,
`RoleRepo.ListUserRoles` plus composite expansion, and `internal/admin` already
does it - plus bootstrap creating the `account` client's three roles and the
`default-roles-master` composite that grants them. `aud` then falls out of
`resource_access`, and the introspection audience check can be added with it.

`oidc/introspection/active-access-token` stays `Pending` throughout: even with
all of that, no fixture can put the introspecting client inside an access
token's audience without assigning the user a role on it (P2's second cut) or
an audience protocol mapper (P5).

## F19: two access.token.lifespan values are measured and not reproduced

Gloak honours the client attribute `access.token.lifespan` when it is a
positive integer, which is what the expired-token case needs. Two neighbouring
values were measured and are not reproduced:

| Attribute | Keycloak | Gloak |
|---|---|---|
| `"0"` | `expires_in` 0, token still accepted | falls back to the realm's 60 |
| `"-1"` | `expires_in` 36000 | falls back to the realm's 60 |

36000 is ten hours and matches no value this realm models, so reproducing it
would mean copying a number without knowing what it is. Both are corner cases
no client sets deliberately, and both are wrong today.

## F20: the service account's access token differs in four places

Measured 2026-08-23 by decoding a `client_credentials` token, while closing
F18. Gloak reproduces the roles and none of the rest:

| | Keycloak | Gloak |
|---|---|---|
| `sid` | **absent** | present |
| `clientHost` | the caller's address | absent |
| `clientAddress` | the caller's address | absent |
| `client_id` | the client's `clientId` | absent |

The three extra claims sit around `preferred_username`: `clientHost` before it,
`clientAddress` and `client_id` after. `sid`'s absence agrees with the response
body, which carries no `session_state` either - Gloak already reproduces that
half and issues a token that disagrees with it.

None of this is observable through a golden today: every token is `Volatile` in
every recorded response, and the one endpoint that would expose these claims is
introspection, which cannot reach a service account's own token for the reason
F18's closing note gives.

`clientHost` and `clientAddress` also raise a question this project has not had
to answer before - what a token claim should say behind a proxy - so they want
deciding rather than copying.

## F21: introspection does not accept an ID token

Measured 2026-08-23. An ID token introspects active from a client in its
audience, with the same rebuilt claim set the refresh token produces, `typ` and
`token_type` both `ID`, and **no `scope` key** since an ID token has none.

`internal/oidc`'s introspection tries `ParseAccess` then `ParseRefresh` and
reports anything else inactive, so Gloak answers `{"active":false}` where
Keycloak answers with the body. Adding a third parse is small; what stops it
being small is that the ID token is RS256 like the access token, so the branch
that currently answers "access token, apply the audience check" has to tell the
two apart by `typ` before deciding which rule applies - and whether the audience
check applies to an ID token at all is **unmeasured**.

It has no conformance case yet, because a fixture needs the same role
assignment `active-access-token` is waiting for.

## F22: `fullScopeAllowed` is not honoured

Every client Gloak knows about has full scope allowed - the six bootstrapped
ones and every client the admin API creates, since Keycloak's default is true
and F16 records the created client's representation as otherwise correct. So
nothing is wrong today.

What is missing is the switch. In Keycloak a client with `fullScopeAllowed`
false carries only the roles in its own scope mappings, and Gloak would put all
of them in the token regardless. That needs the scope-mapping model, which is
P5, and it needs measuring first: nobody has recorded what a narrowed token
looks like.

## F23: three login-theme goldens churn on every re-record (closed 2026-09-01)

**Closed by exactly what it asked for**: a normalisation pass replacing the
resource version. It is `ReplaceThemeResource` in
`internal/conformance/normalize.go`, called from `normalisePasses` so both sides
of a comparison get it, and its three named goldens are compared contracts now.

**Its own description of the value was wrong, and so was this document's.** The
version is minted with the **database**, not per container: six `docker restart`
of one container gave one value, and eight wipes of `/opt/keycloak/data/h2` gave
eight. The sentence below is kept as it stood, because five copies of it had
been made without anybody restarting a container, and the reason it survived is
worth more than the sentence: **nothing in the harness turned on it**. `make
record` starts a fresh container every run, so the claim was never in a position
to be falsified by anything the project does. Thirteen values are now measured
and every one is five lowercase alphanumerics.

What the finding said, kept for the record:

`oidc/authorization/invalid-redirect-uri`, `unknown-client-id` and
`oidc/logout/invalid-post-logout-redirect-uri` record Keycloak's login page,
whose asset URLs carry a per-container resource version -
`/resources/l3kth/...` one run, `/resources/esh1o/...` the next. Every
`make record` rewrites all three with no change in meaning.

That is exactly what `VolatileHeaders` exists to prevent for headers, and it is
worse here: a reviewer who sees three files change every time stops reading the
diff, which is how a recorder's output stops being read.

All three are `Pending`, so nothing compares them and nothing is at risk yet.
The fix is a normalisation pass replacing the resource version, and it belongs
with P3, which is when these bodies start being served and compared.

## F24: a composite write onto the realm's own client's role diverges from Keycloak (closed)

**Closed 2026-08-25** by the final fix wave of `feat/p2-roles`, commit
"fix(admin): refuse composite writes on the realm's own client's roles".
Closed in full: `POST` and `DELETE .../composites` on a role the
`{realm}-realm` client owns now answer 403 on both the by-name and the
`roles-by-id` routes, matching the measurement, and `GET .../composites` still
answers 200. Nothing of F24 remains open. The neighbouring question it raised
but did not itself cover - `PUT` and `DELETE` of those roles - is **F26**, and
it is not a leftover of F24 but an unmeasured behaviour of its own.

**The fix location recorded below was wrong**, and is corrected here rather
than deleted, because the reasoning that was wrong is the point. It said the
fix belonged in `clientRoleContainer`, "which `roles-by-id` already shares"
through `clientRoleLocator`. `roles-by-id` shares no such thing: the
`roles-by-id` routes are registered with `guardByRoleContainer`
(`internal/admin/router.go`), which resolves the role itself with
`Roles().ByID` and hands it to `byIDLocator`, so `clientRoleContainer` never
runs on them. A task obeying the text below would have closed
`POST /clients/{uuid}/roles/{name}/composites` and left
`POST /roles-by-id/{master-realm client role id}/composites` wide open - the
same escalation by a different path.

The check went into `eachComposite` instead, which is the one place the
by-name and by-id families meet, and `TestTheRealmsOwnClientRefusesCompositeWrites`
exercises both so the two cannot drift apart again.

It was also more serious than the 204-vs-403 the text below describes. A
caller holding only `manage-clients` could `POST` a composite onto
`master-realm`'s own `manage-clients` role naming **`manage-realm`** as the
child: the route guard wants `manage-clients`, and the per-child
`requiresChildManageRole` wants `manage-clients` too, because `manage-realm`
is itself a client role on that same client. Every check passed, and
`roles.Effective` returned `manage-realm` on the next request. Nothing outside
could mint a narrow-role admin while it was open.

The original entry, unedited:

Measured while building `roles-by-id` (P2's second cut, Task 9). Keycloak
refuses `POST /clients/{master-realm uuid}/roles` outright - the realm's own
client takes no new role from anybody, and that much Gloak already matches.
The same refusal turns out to extend further than a create: writing a
composite onto a role the realm's own client **already has** is refused too,
even to the full administrator:

```
POST /admin/realms/master/clients/{master-realm uuid}/roles/query-groups/composites
Authorization: Bearer <full administrator token>
Body: [{"id":"...","name":"byname-child-role"}]

HTTP/1.1 403 Forbidden
{"error":"HTTP 403 Forbidden"}
```

**Gloak answers 204 to the identical request.** `clientRoleContainer` in
`internal/admin/roles.go`, which every client-role-composite route reaches
through `clientRoleLocator`, has no check for `c.ClientID ==
rc.realm.Name+"-realm"` - only `createClientRole` carries it. Confirmed
directly against Gloak, not only reasoned from the source.

Left unfixed on purpose. The fix belongs in `clientRoleContainer`, which
`readClientRole`, `updateClientRole`, `deleteClientRole`, the composite
routes and `roles-by-id` (through `clientRoleLocator`) all already share -
several of them shipped in earlier tasks of this same cut. Deciding which of
those should gain the check, and whether it belongs in `clientRoleContainer`
itself or only at the composite call sites, needs its own deliberate task
rather than a fold-in here. Full transcript and reasoning: the "Roles" section
of `2026-08-18-keycloak-26.7.1-observed.md`, under "Which role each role
operation needs".

## F25: `first` and `max` are ignored on every role listing

Opened by the final whole-branch review of `feat/p2-roles`, 2026-08-25.

**Partly closed 2026-08-26** by `feat/keycloak-testsuite-mining`, commits
"feat(admin): apply first and max to the role listings" and "fix(admin): page
the role listings when first and max are both present". **It stays open**, for
the reason in the third paragraph below.

*Closed:* the two flat listings. `GET /roles` and `GET /clients/{uuid}/roles`
both honour `first` and `max` through `pageRoles`, and the measured rule - the
listing pages when `search` is non-empty **or** when both bounds are present,
over an order sorted by name - is in the "Role listing: first and max" section
of `2026-08-18-keycloak-26.7.1-observed.md`. Every detail this entry listed as
unmeasured now is: `first` past the end is `[]` rather than an error, `max=0`
is an empty array rather than "ignored", and the bounds apply after `search`
narrows the set. Seven conformance cases cover it. Four send `first` or `max`:
`admin/roles/list-realm-page-empty`, `list-realm-page-past-end`,
`list-realm-page-first` and `list-realm-page-no-search`. Three send only
`search`, which is the gate's other half: `admin/roles/list-realm-brief`,
`list-realm-full` and `list-realm-search-excludes-client-roles`.

*Not closed:* the composite listings, which this entry also names.
`listComposites` (`internal/admin/roles.go`) still reads neither parameter,
and - the point - **nothing has measured whether Keycloak's composite
listings take them at all.** It serves `GET .../composites` and its two
filtered forms on the by-name and `roles-by-id` families alike, so one
unmeasured behaviour covers ten routes. Do not copy `pageRoles` into it on the
strength of the flat listings agreeing; the flat listings' own rule turned out
to have a second gate nobody predicted from the first three probes.

*Also not closed:* the conformance-model question in the last paragraph below,
whether `Implemented` needs to mean "every query parameter" or the catalogue
needs a way to say "implemented except for these". This branch did not decide
it.

**One line of the text below is now wrong** and is corrected here rather than
deleted, because it is the same mistake the fix wave had to undo. It says the
"realm role listing is not sorted" section "already records that `first`/`max`
page in the listing's own order, so the parameters were observed working".
That sentence has been removed from the observed spec: the listing's own order
is unstable and unsorted, the paged path is sorted by name, and the two are
different code paths. Nothing had observed the parameters working.

Every role listing this cut shipped reads only `search` and
`briefRepresentation` off the query string. `first` and `max` are accepted and
silently dropped. That covers `GET /roles`, `GET /clients/{uuid}/roles`, and
the composite listings - `filterRoles` and `writeRoleList` in
`internal/admin/roles.go` are the whole of the parameter handling.

The user listing next door implements both (`internal/admin/users.go`), so
this is an inconsistency inside Gloak as well as a divergence: two listings in
the same API, one of which pages.

Keycloak pages these. The "The realm role listing is not sorted" section of
`2026-08-18-keycloak-26.7.1-observed.md` already records that `first`/`max`
page in the listing's own order, so the parameters were observed working -
what is unmeasured is the detail: what a `first` past the end answers, whether
`max=0` is an empty list or ignored, whether they apply before or after
`search`, and whether the composite listings take them at all.

**These operations are marked `Implemented` in `internal/conformance` and
counted in the meter**, so the published number overstates what is served.
Whatever fixes this should decide whether "implemented" needs to mean "every
query parameter", or whether the catalog needs a way to say "implemented
except for these parameters" - the second is probably right, and is a change
to the conformance model rather than to the roles code.

## F26: `PUT` and `DELETE` on the realm's own client's roles are not refused

Opened by the final whole-branch review of `feat/p2-roles`, 2026-08-25.
Neighbour of F24, and deliberately not folded into it.

`createClientRole` refuses `POST /clients/{{realm}-realm uuid}/roles`, and as
of F24's fix `eachComposite` refuses both composite writes on those roles.
`updateClientRole` and `deleteClientRole` refuse neither, and neither does
`roles-by-id`. So a caller holding `manage-clients` can `DELETE` the
`master-realm` client's `view-users` role outright, which cascades its
`user_role_mapping` rows away with it and silently strips the right from every
user that held it.

**Measured 2026-08-27, and the answer is 403 on all four.** This entry used to
say Keycloak's behaviour here was unmeasured and that 403 was only likely; the
four requests it asked for were run against a live 26.7.1 with the full
administrator token, and `query-groups` was read back afterwards and is still
there:

```
PUT    /admin/realms/master/clients/{master-realm uuid}/roles/query-groups   403
PUT    /admin/realms/master/roles-by-id/{query-groups id}                    403
DELETE /admin/realms/master/roles-by-id/{query-groups id}                    403
DELETE /admin/realms/master/clients/{master-realm uuid}/roles/query-groups   403
```

The `PUT` bodies were the role's own representation unchanged, so nothing about
the content earns the refusal. Both route families were asked, because F24
showed they have to be. So this is now an implementation gap, not an unmeasured
one: the check already written for F24 - `ownedByRealmOwnClient` in
`internal/admin/roles.go` - is the piece to reuse, and the only decision left is
where it goes so that both families reach it, which for these two is not
`eachComposite`. Verbatim transcript in the "realm's own client is never
configurable" passage of `2026-08-18-keycloak-26.7.1-observed.md`.

**The same pass found a second, wider divergence: the realm roles `admin` and
`create-realm` refuse `PUT` to a full administrator too, and Gloak accepts it.**
Both answer 403 to a `PUT` carrying the role's own representation unchanged,
where `offline_access` answers 204 to that body and to one that adds an
`attributes` key. So the refusal is not about attributes and not about being
bootstrapped. `updateRealmRole` has no check at all, so Gloak answers 204 to
all of them.

**The boundary is not measured.** Two of `master`'s five realm roles,
`default-roles-master` and `uma_authorization`, were never probed, so "these two
and no others" is one negative control short of a sweep. That `admin` and
`create-realm` happen to be the two realm roles F28's predicate treats as admin
roles is suggestive and is not evidence. Whoever fixes this measures all five
first, and `DELETE` alongside `PUT`, rather than assuming the predicate
transfers. Filed here rather than as its own entry because the fix is the same
shape and the same call-site family as the client half above; if the boundary
turns out to be F28's admin-role set, `mayGrantRole` already computes it.

## F27: `make oracle` exercises no role commands

Opened by the final whole-branch review of `feat/p2-roles`, 2026-08-25; first
raised by Task 11's implementer.

`internal/admin/kcadm_docker_test.go` is deliberately client-scoped and
user-scoped. It drives a real `kcadm.sh` against Gloak and asserts the CLI is
satisfied, which is the only check in the repository that a real Keycloak
client - rather than the project's own idea of one - accepts what Gloak
serves.

**Thirty role endpoints shipped in this cut with no external-oracle
coverage.** The conformance suite compares against recorded goldens, which is
a different guarantee: goldens confirm Gloak reproduces what was recorded, not
that a client which was never used during recording can drive it.

Four `kcadm` invocations would cover most of it:

```
kcadm create roles -r master -s name=probe-role
kcadm get roles -r master
kcadm add-roles --uusername ... --rolename probe-role
kcadm delete roles/probe-role -r master
```

The `add-roles` one belongs with the role-mapping cut rather than here. The
other three are available now and would have caught anything that made the
role representation unparseable to a real client.

## F28: composite writes do not apply Keycloak's caller-relative admin-role rule (closed)

Opened by the final whole-branch review of `feat/p2-roles`, 2026-08-25. **This
one is a privilege-escalation path, not a cosmetic divergence.**

Keycloak judges *who is asking* before letting an admin role become a
composite child: a caller may attach an admin role only if it already has the
administrative power that role confers. The full transcript - three tables,
27 children swept against two callers, plus a re-run after granting the caller
one more role - is in the "Adding an admin role as a composite is judged
against the caller, not the role" section of
`2026-08-18-keycloak-26.7.1-observed.md`. In short:

- full administrator, `POST /roles/default-roles-master/composites` naming
  `admin`: **204**
- a caller holding only `manage-realm`, the identical request: **403**
- the same caller naming an ordinary realm role instead: **204**

**Gloak answers 204 to all three.** A `manage-realm`-only caller can therefore
put `admin` onto `default-roles-master`, which every user in the realm holds,
and hand full administration to the entire realm. Not reachable from outside
today - nothing can mint a narrow-role admin until role assignment ships - and
reachable the moment it does.

Not fixed in the fix wave that measured it, on purpose. The naive rule
("refuse when the caller does not hold the child") is **falsified** by the
measurement: fourteen of the swept children are 204 for a caller that does not
hold them. Implementing it that way would diverge in the too-restrictive
direction, which is the mistake this branch already made once with the
`DELETE .../composites` cross-family rule and had to undo. The real rule is a
mapping from each admin role name to the administrative power it confers, and
Gloak's `caller` today is a flat effective-role set with nothing to hang that
on.

The same check governs assigning a role to a user
(`POST /users/{id}/role-mappings/realm`), which is a later cut, so the two
want one task between them rather than a bolt-on here. That task needs one
more measurement pass first: the sweep above is two callers' rows, and what is
wanted is the rule for an arbitrary caller.

**There is a third call site, and it is a read.** Added 2026-08-26 by Task 2 of
`feat/p2-role-mappings`. The paragraph above says "the two", and that count is
now wrong: it is three. The correction is recorded here rather than made in
place, because the reason the third was missed is the point - the first two are
writes, and nobody looked for the same predicate on a read.

`GET /users/{id}/role-mappings/realm/available` is **not** simply "every realm
role not assigned directly". Keycloak also drops the roles the *caller* may not
grant. Measured against a live 26.7.1 on one subject - `probe-subject`, holding
`probe-attr` and `default-roles-master` directly - with three callers, a fresh
token minted immediately before each call. **All three answer 200**; only the
bodies differ:

```
--- caller probe-view-users ---
    []
--- caller probe-manage-users ---
    ['offline_access', 'uma_authorization']
--- caller admin ---
    ['create-realm', 'offline_access', 'uma_authorization', 'admin']
```

The full administrator's answer is exactly the complement of the direct
assignments. `manage-users` loses `admin` and `create-realm`, the two it may not
grant. `view-users` loses everything, because it may grant nothing at all - it
can read the list and assign none of it.

**Gloak answers the full administrator's list to every caller its guard
admits**, so a `view-users` caller sees four roles where Keycloak shows it
none. This is the *permissive* direction, and it is milder than the two writes
above: it leaks the names of roles the caller may not grant, and grants
nothing. The write guard is unaffected. But it is the same divergence from the
same rule, and a fix wave that closes the two writes and leaves this one open
would leave F28's predicate applied inconsistently across the four places the
API exposes it - see the count at the end of this entry.

So: **F28 cannot be closed until this call site is covered as well.** Task 7 of
the role-mappings plan enumerates two call sites - `eachComposite`'s child
check and the mapping writes - and its Step 3 says "write one predicate and
call it from" them. It is one predicate and **three** call sites; the third is
`availableRealmMappings` in `internal/admin/rolemappings.go`, whose doc comment
already names F28 and says the filter is deliberately absent. The client
mirror, `.../role-mappings/clients/{uuid}/available`, is the same endpoint by
another locator and was not measured - it should be, in the same pass, rather
than inferred from this one.

**That measurement was taken, 2026-08-26, by Task 4 of the role-mappings plan,
and the mirror agrees.** On the `master-realm` container: a caller holding only
`view-users` gets `[]`, one holding only `manage-users` gets seven of the 21 -
the ones it may hand out - and a full administrator gets the whole complement of
the direct assignments. Only `available` is filtered; the direct listing and the
composite expansion answer the same for all three callers. So the count is one
predicate and **four** read/write call sites once the client reads ship:
`eachComposite`'s child check, the mapping writes, `availableRealmMappings` and
`availableClientMappings`. The latter carries the same deliberately-absent
comment as its realm mirror. Transcript: "The client mirror is filtered the same
way" in `2026-08-18-keycloak-26.7.1-observed.md`.

**Five, not four.** Added 2026-08-26 by Task 5 of the role-mappings plan, which
shipped `POST` and `DELETE /users/{id}/role-mappings/clients/{uuid}`. That task
was told to measure whether the client write is filtered and to record the
answer without implementing it. It is filtered, so the fourth call site above
splits in two: the mapping writes are a realm pair **and** a client pair, and
each was measured on its own routes.

Caller `probe-manage-users`, subject `probe-mapped`, container `master-realm`, a
fresh token minted immediately before each call:

- `POST .../role-mappings/clients/{master-realm}` naming `view-users`: **204**
- the same request naming `manage-realm`: **403**
- naming `impersonation`: **403**
- naming `manage-clients`: **403**
- `DELETE` naming `manage-realm`, on a subject that holds it: **403**
- a batch naming `view-users` and `manage-realm` together: **403**, applying
  neither, in both array orders

The set it may write is again exactly the set its own `available` read shows it
on that container - the seven of `master-realm`'s 21 already recorded above. On
the ordinary client `probe-app`, whose three roles are all in that list, it may
assign and remove freely, which is the control that the filter is per role
rather than per container.

So: one predicate and **five** measured surfaces - `eachComposite`'s child
check, the realm mapping writes, the client mapping writes,
`availableRealmMappings` and `availableClientMappings`. In the code it is
**four** places, not five, because both write pairs run through one helper:
`eachMapping` in `internal/admin/rolemappings.go`, whose doc comment records the
gap for both. Task 7 writes the predicate once and calls it from those four.
Transcript: "The client writes are filtered the same way" in
`2026-08-18-keycloak-26.7.1-observed.md`.

Full transcript: the "`available` is filtered by what the caller may grant"
section of `2026-08-18-keycloak-26.7.1-observed.md`, at line 2730. It sits
beside the write-side sweep this entry already cites, "Adding an admin role as
a composite is judged against the *caller*, not the role", at line 2297 of the
same file.

Not fixed in the task that measured it, for the reason the entry gives above:
the rule is a mapping from an admin role to the power it confers, that mapping
is not in this repository, and a partial version of it is what Task 7's own
Step 2 tells its implementer to refuse to write.

**The escalation is now reachable.** Added 2026-08-26 by Task 3 of
`feat/p2-role-mappings`, which shipped `POST` and `DELETE
/users/{id}/role-mappings/realm`. The entry above says "Not reachable from
outside today - nothing can mint a narrow-role admin until role assignment
ships - and reachable the moment it does". That moment is this commit: a
`manage-users` caller can now assign `admin` to any user through Gloak's API,
and from that user's token do anything at all.

The second call site's own rule was measured in the same task, so Task 7 does
not have to go back to the container for it. Against a live 26.7.1, caller
`probe-manage-users`, subject `probe-mapped`, a fresh token minted immediately
before each call:

- `POST .../role-mappings/realm` naming `admin`: **403**
- the same request naming `create-realm`: **403**
- the same request naming `uma_authorization`: **204**
- `DELETE .../role-mappings/realm` naming `admin`, on a subject that holds it:
  **403**

So the predicate governs **both verbs**, not just the assignment - and the
refusal is all-or-nothing, exactly like the 404: a batch naming
`uma_authorization` and `create-realm` together applies neither. The set the
caller may write is the same set its `available` read shows it, which ties the
write and the third call site together: one predicate, and `available` is its
enumeration.

Note also that this is a *second* authorization stage, distinct from the route
guard. `view-users` is refused for an empty array, which has no role to filter,
so the guard fires first; `manage-users` passes the guard and is then judged
per role. Whatever Task 7 writes has to sit inside the handler, after the
guard, not replace it.

Full transcript: the "A mapping write **is** filtered by what the caller may
grant" section of `2026-08-18-keycloak-26.7.1-observed.md`.

**The call-site count stays at four.** Task 6 measured
`GET /users/{id}/role-mappings` for the same filter on 2026-08-26 and it does
not have one: a `view-users` caller and a full administrator reading the
bootstrapped administrator get byte-identical bodies. So the predicate is on
the two `available` reads and the two write pairs, and the combined view - like
the four `direct` and `composite` reads - reports what the subject holds
regardless of who is asking. Transcript under "The combined view is not
caller-filtered" in `2026-08-18-keycloak-26.7.1-observed.md`.

**Closed 2026-08-27** by Task 7 of `feat/p2-role-mappings`, on all four call
sites. What closed it is a measurement, not a decision: the rule this entry says
"is a mapping from each admin role name to the administrative power it confers"
was derived by sweeping a live 26.7.1 and is now recorded there.

The rule:

> A caller may hand out a role only if the role is not one of the realm's own
> admin roles, or the caller's own effective roles already confer that admin
> role - itself, or one measured to subsume it.

**One predicate, not two.** For every one of 23 caller rows, the set of roles a
caller may write is the set its own `available` read returns, on the realm
locator and on the client one. The read filter and the write check are the same
question rather than two that agree by coincidence. (The *equality* is claimed
more strongly in `2026-08-18-keycloak-26.7.1-observed.md` than the evidence on
that page supports - the matrix-B `available` block was never pasted. See F35.)
It is `mayGrantRole` in `internal/admin/auth.go`, called from **three** call
sites serving four surfaces: `eachMapping`, `grantable` - which both
`availableRealmMappings` and `availableClientMappings` go through, exactly as
the write pair shares `eachMapping` - and `addComposites`' `mayAttachChild`.

Three things the sweep found that the two-caller version could not:

- **The role-mapping surface has a second condition.** A caller holding
  `view-users` plus any one other admin role gets `[]` from both `available`
  reads, ordinary roles included. Handing a role to a *user* needs `manage-users`
  first and the conferral second, so the two `available` reads re-apply the
  *write* guard - their own is looser. The composite surface has no such
  condition.
- **`DELETE .../composites` does not apply the rule**, measured on that verb
  rather than carried over from `POST`: the caller refused `POST` naming `admin`
  removes that same child, 204. The role-mapping `DELETE` **does**. That is why
  `removeComposites` still passes nil and `eachMapping` checks both verbs.
- **A role's container decides whether it is an admin role, not its name.** A
  client of one's own carrying roles named `admin`, `impersonation` and
  `manage-realm` is assignable in full by a `manage-users` caller, while
  `master-realm`'s roles of those names are refused it.

**F28 is closed against callers who cannot obtain a name collision.** That
qualification is the entry, not a footnote on it. The rule above is
caller-relative, and the caller's side of it is a name test as long as F32
stands: `has` and `hasAny` are keyed on the role name with the owning container
dropped, so a caller who can mint or rename an ordinary role into an admin
role's name passes a guard it does not hold. `mayGrantRole` no longer inherits
that - its own caller side was moved onto the container test on 2026-08-27, see
the closing note under F32 - but the guards in front of it did not move, and a
caller that reaches a route it should not have reached is still inside F28's
surface when it gets there. **F28 is not fully closed until F32 is**, and F32 is
where the remaining half lives.

Nothing else is re-filed from this entry: all three call sites are covered and
the predicate is one.

Full transcript, including all four matrices as data: the "A caller may hand out
a role only if its own rights already confer it" section of
`2026-08-18-keycloak-26.7.1-observed.md`.

## F29: deleting a client leaves its roles behind, and Keycloak deletes them

Found and measured 2026-08-25 while verifying F-nothing in particular - it
turned up on the way to checking whether the composite-flag resync that this
branch added to `RoleRepo.Delete` also covered a client deletion. It does not,
because nothing deletes the roles at all.

Measured against a live 26.7.1 with the full administrator token: create a
client, give it a role, make that role the only child of a realm role, then
delete the client.

```
create client cascade-client: 201
create client role:           201
create realm parent:          201
add composite:                204
parent before: composite= True
delete the client:            204

the client role by id after the client is gone: 404
parent after:  composite= False
parent composites after: []
```

**Keycloak deletes a client's roles with the client**, and resyncs the
composite flag of anything that had one of them as its last child - the same
derived-flag rule this branch measured and implemented for a role deletion.

**Gloak does neither.** `keycloak_role.client_id` is a plain `TEXT NOT NULL
DEFAULT ''` column with no foreign key (`0001_init.sql`, both drivers), so the
role row survives its client. Run against Gloak, the identical sequence leaves
the parent reading `"composite":true` with `cascade-role` still in its
composites listing, carrying a `containerId` that names a client which no
longer exists. The role is also still assignable and still resolves through
`roles-by-id`.

(**"Still assignable" was true on 2026-08-25 and is not true now.** `104f495`
added `mayAttachChild`, whose container lookup turns a composite add naming an
orphan into a 500; the role-mapping writes that shipped after it answer 404. The
listing and `roles-by-id` halves of that sentence still hold. Probed both
sides - see the 2026-08-27 subsection at the end of this entry.)

Two pieces, and the second depends on the first:

1. A client deletion has to take its roles with it. That is a schema change -
   a foreign key with `ON DELETE CASCADE`, matching the one `realm_id` already
   has - plus a migration.
2. Once it cascades at the database level, `RoleRepo.Delete` is no longer on
   the path, so the composite resync this branch put there would be bypassed.
   Whoever does (1) has to carry the resync into the client deletion too, or
   move it somewhere both reach. The resync statement itself is reusable; only
   its `WHERE` changes, from one role id to every role the client owns.

Not fixed here: it is a client-lifecycle concern that predates the roles cut,
it needs a migration, and the roles half of this cut had no business changing
the client schema on the way past.

**It got one degree worse on 2026-08-26**, when Task 6 added
`GET /users/{id}/role-mappings`. That endpoint has to resolve every owning
client to key `clientMappings` by `clientId`, so an orphaned role is not merely
cosmetic there - it is a **500**. Measured on Gloak: create a client and a role
on it, assign the role to a user, delete the client, then read the combined
view.

```
delete client -> 204
combined view -> 500 {"error":"Internal Server Error"}
realm view    -> 200 [{"id":"48284e32-4ca0-48ea-8ca6-4e9f5818bae1","name":"default-roles-master","description":"${role_default-roles}","composite":true,"clientRole":false,"containerId":"18effee7-1b68-4193-88c3-a1740f751e13"}]
```

The realm-half read beside it is unaffected, because it never looks a client
up. `clientMappingsOf` was deliberately left to fail rather than skip the
orphan: skipping would make this the one endpoint that conceals F29 while
answering with a role list it knows to be short. Fixing F29 fixes this with it.

### 2026-08-27: one symptom is now deliberately concealed, and this says which

`adminRoleNames` resolves each of the caller's client roles to its owning client
on **every** admin request - that is F28's caller-side fix. Run against an
orphan it propagated `ErrNotFound`, and the effect was out of all proportion to
F29's own severity:

- a caller holding one role on a deleted client got **500 on every admin
  route**, not merely on the endpoints that report that role;
- it was **unrecoverable through the API**, because the role-mapping route that
  would remove the offending mapping answered 500 too;
- and `DELETE /admin/realms/{realm}/clients/{uuid}` on `master-realm`, which
  Gloak answers 204, took the **bootstrapped administrator** down with it.

**The decision, taken deliberately: `adminRoleNames` now treats `ErrNotFound`
from that lookup as "not an admin role" and carries on.** It stays fail-closed
for the decision the set feeds - an orphan cannot be an admin role of a living
container, so it confers nothing - and only `ErrNotFound` is swallowed; any
other store error still stops the request.

**This is against the spirit of the paragraph above, and that is the point of
recording it here.** What is concealed: an orphan no longer announces itself on
every admin request. What the swallow did **not** touch, all measured against
this head on 2026-08-27:

- `GET /users/{id}/role-mappings` still answers **500**, which is the symptom
  that paragraph is about and the one `clientMappingsOf` refuses to hide;
- the **composites listing** still returns the orphan - `GET
  /roles/probe-parent/composites` answers `200` with `"clientRole":true` and a
  `containerId` naming a client that does not exist - which is the surface F29's
  own body describes;
- `roles-by-id` still resolves it, `200`, with the same dead `containerId`;
- **`POST .../composites` naming the orphan as a child answers 500**, and so do
  `POST` and `DELETE .../roles-by-id/{orphan}/composites` with the orphan as the
  parent. See the paragraph below.

Two clauses that stood here until 2026-08-27 were wrong and are removed rather
than softened, because this list's job is to be checkable:

- "still listed by the **realm-half** reads" - it is not. That read filters to
  `clientRole:false`, so a client role can never appear in it; measured, it
  answers `200` with the subject's realm roles and no orphan. The composites
  listing above is the surface that was meant.
- "still **assignable**" - not through any route probed at this head. The realm
  mapping write answers `404 {"error":"Role not found"}`, the client mapping
  write `404 {"error":"Client not found"}` because the path segment no longer
  resolves, and the composite add answers 500. A live realm role assigned
  through the same route in the same run answered 204, so the route works and
  the refusals are about the orphan.

That clause was **true when F29 was written** and went stale, which is why it is
dated rather than called a mistake: probed on `694dfc7`, the commit before this
branch, `POST /roles/probe-parent/composites` naming the orphan as a child
answered **204** and the listing showed it. `mayAttachChild` shipped in
`104f495` and turned that into the 500 above. The same clause in F29's body at
"The role is also still assignable" carries the same date stamp for the same
reason.

So F29 is no *less* visible than it was before this branch existed; what was
removed is a new, wider symptom this branch introduced. The alternative was
leaving a caller unable to reach any admin endpoint, with no way back through
the API, over a state Gloak creates by answering 204.

`mayGrantRole`'s own container lookup was **not** changed and must not be:
there the same swallow would answer "not an admin role" for the role being
handed out and make an orphan grantable, which is fail-open. The asymmetry is
spelled out at `adminRoleNames` in `internal/admin/auth.go`.
`TestARoleOnADeletedClientDoesNotLockTheCallerOut` and
`TestAFailingClientLookupStillStopsTheRequest` pin both halves.

**The composite writes therefore answer 500 on an orphan, and that is left
standing.** Same root cause as the lock-out above, on routes this pass
deliberately did not touch. Measured 2026-08-27 against this head, two distinct
lookups:

```
POST   /roles/probe-parent/composites          [orphan as child]   -> 500
DELETE /roles/probe-parent/composites          [orphan as child]   -> 204
POST   /roles/probe-parent/composites  as manage-realm, no manage-clients -> 403
POST   /roles-by-id/{orphan}/composites        [orphan as parent]  -> 500
DELETE /roles-by-id/{orphan}/composites        [orphan as parent]  -> 500
```

The child-side 500 is `mayGrantRole`'s lookup (`auth.go:175`), reached through
`mayAttachChild` (`roles.go:109`) - **not** the parent-side check at
`roles.go:652`, which returns without a lookup for a realm parent. The two
controls prove it: `DELETE` passes nil for `checkChild` and answers 204, and a
caller without `manage-clients` short-circuits at `requiresChildManageRole` and
answers 403 before any lookup runs. The parent-side check at `roles.go:652` is
reached separately, through `roles-by-id` with the orphan **as** the parent, and
that is the last two rows.

Bounded to those routes, fail-closed, and unreachable on Keycloak, which deletes
a client's roles with the client. Not fixed here for the reason `mayGrantRole`
was not: these judge a role rather than the caller, so the safe direction is to
refuse. `PUT` and `DELETE` on `/roles-by-id/{orphan}` both answer 204, so an
operator can still remove the orphan and is not stuck.

None of this reduces F29's priority. Fixing F29 removes the state, and this
paragraph with it.

## F30: the role-mapping guards are one stage where Keycloak has two (closed)

Closed 2026-08-28 on `fix/guard-sweep-users-and-listings`, swept together with
F36 as this entry asked.

`guardUserSubject` is the combinator the entry said was missing: coarse gate,
resolve the subject, fine check. The coarse gate is `usersReadRoles` and the
fine stage is what the route itself takes.

The sweep widened the entry's own claim. It measured the role-mapping routes;
the same rule holds on **all 18** routes naming a `{userID}` - the single-user
reads and writes, the whole credential family and the logout as well - which is
why the entry told whoever fixed it to sweep those rather than assume the same
gate. They do behave the same; that is now measured rather than extended.

`query-users` is the row that makes it two stages. It opens no route in the
family and still gets the 404, so no single-stage guard can produce the
contract: name `query-users` and every real-subject 403 breaks, leave it out and
every 404 does.

`admin/users/read-missing-to-a-query-users-caller` and
`admin/users/read-to-a-query-users-caller` are the pair that records it, and
`TestAMissingSubjectIs404ToTheWholeUsersFamily` covers all 16 route shapes
against both sides of the gate.

The original entry follows.

## F30 (original): the role-mapping guards are one stage where Keycloak has two

Found and measured 2026-08-26 by Task 3 of `feat/p2-role-mappings`, while
sweeping the write guards. Not what the task was looking for.

Every `/users/{id}/role-mappings/...` route in Gloak is a single-stage route
guard: `guardAny` or `guard` checks the caller's roles and the handler resolves
the subject afterwards. Keycloak checks **twice**, with the subject resolved in
between - so a caller that fails the fine-grained check but passes a coarse one
learns whether the user exists, and a caller that fails the coarse check does
not.

Measured against a live 26.7.1 on
`/users/00000000-0000-0000-0000-000000000000/role-mappings/realm`, a user id
that resolves to nothing, one user per role and a fresh token minted
immediately before each call:

```
probe-view-users       GET  .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-query-users      GET  .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-manage-realm     GET  .../role-mappings/realm (missing user) -> 403 {"error":"HTTP 403 Forbidden"}

probe-view-users       POST   .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-view-users       DELETE .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-query-users      POST   .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-query-users      DELETE .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-manage-realm     POST   .../role-mappings/realm (missing user) -> 403 {"error":"HTTP 403 Forbidden"}
probe-manage-realm     DELETE .../role-mappings/realm (missing user) -> 403 {"error":"HTTP 403 Forbidden"}
probe-manage-users     POST   .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
probe-manage-users     DELETE .../role-mappings/realm (missing user) -> 404 {"error":"User not found"}
```

`query-users` opens neither the reads nor the writes, and still gets 404. The
coarse gate is exactly `usersReadRoles` - `view-users`, `query-users`,
`manage-users` - and everything outside the users family fails it:

```
probe-subject          GET -> 403 {"error":"HTTP 403 Forbidden"} POST -> 403 {"error":"HTTP 403 Forbidden"}
probe-view-clients     GET -> 403 {"error":"HTTP 403 Forbidden"} POST -> 403 {"error":"HTTP 403 Forbidden"}
probe-manage-clients   GET -> 403 {"error":"HTTP 403 Forbidden"} POST -> 403 {"error":"HTTP 403 Forbidden"}
probe-view-realm       GET -> 403 {"error":"HTTP 403 Forbidden"} POST -> 403 {"error":"HTTP 403 Forbidden"}
```

(`probe-subject` holds `probe-attr` and `default-roles-master` and no
`master-realm` role at all.)

**Gloak answers 403 in every one of the 404 rows.** It is the *conservative*
direction - it tells the caller less, not more - so it is not an escalation
path. It is still a divergence, and it is on eight route registrations, five of
which shipped with the reads a day before this was found.

Not fixed in the task that measured it, for two reasons. It needs a combinator
that neither `guard`, `guardAny`, `guardAnyAndAny` nor `guardByRoleContainer`
expresses - coarse check, resolve the subject, fine check - and adding it would
change the three reads Task 2 shipped as well as the two writes Task 3 added,
which is a wider blast radius than a write task should take on its own. And the
coarse gate was swept on this route family only; the credential endpoints and
`GET /users/{id}` take a user id too and were not measured, so whoever fixes
this should sweep them in the same pass rather than assume the same gate.

**F36 wants the same two routes swept for a different question** - which roles
open them at all, where this entry asks in what order the two checks run. Same
fixtures, same tokens, two columns; do them together.

Transcript: the "Existence is answered before authorization, but only for the
users family" section of `2026-08-18-keycloak-26.7.1-observed.md`.

## F31: a real 405 exists, and the "wrong method is always 404" rule is too broad

**A second counter-example, measured 2026-08-29 by P4's first cut**, and it
refutes the rule that replaced the first one. `DELETE /admin/realms` and
`PUT /admin/realms` answer **405**, and so does `PATCH /admin/realms/{realm}` -
while `DELETE` on a role-mapping path answers 404 for the same class of
mistake. So "the verb decides" does not fit either: the same verb answers 404 on
one path and 405 on another. Neither rule this entry has tried holds, and the
sweep that would settle it has still not been run.

The original entry follows.

### F31 (original): a real 405 exists, and the "wrong method is always 404" rule is too broad

Found and measured 2026-08-26 by Task 6 of `feat/p2-role-mappings`, while
checking whether `POST /users/{id}/role-mappings` is an operation before writing
down that it is not. It is not - but the way it is not turned up something else.

`AGENTS.md` says, under "Things that look like bugs and are not":

> **A wrong method on a known path returns 404, not 405, with no `Allow`
> header.** Gloak once invented a 405 that does not exist [...]

The second sentence is still true of whatever route that was. The first is too
broad: **`PUT` and `PATCH` on the role-mapping paths answer a genuine 405**,
with no `Allow` header, on a live 26.7.1. Measured on all three, a fresh token
minted immediately before each call:

```
$ curl -s -i -X PUT -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '[]' "$KC/admin/realms/master/users/$PU/role-mappings"
HTTP/1.1 405 Method Not Allowed
content-length: 39
Content-Type: application/json
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Robots-Tag: none

{"error":"HTTP 405 Method Not Allowed"}
```

`PATCH` on the same path, and `PUT` and `PATCH` on `.../role-mappings/realm` and
`.../role-mappings/clients/{uuid}`, all answer that byte for byte - same status,
same 39-byte body, same five security headers, no `Allow`.

The same path does answer 404 for other verbs, which is why this is a
refinement rather than a reversal:

```
$ curl -s -o /dev/stdout -w '\nHTTP %{http_code}\n' -X POST -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '[]' "$KC/admin/realms/master/users/$PU/role-mappings"
{"error":"HTTP 404 Not Found"}
HTTP 404
$ curl -s -o /dev/stdout -w '\nHTTP %{http_code}\n' -X DELETE -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '[]' "$KC/admin/realms/master/users/$PU/role-mappings"
{"error":"HTTP 404 Not Found"}
HTTP 404
```

All four command lines above were re-run verbatim on 2026-08-26 after this
entry was first written, because the version committed with it had the
`Authorization` header missing - a rendering fault, not a measurement fault.
The corrected lines reproduce the statuses shown; the version without the
header returns `401 {"error":"HTTP 401 Unauthorized"}` and measures nothing.

So on one single path, `POST` and `DELETE` are 404 and `PUT` and `PATCH` are
405. The status is not a property of "known path, wrong method" at all; which
verb it is decides. Nothing measured so far says what the rule is - only that
the current one-line summary cannot be it.

**Gloak answers 404 for all four**, on every one of these paths:

```
PUT    role-mappings        -> 404 {"error":"HTTP 404 Not Found"}
PATCH  role-mappings        -> 404 {"error":"HTTP 404 Not Found"}
POST   role-mappings        -> 404 {"error":"HTTP 404 Not Found"}
DELETE role-mappings        -> 404 {"error":"HTTP 404 Not Found"}
PUT    role-mappings/realm  -> 404 {"error":"HTTP 404 Not Found"}
PATCH  role-mappings/realm  -> 404 {"error":"HTTP 404 Not Found"}
```

Two of the six match and four do not.

Not fixed in the task that found it. It is a `withKeycloakFallbacks` concern,
not a role-mapping one - the divergence is on every route in the tree, it
predates this branch, and the three `role-mappings/realm` rows above are Task
2's registrations rather than Task 6's. Fixing it needs the rule measured
first: which verbs get 405 and on which paths, swept across route families
rather than generalised from this one, since generalising from one sweep is
what put the too-broad sentence in `AGENTS.md` in the first place.

`AGENTS.md`'s bullet has not been rewritten, only marked. Its text is the
contract for the two 404 bodies, which are unchanged and still measured; only
the "not 405" clause is now known to be narrower than it reads, and rewriting
it before the rule is known would replace one guess with another. So the
bullet stands and the sentence under it - "That rule is measured too broad" -
records what this entry measured and points back here.

Transcript: the "A wrong method is not always 404" section of
`2026-08-18-keycloak-26.7.1-observed.md`.

## F32: the caller's roles are flattened by name, so an ordinary client role can impersonate an admin one (closed)

Closed 2026-08-28 on `fix/guard-the-caller-by-container`. `caller` no longer
carries the name-keyed set at all: `has` and `hasAny` read the container-reduced
one that `adminRoleNames` already built for F28's grant predicate, and
`roles.Names` was removed rather than left where the next call site could reach
for it - its doc comment asserted the very premise this entry refutes.

The entry below says the remaining fix "is not local" and would need every
`has`/`hasAny` call site to decide which container it means. It does, and the
answer turned out to be the same at all of them: **every question this API asks
of a caller is an admin-role question** - the route guards, the `access` claims
on a user and a client representation, and `mayGrantRole`. So one set answers
all of them and no call site was left meaning "any container".

Measured on 2026-08-28 by one script run against Keycloak and against two Gloak
builds, `main` at `dcbcd11` and the fix, on the two paths that reach the name
from `manage-clients` alone - minting an impostor role on a client of one's own,
and renaming the `account` client's own roles into admin names. Keycloak refuses
`POST /roles` with 403 on both and creates nothing; `dcbcd11` answered 201 on
both and the roles are there afterwards; the fix answers 403 and creates
nothing. The table is the "The role check is by container, so a role named after
an admin one opens nothing" section of
`2026-08-18-keycloak-26.7.1-observed.md`.

Two unit tests carry it, one per path, and under the mutation that drops the
container test from `adminRoleNames` both fail with the measured symptom - 201
where 403 is wanted.

**Not covered by a conformance case, deliberately and not silently.** Every
fixture in the harness mints a full administrator, so there is no non-admin
caller token to record this against; building one is its own piece of work.
Filed as F37.

The original entry follows.

## F32 (original): the caller's roles are flattened by name, so an ordinary client role can impersonate an admin one

Found 2026-08-27 by Task 7 of `feat/p2-role-mappings`, while writing F28's
predicate. It is **older than F28 and wider**: it is the whole guard layer, not
the role-mapping family.

`caller.roles` is `roles.Names(effective)` - a `map[string]bool` keyed on the
role's **name**, with the owning container dropped. `caller.has("manage-realm")`
therefore cannot tell `master-realm`'s `manage-realm` from an ordinary client's
role that happens to be called `manage-realm`. The doc comment on `has` says so
and treats it as safe ("Names are unique within the admin role container"),
which is true of that container and not of the realm.

Measured on both sides, 2026-08-27. Create a client, give it a role named
`manage-realm`, assign that role to a user, and ask for a realm role to be
created:

```
Keycloak 26.7.1:  POST /admin/realms/master/roles -> 403 {"error":"HTTP 403 Forbidden"}
                  the role was not created
Gloak:            POST /admin/realms/master/roles -> 201
                  read back: {"id":"...","name":"minted-by-an-ordinary-role",...}
```

**This is a privilege escalation.** Minting the impostor needs `manage-clients`
(to create the client and its role) and `manage-users` (to assign it), so it is
a narrow admin widening itself rather than an anonymous path - the same shape
F28 had, one layer down. Keycloak is immune because it resolves the caller's
admin roles by container, which is exactly what F28's own predicate was measured
doing and what `mayGrantRole` implements for the role it is judging.

**`mayGrantRole` inherited the hole for the *caller* side, and that half is now
fixed.** `grants()` was seeded from `caller.roles`, so an impostor
`manage-clients` conferred the client-domain roles there too.

This entry used to say that was harmless - "no weaker than the guard beside it -
the same caller already passes `guard("manage-clients")` on every client route -
so closing F28 did not widen anything". **Both halves of that sentence were
wrong, and it is corrected here rather than deleted, because the reasoning is
what failed and not only the wording.**

- The predicate consults `grants()` *before* any container test, so it is not a
  second opinion on a decision the guard already made. It is the whole decision
  for a role whose name collides.
- The names that mattered are `admin` and `create-realm`, and **no route on
  `694dfc7`, the commit before this branch, requires either of them.** They
  conferred nothing before F28 was closed. Afterwards they conferred the ability
  to hand out realm superuser, which is the widening the sentence denied.

Measured on the branch head by review, 2026-08-27, and the minimal precondition
is narrower than this entry's own: `manage-clients` **alone**, plus the default
roles every `POST /users` grants. `account` is not the realm's own client, so a
`manage-clients` caller may rename its `manage-account` to `admin` and its
`view-profile` to `manage-users`; the second rename passes `guard` by F32, and
the first then passes `mayGrantRole` by the same name-keying. The realm role
`admin` goes to any user: 403 before, 204 after, and the subject's realm
mappings read back `[admin default-roles-master]`. The implication closure
amplified each collision - ordinary roles named `manage-realm`, `impersonation`
and `manage-events` took a caller's `available` list on `master-realm` from 12
roles to 19.

`mayGrantRole`'s caller side was moved onto the container test the same day, in
`fix(admin): judge the caller's own roles by container, not by name`:
`adminRoleNames` reduces the caller's effective set to the admin role names in
it, and `grants()` closes over that instead of over every name held.
`internal/admin/rolemappings_test.go` carries the regression.

**What remains is F32 proper**, which this branch does not introduce: on
`694dfc7` the same rename already gets a `manage-clients` caller to
`POST /roles` answering 201. The remaining fix is not local. `caller` would have
to carry the container alongside the name, which means `resolveCaller` resolving
each effective role's owning client - `adminRoleNames` now does exactly that for
the grant set, so the mechanism exists - and every `has`/`hasAny` call site
deciding which container it means. That is the whole authorization layer of
`internal/admin`, so it wants its own task rather than a bolt-on to the one that
found it. **F28 is qualified on this entry**: see its closing note.

## F33: a mapping write resolves the role by id, where Keycloak resolves it by name (closed)

Closed 2026-08-28 on `fix/mapping-write-name-and-id`. **The decision this entry
was held open for does not exist**, and that is the finding rather than the fix.

The discriminating probe below was run, on both verbs and both containers, and
answered **404 in both directions**: with the `id` naming a role the caller may
grant and the `name` one it may not, and again the other way round. So the
disagreement between the two keys is settled *before* the caller check, and a
mismatch authorises neither role. There is no "which role must a correct
implementation judge", because on a mismatch it judges none. The controls in the
same run are 403 when the keys agree on a refused role and 204 when they agree
on a grantable one, so the caller check was demonstrably reachable.

One rule covers every shape measured, 17 cells: an entry is accepted exactly
when its `id` and its `name` resolve to the same role in the route's own
container.

The fix is therefore one comparison beside the container test `eachMapping`
already ran, not a new lookup path. Keycloak resolves by name and compares the
id; Gloak resolves by id and compares the name; **the two cannot be told apart
through this API**, because a name is unique within a container and so is an id,
so each key resolves to at most one role and both orders accept exactly the
pairs that agree. That equivalence is argued rather than assumed, and it is
written into the handler's doc comment so the difference is not later read as a
divergence.

Both recorded cases are `Implemented` and two more were added for the
disagreeing pair - `admin/role-mapper/assign-realm-name-disagrees` and
`admin/client-role-mappings/assign-name-disagrees` - because an id-only entry is
also 404 under "resolve by name and find nothing", so the id-only cases alone
never pinned the rule. The four conformance cases run as a full administrator,
for which every role is grantable, so none of them can pin the *ordering*;
`TestMappingWriteRequiresTheIdAndNameToAgree` does, on a `manage-users` caller,
and under the mutation that removes the comparison it reproduces the measured
before-column exactly - 204 where the id was grantable, 403 where it was not.

The measurement is the "The two keys are reconciled before the caller is judged"
subsection of `2026-08-18-keycloak-26.7.1-observed.md`.

The original entry follows.

## F33 (original): a mapping write resolves the role by id, where Keycloak resolves it by name

Found 2026-08-27 by Task 8 of `feat/p2-role-mappings`, by the conformance
fixture failing silently: its assignment steps sent `[{"id":"..."}]`, which is
the shape `POST .../roles/{name}/composites` next door accepts, and every
recorded body came back as though nothing had been assigned.

Measured on all four write routes - `POST` and `DELETE`, realm and client -
with three body shapes each:

```
[{"id":R}]                  -> 404 {"error":"Role not found"}
[{"name":"role-two"}]       -> 404 {"error":"Role not found"}
[{"id":R_other,"name":"role-two"}] -> 404 {"error":"Role not found"}
[{"id":R,"name":"role-two"}]       -> 204
```

So Keycloak looks the entry up by **name** and then requires `id` to name the
same role. Gloak's `eachMapping` does `store.Roles().ByID(ctx, realm.ID, rep.ID)`
and never reads `name`.

**Two of the three failing shapes diverge, not three.** Measured against a
`./gloak serve -db sqlite` on 2026-08-27, subject `t8-verify`, so that this
entry states what Gloak does rather than what reading it suggests:

| body | Keycloak | Gloak | verdict |
|---|---|---|---|
| `[{"id":R}]` | 404 `Role not found` | **204** | diverges |
| `[{"name":"role-two"}]` | 404 `Role not found` | 404 `Role not found` | **agrees** |
| `[{"id":R,"name":"role-two"}]`, the two disagreeing | 404 `Role not found` | **204** | diverges |
| `[{"id":R2,"name":"role-two"}]`, the two agreeing | 204 | 204 | agrees |

The name-only body already answers correctly, and by accident rather than by
design: `rep.ID` decodes to `""`, `roleRepo.ByID` matches no row, `classify`
turns `sql.ErrNoRows` into `store.ErrNotFound`, and `eachMapping` writes the
same 404 the measured one is. **Whoever fixes this must not touch that shape** -
it is already right, and the right answer is currently reached down a path that
would disappear if the lookup moved to the name.

The disagreeing pair is the worse of the two divergences, because it is not
merely lax: Gloak **writes the role the `id` names and ignores the `name`
entirely**, where Keycloak writes nothing. Measured with `id` naming
`t8-verify-role-three` and `name` naming `t8-verify-role-four`, neither held
beforehand: 204, and `t8-verify-role-three` is what the subject came away
holding.

Not a privilege escalation: the per-entry `mayGrantRole` check still runs on
whatever role the id resolved to, so nothing is granted that the caller could
not grant anyway. It is a fidelity gap - Gloak accepts requests Keycloak
refuses, and on the disagreeing pair silently picks a role for the caller - and
one that a client written against Gloak would not survive being pointed at
Keycloak.

Why it was missed until now: every body in the "Writing a mapping" sections of
the observed document sends both keys, so "resolve by id" was consistent with
every measurement taken and was never probed. Task 8's fixture was the first
thing to send one key on its own.

Not fixed in the task that found it: Task 8 records contracts and does not
change handlers, and the fix has a decision in it - whether the 404 for a
mismatched pair is reached by looking up the **name** and comparing the id, or
by looking up the **id** and comparing the name. Every body measured so far
answers the same either way.

**The probe that separates them, and it needs no second container.**
`eachMapping` raises its 404 and its 403 at two different points of one validate
loop, and that precedence is itself measured - see the doc comment there, and
"The refusal answers in array order, like the 404 beside it" in the observed
document. So send **one entry whose `id` names a role the caller may grant and
whose `name` names one it may not**, as a caller narrow enough for the
distinction to exist: `manage-users` may grant `offline_access` and may not
grant `admin`, which is the pair the F28 sweep already used. The two orders then
answer differently, because the role that reaches the caller check is not the
same role:

- 403 means the entry was resolved by `name` and the resolved role reached
  `mayGrantRole` before any id comparison.
- 404 means the mismatch was decided first - either because the id comparison
  precedes the caller check, or because the lookup went by `id`.

Run it against Keycloak first. Whichever way it answers also fixes **which role
a correct implementation must authorize**, which is the part the fix cannot
guess and the part that makes this a decision rather than a rename. Gloak today
authorizes the role `id` picked, so a fix that moves the lookup to `name`
without settling this silently moves what `mayGrantRole` judges.

Recorded as `admin/role-mapper/assign-realm-id-only` and
`admin/client-role-mappings/assign-id-only`, both `Recorded` - so the day the
handler is fixed, the verifier's "already matches, promote it" alarm says so.

Transcript: the "A mapping write resolves the role by name, and the id has to
agree" section of `2026-08-18-keycloak-26.7.1-observed.md`.

## F34: a fixture step that fails is silent, so the recorder can write a wrong contract and pass (closed)

Found 2026-08-27 by Task 8 of `feat/p2-role-mappings`, the hard way. Split out
of F13 rather than added to it: every other item on that list is a way the
harness *could* do less than it appears to, and this one already did.

**Closed 2026-08-27** by `fix(conformance): fail a fixture whose step is
refused`. `Step.ExpectStatus` takes the first of the two options sketched below,
defaulting to any 2xx; the failure names the step index, the method, the path,
the expected status and the body. The 24 creates whose repeat answers 409 on the
recorder's shared container carry `idempotentCreate` explicitly, which is what
turns each of the comments that documented that 409 into something checked; the
creates that capture from `Location` keep the strict default, because a 409
leaves them nothing to read. `TestRunFixtureFailsOnARefusedStep` and
`TestRunFixtureAcceptsAnExpectedNon2xx` pin both halves.

`RunFixture` (`internal/conformance/fixture.go:1130`) reads `resp.StatusCode`
only to decorate a capture-failure message. A step whose request is refused -
403, 404, 409, 400 - returns no error, so the fixture runs to completion, the
case's own request is sent against a server that is not in the state the fixture
claims, and `make record` writes the response as the contract and reports `PASS`.

The realised symptom: Task 8's mapping fixtures assigned roles with
`[{"id":"..."}]`, which F33 shows Keycloak refuses with 404. All four
assignment steps failed. **Nineteen goldens recorded, every subtest `PASS`, and
every one of them described a subject holding no roles** - `[]` for the client
listing, `default-roles-master` alone for the realm one, and 404 for the four
write cases. Nothing in the run said anything was wrong. It was caught only
because the goldens were read line by line before committing, which is a
discipline rather than a mechanism.

What makes it dangerous rather than merely annoying: the wrong goldens are
*self-consistent*. Gloak's fixture run fails in exactly the same way against
exactly the same handler, so the verifier agrees with the recorder and
`make test` is green. A wrong contract recorded this way is invisible to every
check the suite has.

The fix is small and the decision inside it is what to do about the steps that
are *meant* to be refused. `confidentialClientFixture` and `clientRoleFixture`
document a create answering 409 on the recorder's shared container as normal and
harmless, so a blanket "non-2xx is an error" would break several fixtures on the
second case that names them. Options, in the order they look sensible:

- a per-step `AllowStatus []int`, defaulting to "2xx only", with the idempotent
  creates naming 409 explicitly - which also turns each of those comments into
  something checked;
- or an `Expect` predicate per step, if a range turns out to be too coarse.

Either way the failure has to name the step index, the method, the path and the
body, because the symptom appears one request later at the earliest.

Worth doing before the next family of endpoints is recorded, not after: the cost
of this defect scales with how much of the catalogue is written by fixtures that
mutate state, and that is the direction every remaining chapter goes.

## F35: `available` is claimed equal to the write set cell by cell, and the comparison is not on the page

Found 2026-08-27 by review of `feat/p2-role-mappings`. Nothing is falsified -
this is a **traceability** defect, which in a project whose governing rule is
"observable values are measured, never remembered" is the kind that matters.

`2026-08-18-keycloak-26.7.1-observed.md` says that for all 23 caller rows of
matrix B the set a caller may `POST` is "byte-for-byte the set its own
`available` read returns ... Not 'resembles': the same set, on every row, checked
cell by cell." F28's own entry repeated it. The write cells for matrices B, C and
D are pasted, and matrix A's `available` output is pasted - but matrix A's
callers are `view-users` plus row, which measures the *gate*, not the equality.
**The matrix-B `available` block is in neither the observed document nor
`task-7-report.md`.**

The document's own arithmetic exposes it: 3178 claimed verdicts minus 1890
pasted write cells is 1288, exactly two blocks of 23 by 28 read verdicts, one of
which is on the page. The other is the one the equality rests on.

The plan for that task forbade exactly this: "Report raw request and response
text, not summary tables. A reviewer cannot check a table against anything."

**The consequence is bounded.** A wrong read filter produces a wrong list, not
an escalation - the writes are guarded by the same predicate whatever the reads
show, and those cells *are* pasted. The wording in both documents has been
downgraded to what the page supports.

The container is gone, so this cannot be re-measured now. **Sweep instruction
for whoever next has one running:** build matrix B's 23 callers again
(`manage-users` + each of the 21 `master-realm` roles, plus `manage-users` alone
and the realm role `admin`), and for each caller read
`GET /users/{subject}/role-mappings/realm/available` and
`.../role-mappings/clients/{master-realm}/available` with a fresh token minted
immediately before each call. Paste the two lists verbatim per row beside that
row's write line. The claim is true only if each list equals that row's `204`
columns exactly; if it does not, the read filter and the write check are two
predicates and `grantable` is wrong to share `mayGrantRole`.

## F36: `manage-users` opens all seven mapping reads and is refused `GET /users/{id}` (closed)

Closed 2026-08-28 on `fix/guard-sweep-users-and-listings`, in the same pass as
F30 as both entries asked.

The suspicion was right and the shape was the one this entry called unlikely:
**Keycloak lets `manage-users` read.** `GET /users/{id}` and
`GET /users/{id}/credentials` both answer 200 to it, so the caller that could
update and delete a user it could not read was Gloak's invention, not
Keycloak's. Both routes now take `view-users` or `manage-users`.

The rest of the credential family - `reset-password`, `userLabel`,
`moveToFirst`, `moveAfter`, `disable-credential-types` - is `manage-users`
alone, and so are the update and the delete. Every other role, `query-users`
included, is 403 on all nine. The whole family was swept rather than the two
routes this entry named, because assuming the neighbours agree is what put the
divergence there.

`admin/users/read-to-a-manage-users-caller` records it.

The original entry follows.

## F36 (original): `manage-users` opens all seven mapping reads and is refused `GET /users/{id}`

Filed 2026-08-27 by review of `feat/p2-role-mappings`. Pre-existing, needs a
container, and it is the **too-restrictive** direction this cut has already
reverted twice - which is the reason it is worth a sweep rather than a shrug.

`manage-users` is not composite over `view-users`: it has no children at all,
measured. It nevertheless opens all seven role-mapping reads, which is why
`userMappingsReadRoles` is `{view-users, manage-users}` rather than `view-users`
alone. Two neighbouring routes that take a user id were never swept the same way
and are still guarded by `view-users` on its own:

- `GET /admin/realms/{realm}/users/{userID}` (`internal/admin/router.go:41`)
- `GET /admin/realms/{realm}/users/{userID}/credentials` (`router.go:47`)

The comment at `router.go:386-389` records only that `query-users` was measured
getting 403 on the first of those and 200 on the listing and the count. **That
says nothing about `manage-users`**, and a caller holding `manage-users` alone
can currently update and delete a user it may not read - which is not a shape
Keycloak is likely to have.

**Sweep instruction:** one user per role, a fresh token minted immediately
before each call, over `view-users`, `query-users` and `manage-users` at least,
against `GET /users/{id}`, `GET /users/{id}/credentials`, and the rest of the
credential family (`PUT .../reset-password`, `DELETE
.../credentials/{id}`, `PUT .../credentials/{id}/userLabel`, the two `move*`
routes and `PUT .../disable-credential-types`) so the whole family is decided in
one pass rather than one route at a time.

F30 also names `GET /users/{id}` and the credential endpoints, for a different
question - whether the subject is resolved before the caller is judged, which is
about the **404-before-403 ordering** rather than about which roles open the
route. **Do both in the same pass**: same fixtures, same tokens, two columns.

## F37: the harness has no non-admin caller, so no guard refusal can be recorded (closed)

Closed 2026-08-28 on `feat/non-admin-caller-fixture`, the same day it was filed.

`callerFixture(username, roles...)` in `internal/conformance/fixture.go` creates
the user, sets a password through `PUT .../reset-password`, assigns the named
roles **from `master-realm` by container**, and password-grants it on
`admin-cli`, capturing `caller_token`. A case picks the caller it means by which
of the two tokens it sends. Three registrations use it:
`narrow-caller-manage-users`, `narrow-caller-view-users`, and
`narrow-caller-impostor`, which additionally holds an ordinary client role named
`manage-realm`.

Three contracts that were prose are now goldens recorded from the reference
container:

- `admin/role-mapper/assign-refused-to-a-manage-users-caller` - 403. F28's
  caller-relative rule, which had no case at all.
- `admin/role-mapper/available-to-a-view-users-caller` - `[]`. The `available`
  filtering, which until now was scored on the administrator's answer, and an
  implementation ignoring the caller entirely passed every other case on the
  route.
- `admin/roles/create-refused-to-an-impostor-role` - 403. F32's container rule,
  the fix from the day before, which shipped without one.

Each was mutation-tested against the branch its own claim lives in, and the
third round mattered: dropping `mayGrantRole` killed two of the three and left
the `available` case passing, because `grantable` returns early on the write
guard before any role is judged. That case is pinned by removing **that** early
return instead. A case that cannot fail is a case that is not evidence, and one
mutation per file would have missed it.

**Parity did not move**, and the roles come from the container test rather than
by name, which is the distinction F32 turned out to be about: a fixture minting
a role of its own named `manage-users` would have been building the impostor.

What this does **not** unblock: `admin/users/list-without-view-users` stays
`Pending`. Its other blocker is F17's first - the listing is not filtered by
caller visibility and that filtering is unmeasured - and no fixture fixes that.
F17's blocker 2 is struck through; blocker 1 is untouched.

Still unrecordable for want of the measurement rather than the fixture: F36's
sweep over which roles open the user and credential routes, and F30's
404-before-403 ordering. Both now need only a live pass, and the fixture is
there when they have one.

The original entry follows.

## F37 (original): the harness has no non-admin caller, so no guard refusal can be recorded

Filed 2026-08-28 by `fix/guard-the-caller-by-container`, which wanted a
conformance case and could not have one.

Every fixture in `internal/conformance` authenticates as the bootstrapped
administrator. There is no fixture that mints a user holding a chosen admin
role, gives it a password and captures its token, so **no case in the catalogue
can assert a 403**. The one case that would - `admin/users/list-without-view-users`
- is `Pending` with no fixture, and it has been in the skipped list of every
`make record` run since it was written.

The consequence is not that guards are untested: `internal/admin` tests them
thoroughly, on a caller built directly through the store. It is that none of it
is measured against Keycloak *through the harness*, so the guard contract rests
on hand-run probes recorded in prose - F28's sweep, F32's table - rather than on
goldens the suite replays. Those probes are real measurements, but nothing
re-runs them.

What it needs: a fixture that creates a user, sets a password through
`PUT .../reset-password`, assigns one named role from `master-realm`, and
captures a token for it. `tokenForRoles` in `internal/admin/auth_test.go` is the
same shape and can be read for the steps; the harness version has to go through
the API rather than the store, because the recorder drives a container.

It unlocks more than one case. F28's caller-relative rule, F32's container rule,
the `available` filtering, `admin/users/list-without-view-users`, and F36's
sweep over which roles open the user and credential routes are all currently
unrecordable for the same reason.

## F38: a golden cannot mask a per-request value inside an HTML body (closed, not built)

**Closed 2026-08-29 as not worth building**, on four grounds, and it should not
sit here as a standing to-do. The gap is real; the mechanism is not the answer.

1. It is **one** `Pending` case, and what its golden would assert - the 200, the
   `text/html` with no charset, the form's `code, iss, state, session_state`
   order - is already measured and written into the observed document in full,
   the body included verbatim. A golden would be a second copy of a
   measurement rather than a new one.
2. **It is not one masker but two positions.** The entry below asks for "mask
   the value of this attribute at this place in the HTML", which reaches the
   four `<INPUT ... VALUE="...">`s. The measured body also carries a `<SCRIPT>`
   whose `history.replaceState` argument is a URL holding `tab_id` and
   `client_data`, both minted by the same request. A `VALUE` masker leaves the
   case churning on every recording, which is the disease it was for.
3. The blunt alternatives are larger retreats than the one AGENTS.md permits. A
   whole-body mask leaves the case asserting a status line and headers, and
   AGENTS.md names `UnorderedKeys` as "the only such retreat - do not add a
   second without writing down why". A list of regexes in the catalogue is
   powerful enough to mask any body and moves the reviewing burden into
   regexes.
4. The natural moment to revisit is not now. F23's three login-theme goldens
   need a substitution pass for a per-container resource version, and that pass
   and this one may be the same shape.

**If it is reopened, reopen it against a second case that wants the same
mechanism.** One case is not a mechanism's evidence.

What the finding said, kept for the record:

Found 2026-08-29 while recording P3's first cut.

`Case.Volatile` addresses slash-separated paths into a JSON document, and
`Case.VolatileHeaders` masks a whole header. Neither can reach inside an HTML
body, and one measured response needs exactly that.

`oidc/authorization/response-mode-form-post` answers 200 with an auto-submitting
form:

```html
<FORM METHOD="POST" ACTION="http://localhost:9999/callback">
  <INPUT TYPE="HIDDEN" NAME="code" VALUE="5b316524-...anCYj088k42Tzt2U65m0QCz2.e7e7a673-..." />
  <INPUT TYPE="HIDDEN" NAME="iss" VALUE="{{issuer}}/realms/master" />
  <INPUT TYPE="HIDDEN" NAME="state" VALUE="xyz123" />
  <INPUT TYPE="HIDDEN" NAME="session_state" VALUE="anCYj088k42Tzt2U65m0QCz2" />
```

The `code` and `session_state` are minted by the case's own request, and the
`<SCRIPT>` above the form carries a `tab_id` and a `client_data` from the same
request. A golden holding them churns on every recording and can never match a
served implementation, so the case is `Pending` with that as its reason rather
than `Recorded` against a golden nobody could satisfy.

It is not the theme problem the other four HTML cases have. This markup is
Keycloak's own, not the `keycloak.v2` theme's, so it carries no per-container
resource hash: the *only* thing standing between it and a golden is the four
values.

What it needs is a way to say "mask the value of this attribute at this place in
the HTML". Nothing else in the catalogue wants one today, which is why it is
filed rather than built - and why the P3 plan says so explicitly rather than
growing the harness a feature to land one case.

**2026-09-01, and the reopening condition was tested and not met.**
`oidc/authorization/prompt-create` is now the second case that wants this
mechanism - it is the one theme page still parked, and it carries a `tab_id` and
a `checkAuthSession` argument that move per request. That is **two** cases, and
this entry closed on one; a third is what should reopen it.

P13 is deliberately **not** counted as that second case. Seven of the eight
parked theme pages wanted no HTML masker at all: they wanted one unconditional
substitution of an installation-wide constant, which is `ReplaceIssuer`'s shape
and has no catalogue surface, where this entry asks for a mask per case and per
position.

Worth recording because ground 4 of this entry anticipated it. An earlier cut
wrote the resource-version pass, measured **prompt-create's** diff, found the
segment was one churn source of three, concluded "a third of the churn" and
reverted the pass. True of prompt-create; false of the other seven, where the
segment was the whole of it - and false of prompt-create too, since `client_data`
turned out to be stable and the movers are two, not three. A judgement made from
one example and generalised, which is the failure this project keeps paying for.

## F39: a success redirect's golden masks its whole Location, so the query key order is unasserted

Found 2026-08-29, same recording.

The five browser cases whose response is the redirect carrying an authorization
code mask the entire `Location` header, because it holds a `code` and a
`session_state` the case's own request mints and no fixture can capture by name.

What that costs is measured and specific: the query key order is
`state`, `session_state`, `iss`, `code`, with `state` dropped rather than
emptied when the request sent none. The error redirects do not have this
problem - after `ReplaceIssuer` they hold nothing per-request, so their golden
pins the error code, the description and the key order exactly - which is what
makes the loss visible as a loss rather than as the way things are.

A `Case.VolatileQueryParams`, naming the parameters of a header's URL to mask
rather than the header, would fix it in about twenty-five lines applied on both
sides of the comparison. It was left out of P3's first cut deliberately: the
cut's job was the fixture, the five affected cases are `Recorded` rather than
`Implemented`, and a mechanism added to improve a golden nothing yet compares is
a guess about what the next cut wants.

**2026-08-29: still open, and the design above is wrong.** It does not cover its
own fifth case. `oidc/authorization/response-mode-fragment` puts `state`,
`session_state`, `iss` and `code` in the `Location`'s **fragment**, not its
query - measured, and in the observed document's `response_mode` table. A masker
reading `url.Parse(v).Query()` finds nothing there, masks nothing, and writes a
live authorization code into a committed golden which then churns on every
recording. That is precisely the failure `normalize.go` names in its own doc
comment: masking nothing while claiming to have checked is worse than failing
loud.

Corrected requirement, for whoever promotes those five cases: mask the named
parameters in the query **and** the fragment, and **error** when a named
parameter is in neither rather than passing. The trigger is unchanged - the cut
that promotes them to `Implemented`, because that cut can record the goldens
that prove the masker works on both sides.

## F40: an `available` golden is order-dependent and the shared container pollutes it (closed)

**Closed 2026-08-29, and not at the place this entry points to.** The entry
below offers two candidate fixes and says the choice is a measurement. It is,
and the measurement rejects both: `PristineRealm` meant "recorded before every
other case", and **ordering cannot carry the property at all**.

The proof was already in the repository. The pristine group pollutes itself.
`admin/groups/list` creates a group; `admin/groups/count` counts the realm three
cases later; and that case's `count` is masked to this day because the recorder
said 3 where a pristine replay says 2. Nor can ordering be checked afterwards -
`admin/users/count`'s entire body is the byte `1`, and no guard can tell a
polluted count from a clean one.

So the container resets, not the position. A `PristineRealm` case now gets a
Keycloak of its own, started inside its subtest and terminated with it:
bootstrap plus that case's own fixture, which is exactly what the verifier's
`newFixture` builds. `recordingOrder` is deleted. This case is marked
`PristineRealm`, and that marking now means something the catalogue's order
cannot take away.

Rejected on merit, both in the commit message. *Mark the case and leave the
recorder alone* produces the right bytes today purely because none of the eight
pristine fixtures happens to create a realm role, and pins the golden to
catalogue order - which is `admin/groups/count`'s defect, already realised.
*Record every case against its own container* is honest and costs three hundred
Keycloak starts, over two hours for a run meant to be a habit.

Measured on both regimes, whole `make record` runs against a live 26.7.1 with
the image already pulled:

| Recorder | Whole run | Goldens wrongly rewritten |
|---|---|---|
| shared container, pristine cases first | 27s | `admin/role-mapper/group-realm-available`, with **18 roles, 13 of them probes** - and PASS reported |
| a container per pristine case | 147s | none |

Every other golden came back byte-identical apart from F23's three known
churners, which is the evidence that the new recorder reproduces the committed
contract rather than merely producing a different one.

The guard was widened in the same cut: see **F45**, which is what the last
paragraph below was really pointing at.

What the finding said, kept for the record:

Found 2026-08-29 while re-recording for P3.

`make record` shares one container across the whole catalogue, and the verifier
builds a **fresh** in-process handler per case - `serve` calls
`newFixture(t, f.State)` every time. For a case that enumerates the realm the
two are not equivalent, and `Case.PristineRealm` exists for exactly that.

`admin/role-mapper/group-realm-available` is not marked `PristineRealm` and it
enumerates the realm's roles. Its committed golden holds the five bootstrapped
realm roles; a fresh recording produced eighteen, the extra thirteen being the
`gloak-probe-*` roles other fixtures create. The golden was reverted rather than
committed, because the change has nothing to do with P3 and pinning it would
make the case pass only for as long as the recording order happens to hold.

`TestPristineRealmGoldensAreNotPolluted` did not catch it: it checks
`"clientId":"..."` against the clients fixtures create, and these are roles.

Two candidate fixes, and the choice is a measurement rather than a preference.
Marking the case `PristineRealm` moves it to the front of the recording, which
works only if nothing before it in the *pristine* group creates a role. Making
the assertion `Unordered` does not help at all, since the difference is
membership and not order. The real question - whether Keycloak's `available`
listing is meant to be read as "the whole realm minus what the holder has", in
which case any golden of it on a shared container is fragile - has not been
asked.

## F41: the parity comment's 403 tolerance identified the wrong thing (closed)

Found 2026-08-29 by reading the workflow rather than by a failing run.

The "Compare and comment" step grepped `gh`'s stderr for `HTTP 403` and, on a
match, wrote the comment to the run summary and let the job pass with a summary
asserting the cause: "a pull request from a fork gets a read-only token, so the
API answered 403". Nothing had checked that. A fork's read-only token is **one**
cause of a 403; a secondary rate limit is another and a permission revoked at
the repository or organisation level is a third. The last two are this
repository's own configuration, both deserve a red build, and both were being
swallowed under a sentence naming a cause nobody had established. The failure
mode is the bad one: the job goes green, the comment is not on the pull request,
and the summary explains it with a fact that is false.

**Closed** by requiring `github.event.pull_request.head.repo.fork` - passed in
as `IS_FORK` - in addition to the grep, and by rewriting the message to say only
what the two conditions together establish.

Two things for a later reader. `head.repo` is `null` when the fork has been
deleted, so `IS_FORK` arrives empty and the tolerance does not fire; the job
goes red, which is the safe direction, but the message will not say why. And the
tolerance now covers a refused **lookup** as well as a refused post, because F42
routed both through one status.

Untested, and that is not an oversight: it is YAML, and the parity design's §10
says YAML is not tested here. What exists instead is a local `bash` simulation
with `gh` and `cmd/parity` stubbed, run against the old script and the new one
over eight scenarios, and it is evidence about `bash` rather than about GitHub
Actions.

## F42: `set -o pipefail` was read as missing its `set -e`, and the hazard runs the other way (declined as stated, hazard fixed)

Found 2026-08-29. **The finding as filed was wrong, and acting on it literally
would have made a no-op that misinforms.**

The claim was that `set -o pipefail` without `set -e` is half a safety measure.
It is not: GitHub runs a `run:` step with no `shell:` as `bash -e {0}`, so `-e`
is already on. Writing `set -e` into the script would tell a reader it was
turned on by that line.

The real hazard runs the opposite way. `id=$(gh pr view ... | sed ...)` is a
plain assignment, so `-e` applies to it, and `pipefail` hands it `gh`'s status
rather than `sed`'s. A transient lookup failure therefore killed the step
outright - before the 403 fallback and before `exit $status`. And with
`pipefail` **off** it is worse rather than better: the empty `id` is
indistinguishable from "no comment posted yet", so the script posts a second
comment beside the one it could not see, against the design's
one-comment-updated-in-place rule.

**Fixed** by giving the lookup its own `|| gh_status=$?` and routing it into the
same handling as a failed post, so the step behaves identically whichever flags
the platform sets. `pipefail` stays, and is now load-bearing rather than inert.

The general lesson, which is why this entry keeps its wrong premise: a finding
about a shell flag is a finding about a platform's defaults, and the defaults
were not checked before it was filed.

## F43: `make lint` was weaker than the gate it stands in for (closed)

`make lint` ran `go vet ./...`. CI runs that **and** `go vet -tags docker ./...`.
Without the tag the docker-tagged files are not compiled at all, so `make
record`, `make oracle` and the Postgres driver suite could stop building while
the local target stayed silent. A target weaker than the gate is worse than no
target: a contributor runs it, gets silence, and is broken by CI anyway.

**Closed**: `make lint` now runs both invocations. Neither covers the other.

## F44: the parity comment said "no change" for work that changed something (closed)

Four chapters have no denominator - nobody has counted their surface - so the
meter leaves their served counts out of the total. Behaviour served in one of
them moves a row in the table and cannot move the total, and the comment printed
`Parity: N of M, no change.` directly above a table reading `+3`. A comment that
says two things at once and resolves neither.

**Closed**: `Render` now tells three cases apart - nothing moved (`no change`),
a rearrangement with a flat total (`total unchanged`), and work in an
unenumerated chapter (`total unchanged` plus a paragraph naming why the total
could not move). `ChapterDelta` carries the `Enumerated` flag to make the third
distinguishable, and `internal/parity`'s tests pin all three shapes. Ten
mutations were applied and ten died, the original defect restored verbatim among
them.

## F45: the pollution guard watched one resource family of four (closed)

Found 2026-08-29 while fixing F40, and it is **why** F40 got past the guard.

`TestPristineRealmGoldensAreNotPolluted` searched goldens for
`"clientId":"<value>"` against the clients fixtures create. Fixtures create
roles, groups, users and - since P4's first cut - realms as well, so the blind
spot was four times the size of the one thing being watched. The body that
produced F40 holds **zero** occurrences of `clientId`.

**Closed.** The guard now reads every creation body for the key it named its
object by - `clientId`, `username`, `realm`, `name` - from two sources: fixture
steps **and a case's own request**. The second source is not decoration:
`admin/roles/create` POSTs `{"name":"gloak-probe-role-create"}` and that role is
in the realm for everything recorded after it. Reading fixtures alone named
twelve of the thirteen probe roles in the polluted recording, and the
thirteenth was this one.

Three details that are load-bearing rather than defensive, each established by
breaking it:

- A case's **own** fixture and the case itself are exempt, because both run on
  both sides of the comparison. Removing the exemption fails on
  `admin/groups/list`, whose golden legitimately holds its own fixture's group.
- A name is matched **against the key its creation body used**, not as a bare
  substring, or `gloak-probe-group` would report the
  `gloak-probe-group-mapped` a sibling fixture creates.
- A POST whose body is a JSON **array** is not a creation. The role-mapping and
  composite writes are POSTs naming roles that already exist, and reading
  `[{"id":"...","name":"manage-users"}]` as a creation puts six bootstrapped
  admin role names into the guard's set.

`TestPollutionGuardSeesEveryCreatedFamily` proves the guard can fail in each of
the four families separately, and
`TestPollutionGuardReadsTheCataloguesOwnCreates` proves the second source is
wired - the four families are each also created by some fixture, so deleting the
catalogue loop left every other test green.

## F46: a masked header is asserted on presence alone, and nothing else (closed)

**Closed 2026-08-30 by `Case.VolatileTailHeaders`**, which masks a header's
final path segment and compares everything before it exactly.

The mechanism was designed **after** measuring all seven admin `Location`s, not
from the four the entry had in mind - and that is what the design turned on.
Only four end in something minted: `POST .../clients`, `.../users`, `.../groups`
and `.../groups/{id}/children`. `POST .../roles` and `POST .../clients/{id}/roles`
end in the **role's name** and `POST /admin/realms` in the **realm's name**, so
those three carry nothing per-request once `ReplaceCaptured` and `ReplaceIssuer`
have run, and they now assert their `Location` **whole**. `MaskURLTail` refuses
a tail that is not a UUID rather than masking it, which is the F39 lesson
applied: masking nothing while looking as though it had checked is the failure
mode.

The measurement also corrected a route: the child create's `Location` is
`/groups/<child uuid>`, **not** `/groups/{parent}/children/<child uuid>`. The
route that makes a child is not the route that addresses it, and the mask had
been hiding that too.

What the finding said, kept for the record:


Found 2026-08-29 while reading `diff` for F39. A neighbour of F13.

`diff` compares a `VolatileHeaders` entry by checking it is present and its
first value is non-empty. So the seven admin cases that mask `Location` would
accept `Location: x`. The value really is per-request - it ends in a
server-minted UUID - but everything before that UUID is not, and none of it is
asserted: not the scheme, not the host, not the path that says which collection
the new object landed in.

It is the same gap F39 describes for the browser redirects, in a family that is
`Implemented` today rather than `Recorded`. Fixing it means re-recording those
goldens, so it is filed rather than done.

## F47: `admin/groups/count` can have its measured number back (closed)

**Closed 2026-08-30.** The claim was verified rather than trusted - a
bootstrapped realm holds no groups, so the fixture's parent and child make the
count a deterministic `{"count":2}` on both sides - the mask was dropped and the
number re-recorded. The one place in the catalogue where F40's defect had been
papered over instead of fixed is now a measurement again.

What the finding said, kept for the record:


`admin/groups/count` masks `count` with a comment saying why: "the recorder
shares one container, so any fixture that creates a group moves it - the first
recording of this case said 3 where a pristine replay says 2". That reason is
gone. With a container per pristine case, its fixture (`admin-token-group-tree`:
a parent and a child) makes the count a deterministic 2 on both sides.

Dropping `Volatile: []string{"count"}` and re-recording turns a masked number
back into a measurement. It is the smallest possible piece of work and it undoes
the one place in the catalogue where F40's defect was papered over instead of
fixed.

## F48: the conformance harness cannot express a repeated query parameter (closed as a mechanism)

**Closed 2026-08-30 by `Request.RawQuery`**, the query string sent verbatim. It
**replaces** `Query` rather than adding to it, because merging the two would
need an order and there is no honest one, and it is deliberately **not**
expanded: `Expand` rewrites `Path`, `Query`, `Headers`, `Form` and `Body` and
does not reach it, so `TestCatalogIsWellFormed` refuses a `{{name}}` inside one
rather than letting the braces reach the server.

The conformance case was deliberately **not** added: `catalog_oidc.go` belonged
to a concurrent cut. The family is now expressible and the case is owed.

What the finding said, kept for the record:


`Request.Query` is a `map[string]string` and `buildRequest` writes it with
`url.Values.Set`, so no case can send one key twice.

That leaves an entire measured error family - `duplicated parameter`, step 7 of
the authorization endpoint's ten - served, unit-tested in `internal/oidc`, and
under no golden at all. A `[]string` variant, or a raw query-string field on
`Request`, closes it. `case.go` belonged to another cut the week this was found.

## F49: `internal/admin`'s client create does not default the client scopes (closed)

**Closed 2026-08-30, and it was six defects rather than one.** Only the scopes
were filed. Fixing them was not possible without fixing five more, because
`POST /clients` also served the wrong `standardFlowEnabled`, `fullScopeAllowed`,
`protocol`, `nodeReRegistrationTimeout` and `name`, and gave a public client a
`client.secret.creation.time` it does not get. The coupling is the `protocol`
default: **with no protocol on the client, the scope-inheritance filter matches
nothing**, so the scope fix could not be tested until the protocol fix existed.
Both `Recorded` cases that were blocked on this are now `Implemented` and
matching.

The inheritance rule itself was measured over nine creation bodies and is not
what the obvious implementation does. **Naming *either* list - as an array,
empty or not - suppresses inheritance on *both*.** So
`{"defaultClientScopes":["email"]}` produces a client with one default and **no**
optionals, where a per-list nil check gives it the realm's five. That per-list
check was written first here and a mutation caught it, but only after a case was
added that could tell the two apart; see the mutation notes in
`docs/superpowers/handover/p5-client-scopes.md`.

What the finding said, kept for the record:

Keycloak gives a client created with no `defaultClientScopes` the realm's six
defaults and five optionals. Gloak's `POST /admin/realms/{realm}/clients` writes
`[]` for both.

Nothing noticed until `/auth` started validating `scope` against them, and the
consequence is now measurable: **Gloak refuses `scope=profile` on a client
created through its own admin API, where Keycloak accepts it.** The constants
already exist as `defaultScopeNames` and `optionalScopeNames` in
`internal/bootstrap`. Client scopes are P5's; this is the part of them that is
already observable from an endpoint that is already served.

## F50: `GET /auth` answers a fully valid request with the page family's 400 (closed)

**Closed 2026-08-30.** A valid authorization request now serves a login form,
`POST /login-actions/authenticate` checks the credential, and the redirect
carries a real authorization code. The four cases that were `Recorded` because
of this are `Implemented`, and `oidc/authorization`'s `recorded` column is zero
for the first time.

What is still a placeholder is the page **body** - not the flow. As of
2026-09-01 that list is shorter and named: `/auth`'s whole error-page family is
served, and what remains is the login-actions family (F109's), the logout
confirmation, "You are logged out", "Page has expired", the consent page and the
five required-action pages. See F67, closed.

What the finding said, kept for the record:


Deliberate, and documented at the handler rather than hidden. A request that
survives all ten checks reaches the point where Keycloak renders its login page,
which is P13's theme work, so Gloak answers the same 400 envelope its
unknown-client and bad-redirect rejections take.

It is a real divergence from Keycloak, which answers 200 with a login form. The
alternatives were a login form whose `POST` target does not exist, or a status no
measurement supports. It closes when the success path lands. Anyone driving
Gloak by hand will meet it, which is why it is filed and not only commented.

## F51: five of the seven response modes are accepted and not transported

`form_post` and `form_post.jwt` answer **200** with an auto-submitting HTML form;
`jwt`, `query.jwt` and `fragment.jwt` answer with a signed **JARM** assertion in
a `response` parameter, the plain parameters gone.

Measured 2026-08-29 on the **error** path - a request with no `response_type` -
so this is not extrapolated from the success one. Gloak recognises all five as
valid, because refusing them would contradict a measurement, and answers the
page family instead of transporting them: emitting the plain parameters would
hand a JARM client an unsigned error where it asked for a signed one, which is
worse than answering nothing.

The observed document records `form_post` only on the success path and records
JARM nowhere before this.

## F52: the two disabled-flow rejections are served and under no golden

Both spellings - "Client is not allowed to initiate browser login with given
response_type. Standard flow is disabled for the client." and its Implicit twin -
are implemented and unit-tested. No conformance case covers either:
`oidc/authorization/implicit-flow` is deliberately `Pending` as outside P3's
scope, and there is no case for the standard-flow one at all.

Adding either means a fixture client with the flag off, which is a fixture
nothing else needs. Worth doing with the next case that wants such a client
rather than on its own.

## F53: which other goldens enumerate a realm-wide set without claiming `PristineRealm`? (swept, and it came back)

**Swept 2026-08-30. Three cases found, all of them clean today** - which is
exactly what "order-dependent and currently clean" means, and why the
byte-reading guard could not have found them:

- `admin/roles/users` and `admin/roles/groups` list every user or group holding
  a bootstrapped role. Granting `admin` to a created user or group puts it in
  the body, measured live. No fixture grants it, and that was the whole
  protection.
- `admin/realms-admin/default-groups-empty` reads a list that
  `admin/realms-admin/default-group-add` **writes three cases later in the same
  realm**. The first instance where the polluter is a case rather than a
  fixture.

**Then it came back within the week, which is the actual finding.** Three
commits after the sweep landed, P5's cut produced a fourth:
`admin/clients/default-client-scopes` reads a client's inherited defaults, and
two cases earlier in the catalogue add a scope to master's default set, so the
recorder wrote seven entries where a pristine replay serves six. It does not
look like a realm-wide body, which is F53's point restated by example. Both it
and its optional sibling now carry the flag.

The sweep was complete and a one-off sweep cannot hold. Every cut that adds a
fixture writing to a realm-wide set can add another, and one did immediately.

**The derived check was tried and declined on two measurements**, not on taste.
Request shape cannot decide it: `GET /admin/realms/master/clients` with no query
is realm-wide for an administrator, and measured `[]` both before *and* after
pollution for a `query-clients` caller. And replaying every case against a realm
every fixture has touched does not work either, because the fixtures are
deliberately not idempotent - `idempotentCreate` exists for the creates that may
repeat, and the ones capturing a `Location` may not - so putting them all on one
handler produced 22 failures, nine inside the pollution pass itself, and none of
them order-dependence.

What was built instead is a ratchet rather than a finder:
`TestNoGoldenHoldsAnObjectItDidNotCreate` applies F45's check to **all 273**
goldens rather than the ten pristine ones, because the invariant was never the
pristine group's. It fires one step earlier than `TestConformance` - on the
re-record that first pollutes a golden, rather than on the run that then cannot
reproduce it. It does not catch a case that is order-dependent and still clean,
and nothing does; that is what this entry stays open for.

What the finding said, kept for the record:

F40 was one case. The question it raises is not.

`PristineRealm` is a claim a case makes about itself, and nothing derives it. A
golden whose body is a function of the whole realm - every `available` listing,
every count, every unfiltered listing - needs the flag, and the only thing
standing between the catalogue and a second F40 is that somebody noticed. The
widened guard (F45) catches the ones that get **polluted**, which is not the same
set: a case can be order-dependent and currently clean.

The work is a sweep of the catalogue asking, per case, whether a fixture running
before it could change its body. It is cheap to do and cheaper still to do while
the reasoning in F40 is fresh.

## F54: every 204 Gloak sent carried a `Date` header (closed)

Found 2026-08-29 by reading a live 204 off the wire while measuring P4's default
groups.

AGENTS.md says "Gloak deletes the `Date` header on every response". It did not.
`httpx.WriteNoContent` was the one writer that never called `suppressDate`, so
every 204 carried one - the deletes, the client and user updates, the credential
moves, the group joins alike.

**Neither existing guard could see it.** Both go through `WriteJSON`, and the
conformance harness serves through `httptest.ResponseRecorder`, which adds no
`Date` either. So this is a rule with two tests and a hole exactly where the
third writer is, and it was found by looking at bytes on a socket rather than by
running anything.

**Closed**, with a third real-server test beside the two that already existed.

## F55: two client-policy error bodies Gloak does not reproduce

Both measured 2026-08-29 on the client-policies routes.

- An unrecognised field answers 400 `Invalid json representation for
  ClientProfilesRepresentation. Unrecognized field "nosuchfield" at line 1
  column 20.` The line and column are a function of the request body, so
  reproducing the string means reproducing Jackson's parser positions. Gloak
  ignores the field and answers 204. **`PUT /admin/realms/{realm}` has the same
  gap for its own copy of that error**, so this is one follow-up covering two
  endpoints; the conformance case is `Recorded`.
- A profile naming an executor that is not a registered provider answers 400
  `proposed client profile contains the executor, which does not have valid
  provider, or has invalid configuration.` Gloak accepts it. The executor and
  condition inventories belong to an engine it has not built - see F57.

## F56: a new user does not join the realm's default groups

Measured on Keycloak: `POST /users` in a realm holding two default groups
produced a user who was a member of both. Gloak's `POST /users` joins none.

No existing golden changes, because `master` has no default groups and nothing
in the catalogue creates one - but the moment an operator sets a default group,
Gloak and Keycloak disagree about **every user created afterwards**. It is `POST
/users`' behaviour, which is P2's, and P4's cut deliberately did not reach into
it.

## F57: nothing enforces a client policy

Gloak stores client profiles and policies and serves them back on both routes
that read them. No client request is evaluated against any of them.

Filed as a note rather than a defect: serving a field is not implementing it, as
the parity design's §10 says of the realm representation's other 104. It is here
so that "client policies work" is never inferred from "client policies round
trip".

## F58: a paged golden's window is held by a naming convention nobody enforces (closed)

**Closed 2026-08-30** by `TestEveryCreatedObjectCarriesTheProbePrefix`, over the
same `createdObjects()` set the pollution guard reads.

Its first run turned up **seven** real exceptions and none was renamed, which is
the interesting part. Two matter: `aa-gloak-srch-kid` sorts before every
bootstrapped name in the realm - exactly this entry's hazard, one resource family
over - and three group names whose sort positions **are**
`admin/groups/search-pages-the-matches`'s measurement, so renaming them would
change a measurement rather than protect one. Each is declared in
`namedOutsideTheConvention` with its reason, and an entry that stops matching
anything fails too, so a reason nobody has re-read cannot sit there.

An eighth was a phantom and a defect in the pollution guard: see **F71**.

What the finding said, kept for the record:


`admin/roles/list-realm-page-no-search` sends `first=1&max=2` with no `search`,
and its golden holds `create-realm` and `default-roles-master`. The case's
comment argues, correctly, that every realm role a fixture creates is named
`gloak-probe-...`, which sorts after `default-roles-master` and cannot enter the
window. Six of the user listings rest on the same kind of argument -
`?username=admin` is a substring filter no `gloak-probe-*` username matches.

**Every one of those arguments is about names, and nothing enforces the naming
convention they rest on.** A fixture creating a realm role called `a-probe-role`,
or a user called `admin-probe`, breaks several goldens at once. It breaks them
loudly, which is the good case - but it breaks them in cases whose comments then
read as though they had been checked.

A test asserting that every object any fixture or case creates is named
`gloak-probe-*` turns six written arguments into one checked one, and it is
cheap: `createdObjects()` already collects exactly that set for the pollution
guard, so asserting a prefix over it is three lines. Not done at the time
because it is a new rule *about the catalogue* rather than a fix to a measured
divergence, and imposing one belongs to whoever owns the convention.

## F59: `Case.Unordered` silently sorts only the root when the root is one of its paths (closed)

**Closed 2026-08-30 by handling it rather than erroring**, and the judgement is
worth keeping. Erroring on the combination was the cheaper option and this entry
invited it - but it would have left `admin/client-scopes/list` masking
`*/protocolMappers` whole, and **thirty-five bootstrapped protocol mappers under
no golden**. The walk now runs once per distinct path depth, deepest first;
inside one depth no path can be a prefix of another, because being a prefix
means being shorter. Four entry points collapsed into one `editPaths`, so the
change is smaller than the code it replaced.

The two goldens were re-recorded and Gloak reproduces all thirty-five mappers
byte for byte, `config` key order included - a Java map that needed **no**
`UnorderedKeys` retreat.

What the finding said, kept for the record:


`editor.sortArray` decodes the value it matched in one go, so a path matching
the root consumes the whole document and the nested paths are never visited.
`Unordered: {".", "*/protocolMappers"}` sorts the first and ignores the second,
**with no error**.

Silence is the part that matters: the case looks as though it asserts the nested
set and does not. Both orders are unstable in the case that found this, so
`admin/client-scopes/list` masks `*/protocolMappers` whole and the thirty-five
bootstrapped protocol mappers are under no golden at all.
`TestBootstrappedClientScopeMappers` in `internal/admin` asserts one scope's
fourteen mappers and one full configuration directly, which closes the hole for
the richest of them and for none of the rest.

The fix is in `normalize.go`. It should **error** on the combination rather than
learning to handle it, unless handling it is cheap - an unsorted assertion that
believes itself sorted is the same disease as F39's.

## F60: a `saml` client created through the Admin API gets no keystore

Keycloak generates a signing certificate and a private key for a `saml` client
created through `POST /clients`, sets twelve `saml.*` attributes and
`frontchannelLogout: true`. Gloak sets none of them.

P11's, and filed here because it is observable from an endpoint that already
ships rather than from SAML itself.

## F61: `PUT /clients/{uuid}` ignoring the two scope lists is unasserted

Keycloak ignores `defaultClientScopes` and `optionalClientScopes` on the update
path - measured. Gloak also ignores them, because `clientRepo.Update` does not
touch the attachment table.

**But nothing asserts it**, and the merge in `updateClient` does carry both
lists through `newClientFrom`. The agreement is an accident of which table the
repository writes, not a decision anything guards, and a case would cost one
fixture.

## F62: `scopes_supported` is still a constant

The parity roadmap's §6 second debt. `internal/oidc/discovery.go` emits a list
no model backs. The realm's client scopes now exist as rows and could back it,
which they could not when the debt was taken on.

## F63: the protocol mapper engine is still staged

Roadmap §6's first debt, and the note needs updating rather than repeating. All
thirty-five bootstrapped protocol mappers are now **stored** and served in the
client scope representation; token issuance still reproduces the measured claim
set directly rather than deriving it from them.

That was the plan - the roadmap staged the engine behind the scopes - and the
prerequisite is now built. What remains is the derivation.

## F64: Gloak issues no `AUTH_SESSION_ID` (closed)

**Closed 2026-08-30.** `GET /auth` issues one, and its decoded value is
`<root id>.<86 chars>` where the root id is the same value that becomes the
redirect's `session_state`, `KEYCLOAK_IDENTITY`'s `sid` and the authorization
code's second part.

Two things about it are Gloak's own and are filed rather than claimed:
`KC_RESTART` is a **handle** where Keycloak's is a self-contained JWE (F73), and
`AUTH_SESSION_ID`'s second half is a stored random string rather than a derived
one (F74).

What the finding said, kept for the record:


Keycloak sets a fresh one on the logout 302 and on both 200 pages. Gloak has no
authentication-session concept and minting a cookie value would be inventing an
observable, so it sets none.

The conformance cases mask `Set-Cookie` as volatile and assert none of it, so
nothing catches this. Closes when P13 builds authentication sessions.

## F65: the browser-session branch of the logout confirmation page is unmodelled (closed)

**Closed 2026-08-30.** Gloak reads `KEYCLOAK_IDENTITY`, so the branch is
reachable and served. A browser session changes exactly one cell of the logout
grid, which is measured rather than assumed.

The sentence this entry was filed against - "Gloak has no browser session
cookie, so it always takes the second branch" - **was already false when it was
written**, because the login cut had set the cookie the same day. That is on the
record because it is the failure mode this list keeps meeting: a claim about
Gloak's own capabilities, written from what the author had just built rather
than from what the tree held.

What the finding said, kept for the record:


Keycloak serves `Logging out` when a session cookie is present and redirects
when it is not. Gloak has no session cookie and therefore always takes the
second branch.

That is the correct answer for every request Gloak can receive **today**, and it
becomes a divergence the moment P13 sets one. It is the one place the logout
endpoint has fewer branches than Keycloak, and it is written down rather than
left to be discovered.

## F66: the two logout cookie clears are recorded and no longer measured

`oidc/logout/rp-initiated-with-id-token-hint` moved off the `browser-logged-in`
fixture, so `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION` being cleared with
`Max-Age=0` now lives in the observed document and in no test.

It was asserted by no test before either - `Set-Cookie` was masked - so this is
the loss of a recording rather than of a guard. Re-earn it when P13 makes the
browser fixture replayable.

## F67: the logout page's three instructions are one placeholder (closed 2026-09-01)

**Closed.** All three are served, each from the branch measured producing it,
and `TestLogoutPageInstructions` holds the eight-cell grid over `client_id` and
the target that places them. The grid is the part worth keeping: an unknown
`client_id` and a real one give the **same** sentence while an unknown one and
an absent one do not, so the sentence turns on the request naming *something*
and the page's chrome turns on that something resolving - two questions with two
answers on one response.

What the finding said, kept for the record:


Keycloak distinguishes `Invalid parameter: id_token_hint`, `Invalid redirect
uri` and `Missing parameters: id_token_hint`; Gloak's placeholder body says
`We are sorry...` for all three. The envelope is served and the branch that was
taken is guarded by `internal/oidc`'s own tests, so what is missing is the
prose. P13's, with F50.

## F68: a relative redirect target is not resolved, at either endpoint

Keycloak accepts `post_logout_redirect_uri=-` against a `##` list containing `-`
and answers `Location: http://127.0.0.1:8092/-`, resolving the relative value
against the server's base URL. Gloak's `matchRedirectURI` is a string comparison
and would emit it unchanged.

**One follow-up for two endpoints**: it is the same unhandled case as
`security-admin-console`'s host-relative `/admin/master/console/*` at `/auth`.

## F69: `make record` rewrites `Pending` theme-page goldens on every run (closed)

**Closed 2026-08-30 by `GoldenIsAsserted(c Case) bool`** in `case.go`, the one
predicate both the recorder and `TestConformance` read, so the two cannot drift
about which goldens are compared and which are merely present.

The "unless asked" this entry called for is **promoting the case to
`Recorded`** - which is what `Recorded` already means, and which a reviewer sees
as a one-word edit in the diff, where an environment variable is a thing nobody
sets and nobody reads.

Verified across four container starts through `make record`'s own
testcontainers: with the skip deliberately removed, exactly the four names below
moved and nothing else; with it in place, **none**, and 290 goldens were
rewritten with identical bytes.

What it does **not** do is keep a parked golden honest. Nothing compares it, so
nothing notices when Keycloak's answer moves underneath it - which was already
true before the recorder stopped rewriting it. Whether a `Pending` case should
carry a golden at all is **F72**.

What the finding said, kept for the record:


Four goldens now churn their whole body on every recording because the
`/resources/<hash>/` segment is regenerated per container start:
`oidc/authorization/invalid-redirect-uri`, `oidc/authorization/unknown-client-id`,
`oidc/logout/invalid-post-logout-redirect-uri` and, since 2026-08-30,
`oidc/logout/invalid-id-token-hint`. All four are `Pending`, so nothing compares
them, and the churn is pure noise in the one diff this project asks people to
read carefully.

The count grew from three to four the same day the problem was filed, by a cut
that had filed it - which is the argument for fixing it rather than listing it.
**A recorder that left a `Pending` golden alone unless asked** would make `make
record`'s diff readable. Reverting the churn by hand works and is not a rule.

This supersedes the "three churners" wording in F23 and in `README.md`.

## F70: `TestFixturesAreWellFormed` assumed a GET never writes (closed)

`GET /logout` with a valid `id_token_hint` ends the session, so a fixture step
that is a GET, captures nothing and changes everything was rejected by the
"dead weight" rule - a rule that had been right until an endpoint mutated on a
GET.

**Closed 2026-08-30**: `Step.Mutates` declares it, and the test now also rejects
`Mutates` on a step that *does* capture something and on any non-GET, so the
escape hatch cannot be used to wave through a step that is simply unnecessary.

## F71: the pollution guard read one object per body where a body can carry several (closed)

Found 2026-08-30 at the fold, by two cuts that were green on their own and
failed together.

F45's guard reads the most specific `createdKeys` entry a creation body carries,
and F58's first run narrowed that to **one object per body** to kill a phantom:
`{"clientId":"gloak-probe-described","name":"A name"}` was being reported as a
role called `A name`, which is `ClientRepresentation.name`.

Applied per **body**, that rule is wrong in the other direction. A create can
carry objects nested inside it: `POST /clients` with
`{"clientId":"...","protocolMappers":[{"name":"..."}]}` creates a client **and**
two protocol mappers, and they outlive the request exactly as the client does.
The client's `clientId` won and the nested mappers were never recorded - which
lost them from the guard, and, because the exemption reads the same set, made
the guard report a false positive against the very case whose own fixture had
created them. A client-scope fixture and a client fixture share the mapper
names, so only the scope's were attributed.

**Closed** by applying the rule per JSON **object** rather than per body. The
phantom stays suppressed - a client's display name loses to its `clientId`
inside one object - while objects nested in arrays under it are recorded.

Two shapes the old regular expression excluded by accident and the walk has to
exclude on purpose: a body that does not parse, and an empty name.
`admin/users/create-malformed` and `admin/client-scopes/create-empty-name` send
one each, on purpose, and both are measured answering 400. Both are creates that
create nothing.

**The lesson is about integration, not about either cut.** Neither author could
have seen it: each guard and each fixture was correct against the tree its
author had. It is the second finding this week that only existed in the
combination.

## F72: should a `Pending` case carry a golden at all? (closed - they stay, declared)

**Decided 2026-08-30: they stay, and each says why.** There are **seven**, not
the four this entry counted - the device, CIBA and dynamic-registration refusals
had been parked without anybody counting them, which is itself the argument for
declaring rather than tolerating.

`parkedGoldens` names all seven with the reason each is kept, and says what a
reader is to do with such a file: **read it as a measurement and never as a
contract.** `TestEveryParkedGoldenIsDeclared` refuses an eighth arriving without
one, a declaration whose file has gone, one whose case is no longer `Pending`,
and one naming nothing in the catalogue.

**2026-09-01: there is one.** P13 promoted seven theme pages to contracts, and
`oidc/authorization/prompt-create` is the only parked golden left. The decision
above is unchanged in substance and nearly out of scope: `TestNoPendingGolden
IsCompared`'s "parked == 0" guard is one promotion from firing, and when the
last one goes **that test has to be deleted rather than loosened** - the comment
there says so, and this is the entry that will be read when somebody wonders
why.

The grounds for keeping rather than deleting: a declared exception carrying its
reason is the shape this project already uses three times over -
`UnorderedKeys`, `VolatileHeaders`, `namedOutsideTheConvention`. And deletion
was only defensible for four of the seven, so it would have produced a rule with
three exemptions instead of an exemption list with seven entries.

What the question was:


F69 stopped the recorder rewriting them, which was the cost. The question it
leaves is whether the file should be there.

Nothing compares a `Pending` golden, so nothing notices when Keycloak's answer
moves underneath it - true before F69 and true after, since the rewrite was
compared by nothing either. What the file buys is a reader being able to see
the measured bytes without a container. What it costs is four theme pages of
committed HTML that look like a contract and are not.

Worth deciding once, for all four, rather than per cut.

## F73: `KC_RESTART` is a handle where Keycloak's is a self-contained JWE

Keycloak's `KC_RESTART` carries the restart state inside the cookie, signed and
encrypted. Gloak's is a handle into the in-memory authentication session store.

Observably the same on the branches measured so far - the cookie is opaque to a
client either way - and different the moment there are two Gloak processes, or
the moment something restarts. It is filed beside F75 rather than inside it,
because the fix is not the same fix.

## F74: `AUTH_SESSION_ID`'s second half is stored rather than derived

Its decoded value is `<root id>.<86 chars>`. Gloak stores those 86 characters;
whether Keycloak derives them from anything is unmeasured, and nothing
observable distinguishes the two today.

Filed so that the next person to look does not have to re-establish that it was
a choice rather than a measurement.

## F75: the authentication session and the authorization code are in memory

Both live in the handler, not the store. That is the faithful model - Keycloak
keeps both in Infinispan caches rather than in its schema, because both are
short-lived - and it means **this cut is single-process**: two Gloak replicas
will not share a login in progress or a code awaiting exchange.

That matters here in a way it does not for Keycloak, because realm signing keys
were deliberately persisted so that two replicas agree. The design to use is
written in the P13 handover; the trigger is whoever first runs two replicas.

## F76: the `authorization_code` grant is not served at the token endpoint (closed)

**Closed 2026-08-30. Gloak can complete a browser OAuth flow**: `GET /auth` to
login form to code to token, for a public client and a confidential one. PKCE is
carried onto the code, `oidc/token`'s `recorded` column is zero, and between it
and `oidc/authorization` the browser flow holds no case waiting on an
unimplemented endpoint.

The measured contract turned out to be right and **incomplete**: the observed
document's table said "Every rejection" over eight rows and there are twelve.
See F77 for the one thing the flow still does not do.

What the finding said, kept for the record:


The code is minted, stored, and spent on the first attempt. Redeeming it is
eight measured rejections and its own cut, and PKCE is carried nowhere yet:
`/auth` validates `code_challenge` and `code_challenge_method` and neither is
attached to the code.

Until it lands, a browser login produces a code nothing can exchange.

## F77: SSO is not recognised (closed)

**Closed 2026-08-30.** A second `GET /auth` from a browser holding
`KEYCLOAK_IDENTITY` is a 302 with a real code. The original user session id is
carried into a fresh `AUTH_SESSION_ID`, the original `auth_time` survives, and
the first session stays refreshable.

`prompt` turned out to be a **set of tokens** rather than a value, ignoring
unknown ones, and it is the parameter that makes all of this observable.

What the finding said, kept for the record - and note that **one item of it was
wrong**: `prompt=none` does not *clear* `KC_RESTART`, it never sets one, and the
clear is conditional on the request having presented one.


Deliberately scoped out of the code-grant cut, and **measured anyway so the next
one does not repeat it**: five cookies, the *original* user session id carried
into a fresh `AUTH_SESSION_ID`, the original `auth_time`, the first session
still refreshable, and `prompt=none` clearing `KC_RESTART`.

**F65 closes with it** - the logout confirmation page's branch is unreachable
until a browser can be recognised as already signed in.


Gloak sets `KEYCLOAK_IDENTITY` and never reads it, so a second `GET /auth` from
a browser that has already logged in serves the form again rather than
redirecting straight through.

That is also what makes F65's confirmation-page branch unreachable today, so
the two close together or not at all.

## F78: a protocol mapper id is not realm-unique in Gloak (still open, and this entry was wrong three ways)

Corrected 2026-08-30 by the cut that went to close it, and handed back rather
than closed: it needs a **server-wide** index, which is a second migration in a
branch that had already spent its number.

Three corrections. The id is unique across the **server**, not the realm - a
client scope created in a *different* realm carrying a mapper id already in use
in master is a 409. It is enforced on **five** routes, not three: `POST
/clients`, `POST /client-scopes`, `PUT /clients/{uuid}`,
`POST .../protocol-mappers/models` and `POST .../protocol-mappers/add-models`.
And which of the two 409 messages you get is decided by **where** the colliding
mapper is - same container or another - not by which route asked, which was an
artefact of the probes.


Keycloak's are. This bit the cut that found it: three fixtures shared an id and
three client scopes were silently never created, which is the failure mode of a
constraint that exists upstream and not here.

## F79: two protocol mapper providers seed config keys of their own

Measured, and Gloak stores what it is given. A create naming one of the two
comes back from Keycloak with keys the request did not send.

## F80: `internal/javamap` models the wrong constructor for a sized map (closed, and this entry's model was wrong)

**Closed 2026-08-30, and the model below was falsified on re-measurement.** It
fits 13 of the 14 vectors, and the fourteenth says one table cannot be right:
`{claim.name, jsonType.label, user.attribute}` comes back in **one** order from
all six of its insertion orders, so something ahead of the final table already
put those three in hash order - while `{zz, aa, mm}` comes back in whichever
order it went in, also from all six, so that something does not separate
*those*.

The model that fits is **two** tables: one asked for `7n/4` buckets, then one
asked for `n`, with collisions in the second chaining in insertion order. The
`7n/4` was read off the server at **every entry count from 1 to 50** and is
pinned by four boundaries where the answer flips - n=5/6, 9/10, 18/19, 37/38 -
and no plain multiple of `n` fits all four.

**Both shapes the follow-up offered were needed, not one.** `SizedKeyOrder`
models the sized constructor and `KeyOrder` keeps the no-argument one, as two
exported functions rather than one with a heuristic, because which constructor
built a Java map is a fact about the Java and not something a Go function can
read off the keys. `SizedKeyOrder` also takes the count the map was **built
for**, because a create that mirrors a config key appends the mirror after the
first table pass.

14 of 14 pass, and so do 495 of 495 across every sweep taken. `KeyOrder` gets
**seven** of the fourteen wrong, not six - this entry counted a vector set
nobody had written down - and `TestKeyOrderIsWrongOnHalfTheMapperConfigs` pins
that count.

**The most useful thing this produced is about tests, not about Java.** The
fourteen vectors do **not** pin the rounding rule: mutating `tableSizeFor`'s `<`
to `<=` passes all fourteen and fails only the boundary probes. A cut that added
the vectors and stopped would have shipped an unpinned rule that looked
measured. The boundary probes exist because somebody asked what the vectors did
*not* pin.

What the finding said, kept for the record:


A protocol mapper's `config` is a Java `HashMap` **sized to its entry count**,
which is a different table size from the one `javamap` models. Fourteen vectors
were measured against it and it gets **six** wrong.

Nothing is broken by this today: the conformance cases use config key sets
measured to be order-stable, so their goldens assert real bytes with no
`UnorderedKeys` mask. What is wrong is the package's own claim about what it
reproduces. The vectors are in the P5 handover.

## F84: `POST /users` ignores an inline `credentials` array (closed, and it was six)

**Closed 2026-08-30. Filed as one defect, shipped as six** - the second time
this has happened, after F49.

The array was the headline. Measuring the whole shape found: `PUT /users/{id}`
ignores the same field; an entry with no `value` is a **500** on the create and
a **400** on the update, with the whole request rolling back; `value:""` is a
201 storing a credential with no `credentialData`, which is Keycloak's own
defect; an empty body on `PUT` is a 400 where the create's is a 500, and Gloak
shared one decoder and was wrong on the update; and `invalid_request` is a
**syntax** failure where `unknown_error` is a **binding** one, a distinction
that only became reachable once the field was read at all.

**The "same code path as `reset-password`" hypothesis was refuted twice.**
`userLabel` is never read here where reset-password *clears* it, and
`temporary` is a **disjunction over the array that only ever adds** where
reset-password with `false` removes.

What the finding said, kept for the record:


Keycloak honours it: a user created with `{"username":"x","credentials":[{"type":"password","value":"..."}]}`
can use the password grant immediately. Gloak accepts the body, answers 201, and
stores no credential.

**Found by accident**, which is the part worth keeping: a fixture written the
short way recorded green against the reference container and then failed the
verifier at the password grant. The create is not what caught it; the grant two
steps later was. A defect in `POST /users` that no case for `POST /users` would
have found.

## F85: refresh loses `auth_time`

`auth_time` is a property of the **user session**, survives a refresh, and is
the login time rather than the issuance time - measured `iat - auth_time == 6`
on a token minted six seconds after the login.

Gloak cannot reproduce the refresh row without a column in `internal/store`,
which the cut that measured it did not own.

## F86: the access token's `jti` carries a grant prefix

`onrtac:`, `onrtro:`, `onrtrt:`, `onltac:` - measured on all four grants, so
this is pre-existing rather than something the code grant introduced. Gloak
mints a bare UUID.

## F87: a lightweight client's refresh token omits `sub` and `aud_x`

Live on `admin-cli`, so it is reachable from the default bootstrap rather than
from a client somebody has to configure.

## F88: whether introspection carries `auth_time` is unmeasured

It could not be measured from the outside: a client cannot introspect a token
whose `aud` excludes it, which is the rule AGENTS.md already records as the
reason introspecting your own access token is refused. Filed so the gap is on
the record rather than looking like an answer nobody wrote down.

## F89: `SizedKeyOrder`'s caller discards the count it needs (closed, and it was worse)

**Closed 2026-08-30.** The lost count was real and so was a second thing this
entry did not know: **`mapperConfig` was not ordering the config at all.** There
was no call to make the count matter. Every existing case used an order-stable
key set, so "a protocol mapper's `config` key order is reproduced exactly" was
an accident rather than a property - and one request separates all three
candidate implementations.

What the finding said, kept for the record:


`mapperConfig` in `internal/admin/protocolmappers.go` appends the mirrored
config keys and, in doing so, loses the number of keys the request carried -
which is `SizedKeyOrder`'s first argument. Nothing is wrong today because the
conformance cases use order-stable key sets, but the function cannot be used
correctly from there until the count survives.

Reported rather than changed by the cut that found it: `internal/admin` was not
its file.

## F90: `internal/conformance`'s `attributes` retreat has never been re-examined (closed - asked, and the answer is "it depends which map")

**Closed 2026-08-30 with this entry's own third outcome**: reproducible for some
cases and not others, and the two halves have different reasons.

| case | disposition |
|---|---|
| `admin/roles/list-realm-full` | mask **removed** - it covered a one-key object and was inert |
| the five `admin/clients/*` | mask **kept**, blocked on the *serialiser*, not the model - F95 |
| the two `admin/realms-admin/*` | mask **kept**, blocked on a bucket collision, which is the documented limit |

**A client's `attributes` is placeable and the old reason has stopped being
true.** All five key sets a default install has come back in `KeyOrder`'s order,
sorting is wrong on all five, and the keys occupy buckets 0, 2, 3, 9 and 11 at
the default 16 - nothing collides, so no insertion order is needed. The blocker
moved rather than vanished: `internal/admin` marshals a Go `map[string]string`.

**A realm's genuinely cannot be placed**: four of eight keys share bucket 0 and
chain in an insertion order nothing observable reveals.

Pinned by `TestKeyOrderReproducesAClientsAttributes` and
`TestKeyOrderCannotPlaceARealmsAttributes`, so the answer cannot rot the way the
question did.

What the question was:


`Case.UnorderedKeys` exists because a client's `attributes` is a Java map whose
order the suite gave up on. That was before `javamap` modelled either
constructor. Whether the retreat is still necessary is now an answerable
question and nobody has asked it.

Declined by the cut that raised it - it is a sweep of existing goldens rather
than a fix to a measured divergence - and filed so the question is on the record.

## F91: nothing explains `7n/4`

`SizedKeyOrder`'s first table is asked for `7n/4` buckets. That number is read
off the server at every entry count from 1 to 50 and pinned by four boundaries,
and **no reading of Keycloak or of the JDK has been offered for why it is that
number**.

A measured constant with no mechanism behind it is a fact, not an understanding.
It will hold until something upstream changes it, and nothing here will predict
that. Filed so the next person knows the reason is missing rather than assuming
it was obvious.

## F92: three differences remain in `admin/clients/list-all`

Two are bootstrap: `master-realm` is created with no `name` and with neither
client-scope list. The third is the `audience resolve` mapper serialising two
ways, which is measured Keycloak behaviour Gloak does not reproduce.

The case's `Reason` names all three, so this entry is where they are counted
rather than the only place they are written down.

## F93: five `Reason` strings in `catalog_oidc_pending.go` were stale (closed)

**Closed 2026-08-30 by the stream that owned the file**, hours after the guard
that found them landed. All five said "the token endpoint is not implemented",
false since P1, and all five named `admin-cli`, which has both the grants two of
them claimed to measure **disabled** - so they could never have reached the body
they described.

**Two did not take the replacement text the hand-off suggested**, because the
suggestion was itself stale the day it was written: both grants landed that same
day, and what is actually missing is the consent pages for one and an
authentication channel for the other. A hand-off's suggested text is a hand-off,
not a measurement.

## F94: a `Reason` naming a plan phase expires when the phase closes

`oidc/authorization/implicit-flow` says "out of P3's scope". P3 is over and the
flow is still unbuilt, so the sentence is now true of nothing.

**No mechanical check reaches it.** A `\bP\d+\b` rule fires on six `Reason`
strings of which two are stale, and a guard that cries wolf four times out of
six is worse than the convention it replaces. This one is for reviewers, and it
is written down so that "the test would have caught it" is not assumed.

## F95: a client's `attributes` is serialised from a Go map

`internal/admin` marshals `model.Client.Attributes`, a `map[string]string`, so
`encoding/json` sorts the keys. Keycloak's order is `javamap.KeyOrder`'s and is
exactly reproducible - measured on all five key sets a default 26.7.1 has, with
no bucket collision in any of them.

**2026-09-01: the pattern this entry asks for is now the majority and the client
is the holdout.** P9 added two more families that serialise a Java map from an
ordered slice with a marshaller of their own - `identityProviderConfig` and
`componentConfig` - which makes four counting an organization's attributes and a
protocol mapper's config. Not closed here because it lives in `clients.go` and
moving it re-records five goldens in another chapter, which is a change that
should arrive on its own branch.

The fix is the move `model.StringMap` already makes for a client scope's
`attributes` and a protocol mapper's `config`. When it lands, `UnorderedKeys`
comes off five cases and their goldens start asserting real bytes. This is the
whole of what stands between F90's answer and the retreat coming off.

## F96: `POST /users` drops `requiredActions`

Measured. Filed by the cut that closed F84, which found it while measuring the
shape of a neighbouring field - the same way F84 itself was found.

## F97: `{"username":123}` is a 201

Jackson coerces a JSON number into a string, so a body no client should send is
accepted and creates a user named `123`. Gloak refuses it.

Filed rather than fixed: reproducing a coercion is a decision about how far the
copy goes, not a local edit.

## F98: the hashless credential's grant differs in the body

The `value:""` credential from F84 stores no `credentialData`, and what the
password grant then answers is not what Keycloak answers. Gloak reaches the same
201; the divergence is one step later.

## F99: the `expired_token` grace window has no mechanism and its value is untested

Fifteen seconds is bracketed by three lifespans and nothing explains it - the
same shape as F91's `7n/4`.

Two separate gaps. **No mechanism**: it is a measured approximation. **No test
of the value**: the tests use the constant symbolically, so changing 15s to 60s
fails nothing. That is honest, since the measurement brackets rather than fixes
the number, but it means the constant carries a comment's worth of evidence and
not a test's.

## F100: `Request.Form` cannot express a repeated form key

F48 gave the query a `RawQuery` and left the body alone.
`oidc/device/duplicated-parameter` works around it with `Body` plus an explicit
`Content-Type`, which works **only** because `buildRequest` uses `Body` when
`Form` is empty and sets the form `Content-Type` only when it is not - two
behaviours that now have to stay coupled or that case breaks silently.

A `RawForm` is the honest fix and it is three lines beside `RawQuery`.

## F101: the device grant's browser half is unbuilt (closed)

**Closed 2026-08-30, and a user can now complete a device login**: verification
landing, login page, `OAUTH_GRANT` consent, accept, `/device/status`, and the
device's next poll returns tokens. `oidc/device/poll-access-denied` closes with
it, driven end to end against a live Keycloak inside `make record` - which is
the strongest confirmation this project can produce.

The surprise is that **the verification page cannot be submitted**:
`/realms/{realm}/device` and `/protocol/openid-connect/auth/device` are one
endpoint at two paths, so the theme's own form posts into the device
authorization request and gets 401. Gloak reproduces the broken form.

What the finding said, kept for the record:


`GET /realms/{realm}/protocol/openid-connect/auth/device` is a page Gloak
answers 404. With the `OAUTH_GRANT` consent page,
`POST /login-actions/consent` and `/realms/{realm}/device/status`, that is the
whole of what stands between the grant as shipped and `access_denied` plus a
device login a user can actually complete.

Measured down to the redirect targets in `docs/superpowers/handover/p7-device-grant.md`.

## F102: the `user_code` alphabet's freedom from modulo bias is untested

256 is not a multiple of 26, so a plain modulo would favour the first four
letters; the draw rejects the biased tail instead.

That is a statistical property no unit test in this repository's style can
catch, so it is written down rather than tested - which is the point of filing
it, since an untested property that nobody has named reads exactly like a tested
one.

## F103: twenty-one authentication operations move state nothing consumes

The `flows` 10, `executions` 7 and `config` 4 of the Authentication Management
tag - the flow model. They are deferred rather than built, and the reason is
worth more than the deferral: **Gloak walks a hard-coded authentication flow**,
so every one of those twenty-one would let a caller edit a description of
something the server does not read.

That is the shape the parity roadmap's §6 calls a staged debt, and this project
has twice found that "we store it and serve it back" reads as "we implement it"
to the next person. The twenty-one are named individually in
`docs/superpowers/plans/2026-08-30-p8-authentication.md` §1 so that the next cut
inherits the list rather than the tag.

The prerequisite for paying it is an execution engine in `internal/oidc`, not
more admin surface.

## F104: `enabled` and `defaultAction` on a required action are consumed by nothing (closed, and it named the smaller half)

**Closed 2026-08-31. A temporary password is now actually temporary**, and the
divergence was on **two** endpoints rather than the one this entry describes.

The admin half is what the entry names. The larger half is that `internal/oidc`
never read a user's `requiredActions` **on any endpoint**, so the direct grant
was handing out tokens too - and **nothing in these two sentences would have led
a reader to the token endpoint.** The briefing written from this entry described
it the same way, so the understatement propagated once before the measurement
caught it.

Tokens are **withheld**, not issued-then-restricted: no code exists until the
queue is empty. And the two endpoints disagree about one user - the browser
login asks whether an *enabled* provider has anything to do, the direct grant
reads `requiredActions` raw.

What the finding said, kept for the record:


Both are stored and served. Gloak's login imposes no required action and never
reads a user's `requiredActions`, so a realm can register, enable and prioritise
an action that changes nothing.

The admin half is measured and correct; what is missing is the half that acts on
it. Filed beside F103 because they close together or not at all.

## F105: `javamap` gains three vectors and a near-miss that is not a test (closed, and the base was wrong)

**Closed 2026-08-31**, with all four in the package's tests including the
near-miss, which is the only test that shows what `KeyOrder` *cannot* do. All
four reproduced when re-measured rather than transcribed.

**This entry's "six to nine" inherited a wrong base.** `AGENTS.md` said six
measured key sets and the package's own tests already held nine - the other five
are the client `attributes` sets a bullet four paragraphs earlier describes. The
count is fourteen now and it is what the tests assert, which is the only place a
count like that can live without drifting.

A second finding came with it: **four measured bucket chains come back
descending**, so reversing `KeyOrder`'s pre-sort passes every vector in the
package. A realm's `attributes` refutes it - one chain ascending, one fitting
neither direction - and the package doc now carries the refutation beside the
temptation.

What the finding said, kept for the record:


The authentication SPI registry's key order confirmed `javamap.KeyOrder` on
three more key sets, taking it from six to nine. A fourth **near-miss**
demonstrates the documented bucket-collision limit rather than refuting it, and
it is not in the package's tests because `internal/javamap` was outside that
cut's files.

Adding it is three lines and would make the limit a tested claim instead of a
sentence.

## F106: a `Volatile` mask over a string with a stable prefix cannot be checked mechanically (closed - it can, and this entry named a different question)

**Closed 2026-08-31 by measurement, not by machinery.** The claim was that
deciding it needs two recordings diffed per value. That is true of *a* question
and not of the one this entry names.

`ReplaceCaptured` and `ReplaceIssuer` run before `Normalize` **on both sides**,
so a byte inside `{{issuer}}` or `{{group_id}}` is identical on both sides by
construction: it carries no volatility, and a mask over it gives up an assertion
for nothing. This entry's own example - `https://host/realms/x/<uuid>` - is
therefore decidable from a single response.

What genuinely needs two recordings is a value whose stable part carries **no
placeholder at all**, and the guard says nothing about those.

`volatileMasksOverPinnedPrefixes` was shown failing on a real over-wide mask
before that mask was excused - with the exception list empty it fired on exactly
one case in the whole catalogue, the one the mask audit had predicted.

What the finding said, kept for the record:


The two new mask ratchets catch a mask that changes nothing and a mask that
covers a captured value. What neither reaches is a mask that is **too wide by a
prefix** - `Location: https://host/realms/x/<uuid>` masked whole rather than by
its tail - because deciding it needs two recordings diffed per value, which is
one more `make record` run than a sweep has.

It is a real design and it is written down rather than half-built. Whoever wants
it should read F46, which is the same question already answered for headers.

## F107: seven masks in `catalog_oidc_pending.go` were not examined

The mask sweep could not edit that file - it belonged to a parallel stream - so
it reported instead: two inert `id_token` masks, one over-wide `session_state`,
F39's four whole-`Location` masks, and `registration_client_uri` and
`verification_uri_complete` as F46's shape in cases nobody has built yet.

The evidence is per case in `docs/superpowers/handover/mask-audit.md`. This is a
list to work from, not a question to re-ask.

## F108: `POST /logout/logout-confirm` and `/login-actions/restart` are measured and unbuilt

Both fell out of the SSO work. Neither is on any tag's operation list, so they
move no parity number, and both are reachable from a browser today.

## F109: `prompt=login` serves the plain login page

Keycloak serves a re-authentication page; Gloak serves the ordinary form. The
envelope is right and the prose is not, which is F67's family.

**2026-09-01: F67 is closed and this one is not, and the reason is now written
down rather than implied.** `writeLoginActionErrorPage` deliberately keeps the
placeholder body while the rest of the page family serves markup. **Twelve call
sites across three files reach it and no golden compares any of them**, so
mapping each to one of the three measured sentences would be twelve unpinned
judgements - and the chrome would be unpinned too, since nothing has measured
which client that page's restart URL names. Guessing twelve sentences does not
close this; measuring the twelve does.

## F110: consent grants are in memory, and that one is a real divergence

The authentication session, the authorization code and the device store are all
in memory by design - F75 - because Keycloak keeps them in Infinispan rather
than its schema.

**A consent grant is not like those three.** Keycloak persists it and exposes it
through the Admin API, so this is a divergence rather than a faithful copy, and
it is filed separately from F75 for that reason.

## F111: `httpx.WriteJSONCharset`'s doc comment repeats a corrected reason

It says the charset is a quirk of `GET /realms/{realm}`. The rule is per API
surface and status class, and `AGENTS.md` now says so. One comment, and it is
the last place the old explanation survives.

## F112: the 87 authentication config properties are asserted for three providers

The other forty-nine were swept by hand against the server and that sweep is not
a test. It is the difference between "somebody checked" and "something checks",
and this list exists to keep that difference visible.

## F113: `Recorded` is the hole `GoldenIsAsserted` leaves, and it was walked through (closed)

F69 stopped the recorder rewriting `Pending` goldens. `GoldenIsAsserted` returns
true for a **`Recorded`** case, because a golden worth comparing is a golden
worth re-recording - and on 2026-08-30 four theme pages were promoted to
`Recorded`, so the churn came straight back.

**No test could see it.** A `Recorded` case is required *not* to match, and it
did not match either way. Three later cuts refuted the "silent on a clean
checkout" line independently, none of them looking for it, and each reverted the
four files rather than committing them - which means each of the three spent
time deciding whether four unrelated moves were a regression.

**Closed 2026-08-31** by parking the four, each declared with its reason. The
rule that follows is stronger than the fix: **a page carrying a per-request
value cannot be `Recorded`**, whatever else is true of it, because `Recorded` is
a promise the recorder has to be able to keep.

A theme-resource substitution pass was written first and reverted. It removes
one of the three churn sources - the `/resources/<hash>/` segment - and the
other two are login session cookies and a `tab_id` inside the markup, which need
the HTML masking F38 declined on four written grounds. Machinery that fixes a
third of a problem and has no consumer is what this project calls a guess about
what the next cut wants.

**The arithmetic in that paragraph was wrong, and it was measured wrong on
2026-09-01.** Each of the eight parked pages was requested twice against one
container: **seven were byte-identical**, carrying the `/resources/<version>/`
segment and nothing else per-request. Only `prompt-create` moved, and it moved in
**two** places rather than three - `client_data` is a base64 of the request's own
redirect URI, response type and state, and came back identical. So the pass
removed a third of the churn on the one page it was measured against and *all* of
it on the other seven. It was restored, the seven are contracts, and the rule
this entry states is intact: prompt-create is still `Pending` precisely because
it carries a per-request value.

The general lesson is the one F38's note repeats: a judgement made from one
example and generalised to a set. Checking the other seven cost one loop of
`curl` twice.

## F114: CI was killed inside `fsync`, and the first diagnosis was wrong (closed)

A cut reported that the identical tree passed, failed, then passed again, and
read it as a slow runner. The fix applied from that reading - raising Go's
per-package timeout from 10 minutes to 30 - **failed at 30 minutes**, with
goroutine 1 waiting 22 minutes and the running goroutine inside
`modernc.org/libc.Xfsync`.

The cause is `fsync`. Every conformance case opens a fresh SQLite file and
bootstraps it; a bootstrap is hundreds of writes, and under the default
`synchronous=full` each waits on the disk. The runner's disk was the variable
and nothing in the output named it.

**Closed 2026-08-31**: the three test packages that build a throwaway store open
it with `synchronous(off)`. Durability is meaningless for a file that lives in
`t.TempDir()` for one subtest, and production is untouched. The CI `Test` step
went from dying at 30 minutes to passing in 9m33s.

The timeout flag stays at 20 minutes as a **backstop**, and its comment says so.
Two lessons, and the second is the one worth keeping:

- A package-level timeout reads as a failed assertion. `AGENTS.md` tells the
  reader that any failure is a real regression - true of the local suite, and
  it is what made this misread twice, once by the cut that found it and once by
  the fold that acted on it.
- **Raising a timeout to make a red build green buys time, not information.**
  Thirty minutes of not knowing is worse than ten.

## F115: one case's recording depends on the load average (closed)

`oidc/userinfo/expired-token` waited two seconds on a one-second token lifespan.
`iat` is truncated to the second, so `exp` can sit up to a second later than the
mint and the real margin is under a second - which a machine running three
containers eats.

A whole `make record` recorded its **200** where the golden holds the **401**,
and the golden was right. Five seconds now, which is three seconds of a
six-minute run.

Worth generalising: a fixture `Delay` tuned to the smallest value that worked
once is tuned to the machine it was written on.

## F116: `kc_action` triggers a required action on demand and is not built

Measured: it echoes an **alias** on success and a **flow execution id** on
failure. Two different vocabularies from one parameter.

## F117: `CONFIGURE_TOTP` cannot be completed

It is reachable - the secret's raw ASCII bytes are the HMAC key rather than a
base32 decoding, so no device is needed - but completing it needs an `otp`
credential type Gloak does not have.

## F118: the required-action landing page has no conformance case

It would need a `Pending` case plus a `parkedGoldens` entry, and `case_test.go`
belonged to another stream. Filed so the gap is on the record rather than
looking like a page nobody thought to measure.

## F119: three aliases serve one 302 fewer than Keycloak

The end state is identical; the redirect chain is shorter. Measured, and left as
measured rather than padded to match, because inventing a redirect to make a
count agree is the shape of divergence this project exists to avoid.

## F120: the organization group family is blocked on a hidden root group

A created organization's group carries a `parentId` naming an id the
representation never shows. Eleven operations under
`/organizations/{org-id}/groups`, and eleven more of their role-mappings
currently counted under `Role Mapper` and `Client Role Mappings`, wait on
understanding it.

## F121: the `Workflows` tag needs a YAML writer

Nine operations answering `application/yaml`, chunked. `internal/httpx` owns
every response body this project writes and has no YAML path, so this is a
decision about that package before it is nine handlers.

## F122: the two admin logout triggers notify nobody

`POST /users/{id}/logout` and `DELETE /sessions/{sid}` fire the back-channel
notification on Keycloak. Gloak serves the two protocol paths and not these two,
because `internal/admin` was not the channel-logout cut's to change.

Until they land, an administrator ending a session leaves every other client
believing the user is still signed in - which is the failure mode back-channel
logout exists to prevent.

## F123: the logout responses' cookie clears are unserved and unseeable

Keycloak's logout responses carry cookie clears Gloak does not send. Three
goldens mask `Set-Cookie`, so **no conformance case can see the difference** -
the gap is real and the suite is structurally blind to it.

It belongs with the SSO machinery rather than with the channel logout, and it is
filed here so that "the goldens are green" is not read as "the cookies agree".

## F124: Jackson's ` : ` spacing in every Keycloak JOSE header

Keycloak's JOSE headers are serialised with a space on both sides of the colon.
Gloak's `go-jose` does not reproduce it. **This affects every token this project
issues**, was found while measuring the logout token, and is not caused by that
cut.

Whether it is observable to a client is the first question: a JOSE header is
base64url-encoded, so the bytes differ while the parsed object does not. A
client comparing the encoded header - or a signature over it - would see it.

## F125: `frontchannel.logout.session.required` is measured and unread

What it decides lives in the page body, which is P13's, so Gloak reads the
attribute and does nothing with it. Filed rather than left as an attribute that
looks honoured.

## F126: `permission/providers` is not filtered to permission providers (confirmed)

Confirmed by the second cut and unchanged. Reproduced as measured.


It is byte-identical to `policy/providers` - `cmp`-verified. Reproduced as
measured. Filed because the next reader will assume the two endpoints differ,
and the only thing that says otherwise is a comment.

## F127: `javamap.KeyOrder` is wrong where `SizedKeyOrder` is right, on a served body

The provider catalogues' key order is placed exactly by `SizedKeyOrder` and got
wrong by `KeyOrder`. That is the documented difference between the two
constructors and it is now visible on a body Gloak serves, rather than only in
the package's tests.

Nothing is broken - the cases assert the bytes that are served - but a caller
reaching for `KeyOrder` here would be wrong, and the call site is the only thing
that says which to use.

## F128: `CONSENSUS` is a documented `decisionStrategy` and a 500

Keycloak's own defect, reproduced, the same way `POST /users` with an empty body
is reproduced. Filed so that a later cut does not "fix" it into the 400 an
unknown value gets.

## F129: the other twenty-six authorization-services operations (partly closed)

**Eight of the twenty-six landed 2026-08-31** - the whole scope family.
Eighteen remain: resource 9, policy 4, permission 4, import 1.

The cut deliberately did **not** take the three permanently-`[]` listings
(`GET /resource`, `/policy`, `/permission`), which would have been three cheap
parity points indistinguishable from stubs. The resource family is keyed `_id`,
carries an `attributes` Java map - so `javamap` and F95 are both in play - and
takes eight query parameters; policy and permission need a provider model before
`POST` means anything; `import` needs all four families first.

What the finding said, kept for the record:


The resource server, its two provider catalogues and the twelve refusals are the
first cut. The scope family was swept in full anyway and its measurements are in
`docs/superpowers/handover/p10-authz-services.md` §1.9, so the second cut starts
from measurements rather than from the tag.

## F130: `internal/store`'s `SessionRepo` cannot list a realm's sessions

`channelLogoutTargets` enumerates clients through `ListByRealm` plus
`ClientSession` because `SessionRepo` has no listing method. It works and it is
the wrong shape - a second instance of F110's, where a cut could not reach the
store it needed.

Two cuts have now routed around this repository's missing listing methods. The
third should add them rather than route again.

## F131: a cross-resource-server scope id collision corrupts the other resource server

Measured on 26.7.1 and reproduced on a fresh pair: reusing a scope id across two
resource servers leaves the **other** one broken - its listing answers 400 and
its settings 500.

**Gloak deliberately does not reproduce it.** That makes it the first measured
behaviour this project has declined to copy, which is a decision worth having on
the record rather than in a comment: the rule is byte-identical observable
behaviour, and this is the exception, taken because reproducing data corruption
is not what "compatible" is for.

If a client is ever found depending on it, this entry is where the argument
starts.

## F132: nine `WriteHeader(http.StatusCreated)` call sites send a `Date` header

Pre-existing, invisible to the conformance suite - which serves through
`httptest.ResponseRecorder` and so never sees a `Date` either - and outside the
cut that found it, because the fix belongs in `internal/httpx`.

This is F54's shape for the fourth time. The rule "Gloak deletes the `Date`
header on every response" has now been false three times in three different
writers, each found by somebody reading a socket rather than by a test.

## F133: `writeEmptyStatus` lives in `internal/admin`

It writes no body, so no second marshaller exists and the boundary rule is not
broken in substance - but `internal/httpx` is where every other writer lives,
and moving it is a rename. Filed so it is a decision rather than an accident.

## F134: four listings still treat an unparseable bound as no bound

The scope family answers a malformed integer query parameter with a 404, which
is measured. Four older listings silently treat the same input as an absent
bound.

Whether Keycloak agrees on those four is unmeasured - the finding is that Gloak
is inconsistent with itself, which is knowable without a container.

**2026-09-01: measured on two more families, and they disagree with each
other.** The identity provider listing answers `?first=abc` with the 404; on
`/components` the same input is a 200 with the whole listing, and `?first=1&max=2`
returns every row too, so that endpoint does not read the bounds at all. **There
is therefore no single Keycloak answer to import into the four.** The premise of
this entry survives for a second reason: the server is inconsistent as well, so
each of the four has to be measured in its own family rather than settled by a
rule. The new listing implements the 404 because that is what its own family
answers.

## F135: DPoP is measured in full and not implemented

It works on a default container: `token_type: DPoP` and `cnf.jkt` on both
tokens. It is **not built**, and deliberately: a proof's `iat` window and its
single-use `jti` make it unrecordable, and a partial implementation would refuse
valid proofs.

The contract is in the repository anyway - `oidc/token/dpop-header-invalid` is
`Recorded` - so the next cut starts from measurements.

## F136: the registration access token's identity is in memory

The registered **client** persists through `store.ClientRepo`, so F75's
precedent was deliberately not leaned on. What is ephemeral is only the `jti` a
`PUT` rotates, because `model.Client` has no field for it and `Attributes` is
serialised into the Admin API's client representation.

A restart kills outstanding registration access tokens.

## F137: Gloak's registration decoder is not strict

Keycloak's is, and it is the only one of the five strict decoders that reports a
line and column. Gloak ignores unknown fields there.

Filed rather than hidden: the divergence is one field name away from being
invisible.

## F138: three registration providers and the unknown-provider 404 are unbuilt

`default`, `install` and `saml2-entity-descriptor`. They currently fall through
to the unmatched-path 404 rather than borrowing a measured string for the wrong
condition, which is the right failure to have while they are unbuilt.

## F139: a `Content-Type` present with an empty value is a 500 HTML page

On Keycloak. Gloak treats it as absent. Measured, not reproduced, and small
enough that it would otherwise be forgotten.

## F140: F86's `jti` prefixes are six

The entry says four, a later cut said five, and the count on one container is
**six**. Counted from the list. The prefixes are a per-grant marker, so the
count grows with the grants - which is exactly why it should not have been
written as a number in prose.

## F141: `Case.VolatileTailHeaders` is declared on six cases and ten routes mint a UUID tail

Six of the ten UUID-tailed creates are routes this project already serves. The
gap is not a defect - the other four either pin their tail through the body's
`id` or are not served - but the arithmetic is worth having written down, since
F46's mechanism exists precisely to keep those tails asserted.

## F142: every conformance case runs against `master`, so realm-derived values are invisible

Found by a mutation on 2026-09-01: hard-coding `master` into the theme page's
restart URL, instead of using the realm the page was built for, **passed the
whole tree** - all seven theme goldens included.

The reason is structural rather than a gap in one suite. Every case in
`internal/conformance` is recorded and replayed against `master`, so no golden
here can tell a realm-derived value from that literal. It is the same blind spot
`session_state` has, and the same answer: the claim has to live in
`internal/httpx`'s or `internal/oidc`'s own tests, which can render for a second
realm. `TestThemeErrorPageCarriesTheChrome` now does, and asserts the string
`/realms/master/` does not appear.

What is worth acting on is the general form. **Any** value a handler derives from
the realm name is unpinned by this catalogue. A cut that adds one should say so
and put the assertion in its package's tests; a `PristineRealm`-style second
realm in the harness would be the alternative, and nobody has costed it.

## F143: the group listing's `search` treats `*` as a literal and Keycloak does not

`internal/admin/groups.go` uses `strings.Contains`. Measured: `search=*bbc`
against a group named `xabbcx` matches on the server, and the identity provider,
user and group listings all share Keycloak's LIKE rule - a wildcard `*`, an
implied trailing `%`, `"quotes"` for equality. The **role** listing does not, and
treats `*` as a literal.

Measured, not fixed: a search-semantics change in a third chapter is not the
branch that found it. `matchesSearch` is the function to call, the discriminating
probe is `*bbc` against `xabbcx`, and the fix is one edit.

## F144: `PUT /components/{id}` with a partial body is a 500 that has already written the name

Measured on a live 26.7.1 while building the component reads. The row was
renamed and its config kept, and *then* the request failed with a 500. Recorded
here so the cut that builds that endpoint finds it in this document rather than
by accident, and so the half-written state is understood to be Keycloak's own
rather than a bug in the reimplementation of it.

## F145: the components table exists now and `GET /admin/realms/{realm}/keys` does not read it

AGENTS.md records that Gloak "has no component table and derives `providerId`
from the `kid` by a fixed hash". As of P9 it has one, and the two are not wired
together.

**Wiring them is not a rename.** Master carries four key-provider components
against Gloak's three realm keys - the arithmetic AGENTS.md already flags as
"serving three keys is a divergence" - so there is an `rsa-enc-generated`
component with no key behind it. Left alone deliberately; what changed is that
the mismatch is now visible in one place instead of implied across two.

Related: `DELETE /components/{id}` is deliberately unbuilt. Deleting
`rsa-generated` in Keycloak removes the realm key, and Gloak's `GET /keys` is not
backed by this table, so the delete would leave a realm in a state Keycloak
cannot reach. That is the argument migration 0019 already makes for
`authz_resource_server` having no `enabled` column.

## F146: nine theme pages still serve the placeholder body

Named in `themePageBody`'s doc comment: the logout confirmation, "You are logged
out", "Page has expired", the consent page and the five required-action pages.
Each is an hour with a container; the instruction and the chrome are what have to
be measured. The login-actions family is separate and is F109.

Also unmeasured, and served as a constant: the `<html lang="en">` attribute.
Whether it follows the realm's locale has never been asked.
