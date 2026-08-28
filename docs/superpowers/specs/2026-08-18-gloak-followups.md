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

## F17: the listings are gated where Keycloak filters

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
2. **No fixture yet captures a narrow-role caller's access token.** This is a
   smaller gap than it first looks. `loggedOutUserFixture`
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

## F23: three login-theme goldens churn on every re-record

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

## F30: the role-mapping guards are one stage where Keycloak has two

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

## F32: the caller's roles are flattened by name, so an ordinary client role can impersonate an admin one

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

## F36: `manage-users` opens all seven mapping reads and is refused `GET /users/{id}`

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
