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
fix location turned out to be wrong - and opened F25 through F28. **F28 is the
one to read first**: it is a second escalation path, measured on the same day,
and left open because the naive fix is falsified by the measurement.

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

It cannot become a conformance case until role assignment is served - that is
the Role Mapper tag, P2's second cut - because a fixture reaching a
narrow-role caller has to build one through the API in both the reference
container and Gloak. `internal/admin`'s own tests cover what they can:
TestQueryUsersOpensTheListingButNotTheRead pins the status codes.

Role assignment does not arrive with the roles half of the second cut, the
work this entry's own measurements came out of - `Role Mapper` and `Client
Role Mappings`' user halves are the second half of that cut, still to be
built. So this stays open, and its conformance case with it, until that half
lands.

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

**Keycloak's behaviour here is unmeasured.** F24 is evidence that the "the
realm's own client is never configurable" rule extends past create - it turned
out to cover both composite verbs - so the likely answer is 403, but likely is
not measured and this repository does not ship likely. Two `curl`s against a
live 26.7.1 with the full administrator token settle it:

```
PUT    /admin/realms/master/clients/{master-realm uuid}/roles/query-groups
DELETE /admin/realms/master/clients/{master-realm uuid}/roles/query-groups
```

and the `roles-by-id` forms of the same two, since F24 showed the two route
families have to be checked separately. If they are 403, the check already
written for F24 - `ownedByRealmOwnClient` in `internal/admin/roles.go` - is
the piece to reuse; the only decision is where it goes so that both families
reach it, which for these two is not `eachComposite`.

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

## F28: composite writes do not apply Keycloak's caller-relative admin-role rule

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
