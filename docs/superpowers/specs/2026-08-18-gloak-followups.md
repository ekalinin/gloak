# Gloak: tracked follow-ups after the foundation slice

Date: 2026-08-18
Source: the final whole-branch review of `feat/foundation`

Six findings from that review were fixed in the branch. These were deliberately
not fixed, because each needs a design decision rather than a local edit. They are
recorded here so the next plan starts from them rather than rediscovering them.

Each was reproduced, not theorised.

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

## F12: the recorder cannot capture a multi-valued header or a volatile `Location`, together

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

## F17: `GET /clients` is gated where Keycloak filters

Measured 2026-08-23. A caller holding only `query-clients` gets **200 and an
empty array** from `GET /admin/realms/master/clients`, even filtering to a
client that exists. Keycloak returns the objects the caller may view rather
than refusing the caller.

Gloak guards the route with `view-clients` alone, so the same caller gets 403.
Two changes are needed: accept `query-clients` as well, and filter the list by
`clientAccessFor(...).View` instead of returning everything.

It cannot become a conformance case until role assignment is served - that is
the Role Mapper tag, P2's second cut - because a fixture reaching a
narrow-role caller has to build one through the API in both the reference
container and Gloak.

## F18: tokens carry no roles, so `aud` is wrong and introspection is too permissive

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
