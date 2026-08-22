# P1: the token foundation

Date: 2026-08-21
Status: implemented, 2026-08-22
Roadmap: `2026-08-21-gloak-parity-roadmap.md`
Plan: `../plans/2026-08-22-p1-token-foundation.md`

## 1. What this is

The first sub-project of the parity roadmap: persisted realm keys, a session
model, token issuance, and the protocol endpoints that need no browser.

It is the sub-project everything else waits on. Both the Admin API (P2) and the
browser flow (P3) need a token before they can authenticate anything, and neither
can be recorded against a live Keycloak until the harness can obtain one.

## 2. Scope

In:

- realm signing material persisted and modelled per realm
- `UserSession` and `ClientSession`
- `internal/token` - issuing and parsing access, ID and refresh tokens
- `internal/auth` - password verification
- client authentication, confidential and public
- `POST .../token` with `password`, `client_credentials` and `refresh_token`
- `GET POST .../userinfo`
- `POST .../token/introspect`
- `POST .../revoke`

Out:

- the `authorization_code` grant. It needs `/auth` to mint a code, which is P3.
  Its catalogue case stays `Recorded` until then.
- consent, protocol mappers (P5), offline sessions (P6), device and CIBA (P7)

## 3. Components

| Package | What appears |
|---|---|
| `internal/model` | `RealmKey`, `UserSession`, `ClientSession` |
| `internal/store` | `KeyRepo`, `SessionRepo`, in both drivers and in `storetest` |
| `internal/keys` | keys loaded from the store, one set per realm |
| `internal/token` | new: issue and parse access, ID and refresh tokens |
| `internal/auth` | new: argon2id password verification |
| `internal/oidc` | `token.go`, `userinfo.go`, `introspect.go`, `revoke.go`, `clientauth.go` |

Three of these need justification.

**Realm keys become a set, per realm, in the database.** Follow-up F5: today
`keys.Generate()` runs once per process, the result lives in memory, one
`RealmKeys` value serves every realm the router resolves, and the `kid` changes on
every restart - invalidating every cached JWKS a client holds and making two
replicas publish different keys for the same realm. A realm's set is three keys:
RS256 for signing, RSA-OAEP for encryption, and an HS512 secret for refresh
tokens. The first two are published; the HMAC secret is not, and `internal/keys`
must keep it that way. Persisting the pair is also what makes
`oidc/certs/master` - the project's one deliberately red test - pass, since the
live `master` realm publishes two keys and Gloak generates one.

**Argon2 parameters are read from the credential, not from constants.** The
constants in `internal/bootstrap` are the parameters for *creating* a password.
Verification has to work with whatever is stored, including
`additionalParameters` values that arrive as arrays of strings (see the "Password
hashing" section of the observed-behaviour document). Verifying against constants
means any future parameter change silently locks out every existing account.

**Client authentication gets its own file.** Two traps live there, both measured:
an unknown client returns `invalid_client` while a wrong secret returns
`unauthorized_client`, with identical descriptions. And `broker` and
`master-realm` are currently bootstrapped as confidential clients with an empty
secret (recorded in the follow-ups). An empty secret must never authenticate.

## 4. Claim sets are copied, not derived

Every claim set P1 emits is already measured, in the "Claim sets" and "Lightweight
access tokens" sections of
`2026-08-18-keycloak-26.7.1-observed.md`. P1 reproduces them literally:

- access and ID tokens RS256, refresh tokens HS512
- `aud` is an array on the access token and a **string** on the ID token
- the refresh token's `aud` is the issuer URL, `aud_x` carries what the access
  token puts in `aud`, and `prov` is `default`
- the refresh token's `scope` is the full internal list, longer than the access
  token's
- `admin-cli` is a lightweight client: `azp, exp, iat, iss, jti, scope, sid, typ`
  and nothing else - no `sub`, no `aud`, no `realm_access`
- `jti` on access tokens carries an instance prefix such as `onrtro:`; ID and
  refresh tokens use a plain UUID. It is a normalisation target.

In Keycloak these sets are produced by protocol mappers attached to client scopes.
That model is P5. P1 hardcodes the results.

**This is staging and it is written into the roadmap as debt** (section 6 there).
P5 has to convert this into a mapper model rather than discovering mid-flight that
"just add mappers" means rewriting token issuance.

### 4.1 A dependency this removes

The lightweight claim set answers a question that would otherwise have blocked P2:
where does the Admin API get the caller's roles?

Not from the token. An `admin-cli` access token carries no `sub` and no
`realm_access`, so there is nothing there to authorise against. Keycloak must
resolve the session server-side from `sid`.

P2 therefore resolves roles from the session and the user's role mappings, and
does **not** pull P5's `roles` mapper forward. This follows from a value already
measured, not from an assumption about how Keycloak works internally - though the
exact 403 shape still has to be recorded when P2 gets there.

## 5. The harness has to be able to express this first

Four pieces of `internal/conformance` are missing, and until they exist P1's
contract cannot be written down at all.

**Fixture chaining.** This is the blocker. `userinfo`, `introspect` and `revoke`
cannot be recorded without first obtaining a token, and `Fixture` is currently a
bare name that the recorder rejects unless it equals `"bootstrap"`. It becomes a
recipe: a sequence of requests whose responses yield captured values, substituted
into the target request.

```go
"admin-token": {Steps: []Step{{
    Request: Request{Method: "POST", Path: ".../token", Form: map[string]string{
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": "admin"}},
    Capture: map[string]string{"access_token": "access_token"},
}}},
```

A case then refers to what was captured:
`Headers: {"Authorization": "Bearer {{access_token}}"}`.

Two rules, without which this quietly corrupts the contract:

- **Fixture steps are never written to a golden.** Only the target response is
  recorded. Otherwise a live token ends up committed to the repository.
- **Captured values are masked out of the recorded body** by a `ReplaceCaptured`
  pass alongside the existing `ReplaceIssuer`. A token left verbatim in a golden
  makes the file churn on every recording - the same disease four goldens already
  have.

One recipe, executed twice: by the recorder against the container, by the verifier
against the in-process handler. Any other arrangement compares responses obtained
in different ways.

**The `Recorded` status**, as specified in section 3.3 of the roadmap.

**The parity meter**, as specified in section 3 of the roadmap. It is not a P1
dependency - P1's chapters are hand-written - but it is what makes P2 measurable,
and it is cheaper to build alongside the other harness work than on its own.

**Sorting words inside a string.** The token response's `scope` is a
space-delimited string whose word order is not stable across container starts (see
the observed-behaviour document, "Token response `scope` word order"). `Unordered`
sorts JSON arrays and cannot help. A parallel `UnorderedWords` naming string-valued
paths closes one of the four churning goldens the README warns about.

Not needed here: the volatile-header half of follow-up F12. No P1 response carries
a `Set-Cookie` or a changing `Location`. It becomes mandatory in P2, where every
201 carries a `Location` holding a fresh UUID.

## 6. Test order, and what cannot come first

**Unit tests for `internal/token` and `internal/auth` cannot be written first.** A
Go test for a package that does not exist fails to compile, and a package that
does not compile takes `go test ./...` down with it. That is worse than a red
test: it is no signal at all. Those tests are written inside their tasks, TDD,
task by task.

What comes first is the layer that *can*: the machinery to express P1's contract,
and the contract itself in bytes.

**Layer 0, the harness.** `Recorded`, the parity meter, fixture chaining and
`UnorderedWords`. No Docker, no network; verified by its own tests.

**Layer 1, the contract.** `make record` writes goldens for every P1 case at
status `Recorded`: nine existing cases in `oidc/token`, five in `userinfo`, four in
`introspection`, four in `revocation`, plus the ones P1 adds - a confidential
client authenticating with its secret, an expired refresh token, a service
account. `make test` stays green, and the repository holds a byte-exact target for
every task that follows.

**Layer 2, inside each task.** Key persistence and `kid` stability across a
restart, key isolation between realms, claim sets against the measured sets,
`storetest` coverage for both new repositories in both drivers.

**Layer 3, the end-to-end test design section 10 specified and nobody delivered.**
`coreos/go-oidc` as a relying party validating an ID token. It catches what a
response diff cannot catch by construction. `coreos/go-oidc` is not currently in
`go.mod`.

## 7. Follow-ups this closes and does not close

Closes **F5** - realm keys generated per process and never persisted, along with
the missing encryption key and the resulting red `oidc/certs/master`.

Closes the first half of **F12** only in the sense of not needing it; the
volatile-header gap stays open for P2.

Does not touch **F4** (SQLite concurrency), **F6** (migrations take no lock),
**F10** (graceful shutdown, CI, Dockerfile) or **F11** (non-clean paths escaping
`withKeycloakFallbacks`). None of them blocks P1 and each needs its own decision.

Adds one: the empty secret on `broker` and `master-realm`, harmless until P1 and
a real hole the moment client authentication exists. P1 must not let an empty
secret validate; whether bootstrap should generate real secrets is P2's question,
since that is where client management lives.

## 8. What P1 shipped

Written after the fact, on 2026-08-22.

**Served.** The token endpoint with the `password`, `refresh_token` and
`client_credentials` grants; `userinfo`; `token/introspect`; `revoke`. Realm
keys are persisted per realm as three rows - RS256, RSA-OAEP, HS512 - and
resolved through `keys.Manager`, which closed follow-up F5 and with it the
project's one sanctioned red test. Sessions are modelled, so `sid` survives a
refresh and revocation ends the session rather than only saying it did.

**Measured and served.** Seventeen cases moved from `Recorded` to
`Implemented`, clearing that list entirely. The meter went from 8 of 483 to 25
of 483.

**Served but unmeasured, and marked so in the code.** userinfo's success body,
introspection's active and inactive bodies, the `client_credentials` response
shape, the `service-account-<clientId>` username, the access token's `aud` for
an ordinary client, `acr`. Every one of them needs a confidential client with a
known secret, which is P2. Follow-ups F14 and F15 carry them, and their
conformance cases stay `Pending`, so nothing asserts a value nobody measured.

**Not attempted.** The `authorization_code` grant, as section 2 said: it needs
`/auth`, which is P3.

## 9. The debt this hands to P5, restated

`internal/token/claims.go` hardcodes three claim sets and
`internal/oidc/token.go` hardcodes `defaultClientScopes` and
`internalRefreshScope`. In Keycloak all five are produced by protocol mappers
attached to client scopes.

P5 has to **replace** those, not extend them. The shape of the debt is that
`token.Request` currently takes a finished `Scope` string and finished role
slices from its caller; a mapper model makes the token package compute them
from the client's scopes instead, which changes who owns the decision. Adding
mappers on top of the current code means rewriting issuance, which is exactly
what section 6 of the roadmap warned about and what this paragraph exists to
stop being a surprise.
