# Gloak: tracked follow-ups after the foundation slice

Date: 2026-08-18
Source: the final whole-branch review of `feat/foundation`

Six findings from that review were fixed in the branch. These were deliberately
not fixed, because each needs a design decision rather than a local edit. They are
recorded here so the next plan starts from them rather than rediscovering them.

Each was reproduced, not theorised.

## F3: two shipped endpoints have no measured contract

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` records the token
endpoint, the error shapes, the cookies, the discovery document and the bootstrap.
It has no section for `/protocol/openid-connect/certs` or for `GET /realms/{realm}`.

So the JWKS entry's field set, the realm-info field order, and the `Cache-Control`
and CORS headers on all three shipped endpoints were written from memory. That
breaks the project's own rule. Live Keycloak also publishes `x5c`, `x5t` and
`x5t#S256` in its JWKS, which Gloak currently does not.

Measure and record before the golden harness is written, or the harness will pin
guesses.

## F4: the two store drivers are not behaviourally identical under concurrency

The SQLite driver opens with no `busy_timeout`, no WAL mode and an unbounded
connection pool. Under 32 concurrent inserts, 31 failed with `SQLITE_BUSY`, and the
error surfaced raw rather than as `store.ErrConflict` or `store.ErrNotFound`, so a
handler cannot map it to a response. Postgres has no equivalent failure.

The conformance suite runs single-goroutine, so it can never show this. Whatever
fixes it should also add a concurrent case to the suite.

## F5: realm signing keys are generated per process and never persisted

`keys.Generate()` runs at startup and the result lives only in memory. The `kid`
therefore changes on every restart, invalidating every cached JWKS a client holds,
and two replicas publish different keys for the same realm. Keycloak persists realm
keys.

The same single `RealmKeys` value also serves every realm the router resolves,
which stops being correct as soon as a second realm exists.

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

## Smaller items carried from the task reviews

- `classify` in both drivers maps only "no rows" and unique-constraint violations. A
  foreign-key violation surfaces raw. Must land before the admin API maps store
  errors to status codes.
- `broker` and `master-realm` are confidential clients created with an empty secret.
  Harmless while nothing authenticates clients; an empty secret must never validate
  once client authentication exists.
- `WriteBearerChallenge` quotes header parameters with Go's `%q` rather than RFC 7235
  rules. Fine for ASCII without quotes, wrong once realm names are user-supplied.
- The conformance suite exercises 11 of 17 interface methods, while its doc comment
  claims it covers every one. Either widen it or correct the comment.
- The 21 client roles on the `master-realm` client are required by section 8 of the
  design spec and were deliberately deferred to the admin API plan.
- Two response shapes are chosen rather than measured, and are marked as such in the
  code: the 404 and 405 fallback bodies, and the realm-info key order.
