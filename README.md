# Gloak

Keycloak, rewritten in Go.

Gloak is a deliberate copy, not a different product. From the outside it aims to be
indistinguishable from Keycloak, byte for byte wherever a client can observe it.
Inside, the database schema and the abstractions are its own.

The name is **G** from Go plus **loak** from Keycloak.

**Compatibility target: Keycloak 26.7.1.** The version is pinned as a contract.
"Compatible with Keycloak" means nothing without a version number, since the admin
API and the export formats change between minor releases.

## Status

Early. The foundation is in place and works; most of Keycloak is not implemented yet.

Working today:

- `gloak serve` starts, bootstraps the `master` realm, and survives restarts
- OIDC discovery document, all 56 keys in Keycloak's own order
- JWKS endpoint
- realm info endpoint
- Postgres and SQLite behind one storage interface, both passing the same
  conformance suite
- a documentation-derived conformance suite (`internal/conformance`) that checks
  Gloak's responses byte-for-byte against bytes recorded from a live
  Keycloak 26.7.1 - with one known exception, see below
- a parity meter whose denominator comes from Keycloak's own OpenAPI description
  rather than from a hand-kept list: **8 of 483 enumerated behaviours served**,
  plus four chapters whose surface has not been counted
- 17 behaviours measured and committed but not yet served, so the tasks that
  build them start from byte-exact expected output

Not implemented yet: tokens and grants, the browser login flow, userinfo, logout,
introspection, revocation, the admin REST API, SAML, user federation, identity
brokering, authorization services, the admin console.

Where this is going is `docs/superpowers/specs/2026-08-21-gloak-parity-roadmap.md`:
fourteen sub-projects with their dependencies and what each closes.

## Quick start

```bash
make build

GLOAK_ADMIN_PASSWORD=changeme ./gloak serve
```

Then:

```bash
curl -s localhost:8080/realms/master/.well-known/openid-configuration
curl -s localhost:8080/realms/master/protocol/openid-connect/certs
```

There is no default administrator password. The server refuses to start without
`GLOAK_ADMIN_PASSWORD`, and the password cannot be passed as a flag, because
command-line arguments are readable by any process on the machine.

## Configuration

Every flag has an environment variable equivalent. Environment names are Gloak's own
and deliberately do not mirror Keycloak's `KC_*`: configuration is not part of the
API contract, and copying it would drag in Keycloak's whole build-time and runtime
option model.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-db` | `GLOAK_DB` | `sqlite` | store driver, `sqlite` or `postgres` |
| `-dsn` | `GLOAK_DSN` | `gloak.db` | data source name |
| `-addr` | `GLOAK_ADDR` | `:8080` | listen address |
| `-issuer` | `GLOAK_ISSUER` | `http://localhost:8080` | externally visible issuer base URL, no trailing slash |
| `-admin-user` | `GLOAK_ADMIN_USER` | `admin` | bootstrap administrator username |
| none | `GLOAK_ADMIN_PASSWORD` | none, required | bootstrap administrator password |

`GLOAK_ISSUER` must be the URL clients actually reach, since every endpoint in the
discovery document is derived from it.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /realms/{realm}/.well-known/openid-configuration` | discovery document |
| `GET /realms/{realm}/protocol/openid-connect/certs` | JWKS |
| `GET /realms/{realm}` | realm name and public key, used by adapters |

There is no `/auth` prefix. Keycloak dropped it in version 17.

## How compatibility is established

Values are measured against a running Keycloak, never taken from documentation.
Documentation drifts from the implementation in exactly the small details that
matter here.

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` records what was
measured on `quay.io/keycloak/keycloak:26.7.1`: claim sets, error shapes, cookie
attributes, password hashing parameters, the objects created when the `master` realm
is bootstrapped. Anything in that document is a contract, not a suggestion.

That measurement contradicted three assumptions written into the original design
before it happened: Keycloak emits four distinct error shapes rather than two,
refresh tokens are signed HS512 rather than RS256, and the admin role container in
the `master` realm is the `master-realm` client rather than `realm-management`.

## Development

```bash
make test    # no Docker, no network
make lint
make build
```

`go test ./...` must never require Docker or network access, so tests that need
either are behind the `docker` build tag:

```bash
go test -tags docker ./internal/store/postgres/
```

That suite is the only evidence the two store drivers agree, so it is worth running
before touching either.

### Conformance against a live Keycloak

The regression catalogue in `internal/conformance` lists documented Keycloak
behaviours. The documentation supplies the list; a running Keycloak supplies the
expected bytes. Nothing in the suite asserts a value taken from a document.

```bash
make conformance   # how much of the parity surface is served
make record        # re-record expected bytes from Keycloak 26.7.1; needs Docker
```

`make conformance` measures against a denominator taken from outside the project
wherever one exists. For the Admin REST API that is Keycloak's own OpenAPI
description, vendored at
`internal/conformance/testdata/openapi/keycloak-26.7.1.json`: 273 paths, 413
operations, 22 resource groups. Chapters with no machine-readable source say so
and stay out of the total rather than being dropped from it silently, which
would inflate the percentage by hiding the parts nobody has counted. It reads:

```
total: 8 of 483 enumerated behaviours served; 4 chapters not enumerated
```

A case has one of three statuses. `Implemented` is served and compared, and a
mismatch is a regression. `Pending` is not built and has no contract. `Recorded`
sits between them: the bytes have been measured and committed, but nothing
serves them yet, so the verifier requires the case *not* to match and fails if
it ever does - a case that starts passing as a side effect would otherwise sit
unguarded until the next refactor broke it.

That is also how a task starts: flip its cases from `Recorded` to `Implemented`
and the failures carry byte-exact diffs against a real Keycloak response.

`make record` rewrites the expected values in
`internal/conformance/testdata/golden`. Read its diff before committing: an
unreviewed re-record pins a regression as the new contract.

An endpoint served without a recorded golden fails `make test`. That is
deliberate - it is how "measured, never remembered" stops being a convention.

`make test` has exactly one known failure, `TestConformance/oidc/certs/master`:
the `master` realm publishes two JWKS keys and Gloak generates one, left red
until realm keys get their own slice. Any other failure is a real regression -
see AGENTS.md's "Build and test" section.

`make record` is not silent on a clean checkout: three of the goldens it writes
churn on every run and will show a diff even when nothing has changed.
`oidc/authorization/invalid-redirect-uri`, `oidc/authorization/unknown-client-id`
and `oidc/logout/invalid-post-logout-redirect-uri` capture login-theme HTML that
carries a resource cache-busting hash generated fresh per container start.

All three are `Pending`, so nothing compares them yet, but their diffs are
expected and can be skipped when reviewing a `make record` run; a diff on any
other golden is the one to read carefully.

A fourth used to churn - `oidc/token/password-grant-admin-cli`'s `scope`, whose
word order is not stable across container starts. `UnorderedWords` sorts the
words inside a string value, so it no longer does.

If Docker runs through Colima or another non-default context, testcontainers does
not discover it on its own:

```bash
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
```

The build must stay cgo-free, so `CGO_ENABLED=0 go build ./...` has to work. SQLite
is `modernc.org/sqlite` for that reason, and swapping in a cgo driver would break the
single-binary property.

## Documentation

| Document | Contents |
|---|---|
| `docs/superpowers/specs/2026-08-18-gloak-design.md` | design of the first slice, and what is deliberately out of it |
| `docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` | measured Keycloak behaviour, the compatibility contract |
| `docs/superpowers/specs/2026-08-18-gloak-followups.md` | known gaps, each reproduced rather than theorised |
| `docs/superpowers/plans/2026-08-18-gloak-foundation.md` | the implementation plan that produced the current code |
| `docs/superpowers/specs/2026-08-20-conformance-harness-design.md` | design of the conformance harness |
| `docs/superpowers/plans/2026-08-20-conformance-harness.md` | the plan that produced it |
| `AGENTS.md` | working conventions, including the traps that look like bugs |

## Trademark

Keycloak is a trademark of Red Hat. Gloak is an independent reimplementation and is
not affiliated with or endorsed by Red Hat.
