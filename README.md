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

Not implemented yet: tokens and grants, the browser login flow, userinfo, logout,
introspection, revocation, the admin REST API, SAML, user federation, identity
brokering, authorization services, the admin console.

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
| `AGENTS.md` | working conventions, including the traps that look like bugs |

## Trademark

Keycloak is a trademark of Red Hat. Gloak is an independent reimplementation and is
not affiliated with or endorsed by Red Hat.
