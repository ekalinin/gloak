# Gloak: design of the first slice

Date: 2026-08-18
Status: accepted

## 1. What this is

Gloak is Keycloak rewritten in Go. It is a deliberate copy, not a separate product
with a different feature set.

The name: **G** from Go, **loak** from Keycloak. Module path is
`github.com/ekalinin/gloak`. The word "keycloak" is not used in the name in full,
as it is a Red Hat trademark.

## 2. What compatibility means here

The copy targets **API compatibility**, not internal structure. From the outside
Gloak must look like Keycloak; on the inside it is free.

Compatible:

- OIDC and OAuth2 endpoints
- Admin REST API
- Representation JSON structures, and therefore the realm export format

Deliberately incompatible:

- database schema is our own
- internal abstractions are our own
- configuration is our own

That is the goal of the project as a whole. Which part of it lands in the first
slice is covered in section 3.

**Target version: Keycloak 26.7.1** (released 2026-08-05, the latest stable at the
time this decision was made). The version is pinned as a contract. "Compatible with
Keycloak" is undefined without a version number: the admin API and export formats
change between minor releases.

## 3. Scope of the first slice

The first slice is a working OIDC provider for a single realm, good enough to point
a real application at Gloak instead of Keycloak and watch the login succeed. Plus a
thin slice of the admin REST API, enough for entities to be created from the
outside by existing tooling.

The admin API is included in the first slice on purpose: compatibility has to be
held in mind from the start, because bolting it on later costs more.

## 4. Architecture

| Package | Responsibility | Depends on |
|---|---|---|
| `internal/model` | domain types: realm, client, user, role, credential, session | nothing |
| `internal/store` | repository interfaces | `model` |
| `internal/store/postgres` | Postgres implementation | `store`, `model` |
| `internal/store/sqlite` | SQLite implementation | `store`, `model` |
| `internal/keys` | realm signing keys, JWKS, rotation | `go-jose` |
| `internal/token` | issuing and parsing access, refresh and ID tokens | `keys`, `model` |
| `internal/auth` | password verification, browser session, login form | `store`, `model` |
| `internal/oidc` | discovery, authorize, token, userinfo, logout, certs | `store`, `token`, `auth` |
| `internal/admin` | admin REST API | `store`, `model` |
| `internal/httpx` | router, middleware, error format | nothing domain-specific |
| `cmd/gloak` | configuration, migrations, startup | everything above |

Three of these decisions need justification.

**The error format lives in its own package, `httpx`.** Compatibility breaks on
error paths more often than on the happy path: status code, body, field names. A
format smeared across handlers gets fixed forever. One package gives one place to
change and one place for the differential test to look at.

**`oidc` knows nothing about SQL**, it only sees `store` interfaces. That is what
lets tests swap in SQLite and run protocol checks without Postgres.

**`keys` is separate from `token`.** Today it is a single key pair per realm, but
rotation, multiple active keys in the JWKS and algorithms beyond RS256 are
inevitable, and splitting this later is more expensive.

## 5. Data model

The schema is our own, but entity names and the shape of identifiers follow
Keycloak: `realm`, `client`, `user_entity`, `keycloak_role`, `user_role_mapping`,
`credential`, `user_session`.

This is not about aesthetics. Entity identifiers leak outward through admin API
responses and through tokens, so the string UUIDs have to match the original, or
clients and the Terraform provider will see the difference.

Passwords live in a `credential` table split into a public part (algorithm,
iteration count, parameters) and a secret part (hash, salt), the way the original
arranges it.

Migrations: SQL files embedded through `embed.FS`, a separate set per driver
(Postgres and SQLite diverge in syntax and types anyway), applied at startup.

## 6. Protocol endpoints

Everything under `/realms/{realm}/protocol/openid-connect/`. There is no `/auth`
prefix: Keycloak dropped it in version 17.

| Endpoint | Purpose |
|---|---|
| `GET /realms/{realm}/.well-known/openid-configuration` | discovery document |
| `GET /realms/{realm}` | realm name and public key, used by adapters |
| `GET .../certs` | JWKS |
| `GET .../auth` | authorization endpoint and login form |
| `POST .../token` | grants `authorization_code`, `refresh_token`, `password`, `client_credentials` |
| `GET POST .../userinfo` | user claims |
| `GET POST .../logout` | RP-initiated logout |
| `POST .../token/introspect` | introspection |
| `POST .../revoke` | token revocation |

PKCE is mandatory for public clients, `code_challenge_method=S256`.

The `password` and `client_credentials` grants are in the first slice not as part
of the browser login, but as a precondition for the admin API being usable at all:
`kcadm.sh` authenticates through the password grant on the `admin-cli` client, and
the Terraform provider normally runs as a service account through client
credentials. An admin API without those two grants is an API no existing tool can
connect to.

## 7. Admin REST API

Under `/admin/realms/`:

- **realms** - list, create, read, update, delete
- **clients** - CRUD plus `client-secret`. Paths use the client's internal UUID, not
  its `clientId`, which is a recurring source of incompatibility in clones
- **users** - CRUD, search by username and email, `count`, `reset-password`
- **roles** - realm roles and client roles
- **role-mappings** - granting and revoking roles for a user

Realm export (`partial-export`) is out of the first slice, but it will not require
separate work: the export format is made of the same representation structures the
admin API returns. Correct `RealmRepresentation`, `ClientRepresentation` and
`UserRepresentation` make export nearly free. That is one more argument for getting
the JSON exactly right from the beginning.

## 8. Bootstrap

At startup we create: the `master` realm, the public `admin-cli` client with direct
grant enabled, an administrator user, and the `realm-management` client roles. This
is the arrangement existing tooling expects to find.

## 9. Deliberate departures from the original

**The browser flow is reproduced by behaviour, not by internal URLs.** Keycloak's
login form posts to `/realms/{realm}/login-actions/authenticate` with `session_code`,
`execution` and `tab_id` parameters. That is the plumbing of its configurable flow
engine, not part of the contract: client applications never see it, they follow a
redirect and come back with a code. Reproducing those URLs in the first slice would
mean dragging in the whole executions model.

**Configuration is not copied.** Environment variables are our own, prefixed
`GLOAK_`, rather than `KC_DB` and `KC_HOSTNAME`. Configuration is not part of the
API contract, no client ever sees it, and copying it would pull in Keycloak's whole
model of build-time and runtime options.

**The first slice hardcodes a single authentication flow**: login by password. The
configurable graph of executions is a later slice of its own.

## 10. Verifying compatibility

Compatibility is verified by diffing against a live Keycloak, not by reading the
documentation. Documentation drifts from the implementation in small details, and
small details are the entire subject here.

The harness runs in two modes.

**Record mode.** Starts `quay.io/keycloak/keycloak:26.7.1` in Docker, runs the
scenarios through it (login, code exchange, refresh, userinfo, client creation,
malformed requests) and stores the responses as golden files in the repository.

**Check mode.** Runs the same scenarios against Gloak and compares them to the
golden files. Requires neither Docker nor network access.

The split matters: `go test ./...` must not require Docker, or people will stop
running it. Recording golden files is a separate command, invoked deliberately when
the target version changes.

What gets compared: status code, the `Content-Type` and `Cache-Control` headers, the
full JSON body, and the **set** of token claims (the values differ by definition).

Whatever cannot match - UUIDs, timestamps, nonces, signatures - is normalised
through an explicit list of rules. **That list must stay short.** Every new
normalisation rule is a piece of compatibility that stopped being checked, and the
list can grow without anyone noticing.

On top of the golden diff there is one end-to-end test driven by a real client
library (`coreos/go-oidc` acting as the relying party): a full login from redirect
to ID token validation. It catches what a response diff cannot catch by
construction - wrong redirect ordering, malformed `Set-Cookie`, disagreement
between the discovery document and actual behaviour.

The OpenID Foundation conformance suite is out of the first slice; the architecture
must not stand in the way of adding it later.

## 11. Error format

There are two formats:

- **protocol errors** follow RFC 6749:
  `{"error": "invalid_grant", "error_description": "..."}`
- **admin API errors** use Keycloak's own format with an `errorMessage` field and
  its own conventions for status codes, in particular 409 on conflicts

Both are pinned by golden tests, because they cannot be reconstructed from the
documentation.

## 12. Technology decisions

- **Go 1.26**
- **Router** - the standard library `net/http`. Since 1.22 `ServeMux` supports
  methods and path parameters, so no external router is needed
- **JOSE** - `go-jose/go-jose` v4. We do not write our own cryptography, only our
  own protocol layer on top of it
- **Database drivers** - `jackc/pgx` and `modernc.org/sqlite`. SQLite in pure Go,
  without cgo, so the build stays a single binary
- **Logging** - `log/slog`
- **Test dependencies** - `testcontainers-go`, `coreos/go-oidc`
- **Build** - a single binary plus a Docker image

`ory/fosite` was considered and rejected: its last release was in December 2024,
close to two years without a release. `zitadel/oidc` was considered and rejected for
a different reason: it is a full OP framework with its own storage model and its own
error formats, which would have to be bent around Keycloak's quirks, meaning the
friction would appear exactly where compatibility matters most.

## 13. Out of scope for the first slice

Admin console UI, account console, SAML 2.0, user federation (LDAP, Kerberos),
identity brokering and social logins, authorization services (UMA 2.0), configurable
authentication flows, themes and i18n, SMTP, events and audit, clustering and
caching, device flow, back-channel logout, session iframe, self-registration, token
exchange.

Each of these is a spec and an implementation cycle of its own.

## 14. To be measured against a live instance during implementation

Not "open design questions", but a list of things to be taken by measurement against
`quay.io/keycloak/keycloak:26.7.1` rather than from memory:

- the default password hashing algorithm and its parameters (in 26.x this is argon2;
  the exact parameters are to be read from the instance)
- the exact contents of the discovery document
- the exact claim sets of access, refresh and ID tokens
- the exact bodies and status codes for malformed requests, in both formats
- the exact field sets of `RealmRepresentation`, `ClientRepresentation` and
  `UserRepresentation`
- the set of objects Keycloak creates when bootstrapping the `master` realm
