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
- the token endpoint: the `password`, `refresh_token` and `client_credentials`
  grants, with client authentication for public and confidential clients
- userinfo, token introspection and token revocation
- roles resolved at issuance, so a token's `realm_access`, `resource_access` and
  `aud` are Keycloak's - including the rule that `aud` names the clients the
  *user* has roles on and never the one that asked for the token, which is why
  introspecting your own access token is refused
- SSO sessions, so `sid` is stable across a refresh and revocation actually ends
  the session
- realm signing keys persisted per realm, so the published `kid` survives a
  restart and two replicas agree
- Postgres and SQLite behind one storage interface, both passing the same
  conformance suite
- the Admin REST API for clients and users: 24 operations, each guarded by the
  `master-realm` client role Keycloak guards it with, resolved from the session
  behind the token because an `admin-cli` token carries no roles to read
- realm roles and client roles: CRUD, composites, `roles-by-id`, and the direct
  holders of a role - 32 operations, guarded by the pair of roles (view or
  manage) Keycloak guards each with, not the single role either name suggests
- a user's role mappings: reading the realm and per-client direct, effective and
  assignable lists, the combined view, and assigning or removing both kinds -
  11 operations, including Keycloak's rule that a caller may hand out a role
  only if its own rights already confer it, which filters the assignable lists
  as well as refusing the writes
- groups: the tree, membership, and a group's role mappings - 24 operations,
  where a group is resolved before the caller is judged, `search` pages the
  matches rather than the rows, and one group has six representations
- multi-realm: realm CRUD, the key listing, default groups, `group-by-path` and
  client policies - 16 operations
- client scopes: the tag in full, a client's and a realm's default and optional
  attachments, and the inheritance a new client gets - 22 operations
- the authorization endpoint's rejections: both error families of `GET`/`POST
  /auth`, the ten-step order they are decided in, and the redirect URI
  comparison. Not the login page, which needs themes
- RP-initiated logout: the redirect, the session end, and
  `post.logout.redirect.uris` - which turned out to be a filter over
  `redirectUris` rather than a separate registration
- **the browser code flow, end to end**: `GET /auth`, the login form,
  `/login-actions/authenticate`, an authorization code carrying the
  `session_state` minted before the password was seen, and its exchange at the
  token endpoint - twelve measured rejections, not the eight the first
  recording named
- protocol mappers and scope mappings: both tags in full - 54 operations, where
  the scope-mapping guard turned out **not** to be the role-mapping guard, in
  both directions at once
- client secrets, service accounts, user credentials and user logout
- a documentation-derived conformance suite (`internal/conformance`) that checks
  Gloak's responses byte-for-byte against bytes recorded from a live
  Keycloak 26.7.1
- a parity meter whose denominator comes from Keycloak's own OpenAPI description
  rather than from a hand-kept list: **242 of 500 enumerated behaviours served**,
  plus four chapters whose surface has not been counted
- an external oracle: `make oracle` drives Gloak with `kcadm.sh`, Keycloak's own
  admin CLI, which asks for things no recorded case asks for

Not implemented yet: the login page's own markup (the flow is served, the theme
is not), SSO recognition - a second visit serves the form where Keycloak
redirects straight through - back-channel and front-channel logout, SAML, user
federation, identity brokering, authorization services, the admin console.

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
| `POST /realms/{realm}/protocol/openid-connect/token` | token issuance |
| `GET POST /realms/{realm}/protocol/openid-connect/userinfo` | claims about the subject |
| `POST /realms/{realm}/protocol/openid-connect/token/introspect` | token introspection |
| `POST /realms/{realm}/protocol/openid-connect/revoke` | token revocation |
| `GET POST /realms/{realm}/protocol/openid-connect/auth` | authorization: validation, the login form, and the code |
| `POST /realms/{realm}/login-actions/authenticate` | the credential check |
| `GET POST /realms/{realm}/protocol/openid-connect/logout` | RP-initiated logout |

There is no `/auth` **prefix** - Keycloak dropped it in version 17 - which is a
different thing from the `/protocol/openid-connect/auth` endpoint above.

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
total: 242 of 500 enumerated behaviours served; 4 chapters not enumerated
```

The denominator is 500 rather than 413 plus a fixed number because the protocol
chapters have no OpenAPI source and are counted case by case, so they grow as
measurements find behaviours nobody had named. It moved from 485 on 2026-08-29
for the first time since it was set, and again the next day when the logout
endpoint turned out to have fourteen measurable behaviours where the catalogue
had five. The Admin API chapters cannot move this way and none has.

CI reruns this meter on every pull request and posts the parity increment as
a comment, failing the pull request when the total falls. A flat total is
reported as `total unchanged` rather than `no change` when chapters moved
underneath it: four chapters have no denominator, so work served in one of them
moves a row and cannot move the total, and saying "no change" above a table
showing `+3` would be a comment contradicting itself. A deliberate fall
is declared with a `Parity-decrease: <reason>` line in the pull request
description - the marker must be the first non-whitespace content of its
own line (leading whitespace is fine, case does not matter, and a mid-line
mention does not count), so a markdown bullet such as
`- Parity-decrease: <reason>` does not match either. With several such
lines, only the first is used.

The same comparison runs locally. `GLOAK_PARITY_REPORT=<path>` makes the meter
write its tally to that path as tab-separated values, alongside printing it;
`cmd/parity` compares two of them. AGENTS.md's "Build and test" section spells
out the five commands.

A case has one of three statuses. `Implemented` is served and compared, and a
mismatch is a regression. `Pending` is not built and has no contract. `Recorded`
sits between them: the bytes have been measured and committed, but nothing
serves them yet, so the verifier requires the case *not* to match and fails if
it ever does - a case that starts passing as a side effect would otherwise sit
unguarded until the next refactor broke it.

That is also how a task starts: flip its cases from `Recorded` to `Implemented`
and the failures carry byte-exact diffs against a real Keycloak response. P1
worked exactly that way and cleared the list; P2 put six cases back on it, each
naming the sub-project that unblocks it.

`make record` rewrites the expected values in
`internal/conformance/testdata/golden`. Read its diff before committing: an
unreviewed re-record pins a regression as the new contract.

It runs two container regimes. Almost every case is recorded against one shared
Keycloak in catalogue order, which is why a whole run is one container start and
not three hundred. A case marked `PristineRealm` - one whose body describes the
realm as a whole rather than one object in it - gets a container of its own,
started inside its subtest and thrown away with it, because the verifier will
serve it from a handler that has seen nothing but that case's own fixture. That
costs about two minutes for a whole run instead of thirty seconds, and it
replaced "record the pristine cases first", which cannot work: the pristine
group pollutes itself.

An endpoint served without a recorded golden fails `make test`. That is
deliberate - it is how "measured, never remembered" stops being a convention.

`make test` is clean, and any failure is a real regression - see AGENTS.md's
"Build and test" section. It used to carry one sanctioned failure,
`TestConformance/oidc/certs/master`, because the `master` realm publishes two
JWKS keys and Gloak generated one; realm keys are now modelled and persisted, so
that case passes.

**`make record` is silent on a clean checkout.** It rewrites 327 goldens with
identical bytes and moves none, so any diff at all is one to read carefully.

That was not always so. Four login-theme pages churned their whole body on every
run, because the `/resources/<hash>/` segment is regenerated per container start,
and the count went from three to four inside two days. Those four are `Pending`,
so nothing compared them and the churn bought nothing. The recorder now leaves a
`Pending` golden exactly as it found it; the way to ask for one back is to
promote the case to `Recorded`, which is what `Recorded` already means. Seven
`Pending` goldens are parked in all, each declared in `parkedGoldens` with the
reason it is kept - a parked golden is a measurement, never a contract.

A fourth used to churn - `oidc/token/password-grant-admin-cli`'s `scope`, whose
word order is not stable across container starts. `UnorderedWords` sorts the
words inside a string value, so it no longer does.

If Docker runs through Colima or another non-default context, testcontainers does
not discover it on its own:

```bash
export DOCKER_HOST="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
export TESTCONTAINERS_RYUK_DISABLED=true
```

The third was needed to get `make record` and the Docker-tagged suites to run
under Colima on the machine this was last done on; the first two alone were not
enough. It turns off Ryuk, the reaper testcontainers starts to clean up after
itself, which leaves cleanup to each test's own teardown - so an interrupted
run can leave a container behind, and `docker ps` afterwards is worth a look.

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
