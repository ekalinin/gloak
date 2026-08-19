# Working on Gloak

Gloak is Keycloak rewritten in Go. It is a deliberate copy: from the outside it must
be indistinguishable from **Keycloak 26.7.1**, byte for byte wherever a client can
observe it, while its schema and internals are its own.

Read `README.md` for what the project is and how to run it. This file is about how
to change it.

## The one rule that overrides the others

**Observable values are measured, never remembered.**

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` records what a live
Keycloak 26.7.1 actually emits. Every value in it is a contract: error strings,
status codes, header spellings, claim names, cookie attributes, argon2 parameters,
JSON key order.

If you need an observable value that is not in that document, measure it and record
it there. Do not write it from memory, and do not infer it from the documentation:

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
# ... measure ...
docker rm -f gloak-ref
```

Two endpoints are shipped with no measured contract yet, noted in the follow-ups
document: `/protocol/openid-connect/certs` and `GET /realms/{realm}`. Their field
sets and cache headers were written from memory, against this rule, and should be
measured before the golden harness lands.

## Things that look like bugs and are not

Fixing any of these breaks compatibility. They are measured Keycloak behaviour.

- **Four error shapes, not one.** `{"error","error_description"}`, a bare `error`
  holding prose, `{"errorMessage"}`, and the RFC 6749 shape on the admin API. They do
  not split along the protocol/admin boundary. `userinfo` with a bad token is its own
  case: 401, `text/plain`, empty body, error in `WWW-Authenticate`.
- **An unknown client returns `invalid_client`, a wrong secret returns
  `unauthorized_client`** with identical descriptions.
- **"Realm not found." has a trailing period on the admin API and none on the
  protocol endpoint.**
- **`not-before-policy`** in the token response is spelled with hyphens.
- **Refresh tokens are signed HS512**, access and ID tokens RS256. That is why a
  realm holds two keys.
- **`admin-cli` has standard flow disabled and direct grants enabled**, and carries
  `client.use.lightweight.access.token.enabled = true`. Without that attribute its
  access tokens carry a different claim set than Keycloak's.
- **The admin role container in `master` is the `master-realm` client.**
  `realm-management` is its equivalent inside non-master realms.

## Boundaries

| Package | Owns | Must not |
|---|---|---|
| `internal/model` | domain types | depend on anything in the project |
| `internal/store` | repository interfaces, `ErrNotFound`, `ErrConflict` | know about SQL dialects |
| `internal/store/sqlite`, `internal/store/postgres` | the two drivers | diverge from each other in behaviour |
| `internal/keys` | realm signing keys, JWKS | publish the HMAC key or any private key |
| `internal/httpx` | **all** response body formatting | know anything domain-specific |
| `internal/oidc` | protocol handlers | know about SQL; it sees only `store` interfaces |
| `internal/bootstrap` | creating the `master` realm | modify objects that already exist |
| `cmd/gloak` | config, wiring, serving | contain logic worth testing on its own |

Two of these have already been violated once and repaired, so they are worth
restating:

- **`internal/httpx` is the only place a response body is marshalled.** A second
  JSON writer appeared in the router, diverged on the trailing newline, and made
  success bodies differ from Keycloak by one byte with no test noticing.
- **The two store drivers must behave identically.** A retry loop added to the
  Postgres `Open` to work around a test-environment race made it mask an unreachable
  server for ten seconds while SQLite failed fast. Test-environment problems get
  fixed in the test.

## Response bodies

Marshal from structs with fields declared in Keycloak's order, never from
`map[string]any`. Go emits map keys alphabetically, which silently reorders every
key in the response, and tests that parse JSON will not see it.

The discovery document's order comes from
`internal/oidc/testdata/discovery-26.7.1.json`, which preserves what Keycloak sent.

## Build and test

```bash
make test    # CGO_ENABLED=0 go test ./...
make lint
make build
```

- `go test ./...` must never require Docker or network access. Anything that does
  goes behind the `docker` build tag.
- `CGO_ENABLED=0 go build ./...` must work. SQLite is `modernc.org/sqlite` to keep
  the binary a single static file; do not swap in a cgo driver.
- The Postgres suite (`go test -tags docker ./internal/store/postgres/`) is the only
  evidence the drivers agree. Run it after touching either.
- Adding a store interface method means implementing it in **both** drivers. The
  conformance suite in `internal/store/storetest` does not exercise every method, so
  compiling is not proof.

## Conventions

- Commit messages `type(scope): subject`, types limited to `feat`, `fix`, `docs`,
  `refactor`, `perf`, `chore`.
- Never commit to `main`. Branch names carry their work type: `feat/`, `fix/`,
  `refactor/`, `docs/`, `chore/`.
- Code comments in English.
- Prefer the smallest diff that does the job, and preserve existing names.
- Environment variables use the `GLOAK_` prefix, never `KC_`.
- Secrets never arrive by command-line flag; argv is readable by any process.

## Before claiming something works

Run it. The measured contract makes this project unusually easy to satisfy on paper
and fail in practice: tests that parse JSON pass while byte order is wrong, tests on
in-memory SQLite pass while the file-backed path is broken, and a driver method that
compiles can still return the wrong rows.

Known gaps are in `docs/superpowers/specs/2026-08-18-gloak-followups.md`. Each was
reproduced, not theorised. Read it before concluding you have found something new.
