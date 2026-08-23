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

The rule is no longer only a convention. `internal/conformance` fails the build
for any endpoint marked `Implemented` that has no recorded golden, so shipping a
response nobody measured is a red test rather than something a reviewer has to
catch.

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
- **`GET /realms/{realm}` sends `Content-Type: application/json;charset=UTF-8` on
  its 200, and plain `application/json` on its own 404.** Every other endpoint
  measured so far, success or error, sends plain `application/json`. The
  inconsistency is real and it is only on this one endpoint.
- **A wrong method on a known path returns 404, not 405, with no `Allow`
  header.** Gloak once invented a 405 that does not exist; Keycloak answers with
  the same generic 404 it uses for everything else it cannot route. The two 404s
  are not the same body, though: an unmatched path answers `{"error":"Unable to
  find matching target resource method"}`, a wrong method on a known path
  answers `{"error":"HTTP 404 Not Found"}`. That is why `withKeycloakFallbacks`
  still tells the two cases apart even though both return the same status.
- **The five security headers have three exceptions, not one.** A route match
  and a known path hit with the wrong method both get `Referrer-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`
  and `X-Robots-Tag`. A path matching no route at all gets none of them,
  because that request never reaches Keycloak's filter chain. **`userinfo`'s
  rejections send four of the five, omitting `X-Frame-Options`** - they do
  reach the filter chain, so this one is not explained by routing, and its
  own 200 sends all five, so it is not explained by the endpoint either. And
  **a 204 carries `X-Frame-Options` only when the request declared an
  `application/*` `Content-Type`**: measured across seven Content-Type values
  on one endpoint, every one answering 204. That covers every delete (no
  Content-Type, so no header), the client and user updates (JSON, so the
  header), and `PUT .../userLabel` (`text/plain`, so no header).
  `httpx.WriteNoContent` is the one place that decides. Applying them
  uniformly "for consistency" is the fix that would break all three.
- **That rule was wrong once already.** P2's Task 11 recorded it as "a
  successful `DELETE`'s 204 omits it", from four deletes that all happened to
  send no `Content-Type`. When a new 204 disagrees with a header rule, measure
  the request's headers before believing the method.
- **`Cache-Control` on a 204 does not follow the method.** Four of the five
  measured deletes carry `no-cache` and `DELETE .../client-secret/rotated`
  does not; no `PUT` carries it. It is pinned per endpoint.
- **A client with no secret answers `GET .../client-secret` with 200 and no
  `value` key**, not 404 - and none of the six bootstrapped clients has one.
  `POST` mints a secret even for a public client, whose representation then
  still omits it: `secret` in `ClientRepresentation` follows `publicClient`,
  not what is stored.
- **A rotated client secret cannot exist on a default 26.7.1.**
  `CLIENT_SECRET_ROTATION` is a disabled preview feature and `secret-rotation`
  is not a registered executor, so `GET .../client-secret/rotated` is always
  404 and `DELETE` always 204. Those constants are the contract, not stubs.
- **`attributes` key order is the one thing the conformance suite does not
  compare.** It is a Java `Map` in hash order and Go sorts map keys; matching it
  would mean emulating `java.util.HashMap` in Go. `Case.UnorderedKeys` sorts
  both sides, so membership and values are still asserted. This is the only
  such retreat - do not add a second without writing down why.
- **Gloak deletes the `Date` header on every response.** Keycloak sends none;
  Go's `net/http` adds one automatically, so `internal/httpx` suppresses it with
  `w.Header()["Date"] = nil`. The conformance verifier cannot catch its removal:
  it serves through `httptest.ResponseRecorder`, which never adds a `Date`
  header either. The guard is `internal/httpx`'s own test, which uses a real
  `httptest.NewServer` instead.
- **A dead session and a bad refresh token answer differently.** A token whose
  session was ended - by an admin logout or by revocation - answers
  `"Session not active"`; one that was never valid answers
  `"Invalid refresh token"`. Same status, same code, different description.
- **`POST /users/{id}/logout` stamps the user's `notBefore`** with the moment
  it happened, so its effect is visible in the representation and not only in
  its 204.
- **Revocation answers an unknown token with 200 and an error body**, not 400:
  `{"error":"invalid_token","error_description":"Invalid token"}` with a 200 status
  line. The client asked for a token to stop working and it does not work.
- **The revocation success is the only response measured so far carrying
  `Content-Security-Policy`**, and it carries no `Content-Type` at all - the body
  is empty. Revocation's own error responses carry neither. That is why the header
  is set at one call site rather than alongside the five security headers.
- **A public client may revoke but may not introspect.** `admin-cli` revoking
  succeeds; `admin-cli` introspecting is refused with 403
  `{"error":"invalid_request","error_description":"Client not allowed."}`.
- **A client cannot introspect its own access token.** An access token's `aud`
  holds the clients the *user* has roles on, never the issuing client, and
  Keycloak answers `{"active":false}` with 200 when the caller is outside it.
  A refresh token from the same client introspects active, so the check is on
  access tokens alone. Gloak does not do this yet - see F18.
- **`userinfo`'s 200 sends `Cache-Control` twice**, `no-store` then
  `no-cache`. Every rejection sends only `no-store`. The conformance harness
  compares every value of a repeated header because of this one response.
- **A refresh token introspects into the access token's claim set**, nineteen
  keys with `active` last, not RFC 7662's small set.
- **`not-before-policy`** in the token response is spelled with hyphens.
- **Refresh tokens are signed HS512**, access and ID tokens RS256. That is why a
  realm holds two keys.
- **`admin-cli` has standard flow disabled and direct grants enabled**, and carries
  `client.use.lightweight.access.token.enabled = true`. Without that attribute its
  access tokens carry a different claim set than Keycloak's.
- **The admin role container in `master` is the `master-realm` client.**
  `realm-management` is its equivalent inside non-master realms.
- **One user serialises three ways.** `GET /users` carries a one-key `access`
  block, `GET /users/{id}` a six-key one, and
  `.../clients/{uuid}/service-account-user` none at all. A shared user
  serialiser would be wrong twice. `access` describes the **caller's**
  permissions, never the user being read.
- **`GET /users/count` is a bare JSON number**, and it is not filtered by what
  the caller may see, while the listing beside it is.
- **The user listing's two filter families do not agree.** `username`, `email`,
  `firstName` and `lastName` are case-insensitive **substrings** where `*` is a
  literal; `search` is a case-insensitive **prefix** where `*` is a wildcard
  and `"quotes"` mean equality, and `exact=true` does not reach it. Writing one
  comparison for both is the mistake this project already made once.
- **A user's username is lowercased on create and immutable on update.** A
  `PUT` naming a free username answers 204 and changes nothing; naming a taken
  one still answers 409.
- **An empty or `null` request body on `POST /users` is a 500**, not a 400.
  Another of Keycloak's own defects, reproduced.
- **A credential list carries no secret**, so `view-users` is enough to read
  it. `credentialData` inside it is a **JSON string**, not a nested object, and
  the `additionalParameters` inside *that* are a Java map in hash order which
  the suite cannot normalise - so `internal/admin` writes the five argon2 keys
  out in the measured order rather than marshalling a Go map.
- **`reset-password` ignores the `type` it is given** and sets a password
  whatever it is told, replacing the credential in place: same id, refreshed
  `createdDate`, `userLabel` cleared.
- **`PUT .../userLabel` consumes `text/plain`.** Sending JSON answers 415.
- **"Credential not found" is a fourth not-found spelling**, after "Could not
  find client", "User not found" and "Realm not found." with its full stop.

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
| `internal/conformance` | the documentation-derived catalogue and golden comparison | be imported by production code, or know about SQL or handler internals; it sees only an `http.Handler` |

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

- `make test` is clean. **Any** failure is a real regression. It was not always so:
  `TestConformance/oidc/certs/master` was allowed to fail until realm keys were
  modelled and persisted (follow-up F5), which P1 did. No case is exempt now, and
  adding an exemption means changing this line first.
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
