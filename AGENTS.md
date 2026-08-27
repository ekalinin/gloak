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
- **That rule is measured too broad.** On the role-mapping paths `PUT` and
  `PATCH` answer a real 405 while `POST` and `DELETE` answer the 404 above -
  same path, four verbs, two statuses - so the verb decides and not the path.
  Gloak sends 404 to all four. What the actual rule is has not been measured;
  only that one line cannot be it. See F31 before adding a 405 or defending
  the 404.
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
  holds the clients the *user* has roles on **minus the issuing client**, and
  Keycloak answers `{"active":false}` with 200 when the caller is outside it.
  The exclusion is measured directly: give the user a role on the requesting
  client and that client appears in `resource_access` and still not in `aud`.
  A refresh token from the same client introspects active, so the check is on
  access tokens alone.
- **Four token claims are absent rather than empty**: `aud` and
  `resource_access` when the user holds no client role, `realm_access` when it
  holds no realm role, `allowed-origins` when the client has no web origins.
  A user with no roles gets a token with none of the four - not `[]`, not `{}`,
  not `{"roles":[]}`. Emitting an empty one "for consistency" is the fix that
  breaks it.
- **`aud` is a string when it names one client and an array when it names
  several.** So is the refresh token's `aud_x`, and so is the introspection
  body's `aud`. The ID token's `aud` is a string always, and it names the
  issuing client - the one place the two tokens disagree.
- **Keycloak's JSON key order for a Java `Map` is `HashMap` bucket order**, not
  sorted and not insertion order. `internal/javamap` reproduces it and is
  confirmed against four measured key sets. It cannot resolve a bucket
  collision, because those chain in insertion order and nothing observable says
  what that was; the 21 admin role names collide twice and come back the other
  way round. Sorting instead is what makes `resource_access` come out
  `account, master-realm` where Keycloak says `master-realm, account`.
- **The refresh token's `scope` is the granted scope plus the client's default
  client scopes**, not a constant. `service_account` is one of them only on a
  client with service accounts enabled, and `openid` only when it was asked
  for. It was written down as a fixed list of eight and was wrong both ways.
- **`account` is the client every user has roles on.** A bootstrap that creates
  it without its eight roles, or without wiring `default-roles-master` over
  `manage-account` and `view-profile`, issues tokens with an empty
  `resource_access` and therefore no `aud` at all. Every user creation path -
  the admin API's and the service account one - has to assign
  `default-roles-<realm>`.
- **`userinfo`'s 200 sends `Cache-Control` twice**, `no-store` then
  `no-cache`. Every rejection sends only `no-store`. The conformance harness
  compares every value of a repeated header because of this one response.
- **A refresh token introspects into the access token's claim set**, nineteen
  keys with `active` last, not RFC 7662's small set. The roles in it are
  resolved at introspection time rather than read out of the token, which is
  how a refresh token carrying none comes back with all of them.
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
- **`PUT` on a role replaces; `PUT` on a client or a user merges.** A role
  updated with a body carrying only `name` loses its description. A role can
  also be renamed through it, where a username cannot. Copying `updateClient`'s
  shape into `updateRealmRole` is the mistake this warns about.
- **`briefRepresentation` defaults to true on a role listing and false on the
  user listing.** Same parameter, two endpoints, opposite defaults, both
  measured. One shared helper would get one of them wrong.
- **Reads accept the manage role, not just the view role.** `view-realm` or
  `manage-realm` for realm roles, `view-clients` or `manage-clients` for
  client roles, on the plain reads and the composite listings alike. The plan
  assumed single-role guards four separate times and was wrong every time.
- **`roles-by-id`'s required role comes from the resolved role's container**,
  and its 404 precedes its 403 - which does leak which role ids exist. That is
  Keycloak's measured order, and the reason previously written down for it was
  backwards.
- **`/roles/{name}/users` needs a conjunction**: a role-management role
  **and** a user-read role (`view-users`/`manage-users`/`query-users`) held
  together. Neither family alone opens it, and two roles from the same family
  do not either. It is the only endpoint in the group that works this way -
  the three siblings that look identical do not.
- **A composite write needs the manage role of every child's own container,
  and only on the add path.** Attaching a client-role child to a realm-role
  parent needs `manage-realm` and `manage-clients` together; removing the
  same child needs only the parent's. Measured on both verbs in both
  directions. Nobody knows why they differ.
- **A composite batch validates before it applies**, so one bad id leaves the
  store untouched, and the answer to a batch mixing a bad id with a forbidden
  child depends on array order.
- **The composite flag is derived, not stored intent**: it is true exactly
  when the role has children, and Keycloak flips it off when the last child is
  removed.
- **The realm's own client refuses a new role even to a full administrator.**
  `POST /clients/{master-realm uuid}/roles` is 403 for everybody; reading its
  21 roles is not.
- **A role listing pages when `search` is non-empty, or when `first` and `max`
  are both present.** Either condition alone is enough; only a request with
  neither gets the whole set back. So `max=5` alone is ignored and
  `first=1&max=5` is not. Measured on both the realm listing and the client
  listing, which agree. The paged path is **sorted by name** and the
  unpaginated one is not sorted at all, which is what makes `first=-1&max=-1`
  come back sorted where `max=2` does not: a negative bound means "no bound",
  but it still counts as present. An empty `search=` neither opens the gate nor
  closes it.
- **That rule was got wrong once, by inference rather than measurement.** The
  first version said pagination needs `search`, generalised from three probes
  that each sent only one bound; the central case, both bounds and no
  `search`, had never been issued. When it was, it paged. Upstream's
  `RealmRolesSearchTest.testPaginationRoles` had said so all along, and the
  contradiction the spec claimed with it was an artifact of comparing
  `list(1, null)` against an assertion about `list(1, 5)`.
- **Role listings have no stable order across container starts.** Every one of
  them is a bare array at the root of the body, which is why `Case.Unordered`
  learned the root path spelling `"."`.
- **Eight spellings of not-found now**, including three for one resource:
  `Could not find client`, `User not found`, `Realm not found.` with its full
  stop, `Credential not found`, `Could not find role`, `Role not found`,
  `Could not find role with id`, `Could not find composite role`.

## Boundaries

| Package | Owns | Must not |
|---|---|---|
| `internal/model` | domain types | depend on anything in the project |
| `internal/store` | repository interfaces, `ErrNotFound`, `ErrConflict` | know about SQL dialects |
| `internal/store/sqlite`, `internal/store/postgres` | the two drivers | diverge from each other in behaviour |
| `internal/keys` | realm signing keys, JWKS | publish the HMAC key or any private key |
| `internal/httpx` | **all** response body formatting | know anything domain-specific |
| `internal/javamap` | Keycloak's JSON key order for a Java map | know what the keys mean |
| `internal/roles` | expanding a user's roles through composites | write anything, or decide who may do what |
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
make oracle  # drives Gloak with kcadm.sh; needs Docker
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
- **`make oracle` is the only test that is not written against a golden.** It
  runs Keycloak's own `kcadm.sh` against Gloak, so it asks for things no case
  asks for. It found `ClientRepresentation.description` - a field Gloak did not
  have, because none of the six bootstrapped clients carries one and so no
  recording ever showed it. Run it after touching a representation.
- Adding a store interface method means implementing it in **both** drivers. The
  conformance suite in `internal/store/storetest` does not exercise every method, so
  compiling is not proof.

## Where a new case can come from

Three sources, in order of how much they cost:

1. **The vendored OpenAPI description.** It says which operations exist. It
   never says what one answers.
2. **A live 26.7.1.** Every expected value comes from here. This is the rule
   at the top of this file.
3. **Keycloak's own test suite.** `make kcsrc` materialises a sparse checkout
   at the pinned tag under `.kc-testsuite/` - `tests/`, `test-framework/`, and,
   because sparse cone mode always includes them, the repository's root files
   too. Nothing makes it read-only; that is a discipline, and the next sentence
   is the actual rule. Its 2490 test methods are claims somebody upstream
   thought worth guarding; the ones about surface Gloak already serves are
   cases this catalogue may be missing.

A mined case goes: read the upstream assertion, measure the same thing against
a live 26.7.1, then add the `Case` under the status the measurement earns. One
Gloak does not serve yet goes in as `Recorded` with a `Reason`, and it is
`make test`'s `TestConformance` failing with "already matches" that tells you
to promote it to `Implemented`; one Gloak already serves goes in as
`Implemented` directly, with no `Reason`.

Those last two are separate rules enforced in separate places, not one rule
and its consequence. An `Implemented` case must carry no `Reason`
(`catalog_test.go`). A `Recorded` case that matches its golden is a hard
failure (`conformance_test.go`, and `case.go`'s `Recorded` doc comment says
why). Neither follows from the other; you can break either on its own.

Cite the upstream file and test method in `Case.Doc.Section`. Nothing is
copied out of `.kc-testsuite/`: upstream is Apache-2.0 and this repository
carries no upstream source.

**Most mined cases pass on the first run, and that is the expected outcome.**
An already-correct behaviour with a golden under it is one the next refactor
cannot break silently. The ones that fail are the finds: `first` and `max` on
the role listings were accepted and ignored until
`RealmRolesSearchTest.testPaginationRoles` was read.

Do not mine `testsuite/`. `testsuite/DEPRECATED.md` freezes it, and
`make kcsrc` does not check it out.

## Conventions

- Commit messages `type(scope): subject`, types limited to `feat`, `fix`, `docs`,
  `test`, `refactor`, `perf`, `chore`. `test` was in use long before it was
  listed - counted across the 144 conventional commits behind this line, `feat`
  59, `docs` 47, `fix` 27, `test` 7, `chore` 3, `refactor` 1, `perf` 0, so it
  outranks three types the list already allowed and `perf` has never been used
  at all. The list was wrong, not the commits; none were rewritten.
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
