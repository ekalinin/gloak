# Keycloak's own test suite as a second oracle

Date: 2026-08-25
Status: accepted

## 1. What this is

Gloak has one external oracle today: `make oracle` drives Gloak with `kcadm.sh`,
the admin CLI that ships inside the Keycloak image, and it earns its keep by
asking for things no golden asks for. It found `ClientRepresentation.description`
on its first run.

Keycloak also ships something larger: its own regression suite, 2490 test methods
of it. This document answers whether that suite can become a second oracle, what
it would cost, and what has to exist first.

The answer is yes, but not yet, and the blocker is a sub-project the roadmap has
already scheduled. Section 4 is the measurement that says so. Section 5 splits
the work into three tracks and says which one is available today.

This is not an implementation plan. Track A has one:
`docs/superpowers/plans/2026-08-25-keycloak-testsuite-mining.md`. Tracks B and C
get theirs when their dependencies land, for the reason
`2026-08-21-gloak-parity-roadmap.md` section 7 gives: a specification written
before anyone reaches the work has the appearance of accuracy without the
measurement behind it.

## 2. What upstream actually has

Measured against tag `26.7.1`, commit `73f08b397f193712b26d317210dce99898129709`,
read on 2026-08-25 from a sparse checkout of `github.com/keycloak/keycloak`.

Three top-level trees carry tests:

| Tree | What it is | Test classes |
|---|---|---|
| `tests/` | the current suite, written against the Keycloak Test Framework, JUnit 5 | 447, of which `tests/base` holds 430 |
| `test-framework/` | the framework those tests run on, published as `keycloak-test-framework-*` Maven modules | its own 4 |
| `testsuite/` | the Arquillian suite, JUnit 4 | 649 |

`tests/base` holds **2490 test methods**: 2483 `@Test` plus 7
`@ParameterizedTest`. They are spread over the 364 of its 484 `.java` files
that declare at least one, and 398 of those files carry
`@KeycloakIntegrationTest`, the annotation that starts a server. Every `.java`
file in `tests/base` is under `src/test/java`.

**An earlier version of this line said 2643, and that number was a grep
artifact.** It came from `grep -rho '@Test[A-Za-z]*'`, which has no word
boundary, so it also counted 121 `@TestOnServer`, 22 `@TestSetup`, 15
`@TestMethodOrder` and 2 `@TestCleanup` - lifecycle and ordering annotations,
not test methods. 2483 + 121 + 22 + 15 + 2 = 2643 exactly. The counts above are
word-bounded:

```
grep -rhoE '@(Test|ParameterizedTest)\b' .kc-testsuite/tests/base | wc -l
```

Counted against the pinned checkout, `73f08b397f193712b26d317210dce99898129709`.

**`testsuite/` is deprecated and should be ignored.** `testsuite/DEPRECATED.md`
says so in as many words: Arquillian is no longer maintained upstream, the module
is frozen, "adding new files is not allowed", and edits are permitted only to add
a case alongside a bug fix. Anything mined from there is mined from a tree its
own authors are emptying. The migration is tracked by `tests/migration-util`,
a tool whose stated purpose is to be deleted when the move is finished.

The role tests have already made the move, which matters because roles are what
P2's second cut just built: `admin/RoleByIdResourceTest`,
`admin/realm/RealmRolesCRUDTest`, `RealmRolesSearchTest`, `RealmRolesUserTest`,
`admin/client/ClientRolesTest`, `ClientRoleMapperTest`,
`admin/user/UserRoleTest` and `admin/user/CompositeClientRoleMappingsTest` are
all in `tests/base`.

One more module is worth naming and setting aside. `tests/conformance` is not a
general OIDC conformance run: in 26.7.1 it covers OID4VCI only, four issuer
tests. What it does show is that Keycloak drives
`registry.gitlab.com/openid/conformance-suite` from Testcontainers, which is
track C below.

## 3. The connection point already exists

The framework can be told not to manage the server.
`test-framework/core/src/main/java/org/keycloak/testframework/server/RemoteKeycloakServerSupplier.java`
registers the alias `remote`, and `RemoteKeycloakServer` beside it does nothing
on `start()` beyond checking that something is listening, nothing at all on
`stop()`, and reports a fixed base URL of `http://localhost:8080`. It is selected
with `KC_TEST_SERVER=remote`.

Readiness is not the management port. `ReadinessProbe.waitUntilReady` polls
`<base>/realms/master` for a 200, with a comment saying `/health/ready` is
deliberately not used because most tests do not enable it. Gloak serves that
endpoint already.

So there is no architectural objection to pointing the suite at a server upstream
did not build. The objections are all about what the tests then ask for.

## 4. Why almost none of it runs today

Every class was classified by resolving `extends` within `tests/base` and taking
the union of the annotations on the class and its ancestors. That step is not
optional: `RealmRolesCRUDTest` looks clean on its own and inherits
`@InjectRealm` and `@InjectAdminEvents` from `AbstractRealmRolesTest`. An
unresolved grep says 65 classes are clean; resolved, the answer is 8.

Of the 393 classes carrying `@KeycloakIntegrationTest`:

| Needs | Classes | Reachable for Gloak? |
|---|---|---|
| a fresh realm, client or user fixture | 357 | after P4 |
| code executed inside the server JVM (`RunOnServer`) | 183 | never |
| a browser (`@InjectPage`, `@InjectWebDriver`) | 157 | after P3 |
| admin or user events | 169 | after P14 |
| a custom `KeycloakServerConfig` | 184 | case by case |
| mail, Infinispan, syslog or its own database | 20 | case by case |
| none of the above | 8 | today |

The buckets overlap; a class usually sits in several.

The dominant number is the first one. **`@InjectRealm` creates a realm over the
Admin API and deletes it afterwards.**
`test-framework/core/.../realm/RealmSupplier.java` calls
`adminClient.realms().create(realmRepresentation)` in `getValue` and
`instanceContext.getValue().admin().remove()` in `close`. Gloak serves `master`
and nothing else: `internal/admin/router.go` has no route for `/admin/realms`
without a realm segment after it. Realms Admin is **P4** in the roadmap, 45
operations of it.

Three smaller blockers sit behind that one:

- **The admin client authenticates as a bootstrap service account.**
  `Config.getAdminClientId()` returns `temp-admin` and `getAdminClientSecret()`
  returns `mysecret`, used with the client credentials grant against `master`.
  Keycloak mints that client from `--bootstrap-admin-client-id` and
  `--bootstrap-admin-client-secret`. `internal/bootstrap` creates six clients and
  `temp-admin` is not one of them.
- **`RunOnServer` deploys a JAR into the server and runs the test body inside
  it.** There is no version of that which a Go server can serve. Those 183
  classes are permanently out of reach, and no amount of P-numbers changes it.
- **A custom `KeycloakServerConfig` restarts the server.** In `remote` mode the
  framework cannot restart anything, so it prints the required command line and
  waits up to five minutes. A run that hits one of those 184 classes hangs rather
  than fails, which makes an unfiltered run useless as a signal.

The eight classes that need none of it are
`AdminConsoleLandingPageTest`, `AdminEndpointAccessibilityTest`,
`AdminPreflightTest`, `DatabaseIndexCheckerTest`,
`HostnameV2NoHostnameConfiguredTest`, `PartialExportTest`, `ServerInfoTest` and
`TokenInputValidationTest`. Three of them are about surface Gloak has
(`AdminPreflightTest`, `AdminEndpointAccessibilityTest`,
`TokenInputValidationTest`); the rest are about the admin console, the database
schema, hostname resolution and partial export. Standing up the Maven reactor to
run three test classes is not a trade worth making.

## 5. Three tracks, in dependency order

### 5.1 Track A: mine the tests for behaviours, available today

Read upstream's tests as a **source of scenarios** rather than running them.
Every assertion in `tests/base` is a claim about Keycloak that somebody at Red
Hat thought worth guarding. A claim about surface Gloak already serves is a case
the catalogue may be missing.

The workflow is the one this project already has, unchanged: read the claim,
measure it against a live 26.7.1, add a `Case`, record the golden, run the suite.
Nothing new is imported, nothing Java is built, no dependency is added, and the
result lands in `internal/conformance` where every other measured value lives.

Most mined cases will pass on the first run. That is the expected outcome and it
is not a wasted task: an already-correct behaviour with a golden under it is a
behaviour the next refactor cannot break silently. The ones that fail are the
finds.

The first pass already has one. `RealmRolesSearchTest.testPaginationRoles` calls
`roles().list(first, max)` and asserts page sizes; `internal/admin/roles.go`
reads only `search` and `briefRepresentation` from the query, so `first` and
`max` are accepted and ignored. That is a real gap on an operation the roadmap
counts as served, and no case in the catalogue would have caught it.

Track A has its own plan: `docs/superpowers/plans/2026-08-25-keycloak-testsuite-mining.md`.

### 5.2 Track B: run the suite in remote mode, after P4

Once P4 gives Gloak realm creation and deletion, the largest bucket in section 4
opens and the suite becomes runnable in principle. What Track B then builds:

1. A pinned checkout of the upstream sources at the target tag, the same one
   Track A uses.
2. A `temp-admin` bootstrap client, configurable so the framework's defaults
   work without patching upstream. This is small and it is measurable: the
   reference container can be started with the same two options and the resulting
   client read back.
3. A curated allowlist of test classes, not a whole-suite run. The 184
   custom-config classes hang rather than fail, so an allowlist is a correctness
   requirement, not tidiness.
4. A `make` target behind the `docker` build tag, next to `oracle`, because it
   needs Docker, Java and Maven and `go test ./...` must never need any of them.

The value is not the pass count. It is that these tests ask for shapes no golden
asks for, in the same way `kcadm.sh` did.

### 5.3 Track C: the OpenID Foundation conformance suite, after P3

`tests/conformance/.../OpenIdConformanceSuite.java` runs
`registry.gitlab.com/openid/conformance-suite` and its nginx and MongoDB
sidecars in Testcontainers, and drives them over the suite's own API. The suite
itself is language-agnostic and black-box: it does not care that the server under
test is not Java, and it does not need the Maven reactor.

It needs the authorization code flow, which is P3, so it cannot report anything
useful before then. It is the closest thing to an independent certification of
the protocol surface, and it is the one track whose result would mean something
to somebody outside this repository.

## 6. What Track B costs once P4 lands

Worth writing down now, because the cost is what decides whether Track B is worth
starting at all, and it is easy to underestimate from the outside.

- The suite builds against the Keycloak Maven reactor. `tests/base` depends on
  `keycloak-test-framework-*`, on `tests/utils`, on `tests/utils-shared` and on
  the server's own representation classes. There is no published artifact that
  lets a test class be compiled alone.
- CI would need a JDK and Maven, which the repository has needed for nothing so
  far.
- Upstream's tests are written against upstream's defaults. A test asserting on
  a realm's default client scopes is asserting on P5.
- The suite pins `localhost:8080`, `8443` and `9000`. `RemoteKeycloakServer`
  hard-codes them; they are not configurable.

None of this is a reason not to do it. It is a reason to do it as an allowlist
that grows, and never as a whole-suite run whose red is permanent and therefore
ignored.

## 7. Licensing

Keycloak is Apache-2.0. Reading its tests to learn what to measure raises
nothing. Copying test source into this repository means carrying the Apache-2.0
header and the attribution with it.

Gloak has no `LICENSE` file at its root today. That should be settled before any
upstream source is copied in, not after. Track A does not copy any: it copies
scenarios, and cites the file it read them from in `Case.Doc`.

## 8. What this document does not decide

Whether Track B happens at all. It records what it would cost and what it depends
on, so that the decision can be made when P4 is done and the cost is real rather
than estimated.

It also does not decide the fate of the eight runnable classes in section 4.
Three of them are relevant, and running three test classes through the whole
Maven reactor is a bad trade today. If Track B is built for other reasons, they
come along for free.
