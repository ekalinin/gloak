# F142: a second realm in the conformance harness

## 0. The count, and the route it argues for

F142 says every conformance case is recorded and replayed against `master`, so
no golden can tell a realm-derived value from the literal. **The premise is
false, and the count is what says so.** Counted from the catalogue and the
committed goldens on 2026-09-01, not estimated:

| counted | number |
|---|---|
| cases in the catalogue | 592 |
| cases whose request path names a realm other than `master` | 66 |
| of those, `Implemented` | 65 |
| goldens whose **response** (headers + body, not the request line) carries the realm name the case addressed | 60 |
| of those 60, addressed at `master` | 58 |
| of those 60, addressed at a realm the case's own fixture created | **2** |

The two are `admin/organizations/create`, whose `Location` is built from
`rc.realm.Name`, and `admin/realms-admin/read`, whose body's `realm` and
`defaultRole.name` are. Both would fail today if a handler hard-coded `master`.

Behind the 60 goldens sit **20 distinct request-time derivation sites** - places
in served code where the realm name of the request becomes a response byte.
Counted from the list rather than incremented:

| # | site | what it produces | asserted against |
|---|---|---|---|
| 1 | `admin/clients.go:154` | `POST /clients` `Location` | master only |
| 2 | `admin/users.go:278` | `POST /users` `Location` | master only |
| 3 | `admin/groups.go:386` | `POST /groups` `Location` | master only |
| 4 | `admin/groups.go:409` | `POST /groups/{id}/children` `Location` | master only |
| 5 | `admin/roles.go:254` | `POST /roles` `Location` | master only |
| 6 | `admin/roles.go:482` | `POST /clients/{u}/roles` `Location` | master only |
| 7 | `admin/identityproviders.go:437` | `POST .../instances` `Location` | master only |
| 8 | `admin/organizations.go:360` | `POST /organizations` `Location` | **a created realm** |
| 9 | `admin/realms.go:449`,`:456` | `GET /admin/realms/{r}` body | **a created realm** |
| 10 | `admin/representation.go:123` | a client's `access` block, via `isAdminContainerName` | master only |
| 11 | `oidc/discovery.go:165` | every URL in the discovery document | master only |
| 12 | `oidc/router.go:351`,`:354` | `GET /realms/{r}` body | master only |
| 13 | `httpx/theme.go:141` (`ThemeChrome.Realm`) | the restart URL on every theme page | master only |
| 14 | `oidc/deviceverify.go:74` | the device page's form `action` | master only |
| 15 | `oidc/device.go:167` | `verification_uri`, `verification_uri_complete` | master only |
| 16 | `oidc/introspect.go:54` | the introspection body's `iss` | master only |
| 17 | `oidc/registration.go:863` | `Location` and `registration_client_uri` | master only |
| 18 | `httpx/errors.go:696` | `WWW-Authenticate: Bearer realm="..."` | master only |
| 19 | `oidc/authorize.go:608` | the `iss` in `/auth`'s error redirect | master only |
| 20 | `admin/clientscopes.go:205`, `admin/protocolmappers.go:264` | `Location`, built from `r.URL.Path` | **cannot be hard-coded** |

**Eighteen of twenty are asserted against `master` alone. Exactly one of the
eighteen is pinned by a package test**: site 13, by
`internal/httpx`'s `TestThemeErrorPageCarriesTheChrome`, which F142's own cut
added when it filed the finding.

A further set of derivation sites is asserted by **no** golden at all -
`realmCookiePath` (every `Set-Cookie` in the flow is masked whole),
`realmIssuer` inside the tokens (opaque), the login form's `action`, the
required-action and consent redirects, `roles.go:454`'s `<realm>-realm` refusal,
`adminRealmOf`, `AssignDefaults` and the rename cascade. They are outside this
cut and are named in the handover.

**Eighteen is not four, so this is not a checklist.** It is also not the
machinery F142 costed, because:

> **the machinery already exists.** `realmFixture(name)` in `fixture.go` creates
> a realm through `POST /admin/realms` and 66 cases already address it; the
> pollution guard's `createdKeys` already carries `"realm"`;
> `admin/realms-admin/list` is already `PristineRealm` so a new realm on the
> shared container cannot pollute it; and `ReplaceIssuer` deliberately rewrites
> the base URL and **not** the realm segment, which is what leaves the realm name
> asserted in the golden.

F142 costed neither route because it read the harness as master-only. It is not,
and has not been since P4's first cut. What is missing is not machinery and not a
checklist: it is **cases**, plus the one piece of machinery that keeps adding
them from lying about parity.

### Why F53 went the other way and this does not contradict it

F53 decided `PristineRealm` "stays a declaration and the sweep that checks it is
a person reading the catalogue", after a derived check was tried and declined on
two measurements: request shape cannot decide whether a body is realm-wide, and
replaying every case against a shared realm produces 22 failures that are not
order-dependence.

`Case.SecondRealm` is a declaration for the same reason and by the same
argument - it cannot be derived from the path, because
`oidc/discovery/unknown-realm` addresses `nosuchrealm` and *is* a distinct
behaviour that belongs in the denominator, while a second-realm re-measurement is
not and does not. Deriving the flag from "the path does not say master" would
silently drop that case from parity.

**Where it differs from F53 is that this declaration is falsifiable.** A
`PristineRealm` claim has nothing behind it but a reader. A `SecondRealm` claim
carries two consequences a test can check, and both are checked here:

- the realm it addresses must be one the case's **own fixture** creates, which
  `createdObjects()` already knows;
- its golden's response must carry that realm name and must **not** carry
  `master`, which is the whole reason the case exists.

So this follows F53's decision - declare, do not derive - and pays the cost F53
could not: a declaration that changes nothing is worse than none, and this one
fails when it is wrong.

## 1. What is built

### 1.1 `Case.SecondRealm`

One bool. It marks a case that re-measures a behaviour another case already
covers, against a realm other than `master`, to pin the values the handler
derives from the realm name.

Its one effect on the meter: **`TestCoverage` leaves it out of the tally.** The
protocol chapters' denominator is the catalogue's own case count, so a
second-realm sibling would otherwise add one to both the numerator and the
denominator and make Gloak read as serving one more behaviour than it does. That
is exactly the failure `Chapter`'s doc comment names - a denominator of "cases
somebody bothered to write down" measures diligence rather than coverage. Parity
is **352 of 535 before and after**.

### 1.2 The `second-realm` fixture

`realmFixture("gloak-probe-second")`, unchanged from the function four other
fixtures already call. The name carries `probePrefix`, so
`TestEveryCreatedObjectCarriesTheProbePrefix` needs no exception.

### 1.3 Four cases, appended to `oidcCore` in `catalog_oidc.go`

`adminCases` is another stream's this round and is not touched.

| case | status | site it pins | measured |
|---|---|---|---|
| `oidc/discovery/second-realm` | `Implemented` | 11 | the created realm's document is byte-identical to master's with the name swapped, **except `scopes_supported`' order**, which the master case already declares `Unordered` |
| `realm/info/second-realm` | `Implemented` | 12 | `realm`, `token-service` and `account-service` follow the name; `public_key` is the realm's own key and is masked, as on the master case |
| `oidc/userinfo/second-realm` | `Implemented` | 18 | `WWW-Authenticate: Bearer realm="gloak-probe-second"` |
| `oidc/authorization/second-realm-error-page` | `Recorded` | 13 | see below |

All four measured on 2026-09-01 against a live Keycloak 26.7.1, container
`kc-realm2` on port 8155, and served against Gloak's own handler for comparison.

### 1.4 The fourth case is `Recorded`, and that is the finding

The 400 error page on a created realm differs from master's in **three** places,
not one. Two of them are not the restart URL:

```
--- keycloak (realm gloak-probe-second)          +++ gloak
-    <title>Sign in to gloak-probe-second</title>
+    <title>Sign in to Keycloak</title>
-              class="pf-v5-c-brand">gloak-probe-second</div>
+              class="pf-v5-c-brand"><div class="kc-logo-text"><span>Keycloak</span></div></div>
```

`internal/httpx/theme.go` serves master's `displayName` and `displayNameHtml` as
constants. On master they are right; on any other realm they are not, and a realm
created through `POST /admin/realms` has neither, so Keycloak falls back to the
realm **name** in both places. The `<div class="kc-logo-text">` wrapper is
`displayNameHtml`'s and disappears with it.

So the case is `Recorded`: measured, contract in the repository, not served. It
is not a per-request page - the only moving value in it is the
`/resources/<version>/` segment, which `ReplaceThemeResource` handles - so the
rule that a page carrying a per-request value cannot be `Recorded` does not bite.
Gloak's answer differs, which is what `Recorded` requires.

**This is the argument for the case route over the package-test route in one
diff.** A package test asserts what its author believed; this golden asserts what
Keycloak did, and it found two divergences nobody had looked for. `internal/httpx`
is not this cut's to change, so the fix is named in the handover.

### 1.5 Two guards

- `TestSecondRealmCasesAddressARealmTheyCreate` - a `SecondRealm` case's path
  must name a realm other than `master`, and one its own fixture creates.
  Reuses `createdObjects()`.
- `TestSecondRealmGoldenPinsItsRealmName` - a `SecondRealm` case's golden must
  carry the realm name in its **response** and must not carry `master`
  anywhere in it. This is the guard that makes the flag do F142's job: a
  second-realm case whose golden pins nothing realm-derived is a mask that
  changes nothing, and it fails here.

Both guards assert their own set is non-empty, the way
`TestPristineRealmGoldensAreNotPolluted` and
`TestEveryCreatedObjectCarriesTheProbePrefix` do, so deleting the last
second-realm case fails rather than going quiet.

### 1.6 One stale comment corrected

`unservedEndpointPhrases`' doc comment in `catalog_test.go` says the probe paths
are spelled for master "because that is what every case in the catalogue
addresses". That has been false since P4. The paths stay as they are - the probe
only needs one routed path - and the reason is corrected to the true one.

## 2. What is deliberately not built

- **No `Case.Realm` field and no path templating.** A case's `Request.Path` is
  literal by design and 66 cases already spell a created realm into it. A
  `{{realm}}` expansion would buy nothing and would put a second spelling of the
  same thing in the catalogue.
- **No second `Fixture.State`.** `realmFixture`'s own doc comment already argues
  this: a state that seeded a realm behind the API's back would seed it
  differently from the way a caller does.
- **No case for the other fifteen blind sites.** Each costs a measurement, and
  three of them (the device pages, the registration URI, the introspection `iss`)
  need a fixture that builds a client inside the second realm. They are named in
  the handover with the site each would pin, so the next cut adds cases rather
  than re-deriving the list.
- **No package tests.** Where a claim belongs in `internal/oidc`'s or
  `internal/httpx`'s own tests, this cut says so in the handover and does not
  write it; those packages are not this cut's.

## 3. Order of work

1. Commit the branch point. (Done before anything else - `git checkout` has
   destroyed uncommitted work here seven times.)
2. `Case.SecondRealm`, the coverage exclusion, the two guards, the fixture, the
   four cases with `Status: Recorded` and no goldens yet.
3. `make record`. Read the diff: it must add exactly four goldens and move none.
4. Promote the three that match to `Implemented`; leave the theme page
   `Recorded` with its `Reason`.
5. `CGO_ENABLED=0 go test ./...`, `make lint`, `make conformance` - the last must
   still read 352 of 535.
6. Mutations, one per claim, each reverted.
7. Handover.

## 4. The mutations this cut owes

| claim | mutation | test that must fail |
|---|---|---|
| the discovery document's realm is derived | `discoveryDoc` builds `realmBase` from `"master"` | `TestConformance/oidc/discovery/second-realm` |
| the realm info body's realm is derived | `realmInfo` uses `"master"` for `realmBase` and `Realm` | `TestConformance/realm/info/second-realm` |
| the bearer challenge's realm is derived | `WriteBearerChallenge` writes `realm="master"` | `TestConformance/oidc/userinfo/second-realm` |
| a `SecondRealm` case must address a created realm | point one at `/realms/master/...` | `TestSecondRealmCasesAddressARealmTheyCreate` |
| a `SecondRealm` golden must pin its realm name | rewrite the guard's own probe body to hold `master` | `TestSecondRealmGoldenPinsItsRealmName` |
| `SecondRealm` keeps the meter honest | drop the exclusion from `TestCoverage`'s tally | `TestSecondRealmCasesAreOutsideTheParityDenominator` |

The first is F142's own headline mutation, aimed at a second site rather than
the theme page's: hard-code `master` where a realm name belongs, and something
must now fail. If nothing does, this cut has not closed F142.
