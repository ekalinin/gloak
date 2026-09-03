# Gloak: the parity roadmap

Date: 2026-08-21
Status: accepted

## 1. What this is

Two things that only make sense together: a way to measure how much of Keycloak
26.7.1 Gloak actually serves, and the decomposition of the remaining distance into
sub-projects that can each be specified, planned and built on their own.

It is not an implementation plan. Each sub-project gets its own spec and its own
plan when it is reached. This document fixes their boundaries, their order and
their dependencies, so that the next one to start does not have to rediscover them.

The first sub-project, P1, has its spec already:
`2026-08-21-p1-token-foundation-design.md`.

## 2. Where the project stands

**Updated 2026-08-23, after P2's first cut and follow-up F18.** `make
conformance` reports **57 of 485** enumerated behaviours served. P1 built the
token foundation and P2's first cut added 24 Admin REST API operations -
`admin/clients` 10 of 35, `admin/users` 14 of 34 - along with the six protocol
bodies P1 could not reach without a confidential client.

F18 then added the last two, and they came from the other direction: roles are
resolved at issuance, so `aud`, `realm_access` and `resource_access` are what
Keycloak emits, and the two introspection cases that had been sitting
`Recorded` began matching on their own. `oidc/introspection` is 4 of 5, with
the fifth blocked on role assignment through the API.

The denominator moved from 483 to 485 because two cases were added for
behaviours nobody had catalogued: an access token introspected from outside its
audience, and a refresh token whose session has been ended. Neither is a new
operation; both are protocol-chapter cases, which is why that chapter's
denominator is the catalogue rather than the OpenAPI description.

**Updated 2026-08-25, after the roles half of P2's second cut.** `make
conformance` now reports **89 of 485** enumerated behaviours served:
`admin/roles` 24 of 28 and `admin/roles-by-id` 8 of 10, the 32 operations of
`2026-08-23-p2-roles-and-role-mappings-design.md` section 1's `Roles` and
`Roles (by ID)` blocks. The remaining 11 operations of that cut - the user
halves of `Role Mapper` and `Client Role Mappings` - are the second half and
are not built yet.

**Updated 2026-08-27, after the role-mapping half of P2's second cut, which
completes it.** `make conformance` now reports **100 of 485** enumerated
behaviours served: `admin/role-mapper` 6 of 18 and
`admin/client-role-mappings` 5 of 15, the 11 operations that were the second
half. Both tags stop short of their denominator because each tag covers three
locators and only the **user** one is in this cut: the two tags hold 33
operations, 11 on a user, 11 on a group (P2's third cut) and 11 on an
organization (P12).

The cut also closed F28: a caller may hand out a role only if its own rights
already confer it, one predicate over both `available` reads, both write pairs
and `POST .../composites`. F30 through F34 were opened along the way and are in
`2026-08-18-gloak-followups.md`; F32 is the widest and is older than this cut.

The rest of this section is the state before P1, kept because section 3 is the
argument that produced the reporting, and the argument reads oddly without the
number it was arguing about.

Before this document, `make conformance` reported 8 of 68 documented behaviours
served. That number was honest about the OIDC protocol surface and silent about
everything else, because the catalogue only covered the OIDC layer. The Admin
REST API, SAML, the account and admin consoles, themes and the operational
surface were not in it at all.

Measured against the whole target rather than the part that happened to be
catalogued, the served fraction is under two percent. Section 3 is how the
report came to say that instead.

Working today: the discovery document, JWKS, the realm info endpoint and the two
fallback 404s. Everything else in `docs/superpowers/specs/2026-08-18-gloak-design.md`
section 6 and section 7 is unbuilt, and three of the packages that design names -
`internal/token`, `internal/auth`, `internal/admin` - do not exist.

## 3. What a parity number has to survive to be worth printing

A percentage is only as good as its denominator. If the denominator is "cases
somebody bothered to write down", it measures diligence, not coverage: it grows
when someone remembers a gap and shrinks when they forget one. A meter like that
reads best when the catalogue is worst.

So the denominator is taken from outside wherever an outside source exists.

**Keycloak publishes a version-pinned OpenAPI description of its Admin REST API.**
For the pinned target it is
`https://www.keycloak.org/docs-api/26.7.1/rest-api/openapi.json`: 273 paths, 413
operations, 117 schemas, 22 resource groups. That list is not ours, which is
exactly what makes it usable as a denominator.

This is the same split the conformance harness already runs on, applied one level
up. **The documentation supplies the list; a running Keycloak supplies the values.**
The OpenAPI description is documentation. Not one expected byte comes from it -
only the names of operations that exist.

### 3.1 The spec is vendored, not fetched

The description is downloaded once and committed:

```
internal/conformance/testdata/openapi/keycloak-26.7.1.json
```

Tests read the file. Nothing fetches anything, so `go test ./...` keeps its
promise of needing neither Docker nor network.

Retargeting to another Keycloak version means committing that version's file
alongside this one, repointing the constant, and re-recording the goldens against
the new container. The old file stays: it is the record of what parity was being
measured against before.

The cost is that a version bump produces an unreadable diff of two 561 KB JSON
files. That is not a real loss - nobody would read that diff either way. If
comparing two versions' operation lists ever becomes useful, it is a test, written
when it is needed. It is not built now.

### 3.2 What the report says, and what it refuses to say

Coverage is reported per chapter, with the source of each denominator named:

```
chapter                     served  documented  source
oidc/token                       0          17  catalogue
admin/users                      0          34  openapi 26.7.1
admin/realms-admin               0          45  openapi 26.7.1
saml                             0           ?  not enumerated
```

A chapter with no external source carries `Enumerated: false` and a reason. The
total then reads as "8 of 483 enumerated behaviours served; 4 chapters not
enumerated" - a sentence that cannot be mistaken for completeness.

The alternative, quietly leaving unenumerated chapters out of the denominator,
would inflate the percentage by hiding exactly the parts nobody has looked at yet.

### 3.3 The `Recorded` status

`internal/conformance` has two statuses and three states. `Pending` covers both
"not measured, not built" and "measured, not built"; the second is distinguished
only by whether a file happens to exist on disk.

`Recorded` gives the second state a name.

| Status | Golden | Served | Verifier |
|---|---|---|---|
| `Pending` | optional | no | skips |
| `Recorded` | **required** | no | compares, and requires a mismatch |
| `Implemented` | required | yes | compares; a mismatch is a regression |

Two things change for that middle state.

**The golden becomes mandatory.** Under `Pending`, forgetting to record is
indistinguishable from deliberately deferring. Under `Recorded` a missing golden
fails, by the same logic that already fails an `Implemented` case without one.

**The verifier asserts the mismatch.** A `Recorded` case is served and expected
*not* to match. If it does match, the build fails with "promote this to
`Implemented`". Without that, a case that starts passing as a side effect of
neighbouring work stays silently unguarded, and the next refactor breaks a
contract nobody knew was being met.

Being honest about its strength: while a case is `Recorded`, the assertion is
weak. It passes on *any* difference and proves only "not built yet". It is a
status marker with an alarm on it, not a correctness check.

### 3.4 Why this keeps `main` green

AGENTS.md rests on a rule: `make test` has exactly one known failure, and any
other failure is a real regression. That rule is the project's regression
detector. Park forty deliberate failures on `main` and it stops working - nobody
finds the real one among the intentional ones.

So the red phase does not live on `main`. It lives in the task branch:

```
make record        -> goldens written, status Recorded, make test green
start a task       -> flip that task's cases to Implemented
                      make test RED, byte-exact diffs, and that is the brief
write the code     -> failures go out one at a time
commit             -> green again, cases guarded from then on
```

`Recorded` is not the red phase. It is the measured contract parked in the
repository before any code exists to satisfy it.

## 4. The decomposition

Operation counts come from the vendored OpenAPI description. Every one of its 413
operations is allocated below; none is left unassigned.

| # | Sub-project | Depends on | Closes | Size |
|---|---|---|---|---|
| **P1** | Token foundation **(done)** | - | `oidc/token` 8 of 17, `userinfo` 4 of 7, `introspection` 1 of 4, `revocation` 4 of 4; closed `oidc/certs` | 17 cases |
| **P2** | Admin API core **(done 2026-08-28)** | P1 | Users 34, Clients 35, Roles 28, Roles by ID 10, Groups 11, Role Mapper 18, Client Role Mappings 15 | 151 ops |
| P2 first cut | Clients and Users, done 2026-08-23 | | 24 of the 69 in those two tags; the other 45 belong to P5, P6, P7, P9, P10, P13, P14 or the second cut - see §1.1 of the P2 design | 24 ops |
| P2 second cut | Roles and role mappings on a user, specced 2026-08-23, **done 2026-08-27** | P2 first cut | 43 of the 71 in `Roles`, `Roles (by ID)`, `Role Mapper`, `Client Role Mappings`; the other 28 are groups (11), organizations (11) and P10 (6) - see `2026-08-23-p2-roles-and-role-mappings-design.md`. All 43 are served: the roles half 32 (`Roles` 24, `Roles (by ID)` 8) on 2026-08-25, and the role-mapping half 11 (`Role Mapper` 6, `Client Role Mappings` 5) on 2026-08-27 | 43 ops |
| P2 third cut | Groups, specced 2026-08-28 | P2 second cut | `Groups` 9, a user's group membership 4, the group halves of the two mapping tags 11. The allocation was checked against the description and holds exactly: the `Groups` tag has 11 and the two `management/permissions` operations are P10, and 11 of the 22 group role-mappings are under `/organizations` and so P12. **Done 2026-08-28**, all three cuts: the group tree 9, the membership 4 and the group role-mappings 11 | 24 ops |
| **P3** | Browser code flow | P1, **P2** | `oidc/authorization` 11, `oidc/logout` (part) | ~15 cases |
| P3 first cut | The recorder learns to log in, **done 2026-08-29** | P2 | no operations: the fixture machinery, and 11 cases moved from `Pending` to `Recorded` | 0 ops |
| P3 second cut | `/auth`'s two error families, **done 2026-08-29** | P3 first cut | the validation half of `GET`/`POST /auth`: 7 cases served, 4 new. **Not the success path** - the four cases that need a login page stay `Recorded` and P13 closes them | 0 ops |
| **P4** | Multi-realm, specced 2026-08-29, **complete 2026-08-29** | P2 | Realms Admin 45, Key 1. The tag's 45 is a denominator and **16** is what P4 builds: the rest is P5's client scopes, P8's authentication, P12's organizations and P14's events, export and import, and the roadmap already said the last of those. Both cuts done: the realm as a resource 5 ops, then keys, default groups, group-by-path, client policies and client types 11 ops. `Realms Admin` stays at 15 of 45 and that is the finished state | 46 ops |
| **P5** | Client scopes and protocol mappers, **first cut done 2026-08-30** | P2 | Client Scopes 10, Protocol Mappers 21, Scope Mappings 33, Client Attribute Certificate 7, Client Initial Access 3, Client Registration Policy 1. The 75 is a denominator and is badly misleading as work: **23 of it is `client-templates`, a path alias for `client-scopes` measured identical on all three verbs**, and one operation is P9's. Twelve operations P5 *does* build are counted in other tags - the realm's six `default-*-client-scopes` and a client's six `*-client-scopes`. The first cut is those 22, and closes the `Client Scopes` tag outright | 75 ops |
| P5 first cut | Client scopes, the two attachment families, and F49 | P2 | `admin/client-scopes` 0->10, `admin/clients` 10->16, `admin/realms-admin` 15->21. Protocol Mappers and Scope Mappings are cuts B and C | 22 ops |
| P5 third cut | Scope mappings, **done 2026-08-30 - P5 complete** | P5 second cut | `admin/scope-mappings` 0->33, the tag closed outright. The `client-templates` alias is byte-identical on all eleven with **no** exception here, because nothing on this tag mints a `Location` | 33 ops |
| P5 second cut | Protocol mappers, **done 2026-08-30** | P5 first cut | `admin/protocol-mappers` 0->21, the tag closed outright. Seven of its 21 are the `client-templates` alias again, verified byte-identical against the server rather than inferred from the first cut. Scope Mappings is cut C | 21 ops |
| P6 second cut | Back-channel and front-channel logout, **done 2026-08-31** | P6 first cut, P13 | no operations, and none available: back-channel logout is a request **Keycloak** makes and a `Case` holds one request and one response. Fifteen tests instead. `oidc/logout/frontchannel` becomes promotable when P13 lands | 0 ops |
| **P6** | Sessions and logout in full, **first cut done 2026-08-30** | P3 | back-channel, front-channel, session iframe, offline sessions, Attack Detection 3 | 3 ops + cases |
| P6 first cut | The RP-initiated logout endpoint | P3 | `oidc/logout` 0->10, and the chapter's denominator 5->14. The estimate before the cut was **+1**, from counting the five cases already in the catalogue; the endpoint has two verbs, two request families per verb and six response shapes | 0 ops |
| **P7** | Advanced grants, **first cut done 2026-08-30** | P1, P5 | `device` 5, `ciba` 3, `registration` 6, token exchange, JWT bearer, DPoP, PAR | ~20 cases |
| P7 second cut | Dynamic registration and two grants, **done 2026-09-01** | P7 first cut, P5 | `oidc/registration` 0->14 of 14, `oidc/token` 16->19. The initial access token turned out **not** to be needed: an ordinary admin token registers a client, and a fixture built to mint one would have depended on a route Gloak does not serve | 0 ops |
| P7 first cut | The device grant's flow, CIBA's refusals | P5 | `oidc/device` 0->11 of 12, `oidc/ciba` 0->10 of 12. The eight cases the catalogue held all measured the grant **disabled**, which is its state on every client of a default install; the two endpoints have twenty-two distinct answers. CIBA cannot complete on a default container at all, which is a measurement rather than a gap | 0 ops |
| **P8** | Authentication flow engine, **first cut done 2026-08-30** | P3 | Authentication Management 39, required actions, OTP, WebAuthn, brute force | 39 ops |
| P8 second cut | Required actions enforced at login, **done 2026-08-31** | P8 first cut, P13 | no operations. F104 closed, and it named the smaller half: `internal/oidc` read a user's `requiredActions` on **no** endpoint, so the password grant was handing out tokens too. A temporary password is now temporary | 0 ops |
| P8 first cut | The SPI registry and required actions | P3 | `admin/authentication-management` 0->18 of 39. The other 21 - `flows`, `executions`, `config` - are **deliberately deferred**: Gloak walks a hard-coded flow, so they would edit a description nothing reads. Named individually in F103 | 18 ops |
| **P9** | Federation and brokering, **first cut done 2026-09-01** | P4, P8 | Identity Providers 17, Component 6. The first cut built nine - the instances listing, create, read, update, delete, `export` and `reload-keys`, and the component listing and single read. The estimate held to the operation for the first time; what moved was the *content* of three of them. The twelve left need two things this cut did not build: a **per-provider property catalogue** (`providers/{provider_id}`, `mapper-types`, `sub-component-types`, `POST`/`PUT /components`, the five mapper operations) and an outbound HTTP fetch (`import-config`). `DELETE /components/{id}` is deliberately unbuilt - see F145 | 23 ops |
| P9 second cut | The provider catalogue and the mapper family, **done 2026-09-02** | P9 first cut | `admin/identity-providers` 9->16. The catalogue is **three endpoints, three envelopes and one atom**, and it is also the filter `POST /components` applies to a submitted config. Only `import-config` is left in the chapter, and it makes a real outbound fetch. The component writes are unbuilt: one of them, a second `declarative-user-profile`, **breaks every login in the realm** | 7 ops |
| **P10** | Authorization services (UMA 2.0), **first cut done 2026-08-31** | P5 | `authz/resource-server/*` 31, plus **twelve** `management/permissions` operations counted under five other tags - the brief said eight, which was right only for the three chapters that had no other unserved operations | 43 ops |
| P10 second cut | The scope family, **done 2026-08-31** | P10 first cut | `admin/authz-resource-server` 5->13. Eighteen operations remain; the three permanently-`[]` listings were **deliberately excluded** as parity points indistinguishable from stubs | 8 ops |
| P10 third cut | The resource family, **done 2026-09-01** | P10 second cut | `admin/authz-resource-server` 13->22 - the whole resource family, listing and search included. **The "permanently-`[]` listings" were not permanently `[]`**: they were empty because nothing had been created, and `GET /resource` is served by the real store here. Nine remain: policy 4, permission 4, import 1, and they need the **typed per-provider representation** that `GET .../permission` uses and `GET .../policy` does not - not the "provider model before `POST` means anything" F129 claimed, since a policy needs a `type` and nothing else | 9 ops |
| P10 fourth cut | Policy, permission and import, **done 2026-09-02** | P10 third cut | `admin/authz-resource-server` 22->29. **The nine policy types have eight representations over one stored map** - a projection table, not nine structures - which is what F129 meant by "a provider model" and did not say. Two operations remain, the `evaluate` pair, and they need an RPT from `internal/token`: F148 | 7 ops |
| P10 first cut | The resource server and the twelve refusals | P5 | `admin/authz-resource-server` 0->5, and **three chapters closed outright**: `admin/roles` 28/28, `admin/roles-by-id` 10/10, `admin/groups` 11/11. The gate is the **client's** `authorizationServicesEnabled` and it runs **before** authorization - a fourth gate shape in four families | 17 ops |
| **P11** | SAML 2.0 | P4 | descriptors, SSO and SLO bindings | not in OpenAPI |
| **P12** | Organizations and Workflows, **first cut done 2026-08-31** | P4 | Organizations 36, Workflows 9. **The row's 45 is 56**: eleven more operations live under `/organizations/{org-id}/groups/.../role-mappings` and are counted under `Role Mapper` and `Client Role Mappings`, so building this unlocks them. 47 operations live under `/organizations` in all | 56 ops |
| P12 second cut | Members, invitations and linked brokers, **done 2026-09-02** | P12 first cut | `admin/organizations` 6->24. A member **is a user**, addressed by the user id, and `POST .../members` takes it as **raw bytes rather than JSON**. Nineteen routes, five different role conjunctions, and no single role opens any of them. **F120 is unblocked** - the hidden root group's name and path are the organization's own id - leaving the eleven group operations as ordinary work. One operation is left, F153: it overlaps a sibling on one path and `ServeMux` panics | 18 ops |
| P12 first cut | The organization as a resource | P4 | `admin/organizations` 0->6. `ORGANIZATION` is **not** a preview feature: what is off is the realm's `organizationsEnabled`, and the refusal sits **after** the caller's roles - the opposite of `client-types` | 6 ops |
| **P13** | Themes, i18n, account console, admin console, **first cut done 2026-08-30, markup cut done 2026-09-01** | P5 | - . The markup cut served the login theme's error and info pages and took seven parked goldens to contracts (+7). Nine theme pages still serve the placeholder body (F146) and the login-actions family is F109 | not in OpenAPI |
| P13 pages cut | The login-action page and the nine measured, **done 2026-09-02** | P13 markup cut | no operations of its own; `oidc/authorization` 18->23 and the denominator +5. **F109 closed**: twelve call sites answer three sentences and four are not that page. The nine remaining pages are measured and none is served - each carries a `tab_id` minted by its own request, so F146 is blocked on **F38, reopened** | 0 ops |
| P3 third cut | The `authorization_code` grant, **done 2026-08-30** | P13 first cut | `oidc/token` 10->14 and its `recorded` column to **zero**. With P13's cut this is the first time Gloak can complete a browser OAuth flow. The measured contract said "Every rejection" over eight rows and there are twelve | 0 ops |
| P13 second cut | SSO and the consent pages, **done 2026-08-30** | P13 first cut, P7 first cut | no operations: F65, F77 and F101 close, so a browser that has signed in once gets a code without a form and a user can finish a device login. `oidc/authorization` 12->14, `oidc/device` 11->13 | 0 ops |
| P13 first cut | The browser login, end to end | P3, P5 | no operations, and the column that matters is `oidc/authorization`'s `recorded` going **4 -> 0**: the chapter no longer holds a case waiting on an endpoint nobody built. The flow is served - authentication session, login form, `/login-actions/authenticate`, authorization code - and the theme's markup is not | 0 ops |
| **P14** | Operational parity | P4 | events and audit, SMTP, health and metrics, clustering | not in OpenAPI |

Denominator today: **413 Admin API operations plus 122 protocol behaviours, 535
enumerated**, plus four chapters (P11, P13, and parts of P6 and P14) whose
surface is not counted and which the report says so about. Served: **400 of 541**
after the organization member family, and **P2, P4 and P5 are complete** - as are
the `Roles`,
`Roles (by ID)` and `Groups` chapters, which P10 closed by measuring what their
last operations refuse - up from 8 before P1, 25 after it, 89 after the second cut's
roles half, 100 after that cut was complete, 109 after the group tree and 113
after the membership.

The denominator moved from 485 for the first time since it was set, and then
again: 489 after P3's second cut named four `oidc/authorization` behaviours no
earlier recording had, 498 after P6's cut took `oidc/logout` from 5 to 14. The
protocol chapters have no OpenAPI source and are counted case by case, so they
**grow as measurements find behaviours nobody had named**. The Admin API
chapters cannot move this way, and none has.

That is worth stating as a rule rather than as an observation, because it has
now caused two under-estimates in two days. **A chapter's case count is not the
size of its endpoint.** P6's cut was scoped at +1 from the five cases sitting in
the catalogue; the endpoint turned out to have two verbs, two request families
per verb and six response shapes, and it delivered +10. And P5's row said 75
operations where the work was 22, because 23 of the 75 are one path alias and
twelve of the operations P5 builds are filed under other tags. Both numbers were
checked against the vendored description before the cuts started, and both were
still wrong in the direction of the catalogue rather than the server.

124 is the number this table predicted for P2 before any of it was built: 100
plus the third cut's 24. The allocation was checked against the description
rather than taken on trust when the cut started, and it held to the operation.

**Updated 2026-09-02 (thirteenth fold).** `make conformance` reports **400 of
541**. `admin/organizations` went 6 of 36 to 24 of 36 in one cut, the largest
single move since P2, and F38 was built after being closed for four days.

**The round's lesson is that a probe built by a convenience library is a probe
whose headers nobody has read.** F149 said this API answers 415 to a write
carrying no `Content-Type`, measured across four chapters. It is false: Python's
`urllib` adds `application/x-www-form-urlencoded` to any POST carrying data, so
the probe measured the 415 of a header **it set itself**. The wrong rule reached
a handler and a test before anything caught it, and what caught it was
`make record` - the recorder builds its requests by hand, so the golden disagreed
with the code. Third time recording has refuted a hand probe.

The rule that follows is narrow and cheap: **before writing down an absence - a
missing header, an omitted parameter, an empty body - dump the bytes that
actually left.** An absence is the one thing a convenience layer fills in for
you.

**Two counts this project wrote were wrong in opposite directions.** F38 was
reopened on the strength of eleven cases wanting its mechanism; there are two,
because F146 confused where a value comes from with what a fixture can hold. And
the organization member family was briefed at eight operations where the
description enumerates ten. The first inflated a justification, the second
undersized a cut, and neither number came from counting the list it named.

**Earlier on 2026-09-02 (twelfth fold).** `make conformance` reports **380 of 540**.
The denominator moved for the first time in a week: five `oidc/authorization`
cases were added for behaviours nobody had catalogued, which is how a protocol
chapter grows. F109 closed, `admin/identity-providers` reached 16 of 17.

**The round's lesson is that a count in prose beside the list it counts will rot,
and this project proved it on its own file.** AGENTS.md's header bullet said
"fifteen committed goldens" while the tree held sixteen - and the sixteenth had
arrived in the **same fold that wrote the sentence**. The conclusion survived and
the evidence it cites did not.

That count is now a test.
`TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb` walks the goldens,
prints the split and asserts the **claim** rather than the number, so a cut that
adds another such golden needs no documentation edit and a cut that makes one
verb consistent breaks the build. It is the first time this project has answered
a recurring documentation defect with code rather than with a more careful
sentence.

**Two follow-ups turned out to be about something other than what they said.**
F109 asked for twelve unpinned judgements; the twelve call sites answer **three**
sentences and four of them are not that page at all. F146 said the instruction
and the chrome had to be measured; they were readable in an afternoon, and the
real blocker is that **all nine pages carry a `tab_id` minted by their own
request**, so none can carry a golden. F146 is now blocked on F38, which is
**reopened**: the mechanism it declined for one case is wanted by eleven.

**Earlier on 2026-09-02 (eleventh fold).** `make conformance` reports **368 of
535**. P10's fourth cut took `admin/authz-resource-server` to **29 of 31** - the
last two need an RPT and are F148 - and F142's protocol half closed the theme
chrome and four other derivation sites, leaving **no measured survivor**.

**The round's lesson is that a rule with one data point behind it should be
written as one data point.** Two of this project's own rules were generalised
from a single example and both were refuted within a day.

I wrote that a created realm "falls back to the realm **name** in both" the
title and the brand. That is what a realm carrying **neither** display field
answers, and it was the only realm measured. Twelve realms say the brand's chain
is one rung longer - `displayNameHtml`, then `displayName`, then the name - and
the realm that separates the two readings is one carrying a `displayName` and no
`displayNameHtml`.

And the security-header bullet, wrong for a **fifth** time. Its lead was "a
`POST`'s 409 keeps the five and a `PUT`'s drops them", written from two data
points and labelled as two data points, which did not save it: fifteen committed
goldens split on both verbs. "The endpoint decides" does not survive either -
`add-models-duplicate-id-same-container` and `-other-container` are the same
route, the same verb and the same 67 bytes, and disagree. The header set follows
whatever produced the response and nothing observable distinguishes them. The
bullet now removes a claim without adding one, which is the first correction in
that sequence to do so.

**Earlier on 2026-09-01 (tenth fold).** `make conformance` reports **361 of 535**.
P10's third cut built the whole resource family (+9, `admin/authz-resource-server`
13->22) and the harness cut closed part of F142 without moving the meter, which
is what a harness cut should do.

**The round's lesson is that a wrong number is cheaper than a wrong
explanation.** Two of this project's own records were the thing that misled the
cuts written from them.

F129 - written by this project, three cuts ago - said the resource family took
eight query parameters (it is eleven), that policy and permission "need a
provider model before `POST` means anything" (they need a `type`), and that three
listings were "permanently `[]`" (none is; they were empty because nothing had
been created). The brief I wrote from it repeated the second and third verbatim
and told the cut to take them seriously rather than re-derive them. It measured
anyway, which is the only reason they are corrected here.

F142 was worse, because it was mine and it was about the harness rather than the
server: "every case in `internal/conformance` is recorded and replayed against
`master`" **has been false since P4**. Sixty-six cases address a realm their own
fixture created, and `realmFixture` has existed since then. The entry costed
"a second realm in the harness" as the expensive route while that route sat in
`fixture.go`. Counting took one command; nobody had run it, because the entry
said what the answer was.

**And the header bullet was wrong for the fourth time, twice refuted by the very
golden it cited.** It now says the split is **not explained** and files the probe
that would settle it (F147). Preferring "not explained" to a fifth explanation is
the correction that should have been made three explanations ago.

**Earlier on 2026-09-01 (ninth fold).** `make conformance` reports **352 of 535**.
P13 served the login theme's markup (+7: `oidc/authorization` 15->18,
`oidc/device` 13->15, `oidc/logout` 10->12) and P9's first cut built identity
provider instances and the component listing (+9:
`admin/identity-providers` 2->9, `admin/component` 0->6 in the two operations it
serves). **Seven of the eight parked goldens are contracts now**, and
`oidc/authorization/prompt-create` is the only one left.

The round's lesson is that **a claim nothing depends on is a claim nothing
falsifies.** The login theme's `/resources/<version>/` segment was described as
"regenerated per container start" in five places - this document's neighbours,
F23, a doc comment, four `parkedGoldens` entries and four catalogue `Reason`
strings. It is minted with the **database**: six `docker restart` gave one
value, eight fresh databases gave eight. Nobody had restarted a container,
because nothing in the harness turns on it - `make record` starts a fresh
container every run - so the sentence was copied five times without ever being
in a position to fail.

Two things followed from measuring it. Seven of the eight parked pages carry
**only** that segment, so one substitution pass made them comparable; the
judgement that had kept them parked was made from the diff of `prompt-create`,
the single page that carries more, and generalised to the rest. And `client_data`
in that page is **not** volatile either, so even the one example had been read
wrong.

**A survivor is a finding, and the finding is not always about the test.** P9's
mutation pass left three survivors and read two of them as awkward mutations of
one function. Review deleted the block outright - three lines - and both packages
stayed green. The block was a no-op whose comment claimed to carry the rule it
did not carry, and it **masked** the tail anchor that did, which is why the
mutation that should have guarded all of this looked harmless. The inference to
keep: **if every mutation of a block preserves behaviour, the block preserves
behaviour.**

**Earlier on 2026-09-01 (eighth fold).** `make conformance` reported **336 of 535**,
and `oidc/registration` is closed outright, 14 of 14.

The round's lesson is about this project's own documents. **Six counted claims
were re-counted and five were wrong** - the security-header exceptions, the
generic-404 producers, the `Location` tails, the strict decoders, the `jti`
prefixes, and a parked-golden total that said *nine, seven and eight in one
paragraph* because each cut that moved it edited a different sentence.

One of the five was refuted by **this repository's own committed goldens**, for
the third time in a week: a cut measured a 409 sending no security headers and
wrote the rule over "a 409", and a golden carrying all five on exactly that
status had been committed since P5. The rule is about the **empty body**.

The habit that follows is cheap: **before writing a rule about headers or
shapes, grep the goldens for a case that would break it.** The evidence is
already here and reading it costs less than measuring.

**Earlier on 2026-08-31 (seventh fold).** `make conformance` reported **311 of 526**,
and three chapters are closed outright - `admin/roles` 28/28,
`admin/roles-by-id` 10/10, `admin/groups` 11/11 - by measuring what their last
operations *refuse* rather than by building anything.

**Four families, four gate shapes, and no two share an implementation.**
`client-types` refuses before authorization with a 501; organizations refuse
after it with a 404 on a *realm* flag; authorization services refuse before it
with a 404 on a *client* flag; required actions are not a gate at all. Each was
measured only because the cut was told not to assume which shape it was, and
each would have been got wrong by reusing the last. That is worth stating as a
rule: **this API's gates are not a family, and the description's tag does not
predict them.**

A wrong explanation was killed **before** it shipped for the first time rather
than after - the `PUT .../authz/resource-server` rule was first read as "a body
with no name is a 409" and the distinguishing probe arrived by accident, from a
role sweep that happened to use it. The pattern this project has twice recorded
as its most expensive was caught by luck, which is not a method.

**Earlier on 2026-08-31 (sixth fold).** `make conformance` reported **294 of 526**,
and **a temporary password is now actually temporary** - `internal/oidc` had
read a user's `requiredActions` on no endpoint at all, so the password grant was
handing out tokens as well as the browser flow.

Two things about the round are worth more than the number.

**Two follow-up entries named the smaller half of their own subject**, and both
understatements propagated into a briefing before a measurement caught them. One
described an admin field as unconsumed when the divergence was on the token
endpoint; the other gave a count whose base the package's own tests already
contradicted.

**A wrong explanation attached to a correct observation is the most expensive
thing these documents carry.** The observed spec explained an incomplete-profile
refusal by an attribute that exempts nothing; a cut implemented the exemption
from that paragraph, broke two fixtures, and reverted it after measuring. The
observation had been right all along, which is what kept the explanation looking
checked - and without the fabrication the same code locks the administrator out
on first start.

The gate also lied twice, and both are fixed: CI was being killed inside `fsync`
rather than being slow (F114), and four goldens promoted to `Recorded` walked
back through the door F69's fix leaves open (F113).

**Earlier on 2026-08-30 (fifth fold).** `make conformance` reported **285 of 523**,
and the **browser flow is complete**: a browser that has signed in once gets a
code without a form, and a user can finish a device login through the
verification and consent pages.

The round's most useful result is not a feature. **116 of the catalogue's 293
masks were doing nothing**, found by asking a question nobody had asked - which
of these change no byte? Forty sat on arrays of one element or none; sixty-six
masked a value `ReplaceCaptured` had already rewritten; three contradicted a
measurement the case beside them asserts. Every one read as "this varies", which
is a claim about Keycloak the next reader believes. The proof they were inert is
arithmetic: removing all fifty inert ones moved **zero** goldens.

Two documents were wrong in ways the repository itself had already contradicted.
`AGENTS.md` said the `;charset=UTF-8` split was "only on this one endpoint" -
438 committed goldens had said otherwise since P2, and so had a doc comment in
`internal/admin`. **The code knew and the contract document did not**, which is
the failure this project is least able to catch in itself.

And one deferral is worth recording as a decision rather than a gap. P8's other
21 operations are the flow model, and Gloak walks a **hard-coded** flow, so
building them would let a caller edit a description the server does not read.
That is the roadmap's own §6 debt shape, and twice now "we store it and serve it
back" has read as "we implement it" to the next person. F103 names all twenty-one.

**Earlier on 2026-08-30 (fourth fold).** `make conformance` reported **263 of 516**.
The denominator grew by sixteen because the device and CIBA endpoints turned out
to have twenty-two distinct answers where the catalogue held eight - and the
eight it held all measured the grant **disabled**, which is its state on every
client of a default install. A chapter's cases can describe the wrong half of an
endpoint, not only too few of them.

Three findings from the round, none of which any single cut could have produced:

- **A defect filed as one was six**, for the second time in a week. F49 and F84
  are the same shape: a field the admin API ignores is rarely alone, because
  whatever review missed it missed its neighbours.
- **F78's already-corrected entry was wrong a fourth way.** It had been rewritten
  once by the cut that found it wrong. The next cut found the correction half
  right.
- **Nothing in the gate checked `gofmt`**, so three files reached `main`
  unformatted and were found by somebody reading a diff. `vet` is a correctness
  tool and says nothing about layout; there was no step that could have caught
  it, and now there is one in both the Makefile and the workflow.

**Earlier on 2026-08-30 (third fold).** `make conformance` reported **242 of 500**,
**P5 is complete**, and **Gloak can complete a browser OAuth flow for the first
time**: `GET /auth`, the login form, the code, the exchange.

Two entries in the follow-up list were **wrong when the cut arrived to close
them**. F80 named a `HashMap` model that fits 13 of 14 measured vectors, and the
fourteenth proves one table cannot be right. F78 was wrong three ways at once.
Both had been written by cuts that measured carefully and generalised one step
past their evidence, which is a different failure from not measuring - and it is
caught by the next person measuring the same thing rather than by any test.

The sharpest finding of the three days is about tests. F80's fourteen vectors
**do not pin the rounding rule** the model rests on: the mutation that breaks it
passes all fourteen and fails only the boundary probes somebody added by asking
what the vectors did *not* pin. A passing suite never prompts that question.

**Earlier on 2026-08-30 (second fold).** `make conformance`
reported **205 of 499**, and `oidc/authorization`'s `recorded` column reached
**zero**: no case in that chapter is waiting on an endpoint nobody built.

The three were the browser login, the protocol mappers and the recorder's own
debt, and the integration produced the sharpest finding of the week. **Two cuts
were green on their own and failed together**: the pollution guard reads "one
object per creation body", and a `POST /clients` carrying `protocolMappers`
creates a client *and* two mappers. The nested mappers were never recorded,
which lost them from the guard and made it report a false positive against the
very case whose own fixture had made them. Neither author could have seen it -
each was correct against the tree they had. It is F71.

A second integration finding: the login cut's most surprising measurement -
`PUT .../protocol-mappers/models/{id}` writes the mapper the **body's** id
names, not the path's - was implemented, documented at the call site, and tested
by nothing, because every other case sends a body whose id agrees with its path.
A mutation swapping the two left the whole suite green. **The case where they
disagree is the only place the difference is observable**, and it now exists.

Both of these argue for the same thing: the fold is not clerical work, and it is
the only place where the combination is examined at all.

**Earlier on 2026-08-30, after three parallel cuts.** `make conformance`
reported **179 of 498**. Three streams - P5's first cut, P6's first cut and a
harness sweep - ran the same way as the four the day before, and the collision
analysis had to be redone because it came out differently: P5, P8 and P12 all
live in `internal/admin`, so **only one admin stream can run at a time**. The
three that ran were one admin, one protocol and one harness, and the two that
shared `catalog_admin.go` were separated by having one append at the end of the
slice and the other edit existing cases in place.

**The most valuable output of each stream was a line in `AGENTS.md` its
measurements refuted, and there were four in one day.** Two of them - "logout
without an `id_token_hint` does not redirect" and "`post.logout.redirect.uris`
is a separate client attribute" - had been folded in the day before, from the
day before that's measurements. One had a conformance case filed `Pending` on
the strength of it, with the wrong reason attached. The lesson is not that the
documents drift; it is that **a measurement taken to answer one question is
evidence about that question and not about its neighbours**, and the first of
those two was taken through a cookie jar that turned out to be the variable.

**Earlier, after four parallel cuts.** `make conformance` reported
**147 of 489**. Four streams ran concurrently in separate worktrees against
separate reference containers - P3's second cut, P4's second cut, the harness
debt (F38, F39, F40) and the CI residuals - and the two that moved the meter
moved it by seven and eleven. The other two moved nothing on purpose: one fixed
how the two sides of the comparison are obtained, the other fixed the workflow
that reports the number.

They collided nowhere in code. P3 lived in `internal/oidc`, P4 in
`internal/admin` and `internal/store`, the harness in `internal/conformance`'s
machinery, CI in `.github` and `internal/parity`. The only shared surface was
this document and four others like it, which is why all five were taken out of
the agents' scope and folded in afterwards in one pass. That is the practice
worth repeating: **parallelism is cheap when the collision surface is prose, and
prose is the one thing that can be written once at the end.**

One finding was handed over that had already been fixed - P4 reported
`admin/role-mapper/group-realm-available` as lacking `PristineRealm`, and the
harness stream had added the flag in a commit P4's own branch had merged. It was
dropped at the fold rather than filed, which is the second reason the
consolidation is not the agents' job.

**Earlier, after P3's first cut.** `make conformance` still reported
**124 of 485**, and that was the intended result rather than a stalled one. The
cut built the fixture machinery this document ordered P2 first to avoid
building twice - a cookie jar shared by both sides of the harness, an HTML form
parser, a query capture out of a redirect - and used it to move eleven cases
from `Pending` to `Recorded`. `Recorded` is measured and not served, and the
meter counts served, so the number cannot move until the endpoint exists.

Section 5's argument was vindicated more directly than expected. The cut's
first measurement found that `security-admin-console`, which every
`oidc/authorization` case named, cannot serve nine of them: it pins
`pkce.code.challenge.method` to `S256` and registers a host-relative redirect
pattern. Four of those cases already carried a comment blaming the recorder's
run-time port, which was half the reason and the half that a client the fixture
registers now fixes. **P3's recordings need P2's client management** was written
here before anyone reached the work, and it turned out to be the load-bearing
dependency rather than a caveat.

Three of the cases in that group changed status on the measurement rather than
on any code: `oidc/logout/rp-initiated-without-id-token-hint` asserted a
`Location` that does not exist, since a logout without an `id_token_hint`
serves a confirmation page. P3's share of `oidc/logout` is one case, not two.
The design is `2026-08-29-p3-browser-code-flow-design.md`, which supersedes the
2026-08-22 one and says line by line which of its claims survived.

Four pull requests between 100 and 109 moved the number not at all, and that is
worth naming rather than reading as a gap: they closed F17, F30, F32, F33, F36
and F37, which are divergences on surface already counted as served. The counter
measures reach, not correctness, and a cut that finds a privilege escalation
scores zero on it. Section 2 records how the denominator moved from 483 to 485
and where each step of the numerator came from.

P1 did not close its four chapters outright, and the remainder is worth naming
rather than leaving as a subtraction. Nine `oidc/token` cases need the
authorization code (P3), the device flow or CIBA (P7), or a client the Admin
API has to create (P2 and P5). Three `oidc/userinfo` and three
`oidc/introspection` cases need a confidential client with a known secret,
which is P2. None of them is blocked on token issuance any more.

The 31 operations OpenAPI leaves untagged are all
`/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/*`. They are
Authorization Services, and they are P10.

Each operation is counted once, under the sub-project that builds the resource,
which is not always the sub-project that cares about it. **The Size column is
therefore a denominator, not an estimate of work.** Section 1.1 of
`2026-08-22-p2-admin-api-core-design.md` works the split out per operation for
the two largest tags and finds that 45 of 69 are built elsewhere; expect the
same ratio wherever a resource has many sub-paths. Realm export and import
and the events configuration are Realms Admin operations and so are counted in
P4, while the behaviour behind them belongs to P14. P14 therefore has no
operations of its own: its surface is the management port, SMTP and clustering,
none of which the Admin API describes.

## 5. Why this order

The ordering principle is not "layer after layer" but "scenario after scenario":
each sub-project ends with something that can be demonstrated, and unblocks the
next.

P1 is forced. Persisted realm keys, a session model and token issuance sit under
both the Admin API and the browser flow, and nothing observable can be built
before them.

**P2 and P3 were deliberately swapped.** The browser flow is section 3 of the
design's own success criterion, so it was the obvious second. The argument that
moved it to third is the test harness, not the product:

- P3's fixtures are the hardest machinery in the harness. Recording an
  authorization-code exchange means opening `/auth`, parsing the login form's
  HTML for `session_code`, `execution` and `tab_id`, posting credentials,
  intercepting a redirect and extracting `code` from `Location`. That is a small
  browser living inside the recorder, and it needs both halves of follow-up F12.
- P2's fixtures are a straight extension of what P1 already needs: obtain a token,
  put it in a header, make the request. No HTML.
- P2 needs only one half of F12, the volatile-header mask for the `Location`
  header every 201 carries.
- P2 exercises the OpenAPI-derived meter on 151 operations with an objective
  denominator. If the meter's design is wrong, that is where to find out.

Building the hardest part of the harness immediately after P1, before the chaining
mechanism has been shaken out on the simple case, is how it gets built twice.

One caveat, so the tooling argument is not overstated: `kcadm.sh` and the Terraform
provider will only **partly** work after P2, which P2 confirmed: `make oracle`
drives Gloak with `kcadm.sh` today and it works for clients and users, having
found a missing `ClientRepresentation.description` on its first run. `kcadm`
usually starts by creating a
realm, which is P4, and the Terraform provider leans on client scopes, which is
P5. They become real external oracles after P2, P4 and P5, not immediately.

## 6. Debt this roadmap knowingly takes on

**Token claims are staged.** In Keycloak the claim set of a token is produced by
protocol mappers attached to client scopes. That is P5. P1 therefore reproduces
the measured claim set of `admin-cli` directly rather than deriving it from a
mapper model. This is staging, not an oversight, but it has to be written into P5
explicitly, or P5 will discover that "just add mappers" means rewriting token
issuance.

**`scopes_supported` is already a constant.** `internal/oidc/discovery.go` emits a
list that no model backs. After P5 it must be derived from the realm's client
scopes. Filed here because it is the same debt, already shipped.

## 7. What this document deliberately does not decide

Anything past P1. P2 through P14 have a boundary, a dependency and a count, and
nothing else. Specifying P9 today means writing a document that expires before
anyone reaches it, and the accuracy it appears to have would be invented rather
than measured.
