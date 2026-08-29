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
| **P4** | Multi-realm, specced 2026-08-29 | P2 | Realms Admin 45, Key 1. The tag's 45 is a denominator and **16** is what P4 builds: the rest is P5's client scopes, P8's authentication, P12's organizations and P14's events, export and import, and the roadmap already said the last of those. **First cut done 2026-08-29**: the realm as a resource, 5 ops | 46 ops |
| **P5** | Client scopes and protocol mappers | P2 | Client Scopes 10, Protocol Mappers 21, Scope Mappings 33, Client Attribute Certificate 7, Client Initial Access 3, Client Registration Policy 1 | 75 ops |
| **P6** | Sessions and logout in full | P3 | back-channel, front-channel, session iframe, offline sessions, Attack Detection 3 | 3 ops + cases |
| **P7** | Advanced grants | P1, P5 | `device` 5, `ciba` 3, `registration` 6, token exchange, JWT bearer, DPoP, PAR | ~20 cases |
| **P8** | Authentication flow engine | P3 | Authentication Management 39, required actions, OTP, WebAuthn, brute force | 39 ops |
| **P9** | Federation and brokering | P4, P8 | Identity Providers 17, Component 6 | 23 ops |
| **P10** | Authorization services (UMA 2.0) | P5 | `authz/resource-server/*` | 31 ops |
| **P11** | SAML 2.0 | P4 | descriptors, SSO and SLO bindings | not in OpenAPI |
| **P12** | Organizations and Workflows | P4 | Organizations 36, Workflows 9 | 45 ops |
| **P13** | Themes, i18n, account console, admin console | P5 | - | not in OpenAPI |
| **P14** | Operational parity | P4 | events and audit, SMTP, health and metrics, clustering | not in OpenAPI |

Denominator today: **413 Admin API operations plus 72 protocol behaviours, 485
enumerated**, plus four chapters (P11, P13, and parts of P6 and P14) whose
surface is not counted and which the report says so about. Served: **129** after
P4's first cut, and **P2 is complete** - up from 8 before P1, 25 after it, 89 after the second cut's
roles half, 100 after that cut was complete, 109 after the group tree and 113
after the membership.

124 is the number this table predicted for P2 before any of it was built: 100
plus the third cut's 24. The allocation was checked against the description
rather than taken on trust when the cut started, and it held to the operation.

**Updated 2026-08-29, after P3's first cut.** `make conformance` still reports
**124 of 485**, and that is the intended result rather than a stalled one. The
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
