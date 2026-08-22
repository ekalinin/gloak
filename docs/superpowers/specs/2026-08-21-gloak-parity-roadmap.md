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
| **P1** | Token foundation | - | `oidc/token` (part), `userinfo` 5, `introspection` 4, `revocation` 4; fixes `oidc/certs` | ~20 cases |
| **P2** | Admin API core | P1 | Users 34, Clients 35, Roles 28, Roles by ID 10, Groups 11, Role Mapper 18, Client Role Mappings 15 | 151 ops |
| **P3** | Browser code flow | P1 | `oidc/authorization` 11, `oidc/logout` (part) | ~15 cases |
| **P4** | Multi-realm | P2 | Realms Admin 45, Key 1 | 46 ops |
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

Denominator today: **413 Admin API operations plus 70 protocol behaviours, 483
enumerated**, plus four chapters (P11, P13, and parts of P6 and P14) whose
surface is not counted and which the report says so about. Served: 8.

The 31 operations OpenAPI leaves untagged are all
`/admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/*`. They are
Authorization Services, and they are P10.

Each operation is counted once, under the sub-project that builds the resource,
which is not always the sub-project that cares about it. Realm export and import
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
provider will only **partly** work after P2. `kcadm` usually starts by creating a
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
