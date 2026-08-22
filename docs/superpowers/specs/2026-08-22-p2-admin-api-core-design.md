# P2: Admin API core

Date: 2026-08-22
Status: accepted
Roadmap: `2026-08-21-gloak-parity-roadmap.md`
Depends on: P1, `2026-08-21-p1-token-foundation-design.md` (implemented)

## 1. What this is

The first cut of the Admin REST API: the authorization model every admin
operation sits on, plus the `clients` and `users` resource groups.

The roadmap allocates P2 seven OpenAPI tags totalling 151 operations. This spec
covers **69 of them** - `clients` 35 and `users` 34. `roles` 28, `roles-by-id`
10, `groups` 11, `role-mapper` 18 and `client-role-mappings` 15 remain inside
P2's boundary and get a second spec.

The split is not arbitrary. `clients` and `users` are the two groups that
unblock other work: a confidential client with a known secret is what six P1
cases have been waiting for, and a second user is what several P3 and P8 cases
will need. The five remaining groups unblock nothing outside P2.

## 2. P2 does not start at the endpoints

Nothing in the store maps a user to a role. `internal/bootstrap` creates five
realm roles and assigns none of them, and it creates no client roles at all.

That matters more than it sounds, because P1 measured where admin authorisation
has to come from. An `admin-cli` access token carries `azp, exp, iat, iss, jti,
scope, sid, typ` and nothing else - no `sub`, no `realm_access`. There is
nothing in the token to authorise against. Section 4.1 of the P1 design drew the
conclusion and P2 is where it lands:

```
Authorization: Bearer <token>
  -> token.ParseAccess          verifies signature, issuer, expiry, typ
  -> parsed.SessionID           the sid claim
  -> SessionRepo.UserSessionByID
  -> the user behind the session
  -> that user's role mappings
  -> the role this operation requires
```

Every step exists today except the last two. Building them is the first half of
P2 and it produces no HTTP surface at all.

## 3. Authorization is fine-grained from the start

Each operation requires its own role, not a blanket `admin` check.

**The roles live on the `master-realm` client.** Measured: it carries 21 roles -
`manage-users`, `manage-realm`, `view-clients`, `query-groups` and so on. See
"Bootstrap of the master realm" in
`2026-08-18-keycloak-26.7.1-observed.md`. `realm-management` is the equivalent
client inside non-master realms, which is P4's problem, not P2's.

The exact 21 names, and which one each of the 69 operations demands, are
**measured, not read off the OpenAPI description**. The description says an
operation exists; it does not say who may call it. The measurement is a
recording per operation against a caller holding a deliberately narrow role set.

The coarse alternative - "any caller with the `admin` realm role passes" - was
rejected. Authorisation is observable behaviour: a caller with `view-users` and
not `manage-users` gets 200 on a read and 403 on a write, and a build that
returns 200 to both differs from Keycloak on every such request. Retrofitting it
later means revisiting every handler.

**The 403 shape is not yet measured.** P1's design flagged this and it is still
open. It is the first thing P2 records, because every authorization test depends
on it, and it must not be written from memory.

## 4. Representations are the risky part

`ClientRepresentation` is 26 fields as returned by the client list endpoint.
`UserRepresentation` is 11 fields for the bootstrapped admin, in this order:

```
access, attributes, createdTimestamp, disableableCredentialTypes,
emailVerified, enabled, id, notBefore, requiredActions, totp, username
```

`totp` and `disableableCredentialTypes` are legacy fields Keycloak still emits.
`access` is a computed permissions block, not stored state. Reproducing them is
not optional: a client parsing JSON will not notice a missing field, and a
golden will.

**Which fields appear is measured per endpoint, never inferred from the OpenAPI
schema.** The schema lists what *may* appear. The list endpoint, the single-read
endpoint and the create response do not all return the same set, and the
document is silent about the difference. This is the same split the whole
project runs on: the description supplies the list of operations, a running
Keycloak supplies the bytes.

Marshal from structs with fields in the measured order, per AGENTS.md. A
`map[string]any` sorts its keys and silently reorders every response.

## 5. Harness prerequisites

Three, and none is optional.

**The volatile-header half of follow-up F12.** Every 201 carries a `Location`
holding a fresh UUID. Without masking it, every create case churns on each
recording - the disease four goldens already had.

**Capture from a response header.** Recording `GET .../clients/{uuid}` means
creating a client first and reading its UUID out of `Location`. `Fixture.Step`'s
`Capture` reads the body only. It needs a header form, and the captured value
has to be masked out of the recorded response the same way body captures already
are.

**The parity meter counts the wrong thing.** `TestCoverage` computes a chapter's
`served` as the number of `Implemented` cases in it, while the admin chapters'
denominator is the OpenAPI operation count. Three cases for one endpoint - a
success, a 404 and a 403 - would report "3 of 34 served" when one operation of
34 is implemented. The meter would overcount, and it would overcount most where
the error handling is most careful.

P2 is the first chapter with an OpenAPI denominator, so this is exactly what the
roadmap predicted: "P2 exercises the OpenAPI-derived meter on 151 operations
with an objective denominator. If the meter's design is wrong, that is where to
find out."

The fix: `Case` gains `Operation string`, naming the OpenAPI `operationId`. A
chapter's `served` becomes the count of **distinct operations** with at least
one `Implemented` case. Two tests guard it - every admin case names an
`operationId` that exists in the vendored description, and every case in a
chapter with an OpenAPI tag names one at all.

Protocol chapters keep counting cases: they have no operation list, which is
what `source: catalogue` in the report already says.

## 6. What P2 closes outside its own chapters

Creating a confidential client with a known secret is what five cases have been
`Pending` for:

- `oidc/userinfo/get-with-valid-token`, `post-with-valid-token`
- `oidc/introspection/active-access-token`, `active-refresh-token`,
  `inactive-token`

and one more, `oidc/token/client-credentials-grant`, which needs a client with a
service account.

A seventh, `oidc/userinfo/expired-token`, is blocked on something else: its
comment says a bootstrap fixture cannot wait out a 60-second token. P2 probably
unblocks it too, because the access token lifespan is a client attribute and
client update is in scope, but that is a guess about Keycloak's behaviour rather
than a measurement. It is listed here as a candidate, not a deliverable.

Those six are the bodies follow-up **F15** describes as served-but-unmeasured:
userinfo's success body, introspection's active and inactive bodies, and the
`client_credentials` response shape. P2 records them, corrects whatever the code
guessed, and closes F15.

It also settles the `service-account-<clientId>` username convention, which P1
adopted from Keycloak's documentation without measuring it.

This is not a bonus. It is the reason `clients` is in the first cut.

## 7. Test order

The same four layers P1 used, for the same reason: the harness has to be able to
express a contract before the contract can be written down.

**Layer 0, the harness.** The three prerequisites in section 5. No Docker, no
network; verified by its own tests.

**Layer 1, the contract.** `make record` writes goldens at status `Recorded`.
Unlike P1, this happens per slice rather than once: an admin fixture creates
objects and captures their identifiers, so the fixtures grow with the endpoints
and cannot all be written up front.

**Layer 2, inside each task.** Role resolution from `sid`, the composite-role
expansion, both store drivers through `storetest`, and representation field sets
against the measured sets.

**Layer 3, an external oracle.** `kcadm.sh` against the subset that needs
neither a realm nor client scopes - create, read, update and delete a client and
a user - behind the `docker` build tag. The roadmap's caveat stands: `kcadm`
usually starts by creating a realm, which is P4, so it becomes a real oracle
only after P4 and P5. What it can do today is still worth having, because it is
a client nobody here wrote.

## 8. Scope

In:

- role mappings, composite role expansion, the `master-realm` client's roles
- admin authentication and per-operation authorization
- `clients` 35 operations, `users` 34 operations
- the seven P1 cases section 6 names

Out:

- `roles`, `roles-by-id`, `groups`, `role-mapper`, `client-role-mappings` -
  P2's second spec
- everything about a realm other than `master`, which is P4
- client scopes and protocol mappers, which are P5 and which is why the claim
  sets P1 hardcoded stay hardcoded through P2
- the admin console itself, which is P13

## 9. Debt this knowingly takes on

**Token claims stay hardcoded.** P2 adds role mappings, which is the data a
`roles` protocol mapper would read, and it would be tempting to start emitting
`realm_access` from it. That is P5's model, and the roadmap already carries the
debt. P2 must not half-build it.

**Fine-grained admin permissions are not the same as fine-grained
authorization.** Keycloak has a second, optional model where permissions are
expressed as Authorization Services policies on the `realm-management` client.
That is P10. P2 implements the role check only, and says so where somebody would
otherwise reach for the policy engine.

## 10. What this document deliberately does not decide

The five remaining resource groups in P2's boundary. They get their own spec
once the first cut is serving, when the shape of the authorization model and the
representation work is known from having done it rather than predicted.
