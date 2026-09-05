# F103: the authentication flow model

Date: 2026-09-03
Status: accepted
Reference container: `kc-flows`, `quay.io/keycloak/keycloak:26.7.1 start-dev`, port 8169

## 0. The inherited list, re-counted

F103 says the twenty-one are named individually in
`docs/superpowers/plans/2026-08-30-p8-authentication.md` §1, so this cut inherits
a list rather than a tag. A handover's list has been wrong twice, so it was
checked against `internal/conformance/testdata/openapi/keycloak-26.7.1.json`
operation by operation rather than re-counted from the prose.

It holds. The tag carries 39 operations; 18 are served; the unserved set is
exactly these, and the three family counts F103 quotes are exact:

| Family | Operation |
|---|---|
| flows | `GET /flows` |
| flows | `POST /flows` |
| flows | `POST /flows/{flowAlias}/copy` |
| flows | `GET /flows/{flowAlias}/executions` |
| flows | `PUT /flows/{flowAlias}/executions` |
| flows | `POST /flows/{flowAlias}/executions/execution` |
| flows | `POST /flows/{flowAlias}/executions/flow` |
| flows | `GET /flows/{id}` |
| flows | `PUT /flows/{id}` |
| flows | `DELETE /flows/{id}` |
| executions | `POST /executions` |
| executions | `GET /executions/{executionId}` |
| executions | `DELETE /executions/{executionId}` |
| executions | `POST /executions/{executionId}/config` |
| executions | `GET /executions/{executionId}/config/{id}` |
| executions | `POST /executions/{executionId}/raise-priority` |
| executions | `POST /executions/{executionId}/lower-priority` |
| config | `POST /config` |
| config | `GET /config/{id}` |
| config | `PUT /config/{id}` |
| config | `DELETE /config/{id}` |

The table above is the list. No count is written beside it; `TestF103ListIsTheTag`
computes both sides from the description and the catalogue and asserts they are
the same set, which is the only place a number like this can live without
drifting.

The only correction to P8 §1.1's spelling is cosmetic: it writes
`/executions/{id}` where the description writes `/executions/{executionId}`.
Same operations.

## 1. Which of the three shapes, and why the other two are worse *here*

**This cut takes shape 3.** The stored flow model is seeded and served, *and*
`internal/oidc`'s browser login reads it for the two decisions it actually
makes. The parts that are read are named in the handlers; the parts that are
not are named there too.

The argument is not "a middle is usually safest". It is three specific facts
about this repository.

### 1.1 Shape 1 is worse here than in general, because the dangling half already exists

`internal/admin/realmrep.go:152-158` already serves seven flow-binding names on
every realm representation - `browserFlow`, `registrationFlow`, `directGrantFlow`,
`resetCredentialsFlow`, `clientAuthenticationFlow`, `dockerAuthenticationFlow`,
`firstBrokerLoginFlow` - with defaults at `realmrep.go:359-365`. They round-trip
through the `Settings` blob and **are read by nothing**. That is already the
F103 shape, shipped, in a chapter that is marked served.

Serving twenty-one operations over a flow model that nothing reads would not
add one instance of "state nothing consumes". It would complete a second one:
a reader would find `browserFlow: "browser"` on the realm, find a flow called
`browser` with fifteen executions behind it, and have every reason to believe
one names the other. Today the name points at nothing and that is at least
visible. After shape 1 the name would point at an object, and the object would
still not be walked.

### 1.2 Shape 2 asserts a dispatch that cannot happen, which is a louder untruth than F103's

The measured seed (§2) is 55 execution rows naming **25 distinct authenticator
provider ids**, nested six levels deep, under four requirement values. Gloak
implements two of the twenty-five for real: `auth-cookie` (as
`resolveBrowserSession`, `internal/oidc/sso.go:98`) and
`auth-username-password-form` (as `verifyLoginCredentials`,
`internal/oidc/loginactions.go:359`). `identity-provider-redirector`, every OTP
and WebAuthn form, the whole `registration` and `reset credentials` and
`first broker login` and `docker auth` trees, and `conditional-credential` are
absent from `internal/oidc` entirely.

An engine that walks the tree and dispatches into a registry where twenty-three
of twenty-five entries answer "not implemented" is not the honest alternative to
F103. It is a **stronger** claim than the one F103 objects to: "we store it and
serve it back" becomes "we execute it", on a table where the execution is a
stub. This project's own record is that the first reading is what the next
person takes away.

There is a second, repository-specific cost. `internal/oidc`'s ordering is
measured, not designed: `p13-login.md` §1.4 pins the rejection order at
`/login-actions/authenticate` as client_data, cookies, client_id, session_code,
execution, credentials, and `authorize.go:13-94` records a ten-step order pinned
by twenty-nine paired requests. Re-deriving those orders from a flow tree means
re-deriving twenty-seven browser goldens from data instead of preserving the
straight line that was measured. That is the largest re-recording risk this
project could take, and it would be taken to make a stub tree walkable.

### 1.3 Shape 3 has an unusually cheap entry price here, because the pivot is already in the tree and already named as a stand-in

`internal/oidc/authsession.go:612` computes the login form's `execution`
parameter as a SHA-256 of a literal prefix and the realm id. Its own doc comment
says why: *"Gloak has no authentication-flow model, so it derives a stable
per-realm UUID from the realm's id ... without inventing a table."*

**Keycloak's value is the id of the `auth-username-password-form` execution
inside the realm's bound browser flow.** Measured directly (§3.1): on realm
`f103b` the login page emitted `execution=6024bf28-...` and that realm's browser
flow lists `6024bf28-... auth-username-password-form REQUIRED`; on a second
realm both values moved together to `9f4cf29c-...`. Two realms, two values, the
same identity - the control differs, so the probe is not measuring itself.

So the constant this project already flagged as a fabrication becomes a read of
the seeded model. And it is **golden-neutral**: the value is captured and
rewritten to `{{execution}}` by `fixture.go:2804`, and exactly one golden
mentions it.

That is the whole argument for shape 3 being available at all. Without that
pivot the middle would be a design; with it, it is the removal of a stand-in.

### 1.4 What "read rather than hard-coded" means concretely - three bindings

Each is a claim about behaviour, each was measured against 26.7.1 before being
planned, and each gets its own mutation.

| # | Binding | Today | After |
|---|---|---|---|
| B1 | which flow the login walks | nothing reads `browserFlow` | the realm's `browserFlow` alias resolves a stored top-level flow; an unresolvable alias falls back to the alias `browser` |
| B2 | the `execution` parameter | `sha256("gloak-execution:" + realm.ID)` | the id of the `auth-username-password-form` execution in that flow |
| B3 | whether SSO is attempted | always | only when that flow's `auth-cookie` execution is not `DISABLED` |

B3 measured on the reference (§3.2): with `auth-cookie` `ALTERNATIVE` a live
session answered 302 with a code; set to `DISABLED` the same request answered
200 with the login page; restored to `ALTERNATIVE` it answered 302 again. Three
states, and the revert reverted.

### 1.5 What shape 3 explicitly does not claim

Written here so the handler comments and the PR body say the same thing:

- The other **six** flow bindings on the realm representation stay unread. Only
  `browserFlow` gains a consumer.
- Of the browser flow's fifteen execution rows, **two** are read: `auth-cookie`
  (B3) and `auth-username-password-form` (B2). The other thirteen are stored,
  served and not read.
- `requirement` is read as a two-valued thing on one row - `DISABLED` or not.
  Keycloak's `REQUIRED`/`ALTERNATIVE`/`CONDITIONAL` semantics over a tree are
  **not** implemented, and nothing in this cut pretends they are.
- The `registration`, `reset credentials`, `first broker login`, `docker auth`
  and `clients` flows are seeded and served and walked by nothing.

That list is the boundary. It goes in `internal/admin/flows.go`'s package
comment, not only in a handover, because F103's complaint is precisely that a
handover is not where a reader meets the code.

## 2. The seed: what the built-in flows actually are on a fresh realm

Everything in this section was read off `kc-flows` on 2026-09-03. It is the
largest measurement in the cut and everything else rests on it.

### 2.1 The shape of the seed

Walked rather than assumed: `GET /flows` returns **top-level flows only**, so
sub-flows were reached by following every `flowId` in each flow's execution
listing until the set closed.

| | master | a realm created through `POST /admin/realms` |
|---|---|---|
| flows, top-level | 7 | 7 |
| flows, sub | 10 | 13 |
| execution rows | 48 | 55 |
| authenticator configs | 4 | 4 |

### 2.2 The two realm variants differ in exactly three flows and two rows

P8 §1.2's item 6 said a created realm has two executions master does not.
Re-measured here and made exact by diffing the two seeds field by field:

- Three **flows** exist only in a created realm: `Organization`,
  `Browser - Conditional Organization`, `First Broker Login - Conditional
  Organization`.
- Two **execution rows** exist only in a created realm: `Organization` at
  priority 26 in `browser`, and `First Broker Login - Conditional Organization`
  at priority 60 in `first broker login`.
- Everything else - every other flow's alias, description, providerId, topLevel,
  builtIn and full execution list, and all four configs - is byte-identical
  between the two.

So the seed is one table with a not-in-master flag on three flows and two rows,
which is `components.go`'s `MasterOnly` pattern inverted. The client-scope
precedent ("identical in every realm") does not hold, and this is the second
chapter where it does not.

### 2.3 The seven top-level flows

| alias | providerId | description |
|---|---|---|
| `browser` | `basic-flow` | Browser based authentication |
| `direct grant` | `basic-flow` | OpenID Connect Resource Owner Grant |
| `registration` | `basic-flow` | Registration flow |
| `reset credentials` | `basic-flow` | Reset credentials for a user if they forgot their password or something |
| `clients` | `client-flow` | Base authentication for clients |
| `first broker login` | `basic-flow` | Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account |
| `docker auth` | `basic-flow` | Used by Docker clients to authenticate against the IDP |

`GET /flows` returns them in that order, which is insertion order, not sorted.
All seven are `topLevel: true, builtIn: true`.

### 2.4 The thirteen sub-flows

`Organization`, `Browser - Conditional Organization`, `forms`,
`Browser - Conditional 2FA`, `Direct Grant - Conditional OTP`,
`User creation or linking`, `Handle Existing Account`,
`Account verification options`, `Verify Existing Account by Re-authentication`,
`First broker login - Conditional 2FA`,
`First Broker Login - Conditional Organization`, `registration form`,
`Reset - Conditional OTP`.

All are `topLevel: false, builtIn: true` and `providerId: basic-flow` **except
`registration form`, which is `form-flow`**. That single exception is why a
`providerId` column cannot be defaulted.

### 2.5 The four authenticator configs

Identical on master and on a created realm:

```
browser-conditional-credential              {"credentials":"webauthn-passwordless"}
create unique user config                   {"require.password.update.after.registration":"false"}
first-broker-login-conditional-credential   {"credentials":"webauthn-passwordless"}
review profile config                       {"update.profile.on.first.login":"missing"}
```

Two of the four aliases are hyphenated and two contain spaces, which is a fact
about the seed and not a normalisation to apply.

### 2.6 The two serialisations of an execution, and their key orders

A flow's **nested** `authenticationExecutions` and the **flat**
`/flows/{alias}/executions` listing are different objects. Both are seeded from
the same rows and neither is derivable from the other by sorting.

Nested (`GET /flows/{id}`), field order with absent keys omitted:

```
authenticatorConfig, authenticator, authenticatorFlow, requirement,
priority, autheticatorFlow, flowAlias, userSetupAllowed
```

Flat (`GET /flows/{alias}/executions`), five distinct key orders observed on a
fresh realm:

```
38x  id, requirement, displayName, requirementChoices, configurable, providerId, level, index, priority
11x  id, requirement, displayName, description, requirementChoices, configurable, authenticationFlow, flowId, level, index, priority
 4x  id, requirement, displayName, alias, requirementChoices, configurable, providerId, authenticationConfig, level, index, priority
 1x  id, requirement, displayName, requirementChoices, configurable, authenticationFlow, flowId, level, index, priority
 1x  id, requirement, displayName, description, requirementChoices, configurable, authenticationFlow, providerId, flowId, level, index, priority
```

This is a fixed field order with nulls omitted, **not** a Java map - `javamap`
is not in play. The relative order of `flowId` and `authenticationConfig` is
**unmeasured**, because no seeded row carries both; a sixth shape appears on a
sub-flow created without an alias, which omits `displayName`. Both facts are
recorded rather than resolved.

`level` is the nesting depth and `index` is the position among siblings; the
listing is a depth-first pre-order walk, which is why `first broker login`'s
`First Broker Login - Conditional Organization` at `level 0, index 2` appears
*after* rows at `level 5`.

### 2.7 `autheticatorFlow`

Every nested execution carries **both** `authenticatorFlow` and
`autheticatorFlow` - the second missing its `n` - always with the same value.
It is Keycloak's own misspelled accessor, serialised beside the correct one.
It is contract, not a defect to tidy.

## 3. The bindings, measured

### 3.1 B2 - the `execution` parameter is a real execution id

On realm `f103b` the browser flow's fifteen rows include
`6024bf28-54d3-426e-a5b5-ed862b5d9c93 auth-username-password-form REQUIRED`,
and `GET /auth` rendered `execution=6024bf28-54d3-426e-a5b5-ed862b5d9c93`.

Control: on realm `f103b2` both values are `9f4cf29c-83d0-473a-b05a-f2b2d5259809`.
Two realms, two values, one identity.

### 3.2 B3 - `auth-cookie`'s requirement decides the SSO short-circuit

One cookie jar holding a live `KEYCLOAK_IDENTITY`, one unchanged `GET /auth`:

| `auth-cookie` requirement | answer |
|---|---|
| `ALTERNATIVE` (seeded) | 302 to the client with a code |
| `DISABLED` | 200, the login page |
| `ALTERNATIVE` (restored) | 302 to the client with a code |

### 3.3 What is *not* claimed from these two

`auth-spnego` is seeded `DISABLED` and Gloak has no Kerberos, so its requirement
is stored and unread. `identity-provider-redirector` is seeded `ALTERNATIVE` and
Gloak has no identity-provider redirect in the login path at all, so its
requirement is stored and unread. Neither is given a binding, and §1.5 says so.

## 4. The measured contract for the twenty-one

All read off `kc-flows` on 2026-09-03, in created realms.

### 4.1 Statuses, headers and bodies

| Operation | Status | Notes |
|---|---|---|
| `GET /flows` | 200 | `application/json;charset=UTF-8`, `Cache-Control: no-cache`; **top-level only** |
| `GET /flows/{id}` | 200 | nested representation; `Cache-Control: no-cache` |
| `POST /flows` | 201 | empty body, `Location` ends in a server-minted UUID, `no-cache` |
| `PUT /flows/{id}` | 204 | `no-cache` |
| `DELETE /flows/{id}` | 204 | `no-cache` |
| `POST /flows/{alias}/copy` | 201 | empty body, `Location` **echoes the creating path**: `.../flows/{alias}/copy/{new id}` |
| `GET /flows/{alias}/executions` | 200 | flat depth-first listing |
| `PUT /flows/{alias}/executions` | 204 | `no-cache` |
| `POST /flows/{alias}/executions/execution` | 201 | `Location` under `.../authentication/executions/{id}` - a **different** family from the creating route |
| `POST /flows/{alias}/executions/flow` | 201 | `Location` under `.../authentication/flows/{id}` - likewise |
| `GET /executions/{id}` | 200 | the *nested* shape plus `id` and `parentFlow` |
| `DELETE /executions/{id}` | 204 | |
| `POST /executions/{id}/raise-priority` | 204 | **swaps** priorities with the neighbour |
| `POST /executions/{id}/lower-priority` | 204 | likewise |
| `POST /executions/{id}/config` | 201 | `Location` **echoes the creating path**: `.../executions/{execId}/config/{cfgId}` |
| `GET /executions/{id}/config/{cfgId}` | 200 | byte-identical to `GET /config/{cfgId}` |
| `POST /config` | 201 | `Location` under `.../authentication/config/{id}`; creates a config attached to no execution |
| `GET /config/{id}` | 200 | `{id, alias, config}` |
| `PUT /config/{id}` | 204 | replaces `alias` and `config` |
| `DELETE /config/{id}` | 204 | |

`GET /executions/{id}` answers the nested execution shape with two extra keys:

```
{"authenticator":"auth-otp-form","authenticatorFlow":false,"requirement":"DISABLED",
 "priority":0,"autheticatorFlow":false,"id":"<id>","parentFlow":"<flow id>"}
```

`id` and `parentFlow` come **last**, after the misspelled key. That is a third
serialisation of one row.

### 4.2 The three Location families on one tag

AGENTS.md's Location bullet counts eleven server-minted uuid tails out of
fifteen routes and records `POST /authentication/flows` among them. This tag
adds **five** more creates and they do not agree with each other:

- `POST /flows` and `POST /flows/{alias}/executions/flow` →
  `.../authentication/flows/{uuid}`
- `POST /flows/{alias}/executions/execution` → `.../authentication/executions/{uuid}`
- `POST /config` → `.../authentication/config/{uuid}`
- `POST /flows/{alias}/copy` → `.../authentication/flows/{alias}/copy/{uuid}`
- `POST /executions/{id}/config` → `.../authentication/executions/{id}/config/{uuid}`

The last two echo their own creating path, which AGENTS.md records as the
organization family's inversion of the realm family's rule. That makes it three
families, not two, and two of them are on this tag. All five tails are
server-minted, so the eleven-of-fifteen split itself is unaffected.

### 4.3 Five new not-found spellings, and a pair separated by capitalisation

AGENTS.md lists twenty-eight spellings of not-found on the admin API. This tag
adds five:

- `Could not find flow with id` - from `GET /flows/{id}` and `PUT /flows/{id}`
- `Flow not found` - from `DELETE /flows/{id}` and `POST /flows/{alias}/copy`
- `flow not found` - from `PUT /flows/{alias}/executions`, **lower case**
- `Illegal execution` - from every `/executions/{id}` route, and from
  `POST /executions/{id}/config`
- `Could not find authenticator config` - from all four config routes

The second and third differ **only in the case of the first letter**. AGENTS.md
already records three pairs separated by a full stop alone; this is the first
separated by capitalisation, and it is the first time one missing resource has
three spellings decided by which route went looking.

### 4.4 The rejections that are not 404s

| Request | Answer |
|---|---|
| `POST /flows` with no alias, or `{}` | **409** `{"errorMessage":"Failed to create flow with empty alias name"}` |
| `POST /flows` with an alias and **no `providerId`** | **409** `{"error":"conflict","error_description":"Duplicate resource error"}` |
| `POST /flows` with a taken alias | 409 `{"errorMessage":"Flow f103-alpha already exists"}` |
| `POST /flows/{alias}/copy` with a taken `newName` | 409 `{"errorMessage":"New flow alias name already exists"}` |
| `PUT /flows/{id}` with no alias | 409 `{"errorMessage":"Failed to update flow with empty alias name"}` |
| `DELETE /flows/{id}` on a built-in flow | **400** `{"error":"Can't delete built in flow"}` |
| `POST /flows/{alias}/executions/execution` with an unknown or absent provider | 400 `{"error":"No authentication provider found for id: <id or null>"}` |
| `POST .../executions/execution` on an unknown flow | **400** `{"error":"Parent flow doesn't exist"}` |
| `POST .../executions/flow` with no `type` | **500** `unknown_error` |
| `PUT /flows/{alias}/executions` with `requirement: "NOPE"` | **500** `unknown_error` |
| any of the four representations with an unknown JSON field | 400 `{"error":"Invalid json representation for <Rep>. Unrecognized field \"zzz\" at line 1 column N."}` |

The second row is the surprise and is reproduced as measured: a **missing**
`providerId` answers `Duplicate resource error`. Three representation names
appear in the strict-decoder message - `AuthenticationFlowRepresentation`,
`AuthenticationExecutionInfoRepresentation`, `AuthenticatorConfigRepresentation` -
and the column number is the byte offset in the submitted body, which is why the
cases pin bodies of a fixed length.

### 4.5 Two creates that make a resource the API cannot name

`POST /flows/{alias}/copy` with **no `newName`** answers **201** and creates a
top-level flow whose representation has **no `alias` key at all**.
`POST /flows/{alias}/executions/flow` with no `alias` does the same for a
sub-flow, whose flat execution row then omits `displayName` and carries
`description: ""`.

Both are reproduced. They are Keycloak's own defects in the family F97, F159 and
`POST /users` with an empty body already belong to, and this cut does not tidy
them. They cost a real probe: an extraction that read `alias` off the listing
crashed on the nameless row, every subsequent `DELETE` and `PUT` was issued
against an empty path segment, and **all five answered the identical
`{"error":"HTTP 404 Not Found"}`**. The control - a `PUT` at a deliberately
unknown id - answered `Could not find flow with id` instead, which is the only
reason the artefact was caught. Every probe in this plan has a control known to
differ, for that reason.

### 4.6 A second `POST /executions/{id}/config` replaces rather than adds

Posting a config to an execution that already has one answers 201, repoints the
execution at the new config, and **deletes the old one** - a subsequent
`DELETE /config/{old id}` answers 404 `Could not find authenticator config`.
So an execution holds at most one config and the route is an upsert wearing a
create's status code.

### 4.7 Three role sets, and `GET /flows` is the wide one

Swept across all 21 roles of the target realm's own `realm-management` client
plus a caller holding none, one role at a time, in realm `f103h`:

| Operations | Opened by |
|---|---|
| `GET /flows` | `view-realm`, `manage-realm`, **`view-clients`**, **`query-clients`** |
| every other read on the twenty-one | `view-realm`, `manage-realm` |
| every write on the twenty-one | `manage-realm` alone |

This confirms P8 §1.3 and narrows it: the wide admission is on `GET /flows`
alone, and `view-clients` is **403** on `GET /flows/{id}` and on
`GET /flows/{alias}/executions` immediately beside it. A role list shared across
the family gets that one wrong.

Ordering: the **role** is checked before the resource. A `view-realm` caller
`PUT`ting an unknown execution gets 403 where `manage-realm` gets 404. That is
the `default-*-client-scopes` order, not `/client-scopes/{id}`'s.

## 5. Design

### 5.1 Migration `0030_authentication_flow.sql`

Three tables, identical bytes in both driver directories.

```sql
CREATE TABLE authentication_flow (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias       TEXT,                       -- nullable: see 4.5
    description TEXT NOT NULL DEFAULT '',
    provider_id TEXT NOT NULL,
    top_level   INTEGER NOT NULL,
    built_in    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL            -- GET /flows order is insertion order
);

CREATE TABLE authentication_config (
    id       TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias    TEXT NOT NULL,
    config   TEXT NOT NULL                  -- ordered JSON, not a Go map
);

CREATE TABLE authentication_execution (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    parent_flow_id TEXT NOT NULL REFERENCES authentication_flow (id) ON DELETE CASCADE,
    authenticator  TEXT,                    -- null on a pure sub-flow row
    flow_id        TEXT,                    -- null on a leaf row
    config_id      TEXT,
    requirement    TEXT NOT NULL,
    priority       INTEGER NOT NULL
);
```

`alias` is nullable because §4.5's two creates produce a row that has none, and
a `NOT NULL` column would refuse a request Keycloak answers 201.
`authentication_execution` carries no `ordinal`: the listing order is `priority`
within a parent, which `raise-priority` swaps.

`config` is stored as the JSON text it arrived as, in key order, for the reason
F95 gives: a Go `map[string]string` marshals sorted. The four seeded configs
each have one key so no order is observable in them yet, but a caller's
`POST /config` can carry several and `model.StringMap` is the existing answer.

### 5.2 Store

One repository, `AuthenticationFlowRepo`, in `internal/store/store.go`, with the
`Store` accessor `AuthenticationFlows()`. Implemented in both drivers, exercised
by `storetest.RunConformance`, which is the only evidence they agree.

### 5.3 Bootstrap

`internal/bootstrap/flows.go` plus an embedded `flows.json` holding the seed of
§2, with a `notInMaster` flag on the three flows and two rows of §2.2.
`ensureAuthenticationFlows` is called from `CreateRealm`, converging like its
siblings and returning early if the realm already has flows, so an operator's
delete is never re-seeded.

Seed ids are minted per realm, not fixed, because §3.1 shows the values are
per-realm and observable.

### 5.4 Admin

`internal/admin/flows.go` holds the twenty-one handlers and, in its package
comment, §1.5's boundary. Routes in `router.go` with two new role slices,
`authFlowReadRoles` and the existing `realmWriteRoles`, plus one wider slice for
`GET /flows` alone.

### 5.5 The wiring in `internal/oidc`

The smallest possible change:

- `authsession.go`'s `executionID(realm.ID)` becomes
  `h.usernamePasswordExecutionID(ctx, realm)`, which resolves B1 then B2 and
  falls back to the existing hash when the realm has no seeded flow - a store
  written by an older migration, and the fallback keeps it serving.
- `sso.go:202`'s `fresh` gains B3's conjunct.

No other file in `internal/oidc` changes.

### 5.6 Conformance

New cases appended at the very end of `catalog_admin.go`, fixtures appended at
the very end of `fixture.go`. `catalog_oidc.go` is **not** touched: B2 is
golden-neutral (§1.3) and B3 changes nothing on a seeded default realm, where
`auth-cookie` is `ALTERNATIVE`.

If any browser golden moves, that is the loudest signal in this repository and
the cut stops and reports rather than re-recording.

## 6. Mutation plan

One mutation per claim, each confirming a **named** test fails, each reverted
and the revert checked.

| Claim | Mutation | Test that must fail |
|---|---|---|
| the seed is 20/55/4 on a created realm | drop the `Organization` flow from `flows.json` | `TestCreatedRealmSeedsTheOrganizationFlows` |
| master's seed omits exactly three flows | clear `notInMaster` | `TestMasterOmitsTheOrganizationFlows` |
| `GET /flows` is top-level only | serve all flows | `TestListFlowsIsTopLevelOnly` |
| B1 | resolve `browser` literally, ignoring `browserFlow` | `TestLoginWalksTheRealmsBoundBrowserFlow` |
| B2 | return the old hash | `TestExecutionParameterIsTheUsernamePasswordExecutionID` |
| B3 | ignore `auth-cookie`'s requirement | `TestDisablingAuthCookieStopsTheSSOShortCircuit` |
| `raise-priority` swaps | decrement instead | `TestRaisePrioritySwapsWithTheNeighbour` |
| `GET /flows`'s wide role set | share the narrow slice | `TestViewClientsReadsTheFlowListingAndNothingElse` |
| the capitalisation pair | spell both `Flow not found` | `TestFlowNotFoundSpellingsDifferByRoute` |
| a second execution config replaces | append instead | `TestSecondExecutionConfigReplacesTheFirst` |

## 7. Parity

Before: 451 of 541. The chapter `admin/authentication` is enumerated against the
`Authentication Management` tag, 18 of 39 served. Twenty-one more operations
take the tag to 39 of 39 and the total to 472 of 541, if all twenty-one land.

**Fewer than twenty-one with a defensible boundary is the better outcome**, and
the boundary is §1.5's, not a budget. Whatever lands, the number is what
`TestCoverage` computes and not what this section predicts.
