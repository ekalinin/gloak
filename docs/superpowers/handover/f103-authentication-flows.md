# F103: the authentication flow model

Branch `feat/f103-authentication-flows`. The `flows` 10, `executions` 7 and
`config` 4 of the Authentication Management tag - the twenty-one operations F103
deferred - plus the three bindings that make the stored model something
`internal/oidc` reads rather than something it ignores.

The plan is `docs/superpowers/plans/2026-09-03-f103-authentication-flows.md`.
Its §1 is the argument for the shape and §2 is the seed; this file is what came
out of building it.

Everything below was measured on 2026-09-03 against a live Keycloak 26.7.1 -
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8169, container removed at
the end - in realms created for the purpose. Nothing destructive touched
`master`: `PUT /flows/{id}` renames a built-in flow with a 204, and the flow it
would have renamed on `master` is the one the admin console logs in through.

## The shape this cut took, in one paragraph

**Shape three.** The model is seeded and served, and the browser login reads
three things out of it: the realm's `browserFlow` binding, that flow's
`auth-username-password-form` execution id, and that flow's `auth-cookie`
requirement. Everything else in the model is stored, served and not read, and
the list of what that means is in `internal/admin/flows.go`'s file comment
rather than only here - F103's complaint is precisely that a handover is not
where the next reader meets the code.

The argument against the other two shapes is in the plan's §1 and is specific to
this repository rather than general. The short version: shape one was already
half-shipped, because `internal/admin/realmrep.go` has been serving seven flow
binding names read by nothing since P4; and shape two would have had to dispatch
into a registry where twenty-three of twenty-five authenticators are
unimplemented, which is a stronger claim than the one F103 objects to.

## Measurements

### The inherited list survived checking

F103 says the twenty-one are named individually in
`docs/superpowers/plans/2026-08-30-p8-authentication.md` §1. Checked operation by
operation against `internal/conformance/testdata/openapi/keycloak-26.7.1.json`:
the tag carries 39 operations, 18 were served, and the unserved set is exactly
the `flows`/`executions`/`config` families P8 lists. The three counts are exact
and so are the paths. The only difference is a spelling: P8 writes
`/executions/{id}` where the description writes `/executions/{executionId}`.

That is the second inherited count in this project to survive re-counting, and
it is why the rest of F103 was taken at face value.

### The seed

Walked rather than assumed - `GET /flows` serves top-level flows only, so
thirteen of a created realm's twenty are unreachable from it. Sub-flows were
reached by following every `flowId` an execution listing named until the set
closed.

| | master | a realm created through `POST /admin/realms` |
|---|---|---|
| flows, top-level | 7 | 7 |
| flows, sub | 10 | 13 |
| execution rows | 48 | 55 |
| authenticator configs | 4 | 4 |

**The two variants differ in exactly three flows and two execution rows**, and
in nothing else. Diffed field by field rather than eyeballed: every other flow's
alias, description, providerId, topLevel, builtIn and full execution list, and
all four configs, compared byte-identical.

- flows only a created realm has: `Organization`,
  `Browser - Conditional Organization`,
  `First Broker Login - Conditional Organization`
- rows only a created realm has: `Organization` at priority 26 in `browser`,
  `First Broker Login - Conditional Organization` at priority 60 in
  `first broker login`

`internal/bootstrap/flows.json` is that measurement, with a `notInMaster` flag
on the three flows and the two rows. It was generated from the two dumps rather
than transcribed.

The seven top-level flows are `browser`, `direct grant`, `registration`,
`reset credentials`, `clients`, `first broker login`, `docker auth`, in that
order, which is insertion order and not sorted. All are `builtIn`.
`providerId` is `basic-flow` on eighteen of the twenty flows, `client-flow` on
`clients` and **`form-flow` on `registration form`** - three values, so it
cannot be defaulted.

The four configs, identical in both realms:

```
browser-conditional-credential              {"credentials":"webauthn-passwordless"}
create unique user config                   {"require.password.update.after.registration":"false"}
first-broker-login-conditional-credential   {"credentials":"webauthn-passwordless"}
review profile config                       {"update.profile.on.first.login":"missing"}
```

Two of the four aliases are hyphenated and two contain spaces. That is a fact
about the seed, not a normalisation to apply.

### Three serialisations of one execution row, and they disagree about `flowId`

```
nested, inside GET /flows and GET /flows/{id}
  authenticatorConfig, authenticator, authenticatorFlow, requirement,
  priority, autheticatorFlow, flowAlias, userSetupAllowed

flat, GET /flows/{alias}/executions
  id, requirement, displayName, description, alias, requirementChoices,
  configurable, authenticationFlow, providerId, flowId, authenticationConfig,
  level, index, priority

single, GET /executions/{id}
  authenticatorConfig, authenticator, authenticatorFlow, requirement,
  priority, autheticatorFlow, id, flowId, parentFlow
```

The nested shape names a sub-flow by **alias**, the other two by **id**, and
`flowId` sits in a different place in each. One shared serialiser is wrong on
two of the three.

Five key orders were observed on a seeded realm and a sixth on a sub-flow
created without an alias, which omits `displayName`. The flat order above is
their merge. **The relative order of `description` and `alias`, and of `flowId`
and `authenticationConfig`, is unmeasured** - no observed row carries either
pair together. That is recorded rather than resolved, and it is the honest state
of the measurement.

This is a fixed field order with nulls omitted, not a Java map, so `javamap` is
not in play anywhere on this tag.

`level` is depth and `index` is position among siblings; the listing is a
depth-first pre-order walk, which is why `first broker login`'s
`First Broker Login - Conditional Organization` at `level 0, index 2` comes
*after* rows at `level 5`.

### `requirementChoices` is stored per provider, and one row would survive sorting

Measured by adding all fifty-three providers the four registries publish to one
scratch flow and reading the listing back. Four distinct lists cover the
fifty-three:

```
26 providers   REQUIRED, ALTERNATIVE, DISABLED
18             REQUIRED, DISABLED
 8             REQUIRED
 1             REQUIRED, ALTERNATIVE, CONDITIONAL, DISABLED
```

The one is `http-basic-authenticator`, and it carries `CONDITIONAL` **third**,
before `DISABLED`, where every other list ends with `DISABLED`. So it is a
stored list and not a set: sorting the field is wrong on exactly one row out of
fifty-three, which is the kind of tidy-up that survives review by looking like
tidiness. It lives in `internal/admin/requirementchoices.json` rather than on
`authProvider`, because `authProvider` is a serialiser and a new tag on it would
put a key into four registry listings that do not carry one.

**`configurable` needed no data at all.** It is exactly "the provider declares at
least one config property", checked against all fifty-three with **zero**
mismatches, so it is the registry this package already embeds asked a different
question.

### A row's discriminator is the provider, not the flow

The `registration` flow's single row carries **both** `registration-page-form`
and a `flowId` pointing at `registration form`. Its `requirementChoices` are the
**provider's** and its `displayName` and `description` are the **sub-flow's**. A
model that made authenticator and flow exclusive would refuse the seed; one that
took the sub-flow's choices would be wrong on that row.

### The Location header has three shapes on this one tag

```
POST /flows                                   .../authentication/flows/{uuid}
POST /flows/{alias}/executions/flow           .../authentication/flows/{uuid}
POST /flows/{alias}/executions/execution      .../authentication/executions/{uuid}
POST /executions                              .../authentication/executions/{uuid}
POST /config                                  .../authentication/config/{uuid}
POST /flows/{alias}/copy                      .../authentication/flows/{alias}/copy/{uuid}
POST /executions/{id}/config                  .../authentication/executions/{id}/config/{uuid}
```

The last two **echo their own creating path**, which AGENTS.md records as the
organization group family's inversion of the realm family's rule. Two more
families do it, both on this tag, and one of them (`copy`) sits beside three
routes on the same tag that do not. All seven tails are server-minted.

### Five new not-found spellings, and the first pair split by capitalisation

```
Could not find flow with id           GET /flows/{id}, PUT /flows/{id}
Flow not found                        DELETE /flows/{id}, POST /flows/{alias}/copy
flow not found                        PUT /flows/{alias}/executions
Illegal execution                     every /executions/{id} route, and
                                      POST /executions/{id}/config
Could not find authenticator config   all four config routes, and
                                      GET /executions/{id}/config/{id}
```

The second and third differ **only in the case of the first letter**. AGENTS.md
already records three pairs separated by a full stop alone; this is the first
separated by capitalisation. It is also the first time one missing resource has
**three** spellings decided by which route went looking.

### The rejections that are not 404s

| request | answer |
|---|---|
| `POST /flows` with no alias, or `{}` | **409** `{"errorMessage":"Failed to create flow with empty alias name"}` |
| `POST /flows` with an alias and **no `providerId`** | **409** `{"error":"conflict","error_description":"Duplicate resource error"}` |
| `POST /flows` with a taken alias | 409 `{"errorMessage":"Flow <alias> already exists"}` |
| `POST /flows/{alias}/copy` with a taken `newName` | 409 `{"errorMessage":"New flow alias name already exists"}` |
| `PUT /flows/{id}` with no alias | 409 `{"errorMessage":"Failed to update flow with empty alias name"}` |
| `DELETE /flows/{id}` on a built-in flow | **400** `{"error":"Can't delete built in flow"}` |
| `POST .../executions/execution`, unknown or absent provider | 400 `{"error":"No authentication provider found for id: <id or null>"}` |
| `POST .../executions/execution` on an unknown flow | **400** `{"error":"Parent flow doesn't exist"}` |
| `POST .../executions/flow` with no `type` | **500** `unknown_error` |
| `PUT /flows/{alias}/executions` with `requirement: "NOPE"` | **500** `unknown_error` |
| any of them with an unknown JSON field | 400, the strict decoder, naming the class, line and column |

The second row is the one nobody would design: a **missing** `providerId`
answers `Duplicate resource error`. It is reproduced as measured.

Three representation class names appear in the strict decoder's message -
`AuthenticationFlowRepresentation`,
`AuthenticationExecutionInfoRepresentation`,
`AuthenticatorConfigRepresentation` - and the column is a byte offset into the
submitted body, so the case bodies are fixed-length on purpose.

### Two creates make a resource the API cannot name afterwards

`POST /flows/{alias}/copy` with **no `newName`** answers **201** and creates a
top-level flow whose representation has no `alias` key at all.
`POST /flows/{alias}/executions/flow` with no `alias` does the same for a
sub-flow, whose execution row then omits `displayName` and carries
`description: ""`.

Both are reproduced, which is why `authentication_flow.alias` is nullable and
`model.AuthenticationFlow.Alias` is a `*string`. A `NOT NULL` column would
refuse a request Keycloak answers 201.

### `POST /executions/{id}/config` is an upsert wearing a create's status code

A second config posted to an execution that already has one answers 201,
repoints the row and **deletes the first**: a subsequent `DELETE /config/{first}`
is 404. So an execution holds at most one config.

### Three role sets, and the second wide read on this tag

Swept one role at a time across all 21 roles of a created realm's own
`realm-management` client, plus a caller holding none:

| operations | opened by |
|---|---|
| `GET /flows` | `view-realm`, `manage-realm`, **`view-clients`**, **`query-clients`** |
| every other read on the twenty-one | `view-realm`, `manage-realm` |
| every write on the twenty-one | `manage-realm` alone |

This confirms P8 §1.3 and narrows it in a way that matters: the wide admission
is on `GET /flows` **alone**, and `view-clients` is 403 on `GET /flows/{id}` and
`GET /flows/{alias}/executions` one path segment away.

And the two wide reads on this tag do not overlap. `GET /required-actions` takes
the extra **users** pair; `GET /flows` takes the extra **clients** pair; neither
list opens the other's route. A single tag-wide slice gets both wrong.

Ordering: the **role** is checked before the resource. A `view-realm` caller
`PUT`ting an unknown execution gets 403 where `manage-realm` gets 404 - the
`default-*-client-scopes` order, not `/client-scopes/{id}`'s.

### The three bindings, measured before they were built

**B2 - the `execution` parameter is a real execution id.** On realm `f103b` the
login page emitted `execution=6024bf28-...` and that realm's browser flow lists
`6024bf28-... auth-username-password-form REQUIRED`. On a second realm both
values moved together to `9f4cf29c-...`. Two realms, two values, one identity -
so the control differs and the probe is not measuring itself.

This is what the observed document's "`execution` is the same UUID across logins
in one container" was describing without saying what it was.

**B3 - `auth-cookie`'s requirement decides the SSO short-circuit.** One cookie
jar holding a live `KEYCLOAK_IDENTITY`, one unchanged `GET /auth`:

```
auth-cookie ALTERNATIVE (seeded)   302 to the client with a code
auth-cookie DISABLED               200, the login page
auth-cookie ALTERNATIVE (restored) 302 to the client with a code
```

Three states, and the revert reverted.

**B1 - the realm's `browserFlow` selects the flow.** Not measured against the
reference as a separate probe, because it is the composition of B2 with the fact
that `PUT /flows/{id}` renames a built-in flow (204, measured). It is asserted
against Gloak by `TestLoginWalksTheRealmsBoundBrowserFlow`, which binds a second
flow and watches the `execution` parameter follow.

### Two probes that were measuring themselves

**One.** An extraction that read `alias` off `GET /flows` crashed on the
nameless flow the no-`newName` copy had just created, leaving the shell variable
empty. Five subsequent `DELETE` and `PUT` requests went to a path with an empty
segment and **all five answered the identical `{"error":"HTTP 404 Not Found"}`**.
The control - a `PUT` at a deliberately unknown id - answered
`Could not find flow with id` instead, and that difference is the only reason the
artefact was caught. Every probe in this cut has a control known to differ.

**Two.** The first role sweep reported `NO TOKEN` for all 22 callers. The cause
was Keycloak 26's declarative user profile: a user created in a non-master realm
without an email, a firstName and a lastName answers
`{"error":"invalid_grant","error_description":"Account is not fully set up"}` on
the password grant. The session family's handover records the same trap. A sweep
whose every row is identical is a sweep that measured its own setup.

## Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds this cut.

- **`autheticatorFlow` is spelled without its `n` and is not a typo to fix.**
  Every nested execution row in `GET /flows` and `GET /flows/{id}` carries
  **both** `authenticatorFlow` and `autheticatorFlow`, always with the same
  value - Keycloak serialises the row through a correct accessor and a
  misspelled one side by side. It is the second misspelling in this contract
  after `Sesssion not found`'s three `s`s, and like that one, correcting it
  breaks the one thing this project exists to do.

- **A flow's three serialisations disagree about where `flowId` goes, and one of
  them does not carry it at all.** The nested shape names a sub-flow by
  `flowAlias`; the flat execution listing puts `flowId` between `configurable`
  and `level`; `GET /executions/{id}` puts it between `id` and `parentFlow`. One
  row, three orders, and a shared serialiser is wrong on two of them. The flat
  listing also carries `level`, `index`, `displayName`, `requirementChoices` and
  `configurable`, which are properties of the walk and of the SPI rather than of
  the row.

- **`POST /flows` answers a missing `providerId` with `Duplicate resource
  error`.** A body naming an alias and no provider id is a 409 in the RFC shape,
  for a body that duplicates nothing, where the same route's empty-alias refusal
  is the `errorMessage` shape. Two 409s, one route, one verb, two body shapes -
  and **the `Duplicate resource error` one carries none of the five security
  headers where the other carries all five**. That is a fresh instance of the
  split that bullet records as unexplained, on a route family it has not seen,
  and it points the same way: the body decides, not the route and not the verb.

- **One missing flow has three spellings and two of them differ only in
  capitalisation.** `Could not find flow with id` from `GET` and `PUT
  /flows/{id}`, `Flow not found` from `DELETE /flows/{id}` and from
  `POST /flows/{alias}/copy`, and the lower-case **`flow not found`** from
  `PUT /flows/{alias}/executions`. The not-found list already holds three pairs
  separated by a full stop alone; this is the first separated by the case of a
  letter. With `Illegal execution` and `Could not find authenticator config`
  the list gains five.

- **A built-in flow can be renamed and cannot be deleted.** `PUT /flows/{id}`
  answers 204 on `browser` and the listing then serves the new alias; `DELETE`
  answers **400** `{"error":"Can't delete built in flow"}` - not 403, not 409,
  apostrophe included. Only the delete looks at `builtIn`. On a realm whose
  `browserFlow` still names the old alias that rename detaches the login from
  its flow, which is why the destructive half of this cut was done in created
  realms.

- **Two creates make a resource the API cannot name afterwards.**
  `POST /flows/{alias}/copy` with no `newName` is a 201 producing a top-level
  flow whose representation has **no `alias` key**, and
  `POST /flows/{alias}/executions/flow` with no `alias` does the same for a
  sub-flow. Both are reproduced, which is why the `alias` column is nullable. It
  is the family `POST /users` with an empty body and F97's `{"username":123}`
  belong to.

- **`POST /executions/{id}/config` is an upsert.** A second config on an
  execution that already has one answers **201**, repoints the row and deletes
  the first - the first's id then 404s. An execution holds at most one config,
  and a handler that appends leaves a config nothing points at.

- **`requirementChoices` is a stored list per provider, not a sorted set.** Four
  distinct lists cover the fifty-three providers the four registries publish,
  and `http-basic-authenticator` alone carries `CONDITIONAL` - **third**, before
  `DISABLED`, where every other list ends with `DISABLED`. Sorting the field is
  wrong on exactly one row out of fifty-three. `configurable` beside it needs no
  table at all: it is exactly "the provider declares a config property",
  measured with zero mismatches on all fifty-three.

- **The `Location` header has three shapes on this one tag and two of them echo
  their own creating path.** `POST /flows/{alias}/copy` answers
  `.../flows/{alias}/copy/{uuid}` and `POST /executions/{id}/config` answers
  `.../executions/{id}/config/{uuid}`, where `POST /flows`,
  `POST /executions`, `POST /config` and both `.../executions/{execution,flow}`
  creates answer a bare route-plus-uuid - and the two `.../executions/...`
  creates answer under a *different* route family from the one that made them.
  The creates bullet's list of fifteen routes does not include six of these
  seven; all seven tails are server-minted, so the split it counts is unchanged
  and the list is not.

- **`GET /flows` is the tag's second wide read, and it is wide in a different
  direction from the first.** `view-clients` and `query-clients` read it and are
  **403** on `GET /flows/{id}` and `GET /flows/{alias}/executions` one segment
  away; `GET /required-actions` takes the *users* pair instead. Two wide reads
  on one tag, four extra roles, no overlap, and neither is the "200 with a
  shorter list to a weaker caller" pattern - both bodies are byte-identical to a
  `manage-realm` caller's.

## Where my measurements meet AGENTS.md and the observed document

Nothing here **contradicts** either document. Three places are incomplete, and
one is a count that has grown.

1. **AGENTS.md's creates bullet counts fifteen routes.** This tag has seven
   creates and the bullet lists one of them (`POST /authentication/flows`). The
   six it does not list are all server-minted uuid tails, so "eleven out of
   fifteen" becomes "seventeen out of twenty-one" and the *ratio* the bullet is
   about - server-minted against caller-chosen - is untouched. The bullet also
   says the organization family is where the echoing Location lives; there are
   two more, both here.

2. **AGENTS.md's not-found list says twenty-eight.** Five more:
   `Could not find flow with id`, `Flow not found`, `flow not found`,
   `Illegal execution`, `Could not find authenticator config`.

3. **AGENTS.md's `Duplicate resource error` bullet says the split is not
   explained**, and this cut adds a data point rather than an explanation. It is
   consistent with "the body decides" and inconsistent with nothing. The bullet
   should stay as it is; the new instance is worth adding to it because it is
   the first on a route where the *same verb on the same path* produces both
   header sets depending only on which refusal fired.

4. **The observed document, line 7744**, says "a created realm has two
   authentication executions master has not got". That is true and it is half
   the difference: there are also **three flows**. The line names the rows
   because the rows are what P8 could see through the executions listing it had.

5. **The observed document, line 6206**, says "`execution` is the same UUID
   across logins in one container" without saying what the UUID is. It is the
   `auth-username-password-form` execution's row id in the realm's bound browser
   flow, which is why it is stable and why it differs between realms.

## Follow-up dispositions

**F103 - closes.** The twenty-one are served and the model is no longer
described-but-unread. The entry's own prerequisite - "an execution engine in
`internal/oidc`" - is deliberately **not** what was built, and the reason is in
the plan's §1.2: an engine dispatching into a registry where twenty-three of
twenty-five authenticators are unimplemented asserts more than the surface does.
What replaced it is three named bindings and a written boundary. Whether that
satisfies F103 is a judgement, and it is recorded as a judgement:
`internal/admin/flows.go`'s file comment lists what is read and what is not, so
the next reader is not left to infer it.

**What F103 leaves behind, filed rather than closed silently:** six of the seven
flow bindings on the realm representation - `registrationFlow`,
`directGrantFlow`, `resetCredentialsFlow`, `clientAuthenticationFlow`,
`dockerAuthenticationFlow`, `firstBrokerLoginFlow` - still resolve nothing, and
thirteen of the browser flow's fifteen rows are stored and unread. That is a
smaller version of the same debt and it should be filed as its own entry rather
than left inside a closed one.

**F157 - unchanged, and this cut is the argument for it rather than against
it.** F157 says `attack-detection` deliberately has no table because nothing in
Gloak counts a failed authentication, and that "a column nothing writes is a
claim about the model that is not true". This cut is the same rule applied in
the opposite direction: the table exists because something now reads it. The two
entries agree, and F157 stays open until the login path counts failures. Nothing
here counts one.

**F104 - stays closed, and this cut adds to what closed it.** F104 was the
required actions' `enabled` and `defaultAction` being consumed by nothing, and
it closed when the login started reading them. The `execution` parameter was the
other half of the same shape on the same endpoint and it survived that cut,
because `executionID`'s hash *looked* like a value rather than a stand-in. It
was a stand-in, its own doc comment said so, and it is gone.

**F95 - unchanged and one step nearer.** F95 wants `model.StringMap` where
`internal/admin` marshals a Go `map[string]string`, and it names the client's
`attributes` as the holdout. The authenticator config added here is a
`model.StringMap` from the start, so the pattern F95 asks for gains a sixth
family and the holdout is still the client. Nothing in this cut touches
`clients.go`, which is what F95 says has to arrive on its own branch.

## What the tests pin, and the mutation that found a survivor

Fifteen mutations, one per claim, each confirming a **named** test fails, each
reverted with the revert checked. They ran in a `git clone --no-local` of the
worktree, because a worktree copied with `cp` shares its git dir.

**One survived, and it was a finding.** Disabling the seed's not-in-master guard
on the *flow* loop alone left `TestMasterOmitsTheOrganizationFlows` passing: the
three organization flows were created in master and the execution rows pointing
at them were still skipped, so master gained three flows nothing referenced and
the test - which looked only at the browser flow's four rows - saw nothing.
Three orphan flows nothing reads is exactly the shape F103 exists to complain
about, arriving inside the cut that pays F103 off.

The test now asserts master's totals - 17 flows, 48 execution rows, 4 configs -
and the mutation is killed twice over, by the flow-loop guard alone and by all
three guards together.

## Parity, before and after

Before: **451 of 541** enumerated behaviours served, 4 chapters not enumerated.
The chapter `admin/authentication-management` read **18 of 39**.

After: see the PR body, which carries the number `TestCoverage` computed rather
than the one this section predicts. The chapter is expected to read 39 of 39 and
the total 472 of 541, and if it reads anything else the meter is right and this
paragraph is wrong.

## What is left undone

- **`GET /flows/{alias}/executions` is served for a top-level flow.** A sub-flow
  addressed by its own alias is served too, because the store resolves any
  alias; whether Keycloak refuses that was not measured.
- **`POST /executions` with a `parentFlow` naming a sub-flow** was not measured;
  Gloak accepts it.
- **The `level`/`index` walk is not measured past three levels in a *created*
  flow.** The seed reaches level 5 and is asserted; a caller nesting six deep is
  not.
- **The relative order of `description` and `alias`, and of `flowId` and
  `authenticationConfig`,** in the flat execution row. No observed row carries
  either pair, so the merge in `executionInfoRepresentation` is a guess about
  two adjacencies and is marked as one.
- **Requirement semantics.** `REQUIRED`, `ALTERNATIVE` and `CONDITIONAL` are
  stored and compared for equality. B3 reads one row as DISABLED-or-not. There
  is no traversal and no algebra, and `internal/admin/flows.go` says so.
