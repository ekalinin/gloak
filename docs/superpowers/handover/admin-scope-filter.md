# The Admin API's scope filter: one mechanism, two role sets, and a family that reads the other one

F198 recorded a **symptom**: a client with `fullScopeAllowed: false` is refused
`/admin/realms/{realm}`, `/admin/realms` and `/admin/serverinfo` with the generic
`HTTP 403 Forbidden`, behind the realm resolution, and Gloak answered 200. It did
not say why, and it named two cells nobody had probed.

The mechanism is **not** what the brief's most likely candidate said. It is not
yesterday's token filter showing through - the Admin API's guard never reads the
token's claims and could not - and it is not an audience or client check either.
It is the **role set**, recomputed server-side under the token's client scope,
and it is the account gate's finding on a third surface.

Two things also turned out to read the **unfiltered** set, both measured and
neither predictable from the other: the conferral closure behind `mayGrantRole`,
and the whole `Workflows` family.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1
start-dev` on 2026-09-08 and re-verified on a second, clean container on
2026-09-09.

## 1. The corpus, and why it came first

F198 said this and it is the reason the cut could not start with the handler:

> Every fixture in the admin chapter authenticates through `admin-cli`, whose
> `fullScopeAllowed` is on, and `security-admin-console`'s is on too - so a
> guard that works and a guard that is never reached produce the identical
> 900-odd admin goldens.

That is exact. `POST /clients` defaults the flag to **true**, `internal/bootstrap`
sets it on the two clients that carry it, and `internal/oidc/registration.go`
sets it on every dynamically registered client. Before this branch **no admin
fixture in the tree had a flag-off caller at all**, so serving the filter and
running the suite would have proved nothing and a green tree would have looked
like evidence.

`adminScopeFilteredFixture` is the corpus. One user and three clients:

```
gloak-probe-adminscope-full    fullScopeAllowed true
gloak-probe-adminscope-narrow  fullScopeAllowed false, nothing mapped
gloak-probe-adminscope-view    fullScopeAllowed false, master-realm's view-users mapped
```

The user is a **full administrator** - it holds the realm role `admin`, composite
over all 21 of `master-realm`'s roles plus `create-realm` - so every refusal is a
statement about the client and not about the user. `-full` and `-narrow` differ in
**one field**, which is the minimal pair AGENTS.md asks for and which the account
chapter's older pair was one variable short of.

Measured on exactly these three clients:

```
                       -full  -narrow  -view
GET /users/{unknown}    404     403     404
GET /clients            200     403     403
GET /admin/realms/{r}   200     403     200
GET /admin/realms       200     403     200
GET /admin/realms/nope  404     404     404
GET /workflows          200     200     200
```

**All three are lightweight**, held constant so it is not a second variable, and
that buys two things. Their tokens carry the **identical eight claims** - `exp`,
`iat`, `jti`, `iss`, `typ`, `azp`, `sid`, `scope` - with no `aud`, no
`realm_access` and no `resource_access` between them, and they answer 403, 404
and 200. So the corpus asserts the mechanism itself rather than leaving it to
this document's prose. Section 7.1 is the second reason, and it was a finding.

### 1.1 What it can refute

Eight cases read it, and each of these mistakes moves at least one golden:

| a wrong implementation | the case that catches it |
|---|---|
| no filter at all - today's Gloak | `admin/users/scope-filtered-read` moves 403 → 404 |
| the flag read backwards | `admin/users/scope-filtered-read-full-scope` moves 404 → 403 |
| **a coarse gate**: a flag-off client refused outright | `admin/users/scope-filtered-role-in-scope` moves 404 → 403 |
| **any mapping opens everything**: flag-off plus one scope mapping admitted wholesale | `admin/clients/scope-filtered-role-out-of-scope` moves 403 → 200 |
| the filter applied only to the container-narrowed set and not to `maySeeRealm`'s wider one | `admin/realms-admin/scope-filtered-read` |
| the filter skipped where there is no `{realm}` segment and so no container | `admin/realms-admin/scope-filtered-listing` |
| the filter run **ahead** of the realm resolution | `admin/realms-admin/scope-filtered-unknown-realm` moves 404 → 403 |
| the filter applied uniformly, `Workflows` included | `admin/workflows/scope-filtered-held-roles` moves 200 → 403 |

The third and fourth rows are the pair that matters most. They are the same
flag-off client on two routes, and no single-cell reading passes both: refusing a
flag-off caller outright is right on `-narrow` and wrong on `-view`'s user read,
and admitting one with any mapping at all is right on `-view`'s user read and
wrong on its client listing.

### 1.2 Two decisions inside the fixture

**`view-users` rather than `view-realm` on the third client.** Both prove the
same thing. `view-users` opens the user read with a 26-byte body and is refused
on the client listing with a 30-byte one; `view-realm`'s 200 is the realm's whole
4486-byte representation. The evidence is identical and the goldens are two
orders of magnitude smaller.

**A user id that names nothing** in the three user reads. A real user would make
the golden a representation, which the pollution guard then has to reason about
and which changes whenever the user serialiser does. A missing id keeps all three
goldens under thirty bytes and still separates 403 from 404, which is the whole
question.

**The cases are last in `catalog_admin.go` on purpose.** The fixture creates a
user and three clients, and AGENTS.md records that a fixture's objects are in the
shared recording realm for everything recorded after it. Last means nothing in
the admin chapter is recorded after them.

## 2. The mechanism

### 2.1 It is not the token's claims, and it cannot be

The first probe settles the most likely reading before anything else.

```
admin-cli, the bootstrapped administrator, master

  azp, exp, iat, iss, jti, scope, sid, typ         -- eight claims
  realm_access     ABSENT
  resource_access  ABSENT
  aud              ABSENT
```

`admin-cli` carries `client.use.lightweight.access.token.enabled = true`, so its
token names **no roles at all**, and it drives the entire Admin API. So the guard
cannot be reading `resource_access`.

The pair that makes it airtight is two lightweight clients differing only in the
flag:

```
p-full-lw   fullScopeAllowed true,  lightweight   8 claims   200
p-narrow-lw fullScopeAllowed false, lightweight   8 claims   403
```

**The identical eight claims, and opposite answers.** There is no byte in either
token an implementation could read. That is exactly the shape
`account/gate/scope-filtered-lightweight` records one chapter over, and it says
the same thing here: the server recomputes the granted role set.

`aud` is ruled out separately and it is worth saying, because it is the obvious
second guess. `admin-cli` has **no** `aud` and is served; `p-narrow-view` has
`aud: "master-realm"` and is refused on `/users`; `p-full` has
`aud: ["master-realm","account"]` and is served. Every combination occurs.

### 2.2 It is the roles, and mapping them back restores everything

`p-narrow-mapped` is `fullScopeAllowed: false` with all 21 of `master-realm`'s
roles mapped into its scope:

```
                     /admin/realms/master  /admin/realms  /admin/serverinfo  ~/users  ~/clients
p-narrow              403                   403            403                403      403
p-narrow-mapped       200                   200            200                200      200
```

So there is no audience test, no client test and no coarse gate. Put the roles
back in scope and the flag-off client is a full administrator again.

Three other candidate explanations are refuted by construction, each with its
control:

```
p-conf-narrow  confidential, flag off        403      p-conf-full  confidential, flag on   200
p-sa-narrow    client_credentials, flag off  403      p-sa-full    same, flag on           200
p-narrow-lw    lightweight, flag off         403      p-full-lw    lightweight, flag on    200
```

Public against confidential, user grant against service account, lightweight
against ordinary - none of them is the variable.

### 2.3 The scope side expands composites

`p-narrow-adminrole` maps the **realm** role `admin` alone into its scope. Its
token comes back carrying all 21 `master-realm` client roles and it is 200
everywhere. So the scope side's downward closure that yesterday's cut measured on
the token path reaches client roles through a realm composite, and the admin
surface inherits it rather than having a rule of its own.

### 2.4 The granted scope is read off the token

One client, one user, an optional client scope carrying the 21 admin scope
mappings, and two token requests differing only in `scope`:

```
optional, not named   scope "openid email profile"                      403
optional, NAMED       scope "openid email f198-admin-scope profile"     200
default, not named    scope "openid email f198-admin-scope profile"     200
```

So the granted scope is an input, not a default. `inTokenScope` passes
`parsed.Scope` for that reason. **Gloak cannot exercise this cell today**: F16's
`grantedScope` is a constant plus `openid`, so no request can put a client
scope's name into a Gloak token's `scope` claim. The code is right and the case
cannot be written - F203.

### 2.5 The filter is frozen at issuance, and Gloak recomputes

This is the one place Gloak diverges knowingly, and it was not guessed.

```
token minted with the flag OFF                    403
  flip the flag ON, same token                    403
  a fresh token, flag ON                          200
flip the flag OFF again, the fresh ON token       200
  a fresh token, flag OFF                         403

fresh token before a scope mapping is added       403
  add the mapping, same token                     403
  a fresh token                                   200
  remove the mapping, that same token             200
```

**Keycloak records the granted role set on the client session at login and reads
it afterwards.** That is the last piece of the mechanism and it explains
everything above at once: lightweight tokens work because the roles are on the
session rather than in the token; a flag-off token is refused because the stored
set is empty; and flipping the flag under a live token changes nothing.

Gloak recomputes per request from the client's current state. It has no stored
granted set and giving it one means a migration and the session model, which is
the "fixing a general rule inside a family branch" mistake AGENTS.md names. The
divergence is observable **only** by mutating a client's flag or scope mappings
while one of its tokens is alive. No conformance case does that, and the fixture
creates its clients before it mints anything. Filed as **F202**, with the
direction stated: removing a mapping revokes immediately in Gloak where Keycloak
waits for expiry, which is the restrictive side; adding one grants immediately,
which is permissive relative to Keycloak but never beyond the client's configured
scope.

### 2.6 So: is the fix one line?

Nearly, and the brief asked for that to be said plainly if so.

The **route guard** half is one line of intent: filter the caller's effective
roles by the token client's scope before `adminRoleNames` narrows them, using the
`roles.InScope`/`roles.ScopesInEffect`/`roles.Filter` trio yesterday's cut
already built. Nothing new was needed in `internal/roles`. The measurement is
the work, and it is what says that one line is right rather than a coarse gate.

What stops it being *only* one line is section 4: two questions on this API read
the other set, and neither is predictable from the guard.

## 3. The per-family guard order

F198 said the order was measured on three routes and not on the family. It is
measured on the family now, and the answer is that **the filter is not a step in
the order at all.**

### 3.1 The sweep

79 routes across every family Gloak serves, four callers, two pairs:

```
PAIR 1   admin-cli + a user holding no admin role
   vs    a flag-off client + a full administrator

PAIR 2   admin-cli + a user holding master-realm's view-realm alone
   vs    a flag-off client scoping view-realm + a full administrator
```

**77 of 79 routes are identical in both pairs**, status and body. Not "both
403" - identical, including every family whose resolution order AGENTS.md
records as unusual:

```
GET  /admin/realms/master/groups/{unknown}      404 Could not find group by id   both
GET  /admin/realms/master/roles-by-id/{unknown} 404 Could not find role with id  both
GET  /admin/realms/master/group-by-path/nope    404 Group path does not exist    both
GET  /admin/realms/master/client-scopes/{unk}   403                              both
PUT  /admin/realms/master/default-groups/{unk}  403                              both
GET  /admin/realms/master/organizations         403                              both
GET  /admin/realms/master/clients/{unk}/roles   403                              both
GET  /admin/realms/master/client-types          501 Feature not enabled          both
GET  /admin/realms/nosuchrealm                  404 Realm not found.             both
GET  /admin/realms/master/nosuchthing           404 unmatched-path body          both
```

The `Groups` family still resolves its group before the caller and answers 404 to
everybody. `client-types` still answers its 501 ahead of authorization.
`Organizations` still resolves the caller first. The scope filter changes none of
it, because it is upstream of all of it: it decides *which roles the caller has*,
and each family then asks its own question of that set in its own order.

That is the finding, and it is the reason the fix could go in `resolveCaller`
rather than in 26 guard combinators.

### 3.2 Where it does sit

```
1.  authentication          401  - a garbage or absent bearer, ahead of the realm:
                                   /admin/realms/nosuchrealm is 401 without a token
2.  realm resolution        404  `Realm not found.` to a flag-off caller
3.  feature gates           501  client-types answers a flag-off caller its 501
4.  the caller's roles           <- the filter is here, inside the set
5.  each family's own order      unchanged
```

Steps 1 and 2 in that order are worth pinning: a garbage bearer aimed at
`/admin/realms/nosuchrealm` is **401**, not `Realm not found.`, so authentication
precedes realm resolution, while a *valid* flag-off token aimed at the same path
is 404. `admin/realms-admin/scope-filtered-unknown-realm` is the golden.

## 4. The two questions that read the unfiltered set

This is the part nothing predicted and the part that made the diff bigger than
one line.

### 4.1 `mayGrantRole`'s conferral closure

Measured with a flag-off client whose scope carries `manage-users` alone, over a
user holding the realm role `admin`, handing out `master-realm`'s `manage-realm`:

```
                                                        grant  available
full administrator @ flag-off client scoping manage-users  204     20
manage-users holder @ THE SAME flag-off client             403      7
manage-users holder @ admin-cli (flag on)                  403      7
full administrator @ admin-cli                             204     20
```

The first row answers what the **fourth** answers and not what the second does -
although its *route guard* answers what the second's does, since `manage-users`
is the only admin role its token scope carries and that is what admits it to the
route at all.

So one request asks two questions of two different sets. The route guard reads the
scope-filtered set; the conferral closure reads the roles the caller really holds.
Rows two and three together are what make it a statement about the **source** of
the set rather than about the client: the same holder is refused through both
clients.

### 4.2 The `Workflows` family

The two routes of the 79 that differ between the pairs are both `Workflows`, and
the whole nine-operation family behaves the same way:

```
                                                 workflows  users
full administrator @ flag-off, nothing mapped        200      403
manage-users holder @ flag-off, nothing mapped       403      403
manage-users holder @ admin-cli                      403      200
full administrator @ admin-cli                       200      200
```

The family authorises - row two is 403 - and it authorises against the unfiltered
set. AGENTS.md already records that its guard is the realm role `admin` itself
and that all 21 `master-realm` roles are 403 singly; what is new is *which* role
set that name is looked up in.

It is not "the realm roles escape the filter", and that was checked rather than
assumed: `create-realm` is filtered like everything else - a `create-realm`
holder through a flag-off client is 403 on `POST /admin/realms` - and a user
holding **only** the realm role `admin` through a flag-off client is 403 on
`/admin/realms/master` and 200 on `/workflows`. One role, two routes, two
answers. The family is the variable.

### 4.3 What that cost in code

`caller` grew one field and one memo:

```go
effective []*model.Role   // scope-filtered  - every route admission
held      []*model.Role   // unfiltered      - conferral and Workflows
```

`effective` keeps its name and every existing reader - `namesOnContainerFor`,
`adminRolesAnywhere`, `guardRealmContainerAny` - and silently becomes right,
because all three are route admissions. `foreignGrants` moves to `held`, which is
where it was already going conceptually. `grants()` stops closing over
`adminGrants` and closes over `caller.names()` instead, which is
`adminRoleNames` over `held` - **exactly what `adminGrants` used to be**, so for
every flag-on caller in the tree nothing changed at all. `guardAnyHeld` is a new
combinator with one user, the nine `Workflows` routes.

## 5. The cross-realm cell

F198's second unprobed cell: "which realm's client the filter reads is a probe
nobody has sent".

The probe has to be built rather than looked for, because a token from master
naming a client that exists only in master is consistent with both readings. So:
**one `clientId` in two realms with opposite flags**, both ways round.

```
twin      master: flag OFF     f198x: flag ON
twinrev   master: flag ON      f198x: flag OFF

caller                        GET /admin/realms/f198x   GET /admin/realms/master
master admin @ twin    (off/on)      403                      403
master admin @ twinrev (on/off)      200                      200
f198x xadmin @ twin    (off/on)      200                      403
f198x xadmin @ twinrev (on/off)      403                      403
```

**The filter reads the client of the token's issuing realm, never the addressed
realm's client of the same name**, and the twin pair says so in both directions:
a master token from the flag-off `twin` is refused `f198x` although `f198x`'s
`twin` has the flag on, and a master token from the flag-on `twinrev` is served
`f198x` although `f198x`'s `twinrev` has it off.

Gloak gets this for free and it is worth saying why rather than claiming credit:
`resolveCaller` already carries `authRealm`, the realm that issued the token, for
`foreignGrants`' sake, and `inTokenScope` looks the client up in it. Looking it
up in the path's realm would have been the natural mistake and it is the one this
probe rules out.

The cross-realm cell is otherwise **not a new rule**. `p-narrow-view`, whose
filtered set is `view-users` alone, still reads `f198x`'s realm representation
and is still 403 on its users and clients - AGENTS.md's "one read leaks
sideways", running on the filtered set exactly as it runs on the unfiltered one.
The filter is computed once in the token's realm and the ordinary cross-realm
container logic runs on the result.

## 6. The boundary question

**`internal/roles` gained nothing and decides nothing new.** No function was
added, no signature changed, and the package's own comment - *"must not write
anything, or decide who may do what"* - is untouched.

`internal/admin/auth.go` is the fifth caller of `roles.InScope`, and it calls it
the way the other four do: as a set computation. The three calls are
`ScopesInEffect`, `InScope` and `Filter`, and what comes back is a `[]*model.Role`.
The **authorisation** decision is made afterwards and in `internal/admin`, by
`adminRoleNames` narrowing that slice to one container and by `hasAny` asking
whether a route's names are in it. `mayMapRole` and `mayGrantRole` did not move
and did not change shape.

The line is easy to state and worth stating, because the tempting version of this
fix crosses it: it would have been shorter to give `internal/roles` a
`roles.AdminGrants(ctx, repo, client, user, container)` that answered "the admin
names this caller has". That would have put the container test - F32's
escalation - inside `internal/roles`, where the boundary table says it must not
be, and it would have made a second place that decides who is an administrator,
which is the exact thing `internal/roles`' package comment warns about. It was
not done.

Section 4's split is a second argument for the boundary sitting where it does.
One request now asks `internal/roles` for one set and then asks **two different
questions** of two different sets. A `roles` function that answered "may this
caller do this" would have had to be told which - which is a policy argument, and
a policy argument is the boundary being crossed with extra steps.

## 7. The record diff, read file by file

`make record` was run three times. The first two were on the heavy corpus and
section 7.1 is what they found; the third is the one the branch carries.

**Run 3: 1078 goldens rewritten. Every golden that existed on `main` is
byte-identical to `main`. Eight added, none modified, none removed.**

```
$ git status --short internal/conformance/testdata/golden
?? admin/clients/scope-filtered-role-out-of-scope.http
?? admin/realms-admin/scope-filtered-listing.http
?? admin/realms-admin/scope-filtered-read.http
?? admin/realms-admin/scope-filtered-unknown-realm.http
?? admin/users/scope-filtered-read.http
?? admin/users/scope-filtered-read-full-scope.http
?? admin/users/scope-filtered-role-in-scope.http
?? admin/workflows/scope-filtered-held-roles.http
```

Eight `??` and nothing else. There is no golden to explain, because none moved -
which is the answer the corpus problem predicted and the reason the corpus had to
exist. **413 operations' worth of admin authorisation goldens all authenticate
through `admin-cli`, whose `fullScopeAllowed` is on, so `roles.InScope`
short-circuits to "everything" for every one of them and `adminGrants` is
computed from exactly the slice it was computed from before.** Serving the filter
could not have moved them, and if one had moved that would have been the finding.

The eight new ones, read individually:

| golden | what it holds | why that is right |
|---|---|---|
| `admin/users/scope-filtered-read` | 403, `{"error":"HTTP 403 Forbidden"}`, `application/json`, five headers | the flag-off caller, refused - F198's symptom |
| `admin/users/scope-filtered-read-full-scope` | 404, `{"error":"User not found"}` | the control one field away; the administrator really is one |
| `admin/users/scope-filtered-role-in-scope` | 404, `{"error":"User not found"}` | flag off **and** served, because `view-users` is in scope |
| `admin/clients/scope-filtered-role-out-of-scope` | 403 | the same token, refused a role its scope does not carry |
| `admin/realms-admin/scope-filtered-read` | 403 | `maySeeRealm`'s wider question, filtered too |
| `admin/realms-admin/scope-filtered-listing` | 403 | the route with no `{realm}` segment and so no container |
| `admin/realms-admin/scope-filtered-unknown-realm` | 404, `{"error":"Realm not found."}` | the refusal sits behind the realm resolution |
| `admin/workflows/scope-filtered-held-roles` | 200, `--- []`, `application/yaml;charset=UTF-8`, **four** headers | the family that reads the unfiltered set |

The last row's four headers are not an anomaly: `application/yaml` is one of the
media types AGENTS.md records as omitting `X-Frame-Options`, and it does here.

### 7.1 A golden that could not be reproduced, and what it was measuring

The first run's flag-on control recorded

```
HTTP/1.1 431 Request Header Fields Too Large
```

with an empty body, where every hand probe of the same request had answered
`404 {"error":"User not found"}`. Read rather than re-recorded, and the mechanism
is this: **master holds a `{realm}-realm` client for every realm that exists**,
and the realm role `admin` is composite over each one's 21 roles. So a full
administrator's ordinary access token gains a `resource_access` key per realm.
Measured directly, on one container, adding realms four at a time:

```
realms   token bytes   resource_access keys
     1          1759                      2
     5          3999                      6
     9          6239                     10
    13          8485                     14
    17         10735                     18
    21         12986                     22
```

About 560 bytes a realm. Recorded in catalogue order **after** every fixture that
creates a realm, the `Authorization` header crossed Quarkus's limit and Keycloak
answered 431 instead of the case's behaviour.

That golden was a measurement of the container's history rather than of anything
this cut is about, and AGENTS.md names the shape: *a golden that holds only while
the catalogue's order holds is worse than no golden, because it looks like a
measurement.* It would also have failed `TestConformance` outright - `net/http`'s
default `MaxHeaderBytes` is 1 MB and the verifier serves through a
`ResponseRecorder` with no limit at all, so Gloak answers the 404.

The fix is in the fixture rather than in a mask: all three clients are
lightweight, so all three tokens are eight claims and about 760 bytes **whatever
the container's history**. Re-measured on the same container at 21 realms: 758,
761 and 758 bytes, and all six route cells unchanged. The 431 itself is a real
measured Keycloak behaviour that Gloak does not reproduce, and it is **F206**.

**This is the third recent cut to find a real defect by reading the record diff**,
and it is the first to find one in a golden it had just written itself.

## 8. The mutation pass

The harness is `/tmp/f198/mutate.sh`, driven by `/tmp/f198/run_mutations.py`. Its
order is the one this project asks for: refuse an empty diff, refuse a build
failure, **read `go test`'s exit code before looking at any output**, revert,
verify the revert restored the byte-identical file, and run **every package
separately** rather than a filtered `-run`. All four refusals were self-tested
against deliberate controls before any real mutation ran - a no-op substitution
is `REFUSED: the diff is empty`, a typo'd field is `REFUSED: does not build`, an
absent pattern is `REFUSED: the pattern is not in <file>`, and a known-good
mutation of `caller.has` is `KILLED`.

Every mutation names the tests that kill it. Seventeen were run over every
package; **fourteen were killed on the first pass, two survived and were closed,
and one survives deliberately.**

| # | mutation | verdict | killed by |
|---|---|---|---|
| A1 | no filter at all - the whole cut inverted, which is what `main` does | killed | `TestConformance/admin/users/scope-filtered-read` and three siblings; `TestWorkflowsReadsTheRolesTheCallerHolds`; `TestScopeFilterReadsTheTokenRealmsClient` |
| A3 | **a coarse gate**: the flag read as "may this client do anything" | killed | `TestConformance/admin/users/scope-filtered-role-in-scope`; `TestGrantsAreComputedFromTheRolesTheCallerHolds` |
| A4 | **any mapping opens everything**: a non-empty filtered set admitted wholesale | killed | `TestConformance/admin/clients/scope-filtered-role-out-of-scope` |
| A5 | the filter reaches `adminGrants` and not the realm predicates | killed | `TestConformance/admin/realms-admin/scope-filtered-read` and `-listing`; `TestScopeFilterReadsTheTokenRealmsClient` |
| A6 | the missing client falls open - L1's shape here | killed | `TestScopeFilterRefusesATokenWhoseClientIsGone` |
| A7 | the missing client refuses with an empty set - `internal/account`'s answer | killed | same |
| A9 | `grants()` closes over `adminGrants` again - the pre-split implementation | killed | `TestGrantsAreComputedFromTheRolesTheCallerHolds` |
| A11 | `names()` reads the filtered set - "apply it uniformly" | killed | `TestConformance/admin/workflows/scope-filtered-held-roles`; both new package tests |
| A12 | Workflows guarded by the filtered set | killed | same golden; `TestWorkflowsReadsTheRolesTheCallerHolds` |
| A13 | `guardAnyHeld` admits everybody | killed | `TestConformance/admin/workflows/list-forbidden`; `TestWorkflowGuardIsTheAdminRoleItselfAndNotItsComposites` |
| A15 | the realm listing's per-row question reads the unfiltered set | killed | `TestConformance/admin/realms-admin/scope-filtered-listing` |
| A16 | `maySeeRealm`'s wider question reads the unfiltered set | killed | `TestConformance/admin/realms-admin/scope-filtered-read`; `TestScopeFilterReadsTheTokenRealmsClient` |
| A2 | `roles.InScope` ignores the flag, so the filter always applies | killed | `internal/account`, `internal/admin` and `internal/conformance`, broadly |
| S1 | `InScope` **keys and looks up** by name - yesterday's S5, re-run here | killed | `TestConformance/oidc/introspection/scope-filtered-access-token` |
| A10 | `foreignGrants` reads the filtered set | **survived, then closed** - 8.3 | `TestForeignGrantsAreComputedFromTheRolesTheCallerHolds` |
| A17 | `guardRealmContainerAny` reads the unfiltered set | **survived, then closed** - 8.4 | `TestLocalizationGuardReadsTheScopeFilteredRoles` |
| A14 | the granted scope is ignored | **survivor** - 8.5 | nothing |

Three rows deserve reading rather than counting.

**A1 is the corpus earning its keep.** It is this cut inverted - the filter
resolved and thrown away - and **nothing on `main` would have caught it.** Six
tests kill it now and all six are new. That is the corpus problem demonstrated
rather than asserted, and it is why the fixture had to come first.

**A3 and A4 are the pair no single case separates.** A3 is a coherent
implementation of "the flag is a gate" and A4 of "a mapping is a pass"; each is
right on every case the other fails. Only `-view` answering **404 on the user
read and 403 on the client listing** rules out both, which is the 2x2 section 1.1
describes. A corpus with two clients instead of three would have passed one of
them.

**S1 is killed by yesterday's golden and not by mine**, and that is worth being
honest about. Every role in `adminScopeFilteredFixture` has a distinct name, so a
name-keyed `InScope` and an id-keyed one agree on all of it - the admin corpus
inherits `introspect-scope-filtered`'s protection rather than adding to it. The
mutation was run from this branch precisely because the admin guard is a fifth
caller of that function, and the answer is that the fifth caller is covered by
the second caller's fixture.

### 8.1 The harness had to be rewritten twice, and both reasons are findings

**The first version could leave the tree mutated.** It built its package list
with `mapfile`, which does not exist in macOS's bash 3.2, so under `set -u` the
unbound `PKGS` aborted the script **before the revert ran**. Five mutations were
left applied in the working tree at once. Nothing detected it except reading
`git status`.

The fix is that the revert is a `trap ... EXIT` rather than a step on the happy
path. **A harness whose revert is reachable only on the success path is a harness
that leaves the tree mutated exactly when something has gone wrong**, which is
the moment it matters. AGENTS.md's list of what a mutation harness must do says
"revert, and verify the revert"; it does not say *from where*, and this is the
argument for adding it.

**The second version silently failed to match three patterns.** Driven from
shell, multi-line `from` strings carrying tabs did not survive quoting, and three
mutations reported `REFUSED: the pattern is not in <file>` - which reads like a
stale mutation list rather than like a broken harness. It is driven from Python
now, so the patterns reach the harness byte for byte. Worth saying because
`REFUSED` is the harness's *safe* answer and is easy to skim past: a refusal that
should have been a kill looks like housekeeping.

### 8.2 `git add -A` during a mutation pass commits the mutation

This project says "commit early and often" and "apply a mutation, confirm the
named test fails, revert". **Those two instructions are in tension and nothing
says so.** A `git add -A && git commit` issued while the pass was running staged
a mutated `internal/admin/auth.go` - `edeb841` carries mutation A1 - and the
commit message was about a documentation change. The working tree was correct
within the second, because the harness's trap restored it; the commit was not.

It was caught by reading `git diff e1e2dad HEAD` over the source files, which is
not something the tree can do for itself: `make test` passes on the mutated
commit's *working tree*, CI would have run the mutation, and no test in this
repository compares HEAD against the working tree.

Fixed in `9341abc`, which reverts the source and says so in its subject rather
than being folded silently into the next commit. The rule worth folding is narrow
and absolute: **never stage by wildcard while a mutation pass is running**, and
name paths instead.

### 8.3 A10, and a survivor that was a question rather than a hole

`foreignGrants` is the conferral set for a role belonging to **another realm's**
admin container. Section 4.1 measured the same-realm closure unfiltered, and this
cut pointed the foreign one at the same set - **by symmetry, not by measurement**,
which is the reasoning this project distrusts. Pointing it back at the filtered
set survived every package.

The right response was not a test, it was a probe. Sent 2026-09-09, handing out
`f198y-realm`'s `manage-realm` to a master user:

```
full administrator @ flag-off client scoping manage-users   204, available 20
full administrator @ flag-on client                         204, available 20
full administrator @ admin-cli                              204, available 20
a master manage-users holder @ admin-cli                    403, available 0
```

The foreign closure follows the same-realm one. The implementation was right and
the argument for it was not, and the difference matters: a test written before
the probe would have frozen an assumption. Closed with
`TestForeignGrantsAreComputedFromTheRolesTheCallerHolds`, which carries the
control - the last row - so it asserts the source of the set rather than that the
route is open.

The caller's token scope has to carry `manage-users` for this test to exist at
all, because the route guard is filtered and runs first. That is the two-set
split showing up as a constraint on how it can be observed.

### 8.4 A17, and two routes nothing had pointed a flag-off token at

`guardRealmContainerAny` has exactly two users, `GET .../localization` and
`GET .../localization/{locale}/{key}`, and no case sends them a flag-off token -
so pointing it at the unfiltered set survived. It is a route admission and every
other route admission is filtered, but "it should be" is the argument that got
A10 wrong, so it was measured too:

```
full administrator @ flag-on client                200 and 404
full administrator @ flag-off, nothing mapped      403 and 403
full administrator @ flag-off, view-realm mapped   200 and 404
```

Closed with `TestLocalizationGuardReadsTheScopeFilteredRoles`. Both re-runs
confirmed the kill.

### 8.5 A14 is a survivor and is left as one

Replacing `parsed.Scope` with `""` in `inTokenScope` survives the whole tree, and
it is **J1's shape on a third surface**. F16's `grantedScope` is a constant plus
`openid`, so no request can put a client scope's name into a Gloak token's
`scope` claim; `ScopesInEffect("")` and `ScopesInEffect(<the constant>)` return
the same set, and no case can be written that would tell them apart.

It is left open rather than closed at the seam, and that is a departure from
yesterday's treatment of J1. The reason is that J1's seam test asserted a rule
Gloak's own code could express - the granted scope naming an optional client
scope - where here the value is measured against **Keycloak** (section 2.4) and
Gloak cannot produce it at all. A seam test would assert that the argument is
passed, which is what the `git diff` already shows, and not that it is the right
argument. F203 is the entry, and F16 is what unblocks it.

## 9. What belongs in AGENTS.md

Phrased as it would be folded, under "Things that look like bugs and are not".

- **The Admin API is scope-filtered, and the filter is the caller's role set
  rather than a check of its own.** A full administrator reaching the API through
  a client with `fullScopeAllowed` off answers, **cell for cell over 79 routes**,
  what a caller holding no admin role answers; one through a client scoping
  `view-realm` alone answers cell for cell what a user genuinely holding
  `view-realm` answers. So no family's resolution order changes: the filter
  decides which roles the caller has and each family then asks its own question
  in its own order. The refusal is the generic
  `{"error":"HTTP 403 Forbidden"}`, `application/json` with no charset, and it
  sits **behind** the realm resolution and behind `client-types`' 501 - an
  unknown realm is still `Realm not found.` and `client-types` is still 501 - and
  **in front of** nothing, because it is not a step.
- **Nothing in the token could have answered it.** `admin-cli` is lightweight:
  its token carries eight claims, no `realm_access`, no `resource_access` and no
  `aud`, and it drives the whole API. Two lightweight clients differing only in
  the flag mint **byte-identically shaped tokens** and answer 200 and 403. `aud`
  is ruled out separately: the served `admin-cli` has none, a refused caller has
  a bare string, a served one has an array. The server recomputes the granted set
  - which is `internal/account`'s finding on a third surface.
- **Two questions on this API read the roles the caller *holds*, not the filtered
  set, and neither is predictable from the guard beside it.** `mayGrantRole`'s
  conferral closure is one: a full administrator through a client scoping
  `manage-users` alone hands out `master-realm`'s `manage-realm` and sees the
  full available list, where a caller genuinely holding `manage-users` is refused
  and sees seven - so one request asks two questions of two sets. The
  `Workflows` family is the other, and it is the only family of 79 routes that
  does: the same flag-off administrator is 403 everywhere else and 200 on all
  nine of its operations, while a `manage-users` holder is 403 there through
  either client. It is not "the realm roles escape the filter" - `create-realm`
  is filtered, and a user holding only `admin` is 403 on the realm read and 200
  on `/workflows`.
- **The granted scope is an input.** An optional client scope carrying the admin
  scope mappings opens the Admin API exactly when the token request named it -
  one client, one user, two requests differing only in `scope`, 403 and 200.
- **The filter is frozen at issuance and lives on the client session.** Flipping
  a client's `fullScopeAllowed` on does not open an already-minted token, and
  flipping it off does not close one; the same holds for adding and removing a
  scope mapping. Gloak recomputes per request instead, which is observable only
  by mutating a client while one of its tokens is alive. See F202.
- **The filter reads the client of the token's issuing realm, never the addressed
  realm's.** Measured with one `clientId` in two realms carrying opposite flags,
  both ways round: a master token from the flag-off twin is refused another
  realm's admin API although that realm's twin has the flag on, and the flag-on
  twin is served there although that realm's has it off. Reading the path's realm
  is the natural mistake.
- **A token whose client the realm no longer has is a 401 on the Admin API**, not
  a 403 and not a fall-open - measured by minting a token and deleting its
  client, on a flag-on and a flag-off client alike. `internal/account`'s
  equivalent branch refuses with an empty role set instead, which is that API's
  own measured answer; the two surfaces do not share one.

And two for the mutation-discipline paragraph at the end of the file, both earned
in this cut rather than reasoned about:

- **A mutation harness's revert belongs on a `trap ... EXIT`, not on the happy
  path.** This one's first version built its package list with `mapfile`, which
  macOS's bash 3.2 does not have, so `set -u` aborted **before** the revert and
  left five mutations applied at once. A revert reachable only when nothing went
  wrong is missing exactly when it is needed. The existing sentence says a
  harness must "revert, and verify the revert"; it does not say from where.
- **Never stage by wildcard while a mutation pass is running.** A
  `git add -A && git commit` about a documentation change committed a mutated
  `internal/admin/auth.go`. Nothing in this repository can catch that: `make test`
  passes on the mutated commit's working tree, because the harness had already
  restored it, and no test compares HEAD against the tree. "Commit early and
  often" and "apply a mutation, then revert" are in tension and neither says so.

## 10. Follow-ups

**F202: Keycloak freezes the scope filter at issuance and Gloak recomputes it per
request.** Measured both ways in section 2.5: flipping a client's
`fullScopeAllowed` on does not open an already-minted token and flipping it off
does not close one, and adding or removing a scope mapping behaves the same.
Keycloak records the granted role set on the client session at login; Gloak has
no stored granted set and reads the client's current state on every request.
Observable **only** by mutating a client while one of its tokens is alive, which
no case does. Closing it means a migration and the session model, which is why it
is an entry rather than part of this cut. The direction is worth recording:
removing a mapping revokes immediately in Gloak where Keycloak waits for expiry,
which is the restrictive side; adding one grants immediately, which is permissive
relative to Keycloak but never beyond the client's configured scope.

**F203: the Admin API's granted-scope input cannot be exercised, and the mutation
that ignores it survives.** `inTokenScope` passes `parsed.Scope` to
`roles.ScopesInEffect`, which is measured right - an optional client scope
carrying the admin scope mappings opens the API exactly when the token request
named it, section 2.4. But F16's `grantedScope` is a constant plus `openid`, so
no request can put a client scope's name into a Gloak token's `scope` claim, and
replacing `parsed.Scope` with `""` survives the whole tree - A14, section 8.5. It
is J1's shape on a third surface: `internal/account`'s gate is in the same
position, and **nothing has swept for a fourth**. The entry is that F16 is what
unblocks the case, and that until then the argument is a measurement in this
document rather than a test.

**F204: a disabled client's token is 401 on the Admin API and Gloak serves it.**
Measured 2026-09-08: a token minted at a client that is then disabled answers
`401 {"error":"HTTP 401 Unauthorized"}` where it had answered 200, on the same
request. `inTokenScope` now looks the client up and could read `Enabled` in the
same branch that already answers 401 for a client that is gone - one `||`. It was
left out deliberately: it is a rule about **authentication** rather than about the
scope filter, it has no case, and folding an unrelated refusal into this branch is
how a one-line fix reaches every admin route. The probe is already written; the
entry is to serve it with a case of its own.

**F205: `/admin/serverinfo` is one of F198's three symptom routes and Gloak does
not serve it at all.** There is no `HandleFunc` for it anywhere in the tree - the
path appears only in doc comments citing it as a measurement source. So F198's
symptom is now served on two of its three routes and the third is unreachable.
Worth saying because a reader of F198 will otherwise look for a
`serverinfo` case and not find one.

**F206: a full administrator's access token outgrows Keycloak's request header
limit, and Gloak answers the route instead of 431.** Section 7.1 is the
measurement: master holds a `{realm}-realm` client per realm and the realm role
`admin` is composite over each one's 21 roles, so an ordinary token grows about
560 bytes per realm - 1759 bytes at one realm, 12986 at 21. Past Quarkus's limit
the Admin API answers `431 Request Header Fields Too Large` with an empty body
and no headers at all. `net/http`'s default `MaxHeaderBytes` is 1 MB and the
conformance verifier serves through a `ResponseRecorder` with no limit, so Gloak
cannot reproduce it as things stand. Two things are unmeasured and both are cheap:
where the limit actually is, and whether the 431 carries the security headers.
This is also a **harness** entry - it is the second known way for a golden to be a
measurement of the container's history rather than of a behaviour, after F40's
counts, and nothing sweeps for a case whose request grows with the catalogue.

**F207: a mutation harness whose revert is on the happy path leaves the tree
mutated, and nothing in this repository can detect a mutation that got
committed.** Both halves bit in this cut, an hour apart. The first version of the
harness aborted under `set -u` before its revert and left five mutations applied
at once (section 8.1); a `git add -A` issued while the pass was running committed
one of them under a documentation subject (section 8.2). The second is the
sharper of the two, because the tree cannot see it: `make test` passes on the
mutated commit's working tree, and no test compares HEAD against the working
tree. Two cheap things would close it - a revert on a `trap ... EXIT`, which this
cut's harness now has, and a pre-commit check that refuses a commit while a
mutation is applied. AGENTS.md says a harness must "revert, and verify the
revert" and does not say from where; that is the sentence to sharpen.

## 11. Parity

`make conformance` on the branch head:

```
total: 570 of 622 enumerated behaviours served; 2 chapters not enumerated
```

and reproduced by hand with `cmd/parity` between the merge base `e1e2dad` and the
branch head, which is what CI posts:

```
Parity: 570 of 622, no change.
```

`no change` rather than `total unchanged` is the meter's stronger phrasing: it is
reserved for a diff where **no row moved at all**, not merely one where the total
came out level. The brief's base is **570 of 622, 2 chapters not enumerated**, and
it is unchanged. That is the expected result and not a disappointment, and the reason
is worth stating so nobody reads it as the cut having served nothing:

**the admin chapters' denominator counts distinct OpenAPI operations, not
cases.** All four operations the eight new cases address -
`GET /admin/realms/{realm}/users/{id}`, `GET /admin/realms/{realm}/clients`,
`GET /admin/realms/{realm}`, `GET /admin/realms` and
`GET /admin/realms/{realm}/workflows` - were already served and already counted,
so eight new `Implemented` cases move the numerator by nothing. The meter is
measuring surface, and this cut added no surface; it made an authorisation
decision correct on surface that was already there.

```
chapter                served  recorded  documented
admin/clients              31         1          35
admin/realms-admin         44         3          45
admin/users                31         2          34
admin/workflows             9         0           9
```

**The total did not fall and no case that was `Implemented` stopped matching.**
`CGO_ENABLED=0 go test ./...` is green over the whole tree, which is the number
section 7 cannot answer on its own: all 1079 comparable goldens are served from
Gloak and compared, including the 1071 that did not move.
