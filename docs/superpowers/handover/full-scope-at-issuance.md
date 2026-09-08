# `fullScopeAllowed` at issuance: one flag, four consumers, and a second surface nobody had asked about

F192 said Gloak ignores `fullScopeAllowed` when a token is issued, that the
defect is in `internal/oidc`, and that the fix belongs there.

The first half is right. **The second half is one place short and the third is
wrong about where the account case is decided.** `internal/account`'s gate never
read the token's claims either - it recomputes the user's roles from the
session - so filtering the token alone left `account/gate/scope-filtered-token`
answering 200 exactly as before. And the same defect exists on a **third**
surface this cut deliberately does not change: a `fullScopeAllowed: false`
client's token drives Gloak's Admin API as a full administrator where Keycloak
answers 403. Section 9 is that measurement and F198 is the entry.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1
start-dev` on 2026-09-08, on a container started clean for this session, in a
realm built for the purpose.

## 1. The fixture every measurement was taken against

```bash
docker run -d --name gloak-f192 -p 18192:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
```

Realm `f192`, and three things about it are load-bearing:

- **the user needs `email`, `firstName` and `lastName`**, or a password grant in
  a realm created through `POST /admin/realms` answers
  `{"error":"invalid_grant","error_description":"Account is not fully set up"}`
  and names neither the realm nor the profile. `accountBrokerFixture` already
  records this; it cost a probe here anyway;
- **a username under three characters is a 400**
  `{"field":"username","errorMessage":"error-invalid-length","params":["username",3,255]}`,
  so `u1` is not a legal probe name;
- `capp` is the client under test with the flag **off**, `cfull` is byte-for-byte
  the same client with the flag **on**, and `cother` is a third client owning
  roles the user holds. Two clients differing in one field is what every table
  below rests on.

```
realm roles   rr1 rr2 rr3 rrchild rrparent(composite over rrchild)
client roles  capp:capp-own  cother:co1  cother:co2
user          probeuser, holding all of them plus default-roles-f192
```

## 2. What Keycloak actually filters

### 2.1 The flag off, with nothing mapped

```
POST /realms/f192/protocol/openid-connect/token
     grant_type=password&client_id=capp&username=probeuser&password=pw&scope=openid

  scope           "openid profile email"
  realm_access    ABSENT
  resource_access {"capp":{"roles":["capp-own"]}}
  aud             ABSENT
```

The same request at `cfull`, which differs only in the flag:

```
  realm_access    {"roles":["rr1","rr3","rr2","default-roles-f192",
                            "offline_access","uma_authorization","rrparent","rrchild"]}
  resource_access {"capp":{"roles":["capp-own"]},
                   "account":{"roles":["manage-account","manage-account-links","view-profile"]},
                   "cother":{"roles":["co1","co2"]}}
  aud             ["capp","account","cother"]
```

Eight realm roles to none, three clients to one, and an `aud` of three to no
`aud` key at all. **`capp-own` survives with nothing mapped**, which is the
own-roles clause, and it is the *issuing* client's rather than every client's -
section 2.4.

### 2.2 Mapping moves the answer, and it moves `aud` too

```
POST /admin/realms/f192/clients/{capp}/scope-mappings/realm  [rr1]
  realm_access    {"roles":["rr1"]}
  resource_access {"capp":{"roles":["capp-own"]}}
  aud             ABSENT

POST /admin/realms/f192/clients/{capp}/scope-mappings/clients/{cother}  [co1]
  realm_access    {"roles":["rr1"]}
  resource_access {"capp":{"roles":["capp-own"]},"cother":{"roles":["co1"]}}
  aud             "cother"
```

`co2` is held by the user and not mapped, and it is not in the token. **`aud`
moved from absent to a bare string on the strength of a scope mapping**, which
is the second observable the brief asked about and which nobody had asked
before: `token.Audience` is computed from the client roles, so filtering the
roles filters the audience. The refresh token's `aud_x` follows it exactly.

### 2.3 The composite question, and the measurement that settles it

The question is whether the expansion happens before or after the filter. Both
readings are plausible and they differ on exactly one input, so the probe has to
be built rather than looked for.

**Take the user's direct `rrchild` away and leave `rrparent`.** The user now
holds the parent and reaches the child only through the composite. Then map the
**child alone** into `capp`'s scope:

```
user direct realm roles   ["rr1","rr2","rr3","default-roles-f192","rrparent"]
capp scope-mappings/realm ["rrchild"]

  realm_access    {"roles":["rrchild"]}
```

- expand-then-filter answers `rrchild` - the child is in the user's effective
  set and in the scope;
- filter-then-expand answers **nothing** - `rrparent` is not in the scope, so
  there is nothing left to expand.

Keycloak answers `rrchild`. **The subject's roles are expanded first and the
filter runs per role.**

The scope side is expanded too, and it is a separate closure. Map the **parent
alone**, with the user still holding the parent only:

```
capp scope-mappings/realm ["rrparent"]
  realm_access    {"roles":["rrparent","rrchild"]}
```

And the closure runs one way only: with the child mapped, the parent stayed out
of the token although the user holds it. So it is **set membership over two
independent downward closures**, and neither side closes upwards.

### 2.4 A client's own roles, and whose

`capp` issuing, user holding `capp-own`, `co1` and `co2`, nothing mapped:

```
  resource_access {"capp":{"roles":["capp-own"]}}
```

`cother` issuing, same user, `cother` also `fullScopeAllowed: false` with
nothing mapped:

```
  resource_access {"cother":{"roles":["co1","co2"]}}
```

Symmetric. The clause is **the issuing client's own roles**, not every client's,
and the pair is what says so - either half alone is consistent with "a client
role is always in scope".

### 2.5 A client scope, on all four cells

A client scope carrying a scope mapping to `rr2`, which the user holds:

```
  the scope exists, attached to nothing         realm_access ABSENT
  attached to capp as a DEFAULT scope           realm_access {"roles":["rr2"]}
  attached as OPTIONAL, scope=openid            realm_access ABSENT
  attached as OPTIONAL, scope=openid f192-default   realm_access {"roles":["rr2"]}
```

So neither the attachment alone nor the request alone is enough: an optional
scope contributes exactly when the granted scope names it. A client role mapped
into the same client scope reaches `resource_access` and moves `aud` the same
way a directly mapped one does.

**And with that scope attached, the client's own three scope-mapping reads say
nothing about it:**

```
GET .../clients/{capp}/scope-mappings                {}
GET .../clients/{capp}/scope-mappings/realm          []
GET .../clients/{capp}/scope-mappings/realm/composite []
                              while the token carries rr2
```

That is the sharpest instance of AGENTS.md's rule that the three reads
measurably disagree with each other, and it is the one that decides where the
issuer's rule comes from - section 3.

### 2.6 `include.in.token.scope` gates the spelling, not the mapping

One client scope, one client, the attribute flipped and nothing else:

```
  "true"    scope "openid profile f192-default email"   realm_access {"roles":["rr2"]}
  "false"   scope "openid profile email"                realm_access {"roles":["rr2"]}
```

Measured because a flag that gated the mapping too would have made the fixture in
section 6 measure the wrong thing. It does not; it decides only whether the
scope's name is written into the `scope` claim.

### 2.7 Where else the filter reaches

```
refresh grant           the same filtered set, on both clients
client_credentials      the service account's own roles, filtered - a service
                        account holding rr1 (unmapped) gets realm_access ABSENT
                        and one holding rr2 (in scope through the client scope)
                        gets {"roles":["rr2"]}
introspection           the filtered set - section 4
userinfo                **no roles at all**, on both clients. Six keys - sub,
                        email_verified, name, preferred_username, given_name,
                        family_name - identical for capp and cfull. So userinfo
                        is not a second observable and no case is needed.
id_token                seventeen keys, no realm_access and no resource_access on
                        either client. Not an observable either.
```

## 3. Does the evaluator's rule agree with the issuer's?

**Yes, and it was proved by measurement rather than by reading the code**, which
is what AGENTS.md asks for - it records that three scope-mapping reads disagree
with each other on this very flag, so the evaluator being next door was never
evidence.

On every probe in section 2 the scope evaluator's two reads were taken beside
the real password grant:

```
                                   granted(realm)        example access token
child mapped, user holds parent    ["rrchild"]           realm_access {"roles":["rrchild"]}
parent mapped, user holds parent   ["rrchild","rrparent"] realm_access {"roles":["rrparent","rrchild"]}
client scope attached              ["rr2"]               realm_access {"roles":["rr2"]}
```

and the real token's `realm_access` and `resource_access` matched the example
token's on all three, including `resource_access {"capp":{"roles":["capp-own"]}}`
under every one. The only difference between the two bodies is the `scope`
claim - `profile email` against `openid profile email` - because the evaluator's
request names no `openid`, which is not a role rule.

**The three scope-mapping reads do not agree**, and section 2.5 is the
counterexample: with a client scope attached, all three answer empty while the
token and the evaluator both answer `rr2`. So the evaluator has the input the
reads do not, and the issuer has it too.

That is why `roles.InScope` has four callers and `hasScope` in
`internal/admin/scopemappings.go` is deliberately **not** one of them. Merging
them is the tidy-up that makes three reads agree where Keycloak disagrees with
itself, which AGENTS.md names by that description.

## 4. Which client's filter introspection applies

Not the caller's. Measured with `cother` - itself `fullScopeAllowed: false` with
nothing mapped, so its own token carries no `realm_access` at all - introspecting
a token minted by `capp`:

```
POST /realms/f192/protocol/openid-connect/token/introspect   (as cother)
  active          true
  aud             "cother"
  realm_access    {"roles":["rr2"]}
  resource_access {"capp":{"roles":["capp-own"]},"cother":{"roles":["co2"]}}
```

`rr2` is in `capp`'s scope and in nothing of `cother`'s. So the filter belongs to
the client named by the subject token's `azp`. Passing the caller is the obvious
implementation and it is wrong on exactly the tokens this endpoint exists to
describe - and it is wrong in the permissive direction.

## 5. The account gate, and the half F192 did not name

F192 says the account case is "a defect in `internal/oidc`'s token path rather
than in this package". **Fixing `internal/oidc` alone does not move it**, because
`internal/account`'s `resolve` calls `roles.Effective` on the session's user and
never looks at the token's claims. The token got right and the gate stayed
permissive.

The chapter's existing evidence could not have caught that, and the reason is
worth writing down. Its pair is:

```
admin-cli token,               user holding account roles   200
fullScopeAllowed=false client, user holding account roles   401
```

Those two clients differ in **two** things - the flag and
`client.use.lightweight.access.token.enabled` - so a gate reading `aud` is
consistent with both rows. The discriminating pair holds the second variable
still:

```
lw-full    fullScopeAllowed=true,  lightweight   200   aud null realm_access null resource_access null
lw-nofull  fullScopeAllowed=false, lightweight   401   aud null realm_access null resource_access null
heavy-full fullScopeAllowed=true,  ordinary      200   aud ["capp","account","cother"] ...
```

**The two lightweight tokens carry the identical eight keys** - `exp`, `iat`,
`jti`, `iss`, `typ`, `azp`, `sid`, `scope` - and answer 200 and 401. There is no
byte in either token an implementation could read. The gate recomputes the
granted scope server-side, and that is now a case:
`account/gate/scope-filtered-lightweight`.

## 6. What was built

### 6.1 `internal/roles` grew two functions and the boundary argument for them

`ScopesInEffect` and `InScope`, with four callers between them: issuance,
introspection, the account gate and the admin evaluator.

The alternative was a copy in `internal/oidc`, and it was rejected on F148's
argument rather than on taste: `internal/roles`'s own package comment already
says *"Two copies of the expansion would be two chances to disagree about who is
an administrator"*, and this is the same walk over a different set. The boundary
table says `internal/roles` must not "decide who may do what"; a scope mapping
grants nothing and is not an escalation surface - AGENTS.md says so in the scope
mappings section - so the set computation is inside the line and `mayMapRole`
and `mayGrantRole`, which do decide it, stay in `internal/admin`.

`internal/admin`'s `evaluatedScopePredicate` and `evaluatedScopes` are now three
lines each, delegating. **Their measured doc comments stay where they are**: the
comments are about the endpoint, and the shared function's comment is about the
rule.

### 6.2 The corpus problem, and the fixture that answers it

`POST /clients` defaults `fullScopeAllowed` to **true**, `internal/bootstrap`
sets it on the two clients that carry it, and `internal/oidc/registration.go`
sets it on every dynamically registered client. So **before this cut, no client
in the catalogue had the flag off except one**, and that one's case was
`Recorded`. A filter that works and a filter that is never reached produce the
same goldens.

`introspect-scope-filtered` is the corpus that separates them, and introspection
is the only endpoint that can hold it: a token's decoded claims are `Volatile` in
every golden that carries one, and this endpoint serves the access token's claim
set as an ordinary JSON body that is compared byte for byte.

The subject holds nine roles and the token carries five:

| role | held | in scope how | in token |
|---|---|---|---|
| `-own` | yes | the issuer's **own** role, never mapped | yes |
| `-peer-role` | yes | mapped into the issuer's scope by name | yes |
| `-user-child` | yes | reached by expanding the user's parent; mapped directly | yes |
| `-user-parent` | yes | nothing maps it | **no** |
| `-scope-child` | yes | reached by expanding the scope's mapped parent | yes |
| `-scoped` | yes | mapped into an attached client scope | yes |
| `default-roles-master`, `offline_access`, `uma_authorization` | yes | nothing maps them | **no** |
| `account`'s three roles | yes | nothing maps them | **no** |

and the recorded body is

```
"aud":"gloak-probe-narrow-peer"
"realm_access":{"roles":["gloak-probe-narrow-scope-child",
                         "gloak-probe-narrow-scoped",
                         "gloak-probe-narrow-user-child"]}
"resource_access":{"gloak-probe-narrow-issuer":{"roles":["gloak-probe-narrow-own"]},
                   "gloak-probe-narrow-peer":{"roles":["gloak-probe-narrow-peer-role"]}}
```

Seven separate mistakes each lose or gain a byte of it, and section 7 fires each
one.

**The introspecting client's own flag is on**, so the body also pins section 4:
reading the caller's `fullScopeAllowed` answers every role the subject holds.

## 7. The record diff, read file by file

`make record` on the branch, log preserved. **1071 goldens rewritten, 1069 of
them byte-identical to `main`, two added and none modified.**

It was run twice. The second run is on the branch head after every commit below,
and its whole result is `git status --short` printing nothing: 1071 rewritten, 11
Pending left alone, 4 cases skipped for want of a fixture, and **not one byte
different from what is committed**. That is the property this section is really
about - the goldens in the tree are what a single `make record` produces on this
source, rather than what a sequence of partial runs accumulated.

```
git diff --name-status 1d2ac8d HEAD -- internal/conformance/testdata/golden/
A  account/gate/scope-filtered-lightweight.http
A  oidc/introspection/scope-filtered-access-token.http
```

The accounting is complete rather than asserted. 1072 golden files exist and
1071 were rewritten; the one that was not is
`admin/realms-admin/partial-export-clients.http`, the single parked `Pending`
golden AGENTS.md declares, which the recorder is required to leave alone.

Per file:

- **`account/gate/scope-filtered-lightweight.http`** - new. 401
  `{"error":"HTTP 401 Unauthorized"}` with five headers, byte-identical to the
  chapter's other 401s. It moved because it did not exist: it is Keycloak's
  answer for a lightweight client with the flag off, and section 5 is the
  measurement.
- **`oidc/introspection/scope-filtered-access-token.http`** - new. The filtered
  claim set in section 6.2, and every byte of it is Keycloak's. It was recorded
  three times and only the third is committed; sections 7.1 and 7.2 say why,
  because both intermediate failures were the harness refusing something and
  both are findings.
- **Everything else** - unmoved, and the reason is worth stating exactly,
  because "nothing moved" is easy to read as "nothing was at risk".

**`make record` re-measures Keycloak, not Gloak.** A change to Gloak's handlers
cannot move a golden; only a changed fixture or a changed case can. So the empty
diff is evidence about the *fixtures* - that `introspect-scope-filtered` created
two clients, five realm roles, two client roles, a client scope and a user in
**master**, on the shared container, ahead of most of the admin chapter, and
polluted nothing - and it is **not** evidence that the handler change is safe.

The evidence for the handler change is a different test. `TestConformance`
serves all 1071 from Gloak and compares them, and it is green: the run is in
section 11. That is the number the blast-radius question actually asks about,
and reading the record diff cannot answer it.

One fixture was refactored rather than added -
`accountScopeFilteredFixture` became a call into `accountNarrowClientFixture` -
and its golden is one of the 1069 that did not move, which is the check that the
refactor changed no byte the recorder sends: the same `clientId`, the same
derived username `gloak-probe-account-narrow-user`, the same create body.

### 7.1 The recorder refused a mask, and the refusal is a rule

The first recording of the introspection case failed with

```
normalize: conformance: sort unordered: value at this path is not an array:
"gloak-probe-narrow-peer"
```

`Unordered: ["aud"]` was copied from the two sibling cases, whose `aud` is an
array. Here the scope admits one client, so `aud` takes the measured
absent/string/array rule's middle case and is a **bare string** - which is
itself the filter's second observable, section 2.2.

**A mask cannot be copied from a neighbour on the assumption the shape
matches**: the harness refuses it at record time and writes nothing. That is
stronger than the inert-mask ratchets, which run afterwards over what was
written.

### 7.2 And a second mask, for the opposite reason

With `aud` dropped, `TestNoMaskIsInertOnItsGolden` refused
`resource_access/*/roles`: each of the two clients has exactly one role in
scope, so sorting is the identity. It is gone, and **both role lists under
`resource_access` are now asserted in full** - which is stronger than either
sibling case and is what makes the own-roles clause and the mapped-client-role
clause separately refutable.

Two guards, in one case, each rejecting a mask taken from the neighbours.

## 8. The mutation pass

The harness is `/tmp/f192/mutate.sh` and its order is the point: refuse an empty
diff, refuse a build failure, **read `go test`'s exit code before looking at any
output**, revert, and verify the revert restored the byte-identical file. Both
refusals were self-tested against deliberate controls before any real mutation
ran - a no-op substitution is `REFUSED: the diff is empty` and a typo'd field is
`REFUSED: does not build`.

Every mutation names the test that kills it.

| # | mutation | verdict | killed by |
|---|---|---|---|
| A1 | `if c.FullScopeAllowed` → `if false`: the flag is ignored and the filter always applies | killed | `TestConformance/oidc/introspection/active-access-token` |
| A2 | → `if true`: never filter, which is the pre-F192 behaviour | killed | `TestConformance/oidc/introspection/scope-filtered-access-token` |
| A3 | drop the own-roles clause | killed | same |
| A4 | drop the client-scope clause | killed | same |
| A5 | no composite expansion on the scope side | killed | same |
| A7 | `ScopesInEffect` drops the client's default scopes | killed | same |
| A8 | `ScopesInEffect` drops the optional half | killed | `internal/admin`'s `TestEvaluatedScopeReadsTheLinkedClientScopesMappings` |
| A9 | every optional scope in scope always - the permissive half | killed | `TestTokenRolesReadsTheGrantedScopeForOptionalClientScopes` |
| B1 | the issuer's predicate is always true | killed | `TestConformance/oidc/introspection/scope-filtered-access-token` |
| C1 | introspection reads the **caller's** `fullScopeAllowed` | killed | same |
| D1 | the account gate does not filter | killed | `TestConformance/account/gate/scope-filtered-token` |
| D1b | the same | killed | `TestConformance/account/gate/scope-filtered-lightweight` |
| E1 | the admin evaluator's predicate is always true | killed | `TestConformance/admin/clients/evaluate-scope-mappings-not-granted` **and** `.../evaluate-example-access-token` |
| E2 | the admin evaluator sees no client scopes | killed | `TestConformance/admin/clients/evaluate-protocol-mappers` |
| G1 | the account gate reads a fixed client, not `azp` | killed | `TestConformance/account/gate/scope-filtered-token` |
| H1 | `ScopesInEffect` swaps default for optional | killed | `TestConformance/oidc/introspection/scope-filtered-access-token` |
| I1 | `roles.Filter` keeps nothing | killed | same |
| J1 | the issuer ignores the granted scope | **survived, then closed** - 8.2 | `TestTokenRolesReadsTheGrantedScopeForOptionalClientScopes` |
| L1 | the account gate falls open on an unknown `azp` | **survived, then closed** - 8.3 | `TestGrantedRolesRefusesATokenWhoseClientIsGone` |
| M1 | `InScope` matches by **name**, not id - F32's shape | killed | `TestConformance/oidc/introspection/scope-filtered-access-token` |
| N1 | introspection falls back to the caller when `azp` is gone | **survivor** - 8.4 | nothing |

### 8.1 The corpus problem, demonstrated rather than asserted

A2 is the whole cut inverted - the filter never runs - and **before this branch
nothing in the tree would have caught it.** Every client the catalogue creates
carries the flag on, the two bootstrapped clients that carry it are lightweight,
and the one client with it off had a `Recorded` case, which is required *not* to
match. `oidc/introspection/scope-filtered-access-token` is what kills A2, and it
did not exist on `main`.

E1 is the same shape one chapter over and it is worth reading carefully. The
first run named `admin/clients/evaluate-scope-mappings-granted` and reported a
**survivor**. It is not one: that case asks about the client's **own**
container, where every role is in scope through the own-roles clause, so an
always-true predicate answers the identical eight roles. Its `not-granted`
sibling, asked about the realm container, is what guards the predicate. One
family, two cases, and only one of them can fail.

### 8.2 J1, and why the survivor was real before it was closed

`internal/oidc`'s `tokenRoles` passes the granted scope to `ScopesInEffect`, and
replacing it with `""` **survived the entire tree** - `CGO_ENABLED=0 go test
./...`, not one package.

That is not a hole in this rule. It is F16 showing through: `grantedScope` is a
constant, so an optional client scope's name can never reach the function
through an HTTP request, and no case can be written that would. A8 dies because
`internal/admin`'s evaluator *does* honour `?scope=` and has its own package
test for it; the protocol path has no equivalent.

Closed with `TestTokenRolesReadsTheGrantedScopeForOptionalClientScopes`, at the
seam rather than through a request, which is strictly weaker than a golden and
strictly stronger than the prose it replaces - `TestKeystoreDownloadHeaders`
makes the same trade for the same reason. **Both directions are asserted**: A9,
which puts every optional scope in scope always, is the permissive half and a
test checking only the naming case passes it.

### 8.3 L1, and a fall-open branch that is reachable

`grantedRoles` returns no roles when the token's `azp` names no client of the
realm, so the gate refuses. Flipping it to return the user's whole role set
**survived the whole tree.**

The state is not hypothetical. `client_session` cascades when a client is
deleted and `user_session` does not - `0003_session.sql` - so a token minted by
a deleted client still verifies, still resolves to a live user session, and
reaches this branch. With the mutation applied it opens the account API to that
token.

Closed with `TestGrantedRolesRefusesATokenWhoseClientIsGone`, which has the
control beside it: the same user through a client that **does** exist answers the
account roles, so the refusal is a statement about the missing client rather
than about the user. It needed the first handler builder this package has had.

### 8.4 N1 is a survivor, and it is left as one

`internal/oidc`'s introspection answers the inactive body when the subject
token's `azp` names no client, and falling back to the caller's client survives
`TestConformance/oidc/introspection`. It is L1's shape on the neighbouring
surface and it is **not** closed here, for two reasons: the direction chosen is
the conservative one, and introspection reports rather than authorises - the
worst case is a slightly wrong role set handed to a caller already inside the
token's audience, where L1's worst case was an open gate.

The cell is unmeasured against Keycloak - no probe was sent - which is F197, and
the code comment says so at the branch.

### 8.5 The harness manufactured one false kill, and the brief predicted it

N1's first run used `-run '.'` over `./...` and reported **killed by
`TestCodeGrantCarriesTheAuthorizationRequest`**. That test has nothing to do
with introspection. Its assertion is

```
auth_time 1.788881285e+09 and iat 1.788881286e+09 disagree on a login redeemed at once
```

a login and a redemption straddling a **second boundary**. It is a pre-existing
flake in a file this cut does not otherwise touch, and it was the difference
between a survivor and a kill.

Exit-code-first is necessary and not sufficient. **Naming the test is what
catches this**, and it is the same discipline that turned E1's false survivor
into a kill in the opposite direction: an unnamed run can invent a kill, and a
wrongly named one can invent a survivor. Both happened in this pass.

The flake is fixed - one second of slack, with a gap of two or more still
failing, so the six-second case the comment contrasts with is still caught. The
test cannot pin the clock because `writeTokens` builds its own `token.Issuer`
and nothing threads a `Now` into it. F199.

## 9. The Admin API is scope-filtered too, and this cut does not serve it

The same discriminator, on the surface nobody asked about. Two lightweight
clients in **master** differing only in the flag, the bootstrapped administrator
logging in through each:

```
                          GET /admin/realms/master   GET /admin/realms/master/users
f192-admin-full  (on)     200                        200
f192-admin-narrow (off)   403                        403
```

and the refusal is the generic `{"error":"HTTP 403 Forbidden"}`. **The realm is
resolved first**: `GET /admin/realms/nosuchrealm` answers
`{"error":"Realm not found."}` for both tokens, so the scope check sits behind
the realm and in front of the role. `GET /admin/realms` and `GET /admin/serverinfo`
are 403 as well.

Gloak's `internal/admin/auth.go` resolves the caller's roles with
`roles.Effective` and applies no filter, so **Gloak answers 200 to all three**.
It is the same defect as F192 on a larger surface and in the same permissive
direction.

It is **not fixed here**, and the reason is the one AGENTS.md names about fixing
a general rule inside a family branch. Serving it needs its own cut:

- the corpus problem again, one chapter over. Every admin fixture authenticates
  through `admin-cli`, whose flag is on, so the filter would change no golden and
  the cut would have no evidence it works. It needs an admin fixture with a
  flag-off client and a golden that moves, exactly as section 6.2 needed one;
- the guard order is measured above for three routes and not for the family. The
  Admin API has a coarse gate, a container resolution and a fine check per
  family, and where the scope check sits relative to each is three more probes;
- **the cross-realm cell is unmeasured.** AGENTS.md records that a request to
  `/admin/realms/{realm}` may carry a token from that realm or from master. Which
  realm's client the filter reads, and what a master token with the flag off
  answers for another realm, is the probe nobody has sent.

F198.

## 10. What belongs in AGENTS.md

Phrased as it would be folded, under "Things that look like bugs and are not".

- **`fullScopeAllowed` is a filter on the roles that reach a token, and it
  reaches four observables rather than one.** `realm_access`, `resource_access`,
  `aud` and the refresh token's `aud_x` - the last two because the audience is
  computed from the client roles, so a scope mapping moves `aud` from absent to
  a bare string. `userinfo` and the ID token carry no roles at all and are
  unaffected, measured on two clients differing only in the flag.
- **The rule has three clauses and the third is the one the scope-mapping reads
  do not have.** A client's own roles are in its own scope without ever being
  mapped - the *issuing* client's, measured symmetrically on two clients - and
  the scope mappings of every **granted** client scope contribute. With a client
  scope attached, `.../scope-mappings`, `.../realm` and `.../realm/composite` on
  the client all answer empty while the token carries the role. So the issuer's
  rule is the **scope evaluator's** and not the scope-mapping family's, measured
  by taking `granted` and `generate-example-access-token` beside a real password
  grant on every probe.
- **A granted client scope is the default ones plus the optional ones the
  request names.** Four cells, all measured: unattached contributes nothing,
  default contributes, optional-and-unnamed contributes nothing,
  optional-and-named contributes. `include.in.token.scope` decides only whether
  the scope's name is written into the `scope` claim and does **not** gate the
  mapping, measured both ways on one client.
- **The subject's roles are expanded first and the filter runs per role, and the
  scope side is a second, independent closure.** A user holding a composite
  parent and not its child, with the child alone mapped, gets the child - which
  filter-then-expand cannot produce. Mapping the parent alone puts both in scope.
  Neither closure runs upwards: with the child mapped, the parent the user holds
  stays out.
- **Introspection applies the filter of the client named by the subject token's
  `azp`, not the caller's.** Measured with a caller whose own scope holds none of
  what came back.
- **The account API's gate reads the granted role set and no byte of the token,
  and the pair that says so is two lightweight clients differing only in the
  flag.** Their tokens carry the identical eight keys - no `aud`, no
  `realm_access`, no `resource_access` - and answer 200 and 401. The chapter's
  older pair also differed in the lightweight attribute, so it was one variable
  short of this.
- **The Admin API is scope-filtered as well, and Gloak is not.** A flag-off
  client's token is 403 on `/admin/realms/{realm}`, `/admin/realms` and
  `/admin/serverinfo` with the generic `HTTP 403 Forbidden`, behind the realm
  resolution - an unknown realm is still `Realm not found.` Gloak answers 200.
  See F198.
- **`Case.Unordered` on a path whose value is not an array is a hard failure at
  record time**, not a no-op: `normalize: sort unordered: value at this path is
  not an array`. So a mask cannot be copied from a neighbouring case on the
  assumption the shape matches - which is a stronger guarantee than the
  inert-mask ratchets give, and it is how `aud`'s bare-string form was noticed
  here.

## 11. Follow-ups

**F196: token exchange's scope filter is the requesting client's, and it is
unmeasured.** `internal/oidc/tokenexchange.go` mints a new token for the
requesting client and passes that client's `fullScopeAllowed`, which is the only
reading consistent with "the token is for this client". A default 26.7.1 does
not enable the token-exchange feature, so the container cannot answer and no
probe was sent. The entry is the request to send: enable
`token-exchange`, exchange a token from a full-scope client at a flag-off one
and back, and read `realm_access` on both.

**F197: introspection's unknown-`azp` cell is unmeasured, and its branch is a
mutation survivor.** When a subject token's `azp` names no client of the realm,
`internal/oidc` answers the inactive body - the conservative direction, chosen
without a measurement. The state is reachable in Gloak, since `client_session`
cascades on a client delete and `user_session` does not. The probe: mint a token
at a client, introspect it once from a client in its audience, delete the issuing
client, introspect again. N1 in section 8.4 is the survivor; a case cannot be
written until the answer is known.

**F198: the Admin API is scope-filtered and Gloak is not.** Section 9 is the
measurement and the reason this cut does not serve it. It needs its own corpus -
every admin fixture authenticates through `admin-cli`, whose flag is on - and
three probes it does not have: where the check sits in each family's guard
order, and what a master token with the flag off answers for another realm.
**This is the largest remaining instance of F192's defect** and it is on the
surface that matters most.

**F199: `internal/oidc`'s browser-flow tests cannot pin the clock.**
`TestCodeGrantCarriesTheAuthorizationRequest` compared `auth_time` to `iat` for
equality and flaked on a second boundary, manufacturing a false mutation kill -
section 8.5. It now takes one second of slack, which is a workaround: the real
fix is a `Now` threaded into the `token.Issuer` that `writeTokens` builds, which
would let the assertion be exact. Any other wall-clock assertion in that file is
in the same position and nobody has swept for them.

**F200: `Case.Unordered` and `Case.Volatile` have no static check against the
golden's shape.** Section 7.1: a mask on a path whose value is not an array is a
record-time failure with no golden written, and it was found by running the
recorder rather than by any test. `TestCatalogIsWellFormed` could refuse it
against the committed golden without a container, the way
`TestNoMaskIsInertOnItsGolden` already reads them. The entry is that the check is
cheap and the failure it prevents costs a container start.

**F201: the account chapter's gate now has two pairs and only one is minimal.**
`account/gate/lowercase-scheme` and `account/gate/scope-filtered-token` differ in
two variables and `scope-filtered-lightweight` holds one of them still - section
5. The older pair is not wrong, but it is the shape AGENTS.md warns about, and
the chapter has other two-variable pairs nobody has audited. The entry is to
sweep them rather than to change this one.

## 12. Parity

`make conformance`, reproduced by hand with `cmd/parity` between `1d2ac8d` and
the branch head:

```
Parity: 567 -> 570 of 622 (+3)

chapter                         before  after  delta
account/gate                        13     15     +2
oidc/introspection                   5      6     +1
```

The base is the brief's **567 of 620, 2 chapters not enumerated**, and it
reproduces exactly. Three behaviours served and two added to the denominator:

- `account/gate/scope-filtered-token` promoted from `Recorded` to `Implemented`,
  which moves the numerator and not the denominator - F192 closed;
- `account/gate/scope-filtered-lightweight`, new and `Implemented`;
- `oidc/introspection/scope-filtered-access-token`, new and `Implemented`.

**The total did not fall and no case that was `Implemented` stopped matching.**
`CGO_ENABLED=0 go test ./...` is green over the whole tree, which is the number
section 7 says the record diff cannot answer: all 1071 comparable goldens are
served from Gloak and compared, including the 1069 that did not move.

`make lint` is clean, both invocations, `gofmt` included.
