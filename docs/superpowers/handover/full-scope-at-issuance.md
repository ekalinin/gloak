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
answers 403. Section 8 is that measurement and F198 is the entry.

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

## 7. The mutation pass

*(filled in below)*

## 8. The Admin API is scope-filtered too, and this cut does not serve it

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

## 9. What belongs in AGENTS.md

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

## 10. Follow-ups

*(numbered from F196; F171-F195 are taken)*

## 11. Parity

*(filled in below)*
