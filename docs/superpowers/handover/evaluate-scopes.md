# The `evaluate-scopes` family

Seven operations under `Clients`, computed from the vendored description rather
than taken on trust, and confirmed: a filter over `paths` for `evaluate-scopes`
in `internal/conformance/testdata/openapi/keycloak-26.7.1.json` yields exactly
the seven the brief lists, all `GET`, all tagged `Clients`.

Five are served. Two are `Pending`, both for boundary reasons rather than for
effort, and both reasons are measured rather than argued.

Everything below was measured against a live Keycloak 26.7.1 on `localhost:8170`
on 2026-09-05. The plan is
`docs/superpowers/plans/2026-09-03-evaluate-scopes.md`.

## 1. Measurements

### The whole family answers whatever the client's protocol is

**`generate-example-saml-response` is not gated by the client's protocol.** An
`openid-connect` client answers it with a real SAML `<samlp:Response>`, and a
`saml` client answers the three OIDC generators with token-shaped bodies. The
protocol decides the *content* and never whether the route answers. This is the
first thing to know about the operation and it inverts the question the brief
asked - the operation is buildable in the sense that every client can be asked,
and unbuildable for reasons that have nothing to do with the protocol.

The two protocols' bodies differ a great deal. A SAML client's example access
token is eight claims - `exp, iat, jti, iss, typ, azp, sid, scope` - with **no
`sub`, no `acr`, no `resource_access` and no `preferred_username`**, because a
SAML client carries none of the client scopes whose mappers write them. Its
userinfo is `{"sub":"…"}` alone. That is the mapper model showing through, and
it is what makes the claim set a function of the client rather than a struct.

### The four `generate-example-*` bodies, and every per-request value

Measured on `master`, client `account`, user `admin`:

```
access token
{"exp":…,"iat":…,"jti":"onrtna:…","iss":"…","sub":"…","typ":"Bearer","azp":"account",
 "sid":"wf6Mmr1H3-bYD-kwD1aQi3Jm","acr":"1",
 "resource_access":{"account":{"roles":["manage-account","manage-account-links","view-profile"]}},
 "scope":"email profile","email_verified":false,"preferred_username":"admin"}

id token
{"exp":…,"iat":…,"jti":"54fe97e7-…","iss":"…","aud":"account","sub":"…","typ":"ID",
 "azp":"account","sid":"…","acr":"1","email_verified":false,"preferred_username":"admin"}

userinfo
{"sub":"…","email_verified":false,"preferred_username":"admin"}

saml response
a JSON *string* at the root, holding a 1485-byte <samlp:Response>
```

**Four values move between two identical requests to the two token
generators**, and no more: `exp`, `iat`, `jti` and `sid`. Three notes on them:

- `exp - iat` is the **realm's** access token lifespan - 60 on master, 300 on a
  created realm. It is not a constant of the endpoint.
- The access token's `jti` carries the grant prefix **`onrtna:`**, which is not
  one of F86's four. The ID token's `jti` carries **no prefix at all**.
- `sid` is a fresh 24-character session id **naming a session that does not
  exist**. The endpoint mints a throwaway one per request.

**`generate-example-userinfo` carries no per-request value at all** - the one
body in the family whose golden could be unmasked.

**The SAML response is a different order of problem.** Two `ID="ID_<uuid>"`
attributes, an `IssueInstant` on the response and another on the assertion
**measured two milliseconds apart inside one response**, `NotBefore`,
`NotOnOrAfter` twice and `SubjectConfirmationData/@NotOnOrAfter`; on a SAML
client also `AuthnInstant`, `SessionNotOnOrAfter` and a `SessionIndex` holding a
session id, plus an `AttributeStatement` whose role order is a Java set's.

### The parameters

| parameter | measured |
|---|---|
| absent `userId` | 404 `{"error":"No userId provided"}` on all four generators |
| unknown `userId` | 404 `{"error":"No user found"}` |
| `scope=<an optional client scope>` | adds that scope's mappers, its scope mappings and its name in the `scope` claim |
| `scope=nosuchscope` | **200**, byte-identical to the plain answer |
| `audience=<a client in the token's own aud>` | **200** |
| `audience=<the asking client itself>` | 404 `Requested audience not available: <name>` |
| `audience=<a resolvable client out of scope>` | 404, same sentence |
| `audience=<a client that does not exist>` | **200**, silently ignored |

The audience pair is the one to read twice: an audience naming a client that
**does not exist** is dropped, and one naming a client that does but is out of
scope is a 404. The positive case was measured rather than inferred - a second
client whose role the user holds and whose role is mapped into the asking
client's scope answers 200, and it is exactly the value the token's own `aud`
already carries.

### `granted` is not `.../scope-mappings/realm/composite`, and that was measured

The neighbouring family is a hypothesis. On a purpose-built client with
`fullScopeAllowed` off, one realm role mapped directly and composite over a
second, and a **linked default client scope** carrying a scope mapping to a
third:

```
evaluate-scopes/scope-mappings/{realm}/granted   r1, r2, r3
scope-mappings/realm/composite                   r1, r2
scope-mappings/realm                             r1
```

The third arrives through the linked client scope's own scope mappings, which
the neighbour does not read, and `scope=<an optional scope>` adds a fourth. Two
inputs `hasScope` has none of. Pointing `compositeRealmScopeMappings` at this
route would have been wrong on both.

`not-granted` is the exact complement over the container's roles, measured on
both containers of a client holding some of each.

### `roleContainerId` takes two spellings and neither is the obvious one

The realm's **name** and a client's **UUID**. The realm's own **id** - which is
what every realm role's `containerId` carries - is a 404, and a client's
**clientId** is a 404 too. An unknown container is
404 `{"error":"Role Container not found"}`.

### `protocol-mappers`

Every mapper of every evaluated client scope, then the client's own. On
`account`, 23 rows. A client's own mapper carries `containerType:"client"` and
**`containerName:""`** - an empty string, measured by putting a `name` on the
client and re-reading, so it is not a fallback that happened not to fire.

### The guards: two shapes, and one of them is a conjunction

Swept one role at a time over eleven single `master-realm` admin roles plus a
caller holding nothing, with `GET /admin/realms/master/clients` as a control
known to differ.

```
                       CONTROL   the three reads   the four generators
view-clients             200          200                 403
manage-clients           200          200                 403
query-clients            200          403                 403
every other single role  403          403                 403
```

**The four generators refuse every single role there is.** A conjunction sweep
followed:

```
view-clients  + view-users     200      manage-clients + view-users    200
view-clients  + manage-users   200      manage-clients + manage-users  200
view-clients  + query-users    403      query-clients  + view-users    403
view-clients  + impersonation  403      view-clients   + view-realm    403
```

A client-read role **and** a user-read role, held together, with neither
family's `query-` role opening its half.

The resolution order, from varying which id is bad against four callers:

```
realm            404 "Realm not found." to everybody, a caller with nothing included
coarse gate      403 to a caller holding no clients role, even for an unknown client
client           404 "Could not find client" - query-clients gets this
fine role check  403 to query-clients for a container that does not exist
userId presence  404 "No userId provided" to a view-clients caller holding no user role
user-read role   403 {"error":"You have no access to this user"}
user             404 "No user found"
```

### Headers, and the wrong verbs

All seven 200s: `application/json;charset=UTF-8`, `Cache-Control: no-cache`, all
five security headers. All eight measured refusals: plain `application/json`, no
`Cache-Control`, all five. Nothing here contradicts what is written down.

`POST`, `PUT`, `DELETE` and `PATCH` on `.../evaluate-scopes/protocol-mappers`
all answer a **real 405** `{"error":"HTTP 405 Method Not Allowed"}`. Gloak sends
404. Recorded, not changed - see F31.

### `javamap.KeyOrder` places one of these two listings and not the other

A finding rather than a change. `not-granted`'s five realm roles came back
`create-realm, default-roles-master, offline_access, admin, uma_authorization`,
which is **exactly** `javamap.KeyOrder`'s answer for that set and is not sorted
order. The same function on `granted`'s eight `account` roles answers a
different order from Keycloak's. One hit, one miss, on two bodies from one
route family measured minutes apart - which is why nothing was changed on the
strength of the hit and both cases keep `Unordered`. The masks say so in the
case comments rather than reading as "this varies".

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **The scope evaluator answers for a client of either protocol, and only the
  body changes.** `generate-example-saml-response` on an `openid-connect`
  client returns a real SAML assertion, and the three OIDC generators on a
  `saml` client return token-shaped bodies - a SAML client's example access
  token is eight claims with no `sub`, no `acr`, no `resource_access` and no
  `preferred_username`, because it carries none of the scopes whose mappers
  write them. Refusing the mismatched protocol is the obvious implementation
  and it is wrong on four routes at once.

- **An `audience` naming a client that does not exist is ignored, and one
  naming a client that does is a 404.** Measured on five values against three
  clients: an audience in the token's own `aud` is 200, the asking client
  itself is `404 Requested audience not available: <name>`, a resolvable
  client out of scope is the same 404, and `audience=nosuchclient` is a **200**
  whose body is unchanged. Refusing what cannot be resolved is the defensive
  implementation and it is wrong on the only value of the four that succeeds.
  The same 404 is the first body in this API to **interpolate the request's own
  value into a not-found sentence**.

- **`roleContainerId` is the realm's name or a client's UUID, and the two
  neighbouring spellings are 404s.** The realm's own **id** does not resolve,
  although it is exactly what every realm role's `containerId` carries; a
  client's **clientId** does not resolve either. So the two values a reader
  would reach for first are the two that fail, and the 404 is
  `Role Container not found` - a spelling with a capital C in the middle and no
  full stop.

- **The scope evaluator's scope-mapping reads are not the scope-mapping
  family's with a prefix.** `evaluate-scopes/.../granted` reads the **linked
  client scopes' own scope mappings** and honours a `scope` parameter naming an
  optional one; `.../scope-mappings/realm/composite` reads neither. Measured on
  a client whose scope holds one role each way: the evaluator answered three
  roles where the neighbour answered two, and four with the parameter. Two
  inputs, one route family away, and reusing the neighbour's predicate loses
  both.

- **The scope evaluator has two guards and one of them is a conjunction.** The
  three reads take `view-clients` or `manage-clients` and refuse
  `query-clients`, which is the protocol mappers' pair. The **four generators
  refuse every single admin role there is** and need a client-read role and a
  user-read role held together - `query-clients` and `query-users` opening
  neither half. That is `/roles/{name}/users`' shape met on a second family.
  The generators' order has the `userId` **presence** check ahead of the
  user-read role, so a caller that may read clients and not users is told the
  parameter is missing rather than that it may not look; and the refusal that
  follows is its own sentence, `You have no access to this user`, rather than
  the generic 403.

- **An example token is minted for a session that does not exist.** `sid` is a
  fresh 24-character value on every request, `jti` carries the `onrtna:` grant
  prefix on the access token and **none at all** on the ID token, and the ID
  token carries **no `at_hash`** because there is no access token to hash -
  where every issued ID token carries one. `exp - iat` is the realm's lifespan
  rather than a constant. Four values move and nothing else does.

- **A client's own protocol mapper names an empty container.**
  `evaluate-scopes/protocol-mappers` gives a mapper attached to the client
  `containerType:"client"` and `containerName:""`, measured on a client
  carrying a `name`, so falling back to the name or the clientId is wrong.
  A client scope's mapper names the scope. The client's own come last.

- **Two more spellings of not-found, and one 404 that is not one.** The scope
  evaluator adds `Role Container not found` and `No user found` to the list,
  and `Requested audience not available: <name>` which interpolates. It also
  answers `No userId provided` with a **404** - a status about a missing
  request parameter rather than a missing resource, which is the first of its
  kind here.

- **`evaluate-scopes/protocol-mappers` answers all four wrong verbs a real
  405.** That is the client scopes' answer rather than the 404 the fallback
  produces, and it is another family for the list that bullet already keeps
  short of a rule. Gloak sends 404. See F31.

## 3. Follow-up dispositions

### F148 - closed in principle, and this cut is the working precedent

**The answer is shape 2, and F148's two `evaluate` operations take it too.**

The argument is not preference. `internal/token` already contains the
precedent, doing the same job, with its own reason written above it:

```go
// Introspection ... It lives beside the claim sets rather than in internal/oidc
// because that is what it is: the same claim set, one key order, changed in one
// place.
```

`Introspection` is an exported struct with an exported builder, whose caller
resolves the inputs and serves the result as an ordinary JSON body. An example
token is the third member of that family, not a new kind of thing, so the
"interface that exists only for this" the brief worried about does not exist:
`token.Request` already takes roles as arguments precisely because the package
signs claim sets and does not reach a store.

This cut adds `(*Issuer).ExampleAccessClaims` and `(*Issuer).ExampleIDClaims`
beside it, and `internal/admin` resolves the inputs. **An RPT is an access
token's claim set, so it is built in the same place**, and F148's cut inherits a
worked example rather than the question.

One thing this cut learned that F148's entry does not say: **shape 2 says where
the claim set is built and not that it can be built.** Two of the four
generators are refused for boundary reasons that survive the decision, and both
are recorded as `Pending` with the reason in the case:

- **`generate-example-userinfo`** is the userinfo document, whose one truth is
  `userinfoDocument` in `internal/oidc/userinfo.go`. This branch may not touch
  `internal/oidc`, so serving it here means declaring the shape a second time -
  shape 1 wearing a different hat, refused on F148's own grounds. It is one
  moved struct away on a branch allowed to make the move, and it is the
  cheapest operation left in this family: its body carries no per-request value
  at all.
- **`generate-example-saml-response`** is refused for three independent
  reasons, in §1 and in the case.

### F122 - not closed, and this cut says nothing new about it

Left where it is, deliberately. The two admin logout triggers are an
**outbound** mechanism whose machinery is `internal/oidc`'s, and this branch
may not touch that package. F122's own 2026-09-03 note already records the
boundary holding for `push-revocation` for exactly this reason, and nothing
measured here moves it: the scope evaluator makes no outbound call and ends no
session.

The one transferable thing is the shape of the argument. F122 and F148 read as
one question - "may `internal/admin` do this itself?" - and they have opposite
answers, because they are asking about different things. F148 is about a
**value** that already has one owner, so the answer is "call the owner". F122 is
about a **capability** that lives in another package with half a protocol
attached, so the answer is "move the owner, on its own branch". This cut is
evidence for the first and none for the second.

### F95 - untouched, and one measurement makes it slightly more urgent

`internal/admin` still marshals `model.Client.Attributes` as a Go map and this
cut did not move it: it lives in `clients.go` and moving it re-records five
goldens in a chapter this branch is not otherwise touching, which is F95's own
stated reason for staying open.

What is new is a data point for the ordering model underneath it.
`javamap.KeyOrder` places `not-granted`'s five-role realm set **exactly**, and
answers a different order from Keycloak's on `granted`'s eight-role client set,
on two bodies of one route family measured minutes apart. That is the same
"places some key sets and not others" the entry rests on, met on role name sets
rather than on attribute keys, and it is why both cases here keep `Unordered`
rather than asserting an order one measurement supports and the neighbouring one
refutes.

### F157 - untouched and unrelated, and worth saying why it was checked

`attack-detection` stores nothing because nothing counts a failed
authentication. The scope evaluator counts nothing, authenticates nobody and
mints no session that is stored, so it adds no writer to that record and closes
nothing. It was checked rather than assumed because the generators do mint a
session-shaped value: they do not persist it, so the entry is untouched.

## 4. Parity before and after

```
chapter          served  recorded  documented  source
admin/clients        23         1          35   before
admin/clients        28         1          35   after

total: 451 of 541 enumerated behaviours served   before
total: 456 of 541 enumerated behaviours served   after
```

Five operations, and the two that are not served are `Pending` rather than
absent, so the gap is on the record with its reason attached.

## 5. Lines in AGENTS.md or the observed document these measurements contradict

**None outright.** Three that need widening rather than correcting, and one that
was checked and holds:

1. **"`/roles/{name}/users` needs a conjunction … It is the only endpoint in the
   group that works this way."** The qualifier "in the group" saves it, but the
   sentence reads as a claim about the API. The four `generate-example-*`
   operations are a second family with the same shape, on a different pair of
   role families, and the organization chapter already records nineteen more.

2. **"Twenty-eight spellings of not-found in the admin API now."** Two more, and
   the list rather than the number is the answer: `Role Container not found`
   and `No user found`. A third, `Requested audience not available: <name>`,
   does not belong on that list as it stands - it **interpolates the request's
   own value**, which nothing already on it does.

3. **The 405 bullet's list of families.** `evaluate-scopes/protocol-mappers`
   answers all four wrong verbs a real 405, which is another member for a
   bullet that already says six data points do not make a rule.

4. **The charset and security-header rules hold exactly**, on seven 200s and
   eight refusals, including the four exceptions' predictions. Checked because
   the bullet records having been wrong five times, and it is right here.

The observed document says nothing about this family at all, so there is nothing
in it to contradict.

## 6. What is left undone

- `generate-example-userinfo`, waiting on one struct moving out of
  `internal/oidc`. Its body is measured and in the case.
- `generate-example-saml-response`, waiting on a SAML issuance path and on a
  mask that can reach inside a JSON string. Neither is close.
- **The claim sets are the issuance path's, which is P5's gap reached through a
  new door.** A user carrying a `firstName`, `lastName` or `email` gets
  `name`, `given_name`, `family_name` and `email` from Keycloak's `profile` and
  `email` mappers, and Gloak's `accessClaims` has no such fields - so the
  preview is wrong for that user in exactly the way Gloak's **issued** token
  already is. That is deliberate: a preview that disagreed with the tokens the
  server issues would be worse than one that agrees. The conformance cases
  address the default install's own `account`/`admin` pair, where the two claim
  sets are measured identical.
- `granted`'s eight-role order is unexplained by anything in the repository.
  The measurement is in §1 for whoever takes `javamap` next.
