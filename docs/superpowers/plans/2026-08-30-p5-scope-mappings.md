# P5 cut C: scope mappings

Date: 2026-08-30
Branch: `feat/p5-scope-mappings`
Reference container: `kc-scope`, `quay.io/keycloak/keycloak:26.7.1 start-dev`,
port 8098. Checked to be Keycloak and not another stream's process before any
value below was believed: `GET /admin/realms/master/client-scopes` served the
fifteen bootstrapped scopes with Keycloak's own key order and its five security
headers.

The first cut (`2026-08-29-p5-client-scopes.md`) built the client scopes, the
second (`2026-08-30-p5-protocol-mappers.md`) the mappers inside them. This cut
builds the third thing that hangs off a client scope and off a client: the roles
either of them may put into a token.

## 1. The allocation exercise

### 1.1 What the description says

`Scope Mappings` holds **33** operations, and they are three identical families
of eleven:

```
/admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/...     11
/admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/...  11
/admin/realms/{realm}/clients/{client-uuid}/scope-mappings/...               11
```

each with the combined read (`GET`), a realm quintet (`GET`, `POST`, `DELETE`,
`GET .../available`, `GET .../composite`) and the same quintet under
`clients/{client}`.

The 11/11/11 split in the brief is a count off the vendored description. It is
now also a measurement: see below.

### 1.2 What the server says about the alias

Two cuts have now found `client-templates` to be a byte-identical alias of
`client-scopes` with exactly one exception each, and the brief says neither
result transfers. It does not, and here the **exception is absent**.

All seven reads were compared body-for-body and header-for-header (`Date`
excluded, which Keycloak never sends anyway):

| Operation | `client-scopes` vs `client-templates` |
|---|---|
| `GET .../scope-mappings` | body and every header identical |
| `GET .../scope-mappings/realm` | identical |
| `GET .../scope-mappings/realm/available` | identical |
| `GET .../scope-mappings/realm/composite` | identical |
| `GET .../scope-mappings/clients/{c}` | identical |
| `GET .../scope-mappings/clients/{c}/available` | identical |
| `GET .../scope-mappings/clients/{c}/composite` | identical |
| `POST`/`DELETE .../realm` | 204, writes the same rows |
| `POST`/`DELETE .../clients/{c}` | 204, writes the same rows |

Error bodies come through unchanged: an unknown scope is
`Could not find client scope`, an unknown role is `Role not found`.

**The exception the previous two cuts each found does not exist on this tag, and
the reason is structural rather than lucky.** Both exceptions were `POST`
answering a `Location` under the path it was called on. **No operation on this
tag mints a `Location` at all** - the two writes are 204 with no body and no
`Location` - so there is nothing left for the two spellings to disagree about.
That is a stronger statement than "the alias holds again": it says the alias can
only ever be distinguishable through a `Location`, which is consistent with all
three measurements rather than merely compatible with them.

### 1.3 The description checked against the server

The previous cut did this and found nothing, which is the outcome that makes the
check worth repeating. Repeated, and again nothing:

- `.../scope-mappings/clients` with no id, `.../scope-mappings/available`,
  `.../scope-mappings/composite`, `.../scope-mappings/roles`,
  `.../scope-mappings/client-scopes`, `.../scope-mappings/realm/composite/x` and
  `.../scope-mappings/clients/{c}/realm` are all **404**
  `{"error":"HTTP 404 Not Found"}`.
- No other container carries the sub-resource: `/roles/{name}/scope-mappings`,
  `/groups/scope-mappings` and `/users/scope-mappings` are all 404.
- Every one of the 33 the description names answers. None is a 501, none is
  behind a preview feature.

So the tag is 33 operations on the server as well as in the description, and the
three-way split is now measured rather than counted.

### 1.4 The allocation

**All 33.** Twenty-two of them are one handler set registered under two base
paths, which is the loop the two previous cuts already wrote; the remaining
eleven are the same handlers over a different container. There are **eleven
distinct behaviours**, not thirty-three, and the container difference is one
interface with two implementations - exactly the `mapperHolder` shape cut B
built.

That is the whole tag, so `admin/scope-mappings` goes **0 -> 33** and closes
outright, the way `admin/client-scopes` and `admin/protocol-mappers` did.

Nothing outside the tag moves. Unlike cut A - which delivered twelve operations
filed under `admin/clients` and `admin/realms-admin` - every route here is
tagged `Scope Mappings`, so the predicted delta is **+33 and no other chapter**.

### 1.5 Does this complete P5?

**No.** The roadmap's P5 row is `Client Scopes 10, Protocol Mappers 21, Scope
Mappings 33, Client Attribute Certificate 7, Client Initial Access 3, Client
Registration Policy 1`. After this cut the first three are closed and **eleven
operations remain**, in three tags nobody has cut:

| Tag | Ops | Note |
|---|---|---|
| `Client Attribute Certificate` | 7 | six under `/clients/{uuid}/certificates/{attr}/...`, and **`POST /admin/realms/{realm}/identity-provider/upload-certificate`, which is P9's** - it is in the tag only because it uploads a certificate |
| `Client Initial Access` | 3 | `GET`/`POST /clients-initial-access`, `DELETE .../{id}` - dynamic client registration, which the roadmap also names under P7 |
| `Client Registration Policy` | 1 | `GET .../client-registration-policy/providers` |

Six of the seven certificate operations depend on a client keystore, which is
**F60** (`a saml client created through the Admin API gets no keystore`) and
which the first cut deferred to P11. So the honest statement is: this cut
finishes P5's client-scope trilogy, and P5's row does not close until a fourth
cut takes the certificate and registration tags, with one of its eleven
operations belonging to P9 and six of them blocked on P11's keystore.

## 2. Does the caller-relative rule govern this family?

This is the question the brief singles out, and the answer is **no**. The
predicate here is a different one this project already has, and getting it wrong
in either direction was possible.

### 2.1 What was measured

Nine probe users in `master`, each holding exactly one `master-realm` client
role, plus seven holding a measured pair. Swept over the reads, both writes, and
both containers.

```
role             badScope  rdRealm  rdCombi  rdAvail  rdComp  wrRealm  delRealm
<none>              403      403      403      403     403      403      403
query-clients       404      403      403      403     403      403      403
view-clients        404      200      200      200     200      403      403
manage-clients      404      200      200      200     200      403      403
view-realm          403      403      403      403     403      403      403
manage-realm        403      403      403      403     403      403      403
create-client       403      403      403      403     403      403      403
view-users          403      403      403      403     403      403      403
manage-users        403      403      403      403     403      403      403
```

`manage-clients` **cannot write a realm role**, which is what says the write
guard is not `manage-clients`. The second sweep says what it is:

```
caller                      write realm role   write client role
manage-clients                     403                204
manage-clients + manage-users      403                204
manage-clients + view-users        403                204
manage-clients + query-users       403                204
manage-clients + view-realm        403                204
manage-clients + manage-realm      204                204
view-clients   + manage-users      403                403
manage-users                       403                403
```

Identical on `/client-scopes/{id}/scope-mappings/...` and on
`/clients/{uuid}/scope-mappings/...`, and on both verbs.

### 2.2 The predicate

```
realm  ->  coarse gate {view,query,manage}-clients        (403)
       ->  the container: the scope or the client         (404)
       ->  the fine check: read view|manage-clients,
                           write manage-clients           (403)
       ->  the role                                       (404)
       ->  the manage role of the role's own container    (403)
```

The last line is the one that matters. **It is the composite-write rule, not the
caller-relative rule.** AGENTS.md already records the composite-write rule -
*"A composite write needs the manage role of every child's own container"* - and
this family runs the same predicate: `manage-realm` for a realm role,
`manage-clients` for a client role. It is **not** the admin-role predicate the
user and group role-mapping families use, and three measurements say so:

1. `manage-clients` is refused `create-realm` and `offline_access`, which are
   ordinary realm roles and not admin roles at all. The caller-relative rule
   would allow both.
2. `manage-clients + manage-realm` is **allowed `admin`**, master's own
   superuser realm role. Under the caller-relative rule `manage-realm` does not
   confer `admin` - `admin` is composite over `manage-realm`, not the reverse -
   so that write would be refused.
3. `manage-clients` alone is **allowed `master-realm`'s `manage-realm`**, a
   client role that confers full realm management. The caller-relative rule
   refuses exactly this on `POST /users/{id}/role-mappings/clients/{uuid}`.

So the naive move - reusing `mayGrantRole`, which is right next door and has the
right signature - is falsified. It would refuse writes Keycloak accepts (case 2
and 3) and accept none it refuses.

### 2.3 Is the permissive direction an escalation?

No, and it is worth writing down because the brief flags F28 and F32 as the two
times this project met one.

A scope mapping does not grant a role to anybody. It is a **filter**: it decides
which of the roles a user *already holds* survive into a token issued for that
client. A `manage-clients` caller putting `master-realm/manage-realm` into a
client scope has given nobody that role; it has only stopped that role from
being stripped out of a token for a user who already has it. The caller-relative
rule exists on the user family because that write really does hand out a right.
Here there is nothing to hand out, which is a plausible reason for Keycloak to
have a different predicate - though the reason is inference and only the
predicate is measured.

The one place it *is* a widening is `fullScopeAllowed`, and that flag lives on
`PUT /clients/{uuid}`, which already takes `manage-clients` and is not this
cut's.

### 2.4 The available/composite triple, and how it differs

The brief said to expect the triple and expect it to differ. It does, in two
ways.

**`available` is caller-filtered and `composite` and the direct read are not.**

```
caller           realm(direct)  realm/available  realm/composite
view-clients           1               0                1
manage-clients         1               0                1
mc + manage-realm      1               5                1
mc + view-realm        1               0                1
```

`available` runs the same per-role predicate the write runs, so
`manage-clients` sees `[]` where a caller that could actually write them sees
five. That is the fourth instance of "200 with a shorter list to a weaker
caller" and it matches the user family's shape - but the predicate inside the
filter is the write's, which here is the container-manage rule and not
`mayGrantRole`.

**`available` is the complement of the *direct* list; `composite` is not the
complement of anything.** With a composite realm role `comp` mapped, whose
children are a realm role `rr` and a client role `cr`:

```
realm            [comp]
realm/composite  [comp, rr]
realm/available  [admin, create-realm, default-roles-master, rr,
                  offline_access, uma_authorization]      <- rr is in BOTH
clients/{c}      []
clients/{c}/composite  [cr]
```

`rr` is in the composite expansion **and** in `available`, because `available`
subtracts only what is directly mapped. That is the same rule the user family
has and it is measured here rather than inherited.

**`composite` has a third input nothing else in this family has:
`fullScopeAllowed`.**

```
client with fullScopeAllowed=true,  nothing mapped:
  clients/{uuid}/scope-mappings/realm            []
  clients/{uuid}/scope-mappings/realm/composite  all 7 realm roles

the same client with fullScopeAllowed=false, nothing mapped:
  clients/{uuid}/scope-mappings/realm/composite  []
```

A client scope has no such flag and always answers the expansion. So `composite`
is `hasScope`, which is three clauses on a client and one on a client scope:

```
hasScope(container, role) =
      container is a client and its fullScopeAllowed is set
   or role is in the direct scope mappings, or reachable through one
   or container is a client and role is one of that client's OWN roles,
        or reachable through one
```

and `available` is `!hasDirectScope`, which is two clauses on a client and one
on a client scope - the direct mappings, plus the client's own roles. The third
clause is measured: `GET /clients/{c}/scope-mappings/clients/{c}/available` is
`[]` with nothing mapped and `fullScopeAllowed` off, on a client that owns
exactly one role, and its `composite` sibling answers that one role.

## 3. Everything else measured

### 3.1 The representation

The role shape is the brief one the role-mapping family already serves:

```
id, name, description, composite, clientRole, containerId
```

`description` present only when set, `attributes` absent. 200,
`Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`, the
five security headers.

The combined read is the same `MappingsRepresentation`
`GET /users/{id}/role-mappings` serves: `realmMappings` then `clientMappings`,
each **absent** when empty, and each `clientMappings` entry is `id, client,
mappings` keyed by `clientId` in Java map order. An empty scope answers `{}`.

`briefRepresentation` is honoured by **`.../composite` alone**, on both triples -
`false` grows an `attributes` key. The other five reads and the combined read
ignore it. That is the user family's rule confirmed on a new family, which is
the first time one of these parameter rules has generalised.

### 3.2 The two writes read different keys off the same body

This is the sharpest thing on the tag.

```
POST/DELETE .../scope-mappings/realm          resolves by  id,   ignores name
POST/DELETE .../scope-mappings/clients/{c}    resolves by  name, ignores id
```

| Body on `.../realm` | | Body on `.../clients/{c}` | |
|---|---|---|---|
| `[{"id":<rr>}]` | 204 | `[{"name":"cr"}]` | 204 |
| `[{"id":<rr>,"name":"wrong"}]` | **204** | `[{"id":<cr>,"name":"wrong"}]` | 404 |
| `[{"name":"gloak-probe-sm-realm-role"}]` | **500** | `[{"id":<cr>}]` | **404** |
| `[{"id":<unknown>}]` | 404 `Role not found` | `[{"id":<bogus>,"name":"cr"}]` | **204** |

And the `realm` path segment does not mean "a realm role": a **client** role
posted to `.../scope-mappings/realm` answers 204 and lands in `clientMappings`,
readable at `.../scope-mappings/clients/{that client}` and removable through
`.../scope-mappings/realm` again. The `clients/{client}` write is the strict one:
a realm role, or another client's role, is 404 `Role not found`.

The read side is not like this - `GET .../realm` filters to realm roles
properly. So the asymmetry is on the writes alone, and it is the same family of
defect as cut B's `PUT .../protocol-mappers/models/{id}` writing the mapper the
body names.

### 3.3 Every status

| Request | Status | Body |
|---|---|---|
| `POST`/`DELETE`, good | 204 | **no `Cache-Control` at all**, five security headers |
| the same role twice | 204 | idempotent on both verbs |
| `DELETE` of a role not mapped | 204 | |
| `POST []` | 204 | |
| unknown scope, any of the eleven | 404 | `{"error":"Could not find client scope"}` |
| unknown owner client | 404 | `{"error":"Could not find client"}` |
| unknown `{client}` in the path | 404 | `{"error":"Could not find client"}` |
| unknown or mismatched role | 404 | `{"error":"Role not found"}` |
| `.../realm` write with no `id` | **500** | `unknown_error` |
| body `{` | 400 | `unknown_error` / `Cannot parse the JSON` |
| body `[` | 400 | `invalid_request` / `Cannot parse the JSON` |
| body `[{` | 400 | `HTTP 400 Bad Request` / `Cannot parse the JSON` |
| body empty or `null` | 500 | `unknown_error` |
| `Content-Type` not `application/json` | **415** | `{"error":"The content-type header value did not match the value in @Consumes"}` |
| `PUT`, `PATCH` on any of the seven paths | **405** | `{"error":"HTTP 405 Method Not Allowed"}`, no `Allow` |
| `POST`, `DELETE` on the five read-only paths | 404 | `{"error":"HTTP 404 Not Found"}` |

Two things there are new to this project. The **415** is a body no other route
has produced, and it is reachable because these are the first routes whose
`DELETE` carries a request body. And the **no `Cache-Control` on the 204** is
this family's per-endpoint answer; cut A's client-scope `DELETE` carries it.

`Could not find client` for the `{client}` path segment is worth noting against
the role-mapping family, which answers **`Client not found`** for the same kind
of segment. Same missing client, two spellings, decided by the route - so no new
spelling of not-found, but a second family that picks the other one.

### 3.4 The bootstrap owes two scope mappings

A pristine realm - master and a realm created through `POST /admin/realms`
alike - has exactly two:

```
client scope offline_access  ->  realm role offline_access
client account-console       ->  account's manage-account and view-groups
```

The other fourteen scopes and the other five clients have none. `account-console`
is `fullScopeAllowed: false`, which is what makes its two scope mappings
observable at all. The array order of its pair differed between master and the
created realm, so it is not asserted in order.

Gloak's bootstrap already gets `fullScopeAllowed` right (true on `admin-cli` and
`security-admin-console`, false on the other four) and has neither scope mapping.

### 3.5 Ordering

Read three times in one container, all three arrays came back in one order, and
that order is neither sorted nor insertion. It is the realm's role-listing order,
which AGENTS.md already records as **not stable across container starts**. So
every array here is `Case.Unordered` at the root, for the reason the role
listings already are, rather than because this cut saw it move.

## 4. What gets built

### 4.1 `internal/store`, migration `0016`

Two tables, not one, and not a JSON column.

Keycloak's own schema has exactly this split - `SCOPE_MAPPING(CLIENT_ID,
ROLE_ID)` and `CLIENT_SCOPE_ROLE_MAPPING(SCOPE_ID, ROLE_ID)` - and here the
reason is a foreign key rather than 0011's: one table cannot reference two
parents, and a nullable pair of holder columns is the shape 0011 refused. A
column on `client_scope` the way 0014 and 0015 did it is wrong for a different
reason: a scope mapping's identity is a role id, deleting the role must delete
the mapping, and a measured cascade needs a real foreign key.

```sql
CREATE TABLE scope_mapping (
    client_id TEXT NOT NULL REFERENCES client (id) ON DELETE CASCADE,
    role_id   TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, role_id)
);
CREATE TABLE client_scope_role_mapping (
    client_scope_id TEXT NOT NULL REFERENCES client_scope (id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES keycloak_role (id) ON DELETE CASCADE,
    PRIMARY KEY (client_scope_id, role_id)
);
```

Six `RoleRepo` methods, both drivers:

```go
AddClientScopeMapping(ctx, clientID, roleID) error
RemoveClientScopeMapping(ctx, clientID, roleID) error
ListClientScopeMappings(ctx, clientID) ([]*model.Role, error)
AddClientScopeScopeMapping(ctx, clientScopeID, roleID) error
RemoveClientScopeScopeMapping(ctx, clientScopeID, roleID) error
ListClientScopeScopeMappings(ctx, clientScopeID) ([]*model.Role, error)
```

`Scope` twice in the second trio is deliberate and the doc comment says so: the
container is a client scope and the thing stored is a scope mapping. Both adds
are `ON CONFLICT DO NOTHING` and both removes ignore a missing row, because both
verbs are measured idempotent - the group mirror's shape, not the user's.

### 4.2 `internal/admin/scopemappings.go`

One `scopeContainer` interface with two implementations, mirroring cut B's
`mapperHolder`:

```go
type scopeContainer interface {
    mappings(ctx) ([]*model.Role, error)
    add(ctx, roleID) error
    remove(ctx, roleID) error
    fullScope() bool                       // false for a client scope
    ownRoles(ctx) ([]*model.Role, error)   // nil for a client scope
}
```

Eleven handlers on top of it, plus `hasScope` and `hasDirectScope` as the two
predicates §2.4 measured. Two guards, `guardScopeScopeMappings` and
`guardClientScopeMappings`, both `guardAnyRejecting(clientsReadRoles, ...)` with
the container resolved and then `mayUseClientMappers` - which is already the
measured fine check and is reused rather than copied.

The per-role check is new: `mayMapRole(caller, role)` is `manage-realm` for a
realm role and `manage-clients` for a client role. It is **not** `mayGrantRole`,
and its doc comment carries §2.2's three falsifying measurements so nobody
merges the two.

### 4.3 `internal/bootstrap`

The two measured scope mappings, applied after the roles and the client scopes
exist. Pinned by a Go test, because no golden can name a bootstrapped client's
UUID - the same hole `TestBootstrappedClientMappers` fills for cut B.

### 4.4 `internal/conformance`

Cases appended at the very end of `adminCases`, covering the eleven behaviours
once each plus the alias, the second container, the guards, the two lookup keys,
`fullScopeAllowed`, the 415 and the parse codes. Every case that claims an
operation is what moves parity, so all 33 need one claim each.

## 5. Order of work

1. Commit the plan.
2. Migration `0016` in both drivers, the six repository methods in both, the
   store tests.
3. `internal/model` - nothing new; a scope mapping is a `(container, roleID)`
   pair and never becomes a type, exactly as a role mapping does not.
4. `internal/admin/scopemappings.go` and the router registrations.
5. `internal/bootstrap`, and its test.
6. Conformance fixtures and cases; `make record`; read the diff.
7. F78, if it fits (§6).
8. Mutation-test every claim, one mutation each.
9. `CGO_ENABLED=0 go test ./...`, `make lint`, `make oracle`,
   `go test -tags docker ./internal/store/postgres/`.

## 6. F78 and F61

**F78** - a protocol mapper id is not realm-unique in Gloak - is cut B's, filed
against `internal/store` and `internal/model`, both of which this cut owns. It
fits: mappers live in two JSON columns, so the index is a query over
`client_scope.protocol_mappers` and `client.protocol_mappers` rather than a
constraint, and the three measured messages are cut B's to reproduce. Decision
recorded in the handover either way.

**F61** - `PUT /clients/{uuid}` ignoring the two scope lists is unasserted - is
one conformance case and a fixture. It is not this cut's family, but it is one
line and it is the follow-up the brief names, so it goes in if the fixture is
free.

## 7. Predicted parity

Baseline on this branch's merge base: **205 of 499**.

```
chapter                before  after  delta
admin/scope-mappings        0     33    +33
```

**Total 205 -> 238.** No other chapter moves, because every route here is tagged
`Scope Mappings` and nothing this cut adds is behaviour under an operation
another tag claims.
