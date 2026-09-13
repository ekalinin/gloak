# The fixture id spaces, and what a collision does in each

F234. F230 found that two fixtures minted one identity provider `internalId`,
that the duplicate create answers a 409 naming the alias that does **not**
exist, that `idempotentCreate` swallows it, and that the case addressing the
loser gets a 404 with every test green. It closed that family with
`TestNoTwoFixturesMintOneIdentityProviderID` and observed that nothing
enumerated the others.

This cut enumerates them. **There are nine id spaces over thirteen create
routes, every one of them is global, and no two of them are the same space.**
Both halves were measured rather than reasoned about: one id offered to all
nine families in one realm produced **nine 201s and nine coexisting objects**,
so the per-family id prefixes the fixtures use (`c11e0000` clients, `a5c09e00`
client scopes, `1de07000` identity providers, and six more) are tidiness and
not a constraint.

**What a colliding create answers is not shared, and this is the half a sweep
built on the identity provider's case would have got wrong.** Three of the nine
do not answer 409:

- an identity provider id taken in **another realm** is a **500**, which
  `idempotentCreate` does not accept - so that cell is loud where the
  same-realm one is silent;
- an identity provider **mapper** repeated under one name is a **400**, not a
  409, with or without an id;
- and the two authz stores that own the row answer **201 and silently rename
  what was there**. There is no error at all, the winner is the **last** create
  rather than the first, and no status anywhere in the harness can catch it.

Their sibling `POST .../authz/resource-server/policy`, one path segment away,
answers 409 and keeps the first row. Three stores under one resource server,
two answers.

Everything below was measured on **2026-09-13** against
`quay.io/keycloak/keycloak:26.7.1`, from `main` at `70aaa16`.

## 1. The enumeration

A fixture mints into an id space when its create body carries a **literal**
id. A create with no id gets a server-minted UUID, which cannot collide with
anything this tree writes down, so only the literals are in scope.

| space | create routes | id key | name key | global over |
|---|---|---|---|---|
| client | `POST .../clients` | `id` | `clientId` | **realms** |
| client scope | `POST .../client-scopes` | `id` | `name` | **realms** |
| protocol mapper | `POST .../clients` (nested), `POST .../client-scopes` (nested), `POST .../protocol-mappers/models`, `POST .../protocol-mappers/add-models`, `PUT .../clients/{uuid}` (nested) | `id` | `name` | containers **and** realms |
| component | `POST .../components` | `id` | `name` | **realms** |
| identity provider | `POST .../identity-provider/instances` | `internalId` | `alias` | **realms** |
| identity provider mapper | `POST .../identity-provider/instances/{alias}/mappers` | `id` | `name` | providers **and** realms |
| authz resource | `POST .../authz/resource-server/resource` | `_id` | `name` | resource servers **and** realms |
| authz scope | `POST .../authz/resource-server/scope` | `id` | `name` | resource servers **and** realms |
| authz policy | `POST .../authz/resource-server/policy` | `id` | `name` | resource servers **and** realms |

Four of these objects live **inside a realm** and none of their ids is scoped
to it. Three live inside a **resource server** and none of their ids is scoped
to that. The nesting in the URL says nothing about the key space, and that is
the sentence this table exists to replace.

### 1.1 The protocol mapper is one space over five routes

F78 measured that a protocol mapper id is unique across the server, and
`admin/protocol-mappers/duplicate-id-same-container` and `-other-container` are
the pair that says so. The consequence for a sweep is that the five routes have
to be **pooled**: an id minted by a `POST /clients` nested mapper and by a
`POST .../protocol-mappers/models` is one collision, and a sweep run per route
sees two clean routes.

### 1.2 The `PUT` is a mint, and it was written off as an update first

`PUT .../clients/{uuid}` carrying a `protocolMappers` array looked like an
update. AGENTS.md says Keycloak matches the body's mappers to the client's by
`(protocol, name)` and keeps the id it already had; `mapperRenamedByPutFixture`
measures exactly that and the tree's one such body names an existing mapper. So
the first version of this cut's table put it in the **exemption** list with that
measurement as the reason.

That is the measurement for a name the client **has**. For a name it does not:

```
POST /admin/realms/f234j/clients
     {"id":"…701","clientId":"pz-1","protocolMappers":[{"id":"…710","name":"mp-a",…}]}   -> 201
PUT  /admin/realms/f234j/clients/…701
     {"protocolMappers":[{"id":"…711","name":"mp-new",…}]}                               -> 204
GET  .../protocol-mappers/models  -> [{"id":"…711","name":"mp-new"}]
POST /admin/realms/f234j/clients
     {"id":"…702","clientId":"pz-2","protocolMappers":[{"id":"…711","name":"mp-b",…}]}   -> 409
```

The `PUT` created a mapper at the id the body chose, and that id is then taken
server-wide. A `PUT` naming an id another client holds is a 409 and changes
nothing on either client.

So the route is the fifth member of the protocol mapper space. It is worth the
paragraph because the reason it was nearly exempted is a **true** measurement
about a **different** input, which is the most convincing kind of wrong.

### 1.3 The four places a literal id is not a mint

`TestEveryLiteralIDInAFixtureBodyIsInADeclaredSpace` walks the other way -
every UUID-shaped literal in a fixture body has to be a declared route's id or
a declared exemption - so the table cannot fall behind the fixtures. Four
exemptions, each a reference to something that already exists:

```
POST .../authz/resource-server/resource   /scopes/*/id     a resource naming a scope
POST .../authz/resource-server/policy     /scopes/*        a scope permission naming its scopes
POST .../authz/resource-server/policy     /resources/*     a resource permission naming its resources
PUT  .../protocol-mappers/models/{id}     /id              an update, addressed by the same id in the path
```

An exemption nothing matches fails too: a claim about a tree that no longer
holds it is worse than none, because the same pointer can come back as a real
mint under it.

## 2. What a collision does, per space

Every cell below was issued against a live container. "Same parent" means the
same realm, or the same resource server, or the same mapper container. Blank
means the cell does not exist for that family.

| space | same parent | other parent | other realm | `idempotentCreate` accepts | the loser afterwards |
|---|---|---|---|---|---|
| client | 409 `Duplicate resource error` | | 409 `Client <new clientId> already exists` | **yes, both** | absent |
| client scope | 409 `Client Scope <new name> already exists` | | 409, same shape | **yes, both** | absent |
| protocol mapper | F78's two bodies, by route and holder | 409 `Duplicate resource error` | 409, same | **yes** | absent, **and the enclosing create is rolled back** |
| component | 409 `Duplicate resource error` | | 409, same | **yes, both** | absent |
| identity provider | 409 `Identity Provider <new alias> already exists` | | **500** `unknown_error` | same realm yes, **other realm no** | absent |
| identity provider mapper | **400** for one name, 409 for another | 409 `Duplicate resource error` | 409, same | 409 yes, **400 no** | absent |
| authz resource | **201, a silent rename** | 409 `Duplicate resource error` | 409, same | not a refusal | **the winner's own name is replaced** |
| authz scope | **201, a silent rename** | 409 `Duplicate resource error` | 409, same | not a refusal | same |
| authz policy | 409 `Duplicate resource error` | 409, same | 409, same | **yes** | absent, first row survives |

### 2.1 Two bodies for one question, decided by the realm

The client family answers the same question two ways:

```
POST /admin/realms/f234c1/clients {"id":X,"clientId":"k-one"}    -> 201
POST /admin/realms/f234c1/clients {"id":X,"clientId":"k-two"}    -> 409 {"error":"conflict","error_description":"Duplicate resource error"}
POST /admin/realms/f234c2/clients {"id":X,"clientId":"k-three"}  -> 409 {"errorMessage":"Client k-three already exists"}
GET  /admin/realms/f234c1/clients?clientId=k-two                 -> []
```

The cross-realm body **names the client that does not exist**, which is F230's
identity provider shape arriving on a second family. Measured in both orders on
container A - same-realm first in one round, cross-realm first in another - so
it is the realm and not the sequence that decides, and reproduced on container
B.

The client scope answers the naming-the-absent body in **both** cells.

### 2.2 The identity provider's cross-realm cell is a 500

```
POST /admin/realms/f234c3/identity-provider/instances {"alias":"k-i1","internalId":X,…}  -> 201
POST /admin/realms/f234c3/identity-provider/instances {"alias":"k-i2","internalId":X,…}  -> 409 Identity Provider k-i2 already exists
POST /admin/realms/f234c4/identity-provider/instances {"alias":"k-i3","internalId":Y,…}  -> 201   (control: a fresh id in that realm)
POST /admin/realms/f234c4/identity-provider/instances {"alias":"k-i4","internalId":X,…}  -> 500 unknown_error
```

The container's log names it in one line, on both containers:

```
ERROR [org.keycloak.services.error.KeycloakErrorHandler] Uncaught server error:
org.keycloak.models.ModelException: Identity Provider with internal id
[f2340000-0000-4000-8000-000000000008] does not belong to realm [f234b]
```

The control matters: without it the 500 could be the `oidc` provider refusing
that realm for some other reason.

`idempotentCreate` is `{201, 409}`, so this cell **fails the fixture loudly**.
The four organization broker fixtures are the ones that would meet it, and they
are the reason the cell was probed at all.

### 2.3 A nested mapper collision strands the object around it

```
POST /admin/realms/f234c1/client-scopes
     {"id":A,"name":"k-h1","protocolMappers":[{"id":M,"name":"k-mp1",…}]}   -> 201
POST /admin/realms/f234c1/client-scopes
     {"id":B,"name":"k-h2","protocolMappers":[{"id":M,"name":"k-mp2",…}]}   -> 409 Duplicate resource error
GET  /admin/realms/f234c1/client-scopes/B                                   -> 404 Could not find client scope
```

So the blast radius of a nested collision is the **enclosing** object, not the
mapper: `idempotentCreate` accepts the 409, the fixture reports success, and a
case addressing the client scope - not the mapper - gets the 404.
`mapperIDRollbackFixture` pins that rollback for the tree's own case.

### 2.4 The authz stores that overwrite

This is the cell worth the most attention, because it produces no error at all.

```
POST .../clients/az-1/authz/resource-server/resource {"_id":R,"name":"res-one"}   -> 201
GET  .../resource                                                                -> ["res-one"]
POST .../clients/az-1/authz/resource-server/resource {"_id":R,"name":"res-two"}   -> 201
GET  .../resource                                                                -> ["res-two"]
```

`res-one` is gone and nothing said so. The same holds for
`.../scope`. Repeated a third time it renames again, so the **last** create
wins - the opposite of every other space here, where the first does.

Confirmed on four independent clean resource servers on container A and two
more on container B. A cross-server or cross-realm create is a 409 and leaves
the owner untouched, measured before and after.

`.../policy` refuses: 409 `Duplicate resource error`, and `pol-one` is still
there. Same path prefix, same verb, same question, and one of the three
disagrees with the other two - which is why this table has a row per store and
not one row for "authz".

### 2.5 One anomaly, recorded and not chased

On container A, two sequences left the authz **scope** family in a state its
own reads could not serve: after a cross-server 409 *and* a same-server
collision on one id, `GET .../authz/resource-server/scope` on the owning server
answered `400 {"error":"unknown_error","error_description":"Cannot parse the
JSON"}` - a request-parse error on a `GET` with no body - and the same-server
create answered 409 where a clean server answers the 201 upsert. Reproduced on
two fresh realms with the same ordering, and **not** reproduced when the scope
probes ran alone.

It is order-dependent, it is Keycloak's, and it is not F234's question. F238.

## 3. Every collision in the tree, and what holds it shut

**Five ids are minted more than once. All five are deliberate, and zero are
accidental.** Each was checked against the constructor that produces it rather
than against a comment.

| # | space | id | mints | what holds it shut | chosen or coincidence |
|---|---|---|---|---|---|
| 1 | client | `c11e0000-…0031` | `scope-mappings-composite`, `-narrow-caller`, `-scope`, all `gloak-probe-sm-rc`, all `master` | one constant `smRoleClientID` through one constructor - they build **one** client | chosen |
| 2 | client scope | `f7800000-…0001` | five `mapper-id-holder*` fixtures, all `gloak-probe-f78-holder`, all `master` | `mapperIDHolderFixture`, whose comment says the id has to be held by exactly one thing for the family to mean anything | chosen |
| 3 | protocol mapper | `f7800000-…00aa` | six mints over five fixtures, all `gloak-probe-f78-held` | the same constructor; the sixth is `mapperIDRollbackFixture`'s create, which **declares** `ExpectStatus: []int{409}` | chosen |
| 4 | component | `c0e00000-…0002` | `component-dup-id`, twice, two names, one realm | `componentCollideStep` declares `ExpectStatus: []int{409}` - the fixture collides on purpose so the case's own collision is never the first, which is F147 | chosen |
| 5 | identity provider | `1de07000-…0002` | `idp-minimal` and `idp-taken`, one alias `gloak-probe-idp-min` | one id for one alias, so the 409 leaves exactly the object the case wants | chosen |

**Nothing in the tree is held shut by a coincidence today.** The one that was -
F230's `…020`/`…021`, held apart by a `PristineRealm` flag set for F40's reason
- was moved to `…050`/`…051` by the cut that filed F234, so it is already gone.
What this cut adds is that the same thing cannot come back anywhere, in any of
the nine spaces, without a named test failing.

### 3.1 The discriminator is in the data, twice

The brief's requirement is that deliberate sharing and accidental collision be
told apart by the data rather than by a comment. Two signals do it, and both
are fields the fixture runner already reads:

- **`ExpectStatus`.** A step that accepts no 2xx is a step that means to lose.
  `idempotentCreate` is `{201, 409}` and accepts one; `{409}` does not. That is
  what excuses rows 3 and 4 above.
  "Would not accept a 201" was the first version of this predicate and it is
  wrong: `POST .../protocol-mappers/add-models` answers **204**, so a route's
  success code is not 201 everywhere. Any 2xx is.
- **The object's identity.** Rows 1, 2, 3 and 5 are two fixtures building the
  same object, which is harmless because the loser's refusal leaves what the
  case wanted.

### 3.2 "One id, one name" is not the invariant, and getting that wrong was mine

The first version of this cut's sweep keyed on **one id for one name**, which
is the precedent's rule. It passes the whole tree, and it is too weak.

One name in two **realms** is one name and two objects. A client called
`gloak-probe-x` minted at `…001` in realm A and in realm B is a 409 in realm B,
swallowed, and realm B's client does not exist. The same is true in eight of
the nine spaces - every one that answers 409. The tree has no such pair today,
which is exactly why the weak rule looked right.

The key is therefore the **object**: the route, the container and the name. The
container is the request path, plus

- the **fixture name** when the path holds a capture, because every authz
  fixture POSTs to `.../clients/{{client_uuid}}/authz/...` and means a
  different resource server by it - one path string, twelve parents;
- the **enclosing create's own name** for a mapper nested inside it, because
  two clients created at one path are two containers and the path cannot say
  which.

The component family runs eight realms, the organization brokers four and the
session fixtures four, so the cross-realm shape is a copy-paste away rather
than hypothetical.

## 4. What was added

Four tests and one table, all in `internal/conformance/fixture_idspaces_test.go`:

- **`fixtureIDSpaces`** - the nine spaces, their thirteen routes, and what a
  colliding create answers in each, in the failure message so that a person
  reading a red test reads the measurement rather than the identity provider's.
- **`TestNoTwoFixturesMintOneObjectID`** - the sweep, one subtest per space,
  with a **per-space floor**. One floor over the table would be satisfied by
  the eight spaces that still match while the ninth went quiet.
- **`TestTheFixtureIDSpacesAreTheOnesMeasured`** - the table pinned whole,
  every field of every route, so that an entry arriving and an entry leaving
  each fail on their own. This is where the coherent-wrong-table mutation dies:
  a `NameKey` changed to the `IDKey` maps every id to exactly one name,
  silences that space for ever, and leaves every floor satisfied.
- **`TestEveryLiteralIDInAFixtureBodyIsInADeclaredSpace`** - §1.3. This is the
  half that is about the **tenth** family rather than the nine here, and it is
  what actually answers F234: a table alone leaves the next one as invisible as
  these were.
- **`TestContainerOfSeparatesWhatACollisionWouldSeparate`** - `containerOf`
  pinned directly, against the measurements, because **the tree cannot pin
  it**. Every distinction it draws is about a collision no fixture makes today,
  so neutering the whole function to a constant leaves the sweep green. M3b
  below is that, demonstrated.

`TestNoTwoFixturesMintOneIdentityProviderID` **keeps its name** and becomes the
identity provider's row of the same sweep. F230 cites it and F230 is in a spec
file; a renamed test would leave that entry pointing at nothing, and two
implementations of one invariant would drift. One implementation, one name, one
extra line.

No fixture, no case and no golden was touched, so no golden was re-recorded.

## 5. The mutation pass

Eleven mutations, run against `internal/conformance` **whole** - no `-run`
filter - from a committed and clean tree, with the revert on a `trap … EXIT`
rather than on the happy path, the diff checked non-empty before each run, and
`git status --porcelain` checked empty after each revert. `internal/conformance`
is the only package this cut touches.

<!-- MUTATION TABLE -->

## 6. Containers

**Two containers. Both created with `docker run` from
`quay.io/keycloak/keycloak:26.7.1`, neither restarted, and the second was not a
second start of the first.**

| | name | created | what ran on it |
|---|---|---|---|
| A | `gloak-f234` | 21:31 | eight probe rounds, realms `f234a`…`f234k`; every cell that could depend on order run in both orders; the cross-family nine-way probe |
| B | `gloak-f234b` | 22:10 | one confirmation pass over every headline cell in §2, in its own realms `f234c1`…`f234c7`, each family on parents nothing else had touched |

Every cell in §2 reproduced on B. The ordering anomaly of §2.5 was **not**
re-provoked on B, because B ran each family's probes on parents of their own -
which is itself the evidence that the anomaly is about the sequence and not
about the family.

Realms are what isolate a probe here, not containers, and §2.5 is the reminder
that realm isolation is not total: a resource-server cache entry outlived one.
Where the answer could turn on that, the probe got a fresh realm **and** a
fresh parent, and the count above is the reason the distinction is recorded at
all.

## 7. Parity

```
make conformance
total: 598 of 644 enumerated behaviours served; 2 chapters not enumerated
```

Unmoved, and it should be: this is a harness cut. No case was added, removed or
re-classified, and no golden was re-recorded. `make lint` is clean and
`CGO_ENABLED=0 go test ./...` passes without Docker or the network.

## 8. What belongs in AGENTS.md

Phrased to be folded as-is, under "Things that look like bugs and are not" for
the first, and beside the recorder and pollution-guard bullets for the second.

- **A fixture id space is global, on all nine of them, and the URL says
  nothing about it.** A client, a client scope and a component live inside a
  realm; a resource, a scope and a policy live inside a resource server; a
  protocol mapper lives inside a client or a client scope. **None of their ids
  is scoped to its parent**, and one id can be all nine objects at once -
  measured, nine creates, nine 201s, one realm. The per-family prefixes in
  `fixture.go` are tidiness, not a constraint. `fixtureIDSpaces` is the
  enumeration and `TestEveryLiteralIDInAFixtureBodyIsInADeclaredSpace` is what
  stops the tenth family arriving unswept.
- **What a colliding create answers is different per family, and three of the
  nine do not answer 409.** An identity provider id taken in another realm is a
  **500** - `ModelException: … does not belong to realm …` - which
  `idempotentCreate` does not accept, so that one cell is loud where its
  same-realm neighbour is silent. An identity provider mapper repeated under
  one name is a **400**. And `POST .../authz/resource-server/resource` and
  `.../scope` answer **201 and silently rename the row that was there**: no
  error, the **last** create wins, and nothing in the harness can catch it.
  `.../policy` beside them answers 409 and keeps the first row. Reading one
  family's answer into another is the mistake F234 was filed about.
- **The 409 several of these send names the object that does **not** exist.**
  `Client <the new clientId> already exists` across realms,
  `Client Scope <the new name> already exists` in both cells, and the identity
  provider's `Identity Provider <the new alias> already exists`. A reader
  debugging one of these looks for the wrong object first, every time.
- **A nested create's collision strands the object around it.** A
  `POST /client-scopes` whose `protocolMappers` entry carries a taken id is a
  409 and the **client scope** is not created either - 404
  `Could not find client scope`. So the blast radius is the enclosing object,
  and the case that fails is the one addressing that.
- **`PUT .../clients/{uuid}` mints protocol mapper ids.** It matches the body's
  mappers to the client's by `(protocol, name)` and keeps the id it had - which
  is true, is what `mapperRenamedByPutFixture` measures, and is only half the
  behaviour. For a name the client does **not** hold, the same `PUT` creates
  the mapper at the body's id and that id is then taken server-wide. A true
  measurement of a different input is the most convincing way to be wrong about
  a route.
- **Two fixtures sharing an id is safe only when they build the same
  object.** The same route, the same container and the same name. One name in
  two **realms** is two objects, and the loser is stranded silently in eight of
  the nine spaces. `TestNoTwoFixturesMintOneObjectID` keys on the object for
  that reason, and `containerOf` counts a `{{capture}}` in the path as
  fixture-local, because every authz fixture POSTs to one path string and means
  a different resource server.
- **A deliberate collision declares itself with `ExpectStatus`.** A step
  accepting no 2xx means to lose; `idempotentCreate` accepts one and does not.
  That is the only thing separating `componentCollideStep` and
  `mapperIDRollbackFixture` from a defect, and it is a field rather than a
  comment on purpose. "Would not accept a 201" is the wrong spelling of it:
  `add-models` answers 204.

## 9. Follow-ups

### F236: `containerOf`'s distinctions have no witness in the corpus

Every distinction `containerOf` draws - realm from realm, resource server from
resource server, container from container - is about a collision no fixture
makes. Neutering it to a constant leaves `TestNoTwoFixturesMintOneObjectID`
green over all nine spaces, which M3b demonstrates. The remedy taken here is
`TestContainerOfSeparatesWhatACollisionWouldSeparate`, which asserts the
function against the measurements rather than against the tree.

That is strictly weaker than a corpus that exercises it, and the same shape as
`identityProvidersFetchingOnConstruction`: a list pinned against a measurement
because no usage can pin it. The open question is whether the harness should
grow a **negative fixture** - a pair of fixtures that really do collide, run
against a real container once and asserted to fail - or whether a unit test on
the predicate is where this correctly stops. Nothing is proposed; the
observation is that five of this repository's guards are now in this category
and none of them knows about the others.

### F237: the authz upsert is a divergence Gloak has not been asked about

`POST .../authz/resource-server/resource` and `.../scope` answer **201** to an
id their own resource server already holds, and rename the row. Nothing in the
tree measures that: there is no case for it, Gloak's behaviour on that input is
unknown, and the two goldens nearest to it are creates with fresh ids.

It is worth a case for a reason beyond coverage: it is the only measured create
in this repository where **repeating a request destroys information**, which
makes it the one place `idempotentCreate`'s whole premise - "the object is
already there, the state the case needs is reached either way" - is false while
looking true. What to measure first is whether the `PUT` on the same row does
the same thing, and whether `owner` or `type` survive the rename.

### F238: an authz collision leaves reads that depend on what ran before

§2.5. After a cross-server 409 followed by a same-server collision on one id,
`GET .../authz/resource-server/scope` on the **owning** server answers
`400 unknown_error / Cannot parse the JSON`, and that server's own same-id
create answers 409 where a clean one answers the 201 upsert. Reproduced on two
fresh realms with the same ordering on container A; not provoked when the scope
probes ran alone.

This is the F40/F206/F230 family - a value that is a function of what else the
recorder did - arriving in a place none of them reaches, because the fresh
**realm** does not clear it. What to measure first is which of the two requests
poisons it, and whether a fresh container does clear it; the cheap half is that
no golden under `admin/authz` should be recorded after a collision case in
catalogue order.

### F239: `idempotentCreate` is one constant for nine different refusals

The nine spaces answer a repeat with a 409, a 400, a 500 and a 201 between
them, and `idempotentCreate` is `{201, 409}` on every create that carries it -
108 steps. On the identity provider's cross-realm cell and the mapper's
same-name cell it is already wrong in the safe direction: the step fails loudly.
On the authz pair it is wrong in the unsafe one, because there is nothing to
swallow.

The observation is not that the constant should be widened - AGENTS.md already
records that widening one to accept a 400 would also accept `Issuer is
required` - but that there is **no way to say which repeat a step expects**. A
step saying `idempotentCreate` today claims "a repeat of this is harmless", and
in two of the nine spaces that claim is unchecked and false. Whether that wants
a per-space constant, or a field, or nothing at all, is a design question this
cut did not need to answer.
