# P5 cut C: what belongs in the documents this branch may not edit

Date: 2026-08-30
Branch: `feat/p5-scope-mappings`
Plan: `docs/superpowers/plans/2026-08-30-p5-scope-mappings.md`

Everything below was measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8098 (`kc-scope`, removed at
the end of the session), on 2026-08-30. The container was checked to be Keycloak
before any value was believed - `GET /admin/realms/master/client-scopes` served
the fifteen bootstrapped scopes in Keycloak's own key order with its five
security headers - because a cut lost two probes this week to another stream's
process on the same port.

Gloak was then compared against the same requests through the conformance
recorder and verifier.

This branch does not touch `AGENTS.md`, `README.md` or the three spec documents,
so what is owed to them is written out here.

---

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

### 1.1 The tag is 33 operations and the alias holds on all eleven, with no exception

Three families of eleven: `client-scopes/{id}/scope-mappings/...`,
`client-templates/{id}/scope-mappings/...` and
`clients/{uuid}/scope-mappings/...`, each with the combined read (`GET`), a realm
quintet (`GET`, `POST`, `DELETE`, `GET .../available`, `GET .../composite`) and
the same quintet under `clients/{client}`.

`client-templates` serves what `client-scopes` serves **byte for byte, headers
included**, on every one of the eleven, and **with none of the single exception
its two predecessors each had**. Both of those exceptions were `POST` echoing its
own path into `Location`; **no operation on this tag mints a `Location` at all**,
because the two writes are 204 with an empty body. So the alias can only ever be
distinguishable through a `Location`, which is a stronger statement than "the
alias holds again" and is consistent with all three families' measurements
rather than merely compatible with them.

Error bodies come through the alias unchanged: an unknown scope is
`Could not find client scope`, an unknown role is `Role not found`.

Checked in the other direction too, which is the check the previous cut found
worth repeating: `.../scope-mappings/clients` with no id,
`.../scope-mappings/available`, `.../scope-mappings/composite`,
`.../scope-mappings/roles`, `.../scope-mappings/client-scopes`,
`.../scope-mappings/realm/composite/x` and
`.../scope-mappings/clients/{c}/realm` are all 404
`{"error":"HTTP 404 Not Found"}`, and `/roles/{name}/scope-mappings`,
`/groups/scope-mappings` and `/users/scope-mappings` are 404 as well. Nothing the
description omits.

### 1.2 The representations

The role shape is the role-mapping family's brief one:

```
id, name, description, composite, clientRole, containerId
```

`description` present only when set; no `attributes` unless
`briefRepresentation=false` on `.../composite`. 200,
`Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`, the
five security headers.

The combined read is the same `MappingsRepresentation`
`GET /users/{id}/role-mappings` sends: `realmMappings` then `clientMappings`,
each **absent** when empty, each `clientMappings` entry `id, client, mappings`
keyed by `clientId` in Java map order. A container with nothing mapped answers
`{}` with content-length 2.

**`briefRepresentation` is honoured by `.../composite` alone**, on the realm
triple and the client triple. The other five reads and the combined read ignore
it. That is the user role-mapping family's rule holding on a new family - **the
first time one of this API's parameter rules has generalised rather than
inverted**, and it was measured here rather than carried over.

### 1.3 The two writes read different keys off the same JSON

The sharpest thing on the tag, and the reason one shared decoder is wrong.

```
POST/DELETE .../scope-mappings/realm          resolves by  id,   ignores name
POST/DELETE .../scope-mappings/clients/{c}    resolves by  name, ignores id
```

| Body on `.../realm` | | Body on `.../clients/{c}` | |
|---|---|---|---|
| `[{"id":<realm role>}]` | 204 | `[{"name":"<a role of {c}>"}]` | 204 |
| `[{"id":<realm role>,"name":"wrong"}]` | **204** | `[{"id":<bogus>,"name":"<that role>"}]` | **204** |
| `[{"name":"<a real realm role>"}]` | **500** `unknown_error` | `[{"id":<that role's real id>}]` | **404** `Role not found` |
| `[{"id":<unknown>}]` | 404 `Role not found` | `[{"name":"<a realm role>"}]` | 404 |
| `[{"id":<a CLIENT role>}]` | **204**, and it lands under `clientMappings` | `[{"name":"<another client's role>"}]` | 404 |

**The `realm` path segment is a precondition on nothing.** A client role POSTed
to `.../scope-mappings/realm` answers 204, is readable at
`.../scope-mappings/clients/{that client}` and in the combined view, and is
removable through `.../scope-mappings/realm` again. Only the matching **read**
filters to realm roles. The `clients/{client}` write is the strict one: a realm
role and another client's role are both 404.

Measured identically on all three families and on both verbs.

### 1.4 `available` and `composite` are two different predicates, and one has a third input

**`available` is the complement of the *direct* list**, not of the composite one.
With a composite realm role `comp` mapped, whose children are a realm role `rr`
and a client role `cr`:

```
realm                  [comp]
realm/composite        [comp, rr]
realm/available        [admin, create-realm, default-roles-master,
                        rr, offline_access, uma_authorization]   <- rr in BOTH
clients/{c}            []
clients/{c}/composite  [cr]
clients/{c}/available  [cr]                                      <- cr in BOTH
```

**`composite` is `hasScope`, which is three clauses on a client and one on a
client scope:**

```
hasScope(container, role) =
      container is a client and its fullScopeAllowed is set
   or role is mapped directly, or reachable through a directly mapped role
   or container is a client and role is one of that client's OWN roles,
        or reachable through one
```

`fullScopeAllowed` is the surprise. Measured on one client, both ways round:

```
fullScopeAllowed = true,  nothing mapped:
  .../scope-mappings/realm            []
  .../scope-mappings/realm/composite  all 7 realm roles
  .../scope-mappings                  {}
fullScopeAllowed = false, nothing mapped:
  .../scope-mappings/realm/composite  []
```

So the combined read is the **direct** list where the composite read beside it
is not, on one container, decided by a flag. Two of the six bootstrapped clients
carry the flag.

**`available` is `!hasDirectScope`**, which is two clauses on a client and one on
a client scope - the direct mappings, plus (on a client) the client's own roles,
with no composite expansion in either. Measured:
`GET /clients/{c}/scope-mappings/clients/{that same c}/available` is `[]` on a
client that owns two roles, has `fullScopeAllowed` off and has mapped nothing,
and its `composite` sibling answers both roles.

### 1.5 The guard, and why it is **not** the caller-relative rule

Nine probe users holding exactly one `master-realm` role each, plus seven holding
a measured pair, swept over the reads, both writes and both containers.

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

`manage-clients` cannot write a **realm** role. What it can:

```
caller                          write realm role   write client role
manage-clients                         403                204
manage-clients + manage-users          403                204
manage-clients + view-users            403                204
manage-clients + query-users           403                204
manage-clients + view-realm            403                204
manage-clients + manage-realm          204                204
view-clients   + manage-users          403                403
manage-users                           403                403
```

So the order is:

```
realm -> coarse gate {view,query,manage}-clients        (403)
      -> the container: the scope or the client         (404)
      -> the fine check: read view|manage-clients,
                         write manage-clients           (403)
      -> the role                                       (404)
      -> the manage role of the role's own container    (403)
```

The last line is the **composite-write rule**, not the caller-relative rule.
Three measurements say so:

1. `manage-clients` is refused `create-realm` and `offline_access`, ordinary
   realm roles that are not admin roles at all. The caller-relative rule allows
   both.
2. `manage-clients` + `manage-realm` is **allowed** master's `admin`. Under the
   caller-relative rule `manage-realm` does not confer `admin` - `admin` is
   composite over `manage-realm`, not the reverse - so it would be refused.
3. `manage-clients` alone is **allowed** `master-realm`'s `manage-realm`, a
   client role conferring full realm management. The caller-relative rule
   refuses exactly this on `POST /users/{id}/role-mappings/clients/{uuid}`.

It differs from the composite-write rule too: that one runs on the **add path
alone**, and this one runs on both verbs - a `manage-clients` caller is refused
`DELETE` of a realm role off a container's mappings where
`DELETE .../composites` allows the same removal.

`available` runs the same per-role predicate, so a `manage-clients` caller reads
`realm/available` as `[]` where a caller holding `manage-realm` too sees all six
realm roles. Fourth instance of "200 with a shorter list to a weaker caller".
`composite`, the two direct reads and the combined read are **not** filtered: a
`view-clients` caller and a full administrator get identical bodies.

**The permissive direction is not an escalation**, and it is worth writing down
because F28 and F32 were. A scope mapping grants nothing: it decides which of a
subject's *existing* roles survive into a token for that client. The
caller-relative rule exists on the user family because that write really does
hand out a right.

### 1.6 Every status on the tag

| Request | Status | Body |
|---|---|---|
| `POST`/`DELETE`, good | 204 | **no `Cache-Control` at all**, five security headers |
| the same role twice, either verb | 204 | idempotent on both |
| `DELETE` of a role not mapped | 204 | |
| `POST []` | 204 | |
| unknown scope, any of the eleven | 404 | `{"error":"Could not find client scope"}` |
| unknown owner client | 404 | `{"error":"Could not find client"}` |
| unknown `{client}` segment | 404 | `{"error":"Could not find client"}` |
| unknown or wrong-container role | 404 | `{"error":"Role not found"}` |
| `.../realm` write with no `id` | **500** | `unknown_error` |
| body `{` | 400 | `unknown_error` / `Cannot parse the JSON` |
| body `[` | 400 | `invalid_request` / `Cannot parse the JSON` |
| body `[{` | 400 | `HTTP 400 Bad Request` / `Cannot parse the JSON` |
| body empty or `null` | 500 | `unknown_error` |
| `Content-Type` other than `application/json` | **415** | `{"error":"The content-type header value did not match the value in @Consumes"}` |
| `PUT`, `PATCH`, any of the seven paths | **405** | `{"error":"HTTP 405 Method Not Allowed"}`, no `Allow` |
| `POST`, `DELETE` on the five read-only paths | 404 | `{"error":"HTTP 404 Not Found"}` |

Two of those are new to this project.

**The 415 is a body no route has produced before**, and this family is where it
became reachable: these are the first routes whose `DELETE` carries a body, so a
caller's HTTP library picks a `Content-Type` for itself. Measured on both verbs
across four values: `application/json` and **no `Content-Type` at all** are
accepted; `text/plain` and `application/x-www-form-urlencoded` are the 415. The
absent case is not an artefact of a suppressed header - it was measured
separately from the probe that first looked like it.

**No `Cache-Control` on any 204 here**, where the client-scope `DELETE` one level
up carries `no-cache`. Pinned per endpoint, as every other one on this API is.

`Could not find client` for the `{client}` segment is worth stating against the
role-mapping family, whose identical-looking segment answers **`Client not
found`** for the same missing client. No new spelling of not-found; a second
family picking the other one of the two.

The batch **validates in full before it applies**, on both verbs, measured in
both array orders: one real id and one that resolves to nothing applies neither
and answers 404; one role the caller may map and one it may not applies neither
and answers 403. Array order decides which of the two a body wrong in both ways
gets.

### 1.7 The bootstrap owes two scope mappings, and nineteen containers owe none

Counted, not assumed: `GET .../scope-mappings` was read on all fifteen
bootstrapped client scopes and all six bootstrapped clients, on master **and** on
a realm created through `POST /admin/realms`.

```
client scope offline_access  ->  the realm role offline_access
client account-console       ->  account's manage-account and view-groups
```

Nineteen of the twenty-one answer `{}`. `account-console`'s pair came back in a
different order in the two realms, so it is not asserted in order.

`fullScopeAllowed` on the six: `admin-cli` and `security-admin-console` true,
`account`, `account-console`, `broker` and `master-realm`/`realm-management`
false. Gloak already had that right; it had neither scope mapping.

### 1.8 Ordering

Read three times in one container, every array came back in one order, and that
order is neither sorted nor insertion - it is the realm's role-listing order,
which AGENTS.md already records as not stable across container starts. So every
array here is `Case.Unordered` at the root for the reason the role listings
already are, rather than because this cut saw it move.

The combined view's `clientMappings` key order is `javamap.KeyOrder`'s, the same
as `GET /users/{id}/role-mappings`. Measured over two clients on the reference
container: `gloak-probe-sm-client` came back before `master-realm`. No golden
here holds more than one key, so that pair is a vector this cut recorded and did
not assert.

### 1.9 The `Duplicate resource error` 409 is headerless on one family and not on another

Re-measured while working on F78, and it refutes the *explanation* attached to a
bullet written yesterday rather than the bullet:

```
POST .../protocol-mappers/models, absent name        409  0 of 5 security headers
POST .../protocol-mappers/models, id held elsewhere  409  0 of 5
POST .../protocol-mappers/add-models, id elsewhere   409  0 of 5
PUT  .../default-default-client-scopes/{id} twice    409  5 of 5
```

Same status, same body, same `conflict` code, opposite header sets. So it is not
"the exception mapper Keycloak installs for every constraint violation" - the
realm-level client-scope `PUT` is a constraint violation too and it reaches the
filter chain. Whatever decides it, it is not the constraint.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Ready to paste, in that file's voice.

- **A scope mapping is not a role anybody holds, and its guard is not the role
  mappings' guard.** The write takes `manage-clients` on the container **and the
  manage role of the role's own container** - `manage-realm` for a realm role,
  `manage-clients` for a client role. That is the composite-write rule, not the
  caller-relative rule the user and group families use, and three measurements
  say so: `manage-clients` is refused `create-realm` and `offline_access`, which
  are not admin roles at all; `manage-clients` **plus `manage-realm`** is
  *allowed* master's `admin`, which the caller-relative rule refuses because
  `admin` is composite over `manage-realm` and not the reverse; and
  `manage-clients` alone is *allowed* `master-realm`'s `manage-realm`, which the
  caller-relative rule refuses on the user family. Reusing `mayGrantRole` here is
  the obvious move and it is wrong in both directions. It differs from the
  composite-write rule too: that one runs on the add path alone and this runs on
  both verbs. The permissive direction is not an escalation - a scope mapping
  grants nothing, it decides which of a subject's existing roles survive into a
  token.
- **The two scope-mapping write pairs read different keys off the same JSON.**
  `POST`/`DELETE .../scope-mappings/realm` resolves each entry by **`id`**,
  realm-wide, and never looks at `name`: an entry with a real id and a wrong name
  is 204, one with a real name and no id is a **500**, and **a client role is
  accepted** and lands under `clientMappings`, readable and removable through the
  `realm` path that took it. `POST`/`DELETE .../scope-mappings/clients/{client}`
  does the opposite: it resolves by **`name`** within that client and ignores the
  id, so a bogus id with the right name is 204 and a real id with no name is 404.
  Four operations, two lookup keys, each ignoring the other's. A decoder that
  accepts an entry when *either* key matches passes every happy path and gets
  four measured rejections wrong, and adding a `role.ClientID == ""` check to
  make the realm write agree with its own path breaks the one thing that write
  does.
- **`composite` has a third input that `available` and the combined read do not:
  `fullScopeAllowed`.** A client with the flag set answers **every realm role in
  the realm** from `.../scope-mappings/realm/composite` while
  `.../scope-mappings/realm` answers `[]` and `.../scope-mappings` answers `{}`.
  Turn the flag off and the composite answers `[]`. A client scope has no such
  flag. Two of the six bootstrapped clients carry it, so it is not a corner, and
  composing the combined read out of the composite predicate is the tidy-up that
  makes the three agree where Keycloak measurably disagrees with itself.
- **A client's own roles are in its own scope without ever being mapped.**
  `GET /clients/{c}/scope-mappings/clients/{that same c}/available` is `[]` on a
  client that owns roles, has `fullScopeAllowed` off and has mapped nothing, and
  the `composite` beside it answers those roles. So `available` subtracts a set
  with two clauses on a client and one on a client scope, and every other
  `available` read on the family points at a *different* client and cannot see
  it.
- **`available` is the complement of the direct list and `composite` is not its
  complement.** With one composite role mapped, its child is in the composite
  expansion **and** in the available list, on both triples. Computing one from
  the other is the tidy-up that drops it - the same rule the user role-mapping
  family already records, confirmed here rather than inherited.
- **`briefRepresentation` is honoured by `.../composite` alone on the scope
  mappings too.** Six other reads on the family ignore it. That is the first time
  one of this API's parameter rules has generalised from one family to another
  rather than inverting, and it was still measured rather than assumed.
- **No response on the Scope Mappings tag carries a `Location`, which is why the
  `client-templates` alias has no exception here.** The two previous families
  each had exactly one difference between the two spellings and both were `POST`
  echoing its own path into `Location`; the two writes here are 204 with an empty
  body, so the eleven operations are byte-identical, headers included. The alias
  is distinguishable only through a `Location`.
- **A 415 exists on this API and the scope mappings are where it is reachable.**
  `{"error":"The content-type header value did not match the value in
  @Consumes"}`. These are the first routes whose `DELETE` carries a body, so the
  request's `Content-Type` is whatever the caller's library chose:
  `application/json` and **no `Content-Type` at all** are accepted, `text/plain`
  and `application/x-www-form-urlencoded` are the 415. `PUT
  .../credentials/{id}/userLabel` has the mirror-image rule and Gloak serves it
  for neither.
- **The scope-mapping 204s carry no `Cache-Control` at all**, where the client
  scope `DELETE` three path segments up carries `no-cache`. Another data point
  for "pinned per endpoint", on a family where all four writes agree with each
  other and disagree with their parent.
- **The `{client}` segment's 404 is `Could not find client` here and `Client not
  found` on the role mappings.** Same missing client, two families, the two
  strings this API already has for it - so no new spelling, and no shared helper
  either.
- **The `Duplicate resource error` 409 is headerless on the protocol mappers and
  carries all five on the realm's default client scopes.** Same status, same
  body, same code, opposite header sets, measured side by side. So the
  explanation written for the first - "a constraint violation surfaced through
  the exception mapper, which never reaches the filter chain" - does not survive
  the second, which is a constraint violation that does. The behaviour stands;
  the reason does not.

### 2.1 Lines these measurements contradict

**Four.**

1. **"A caller may hand out a role only if the role is not one of the realm's
   own admin roles, or the caller's own effective roles already confer that
   admin role ... One predicate governs four operations."** It governs four, and
   **not these**. The Scope Mappings tag's four writes and two `available` reads
   run a different predicate - the manage role of the role's own container - and
   the two rules disagree in **both** directions on measured inputs: this family
   refuses `manage-clients` an ordinary non-admin realm role that the
   caller-relative rule allows, and allows a `manage-clients` caller
   `master-realm`'s `manage-realm` that the caller-relative rule refuses. The
   bullet's own sentence "One predicate governs four operations" should say
   which four, because a fifth and sixth family now exist that it does not
   govern. Nothing was changed on the strength of it; `mayMapRole` is a second
   predicate beside `mayGrantRole` and its doc comment carries the three
   measurements.

2. **"That rule is measured too broad, six times now"** gains a **seventh**, and
   this one *agrees* with an earlier data point instead of adding a new shape.
   Every scope-mapping path answers `PUT` and `PATCH` with a real **405**
   `{"error":"HTTP 405 Method Not Allowed"}` and answers `POST` and `DELETE` on
   the five read-only paths with the **404**. That is exactly the role-mapping
   paths' split, which the bullet already records - so the Admin API now has
   three families in three shapes: the client scopes answer all four verbs 405,
   the protocol mappers answer `PATCH` alone 405, and the scope mappings answer
   `PUT` and `PATCH` 405. Three sibling families, three answers, one API. The
   count needs updating; the conclusion still does not follow. Gloak answers 404
   to all of them, and this branch changed nothing. See F31.

3. **"A protocol mapper id is unique across the whole realm, not within its
   container"** - the bullet cut B added yesterday - is wrong in three ways, and
   §3's F78 disposition sets them out. It is unique across the **server**, not
   the realm: a client scope created in a *different* realm with a mapper id
   already in use in master is 409. It is enforced on **five** routes, not
   three - `POST /clients`, `POST /client-scopes`, `PUT /clients/{uuid}`,
   `POST .../protocol-mappers/models` and `POST .../protocol-mappers/add-models`.
   And the "three messages, none about what actually collided" framing is an
   artefact of the probes: which message you get is decided by **where** the
   colliding mapper is, not by which route asked.

   ```
   collision inside the SAME container   POST models      Protocol mapper exists with same name
   collision inside the SAME container   POST add-models  Duplicate resource error
   collision ELSEWHERE in the server     POST models      Duplicate resource error
   collision ELSEWHERE in the server     POST add-models  Duplicate resource error
   collision ELSEWHERE in the server     POST /client-scopes   Duplicate resource error
   collision ELSEWHERE in the server     POST /clients    Client <clientId> already exists
   collision ELSEWHERE in the server     PUT /clients/{u} Duplicate resource error
   ```

   Cut B's probes all reused an id held by the container they were writing to,
   which is the row that answers about the name. Its own sentence says so -
   "a message about the name, for a conflict on the id" - and the id was in the
   same container, where the name check is what fires. Measured as a grid this
   time, with a fresh name and a held id and the other way round, on one
   container in one session.

4. **"The `Duplicate resource error` 409 carries none of the five security
   headers ... it is a NOT NULL violation surfaced through the exception mapper
   Keycloak installs for every constraint violation."** The behaviour is right
   and the explanation is not. `PUT /admin/realms/{r}/default-default-client-scopes/{id}`
   twice answers the identical body with **all five**, and that is a unique
   constraint violation. Measured side by side. §1.9.

**A fifth line, not contradicted but extended.** "**On a role mapping,
`briefRepresentation` is honoured by `.../composite` alone**" is now true of a
third family. That is the first parameter rule in this project to generalise; it
was still measured on the two new triples rather than carried over, and the
bullet should say which families it covers.

---

## 3. Follow-up dispositions

### F78: measured, corrected, and **not closed**

**Not closed on this branch, and the reason is that closing it correctly is a
bigger and differently-shaped piece of work than the follow-up describes.**

What the measurements changed (§2.1.3):

- Uniqueness is **server-wide**, not realm-wide, so the check is a scan of every
  client scope and every client in **every realm**, not one realm.
- **Five** write routes enforce it, not three: `POST /client-scopes`,
  `POST /clients`, `PUT /clients/{uuid}`, `POST .../protocol-mappers/models` and
  `POST .../protocol-mappers/add-models`.
- The message is decided by **where** the collision is, not by which route asked.

Why it did not land here:

1. **It needs an index, and an index needs a migration.** A server-wide scan of
   two JSON columns across every realm on five write paths is a performance and
   correctness decision, and this branch has already spent `0016` on something
   unrelated to it. A second migration for an unrelated follow-up inside a
   scope-mappings pull request is exactly the scope creep that makes a diff
   unreviewable.
2. **The cross-container 409 must ship with none of the five security headers**
   (§1.9). That is doable without `internal/httpx` -
   `httpx.WriteAuthorizationRedirect` already deletes a header the router set
   before the mux ran - but it would be the **first** admin-side response to do
   so, and it belongs beside the protocol-mapper family's other error shapes
   rather than here.
3. Gloak's own bootstrap is safe either way: `ensureClientScopes` mints a fresh
   `model.NewID()` per mapper per realm, so nothing Gloak creates for itself
   would trip the constraint.

**Suggested replacement text for F78:** *a protocol mapper id is unique across
the whole **server** in Keycloak and unique nowhere in Gloak. Five write routes
enforce it - `POST /client-scopes`, `POST /clients`, `PUT /clients/{uuid}`,
`POST .../protocol-mappers/models`, `POST .../protocol-mappers/add-models` - and
the 409 they send is decided by whether the colliding mapper is in the same
container (`Protocol mapper exists with same name` on `models`,
`Protocol mapper name must be unique per protocol` on `add-models`) or elsewhere
in the server (`Duplicate resource error`, and
`Client <clientId> already exists` on `POST /clients`). The elsewhere case ships
with **none** of the five security headers where the realm's default-client-scope
409 ships with all five. Closing it needs an index and therefore a migration.
The grid is in `docs/superpowers/handover/p5-scope-mappings.md` §2.1.3.*

### F61: not closed, and it is now measurably narrower than it says

F61 says `PUT /clients/{uuid}` accepting `defaultClientScopes` is unguarded in
Gloak. That is still true and this branch did not close it - the fixture that
would cost one line lives in the client-scope family, not this one, and it is
the same fixture cut B declined for the same reason.

What this cut adds is that **the same `PUT` now has a third array on it whose
rule is different again**. Cut B recorded that `protocolMappers` is honoured
where the two scope-name lists are ignored. This cut measured that the same
`PUT` also enforces the **server-wide protocol mapper id** (§2.1.3): a body
carrying a mapper id already in use anywhere answers 409 `Duplicate resource
error`. So `PUT /clients/{uuid}` has three arrays with three rules - two ignored,
one replaced, and the replaced one validated against a global constraint - and
F61 should name which one it means, which is what cut B already asked for.

### New follow-ups, to file

- **F81: `POST /users` ignores an inline `credentials` array.** Keycloak sets the
  password from it - every probe user in this cut's guard sweep was created that
  way and password-granted immediately - and Gloak drops it, so the same user
  cannot log in. Found by writing a fixture the short way: it recorded green
  against the reference container and then failed the verifier on the password
  grant, three cases at once. The fixture now uses `PUT .../reset-password`,
  which is what every other fixture in the file already does, and the divergence
  is unasserted by anything.
- **F82: the 415 is served on five routes and measured on more.** `PUT
  .../credentials/{id}/userLabel` has the mirror-image `@Consumes` rule -
  measured on 2026-08-27, recorded in a comment in `internal/admin/credentials.go`
  and served by nothing. This cut implements the check on its own four writes
  because that is where it measured it. Generalising it to every admin route
  needs its own sweep: `@Consumes` is a JAX-RS annotation and the rule is
  therefore global on Keycloak, but *which* media types each route declares is
  not.
- **F83: the third parse code is still unserved.** `[{` - a truncated array
  **element** - answers `{"error":"HTTP 400 Bad Request","error_description":"Cannot parse the JSON"}`
  on these four writes as it does on the role-array endpoints. Cut B left it and
  so does this one, for the same reason: telling it apart needs the decoder to
  report where in the document it stopped. It is F64's third code and the two
  entries should be merged.

### Bearing on existing follow-ups

- **F31** gains its seventh data point, §2.1.2, and it is the first one that
  *repeats* an existing shape rather than adding a new one: the scope mappings
  answer exactly as the role mappings do. Three Admin API families now answer
  three different ways. Nothing was changed.
- **F59** is not needed by this cut. Every array asserted here is at the root of
  its body, where `Case.Unordered`'s `"."` works, and the one nested array -
  `clientMappings/*/mappings` - is a single element in every golden. The hole
  F59 describes is untouched. `normalize.go` was not read or edited.
- **F64** gains its second family. `internal/admin`'s `decodeMapperBody` - the
  shape classifier cut B wrote and F64 asks for - is now used by the scope
  mappings' four writes as well as the protocol mappers' two, and
  `admin/scope-mappings/wrong-shape-body` and
  `admin/scope-mappings/truncated-array-body` are the pair that pin it there.
  The ten role-array endpoints still answer per endpoint.
- **F60** is the reason six of the seven `Client Attribute Certificate`
  operations cannot be cut yet, which is now on P5's critical path: see §4.

---

## 4. Parity before and after per chapter

`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1`

The branch's merge base is `a308eb0`. **`main` was not merged mid-flight**, so no
finding in this document needs re-checking against a commit this branch already
carries.

| | before | after | delta |
|---|---|---|---|
| total, measured locally at `a308eb0` | **205 of 499** | **238 of 499** | **+33** |
| total, CI against `main` as it stands | **209 of 500** | **242 of 500** | **+33** |

The two rows differ because `main` moved while this branch was open and CI
measures the merge, not the branch: P3's `authorization_code` grant and the
`javamap` sized-`HashMap` fix landed between the branch point and the pull
request. **The increment is the same both ways**, as it was for cut A.

One of those two is worth a note rather than a re-check. The `javamap` fix
changes `KeyOrder`'s model, and the combined scope-mapping view orders its
`clientMappings` keys through it. Nothing here depends on the part that changed:
every golden in this cut holds **at most one** `clientMappings` key, so no
ordering decision is exercised, and CI is green on the merge commit. The two
`clientMappings` keys measured on the reference container -
`gloak-probe-sm-client` before `master-realm` - are recorded in §1.8 and are
under no golden, which is a case somebody could add now that the model is
right.

```
chapter                         before  after  delta
admin/scope-mappings                 0     33    +33
```

`admin/scope-mappings` closes its tag outright: **33 of 33**. No other chapter
moved, which the plan predicted before any code was written: every route on this
tag is tagged `Scope Mappings`, unlike cut A, which delivered twelve operations
filed under `admin/clients` and `admin/realms-admin`.

+33 is exactly what the plan allocated, and the allocation held to the operation
for the third cut running.

### Does this complete P5?

**No.** The roadmap's P5 row is `Client Scopes 10, Protocol Mappers 21, Scope
Mappings 33, Client Attribute Certificate 7, Client Initial Access 3, Client
Registration Policy 1`. The first three are now closed and **eleven operations
remain**:

| Tag | Ops | Note |
|---|---|---|
| `Client Attribute Certificate` | 7 | six under `/clients/{uuid}/certificates/{attr}/...`, all six blocked on **F60** - a client created through the Admin API gets no keystore, which is P11's. The seventh, `POST /admin/realms/{realm}/identity-provider/upload-certificate`, is **P9's**: it is in this tag only because it uploads a certificate |
| `Client Initial Access` | 3 | `GET`/`POST /clients-initial-access`, `DELETE .../{id}` - dynamic client registration, which the roadmap also names under P7 |
| `Client Registration Policy` | 1 | `GET .../client-registration-policy/providers` |

So P5's row closes on a fourth cut of eleven operations, one of which belongs to
P9 and six of which are blocked on P11's keystore. The client-scope trilogy - the
thing P5 was staged around, and the thing the protocol mapper engine (F63) waits
on - is finished.

---

## 5. Mutation survivors

Twenty-three mutations, a different one per claim, each confirmed to fail a
named test and reverted. **Three survived on the first pass and all three are
now closed.** Two of them were findings about the tests and one was a finding
about the code.

1. **The combined view built from the direct-*scope* set rather than from the
   mappings.** `allScopeMappings` composes `sc.mappings()`; swapping it for
   `h.directScope()` - which adds a client's own roles - changed no golden,
   because **no container in the cut owned a role of its own**. Every fixture
   put the roles on a separate client on purpose, so the two sets coincided
   everywhere.

   Measured on the reference container before fixing it, on a client owning one
   role with `fullScopeAllowed` off and nothing mapped:

   ```
   GET .../scope-mappings                        {}
   GET .../scope-mappings/realm                  []
   GET .../scope-mappings/clients/{itself}       []
   GET .../scope-mappings/clients/{itself}/available   []
   GET .../scope-mappings/clients/{itself}/composite   [the owned role]
   ```

   So a client's own roles reach `available` and `composite` and reach neither
   direct read nor the combined view - which is what the code already did.
   Closed by one fixture line: `scope-mappings-full-scope`'s client now owns a
   role, and `admin/scope-mappings/full-scope-all` kills the mutation. **The
   case was wrong, not the code**, which is the same shape as cut B's first two
   survivors.

2. **The `if len(byClient) == 0 { return nil, nil }` early return in
   `scopeClientMappingsOf`.** Replacing it with `if false` changed nothing:
   `omitempty` on a slice drops an empty one whether it is nil or not, so the
   branch was **dead code**. Deleted, with the reason written at the site, and
   the absent-key rule is now pinned by mutating the struct tag instead -
   `admin/scope-mappings/refused-batch-writes-nothing` and
   `admin/scope-mappings/full-scope-all` both fail when `omitempty` comes off.

   This is the second time this project has met exactly this: cut B found
   `protocolMapperListOrNil` dead for the same reason on the same day. The
   general shape - "a nil-versus-empty guard in front of an `omitempty` slice" -
   is worth a sweep.

3. **`ON DELETE CASCADE` dropped from `client_scope_role_mapping.role_id`.** The
   store test deleted a mapped role and asserted the listing had lost it, and
   the listing **JOINs `keycloak_role`**, so an orphaned mapping row is
   invisible to every read the repository has. Dropping the foreign key changed
   no observable behaviour.

   Closed by making the constraint observable through the interface alone:
   delete the role, then create a new role **reusing its id**, and read the
   container back. With the cascade the row went with the old role and the new
   one starts unmapped; without it the orphan resurfaces under a role that was
   never mapped. A role id is a fresh UUID in every path that mints one, so this
   is only reachable through the store - which is the level the constraint lives
   at.

   It survived a second time after the first fix, because the first fix read the
   **other** table. They are two tables and the check now reads both.

The twenty that were killed on the first pass, with the case that killed each:

```
mayMapRole always true                    refused-realm-role
mayMapRole's two branches swapped         refused-realm-role, available-to-a-manage-clients-caller
available not caller-filtered             available-to-a-manage-clients-caller
available computed from hasScope          available-keeps-a-reachable-child
hasScope ignores fullScopeAllowed         full-scope-composite
directScope drops a client's own roles    a-clients-own-roles-are-in-scope
hasScope stops expanding composites       composite-expands-a-composite
the realm write refuses a client role     realm-write-lands-under-its-client
a missing id is 404 rather than 500       realm-write-without-an-id
the client write resolves by id           client-write-without-a-name and 9 more
the {client} 404 is `Client not found`    unknown-role-client
the coarse gate drops query-clients       to-a-query-clients-caller
the batch applies as it validates         refused-batch-writes-nothing
requireJSONBody removed                   unsupported-media-type
decodeRoleList instead of the classifier  truncated-array-body
composite ignores briefRepresentation     composite-brief-false
the clientMappings omitempty removed      refused-batch-writes-nothing, full-scope-all
ensureScopeMappings removed               TestBootstrappedScopeMappings
the two store tables merged into one      the store suite's scope-mapping subtest
the removes stop being idempotent         the store suite's scope-mapping subtest
scope_mapping's cascade dropped           the store suite's scope-mapping subtest
client-templates dropped from the loop    all eleven template cases
the client family not registered          all fourteen owner and client cases
the scope family given the client guard   all eleven client-scope cases
```

---

## 6. What was run

All green on the branch head:

```
CGO_ENABLED=0 go test ./...
make lint                                   (both vet invocations)
make oracle
go test -tags docker ./internal/store/postgres/
make record                                 (four runs; see below)
```

**`make record` moved no golden it was not asked to, across four runs.** The
first wrote the 51 new files and touched nothing else. The second, after a
`Volatile` path was widened, rewrote only the three files that needed it. The
third, after a fixture gained a step and a case was added, moved exactly one
file - the new one. The fourth, after `scope-mappings-full-scope`'s client
gained a role of its own to close a mutation survivor, moved **nothing at all**,
which is the measurement that says a client's own roles reach neither the
combined view nor either direct read. Silent on a clean checkout, four times,
on a branch that twice changed a fixture other cases share.
