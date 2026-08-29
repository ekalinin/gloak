# P5 cut A: what belongs in the documents this branch may not edit

Date: 2026-08-29
Branch: `feat/p5-client-scopes`
Plan: `docs/superpowers/plans/2026-08-29-p5-client-scopes.md`

Everything below was measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8091, on 2026-08-29, and
where it says two container starts agreed the container was removed and
recreated between them. Gloak was then run on port 8092 against the same
requests and the two compared body by body; anything this document reports as
served has been compared that way as well as through a golden.

This branch does not touch `AGENTS.md`, `README.md` or the three spec
documents, so what is owed to them is written out here.

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

### 1.1 The client scope representation

`GET /admin/realms/{realm}/client-scopes` and
`GET /admin/realms/{realm}/client-scopes/{id}` serve the identical body. 200,
`Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`, the
five security headers.

Key order:

```
id, name, description, protocol, attributes, protocolMappers
```

- `description` is **absent** when unset, not `""`.
- `attributes` is **always present**, `{}` when empty.
- `protocolMappers` is **absent** when the scope has none. `offline_access` is
  the one bootstrapped scope with no mappers and its body has **five** keys
  where every other scope's has six.

A protocol mapper's key order is
`id, name, protocol, protocolMapper, consentRequired, config`. `config` is a
Java map, as is `attributes`.

**There are three brief shapes of one object, decided by the route**:

| Route | Keys |
|---|---|
| `/client-scopes`, `/client-scopes/{id}` | the six above |
| `/default-{default,optional}-client-scopes` | `id, name, protocol` |
| `/clients/{uuid}/{default,optional}-client-scopes` | `id, name` |

The client's listing omits `protocol` on scopes that have one. One shared
serialiser would be wrong on two of the three.

### 1.2 A realm's fifteen client scopes

A realm created through `POST /admin/realms` gets the **same fifteen client
scopes as master, byte-identical modulo the UUIDs**, with the same
thirty-five protocol mappers, the same attributes and the same two default
sets. Verified by dumping both, stripping ids and sorting each scope's mappers
by name: zero differences across all fifteen. That is why
`internal/bootstrap/clientscopes.json` is one file rather than two.

The realm's own two sets:

```
default   role_list, saml_organization, AuthnContextClassRef,
          profile, email, roles, web-origins, acr, basic          (9)
optional  offline_access, address, phone, microprofile-jwt,
          organization                                            (5)
```

**Nine, not six.** The six in the old `bootstrap.defaultScopeNames` were the six
`openid-connect` ones; the three SAML scopes are in the realm's default set and
are filtered out only when an `openid-connect` client inherits from it.

**That listing's order is reproducible and the client's is not.** The nine came
back in exactly the order above on master and on a created realm, on two
separate container starts - four measurements, one order, neither alphabetical
nor by protocol. It is insertion order, and a scope added later by `PUT`
appears at the end. A **client's** two lists are the opposite: two clients
created minutes apart in one container came back with `roles` and `profile`
swapped. So the realm listing is asserted in order and the client listing is
sorted, and the existing note that "the client-scope name lists have no stable
order" is about the client's and should say so.

**The mapper order inside a scope is not reproducible either.** Six of the
fifteen scopes came back with a different `protocolMappers` order on two
container starts - `profile`'s fourteen mappers were in an entirely different
order both times.

### 1.3 Every status on the Client Scopes tag

`POST /admin/realms/{realm}/client-scopes`:

| Body | Status | Body |
|---|---|---|
| `{"name":"x","protocol":"openid-connect"}` | 201 | empty, absolute `Location`, **`Cache-Control: no-cache`**, no `Content-Type` |
| `{"name":"x"}` | 400 | `{"errorMessage":"Unexpected protocol"}` |
| `{"name":"x","protocol":"bogus"}` | 400 | the same message |
| `{"protocol":"openid-connect"}` | **500** | `{"error":"unknown_error","error_description":"For more on this error consult the server log."}` |
| `{}` | **500** | the same |
| `""`, `null` | **500** | the same |
| `{"name":"","protocol":"openid-connect"}` | 400 | `{"errorMessage":"Unexpected name \"\" for ClientScope"}` |
| `{` | 400 | `{"error":"invalid_request","error_description":"Cannot parse the JSON"}` |
| a taken name | 409 | `{"errorMessage":"Client Scope <name> already exists"}` |

Three things in that table are not obvious. An **absent** protocol and an
**invalid** one give the identical message. A **duplicate name conflicts
whatever the protocol says** - the same name under `saml` is still 409. And the
name is looked at **twice with the protocol check between the two halves**:
absent is the 500 and is checked first, present-and-empty is the 400 and is
checked last, which is why `{}` answers about the name and `{"name":"x"}`
answers about the protocol.

`PUT /client-scopes/{id}`: 204 with **no `Cache-Control`**; 404
`{"error":"Could not find client scope"}` for an unknown id; 409 for a taken
name; 400 for a malformed body; **500 `unknown_error` when the body omits
`name`**, the same as the create.

`DELETE /client-scopes/{id}`: 204 **with** `Cache-Control: no-cache` and no
`X-Frame-Options`; 404 for an unknown or already-deleted id.

`GET /client-scopes/{id}`: 404 `Could not find client scope` for an unknown id
**and for a path segment that is not a UUID at all** - not a 400.

**`POST /client-scopes`'s 201 carries `Cache-Control: no-cache` where
`POST /clients`'s does not.** Two creates on one API, one with the header and
one without.

**The body's `id` wins on create.** A `POST` naming
`11111111-1111-1111-1111-111111111111` created a scope with exactly that id and
put it in `Location`. The same is true of `POST /clients`. Minting one
regardless is the obvious implementation and it is wrong.

**`PUT` on a client scope merges, like a client and unlike a role.** A body
carrying only `name` keeps the description and the attributes;
`"attributes":{}` does **not** clear them; the protocol can be changed through
it and so can the name.

### 1.4 `client-templates` is a path alias, and it echoes its own path

All five `client-templates` operations serve what their `client-scopes` sibling
serves - the same fifteen, a byte-identical single read, a working `DELETE`.
**With one difference**: `POST /client-templates` answers a `Location` under
`/client-templates`, not under `/client-scopes`. It is the only place in a
response where the two spellings are distinguishable.

### 1.5 The realm's two default sets

`GET /default-default-client-scopes`, `GET /default-optional-client-scopes`:
200, `application/json;charset=UTF-8`, `Cache-Control: no-cache`.

`PUT .../{clientScopeId}`: 204 with `Cache-Control: no-cache` the first time and
**409 `{"error":"conflict","error_description":"Duplicate resource error"}` the
second** - and also 409 for putting into one list a scope already in the
**other**. That is what says the two sets are one row carrying a flag rather
than two lists.

`DELETE .../{clientScopeId}`: 204 whether or not the scope was in the list, and
404 `{"error":"Client scope not found"}` for a scope that does not exist.

**The `DELETE` ignores which list its path names.** `DELETE
/default-default-client-scopes/{id}` removed a scope that was in the realm's
**optional** list. Measured on the client routes too. So the `PUT` is
list-specific and the `DELETE` is not, and making the two verbs symmetrical is
the tidy-up that breaks it.

**`PUT .../default-default-client-scopes/{id}` is not idempotent where
`PUT .../default-groups/{groupId}` is.** Two neighbouring realm-level `PUT`s,
opposite answers to the repeat.

### 1.6 A client's two sets

`PUT /clients/{uuid}/{default,optional}-client-scopes/{id}` is **204 and silent
in three cases that change nothing**:

- the scope is already in that list;
- the scope is already in the **other** list - it is **not moved**;
- the scope's protocol is not the client's - a `saml` scope offered to an
  `openid-connect` client is 204 and is not attached.

To move a scope between a client's two lists you have to `DELETE` it from one
and `PUT` it into the other. The `DELETE` ignores its own list, as above.

404s: `{"error":"Could not find client"}` for an unknown client,
`{"error":"Client scope not found"}` for an unknown scope.

**Deleting a client scope cascades.** It leaves every client's lists and both
of the realm's, measured in both places.

**A built-in client scope can be deleted with no protection at all.**
`DELETE .../client-scopes/{microprofile-jwt id}` is 204 and the realm is left
with fourteen.

**Renaming a client scope cascades too**: the attachment survives and the name
in every client's list and in both of the realm's follows the rename. That is
what says the attachment is stored by id.

### 1.7 What a client created through the API inherits (follow-up F49)

Measured over nine bodies on `POST /admin/realms/{realm}/clients`:

```
{}                                                6 defaults, 5 optionals
{"defaultClientScopes":null}                      6 defaults, 5 optionals
{"optionalClientScopes":null}                     6 defaults, 5 optionals
{"defaultClientScopes":["email"]}                 ["email"] and **[] optionals**
{"defaultClientScopes":[]}                        [], []
{"optionalClientScopes":["phone"]}                **[] defaults**, ["phone"]
{"optionalClientScopes":[]}                       [], []
{"default...":["email"],"optional...":["phone"]}  exactly those
{"default...":null,"optional...":["phone"]}       [], ["phone"]
```

**Inheritance is all-or-nothing across the pair.** Naming *either* list - as an
array, empty or not - suppresses inheritance on **both**. A per-list nil check
gives a client that asked for one default the realm's five optionals as well,
which is what the first implementation on this branch did.

Inheritance is filtered by the client's protocol. A `saml` client created bare
inherits `AuthnContextClassRef, role_list, saml_organization` and no optionals,
out of the same nine and five.

A name the realm does not have is **dropped in silence**: a client created
naming `nosuchscope` answers 201 and reads back with an empty list.

**`PUT /clients/{uuid}` ignores both lists entirely.** Neither
`"defaultClientScopes":["email"]` nor `"defaultClientScopes":[]` changes
anything; both answer 204. The two lists are write-once at create, and
afterwards only the four dedicated routes move them.

### 1.8 The creation defaults for a client, which were wrong in six more ways

F49 named the client scopes. Measuring `POST /clients` with `{"clientId":"x"}`
alone found five more fields Gloak got wrong, and they are coupled to the
scopes: with no `protocol` the protocol filter matches nothing, so the scopes
cannot be right until the protocol is.

| Field | Keycloak's default | Gloak served |
|---|---|---|
| `standardFlowEnabled` | `true` | `false` |
| `fullScopeAllowed` | `true` | `false` |
| `protocol` | `"openid-connect"` | absent |
| `nodeReRegistrationTimeout` | `-1` | `0` |
| `name` | **absent** | `""` |
| `attributes` on a **public** client | `{"realm_client":"false"}` | plus `client.secret.creation.time` |

Every one of them is honoured as sent when the body does send it, including
`"standardFlowEnabled":false`, so the defaults have to be in place **before**
the decoder runs rather than applied after it - an absent key and a `false` are
one Go value. `internal/admin`'s `decodeNewClient` does that, which is the trick
`updateClient` already used to merge over the stored representation.

`name`, `rootUrl`, `baseUrl` and `description` are all **absent unless the body
sent the key**, and present as `""` when the body sent `""`. Gloak now carries
`omitempty` on all four, which reproduces the first and not the second;
reproducing both means a `*string` on four fields to serve a body nobody sends.
That is a knowing divergence and it is written at the field.

### 1.9 A `saml` client gets a keystore, and that is P11

`POST /clients` with `"protocol":"saml"` answers 201 with **ten extra
attributes** - `saml.signing.certificate`, `saml.signing.private.key`,
`saml.signature.algorithm`, `saml.artifact.binding.identifier`,
`saml.force.post.binding`, `saml.server.signature`, `saml.client.signature`,
`saml.authnstatement`, `saml.allow.ecp.flow`, `saml_name_id_format`,
`saml_force_name_id_format`, `saml_signature_canonicalization_method` - and
`frontchannelLogout: true`. Gloak serves none of them.

Not in this cut: it is SAML client registration and belongs with P11. Its
*client scopes* are right, which is what P5 owed.

### 1.10 The guards

Swept one role at a time over a probe user holding exactly one `master-realm`
role, across eight candidates, on twelve routes.

| Route | Read | Write |
|---|---|---|
| `GET /client-scopes` | `view-clients`, `manage-clients`; **`query-clients` gets 200 and `[]`** | - |
| `GET /client-scopes/{id}` | `view-clients`, `manage-clients` | - |
| `POST`/`PUT`/`DELETE /client-scopes[/{id}]` | - | `manage-clients` alone |
| `GET /default-{default,optional}-client-scopes` | `view-clients`, `manage-clients` | - |
| `PUT`/`DELETE /default-*-client-scopes/{id}` | - | `manage-clients` alone |
| `GET /clients/{u}/{default,optional}-client-scopes` | `view-clients`, `manage-clients` | - |
| `PUT`/`DELETE /clients/{u}/*-client-scopes/{s}` | - | `manage-clients` alone |

Two findings.

**The three `Realms Admin` routes are guarded by the clients role family.**
`view-realm` and `manage-realm` are 403 on `default-default-client-scopes` and
`default-optional-client-scopes`, both verbs, both lists, and `view-clients`
reads them. The description's tag says Realms Admin and the guard says clients.

**`query-clients` gets a filtered listing, not a refusal**: 200 with `[]` where
`view-clients` gets 200 with fifteen. That is the client listing's shape, and
the third time this API has answered a weaker caller with a shorter list rather
than a 403.

`create-client` is in none of it: 403 on every route above, including the paths
where `query-clients` gets a 404.

### 1.11 Three resolution orders on one resource

```
/client-scopes/{id}                  realm -> coarse gate -> SCOPE (404) -> fine role (403)
/clients/{u}/*-client-scopes/{s}     realm -> coarse gate -> CLIENT (404) -> fine role (403) -> SCOPE (404)
/default-*-client-scopes/{id}        realm -> fine role (403) -> SCOPE (404)
```

Measured directly. `view-clients` naming a scope that does not exist gets
**404** on `DELETE /client-scopes/{id}` and **403** on
`PUT /default-default-client-scopes/{id}` - the same caller, the same missing
object, opposite answers on neighbouring routes. On the client family it gets
404 for an unknown client and 403 for a known client with an unknown scope, so
the client is resolved before the write role and the scope after it.

The coarse gate is `{view-clients, query-clients, manage-clients}`. A caller
holding none of the three gets 403 even for a scope that does not exist, so the
existence leak is to a client-reading caller only.

### 1.12 Two more spellings of not-found

**`Could not find client scope`** from `/client-scopes/{id}`, and **`Client
scope not found`** from the realm's default-scope routes and from a client's -
for the very same missing object, decided by which route went looking. That
takes the admin API's count from twelve to **fourteen**, and it is the second
resource after the group to have more than one spelling.

### 1.13 A real 405, on a whole route family

```
PUT    /admin/realms/master/client-scopes        405 {"error":"HTTP 405 Method Not Allowed"}
DELETE /admin/realms/master/client-scopes        405 same
POST   /admin/realms/master/client-scopes/{id}   405 same
PATCH  /admin/realms/master/client-scopes/{id}   405 same
```

`application/json`, all five security headers, **no `Allow`**, no
`Cache-Control`. Gloak answers 404 to all four. See section 3.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Ready to paste, in that file's voice.

- **A client scope's two lists on a client are one attachment with a flag, and
  the two verbs disagree about which list they mean.** `PUT
  .../default-client-scopes/{id}` naming a scope the client already holds as an
  **optional** scope answers 204 and moves nothing; to move it you delete it
  from one list and put it into the other. `DELETE
  .../default-client-scopes/{id}` then **ignores the list its own path names**
  and removes the scope from whichever list holds it - measured on the client
  routes and on the realm's. Giving the delete a list argument to make the pair
  symmetrical is the tidy-up that breaks it.
- **The realm's `PUT` is a 409 on the repeat where the client's is a 204.** Two
  neighbouring writes on one resource:
  `PUT /admin/realms/{r}/default-default-client-scopes/{id}` twice answers
  `{"error":"conflict","error_description":"Duplicate resource error"}`, and so
  does putting into one of the realm's lists a scope already in the other -
  which is what says they are one row. `PUT
  /clients/{uuid}/default-client-scopes/{id}` twice answers 204 both times.
  `PUT .../default-groups/{groupId}` is idempotent too, so the realm-level
  client scope write is the odd one.
- **A client scope attached to a client of the wrong protocol is a silent
  no-op.** A `saml` scope offered to an `openid-connect` client answers 204 and
  attaches nothing; the representation confirms it. So does an unknown scope
  *name* at create time - 201 and an empty list. Both are refusals that look
  like successes.
- **A client inherits the realm's client scopes only when it names **neither**
  list.** Measured over nine creation bodies: naming either list, as an array,
  empty or not, suppresses inheritance on **both**, so
  `{"defaultClientScopes":["email"]}` produces a client with one default and
  **no** optionals rather than one default and the realm's five. A per-list
  nil check is the obvious implementation and it is wrong. `PUT /clients/{uuid}`
  ignores both lists outright, so they are write-once at create and only the
  four dedicated routes move them afterwards.
- **A client scope's `name` is looked at twice, with the protocol check between
  the halves.** An **absent** name is a 500 `unknown_error` - Keycloak's own
  defect, the same family as an empty body on `POST /users` - and is checked
  first; a **present and empty** name is a 400 naming the empty string and is
  checked last. That is why `{}` answers about the name and `{"name":"x"}`
  answers about the protocol. An absent protocol and an invalid one give the
  identical `Unexpected protocol`, so the protocol check is membership rather
  than presence.
- **`protocolMappers` is absent rather than empty.** `offline_access` is the one
  bootstrapped client scope with no mappers and its representation has **five**
  keys where every other scope's has six. `attributes` goes the other way and is
  always present, `{}` when empty. Two neighbouring keys on one body, opposite
  rules.
- **The body's `id` wins on create**, on `POST /client-scopes` and on
  `POST /clients` alike: a create naming an id produced an object with exactly
  that id and put it in `Location`. It is what lets a conformance fixture know
  an object's id before it asks for it, which is how P5's fixtures avoid the
  capture-from-`Location` hazard the shared container creates.
- **`client-templates` is a path alias for `client-scopes` that echoes its own
  path.** All five operations serve what their sibling serves, byte for byte,
  with one exception: `POST /client-templates` answers a `Location` under
  `/client-templates`. Building that header from a constant rather than from
  `r.URL.Path` sends a caller of the deprecated path to the other one.
- **The three shapes of a client scope are decided by the route, not by a
  `briefRepresentation` parameter.** Six keys on `/client-scopes`, three
  (`id, name, protocol`) on the realm's two default listings, and **two**
  (`id, name`) on a client's - the client's omits `protocol` on scopes that have
  one. A shared serialiser would be wrong on two of the three.
- **The client-scope family is authorised out of the clients role set, and that
  includes the routes the description tags `Realms Admin`.** `view-realm` and
  `manage-realm` are 403 on `default-default-client-scopes` and
  `default-optional-client-scopes`, both verbs; `view-clients` reads them and
  `manage-clients` writes them. That is the second time the description's tag
  has failed to predict the guard, and the first time it has failed in this
  direction.
- **`query-clients` gets the client-scope listing as 200 and `[]`.** Not a 403.
  The coarse gate admits it and the handler empties the body, the same way
  `GET /clients` does - the third instance of "200 with a shorter list to a
  weaker caller".
- **Three resolution orders on one resource.** On `/client-scopes/{id}` the
  scope is resolved **before** the caller's write role, so a `view-clients`
  caller gets 404 for a scope that does not exist and 403 for one that does. On
  `/default-*-client-scopes/{id}` the role comes first, so the same caller gets
  403 for the same missing scope. On `/clients/{u}/*-client-scopes/{s}` the
  **client** comes first, the role second and the scope third. Three routes on
  one object, three orders, and the missing scope has **two** spellings on top
  of that: `Could not find client scope` from the first family and `Client scope
  not found` from the other two.
- **A realm's fifteen client scopes are identical in every realm.** A realm
  created through `POST /admin/realms` gets the same fifteen as master, the same
  thirty-five protocol mappers, the same attributes and the same two default
  sets, byte for byte once the UUIDs are stripped. But **the realm's default
  set is nine, not the six a client carries**: the three SAML scopes are in it
  and are filtered out when an `openid-connect` client inherits.
- **The realm's default-scope listing has a reproducible order and a client's
  does not.** `role_list, saml_organization, AuthnContextClassRef, profile,
  email, roles, web-origins, acr, basic` came back on master and on a created
  realm on two separate container starts - insertion order, with a scope added
  by `PUT` appearing at the end. A client's two lists swapped `roles` and
  `profile` between two clients created minutes apart in one container, and the
  protocol mappers inside six of the fifteen scopes came back in a different
  order on two container starts. So one of the three is asserted in order and
  the other two are sorted.

### 2.1 Lines in AGENTS.md these measurements contradict

**Two, and the second is the more useful.**

1. **"A wrong method on a known path returns 404, not 405, with no `Allow`
   header"** is now measured too broad a **fourth** time, and this is the
   cleanest instance yet: `PUT` and `DELETE` on `/admin/realms/{r}/client-scopes`
   and `POST` and `PATCH` on `/admin/realms/{r}/client-scopes/{id}` all four
   answer a real **405** `{"error":"HTTP 405 Method Not Allowed"}`, with
   `application/json`, all five security headers, **no `Allow`** and no
   `Cache-Control`. Every previous data point was a mixture within one path
   family; this is a whole route family answering 405 uniformly. The existing
   bullet says "three data points that disagree still do not say what the rule
   is" - there are four now, and the count in that sentence needs updating even
   if the conclusion does not. Gloak still answers 404, because the decision is
   in `internal/oidc`'s `WithKeycloakFallbacks` and this branch may not touch
   it. See F31, and section 3.

2. **"The client-scope name lists have no stable order"** is stated in the
   observed document about `defaultClientScopes` and `optionalClientScopes` and
   is **true of a client's and false of the realm's**. The realm's
   `default-default-client-scopes` listing was measured in one order four times
   across two container starts and two realms. The sentence should say which of
   the two it is about; as written it would have had this cut mask an assertion
   it can make.

3. Not a contradiction but a count: **"Twelve spellings of not-found in the
   admin API now"** becomes **fourteen** with `Could not find client scope` and
   `Client scope not found`. That bullet already records having been wrong once
   by being incremented rather than counted, so it is worth re-counting the list
   rather than adding two.

## 3. Follow-ups to file or close

**F49 is closed on this branch**, and it was smaller than the whole defect.
Keycloak fills a client's two scope lists from the realm's own default sets,
filtered by protocol, when the body names neither. `bootstrap.InheritClientScopes`
does that and `internal/admin`'s `createClient` calls it, and the two conformance
cases F49 blocked - `admin/clients/read-created` and
`admin/clients/read-described` - are `Implemented` and matching. `/auth` now
accepts `scope=profile` on a client created through Gloak's own admin API,
which was F49's stated consequence.

Fixing it required fixing §1.8's five other creation defaults first, because
with no `protocol` the inheritance filter matches nothing. Those five were not
in F49 and nobody had looked.

**New follow-ups, to file:**

- **F58: `Case.Unordered` cannot sort a nested array inside an array it also
  sorts at the root.** `editor.sortArray` decodes the value it matched in one
  go, so a path matching the root consumes the document and the nested paths are
  never visited - `Unordered: {".", "*/protocolMappers"}` silently sorts only
  the first, with no error. It is silent, which is the part that matters: the
  case looks like it asserts the mapper set and does not. Both orders here are
  unstable, so `admin/client-scopes/list` masks `*/protocolMappers` whole and
  the thirty-five bootstrapped mappers are under no golden.
  `TestBootstrappedClientScopeMappers` in `internal/admin` asserts one scope's
  fourteen mappers and one full config directly, which closes the hole for the
  richest of them and not for the rest. The fix is in `normalize.go`, which this
  branch may not touch.
- **F59: a `saml` client created through the Admin API gets no keystore.**
  §1.9. Keycloak generates a signing certificate and private key and sets twelve
  `saml.*` attributes and `frontchannelLogout: true`; Gloak sets none of them.
  P11.
- **F60: `PUT /clients/{uuid}` accepting `defaultClientScopes` is unguarded in
  Gloak.** Keycloak ignores both lists on the update path, measured. Gloak also
  ignores them, because `clientRepo.Update` does not touch the attachment table -
  but nothing asserts it, and the merge in `updateClient` does carry the lists
  through `newClientFrom`. A case would cost one fixture.
- **F61: `scopes_supported` is still a constant.** The parity roadmap's §6
  second debt. `internal/oidc/discovery.go` emits a list no model backs; the
  realm's client scopes now exist and could back it. Not in this cut because
  `internal/oidc` was another agent's file this session.
- **F62: the protocol mapper engine is still staged.** Roadmap §6's first debt.
  This cut **stores** all thirty-five mappers and serves them in the client
  scope representation, and token issuance still reproduces the measured claim
  set directly rather than deriving it. That was the plan; the prerequisite is
  now in place and the note should say so rather than saying nothing exists.

**Bearing on an existing follow-up:**

- **F31** gains its fourth data point, §1.13. Nothing was changed on the
  strength of it.
- **F53** - "which other goldens enumerate a realm-wide set without claiming
  `PristineRealm`?" - **found one, in this cut, before it shipped.**
  `admin/clients/default-client-scopes` reads a client's inherited defaults; two
  cases earlier in the catalogue add a scope to master's default set, so the
  recorder wrote seven entries where a pristine replay serves six. It does not
  look like a realm-wide body, which is exactly F53's point. Both it and its
  optional sibling now carry `PristineRealm`. The sweep F53 asks for is still
  worth doing.

## 4. Parity before and after

`CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1 -v`

| | total |
|---|---|
| `main` (merge base) | **147 of 489** |
| `feat/p5-client-scopes` | **169 of 489** |

**+22**, which is exactly the 22 operations the plan allocated to this cut.

```
chapter                         before  after  delta
admin/client-scopes                  0     10    +10
admin/clients                       10     16     +6
admin/realms-admin                  15     21     +6
```

`admin/client-scopes` closes its tag outright: 10 of 10. `admin/realms-admin`
goes to 21 of 45, and the six added are the ones P4's row said belonged to P5.
`admin/clients` goes to 16 of 35, and its six are the ones nobody had allocated
anywhere - see §1.3 of the plan.

The plan predicted 22 before any of it was built and the allocation held to the
operation, as P2's third cut's did.
