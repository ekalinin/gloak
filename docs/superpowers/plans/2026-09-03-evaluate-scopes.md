# The `evaluate-scopes` family

Seven operations under the `Clients` tag, computed from the vendored description
rather than taken from the brief:

```
GET .../clients/{client-uuid}/evaluate-scopes/generate-example-access-token
GET .../clients/{client-uuid}/evaluate-scopes/generate-example-id-token
GET .../clients/{client-uuid}/evaluate-scopes/generate-example-userinfo
GET .../clients/{client-uuid}/evaluate-scopes/generate-example-saml-response
GET .../clients/{client-uuid}/evaluate-scopes/protocol-mappers
GET .../clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/granted
GET .../clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/not-granted
```

The brief's list of seven is confirmed: a filter over `paths` in
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` for
`evaluate-scopes` yields exactly these, all `GET`, all tagged `Clients`.

Everything below was measured against a live 26.7.1 on `localhost:8170`
2026-09-05, never written from memory.

## 1. Which shape the example-token boundary takes, and what that decides for F148

### The three shapes, and why the answer is not "whichever is quickest"

F148 defers the same question for `POST .../policy/evaluate` and
`POST .../permission/evaluate`: their 200 mints an RPT, an access token's claim
set, and `internal/token` owns that. The brief offers three shapes. The measured
facts decide between them, and the decision is **not uniform across the four
`generate-example-*` operations** - which is itself the finding.

**Shape 2 is right, and it is not "an interface that exists only for this".**
`internal/token` already has the precedent, in the same package, doing the same
job:

```go
// introspect.go, on Introspection
// It lives beside the claim sets rather than in internal/oidc because that is
// what it is: the same claim set, one key order, changed in one place.
```

`Introspection` is an exported struct with an exported `Introspect` builder;
`internal/oidc` supplies the inputs and serves the result as an ordinary JSON
body, byte for byte. An example token is the third member of that family, not a
new kind of thing. So the interface shape is already chosen: **the caller
resolves the inputs and `internal/token` renders the claim set.** `Request`
already works that way on purpose -

```go
// RealmRoles and ClientRoles are passed in rather than looked up here: this
// package signs claim sets and does not reach a store.
```

**Shape 1 is refused for the reason F148 gives.** A claim set built in
`internal/admin` is a second answer to "what does an access token look like",
and the first place it would disagree is the one nobody looks at - key order.

### What that decides for F148

**The same way.** The RPT is an access token's claim set, so it is
`internal/token`'s, and `internal/admin`'s authorization engine passes the
evaluated permissions in the way `IntrospectionRequest` passes roles. The two do
not differ, and this cut is the working precedent for it: an admin-side handler
resolving inputs and calling `internal/token` to render a claim set.

### The part of the answer that is not "build it"

Shape 2 says **where** the claim set is built. It does not say the claim set can
be built at all, and for two of the four generators it measurably cannot - for
two different reasons, both boundary reasons:

- **`generate-example-userinfo` is refused this cut.** Its body is the userinfo
  document, whose one truth is `userinfoDocument` in
  `internal/oidc/userinfo.go`. `internal/oidc` is out of bounds for this cut, so
  serving it means declaring the userinfo shape a second time. That is shape 1
  wearing a different hat, and it is refused on exactly F148's grounds. The
  operation is not hard; it is one `git mv` of a struct away, on a branch allowed
  to touch `internal/oidc`.

- **`generate-example-saml-response` is refused outright, and see §3.**

The other two - `generate-example-access-token` and `generate-example-id-token` -
are built through `internal/token`, and their fidelity is **exactly** the
issuance path's, no more and no less. That is the point of putting them there:
a preview that disagreed with the tokens Gloak actually issues would be worse
than one that agrees. Where Keycloak's claim set is richer than Gloak's, the
gap is the pre-existing P5 one that `internal/token/claims.go`'s own package
comment declares, reached through a new door rather than created here.

## 2. What each of the four `generate-example-*` bodies contains, including every per-request value

Measured on `master`, client `account`, user `admin` (the default install's own
state), and on a purpose-built realm `gloak-probe-eval` whose user carries
`firstName`, `lastName` and `email`.

### `generate-example-access-token`

```
account + admin
{"exp":…,"iat":…,"jti":"onrtna:…","iss":"…/realms/master","sub":"…","typ":"Bearer",
 "azp":"account","sid":"wf6Mmr1H3-bYD-kwD1aQi3Jm","acr":"1",
 "resource_access":{"account":{"roles":["manage-account","manage-account-links","view-profile"]}},
 "scope":"email profile","email_verified":false,"preferred_username":"admin"}
```

That is `internal/token`'s `accessClaims` exactly, with `aud`,
`allowed-origins`, `realm_access` and `auth_time` absent for the four measured
reasons the struct already documents.

**Per-request values: four.** `exp`, `iat`, `jti`, `sid`. Nothing else moves
between two identical requests.

- `exp - iat` is the realm's access token lifespan: 60 on `master`, 300 on a
  created realm. It is not a constant of the endpoint.
- `jti` carries the **`onrtna:` grant prefix**, which is a fifth spelling beside
  F86's four and consistent with F140's "the count grows with the grants". The
  ID token's `jti` carries **no** prefix. Gloak mints a bare UUID for both,
  which is F86 and is not this cut's to close.
- `sid` is a fresh 24-character session id **for a session that does not exist**.
  The endpoint mints a throwaway one per request.

**The claim set is the user's roles filtered by the client's scope**, which is
why this operation and `granted` are one measurement seen twice: `account` has
`fullScopeAllowed` off and no realm role in scope, so `realm_access` is absent
although `admin` holds five realm roles.

### `generate-example-id-token`

```
{"exp":…,"iat":…,"jti":"54fe97e7-…","iss":"…","aud":"account","sub":"…","typ":"ID",
 "azp":"account","sid":"rP5JkIv2G0OFCwRmokIwfKX4","acr":"1",
 "email_verified":false,"preferred_username":"admin"}
```

`idClaims` exactly, **minus `at_hash`**: no access token was minted, so the
claim is absent rather than empty. `idClaims.AtHash` carries no `omitempty`
today and would emit `"at_hash":""`. Same four per-request values.

### `generate-example-userinfo`

```
{"sub":"…","email_verified":false,"preferred_username":"admin"}
```

**No per-request value at all** - the one body in this family a golden could
hold unmasked. Refused for the boundary reason in §1, not for a measurement one.

### `generate-example-saml-response`

A JSON **string** at the root of the body holding a SAML `<samlp:Response>`, and
see §3.

### The parameters

| parameter | measured |
|---|---|
| absent `userId` | 404 `{"error":"No userId provided"}` on all four |
| unknown `userId` | 404 `{"error":"No user found"}` |
| `scope=<optional scope name>` | adds that scope's mappers, roles and scope word |
| `scope=nosuchscope` | **200**, silently ignored |
| `audience=<a client not in scope>` | 404 `{"error":"Requested audience not available: <name>"}` |
| `audience=<a client that does not exist>` | **200**, silently ignored |
| `audience=<the client itself>` | 404 - a client is never its own audience |

The two silent ignores are the shape this project files under "things that look
like bugs and are not": an audience naming nothing is dropped and an audience
naming something out of scope is a 404.

## 3. `generate-example-saml-response`: measured, and refused

**It is not gated by the client's protocol.** An `openid-connect` client answers
it with a real SAML assertion, and a `saml` client answers the three OIDC
generators with token-shaped bodies. The protocol decides the *content*, never
whether the route answers.

The `openid-connect` client's body is a 1485-byte JSON string; the SAML client's
adds an `AuthnStatement` and an `AttributeStatement` naming every role. Between
two identical requests these move:

- two `ID="ID_<uuid>"` attributes, on the `Response` and on the `Assertion`;
- `IssueInstant` twice, measured **two milliseconds apart** within one response;
- `NotBefore`, `NotOnOrAfter` twice, and `SubjectConfirmationData/@NotOnOrAfter`;
- on a SAML client, `AuthnInstant`, `SessionNotOnOrAfter` and a `SessionIndex`
  holding a fresh session id;
- the `AttributeStatement`'s role order, which is a Java set's.

Three reasons to refuse it, any one sufficient:

1. **Gloak serves no SAML at all.** There is no assertion builder, no
   `saml`-protocol issuance path and no signing surface for one. Writing one
   inside `internal/admin` is a whole protocol in the admin package.
2. **A golden cannot hold it.** The harness has no mask that reaches inside a
   JSON string: `Volatile` replaces a whole JSON value, and masking the whole
   body asserts its type and nothing else - the retreat AGENTS.md records under
   "a mask is a path". No committed golden has a root-level JSON string body.
3. **It cannot be `Recorded` either.** AGENTS.md: a response carrying a
   per-request value cannot be, "because `Recorded` is a promise the recorder has
   to be able to keep" - the same reason
   `GET .../instances/{alias}/export`'s SAML branch cannot be.

So it goes into the catalogue as `Pending` with a `Reason` naming all three, and
no golden. That is what `Pending` is for.

## 4. The three operations that mint nothing

These need no token machinery and are pure store reads. They are also **not the
neighbouring family with a prefix**, which was measured rather than assumed.

### `protocol-mappers`

An array of `{mapperId, mapperName, containerId, containerName, containerType,
protocolMapper}` - every mapper of every client scope linked to the client, plus
the client's own. Measured on `account`: 23 rows, `containerType` `client-scope`
throughout, grouped in the client's own default-scope order.

Two things a reader would get wrong:

- **A client's own mapper has `containerType:"client"` and
  `containerName:""`** - an empty string, even on a client carrying a `name`.
  Measured by setting one and re-reading. The client's own mappers come last.
- `scope=<optional scope>` adds that scope's mappers; `scope=nosuchscope` is a
  200 that adds nothing.

### `granted` and `not-granted`

`granted` is the roles of the named container that are in the client's scope;
`not-granted` is that container's remaining roles. `roleContainerId` is the
realm's **name** or a client's **UUID** - the realm's own id is a 404 and so is
a client's `clientId`. An unknown one is
404 `{"error":"Role Container not found"}`, a spelling this API did not have.

**`granted` is measurably not `.../scope-mappings/realm/composite`.** On a
client with `fullScopeAllowed` off, one realm role mapped directly (composite
over a second) and a linked client scope carrying a scope mapping to a third:

```
evaluate-scopes/.../granted        r1, r2, r3
scope-mappings/realm/composite     r1, r2
scope-mappings/realm               r1
```

The third role arrives through the **linked client scope's** own scope
mappings, which the neighbour does not read. `scope=<optional scope>` adds a
fourth. So the evaluated scope has two inputs the neighbour has none of, and
pointing the existing handler at this route would be wrong on both.

## 5. Guards

Swept one role at a time over eleven single master-realm admin roles plus a
caller holding nothing, with `GET /admin/realms/master/clients` as a control
known to differ (200 for the three client roles, 403 for the rest).

```
                       CONTROL  the four generators   the other three
view-clients             200            403                 200
manage-clients           200            403                 200
query-clients            200            403                 403
every other single role  403            403                 403
```

**The four generators refuse every single role**, so a conjunction sweep
followed:

```
view-clients  + view-users     200      manage-clients + view-users    200
view-clients  + manage-users   200      manage-clients + manage-users  200
view-clients  + query-users    403      query-clients  + view-users    403
view-clients  + impersonation  403      view-clients   + view-realm    403
```

So the generators need **a client-read role and a user-read role held
together**, `query-clients` and `query-users` opening neither half. That is the
second family in this API with `/roles/{name}/users`' conjunction shape.

The other three take `view-clients` or `manage-clients` and **refuse
`query-clients`** - so the guard is `clientsReadRoles` as the coarse gate and
`mayUseClientMappers(caller, false)` as the fine check, which is the protocol
mapper family's shape exactly.

The order, measured by varying which id is bad against four callers:

```
realm            404 "Realm not found." to everybody, including a caller with nothing
coarse gate      403 to a caller holding no clients role, even for an unknown client
client           404 "Could not find client" - query-clients gets this, so it is inside the gate
fine role check  403 to query-clients for a container that does not exist
userId presence  404 "No userId provided" to a view-clients caller holding no user role
user-read role   403 {"error":"You have no access to this user"} - its own sentence
user             404 "No user found"
```

`You have no access to this user` is a 403 body this API did not have.

## 6. Headers

Measured on all seven 200s and on eight refusals. Nothing here contradicts
AGENTS.md.

```
200      application/json;charset=UTF-8   Cache-Control: no-cache   five/five
4xx      application/json                 no Cache-Control          five/five
```

`POST`, `PUT`, `DELETE` and `PATCH` on `.../evaluate-scopes/protocol-mappers`
all answer a **real 405** `{"error":"HTTP 405 Method Not Allowed"}`, which is the
client scopes' answer rather than the 404 Gloak sends. Recorded, not changed -
F31.

## 7. What gets built

| operation | status | why |
|---|---|---|
| `protocol-mappers` | Implemented | store read |
| `scope-mappings/{c}/granted` | Implemented | store read |
| `scope-mappings/{c}/not-granted` | Implemented | store read |
| `generate-example-access-token` | Implemented | shape 2, through `internal/token` |
| `generate-example-id-token` | Implemented | shape 2, through `internal/token` |
| `generate-example-userinfo` | Pending | its truth is `internal/oidc`'s, out of bounds |
| `generate-example-saml-response` | Pending | no SAML, and no golden can hold it |

Five of seven, with the boundary settled and the two refusals explained by the
boundary rather than by effort. `admin/clients` goes 23/35 to 28/35.

### The `internal/token` change

One exported entry point beside `Introspect`, and one struct-tag change:
`idClaims.AtHash` gains `omitempty`, because the example ID token has no
`at_hash` and a real one always does - so the tag is correct on both and no
issued token moves. Verified by the whole `oidc/token` golden set staying put.

### The inputs `internal/admin` resolves

- **the roles**: the user's effective roles, kept by the evaluated-scope
  predicate - the existing `hasScope` widened with the linked client scopes'
  own scope mappings, which is the difference §4 measures.
- **the scope string**: the client's default client scopes carrying
  `include.in.token.scope` other than `"false"`, plus the requested optional
  ones, in the client's own list order. That order is not reproducible across
  container starts, so the case masks it with `UnorderedWords`, exactly as
  `oidc/introspection/active-refresh-token` does.
- **a throwaway session**, minted per request and never stored.

## 8. Cases

Recorded against `account`/`admin` on `master` - the default install's own
state, not a contrived one - plus the probe realm for the reads whose
interesting shape needs one.

Every case masks `exp`, `iat`, `jti` and `sid` and nothing else on the two token
bodies; `TestNoMaskIsInertOnItsGolden` is what keeps that honest.

## 9. Store

No migration. Every row these seven read already exists: client scopes and
their protocol mappers, the two attachment lists, and both scope-mapping
tables. `0031_*` is not needed.
