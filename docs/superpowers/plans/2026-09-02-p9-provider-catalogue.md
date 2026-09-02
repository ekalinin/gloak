# P9 second cut: the per-provider property catalogue

Branch `feat/p9-provider-catalogue`, off `main` at `6e5a096`. Everything below
was measured against a live Keycloak 26.7.1 on 2026-09-02 - container `kc-cat`,
port 8158, `start-dev`, bootstrap admin `admin/admin`, removed afterwards. The
first cut is `docs/superpowers/handover/p9-identity-providers.md`.

## 1. The measured shape and size of the catalogue

This is the question the brief said nothing on paper answers, so it is answered
first and everything after it follows from the numbers.

### 1.1 Three endpoints, three envelopes, one atom

**The three do not serve the same bytes and no two of them share a body.** What
they share is one inner object, Keycloak's `ConfigPropertyRepresentation`:

```
{"name","label","helpText","type",["defaultValue"],["options"],"secret","required","readOnly"}
```

The envelopes around it are three different things:

```
GET .../identity-provider/providers/{id}        an object   {name,id,configProperties[],helpText,configMetadata[]}
GET .../instances/{alias}/mapper-types          a Java Map  mapperId -> {id,name,category,helpText,properties[]}
GET .../components/{id}/sub-component-types     an array    [{id,helpText,properties[],metadata{}}]
```

The property key is spelled `configProperties` on the first and `properties` on
the other two. The first carries `helpText` at the top level **and** inside each
property; the third carries `metadata` where the first carries `configMetadata`;
the second carries neither.

**The sharpest single fact about the three is that two of them are about
identity provider mappers and they disagree.**
`sub-component-types?type=org.keycloak.broker.provider.IdentityProviderMapper`
answers `[]` - two bytes - while `mapper-types` answers 23 distinct mapper types
for the same SPI. `GET /admin/serverinfo` lists 26 providers under that
`componentTypes` key. Three numbers for one family, and no two agree.

### 1.2 The sizes

Measured with `curl -w '%{size_download}'`, and **every body below was
re-measured byte for byte on a second container start and was identical** - 17
providers and 17 mapper-type responses, 34 comparisons, 34 `same`. The catalogue
is a function of the Keycloak version and of nothing else.

```
providers/{id}          17 providers        87 .. 2386 bytes     5816 total
mapper-types            13 answer, 4 do not 2090 .. 10212 bytes  union: 23 entries, 21990 bytes
sub-component-types     18 types, 4 answer  163 .. 25921 bytes   47650 total
                                            ---------------------------------
                                            73 catalogue entries, 75456 bytes
```

The `providers/{id}` half is small because **eleven of the seventeen have an
empty `configProperties`, `oidc` and `saml` among them** - the endpoint serves a
provider's *extra* properties, not its whole configuration surface. `google` is
the biggest at 2386 bytes and six properties.

`mapper-types` is the one the brief flagged: **the largest is `saml` at 10212
bytes**, not 11 kB, and the four that do not answer are two 404s
(`jwt-authorization-grant` and `oauth2` cannot be created bare, so no instance
exists to ask through) and **two 500s** - `linkedin-openid-connect` and
`openshift-v4` answer the consult-the-log `unknown_error` on a provider that was
created without complaint.

`sub-component-types` is the expensive half. Fourteen of the eighteen component
types answer `[]`; the four that answer carry 33 providers and 168 properties
between them, and `LDAPStorageMapper` alone is 25921 bytes.

### 1.3 Chunked or not, and why it does not matter here

Bodies above 8 kB come back `transfer-encoding: chunked` and everything below
carries a `content-length`. The boundary sits between `stackoverflow`'s 4070 and
`oidc`'s 8255, which is Quarkus's 8 kB output buffer rather than anything about
this family. **Nothing in this project can observe it**: the conformance
verifier serves through `httptest.ResponseRecorder`, which has no transport, and
Go's `net/http` makes the same decision on its own. Recorded and not acted on.

### 1.4 So: a table, a generator or a blob?

**A table of typed structs, and the reason is that the writes need the same rows
the reads serve.** `POST /components` filters a submitted config down to the
provider's declared property *names* (§2.3), so a blob served verbatim would
have to be re-parsed to answer a write, and two representations of one fact is
the thing the boundary table exists to prevent.

Not a generator, because there is nothing to generate from at build time: the
source is a live container, and the repository already has the right precedent
for that - `internal/oidc/testdata/discovery-26.7.1.json` is a measured artifact
checked in, and AGENTS.md says so. The difference is that the discovery document
has one shape and this has three, so the atom is stored and the three envelopes
are computed.

**The 47650-byte component half is not in this cut**, and §5 says why.

## 2. The rest of the measurements

### 2.1 `mapper-types` is a `javamap.KeyOrder` map with six collision chains

The top-level object is a Java `HashMap` keyed by mapper id. Thirteen key sets
were measured, 4 to 11 keys each, and **all thirteen are bucket-monotone at
capacity 16**. `javamap.KeyOrder` places **eight of the thirteen** exactly; the
five it misses hold six colliding pairs between them, and every one of those six
is the documented tie-break gap rather than a wrong bucket.

All six chains come back in **descending** alphabetical order, which is where
`javamap`'s own package comment already says a rule looks like a rule and is
not - a realm's `attributes` has an ascending one. So this cut adds six data
points to that count and changes nothing.

**Nothing needs the guess.** The order is a measured constant per provider and
is stable across container starts, so the catalogue stores the id list in the
order the server sent it and serves it back. That is the whole of "what to store
and what to compute": the order is stored, the envelope is computed.

### 2.2 A mapper's `config` is `SizedKeyOrder` and a component's is `KeyOrder`, on one key set

The first cut established the two constructors from two different key sets. This
cut has them **on the same key set**:

```
{priority, enabled, active}   component            -> active priority enabled
{priority, enabled, active}   identity provider mapper -> priority active enabled
```

One key set, two families, two orders, one container. Ten mapper config key sets
were measured and `javamap.SizedKeyOrder` places all ten, `KeyOrder` getting six
of the ten wrong - including `{clientId, clientSecret}` and `{k1..k10}`, which
are the identity provider's own signature sets from the first cut. Three
component sets were measured beyond the first cut's seven and `KeyOrder` places
all three, `SizedKeyOrder` getting two wrong.

So the mapper agrees with its parent identity provider and not with the
component beside it.

### 2.3 `POST`/`PUT /components` filter the config, and the filter is the catalogue

Measured, and it is the mechanism the brief named:

```
POST config {"priority":["7"],"zzzUndeclared":["v"],"keySize":["2048"],"algorithm":["RS256"]}
read        {"keySize":["2048"],"priority":["7"],"algorithm":["RS256"]}
```

`zzzUndeclared` is dropped and the survivors come back in `KeyOrder` over the
provider's declared property order. `max-clients` with `{"max-clients":["42"],
"nope":["x"]}` keeps one key and drops the other the same way.

**`PUT` merges where `POST` filters.** A `PUT` naming `{priority, junk,
algorithm}` on a component holding `{keySize, priority, algorithm}` left
`keySize` in place, dropped `junk` and moved the other two; `{"config":{}}` and
an absent `config` both change nothing. So the config cannot be cleared through
this endpoint. And **changing `providerId` re-filters against the new
provider**: `hmac-generated` does not declare `keySize`, so that key vanished.

**The five provider types `POST /components` accepts are exactly the five
`sub-component-types` answers non-empty for.** Swept over all 245
(`providerType`, `providerId`) pairs `GET /admin/serverinfo` lists:

```
201  18   KeyProvider 7, ClientRegistrationPolicy 6, LDAPStorageMapper 3,
          UserStorageProvider 1, UserProfileProvider 1
400  15   {"errorMessage": ...} - a required property, per provider
403  16   {"error":"Components managed through internal APIs cannot be managed
          through the component endpoint"} - the two Workflow types
500 196   the eleven other types
```

### 2.4 The refusals are not in the catalogue, and that is what stops this cut

Of the 15 rows that answer 400, **only 8 name a property the catalogue declares
`required`, and all 8 are `LDAPStorageMapper`** - no `KeyProvider`,
`ClientRegistrationPolicy`, `UserStorageProvider` or `UserProfileProvider`
provider declares a required property at all. The other seven refuse anyway:

```
ldap            "Edit Mode is mandatory"
full-name-ldap-mapper "Missing configuration for LDAP Full Name Attribute"
max-clients     "'Max Clients Per Realm' is required"
trusted-hosts   "'Host Sending Client Registration Request Must Match' is required"
java-keystore   "'Keystore' is required"
rsa             "'Private RSA Key' is required"
rsa-enc         "'Private RSA Key' is required"
```

Four more things a `required`-flag reading gets wrong, each measured:

- **`trusted-hosts` needs two properties, not one.** Satisfying the first
  produced `'Client URIs Must Match' is required`, so the refusal is a sequence
  and not a set.
- **An empty string counts as absent**: `{"max-clients":[""]}` is the same 400.
- **There is value validation beside presence validation**:
  `'Max Clients Per Realm' should be a number` and `'Key size' should be 1024,
  2048, 3072 or 4096`.
- **And it is not applied to every typed property**: `algorithm` is a `List`
  with a declared `options` array and `{"algorithm":["nope"]}` is a **201**.

Two sentence shapes, `'Label' is required` interpolating the property's **label**
and a per-provider sentence, and no rule in the catalogue picks between them.

### 2.5 The identity provider mapper family

`GET/POST/PUT/DELETE .../instances/{alias}/mappers[/{id}]`, measured in full.

```
{"id","name","identityProviderAlias","identityProviderMapper","config"}
```

- **The config is *not* filtered.** `{"role":"x","undeclared":"v"}` comes back
  with both keys, and an unknown `identityProviderMapper` is a **201**. The
  neighbouring component family filters and validates; this one does neither. So
  the five mapper operations need the catalogue for `mapper-types` and for
  nothing else.
- **The values are strings, not arrays** - a `Map<String,String>` where a
  component's config is a `MultivaluedHashMap`.
- **`PUT` replaces the config outright**, where `PUT /components/{id}` merges.
- **`PUT` writes the mapper the *body's* `id` names, not the path's.** A PUT
  addressed to one mapper carrying another's id answered 204 and changed the
  other one, leaving the addressed mapper untouched. Same defect as
  `PUT .../protocol-mappers/models/{id}` - and unlike that one it writes
  **every** field, `name`, `identityProviderAlias` and `identityProviderMapper`
  included.
- **`identityProviderAlias` is stored raw and echoed.** A body naming `other`
  on a mapper living under `mt-oidc` was accepted and served back as `other`.
- **The body's `id` wins on create**, the fifth endpoint with that rule.
- **A create with no `name` is `409 Duplicate resource error`**, which is the
  policy family's answer to a body with no name and the third family to give it.
- **A duplicate name is `400 {"errorMessage":"Failed to add mapper 'm1b' to
  identity provider [oidc]."}`** - and the sentence names the **providerId**,
  not the alias the route carries.
- **An unknown mapper id is `404 {"error":"Model not found"}`** on the read and
  on the delete, which is a **new spelling of not-found**, the twenty-fourth.
- The create is a strict decoder naming `IdentityProviderMapperRepresentation`
  with a line and a column, the **tenth**. An empty body is a 500, a malformed
  one the 400 `invalid_request` / `Cannot parse the JSON`.
- An unknown alias on `mappers` and on `mapper-types` alike is the family's
  generic `{"error":"HTTP 404 Not Found"}`.
- `GET .../providers/{unknown}` is `400 {"error":"HTTP 400 Bad Request"}`.

### 2.6 Guards

Swept one role at a time over six callers - no role, `view-realm`,
`manage-realm`, `view-identity-providers`, `manage-identity-providers` and
`view-clients` as a control:

```
                                        norole v-realm m-realm v-idp m-idp v-clients
GET  providers/{id}                       403    403     403    200   200    403
GET  instances/{a}/mapper-types           403    403     403    200   200    403
GET  instances/{a}/mappers                403    403     403    200   200    403
GET  instances/{a}/mappers/{id}           403    403     403    200   200    403
POST instances/{a}/mappers                403    403     403    403   201    403
PUT  instances/{a}/mappers/{id}           403    403     403    403   204    403
DELETE instances/{a}/mappers/{id}         403    403     403    403   204    403
POST import-config                        403    403     403    403   200    403
GET  components/{id}/sub-component-types  403    200     200    403   403    403
POST components                           403    403     201    403   403    403
PUT  components/{id}                      403    403     204    403   403    403
```

The first cut's two disjoint role pairs hold on all eleven new operations, and
**the resource is still resolved after the role**: `PUT /components/{unknown}` is
403 to a `view-realm` caller and 404 to a `manage-realm` one, and
`GET .../instances/nope/mappers` is 403 to `view-realm` and 404 to `v-idp`.

### 2.7 Verbs

```
providers/{id}          GET 200  POST 404  PUT 405  PATCH 405  DELETE 405
mapper-types            GET 200  POST 404  PUT 404  PATCH 405  DELETE 404
mappers                 GET 200  POST 500  PUT 404  PATCH 405  DELETE 404
import-config           GET 404  POST 400  PUT 405  PATCH 405  DELETE 405
sub-component-types     GET 400  POST 404  PUT 404  PATCH 405  DELETE 404
```

`providers/{id}` and `import-config` are two more Admin API routes answering a
**real 405** on three verbs. Recorded, acted on by nothing - F31.

### 2.8 `import-config` makes a real outbound fetch and nothing constrains it

```
{"fromUrl":"http://localhost:8080/realms/master/.well-known/openid-configuration",
 "providerId":"oidc"}   -> 200, ten keys read out of the fetched document
```

The server log names `IdentityProvidersResource.importFrom` and an Apache
`HttpClient`. What it does on failure, measured one request each: an unreachable
host, a `file://` URL, a scheme with no host, a 404 target and an unknown
`providerId` are all the consult-the-log `500`; a **reachable target that is not
JSON** is a `500` carrying the `400`-shaped body `{"error":"invalid_request",
"error_description":"Cannot parse the JSON"}`; an absent `fromUrl` or absent
`providerId` is `400 {"error":"HTTP 400 Bad Request"}`; an unknown field is
**ignored**, so this is not a strict decoder; and a form-encoded request is a
`500` serving Quarkus's own `text/plain` error page rather than anything
Keycloak wrote.

**About a URL pointing at the host**: there is no allowlist, no scheme check
beyond what `HttpClient` enforces and no loopback refusal. Pointing it at
`http://localhost:8080/` from inside the container fetched the container's own
discovery document and returned it. That is a server-side request forgery
primitive available to any `manage-identity-providers` caller, and it is
Keycloak's behaviour rather than a defect this project may quietly fix.

### 2.9 Two things the sweep broke, which are findings

- **`POST /components` accepts a second `declarative-user-profile` and it breaks
  every login in the realm.** After the 245-pair sweep ran against `master`, the
  bootstrap administrator's password grant answered `400 {"error":
  "invalid_grant","error_description":"Account is not fully set up"}` and the
  container had to be replaced. The destructive half of the sweep was re-run in
  a created realm.
- **A component created with no `name` is a 201 and reads back with no `name`
  key.** AGENTS.md says `declarative-user-profile` is "the only component with no
  `name` key at all"; that is true of a default install and false of what the
  API allows.

## 3. What this cut builds

Seven operations, which is `admin/identity-providers` **entire** save the one
that makes an outbound HTTP call.

```
GET    /admin/realms/{realm}/identity-provider/providers/{provider_id}
GET    /admin/realms/{realm}/identity-provider/instances/{alias}/mapper-types
GET    /admin/realms/{realm}/identity-provider/instances/{alias}/mappers
POST   /admin/realms/{realm}/identity-provider/instances/{alias}/mappers
GET    /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}
PUT    /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}
DELETE /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}
```

### Stage 1 - the catalogue in `internal/model`

`model.ProviderProperty` for the shared atom, with `DefaultValue` an `any` so
that `false`, `"3600"` and absent are three states (`github`'s
`githubJsonFormat` sends the JSON `false` and `google`'s
`jwtAuthorizationGrantMaxAllowedAssertionExpiration` sends the string `"3600"` -
one endpoint, two JSON types for one field). `Options` a `[]string`, absent when
the property is not a `List`.

Two tables:

- `identityProviderCatalogue`: 17 entries, `{name, properties}` keyed by
  provider id.
- `identityProviderMapperCatalogue`: 23 entries `{id, name, category, helpText,
  properties}`, plus `identityProviderMapperIDs`, the **measured** id order per
  provider id for the 13 that answer.

Transcribed from the measured bodies rather than typed, and the goldens are what
check the transcription.

### Stage 2 - migration `0024_identity_provider_mapper.sql`

```sql
CREATE TABLE identity_provider_mapper (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm (id) ON DELETE CASCADE,
    alias         TEXT NOT NULL,   -- the body's, stored raw; see §2.5
    name          TEXT NOT NULL,
    mapper        TEXT NOT NULL,
    ordinal       INTEGER NOT NULL,
    UNIQUE (realm_id, alias, name)
);
CREATE TABLE identity_provider_mapper_config (...name, value, ordinal);
```

Keyed on `(realm_id, alias)` and **not** on the provider's `internal_id`,
because the mapper's stored alias is the body's and a `PUT` can change it to one
no provider has. A foreign key onto `identity_provider` would make that measured
state unreachable. `ordinal` because the config chains in insertion order.

`store.IdentityProviderMapperRepo` with `Create`, `Update`, `ByID`, `Delete` and
`List`, in both drivers.

### Stage 3 - the handlers

`internal/admin/identityprovidermappers.go` and the two catalogue reads in
`identityproviders.go`. The mapper config is serialised through
`javamap.SizedKeyOrder`, the same call the provider config beside it makes and
the opposite of the component config one path segment away.

### Stage 4 - the router, the conformance cases and the goldens

Cases appended at the very end of `adminCases`, fixtures at the very end of the
map with the helpers after the last one.

### Stage 5, and it is droppable

`GET /components/{id}/sub-component-types`, if stages 1-4 land with room. It
needs the 47650-byte half of the catalogue and no store change and no validator,
so it is the one component operation the catalogue alone unlocks.

## 4. Mutation plan

One mutation per claim, a different mutation each time, each confirming the
**named** test fails, then reverted - and **committed before any of it runs**,
because the harness reverts with `git checkout -- .`.

Named claims, one mutation each: the catalogue's per-provider mapper id order;
the mapper config's constructor; the strict decode's class name; the missing
name 409; the duplicate name 400 and the providerId inside it; `Model not
found`; the body's id winning; the PUT writing the body's id; the PUT replacing
rather than merging; the guard's two role sets; the alias-after-role order.

**Fixture ids and names differ from each other everywhere**, which is the hole
that ate four of the last two cuts' five survivors.

## 5. What this cut does not build, and why

- **`POST /admin/realms/{realm}/identity-provider/import-config`** - §2.8. It is
  an outbound HTTP fetch made from `internal/admin`, and the boundary table
  gives that package no client and no timeout policy. Building it means deciding
  where an outbound HTTP client lives in this project, and that decision is not
  a family cut's to make. Recorded in full so the cut that makes it does not
  have to re-measure.
- **`POST /components` and `PUT /components/{id}`** - the filter is the
  catalogue (§2.3) and the refusals are not (§2.4). A create built on the
  catalogue's `required` flag answers 400 for the eight LDAP mappers and 201 for
  the seven other providers Keycloak refuses, and would still miss the two value
  validators, the two-property sequence and the empty-string rule. That is seven
  measured divergences on fifteen measured inputs.
- **`GET /components/{id}/sub-component-types`** - 47650 bytes and 168
  properties, the expensive half. Stage 5 above.
- **`DELETE /components/{id}`** - F145, and this cut **agrees**. Nothing has
  changed: `GET /keys` is still not backed by the components table, and the
  delete would still leave a realm Keycloak cannot reach. §3 of the handover
  restates the argument with what this cut adds to it.
