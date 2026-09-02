# P9 second cut: the per-provider property catalogue

Branch `feat/p9-provider-catalogue`, off `main` at `6e5a096`, with `main` merged
mid-flight at `8ec87ac` (P13's remaining theme pages). Everything below was
measured against a live Keycloak 26.7.1 on 2026-09-02 - container `kc-cat`, port
8158, `start-dev`, bootstrap admin `admin/admin`, removed afterwards. The plan is
at `docs/superpowers/plans/2026-09-02-p9-provider-catalogue.md` and the first cut
at `docs/superpowers/handover/p9-identity-providers.md`.

## 1. Measurements

### 1.1 The catalogue: three endpoints, three envelopes, one atom

**No two of the three serve the same bytes.** What they share is Keycloak's
`ConfigPropertyRepresentation`, and the field order of that inner object is fixed
across all three:

```
name label helpText type [defaultValue] [options] secret required readOnly
```

The envelopes are not:

```
GET .../identity-provider/providers/{id}        an object   {name,id,configProperties[],helpText,configMetadata[]}
GET .../instances/{alias}/mapper-types          a Java Map  mapperId -> {id,name,category,helpText,properties[]}
GET .../components/{id}/sub-component-types     an array    [{id,helpText,properties[],metadata{}}]
```

The property array is spelled `configProperties` on the first and `properties` on
the other two; the first carries `helpText` at the top level *and* inside each
property; the third spells its metadata `metadata` where the first spells it
`configMetadata`; the second has neither.

**The sharpest single fact is that two of the three are about identity provider
mappers and they disagree.**
`sub-component-types?type=org.keycloak.broker.provider.IdentityProviderMapper`
answers `[]` - two bytes - where `mapper-types` answers 23 distinct mapper types
for the same SPI, and `GET /admin/serverinfo` lists 26 providers under that same
`componentTypes` key. Three numbers for one family and no two agree.

### 1.2 The sizes, and they are a constant of the version

```
providers/{id}          17 providers        87 .. 2386 bytes     5816 total
mapper-types            15 answer, 2 do not 2090 .. 10212 bytes  union: 23 entries, 21990 bytes
sub-component-types     18 types, 4 answer  163 .. 25921 bytes   47650 total
                                            ---------------------------------
                                            73 catalogue entries, 75456 bytes
```

**Every one of those bodies was fetched twice, from two separate container
starts, and was byte-identical both times** - 17 provider bodies and 17
mapper-type responses, 34 comparisons, 34 identical. The catalogue is a function
of the Keycloak version and of nothing that happens at runtime. That is what
makes a table the right shape for it: there is nothing to compute.

Three things the numbers say that the endpoint names do not:

- **Eleven of the seventeen providers declare no properties at all**, `oidc` and
  `saml` among them. So `providers/{id}` serves a provider's *extra*
  configuration, not its whole surface - an `oidc` broker plainly has a
  `clientId` and this endpoint does not mention it. `google` is the biggest at
  2386 bytes and six properties.
- **The `mapper-types` maximum is 10212 bytes on `saml`**, not the 11 kB the
  brief carried. Two of the four that do not answer are 404s
  (`jwt-authorization-grant` and `oauth2` refuse a bare create, so there was no
  instance to ask through until one was made with the config they demand - both
  then answer the same four-mapper base set as `kubernetes`), and **two are
  500s**: `linkedin-openid-connect` and `openshift-v4` answer the
  consult-the-log `unknown_error` on an instance that was created without
  complaint and reads back normally through every other route in the family.
- **Fourteen of the eighteen component types answer `sub-component-types` with
  `[]`.** The four that answer carry 33 providers and 168 properties between
  them, and `LDAPStorageMapper` alone is 25921 bytes.

Bodies above 8 kB come back `transfer-encoding: chunked` and everything below
carries a `content-length`; the boundary sits between `stackoverflow`'s 4070 and
`oidc`'s 8255. **Nothing in this project can observe it** - the verifier serves
through `httptest.ResponseRecorder`, which has no transport - so it is recorded
and acted on by nothing.

### 1.3 `sub-component-types` ignores its parent component entirely

Byte-identical bodies came back for one `type` asked through three different
parent components - a key provider, the user-profile component and a
client-registration policy. Two types, three parents, six requests, one pair of
answers. The parent is read only to decide whether the request is
`404 {"error":"Could not find parent component"}`; after that the `type`
parameter is the whole input.

The realm's own id answers that 404 too, which is the first cut's finding from
the other side: a component is parented on the realm and the realm is not one.
With no `type` at all, or `type=`, the answer is `400 {"error":"must specify a
subtype"}`; with `type=bogus` it is the consult-the-log 500.

### 1.4 `POST /components` filters the config, and the filter is the catalogue

```
POST config {"priority":["7"],"zzzUndeclared":["v"],"keySize":["2048"],"algorithm":["RS256"]}
read        {"keySize":["2048"],"priority":["7"],"algorithm":["RS256"]}
```

The undeclared key is dropped and the survivors come back in `javamap.KeyOrder`
over the provider's declared property order. `max-clients` with
`{"max-clients":["42"],"nope":["x"]}` keeps one and drops the other the same way.

**`PUT` merges where `POST` filters.** A `PUT` naming `{priority, junk,
algorithm}` on a component holding `{keySize, priority, algorithm}` left
`keySize` alone, dropped `junk` and moved the other two. `{"config":{}}` and an
absent `config` both change nothing, so **the config cannot be cleared through
this endpoint at all**. And changing `providerId` re-filters against the *new*
provider: `hmac-generated` does not declare `keySize`, so that key vanished.

**The five provider types `POST /components` accepts are exactly the five
`sub-component-types` answers non-empty for.** Swept over all 245
`(providerType, providerId)` pairs `GET /admin/serverinfo` lists:

```
201  18   KeyProvider 7, ClientRegistrationPolicy 6, LDAPStorageMapper 3,
          UserStorageProvider 1, UserProfileProvider 1
400  15   {"errorMessage": ...}, a required property, per provider
403  16   {"error":"Components managed through internal APIs cannot be managed
          through the component endpoint"} - the two Workflow types
500 196   the eleven other types
```

### 1.5 The refusals are not in the catalogue, and that is what stops the writes

Of the 15 rows that answer 400, **only 8 name a property the catalogue declares
`required`, and all 8 are `LDAPStorageMapper`**. No `KeyProvider`,
`ClientRegistrationPolicy`, `UserStorageProvider` or `UserProfileProvider`
provider declares a required property at all, and seven of them refuse anyway:

```
ldap                   "Edit Mode is mandatory"
full-name-ldap-mapper  "Missing configuration for LDAP Full Name Attribute"
max-clients            "'Max Clients Per Realm' is required"
trusted-hosts          "'Host Sending Client Registration Request Must Match' is required"
java-keystore          "'Keystore' is required"
rsa                    "'Private RSA Key' is required"
rsa-enc                "'Private RSA Key' is required"
```

Four more things a `required`-flag reading gets wrong, each one request:

- **`trusted-hosts` needs two properties, not one.** Satisfying the first
  produced `'Client URIs Must Match' is required`, so the refusal is a sequence
  and not a set.
- **An empty string counts as absent**: `{"max-clients":[""]}` is the same 400.
- **There is value validation beside presence validation**: `'Max Clients Per
  Realm' should be a number`, and `'Key size' should be 1024, 2048, 3072 or
  4096`.
- **And it is not applied to every typed property**: `algorithm` is a `List` with
  a declared `options` array, and `{"algorithm":["nope"]}` is a **201**.

Two sentence shapes - `'Label' is required`, interpolating the property's
**label**, and a per-provider sentence - and nothing in the catalogue picks
between them.

### 1.6 The identity provider mapper family

- **The config is not filtered and the mapper type is not validated.**
  `{"role":"x","undeclared":"v"}` comes back with both keys, and a create naming
  `identityProviderMapper: "nope"` is a **201**. So is one whose
  `identityProviderAlias` names no provider in the realm. The component family
  one chapter away filters and validates; this one does neither.
- **The values are strings**, a `Map<String,String>`, where a component's config
  is a `MultivaluedHashMap`.
- **`PUT` replaces the config outright**, where `PUT /components/{id}` merges. A
  PUT naming one key on a mapper holding four left it holding one.
- **`PUT` writes the mapper the *body's* `id` names, not the path's.** A PUT
  addressed to one mapper carrying another's id answered 204, changed the other
  one and left the addressed mapper exactly as it was. Same defect as
  `PUT .../protocol-mappers/models/{id}` and worse in one respect: that route
  writes two fields and discards three, this one writes **all four**.
- **`identityProviderAlias` is stored raw and echoed.** A body naming `other` on
  a mapper living under `mt-oidc` was accepted and served back as `other`.
- **The listing is per alias and the three single-mapper routes are not.** A
  mapper created under one broker was read through a second broker's path with a
  200 and then **deleted** through it with a 204, while the second broker's own
  listing stayed `[]` throughout.
- **The listing has no reproducible order.** Five mappers created
  `zzz, mmm, aaa, qqq, bbb` came back `bbb, zzz, qqq, mmm, aaa`, twice on one
  container. It is a collection over the mapper id and an id is a minted UUID, so
  nothing about a later run repeats it.
- **The listing takes no parameters.** `first`, `max`, `search`,
  `briefRepresentation` and the malformed `first=abc` each returned the whole
  set - where the instance listing one path segment up answers `first=abc` with a
  404.
- **The body's `id` wins on create**, the fifth endpoint in this API with that
  rule, and the `Location` ends in it.
- **A create with no `name` is `409 Duplicate resource error`** on a broker
  holding no mappers at all - the policy family's answer to the same omission and
  the third family in this API to give it.
- **A duplicate name is a 400, not a 409**, and the sentence names the provider's
  **`providerId`** where the route carries its alias:
  `{"errorMessage":"Failed to add mapper 'm1b' to identity provider [oidc]."}`.
- **An unknown mapper id is `404 {"error":"Model not found"}`** on the read and
  on the delete. A new spelling of not-found, in the bare-`error` family.
- The create is a strict decoder naming `IdentityProviderMapperRepresentation`
  with a line and a column. An empty body or a literal `null` is a **500**; a
  merely malformed one is the 400 `invalid_request` / `Cannot parse the JSON`.
- An unknown alias on `mappers` and on `mapper-types` alike is the family's
  generic `{"error":"HTTP 404 Not Found"}`, and
  `GET .../providers/{unknown}` is `400 {"error":"HTTP 400 Bad Request"}`.

### 1.7 Two HashMap constructors, settled on one key set

The first cut established the two constructors from two different key sets. This
cut has them **on the same one**, on one container:

```
{priority, enabled, active}   a component               -> active priority enabled
{priority, enabled, active}   an identity provider mapper -> priority active enabled
```

So the mapper agrees with its parent identity provider and not with the component
beside it. Ten mapper config key sets were measured and `javamap.SizedKeyOrder`
places all ten, `KeyOrder` getting **seven** of the ten wrong - the count was
written down as six first and the test refused it, which is the third counted
claim in that package to be corrected by the thing it counts. All ten are vectors
now, with `TestTheTwoConstructorsDisagreeOnOneKeySet` carrying the cross-family
pair.

**`mapper-types`' own key order is `KeyOrder` and it is stored rather than
computed.** All thirteen measured key sets are bucket-monotone at capacity 16;
`javamap.KeyOrder` places **eight of the thirteen** and the five it misses hold
six colliding pairs between them, which is the tie-break gap that package
documents rather than a wrong bucket. All six chains come back in *descending*
alphabetical order - which is where `javamap`'s own comment already says a rule
looks like a rule and is not, because a realm's `attributes` has an ascending
one. Nothing was changed on the strength of it: the order is a constant of the
version, so the catalogue records it and the serialiser serves it back.

### 1.8 Guards, and they are the first cut's two

Swept one role at a time over six callers - no role, `view-realm`,
`manage-realm`, `view-identity-providers`, `manage-identity-providers`, and
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

The two disjoint role pairs hold on all eleven new operations, and **the resource
is still resolved after the role**: `PUT /components/{unknown}` is 403 to a
`view-realm` caller and 404 to a `manage-realm` one, and
`GET .../instances/nope/mappers` is 403 to `view-realm` and 404 to
`view-identity-providers`.

### 1.9 Verbs

```
providers/{id}          GET 200  POST 404  PUT 405  PATCH 405  DELETE 405
mapper-types            GET 200  POST 404  PUT 404  PATCH 405  DELETE 404
mappers                 GET 200  POST 500  PUT 404  PATCH 405  DELETE 404
import-config           GET 404  POST 400  PUT 405  PATCH 405  DELETE 405
sub-component-types     GET 400  POST 404  PUT 404  PATCH 405  DELETE 404
```

`providers/{id}` and `import-config` are two more Admin API routes answering a
**real 405** on three verbs each. Recorded, acted on by nothing - F31.

### 1.10 `import-config` makes a real outbound fetch and nothing constrains it

```
{"fromUrl":"http://localhost:8080/realms/master/.well-known/openid-configuration",
 "providerId":"oidc"}   -> 200, ten keys read out of the fetched document
```

The container log names `IdentityProvidersResource.importFrom` and an Apache
`HttpClient`. What it does on failure, one request each: an unreachable host, a
`file://` URL, a scheme with no host, a 404 target and an unknown `providerId`
are all the consult-the-log **500**; a **reachable target that is not JSON** is a
**500 carrying the 400-shaped body** `{"error":"invalid_request",
"error_description":"Cannot parse the JSON"}`; an absent `fromUrl` or an absent
`providerId` is `400 {"error":"HTTP 400 Bad Request"}`; **an unknown field is
ignored**, so this is not a strict decoder; and a form-encoded request is a 500
serving Quarkus's own `text/plain` error page rather than anything Keycloak
wrote.

**About a URL pointing at the host**: there is no allowlist, no scheme check
beyond what `HttpClient` enforces, and no loopback refusal. Pointed at
`http://localhost:8080/` from inside the container it fetched the container's own
discovery document and returned it. Any `manage-identity-providers` caller has a
server-side request forgery primitive, and it is Keycloak's behaviour rather than
a defect this project may quietly fix.

### 1.11 Two things the sweep broke, which are findings

- **`POST /components` accepts a second `declarative-user-profile` and it breaks
  every login in the realm.** After the 245-pair sweep ran against `master`, the
  bootstrap administrator's password grant answered `400 {"error":
  "invalid_grant","error_description":"Account is not fully set up"}` and the
  container had to be replaced. The destructive half was re-run in a created
  realm.
- **A component created with no `name` is a 201 and reads back with no `name`
  key.** AGENTS.md says `declarative-user-profile` is "the only component with no
  `name` key at all"; that is true of a default install and false of what the API
  allows.

### 1.12 One more golden for the security-header split, and AGENTS.md's count of it is stale

`admin/identity-providers/mappers-create-no-name` sends **none** of the five
security headers with its 67-byte `Duplicate resource error` body, while
`mappers-create-duplicate` and `mappers-create-empty-body` beside it - **same
route, same verb, same `Content-Type`** - send all five. Three failures of one
endpoint, two header sets, and nothing about the request or the response
separates them. It refutes nothing and explains nothing; the goldens hold it per
case, as F147 says they must.

**AGENTS.md's tally of that family is out of date and this cut is not what made
it so.** Its header bullet reads "fifteen committed goldens" with

```
POST  seven send none of the five, three send all five
PUT   four send none, one sends all five
```

Counted from the goldens whose body *is* that 67-byte string, on the merged tree
and before this cut's own case is added, it is **sixteen**:

```
POST  seven send none of the five, four send all five
PUT   four send none, one sends all five
```

so one `POST` sending all five arrived - from P10's authz work - without the
bullet moving. With this cut's case it is seventeen and the `POST` row is eight
and four. Nothing about the split changes: a `POST` still does both and a `PUT`
still does both. That is exactly why the drift matters - the paragraph's
conclusion survived while its arithmetic did not, and the arithmetic is what the
bullet offers as evidence.

Confirmed in review against `main`: the sixteenth golden and the bullet's
"fifteen" were written in **the same fold**, so the number was stale before it
was committed. It is being replaced with a test that computes it, which is the
only thing that stops the next cut inheriting it - a count in prose beside the
list it counts is the failure mode AGENTS.md already names twice and this is its
third instance.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **The per-provider property catalogue is three endpoints, three envelopes and
  one atom, and no two of them serve the same bytes.** They share Keycloak's
  `ConfigPropertyRepresentation` -
  `name label helpText type [defaultValue] [options] secret required readOnly` -
  and nothing else: the array is `configProperties` on
  `identity-provider/providers/{id}` and `properties` on the other two, the
  metadata is `configMetadata` on the first and `metadata` on the third, and
  `mapper-types` has neither. **Two of the three are about identity provider
  mappers and they disagree**: `sub-component-types` for the
  `IdentityProviderMapper` SPI answers `[]` where `mapper-types` answers
  twenty-three types and `GET /admin/serverinfo` lists twenty-six providers.
  Three numbers for one family, no two alike. The whole catalogue is 73 entries
  and 75456 bytes of JSON, and **every body of it was byte-identical across two
  container starts** - it is a function of the Keycloak version and of nothing
  at runtime, which is why it is a stored table and not something computed.
- **`providers/{provider_id}` serves a provider's *extra* configuration, not its
  configuration.** Eleven of the seventeen registered providers declare no
  properties at all, `oidc` and `saml` among them, and an `oidc` broker plainly
  has a `clientId`. The biggest is `google` at 2386 bytes and six properties.
  **One field in it carries two JSON types**: `github`'s `githubJsonFormat`
  defaults to the literal `false` and `google`'s
  `jwtAuthorizationGrantMaxAllowedAssertionExpiration` to the string `"3600"`, so
  a `string` field loses one and a `bool` loses the other. And **an unregistered
  id here is a 400**, `{"error":"HTTP 400 Bad Request"}`, where the instance
  routes one path segment away answer an unknown alias with the generic 404.
- **Two of the seventeen providers answer `mapper-types` with a 500.**
  `linkedin-openid-connect` and `openshift-v4` answer the consult-the-log
  `unknown_error` on an instance that was created without complaint and reads
  back normally through every other route in the family. Two more answer a 404
  until an instance exists at all - `oauth2` and `jwt-authorization-grant` refuse
  a bare create for required config - and once one does, both serve the same
  four-mapper base set `kubernetes` serves. So the seventeen split four ways on
  one route and only the 500 is a defect.
- **`sub-component-types` reads its parent component only to decide whether to
  404.** Byte-identical bodies came back for one `type` asked through three
  different parent components, twice over. The `type` parameter is the whole
  input; the parent is a presence check. With no `type` the answer is
  `400 {"error":"must specify a subtype"}` and with an unknown one it is the
  consult-the-log 500, so the parameter has three outcomes and none of them
  depends on the component in the path.
- **`POST /components` filters a submitted config to the provider's declared
  properties and `PUT /components/{id}` merges into it.** The create drops an
  undeclared key and orders the survivors by `javamap.KeyOrder` over the declared
  property order; the update leaves alone any key it does not name, so
  `{"config":{}}` and an absent `config` both change nothing and **the config
  cannot be cleared through the endpoint at all**. Changing `providerId` on the
  update re-filters against the *new* provider, which is how a key survives one
  write and vanishes on the next. **The five provider types the create accepts
  are exactly the five `sub-component-types` answers non-empty for**, measured
  over all 245 `(providerType, providerId)` pairs `GET /admin/serverinfo` lists;
  the two `Workflow` types answer a 403 saying they are managed through internal
  APIs and the other eleven answer a 500.
- **The catalogue's `required` flag is not the validator, and building the create
  on it is wrong seven ways.** Fifteen of the thirty-three component providers
  refuse a bare create and **only eight declare a required property**, all eight
  of them `LDAPStorageMapper`. `trusted-hosts` needs two properties and reveals
  the second only after the first is satisfied; an empty string counts as absent;
  two providers range-check a value (`should be a number`, `should be 1024, 2048,
  3072 or 4096`); and a bad `algorithm` against a declared `options` list is a
  **201**. Two sentence shapes, one interpolating the property's **label** and
  one per provider, and nothing in the catalogue picks between them.
- **An identity provider mapper's config is not filtered and its mapper type is
  not validated, one path segment inside the family whose neighbour does both.**
  An undeclared config key comes back, a create naming a mapper type that does
  not exist is a 201, and so is one whose `identityProviderAlias` names no
  provider in the realm. **Its `PUT` replaces the config where
  `PUT /components/{id}` merges**, and its values are plain strings where a
  component's are arrays. Validating a mapper against the catalogue this API
  ships is the obvious tightening and it is measurably wrong.
- **`PUT .../instances/{alias}/mappers/{id}` writes the mapper the *body's* `id`
  names, not the path's** - a PUT addressed to one mapper carrying another's id
  answered 204, changed the other one and left the addressed one alone. That is
  `PUT .../protocol-mappers/models/{id}`'s defect and it is worse here: the
  protocol mapper route writes two fields and discards three, this one writes
  **all four**, the name, the alias and the mapper type included. Keycloak's own
  defect, reproduced.
- **The mapper listing is scoped to the path's alias and the three routes naming
  a mapper id are not.** A mapper created under one broker was read through a
  second broker's path with a 200 and **deleted** through it with a 204, while
  that second broker's own listing stayed `[]`. Giving the id lookup an alias
  argument for symmetry is the tidy-up that turns two measured 2xx into 404s.
  `identityProviderAlias` is stored raw and echoed too, so a `PUT` can set it to
  a value no provider has and strand the row the way a null alias strands a
  provider.
- **The mapper listing has no reproducible order and takes no parameters at
  all.** Five mappers created `zzz, mmm, aaa, qqq, bbb` came back
  `bbb, zzz, qqq, mmm, aaa`, twice on one container: it is a collection over the
  mapper **id**, and an id is a minted UUID. `first`, `max`, `search`,
  `briefRepresentation` and the malformed `first=abc` each returned the whole
  set, where the instance listing one path segment up answers `first=abc` with a
  404. Three listings in one chapter, three paging rules, and this one is "none".
- **A mapper create with no name is a 409 and one with a taken name is a 400.**
  The missing name answers `{"error":"conflict","error_description":"Duplicate
  resource error"}` on a broker holding no mappers at all - the policy family's
  answer to the same omission, and the third family in this API to give it - and
  the duplicate answers `400 {"errorMessage":"Failed to add mapper 'x' to
  identity provider [oidc]."}`, a sentence naming the provider's **`providerId`**
  where the route carries its alias. Two ways one field can fail, two statuses,
  and neither is the 409 the rest of the API gives a duplicate.
- **`Model not found` is a twenty-fourth spelling of not-found**, answered by the
  mapper read and the mapper delete for an id that resolves to nothing. It is in
  the bare-`error` family, and the chapter it lives in answers an unknown *alias*
  with the generic `HTTP 404 Not Found` - so one chapter now has both.
- **An identity provider mapper's `config` is `javamap.SizedKeyOrder` and a
  component's is `javamap.KeyOrder`, and one key set settles it.**
  `{priority, enabled, active}` sent to a component comes back
  `active priority enabled` and sent to a mapper comes back
  `priority active enabled`, on one container. Every earlier claim about the two
  constructors compared different key sets on different families; this is one key
  set and two answers. Ten mapper configs are measured, SizedKeyOrder places all
  ten and KeyOrder gets **seven** wrong - a count that was written down as six
  first and corrected by the test that holds the vectors.
- **`mapper-types`' own key order is `KeyOrder`'s and it is stored rather than
  computed.** All thirteen measured key sets are bucket-monotone at capacity 16;
  KeyOrder places eight and the five it misses hold six colliding pairs, which is
  the documented tie-break gap. All six of those chains come back in **descending**
  alphabetical order, which is where `javamap`'s own comment already warns that a
  rule which looks like a rule is not one - a realm's `attributes` has an
  ascending chain. Nothing was changed on the strength of it, because nothing
  needs to be: the order was byte-identical across two container starts, so it is
  recorded and served back.
- **A custom `MarshalJSON` cannot inherit the encoder's `SetEscapeHTML(false)`.**
  `internal/httpx` turns HTML escaping off for every response body because
  Keycloak escapes none of `<`, `>` and `&`; but a type with its own
  `MarshalJSON` is asked for bytes, and whatever `json.Marshal` produced inside
  it is already escaped. The outer encoder only *compacts* what it is handed, so
  the escape survives to the wire. Measured on both sides on 2026-09-02: an
  identity provider created with `{"config":{"note":"a<b>c&d"}}` reads back from
  Keycloak as `a<b>c&d` and read back from Gloak with all three characters in
  their `\u00xx` spelling, while a plain struct written through the same response
  writer came out right. Shipped since P9's first cut and fixed on this branch;
  found only because the catalogue's own `saml-username-idp-mapper` helpText
  contains `ATTRIBUTE.<NAME>` and no caller can avoid it.
- **`POST /admin/realms/{realm}/identity-provider/import-config` fetches a URL
  the caller names, with no allowlist and no loopback refusal.** Pointed at the
  server's own base URL it returns the server's own discovery document as broker
  config. Its failures are all the consult-the-log 500 - an unreachable host, a
  `file://` URL, a 404 target, an unknown `providerId` - except a **reachable
  target that is not JSON**, which is a 500 carrying the 400-shaped
  `{"error":"invalid_request","error_description":"Cannot parse the JSON"}` body,
  and an absent `fromUrl` or `providerId`, which is
  `400 {"error":"HTTP 400 Bad Request"}`. An unknown field is ignored, so it is
  not one of the strict decoders. Gloak does not serve it, and the reason is that
  `internal/admin` has no outbound HTTP client and the boundary table gives it
  none.
- **A component created with no `name` is a 201 and reads back with no `name`
  key.** "The nameless component" is a state the API reaches, not only the row
  `declarative-user-profile` occupies on a default install - so a `name` column
  that cannot be null is wrong for a second reason. And **a second
  `declarative-user-profile` breaks every login in the realm**: after a sweep
  created one on `master`, the bootstrap administrator's password grant answered
  `400 invalid_grant / "Account is not fully set up"` and the container had to be
  replaced.
- **`GET .../identity-provider/providers/{provider_id}` and `POST
  .../import-config` answer three verbs with a real 405** - `PUT`, `PATCH` and
  `DELETE` - which makes two more Admin API routes in the family F31 tracks.
  `mapper-types`, `mappers` and `sub-component-types` beside them answer `PATCH`
  405 and everything else 404, and `POST .../mappers` with no body at all is a
  **500**. Five neighbouring routes, three answers. See F31 before acting on any
  of it.

### 1.13 Lines in AGENTS.md and the observed document these measurements contradict

Six, each with the request that settles it.

1. **AGENTS.md, the components bullet, and the observed document's "Components on
   a fresh realm":** `declarative-user-profile` is called "the **only** component
   with no `name` key at all" and "the only component in the family with no
   `name` key". True of a default install and **false of what the API allows**:
   `POST /components` with no `name` is a 201 and the row reads back with no
   `name` key. The state is reachable, so the sentence needs "on a default
   install" or it is a claim about the API that a single request refutes.
2. **AGENTS.md's security-header bullet, twice.** "Fifteen committed goldens"
   with "`POST` seven send none of the five, three send all five": the tree held
   **sixteen** and **four** before this cut, and seventeen and four after. See
   §1.12. The conclusion is untouched; the evidence it cites is not what is in
   the repository.
3. **AGENTS.md's `Location` bullet.** "A create's `Location` ends in a
   server-minted UUID on ten routes out of fourteen." `POST .../identity-provider/`
   `instances/{alias}/mappers` is a fifteenth create and its tail is a UUID -
   server-minted when the body names none and the body's own when it does, which
   is the `POST /clients` rule rather than a new one. Eleven of fifteen, counted
   from the list.
4. **AGENTS.md's "Twenty-three spellings of not-found".** `Model not found`, from
   the mapper read and the mapper delete, makes twenty-four.
5. **AGENTS.md's "Eight strict JSON decoders".** `POST .../instances/{alias}/`
   `mappers` and `PUT /components/{id}` are the ninth and tenth, both naming
   their class with a line and a column, and both running the decode **before**
   the path's resource is resolved - a `PUT` to a component id that does not
   exist carrying an unknown field answers the 400 and not the 404. That is the
   required-action PUT's order and the opposite of the organization PUT's, so the
   split the bullet describes gains two members on one side and none on the
   other.
6. **AGENTS.md's malformed-integer-bound bullet.** It closes "this behaviour is
   **per family** rather than per API". The mapper listing is inside the identity
   provider family and **ignores every bound**, `first=abc` included, answering
   200 with the whole set - where the instance listing one path segment up
   answers that same input with a 404. So it is per **route**, and the two
   disagreeing routes are in one chapter.

## 3. Follow-up dispositions

**F145 (`DELETE /components/{id}` is deliberately unbuilt, and the components
table is not what `GET /keys` reads): agreed, and this cut adds two reasons to
leave the whole write side alone rather than only the delete.**

Nothing has changed in F145's premise - `GET /admin/realms/{realm}/keys` is still
not backed by the components table, master still carries four key-provider
components against Gloak's three realm keys, and deleting `rsa-generated` in
Keycloak still removes the realm key. What is new is that the *creates* reach the
same hazard from the other side. `POST /components` accepts a new
`org.keycloak.keys.KeyProvider` row, and on Gloak that would add a key provider
`GET /keys` does not know about - the identical mismatch F145 already records,
one row deeper. And a second `declarative-user-profile` created through the same
endpoint broke every login in the reference realm, which says a row in this table
can take a realm out of service rather than merely misreport it. So the argument
migration 0019 makes for `authz_resource_server` having no `enabled` column now
covers the family's four writes and not only its delete.

**F95 (a client's `attributes` is serialised from a Go map): left open, and this
cut is more evidence and one new argument.**

The ordered-slice pattern now has a **sixth** member, `identityProviderMapperConfig`,
after an organization's attributes, a protocol mapper's config, an identity
provider's config, a component's config and an authz resource's attributes. The
new argument is `marshalOrderedValue`: the HTML-escaping defect in §2 above was
in every one of those marshallers at once, and the fix is one helper they all now
call. `clients.go` marshals a Go map and so is not exposed to it - but it is also
the one place that cannot join the helper, and the day it moves to the ordered
slice it has to. Still not closed here: it lives in `clients.go` and moving it
re-records five goldens in another chapter, which is a change that should arrive
on its own branch.

**F150 (`javamap.SizedKeyOrder` is wrong on `{roles, zzz}`): not closed, and this
cut has the measurement that explains it rather than a fix.**

F150 records that `{roles, zzz}` comes back `[roles, zzz]` from **both** request
orders on the policy family while the model preserves whichever order it was
handed. This cut sent `{zz, aa, mm}` and `{aa, mm, zz}` to the identity provider
mapper family and **both came back in the order they went in** - the model's
behaviour exactly, on three keys that share a bucket at that table size. So the
model is right about the mapper family and wrong about the policy family on the
same shape of input, and the difference is not in `javamap`: `roles` is a key the
**policy provider adds** rather than one the request carried, so the insertion
order `SizedKeyOrder` is handed there is not the insertion order the server used.
That is a claim about the caller, not about the function, and it points the fix
at `authzpolicy.go` rather than at `internal/javamap`. Both request orders of
`{zz, aa, mm}` are vectors now, so the next cut to look at F150 has the
contrasting case beside it.

**F147 (the fifth security-header exception): one more row, no explanation, and a
stale count in AGENTS.md.** See §1.12. The three failures of `POST .../mappers`
are the same route, the same verb and the same `Content-Type`, and two send all
five headers while one sends none - the shape F147 already names as decisive
against "the endpoint decides", now on a second family. And the bullet's own
arithmetic has drifted: it says fifteen goldens with three `POST`s sending all
five, where the tree held sixteen with four before this cut touched anything.

**F134 (four listings treat an unparseable bound as no bound): a third answer.**
The first cut measured the identity provider listing answering `?first=abc` with
a 404 and `/components` ignoring bounds outright. The mapper listing is a third:
it **ignores every bound**, `first=abc` included, and answers 200 with the whole
set - and it is inside the family whose other listing answers 404. So the
behaviour is not even per family; it is per route.

**New: nothing enforces that a package test exercises the code it names.** The
byte-for-byte comparison against the thirty-two measured catalogue bodies
assembled the bodies itself, so a mutation of the serving path survived it. Fixed
on the branch by putting both envelopes behind functions the handler and the test
share - see §5 - but the general shape is worth a follow-up: a test that rebuilds
what it is checking is checking the rebuild, and nothing in this repository would
notice a second one.

## 4. Parity, before and after

```
chapter                    before    after
admin/identity-providers    9/17     16/17
admin/component             2/6       2/6
total                     373/540   380/540   (+7)
```

Measured with the `GLOAK_PARITY_REPORT` procedure AGENTS.md documents, against
the merge base `8ec87ac`.

The seven are `providers/{provider_id}`, `mapper-types` and the five mapper
operations. **The one operation of the chapter that is left is
`import-config`**, and §5 says why.

**`main` was merged mid-flight**, at P13's remaining theme pages (`8ec87ac`),
after the goldens were recorded. Every finding above was re-checked against it
and none moves: that work is in `internal/oidc`, `internal/httpx`'s theme writers
and the conformance normaliser. The one file it touched that this cut depends on
is `internal/httpx/errors.go`, and the change there is a doc comment on
`themePageBody`; `writeJSON`'s `SetEscapeHTML(false)` - which the escaping
finding rests on - is untouched. The whole suite, `make lint`, the Postgres suite
and the kcadm oracle are green on the merged tree.

Not built, each with a stated reason in §5: `import-config`, `POST /components`,
`PUT /components/{id}`, `GET /components/{id}/sub-component-types` and
`DELETE /components/{id}`.

## 5. What was fixed or decided on the branch

- **`marshalOrderedValue`, and the four marshallers that now go through it.**
  Every ordered-object marshaller in `internal/admin` escaped `<`, `>` and `&`
  where Keycloak escapes none of them, because a custom `MarshalJSON` cannot
  inherit the encoder's `SetEscapeHTML(false)`. Measured on the server and on
  Gloak side by side; shipped since P9's first cut; reachable through any
  identity provider config value a caller writes. Fixed, and
  `TestCatalogueValuesAreNotHTMLEscaped` is the guard.
- **A nil `r.Body` panicked the mapper create.** `io.ReadAll(nil)` panics, and
  this is the first strict endpoint that reads the body itself rather than
  through `decodeStrict`. **`make record` found it**, not any package test: the
  harness builds requests by hand and leaves `Body` nil where the server would
  put `http.NoBody`. Both directions of the guard are now mutation-killed.
- **The catalogue's two envelopes were put behind functions the handler and the
  test share.** A mutation that reversed the mapper-types loop **survived** the
  byte-for-byte test, because the test assembled the bodies itself. That is the
  one survivor of this cut's mutation pass that was a hole in a test rather than
  a hole in a mutation, and it is fixed rather than excused.
- **`decodeStrict` was split into a bytes half.** One endpoint has to look at the
  body before the decode - an empty body is a 500 there and a malformed one a
  400 - and splitting the function is what kept that endpoint on the same strict
  decoder as the other nine rather than growing a second one.
- **`IdentityProviderMapperTypesFail` and the branch that consulted it are
  gone.** Review found the branch survived deletion; the check that explains it
  is one request, and it is in §6. The two provider ids the predicate named are
  exactly the two the catalogue has no mapper set for, so the fallback below it
  wrote the identical body and the branch could not change an answer. The
  condition is asserted now -
  `TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s` compares the whole
  absent list, so each of the two fails it on its own - and the one branch that
  is left is mutation-killed.
- **Not built, and each reason is a measurement rather than a budget:**
  - `POST .../identity-provider/import-config` - §1.10. An outbound HTTP fetch
    made from `internal/admin`, which the boundary table gives no client and no
    timeout policy. Building it means deciding where an outbound HTTP client
    lives in this project, and a family cut is the wrong place to decide it. Its
    failure modes, its SSRF surface and its success body are all measured above
    so the cut that decides does not re-measure.
  - `POST /components` and `PUT /components/{id}` - the filter is the catalogue
    (§1.4) and the refusals are not (§1.5). A create built on the catalogue's
    `required` flag answers 400 for the eight LDAP mappers and 201 for the seven
    other providers Keycloak refuses, and would still miss the two value
    validators, the two-property sequence and the empty-string rule: seven
    measured divergences on fifteen measured inputs. F145's hazard applies too.
  - `GET /components/{id}/sub-component-types` - 47650 bytes and 168 properties,
    the expensive half of the catalogue, and the only one of the three envelopes
    with no caller in this cut once the two writes are out.
  - `DELETE /components/{id}` - F145, agreed, with two reasons added in §3.

## 6. The mutation pass

Thirty-seven mutations that applied, a different one per claim, each confirming
the **named** test fails and then reverted. Counted from the runs rather than
incremented:

```
handlers and store   1..12, 14, 15, 17, 19          16 killed
                     13, 16                          2 killed on the second try
                     18                              1 SURVIVOR, then killed
goldens              20, 21, 22                      3 killed
the nil-body guard   23                              1 SURVIVOR (not discriminating)
                     23a, 23b                        2 killed
javamap              the two table sizes             2 killed
                     the three vectors               3 killed
in review            the mapper-types 500 branch     1 SURVIVOR (dead code)
                     the branch that replaced it     1 killed
                     the absent set, four ways       4 killed
```

Thirty-four killed, three survivors, and none of the three was a mutation
problem: one was a hole in a test, one was a blunt mutation of a live block, and
one was dead code.

**The one real survivor was a hole in a test, and the rule caught it.**
Reversing the `mapper-types` loop inside the handler passed
`TestProviderCatalogueReproducesEveryMeasuredBody`, which compares the served
bytes against thirty-two measured bodies - because the test built those bytes
itself instead of asking the handler for them. A test that rebuilds what it is
checking is checking the rebuild. Both envelopes are functions now, the test
calls them, and the same mutation is killed.

**The second survivor was not a survivor.** Replacing the nil-body guard's
condition with `if false` left the empty-body case answering the same 500, so the
mutation was behaviour-preserving on that one input rather than the block being
dead. AGENTS.md's rule - if every mutation of a block preserves behaviour, the
block preserves behaviour - was applied rather than assumed: both real mutations
of that block, removing the guard outright and never reading the body, are
killed, one by the conformance golden and one by the create's own test.

**The third survivor came from review, and it was dead code.** Deleting the four
lines that asked `model.IdentityProviderMapperTypesFail` whether this provider
was one of the two that answer a 500 left `./internal/admin/` and
`./internal/conformance/` both `ok`.

The reason is not that the behaviour was untested. **It is that the deletion
cannot change an answer**, and the check that says so is one request, not an
argument: with the branch removed, `linkedin-openid-connect` answers 500,
`openshift-v4` answers 500 and `oidc` answers its map - byte for byte what they
answered before. The two ids the predicate named are exactly the two the
catalogue has no mapper set for, so the `!ok` fallback two lines below wrote the
identical body. Two spellings of one condition, one of them unreachable, and the
first reading of the survivor - that the two providers would start serving a map
- is refuted by the map not existing.

So this is the nil-body block's class and not a new one, with one difference that
matters: **that block was live and only the mutation was blunt, this block was
dead.** AGENTS.md's rule is what separates them, and it is the whole of the
method here - a survivor is a finding, and the finding is about the code exactly
when every mutation of the block preserves behaviour.

The branch and the predicate are gone. What is left is the one `!ok` branch,
which is live - deleting it serves `{}` with a 200 and fails
`TestMapperTypesFollowTheProvider` - and
`TestTheProvidersWithNoMapperTypesAreTheTwoMeasured500s`, which compares the
**whole** absent list rather than asking about each id. Five mutations confirm
it, each failing the named test:

```
the 500 branch deleted outright                TestMapperTypesFollowTheProvider
openshift-v4 gains a mapper set                TestTheProvidersWithNoMapperTypes...
linkedin-openid-connect gains a mapper set     TestTheProvidersWithNoMapperTypes...
github loses its mapper set                    TestTheProvidersWithNoMapperTypes...
the consult-log sentence                       TestMapperTypesFollowTheProvider
```

The middle two are the point of comparing the list rather than the members: **two
ids behind one claim is the shape where a test pins one and lets the other rot**,
and each of them fails on its own.

**A golden would not be stronger here, and that is a judgement worth stating.**
`admin/identity-providers/mapper-types-unsupported` already holds
`linkedin-openid-connect`'s 500 as recorded bytes, headers included. A second
golden for `openshift-v4` would assert byte-identical content through the same
writer - a duplicate measurement - and, more to the point, **no golden can pin a
set**: it says "this provider answers this" and cannot say "and these are the
only two", which is the half that rots. The package test carries the set and both
ids, the golden carries the bytes, and neither replaces the other.

**A counted claim was wrong on its first writing and the test refused it.**
`KeyOrder` is wrong on **seven** of the ten mapper config vectors, not six. That
is the third time in `internal/javamap` alone.

**One process failure, and it cost the javamap work once.** The mutation script
reverts with `git checkout -- <file>`, and the javamap vectors were still
uncommitted when it ran, so they were destroyed and had to be rewritten. AGENTS.md
names that exact command and this cut's own plan quoted the rule in its §4. The
rule is not "commit before the mutation pass"; it is **commit before the edit
that the mutation pass will revert**, which includes an edit made in the middle
of one.

The store claims were mutated against the SQLite driver and the Postgres suite
was run by hand on the merged tree, uncached and with `-v`: 58 subtests,
`an_identity_provider_mapper_is_listed_by_alias_and_found_without_one` among
them.
