# P9 first cut: identity providers and components

Measured against a live Keycloak 26.7.1 on 2026-09-01, container `kc-idp` on
port 8151, `start-dev`, bootstrap admin `admin/admin`. Every value below came
off that container. Nothing here is written from memory.

## 0. The two things the brief asked to establish first

### A provider instance can be created, and the `http` refusal is one attribute away

The previous cut's note is exact and its consequence is the opposite of what it
looked like. `POST /admin/realms/{realm}/identity-provider/instances` with

```json
{"alias":"a","providerId":"oidc","config":{"clientId":"cid","clientSecret":"s",
 "authorizationUrl":"http://example.com/auth","tokenUrl":"http://example.com/token"}}
```

answers `400 {"errorMessage":"The url [authorization_url] requires secure connections"}`.
The **identical body with `https`** answers `201`. So the refusal is about the
scheme of one config value, not about TLS on the server, and **the whole tag is
reachable on a default container over plain HTTP**. Nothing in this cut needs a
certificate.

A social provider needs no URL at all: `{"alias":"a","providerId":"github",
"config":{"clientId":"cid","clientSecret":"s"}}` is a 201, and so is the
**minimal** body `{"alias":"a","providerId":"oidc"}` with no config whatsoever.

Fifteen of the seventeen registered providers are creatable from a bare
`{alias, providerId}`. The two that are not are not unregistered - they have
required config:

```
jwt-authorization-grant  400 {"errorMessage":"Issuer is required"}
oauth2                   400 {"errorMessage":"User Info URL not provided"}
```

That is the correction to a first reading of the same 400s as "not registered",
which `GET /admin/serverinfo` refutes: it lists all seventeen.

### What `components` holds on a fresh realm - and master and a created realm differ

`GET /admin/realms/master/components` on a container that has done nothing is
**15 rows**. `GET /admin/realms/{created}/components` on a realm made with
`POST /admin/realms {"realm":"x","enabled":true}` is **14**.

The one master has and a created realm does not is the
`org.keycloak.userprofile.UserProfileProvider` / `declarative-user-profile`
row, and it is also **the one component with no `name` key at all**. Its single
config value is a 1.1 kB JSON *string*.

The other fourteen are the same in both, counted from the listing:

```
 4  org.keycloak.keys.KeyProvider
      rsa-generated       {"priority":["100"]}
      rsa-enc-generated   {"priority":["100"],"algorithm":["RSA-OAEP"]}
      hmac-generated-hs512 (providerId hmac-generated) {"priority":["100"],"algorithm":["HS512"]}
      aes-generated       {"priority":["100"]}
10  org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy
      subType anonymous     (7): Consent Required, Allowed Client Scopes, Full Scope Disabled,
                                 Allowed Protocol Mapper Types, Allowed Registration Web Origins,
                                 Trusted Hosts, Max Clients Limit
      subType authenticated (3): Allowed Protocol Mapper Types,
                                 Allowed Registration Web Origins, Allowed Client Scopes
```

So the listing is **not** empty and it is not user federation: a default
install's components are the realm's key providers plus the client-registration
policy set, and `parentId` on every one of them is the **realm's internal id**.

Two things in it have **no reproducible order** and both were measured on two
realms of one container:

- the **row order** of the listing. Two realms created minutes apart returned
  the same fourteen rows in two completely different orders.
- the `allowed-protocol-mapper-types` **array inside a config value**. Eight
  names, two realms, two orders.

Neither is insertion order, name order or id order.

## 1. Scope of this cut

The tag counts are 17 and 6, and the brief's breakdown of the 13 under
`{alias}` is correct - re-counted from the description rather than incremented.

**Nine operations are built here**, taking the two chapters from 2 of 23 to
11 of 23.

| # | Operation | Note |
|---|---|---|
| 1 | `GET /identity-provider/instances` | search, first, max, briefRepresentation, realmOnly |
| 2 | `POST /identity-provider/instances` | |
| 3 | `GET /identity-provider/instances/{alias}` | |
| 4 | `PUT /identity-provider/instances/{alias}` | |
| 5 | `DELETE /identity-provider/instances/{alias}` | |
| 6 | `GET /identity-provider/instances/{alias}/export` | |
| 7 | `GET /identity-provider/instances/{alias}/reload-keys` | |
| 8 | `GET /components` | type, parent, name |
| 9 | `GET /components/{id}` | |

Already served, unchanged: the two `management/permissions` operations P10
measured as a 501.

**Not built, each for a stated reason** - all get a `Recorded` case carrying the
measurement so the next cut starts from bytes rather than from a guess:

| Operation | Why not now |
|---|---|
| `POST /identity-provider/import-config` | makes an **outbound HTTP fetch** of a discovery document. Unrecordable without a second server in the harness. |
| `GET /identity-provider/providers/{provider_id}` | a per-provider `configProperties` catalogue: 17 providers, each a list of typed properties with help text. A constant of the same kind as `policyProviders`, an order of magnitude larger. |
| `GET .../{alias}/mapper-types` | the same shape again and **chunked** - ten mapper types with full property lists, 11 kB for `oidc`. |
| the five `.../{alias}/mappers` operations | need a mapper table and the mapper-type catalogue above to validate against. |
| `POST` / `PUT /components` | need the per-provider config-property catalogue: the write **filters the config down to the provider's declared properties** (measured: four keys in, one key back) and refuses an unknown provider with `Invalid provider type or no such provider`. |
| `DELETE /components/{id}` | trivial as a row delete and **wrong as a behaviour**: deleting `rsa-generated` in Keycloak removes the realm key, and Gloak's `GET /keys` is not backed by this table. Shipping it would offer a state Keycloak cannot reach - the argument migration 0019 already makes for `authz_resource_server` having no `enabled` column. |
| `GET /components/{id}/sub-component-types` | same catalogue, plus a measured 500 for an unknown `type`. |

## 2. What was measured

### 2.1 The gate is a fifth shape, and it splits inside itself

Swept one role at a time over sixteen callers (fourteen single-role probe users,
one holding nothing, and a full administrator):

```
                                            norole  v-idp  m-idp  v-realm m-realm  every other
GET  identity-provider/instances              403    200    200     403     403       403
GET  identity-provider/instances/{alias}      403    200    200     403     403       403
GET  .../{alias}/export                       403    204    204     403     403       403
GET  .../{alias}/mappers                      403    200    200     403     403       403
GET  .../{alias}/mapper-types                 403    200    200     403     403       403
GET  identity-provider/providers/{id}         403    200    200     403     403       403
GET  .../{alias}/reload-keys                  403    403    200     403     403       403   <-- !
DELETE identity-provider/instances/{alias}    403    403    204     403     403       403
GET  components                               403    403    403     200     200       403
GET  components/{id}                          403    403    403     200     200       403
DELETE components/{id}                        403    403    403     403     204       403
```

Three findings in that table.

**`GET .../{alias}/reload-keys` is a read that refuses the view role.** It needs
`manage-identity-providers`. AGENTS.md records exactly one such read in the
whole API - `GET .../authz/resource-server/settings` - and says sharing a role
list between it and its neighbour "opens a settings export to a read-only
caller". This is the second, and the two are not related: `reload-keys` sits
among six sibling reads that all take the view role.

**The Component tag is authorised out of the *realm* role set, not the
identity-provider one**, although its rows are key providers and user
federation. `manage-identity-providers` is 403 on every component route.

**`view-clients` and `manage-clients` reach neither family.** So this is a fifth
gate shape: neither `client-types`' feature 501, nor organizations' realm flag,
nor the client flag, nor `guardAuthz`'s client-resolution order, nor no gate at
all. It is a plain two-role gate, and its **resolution order is role-first** -
`DELETE` of an alias that does not exist is 403 to a `view-identity-providers`
caller and 404 to a `manage-identity-providers` one. That is the
`default-*-client-scopes` order and the opposite of the `Groups` tag's.

### 2.2 The two families use the two different Java map constructors

This is the finding with the most consequence for the code.

**An identity provider's `config` is `javamap.SizedKeyOrder(n, keys)`.** Nine
key sets measured on the server, `SizedKeyOrder` places all nine, `KeyOrder`
gets **four** wrong:

```
{clientId,clientSecret}                                  -> clientSecret clientId
{clientId,clientSecret,authorizationUrl,tokenUrl}        -> clientSecret clientId tokenUrl authorizationUrl
{clientId,clientSecret,authorizationUrl,tokenUrl,
 userInfoUrl,logoutUrl,issuer}                           -> userInfoUrl clientId tokenUrl authorizationUrl logoutUrl clientSecret issuer
{zz,aa,mm}   -> zz aa mm      (insertion order)
{aa,mm,zz}   -> aa mm zz      (insertion order, same three keys)
{a..e} {a..f} {k1..k9}                                   -> insertion order
{k1..k10}                                                -> k1..k6 k10 k7 k8 k9
```

**A component's `config` is `javamap.KeyOrder`.** Seven key sets measured,
`KeyOrder` places six, `SizedKeyOrder` gets **two** of those six wrong:

```
{priority,enabled}                          -> priority enabled
{priority,enabled,active}                   -> active priority enabled          Sized wrong
{priority,enabled,active,algorithm}         -> active priority enabled algorithm
{priority,enabled,active,algorithm,keySize} -> keySize active priority enabled algorithm   Sized wrong
{priority,enabled,active,algorithm,secretSize} -> active secretSize priority enabled algorithm
{priority,enabled,active,secretSize}        -> active secretSize priority enabled
```

The seventh is twelve LDAP keys and **neither function places it**: three pairs
come back the other way round, which is the documented bucket-collision limit of
both. It is recorded and not used.

So a shared `config` serialiser between the two families is wrong on one of
them, and which one it is wrong on depends on the key count. Both are pinned as
`javamap` vectors.

### 2.3 The identity provider representation

Field order, measured on a create carrying every field the type accepts:

```
alias displayName internalId providerId enabled updateProfileFirstLoginMode
trustEmail storeToken addReadTokenRoleOnCreate authenticateByDefault linkOnly
hideOnLogin firstBrokerLoginFlowAlias postBrokerLoginFlowAlias organizationId
config types
```

Of those, `updateProfileFirstLoginMode` and `postBrokerLoginFlowAlias` were sent
and **never come back**, and `organizationId:""` is a
`400 {"errorMessage":"Organization associated with broker does not exist"}` -
an empty string is not an absent field there.

- **`alias` carries `omitempty` and it is measurable.** A `PUT` whose body has
  no alias answers **204** and leaves a row the listing serves **with no `alias`
  key**, which no other request can then address. Keycloak's own defect; see
  §2.6.
- **`enabled` is always present**, `true` by default.
- **`trustEmail`, `storeToken`, `addReadTokenRoleOnCreate`,
  `authenticateByDefault`, `linkOnly`, `hideOnLogin` are absent when never set
  and present as `false` when sent `false`.** Six tri-state booleans on one
  body. A plain `bool` collapses two states the wire distinguishes.
- **`displayName` is not tri-state**: `""` is stored and served as `""`.
- **`config` is present as `{}` rather than absent**, always.
- **`clientSecret` is served as the ten characters `**********`** on every read
  and in the listing.
- **`types` is derived from `providerId` and stored nowhere.** Four values over
  the seventeen providers:

```
oidc, keycloak-oidc  ["USER_AUTHENTICATION","CLIENT_ASSERTION","TRUST_MATERIAL",
                      "EXCHANGE_EXTERNAL_TOKEN","JWT_AUTHORIZATION_GRANT"]
saml                 ["USER_AUTHENTICATION"]
kubernetes           ["CLIENT_ASSERTION"]
the eleven social,
oauth2, jwt-authorization-grant   []
```

### 2.4 The listing

Sorted **by alias**: three providers created `zzz, mmm, aaa` came back
`aaa, mmm, zzz`.

`search` is a **case-insensitive prefix with `*` as a wildcard and `"quotes"`
meaning equality** - the user listing's `search` rule, not the four-field
substring one. The discriminating probe is a middle substring: with an alias
`xabbcx`, `search=abb` is `[]` and `search=xab`, `search=XAB`, `search=*abb*`,
`search=*bbc`, `search=x*` and `search="xabbcx"` all match. An empty `search=`
returns everything.

`first` and `max` page, and **either bound alone is enough** - `max=1` alone
pages, which is the role listings' rule and not the requirement that both be
present. `first=-1&max=-1` returns everything.

**`briefRepresentation` defaults to `false` here and drops `types` when true.**
That is the third default this parameter has in this API. The single read
**ignores it**, exactly as the organization read does.

**A malformed bound is the measured 404**: `?first=abc` answers
`404 {"error":"HTTP 404 Not Found"}`. `/components` next door **ignores `first`
and `max` outright** - `?first=1&max=2` returns all fourteen rows and
`?first=abc` is a 200 with the whole list. Two neighbouring families, opposite
answers to one malformed input, both measured in this cut. See F134.

`realmOnly=true` changed nothing on a realm with no organizations.

### 2.5 The refusals

```
POST, no alias                {"errorMessage":"path is null"}                          400
POST, no providerId           {"errorMessage":"Invalid identity provider id [null]"}   400
POST, unknown providerId      {"errorMessage":"Invalid identity provider id [x]"}      400
POST, duplicate alias         {"errorMessage":"Identity Provider a already exists"}    409
POST/PUT, unknown field       {"error":"Invalid json representation for
                               IdentityProviderRepresentation. Unrecognized field
                               \"zzz\" at line 1 column 58."}                          400
POST/PUT, empty body          {"error":"unknown_error", ...}                           500
POST/PUT, malformed body      {"error":"invalid_request",
                               "error_description":"Cannot parse the JSON"}            400
PUT, alias changed            {"errorMessage":"Identity Provider alias cannot be changed"} 400
GET/PUT/DELETE, unknown alias {"error":"HTTP 404 Not Found"}                           404
GET components/{id} unknown   {"error":"Could not find component"}                     404
GET .../sub-component-types   {"error":"Could not find parent component"}              404
GET .../sub-component-types   {"error":"must specify a subtype"}                       400
```

Three of those matter beyond their own route.

**`POST` and `PUT` on the instances are the sixth and seventh strict decoders**,
and `POST /components` is the eighth. All three name their class and **report a
line and column**. AGENTS.md says client registration "is the only one that
reports a position"; that was already false when it was written - `decodeStrict`
in this repository has produced a position since the required-action PUTs - and
it is now false four ways over.

**The strict decode runs before the alias is resolved.** A `PUT` to an alias
that does not exist carrying an unknown field answers the 400, not the 404. That
is `PUT /required-actions/{alias}`'s order and the opposite of
`PUT /organizations/{id}`'s.

**An unknown alias is the generic `{"error":"HTTP 404 Not Found"}`,** not a
twenty-second spelling of not-found. The two component 404s *are* new spellings.

### 2.6 Two Keycloak defects reproduced, and one declined

**`PUT` with no alias in the body answers 204 and strands the row.** The alias
becomes absent; the listing serves the row with no `alias` key and it sorts
first; nothing can address it again. The rename check is `alias cannot be
changed`, and a null alias is not a change, so the check passes and the write
lands anyway. Reproduced: the `PUT` replaces, and it replaces the alias too.

**`PUT` replaces outright and does not merge.** A provider carrying eight
non-default fields and four config keys, updated with
`{"alias":"a","providerId":"oidc","displayName":"Renamed"}`, kept its
`internalId` and lost everything else, config included.

**`POST` honours the body's `internalId`.** A create naming
`11111111-1111-1111-1111-111111111111` produced a provider with exactly that id.
That is the third create whose body id wins, after `POST /clients` and
`POST /client-scopes`, against `POST /organizations` where it loses.

**Declined:** `PUT /components/{id}` with a partial body is a **500 that has
already written the name** - the row was renamed and the config kept, and then
the request failed. That endpoint is not in this cut, so nothing is decided
here; it is recorded so the cut that builds it does not discover it by
accident.

### 2.7 Headers

Everything in this cut follows the rules AGENTS.md already records, and two
values are worth pinning because they are per endpoint:

```
GET  instances, instances/{alias}, mappers, mapper-types, providers/{id}
                                        200  ;charset=UTF-8  Cache-Control: no-cache
GET  components, components/{id}        200  ;charset=UTF-8  Cache-Control: no-cache
GET  .../{alias}/reload-keys            200  ;charset=UTF-8  Cache-Control: no-cache   body `false`
GET  .../{alias}/export  (non-saml)     204  no body, no Content-Type, Cache-Control: no-cache
GET  .../{alias}/export  (saml)         200  application/xml, Cache-Control: no-cache
PUT  instances/{alias}                  204  Cache-Control: no-cache, X-Frame-Options
DELETE instances/{alias}                204  Cache-Control: no-cache, no X-Frame-Options
POST instances                          201  Location, no Content-Type, content-length 0
```

`Location` ends in the **alias**, not a UUID - a name tail, joining
`POST /roles`, `POST /clients/{uuid}/roles` and `POST /admin/realms`. AGENTS.md
says two of the thirteen creates "could not be reached on a default container
and are not counted"; this is one of them, and it makes the tally **eleven name
or uuid tails out of fourteen** rather than ten of thirteen.

**The SAML export cannot be `Recorded`.** Its body carries
`ID="ID_<fresh uuid>"`, minted per request; two identical requests differ. Only
the non-SAML 204 is asserted here.

### 2.8 Wrong verbs, for the record and not for changing anything

```
/identity-provider/instances            PUT 405   PATCH 405   DELETE 405
/identity-provider/instances/{alias}    POST 404  PATCH 405
/components                             PUT 404   PATCH 405   DELETE 404
```

The instances listing answers three real 405s - the client-scope attachments'
shape. `/components` answers `PATCH` alone - the protocol mappers' shape. Two
sibling families in one cut, two answers. Gloak answers 404 to all of them
through `WithKeycloakFallbacks` and **nothing is changed on the strength of
this**. See F31.

## 3. Implementation

### 3.1 `internal/model`

`model.IdentityProvider`: `InternalID, RealmID, Alias (nullable), DisplayName,
ProviderID, Enabled, TrustEmail/StoreToken/AddReadTokenRoleOnCreate/
AuthenticateByDefault/LinkOnly/HideOnLogin (all *bool),
FirstBrokerLoginFlowAlias, Config []IdentityProviderConfigEntry`.

`model.Component`: `ID, RealmID, Name (nullable), ProviderID, ProviderType,
ParentID, SubType, Config []ComponentConfigEntry` where a config value is a
`[]string`.

`identityProviderTypes(providerID) []string` and the seventeen-name registry
live here: they are derived from `providerId` and nothing stores them.

### 3.2 `internal/store` + migration `0021_identity_provider.sql`

```
identity_provider          internal_id PK, realm_id FK, alias NULL, display_name,
                           provider_id, enabled, six nullable INTEGER flags,
                           first_broker_login_flow_alias,
                           UNIQUE (realm_id, alias)
identity_provider_config   internal_id FK, name, value, ordinal
component                  id PK, realm_id FK, name NULL, provider_id,
                           provider_type, parent_id, sub_type, ordinal
component_config           component_id FK, name, value, ordinal
```

`alias` and `name` are nullable because the wire distinguishes absent from
empty on both, and §2.6 shows a request that reaches the absent state.

Repositories `store.IdentityProviderRepo` and `store.ComponentRepo`, both
drivers, `storetest` coverage, and the Postgres suite run by hand.

### 3.3 `internal/bootstrap`

`components.json` beside `clientscopes.json`, holding the fourteen a created
realm gets plus the `declarative-user-profile` row flagged as master-only. The
bootstrap writes them for `master`; the realm-create path writes the fourteen.

### 3.4 `internal/admin`

`identityproviders.go` and `components.go`, `guardIdentityProviders` and
`guardComponents` on the two role pairs, routes appended to the router.
`decodeStrict` is reused unchanged.

### 3.5 `internal/conformance`

Cases appended at the very end of `adminCases`, fixtures at the very end of the
fixture map and after the last helper. Masks:

- `admin/component/list`: `Unordered` at the root **and** on
  `*/config/allowed-protocol-mapper-types`. Neither is inert - fourteen rows and
  an eight-element array, both measured moving between two realms.
- `Volatile` on the component ids and `parentId`, which are per-realm UUIDs.
- `VolatileTailHeaders` is **refused** on `POST /identity-provider/instances`:
  its `Location` tail is the alias the request chose, so it is asserted.

## 4. Order of work

1. Commit this plan.
2. `internal/model`, migration `0021`, both drivers, `storetest`.
3. `internal/bootstrap`.
4. `internal/admin/identityproviders.go`, `components.go`, router.
5. Package tests; a mutation per claim, each confirming the named test fails.
6. Conformance cases and fixtures, `make record`, read every moved golden.
7. `make lint`, `make test`, the Postgres suite, `make oracle`.
8. The handover at `docs/superpowers/handover/p9-identity-providers.md`.
