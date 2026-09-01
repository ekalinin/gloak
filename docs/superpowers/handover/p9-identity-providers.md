# P9 first cut: identity providers and components

Branch `feat/p9-identity-providers`. Everything below was measured against a
live Keycloak 26.7.1 on 2026-09-01 - container `kc-idp`, port 8151, `start-dev`,
bootstrap admin `admin/admin`, removed afterwards. The plan is at
`docs/superpowers/plans/2026-09-01-p9-identity-providers.md`.

## 1. Measurements

### 1.1 The two questions the brief asked first

**A provider instance can be created on a default container, and the `http`
refusal is one attribute away.** `POST .../identity-provider/instances` with an
`http` authorization URL is
`400 {"errorMessage":"The url [authorization_url] requires secure connections"}`;
the identical body with `https` is a 201. A social provider needs no URL at all,
and the minimal body `{"alias":"a","providerId":"oidc"}` is a 201 with no config
whatsoever. Nothing in this tag needs TLS on the server.

Fifteen of the seventeen registered providers take a bare `{alias, providerId}`.
The two that do not are **not unregistered** - `GET /admin/serverinfo` lists all
seventeen - they have required config: `jwt-authorization-grant` answers
`{"errorMessage":"Issuer is required"}` and `oauth2` answers
`{"errorMessage":"User Info URL not provided"}`. Reading those two 400s as "not
registered" was this cut's own first mistake, caught by asking serverinfo.

**`components` on a fresh realm holds fifteen rows on master and fourteen on a
created realm.** Four key providers (`rsa-generated`, `rsa-enc-generated`,
`hmac-generated`, `aes-generated`), ten client-registration policies (seven
`anonymous`, three `authenticated`), and - **on master alone** - the
`declarative-user-profile` `UserProfileProvider`, whose config is a 1.1 kB JSON
string. That row is also **the one component in the family with no `name` key at
all**, so "the nameless component" and "the component a created realm does not
get" are the same row.

`parentId` on every one of them is the **realm's internal id**. So the listing is
neither empty nor about user federation, which is what the tag name suggests.

### 1.2 The tag counts and the scope estimate

Re-counted from the vendored description rather than incremented, and the
brief's breakdown is exact: Identity Providers 17 (13 under `{alias}`, 2 on
`instances`, 1 `import-config`, 1 `providers/{provider_id}`), Component 6.

**The estimate held this time**, which is worth saying because the brief warns
it never has. Nine operations planned, nine built. What moved instead was the
*content* of three of them - see §1.9.

### 1.3 A fifth gate shape, and one read inside it that refuses the view role

Swept one role at a time, a token per role, sixteen callers against fifteen
requests:

```
                                          norole v-idp m-idp v-realm m-realm  the other eleven
GET  identity-provider/instances            403   200   200    403     403         403
GET  .../instances/{alias}                  403   200   200    403     403         403
GET  .../instances/{alias}/export           403   204   204    403     403         403
GET  .../instances/{alias}/mappers          403   200   200    403     403         403
GET  .../instances/{alias}/mapper-types     403   200   200    403     403         403
GET  identity-provider/providers/{id}       403   200   200    403     403         403
GET  .../instances/{alias}/reload-keys      403   403   200    403     403         403
DELETE .../instances/{alias}                403   403   204    403     403         403
GET  components                             403   403   403    200     200         403
GET  components/{id}                        403   403   403    200     200         403
DELETE components/{id}                      403   403   403    403     204         403
```

Three things in that table.

**`GET .../reload-keys` is a read that refuses the view role.** It needs
`manage-identity-providers` where its six siblings take
`view-identity-providers` too. AGENTS.md records exactly one such read in the
API - `GET .../authz/resource-server/settings` - and warns that sharing a role
list between it and its neighbour "opens a settings export to a read-only
caller". This is the second, and it sits among six siblings that do not share
it, rather than beside one.

**The Component tag is authorised out of the realm role pair**, although its rows
are key providers and client-registration policies. `manage-identity-providers`
is 403 on both component routes. Two neighbouring chapters, two disjoint role
pairs, and nothing in the description says so - the third time the tag has failed
to predict the guard.

**The gate itself is a fifth shape**: neither `client-types`' feature 501, nor
organizations' realm flag, nor `guardAuthz`'s client-resolution order, nor no
gate at all. It is a plain two-role check, and the resource is resolved
**after** it: a `DELETE` of an alias that does not exist is 403 to a
`view-identity-providers` caller and 404 to a `manage-identity-providers` one.
That is the `default-*-client-scopes` order and the opposite of the `Groups`
tag's.

### 1.4 The two families use Keycloak's two HashMap constructors, one each

The finding with the most consequence for the code.

**An identity provider's `config` is `javamap.SizedKeyOrder`.** Nine key sets
measured, all nine placed; `javamap.KeyOrder` gets **four** of the nine wrong:

```
{clientId,clientSecret}                            -> clientSecret clientId
{clientId,clientSecret,authorizationUrl,tokenUrl}  -> clientSecret clientId tokenUrl authorizationUrl
{zz,aa,mm} sent in that order                      -> zz aa mm
{k1..k10}                                          -> k1..k6 k10 k7 k8 k9
```

**A component's `config` is `javamap.KeyOrder`.** Seven key sets measured, six
placed; `SizedKeyOrder` gets **two** of those six wrong:

```
{priority,enabled,active}                          -> active priority enabled       Sized wrong
{priority,enabled,active,algorithm,keySize}        -> keySize active priority enabled algorithm   Sized wrong
```

The seventh is twelve LDAP keys and **neither function places it**: three pairs
come back the other way round, the documented bucket-collision limit of both.

So a shared `config` serialiser between the two families is wrong on one of them,
and which one depends on the key count. Both directions are now vectors in
`internal/javamap`'s own tests - see §1.10, because the *serialisers* cannot pin
this and a mutation proved it.

### 1.5 The identity provider representation

Field order, from a create carrying every field the type accepts:

```
alias displayName internalId providerId enabled trustEmail storeToken
addReadTokenRoleOnCreate authenticateByDefault linkOnly hideOnLogin
firstBrokerLoginFlowAlias config types
```

- **`updateProfileFirstLoginMode` and `postBrokerLoginFlowAlias` are accepted
  and never echoed.** Sent, 201, absent from every read.
- **`organizationId` is a 400 for any value including `""`**:
  `{"errorMessage":"Organization associated with broker does not exist"}`. An
  empty string is not an absent field there.
- **Six tri-state booleans.** `trustEmail`, `storeToken`,
  `addReadTokenRoleOnCreate`, `authenticateByDefault`, `linkOnly` and
  `hideOnLogin` are **absent** when never set and present as `false` when sent
  `false`. `displayName` on the same body is not tri-state - `""` is stored and
  served. Two rules, one body.
- **`enabled` is always present**, defaulting to `true`.
- **`config` is always present**, `{}` when empty.
- **`clientSecret` is served as the ten characters `**********`** on every read.
- **`types` is derived from `providerId` and stored nowhere.** Four values over
  the seventeen providers: five entries for `oidc` and `keycloak-oidc`, one
  (`USER_AUTHENTICATION`) for `saml`, one (`CLIENT_ASSERTION`) for `kubernetes`,
  and `[]` for the eleven social providers, `oauth2` and
  `jwt-authorization-grant`. A boolean "is it OIDC" gets two of the four wrong.

### 1.6 The listing

Sorted **by alias**: three created `zzz, mmm, aaa` came back `aaa, mmm, zzz`.

`first` and `max` page, and **either bound alone is enough** - `max=1` alone
pages, which is the role listings' rule and not "both or search".
`first=-1&max=-1` returns everything.

**A malformed bound is `404 {"error":"HTTP 404 Not Found"}`**, the scope
family's answer. `/components` next door **ignores both bounds outright**:
`?first=1&max=2` returned all fourteen rows and `?first=abc` a 200 with the whole
listing. Two neighbouring families, one malformed input, opposite answers,
measured in one cut on one container. See §3, F134.

`realmOnly=true` changed nothing on a realm with no organizations.

### 1.7 `search` is one rule on three families and a different one on two, and Gloak had it wrong

The sharpest finding of the cut, and it reaches outside P9.

With a value `xabbcx`, `search=*bbc` **matches** - and `xabbcx` does not end in
`bbc`. So the rule is not an anchored glob. What fits every probe is Keycloak's
LIKE: replace each `*` with `%`, **append a `%` when the pattern does not already
end in one**, compare case-insensitively; `"quotes"` mean equality.

```
search   idp    users  groups  roles
*bbc     match  match  match   []
xab      match  -      match   match
abb      []     -      -       -
```

**`*` is a wildcard on the identity providers, the users and the groups, and a
literal on the roles**: `xa*`, `*abbcx`, `*abb*` and `x*x` all answer `[]` there
while the bare `xabbcx` matches.

**Gloak's `matchesSearch` implemented the anchored glob**, and its doc comment
enumerated six probes that agreed with it - because not one of those six can tell
the two readings apart. `user*` is `user%` under both. Only a pattern whose last
literal run is neither at the end of the value nor followed by a `*` separates
them, and nobody had sent one.

Fixed on this branch (§4). No golden moved: the one wildcard search in the
catalogue is `*probe-user@example*`, which both readings match.

### 1.8 Two Keycloak defects reproduced

**A `PUT` with no `alias` in the body answers 204 and strands the row.** The
alias is cleared; the listing then serves the row with **no `alias` key**, sorted
first, and nothing can address it again. The rename guard is
`Identity Provider alias cannot be changed`, and a null alias is not a change, so
the check passes and the write lands anyway. Reproduced, and
`admin/identity-providers/update-strands-the-row` is the golden that holds it.
Refusing an absent alias is the tidy-up that turns a measured 204 into a 400.

**A present alias that differs is refused**, 400. Two halves of one sentence, one
request each.

**The `PUT` replaces outright.** A provider carrying eight non-default fields and
four config keys, updated with a body naming only the alias, the provider id and
a display name, kept its `internalId` and lost everything else, config included.

**The body's `internalId` wins on create.** A create naming
`11111111-1111-1111-1111-111111111111` produced a provider with exactly that id -
the third create with that rule after `POST /clients` and `POST /client-scopes`,
against `POST /organizations` where the id is read and discarded.

**Not reproduced, and not in this cut:** `PUT /components/{id}` with a partial
body is a **500 that has already written the name**. The row was renamed and its
config kept, and then the request failed. Recorded so the cut that builds that
endpoint does not find it by accident.

### 1.9 What the recorder found that the probes did not

**`briefRepresentation=true` on the identity provider listing answers a six-key
shape, not the full shape minus a field.** It drops the six tri-state flags,
`firstBrokerLoginFlowAlias` and `types`, **and empties `config`** - the key stays
and its contents go.

```
default                    alias displayName internalId providerId enabled
                           trustEmail config(4 entries) types
briefRepresentation=true   alias displayName internalId providerId enabled config({})
briefRepresentation=false  byte-identical to the default
```

The hand probes all used providers that happened to carry neither a config nor a
flag, so "it drops types" fitted every one of them. **The golden sent the request
nobody had sent**, because its fixture creates a provider carrying both.
`make record` produced a body Gloak could not reproduce and that is how it was
found. Same mechanism as AGENTS.md's `KC_RESTART` cookie note: when a probe and a
golden disagree, the golden saw more.

The single read **ignores** the parameter and always answers the full shape,
which is the organization read's behaviour on the same parameter and was measured
here rather than inherited.

### 1.10 Two orders with no reproducible value, measured on two realms

**The components listing has no row order.** Two realms created minutes apart on
one container returned the same fourteen rows in two entirely different orders,
matching neither insertion, name, id nor provider.

**`allowed-protocol-mapper-types` has no element order** either - eight names,
two realms, two orders.

Both are masked with `Unordered` on `admin/component/list`, and neither mask is
inert: fourteen rows and an eight-element array, both measured moving.

### 1.11 Errors, headers and verbs

```
POST, no alias                {"errorMessage":"path is null"}                          400
POST, no providerId           {"errorMessage":"Invalid identity provider id [null]"}   400
POST, unknown providerId      {"errorMessage":"Invalid identity provider id [x]"}      400
POST, duplicate alias         {"errorMessage":"Identity Provider a already exists"}    409
POST/PUT, unknown field       Invalid json representation for IdentityProviderRepresentation.
                              Unrecognized field "zzz" at line 1 column 53.            400
POST/PUT, empty body          {"error":"unknown_error", ...}                           500
POST/PUT, malformed body      {"error":"invalid_request", "..."Cannot parse the JSON"} 400
PUT, alias changed            {"errorMessage":"Identity Provider alias cannot be changed"} 400
GET/PUT/DELETE, unknown alias {"error":"HTTP 404 Not Found"}                           404
GET components/{id} unknown   {"error":"Could not find component"}                     404
GET .../sub-component-types   {"error":"Could not find parent component"}              404
GET .../sub-component-types   {"error":"must specify a subtype"}                       400
GET .../sub-component-types?type=bogus   the 500 unknown_error                         500
POST /components, bad provider {"error":"Invalid provider type or no such provider"}   400
```

**`POST` and `PUT` on the instances are the sixth and seventh strict decoders**
and `POST /components` is the eighth, all naming their class and reporting a line
and column. The strict decode runs **before** the path's alias is resolved - the
required-action PUT's order and the opposite of the organization PUT's.

**An unknown alias is the generic 404, not a spelling of not-found.** So this
family adds none while the Component family next door adds **two**.

Headers, all following rules AGENTS.md already records:

```
every 200                     ;charset=UTF-8, Cache-Control: no-cache
GET .../export (non-SAML)     204, no body, no Content-Type, Cache-Control: no-cache
GET .../export (SAML)         200 application/xml with a per-request ID_<uuid>
GET .../reload-keys           200, the bare JSON `false`
PUT .../instances/{alias}     204, Cache-Control: no-cache, X-Frame-Options
DELETE .../instances/{alias}  204, Cache-Control: no-cache, no X-Frame-Options
POST .../instances            201, Location, no Content-Type, content-length 0
PUT /components/{id}          204, no Cache-Control at all
DELETE /components/{id}       204, no Cache-Control, no X-Frame-Options
```

**The create's `Location` ends in the alias** - a name tail, not a uuid one.

**The SAML export cannot be `Recorded`**: its body carries `ID="ID_<fresh uuid>"`
minted per request. Only the non-SAML 204 is asserted.

Wrong verbs, recorded and acted on by nothing (F31):

```
/identity-provider/instances          PUT 405   PATCH 405   DELETE 405
/identity-provider/instances/{alias}  POST 404  PATCH 405
/components                           PUT 404   PATCH 405   DELETE 404
```

Two sibling families in one cut, two answers: the instances listing answers the
client-scope attachments' shape and `/components` answers the protocol mappers'.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **`search` is two rules and the family decides which.** With a value
  `xabbcx`, `search=*bbc` matches on the **user, group and identity provider**
  listings and answers `[]` on the **role** listing, where `*` is a literal -
  `xa*`, `*abbcx`, `*abb*` and `x*x` all find nothing and the bare `xabbcx`
  does. The rule the first three follow is Keycloak's LIKE: each `*` becomes
  `%`, **a trailing `%` is appended when the pattern does not already end in
  one**, and `"quotes"` mean equality. That trailing wildcard is the whole
  difference and it makes `*bbc` a **substring** match rather than a suffix one.
  Gloak implemented an anchored glob until 2026-09-01, and the six probes its
  doc comment listed are all explained by **both** readings - `user*` is `user%`
  either way. Only a pattern whose last literal run is neither at the end of the
  value nor followed by a `*` separates them, which is why the wrong rule stood
  for a week with a test under it. The user listing is fixed; **the group
  listing still uses `strings.Contains` and is measured wrong on the same
  probe**.
- **The identity provider `config` and the component `config` use Keycloak's
  two different HashMap constructors, and they are one path segment apart.** An
  identity provider's is `javamap.SizedKeyOrder` - nine measured key sets, all
  nine placed, `KeyOrder` wrong on four including `{clientId, clientSecret}`. A
  component's is `javamap.KeyOrder` - seven measured, six placed,
  `SizedKeyOrder` wrong on two of the six. A shared serialiser is wrong on one
  of the two families and which one depends on the key count. **No body Gloak
  serves can tell them apart on the component side**: every config a default
  install has holds nought, one or two keys and both functions agree on all of
  those, so a mutation swapping the constructor survived the whole component
  test file. The claim lives in `internal/javamap`'s vectors, not in the
  serialiser's tests.
- **`briefRepresentation` on the identity provider listing is a six-key shape,
  not the full shape minus a field.** It drops the six tri-state flags,
  `firstBrokerLoginFlowAlias` and `types`, **and empties `config` while keeping
  the key**. Its default here is `false`, which is the third default this one
  parameter has in this API, and the single read ignores it entirely. The first
  reading of it was "it drops types", from probes on providers that happened to
  carry neither a config nor a flag; **the golden refuted it**, because its
  fixture creates one that carries both. Sending the request nobody thought to
  send is what recording does.
- **An identity provider has six tri-state booleans and one field beside them
  that is not.** `trustEmail`, `storeToken`, `addReadTokenRoleOnCreate`,
  `authenticateByDefault`, `linkOnly` and `hideOnLogin` are **absent** when
  never set and `false` when sent `false`; `displayName` on the same body is
  stored and served as `""`. A plain `bool` collapses two states the wire
  distinguishes, six times over, and `omitempty` on the seventh loses a value
  the server keeps.
- **A `PUT` whose body carries no `alias` answers 204 and strands the row.** The
  alias is cleared, the listing serves the row with no `alias` key, it sorts
  first, and nothing can address it again. The rename guard is
  `Identity Provider alias cannot be changed` and a null alias is not a change,
  so the check passes and the write lands. Keycloak's own defect, reproduced.
  Refusing an absent alias is the tidy-up that turns a measured 204 into a 400.
  A **present** alias that differs is the 400, so the two halves of that
  sentence need one request each.
- **`GET .../identity-provider/instances/{alias}/reload-keys` is a read that
  refuses the view role.** It needs `manage-identity-providers` where its six
  sibling reads take `view-identity-providers` too, and its body is the bare
  JSON `false`. That is the second such read in the API after
  `GET .../authz/resource-server/settings`, and unlike that one it sits among
  siblings that do **not** share it rather than beside a single neighbour.
- **The `Component` tag is authorised out of the realm role pair.** `view-realm`
  and `manage-realm` read it; `manage-identity-providers` is 403, although the
  rows are key providers and client-registration policies and although user
  federation lives in the same table. The identity provider family one path
  segment away takes the other pair and refuses `manage-realm`. Two neighbouring
  chapters, two disjoint role pairs - the third time the description's tag has
  failed to predict a guard.
- **A created realm has fourteen components and master has fifteen.** The
  fifteenth is `declarative-user-profile`, and it is also the **only component
  with no `name` key at all**. One bootstrap list for every realm is wrong on
  master, and a `name` column that cannot be null is wrong on that one row.
- **Neither the components listing's row order nor the
  `allowed-protocol-mapper-types` array inside it is reproducible.** Two realms
  created minutes apart on one container returned the same fourteen rows in two
  entirely different orders, matching neither insertion, name, id nor provider,
  and the eight mapper-type names in two orders as well. Both are masked;
  neither mask is inert.
- **A malformed integer bound is a 404 on the identity provider listing and is
  ignored outright on `/components`.** `?first=abc` answers
  `{"error":"HTTP 404 Not Found"}` on the first and 200 with the whole listing on
  the second, and `?first=1&max=2` returns all fourteen rows there - so
  `/components` does not read the bounds at all. Two neighbouring families, one
  input, two answers, measured on one container in one cut. The 404 producer
  count in AGENTS.md's fallback bullet is unchanged; what is new is that the
  behaviour is per family rather than per API.
- **The identity provider create's `Location` ends in the alias.** A name tail,
  joining `POST /roles`, `POST /clients/{uuid}/roles` and `POST /admin/realms`.
  AGENTS.md's Location bullet says two of the thirteen creates "could not be
  reached on a default container and are not counted"; this is one of them, so
  the tally is **eleven of fourteen** rather than ten of thirteen. Counted from
  the list.
- **An unknown identity provider alias is the generic `HTTP 404 Not Found`** on
  the read, the update and the delete alike, so the family adds nothing to the
  spellings of not-found. The **Component** family beside it adds two:
  `Could not find component` from `/components/{id}` - which the realm's own id
  answers too, because components are parented on the realm and the realm is not
  one - and `Could not find parent component` from
  `/components/{id}/sub-component-types`. Both are in the bare-`error` family.
- **`POST` and `PUT .../identity-provider/instances` and `POST /components` are
  strict decoders that report a line and column**, which makes eight such
  endpoints. AGENTS.md says client registration "is also the only one that
  reports a position"; that was already false when it was written - `decodeStrict`
  has produced a position since the required-action PUTs - and it is now false
  four ways over. The decode on the identity provider `PUT` runs **before** the
  path's alias is resolved, which is the required-action order and the opposite
  of the organization PUT's.
- **Two of the seventeen registered identity providers refuse a bare create for
  required config, not for being unknown.** `jwt-authorization-grant` answers
  `Issuer is required` and `oauth2` answers `User Info URL not provided`, both
  400 - the same status an unregistered id gets and a different sentence.
  `GET /admin/serverinfo` lists all seventeen, which is what tells the two cases
  apart; reading the pair of 400s as "not registered" was this cut's own first
  reading and it was wrong.
- **`types` is derived from the provider id and stored nowhere**, and it has
  four values over seventeen providers: five entries for `oidc` and
  `keycloak-oidc`, `["USER_AUTHENTICATION"]` for `saml`,
  `["CLIENT_ASSERTION"]` for `kubernetes`, and `[]` for the eleven social
  providers, `oauth2` and `jwt-authorization-grant`. A boolean "is it OIDC" gets
  two of the four wrong.
- **`GET .../instances/{alias}/export` is a bodyless 204 for everything but a
  SAML provider**, and the SAML body carries a freshly minted
  `ID="ID_<uuid>"` on every request - so that half **cannot be `Recorded`**,
  whatever else is true of it.

## 3. Follow-up dispositions

**F95 (a client's `attributes` is serialised from a Go map): left open, and this
cut is evidence for the fix.** Two more families now serialise a Java map from an
ordered slice with a marshaller of their own - `identityProviderConfig` and
`componentConfig` - which makes four counting an organization's attributes and a
protocol mapper's config. The pattern F95 asks for is now the majority; the
client is the holdout. Not closed here because it lives in `clients.go` and
moving it re-records five goldens in another chapter.

**F134 (four listings treat an unparseable bound as no bound): not closed, and
now partly answered.** F134 says "whether Keycloak agrees on those four is
unmeasured". It has been measured on two more families, and **they disagree with
each other**: the identity provider listing answers `?first=abc` with the
measured 404 and `/components` answers 200 with the whole listing, having ignored
both bounds. So there is no single Keycloak answer to import into the four
listings, and the follow-up's premise - that Gloak's inconsistency is the finding
- is right for a second reason: the server is inconsistent too. The new listing
implements the 404 because that is what its own family answers.

**New: the group listing's `search` treats `*` as a literal and Keycloak does
not.** `internal/admin/groups.go` uses `strings.Contains`; `search=*bbc` against
a group named `xabbcx` matches on the server. Measured, not fixed - a
search-semantics change in a third chapter is not this branch's to make, which is
the argument `authzIntBound`'s doc comment already uses for the same shape of
decision. The discriminating probe is written down so the fix is one edit.

**New: `PUT /components/{id}` with a partial body is a 500 that has already
written the name.** The row was renamed and its config kept, and the request then
failed. Not built here.

**New: the components table exists and `GET /admin/realms/{realm}/keys` does not
read it.** AGENTS.md records that Gloak "has no component table and derives
[`providerId`] from the `kid` by a fixed hash". It has one now. Wiring the two
together is not a rename: master's four key-provider components against Gloak's
**three** realm keys is the same arithmetic AGENTS.md already flags as "serving
three keys is a divergence" - there is a `rsa-enc-generated` component with no
key behind it. Left alone, and the mismatch is now visible in one place instead
of implied.

**New: `DELETE /components/{id}` is deliberately not built.** It is a row delete
and it would be wrong: deleting `rsa-generated` in Keycloak removes the realm
key, and Gloak's `GET /keys` is not backed by this table, so the delete would
leave a realm in a state Keycloak cannot reach. That is the argument migration
0019 already makes for `authz_resource_server` having no `enabled` column.

## 4. What was fixed on the branch

- **`internal/admin/users.go`'s `matchesSearch`.** It implemented an anchored
  glob; Keycloak appends an implied trailing wildcard, which makes `*bbc` a
  substring match. Fixed, with the discriminating probe as a test row and the
  doc comment rewritten to say which reading the six original probes could not
  decide. No golden moved.
- **`briefRepresentation` on the identity provider listing**, corrected from "it
  drops types" to the measured six-key shape after `make record` produced a body
  Gloak could not reproduce.

## 5. Parity, before and after

```
chapter                    before    after
admin/identity-providers    2/17      9/17
admin/component             0/6       2/6
total                     336/535   345/535
```

The nine are the identity provider listing, create, read, update, delete, export
and reload-keys, and the component listing and single read. The two already
served are the `management/permissions` pair P10 measured as a 501.

Not built, each with a stated reason in the plan: `import-config` (an outbound
HTTP fetch), `providers/{provider_id}` and `mapper-types` (per-provider property
catalogues, the second chunked at 11 kB), the five mapper operations (a mapper
table plus that catalogue), `POST`/`PUT /components` and `sub-component-types`
(the config is filtered to the provider's declared properties, which needs the
same catalogue), and `DELETE /components/{id}` (§3).
