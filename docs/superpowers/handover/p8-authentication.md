# P8's first cut: the SPI registry and the required actions

Branch `feat/p8-authentication`. Reference container: `kc-auth`,
`quay.io/keycloak/keycloak:26.7.1 start-dev`, host port 8111, removed at the end.
Everything below was read off that container on 2026-08-30.

Parity **263 -> 281 of 516 (+18)**. `admin/authentication-management` 0 -> 18 of 39.

**The port was checked before the probes were trusted.** A token minted at 8111
was 401 at 8112, where another stream's `kc-browser` runs, and `docker port`
agreed. IPv6 answered nothing on 8111 at all.

---

## 1. Measurements

### 1.1 The scope count was right, and the shape of it was not

The tag's 39 operations were checked family by family against
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and the brief's
breakdown **holds exactly**: flows 10, required-actions 10, executions 7,
config 4, singletons 8. This is the first scope estimate in this project a
check has confirmed rather than moved.

Checking the description against the *server* moved four things:

1. **`per-client-config-description` is not a provider list.** It is a JSON
   object keyed by client-authenticator id. The brief counted it among "five
   static provider lists"; four are lists and this is a map.
2. **`config-description/{providerId}` resolves 52 of the 53 ids the four
   registries publish.** The four registries are disjoint - 53 ids, none in two
   of them - and the fifty-third, `registration-page-form`, is a **404**. So the
   one form provider is the only registry entry with no config description.
3. **`unregistered-required-actions` is `[]` on a default install and is not a
   constant.** Unlike `client-types`' 501 or `client-secret/rotated`'s 404, a
   delete populates it. It is a real read over real state.
4. **A realm created through `POST /admin/realms` has two authentication
   executions master has not got** - an `Organization` sub-flow in `browser` at
   priority 26 and a `First Broker Login - Conditional Organization` sub-flow in
   `first broker login` at 60. The client-scope precedent ("a realm's fifteen
   client scopes are identical in every realm") does **not** extend to the
   flows. It does hold for the required actions and all four registries, which
   are byte-identical between master and a created realm.

### 1.2 The required action representation

```
{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP",
 "enabled":true,"defaultAction":false,"priority":54,"config":{}}
```

**The two conditional keys are conditional in opposite ways.** `alias` is plain
omitempty: a row whose alias is the empty string reads back with **no `alias`
key at all**. `name` is not: a row that never had one reads back without the
key, and a row whose name is `""` reads back carrying `"name":""`. Two adjacent
string keys, opposite emptiness rules. One shared rule gets one of them wrong,
which is why `Name` is a `*string` and `Alias` is not.

`config` is always present and `{}` when empty.

Fourteen rows on a default realm, sorted by priority:
`TERMS_AND_CONDITIONS 20, UPDATE_PROFILE 40, VERIFY_EMAIL 50, CONFIGURE_TOTP 54,
UPDATE_PASSWORD 57, delete_account 60, UPDATE_EMAIL 70, webauthn-register 80,
webauthn-register-passwordless 90, VERIFY_PROFILE 100, delete_credential 110,
idp_link 120, CONFIGURE_RECOVERY_AUTHN_CODES 130, update_user_locale 1000`.
Three are `enabled:false` (`TERMS_AND_CONDITIONS`, `delete_account`,
`UPDATE_EMAIL`) and none is `defaultAction:true`.

### 1.3 Five refusals for one alias, three of them new spellings of not-found

```
GET    /required-actions/{alias}                 404  Failed to find required action
PUT    /required-actions/{alias}                 404  Failed to find required action
DELETE /required-actions/{alias}                 404  Failed to find required action.
POST   /required-actions/{alias}/raise-priority  404  Failed to find required action.
POST   /required-actions/{alias}/lower-priority  404  Failed to find required action.
```

One resource, one key, **two sentences differing only in a full stop**, split by
verb. That is the `Realm not found.` pattern a second time.

Two more on the sub-resources, and a fifth at the top of the tag:

```
GET/PUT/DELETE .../{alias}/config, alias is not a configurable provider id
                                                 400  RequiredAction is not configurable
GET/PUT/DELETE .../{alias}/config, it is, and no row carries it
                                                 404  Could not find RequiredAction config
GET .../{alias}/config-description, not configurable
                                                 404  Could not find configurable RequiredAction provider
GET /config-description/{providerId}, unknown    404  Could not find authenticator provider
```

**AGENTS.md's not-found list moves from fourteen to nineteen**, and the tally
line has to be re-counted rather than incremented, exactly as that bullet
instructs. The five new ones are `Failed to find required action`, `Failed to
find required action.`, `Could not find RequiredAction config`, `Could not find
configurable RequiredAction provider` and `Could not find authenticator
provider`. The first two are one resource by one key spelled two ways - the
third such pair, after `Realm not found.` and the group family's.

### 1.4 The `/config` sub-resource resolves the alias as a **provider id**

This is the finding the obvious implementation gets backwards, and it took a
rename to see. Rename CONFIGURE_TOTP's row to `ZZZ` and:

```
ZZZ/config                          400 RequiredAction is not configurable
ZZZ/config-description              404 Could not find configurable RequiredAction provider
CONFIGURE_TOTP/config               404 Could not find RequiredAction config
CONFIGURE_TOTP/config-description   200 with the properties, and no row exists
```

So the path segment is matched against the SPI's configurable required actions
first and against the rows second, and `config-description` never needs a row at
all. "Resolve the row, then ask whether it is configurable" answers all four of
those wrongly.

**13 of the 14 are configurable.** Only `delete_account` is not.

### 1.5 `PUT /required-actions/{alias}` renames, discards `providerId`, and can orphan a row

- **The body's `alias` wins.** A PUT addressed to `UPDATE_PROFILE` carrying
  `{"alias":"ZZZ",...}` answered 204, made the old alias a 404 and the new one a
  200. This is the rename.
- **`providerId` is read off the wire and discarded.** The same body said
  `"providerId":"XXX"` and the stored row kept `UPDATE_PROFILE`. `name`,
  `enabled`, `defaultAction`, `priority` and `config` are all written.
- **`PUT {}` is a 204 that orphans the row.** Every field takes its zero value,
  so the alias becomes `""`, the row leaves every alias-addressed route and stays
  in the listing as a six-key object with no `alias` key, `enabled:false`,
  `priority:0` - which sorts it first. Keycloak's own defect; it falls out of the
  two rules above rather than needing to be coded for.

### 1.6 Two writers of one field, one filters and one does not

`PUT .../{alias}/config` **filters the config to the provider's declared
property names**: `{"max_auth_age":"700","zzz":"nope"}` stored `max_auth_age`
alone. `PUT` on the representation writes the same field and does **not** filter -
the identical `zzz` survived. `PUT .../config` with `{}` clears the config;
`DELETE .../config` leaves `{"config":{}}` rather than removing the key.

### 1.7 The first strict decoder measured in this API

Both PUTs reject an unrecognised top-level field with a 400 naming the Java
class, the field, the line and the column:

```
{"error":"Invalid json representation for RequiredActionProviderRepresentation. Unrecognized field \"bogusField\" at line 1 column 123."}
{"error":"Invalid json representation for RequiredActionConfigRepresentation. Unrecognized field \"alias\" at line 1 column 11."}
```

Every other endpoint this project has measured ignores fields it does not know.
The decode runs **before** the alias is resolved.

**The third write on the same tag is not strict.** `POST
/register-required-action` answered 204 to `{"providerId":"CONFIGURE_TOTP","zz":1}`.
Three write endpoints on one tag, two strict decoders and one lax one.

**Jackson's column is one past the last character it consumed**, and how much
that is depends on the value's token. Derived from twelve paired bodies:

```
{"zz":1}         8    a number consumes all of its own digits
{"zz":12}        9
{"zz":null}     11    so do null, true and false
{"zz":"a"}       8    a string consumes only its opening quote
{"zz":[1,2]}     8    so does an array
{"zz":{"a":1}}   8    and an object
{ "zz" : 1 }    11    whitespace counts
```

A first implementation used the consumed index rather than the position after
it and was wrong by one on **all** of them at once.

### 1.8 raise-priority swaps values; register appends at max+1

`raise-priority` exchanges the row's `priority` with its neighbour's rather than
decrementing: `UPDATE_PASSWORD` 57 and `CONFIGURE_TOTP` 54 became 54 and 57,
measured on a non-adjacent pair so a decrement cannot pass by coincidence.
Raising the first row and lowering the last are both 204 and a no-op.

`DELETE` moves the row into `unregistered-required-actions`, whose entries carry
**two** keys. `POST /register-required-action` puts it back at
**`max(priority)+1`** with `enabled:true`, `defaultAction:false` and an empty
config, and honours the body's `name` verbatim.

```
already registered   409 {"error":"conflict","error_description":"A Required Action Provider with given alias already exists."}
unknown providerId   400 {"error":"Required Action Provider with given providerId not found"}
{}                   400 the same
empty body           500 unknown_error
```

Registration is tracked by **providerId**, not alias: a row renamed to `ZZZ`
keeps `CONFIGURE_TOTP` registered, and deleting that row unregisters
`CONFIGURE_TOTP`. And `unregistered-required-actions` emits the **provider's**
display name, not the deleted row's - a row renamed to "MY OWN NAME" came back
as "Linking Identity Provider".

### 1.9 The order of `unregistered-required-actions` is HashMap bucket order

Unregistering all fourteen gives:

```
CONFIGURE_TOTP, webauthn-register-passwordless, UPDATE_PASSWORD,
update_user_locale, TERMS_AND_CONDITIONS, idp_link, delete_account,
VERIFY_EMAIL, UPDATE_EMAIL, webauthn-register, VERIFY_PROFILE,
delete_credential, CONFIGURE_RECOVERY_AUTHN_CODES, UPDATE_PROFILE
```

Neither alphabetical, nor by priority, nor by deletion order.
**`javamap.KeyOrder` puts twelve of the fourteen in the measured position and
swaps exactly the two colliding pairs** - `{TERMS_AND_CONDITIONS,
update_user_locale}` and `{VERIFY_EMAIL, delete_account}`. That is the
documented limit of the function rather than a failure of it, and it is the
second measured key set to demonstrate it. The order is therefore stored.

### 1.10 Three new confirmed vectors for `javamap.KeyOrder`

The four provider registries are `Map<String,Object>`s Keycloak builds by hand,
and `javamap.KeyOrder` places all of them:

```
{id, displayName, description}                  -> displayName, description, id
{id, displayName, description, supportsSecret}  -> supportsSecret, displayName, description, id
{client-jwt, client-secret, federated-jwt, client-x509, client-secret-jwt}  -> unchanged
```

The third is `per-client-config-description`'s key order, which `SizedKeyOrder`
gets wrong. So the function goes from **six confirmed key sets to nine**, plus
the near-miss in §1.9. Nothing calls it at runtime here - the orders are
declared struct fields, per AGENTS.md's "Response bodies" - but they are
explained rather than merely copied.

### 1.11 Authorization: three role sets inside one tag

Measured across all 21 roles of the target realm's own container plus a caller
holding none, one fresh token per call:

| Operations | Opened by |
|---|---|
| the four registries, `per-client-config-description`, `config-description/{id}`, `unregistered-required-actions`, every `/required-actions/{alias}...` read | `view-realm`, `manage-realm` |
| every write on the tag | `manage-realm` alone |
| **`GET /required-actions`** | + **`view-users`**, **`query-users`** |
| **`GET /flows`** (not built) | + **`view-clients`**, **`query-clients`** |

The two wide reads are **not** the "200 with a shorter list to a weaker caller"
pattern: a `query-users` caller's `GET /required-actions` is **byte-identical**
to a `manage-realm` caller's, and so is a `query-clients` caller's `GET /flows`.
A single tag-wide role set gets both wrong.

Resolution order is realm, then caller, then alias: an unknown realm is 404 to a
caller holding nothing, and a `view-realm` caller PUTting an unknown alias gets
**403**, not 404. That is the `default-*-client-scopes` order.

### 1.12 Headers

Every 200 on the tag: `Cache-Control: no-cache`,
`Content-Type: application/json;charset=UTF-8`, five security headers. Every
error: no `Cache-Control`, plain `application/json`.

The 204s split, and both existing rules hold:

| Operation | X-Frame-Options | Cache-Control |
|---|---|---|
| `PUT /required-actions/{alias}` | yes | **absent** |
| `DELETE /required-actions/{alias}` | no | **absent** |
| `POST .../{raise,lower}-priority` | yes | `no-cache` |
| `POST /register-required-action` | yes | `no-cache` |
| `PUT .../config` | yes | `no-cache` |
| `DELETE .../config` | no | `no-cache` |

`X-Frame-Options` follows the request's `Content-Type` exactly as AGENTS.md
records; `Cache-Control` is pinned per endpoint and the two
`/required-actions/{alias}` verbs are the pair that omit it - **a sixth data
point for "every generalisation over the method has failed"**, since one PUT and
one DELETE omit it while a different PUT and a different DELETE on the same tag
carry it.

Wrong verbs on `/required-actions`: `POST`, `PUT`, `DELETE` are **404**
`{"error":"HTTP 404 Not Found"}` and **`PATCH` is 405**. That is the protocol
mappers' split exactly - a seventh reading for F31, and nothing was changed on
the strength of it.

`PUT` with `text/plain` is 415 `{"error":"The content-type header value did not
match the value in @Consumes"}`; absent and `application/json` are both accepted.
**Identical to the scope mappings' rule**, so `requireJSONBody` is reused rather
than a second copy written. (An earlier probe here reported "no Content-Type is
a 415"; that was `curl -d` defaulting to `application/x-www-form-urlencoded`,
and it was corrected by sending `-H 'Content-Type:'` explicitly. Recorded
because it is the shape of probe error this project keeps meeting.)

### 1.13 A provider's two property lists are different lists

`config-description/federated-jwt` answers `"properties":[]`;
`per-client-config-description["federated-jwt"]` answers **two** properties. One
provider, one container, one second apart. Four of the five client
authenticators have the two lists equal, which is exactly why one list looked
like enough - and **the byte comparison against the live server is what caught
it**, not anything a reader would have noticed. It is
`ClientAuthenticatorFactory`'s `getConfigProperties` against
`getConfigPropertiesPerClient`.

### 1.14 The registry and the config description are one table

For all 52 resolvable ids, `config-description.name` equals the registry entry's
`displayName` and `.helpText` equals its `description`, with **zero**
mismatches. That identity is what makes six operations cost one table. It does
**not** extend to `properties`, per §1.13.

87 config properties across 20 of the 52; the other 32 answer `[]`. Five key
orders, all reproduced by one field list with `helpText`, `defaultValue` and
`options` optional. `defaultValue` holds strings, booleans **and numbers**, and
the number is on a property whose `type` is `"String"`: `max_auth_age` defaults
to `300`, not `"300"`.

All four listings, `per-client-config-description`, all 52 config descriptions
and the required-action listing came back **byte-identical after a
`docker restart`**, so no `Case.Unordered` retreat was needed anywhere in this
cut.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for folding in.

- **A missing required action has two spellings and the verb picks.** `GET` and
  `PUT /authentication/required-actions/{alias}` answer `Failed to find required
  action`; `DELETE` and both priority `POST`s answer `Failed to find required
  action.` with a full stop, for the identical missing alias. That is the third
  time one resource by one key has come back spelled two ways, after `Realm not
  found.` and the group family's three, and it is the first time the **verb** is
  what decides. `writeRequiredActionNotFound` takes the sentence as an argument
  for exactly that reason.
- **The `/config` sub-resource resolves the alias as a *provider id*, not as a
  row, and answers 400 where its parent answers 404.** Rename CONFIGURE_TOTP's
  row to `ZZZ` and `ZZZ/config` is `400 RequiredAction is not configurable`
  while `CONFIGURE_TOTP/config` is `404 Could not find RequiredAction config`
  and `CONFIGURE_TOTP/config-description` is a **200** describing a row that no
  longer exists. So the sub-resources never follow a rename, and "resolve the
  row, then ask whether it is configurable" - the obvious implementation - gets
  all four of those wrong. Thirteen of the fourteen actions are configurable;
  `delete_account` is the one that is not, and it is why the 400 is reachable
  without inventing an alias.
- **`PUT .../required-actions/{alias}` renames the row, discards its
  `providerId`, and turns an empty body into an orphan.** The body's `alias`
  wins over the path's; `providerId` is read off the wire and thrown away, so a
  row's provider cannot change after registration; and `PUT {}` is a **204**
  that zeroes every field, which renames the row to the empty string. It then
  answers nothing under any alias and stays in the listing as a six-key object
  with **no `alias` key at all**, `enabled` false and priority 0 - sorting
  first. Keycloak's own defect, reproduced. It is also why the table is keyed by
  a minted id and not by `(realm, alias)`: keyed by alias that row could not
  exist.
- **`alias` and `name` on one representation have opposite emptiness rules.**
  An empty `alias` is an **absent key**; an empty `name` is `"name":""`, and a
  `name` that was never set is absent. So one is `string,omitempty` and the
  other is a `*string`, and giving them the same treatment puts a key in a body
  Keycloak leaves out or the reverse.
- **Two writers of one required-action `config`, and only one filters.**
  `PUT .../{alias}/config` drops keys the provider does not declare;
  `PUT .../{alias}` writes the same field unfiltered. Measured on the identical
  key in both directions. `DELETE .../config` leaves `{"config":{}}` rather than
  removing the key.
- **The first strict JSON decoder on this API is on the two Authentication
  Management `PUT`s, and its neighbour on the same tag is not strict.** They
  answer an unrecognised top-level field with a 400 naming the Java class, the
  field, the line and the **column** - `Invalid json representation for
  RequiredActionProviderRepresentation. Unrecognized field "zz" at line 1 column
  8.` - where every other endpoint measured here ignores what it does not know.
  `POST /register-required-action` answered 204 to the same unknown field beside
  a good `providerId`. The column is one past the last character Jackson
  consumed, and a number or a literal costs all of itself while a string, an
  array and an object cost only their opening character; the two obvious
  arithmetics are wrong on every one of twelve measured bodies.
- **`raise-priority` exchanges two priority values; it does not decrement.**
  `UPDATE_PASSWORD` 57 and `CONFIGURE_TOTP` 54 became 54 and 57, and every other
  row was untouched. Raising the first and lowering the last are 204 and change
  nothing. `POST /register-required-action` appends at `max(priority)+1`, so a
  re-registered action sorts last however low its provider's default was.
- **`unregistered-required-actions` is `[]` on a default install and is not a
  constant**, unlike `client-types`' 501 and `client-secret/rotated`'s 404. It
  is keyed by **providerId** rather than alias - a renamed row keeps its provider
  registered - it emits the **provider's** display name rather than the deleted
  row's, and its two-key entries come back in `HashMap` bucket order.
  `javamap.KeyOrder` places twelve of the fourteen and swaps exactly the two
  colliding pairs, which is the second key set to show that function's
  documented limit rather than to refute it.
- **A realm created through `POST /admin/realms` has two authentication
  executions master has not got** - an `Organization` sub-flow in `browser` and a
  `First Broker Login - Conditional Organization` one in `first broker login`.
  The client scopes' "identical in every realm" does **not** extend to the
  flows. It does hold for the required actions and for all four provider
  registries, which are byte-identical between the two realms.
- **A client authenticator's two property lists are different lists.**
  `config-description/federated-jwt` answers `"properties":[]` and
  `per-client-config-description["federated-jwt"]` answers two properties, on
  one container seconds apart. The other four client authenticators have them
  equal, so a single list passes four of five and is wrong on the one that
  matters. Found by comparing bytes against a live server, not by reading.
- **`GET .../authentication/required-actions` admits `view-users` and
  `query-users`, and every other read on its tag refuses them.** The body is
  **byte-identical** to a `manage-realm` caller's, so this is a wider admission
  and not the "200 with a shorter list" pattern. `GET .../authentication/flows`
  does the same thing with `view-clients` and `query-clients`. Three role sets
  inside one tag, and a tag-wide set gets two operations wrong.
- **The `Cache-Control` generalisation fails a third time, inside one tag.**
  `PUT` and `DELETE /authentication/required-actions/{alias}` carry **no**
  `Cache-Control` on their 204s while `PUT` and `DELETE .../{alias}/config` and
  the three `POST`s all carry `no-cache`. Same tag, same verbs, both answers.
  "Pinned per endpoint" survives; nothing about the method predicts it.

### The AGENTS.md line the measurements contradict

> **`GET /realms/{realm}` sends `Content-Type: application/json;charset=UTF-8`
> on its 200, and plain `application/json` on its own 404.** Every other
> endpoint measured so far, success or error, sends plain `application/json`.
> The inconsistency is real and it is only on this one endpoint.

**The second and third sentences are false, and the repository's own goldens
have said so since P2.** Measured on `kc-auth` across eight admin endpoints
(`/admin/realms/master`, `clients`, `client-scopes`, `users`, `roles`, `groups`,
`keys`, `default-groups`) and counted across all 438 committed goldens:

- **On the Admin API, every 2xx with a body carries `;charset=UTF-8` and every
  error carries plain `application/json`.** 158 goldens to 151. The single
  admin-side counterexample is `POST /groups/{id}/children`'s 201, which
  AGENTS.md already records separately in the group bullet.
- **On the protocol side every 200 carries plain `application/json`**: token,
  userinfo, certs, discovery, introspection, revocation, device. Those are the
  fourteen "2xx plain" goldens and every one of them is `oidc/*`.

So the split is by **API surface and status class**, not by endpoint, and
`GET /realms/{realm}` is unremarkable - it is simply the one endpoint of that
family that had been measured when the line was written. `Accept` is not the
variable: five spellings including none at all gave the charset on all three
endpoints tried.

**Nothing was changed on the branch**, because nothing is wrong:
`internal/httpx` already has `WriteJSON` and `WriteJSONCharset`, and
`writeAdminJSON`'s own doc comment in `internal/admin/clients.go` states the
correct rule ("That is the same split already measured on GET /realms/{realm},
so it is not a client-endpoint quirk"). The code knew and the contract document
did not. `WriteJSONCharset`'s doc comment still repeats the wrong reason and
should be corrected when the bullet is.

**And the not-found tally moves from fourteen to nineteen** (§1.3), which that
bullet asks to be re-counted from the list rather than incremented.

---

## 3. Follow-up dispositions

Nothing in the existing list was closed by this cut, and one entry was checked
against it.

- **F96 (`POST /users` drops `requiredActions`)** is about a **user's**
  requiredActions, not a realm's registered providers. This cut builds the
  registry the user's list draws its vocabulary from and does not touch
  `POST /users`. F96 stands, unchanged and unblocked - it is now cheaper,
  because the valid alias set exists.
- **F31 (the 404/405 fallback family)** gains a seventh reading and no decision:
  `/authentication/required-actions` answers `POST`, `PUT`, `DELETE` with 404
  and `PATCH` with 405, which is the protocol mappers' split exactly. Gloak
  answers all of them 404 through `WithKeycloakFallbacks` and nothing was
  changed.

### New follow-ups this cut files

- **F103: the flow model is unbuilt, and 21 operations of the tag depend on it.**
  `flows` 10, `executions` 7, `config` 4. **Every one of those 21 would move
  state nothing consumes**, because Gloak's browser flow is hard-coded in
  `internal/oidc` and no stored flow can change what it walks. That is the whole
  list, named as §6 of the roadmap asks: `GET/POST /flows`,
  `POST /flows/{alias}/copy`, `GET/PUT /flows/{alias}/executions`,
  `POST /flows/{alias}/executions/execution`,
  `POST /flows/{alias}/executions/flow`, `GET/PUT/DELETE /flows/{id}`,
  `POST /executions`, `GET/DELETE /executions/{id}`,
  `POST /executions/{id}/config`, `GET /executions/{id}/config/{id}`,
  `POST /executions/{id}/{raise,lower}-priority`, `POST /config`,
  `GET/PUT/DELETE /config/{id}`. A second cut that serves them without an engine
  must say so in its own PR body; the honest alternative is to build the engine
  first and let `/auth` walk a stored flow.
- **F104: two fields of the twelve operations this cut *did* build are not
  consumed either.** `enabled` and `defaultAction` on a required action decide
  what a login imposes, and Gloak's login imposes nothing - it does not read
  `model.User.RequiredActions` at all, which P2 has stored since the credentials
  work. So `reset-password` with `temporary:true` writes `UPDATE_PASSWORD` onto
  a user and the next login ignores it. This is smaller and more concrete than
  F103 and is the first thing a required-action engine would close.
- **F105: `javamap.KeyOrder`'s near-miss on the fourteen required action
  providers is not a test vector.** It places twelve of fourteen and swaps the
  two colliding pairs, which is the clearest demonstration yet that the model is
  right about buckets and blind inside a chain - and
  `internal/javamap/javamap_test.go` does not hold it.
  `TestKeyOrderCannotResolveBucketCollisions` uses the 21 admin role names; this
  set collides **twice** and would pin the count of collisions rather than their
  existence. Not added here because `internal/javamap` is outside this cut's
  files.
- **F106: `Case.AssertHeaders` cannot say "this header is absent on a 204 and
  present on its sibling" without two cases.** Six of this cut's cases exist
  only to hold one header assertion each. Not a defect, but the reason the
  header table in §1.12 lives in a handover rather than in goldens.

---

## 4. Parity before and after, per chapter

```
chapter                         before  after  delta
admin/authentication-management       0     18    +18
total                               263    281    +18   of 516
```

Nothing else moved. `cmd/parity` against the merge base agrees, exit 0.

The 18 operations, all `Implemented` with a recorded golden:

```
GET  /admin/realms/{realm}/authentication/authenticator-providers
GET  /admin/realms/{realm}/authentication/client-authenticator-providers
GET  /admin/realms/{realm}/authentication/form-action-providers
GET  /admin/realms/{realm}/authentication/form-providers
GET  /admin/realms/{realm}/authentication/per-client-config-description
GET  /admin/realms/{realm}/authentication/config-description/{providerId}
GET  /admin/realms/{realm}/authentication/required-actions
GET  /admin/realms/{realm}/authentication/unregistered-required-actions
POST /admin/realms/{realm}/authentication/register-required-action
GET  /admin/realms/{realm}/authentication/required-actions/{alias}
PUT  /admin/realms/{realm}/authentication/required-actions/{alias}
DELETE /admin/realms/{realm}/authentication/required-actions/{alias}
GET  /admin/realms/{realm}/authentication/required-actions/{alias}/config
PUT  /admin/realms/{realm}/authentication/required-actions/{alias}/config
DELETE /admin/realms/{realm}/authentication/required-actions/{alias}/config
GET  /admin/realms/{realm}/authentication/required-actions/{alias}/config-description
POST /admin/realms/{realm}/authentication/required-actions/{alias}/raise-priority
POST /admin/realms/{realm}/authentication/required-actions/{alias}/lower-priority
```

33 new goldens, 13 new unit tests in `internal/admin`, one new block in
`internal/store/storetest`. `make record` rewrote **no existing golden**.

---

## 5. Mutation testing, and the two survivors

Nineteen mutations, one per claim, each confirmed to fail the **named** test and
then reverted. Seventeen were caught first time. Two survived, and both were
findings about the tests.

### Survivor 1: "PUT discards `providerId`" was pinned by neither layer

`m.ProviderID = rep.ProviderID` added to the handler left
`TestUpdateRequiredActionRenamesAndDiscardsProviderID` **green**, because the
store's `Update` deliberately omitted `provider_id` from its `SET`. Adding
`provider_id` to the store's `SET` also left it green, because the handler never
assigned it. **Two guards, one behaviour, and every single-point mutation
invisible** - the test pinned only the conjunction.

**Fixed on the branch.** The store now writes every column, and
`internal/admin` is the one place that decides the field is not moved. The
mutation is caught. The reasoning is recorded at both sites, in
`store.RequiredActionRepo.Update` and in `updateRequiredAction`.

### Survivor 2: the SPI order test did not cover a collision pair

Swapping `TERMS_AND_CONDITIONS` and `update_user_locale` in the seed - which is
**exactly** the difference between the measured order and `javamap.KeyOrder`'s
answer - left `TestUnregisteredCarriesTheProviderNameInSPIOrder` green, because
the first version of that test unregistered three actions and only one member of
that pair was among them.

**Fixed on the branch.** The test now unregisters all fourteen and asserts the
whole measured order, so both collision pairs are observable. Both swaps are
caught.

### What the tests still do not pin

- **That `enabled` and `defaultAction` mean anything.** They round-trip and are
  serialised correctly, and nothing consumes them - F104. A mutation making
  every required action `enabled:false` at login time would change no test,
  because there is no login-time behaviour to change.
- **That the 87 config properties are the right 87.** The goldens assert two
  providers' properties in full and the rest only through the four registry
  listings, which do not carry properties. A property silently dropped from a
  provider outside `auth-cookie`, `idp-review-profile` and `CONFIGURE_TOTP`
  would not fail anything. The by-hand sweep in §1 compared all 52 against the
  server, but that sweep is not a test.
- **Nothing about the *shared* container's ordering.** Every write case here
  works in a realm of its own, which is right, and it means the suite says
  nothing about what two of these operations do to each other. The one place
  order-dependence showed up was in the recorder, not in a test: a fixture whose
  step is a `DELETE` is not idempotent, two cases shared one, and the second
  case's fixture asked the server to delete a row the first had already taken
  away. Both cases passed on their own. `make record` is the only thing that
  could have found it.
