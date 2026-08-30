# P8, first cut: the required actions and the provider registry

Date: 2026-08-30
Status: accepted
Reference container: `kc-auth`, `quay.io/keycloak/keycloak:26.7.1 start-dev`, port 8111

## 0. The question this plan opens with

**Describe the flows, or execute them?**

Neither, in this cut - and the reason is that the choice is a false one for
the half of the tag it applies to.

Gloak walks a hard-coded browser flow. Twenty-one of the tag's thirty-nine
operations (`flows` 10, `executions` 7, `config` 4) exist to describe and edit
that flow. Serving them without an engine is the shape §6 of the roadmap calls
a staged debt, and the project has twice found that "we store it and serve it
back" reads as "we implement it" to the next reader. This cut **defers all
twenty-one** and says so in the PR body.

What it builds instead is the other eighteen, which are not the same kind of
thing:

- **Six of them are read-only descriptions of the SPI registry.** They do not
  move state at all. They are a catalogue of what an authenticator, a form
  action or a client authenticator *is*, and they are byte-identical in every
  realm and across container restarts (measured, §1.4). Serving them cannot be
  mistaken for implementing a flow, because they are not addressable state.
- **Twelve of them are the required actions**, which are realm state Gloak
  **already partly consumes**: `model.User.RequiredActions` exists,
  `reset-password` with `temporary:true` writes `UPDATE_PASSWORD` into it, and
  two conformance goldens assert it. The registered-provider table is the
  vocabulary that list is drawn from. It is the least staged family on the tag.

So the answer is: **build the part whose state is not a flow**, and leave the
flow model to a second cut that can arrive with an engine or arrive honest
about not having one.

## 1. The allocation exercise

### 1.1 The count, checked against the description

The brief's breakdown was checked operation by operation against
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and **holds
exactly**. 39 operations carry the tag `Authentication Management`:

| Family | Ops | Paths |
|---|---|---|
| flows | 10 | `/flows`×2, `/flows/{flowAlias}/copy`, `/flows/{flowAlias}/executions`×2, `/flows/{flowAlias}/executions/execution`, `/flows/{flowAlias}/executions/flow`, `/flows/{id}`×3 |
| required-actions | 10 | `/required-actions`, `/required-actions/{alias}`×3, `/required-actions/{alias}/config`×3, `/required-actions/{alias}/config-description`, `/required-actions/{alias}/{raise,lower}-priority` |
| executions | 7 | `/executions`, `/executions/{id}`×2, `/executions/{id}/config`, `/executions/{id}/config/{id}`, `/executions/{id}/{raise,lower}-priority` |
| config | 4 | `/config`, `/config/{id}`×3 |
| singletons | 8 | `authenticator-providers`, `client-authenticator-providers`, `config-description/{providerId}`, `form-action-providers`, `form-providers`, `per-client-config-description`, `register-required-action`, `unregistered-required-actions` |

10 + 10 + 7 + 4 + 8 = 39. **This is the first scope estimate in this project
that a check has confirmed rather than moved.** It is still only a count of
what exists; §1.2 is what the operations turned out to be.

### 1.2 The description checked against the server, and back

Nine corrections came out of measuring the operations the description names.
Four of them change the allocation.

1. **`per-client-config-description` is not a list.** The brief calls the five
   cheap singletons "static provider lists"; this one is a JSON **object**
   keyed by client-authenticator id, five keys, each an array of config
   properties. Four registries are lists; this is a map.
2. **`config-description/{providerId}` resolves 52 of the 53 ids the four
   registries publish, and 404s on the fifty-third.** The one form provider,
   `registration-page-form`, is not resolvable through it. The three other
   registries resolve completely. The four registries are **disjoint** - no id
   appears in two - so the union is exactly 53.
3. **The registry and the config description are one table.** For all 52
   resolvable ids, `config-description.name` equals the registry entry's
   `displayName` and `config-description.helpText` equals its `description`,
   with **zero** mismatches. So six operations rest on one 52-row table plus 87
   config properties, not on six tables. This is the single biggest reason the
   registry half is cheap.
4. **`unregistered-required-actions` is `[]` on a default install and is not a
   constant.** Unlike `client-types`' 501 or `client-secret/rotated`'s 404, it
   becomes non-empty the moment a required action is deleted - measured. It is
   a real read over real state, and `register-required-action` is its inverse.

Five more that do not change the allocation but do change the code:

5. `GET /flows` returns **top-level flows only** - 7 of the realm's flows, not
   all of them. The sub-flows are reachable only through
   `/flows/{alias}/executions`.
6. A realm created through `POST /admin/realms` has **two authentication
   executions master does not have** - an `Organization` sub-flow in `browser`
   and a `First Broker Login - Conditional Organization` sub-flow in
   `first broker login`. The client-scope precedent ("identical in every
   realm") does **not** hold for flows. It does hold for the required actions
   and all four registries, which are byte-identical between master and a
   created realm.
7. Three role sets guard one tag (§1.3).
8. `raise-priority` **swaps priority values with the neighbour**; it does not
   decrement (§2.4).
9. Both `PUT`s on this family use a **strict** JSON decoder that rejects an
   unknown field by name, line and column - the first strict decoder measured
   in this API (§2.6).

### 1.3 Three role sets on one tag

Measured across all 21 roles of the target realm's own container, plus a caller
holding none, on `gloak-probe-ra`:

| Operation | Opened by |
|---|---|
| the four registries, `per-client-config-description`, `config-description/{id}`, `unregistered-required-actions`, every `/required-actions/{alias}...` read | `view-realm`, `manage-realm` |
| every write on the family | `manage-realm` alone |
| **`GET /required-actions`** | `view-realm`, `manage-realm`, **`view-users`**, **`query-users`** |
| **`GET /flows`** | `view-realm`, `manage-realm`, **`view-clients`**, **`query-clients`** |

The two wide ones are **not** the "200 with a shorter list to a weaker caller"
pattern this API has three instances of: a `query-users` caller's
`GET /required-actions` is **byte-identical** to `manage-realm`'s, and so is a
`query-clients` caller's `GET /flows`. It is a genuinely wider admission on two
operations out of thirty-nine, and a single tag-wide role set gets both wrong.

Ordering: the **realm** is resolved first (an unknown realm is 404 to a caller
holding nothing), then the **caller**, then the **alias** - a `view-realm`
caller `PUT`ting an unknown alias gets 403, not 404. That is the
`default-*-client-scopes` order, not `/client-scopes/{id}`'s.

### 1.4 What the cut is, and why

**Eighteen operations.** The registry six and the required-action twelve.

Ordered by what each buys per unit of risk:

| Ops | Family | Why in |
|---|---|---|
| 10 | `required-actions` | realm state Gloak already half-consumes; the only family on the tag with an existing consumer. Migration `0017`, one store repository, one bootstrap seed |
| 2 | `register-required-action`, `unregistered-required-actions` | the same state read the other way round; free once the table exists, and leaving them out would ship a family that cannot be restored after a delete |
| 4 | `authenticator-providers`, `client-authenticator-providers`, `form-action-providers`, `form-providers` | 53 static rows, no state, byte-stable across a restart |
| 1 | `per-client-config-description` | 5 keys off the same table |
| 1 | `config-description/{providerId}` | the 52-row table again plus 87 properties; §1.2's identity is what makes it marginal rather than a sixth table |

**Deferred: 21.** `flows` 10, `executions` 7, `config` 4 - the flow model.

The registry six are read-only and describe an SPI, so they cannot become
"state nothing consumes". The required-action twelve **do** move state, and
part of that state is consumed today and part is not: `enabled` and
`defaultAction` decide what a login imposes, and Gloak's login imposes nothing.
That is named in §5 as this cut's own staged debt rather than left for a reader
to find.

## 2. The measured contract

Everything here was read off `kc-auth` on 2026-08-30. Nothing is from memory.

### 2.1 The required action representation

```
{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP",
 "enabled":true,"defaultAction":false,"priority":54,"config":{}}
```

Seven keys in that order. `config` is always present and `{}` when empty.
**`name` is absent rather than empty when it was never set** - a row registered
with no `name` reads back with six keys - and an explicitly empty `name` reads
back as `""`. So it is `*string`, not `string,omitempty`: Go's `omitempty`
would drop the second case too.

The listing is `GET /required-actions`, sorted by `priority` ascending, 14 rows
on a default realm:

```
TERMS_AND_CONDITIONS 20  UPDATE_PROFILE 40  VERIFY_EMAIL 50  CONFIGURE_TOTP 54
UPDATE_PASSWORD 57  delete_account 60  UPDATE_EMAIL 70  webauthn-register 80
webauthn-register-passwordless 90  VERIFY_PROFILE 100  delete_credential 110
idp_link 120  CONFIGURE_RECOVERY_AUTHN_CODES 130  update_user_locale 1000
```

`TERMS_AND_CONDITIONS`, `delete_account` and `UPDATE_EMAIL` are the three with
`enabled:false`. No row has `defaultAction:true`.

### 2.2 Two spellings of one missing required action, split by verb

```
GET    /required-actions/{alias}                 404 {"error":"Failed to find required action"}
PUT    /required-actions/{alias}                 404 {"error":"Failed to find required action"}
DELETE /required-actions/{alias}                 404 {"error":"Failed to find required action."}
POST   /required-actions/{alias}/raise-priority  404 {"error":"Failed to find required action."}
POST   /required-actions/{alias}/lower-priority  404 {"error":"Failed to find required action."}
```

One resource, one key, **two spellings differing only in a full stop**, and the
split is by verb rather than by family. This is the `Realm not found.` pattern
a second time.

Two further spellings on the same family, for the same unknown alias:

```
GET/PUT/DELETE /required-actions/{alias}/config      400 {"error":"RequiredAction is not configurable"}
GET /required-actions/{alias}/config-description     404 {"error":"Could not find configurable RequiredAction provider"}
```

The `config` sub-resource **never resolves the alias**: it asks whether the
action is configurable, and an unknown alias is not, so it is a **400** where
its parent is a 404. And `config-description/{providerId}` at the top level is
a fifth: `404 {"error":"Could not find authenticator provider"}`.

### 2.3 Which required actions are configurable

13 of 14. Only **`delete_account`** is not: its `config-description` is 404 and
its `config` is the 400 above. The other thirteen answer `{"config":{}}`.

### 2.4 raise-priority and lower-priority swap values

`raise-priority` exchanges the row's `priority` with the neighbour above it,
rather than decrementing. Measured on a non-adjacent pair: `UPDATE_PASSWORD` 57
and `CONFIGURE_TOTP` 54 became `UPDATE_PASSWORD` 54 and `CONFIGURE_TOTP` 57.
Raising the first row and lowering the last are both **204 and a no-op**.

### 2.5 register, unregister, re-register

`DELETE /required-actions/{alias}` is 204 and moves the row out of the listing
and into `unregistered-required-actions`, whose entries carry **two** keys:
`{"providerId":"VERIFY_EMAIL","name":"Verify Email"}`.

`POST /register-required-action` puts it back at **`max(priority)+1`** with
`enabled:true`, `defaultAction:false` and an empty config. The body's `name` is
**honoured** - registering with `{"providerId":"UPDATE_EMAIL","name":"totally
different"}` produced a row named exactly that - and a body with no `name`
produces the six-key representation of §2.1.

```
already registered      409 {"error":"conflict","error_description":"A Required Action Provider with given alias already exists."}
unknown providerId      400 {"error":"Required Action Provider with given providerId not found"}
{}                      400 the same
empty body              500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
```

### 2.6 The two writes to `config` disagree, and both decoders are strict

`PUT /required-actions/{alias}/config` **filters the config to the provider's
declared property names**: `{"max_auth_age":"700","zzz":"nope"}` stored
`max_auth_age` alone. `PUT /required-actions/{alias}` writes the same field and
does **not** filter: the same `zzz` survived. One field, two writers, one
filters.

Both reject an unrecognised top-level field with a 400 naming the Java class,
the field, the line and the column:

```
{"error":"Invalid json representation for RequiredActionConfigRepresentation. Unrecognized field \"alias\" at line 1 column 11."}
{"error":"Invalid json representation for RequiredActionProviderRepresentation. Unrecognized field \"bogusField\" at line 1 column 118."}
```

This is the **first strict decoder measured in this API**. Every other endpoint
this project has measured ignores fields it does not know.

`PUT .../config` with `{}` is 204 and clears the config; with an empty body it
is a 500. `DELETE .../config` sets it to `{}`, not absent.

### 2.7 `PUT /required-actions/{alias}` renames, ignores providerId, and can orphan a row

The **body's `alias` wins**: a `PUT` addressed to `UPDATE_PROFILE` carrying
`{"alias":"ZZZ",...}` answered 204, made `GET .../UPDATE_PROFILE` a 404 and
`GET .../ZZZ` a 200. `providerId` is read off the wire and **discarded** - the
same body said `"providerId":"XXX"` and the stored row kept `UPDATE_PROFILE`.
`name`, `enabled`, `defaultAction`, `priority` and `config` are all written.

Consequently **`PUT /required-actions/{alias}` with `{}` is a 204 that orphans
the row**: it is renamed to the empty string, disappears from every
alias-addressed route, and stays in the listing as a six-key object with **no
`alias` key at all**, `enabled:false`, `priority:0` - which sorts it first.
Keycloak's own defect, reproduced as far as the admin API reaches.

### 2.8 The four registries are Java `HashMap`s and `javamap.KeyOrder` places them

The registry entries are `Map<String,Object>`s Keycloak builds by hand, not
beans, and their key order is bucket order:

```
{id, displayName, description}                  -> displayName, description, id
{id, displayName, description, supportsSecret}  -> supportsSecret, displayName, description, id
```

`javamap.KeyOrder` reproduces both, and also places
`per-client-config-description`'s five keys
(`client-jwt, client-secret, federated-jwt, client-x509, client-secret-jwt`)
exactly, where `SizedKeyOrder` gets that one wrong. **Three new confirmed
vectors**, taking the function from six measured key sets to nine.

The config property entries are beans, not maps, and their five observed key
orders are one field list with three optional members:

```
name, label, helpText, type, defaultValue, options, secret, required, readOnly
```

`helpText`, `defaultValue` and `options` are absent when unset. 87 properties
across 20 of the 52 providers; the other 32 answer `"properties":[]`.

### 2.9 Headers

Every 200 on the family: `Cache-Control: no-cache`,
`Content-Type: application/json;charset=UTF-8`, and the five security headers.

The 204s split, and both splits are already-known rules holding:

| Operation | X-Frame-Options | Cache-Control |
|---|---|---|
| `PUT /required-actions/{alias}` | yes (JSON body) | **absent** |
| `DELETE /required-actions/{alias}` | no (no Content-Type) | **absent** |
| `POST .../{raise,lower}-priority` | yes | `no-cache` |
| `POST /register-required-action` | yes | `no-cache` |
| `PUT .../config` | yes | `no-cache` |
| `DELETE .../config` | no (no Content-Type) | `no-cache` |

`X-Frame-Options` follows the request's `Content-Type` exactly as AGENTS
records. `Cache-Control` is pinned per endpoint and the two
`/required-actions/{alias}` verbs are the pair that omit it.

Wrong verbs on `/required-actions`: `POST`, `PUT`, `DELETE` answer **404**
`{"error":"HTTP 404 Not Found"}` and **`PATCH` answers 405**
`{"error":"HTTP 405 Method Not Allowed"}`. That is the protocol mappers' split
exactly. Nothing is changed on the strength of it - see F31.

### 2.10 The AGENTS line this contradicts

> **`GET /realms/{realm}` sends `Content-Type: application/json;charset=UTF-8`
> on its 200, and plain `application/json` on its own 404.** Every other
> endpoint measured so far, success or error, sends plain `application/json`.
> The inconsistency is real and it is only on this one endpoint.

**The second and third sentences are false**, and the repository's own goldens
have said so since P2. Measured on `kc-auth` across eight admin endpoints, and
counted across all 438 committed goldens:

- **Admin API and `/realms/{realm}`: every 2xx with a body carries
  `;charset=UTF-8`; every error carries plain `application/json`.** 158 goldens
  to 151, with one admin-side counterexample - `POST /groups/{id}/children`'s
  201 - which AGENTS already documents separately in the group bullet.
- **The protocol endpoints carry plain `application/json` on their 200s**:
  token, userinfo, certs, discovery, introspection, revocation, device. Those
  are the 14 "2xx plain" goldens and every one of them is `oidc/*`.

So the split is by **API surface and status class**, not by endpoint, and
`GET /realms/{realm}` is unremarkable. `Accept` is not the variable: five
spellings including none at all gave charset on all three endpoints tried.
Nothing in the code changes - `internal/httpx` already emits both correctly,
which is why 438 goldens pass - but the bullet is the wrong reason for the
right behaviour, and the next person to add an admin endpoint would read it and
send the wrong header.

## 3. What gets built

### 3.1 `internal/model`

```go
type RequiredActionProvider struct {
    ID            string   // server-minted; the row survives an empty alias
    RealmID       string
    Alias         string
    Name          *string  // nil is an absent key, "" is a present empty one
    ProviderID    string
    Enabled       bool
    DefaultAction bool
    Priority      int
    Config        model.StringMap
}
```

Keyed by `ID` rather than by `(realm, alias)` because §2.7's orphan row has no
alias and must still be listed. `Name` is a pointer for §2.1.

### 3.2 `internal/store`, migration `0017_required_action.sql`

One table in both drivers, one repository:

```go
type RequiredActionRepository interface {
    ListByRealm(ctx context.Context, realmID string) ([]*model.RequiredActionProvider, error)
    ByAlias(ctx context.Context, realmID, alias string) (*model.RequiredActionProvider, error)
    Create(ctx context.Context, m *model.RequiredActionProvider) error
    Update(ctx context.Context, m *model.RequiredActionProvider) error
    Delete(ctx context.Context, realmID, id string) error
}
```

`ListByRealm` orders by `priority`, then by `id` so a tie is at least stable.
Both drivers, and the Postgres suite run by hand - CI does not run it.

### 3.3 `internal/bootstrap`

`requiredactions.json`, embedded, seeding the 14 rows of §2.1 into master and
into every realm `CreateRealm` makes - the `ensureClientScopes` pattern, called
from the same two places. The rows are identical in both, measured.

### 3.4 `internal/admin`

- `authproviders.json` + `authproviders.go`: the 53 registry rows and the 87
  config properties, generated from the server and embedded. Serves the six
  registry operations off one table, per §1.2.
- `requiredactions.go`: the twelve stateful operations.
- `router.go`: eighteen routes, with `GET /required-actions` on its own role
  set per §1.3.

### 3.5 `internal/conformance`

Cases appended **at the very end** of `adminCases`, and fixtures at the very
end of the fixture map and after the last helper. New goldens under
`testdata/golden/admin/authentication-management/`.

## 4. Test plan

Unit tests in `internal/admin` for the rules a golden cannot see:

- the two not-found spellings, one per verb (§2.2)
- `raise-priority` swaps rather than decrements, on a non-adjacent pair (§2.4)
- `PUT` ignores `providerId` and honours the body's `alias` (§2.7)
- `PUT .../config` filters unknown keys and `PUT` on the representation does
  not (§2.6)
- `name` absent vs `""` (§2.1)
- `GET /required-actions` admits `query-users` where its siblings do not (§1.3)

Every claim that a test now catches something is mutation-tested: a different
mutation per claim, confirming the **named** test fails, then reverted.

## 5. What this cut defers, and the debt it takes on

**Deferred: the flow model, 21 operations.** `flows` 10, `executions` 7,
`config` 4. A second cut takes them, and the follow-up filed for it must say
**which endpoints move state nothing consumes** - on today's engine that is all
21 of them, because Gloak's browser flow is hard-coded and no stored flow can
change it.

**Taken on: two fields of the twelve built here are not consumed either.**
`enabled` and `defaultAction` on a required action decide what a login imposes,
and Gloak's login imposes no required action at all - it does not read
`model.User.RequiredActions` either, which P2 already stores. The rest of the
family is consumed or is description. This is smaller and more concrete than
the flow debt, and it is written here so the follow-up can name it rather than
rediscover it.
