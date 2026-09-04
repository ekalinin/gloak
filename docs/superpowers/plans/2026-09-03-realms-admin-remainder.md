# The `admin/realms-admin` remainder: localization and the converter

Date: 2026-09-03
Status: accepted
Branch: `feat/realms-admin-remainder`

## 1. The count, taken from the description and checked against the server

`admin/realms-admin` maps onto the description's `Realms Admin` tag, which holds
**45** operations. Twenty-one carry an `Implemented` case today and **24 do
not**. Both halves are computed from the vendored description and the catalogue
rather than incremented: the tag's operations come out of
`internal/conformance/testdata/openapi/keycloak-26.7.1.json`, and the served set
is the distinct `Case.Operation` of every `Implemented` case whose id begins
`admin/realms-admin/`, which is exactly what `servedOperations` counts.

No case outside the chapter names an operation of this tag, so the chapter's
numerator and the tag's are the same set.

### 1.1 The 24, and the family each belongs to

| # | Operation | Family |
|---|---|---|
| 1 | `GET /admin/realms/{realm}/localization` | localization |
| 2 | `GET /admin/realms/{realm}/localization/{locale}` | localization |
| 3 | `GET /admin/realms/{realm}/localization/{locale}/{key}` | localization |
| 4 | `POST /admin/realms/{realm}/localization/{locale}` | localization |
| 5 | `PUT /admin/realms/{realm}/localization/{locale}/{key}` | localization |
| 6 | `DELETE /admin/realms/{realm}/localization/{locale}` | localization |
| 7 | `DELETE /admin/realms/{realm}/localization/{locale}/{key}` | localization |
| 8 | `POST /admin/realms/{realm}/client-description-converter` | converters |
| 9 | `GET /admin/realms/{realm}/events` | events |
| 10 | `DELETE /admin/realms/{realm}/events` | events |
| 11 | `GET /admin/realms/{realm}/admin-events` | events |
| 12 | `DELETE /admin/realms/{realm}/admin-events` | events |
| 13 | `GET /admin/realms/{realm}/events/config` | events |
| 14 | `PUT /admin/realms/{realm}/events/config` | events |
| 15 | `GET /admin/realms/{realm}/client-session-stats` | sessions |
| 16 | `DELETE /admin/realms/{realm}/sessions/{session}` | sessions |
| 17 | `POST /admin/realms/{realm}/logout-all` | sessions |
| 18 | `POST /admin/realms/{realm}/push-revocation` | sessions |
| 19 | `GET /admin/realms/{realm}/credential-registrators` | credentials |
| 20 | `GET /admin/realms/{realm}/users-management-permissions` | management permissions |
| 21 | `PUT /admin/realms/{realm}/users-management-permissions` | management permissions |
| 22 | `POST /admin/realms/{realm}/partial-export` | export/import |
| 23 | `POST /admin/realms/{realm}/partialImport` | export/import |
| 24 | `POST /admin/realms/{realm}/testSMTPConnection` | SMTP |

Eight families, not the four the brief's hint sketched, and **three of the
hint's numbers were wrong**:

- **Localization is seven, not six.** The description enumerates a `GET`, a
  `POST` and a `DELETE` on `{locale}`, and a `GET`, a `PUT` and a `DELETE` on
  `{locale}/{key}`, plus the collection `GET` - which is the family this brief
  warned had twice been undersized, undersized again.
- **Client policies are already served, all four.** `GET`/`PUT` on
  `client-policies/policies` and `client-policies/profiles` have carried
  `Implemented` cases since P4's second cut. There is nothing to take.
- **`client-types` is already served too**, both operations, as the measured 501
  behind the disabled `CLIENT_TYPES` preview feature. The brief asked for this
  to be checked before counting and it is: they are two of the 21, not two of
  the 24.

The hint's `2 .../events + 2 .../admin-events + 2 .../events/config` is right,
and `1 .../client-session-stats` and `1 .../client-description-converter` are
right. The nine operations in rows 16 to 24 appear in no line of the hint at
all.

### 1.2 What this cut takes

**Localization, seven operations, and the converter, one.** Eight. The events
family is P14's own cut and is left alone; client policies need nothing; the
other nine belong to families this branch does not open.

Parity moves `admin/realms-admin` from **21 of 45** to **29 of 45**.

## 2. What was measured

Against a live 26.7.1 on `:8164`, `2026-09-03`. Every write was done in a realm
created for the sweep. The full record is in
`docs/superpowers/handover/realms-admin-remainder.md` §1; what the code has to
reproduce is here.

### 2.1 Localization: the seven answers

```
GET    /localization                200 ["de","en"]          application/json;charset=UTF-8
GET    /localization/{locale}       200 {"k":"v"}            application/json;charset=UTF-8
GET    /localization/{locale}/{key} 200 v                    text/plain;charset=UTF-8
POST   /localization/{locale}       204
PUT    /localization/{locale}/{key} 204
DELETE /localization/{locale}       204
DELETE /localization/{locale}/{key} 204
```

**No response in the family carries `Cache-Control`**, success or failure -
which is not the realm family's habit and is measured on all seven.

Refusals:

```
GET    /localization/{locale}/{key} unknown  404 {"error":"Localization text not found"}
DELETE /localization/{locale}/{key} unknown  404 {"error":"Localization text not found"}
DELETE /localization/{locale}       unknown  404 {"error":"No localization texts for locale en found."}
GET    /localization/{locale}       unknown  200 {}
```

So a locale that does not exist is a **200 `{}`** on the read and a **404** on
the delete, and the two 404 spellings differ by a full stop and by wording.
Neither is the `errorMessage` family: both are the bare `error` key.

### 2.2 The key order, which is two rules and the write path decides

The texts are one JSON document per (realm, locale), and its key order is the
truth the read serves back. Measured with a designed sequence:

```
POST k1..k5 on a new locale   -> k1,k2,k3,k4,k5          the request's own order
POST {k6}   over those five   -> k3,k4,k5,k6,k1,k2       re-bucketed, capacity 8
PUT  k7                       -> k3,k4,k5,k6,k1,k2,k7    appended, nothing moved
DELETE k1                     -> k3,k4,k5,k6,k2,k7       removed, nothing moved
PUT  k8                       -> ...,k7,k8               appended
POST {k9}   over those seven  -> k2,k3,...,k9            re-bucketed, capacity 16
PUT  k2 (a key already there) -> value replaced in place, position kept
```

`POST` is the only write that re-orders, and the capacity it re-buckets at is
`javamap`'s `capacity(n, n)` for the resulting entry count - `capacity(6,6)`
is 8 and `capacity(8,8)` is 16, and both are what the server answered. The
other three writes preserve the document's order exactly.

**So the store holds an ordered list of pairs, not a map**, and `POST` is the
one path that runs the ordering function.

### 2.3 The default-locale fallback

`GET /localization/{locale}?useRealmDefaultLocaleFallback=true` merges the
realm's `defaultLocale` texts **under** the requested locale's: a key both hold
comes back with the requested locale's value, and a key only the default holds
is added. Measured:

```
default aa = {"only.aa":"a","k":"aa"}    requested zz = {"only.zz":"z","k":"zz"}
zz?useRealmDefaultLocaleFallback=true -> {"only.aa":"a","only.zz":"z","k":"zz"}
```

It is driven by `defaultLocale` **alone**: turning `internationalizationEnabled`
on and off left the answer identical. A locale that does not exist answers the
default locale's texts outright. The single-key read ignores the parameter -
`GET zz/only.aa` is the 404 - and so does the collection listing.

### 2.4 Two Keycloak defects the family has, reproduced

- **`POST /localization/{locale}` with an empty body or a literal `null` is a
  204 that creates the locale with no document at all**, after which
  `GET /localization/{locale}`, `GET .../{key}` and `PUT .../{key}` are all
  **500 `unknown_error`** for ever. The locale appears in
  `GET /localization`; `DELETE /localization/{locale}` still removes it, and
  `DELETE .../{key}` on it is the ordinary 404. `{}` is a different body and a
  different outcome: 204, and the locale reads back `{}`.
- **`POST` with a non-string value coerces it**: `{"n":123}` stores `"123"`,
  which is F97's coercion in a second place.

### 2.5 The bodies the writes refuse

```
POST  {                     400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
POST  []                    400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
PUT   Content-Type: application/json
                            415 {"error":"The content-type header value did not match the value in @Consumes"}
PUT   no Content-Type       204, and the value is stored
PUT   empty body            204, and the key reads back 200 with a zero-length body
GET   Accept: application/json on the key read
                            406 {"error":"HTTP 406 Not Acceptable"}
```

The 415 body is byte-identical to the one `admin/scope-mappings/unsupported-media-type`
already holds. The 406 is a **sixth** body in the fallback family, after the
two 404s, the 405, the 401 and the 403.

### 2.6 The guards

Swept one single role at a time over all 21 roles of the realm's own container
plus a caller holding none, with a token minted per caller:

```
the three reads     every role except impersonation      - opensARealm
the four writes     manage-realm alone
the converter       manage-clients alone
```

The reads' admission is `GET /admin/realms/{realm}`'s, which was the only route
in this API measured taking it. It is now four routes.

**`GET /localization/{locale}` leaks across realms and its two siblings do
not.** A master caller holding any `master-realm` admin role reads another
realm's texts in full - not a reduced body - and is 403 on
`GET /localization` and on `GET /localization/{locale}/{key}` for the same
realm. AGENTS.md records exactly one read that reaches sideways; there are two.

The realm is resolved before the caller on all eight routes: an unknown realm is
`404 {"error":"Realm not found."}` to a caller holding nothing.

### 2.7 The converter

`POST /admin/realms/{realm}/client-description-converter`:

- **The `Content-Type` is not read.** The same OIDC body converts under
  `application/json`, `text/plain`, `application/xml` and with no `Content-Type`
  at all, and the SAML body converts under all of them too. The **body's shape**
  decides.
- The OIDC branch is taken when the trimmed body starts with `{`, ends with `}`
  and contains `redirect_uris`. `{"x":"redirect_uris"}` satisfies that and then
  fails to parse, answering **500 `unknown_error` / `Cannot parse the JSON`** -
  which is how the string test is visible at all. Anything else is
  `400 {"error":"Unsupported format"}`, including an empty body and
  `{"client_id":"x"}`.
- The decode is **strict**: an unrecognised field is the same 500. That is a
  fifteenth strict decoder on this API and the **first that answers 500**.
- `token_endpoint_auth_method` with an unregistered value is a 500 too.

The mapping this cut implements, measured one field at a time:

```
client_id                  -> clientId
client_name                -> name
client_uri                 -> baseUrl
logo_uri                   -> attributes["logoUri"]
redirect_uris              -> redirectUris        (null drops the key)
response_types             -> standardFlowEnabled = contains "code"
                              implicitFlowEnabled = contains "token" or "id_token"
                              absent behaves as ["code"]
grant_types                -> six flags and five attributes, and its presence
                              adds serviceAccountsEnabled and
                              authorizationServicesEnabled to the body
token_endpoint_auth_method -> clientAuthenticatorType, publicClient and
                              attributes["client.secret.authentication.allowed.method"]
scope                      -> optionalClientScopes, split on spaces
```

**`attributes` is a Java map whose capacity is not a function of its key set**:
three keys came back at capacity 16, six and eight at capacity 32, eighteen at
capacity 32. `javamap.capacityFor` gives 16 for six and eight, so no function in
that package can be handed the right table, and the order is a fact about
Keycloak's internal construction sequence rather than about the keys. It is
therefore reproducible for the three-key shape and not for the rest.

## 3. What the code does

### 3.1 `internal/model`

```go
type LocalizationText struct { Key, Value string }
type LocalizationTexts struct {
    Locale string
    // Texts is nil for the locale POST's empty body leaves behind, and
    // non-nil-but-empty for the one {} leaves. The two read differently.
    Texts []LocalizationText
}
```

The nil/empty distinction is the whole of §2.4's first defect, so it lives in
the model rather than in a driver.

### 3.2 `internal/store`, migration `0027_realm_localization`

One table, one row per (realm, locale), the texts flattened into a second table
with an ordinal - `component_config`'s shape, for `component_config`'s reason:
the order is the contract and a map column would lose it. A locale with no
document is a parent row with no children **and** a `has_texts` flag, because
"no rows" cannot tell `{}` from `null`.

```go
type LocalizationRepo interface {
    Locales(ctx, realmID string) ([]string, error)
    ByLocale(ctx, realmID, locale string) (*model.LocalizationTexts, error)
    Put(ctx, realmID string, t *model.LocalizationTexts) error
    DeleteLocale(ctx, realmID, locale string) error
}
```

`Put` replaces the whole document, which is what every measured write does after
`internal/admin` has computed the new order. Deciding the order in the repo
would put a measured Keycloak behaviour behind a SQL boundary.

Both drivers implement it, and `internal/store/storetest` gains a case for the
nil/empty split and for the ordinal round-trip.

`bootstrap.DeleteRealm` removes the rows.

### 3.3 `internal/admin/localization.go`

Seven handlers. The ordering rule of §2.2 is one function, `mergeTexts`, and it
calls `javamap.SizedKeyOrder` for the `POST` path - **with `builtFor` 1**, which
disables that function's first table and leaves exactly the second, the one
measured here. The doc comment says so and a test pins the three measured
sequences.

A new writer, `writeAdminPlainText`, is needed for the key read: it is the first
`text/plain` 200 on this API, and it omits `X-Frame-Options`. It lives beside
`writeEmptyStatus` for `writeEmptyStatus`'s reason and is folded into the same
follow-up.

### 3.4 `internal/admin/clientdescription.go`

The converter. The OIDC branch as measured; the SAML branch is not built, and a
`Recorded` case carries the measurement so the gap is in the catalogue rather
than only in prose. `attributes` goes out through `javamap.KeyOrder`, which is
measured right for the three-key shape and wrong for the larger ones; the cases
that assert bytes are the ones it places, and a `Recorded` case carries a shape
it does not.

### 3.5 Routes

```
GET    /admin/realms/{realm}/localization                 guardAny(realmAnyRoles)
GET    /admin/realms/{realm}/localization/{locale}        guardRealmRead
GET    /admin/realms/{realm}/localization/{locale}/{key}  guardAny(realmAnyRoles)
POST   /admin/realms/{realm}/localization/{locale}        guardAny(realmWriteRoles)
PUT    /admin/realms/{realm}/localization/{locale}/{key}  guardAny(realmWriteRoles)
DELETE /admin/realms/{realm}/localization/{locale}        guardAny(realmWriteRoles)
DELETE /admin/realms/{realm}/localization/{locale}/{key}  guardAny(realmWriteRoles)
POST   /admin/realms/{realm}/client-description-converter guard("manage-clients")
```

`guardRealmRead` is `GET /admin/realms/{realm}`'s own combinator and is reused
on the single route measured to share its cross-realm admission. The other two
reads take a new role set - every admin role of the realm's container except
`impersonation` - which is `opensARealm` applied to the caller's grants on the
realm in the path.

**No catch-all is registered.** F153's hazard does not arise: all four patterns
are literal-prefixed and none of them overlaps another, checked by registering
them.

### 3.6 Conformance

Cases appended at the very end of `adminCases`, fixtures at the very end of the
fixture map and after the last helper. The counted list is in the handover.

## 4. Order of work

1. Plan (this file), committed before any code.
2. Model, migration, both drivers, `storetest`.
3. Handlers, routes, guards.
4. Package tests, then the catalogue and `make record`.
5. Mutation testing, one mutation per claim.
6. `make lint`, `CGO_ENABLED=0 go test ./...`, the Postgres suite with `-v`.
7. Handover, then the pull request.
