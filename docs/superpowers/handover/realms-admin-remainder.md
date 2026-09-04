# The `admin/realms-admin` remainder: localization and the converter

Date: 2026-09-03
Branch: `feat/realms-admin-remainder`
Plan: `docs/superpowers/plans/2026-09-03-realms-admin-remainder.md`

Everything below was measured against a live Keycloak 26.7.1 on `:8164`, on
2026-09-03. Every destructive probe was done in a realm created for the sweep.
What `master` received is exactly two things, both of them additive: the users
the guard sweeps needed, and one localization bundle, which the cross-realm half
of the guard sweep had to read on master as well as on a created realm. No
component was created anywhere, which is the sweep that has cost two containers.

## 1. Measurements

### 1.1 The chapter's count, which the brief asked to be established first

`Realms Admin` holds **45** operations. **21** carry an `Implemented` case and
**24 do not**, computed from the vendored description and the catalogue rather
than incremented. The 24 fall into **eight** families, not four:

```
7  localization                 the seven this cut builds
1  client-description-converter the one this cut builds
6  events / admin-events / events/config          P14's own cut
1  client-session-stats
1  sessions/{session}  DELETE
1  logout-all           1  push-revocation
1  credential-registrators
2  users-management-permissions GET and PUT
1  partial-export       1  partialImport
1  testSMTPConnection
```

**Three of the brief's hint numbers were wrong, and all three the same way.**

- **Localization is seven, not six.** The description enumerates `GET`, `POST`
  and `DELETE` on `{locale}`, `GET`, `PUT` and `DELETE` on `{locale}/{key}`, and
  the collection `GET`. This is the family the brief warned had twice been
  undersized, undersized again by one.
- **Client policies are all four served already** - `GET`/`PUT` on
  `client-policies/policies` and `client-policies/profiles` have carried
  `Implemented` cases since P4's second cut. There was nothing in that family to
  take, and the brief's scope named it.
- **`client-types` is served too**, both operations, as the 501 behind the
  disabled preview feature. They are two of the 21, not two of the 24.

Nine of the 24 - rows 16 to 24 of the plan's table - appear in no line of the
hint at all.

### 1.2 The localization family's seven answers

```
GET    /localization                 200  ["de","en"]   application/json;charset=UTF-8
GET    /localization/{locale}        200  {"k":"v"}     application/json;charset=UTF-8
GET    /localization/{locale}/{key}  200  v             text/plain;charset=UTF-8
POST   /localization/{locale}        204
PUT    /localization/{locale}/{key}  204
DELETE /localization/{locale}        204
DELETE /localization/{locale}/{key}  204
```

**No response in this family carries `Cache-Control`** - success or refusal, on
any of the seven. The realm's own reads one path segment away all carry
`no-cache`, and `GET /admin/realms/{realm}/client-session-stats` and
`/credential-registrators`, measured in the same sweep, carry `no-cache` too.

The locale listing is **sorted**: five locales written `zz, aa, mm, ru, de-CH`
came back `aa, de-CH, mm, ru, zz`.

Refusals:

```
GET    /localization/{locale}        unknown  200 {}
DELETE /localization/{locale}        unknown  404 {"error":"No localization texts for locale en found."}
GET    /localization/{locale}/{key}  unknown  404 {"error":"Localization text not found"}
DELETE /localization/{locale}/{key}  unknown  404 {"error":"Localization text not found"}
```

One missing locale, **two answers decided by the verb**; and the two 404
spellings differ by a full stop, one naming the locale and one not. Both are the
bare `error` key rather than the `errorMessage` family.

### 1.3 The key order is the contract, and four writes give three rules

The bundle is one JSON document per (realm, locale) and the read serves its key
order back. Measured as a designed sequence on one locale:

```
POST k1..k5 onto a locale that does not exist  -> k1,k2,k3,k4,k5     the request's order
POST {k6}                                      -> k3,k4,k5,k6,k1,k2  re-bucketed, capacity 8
PUT  k7                                        -> ...,k1,k2,k7       appended, nothing moved
DELETE k1                                      -> k3,k4,k5,k6,k2,k7  removed, nothing moved
PUT  k8                                        -> ...,k7,k8          appended
POST {k9} onto those seven                     -> k2,k3,...,k9       re-bucketed, capacity 16
PUT  k2, a key already there                   -> value replaced in place
```

The capacity is `javamap`'s `capacity(n, n)` for the resulting entry count -
`capacity(6,6)` is 8 and `capacity(8,8)` is 16, and both are what the server
answered. `javamap.SizedKeyOrder(1, insertionOrder)` is exactly that function's
second table with its first disabled, and it reproduces all three measured
orders.

**And the re-bucketing is a consequence of the row being written, not of the
verb.** Found by a golden disagreeing with the handler, which is what that rule
is for:

```
POST the same six pairs three times over  -> the order never moves
POST the same six keys, one value changed -> the whole document re-buckets
POST a subset whose values already match  -> the order never moves
```

So a repeated import - the commonest thing a caller does with this route -
changes nothing at all. A handler that re-buckets unconditionally is wrong on
every one of them, and Gloak's did until the golden said so.

### 1.4 The default-locale fallback

`?useRealmDefaultLocaleFallback=true` merges the realm's `defaultLocale` bundle
**under** the requested one and **re-buckets the result**, which neither
document's own order survives:

```
default aa = {"only.aa":"a","k":"aa"}   requested zz = {"only.zz":"z","k":"zz"}
zz?useRealmDefaultLocaleFallback=true -> {"only.aa":"a","only.zz":"z","k":"zz"}
```

It is driven by `defaultLocale` **alone**: turning `internationalizationEnabled`
on and off left the answer identical. A locale that does not exist answers the
default's texts outright. The single-key read and the collection listing ignore
the parameter entirely.

`defaultLocale` itself is **absent from the realm representation until it is
set** and present as `""` once it has been, between `supportedLocales` and
`browserFlow`. Master carries neither key.

### 1.5 Two of Keycloak's own defects, reproduced

- **`POST .../localization/{locale}` with an empty request body or a literal
  `null` answers 204 and leaves the locale with no document at all.** After
  that, `GET /localization/{locale}`, `GET .../{key}`, `PUT .../{key}` and a
  further `POST` are all **500 `unknown_error`** for ever; `GET /localization`
  lists the locale; `DELETE .../{key}` on it is the ordinary 404 and
  `DELETE /localization/{locale}` removes it. `{}` is a different body and a
  different outcome: 204, and the locale reads back `{}`.
- **Poisoning a locale is not idempotent**: the first empty POST is 204 and
  every one after it is 500.

### 1.6 Values, and the two 400s

```
{"n":123}    204, stored as "123"      {"n":1.5}  204, stored as "1.5"
{"n":true}   204, stored as "true"     {"n":null} 204, and the key is dropped
{"n":{}}     400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
{"n":[1]}    400 the same
[]           400 the same
{            400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
{"n":"x",}   400 the same invalid_request
```

**The code is not the body's first byte.** A body that is not JSON is
`invalid_request`; one that is JSON and is not an object of scalars is
`unknown_error`, whether it starts with `[` or `{`. That is a refinement of
AGENTS.md's "per body *shape*, not per endpoint": the shape that decides is
"parses at all", and `{"n":{}}` is the body that separates the two readings.

The number coercion is F97's, met a second time. The `null` drop is its own
rule and a decoder into `map[string]string` gets it wrong by storing `null`.

### 1.7 `PUT .../{locale}/{key}` consumes `text/plain`

Measured over nine spellings:

```
text/plain, text/plain;charset=UTF-8, TEXT/PLAIN, */*, absent   204
application/json, application/xml, text/html, application/octet-stream   415
```

The 415 body is byte-identical to the one
`admin/scope-mappings/unsupported-media-type` already holds. An empty body is a
204 storing the empty string, which the read answers with a zero-length
`text/plain` 200.

`POST .../localization/{locale}` is different again: `application/json`,
`application/json;charset=UTF-8`, `*/*` and an absent header are 204, and
`text/plain` and `application/xml` are a **500 whose body is Quarkus's
`text/plain` error page carrying a per-request error id**. That answer cannot be
recorded and Gloak does not attempt it - the header is left unread, which is a
declared divergence.

### 1.8 The guards, swept one single role at a time

Over all 21 roles of the realm's own container, the two master-only realm roles
and a caller holding nothing, with a token minted per caller:

```
GET /localization                every container role but impersonation
GET /localization/{locale}       GET /admin/realms/{realm}'s own admission
GET /localization/{locale}/{key} every container role but impersonation
the four writes                  manage-realm alone
the converter                    manage-clients alone
```

**`GET /localization/{locale}` is the second read in this API that leaks
sideways across a realm boundary, and its two siblings do not.** A master caller
holding any `master-realm` admin role reads another realm's texts **in full** -
not a reduced body the way the realm read is - and is 403 on `GET /localization`
and `GET /localization/{locale}/{key}` for the same realm. A caller holding only
the realm role `create-realm`, which owns no container at all, reads it too and
is 403 on the other two. That caller is what separates the two admissions, and
without it the two guards are indistinguishable and swapping them passes.

The realm is resolved before the caller on all eight routes: an unknown realm is
`404 {"error":"Realm not found."}` to a caller holding nothing. The converter
judges the caller **before** the body: a bad body from a refused caller is the
403.

### 1.9 The converter

- **The `Content-Type` is not read at all.** The same OIDC body converts under
  `application/json`, `text/plain`, `application/xml` and with no header; the
  SAML body does too. The body's shape decides.
- The OIDC branch is taken when the trimmed body starts with `{`, ends with `}`
  and **contains the string `redirect_uris`**. `{"x":"redirect_uris"}` passes
  that and then fails to decode, answering **500 `unknown_error` / `Cannot parse
  the JSON`** - which is how the string test is visible at all. Anything else is
  `400 {"error":"Unsupported format"}`, including an empty body and
  `{"client_id":"x"}`. Whitespace is trimmed before the braces are looked at.
- The decode is **strict**, and an unrecognised field is the same 500. That is a
  fifteenth strict decoder on this API and the **first that answers 500**; the
  other fourteen all answer 400.
- `token_endpoint_auth_method` with an unregistered value is a 500 too, with a
  **different** body: `For more on this error consult the server log.` Two 500
  bodies on one route.
- The 200 carries **no `Cache-Control`**.
- The whole accepted field set was sent in one body and answered 200, and it is
  declared in `oidcClientDescription` because the decode is strict. **The one
  name that separates the measurement from the specification is
  `software_statement`**: it is RFC 7591's, it is the obvious next field, and it
  is a **500** - Keycloak's representation has no such field. Declaring it would
  have made Gloak accept a body Keycloak refuses, and only sending it says so.
  `TestClientDescriptionConverterAcceptsEveryMeasuredFieldName` sends both.

The mapping, measured one field at a time:

```
client_id -> clientId          client_name -> name        client_uri -> baseUrl
logo_uri  -> attributes.logoUri
redirect_uris -> redirectUris  (null drops the key, [] sends [])
response_types / grant_types -> the flow flags, see below
token_endpoint_auth_method -> clientAuthenticatorType, publicClient and
                              attributes["client.secret.authentication.allowed.method"]
scope -> optionalClientScopes, Java's String.split(" ") with "" giving []
frontchannel_logout_uri -> frontchannelLogout and attributes
backchannel_logout_uri  -> attributes only
post_logout_redirect_uris and default_acr_values -> joined with ##
*_logout_session_required -> attributes, backchannel defaulting to **true**
```

The flags, ten measured combinations:

```
response_types absent, [], ["none"], ["code"]     standard, no implicit
response_types ["token"], ["id_token"], ["id_token token"]  implicit, no standard
response_types ["code","token"]                   both
grant_types []                                    the response_types answer
grant_types ["authorization_code"]                standard
grant_types ["password"] / ["refresh_token"] / ["bogus"]  neither
grant_types ["authorization_code","implicit"]     both
grant_types ["client_credentials"] + rt ["token"] implicit, no standard
```

So a **non-empty** `grant_types` decides the standard flow, an empty one hands
the question back to `response_types`, and the implicit flow is the union of the
two. The naming of `grant_types` at all - even as `[]` - is what adds
`serviceAccountsEnabled` and `authorizationServicesEnabled` to the body and five
attributes to the map.

### 1.10 The converter's `attributes` cannot be placed, and the reason is two

**The capacity is not a function of the key set.** Three keys came back at
capacity 16, six at 32, eight at 32, eighteen at 32 and forty-one at 32.
`javamap.capacityFor` gives 16 up to twelve entries, so it agrees on every set of
four or fewer and on every set of thirteen or more, and disagrees in between -
exactly the range a body naming `grant_types` or `jwks_uri` lands in. No function
in that package can be handed the right table, because the number that decides it
is how many entries Keycloak's own construction sequence put in before it dropped
some, and nothing on the wire says what that was.

**And two of the attribute names collide with two that every body carries**, at
capacity 16 and at 32 alike:

```
bucket 4 / 20   backchannel.logout.url        with backchannel.logout.session.required
bucket 9 / 9    post.logout.redirect.uris     with frontchannel.logout.session.required
bucket 11 / 11  logoUri                       with use.jwks.url
bucket 2 / -    client.secret.authentication.allowed.method with use.jwks.string
```

Keycloak chains a collision in **insertion** order and `javamap.KeyOrder` breaks
it alphabetically, which is that function's documented limit. Keycloak put the
added key first in both measured cases and alphabetically it sorts second in
both.

So the shapes Gloak reproduces byte for byte are the ones with four or fewer
attributes and no collision, and the byte-exact table in
`clientdescription_test.go` is exactly those. Two measured bodies are asserted
by membership and value with their order recorded in a comment, and a
`grant_types` body is a `Recorded` conformance case.

### 1.11 A 406 nobody has implemented anywhere

`Accept: application/json` on the `text/plain` key read is
`406 {"error":"HTTP 406 Not Acceptable"}`, and `Accept: text/plain` on
`GET /admin/realms/master`, `/clients`, `/groups` and `/admin/realms` is the
same 406. So it is API-wide rather than this family's, it is a **sixth** body in
the fallback family after the two 404s, the 405, the 401 and the 403, and Gloak
implements it nowhere. Not built here: a rule applied to two routes and no
others would be worse than the gap.

### 1.12 A `PATCH` that is a real 405

```
PUT / POST / DELETE  /localization        404
PATCH                /localization/{l}    405
PATCH                /localization/{l}/{k} 405
```

That is the protocol mappers' split - `PATCH` alone answering a real 405 - met
on a second family. Gloak answers 404 to all of them through
`WithKeycloakFallbacks`, so nothing was changed on the strength of it. See F31.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for folding.

---

- **The `X-Frame-Options` exception is about the response's media type, and the
  request's is only the fallback.** Measured 2026-09-03 as a 2x2 on the
  localization family: `GET .../localization/{locale}/{key}` answers a
  `text/plain` 200 and omits the header whether the request declared
  `application/json`, `text/plain` or nothing at all, and
  `GET .../localization` beside it answers an `application/json` 200 and carries
  it under all three. **The same route answers its own 404 as
  `application/json` and carries it** - one route, one verb, two media types,
  two header sets. So `userinfo`'s rejections omitting it is not a fact about
  `userinfo`: they are `text/plain` and its own 200 is `application/json`, and
  the repository's own six userinfo goldens say so. The 204 rule reads back as
  the same rule seen through a response with no media type of its own, which is
  why `httpx.WriteNoContent` consults the request. What is **not** explained is
  the `Duplicate resource error` split, which is two `application/json` 409s on
  one route disagreeing; that one stands. Three of the five exceptions are one
  rule and the fifth is still a fifth.
- **A localization import that changes nothing changes nothing at all, the key
  order included.** `POST .../localization/{locale}` re-buckets the whole
  document through a Java map - `k1..k5` then `{k6}` came back
  `k3,k4,k5,k6,k1,k2` - but the same six pairs posted three times over never
  moved, and a subset whose values already match never moved either. Change one
  value and the whole document re-buckets. So the re-ordering follows the row
  being written, not the verb, and a handler that re-buckets unconditionally is
  wrong on every repeated import. Found by a recorded golden disagreeing with a
  handler written from a three-probe model, which is what that discipline is
  for.
- **The four localization writes give three ordering rules.** `POST` re-buckets;
  `PUT .../{key}` appends a new key at the end and replaces an existing one in
  place; `DELETE .../{key}` removes one and moves nothing - and the surviving
  order is the document's own rather than what the same key set would re-bucket
  to, which is what makes it a measurement rather than an assumption. A create
  on a locale that does not exist stores the request's own key order.
- **`POST .../localization/{locale}` with an empty body or a literal `null` is a
  204 that leaves the locale unreadable for ever.** The row is created,
  `GET /localization` lists it, and the three reads, the `PUT` and a further
  `POST` are all 500 `unknown_error`; only the two deletes still work, and the
  key delete answers the family's ordinary 404. `{}` is a different body and a
  different outcome. Keycloak's own defect, reproduced, and **poisoning is not
  idempotent** - the first empty POST is 204 and every one after it is 500.
- **One missing locale, two answers, decided by the verb.**
  `GET .../localization/{locale}` is `200 {}` and
  `DELETE .../localization/{locale}` is
  `404 {"error":"No localization texts for locale <l> found."}`. Its sibling
  `Localization text not found` has **no** full stop and does not name the key,
  so this family adds two spellings of not-found and one more pair separated by
  punctuation. Both are the bare `error` key.
- **`GET .../localization/{locale}` leaks across a realm boundary and its two
  siblings do not.** A master caller holding any `master-realm` admin role reads
  another realm's texts **in full**, where the realm read next door serves that
  caller its shortest shape; the collection listing and the single-key read
  answer it 403. A caller holding only `create-realm` reads it too. So this API
  has **two** reads that reach sideways, one family has two admissions one path
  segment apart, and `create-realm` is the caller that tells them apart.
- **`useRealmDefaultLocaleFallback` follows `defaultLocale` alone.** Turning
  `internationalizationEnabled` on and off changed nothing either way. It merges
  the default's bundle **under** the requested one and **re-buckets the
  result**, so neither document's own order survives; a locale that does not
  exist answers the default's texts outright; and the single-key read and the
  collection listing ignore the parameter entirely.
- **The localization import has two 400s and the first byte does not pick.** A
  body that is not JSON is `invalid_request`; one that is JSON and is not an
  object of scalars is `unknown_error`, whether it starts with `[` or `{`.
  `{"n":{}}` is the body that separates the two readings, and eleven earlier
  probes of this rule all sent a truncated object. Inside the object, a number
  and a boolean are coerced to strings and a **`null` is dropped**, which a
  decoder into `map[string]string` gets wrong by storing four characters.
- **`client-description-converter` reads the body's shape and never the
  `Content-Type`.** The same OIDC body converts under `application/json`,
  `text/plain`, `application/xml` and with no header at all. The OIDC branch is
  a **string** test - trimmed, starts `{`, ends `}`, contains `redirect_uris` -
  so `{"x":"redirect_uris"}` passes it and then fails to decode, and that is a
  **500** where an unrecognised shape is a 400. Its decode is strict, which
  makes it the fifteenth strict decoder on this API and the first answering 500;
  and an unregistered `token_endpoint_auth_method` is a second 500 with a
  different description. Two 500 bodies on one route.
- **The converter is authorised out of the clients role set.** `manage-clients`
  alone opens it and `manage-realm`, `view-realm`, `view-clients` and
  `create-client` are all 403, on a route the description tags `Realms Admin`.
  That is the fourth time that tag has failed to predict a guard, and the second
  time it has failed in this direction.
- **A converted client's `attributes` cannot be placed and there are two
  reasons.** The capacity is not a function of the key set - three keys at 16,
  six and eight and eighteen and forty-one at 32 - so no `javamap` function can
  be handed the right table; and two of the attribute names collide with two
  every body carries, where Keycloak chains in insertion order and
  `javamap.KeyOrder` breaks the tie alphabetically. Gloak reproduces the shapes
  with four or fewer attributes and no collision, and a `grant_types` body is a
  `Recorded` case rather than a mask.
- **A mismatched `Accept` is a 406 across the whole Admin API and Gloak
  implements it nowhere.** `Accept: text/plain` on `GET /admin/realms/master`,
  `/clients`, `/groups` and `/admin/realms` all answer
  `406 {"error":"HTTP 406 Not Acceptable"}`, and so does `Accept:
  application/json` on the one route that produces `text/plain`. It is a sixth
  body in the fallback family. Nothing was changed on the strength of it: a rule
  applied to two routes and no others is worse than the gap.

---

## 3. Follow-up dispositions

**F95 - a client's `attributes` is serialised from a Go map.** Untouched and
unchanged. This cut adds a **sixth** family that serialises a Java map from an
ordered slice with a marshaller of its own - a converted client's `attributes` -
and a seventh shape that is an ordered *object* rather than a map, the
localization bundle. The entry's own note that "the pattern this entry asks for
is now the majority and the client is the holdout" gains two more members.

**F133 - `writeEmptyStatus` lives in `internal/admin`.** Its shape now has a
second instance and the entry should name both: `writeLocalizationText` writes
this API's only `text/plain` 200 and lives in `internal/admin` for
`writeEmptyStatus`'s reason - `internal/httpx` was not this branch's to change.
The body it writes is the stored value with nothing done to it, so the
divergence that package's boundary exists to prevent is not reachable through
it. Moving both is one rename.

**F134 - four listings treat an unparseable bound as no bound.** Untouched. The
localization family takes no integer bounds at all, so it adds nothing to the
entry either way.

**F153 - two organization member routes overlap and `ServeMux` panics.**
Untouched, and its hazard does not arise here: all seven localization patterns
sit under the literal `/localization` and none of them overlaps another, so
`net/http` accepts the set. Checked by registering it - every test in
`internal/admin` builds the whole router, and a conflict is a panic at
registration rather than a failure later.
**No catch-all was registered on this branch**, so the entry's unmeasured
question - whether `/organizations/{a}/{b}/{c}` behaves like the group family's
locator - is still unmeasured and still the request to send before reopening it.

### New follow-ups this cut opens

- **The converter's `attributes` order for a map of five to twelve entries.**
  Measured unreproducible with `javamap` as it stands, for the two reasons in
  §1.10. A cut that wants it needs either a capacity `javamap` can be told, or
  the insertion order Keycloak's construction sequence uses. The `Recorded`
  golden `admin/realms-admin/client-description-converter-grant-types` is the
  contract to implement against.
- **The converter's SAML branch.** Measured and not built. The `Recorded` golden
  `admin/realms-admin/client-description-converter-saml` is the contract.
- **The converter's unmapped fields.** Sixteen of the fifty-four names it
  accepts are mapped and the rest are declared on the request struct so the
  strict decode is faithful, and ignored. Their measured effect - a
  forty-one-key `attributes` map - is in §1.9's sweep, and it is unreachable
  byte-exactly for §1.10's reason anyway.
- **`supportedLocales` is dropped by `PUT /admin/realms/{realm}`.** Gloak's
  realm representation has no such field, so a `PUT` naming it loses it. That is
  a pre-existing gap this cut found while adding `defaultLocale` beside it, and
  it is not fixed here because the field needs a pointer to distinguish absent
  from `[]` and that is a change to a 104-key golden's neighbourhood.
- **The 406 on a mismatched `Accept`, API-wide.** §1.11.
- **`POST .../localization/{locale}` with a refused `Content-Type`** answers
  Quarkus's `text/plain` error page carrying a per-request error id. It cannot
  be recorded and Gloak leaves the header unread, so a `text/plain` import is a
  204 here and a 500 there.

## 4. Lines this cut contradicts

- **AGENTS.md's security-header bullet**, in its third and fourth exceptions:
  "`userinfo`'s rejections send four of the five ... this one is not explained by
  routing, and its own 200 sends all five, so it is not explained by the endpoint
  either". It is explained, by the response's media type - see §2's first entry.
  The bullet's own closing advice, "prefer 'not explained' to the next
  explanation", is why this one is offered with the 2x2 that produced it and
  with the one exception it does **not** cover named.
- **`internal/httpx`'s `SetUserinfoSecurityHeaders` doc comment** repeats the
  same claim - "unlike the first ... it is not explained by routing" - and would
  need the same correction. Not changed: that package was not this branch's.
- **`internal/admin/authzscope.go`'s `writeEmptyStatus` doc comment**: "The rule
  AGENTS.md records for a 204 is really about an empty body." True as far as it
  goes and one step short - it is about the effective media type, of which an
  empty body's is the request's. The function is correct as written.
- **AGENTS.md: "The 'cannot parse the JSON' code is per body *shape*, not per
  endpoint."** True, and the shape that decides is not the first byte: `{"n":{}}`
  and `[]` answer the same code on one route where `{` answers the other.
- **AGENTS.md: "A caller's rights reach exactly one container, and one read
  leaks sideways."** Two, now.
- **AGENTS.md's `guardRealmRead` claim, in `router.go`: "it is the only one whose
  admission is not a role list."** Two routes take it.
- **AGENTS.md: "Fourteen strict JSON decoders."** Fifteen, and the fifteenth is
  the first that answers 500.
- **AGENTS.md's not-found list, twenty-five spellings.** Two more, both in the
  bare `error` shape: `Localization text not found` and `No localization texts
  for locale <l> found.` The count is left to the fold, which is what that
  bullet's own rule asks for.
- **AGENTS.md's wrong-method bullet**: the protocol mappers are no longer the
  only family answering `PATCH` alone with a real 405.
- **The observed document says nothing about localization or the converter**, so
  nothing in it is contradicted; §1 above is what it is missing.

## 5. What was fixed on this branch

- **The import's re-bucketing** was written from a three-probe model that
  re-bucketed unconditionally. The recorded golden refuted it, three further
  probes isolated the rule, and the handler now leaves a document alone when the
  import changes nothing. The golden was right and the handler was wrong.
- **A `null` value in an import** was being stored as the four characters
  `null`; it is dropped, measured.
- **The import's two 400 codes** were being picked by the body's first byte;
  they are picked by whether the body parses at all, measured on five bodies.
- **A dead branch in `splitScope`** - an explicit empty-string case that a
  mutation showed changed no byte, because Go's `strings.Split` plus the
  trailing-empty trim already covers it. Removed, with the reason written down.
- **A nil `r.Body` panic** in the two writes and the converter, found by the
  conformance verifier rather than by a probe: `httptest.NewRequest` with no
  body leaves `Body` nil where net/http's server never does. `clientpolicies.go`
  already documented the same hazard.

## 6. Parity

```
                         before  after  delta
admin/realms-admin           21     29     +8
total                       422    430     +8   of 541
```

Eight operations: the seven of the localization family and
`POST /admin/realms/{realm}/client-description-converter`. The chapter's
sixteen remaining unserved operations are the eight families in §1.1 that this
cut did not open.

Twenty-two goldens were recorded and **no existing golden was rewritten**. Two
of the twenty-two are `Recorded` rather than `Implemented`, and both are named
in §3.
