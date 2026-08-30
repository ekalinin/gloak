# Two claims the harness had stopped checking

Branch `fix/harness-claims`, cut against `main` at `db9f4f3`, answering **F90**
and sweeping every `Pending` and `Recorded` `Reason` in the catalogue.

Everything observable below was measured against a live Keycloak 26.7.1 started
for this cut on port 8103 and removed at the end of it. Nothing in it is
remembered. `kc-device` and `kc-defect` were left alone, and the port was
checked before it was trusted: `GET /realms/master` on 8103 answered an issuer
of `http://localhost:8103/realms/master`.

---

## 1. Measurements

### 1.1 `attributes` is three different maps and they do not answer alike

F90 asks which constructor builds a client's `attributes` and whether the model
reproduces its order. The question turns out to have three answers, one per
resource, which is why the retreat could not come off or stay on as a whole.

**A client's `attributes` is the no-argument constructor and `javamap.KeyOrder`
places it exactly.** Every distinct attribute key set a default 26.7.1 has on
this resource, read off the container on 2026-08-30:

| client | measured order | `KeyOrder` | `SizedKeyOrder` | sorting |
|---|---|---|---|---|
| `account` | `realm_client, post.logout.redirect.uris` | right | right | wrong |
| `account-console` | `realm_client, post.logout.redirect.uris, pkce.code.challenge.method` | right | right | wrong |
| `admin-cli` | `realm_client, client.use.lightweight.access.token.enabled` | right | right | wrong |
| `broker`, `master-realm` | `realm_client` | right | right | right |
| `security-admin-console` | `realm_client, client.use.lightweight.access.token.enabled, post.logout.redirect.uris, pkce.code.challenge.method` | right | **wrong** | wrong |
| a client created through `POST .../clients` | `realm_client, client.secret.creation.time` | right | right | wrong |

The four keys occupy buckets 0, 2, 3, 9 and 11 at the default table of 16, so
**nothing here collides** and the answer does not depend on insertion order at
all. `SizedKeyOrder` gets the four-key set wrong, which is what says the fork
between the two constructors is real on this resource rather than a distinction
without a difference.

**A realm's `attributes` is the same constructor and `KeyOrder` cannot place
it.** Measured on `master` and on a realm created through `POST /admin/realms`:

```
created realm  cibaBackchannelTokenDeliveryMode cibaExpiresIn cibaAuthRequestedUserHint
               oauth2DeviceCodeLifespan oauth2DevicePollingInterval
               parRequestUriLifespan cibaInterval realmReusableOtpCode
master         the same, minus the two oauth2Device* keys
```

Buckets at 16: `0, 0, 0, 0, 2, 6, 15, 15`. The measured order **is** bucket
order; what it is not is alphabetical inside bucket 0. `KeyOrder` breaks a chain
alphabetically, puts `cibaAuthRequestedUserHint` first, and gets the first three
positions wrong and the last five right - the documented limit, the same shape
as the 21 admin role names, and an insertion order nothing observable reveals.
This is the second of F90's three outcomes and it now has a reason attached
rather than "we gave up".

**A realm role's `attributes` had nothing to give up.** The fixture behind
`admin/roles/list-realm-full` gives its role one attribute, so the object the
mask covered has a single key. Sorting a one-key object is the identity, the
mask was inert, and the golden's bytes are the same with it and without it -
confirmed by a whole `make record`, below.

### 1.2 What Gloak serves, which is a different question from what the model can place

The retreat on a client's attributes is no longer about the order being unknown.
It is about the serialiser: `model.Client.Attributes` is a `map[string]string`
and `encoding/json` sorts it, so Gloak answers `account` with
`post.logout.redirect.uris, realm_client` where Keycloak answers the other way
round. Dropping the mask today fails five cases rather than tightening them, and
`internal/admin` is not this cut's file. See §3.

`model.StringMap` is the shape that already solves this for a client scope's
`attributes` and a protocol mapper's `config`; a client's attributes is the same
problem one resource over.

### 1.3 The `Reason` sweep: six stale strings out of thirty-one

Thirty-one cases are not `Implemented` - twenty-eight `Pending`, three
`Recorded`. Each `Reason` was checked against the router and, where a fixture
allowed it, against what Gloak actually answers.

**Stale, in `catalog_oidc_pending.go` (reported, not edited - that file is the
device-grant stream's):**

| case | says | should say |
|---|---|---|
| `oidc/token/device-code-grant` | the token endpoint is not implemented | the `device_code` grant is not implemented |
| `oidc/token/ciba-grant` | the token endpoint is not implemented | the CIBA grant is not implemented |
| `oidc/token/token-exchange` | the token endpoint is not implemented | the token-exchange grant is not implemented |
| `oidc/token/jwt-authorization-grant` | the token endpoint is not implemented | the `jwt-bearer` grant is not implemented |
| `oidc/token/dpop-bound-token` | the token endpoint is not implemented | DPoP is not implemented |

The token endpoint is routed at `internal/oidc/router.go:98` and dispatches four
grants - `password`, `refresh_token`, `client_credentials` and
`authorization_code`. This is the same shape as the four `oidc/authorization`
cases found stale earlier in the week, one endpoint over.

**Stale, in `catalog_admin.go` (fixed here):** `admin/clients/list-all` said
"two bootstrapped clients carry protocolMappers, which is P5". P5 landed. Serving
the case against the golden leaves **three** differences and none of them is a
missing mapper:

```
client 4 (master-realm)  "name"                  want "master Realm", served: absent
client 4 (master-realm)  defaultClientScopes     want the six, served []
client 4 (master-realm)  optionalClientScopes    want the five, served []
client 1 (account-console) protocolMappers[0].config
                         want {}, served {"introspection.token.claim":"true",
                                          "access.token.claim":"true"}
```

The last is AGENTS.md's own "one mapper serialises two ways" bullet: Keycloak
answers `"config":{}` for `account-console`'s `audience resolve` from
`GET /clients` and a populated config from the dedicated mapper route. Gloak
serves it populated from both.

**Expired phrasing, substance still true (reported only):**
`oidc/authorization/implicit-flow` says "the implicit flow is out of P3's
scope". P3 is finished. `classifyResponseType` in `internal/oidc/authorize.go`
recognises the implicit and hybrid response types and rejects them on a client
with the flag off; nothing issues an implicit response, so the case is still
correctly `Pending`. A `Reason` naming a plan phase stops being readable the
moment the phase closes, whichever way the code went.

**Checked and accurate:** the four theme-page cases ("the login theme is P13"),
the five device cases, the three CIBA cases, the six registration cases, the two
Jackson line-and-column cases, the two harness-limitation cases and
`oidc/introspection/active-access-token`. Gloak answers the four theme pages
with the right status and header set and a placeholder body, which is exactly
what "the theme is P13" describes; it answers `/auth/device`, `/ext/ciba/auth`
and `/clients-registrations/openid-connect` with the unmatched-path 404.

### 1.4 What the tests here do **not** pin

The five client vectors land in five separate buckets, so **not one of them
exercises a chain**. A build that resolved bucket collisions the other way round
passes all five. That limit is pinned by
`TestKeyOrderCannotResolveBucketCollisions` and by nothing in the new test; the
new test's doc comment says so rather than leaving it to be noticed.

What they do pin is the table size, and this was checked rather than assumed: at
8, 32 or 64 buckets at least one of the five comes back in a different order.
So they are not the F80-shaped trap where fourteen vectors passed a mutation of
the rule they were meant to establish.

---

## 2. Entries for AGENTS.md

### 2.1 "Things that look like bugs and are not" - **replacing** the `attributes` bullet

The bullet standing today says matching `attributes` "would mean emulating
`java.util.HashMap` in Go". That emulation exists, it is `internal/javamap`, and
it **does** match a client's attributes. Suggested replacement:

> - **`attributes` key order is masked on seven cases, and for two different
>   reasons.** It is a Java `Map` in hash order and Go sorts map keys.
>   `Case.UnorderedKeys` sorts both sides, so membership and values stay
>   asserted and only the order stops being. **The reason is per resource, not
>   per key name.** A **client's** attributes are the no-argument constructor's
>   map and `javamap.KeyOrder` places every key set a default 26.7.1 has on one -
>   five of them, no bucket collision anywhere in the set - so the mask there is
>   waiting on the *serialiser*: `model.Client.Attributes` is a Go map and
>   `encoding/json` sorts it. A **realm's** attributes are the same constructor
>   and the model genuinely cannot place them: four of the eight keys share
>   bucket 0 and Keycloak chains a collision in an insertion order nothing
>   observable reveals, so `KeyOrder` gets the first three positions wrong and
>   the last five right. Do not add a third kind of retreat without writing down
>   which of the two it is. Not every Java map in this API needs one: a protocol
>   mapper's `config` is reproduced exactly, asserted by
>   `admin/client-scopes/list` since 2026-08-30.
>   **An eighth mask came off on 2026-08-30 because it was inert.**
>   `admin/roles/list-realm-full` masked a one-key object, where sorting is the
>   identity; the golden's bytes were the same with it and without it. An inert
>   retreat is worse than none, because it reads as though something was
>   measured and conceded.

### 2.2 "Things that look like bugs and are not" - a new bullet, next to the `master-realm` material

> - **`master-realm` is not a bare client.** Keycloak gives it the display name
>   `master Realm` and both client-scope lists - the six defaults and the five
>   optionals - like every other bootstrapped client. Gloak bootstraps it with
>   neither, which is two of the three differences left in
>   `admin/clients/list-all` now that P5 has landed. The third is
>   `account-console`'s `audience resolve` serving a populated `config` where
>   `GET /clients` measures an empty one.

### 2.3 "Build and test" - a new bullet after the parked-goldens material

> - **A `Reason` is checked, not trusted.** It is what the next person reads
>   when deciding what to work on, and a stale one sends them past work that is
>   already possible. Two families went stale inside one week and both were
>   found by accident. `TestNoReasonClaimsAServedEndpointIsUnserved` fails a
>   `Pending` or `Recorded` case whose `Reason` says a named endpoint is not
>   built when the router serves it. It is a table of **literal phrases**
>   mapped to paths rather than a heuristic over prose: the obvious version -
>   "the `Reason` mentions an endpoint the router serves" - cries wolf on seven
>   accurate `Reason`s, because five device cases `POST` to the token endpoint
>   and truthfully say the *device* endpoint is not built. The probe is a method
>   no route registers, so it needs no fixture - which matters, because 21 of
>   the 28 `Pending` cases have none and cannot be served at all. It is a
>   ratchet: a `Reason` phrased some other way is unchecked until the phrasing
>   is added, the same bargain `parkedGoldens` and `namedOutsideTheConvention`
>   take. `staleReasonsOwnedElsewhere` holds the five it finds in another
>   stream's file, each with the text it should carry instead, and an entry that
>   stops being stale fails so the list shrinks to nothing.

### 2.4 "Build and test" - amending the `make record` count

The line reads "327 rewritten with identical bytes". The catalogue has grown:
a whole run now rewrites **380** of the 387 golden files, leaving the seven
parked `Pending` ones alone, and it is still silent on a clean checkout.

---

## 3. Follow-up dispositions

### F90: the `attributes` retreat has been re-examined - **close it**

Answered, and the answer is F90's own third outcome: reproducible for some cases
and not others. Per case:

| case | disposition |
|---|---|
| `admin/roles/list-realm-full` | mask **removed** - it covered a one-key object and was inert |
| `admin/clients/list`, `list-all`, `read`, `read-created`, `read-described` | mask **kept**, blocked on the serialiser rather than the model - F92 |
| `admin/realms-admin/list`, `read` | mask **kept**, blocked on a bucket collision, which is the documented limit |

The measurement is pinned by `TestKeyOrderReproducesAClientsAttributes` and
`TestKeyOrderCannotPlaceARealmsAttributes` in `internal/javamap`, so the answer
cannot quietly rot the way the question did.

### F92 (new): a client's `attributes` is serialised from a Go map

`internal/admin` marshals `model.Client.Attributes`, a `map[string]string`, so
`encoding/json` sorts the keys. Keycloak's order is `javamap.KeyOrder`'s and is
exactly reproducible - measured on all five key sets a default 26.7.1 has, with
no bucket collision anywhere in them, so no insertion order is needed.

Fixing it is the same move `model.StringMap` already makes for a client scope's
`attributes` and a protocol mapper's `config`. When it lands, `UnorderedKeys`
comes off five cases in `catalog_admin.go` and their goldens start asserting
real bytes.

Reported rather than changed: `internal/admin` and `internal/model` are not this
cut's files.

### F93 (new): three differences left in `admin/clients/list-all`

Two are bootstrap - `master-realm` gets no `name` and neither client-scope list.
One is the `audience resolve` mapper serialising two ways, which AGENTS.md
already records as measured Keycloak behaviour that Gloak does not reproduce.

The case's `Reason` now names all three, so this follow-up is the place the
three are counted rather than the only place they are written down.

### F94 (new): five `Reason`s in `catalog_oidc_pending.go` are stale

The five in §1.3, with the replacement text. `TestNoReasonClaimsAServedEndpointIsUnserved`
declares them in `staleReasonsOwnedElsewhere` and will fail on the entry once it
is corrected, which is the hand-off.

A sixth is softer and is not in the guard, because no mechanical check reaches
it: `oidc/authorization/implicit-flow` says "out of P3's scope" and P3 is over.
**A `Reason` naming a plan phase expires when the phase closes**, whichever way
the code went, and a `\bP\d+\b` rule would fire on six `Reason`s of which only
two are stale. That one is a convention for reviewers, not a test.

### F80, F59: nothing owed

F80's two-constructor model held on every vector this cut measured against it,
including two resources it was not built from. F59's `editPaths` rewrite is what
lets `admin/roles/list-realm-full` drop a mask at one depth without disturbing
another; nothing here reopens either.

### The numbers to confirm at fold-in

F92, F93 and F94 are the next free numbers as of `db9f4f3`, where F91 is last.
`catalog_admin.go` cites F92 and F93 in two comments. If another stream files
first, those two citations move with them.

---

## 4. Parity, before and after

```
Parity: 242 of 500, no change.
```

Measured with the recipe in AGENTS.md: `GLOAK_PARITY_REPORT` on `db9f4f3` and on
this branch's head, compared with `cmd/parity`, exit 0.

Unchanged is the expected result and not a disappointment. Nothing here serves
new surface: one mask came off a case that was already `Implemented`, one
`Reason` was corrected on a case that is still `Recorded`, and the rest is
tests and comments. `Case.Status` and `Case.Operation` are what the meter reads,
and neither moved on any case.

### `make record`

Run twice: once on the clean checkout as a baseline and once after the change.
**380 goldens rewritten each time, none moved** - `git status` empty after both.
That is the evidence that `admin/roles/list-realm-full`'s `UnorderedKeys` was
inert: a mask that had been doing anything would have moved that golden's bytes
the moment it came off.

### Mutations run

Every claim was mutated separately, the named test confirmed failing, and the
mutation reverted. No mutation survived.

| mutation | test that failed |
|---|---|
| `capacityFor` starts at 32 instead of 16 | `TestKeyOrderReproducesAClientsAttributes`, four of five vectors |
| `bucket` drops the `h ^ (h >> 16)` spread | `TestKeyOrderCannotPlaceARealmsAttributes` - wrong positions become `[0 2 3 5]` |
| one entry removed from `staleReasonsOwnedElsewhere` | `TestNoReasonClaimsAServedEndpointIsUnserved`, on the error path rather than the log |
| a phrase pointed at an unrouted path | the same test, on the "declared stale and no longer is" path, five entries |
| the routed-ness probe forced to `false` | the same test, on its own vacuity check |
| a fresh stale `Reason` planted in `catalog_admin.go` | the same test, naming `admin/users/create-unknown-field` |

The last is the one worth keeping: it is the guard catching a `Reason` that
nobody had declared, which is the case it exists for.
