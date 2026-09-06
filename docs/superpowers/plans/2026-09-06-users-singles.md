# The `Users` tag's remaining eight

The eight operations of the `Users` tag that nothing in the catalogue serves.
They are not a chapter: they are four unrelated groups that happen to be what is
left after `docs/superpowers/handover/scattered-remainder.md` took eleven of the
twenty-seven.

**The list was recomputed rather than inherited.** The hint this cut was handed
had been wrong three times in a fortnight and had been mis-computed twice on the
day it was written, by a regex that truncated a path at a Go string
concatenation. So the set difference was taken **inside Go**, where a
concatenated literal is already one string: a throwaway test in
`internal/conformance` walked the `Users` tag of
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and subtracted the
`Operation` field of every `Implemented` case in `Catalog`. It carried two
controls - a key known to be served must read served, and a key that cannot
exist must not - so a probe answering the same thing for every input would have
failed rather than agreed.

The answer is **34 operations, 26 served, 8 missing**, and the eight are exactly
the eight in the brief. The hint was right this time, and it is recorded as
checked rather than as trusted.

Everything measured below was measured against `quay.io/keycloak/keycloak:26.7.1`
on :8178, whose `GET /admin/serverinfo` reported `26.7.1` before anything was
believed. Another stream's container answers :8179 and was not touched.

## 1. One row per operation

| # | operation | what it needs | taken | why |
|---|---|---|---|---|
| 1 | `GET /users/profile/metadata` | a derivation of the stored profile, two Java maps one nesting level apart | **yes** | it really is a derivation, and this cut is the first that could prove it |
| 2 | `PUT /users/profile` | a strict decoder, nine validators, canonicalisation, a component write | **yes** | the whole validator surface is measured and bounded, and the write it performs is one Gloak already exposes through `PUT /components/{id}` |
| 3 | `PUT /users/{id}/execute-actions-email` | the user's email, the realm's `smtpServer`, a required-action set, and a mail client for the 204 | **the refusals** | see §1.1 |
| 4 | `PUT /users/{id}/reset-password-email` | the same, minus a body and minus `lifespan` | **the refusals** | see §1.1 |
| 5 | `PUT /users/{id}/send-verify-email` | the same, minus a body | **the refusals** | see §1.1 |
| 6 | `GET /users/{id}/consents` | the consent grants `internal/oidc` records | **no** | F110, see §1.2 |
| 7 | `DELETE /users/{id}/consents/{client}` | the same, plus a revoke | **no** | F110, see §1.2 |
| 8 | `POST /users/{id}/impersonation` | the `KEYCLOAK_IDENTITY`/`KEYCLOAK_SESSION` pair | **no** | F148, see §1.3 |

Five taken, three refused. `admin/users` goes from **26 / 34 to 31 / 34**.

### 1.1 The three emails: the refusals, not the mail client

**The decision is the refusals, and the reason is that on Gloak they are the
whole reachable answer rather than three quarters of it.**

Measured over four states, each with the control that differs - the realm's
`smtpServer` was changed between blocks and re-read, so a block answering what
the block before it answered would have been a block whose state did not move:

| realm `smtpServer` | user has an email | answer |
|---|---|---|
| any | no | `400 {"errorMessage":"User email missing"}` |
| `{}` | yes | 500 `… Invalid sender address 'null'. …` |
| host unreachable | yes | 500 `… Error when attempting to send the email to the server. …` |
| reachable | yes | 204, and the message arrives |

Rows three and four are the ones a mail client buys. **Neither is reachable in
Gloak, and not because of this cut.** `internal/admin/realmrep.go` builds the
realm representation with `SMTPServer: map[string]string{}` - a literal, never
read from and never written to storage - so every Gloak realm's `smtpServer` is
`{}` for ever. Row three needs a stored `smtpServer`, which is a realm-settings
chapter this cut does not own; row four needs that *and* a mail transport *and*
Keycloak's message templates.

So serving rows one and two is not "three quarters of an operation". It is the
same shape as `configured-user-storage-credential-types` answering `[]` because
Gloak has no user storage federation, and `client-types` answering 501 because
the feature cannot be switched on: **a constant that is a contract because the
state behind the other branch cannot be reached.** The difference is that this
one *will* become reachable the day a cut stores `smtpServer`, so it is filed as
a follow-up with the two measured bodies in it rather than left implicit.

The alternative - a `net/smtp` client in this project - was declined on the
ground the brief already names. It buys one status code on a cell no golden can
hold, because a golden over a 204 whose evidence is a message in a mail catcher
asserts the 204 and not the message.

### 1.2 The consents pair: refused on F110, and the reason is a package next door

`GET /users/{id}/consents` answers `200 []` for a user who has consented to
nothing. An `internal/admin` handler answering `[]` would be right for every
user in a freshly started Gloak and **wrong the moment anybody clicks through
the consent page**, because `internal/oidc/authsession.go`'s `consentStore`
records that grant in memory and `internal/oidc/consent.go:264` calls
`grant(...)` on every approval. The Admin API would then say a user has never
consented while the package next door is remembering that they have.

That is not `attack-detection`'s shape and not
`configured-user-storage-credential-types`'. Those answer the empty case because
**nothing in the project writes the state**. Here something does, in a package
this branch may not touch. The two halves have to move in one cut, which is
exactly what F110 says, and `consentStore`'s own doc comment names these two
endpoints as the ones that would expose it.

Both go in as `Pending` with the measurements written where the next reader is
looking. Measured for that cut so it does not have to:

```
GET  .../consents                       200 []   application/json;charset=UTF-8, Cache-Control: no-cache
GET  .../consents  unknown user         404 {"error":"User not found"}
DEL  .../consents/account               404 {"error":"Consent nor offline token not found"}
DEL  .../consents/nosuchclient          404 {"error":"Client not found"}
DEL  .../consents/<a uuid>              404 {"error":"Client not found"}
DEL  .../consents/account unknown user  404 {"error":"User not found"}
```

**The client is resolved before the consent**, so a client that does not exist
and a client with no consent are two different 404s one lookup apart. The guard
is `view-users` or `manage-users` on the read and `manage-users` alone on the
delete, with `query-users` refused on both and still getting `User not found`
for a subject that does not exist - `guardUserSubject`'s two stages, swept one
role at a time.

### 1.3 Impersonation: refused on F148, and it is already refused

`POST /users/{id}/impersonation` mints the browser SSO pair, `KEYCLOAK_IDENTITY`
is `internal/token`'s to sign and the cookies are written by `setLoginCookies` in
`internal/oidc/loginactions.go`, which is unexported and in a package this branch
may not touch. That is F148's settled shape - "if it needs something only
`internal/oidc` has, the honest answer is a case and not a second copy" - and
`admin/users/impersonation` is **already** in the catalogue as `Pending` with
that reason and with the 2026-09-05 measurement above it, including that it ends
the calling administrator's own session.

**This cut changes nothing about it.** Re-litigating a boundary that was settled
twice and applied twice is how a decided question becomes an open one again. It
is listed here because the brief asked which side was taken, and the answer is
the side already taken.

## 2. What is being built

### 2.1 `GET /users/profile/metadata` - a derivation, and the proof of it

`internal/admin/userprofile.go`'s header says of this endpoint that "the two
configs a default install can have produce **byte-identical** metadata although
their profiles differ, so nothing reachable distinguishes the derivation from a
constant". The first half is measured and true - master's metadata and a created
realm's are both 1196 bytes, md5 `d96998890507ef0a1b55714721f626c3`, while their
profiles are 988 and 1078 bytes and differ.

**The second half stopped being true when `POST`/`PUT /components/{id}` became
reachable, and this cut sent the request.** A third profile written into a
created realm - `username` at `length:{min:4,max:60}` and a fifth attribute
`zzcustom` - answered 1278 bytes, md5 `06afad49269918739dee457bb3284092`, with
the new bounds and the new attribute in it. A constant cannot move.

The rules, one cell per request and each with a control:

```
displayName   the attribute's `displayName`, or its `name` when there is none
required      true for `username` always - measured with required:{roles:[user]},
              which is false for every other attribute - and otherwise true iff
              the attribute has a `required` block whose `roles` is absent,
              empty, or contains "admin"
readOnly      true iff "admin" is not in permissions.edit
              (edit:[admin] false, edit:[user] true, edit:[] true)
the attribute is absent altogether when "admin" is not in permissions.view
annotations   passed through
validators    the profile's `validations`, each gaining "ignore.empty.value":true,
              plus a synthesised `multivalued:{"max":"1"}` - **only when the
              attribute is single-valued**; a multivalued attribute with one
              validator answers one validator
group         carried through
selector      dropped
groups        the profile's own groups verbatim, annotations and order included
```

Key order is **two Java maps built by two different constructors, one nesting
level apart** - the third instance of the split `internal/javamap` already
records between an identity provider's config and a component's:

| map | model | vectors |
|---|---|---|
| the `validators` object | `javamap.KeyOrder` | 5 of 6 exact |
| a validator's own config | `javamap.SizedKeyOrder(len(stored), stored + ["ignore.empty.value"])` | **7 of 7 exact** |

The inner one is the protocol-mapper rule exactly - built for the key count the
profile stored, with the appended key arriving after the first table - and the
`len(stored)` is load-bearing rather than cosmetic: `SizedKeyOrder(len(all), …)`
gets `{min, max, ignore.empty.value}` wrong, which is the one vector that
separates the two spellings and is in `master`'s own metadata.

The outer one's single miss is a six-validator attribute where `pattern` and
`options` swap - a bucket collision chaining in insertion order, which is the
documented limit of `KeyOrder` and not a new finding. **No default realm reaches
it**: it needs five validators on one attribute, which only a caller writing the
profile can produce. It is written down rather than masked, because a
`UnorderedKeys` here would say "this varies" about a value that is exactly
determined and merely unmodelled.

Guard: **the same five-role union `GET /users/profile` takes**, and that is
measured rather than assumed. Fifteen master-realm roles, one at a time, a fresh
token each: `view-users`, `manage-users`, `query-users`, `view-realm` and
`manage-realm` answer 200 and the other ten answer 403, cell for cell identical
to the read beside it. So `userProfileReadRoles` is reused unchanged rather than
copied. 401 with no token, `Realm not found.` for a realm that does not exist.

`application/json;charset=UTF-8`, and **no `Cache-Control`** - the same pair
`GET /users/profile` carries, asserted absent for the same reason.

### 2.2 `PUT /users/profile`

200, `application/json` **with no charset** - the third Admin API 2xx body
outside the charset rule, after `POST /groups/{id}/children` and
`POST /partial-export` - no `Cache-Control`, and **the body is byte-identical to
what `GET /users/profile` then serves** and to what the component stores.
Measured all three ways round on one realm.

Guard: **`manage-realm` alone**, measured with callers *inside* the realm they
address. The first sweep put master's callers against a created realm, where a
master caller's rights do not reach, and read 403 in every cell - a probe
measuring the realm boundary rather than the route. Re-run properly:
`view-realm` 403, `manage-users` 403, `manage-realm` 200, `realm-admin` 200. So
a `manage-users` caller may read this profile and may not write it, and the
write guard is not a slice of the read guard.

Nine validators, every message measured verbatim. The 400 is
`{"errorMessage":"[...]"}` and the list inside the brackets is comma-joined, so
`attributes: []` answers about `username` **and** `email` in one body:

```
[The attribute 'username' can not be removed]        username and email only;
[The attribute 'email' can not be removed]           removing firstName is a 200
[Attribute configuration already exists with 'name':'email']
[Attribute configuration without 'name' is not allowed]     absent or empty
[Validator 'x' defined for attribute 'y' doesn't exist]
['permissions.view' configuration for attribute 'x' contains unsupported role 'y']
['required.scopes' configuration for attribute 'x' contains unsupported scope 'y']
['selector.scopes' configuration for attribute 'x' contains unsupported scope 'y']
[Attribute 'x' references unknown group 'y']
```

A tenth refusal is the **strict decoder**, which reports a position:
`Invalid json representation for UPConfig. Unrecognized field "bogus" at line 1
column 412.` and the same sentence naming `UPAttribute` for a field inside one.
That is a **sixteenth** strict decoder for the bullet that counts fifteen.

Three bodies that are not a document, and they are three answers rather than
one:

```
{}  or a body with no `attributes` key   200, and the profile becomes {"groups":[]}
no body at all, or the literal `null`    200, and the profile is **reset to the built-in default**
{                                        400 invalid_request  / Cannot parse the JSON
[]                                       400 unknown_error    / Cannot parse the JSON
text/plain                               415
```

The reset was measured with a control: a marker attribute was written, confirmed
present, and was gone after a bodyless `PUT`.

**The destructive half was done in a created realm and never on master.** `{}`
is the body that breaks every login in the realm it lands in, and it has cost
two cuts a container. Every `PUT /users/profile` in this cut addressed a realm
the probe had just created.

Gloak reproduces the validators and the four body shapes. It does **not**
reproduce the login coupling, and that is a divergence this cut declares rather
than one it introduces: `PUT /components/{id}` writes the identical row today
with no validation at all, so declining the `PUT` would have protected nothing
and would have left the validators unwritten.

### 2.3 The three email writes

One handler family, three routes, and the differences between them are measured
rather than assumed. Two independent sources agree on which parameters exist -
the live server and the vendored description - which is worth saying because
they disagree about the responses (the description gives `send-verify-email` no
404 and the server sends one).

```
                        body   client_id  redirect_uri  lifespan   failing 500
execute-actions-email    yes       yes         yes        yes      "Failed to send execute actions email: …"
reset-password-email      no       yes         yes        **no**   the same sentence, word for word
send-verify-email         no       yes         yes        yes      "Failed to send verify email"
```

`reset-password-email` ignoring `lifespan` is measured on the distinguishing
request: `?lifespan=abc` is the generic `404 {"error":"HTTP 404 Not Found"}` on
the other two and a plain 500 on this one. `execute-actions-email` is the only
one that reads a body, and the only one that answers `text/plain` a 415; the
other two accept any body and any `Content-Type` and ignore both.

The rejection order is ten deep and every adjacency below was decided by a
request wrong in **two** ways, because a request wrong in one way cannot say
which check ran first:

```
1  no token                    401 {"error":"HTTP 401 Unauthorized"}
2  coarse users gate           403 to view-clients, manage-realm, impersonation, …
3  the subject                 404 {"error":"User not found"}  - beats 4..10
4  manage-users                403 to view-users and query-users
5  the body                    400 HTTP 400 Bad Request / Cannot parse the JSON   - beats 6..10
6  lifespan                    404 {"error":"HTTP 404 Not Found"}                 - beats 7..10
7  the user's email            400 {"errorMessage":"User email missing"}          - beats 8..10
8  client_id                   400 {"errorMessage":"Client doesn't exist"}
   with no client_id at all    400 {"errorMessage":"Client id missing"}
9  redirect_uri                400 {"errorMessage":"Invalid redirect uri."}
10 the required actions        400 {"errorMessage":"Provided invalid required actions"}
```

Step 7 beating step 10 is the two-condition cell the brief warns about: a user
with no email **and** a bogus action answers about the email, and the same bogus
action on a user with an email answers about the action. One request supplies
one condition and says nothing; the pair says which runs first.

Guard: **`manage-users` alone** on all three, swept one role at a time over
eight roles. `view-users` and `query-users` are 403 on the route and still get
`User not found` for a subject that does not exist, which is `guardUserSubject`
with `userWriteRoles` - the combinator and the role set the rest of the family's
writes already use.

The body decode's two codes are a **fourth** data point for the "cannot parse
the JSON is per body shape" bullet. One body, `[`, now has three answers across
three families: `unknown_error` on `POST /users`, `invalid_request` on the ten
role-array endpoints, and `HTTP 400 Bad Request` here. `{}` - an object where an
array is wanted - answers `unknown_error`.

## 3. What this cut deliberately does not fix

**`GET /users/profile` reorders an attribute's `annotations` and Gloak passes
them through, which is measurably wrong.** `userprofile.go` records this cell as
open because "one measured pair cannot tell sorting from a Java map". Three keys
can, and nine key sets were measured through `PUT /components/{id}`, which stores
the bytes it is given and is therefore the only writer that can separate the read
from the write:

```
z, m, a                        ->  m, a, z          not sorting
aa, bb, cc, dd                 ->  aa, bb, cc, dd
inputType, kc.foo, zzz         ->  kc.foo, inputType, zzz
one, two, three, four, five    ->  two, three, five, four, one
b, a                           ->  a, b
k1, k2, k3                     ->  k3, k1, k2
a, b, c, d, e                  ->  a, b, c, d, e
d, e, f, g, h                  ->  h, d, e, f, g
f, g, h, i, j                  ->  h, i, j, f, g
```

The first six left **two** models standing - a single table of four buckets over
insertion order, and `SizedKeyOrder(n-1, …)` - and six vectors that two models
both fit is not a rule. The last three were chosen in Go *because* the two models
disagree on them, and all three went the same way. What fits all nine is **one
Java table asked for the entry count, walked in insertion order**:
`byBucket(keys, capacity(n, n))`.

That is neither of the two constructors `internal/javamap` exports. Adding a
third belongs in `internal/javamap`, **which this branch may not touch**, so the
finding is filed with its nine vectors and the fix is not attempted here. Gloak
stays self-consistent - its `PUT` stores what its reads serve - and no committed
golden moves, because no profile a default install ships carries an annotation.

## 4. Files

- `internal/admin/userprofile.go` - the metadata derivation and the `PUT`
- `internal/admin/useremails.go` (new) - the three email writes
- `internal/admin/consents.go` - **not created**; the two operations are catalogue
  cases, and a file holding two handlers that answer a constant would be the
  divergence F110 names wearing an implementation's coat
- `internal/admin/router.go` - five routes
- `internal/conformance/catalog_admin.go` - appended at the very end
- `internal/conformance/fixture.go` - appended at the very end of the map and
  after the last helper
- new goldens under `internal/conformance/testdata/golden/admin/`

**No migration.** The profile is a component row and `internal/store`'s
`ComponentRepo` already writes one; the email refusals read the user's email and
the realm's `smtpServer`, both of which already exist. The `0037_*` slot is
unused by this cut.

## 5. Discipline

- Commit before any edit a mutation pass will revert, and check the revert
  reverted.
- One mutation per claim, a different mutation each time, the **named** test
  confirmed failing, then reverted. A control known not to differ runs first, so
  a harness reporting KILLED for everything is caught before anything is
  believed.
- `go test`'s exit code is read before its log, every time.
- `CGO_ENABLED=0 go test ./...` passes and needs neither Docker nor the network.
- `make lint`.
- Both store drivers - nothing is added to either, and that is checked rather
  than assumed.
