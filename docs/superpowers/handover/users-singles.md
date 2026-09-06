# The `Users` tag's remaining eight

The eight operations of the `Users` tag that nothing in the catalogue served
after `docs/superpowers/handover/scattered-remainder.md` took eleven of the
twenty-seven. The plan is
`docs/superpowers/plans/2026-09-06-users-singles.md`, whose first section is one
row per operation and which side of each decision this cut came down on.

**The list was recomputed rather than inherited, and by a method that handles a
Go string concatenation** - the hint this cut was handed had been wrong three
times in a fortnight, and had twice been mis-computed on the day by a regex that
truncated a path at a `"a" + "b"`. So the set difference was taken **inside
Go**: a throwaway test in `internal/conformance` walked the `Users` tag of
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and subtracted the
`Operation` field of every `Implemented` case in `Catalog`, where a concatenated
literal is already one string. It carried two controls - a key known to be
served must read served, a key that cannot exist must not - so a probe answering
the same thing for every input would have failed rather than agreed. The answer
was **34 operations, 26 served, 8 missing**, and the eight were exactly the
eight in the brief. The hint was right this time and it is recorded as checked
rather than as trusted.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1` on
:8178, whose `GET /admin/serverinfo` reported `26.7.1` before anything was
believed. Another stream's container answers :8179 and was not touched.

**Five taken, three refused.** `admin/users` goes from 26 / 34 to 31 / 34.

## 1. Measurements

### 1.1 `GET /users/profile/metadata` is a derivation, and the sentence that said otherwise is refuted

`internal/admin/userprofile.go` said of this endpoint that "the two configs a
default install can have produce **byte-identical** metadata although their
profiles differ, so nothing reachable distinguishes the derivation from a
constant".

The first clause holds and was re-measured: master and a created realm both
answer 1196 bytes, md5 `d96998890507ef0a1b55714721f626c3`, while their profiles
are 988 and 1078 bytes and differ by three `required` blocks.

**The second clause stopped being true when this package's own
`POST`/`PUT /components/{id}` became reachable, and this cut sent the request.**
A third profile written into a created realm - `username` at
`length:{min:4,max:60}` plus a fifth attribute - answered **1278 bytes**, md5
`06afad49269918739dee457bb3284092`, with both changes in it. A constant cannot
move. The previous cut's claim was true of the sample and not of the endpoint.

The rules, one cell per request, each with a control:

```
the attribute is rendered at all  iff permissions.view names "admin";
                                  an absent block and {} both drop it
displayName                       its own, falling back to `name`; "" counts as absent
readOnly                          true unless permissions.edit names "admin"
                                  (edit:[admin] false, edit:[user] true, edit:[] true,
                                   edit absent true)
required                          `username` always; otherwise a `required` block
                                  whose `scopes` is empty and whose `roles` is
                                  empty or names "admin"
validators                        the profile's `validations`, each gaining
                                  "ignore.empty.value":true, plus a synthesised
                                  `multivalued:{"max":"1"}` **only when the
                                  attribute is single-valued**
group                             carried through
selector                          dropped
annotations                       carried through
groups                            the profile's own array verbatim, order and
                                  annotations included
```

**`required` took seven requests because three readings fit fewer.** `{}` and
`{"roles":[]}` are both **true**; `{"roles":["user"]}` is false;
`{"roles":["user","admin"]}` is true; and `{"scopes":["profile"]}` - which has
no roles at all and would be true under "roles empty means everybody" - is
**false**. So a non-empty `scopes` is a second condition rather than a second
spelling of the first, and the admin context requests no scopes.

`username` overriding all of it is measured on the request that separates the
two readings: a profile marking `username` required for the `user` role alone
still renders `"required":true`, where the identical block on `email` renders
false.

The synthesised `multivalued` validator's bound is the JSON **string** `"1"`
where a declared `length`'s `max` is a number, and it is the one validator that
does **not** gain `ignore.empty.value`.

### 1.2 Two Java maps one nesting level apart, built by two different constructors

This is the third instance of the split `internal/javamap` already records
between an identity provider's config and a component's.

| map | model | vectors |
|---|---|---|
| the `validators` object | `javamap.KeyOrder` | **5 of 6** exact |
| a validator's own config | `javamap.SizedKeyOrder(len(stored), stored + ["ignore.empty.value"])` | **7 of 7** exact |

The inner one is the protocol-mapper rule unchanged - built for the key count
the profile stored, with the appended key arriving after the first table - and
`len(stored)` is load-bearing rather than cosmetic. `{min, max}` growing to
`{min, max, ignore.empty.value}` comes back `max, ignore.empty.value, min` from
`SizedKeyOrder(2, …)` and `ignore.empty.value, max, min` from
`SizedKeyOrder(3, …)`. **That key set is in master's own metadata**, so the
distinguishing vector is not a corner case somebody had to invent.

The outer map's single miss is an attribute carrying six validators, where
`pattern` and `options` come back the other way round: a bucket collision
chaining in insertion order, which is exactly the limit `javamap`'s own package
comment states. **No realm a default install can produce reaches it** - it needs
five validators declared on one attribute - so it is recorded in
`TestTheSixValidatorKeySetIsTheKnownMiss` rather than masked. A
`Case.UnorderedKeys` there would claim the value varies when it is exactly
determined and merely unmodelled, which is the retreat AGENTS.md permits once
and asks nobody to repeat.

### 1.3 `GET /users/profile` reorders `annotations`, and Gloak's pass-through is wrong

`userprofile.go` recorded this cell as open, because "one measured pair cannot
tell sorting from a Java map". Three keys can. Nine key sets were read back
through `PUT /components/{id}` - the only writer that stores the bytes it is
handed, and therefore the only one that can tell the **read's**
canonicalisation from the **write's**:

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

**The first six left two models standing** - a single table of four buckets over
insertion order, and `SizedKeyOrder(n-1, …)` - and six vectors that two models
both fit is not a rule. The last three were computed in Go *because* the two
models disagree on them, and all three went the same way. What fits all nine is
**one Java table asked for the entry count, walked in insertion order**:
`byBucket(keys, capacity(n, n))`, which `internal/admin/localization.go` already
spells `javamap.SizedKeyOrder(1, keys)`.

**It is not fixed here.** That is a third map shape and the place for a third
constructor is `internal/javamap`, which this branch may not touch; spelling it
`SizedKeyOrder(1, …)` works only because the first table collapses at that
argument, which is an accident rather than a reason. Nothing in the tree moves
either way, because no profile a default install ships carries an annotation.
Filed with its nine vectors rather than guessed.

### 1.4 `PUT /users/profile`, and the two ways it breaks a realm

200, `application/json` with **no charset** - the third Admin API 2xx body
outside the charset rule after `POST /groups/{id}/children`'s 201 and
`POST /partial-export` - no `Cache-Control`, and **the body is byte-identical to
what `GET /users/profile` then serves and to what the component stores**,
measured all three ways round on one realm.

The component it creates on a realm that had none carries `providerId`,
`providerType`, `parentId` and `config` and **no `name` key** - the same
nameless shape AGENTS.md records master's shipped row having.

Guard: **`manage-realm` alone**. The first sweep of it was wrong in a way worth
recording: it put master's callers against a created realm, where a master
caller's rights do not reach, and **read 403 in every cell** - a probe measuring
the realm boundary rather than the route, and one that looked exactly like an
answer. Re-run with callers inside the realm they address: `view-realm` 403,
`manage-users` 403, `manage-realm` 200, `realm-admin` 200.

Four bodies that are not a document, and they are **four** answers rather than
two:

```
{}  or a body with no `attributes` key   200, and the profile becomes {"groups":[]}
no body at all, or the literal `null`    200, and the component row is **deleted**
{                                        400 invalid_request  / Cannot parse the JSON
[]                                       400 unknown_error    / Cannot parse the JSON
text/plain                               415
```

The delete was measured with a control - a marker attribute written, read back,
and gone - and confirmed on the component listing, which drops from one row to
none.

**Both destructive halves were reached, and the second one cost a container.**
The warning this cut was given was about `{}`, and `{}` was carefully kept to
created realms throughout. The bodyless `PUT` had been measured as harmless on a
created realm and was then sent to **master** to find out what it did to a realm
whose profile is not the built-in default. It deletes the row, master falls back
to the built-in default, and that default marks `email`, `firstName` and
`lastName` required for the `user` role - which the bootstrap `admin`, who has
none of the three, cannot satisfy. The next password grant answered
`{"error":"invalid_grant","error_description":"Account is not fully set up"}` and
the container had to be replaced. **It is the same failure by a different route,
and the route nobody had been warned about.**

### 1.5 Nine validators, a tenth refusal, and a set that is not the shipped catalogue

The 400 is `{"errorMessage":"[...]"}` and the entries inside the brackets are
joined with `, `, so `{"attributes":[]}` answers about `username` **and**
`email` in one body. A validator returning on the first problem is right on
every other refusal and wrong on the one a caller clearing the profile sends.

```
[The attribute 'username' can not be removed]        username and email only;
[The attribute 'email' can not be removed]           removing firstName is a 200
[Attribute configuration already exists with 'name':'email']
[Attribute configuration without 'name' is not allowed]     absent and "" alike
[Validator 'x' defined for attribute 'y' doesn't exist]
['permissions.view' configuration for attribute 'x' contains unsupported role 'y']
['required.scopes' configuration for attribute 'x' contains unsupported scope 'y']
['selector.scopes' configuration for attribute 'x' contains unsupported scope 'y']
[Attribute 'x' references unknown group 'y']
```

**An absent `attributes` is not an empty one.** `{}` and `{"groups":[]}` are
200s; `{"attributes":[]}` is the 400 naming both undeletable names. Found by a
test failing, not by a probe.

**The validator set is the thirty registered providers and not the thirteen the
component catalogue declares.** `GET /admin/serverinfo` offers both lists and
they are seventeen names apart. All thirty were sent one at a time: twenty-six
answered 200 with an empty config, four answered about their **configuration**
rather than their existence, and only a name outside the thirty answered
`doesn't exist`. Validating against the smaller list would refuse `not-blank`,
`up-duplicate-email` and fifteen others a live 26.7.1 accepts - which is the
mistake AGENTS.md already records the authorization policy family punishing.

The tenth refusal is a per-validator configuration schema, and **exactly four of
the thirty have one**, which is a complete sweep rather than a sample:

```
length      needs min or max; with neither it reports **both** hints
pattern     needs pattern
options     needs options
multivalued needs max
```

Two spellings inside it are easy to get wrong by sharing a formatter. The inner
`ValidationError{...}` list appends `, ` after **every** entry including the
last, where the outer list is a plain join - so one bad validator ends
`messageParameters=[]}, ]` and two on one attribute leave an empty gap between
the two conventions. And the invalid-number error **echoes the offending value
for `length` and not for `multivalued`**: `{"length":{"min":"x"}}` reports
`messageParameters=[x]` and `{"multivalued":{"max":"x"}}` reports
`messageParameters=[]`. One error kind, two behaviours.

The number check is a **parse and not a JSON type test**: `{"min":"5"}` is a
200 and `{"min":"x"}` is not, and `{"min":true}` is refused.

### 1.6 A sixteenth strict decoder, and the first whose class depends on depth

`PUT /users/profile` decodes strictly and names three classes:

```
{"zz":1}                                          UPConfig    column 8
{"zz":"a"}                                        UPConfig    column 8
{"zz":null}                                       UPConfig    column 11
{"groups":[],"zz":1}                              UPConfig    column 20
{"attributes":[…],"groups":[],"zz":1}             UPConfig    column 200
{"attributes":[{"name":"username","zz":1,…}],…}   UPAttribute column 41
{"attributes":[…,{"name":"q","zz":"a",…}],…}      UPAttribute column 199
{"attributes":[…],"groups":[{"name":"g","zz":1}]} UPGroup     column 210
```

**The line and column are absolute in the whole request body in all three
cases.** A field 192 bytes into the document answered column 199 whether it was
at the top level or inside an attribute, so only the class varies with depth.
A decoder handed the sub-object would have reported the fragment's own column
and been right only on the first attribute of a document with no whitespace -
which is why `firstUnknownFieldFrom` takes an offset rather than a slice.

The counting rule itself is unchanged: it is `decodeStrict`'s, which was derived
from twelve paired measurements and needed nothing added.

### 1.7 The three email writes: four states, and only two of them exist on Gloak

Measured with the realm's `smtpServer` changed between blocks and re-read each
time, so a block answering what the block before it answered would have been a
block whose state did not move:

| realm `smtpServer` | user has an email | answer |
|---|---|---|
| any | no | `400 {"errorMessage":"User email missing"}` |
| `{}` | yes | 500 `Failed to send execute actions email: Invalid sender address 'null'. …` |
| host unreachable | yes | 500 `… Error when attempting to send the email to the server. …` |
| reachable | yes | 204, and the message arrives |

The last two rows are what a mail client buys, and **neither is reachable in
Gloak, and not because of this cut.** `internal/admin/realmrep.go` builds every
realm representation with `SMTPServer: map[string]string{}`, a literal that is
never read from storage and never written to it, so a Gloak realm's `smtpServer`
is `{}` for ever. Row three needs a stored one; row four needs that as well as a
transport and Keycloak's message templates.

So serving rows one and two is not three quarters of an operation. It is the
shape `configured-user-storage-credential-types` already has and `client-types`'
501 has: a constant that is a contract because the state behind the other branch
cannot be reached. The difference is that **this one becomes reachable the day a
cut stores `smtpServer`**, so both bodies are written down rather than left
implicit.

**They are one implementation and two measurements prove it.**
`reset-password-email` answers `execute-actions-email`'s 500 **word for word,
including the words "execute actions"**, on a route whose path says nothing
about them. `send-verify-email` answers its own constant in both failing states
and interpolates nothing.

What separates them is what they read, and the live server and the vendored
description agree - worth saying, because the two disagree about the responses,
the description giving `send-verify-email` no 404 where the server sends one:

```
                        body   client_id  redirect_uri  lifespan
execute-actions-email    yes       yes         yes        yes
reset-password-email      no       yes         yes        **no**
send-verify-email         no       yes         yes        yes
```

`reset-password-email` ignoring `lifespan` is measured on the distinguishing
request: `?lifespan=abc` is the generic `404 {"error":"HTTP 404 Not Found"}` on
the other two and a plain 500 on this one. And `execute-actions-email` is the
only one that reads a body at all, which is also the only one that answers
`text/plain` a **415**; the other two accept any body under any `Content-Type`
and ignore both.

### 1.8 The rejection order, ten deep, every adjacency decided by a request wrong in two ways

```
1  no token                    401 {"error":"HTTP 401 Unauthorized"}
2  the coarse users gate       403 to view-clients, manage-realm, impersonation, …
3  the subject                 404 {"error":"User not found"}                  - beats 4..10
4  manage-users                403 to view-users and query-users
5  the body                    400 HTTP 400 Bad Request / Cannot parse the JSON - beats 6..10
6  lifespan                    404 {"error":"HTTP 404 Not Found"}               - beats 7..10
7  the user's email            400 {"errorMessage":"User email missing"}        - beats 8..10
8  client_id                   400 {"errorMessage":"Client doesn't exist"}
   a redirect_uri, no client   400 {"errorMessage":"Client id missing"}
9  redirect_uri                400 {"errorMessage":"Invalid redirect uri."}
10 the required actions        400 {"errorMessage":"Provided invalid required actions"}
```

**Step 7 beating step 10 is the two-condition cell.** A user with no email *and*
a bogus action answers about the email; the identical bogus action on a user who
has one answers about the action. One request supplies one condition and says
nothing at all about the order.

The guard is `manage-users` alone on all three, swept one role at a time over
eight, with `guardUserSubject`'s two stages visible on every row: the roles
inside the users family still resolve the subject and answer 404 for one that
does not exist, and the roles outside it answer 403 to the same request.

`execute-actions-email`'s body decode is a **fourth** data point for the "cannot
parse the JSON is per body shape" bullet. One body, `[`, now has three answers
across three families: `unknown_error` on `POST /users`, `invalid_request` on
the ten role-array endpoints, and **`HTTP 400 Bad Request`** here. `{}` - an
object where an array is wanted - answers `unknown_error`. An empty array, a
literal `null` and no body at all all reach the send, so emptiness is not a
refusal on this route.

### 1.9 The consents pair

```
GET  .../consents                       200 []   application/json;charset=UTF-8, no-cache
GET  .../consents  unknown user         404 {"error":"User not found"}
DEL  .../consents/account               404 {"error":"Consent nor offline token not found"}
DEL  .../consents/nosuchclient          404 {"error":"Client not found"}
DEL  .../consents/<a uuid>              404 {"error":"Client not found"}
DEL  .../consents/account unknown user  404 {"error":"User not found"}
```

**The client is resolved before the consent**, so a client that does not exist
and a client with no consent are two different 404s one lookup apart, and the
`{client}` segment is a clientId rather than a uuid. Guards, one role at a time:
the read takes `view-users` or `manage-users`, the delete takes `manage-users`
alone, `query-users` opens neither and still gets `User not found` for a subject
that does not exist.

Neither is served. See §3.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds them in.

- **`GET /users/profile/metadata` is a derivation and it took a third profile to
  prove it.** Master's metadata and a created realm's are byte-identical - 1196
  bytes both - although their profiles differ by three `required` blocks, and
  `internal/admin` recorded on that basis that "nothing reachable distinguishes
  the derivation from a constant". A profile written through
  `PUT /components/{id}` moves it: `length:{min:4,max:60}` on `username` and a
  fifth attribute answered 1278 bytes carrying both. The sentence was true of
  the two profiles a default install has and false of the endpoint, which is the
  failure mode this file records for its own bullets and meets here in a doc
  comment.

- **`username` is always `required` in the metadata and nothing else is by
  default.** A profile marking `username` required for the `user` role alone
  still renders `"required":true`; the identical block on `email` renders false.
  For every other attribute the rule needs **both** halves - the `required`
  block's `roles` must be empty or name `admin`, **and** its `scopes` must be
  empty - and it took seven requests, because `{}` and `{"roles":[]}` are both
  true while `{"scopes":["profile"]}`, which also has no roles, is false.
  "Roles empty means everybody" is the obvious reading and it is wrong on that
  last row.

- **A metadata attribute's two maps are built by two different Java
  constructors, one nesting level apart.** The `validators` object is
  `javamap.KeyOrder` and a validator's own config is
  `javamap.SizedKeyOrder(len(stored), …)` - the protocol mappers' rule, sized on
  what the profile stored rather than on what is served. The one measured key
  set that separates the two spellings, `{min, max}` growing by
  `ignore.empty.value`, is in **master's own metadata**, so this is not a corner
  somebody had to invent. That is the third family after an identity provider's
  config against a component's.

- **The `multivalued` validator is synthesised only for a single-valued
  attribute, and its bound is a string.** `"multivalued":{"max":"1"}`, where a
  declared `length`'s `max` is a number, and it is the one validator that does
  **not** gain `"ignore.empty.value":true`. A multivalued attribute carrying one
  validator answers one validator and one carrying none answers
  `"validators":{}` - which is what says the synthesis is conditional rather
  than the bound being different.

- **`GET /users/profile` re-buckets an attribute's `annotations` and the cell
  that was left open is now measured.** `internal/admin` records it as open
  because "one measured pair cannot tell sorting from a Java map"; nine key sets
  say it is a Java map, read back through `PUT /components/{id}`, which is the
  only writer that stores what it is handed and therefore the only one that can
  separate the read's canonicalisation from the write's. **The first six left
  two models standing and three more were computed in Go because the two models
  disagree on them**; all three went the same way. What fits all nine is one
  Java table asked for the entry count, walked in insertion order - a third
  shape after `KeyOrder` and `SizedKeyOrder`. Gloak still passes the bytes
  through and is measured wrong on three of the nine; nothing in the tree moves,
  because no profile a default install ships carries an annotation.

- **`PUT /users/profile` breaks every login in a realm two different ways, and
  the second is not the one anybody is warned about.** `{}` leaves a profile
  with no `username` attribute, which is the documented hazard. A **bodyless**
  `PUT` deletes the `declarative-user-profile` row outright, and the realm then
  falls back to the built-in default - which marks `email`, `firstName` and
  `lastName` required for the `user` role. On master that is fatal: the
  bootstrap `admin` has none of the three, and the next password grant answers
  `Account is not fully set up`. A cut that carefully keeps `{}` off master and
  sends a bodyless `PUT` there loses the container anyway. Measured, and it cost
  one.

- **An absent `attributes` is not an empty one on `PUT /users/profile`.** `{}`
  and `{"groups":[]}` are 200s that store a document with no attributes;
  `{"attributes":[]}` is a 400 naming **both** `username` and `email`. The two
  undeletable names are the only two - dropping `firstName` is a 200 - and the
  refusals arrive as a comma-joined list inside one pair of brackets, so a
  validator that returns on the first problem is right on every other body this
  endpoint refuses and wrong on the one a caller clearing the profile sends.

- **The user profile's validator set is the thirty registered providers, not the
  thirteen `GET /admin/serverinfo` declares as component types.** The two lists
  are seventeen names apart and the endpoint accepts the larger: `not-blank`,
  `up-duplicate-email` and fifteen more are refused by the smaller and answered
  200 by the server. All thirty were sent one at a time, which is what says only
  a name outside them earns `doesn't exist`. This is the authorization policy
  family's trap met a second time - validating against the catalogue this
  repository already ships would refuse working values.

- **Exactly four validators require configuration, and two spellings inside that
  refusal punish a shared formatter.** `length` needs `min` or `max` and reports
  **both** hints when it has neither; `pattern`, `options` and `multivalued`
  need one key each. The `ValidationError{...}` list appends `, ` after **every**
  entry including the last, where the outer refusal list is a plain join, so two
  bad validators on one attribute leave an empty gap between the two
  conventions. And the invalid-number error **echoes the offending value for
  `length` and not for `multivalued`** - `messageParameters=[x]` against
  `messageParameters=[]`, one error kind and two behaviours. The number check is
  a parse rather than a type test: `"5"` is accepted and `true` is not.

- **The strict decoder on `PUT /users/profile` names three classes and the
  position is absolute in all three.** `UPConfig` at the top, `UPAttribute`
  inside an element of `attributes`, `UPGroup` inside `groups` - and a field 192
  bytes into the document answers column 199 wherever it sits, so only the class
  varies with depth. It is the sixteenth strict decoder in this API and the
  first whose class is decided by nesting rather than by the endpoint.

- **`PUT /users/profile`'s 200 is `application/json` with no charset**, which
  makes it the third Admin API 2xx body outside the charset rule after
  `POST /groups/{id}/children`'s 201 and `POST /partial-export`. The read on the
  identical path carries the charset. Three writers on two routes of one path.

- **The three email writes read three different request shapes, and only one of
  them reads a body.** `execute-actions-email` takes an array of required action
  aliases and answers `text/plain` a 415; `reset-password-email` and
  `send-verify-email` accept any body under any `Content-Type` and ignore both.
  `lifespan` splits them the other way: the first and the third parse it -
  `?lifespan=abc` is the generic 404 - and **`reset-password-email` does not
  read it at all**, which the vendored description agrees with by not declaring
  it. One parameter, three neighbouring routes, two answers.

- **`reset-password-email` answers `execute-actions-email`'s failure word for
  word, "execute actions" included**, on a route whose path says nothing about
  them; `send-verify-email` answers its own constant in both failing states.
  That is what says two of the three share an implementation and the third does
  not, and it is the reason two goldens that look like duplicates are not.

- **The email writes answer about the user before they answer about the mail,
  and the order is ten deep.** A user with no email is
  `400 {"errorMessage":"User email missing"}` whatever else is wrong with the
  request - including a bogus required action, which is checked **last**. Above
  the email sit the subject, the role, the body and `lifespan`; below it sit
  `client_id`, `redirect_uri` and the actions. Every adjacency was decided by a
  request wrong in two ways, because a request wrong in one way cannot say which
  check ran first.

- **`execute-actions-email` is a fourth answer to `[`.** The truncated array
  that answers `unknown_error` on `POST /users` and `invalid_request` on the ten
  role-array endpoints answers **`HTTP 400 Bad Request`** here, and `{}` - an
  object where an array is wanted - answers `unknown_error`. The code follows
  the body's shape rather than the endpoint, and this is the third family it has
  been measured on.

- **`DELETE /users/{id}/consents/{client}` resolves the client before the
  consent**, so a `{client}` naming nothing is `404 {"error":"Client not found"}`
  and a real client with no consent is
  `404 {"error":"Consent nor offline token not found"}` - two 404s one lookup
  apart on one route. The segment is a **clientId**, so a uuid takes the first
  branch. `scattered-remainder.md` already contributed the second spelling to
  the not-found list; `Client not found` was already on it.

- **A master caller measured against another realm answers 403 in every cell,
  and that looks exactly like a guard.** A guard sweep for
  `PUT /users/profile` was run that way and read 403 for `manage-realm`,
  `view-realm` and everything else - a probe measuring the realm boundary rather
  than the route, with no cell that could have differed. AGENTS.md already
  records that a caller's rights reach exactly one container; what is worth
  adding is that a role sweep run across a realm boundary is a probe whose
  output cannot change, which is this file's own definition of one measuring
  itself.

## 3. Follow-up dispositions

**F148 - the settled boundary, applied twice more and re-litigated not at all.**
`POST /users/{id}/impersonation` is already in the catalogue as `Pending` with
that reason and with the 2026-09-05 measurement above it, including that it ends
the calling administrator's own session. **This cut changes nothing about it.**
Re-deciding a boundary that has been settled twice and applied twice is how a
closed question reopens, and the brief asked which side was taken rather than
for a new argument.

What this cut adds is F148's shape at a **finer granularity than an operation**:
`PUT /users/{id}/execute-actions-email`'s `Invalid redirect uri.` branch needs
`matchRedirectURI` from `internal/oidc/authorize.go`, which is unexported and in
a package this branch may not touch. AGENTS.md records that comparison at length
- nothing normalised, a wildcard that is not a bare prefix, the query and
fragment cut in one branch only - and records that this project got it wrong
once already. A second copy of a rule with eight recorded corner cases is a
second copy that will diverge. So the **operation is served and that one branch
is not**, and it is a `Recorded` case
(`admin/users/execute-actions-email-bad-redirect`) rather than a silence: the
verifier requires a `Recorded` golden **not** to match, so the day the
comparison moves somewhere both packages can reach, the suite fails with
"already matches" and names the case to promote. That is the first time F148 has
been applied to an error branch rather than to a whole operation, and it is
worth a line in the entry.

**F154 - `briefRepresentation` on the user listing, and which attributes depend
on the realm's profile. Not closed, and this cut removes the last obstacle.**
F154 says "no golden can reach it: the user profile would have to be edited
first, and that is a chapter this project does not serve".
`scattered-remainder.md` narrowed that to "the write is deliberately not served,
so a fixture still cannot edit the profile through the API".

**Both halves are now false.** `PUT /users/profile` is served, and a conformance
fixture can set a realm's user profile with one request. What F154 wants is a
fixture that writes a profile declaring an unmanaged attribute policy and a
custom attribute, creates a user carrying it, and reads `GET /users` with and
without `briefRepresentation` - and every step of that is a served operation as
of this cut. It is filed rather than done here because it belongs to the user
listing's chapter and because the shape it would pin is a claim about
`userRepresentation`, not about the profile.

The one caution for whoever takes it: **do the write in a realm the fixture
creates.** §1.4 records what a profile write does to master, twice over.

**F157 - `attack-detection` stores nothing. Untouched and unaffected**, and
named here because its shape is the one §1.7 leans on and the difference matters.
F157's reads answer the zero record because **nothing in this project counts a
failed authentication**, so the whole reachable state is the empty case and a
table nobody writes would be a claim about the model that is not true. The three
email writes are the same argument with the same conclusion: `smtpServer` is a
literal empty map in `realmrep.go`, so the two states beyond the 500 are
unreachable and no mail client would make them reachable on its own.

Where they differ is that F157's cell closes when the login path counts
failures - a change inside this project - while the email writes' cell closes
when a cut **stores** `smtpServer`, which is a realm-settings change and is
filed with both measured bodies so that cut does not have to re-measure them.

**F110 - consent grants are in memory, and this cut is the second that could
have half-closed it and should not.** `scattered-remainder.md` left the pair
against this entry and the argument is unchanged and re-checked:
`internal/oidc/authsession.go`'s `consentStore` is a `map[string]bool` and
`internal/oidc/consent.go` calls `grant(...)` on every approval, so a Gloak user
really can hold a consent. An `internal/admin` handler answering `[]` would pin
"this user has never consented" as a contract while the package next door
remembers that they have.

**That is what separates it from F157 and from
`configured-user-storage-credential-types`**, and the separation is the whole
disposition: those two answer the empty case because nothing writes the state.
Here something does, in a package this branch may not touch. Both endpoints go
in as `Pending` with §1.9's measurements written where the next reader is
looking, including the two 404s and the lookup order between them.

**F95 - a client's `attributes` is serialised from a Go map. Not closed and not
touched.** Named because the metadata endpoint adds a **third** family with the
same problem and solves it the same way: `upValidators` and a validator's config
are ordered slices with a `MarshalJSON`, because a Go map would sort them. When
F95's move to `model.StringMap` lands it should take these with it and keep the
constructor split - the outer map is `KeyOrder` and the inner one is
`SizedKeyOrder`, and a shared ordered-map type that hard-codes either is wrong
on one of them. That is the same caution `registeredNodes` earned.

**F158 - the component validators refuse deeper than this project can reach.**
Half-closed in one place and reinforced in another. The four validator
configuration schemas `PUT /users/profile` needs are **completely swept** - all
thirty validators sent an empty config, and the four that objected measured for
both their error kinds - so that surface is reproduced rather than approximated.
What remains open is F158's own subject: the component route's deeper validators
still want a keystore, a PEM or an LDAP server, and nothing here changes that.

**A new follow-up: `smtpServer` is a literal.** `realmrep.go` answers
`"smtpServer":{}` from `map[string]string{}` and nothing reads or writes it.
Two consequences worth one entry: `POST /testSMTPConnection` and the three email
writes are all stuck on the branch a `{}` produces, and the two measured 500
bodies plus the 204 are recorded in §1.7 for the cut that stores it.

**A new follow-up: `annotations` needs a third `javamap` constructor.** §1.3 has
the nine vectors and the model that fits them. It cannot be added from here.

## 4. The mutation pass, and the two survivors

Twenty-six mutations, a different one per claim, each reverted and each revert
checked against the file's bytes and against `git status`. The harness refuses
to run on a dirty tree, refuses a mutation that changes no byte, refuses one
that does not compile, and **reads `go test`'s exit code before it looks at the
log**. A control known **not** to differ - a comment-only edit - ran first in
each of the three rounds and survived all three, so the harness was never
reporting `killed` for everything.

| # | mutation | test | result |
|---|---|---|---|
| 0 | a comment only | any | SURVIVED, as required, three times |
| 1 | the metadata is a constant | `TestTheMetadataIsDerivedAndNotAConstant` | killed |
| 2 | `username` is not special-cased | `TestMetadataRequiredIsUsernameAlwaysAndAdminOtherwise` | killed |
| 3 | `readOnly` follows `view` | `TestMetadataReadOnlyAndVisibilityFollowThePermissions` | killed |
| 4 | the `multivalued` validator is unconditional | `TestTheMultivaluedValidatorIsSynthesisedForSingleValuedAttributesOnly` | killed |
| 5 | a config is sized on what is served | `TestMetadataValidatorKeyOrderIsTwoJavaMaps` | killed |
| 6 | the validators object is the sized constructor | `TestTheMetadataIsByteExactOnMaster` | killed |
| 7 | the metadata read reuses `userReadRoles` | `TestTheMetadataTakesTheSameFiveRolesAsTheProfileRead` | killed |
| 8 | the write stores the request | `TestThePutUserProfileRoundTripsWithTheReadAndTheStore` | killed |
| 9 | the write answers with the charset | `TestThePutUserProfileSendsNoCharsetAndTheReadDoes` | killed |
| 10 | a bodyless write leaves the row | `TestAProfilePutWithNoBodyDeletesTheRow` | killed |
| 11 | an absent `attributes` is an empty one | `TestAProfilePutWithAnEmptyObjectIsNotTheReset` | killed |
| 12 | `firstName` joins the undeletable set | `TestThePutUserProfileValidators` | killed |
| 13 | the validator set loses `not-blank` | `TestTheValidatorSetIsTheThirtyProvidersAndNotTheCatalogue` | killed |
| 14 | `length` reports one hint, not both | `TestFourValidatorsRequireConfiguration` | killed |
| 15 | the strict decoder reports the fragment's column | `TestTheProfileStrictDecoderNamesThreeClasses` | killed |
| 16 | the profile write takes the read's five | `TestThePutUserProfileGuardIsManageRealmAlone` | killed |
| 17 | the email check runs after the client | `TestTheEmailRejectionOrder` | killed |
| 18 | `reset-password-email` answers the verify sentence | `TestResetPasswordEmailAnswersExecuteActionsEmailsSentence` | killed |
| 19 | every email route declares a JSON `@Consumes` | `TestOnlyExecuteActionsEmailReadsABody` | killed |
| 20 | `reset-password-email` reads `lifespan` | `TestResetPasswordEmailIgnoresLifespanAndItsNeighboursDoNot` | killed |
| 21 | the email writes take the read pair | `TestTheEmailWritesTakeManageUsersAlone` | killed |
| 22 | `[` answers the object's code | `TestExecuteActionsEmailBodyShapes` | killed |
| 23 | the required actions are never checked | `TestTheEmailRejectionOrder` | killed |
| 24 | an attribute loses its `group` | `TestMetadataCarriesTheGroupAndDropsTheSelector` | **survived**, then killed |
| 25 | `selector` goes into the annotations slot | `TestMetadataCarriesAnnotations` | **survived**, then killed |
| 26 | the metadata drops `annotations` | `TestMetadataCarriesAnnotations` | killed |

**Both survivors are the same shape and neither is an unmeasured cell.** `group`
and `annotations` were both measured on a live 26.7.1 - an attribute in a group
comes back with `"group":"user-metadata"`, and one carrying
`{"inputType":"text"}` comes back with it - and neither had been written into a
test. Nothing could catch them: **no realm a default install has puts an
attribute in a group or gives one an annotation**, so the committed metadata
goldens cannot see either field, and none of the earlier tests sent an
attribute that carried one.

That is the difference AGENTS.md asks to be stated. A survivor whose cell is
unmeasured is an unasked question and should be left alive; these two were
measurements somebody had taken and nobody had written down, so the fix is the
assertion. `TestMetadataCarriesTheGroupAndDropsTheSelector` and
`TestMetadataCarriesAnnotations` exist because of these two mutations and say so
in their own doc comments.

Two things about the pass itself are worth recording, because both are the
harness measuring itself rather than the code:

- **Mutation 13 was never applied** on the first run: its anchor had been
  reflowed by `gofmt` after it was written, so the harness reported
  `NOT-APPLIED` rather than a verdict. A harness that had silently skipped it
  would have reported twenty-six killed and one of them would have been a lie.
  Counting `NOT-APPLIED` as its own outcome is what caught it.
- **Mutation 18 was written badly** - `_ = verifyEmailFailure` changes no
  behaviour - and survived because it was not a mutation. The harness's
  no-byte-changed check does not catch that one, because bytes did change; only
  reading the mutation caught it. It was replaced with one that really swaps the
  two sentences and that one is killed.

Two cells are **left unmeasured on purpose** and no mutation was written for
either, because killing one would turn a question into a contract:

- the `annotations` key **order** - §1.3 has nine vectors and a model that fits
  them, and the model needs a constructor `internal/javamap` does not export and
  this branch may not add;
- the six-validator key set the outer map places wrong - it is a bucket
  collision chaining in insertion order, which `javamap` says it cannot resolve,
  and no default realm reaches it. `TestTheSixValidatorKeySetIsTheKnownMiss`
  records which way round Gloak comes out so a later fix shows in a diff.

## 5. Parity, before and after

| chapter | before | after |
|---|---|---|
| `admin/users` | 26 / 34 | 31 / 34 |
| total | 512 / 541 | 517 / 541 |

Measured with `cmd/parity`. The branch was cut at `087053c`, where it read
**498 → 503**; `main` moved to `74db295` while it was open and brought the
`Workflows` tag with it, so the rebased branch reads **512 → 517**. The
per-chapter row is the same either way: no operation is claimed by both cuts,
and the increment is +5 against both bases.

**The rebase was checked rather than trusted.** Every line this branch adds was
compared before and after: twenty-one of the twenty-three files are byte-
identical, and the two both cuts appended to - `catalog_admin.go` and
`fixture.go` - keep every one of this branch's lines with main's additions as
the only difference. The conflict in those two was three appends at the same
three places and was resolved by taking main's file whole and re-applying this
branch's block from `git show` rather than from the conflict markers, which is
what made the check possible.

**One recorder artefact, not committed.** `make record` on this branch produced
a diff to `admin/clients/evaluate-scope-mappings-not-granted.http` that gained
sixteen `gloak-probe-*` realm roles other fixtures create. Nothing in this cut
creates a realm role, so the shift is in the recorder rather than in the
catalogue: that case reads a realm-wide listing and is not `PristineRealm`, so
what it holds depends on how much state the shared container has when it runs.
It was reverted and the verifier then passed against the committed bytes.
`scattered-remainder.md` reported the identical artefact on the identical case
and filed it; **this is the second cut to meet it**, which is the argument for
marking that case `PristineRealm` rather than for filing it a third time.

Five operations of the eight. **The three left are the consents pair and the
impersonation**, and none of them is left for want of effort: each names a
package this branch may not touch, two of them the same one, and each has its
measurements in the catalogue beside a `Pending` case so the cut that owns both
packages starts from data rather than from a probe.

What was taken:

```
GET  /users/profile/metadata                   a derivation, two Java maps
PUT  /users/profile                            nine validators, four body shapes,
                                               a strict decoder naming three classes
PUT  /users/{id}/execute-actions-email         the refusals; the ten-step order
PUT  /users/{id}/reset-password-email          the refusals
PUT  /users/{id}/send-verify-email             the refusals
```

What was left, and why in one line each:

```
GET    /users/{id}/consents             F110 - internal/oidc records the grant
DELETE /users/{id}/consents/{client}    F110 - the same row
POST   /users/{id}/impersonation        F148 - already refused, not re-litigated
```

And one **error branch** left inside an operation that was taken:
`execute-actions-email`'s `Invalid redirect uri.`, refused on F148's argument
and carrying a `Recorded` case so the refusal has an alarm on it rather than a
paragraph.
