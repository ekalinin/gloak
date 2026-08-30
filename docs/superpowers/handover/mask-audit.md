# Mask audit: every place the conformance suite has stopped comparing something

Date: 2026-08-30
Branch: `fix/mask-audit`
Follow-ups touched: **F39, F46, F47, F53, F59, F90, F95** - none closed, four
confirmed, one corrected.

Every observable value below came from a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8113, started twice and
removed by this branch alone. `kc-auth` and `kc-browser` were not touched. The
goldens came from a whole `make record` after each change, three runs in all.

This branch does not touch `AGENTS.md`, `README.md`, the parity roadmap, the
observed spec or the follow-ups list, so what is owed to them is written out
here.

---

## 1. Measurements

### 1.1 The catalogue holds 409 masks, not 235

The count in the brief is a stale snapshot. Measured by parsing the three
catalogue files:

| mask | brief | measured before | after this branch |
|---|---|---|---|
| `Volatile` | 132 | 295 | 219 |
| `Unordered` | 76 | 84 | 44 |
| `VolatileHeaders` | 10 | 14 | 14 |
| `UnorderedKeys` | 8 | 7 | 7 |
| `UnorderedWords` | 5 | 5 | 5 |
| `VolatileTailHeaders` | 4 | 4 | 4 |
| **total** | **235** | **409** | **293** |

`UnorderedKeys` is 7 rather than the brief's 8 because F90 had already removed
the eighth. The rest of the gap is growth: a `Volatile` declaration carries
several paths, and counting declarations rather than paths gives 132 - which is
almost certainly where 235 came from. **A mask is a path, not a field**, because
a path is the unit that can be inert on its own, and half of this sweep's
findings are one path inside a two-path declaration.

### 1.2 116 of the 409 were doing less than they claimed

| verdict | count |
|---|---|
| kept: measured varying per response | 176 |
| **over-wide, narrowed**: the value was already `{{captured}}` | 66 |
| not evaluable: the case is `Pending` and has no golden | 41 |
| **inert, removed**: `Unordered` over an array of 0 or 1 | 40 |
| kept: `Unordered` over an array of 2 to 21 | 44 |
| **inert, removed**: the path addresses nothing in the body | 10 |
| kept: `Set-Cookie`, every value minted per request | 9 |
| kept: `UnorderedKeys` over an object of 2 to 8 keys (F90/F95) | 7 |
| kept: `UnorderedWords` over 2 to 7 words | 5 |
| kept: `VolatileTailHeaders`, masking the minted tail only (F46) | 4 |
| **over-wide, reported**: whole `Location` masked (F39, `oidc/`) | 4 |
| **inert, reported**: `id_token` on two grants that return none (`oidc/`) | 2 |
| **over-wide, reported**: `session_state` (`oidc/`) | 1 |

The full per-mask table is section 5.

### 1.3 Removing an inert mask moved zero goldens, which is the proof

Three whole `make record` runs, each 433 goldens rewritten:

| run | goldens rewritten | goldens moved |
|---|---|---|
| clean checkout of `main` | 433 | **0** |
| after 50 inert masks removed | 433 | **0** |
| after 66 over-wide masks narrowed | 433 | **54** |

The second row is the measurement, not a formality. `sortArray` re-emits the
array it sorted, so "sorting is the identity" had to be true of the *bytes* and
not only of the ordering, and a run that rewrites 433 files and moves none says
it is. The 54 in the third row are exactly the 54 cases edited, and every one of
the 54 diffs is one `"{{string}}"` becoming the placeholder that names the
object.

The brief says a clean checkout rewrites 380. It rewrites 433 today.

### 1.4 Two container starts: every surviving `Volatile` really does vary

The masks a golden cannot be asked about are the `Volatile` ones - `Normalize`
has replaced the value before the file is written. So the question "is this
value the same on every recording?" was put to the server instead: one
container, seven bootstrap endpoints, then the container destroyed, started
again from the same image, and the same seven endpoints fetched.

All nineteen masked paths reachable this way **vary**:

| endpoint | masked paths | verdict |
|---|---|---|
| `GET /admin/realms/master/keys` | `keys/*/kid`, `providerId`, `validTo`, `publicKey`, `certificate`, `active/*` | all vary |
| `GET /realms/master` | `public_key` | varies |
| `GET /realms/master/protocol/openid-connect/certs` | `keys/*/kid`, `n`, `x5c`, `x5t`, `x5t#S256` | all vary |
| `GET /admin/realms/master/roles` | `*/id`, `*/containerId` | vary |
| `GET /admin/realms/master/clients` | `*/id` | varies |
| `GET /admin/realms/master/client-scopes` | `*/id`, `*/protocolMappers/*/id` | vary (15 and 35 of them) |
| `GET /admin/realms/master` | `defaultRole/id`, `defaultRole/containerId` | vary |

So there is **no** third class of inert `Volatile` - a mask over a value that is
the same on every recording - among the ones a bootstrapped realm can show. The
inert `Volatile` masks this sweep found are all of the other kind: paths that
address nothing at all.

### 1.5 Two container starts, and the order of four listings

| listing | order across two starts |
|---|---|
| `GET /admin/realms/master/roles` | **varies** - `admin, offline_access, uma_authorization, default-roles-master, create-realm` then `uma_authorization, offline_access, admin, create-realm, default-roles-master` |
| `GET /admin/realms/master/client-scopes` | **varies**, all fifteen |
| `GET /admin/realms/master/keys` | **varies** by algorithm, `RSA-OAEP, RS256, AES, HS512` then `RS256, AES, HS512, RSA-OAEP` |
| `GET /admin/realms/master/clients` | **same** both times, alphabetical by `clientId` |

The first three earn their `Unordered`. The fourth has none to earn, which is
consistent: `admin/clients/list` masks only the two client-scope arrays inside
each row, never the row order.

### 1.6 A client's `defaultClientScopes` came back identical twice, and the mask stays

Measured on all six bootstrapped clients, on both starts:

- `defaultClientScopes`: `web-origins, acr, profile, roles, basic, email` -
  **identical on both starts, on all six clients**.
- `optionalClientScopes`: `address, phone, offline_access, organization,
  microprofile-jwt` then `address, phone, organization, offline_access,
  microprofile-jwt` - **varies**.

**The mask on `defaultClientScopes` stays, and the reason is the whole
methodology of this sweep.** AGENTS.md already records the opposite
measurement - "a client's two lists swapped `roles` and `profile` between two
clients created minutes apart in one container" - and `roles` and `profile` are
both in `defaultClientScopes`. Two starts agreeing is not evidence of stability;
it is the absence of evidence of instability, and a prior measurement of
instability beats it outright.

This is why **not one mask on this branch was removed because two recordings
agreed.** The 40 `Unordered` removals rest on arithmetic - sorting a list of one
element cannot produce different bytes - and the 66 narrowings rest on the
harness's own `ReplaceCaptured` pass having already fixed the value. Neither is
an observation that something looked the same twice.

### 1.7 A realm's `attributes` key order is identical across starts

`cibaBackchannelTokenDeliveryMode, cibaExpiresIn, cibaAuthRequestedUserHint,
parRequestUriLifespan, cibaInterval, realmReusableOtpCode`, byte for byte on
both starts. That confirms F90's model rather than contradicting it: the order
is Java hash order, **deterministic for a given key set** and not a function of
anything Keycloak decided. The `UnorderedKeys` retreat there is about Go sorting
map keys, not about Keycloak varying, and the two are easy to confuse.

### 1.8 The mutation that survived

`internal/admin/groups.go`, `groupRepresentationOf`: `ParentID: g.ParentID`
changed to `ParentID: g.ID`, so every child reports itself as its own parent.

- Against `main`: `TestConformance/admin/groups/children-list` **passes**. Both
  `*/id` and `*/parentId` were masked, so both sides read `"{{string}}"` and the
  swap was invisible.
- Against this branch: it **fails**, and the diff names the field.

That is one mutation of one field. The same shape covered eleven `containerId`s,
every role-mapping listing, every group read and every scope-mapping listing, so
the mutation that survived is a family rather than an instance.

### 1.9 `admin/groups/count` is not masked any more, and two comments say it is

`Case.PristineRealm`'s doc comment and AGENTS.md's `make record` bullet both say
"that case's number is masked to this day". F47 took the mask off; the golden
holds `{"count":2}`. The copy in `case.go` is fixed on this branch. The copy in
AGENTS.md is section 2.4.

---

## 2. Entries for AGENTS.md

### 2.1 For "Things that look like bugs and are not", beside the `attributes` bullet

- **A mask is a path, and a mask that changes nothing is worse than none.** The
  catalogue holds 293 of them across six fields, and 116 were removed on
  2026-08-30 because they changed no byte of any golden. Forty `Unordered`
  entries sat on arrays of one element or none, where sorting is the identity;
  ten `Volatile` entries named rows an empty listing does not have; and
  sixty-six masked a value `ReplaceCaptured` had already turned into
  `{{group_id}}` or `{{client_uuid}}`. All three read as "this varies", which is
  a claim about Keycloak the next person believes and will not go behind.
  `TestNoMaskIsInertOnItsGolden` and `TestNoVolatileMaskCoversACapturedValue`
  are what stop the next one, and both are ratchets: they fail on the catalogue
  as it stands, not only on what a diff changed.
- **The paged role listings masked an order that the case beside them
  asserts.** `admin/roles/list-realm-page-first`, `-page-empty` and
  `-page-past-end` all declared `Unordered`, while
  `admin/roles/list-realm-page-no-search` deliberately does not, with a comment
  saying the paged path was measured sorted and stable. All three masks were
  inert - their windows are one row or none - so the contradiction had no effect
  and no way of being noticed.

### 2.2 For "Things that look like bugs and are not", beside the create `Location` bullet

- **F46's question has a second half in the body, and it was answered the same
  way.** Masking a whole `Location` asserted its presence and nothing else;
  masking a whole body value asserted its type and nothing else. By the time
  `Normalize` runs, `ReplaceCaptured` has already rewritten every id a fixture
  step captured, so sixty-six masks were replacing `{{group_id}}` - stable,
  identical on both sides, and a statement about *which object this is* - with
  `{{string}}`. `admin/groups/children-list` masked `*/id` and `*/parentId`
  alike, and a handler answering with the child's own id in `parentId` compared
  equal to one answering with the parent's; it was measured doing so. A path
  only **partly** captured keeps its mask, and nine do: the realm's own id sits
  in a `containerId` beside a client's and nothing captures it.

### 2.3 For "Things that look like bugs and are not", beside the client-scope order bullet

- **A client's `defaultClientScopes` can come back in the same order twice and
  still be unordered.** Measured identical on both of two container starts, on
  all six bootstrapped clients, while `optionalClientScopes` swapped
  `offline_access` and `organization` between the same two. The existing
  measurement - the two lists swapping `roles` and `profile` between two clients
  minutes apart - is the one that decides it. Two recordings agreeing is the
  absence of evidence of instability and never evidence of stability, and no
  mask in this repository may be removed on that basis. The masks that were
  removed rest on arithmetic instead.

### 2.4 For "Build and test", correcting the `make record` bullet

The bullet on recording pristine cases first says `admin/groups/count`'s "number
is masked to this day because the recorder said 3 where a pristine replay says
2". **The mask came off with F47** and the golden holds `{"count":2}`. The
example is worth keeping; it wants "was masked for it" and a note that the
container regime is what let the number come back.

### 2.5 For "Build and test", on what `make record` costs now

A clean run rewrites **433** goldens and takes about five and a half minutes on
this machine, not the 380 the working notes say. The number is a count of
`Implemented` and `Recorded` cases with a fixture, so it grows with the
catalogue and any figure written down goes stale; what does not is that **a
clean run moves none of them.**

---

## 3. Follow-up dispositions, and what this sweep opens

### 3.1 Confirmed, not reopened

**F46** is closed and stays closed. This sweep is its body-side sibling rather
than a reopening: the header mechanism it built is correct, all four
`VolatileTailHeaders` are live, and no case declares one it does not assert
(`TestCatalogIsWellFormed` already refuses that).

**F59**'s depth-grouped walk is what the new guards resolve paths with, through
a new `MaskedValues`. Writing a second path resolver in the test file was the
obvious way and is the way it must not be done: two resolvers drift, and the one
that drifts is the one nobody runs against a real golden.

**F90** is confirmed by measurement, in the direction it claims. A realm's
`attributes` key order was identical across two container starts, so the
retreat there is about Go sorting map keys and not about Keycloak varying. All
seven surviving `UnorderedKeys` masks cover objects of 2, 2, 2, 2, 4, 6 and 8
keys; none is inert, and the guard now says so on every run.

**F95** is untouched. The five `admin/clients/*` masks stay until
`model.StringMap` lands.

**F53** is the entry this sweep is measured against, and the answer is different
in kind. F53 could not be mechanised because a case that is order-dependent and
currently clean leaves no trace in the bytes. An inert mask does leave one - the
array it sorts has one element, in the committed file - so the ratchet that was
impossible there is possible here.

### 3.2 Reported, in files this branch may not edit

Three findings in `catalog_oidc_pending.go`, all declared in the guards'
exception lists so they fail the day they are fixed rather than being forgotten:

| case | mask | finding |
|---|---|---|
| `oidc/token/password-grant-admin-cli` | `Volatile: id_token` | **inert.** The golden's `scope` is `email profile`, with no `openid`, so the grant returns no `id_token` and the path addresses nothing. |
| `oidc/token/refresh-token-grant` | `Volatile: id_token` | **inert**, same absence on the refresh of the same session. |
| `oidc/token/authorization-code-grant` | `Volatile: session_state` | **over-wide.** The value is already `{{session_state}}`, captured from the authorization redirect. Masking it drops the assertion that the token belongs to the session that authorised it. |

Two more are in `Pending` cases, so no golden shows them and the guards cannot
reach them. Both are F46's shape in a body:

- `oidc/registration/*` (four cases) mask `registration_client_uri` whole. It is
  `{{issuer}}/realms/master/clients-registrations/openid-connect/<client id>`,
  and the client id is masked separately in the same body as `client_id`. So the
  scheme, the host and the path saying which registration endpoint minted it are
  all unasserted, for a tail that is asserted a key away.
- `oidc/device/authorization-request` masks `verification_uri_complete` whole:
  measured `{{issuer}}/realms/master/device?user_code=UOHG-OJZA`, where
  `user_code` is masked separately in the same body. Same shape.

Neither has been measured against a live 26.7.1 by this branch, because both
cases are unbuilt and there was nothing to compare. They are pattern matches on
the shape, and the stream that promotes them should measure them.

**F39 is confirmed at exactly four cases** and not one more:
`oidc/authorization/code-flow-redirect`, `pkce-s256`, `pkce-plain` and
`response-mode-fragment` mask `Location` whole. `response-mode-form-post` has no
golden. The other ten `VolatileHeaders` entries are all `Set-Cookie`, every
value of which is minted per request; those are correct. F39's fix is not
`VolatileTailHeaders`: what varies in an authorization redirect is query
parameters, not a path tail, so the mechanism would be a query-aware mask and
not a reuse.

### 3.3 What this sweep opens

**A `Volatile` masking a stable *prefix* is still unmechanised.** The guards
catch a mask that addresses nothing and a mask over a value the harness has
already pinned. They do not catch a mask over a string that is half constant -
the two `oidc/` bodies above, and any future URL, template or composite value.
The golden cannot answer it, because the value is gone by the time the file is
written, and the served side cannot either, because a stable prefix and a stable
whole look the same to a single response. What would answer it is **two
recordings of the same case from two container starts, diffed per masked
value**: a value whose recordings share a prefix is a mask that could be
narrower. That is one more `make record` per audit, and it is a real design, not
a shrug - it is left undone because it needs a second recording regime and this
cut had three record runs in it already.

**Nothing checks that a mask is declared at the narrowest path that works.**
`Volatile: ["a"]` and `Volatile: ["a/b"]` are both legal when only `a/b` varies,
and the first is the one-level-down version of F46 that this sweep expected to
find. It found **none**: no `Volatile` in the catalogue resolves to an object,
and exactly one resolves to an array (`oidc/certs/master`'s `keys/*/x5c`, an
array of one certificate that regenerates per container start). So the defect
does not exist today and there is nothing to fix - but nothing would stop it
either, and the check is the same two-recording diff above.

---

## 4. Parity, before and after

**Unchanged, and measured rather than assumed.** `make conformance` on `main`'s
`catalog_admin.go` and on this branch's:

```
total: 263 of 516 enumerated behaviours served; 4 chapters not enumerated
```

identical on both. The diff against `main` touches no `ID`, `Status`,
`Operation`, `Fixture` or `PristineRealm` line - checked mechanically, the count
is zero - and `coverage_test.go` reads none of the mask fields, so there is no
route by which parity could have moved.

The two guards cost the conformance package about half a minute. Timed on their
own: `TestNoMaskIsInertOnItsGolden` is 0.5s, because it reads committed bytes,
and `TestNoVolatileMaskCoversACapturedValue` is 27s, because it serves every
`Implemented` case that declares a `Volatile`. The package as a whole runs
between 127s and 154s depending on what else is on the machine, so the before
and after figures are not separable from the noise and only the guards' own
times are quoted. `CGO_ENABLED=0 go test ./...` passes and needs neither Docker
nor the network.

---

## 5. Every mask examined, and its verdict

409 rows, one per declared path, in the state the catalogue was in when the
sweep started. `kept` means the mask was examined and earns its place; a bold
verdict means it did not.

| case | mask | path | verdict |
|---|---|---|---|
| `admin/client-role-mappings/available` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/client-role-mappings/composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/composite-full` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/composite-full` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/group-client` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/group-client` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/group-client` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/group-client-available` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/group-client-available` | `Volatile` | `*/containerId` | **inert, removed**: addresses nothing |
| `admin/client-role-mappings/group-client-available` | `Volatile` | `*/id` | **inert, removed**: addresses nothing |
| `admin/client-role-mappings/group-client-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/group-client-composite` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/group-client-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-role-mappings/list` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/client-role-mappings/list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/client-scopes/list` | `Unordered` | `*/protocolMappers` | kept: sorts an array of 14 |
| `admin/client-scopes/list` | `Unordered` | `.` | kept: sorts an array of 15 |
| `admin/client-scopes/list` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/client-scopes/list` | `Volatile` | `*/protocolMappers/*/id` | kept: measured varying per response |
| `admin/client-scopes/list-templates` | `Unordered` | `*/protocolMappers` | kept: sorts an array of 14 |
| `admin/client-scopes/list-templates` | `Unordered` | `.` | kept: sorts an array of 15 |
| `admin/client-scopes/list-templates` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/client-scopes/list-templates` | `Volatile` | `*/protocolMappers/*/id` | kept: measured varying per response |
| `admin/clients/create` | `VolatileTailHeaders` | `Location` | kept: masks the minted tail only (F46) |
| `admin/clients/default-client-scopes` | `Unordered` | `.` | kept: sorts an array of 6 |
| `admin/clients/default-client-scopes` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/clients/default-client-scopes-protocol-mismatch` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/clients/default-client-scopes-protocol-mismatch` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/clients/list` | `Unordered` | `*/defaultClientScopes` | kept: sorts an array of 6 |
| `admin/clients/list` | `Unordered` | `*/optionalClientScopes` | kept: sorts an array of 5 |
| `admin/clients/list` | `UnorderedKeys` | `*/attributes` | kept: sorts an object of 2 keys (F90/F95) |
| `admin/clients/list` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/clients/list-all` | `Unordered` | `*/defaultClientScopes` | kept: sorts an array of 6 |
| `admin/clients/list-all` | `Unordered` | `*/optionalClientScopes` | kept: sorts an array of 5 |
| `admin/clients/list-all` | `UnorderedKeys` | `*/attributes` | kept: sorts an object of 4 keys (F90/F95) |
| `admin/clients/list-all` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/clients/list-all` | `Volatile` | `*/protocolMappers/*/id` | kept: measured varying per response |
| `admin/clients/optional-client-scopes` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/clients/optional-client-scopes` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/clients/read` | `Unordered` | `defaultClientScopes` | kept: sorts an array of 6 |
| `admin/clients/read` | `Unordered` | `optionalClientScopes` | kept: sorts an array of 5 |
| `admin/clients/read` | `UnorderedKeys` | `attributes` | kept: sorts an object of 2 keys (F90/F95) |
| `admin/clients/read` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/clients/read-created` | `Unordered` | `defaultClientScopes` | kept: sorts an array of 6 |
| `admin/clients/read-created` | `Unordered` | `optionalClientScopes` | kept: sorts an array of 5 |
| `admin/clients/read-created` | `UnorderedKeys` | `attributes` | kept: sorts an object of 2 keys (F90/F95) |
| `admin/clients/read-created` | `Volatile` | `attributes/client.secret.creation.time` | kept: measured varying per response |
| `admin/clients/read-created` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/clients/read-created` | `Volatile` | `secret` | kept: measured varying per response |
| `admin/clients/read-described` | `Unordered` | `defaultClientScopes` | kept: sorts an array of 6 |
| `admin/clients/read-described` | `Unordered` | `optionalClientScopes` | kept: sorts an array of 5 |
| `admin/clients/read-described` | `UnorderedKeys` | `attributes` | kept: sorts an object of 2 keys (F90/F95) |
| `admin/clients/read-described` | `Volatile` | `attributes/client.secret.creation.time` | kept: measured varying per response |
| `admin/clients/read-described` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/clients/read-described` | `Volatile` | `secret` | kept: measured varying per response |
| `admin/clients/secret-read` | `Volatile` | `value` | kept: measured varying per response |
| `admin/clients/secret-regenerate` | `Volatile` | `value` | kept: measured varying per response |
| `admin/clients/service-account-user` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/clients/service-account-user` | `Volatile` | `id` | kept: measured varying per response |
| `admin/groups/children-create` | `Volatile` | `id` | kept: measured varying per response |
| `admin/groups/children-create` | `Volatile` | `parentId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/children-create` | `VolatileTailHeaders` | `Location` | kept: masks the minted tail only (F46) |
| `admin/groups/children-list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/children-list` | `Volatile` | `*/parentId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/create` | `VolatileTailHeaders` | `Location` | kept: masks the minted tail only (F46) |
| `admin/groups/list` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/groups/list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/members` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/groups/members` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/read` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/search-pages-the-matches` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/groups/search-pages-the-matches` | `Volatile` | `*/subGroups/*/id` | kept: measured varying per response |
| `admin/groups/search-pages-the-matches` | `Volatile` | `*/subGroups/*/parentId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/key/realm-keys` | `Unordered` | `keys` | kept: sorts an array of 4 |
| `admin/key/realm-keys` | `Volatile` | `active/*` | kept: measured varying per response |
| `admin/key/realm-keys` | `Volatile` | `keys/*/certificate` | kept: measured varying per response |
| `admin/key/realm-keys` | `Volatile` | `keys/*/kid` | kept: measured varying per response |
| `admin/key/realm-keys` | `Volatile` | `keys/*/providerId` | kept: measured varying per response |
| `admin/key/realm-keys` | `Volatile` | `keys/*/publicKey` | kept: measured varying per response |
| `admin/key/realm-keys` | `Volatile` | `keys/*/validTo` | kept: measured varying per response |
| `admin/protocol-mappers/by-protocol` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/protocol-mappers/by-protocol-client` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/protocol-mappers/by-protocol-template` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/protocol-mappers/list` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/protocol-mappers/list-after-batch-conflict` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/protocol-mappers/list-client` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/protocol-mappers/list-template` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/protocol-mappers/read-created` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/realms-admin/default-default-client-scopes` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/realms-admin/default-groups` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/realms-admin/default-groups` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/realms-admin/default-groups` | `Volatile` | `*/parentId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/realms-admin/default-optional-client-scopes` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/realms-admin/group-by-path` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/realms-admin/group-by-path-nested` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/realms-admin/group-by-path-nested` | `Volatile` | `parentId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/realms-admin/list` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/realms-admin/list` | `UnorderedKeys` | `*/attributes` | kept: sorts an object of 6 keys (F90/F95) |
| `admin/realms-admin/list` | `Volatile` | `*/defaultRole/containerId` | kept: measured varying per response |
| `admin/realms-admin/list` | `Volatile` | `*/defaultRole/id` | kept: measured varying per response |
| `admin/realms-admin/list` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/realms-admin/read` | `UnorderedKeys` | `attributes` | kept: sorts an object of 8 keys (F90/F95) |
| `admin/realms-admin/read` | `Volatile` | `defaultRole/containerId` | kept: measured varying per response |
| `admin/realms-admin/read` | `Volatile` | `defaultRole/id` | kept: measured varying per response |
| `admin/realms-admin/read` | `Volatile` | `id` | kept: measured varying per response |
| `admin/role-mapper/all` | `Unordered` | `realmMappings` | kept: sorts an array of 2 |
| `admin/role-mapper/all` | `Volatile` | `realmMappings/*/containerId` | kept: measured varying per response |
| `admin/role-mapper/all` | `Volatile` | `realmMappings/*/id` | kept: measured varying per response |
| `admin/role-mapper/available-realm` | `Unordered` | `.` | kept: sorts an array of 4 |
| `admin/role-mapper/available-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/available-realm` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/role-mapper/composite-realm` | `Unordered` | `.` | kept: sorts an array of 4 |
| `admin/role-mapper/composite-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/composite-realm` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/role-mapper/composite-realm-full` | `Unordered` | `.` | kept: sorts an array of 4 |
| `admin/role-mapper/composite-realm-full` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/composite-realm-full` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/role-mapper/group-all` | `Volatile` | `clientMappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/group-all` | `Volatile` | `clientMappings/*/mappings/*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/group-all` | `Volatile` | `clientMappings/*/mappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/group-all` | `Volatile` | `realmMappings/*/containerId` | kept: measured varying per response |
| `admin/role-mapper/group-all` | `Volatile` | `realmMappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/group-realm` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/role-mapper/group-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/group-realm` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/group-realm-available` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/role-mapper/group-realm-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/group-realm-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/role-mapper/group-realm-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/role-mapper/group-realm-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/group-realm-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/role-mapper/list-realm` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/role-mapper/list-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/list-realm` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/role-mapper/list-realm-ignores-brief` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/role-mapper/list-realm-ignores-brief` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/role-mapper/list-realm-ignores-brief` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles-by-id/composites-clients-filter` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles-by-id/composites-clients-filter` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles-by-id/composites-list` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/roles-by-id/composites-list` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles-by-id/composites-list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles-by-id/composites-realm-filter` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles-by-id/composites-realm-filter` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles-by-id/read` | `Volatile` | `containerId` | kept: measured varying per response |
| `admin/roles-by-id/read` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-clients-filter` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-clients-filter` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-clients-filter-client` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-clients-filter-client` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-list` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/roles/composites-list` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/composites-list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-list-client` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/roles/composites-list-client` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/composites-list-client` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-realm-filter` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/composites-realm-filter` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/composites-realm-filter-client` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/composites-realm-filter-client` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/list-client` | `Volatile` | `*/containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/list-client` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/roles/list-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm-brief` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-brief` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm-brief` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm-full` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-full` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm-full` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm-page-empty` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-page-empty` | `Volatile` | `*/containerId` | **inert, removed**: addresses nothing |
| `admin/roles/list-realm-page-empty` | `Volatile` | `*/id` | **inert, removed**: addresses nothing |
| `admin/roles/list-realm-page-first` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-page-first` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm-page-first` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm-page-no-search` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm-page-no-search` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/list-realm-page-past-end` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-page-past-end` | `Volatile` | `*/containerId` | **inert, removed**: addresses nothing |
| `admin/roles/list-realm-page-past-end` | `Volatile` | `*/id` | **inert, removed**: addresses nothing |
| `admin/roles/list-realm-search-excludes-client-roles` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/roles/list-realm-search-excludes-client-roles` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/roles/list-realm-search-excludes-client-roles` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/roles/read-client` | `Volatile` | `containerId` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/roles/read-client` | `Volatile` | `id` | kept: measured varying per response |
| `admin/roles/read-created` | `Volatile` | `containerId` | kept: measured varying per response |
| `admin/roles/read-created` | `Volatile` | `id` | kept: measured varying per response |
| `admin/roles/read-realm` | `Volatile` | `containerId` | kept: measured varying per response |
| `admin/roles/read-realm` | `Volatile` | `id` | kept: measured varying per response |
| `admin/roles/users` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/roles/users` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/a-clients-own-roles-are-in-scope` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/a-clients-own-roles-are-in-scope` | `Volatile` | `*/containerId` | **inert, removed**: addresses nothing |
| `admin/scope-mappings/a-clients-own-roles-are-in-scope` | `Volatile` | `*/id` | **inert, removed**: addresses nothing |
| `admin/scope-mappings/all` | `Volatile` | `clientMappings/*/mappings/*/id` | kept: measured varying per response |
| `admin/scope-mappings/all` | `Volatile` | `realmMappings/*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/all` | `Volatile` | `realmMappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/available-keeps-a-reachable-child` | `Unordered` | `.` | kept: sorts an array of 6 |
| `admin/scope-mappings/available-keeps-a-reachable-child` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/available-keeps-a-reachable-child` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/available-to-a-manage-clients-caller` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/available-to-a-manage-clients-caller` | `Volatile` | `*/containerId` | **inert, removed**: addresses nothing |
| `admin/scope-mappings/available-to-a-manage-clients-caller` | `Volatile` | `*/id` | **inert, removed**: addresses nothing |
| `admin/scope-mappings/client` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/client` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/client` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/client-available` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/client-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/client-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/client-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/client-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/client-composite` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/composite-brief-false` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/composite-brief-false` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/composite-brief-false` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/composite-expands-a-composite` | `Unordered` | `.` | kept: sorts an array of 2 |
| `admin/scope-mappings/composite-expands-a-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/composite-expands-a-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/full-scope-composite` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/scope-mappings/full-scope-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/full-scope-composite` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-all` | `Volatile` | `clientMappings/*/mappings/*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-all` | `Volatile` | `realmMappings/*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-all` | `Volatile` | `realmMappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/owner-client` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/owner-client` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-client` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-client-available` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/owner-client-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-client-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-client-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/owner-client-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-client-composite` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-realm` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/owner-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-realm` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/owner-realm-available` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/scope-mappings/owner-realm-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-realm-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/owner-realm-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/owner-realm-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/owner-realm-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/realm` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/realm` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/realm-available` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/scope-mappings/realm-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/realm-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/realm-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/realm-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/realm-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/template-all` | `Volatile` | `clientMappings/*/mappings/*/id` | kept: measured varying per response |
| `admin/scope-mappings/template-all` | `Volatile` | `realmMappings/*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-all` | `Volatile` | `realmMappings/*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/template-client` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/template-client` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-client` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/template-client-available` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/template-client-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-client-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/template-client-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/template-client-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-client-composite` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/template-realm` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/template-realm` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-realm` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/scope-mappings/template-realm-available` | `Unordered` | `.` | kept: sorts an array of 5 |
| `admin/scope-mappings/template-realm-available` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-realm-available` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/scope-mappings/template-realm-composite` | `Unordered` | `.` | **inert, removed**: array of 0 or 1 |
| `admin/scope-mappings/template-realm-composite` | `Volatile` | `*/containerId` | kept: measured varying per response |
| `admin/scope-mappings/template-realm-composite` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/create` | `VolatileTailHeaders` | `Location` | kept: masks the minted tail only (F46) |
| `admin/users/credential-label-read` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/credential-label-read` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/credentials-list` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/credentials-list` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/groups` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/inline-credential` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/inline-credential` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/inline-credential-empty-value` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/inline-credential-empty-value` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/inline-credential-ignores-type-and-label` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/inline-credential-ignores-type-and-label` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/inline-credential-keeps-temporary` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/inline-credential-keeps-temporary` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/inline-credential-temporary` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/inline-credential-temporary` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/inline-credential-temporary-then-not` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/inline-credential-temporary-then-not` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/inline-credential-twice` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/inline-credential-twice` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/list` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/users/list` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/list-brief` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/users/list-brief` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/list-by-search` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/users/list-by-search` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/list-by-username` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/users/list-by-username` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/list-search-wildcard` | `Volatile` | `*/createdTimestamp` | kept: measured varying per response |
| `admin/users/list-search-wildcard` | `Volatile` | `*/id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/read` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/read` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/read-to-a-manage-users-caller` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/read-to-a-manage-users-caller` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/reset-password-temporary` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/reset-password-temporary` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `admin/users/update-inline-credential` | `Volatile` | `*/createdDate` | kept: measured varying per response |
| `admin/users/update-inline-credential` | `Volatile` | `*/id` | kept: measured varying per response |
| `admin/users/update-merges` | `Volatile` | `createdTimestamp` | kept: measured varying per response |
| `admin/users/update-merges` | `Volatile` | `id` | **over-wide, narrowed**: already `{{captured}}` |
| `oidc/authorization/code-flow-redirect` | `VolatileHeaders` | `Location` | **over-wide**: whole `Location` masked (F39) |
| `oidc/authorization/code-flow-redirect` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/authorization/pkce-plain` | `VolatileHeaders` | `Location` | **over-wide**: whole `Location` masked (F39) |
| `oidc/authorization/pkce-plain` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/authorization/pkce-s256` | `VolatileHeaders` | `Location` | **over-wide**: whole `Location` masked (F39) |
| `oidc/authorization/pkce-s256` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/authorization/prompt-none-no-session` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/authorization/response-mode-form-post` | `VolatileHeaders` | `Set-Cookie` | not evaluable: Pending, no golden |
| `oidc/authorization/response-mode-fragment` | `VolatileHeaders` | `Location` | **over-wide**: whole `Location` masked (F39) |
| `oidc/authorization/response-mode-fragment` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/certs/master` | `Unordered` | `keys` | kept: sorts an array of 2 |
| `oidc/certs/master` | `Volatile` | `keys/*/kid` | kept: measured varying per response |
| `oidc/certs/master` | `Volatile` | `keys/*/n` | kept: measured varying per response |
| `oidc/certs/master` | `Volatile` | `keys/*/x5c` | kept: measured varying per response |
| `oidc/certs/master` | `Volatile` | `keys/*/x5t` | kept: measured varying per response |
| `oidc/certs/master` | `Volatile` | `keys/*/x5t#S256` | kept: measured varying per response |
| `oidc/ciba/poll-complete` | `Volatile` | `access_token` | not evaluable: Pending, no golden |
| `oidc/ciba/poll-complete` | `Volatile` | `id_token` | not evaluable: Pending, no golden |
| `oidc/ciba/poll-complete` | `Volatile` | `refresh_token` | not evaluable: Pending, no golden |
| `oidc/ciba/poll-complete` | `Volatile` | `session_state` | not evaluable: Pending, no golden |
| `oidc/device/authorization-request` | `Volatile` | `device_code` | kept: measured varying per response |
| `oidc/device/authorization-request` | `Volatile` | `user_code` | kept: measured varying per response |
| `oidc/device/authorization-request` | `Volatile` | `verification_uri_complete` | kept: measured varying per response |
| `oidc/discovery/master` | `Unordered` | `scopes_supported` | kept: sorts an array of 13 |
| `oidc/introspection/active-refresh-token` | `Unordered` | `aud` | kept: sorts an array of 3 |
| `oidc/introspection/active-refresh-token` | `Unordered` | `realm_access/roles` | kept: sorts an array of 5 |
| `oidc/introspection/active-refresh-token` | `Unordered` | `resource_access/*/roles` | kept: sorts an array of 21 |
| `oidc/introspection/active-refresh-token` | `UnorderedWords` | `scope` | kept: sorts 7 words |
| `oidc/introspection/active-refresh-token` | `Volatile` | `exp` | kept: measured varying per response |
| `oidc/introspection/active-refresh-token` | `Volatile` | `iat` | kept: measured varying per response |
| `oidc/introspection/active-refresh-token` | `Volatile` | `jti` | kept: measured varying per response |
| `oidc/introspection/active-refresh-token` | `Volatile` | `sid` | kept: measured varying per response |
| `oidc/introspection/active-refresh-token` | `Volatile` | `sub` | kept: measured varying per response |
| `oidc/logout/post-logout-uri-defaults-to-redirect-uris` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/logout/rp-initiated-with-id-token-hint` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/logout/rp-initiated-without-id-token-hint` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/logout/spent-id-token-hint` | `VolatileHeaders` | `Set-Cookie` | kept: every value minted per request |
| `oidc/registration/create-client` | `Volatile` | `client_id` | not evaluable: Pending, no golden |
| `oidc/registration/create-client` | `Volatile` | `client_id_issued_at` | not evaluable: Pending, no golden |
| `oidc/registration/create-client` | `Volatile` | `client_secret` | not evaluable: Pending, no golden |
| `oidc/registration/create-client` | `Volatile` | `client_secret_expires_at` | not evaluable: Pending, no golden |
| `oidc/registration/create-client` | `Volatile` | `registration_access_token` | not evaluable: Pending, no golden |
| `oidc/registration/create-client` | `Volatile` | `registration_client_uri` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `client_id` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `client_id_issued_at` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `client_secret` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `client_secret_expires_at` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `registration_access_token` | not evaluable: Pending, no golden |
| `oidc/registration/read-client` | `Volatile` | `registration_client_uri` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `client_id` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `client_id_issued_at` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `client_secret` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `client_secret_expires_at` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `registration_access_token` | not evaluable: Pending, no golden |
| `oidc/registration/update-client` | `Volatile` | `registration_client_uri` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `client_id` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `client_id_issued_at` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `client_secret` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `client_secret_expires_at` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `registration_access_token` | not evaluable: Pending, no golden |
| `oidc/registration/with-registration-access-token` | `Volatile` | `registration_client_uri` | not evaluable: Pending, no golden |
| `oidc/token/authorization-code-grant` | `UnorderedWords` | `scope` | kept: sorts 3 words |
| `oidc/token/authorization-code-grant` | `Volatile` | `access_token` | kept: measured varying per response |
| `oidc/token/authorization-code-grant` | `Volatile` | `id_token` | kept: measured varying per response |
| `oidc/token/authorization-code-grant` | `Volatile` | `refresh_token` | kept: measured varying per response |
| `oidc/token/authorization-code-grant` | `Volatile` | `session_state` | **over-wide**: already `{{captured}}` |
| `oidc/token/ciba-grant` | `Volatile` | `access_token` | not evaluable: Pending, no golden |
| `oidc/token/ciba-grant` | `Volatile` | `id_token` | not evaluable: Pending, no golden |
| `oidc/token/ciba-grant` | `Volatile` | `refresh_token` | not evaluable: Pending, no golden |
| `oidc/token/ciba-grant` | `Volatile` | `session_state` | not evaluable: Pending, no golden |
| `oidc/token/client-credentials-grant` | `UnorderedWords` | `scope` | kept: sorts 2 words |
| `oidc/token/client-credentials-grant` | `Volatile` | `access_token` | kept: measured varying per response |
| `oidc/token/device-code-grant` | `Volatile` | `access_token` | not evaluable: Pending, no golden |
| `oidc/token/device-code-grant` | `Volatile` | `id_token` | not evaluable: Pending, no golden |
| `oidc/token/device-code-grant` | `Volatile` | `refresh_token` | not evaluable: Pending, no golden |
| `oidc/token/device-code-grant` | `Volatile` | `session_state` | not evaluable: Pending, no golden |
| `oidc/token/dpop-bound-token` | `Volatile` | `access_token` | not evaluable: Pending, no golden |
| `oidc/token/dpop-bound-token` | `Volatile` | `id_token` | not evaluable: Pending, no golden |
| `oidc/token/dpop-bound-token` | `Volatile` | `refresh_token` | not evaluable: Pending, no golden |
| `oidc/token/dpop-bound-token` | `Volatile` | `session_state` | not evaluable: Pending, no golden |
| `oidc/token/password-grant-admin-cli` | `UnorderedWords` | `scope` | kept: sorts 2 words |
| `oidc/token/password-grant-admin-cli` | `Volatile` | `access_token` | kept: measured varying per response |
| `oidc/token/password-grant-admin-cli` | `Volatile` | `id_token` | **inert**: addresses nothing |
| `oidc/token/password-grant-admin-cli` | `Volatile` | `refresh_token` | kept: measured varying per response |
| `oidc/token/password-grant-admin-cli` | `Volatile` | `session_state` | kept: measured varying per response |
| `oidc/token/refresh-token-grant` | `UnorderedWords` | `scope` | kept: sorts 2 words |
| `oidc/token/refresh-token-grant` | `Volatile` | `access_token` | kept: measured varying per response |
| `oidc/token/refresh-token-grant` | `Volatile` | `id_token` | **inert**: addresses nothing |
| `oidc/token/refresh-token-grant` | `Volatile` | `refresh_token` | kept: measured varying per response |
| `oidc/token/refresh-token-grant` | `Volatile` | `session_state` | kept: measured varying per response |
| `oidc/userinfo/get-with-valid-token` | `Volatile` | `sub` | kept: measured varying per response |
| `oidc/userinfo/post-with-valid-token` | `Volatile` | `sub` | kept: measured varying per response |
| `realm/info/master` | `Volatile` | `public_key` | kept: measured varying per response |

