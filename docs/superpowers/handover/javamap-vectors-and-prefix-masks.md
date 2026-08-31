# javamap vectors and prefix masks

Date: 2026-08-31
Branch: `fix/javamap-vectors-and-prefix-masks`
Follow-ups touched: **F105 (closed), F106 (closed, first outcome), F107
(partly answered), F111 (reported, not fixed), F23/F69 (reopened by somebody
else's promotion)**

Every observable value below came from a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8123, in a container this
branch started and removed. `kc-reqact` and `kc-org` were not touched. Two whole
`make record` runs, one on this branch and one on the branch point, are what the
golden accounting rests on.

This branch does not touch `AGENTS.md`, `README.md`, the parity roadmap, the
observed spec or the follow-ups list, so what is owed to them is written out
here.

---

## 1. Measurements

### 1.1 All four of F105's vectors reproduced, on two realms

Re-measured rather than transcribed, which is the whole instruction. Every one
came back byte for byte as the P8 handover recorded it, on `master` and on a
realm created through `POST /admin/realms`:

| key set | source | measured order |
|---|---|---|
| `{id, displayName, description}` | `authenticator-providers` (42 rows), `form-providers` (1), `form-action-providers` (5) | `displayName, description, id` |
| `{id, displayName, description, supportsSecret}` | `client-authenticator-providers` (5 rows) | `supportsSecret, displayName, description, id` |
| the five client authenticator ids | `per-client-config-description` | `client-jwt, client-secret, federated-jwt, client-x509, client-secret-jwt` |
| the fourteen required action providers | `unregistered-required-actions`, after unregistering all fourteen | `CONFIGURE_TOTP, webauthn-register-passwordless, UPDATE_PASSWORD, update_user_locale, TERMS_AND_CONDITIONS, idp_link, delete_account, VERIFY_EMAIL, UPDATE_EMAIL, webauthn-register, VERIFY_PROFILE, delete_credential, CONFIGURE_RECOVERY_AUTHN_CODES, UPDATE_PROFILE` |

`javamap.KeyOrder` places the first three exactly. Sorting is wrong on all
three and `SizedKeyOrder` is wrong on all three, so each says something about
*which constructor* built the map and not only about the bucket rule. The
fourteen are the near-miss.

The three registry listings that share a row shape came back in **one** key
order across all 48 of their rows, so the vector is a property of the row and
not of one endpoint.

### 1.2 What the three confirming vectors pin, and what they do not

They pin the **table size**, which the client `attributes` vectors do not pin
very hard. Sorting each key set by bucket at every power of two from 1 to 128:

| key set | capacities that reproduce the measured order |
|---|---|
| `{displayName, description, id}` | 2, 16, 32, 64 |
| `{supportsSecret, displayName, description, id}` | 16, 32 |
| the five client authenticator ids | **16 alone** |

So the weakest of the three is not the one carrying the claim, and a build that
got `capacityFor` wrong for a five-key map fails. Mutating
`capacityFor`'s initial `16` to `32` fails
`TestKeyOrderReproducesTheAuthenticationRegistries` on that vector alone.

**They do not pin the tie-break**, exactly as the client `attributes` vectors do
not. Every key in the three lands in a bucket of its own - 6, 9, 11; 4, 6, 9,
11; and 1, 5, 7, 14, 15 - so no chain is exercised. That is what the fourth
vector is for.

They also do not pin `capacityFor`'s **boundary**. The fourteen sit at 14 keys,
where the doubling happened at 13, so nothing here is at 12/13 and
`TestKeyOrderAccountsForResizing` is still the only thing that is.

### 1.3 The near-miss, and a coin that has landed the same way four times

The fourteen required action providers collide **twice** at capacity 32:
bucket 16 holds `{update_user_locale, TERMS_AND_CONDITIONS}` and bucket 19
holds `{delete_account, VERIFY_EMAIL}`. Twelve of the fourteen are placed
exactly; the two chains come back the other way round. It is the second key set
to show that limit after the 21 admin role names, and the test names *which*
pairs move rather than counting them - the 21 roles' test asserts a count of
four differing positions and would pass a build that swapped some other pair.

**Then the thing the vectors do not pin turned out to have a pattern, and the
pattern is not a rule.** All four of these chains - both of the 21 roles' and
both of the fourteen's - come back in **descending** alphabetical order.
`KeyOrder` sorts ascending. So reversing the pre-sort in `KeyOrder` would pass
every vector in the package, `TestKeyOrderCannotResolveBucketCollisions`
included.

It is still a guess, and the thing that says so is the eight-key realm
`attributes` set already in the tests:

| chain | keys | measured order is |
|---|---|---|
| realm attributes, bucket 0 | 4 keys | neither ascending nor descending |
| realm attributes, bucket 15 | `cibaInterval, realmReusableOtpCode` | **ascending** |
| 21 admin roles, bucket 0 | `view-realm, view-identity-providers` | descending |
| 21 admin roles, bucket 30 | `query-organizations, query-groups` | descending |
| 14 required actions, bucket 16 | `update_user_locale, TERMS_AND_CONDITIONS` | descending |
| 14 required actions, bucket 19 | `delete_account, VERIFY_EMAIL` | descending |

Four of the five two-key chains descending is what a coin looks like after five
flips, the four-key chain fits no alphabetical rule at all, and a chain is
ordered by an insertion order nothing observable reveals. The package doc now
says this, so that the obvious "fix" - reverse the sort, watch the tests go
green - arrives with its refutation attached rather than looking like a
discovery.

### 1.4 A fifth key set came off the same response and is not a vector

`unregistered-required-actions` serves entries of `{providerId, name}`, and they
come back `providerId, name` on both realms. `KeyOrder` places it; sorting gives
`name, providerId` and is wrong. It is left out of the tests deliberately: a
two-key set is one permutation out of two, and the same response already yields
the fourteen-key near-miss, which is the strongest thing in this cut.

It is written down here because the count in `AGENTS.md` is about to move and
somebody re-deriving it from the endpoint list should not have to wonder whether
this one was missed or excluded.

### 1.5 `AGENTS.md` says six key sets and its own tests hold nine

This is the second instance of the failure mode `AGENTS.md` records for the
charset bullet, in the neighbouring paragraph, and it is the same shape: the
code knew and the contract document did not.

The javamap bullet reads "confirmed against six measured key sets - four in its
own tests". `internal/javamap/javamap_test.go` held **nine** confirming vectors
before this branch: the four that bullet counts, plus the five client
`attributes` key sets added on 2026-08-30 - which the `attributes` bullet
**four paragraphs earlier in the same document** describes as "all five key sets
a default install has come back in its order". One document, two bullets, and
the arithmetic between them was never done.

So P8's "six confirmed key sets to nine" is right about the delta and inherits a
wrong base. The count after this branch:

| where | confirming key sets |
|---|---|
| `TestKeyOrderReproducesMeasuredKeycloakOrders` | 4 |
| `TestKeyOrderReproducesAClientsAttributes` | 5 |
| `TestKeyOrderReproducesTheAuthenticationRegistries` | 3 |
| **in the package's own tests** | **12** |
| `clientMappings`, pinned in `internal/admin` | 1 |
| the `active` map of `GET .../keys`, pinned in `internal/admin` | 1 |
| **total** | **14** |

Plus two near-misses that are tests of the limit rather than of the rule (the 21
admin role names, the fourteen required action providers) and one key set that
cannot be placed at all (a realm's `attributes`).

`RSA-OAEP, HS512, RS256, AES` was re-measured on this container and still holds,
so the two vectors outside the package are not stale.

### 1.6 F106 is decidable from one recording, on the example the entry gives

F106 says a mask that is too wide by a prefix needs "two recordings diffed per
value". That is true of one subclass and false of the one the entry names.

By the time `Normalize` runs, two passes have already rewritten parts of the
body: `ReplaceCaptured` puts `{{group_id}}` where a fixture-captured id was, and
`ReplaceIssuer` puts `{{issuer}}` where the server's base URL was. **Both sides
of a comparison run both passes**, so a byte inside one of those placeholders is
identical on both sides by construction. It carries no volatility. A `Volatile`
mask that covers it therefore gives up an assertion in exchange for nothing, and
saying so needs one response, not two.

F106's own example is `Location: https://host/realms/x/<uuid>`. The host in that
string is `{{issuer}}` before `Normalize` ever sees it. The example is
decidable.

What genuinely needs the second recording is a value whose stable part carries
**no** placeholder - a bare constant prefix, a template, a fixed scheme in front
of a random token. This guard says nothing about those, and the design F106
writes down is still the answer for them.

### 1.7 The guard fires once, on a real over-wide mask

Run against the whole catalogue with the exception list empty, before any entry
was written for it:

```
--- FAIL: TestNoVolatileMaskCoversACapturedValue/oidc/device/authorization-request
    Volatile "verification_uri_complete" covers 1 value(s), every one of them
    carrying {{issuer}} and more - the mask gives up bytes the harness had
    already pinned
```

One finding on the whole catalogue, and it is the one the mask audit predicted
as **F107** and could not reach: that sweep read the case as `Pending`, and it is
`Implemented` today with a golden, so the guard sees it on its first run.

Measured on a live 26.7.1 on 2026-08-31, on a client carrying
`oauth2.device.authorization.grant.enabled`:

```
device_code                ySS6DwAUjd-qCJUACXokTwScytXtzdFAgWgy1-md8E0
user_code                  BKSP-TWQJ
verification_uri           http://localhost:8123/realms/master/device
verification_uri_complete  http://localhost:8123/realms/master/device?user_code=BKSP-TWQJ
```

Every part of the masked value is pinned or masked **elsewhere in the same
body**: `verification_uri` is asserted whole one key later - the committed golden
holds `{{issuer}}/realms/master/device` - and `user_code` is masked two keys
earlier. So the mask gives up the issuer, the realm and the endpoint in order to
hide eight characters the case has already given up beside it.

It is the one finding in this cut that needs a **mechanism** rather than an edit.
F46's answer for a header was a new field, `VolatileTailHeaders`; `Case` has no
body-side equivalent, so there is nothing to narrow this to today. It is declared
in `prefixMasksLeftInPlace` with that reason, and the list is a ratchet: the day
a body-side tail mask lands, the entry goes stale and fails.

### 1.8 `make record` is not silent on a clean checkout any more, and it is not this branch

The working baseline says a clean run rewrites 433 goldens and moves none. Both
halves have moved, and the second one matters.

| run | goldens rewritten | goldens moved |
|---|---|---|
| this branch | 474 | 4 |
| **the branch point `8372b1b`, nothing of mine present** | 474 | **the same 4** |

Same four files, same 33 insertions and 33 deletions. So the churn is
pre-existing and this branch did not cause it - which is the only reason the
golden accounting here can say "nothing of mine moved".

The four are `oidc/authorization/max-age-invalid`,
`oidc/authorization/prompt-create`, `oidc/device/status-page` and
`oidc/device/verification-page`, and all four are `Status: Recorded`. Three churn
on the `/resources/<hash>/` segment alone; `prompt-create` churns on that plus
`AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH` and a `tab_id` **inside the HTML
body**.

**This is F23/F69 coming back through the door `GoldenIsAsserted` left open.**
That predicate stopped the recorder rewriting a `Pending` golden, and
`AGENTS.md` records the sanctioned way to ask for one back: promote the case to
`Recorded`. Four theme pages were promoted, and the churn came with them, because
what `Recorded` restores is the rewrite and the reason those goldens churned was
never their status - it was that a theme page holds per-container-start bytes no
mask reaches. That is F38, closed as "not built".

Nothing was done about it here: all four cases live in `catalog_oidc_pending.go`,
which this branch may not edit, and the fix is either an HTML-body mask (F38) or
demoting them.

---

## 2. Entries for AGENTS.md

### 2.1 For "Things that look like bugs and are not", replacing the `javamap` bullet

The existing bullet's count and list are both wrong, and were wrong before this
branch. Suggested replacement for the sentence beginning "`javamap.KeyOrder` is
the no-argument one":

- **Keycloak's JSON key order for a Java `Map` is `HashMap` bucket order**, not
  sorted and not insertion order. **There are two constructors and
  `internal/javamap` models them separately.** `javamap.KeyOrder` is the
  no-argument one - 16 buckets, doubling at the 0.75 load factor - and is
  confirmed against **fourteen** measured key sets: twelve in its own tests, and
  two pinned where they are served. The twelve are four token and `access`
  shapes, the five client `attributes` sets a default install has, and three from
  the authentication SPI - a provider registry's `{id, displayName,
  description}` row, a client authenticator's `{id, displayName, description,
  supportsSecret}` row, and `per-client-config-description`'s five ids, which is
  the one vector reproduced at a table of 16 buckets and **no other**. The two
  outside are the `clientMappings` of a combined role-mapping view, where six
  clients created and assigned `cx1..cx6` came back `cx6, cx5, cx2, cx1, cx4,
  cx3`, and the `active` map of `GET /admin/realms/{realm}/keys`, `RSA-OAEP,
  HS512, RS256, AES` on both master and a created realm, which has **no** bucket
  collision at all. It cannot resolve a bucket collision, because those chain in
  insertion order and nothing observable says what that was; **two key sets
  demonstrate that and both collide exactly twice** - the 21 admin role names,
  and the fourteen providers of `unregistered-required-actions`, where twelve of
  fourteen are placed and the two colliding pairs come back the other way round.
  Sorting instead is what makes `resource_access` come out `account,
  master-realm` where Keycloak says `master-realm, account`.
  (This bullet said "six measured key sets - four in its own tests" until
  2026-08-31, and **the tests already held nine** - the other five are the client
  `attributes` sets that the `attributes` bullet above describes in as many
  words. One document, two bullets, and nobody had done the arithmetic between
  them. It is the charset bullet's failure mode with the two halves inside one
  file.)
- **Four measured chains come back in descending alphabetical order and that is
  not a rule.** Both of the 21 admin role names' and both of the fourteen
  required actions'. `KeyOrder` sorts ascending, so reversing its pre-sort would
  pass every vector in the package - and a realm's `attributes` refutes it, with
  a two-key chain that comes back **ascending** and a four-key chain that fits
  neither direction. Four of five is what a coin looks like after five flips.
  The tie-break is a guess by construction and no measurement has moved it.

### 2.2 For "Things that look like bugs and are not", beside the mask bullet

- **A mask can be too wide by a prefix, and one recording is enough to say so
  when the harness pinned the prefix.** `ReplaceCaptured` and `ReplaceIssuer` run
  before `Normalize`, on both sides, so a byte inside `{{issuer}}` or
  `{{group_id}}` is identical on both sides by construction and carries no
  volatility at all. A `Volatile` covering one gives up an assertion for nothing.
  `volatileMasksOverPinnedPrefixes` is the third ratchet and it rides on
  `TestNoVolatileMaskCoversACapturedValue`'s served body rather than a second
  loop, because serving is what that test's time goes on. It fires **once** on
  the catalogue: `oidc/device/authorization-request` masks
  `verification_uri_complete` whole, where `verification_uri` is asserted whole
  one key later and `user_code` is masked two keys earlier - so the mask hides
  eight characters at the cost of the issuer, the realm and the endpoint. That
  one is declared rather than fixed, because narrowing it needs a **body-side**
  `VolatileTailHeaders` that `Case` has not got. **F106 says this needs two
  recordings diffed per value and that is true of a different question**: a value
  whose stable part carries no placeholder still needs them, and F106's own
  example - a `Location` under the issuer - does not.

### 2.3 For "Build and test", correcting the `make record` bullet

The bullet ending "**The way to ask for a Pending golden back is to promote the
case to `Recorded`**" is true and incomplete, and the omission is live. Suggested
addition:

  **Promoting a theme page to `Recorded` brings its churn back with it, and four
  have been promoted.** `oidc/authorization/max-age-invalid`,
  `oidc/authorization/prompt-create`, `oidc/device/status-page` and
  `oidc/device/verification-page` move on **every** `make record`, measured on a
  clean checkout of `8372b1b` with nothing else present. What `Recorded` restores
  is the rewrite, and the reason those goldens churned was never the status - it
  is that a theme page holds a `/resources/<hash>/` segment minted per container
  start, and `prompt-create` holds `AUTH_SESSION_ID`, `KC_AUTH_SESSION_HASH` and
  a `tab_id` inside the HTML besides. That is F38, closed as "not built". **So a
  `make record` diff is no longer empty by default**, and the next person to read
  one has four files to account for before they start.

### 2.4 For "Build and test", on what `make record` costs now

A clean run rewrites **474** goldens, not the 433 the mask audit measured on
2026-08-30 and not the 380 the older working notes say. The number is a count of
`Implemented` and `Recorded` cases with a fixture, so it grows with the
catalogue and any figure written down goes stale. What used to survive the
staleness - "a clean run moves none of them" - is the sentence 2.3 corrects.

---

## 3. Follow-up dispositions

### 3.1 F105: closed

All four vectors re-measured against a live 26.7.1 and all four reproduced. They
are in `internal/javamap/javamap_test.go` as
`TestKeyOrderReproducesTheAuthenticationRegistries` (the three) and
`TestKeyOrderMissesTheCollidingRequiredActionPairs` (the near-miss).

The near-miss is worth more than the three, as the entry says, and for a reason
the entry did not have: it pins **which** pairs move. The 21 roles' test asserts
a count of four differing positions, so a build that swapped some other pair
passes it; this one reconstructs the expected output by swapping the two named
pairs and compares whole.

F105 says adding it is three lines. It was closer to forty with the comments,
and the extra thirty are §1.3's table - the finding that a descending tie-break
fits four of the five measured chains. That was not in the entry and is the part
most likely to be re-discovered as a "fix".

### 3.2 F106: closed, first outcome - it is checkable from what exists

**Evidence for the outcome**, in the order it was established:

1. The prefix in F106's own example is `{{issuer}}` by the time `Normalize` runs,
   and both sides write it from the same code. So it is pinned, not measured, and
   one response settles it.
2. The guard, run with an empty exception list, failed on a real over-wide mask
   in the catalogue - `oidc/device/authorization-request` - and on nothing else.
3. That value was then measured against a live 26.7.1 and is
   `verification_uri` + `?user_code=` + the code, every part of which the same
   body already pins or masks separately.

The claim "deciding it needs two recordings diffed per value" is **half right**,
and the half that survives is worth keeping: a stable prefix carrying no
placeholder is still out of reach, and F106's design is still the answer to it.
The half that does not survive is the example the entry chose to illustrate it
with.

**What the guard does not reach**, stated so it is not assumed:

- A stable prefix with no placeholder in it - a literal scheme, a constant
  template, a fixed path in a body that carries no issuer. Two recordings.
- A `Volatile` over a **non-string** value. `MaskedValues` returns the raw JSON
  and the check is `bytes.Contains`, so a number or an object cannot carry a
  placeholder and is never reported. That is right today - no `Volatile` in the
  catalogue resolves to an object - and it is a silent hole if one ever does.
- A path whose values are only **partly** pinned. Deliberate, and the capture
  guard's rule: the mask is still earning its place on the others.
- Anything about a `Pending` case. The loop is `Implemented` only, which is what
  hid this very finding from the mask audit.

### 3.3 F107: partly answered, and one entry of it can be struck

F107 lists `oidc/device/authorization-request`'s `verification_uri_complete` as
one of two "F46's shape in cases nobody has built yet". The case **is** built -
`Implemented`, with a golden - so that half is no longer a pattern match on the
shape: it is measured, reported by a guard, and declared in
`prefixMasksLeftInPlace`. The `oidc/registration/*` half is still `Pending` and
still unmeasured, and this guard cannot reach it.

### 3.4 F111: reported, not fixed

`internal/httpx/errors.go` still carries it, unchanged:

```go
// WriteJSONCharset is WriteJSON with ";charset=UTF-8" appended to the
// Content-Type. Measured on GET /realms/{realm}: unlike every other endpoint
// recorded so far, which sends plain "application/json", Keycloak 26.7.1
// sends this on the realm info endpoint's success response.
```

`internal/httpx` is another stream's this session and is on this branch's
do-not-touch list. No branch has committed to that file since the last merge,
but two sibling worktrees sit at `8372b1b` and their uncommitted work is not
visible from here, so "clearly not touched" cannot be established. It is one
comment; here is the text, so whoever fixes the bullet can apply it in one edit:

```go
// WriteJSONCharset is WriteJSON with ";charset=UTF-8" appended to the
// Content-Type. The split is by **API surface and status class**, not by
// endpoint: on the Admin API every 2xx with a body carries the charset and
// every error carries plain "application/json", and on the protocol side
// every 200 carries plain "application/json". GET /realms/{realm} was simply
// the first endpoint of that family to be measured. See the charset bullet in
// AGENTS.md, and writeAdminJSON in internal/admin/clients.go, which has stated
// the rule correctly since P2.
```

### 3.5 F23, F69 and F38: reopened by somebody else, reported here

See §1.8. Four `Recorded` theme pages churn on every `make record`. The
mechanism is F38's - a per-request value inside an HTML body that no mask
reaches - and the door is `Recorded`, which `GoldenIsAsserted` deliberately
leaves open. Not touched: `catalog_oidc_pending.go` is another stream's.

### 3.6 F95 and F90: unchanged

`internal/admin` still marshals a Go `map[string]string` for a client's
`attributes`, so the five `UnorderedKeys` masks stay. Nothing here moves that,
and nothing here needed to change a `javamap` caller - the three new vectors are
explanations of orders `internal/admin` already carries as declared struct
fields, which is what `AGENTS.md`'s "Response bodies" asks for.

---

## 4. Parity, before and after

**Unchanged, and measured rather than assumed.** `make conformance` on the
branch point and on this branch:

```
total: 285 of 523 enumerated behaviours served; 4 chapters not enumerated
```

identical on both. The diff against `8372b1b` touches three files -
`internal/javamap/javamap.go`, `internal/javamap/javamap_test.go` and
`internal/conformance/catalog_test.go` - and carries **zero** `ID`, `Status`,
`Operation`, `Fixture` or `PristineRealm` lines, checked mechanically. No case
was added, removed or promoted, no golden was written, and `coverage_test.go`
reads none of the fields this branch touches.

The new guard costs nothing measurable, and the reason no before-and-after
number is quoted is that one would be dishonest.
`TestNoVolatileMaskCoversACapturedValue` ran 22.2s, 22.8s and 28.5s in three
runs **on this branch**, so the machine's noise is six seconds wide and the walk
this adds - over a body that test has already served and parsed - is nowhere
near it. Serving is the cost; that is also why the check rides on the existing
loop instead of a second one.

---

## 5. Mutations run, and the one thing that survived

Seven mutations, one per claim, each reverted, each confirmed to fail the
**named** test.

| mutation | named test | outcome |
|---|---|---|
| `capacityFor`'s initial `16` becomes `32` | `TestKeyOrderReproducesTheAuthenticationRegistries` | fails, on the five ids alone |
| `bucket`'s spread `h ^ (h >> 16)` becomes `h` | `TestKeyOrderReproducesTheAuthenticationRegistries` | fails, all three |
| `hashCode`'s `31*h` becomes `33*h` | `TestKeyOrderMissesTheCollidingRequiredActionPairs` | fails at the named-pairs assertion, not the count |
| `KeyOrder`'s pre-sort reversed | `TestKeyOrderMissesTheCollidingRequiredActionPairs` | fails - it now places all fourteen |
| `{{issuer}}` dropped from `pinnedPlaceholders` | `TestNoVolatileMaskCoversACapturedValue` **and** `TestVolatilePrefixGuardCanFail` | both fail; the first via the stale-entry ratchet |
| "every value pinned" becomes "any value pinned" | `TestVolatilePrefixGuardCanFail` | fails on the mixed path and the non-string |
| the capture exclusion removed | `TestVolatilePrefixGuardCanFail` | fails - one mask would need two exception entries |

**Nothing survived.** The fourth is the interesting one and is not a survivor:
reversing the tie-break is *killed* by the two collision tests, and §1.3 is the
reason that kill is the right answer rather than a test defending a wrong
implementation.

The one thing that is not mutation-tested is §1.8's finding, because it is not
this branch's code. It was established by running `make record` twice - once
here, once on a detached `8372b1b` with nothing of this branch present - and
diffing.
