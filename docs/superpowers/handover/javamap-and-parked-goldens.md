# javamap and the parked goldens: what belongs in the documents this branch may not edit

Branch `fix/javamap-and-parked-goldens`, cut against `main` at `a308eb0`,
closing **F80** and **F72**.

Everything below was measured against a live Keycloak 26.7.1 started for this
cut on port 8099 and removed at the end of it. Nothing in it is remembered.

---

## 1. Measurements

### 1.1 The mapper `config`'s order is two tables, and the model is now pinned

F80 was filed with a model: `capacity = tableSizeFor(n)`, doubled once past the
load factor, buckets ascending, collisions in insertion order. Re-measured, that
model fits **thirteen of fourteen** vectors and the fourteenth falsifies it.

The one that falsifies it is three keys, `{claim.name, jsonType.label,
user.attribute}`. It comes back `claim.name, user.attribute, jsonType.label`
from **all six** of its insertion orders. A single table of four puts
`jsonType.label` and `user.attribute` in one bucket, so their order would have to
be the order they were sent in, and it is not. `{zz, aa, mm}` comes back in
whichever order it went in, from all six of its insertion orders, so the same
table cannot be separating those three either. **One table cannot produce both
answers.**

The model that does:

```
c1 = capacity(7n/4, n)      // the table the keys pass through first
c2 = capacity(n,   n)       // the table they are re-inserted into
capacity(requested, entries):
    c = tableSizeFor(requested)         // next power of two >= requested
    if entries*4 > c*3 { c *= 2 }       // one load-factor doubling
order: stable by bucket at c1, then stable by bucket at c2
```

`bucket` and `String.hashCode` are unchanged from what `internal/javamap`
already had.

### 1.2 How the intermediate table was read off the server rather than guessed

Two keys that agree at capacity `C` agree at every smaller capacity, because the
mask is a suffix. So a pair that agrees at `C` and differs at `2C`, sent in both
orders, answers exactly one question: does anything ahead of the final table
have at least `2C` buckets? If it does, the pair comes back in hash order both
times. If it does not, it comes back in the order it was sent.

Swept at **every entry count from 1 to 50**, three probes per count. The answer
flips at four places:

| n | intermediate | n | intermediate |
|---|---|---|---|
| 5 | = final table | 6 | twice the final table |
| 9 | = final table | 10 | twice the final table |
| 18 | = final table | 19 | twice the final table |
| 37 | = final table | 38 | twice the final table |

`n=5` needs the request to round down to 8 and `n=10` needs it to round up past
16, so no plain multiple of `n` fits: 1.6n is refuted by n=10 and 1.75n exactly
fits because `floor(7*5/4) = 8` and `floor(7*10/4) = 17`. `n=37` and `n=38`
(`floor(64.75) = 64`, `floor(66.5) = 66`) are the sharpest pair, because they
straddle a power of two by one key.

**What 7n/4 *means* is unknown.** It is not `new HashMap<>(map)`, whose
`(int)(n/0.75f + 1.0f)` request is refuted at n=10; it is not `2 *
tableSizeFor(n)` applied to the final table, refuted at n=7, 13, 14 and 16; it
is not Hibernate's `CollectionHelper.mapOfSize`, refuted at n=10. It is written
down as the arithmetic that fits, not as an explanation.

### 1.3 A create that appends its own keys built its map for fewer of them

A provider that mirrors `access.token.claim` into `introspection.token.claim`
appends the mirror **after** the map has already been through the first table.
So the map was built for the *request's* key count and serialised at a larger
one, and the two counts give different answers. Eleven of twelve grown configs
come out the same either way; the twelfth, a request of four grown to six, does
not, because `access.token.claim` and `introspection.token.claim` land in one
final bucket and which of them the first table separated decides the order.

This **refines** the P5 handover's "appended rather than inserted". Appended is
right; what it does not say is that the appending happens after a pass the
appended key therefore misses.

**Whether the appended key misses that pass is itself measurable, and it was
nearly not measured.** The two spellings - the appended key goes through the
first table with the rest, or arrives behind it - agree on every configuration
small enough to be realistic. A 400,000-sample search over configs of ten keys
or fewer found no key set that separates them, because
`introspection.token.claim`'s bucket is in the *upper* half of the intermediate
table at every size in that range, so nothing can outrank it. They separate at
19 to 23 keys and at 38 to 47. Measured at 19 grown to 20: the appended key
stays behind its bucket-mate, so it **arrives after** the first table.

### 1.4 The corpus

495 measured (insertion order, served order) pairs, every one of them a mapper
`config` created through
`POST /admin/realms/master/client-scopes/{id}/protocol-mappers/models` and read
back from `GET .../protocol-mappers/models/{id}`. The model fits **495 of 495**.

| Sweep | Pairs | What it was for |
|---|---|---|
| the fourteen | 14 | F80's own claim, re-measured |
| permutations | 12 | two key sets in all six of their insertion orders |
| sizes 2-16, five permutations each | 50 | first fit |
| collide-here-not-there triples | 6 | the first decisive probe |
| random holdout | 52 | nothing fitted, and it found the model wrong |
| the A/B split at 7, 13, 14, 16 | 8 | refuted `2 * cap_sized` |
| every count from 1 to 50 | 300 | the four boundaries |
| random holdout, sizes 1-60 | 40 | nothing fitted, and it fits |
| grown by a mirroring create | 12 | §1.3 |
| the 19-to-20 discriminator | 1 | §1.3's last paragraph |

The 1-to-50 sweep contains, by accident, six probes with **60,000 keys** in one
`config` - an off-by-one in the probe's filler - and the model predicts all six.
The endpoint accepted them.

The non-mirroring provider used throughout is
`oidc-nonce-backwards-compatible-mapper`: one of the four registered providers
that mirrors neither `access.token.claim` nor `id.token.claim`, so the served
config holds exactly the keys the request sent and nothing was appended behind
them. The grown sweep uses `oidc-usermodel-attribute-mapper`, which mirrors
both.

### 1.5 `javamap.KeyOrder` gets seven of the fourteen wrong, not six

F80 says six. It counted a set of fourteen vectors that was never written down -
the P5 handover names five of them - so the number could not be reproduced. On
the fourteen in `javamap_test.go` it is **seven**, and the test pins that count
rather than a description.

The five the handover does name reproduce byte for byte on a second container a
week later, including the twelve-key one: inserted `k12..k01`, served
`k06 k05 k08 k07 k09 k11 k10 k02 k12 k01 k04 k03`.

### 1.6 Mutations run, and the two that survived

Fifteen mutations, each aimed at one named test, each confirmed failing that
test and reverted. Nine against `internal/javamap`, five against F72's guard,
and one that turned out to be an equivalent mutation.

| Mutation | Test that caught it |
|---|---|
| final table `capacity(n,n)` → `capacityFor(n)` | `TestSizedKeyOrderReproducesMeasuredMapperConfigOrders` |
| intermediate `7n/4` → `2n` | `TestSizedKeyOrderPinsTheIntermediateTableSize` |
| sort the input before bucketing | `TestSizedKeyOrderFollowsInsertionOrderInsideAChainAndNotOutsideOne` |
| `KeyOrder` uses the sized table | `TestKeyOrderIsWrongOnHalfTheMapperConfigs` |
| `capacityFor` starts at 4 rather than 16 | `TestSizedKeyOrderIsNotKeyOrder` |
| drop the defensive clone | `TestSizedKeyOrderDoesNotModifyItsInput` |
| the intermediate pass sees the appended keys | `TestSizedKeyOrderModelsAMapThatGrewAfterItWasBuilt` |
| the `builtFor` clamp becomes `builtFor < 0` | `TestSizedKeyOrderReadsAnImpossibleBuiltForAsTheWholeSlice` |
| `tableSizeFor`'s `<` → `<=` | `TestSizedKeyOrderPinsTheIntermediateTableSize`, and **only** that one |
| a golden appears for an undeclared Pending case | `TestEveryParkedGoldenIsDeclared` |
| a declared golden is removed from the tree | `TestEveryParkedGoldenIsDeclared` |
| a declared entry's reason is blanked | `TestEveryParkedGoldenIsDeclared` |
| a non-Pending case is declared | `TestEveryParkedGoldenIsDeclared` |
| a case that is not in the catalogue is declared | `TestEveryParkedGoldenIsDeclared` |

The five conformance mutations are five different branches of one test, which is
the point of listing them separately: a guard with four unexercised branches is
a guard with four places to be wrong.

**Two survivors, both reported rather than papered over.**

1. **`capacity(n, n)` → `capacity(n+1, n)` survives everything**, and it is
   right to: the two are the same function. `tableSizeFor(n+1)` differs from
   `tableSizeFor(n)` only when `n` is a power of two, and there the load factor
   doubles `capacity(n, n)` to the same value. An equivalent mutation, not a
   hole - recorded because the next person to try it will spend the same ten
   minutes.
2. **`TestSizedKeyOrderHandlesTheEmptyAndSingleCases` caught nothing.** No
   mutation of the model can fail it, because every model in play is the
   identity on nought and one key. It is a smoke test against a divide-by-zero
   or a mask of `0xFFFFFFFF`, and it should be read as one.

The third finding is not a survivor but is the same shape: **the fourteen
vectors do not pin `tableSizeFor`.** The `<` → `<=` mutation passes the fourteen
and fails only the boundary probes. A cut that had added the fourteen and
stopped would have shipped an unpinned rounding rule.

### 1.7 `internal/admin` needs a change this cut may not make

`internal/javamap` has five callers - `internal/token/claims.go` (three),
`internal/token/issue.go`, `internal/admin/rolemappings.go`,
`internal/admin/keys.go` - and every one of them calls `KeyOrder`, whose
behaviour is unchanged. Nothing breaks and nothing is wired to `SizedKeyOrder`.

What would use it is `internal/admin/protocolmappers.go`. Gloak stores a
mapper's `config` as a `model.StringMap`, an ordered slice, and serves it in the
order it was written; Keycloak serves it in `SizedKeyOrder`'s order. The two
coincide for the key sets the conformance cases use, which is why the goldens
assert real config bytes today, and diverge for a set as ordinary as
`{claim.name, jsonType.label, user.attribute}`.

**The wiring is not a one-liner, and that is the part worth handing over.**
`SizedKeyOrder` needs the count of keys the *request* carried, and Gloak does
not store it: `mapperConfig` (`internal/admin/protocolmappers.go:404`) appends
the mirrors into the same slice and the pre-mirror length is gone by the time
anything reads it. Either that count is persisted, or the mirrors are stored
apart from the request's keys, or the serialiser recovers the boundary from the
mirror rule - and the third is guesswork, because a request may send
`introspection.token.claim` itself, in which case nothing was appended at all.
Filed as F81 below rather than done here.

---

## 2. Entries for the documents this branch may not edit

### 2.1 `AGENTS.md`, "Things that look like bugs and are not" - replacing the javamap bullet

The bullet beginning **"Keycloak's JSON key order for a Java `Map` is `HashMap`
bucket order"** claims `internal/javamap` "reproduces it". It reproduces one of
the two constructors. Replace the first sentence and add the second paragraph;
the rest of the bullet is unchanged and still correct:

- **Keycloak's JSON key order for a Java `Map` is `HashMap` bucket order**, not
  sorted and not insertion order. **There are two constructors and
  `internal/javamap` models them separately.** `javamap.KeyOrder` is the
  no-argument one - 16 buckets, doubling at the 0.75 load factor - and is
  confirmed against six measured key sets: four in its own tests; the
  `clientMappings` of a combined role-mapping view, where six clients created
  and assigned `cx1..cx6` came back `cx6, cx5, cx2, cx1, cx4, cx3` and
  `internal/admin` pins it; and the `active` map of
  `GET /admin/realms/{realm}/keys`, `RSA-OAEP, HS512, RS256, AES` on both master
  and a created realm, which is the first confirmed vector with **no** bucket
  collision at all. It cannot resolve a bucket collision, because those chain in
  insertion order and nothing observable says what that was; the 21 admin role
  names collide twice and come back the other way round. Sorting instead is what
  makes `resource_access` come out `account, master-realm` where Keycloak says
  `master-realm, account`.
- **`javamap.SizedKeyOrder` is the other constructor, and it is not KeyOrder
  with a different number in it.** A protocol mapper's `config` passes through
  **two** tables, one asked for 7n/4 buckets and then one asked for n, and
  collisions in the second chain in insertion order rather than alphabetically.
  One table cannot fit the measurements: `{claim.name, jsonType.label,
  user.attribute}` comes back in one order from all six of its insertion orders
  while `{zz, aa, mm}` comes back in whichever order it went in, from all six.
  Read off the server at every entry count from 1 to 50, and the 7n/4 is
  measured rather than derived - the doubling it produces moves between n=9 and
  n=10, n=18 and n=19, and n=37 and n=38, and no plain multiple of n fits all
  three. `KeyOrder` gets seven of the fourteen measured mapper configs wrong and
  `TestKeyOrderIsWrongOnHalfTheMapperConfigs` pins that count, so the package
  cannot quietly start claiming both again.

### 2.2 `AGENTS.md`, same section - replacing the mapper `config` bullet

The bullet beginning **"A protocol mapper's `config` key order is a Java
`HashMap` sized to its entry count"** says `javamap.KeyOrder` "gets six of
fourteen measured vectors wrong" and that the table size is the only difference.
Both are now measured otherwise. Replace it whole:

- **A protocol mapper's `config` key order is two Java `HashMap`s, not one**,
  and `internal/javamap` models it as `SizedKeyOrder`: a table asked for 7n/4
  buckets, then one asked for n, collisions chaining in insertion order.
  `javamap.KeyOrder`, which models the no-argument constructor, gets **seven** of
  the fourteen measured configs wrong - the follow-up said six, from a vector set
  that was never written down. **And a create that appends a key of its own
  appends it after the first table**, so a config the create grew was built for
  the request's key count and serialised at a larger one; `SizedKeyOrder` takes
  that count as its first argument. Measured at 19 keys grown to 20, which is
  the smallest size at which the difference is visible at all. The conformance
  cases avoid all of this by using config key sets measured to be order-stable,
  so the goldens assert real config bytes with **no** `UnorderedKeys` retreat.

### 2.3 `AGENTS.md`, "Build and test" - the `make record` bullet gains a sentence

The bullet beginning **"`make record` leaves a `Pending` golden exactly as it
found it"** is correct and now under-counts. Append to it:

  **Seven Pending goldens are parked, not four.** The four login-theme pages are
  the ones that churned; the device, CIBA and dynamic-registration refusals are
  three more that had been parked without anybody counting them. All seven are
  declared in `parkedGoldens` (`case_test.go`) with the reason each is kept, and
  `TestEveryParkedGoldenIsDeclared` refuses an eighth that arrives without one -
  and refuses a declaration whose file has gone, or whose case is no longer
  Pending. A parked golden is a **measurement, not a contract**: read it for what
  Keycloak answered, never for what Gloak must serve. See F72.

### 2.4 `README.md` - two numbers in the "make record is silent" paragraph

The paragraph reading **"It rewrites 290 goldens with identical bytes and moves
none"** is right in kind and wrong in both numbers, and the paragraph after it
says "All four are `Pending`" where seven are. A whole `make record` on this
branch rewrote **327** and moved none. Suggested replacement for the two
paragraphs:

> **`make record` is silent on a clean checkout.** It rewrites 327 goldens with
> identical bytes and moves none, so any diff at all is one to read carefully.
>
> That was not always so. Four login-theme pages churned their whole body on
> every run, because the `/resources/<hash>/` segment is regenerated per
> container start, and the count went from three to four inside two days. Those
> four are `Pending`, so nothing compared them and the churn bought nothing. The
> recorder now leaves a `Pending` golden exactly as it found it; the way to ask
> for one back is to promote the case to `Recorded`, which is what `Recorded`
> already means. Seven `Pending` goldens are parked in all, each declared in
> `parkedGoldens` with the reason it is kept.

### 2.5 The observed spec's "Java map key order" section

It currently says the rule was "confirmed on four independent key sets" and
gives one capacity rule, "capacity 16 until 12 entries". That is the no-argument
constructor and is still right for the four key sets in its table. It needs a
paragraph saying it is one of two, pointing at §1.1 and §1.2 above for the
sized one, and the sentence **"A conformance case comparing a large key set has
to say so with `Case.Unordered`"** should gain "unless the map is a sized one,
where `javamap.SizedKeyOrder` reproduces it exactly".

---

## 3. Follow-up dispositions

### F80: closed

`internal/javamap` no longer claims to reproduce a map it does not. `KeyOrder`
is documented as the no-argument constructor and unchanged in behaviour;
`SizedKeyOrder` is the other one; the fourteen vectors are in the package's
tests, including the seven `KeyOrder` gets wrong, and the count is pinned.

**Both shapes the follow-up offered were taken, because neither alone was
enough.** Modelling the sized constructor is what makes the fourteen pass;
narrowing `KeyOrder`'s claim is what stops the two being confused, and no Go
function can decide between them from the keys alone - which constructor built a
map is a fact about the Java, so it is two exported functions rather than one
with a heuristic.

Fourteen of fourteen pass. So do 495 of 495 across every sweep taken.

### F72: closed - **they stay, and they are declared**

The four in the follow-up are seven. **Decided once, for all seven.**

A `Pending` case may carry a golden, and it has to say so in `parkedGoldens`.
What a reader is to do with such a file: **read it as a measurement and never as
a contract.** Nothing compares it, so it does not say what Gloak must serve and
it will not notice when Keycloak's answer moves. What it buys is the measured
status, headers and body of an endpoint this project has not built yet, without
a container and without Docker.

**Why not delete them.** The argument for deleting is that a golden nobody
compares looks like a contract. The answer this project already uses everywhere
else is to declare the exception with its reason rather than to remove the
thing - `Case.UnorderedKeys`, `VolatileHeaders`, `namedOutsideTheConvention` are
all that shape. A declared list buys what deletion buys, which is that nobody
mistakes the file for a contract, and keeps what deletion throws away, which is
four kilobytes of measured theme page that costs a container start to recover.
And the deletion permitted to this cut covers four of the seven, so deleting
would have left a rule with three exemptions where a declaration covers all
seven.

**Why not promote them to `Recorded` instead.** That is the right answer for a
golden worth comparing, and it stays the only way to ask for one: `Recorded`
means measured, committed, not served yet, and the verifier requires it *not* to
match. It is a one-word edit in `catalog_oidc_pending.go`, a file this cut may
not touch, and for the four theme pages it is not obviously right anyway - their
bodies carry a per-container `/resources/<hash>/` segment that no comparison can
survive.

**What the guard does.** `TestEveryParkedGoldenIsDeclared` fails on a `Pending`
case that grows a golden without an entry, on an entry whose file has gone, on
an entry naming a case that is no longer `Pending`, and on an entry naming
nothing in the catalogue. All four branches were shown failing before they were
shown passing, plus the empty-reason branch. It is not a ratchet: every parked
golden in the tree is declared today.

### The decline: `SizedKeyOrder` is not wired into `internal/admin`

Gloak still serves a mapper's `config` in the order it was written rather than
Keycloak's. Nothing regresses - the affected key sets are the ones no case uses,
and the conformance cases were built on order-stable sets for exactly this
reason - and the change is outside this cut's file set.

It is also **not the one-line call it looks like**. §1.7 has the detail: the
count `SizedKeyOrder` needs is the request's key count, and Gloak throws it away
at create time. Wiring it without that count would be right on eleven mapper
configs in twelve and wrong on the twelfth, which is the failure mode this
follow-up exists to end. Filed as F81.

### A second decline: `attributes` was not re-examined

The P5 handover suggested the suite's one documented retreat -
`Case.UnorderedKeys` over `attributes` - might be narrower than it looks, since
`attributes` was never checked against a sized-constructor model. It still has
not been, and this cut declines it: establishing it needs the *insertion* order
of a map whose insertion order is not observable on the bootstrapped objects
where the retreat is actually used, and the cases that would change are in files
this cut may not touch. Filed as F82 so that the next person does not have to
re-establish that it was a decision.

### New follow-ups to file

- **F81: a mapper `config` is served in the order it was stored, not Keycloak's.**
  `internal/javamap.SizedKeyOrder` exists and nothing calls it.
  `internal/admin/protocolmappers.go` would, except that it needs the count of
  keys the create request carried and `mapperConfig` discards it when it appends
  the mirrors. Three ways out - persist the count, store the mirrors apart, or
  recover the boundary from the mirror rule - and the third is guesswork,
  because a request may send `introspection.token.claim` itself. Nothing is
  broken today because every conformance case uses an order-stable key set.
- **F82: `attributes` has never been tried against the sized model.** AGENTS.md
  calls `UnorderedKeys` "the only such retreat"; whether it is still needed is
  now a question with a second candidate answer. See the decline above for why
  it is hard rather than merely undone.
- **F83: nothing explains 7n/4.** It fits 495 measurements at every entry count
  from 1 to 50 and matches no `HashMap` constructor anybody has identified -
  `HashMap(Map)`, `2 * tableSizeFor(n)` and Hibernate's `mapOfSize` are each
  refuted by a different measured size. It is a fitted constant with four
  boundary points holding it, which is enough to serve bytes from and not enough
  to reason from. If somebody reads the Java, the thing to check is what number
  the mapper `config` copy is constructed with.

### Bearing on existing follow-ups

- **F69 re-verified.** A whole `make record` on this branch left all seven
  parked goldens byte for byte and moved nothing at all.
- **F79** (two providers seed config keys of their own) gains a neighbour rather
  than a change: §1.3's finding is about *when* the seeded keys arrive, not
  which ones.

---

## 4. Parity before and after

Unchanged, and it is the strict form rather than the flat one:

```
Parity: 205 of 499, no change.
```

Measured with the recipe in AGENTS.md's "Build and test": `GLOAK_PARITY_REPORT`
on this branch and on the merge base `a308eb0`, compared with `cmd/parity`,
which exited 0.

Nothing here serves a new behaviour. `internal/javamap` is not on any request
path yet, `KeyOrder`'s behaviour is byte for byte what it was, and the
conformance change is one test and one comment. No case changed status, no
golden moved, and `CGO_ENABLED=0 go test ./...` is clean without Docker or the
network.
