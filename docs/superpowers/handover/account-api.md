# The account API: a chapter enumerated, a gate served, and a ratchet that was right about the wrong family

The `account` chapter had no denominator. Its declared reason was *"the account
REST API is not described by the Admin API document and has not been enumerated"*,
and that sentence had been true since the parity meter was built.

This cut removes it. The surface is enumerated against a live Keycloak 26.7.1 -
**16 route shapes, 112 verb cells, 40 catalogued behaviours** - and the gate plus
its two derived reads are served. Everything else is measured and deliberately
not served, and section 4 gives the measurement behind each refusal.

**This is the third session on the branch.** Two ended mid-change and their work
was committed unreviewed. Section 7 says which of their claims were verified,
which were re-measured, and which were wrong.

## 1. What was inherited and what was re-measured

The governing rule applies to inherited work as much as to new work: **a
measurement you did not make is a claim, not a fact.** The branch arrived with
seven commits, two of them explicitly unreviewed checkpoints.

| Claim | Source | Status |
|---|---|---|
| The account client ships eight roles including `view-profile` | inherited | **re-measured**, confirmed |
| `bearerToken`'s sixteen-row `Authorization` table | checkpoint `d8a74f0` | **re-measured**, all sixteen reproduce |
| The enumeration's *method* (the two-404 discriminator) | inherited | **re-measured, refuted** - section 2 |
| 16 route shapes | inherited | **re-measured**, confirmed |
| "36 behaviours" (commit subject) | inherited | **counted, wrong** - the slice held 39 |
| "41 counted behaviours" (file heading) | inherited | **counted, wrong** |
| "Seventeen paths ... 119 cells" | inherited | **wrong**: 16 shapes is 112; the 17th was the sweep's own control |
| `account-user` is "named by seven cases" | checkpoint `bbbf3e3` | **counted, wrong** - it is 21 |
| `PATCH /account/resources` is 403 where PATCH is 405 elsewhere | inherited | **re-measured**, confirmed |
| `OPTIONS` is 200 with no `Allow` and no `Content-Type` | inherited | **re-measured**, confirmed |
| `DELETE /account/sessions/{unknown}` is 204 | inherited | **re-measured**, confirmed |
| `PUT .../credentials/{id}/label` is `Credential not found` where `GET` on the same path is generic | inherited | **re-measured**, confirmed |
| `GET .../linked-accounts/{unknown}` is 400 with an unresolved i18n key | inherited | **re-measured**, confirmed |
| `POST .../applications/{id}/consent` is 415 `No supported MessageBodyReader found` | inherited | **re-measured**, confirmed |
| The sessions golden is order-dependent | checkpoint note | **confirmed**, and the stated fix was wrong - section 3 |
| Two catalogue cases cited by `bearerToken` | checkpoint `d8a74f0` | **did not exist**; one now does, one cannot - section 5 |
| `account/linked-accounts/none` answers `[]` | inherited golden | **refuted by `make record`** - sixteen rows on the shared container, section 8 |
| The `unlistedProviderIDs` table | inherited | **re-measured**, confirmed, and given the input that makes it falsifiable |
| `make lint` is clean | implied | **was red**: `account_test.go` was unformatted |

Everything in section 2 came from `quay.io/keycloak/keycloak:26.7.1 start-dev`
on 2026-09-07, on a container started clean for this session. The previous
sessions' container was gone with the daemon and was not reused: a container
written to by an unknown sequence of probes is not a clean measurement surface.

## 2. The enumeration, and why the SAML method does not transfer

### 2.1 The two-404 discriminator does not hold on this surface

`p11-saml-descriptor.md` enumerated a chapter with no document by sweeping
candidate paths against Keycloak's own pair of 404s: an unmatched path answers
`Unable to find matching target resource method` with none of the five security
headers, and a path the router knows answers `HTTP 404 Not Found` with all five.

The inherited catalogue header claimed the same method worked here, once the
request carried `Accept: application/json`. **It does not.** Measured on one
container with one fully-privileged account user:

```
GET /realms/master/account/nosuchthing          404  HTTP 404 Not Found        5 of 5
GET /realms/master/account/credentials/bogus    404  HTTP 404 Not Found        5 of 5
GET /realms/master/nosuchthing                  404  HTTP 404 Not Found        5 of 5
GET /nosuchthingatall                           404  Unable to find matching…  0 of 5
```

A path that exists and a path that does not answer the **same body with the same
five headers**. The unmatched-path body is not reachable anywhere under
`/realms/`, which is exactly what F184 records - and this chapter sits inside
F184's shape, so the discriminator the SAML cut relied on is the one thing this
chapter cannot borrow.

What the `Accept` header buys is real but different: without it, **every** path
under `/account` answers 200 with the console's markup, including paths no route
serves, so a sweep run without it finds an infinite surface. `Accept` selects the
JSON branch. It does not restore the discriminator.

### 2.2 What actually enumerated it

A weaker test, and it has to be stated because it is weaker: **a route exists
when at least one verb answers outside the generic fallback family** - a 200, a
204, a 400, a 403, a 415, a 500, or a 404 carrying its own sentence rather than
`HTTP 404 Not Found`.

`OPTIONS` is excluded and the exclusion is load-bearing: it answers **200 with an
empty body on every path**, including `/account/nosuchthing`. An enumeration that
counted an OPTIONS 200 as evidence of a route would have accepted every candidate
it tried.

### 2.3 The sweep

Sixteen route shapes crossed with seven verbs, plus `/account/nosuchthing` as the
control - `GET POST PUT DELETE PATCH HEAD OPTIONS`, `Accept: application/json`,
a token holding all eight account roles so the gate never hides a route:

```
/account                                 GET 200   POST 500  PUT 404g DEL 404g PATCH 405 HEAD 200 OPT 200
/account/credentials                     GET 200   POST 405  PUT 404g DEL 404g PATCH 405 HEAD 200 OPT 200
/account/credentials/{id}                GET 404g  POST 405  PUT 404g DEL 404* PATCH 405 HEAD 405 OPT 200
/account/credentials/{id}/label          GET 404g  POST 405  PUT 404* DEL 404g PATCH 405 HEAD 405 OPT 200
/account/credentials/{id}/moveToFirst    GET 404g  POST 405  PUT 404g DEL 404g PATCH 405 HEAD 405 OPT 200
/account/credentials/{id}/moveAfter/{id} GET 404g  POST 405  PUT 404g DEL 404g PATCH 405 HEAD 405 OPT 200
/account/sessions                        GET 200   POST 405  PUT 405  DEL 204  PATCH 405 HEAD 200 OPT 200
/account/sessions/devices                GET 200   POST 405  PUT 405  DEL 204  PATCH 405 HEAD 200 OPT 200
/account/sessions/{id}                   GET 404g  POST 405  PUT 405  DEL 204  PATCH 405 HEAD 405 OPT 200
/account/applications                    GET 200   POST 404g PUT 404g DEL 404g PATCH 405 HEAD 200 OPT 200
/account/applications/{clientId}/consent GET 404*  POST 415  PUT 415  DEL 404* PATCH 405 HEAD 404 OPT 200
/account/groups                          GET 200   POST 404g PUT 404g DEL 404g PATCH 405 HEAD 200 OPT 200
/account/linked-accounts                 GET 200   POST 405  PUT 405  DEL 404g PATCH 405 HEAD 200 OPT 200
/account/linked-accounts/{alias}         GET 400   POST 405  PUT 405  DEL 400  PATCH 405 HEAD 400 OPT 200
/account/resources                       GET 403   POST 403  PUT 403  DEL 403  PATCH 403 HEAD 403 OPT 200
/account/supportedLocales                GET 200   POST 404g PUT 404g DEL 404g PATCH 405 HEAD 200 OPT 200
--- control ---
/account/nosuchthing                     GET 404g  POST 404g PUT 404g DEL 404g PATCH 405 HEAD 405 OPT 200
```

`404g` is the generic `HTTP 404 Not Found`; `404*` is a 404 carrying its own
sentence. Twenty-three further candidates were tried and every verb answered the
fallback family: `/totp`, `/password`, `/organizations`, `/profile`,
`/attributes`, `/metadata`, `/devices`, `/consents`, `/roles`, `/realm`,
`/logout`, `/login-redirect`, `/credentials/password`, `/user-profile-metadata`
among them.

**Most of the sweep is the generic fallback family** and those cells are not in
this chapter's denominator - `http/fallback` counts them once for the whole API,
and counting them per path would report two behaviours ninety-odd times. That is
the SAML cut's decision, and it is the one part of its method that does transfer.

**Two cells that look like fallback are counted, because they are not.**
`PATCH /account/resources` is **403** where `PATCH` is 405 on every other path
here, so the realm's UMA gate is judged before the method is dispatched. And
`OPTIONS` is a **200 with an empty body, no `Allow` header at all and no
`Content-Type`** - which is neither the SAML family's OPTIONS, which carries an
`Allow`, nor any 405. Its header set is four of the five, missing
`X-Frame-Options`, which is AGENTS.md's measured rule for an OPTIONS 200 met on
a third API.

### 2.4 The count

```
 112   16 route shapes x 7 verbs
   7   the control path, not a route
 ---
 119   cells issued
```

and **40 catalogued behaviours**, which is the chapter's denominator.

**Three numbers disagreed and nothing could fail on any of them.** The commit
subject said 36, the file's own heading said 41, the slice held 39, and a
paragraph said seventeen paths where the list above it had sixteen. The count is
now `accountChapterCases` in `catalog_test.go` and
`TestAccountChapterCountIsThePinnedNumber` reads the slice, so the heading's
number is asserted rather than trusted. This is AGENTS.md's own repeated finding
- "a count in prose beside the list it counts will drift" - and it drifted three
ways inside one chapter before anybody had merged it.

## 3. The sessions fixture: the diagnosis was half right

The first session's note read: *the sessions golden is order-dependent, because
repeated logins run against a shared fixture, and the fix in progress is to give
it a realm of its own.*

**The first half is right and the arithmetic proves it.** `account-user` creates
`gloak-probe-account-user` and logs it in; the recorder runs a fixture once per
case naming it, against one shared container; every login is a session
`GET /account/sessions` then answers. Ten `account-user` cases sit ahead of the
listing in catalogue order, so the first recording held eleven rows. A later
commit inserted `account/gate/wrong-scheme`, an eleventh, and the next recording
held twelve - and `"current":true` moved from index 6 to index 3. A golden whose
length is a function of the catalogue's contents is exactly what AGENTS.md calls
"a golden that holds only while the catalogue's order holds".

**The second half is wrong, and so was the fixture comment that justified it.**
A realm of its own is not needed: `/account/sessions` is scoped to the subject,
so a **user** of its own is sufficient and is what the checkpoint actually built
(`account-user-sessions`). No realm is created and the case still addresses
`master`. The note described a fix that was not the one in the tree.

**And the fix was never finished.** `bbbf3e3` changed the fixture and re-recorded
the golden in one commit, but the golden it committed still held twelve rows -
the pre-swap shape. The recording that produced it was made under the old
fixture. Nothing could catch this: `account/sessions/list` is `Recorded`, and a
`Recorded` case is required *not* to match, so it does not match either way.
**That is the hole this cut walked into from the other side**, and it is the same
hole F113 records for `Pending` goldens: a status whose contract is "must not
match" makes any wrong golden invisible.

The fixture comment also said `account-user` is "named by seven cases". It is
named by **21**. The wrong number made the problem look smaller than it was -
seven logins is a plausible accident, twenty-one is a structural one.

Resolved by re-recording. The golden now holds the one session the fixture's own
login makes, which is what the case's `Volatile` comment had described all along.

## 4. What is served and what is refused

Served: the gate, `GET /account/groups`, `GET /account/linked-accounts`.

### 4.1 The gate is two stages and the statuses are the finding

A caller whose token grants **no role at all on the realm's `account` client** is
**401**, not 403. A caller past that stage holding the wrong account role is
**403**. Two stages, two statuses, and a single-stage gate answers one of them
wrong on every request.

The role sets are per route and neither is predictable from the route's name:

```
GET /account/groups           view-groups  or manage-account
GET /account/linked-accounts  view-profile or manage-account
```

**`manage-account-links` is refused by `/linked-accounts`** - measured - although
it is the one account role whose name matches the route. A guard written from the
name is wrong in both directions, and `account/gate/links-role-opens-nothing` is
the case that says so.

### 4.2 The refusals, each with its measurement

Every one is `Recorded`: measured, deliberately not served. The measurement is in
the case's `Reason`; the reason it is a refusal rather than a gap is here.

- **`supportedLocales`** - the realm's locales come back in **stored order** and
  `internationalizationEnabled` does not gate them, measured with the flag off
  and on. Gloak stores no locales at all: `realmReducedRepresentation` sends a
  constant `[]`. A handler here could only return that constant, would match a
  golden recorded against master, and would be wrong on every realm that has
  locales. That is the corpus-with-no-discriminating-case shape, and the fixture
  deliberately builds a realm with four **unsorted** locales and the flag off so
  the case that eventually serves it cannot pass by accident.
- **`/account` (the profile)** - the body is the user plus a
  `userProfileMetadata` block, the same derivation `GET /users/profile/metadata`
  performs. AGENTS.md records that as a real derivation a constant used to pass.
  Sharing that serialiser needs the two shapes measured to agree, which they are
  not.
- **`credentials`** - the body is the realm's credential **provider metadata**,
  not the user's credentials: two entries with categories, i18n display names,
  help text, icon classes and actions. The user's own credential nests inside the
  first.
- **`sessions`** - five fields nothing in Gloak's store holds: `ipAddress`,
  `started`, `lastAccess`, `expires` and a per-client breakdown.
- **`applications`** - `inUse` and `offlineAccess` come from live and offline
  client sessions, which Gloak's session store does not distinguish.
- **`resources`** - user-managed access is off on every realm a default install
  has, so the 403 is the contract rather than a stub, the same situation as
  `client-types`' 501.
- **`console`** - a theme resource, and the themes chapter is not enumerated.
- **`dispatch/unknown-subpath-json`** - F184's shape, and deliberately not fixed
  here: Gloak answers the header-less unmatched-path body where Keycloak answers
  `HTTP 404 Not Found` with all five. Fixing it means a wildcard dispatcher under
  `/account`, which is a cut of its own and which F184 says should be done once
  for the whole `/realms/{realm}/` tree rather than a fourth time per family.
- **`dispatch/accept-unparseable`** - `Accept: xyz` is a **500 unknown_error**.
  Reproducing it needs a media-type parser whose only consumer is this refusal.
- **`dispatch/options`** - F31, and not this chapter's to change.
- **`gate/scope-filtered-token`** - the one refusal that is a **Gloak
  divergence** rather than an unserved behaviour. Gloak's token path does not
  implement `fullScopeAllowed`, so the client's filter is ignored, the account
  roles reach the gate and Gloak answers 200 where Keycloak answers 401. It is a
  defect in `internal/oidc`, recorded here because this is the request that
  exposes it. See F192.

### 4.3 Three new spellings this API adds

- `{"errorMessage":"identityProviderNotFoundMessage"}` - an **unresolved i18n
  message key on the wire**, 400, from `GET .../linked-accounts/{unknown}`.
- `{"errorMessage":"No client with clientId: x found."}` - interpolates the
  request's own value and carries a full stop, and is on none of the Admin API's
  thirty-six.
- `{"error":"No supported MessageBodyReader found"}` - 415, and it fires
  **before** the client is resolved, which is client registration's order and not
  the Admin API's.

## 5. The `Authorization` header, and one case that cannot exist

`d8a74f0` changed `bearerToken`'s behaviour and wrote a sixteen-row measured
table into its doc comment, citing two catalogue cases -
`account/gate/double-space-scheme` and `account/gate/leading-space-scheme` -
**neither of which existed**.

The table itself is right. All sixteen rows were re-issued against a fresh
container and all sixteen reproduce: the scheme folds case; exactly one space
separates it from the token, so `Bearer  <t>`, `Bearer   <t>` and `Bearer\t<t>`
are 401; whitespace around the whole value is ignored; `Bearer <t> extra` and
`Bearer, <t>` are 401.

`account/gate/double-space-scheme` now exists. The space is **inside** the field
value, so no HTTP stack removes it, and the case kills the mutation that found
the rule - a `strings.TrimSpace` over the part after the first space, which
passes every other case on this API.

**`leading-space-scheme` cannot exist, and that is a measured refusal rather than
an omission.** A leading or trailing space is optional whitespace around the
field value and a conformant receiver strips it before any handler runs:

```
client sets       Authorization = " Bearer tok"
server over a socket sees        "Bearer tok"
in-process handler sees          " Bearer tok"
```

So a conformance case would compare 200 against 200 for two different reasons -
the recorder's Keycloak never sees the space, and the verifier's Gloak sees it
and trims it. It would be a case measuring the harness. The outer `TrimSpace` in
`bearerToken` is therefore defensive rather than measured, and it is documented
as such. See F191.

## 6. The ratchet failure, and what it says about written arguments

`TestNoGoldenHoldsAnObjectItDidNotCreate` failed on
`admin/clients/evaluate-scope-mappings-granted`:

```
golden holds name "view-profile", which "account-user-realm-role-collision" created
- neither this case's fixture nor its own request makes it, so the verifier
cannot reproduce this body
```

### 6.1 The message was false in both of its claims

The golden's `view-profile` carries `"clientRole":true` and a `containerId` that
is a client UUID. It is one of the eight roles Keycloak bootstraps on the
`account` client - measured on an untouched container:

```
account client roles:  delete-account manage-account manage-account-links
                       manage-consent view-applications view-consent
                       view-groups view-profile
master realm roles:    create-realm uma_authorization default-roles-master
                       admin offline_access
```

The golden was committed in `77529c7`, months before this branch existed. And
"the verifier cannot reproduce this body" was false of a case `TestConformance`
serves green.

`pollution()` matches the bytes `"name":"view-profile"` and has no way to tell a
realm role from a client role, or a fixture's object from one the product ships.
It reports a **name** while claiming to report an **object**.

### 6.2 The written argument was precise, checkable, and about the wrong family

The author foresaw the ratchet and wrote nine lines in `catalog_test.go` arguing
that the name could not reach any golden's window: the only realm-role listing on
the shared container is `admin/roles/list-realm-page-no-search`, which sends
`first=1&max=2` on a sorted listing, and `view-profile` sorts outside it.

**Every clause of that is true.** It was checked again rather than adopted, and
the stronger statement holds too: all six goldens that enumerate a realm's realm
roles are `PristineRealm`, so each is recorded against a container this fixture
never touches. Thirty-eight shared-container goldens hold realm roles and every
one of them holds either a specific mapped role its own fixture made or a paged
window that was argued.

And it addressed nothing. **No realm-role listing was involved at any point.**
The argument enumerated the family the fixture writes into and the failure was in
the family the *name* collides with.

This is the shape this repository keeps meeting - a rule right on one family and
inverted on its neighbour - with a twist worth naming: here the two families are
not neighbours in the route table, they are neighbours **in a string**. Nothing
about `view-profile` the realm role and `view-profile` the client role is related
except eleven bytes, and the guard's matcher is exactly eleven bytes wide.

### 6.3 The precedent had never been exercised

`namedOutsideTheConvention` already held one product name: `name manage-realm`,
the impostor caller's client role deliberately named after an admin role. Its
declared reason is about the fixture being load-bearing, not about goldens.

**No golden holds `"name":"manage-realm"`.** The entry has been lucky, not safe,
and would fire the day any golden enumerates `master-realm`'s 21 roles. The
account entry copied the precedent's shape and the precedent had never been
tested. A declaration that has never been exercised is a declaration nobody has
checked, and this file now has two of them where it thought it had one.

### 6.4 The fix

Three options were on the table: exempt the case, teach `pollution()` to
distinguish a realm role from a client role, or find a different input.

**The third was ruled out by measurement.** The mutation the fixture kills is the
one that drops the container test from `accountGrants`. To kill it, a subject
must hold a non-account role named exactly like an account role - so the name
*must* be one of the eight. Putting the role in another realm or on another
client does not help, because the guard matches names globally.

**The first was rejected as untrue.** A case-level exemption says "this golden
may hold a polluted object". The golden holds a bootstrapped object, and the
exemption would mask a genuine future pollution of the same file.

**The second was taken, in a more general form than "realm role versus client
role".** The invariant the guard enforces has three sources - bootstrap, the
case's own fixture, and the case's own request - and only the last two were ever
implemented. `pollution()` now takes the set of names a bootstrap-only handler
already answers and declines to judge them.

The oracle is **Gloak's own bootstrap, read through the handler the verifier
serves**, not a list copied out of `internal/bootstrap`. That is the right oracle
rather than a convenient one: the question the guard asks is "can the verifier
reproduce these bytes", and the verifier serves exactly that handler. A copied
list would answer a different question and would drift from it.

The match is deliberately the same byte comparison `pollution` makes. If a
listing bootstrap produces on its own contains the exact bytes the guard would
report, those bytes are not evidence that a fixture's object leaked.

**This does not make such a name safe - it makes it unjudgeable there.** What
judges it is `TestEveryCreatedObjectCarriesTheProbePrefix`, which forces any
created object bearing a product name to be declared with an argument. The two
ratchets compose, and the declaration was rewritten to say what is actually true
rather than what the window argument said.

`createdObjects()`' own doc comment had foreseen this exact failure: it refuses
to read a POST whose body is a JSON array because that "would put six
bootstrapped admin role names into the set and make this test fail on any golden
that legitimately lists one". That rule closed the route by which a bootstrapped
name arrives **without being created**. A fixture that deliberately creates an
object under a name the product ships is the other route, and it was not
foreseen. The remedy was written down two years of commits before the hazard
arrived by its second door.

## 7. The two checkpoints

Neither was reviewed when committed. Both were read line by line.

**`bbbf3e3`** added three gate cases, the sessions fixture swap, the
`view-profile` declaration and two fixtures. Its cases and fixtures are sound.
Its two defects are in section 3: the golden it re-recorded was the pre-swap
shape, and its "seven cases" count was wrong by a factor of three.

**`d8a74f0`** changed `bearerToken`, rewrote its test table and corrected two
comments in `reads.go`. The behaviour change is **correct and confirmed by
re-measurement** - see section 5. Its three defects: the dangling case citations;
a comment claiming a divergence in `internal/admin`'s own `bearerToken` (that the
admin API folds the scheme's case and `internal/admin` does not), which is
**inherited and not re-measured here** because it is about a different package
and a different chapter and is filed as F193 rather than acted on; and it left
`internal/account/account_test.go` **unformatted**, so `make lint` was red on the
branch independently of the failing test. AGENTS.md records `gofmt` reaching
`main` once before "found by somebody reading a diff, since no step existed that
could have caught it" - a step exists now, and this is the first time it has
caught something.

**Neither checkpoint's own claim about itself was reliable.** `bbbf3e3` said it
was checkpointing the sessions fixture and committed a golden that contradicted
the fixture it had just written; `d8a74f0` said "the sessions-fixture problem the
previous checkpoint names is still open as far as anything here shows", which was
true and is the only self-assessment in either that held. When reading a
checkpoint, the commit message is the least reliable part of it.

## 8. `make record`, and what reading the diff found

Four full recordings were run. The instruction to **read the diff** paid for
itself on the first one.

**Run 1** moved three files, all inside this chapter. Two were expected:
`sessions/list` collapsed from twelve rows to one, and
`gate/double-space-scheme` was new. The third was not.

**`account/linked-accounts/none` moved from `[]` to sixteen rows** - every
`gloak-probe-idp*`, `gloak-probe-map-broker-*` and `gloak-probe-mt-broker-*` the
admin chapter's fixtures create in master before the account cases run. The `[]`
it had held could only have come from a run that recorded the account chapter
alone, so it was a golden that held while the *recording's scope* held, which is
a weaker thing even than holding while the catalogue's order does.

The hazard was known and defended on the wrong half of a pair.
`accountBrokerFixture` builds a realm of its own precisely "because four identity
providers in master would appear in every golden that enumerates the realm's
own"; the case that **creates** providers was protected and the case that asserts
there are **none** was left addressing master. That is the same "right on one
family, inverted on its neighbour" shape as section 6, this time between two
sibling cases forty lines apart.

Fixed with `PristineRealm`. The pollution guard could not have caught it - see
F195.

**Run 2**, after that fix, moved nothing.

**Run 3** *failed*, and the failure was the issuer collision described in section
9. Nothing was recorded.

**Run 4**, after splitting the broker fixture, moved nothing. That is the run the
branch carries: `make record` is clean, and **no golden outside this chapter has
moved at any point**.

## 9. The mutation pass

Run over the whole cut, not only over what this session added, with a harness
that reads `go test`'s exit code before its output and refuses a mutation whose
diff is empty or which fails to build. Both have produced false passes here.

Twenty mutations, each applied, confirmed to make the **named** test fail,
reverted, and the revert verified. `TestConformance/account` runs in ten seconds,
which is what makes a pass at this granularity affordable.

**The harness earned its refusals.** Six of the twenty first attempts were
rejected before their result was read: five did not compile - four of them
because removing a condition left a variable unused, which is Go turning a
behavioural mutation into a build error - and one matched no bytes because its
indentation was wrong. Every one of those would have looked like a failing test
and therefore like a killed mutation. All six were reformulated so that they
compile and change behaviour, and re-run.

Killed, with the case that killed each:

```
M1b  scheme compared case-sensitively      gate/lowercase-scheme
M2   a space inside the value allowed      gate/double-space-scheme
M3   the !user.Enabled check removed       gate/disabled-user
M4b  grants not reduced by container       gate/realm-role-of-the-same-name
M5   no grants is not a 401                gate/no-account-roles, gate/realm-role-of-the-same-name
M6b  any non-empty scheme accepted         gate/wrong-scheme, gate/double-space-scheme
M7   the groups guard opened               gate/wrong-role-groups
M8   manage-account dropped from it        gate/lowercase-scheme, groups/none, groups/member
M9   the linked-accounts guard opened      gate/wrong-role-linked-accounts, gate/links-role-opens-nothing
M10b that guard reads manage-account-links gate/links-role-opens-nothing
M11  the `enabled` filter removed          linked-accounts/providers
M13  sorted by display name, not alias     linked-accounts/providers
M14b the social display-name fallback cut  linked-accounts/providers
M15d `social` always false                 linked-accounts/providers
M16  groupPath's separator changed         groups/member, groups/child-only
M17  subGroups nil instead of []           groups/member, groups/child-only
M18  pollution ignores bootstrap's names   TestPollutionGuardIgnoresNamesBootstrapShips
M19  the account chapter's count unpinned  TestAccountChapterCountIsThePinnedNumber
```

M4b is the one that justifies the whole `view-profile` collision: it makes
`accountGrants` stop reducing by the role's container, and only
`gate/realm-role-of-the-same-name` notices. Without that fixture the gate would
hand the account API to anybody who can mint a realm role, and nothing would say
so.

### One survivor, and the input that kills it

**M12 - deleting the `unlistedProviderIDs` filter - survived the entire
chapter.** Every provider the broker fixture created was one the listing shows,
so removing the filter changed no byte of any golden. That is AGENTS.md's second
named shape exactly: *a set of inputs an incorrect implementation satisfies
entirely*, a corpus with no discriminating case.

It was not left as a survivor. The two provider types the listing omits were
measured creatable and measured absent:

```
POST .../identity-provider/instances  kubernetes                201
POST .../identity-provider/instances  jwt-authorization-grant   201  (needs an issuer)
admin identity provider listing:      all three present
account linked-accounts:              only the oidc one
```

`accountBrokerFixture` now creates both. They add **no row** to the golden -
which is what they are there to assert, and `make record` confirmed it by moving
nothing - and there is one per entry in the table. Re-run after the fixture
change, all three forms are killed by `linked-accounts/providers`:

```
M12b  the whole filter deleted            KILLED
M12c  only the kubernetes entry deleted   KILLED
M12d  only the jwt-grant entry deleted    KILLED
```

**No survivors.**

### The fixture change found a behaviour of its own

Adding the two providers made `make record` fail, which is the useful kind of
failure:

```
POST .../identity-provider/instances  -> 400
{"errorMessage":"Issuer URL already used for IDP 'gloak-probe-k8s', Issuer must
be unique if the idp supports JWT Authorization Grant or Federated Client
Authentication"}
```

**A repeated `kubernetes` create is a 400 about the issuer, not the 409 about the
alias that every other create in this fixture answers.** A kubernetes provider's
issuer is server-filled and constant -
`https://kubernetes.default.svc.cluster.local` when the create names no config -
and the **issuer-uniqueness check runs before the alias check**, so the repeat
collides with itself. `idempotentCreate` does not cover it.

Widening the step's `ExpectStatus` to accept 400 was the smaller diff and is the
wrong one: `Issuer is required` is a 400 on the same route, so a step that
accepted it would pass while creating nothing, and the mutation these two rows
exist to kill would survive again with the fixture looking green. That is a false
pass built deliberately. Instead the pair lives in
`account-user-brokers-unlisted`, a fixture named by **exactly one case**, so the
create happens once and the 400 is never reached. Both broker fixtures build the
same realm and the same four brokers idempotently, so either may run first.

## 10. Parity

Base, on `main` at `f252858`:

```
549 of 580 enumerated behaviours served; 3 chapters not enumerated
```

Head:

```
567 of 620 enumerated behaviours served; 2 chapters not enumerated
```

**+18 served, +40 denominator, and one fewer unenumerated chapter.** The
denominator moves by exactly the chapter's 40 cases and the numerator by its 18
`Implemented` ones, so the two numbers are the same fact counted twice - which is
the check worth doing, because a numerator that moved by anything else would mean
a case outside this chapter had changed status.

The remaining two unenumerated chapters are `themes` and `management`, and
neither is this cut's.

Per chapter:

```
account/gate                13 of 14
account/groups               3 of 3
account/linked-accounts      2 of 3
account/supported-locales    0 of 2
account/profile              0 of 2
account/credentials          0 of 3
account/sessions             0 of 2
account/applications         0 of 4
account/resources            0 of 2
account/console              0 of 2
account/dispatch             0 of 3
```

The gate is the chapter: thirteen of the eighteen served behaviours are it, which
is the shape a reader should expect from an API whose interesting part is who may
call it. **The parity total does not fall.**

## 11. What belongs in AGENTS.md

Phrased as it would be folded.

- **The account API's gate is two stages with two statuses, and the second is
  per route.** A token granting no role on the realm's `account` client is
  **401**; a caller past that stage holding the wrong account role is **403**. A
  single-stage gate is wrong on every request of one of the two kinds. The role
  sets do not follow the route's name - **`manage-account-links` is refused by
  `/linked-accounts`**, the one route whose name matches it.

- **The two-404 discriminator does not work under `/realms/{realm}/`, and that
  is what makes a surface there unenumerable by the SAML cut's method.** A path
  that exists and a path that does not both answer `HTTP 404 Not Found` with all
  five security headers; the unmatched-path body is reachable only outside
  `/realms/`. What enumerates such a surface is weaker and has to be said: a
  route exists when at least one verb answers outside the generic fallback
  family, with **`OPTIONS` excluded**, because it answers 200 on every path
  including ones that do not exist.

- **A whole API can hide behind `Accept`.** Every path under
  `/realms/{realm}/account` answers 200 with the console's markup to a request
  that did not ask for JSON, including paths no route serves. The REST resource
  is reached exactly when the parsed accept list holds `application/json` **with
  no parameters** - `application/json;q=1` is the console, although `q=1` is the
  default and changes nothing about the request's meaning. A sweep written
  without that header measures an infinite surface.

- **The pollution guard reports a name and claims an object, and bootstrap is
  the third source it never had.** A golden may hold what bootstrap, the case's
  own fixture and its own request produced. Matching a created object's name
  against a golden's bytes cannot tell a fixture's object from one the product
  ships, and on 2026-09-07 it named a fixture for the `account` client's built-in
  `view-profile`. **Two entries in `namedOutsideTheConvention` take a product
  name and only one has ever been exercised** - no golden holds
  `"name":"manage-realm"`, so that entry is lucky rather than safe.

- **A `Recorded` golden that is wrong is invisible**, for the same reason F113
  gives for `Pending` ones: the case is required *not* to match, so a golden
  recorded against the wrong fixture does not match either way and nothing
  fails. The sessions golden carried the pre-fix shape through two commits on
  exactly that. When a fixture changes under a `Recorded` case, the re-record is
  the only thing that can be checked, and nothing checks that it happened.

- **A case whose two sides agree for different reasons is measuring the
  harness.** A leading space in `Authorization` is optional whitespace: a real
  socket strips it before the server sees it and an in-process handler does not.
  A golden for it would compare 200 against 200 with neither side exercising the
  rule. Before adding a case for a header's whitespace, check whether the
  transport removes it.

- **A repeated identity provider create is not always a 409, and which check
  fires first decides.** A second `kubernetes` create under a name the realm
  already holds answers `400 Issuer URL already used for IDP '<alias>'`, because
  the issuer-uniqueness check runs **before** the alias check and that provider's
  issuer is the server-filled constant
  `https://kubernetes.default.svc.cluster.local`. So `idempotentCreate` does not
  cover every create, and widening a step to accept the 400 would also accept
  `Issuer is required` - a fixture that passes while creating nothing.

## 12. Follow-ups

Numbered from F190. F171-F189 are taken.

### F190: why does the linked-accounts listing omit two enabled providers?

`GET /realms/{realm}/account/linked-accounts` lists fifteen of the realm's
seventeen identity provider types. `kubernetes` and `jwt-authorization-grant` are
absent while present and `enabled: true` in the realm's own admin listing.

`hideOnLogin` is the obvious hypothesis and the pair refutes it: a `kubernetes`
create sets it true by default and a `jwt-authorization-grant` create sets
nothing. `enabled` is not the filter either - both were confirmed enabled.
`unlistedProviderIDs` in `internal/account/reads.go` records the measurement and
encodes no hypothesis, which is deliberate. The entry asks for the mechanism.

### F191: the harness cannot express a header rule the transport erases

A leading or trailing space in a header value is stripped by any conformant
receiver, so the recorder's Keycloak never sees one; the verifier hands the
handler an `http.Request` directly, so Gloak does. A conformance case for such a
rule passes with both sides doing different things.

This is a general limit rather than one header's oddity - it applies to any
request-side rule the transport normalises, which includes header folding, case
in header **names**, and the request line's own whitespace. Nothing in the
harness detects it. A `Case` that declared "this exercises a byte the transport
removes" and failed would be the checkable form; today the only defence is
somebody noticing, and this session noticed only because the two cases were
written as a pair and one of them looked too easy.

### F192: Gloak ignores `fullScopeAllowed` when issuing tokens

`account/gate/scope-filtered-token` is `Recorded` for this and it is a divergence
rather than an unserved behaviour. A public client with `fullScopeAllowed: false`
and no scope mappings should yield a token whose granted roles are filtered;
Gloak's token path does not implement the filter at all, so the account roles the
user really holds reach the gate and Gloak answers 200 where Keycloak answers
401.

The case is in this chapter because this is the request that exposes it, but the
defect is in `internal/oidc` and the fix belongs there. Note the pairing that
makes it visible at all: `admin-cli`'s token also carries no `aud` claim and *is*
accepted, so the two fixtures together say the gate reads the granted roles
rather than the claim. Neither alone would have found this.

### F193: does `internal/admin`'s `bearerToken` diverge on the scheme's case?

`internal/account`'s `bearerToken` folds the scheme's case, measured. A comment
added in the unreviewed checkpoint `d8a74f0` claims the **Admin API** folds it
too and that `internal/admin`'s own `bearerToken` does not - which would make it
a divergence in a chapter this cut does not touch.

That claim is inherited and was **not** re-measured here, because it is about a
different package and a different surface and acting on it inside an account cut
is how a one-line fix reaches every admin route. The entry is the request to
send: `bearer <t>` and `BEARER <t>` against `/admin/realms/master` with an
administrator's token, and `internal/admin`'s parser read beside the answer.

### F195: the pollution guard's fifth family is identity providers, and closing it is a cut

AGENTS.md already says the guard "watches four resource families ... A fixture
creating a fifth kind of object named by some other key is invisible to it until
that key joins `createdKeys`". **That blind spot was hit for real by this
chapter**: `account/linked-accounts/none` recorded sixteen identity providers
that other fixtures created, and `TestNoGoldenHoldsAnObjectItDidNotCreate` was
silent, because an identity provider is named by `alias`.

Adding `alias` to `createdKeys` was **measured rather than assumed**, and it is a
cut of its own. With it applied, the tree reports:

- **seventeen authentication-flow aliases outside the naming convention** -
  `f103-gamma`, `f103-twiglet`, `f103-doomed` and the rest - each needing a
  rename or a `namedOutsideTheConvention` entry;
- **the bootstrapped alias `browser`**, which
  `admin/authentication-management/create-duplicate-alias` POSTs on purpose to
  measure a 409. It creates nothing, and it is reported as polluting four
  `partial-export` goldens and `authentication-management/list`. Note that
  `namesBootstrapShips` does **not** filter it, because `bootstrapListings` does
  not read `/authentication/flows` - so closing this family means extending that
  reader too;
- **an inverted key precedence on organizations**, which carry both `name` and
  `alias`. Putting `alias` before `name` changes which key an organization is
  recorded under and breaks the ownership match on four `admin/organizations`
  goldens. It has to go **after** `name`, and that ordering is the kind of thing
  that needs its own test.

None of this belongs in an account cut - it reaches the authentication-management
and organizations chapters for one instance of a rule, which is the mistake
AGENTS.md names about fixing a general rule inside a family branch. The account
case is fixed structurally instead, with `PristineRealm`.

### F194: the account chapter's refusals are eleven cuts, not one

Twenty-three of the forty cases are `Recorded`, and they do not share a blocker.
Four need session-model state Gloak does not hold (`sessions`, `applications`),
two need the `userProfileMetadata` derivation, three need credential provider
metadata, one needs realm-stored locales, six are the dispatch and console
shapes, and one is F192. Sequencing them as one "serve the account API" cut would
mean opening the session model, the user-profile serialiser and a media-type
parser in one branch. The entry is to record that the chapter's remaining parity
is **not** a single unit of work, before somebody plans it as one.
