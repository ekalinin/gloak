# The pollution guard's fifth family

F195. The guard watched four resource families - clients by `clientId`, users by
`username`, realms by `realm`, roles and groups by `name` - and AGENTS.md had
already written down what that costs: *"A fixture creating a fifth kind of
object named by some other key is invisible to it until that key joins
`createdKeys`."* An identity provider is named by `alias`. That sentence came
true on `account/linked-accounts/none`, which recorded sixteen identity
providers other fixtures had created while the guard stayed silent.

This is the cut that closes it, and the first thing to say is that **F195's
remedy was not sufficient**. Adding `alias` to `createdKeys` - the whole of what
F195 prescribed, measured on a tree three merges back - produces a guard that is
green, reports the four things F195 predicted, and **still reads straight past
the golden it exists for**. Section 2 is that measurement. It is the exact
failure shape this project names: a guard extended so that it reports nothing is
indistinguishable from a guard extended correctly, if the corpus holds nothing
it should report.

Everything below was measured on **2026-09-10** on `main` at `5a4da1d`, in the
tree, against the committed goldens and against Gloak's own bootstrap through
the handler the verifier serves. The re-record ran against
`quay.io/keycloak/keycloak:26.7.1` through testcontainers.

## 1. F195's measurement, re-taken

Applied verbatim - `createdKeys` becomes
`{"clientId", "username", "realm", "name", "alias"}` - and nothing else changed.

### 1.1 The flow aliases: seventeen lines, and the count needs a qualifier

`TestEveryCreatedObjectCarriesTheProbePrefix` reports **seventeen lines from the
authentication-management family**, which is F195's number. What the number is
made of is worth writing down, because two different counts land on it:

- **sixteen lines are `f103-*` flow, sub-flow and authenticator-config aliases**,
  and they are **fifteen distinct names** - `f103-twiglet` is created by
  `admin/authentication-management/add-sub-flow` and again by
  `add-sub-flow-built-in`, and the guard reports one line per creator on purpose;
- **the seventeenth is `browser`**, which is section 1.2.

So "seventeen aliases" is seventeen *reports*, fifteen *names*, and one of the
seventeen is not a flow the catalogue creates at all. F195 read the count off the
failure output, which is the right place to read it from and is why it
reproduced.

### 1.2 `browser`, exactly as predicted

`admin/authentication-management/create-duplicate-alias` POSTs
`{"alias":"browser"}` at a realm that already has the flow every install ships,
to measure `409 Flow browser already exists`. It creates nothing, and
`createdObjects` records it anyway - deliberately, for the reason `pollution`'s
doc comment gives about `admin/roles/create-duplicate`.

Reported as polluting five goldens, and F195 named all five:

```
admin/realms-admin/partial-export                    PristineRealm
admin/realms-admin/partial-export-groups-and-roles   PristineRealm
admin/realms-admin/partial-export-clients            PristineRealm
admin/realms-admin/partial-export-manage-realm       PristineRealm
admin/authentication-management/list
```

`namesBootstrapShips` did not filter it, because `bootstrapListings` read
`/clients`, `/roles`, `/users`, `/groups`, `/client-scopes`, `/admin/realms` and
each client's roles, and no flow listing. Confirmed by reading the function, and
confirmed by the fix working.

### 1.3 The organizations precedence, reproduced to the golden

`alias` moved **before** `name`:

```
admin/organizations/list                golden holds name "gloak-probe-org-named"
admin/organizations/list-full           …which "admin/organizations/create-duplicate-name" created
admin/organizations/read
admin/organizations/read-brief-ignored
```

Four goldens, which is F195's number, and they are the four F195 meant.

The mechanism is worth stating because F195 records the symptom rather than the
cause. `organizationFixture` POSTs
`{"name":"gloak-probe-org-named","alias":"gloak-probe-org-alias",…}` - the one
family whose create names its object twice. Every *other* body naming that same
organization carries only `name`, including
`admin/organizations/create-duplicate-name`'s `{"name":"gloak-probe-org-named"}`.
So with `alias` first, the fixture's organization enters the set as
`alias gloak-probe-org-alias` and the duplicate case's enters as
`name gloak-probe-org-named`; the listing's golden holds the `name` pair; the
ownership match is on the `{key, name}` pair, so the fixture no longer owns what
its own golden holds, and the guard reports the duplicate case as the creator.

It is not that `alias` is a worse key. It is that **the key an object is recorded
under has to be the one every body naming it agrees on**, and for organizations
that is `name`.

### 1.4 What F195 did not have: a fifth report

`zzz-probe-broker`, created by `account-user-brokers` and
`account-user-brokers-unlisted`, is reported too. F195 does not mention it
because the fixture that makes it was split in two on 2026-09-08, after F195 was
filed - the split that gave the unlisted providers a fixture of their own. It is
an exemption, not a rename, and section 3.2 says why.

## 2. The finding: `alias` is the key and it is not the spelling

`account/linked-accounts/none` is the golden this family exists for. Its first
recording held sixteen rows - every `gloak-probe-idp*`, `gloak-probe-map-broker-*`
and `gloak-probe-mt-broker-*` the admin chapter creates in master. The account
cut fixed it structurally with `PristineRealm` and filed F195 to make the guard
able to see it.

**With F195 applied in full, the guard cannot see it.** The account API does not
serve an identity provider under `alias`. It serves
`LinkedAccountRepresentation`:

```json
{"connected":false,"providerAlias":"gloak-probe-oidc","providerName":"gloak-probe-oidc",
 "displayName":"gloak-probe-oidc","social":false}
```

`pollution` builds the needle `"alias":"<name>"` and looks for it as a substring.
`"providerAlias":"gloak-probe-oidc"` does not contain `"alias":"gloak-probe-oidc"` -
the `A` is capital and there is no quote before it - so the match fails on every
row.

Measured rather than reasoned. The body was rebuilt from the aliases fixtures
create today, in both spellings, and handed to `pollution` with `alias` in
`createdKeys`:

```
                                       providerAlias-spelled   alias-spelled
F195's remedy: `alias` in createdKeys                      0              31
this cut: `alias` plus objectSpellings                    31              31
```

Thirty-one objects visible one way and none the other, on the same names and the
same guard. The bottom row is what closing the family means and the top row is
what F195 prescribed. F195 named the key and not the spelling, and a cut that had stopped
where F195 stopped would have shipped a green tree, a closed follow-up, and a
guard that still misses the only golden anyone has ever caught this way.

### 2.1 The sweep that found the rest

Guessing a second spelling is the same mistake one step along, so the goldens
were swept instead: for every object the recording creates, every `"key":"value"`
pair in every committed golden whose value is **exactly** that object's name, and
whose key is not the creation key. For the `alias` family:

```
providerAlias          gloak-probe-oidc, gloak-probe-social, zzz-probe-broker
identityProviderAlias  gloak-probe-map-broker-list, gloak-probe-map-broker-one
identityProvider       gloak-probe-idp
browserFlow            browser
providerName           gloak-probe-oidc, gloak-probe-social, zzz-probe-broker
displayName            gloak-probe-oidc
```

Four of the six are the object under another name and are now matched:

- **`providerAlias`** - `LinkedAccountRepresentation`, the account API's word for
  an identity provider. The one this cut exists for.
- **`identityProviderAlias`** - `IdentityProviderMapperRepresentation`. A mapper
  names the provider it hangs off, so a mapper listing holds the provider's alias.
- **`identityProvider`** - `FederatedIdentityRepresentation`, from
  `GET /users/{id}/federated-identity`.
- **`browserFlow`** - a realm representation's flow binding names a flow by its
  alias. This is the one that made the four `partial-export` goldens hold
  `browser` under a second key as well as the first.

Two are **not** the object and are declared as such:

- **`providerName`** carries the alias a second time in the same row. Every row
  holding it holds `providerAlias`, so matching it reports nothing new - an inert
  matcher, which this repository treats as worse than a gap because it reads as a
  claim.
- **`displayName`** falls back to the alias when a provider has none. It is a
  label. Matching it is exactly the phantom `createdKeys` already refuses about
  `ClientRepresentation.name`, one API over.

The six other realm flow bindings - `registrationFlow`, `directGrantFlow` and the
rest - are **left out**. Nothing in the corpus binds a flow the catalogue creates,
so listing them would be six unexercised claims. `TestEveryDeclaredSpellingIsExercised`
is what keeps them out and what would fail if one were added on speculation.

### 2.2 The request side has the same asymmetry, and one operation needs it

`POST .../authentication/flows/{alias}/copy` takes `{"newName":"…"}` and creates
a flow that every listing then serves under `alias`. Read literally,
`admin/authentication-management/copy` created a flow nothing watched - the same
blind spot, one key further along, and not named in F195.

`creationKeySpellings` maps `newName` onto the `alias` family, so the copy's
`gloak-probe-f103-copied` is a flow rather than a `newName`. The value is the
family rather than a flag, because everything downstream keys on family: the
probe-prefix convention, `namedOutsideTheConvention`, the bootstrap filter and
`objectSpellings`.

Two names entered `createdObjects` when it was closed, both renamed in section 3.

## 3. Every rename and every exemption, with its reason

Nineteen reports, seventeen renames, two exemptions. The standard applied is the
one `namedOutsideTheConvention`'s own doc comment sets: an entry is for a name
that is **load-bearing where it stands**, so that renaming it would change a
measurement. Anything else is a rename.

### 3.1 Seventeen renamed: `f103-*` to `gloak-probe-f103-*`

| alias | what it is | why it is a rename |
| --- | --- | --- |
| `f103-bad` | the flow `create-unrecognised-field` POSTs | arbitrary |
| `f103-copied` | the flow `copy` makes | arbitrary |
| `f103-doomed` | "a flow made to be deleted" | arbitrary |
| `f103-duet` | the two-execution flow for the lower case | arbitrary |
| `f103-gamma` | the flow `create` makes | arbitrary |
| `f103-host` | the flow that receives an execution | arbitrary |
| `f103-nest` | the flow that receives a sub-flow | arbitrary |
| `f103-never` | the copy target of a copy that 404s | arbitrary |
| `f103-no-provider` | the flow created with no `providerId` | arbitrary |
| `f103-orphan-config` | an authenticator config alias | arbitrary |
| `f103-own-config` | an authenticator config alias | arbitrary |
| `f103-pair` | the two-execution flow for the raise case | arbitrary |
| `f103-plot` | the flow that receives a new execution | arbitrary |
| `f103-redirect-config` | an authenticator config alias | arbitrary |
| `f103-shed` | the flow whose execution is deleted | arbitrary |
| `f103-twiglet` | the sub-flow both add-sub-flow cases make | arbitrary |
| `f103-vane` | the flow whose execution is configured | arbitrary |

Not one of them is load-bearing. Checked rather than assumed, in three ways:

- **No golden's window depends on them.** Every `f103-*` flow lives in a realm of
  its own that its own fixture creates - `gloak-probe-flow-oax`, `-osb`, `-cpy`
  and the rest - so none can reach another case's listing. Grepping the corpus
  agrees: exactly seven goldens hold an `f103-` string and five of those hold a
  name of something that **does not exist**.
- **No golden sorts them.** There is no paged or filtered flow listing in the
  catalogue.
- **`f103-` sorts before `gloak-probe-`**, which is the F58 hazard shape - the
  same shape `aa-gloak-srch-kid` is an exemption *for*. The difference is that
  `aa-` is there to take the first place and `f103-` is there because it was
  typed. That asymmetry is the whole argument for renaming these and keeping
  those.

Seventeen exemptions each reading "lives in its own realm" would have been a
blanket with a reason attached, which is what `namedOutsideTheConvention` says it
is not.

`gloak-probe-f103-` rather than `gloak-probe-flow-` keeps the existing `f103`
token, which names the follow-up this family came from, and keeps the aliases
distinct from the realm constants `gloak-probe-flow-*` beside them - the family's
own comment records that six of six survivors in this repository have been a test
where one thing played two roles.

**Twelve bare `f103-*` names stay**, and the distinction now carries information:
`gloak-probe-f103-*` is a flow that exists, and bare `f103-*` is a name for
something that does not. `f103-absent`, `f103-nope`, `f103-no-such-id`,
`f103-no-such-config`, `f103-no-such-execution` and `f103-not-a-provider` name
missing things; `f103-zeta`, `f103-omega` and `f103-kappa` are `defaultProvider`
config values; `f103-alpha` is in a comment; `f103-docker-renamed` and
`f103-cfg-renamed` are section 8's follow-up.

### 3.2 Two exempted

**`alias browser`** - `admin/authentication-management/create-duplicate-alias`.
The product's name **is** the input. The case exists to measure
`409 Flow browser already exists` on a bootstrapped alias, and renaming it to
`gloak-probe-f103-browser` builds a case that creates a flow and measures a 201.
It is the third instance of the shape `name manage-realm` and `name view-profile`
already carry - a fixture deliberately colliding with a name the product ships -
and the first on `alias`.

It is also the entry AGENTS.md's warning about `manage-realm` is about, resolved
the other way. That bullet says two entries take a product name and only one has
ever been exercised, "so that entry is lucky rather than safe". This one is
exercised: five committed goldens hold it, and
`TestPollutionGuardIgnoresTheBootstrappedFlowAlias` reads those five rather than
a synthetic body, and **fails if the count reaches zero**.

**`alias zzz-probe-broker`** - `accountBrokerFixture`. The sort position is the
measurement, which is the group-search fixture's argument one API over. The
fixture's own comment lays out the table: this provider sorts *last* by alias and
*first* by display name, so `account/linked-accounts/providers` refutes a listing
sorted by display name only because `zzz-` sorts after every `gloak-probe-`
sibling. A shared prefix sorts it among them and the case measures nothing.

`aa-gloak-srch-kid` takes the first place on purpose and this takes the last; both
are deliberate, and F58's warning is the reason to say so out loud rather than
leave the prefix looking like a typo.

## 4. The organizations precedence, and the test that pins it

`alias` goes after `name`. The reason is section 1.3; this section is about why a
comment is not enough.

The precedence is a property of **one body**, not of the catalogue, and until this
cut nothing could observe it except through whichever bodies happened to be in the
catalogue. So `createdObjects` grew a seam - `objectsCreatedBy(Request, creator)`,
the same reader applied to one request - and
`TestCreatedKeysReadAnOrganizationUnderItsName` hands it three bodies:

1. **an organization's create, carrying both keys**, which must be read under
   `name`. This is the claim that fails when the two lines are swapped;
2. **a flow's create, carrying no `name`**, which must be read under `alias`.
   This is the claim that fails when `alias` is removed - so the test cannot be
   satisfied by deleting the key it is about;
3. **the consequence**: the fixture's organization and
   `create-duplicate-name`'s, fed to `pollution` against the shape
   `admin/organizations/list`'s golden has. Clean for the fixture that made it.
   This is the four-golden failure, in-memory, with no golden read.

A test asserting the literal contents of `createdKeys` would also fail on the
swap and would say nothing about why, which is the difference between a pin and a
tautology. Mutation M4 in section 6 is the swap, run against the whole package.

## 5. The record diff, read file by file

One run, whole catalogue, 759 seconds, against
`quay.io/keycloak/keycloak:26.7.1` through testcontainers. **Three files moved
and nothing outside the authentication-management chapter did.**

```
add-execution.http               1 line   the recorded request line
add-sub-flow.http                1 line   the recorded request line
create-unrecognised-field.http   1 line   the response body
```

The first two are the `# POST …` line the recorder writes above each golden.
Both cases address a flow by an alias the rename changed. Nothing compares that
line - `RequestLine` is written by `record_test.go` and read by nobody, which is
worth knowing and is **not** a reason to leave it stale: a golden whose request
line names a path the catalogue no longer sends is a golden that lies to the
next reader.

The third is a real response body and it is the one worth reading:

```
-{"error":"… Unrecognized field \"zzz\" at line 1 column 70."}
+{"error":"… Unrecognized field \"zzz\" at line 1 column 82."}
```

`admin/authentication-management/create-unrecognised-field` measures Keycloak
reporting **the column** of the unrecognised field, and the alias sits in the
body ahead of it. `len("gloak-probe-") == 12`, and 70 + 12 = 82.

This is the only golden in the tree whose bytes depend on the *length* of a
probe name, and it found itself: the package went red before the re-record with
Gloak answering 82 and the golden holding 70. **Gloak was right** - it computes
the column rather than carrying it - so the red was the golden being stale, and
the measurement is unchanged: Keycloak still reports the column, for the body
that is now sent.

It is also the sharpest argument in this cut for the rule about re-recording. A
rename that "only touches fixtures" moved a recorded contract value, and the
only thing that noticed was running the suite.

## 6. The mutation pass

Twenty applied, **eighteen killed, two survivors**. The harness copies the file
aside and installs the revert on a `trap ... EXIT` before anything can fail,
counts the target as a substring rather than as `grep`'s matching lines, refuses
a target that does not appear exactly once, refuses one that does not build,
refuses one whose `-run` selected no test, and re-hashes the file afterwards.
The tree was committed before the pass and nothing was staged by wildcard during
it; `git status` was read at the end and held exactly one intended edit.

```
     createdKeys and its precedence
M1   drop "alias" from createdKeys                     KILLED  6 tests, incl. the positive control
M2   move "alias" before "name"                        KILLED  TestCreatedKeysReadAnOrganizationUnderItsName
M18  read every key rather than the most specific      KILLED  TestCreatedKeysReadAnOrganizationUnderItsName
     the spellings
M3   drop "providerAlias"                              KILLED  TestPollutionGuardSeesAnIdentityProviderInTheAccountListing
M4   drop "identityProviderAlias"                      KILLED  TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey
M5   drop "identityProvider"                           KILLED  TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey
M6   drop "browserFlow"                                KILLED  TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey
M10  mentions ignores objectSpellings entirely         KILLED  TestPollutionGuardSeesAnIdentityProviderInTheAccountListing
M14  declare providerAlias in both lists at once       KILLED  TestEveryDeclaredSpellingIsExercised
M20  drop displayName from the non-identifiers         KILLED  TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey
     the bootstrap reader
M7   drop the /authentication/flows read               KILLED  TestPollutionGuardIgnoresTheBootstrappedFlowAlias  (survived first - see 6.1)
M8   drop the /identity-provider/instances read        SURVIVED  see 6.2
M15  pollution ignores the bootstrap filter            KILLED  4 tests
     the request-side spelling
M11  empty creationKeySpellings                        KILLED  TestEveryDeclaredSpellingIsExercised
M16  creationKeyFamily is the identity                 KILLED  TestEveryDeclaredSpellingIsExercised
M17  read the spellings before the family keys         SURVIVED  see 6.3
     the matcher
M9   match the bare value rather than the pair         KILLED  3 tests
     the declarations
M12  drop the `alias browser` exemption                KILLED  TestEveryCreatedObjectCarriesTheProbePrefix
M13  drop the `alias zzz-probe-broker` exemption       KILLED  TestEveryCreatedObjectCarriesTheProbePrefix
M19  rename one alias back out of the convention       KILLED  TestEveryCreatedObjectCarriesTheProbePrefix
     round two, whole package, no -run filter
R1   M2 unfiltered                                     KILLED  same three tests
R2   M10 unfiltered                                    KILLED  the positive control
R3   M7 unfiltered                                     KILLED  the bootstrapped-flow test
R4   M8 unfiltered                                     SURVIVED
R5   M17 unfiltered                                    SURVIVED
```

Every mutation here is of the second kind AGENTS.md distinguishes - each leaves
a **coherent** guard that reports something, rather than one that crashes. M1 is
literally the pre-cut implementation; M2 is F195's own prescription with the two
lines the other way round.

### 6.1 M7 survived first, and reading the line is what closed it

Deleting the `/authentication/flows` read from `bootstrapListings` - the fix
F195 explicitly asked for - **survived the whole guard suite**. That is the
cut's own failure shape arriving from inside, and the rule about reading the
mutated line before reporting it is what turned it into a fix.

`browser` does not need that read. A realm representation binds the browser flow
under `browserFlow`, `browserFlow` is a declared spelling as of section 2.1, and
`GET /admin/realms` is already in `bootstrapListings` - so the realms listing
witnesses that one alias on its own and `shipped` is populated either way.

Measured, rather than left as a theory: all seven top-level flows a default
install ships are named by the realms listing, and **six of them under bindings
this guard does not watch** - `registrationFlow`, `directGrantFlow`,
`resetCredentialsFlow`, `clientAuthenticationFlow`, `dockerAuthenticationFlow`
and `firstBrokerLoginFlow`, none of which is in `objectSpellings` because no
golden exercises one. So through `mentions`, the flows listing is the **only**
body that names those six.

An implementation satisfying M7 is therefore one that relies on a realm binding
to witness every bootstrapped flow. It is correct for exactly one alias, and a
case POSTing `{"alias":"registration"}` to measure the same 409 that
`create-duplicate-alias` measures on `browser` is one line away from making it
wrong.

The claim is now made directly - some flow bootstrap ships must be witnessed by
exactly one listing - and M7 is killed, filtered and unfiltered.

### 6.2 M8 survives, and it should

Deleting the `/identity-provider/instances` read changes nothing, because
**bootstrap ships no identity providers**: the listing is `[]`, two bytes, and
contributes no name to `shipped`.

An implementation satisfying M8 is one whose `bootstrapListings` reads only the
listings that are non-empty on a default install. It is correct today and it
becomes wrong the day Gloak's bootstrap creates an identity provider, which
nothing here would notice.

The read stays, and the precedent is in the function already:
`get(realm + "/groups")` is **also** `[]` on bootstrap master, and so are three
of the six client-role listings. `bootstrapListings` reads the families
`createdKeys` names, not the ones that happen to be occupied, and its doc
comment says so. Making the identity-provider read the one exception would be a
narrower rule than the sentence above it.

There is nothing true to assert here that would kill it. A test that the listing
is empty asserts bootstrap's shape rather than the guard's, and would have to be
deleted the moment the shape changed - which is the inert-mask bargain in
reverse.

### 6.3 M17 survives, and the comment now says so

`readKeys` is `createdKeys` followed by the `creationKeySpellings` keys, so that
a body carrying both a family key and a spelling is read under the family key.
Reversing the two halves survives.

An implementation satisfying M17 reads `newName` before `clientId`, `username`,
`realm`, `name` and `alias`. It is indistinguishable from this one on the
corpus, because **no body carries `newName` beside any of the five** - the only
operation taking a `newName` takes nothing else.

This is the same *kind* of claim as the organizations precedence and it has none
of the evidence. Section 4's test argues from a body that is really in the
catalogue; a test for this one would have to invent a body no Keycloak operation
sends, which is a test that pins a preference rather than a measurement. The
comment on `readKeys` now says the ordering is unexercised and points here,
which is the honest version of what was there before.

## 7. What moved on the meter

```
before   total: 578 of 631 enumerated behaviours served; 2 chapters not enumerated
after    total: 578 of 631 enumerated behaviours served; 2 chapters not enumerated
```

**Unchanged, and it should be.** This cut serves no behaviour: it is the
harness's own guard, three re-recorded goldens and seventeen fixture renames.
Nothing was added to the catalogue and nothing was promoted.

The parity total not falling is the assertion that matters, and it is the one
that could have failed: seventeen fixture renames and a re-record are exactly
the shape that quietly drops a case. `CGO_ENABLED=0 go test ./...` is green
across every package and `make lint` is clean.

## 8. What belongs in AGENTS.md, phrased as I would want it folded

The existing bullet - *"`TestPristineRealmGoldensAreNotPolluted` watches four
resource families … A fixture creating a fifth kind of object named by some
other key is invisible to it until that key joins `createdKeys`"* - has come
true and should be updated rather than deleted. Suggested replacement and two
additions:

> - **The pollution guard watches five resource families now**, read out of the
>   creation bodies themselves: clients by `clientId`, users by `username`,
>   realms by `realm`, roles and groups by `name`, and identity providers,
>   authentication flows and authenticator configs by `alias`. The fifth was
>   added on 2026-09-10 after the blind spot this bullet described was hit for
>   real: `account/linked-accounts/none` recorded sixteen identity providers
>   other fixtures had created and the guard was silent.
>
> - **A key is not a spelling, and the guard needs both.** `createdKeys`' first
>   sentence - the key a creation body uses is the key a listing answers under -
>   is true of four families and **false of the fifth**. An identity provider is
>   created under `alias` and served under `providerAlias` by the account API,
>   `identityProviderAlias` on a mapper and `identityProvider` on a federated
>   identity; a flow is created under `alias`, copied under `newName` and bound
>   under `browserFlow`. Measured on 2026-09-10 by rebuilding the polluted
>   linked-accounts body from the aliases fixtures create today: **the `alias`
>   spelling reports 31 objects and the `providerAlias` spelling reports none.**
>   So adding the key alone - which is the whole of what F195 prescribed -
>   produces a guard that is green, reports the four things F195 predicted, and
>   still reads past the golden it exists for. `objectSpellings` is the response
>   side and `creationKeySpellings` the request side, and both were found by
>   **sweeping the goldens for a key whose value is a created object's name**
>   rather than by reading the representations.
>   `TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey` keeps that sweep; it covers
>   `alias` alone, and the other four families report about thirty pairs. F216.
>
> - **`createdKeys`' order is a precedence and `alias` goes after `name`.** An
>   organization's create is the one body naming its object twice, and every
>   other body naming that organization - including the duplicate-name case's -
>   carries `name` alone, so recording it under `alias` breaks the ownership
>   match on four `admin/organizations` goldens. The rule the two orders are
>   really about: **the key an object is recorded under has to be the one every
>   body naming it agrees on.** Pinned by
>   `TestCreatedKeysReadAnOrganizationUnderItsName` through a seam that takes a
>   body, because the precedence is a property of one body and a test that can
>   only see the catalogue can only observe it through whichever bodies happen
>   to be in it.
>
> - **Extending a guard without a positive control is the failure shape this
>   project names, and it arrived from inside on this cut.** Deleting the
>   `/authentication/flows` read that F195 asked for - the fix, not a
>   hypothetical - survived the whole guard suite, because a realm
>   representation binds the browser flow and `GET /admin/realms` witnesses that
>   one alias on its own. The other six flows bootstrap ships are bound under
>   keys nothing watches, so the read is load-bearing for six of seven and
>   redundant for the one the corpus exercises. **Read the mutated line before
>   reporting a survivor, and the fix is usually in what you read.**
>
> - Two entries in `namedOutsideTheConvention` take a product name and only one
>   has ever been exercised → **three entries now, and two are exercised.**
>   `alias browser` is the third, and five committed goldens hold it, so
>   `TestPollutionGuardIgnoresTheBootstrappedFlowAlias` reads those five rather
>   than a synthetic body and fails if the count reaches zero. `name
>   manage-realm` is still the lucky one.

The `Conventions` section could also gain one line, since the rename made it
true of a new family:

> - Every object a fixture or a case creates is named `gloak-probe-*`. On the
>   flow family a bare `f103-*` name now means the opposite - a name for
>   something that deliberately does **not** exist, which five goldens measure a
>   404 or a 409 against.

## 9. Follow-ups

Numbered from F216; F171-F215 are taken.

### F216: the spelling sweep is `alias`-only, and the other four families report about thirty pairs

`TestNoGoldenSpellsAnAliasUnderAnUnwatchedKey` reads every committed golden for
a `"key":"value"` pair whose value is exactly a created object's name and whose
key the guard does not match. Run over `alias` it is clean - the only two hits
are `displayName` and `providerName`, both declared. Run over the other four
families on 2026-09-10 it reports **ten family/key pairs covering 34 names**:

```
clientId  aud                  1   gloak-probe-narrow-peer
clientId  azp                  3   in tokens
clientId  client_id            3   in tokens and introspection bodies
clientId  client               7   on scope-mapping and group-mapping rows
clientId  name                10   authz resource servers, whose name is the client's id
username  preferred_username   2   in tokens
username  client_name          1   on an initial access token
username  name                 1   gloak-probe-solo
username  resourceName         4   on workflow rows
realm     name                 2   an organization group and a workflow
```

They are not one answer. `azp`, `client_id` and `preferred_username` genuinely
name the object; `name` on an authorization resource server is the same client
under its own id; `client_name` on an initial access token and `resourceName` on
a workflow row need reading before either is called an identifier; and some are
the phantom `createdKeys` already refuses. Doing them inside an `alias` cut would
have turned it into a sweep of the whole corpus - F181's shape, and the mistake
AGENTS.md names about fixing a general rule inside a family branch. The entry is
that the sweep already exists and already passes on one family; widening it is a
cut with ten declarations and 34 goldens to read behind them.

### F217: a `PUT` that renames an object creates a name the guard never sees

`createdObjects` reads `POST` bodies alone, which is right for creates and wrong
for renames. Two bodies in the catalogue rename an object into a name nothing
watches:

- `f103-docker-renamed`, a `PUT` on the built-in `docker auth` flow;
- `f103-cfg-renamed`, a `PUT` on an authenticator config;
- and `gloak-probe-renamed-action`, a `PUT` on a required action, which is
  inside the convention by luck rather than by a check.

Each leaves an object in a realm under a name `TestEveryCreatedObjectCarriesTheProbePrefix`
never judges and `pollution` never matches. The first two are outside the
convention today and nothing says so.

It is not a straight widening: a `PUT` that renames also **removes** the old
name, so reading `PUT` bodies the way `POST` bodies are read would record an
object under two names of which only one exists. The entry is the question -
does the guard want a third source with different semantics, or does the
convention want extending to `PUT` bodies without the pollution match? - and the
measurement is which committed goldens hold either name.

### F218: `bootstrapListings` cannot fail on a family it does not read

The function's doc comment claims it answers for "every family `createdKeys`
names", and nothing checks that. Adding a sixth key to `createdKeys` without a
matching read leaves the guard reporting every bootstrapped object of the new
family as a fixture's - which is exactly what `browser` did for the two days
between F195 being filed and this cut.

The check is awkward rather than hard: the map from a family to the endpoint
that enumerates it is not derivable, and organizations are the counterexample
that makes it interesting - they are named by `name`, they are enumerable, and
`GET /admin/realms/master/organizations` is `404 Organizations not enabled for
this realm.` on a default install, so `bootstrapListings`' `get` would fatal on
it. A per-family declaration with a "not enumerable on master, and why" arm is
probably the shape. The entry is to write it before the sixth family is added,
not after.

### F219: `RequestLine` is written by the recorder and read by nobody

`record_test.go` writes `# METHOD path` above every golden and `ParseGolden`
reads it back into `Golden.RequestLine`, which no verifier compares. This cut's
rename left two of them stale and no test could have said so; they were fixed
because the re-record rewrote them, not because anything asked.

That is benign for a recorded golden and not benign for a **hand-edited** one,
which is the case the rule against hand-editing exists for. A cheap check -
every golden's request line equals its case's method and path, after `Expand` -
would turn the recorder's comment into an assertion and would fire on a golden
somebody edited without re-recording. The reason it is a follow-up rather than
part of this cut: the request line holds the *unexpanded* path for some cases
and the expanded one for others, so the comparison needs measuring before it can
be written.
