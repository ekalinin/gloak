# Harness recorder: what belongs in the documents this branch may not edit

Date: 2026-08-30
Branch: `fix/harness-recorder`
Follow-ups cleared: **F58, F59, F69**. F23 is superseded by F69 and should be
closed with it.

This branch does not touch `AGENTS.md`, `README.md`, the parity roadmap, the
observed spec or the follow-ups list, so what is owed to them is written out
here. It also does not touch `fixture.go`, `catalog_oidc.go`,
`catalog_oidc_pending.go` or anything under `testdata/golden/oidc/`, which
belong to streams running in parallel.

Everything recorded came from a live `quay.io/keycloak/keycloak:26.7.1
start-dev` started and removed by `make record`'s own testcontainers. Three
whole-catalogue runs and one single-case run, four independent container starts
in all.

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

Only one, and it is a stability claim rather than a new value. Everything else
in this cut is harness machinery.

### 1.1 A client scope's protocol mappers are stable in content and not in order

The observed document already says the mapper order inside a scope moves
between container starts, and `admin/client-scopes/list` masked
`protocolMappers` whole because of it. Sorted, the set is reproducible: the
thirty-five mappers of master's fifteen client scopes were recorded on one
container, then re-recorded on a second whole `make record` against a fresh
container, and came back **byte for byte identical** once each mapper array was
sorted and the per-container UUIDs were masked.

What that pins, and what the two goldens now assert:

- fifteen scopes, thirty-five protocol mappers, `offline_access` the only one
  with **no** `protocolMappers` key at all - five keys where the others have
  six, exactly as the document already states.
- each mapper's `name`, `protocol`, `protocolMapper` and `consentRequired`.
- **every key of `config`, in Keycloak's own key order**, unsorted. The
  `audience resolve` mapper on `roles` serves
  `{"introspection.token.claim":"true","access.token.claim":"true"}` - not
  alphabetical, and Gloak reproduces it. That is a Java map whose order the
  suite is now asserting rather than retreating from, which makes it the
  opposite of `attributes`; it is worth knowing that not every Java map in this
  API needed `UnorderedKeys`.

So the sentence in the observed document about the mapper order being unstable
stays true and gains a qualifier: **the order moves and the content does not.**

## 2. Entries for AGENTS.md

### 2.1 For "Build and test"

Place immediately after the `TestNoGoldenHoldsAnObjectItDidNotCreate` bullet,
which it neighbours - both are about what a re-record is allowed to do.

> - **`make record` leaves a `Pending` golden exactly as it found it.**
>   `TestConformance` skips a Pending case whether or not a golden exists, so
>   nothing compares one, and rewriting it can only add noise to the diff this
>   project asks people to read carefully. Four login-theme pages did that on
>   every single run, because their `/resources/<hash>/` segment is regenerated
>   per container start; the count went from three to four inside two days, by
>   the cut that filed the follow-up. `GoldenIsAsserted` in `case.go` is the one
>   predicate the recorder and the verifier both read, so the two cannot drift.
>   **The way to ask for a Pending golden back is to promote the case to
>   `Recorded`**, which is what `Recorded` already means and which a reviewer
>   sees in the diff; there is no flag. A whole run now moves **no** goldens on
>   a clean checkout, and 290 of the 297 are rewritten with identical bytes.

Place this one after it:

> - **Every object a fixture or a case creates is named `gloak-probe-*`, and
>   `TestEveryCreatedObjectCarriesTheProbePrefix` is what says so.** Six
>   goldens' windows rest on that convention and nothing enforced it:
>   `admin/roles/list-realm-page-no-search` sends `first=1&max=2` and holds
>   `create-realm` and `default-roles-master` only because no probe role sorts
>   before them, and six user listings rest on the same kind of argument about
>   names - `?username=admin` is a substring filter no `gloak-probe-*` username
>   matches. Seven objects are outside the convention and each is
>   declared in `namedOutsideTheConvention` with the reason it stands - three
>   `gloak-confidential*` clients that predate it, the three group names whose
>   sort positions **are** `admin/groups/search-pages-the-matches`'s
>   measurement, and the impostor's client role deliberately named
>   `manage-realm`. An entry that stops matching anything fails too, so a reason
>   nobody has re-read cannot sit there.

### 2.2 For "Things that look like bugs and are not"

Nothing. This cut measured no new Keycloak behaviour, and the mapper stability
in section 1.1 belongs in the observed document rather than here.

### 2.3 A correction to an existing bullet

The `attributes` bullet says `Case.UnorderedKeys` is "the only such retreat -
do not add a second without writing down why". Still true, and now worth one
clause: a protocol mapper's `config` is a Java map too and needed **no**
retreat - Gloak reproduces its key order exactly, asserted by
`admin/client-scopes/list` since 2026-08-30. Suggested edit, at the end of that
bullet:

> Not every Java map in this API needs it: a protocol mapper's `config` is one
> and its key order is reproduced exactly.

## 3. Follow-up dispositions

### F69: `make record` rewrites `Pending` theme-page goldens on every run - **closed**

Closed by `GoldenIsAsserted(c Case) bool` in `case.go`, read by both the
recorder and `TestConformance`. A Pending case is skipped by the recorder and
its golden is not touched; the run logs which ones it left alone.

Three designs were on the table.

1. **A flag on the recorder** (`GLOAK_RECORD_PENDING=1`). Rejected on the
   brief's own ground: a flag nobody sets is not an "unless asked", it is a
   dead branch. It also lives outside the diff, so nothing about the repository
   says a golden was or was not refreshed.
2. **Delete the four goldens.** This is the honest answer to "what is a golden
   for if nothing compares it", and it is probably right - see the paragraph
   below. Not done here: all seven Pending goldens are under
   `testdata/golden/oidc/` and `catalog_oidc_pending.go`, which are P13's this
   session, and deleting another stream's files mid-session is how two cuts
   fight.
3. **Skip Pending, promote to ask.** Done. `Recorded` already means "measured,
   golden committed, not served yet", so the catalogue already had the word for
   "I want this golden kept current", and using it is a one-word edit a reviewer
   reads.

**What the goldens are for, since nothing compares them.** Seven Pending cases
carry one. Three of them - `oidc/device/authorization-request`,
`oidc/ciba/authentication-request`,
`oidc/registration/without-initial-access-token` - are stable measured bodies
that are `Recorded` in everything but the status flag, and promoting them would
put them under the "must not match" alarm and keep them current. The other four
are the login-theme pages, and their bodies are about 4 kB of theme HTML each
whose resource hash is per-container: nothing in them is contract,
`internal/oidc` serves a placeholder, and F67 says the prose is still owed. **The honest answer
for those four is that they should not be committed at all.** They are P13's to
delete, and this cut has stopped them costing anything in the meantime.

The recorder's skip itself is exercised by no unit test, because `record_test.go`
is behind the `docker` build tag and CI runs nothing tagged. That hole is the
same one `passes.go`'s doc comment names for `normalisePasses`, and the evidence
that the wiring is live is the pair of whole runs in section 5.

### F58: a paged golden's window is held by a naming convention nobody enforces - **closed**

Closed by `TestEveryCreatedObjectCarriesTheProbePrefix` over `createdObjects()`,
with the exceptions declared and a stale exception failing. It fatals when a
family stops being created at all, the way the pollution guard already does.

**The first run is the interesting output, and it found eight things.** Seven
are real and none was renamed, because `fixture.go` belongs to another agent
this session and because every one of them is load-bearing where it stands:

| Object | Creator | Why it is outside the convention |
|---|---|---|
| `clientId gloak-confidential` | `confidential-user-token` | named before the convention existed |
| `clientId gloak-confidential-expiring` | `confidential-expired-token` | the same |
| `clientId gloak-confidential-sa` | `confidential-service-account` | the same |
| `name aa-gloak-srch-kid` | `admin-token-group-search` | **sorts first on purpose** |
| `name gloak-srch-one` | `admin-token-group-search` | matched by `search=gloak-srch` |
| `name zz-gloak-srch` | `admin-token-group-search` | sorts last on purpose |
| `name manage-realm` | `narrow-caller-impostor` | a client role named after an admin role, deliberately |

Two of those deserve reading rather than skimming.

**`aa-gloak-srch-kid` is exactly the hazard F58 describes, one resource family
over.** It sorts before every bootstrapped name in the realm.
`admin/groups/search-pages-the-matches` sends `search=gloak-srch&max=1` and its
answer *turns on* that fact - the matches are sorted, the first is the child,
and what comes back is the child's top-level ancestor with it nested. Renaming
the three to `gloak-probe-*` would sort them together and change which group the
page returns. They are groups, and no golden pages a group listing on
`first`/`max` without a search, so they cannot reach the six windows F58 is
about. But "cannot reach" is now a checked statement about seven names rather
than an unchecked one about all of them.

**`manage-realm` is the impostor and must keep that name.** `callerFixture`'s
own comment says the caller's roles come from `master-realm` *by container, not
by name*, precisely because a fixture minting its own `manage-users` would be
building an impostor rather than a caller. `narrow-caller-impostor` is the
fixture that deliberately builds the impostor, so its role is named after a real
admin role on a client of its own.

**The eighth was a phantom, and it is a defect in the pollution guard rather
than a violation.** `admin-token-client-described` creates
`{"clientId":"gloak-probe-described","enabled":true,"name":"A name",...}`, and
`createdObjects` reported a role called `A name`. That is
`ClientRepresentation.name` - a display name, not a key anything is addressed
by. `createdKeys` is ordered most-specific-first and `name` is last because it
is the fallback for the three families with no key of their own, so the fix is
to read only the first key a body carries: one body names one object.
`TestEveryCreatedObjectCarriesTheProbePrefix` is what guards that now - put the
old behaviour back and it reports `A name`.

The guard's precision improves in the same stroke: it no longer watches a string
that could appear in any golden as a display name.

### F59: `Case.Unordered` silently sorts only the root - **closed, by handling rather than erroring**

**The judgement the brief asked for.** Erroring on the combination is honest and
was the follow-up's own suggestion. Handling it turned out to be cheaper, and
that decided it:

- The walk now runs **once per distinct path depth, deepest first**, splicing
  between passes. Inside one depth no path can be a prefix of another, because
  being a prefix means being shorter, so each walk is the old walk with the
  ambiguity arithmetically impossible. No new matching rules, no new syntax.
- The four entry points collapsed into one shared `editPaths`, so the diff is
  **smaller** than the file it replaces despite adding the behaviour.
- Erroring would have left `admin/client-scopes/list` masking
  `*/protocolMappers` whole - thirty-five bootstrapped protocol mappers under no
  golden - or given up sorting the root, which it cannot, because the scope
  order is unstable too. The error would have been correct and would have
  changed nothing for the better.
- Sorting the inner arrays first is not only permissible, it is better: an
  element's bytes are settled before the outer sort compares them, so the outer
  order is deterministic where before it depended on unsorted inner bytes.

`admin/client-scopes/list` and `admin/client-scopes/list-templates` were edited
in place and re-recorded: `Volatile: {"*/id", "*/protocolMappers/*/id"}`,
`Unordered: {".", "*/protocolMappers"}`. Gloak reproduces all thirty-five
mappers byte for byte on the first try, `config` key order included, so nothing
was promoted or demoted and no new `UnorderedKeys` retreat was needed.

The follow-up in `docs/superpowers/handover/p5-client-scopes.md` about the
masked mappers is closed by this, and the two case comments that described the
limitation now describe the fix.

### F23: three login-theme goldens churn on every re-record - **close it with F69**

F69 supersedes its wording and its fix. The normalisation pass F23 proposes -
rewriting the `/resources/<hash>/` segment - is no longer needed for the churn,
and would be the wrong shape of work for four bodies nothing compares. If those
four cases are ever promoted, the pass becomes necessary again and F23's text is
the design; until then it is closed.

### F40, F45, F53 - **untouched, and one of them is worth a note**

Nothing here changes the pollution guards' behaviour, and
`TestPristineRealmGoldensAreNotPolluted`,
`TestNoGoldenHoldsAnObjectItDidNotCreate`,
`TestPollutionGuardSeesEveryCreatedFamily` and
`TestPollutionGuardReadsTheCataloguesOwnCreates` all still pass.

The one thing they gain is precision: F45's guard read four keys out of every
creation body, and now reads the first key only, so the phantom `A name` object
is gone from its set. **This narrows what the guard watches**, and the narrowing
is safe for the reason above - a client is watched by `clientId`, so a display
name adds nothing - but it is a change to a guard F45 closed and is recorded
here rather than left in a diff.

F53 stays open. Nothing in this cut is a finder for the order-dependent-and-
currently-clean set it exists for.

## 4. Parity before and after

| | total |
|---|---|
| `main` (`4419956`) | **179** of 498 enumerated behaviours served; 4 chapters not enumerated |
| `fix/harness-recorder` | **179** of 498 enumerated behaviours served; 4 chapters not enumerated |

`cmd/parity` reports `no change` - the strong form, meaning no row moved at all,
not `total unchanged`. The two TSV reports are byte-identical; the base was
measured in a `git worktree` at the merge base, as AGENTS.md's recipe describes.

**No case changed status.** F69 and F58 are test-only. F59 changes two existing
`Implemented` cases' masks so that they assert more of the same response; a mask
is not surface, and `Operation` is untouched on both.

## 5. What was run, and every golden that moved

`CGO_ENABLED=0 go test ./...` passes with no Docker and no network.
`go vet ./...` and `go vet -tags docker ./...` are both clean.

Four container starts' worth of recording, all through `make record`'s own
testcontainers, with no hand-started container at any point:

| Run | Purpose | Goldens moved |
|---|---|---|
| whole run, F69's skip deliberately removed | the "before" | **exactly the four F69 names**, and nothing else |
| whole run, F69's skip in place | the "after" | **none**, 290 recorded, 7 parked |
| one case, `admin/client-scopes/list` | the F59 re-record | the two client-scope listings |
| whole run, everything in place | final accounting | **none**, 290 recorded, 7 parked |

The last row is the answer F69 asks for. The third and fourth runs together are
also the stability evidence for section 1.1: the two goldens were written by one
container and reproduced byte for byte by another.

The 297 committed goldens break down as 290 rewritten identically, 4 parked
theme pages, and 3 parked bodies that should probably be `Recorded`.

### Mutations

Eight, one per claim, each applied to a committed tree and reverted:

| Mutation | Killed by |
|---|---|
| `GoldenIsAsserted` returns `true` always | `TestGoldenIsAssertedFollowsTheStatus`, `TestNoPendingGoldenIsCompared` |
| every Pending golden treated as absent | `TestNoPendingGoldenIsCompared`, on its empty-set `Fatal` |
| the recorder's skip deleted | the whole `make record` run: the four F69 goldens churn |
| `admin/roles/create` POSTs `{"name":"a-probe-role"}` - F58's own example | `TestEveryCreatedObjectCarriesTheProbePrefix` |
| an exception naming an object nothing creates | `TestEveryCreatedObjectCarriesTheProbePrefix`, on the stale branch |
| `createdObjects` returns nothing | `TestEveryCreatedObjectCarriesTheProbePrefix`, on the empty-family `Fatal` |
| `createdObjects` reads every key of a body again | `TestEveryCreatedObjectCarriesTheProbePrefix`, reporting `A name` |
| `editPaths` walks once over all depths - the pre-F59 behaviour | `TestSortUnorderedSortsANestedPathUnderTheRoot`, `TestSortUnorderedSortsAPathInsideAnotherPath`, `TestSortUnorderedStillRejectsANonArrayNestedPath` |

**One test survived a mutation it was never meant to catch, and it says so in
its own comment.** `TestNormalizeMasksAnOuterPathThatContainsAnInnerOne` passes
under both the old single walk and the new depth passes, because `Normalize`'s
outer placeholder subsumes the inner one either way. It is a regression guard on
the refactor - proof that four call sites collapsing into one changed no answer -
and not a guard on F59. Reading it as the latter would be reading a green test as
evidence for a claim it does not make, which is the failure this repository keeps
filing follow-ups about.

**The recorder's skip has no unit test.** `record_test.go` is behind the `docker`
tag and CI runs nothing tagged, so deleting the three-line skip leaves
`CGO_ENABLED=0 go test ./...` green. What kills it is running `make record`,
which is where the mutation above was demonstrated. `GoldenIsAsserted` is in
`case.go` rather than in the recorder for exactly this reason - it is the part
that *can* be tested - and `TestConformance` reading the same predicate means the
verifier's half is covered by `make test`. The uncovered part is the call site.

## 6. What `README.md`'s churn paragraph should say instead

The paragraph beginning "`make record` is not silent on a clean checkout" and
the one after it ("All four are `Pending`...") are both wrong now. They should
be replaced by:

> `make record` is silent on a clean checkout: a whole run rewrites 290 goldens
> with identical bytes and moves none of them. Any file in the diff is a real
> change, and there is no expected churn to skip past.
>
> Seven `Pending` cases carry a golden and the recorder leaves all seven exactly
> as it found them, because nothing compares a `Pending` golden - `make test`
> skips those cases whether or not a file exists. Four of the seven are
> login-theme pages whose whole body used to churn per container start, since
> the theme's `/resources/<hash>/` segment is regenerated with the container;
> that is what the run no longer touches. To have one of them recorded again,
> promote the case to `Recorded`, which is what `Recorded` means and which is a
> change a reviewer can see.

The paragraph after those two - the one about
`oidc/token/password-grant-admin-cli`'s `scope` and `UnorderedWords` - opens
with "A fourth used to churn". With the four named churners gone from the text
above it, that "fourth" no longer has three to be fourth to. It should read
"One more used to churn".
