# Harness sweep: what belongs in the documents this branch may not edit

Date: 2026-08-29
Branch: `fix/harness-sweep`
Follow-ups cleared: **F46, F47, F48, F53**

Everything measured below came from a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on port 8093, started and removed
by this branch alone. The goldens came from a whole `make record` after all four
changes were in place. This branch does not touch `AGENTS.md`, `README.md` or
the three spec documents, so what is owed to them is written out here.

Everything in section 1 is **already applied on the branch** unless a line says
otherwise. `main` had not moved from `503ecc0` at any point during this cut, so
nothing here needs re-checking against a parallel stream.

## 1. Measurements to fold into `2026-08-18-keycloak-26.7.1-observed.md`

### 1.1 All seven admin creates' `Location`, measured together

The seven admin 201s that carry a `Location` were measured in one session,
before the masking mechanism was designed, because F39 was filed with a design
that did not cover its own fifth case. These are the values, with the live host
written as `{issuer}`:

| Request | `Location` |
|---|---|
| `POST /admin/realms/{r}/clients` | `{issuer}/admin/realms/master/clients/<uuid>` |
| `POST /admin/realms/{r}/users` | `{issuer}/admin/realms/master/users/<uuid>` |
| `POST /admin/realms/{r}/groups` | `{issuer}/admin/realms/master/groups/<uuid>` |
| `POST /admin/realms/{r}/groups/{id}/children` | `{issuer}/admin/realms/master/groups/<uuid>` |
| `POST /admin/realms/{r}/roles` | `{issuer}/admin/realms/master/roles/<the role name>` |
| `POST /admin/realms/{r}/clients/{id}/roles` | `{issuer}/admin/realms/master/clients/<client uuid>/roles/<the role name>` |
| `POST /admin/realms` | `{issuer}/admin/realms/<the realm name>` |

Two of these are new facts rather than confirmations.

**The child create's `Location` is `/groups/<child uuid>`, not
`/groups/{parent}/children/<child uuid>`.** The route that creates a child is
not the route that addresses it; a child is addressed like any other group once
it exists. The whole-header mask had been hiding this since the case was
written.

**Three of the seven end in a name the request chose, and only four end in
something minted.** A rule of the form "an admin create's `Location` ends in the
new object's id" is wrong on three of seven. The two that end in a realm name or
a role name are the same two families that address those resources by name
elsewhere.

The UUIDs are the canonical 8-4-4-4-12 spelling in lower case, on all four.

### 1.2 `GET /admin/realms/{realm}/groups/count` on a two-group realm

A bootstrapped realm holds **no** groups: `{"count":0}` on a realm created
through `POST /admin/realms`, and `master`'s count moved from 0 to exactly 3
after this session created three groups in it. A parent plus one child - the
`admin-token-group-tree` fixture - answers `{"count":2}`, and `?top=true`
answers `{"count":1}`.

That is what lets `admin/groups/count`'s golden hold a number again instead of
`{{number}}`. See F47 below.

### 1.3 A repeated query parameter, re-measured end to end

On `GET /realms/master/protocol/openid-connect/auth` with a valid `client_id`,
`redirect_uri`, `response_type`, `scope` and `state`, plus `zz=1&zz=2`:

```
HTTP/1.1 302 Found
Cache-Control: no-store, must-revalidate, max-age=0
Location: http://localhost:9999/callback?error=invalid_request&error_description=duplicated+parameter&state=xyz123&iss=http%3A%2F%2Flocalhost%3A8093%2Frealms%2Fmaster
```

A repeated `nonce` in place of the repeated `zz` answers identically. This
confirms the two claims already in the observed document - the description is
lower case, and the check fires on a key the endpoint never reads - and adds the
one a golden needs: **nothing in that `Location` is per-request** once
`ReplaceIssuer` has run, so the case that pins this family needs no mask at all.

### 1.4 Four filtered realm-wide reads are immune to what the realm holds

Measured by taking a baseline, then creating a client, a user, a realm role and
a group, and granting the realm role `admin` to the new user and to the new
group. The four reads below were issued before and after:

| Read | before | after |
|---|---|---|
| `GET /clients`, caller holding `query-clients` | `[]` | `[]` |
| `GET /users`, caller holding `query-users` | `[]` | `[]` |
| `GET /users/{id}/role-mappings/realm/available`, caller holding `view-users` | `[]` | `[]` |
| `GET /roles/admin/users`, administrator | `["admin"]` | `["admin", <the new user>]` |
| `GET /roles/admin/groups`, administrator | `[]` | `[<the new group>]` |

The first three are `[]` because of the **caller**, and stay `[]` however much
the realm accumulates - including a realm role that is not an admin role, which
a `view-users` caller still may not confer. The last two are functions of the
whole realm.

This is the measurement that decides F53's derived check, so it is worth
stating as a contract rather than as a note: **`GET /admin/realms/{realm}/clients`
with no query is realm-wide for an administrator and provably empty for a
`query-clients` caller.** Same method, same path, same query, opposite answers,
decided by the bearer token.

## 2. Entries for AGENTS.md

### 2.1 For "Things that look like bugs and are not"

Place after the group-tree bullet, since it is a seventh disagreement inside
that family, and before the realm-keys bullet.

> - **A create's `Location` ends in the new object's id on four routes out of
>   seven.** `POST .../clients`, `.../users`, `.../groups` and
>   `.../groups/{id}/children` end in a server-minted UUID; `POST .../roles` and
>   `POST .../clients/{id}/roles` end in the **role's name**, and
>   `POST /admin/realms` in the **realm's name**. And the child create's
>   `Location` is `/groups/<child uuid>`, not
>   `/groups/{parent}/children/<child uuid>` - the route that makes a child is
>   not the route that addresses it. All seven measured in one session on
>   2026-08-29, because a masking rule written from four of them would have been
>   wrong on three. `Case.VolatileTailHeaders` masks the last segment for the
>   four that need it and refuses the three that do not.

### 2.2 For "Build and test"

Place immediately after the `TestPristineRealmGoldensAreNotPolluted` bullet,
which it extends.

> - **The pollution guard now reads every golden, not the ten pristine ones.**
>   `TestNoGoldenHoldsAnObjectItDidNotCreate` applies the same check to the rest
>   of the catalogue, because the invariant was never the pristine group's: a
>   golden may hold only what bootstrap, the case's own fixture and its own
>   request produced, since those three are exactly what the verifier
>   reproduces. It is a ratchet and not a finder - every committed golden passes
>   it today - and it fires one step earlier than `TestConformance`, on the
>   re-record that first pollutes a golden rather than on the run that then
>   cannot reproduce it.
> - **`PristineRealm` cannot be derived, and two measurements say so.** The
>   request shape does not determine it: `GET /admin/realms/master/clients` with
>   no query is realm-wide for an administrator and measured `[]` before and
>   after pollution for a `query-clients` caller. And replaying every case
>   against a realm every fixture has touched does not work, because fixtures
>   are deliberately not idempotent - `idempotentCreate` exists for the creates
>   that may repeat, and the ones capturing a `Location` may not - so putting
>   all 73 on one handler produced 22 failures, nine in the pollution pass
>   itself, and none of them order-dependence. The flag stays a declaration, and
>   the sweep that checks it is a person reading the catalogue. See F53.
> - **A case can send one query key twice.** `Request.RawQuery` is the query
>   string verbatim, which is the only way to express the authorization
>   endpoint's `duplicated parameter`. It replaces `Query` rather than adding to
>   it, and it is **not** expanded - `Expand` rewrites `Path`, `Query`,
>   `Headers`, `Form` and `Body` and does not reach it, so
>   `TestCatalogIsWellFormed` refuses a `{{name}}` inside one rather than
>   letting the braces reach the server.

### 2.3 A line in AGENTS.md this work contradicts

The `make record` section says, of F40:

> **Ordering also cannot be checked afterwards** - `admin/users/count`'s entire
> body is the byte `1`, and no guard can tell a polluted count from a clean one.

That is still true of a guard that reads bytes, and this cut confirms it: with
`admin/groups/count`'s `PristineRealm` removed, both pollution guards stay green.
But the sentence reads as though nothing could check it, and something can -
**re-serving the case against a polluted realm** tells a polluted count from a
clean one directly, because the answer moves. That route was tried here and
rejected on a different ground (the fixtures are not replayable, section 2.2),
not because the property is unobservable. Suggested amendment: replace "no guard
can tell" with "no guard that reads the recorded bytes can tell", and let F53
carry the reason the semantic route is closed too.

There is a second, smaller contradiction, already fixed on the branch rather
than owed to a document. `catalog_admin.go`'s `admin/realms-admin/create` carried
the comment "the served side's headers are not issuer-normalised by the differ
today". `diff` has normalised them since P3 and says so in its own comment. The
claim survived because the header it was written about was masked, which is
exactly F46's point.

## 3. Follow-ups to file or close

### F46 - a masked header is asserted on presence alone: **closed**

`Case.VolatileTailHeaders` masks a header's final path segment and compares
everything before it, requiring the segment to be a UUID on both sides. Applied
to the four admin creates whose `Location` ends in a minted id.

The other three - `admin/roles/create`, `admin/roles/create-client` and
`admin/realms-admin/create` - **dropped their mask entirely** and assert their
`Location` whole. Nothing in them is minted once `ReplaceCaptured` and
`ReplaceIssuer` have run; the client UUID in the middle of the sixth is the
fixture's own capture. Declaring one of those three here is a loud failure at
record time rather than a wider mask.

All seven goldens re-recorded. The mechanism was checked against all seven
before it was written, which is what F39 says to do.

### F47 - `admin/groups/count` can have its measured number back: **closed**

The claim was verified rather than trusted: a bootstrapped realm holds no
groups, and this fixture's parent and child answer `{"count":2}` on a live
26.7.1. `Volatile: []string{"count"}` is gone and the golden holds `{"count":2}`.

The case was already `PristineRealm`, so no container was added.

### F48 - the harness cannot send one query key twice: **closed as a mechanism**

`Request.RawQuery` sends the query verbatim; `buildRequest` refuses a case that
sets both it and `Query`, because merging them would need an order and
`url.Values.Encode` sorts.

**The conformance case is deliberately not added** - `catalog_oidc.go` belongs to
another cut this session. The family is now expressible, and the case a later
cut should add is:

- **ID**: `oidc/authorization/duplicated-parameter`
- **Fixture**: `browser-client`
- **Status**: `Implemented` - `internal/oidc/authorize.go` serves it at step 7
  (`descDuplicatedParameter`) and unit-tests the two adjacencies around it
- **Request**: `GET /realms/master/protocol/openid-connect/auth` with
  `RawQuery: "client_id=gloak-probe-browser&redirect_uri=http://localhost:9999/callback&response_type=code&scope=openid&state=xyz123&zz=1&zz=2"`
- **Expected**: 302, `Cache-Control: no-store, must-revalidate, max-age=0`, and
  a `Location` carrying `error=invalid_request`,
  `error_description=duplicated+parameter`, `state=xyz123` and `iss` - measured,
  section 1.3. No mask of any kind, which is the point: the whole query key
  order is asserted.
- A second case sending a repeated `nonce` would add nothing; it was measured
  and answers identically.

One limitation to hand on: `Expand` lives in `fixture.go` and does not reach
`RawQuery`, so a case needing both a repeat and a `{{name}}` cannot be written
yet. `TestCatalogIsWellFormed` refuses one rather than sending the braces.
Teaching `Expand` the field is one line in a file this branch may not touch.

### F53 - which other goldens enumerate a realm-wide set: **closed, three found**

The sweep read all 273 cases. **Three needed the flag and did not carry it**, and
all three were clean today, which is the outcome F53 predicted:

1. **`admin/roles/users`** - `GET /roles/admin/users` is every user in the realm
   holding a bootstrapped role. Measured: granting `admin` to a created user puts
   that user in the body. No fixture grants it, and that was the whole guard.
2. **`admin/roles/groups`** - the same, for groups. Eight fixtures create groups.
3. **`admin/realms-admin/default-groups-empty`** - reads a list that
   `admin/realms-admin/default-group-add` writes three cases later in the same
   realm. Its `[]` held because the catalogue reads before it writes; this is
   F40's disease with a case rather than a fixture as the polluter, and the
   first instance found where the polluter is a **case**.

No golden changed when they were marked, so none was wrong - which is what
"order-dependent and currently clean" means.

**Four more were examined and deliberately left unmarked**, with the reasoning
written at the case rather than here: `client-profiles-empty`,
`client-profiles-global`, `client-policies-empty` and `client-policies-global`
all read `gloak-probe-profiles`, and four later cases PUT that realm's profiles
and policies. They survive because every one of those writes writes the *empty*
state. Give any of those PUTs a non-empty body and the four goldens become
wrong, so the body and the flag change together.

**Ones the sweep cleared, with the measurement that cleared them**, since
"realm-wide listing" describes all of them: `admin/clients/list-to-a-query-clients-caller`,
`admin/users/list-without-view-users` and
`admin/role-mapper/available-to-a-view-users-caller` are `[]` because of the
caller, not because of the realm, and stay `[]` under pollution - section 1.4.
`admin/roles/list-realm-page-no-search` already carried its own written argument
and it holds. The six filtered user listings are narrowed by a name no fixture
uses; that is an accident nothing checks, and it is the residual risk this cut
leaves behind.

**The derived check was attempted and is declined**, on two grounds, both
measured rather than argued - see section 2.2 for the wording. Its replacement
is `TestNoGoldenHoldsAnObjectItDidNotCreate`, the F45 guard widened from ten
goldens to all of them. That is a ratchet rather than a finder and the code says
so.

### New: F58 - a paged golden's window is held by a name nobody guards

Worth filing. `admin/roles/list-realm-page-no-search` sends `first=1&max=2` with
no `search` and its golden holds `create-realm` and `default-roles-master`. The
case's comment argues correctly that every realm role any fixture creates is
named `gloak-probe-...`, which sorts after `default-roles-master` and cannot
enter the window. Six of the user listings rest on the same kind of argument -
`?username=admin` is a substring filter that no `gloak-probe-*` username matches.

Every one of those arguments is about **names**, and nothing enforces the naming
convention they rest on. A fixture creating a realm role named `a-probe-role`, or
a user named `admin-probe`, breaks several goldens at once and breaks them
loudly, which is the good case - but it breaks them in cases whose comments then
read as though they had been checked.

A test asserting that every object any fixture or case creates is named
`gloak-probe-*` would turn six written arguments into one checked one. It is
cheap: `createdObjects()` already collects exactly that set for the pollution
guard, and asserting a prefix over it is three lines. Not done here because it
is a new rule about the catalogue rather than a fix to a measured divergence,
and imposing it belongs to whoever owns the naming convention.

## 4. Parity before and after

| | total |
|---|---|
| `main` (`503ecc0`) | **147** of 489 enumerated behaviours served; 4 chapters not enumerated |
| `fix/harness-sweep` | **147** of 489 enumerated behaviours served; 4 chapters not enumerated |

Unchanged, and no case changed status. Nothing here adds surface: F46 and F47
make two existing goldens assert more, F48 adds a mechanism and no case, and F53
adds three `PristineRealm` markings that moved no bytes.

## 5. What was run, and what a mutation survived

`CGO_ENABLED=0 go test ./...` passes with no Docker and no network. A whole
`make record` ran against a live 26.7.1 after every change: **eleven goldens
moved**, the eight this cut intends and F23's three login-theme churners, whose
resource hash went `l3kth` to `qw6hr`. There is no fourth. The run cost 337s and
started 14 containers, one shared and thirteen pristine - the ten that were
marked before plus the three above.

Every guard was mutation-tested. Nine mutations, one per claim, each applied to
a committed tree and reverted:

| Mutation | Killed by |
|---|---|
| `MaskURLTail` masks the whole value | `TestDiffAcceptsADifferentIDInAVolatileTail`, `TestRecordedHeadersKeepsEverythingBeforeAVolatileTail` |
| `diff` compares a volatile tail on presence alone (the pre-F46 behaviour) | `TestDiffRejectsAWrongPathUnderAVolatileTail`, `TestDiffRejectsAVolatileTailThatIsNotAURL` |
| the recorder stops refusing a tail that is not a UUID | `TestRecordedHeadersRefusesATailThatIsNotMinted` |
| `admin/groups/count` asks `?top=true` | `TestConformance/admin/groups/count`, `want {"count":2}, got {"count":1}` |
| `RawQuery` flattened through `url.Values` | `TestBuildRequestSendsOneKeyTwice`, `TestBuildRequestSendsARawQueryVerbatim` |
| both query forms accepted silently | `TestBuildRequestRefusesBothQueryForms` |
| a volatile tail nobody asserts | `TestCatalogIsWellFormed` |
| one header masked whole and by its tail | `TestCatalogIsWellFormed` |
| a `RawQuery` carrying `{{access_token}}` | `TestCatalogIsWellFormed` |
| `admin/groups/read` given a fixture that makes no group | `TestNoGoldenHoldsAnObjectItDidNotCreate` |

**One survivor, and it is a finding about a test rather than about the code.**
`TestDiffRejectsAWrongPathUnderAVolatileTail` passes when `MaskURLTail` is
mutated to mask the whole value, because that mutation also produces a
difference - the test asserts *that* the diff is non-empty and cannot say why.
It is killed by its sibling on the accept side, so the pair is sound and the
mutation does not survive the suite; but the reject test alone is insensitive to
over-masking, and a reader taking it as the guard for F46 would be taking too
much from it.

**A second, deliberate non-kill.** Removing `PristineRealm` from
`admin/groups/count` leaves both pollution guards green. That is not a survivor -
it is the documented limit of a guard that reads recorded bytes, stated in
`case.go`, in AGENTS.md and in F40, and it is the reason F53's derived check was
looked for at all. It is recorded here because it is the mutation a reviewer
will reach for first.
