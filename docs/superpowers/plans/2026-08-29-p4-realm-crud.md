# P4's first cut, A: the realm as a resource

Date: 2026-08-29
Spec: `docs/superpowers/specs/2026-08-29-p4-multi-realm-design.md`

Five operations: `GET`/`POST /admin/realms`, `GET`/`PUT`/`DELETE
/admin/realms/{realm}`. Plus the thing that makes them mean anything - a second
realm that is bootstrapped like Keycloak bootstraps one.

Cuts B (the key set) and C (the realm-level defaults) get their own plans when
this one lands, for the reason the roadmap gives: a plan written before anyone
reaches the work has the appearance of accuracy without the measurement behind
it.

## Files

| File | Why |
|---|---|
| `internal/model/model.go` | `Realm` gains `Settings` |
| `internal/store/store.go` | `RealmRepo` gains `ByID`, `Update`, `Delete` |
| `internal/store/sqlite/migrations/0012_realm_settings.sql` | **new** |
| `internal/store/postgres/migrations/0012_realm_settings.sql` | **new** - the two drivers migrate separately |
| `internal/store/sqlite/sqlite.go` | the three new methods |
| `internal/store/postgres/postgres.go` | the three new methods |
| `internal/store/storetest/conformance.go` | the driver-agreement suite gains them, and a second realm |
| `internal/bootstrap/bootstrap.go` | split into master-only and per-realm |
| `internal/bootstrap/bootstrap_test.go` | the second realm's own assertions |
| `internal/admin/realms.go` | **new** - the five handlers |
| `internal/admin/realmrep.go` | **new** - the 106-field representation and its five shapes |
| `internal/admin/realms_test.go` | **new** |
| `internal/admin/auth.go` | cross-realm caller resolution |
| `internal/admin/roles.go` | `ownedByRealmOwnClient` learns `realm-management` |
| `internal/admin/representation.go` | `clientAccessFor` learns the same |
| `internal/admin/router.go` | five registrations, two new guards |
| `internal/keys/manager.go` | evict the cache on a realm delete |
| `internal/conformance/catalog_admin.go` | the cases |
| `internal/conformance/fixture.go` | realm fixtures |
| `docs/.../2026-08-18-keycloak-26.7.1-observed.md` | the measurements |
| `docs/.../2026-08-18-gloak-followups.md` | F31's second counter-example |
| `AGENTS.md` | the boundary that moves, and the new must-not-tidy list |

## Task 1: the measurement that constrains everything else

**This is first because its answer decides whether the cut is five handlers or a
rewrite of the guard layer.**

Section 7.1 of the spec asks whether a caller's rights in one realm reach
another. Take it on a live 26.7.1, one caller per role, a fresh token minted
immediately before every call:

- a caller in `master` holding exactly one role of `master-realm`, against
  `/admin/realms/master`, `/admin/realms/other`, and `other`'s `/users`,
  `/clients`, `/roles`;
- the same caller shape holding a role of `other-realm` instead;
- a caller inside `other` holding exactly one role of `realm-management`,
  against its own realm, `master`, and a third realm;
- all 21 admin roles individually against `GET`, `PUT` and `DELETE` of a realm,
  and against the listing;
- the realm role `create-realm` against `POST /admin/realms` and against
  everything else.

Record the tables in the observed document beside "The role check is by
container", and say plainly whether one container answers every question or two
do.

**Done 2026-08-29.** Two containers, and the answer is in section 7 of the spec.
The load-bearing findings, because Task 5 is written against them:

- rights are resolved against **one** container chosen by the **token's** realm:
  `{target}-realm` in master for a master token, `realm-management` in the realm
  for a realm token;
- `GET /admin/realms/{realm}` is the **one** place a master caller's rights
  cross into another realm, and only into its four-key body;
- nothing crosses upwards: `realm-admin` inside `other` is 403 on master;
- `impersonation` is the one admin role that opens nothing here;
- `POST /admin/realms` takes `create-realm` and refuses `manage-realm` and
  `realm-admin`;
- the realm is resolved **before** the caller is judged, so an unknown realm is
  404 to a caller holding nothing.

**Nothing is implemented in this task.** Its output is the spec and the observed
document.

Commit: `docs(realms): measure realm CRUD and whether rights cross a realm`

## Task 2: the representation, before any route serves it

`internal/admin/realmrep.go`. The struct and its five shapes, no handlers, no
store.

The spec's section 4.1 body is 104 keys in a fixed order and master's is those
plus `displayName` and `displayNameHtml` after `realm`. Go's struct field order
is the only thing that reproduces it, so the struct is written out in full and a
test asserts the marshalled key order against the recorded body rather than
against a hand-typed list.

Five shapes, and they are **not** a hierarchy:

| Shape | Keys | Who gets it |
|---|---|---|
| full | 104-106 | `view-realm`, `manage-realm`, `realm-admin` |
| users-reduced | 5-7 | `view-users`, `manage-users` |
| reduced | 4-6 | the other sixteen admin roles |
| listing brief | 3-5 | `briefRepresentation=true`, `view-realm` caller |
| listing narrow | 1 | any caller without `view-realm`, flag ignored |

The trap is `supportedLocales`: it is **absent** from the full shape and `[]` in
the two reduced ones, so it cannot be one field with `omitempty`, and it cannot
be a pointer set on both paths either. Three shapes want three structs; the
alternative is one struct and a marshaller that drops keys, which is the "one
serialiser" mistake the user representation already records.

`defaultRole` is a `roleRepresentation` and is **derived** from the realm's
`default-roles-{name}` role, not stored: its `id` and `containerId` are the
store's.

Tests: one per shape, each asserting the byte-exact key order, plus one
asserting `displayName`/`displayNameHtml` appear only when set and in position.

Commit: `feat(admin): the five shapes of a realm representation`

## Task 3: the store

`model.Realm` gains one field:

```go
Settings []byte // the RealmRepresentation as last written, minus the five
                // fields the columns own
```

**Why a blob and not 104 columns.** Gloak interprets five of the realm's fields
- `id`, `realm`, `enabled`, `accessTokenLifespan` and `ssoSessionIdleTimeout`,
the last two being `AccessTokenLifespan` and `RefreshTokenLifespan`. The other
101 are configuration P4 stores and does not read: `otpPolicyDigits` is P8's,
`smtpServer` is P14's, `browserFlow` is P8's. A column each is 101 columns in
two drivers for state nothing queries, and every one of them is a migration when
a later cut needs a 102nd. Nothing observable depends on the answer, which is
what section 10 of the spec says.

**The five columns stay the truth.** The blob is written whole and read whole,
and the read path then overwrites those five from the row, so the copies inside
the blob can never be observed and cannot drift into a divergence. One function
does it and a round-trip test asserts it.

`RealmRepo` gains three methods:

```go
ByID(ctx, id) (*model.Realm, error)
Update(ctx, r *model.Realm) error   // renames; the id does not change
Delete(ctx, id) error
```

`Update` must map a name collision to `ErrConflict` - the measured 409 on a
rename onto a taken name - and `affectedOne` is the existing helper for "changed
nothing" to `ErrNotFound`.

`Delete` needs nothing new in the schema: every root table already cascades off
`realm(id)`, and SQLite enforces it because `withForeignKeysPragma` is on.
`internal/store/storetest` gains a subtest that proves it, because "the schema
says so" is not evidence that both drivers do.

Both migrations, written separately, `0012_realm_settings.sql` in each driver.

Verify: `CGO_ENABLED=0 go test ./internal/store/...`, then
`go test -tags docker ./internal/store/postgres/` by hand, and paste both
outputs into the commit body. `AGENTS.md` requires the second.

Commit: `feat(store): a realm's settings, update and delete`

## Task 4: bootstrap becomes realm-parameterised

`EnsureMaster` splits in two.

`CreateRealm(ctx, s, name)` builds what section 5 of the spec measured:

- six clients, five of them master's and the sixth `realm-management` where
  master has `master-realm`;
- **three** realm roles, not five - `admin` and `create-realm` exist in master
  alone;
- `realm-management` with **22** roles, the extra one `realm-admin`, composite
  over the other 21, and the three `view-*` composites master's container has;
- `default-roles-{name}` over `offline_access`, `uma_authorization` and
  `account`'s `manage-account` and `view-profile`;
- **and, in master, a `{name}-realm` client** with 21 roles and no
  `realm-admin`, `defaultClientScopes` and `optionalClientScopes` empty, name
  `{name} Realm`;
- **and 21 new composites on master's `admin` realm role.**

`EnsureMaster` becomes `CreateRealm("master")` plus the master-only part: the
`admin` and `create-realm` realm roles, the administrator account and its
credential.

**The boundary in AGENTS.md is contradicted by the measurement and moves in this
task, not after it.** `internal/bootstrap` "must not modify objects that already
exist" and creating a realm modifies master's `admin` role. The line becomes
"must not modify objects that already exist, except master's `admin` role, which
Keycloak was measured extending by 21 composites per realm created and
contracting by 21 per realm deleted." A boundary that the code quietly breaks is
worse than one that says what it allows.

`DeleteRealm(ctx, s, realm)` is the inverse: remove the `{name}-realm` client
from master, which takes the 21 composites with it through the schema's cascade,
and remove the realm, which takes everything else.

Tests: the existing 14 assert master and keep asserting it unchanged. New ones
assert a second realm's six clients, three realm roles, 22-role container,
`{name}-realm` in master with 21, and that `admin` gains exactly 21 composites
and loses exactly 21.

Commit: `feat(bootstrap): create any realm, not only master`

## Task 5: the caller crosses realms, and the container test learns a second name

Three changes that have to land together, because each on its own is a
divergence.

**`resolveCaller` resolves the caller in the realm that issued the token, not
the realm in the path.** Today it verifies the token against the path realm's
issuer and keys and looks the session up there. A master administrator reading
`/admin/realms/other` has a master token and a master session, so today it
cannot authenticate at all. It tries the path realm first and master second -
that order, because a realm-issued token must not be resolvable against master's
keys by accident, and `token.ParseAccess` checks `iss`, so a wrong realm fails
closed.

**`ownedByRealmOwnClient` learns `realm-management`.** The predicate answers "is
this role one of the realm's admin roles". The container is `{realm}-realm` when
the caller authenticated in master and `realm-management` when it authenticated
in the realm itself. Its own comment already says a missed generalisation here
makes every admin role outside master grantable to anybody; that is why this is
not a later task. `clientAccessFor` in `representation.go` takes the same
change.

**The realm roles `admin` and `create-realm` stay master-only.**
`adminRoleNames` tests them by name, which is safe exactly because no other
realm has them - and Task 4 must not create them in one.

Tests: a table over the four combinations - master token on master, master token
on another realm, realm token on its own realm, realm token on another - each
asserting the container the caller's rights were read from. And a regression
test for the escalation the comment names: a `realm-management` role must not be
grantable by a caller that does not hold it.

Verify: `CGO_ENABLED=0 go test ./...` **whole**, not only `internal/admin`. This
task touches the guard every existing admin case goes through.

Commit: `fix(admin): resolve an admin caller in the realm that issued its token`

## Task 6: the five routes

`internal/admin/realms.go`, `internal/admin/router.go`.

Two new guards, because `GET` and `POST /admin/realms` have no `{realm}` segment
and every one of the twelve existing combinators starts with `resolveRealm`:

- `guardRealmless` for the collection: authenticate against master, then the
  route's roles. `POST` takes `create-realm` and `GET` takes any admin role
  except `impersonation`.
- `guardRealmResource` for the three that name a realm: **resolve the realm,
  then the caller, then the role** - the order section 7.2 measured, which is
  `guardGroup`'s and not `guardUserSubject`'s.

The routes:

| Route | Guard | Roles |
|---|---|---|
| `GET /admin/realms` | `guardRealmless` | any admin role but `impersonation` |
| `POST /admin/realms` | `guardRealmless` | `create-realm` |
| `GET /admin/realms/{realm}` | `guardRealmResource` | any admin role but `impersonation`; the shape follows the role |
| `PUT /admin/realms/{realm}` | `guardRealmResource` | `manage-realm` |
| `DELETE /admin/realms/{realm}` | `guardRealmResource` | `manage-realm` |

**`impersonation` being the exception is a measurement, not a rule.** Twenty of
the 21 open the read. It is written as an exclusion rather than a 20-name list
so the next reader sees that the list was not chosen.

The error shapes are section 8's, all seventeen of them, and the three families
are three helpers rather than one. `PUT`'s malformed-body 400 is the RFC 6749
shape and `POST`'s is the `errorMessage` one; a shared decoder gets one wrong.

Commit: `feat(admin): realm CRUD, five operations`

## Task 7: the cases and the goldens

Fixtures. The existing 55 all use `State: "bootstrap"` and address
`/realms/master`. Two new ones build a second realm through `Steps` calling
`POST /admin/realms`, rather than a second `State`, which is what the file
already does for every other resource.

**Check what this does to `PristineRealm`.** Those cases record the realm as a
whole and the recorder runs them first, before every other case, because one
container is shared. A fixture that creates a **second** realm does not disturb
master's users, clients, roles or groups - but `GET /admin/realms` is itself a
`PristineRealm` case and every realm any other fixture creates is in its body.
So the listing case has to be `PristineRealm: true` **and** the realm-creating
fixtures have to come after it, and `TestPristineRealmGoldensAreNotPolluted` is
what says whether that held.

Cases: one per operation, plus the shapes and the errors. Each success carries
`Operation` so the meter counts it once; the errors carry none, by the rule
`admin/users/unknown-realm` states.

IDs are `admin/realms-admin/...` - `chapterOf` is the first two segments, so a
case named anything else counts towards the wrong denominator.

Record against the container. **Read the diff before committing**: an unreviewed
re-record pins a regression as the contract.

Then `make conformance` and state the number in the commit body.

Commit: `test(conformance): realm CRUD`

## Task 8: the documents

`AGENTS.md`: the bootstrap boundary, the two admin containers, and the twelve
behaviours in section 6 of the spec that must not be tidied up.

`docs/.../2026-08-18-gloak-followups.md`: F31 gains its second counter-example -
`DELETE /admin/realms` answers **405** where `DELETE` on a role-mapping path
answers 404, so "the verb decides" is refuted and neither rule fits.

The roadmap: P4's first cut marked done with the served count, and the per
operation split from section 2 of the spec, because the roadmap's "Realms Admin
45" is a denominator and 16 is the number P4 builds.

`README.md` if it carries a parity number.

Commit: `docs(p4): record realm CRUD and the two admin containers`

## What this plan deliberately does not do

**No `GET /admin/realms/{realm}/keys`.** A created realm carries four keys where
Gloak mints three, and the fourth is an AES key Gloak has no model for. Cut B.

**No default groups, no client policies, no client types, no localization, no
events.** Ten operations of P4's sixteen and twenty of the tag's forty-five.

**No realm import or export.** Counted in this tag, built in P14, and the
roadmap says so.

**No `VERIFY_PROFILE`.** Section 10 of the spec records that a user created in a
new realm with an incomplete profile cannot obtain a token on Keycloak and can
on Gloak. That is P8's, it is a divergence, and this cut names it rather than
fixing it.

**Nothing changes about the 405.** Gloak answers 404 to every unmatched verb.
This cut adds a second counter-example to F31 and no code.
