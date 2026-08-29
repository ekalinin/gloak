# Harness debt: F38, F39, F40 and the guard that missed F40

Branch `fix/harness-debt`. Everything below belongs in a document this branch is
not allowed to edit, so it is written here to be folded in.

Four files changed. No golden changed: the whole catalogue was re-recorded
against a live 26.7.1 with the fix in place and came back byte-identical apart
from F23's three known churners.

- `internal/conformance/catalog_test.go` - the pollution guard, widened, plus a
  test that proves it can fail.
- `internal/conformance/record_test.go` - a fresh container per `PristineRealm`
  case; `recordingOrder` deleted.
- `internal/conformance/case.go` - what `PristineRealm` now means.
- `internal/conformance/catalog_admin.go` - one case marked `PristineRealm`.

## Entries for AGENTS.md

Under **Build and test**, beside the `make record` lines:

- **The recorder runs two container regimes and the catalogue decides which.**
  Almost every case is recorded against one shared Keycloak, in catalogue order,
  which is why a whole run costs one container start and not three hundred. A
  `PristineRealm` case gets a container of its own, started inside its subtest
  and terminated with it, because its body is a function of the whole realm and
  the verifier will serve it from a handler that has seen nothing but that
  case's own fixture. Recording pristine cases *first* was the previous answer
  and it does not hold: the pristine group pollutes itself. `admin/groups/list`
  creates a group, `admin/groups/count` counts the realm three cases later, and
  that case's number is masked to this day because the recorder said 3 where a
  pristine replay says 2.

- **A golden that holds only while the catalogue's order holds is worse than no
  golden**, because it looks like a measurement. That is why F40 was fixed in
  the recorder rather than by marking the case and re-recording: marking it
  alone does produce the right bytes today, purely because none of the eight
  pristine fixtures happens to create a realm role.

- **Ordering cannot be checked afterwards, only replaced.**
  `TestPristineRealmGoldensAreNotPolluted` compares names, and
  `admin/users/count`'s entire body is the byte `1`. No guard can tell a
  polluted count from a clean one, which is why the container resets rather
  than the position.

- **`TestPristineRealmGoldensAreNotPolluted` watches four resource families**,
  read out of the creation bodies themselves: clients by `clientId`, users by
  `username`, realms by `realm`, roles and groups both by `name`. A fixture that
  creates a fifth kind of object named by some other key is invisible to it
  until that key is added to `createdKeys`. It watched `clientId` alone until
  2026-08-29, which is exactly how F40 got past it.

- **A case's own request creates objects too, and the shared container cannot
  tell them from a fixture's.** `admin/roles/create` POSTs
  `{"name":"gloak-probe-role-create"}` and that role is in the realm for
  everything recorded after it. The guard reads fixture steps and catalogue
  requests for that reason: reading fixtures alone named twelve of the thirteen
  roles in the polluted F40 recording, and the thirteenth was this one.

- **A POST whose body is a JSON array is not a creation.** The role-mapping and
  composite writes are POSTs naming roles that already exist, and reading
  `[{"id":"...","name":"manage-users"}]` as a creation puts six bootstrapped
  admin role names into the guard's set.

Under **Things that look like bugs and are not**, nothing changes. None of this
is Keycloak behaviour; it is all about how the two sides of the comparison are
obtained.

## Follow-ups

### F40: fixed

`admin/role-mapper/group-realm-available` reads every realm role the group does
not hold, so its body is a function of the whole realm. It was not marked
`PristineRealm`, and a whole-catalogue recording put thirteen other fixtures'
probe roles into a golden whose committed form has the five Keycloak bootstraps.

**Reproduced live before fixing.** A whole `make record` on the pre-fix
recorder against 26.7.1 rewrote this golden with **18 roles, 13 of them
`gloak-probe-*`** - exactly what F40 describes - and reported PASS. It is the
only golden in the catalogue that regime gets wrong; the other three that moved
are F23's login-theme churn.

The old guard could not have seen it. That body holds zero occurrences of
`clientId`. The widened guard names all thirteen, each with what made it:

```
"admin/role-mapper/group-realm-available": golden holds name "gloak-probe-attrs",
which "admin-token-role-with-attributes" created - this case has to be recorded
against a realm nothing else has touched
... twelve more, one of them naming a case rather than a fixture
```

**Fixed** by giving every `PristineRealm` case a container of its own, and
marking this case `PristineRealm`.

Two alternatives rejected, both in the commit message:

- *Mark the case and leave the recorder alone.* It produces the right bytes
  today by luck of catalogue order, and pins the golden to that order. The first
  pristine case added above it with a role-creating fixture moves it silently.
  `admin/groups/count` is the same defect already realised, and its answer was
  to mask the number.
- *Record every case against its own container.* Honest, and it would make the
  recorder and the verifier the same in all cases rather than in the nine that
  declare it. Three hundred Keycloak starts is north of two hours for a run that
  is meant to be a habit.

**A whole `make record` was then run against 26.7.1 with the fix in place, and
the only goldens that changed are F23's three** - the login-theme
per-container resource version, unrelated and already filed. Every other golden
in the catalogue, pristine ones included, came back byte-identical, which is the
evidence that the recorder change reproduces the committed contract rather than
merely producing a different one.

Both whole runs were timed on this machine with the image already pulled:

| Recorder | Whole `make record` | Goldens wrongly rewritten |
|---|---|---|
| shared container, pristine cases first | 27s | `admin/role-mapper/group-realm-available` |
| a container per pristine case | 147s | none |

So the fix costs two minutes on a run that is deliberate and rare. A Keycloak
start is about 12 seconds on an idle machine and several times that on a busy
one, so budget minutes rather than seconds when other containers are alive.

### F39: keep open, and the design in it is wrong

Not built. Two reasons, and the second is the one that matters.

1. The five cases that want it are in `catalog_oidc_pending.go` and are all
   `Recorded`, so nothing compares their goldens yet. A masker landed without
   them would ship unused, and unused means it would never have been proven
   against a live 26.7.1 on both sides of the comparison, which is the one rule
   that overrides the others here.

2. **`Case.VolatileQueryParams` as F39 describes it does not cover its own fifth
   case.** `oidc/authorization/response-mode-fragment` puts `state`,
   `session_state`, `iss` and `code` in the `Location`'s **fragment**, not its
   query - measured, and in the observed spec's `response_mode` table. A masker
   reading `url.Parse(v).Query()` finds nothing there, silently masks nothing,
   and writes a live authorization code into a committed golden that then churns
   on every recording. That is the failure `normalize.go` names in its own doc
   comment: masking nothing while claiming to have checked is worse than
   failing loud.

So the corrected requirement, for whoever promotes those five: mask named
parameters in the query **and** the fragment, and error when a named parameter
is absent from both rather than passing. The trigger is the cut that promotes
them to `Implemented`, because that cut can record the goldens that prove it
works.

Nothing is lost meanwhile except assertion. The key order itself
(`state, session_state, iss, code`, `state` dropped rather than emptied when the
request sent none) is measured and written down in the observed spec.

### F38: close as not worth building

Not built, and it should not be filed as a standing to-do. Four reasons:

1. It is one `Pending` case, and what a golden of it would assert - the 200, the
   `text/html` with no charset, the form's `code, iss, state, session_state`
   order - is already measured and written into the observed spec, in full,
   including the response body verbatim. A golden would be a second copy of a
   measurement, not a new one.

2. **It is not one masker but two positions.** F38 asks for "mask the value of
   this attribute at this place in the HTML", which reaches the four
   `<INPUT ... VALUE="...">`s. The measured body also carries a `<SCRIPT>` whose
   `history.replaceState` argument is a URL holding `tab_id` and `client_data`,
   both minted by the same request. A `VALUE` masker leaves the case churning on
   every recording, which is the disease the masker was for.

3. The blunt alternatives are worse than the gap. A whole-body mask would give
   the case a golden asserting only the status line and the headers; AGENTS.md
   already names `UnorderedKeys` as "the only such retreat - do not add a second
   without writing down why", and a body mask is a larger retreat than that one
   and reusable everywhere. A list of regexes in the catalogue is powerful
   enough to mask any body and moves the reviewing burden into regexes.

4. The natural moment to revisit is not here. F23's three login-theme goldens
   need a substitution pass for a per-container resource version, and that pass
   and this one may be the same shape. Both sets of cases live in
   `catalog_oidc_pending.go`, so whoever owns them decides from a body they are
   recording rather than from this file.

If it is reopened, reopen it against a second case that wants the same
mechanism.

### New: `admin/groups/count` can have its number back

The case masks `count` with a comment saying why: "the recorder shares one
container, so any fixture that creates a group moves it - the first recording of
this case said 3 where a pristine replay says 2". With a container per pristine
case, its fixture (`admin-token-group-tree`: a parent and a child) makes the
count a deterministic 2 on both sides. Dropping `Volatile: []string{"count"}`
and re-recording would turn a masked number back into a measurement. Not done
here: the case and its golden belong to another agent's files this cut.

### New F13 bullet: a masked header is asserted on presence alone, and nothing else

`diff` compares a `VolatileHeaders` entry by checking it is present and its
first value is non-empty. So the seven admin cases that mask `Location`
would accept `Location: x`. The value really is per-request - it ends in a
server-minted UUID - but everything before that UUID is not, and none of it is
asserted. It is the same gap F39 describes for the redirects, in a family that
is `Implemented` today rather than `Recorded`. Fixing it needs those goldens
re-recorded, so it is filed rather than done.

## What was proved, and how

Every claim above that a test now catches something was checked by breaking the
thing it guards, one mutation per claim:

| Mutation | What failed |
|---|---|
| extraction narrowed back to `clientId` | both guard tests, on "nothing in the recording creates an object named by `username`" |
| own-fixture exemption removed | `TestPristineRealmGoldensAreNotPolluted` on `admin/groups/list`, which legitimately holds its own fixture's group |
| catalogue's own creates not read | the guard passes on a golden a live recording had just polluted with `gloak-probe-role-create` |
| pre-fix recorder, live 26.7.1 | `admin/role-mapper/group-realm-available` rewritten with 18 roles, PASS reported; the guard then names all 13 probes, in 14 lines because `gloak-probe-role` has two creators |

## Parity

Unchanged: **129 of 485 enumerated behaviours served**, before and after. No
case changed status, no operation was claimed or released. The work is entirely
in how the two sides of the comparison are obtained.
