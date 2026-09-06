# F121: the `Workflows` tag

Measured against a live Keycloak 26.7.1 on 2026-09-06, container `kc-wf` on port
8177, removed at the end. The plan is
`docs/superpowers/plans/2026-09-06-f121-workflows.md`; this is what the work
owes the documents it may not edit.

## 1. Measurements

### The count in the entry is wrong, and so is the count in AGENTS.md

F121 says "nine operations answering `application/yaml`". **Two do.** Read off
the responses rather than off the description's content lists, which name the
media type on request bodies as well:

```
GET  /workflows                      application/yaml;charset=UTF-8, chunked
GET  /workflows/{id}                 application/yaml;charset=UTF-8, chunked
GET  /workflows/scheduled/{id}       application/json;charset=UTF-8
POST /workflows                      201, empty body, no Content-Type
PUT, DELETE, migrate, activate,
deactivate                           204
```

`POST /workflows` and `PUT /workflows/{id}` *consume* `application/yaml`, which
is where two of the other occurrences live.

**AGENTS.md line 1192 and the observed spec's line 7857 say the same thing** -
"The `Workflows` tag answers `application/yaml`, chunked, and is not gated by
`organizationsEnabled` at all". The second half is right: no feature flag, no
preview profile, no 404 on a stock `start-dev` container. The first half is a
fact about two of the nine, and `GET /workflows/scheduled/{resource-id}` is its
counterexample twice over - it is JSON only *and* it answers
`Accept: application/yaml` with **406**.

### The two reads negotiate, and YAML wins ties

Seven `Accept` headers on one route:

```
(absent)                                    application/yaml;charset=UTF-8
*/*                                         application/yaml;charset=UTF-8
text/html                                   application/yaml;charset=UTF-8
text/plain                                  application/yaml;charset=UTF-8
application/json, application/yaml          application/yaml;charset=UTF-8
application/json                            application/json;charset=UTF-8
application/yaml;q=0.5, application/json    application/json;charset=UTF-8
```

The fifth row is what says a tie goes to the server's preference and not to the
order the header lists. Rows three and four say a header matching neither is not
a 406 **on these two routes**, where it is on the third read - two reads on one
tag, opposite answers to an unmatched `Accept`.

### The bytes

`GET /admin/realms/master/workflows` with one workflow, read with `od -c`:

```
---
- id: "61ad9536-3e7b-454e-ba51-b101ed3a475a"
  name: "t"
  "on": "user-created"
  steps:
  - uses: "disable-user"
    after: "P5D"
    id: "c3bd4e19-a543-4db6-84d7-905cdb4bfcd8"
```

with a trailing newline. The empty listing is **`--- []`** with a trailing
newline - seven bytes, the whole of what a default realm answers, on `master`
and on a created realm alike. A single read is the same shape one indent out.
`schedule.batch-size` is a bare integer where every string beside it is quoted.

Key order is the description's declaration order with absent keys skipped:
`id, name, on, schedule, concurrency, if, steps`, and inside a step
`uses, after, scheduled-at, status, id`. It is not `javamap.KeyOrder`'s and does
not need it - Jackson serialises a bean here rather than a map.

### `gopkg.in/yaml.v3` cannot produce those bytes

Four ways, measured in a scratch module against the exact string above:

| encoded from | `SetIndent(2)` | `SetIndent(4)` |
| --- | --- | --- |
| a Go struct with yaml tags | differs | differs |
| a hand-built `yaml.Node` tree | differs | differs |
| **the measured bytes, parsed and re-emitted** | **differs** | - |

The last row is the control. The differences: **no `---`** (emitted only for a
second document, no option); **the nested sequence indented one level too far**
(Keycloak puts a sequence's `-` at the parent key's column, `SetIndent` moves
both together and `SetIndent(2)` and `SetIndent(4)` produced byte-identical
output on this shape); plain scalars where Keycloak double-quotes everything;
and `on` emitted bare where Keycloak writes `"on"`, because SnakeYAML is
YAML 1.1 and yaml.v3 is YAML 1.2.

Only the last two are reachable through the library's API, and reaching them
means hand-building the tree anyway. So `internal/httpx/yaml.go` emits, and
that is `internal/javamap`'s situation one layer up.

**The library is still used, for reading.** A response body is observable and a
request body is not, so `POST` and `PUT` decode with `yaml.v3` and
`KnownFields(true)`, which also accepts every spelling SnakeYAML accepts where a
hand-written subset parser would refuse some. YAML is a superset of JSON, so one
decoder serves both media types these routes consume.

### The security-header rule is about the media type, and the 204 test was wrong

**The sharpest data point this repository has on AGENTS.md's `X-Frame-Options`
bullet**: one route, one status, one caller, differing only in an `Accept`
header.

```
GET .../workflows/{id}                        application/yaml;charset=UTF-8   no X-Frame-Options
GET .../workflows/{id}  Accept: application/json   application/json;charset=UTF-8   X-Frame-Options
```

And on the request side, `DELETE /admin/realms/master/users/{id}` - a 204 on an
endpoint that consumes nothing - one fresh user per row, `application/json` in
the same run as the control that differs:

```
application/json                    X-Frame-Options
application/xml                     X-Frame-Options
application/x-www-form-urlencoded   X-Frame-Options
APPLICATION/JSON                    X-Frame-Options
Application/Json                    X-Frame-Options
application/json;charset=UTF-8      X-Frame-Options
application/yaml                    no X-Frame-Options
application/yaml;charset=UTF-8      no X-Frame-Options
application/YAML                    no X-Frame-Options
application/octet-stream            no X-Frame-Options
application/pdf                     no X-Frame-Options
application/ld+json                 no X-Frame-Options
application/json ; charset=UTF-8    no X-Frame-Options
text/plain                          no X-Frame-Options
(absent)                            no X-Frame-Options
```

Three things follow and each has a row that says so. It is an **allow-list of
three exact media types**, not the `application/` prefix `httpx.WriteNoContent`
and `admin.writeEmptyStatus` both tested. It is not a `+json` **suffix**, which
`application/ld+json` rules out. And the parameters are **cut without being
trimmed**: `application/json ; charset=UTF-8`, with a space before the
semicolon, answers without the header where the same value without the space
carries it - Jakarta's parser splits on the semicolon and leaves the space on
the subtype.

Both writers are corrected, and `writeEmptyStatus` moved into `internal/httpx`
on the way, which is F133.

### The guard is the realm role `admin` itself

Every one of the twenty-one `master-realm` admin roles is **403** on every one
of the nine routes, held singly. So are `view-realm`+`view-users`,
`manage-realm`+`manage-users`, six held together, and **all twenty-one together
with `create-realm`** - which is exactly `admin`'s composite closure, read out
of `GET /admin/realms/master/roles/admin/composites`. Holding `admin` is
200/201/204, and removing it again is 403 again.

`GET /users` and `GET /admin/realms` were the controls and flipped with the
assignment in every row, so the sweep was not measuring itself. The first run of
it *was* - every cell came back 401, because `POST /users` with only a
`username` creates a **disabled** user and the password grant refused it.

### What a workflow is

`GET /admin/serverinfo` carries four SPIs nothing in this repository had read:

```
workflow-event      client-created  client-authenticated  user-created  user-authenticated
                    user-group-membership-added  user-group-membership-removed
                    user-role-granted  user-role-revoked
                    user-federated-identity-added  user-federated-identity-removed
workflow-step       add-required-action  delete-client  delete-user  disable-client
                    disable-user  grant-role  join-group  leave-group  notify-user
                    remove-required-action  remove-user-attribute  restart
                    revoke-role  set-user-attribute  unlink-user
workflow-condition  has-identity-provider-link  has-role  has-user-attribute  is-member-of
workflow-state      jpa
```

```
listing order       sorted by name, ASCII. zzz/aaa/mmm added in that order came
                    back aaa, mmm, zzz, so no case masks this listing
search              case-insensitive substring; exact=true compares the whole name
first / max         **either bound alone pages** - a third paging rule in this API
max=abc             404 {"error":"HTTP 404 Not Found"}
includeId=false     drops `id` from the workflow **and from every step**
after               an ISO-8601 duration; 5 days, 5d, 5 day, 5, 5000, 5 DAYS,
                    5days and PT5M are all 400
name                unique per realm; a repeat with a different id is
                    400 {"errorMessage":"Workflow name must be unique. …"}
{type}              an uppercase enum: USERS and CLIENTS route, and `users`,
                    `user`, `clients`, `client`, `User`, `groups`, `roles` and
                    `organizations` are all {"error":"HTTP 404 Not Found"}
activation          schedules **every** step, cumulatively: P1D, P2D, P3D came
                    back one, three and six days out
deactivation        204 before any activation, and clears every row after one
scheduled read      200 and [] for a resource id that names nothing
migrate             `from` and `to` are **step** ids; either alone is the same
                    400 as neither
Cache-Control       absent on all nine
unknown realm       404 {"error":"Realm not found."}
```

Rejections, one fault at a time:

```
name absent or ""      400 {"errorMessage":"Workflow name cannot be null or empty."}
on names no provider   400 {"errorMessage":"Could not find provider factory with id: <x>"}
if names no provider   the same sentence
uses names no step     400 {"errorMessage":"Could not find step provider: <x>"}
after is not a duration 400 {"errorMessage":"Step 'after' configuration is not valid: <x>"}
no steps at all        400 {"errorMessage":"Steps provided should support a single type, actual: USERS, CLIENTS"}
steps of two types     400 {"errorMessage":"Steps provided are not compatible with each other."}
an unknown field       400 {"error":"unknown_error","error_description":"Cannot parse the JSON"}
not YAML at all        400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
an empty body          500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
an id that resolves to nothing  400 {"error":"Not a valid workflow resource: <id>"}
an activation resource that does not exist  400 {"error":"Resource with id <id> not found"}
migrate with fewer than two ids 400 {"errorMessage":"Both 'from' and 'to' step ids must be provided for migration."}
```

### Four fields in the schema that no request can set

`enabled` on a workflow and `config` on a step are both **refused by the
deserialiser** - a body carrying either is 400 `Cannot parse the JSON`, measured
with `config` as a one-key map and as the multivalued map the schema declares.
`with` is accepted at create and echoed by no read. `state` has never appeared
on the wire. None of them has a column, which is F157's rule applied at the
moment the table was written rather than afterwards.

### `POST /users` ignores an `id` in the body

A create naming `id` answered 201 with a **different** id in `Location`. That is
the third endpoint in AGENTS.md's "the body's `id` wins on create on two
endpoints and loses on a third", named. `POST /workflows` is a **third winner**,
and its id need not be a UUID: `id: my-own-id` came back in `Location`
verbatim. In one request body, the workflow's id is honoured and a step's is
discarded and re-minted.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds them in.

- **`X-Frame-Options` is decided by a media type, and the rule is a list of
  three rather than a prefix.** Measured 2026-09-06 across fifteen request
  `Content-Type` values on one 204 and across two `Accept` values on one 200:
  `text/html`, `application/json`, `application/xml` and
  `application/x-www-form-urlencoded` carry it and everything else does not,
  `application/yaml`, `application/octet-stream`, `application/pdf`,
  `application/ld+json` and `text/plain` included. The `+json` suffix is not the
  rule - `application/ld+json` sends none - and the parameters are cut **without
  being trimmed**: `application/json ; charset=UTF-8`, with a space before the
  semicolon, sends none where the same value without the space carries it. The
  200 pair is the sharpest of the lot: `GET /workflows/{id}` answers
  `application/yaml` with four headers and answers `application/json` with five,
  on one route, one status and one caller, differing only in `Accept`. Gloak
  tested this with `strings.HasPrefix(ct, "application/")` in two places until
  `PUT /workflows/{id}` sent the first `application/yaml` this project had ever
  sent; both are now the list. **This is the seventh time this bullet has moved
  and the first time a media type outside the measured set existed to move it**,
  which is the argument for re-measuring it whenever a new one appears rather
  than for believing the list.

- **A YAML body ends with a newline where a JSON body does not.**
  `writeJSON` trims the newline `json.Encoder` appends, because Keycloak's JSON
  carries none. Keycloak's YAML carries one, and an empty listing is `--- []`
  followed by it - seven bytes. Two body formats in one server, opposite rules,
  and a shared writer taking the format as a parameter would get one of them
  wrong.

- **A workflow's own id is the caller's and its steps' ids are not.** One
  request body, two opposite decisions. `POST /workflows` puts the body's `id`
  in `Location` verbatim and does not require it to be a UUID -
  `id: my-own-id` works - while an `id` inside a step is discarded and replaced.
  That makes three endpoints measured honouring a body id (`POST /clients`,
  `POST /client-scopes`, `POST /workflows`) and confirms the fourth as the one
  that ignores it: **`POST /users` mints its own**, measured 2026-09-06, which
  is the endpoint the existing bullet says "loses" without naming.

- **A workflow delete is not idempotent.** A second `DELETE` of an id already
  removed is **400** `Not a valid workflow resource: <id>`, where almost every
  other delete on this API answers 204 twice. Every route on the tag answers
  that same 400 for an unknown id rather than a 404, so this chapter contributes
  no new spelling of not-found: the sentence interpolates the request's own
  value, which makes it a template like `Requested audience not available` and
  not a spelling.

- **A duplicate workflow **id** answers `Duplicate resource error` in two
  shapes and nothing in the request decides which.**
  `400 {"errorMessage":"Duplicate resource error"}` and
  `409 {"error":"conflict","error_description":"Duplicate resource error"}`, on
  one container, with the same body and the same caller, within seconds of each
  other - measured alternating while recording. A duplicate **name** with a
  different id is separately and reliably
  `400 {"errorMessage":"Workflow name must be unique. …"}`. It is the same
  phrase AGENTS.md already records as the family that sends no security headers
  and that nobody has explained; this is a second unexplained thing about it, on
  the status rather than on the headers. Gloak serves the 400, because that is
  the one measured in isolation with its headers read off the wire, and no
  golden can hold either.

- **`{"error":"HTTP 406 Not Acceptable"}` is a sixth body in the fallback
  family.** `GET /workflows/scheduled/{resource-id}` serves JSON alone and
  answers `Accept: application/yaml` with it. The two YAML reads beside it
  answer `text/html` and `text/plain` with a YAML 200 rather than a 406, so it
  is not "this API refuses an unmatched Accept"; it is this route.

- **An unconvertible path parameter is a fifth producer of
  `{"error":"HTTP 404 Not Found"}`.** `{type}` on the two activation routes is
  an uppercase enum: `USERS` and `CLIENTS` reach the handler and `users`,
  `user`, `clients`, `client`, `User`, `groups`, `roles` and `organizations` all
  answer that body, on a workflow that exists and to a caller that may use the
  route. It is the first producer on the **path** - the other four are the verb,
  the switched-off resource, the malformed integer query parameter and the
  unmatched route - so the body still means "the router found nothing to run"
  and the set of ways to mean it has grown again.

- **The `Workflows` tag is guarded by the realm role `admin` itself, not by
  what it confers.** All twenty-one `master-realm` admin roles are 403 on all
  nine routes singly; so are six of them together; so are **all twenty-one plus
  `create-realm`**, which is `admin`'s entire composite closure. `admin` alone
  opens them and removing it closes them again, with `GET /users` and
  `GET /admin/realms` as controls that flipped in every row. Every other guard
  in this project is satisfied by a fine-grained role, and an implementation
  that expanded composites - which is what a reader would write - opens this tag
  to a caller Keycloak refuses.

- **The line "The `Workflows` tag answers `application/yaml`, chunked" is true
  of two of its nine operations.** Six answer 201 or 204 with no body at all and
  the seventh is JSON only. "Not gated by `organizationsEnabled`" survives and
  is now measured rather than inferred: the tag works on a stock `start-dev`
  container with no feature flag.

## 3. Follow-up dispositions

**F121 - the `Workflows` tag needs a YAML writer. Closed.** The writer is
`internal/httpx.WriteYAML` and the emitter beside it; all nine operations are
served and nineteen cases record them. The entry's premise - that this is a
decision about `internal/httpx` before it is nine handlers - was right, and its
count was not: two of the nine answer YAML.

**F157 - a table nothing writes is a claim about the model that is not true.
Honoured, and the entry got a fourth instance.** Four fields the description
declares have no column: `enabled` and a step's `config` because the
deserialiser refuses them outright, `with` because no read echoes it, and
`state` because it has never been on the wire. The reasons are in
`0036_workflow.sql` beside the table rather than in a comment somewhere else.

**F95 - `internal/admin` marshals a Go `map[string]string`, which
`encoding/json` sorts, so a client's `attributes` stays masked. Not touched,
and this chapter says why it did not have to be.** A workflow representation is
a bean and not a Java map: its key order is the declaration order and this
chapter's goldens assert it exactly, with no mask and no call to
`javamap.KeyOrder`. So F95 is still one `model.StringMap` away and this chapter
adds no pressure on it either way - the one place a multivalued map would have
appeared, a step's `config`, is the field the server refuses.

**F133 - `writeEmptyStatus` lives in `internal/admin`. Closed.** It is
`httpx.WriteEmptyStatus` now, and the move is what put its media-type test and
`WriteNoContent`'s in one place; both were the `application/` prefix that
`application/yaml` refutes. `admin.writeEmptyStatus` is a one-line forward, left
so that the diff which moves the rule and the diff which renames fourteen
call sites are two reviews.

**New: `admin/clients/evaluate-scope-mappings-not-granted` cannot survive a
`make record`.** It lists master's realm roles, it is not `PristineRealm`, and
it sits near the end of the catalogue - so by the time the recorder reaches it,
sixteen `gloak-probe-*` realm roles other fixtures created are in the realm. A
full recording rewrote its golden from five roles to twenty-one and
`TestNoGoldenHoldsAnObjectItDidNotCreate` reported every one of them. The
rewrite was reverted, unread by nothing: the guard named the sixteen and the
fixtures that made them. **The committed golden is right and the recorder
disagrees with it**, which means the case is green only for as long as nobody
re-records. It wants `PristineRealm: true` and a re-record, which is a
one-word change in a chapter this branch does not own.

## 4. Parity, before and after

```
at the branch point   498 of 541, admin/workflows 0 of 9
rebased onto main     503 of 541, admin/workflows 0 of 9
after                 512 of 541, admin/workflows 9 of 9
```

The middle row is arithmetic rather than a second measurement: main moved five
operations ahead while this branch was open, and the branch adds nineteen cases
claiming exactly the nine workflow operations and changes no other case's
`Status` or `Operation`.

Nine operations, and the chapter is complete rather than half-served: every one
of the nine claims an `Operation` in the catalogue and answers a golden recorded
from a live 26.7.1.

Nineteen conformance cases, ten fixtures, fifteen unit tests in
`internal/admin/workflows_test.go` for the claims a golden cannot state - the
guard sweep over every admin role, the cumulative scheduling arithmetic, the
`Accept` table, the resolution order of the workflow against the type, and the
twelve rejections one fault at a time.

## 5. What is left undone

- **The `on` and `if` expressions are validated as bare provider ids.**
  Keycloak parses them with an ANTLR grammar and reports
  `Invalid expression: user.create / Error at line 1:5 - extraneous input
  'create' expecting <EOF>`. Gloak answers
  `Could not find provider factory with id: user.create` instead. A request
  carrying a compound expression gets a different body here, and no catalogue
  case sends one.
- **Nothing runs a step.** `activate` writes the rows the scheduled read serves
  and `migrate` validates its two ids; `status` is `PENDING` on everything and
  `COMPLETED` is unreachable. `notBefore` on the activation is accepted and
  changes nothing observable - what it moves was not measured, because the only
  window onto a schedule showed the same value either way.
- **`concurrency` is stored and not interpreted.**
  `cancel-in-progress: "true"` is a 201 and `restart-in-progress: "false"` is
  400 `Could not find provider factory with id: false`, so the values are
  expressions rather than booleans and only one of the two literals parses.
  Gloak stores both as written.
- **The guard was measured in `master` only.** A realm-local administrator
  would hold `realm-management`'s `realm-admin` rather than master's `admin`,
  and whether that opens the tag inside its own realm is unmeasured. Gloak
  refuses it, which is what `adminRoleNames` already does for `admin` outside
  master.
