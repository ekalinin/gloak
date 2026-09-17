# Three header divergences, and the one that turned out to be four

F226, F220 and F221, taken as one cut because they are one subject: which
headers go on which response, and what decides it.

Everything below was measured on **2026-09-17**, on `fix/header-divergences`
branched from `main` at `df9a251`. The live measurements were taken against
`quay.io/keycloak/keycloak:26.7.1` on `start-dev`. The golden counts are
computed over the committed tree, not quoted from anywhere.

Three things up front:

- **all three entries were right about what they measured**, and the two that
  described a *scope* were both too narrow. F220 had already widened
  `X-Frame-Options` from "this endpoint's redirect" to "the empty-body rule";
  F221 wrote `Content-Security-Policy` up as "on those redirects" one bullet
  later, and it is the same rule on the same axis - measured here on a plain
  admin `DELETE`'s 204, as far outside the browser flow as this API goes;
- **F226's "one call site of thirteen" is a count of two different things**, and
  re-counting found a second divergence of the same shape that nothing in the
  repository can see;
- **the parity total moved by construction and not by merit**: 610 of 677 to
  614 of 681. Four cases were added to a chapter whose denominator is its own
  case count, so both numbers moved by four. No operation was claimed and no
  behaviour that was unserved is served now.

## 1. Containers

| # | name | fresh | what it was for |
| --- | --- | --- | --- |
| 1 | `gloak-hdr-1` | yes, `start-dev`, bootstrap admin only | the fourteen-row `GET /auth` and `GET /logout` tables; the whole-response probes on six other endpoints; the admin 204 probe (six throwaway clients created on it, one per row, so that every row is really a 204) |
| 2 | `gloak-hdr-2` | yes, `start-dev`, bootstrap admin only | the **second, independent** run of both fourteen-row tables; the `POST /login-actions/authenticate` login flow; the F226 re-measurement (one client and one identity provider created on it, both of them the fixture those probes need) |
| 3+ | the recorder's own | yes, started per run by `TestRecordGoldens` | `make record` |

Two containers were started by hand, both fresh, and every table was read off a
**raw socket** in Python rather than through `curl`. That is not superstition:
this project has twice measured its own tool instead of the server, and the
absences here - a header that is *not* sent - are exactly the shape that gets
lost between a client library and a terminal.

Every row of the two headline tables was taken twice, on two fresh containers,
and the two runs agree cell for cell. On container 2 both tables were widened
from ten rows to fourteen and the `Location` came back as **one distinct value
across all fourteen rows** on each endpoint, which is what makes this one branch
answering differently rather than fourteen different responses.

The recorder's containers are its own regime and the count is not something this
cut chose: one per configuration for the shared cases - there are two
configurations, and the four new goldens are on the default - plus one per
recorded `PristineRealm` case, of which the catalogue declares 40. The run was
quiet, so that is derived from the catalogue rather than counted off the daemon.

## 2. F226: what was re-measured, and what the number thirteen counts

### 2.1 The measurement agreed

`POST /admin/realms/master/identity-provider/instances/{alias}/mappers` with a
body carrying no `name`, `Content-Type: application/json`, on container 2:

```
HTTP/1.1 409 Conflict
content-length: 67
Content-Type: application/json
{"error":"conflict","error_description":"Duplicate resource error"}
```

**None of the five security headers. No `Cache-Control`. No `Date`.** The three
neighbours on the same route, same verb and the same request `Content-Type`
were taken in the same run and all send five of five:

```
first create with a name   201   five of five   0 bytes
duplicate name             400   five of five  74 bytes
empty body                 500   five of five  94 bytes
```

So the committed golden was right, the case's comment was right, and the
divergence was Gloak's. `createIdentityProviderMapper` now calls
`writeDuplicateResource`, the case declares the five absent, and
`omissionsGloakStillSends` is empty - which is how that list was designed to
end.

### 2.2 The other call sites, counted rather than assumed

F226 says *"the thirteenth call site of a 409 `Duplicate resource error` in
`internal/admin`, and the only one that does not go through
`writeDuplicateResource`"*. Counted over the tree:

```
                                                      before   after
call sites that emit exactly the 67-byte body             22      22
  through writeDuplicateResource, which deletes the
  five (two of them a returned function value)            12      13
  through writeAuthzScopeConflict, which keeps them        7       7
  inline httpx.WriteOAuthError, neither helper             3       2
committed goldens holding exactly that body               19      19
  carrying none of the five                               13      13
  carrying all five                                        6       6
  carrying a partial set                                   0       0
```

**Thirteen is true of two different tallies and the entry does not say which.**
It is the 12 `writeDuplicateResource` sites plus the one inline site that should
have been one of them, and it is also the 13 goldens that carry the body with
none of the five. Both are worth knowing and neither is "the number of ways this
409 is written", which is 22 across three writers. The entry's other half - *"the
only one that does not go through `writeDuplicateResource`"* - is false as
written and true as meant: there are three inline sites and seven more behind a
second helper, and it was the only one of them that should have been in this
family.

The other two inline sites are not mistakes. `clientscopes.go:385`
(`PUT /default-default-client-scopes/{id}`) and `components.go:306`
(`POST /components`) both **keep** the five, and both have a golden recording
exactly that. `writeAuthzScopeConflict` keeps them too and says why in its own
doc comment, at length, because it was itself a correction. So the split is not
a convention nobody wrote down: it is two measured families sharing one body,
and the thirteenth site was filed in the wrong one.

Seven of the 22 sites have no golden at all - three under
`writeDuplicateResource` and four under `writeAuthzScopeConflict`. They are not
findings; they are the ordinary tail of a catalogue that covers what was
measured.

### 2.3 The second divergence of the same shape, which nothing can see

`admin/protocol-mappers/add-models-duplicate-id-same-container` and
`-other-container` are AGENTS.md's sharpest pair: same route, same verb, same 67
bytes, one recording all five and the other none. They are served by **one line**
- `protocolmappers.go:312`, which calls `writeDuplicateResource`, which deletes
the five unconditionally. So Gloak answers both with none, and:

- `-other-container` declares the five absent, so it is compared and passes;
- `-same-container` names only `Content-Type` in `AssertHeaders`, so **nothing
  in the repository compares the five in either direction**, and Gloak's answer
  differs from the recording on five headers.

This is F226's mirror image. The mirror header rule catches a golden that omits
a header its case does not declare; **nothing catches a golden that carries a
header its case does not assert and the server does not send.** That is the
asymmetry F223 is about, here as a live divergence rather than a hypothetical.
It cannot be fixed without knowing F147's rule, which nobody does. Filed as
F266.

## 3. F220 and F221: the tables

### 3.1 `GET /auth`, ten request media types, one byte-identical `Location`

Container 1, re-run whole on container 2, both fresh. The request is `GET /auth`
with a registered `redirect_uri` and no `response_type`, so every row is the
same 302 back to the client; the `Location` was byte-identical on all rows and
the probe prints the number of distinct values rather than trusting the eye.

```
request Content-Type                  X-Frame-Options   Content-Security-Policy
absent                                -                 -
application/json                      SAMEORIGIN        -
application/xml                       SAMEORIGIN        -
application/x-www-form-urlencoded     SAMEORIGIN        present
application/json;charset=UTF-8        SAMEORIGIN        -
application/json ; charset=UTF-8      -                 -
application/ld+json                   -                 -
application/yaml                      -                 -
text/plain                            -                 -
*/*                                   -                 -
```

`GET /logout` answers identically, on its own byte-identical `Location`.

**This agrees with F220 and with AGENTS.md's bullet, row for row**, including
the untrimmed space. Agreement is worth recording on a passage that has been
corrected nine times.

Four further rows were added to widen the `Content-Security-Policy` half,
because a one-member allow-list is the kind of rule that is usually a mis-read
of a wider one:

```
application/x-www-form-urlencoded;charset=UTF-8      SAMEORIGIN   present
application/x-www-form-urlencoded ; charset=UTF-8    -            -
multipart/form-data; boundary=zz                     -            -
text/html                                            -            -
```

So the second list is parsed by the same rule as the first - parameters cut,
not trimmed - and it really does hold one entry. `multipart/form-data` is what
rules out "a form request".

### 3.2 The finding: the `Content-Security-Policy` rule is not the redirect's

F221 says the rule is *"on those redirects"*. It is not. The same one-entry
allow-list decides the header on a plain admin delete, measured on container 1
with a fresh client per row so that every row is really a 204:

```
DELETE /admin/realms/master/clients/{id}
request Content-Type                    X-Frame-Options   Content-Security-Policy
absent                                  -                 -
application/json                        SAMEORIGIN        -
application/xml                         SAMEORIGIN        -
application/x-www-form-urlencoded       SAMEORIGIN        present
application/x-www-form-urlencoded ; charset=UTF-8   -     -
text/plain                              -                 -
```

That is `WriteNoContent`'s own rule with a second header on it, on a route with
no browser, no theme and no redirect. **`Content-Security-Policy` on an
empty-bodied response is decided by the request's media type, exactly as
`X-Frame-Options` is, and the only difference between the two is the size of the
allow-list.**

This is the same correction F220 made, one bullet later, made by the same cut
and not noticed: F220 took `X-Frame-Options` from "this endpoint's redirect" to
"the empty-body rule", and F221 then wrote `Content-Security-Policy` up as
"those redirects". The corpus could not tell: it held no empty-bodied response
with a form request outside the browser flow.

Two responses with a body were taken as controls in the same run, and they say
the axis is the response and not only the request:

```
GET /admin/realms/master/clients   200 application/json   XFO on all three rows, CSP on none
GET /auth (no client_id) 400 page  3572 bytes text/html   XFO and CSP on all three rows
```

So a response with a body is not subject to the request-side rule at all, in
either direction. That is consistent with the corpus, where the request-side
split lands exactly on the 214 goldens whose response carries **no
`Content-Type`**.

### 3.3 The third endpoint, and a fourth divergence

F221 asks for a third measurement outside the browser flow and names
`POST /login-actions/authenticate` as the sharpest, "because it sends the header
today". Measured on container 2 through a real login: open `/auth`, keep the
cookies, post the credentials once so the session code is spent, then replay it
across the ten media types.

```
request Content-Type                  X-Frame-Options   Content-Security-Policy
absent                                -                 -
application/json                      SAMEORIGIN        -
application/xml                       SAMEORIGIN        -
application/x-www-form-urlencoded     SAMEORIGIN        present
application/json;charset=UTF-8        SAMEORIGIN        -
application/json ; charset=UTF-8      -                 -
application/ld+json                   -                 -
application/yaml                      -                 -
text/plain                            -                 -
*/*                                   -                 -
```

Ten 302s, the same branch on every row. **This one is weaker than the other two
and it should be read that way**: the `Location` is *not* byte-identical,
because a spent session code restarts the flow and the restart carries a fresh
`tab_id`. Ten responses that differ in a per-request id, rather than one
response answered ten ways.

It is still enough to refute the sentence it was sent to test.
`httpx.WriteLoginActionRedirect`'s doc comment, and AGENTS.md beside it, cite
this endpoint as the counterexample that proves `/auth`'s two absences are
`/auth`'s:

> GET  /auth                        302   no X-Frame-Options, no Content-Security-Policy
> POST /login-actions/authenticate  302   both present

Both rows are true and the conclusion does not follow. The six committed
`POST {{login_action}}` goldens are **all** form-urlencoded, which is the one
media type that brings both headers; the sixteen `GET` goldens all send no
`Content-Type`, which is the value that brings neither. The endpoint was never
the variable. `WriteLoginActionRedirect` sets both unconditionally, so it
diverges for any other request - **which is P2's Task 11's mistake for the
third time in this bullet's history, and the second time this month.**

It is not fixed here, and the reason is F220's own: a golden that could tell the
fix from the bug needs the `Location` masked, and masking a whole `Location`
asserts presence and nothing else - which is what F46 spent a cut removing. It
needs a case whose redirect is to the client rather than a restart. Filed as
F265.

### 3.4 The bullet, line by line: where it agreed and where it did not

The security-header bullet is the passage AGENTS.md records as having been wrong
more times than any other, and it has been corrected twice this month - once
about which *responses* carry the headers and once about which *requests* do.
Three of the four claims this cut re-measured are its own. Stated plainly, with
the request each rests on:

| claim | source | verdict |
| --- | --- | --- |
| `X-Frame-Options` on `/auth`'s and `/logout`'s 302s follows an allow-list of three, parameters cut untrimmed | the bullet, F220 | **agrees**, fourteen rows, two containers, one distinct `Location` per endpoint |
| `application/ld+json` rules out a "+json suffix" reading | the bullet | **agrees** |
| `application/json ; charset=UTF-8` sends no header - the untrimmed space | the bullet | **agrees** |
| Gloak deletes the header unconditionally in both writers | the bullet, F220 | **agrees**, and it is fixed here |
| the `Duplicate resource error` family sends none of the five | the bullet | **agrees**, re-measured against three neighbours on one route in one run |
| `Content-Security-Policy` is one media type wide | the bullet, F221 | **agrees on the value** |
| ... *"on those redirects"* | the bullet, F221 | **too narrow.** The same one-entry list decides an admin `DELETE`'s 204 and a login-action 302 |
| *"the two headers move together in every committed golden"* | the bullet, F221 | **was true and is not now.** Four goldens hold them apart |
| `POST /login-actions/authenticate`'s 302 carries both, so `/auth`'s absences are `/auth`'s | the bullet, `WriteLoginActionRedirect` | **both rows true, conclusion refuted.** The six goldens behind it are all form-urlencoded |
| revocation's `Content-Security-Policy` is "the odd one on the protocol side" | the bullet | **the fact is right and the reason is not a reason**, and the endpoint cannot be probed to settle it |

**Agreement after nine corrections is worth recording as much as the
disagreement.** Every table this cut took on the `X-Frame-Options` side came
back exactly as the bullet describes, down to the space before the semicolon,
and the entries were right about everything they measured. What went wrong twice
is the same thing both times, and it is not a measurement error: a family
measured with one request shape throughout gets written up as a property of the
family. F220 corrected that for `X-Frame-Options` and wrote F221 in the same
sentence with the same defect.

## 4. Why the cases were recorded before the handler moved

F220 says it plainly: *"otherwise the fix is a change no test can distinguish
from the bug."* That is not a style preference here. The divergence had existed
since P2 and the suite was green, because `AssertHeaders` only ever checks a
header that is named and no case named these. A fix landing first would have
been a diff nobody could review against anything.

The order actually run was: measure, write four cases, watch them fail for want
of a recording, `make record`, read the recording against the socket bytes,
**then** move the handler and watch the four go from failing to passing.

The four cases:

| case | request `Content-Type` | what it pins |
| --- | --- | --- |
| `oidc/authorization/redirect-json-content-type` | `application/json` | `X-Frame-Options` present, `Content-Security-Policy` **absent** |
| `oidc/authorization/redirect-form-content-type` | `application/x-www-form-urlencoded` | both present |
| `oidc/logout/redirect-json-content-type` | `application/json` | `X-Frame-Options` present, `Content-Security-Policy` **absent** |
| `oidc/logout/redirect-form-content-type` | `application/x-www-form-urlencoded` | both present |

Each is the request an existing case already sends, byte for byte, plus one
header. `oidc/authorization/missing-response-type` and
`oidc/logout/post-logout-uri-defaults-to-redirect-uris` are the controls, and
they were not touched: they still declare both headers absent, and they still
send no `Content-Type`.

Both endpoints get both cells rather than one endpoint getting both, because a
rule measured on one endpoint and assumed on the other is exactly how this
bullet has been wrong twice. Without the logout form cell, deleting the
`Content-Security-Policy` half of `WriteLogoutRedirect` is a mutation that
survives.

### 4.1 Are F220 and F221 distinguishable in the corpus now?

**Yes, and they were not before.** The two `-json-content-type` cases are the
first goldens in the tree where the two headers disagree: `X-Frame-Options`
present and `Content-Security-Policy` absent, on a response whose `Location` is
identical to the one where both are present.

Computed over the committed tree, on goldens whose response carries no
`Content-Type` at all, keyed on the request's media type:

before this cut

```
request media type                  CSP present   CSP absent   XFO present   XFO absent
(none)                                        0          104             0          104
application/json                              0           96            96            0
application/x-www-form-urlencoded             9            1             9            1
application/yaml                              0            2             0            2
text/plain                                    0            2             0            2
```

The single off-diagonal in both columns is `saml/endpoint/logout-request-post`,
and it is not one: `POST /realms/{realm}/protocol/saml` is AGENTS.md's
matched-route-serving-a-real-page exception, which sends none of the six
whatever the request says. Its case declares all eight absences.

after this cut, the `application/json` row is `0 present / 98 absent` for
`Content-Security-Policy` and `98 present / 0 absent` for `X-Frame-Options`, and
the form row is `11 / 1` both ways. The two columns are no longer the same
column.

## 5. The record diff, file by file

`make record` was run whole rather than filtered, so that the diff is the
evidence rather than a claim about it.

**Four files added. Zero files modified.**

```
A  internal/conformance/testdata/golden/oidc/authorization/redirect-form-content-type.http
A  internal/conformance/testdata/golden/oidc/authorization/redirect-json-content-type.http
A  internal/conformance/testdata/golden/oidc/logout/redirect-form-content-type.http
A  internal/conformance/testdata/golden/oidc/logout/redirect-json-content-type.http
```

Each carries `# recorded-with: start-dev --health-enabled --metrics-enabled`,
the default configuration, inherited rather than declared - none of the four
sets `Case.Configuration`, and none of them is about the served ports.

Read against the socket bytes taken on container 1 before the record existed,
the four agree header for header. The two `/auth` goldens differ from each other
in exactly one line, `Content-Security-Policy`, and so do the two `/logout`
ones - which is the point of the pair and is visible in the diff rather than
asserted about it.

The two `/logout` goldens carry `Set-Cookie: {{volatile}}`. A hintless logout
mints an `AUTH_SESSION_ID`, the existing logout redirect cases already mask it,
and the value is per-request.

**Zero existing goldens moved**, which is the outcome to want and not a given:
a full re-record that rewrote nothing else is what says the four new cases
carry no fixture side effect into the shared container.

## 6. The mutation pass

Each mutation applied to a committed tree, the **named** test run, reverted on a
`trap ... EXIT`, and the revert verified with `git diff --quiet` scoped to the
package it mutated. Every production mutation was run against
`internal/conformance` as well as its own package, because the contract lives in
goldens here and a recent cut had every production mutation survive
`internal/admin` and die in `internal/conformance`.

| # | mutation | run against | result |
| --- | --- | --- | --- |
| M1 | `WriteAuthorizationRedirect` deletes `X-Frame-Options` unconditionally and never sets the policy - **the code exactly as it stood before this cut** | `internal/conformance` | **killed**, both new `/auth` cases: `X-Frame-Options: want ["SAMEORIGIN"], got []` |
| M2 | the same on `WriteLogoutRedirect` | `internal/conformance` | **killed**, both new `/logout` cases |
| M3 | `policyRequestMediaTypes` **gains** `application/json` - additive, and the map still looks like a measured list | `internal/conformance`, whole suite | **killed** by exactly the two `-json-content-type` cases and by nothing else in 1140 goldens |
| M4 | the guard stays but reads `framedRequestMediaTypes` - present, and silently wrong | `internal/conformance` | **killed**, the same two cases |
| M5a | `requestMediaType` gains a `TrimSpace` - the untrimmed space, which is a measured byte | `internal/conformance`, whole suite | **survived** |
| M5b | the same mutation | `internal/httpx` | **killed**, three tests, all on the `application/json ; charset=UTF-8` row |
| M6 | F226 reverted: the 409 written through `httpx.WriteOAuthError` again | `internal/conformance` | **killed**, naming all five headers |
| M6b | the same mutation | `internal/admin` | **survived** |
| M7 | the F226 case's `AssertAbsentHeaders` deleted | `internal/conformance` | **killed** by the mirror header rule, naming the golden |
| M8 | an `omissionsGloakStillSends` entry nothing uses, added to the now-empty map | `internal/conformance` | **killed** by the stale-entry ratchet |
| M9 | the redirect table ranged over `[:0]` | `internal/httpx` | **survived** |
| M9b | the same, after the guard this cut added | `internal/httpx` | **killed**: `ran 0 of 11 cells` |
| M10 | not a mutation of this cut's code - `add-models-duplicate-id-same-container` made to assert the five | `internal/conformance` | **failed**, naming all five. This is section 2.3 as an observation rather than a static reading |

Five of these are worth reading rather than counting.

**M5a and M5b are the pair the discipline asks for.** The untrimmed space is a
measured byte - `application/json ; charset=UTF-8` sends no `X-Frame-Options`
where the same value without the space sends one - and **no golden in the tree
can see it**. Adding a `TrimSpace` passes 1140 goldens and dies in the package's
own table. The four new cases did not fix that and were never going to: a
conformance case sends one `Content-Type`, and the cheap place to hold eleven is
`internal/httpx`.

**M6 and M6b are the other pair**, and they are this project's rule about where
a production mutation has to be run. The whole of F226 is a header set, headers
live in goldens here, and `internal/admin`'s own tests never look at them.
Reverting the fix and running `internal/admin` is green.

**M3 is the one that answers "are F220 and F221 two rules or one?"** It widens
the `Content-Security-Policy` allow-list by a single entry - the kind of
widening a reader does when a one-member list looks like a typo - and the whole
suite reports exactly two failures, both of them cases this cut wrote. Before
this cut that mutation was green everywhere.

**M9 is a survivor this cut closed rather than filed.** Eleven cells and a
zero-length range read the same green. It is the vacuity failure this project
has hit before, and the guard is two: one for the traversal, one for the
comparison, because a table of eleven rows all expecting both headers absent
would pass the first and assert half of each rule.

**M10 is not a mutation and is in the table because it is the same kind of
evidence.** It is the only way to show that section 2.3's divergence is real
rather than read off the source, and the answer is five headers wide.

## 7. Parity

`make conformance`:

```
before   total: 610 of 677 enumerated behaviours served; 0 chapters not enumerated
after    total: 614 of 681 enumerated behaviours served; 0 chapters not enumerated
```

**Both numbers moved by four and the ratio did not.** `oidc/authorization` and
`oidc/logout` are protocol chapters, whose denominator is the catalogue's own
case count, so every case added moves the top and the bottom together. That is
the weak denominator `Chapter`'s doc comment warns about, working exactly as
described.

Nothing here should be read as progress. No `Operation` was claimed - these
cases pin header cells of endpoints already counted - and no behaviour that was
unserved before is served now. **Three divergences were closed and the meter
cannot see any of them**, which is the honest summary: the meter counts surface,
and a wrong header on a served response is not missing surface.

`CGO_ENABLED=0 go test ./...` green. `make lint` clean.

## 8. What belongs in AGENTS.md

Phrased as it would be folded.

**Replace the `Content-Security-Policy` bullet.** It is right about the value
and wrong about the scope, and the scope is the half that gets believed:

> - **`Content-Security-Policy` on an empty-bodied response is the same
>   request-side rule as `X-Frame-Options`, with an allow-list of one instead of
>   three.** Only `application/x-www-form-urlencoded` gets it, parameters cut
>   untrimmed, and `multipart/form-data` does not - so it is that media type and
>   not "a form request". Measured 2026-09-17 on `GET /auth`'s and `GET
>   /logout`'s 302s, on `POST /login-actions/authenticate`'s, and on a plain
>   admin `DELETE`'s 204, which is as far outside the browser flow as this API
>   goes. F221 filed it as a rule of those redirects, which is the same mistake
>   F220 had corrected one bullet above it. `application/json` is the probe that
>   separates the two headers, and four committed goldens hold the two cells
>   apart now - `oidc/{authorization,logout}/redirect-{json,form}-content-type`.

**Correct the revocation bullet's reason, and say what cannot be measured.**
The fact stands, the explanation is now the general rule, and the endpoint
**cannot be probed to confirm it**:

> - **The revocation success carries `Content-Security-Policy` and no
>   `Content-Type` at all** - the body is empty. The reason written here until
>   2026-09-17 - that revocation is "the odd one on the protocol side" - is not
>   a reason: it is an empty-bodied response answering an
>   `application/x-www-form-urlencoded` request, which is the rule above and
>   predicts the header exactly. **It cannot be shown by varying the request**,
>   and that is worth writing down rather than leaving for somebody to try:
>   measured 2026-09-17, a revocation with any other `Content-Type` is a **401
>   with a 93-byte JSON body**, because Keycloak never reads the form and the
>   client is never authenticated. `POST /logout` with a refresh token is the
>   same shape - a non-form request answers the theme's 4645-byte page, 200 -
>   so both of those call sites are consistent with the rule and falsifiable by
>   nothing. `POST /login-actions/authenticate` is the one that **is**
>   falsifiable, and it diverges. See F265.

**Replace the `POST /login-actions/authenticate` counterexample**, in the bullet
and in `WriteLoginActionRedirect`'s doc comment, which say the same thing:

> - **`POST /login-actions/authenticate`'s 302 is not the counterexample that
>   makes `/auth`'s absences `/auth`'s.** Measured 2026-09-17 across ten request
>   media types: it follows the same two allow-lists. Its six committed goldens
>   are all form-urlencoded and `/auth`'s sixteen all send no `Content-Type`, so
>   the corpus had one endpoint at each extreme and read the endpoint as the
>   variable. That is P2's Task 11's mistake for the third time in this bullet.

**And one sentence about the shape of all three**, because it is the part that
keeps recurring rather than any one header:

> Every correction this bullet has taken about which *requests* carry a header
> has been the same discovery: a family measured with one request shape
> throughout, written up as a property of the family. Deletes with no
> `Content-Type`, redirects with no `Content-Type`, login actions with a form.
> Before writing that a response omits a header, check what the requests that
> measured it had in common.

## 9. Follow-ups

### F265: `Content-Security-Policy` is set at three call sites and is a rule about the request

Sections 3.2 and 3.3. `internal/oidc/revoke.go:63`,
`internal/oidc/logout.go:381` and `httpx.WriteLoginActionRedirect` each set the
header unconditionally. The measured rule is the one `WriteNoContent` and
`WriteEmptyStatus` already implement for `X-Frame-Options`, with
`policyRequestMediaTypes` in place of `framedRequestMediaTypes`, and the fix is
`setEmptyBodyRequestHeaders` gaining those writers as callers.

**The three are not in the same position and the entry should not lump them.**

- **`WriteLoginActionRedirect` diverges.** Its 302 was measured across ten
  request media types and follows both allow-lists; the writer sets both
  headers whatever the request says. This is a live divergence, not a
  suspicion.
- **Revocation's success and `POST /logout`'s 204 are consistent with the rule
  and cannot be falsified.** A request to either with any other `Content-Type`
  is a different response - a 401 with a JSON body, and the theme's 200 page -
  because Keycloak never reads the form. There is no request that produces
  those two empty bodies and disagrees with the call site, so the call sites
  cannot be shown wrong and cannot be shown right either. Moving them to the
  shared rule is a tidy-up with no observable behind it, which is the kind this
  project has a bullet about.

What the fix needs, in order, and it is filed rather than done for the reason
F220 gives about itself - **no committed golden can tell the change from the
bug**:

- one recorded admin case: a `DELETE` with
  `Content-Type: application/x-www-form-urlencoded`. That makes the
  `WriteNoContent` half assertable and is the cheapest of the three, because the
  request is legal, the response is unchanged and the measurement is already in
  section 3.2;
- one on `POST /login-actions/authenticate` with `application/json`. The
  measurement is section 3.3 and the obstacle is the `Location`: a spent session
  code restarts the flow with a fresh `tab_id`, and masking a whole `Location`
  asserts presence and nothing else, which F46 spent a cut removing. A case
  whose redirect goes to the client - `oidc/authorization/replayed-session-code`
  is that shape - would not need the mask, and whether that branch survives a
  non-form `Content-Type` is one probe;
- the revocation and `POST /logout` call sites last or never, on the paragraph
  above.

### F266: a golden that carries a header nothing asserts is invisible in the other direction

Section 2.3. `admin/protocol-mappers/add-models-duplicate-id-same-container`
records all five security headers; Gloak sends none, because the call site it
shares with `-other-container` deletes them unconditionally; and its case names
only `Content-Type`, so nothing compares them.

The mirror header rule closes one direction - every golden **missing** a
security header must have a case declaring it absent. This is the other: a
golden **carrying** one whose case does not assert it. F223 describes the gap in
the abstract ("nothing asserts the first column"); this is a committed instance
of it, on the pair AGENTS.md's fifth exception turns on.

It is two separable pieces:

- **the sweep**, which is F223's: every golden carrying one of the five must
  have a case naming it in `AssertHeaders`. That would report this one by name
  and would be red on the tree as it stands, so it needs the exception list the
  mirror rule already has the pattern for;
- **the divergence itself**, which cannot be fixed. One call site serves both
  cells of a split nobody has explained - F147 - so Gloak can reproduce one of
  them and not both. The entry that makes it visible is worth more than a fix
  nobody can write.

### F267: `omissionsGloakStillSends` is empty and its ratchet is now vacuous

The map emptied when F226 was fixed, which is what it was designed to do. Its
ratchet - an entry no golden uses is reported - iterates the map, so with the
map empty it asserts nothing, and `TestTheMirrorHeaderRuleCanFail` does not
cover it. The mutation that closes it is M9's: add an entry whose golden
declares its omissions and check the failure. That is run in section 6 and it
kills, so the ratchet works today; nothing in the committed tree says so.

A cell in `TestTheMirrorHeaderRuleCanFail` that hands the sweep a corpus, a
declaration set and an excuse list, and checks the stale-entry report, closes
it without needing the map to be non-empty. One cell, the shape of the five
already there.
