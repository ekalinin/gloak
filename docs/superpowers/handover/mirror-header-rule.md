# The mirror header rule

F181. `TestAssertAbsentHeadersAgreeWithTheGolden` checks every absent-header
declaration against the recorded bytes and **cannot catch one being deleted** - a
smaller set of true claims is still true. That was a surviving mutation, half
closed. The rule that closes it is the mirror: **every golden missing a security
header must have a case declaring it absent.**

Everything below was measured on **2026-09-11**, on `test/mirror-header-rule`
branched from `main` at `15af568`. The golden counts are computed over the 1089
committed goldens in the tree, not quoted from anywhere. The one thing that
needed a container - section 5 - was measured against
`quay.io/keycloak/keycloak:26.7.1` on a fresh `start-dev`, three times.

Three things up front:

- **the rule fires on 18 goldens, not 87**, and section 1 is why;
- **all 134 goldens that omit a security header fit a measured bucket.** None is
  a finding, and the two findings this cut did produce are elsewhere: a Gloak
  divergence the rule caught on its first full run (section 4.5) and a refuted
  AGENTS.md rule that needed a container (section 5);
- **the exception list holds exactly one entry**, and it is a divergence rather
  than an unexplained omission.

## 1. The brief's 87, and where it came from

The brief said the rule fires on 87 committed goldens, "none of which declares
anything". It does not. Computed over the tree:

```
1089 committed goldens
 134 omit at least one of the five security headers
 116 of those already declared every header they omit
  18 did not
  17 of the 18 are what this cut wrote
   1 could not be written - section 4.5 - and is the exception list
```

**87 is AGENTS.md's own number and it counts something else.** The bullet's table
reads `no Content-Type  105 all five, 87 four of five, missing X-Frame-Options`.
That is a count of *goldens with no response `Content-Type` that omit
`X-Frame-Options`* - not a count of undeclared omissions - and it was computed on
2026-09-06 over 921 goldens. The tree holds 1089 now and the same cell is **98**.

This is the failure AGENTS.md names about itself: a count written in prose beside
the list it counts will rot, and the brief inherited the rot by reading the
number rather than the list. `TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb`
exists because the same thing happened three times to the number two paragraphs
below this one. The difference here is that the cut that inherited it was the cut
whose job was to stop it.

### 1.1 AGENTS.md's table, recomputed today

```
                    goldens   all five   four of five   none
application/json        843        826              0     17
no Content-Type         203        105             98      0
text/html                28         22              0      6
text/plain                7          0              7      0
application/yaml          6          0              6      0
application/xml           2          2              0      0
```

Two things to say about it.

**The bullet's sharpest claim survives at 1089 goldens.** *"No golden carries a
partial set except one missing exactly `X-Frame-Options`."* Computed: 111 omit
exactly `X-Frame-Options`, 23 omit all five, and **zero** carry any other partial
set. The claim is still true and it is still the fact that says the grouping is
four headers with one rule and `X-Frame-Options` with its own.

**The table's `text/html` row was already incomplete when it was written.** It
shows `15 all five` and no "none" column, while the prose two paragraphs below
describes `GET /realms/{realm}/protocol/saml`'s 400 page - which is `text/html`
and sends none of the five. Six committed goldens are in that cell today. A table
with no column for the exception the paragraph beside it is about is a table that
cannot disagree with the paragraph, which is most of why it went four days
without anybody noticing it had.

## 2. The 134, by bucket, counted rather than quoted

Each bucket is one of AGENTS.md's measured omissions. The "declared before"
column is how many of the bucket already had the declaration; "written here" is
what this cut added.

```
bucket                                                  goldens  declared before  written here
A1  a request that resolves nothing at all                    3                3             0
A2  the path-not-normalized 400, ahead of the route table      1                1             0
B   GET /protocol/saml's 400 page                              6                6             0
C   the Duplicate resource error family                       13                3             9*
D   a text/plain response                                      7                7             0
E   an application/yaml response                               6                5             1
F   an empty body whose request media type is not
    one of the allow-listed three                             98               91             7
                                                            ---              ---           ---
                                                             134              116            17
```

`*` the tenth of bucket C is `admin/identity-providers/mappers-create-no-name`,
which is section 4.5: the declaration is right, Gloak is wrong, and the entry is
in the exception list instead.

### 2.1 A - nothing resolved, and the one that never reached the route table

`http/fallback/unknown-path`, `-trailing-slash-unknown-path` and
`-realms-collection` send none of the five because nothing resolved on the way
in. `http/fallback/path-not-normalized` is the separate one: it runs *before* the
route table, so it is the never-reached-the-filter-chain case rather than the
nothing-resolved one, and it declares `Cache-Control` alongside the five.

All four were already declared. They are the pair AGENTS.md's seventh correction
rests on, and the correction landed with its declarations, which is the shape
every one of these should have had.

### 2.2 B - the SAML 400 page

Six goldens, all `400 text/html;charset=utf-8`, all declaring the five plus
`Content-Security-Policy`. All were already declared, by P11, and they are the
reason `AssertAbsentHeaders` exists at all.

### 2.3 C - the `Duplicate resource error` family: ten of the eighteen

Thirteen goldens carry the 67-byte body and none of the five. **Three declared
it. Ten did not**, and six of those ten carried a comment saying the absence in
prose:

| golden | what it said before |
| --- | --- |
| `admin/protocol-mappers/duplicate-id-other-container` | nothing |
| `admin/protocol-mappers/add-models-duplicate-id-other-container` | nothing |
| `admin/client-scopes/create-duplicate-mapper-id` | nothing |
| `admin/client-scopes/create-duplicate-mapper-id-across-realms` | nothing |
| `admin/clients/create-duplicate-mapper-id` | nothing |
| `admin/clients/update-duplicate-mapper-id` | nothing |
| `admin/identity-providers/mappers-create-no-name` | *"it sends **none** of the five"* - and nothing asserted it |
| `admin/authentication-management/create-no-provider` | *"it carries **none** of the five"* - `Cache-Control` declared, the five not |
| `admin/authz-resource-server/put-no-decision-strategy` | *"the 409 **drops the five**"* - two of five declared |
| `admin/authz-resource-server/resource-put-conflict` | *"carries **none** of the five"* - one of five declared |

The last four are the interesting ones. **A sentence claiming five and a
declaration naming one or two passed every test in this repository**, because
nothing counted the sentence against the list. That is the same defect the rule
is about, one level down: the prose was the assertion and the assertion was a
sample.

`admin/protocol-mappers/add-models-duplicate-id-other-container` is the sharpest.
AGENTS.md cites it by name, against `-same-container`, as the pair that refutes
every explanation of the split - same route, same verb, same 67 bytes, one sends
all five and the other none. **The golden the bullet cites was declaring
nothing**, so the half of the pair the argument turns on was unasserted from both
sides. AGENTS.md records this bullet as having been refuted twice by the very
golden it cited; this is a third shape of the same thing, where the golden was
not contradicting the sentence but failing to say anything at all.

### 2.4 E - the `application/yaml` response

Five of the six workflow reads declared `X-Frame-Options` absent.
`admin/workflows/scope-filtered-held-roles` did not, and it is **byte-identical to
`admin/workflows/list-empty`, headers included** - same status, same
`Content-Type`, same `--- []` body, same four headers. One declared both of its
absences and the other declared neither. Nothing could have told them apart.

### 2.5 F - the empty-body rule, and the 2x2 that has no off-diagonal

Ninety-eight goldens, and the seven this cut wrote are all 204s or a 204-shaped
`GET`:

```
admin/clients/delete
admin/identity-providers/export
admin/authentication-management/delete
admin/authentication-management/delete-config
admin/authentication-management/delete-execution
admin/authentication-management/execution-raise-priority
admin/authentication-management/execution-lower-priority
```

Two of the seven are **`POST`s with no body**, which is the half of the rule P2's
Task 11 got wrong: it read four deletes that all happened to send no
`Content-Type` and wrote "a successful `DELETE`'s 204 omits it". Declaring the
absence on a `POST` is what keeps the method out of it.

`admin/identity-providers/export` is the one to notice. The delete two cases
above it in the catalogue, **on the same fixture**, already declared exactly
`{"Content-Type", "X-Frame-Options"}`. The export declared `Content-Type` alone.
One case apart, same rule, half the declaration.

The bucket is not a bucket of 204s. By status:

```
204  73      400   3
302  16      404   3
200   2      201   1
```

and the request media types are: none at all 94, `text/plain` 2,
`application/yaml` 2.

**The control is what makes this a rule rather than a list.** Over the same tree:

```
                                      omit X-Frame-Options   carry it
empty body, request media type in
the allow-list of three                                  0        105
empty body, request media type
outside it                                              98          0
```

203 goldens, no off-diagonal cell. The allow-list is
`application/json`, `application/xml`, `application/x-www-form-urlencoded`, with
parameters cut and **not trimmed**.

## 3. Every golden that did not fit

**None.** All 134 fit a bucket above, and the classification was computed rather
than eyeballed: response media type, status, body length and the case's own
request `Content-Type`, joined to the golden.

Three near-misses are worth naming, because each looked like a finding until it
was read:

- **the sixteen 302s in bucket F.** AGENTS.md files these under a different rule
  - *"`GET /auth`'s redirect back to the client is the one response in the
  browser flow that omits `X-Frame-Options` ... the rule is per endpoint"* - and
  they satisfy bucket F's rule as well, because a 302 to a client's redirect URI
  is an empty body and every one of these requests is a `GET` with no
  `Content-Type`. Two rules, one set of goldens, no golden separating them. That
  is section 5, and it turned out to be the finding of this cut;
- **the two `OPTIONS` 200s**, `saml/descriptor/options` and
  `account/dispatch/options`. AGENTS.md's bullet says `X-Frame-Options` is absent
  on "an `OPTIONS` 200 (measured on four endpoints, **no golden records it**)".
  Two goldens record it, and both were already declared. The parenthesis is
  stale, not wrong about the behaviour;
- **`admin/identity-providers/export`**, a `GET` that answers **204**. It is not
  an error and not a mis-recording: the export of anything but a SAML provider is
  a bodyless 204, which the case's own comment says.

## 4. The proof that the rule still bites

A rule green with 134 excused goldens is the same colour as a rule watching
nothing. Three things stand behind it, and the first is the one that matters.

### 4.1 Written first, and observed failing on exactly 18

`TestEveryGoldenMissingASecurityHeaderDeclaresItAbsent` was written before any
declaration and run against the untouched tree. It reported **18 goldens by
name** - the 10 of bucket C, the 7 of bucket F and the 1 of bucket E - and
`TestAssertAbsentHeadersAgreeWithTheGolden` was green throughout, which is the
hole stated as an observation rather than as an argument.

### 4.2 `TestTheMirrorHeaderRuleCanFail`

Six cells, each a way the sweep could have been written to pass everything: an
undeclared omission is reported; a declared one is not; a **partial** declaration
reports the remainder rather than being satisfied by its first entry; a header
the golden carries is left to the test on the other side of the mirror; a golden
no case names is reported whole; and a golden spelling its headers in lower case
is not read as omitting them.

The third cell is not hypothetical - two committed cases were in exactly that
state, declaring two of five and one of five against a comment claiming all five.
The sixth is section 4.4.

### 4.3 The mutation pass

Each mutation applied, the **named** test run, reverted on a `trap ... EXIT`, and
the revert verified against `git diff --quiet`. Every run was from a committed
tree. The `internal/httpx` mutations are the only production code this cut
touched at all, and both were reverted inside their own script.

| # | mutation | killed by | survived |
| --- | --- | --- | --- |
| M1 | delete `AssertAbsentHeaders` from `admin/clients/delete` - **F181's mutation, verbatim** | the mirror rule, naming the golden | `TestAssertAbsentHeadersAgreeWithTheGolden` stayed **green**, which is the hole |
| M2 | one declared header excuses all five | `TestTheMirrorHeaderRuleCanFail`, partial cell | the sweep over the tree stayed green |
| M3 | skip a golden the catalogue does not name | `TestTheMirrorHeaderRuleCanFail`, orphan cell | the sweep over the tree stayed green |
| M4 | sweep an empty corpus | the `read == 0` fatal | - |
| M5 | `httpx.WriteEmptyStatus` stops deciding from the request | `TestConformance`, `want absent, got ["SAMEORIGIN"]` | - |
| M6 | `httpx.WriteNoContent` stops deciding from the request | `TestConformance`, 72 cases, **including all seven this cut declared** | - |
| M7 | drop `http.CanonicalHeaderKey` from both sides | **nothing** - see 4.4 | the whole suite |
| M8 | remove `X-Frame-Options` from `theFiveSecurityHeaders` | `TestTheMirrorHeaderRuleCanFail`, first cell | the sweep **and** `TestTheDuplicateResourceErrorSplit...` - see F224 |
| M9 | an exception-list entry no golden uses | the ratchet, naming the entry | - |
| M10 | delete the one real exception-list entry | the sweep, naming the golden | - |

M2 and M3 are the pair the discipline asks for: a mutation that makes a function
*fail* is not the same as one that makes it *wrong consistently*, and both of
these leave the tree green and a future half-declaration unreported. They are
what the guard exists for rather than the sweep.

M6 is worth reading as the answer to "do these declarations assert anything about
Gloak, or only about a file?". Seventy-two cases fail, and the seven names this
cut added are all in the list.

### 4.4 The survivor, and what an implementation satisfying it looks like

**M7 survived the entire suite.** The mutated lines are the three
`http.CanonicalHeaderKey` calls in `undeclaredSecurityHeaderOmissions`: the
golden's header names, the declaration's, and the lookup.

An implementation satisfying it is one that compares header names **as written**.
It passes today because every committed golden spells its headers canonically -
`recordedHeaders` takes them from Go's `http.Header`, whose keys are canonical by
construction - and because every `AssertAbsentHeaders` entry in the catalogue is
written canonically too. Nothing in the corpus exercises the folding.

The two directions are not equally bad. A **declaration** spelled
`x-frame-options` would make a real omission report as undeclared, which is loud.
A **golden** whose head spelled `x-frame-options` would read to a raw comparison
as a header that is not there, and the omission it really is would go
**unreported** - silent, and on the only kind of golden the rule against
hand-editing exists for. Closed in `cc2411e` by a sixth cell in the guard, and
M7 is red after it.

## 4.5 The rule found a divergence on its first full run

Seventeen of the eighteen declarations went in and `CGO_ENABLED=0 go test ./...`
came back with **one** failing case:

```
--- FAIL: TestConformance/admin/identity-providers/mappers-create-no-name
    header Referrer-Policy: want absent, got ["no-referrer"]
    header Strict-Transport-Security: want absent, got ["max-age=31536000; includeSubDomains"]
    header X-Content-Type-Options: want absent, got ["nosniff"]
    header X-Frame-Options: want absent, got ["SAMEORIGIN"]
    header X-Robots-Tag: want absent, got ["none"]
```

The golden records none of the five. **Gloak sends all five.**
`createIdentityProviderMapper` writes its 409 through `httpx.WriteOAuthError`,
where the twelve other goldens carrying this body go through `internal/admin`'s
`writeDuplicateResource`, whose whole job is to delete the five first. One call
site of thirteen.

It is worth being precise about what was and was not known. The case's own
comment has read *"it sends **none** of the five, while the duplicate 400 below
and the empty-body 500 beside it - same route, same verb, same `Content-Type` -
send all five"* since 2026-09-02. The golden has held the recording since then
too. **The divergence is older than this cut and nothing in the repository could
see it**, because `AssertHeaders` only checks a header that is named and this
case named none of the five in either direction. The declaration is what made
the server's answer comparable to the recording.

That is the rule earning its keep, and it is the answer to "is a rule with
exemptions worth anything": the first sweep over the tree produced a real
divergence in production code, on a route whose contract had been written down
and agreed with by nobody for nine days.

**It is not fixed here.** A handler change riding along on a test sweep is the
thing this cut was told not to do, and the reason is good: the fix is one line in
`internal/admin` and the case for it should be read on its own. The entry lives
in `omissionsGloakStillSends` in `mirrorheader_test.go` with the reason, the two
call sites that differ and F226, under the same ratchet
`namedOutsideTheConvention` carries.

Two mutations pin the bargain:

| # | mutation | result |
| --- | --- | --- |
| M9 | add an entry whose golden declares its omissions | **fails**: `omissionsGloakStillSends excuses "admin/clients/delete" and its golden's omissions are declared now` |
| M10 | delete the one real entry | **fails**: the sweep reports `mappers-create-no-name` by name |

So the list cannot hold a reason nobody re-reads, and the one reason in it is
load-bearing. It empties by somebody fixing the handler and writing the
declaration, at which point the entry goes stale and the ratchet says so.

## 5. The finding: the `/auth` and `/logout` 302s are not a per-endpoint rule

This is the one question the cut could not answer by reading committed bytes, so
it was measured.

AGENTS.md says, twice:

> **`GET /auth`'s redirect back to the client is the one response in the browser
> flow that omits `X-Frame-Options`,** measured across seven different rejections
> [...] It is not "errors omit them" [...] It is not "302s omit them" [...] It is
> not "failures omit them" [...] RP-initiated logout's redirect behaves the same
> way, **so the rule is per endpoint**.

The corpus is consistent with that and also consistent with bucket F, and it
cannot tell them apart: all 22 committed 302 goldens split exactly along the
request's `Content-Type`.

```
XFO  oidc/authorization/code-flow-redirect          POST {{login_action}}   form-urlencoded
XFO  oidc/authorization/pkce-plain                  POST {{login_action}}   form-urlencoded
XFO  oidc/authorization/pkce-s256                   POST {{login_action}}   form-urlencoded
XFO  oidc/authorization/replayed-session-code       POST {{login_action}}   form-urlencoded
XFO  oidc/authorization/required-action-redirect    POST {{login_action}}   form-urlencoded
XFO  oidc/authorization/response-mode-fragment      POST {{login_action}}   form-urlencoded
---  the other sixteen                              GET                     no Content-Type
```

Measured on a live 26.7.1, `GET /auth` with a registered `redirect_uri` and no
`response_type`, so every row is the same 302 to the client. The `Location` is
**byte-identical across all ten rows**, so this is one branch answering
differently, not ten different responses:

```
request Content-Type                  X-Frame-Options
absent                                -
application/json                      SAMEORIGIN
application/xml                       SAMEORIGIN
application/x-www-form-urlencoded     SAMEORIGIN
application/json;charset=UTF-8        SAMEORIGIN
application/json ; charset=UTF-8      -          (the untrimmed space)
application/ld+json                   -
application/yaml                      -
text/plain                            -
*/*                                   -
```

`GET /logout` answers the same way. Three runs, identical.

**That is the allow-list of three, with parameters cut untrimmed, exactly as
`WriteNoContent` and `WriteEmptyStatus` already implement it for every other
empty-bodied response.** The 302 to a client's redirect URI is an empty body. It
is not this endpoint's rule; it is the rule.

The sweep of 2026-08-29 that wrote "per endpoint" sent **seven rejections and no
`Content-Type` on any of them**, which is precisely the shape of P2's Task 11 -
four deletes that all happened to send none, written up as a statement about the
method. The same mistake, the same way, a second time, and this bullet records
the first one three paragraphs further down.

**This makes it a Gloak divergence, and this cut deliberately does not fix it.**
`httpx.WriteAuthorizationRedirect` and `httpx.WriteLogoutRedirect` call
`Del("X-Frame-Options")` unconditionally, so Gloak omits the header where
Keycloak sends it for a JSON-typed request. No golden catches it, because no case
sends a `Content-Type` on a `GET` to those endpoints. F220.

### 5.1 And `Content-Security-Policy` is a rule of its own, on one media type

The same table, read for `Content-Security-Policy`:

```
application/x-www-form-urlencoded     present
everything else, including json/xml   absent
```

One media type of the three, and only that one. AGENTS.md pairs the two headers -
*"it omits `Content-Security-Policy` with it"* - and in the corpus they do move
together, because the corpus has only the two extreme cells. They are two rules
and `application/json` is the probe that separates them: `X-Frame-Options`
appears and `Content-Security-Policy` does not. F221.

## 6. Parity

`make conformance`, before and after this cut:

```
total: 578 of 631 enumerated behaviours served; 2 chapters not enumerated
```

Unmoved, which is the expected outcome: no case changed status, no operation was
claimed, and no production code changed.

`CGO_ENABLED=0 go test ./...` green. `make lint` clean.

The one thing that moved and should be said plainly: the suite was **red for one
case** between the seventeenth declaration and the exception list, and that red
is section 4.5. It is not a regression this cut introduced; it is a divergence
this cut made visible, parked with a reason and a ratchet rather than fixed.

## 7. What belongs in AGENTS.md

Phrased as it would be folded, into the security-header bullet.

**Replace the `GET /auth` redirect bullet.** It currently reads as a per-endpoint
rule and is the eighth correction:

> - **`GET /auth`'s and `GET /logout`'s redirects back to the client obey the
>   empty-body rule, not a rule of their own.** They were recorded as "this
>   endpoint's redirect" from a sweep of seven rejections that all sent no
>   request `Content-Type` - which is P2's Task 11's mistake in a second place.
>   Measured 2026-09-11 on one 302 with a byte-identical `Location`
>   across ten request media types: `application/json`, `application/xml`,
>   `application/x-www-form-urlencoded` and `application/json;charset=UTF-8`
>   carry `X-Frame-Options`; absent, `application/yaml`, `application/ld+json`,
>   `text/plain`, `*/*` and `application/json ; charset=UTF-8` do not. That is the
>   allow-list of three with parameters cut untrimmed. **Gloak deletes the header
>   unconditionally in `WriteAuthorizationRedirect` and `WriteLogoutRedirect`,
>   which is a divergence, not a copy** - F220.
> - **`Content-Security-Policy` on those redirects is a separate rule and it is
>   one media type wide.** Only `application/x-www-form-urlencoded` gets it;
>   `application/json` carries `X-Frame-Options` and not this. The two headers
>   move together in every committed golden because the corpus holds only the two
>   extreme cells - F221.

**Replace the table with a pointer**, the way the fifth exception was already
replaced:

> **They are not five headers with one rule. They are four with one rule and
> `X-Frame-Options` with its own.** No golden carries a partial set except one
> missing exactly `X-Frame-Options` - computed by
> `TestEveryGoldenMissingASecurityHeaderDeclaresItAbsent`, which requires every
> omission in the tree to be declared on its case, so the omissions are a
> catalogue rather than a paragraph. The numbers are not written here: the table
> that used to be was computed over 921 goldens on 2026-09-06, the tree holds
> 1089, and one of its cells was read as an undeclared-omission count by a later
> cut that trusted it.

**And one sentence beside `AssertAbsentHeaders`' own bullet**, which is the
general lesson rather than a header fact:

> A comment claiming a header is absent is not an assertion. Four cases carried
> a sentence saying "none of the five" while declaring one or two of them, and
> nothing in the repository compared the sentence to the list. One of them was
> describing a response Gloak had never sent - F226 - and the prose had been
> right and unchecked for nine days.

## 8. Follow-ups

### F220: `GET /auth` and `GET /logout` omit `X-Frame-Options` by request media type, and Gloak omits it always

Section 5 is the measurement. Gloak's `WriteAuthorizationRedirect` and
`WriteLogoutRedirect` call `Del("X-Frame-Options")` unconditionally; Keycloak
deletes it only when the request's media type is outside the allow-list of three.

The fix is the two writers taking `*http.Request` and reusing
`framedRequestMediaTypes`, which is the check `WriteNoContent` and
`WriteEmptyStatus` already share - so it is a shared predicate gaining a third
and fourth caller rather than new logic. What makes it a cut rather than a
one-liner is the golden: **no committed case sends a `Content-Type` on a `GET` to
either endpoint**, so the change is unassertable today. It needs one new case per
endpoint sending `Content-Type: application/json`, recorded, before the handler
moves - otherwise the fix is a change no test can distinguish from the bug.

Worth doing in the same cut: the six `POST {{login_action}}` 302s carry the
header today for the right reason by accident, and nothing says so.

### F221: `Content-Security-Policy` on the client redirect is one media type wide

Section 5.1. `application/x-www-form-urlencoded` gets it and `application/json`
does not, on a response whose `Location` is byte-identical either way. Gloak
sends it on neither.

This is stranger than F220 and should not be folded into it. `X-Frame-Options`
follows a three-member allow-list that eight other measured cells agree with;
this follows a one-member list that nothing else in the project matches. The
entry is to measure it on a second endpoint before believing it is a rule at all
- `GET /logout` already agrees, so the third should be outside the browser flow,
and `POST /login-actions/authenticate` with a JSON `Content-Type` is the sharpest
because it sends the header today.

### F222: the `OPTIONS` 200 cell says "no golden records it" and two do

AGENTS.md's bullet reads *"on an `OPTIONS` 200 (measured on four endpoints, no
golden records it)"*. `saml/descriptor/options` and `account/dispatch/options`
record it, both declared. The parenthesis is stale rather than wrong, and it is
the kind of stale that makes a reader go and measure something the tree already
holds.

The entry is one sentence, and it is filed rather than folded because the same
paragraph needs F220's rewrite and the two should land together.

### F223: the empty-body 2x2 is computed here and asserted nowhere

Section 2.5 computes it: 105 goldens whose request media type is allow-listed
carry `X-Frame-Options`, 98 whose is not omit it, and there is no off-diagonal
cell. The mirror rule asserts the second column - every omission is declared - and
**nothing asserts the first**. A new golden landing in the wrong cell of the
first column is caught by its own case's `AssertHeaders` only if somebody
remembered to name the header there, which is the asymmetry
`AssertAbsentHeaders`' doc comment is about, pointing the other way.

The shape is the one `TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb`
already uses: compute the 2x2 over the tree and assert the claim rather than the
counts, so a cut that adds a golden moves the numbers and leaves the claim
standing. The reason it is not in this cut: it needs the request's media type,
which means joining the catalogue to the corpus for a property the goldens do not
record, and it wants deciding whether a `Pending` case's request counts.

### F224: `TestTheDuplicateResourceErrorSplit...` does not pin the size of the set

M8 removed `X-Frame-Options` from `theFiveSecurityHeaders` and that test stayed
green. It counts headers present and compares against `len(theFiveSecurityHeaders)`,
so the slice shrinking to four re-labels "four of five" as "all of them" and every
tally still lands in a bucket it recognises. The mirror rule's guard does kill
M8, so the set's size is pinned in the package - by the wrong test.

A one-line `if len(theFiveSecurityHeaders) != 5` in `headersplit_test.go` closes
it. It is filed rather than done because it belongs to that test's cut and this
one had no business editing it.

### F226: `createIdentityProviderMapper`'s 409 sends the five where Keycloak sends none

Section 4.5. The thirteenth call site of a 409 `Duplicate resource error` in
`internal/admin`, and the only one that does not go through
`writeDuplicateResource`:

```go
// internal/admin/identityprovidermappers.go
if body.Name == "" {
    httpx.WriteOAuthError(w, http.StatusConflict, "conflict", "Duplicate resource error")
    return
}
```

The measurement is the committed golden,
`admin/identity-providers/mappers-create-no-name`, recorded from a live 26.7.1 by
this project's own recorder, and the case's comment describes it: the 409 sends
none of the five while the duplicate-name 400 and the empty-body 500 on the same
route, same verb and same request `Content-Type` send all five.

The fix is `writeDuplicateResource(w)` - same package, already exported to the
file's neighbours, already carrying the doc comment that explains why the delete
is there. Two things to do with it rather than just the one line:

- **take the entry out of `omissionsGloakStillSends` and write the declaration**,
  or the ratchet will say so anyway;
- **ask whether the other twelve reached `writeDuplicateResource` by rule or by
  luck.** Twelve of thirteen is the ratio that suggests a convention nobody
  wrote down. If there is one, `internal/admin` wants a single writer for this
  body rather than a helper somebody has to remember; if there is not, the
  thirteen want a test that enumerates them.

### F225: `TestAssertAbsentHeadersAgreeWithTheGolden` has M7 unclosed

Section 4.4 closed the canonicalisation survivor for the mirror rule. The test on
the other side of the mirror canonicalises identically and has the same untested
folding, and its exposure is the same: a golden hand-edited to spell a header in
lower case would make a declaration that contradicts it read as agreeing.

The fix is the same one cell. It is filed rather than done for F224's reason.
