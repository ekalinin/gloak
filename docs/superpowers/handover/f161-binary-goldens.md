# F161: what a golden can assert about a body that is not text

Measured against a live Keycloak 26.7.1 on `localhost:8172` on 2026-09-05,
container `kc-cert`, started for this cut and removed after it. Nothing below is
written from memory.

The question F161 asks is answered: **nothing**, and the harness now says so
where it can fail rather than in a paragraph. The chapter went from 0 of 7 to 4
of 7 on the way, and F161's own description of the seven turned out to be wrong
twice.

## 1. Measurements

### 1.1 The seven operations, and how many are actually binary

Computed from `paths` in the vendored description filtered on the
`Client Attribute Certificate` tag, not taken from the entry. The count of seven
is right; the seventh is not under `/clients`.

| operation | status | `Content-Type` | `Cache-Control` | five security headers |
|---|---|---|---|---|
| `GET .../certificates/{attr}` | 200 | `application/json;charset=UTF-8` | `no-cache` | all five |
| `POST .../generate` | 200 | `application/json;charset=UTF-8` | `no-cache` | all five |
| `POST .../download` | 200 | `application/octet-stream` | `no-cache` | **four** |
| `POST .../generate-and-download` | 200 | `application/octet-stream` | `no-cache` | **four** |
| `POST .../upload` | 200 | `application/json;charset=UTF-8` | **absent** | all five |
| `POST .../upload-certificate` | 200 | `application/json;charset=UTF-8` | **absent** | all five |
| `POST /identity-provider/upload-certificate` | 200 | `application/json;charset=UTF-8` | **absent** | all five |

**Five of the seven answer JSON.** The three that *take* `multipart/form-data`
answer JSON, and a golden records a response, so they were never blocked by the
binary question. Neither binary response carries a `Content-Disposition` at all.

### 1.2 The two binary bodies, and the length claim

Twelve requests per operation per format, one client:

```
                              distinct lengths            distinct bodies
download JKS                  4413                        12 of 12
download PKCS12               4869                        12 of 12
download BCFKS                4948                        12 of 12
generate-and-download JKS     4412 4413 4414 4415         12 of 12
generate-and-download PKCS12  4869 4877                   12 of 12
generate-and-download BCFKS   4947 4948 4949              12 of 12
```

The keystore is re-encrypted under a fresh salt on every request even when the
key inside it has not moved.

**`generate-and-download` cannot hold a length**, so F161's "even a byte-holding
golden could assert nothing but a length" is wrong for it. And `download`'s
length is stable only while the key is: generate first, which is what a fixture
does on every recording, and JKS came back 4412, 4413, 4414 and 4415 over ten.

The accepted format set is the server's own, from its 406:
`{"error":"Not supported keystore format. Supported keystore formats: [BCFKS, PKCS12, JKS]"}`.
It is case-sensitive - lower-case `jks` is a **500**, which is how the first
probe in this cut came to report the same answer for four different inputs.

### 1.3 The three multipart operations are byte-deterministic

All three echo what they are given, decoded and re-encoded. The same file
uploaded twice gave byte-identical responses on all three.

```
POST .../upload             JKS or PKCS12 keystore -> {privateKey, certificate}
POST .../upload-certificate Certificate PEM        -> {certificate}
POST /identity-provider/upload-certificate         -> {publicKey, certificate}
```

Given a constant file in the catalogue they carry byte-exact goldens with no
mask at all. Their refusals:

```
no body at all, or a body that is not multipart  400 {"error":"keystoreFormat cannot be null"}
a format, no file part                           400 {"error":"file cannot be empty"}
upload-certificate, any format but Certificate PEM   500 unknown_error
upload-certificate, a file that is not a certificate 500 unknown_error
upload, Certificate PEM or Public Key PEM            500 unknown_error
upload, a file that is not the format it was given   400 {"error":"error loading keystore"}
```

The format is checked before the file, so a request sending neither answers
about the format. `file cannot be empty` is a spelling this API had not used
before. **The armour is optional**: the same certificate was accepted as a
`-----BEGIN CERTIFICATE-----` block and as bare base64, byte-identical answers.

### 1.4 State

`{attr}` is a **free-form prefix**, not an enum: `my.prefix` works and stores
`my.prefix.private.key` and `my.prefix.certificate`. The whole chapter is client
attributes, so **no migration was needed**.

An `{attr}` naming nothing is `200 {}`, not a 404, on a client that has other
keys. So is `jwt.credential` on a client that has never generated one.

**`upload-certificate` deletes the private key.** A client carrying both came
back `{certificate}` alone, and its representation held only
`jwt.credential.certificate`. It is not a partial update of the pair.

### 1.5 The guards, swept one role at a time with a control

`POST /admin/realms/master/clients` is the control column, so a sweep answering
the same code for every role would have been visible:

```
role                      GET  generate  download  gen-and-dl  upload-cert  idp-upload  CONTROL
view-clients              200  403       200       403         403          403         403
manage-clients            200  200       200       200         200          403         201
view-realm                403  403       -         -           403          403         403
manage-realm              403  403       -         -           403          403         403
query-clients             403  403       -         -           403          403         403
view-identity-providers   403  403       -         -           403          403         403
manage-identity-providers 403  403       -         -           403          200         403
```

1. **`POST .../download` takes the *view* role.** A POST opened by
   `view-clients` is new here, and it is not the family's rule - its sibling
   `generate-and-download` needs `manage-clients`. The verb does not decide;
   whether the operation writes does.
2. **`POST /identity-provider/upload-certificate` is authorised out of the
   identity-provider role set**, though its tag is `Client Attribute
   Certificate`. `manage-clients`, which opens every other operation in the tag,
   is 403.
3. It takes the **manage** role where six sibling reads under
   `/identity-provider/instances/{alias}` take the view role.

### 1.6 What `POST .../generate` mints

Read off a certificate 26.7.1 produced, and off two more with the request time
recorded alongside:

```
RSA 4096                     not 2048
X.509 version 1              and no extensions
serial                       the request's millisecond epoch
sha256WithRSAEncryption
issuer == subject            CN=<the client's clientId>
notBefore                    the request, less ~100 seconds
notAfter                     the request, plus three calendar years (1096 days)
privateKey                   PKCS#1, base64 std, no PEM armour
```

The backdate came back 98, 99 and 99 seconds on three certificates, so Keycloak
computes its two bounds from instants a keygen apart and the exact second is not
reproducible. Gloak takes one instant and is exactly 100.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds them in. This branch does not
edit it.

### For the security-headers bullet, exception (2)

> **`application/octet-stream` carries four of the five, omitting
> `X-Frame-Options`.** Measured 2026-09-05 on both binary operations of the
> certificate family, against five `application/json` 200s in the same family
> and on the same resource that carry all five. That is a fourth media type in
> the table above and the first response measured to carry *some* of the five
> rather than all or none.
>
> It is also **the first non-`OPTIONS` response measured to omit exactly
> `X-Frame-Options`**, which is the shape exception (4) describes and calls
> unmeasured. Whether the two are one rule is still unmeasured: an `OPTIONS` 200
> has no media type of its own, so the response that would say so has not been
> issued.
>
> **No golden records it**, because the two operations that produce it are the
> two F161 says can carry none - so like (4), it cannot be checked from the tree.
> This is two responses in one family, not a rule. See F161.

### For the `Cache-Control` bullet

> The certificate family splits **four to three inside one resource**: `GET
> .../certificates/{attr}`, `POST .../generate`, `POST .../download` and `POST
> .../generate-and-download` send `no-cache`, and the three uploads send none.
> Seven operations on one path prefix, one attribute, two answers - which is the
> tightest confirmation yet that "pinned per endpoint" is the only part of this
> bullet that has ever survived. Asserted by
> `admin/client-attribute-certificate/read-empty` and
> `.../upload-certificate`, which declares `Cache-Control` in
> `AssertAbsentHeaders`.

### For the "reads accept the manage role" bullet

> **A third read refuses the view role, and a POST accepts one.**
> `POST /admin/realms/{realm}/identity-provider/upload-certificate` needs
> `manage-identity-providers`, where six sibling reads under
> `/identity-provider/instances/{alias}` take the view role too - the same shape
> as `reload-keys`, on a route that stores nothing. And going the other way,
> **`POST .../certificates/{attr}/download` is opened by `view-clients`**, which
> is the first POST in this API measured taking a read role. Its sibling
> `generate-and-download` needs `manage-clients`, so the split inside the pair
> is whether the operation writes, not the verb.

### For the "description's tag does not predict the guard" thread

> **A fourth instance**, and the first where the route is not even in the tag's
> path family. `POST /admin/realms/{realm}/identity-provider/upload-certificate`
> is tagged `Client Attribute Certificate` and every other operation in that tag
> is under `/clients/{uuid}/certificates/`. `manage-clients` opens all of those
> and is 403 on this one. Pinned by
> `admin/client-attribute-certificate/identity-provider-upload-certificate-forbidden`,
> which sends a `manage-clients` caller rather than the administrator - the case
> beside it would pass whatever role list the route carried.

### A new bullet, for the goldens themselves

> **A golden's body must be text, and the harness refuses one that is not.**
> `RefuseNonTextBody` is called by the recorder before it writes and by
> `TestEveryGoldenBodyIsText` over every committed golden - 900 after the events
> family landed, and the test **prints the number rather than asserting one**,
> because a count in prose beside the thing counted is a count that will drift.
> The question it
> answers is F161's: two operations answer a JKS, PKCS12 or BCFKS keystore, and
> twelve requests for each of six combinations produced twelve distinct bodies
> every time. The length does not survive either - `generate-and-download` came
> back at four different lengths, and `download`'s is stable only until the key
> is regenerated, which is what a fixture does on every recording.
>
> So a case whose response is binary carries no golden and is therefore not
> `Implemented`, which is the honest state: the operation is counted as unserved
> rather than served behind an assertion about a length. This is **F113's rule
> one layer down** - a response carrying a per-request value cannot be
> `Recorded`, because `Recorded` is a promise the recorder has to keep - made
> checkable over the bytes rather than over the status.
>
> Reopening it means the decoded projection F161 calls shape 2, and the argument
> against that is in the plan: it costs a JKS reader Go does not have, to assert
> a key `admin/client-attribute-certificate/read-after-upload` already pins byte
> for byte.

### For the not-found list

> Nothing is added. `GET .../certificates/{attr}` for an unknown client answers
> `Could not find client`, which is already (1); an unknown realm answers
> `Realm not found.`, already (4); and **an `{attr}` naming nothing is not a
> not-found at all** - it is `200 {}`. That is the second endpoint family
> measured answering an empty 200 where a 404 would be expected, after
> `GET .../localization/{locale}` on a missing locale.

## 3. Follow-up dispositions

### F161 - closes

The question is answered and the answer is enforced. **Shape 3**: the two binary
operations carry no golden and are `Pending` with the measurement as their
reason; the other five are ordinary. Four of them are served in this cut.

Three things the entry says that did not survive measurement, recorded because
the entry will be read again:

- "Two answer a binary keystore and **three take multipart/form-data**" is true
  and misleading. **Five of the seven answer JSON.** The multipart three answer
  JSON and needed **no harness mechanism at all**: `Request.Body` plus a
  `Content-Type` header in `Request.Headers` has expressed a multipart request
  since the field existed.
- "even a byte-holding golden could assert nothing but a length" is **wrong for
  `generate-and-download`**, which has no stable length, and wrong for
  `download` too once the golden is recorded the way goldens are recorded.
- The entry treats the chapter as blocked on one question. It was blocked on
  two, and the second is not about the harness: **`POST .../upload` needs a JKS
  or PKCS12 reader in production code**, which Go's standard library and
  `x/crypto` do not have. That is the one operation of the five servable ones
  this cut leaves.

**What replaces it**, as three smaller entries a later cut can pick up:

1. `POST .../upload` needs a keystore reader. `x/crypto/pkcs12` decodes only the
   legacy PBE algorithms; JKS has no Go reader anywhere in the standard
   distribution. Its response is ordinary JSON and would carry a byte-exact
   golden the moment it can be served, so this is a dependency question and not
   a harness one.
2. `POST .../download` and `POST .../generate-and-download` are measured in full
   (section 1.2, 1.5) and cannot be `Implemented` while `RefuseNonTextBody`
   stands. Reopening means building the decoded projection, and the bar for that
   is a consumer whose assertion is not a duplicate of a JSON sibling's.
3. `admin/client-attribute-certificate/generate`'s golden masks both of its two
   values. That is the whole-`Location` retreat at body scale, and it is
   compensated rather than fixed: `internal/admin`'s own tests pin the key size,
   the encoding, the certificate version, the issuer, the serial and the
   validity. If a mechanism ever exists that can assert "this value is base64 of
   a DER RSA key", this case is its first consumer.

### F38 - the model this cut followed, and the way it did not

F38 is why the harness change here is a **ratchet and not a mechanism**. Its
lesson - built on a count that was wrong by nine, and only saved by two
consumers being real - reads directly onto shape 2: a decoder for JKS and BCFKS
would have had exactly two consumers, and both of them assert a key that
`read-after-upload` and `generate` already reach by a shorter route.

What was built instead has **every committed golden as a consumer on the day it
lands** - 900 of them after the rebase onto the events family - costs one file
read per golden inside a test that already reads them all, and refuses the file
F161 was about to add. F38's three surviving grounds are each answered where
they can fail: the guard's own inertness is `TestGoldenTextGuardCanFail`, the
walk's is `TestGoldenSweepCanFail`, and the recorder and the verifier share one
predicate so it cannot exist on one side only.

No change to F38 itself.

### F113 - unchanged, and now enforced one layer down

F113's closing rule is the load-bearing precedent here: *a page carrying a
per-request value cannot be `Recorded`, whatever else is true of it, because
`Recorded` is a promise the recorder has to be able to keep.* A keystore is a
per-request value all the way down, so the two binary cases could not be
`Recorded` even before this cut - and nothing said so. `RefuseNonTextBody` is
that rule made checkable over bytes.

No change to F113. It should gain a cross-reference to the new bullet, because
the next person to meet an unrecordable response will find one entry or the
other and should find both.

### F72 - unchanged, and deliberately not extended

F72 decided that a `Pending` case **may** carry a golden, declared in
`parkedGoldens`. The three `Pending` cases added here carry **none**, and that is
the right side of F72's line rather than an exception to it: a parked golden buys
a reader the measured bytes without a container, and a keystore's bytes are not
something a reader can read. What they carry instead is the measurement in prose,
in the case's own comment - the format set, the header set, the guard, the
lengths - which is what a parked golden would have been for.

`parkedGoldens` stays empty and `TestNoPendingGoldenIsCompared` stays deleted.

### F107 - untouched

Named in the brief and out of this branch's files: the seven masks it lists are
in `catalog_oidc_pending.go`. No mask in this cut is over a value that does not
move; `TestNoMaskIsInertOnItsGolden` passes on the two `Volatile` paths added.

### F60 - one new data point, no change

F60 records that a `saml` client created through `POST /clients` gets twelve
`saml.*` attributes in Keycloak and none in Gloak. **Its count of twelve is
confirmed**, counted from the list rather than incremented: nine spelled with
dots (`allow.ecp.flow`, `artifact.binding.identifier`, `authnstatement`,
`client.signature`, `force.post.binding`, `server.signature`,
`signature.algorithm`, `signing.certificate`, `signing.private.key`) and three
with underscores (`saml_force_name_id_format`, `saml_name_id_format`,
`saml_signature_canonicalization_method`). The client's whole attribute map is
fourteen keys; the other two are `client.secret.creation.time` and
`realm_client`, which every client has.

Worth the recount because the first draft of this section said "fourteen", from
reading the map's length instead of the list. That is the mistake this project
keeps paying for, caught here by counting.

Two of the twelve - `saml.signing.private.key` and `saml.signing.certificate` -
are exactly the pair this chapter reads and writes, under the `{attr}` prefix
`saml.signing`. So `GET .../certificates/saml.signing` on a Gloak `saml` client
answers `{}` where Keycloak answers a key pair, measured on both. That is F60's
symptom seen from this chapter, not a new finding, and it is why nothing here
bootstraps a saml client.

## 4. Parity before and after

```
before  admin/client-attribute-certificate    0 of 7
        total                               483 of 541

after   admin/client-attribute-certificate    4 of 7
        total                               487 of 541
```

**The base moved under this branch**, so the totals above are not the ones first
reported. This cut was written against 477 and rebased onto the events family
(#87), which had already taken the total to 483. This branch's own contribution
is unchanged and is the number to read: **+4 operations, all of them in the
certificate chapter**, 0 of 7 to 4 of 7. The rebase was verified line by line -
this branch's exclusive files are byte-identical across it, and the two shared
files (`catalog_admin.go`, `fixture.go`) gained main's lines with **zero
deletions**, so no line of either stream was merged into a union.

Four operations, nine cases, nine goldens, six of them carrying **no mask at
all**:

| case | asserts | masks |
|---|---|---|
| `read-empty` | `{}`, three headers | none |
| `read-unknown-attr` | `{}` for a prefix nothing wrote | none |
| `generate` | status, headers, two key names in order | `Volatile` x2 |
| `upload-certificate` | the uploaded certificate, byte for byte | none |
| `read-after-upload` | the same bytes, and the private key **gone** | none |
| `identity-provider-upload-certificate` | the public key derived from it | none |
| `identity-provider-upload-certificate-forbidden` | the 403 a `manage-clients` caller gets | none |
| `upload-no-format` | `keystoreFormat cannot be null` | none |
| `read-unknown-client` | `Could not find client` | none |

The three left `Pending` are `download`, `generate-and-download` and `upload`.

**No existing golden moved.** `git status` after `make record`'s selector showed
one new directory and nothing else, checked after both recordings.

### The mutation pass

Nine mutations, one per claim, each confirmed to fail the *named* test, each
reverted and the revert checked. The harness reads `go test`'s own exit code and
runs `go vet` first, so a mutation that does not compile is reported
`BUILD-FAILED` and never counted as killed - which happened once, on M1's first
attempt, exactly as intended.

```
M1  RefuseNonTextBody made inert           killed  TestGoldenTextGuardCanFail
M2  upload-certificate keeps the key       killed  TestConformance/.../read-after-upload
M3  the read drops Cache-Control           killed  TestConformance/.../read-empty
M4  the two 400s swapped                   killed  TestCertificateUploadRefusalOrder
M5  key size 4096 -> 2048                  killed  TestGeneratedCertificateMatchesKeycloaksShape
M6  the notBefore backdate removed         killed  TestGeneratedCertificateMatchesKeycloaksShape
M7  idp upload guarded by manage-clients   killed  TestConformance/.../idp-upload-certificate-forbidden
M8  the multipart closing boundary dropped killed  TestCertificateBoundaryIsNotInTheBody
M9  the sweep walks nothing                killed  TestGoldenSweepCanFail
M10 the UTF-8 half made unreachable        killed  TestGoldenTextGuardCanFail  (was SURVIVED)
M11 the control-byte half unreachable      killed  TestGoldenTextGuardCanFail  (was SURVIVED)
M12 the UTF-8-only fixtures removed        killed  TestGoldenTextGuardCanFail
```

### M1 was the ratchet ground and it was only half-covered

**The nine-of-nine above was wrong, and it was wrong about the one mutation this
cut called its headline.** M1 replaced the whole of `RefuseNonTextBody` with a
check that cannot vary, and `TestGoldenTextGuardCanFail` caught it. That was
read as "the guard is pinned". It is two rules - not valid UTF-8, **or** a
control byte - and M1 disabled both at once, so killing it says only that
*something* refuses a keystore.

Disable either half on its own and the branch as first pushed stayed green:

```
M10  if !utf8.Valid(body) && false          SURVIVED, ./internal/conformance/ ok
M11  the control-byte loop short-circuited  SURVIVED, ./internal/conformance/ ok
```

M10 is the coordinator's, on review of #88. **M11 is the mirror and it was not
in the report** - so the branch had two survivors of this shape, not one, and
both were in the ratchet's own ground.

The cause is the fixtures, and the comment above them claimed the opposite:

> The JKS magic is not valid UTF-8; the PKCS12 header is valid UTF-8 and carries
> NUL, so the two halves of the rule are each exercised by a body this
> repository actually declined to record.

Measured, byte by byte:

```
                                       validUTF8   hasControlByte
JKS     fe ed fe ed 00 00 00 02          false         true
PKCS12  30 80 02 01 03 30 80 06          false         true
```

**Both halves of that sentence about PKCS12 are false.** `0x80` is a
continuation byte with no lead byte in front of it, so the header is *not* valid
UTF-8; and there is no `0x00` anywhere in those eight bytes - the control bytes
are `0x02`, `0x01`, `0x03` and `0x06`. Both fixtures trip both halves, and since
the UTF-8 check runs first and returns, neither half could be reached alone.

This is **the tenth survivor of one shape in this project and the second this
round**: a test whose input supplies both conditions a two-part rule needs, so
it cannot say which part did the work. The rule the events cut wrote down about
a handler's state applies to a test's fixtures unchanged.

**The fix is not a third fixture, it is a checked claim.** `refusedBodies` is
now a table where every row *declares* which half its bytes trip; the test
verifies the declaration against `utf8.Valid` and against the byte range before
it asks the guard anything, and then asserts that **at least one row trips each
half alone**. The real keystore magics stay - they are what this repository
actually declined to record - labelled as tripping both and therefore as unable
to separate them. Two synthetic rows carry each half:

```
0xff, and 0xc3 0x28   invalid UTF-8, every byte >= 0x20 and not 0x7f
"a\x00b", "a\x7fb"    plain ASCII, so valid UTF-8, one control byte each
```

M10 and M11 are now killed by exactly the rows that trip their half - and the
keystore rows fail in neither, which is the point. M12 removes the two
UTF-8-only rows and confirms the coverage assertion itself fires, with the
message "no refused body is invalid UTF-8 *and nothing else*".

**The mutation harness had the same disease and was fixed with it.** Its first
run of M10 printed `KILLED (go test exit 0)` - a contradiction it could not
notice, because `<named>` was interpolated into the grep unparenthesised, so
`Guard|Sweep|Text` became `^ *--- FAIL: .*Guard` OR `Sweep` OR `Text` and
matched any line holding the word "Text". It now checks the exit code **first**,
so a zero exit can never be reported as a kill, and wraps the alternation. A
harness that can report a kill on a passing run is the tool version of the bug
it was built to find.

### What M1 does still establish

With the guard inert, `TestEveryGoldenBodyIsText` **passed** - because every
committed body is already text - and only the control caught it. That part of
the original report holds: a sweep over a clean tree cannot tell itself apart
from a predicate that returns nil, which is why the controls exist. What it does
not establish is that either half of the predicate is reachable, and saying so
was the error.

### Four of this cut's own tests were survivors before they were fixed

Two were found here by asking what mutation would kill them; **two were found on
review, after this branch was pushed and CI was green**, and those two are the
ones worth reading - they were in the ratchet's own ground and are written up in
full under M10 and M11 above. All four are the shape the
brief warns about - one thing playing two roles, and a test that reads a
fraction of what it names.

- `read-after-upload`'s fixture uploaded onto a client that had **never had a
  private key**, so it could not tell a handler that deletes the key from one
  that does not. Both answer `{certificate}`. The fixture now generates first,
  and M2 is what proves it.
- `TestGeneratedPrivateKeyIsPKCS1` called `x509.MarshalPKCS1PrivateKey` and then
  checked the result was PKCS#1. That asserts something about the standard
  library and nothing about this package. It now goes through `storedKeyPair`,
  which is the code path the handler uses.
- `TestGoldenTextGuardCanFail` used two keystore magics that each trip **both**
  halves of a two-part rule, so neither half was reachable alone and both could
  be deleted with the package still `ok`. Found on review. See M10 and M11.
- The mutation harness itself reported `KILLED (go test exit 0)`. Found while
  reproducing M10. See M10.

**The lesson is not "add a fixture".** Three of the four are a test whose input
satisfies more conditions than the claim needs, and the only reliable way to
catch that is to make the test **declare what each input exercises** and check
the declaration - which is what `refusedBodies` now does, and what a prose
comment above two byte slices could never do. The comment there was not merely
unchecked; it was **false in both of its factual claims**, and it read as
coverage for a fortnight of nobody noticing because there was nothing for it to
disagree with.

### What is not covered

`RefuseNonTextBody`'s **call site in the recorder** is behind the `docker` build
tag, so nothing in `go test ./...` runs it. The predicate is unit-tested and the
tree-wide sweep is the guard that runs in CI; the four lines that call it in
`record_test.go` are checked by `go vet -tags docker` and by nothing else. That
is the same position `recordedHeaders`' own refusal is in, and it is why the
logic lives in `golden.go` rather than beside the caller.
