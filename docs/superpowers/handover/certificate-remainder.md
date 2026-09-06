# The certificate chapter's last three operations

Measured against a live Keycloak 26.7.1 on `localhost:8181` on 2026-09-06,
container `kc-certs`, started for this cut and removed after it. Nothing below
is written from memory.

The chapter goes from **4 of 7 to 5 of 7**, and the two operations that do not
move it are **served**. That is the whole shape of the cut and it is stated
plainly in section 4.

## 1. Measurements

### 1.1 The three operations, verified against the vendored description

The list was computed by compiling the catalogue rather than grepping it. A
throwaway test in `internal/conformance` printed the description's operations
for the `Client Attribute Certificate` tag beside the catalogue's `Operation`
values read out of `Catalog`, so Go's compiler joined the concatenated string
literals. The tag holds seven; four carried an `Operation`; the three left were
`download`, `generate-and-download` and `upload`. **The control was a second tag
in the same run**, `Key`, which answered 1 - so the probe was not answering
seven to everything.

### 1.2 What `upload` needs from the file: the whole keystore, decrypted

**The brief's guess was that it might store only a certificate**, which would
have made a purpose-built extractor smaller than a reader. It is kept here as a
refuted guess rather than dropped, because it is the obvious one and the next
person will have it too: the operation is named "upload certificate and
eventually private key", its sibling `upload-certificate` really does store one
certificate, and nothing short of sending a keystore says otherwise. It is
refuted:

```
POST .../upload with a JKS Keycloak itself produced
  -> 200 {"privateKey": <the PKCS#1 base64 the generate had answered>,
          "certificate": <the DER base64 the generate had answered>}
```

Byte-identical to what `POST .../generate` had answered for the client the file
came from, and then written onto the target client - the `GET` beside it answers
the same two keys afterwards. The same is true of PKCS12 and of BCFKS.

### 1.3 The dependency question, and why the answer is no new dependency

**`golang.org/x/crypto` is already a direct dependency**, so `x/crypto/pkcs12`
was never a tenth. It was measured on the exact bytes the endpoint receives and
**it cannot read them**:

```
encoding/asn1 on the raw file: asn1: syntax error: indefinite length found (not DER)
pkcs12.Decode(storepw):        pkcs12: error reading P12 data: ... indefinite length found
pkcs12.ToPEM(storepw):         n=0, the same error
```

Keycloak writes its PKCS12 with BouncyCastle: the outer `SEQUENCE`, the `[0]`
and the content `OCTET STRING` all carry the indefinite length `0x80`, and the
content octets are a **constructed** OCTET STRING chunked at 1000 bytes.
`software.sslmate.com/src/go-pkcs12`, the alternative that would have been
argued for, reads DER through the same `encoding/asn1` and fails on the same
byte. So **a dependency does not close this gap**, and that is a measurement
rather than a preference.

What closes it is `internal/keystore/ber.go`, about 150 lines: collapse
indefinite lengths, join constructed OCTET STRINGs, and convert an
indefinite-length constructed context tag whose children are all primitive
OCTET STRINGs into the implicitly tagged string it is. That last rule is where
BER is genuinely ambiguous without a schema, and the indefinite length is what
resolves it - a writer that knew the length would have emitted a definite one,
which the normaliser leaves alone.

The alternative, for the record: two dependencies -
`github.com/pavlo-v-chernykh/keystore-go/v4` for JKS and
`software.sslmate.com/src/go-pkcs12` for PKCS12 - would have bought the JKS half
and **not** the PKCS12 half, because of the BER above.

### 1.4 The JKS format, reproduced and checked against the file rather than remembered

```
uint32   0xfeedfeed
uint32   version, 2
uint32   entry count
entry*   uint32 tag, UTF alias, int64 milliseconds
           tag 1: uint32 len, EncryptedPrivateKeyInfo, uint32 chain len,
                  then per certificate UTF type, uint32 len, DER
           tag 2: UTF type, uint32 len, DER
[20]byte SHA1(password ‖ "Mighty Aphrodite" ‖ everything above)
```

Every field was located by reading the downloaded file and printing its length,
so a wrong guess would have produced a nonsensical number rather than a
plausible answer. The store digest was **recomputed and matched**; the SunJCE
key protector's keystream was reproduced, its check digest **matched**, and the
PKCS#8 inside decoded to a PKCS#1 key byte-identical to what the API reports.
The controls failed as they must: the store password and a wrong password both
mismatched.

### 1.5 The two formats protect a key with different passwords

Measured on a store downloaded with `keyPassword=keypw, storePassword=storepw` -
two different values on purpose, because a probe using one for both cannot tell
these apart:

```
JKS      the key by keyPassword     the store MAC by storePassword
PKCS12   the key by storePassword   the MAC by storePassword; keyPassword unused
```

The PKCS12 half was confirmed twice: `openssl pkcs12 -passin pass:storepw` opens
the shrouded key bag, and the endpoint answers `{privateKey, certificate}` for a
**wrong** `keyPassword` and for an **absent** one alike. On a JKS a wrong or
absent key password degrades instead - 200 with `{certificate}` alone and the
key silently dropped.

### 1.6 The writer was verified against Keycloak itself

A keystore writer has no golden and no oracle in Go. It has one here: **hand
what Gloak writes to the live Keycloak's own `upload` endpoint.** With the
keystore Keycloak wrote as the control in the same run:

```
                                 result
Keycloak's own JKS               200, key and certificate match
Keycloak's own PKCS12            200, key and certificate match
Gloak's JKS                      200, key and certificate match
Gloak's PKCS12                   200, key and certificate match
Gloak's JKS,    wrong password   400 Password verification failed
Gloak's PKCS12, wrong password   400 PKCS12 key store mac invalid
```

Gloak's JKS is 4419 bytes where Keycloak's is 4419 bytes. The PKCS12 differs -
Gloak writes definite-length DER and encrypts the certificate bags with 3DES
where Keycloak writes BER and 40-bit RC2 - and **no golden holds either**, so
the difference is invisible to everything that compares and visible to nothing
that reads.

### 1.7 `download` and `generate-and-download`

```
request   application/json or */*; a Content-Type that is anything else, and an
          absent one, are 415 "The content-type header value did not match the
          value in @Consumes"
          `{`        400 invalid_request / Cannot parse the JSON
          `[]`, `"x"` 400 unknown_error  / Cannot parse the JSON
          empty      500 unknown_error / consult-the-log
fields    format          absent or null -> 500 unknown_error
          keyAlias        absent -> the client's clientId; empty -> the empty
                          string, and the store really holds it under that name;
                          equal to the realm's name -> 500, the entries collide
          keyPassword     required only when a private key is stored
          storePassword   always required
state     a client with no **certificate** is 404 {"error":"keypair not
          generated for client"}; a client holding a certificate and no key is
          served, and its entry is a trusted certificate rather than a key entry
headers   200, application/octet-stream, Cache-Control: no-cache, four security
          headers, **no X-Frame-Options**, **no Content-Disposition at all**
guard     download: view-clients OR manage-clients
          generate-and-download: manage-clients
```

Three things in there are worth reading twice.

**The 406's membership test folds case and everything after it does not.**
Fifteen spellings:

```
JKS, PKCS12, BCFKS                 200
jks, Jks, jKs, pkcs12, bcfks       500 unknown_error
bogus, BOGUS, "", " JKS", "JKS "   406
absent or null                     500 unknown_error
```

So a lower-case spelling of a real format passes the first check and dies on the
second, which is what makes `jks` and `bogus` two different answers. Nothing is
trimmed either. The first version of this handler had one case-sensitive
membership test and answered 406 for `jks`; the mutation pass named it M9.

**The `password-missing` description says `jks` whatever format was asked for**,
measured on all three, and its two spellings differ only in their last words -
`for jks download` and `for jks generation and download`. Keycloak's own defect,
reproduced.

**`generate-and-download` deletes the private key.** It mints a pair, gives the
whole of it away inside the keystore and keeps only the certificate: afterwards
the client's attributes hold `<attr>.certificate` and no `<attr>.private.key`.
That is the same deletion `upload-certificate` performs, from the other
direction, and an implementation that stored the pair would pass every other
case in this chapter.

### 1.8 `upload`'s refusals, and their order

Each pair was decided by a request wrong in exactly two ways, beside a control
wrong in one:

```
unknown client                     404 Could not find client
keystoreFormat absent              400 keystoreFormat cannot be null
no file part                       400 file cannot be empty
keyAlias absent                    500 unknown_error - before the store is read
Certificate PEM, Public Key PEM    500 unknown_error
a file that is not its format      400 error loading keystore
an unrecognised format, and `jks`  400 error loading keystore
JKS, wrong storePassword           400 Password verification failed
PKCS12, wrong storePassword        400 PKCS12 key store mac invalid
PKCS12, no storePassword           400 error loading keystore
JKS, no storePassword              200 - a JKS may have no integrity check
an alias the store does not hold   400 certificate-not-found
```

An unknown format is a **400 `error loading keystore`** here where the download
answers 406 and 500 - one tag, two families, three answers for an unrecognised
format.

**A PKCS12 file declared `JKS` is a 200**, answering `{certificate}` alone: the
JDK's JKS keystore is dual-format and reads a PKCS12, after which the key
password fails and the fallback keeps the certificate.

### 1.9 The keystore holds two entries, and the second is the realm's

The client's pair under the caller's alias, and **the realm's own certificate
under the realm's name** as a trusted certificate - `master` in master and
`certprobe` in a realm called `certprobe`, measured on both. A store holding
only the client's pair would be a keystore a client could use and not the one
Keycloak sends.

### 1.10 Two corrections to what was already written down

**The format list's order was wrong in the 2026-09-05 handover.** It recorded
`[BCFKS, PKCS12, JKS]`; it is `[PKCS12, JKS, BCFKS]`, ten requests on one
container and one more after a restart. It was prose that nothing compared,
which is exactly how it drifted, and inside a day. It is now in a golden -
`admin/client-attribute-certificate/download-unsupported-format`.

That is the **fourth prose count to drift in this project this fortnight**,
after the security-header tally, the `javamap` key-set count and the create
`Location` count. Putting it in a golden is the same fix that worked for the
header tally: the number stops living in a sentence somebody has to re-read and
starts living somewhere a run can disagree with it. Every observable value in a
handover is a value nothing compares, and this one had one day to prove it.

**`POST .../upload-certificate` with a file part that is present and empty
answers `200 {"certificate":""}`**, storing an empty string, where Gloak answers
`400 file cannot be empty`. That is an existing divergence on an operation this
cut did not set out to touch, found while measuring the difference between an
absent file part and an empty one - the two upload families answer it
differently, `.../upload` giving `error loading keystore`. It is **not fixed
here**: reproducing it needs `certificateRepresentation` to emit a *present and
empty* certificate, and every field of it is `omitempty` for four other measured
shapes. It is filed in section 3.

### 1.11 The guards, one role at a time, with a control known to differ

```
role             download  gen+dl  upload  GET .../certificates  POST /clients
view-clients        200      403     403          200                403
manage-clients      200      200     200          200                201
view-realm          403      403     403          403                403
manage-realm        403      403     403          403                403
query-clients       403      403     403          403                403
```

`download` is **the first POST in this API measured opened by a read role**, and
its own sibling is not. The verb does not decide; whether the operation writes
does, and `download` writes nothing - measured, the stored pair is unchanged
afterwards.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds them in. This branch does not
edit it.

### For the security-headers bullet, exception (2)

> **`application/octet-stream` carries four of the five, and a test can now fail
> on it.** F161 recorded this as measured with no golden able to hold it, which
> was true and left the rule uncheckable from the tree. The two operations that
> produce it are served as of 2026-09-06 and `internal/admin`'s
> `TestKeystoreDownloadHeaders` asserts the whole set - the status, the media
> type, `Cache-Control: no-cache`, the four headers present, and
> `X-Frame-Options` and `Content-Disposition` both absent.
>
> It is still not a golden and the difference matters: a package test compares
> against what this project believes, where a golden compares against a
> recording. The recording exists, in
> `docs/superpowers/handover/certificate-remainder.md`, and nothing re-checks it
> on a fresh container. That is strictly weaker than a golden and strictly
> stronger than the prose it replaces.

### For the not-found list

> A **thirty-sixth** spelling: `keypair not generated for client`, from
> `POST .../certificates/{attr}/download` on a client that has never generated
> one. It is decided by the **certificate** and not by the key - a client holding
> a certificate alone, which is what `upload-certificate` and
> `generate-and-download` both leave behind, is served. Pinned by
> `admin/client-attribute-certificate/download-no-keypair`.
>
> `POST .../certificates/{attr}/upload` adds none: an unknown client is
> `Could not find client`, already (1). What it does add is a **two-key error
> body outside the RFC 6749 shape** - `{"error":"certificate-not-found",
> "error_description":"Certificate or key with given alias not found in the
> keystore"}` - which is a code in `error` and prose in `error_description`, the
> ordinary way round, in a family whose every other refusal is the bare-message
> shape.

### For the four-error-shapes bullet

> Two spellings this API had not used, both from `POST .../upload` and both
> decided by a **field of the request** rather than by the endpoint:
> `Password verification failed` for a JKS whose store password is wrong and
> `PKCS12 key store mac invalid` for a PKCS12's. One operation, two messages,
> and a handler with one of them passes whichever case is written first. Pinned
> by `admin/client-attribute-certificate/upload-wrong-store-password` and its
> `-pkcs12-` sibling.

### For the "reads accept the manage role" bullet

> **A POST opened by a read role, and its own sibling is not.**
> `POST .../certificates/{attr}/download` takes `view-clients` **or**
> `manage-clients`; `POST .../certificates/{attr}/generate-and-download` takes
> `manage-clients` alone. Two operations on one path prefix, one verb, two guards
> - and what separates them is that `download` writes nothing, measured on the
> stored pair before and after. F161 recorded the pair; this cut confirms it with
> `upload` measured alongside, which takes the manage role.

### For the "Cannot parse the JSON" bullet

> **A third family measured agreeing with F163's syntax-against-binding
> reading.** On `POST .../certificates/{attr}/download`, `{` is
> `invalid_request` and `[]` and `"x"` are both `unknown_error`, all three at
> 400. `writeCannotParseJSON` splits on a leading `[` instead, which is right on
> `[]` and wrong on `"x"`, so this family writes its own predicate - a rule about
> a code four families produce should not be rewritten from a fifth, and neither
> should a fifth borrow it.

### A new bullet, for the two checks that disagree about case

> **One membership test folds case and the code behind it does not.** On the two
> certificate downloads, `format` is checked against `[PKCS12, JKS, BCFKS]`
> case-insensitively and used case-sensitively, so `bogus` is a 406 and `jks` is
> a **500** - and so are `pkcs12` and `bcfks`. Nothing is trimmed either, so
> `" JKS"` is a 406. Fifteen spellings were sent to establish it, because a
> single case-sensitive membership test answers 406 for every one of the
> unrecognised ones and is wrong on three.

### For the `Cache-Control` bullet

> The certificate family's four-to-three split is confirmed with the three
> operations F161 left: the two downloads send `no-cache`, `upload` sends none.
> Seven operations on one path prefix, two answers, unchanged since 2026-09-05.

## 3. Follow-up dispositions

### F161 - stays closed, and its remaining three entries are answered two and a half

F161's replacement entries were three. This cut answers the first outright, and
the second is answered in the only way it can be.

1. *"`POST .../upload` needs a keystore reader ... this is a dependency question
   and not a harness one."* **Answered, and the dependency question goes the
   other way.** `x/crypto/pkcs12` is already a direct dependency and cannot read
   Keycloak's own PKCS12, because Keycloak writes BER - measured, section 1.3.
   Every Go PKCS12 reader is built on `encoding/asn1`. What was written is
   `internal/keystore`: a JKS codec and a BER-to-DER normaliser in front of the
   decoder that was already here. **No new module.**
2. *"`download` and `generate-and-download` ... cannot be `Implemented` while
   `RefuseNonTextBody` stands. Reopening means building the decoded projection,
   and the bar for that is a consumer whose assertion is not a duplicate of a
   JSON sibling's."* **Not reopened, and now with the operations served rather
   than absent.** The case shape that would count them is written up in
   `docs/superpowers/plans/2026-09-06-certificate-remainder.md` section 2 and
   refused there: a golden holding the status and the headers and no body would
   move the meter by **two** on the strength of an assertion about no byte of
   either response, which is F46's whole-value mask one level worse. What was
   built instead is `TestKeystoreDownloadHeaders`, which costs forty lines, needs
   no harness change, cannot inflate the meter, and makes AGENTS.md's
   `application/octet-stream` rule checkable for the first time.
3. *"`generate`'s golden masks both of its two values."* Unchanged.

`RefuseNonTextBody` is untouched and neither download carries a golden.
`parkedGoldens` stays empty.

### F38 - the model this cut followed, twice

F38 is why `internal/keystore` holds a JKS codec and a BER normaliser and **not**
a BCFKS one. BCFKS's payload is AES-256-CCM keyed by PBKDF2-HMAC-SHA512 inside a
schema published nowhere but BouncyCastle's source, and Go has no CCM anywhere
in its standard distribution. Writing an AEAD by hand to reach a format whose
only consumers are two operations no golden can cover is machinery with no
consumer **and** a security risk; the honest move is to leave it out and say so.

It is also why no new `Case` field was added. F38's surviving grounds read
straight onto the body-less golden: it is still a mask per case, it still has to
survive `make record`, and it still risks asserting presence and nothing else -
except that at body scale there is not even a presence to assert.

What was built has consumers on the day it lands: `internal/keystore` serves
three operations and two conformance cases, and its BER normaliser is exercised
by `admin/client-attribute-certificate/upload-pkcs12` as well as by its own
tests.

No change to F38.

### F113 - unchanged, and the reason the two downloads are still `Pending`

F113's rule is the one that keeps them there: *a response carrying a per-request
value cannot be `Recorded`, whatever else is true of it.* A keystore is a
per-request value all the way down. What has changed is only that the operations
are now served, so their `Reason` reads "served, and uncounted" rather than
"not built".

That combination - **served, `Pending`, and honest** - is worth naming, because
it is new here. Every other `Pending` case in this repository is unbuilt. These
two are built, exercised by `internal/admin`'s tests, and counted by nothing,
and the `Reason` says which.

No change to F113.

### F72 - unchanged, and still not extended

The two `Pending` cases carry no golden. `parkedGoldens` stays empty and
`TestNoPendingGoldenIsCompared` stays deleted.

### F163 - one more family, and it agrees

The download's parse refusal splits syntax from binding, which is F163's
answer measured on a third family. Nothing shared was changed.

### F168 - followed

Both files this cut shares were appended to at the **end of the file**, not
after whatever happened to be last.

### A new entry: BCFKS is a deliberate divergence

> **Gloak serves two of the three keystore formats.** `download`,
> `generate-and-download` and `upload` answer JKS and PKCS12; `BCFKS` answers the
> 500 that `jks` answers, where Keycloak answers a keystore. The 406's body is
> **not** edited: it is a measured contract that lists BCFKS as supported, and a
> server that removed it would be wrong about Keycloak in a golden as well as in
> the handler.
>
> The reason is specific rather than a shrug. A BCFKS store is
> PBKDF2-HMAC-SHA512 at 51200 iterations over **AES-256-CCM**
> (`2.16.840.1.101.3.4.1.47`, 12-byte nonce, 8-byte ICV), wrapped in an
> `ObjectStore` schema published nowhere but BouncyCastle's source. Go's standard
> library and `x/crypto` have no CCM. Those identifiers were read off a real
> BCFKS the container produced, so whoever picks this up starts from a
> measurement.
>
> `TestBCFKSIsRefusedAndTheRefusalListsItAnyway` is where the divergence is
> stated so that closing it removes a test rather than being noticed by nobody.

### A new entry: `upload-certificate` stores an empty certificate and Gloak refuses one

> **`POST .../certificates/{attr}/upload-certificate` with a file part that is
> present and empty answers `200 {"certificate":""}`**, measured 2026-09-06, and
> stores the empty string. Gloak answers `400 file cannot be empty`. The two
> upload families disagree about this input - `.../upload` answers
> `400 error loading keystore` - so it is a per-endpoint rule and not one
> `certificateUpload` can share.
>
> It is filed rather than fixed because the fix is not one line:
> `certificateRepresentation` has `omitempty` on every field for four other
> measured shapes, and a body carrying a **present and empty** `certificate`
> needs one of them to stop being. The operation is `Implemented` and its golden
> is unaffected - the case sends a real certificate.

## 4. Parity before and after

```
before  admin/client-attribute-certificate    4 of 7
        total                               535 of 554

after   admin/client-attribute-certificate    5 of 7
        total                               536 of 554
```

**+1 counted, +3 served.** The arithmetic is the point of this section and it is
not a rounding error:

| operation | served | counted | why |
|---|---|---|---|
| `POST .../upload` | yes | **yes** | ordinary JSON, two byte-exact goldens, no mask |
| `POST .../download` | yes | **no** | the body is a keystore; no golden can hold one |
| `POST .../generate-and-download` | yes | **no** | the same, and its length moves too |

So **`download` and `generate-and-download` are served and uncounted**, and the
chapter reads 5 of 7 rather than 7 of 7. That is the honest number: the meter
counts operations with a measured contract in the tree, and those two have none
and can have none. Their contract is in `internal/admin`'s tests and in section
1.7 above.

Eight new goldens, six of them refusals, and **not one carries a mask**:

| case | asserts |
|---|---|
| `upload` | the pair inside a JKS, byte for byte |
| `upload-pkcs12` | the same pair out of a BER-encoded PKCS12 |
| `upload-unknown-alias` | `certificate-not-found`, the tag's first two-key body |
| `upload-wrong-store-password` | `Password verification failed` |
| `upload-pkcs12-wrong-store-password` | `PKCS12 key store mac invalid` |
| `download-unsupported-format` | the 406, and the format list the handover got wrong |
| `download-no-keypair` | `keypair not generated for client` |
| `download-wrong-media-type` | the 415, on a route whose neighbours accept no Content-Type |

`upload` and `upload-pkcs12` are **byte-identical** apart from the request they
were made with, which is the assertion rather than a coincidence: two formats,
two key-protection schemes, one answer.

**No existing golden moved.** The nine already in this chapter were re-recorded
in the same run and `git status` showed eight new files and nothing else.

### The mutation pass

Twenty mutations, one per claim, each confirmed to fail the **named** test, each
reverted with `git checkout --` and the revert checked with `git diff --quiet`.
The harness runs `go vet` first, so a mutation that does not compile is reported
`BUILD-FAILED` and never counted - which happened once, on M2's first attempt,
exactly as intended - and it reads `go test`'s **exit code before anything
else**, so a zero exit can never be reported as a kill.

```
M1  the Mighty Aphrodite phrase changed        killed  TestReadJKSMatchesWhatKeycloakReports
M2  the key check digest drops the password    killed  TestTheJKSPasswordsAreNotInterchangeable  (was SURVIVED)
M3  the PKCS12 derivation always uses id 1     killed  TestReadPKCS12MatchesWhatKeycloakReports
M4  the chunked-string join disabled           killed  TestReadPKCS12MatchesWhatKeycloakReports
M5  berEncode always uses the long form        killed  TestBERToDERLeavesDERAlone
M6  the PKCS12 writer emits one ContentInfo    killed  TestWritePKCS12RoundTrips
M7  download stores what it hands over         killed  TestDownloadLeavesTheStoredPairAlone
M8  generate-and-download keeps the key        killed  TestGenerateAndDownloadKeepsOnlyTheCertificate
M9  the format check becomes case-sensitive    killed  TestKeystoreDownloadRefusalOrder
M10 the key password is always required        killed  TestTheKeyPasswordIsRequiredOnlyWhenThereIsAKey
M11 the binary response keeps X-Frame-Options  killed  TestKeystoreDownloadHeaders
M12 the realm certificate is not bundled       killed  TestTheDownloadedKeystoreCarriesTheRealmCertificate
M13 download takes the manage role             killed  TestKeystoreGuards
M14 both formats spell a bad password alike    killed  TestKeystoreUploadRefusalOrder
M15 upload answers the first entry             killed  TestConformance
M16 upload unlocks a JKS with the store password killed TestKeystoreRoundTrip
M17 the JSON refusal loses its syntax split    killed  TestKeystoreDownloadRefusalOrder
M18 an absent Content-Type is accepted         killed  TestKeystoreDownloadRefusalOrder
M19 the chunked join loses its tag-class guard killed  TestBERToDERJoinsChunksOnlyUnderAContextTag  (was SURVIVED)
M20 the chunked join disabled outright         killed  TestBERToDERJoinsChunksOnlyUnderAContextTag
```

### M2 survived, and the reason is the shape this project keeps meeting

`TestTheJKSPasswordsAreNotInterchangeable` held three assertions and **all three
were refusals**: the key password must not open the store, the store password
must not open the key, a wrong password must not open the key. A key protector
that refused *every* password satisfies all three, and M2 - dropping the
password from the check digest - is exactly that. The branch was green.

It was killed only by `TestReadJKSMatchesWhatKeycloakReports`, which is a
different test with a different name, so the report would have read
`FAILED-ELSEWHERE` rather than `killed` had the harness not been asked for the
named test.

**The fix is a positive control, not another refusal.** The test now also
requires the key password to open the key, so it asserts both directions of a
two-direction rule. That is the eleventh survivor of this shape here: a test
whose inputs satisfy fewer conditions than the claim needs, or - as here - whose
assertions cover one direction of it.

### M19 survived too, and it is M2's shape with the corpus playing the part

**Found on review, after this branch was pushed and CI was green.** The
coordinator dropped the tag-class test from the chunked-string join in
`berToDER`:

```go
if indefinite && allOctetStrings {          // was: indefinite && tag&0xc0 == 0x80 && allOctetStrings
```

`./internal/keystore/` and `./internal/admin/` were both `ok`.

**The guard is load-bearing**, and it is stated at the line now. Without it the
rule reads "any indefinite constructed node whose children are all OCTET
STRINGs", so a BER `SEQUENCE OF OCTET STRING` - `30 80 04 .. 04 .. 00 00` -
collapses into `10 ..`, a primitive universal SEQUENCE, which is not a legal tag
and has lost both of its values. That shape is reachable rather than
hypothetical: a PKCS12 attribute's `attrValues SET OF ANY` around a `localKeyId`
is `31 { 04 .. }`, and a writer that streamed it would send it indefinite.
Keycloak's writer sends it **definite**, which is why every keystore in this
repository is silent on the question.

So this is M2's shape with a different thing playing the missing part. M2 was an
assertion set a wrong implementation could satisfy entirely - three refusals and
no positive control. M19 is an **input** set a wrong implementation can satisfy
entirely: the corpus is three real keystores and none of them contains the
discriminating shape. Neither is fixed by another keystore, and this one is not
fixable by one at all.

`TestBERToDERJoinsChunksOnlyUnderAContextTag` is therefore a hand-built byte
slice, and it carries the control the coordinator asked for: **a row the guard's
presence does not change**, so the test cannot be satisfied by an
implementation that joins nothing. The two rows were checked to do different
work rather than assumed to:

```
                                    SEQUENCE row   context-tag row (the control)
M19  the class guard dropped            FAIL            PASS
M20  the join branch disabled           PASS            FAIL
```

Each row is the sole killer of its own mutation, which is what says the test
pins the **guard** and not merely the rewrite. The two inputs are asserted to
differ in exactly one byte - the tag - so the pair cannot drift into two
unrelated cases, and the table declares per row whether the class test is what
decides it, in the spirit of F161's `refusedBodies`.

A third row pins the other half of the documented rule - a **definite** length
is left alone whatever its children are - and it is labelled as a control for a
different mutation rather than as coverage of this one.

**A process note worth keeping.** The first attempt at this fix was made with
the `ber.go` documentation edited and **not committed**, and the mutation
harness's `git checkout --` reverted it along with the mutation. Nothing was
lost that could not be retyped, but the brief's "commit before any edit a
mutation pass will revert" is not advice about tidiness: a harness that reverts
to HEAD will silently eat the work that explains why the mutation matters.

### What is not covered

- **Nothing in `go test ./...` compares either download's body**, and nothing
  can. `TestKeystoreDownloadHeaders` reads the headers and
  `TestTheDownloadedKeystoreCarriesTheRealmCertificate` reads the store back
  through this repository's own reader, which is self-consistency rather than
  conformance. The one real check on the writer was made by hand, once, against
  a live container, and is written up in section 1.6; **nothing re-runs it**.
  A `docker`-tagged test that posts Gloak's keystore to a reference container's
  `upload` would close that, and it is the obvious next thing here.
- **BCFKS is unserved** and the divergence is stated in section 3.
- **A PKCS12 whose MAC is SHA-256** - a modern `keytool`'s default - is
  `error loading keystore` here, because the decoder behind `ReadPKCS12` supports
  SHA-1 only and the key bags would be PBES2 besides. Keycloak reads one.
  Unmeasured beyond that: no probe sent a JDK-written keystore, so what Keycloak
  answers for one is not recorded either.
- **A PKCS12 whose key bag uses a password other than the store's** is not
  reachable through this reader. Keycloak's own writer never produces one, and
  no probe sent one.
- The upload's `keyAlias`-absent 500 and its `Certificate PEM` 500 are the same
  body, so no measurement here can say which check ran first.
- **The BER normaliser's corpus is three real keystores and one hand-built
  vector.** M19 is what showed the corpus alone cannot decide the tag-class
  question, and the same is true of everything else `berToDER` does that
  BouncyCastle's writer never produces: high-tag-number forms are refused
  outright, and a constructed OCTET STRING with a *definite* length is joined on
  a rule no measurement here exercises. Both are written down at the line; both
  are unprobed cells rather than pinned ones, and saying so is the point.
