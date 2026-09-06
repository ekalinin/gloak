# The certificate chapter's last three operations

`admin/client-attribute-certificate` is 4 of 7. This plan is for the other
three, verified against the vendored description before anything was designed:

```
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/download
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/generate-and-download
POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/upload
```

The list was computed by compiling the catalogue rather than by grepping it -
`Case.Operation` values are plain literals but `Request.Path` is built from
concatenated ones, and a regex that does not join them under-reports. A throwaway
test in `internal/conformance` printed the description's operations for the tag
beside the catalogue's `Operation` values read out of `Catalog`. The tag holds
**seven**; four carry an `Operation`; the three above carry none. The control was
a second tag in the same run, `Key`, which answered **1** - so the probe was not
answering seven to everything.

Everything below was measured against a live Keycloak 26.7.1 on `localhost:8181`
on 2026-09-06, container `kc-certs`, started for this cut and removed after it.
Nothing is written from memory.

## 1. What `upload` needs from the file it is given

**The whole keystore, the private key included, decrypted.** The hypothesis that
it might store only a certificate - which would have made a purpose-built
extractor smaller than a reader - is refuted directly:

```
POST .../upload, a JKS Keycloak itself produced
  -> 200 {"privateKey": <the PKCS#1 base64 the generate answered>,
          "certificate": <the DER base64 the generate answered>}
```

Both values came back **byte-identical to what `POST .../generate` had answered
for that client**, so the endpoint is decrypting the protected key out of the
store and re-encoding it. It then writes both onto the client: the `GET` beside
it answers the same two keys afterwards. The same is true for PKCS12 and for
BCFKS.

So there is no smaller job here. `upload` needs a reader.

### 1.1 What a reader costs, format by format

| format | how Keycloak protects it | what Go has |
|---|---|---|
| JKS | SunJCE `KeyProtector`, OID `1.3.6.1.4.1.42.2.17.1.1`; store MAC `SHA1(pw ‖ "Mighty Aphrodite" ‖ bytes)` | nothing |
| PKCS12 | `pbeWithSHAAnd3-KeyTripleDES-CBC` key bag, `pbeWithSHAAnd40BitRC2-CBC` cert bag, SHA-1 MAC, **BER with indefinite lengths** | `x/crypto/pkcs12`, already a direct dependency - and it **fails** |
| BCFKS | PBKDF2-HMAC-SHA512, 51200 iterations, **AES-256-CCM** (`2.16.840.1.101.3.4.1.47`), 12-byte nonce, 8-byte ICV | nothing, and no CCM anywhere in the standard distribution |

**The JKS format was reproduced before this plan was written**, which is what
lets it be costed rather than guessed. A parser written against the downloaded
file recomputed the store's `Mighty Aphrodite` SHA-1 digest and it **matched**;
the key protector's keystream was reproduced, its check digest **matched**, and
the PKCS#8 inside decoded to a PKCS#1 key whose base64 is byte-identical to what
the API reports. The controls failed as they should: the store password and a
wrong password both produced a mismatched digest. That is a measured algorithm,
not a remembered one, and it is roughly 250 lines of Go.

**The PKCS12 measurement is the one that decides the dependency question, and it
goes the opposite way to the obvious reading.** Keycloak writes its PKCS12 with
BouncyCastle: the outer `SEQUENCE`, the `[0]` and the `OCTET STRING`s are
**indefinite-length BER**, and the content octets are a *constructed* OCTET
STRING chunked at 1000 bytes. Measured with `x/crypto/pkcs12` - which is not a
tenth dependency, `golang.org/x/crypto` is already a direct one - on the exact
bytes the endpoint receives:

```
encoding/asn1 on the raw file: asn1: syntax error: indefinite length found (not DER)
pkcs12.Decode(storepw):        pkcs12: error reading P12 data: ... indefinite length found (not DER)
pkcs12.ToPEM(storepw):         n=0, same error
```

Every Go PKCS12 reader is built on `encoding/asn1`, so **a dependency does not
solve this**: the newer `software.sslmate.com/src/go-pkcs12` reads DER through
the same package and fails on the same byte. What closes the gap is a **BER to
DER normaliser** - collapse indefinite lengths, join constructed OCTET STRINGs -
in front of the decoder that is already here. That is about 120 lines and it is
the `internal/javamap` / `internal/httpx/yaml.go` shape exactly: a small
purpose-built thing that a general library does not sell.

So the answer to the dependency question is **no tenth dependency**, and the
reason is not taste. The one library that would have been worth arguing for
cannot read the bytes.

**BCFKS is out of this cut**, and the reason is specific rather than a shrug:
its payload is AES-256-CCM, a mode Go's standard library and `x/crypto` do not
implement, wrapped in an `ObjectStore` schema published nowhere but
BouncyCastle's source. Hand-rolling an AEAD to reach a format with no
conformance coverage is F38's "machinery with no consumer" carrying a security
risk as well. It is filed with the algorithm identifiers above so the next
person starts from the measurement.

### 1.2 The passwords are not symmetric, and one test would have missed it

Measured on a store downloaded with `keyPassword=keypw, storePassword=storepw` -
two different values on purpose, because a probe using one password for both
cannot tell these apart:

```
JKS      key protected by keyPassword     store MAC by storePassword
PKCS12   key protected by storePassword   MAC by storePassword; keyPassword unused
```

The PKCS12 half was confirmed twice over: `openssl pkcs12 -passin pass:storepw`
opens the shrouded key bag, and the endpoint answers `{privateKey, certificate}`
for a **wrong** `keyPassword` and for an **absent** one alike. On JKS a wrong or
absent `keyPassword` degrades instead - 200 with `{certificate}` alone, the key
silently dropped.

### 1.3 The refusals, measured

```
no keystoreFormat, or no body at all      400 {"error":"keystoreFormat cannot be null"}
a format, no file part                    400 {"error":"file cannot be empty"}
no keyAlias                               500 unknown_error
keyAlias naming nothing, or empty         400 {"error":"certificate-not-found",
                                               "error_description":"Certificate or key with given alias not found in the keystore"}
JKS,    wrong storePassword               400 {"error":"Password verification failed"}
PKCS12, wrong storePassword               400 {"error":"PKCS12 key store mac invalid"}
PKCS12, no storePassword                  400 {"error":"error loading keystore"}
JKS,    no storePassword                  200 - a JKS may have no integrity check
a file that is not the format it names    400 {"error":"error loading keystore"}
an unrecognised format, and `jks`         400 {"error":"error loading keystore"}
Certificate PEM or Public Key PEM         500 unknown_error
unknown client                            404 {"error":"Could not find client"}
```

Two spellings are new to this repository - `Password verification failed` and
`PKCS12 key store mac invalid` - and `certificate-not-found` is the family's
first two-key error body outside the RFC 6749 shape.

**A PKCS12 file declared `JKS` is a 200**, not an error, and it answers
`{certificate}` alone: the JDK's JKS keystore is dual-format and reads a PKCS12,
after which the key password fails and the fallback keeps the certificate. That
is a two-condition answer and it is why the format mismatch matrix was run over
every pair rather than down the diagonal.

## 2. What a case over a binary response could honestly assert

The stable half of a `download` response is real and it is not nothing:

```
200
Content-Type: application/octet-stream
Cache-Control: no-cache
Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Robots-Tag
no X-Frame-Options
no Content-Disposition
```

Confirmed on both binary operations, against five `application/json` responses
on the same resource in the same session that carry all five security headers.

### 2.1 The shape that would count them, and why it is not built

The harness could grow a `Case` field meaning *the body is not asserted*: the
recorder writes the status line and the headers and a placeholder where the body
goes, and `diff` skips the body comparison. `RefuseNonTextBody` would never see
the bytes, so the ratchet stands.

It is rejected, on the ground F46 already settled one level down. **Masking a
whole value asserts presence and nothing else**, and at body scale there is not
even a presence to assert: a handler answering `200 application/octet-stream`
with an empty body would pass, and so would one answering a JKS where PKCS12 was
asked for. That golden would move the meter by **two** on the strength of an
assertion about no byte of the response. AGENTS.md names `UnorderedKeys` as the
suite's one documented retreat from byte-exactness and says not to add a second
without writing down why; this would be a larger retreat than that one and the
reason for it would be the meter.

The `generate` case in this same chapter is already the weakest golden here -
both of its values masked - and it survives review because the key names, their
order and every header stay asserted. A body-less golden keeps none of that.

### 2.2 What is built instead, and what it costs

The stable half gets asserted where it can be: **`internal/admin`'s own tests**,
which is exactly how this chapter already compensates for `generate`'s masked
golden. A test serves each download through the handler and asserts the status,
the media type, `Cache-Control`, the four security headers, the absence of
`X-Frame-Options` and the absence of `Content-Disposition`.

What that costs is honest and worth stating: those assertions live in a package
test rather than in a golden, so **they are compared against what this project
believes rather than against a recording**. The recording exists - it is in
section 1 of this plan and in the case comments - and nothing re-checks it on a
new container. That is strictly weaker than a golden and strictly stronger than
the prose it replaces, which is what nothing was checking before.

It also buys something no golden could: AGENTS.md's rule that
`application/octet-stream` carries four of the five security headers is
currently marked *measured, no golden can hold one*. After this cut a test can
fail on it.

**So the two downloads are served and left uncounted.** That is the outcome, said
as an outcome: the chapter goes to 5 of 7, not 7 of 7, and the two operations
that move no number are the two whose response a golden cannot hold.

## 3. What the three operations do

### 3.1 `download`

Reads the pair off the client, packs it into a keystore, and hands it over. It
writes nothing - measured, the stored key is unchanged after a download.

```
request   application/json only; form-urlencoded and a missing Content-Type are
          415 {"error":"The content-type header value did not match the value in @Consumes"}
          a malformed body is 400 invalid_request "Cannot parse the JSON"
          an empty body is 500 unknown_error
fields    format          absent -> 500 unknown_error
                          unrecognised -> 406 {"error":"Not supported keystore format.
                             Supported keystore formats: [PKCS12, JKS, BCFKS]"}
                          case-sensitive: `jks` is a 500, not a 406
          keyAlias        absent -> the alias is the client's clientId
                          empty  -> the alias is the empty string, and the store holds it
                          equal to the realm's name -> 500, the entries collide
          keyPassword     required only when a private key is stored; 400
                          {"error":"password-missing","error_description":
                           "Need to specify a key password for jks download"}
          storePassword   always required; the same shape, "store password"
state     a client with no certificate at all is
          404 {"error":"keypair not generated for client"}
guard     view-clients OR manage-clients
```

The two `password-missing` descriptions say **`jks`** whatever format was asked
for - measured on all three. That is Keycloak's own defect and it is reproduced.

The keystore holds **two** entries, not one: the client's key with a
single-certificate chain under `keyAlias`, and **the realm's own certificate
under the realm's name** as a trusted certificate - `master` in master,
`certprobe` in a realm called `certprobe`, measured on both.

### 3.2 `generate-and-download`

Mints a fresh pair, hands the whole thing over, and **deletes the private key
from the client**, keeping only the new certificate. Measured twice: after it,
`GET .../certificates/{attr}` answers `{certificate}` alone and the client's
attributes hold `jwt.credential.certificate` and no `jwt.credential.private.key`.
It is the same deletion `upload-certificate` performs, from the other direction,
and an implementation that stored the pair would pass every other case here.

Both passwords are always required, because it always has a key to protect, and
their descriptions end `for jks generation and download`. It works on a client
that has never generated anything. Its guard is **`manage-clients`** where
`download` takes `view-clients` - so the verb does not decide, whether the
operation writes does.

### 3.3 `upload`

Section 1. `manage-clients`. Stores both values on the client and answers them.

## 4. The work

### Task 1 - `internal/keystore`

A new package, on the `internal/javamap` precedent, holding only what these
three operations need.

- `jks.go` - read and write. The layout, the `Mighty Aphrodite` store digest and
  the SunJCE key protector are each pinned by a test against **the real
  keystore Keycloak produced**, committed as testdata, whose expected key and
  certificate are the base64 the API answered for the same client.
- `ber.go` - the BER-to-DER normaliser, pinned by the same real PKCS12.
- `pkcs12.go` - read through `x/crypto/pkcs12` after normalising; write with the
  PKCS#12 KDF, `pbeWithSHAAnd3-KeyTripleDES-CBC` for the key bag and a plain
  `data` ContentInfo for the certificates, so that what Gloak writes is what
  Gloak can read back.
- No new module. `golang.org/x/crypto` is already required.

### Task 2 - `internal/admin`

`client_certificates.go` gains the three handlers and their measured refusals,
and `router.go` the three routes with the two different guards. No migration:
the whole chapter is client attributes, and `{attr}` is a free-form prefix.

**BCFKS is the one divergence**, and it is deliberate: Gloak answers the 500 it
answers for a lower-case format rather than pretending to a keystore it cannot
write, and rather than editing the 406's body, which is a measured contract
listing BCFKS. Filed as a follow-up naming AES-256-CCM.

### Task 3 - `internal/conformance`

Two `Implemented` cases for `upload`, one per format, each sending a keystore
Keycloak itself produced and each carrying a byte-exact golden with **no mask**;
plus the measured refusals. `download` and `generate-and-download` stay
`Pending` with the reason rewritten from "not built" to "built, and no golden
can hold its body".

### Task 4 - the mutation pass, the handover, the follow-up dispositions

One mutation per claim, a different mutation each time, each confirmed to fail
the **named** test, each reverted and the revert checked.
