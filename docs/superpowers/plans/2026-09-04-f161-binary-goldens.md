# F161: what a golden can assert about a body that is not text

F161 files `client-attribute-certificate` as a harness question before it is
seven handlers:

> All seven operations are unserved. Two answer a **binary JKS or PKCS12
> keystore** and three take **`multipart/form-data`**, and **no golden in this
> repository holds a non-text body**. A generated keystore is also different
> bytes on every request, so even a byte-holding golden could assert nothing but
> a length.

Everything below was measured against a live 26.7.1 on `localhost:8172`
2026-09-05, never written from memory. The container was `kc-cert`, started for
this cut and removed after it.

The seven operations were computed from `paths` in
`internal/conformance/testdata/openapi/keycloak-26.7.1.json`, filtered on the
`Client Attribute Certificate` tag, rather than taken from the entry:

```
GET  .../clients/{uuid}/certificates/{attr}
POST .../clients/{uuid}/certificates/{attr}/generate
POST .../clients/{uuid}/certificates/{attr}/download
POST .../clients/{uuid}/certificates/{attr}/generate-and-download
POST .../clients/{uuid}/certificates/{attr}/upload
POST .../clients/{uuid}/certificates/{attr}/upload-certificate
POST /admin/realms/{realm}/identity-provider/upload-certificate
```

The count of seven is right. The seventh is not under `/clients` at all.

## 1. What the seven actually answer, measured

### 1.1 Five of the seven answer `application/json`

| operation | status | `Content-Type` | `Cache-Control` | five security headers |
|---|---|---|---|---|
| `GET .../certificates/{attr}` | 200 | `application/json;charset=UTF-8` | `no-cache` | all five |
| `POST .../generate` | 200 | `application/json;charset=UTF-8` | `no-cache` | all five |
| `POST .../download` | 200 | `application/octet-stream` | `no-cache` | **four**, no `X-Frame-Options` |
| `POST .../generate-and-download` | 200 | `application/octet-stream` | `no-cache` | **four**, no `X-Frame-Options` |
| `POST .../upload` | 200 | `application/json;charset=UTF-8` | **absent** | all five |
| `POST .../upload-certificate` | 200 | `application/json;charset=UTF-8` | **absent** | all five |
| `POST /identity-provider/upload-certificate` | 200 | `application/json;charset=UTF-8` | **absent** | all five |

**F161's framing is right on the counts and wrong on what follows from them.**
Two operations answer a binary body. The three that *take* `multipart/form-data`
**answer JSON**, and a golden records the response. So the multipart three were
never blocked by the binary question at all.

Neither binary response carries a `Content-Disposition`. A "download" that names
no filename is Keycloak's, and reproducing it means sending none.

### 1.2 The three multipart operations are byte-deterministic

Every one of them echoes what was uploaded, decoded and re-encoded:

- `upload` takes a JKS **or** PKCS12 keystore and answers
  `{"privateKey":...,"certificate":...}` read out of it.
- `upload-certificate` takes a `Certificate PEM` and answers
  `{"certificate":...}` - the same base64 DER that was in the PEM.
- `identity-provider/upload-certificate` takes a `Certificate PEM` and answers
  `{"publicKey":...,"certificate":...}`, the public key derived from it.

The same file uploaded twice gave byte-identical responses on all three,
measured. **Given a constant file in the catalogue, these carry byte-exact
goldens with no mask at all** - not one `Volatile` path between them.

The `keystoreFormat` part is checked and its failures are Keycloak's own:

```
POST .../upload             keystoreFormat=JKS               200
                            keystoreFormat=PKCS12            200 (with a real PKCS12)
                            keystoreFormat=Certificate PEM   500 unknown_error
                            keystoreFormat=bogus             400 {"error":"error loading keystore"}
POST .../upload-certificate keystoreFormat=Certificate PEM   200
                            keystoreFormat=anything else      500 unknown_error
either, with no body at all                                  400 {"error":"keystoreFormat cannot be null"}
```

A body that is not multipart at all - `application/json`, `{}` - answers the
same `keystoreFormat cannot be null` 400 as no body.

### 1.3 The two binary operations, and the entry's claim about the length

Twelve requests per format, against one client:

```
                        distinct lengths           distinct bodies
download JKS            4413                       12 of 12
download PKCS12         4869                       12 of 12
download BCFKS          4948                       12 of 12
generate-and-download JKS     4412 4413 4414 4415  12 of 12
generate-and-download PKCS12  4869 4877            12 of 12
generate-and-download BCFKS   4947 4948 4949       12 of 12
```

The bytes move on every single request, for both operations and all three
formats: the keystore is re-encrypted under a fresh salt each time even when the
key inside it has not changed.

**`generate-and-download`'s length moves too, so F161's "could assert nothing
but a length" is measured wrong for it.** That is the second counted claim in
this entry to be wrong when re-counted, after the multipart three.

`download`'s length looked stable, and it is stable only while the key is fixed.
Regenerate the key first - which is exactly what a fixture does on every
recording - and it moves as well:

```
generate, then download JKS, ten times:     4412 4413 4414 4412 4413 4413 4412 4413 4413 4415
generate, then download PKCS12, ten times:  4869 x9, 4877
```

So **neither binary operation can hold a stable length either**, once the golden
is recorded the way the harness records goldens.

For contrast, `POST .../generate`'s JSON body held 4770 bytes across ten fresh
keys. That is not a contract worth leaning on - base64 quantises a DER length
that varies by one or two bytes into the same character count - and nothing
below depends on it.

### 1.4 The guards, swept one role at a time with a control

`POST /admin/realms/master/clients` in the last column is a role known to
differ, so a sweep answering the same code for every input would be visible:

```
role                      GET  generate  download  gen-and-dl  upload-cert  idp-upload-cert  CONTROL
view-clients              200  403       200       403         403          403              403
manage-clients            200  200       200       200         200          403              201
view-realm                403  403       -         -           403          403              403
manage-realm              403  403       -         -           403          403              403
query-clients             403  403       -         -           403          403              403
view-identity-providers   403  403       -         -           403          403              403
manage-identity-providers 403  403       -         -           403          200              403
```

Three findings in that table:

1. **`POST .../download` takes the *view* role.** A POST opened by
   `view-clients` is a shape this project has not met before, and it is not the
   family's rule: its sibling `generate-and-download` needs `manage-clients`.
   The verb does not decide; whether the operation writes does.
2. **`POST /identity-provider/upload-certificate` is authorised out of the
   identity-provider role set**, not the client one, although its tag is
   `Client Attribute Certificate`. `manage-clients` is refused it and
   `manage-identity-providers` opens it. That is the fourth time the
   description's tag has failed to predict the guard.
3. It needs the **manage** role where six sibling reads under
   `/identity-provider/instances/{alias}` take the view role - the same shape
   AGENTS.md already records for `reload-keys`.

### 1.5 The rest of the measured surface

- **`{attr}` is a free-form prefix**, not an enum. `my.prefix` works and stores
  `my.prefix.private.key` and `my.prefix.certificate`.
- **The state is client attributes and nothing else.** After a generate on
  `jwt.credential` the client representation carries
  `jwt.credential.private.key` and `jwt.credential.certificate`. **No migration
  is needed** - Gloak already stores a client's `attributes`.
- **An `{attr}` naming nothing is `200 {}`, not a 404.** So is `jwt.credential`
  on a client that has never generated one. `GET .../certificates/bogus.attr`
  answered `{}` on a client that had a `jwt.credential` key.
- An unknown client uuid is `404 {"error":"Could not find client"}`; an unknown
  realm is `404 {"error":"Realm not found."}`; no token is
  `401 {"error":"HTTP 401 Unauthorized"}`. All three are spellings this
  repository already serves.
- `GET` answers `{"certificate":...}` alone on a client that has a certificate
  and no private key, and `{"privateKey":...,"certificate":...}` when it has
  both. Absent rather than empty, the rule AGENTS.md already records for four
  token claims.

### 1.6 Two things AGENTS.md's own bullets should hear about

**`application/octet-stream` carries four of the five security headers,
omitting `X-Frame-Options`.** Measured on both binary operations, against five
`application/json` 200s in the same family that carry all five. AGENTS.md's
media-type table has three rows - `text/plain`, `text/html`,
`application/json` - and this is a fourth media type and the first response
measured to carry *some* of the five. It is also the first **non-`OPTIONS`**
response to omit exactly `X-Frame-Options`, which is the shape exception (4)
describes and calls unmeasured.

It is reported as two responses in one family, not as a rule. That bullet has
been wrong five times and its own instruction is to prefer "not explained" to
the next explanation. **No golden in this cut records it**, because the two
operations that produce it are the two that cannot carry one - which is worth
saying plainly, since it means this measurement is in the same position as
exception (4)'s.

**`Cache-Control` splits four to three inside one resource family.** `GET`,
`generate`, `download` and `generate-and-download` send `no-cache`; the three
uploads send none. AGENTS.md already says "pinned per endpoint" and that this is
the only part of the bullet to survive every generalisation. This is a fourth
family agreeing with it, and the tightest one yet: seven operations on one
resource, one attribute prefix, two answers.

## 2. Which shape the binary-golden question takes, and what the other three lose

### The harness needs no mechanism for multipart, and already had none to need

`Request.Body []byte` plus `Request.Headers["Content-Type"]` sends a
`multipart/form-data` request today. `buildRequest` writes `Headers` after the
form's own `Content-Type`, so the boundary spelling wins; `Expand` passes
`Body` through `strings.ReplaceAll` on `{{name}}`, which is byte-safe for any
payload that does not contain that spelling.

So one third of F161's premise dissolves on reading `case.go`: a golden holds a
**response**, the three multipart operations' responses are JSON, and their
requests were expressible all along.

### Shape 1 - a golden holds the bytes - is refused by measurement

Section 1.3 is the refusal. The body differs on every request; the length
differs too once the key is fresh, which every recording makes it. A golden
holding the bytes asserts **nothing**: it fails on the next run of the very
recorder that wrote it.

**F113's rule already covers this and was written for a different reason.** "A
page carrying a per-request value cannot be `Recorded`, whatever else is true of
it, because `Recorded` is a promise the recorder has to be able to keep." A
keystore is a per-request value all the way down.

There is a second cost that does not need the measurement: a binary golden is
not readable in the diff this project asks people to read carefully before
committing a `make record`. That is not decorative here - `make record` moving
files in chapters a cut never touched has already happened once.

### Shape 2 - a golden holds a decoded projection - buys an echo and costs a parser

It is the interesting one, and it is worth stating at its strongest before
declining it. A fixture that uploads a **constant** keystore fixes the key, and
a projection could then assert the key material exactly rather than "it is 2048
bits" - the real-assertion bar the brief sets.

It is declined on three grounds, in order of weight.

1. **What it would assert is already asserted, one encoding away.** The key and
   certificate inside `download`'s keystore are byte for byte what
   `GET .../certificates/{attr}` answers as base64 DER, and what
   `POST .../upload` answers for the same client. Both of those carry ordinary
   byte-exact JSON goldens in this cut. The projection's genuinely new content
   is the container envelope - the format, the alias, the chain length - of
   which format and alias are echoes of the request body. A mechanism whose
   assertion is a re-encoding of one two files away is F38's "machinery with no
   consumer" wearing a consumer's coat.
2. **Go cannot read two of the three formats.** `golang.org/x/crypto/pkcs12`
   decodes only the legacy PBE algorithms; JKS has no reader in the standard
   library or in `x/`; BCFKS has none in Go at all. The harness would take a
   dependency, or a hand-written JKS decryptor, to compare against a value the
   catalogue holds as a constant.
3. **It is a new kind of golden.** `FormatGolden`/`ParseGolden` would have to
   learn a second body encoding, and `normalisePasses` a pass that is not a
   substitution but a decode - with the "one pass, both sides, one call site"
   invariant to keep. Every existing golden is `# request` / status / headers /
   blank line / bytes, and that uniformity is what makes the tree greppable:
   AGENTS.md computes its media-type table by reading the goldens.

**What shape 2 loses by not being built:** the assertion that `download`
produced a *well-formed keystore* rather than any 4413 bytes. That is a real
loss and it is why the two operations are not served at all in this cut rather
than served behind a weak golden. An implementation nothing compares is worse
than an absence, because the absence is counted.

### Shape 4 - something better - was looked for and is not there

Three were tried against the measurements and all fail:

- Make the response deterministic by fixing the input. Refused: the salt is
  fresh per request even when the key is not (12 of 12 distinct with a fixed
  key).
- Pick a format that does not encrypt. Refused: the accepted set is exactly
  `[BCFKS, PKCS12, JKS]`, from the server's own 406 -
  `{"error":"Not supported keystore format. Supported keystore formats: [BCFKS, PKCS12, JKS]"}` -
  and all three encrypt.
- Assert the headers and skip the body. Refused: a golden's body is compared
  unconditionally, and a body field that is present and not compared is the mask
  that changes nothing, at whole-body scale.

### Shape 3 is taken, and the harness change is a ratchet rather than a mechanism

The two binary operations stay unserved and carry no golden. The other five are
taken normally, four of them in this cut.

**The harness change is the answer stated where it can fail.** F161 asks what a
golden over a binary body would assert. The answer is *nothing*, and an answer
nothing enforces is a paragraph the next cut will re-decide. So:

`TestEveryGoldenBodyIsText` reads every committed golden and requires its body
to be valid UTF-8 with no NUL byte. It runs over the whole tree rather than over
what a diff touched, the way `TestNoMaskIsInertOnItsGolden` does, and it refuses
the binary golden F161 was about to add.

**This is not machinery with no consumer.** It has 500-odd consumers on the day
it lands, it is the thing that makes the decision above survive, and it costs
one file read per golden in a test that already reads them all.

The headline mutation the brief specifies applies to it directly: point the
guard at something that cannot vary and confirm the harness stops refusing a
binary body. `TestGoldenTextGuardCanFail` is the standing control - the shape
`TestVolatilePrefixGuardCanFail` and `TestHTMLMaskVariesGuardCanFail` already
use in this package.

## 3. What gets built

Four of the seven operations, chosen because they are the ones whose goldens
assert something:

| operation | golden | masks |
|---|---|---|
| `GET .../certificates/{attr}` on a client with no key | `{}` | none |
| `GET .../certificates/{attr}` after a constant upload | the constant | none |
| `POST .../upload-certificate` with a constant PEM | the constant | none |
| `POST /identity-provider/upload-certificate` with the same PEM | derived from it | none |
| `POST .../generate` | two keys, both masked | `Volatile` x2 |

**`POST .../generate` is included and it is the weakest of the four.** Its two
values are minted per request and can only be `Volatile`, so its golden asserts
the status, every header, the two key names and their order, and that both are
present - and not the key size. That is the whole-`Location` retreat's shape and
it is named here rather than discovered later. It is taken anyway because the
alternative is an operation nothing compares at all, and because the key
material it will not assert is asserted byte for byte by the two cases beside
it, which read the same attributes back.

**`POST .../upload` is not taken**, and the reason is production code rather
than the harness: serving it means reading a JKS or a PKCS12 in Go, which is the
same missing parser shape 2 declined. It is filed, with the measurement that it
accepts both formats and answers 500 for the two PEM ones.

The constant certificate is generated once, checked in as a PEM constant in the
catalogue, and is the same bytes on both sides of every comparison.

### Files

- `internal/conformance/catalog_test.go` - the two new tests, appended.
- `internal/conformance/fixture.go` - fixtures inserted immediately after the
  `oidcCore` block, helpers before the last one.
- `internal/conformance/catalog_admin.go` - cases appended at the very end.
- `internal/conformance/testdata/golden/admin/client-attribute-certificate/*`.
- `internal/admin` - the certificate chapter's handlers only.
- No migration. Section 1.5 says why.

## 4. Order

1. Commit the plan.
2. `TestEveryGoldenBodyIsText` + `TestGoldenTextGuardCanFail`, green on the tree
   as it stands. Commit before anything a mutation pass will revert.
3. Handlers in `internal/admin`, with unit tests.
4. Fixtures, cases, `make record`, and a check that **no existing golden moved**.
5. Mutation pass, one mutation per claim, each confirmed to fail the *named*
   test and each reverted and the revert checked.
6. Handover, follow-ups, PR.
