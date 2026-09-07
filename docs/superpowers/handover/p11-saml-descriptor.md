# P11 first cut: the SAML surface enumerated, and the descriptor served

The `saml` chapter had no denominator. Its declared reason was *"no
machine-readable description; the SAML endpoints have not been enumerated by
hand"*, and that sentence had been true since the parity meter was built.

This cut removes it. The surface is enumerated against a live Keycloak 26.7.1 -
**72 request/response pairs over five route shapes** - and one behaviour of it is
served: `GET /realms/{realm}/protocol/saml/descriptor`, the one SAML response
that is a pure function of the realm and needs neither an assertion builder nor a
browser.

Everything else is measured and deliberately not served, and section 1.6 is why:
**the success path is reachable and one client attribute away**, which was found
while measuring something else and which changes what "serve the refusals" would
have meant.

## 1. Measurements

Every value below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on
2026-09-07. Where a header set is claimed present or absent, the bytes were read
off a socket rather than through `curl`, following AGENTS.md's rule that a probe
of an absence measures the probe.

### 1.1 The surface is five route shapes, and Keycloak's own 404s find them

There is no document to enumerate from, so the enumeration needs a discriminator.
Keycloak supplies one, and this repository already records it: **an unmatched
path answers `{"error":"Unable to find matching target resource method"}` with
none of the five security headers, and a path the router knows answers
`{"error":"HTTP 404 Not Found"}` with all five.**

Verified in both directions on the same container before it was used:

```
GET /nosuchtoplevel                          404  Unable to find matching…  0 of 5
GET /realms/master/nosuchthing               404  HTTP 404 Not Found        5 of 5
GET /realms/master/protocol/saml/nosuchsub   404  HTTP 404 Not Found        5 of 5
```

Sweeping candidate paths against that gives five route shapes and no more.
`/protocol/saml/metadata`, `/x509`, `/logout` and `/artifact` were all tried and
all answer the second body, i.e. the router reached the SAML resource and found
nothing to run:

```
/realms/{realm}/protocol/saml                  the SSO and SLO bindings
/realms/{realm}/protocol/saml/descriptor       the IdP metadata
/realms/{realm}/protocol/saml/resolve          artifact resolution
/realms/{realm}/protocol/saml/clients          (no segment - generic 404)
/realms/{realm}/protocol/saml/clients/{name}   IdP-initiated SSO
```

### 1.2 The verb sweep: 35 cells, and 22 of them are the fallback family

|                        | GET             | POST            | PUT | DELETE | PATCH | HEAD        | OPTIONS   |
|------------------------|-----------------|-----------------|-----|--------|-------|-------------|-----------|
| `/saml`                | 400 page        | 400 page        | 405 | 405    | 405   | 400, no body| 200 Allow |
| `/saml/descriptor`     | **200 XML**     | 404 generic     | 405 | 405    | 405   | 200, no body| 200 Allow |
| `/saml/resolve`        | 404 generic     | 500 / 200       | 405 | 405    | 405   | **405**     | 200 Allow |
| `/saml/clients`        | 404 generic     | 404 generic     | 405 | 405    | 405   | **405**     | 200 Allow |
| `/saml/clients/{name}` | 400 page        | 404 generic     | 405 | 405    | 405   | 400, no body| 200 Allow |

Seventeen cells are `405 {"error":"HTTP 405 Method Not Allowed"}` and five are
`404 {"error":"HTTP 404 Not Found"}`. **Those 22 are not counted in this
chapter's denominator**: `http/fallback` holds two cases that count them once for
the whole API, and counting them per path would report two behaviours twenty-two
times. Thirteen cells are left, and they are the ones the catalogue holds.

Two cells in that table are worth naming because they break the row they are in.
`HEAD` is a 405 on `/resolve` and on `/clients` and a real answer on the other
three - which is AGENTS.md's "HEAD is 200 on `/auth` and 404 on
`/login-actions/authenticate`" met a second time, on a family whose five paths
are one resource. And **`OPTIONS` answers the identical `Allow: HEAD, POST, GET,
OPTIONS` on all four real paths**, so the header describes the parent resource
and not the path: `/descriptor` advertises `POST` and answers it 404, `/resolve`
advertises `GET` and answers it 404. Anybody reading `Allow` as a statement about
the path it was asked on gets both wrong.

### 1.3 The count: 72 pairs

```
 35   five route shapes x seven verbs
 12   further paths: two trailing slashes, a deeper path, four invented
       sub-paths, two unknown realms, two unknown protocols, saml-ecp
 18   request families on /protocol/saml beyond its two base cells
  3   request families on /resolve beyond its base POST
  4   request families on /clients/{name} beyond its base GET
 ---
 72
```

The 18 on `/protocol/saml` are the ones that earn the chapter its shape and are
set out in 1.5 and 1.6.

### 1.4 The descriptor: what it is, and what moves

```
GET /realms/master/protocol/saml/descriptor
200, 3422 bytes, Content-Type: application/xml;charset=UTF-8
Cache-Control: no-cache
Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options,
X-Frame-Options, X-Robots-Tag   - all five
```

**It carries no `ID` attribute and no timestamp.** That is the first thing to
check and it is the thing the brief expected to bite: the identity provider
export's SAML branch mints an `ID="ID_<uuid>"` per request, and F113 says a body
carrying a per-request value cannot be `Recorded` whatever else is true of it.
This body does not.

Two recordings against two fresh containers, and five recordings against one:

```
one container, five requests    byte-identical, all five
two containers, one image       3422 bytes both, differing in exactly two places
```

The two places are `<ds:KeyName>` (the RSA kid) and `<ds:X509Certificate>`. Both
are derived from the realm's RSA key, which is minted with the database. Once
those two and the base URL are masked, the two documents are **byte-identical,
2378 bytes each**.

Six things in the layout look wrong and are not:

- the root declares **two prefixes for one namespace**, a default `xmlns` and
  `xmlns:md`, both the metadata URI, then uses `md:` throughout - the default
  declaration is used by no element;
- it declares `xmlns:saml`, the assertion namespace, and **no element is in it**;
- every empty element is spelled `<md:X></md:X>` and never `<md:X/>`;
- there is no `<?xml ?>` prologue and no trailing newline;
- `ArtifactResolutionService` is the only service carrying an `index`, and the
  only one whose `Location` is not the bare `/protocol/saml` endpoint;
- **the two service lists hold the same four bindings in different orders.**
  `SingleLogoutService` is POST, Redirect, Artifact, SOAP; `SingleSignOnService`
  is POST, Redirect, SOAP, Artifact. The four `NameIDFormat` elements sit between
  them. A builder sharing one list is right on three of four entries in both
  places, which no assertion over membership and no count would catch;
  `TestTheTwoBindingListsDisagree` is what pins it.

### 1.5 Three sentences on `/protocol/saml`, and the `Issuer` picks

The endpoint answers a page for everything, and which page is decided by the
`Issuer` inside the SAML message. Measured on a clean container with one SAML
client created exactly as the fixture creates it:

```
Issuer names no client                 400  3572 bytes  Invalid Request
Issuer names an openid-connect client  400  3579 bytes  Wrong client protocol.
Issuer names a saml client             400  3604 bytes  Invalid requester
```

`Invalid Request` is also what an absent `SAMLRequest`, an empty one, base64 that
is not XML, well-formed XML that is not SAML, an `AuthnRequest` with no `Issuer`
element, a `SAMLResponse` of junk and a *raw* (undeflated) base64 message all
get - seven inputs, one answer. So the split is **which client resolved**, not
whether a message was read.

`Wrong client protocol.` was measured on two openid-connect clients, the
bootstrapped `account` and a created one, so it is not a property of either.
It is worth noting the direction: AGENTS.md records that the scope evaluator
serves *both* protocols on one route and that refusing the mismatch there is
wrong on four operations. Here the mismatch **is** the answer. Two families, one
question, opposite answers.

The POST binding carries the message base64'd and **not** deflated, and reaches
the identical three answers. Each binding rejects the other's encoding into
`Invalid Request`, which is what makes both spellings necessary in the catalogue
rather than one being reused.

### 1.6 The success path is reachable, and that is why nothing here is served

This is the measurement that decided the shape of the cut, and it was found while
answering a different question - why a registered SAML client is refused at all.

`POST /admin/realms/master/clients` with `{"protocol":"saml"}` and no attributes
produces a client carrying **`saml.client.signature: "true"`** among fifteen
generated attributes, including a freshly minted signing key pair. So an unsigned
`AuthnRequest` from it fails the signature check, and `Invalid requester` means
*the requester was not authenticated* rather than *the requester is unknown*.

Turn that one attribute off and the same three requests answer:

```
saml.client.signature=false, Destination = the wrong port    400  3602  Invalid Request
saml.client.signature=false, Destination = the server's URL  200  6869  the login page
saml.client.signature=false, no AssertionConsumerServiceURL  400  3607  Invalid redirect uri
```

Three things follow, and all three are load-bearing.

**The rejection ladder is five deep**: client, protocol, signature, `Destination`,
assertion consumer URL. A cut that served the three rejections in 1.5 without
walking it would be right on every request in this catalogue and wrong on the
only request a SAML client ever sends. That is AGENTS.md's "a set of assertions
an incorrect implementation satisfies entirely", and it is the reason
`saml/endpoint/*` is `Recorded` rather than served.

**The `Destination` is validated**, and an earlier reading of mine said it was
not. That reading came from comparing two requests that both failed the signature
check first, so the `Destination` was never reached - a probe whose input could
not change its output. It is corrected here rather than left out because the
first version of this section had it wrong.

**The three catalogue `AuthnRequest`s are stable on any port anyway**, and that
was checked rather than assumed: all three fail before the `Destination` check,
and each was sent with the container's real port and with `8080` and gave the
identical answer. The one request that does depend on the port is the success
path, and that is exactly why it is `Pending` - see 3.

### 1.7 The path segment under `/clients/` is not a clientId

One client, three spellings, one container:

```
GET /protocol/saml/clients/gloak-probe-sso        400  3607  Invalid redirect uri
GET /protocol/saml/clients/gloak-probe-saml-sp    400  3574  Client not found.
GET /protocol/saml/clients/gloak-probe-no-such…   400  3574  Client not found.
```

`gloak-probe-sso` is the value of the client's
`saml_idp_initiated_sso_url_name` attribute; `gloak-probe-saml-sp` is its
`clientId`. **A handler that looked the client up by `clientId` would answer the
unclaimed name correctly by accident** and this one wrongly, and the two cases a
reader would write first - a name nothing carries, and a name something carries -
cannot tell the two implementations apart. That is why
`saml/idp-initiated/client-id-is-not-the-name` is a case: it is the third input,
and it is the one that kills the wrong implementation.

The same client carries a registered `redirectUris` pattern and is still refused
`Invalid redirect uri`, so what is missing is a SAML assertion consumer URL and
not a redirect URI.

### 1.8 `/resolve` answers 200, and it cannot be a golden

```
POST /realms/master/protocol/saml/resolve   <SOAP ArtifactResolve>
200, 631 bytes, Content-Type: text/xml, Cache-Control: no-cache
```

The body is a `samlp:ArtifactResponse` whose status is `RequestDenied`. Two
requests six milliseconds apart:

```
ID="ID_ce601e26-7dad-4c0f-a27c-ade37c205239"  IssueInstant="2026-09-07T11:21:25.363Z"
ID="ID_a2fb9b6c-501d-4b52-b399-4380d8a2fea9"  IssueInstant="2026-09-07T11:21:25.369Z"
```

and identical everywhere else. **F113 applies and the case is `Pending`.** The
XML mask this cut builds does not rescue it and was not extended to try: the `ID`
is an *attribute*, the frame is text-only, and building an attribute frame for a
body that may not be `Recorded` anyway would be a mask with no consumer - which
is the test `Case.VolatileHTMLInput`'s own doc comment records being applied in
the other direction.

The request's `Content-Type` is **not read**: `text/xml`, `application/soap+xml`
and none at all give the identical answer. An empty body is
`500 {"error":"unknown_error",…}` with all five security headers and nothing
per-request in it, and that half **is** a golden -
`saml/artifact-resolution/empty-body` - so the endpoint is not represented in the
catalogue by an unrecordable case alone. A chapter whose only evidence is a
`Reason` string is a chapter nobody can check.

### 1.9 The finding: one page, two endpoints, complementary header sets

```
GET /realms/master/protocol/openid-connect/auth      400  3572 bytes  Invalid Request
GET /realms/master/protocol/saml                     400  3572 bytes  Invalid Request
```

**The two bodies are byte-identical**, checked byte by byte and not by length.
The headers are not:

```
                                   /auth        /saml
Cache-Control                      absent       no-store, must-revalidate, max-age=0
Content-Language: en               yes          yes
Content-Type: text/html;charset=utf-8  yes      yes
Content-Security-Policy            yes          absent
Referrer-Policy                    yes          absent
Strict-Transport-Security          yes          absent
X-Content-Type-Options             yes          absent
X-Frame-Options                    yes          absent
X-Robots-Tag                       yes          absent
```

Read at socket level on one container, side by side, because AGENTS.md's rule
about writing down an absence says to dump the bytes that actually left.

This is a **third producer of "none of the five"**, after an unmatched path and
the `Duplicate resource error` family, and it is the first that is a matched
route serving a real page: `/protocol/saml` answers `405` to `PUT` and `200` with
an `Allow` to `OPTIONS`, so the router certainly reached it.

It is not the endpoint alone, either. One path segment down,
`/protocol/saml/clients/{name}` answers the *same template* with all six. So
within one SAML family, one 400 page family, two rejections, opposite header
sets - which is the sharpest form yet of the thing AGENTS.md's most-corrected
bullet keeps discovering. `AssertAbsentHeaders` on six cases is what pins it;
`AssertHeaders` can only ever check a header that is named, so without the
negative the day Gloak began sending the five here "for consistency" would look
like a pass.

### 1.10 Two more spellings, and neither is SAML's

`GET /realms/master/protocol/nosuchproto/descriptor` answers
`404 {"error":"Protocol not found"}` with all five security headers. It is not
recorded anywhere in this repository. It is **not a SAML behaviour**:
`/protocol/nosuchproto/certs` and `/protocol/nosuchproto` answer the same
sentence, and so does `/protocol/saml-ecp`. It belongs to whoever builds a
protocol dispatcher; it is filed here because this is the sweep that found it,
and a spelling nothing records is a spelling the next cut re-measures.

`GET /realms/nosuchrealm/protocol/saml/descriptor` answers
`404 {"error":"Realm does not exist"}` - the protocol side's spelling with no
full stop, which `internal/oidc/router.go` already serves - and carries **no
`Cache-Control`** where the 200 beside it carries `no-cache`.

### 1.11 The trailing slash is general, and is therefore not this cut's

`/protocol/saml/descriptor/` answers the identical 200. Before treating that as a
descriptor behaviour I measured the control: `/protocol/openid-connect/certs/`
also answers 200, and `/protocol/openid-connect/auth/` answers `auth`'s own 400
page. So it is JAX-RS's trailing-slash rule across the whole protocol surface,
not a property of this endpoint, and special-casing the descriptor for it would
have been a fix aimed at one instance of a rule. It is F173 below.

### 1.12 `encoding/xml` cannot emit the descriptor, proved with bytes

The brief requires this before a hand-written emitter is allowed to exist, and
`TestEncodingXMLCannotEmitTheDescriptor` in `internal/oidc/saml_test.go` runs the
marshaller and compares rather than asserting it in prose. Two failures:

- **the prefix.** `encoding/xml` has no way to say "use this prefix". The same
  tree that Keycloak spells `<md:NameIDFormat>` comes out
  `<NameIDFormat xmlns="urn:oasis:names:tc:SAML:2.0:metadata">`, on every element
  in the document.
- **the double declaration.** No struct tag produces a namespace declaration that
  nothing uses, and the root carries one.

So `internal/oidc/saml.go` emits bytes and `internal/httpx/xml.go` writes them,
which is `internal/httpx/yaml.go`'s situation one format across. The refutation
is a test rather than a paragraph so that the day a Go release makes either
reachable, it fails and the emitter can go.

### 1.13 Gloak's descriptor, checked against Keycloak's before recording

Gloak was built, run on a fresh database and asked the same question. **3422
bytes, the same seven headers, the same values.** With the base URL, the
`<ds:KeyName>` and the `<ds:X509Certificate>` masked, both documents are 2378
bytes and compare byte-identical. That check was done by hand before `make
record`, so the golden confirmed a match rather than establishing one.

## 2. Decisions, each with the alternative rejected

### 2.1 An XML mask, rather than leaving the descriptor `Pending`

**Rejected alternative: leave `saml/descriptor/master` `Pending` with a measured
reason.** That would have been a claim about the harness dressed as a claim about
Keycloak. `oidc/certs/master` masks the *same two facts* - the kid and the
certificate - with `Volatile` over `keys/*/kid` and `keys/*/x5c`, and is
`Implemented`. Refusing the same treatment because the body is XML rather than
JSON would leave a chapter at zero for want of a hundred-line function whose
shape this repository already has three times.

**Rejected alternative: mask the whole body.** AGENTS.md records that as F46's
retreat, twice - a whole `Location` asserts presence and nothing else, a whole
body value asserts its type and nothing else. `VolatileXMLText` covers an
element's *text* and never its frame, which is `VolatileHTMLQuery`'s bargain in a
third dialect. What stays asserted on the descriptor is set out in 1.4: the
entityID, four namespace declarations, `WantAuthnRequestsSigned`,
`protocolSupportEnumeration`, `use="signing"`, `index="0"`, the two service lists
in their two different orders, the four `NameIDFormat`s, and the empty-element
spelling.

**Rejected alternative: an attribute frame beside the text one.** It would have
no consumer. The only measured per-request XML attributes in this project are the
identity provider export's `ID_<uuid>` and `/resolve`'s, and both bodies are
barred by F113 whatever a mask does. `Case.VolatileHTMLInput`'s doc comment
records the same rule applied in the other direction - it was built when it got a
consumer and not before.

The frame refuses four shapes rather than masking them, all for `MaskURLTail`'s
reason: an element never closed, one not inside a closed tag, one written
self-closing, and **one whose content is markup**. That last is the important
one: masking `<ds:KeyInfo>` would swallow `<ds:X509Data>`, its child and the whole
shape of the key block. A text mask covers text.

### 2.2 The XML mask goes through the varies-nothing ratchet

**Rejected alternative: give it only `ReplaceXMLValues`' own "covers nothing"
refusal**, which is what `Volatile` has - `bodyMasks` gives `Volatile` a `changes`
of `nil` and its doc comment explains that a golden physically cannot say whether
a masked value varied.

`TestNoHTMLMaskVariesNothing` asks the *served* body instead, twice, and the
verifier builds a fresh database per case - so Gloak's kid and certificate do move
between two servings and the ratchet is meaningful here. What it catches is the
mistake this frame invites: a mask pointed at `md:NameIDFormat` or
`md:SingleSignOnService`, whose text is a constant of the protocol. Nothing else
in the harness would notice, because `ReplaceXMLValues`' refusal fires only when
a mask covers *nothing*. The finding's label changed from `VolatileHTML` to
`VolatileMarkup` for it; `htmlMasksLeftInPlace` is empty, so no key moved.

### 2.3 The descriptor alone is served

**Rejected alternative: serve the `/protocol/saml` rejections too.** They are
reachable, their bytes are here, and three of them are genuinely distinct. 1.6 is
why not: the success path is one client attribute away, the ladder is five checks
deep, and a handler answering the rejections without walking it answers
`Invalid requester` to a properly configured client. The catalogue would be green
and the server would be wrong on the only request the endpoint exists for.

**Rejected alternative: serve the IdP-initiated rejections.** Same shape. The
client resolves and Keycloak then wants an assertion consumer URL; serving
`Invalid redirect uri` without resolving one answers it to a client that has one.

**Rejected alternative: serve `Protocol not found` and the trailing slash.** Both
are measured general rules of the protocol surface (1.10, 1.11), not SAML
behaviours. Building either here would mean a change reaching every OIDC path in
a branch called "SAML", for one instance of a rule. They are F173 and F174.

### 2.4 Four chapters, and the old `saml` row removed

**Rejected alternative: one enumerated chapter named `saml/protocol`.** One row
changing to one row is the smaller diff. Four is the house split - the OIDC side
has eleven chapters for one protocol - and it makes the report say which part of
the surface is served rather than averaging it. The total is unaffected either
way, since a chapter's numbers are summed.

`chapterOf` takes the first **two** ID segments, so a chapter literally named
`saml` could hold no case at all; the row had to change shape whatever was
decided.

### 2.5 The fallback cells are not in the denominator

**Rejected alternative: count all 35 verb cells.** The brief warns that counting
by endpoint under-estimates, and it is right - but 22 of the 35 are `405` and the
generic `404`, and `http/fallback` already holds two cases that count them once
for the whole API. Counting them again here would report two behaviours
twenty-two times and inflate the meter with a repetition. They are measured, the
table in 1.2 has them, and Gloak diverges on the 405s exactly as F31 records.

### 2.6 `saml/endpoint/login-page` is `Pending` rather than absent

**Rejected alternative: leave the success path out of the catalogue.** Then the
chapter's denominator would say this endpoint has only refusals, which is the
error the first reading of it actually made. It is in, `Pending`, with the two
independent blockers in its `Reason`.

## 3. Refusals, each with the measurement behind it

| What | Measurement | Status |
|---|---|---|
| `saml/artifact-resolution/request-denied` | `ID="ID_<uuid>"` and a millisecond `IssueInstant` move between two requests 6 ms apart; F113 | `Pending` |
| `saml/endpoint/login-page` | needs an `AuthnRequest` naming the server's own `Destination`, inside a DEFLATE+base64 blob; and the page carries a per-request `tab_id` | `Pending` |
| `saml/endpoint/*` (7 cases) | the rejection ladder is five deep and the fifth rung is a 200; serving the rejections alone is wrong on the request that matters | `Recorded` |
| `saml/idp-initiated/*` (3 cases) | the client resolves and an assertion consumer URL is what is missing | `Recorded` |
| `saml/descriptor/unknown-protocol` | `Protocol not found` is a rule of the whole protocol surface, measured on `certs` and on a bare `/protocol/x` too | `Recorded` |
| `saml/descriptor/options` | `OPTIONS` 200 with `Allow`; Gloak 404s `OPTIONS` on every route it has - F31 | `Recorded` |
| `saml/endpoint/unknown-subpath` | Gloak answers the unmatched-path body with no headers where Keycloak answers the generic 404 with five | `Recorded` |
| the trailing slash | `/certs/` answers 200 as well, so it is JAX-RS's rule and not the descriptor's | not a case; F173 |
| `HEAD` on the descriptor | `httptest.ResponseRecorder` does not strip a body for `HEAD` where `http.Server` does, so a `HEAD` case would compare Gloak's body against Keycloak's absence | not a case; F175 |

`saml/endpoint/login-page`'s first blocker is worth restating because it is a
statement about this harness rather than about SAML. A `Request` carries literal
bytes; `Expand` rewrites `Path`, `Query`, `Headers`, `Form` and `Body` from
**fixture captures**, and there is no issuer among them. The `AuthnRequest` has to
name the server's own base URL and is DEFLATE-compressed and base64'd before it
is a parameter, so no literal can be written that works on the recorder's mapped
port. That is F122's boundary met from a third side, and the shape of the answer
is DPoP's: `Fixture.Proofs` mints a value the catalogue cannot spell.

## 4. The mutation pass

Every mutation was applied to the tree, `go test` run, its **exit code** read
first, and the diff checked non-empty and compiling before the result was
believed - both of those have produced false passes in this project before.

The harness itself has three refusals, and **the third was added mid-pass
because it had just produced a false pass**: a `-run` pattern naming a test that
does not exist runs nothing and exits 0, which reads exactly like a survivor.
M20 was reported as surviving `TestEveryUnenumeratedChapterSaysWhy`; the test is
called `TestUnenumeratedChaptersCarryAReason` and had never run. The harness now
requires evidence in the output that something ran, and M20c is the control that
proves the refusal fires.

### The emitter

| # | Mutation | Result |
|---|---|---|
| M1 | the two binding lists become one | killed by `TestTheTwoBindingListsDisagree` |
| M1b | the same, asked of the golden | killed by `TestConformance/saml/descriptor/master` |
| M2 | certificate in base64url | killed by `TestTheCertificateIsStandardBase64OfTheDER` |
| K1b | the two binding lists made identical, asked of the layout test alone | **survived** - a review's mutation, reproduced here; the test's name overclaimed and is renamed |
| M2b | the same, asked of the golden | **survived by design** - the certificate is masked, which is what M2's test exists for |
| M3 | drop the unused `xmlns:saml` | killed by the golden |
| M4 | `Cache-Control: no-store` | killed by the golden |
| M5 | `Content-Type` without the charset | killed by the golden |
| M6 | self-close the empty elements | killed by the golden |
| M7 | hard-code `master` in the entityID | killed by `saml/descriptor/second-realm` |
| M7b | the same, asked of the master case | **survived by design** - F142's mutation, and the second-realm case is what sees it |
| M8 | the resolve `Location` loses its segment | killed by the golden |
| M9 | `WriteXML` deletes `X-Frame-Options` | killed by the golden |
| M22 | drop the second `xmlns:md` declaration | killed by the golden |
| M23 | the artifact service loses its `index` | killed by the golden |
| M24 | a `NameIDFormat` goes missing | killed by the golden |

M2b and M7b are not findings; they are the pair that says **which** assertion
does the killing. M2b is the honest cost of masking the certificate, and it is
why `TestTheCertificateIsStandardBase64OfTheDER` was written: the golden asserts
that the element is there and nothing about what is in it, so a base64url
emitter, PEM armour, or the *encryption* key's certificate would all match. That
test decodes the element with the standard alphabet and compares the bytes to
the realm's signing DER, which is a second opinion rather than a copy of the
emitter's expression.

### The XML mask

| # | Mutation | Result |
|---|---|---|
| M10 | drop the element-name boundary check | killed by `TestXMLMaskedValuesReadsWhatTheMaskCovers` |
| M11 | drop the markup-content check | killed by `TestXMLTextMaskRefusesTheShapesItCannotCover` |
| M12 | drop the self-closing check | killed by the same |
| M13 | the mask covers the tags too | killed by `TestReplaceXMLValuesMasksTheTextAndNothingElse` |
| M14 | drop the covers-nothing refusal | killed by `TestReplaceXMLValuesRefusesNothingAndEmptiness` |
| M15 | `ReplaceXMLValues` out of `normalisePasses` | killed by the golden |
| M16 | point the mask at `md:NameIDFormat`, a constant | killed by `TestNoHTMLMaskVariesNothing` |
| M21 | an XML mask name with two colons | killed by `TestCatalogIsWellFormed` |

M10 is the one the hand-built vector exists for. **The real descriptor cannot
kill it**: it holds no element whose name is a prefix of another, so a mask that
dropped its boundary check would mask the real body identically and every
assertion about it would still pass. `md:Key` against `md:KeyDescriptor` is the
row that kills it, `md:Closed` kills M12, `ds:KeyInfo` kills M11 and `md:Empty`
kills half of M14 - each named in the vector's own comment, so a mutation that
deletes one check is reported against the check it deleted.

### The harness's own guards

| # | Mutation | Result |
|---|---|---|
| M17 | drop `VolatileXMLText` from the varies ratchet's scope | **survived; fixed** |
| M18 | the report writes a wrong unenumerated count | **survived; the assertion was a tautology and is gone** |
| M19 | a chapter loses its row | killed by `TestCoverage` |
| M20 | an enumerated chapter keeps a `Reason` | killed by `TestUnenumeratedChaptersCarryAReason` |
| M20c | control: a test name that does not exist | refused by the harness |
| M26 | an `AssertAbsentHeaders` entry removed | **survived, and is reported below** |
| M27 | declare a header absent that the golden carries | killed by `TestAssertAbsentHeadersAgreeWithTheGolden` |

### The three survivors, and what was done about each

**M17 - the varies ratchet's scope was a hand-written sum and nothing checked
it.** `TestNoHTMLMaskVariesNothing` decides which cases to visit with
`len(VolatileHTMLQuery)+len(VolatileHTMLCall)+len(VolatileHTMLInput)+len(VolatileXMLText)`.
Dropping the last term made it skip every SAML case with the whole package still
green - so the day a fifth markup frame arrives and its author forgets that line,
the frame ships with no ratchet and nothing says so.

Fixed, and the fix reads the committed bytes rather than the predicate: an XML
mask writes `{{prefix:name}}` into a golden, and a colon is a spelling nothing
else in this harness produces - `ReplaceIssuer` writes `{{issuer}}`,
`ReplaceThemeResource` `{{theme_resource}}`, `Normalize` a JSON type name, and a
fixture capture matches `capturedValue`'s `[a-z_0-9]+`. A golden holding one on
an `Implemented` case the ratchet did not visit is now an error, found without
asking the predicate what its reach is.

**M18 - this cut wrote an assertion that could not fail.** Removing the stale
"the catalogue has four" from a message, I replaced it with a count of
`Chapters` compared against `unenumerated` - which `TestCoverage` had already
counted from `Chapters` twenty lines earlier. It was `count(x) == count(x)`. The
mutation that exposed it was a poor one in itself (it disabled the assertion,
which proves nothing); the useful one, making `writeParityReport` emit
`unenumerated+1`, is killed by the `fields[3]` comparison that was already
there. The tautology is gone and the number stays out of the message.

**M26 - a declaration deleted is invisible to a checker of declarations, and it
stands.** `AssertAbsentHeaders` is read only by `diff`, and `diff`'s verdict on
a `Recorded` case is "these differ", which any one difference satisfies. So the
six absent-header lists this cut added - pinning the finding in 1.9 - asserted
nothing at all.

Half of that is fixed. `TestAssertAbsentHeadersAgreeWithTheGolden` now checks
every declaration against the recorded bytes, which works for a `Recorded` or
`Pending` case as readily as for an `Implemented` one, and M27 proves it can
fail. What it cannot catch is a declaration being **removed**: a smaller set of
true claims is still a set of true claims. Killing that needs the mirror rule -
*every* golden missing a security header must have a case declaring it absent -
and **that rule fires on the existing tree**, because 87 committed goldens omit
`X-Frame-Options` for the media-type reasons AGENTS.md records and none of them
declares it. It is a sweep of its own and is F177.

### K1b - a test name that promised a byte comparison it did not make

Found by the review's mutation pass and reproduced here: making the two binding
lists identical and running **only**
`TestDescriptorIsBytewiseWhatKeycloakSends` passes. The test is seven substring
checks and four structural ones, and none of them mentions the sign-on list's
order.

It is not a coverage hole - `TestTheTwoBindingListsDisagree` beside it and
`TestConformance/saml/descriptor/master` above both kill the same mutation, and
both did in this cut's own pass as M1 and M1b. It is a **name that reads as a
guarantee**, in a repository whose recurring failure is a sentence that reads as
coverage; and the giveaway is that the sibling test's comment already described
this one correctly, as the shape "no assertion over membership, and no count"
would catch. Only the name disagreed.

Renamed to `TestDescriptorCarriesTheLayoutRulesThatLookWrong`, with the doc
comment now saying which assertion is the bytewise one. The lesson generalises
past this file: a unit test beside a golden names the rules, and the golden is
the contract - so a name claiming otherwise sends the next reader to the wrong
one of the two.

### A fourth false-pass shape, found in my own harness

M25 was `; _ = 0` appended to a route registration: a textually non-empty diff
that changes nothing. It "survived", correctly and uselessly. The harness
refuses an empty diff and a build failure and now a `-run` that matches nothing,
and it cannot refuse this one - a semantically null edit is a mutation only a
reader can rule out. It is recorded because it is the third shape this session
produced and the first that no check can catch.

## 5. Parity

Measured with the procedure AGENTS.md documents - two `GLOAK_PARITY_REPORT`
runs and `cmd/parity` built rather than `go run` - against the merge base
`8c6448c`:

```
Parity: 536 -> 538 of 572 (+2)

chapter                         before  after  delta
saml/descriptor                      0      2     +2

New chapters: saml/artifact-resolution, saml/descriptor, saml/endpoint, saml/idp-initiated
Chapters gone: saml
```

The chapter table itself:

```
chapter                              served  recorded  documented  source
saml/descriptor                           2         2           4  catalogue
saml/endpoint                             0         8           9  catalogue
saml/idp-initiated                        0         3           3  catalogue
saml/artifact-resolution                  0         1           2  catalogue

total: 538 of 572 enumerated behaviours served; 3 chapters not enumerated
```

**The denominator moved by 18 and the numerator by 2, and the first number is
the point of the cut.** A chapter that reported `?` now reports 18 behaviours,
of which two are served, 14 are measured and parked with a golden, and two are
measured and cannot be. The unenumerated chapter count falls from four to three,
which is the sentence in §3.2 of the roadmap becoming one chapter shorter.

Two arithmetic notes, both so the next reader does not re-derive them:

- **19 cases, 18 counted.** `saml/descriptor/second-realm` is a `SecondRealm`
  case and is out of the denominator by `countsTowardsParity`, because it
  re-measures a behaviour its master sibling already holds.
- **the base is 536, not the 535 the roadmap's closing paragraph states.** That
  line is one behind; it was measured here rather than copied.

## 6. Entries for AGENTS.md

### For the security-headers bullet

> **A matched route serving a real page can send none of the five, and the
> variable is the rejection.** `GET /realms/{realm}/protocol/saml` with no
> parameters and `GET /realms/{realm}/protocol/openid-connect/auth` with no
> `client_id` answer the **byte-identical** 3572-byte 400 page, and their header
> sets are complementary: the SAML one sends `Cache-Control: no-store,
> must-revalidate, max-age=0` and **none** of the five and no
> `Content-Security-Policy`; the OIDC one sends all six and no `Cache-Control`.
> That is a third producer of "none of the five" after an unmatched path and the
> `Duplicate resource error` family, and the first that is a matched route - it
> answers 405 to `PUT` and 200 with an `Allow` to `OPTIONS`. One path segment
> down, `/protocol/saml/clients/{name}` answers the same template with all six.
> Read at socket level; `curl` agrees.

### For the media-type half of the same bullet

> **`application/xml` and `text/xml` disagree about `X-Frame-Options`.** The SAML
> descriptor's `application/xml;charset=UTF-8` carries all five; the artifact
> resolution response's `text/xml` carries four. Two XML media types one path
> segment apart on one endpoint family, so "XML" is not the unit - the exact
> media type is. `text/xml` joins `text/plain`, `application/yaml`,
> `application/zip` and `application/octet-stream`, and `application/xml` joins
> `application/json` and `text/html`.

### For the wrong-method bullet

> **The SAML family answers a real 405 on three verbs and splits on `HEAD`.**
> `PUT`, `DELETE` and `PATCH` are 405 on all five of its route shapes; `HEAD` is
> 405 on `/resolve` and `/clients` and a real answer on `/saml`, `/descriptor` and
> `/clients/{name}`. And `OPTIONS` answers the **identical** `Allow: HEAD, POST,
> GET, OPTIONS` on all four real paths, so the header describes the parent
> resource rather than the path: `/descriptor` advertises `POST` and answers it
> 404, `/resolve` advertises `GET` and answers it 404.

### A new bullet, for the SAML endpoint

> **`/realms/{realm}/protocol/saml` has three rejection sentences and the
> `Issuer` picks.** No client resolves is `Invalid Request` (3572 bytes), an
> `openid-connect` client is `Wrong client protocol.` (3579), a `saml` client is
> `Invalid requester` (3604). Seven different unreadable or unresolvable inputs
> all give the first, so the split is which client resolved and not whether a
> message was read. The ladder continues: `Invalid requester` is the **signature**
> check - every client `POST /clients` creates with `protocol: saml` carries
> `saml.client.signature: "true"` - and with it off the same request reaches the
> `Destination` check and then the login page. Five checks, and the fourth and
> fifth are unreachable while the third fails, which is how a first reading
> concluded the `Destination` was not validated.

### A new bullet, for IdP-initiated SSO

> **The segment in `/realms/{realm}/protocol/saml/clients/{name}` is a client
> *attribute*, not a `clientId`.** It is `saml_idp_initiated_sso_url_name`. One
> client answers `Client not found.` for its own `clientId` and `Invalid redirect
> uri` for the attribute's value, on one container. A handler looking clients up
> by `clientId` answers a name nothing carries correctly by accident, so the two
> cases a reader writes first cannot see the bug.

### For the not-found list, or beside it

> **`Protocol not found` is the protocol surface's own spelling**, answered by
> `/realms/{realm}/protocol/{anything unregistered}` - measured on
> `nosuchproto/descriptor`, `nosuchproto/certs`, a bare `nosuchproto` and
> `saml-ecp`. It is not on the Admin API's list of thirty-five because it is not
> the Admin API, and it is the fourth distinct 404 body under `/realms/`, after
> `Realm does not exist`, `HTTP 404 Not Found` and `Unable to find matching
> target resource method`.

### For the "things that look like bugs" list, on the descriptor

> **The SAML descriptor's two service lists hold the same four bindings in
> different orders.** `SingleLogoutService` is POST, Redirect, Artifact, SOAP and
> `SingleSignOnService` is POST, Redirect, SOAP, Artifact, with the four
> `NameIDFormat`s between them. A shared list is right on three of four in both
> places, which no membership assertion and no count would catch. The root also
> binds one namespace to **two** prefixes, declares a third (`saml`) that no
> element is in, spells every empty element `<md:X></md:X>`, and sends no XML
> prologue and no trailing newline.

### For the masks section

> **A fourth markup frame, and its values are per database rather than per
> request.** `Case.VolatileXMLText` covers an XML element's text and never its
> frame. It is the first mask whose values move between *databases* and not
> between requests, which is `oidc/certs/master`'s situation stated in XML; it
> still goes through `TestNoHTMLMaskVariesNothing`, because the verifier builds a
> fresh database per case and a mask pointed at `md:NameIDFormat` - a constant of
> the protocol - has to fail somewhere. It refuses an element holding markup:
> masking `<ds:KeyInfo>` would swallow the whole key block, which is F46's retreat
> in a new place.

### For the build section

> **`encoding/xml` cannot emit Keycloak's SAML metadata**, and the refutation is
> `TestEncodingXMLCannotEmitTheDescriptor` rather than a paragraph. It has no way
> to bind a prefix, so `<md:NameIDFormat>` comes out
> `<NameIDFormat xmlns="…">` on every element, and no way to declare a namespace
> nothing uses, which the root does. So `internal/oidc/saml.go` emits and
> `internal/httpx/xml.go` writes - `internal/httpx/yaml.go`'s situation one format
> across.

## 7. Follow-ups, numbered from F171

### F171 - `Fixture.SAMLRequests`, the third side of F122's boundary

`saml/endpoint/login-page` is measured and unsendable. An `AuthnRequest` must
name the server's own base URL in its `Destination`, and it is
DEFLATE-compressed and base64'd before it becomes a parameter, so no literal can
be written that works on the recorder's mapped port. `Expand` rewrites five
fields from fixture captures and has no issuer among them.

`Fixture.Proofs` is the precedent and the shape: one field, minted before the
steps run, substituted wherever `{{name}}` appears. A `Fixture.SAMLRequests`
declaring an Issuer and a set of attributes, and minting the deflated blob
against the base URL, would unlock the endpoint's whole success half.

**It would not make the login page recordable** - that page carries a
per-request `tab_id`, F113 - so the first thing it unlocks is a `Pending` case
becoming a *sendable* `Pending` case, plus every rejection past the `Destination`
check.

**Deferred to the cut that would use it, not declined.** `Fixture.Proofs` earned
its field by having three consumers on the day it landed; this would have one,
and behind the five-deep ladder in 1.6 - the success path needs
`saml.client.signature` off **and** an AuthnRequest naming the server's own
`Destination`. That is the shape of P11's second cut, the SSO flow, and the
field belongs there, where it will have consumers. Building it now would be a
mechanism with one caller and a `Pending` case still `Pending` at the end of it,
which is the argument `Case.VolatileHTMLInput`'s own doc comment makes for
having waited.

### F172 - `Case.VolatileXMLAttribute`, deliberately not built

The frame exists for text and not for attributes. Nothing needs the attribute
version today: the two measured per-request XML attributes in this project are
the identity provider export's `ID_<uuid>` and `/resolve`'s, and both bodies are
barred by F113 whatever a mask does.

It is filed rather than forgotten because the argument is contingent. If a body
ever carries a volatile attribute and **nothing else** volatile, the frame
becomes the difference between a contract and a `Pending`, and the shape is
twenty lines beside `xmlTextMatches`.

### F173 and F174 are one cut, and it needs naming rather than an owner

Both are general rules of the protocol surface that Gloak gets wrong on **every**
path it serves, and both were found by this sweep without being SAML's. They want
their own diff: the fix and its recording are one change to
`internal/oidc/router.go` and its fallbacks, and the goldens that move will be
OIDC's rather than SAML's.

**The cut is "the protocol surface's two dispatch rules", and it is not
"whoever next touches `router.go`."** An anchor defined by who happens to arrive
is F168 in another dress - the entry gets read by somebody doing something else,
who is the person least placed to judge whether the sweep is complete. Naming it
as a cut is what makes it schedulable.

Its scope, measured here:

- every protocol endpoint answers a trailing slash as its own 200 or its own
  page, and Gloak answers the unmatched-path 404 with no security headers;
- every unregistered protocol answers `Protocol not found`, and Gloak answers the
  same header-less 404;
- and the two interact, because a dispatcher registered as a catch-all decides
  what a trailing slash matches.

Two things it must measure first and this cut did not: whether JAX-RS strips one
trailing slash or many, and whether the rule reaches the Admin API.

### F173 - the trailing slash, across the whole protocol surface

`/realms/{realm}/protocol/saml/descriptor/` and
`/realms/{realm}/protocol/openid-connect/certs/` both answer their endpoint's
200; `/protocol/openid-connect/auth/` answers `auth`'s 400 page. Go's `ServeMux`
matches none of them, so Gloak answers the unmatched-path 404 with no security
headers on every protocol endpoint it serves.

It is one rule and Gloak is wrong on all of it, which is why this cut did not
special-case the descriptor: a fix aimed at one instance of a general rule reads
as a fix and is not one. The measured question for whoever takes it is whether
JAX-RS strips one trailing slash or many, and whether it reaches the Admin API.

### F174 - `Protocol not found`, and a protocol dispatcher

`/realms/{realm}/protocol/{unregistered}` is
`404 {"error":"Protocol not found"}` with all five security headers, measured on
four paths. Gloak has no dispatcher and answers the unmatched-path body with no
headers.

Serving it means a catch-all under `/realms/{realm}/protocol/`, which Go's
`ServeMux` will let a specific pattern beat - the opposite of the precedence
problem F153 met under `/organizations`, so this one is the easy direction. The
risk to measure first is what it does to paths *under* a real protocol:
`/protocol/openid-connect/nosuchsub` answers `HTTP 404 Not Found`, not `Protocol
not found`, so the dispatcher has to know which protocols exist and stop there.

### F175 - a `HEAD` case cannot be written in this harness

`HEAD /realms/master/protocol/saml/descriptor` answers 200 with the descriptor's
headers and no body, and `HEAD` differs from `GET` on two of the five SAML paths,
so it is real surface. No case can hold it: the verifier serves through
`httptest.ResponseRecorder`, which does **not** strip a body for a `HEAD`
request, where `http.Server` does. Gloak's side would carry 3422 bytes and
Keycloak's none, and the case would fail on a correct implementation.

This is the same class as AGENTS.md's note that the conformance verifier cannot
catch the `Date` header's removal, and the same answer applies: the guard would
have to be a package test using a real `httptest.NewServer`. Filed rather than
built because no `HEAD` behaviour in this repository is currently asserted
anywhere, so building it for SAML alone would leave the other producers unguarded.

### F176 - a committed golden holds a Java set order that is not reproducible

`make record` for this cut moved exactly one golden outside it:

```
admin/client-attribute-certificate/download-unsupported-format
- {"error":"… Supported keystore formats: [PKCS12, JKS, BCFKS]"}
+ {"error":"… Supported keystore formats: [BCFKS, PKCS12, JKS]"}
```

**It was reverted, not committed.** Gloak serves the committed order, so the
recording would have turned the tree red; and AGENTS.md's rule that two
recordings agreeing is not evidence of stability has an obverse - two recordings
*disagreeing* is evidence of instability, and this is it.

**There are three recordings, and the middle one was written down as a
correction.** Supplied by the review, which had folded the second an hour before
this cut found the third:

```
2026-09-05   [BCFKS, PKCS12, JKS]     reported as wrong
2026-09-06   [PKCS12, JKS, BCFKS]     recorded as the correction, and committed
2026-09-07   [BCFKS, PKCS12, JKS]     this cut
```

So the 09-06 recording was **never a correction; it was a second draw**, and the
fold that landed it wrote that putting the order in a golden was the fix that
stops a number drifting. Two draws from a coin, and the second was read as
settling the first - which is precisely the inference AGENTS.md's "two
recordings agreeing is never evidence of stability" bullet forbids, arrived at
from the one direction that bullet does not name. Nothing about the sample size
gave it away; what gave it away was a third draw taken for another reason
entirely.

That is the part worth keeping when this entry is closed. The measurement is
cheap to redo and the reasoning error is not: **a recording that disagrees with
a golden is not evidence that the golden was wrong.** It is evidence that one of
them is unstable, and telling the two apart needs a third.

The list is a Java set's iteration order inside an error string, so `Unordered`
cannot reach it: no mask in this harness reaches inside a JSON string, which is
the same wall `admin/clients/evaluate-example-saml-response` sits behind. The
options are a mask that reaches inside a string value, `Volatile` over the whole
message (which would give up the sentence as well as the order), or accepting a
golden that is a coin flip. The case is `admin/client-attribute-certificate`'s
and this cut does not own it.

### F177 - a declaration removed is invisible, and the mirror rule sweeps the tree

M26's survivor. `TestAssertAbsentHeadersAgreeWithTheGolden` now checks every
absent-header declaration against the recorded bytes, and cannot catch one being
**deleted** - a smaller set of true claims is still true.

The rule that would catch it is the mirror: *every golden missing a security
header must have a case declaring it absent*. That is a real invariant and it
**fires on the tree today**, because 87 committed goldens omit `X-Frame-Options`
for the media-type reasons AGENTS.md records and none of them declares it. So it
is a sweep - eighty-odd declarations to add, each of which has to be read against
that bullet's allow-list rather than pasted - and it is the same bargain
`inertMasksLeftInPlace` took: a ratchet plus a declared exception list, arrived at
by somebody reading the goldens.

Worth noting what it would buy beyond tidiness. The header rule is the bullet
AGENTS.md records as having been wrong six times, twice refuted by the very
golden it cited. A rule that made every omission a declaration would put the
tally in the catalogue instead of in a paragraph, which is what
`TestTheDuplicateResourceErrorSplitIsNotDecidedByTheVerb` already does for one
family.

### F113 - unchanged, and applied twice more

`saml/artifact-resolution/request-denied` is `Pending` under it, measured. And
the rule was *checked and found not to apply* to the descriptor, which is the
half worth recording: the descriptor carries no `ID` and no timestamp, unlike the
identity provider export one chapter away, so the family resemblance is not the
rule.

### F161 - unchanged

The descriptor is text. `RefuseNonTextBody` accepts it, as it should.

### F38 - the model this cut followed, a fourth time

The three HTML frames' shape - per case, per named value, covering the value and
never its frame, refusing what it cannot cover, and ratcheted against masking
something that does not move - transferred to XML without argument. That is now
four frames on one design.

### F142 - one more derivation site pinned

`saml/descriptor/second-realm` pins nine realm-derived values in one body: the
entityID and eight service `Location`s. A handler answering with the literal
`master` compares equal on the master case alone.

## 8. What is left

- Everything `Recorded` above, which is the SSO and SLO bindings, the IdP-initiated
  route and the artifact resolution service. The gate on all of it is a SAML
  message reader and an assertion builder, and 1.6 says how deep the first one has
  to go before any of the rejections can be served honestly.
- SAML single logout was **not separately measured**. `/protocol/saml` serves both
  SSO and SLO and the descriptor advertises four `SingleLogoutService` bindings on
  the same URL; a `LogoutRequest` was never sent, because the three sentences in
  1.5 are decided by the `Issuer` before the message type is looked at and no
  input was found that could separate them. That is a gap in this enumeration and
  it is named rather than papered over: **the count of 72 does not include a
  single `SAMLResponse` or `LogoutRequest` that names a registered client.**
- **The protocol surface's two dispatch rules**, F173 and F174, named as a cut of
  their own above. They are not SAML's and not this branch's, and the goldens that
  move when they land will be OIDC's.
- The ECP flow. `saml.allow.ecp.flow` is `"false"` on every created SAML client
  and `saml ecp` is a `topLevel` authentication flow that
  `GET /authentication/flows` does not list, which AGENTS.md already records.
  Nothing was sent to it.
