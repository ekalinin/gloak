# P11 second cut: the SAML SSO flow, and a ladder two rungs deeper than it looked

The first cut enumerated the SAML surface and served one behaviour of it, the
IdP metadata descriptor. Its §1.6 said why nothing else: the rejection ladder on
`/realms/{realm}/protocol/saml` is **five deep**, the fifth rung is a 200, and a
handler answering the four rejections without walking to it is right on every
case in the catalogue and wrong on the only request a SAML client ever sends.

This cut walks the ladder. It is **seven rungs, not five**, and the two extra
ones sit where nobody would have put them. Seventeen of the endpoint's twenty
enumerated behaviours are now served, and all five of the IdP-initiated route's.

Two of the first cut's own measurements are corrected here, and both were
corrections in the direction that made this cut possible:

- **an `AuthnRequest` needs no `Destination`.** The first cut concluded the
  opposite and opened F175 for a harness field to work around it. The field was
  not built; §2.1 is why, and it is a measurement rather than a judgement.
- **`Invalid requester` is a real signature check with a real positive
  control.** A genuinely signed request is accepted, measured, and the catalogue
  now sends one.

---

## 1. Measurements

Every value below came from `quay.io/keycloak/keycloak:26.7.1 start-dev` on
2026-09-11, one input at a time. Where an ordering is claimed, the input that
separates the two orders was sent and its answer is quoted; where a header set
is claimed absent, the bytes were read off a socket with `http.client` rather
than through `curl`.

### 1.1 The ladder is seven rungs, and two of them are new

The whole of `/realms/{realm}/protocol/saml`, in the measured order. Every row
is a request that reaches exactly that rung and no further.

```
the message will not decode or parse            400  Invalid Request
its Issuer names no client in the realm         400  Invalid Request
the client is disabled                          400  Login requester not enabled
the client is bearer-only                       400  Bearer-only applications are
                                                     not allowed to initiate
                                                     browser login
the client's protocol is not saml               400  Wrong client protocol.
the signature is required and does not verify   400  Invalid requester
the Destination is wrong, or absent on a
  message carrying a Signature parameter        400  Invalid Request
no assertion consumer URL resolves              400  Invalid redirect uri
                                                200  the login page
```

**`Login requester not enabled` and the bearer-only sentence run *before* the
protocol check**, and that is the finding. The inputs that say so name
`openid-connect` clients, so a ladder ordered *client, protocol, signature* -
which is what the first cut recorded and what AGENTS.md still says - answers
`Wrong client protocol.` to both:

```
Issuer = a disabled openid-connect client      400  3584  Login requester not enabled
Issuer = a bearer-only openid-connect client   400  3623  Bearer-only applications…
Issuer = an enabled openid-connect client      400  3579  Wrong client protocol.
```

The bearer-only rung was measured against the signature rung too, on a
bearer-only SAML client carrying `saml.client.signature: "true"` and sent an
unsigned request: `Bearer-only…`, not `Invalid requester`. So it is ahead of that
check as well.

`Login requester not enabled` is a **new sentence** in this repository and has no
full stop. `Bearer-only applications are not allowed to initiate browser login`
is not new - `internal/oidc/themepage.go` measured it on `/auth` a fortnight ago
- and the fact that this endpoint shares it is worth a case, because the two
endpoints disagree about every other sentence on this ladder.

### 1.2 The `Destination` is optional, and F175 rests on the opposite

This is the measurement the cut turns on. The first cut wrote:

> the `Destination` is validated, and it has to be the base URL the server is
> actually reachable on […] so no literal request can name the recorder's mapped
> port

Half of that is right and the load-bearing half is not. Six cells on one
container, one client, one message:

```
unsigned, no Destination attribute at all    200  6871  the login page
unsigned, Destination=""                     200  6871  the login page
unsigned, Destination = the wrong port       400  3603  Invalid Request
signed,   no Destination attribute at all    400  3603  Invalid Request
signed,   Destination=""                     400  3603  Invalid Request
signed,   Destination = this server exactly  200  6871  the login page
```

So the rule is: **a non-empty `Destination` must match exactly, and a request
carrying a `Signature` parameter must additionally have one.**

And the predicate is the **parameter**, not the client's flag. A client with
`saml.client.signature` **off**, sent a junk signature and no Destination,
answers `Invalid Request` - the Destination rung - and not `Invalid requester`:
the signature is never looked at and the Destination is demanded anyway.

When it is compared it is compared as a string. Each of these was sent
separately against the server's own URL:

```
trailing slash             400  Invalid Request
https for http             400  Invalid Request
127.0.0.1 for localhost    400  Invalid Request
the port left off          400  Invalid Request
?x=1 appended              400  Invalid Request
another realm              400  Invalid Request
/protocol/saml/descriptor  400  Invalid Request
the URL exactly            200  the login page
```

### 1.3 The signature check is real, and here is the positive control

The first cut could not tell a signature check from a flag, because every input
it had was a rejection. Both halves were measured here.

A client was created with `{"protocol":"saml"}` and an X.509 certificate
installed on its `saml.signing.certificate` attribute, and the
HTTP-Redirect binding's canonical string - `SAMLRequest=<raw>&SigAlg=<raw>`, the
parameters exactly as sent - was signed with the matching private key:

```
a real RSA-SHA256 signature                  400  3606  Invalid Request      <- past the check
the same, with a signed RelayState           400  3606  Invalid Request
that signature over a **different** message  400  3608  Invalid requester
the same message unsigned                    400  3608  Invalid requester
SigAlg and Signature both junk               400        Invalid requester
SigAlg alone / Signature alone               400        Invalid requester
```

The first row is the whole point: a verifier that refused everything answers
`Invalid requester` there. It is `Invalid Request` because the message carries no
`Destination` and §1.2's second half then demands one - which is also why the
case is a 400 a golden can hold rather than a 200 a golden cannot.

**The accepted `SigAlg` set is three, not the four SAML defines.** Each was
signed with its own digest against the same certificate:

```
http://www.w3.org/2000/09/xmldsig#rsa-sha1           accepted
http://www.w3.org/2001/04/xmldsig-more#rsa-sha256    accepted
http://www.w3.org/2001/04/xmldsig-more#rsa-sha512    accepted
http://www.w3.org/2001/04/xmldsig-more#rsa-sha384    REFUSED
http://www.w3.org/2001/04/xmldsig-more#rsa-sha224    refused
SigAlg naming sha256 with a SHA-512 signature        refused
```

`rsa-sha384` is the one that looks like a bug. The URI is right, the digest is
right, the key is the one the sha256 request verified against, and setting the
client's own `saml.signature.algorithm` to `RSA_SHA512` changes nothing either
way - so the set is a property of the server. Writing the table from the
specification, which is what a reader would do, gives an implementation that
accepts a signature Keycloak refuses.

### 1.4 `saml.client.signature` is compared to the exact string `"true"`

Nine values, one client, one container, the same request each time:

```
"true"    400  Invalid requester      (on)
"TRUE"    200  the login page         (off)
"True"    200  the login page         (off)
" true"   200  the login page         (off)
"false"   200  the login page         (off)
""        200  the login page         (off)
absent    200  the login page         (off)
"0"       200  the login page         (off)
"no"      200  the login page         (off)
```

So it is `"true".equals(value)`. **`strconv.ParseBool` is the obvious
implementation and it is wrong on `"TRUE"` - and so is copying Java's own idiom**,
because `Boolean.parseBoolean("TRUE")` is `true` and this is not.

### 1.5 The assertion consumer URL has two sources and they do not compose

```
message names an ACS the client's redirectUris cover   200  the login page
message names an ACS they do not cover                 400  Invalid redirect uri
message names none, client has no ACS attribute        400  Invalid redirect uri
message names none, client has saml_assertion_consumer_url_post   200  the login page
message names none, client has saml_assertion_consumer_url_redirect 200  the login page
message names the attribute's own URL, redirectUris empty  400  Invalid redirect uri
```

The last row is the cell a reader would get wrong. A **named** ACS is checked
against the client's `redirectUris` and against nothing else; an **absent** one
falls back to the client's ACS attribute and is checked against nothing at all.
So a client whose only assertion consumer URL is that attribute, sent a message
naming that same URL, is refused.

The named half is `matchRedirectURI`, the OIDC redirect matcher, on all seven of
its sharp cells - re-measured here rather than assumed:

```
pattern                      ACS                            answer
http://localhost:9999/callback  …/callback                   accepted
http://localhost:9999/callback  …/callback?x=1               refused
http://localhost:9999/callback  …/callback/                  refused
http://localhost:9999/*         http://localhost:9999?x=1    accepted
http://localhost:9999/*         http://localhost:99990/evil  refused
http://localhost:9999/cb?a=*    …/cb?a=1                     refused
http://localhost:9999/*/cb      …/x/cb                       refused
```

### 1.6 The parser, and the one rule nobody would guess

Eleven inputs, one sentence, so a golden cannot say which check refused any of
them. All measured:

```
SAMLRequest absent / empty                             Invalid Request
base64 of junk                                         Invalid Request
raw undeflated base64 of good XML                      Invalid Request
deflated well-formed non-SAML (<hello/>)               Invalid Request
root in no namespace                                   Invalid Request
root in a namespace that is not SAML's                 Invalid Request
root spelled <samlp:authnrequest>                      Invalid Request
no ID attribute                                        Invalid Request
Version="1.0"                                          Invalid Request
no IssueInstant                                        Invalid Request
Issuer nested inside <Extensions>                      Invalid Request
```

and four that are accepted:

```
root in the protocol namespace by a prefix             accepted
root in the protocol namespace by a default xmlns      accepted
Issuer in the assertion namespace, or in none at all   accepted
**two Issuers: the last one wins**                     accepted
```

The last is the rule worth keeping. `<Issuer>account</Issuer><Issuer>a-saml-
client</Issuer>` is served from the **second**: the answer is the login page and
not `Wrong client protocol.` That is JAXB overwriting a field it has already set,
and an implementation reading the first Issuer is right on every well-formed
message and wrong on that one.

### 1.7 `SAMLRequest` wins over `SAMLResponse`

```
SAMLResponse = a perfectly good AuthnRequest    400  3572  Invalid Request
both parameters, the same message in each       200  6871  the login page
```

So the endpoint reads `SAMLRequest` and nothing else on the way in. A handler
reading whichever parameter is present answers the first row past the ladder's
floor.

### 1.8 The IdP-initiated route is a three-rung ladder, and the name is not a clientId

```
GET /protocol/saml/clients/gloak-probe-no-such-sso-name  400  3574  Client not found.
GET /protocol/saml/clients/account                       400  3574  Client not found.
GET /protocol/saml/clients/<a saml client's clientId>    400  3574  Client not found.
GET /protocol/saml/clients/<a disabled client's name>    400  3573  Client disabled.
GET /protocol/saml/clients/<an oidc client's name>       400  3579  Wrong client protocol.
GET /protocol/saml/clients/<a saml client's name>        400  3608  Invalid redirect uri
  …the same client, with saml_assertion_consumer_url_post set   200  6813  the login page
```

Two things fall out and neither is visible from the first cut's three cases.

**The name is looked up across protocols.** An enabled `openid-connect` client
carrying `saml_idp_initiated_sso_url_name` answers `Wrong client protocol.` and
not `Client not found.`, so the protocol check is a rung of its own. A handler
filtering the scan by protocol - the obvious implementation, and the one that
reads as a safety improvement - answers `Client not found.` there, and the other
three cases cannot see the difference.

**The enabled check runs before it.** A *disabled* `openid-connect` client
carrying the attribute answers `Client disabled.`

And the same client in the same state gets **two different sentences** from the
two routes: `Client disabled.` here, `Login requester not enabled` on
`/protocol/saml` one path segment up. With two different header sets - all six
here, none of the five plus no CSP there.

### 1.9 A `LogoutRequest` is new surface, and the two bindings answer differently

The first cut said in as many words that its 72 pairs held none, because the
endpoint's three sentences are decided by the `Issuer` before the message type is
read. That is right as far as it goes: a `LogoutRequest` walks the **identical**
ladder, rung for rung, answering `Invalid Request`, `Login requester not
enabled`, `Bearer-only…`, `Wrong client protocol.`, `Invalid requester` and the
`Destination` sentence to the same inputs an `AuthnRequest` does.

It diverges at the top, and the two bindings diverge from each other:

```
GET  /protocol/saml?SAMLRequest=<deflated LogoutRequest>
500, 94 bytes, Content-Type: application/json
Cache-Control: no-store, must-revalidate, max-age=0
none of the five security headers, no Content-Language
{"error":"unknown_error","error_description":"For more on this error consult the server log."}

POST /protocol/saml   SAMLRequest=<base64 LogoutRequest>
500, **empty body**, **no Content-Type at all**
Cache-Control: no-cache
none of the five security headers
```

Two requests of each, identical bytes. The JSON one is the **first JSON body
measured carrying this endpoint's header set** - the "none of the five" rule
reaches past the HTML pages to the whole route.

Neither is served; §3 says why.

### 1.10 The `Cache-Control` is decided by the verb, on this endpoint alone

```
GET  /protocol/saml  (every rung, and the 500)  no-store, must-revalidate, max-age=0
POST /protocol/saml  (every rung, and the 500)  no-cache
GET  /protocol/saml/clients/{name}              no-store, must-revalidate, max-age=0
```

The two committed goldens `saml/endpoint/no-parameters` and
`saml/endpoint/post-no-parameters` carried this before this cut and nothing said
so: they are the same 3572-byte body with two different `Cache-Control` values.
AGENTS.md records `Cache-Control` as "pinned per endpoint"; here it is pinned per
endpoint **and verb**.

### 1.11 A malformed percent-escape is a 400 with no body, and it is not SAML's

```
GET /protocol/saml?SAMLRequest=%%%%             400  0 bytes, no headers at all
GET /protocol/saml?SAMLRequest=%zz              400  0 bytes
GET /protocol/saml/descriptor?x=%%%%            400  0 bytes
GET /protocol/openid-connect/auth?x=%%%%        400  0 bytes
```

Four paths, one answer, and two of them are not SAML's. It is the request line
being rejected before anything routes, which is `missingNormalization`'s
neighbourhood rather than this endpoint's. Filed as F231 and not built here, for
the reason the first cut gave F177 and F178: a rule of the whole surface fixed
inside a SAML branch is a change reaching every path for one instance of it.

### 1.12 A client created with `{"protocol":"saml"}` generates fourteen attributes

```
client.secret.creation.time              saml.force.post.binding
realm_client                             saml.server.signature
saml.allow.ecp.flow                      saml.signature.algorithm
saml.artifact.binding.identifier         saml.signing.certificate
saml.authnstatement                      saml.signing.private.key
saml.client.signature                    saml_force_name_id_format
saml_name_id_format                      saml_signature_canonicalization_method
```

The first cut counted fifteen. Counted from the response rather than
incremented, it is fourteen on 2026-09-11. Nothing rests on the number and it is
recorded because the first cut's number is in AGENTS.md.

`saml.client.signature: "true"` is the one this chapter turns on, and
`saml.signing.certificate` is the one that made the positive control spellable.

---

## 2. Decisions, each with the alternative rejected

### 2.1 `Fixture.SAMLRequests` was not built, and the entry is refuted rather than deferred

F175 asked for a fixture field minting a DEFLATE+base64 `AuthnRequest` against
the server's own base URL, because no literal could work on the recorder's mapped
port. **Both halves of that argument are false, and each was measured.**

- **The port is not in the message.** §1.2: an `AuthnRequest` with no
  `Destination` attribute reaches the login page. Every unsigned case in this
  chapter is now a literal with no `Destination`, and they run unchanged on the
  recorder's mapped port and under the harness on 8080.
- **A key is spellable too.** The one request that *does* need a `Destination` is
  a signed one, and signing needs a key - which looked like the second reason for
  a run-time field. It is not: `saml.signing.certificate` is an ordinary client
  attribute, a fixture can install one, and the signature over it can be computed
  once and written down. `saml-signed-client` installs
  `samlSignedClientCertificate` and the catalogue carries two queries signed with
  its private half. Nothing is minted at run time on either side, and the signed
  case still needs no `Destination` because the rung it lands on **is** the
  Destination check.

The brief said the entry would be reviewed the way `Case.VolatileXMLText` and
`Case.UnorderedBracketed` were - does it have consumers on the day it lands, and
what does it refuse. The honest answer is the third one the brief allowed for:
**none, because the thing it was for is not true.**

**Rejected alternative: build it anyway for the login page.** It would not have
helped. `saml/endpoint/login-page` is still `Pending`, for the blocker that was
always the real one: the page carries a per-request `tab_id` and a `session_code`
in its form action, so it cannot be `Recorded` however the request is spelled.
What changed is that the case is now **sendable** - its `Request` is the request
that produces the login page, where before it was a request that produced
`Invalid requester`. That is exactly the unlock F175 predicted, arrived at
without the field.

**What this cost.** A run-time signer would have let the catalogue sign a message
per case, so the `Destination` could name the recorder's own URL and a case could
walk to the top of the ladder with a signature. Nothing in this chapter needs
that: the rung above the signature is the `Destination`, and a signed message
without one lands on it. If a later cut wants a signed message that passes the
`Destination` check, F227 is where that argument goes, and it should be made
then - with a consumer.

### 2.2 The ladder is served and the success path is not, and the success path answers a 404

**Rejected alternative: stop at the signature rung and leave the rest
`Recorded`.** The first cut's objection was to a handler that serves rejections
*without walking the ladder*. A handler that walks it is in a different position
on every rung it implements - but it still has to answer something at the top,
and what it answers is the whole question.

**Rejected alternative: invent a 500, or serve the login page.** The 500 is not
measured. The login page needs an authentication session carrying the SAML
request's id, its relay state and its assertion consumer URL, and a flow that
ends in a **signed SAML assertion** posted back to the service provider. That is
an assertion builder, it is not in this cut, and adding the three fields to
`authTab` and `restartRecord` with nothing that consumes them is the machinery
with no consumer this cut has just refused once already.

So a request that passes every rung falls through to `protocolDispatch`'s
`HTTP 404 Not Found` - **which is what this endpoint answered before this cut**.
The divergence is confined to the one behaviour that is not built, rather than
spread across the ladder by telling a correctly configured client that its
signature is bad.

`TestSAMLEndpointDoesNotRefuseARequestItCannotServe` is what holds that, and it
is the test the catalogue cannot be: every SAML case in the catalogue is a
rejection, so a handler that answered `Invalid redirect uri` to everything would
pass all of them.

### 2.3 The HTTP-POST binding's signature is not verified, and is not refused either

**Rejected alternative: answer `Invalid requester` to a POST from a client
requiring a signature.** That is right for every unsigned POST and wrong for
every signed one, which is this chapter's own failure shape one binding across.

The POST binding's signature is an enveloped XML signature over a canonicalised
document, and nothing in the standard library canonicalises XML - the exclusive
c14n transform is not in `encoding/xml` and cannot be built out of it without
re-implementing the transform. So `verifySAMLSignature` reports a POST
**unverified**, and `samlEndpoint` treats that the way it treats the success
path: the request falls through to the 404. F229.

This is narrower than it sounds. `saml/endpoint/post-binding-saml-client` is
served and matches: an **unsigned** POST from a signature-requiring client
answers `Invalid requester`, because the signature check is not what refuses it -
there is no `<ds:Signature>` in the document at all, and Keycloak's answer and
Gloak's agree byte for byte.

### 2.4 The artifact resolution endpoint is left alone

**Rejected alternative: serve `/resolve`.** Its `empty-body` half is a 500 a
golden can hold, and the parseable half is a `samlp:ArtifactResponse` whose
status is `RequestDenied`, carrying a per-request `ID_<uuid>` and a millisecond
`IssueInstant` - `Pending` under F113 and unrecordable.

Serving the endpoint means serving both, and the second would be a response body
shipped with **no golden under it at all**, which is the rule
`internal/conformance` exists to enforce. Serving only the 500 is the split this
cut has refused twice already. It stays as it was: one `Recorded` case, one
`Pending` one.

### 2.5 `ClearSecurityHeaders` rather than a middleware exception

`WithKeycloakFallbacks` sets the five security headers for every **matched**
route, at the point that tells a request which reached Keycloak's filter chain
from one which did not. `GET /realms/{realm}/protocol/saml` is a matched route -
it answers 405 to `PUT` and 200 with an `Allow` to `OPTIONS` - and sends none of
them.

**Rejected alternative: teach the middleware about the path.** That puts a SAML
fact in the fallback wrapper, where the next reader of either will not look for
it. The exception is expressed where it belongs, in the writer of the one page
family that has it, and `securityHeaders` is now one map so that setting and
clearing cannot come to disagree about which headers "the five" are.

### 2.6 Four `openid-connect` clients in the SAML fixtures, on purpose

`saml-refused-clients` creates a disabled one and a bearer-only one;
`saml-idp-initiated-clients` creates a disabled one and an enabled one. All four
cases that use them are SAML cases.

Making them SAML clients would have been the obvious choice and would have left
§1.1's and §1.8's orderings unpinned: a ladder with the protocol check first
answers a disabled SAML client correctly, because it passes the protocol check and
reaches the enabled one anyway. The whole value of these clients is that their
protocol is wrong.

**The IdP-initiated pair was written the obvious way first and the mutation pass
caught it** - M3 in §5.4. That is the same lesson the endpoint side already had,
arrived at from the other direction, and it is worth keeping because the fixture
that makes a case prove something is not the fixture the case's own sentence
suggests.

### 2.7 `admin/clients/evaluate-example-saml-response`'s reason was narrowed, not promoted

Its first reason read *"Gloak has no SAML assertion builder and no saml-protocol
issuance path"*, qualified by *"it is no longer true that it serves no SAML at
all: `GET .../protocol/saml/descriptor` is served, and it is deliberately the one
SAML response that needs neither"*.

The core of that is still true and is now the whole of it. What expired is the
parenthesis: Gloak serves **twenty-four** SAML responses rather than one. The
comment now says so and says why none of them helps - the descriptor is a pure
function of the realm, and every one of the others is a refusal, a theme page or a
404, which is precisely the class of answer that needs no assertion.

**Reasons 2 and 3 are untouched and are what actually keep the case `Pending`**:
no mask in this harness reaches inside a JSON string, and the body carries two
`ID_<uuid>` attributes and four timestamps. Neither is affected by anything in
this cut, and the case is not promoted.

---

## 3. Refusals, each with the measurement behind it

| What | Measurement | Status |
|---|---|---|
| `saml/endpoint/login-page` | the page carries a per-request `tab_id` and `session_code`; F113. **Sendable since this cut** - §1.2 - and Gloak answers the dispatcher's 404 | `Pending` |
| `saml/endpoint/logout-request-redirect` | 500, 94 bytes of JSON, none of the five. It is Keycloak failing to end a **session that does not exist**; Gloak has no SAML session, and sending it unconditionally answers 500 to a logout that ought to succeed | `Recorded` |
| `saml/endpoint/logout-request-post` | the same failure over the other binding: 500, **empty body**, no `Content-Type`, `Cache-Control: no-cache` | `Recorded` |
| the HTTP-POST binding's XML signature | enveloped, over a canonicalised document; no c14n in the standard library. A POST from a signature-requiring client that carries one falls through rather than being refused | not a case; F229 |
| the success path of both routes | needs a signed SAML assertion and a SAML session store | not servable; F227 |
| `saml/artifact-resolution/request-denied` | `ID="ID_<uuid>"` and a millisecond `IssueInstant` per request; F113 | `Pending`, unchanged |
| `saml/artifact-resolution/empty-body` | serving it means serving its unrecordable sibling too; §2.4 | `Recorded`, unchanged |
| `saml/descriptor/options` | `OPTIONS` 200 with an `Allow`; Gloak 404s `OPTIONS` on every route - F31 | `Recorded`, unchanged |
| `SAMLRequest=%%%%` → 400, empty body, no headers | measured on `/descriptor` and on `/auth` too, so it is the request line and not SAML | not a case; F231 |
| `rsa-sha384` | refused with a correct URI, a correct digest and a verified key. Pinned by a test rather than a golden - no golden can send two SigAlgs | in `sigAlgHashes`' comment |

---

## 4. The record diff, file by file

`make record` was run **four** times: once when the twelve new cases were added,
once after the `destination-mismatch` literal changed, once after the
IdP-initiated fixture's disabled client changed protocol, and once after the
mutation pass asked for the signed-RelayState case. All four are read here,
because the second one is the interesting one.

### Run 1: twelve new goldens and nothing else

```
saml/endpoint/bearer-only-client.http                                    new
saml/endpoint/destination-mismatch.http                                  new
saml/endpoint/disabled-client.http                                       new
saml/endpoint/logout-request-post.http                                   new
saml/endpoint/logout-request-redirect.http                               new
saml/endpoint/no-assertion-consumer-url.http                             new
saml/endpoint/redirect-binding-signature-accepted.http                   new
saml/endpoint/redirect-binding-signature-over-another-message.http       new
saml/endpoint/saml-response-parameter.http                               new
saml/endpoint/unregistered-assertion-consumer-url.http                   new
saml/idp-initiated/disabled-client.http                                  new
saml/idp-initiated/wrong-protocol.http                                   new
```

**Nothing else moved**, which is the half worth stating: the nine goldens this
cut promoted from `Recorded` to `Implemented` were recorded by the first cut and
came back byte-identical, so the promotion compares Gloak against a recording
taken before Gloak served any of it.

Ten of the twelve are 115-line theme pages and two are the LogoutRequest 500s -
a 7-line one and a 5-line one, which is the whole of the empty-bodied POST
answer.

### Run 2: one golden outside this cut moved, and it was reverted

```
admin/identity-providers/mapper-types-unsupported
- HTTP/1.1 500 Internal Server Error
- Content-Type: application/json
- {"error":"unknown_error","error_description":"For more on this error consult the server log."}
+ HTTP/1.1 200 OK
+ Cache-Control: no-cache
+ Content-Type: application/json;charset=UTF-8
+ {"hardcoded-user-session-attribute-idp-mapper":{…}}   six mapper types
```

**Reverted, not committed**, which is F176's precedent exactly: Gloak serves the
500, so recording the 200 turns the tree red, and a recording that disagrees with
a golden is not evidence the golden was wrong.

Here a third draw was taken, which is what F176 says is the only thing that tells
instability from a correction. It says the golden is wrong:

```
a long-running container, 6 draws                200, six mapper types, every draw
a brand-new container, the very first such call  200, six mapper types
the fixture's exact create body                  200, six mapper types
providerId openshift-v4, 4 draws                 500, every draw
```

Ten draws across three containers, including one where the request was the first
thing that touched the provider, and `linkedin-openid-connect` never answered a
500. The case's own comment says *"two of the seventeen answer this route with a
500 - `linkedin-openid-connect` and `openshift-v4`"*; only the second does.

So the 500 the recorder saw is **order-dependent inside the recorder**, and there
is a visible mechanism to look at first: the fixtures share one `internalId`
space and at least two values literally collide -
`1de07000-0000-4000-8000-000000000020` and `…021` are minted both by
`idp-mt-oidc`/`idp-mt-saml` and by the listing fixture's `strand`/`zzz` loop, and
the creates accept a 409 through `idempotentCreate`. It is not this cut's case
and not this cut's change; F230.

### Runs 3 and 4, and a fourth draw on the same golden

```
run 3  (after the IdP-initiated fixture's client changed protocol)   no diff at all
run 4  (after the signed-RelayState case)
       saml/endpoint/redirect-binding-signature-over-a-relay-state   new
```

Run 3 is worth stating because it changed a fixture and moved nothing:
`saml/idp-initiated/disabled-client`'s client went from `protocol: saml` to
`protocol: openid-connect`, and its golden is **byte-identical** either way -
3573 bytes, because the page names no client. So a case that proved nothing about
the ladder's order now proves it, with no byte moving. §5.4 is why that matters.

And the four runs are four draws on `mapper-types-unsupported`:

```
run 1   500, agrees with the committed golden
run 2   200, the diff above
run 3   500
run 4   500
```

One anomalous run in four, from inside the recorder, against ten direct draws
that say 200. Both halves are in F230, because neither on its own is the finding:
the recorder's 500 is not reproducible outside it, and the committed golden
claims a sentence the endpoint does not send.

---

## 5. The mutation pass

Applied to the tree, the diff checked non-empty, `go build ./...` checked to
succeed, then **`internal/oidc`, `internal/httpx` and `internal/conformance` run
separately and in full** - no `-run` filter anywhere in the pass, because
AGENTS.md records one having hidden both a killer and a survivor. The revert is
on an `atexit` hook and a signal handler rather than the happy path, the tree was
committed and clean before the pass began, and the revert is verified with
`git status --porcelain` after every mutation.

Running the three packages concurrently is not the filtered `-run` that rule
warns about: every test in every package still runs, and the three invocations
are separate processes reading a tree nothing writes to while they run.

**Twenty-nine mutations. Three survived, two would not build, and all five are
fixed and now killed - there are no standing survivors.** Each of the three
survivors named a missing input or a missing ratchet, and §5.4 is what was done
about each.

### The ladder's order and the client lookup

| # | Mutation | Result |
|---|---|---|
| M1 | the protocol check moves ahead of the enabled one | killed by `saml/endpoint/disabled-client` and `TestSAMLEndpointWalksTheLadderInTheMeasuredOrder` |
| M2 | the protocol check moves ahead of the bearer-only one alone | killed by `saml/endpoint/bearer-only-client` |
| M3 | the IdP-initiated route checks the protocol before the enabled flag | **survived; fixed** - see §5.4 |
| M4 | the IdP-initiated lookup uses the `clientId` | killed by `saml/idp-initiated/client-id-is-not-the-name` |
| M5 | the IdP-initiated lookup filters by protocol | killed by `saml/idp-initiated/wrong-protocol` |
| M26 | the chrome names the client on every rung | killed by `redirect-binding-wrong-protocol`, `disabled-client` and `bearer-only-client` |
| M27 | the chrome names no client on the signature rung | killed by `redirect-binding-saml-client` and both signature cases |

### The signature

| # | Mutation | Result |
|---|---|---|
| M6 | `saml.client.signature` read the way `Boolean.parseBoolean` does | killed by `TestClientRequiresSignatureComparesTheExactString` |
| M7 | **the verifier refuses every signature** | killed by `saml/endpoint/redirect-binding-signature-accepted`, `TestRedirectSignatureVerifies` and `TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs` |
| M8 | the verifier accepts any request carrying both parameters | killed by `redirect-binding-signature-over-another-message` and `TestRedirectSignatureVerifies` |
| M9 | `rsa-sha384` added to `sigAlgHashes` alone | **survived; ratchet added** - see §5.4 |
| M9b | `rsa-sha384` added to **both** the map and `newSigAlgHash`'s switch | killed by `TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs` |
| M10 | the signed string rebuilt from decoded values | **survived; case added** - see §5.4 |
| M28 | the POST binding reports its signature verified | killed by `saml/endpoint/post-binding-saml-client` |

**M7 is the one the brief asked about by name.** A verifier that rejects
everything is the worst case for "a set of assertions an incorrect implementation
satisfies entirely", and the answer is that **three** things die when
verification is disabled: the golden
`saml/endpoint/redirect-binding-signature-accepted`, and the two package tests
`TestRedirectSignatureVerifies` and
`TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs`. The golden is the one
that matters, because it is a recording of Keycloak rather than a restatement of
Gloak: a correctly signed request answers `Invalid Request` with the client
named, and a reject-everything verifier answers `Invalid requester`, which is a
different 3606-byte page.

M8 is its mirror and says which assertion does which job: an
accept-everything verifier passes M7's case and fails M8's.

### The `Destination` and the assertion consumer URL

| # | Mutation | Result |
|---|---|---|
| M11 | a `Destination` is always required | killed by `saml/endpoint/no-assertion-consumer-url` and two package tests |
| M12 | a `Destination` is never required | killed by `saml/endpoint/redirect-binding-signature-accepted` and `TestSAMLDestinationIsRequiredOnlyWhenTheRequestIsSigned` |
| M13 | the `Destination` compared by origin rather than in full | killed by `saml/endpoint/destination-mismatch` |
| M14 | a named assertion consumer URL is ignored | killed by three package tests, **and by no golden** |
| M15 | an unmatched named ACS falls back to the attribute | killed by `TestSAMLAssertionConsumerURLCrossesItsTwoSources`, **and by no golden** |
| M16 | a named assertion consumer URL accepted unchecked | killed by `saml/endpoint/unregistered-assertion-consumer-url` |
| M25 | a request that passes every rung is refused instead of falling through | killed by `TestSAMLEndpointDoesNotRefuseARequestItCannotServe`, **and by no golden** |

M14, M15 and M25 are the three that no golden catches, and they are the same
hole stated three ways: **every case in this chapter is a rejection**, so an
implementation that refuses more than Keycloak does satisfies all of them. That
is why those three tests exist and why §2.2's fall-through is a package test
rather than a case.

### The parser and the bindings

| # | Mutation | Result |
|---|---|---|
| M17 | the first `Issuer` wins rather than the last | killed by `TestParseSAMLMessageAcceptsWhatKeycloakAccepts` |
| M18 | the `Version` attribute is not checked | killed by `TestParseSAMLMessageRefusesWhatKeycloakRefuses` |
| M19 | a nested `Issuer` is found | killed by the same |
| M20 | `SAMLResponse` is read when `SAMLRequest` is absent | killed by `saml/endpoint/saml-response-parameter` |
| M21 | the POST binding decodes the redirect binding's spelling | killed by `saml/endpoint/post-binding-saml-client` |

### The page writers

| # | Mutation | Result |
|---|---|---|
| M22 | the endpoint's page keeps the five security headers | killed by every `saml/endpoint` page golden |
| M23 | both verbs answer one `Cache-Control` | killed by `post-no-parameters`, `post-binding-saml-client` and `TestSAMLPagesSendTheirMeasuredHeaderSets` |
| M24 | the IdP-initiated page uses the endpoint's header set | killed by all five `saml/idp-initiated` goldens and the same test |

### 5.4 The three survivors, and what was done about each

**M3 - a disabled SAML client cannot tell the IdP-initiated route's two orders
apart.** Swapping the route's enabled and protocol checks survived the whole
tree. Reading the mutated lines says why: `saml/idp-initiated/disabled-client`
used a **SAML** client, so a protocol-first ladder passes the protocol check and
reaches the enabled one anyway and gives the same sentence; and
`wrong-protocol`'s client is enabled, so it never reaches the enabled check under
either order. An implementation satisfying both is one that checks the protocol
first - which is wrong on exactly one input, a disabled client whose protocol is
also wrong.

Fixed by giving the fixture's disabled client `protocol: openid-connect`, which
is the input §1.8 measured answering `Client disabled.` **The golden did not
change** - 3573 bytes either way, because the page names no client - so this is a
case that went from proving nothing to proving the order without a single byte
moving, which is worth knowing for the next reader of it. M3 is now killed by
`saml/idp-initiated/disabled-client`.

The endpoint side already had this right, and not by luck:
`saml-refused-clients` creates two `openid-connect` clients on purpose, and M1
and M2 die on them. The IdP-initiated fixture was written the obvious way and the
pass is what caught the difference.

**M9 - `sigAlgHashes` is half the gate and nothing said so.** Adding `rsa-sha384`
to the map alone survived, and it survived *correctly*: `newSigAlgHash`'s switch
does not know SHA-384, hands back a nil hash, and `verifyRedirectSignature`
refuses the request anyway. The edit changed text and not behaviour.

**That is F208's shape**, and it is the one a mutation pass is least able to
report honestly - it lands in the survivor column looking like a coverage hole
when it is not one. The first cut met the same thing as its M25 and concluded no
check could catch it. That is true of a semantically null edit in general and
**not** true of this one, because here the nullity has a cause: two lists that
have to agree and nothing comparing them.

`TestSigAlgHashesAndNewSigAlgHashAgree` is the ratchet, and it asserts both
directions - a digest the map names must be one this build can hash with, and a
digest this build can hash with must be one the map names - plus the count, which
is the measurement. M9 is now killed by it, and M9b, which adds the digest to
**both** halves and is therefore a real mutation, is killed by
`TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs`.

So the pair is the useful result: the null edit is now caught by a ratchet and
the real edit by the measurement, and they are caught by different tests.

**M10 - every signed literal in the catalogue was escaped by Go, so a Go
re-encoding reproduced all of them.** Rebuilding the signed string from
`url.ParseQuery` + `url.QueryEscape` instead of from the raw query survived.
Reading the mutated lines says exactly what an implementation satisfying it looks
like: one that round-trips the percent-encoding through Go's own escaper, which
is right for every client whose escaping matches Go's and wrong for every client
whose does not. The sharp character is a space - `url.QueryEscape` writes `+`
where a great many clients write `%20` - and the parameter a space realistically
appears in is `RelayState`.

Measured, both directions, on one container:

```
RelayState=gloak%20relay%20state, signature made over that spelling   accepted
the same query and signature with `+` substituted for `%20`           Invalid requester
```

So Keycloak does not normalise either, and the input that kills M10 is a signed
`RelayState` spelled with `%20`. Added as
`saml/endpoint/redirect-binding-signature-over-a-relay-state`, with the refusing
half asserted in `TestRedirectSignatureVerifies` rather than as a second golden
because its bytes are the tampered case's. M10 is now killed by both.

### 5.5 Two mutations that would not build, and one harness rule earned

M7 and M11 were first written as `return false` and `return false`, which left
`crypto/rsa` and a local variable unused. The harness **refused** them - it
builds before it tests, for the reason AGENTS.md records - and both were rewritten
to keep the reference and then killed. A build failure reported as a survivor
would have been the fifth false-pass shape this project has collected.

**The harness earned one new rule, and it earned it by firing.** The pass aborted
at M1 with `revert failed`, and the cause was me: the handover document was being
written into the tree while the pass was running, so `git status --porcelain`
after the revert was not clean. The mutation itself had been reverted correctly by
the exit hook; what the check caught was a *different* edit to the tree.

That is AGENTS.md's "a pass leaves the tree dirty **by design**, so the dangerous
window is the one the discipline itself creates" met from the other side. The
existing rule says commit before the pass and do not stage by wildcard during one;
the new half is **do not write to the tree during one at all, including files the
pass has nothing to do with** - and the check that catches it is comparing the
*whole* tree rather than the mutated file, which is what this harness already did
and what made the abort a stop rather than a wrong result.

Nothing was lost, because everything up to that point was committed.

---

## 6. Parity

Measured with the procedure AGENTS.md documents, against the merge base
`3626de0`:

```
Parity: 578 -> 598 of 644 (+20)

chapter                         before  after  delta
saml/endpoint                        2     17    +15
saml/idp-initiated                   0      5     +5
```

The chapter table:

```
chapter                              served  recorded  documented  source
saml/descriptor                           3         1           4  catalogue
saml/endpoint                            17         2          20  catalogue
saml/idp-initiated                        5         0           5  catalogue
saml/artifact-resolution                  0         1           2  catalogue

total: 598 of 644 enumerated behaviours served; 2 chapters not enumerated
```

**The denominator moved by 13 and the numerator by 20**, and the arithmetic is
worth setting out because the two do not obviously reconcile:

- **nine promotions** from `Recorded` to `Implemented` - six on the endpoint,
  three on the IdP-initiated route - which move the numerator and not the
  denominator;
- **eleven new served cases**, which move both;
- **two new `Recorded` cases**, the LogoutRequest 500s, which move the
  denominator alone.

9 + 11 = 20 on the numerator; 11 + 2 = 13 on the denominator.

The eleventh served case is
`saml/endpoint/redirect-binding-signature-over-a-relay-state`, which the mutation
pass asked for rather than the enumeration: it is the input that kills M10, and
§5.4 is why it exists.

`saml/idp-initiated` is the first SAML chapter at 5 of 5. `saml/endpoint` is 17
of 20: the three left are the login page, which cannot be recorded, and the two
LogoutRequests, which are refused with their measurement.

Measured with `cmd/parity` **built** rather than `go run`, which AGENTS.md gives
the reason for: `go run` collapses exit 2 down to 1 and would make a real parity
decrease indistinguishable from a report it could not read. Exit code 0.

---

## 7. Entries for AGENTS.md

### Replacing the "Invalid requester" bullet, which has the ladder wrong

> **The SAML endpoint's rejection ladder is seven rungs and two of them are not
> where a reader would put them.** In order: the message will not decode or parse
> (`Invalid Request`), its `Issuer` names no client (`Invalid Request`), the
> client is **disabled** (`Login requester not enabled`, no full stop), the
> client is **bearer-only** (`Bearer-only applications are not allowed to
> initiate browser login`), its protocol is not `saml` (`Wrong client
> protocol.`), the signature does not verify (`Invalid requester`), the
> `Destination` is wrong (`Invalid Request`), no assertion consumer URL resolves
> (`Invalid redirect uri`), and then the login page. **The disabled and
> bearer-only rungs run *before* the protocol check** - measured on a disabled
> `openid-connect` client and a bearer-only one, both of which answer their own
> sentence rather than `Wrong client protocol.` - so a ladder written as "client,
> protocol, signature" puts two checks on the wrong side. The page's chrome names
> the client from the signature rung up and on no rung below it, although the
> three rungs below have resolved one.

### For the same bullet, replacing "the Destination is validated"

> **An `AuthnRequest` needs no `Destination`, and the predicate is the request's
> `Signature` parameter rather than the client's flag.** A message with no
> `Destination` attribute, and one with `Destination=""`, both reach the login
> page; one naming the wrong port is `Invalid Request`. A message carrying a
> `Signature` parameter must have a non-empty one - measured on a client with
> `saml.client.signature` **off** sent a junk signature, which answers the
> `Destination` sentence and not `Invalid requester`, so the signature is not
> even looked at and the `Destination` is demanded anyway. When it is compared it
> is compared as a string: a trailing slash, `https` for `http`, `127.0.0.1` for
> `localhost`, the port left off, an appended query, another realm and another
> path are all refused. **This is what makes the endpoint reachable from a
> catalogue at all** - the port comes out of the message, so a literal
> `AuthnRequest` works on whatever port testcontainers maps, and F175's fixture
> field was refuted rather than built.

### A new bullet, for the signature

> **The SAML redirect binding's signature is really verified, and the accepted
> `SigAlg` set is three rather than the four SAML defines.** `rsa-sha1`,
> `rsa-sha256` and `rsa-sha512` are accepted; **`rsa-sha384` is refused** with a
> correct URI, a correct digest and the same certificate the sha256 request
> verified against, and the client's own `saml.signature.algorithm` does not
> change it. A `SigAlg` naming sha256 with a SHA-512 signature under it is
> refused too, so the URI decides the digest. **The bytes signed are the raw query
> parameters as sent**, joined with `&` in the order SAMLRequest, RelayState,
> SigAlg, and the escaping is not normalised in either direction:
> `RelayState=gloak%20relay%20state` signed over that spelling is accepted and the
> same query and signature with `+` for `%20` is `Invalid requester`. A verifier
> that decodes the parameters and re-encodes them with `url.QueryEscape` writes
> `+` for both and gets the first wrong -
> `saml/endpoint/redirect-binding-signature-over-a-relay-state` is the only case
> in the tree that sees it, and it exists because a mutation pass asked for it.
> **`saml.client.signature` is compared to the exact string `"true"`,
> case-sensitively.** `"TRUE"`, `"True"`, `" true"`, `"0"`, `"no"`, `""` and the
> attribute absent are all **off**. `strconv.ParseBool` is wrong on `"TRUE"` -
> and so is copying Java's own idiom, because `Boolean.parseBoolean("TRUE")` is
> `true` and this is not.

### A new bullet, for the assertion consumer URL

> **A SAML assertion consumer URL has two sources and they do not compose.** A
> message naming an `AssertionConsumerServiceURL` is checked against the client's
> **`redirectUris`**, by the same predicate an OIDC `redirect_uri` goes through -
> all seven of its sharp cells re-measured and agreeing. A message naming **none**
> falls back to the client's `saml_assertion_consumer_url_post` or
> `…_redirect` attribute, which is checked against nothing. So a client whose
> only assertion consumer URL is that attribute, sent a message naming that same
> URL, is **refused** - the cell a reader gets wrong, and the one
> `saml/endpoint/unregistered-assertion-consumer-url` exists for.

### Extending the IdP-initiated bullet

> **The IdP-initiated route is a three-rung ladder and the name is looked up
> across protocols.** An enabled `openid-connect` client carrying
> `saml_idp_initiated_sso_url_name` answers `Wrong client protocol.` and not
> `Client not found.`, so filtering the scan by protocol - which reads as a
> safety improvement - is wrong. A **disabled** client carrying it answers
> `Client disabled.`, before the protocol check. And one client in one state gets
> two sentences from the two routes: `Client disabled.` here and `Login requester
> not enabled` on `/protocol/saml` one segment up, with opposite header sets.

### For the `Cache-Control` bullet

> **`/realms/{realm}/protocol/saml` pins its `Cache-Control` per endpoint *and
> verb*.** Every GET answer - all six 400 pages and the 500 - sends `no-store,
> must-revalidate, max-age=0`; every POST answer sends `no-cache`. Same path,
> same body, two verbs, two values, which the committed goldens
> `saml/endpoint/no-parameters` and `saml/endpoint/post-no-parameters` have shown
> since 2026-09-07 without anything saying so.

### For the security-headers bullet, extending the SAML exception

> **The "none of the five" exception on `/realms/{realm}/protocol/saml` is the
> whole route and not its HTML pages.** A `LogoutRequest` that reaches the top of
> the ladder answers `500 {"error":"unknown_error","error_description":"For more
> on this error consult the server log."}`, `application/json`, 94 bytes, with
> `Cache-Control: no-store, must-revalidate, max-age=0` and **none** of the five -
> the first JSON body measured carrying this endpoint's header set. Over the
> HTTP-POST binding the same failure is a 500 with an **empty body**, no
> `Content-Type` at all, and `Cache-Control: no-cache`.

### A new bullet, for SAML single logout

> **`/realms/{realm}/protocol/saml` serves both bindings of SSO and SLO, and a
> `LogoutRequest` walks the identical ladder.** All seven rungs answer the same
> sentences to the same inputs; the two message types diverge only at the top,
> where an `AuthnRequest` gets the login page and a `LogoutRequest` gets a 500.
> That 500 is a session that does not exist failing to end, which is why it is
> `Recorded` rather than served: a handler sending it whenever a `LogoutRequest`
> arrives answers 500 to a logout that ought to succeed.

### For the "things that look like bugs" list

> **A SAML message's `Issuer` is read last-one-wins.** An `AuthnRequest` carrying
> `<Issuer>account</Issuer><Issuer>a-saml-client</Issuer>` is served from the
> **second**, which is JAXB overwriting a field it has already set. The `Issuer`'s
> namespace is ignored entirely - the assertion namespace, a default `xmlns` and
> no namespace at all all resolve - but it must be a **direct child**: one nested
> inside `<Extensions>` is `Invalid Request`. The **root** is strict where the
> child is not: it must be in the SAML protocol namespace, spelled
> `AuthnRequest` case-sensitively, with `ID`, `Version="2.0"` and `IssueInstant`
> all present.

### For the build section

> **`crypto/*` and `encoding/xml` cover the redirect binding's signature and not
> the POST binding's.** The redirect binding signs a query string, which is
> `crypto/rsa` plus `crypto/x509` over the client's `saml.signing.certificate`.
> The POST binding's is an **enveloped XML signature over a canonicalised
> document**, and nothing in the standard library canonicalises XML. So Gloak
> verifies one binding and reports the other unverified rather than refused - a
> POST carrying a signature falls through to the 404 instead of being told its
> signature is bad. See F229.

### For the mutation-discipline paragraph, two halves

> **Do not write to the tree during a mutation pass at all, including files the
> pass has nothing to do with.** The existing rules are "commit before the pass"
> and "never stage by wildcard during one"; this is the third and it is the one
> that fires. P11's pass aborted at its first mutation with `revert failed`
> because a handover document was being written while it ran, so the tree was
> dirty after a revert that had worked perfectly. The check that caught it
> compares the **whole** tree rather than the mutated file, which is what turned a
> wrong result into a stop - and nothing was lost, because everything up to that
> point was committed.

> **F208's null edit sometimes has a cause, and then a ratchet can catch it.**
> Adding a fourth digest to `sigAlgHashes` changed text and not behaviour, because
> `newSigAlgHash`'s switch is the other half of the gate and does not know it -
> so the mutation "survived" correctly and uselessly, in the same column as a real
> finding. The general rule stands: a semantically null edit is a mutation only a
> reader can rule out. But **this** one was null for a reason - two lists that have
> to agree and nothing comparing them - and
> `TestSigAlgHashesAndNewSigAlgHashAgree` makes the pair one claim, after which
> the null edit fails and the edit that changes both halves is a real mutation a
> measurement kills. Before filing a null edit under F208, check whether its
> nullity is an invariant nobody wrote down.

### A correction to the SAML client bullet

> `POST /admin/realms/{realm}/clients` with `{"protocol":"saml"}` generates
> **fourteen** attributes, counted from the response on 2026-09-11. The figure
> recorded here was fifteen.

---

## 8. Follow-ups, numbered from F227

### F227 - the SAML assertion builder and the SAML session store, which are one cut

Everything left in this chapter is behind one thing: Gloak can read a SAML
request and refuse it correctly, and cannot answer one. Three behaviours need the
same two pieces.

- **`saml/endpoint/login-page`.** A request that passes every rung answers a
  login page over the HTTP-Redirect binding and a **302 into
  `/login-actions/authenticate`** over the HTTP-POST binding - measured
  2026-09-11, and the two bindings really do differ there, which is a second
  finding the first cut's 72 pairs did not hold. Finishing the flow means an
  authentication session carrying the request's `ID`, its `RelayState` and its
  resolved assertion consumer URL, and an ending that builds a signed
  `samlp:Response` and posts it.
- **The two `LogoutRequest` 500s.** They are Keycloak failing to end a session
  that does not exist. Serving them means having sessions that can exist.
- **The signed-request `Destination`.** A signed message must name the server's
  own URL, so a catalogue case that walks past the `Destination` rung **with** a
  signature needs a signature computed against the recorder's base URL - which is
  F175's field, with a consumer this time. It is filed here rather than left open
  as F175 because the argument for it is now a different argument: not "no
  literal works", but "no literal works *for the signed case above the
  `Destination` rung*". Nothing today needs that, and the day something does it
  should be built then.

The order matters: the assertion builder is what makes the login page's ending
true, and the session store is what makes the logout 500s true. Neither is
worth building without the other.

### F228 - `saml.force.post.binding` and the response bindings were not measured

Every created SAML client carries `saml.force.post.binding: "true"`, and the
descriptor advertises four `SingleSignOnService` bindings. Nothing in this cut
sent a request that reaches the point where the response binding is chosen,
because that point is past the login page.

It is filed rather than swept because the attribute is on by default, so
whatever it does is what a default client gets, and a builder written without
measuring it will be wrong on every client nobody configured.

### F229 - the HTTP-POST binding's XML signature is not verified

`verifySAMLSignature` reports a POST **unverified** rather than refused, so a
POST carrying a `<ds:Signature>` from a client requiring one falls through to the
404 rather than getting `Invalid requester`. Every unsigned POST is answered
correctly, which is why `saml/endpoint/post-binding-saml-client` is served and
matches.

The gap is exclusive canonicalisation. Before reaching for a module, the rule at
the top of AGENTS.md applies as the first cut applied it to `encoding/xml`:
**prove with bytes** that the standard library cannot do it, and make the
refutation a test. The shape is `TestEncodingXMLCannotEmitTheDescriptor`'s.

The measured input this needs is one nobody has sent: a **correctly signed**
HTTP-POST `AuthnRequest`. This cut signed the redirect binding and did not sign
the POST one, so what Keycloak answers a valid POST signature is measured by
inference only - the client's `saml.client.signature` is one flag for both
bindings and an unsigned POST is `Invalid requester`, which says the check runs,
and nothing says what passing it looks like.

### F230 - a golden that moves between recorder runs, and a shared `internalId` space

`admin/identity-providers/mapper-types-unsupported` recorded a 500 on one
`make record` run and a 200 on the next, on the same tree. Reverted; §4 has the
diff and the third draw.

**The third draw says the golden is wrong.** Ten requests across three
containers, one of them brand new with the request as the first thing to touch
the provider, all answered 200 with six mapper types for
`linkedin-openid-connect`. `openshift-v4` answers the 500 on four draws. The
case's comment claims both providers do.

The mechanism to look at first is that the identity-provider fixtures share one
`internalId` space with literal collisions:
`1de07000-0000-4000-8000-000000000020` and `…021` are minted both by
`idp-mt-oidc`/`idp-mt-saml` and by the listing fixture's `strand`/`zzz` loop,
and every one of those creates accepts a 409 through `idempotentCreate`. A
fixture whose create silently collides leaves a different resource behind than
the case thinks, and which one wins is decided by the order the recorder happens
to run in.

Two things to settle, in this order: whether the 500 can be reproduced at all on
a container where nothing else ran, and whether the collisions are the reason.
The second is cheap to test - give every fixture its own suffix and re-record.

### F231 - a malformed percent-escape is a 400 with no body, and it is the whole server's

`?x=%%%%` and `?x=%zz` answer `400` with an **empty body and no headers at all**,
measured on `/protocol/saml`, `/protocol/saml/descriptor` and
`/protocol/openid-connect/auth`. It is the request line being rejected before
anything routes, which puts it beside `missingNormalization` rather than beside
this chapter.

It is not SAML's and was not built here, for the reason the first cut gave F177
and F178: a rule of the whole surface fixed inside a SAML branch is a change
reaching every path for one instance of it. What to measure first is whether it
reaches the Admin API and whether the malformed escape has to be in the query -
a malformed escape in the **path** is a different code path and was not sent.

### F175 - refuted, not deferred

See §2.1. Both halves of its argument were measured false. The entry should be
closed with the measurement rather than carried: an `AuthnRequest` needs no
`Destination`, and a client's signing certificate is an ordinary attribute a
fixture can install, so both the message and a signature over it are literals.

F227's third bullet is the one thing a run-time field would still buy, and it has
no consumer today.

### F208 - not closed, but its first exception is recorded

M9 in §5.4 is F208's shape and it is **not** an instance of F208's conclusion.
The entry says a mutation that changes text without changing behaviour passes
every empty-diff guard and then passes the tests, and that only a reader can rule
it out. That is right in general.

This one was null because two lists had to agree and nothing compared them, and
a ratchet catches it. So the entry gains a question rather than a closure:
**before filing a null edit under F208, check whether its nullity is an invariant
nobody wrote down.** If it is, the ratchet is cheap and the next pass gets a real
answer instead of a shrug.

### F113 - unchanged, and applied three more times

`saml/endpoint/login-page` stays `Pending` under it - the page carries a
per-request `tab_id` and a `session_code`. `saml/artifact-resolution/request-
denied` is unchanged. And the rule was **checked and found not to apply** to
every one of the sixteen pages this cut serves: none of them holds a `tab_id`, a
`session_code` or an `execution`, and two fetches a second apart are
byte-identical, which is what `TestThemeResourceAppearsOnlyInTheThemePages`'
seven-segment count now records for nineteen SAML goldens.

### F31 - unchanged, and one cell narrowed

`saml/descriptor/options` is still `Recorded`. The routes this cut adds are
registered `GET` and `POST` explicitly rather than as a bare pattern, so `PUT`,
`DELETE`, `PATCH` and `OPTIONS` on `/protocol/saml` still reach
`protocolDispatch` and answer exactly what they answered before.

### F122 - not met from a third side after all

The first cut filed the login page as F122's boundary met a third time: a value
the harness cannot mint. It is not. The value did not need minting; the
measurement that said it did was wrong. The two sides F122 really has - CIBA's
inbound callout and the back-channel logout - are unchanged.

---

## 9. What is left

- **The success path of both routes**, which is F227 and is the whole of what
  `saml/endpoint` and `saml/idp-initiated` still cannot answer. Seventeen of
  twenty and five of five are served; the three left are one page that cannot
  be recorded and two 500s that must not be sent.
- **The artifact resolution service**, unchanged and for an unchanged reason:
  §2.4.
- **The ECP flow.** `saml.allow.ecp.flow` is `"false"` on every created SAML
  client and nothing was sent to it, as in the first cut.
- **`saml.force.post.binding` and the response bindings**, F228 - the first thing
  an assertion builder will have to measure.
- **F230's recorder instability**, which is not SAML's and is the one thing in
  this cut's record diff that a reader should not take at face value.
