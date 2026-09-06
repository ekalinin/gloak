# CIBA and DPoP: one taken, one refused

Five unserved protocol cases carried two reasons. Both were re-checked on
2026-09-06 by the cut before this one and both held. This cut asked what would
lift each, costed it, and took one.

**DPoP is built.** Its reason was true about the 200 and wrong about everything
else: every structural check on a proof runs before the `iat` window and the
`jti` cache, the window is forty seconds wide, and what was missing was one
computed value rather than a faster harness.

**CIBA stays refused, and its three reasons are rewritten.** One startup option
lifts the 503 and the whole flow then completes - measured, not reasoned - and
what stands between that and a recording is two files this stream does not own
and one direction the harness has not got.

Everything below was measured against live Keycloak 26.7.1 containers started
for this cut and removed at the end of it. Two were used, `kc-dpop` on 8180 with
a bare `start-dev` and `kc-ciba` on 8181 with one option added.

## 1. What was measured

### 1.1 A default container binds a token to any proof it is sent

`GET /admin/serverinfo` reports **both** features as `"type":"DEFAULT"`,
`"enabled":true`:

```
CIBA   OpenID Connect Client Initiated Backchannel Authentication (CIBA)
DPOP   OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
```

so nothing was switched on for any of this, and a refusal from either is a
contract rather than a disabled preview.

A proof signed ES256 answers the password grant 200 on `admin-cli`, which
carries **no** `dpop.bound.access.tokens` attribute. `token_type` is `DPoP`
where the identical request without the header answers `Bearer`. So
verification follows the **header**, not the client.

`cnf` is `{"jkt":"…","kc-jkt-type":"DPoP"}` - two keys, and the second is
Keycloak's own - on the access **and** refresh tokens, immediately before
`scope` on both, and on the ID token not at all:

```
access   exp iat jti iss typ azp sid cnf scope                        (lightweight)
access   … sid acr realm_access resource_access cnf scope email_verified …
refresh  exp iat jti iss aud sub typ azp sid cnf scope aud_x prov
id       exp iat jti iss aud sub typ azp sid at_hash acr …            (no cnf)
```

### 1.2 The ladder, and its order

Twelve refusals, all 400. Eleven are `invalid_request` on the token endpoint and
the twelfth is the refresh grant's `invalid_grant`:

```
not a JWT at all               DPoP header verification failure
typ: JWT / DPOP+JWT / ""       Invalid or missing type in DPoP header: <typ>
typ absent                     Invalid or missing type in DPoP header: null
alg: none / HS256              Unsupported DPoP algorithm: <alg>
no jwk in the header           No JWK in DPoP header
alg EdDSA or RS256, EC key     Key with algorithm <alg> and type EC is incorrect
                               for provider algorithm <alg>
alg ES384 over a P-256 key     DPoP verification failure: org.keycloak.common.\
                               VerificationException: Signing failed
signature does not verify      DPoP verification failure: org.keycloak.exceptions.\
                               TokenSignatureInvalidException: Invalid token signature
htm, htu, iat or jti absent    DPoP mandatory claims are missing
htu names another URL          DPoP HTTP URL mismatch
htm names another method       DPoP HTTP method mismatch
iat outside the window         DPoP proof is not active
the same jti twice             DPoP proof has already been used
the header present and empty   DPoP proof is missing
```

Three of them are one sentence apart and none is interchangeable: **an absent
`typ` interpolates the literal word `null`** where an empty one interpolates
nothing, and the three verification failures are a key-type message, a curve
message and a signature message, two of which name a Java class.

**The order was measured by nine proofs each wrong in two ways**: `typ`, then
`alg`, then the `jwk`, then the signature, then the mandatory claims, then
**`htu` before `htm`**, then `iat`, then `jti`. A proof with a broken signature
and a wrong `htm` answers about the signature; one wrong about both the URL and
the method answers about the URL.

And the check's place in the endpoint, by four more requests wrong in two ways:
`grant_type` presence, `grant_type` membership, client authentication, the
duplicated parameter, **then the proof**, then the grant's own work. A bad proof
with an unknown `client_id` is `invalid_client`; with `zz` twice it is
`duplicated parameter`; with a wrong password it is about the proof. It is one
check for every grant - `password`, `client_credentials`, `refresh_token`, the
device grant and CIBA all answer the same sentence for the same bad header.

### 1.3 The window is forty seconds wide, and its lowest second is a 500

Measured at one second's resolution, each request with a fresh `jti`, against a
container whose clock agreed with the host's to the second:

```
iat  now-26 and older     400  DPoP proof is not active
iat  now-25               500  For more on this error consult the server log.
iat  now-24 … now+15      200
iat  now+16 and later     400  DPoP proof is not active
```

`[now-25, now+15]` is exactly a lifetime of 10 and a skew of 15, and the 500 at
the bottom edge is what a single-use cache entry whose remaining life computes
to zero does. Gloak reproduces the window and **not** the 500; see §3.

The first sweep of this looked non-monotonic - `-29` refused, `-25` a 500,
`-21` accepted - and reading it as noise would have been wrong. It is one
window with a defect on its edge.

### 1.4 A refresh token carries the binding, and the attribute is a separate switch

One bound refresh token, refreshed three ways:

```
a proof from the same key      200, the same cnf.jkt
a proof from another key       400  invalid_grant  DPoP confirmation doesn't match DPoP proof
no proof at all                400  invalid_grant  DPoP proof is missing
```

A client carrying `dpop.bound.access.tokens: "true"` answers a request with no
header at all `DPoP proof is missing`, and one carrying `not-a-proof` the
ordinary header failure - so the attribute makes the header **mandatory** rather
than switching verification on.

### 1.5 A probe of the empty header measured curl, and the recorder caught it

`curl -H "DPoP;"` answered 400 `DPoP proof is missing` and `curl -H "DPoP:  "`
answered **200 with a Bearer token**, on the same client, seconds apart. HTTP
trims a field value's surrounding whitespace, so those two requests cannot
differ on the wire - and they did not. `curl` **drops** a header written
`-H "Name:  "` rather than sending an empty one, so the 200 was curl's answer to
a request it never made.

Re-sent with `http.client`, spelling the bytes:

```
no header at all   200  Bearer
""                 400  DPoP proof is missing
" "                400  DPoP proof is missing
"   "              400  DPoP proof is missing
"\t"               400  DPoP proof is missing
```

**A header that is present and empty is a refusal where a header that is absent
is a 200**, on a client that requires nothing.

### 1.6 The resource-server half, measured and not built

`userinfo` cannot be measured with `admin-cli`, and the control is what says so:

```
unbound token + Bearer            401  Lightweight access token not allowed for userinfo endpoint
bound token + DPoP + ath proof    401  Lightweight access token not allowed for userinfo endpoint
bound token + a proof with no ath 401  Token verification failed
bound token + no proof            401  Token verification failed
bound token + Bearer scheme       401  Token verification failed
bound token + another key's proof 401  Token verification failed
```

Three facts survive that: **`ath` is required**, a bound token presented as a
`Bearer` is refused, and the DPoP check runs **before** the lightweight-token
refusal - which is why the one correct row gets further than the other four. The
`WWW-Authenticate` scheme echoes the request's, and the DPoP one carries
`algs="PS384 RS384 EdDSA ES384 ES256 RS256 ES512 PS256 PS512 RS512"` before
`realm`. Filed rather than built: no case wants it and measuring one needs a
non-lightweight client with `openid`.

### 1.7 CIBA completes, and the difference between the two containers is one flag

A second container was started with

```
--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri=\
  http://host.docker.internal:9099/ciba
--add-host=host.docker.internal:host-gateway
```

and a listener on the host. The container called out to it:

```
POST /ciba
  Authorization: Bearer <RS256 JWT, azp=gloak-probe-ciba, aud=the realm's issuer>
  Content-Type: application/json
  {"scope":"openid roles profile email","binding_message":"gloak-probe",
   "login_hint":"admin","is_consent_required":false}
```

The listener answered 201 and replayed that bearer to
`POST /realms/master/protocol/openid-connect/ext/ciba/auth/callback` with
`{"status":"SUCCEED"}`. The flow completed:

```
authentication request  200  {"auth_req_id":"<JWE>","expires_in":120,"interval":5}
poll, pending           400  authorization_pending | The authorization request is still
                             pending as the end-user hasn't yet been authenticated.
poll again, at once     400  slow_down | too early to access
poll after approval     200  nine keys, token_type Bearer, expires_in 60,
                             scope "openid email profile"
```

Both poll responses carry `Cache-Control: no-store` and `Pragma: no-cache`; the
503 on the default container carries **neither**.

**The control is the finding.** The identical request from an identically
created client against the container without the option:

```
503  {"error":"server_error","error_description":"Failed to send authentication request"}
```

and both containers answer an unknown `auth_req_id` with the identical
`{"error":"invalid_grant","error_description":"Invalid Auth Req ID"}`. So the
option is the only variable.

Nothing running can set it: `ciba-auth-channel` is `"internal": true` with one
provider and **no component type**, and the realm's four CIBA attributes -
`cibaBackchannelTokenDeliveryMode`, `cibaExpiresIn`, `cibaAuthRequestedUserHint`,
`cibaInterval` - do not include a URI.

### 1.8 The costing, and the decision for each

**DPoP - taken.** What would lift `oidc/token/dpop-bound-token` is a computed
value in the harness *and* the protocol feature behind it, and the second is the
larger half by far. Costed and built:

| | |
|---|---|
| proof verification, the measured ladder in the measured order | `internal/oidc/dpop.go`, 356 lines including its comments |
| the single-use `jti` | an in-memory store, F75's shape - Keycloak keeps it in Infinispan |
| the binding on the tokens | three struct fields in a measured position |
| `token_type`, and the refresh grant's two refusals | one helper and one guard |
| the harness's computed value | `Fixture.Proofs`, one field and one function |
| the cases | 13 new, 2 promoted, 15 goldens |
| dependencies added | **none** - `go-jose/v4` was already direct |

The mechanism has **three** consumers rather than one, which is what F38 asks
for: the bound token, and the two refresh refusals, whose fixtures need a bound
token before the case's own request can be wrong about it. Eight of the other
cases could have used a literal - every check above the `iat` answers the same
sentence forever - but `htu` is the case's own absolute URL and the recorder's
base is a container's mapped port, so even a stale proof has to be computed.

**CIBA - refused.** Four things would lift the three cases and three of them are
outside this stream:

1. `startKeycloak` must pass the SPI option and a host alias. It is in
   `record_test.go`, which this cut may not touch, and it starts `start-dev`
   with no options at all.
2. The recorder must stand up a listener before the container starts and pass
   its address in. Same file.
3. `Fixture` has no lifecycle and `Run` has no inbound direction. A fixture is
   `{State, Steps, Proofs, Delay}` and `Run` sends requests and reads
   responses, four ways. The approval **arrives**, and there is no capture for
   that. This is F122's boundary measured from the other side, and §1.7 says
   the boundary is the harness's rather than Docker's - the container reached a
   host listener on the first try.
4. Gloak must serve CIBA in process: the JWE `auth_req_id`, the outbound POST,
   the callback endpoint, and the `authorization_pending`/`slow_down` state
   machine off the realm's `cibaInterval` and `cibaExpiresIn`. Pointless until
   1-3 exist, because nothing could record what it should answer.

`oidc/ciba/poll-pending` alone needs 1, 2 and 4 and not the callout, so it is
the cheapest of the three and still blocked on a file this cut does not own.

## 2. Entries for AGENTS.md

- **DPoP verification is opportunistic, and a header present and empty is not a
  header absent.** `admin-cli` carries no `dpop.bound.access.tokens` attribute
  and a proof sent to it still binds both tokens, so the *header* turns
  verification on and the attribute only makes it mandatory. `DPoP:` with an
  empty value - or one holding only whitespace, which HTTP trims to the same
  thing - answers 400 `DPoP proof is missing` on a client that requires
  nothing, where no header at all answers 200 with a `Bearer` token. That pair
  was measured wrong first: `curl` **drops** a header written `-H "Name:  "`
  rather than sending an empty one, so the 200 that spelling produced was
  curl's answer to a request it never made, and only re-sending the bytes
  explicitly told the two apart.
- **A DPoP proof's refusal ladder is nine checks deep and two of them are not
  where they look.** `typ`, then `alg`, then the `jwk`, then the signature,
  then the mandatory claim set, then **`htu` before `htm`**, then `iat`, then
  `jti` - measured by nine proofs each wrong in two ways. A proof with a broken
  signature and a wrong `htm` answers about the signature; one wrong about both
  the URL and the method answers about the URL. Within the endpoint the proof
  is verified **after** client authentication and the duplicated-parameter
  check and **before** the grant, and it is one check for every grant rather
  than one per grant. Reordering any of it changes the answer to a request that
  is wrong in two ways, which is most of them.
- **Three of DPoP's refusals differ by one sentence and none is
  interchangeable.** An **absent** `typ` interpolates the literal word `null`
  and an empty one interpolates nothing. A supported algorithm over the wrong
  *kind* of key is `Key with algorithm EdDSA and type EC is incorrect for
  provider algorithm EdDSA` - which names the algorithm twice - where the right
  kind on the wrong *curve*, ES384 over a P-256 key, is `DPoP verification
  failure: org.keycloak.common.VerificationException: Signing failed`, and a
  signature that simply does not verify names a different Java class again.
  Folding them into one "bad proof" answer is wrong three ways.
- **The DPoP `iat` window is forty seconds wide and its lowest second is a
  500.** `[now-25, now+15]`, measured at one second's resolution against a
  container whose clock agreed with the host's: `now-26` is `DPoP proof is not
  active`, `now-25` is a 500, `now-24` through `now+15` are 200s, `now+16` is
  the refusal again. The edge is a single-use cache entry whose remaining life
  computes to zero, and Gloak reproduces the window and not the 500. The first
  sweep of it looked non-monotonic and reading that as noise would have been
  wrong: it is one window with a defect on its edge.
- **`cnf` goes on the access and refresh tokens, immediately before `scope`,
  and never on the ID token.** Its value has **two** keys -
  `{"jkt":"…","kc-jkt-type":"DPoP"}` - and the second is Keycloak's own, so
  emitting RFC 9449's single `jkt` is a divergence in a claim a client reads.
  The position was measured on a lightweight client and a full one, whose claim
  sets otherwise share almost nothing.
- **A bound refresh token's two refusals are `invalid_grant` where every other
  DPoP sentence on that endpoint is `invalid_request`.** No proof at all is
  `DPoP proof is missing` and a proof from another key is `DPoP confirmation
  doesn't match DPoP proof`. So the code follows the grant and not the check.
- **CIBA's 503 is a fact about `start-dev`, not about Keycloak.** `CIBA` is
  `"type":"DEFAULT","enabled":true`, and a container started with
  `--spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri`
  pointed at a listener on the host answers the identical authentication
  request 200 and takes the flow all the way through: `authorization_pending`,
  `slow_down` on a poll inside the interval, and nine keys with `token_type:
  Bearer` once the channel calls `.../ext/ciba/auth/callback` with
  `{"status":"SUCCEED"}`. Both containers answer an unknown `auth_req_id`
  identically, so the option is the only variable. The URI cannot be set on a
  running server: the `ciba-auth-channel` SPI is `"internal": true` with no
  component type, and the realm's four CIBA attributes do not include it. What
  keeps the three CIBA cases unrecordable is therefore the **recorder's**
  container and an inbound callout `Run` has no capture for - not the feature.

## 3. Follow-up dispositions

| Entry | Disposition |
|---|---|
| **F135** - DPoP is measured in full and not implemented | **Closed for the token endpoint.** Proof verification, `cnf.jkt` on both tokens, `token_type`, the refresh binding and the client attribute are served and pinned by 15 goldens and 12 package tests - nine in `internal/oidc`
and three over the fixture's mint. Its warning - "a partial implementation would refuse valid proofs" - was the right one and is what the ladder's measured order answers. **What is left of it is the resource server**, §1.6, and it should be re-filed as that rather than closed outright. |
| **F38** - do not build a mechanism this cut does not use | **Honoured, with three consumers.** `Fixture.Proofs` is used by `dpop-bound-token`, `dpop-refresh-proof-missing` and `dpop-refresh-key-mismatch`, and by ten more cases that could have used a literal but for `htu`. It is on the **fixture** rather than on a `Step`, so the entry's own sentence - a `Step` is a request and every capture reads a response - stays true. |
| **F122** - the two admin logout triggers notify nobody | **Measured from the third side, and the boundary moved.** The container reached a listener on the host on the first attempt, so "an endpoint Keycloak calls out to" is not unreachable in this environment. What is unreachable is the **harness's**: a fixture has no lifecycle and no capture that reads an inbound request. That is a smaller and more fixable statement than the one this entry has carried. |
| **F107** - seven masks in `catalog_oidc_pending.go` were not examined | **One fewer.** `dpop-bound-token`'s `Volatile` listed `id_token`, and its request does not ask for `openid`. Nothing could see it while the case had no golden; `TestNoMaskIsInertOnItsGolden` reported it the moment there were bytes, and the mask is gone. |
| **F75** - three in-memory stores that are the faithful model | **A fourth, declared.** The single-use `jti` cache. Keycloak keeps it in Infinispan, so a table would be a divergence; the cost is the same one the other three carry, and a restart forgets which proofs have been spent. |
| **New - the 500 at `iat = now-25`** | **Filed, not built.** Reproducing it means a cache whose put refuses a zero lifespan. Nothing in this repository observes it, and a case for it would be a golden asserting a server error for one second of a forty-second window. |
| **New - DPoP at the resource server** | **Filed with its measurements.** §1.6: `ath` is required, a bound token as a `Bearer` is refused, the DPoP check precedes the lightweight-token refusal, and the challenge carries `algs="…"` before `realm`. Gloak accepts a bound token as an ordinary bearer today, which is a divergence no golden can see. |
| **New - `dpop_jkt` on the authorization endpoint** | **Unmeasured, and recorded as unmeasured.** RFC 9449 lets the code grant carry the thumbprint on the authorization request. Nothing here has sent one. |
| **New - token exchange does not bind** | **Unmeasured.** `tokenExchangeGrant` builds its own response body and this cut left it alone; whether Keycloak's exchange binds its issued token to the request's proof was not measured. The bad-proof refusal on that grant **is** measured and is served, because the check is before the dispatch. |

## 4. Parity, before and after

Baseline is `main` at 980502f; head is this branch.

```
Parity: 520 -> 535 of 554 (+15)

chapter        before  after  delta
oidc/token         19     34    +15
```

per chapter, `Implemented` over `Implemented + Recorded + Pending`:

```
                served  recorded  documented      served  recorded  documented
                      before                              after
oidc/ciba           10         0          12          10         0          12
oidc/token          19         1          22          34         0          35
total              520                   554         535                   554
```

`oidc/token`'s denominator grows by 13 because thirteen new cases arrived, and
its `Recorded` column empties because `dpop-header-invalid` was the one and is
now served. `oidc/ciba` does not move: its three `Pending` cases keep their
status and get new reasons.

### The decision for each

- **DPoP: taken.** +15 served, no dependency added, one insertion point in
  `token()`, and 16 mutations run against named tests.
- **CIBA: refused.** Its three reasons are rewritten from "a default 26.7.1 has
  no CIBA authentication channel" - true, and it reads like a fact about
  Keycloak - to what §1.7 measured: a startup option the recorder does not set,
  and an approval that arrives as an inbound request the harness has no shape
  for. Nothing about the cases changed but the sentences, which is the whole
  deliverable for that half.

## 5. The mutation pass

Sixteen mutations, each applied to a clean tree, checked for a non-empty diff,
built, run against a **named** test, reverted, and the revert checked with
`git status`. All sixteen were killed.

| Mutation | Named test | Result |
|---|---|---|
| `tokenTypeFor` always answers `Bearer` | `TestConformance/oidc/token/dpop-bound-token` | killed |
| `cnf` moves after `scope` on the **full** access token | `TestDPoPBindsAFullAccessTokenInTheSamePlace` | killed, after that test existed - see below |
| `cnf` moves after `scope` on the **lightweight** access token | `TestDPoPBindsTheAccessAndRefreshTokensAndNotTheID` | killed |
| the ID token gains a `cnf` | `TestDPoPBindsTheAccessAndRefreshTokensAndNotTheID` | killed |
| the refresh grant stops comparing the binding | `TestConformance/oidc/token/dpop-refresh-key-mismatch` | killed |
| a `jti` may be used twice | `TestDPoPProofCannotBeReplayed` | killed |
| an empty header reads as an absent one | `TestDPoPHeaderPresentAndEmptyIsRefusedWhereNoHeaderIsNot` | killed |
| `htu` keeps its query | `TestDPoPHtuIgnoresTheQueryAndNothingElse` | killed |
| `htm` is compared before `htu` | `TestDPoPComparesTheURLBeforeTheMethod` | killed |
| the clock skew shrinks from 15s to 5s | `TestDPoPIatWindowIsAsymmetric` | killed |
| the proof is verified before the duplicate check | `TestDPoPIsCheckedAfterTheDuplicateParameterAndBeforeTheGrant` | killed |
| the key type is not compared to the algorithm | `TestConformance/oidc/token/dpop-key-type-mismatch` | killed |
| the curve is not compared to the algorithm | `TestConformance/oidc/token/dpop-curve-mismatch` | killed |
| a minted proof reuses one `jti` | `TestAMintedProofIsFreshEveryTime` | killed |
| an absent `typ` spells nothing rather than `null` | `TestDPoPProofWithNoTypeNamesNull` | killed |
| no client requires a proof | `TestConformance/oidc/token/dpop-proof-missing` | killed |

**One survived and one was a bad mutation, and both are here because reading a
red run as a kill is the failure this list exists to avoid.**

The survivor moved `cnf` after `scope` on `accessClaims` and every test passed.
The cause is that **every DPoP test used `admin-cli`, which is a lightweight
client**, so the full claim set the mutation edited was never serialised. The
answer was `TestDPoPBindsAFullAccessTokenInTheSamePlace`, which registers a
client with no lightweight attribute and asserts it is the full set before
looking at `cnf` at all; the mutation dies there now. Two claim sets, one
measurement each, and a suite that exercised one of them.

The bad mutation added `Cnf` to `idClaims` and did not compile, because the
field did not exist - `go test` reported `[build failed]`, which is not a test
failing. It was rewritten to add the field **and** set it, and killed.

## 6. What surprised me

**That a probe of mine measured `curl`.** §1.5. Two spellings of an empty header
answered 400 and 200 on the same client seconds apart, and the difference cannot
exist on the wire, because HTTP trims a field value. `curl` removes a header
written `-H "Name:  "` instead of sending it, so the 200 was its answer to a
request it never made. The rule the brief gives - a probe that reports the same
answer for every input is measuring itself - has a twin: a probe that reports
*different* answers for inputs that cannot differ is measuring itself too.

**That the reason on `dpop-bound-token` was true and pointed the wrong way.**
"A proof carries a per-request `iat` and a single-use `jti`" is correct about
both halves. The window is forty seconds wide and a fixture's last step is one
round trip before the case's request, so the `iat` half never bit; the `jti`
half rules out a literal and nothing else. What was actually missing was a
computed value, and reading the sentence as "the proof goes stale" is what kept
it looking like a race nobody could win.

**That eight of the twelve refusals could have been literals.** Every
structural check runs before the `iat` window, so a deliberately stale proof
answers the same sentence forever - confirmed by sending identical bytes twice.
What forced them to be computed anyway is `htu`, which is the case's own
absolute URL and differs between a container's mapped port and `testIssuer`.

**That the CIBA container reached my listener on the first attempt.** The
project's precedent - F122 - reads as though an outbound call is structurally
out of reach. It is not: `--add-host=host.docker.internal:host-gateway` and a
`net/http` server were enough, and the whole CIBA flow completed in one
afternoon. What is out of reach is the harness's shape, which is a much smaller
and more fixable statement than the one the entry carries.

**That the `iat` window's bottom edge is a 500.** Three sweeps of it looked
non-monotonic and the temptation was to call the number noisy. It is one window
with a defect on exactly one second of it, and the two constants that put its
edges where they are - 10 and 15 - only fall out once the 500 is read as a
cache entry with zero life left.

## 7. What is left

- **DPoP at the resource server.** §1.6. Gloak accepts a bound token as an
  ordinary bearer, which no golden can see.
- **`dpop_jkt` on the authorization endpoint**, unmeasured.
- **Whether the token-exchange grant binds**, unmeasured; its bad-proof refusal
  is served because the check precedes the dispatch.
- **CIBA**, all three cases, blocked as §1.8 sets out. The measurements for the
  whole flow are in §1.7 and will not need taking again.
- **The 500 at `iat = now-25`**, filed and deliberately not reproduced.
