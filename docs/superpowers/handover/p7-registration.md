# P7 cut C: dynamic client registration, and the grants the measurement supports

Branch `feat/p7-registration`, off `969fcc7`. Measured against a live Keycloak
26.7.1 on 2026-08-31 and 2026-09-01, container `kc-reg` on port 8142, checked to
be answering on 127.0.0.1 before any probe was trusted, and removed afterwards.
`kc-authzb` was not running and was not touched.

The plan, with the reachability argument the brief asked for, is
`docs/superpowers/plans/2026-08-31-p7-registration.md`. Its short answer: **nine
of the eleven `Pending` cases are reachable, and the two that are not are
unreachable for reasons that are themselves measurements.**

## 1. Measurements

### 1.1 The initial access token is not on the path

The brief asked whether a conformance fixture can mint an initial access token
through the Admin API it already drives, or whether the five registration cases
wait for `internal/admin`. **Neither: the endpoint does not need one.**

```
POST /realms/master/clients-registrations/openid-connect

no Authorization header                403  insufficient_scope / Policy 'Trusted Hosts' …
Authorization: Bearer  (empty value)   403  the same body
Authorization: Basic …                 403  the same body
Authorization: Bearer not-a-token      401  invalid_token / Failed decode token
Authorization: Bearer <initial access> 201
Authorization: Bearer <admin access>   201
```

The last two are identical in shape and the registration access token each mints
carries the same `"registration_auth":"authenticated"` - so nothing in the token
records which credential made it. The `admin-token` fixture this catalogue has
had since P1 is therefore a working credential for all five cases, and
`POST /admin/realms/{r}/clients-initial-access` never comes into it.

That is not only convenient. Had the fixture minted one, every one of the five
cases would have depended on an Admin API route Gloak does not serve, and the
verifier would have failed on the *fixture* rather than on the case.

The initial access token is still worth writing down, because it is what a real
client uses: an HS512 JWT with `"typ":"InitialAccessToken"`, `exp` 0, a `jti`
equal to the `id` the Admin API answers, and it is **stateful** - `count: 2` used
a third time answers `401 invalid_token / No remaining count on initial access
token`. Gloak grows no branch for it, because nothing in Gloak mints one.

### 1.2 Which caller opens which verb

One role at a time, one caller per role:

```
create                    create-client 201 · manage-clients 201
                          view-clients 403 · query-clients 403 · manage-realm 403 · none 403
read   (GET item)         view-clients 200 · manage-clients 200 · none 403
write  (PUT, DELETE)      manage-clients 200/204 · view-clients 403 · none 403
```

**The two 403s are not the same body.** A caller presenting no bearer at all is
told about the `Trusted Hosts` client registration policy; one presenting a valid
access token without the role is told `Forbidden`. One "not allowed" constant is
wrong on one of them.

### 1.3 The create

201, `Content-Type: application/json;charset=UTF-8`, a `Location` ending in the
new client's id, the five security headers, and **no `Cache-Control` at all** -
where the token endpoint one path away sends `no-store` on every response
including its refusals. Twenty keys:

```
redirect_uris, token_endpoint_auth_method, grant_types, response_types,
client_id, client_secret, client_name, scope, subject_type, request_uris,
tls_client_certificate_bound_access_tokens, dpop_bound_access_tokens,
post_logout_redirect_uris, client_id_issued_at, client_secret_expires_at,
registration_client_uri, registration_access_token,
backchannel_logout_session_required, require_pushed_authorization_requests,
frontchannel_logout_session_required
```

- **`client_id` is a server-minted UUID and a body naming one is refused**:
  400 `invalid_client_metadata` / `Client Identifier included`. So the
  catalogue's three item cases addressing `/gloak-probe` could never have worked;
  the id has to be captured.
- **`client_name` is omitted when absent**, where every array is emitted empty.
- **`scope` is the client's *optional* client scopes joined by spaces**, in the
  realm's order rather than the request's - `"email profile"` in, `"profile
  email"` out - and that order is **not reproducible**: one recording answered
  `address phone offline_access organization microprofile-jwt` where a hand probe
  minutes earlier put `organization` before `offline_access`.
- **`backchannel_logout_session_required` is a constant `false`.** Seven inputs:
  the attribute `"true"`, `"false"` and absent; with and without a
  `backchannel.logout.url`; and a request body naming the field `true`. All seven
  answer false. Its neighbour `frontchannel_logout_session_required` **does**
  follow its attribute, defaulting to true when absent. And a registered client
  is written with `backchannel.logout.session.required: "true"`, which this very
  endpoint then reports as false.

### 1.4 `client_secret` and `client_secret_expires_at` are decided separately

Measured over seven clients:

| client | authenticator | public | `client_secret` | `client_secret_expires_at` |
|---|---|---|---|---|
| a default registration | `client-secret` | no | yes | yes |
| `admin-cli`, `account` | `client-secret` | **yes** | no | **yes** |
| registered with `none` | `none` | yes | no | no |
| `client_secret_jwt` | `client-secret-jwt` | no | yes | yes |
| `tls_client_auth` | `client-x509` | no | no | no |
| Admin-API `client-jwt` | `client-jwt` | no | no | no |

So the expiry follows the **method** and the secret follows the method *and*
`publicClient`. `admin-cli` is the pair that says so: public, carrying the expiry
and no secret.

**`token_endpoint_auth_method` follows `clientAuthenticatorType`, not
`publicClient`.** `admin-cli` is a public client and reads back
`client_secret_basic`.

### 1.5 The accepted auth methods and the emitted ones are different sets

```
client_secret_basic          accepted
client_secret_post           accepted, and writes client.secret.authentication.allowed.method
client_secret_jwt            accepted
tls_client_auth              accepted
none                         accepted, and makes the client public
private_key_jwt              **400 invalid_client_metadata / Client metadata invalid**
self_signed_tls_client_auth  400, the same
an unknown value             400, the same
the empty string             400, the same
```

**`private_key_jwt` is refused on the way in and produced on the way out.** The
discovery document advertises it in `token_endpoint_auth_methods_supported`, and
a client created through the Admin API with `clientAuthenticatorType:
"client-jwt"` reads back as exactly that here. One constant for "the auth
methods" is wrong on one of the two directions.

### 1.6 The Content-Type rule is a media-type match, and an absent header passes

Eight values on one request:

```
(the header absent)                 accepted - falls through to the 403
application/json                    accepted
application/json;charset=UTF-8      accepted
application/JSON                    accepted, so the comparison folds case
*/*                                 accepted
application/x-www-form-urlencoded   415
text/plain                          415
application/xml                     415
application/jsonx                   415, so it is not a prefix match
```

The 415 body is the **bare-error** shape and names a JAX-RS annotation to a
client: `{"error":"The content-type header value did not match the value in
@Consumes"}`.

A ninth input is not reproduced and is filed: a `Content-Type` header **present
with an empty value** answers a 500 serving Keycloak's HTML error page with an
error id in it, which is neither of this endpoint's two body shapes. Go's
`Header.Get` cannot tell it from an absent header without reading the map, and an
HTML 500 is a shape this project has nowhere else.

### 1.7 The body is judged before the caller

```
no Content-Type, no credentials        403 - the header's absence is fine
text/plain, no credentials             415
`{`, no credentials                    400 invalid_request / Cannot parse the JSON
`{`, a view-clients caller             400, the same
an unknown JSON field                  400 {"error":"Invalid json representation for
                                            OIDCClientRepresentation. Unrecognized field
                                            \"x\" at line 1 column 56."}
```

That order is the opposite of every other guarded route in this project, and it
holds on `PUT` as well as `POST`. The last row is a **fifth strict JSON decoder**
and the only one that reports a line and a column.

### 1.8 Three read shapes, and a fourth on the create

`GET .../openid-connect/{clientId}` answers 200 to a registration access token
**and** to an administrator's bearer, and the two bodies differ: the token's
carries `registration_access_token` and the administrator's does not. Both omit
`client_id_issued_at`, which the create emits. So the create, the holder's read
and the administrator's read are three shapes of one representation.

The read is also **not limited to registered clients**:
`GET .../openid-connect/admin-cli` answers 200 with `admin-cli` in the OIDC
shape, `client_name` echoing the theme message key `${client_admin-cli}` raw.

### 1.9 A `PUT` rotates the registration access token and a `GET` does not

Two reads with one token answered with that token both times and it went on
working; one `PUT` answered with a different token and the presented one was 401
immediately afterwards. The `PUT` also **keeps the client secret** and
**replaces** everything else - a `PUT` omitting `redirect_uris` left the client
with none, which is the opposite of `PUT /admin/realms/{r}/clients/{uuid}`, which
merges.

`PUT` requires the body's `client_id` to equal the path's, and an **absent** one
is the same refusal as a disagreeing one: 400 `invalid_client_metadata` /
`Client Identifier modified`. One message for two conditions.

### 1.10 The item path's refusal grid

The four cells that tell the three possible resolution orders apart:

```
missing client, no bearer          401 invalid_token / Not authorized to view client. …
missing client, view-clients       404 invalid_request / Client not found
missing client, no admin role      403 insufficient_scope / Forbidden
present client, another's token    401 invalid_token / Not authorized to view client. …
```

So a caller who proves nothing never learns whether the client exists, and a
caller who proves something but may not act does not either.

**The 401's sentence splits by verb.** A `GET` is told
`Not authorized to view client. Not valid token or client credentials
provided.`; a `PUT` or a `DELETE` is told `Not authorized to update client. Maybe
missing token or bad token type.` Different sentences, different second halves,
one status and one code.

Two more 401 descriptions on the same family: `Failed decode token` for a bearer
that does not verify - and the word is wider than it reads, because a
**well-formed JWT with a wrong signature** answers it too - and `Invalid type of
token` for a refresh token offered as a bearer. Four descriptions, one status,
one code.

The `DELETE`'s 204 carries four of the five security headers, which is the
request-Content-Type rule rather than anything about deletes, and no
`Cache-Control`.

### 1.11 `grant_types` and `response_types` are derived, both ways

Read, from eight clients created through the Admin API one flag at a time:

```
std   impl  direct svc    grant_types                                        response_types
f     f     f      f      [refresh_token]                                    []
t     f     f      f      [authorization_code, refresh_token]                [code, none]
f     t     f      f      [implicit, refresh_token]                          [id_token, id_token token]
f     f     t      f      [password, refresh_token]                          []
f     f     f      t      [client_credentials, refresh_token]                []
t     t     f      f      [authorization_code, implicit, refresh_token]      [code, none, id_token,
                                                                              id_token token, code id_token,
                                                                              code token, code id_token token]
```

The full order, from a client with all nine on and then the same client with
`use.refresh.tokens` off so the position of the one that moves is fixed rather
than inferred:

```
authorization_code, implicit, password, client_credentials,
urn:ietf:params:oauth:grant-type:device_code,
urn:openid:params:grant-type:ciba,
refresh_token,
urn:ietf:params:oauth:grant-type:token-exchange,
urn:ietf:params:oauth:grant-type:jwt-bearer
```

**`refresh_token` is seventh of nine, not last.**

Write, from nine request bodies:

```
(nothing)                        standard
grant_types []                   standard, and use.refresh.tokens off
grant_types [authorization_code] standard
grant_types [refresh_token]      no flow at all
grant_types [password]           direct access
grant_types [client_credentials] service accounts
grant_types [implicit]           implicit
response_types [code]            standard
response_types [token,id_token]  implicit, and standard **off**
```

The empty array is the row that says the two halves are separate: it leaves the
flow flags at their defaults and still turns refresh tokens off.

**Naming `grant_types` writes five attributes, not one** - `use.refresh.tokens`
plus the four grants that have no flow flag of their own. So dynamic
registration is a second way to switch on the device grant, CIBA, standard token
exchange and the JWT bearer grant, and that is how the last of those four
attribute names was found at all.

### 1.12 The family's other three providers, and its verbs

```
openid-connect            POST 201; GET/PUT/DELETE on the item path
default                   POST 201, GET 200 - Keycloak's own ClientRepresentation
install                   GET 200 - an adapter config; POST is 405
saml2-entity-descriptor   POST only, and not JSON; GET is 405
anything else             404 {"error":"Client registration provider not found"}
```

On the collection path of `openid-connect`:

```
GET, PUT, DELETE   404 {"error":"HTTP 404 Not Found"}
PATCH, HEAD        405 {"error":"HTTP 405 Method Not Allowed"}
OPTIONS            200, four of the five security headers, no Allow header
```

On the item path: `POST` 404, `PATCH` 405.

### 1.13 Standard token exchange works on a default 26.7.1

`GET /admin/serverinfo` reports `TOKEN_EXCHANGE` and `TOKEN_EXCHANGE_DELEGATION`
as disabled previews and **`TOKEN_EXCHANGE_STANDARD_V2` as `"type":"DEFAULT"` and
enabled**. The disabled one is the legacy exchange. The gate on the standard one
is the client attribute `standard.token.exchange.enabled`.

| # | Condition | Body (all 400 `invalid_request`) |
|---|---|---|
| 1 | the attribute is off | `Standard token exchange is not enabled for the requested client` |
| 2 | `subject_token` absent | `Parameter 'subject_token' required for standard token exchange` |
| 3 | `subject_token_type` absent | `Parameter 'subject_token_type' required for standard token exchange` |
| 4 | `subject_token_type` not an access token | `Parameter 'subject_token' supports access tokens only` |
| 5 | `requested_token_type` a refresh token | `requested_token_type unsupported` |
| 6 | `subject_token` unverifiable | `Invalid token` |

The success is **eight keys, not nine**: no `refresh_token`, no `id_token` even
on a subject token granted `openid`, `refresh_expires_in` 0 rather than absent,
and `issued_token_type` after `scope`. `session_state` is the **subject's**
session, so the exchange starts none, and the scope is the subject token's rather
than anything the request named. The access token's `jti` prefix is `onrtte:`.

### 1.14 The JWT bearer grant is seven refusals and no success

| # | Condition | Body (all 400 `invalid_grant`) |
|---|---|---|
| 1 | `assertion` absent | `Missing parameter:assertion` |
| 2 | not three parts, or a payload that is not JSON | `The provided assertion is not a valid JWT` |
| 3 | a public client | `Public client not allowed to use authorization grant` |
| 4 | `oauth2.jwt.authorization.grant.enabled` off | `JWT Authorization Grant is not supported for the requested client` |
| 5 | no `iss` claim | `Missing claim: iss` |
| 6 | an `iss` naming no identity provider | `No Identity Provider for provided issuer` |

**`Missing parameter:assertion` has no space after the colon**, where every other
missing-parameter description on this endpoint is `Missing parameter: x` and
CIBA's one endpoint away is `missing parameter : login_hint` with a space on both
sides. Three spellings of one phrase in one protocol.

Rows 3 and 4 both precede row 5, measured on a request carrying an assertion with
no `iss`. The parse is **structural** - three parts, a base64url JSON payload -
with nothing checked about the signature and nothing about `exp`: an assertion
expired ten minutes ago reaches row 6.

Row 6 is where a default container stops. Getting past it needs an identity
provider, which is `POST /admin/realms/{r}/identity-provider/instances` plus a
key that provider names.

### 1.15 DPoP is enabled, works, and cannot be recorded

`DPOP` is `"type":"DEFAULT"` and enabled. A proof signed ES256 over a P-256 key
answers 200 whose `token_type` is `DPoP` and whose access **and refresh** tokens
carry `"cnf":{"jkt":"<RFC 7638 thumbprint>","kc-jkt-type":"DPoP"}`.

It is the **harness** that cannot express the request, for two independent
measured reasons:

- **the proof has an age window** - `iat` at -5s, -11s and -20s are accepted;
  -60s, -3600s, +20s and +60s answer `DPoP proof is not active`; and
- **a proof is single-use** - the identical header twice answers `DPoP proof has
  already been used`.

The refusals are static and were measured anyway, because they are the only part
of DPoP anything in this repository can hold:

```
dpop.bound.access.tokens on the client, no header   DPoP proof is missing
a header that is not a JWS                          DPoP header verification failure
the header sent twice                               the same
htu disagreeing                                     DPoP HTTP URL mismatch
htm disagreeing                                     DPoP HTTP method mismatch
```

**The header is validated on `admin-cli`, which carries no DPoP attribute at
all**, so DPoP verification is opportunistic rather than switched on per client.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for folding in.

- **A protocol-side family answers the Admin API's charset rule.** Every 2xx on
  `/realms/{realm}/clients-registrations/…` carries
  `application/json;charset=UTF-8` and every one of its refusals carries plain
  `application/json` - the create, the two reads and the update on one side, the
  403, the 401s, the 404s, the 415 and the 400 on the other. That is the Admin
  API's split, on a path that is not the Admin API, so the rule's two surfaces
  are three. The distinguishing probe is cheap and was sent: the same endpoint's
  own 403 and its own 201, on one container, seconds apart.

- **Two 403s on one endpoint, and the bearer decides which.** A caller
  presenting no bearer token at all - including `Bearer ` with nothing after it,
  and Basic credentials - is told `Policy 'Trusted Hosts' rejected request to
  client-registration service. Details: Host not trusted.`; a caller presenting
  a valid access token that holds the wrong role is told `Forbidden`. One "not
  allowed" constant is wrong on one of them, and the difference is the only thing
  from outside that separates "anonymous registration is switched off" from "you
  are not an administrator".

- **The registration endpoint judges the body before the caller.** A `POST` or a
  `PUT` carrying `text/plain` and no credentials answers 415; one carrying `{`
  and no credentials answers 400 `Cannot parse the JSON`. Every other guarded
  route in this project resolves the caller first. And an **absent**
  `Content-Type` is accepted - the check is a media-type match over
  `application/json`, `*/*` and nothing at all, folding case and ignoring
  parameters, so `application/jsonx` is a 415 and `application/JSON` is not.

- **One 401, four descriptions, and one of them splits by verb.** A bearer that
  does not verify is `Failed decode token` - which covers a **well-formed JWT
  with a wrong signature**, not only unparseable input. A refresh token offered
  as a bearer is `Invalid type of token`. A caller with no usable credential is
  `Not authorized to view client. Not valid token or client credentials
  provided.` on a `GET` and `Not authorized to update client. Maybe missing token
  or bad token type.` on a `PUT` or a `DELETE`. The same missing credential, two
  sentences, chosen by the method.

- **A registered client's id is the server's and a create naming one is
  refused**, 400 `invalid_client_metadata` / `Client Identifier included`. The
  update's mirror image is `Client Identifier modified`, and it fires both for a
  body naming another client **and** for a body naming none - one message for two
  conditions.

- **A `PUT` rotates the registration access token and a `GET` does not.** Two
  reads with one token answer with that token and it goes on working; one update
  answers with a different one and the presented one is 401 immediately
  afterwards. The update also keeps the client secret and replaces everything
  else - a `PUT` omitting `redirect_uris` leaves the client with none, where
  `PUT /admin/realms/{r}/clients/{uuid}` merges. Two write paths onto one
  resource, opposite rules.

- **One route, two bodies, decided by which token asked.** A read made with a
  registration access token carries `registration_access_token`; a read of the
  same client made with an administrator's does not. Neither carries
  `client_id_issued_at`, which the create emits. Three shapes of one
  representation, and a shared serialiser is wrong on two of them. The read is
  not limited to registered clients either: `admin-cli` comes back in the OIDC
  shape with its theme message key echoed raw.

- **`client_secret` and `client_secret_expires_at` are decided by different
  things.** The expiry appears whenever the client's `clientAuthenticatorType` is
  one of the secret-carrying ones; the secret itself only when the client is also
  confidential. `admin-cli` is public with a `client-secret` authenticator and
  carries the expiry and no secret; a client registered with
  `token_endpoint_auth_method: "none"` carries neither. And that method follows
  `clientAuthenticatorType` rather than `publicClient`, which is why `admin-cli`
  reads back `client_secret_basic`.

- **`private_key_jwt` is refused on the way in and produced on the way out.**
  The discovery document advertises it, a client created with
  `clientAuthenticatorType: "client-jwt"` reads back as exactly that, and a
  registration naming it is 400 `Client metadata invalid` - as are
  `self_signed_tls_client_auth`, an unknown value and the empty string. The set
  this endpoint accepts and the set it emits are different sets.

- **`backchannel_logout_session_required` is a constant `false` on the OIDC
  registration view, and its neighbour is not.** Seven inputs answer false: the
  attribute `"true"`, `"false"` and absent, with and without a backchannel logout
  URL, and a request body naming the field `true`. Meanwhile
  `frontchannel_logout_session_required` does follow its attribute, with the
  opposite default. And a registration **writes**
  `backchannel.logout.session.required: "true"` and then reports it as false, so
  the endpoint disagrees with the client it just created.

- **`scope` on this endpoint is the client's *optional* client scopes**, joined
  by spaces, in the realm's order rather than the request's, and that order is not
  reproducible - one recording answered `address phone offline_access
  organization microprofile-jwt` where a hand probe minutes earlier put
  `organization` before `offline_access`. Reading it as the requested scope is
  the obvious mistake.

- **`grant_types` and `response_types` are derived from the client's flow flags,
  interlock, and put `refresh_token` seventh of nine.** Sending
  `response_types:["token","id_token"]` comes back
  `grant_types:["implicit","refresh_token"]`; sending `grant_types:["implicit"]`
  comes back `response_types:["id_token","id_token token"]`; and an **empty**
  `grant_types` array leaves the flow flags alone while still turning
  `use.refresh.tokens` off, which is what says the two halves are separate
  checks. Naming `grant_types` at all writes **five** attributes, so dynamic
  registration is a second way to switch on the device grant, CIBA, standard
  token exchange and the JWT bearer grant.

- **Standard token exchange is on by a default 26.7.1 and the disabled preview
  beside it is a different feature.** `TOKEN_EXCHANGE` and
  `TOKEN_EXCHANGE_DELEGATION` are disabled previews;
  `TOKEN_EXCHANGE_STANDARD_V2` is `DEFAULT` and enabled, and it is what
  `urn:ietf:params:oauth:grant-type:token-exchange` reaches. Its gate is a client
  attribute. Its success is **eight keys, not nine** - no refresh token, no ID
  token even on a subject granted `openid`, `refresh_expires_in` 0 rather than
  absent, and `issued_token_type` after `scope` - and the token keeps the
  subject's session rather than starting one.

- **The JWT bearer grant is a ladder with no top on a default install.** Six
  refusals in a fixed order, ending in `No Identity Provider for provided
  issuer`; a seventh answer would need an identity provider the Admin API has to
  create. Its first rung is spelled `Missing parameter:assertion` **with no space
  after the colon**, where the rest of the token endpoint says `Missing
  parameter: x` and CIBA says `missing parameter : login_hint` with a space on
  both sides. And the "is this a valid JWT" test is structural: three parts and a
  JSON payload, with nothing checked about the signature and nothing about `exp`,
  so an assertion that expired ten minutes ago reaches the last rung.

- **DPoP works on a default 26.7.1 and cannot be put in a golden.** A proof
  signed ES256 answers 200 with `token_type: DPoP` and a `cnf.jkt` on the access
  *and* refresh tokens. What cannot be recorded is the request: a proof's `iat`
  is refused outside a window of tens of seconds **and** its `jti` is single-use,
  so a literal could not be replayed even seconds after it was written. The
  header is validated on `admin-cli`, which carries no DPoP attribute at all, so
  the verification is opportunistic rather than per client.

## 3. Lines in AGENTS.md and the observed document these measurements contradict

Seven, and three of them are counted claims.

1. **AGENTS.md, the charset bullet: "The charset on `Content-Type` splits by API
   surface and status class … On the **protocol side** every 200 carries plain
   `application/json`."** The client-registration family lives under
   `/realms/{realm}/`, is not the Admin API, and answers the **Admin API's** rule:
   `;charset=UTF-8` on every 2xx with a body, plain `application/json` on every
   error. So there are three surfaces, not two, and the bullet's own list of
   protocol endpoints - "token, userinfo, certs, discovery, introspection,
   revocation, device" - is what it was drawn from. The bullet already records
   being wrong once for exactly this reason, having been written from the one
   endpoint of a family that had been measured.
   **Not changed on the branch beyond serving the measured bytes**: the new
   handlers call `httpx.WriteJSONCharset` for their successes and the ordinary
   writers for their refusals, and `WriteJSONCharset`'s doc comment still says
   the split is `GET /realms/{realm}`'s alone, which AGENTS.md already notes.

2. **AGENTS.md: "A create's `Location` ends in the new object's id on four routes
   out of seven."** Counted from the list rather than incremented, on one
   container today: **thirteen creates answer 201 with a `Location`, and ten of
   them end in a UUID.**

   ```
   uuid tail   POST /clients, /users, /groups, /groups/{id}/children,
               /client-scopes, /client-templates, /clients-initial-access,
               /components, /authentication/flows, and
               /realms/{r}/clients-registrations/openid-connect
   name tail   POST /roles, POST /clients/{uuid}/roles, POST /admin/realms
   ```

   Two more could not be reached on a default container and are not counted:
   `POST /organizations` needs the realm flag and `POST
   /identity-provider/instances` refuses an `http` authorization URL. The
   bullet's "seven" was the set that had been measured when it was written, and
   six of the ten UUID tails are routes this project already serves. `Case.VolatileTailHeaders`
   is declared on five cases and this branch makes it six; the client-scope
   creates need none, because the body's `id` wins there and pins the tail.

3. **AGENTS.md: "Four strict JSON decoders, and two families disagree about when
   the decode runs."** There is a fifth, and it is the only one that reports a
   **position**: `{"error":"Invalid json representation for
   OIDCClientRepresentation. Unrecognized field \"x\" at line 1 column 56."}`,
   in the bare-error shape. It also runs **before the caller is resolved**, which
   is a third answer to that bullet's "when the decode runs": the
   required-action `PUT` decodes before the alias is resolved, the organization
   `PUT` after, and this one before the credential is looked at at all.
   Gloak's decoder is not strict about unknown fields on this branch, which is a
   divergence and is filed rather than hidden.

4. **AGENTS.md, `parkedGoldens`: "Nine Pending goldens are parked, not four …
   All seven are declared in `parkedGoldens` … refuses an eighth arriving without
   one."** Three numbers in one bullet and they disagree with each other. The map
   held **nine** entries before this branch and holds **eight** after it, because
   `oidc/registration/without-initial-access-token` is now Implemented and its
   golden is compared. Counted from the list, not incremented.

5. **F86: "`onrtac:`, `onrtro:`, `onrtrt:`, `onltac:` - measured on all four
   grants."** The follow-ups file still says four; the device cut's handover
   corrected it to five with `onrtdg:`. Counted from the list it is now **six**:
   `onrtac`, `onrtro`, `onrtrt`, `onltac`, `onrtdg` and `onrtte`, the last from a
   standard token exchange. Every re-count of this number has moved it.

6. **AGENTS.md's 404-versus-405 bullet, and the `HEAD` line inside it.** The
   bullet says the Admin API "alone now answers it in three different shapes",
   naming the client scopes, the protocol mappers and the scope mappings. The
   client-registration collection is a **fourth** shape and it is on the protocol
   side: `GET`, `PUT` and `DELETE` answer the 404 and **`PATCH` and `HEAD` answer
   a real 405**. That is the protocol mappers' split with `HEAD` added, and it is
   `HEAD`'s **third** measured answer after 200 on `/auth` and 404 on
   `/login-actions/authenticate`. Its `OPTIONS` is a 200 sending four of the five
   security headers with no `Allow`, which is the fourth exception the
   security-headers bullet already records, on a fifth endpoint.
   Nothing was changed on the strength of any of it; Gloak answers all five
   through `WithKeycloakFallbacks`, which happens to agree on three. See F31.

7. **Four catalogue `Reason` strings, and one of them was stale twice.**
   - `oidc/token/device-code-grant` said a completed device authorization "needs
     the device verification and consent pages, which are not implemented". Those
     landed in the cut that filed it - `deviceDeniedFixture` already walks the
     whole browser flow. **Fixed on the branch**: the case is Implemented on a
     `device-approved` fixture that is `device-denied` minus one form field.
   - `oidc/token/token-exchange` said "the token-exchange grant is not
     implemented", with a `Fixture` comment calling it "a feature that must be
     explicitly enabled". True of `TOKEN_EXCHANGE`, which is not the feature this
     grant type reaches. **Fixed on the branch**, and served.
   - `oidc/token/jwt-authorization-grant` said "the jwt-bearer grant is not
     implemented", with a comment that it "needs a client configured to trust a
     signed JWT assertion, which no bootstrapped client has". Both true, and the
     case was **reachable exactly as written** and nobody had sent it: a literal
     placeholder assertion on `admin-cli` answers the second rung of the ladder.
     **Fixed on the branch**, and served.
   - `oidc/token/dpop-bound-token` said "DPoP is not implemented". True of Gloak
     and wrong about why the case is Pending: DPoP is a `DEFAULT` feature that
     works. **Corrected on the branch** to name the two properties of a proof
     that make it unrecordable. The case stays Pending.
   `oidc/token/ciba-grant` is the one of the five whose `Reason` survived
   unchanged, and it is the only one of the eleven that is still unreachable.

Nothing in the observed document is contradicted, because it has **nothing at
all** about `/clients-registrations`. That is worth saying rather than leaving as
a silence: the endpoint's contract now lives in fourteen goldens, this handover
and `internal/oidc/registration.go`'s comments, and the observed document is one
of the files this cut may not edit.

## 4. Follow-up dispositions

**Closed on this branch**

- Nothing in the numbered list. Dynamic client registration had no follow-up of
  its own; it had six catalogue cases and a parked golden.

**Corrected**

- **F86** is six prefixes, not four and not five. Section 3.5.

**Extended rather than filed anew**

- **F31.** Two more data points, both in section 3.6: a fourth 404/405 split, on
  the protocol side, and `HEAD`'s third answer.

**New, and each reproduced rather than theorised**

- **A registration access token's identity is in memory.** The registered client
  persists through `store.ClientRepo` like any other; what does not is the jti of
  the token a caller must present to read, update or delete it. `model.Client` has
  no field for it and `internal/model` and `internal/store` are owned elsewhere
  this session; writing it into `Attributes` would put it in the Admin API's
  client representation, where the measured five-key attribute set says it does
  not belong. **The cost is that a restart makes every outstanding registration
  access token stop working**, where Keycloak's survives. One column on the
  client table closes it.
- **Nothing mints an initial access token.** `POST
  /admin/realms/{r}/clients-initial-access` is `internal/admin`'s, and until it
  exists the registration endpoint's initial-access-token branch would be
  unreachable, so this cut has none. The Admin API side is also stateful - a
  remaining count that decrements and a measured 401 when it runs out.
- **Three of the four registration providers are unserved.** `default`,
  `install` and `saml2-entity-descriptor` fall through to the unmatched-path 404,
  and so does an unknown provider, where Keycloak answers
  `{"error":"Client registration provider not found"}`. Registering a
  `{provider}` wildcard would let Gloak send that measured string for two
  providers that exist, which is a measured body for the wrong condition, so
  nothing was registered.
- **Gloak's registration decoder is not strict.** Keycloak refuses an unknown
  field with a 400 naming the field, the line and the column;
  `encoding/json` ignores it. `DisallowUnknownFields` would produce a different
  message, and the measured one carries a byte offset Go does not report the same
  way.
- **A `Content-Type` header present with an empty value is a 500 HTML page.**
  Measured; not reproduced. Go's `Header.Get` cannot tell it from an absent
  header without reading the map directly, and an HTML 500 is a shape this
  project has nowhere else.
- **DPoP is unimplemented on purpose.** Section 1.15 has the whole ladder and the
  `cnf` claim's shape. A partial implementation that answered `DPoP header
  verification failure` to everything would refuse a *valid* proof, which is a
  worse divergence than the present unbound 200; a faithful one needs a `cnf`
  claim inside `internal/token`'s access **and** refresh claim structs, whose key
  positions every token golden in the catalogue reads.
  `oidc/token/dpop-header-invalid` is `Recorded` so the contract is in the
  repository for whoever picks it up.
- **The registration endpoint's cross-realm cells are unmeasured.** Only
  master-administering-master was measured, because it is the only cell a default
  container reaches without creating a second realm.
  `registrationGrants` reproduces `internal/admin`'s `containerFor` shape so the
  two cannot answer differently, and says so.

## 5. Parity, before and after

Measured with `TestCoverage` on the branch point (`969fcc7`) and on the tip:

```
                                        before            after
oidc/registration                        0 of 6         14 of 14
oidc/token                              16 of 21        19 of 22
total                             311 of 526        328 of 535
```

`+17` behaviours served, `+9` denominator. The denominator grows because eight
of the fourteen registration cases and one of the token ones are new: eight
registration refusals the six original cases did not name, plus
`oidc/token/dpop-header-invalid`, which is `Recorded` and therefore counts
against the denominator and not for the numerator - honestly, since Gloak does
not serve it.

Two cases stay `Pending`, both for reasons that are measurements rather than
to-do notes: `oidc/token/ciba-grant` needs an authentication channel a default
26.7.1 does not have, and `oidc/token/dpop-bound-token` needs a proof no
`Case.Request` can express.

**Two files outside this cut's own were edited**, both because a guard demanded
it and both a single entry:

- `internal/conformance/case_test.go`, dropping the `parkedGoldens` entry for
  `oidc/registration/without-initial-access-token`. `TestEveryParkedGoldenIsDeclared`
  fails for a declared case that is no longer Pending, so leaving it would have
  been red.
- `internal/conformance/catalog_test.go`, adding one `prefixMasksLeftInPlace`
  entry for `oidc/registration/create-client`'s `registration_client_uri`. The
  mask covers `{{issuer}}` plus a UUID the case's **own request** mints, so no
  fixture capture can reach it and `ReplaceCaptured` cannot narrow it; the
  guard's own message names this list as the way to say so, and the entry beside
  it is the same shape for the same missing mechanism. The three reads of the
  same client mask nothing at all, which is what says the loss is this one
  request's rather than the field's.

## 6. Mutation testing

Forty-one mutations, one per claim, each run against the single named test and
reverted from a copy rather than with `git checkout`. **Thirty-eight were killed
on the first run and three survived**, and two of the three turned out to be
findings about the *server* rather than only about the test.

### Survivor 1: an anonymous caller cannot show an ordering

Swapping the decode and the caller resolution in `registerClient` passed
`TestTheBodyIsJudgedBeforeTheCaller`. The test sent **no Authorization header**,
and an anonymous caller writes nothing on the way through - `registrationCaller`
returns it and lets the handler decide - so moving the decode behind it changed
no byte of either answer.

The request that tells the two orders apart is one whose credential **would**
have written a refusal. Sent to the live container:

```
garbage bearer + text/plain        415  the Content-Type still wins
garbage bearer + `{`               400  the JSON still wins
garbage bearer + a good body       401  Failed decode token
PUT, garbage bearer + text/plain   415  the update behaves the same way
```

So the implementation was right and the test could not see it. **Fixed on the
branch**: the test now sends a garbage bearer, carries the 401 as its control,
and covers the `PUT` as well. The mutation dies, and so does the same swap
inside `updateRegisteredClient`, which nothing had tried.

This is the shape cut A hit on CIBA: a suite that breaks one thing per case
passes an implementation whose *order* is wrong.

### Survivor 2: a mutation that changes nothing observable

Setting `IncludeIDToken: true` in `tokenExchangeGrant` passed
`TestTokenExchangeAnswersEightKeysNotNine`. It is **equivalent**:
`exchangeResponse` has no `id_token` field, so the ID token the issuer mints is
dropped before it reaches the wire. The line is documentation, and what enforces
the measured absence is the response type.

Nothing was changed to make it die, because making it die would mean adding a
field this response must not have. The test now asserts over the **raw body**
that neither `id_token` nor `refresh_token` appears, which is what would catch
the field being added later - the failure the equivalence is hiding.

### Survivor 3: the test could not see the rule it was written for, and the rule was wrong

`TestTheAssertionPredicateIsStructural` passed a mutation that accepted a
**two**-part assertion. Reading why: all five of its refused inputs were refused
for their *payload* - `a.b.c`'s middle part is not JSON, `aGVsbG8.d29ybGQ`'s is
not either - so the part-count check and the JSON check could never be told
apart. Every probe that had been sent at the live container had the same defect.

The distinguishing probe is a two-part string whose second part **is** base64url
JSON, and it says the implementation was wrong:

```
one part                           The provided assertion is not a valid JWT
two parts, a JSON object payload   accepted - reaches Missing claim: sub
three parts                        accepted
three parts, an empty signature    accepted
four parts, five parts             The provided assertion is not a valid JWT
an empty header or payload part    The provided assertion is not a valid JWT
a payload that is a JSON array     The provided assertion is not a valid JWT
```

So the signature is **optional**, an empty one is fine, and the two parts in
front of it are not. **Fixed on the branch**, and the test is now the fourteen
rows above rather than five that all failed the same way.

The same probe found **a seventh rung on the ladder**: an assertion carrying
`iss` and no `sub` answers `Missing claim: sub`, which no earlier probe had seen
because every one of them sent both claims. It is checked after `iss` and before
the identity provider lookup. Implemented, and both adjacencies are pinned.

### What the tests still do not pin

- **`registrationStore.holds` refusing an empty jti** is defence in depth and
  unreachable: `ParseRegistration` already refuses a token whose `jti` is empty,
  so no request can get there. Written down rather than tested.
- **`deleteRegisteredClient` calling `forget`** cannot be observed either: the
  client is gone by then, so the entry it leaves behind can never be matched
  against a client id again. It is a leak rather than a behaviour, and a
  mutation removing it changes nothing.
- **The `Content-Type` header present with an empty value.** Keycloak answers a
  500 HTML page; Gloak treats it as absent. Section 4 has it.

## 7. Two things that would have gone wrong quietly

- **The five registration cases would have waited for `internal/admin`.** Their
  `Fixture` comments said they needed an initial access token "which the
  bootstrap fixture has no admin API access to mint", and the obvious next step
  was to build one - which would have made all five depend on a route Gloak does
  not serve, so the *fixture* would have failed on the verifier and the cases
  would have looked unreachable for a second reason. One probe with an ordinary
  admin token settled it.
- **The catalogue's three item cases addressed `/gloak-probe`.** A registered
  client's id is a server-minted UUID and a create naming one is refused, so
  those three requests could never have found anything. Serving them "correctly"
  without measuring would have produced an endpoint that answers 404 to its own
  clients.
