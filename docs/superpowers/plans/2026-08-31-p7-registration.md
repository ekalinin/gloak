# P7 cut C: dynamic client registration, and the grants the measurement supports

Branch `feat/p7-registration`, off `969fcc7`. Measured against a live Keycloak
26.7.1 on 2026-08-31, container `kc-reg` on port 8142, checked to be answering on
127.0.0.1 before any probe was trusted. `kc-authzb` was not running and was not
touched.

## 1. Which of the eleven are reachable, and why

The brief names eleven `Pending` cases. **Nine of the eleven are reachable and
two are not**, and the two that are not are unreachable for reasons that are
themselves measurements. Every line below was measured on 8142 today.

| Case | Reachable | What the measurement says |
|---|---|---|
| `oidc/registration/without-initial-access-token` | yes | 403, already parked as a golden. Now a compared contract. |
| `oidc/registration/create-client` | yes | **An ordinary admin access token registers.** No initial access token needed - see section 2. |
| `oidc/registration/read-client` | yes | Same token; the read has **two body shapes** and this is the shorter one. |
| `oidc/registration/with-registration-access-token` | yes | The longer shape. The two cases stop being duplicates. |
| `oidc/registration/update-client` | yes | `PUT` with the registration access token, which it then **rotates**. |
| `oidc/registration/delete-client` | yes | 204, four security headers, no `X-Frame-Options`. |
| `oidc/token/device-code-grant` | yes | **Its `Reason` is stale.** The verification and consent pages it waits on landed in cut B; `deviceDeniedFixture` already walks the whole browser flow and an approval is that fixture minus one form field. |
| `oidc/token/token-exchange` | yes | **`TOKEN_EXCHANGE_STANDARD_V2` is `DEFAULT` and enabled** on a default 26.7.1. Only the legacy `TOKEN_EXCHANGE` is the disabled preview. |
| `oidc/token/jwt-authorization-grant` | yes, as refusals | Four measured refusals, all static. The happy path is unreachable on any default container - see section 3. |
| `oidc/token/dpop-bound-token` | **no**, as written | `DPOP` is enabled by default and the grant works. What cannot be recorded is a **proof**: it goes stale in tens of seconds *and* its `jti` is single-use. Section 4. |
| `oidc/token/ciba-grant` | **no** | Unchanged and correct: no default container mints an `auth_req_id`. |

So the count is not "six registration cases plus five grants". Measuring the two
registration endpoints produced **thirty-one distinct answers** against the six
the catalogue names, and the token endpoint's three unmeasured grants produced
**fourteen** against three. The catalogue was naming the happy path of each and
missing every adjacency, which is the same shape cut A found.

## 2. The initial access token, and why these five do not wait on it

The brief asks whether a conformance fixture can mint an initial access token
through the Admin API it already drives, or whether the five cases wait for
`internal/admin`. **Neither. The question does not arise, because the
registration endpoint does not need one.**

Measured, `POST /realms/master/clients-registrations/openid-connect`:

```
no Authorization header                403  insufficient_scope / Policy 'Trusted Hosts' ...
Authorization: Bearer <empty>          403  the same body
Authorization: Basic ...               403  the same body
Authorization: Bearer not-a-token      401  invalid_token / Failed decode token
Authorization: Bearer <initial access> 201
Authorization: Bearer <admin access>   201
```

The last two are **byte-identical in shape**, and the registration access token
each mints carries the same `"registration_auth":"authenticated"`. So the
`admin-token` fixture this catalogue has had since P1 is a working credential for
all five cases, and `POST /admin/realms/{r}/clients-initial-access` - which is
`internal/admin`, owned elsewhere this session - is not on the path.

That matters beyond convenience. Had the fixture minted one, every one of the
five cases would have depended on an Admin API route Gloak does not serve, and
the verifier would have failed on the *fixture* rather than on the case. Using
the admin bearer keeps the five cases dependent only on surface Gloak already
has.

What is measured about the admin bearer is which role opens it. One role at a
time, six callers:

```
no admin role    403  insufficient_scope / Forbidden
create-client    201
manage-clients   201
view-clients     403  insufficient_scope / Forbidden
query-clients    403  insufficient_scope / Forbidden
manage-realm     403  insufficient_scope / Forbidden
```

**Two 403s with different bodies on one endpoint**, decided by whether a bearer
token was presented at all. An anonymous caller is told about the Trusted Hosts
policy; an authenticated caller holding the wrong role is told `Forbidden`. A
single "not allowed" constant gets one of them wrong.

The initial access token is still worth writing down, because it is what a real
client uses: it is an HS512 JWT with `"typ":"InitialAccessToken"`, `exp` 0, and a
`jti` equal to the `id` the Admin API answers - and it is **stateful**, with a
remaining count that decrements. `count: 2` used three times answers
`401 invalid_token / No remaining count on initial access token`. Gloak's
registration endpoint gets no branch for it on this cut: nothing in Gloak mints
one, so the branch could not be reached, let alone recorded. Filed.

## 3. What the grants measure

### `urn:ietf:params:oauth:grant-type:token-exchange`

Standard token exchange (v2) is on by default. `GET /admin/serverinfo` reports
`TOKEN_EXCHANGE_STANDARD_V2` `"type":"DEFAULT"`, enabled, while `TOKEN_EXCHANGE`
and `TOKEN_EXCHANGE_DELEGATION` are disabled previews. The catalogue's `Fixture`
comment - "a feature that must be explicitly enabled" - was true of the feature
that is *not* the one this grant reaches.

The gate is a client attribute, `standard.token.exchange.enabled`. The measured
ladder, on one container:

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | the attribute is off | 400 | `invalid_request` / `Standard token exchange is not enabled for the requested client` |
| 2 | `subject_token` absent | 400 | `invalid_request` / `Parameter 'subject_token' required for standard token exchange` |
| 3 | `subject_token_type` absent | 400 | `invalid_request` / `Parameter 'subject_token_type' required for standard token exchange` |
| 4 | `subject_token_type` not an access token | 400 | `invalid_request` / `Parameter 'subject_token' supports access tokens only` |
| 5 | `subject_token` unverifiable | 400 | `invalid_request` / `Invalid token` |
| 6 | `requested_token_type` a refresh token | 400 | `invalid_request` / `requested_token_type unsupported` |
| 7 | valid | 200 | eight keys, one of them new |

The success is **not the ordinary nine keys**: no `refresh_token`, no `id_token`,
`refresh_expires_in` 0, and an eighth key `issued_token_type` after `scope`. The
access token's `jti` prefix is `onrtte:`, which is a **sixth** prefix for F86 -
cut A corrected that follow-up from four to five and this is one more.

### `urn:ietf:params:oauth:grant-type:jwt-bearer`

| # | Condition | Status | Body |
|---|---|---|---|
| 1 | client authentication | 401 | as elsewhere |
| 2 | a repeated form key | 400 | `invalid_request` / `duplicated parameter` |
| 3 | `assertion` absent | 400 | `invalid_grant` / `Missing parameter:assertion` |
| 4 | `assertion` empty or unparseable | 400 | `invalid_grant` / `The provided assertion is not a valid JWT` |
| 5 | a public client | 400 | `invalid_grant` / `Public client not allowed to use authorization grant` |
| 6 | a confidential client | 400 | `invalid_grant` / `JWT Authorization Grant is not supported for the requested client` |

Note (3): **`Missing parameter:assertion` has no space after the colon**, where
every other missing-parameter description on this endpoint is
`Missing parameter: x`. That is a third spelling of one phrase, after CIBA's
`missing parameter : login_hint` with a space on both sides.

Step 4 precedes step 5, which is what makes the catalogue's case reachable
exactly as written: `admin-cli` plus a literal placeholder assertion answers
`The provided assertion is not a valid JWT` and never reaches the public-client
check. **No client configuration opens step 6.** Six attribute spellings were
tried on a confidential client and all six answered it. The two features that
would - `TOKEN_EXCHANGE` and `TOKEN_EXCHANGE_DELEGATION` - are disabled previews,
so the ladder above is the whole of this grant on a default 26.7.1, the same
shape as `client-types`' 501 and CIBA's 503.

### DPoP

`DPOP` is `"type":"DEFAULT"` and enabled, and the grant works: a proof signed
ES256 over a P-256 key gets a 200 whose `token_type` is `DPoP` and whose access
*and* refresh tokens carry `"cnf":{"jkt":"<RFC 7638 thumbprint>","kc-jkt-type":"DPoP"}`.

It is the **harness** that cannot express it, for two independent reasons, and
each was measured rather than reasoned:

- **The proof has an age window.** `iat` at -5s, -11s and -20s are accepted;
  -60s, -3600s, +20s and +60s answer `DPoP proof is not active`. A literal in the
  catalogue is stale within a minute of being written.
- **A proof is single-use.** The identical header sent twice answers
  `DPoP proof has already been used`. So even a proof minted seconds ago could
  not be recorded and then replayed by the verifier.

The refusals are static and were measured anyway, because they are the only part
of DPoP anything in this repository can hold:

| Condition | Body |
|---|---|
| `dpop.bound.access.tokens` on the client, no header | `invalid_request` / `DPoP proof is missing` |
| a header that is not a JWS | `invalid_request` / `DPoP header verification failure` |
| the header sent twice | the same |
| `htu` disagreeing | `invalid_request` / `DPoP HTTP URL mismatch` |
| `htm` disagreeing | `invalid_request` / `DPoP HTTP method mismatch` |

**Nothing about DPoP is implemented on this branch**, and that is a choice
rather than an omission. A partial implementation that answered
`DPoP header verification failure` to everything would refuse a *valid* proof,
which is a divergence where the present 200 is merely an unbound token; and a
faithful one means a `cnf` claim inside `internal/token`'s access and refresh
claim structs, whose key position is read by every token golden in the
catalogue. The case's `Reason` is corrected to say which of the two halves is
missing, and the ladder is written into the handover for whoever picks it up.

## 4. What dynamic registration is, measured

### Four endpoints, one of which is four endpoints

`/realms/{realm}/clients-registrations/{provider}` has four providers on a
default container and they do not agree about verbs:

```
openid-connect            POST 201, GET/PUT/DELETE on the item path
default                   POST 201, GET 200 - Keycloak's own ClientRepresentation
install                   GET 200 - an adapter config; POST is 405
saml2-entity-descriptor   POST only, and not JSON; GET is 405
anything else             404 {"error":"Client registration provider not found"}
```

Only `openid-connect` is implemented on this branch; the catalogue names only
that one. The other three, and the unknown-provider 404, are recorded and filed.

### The create

`POST .../openid-connect` with an admin bearer answers **201**,
`Content-Type: application/json;charset=UTF-8`, a `Location` ending in the new
client's id, the five security headers, and **no `Cache-Control` at all**. Twenty
keys in this order:

```
redirect_uris, token_endpoint_auth_method, grant_types, response_types,
client_id, client_secret, client_name, scope, subject_type, request_uris,
tls_client_certificate_bound_access_tokens, dpop_bound_access_tokens,
post_logout_redirect_uris, client_id_issued_at, client_secret_expires_at,
registration_client_uri, registration_access_token,
backchannel_logout_session_required, require_pushed_authorization_requests,
frontchannel_logout_session_required
```

Five things about that body are not guessable:

- **`client_id` is a server-minted UUID and a body naming one is refused**:
  400 `invalid_client_metadata` / `Client Identifier included`. So the
  catalogue's `read/update/delete` cases addressing `/gloak-probe` could never
  have worked; the id has to be captured from the create.
- **`client_name` is omitted when absent**, where every array is emitted empty.
- **`token_endpoint_auth_method: "none"` drops two keys, not one**:
  `client_secret` *and* `client_secret_expires_at` both disappear.
- **`grant_types` and `response_types` are derived from the client's flow flags
  and interlock.** Sending `response_types:["token","id_token"]` comes back
  `grant_types:["implicit","refresh_token"]`; sending `grant_types:["implicit"]`
  comes back `response_types:["id_token","id_token token"]`. Neither is stored.
- **`scope` is the client's optional client scopes joined by spaces**, in the
  realm's order rather than the request's: `"email profile"` goes in and
  `"profile email"` comes back.

### The two read shapes

`GET .../openid-connect/{clientId}` answers 200 to a registration access token
**and** to an admin bearer, and the two bodies differ: the registration access
token's carries `registration_access_token` and the admin bearer's does not.
Both omit `client_id_issued_at`, which the create emits. So the create's body,
the token-holder's read and the administrator's read are **three shapes of one
representation** and a shared serialiser is wrong on two of them.

The read is also not limited to registered clients: `GET .../openid-connect/admin-cli`
answers 200 with `admin-cli` in the OIDC shape, `client_name` echoing the theme
key `${client_admin-cli}` raw.

### The update, and the rotation

`PUT` requires the body's `client_id` to equal the path's. Absent and
disagreeing both answer 400 `invalid_client_metadata` / `Client Identifier
modified` - one message for two conditions. It **keeps the client secret** and
**rotates the registration access token**: the old one answers 401 immediately
afterwards. A `GET` does not rotate it - two reads with one token returned the
same token both times and it still worked.

### The refusals

```
no auth                       403  insufficient_scope / Policy 'Trusted Hosts' ...
authenticated, wrong role     403  insufficient_scope / Forbidden
garbage bearer                401  invalid_token / Failed decode token
another client's token        401  invalid_token / Not authorized to view client. Not valid token or client credentials provided.
no Authorization on an item   401  the same
unknown client                404  invalid_request / Client not found
unknown realm                 404  {"error":"Realm does not exist"}
no Content-Type               415  {"error":"The content-type header value did not match the value in @Consumes"}
malformed JSON                400  invalid_request / Cannot parse the JSON
an unknown JSON field         400  {"error":"Invalid json representation for OIDCClientRepresentation. Unrecognized field \"x\" at line 1 column 56."}
```

The last one is a **fifth strict JSON decoder**, and it reports the line and the
column. AGENTS.md counts four.

## 5. Where the code goes

- `internal/token/registration.go` - mint and verify the `RegistrationAccessToken`,
  HS512 over the realm's HMAC secret, the same key `ParseRefresh` uses. New file
  in a package this cut owns.
- `internal/oidc/registration.go` - the provider: the four verbs, the auth
  ladder, the representation and its three shapes.
- `internal/oidc/registrationstore.go` - which registration access token is
  current for a client. **In memory, and the reason is not the device store's.**
  The *client* persists through `store.ClientRepo.Create/Update/Delete`, which
  already exists, so the brief's warning is respected: a registered client is not
  ephemeral and is not treated as such. What is in memory is only the token id a
  `PUT` rotates, because `model.Client` has no field for it and `internal/model`
  and `internal/store` are owned elsewhere this session. Writing it into
  `Attributes` would put it in the Admin API's client representation, where the
  measured five-key attribute set says it does not belong. The cost is stated in
  the file and filed: a restart makes existing registration access tokens stop
  working.
- `internal/oidc/tokenexchange.go` - the standard v2 grant.
- `internal/oidc/jwtbearer.go` - the four refusals, in the measured order.
- `internal/conformance/fixture.go` - `registration-created`, `device-approved`,
  `token-exchange`.
- `internal/conformance/catalog_oidc.go` / `catalog_oidc_pending.go` - promote,
  correct the stale `Reason`s, and add the adjacencies the measurement found.

Client scopes come from `bootstrap.InheritClientScopes`, which is what
`internal/admin` calls on its own create, so a registered client inherits the
same six defaults and five optionals a measured one has. The secret comes from
`model.NewSecret`, whose 86-character alphabet was measured on an
admin-API-created client and is measured here to be the same on a registered one.

## 6. What is deliberately not done

- **DPoP.** Section 3. Recorded, not implemented.
- **The initial access token branch.** Nothing in Gloak mints one.
- **`default`, `install`, `saml2-entity-descriptor`.** Measured and filed. Gloak
  keeps answering the unmatched-path 404 for them rather than borrowing
  `Client registration provider not found`, which is a measured string for a
  different condition.
- **CIBA.** Unchanged.

## 7. Discipline

Every claim gets one mutation, run against the single named test and reverted
from a copy. A survivor is a finding about the test and goes in the handover.
`make record` is run on a clean checkout and its diff read. `make lint` and
`CGO_ENABLED=0 go test ./...` are the gate.
