# P3, the `authorization_code` grant: handover

Branch `feat/p3-code-grant`, off `a308eb0`. Plan:
`docs/superpowers/plans/2026-08-30-p3-code-grant.md`.

Gloak completes a browser OAuth flow for the first time: `GET /auth` serves a
login form, the credential POST mints a code, and the token endpoint now
redeems it into the measured nine-key response.

Everything below was measured against a live `quay.io/keycloak/keycloak:26.7.1`
on port 8097 (`kc-code`), started for this cut and removed after it, on
2026-08-30.

---

## 1. Measurements

### 1.1 The eight recorded rejections all reproduced, and there are twelve

The observed document's section **"The token endpoint's answers to an
authorization code"** was written by a cut that could not serve the endpoint, so
every row was re-measured rather than trusted. **All eight reproduced byte for
byte**, including the two the section itself records as a correction. So did the
success body: nine keys in the recorded order, `expires_in` 60,
`refresh_expires_in` 1800, `scope` `openid profile email`,
`Cache-Control: no-store`, `Pragma: no-cache`, `application/json`, the five
security headers and no `Content-Security-Policy`. The three committed goldens
are right.

What the section is wrong about is its own completeness. It says "Every
rejection" over eight rows; there are **twelve**. The four it does not name:

| Request | Status | Body |
|---|---|---|
| any **form** key sent twice | 400 | `{"error":"invalid_request","error_description":"duplicated parameter"}` |
| a challenge was sent to `/auth` and no `code_verifier` here | 400 | `{"error":"invalid_grant","error_description":"PKCE code verifier not specified"}` |
| no challenge was sent and a `code_verifier` is | 400 | `{"error":"invalid_grant","error_description":"PKCE code verifier specified but challenge not present in authorization"}` |
| a `code_verifier` outside RFC 7636's production | 400 | `{"error":"invalid_grant","error_description":"PKCE verification failed: Invalid code verifier"}` |

All four are **served and tested on this branch**.

### 1.2 The order, and two steps are not where they look

Measured by driving two faults at once, one pair per adjacency.

```
1.  grant_type absent          400 invalid_request  Missing form parameter: grant_type
2.  grant_type unknown         400 unsupported_grant_type  Unsupported grant_type
3.  client authentication      401 invalid_client / unauthorized_client
4.  a duplicated form key      400 invalid_request  duplicated parameter
5.  code absent                400 invalid_request  Missing parameter: code
6.  code not redeemable        400 invalid_grant    Code not valid
7.  redirect_uri               400 invalid_grant    Incorrect redirect_uri
8.  the code's own client      400 invalid_grant    Auth error: Found different client_id in clientSession
9.  PKCE, four answers         400 invalid_grant
```

**Step 4 is fourth.** `zz` twice with no `grant_type` answers about
`grant_type`; with an unknown `grant_type`, about the grant type; with an
unknown `client_id`, the **401**; with a valid client and a wrong password, the
duplicate. So it is neither first nor part of the grant.

**Step 7 precedes step 8.** Another client redeeming a code with a wrong
`redirect_uri` answers `Incorrect redirect_uri`, so the URI is compared against
the code's stored value *before* the caller is compared with the code's client.
An implementation that folded the two into one "may this caller have this code"
check answers the wrong one to a stranger.

Everything else falls where a reader would put it: `zz` twice beats a missing
`code`, a missing `code` beats a missing `redirect_uri`, an unusable code beats
a wrong `redirect_uri`, and a wrong `redirect_uri` beats a wrong verifier.

### 1.3 `duplicated parameter` at the token endpoint reads the body

Same lower-case spelling as `/auth`'s, same "any key, including one the endpoint
never reads" rule - `zz` twice is enough and `grant_type` twice is the same
answer. Two things are this endpoint's own:

- **The body, not the query.** `zz=1&zz=2` on the query of an otherwise valid
  password grant is a **200**; one `zz` in each is a 200; both in the body is the
  400. And the whole grant in the query with an empty body answers
  `Missing form parameter: grant_type`, so the query is not read at all.
- **After client authentication**, where `/auth`'s runs seventh among ten.

It is not this grant's: it fires on the password grant too, which is what the
new conformance case sends.

### 1.4 PKCE, four answers and a production

| stored challenge | `code_verifier` | answer |
|---|---|---|
| none | absent | success |
| none | present | `PKCE code verifier specified but challenge not present in authorization` |
| present | absent | `PKCE code verifier not specified` |
| present | outside 43..128 unreserved | `PKCE verification failed: Invalid code verifier` |
| present | well formed, no match | `PKCE verification failed: Code mismatch` |
| present | matches | success |

Measured at both bounds and on the alphabet: 42 `a` is `Invalid code verifier`,
128 `a` reaches the comparison and is `Code mismatch`, 129 `a` is `Invalid`, 43
`!` is `Invalid`. **An empty `code_verifier=` is `Invalid code verifier`, not
`not specified`** - so "not specified" is about an absent parameter and an empty
one has already reached the shape check.

`S256` and `plain` both verify, and a `code_challenge` sent with **no**
`code_challenge_method` defaults to `plain` - the same default `checkPKCE`
already records at the authorization endpoint.

### 1.5 `auth_time` is the browser flow's, and it is the login's time

| grant | access token | ID token |
|---|---|---|
| `authorization_code` | `auth_time` after `iat` | `auth_time` after `iat` |
| `password` | none | none |
| `refresh_token` of a browser session | **the original** `auth_time` | - |
| `refresh_token` of a password session | none | - |
| `authorization_code` at a **lightweight** client | none | `auth_time` present |

Measured on one container minutes apart, on a client with no lightweight
attribute, so the variable is the grant and not the client. It is the time the
**user authenticated**, not the time of issuance: a login left six seconds
before the exchange produced `iat - auth_time == 6`.

The refresh row is the one Gloak cannot reproduce. `auth_time` is a property of
the **user session**, and `model.UserSession` is `internal/model`'s, which this
cut may not touch. The code grant emits it from the session's start time; the
refresh grant emits none. Filed as F79 rather than half-done.

The lightweight row confirms the observed document's `security-admin-console`
exception, re-measured here through a real browser login at that client: eight
claims `exp iat jti iss typ azp sid scope`, and its **ID** token does carry
`auth_time`.

### 1.6 `nonce` sits between `azp` and `sid`, on the ID token alone

The access and refresh tokens never carry it whatever the authorization request
said.

### 1.7 Which failures spend the code - four of five

| failure | the code afterwards |
|---|---|
| a wrong `redirect_uri` | spent - the retry answers `Code not valid` |
| another client's `client_id` | spent |
| `PKCE code verifier not specified` | spent |
| `PKCE verification failed: Code mismatch` | spent (already recorded) |
| **a failed client authentication (the 401)** | **not spent** - the retry with the secret succeeds |

Which follows from the order rather than from a rule: the 401 is step 3 and the
code is not looked at until step 6.

### 1.8 Three more things that answer `Code not valid`

- **An expired code.** `accessCodeLifespan` is 60 seconds; redeemed at 65 it is
  `Code not valid`, the same as a replay.
- **A code whose user session has been deleted.** `DELETE
  /admin/realms/master/sessions/{id}` between the login and the exchange, and the
  answer is about the code rather than the session.
- **An empty `code=`.** It reaches the lookup, where an absent one answers
  `Missing parameter: code`.

### 1.9 What does *not* stop the exchange

Three things that each looked like a check and are not:

- The client **disabled** between the login and the exchange: 200.
- The client's **standard flow** turned off between them: 200.
- A `redirect_uri` that is registered on the client but is not the code's:
  `Incorrect redirect_uri`. The comparison is against the stored value, never
  against the pattern list.

### 1.10 SSO, measured and deliberately not built

A second `GET /auth` on a jar that has already logged in is a **302 carrying a
real code**, no login page, and it:

- sets **five** cookies - a fresh `AUTH_SESSION_ID` and `KC_AUTH_SESSION_HASH`,
  a `KC_RESTART`, and a re-issued `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION`;
- answers `session_state` = the **original** login's user session id, and mints
  `AUTH_SESSION_ID` around that same value - which is why the two look equal in
  a transcript and are not the same fact, and why a first reading of this
  measurement had it backwards;
- carries the original `auth_time` into the exchanged token;
- leaves the first session refreshable - one user session, two codes;
- omits `X-Frame-Options` and `Content-Security-Policy`, like every other
  `/auth` redirect.

`prompt=none` on that jar answers the same 302 with a code, and **clears**
`KC_RESTART` where the plain second request sets one.

### 1.11 The access token's `jti` carries a per-grant prefix

`onrtac:` for the authorization code, `onrtro:` for the password grant,
`onrtrt:` for a refresh, and `onltac:` on a **lightweight** client's code grant.
So the prefix encodes the token's storage kind and the grant that made it. The
ID and refresh tokens' `jti` carry none. Gloak emits a bare UUID on all four.

Asserted by nothing: `access_token` is masked in every golden and the
introspection golden masks `jti`. **Not fixed on this branch** - see §3, F80.

### 1.12 A lightweight client's refresh token omits `sub` and `aud_x`

Measured on `security-admin-console`: `exp iat jti iss aud typ azp sid scope
prov`, ten claims against the twelve a normal client's carries. Gloak emits both
on every client, including `admin-cli`, which is lightweight. Pre-existing,
unasserted, **not fixed on this branch** - see §3, F81.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

### 2.1 New bullets

- **The token endpoint answers a repeated parameter too, and its rule is not
  `/auth`'s.** `{"error":"invalid_request","error_description":"duplicated
  parameter"}`, the same lower-case spelling, on any key including one nobody
  reads - `zz` twice, `grant_type` twice. But it reads the **form body and not
  the query**: `zz` twice on the query of a valid password grant is a 200, one
  in each is a 200, and both in the body is the 400. And it runs **after client
  authentication**, where `/auth`'s runs seventh of ten. So the two endpoints
  agree on the string and disagree on both the source and the position, and a
  shared checker would get one of them wrong. It is not the code grant's either:
  it fires on every grant.

- **`auth_time` belongs to the user session, not to the token.** A browser
  login's access and ID tokens carry it and a password grant's carry neither,
  measured on one client minutes apart. It is the time the user authenticated,
  not the time of issuance - a login left six seconds before the exchange gives
  `iat - auth_time == 6` - and **it survives a refresh**: refreshing a
  browser-login session produces an access token with the original value, and
  refreshing a password-grant session produces one with none. Stamping it at
  issuance is the obvious implementation and it is wrong on two grants. Gloak
  cannot reproduce the refresh row because `model.UserSession` has nowhere to
  keep it, which is F79. And **a lightweight client is a fifth answer**: its
  access token has no `auth_time` while its ID token does.

- **The code exchange's four PKCE answers.** An absent verifier against a stored
  challenge is `PKCE code verifier not specified`; a verifier against no stored
  challenge is `PKCE code verifier specified but challenge not present in
  authorization`; a verifier outside RFC 7636's 43-to-128 unreserved production
  is `PKCE verification failed: Invalid code verifier`; and only a well-formed
  one that does not match is the `Code mismatch` the catalogue already records.
  **An empty `code_verifier=` is the third and not the first**, so the absence
  check is on the parameter and the shape check catches the empty string.
  Measured at both bounds: 42 characters is invalid, 128 reaches the comparison.

- **A failed code exchange spends the code, except the 401.** Four failures
  spend it - a wrong `redirect_uri`, another client's `client_id`, a missing
  verifier and a mismatched one all answer `Code not valid` on the retry - and a
  failed **client authentication** does not: the retry with the secret succeeds.
  That is not an exception anybody has to remember, it is what the order
  produces, since client authentication happens three steps before the code is
  looked at. Moving the lookup earlier "to fail fast" is the tidy-up that turns
  a mistyped secret into a lost login.

- **The redirect URI is compared before the caller is.** Another client
  redeeming a code with a wrong `redirect_uri` answers `Incorrect redirect_uri`,
  not `Auth error: Found different client_id in clientSession`. And the
  comparison is against the value the authorization request **stored**, never
  against the client's registered patterns: a code minted for one registered URI
  and redeemed naming another registered one is refused. Folding the two checks
  into one "may this caller have this code" is the simplification that answers
  the wrong one.

- **A code is redeemable only while its session lives, and three different
  causes answer `Code not valid`.** A replay, an expiry past the realm's
  60-second `accessCodeLifespan`, and a user session deleted between the login
  and the exchange are one answer, not three. So is an empty `code=`, which
  reaches the lookup where an absent one answers `Missing parameter: code`.

- **A client disabled between the login and the exchange still redeems.** So
  does one whose standard flow has been turned off. Both were measured because
  both look like checks; the client's state is judged at `/auth`, and the code
  is a decision already taken.

### 2.2 Lines these measurements contradict

1. **The observed document, "The token endpoint's answers to an authorization
   code": "Every rejection, ..." over eight rows.** There are twelve. §1.1.
   **Fixed on the branch**: all four are served, and three of them are pinned by
   `TestCodeVerifierHasFourAnswers` and one by a new conformance case.

2. **`AGENTS.md`: "A failed code exchange spends the code."** True from step 6
   onwards and **false of the 401**. §1.7. **Fixed on the branch**: the 401
   cannot reach `spendCode`, and
   `TestEveryRedemptionFailureSpendsTheCodeExceptOne` pins both directions -
   four failures that burn it and one that does not.

3. **`AGENTS.md`: "A repeated parameter is an error at `/auth` and at neither of
   its neighbours ... `/auth` is the odd one of the three, not the rule."** The
   token endpoint is a fourth endpoint in the same flow and it **is** an error
   there, so the count is two against two and "the odd one of the three" no
   longer follows. What survives is per endpoint. **Fixed on the branch** for
   the token endpoint; the sentence about `/auth`'s neighbours is still true of
   `/logout` and `/login-actions/authenticate` and should be re-worded rather
   than deleted.

4. **The observed document's claim-set line for this grant: "plus `auth_time`
   and `acr`".** `acr` is not new. The password grant already carries it on both
   the access and the ID token and Gloak already emits it, re-measured here
   side by side. `auth_time` is the only claim the browser flow adds. Not a
   behaviour change - a wrong reading of a difference, and the reason it matters
   is that "plus `acr`" invites an implementation to add `acr` to a grant that
   has always had it.

5. **The plan's own first draft of §1.10.** A transcript read as "the SSO
   redirect's `session_state` is the new authentication session's root id"; it
   is the **original user session's** id, and `AUTH_SESSION_ID` is minted around
   that value, which makes the two indistinguishable in one sample. Corrected by
   a second measurement that printed both. Recorded here because it is the same
   failure mode this document keeps catching: one transcript where the variable
   was not isolated.

---

## 3. Follow-up dispositions

### Close

- **F76 - the `authorization_code` grant is not served at the token endpoint.**
  **Closed.** The grant is served, with twelve measured answers rather than the
  eight the entry pointed at, and PKCE is carried from `/auth` onto the code -
  the second half of the entry, which named it separately. The three cases it
  blocked are `Implemented` and a fourth was added.

### Still open, re-worded

- **F65 - the browser-session branch of the logout confirmation page is
  unmodelled.** **Untouched and unchanged.** It closes with F77 and F77 is not
  in this cut, exactly as F77 says. Nothing here made it larger or smaller: this
  cut reads no cookie the logout endpoint would need.

- **F75 - the authentication session and the authorization code are in memory.**
  **Still open and unchanged in shape, larger in consequence.** Until this cut a
  code nothing could redeem was a code nothing lost; now the whole browser flow
  is single-process, and a login that starts on one replica and redeems on
  another fails with `Code not valid` - which is indistinguishable, to the
  client, from a replay. The entry should say that the failure mode is now a
  *wrong answer* rather than an unimplemented one. The design in the P13
  handover is still the one to use; `internal/store` was again another agent's
  this session.

- **F77 - SSO is not recognised.** **Still open, and now measured.** §1.10 has
  the whole shape: five cookies, the original user session's id carried into a
  fresh `AUTH_SESSION_ID`, the original `auth_time`, the first session still
  refreshable, and `prompt=none` clearing `KC_RESTART` where the plain request
  sets one. The entry should carry those five facts so the next cut does not
  re-measure them.

  **Why it is not here.** It is a second authentication path with its own cookie
  arithmetic, its own relationship to the user session, and a dependency on
  reading and verifying the `KEYCLOAK_IDENTITY` JWT that nothing in
  `internal/oidc` does today. Redeeming a code and issuing one without a
  password are different problems that happen to meet at the same redirect. The
  code grant turned out to be twelve rejections, four PKCE answers and a claim
  the token package did not have; shipping SSO beside it would have meant one
  reviewer for two endpoints.

### File

- **F79 - a refresh of a browser-login session loses `auth_time`.** Measured:
  Keycloak's refresh of such a session carries the original value and its
  refresh of a password-grant session carries none, so `auth_time` is stored on
  the user session. Gloak has nowhere to put it - `model.UserSession` is
  `internal/model`'s and `internal/store` would need the column - so the code
  grant emits it and the refresh grant does not. The fix is one nullable column
  and one field, set by `startSessionWithID` and read by `writeTokens`.
  Unasserted today: every golden masks `access_token`.

- **F80 - the access token's `jti` has no grant prefix.** Keycloak's is
  `onrtac:`, `onrtro:`, `onrtrt:` or `onltac:` followed by a UUID, chosen by the
  grant and by whether the client is lightweight; the ID and refresh tokens'
  carry none. Gloak emits a bare UUID everywhere. Pre-existing across all four
  grants, not introduced here, and asserted by nothing - `access_token` is
  masked in every golden and the introspection golden masks `jti`. Worth doing
  as one change across the four rather than as a fifth special case.

- **F81 - a lightweight client's refresh token carries `sub` and `aud_x` where
  Keycloak's carries neither.** Measured on `security-admin-console`: ten claims
  against a normal client's twelve. `admin-cli` is lightweight too, so this is
  live on the grant P1 measured first. Also unasserted, for the same reason.

- **F82 - the introspection body has no `auth_time`.** Unmeasured rather than
  measured-and-diverging: the probe that would have answered it came back
  `{"active":false}`, because a client cannot introspect a token whose `aud`
  excludes it and no bootstrapped client is in a browser token's audience.
  Filed so that whoever adds `auth_time` to `Introspection` measures it first.

---

## 4. Parity before and after

`GLOAK_PARITY_REPORT`, on the merge base (`a308eb0`) and on
`feat/p3-code-grant`.

```
Parity: 205 -> 209 of 500 (+4)

chapter                         before  after  delta
oidc/token                          10     14     +4
```

| | served | recorded | documented |
|---|---|---|---|
| base | 10 | **3** | 18 |
| head | **14** | **0** | 19 |

The denominator moves 499 → 500 because this cut adds one case. The `recorded`
column going 3 → 0 is the part worth reading: `oidc/token` now has **no** case
waiting on an unimplemented endpoint, which is what `oidc/authorization`
achieved yesterday. Between the two chapters the browser flow has none left.

The four:

- `oidc/token/authorization-code-grant` - promoted
- `oidc/token/replayed-code` - promoted
- `oidc/token/pkce-verifier-mismatch` - promoted
- `oidc/token/duplicated-parameter` - **new**, and the first case in the
  catalogue to send a repeated key in a **form body**. `Request.Form` is a Go map
  and cannot express it; `RawQuery` is the query-side equivalent and this
  endpoint does not read the query. It uses `Request.Body` with the Content-Type
  set by hand, which is what `buildRequest` requires when `Form` is empty.

The five `Pending` cases left in the chapter are the four grants with no fixture
- device code, CIBA, token exchange, JWT bearer - and DPoP.

### What the goldens still cannot see

Three of the four new cases assert a body that is mostly `{{string}}`. The
claims inside the tokens - `auth_time`, `nonce`, the scope the code carried -
are `internal/oidc`'s own tests, in `codegrant_test.go`, for the same reason
`session_state` was P13's: every token in every golden is masked, so an endpoint
issuing empty strings would match byte for byte.

Seventeen mutations were run against those tests, one per claim, and every one
was killed by the test named for it. No survivors.
