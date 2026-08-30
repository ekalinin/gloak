# P3: the `authorization_code` grant at the token endpoint

Branch `feat/p3-code-grant`, off `a308eb0`.

Everything below was measured against a live `quay.io/keycloak/keycloak:26.7.1`
started for this cut on port 8097 (`kc-code`), on 2026-08-30. The scripts are in
`/tmp/p3code/` and are transient; the numbers are here.

---

## 0. What was re-verified, and what was wrong in it

This cut is the unusual one: the contract for the endpoint it builds already
existed, written by a cut that could not serve it. The section
**"The token endpoint's answers to an authorization code"** of
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` was therefore
re-measured line by line rather than trusted.

**Every one of its eight rejection rows reproduced exactly**, byte for byte,
including the two that were corrected once already (the confidential client's
401 and the different-client 400). The success body reproduced too: nine keys in
the recorded order, `expires_in` 60, `refresh_expires_in` 1800,
`scope: "openid profile email"`, `Cache-Control: no-store`, `Pragma: no-cache`,
`application/json`, the five security headers and no `Content-Security-Policy`.
The three committed goldens are right.

What the section is **wrong about is its own completeness**. It says "every
rejection", and the table is eight rows. Measured, this grant has **twelve**,
and the four it does not name are not exotic:

| Request | Status | Body |
|---|---|---|
| any form key sent twice | 400 | `{"error":"invalid_request","error_description":"duplicated parameter"}` |
| a `code_challenge` was sent to `/auth` and no `code_verifier` here | 400 | `{"error":"invalid_grant","error_description":"PKCE code verifier not specified"}` |
| no `code_challenge` was sent and a `code_verifier` is | 400 | `{"error":"invalid_grant","error_description":"PKCE code verifier specified but challenge not present in authorization"}` |
| a `code_verifier` outside RFC 7636's production | 400 | `{"error":"invalid_grant","error_description":"PKCE verification failed: Invalid code verifier"}` |

Three further sentences in the tree are contradicted or too broad. They are in
section 4 below, with the branch's disposition of each.

The count matters for the reason the brief gives: an estimate made from the
three waiting cases would have been an estimate of a third of the endpoint. The
PKCE branch alone is four answers where the catalogue names one.

---

## 1. The measured contract

### 1.1 The order, ten adjacencies deep

Each step was measured by driving two faults at once and reading which one the
answer is about.

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
10. success                    200
```

The pairs that pin it:

- `zz` twice with no `grant_type` answers about `grant_type`; `zz` twice with an
  unknown `grant_type` answers about the grant type; `zz` twice with an unknown
  `client_id` answers **401**; `zz` twice with a valid client and a wrong
  password answers `duplicated parameter`. So step 4 is fourth, not first.
- `zz` twice with no `code` answers `duplicated parameter`, so 4 precedes 5.
- A bogus code with a wrong `redirect_uri` answers `Code not valid`, so 6
  precedes 7.
- **Another client redeeming a code with a wrong `redirect_uri` answers
  `Incorrect redirect_uri`**, so 7 precedes 8 - the redirect URI is compared
  against the code's stored value before the caller is compared with the code's
  client.
- Another client redeeming a PKCE-bound code with no verifier answers about the
  client, so 8 precedes 9.
- A real code with a wrong `redirect_uri` **and** a wrong `code_verifier`
  answers `Incorrect redirect_uri`, so 7 precedes 9 directly as well.

### 1.2 `duplicated parameter` is the token endpoint's too, and it reads the body

The authorization endpoint's `duplicated parameter` has a sibling here, with the
same lower-case spelling and the same "any key, including one the endpoint never
reads" rule - `zz` twice is enough, and `grant_type` twice is the same answer.

**It reads the form body and not the query string.** `zz=1&zz=2` in the query of
an otherwise valid password grant is a 200; one `zz` in the query and one in the
body is a 200; both in the body is the 400. And the whole grant in the query
with an empty body answers `Missing form parameter: grant_type`, which is the
same "the body is the only source" rule `internal/oidc/token.go` already
follows.

It applies to **every grant**, not to this one. It is implemented at the
endpoint, after client authentication, where it was measured.

### 1.3 PKCE, carried from `/auth` and checked here

The challenge and its method are attached to the code at the authorization
request and looked up at redemption. Four answers, all `400 invalid_grant`:

| stored challenge | `code_verifier` | answer |
|---|---|---|
| none | absent | success |
| none | present | `PKCE code verifier specified but challenge not present in authorization` |
| present | absent | `PKCE code verifier not specified` |
| present | present, outside 43..128 unreserved | `PKCE verification failed: Invalid code verifier` |
| present | well formed, does not match | `PKCE verification failed: Code mismatch` |
| present | matches | success |

The production is RFC 7636's, measured at both bounds and on the alphabet: 42
`a` is `Invalid code verifier`, 128 `a` is `Code mismatch` (so its shape passed),
129 `a` is `Invalid`, and 43 `!` is `Invalid`. **An empty `code_verifier=` is
`Invalid code verifier`, not `not specified`** - so "not specified" is about an
absent parameter and an empty one has already reached the shape check.

`S256` and `plain` both verify. A `code_challenge` sent with **no**
`code_challenge_method` defaults to `plain` and verifies against the challenge
literally, which is the same default `checkPKCE` already documents at `/auth`.

### 1.4 The code carries more than the redirect URI

Four values are decided at `GET /auth` and consumed at the token endpoint. Three
of them are not on the code today.

| value | where it shows | today |
|---|---|---|
| `redirect_uri` | step 7 | stored |
| `scope` | the response's `scope`, and whether an `id_token` exists at all | **not stored** - `completeLogin` calls `grantedScope("")` |
| `nonce` | the ID token's `nonce` claim | **not stored** |
| `code_challenge`, `code_challenge_method` | step 9 | **not stored** |

The success golden's `scope` is `email openid profile` and its body has an
`id_token`, so the scope carry-through is not optional decoration: without it
this cut cannot match its own recorded golden.

### 1.5 `auth_time`, and it is the login's time

The browser flow's access token and ID token carry `auth_time` immediately after
`iat`; the password grant's carry none. Measured on one container minutes apart,
on a client with no lightweight attribute, so the variable is the grant and not
the client.

It is the **authentication** time and not the issuance time: a login followed by
a six-second pause before the exchange produced `iat - auth_time == 6`.

It survives a refresh: refreshing a browser-login session produces an access
token that still carries the original `auth_time`, and refreshing a
password-grant session produces one with none. So it is a property of the user
session rather than of the grant. Gloak cannot store it - `model.UserSession` is
`internal/model`'s and this cut may not touch it - so the code grant emits it
from the session's start time and the refresh grant does not emit it at all.
Filed, with the exact shape, rather than half-done.

The **lightweight** access token has no `auth_time`, confirming the observed
document's `security-admin-console` exception: measured through a real browser
login at that client, its access token is the eight claims
`exp iat jti iss typ azp sid scope` while its **ID** token does carry
`auth_time`.

### 1.6 The ID token's `nonce`

`nonce` sits between `azp` and `sid`, and only in the ID token - the access and
refresh tokens do not carry it whatever the authorization request said.

### 1.7 Which failures spend the code

`AGENTS.md` says "a failed code exchange spends the code". Measured over five
distinct failures, that is true of four and **false of the fifth**:

| failure | code afterwards |
|---|---|
| a wrong `redirect_uri` | spent - the retry answers `Code not valid` |
| another client's `client_id` | spent |
| `PKCE code verifier not specified` | spent |
| `PKCE verification failed: Code mismatch` | spent (already recorded) |
| **a failed client authentication (the 401)** | **not spent** - the retry with the secret succeeds |

Which follows from the order: the 401 is step 3 and the code is not looked at
until step 6. `spendCode` removing the code on lookup is therefore right, and
so is doing client authentication before calling it.

### 1.8 Two further things that answer `Code not valid`

- **An expired code.** The realm's `accessCodeLifespan` is 60 seconds; a code
  redeemed at 65 seconds answers `Code not valid`, the same as a replay. Gloak's
  `authCodeLifespan` is already 60 seconds and `spendCode` already folds expiry
  into "not there".
- **A code whose user session has been deleted.** `DELETE
  /admin/realms/master/sessions/{id}` between the login and the exchange makes
  the code answer `Code not valid`, not a session error.
- **An empty `code=`** answers `Code not valid` and not `Missing parameter:
  code`, so the presence check is on the parameter and not on its value - the
  same `params["x"]` shape `authorize.go` uses.

### 1.9 What does *not* stop the exchange

Measured because each looked likely and none of them is a check:

- The client being **disabled** between the login and the exchange: 200.
- The client's **standard flow** being turned off between them: 200.
- A `redirect_uri` that is registered on the client but is not the one the code
  was minted for: `Incorrect redirect_uri`. So the comparison is against the
  code's stored value, never against the client's pattern list.

---

## 2. What this cut builds

### Task 1 - carry the authorization request onto the code

`internal/oidc/authsession.go`, `authorize.go`, `loginactions.go`.

- `authTab` gains `Scope`, `Nonce`, `CodeChallenge`, `CodeChallengeMethod`.
- `restartRecord` gains the same four, so a login that restarts through
  `KC_RESTART` keeps its PKCE binding. Dropping them there would let a client
  downgrade its own PKCE by discarding a cookie.
- `beginLogin` fills them from the request; `writeRestartRedirect` fills them
  from the record.
- `completeLogin` calls `grantedScope(tab.Scope)` and populates the code's
  `Nonce`, `CodeChallenge` and `CodeChallengeMethod`.

`authCode` already declares the fields. Nothing new in the struct.

### Task 2 - `auth_time` and `nonce` in `internal/token`

- `Request` gains `AuthTime time.Time` and `Nonce string`.
- `accessClaims` and `idClaims` gain `AuthTime *int64 \`json:"auth_time,omitempty"\``
  in the measured position, immediately after `Iat`. A pointer rather than
  `omitempty` on an `int64`, because the key is absent rather than zero and a
  zero epoch is a value Keycloak could in principle emit.
- `idClaims` gains `Nonce string \`json:"nonce,omitempty"\`` between `Azp` and
  `Sid`.
- `lightweightClaims` gains nothing: measured, it has no `auth_time`.

### Task 3 - the endpoint

`internal/oidc/token.go`.

- `grantAuthorizationCode = "authorization_code"`, added to the dispatch.
- `hasDuplicateForm(r.PostForm)` after `authenticateClient` and before the
  grant switch, answering `invalid_request` / `duplicated parameter`.
- `authorizationCodeGrant`, the six checks of §1.1 in order, then the session
  lookup and `writeTokens`.
- `writeTokens` gains the auth time and the nonce. The two existing callers pass
  the zero value, which is what the password and client-credentials grants
  measure.

### Task 4 - the catalogue

- Promote the three `Recorded` cases to `Implemented` and drop their `Reason`.
- Add `oidc/token/duplicated-parameter`, a **new** case for §1.2, expressed with
  `Request.Body` because `Request.Form` is a Go map and cannot say a key twice.
  It is recorded against the live container, not written by hand.

### Task 5 - tests

`internal/oidc/token_test.go` and `internal/token/token_test.go`. Every branch
of §1.1 and §1.3, the spend-vs-401 boundary of §1.7, the scope and PKCE
carry-through of §1.4, and `auth_time`'s presence and value.

---

## 3. F77 (SSO) is **not** in this cut

It was measured, so that the decision is made on evidence and the next cut does
not have to re-measure.

A second `GET /auth` on a jar that has already logged in is a **302 carrying a
real code**, with no login page, and it:

- sets **five** cookies - a *fresh* `AUTH_SESSION_ID` and `KC_AUTH_SESSION_HASH`,
  a `KC_RESTART`, and a re-issued `KEYCLOAK_IDENTITY` and `KEYCLOAK_SESSION`;
- answers `session_state` = the **original** login's user session id, not the
  new authentication session's root id, and mints `AUTH_SESSION_ID` around that
  same value, which is why the two look equal in a transcript and are not the
  same fact;
- carries the original `auth_time` into the exchanged token;
- leaves the first session refreshable - one user session, two codes;
- omits `X-Frame-Options` and `Content-Security-Policy`, like every other
  `/auth` redirect.

`prompt=none` on that jar answers the same 302 with a code, and its `KC_RESTART`
is **cleared** where the plain second request sets one.

That is a second authentication path with its own cookie arithmetic, its own
relationship to the user session, and a dependency on reading and verifying the
`KEYCLOAK_IDENTITY` JWT that nothing in `internal/oidc` does today. It is
neighbouring work, not part of redeeming a code, and putting it here would mean
shipping the two together with the code grant's twelve rejections untested
against a real reviewer's attention. **Next cut**, with F65 - which it does
unblock, exactly as F77 says.

---

## 4. Lines in the tree these measurements contradict

Carried into the handover in full. Listed here because the plan is meant to open
with them.

1. **The observed document, "The token endpoint's answers to an authorization
   code": "Every rejection, each with ..." followed by eight rows.** There are
   twelve. Four are missing, listed in §0. **Fixed on the branch** - served,
   tested, and written up for the fold.

2. **`AGENTS.md`: "A failed code exchange spends the code."** True of every
   failure from step 6 onwards and **false of the 401**, which is measured not
   to spend it. §1.7. **Fixed on the branch**: the 401 cannot reach `spendCode`,
   and a test pins the retry succeeding.

3. **`AGENTS.md`: "A repeated parameter is an error at `/auth` and at neither of
   its neighbours ... `/auth` is the odd one of the three, not the rule."** The
   token endpoint is a fourth endpoint in the same flow and it **is** an error
   there, so "`/auth` is the odd one" is now two against two. The qualifier that
   survives is per endpoint, and the token endpoint's own rule is narrower than
   `/auth`'s: **body only, and after client authentication**, where `/auth`
   reads the query and answers seventh. **Fixed on the branch** for the token
   endpoint.

4. **The observed document's claim-set block for this grant: "plus `auth_time`
   and `acr`".** `acr` is not new - the password grant already carries it, on
   both the access and the ID token, and Gloak already emits it. `auth_time` is
   the only new claim. **Not a behaviour change**, a wrong reading of a
   difference; corrected in the handover.

---

## 5. Unfixed findings this cut will report rather than patch

- **The access token's `jti` carries a per-grant prefix.** `onrtac:` for the
  authorization code, `onrtro:` for the password grant, `onrtrt:` for a refresh,
  and `onltac:` on a **lightweight** client's code grant - so the prefix encodes
  the token's storage kind and the grant that made it. The ID and refresh
  tokens' `jti` carry none. Gloak emits a bare UUID on all four. Not asserted
  anywhere: `access_token` is masked in every golden and the introspection
  golden masks `jti`.

- **A lightweight client's refresh token omits `sub` and `aud_x`.** Measured on
  `security-admin-console`: `exp iat jti iss aud typ azp sid scope prov`, ten
  claims, against the twelve a normal client's carries. Gloak emits both on
  every client, including `admin-cli`, which is lightweight. Pre-existing and
  unasserted.

Both are `internal/token`'s, which this cut owns, and both are outside what it
was scoped to build. Patching either would be an unmeasured change to four
grants at once to fix a value no case compares.
