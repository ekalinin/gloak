# P3: the browser code flow

Date: 2026-08-22
Status: **superseded 2026-08-29 by `2026-08-29-p3-browser-code-flow-design.md`**

> This document was written before anyone drove the endpoint, and it says so
> about itself. It is kept because its boundaries held and because the newer
> document is a scorecard against it: section 2 there checks it claim by claim
> and names the three it falsified - the code's third part is the client's own
> UUID and not a client session id, the login form carries five action
> parameters and not three, and logout without an `id_token_hint` serves a
> confirmation page rather than redirecting. Everything else in it, including
> the whole cookie table, was confirmed by measurement.
>
> Read the newer one. This one is the record of what was reasonable to believe
> beforehand.
Roadmap: `2026-08-21-gloak-parity-roadmap.md`
Depends on: P1, `2026-08-21-p1-token-foundation-design.md` (implemented)

## 1. What this is

The authorization endpoint, the login form, code issuance, the
`authorization_code` grant and the RP-initiated half of logout. It is what makes
Gloak usable by a browser rather than only by a script holding a password.

**It is specified now and built after P2.** The boundaries are worth fixing
while the P1 work is fresh, but the order in the roadmap is deliberate and this
document does not reopen it: P3's fixtures are the hardest machinery in the
harness, and building them before P2 has shaken out chaining on the simple case
is how they get built twice.

## 2. The login page is protocol, not layout

Byte-exact, because a client can observe them:

- the redirect to the login page and the redirect back
- every query and form parameter name, including the hidden ones the form
  carries
- the form's `action` URL
- cookies, their names, values' shape and every attribute
- the authorization code's shape
- every error response

Gloak's own minimal HTML for the form itself, carrying the field names
Keycloak's form carries.

Reproducing Keycloak's `keycloak.v2` Freemarker theme byte for byte is P13, not
P3. Pulling it forward would mean shipping a theme engine before shipping a
login, and it would drag in three goldens that already churn on every recording
because the theme embeds a cache-busting resource hash generated per container
start - `oidc/authorization/invalid-redirect-uri`,
`oidc/authorization/unknown-client-id` and
`oidc/logout/invalid-post-logout-redirect-uri`. Those three stay `Pending` until
P13.

**The consequence, stated rather than buried:** after P3, a browser can log in
to Gloak and the flow is correct, but the page does not look like Keycloak's. A
conformance case that compares login HTML will fail until P13, and no case
should be written to compare it before then.

## 3. What is already measured

The code is composite, three parts separated by dots:

```
8af8c832-0fcf-975e-a55a-38ea2755f967.p2oReT4cpfec5q5LnTYZhz2e.5d844f15-0f13-4b7d-aa51-4da71f020bc0
```

`code UUID`, `session_state`, `client session UUID`. Clients treat it as opaque;
goldens see the shape.

The redirect back carries `state`, `session_state`, `iss` and `code`. `iss` is
there because `authorization_response_iss_parameter_supported` is true in the
discovery document Gloak already serves.

Cookies on `GET /auth`:

| Cookie | Attributes |
|---|---|
| `AUTH_SESSION_ID` | `Path=/realms/{realm}/`, `Secure`, `HttpOnly`, `SameSite=None`, `Version=1` |
| `KC_AUTH_SESSION_HASH` | quoted value, `Max-Age=60`, `Secure`, `SameSite=None`, no `HttpOnly` |
| `KC_RESTART` | a JWE (`dir`, `A256GCM`), `Secure`, `HttpOnly`, `SameSite=None` |

After a successful login:

| Cookie | Attributes |
|---|---|
| `KEYCLOAK_IDENTITY` | a JWT, HS512, `typ` is `Serialized-ID`, `Secure`, `HttpOnly`, `SameSite=None` |
| `KEYCLOAK_SESSION` | `Max-Age=36000`, `Secure`, `SameSite=None`, no `HttpOnly` |
| `KC_RESTART` | cleared with `Max-Age=0` |

Every cookie carries `Version=1` and `Path=/realms/{realm}/`.

`KC_RESTART` being a JWE is the one entry with a cost attached: the realm's
RSA-OAEP encryption key, which P1 generates and publishes but does not use, is
what encrypts it. P3 is where that key stops being decoration.

What is **not** measured yet, and has to be before it is built: the hidden form
parameters (`session_code`, `execution`, `tab_id` and whatever else the form
carries), the form's exact `action` URL, and the error responses for a wrong
password and for a code replayed after use.

## 4. The recorder needs a small browser

This is the piece the roadmap ordered P2 first to avoid building twice.

Recording an authorization-code exchange means:

```
GET /auth?...            -> an HTML login page, plus cookies
parse the form           -> action URL and every hidden input
POST the credentials     -> a 302, plus more cookies
read Location            -> extract code, state, session_state, iss
POST /token              -> exchange the code
```

Four things follow.

**Cookies have to persist across fixture steps.** Today each step is an
independent request. A login is a session.

**The recorder has to parse HTML.** Not render it - find a form, read its action
and its inputs. `golang.org/x/net/html` is the smallest thing that does this
honestly; a regular expression over HTML is the classic mistake.

**Both halves of F12 are needed.** `Location` is volatile and carries the code;
`Set-Cookie` is multi-valued.

**The parsed values must be masked out of the recorded response,** the same rule
that already applies to captured tokens. A `session_code` left verbatim in a
golden makes the file churn on every recording.

## 5. Scope

In:

- `GET /auth`: request validation, redirect URI matching, PKCE challenge
  storage, the login page
- the login form POST: credential verification through `internal/auth`, session
  creation, code issuance
- the `authorization_code` grant on the token endpoint, including PKCE
  verification and single-use code enforcement
- `oidc/logout`, RP-initiated, with `id_token_hint` and
  `post_logout_redirect_uri`
- the cookies in section 3

Out:

- themes, i18n and the page's appearance - P13
- back-channel and front-channel logout, the session iframe, offline sessions -
  P6
- required actions, OTP, WebAuthn, brute-force detection, and the flow engine
  that sequences them - P8. P3 serves one hardcoded username-and-password step,
  and P8 replaces it with a model.
- consent screens
- the implicit and hybrid flows

## 6. Cases this closes

`oidc/authorization`: 8 of 11. `code-flow-redirect`, `pkce-s256`, `pkce-plain`,
`prompt-none-no-session`, `missing-response-type`, `unsupported-scope`,
`response-mode-fragment`, `response-mode-form-post`. Two of the remaining three
are the theme-HTML cases from section 2; `implicit-flow` is out of scope.

`oidc/token`: 3 more - `authorization-code-grant`, `replayed-code`,
`pkce-verifier-mismatch`.

`oidc/logout`: 2 of 5 - `rp-initiated-with-id-token-hint` and
`rp-initiated-without-id-token-hint`. `backchannel` and `frontchannel` are P6;
`invalid-post-logout-redirect-uri` is a theme-HTML case.

Thirteen cases, against a chapter denominator that is hand-kept rather than
taken from OpenAPI - the authorization endpoint is not in the Admin API
description, which is what `source: catalogue` in the coverage report means.

**Several of these were recorded once and produced the wrong page.** Four cases
carry comments saying so - `oidc/authorization/prompt-none-no-session`,
`missing-response-type` and `unsupported-scope`, plus
`oidc/logout/rp-initiated-without-id-token-hint`: no literal `redirect_uri`
matches the recorder's
container, because testcontainers assigns the port at run time and
`security-admin-console`'s redirect pattern validates against the exact
host and port. P3 has to fix the recording, not the expectation - most likely by
registering a client whose redirect pattern the recorder controls, which is a
P2 capability.

That dependency is worth stating plainly: **P3's recordings need P2's client
management**, on top of the ordering argument the roadmap already makes.

## 7. Debt this knowingly takes on

**One authentication step, hardcoded.** Keycloak sequences authenticators
through a configurable flow. P3 serves username and password directly, the same
way P1 hardcoded claim sets rather than deriving them from mappers. P8 replaces
it. Written down here so P8 does not discover mid-flight that "just add
authenticators" means rewriting the login.

**`KC_RESTART`'s JWE contents are opaque to us.** P3 reproduces the cookie's
shape, encryption algorithm and attributes. What Keycloak puts inside it is not
measurable from outside, so Gloak puts in what it needs to restart the flow.
The cookie is Gloak's own to read back, so this is a difference no client can
observe - but it is a difference, and it is here rather than left implicit.

## 8. What this document deliberately does not decide

The hidden form parameters and the two unmeasured error responses in section 3.
They are named as things to measure, not guessed at. Writing a plausible
`session_code` format into a spec is exactly what this project's one overriding
rule forbids, and a spec that guesses is worse than a spec with a gap in it,
because the gap gets measured and the guess gets copied.
