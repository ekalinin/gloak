# Plan: F146's nine pages, and F109's twelve

Branch `feat/theme-remaining-pages`, off `6e5a096`. Everything in section 1 was
measured on 2026-09-02 against a live Keycloak 26.7.1 - container `kc-pages`,
port 8159, `start-dev`, bootstrap admin `admin/admin`.

The charter is F146 (nine theme pages still serving the placeholder body) and as
much of F109 (twelve `writeLoginActionErrorPage` call sites) as the measurements
support.

## 1. One row per page

The nine F146 pages, measured before any of them was scoped. "Carries per
request" is what a second identical request against one container moves, plus
what the harness would have to reproduce on the serving side.

| # | page (`data-page-id`) | how the request is built | carries per request | golden? | this cut |
|---|---|---|---|---|---|
| 1 | logout confirmation (`login-logout-confirm`) | full browser login, then `GET /realms/{r}/protocol/openid-connect/logout` with no `id_token_hint` | `tab_id` (11 chars) in the restart URL **and** in the confirm form's action; `session_code` (43 chars) in a hidden input | **no** | no |
| 2 | "You are logged out" (`login-info`) | login, exchange the code, `GET .../logout?id_token_hint=<jwt>` with no target | `tab_id` in the restart URL | **no** | no |
| 3 | "Page has expired" (`login-login-page-expired`) | `GET /auth`, then `GET /login-actions/authenticate` with a wrong `execution` | `tab_id` in the restart URL and in **both** body links; the `KC_AUTH_SESSION_HASH` inside `checkAuthSession(...)`; a `<SCRIPT> history.replaceState` block that is present on one request and absent on the next | **no** | no |
| 4 | consent (`login-login-oauth-grant`) | login at a `consentRequired` client | `tab_id`; the hidden `code` (the session code); the `checkAuthSession` hash | **no** | no |
| 5 | UPDATE_PASSWORD (`login-login-update-password`) | put the alias on the user, log in, follow the 302 | `tab_id`; `session_code`; the `checkAuthSession` hash | **no** | no |
| 6 | UPDATE_PROFILE (`login-login-update-profile`) | as above | the same three | **no** | no |
| 7 | CONFIGURE_TOTP (`login-login-config-totp`) | as above | the same three, **plus a freshly minted TOTP secret** | **no** | no |
| 8 | Passkey (`login-webauthn-register`) | as above, alias `webauthn-register` or `webauthn-register-passwordless` | `tab_id`, `session_code`, **plus a WebAuthn challenge** | **no** | no |
| 9 | recovery codes (`login-login-recovery-authn-code-config`) | as above | the same three, **plus twelve generated codes** | **no** | no |

**Every one of the nine carries a `tab_id`, and nothing in this harness can mask
a value inside an HTML body.** `ReplaceCaptured` reaches a value a *fixture step*
captured; every `tab_id` above is minted by the **case's own request**, which no
fixture can capture. So the answer to "whether a golden can hold it" is **no,
nine times**, and it is the same answer for the same reason each time.

That is F38's mechanism - "mask the value of this attribute at this place in the
HTML" - wanted by nine more cases than the one it was closed on. §3 has the
disposition.

**This cut therefore takes none of the nine.** It takes F109 instead, and one
page outside the nine that the same measurement round reached.

### 1.1 The page this cut does take

| page | how the request is built | carries per request | golden? |
|---|---|---|---|
| the `/login-actions` error page (`login-error`) | any of the twelve F109 branches; **no cookies at all** reaches three of them | **nothing** - no `tab_id`, no `session_code`, no `checkAuthSession` | **yes** |
| VERIFY_EMAIL's 500 (`login-error`) | `emailVerified:false` plus the alias, then log in | `tab_id` and `client_data` in the restart URL | no - served, pinned by a package test |

The `/login-actions` error page is byte-identical to `/auth`'s error page apart
from the instruction - measured by `diff`, one line - so `themeErrorPageBody`
already produces it and F109 is a change of call site rather than new markup.

## 2. F109's twelve, measured

| # | site | branch | measured answer |
|---|---|---|---|
| 1 | `loginactions.go:76` | unparseable `client_data` | 400 page, `Invalid Request` |
| 2 | `loginactions.go:93` | the client does not resolve, or is not the tab's | 400 page, `An error occurred, please login again through your application.` |
| 3 | `loginactions.go:174` | nothing to restart from | 400 page, `Restart login cookie not found. …` |
| 4 | `loginactions.go:201` | the restart's client does not resolve | 400 page, `An error occurred, …` |
| 5 | `loginactions.go:294` | the body will not form-decode | **500 `application/json`**, not a page |
| 6 | `consent.go:62` | unparseable `client_data` at `/required-action` | 400 page, `Invalid Request` |
| 7 | `consent.go:76` | the client at `/required-action` | 400 page, `An error occurred, …` |
| 8 | `consent.go:225` | unparseable `client_data` at `/consent` | 400 page, `Invalid Request` |
| 9 | `consent.go:239` | the client at `/consent` | 400 page, `An error occurred, …` |
| 10 | `consent.go:243` | the body at `/consent` | **500 `application/json`** |
| 11 | `requiredactions.go:327` | the body in `runUpdatePassword` | **500 `application/json`** |
| 12 | `requiredactions.go:364` | the body in `runUpdateProfile` | **500 `application/json`** |

Three sentences and one non-page, and the chrome is measured too: **the restart
URL names the `client_id` the request sent, whenever that client resolves** -
including when it is a real client that is not the tab's, which is the cell that
says the chrome is not the tab's client.

## 3. The work

1. Commit this plan.
2. `internal/oidc/themepage.go`: two instruction constants and a
   `loginActionChrome` helper.
3. `internal/oidc/loginactions.go`, `consent.go`, `requiredactions.go`: the
   twelve sites, eight to `WriteThemeErrorPage` with the measured instruction and
   chrome, four to `writeUnparseableBody`.
4. `internal/oidc/requiredactions.go`: VERIFY_EMAIL's 500 gains its measured
   instruction and the `prompt=create` chrome shape.
5. Package tests in `internal/oidc`: the three sentences, the chrome grid, and
   the four 500s.
6. Five conformance cases in `catalog_oidc_pending.go` under `oidc/authorization`,
   all on the cookie-free `browser-client` fixture, all `Implemented`.
7. `normalize_test.go`: the five new goldens join
   `TestThemeResourceAppearsOnlyInTheThemePages`.
8. `make record`, `make lint`, `CGO_ENABLED=0 go test ./...`.
9. Mutation-test every claim, one mutation per claim.
10. The handover at `docs/superpowers/handover/theme-remaining-pages.md`.

## 4. What is deliberately not done

- The nine pages of §1. Each is measured and none can carry a golden; serving
  one means minting a `tab_id` on a path that has none today (pages 1 and 2) or
  reproducing a generated secret (pages 7, 8, 9). Both are separate cuts and
  both are named in the handover.
- The "Page has expired" branch grid. Keycloak serves that page for a *wrong*
  session code where Gloak takes the restart branch; that is a change to
  `loginActions`' step order and it is not F109's.
- The restart 302's `execution` parameter. Measured present on Keycloak and
  absent from Gloak's; filed rather than changed, because no golden covers it
  and it is the same branch as the previous item.
