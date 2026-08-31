# P6, second cut: back-channel and front-channel logout

Branch `feat/p6-channel-logout`, off `main` at 78243db. Measured 2026-08-31
against a live Keycloak 26.7.1 - container `kc-logout` on 8132 - with a listener
in a second container at `172.17.0.4:9099`. Both containers removed afterwards;
`kc-authz` on 8131 was not touched.

The plan, including how an outbound call is measured at all, is
`docs/superpowers/plans/2026-08-31-p6-channel-logout.md`.

## 1. Measurements

### 1.1 How an outbound call is measured

This is the first thing this project has had to observe that Keycloak does
without being asked, and the answer is a **second container**, not a host
process. Colima runs the daemon inside a Lima VM, so `docker run -p` forwards
the guest's port outwards and gives the guest nothing pointing back; `172.17.0.1`
inside the container is the VM's bridge gateway and not macOS. Two containers on
the default bridge reach each other by IP. The mount holding the listener binary
lives under `$HOME` and not `/tmp`, because colima shares the home directory into
the VM and does not share `/tmp`.

The listener is a static Go binary that dumps method, path, every header and the
body to stdout and answers by path - `/status/500`, `/status/404`, `/slow`,
anything else 200 - so one process covers the success and every failure mode.
`docker logs` is the transcript.

### 1.2 Neither channel is a preview feature

`GET /admin/serverinfo` lists 73 features, 40 of them disabled. Neither
back-channel nor front-channel logout is among them. `LOGOUT_ALL_SESSIONS_V1` is
the only logout-shaped entry and it is a `DEPRECATED` flag about something else.
So CIBA's answer - "unmeasurable in this container regime" - is **not** the
answer here. Both are core, both are reachable, and both were measured end to
end.

### 1.3 Four triggers fire the back-channel call and two do not

| what | answer | outbound calls |
|---|---|---|
| `GET /logout` with a valid `id_token_hint` | 200/302 | 1 per client session |
| `POST /logout` with a `refresh_token` | 204 | 1 per client session |
| `POST /admin/realms/{r}/users/{id}/logout` | 204 | 1 per client session, per session |
| `DELETE /admin/realms/{r}/sessions/{sid}` | 204 | 1 per client session |
| `POST /admin/realms/{r}/logout-all` | 200 | **0**, and it ended two sessions |
| `POST /revoke` with a refresh token | 200 | **0**, and it ended the session |

A **rejected** logout fires nothing: a valid hint with an unregistered
`post_logout_redirect_uri` answers the 400 page and makes no call.

### 1.4 Who is called

One POST per client session inside the user session being ended, for each client
carrying a `backchannel.logout.url`. Measured on a three-client SSO session: two
with the attribute, one without, two calls. The client that **asked** for the
logout is called too. A second session belonging to the same user is untouched.
The `POST` family notifies the whole session and not the caller - two calls from
a two-client session logged out with one client's refresh token.

### 1.5 The request and the token

```
POST /bc HTTP/1.1
Accept-Encoding: gzip,deflate
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.12)

logout_token=<jwt>
```

```
header  {"alg":"RS256","typ" : "logout+jwt","kid" : "<the realm's RSA kid>"}
payload {"exp":…,"iat":…,"jti":"…","iss":"…","aud":"<clientId>","sub":"<user uuid>",
         "typ":"Logout",["sid":"…",]
         "events":{"http://schemas.openid.net/event/backchannel-logout":{}}}
```

`typ` is `logout+jwt` in the header and `Logout` in the payload. `exp - iat` is
120. `aud` is one client as a bare string. `kid` is the realm's active RSA key -
the same one the ID token carries. **`sid` appears only when
`backchannel.logout.session.required` is the string `"true"`; an absent
attribute behaves as `"false"`.**

### 1.6 A failing client changes nothing, and is not retried

| client answers | logout answers | session | POSTs | elapsed |
|---|---|---|---|---|
| 200 | 302 | ended | 1 | 0.009s |
| 500 | 302 | ended | 1 | 0.009s |
| 404 | 302 | ended | 1 | 0.007s |
| connection refused | 302 | ended | 0 | 0.008s |
| no route to the address | 302 | ended | 0 | 3.10s |
| accepts and never answers | 302/200 | ended | 1 | 5.03s, 4.97s |

The only observable is time. The 3.10s row is the bridge's ARP timeout rather
than anything Keycloak configures and is **not** claimed as a contract; the ~5s
is, twice measured. With the hanging client holding the socket the Admin API
still listed the session, so **the call goes out before the session is removed**.

### 1.7 Front-channel logout is a page, and it replaces the redirect

A session holding a client with `frontchannelLogout: true` **and** a
`frontchannel.logout.url` answers a 200 theme page where the same request on a
plain client answers a 302 - same valid hint, same registered target, same
state.

```
HTTP/1.1 200 OK
Set-Cookie: AUTH_SESSION_ID=…;Version=1;Path=/realms/master/;Secure;HttpOnly;SameSite=None
Set-Cookie: KEYCLOAK_IDENTITY=;Version=1;Path=/realms/master/;Max-Age=0
Set-Cookie: KEYCLOAK_SESSION=;Version=1;Path=/realms/master/;Max-Age=0
Cache-Control: no-cache
Content-Language: en
Content-Security-Policy: frame-src 'self' localhost:9998 localhost:9998 ; frame-ancestors 'self'; object-src 'none';
Content-Type: text/html;charset=utf-8
… the five security headers
```

`data-page-id="login-frontchannel-logout"`, `<h1 id="kc-page-title">Logging
out</h1>`. The body lists each client by `clientId` with a hidden `<iframe>`,
then a script doing `window.location.replace(<target>)` on `readystatechange`
and a `Continue` link to the same place; the target follows the 302's rule,
`state` and nothing else, and an empty `state=` is dropped.

- The **policy is computed**: one `host:port` per client, scheme and path
  stripped, **not de-duplicated**, and a **space before the semicolon**. Read
  with `od -c`.
- `frontchannel.logout.session.required` **defaults to true when absent**, the
  opposite of its back-channel namesake. With it the iframe `src` gains
  `?sid=…&iss=<percent-encoded issuer>`; with `"false"` the URL is bare.
- Either half of the registration alone produces no iframe.
- With no target the page is still served, without the script or the link.
- With no `id_token_hint` the **confirmation page still wins**: this page is
  only reached once the logout is authorised.
- The `POST` family's 204 is unaffected.
- Front-channel and back-channel **coexist**: one session with one of each got
  the page and the outbound call.

### 1.8 Everything in this section is guarded

`internal/oidc/channellogout_test.go` stands up an `httptest.NewServer` on
`127.0.0.1` and asserts the outbound POST byte for byte - method, path,
`Content-Type`, the single form key, the JOSE header and the payload's key order
- so `CGO_ENABLED=0 go test ./...` needs no Docker and no network.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **A logout that ends a session and a session that ends are two different
  things.** Four paths fire the back-channel notification - `GET /logout` with a
  hint, `POST /logout` with a refresh token, `POST /users/{id}/logout` and
  `DELETE /sessions/{sid}` - and two paths end sessions and notify **nobody**:
  `POST /admin/realms/{r}/logout-all`, which ended two sessions and made zero
  calls, and `POST /revoke` with a refresh token, which ended one and made zero.
  Hanging the notification off session removal is the obvious implementation and
  it fires on two paths Keycloak does not. Gloak serves the two protocol paths;
  the two admin ones are `internal/admin`'s and are not built yet.
- **The two `session.required` attributes have opposite defaults.**
  `backchannel.logout.session.required` absent behaves as `"false"` - the logout
  token carries no `sid` - and `frontchannel.logout.session.required` absent
  behaves as `"true"` - the iframe's `src` does gain `?sid=&iss=`. Measured on
  clients differing only in that value, on both sides. One helper reading both
  names is the tidy-up that gets one of them wrong, and the admin console's
  default for the back-channel one is on, so a client created *there* looks like
  the opposite measurement.
- **One token says its own kind twice, in two spellings.** The back-channel
  logout token's JOSE header is `typ: "logout+jwt"` and its payload is
  `typ: "Logout"`. Deriving either from the other is wrong in both directions.
  It is also the only RS256 token Keycloak signs whose header is not `"JWT"`.
- **A client that fails a back-channel logout changes nothing a caller can
  see, and is not retried.** 500, 404, connection refused and an unroutable
  address all left the logout's status, `Location` and ended session identical
  to a healthy client's, and the 500 and the 404 each drew exactly one POST. The
  only observable is **time**: a client that accepts the socket and never
  answers blocks the logout for about five seconds, twice measured. So a
  back-channel URL is a way for a client to make every logout at that realm
  slow, and reporting the failure to the browser is the fix that would diverge.
- **The notification goes out while the session is still alive.** With a hanging
  client holding the socket, the Admin API still listed the session. Deleting
  first and announcing afterwards is the obvious order and it is the wrong one.
- **The logout endpoint has seven response shapes, not six.** The seventh is the
  front-channel page, and it is not a variant of one of the six: it takes the
  302's inputs - a valid `id_token_hint`, a registered `post_logout_redirect_uri`
  and a `state` - and answers 200. It replaces the "You are logged out" page
  too. Its title is **the confirmation page's**, "Logging out", so the title
  cannot tell the two apart; `data-page-id` and the `Content-Security-Policy`
  can.
- **The front-channel logout page is the one theme page whose
  `Content-Security-Policy` is computed**, and both of its oddities are
  measured: the `host:port` is repeated **once per client** rather than
  de-duplicated - two clients on one host put the host in twice - and there is a
  **space before the semicolon** that follows the last host. De-duplicating or
  trimming changes a measured byte. The rule "every page the login theme renders
  sends the same policy" held on eight responses and is false on the ninth.
- **Front-channel logout needs a column and an attribute, and either alone is
  nothing.** `frontchannelLogout: true` with no `frontchannel.logout.url`
  produces no iframe, and the URL on a client whose flag is false produces none
  either - both still answer the 302. So the flag is not a display preference
  and the attribute is not a registration on its own.
- **Front-channel and back-channel are not alternatives.** A session holding one
  client of each kind got the page **and** the outbound call. Treating the two as
  a choice of mechanism is the reading that loses one of them.

## 3. Follow-up dispositions

**F108 - `POST /logout/logout-confirm` and `/login-actions/restart` are measured
and unbuilt.** Still open and untouched. This cut met its neighbour rather than
it: the confirmation page is the branch `logout-confirm` submits, and this cut
measured that a **front-channel client does not change it** - with no
`id_token_hint` the answer is still `data-page-id="login-logout-confirm"` with
the plain policy and no cookie clears. So F108's page is confirmed to be one
page and not two, which is one fewer thing for whoever builds it to establish.
Nothing in this cut moves it.

**F110 - consent grants are in memory, and that one is a real divergence.**
Still open and untouched, and this cut is a second instance of its shape rather
than a fix for it. `channelLogoutTargets` answers "which clients are in this
session" by listing the realm's clients and asking `ClientSession` for each
candidate, because `store.SessionRepo` has no method that lists a user session's
client sessions and `internal/store` is not this cut's to change. That is not a
divergence - the answer is right - but it is the same missing-persistence shape,
and it is the one thing a future cut should tidy: one `ClientSessionsByUserSession`
would replace the loop.

**New, and named here because the follow-ups list is not this cut's to edit:**

- **The two admin triggers are unbuilt.** `POST /users/{id}/logout` and
  `DELETE /sessions/{sid}` were both measured firing the notification, once per
  client session, and both live in `internal/admin`. The machinery they need is
  `handler.channelLogoutTargets` and `handler.notifyBackchannel`, which are
  unexported in `internal/oidc` today.
- **Every Keycloak JOSE header carries Jackson's ` : ` spacing and Gloak's does
  not.** Measured on the logout token, the ID token and the refresh token from
  one container: `{"alg":"RS256","typ" : "JWT","kid" : "…"}` - space around the
  colon on the second and third keys and not the first. Gloak signs through
  go-jose, whose header bytes are its own. This is observable to any client that
  compares bytes, it affects **every token Gloak issues** rather than this cut's
  one, and it was found here rather than caused here. Not fixed: hand-rolling
  the compact serialisation is a change to every token in the project.
- **The logout responses clear two cookies and Gloak sends none.** Measured on a
  browser session: the 302, the "You are logged out" page and the front-channel
  page all carry `KEYCLOAK_IDENTITY=;Version=1;Path=/realms/master/;Max-Age=0`
  and the same for `KEYCLOAK_SESSION`. Three conformance goldens mask
  `Set-Cookie` as volatile, so **no case can see this**, and
  `oidc/logout/rp-initiated-with-id-token-hint`'s own comment already names the
  two clears as the difference it is masking. Not fixed: it is the SSO cookie
  machinery rather than this endpoint's.
- **`frontchannel.logout.session.required` is measured and unread.** What it
  decides - whether the iframe's `src` gains `?sid=&iss=` - is in the page body,
  which is P13's. The measurement is in section 1.7 so P13 does not have to take
  it again.

## 4. Lines this cut contradicts

- **`docs/.../2026-08-18-keycloak-26.7.1-observed.md`, "The logout endpoint":
  "**Six response shapes**"** is now **seven**. Counted from the list, not
  incremented: the 302, the 400 error page, the "Logging out" confirmation page,
  the "You are logged out" page, the front-channel page, the 204 and the POST
  family's JSON rejections. The same list appears at the top of
  `internal/oidc/logout.go` and **is fixed on this branch**; the observed
  document is not this cut's to edit.
- **AGENTS.md, "Whether a hintless logout redirects is decided by the browser
  session, not by the hint" - "There are four outcomes, not two".** Five now,
  and the new one is not hintless: it is what a *hinted* logout answers when the
  session holds a front-channel client. The bullet's own grid is right about the
  variable it names and silent about a second one.
- **`internal/oidc/logout.go`'s `confirmBeforeRedirect` seven-row grid.** Its
  rows "live/yes/yes -> 302" and "none/yes/no -> 200 You are logged out" hold
  only while no client in the session is a front-channel client. **Fixed on this
  branch**, in place, with the qualifier written next to the grid rather than
  the grid rewritten - the function's own row is not one of the changed ones.
- **`internal/httpx.SetContentSecurityPolicy`'s doc comment**: "the header
  measured on exactly one response so far: the token revocation success. No
  other recorded response carries it." AGENTS.md recorded that as false on
  2026-08-29 - six of the seven responses in the browser flow carry it - and the
  function was already being called from `writeThemeHTML` and
  `WriteLoginActionRedirect` while the sentence stood. This is F111's family and
  a *different* comment from the one F111 names. **Fixed on this branch.**
- **`internal/httpx.WriteThemePage`'s doc comment**: "The envelope is measured on
  eight responses ... All of them carry Content-Language: en,
  Content-Security-Policy, ... Only the status, the Cache-Control and the body
  differ." A ninth page carries a **different** `Content-Security-Policy`, so
  the policy is a fourth thing that differs. **Fixed on this branch**, and the
  writer split so the one page with its own policy cannot also acquire its own
  header set.
- **`internal/conformance`, `oidc/logout/frontchannel`'s `Reason`**: "the
  response is a theme page carrying per-client iframes, **and the calls it makes
  are unobservable**". The second half is wrong and it is the interesting half:
  front-channel logout makes no outbound call at all - the browser fetches the
  iframes - so this response is exactly the shape the harness records, and only
  its body keeps it Pending. **Fixed on this branch.**
- **`oidc/logout/backchannel`'s `Reason`**: "the harness cannot observe Keycloak
  calling out to a client" was true and unspecific. **Rewritten on this branch**
  to say what the harness would need - a substituted address both the recorder's
  container and the verifier's in-process handler can reach, a golden shape that
  can hold an outbound *request*, and something that says the call is
  synchronous - and to record the measurement itself, which is now implemented
  and guarded elsewhere.

## 5. Parity before and after

**294 of 526 before, 294 of 526 after - no change, and the meter is right.**

Both cases stay `Pending`, so nothing in the tally moved, and neither should
have. The meter counts catalogue cases that Gloak serves and compares against a
golden, and this cut produced no new golden: the back-channel notification is a
request Keycloak makes, which no `Case` can hold, and the front-channel response
is a theme page whose body is P13's.

That is not "no behaviour landed". What landed is a feature under **thirteen**
tests in `internal/oidc` and **two** in `internal/httpx` - counted from the
`func Test` lines, not incremented - with nineteen mutations killed. What did
not land is a number. The two are separable here, which is worth saying plainly
because a reader looking only at the parity comment would conclude nothing
happened.

The honest way to move the number later is P13: once the login theme renders,
`oidc/logout/frontchannel` is promotable and worth one, and its envelope is
already served.

## 6. Mutation testing

**Nineteen** distinct mutations, one per claim, each run against the *named*
test and reverted; twenty runs, because one of them was run against two
different test selectors to check whether anything else in the package caught
it. Counted from the list at the end of this section. All nineteen are killed -
but **three survived the first attempt**, and they are the finding of this
section:

| survivor | why it survived |
|---|---|
| every logout token carries the **first** client's `aud` | every multi-client test compared only the outbound *paths* |
| `sid` is a constant rather than the session | the table test asserted presence and never the value |
| `sub` carries the session id rather than the user | the helper checked `sub != ""` and then masked it |

Three survivors, and the first was re-run against every test in the package in
case something else caught it. Nothing did - so a server telling every client
that somebody else was being logged out would have shipped green. All three
passed a suite in which every case broke one value at a time, which is the
failure AGENTS.md records four times this week. They are killed now: `aud`,
`sub` and `sid` are each compared against the session they name, and the helper
that does the masking no longer decides whether a value is right.

The nineteen, in full: `sid` unconditional; `events` moved before `typ`; the
payload `typ` set to the header's; the header `typ` set to `JWT`; the lifetime
set to 60s; the client-session check removed; the redirect-URI check disabled;
the call made twice; the front-channel branch removed; the front-channel branch
narrowed to the redirect only; the `frontchannelLogout` flag ignored; the hosts
de-duplicated; the space before the semicolon dropped; the notification moved
after the delete; the POST family's notification removed; the
`session.required` default flipped to yes; and the three survivors above.
