# P6, second cut: back-channel and front-channel logout

Branch `feat/p6-channel-logout`. Measured 2026-08-31 against a live Keycloak
26.7.1, container `kc-logout` on port 8132, with a second container holding a
listener at `172.17.0.4:9099`.

## 0. How an outbound call is measured, and what it costs the harness

Every measurement this project has taken so far is a response to a request the
prober made. Back-channel logout is the first thing Keycloak does that nobody
asked it for: it opens a socket of its own to an address a client registered.
To see it you need to be the address.

**A listener on the host does not work.** Colima runs the Docker daemon inside a
Lima VM, so `docker run -p 8132:8080` forwards the *guest's* port outwards and
gives the guest nothing pointing back. `172.17.0.1` inside the container is the
VM's bridge gateway, not macOS. Nothing on the host is addressable from inside
Keycloak without adding a second forwarding layer.

**A listener in a second container does.** Both containers sit on the default
bridge and reach each other by IP:

```bash
docker run -d --name kc-listener -v $HOME/kclisten:/app:ro alpine:3 /app/kclisten :9099
docker inspect kc-listener --format '{{.NetworkSettings.Networks.bridge.IPAddress}}'   # 172.17.0.4
```

The mount is under `$HOME` and not `/tmp`, because colima shares the home
directory into the VM and does not share `/tmp`. The listener is a static Go
binary that dumps method, path, every header and the body to stdout and answers
by path - `/status/500`, `/status/404`, `/slow` (30s), anything else 200 - so
one process covers the success and every failure mode. `docker logs` is the
transcript.

### What the conformance harness can and cannot express about it

`internal/conformance` serves an `http.Handler` and compares one request against
one recorded response. There is no second socket in that picture, and there is
no place in a `Case` to put one. A case that needed a listener would need:

- a listening address the recorder and the verifier both reach, which means the
  recorder needs a port the reference *container* can dial and the verifier needs
  one an in-process handler can dial. Those are different addresses, so the
  address cannot be a constant in the catalogue - it has to be substituted, the
  way `{{id_token}}` is, from a fixture that started the listener;
- a second golden shape. `Case`'s golden is one response. The outbound POST is a
  *request*, with a method, a path, headers and a body of its own, and nothing in
  `golden.go` writes one;
- a way to say "wait". The outbound call is synchronous here - measured, see 1.7 -
  but nothing in the harness says so, and a case that read the listener's log
  after the response would be racing on any implementation that made it
  asynchronous.

And `CGO_ENABLED=0 go test ./...` must not need the network. An in-process
`httptest.NewServer` on `127.0.0.1` would satisfy that, but it is not the shape
`case.go` has, and `case.go` is not this cut's to change.

**So the decision is: `oidc/logout/backchannel` stays `Pending`**, with a reason
that says what was measured and why the harness cannot hold it, the way
`oidc/ciba/poll-pending` says "unmeasurable in this container regime". The guard
against a regression is `internal/oidc`'s own test, which stands up an
`httptest.NewServer` and asserts the POST byte for byte - localhost, no Docker,
no network.

`oidc/logout/frontchannel` is a different case entirely: **front-channel logout
is not an outbound call at all.** Keycloak answers the browser with a page
carrying an `<iframe>` per client and the *browser* makes the calls. That
response is exactly what the harness records. It stays `Pending` only because
its body is a theme page, which is P13's - the same reason the other five
`/logout` page cases carry - and its envelope is served now.

## 1. What was measured

### 1.1 Neither is a feature flag

`GET /admin/serverinfo` lists 73 features and 40 disabled ones. Neither
back-channel nor front-channel logout is among them; `LOGOUT_ALL_SESSIONS_V1` is
the only logout-shaped entry and it is a `DEPRECATED` flag about something else.
Both are core, both are reachable, and the CIBA answer - "unmeasurable in this
container regime" - is not the answer here.

### 1.2 Four triggers fire the back-channel call and two do not

| what | answer | outbound calls |
|---|---|---|
| `GET /logout` with a valid `id_token_hint` | 200/302 | 1 per client session |
| `POST /logout` with a `refresh_token` | 204 | 1 per client session |
| `POST /admin/realms/{r}/users/{id}/logout` | 204 | 1 per client session, per session |
| `DELETE /admin/realms/{r}/sessions/{sid}` | 204 | 1 per client session |
| `POST /admin/realms/{r}/logout-all` | 200 | **0**, and it ended two sessions |
| `POST /revoke` with a refresh token | 200 | **0**, and it ended the session |

The last two rows are the finding. Hanging the notification off "a session was
removed" is the obvious implementation and it fires on all six.

A **rejected** logout fires nothing: a valid hint with an unregistered
`post_logout_redirect_uri` answers the 400 page and makes no call, which is the
same "a rejected logout ends nothing" the endpoint already records.

### 1.3 Who is called

One POST per **client session inside the user session being ended**, for each
client carrying a `backchannel.logout.url`. Measured on a three-client SSO
session: two clients with the attribute, one without, two calls. The client that
*asked* for the logout is called too. A second session belonging to the same user
is untouched - two direct grants, a logout with the first session's hint, one
call.

### 1.4 The request

```
POST /bc HTTP/1.1
Accept-Encoding: gzip,deflate
Connection: Keep-Alive
Content-Length: 843
Content-Type: application/x-www-form-urlencoded
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.12)

logout_token=<jwt>
```

One form key, no query, no authentication of any kind. The `Content-Type` has no
charset.

### 1.5 The logout token

```
header  {"alg":"RS256","typ" : "logout+jwt","kid" : "<the realm's RSA kid>"}
payload {"exp":…,"iat":…,"jti":"…","iss":"<issuer>","aud":"<clientId>",
         "sub":"<user uuid>","typ":"Logout",["sid":"<24 chars>",]
         "events":{"http://schemas.openid.net/event/backchannel-logout":{}}}
```

- `typ` is `logout+jwt` in the JOSE header and `Logout` in the payload. Two
  spellings of one word in one token.
- `exp - iat` is **120** seconds.
- `aud` is the client's `clientId` as a bare string, always one client.
- `kid` is the realm's active RSA signing key - the same `kid` the ID token
  carries, so a client that already fetched the JWKS needs nothing new.
- **`sid` appears only when `backchannel.logout.session.required` is the string
  `"true"`.** An absent attribute behaves as `false`. Measured on three clients
  differing only in that value.
- The JOSE header's ` : ` spacing is Jackson's and is on **every** Keycloak JWT
  header, not just this one - the ID token and the refresh token were re-read
  beside it and carry it too. See finding F-b.

### 1.6 A client that fails changes nothing

| client answers | logout answers | session | outbound POSTs | elapsed |
|---|---|---|---|---|
| 200 | 302 | ended | 1 | 0.009s |
| 500 | 302 | ended | 1 | 0.009s |
| 404 | 302 | ended | 1 | 0.007s |
| connection refused | 302 | ended | 0 | 0.008s |
| no route to the address | 302 | ended | 0 | 3.10s |
| accepts and never answers | 302/200 | ended | 1 | 5.03s, 4.97s |

**No retry** - one POST for the 500 and one for the 404. **No effect on the
answer** - the status, the `Location` and the session are what a healthy client
would have produced. The only observable is time: a client that holds the socket
open blocks the logout for about five seconds, twice measured. (The 3.10s row is
the bridge's ARP timeout rather than anything Keycloak configures, and is not
claimed as a contract.)

### 1.7 The call happens before the session is removed

With a hanging client holding the socket, the Admin API still lists the session.
So the notification is sent while the thing it announces is still true.

### 1.8 Front-channel logout turns the 302 into a 200

A session holding at least one client with `frontchannelLogout: true` **and** a
`frontchannel.logout.url` answers a **200 theme page** where the same request on
a plain client answers a 302 - with the same valid hint, the same registered
`post_logout_redirect_uri` and the same `state`.

```
HTTP/1.1 200 OK
Set-Cookie: AUTH_SESSION_ID=…;Version=1;Path=/realms/master/;Secure;HttpOnly;SameSite=None
Set-Cookie: KEYCLOAK_IDENTITY=;Version=1;Path=/realms/master/;Max-Age=0
Set-Cookie: KEYCLOAK_SESSION=;Version=1;Path=/realms/master/;Max-Age=0
Cache-Control: no-cache
Content-Language: en
Content-Security-Policy: frame-src 'self' localhost:9998 localhost:9998 ; frame-ancestors 'self'; object-src 'none';
Content-Type: text/html;charset=utf-8
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Robots-Tag: none
```

- `data-page-id="login-frontchannel-logout"`, `<h1 id="kc-page-title">Logging
  out</h1>` - **the same title the confirmation page carries**, which is why the
  title is not enough to tell the two apart.
- The body lists each client by `clientId` with a hidden `<iframe>`, then a
  script doing `window.location.replace(<target>)` on `readystatechange` and a
  `Continue` link to the same place. The target follows the 302's rule: `state`
  and nothing else, and an empty `state=` is dropped.
- **The `Content-Security-Policy` is computed, not the constant every other theme
  page sends.** One `host:port` per client, scheme and path stripped, **not
  de-duplicated** - two clients on `localhost:9998` produce the host twice - and
  a **space before the semicolon**. Read off the wire with `od -c`.
- `frontchannel.logout.session.required` **defaults to true when absent** - the
  opposite of its back-channel namesake. With it the iframe `src` gains
  `?sid=<sid>&iss=<percent-encoded issuer>`; with `"false"` the URL is bare.
- Both halves are required: `frontchannelLogout: true` with no URL attribute
  produces no iframe, and a URL attribute with the flag `false` produces none
  either.
- With **no** `post_logout_redirect_uri` the page is still a 200 with the
  iframes, and carries neither the script nor the `Continue` link.
- With **no** `id_token_hint` the confirmation page still wins: the front-channel
  page is only reached once the logout is authorised.
- The `POST` family's 204 is unaffected - it is not a browser and there is
  nowhere to put an iframe.
- Front-channel and back-channel coexist. One session holding one of each got the
  page **and** the outbound call.

## 2. What this cut builds

`internal/oidc` sees only store interfaces and `internal/store` is not this
cut's to change, so "which clients are in this session" is answered with the two
methods that already exist: `Clients().ListByRealm` filtered to the clients that
carry a channel-logout attribute at all, then `Sessions().ClientSession` for each
of those. That is one query plus one per *registered channel-logout client*,
which is zero on every realm this project bootstraps.

1. **`internal/token`**: `LogoutClaims` in the measured key order and
   `Issuer.IssueLogout`, signing RS256 with the JOSE header's `typ` set to
   `logout+jwt`.
2. **`internal/oidc/channellogout.go`**: the four attribute names, the client
   lookup above, and the outbound POST - one `http.Client` on the handler with
   the measured five-second timeout, every error swallowed, no retry.
3. **`internal/oidc/logout.go`**: fire the notification **before** the session is
   deleted, on both the GET family's authorised branch and the POST family's; and
   serve the front-channel page instead of the 302 when the session holds a
   front-channel client.
4. **`internal/httpx`**: `WriteThemePageCSP`, taking the frame-src hosts, so the
   computed policy is written where every other response body is written. The
   existing `SetContentSecurityPolicy` doc comment is corrected while it is open:
   it still claims revocation is the only response carrying the header, which
   AGENTS.md recorded as false on 2026-08-29.
5. **The catalogue**: both cases stay `Pending`, both get a measured `Reason` and
   a real fixture and request in place of `REPLACE-WITH-A-REAL-ID-TOKEN`.

Not built, and named as follow-ups rather than left silent: the two admin
triggers (`internal/admin` is not this cut's), the cookie clears on the logout
responses, and the JOSE header's byte layout.

## 3. Mutation tests

One mutation per claim, each confirming the *named* test fails:

| claim | mutation |
|---|---|
| `sid` only when the attribute is `"true"` | make it unconditional |
| the payload key order | move `events` before `typ` |
| `typ` is `Logout` in the payload | make it `logout+jwt` |
| the header's `typ` is `logout+jwt` | drop it |
| `exp - iat` is 120s | make it 60 |
| a client with no URL is not called | call every client in the session |
| a rejected logout calls nobody | move the call above the validation |
| a failing client does not change the answer | propagate the error |
| the front-channel page replaces the 302 | keep the 302 |
| the CSP repeats a host per client | de-duplicate it |
| the CSP's space before `;` | remove it |
| front-channel needs both the flag and the URL | drop the flag check |
