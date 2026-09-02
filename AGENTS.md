# Working on Gloak

Gloak is Keycloak rewritten in Go. It is a deliberate copy: from the outside it must
be indistinguishable from **Keycloak 26.7.1**, byte for byte wherever a client can
observe it, while its schema and internals are its own.

Read `README.md` for what the project is and how to run it. This file is about how
to change it.

## The one rule that overrides the others

**Observable values are measured, never remembered.**

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` records what a live
Keycloak 26.7.1 actually emits. Every value in it is a contract: error strings,
status codes, header spellings, claim names, cookie attributes, argon2 parameters,
JSON key order.

If you need an observable value that is not in that document, measure it and record
it there. Do not write it from memory, and do not infer it from the documentation:

```bash
docker run -d --name gloak-ref -p 18091:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7.1 start-dev
until curl -sf http://localhost:18091/realms/master >/dev/null; do sleep 2; done
# ... measure ...
docker rm -f gloak-ref
```

The rule is no longer only a convention. `internal/conformance` fails the build
for any endpoint marked `Implemented` that has no recorded golden, so shipping a
response nobody measured is a red test rather than something a reviewer has to
catch.

## Things that look like bugs and are not

Fixing any of these breaks compatibility. They are measured Keycloak behaviour.

- **Four error shapes, not one.** `{"error","error_description"}`, a bare `error`
  holding prose, `{"errorMessage"}`, and the RFC 6749 shape on the admin API. They do
  not split along the protocol/admin boundary. `userinfo` with a bad token is its own
  case: 401, `text/plain`, empty body, error in `WWW-Authenticate`.
- **An unknown client returns `invalid_client`, a wrong secret returns
  `unauthorized_client`** with identical descriptions.
- **"Realm not found." has a trailing period on the admin API and none on the
  protocol endpoint.**
- **The charset on `Content-Type` splits by API surface and status class, not by
  endpoint.** On the **Admin API** every 2xx with a body carries
  `;charset=UTF-8` and every error carries plain `application/json` - 158
  goldens to 151, with one counterexample this file records separately
  (`POST /groups/{id}/children`'s 201). On the **protocol side** every 200
  carries plain `application/json`: token, userinfo, certs, discovery,
  introspection, revocation, device. `Accept` is not the variable - five
  spellings including none at all give the same answer.
  **There are three surfaces, not two**, corrected 2026-09-01: the
  client-registration family lives under `/realms/{realm}/`, is not the Admin
  API, and answers the **Admin API's** rule. The list of protocol endpoints
  above is exactly the set this bullet was drawn from - which is the second time
  this same bullet has been generalised from the endpoints that happened to have
  been measured.
  (This bullet said the split was "only on this one endpoint",
  `GET /realms/{realm}`, until 2026-08-30. It was simply the one endpoint of
  that family that had been measured when the line was written, and **the
  repository's own 438 goldens had contradicted it since P2** - as had
  `writeAdminJSON`'s doc comment, which states the rule correctly. The code
  knew and the contract document did not, which is the failure mode this
  document exists to prevent and the one it is least able to catch in itself.
  `httpx.WriteJSONCharset`'s doc comment still repeats the old reason.)
- **A wrong method on a known path returns 404, not 405, with no `Allow`
  header.** Gloak once invented a 405 that does not exist; Keycloak answers with
  the same generic 404 it uses for everything else it cannot route. The two 404s
  are not the same body, though: an unmatched path answers `{"error":"Unable to
  find matching target resource method"}`, a wrong method on a known path
  answers `{"error":"HTTP 404 Not Found"}`. That is why `withKeycloakFallbacks`
  still tells the two cases apart even though both return the same status.
  **There are four producers of that second body, not two**: a correct method on
  a correct path whose *resource is switched off* sends it - every route under
  `authz/resource-server` on a client without `authorizationServicesEnabled`,
  to every caller including one holding no admin role - and so does **a
  malformed integer query parameter**, measured on five listings across four
  families, which is the first producer reaching a route the caller may
  legitimately use. So the body does not mean "wrong method"; it means "the
  router found nothing to run".
- **That rule is measured too broad, seven times now, and the Admin API alone
  now answers it in three different shapes** - the client scopes answer all four
  wrong verbs 405, the protocol mappers answer `PATCH` alone 405, and the scope
  mappings answer `PUT` and `PATCH` 405 and `POST`/`DELETE` 404, which is
  exactly the role-mapping paths' split. Three sibling families, three answers,
  one API. On the role-mapping
  paths `PUT` and `PATCH` answer a real 405 while `POST` and `DELETE` answer the
  404 above - same path, four verbs, two statuses. `/admin/realms` answers
  `DELETE` with a 405, refuting "the verb decides". And on
  `/realms/{realm}/protocol/openid-connect/auth`, `PUT`, `DELETE` and `PATCH`
  all answer a real 405 with `application/json`, while `HEAD` answers 200 and
  `OPTIONS` answers 200 with `Allow: HEAD, POST, GET, OPTIONS`. `/logout`
  answers the same three verbs 405 and `OPTIONS` 200 with **no `Allow` at
  all**. And a whole Admin API route family - the client-scope attachments -
  answers a real 405 too, which is the first one outside the protocol side.
  And **`HEAD` is 200 on `/auth` and 404 on `/login-actions/authenticate`**,
  which answers the other four verbs identically to `/auth` - the sharpest data
  point yet, because both endpoints are in one flow on one container and agree
  on four verbs and disagree on the fifth.
  Gloak sends 404 to all of them. **Six data points that disagree still do not
  say what the rule is**, which is exactly why nothing has been changed on the
  strength of any of them. The 405 body is
  `{"error":"HTTP 405 Method Not Allowed"}`, measured independently on the
  protocol and admin sides on the same day, so the fallback family has five
  bodies rather than four. See F31 before adding a 405 or defending the 404.
- **The five security headers have five exceptions, and no two are decided by the same thing.** A route match
  and a known path hit with the wrong method both get `Referrer-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`
  and `X-Robots-Tag`. A path matching no route at all gets none of them,
  because that request never reaches Keycloak's filter chain. **`userinfo`'s
  rejections send four of the five, omitting `X-Frame-Options`** - they do
  reach the filter chain, so this one is not explained by routing, and its
  own 200 sends all five, so it is not explained by the endpoint either. And
  **a 204 carries `X-Frame-Options` only when the request declared an
  `application/*` `Content-Type`**: measured across seven Content-Type values
  on one endpoint, every one answering 204. That covers every delete (no
  Content-Type, so no header), the client and user updates (JSON, so the
  header), and `PUT .../userLabel` (`text/plain`, so no header).
  `httpx.WriteNoContent` is the one place that decides. Applying them
  uniformly "for consistency" is the fix that would break all three.
  **The fourth, added 2026-08-30: an `OPTIONS` 200 sends four of the five,
  omitting `X-Frame-Options`.** Measured on `/auth/device`, `/auth`, `/logout`
  and `/token`, all four on one container and all four alike - three of them
  surface this project has served since P1 and P3. The other three exceptions
  are about the path, the endpoint and the request's `Content-Type`; this one is
  about the method, and none of them covers it. Gloak answers `OPTIONS` through
  `WithKeycloakFallbacks`, so nothing was changed on the strength of it; the
  same sweep also found that **`/auth` is the only one of the four whose
  `OPTIONS` carries an `Allow` header**. See F31.
  **The fifth is not explained, and every explanation offered so far has been
  refuted by goldens already in this repository.** Fifteen committed goldens
  answer the byte-identical 67-byte `Duplicate resource error` body. Counted from
  that list:

  ```
  POST  seven send none of the five, three send all five
  PUT   four send none, one sends all five
  ```

  So the status is out, the body is out, its length is out, emptiness is out
  (none of the fifteen is empty), the request's `Content-Type` is out - varied
  over four spellings on one of them without moving it - and **the verb is out**,
  which was this bullet's last surviving lead.
  "The endpoint decides" does not survive either. `admin/protocol-mappers/`
  `add-models-duplicate-id-same-container` and `-other-container` are the **same
  route, the same verb, the same `Content-Type` and the same 67 bytes**, and one
  sends all five while the other sends none. They differ only in which internal
  failure produced the 409 - a duplicate id inside one container against one
  across two.
  What is measured, and it is all that is measured: **the header set follows
  whatever produced the response, and nothing about the request or the response
  distinguishes the two.** An empty body does send none of the five - every 204
  that omits them, every empty 404 and the resource search's empty 400 agree -
  but emptiness explains only the empty answers and none of these fifteen.
  So four exceptions are decided by the path, the endpoint, the request's
  `Content-Type` and the method; the fifth is a split nobody has explained, and
  a sixth is likelier than a unifying one. See F147.
  **This bullet has now been wrong five times, twice refuted by the very golden
  it cited.** "A 409"; then "an empty response body", folded in from a cut that
  had measured one case, while the golden refuting it was committed in that same
  cut; then "a `POST` keeps them and a `PUT` drops them", which fourteen further
  goldens refute. Its own closing advice was written in the commit that broke it.
  **Before writing a rule about headers, grep the goldens for a case that would
  break it** - and prefer "not explained" to the next explanation.
- **That rule was wrong once already.** P2's Task 11 recorded it as "a
  successful `DELETE`'s 204 omits it", from four deletes that all happened to
  send no `Content-Type`. When a new 204 disagrees with a header rule, measure
  the request's headers before believing the method.
- **`Cache-Control` on a 204 does not follow the method.** Four of the **six**
  measured deletes carry `no-cache`; `DELETE .../client-secret/rotated` does not,
  and neither does `DELETE /organizations/{id}` or its `PUT`. It is pinned per
  endpoint, which is now the third time that is the only part to survive.
  (This bullet ended "no `PUT` carries it" until 2026-08-29, when one cut added
  a `PUT` that does - `.../default-groups/{groupId}`, `no-cache`, and its
  `DELETE` sibling too - and two `PUT`s that do not, the client-policy pair, in
  the same commit. Both directions in one measurement. "Pinned per endpoint" is
  the part that survives; every generalisation over the method has now failed
  twice.)
- **A client with no secret answers `GET .../client-secret` with 200 and no
  `value` key**, not 404 - and none of the six bootstrapped clients has one.
  `POST` mints a secret even for a public client, whose representation then
  still omits it: `secret` in `ClientRepresentation` follows `publicClient`,
  not what is stored.
- **A rotated client secret cannot exist on a default 26.7.1.**
  `CLIENT_SECRET_ROTATION` is a disabled preview feature and `secret-rotation`
  is not a registered executor, so `GET .../client-secret/rotated` is always
  404 and `DELETE` always 204. Those constants are the contract, not stubs.
- **A mask is a path, and a mask that changes nothing is worse than none.** The
  catalogue held 293 across six fields and **116 were removed on 2026-08-30
  because they changed no byte of any golden**: forty `Unordered` on arrays of
  one element or none, where sorting is the identity; ten `Volatile` naming rows
  an empty listing does not have; and sixty-six masking a value
  `ReplaceCaptured` had already rewritten to `{{group_id}}` or
  `{{client_uuid}}`. All three read as "this varies", which is a claim about
  Keycloak that the next person believes and does not go behind.
  `TestNoMaskIsInertOnItsGolden` and `TestNoVolatileMaskCoversACapturedValue`
  are the ratchets, and both fail on the catalogue as it stands rather than only
  on what a diff touched.
  **F46's question has a second half in the body and it was answered the same
  way.** Masking a whole `Location` asserted presence and nothing else; masking a
  whole body value asserted its type and nothing else.
  `admin/groups/children-list` masked `*/id` and `*/parentId` alike, so a
  handler answering with the child's own id in `parentId` compared equal to one
  answering with the parent's - measured doing so. A path only **partly**
  captured keeps its mask, and nine do.
  Three of the removed masks **contradicted a measurement outright**: the paged
  role listings declared `Unordered` while the case beside them deliberately
  does not, with a comment saying the paged path was measured sorted. All three
  were inert, so the contradiction had no effect and no way of being noticed.
- **Two recordings agreeing is never evidence of stability.** A client's
  `defaultClientScopes` came back identical on both of two container starts, on
  all six bootstrapped clients, while `optionalClientScopes` swapped two names
  between the same pair. What decides it is the existing measurement - the two
  lists swapping `roles` and `profile` between two clients created minutes
  apart. **No mask in this repository may be removed on the strength of two
  agreeing recordings**; the 116 that were removed rest on arithmetic instead.
- **`attributes` key order is masked on seven cases and the reason is different
  on each half.** `Case.UnorderedKeys` sorts both sides, so membership and
  values stay asserted. This is the only such retreat - do not add a second
  without writing down why. Not every Java map in this API needs it: a protocol
  mapper's `config` is reproduced exactly, asserted by
  `admin/client-scopes/list`.
  **The old reason - "matching it would mean emulating `java.util.HashMap` in
  Go" - stopped being true on 2026-08-30**, because the emulation exists and
  works. `javamap.KeyOrder` places **a client's** `attributes` exactly: all five
  key sets a default install has come back in its order, sorting is wrong on all
  five, and the keys occupy buckets 0, 2, 3, 9 and 11 at the default 16, so
  nothing collides and no insertion order is needed. The mask stays on those
  five cases for a different reason - `internal/admin` marshals a Go
  `map[string]string`, which `encoding/json` sorts - and that is F95, one
  `model.StringMap` away.
  **A realm's `attributes` genuinely cannot be placed**: four of its eight keys
  share bucket 0 and chain in an insertion order nothing observable reveals,
  which is the documented limit of both functions. Those two masks stay for
  good.
  An eighth mask was **inert** and is gone: `admin/roles/list-realm-full` masked
  a one-key object, where sorting is the identity.
- **Gloak deletes the `Date` header on every response.** Keycloak sends none;
  Go's `net/http` adds one automatically, so `internal/httpx` suppresses it with
  `w.Header()["Date"] = nil`. The conformance verifier cannot catch its removal:
  it serves through `httptest.ResponseRecorder`, which never adds a `Date`
  header either. The guard is `internal/httpx`'s own test, which uses a real
  `httptest.NewServer` instead.
  **It was false for 204s until 2026-08-29.** `WriteNoContent` was the one
  writer that never called `suppressDate`, so every delete, update, credential
  move and group join carried a `Date`. Two tests guarded the rule and both went
  through `WriteJSON`, so the hole was exactly where the third writer is. A
  per-writer rule needs a per-writer test; found by reading bytes off a socket,
  not by running anything. See F54.
- **A dead session and a bad refresh token answer differently.** A token whose
  session was ended - by an admin logout or by revocation - answers
  `"Session not active"`; one that was never valid answers
  `"Invalid refresh token"`. Same status, same code, different description.
- **`POST /users/{id}/logout` stamps the user's `notBefore`** with the moment
  it happened, so its effect is visible in the representation and not only in
  its 204.
- **Revocation answers an unknown token with 200 and an error body**, not 400:
  `{"error":"invalid_token","error_description":"Invalid token"}` with a 200 status
  line. The client asked for a token to stop working and it does not work.
- **The revocation success carries `Content-Security-Policy` and no
  `Content-Type` at all** - the body is empty. Revocation's own error responses
  carry neither. That is why the header is set at one call site rather than
  alongside the five security headers. **This said "the only response measured
  so far" until 2026-08-29, and P3's sweep falsified it**: six of the seven
  responses in the browser flow carry the header, because it is one of the
  realm's `browserSecurityHeaders` and any response Keycloak produces through
  the page path gets it. Revocation is the odd one on the *protocol* side, not
  in the server.
- **A public client may revoke but may not introspect.** `admin-cli` revoking
  succeeds; `admin-cli` introspecting is refused with 403
  `{"error":"invalid_request","error_description":"Client not allowed."}`.
- **A client cannot introspect its own access token.** An access token's `aud`
  holds the clients the *user* has roles on **minus the issuing client**, and
  Keycloak answers `{"active":false}` with 200 when the caller is outside it.
  The exclusion is measured directly: give the user a role on the requesting
  client and that client appears in `resource_access` and still not in `aud`.
  A refresh token from the same client introspects active, so the check is on
  access tokens alone.
- **Four token claims are absent rather than empty**: `aud` and
  `resource_access` when the user holds no client role, `realm_access` when it
  holds no realm role, `allowed-origins` when the client has no web origins.
  A user with no roles gets a token with none of the four - not `[]`, not `{}`,
  not `{"roles":[]}`. Emitting an empty one "for consistency" is the fix that
  breaks it.
- **`aud` is a string when it names one client and an array when it names
  several.** So is the refresh token's `aud_x`, and so is the introspection
  body's `aud`. The ID token's `aud` is a string always, and it names the
  issuing client - the one place the two tokens disagree.
- **Keycloak's JSON key order for a Java `Map` is `HashMap` bucket order**, not
  sorted and not insertion order. **There are two constructors and
  `internal/javamap` models them separately.** `javamap.KeyOrder` is the
  no-argument one - 16 buckets, doubling at the 0.75 load factor - and is
  confirmed against **fourteen** measured key sets: twelve in its own tests, and
  two pinned where they are served. The twelve are four token and `access`
  shapes, the five client `attributes` sets a default install has, and three
  from the authentication SPI. The two outside are the `clientMappings` of a
  combined role-mapping view, where six clients assigned `cx1..cx6` came back
  `cx6, cx5, cx2, cx1, cx4, cx3`, and the `active` map of
  `GET /admin/realms/{realm}/keys`, which has **no** bucket collision at all.
  It cannot resolve a bucket collision, because those chain in insertion order
  and nothing observable says what that was; **two key sets demonstrate that and
  both collide exactly twice** - the 21 admin role names, and the fourteen
  providers of `unregistered-required-actions`, where twelve are placed and the
  two colliding pairs come back the other way round. Sorting instead is what
  makes `resource_access` come out `account, master-realm` where Keycloak says
  `master-realm, account`.
  (This bullet said "six measured key sets - four in its own tests" until
  2026-08-31, **and the tests already held nine**. A cut that measured three
  more and reported "six to nine" inherited the wrong base, and the fold carried
  it. A count in prose beside the tests that hold the thing counted is a count
  that will drift; this one is now the number the package's own tests assert.)
- **The refresh token's `scope` is the granted scope plus the client's default
  client scopes**, not a constant. `service_account` is one of them only on a
  client with service accounts enabled, and `openid` only when it was asked
  for. It was written down as a fixed list of eight and was wrong both ways.
- **`account` is the client every user has roles on.** A bootstrap that creates
  it without its eight roles, or without wiring `default-roles-master` over
  `manage-account` and `view-profile`, issues tokens with an empty
  `resource_access` and therefore no `aud` at all. Every user creation path -
  the admin API's and the service account one - has to assign
  `default-roles-<realm>`.
- **`userinfo`'s 200 sends `Cache-Control` twice**, `no-store` then
  `no-cache`. Every rejection sends only `no-store`. The conformance harness
  compares every value of a repeated header because of this one response.
- **A refresh token introspects into the access token's claim set**, nineteen
  keys with `active` last, not RFC 7662's small set. The roles in it are
  resolved at introspection time rather than read out of the token, which is
  how a refresh token carrying none comes back with all of them.
- **`not-before-policy`** in the token response is spelled with hyphens.
- **Refresh tokens are signed HS512**, access and ID tokens RS256. That is why a
  realm holds two keys.
- **`admin-cli` has standard flow disabled and direct grants enabled**, and carries
  `client.use.lightweight.access.token.enabled = true`. Without that attribute its
  access tokens carry a different claim set than Keycloak's.
- **The admin role container in `master` is the `master-realm` client.**
  `realm-management` is its equivalent inside non-master realms.
- **One user serialises three ways.** `GET /users` carries a one-key `access`
  block, `GET /users/{id}` a six-key one, and
  `.../clients/{uuid}/service-account-user` none at all. A shared user
  serialiser would be wrong twice. `access` describes the **caller's**
  permissions, never the user being read.
- **`GET /users/count` is a bare JSON number**, and it is not filtered by what
  the caller may see, while the listing beside it is.
- **The user listing's two filter families do not agree.** `username`, `email`,
  `firstName` and `lastName` are case-insensitive **substrings** where `*` is a
  literal; `search` is a case-insensitive **prefix** where `*` is a wildcard
  and `"quotes"` mean equality, and `exact=true` does not reach it. Writing one
  comparison for both is the mistake this project already made once.
- **A user's username is lowercased on create and immutable on update.** A
  `PUT` naming a free username answers 204 and changes nothing; naming a taken
  one still answers 409.
- **An empty or `null` request body on `POST /users` is a 500**, not a 400.
  Another of Keycloak's own defects, reproduced.
- **The endpoints taking a role *array* answer a malformed body
  `unknown_error`, where `POST /users` answers `invalid_request`.** Same 400,
  same `"Cannot parse the JSON"` description, different code. Measured on all
  ten registrations that decode a role array - the six composite writes, the
  two realm mapping writes and the two client ones - with `POST /users`
  re-measured alongside as the control, so the difference is per endpoint and
  not a change of version. Gloak served `invalid_request` on the composites
  until this was swept, because one helper decodes for both families.
- **A credential list carries no secret**, so `view-users` is enough to read
  it. `credentialData` inside it is a **JSON string**, not a nested object, and
  the `additionalParameters` inside *that* are a Java map in hash order which
  the suite cannot normalise - so `internal/admin` writes the five argon2 keys
  out in the measured order rather than marshalling a Go map.
- **`reset-password` ignores the `type` it is given** and sets a password
  whatever it is told, replacing the credential in place: same id, refreshed
  `createdDate`, `userLabel` cleared.
- **`PUT .../userLabel` consumes `text/plain`.** Sending JSON answers 415.
- **`PUT` on a role replaces; `PUT` on a client or a user merges - except for
  one field.** A role updated with a body carrying only `name` loses its
  description. A role can also be renamed through it, where a username cannot.
  Copying `updateClient`'s shape into `updateRealmRole` is the mistake this
  warns about.
  **The exception is `authorizationServicesEnabled`**, measured 2026-08-31: a
  `PUT {"description":"touched"}` on a client carrying six non-default values
  left seven fields exactly as they were and **turned that one flag off**,
  destroying the resource server with it. An omitted value means `false` there
  and "unchanged" everywhere else on the same body, because the flag is not a
  field at all - it is whether the client has a resource server. And **naming it
  `true` is not the same as leaving it alone**: on a client that already has one
  it *preserves* the three settings, where off-then-on resets them. Three states
  on one verb, and an implementation that upserts the defaults whenever the flag
  is on is right on two of them and silently resets a caller's settings on the
  third.
- **`briefRepresentation` defaults to true on a role listing and false on the
  user listing.** Same parameter, two endpoints, opposite defaults, both
  measured. One shared helper would get one of them wrong.
- **On a role mapping, `briefRepresentation` is honoured by `.../composite`
  alone.** `.../realm` and `.../realm/available` ignore it and always send the
  brief shape; the `clients/{uuid}` triple was swept separately and answers the
  same way. On the combined `GET /users/{id}/role-mappings` it does nothing at
  all - absent, `true` and `false` gave three byte-identical bodies on a
  subject holding an attribute-bearing role. That is a third answer for one
  parameter name, and plumbing it through all seven of these routes is the
  tidy-up that breaks the five which ignore it.
- **Reads accept the manage role, not just the view role.** `view-realm` or
  `manage-realm` for realm roles, `view-clients` or `manage-clients` for
  client roles, on the plain reads and the composite listings alike. The plan
  assumed single-role guards four separate times and was wrong every time.
  **Two reads refuse the *view* role**, and neither is where a role list would
  put it. `GET .../authz/resource-server/settings` needs `manage-authorization`
  or `manage-clients`, while `view-authorization` and `view-clients` read
  `GET .../authz/resource-server` immediately beside it; sharing a role list
  between those two is the tidy-up that opens a settings export to a read-only
  caller. The second is
  `GET .../identity-provider/instances/{alias}/reload-keys`, which needs
  `manage-identity-providers` where **six** sibling reads under the same
  `{alias}` take `view-identity-providers` too. So the first sits beside one
  neighbour that disagrees with it and the second sits among six, and a guard
  written per family gets one of them wrong either way.
- **`roles-by-id`'s required role comes from the resolved role's container**,
  and its 404 precedes its 403 - which does leak which role ids exist. That is
  Keycloak's measured order, and the reason previously written down for it was
  backwards.
- **`/roles/{name}/users` needs a conjunction**: a role-management role
  **and** a user-read role (`view-users`/`manage-users`/`query-users`) held
  together. Neither family alone opens it, and two roles from the same family
  do not either. It is the only endpoint in the group that works this way -
  the three siblings that look identical do not.
- **A composite write needs the manage role of every child's own container,
  and only on the add path.** Attaching a client-role child to a realm-role
  parent needs `manage-realm` and `manage-clients` together; removing the
  same child needs only the parent's. Measured on both verbs in both
  directions. Nobody knows why they differ.
- **A role mapping's read guard and its write guard are different shapes.**
  Every read under `/users/{id}/role-mappings/...` takes `view-users` **or**
  `manage-users`; every write takes `manage-users` alone. `query-users` opens
  neither, although it opens `GET /users` - so the user listing's role set is
  not reusable here, and `view-users` opening every read and no write means the
  write guard is not the read guard's slice. The guard follows the **subject**,
  not the role: assigning a `master-realm` client role needs `manage-users`,
  and `manage-clients` or `manage-realm` alone is refused, which is the
  opposite of `roles-by-id`. Five sweeps, one single role at a time - the realm
  reads, the client reads, the realm writes, the client writes and the combined
  view - because the two locators, the two columns and the combined view were
  each capable of disagreeing.
- **A caller may hand out a role only if the role is not one of the realm's
  own admin roles, or the caller's own effective roles already confer that
  admin role** - itself, or one measured to subsume it. Conferral is a measured
  implication table, not composition, and which roles count as admin roles is
  decided by the role's **container**, not its name. One predicate governs four
  operations **on the user and group role-mapping families**: both `available`
  reads, both role-mapping write pairs, and `POST .../composites`.
  **It does not govern the scope mappings**, which look like the same shape and
  are not. Their four writes and two `available` reads run the *composite-write*
  rule - the manage role of the role's own container - and the two disagree in
  **both** directions on measured inputs: the scope-mapping family refuses
  `manage-clients` an ordinary non-admin realm role that this rule allows, and
  allows a `manage-clients` caller `master-realm`'s `manage-realm` that this
  rule refuses. It differs from the composite-write rule too, running on both
  verbs where that runs on the add path alone. Reusing one predicate for the
  other family is the obvious saving and it is wrong in both directions at once.
  It is not an escalation surface either way: a scope mapping grants nothing, it
  decides which of a subject's existing roles survive into a token, which is why
  the caller-relative rule exists on the family that really does hand out a
  right and not on this one. The reads are what surprises: they answer **200 with a
  shorter list** to a weaker caller rather than refusing it, so an `available`
  that looks like it lost roles is usually right. `DELETE .../composites` is
  **not** filtered where its `POST` is, and the role-mapping `DELETE` **is** -
  measured per verb and implemented as measured, not as coherent.
- **A composite batch validates before it applies**, so one bad id leaves the
  store untouched, and the answer to a batch mixing a bad id with a forbidden
  child depends on array order.
- **The composite flag is derived, not stored intent**: it is true exactly
  when the role has children, and Keycloak flips it off when the last child is
  removed.
- **The realm's own client refuses a new role even to a full administrator.**
  `POST /clients/{master-realm uuid}/roles` is 403 for everybody; reading its
  21 roles is not.
- **A role listing pages when `search` is non-empty, or when `first` and `max`
  are both present.** Either condition alone is enough; only a request with
  neither gets the whole set back. So `max=5` alone is ignored and
  `first=1&max=5` is not. Measured on both the realm listing and the client
  listing, which agree. The paged path is **sorted by name** and the
  unpaginated one is not sorted at all, which is what makes `first=-1&max=-1`
  come back sorted where `max=2` does not: a negative bound means "no bound",
  but it still counts as present. An empty `search=` neither opens the gate nor
  closes it.
- **That rule was got wrong once, by inference rather than measurement.** The
  first version said pagination needs `search`, generalised from three probes
  that each sent only one bound; the central case, both bounds and no
  `search`, had never been issued. When it was, it paged. Upstream's
  `RealmRolesSearchTest.testPaginationRoles` had said so all along, and the
  contradiction the spec claimed with it was an artifact of comparing
  `list(1, null)` against an assertion about `list(1, 5)`.
- **Role listings have no stable order across container starts.** Every one of
  them is a bare array at the root of the body, which is why `Case.Unordered`
  learned the root path spelling `"."`.
- **Twenty-three spellings of not-found in the admin API now**, including four for
  one resource, **four** for a missing group, and three *pairs* that differ only
  in a full stop. Counted from the list, not incremented: (1) `Could not find client`, (2) `Client not found`,
  (3) `User not found`, (4) `Realm not found.` with its full stop,
  (5) `Credential not found`, (6) `Could not find role`, (7) `Role not found`,
  (8) `Could not find role with id`, (9) `Could not find composite role`,
  (10) `Could not find group by id`, (11) `Group not found` for that same
  missing group from the membership route **and** from the default-groups
  writes, (12) `Group path does not exist` from `group-by-path`,
  (13) `Could not find client scope` from `/client-scopes/{id}`, and
    (14) `Client scope not found` for that same missing client scope from the two
  default-scope families, (15) `Failed to find required action` from `GET` and
  `PUT /required-actions/{alias}`, (16) `Failed to find required action.` from
  its `DELETE` and the two priority posts, (17) `Could not find RequiredAction
  config`, (18) `Could not find configurable RequiredAction provider` and
  (19) `Could not find authenticator provider`, (20) `Group does not exist` from
  all twenty-two operations under `/organizations/{org-id}/groups`,
  (21) `Organization not found.`, (22) `Could not find component` from
  `/components/{id}` - which the **realm's own id** answers too, because
  components are parented on the realm and the realm is not one - and
  (23) `Could not find parent component` from `/components/{id}/sub-component-types`.
  An unknown identity provider alias adds nothing here: the read, the update and
  the delete all answer the generic `HTTP 404 Not Found`, so two neighbouring
  chapters measured in one cut contributed two spellings and none.
  One missing group, **four** answers; one missing client scope, two; one missing
  required action, two - each decided by which route or which verb went looking.
  **(15) and (16) are the third pair in this list separated only by a full
  stop**, after `Realm not found.` and the group family's, and this one is split
  by *verb* on one resource.

- **The group tree disagrees with itself in six places, and with the user
  routes in three more.** `POST /groups` answers 201 with an empty body and
  `POST /groups/{id}/children` answers 201 with the group in it - and with
  `application/json` carrying **no charset**, where every group read carries
  `;charset=UTF-8`. `GET /groups/count` is an object, `{"count":2}`, where
  `GET /users/count` is a bare number. The count counts the whole tree where the
  listing beside it is top-level only, and `top=true` narrows it **except** when
  `search` is set, where it is ignored. `subGroups` is `[]` everywhere except
  under `search`, and `subGroupCount` carries the truth. There are **six**
  representations of one group, and they are not a hierarchy: the child create's
  response omits `subGroupCount` where the children listing carries it, and the
  membership listing under `briefRepresentation=false` gains the attributes trio
  while gaining neither `subGroupCount` nor `access`. The sixth is
  `GET .../group-by-path/{path}`: the single group read **minus its `access`
  block** and identical otherwise. A `default-groups` entry is the membership
  shape rather than a seventh, and `briefRepresentation` does nothing to either.
  `path` is derived from
  the ancestry and cascades on a rename. Membership does not reach upwards: a
  user in a child is not a member of its parent.
- **`search` on the group listing pages the matches, not the rows.** It matches
  over the whole tree, sorts, takes `first`/`max` from the **matches**, and
  returns their top-level ancestors with the matching descendants nested.
  `?search=alpha&max=1` answering the second row rather than the first is what
  says so. Either bound alone pages, which is neither the role listings' rule
  nor the user listing's - three listings, three paging rules.
- **The same group is resolved first by one route family and last by the
  other.** On `/groups/{id}/...` it comes before any caller check; on
  `/users/{id}/groups/{id}` it comes after the subject **and** after the role
  check, so a `view-users` caller gets 403 for a group that does not exist where
  a `manage-users` caller gets 404. When both ids are unknown the **user** wins.
  And the same missing group is `Could not find group by id` on the first family
  and `Group not found` on the second.
- **An unknown client is 404 before any role check, on all twelve mapping
  routes.** A real holder with an unknown client answers `Client not found` to a
  caller that may not use the route at all - and an unknown *holder* with an
  unknown client answers about the holder. So the client's absence is not gated
  and the subject's is, on the user family; on the group family the group comes
  first and the client second, and neither is gated.
- **A group is resolved before the caller is judged - on the routes the
  description tags `Groups`, and not on the two it tags `Realms Admin`.** Every
  route naming a `{groupID}` under `/groups` answers 404 for a group that does
  not exist to **every** caller, including one holding no admin role. That is
  not the user family's shape, where a coarse gate runs first; it is
  `/roles-by-id/{id}`'s. Groups are
  otherwise authorised out of the users family - `manage-realm` is 403 on all of
  them - and `query-groups` opens the listing and the count and nothing else.
  **The exception, measured 2026-08-29:** `PUT` and `DELETE
  /admin/realms/{realm}/default-groups/{groupId}` answer **403** for a group
  that does not exist - to a `view-realm` caller, which may read that listing
  but not write it, and to a caller holding nothing. Measured on both verbs.
  `GET .../group-by-path/{path}` goes the other way and matches the `Groups`
  family. So the ordering follows the **tag**, not the presence of a group in
  the path. That is the third time this project has met a rule that is right on
  one family and inverted on its neighbour, and the second time the description's
  tag turned out to be the thing that predicts it.

- **A create's `Location` ends in a server-minted UUID on ten routes out of
  fourteen; the other four end in a name the caller chose.** Counted from the
  list below rather than incremented, which is the only way this number has ever
  been right. The uuid tails are `POST /clients`, `/users`, `/groups`,
  `/groups/{id}/children`, `/client-scopes`, `/client-templates`,
  `/clients-initial-access`, `/components`, `/authentication/flows` and
  `/realms/{r}/clients-registrations/openid-connect`; the name tails are
  `POST /roles`, `POST /clients/{uuid}/roles`, `POST /admin/realms` and
  `POST .../identity-provider/instances`, which ends in the **alias**. One more
  could not be reached on a default container and is not counted.
  (This said "four out of seven" and then "ten out of thirteen" until
  2026-09-01. The phrasing was half the problem: it used to read "ends in the new
  object's id", and an identity provider *is* addressed by its alias, so P9's
  handover counted that route as an eleventh id tail and reported "eleven of
  fourteen". A role is addressed by its name too and has always been counted on
  the other side. The split is server-minted against caller-chosen, and saying so
  is what stops the next cut re-deciding it.)
  `POST .../clients`, `.../users`, `.../groups` and
  `.../groups/{id}/children` end in a server-minted UUID; `POST .../roles` and
  `POST .../clients/{id}/roles` end in the **role's name**, and
  `POST /admin/realms` in the **realm's name**. And the child create's
  `Location` is `/groups/<child uuid>`, not
  `/groups/{parent}/children/<child uuid>` - the route that makes a child is not
  the route that addresses it. All seven were measured in one session, because a
  masking rule written from four of them would have been wrong on three.
  `Case.VolatileTailHeaders` masks the last segment for the four that need it
  and **refuses** the three that do not.
- **A realm's key set is four keys and the JWKS beside it publishes two.** The
  HMAC key that signs refresh tokens and an AES key that signs and encrypts
  nothing both appear in `GET /admin/realms/{realm}/keys` as bare `kid`s with no
  material - no `publicKey`, no `certificate`, no `validTo`. Serving three keys
  is a divergence on that endpoint alone, which is why Gloak generates an AES
  secret nothing uses.
- **An RSA key's `kid` is a digest of the key and an OCT key's is a UUID.**
  `base64url(sha256(SubjectPublicKeyInfo))`, unpadded - **not** the RFC 7638 JWK
  thumbprint, which is the obvious guess, was computed first, and gives a
  different value. Master's recorded `publicKey` digests to its recorded `kid`
  byte for byte, and the pair is a vector in `internal/keys/keys_test.go`. There
  is no "the kid rule" to share between the two key types.
- **`use` is `SIG`/`ENC` on the Admin API's key listing and `sig`/`enc` in the
  JWKS**, for the same two keys. One constant shared between them is wrong on
  one of them.
- **The `keys` array is ordered by `providerId`, a random UUID**, so its order
  is not reproducible and the case needs `Case.Unordered`. `providerId` is the
  id of the key *provider component*, a different value from the `kid` on every
  measured key; Gloak has no component table and derives it from the `kid` by a
  fixed hash.
- **`client-types` answers 501 to every authenticated caller and that is the
  contract**, not a stub. `CLIENT_TYPES` is a disabled preview feature, the same
  situation as `GET .../client-secret/rotated`'s permanent 404. The check runs
  after the realm is resolved and **before** authorization, so a caller holding
  no admin role at all gets the 501 rather than a 403 - the only route in P4
  whose guard has no role list.
- **A `PUT` with no body is a 400 on the client-policy routes and a 500 on
  `PUT /admin/realms/{realm}`.** Same verb, neighbouring routes on one resource,
  two answers. A shared decoder gets one of them wrong, which is the fourth time
  this API has punished sharing one.
- **Client policies and client profiles are the realm representation's own
  state.** Two endpoint pairs, one storage location, measured in both
  directions: a `PUT` on `.../client-policies/profiles` changes what
  `GET /admin/realms/{realm}` answers, and the reverse. Giving them a table of
  their own would create a second truth. `PUT /admin/realms/{r}` with
  `{"clientProfiles":{}}` **clears** them to `[]`.
- **A `PUT` on a realm replaces `clientProfiles` rather than merging into it**,
  and Go's `encoding/json` does the opposite by default: it unmarshals a JSON
  array into an existing slice **element by element** and keeps whatever the new
  element does not name, so a profile sent without a description kept the old
  one. Both arrays have to be emptied before the merge. Every other slice in
  that 104-key representation holds strings, where the reuse is invisible; these
  two hold structs, where it is not.
- **The default-groups listing has no reproducible order.** Three groups added
  `zzz, aaa, mmm` came back in that order; in another realm a parent added first
  and a child second came back child first. Neither insertion order, name, id
  nor path explains both. `PUT` is idempotent and `DELETE` of a group that is
  not a default group is 204 rather than 404.

- **A client inherits the realm's client scopes only when it names *neither*
  list.** Measured over nine creation bodies: naming either list, as an array,
  empty or not, suppresses inheritance on **both**, so
  `{"defaultClientScopes":["email"]}` produces a client with one default and
  **no** optionals rather than one default and the realm's five. A per-list nil
  check is the obvious implementation and it is wrong. `PUT /clients/{uuid}`
  ignores both lists outright, so they are write-once at create and only the
  four dedicated routes move them afterwards.
- **A client scope's two lists on a client are one attachment with a flag, and
  the two verbs disagree about which list they mean.**
  `PUT .../default-client-scopes/{id}` naming a scope the client already holds
  as an **optional** answers 204 and moves nothing; moving it means deleting
  from one list and putting into the other. `DELETE .../default-client-scopes/{id}`
  then **ignores the list its own path names** and removes the scope from
  whichever list holds it - on the client routes and on the realm's alike.
  Giving the delete a list argument to make the pair symmetrical is the tidy-up
  that breaks it.
- **The realm's `PUT` is a 409 on the repeat where the client's is a 204.**
  `PUT /admin/realms/{r}/default-default-client-scopes/{id}` twice answers
  `{"error":"conflict","error_description":"Duplicate resource error"}`, and so
  does putting a scope into one of the realm's lists when it is already in the
  other - which is what says the two lists are one row.
  `PUT /clients/{uuid}/default-client-scopes/{id}` twice answers 204 both times,
  and `PUT .../default-groups/{groupId}` is idempotent too, so the realm-level
  client-scope write is the odd one of the three.
- **A client scope attached to a client of the wrong protocol is a silent
  no-op.** A `saml` scope offered to an `openid-connect` client answers 204 and
  attaches nothing. So does an unknown scope *name* at create time: 201 and an
  empty list. Both are refusals that look like successes.
- **A client scope's `name` is looked at twice, with the protocol check between
  the halves.** An **absent** name is a 500 `unknown_error` - Keycloak's own
  defect, the same family as an empty body on `POST /users` - and is checked
  first; a **present but empty** name is a 400 naming the empty string and is
  checked last. That is why `{}` answers about the name and `{"name":"x"}`
  answers about the protocol. An absent protocol and an invalid one give the
  identical `Unexpected protocol`, so that check is membership rather than
  presence.
- **`protocolMappers` is absent rather than empty; `attributes` is present
  rather than absent.** `offline_access` is the one bootstrapped client scope
  with no mappers and its representation has **five** keys where every other
  scope's has six. `attributes` goes the other way and is always there, `{}`
  when empty. Two neighbouring keys on one body, opposite rules.
- **The body's `id` wins on create on two endpoints and loses on a third.**
  `POST /client-scopes` and `POST /clients`: a create naming an id produced an object with exactly
  that id and put it in `Location`. It is what lets a conformance fixture know
  an object's id before it asks for it, which is how the client-scope fixtures
  avoid capturing from `Location` on a shared container.
- **`client-templates` is a path alias for `client-scopes` that echoes its own
  path.** All five operations serve what their sibling serves, byte for byte,
  with one exception: `POST /client-templates` answers a `Location` under
  `/client-templates`. Building that header from a constant rather than from
  `r.URL.Path` sends a caller of the deprecated path to the other one. Twenty-
  three of the tag's operations are this aliasing, which is why `Client Scopes`
  10 plus its alias is not twice the work.
- **The three shapes of a client scope are decided by the route, not by
  `briefRepresentation`.** Six keys on `/client-scopes`, three
  (`id, name, protocol`) on the realm's two default listings, and **two**
  (`id, name`) on a client's - the client's omits `protocol` even on scopes that
  have one. A shared serialiser would be wrong on two of the three.
- **The client-scope family is authorised out of the *clients* role set, and
  that includes the routes the description tags `Realms Admin`.** `view-realm`
  and `manage-realm` are 403 on `default-default-client-scopes` and
  `default-optional-client-scopes`, both verbs; `view-clients` reads them and
  `manage-clients` writes them. That is the second time the description's tag
  has failed to predict the guard, and the first time it has failed in this
  direction. `query-clients` gets the client-scope listing as **200 and `[]`**
  rather than 403 - the third instance of "200 with a shorter list to a weaker
  caller".
- **Three resolution orders on one resource.** On `/client-scopes/{id}` the
  scope is resolved **before** the caller's write role, so a `view-clients`
  caller gets 404 for a scope that does not exist and 403 for one that does. On
  `/default-*-client-scopes/{id}` the role comes first, so the same caller gets
  403 for the same missing scope. On `/clients/{u}/*-client-scopes/{s}` the
  **client** comes first, the role second and the scope third.
- **A realm's fifteen client scopes are identical in every realm** - a realm
  created through `POST /admin/realms` gets the same fifteen as master, the same
  thirty-five protocol mappers, the same attributes and the same two default
  sets, byte for byte once the UUIDs are stripped. But **the realm's default set
  is nine, not the six a client carries**: the three SAML scopes are in it and
  are filtered out when an `openid-connect` client inherits.
- **The realm's default-scope listing has a reproducible order and a client's
  does not.** `role_list, saml_organization, AuthnContextClassRef, profile,
  email, roles, web-origins, acr, basic` came back on master and on a created
  realm across two container starts - insertion order, with a scope added by
  `PUT` appearing at the end. A client's two lists swapped `roles` and `profile`
  between two clients created minutes apart in one container, and the protocol
  mappers inside six of the fifteen scopes came back differently on two starts.
  So one of the three is asserted in order and the other two are sorted. The
  observed document's blanket "the client-scope name lists have no stable order"
  is true of a client's and **false** of the realm's; taking it at face value
  would have masked an assertion this project can make.

- **The authorization endpoint has two error families and the redirect URI
  decides which.** If the `client_id` resolves and the `redirect_uri` matches
  its pattern, every later rejection is a **302** to that URI carrying `error`,
  `error_description`, `state` and `iss`, with no `Content-Type` and an empty
  body. If either fails, it is a **400** serving the theme's error page,
  `text/html;charset=utf-8`, with **no `Cache-Control` at all**. So the order -
  realm, client, redirect URI, then everything else - is not a preference: get
  it wrong and the status, the family and the `Content-Type` are all wrong.
- **The page family has three statuses, not one.** An unknown, absent, empty or
  disabled `client_id` and an unregistered `redirect_uri` are 400; a
  **bearer-only** client is **403**, and its check runs *before* the redirect
  URI rather than after - `master-realm` answers 403 with a bad redirect URI,
  with none at all, and with a missing `response_type` alike. All three carry
  `Content-Language: en`, `Content-Security-Policy`, the five security headers,
  and no `Cache-Control`.
- **The rejection order is measured ten steps deep and two steps are not where
  they look.** A duplicated parameter is checked **seventh** - after the
  client's flow flags and before the scope - so a repeated `nonce` on a client
  with the standard flow off answers about the flow, and the same repeat with a
  bad scope answers about the repeat. And the PKCE check is three checks whose
  **first** is the *absent* challenge: `code_challenge_method=bogus` with no
  challenge answers `Missing parameter: code_challenge`, never
  `Invalid parameter: code_challenge_method`. Reordering either "because a
  request-shape check should come first" changes the answer to a request that is
  wrong in two ways, which is most of them. Pinned by twenty-nine paired
  requests, each pair deciding one adjacency.
- **A redirect URI is compared as a string and nothing about it is normalised.**
  A trailing slash, an added query, an added fragment, an uppercased scheme,
  host or path, a `..` segment, a percent-encoded character and `127.0.0.1` for
  `localhost` are all refused by a client registering the literal. Parsing
  either side as a URL is the tidy-up that makes half of those start comparing
  equal. And a wildcard is **not** a bare prefix: `http://localhost:9998/*`
  accepts `http://localhost:9998` and refuses `http://localhost:99980/evil`. It
  is a prefix match on the pattern minus its `*`, plus an equality check against
  that prefix with a trailing slash removed, with the query and fragment cut
  first - and the cutting happens in the wildcard branch **only**, which is why
  an exact registration refuses `?x=1`. A pattern containing a `?` is not a
  wildcard even when it ends in one, and a `*` that is not last matches nothing.
- **The scope a request may ask for follows the client, not the realm.**
  `openid` plus the client's own `defaultClientScopes` and
  `optionalClientScopes`. `service_account`, `role_list`, `AuthnContextClassRef`
  and `saml_organization` are client scopes **of master** that a normal client
  does not carry, and every one of them is refused. An absent `scope` is not
  checked at all; an empty `scope=` is checked and fails. The description echoes
  the parameter **raw**, doubled spaces and all, so it cannot be rebuilt by
  joining the parsed words.
- **`POST /auth` reads the request body and ignores the query string.** The same
  parameters that work on a `GET`'s query answer the 400 page on a `POST` that
  puts them there. `r.Form` merges the two and would hide it, so the two sources
  are read separately.
- **The response mode decides how a *rejection* travels, and two of the seven
  modes are not a redirect at all.** The accepted set is seven, not three:
  `query`, `fragment`, `form_post` and the four `jwt` spellings, compared
  case-sensitively. `form_post` and `form_post.jwt` answer **200** with an
  auto-submitting form even for a missing `response_type`; `jwt`, `query.jwt`
  and `fragment.jwt` replace every parameter with one signed **JARM** assertion
  in `response`. Reading response mode as "which separator" produces a 302 where
  Keycloak sends a 200, and plain parameters where it sends a signature. The
  invalid-`response_mode` rejection itself always goes to the **query**, even
  for `response_type=token`, whose every other rejection lands in the fragment.
- **A repeated query parameter is its own error and its description is lower
  case.** `duplicated parameter`, where every other description on this endpoint
  is capitalised, and it applies to keys the endpoint never reads - `zz` twice
  is enough. A repeated `client_id` never reaches the check, because the client
  cannot be resolved and the answer is the page family.
- **`state` is echoed whenever it was sent, including when it was sent empty.**
  `state=` comes back as `state=`; an absent `state` comes back as three keys
  rather than an empty fourth. `nonce`, `login_hint` and `ui_locales` are not
  echoed at all.
- **`GET /auth`'s redirect back to the client is the one response in the
  browser flow that omits `X-Frame-Options`,** measured across seven different
  rejections including the one that sets cookies, and it omits
  `Content-Security-Policy` with it. It is not "errors omit them":
  `POST /login-actions/authenticate`'s *error* redirect, to the same URI with
  the same status, carries all six. It is not "302s omit them", for the same
  reason. It is not "failures omit them": `prompt=none` with a live session
  redirects with a real code and omits them too. RP-initiated logout's redirect
  behaves the same way, so the rule is per endpoint.
- **`response_mode` moves the parameters and changes the status.** `query` and
  absent use the query, `fragment` the fragment, and `form_post` answers **200**
  with an auto-submitting form whose `Content-Type` is `text/html` with **no
  charset** - where the login page's is `text/html;charset=utf-8`. The form
  emits `code, iss, state, session_state`; the query redirect emits
  `state, session_state, iss, code`. One response, two orderings of four
  parameters, decided by a request parameter.
- **The authorization code's third part is the client's own internal UUID**,
  the `id` the Admin API addresses it by - not a client session id. It is
  identical on every login by any user at that client. The second part is the
  `session_state`. The first is laid out like a UUID and is not one.
- **A failed code exchange spends the code.** A wrong `code_verifier` answers
  `PKCE verification failed: Code mismatch` and the immediate retry answers
  `Code not valid`. So "single use" means single *attempt*, and two conformance
  cases cannot share one login.
- **A missing `redirect_uri` at the token endpoint answers `Incorrect
  redirect_uri`,** where a missing `code` answers `Missing parameter: code`.
  It is compared against what the authorization request stored, and absent
  compares unequal rather than being caught by a presence check.
- **Whether a hintless logout redirects is decided by the browser session, not
  by the hint.** With a live session and no `id_token_hint`, Keycloak serves the
  theme's `Logging out` confirmation page, 200, and **ends nothing** - the
  refresh token still works afterwards. With no session, the same request with a
  `client_id` and a registered target is a **302**. There are four outcomes, not
  two: that 302, the confirmation page, a `You are logged out` page (a valid
  hint and no target, 200, and the session *is* ended), and the 400 error page.
  The successful redirect carries `state` and nothing else - no `iss`, where
  `/auth`'s redirect carries one - and `Cache-Control: no-cache`, where `/auth`
  sends `no-store, must-revalidate, max-age=0`.
  (This bullet read "logout without an `id_token_hint` does not redirect" until
  2026-08-29. That is what one measurement taken through a cookie jar looked
  like: the jar was the variable and the hint was not. A case had been filed
  `Pending` on the strength of it, with the wrong reason attached.)
- **`post.logout.redirect.uris` is a filter over `redirectUris`, not a separate
  registration.** A client with no such attribute redirects to its own
  registered `redirect_uri`; so does one set to `""` or `"+"`. `"-"` refuses
  everything, including its own `redirectUris` and the literal `-`. Anything
  else is a `##`-separated pattern list that **replaces** `redirectUris` rather
  than adding to it, so setting the attribute can only ever narrow what a client
  accepts. And `-` is a marker for the whole value and not for an entry: inside
  a `##` list it is an ordinary relative pattern, accepted and resolved against
  the server's base URL.
  (This bullet said the opposite until 2026-08-29 - "a client whose
  `redirect_uri` validates at the authorization endpoint is still refused at the
  logout endpoint until it is set". Measured across six clients differing only
  in this attribute.)
- **`state=` is echoed at `/auth` and dropped at `/logout`.** One parameter, two
  endpoints, opposite answers to the same empty value. The page families
  disagree the same way: `/logout`'s 400 page carries `Cache-Control: no-cache`
  where `/auth`'s 400 and 403 pages carry none, measured side by side on one
  container. `httpx.WriteThemeErrorPage` takes the value as an argument for
  exactly this reason, and there are **three** values across four rows:

  ```
  GET  /auth                        400 and 403 pages   no Cache-Control at all
  GET  /auth  prompt=create         400 page            no-store, must-revalidate, max-age=0
  GET  /logout                      400 page            no-cache
  POST /login-actions/authenticate  400 pages           no-store, must-revalidate, max-age=0
  ```

  Three endpoints that look like one endpoint three times - **and one of them
  disagrees with itself.** The second row was added on 2026-08-30: `/auth`'s own
  page family is not uniform, and `max_age=abc`'s 400 page beside it sends none,
  so the variable is the rejection rather than the endpoint. Anything that reads
  "the page family sends X" is a claim about the rejections that were measured.
- **The device verification page cannot be submitted, and that is measured.**
  `/realms/{realm}/device` and `/protocol/openid-connect/auth/device` are **one
  endpoint at two paths**, so the theme's own verification form posts
  `device_user_code` into the *device authorization request* and gets 401
  `invalid_client`. A user can only complete a device login through
  `verification_uri_complete`. Gloak reproduces the broken form, because the
  form is the contract.
- **A response can set one cookie twice, in opposite directions.** A presented
  `KC_RESTART` is cleared on the way out and the clear is last, so a browser
  arriving with one leaves without it. Found by **recording a golden, not by
  probing**: `curl` drops a `Max-Age=0` cookie from its jar and the harness
  keeps it as an empty value, so every hand probe showed five cookies and the
  recorder showed six. When a cookie count disagrees between a probe and a
  golden, the golden is the one that saw everything.
- **`prompt` is a set of space-separated tokens, an unknown one is ignored, and
  it is case-sensitive.** `create` fires only as the sole token.
- **The consent endpoint reads `cancel` and nothing else.** No buttons at all is
  an **approval**; `accept` and `cancel` together is a denial, cancel winning;
  and the hidden `code` is not checked - `code=BOGUS` with `accept` granted a
  consent that had just been revoked. Requiring `accept` is the obvious
  implementation and it is wrong on two of the six measured bodies.
- **The device grant asks for consent every time and the browser flow remembers
  one.** The device path records a grant it then ignores.

- **`expired_token` is a window, not a state.** A device code past its expiry
  answers `expired_token` for about fifteen seconds and then answers
  `Device code not valid` - the same answer a code that never existed gets.
  Bracketed at three lifespans and reproduced across two runs at one-second
  granularity, and **no mechanism for the number has been found**, so it is a
  measured approximation rather than an understanding. Both obvious
  implementations are wrong: sweeping at expiry loses the answer the catalogue
  records, never sweeping leaks. See F91's shape and F99.
- **The device grant's poll clock is stamped by some answers and not others.** A
  wrong-client poll and a `slow_down` leave it alone; pending and denied move
  it. Polls at t=0, 3 and 6 with an interval of 5 give pending, `slow_down`,
  pending.
- **A denied device code is not consumed and a redeemed one is.**
- **CIBA checks `login_hint` before `scope`**, and checks presence and value in
  four interleaved steps rather than two. Only a request missing **both** shows
  the order, which is why a case set that breaks one parameter at a time passes
  a wrong implementation - it did, on this very endpoint, and was caught by
  asking rather than by the suite.
- **CIBA cannot complete on a default 26.7.1 and its 503 is the contract.** A
  CIBA-enabled client sending a valid request gets **503 `server_error` /
  "Failed to send authentication request"**, because the default
  `ciba-http-auth-channel` needs an external endpoint `start-dev` does not
  configure - the container log says `Authentication Channel Request URI not
  set properly`. No default container mints an `auth_req_id`, so
  `oidc/ciba/poll-pending` and `poll-complete` are **unmeasurable in this
  project's container regime** rather than unimplemented, and their `Reason`
  says so.
- **One condition, two endpoints, two families disagreeing in opposite ways.**
  The device grant's "grant disabled" pair share neither code nor sentence;
  CIBA's share both and differ on the **status**, 401 against 400.

- **A user create's inline `credentials` array is honoured, and reading it is
  not the same code path as `reset-password`.** Keycloak stores the password
  and the user can use the password grant immediately; `PUT /users/{id}` honours
  the same field. Two things refute reusing the reset-password helper:
  `userLabel` is **never read** here where reset-password *clears* it, and
  **`temporary` is a disjunction over the array that only ever adds**
  `UPDATE_PASSWORD` - both orderings of `{true, false}` leave the action on,
  where reset-password with `false` removes it. Each entry replaces the one
  before it, so an array of two passwords leaves one credential holding the
  second.
- **A credential entry with no `value` is a 500 on the create and a 400 on the
  update**, and the whole request rolls back - a third answer to a missing
  password after `reset-password`'s `No password provided`. `value:""` is a
  **201** storing a credential with no `credentialData` at all, which is
  Keycloak's own defect and is reproduced as far as the admin API reaches.
- **`PUT /clients/{uuid}` matches its protocol mappers by (protocol, name), not
  by id.** Nothing had written that down, and without it every read-modify-write
  through that route becomes a 400 `invalid_input` - which is also what that
  route answers instead of the 409 the other four give, so a mapper id collision
  has **three** answers across five routes, not two.

- **The two scope-mapping write pairs read different keys off the same JSON.**
  `POST`/`DELETE .../scope-mappings/realm` resolves each entry by **`id`**,
  realm-wide, and never looks at `name`: an entry with a real id and a wrong
  name is 204, one with a real name and no id is a **500**, and **a client role
  is accepted** and lands under `clientMappings`, readable and removable through
  the `realm` path that took it. `POST`/`DELETE .../scope-mappings/clients/{c}`
  does the opposite - it resolves by **`name`** within that client and ignores
  the id. Four operations, two lookup keys, each ignoring the other's. A decoder
  accepting an entry when *either* key matches passes every happy path and gets
  four measured rejections wrong, and adding a `role.ClientID == ""` check to
  make the realm write agree with its own path breaks the one thing that write
  does.
- **`composite` has a third input that `available` and the combined read do not:
  `fullScopeAllowed`.** A client with the flag set answers **every realm role in
  the realm** from `.../scope-mappings/realm/composite` while
  `.../scope-mappings/realm` answers `[]` and `.../scope-mappings` answers `{}`.
  Turn the flag off and the composite answers `[]`. A client scope has no such
  flag. Two of the six bootstrapped clients carry it, so it is not a corner, and
  composing the combined read out of the composite predicate is the tidy-up that
  makes three reads agree where Keycloak measurably disagrees with itself.
- **A client's own roles are in its own scope without ever being mapped.**
  `GET /clients/{c}/scope-mappings/clients/{that same c}/available` is `[]` on a
  client that owns roles, has `fullScopeAllowed` off and has mapped nothing, and
  the `composite` beside it answers those roles. So `available` subtracts a set
  with two clauses on a client and one on a client scope.
- **`available` is the complement of the direct list and `composite` is not its
  complement**, here as on the user family: with one composite role mapped, its
  child is in the composite expansion **and** in the available list, on both
  triples. Confirmed on this family rather than inherited from that one.
- **`briefRepresentation` is honoured by `.../composite` alone on the scope
  mappings too**, and six other reads on the family ignore it. That is the first
  time one of this API's parameter rules has generalised from one family to
  another rather than inverting - and it was still measured rather than assumed.
- **No response on the Scope Mappings tag carries a `Location`, which is why the
  `client-templates` alias has no exception here.** The two previous families
  each had exactly one difference between the two spellings and both were `POST`
  echoing its own path into `Location`; the writes here are 204 with an empty
  body, so all eleven operations are byte-identical, headers included. **The
  alias is distinguishable only through a `Location`.**
- **A 415 exists on this API**, and the scope mappings are where it is
  reachable, because they are the first routes whose `DELETE` carries a body.

- **The `X-Frame-Options` rule is about the empty body, not the 204.** The
  scope family's empty 404s and its 400 follow it exactly, and they are not 204s.
  A 204 is simply the commonest empty response.
- **A create's response body is not always a read of what it wrote.**
  `POST .../authz/resource-server/scope`'s 201 is the **request echoed** -
  `policies` and `resources` come back and are stored nowhere - so a handler
  that answers by reading its own write diverges on the fields the store drops.
- **One set of authorization scopes has two reads and two orders, and both are
  reproducible.** The settings export is insertion order and the listing beside
  it sorts byte-wise. One set of rows, two orders, and a shared serialiser gets
  one of them wrong. (Cut A recorded the export as sorted; it is not.)
- **`POST .../scope` is an upsert whose key is the body's id when it has one**,
  and the scope family's `name` means two different things one path segment
  apart. A scope **id** is unique globally and a scope **name** is unique per
  resource server - so a cross-resource-server id collision corrupts the *other*
  resource server on 26.7.1, turning its listing into a 400 and its settings
  into a 500. Reproduced on a fresh pair. **Gloak deliberately does not copy
  that one**, which is the first measured behaviour this project has declined to
  reproduce, and it is filed as a divergence rather than left implicit.

- **A protocol-side family answers the Admin API's charset rule.** Client
  registration lives under `/realms/{realm}/` and carries `;charset=UTF-8` on
  every 2xx with a body and plain `application/json` on every error - see the
  charset bullet, which had to be corrected for it.
- **The registration endpoint judges the body before the caller.** A refused
  `Content-Type` is a 415 and a malformed body a 400, both **ahead** of a bearer
  that does not verify. A test that sends no `Authorization` header at all
  cannot see this, because an anonymous caller writes nothing on the way
  through: the distinguishing request is a *garbage* bearer.
- **Two 403s on one endpoint and the bearer decides which**, and **one 401 with
  four descriptions, one of which splits by verb.**
- **A `PUT` rotates the registration access token and a `GET` does not**, and
  one route answers two different bodies depending on which token asked.
- **`private_key_jwt` is refused on the way in and produced on the way out**, and
  `client_secret` and `client_secret_expires_at` are decided by different things
  - so neither implies the other.
- **The JWT-bearer assertion predicate is structural and it is not "exactly
  three parts".** Two parts with a JSON object payload are **accepted**, an
  empty signature part is fine, four are refused. The signature part is optional
  and the two in front of it are not. Found by a mutation rather than a probe:
  every earlier probe of a short assertion also carried a payload that was not
  JSON, so the length check and the JSON check could not be told apart.

- **A logout that ends a session and a session that ends are two different
  things.** Four paths fire the back-channel notification - `GET /logout` with a
  hint, `POST /logout` with a refresh token, `POST /users/{id}/logout` and
  `DELETE /sessions/{sid}` - and two end sessions and notify **nobody**:
  `POST .../logout-all` ended two sessions and made zero calls, and
  `POST /revoke` with a refresh token ended one and made zero. Hanging the
  notification off session removal is the obvious implementation and it fires on
  two paths Keycloak does not.
- **The two `session.required` attributes have opposite defaults.**
  `backchannel.logout.session.required` absent behaves as `"false"` - the logout
  token carries no `sid`; `frontchannel.logout.session.required` absent behaves
  as `"true"` - the iframe's `src` does gain `?sid=&iss=`. One helper reading
  both names gets one of them wrong. The admin console's default for the
  back-channel one is **on**, so a client created there looks like the opposite
  measurement.
- **Front-channel logout is not an outbound call.** The browser makes the calls;
  the response is an ordinary page and exactly the shape the harness records.
  The case's old `Reason` said "the calls it makes are unobservable" and was
  wrong in precisely its interesting half. **A front-channel client turns the
  302 into a 200** on identical inputs, and its `Content-Security-Policy` is the
  one computed theme-page policy in the project - hosts repeated per client
  rather than de-duplicated, with a space before the semicolon.
- **The back-channel logout token says its own kind twice, in two spellings**:
  `logout+jwt` in the JOSE header and `Logout` in the payload's `typ`. Its
  `exp - iat` is **120**, and every claim in it is per client - `aud`, `sub` and
  `sid` name the client and session being told, so a test that compares outbound
  *paths* and not the token at each path passes a server that tells every client
  somebody else was logged out. That mutation survived a whole package once.
- **The notification goes out while the session is still alive.** With a hanging
  client holding the socket, the Admin API still listed the session - so the
  send is deliberately before the removal and deliberately synchronous, which is
  what the five-second block says.
- **The logout endpoint has seven response shapes, not six.**

- **A required action is enforced on two endpoints and they disagree about one
  user.** The browser login asks whether an **enabled** provider has anything to
  do; the direct grant reads the user's `requiredActions` **raw**. So a user
  carrying only the disabled `TERMS_AND_CONDITIONS` logs in through the browser
  and is refused tokens by the password grant. Measured across seven aliases.
- **Tokens are withheld, not issued-then-restricted.** No authorization code
  exists until the queue is empty, and the redirect to an action sets **no
  cookies at all** - where the credential POST that ends in a code sets three.
- **`/login-actions/required-action` is decided by the `session_code`, and the
  verb decides nothing.** Twelve requests, `GET` and `POST` agreeing on all six
  cells. An **absent** execution serves the page; a *wrong* one is 200 "Page has
  expired". The shipped handler refused anything but `OAUTH_GRANT` and was wrong
  on five of six - its comment cited a measurement whose probe had never sent an
  execution that was absent rather than wrong, and that unbroken request is the
  one that tells the two rules apart.
- **`CONFIGURE_TOTP` needs no device**: the secret's raw ASCII bytes are the
  HMAC key, not a base32 decoding. `VERIFY_EMAIL` genuinely needs SMTP and its
  500 is the contract, the same shape as CIBA's 503.

- **The `Organizations` tag resolves its resource after the caller and the
  `Groups` tag resolves before**, and both tags name their own resource in the
  path and in the tag - so nothing in the description separates them. That is
  the fourth time a rule stated over "every route naming a `{something}ID}`" has
  broken on a neighbouring family.
- **Organizations are gated by a realm flag, not by a feature flag**, and the
  refusal sits **after** the caller's roles. `GET /admin/serverinfo` reports
  `ORGANIZATION` as `"type":"DEFAULT","enabled":true` and it is absent from
  `disabledFeatures` where `CLIENT_TYPES` and `CLIENT_SECRET_ROTATION` appear.
  What is off is `organizationsEnabled` on the realm, and one `PUT` opens the
  whole tag with `404 {"errorMessage":"Organizations not enabled for this
  realm."}` until it does. `client-types`' 501 runs *before* authorization, so
  the two gates could not share an implementation.
- **`POST /organizations` reads the body's `id` and discards it**, inverting the
  rule the client and client-scope creates follow.
- **Eight strict JSON decoders, and three families disagree about when the decode
  runs.** Counted from the list: `POST`/`PUT /organizations`, two of the
  required-action writes, client registration,
  `POST`/`PUT .../identity-provider/instances` and `POST /components`. On the
  required-action `PUT` the decode runs **before** the path's alias is resolved,
  and the identity provider `PUT` joins it there; on the organization `PUT` an
  unknown id answers `Organization not found.` for an unknown field and for
  unparseable JSON alike. Opposite orders on one verb. **Client registration**
  runs before the *caller* is resolved at all - a third answer rather than a
  second.
  This bullet said "five" and claimed client registration "is also the only one
  that reports a **position**". The position claim was **already false when it
  was written** - `decodeStrict` had produced `at line 1 column N` since the
  required-action PUTs - and P9 made it false three more ways. What is measured
  is that client registration, the required-action writes and the three P9
  endpoints all report a line and column; **whether the organization pair does is
  not measured**, and that is the request to send before anybody writes the
  number back down as a rule.
- **The `Workflows` tag answers `application/yaml`**, chunked, and is not gated
  by `organizationsEnabled` at all.

- **`session_state` is minted by the login page, not by the login.** The
  authentication session's root id is created at `GET /auth`, goes out inside
  `AUTH_SESSION_ID`, and is then the redirect's `session_state`, the
  `KEYCLOAK_IDENTITY` cookie's `sid` **and** the authorization code's second
  part - four observables carrying one 24-character value decided before any
  credential was seen. Minting it when the password verifies is the obvious
  implementation and gets all four wrong at once, and **no conformance case
  would see it**: every case in this flow masks `Location` and `Set-Cookie` as
  volatile. `internal/oidc`'s own tests are the only guard.
- **`client_data` is parsed and then ignored.** The login form's fifth
  parameter carries the redirect URI, the response type, the response mode and
  the state, and none of them is used: one naming another redirect URI still
  redirects to the registered one, one naming another state still echoes the
  original, one adding `rm=fragment` still answers in the query, and dropping it
  entirely succeeds. But `client_data=!!!!` is a 400, so it **is** parsed. It is
  a restart hint the browser carries, never an authority. Reading the redirect
  URI out of it is the tidy-up that lets a forged one steer a browser - and the
  one place Gloak does read it, the expired-session restart, validates it
  against the client's registered patterns first.
- **A replayed `session_code` has three answers and the cookies pick.**
  `KC_RESTART` present is a 302 **restart** with a fresh `tab_id` and no
  `session_code`; otherwise `KEYCLOAK_IDENTITY` present is a 302 to the client
  carrying `temporarily_unavailable` / `authentication_expired`; otherwise a 400
  page, `Restart login cookie not found`. Measured as an eight-cell grid. **An
  empty `KC_RESTART` counts as absent**, which is what a successful login leaves
  behind, so a real browser gets the middle branch. An **expired** session code
  takes the identical branch, so expiry and replay are one case.
- **`/login-actions/authenticate` reads its parameters from the query and its
  credentials from the body, and `/auth` does the opposite.** Two endpoints in
  one flow with mirror-image rules, and `r.Form` merges the two and hides both.
- **A repeated parameter is checked by three of the six endpoints that have been
  measured for it, with two different codes.** `/auth` answers
  `invalid_request` / `duplicated parameter` seventh of ten; `/auth/device`
  answers **`invalid_grant`** with the same description; the token endpoint
  answers `invalid_request`, body only, fourth and after client authentication.
  `/logout`, `/login-actions/authenticate` and `ext/ciba/auth` do not check it
  at all - the first value wins, and `session_code` twice with the second value
  garbage still logs in.
  (This bullet read "`/auth` is the odd one of the three" until 2026-08-30. It
  was a fair summary of the browser trio and stopped being one as soon as three
  more endpoints were measured. A rule drawn over the endpoints that happened to
  exist is a rule about the sample.)
- **`GET /login-actions/authenticate` is not a read.** It attempts the login
  with whatever credentials the body carries - none, for a GET - and answers 200
  with the page re-served, `Invalid username or password.`, and the
  `session_code` **rotated**. A handler that made GET serve the form without
  spending the code would look more correct and would diverge.
- **A failed credential rotates the `session_code` and nothing else.**
  `execution`, `tab_id` and `client_data` are unchanged, the username is echoed
  back into the input, the retry with the rotated code succeeds, and the old one
  takes the restart branch.
- **The disabled-account message is checked after the password.** A disabled
  user with the right password gets `Account is disabled, contact your
  administrator.`; the same user with a wrong password gets `Invalid username or
  password.` like everybody else. Checking `enabled` first is the obvious order
  and it turns the login form into an account-enumeration oracle.
- **A second `GET /auth` on one browser sets one cookie, not three.** The
  authentication session is reused and only `KC_RESTART` moves, so two tabs
  share one root id and both log in reporting the **same** `session_state`. The
  restart 302 sets *no* cookie when the browser still has a live authentication
  session and two when it does not.

- **`PUT .../protocol-mappers/models/{id}` writes the mapper the *body's* `id`
  names, not the path's.** A PUT addressed to one mapper and carrying another's
  id answers 204 and changes the other one; the path segment only decides
  whether the request is a 404 at all. **And it writes two fields** -
  `protocolMapper` and `config`, replacing the config outright - while `name`,
  `protocol` and `consentRequired` are read off the wire and discarded. Writing
  the whole representation back is the obvious implementation and it is wrong on
  three fields. Both are Keycloak's own defects, reproduced.
- **A protocol mapper's `config` key order is two Java `HashMap`s, not one**,
  and `internal/javamap` models it as `SizedKeyOrder`: a table asked for `7n/4`
  buckets, then one asked for `n`, with collisions in the second chaining in
  **insertion order** rather than alphabetically. One table cannot fit the
  measurements - `{claim.name, jsonType.label, user.attribute}` comes back in
  one order from all six of its insertion orders while `{zz, aa, mm}` comes back
  in whichever order it went in, also from all six. Read off the server at every
  entry count from 1 to 50; the `7n/4` is measured rather than derived, pinned
  by four boundaries where the answer flips (n=5/6, 9/10, 18/19, 37/38), and no
  plain multiple of `n` fits all four.
  **A create that appends a key of its own appends it after the first table**,
  so a config the create grew was built for the request's key count and
  serialised at a larger one; `SizedKeyOrder` takes that count as its first
  argument.
  `javamap.KeyOrder` gets **seven** of the fourteen measured configs wrong - the
  follow-up said six, from a vector set nobody had written down - and
  `TestKeyOrderIsWrongOnHalfTheMapperConfigs` pins that count so the package
  cannot quietly start claiming both again. The conformance cases sidestep all
  of it by using config key sets measured to be order-stable, so the goldens
  assert real config bytes with **no** `UnorderedKeys` retreat.
  **The fourteen vectors do not pin the rounding rule.** Changing
  `tableSizeFor`'s `<` to `<=` passes all fourteen and fails only the boundary
  probes, so a cut that added the vectors and stopped would have shipped an
  unpinned rule that looked measured.
- **One mapper serialises two ways.** `account-console`'s `audience resolve` is
  `"config":{}` from `GET /clients` and populated from the dedicated mapper
  route, on one container minutes apart, while a client *scope*'s copy is
  populated in both of its views. Neither obvious explanation holds.
- **The "cannot parse the JSON" code is per body *shape*, not per endpoint.**
  An earlier bullet asserted the opposite and explained its own error; all
  eleven of its probes sent `{`, which is the right shape for the one object
  endpoint and the wrong shape for the ten array ones. `POST /users` answers
  `unknown_error` for `[`, the role-array endpoints answer `invalid_request` for
  it, and a truncated array *element* answers a third code,
  `HTTP 400 Bad Request`.

- **The logout endpoint forgives four things the authorization endpoint does
  not.** An **expired** `id_token_hint` still logs out and still redirects; a
  hint naming a session that has already ended answers the same 302 rather than
  an error; a **disabled** client redirects, where `/auth` answers it the 400
  page; and a **duplicated parameter is not an error at all** - the first value
  wins, where `/auth` answers `duplicated parameter` for any key sent twice.
  What it does not forgive is a `client_id` disagreeing with the hint's `azp`:
  that is `Invalid parameter: id_token_hint`, not a client error. A rejected
  logout ends nothing - validation completes before anything is destroyed.
- **A `POST` to the logout endpoint is two endpoints wearing one path, and the
  `refresh_token` decides which.** With one, the request is client-authenticated
  and answers 204 with `Cache-Control: no-cache` and a
  `Content-Security-Policy`, ignoring any `post_logout_redirect_uri` it was
  given, and answering 204 again on a replay. Without one it falls through to
  the `GET` families and answers a page or a 302. The `GET` family authenticates
  no client at all, so the same confidential client that must send its secret on
  the `POST` redirects without one on the `GET`.
- **A realm created through the API is disabled.** `POST /admin/realms` with a
  body that does not say `enabled` answers 201 and creates a realm nobody can
  log into. `PUT` on a realm **merges and can rename it**: the path segment and
  the body's `realm` need not agree, and when they disagree the body wins - the
  opposite of `PUT` on a role, which replaces, and unlike a client or a user,
  which merge but cannot be renamed that way.
- **The realm is resolved before the caller is judged.** A realm that does not
  exist is 404 to every caller including one holding no admin role, where a
  realm that exists and the caller may not see is 403. That leaks which realm
  names exist, and it is Keycloak's behaviour rather than a safe one - the same
  order `guardGroup` and `guardByRoleContainer` already record.
- **A caller's rights reach exactly one container, and one read leaks
  sideways.** A master caller holding `view-users` on `master-realm` reads any
  realm's top-level representation - in its shortest form - and is 403 on that
  realm's users, clients and roles, and the listing shows it master alone.
  Upwards nothing reaches at all: a caller inside another realm holding
  `realm-admin` is refused master outright. And the single realm read has
  **three** shapes decided by the caller's roles, where the shortest omits
  `registrationEmailAsUsername` and the full one omits the `supportedLocales`
  that both short ones emit.
- **Deleting master is 400, not 403.** The refusal is about the realm rather
  than the caller, so it is the `errorMessage` family and not the generic 403.
  `POST /admin/realms` with a malformed body is a **fourth** spelling of
  "cannot parse the JSON" - `unable to read contents from stream` - where
  `POST /users`, the ten role-array endpoints and `PUT /admin/realms/{r}` each
  have their own. A shared decoder gets three of the four wrong.

- **The login theme's `/resources/<version>/` segment is minted with the
  database, not with the container start.** Six `docker restart` of one
  container gave one value; a second container from the same image gave another;
  wiping `/opt/keycloak/data/h2` and restarting gave eight more, and the value
  is inside `keycloakdb.mv.db`. This document, F23, `themePageBody`'s doc
  comment, four `parkedGoldens` entries and four catalogue `Reason` strings all
  said "per container start" until 2026-09-01, and the sentence had been copied
  five times without anybody restarting a container to check it. **Nothing in
  the harness turns on it**, which is exactly why it survived: `make record`
  starts a fresh container every run, so a claim nothing depends on is a claim
  nothing falsifies. Thirteen values are measured and every one is five
  lowercase alphanumerics, which is what `ReplaceThemeResource`'s pattern is
  written against.
- **An absent `client_id` and an empty one are different pages at `/auth` and
  the same page at `/logout`.** `GET /auth` with no `client_id` answers
  `Invalid Request`; `client_id=` answers `Client not found.`, exactly as an
  unknown one does; a disabled one answers `Client disabled.` So the four ways a
  client can fail are **three** sentences. At `/logout` the reading inverts:
  `client_id=` counts as **absent**, and an absent or empty one answers
  `Missing parameters: id_token_hint` where an unknown, disabled or real one all
  answer `Invalid redirect uri`. One parameter, two endpoints in one flow,
  opposite readings of emptiness - after `state=` being echoed at one and
  dropped at the other. A handler reading the value through `url.Values.Get`
  cannot see any of this, because that call cannot tell absent from empty.
- **The theme page's chrome shows how far the request got, not what it asked
  for.** The restart URL inside `startSessionPolling` carries `client_id=<id>`
  exactly when the rejection happened *after* a client resolved. Two cells break
  the obvious rule: a **bearer-only** client resolves - the 403 could not be
  decided otherwise - and its page names no client and offers no link although
  `master-realm` has a `baseUrl`; and `/logout`'s `id_token_hint` rejection
  names no client even when the request sent a good `client_id`, because the
  hint is judged first.
- **The error page's "Back to Application" link is decided by the client's
  `baseUrl` alone.** An absolute `baseUrl` is used as it is, a relative one is
  resolved against `rootUrl` or against the server's base URL when there is no
  `rootUrl`, and **a client carrying a `rootUrl` and no `baseUrl` gets no link
  at all**. The admin console presents the two together as one "Home URL", so
  concatenating whatever is there is the obvious implementation and it invents a
  link on that fourth row. The link follows the **client**, not the rejection:
  measured as a 2x2, a client with a `baseUrl` gets it on a bad `redirect_uri`
  and on `max_age=abc` alike, one without gets it on neither.
- **The device verification page is the same page at both its paths, action
  included.** `GET /realms/{realm}/device` and
  `GET /realms/{realm}/protocol/openid-connect/auth/device` answer
  byte-identical 4692-byte pages naming `action="/realms/{realm}/device"` -
  relative, and not the path the request arrived on. `serveDeviceCodePage`'s doc
  comment claimed the action echoed the arrival path **and cited it as
  measured**; the code had always built `/device`, so the code was right and the
  sentence above it was wrong.
- **An undecodable request body is a 500 with a JSON body on both browser
  endpoints.** `POST /auth` and `POST /logout` carrying a bad percent escape
  answer 500 `{"error":"unknown_error",...}` with `application/json` and the
  five security headers, and none of `Content-Language`,
  `Content-Security-Policy` or `Cache-Control` - so it is not the page family at
  all. A body that is merely **empty** is the 400 page with `Invalid Request`,
  so the two are separate branches.

- **`search` is two rules and the family decides which.** With a value
  `xabbcx`, `search=*bbc` matches on the **user, group and identity provider**
  listings and answers `[]` on the **role** listing, where `*` is a literal -
  `xa*`, `*abbcx`, `*abb*` and `x*x` all find nothing and the bare `xabbcx`
  does. The rule the first three follow is Keycloak's LIKE: each `*` becomes
  `%`, a trailing `%` is appended when the pattern does not already end in one,
  and `"quotes"` mean equality. That trailing wildcard makes `*bbc` a
  **substring** match rather than a suffix one. Gloak implemented an anchored
  glob until 2026-09-01 and the six probes its doc comment listed are explained
  by **both** readings - `user*` is `user%` either way - so only a pattern whose
  last literal run is neither at the end of the value nor followed by a `*`
  separates them. In `matchesSearch` the rule is carried by the **head being
  anchored and the tail deliberately not**; a `term += "*"` written to express
  it was a no-op whose comment claimed otherwise, and it masked the tail anchor
  from the mutation that should have caught all of this. **The group listing
  still uses `strings.Contains` and is measured wrong on the same probe.**
- **The identity provider `config` and the component `config` use Keycloak's two
  different HashMap constructors, one path segment apart.** An identity
  provider's is `javamap.SizedKeyOrder` - nine measured key sets, all nine
  placed, `KeyOrder` wrong on four including `{clientId, clientSecret}`. A
  component's is `javamap.KeyOrder` - seven measured, six placed,
  `SizedKeyOrder` wrong on two of the six, and a twelve-key LDAP set that
  neither places. A shared serialiser is wrong on one of the two families and
  which one depends on the key count. **No body Gloak serves can tell them apart
  on the component side**: every config a default install has holds nought, one
  or two keys and both functions agree on all of those, so the claim lives in
  `internal/javamap`'s vectors rather than in the serialiser's tests.
- **`briefRepresentation` on the identity provider listing is a six-key shape,
  not the full shape minus a field.** It drops the six tri-state flags,
  `firstBrokerLoginFlowAlias` and `types`, **and empties `config` while keeping
  the key**. Its default here is `false`, the third default this one parameter
  has in this API, and the single read ignores it entirely. The first reading
  was "it drops types", from hand probes on providers that happened to carry
  neither a config nor a flag; **the golden refuted it**, because its fixture
  creates one that carries both. Sending the request nobody thought to send is
  what recording does.
- **An identity provider has six tri-state booleans and one field beside them
  that is not.** `trustEmail`, `storeToken`, `addReadTokenRoleOnCreate`,
  `authenticateByDefault`, `linkOnly` and `hideOnLogin` are **absent** when
  never set and `false` when sent `false`; `displayName` on the same body is
  stored and served as `""`. A plain `bool` collapses two states the wire
  distinguishes, six times over, and `omitempty` on the seventh loses a value
  the server keeps. `organizationId` is a 400 for **any** value including `""`.
- **A `PUT` whose body carries no `alias` answers 204 and strands the row.** The
  alias is cleared, the listing serves the row with no `alias` key, it sorts
  first, and nothing can address it again. The rename guard is
  `Identity Provider alias cannot be changed` and a null alias is not a change,
  so the check passes and the write lands. Keycloak's own defect, reproduced.
  A **present** alias that differs is the 400, so the two halves of that
  sentence need one request each.
- **The `Component` tag is authorised out of the realm role pair.** `view-realm`
  and `manage-realm` read it; `manage-identity-providers` is 403, although the
  rows are key providers and client-registration policies. The identity provider
  family one path segment away takes the other pair and refuses `manage-realm`.
  Two neighbouring chapters, two disjoint role pairs, and the gate is a fifth
  shape - a plain two-role check with the resource resolved **after** it, so a
  `DELETE` of an alias that does not exist is 403 to a viewer and 404 to a
  manager.
- **A created realm has fourteen components and master has fifteen.** The
  fifteenth is `declarative-user-profile`, and it is also the **only component
  with no `name` key at all** - so "the nameless component" and "the component a
  created realm does not get" are one row. One bootstrap list for every realm is
  wrong on master, and a `name` column that cannot be null is wrong on that row.
  Neither the listing's row order nor the `allowed-protocol-mapper-types` array
  inside it is reproducible: two realms created minutes apart on one container
  returned the same fourteen rows in two entirely different orders, matching
  neither insertion, name, id nor provider.
- **A malformed integer bound is a 404 on the identity provider listing and is
  ignored outright on `/components`.** `?first=abc` answers
  `{"error":"HTTP 404 Not Found"}` on the first and 200 with the whole listing
  on the second, where `?first=1&max=2` also returns all fourteen rows - so
  `/components` does not read the bounds at all. Two neighbouring families, one
  input, two answers, measured on one container in one cut. The generic-404
  producer count is unchanged; what is new is that **this behaviour is per
  family rather than per API**, so there is no single answer to import into the
  four listings F134 names.
- **`types` is derived from the provider id and stored nowhere**, with four
  values over seventeen providers: five entries for `oidc` and `keycloak-oidc`,
  `["USER_AUTHENTICATION"]` for `saml`, `["CLIENT_ASSERTION"]` for `kubernetes`,
  and `[]` for the eleven social providers, `oauth2` and
  `jwt-authorization-grant`. A boolean "is it OIDC" gets two of the four wrong.
  Two of those seventeen refuse a bare create for **required config** rather than
  for being unknown - `jwt-authorization-grant` answers `Issuer is required` and
  `oauth2` answers `User Info URL not provided`, both 400, the same status an
  unregistered id gets and a different sentence. `GET /admin/serverinfo` lists
  all seventeen, which is what tells the two cases apart.
- **`GET .../instances/{alias}/export` is a bodyless 204 for everything but a
  SAML provider**, and the SAML body carries a freshly minted `ID="ID_<uuid>"`
  on every request - so that half **cannot be `Recorded`**, whatever else is
  true of it.

- **Two Java collections on one body chain in opposite directions.** A
  resource's `uris` is a `HashSet<String>` and its `attributes` a
  `HashMap<String,List<String>>`, and when their keys share a bucket the uris
  chain in **request** order and the attributes in **reverse** request order.
  Measured with six keys that all hash to bucket 0 - a two-letter string of one
  repeated character has a `hashCode` that is a multiple of 32 - so the bucket
  order says nothing and the chain says everything, and the two fields sit one
  key apart on the same request. `javamap.KeyOrder` sorts before bucketing and
  is therefore exact on any collision-free key set and wrong on both chains;
  both goldens and both package tests use collision-free sets, which is the
  protocol mappers' sidestep applied twice. A resource's `scopes` is a third
  set, keyed on the scope's **name**, and its colliding chain is reproducible
  from nothing on the wire: `aa, bb, zz` came back unchanged and `zz, bb, aa`
  came back `bb, aa, zz`, which is neither direction.
- **One scope has five serialisations and the route decides.**
  `{id, name, iconUri, displayName}` from the scope family's own reads;
  `{id, name, iconUri}` inline in a resource; `{id, name}` from
  `GET .../resource/{id}/scopes`; `{name}` inline in a resource in the settings
  export; and `{name, iconUri, displayName}` from the export's own `scopes`
  array. Measured on one scope carrying an iconUri and a displayName and
  confirmed on a second carrying only a displayName, so the missing keys are
  dropped rather than merely empty. A sixth body on the same surface,
  `GET .../scope/{id}/resources`, serves `{"name":..., "_id":...}` - **the only
  response in this API measured putting a name ahead of an id**.
- **`_id` is the resource's wire name and `id` is refused.** Every other create
  in this API takes `id`; this one answers `Unrecognized field "id"` for it, and
  the same body spells the icon `icon_uri` where the scope family one path
  segment away spells it `iconUri` - and where a resource's own inline copy of a
  scope spells it `iconUri` too. Two spellings of one concept inside one
  response.
- **A resource `PUT` replaces everything except `attributes`.** A body naming
  only the name cleared the type, the displayName, the icon_uri, the uris, the
  scopes and `ownerManagedAccess`, and left the attributes untouched;
  `{"attributes":{}}` cleared them, so the exception is about **absence** and not
  about the field. That is the third variation of "`PUT` replaces / `PUT` merges
  - except for one field", and the first pointing this way: the verb replaces
  and one field merges. The other two are a role's `PUT`, which replaces
  outright, and a client's, whose one exception is `authorizationServicesEnabled`.
- **Two 404s on one resource, one path segment apart, and neither is the scope
  family's.** `GET`, `PUT` and `DELETE .../resource/{unknown}` answer
  `{"error":"HTTP 404 Not Found"}` with `application/json` and **no
  `Cache-Control`**; `.../resource/{unknown}/attributes`, `/permissions` and
  `/scopes` answer an **empty body with `Cache-Control: no-cache`**. The scope
  family's single read answers its own missing scope the second way, so the two
  families invert each other and the resource family inverts itself. The JSON one
  is a **fifth producer** of the generic 404 body, after an unmatched path, a
  wrong verb, a switched-off resource and an unparseable integer bound - and the
  first that is an ordinary missing row.
- **`POST` and `PUT` on one resource disagree about a body that is not there.**
  An empty request body and a literal `null` are a **400 with an empty body** on
  the create and a **500 `unknown_error`** on the update. The scope family
  answers the create's bytes with the update's status, so three writes on one
  resource server give two answers split along no line either family shares.
- **A resource create is an upsert on `_id` and a scope create is an upsert on
  the name.** Two resource creates naming one `_id` leave one row holding the
  second body; two naming one **name** are a 409. On the scope family it is the
  other way round. Reusing either family's upsert helper is wrong in both
  directions at once.
- **A policy needs a name *and* a type**, and missing either is
  `409 Duplicate resource error`. This file and F129 both said `type` was the
  gate, from a probe set that left the type out and never left the name out;
  `{"type":"role"}` with no name is the same 409. The rest of the bullet below
  was re-measured and holds. The accepted set is not
  the provider catalogue.** `POST .../policy` and `POST .../permission` answer a
  body with no `type` with `409 Duplicate resource error`, and accept
  `regex role resource scope client time group aggregate uma` - nine. `uma` is
  accepted and is **absent** from `GET .../policy/providers`; `user` and
  `client-scope` are in that catalogue and answer a **500**. Validating against
  the catalogue this repository already ships would refuse one working type and
  admit two that fail.
- **`GET .../authz/resource-server`'s three arrays really are always empty.** The
  first cut measured it against a resource server holding four scopes; it was
  re-measured against one holding seven resources and thirty-three policies and
  still answered `"resources":[],"policies":[],"scopes":[]`, while the settings
  export beside it populates all three. This is the one claim in the family that
  a bigger sample **confirmed** rather than refuted, which is worth recording
  because most single-measurement claims here have not survived one.
- **A theme page names the realm three times, and the two display fields fall
  back through different chains.** Measured over twelve realms on 2026-09-02:

  ```
  title  =  displayName      or  realm name
  brand  =  displayNameHtml  or  displayName  or  realm name
  ```

  **The brand's chain is one rung longer**, and the realm that separates the two
  readings is one carrying a `displayName` and no `displayNameHtml` - its brand
  names the display name, not the realm. This bullet said "falls back to the
  realm **name** in both" until 2026-09-02, which is what a realm carrying
  *neither* answers: the rule was written from the one realm that could not tell
  the two chains apart. An empty string counts as absent and whitespace does not
  (`""` gives the realm name, `"  "` gives two spaces).
  The `<div class="kc-logo-text"><span>` wrapper is `displayNameHtml`'s **own
  markup**, not the template's, so it disappears with the value rather than
  wrapping whatever replaces it. Master's two values are `Keycloak` and that
  wrapper, which is why serving them as constants looks right: it is right on the
  one realm every conformance case used to address.
  **One page spells a double quote two ways, eight lines apart.** The title is
  Freemarker's escaping (`&quot;`) and the brand is a jsoup sanitiser's raw
  output (`&#34;`), so `html.EscapeString` is correct for one and wrong for the
  other. Keycloak **sanitises** the raw branch and Gloak does not - measured,
  `<b onclick="x">Bold</b>` comes back `<b>Bold</b>` - which is a filed
  divergence rather than a simplification: master's value passes through
  unchanged and a created realm has none.
- **A refresh token's introspection body enumerates a realm-wide set.** `aud` and
  `resource_access` name every admin container the subject holds roles on, and
  the bootstrapped administrator holds `create-realm`, so **every realm any
  fixture creates adds a key**. `oidc/introspection/active-refresh-token` was
  clean for a month only because every realm-creating fixture happened to live in
  `adminCases` and run after it; ordering cannot carry that, and the case carries
  `PristineRealm` now.

- **The nine policy types have eight representations and one storage.** One
  config carrying every provider's keys at once was sent to all nine types: the
  generic view came back **byte-identical on all nine** and the typed view
  served exactly the keys the type owns - `resource` and `scope` sharing one
  shape and the other seven each having their own. `resourceType` is not a
  shared base field on the read: a `role` policy carrying `defaultResourceType`
  serves it in the generic view and does not project it. So the provider model
  this family needs is **a table over one stored map, not nine structures**, and
  `uma`'s `scopes` is the one projected field that does not come from the config
  - it is read from the association set, always present, and served **by name**
  where the create that set it echoed the id.
- **A policy create's 201 is the request echoed and its read is not**, which is
  the opposite of the resource create two path segments away. The config comes
  back exactly as sent, where the read has role names resolved to uuids and
  `required` filled in; `owner` and `resourceType` are echoed and no read serves
  either; and a `role` create with no config answers `config:{}` where its own
  read answers `{"roles":"[]"}`, because the provider's key is written after the
  response representation is built.
- **Three providers resolve a reference and all three answer an unknown one
  differently.** An unknown role in `config.roles` is silently dropped, an
  unknown group path in `config.groups` is silently dropped, and an unknown
  clientId in `config.clients` is a **500**. A shared resolver is wrong on one of
  the three whichever answer it picks. Three keys inside `config` are also not
  config at all: `applyPolicies`, `resources` and `scopes` are consumed into the
  association sets and vanish from the stored config on every type, where an
  unknown target is a 500 for all three - including `scopes`, which the body's
  own top-level `scopes` array answers with a bare `400 {"error":"unknown_error"}`
  carrying no description.
- **`GET .../settings` and `GET .../permission` partition the same rows
  differently.** The listing counts `resource`, `scope` and `uma` as permissions;
  the export moves `resource` and `scope` to the end of its `policies` array and
  leaves `uma` among the policies. A shared predicate is wrong on `uma` in one of
  the two places - the fifth time this API has had a rule that is right on one
  family and inverted on its neighbour. The export also **denormalises**: uuids
  go back to names, clients to clientIds, groups to paths, and the three
  association sets are synthesised back into `applyPolicies`, `resources` and
  `scopes`, so a policy whose live read answers `config:{}` exports a config with
  three keys in it.
- **A null enum is a third state.** `{"logic":null}` is a 201 and the row reads
  back with **no `logic` key at all** on the listing, the search and the typed
  view alike, where an absent `logic` gets `POSITIVE`. A plain string field with
  a default is right on one of the two and cannot express the other. And
  `CONSENSUS` is a 201 on `POST .../policy` and a **500** on
  `PUT .../authz/resource-server` - one enum value, two endpoints on one
  resource server, so the two accepted lists are two lists.
- **A policy's `config` is placed by `javamap.SizedKeyOrder` sized on what is
  *stored*, and that is the opposite of the protocol mappers.** A six-key config
  sent to a `role` policy - which adds `roles`, making seven - came back in the
  seven-key order, byte for byte the same as a `uma` policy sent all seven
  outright. The protocol-mapper bullet in this file says a config the create grew
  "was built for the request's key count and serialised at a larger one"; that
  remains true of protocol mappers and **does not generalise**. Two families, two
  answers, and neither can be read off the other.
- **Three families on one resource server, three upsert rules.** The scope create
  upserts on the **name**, the resource create on the **`_id`**, and the policy
  create on **neither** - a repeat of either is a 409. A policy id is global the
  way a resource id is, and the losing create does the other resource server no
  damage.
- **`POST .../import` is strict where the two creates beside it are not.** The
  same unknown field is `400 Invalid json representation for
  ResourceServerRepresentation` there and a 500 `Cannot parse the JSON` on
  `POST .../policy`, on one resource server. It **deletes nothing**, resets the
  three settings to the representation's own initialisers and then overwrites
  what the body names, and a name it already holds it **merges into** rather than
  replaces - a `regex` body imported over a `role` policy left the type alone and
  grew the config.

## Boundaries

| Package | Owns | Must not |
|---|---|---|
| `internal/model` | domain types | depend on anything in the project |
| `internal/store` | repository interfaces, `ErrNotFound`, `ErrConflict` | know about SQL dialects |
| `internal/store/sqlite`, `internal/store/postgres` | the two drivers | diverge from each other in behaviour |
| `internal/keys` | realm signing keys, JWKS | publish the HMAC key or any private key |
| `internal/httpx` | **all** response body formatting | know anything domain-specific |
| `internal/javamap` | Keycloak's JSON key order for a Java map | know what the keys mean |
| `internal/roles` | expanding a user's roles through composites | write anything, or decide who may do what |
| `internal/oidc` | protocol handlers | know about SQL; it sees only `store` interfaces |
| `internal/bootstrap` | creating the `master` realm | modify objects that already exist |
| `cmd/gloak` | config, wiring, serving | contain logic worth testing on its own |
| `internal/conformance` | the documentation-derived catalogue and golden comparison | be imported by production code, or know about SQL or handler internals; it sees only an `http.Handler` |

Two of these have already been violated once and repaired, so they are worth
restating:

- **`internal/httpx` is the only place a response body is marshalled.** A second
  JSON writer appeared in the router, diverged on the trailing newline, and made
  success bodies differ from Keycloak by one byte with no test noticing.
- **The two store drivers must behave identically.** A retry loop added to the
  Postgres `Open` to work around a test-environment race made it mask an unreachable
  server for ten seconds while SQLite failed fast. Test-environment problems get
  fixed in the test.

## Response bodies

Marshal from structs with fields declared in Keycloak's order, never from
`map[string]any`. Go emits map keys alphabetically, which silently reorders every
key in the response, and tests that parse JSON will not see it.

The discovery document's order comes from
`internal/oidc/testdata/discovery-26.7.1.json`, which preserves what Keycloak sent.

## Build and test

```bash
make test    # CGO_ENABLED=0 go test ./...
make lint
make build
make oracle  # drives Gloak with kcadm.sh; needs Docker
```

- `make test` is clean. **Any** failure is a real regression. It was not always so:
  `TestConformance/oidc/certs/master` was allowed to fail until realm keys were
  modelled and persisted (follow-up F5), which P1 did. No case is exempt now, and
  adding an exemption means changing this line first.
- `go test ./...` must never require Docker or network access. Anything that does
  goes behind the `docker` build tag.
- `CGO_ENABLED=0 go build ./...` must work. SQLite is `modernc.org/sqlite` to keep
  the binary a single static file; do not swap in a cgo driver.
- The Postgres suite (`go test -tags docker ./internal/store/postgres/`) is the only
  evidence the drivers agree. Run it after touching either.
- **`make oracle` is the only test that is not written against a golden.** It
  runs Keycloak's own `kcadm.sh` against Gloak, so it asks for things no case
  asks for. It found `ClientRepresentation.description` - a field Gloak did not
  have, because none of the six bootstrapped clients carries one and so no
  recording ever showed it. Run it after touching a representation.
- Adding a store interface method means implementing it in **both** drivers. The
  conformance suite in `internal/store/storetest` does not exercise every method, so
  compiling is not proof.
- **`make record` runs two container regimes and the catalogue decides which.**
  Almost every case is recorded against one shared Keycloak in catalogue order,
  which is why a whole run costs one container start and not three hundred. A
  `PristineRealm` case gets a container of its own, started inside its subtest
  and terminated with it, because its body is a function of the whole realm and
  the verifier will serve it from a handler that has seen nothing but that
  case's own fixture. Two minutes for a whole run instead of thirty seconds;
  budget minutes rather than seconds when other containers are alive.
  **The tests open SQLite with `synchronous(off)`.** Not a tuning knob: with the
  default, a bootstrap's hundreds of writes each wait on `fsync`, and on
  2026-08-31 CI spent thirty minutes inside `libc.Xfsync` and was killed there,
  having reported the same tree green twice before. A throwaway database in
  `t.TempDir()` has nothing to be durable against. `go test` also carries an
  explicit `-timeout`, which is a backstop and not the fix - Go's default is per
  package, and a package-level timeout reads as a failed assertion, which is how
  this was misread twice.
- **Recording pristine cases *first* was the previous answer and it does not
  hold.** The pristine group pollutes itself: `admin/groups/list` creates a
  group, `admin/groups/count` counts the realm three cases later, and that
  case's number is masked to this day because the recorder said 3 where a
  pristine replay says 2 - and its number **was masked for exactly that** until
  F47, when the per-case container made the count deterministic and the
  measurement came back. **Ordering also cannot be checked afterwards** -
  `admin/users/count`'s entire body is the byte `1`, and no guard **that reads
  the recorded bytes** can tell a polluted count from a clean one. So the
  container is what resets, not the position. See F40. (The qualifier is
  load-bearing and was added on 2026-08-30: re-*serving* a case against a
  polluted realm does tell the two apart, because the answer moves. That route
  was tried and rejected on a different ground - the fixtures are deliberately
  not replayable - and the reason lives in F53, not in the word "no".)
- **A golden that holds only while the catalogue's order holds is worse than no
  golden**, because it looks like a measurement. That is why F40 was fixed in
  the recorder rather than by marking one case and re-recording: marking alone
  produces the right bytes today purely because none of the eight pristine
  fixtures happens to create a realm role.
- **`TestPristineRealmGoldensAreNotPolluted` watches four resource families**,
  read out of the creation bodies themselves: clients by `clientId`, users by
  `username`, realms by `realm`, roles and groups both by `name`. A fixture
  creating a fifth kind of object named by some other key is invisible to it
  until that key joins `createdKeys`. It watched `clientId` alone until
  2026-08-29, which is exactly how F40 got past it. Two things it reads that are
  easy to drop: a **case's own request** creates objects too - `admin/roles/create`
  POSTs `{"name":"gloak-probe-role-create"}` and that role is in the realm for
  everything recorded after it - and a POST whose body is a JSON **array** is
  not a creation, or the role-mapping writes would put six bootstrapped admin
  role names into the guard's set.
- **The pollution guard now reads every golden, not the ten pristine ones.**
  `TestNoGoldenHoldsAnObjectItDidNotCreate` applies the same check to the rest
  of the catalogue, because the invariant was never the pristine group's: a
  golden may hold only what bootstrap, the case's own fixture and its own
  request produced, since those three are exactly what the verifier reproduces.
  It is a ratchet rather than a finder - every committed golden passes it today -
  and it fires one step earlier than `TestConformance`, on the re-record that
  first pollutes a golden rather than on the run that then cannot reproduce it.
- **`PristineRealm` cannot be derived, and two measurements say so.** The
  request shape does not determine it: `GET /admin/realms/master/clients` with
  no query is realm-wide for an administrator and measured `[]` both before and
  after pollution for a `query-clients` caller. And replaying every case against
  a realm every fixture has touched does not work, because fixtures are
  deliberately not idempotent - `idempotentCreate` exists for the creates that
  may repeat, and the ones capturing a `Location` may not - so putting all of
  them on one handler produced 22 failures, nine in the pollution pass itself,
  and none of them order-dependence. The flag stays a declaration and the sweep
  that checks it is a person reading the catalogue. See F53.
- **The catalogue could not tell a realm-derived value from the literal
  `master`, and the fix was cases rather than machinery.** Sixty goldens carry
  the realm name of their request in the response and **fifty-eight address
  master**, so a handler answering with the literal compared equal to one
  deriving it. Found by a mutation that hard-coded `master` into the theme
  page's restart URL and passed all 352 served cases. What F142 costed as
  "a second realm in the harness" was **already built**: `realmFixture` has
  created realms through `POST /admin/realms` since P4 and sixty-six cases
  address one - the blind spot was that all sixty-six were on the Admin API, and
  `internal/oidc`'s own tests build nothing but `bootstrap.EnsureMaster`.
  `Case.SecondRealm` marks a case that re-measures a covered behaviour against
  another realm and is kept **out of the parity denominator**, because a
  protocol chapter counts cases and counting a re-measurement would report
  diligence as coverage. It follows F53 rather than overturning it - it is a
  declaration, not a derivation, since `oidc/discovery/unknown-realm` addresses
  `nosuchrealm` and *is* a distinct behaviour that belongs in the denominator -
  but unlike `PristineRealm` both halves are checked, so the declaration can
  fail: the realm must be one the case's own fixture creates, and the golden's
  response must carry that name and never `master`. A second-realm case whose
  golden pins nothing realm-derived is the harness equivalent of a mask that
  changes nothing. **Twenty derivation sites exist, eighteen were master-only,
  four are pinned now, and three of the rest are measured survivors** -
  `registrationURI`, the device grant's `verification_uri` and `/auth`'s
  error-redirect `iss` each take a hard-coded `master` with the whole tree
  green. See F142.
- **`make record` leaves a `Pending` golden exactly as it found it.**
  `TestConformance` skips a Pending case whether or not a golden exists, so
  nothing compares one, and rewriting it can only add noise to the diff this
  project asks people to read carefully. Four login-theme pages did that on
  every run, and the count went from three to four inside two days - added by
  the cut that filed the follow-up. `GoldenIsAsserted` in `case.go` is the one
  predicate the recorder and the verifier both read, so the two cannot drift.
  **The way to ask for a Pending golden back is to promote the case to
  `Recorded`**, which is what `Recorded` already means and which a reviewer sees
  in the diff; there is no flag.
  **One Pending golden is parked**, counted from `parkedGoldens` rather than
  incremented, and it is declared there with the reason it is kept.
  `TestEveryParkedGoldenIsDeclared` refuses one arriving without a declaration,
  a declaration whose file has gone, and one whose case is no longer `Pending`.
  (This bullet said nine, seven and eight **in one paragraph** until 2026-09-01,
  because each cut that moved the number edited a different sentence of it. A
  count written in prose beside the list it counts will do that; the list is the
  answer.) Seven of the eight went on 2026-09-01 when P13 served the theme's
  markup, and the reason they could go is worth keeping: **seven of them carried
  exactly one per-request value between them and a contract**, the
  `/resources/<version>/` segment, which one unconditional substitution pass
  makes comparable. The judgement that had kept them parked was made from the
  diff of `prompt-create`, the one page that carries more, and generalised to the
  rest. A

  parked golden is a **measurement, not a contract**: read it for what Keycloak
  answered, never for what Gloak must serve. See F72.
  **`Recorded` is the hole this leaves, and it was walked through.**
  `GoldenIsAsserted` returns true for a `Recorded` case, so the recorder
  maintains its golden - and four theme pages promoted to `Recorded` on
  2026-08-30 churned on every run again, found independently by three later
  cuts and by nobody's test, because a `Recorded` case is required *not* to
  match. They are parked now. **A page carrying a per-request value cannot be
  `Recorded`**, whatever else is true of it, because `Recorded` is a promise the
  recorder has to be able to keep.
- **Every object a fixture or a case creates is named `gloak-probe-*`, and
  `TestEveryCreatedObjectCarriesTheProbePrefix` is what says so.** Six goldens'
  windows rest on that convention and nothing enforced it:
  `admin/roles/list-realm-page-no-search` sends `first=1&max=2` and holds
  `create-realm` and `default-roles-master` only because no probe role sorts
  before them. Seven objects are outside the convention and each is declared in
  `namedOutsideTheConvention` with the reason it stands - including three group
  names whose sort positions **are** `admin/groups/search-pages-the-matches`'s
  measurement, so renaming them would change a measurement. An entry that stops
  matching anything fails too.
- **The pollution guard reads one object per JSON *object*, not per body.** A
  create can carry objects nested inside it - `POST /clients` with
  `{"clientId":"...","protocolMappers":[{"name":"..."}]}` creates a client *and*
  two mappers, and they outlive the request the same way. Applied per body the
  client's `clientId` won and the nested mappers were never recorded, which both
  lost them from the guard and made it report a false positive on the case whose
  own fixture created them, since the exemption reads the same set. Two cuts
  landed green alone and failed together on exactly that. A body that does not
  parse and an empty name are skipped on purpose: both are measured creates that
  create nothing.
- **A case can send one query key twice.** `Request.RawQuery` is the query
  string verbatim, which is the only way to express the authorization
  endpoint's `duplicated parameter`. It replaces `Query` rather than adding to
  it, and it is **not** expanded - `Expand` rewrites `Path`, `Query`, `Headers`,
  `Form` and `Body` and does not reach it, so `TestCatalogIsWellFormed` refuses
  a `{{name}}` inside one rather than letting the braces reach the server.
- **CI runs `build`, `vet` and `CGO_ENABLED=0 go test ./...` on every pull
  request, and nothing behind the `docker` tag.** `vet` runs twice, plain and
  `-tags docker`, so the three tagged files still compile; nothing runs them.
  `make lint` runs both invocations too, so the local target and the gate are
  the same check. They were not until 2026-08-29, and a contributor who ran
  `make lint` and got silence could still be broken by CI.
  **Both also check `gofmt`, because nothing else in this gate does.** `vet` is
  a correctness tool and says nothing about layout, so three files reached
  `main` unformatted on 2026-08-30 - found by somebody reading a diff, since no
  step existed that could have caught it. `gofmt -l` exits 0 whatever it prints,
  so its output is turned into a failure by hand in both places.
  A green run does not mean the two store drivers agree: that evidence still
  comes only from running the
  Postgres suite by hand. The comment is posted with the job's own token, and a
  failure to post fails the job - with one exception: a 403 **on a pull request
  from a fork**, whose token is read-only whatever the workflow's `permissions`
  block says. That case falls back to the run summary and passes. The fork is
  read from `github.event.pull_request.head.repo.fork` and not inferred from the
  error text: a rate limit and a revoked permission are also 403s, they are this
  repository's own problem, and they go red.
  CI also posts the pull request's parity increment
  and fails when the total falls. A deliberate fall is declared with a
  `Parity-decrease: <reason>` line in the pull request description - the
  marker must be the first non-whitespace content on its own line (leading
  whitespace is fine, case does not matter, and a mid-line mention does not
  count), so a markdown bullet such as `- Parity-decrease: <reason>` does not
  match either and the gate stays shut. With several such lines, only the
  first is used. **The pull request that introduces this workflow fails its
  parity step, and that is correct**: its merge base predates the report mode,
  so the base meter writes nothing and `cmd/parity` exits 2 with
  `parity: open .../parity-base.tsv: no such file or directory`. There is no
  base to compare against. Every later pull request has one.
- **The comparison is reproducible by hand.** `GLOAK_PARITY_REPORT=<path>`
  makes the meter write its tally to that path as tab-separated values, on top
  of printing it as usual; unset, nothing changes. It is a transient artifact
  and never committed. Two of them and `cmd/parity` are the whole of what CI
  does:

  ```bash
  GLOAK_PARITY_REPORT=/tmp/head.tsv \
    CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1
  git worktree add /tmp/base "$(git merge-base main HEAD)"
  ( cd /tmp/base && GLOAK_PARITY_REPORT=/tmp/base.tsv \
      CGO_ENABLED=0 go test ./internal/conformance/ -run '^TestCoverage$' -count=1 )
  git worktree remove /tmp/base
  go build -o /tmp/parity ./cmd/parity && /tmp/parity /tmp/base.tsv /tmp/head.tsv
  ```

  Built rather than `go run`: `go run` collapses any exit code above 1 down to
  1, which would make a real parity decrease (exit 1) indistinguishable from
  the report `cmd/parity` could not read (exit 2) - the exact failure the
  previous paragraph describes.

  `-run` takes an unanchored regex, so the anchors are not decoration: a bare
  `TestCoverage` also selects `TestCoverageWritesAReportWhenAsked`, which
  re-runs the meter and prints the whole table a second time. `-run` also splits
  its pattern on `/`, so a regex group containing a slash is destroyed and
  matches nothing - which rules out selecting several cases by ID in one
  invocation.
- **A flat parity total is not the same claim as "no change".** Four chapters
  have no denominator and are left out of the total, so behaviour served in one
  of them moves a row and cannot move the total. The comment says
  `total unchanged` and names the reason for those, and reserves `no change` for
  a diff where nothing moved at all. `internal/parity`'s tests pin all three
  shapes.

## Where a new case can come from

Three sources, in order of how much they cost:

1. **The vendored OpenAPI description.** It says which operations exist. It
   never says what one answers.
2. **A live 26.7.1.** Every expected value comes from here. This is the rule
   at the top of this file.
3. **Keycloak's own test suite.** `make kcsrc` materialises a sparse checkout
   at the pinned tag under `.kc-testsuite/` - `tests/`, `test-framework/`, and,
   because sparse cone mode always includes them, the repository's root files
   too. Nothing makes it read-only; that is a discipline, and the rule it
   serves is "Nothing is copied out of `.kc-testsuite/`" below.
   Its 2490 test methods are claims somebody upstream
   thought worth guarding; the ones about surface Gloak already serves are
   cases this catalogue may be missing.

A mined case goes: read the upstream assertion, measure the same thing against
a live 26.7.1, then add the `Case` under the status the measurement earns. One
Gloak does not serve yet goes in as `Recorded` with a `Reason`, and it is
`make test`'s `TestConformance` failing with "already matches" that tells you
to promote it to `Implemented`; one Gloak already serves goes in as
`Implemented` directly, with no `Reason`.

Those last two are separate rules enforced in separate places, not one rule
and its consequence. An `Implemented` case must carry no `Reason`
(`catalog_test.go`). A `Recorded` case that matches its golden is a hard
failure (`conformance_test.go`, and `case.go`'s `Recorded` doc comment says
why). Neither follows from the other; you can break either on its own.

Cite the upstream file and test method in `Case.Doc.Section`. Nothing is
copied out of `.kc-testsuite/`: upstream is Apache-2.0 and this repository
carries no upstream source.

**Most mined cases pass on the first run, and that is the expected outcome.**
An already-correct behaviour with a golden under it is one the next refactor
cannot break silently. The ones that fail are the finds: `first` and `max` on
the role listings were accepted and ignored until
`RealmRolesSearchTest.testPaginationRoles` was read.

Do not mine `testsuite/`. `testsuite/DEPRECATED.md` freezes it, and
`make kcsrc` does not check it out.

## Conventions

- Commit messages `type(scope): subject`, types limited to `feat`, `fix`, `docs`,
  `test`, `refactor`, `perf`, `chore`. `test` was in use long before it was
  listed - counted across the 144 conventional commits behind this line, `feat`
  59, `docs` 47, `fix` 27, `test` 7, `chore` 3, `refactor` 1, `perf` 0, so it
  outranks three types the list already allowed and `perf` has never been used
  at all. The list was wrong, not the commits; none were rewritten.
- Never commit to `main`. Branch names carry their work type: `feat/`, `fix/`,
  `refactor/`, `docs/`, `chore/`.
- Code comments in English.
- Prefer the smallest diff that does the job, and preserve existing names.
- Environment variables use the `GLOAK_` prefix, never `KC_`.
- Secrets never arrive by command-line flag; argv is readable by any process.

## Before claiming something works

Run it. The measured contract makes this project unusually easy to satisfy on paper
and fail in practice: tests that parse JSON pass while byte order is wrong, tests on
in-memory SQLite pass while the file-backed path is broken, and a driver method that
compiles can still return the wrong rows.

Known gaps are in `docs/superpowers/specs/2026-08-18-gloak-followups.md`. Each was
reproduced, not theorised. Read it before concluding you have found something new.
