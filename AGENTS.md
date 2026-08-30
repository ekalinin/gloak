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
- **`GET /realms/{realm}` sends `Content-Type: application/json;charset=UTF-8` on
  its 200, and plain `application/json` on its own 404.** Every other endpoint
  measured so far, success or error, sends plain `application/json`. The
  inconsistency is real and it is only on this one endpoint.
- **A wrong method on a known path returns 404, not 405, with no `Allow`
  header.** Gloak once invented a 405 that does not exist; Keycloak answers with
  the same generic 404 it uses for everything else it cannot route. The two 404s
  are not the same body, though: an unmatched path answers `{"error":"Unable to
  find matching target resource method"}`, a wrong method on a known path
  answers `{"error":"HTTP 404 Not Found"}`. That is why `withKeycloakFallbacks`
  still tells the two cases apart even though both return the same status.
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
- **The five security headers have three exceptions, not one.** A route match
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
- **That rule was wrong once already.** P2's Task 11 recorded it as "a
  successful `DELETE`'s 204 omits it", from four deletes that all happened to
  send no `Content-Type`. When a new 204 disagrees with a header rule, measure
  the request's headers before believing the method.
- **`Cache-Control` on a 204 does not follow the method.** Four of the five
  measured deletes carry `no-cache` and `DELETE .../client-secret/rotated`
  does not. It is pinned per endpoint.
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
- **`attributes` key order is the one thing the conformance suite does not
  compare.** It is a Java `Map` in hash order and Go sorts map keys; matching it
  would mean emulating `java.util.HashMap` in Go. `Case.UnorderedKeys` sorts
  both sides, so membership and values are still asserted. This is the only
  such retreat - do not add a second without writing down why. Not every Java
  map in this API needs it: a protocol mapper's `config` is one and its key
  order is reproduced exactly, asserted by `admin/client-scopes/list` since
  2026-08-30.
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
  confirmed against six measured key sets - four in its own tests; the
  `clientMappings` of a combined role-mapping view, where six clients created
  and assigned `cx1..cx6` came back `cx6, cx5, cx2, cx1, cx4, cx3` and
  `internal/admin` pins it; and the `active` map of
  `GET /admin/realms/{realm}/keys`, `RSA-OAEP, HS512, RS256, AES` on both
  master and a created realm, which is the first confirmed vector with **no**
  bucket collision at all. It cannot resolve a bucket
  collision, because those chain in insertion order and nothing observable says
  what that was; the 21 admin role names collide twice and come back the other
  way round. Sorting instead is what makes `resource_access` come out
  `account, master-realm` where Keycloak says `master-realm, account`.
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
- **`PUT` on a role replaces; `PUT` on a client or a user merges.** A role
  updated with a body carrying only `name` loses its description. A role can
  also be renamed through it, where a username cannot. Copying `updateClient`'s
  shape into `updateRealmRole` is the mistake this warns about.
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
- **Fourteen spellings of not-found in the admin API now**, including four for
  one resource and three for a missing group. Counted from the list, not
  incremented: (1) `Could not find client`, (2) `Client not found`,
  (3) `User not found`, (4) `Realm not found.` with its full stop,
  (5) `Credential not found`, (6) `Could not find role`, (7) `Role not found`,
  (8) `Could not find role with id`, (9) `Could not find composite role`,
  (10) `Could not find group by id`, (11) `Group not found` for that same
  missing group from the membership route **and** from the default-groups
  writes, (12) `Group path does not exist` from `group-by-path`,
  (13) `Could not find client scope` from `/client-scopes/{id}`, and
  (14) `Client scope not found` for that same missing scope from the two
  default-scope families. One missing group, three answers; one missing client
  scope, two; each decided by which route went looking.
  (This count said nine while the list held eleven, so it is now written with
  the list numbered and is re-counted rather than incremented whenever it
  moves.) `Could not find client` and `Client not found` are the
  same resource by the same key: the role-mapping routes answer the second for
  an unknown client UUID where the client and role endpoints answer the first
  for that very UUID. The qualifier matters: the protocol side spells a
  fifteenth, `Realm does not exist` (`internal/oidc/router.go:145`), against the
  admin API's `Realm not found.` for the same missing realm - which is written
  once, in `writeRealmNotFound`, because it was written twice and a measured
  string in two places can drift.

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

- **A create's `Location` ends in the new object's id on four routes out of
  seven.** `POST .../clients`, `.../users`, `.../groups` and
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
- **The body's `id` wins on create**, on `POST /client-scopes` and on
  `POST /clients` alike: a create naming an id produced an object with exactly
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
  exactly this reason, and there are **three** values, not two:

  ```
  GET  /auth                        400 and 403 pages   no Cache-Control at all
  GET  /logout                      400 page            no-cache
  POST /login-actions/authenticate  400 pages           no-store, must-revalidate, max-age=0
  ```

  Three endpoints that look like one endpoint three times.
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
- **A repeated parameter is an error at `/auth` and at neither of its
  neighbours.** `/logout` takes the first value and so does
  `/login-actions/authenticate` - `zz` twice, `tab_id` twice, even
  `session_code` twice with the second value garbage all log in. `/auth` is the
  odd one of the three, not the rule.
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
- **Recording pristine cases *first* was the previous answer and it does not
  hold.** The pristine group pollutes itself: `admin/groups/list` creates a
  group, `admin/groups/count` counts the realm three cases later, and that
  case's number is masked to this day because the recorder said 3 where a
  pristine replay says 2. **Ordering also cannot be checked afterwards** -
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
  **Seven Pending goldens are parked, not four.** The four login-theme pages are
  the ones that churned; the device, CIBA and dynamic-registration refusals are
  three more that had been parked without anybody counting them. All seven are
  declared in `parkedGoldens` with the reason each is kept, and
  `TestEveryParkedGoldenIsDeclared` refuses an eighth arriving without one, a
  declaration whose file has gone, and one whose case is no longer `Pending`. A
  parked golden is a **measurement, not a contract**: read it for what Keycloak
  answered, never for what Gloak must serve. See F72.
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
