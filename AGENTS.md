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
- **That rule is measured too broad, three times now.** On the role-mapping
  paths `PUT` and `PATCH` answer a real 405 while `POST` and `DELETE` answer the
  404 above - same path, four verbs, two statuses. `/admin/realms` answers
  `DELETE` with a 405, refuting "the verb decides". And on
  `/realms/{realm}/protocol/openid-connect/auth`, `PUT`, `DELETE` and `PATCH`
  all answer a real 405 with `application/json`, while `HEAD` answers 200 and
  `OPTIONS` answers 200 with `Allow: HEAD, POST, GET, OPTIONS`. Gloak sends 404
  to all of them. **Three data points that disagree still do not say what the
  rule is**, which is exactly why nothing has been changed on the strength of
  any of them. See F31 before adding a 405 or defending the 404.
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
  such retreat - do not add a second without writing down why.
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
  sorted and not insertion order. `internal/javamap` reproduces it and is
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
  operations: both `available` reads, both role-mapping write pairs, and
  `POST .../composites`. The reads are what surprises: they answer **200 with a
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
- **Twelve spellings of not-found in the admin API now**, including four for
  one resource and three for a missing group:
  `Could not find client`, `Client not found`, `User not found`,
  `Realm not found.` with its full stop, `Credential not found`,
  `Could not find role`, `Role not found`, `Could not find role with id`,
  `Could not find composite role`, `Could not find group by id`,
  `Group not found` for that same missing group from the membership route **and
  from the default-groups writes**, and `Group path does not exist` from
  `group-by-path`. One missing group, three answers, decided by which route went
  looking.
  (This count said nine while the list held eleven; the two group spellings
  were added without it. It is at twelve because `group-by-path` added a third
  group spelling on 2026-08-29 - so the count has now been wrong once and is
  checked against the list rather than incremented.) `Could not find client` and `Client not found` are the
  same resource by the same key: the role-mapping routes answer the second for
  an unknown client UUID where the client and role endpoints answer the first
  for that very UUID. The qualifier matters: the protocol side spells a
  thirteenth, `Realm does not exist` (`internal/oidc/router.go:145`), against the
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
- **Logout without an `id_token_hint` does not redirect.** It serves the theme's
  `Logging out` confirmation page, 200, whatever the `post_logout_redirect_uri`
  is. Its successful redirect carries `state` and nothing else - no `iss`,
  where `/auth`'s redirect carries one - and `Cache-Control: no-cache`, where
  `/auth` sends `no-store, must-revalidate, max-age=0`.
- **`post.logout.redirect.uris` is a separate client attribute.** A client whose
  `redirect_uri` validates at the authorization endpoint is still refused at the
  logout endpoint until it is set.
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
  `admin/users/count`'s entire body is the byte `1`, and no guard can tell a
  polluted count from a clean one. So the container is what resets, not the
  position. See F40.
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
