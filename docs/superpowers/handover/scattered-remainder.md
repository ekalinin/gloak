# The scattered remainder of Clients, Users and Realms Admin

The twenty-seven operations under those three tags that nothing in the catalogue
served. They are not a chapter; they are thirteen unrelated groups that happen to
be what is left. The plan is
`docs/superpowers/plans/2026-09-05-scattered-remainder.md`, whose first section
is one row per group and whether this cut took it.

The list was recomputed rather than inherited: the set difference between each
tag's operations in `internal/conformance/testdata/openapi/keycloak-26.7.1.json`
and the `Operation` fields of `catalog_admin.go` is exactly the twenty-seven, and
`internal/conformance`'s coverage meter agreed at 20/34, 28/35 and 39/45 before
this cut.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1` on
:8174, whose `GET /admin/serverinfo` reported `26.7.1` before anything was
believed.

## 1. Measurements

### 1.1 `users-management-permissions` is `client-types`' gate, cell for cell

Both verbs answer

```
501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
```

with plain `application/json` and no `Cache-Control`, byte for byte what
`client-types` and the twelve `management/permissions` routes answer. Four cells,
each with a control that differs:

| request | answer |
|---|---|
| no token | 401 `HTTP 401 Unauthorized` |
| admin token, realm `nosuch` | 404 `Realm not found.` |
| a caller holding **no** admin role | **501**, not 403 |
| that same caller on `GET .../keys` | 403 |

So the order is authenticate, resolve the realm, refuse - authorization never
runs. It is `guardRealmFeature` unchanged. `ADMIN_FINE_GRAINED_AUTHZ` is the
deprecated, disabled feature behind it and `ADMIN_FINE_GRAINED_AUTHZ_V2` being
enabled does not open it, which `internal/admin/managementpermissions.go`
already records for the twelve.

### 1.2 The federated-identity family, and the link nobody can see

Measured in this order, each step its own request:

```
POST   .../federated-identity/nosuchidp   {"userId":…}   204
GET    .../federated-identity                            200 []
POST   .../federated-identity/nosuchidp   (same body)    409
register an identity provider with alias nosuchidp       201
GET    .../federated-identity                            200 [the link]
```

The write does not check the alias; the read filters on it. The fourth step is
the control: it touches nothing about the link and changes what the second step
answers, which is what rules out "the write silently dropped the row".

Also measured:

- **The path's `{provider}` wins over the body's `identityProvider`.** A `POST`
  to `.../federated-identity/fi1` carrying `{"identityProvider":"OTHER"}` stored
  and echoed `fi1`.
- `{}` as a body is a 204; the row reads back as `{"identityProvider":"fi2"}`,
  one key. **No body at all is a 500** `unknown_error`, the same Keycloak defect
  as an empty body on `POST /users`.
- The 409 is `{"errorMessage":"User is already linked with provider"}` - the
  admin error shape, not `Duplicate resource error`, and it names no provider.
- `DELETE` of a link that is not there is `404 {"error":"Link not found"}`.
- The listing's order is insertion order, on two links added in a known order.
- **The decode is strict**: an unknown field answers
  `Invalid json representation for FederatedIdentityRepresentation. Unrecognized
  field "bogus" at line 1 column 24.`
- `federatedIdentities` is a key of neither user serialisation.

Guards, one role at a time: every read takes `view-users` or `manage-users` and
refuses `query-users`; both writes take `manage-users` alone; `query-users` still
gets `User not found` for a subject that does not exist, which is
`guardUserSubject`'s two stages.

### 1.3 `GET /users/profile` is a canonicalisation, and the first reading of it was wrong

Master's `declarative-user-profile` component holds 988 bytes under
`kc.user.profile.config` and the endpoint answers the same 988 bytes,
md5 `7a2c214069eb9085ff019a8e75cbb6c7` on both. **That agreement is a
coincidence** - the shipped config is already canonical - and this cut shipped an
echo on the strength of it before a test written to defend the echo refuted it.

A config stored with odd spacing and `groups` before `attributes` came back
compacted, reordered, and with `"multivalued":false` **added** to every attribute
that lacked one. The full field order was then measured by storing every field at
once in a deliberately wrong order:

```
UPConfig     attributes, groups, unmanagedAttributePolicy
UPAttribute  name, displayName, validations, annotations, required,
             permissions, selector, group, multivalued
UPGroup      name, displayHeader, displayDescription, annotations
required     roles, scopes        - stored scopes-first, served roles-first
permissions  view, edit           - stored edit-first, served view-first
```

**`validations` keeps the order it was stored in and `annotations` does not.**
`{"up-username-not-idn-homograph":{},"length":{"max":255,"min":3}}` came back
unchanged - neither alphabetical nor Keycloak's own order for the same two
validators - while `{"z":"1","a":"2"}` came back `{"a":"2","z":"1"}`. One pair
cannot tell sorting from a Java map, so annotations passes through as stored and
that cell is left open rather than guessed. No config Gloak ships carries an
annotation.

`attributes` is omitted when empty and `groups` is not: a `PUT /users/profile {}`
leaves `{"groups":[]}`.

**A realm created through `POST /admin/realms` has no such component** and the
endpoint answers a built-in default that differs from master's: `email`,
`firstName` and `lastName` each carry `"required":{"roles":["user"]}` where
master's config has no `required` at all. `internal/bootstrap/components.go`
already models that split with its `masterOnly` flag.

The response carries `application/json;charset=UTF-8` and **no `Cache-Control`**,
where every other read in this cut carries `no-cache`.

Its guard is a five-role union no existing role-set variable expresses:
`view-users`, `manage-users`, **`query-users`**, `view-realm` and `manage-realm`
answer 200; `view-clients`, `manage-clients`, `query-clients`,
`view-identity-providers`, `manage-identity-providers`, `view-authorization`,
`manage-authorization`, `view-events` and `manage-events` answer 403. The `PUT`
on the identical path is `manage-realm` **alone**, so a `manage-users` caller may
read this profile and may not write it: the write guard is not a slice of the
read guard.

### 1.4 `unmanagedAttributes` has two cells and both were measured

`{}` on a realm whose profile declares no `unmanagedAttributePolicy`, which is
every default realm - and it is `{}` for a user whose stored attributes are not
empty, so it is the policy and not the user that decides. A realm whose profile
declares `"unmanagedAttributePolicy":"ENABLED"` answers the user's attributes
exactly.

`ADMIN_VIEW` and `ADMIN_EDIT` were **not** measured and are treated as `ENABLED`;
that is the one cell in the implementation resting on a reading rather than a
measurement, and it is called out in the file.

### 1.5 The cluster nodes

- `POST .../nodes` `{"node":"n"}` is 204 with **no `Cache-Control`**; the client
  gains `"registeredNodes":{"n":<unix seconds>}` - ten digits, where every
  timestamp on the user representation is thirteen.
- `registeredNodes` is **absent** when there is none, and sits between
  `nodeReRegistrationTimeout` and `protocolMappers`, measured on a client
  carrying both, in the single read and in the listing alike.
- `POST` with `{}` or a body naming no `node` is
  `400 {"error":"Node not found in params"}`; with no body at all it is
  `500 unknown_error`; with `text/plain` it is the 415; with **no
  `Content-Type` at all** it is accepted. An unknown extra field is 204 - this
  write is not strict where the federated-identity write next door is.
- `DELETE .../nodes/{node}` is 204 **with** `Cache-Control: no-cache`, which its
  `POST` sibling does not carry.
- A node that is not registered is `404 {"error":"Client does not have node "}` -
  trailing space, no node name, confirmed by hexdump.
- The registration is an upsert: the same name twice is 204 twice and leaves one
  entry carrying the second timestamp.

**The key order of `registeredNodes` is the *sized* Java HashMap's.** Three key
sets:

```
inserted kn1, kn2                came back kn2, kn1
inserted kn1, kn2, zzz, aaa      came back aaa, zzz, kn2, kn1
inserted 127.0.0.1, ct3          came back 127.0.0.1, ct3
```

`javamap.SizedKeyOrder` places all three; `javamap.KeyOrder` places the first two
and inverts the third, whose two keys land in buckets 14 and 3 at the
no-argument constructor's 16 and therefore do **not** collide. Neither sorting
nor insertion order explains any of the three. This is a third family for
`internal/javamap` and the first counterexample to `KeyOrder` outside a
collision.

Guard: realm, caller, a coarse gate of `clientsReadRoles`, the client, then
`manage-clients`. The distinguishing cell is `view-clients`, which sees
`Could not find client` for a UUID that resolves to nothing and 403 for one that
resolves; `h.guard("manage-clients", …)`, which the neighbouring client routes
use, answers 403 to both.

### 1.6 `credential-registrators`

`["CONFIGURE_TOTP","webauthn-register","webauthn-register-passwordless","CONFIGURE_RECOVERY_AUTHN_CODES"]`,
200 with `Cache-Control: no-cache`, and the same four on a created realm - so it
follows neither the realm's required actions nor its OTP policy. `view-realm` and
`manage-realm` open it; thirteen other admin roles were swept and all answer 403.

### 1.7 `configured-user-storage-credential-types`

`[]`, and it is the whole reachable answer. It enumerates the credential types
the user's **user storage federation provider** has configured; a default 26.7.1
has no federation provider and Gloak has none at all, so every user in every
Gloak realm is a local user.

### 1.8 The email family is a mail client, not four operations

This was the question the cut was asked to answer first, and the answer is that
it is a mail client. Four states, with the control that differs:

| realm `smtpServer` | the user has an email | answer |
|---|---|---|
| any | no | `400 {"errorMessage":"User email missing"}` |
| absent | yes | 500 `Failed to send execute actions email: Invalid sender address 'null'. …` |
| host unreachable | yes | 500 `Failed to send execute actions email: Error when attempting to send the email to the server. …` |
| **reachable** | yes | **204**, and the message really arrives |

The last row is the control: a mail catcher on the Docker bridge received three
messages, one per operation. `send-verify-email` answers the constant
`{"errorMessage":"Failed to send verify email"}` in both failing states and does
not interpolate; **`reset-password-email` answers the execute-actions message
word for word**, which is what says the two share one implementation.

**`POST /testSMTPConnection` is a two-condition rule and it nearly measured
itself.** It answered `500 {"errorMessage":"Failed to send email"}` to `{}`, to
an unreachable host **and to a reachable, working server** - the same server the
realm used successfully seconds later. The missing condition is not in the
request: the bootstrap `admin` user has **no email address**, and the endpoint
mails the test to the caller. Giving `admin` an email turned the reachable case
into **204 with `Cache-Control: no-cache`** and left the other two at 500. So a
default 26.7.1 answers 500 to every input, and a probe that stopped before the
mail catcher would have reported a constant.

### 1.9 `POST /users/{id}/impersonation` ends the caller's own session

200, `Cache-Control: no-cache`,
`{"redirect":"<base>/realms/master/account","sameRealm":true}`, and two
`Set-Cookie`s: `KEYCLOAK_IDENTITY` carrying a `Serialized-ID` JWT with `sid` and
`state_checker`, and `KEYCLOAK_SESSION`.

**The access token that made the call answered 401 on the very next request.**
The control: an ordinary write made with a sibling token left that token at 200,
and so did the 404 path. An unknown user is `404 {"error":"User not found"}`.

### 1.10 `partial-export` is the realm representation plus twelve keys

Every one of the 106 keys `GET /admin/realms/{realm}` returns comes back with an
identical value, and it adds `authenticationFlows`, `authenticatorConfig`,
`clientScopes`, `components`, `defaultDefaultClientScopes`,
`defaultOptionalClientScopes`, `identityProviderMappers`, `identityProviders`,
`keycloakVersion`, `localizationTexts`, `requiredActions` and `scopeMappings`.
40 576 bytes on a default master; 55 185 with
`exportClients=true&exportGroupsAndRoles=true`, which adds `clients`,
`clientScopeMappings`, `groups` and `roles`. It is sent
`Transfer-Encoding: chunked` with **`application/json` and no charset**.

`POST /partialImport` answers
`{"overwritten":0,"added":0,"skipped":0,"results":[]}` to `{}` and
`{"overwritten":0,"added":1,"skipped":0,"results":[{"action":"ADDED","resourceType":"REALM_ROLE","resourceName":"pi-role-1","id":…}]}`
to a one-role body, with `application/json;charset=UTF-8`.

### 1.11 `installation/providers/{providerId}` is eleven bodies

`GET /admin/serverinfo` names them: `docker-v2-compose-yaml`,
`docker-v2-registry-config-file`, `docker-v2-variable-override`,
`keycloak-oidc-jboss-subsystem`, `keycloak-oidc-jboss-subsystem-cli`,
`keycloak-oidc-keycloak-json`, `keycloak-saml`, `keycloak-saml-subsystem`,
`keycloak-saml-subsystem-cli`, `mod-auth-mellon`, `saml-sp-descriptor`. All
eleven answer 200. Nine are `text/plain` and **`docker-v2-compose-yaml` and
`mod-auth-mellon` are `application/zip`**. Five are SAML. An unknown provider is
`404 {"error":"Unknown Provider"}`.

`keycloak-oidc-keycloak-json`'s body is pretty-printed with Java's `" : "`
spacing, and its `text/plain` 200 carries four of the five security headers,
omitting `X-Frame-Options` - see §5.

### 1.12 The destructive half, and what it cost

`PUT /users/profile {}` on **master** broke every login in the realm: the
administrator's own direct grant afterwards answered
`{"error":"invalid_grant","error_description":"Account is not fully set up"}` and
the container had to be recreated. The warning this cut was given was about
creating a *second* `declarative-user-profile` component; this is the same
failure through the endpoint that writes the first one, and the guard is the
same - **do the destructive half in a realm you created.** That guidance was
followed for `PUT /users/profile` on the created realm and not for the guard
sweep that happened to send the same body on master.

The same write is also what says the profile drives user creation: on a created
realm, a profile declaring `length:{min:3}` on `username` made `POST /users`
`{"username":"u1"}` answer

```
400 {"field":"username","errorMessage":"error-invalid-length","params":["username",3,255]}
```

which is a body shape none of the four error shapes AGENTS.md records covers.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds them in.

- **A user's link to an identity provider can exist and be invisible.**
  `POST /users/{id}/federated-identity/{provider}` does not check that the realm
  has a provider by that alias: an unregistered one answers **204** and stores
  the row, while `GET /users/{id}/federated-identity` beside it answers `[]`.
  The row is really there - a repeat `POST` is
  `409 {"errorMessage":"User is already linked with provider"}` and a `DELETE` is
  204 - and registering an identity provider with that alias afterwards makes the
  same row **appear**, unchanged. So the write is ungated and the read is
  filtered, and validating the alias on the write is the tidy-up that turns a
  measured 204 into a 404. The body's own `identityProvider` is ignored: the
  path's segment wins, measured with the two disagreeing.

- **`GET /users/profile` is not the stored config.** It re-serialises it, and the
  agreement on master - 988 bytes in the component, the same 988 on the wire - is
  a coincidence of the shipped config already being canonical. A config stored
  with `groups` before `attributes` comes back reordered, compacted, and with
  `"multivalued":false` added to every attribute that lacked one. `required` and
  `permissions` are classes and are rewritten to `roles, scopes` and
  `view, edit`; `validations` is a map and **keeps the order it was stored in**;
  `annotations` is a map and **does not**. Two neighbouring maps in one object,
  opposite rules, and one measured pair is not enough to say what the second
  one's rule is.

- **`GET /users/profile` answers two different bodies and the realm decides.**
  Master has a `declarative-user-profile` component and a realm created through
  `POST /admin/realms` has none; the second gets a built-in default in which
  `email`, `firstName` and `lastName` each carry `"required":{"roles":["user"]}`
  and master's has no `required` at all. `GET /users/profile/metadata` beside it
  answers **byte-identically** in both realms, because the metadata is rendered
  in the admin context and `required` there is false either way. One resource,
  two endpoints, one varies with the realm and one does not.

- **`PUT /users/profile` with a body that omits `username` breaks every login in
  the realm.** `{}` is a 200 that leaves `{"groups":[]}`, and the administrator's
  own password grant then answers
  `{"error":"invalid_grant","error_description":"Account is not fully set up"}`.
  It is the same hazard as a second `declarative-user-profile` component, reached
  through the endpoint that writes the first one. Do it in a realm you created.
  The same write drives user validation: a profile declaring `length:{min:3}` on
  `username` makes `POST /users {"username":"u1"}` answer
  `{"field":…,"errorMessage":"error-invalid-length","params":[…]}`, which is a
  **fifth** error shape.

- **`DELETE .../clients/{uuid}/nodes/{node}` names no node.** For a node that is
  not registered it answers `404 {"error":"Client does not have node "}`, with a
  trailing space where the name should be - Keycloak builds the message by
  concatenation and has nothing to concatenate. Confirmed by hexdump.
  Interpolating the name is the tidy-up that breaks it.

- **`POST .../nodes` and `DELETE .../nodes/{node}` disagree about
  `Cache-Control`.** The `POST`'s 204 carries none and the `DELETE`'s carries
  `no-cache`. Two verbs, one path segment apart, one resource - which is the
  cheapest counterexample in this repository to any rule about `Cache-Control`
  stated over the verb or the status.

- **`registeredNodes` is a Java map from the *sized* constructor.** Three key
  sets were measured and `javamap.SizedKeyOrder` places all three, where
  `javamap.KeyOrder` places two and inverts `{127.0.0.1, ct3}` - a pair that does
  **not** collide at 16 buckets, so it is a genuine disagreement between the two
  constructors rather than the chaining `internal/javamap` says it cannot
  resolve. Neither sorting nor insertion order explains any of the three.

- **`GET .../clients/{uuid}/test-nodes-available` needs two conditions.** It
  answers `{}` unless the client has an `adminUrl` **and** a registered node;
  either alone is `{}`. With both it answers
  `{"failedRequests":["<adminUrl>"]}`, because it pushes to each node and reports
  which answered. So the `{}` a default container gives is not the endpoint's
  contract, it is the empty case of a two-condition rule.

- **`POST /testSMTPConnection` fails against a working SMTP server**, and the
  condition is not in the request. It answers
  `500 {"errorMessage":"Failed to send email"}` to `{}`, to an unreachable host
  and to a reachable one alike, because the bootstrap `admin` user has **no email
  address** and the endpoint mails the test to the caller. Give `admin` an email
  and the reachable case becomes 204. On a default 26.7.1 the endpoint therefore
  answers 500 to every input there is, which is exactly the shape of a probe
  measuring itself.

- **The three email writes answer about the user before they answer about the
  mail.** A user with no email is `400 {"errorMessage":"User email missing"}`
  whatever the realm's SMTP is. With an email, the 500 depends on the realm:
  no `smtpServer` gives `Invalid sender address 'null'`, an unreachable one gives
  `Error when attempting to send the email to the server`, and a reachable one
  gives 204. `send-verify-email` answers its own constant in both failing states;
  **`reset-password-email` answers `execute-actions-email`'s message word for
  word**, which is what says the two are one implementation.

- **`POST /users/{id}/impersonation` ends the calling administrator's own
  session.** The access token that made the call answers 401 on the very next
  request, where the same token used for an ordinary write does not, and where
  the 404 path leaves it alone. The 200 is
  `{"redirect":"<base>/realms/{realm}/account","sameRealm":true}` with a
  `KEYCLOAK_IDENTITY`/`KEYCLOAK_SESSION` pair.

- **`POST /partial-export`'s 200 carries `application/json` with no charset and
  no `Content-Length`.** It is chunked, and it is the **second** Admin API 2xx
  with a body outside the charset rule, after `POST /groups/{id}/children`'s
  201 - so that bullet's "one counterexample" is now two. `PUT /users/profile`'s
  200 is a third.

- **`users-management-permissions` answers 501 before authorization**, on both
  verbs, to a caller holding no admin role at all. It is
  `ADMIN_FINE_GRAINED_AUTHZ`, deprecated and disabled, and
  `ADMIN_FINE_GRAINED_AUTHZ_V2` being enabled does not open it - the same trap
  the twelve `management/permissions` routes have. So the fine-grained
  permissions surface is fourteen refusals, not twelve.

- **The strict decoder is on five endpoints, not four.**
  `POST /users/{id}/federated-identity/{provider}` answers an unknown field
  `Invalid json representation for FederatedIdentityRepresentation. Unrecognized
  field "bogus" at line 1 column 24.` Its neighbour in the same cut,
  `POST .../clients/{uuid}/nodes`, answers an unknown field **204**. Two writes,
  one cut, opposite answers.

- **Two more spellings of not-found**, both from this cut: `Link not found` from
  `DELETE /users/{id}/federated-identity/{provider}`, and
  `Client does not have node ` from `DELETE .../clients/{uuid}/nodes/{node}` -
  the second misspelling-shaped entry after `Sesssion not found`, this one a
  trailing space rather than a letter. `DELETE /users/{id}/consents/{client}`
  adds a third, `Consent nor offline token not found`, and `Unknown Provider`
  from `installation/providers/{providerId}` a fourth. **The count in that bullet
  was not incremented here**; whoever folds these in should recount from the
  list.

- **A third read refuses the view role.** `GET .../test-nodes-available` needs
  `manage-clients`; `view-clients` is 403 on it and 200 on
  `GET .../installation/providers/{providerId}` immediately beside it. That
  bullet said two.

## 3. What contradicts AGENTS.md or the observed document

Three, and the first is the one that matters most because the repository's own
goldens already disagree with the prose.

**(1) `text/plain` responses do not "omit the five".** AGENTS.md's security-header
bullet says of `userinfo` that "its rejections are `text/plain` and omit the
five", and its table reads `text/plain 6 goldens · none carries the five`. All
**seven** committed `text/plain` goldens - six `oidc/userinfo/*` and
`admin/realms-admin/localization-text` - carry `Referrer-Policy`,
`Strict-Transport-Security`, `X-Content-Type-Options` and `X-Robots-Tag`, and
omit `X-Frame-Options` alone. `GET .../installation/providers/keycloak-oidc-keycloak-json`
was measured doing the same. The table's wording is defensible read as "none
carries all five"; the sentence is not, and "the media type of the response
decides" is a claim about one header rather than five. This is the failure mode
that bullet says it is least able to catch in itself, and it is caught here by
reading the goldens rather than by a probe.

**(2) The charset counterexample is not one.** The bullet says every Admin API
2xx with a body carries `;charset=UTF-8` "with one counterexample this file
records separately (`POST /groups/{id}/children`'s 201)". `POST /partial-export`'s
200 is a second - plain `application/json`, chunked - and `PUT /users/profile`'s
200 is a third. Both are measured; neither is served by this cut, so no golden in
this tree holds either.

**(3) `javamap.KeyOrder` has a counterexample outside a collision.** The bullet
says `KeyOrder` "is confirmed against fourteen measured key sets" and that what
it cannot resolve is a bucket collision. `{127.0.0.1, ct3}` on
`registeredNodes` is placed the wrong way round by it and the right way round by
`SizedKeyOrder`, and the two keys occupy buckets 14 and 3 at capacity 16, so
nothing collides. The finding is not that `KeyOrder` is wrong - it is that
`registeredNodes` is the other constructor, which is the split the bullet already
records between the component configs and the identity providers.

Nothing in
`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` was contradicted;
none of these operations is in it.

## 4. Follow-up dispositions

**F148 - the settled boundary. Applied twice, unchanged.**
`POST /users/{id}/impersonation` and `POST .../clients/{uuid}/registration-access-token`
are both refused on it and both are in the catalogue as `Pending` with the reason
written where the next reader is looking.

Impersonation mints a browser SSO session: `KEYCLOAK_IDENTITY` is
`internal/token`'s to sign and the cookie pair is written by `setLoginCookies` in
`internal/oidc/loginactions.go`, which is unexported and in a package this branch
may not touch. That is F148's shape exactly - "if it needs something only
`internal/oidc` has, the honest answer is a case and not a second copy" - and the
answer is a case.

The registration access token is the sharper one, because
`internal/token.IssueRegistration` already mints exactly the right token. What
cannot be done from `internal/admin` is make it *work*: which jti is current for
a client lives in `internal/oidc`'s in-memory `registrationStore`, whose own doc
comment says the honest place is a column on `model.Client` and that
`internal/model` and `internal/store` were owned elsewhere when it was written.
**They are owned by this cut and `internal/oidc` is not**, so the move still
needs one cut that holds both. That is a new follow-up and it is the shape of
F110 below.

**F154 - `briefRepresentation` on the user listing, and which attributes depend
on the realm's profile.** Not closed, and this cut is why it is now reachable.
F154 says "no golden can reach it: the user profile would have to be edited
first, and that is a chapter this project does not serve." Half of that is no
longer true - `GET /users/profile` is served and the profile is readable - and
half is: the **write** is deliberately not served, for the reason §1.12 records,
so a fixture still cannot edit the profile through the API. What this cut adds is
`unmanagedAttributes`, whose ENABLED cell is exercised by writing the profile
through `PUT /components/{id}`, which **is** served. So the fixture F154 wants
exists in `internal/admin/userprofile_test.go` and could be lifted into
`internal/conformance` by a cut willing to write a component in a fixture. Filed
against F154 rather than done here, because it belongs to the user listing.

**F157 - `attack-detection` stores nothing.** Untouched and unaffected; nothing
in this cut counts a failed authentication. It is named here because its shape is
the one §1.7 reuses: `configured-user-storage-credential-types` answers `[]`
because Gloak has no user federation, the same way attack-detection answers the
zero record because nothing counts a failure, and in both cases **a table nothing
writes would be a claim about the model that is not true**. No `user_storage`
table was added.

**F95 - a client's `attributes` is serialised from a Go map.** Not closed, and
this cut adds a **second** map to the same representation with the same problem
and a different answer. `registeredNodes` is a `map[string]int64` in the model and
would sort under `encoding/json`, so `internal/admin` gives it a marshaller that
runs `javamap.SizedKeyOrder` over the sorted keys - which is F95's fix applied at
the serialiser rather than in the model. It is not `model.StringMap`, because that
type is `string`→`string` and this map is `string`→`int64`, and because the two
families use different HashMap constructors. When F95's move lands it should take
`registeredNodes` with it and keep the constructor split; a shared ordered map
type that hard-codes `KeyOrder` would be wrong on this one.

**F110 - consent grants are in memory, and that one is a real divergence.** This
is the follow-up the consents pair is left against, and it is named here because
this cut is the first one that could have half-closed it and should not.
`internal/oidc`'s `consentStore` records grants in memory and its own doc comment
names `GET`/`DELETE /users/{id}/consents` as the endpoints that expose them. An
`internal/admin` handler answering `[]` would pin "this user has never consented"
as a contract while the package next door is recording that they have. Both
packages have to move in one cut.

## 5. The mutation pass, and the one survivor

Fifteen mutations, one per claim, each reverted and each revert checked. The
harness refuses to run on a dirty tree, refuses a mutation that changes no byte,
refuses one that does not compile, and **reads `go test`'s exit code before it
looks at the log** - which is the failure mode this project has met three times
inside its own tooling. It was given a control known **not** to differ, a
comment-only edit, before anything else: that one survived, so the harness was
not reporting KILLED for everything.

| # | mutation | test | result |
|---|---|---|---|
| 0 | a comment only | the node tests | SURVIVED, as required |
| 1 | the listing stops filtering to registered aliases | `TestAFederatedLinkToAnUnregisteredAliasIsStoredAndInvisible` | killed |
| 2 | the body's `identityProvider` wins over the path's | `TestAFederatedLinkTakesItsAliasFromThePathAndNotTheBody` | killed |
| 3 | the listing orders by alias | `TestTheFederatedIdentityListingIsInsertionOrdered` | killed |
| 4 | `registeredNodes` loses its `omitempty` | `TestRegisteredNodesIsAbsentUntilThereIsOne` | killed |
| 5 | `KeyOrder` instead of `SizedKeyOrder` | `TestRegisteredNodesKeyOrderIsTheSizedJavaMap` | killed |
| 6 | the role check precedes the client lookup | `TestTheNodeWritesResolveTheClientBeforeTheirRole` | killed |
| 7 | the profile is echoed rather than canonicalised | `TestTheUserProfileIsCanonicalisedAndNotEchoed` | killed |
| 8 | the profile read reuses `usersReadRoles` | `TestTheUserProfileReadTakesFiveRoles` | killed |
| 9 | `unmanagedAttributes` is the constant `{}` | `TestUnmanagedAttributesFollowsTheProfilesPolicy` | killed |
| 10 | the built-in default loses a `required` block | `TestARealmWithNoUserProfileComponentAnswersTheBuiltInDefault` | **survived**, then killed |
| 11 | `UnregisterNode` swallows a missing row | the sqlite `TestConformance` | killed |
| 12 | the node 404 interpolates the node's name | golden `admin/clients/nodes-remove-missing` | killed |
| 13 | the 501 follows authorization | golden `.../users-management-permissions-no-role` | killed |
| 14 | `credential-registrators` is sorted | golden `admin/realms-admin/credential-registrators` | killed |
| 15 | the credential types answer `{}` | golden `admin/users/configured-user-storage-credential-types` | killed |

**Mutation 10 survived because the test was a tautology**, not because the cell
was unmeasured: it compared the response against `defaultUserProfile`, the
constant the handler serves, so an edit to the constant moved both sides. The
test now asserts the measured *difference* between the two realms' profiles -
three `required` blocks on a created realm's and none on master's, over the same
four attribute names - which no single-sided edit satisfies. It was re-run
afterwards and killed. That is the shape AGENTS.md warns about under "a test
pins a two-condition rule only if its state or its request supplies both
conditions", reached from the other side: an assertion whose two sides come from
one place pins nothing.

Two cells were **left unmeasured on purpose** and no mutation was written to
close either, because killing one would have converted a question into a
contract:

- the key order of an attribute's `annotations`, where one measured pair cannot
  tell sorting from a Java map, and which no config Gloak ships reaches;
- `unmanagedAttributePolicy` values `ADMIN_VIEW` and `ADMIN_EDIT`, which are
  treated as `ENABLED` on a reading rather than a measurement, said so in
  `internal/admin/userprofile.go`.

## 6. One recorder artefact, not committed

`make record` on this branch produced a diff to
`admin/clients/evaluate-scope-mappings-not-granted.http` that has nothing to do
with this cut: the golden gained sixteen `gloak-probe-*` realm roles the other
fixtures create. That case reads a realm-wide listing and is not
`PristineRealm`, so what it holds depends on how much state the shared container
has when it runs.

**It was reverted rather than committed**, and the verifier then passed against
the committed bytes - so the committed golden is still what Gloak serves and the
re-record would have pinned pollution as the contract. Nothing in this cut
creates a realm role, so the shift is in the recorder rather than in the
catalogue. Worth a `PristineRealm` on that case, filed here rather than changed,
because it belongs to the scope evaluator's chapter.

## 7. Parity, before and after

| chapter | before | after |
|---|---|---|
| `admin/users` | 20 / 34 | 26 / 34 |
| `admin/clients` | 28 / 35 | 30 / 35 |
| `admin/realms-admin` | 39 / 45 | 42 / 45 |
| total | 483 / 541 | 494 / 541 |

Eleven operations of the twenty-seven. The sixteen left are the four in §1.8, the
two in §1.9 and §1.11's neighbour, the two in §1.10, `PUT /users/profile`,
`GET /users/profile/metadata`, the consents pair, `test-nodes-available`,
`registration-access-token`, and the two `evaluate-scopes` generators this cut
was told not to re-litigate and did not. Their reasons are in the plan's first
section and in the catalogue beside the two that carry a `Pending` case.
