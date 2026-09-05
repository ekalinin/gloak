# The scattered remainder of Clients, Users and Realms Admin

The twenty-seven operations the vendored description carries under `Users`,
`Clients` and `Realms Admin` that nothing in the catalogue serves. They do not
form a chapter; they are what is left when every chapter next to them has been
taken, and they belong to thirteen unrelated groups.

The list was recomputed here rather than inherited. `internal/conformance`'s
coverage meter reports `admin/users 20 of 34`, `admin/clients 28 of 35` and
`admin/realms-admin 39 of 45` before this cut, and the set difference between
each tag's operations in `internal/conformance/testdata/openapi/keycloak-26.7.1.json`
and the `Operation` fields of `catalog_admin.go` is exactly the list in the
table below. Two of them - the `evaluate-scopes/generate-example-*` pair - are
already in the catalogue as `Pending` with written reasons and are not
re-litigated here.

## 1. One row per family

| # | Family | Ops | The open question | Taken |
|---|---|---|---|---|
| 1 | `users-management-permissions` GET, PUT | 2 | which of the five gate shapes | **yes** |
| 2 | `credential-registrators` | 1 | none: is the list realm-dependent | **yes** |
| 3 | federated identity: GET, POST, DELETE | 3 | what a link to an unregistered alias does | **yes** |
| 4 | `unmanagedAttributes` | 1 | whether the answer depends on the profile's policy | **yes** |
| 5 | `configured-user-storage-credential-types` | 1 | whether `[]` is the answer without user federation | **yes** |
| 6 | `GET /users/profile` | 1 | whether the body is derived or stored | **yes** |
| 7 | cluster nodes: `POST /nodes`, `DELETE /nodes/{node}` | 2 | where `registeredNodes` lives | **yes** |
| 8 | `PUT /users/profile` | 1 | what a write does to the realm | no |
| 9 | `GET /users/profile/metadata` | 1 | whether it is derivable from the profile | no |
| 10 | consents: GET, DELETE | 2 | where Gloak's consent grants live | no |
| 11 | the three email writes and `testSMTPConnection` | 4 | four operations or a mail client | no |
| 12 | `POST /users/{id}/impersonation` | 1 | whether it needs `internal/oidc` | no |
| 13 | `GET /clients/{uuid}/test-nodes-available` | 1 | what makes it answer anything but `{}` | no |
| 14 | `GET /clients/{uuid}/installation/providers/{providerId}` | 1 | how many providers there are | no |
| 15 | `POST /clients/{uuid}/registration-access-token` | 1 | where the minted token's jti is recognised | no |
| 16 | `partial-export`, `partialImport` | 2 | what the bodies actually carry | no |
| 17 | `evaluate-scopes/generate-example-{userinfo,saml-response}` | 2 | settled before this cut | untouched |

No total is written beside that table on purpose. The number is the set
difference between the three tags' operations in
`internal/conformance/testdata/openapi/keycloak-26.7.1.json` and the `Operation`
fields of `catalog_admin.go`, and `internal/conformance`'s coverage meter prints
it per chapter on every run - which is a computed number rather than one that
drifts away from the rows it counts.

## 2. What was measured, and what each answer decided

Every value below came off a live `quay.io/keycloak/keycloak:26.7.1` on
:8174, whose `GET /admin/serverinfo` reported `26.7.1`.

### 2.1 `users-management-permissions` is `client-types`' gate exactly

Both verbs answer

```
501 {"error":"Feature not enabled","error_description":"For more on this error consult the server log."}
```

with `Content-Type: application/json` and no `Cache-Control`, byte for byte
what `client-types` and the twelve `management/permissions` routes answer.
The gate order was measured against controls that differ:

| request | answer |
|---|---|
| no token | 401 `HTTP 401 Unauthorized` |
| admin token, realm `nosuch` | 404 `Realm not found.` |
| a caller holding **no** admin role | **501**, not 403 |
| the same caller on `GET .../keys` | 403, which is the control |

So: authenticate, resolve the realm, refuse - authorization never runs. That is
`guardRealmFeature` unchanged, which is the shape `client-types` already uses.
Taken because the whole behaviour is one existing combinator and one existing
terminal.

### 2.2 `credential-registrators` is a four-name constant

```
200 application/json;charset=UTF-8, Cache-Control: no-cache
["CONFIGURE_TOTP","webauthn-register","webauthn-register-passwordless","CONFIGURE_RECOVERY_AUTHN_CODES"]
```

Guard measured one role at a time: `view-realm` and `manage-realm` answer 200;
`view-users`, `manage-users`, `query-users`, `view-clients`, `manage-clients`,
`view-identity-providers`, `manage-identity-providers`, `view-authorization`,
`manage-authorization`, `view-events`, `manage-events`, `query-groups` and
`query-clients` all answer 403. That is `realmConfigReadRoles` as it stands.

### 2.3 The federated-identity family, and the link nobody can see

Four measurements, each with the control that separates it:

- `POST .../federated-identity/{provider}` for an alias that **is not a
  registered identity provider** answers **204** and stores the link. The
  provider is not validated at all.
- `GET .../federated-identity` then answers **`[]`**. The link exists - a repeat
  `POST` answers `409 {"errorMessage":"User is already linked with provider"}`
  and a `DELETE` answers 204 - and the listing does not show it.
- Registering an identity provider with that alias makes the same stored link
  **appear**, unchanged. That is the control: one request that changes nothing
  about the link changes what the listing says about it.
- So the listing is filtered to the realm's registered aliases and the write
  path is not.

Also measured:

- The **path's** `{provider}` wins over the body's `identityProvider`: a `POST`
  to `.../federated-identity/fi1` carrying `{"identityProvider":"OTHER"}` stores
  and echoes `fi1`.
- `{}` as a body is accepted: the link is stored with neither `userId` nor
  `userName`, and the listing omits both keys - `{"identityProvider":"fi2"}`.
- **No body at all** is `500 {"error":"unknown_error",…}`, the same Keycloak
  defect as an empty body on `POST /users`.
- `DELETE` of a link that is not there is `404 {"error":"Link not found"}`.
- The listing's order is insertion order.
- `federatedIdentities` is **not** a key of either user serialisation.

Guards: every read takes `view-users` or `manage-users` and refuses
`query-users`; both writes take `manage-users` alone. An unknown user is
`404 {"error":"User not found"}` and a caller with no role gets 403 for that
same unknown user, so the coarse gate precedes the lookup - `guardUserSubject`'s
shape.

### 2.4 `unmanagedAttributes` has two cells and both were measured

`{}` on a default realm, because the profile's `unmanagedAttributePolicy` is
absent. On a realm whose profile declares `"unmanagedAttributePolicy":"ENABLED"`
and a user created with `{"custom1":["v1"],"custom2":["a","b"]}`, it answers
those attributes exactly. Taken with the branch, not with the constant: a
handler that answered `{}` to both would be a probe measuring itself, and the
policy is reachable through `PUT /components/{id}`, which Gloak serves.

### 2.5 `configured-user-storage-credential-types` is `[]` and says why

`[]` for a local user. It enumerates the credential types the user's **user
storage federation provider** has configured, and 26.7.1 out of the box has no
federation provider at all. Gloak has no user federation - no `UserStorage`
provider type, nothing in the component catalogue that is one - so every user in
every Gloak realm is a local user and `[]` is the answer for the whole reachable
input space, the same way `client-types`' 501 is.

### 2.6 `GET /users/profile` is an echo, not a derivation

The `declarative-user-profile` component's `kc.user.profile.config` on master is
988 bytes and `GET /admin/realms/master/users/profile` is the **same 988 bytes**,
`md5 7a2c214069eb9085ff019a8e75cbb6c7` on both. It is a verbatim echo of a
stored string.

A realm created through `POST /admin/realms` has **no such component** - the
listing filtered to `org.keycloak.userprofile.UserProfileProvider` is `[]` - and
the endpoint answers a built-in default that **differs from master's**: `email`,
`firstName` and `lastName` each carry `"required":{"roles":["user"]}`, which
master's config does not. `internal/bootstrap/components.go` already models that
split with its `masterOnly` flag and already stores the 988 bytes, so both cells
are reachable and neither is invented.

The response carries `application/json;charset=UTF-8` and **no `Cache-Control`**,
where every other read in this cut carries `no-cache`.

Guard: `view-users`, `manage-users`, `query-users`, `view-realm` **and**
`manage-realm` all answer 200; the other nine roles swept answer 403. That is a
five-role union - the whole users read set including `query-users`, plus the
realm pair - and it is not any existing role-set variable.

### 2.7 The cluster-node writes

- `POST .../nodes` with `{"node":"n"}` answers 204 with no `Cache-Control`, and
  the client's representation gains `"registeredNodes":{"n":<unix seconds>}`
  between `nodeReRegistrationTimeout` and `defaultClientScopes`.
- `registeredNodes` is **absent** when there is none, not `{}` and not `null`.
- `POST` with `{}` or with a body naming no `node` is
  `400 {"error":"Node not found in params"}`; with **no body at all** it is
  `500 {"error":"unknown_error",…}`.
- `DELETE .../nodes/{node}` answers 204 **with** `Cache-Control: no-cache`,
  which its `POST` sibling does not carry.
- `DELETE` of a node that is not registered answers
  `404 {"error":"Client does not have node "}` - the node's name is **not**
  interpolated and the message ends in a space. Confirmed by hexdump.
- An unknown client is `404 {"error":"Could not find client"}` on all three node
  routes, and a caller with no role sees 403 for that same unknown client.
- Both writes take `manage-clients` alone.

### 2.8 The four this cut leaves, and what the measurement decided

**`PUT /users/profile`** - `manage-realm` alone, 200 with the stored profile
echoed back, `application/json` with **no charset**. It replaces rather than
merges: `{}` leaves `{"groups":[]}` and the four attributes are gone. And it
creates the `declarative-user-profile` component in a realm that had none.

It is left because of what it does next. On the created realm `up1`, a profile
declaring `length: {min: 3}` on `username` made `POST /users` with
`{"username":"u1"}` answer

```
400 {"field":"username","errorMessage":"error-invalid-length","params":["username",3,255]}
```

which is a body shape this API's four error shapes do not include. And on
`master`, a `PUT /users/profile {}` - which omits `username` - **broke every
login in the realm**: `admin`'s own direct grant afterwards answered
`{"error":"invalid_grant","error_description":"Account is not fully set up"}`
and the container had to be recreated. So the write is not a write to a
representation; it is a write to the thing that validates users and admits
logins, and Gloak implements neither. Serving the 200 alone would let a caller
change something Gloak then ignores, in two requests.

**`GET /users/profile/metadata`** - it is a derivation of the same config and
**not** the config: `validations` becomes `validators`, each validator gains
`"ignore.empty.value":true`, a `multivalued: {"max":"1"}` validator is
synthesised, and `required`/`readOnly` become booleans. `required` is `false`
for `email`, `firstName` and `lastName` **even on the created realm whose
profile marks all three required for the `user` role**, because the metadata is
rendered in the admin context. The consequence is the reason to leave it:
master's metadata and a created realm's are **byte-identical** although their
profiles are not, so the two configs a default install can have do not
distinguish a derivation from a constant. Pinning the constant would be a probe
measuring itself for any third config, and the derivation needs Keycloak's
per-validator default table plus `javamap` ordering of the `validators` map -
whose key order on `username` is `username-prohibited-characters, multivalued,
length, up-username-not-idn-homograph`, which is neither sorted nor the
profile's order.

**The consents pair** - `GET` is `[]` and `DELETE` is
`404 {"error":"Consent nor offline token not found"}` for a real client with no
consent, `404 {"error":"Client not found"}` for a client that does not exist, so
the client is resolved first. Both need `manage-users` for the delete and
`view-users`/`manage-users` for the read.

It is left because of where Gloak's grants are. `internal/oidc`'s
`consentStore` records them in memory, and its own doc comment names these two
endpoints as the divergence it is filing. `internal/oidc` is not this branch's
to touch, so an `internal/admin` handler answering `[]` would pin "this user has
never consented" as a contract while the process next door is recording that
they have. That is F110, and it needs `internal/oidc` and `internal/store` in
one cut.

**The email family is a mail client, not four operations.** Measured across
four states with the control that differs:

| realm `smtpServer` | user has an email | answer |
|---|---|---|
| any | no | `400 {"errorMessage":"User email missing"}` |
| absent | yes | 500, `Failed to send execute actions email: Invalid sender address 'null'. …` |
| host unreachable | yes | 500, `Failed to send execute actions email: Error when attempting to send the email to the server. …` |
| **reachable** | yes | **204**, and the message really arrives |

The last row is the control: a mail catcher on the Docker bridge received three
messages, one per operation. `send-verify-email` answers the constant
`{"errorMessage":"Failed to send verify email"}` in both failing states and
does not interpolate; `reset-password-email` answers the **execute-actions**
message word for word, which is what says the two share one implementation.

`POST /testSMTPConnection` is the sharpest of the four and it is a
**two-condition rule**. It answered `500 {"errorMessage":"Failed to send email"}`
to `{}`, to an unreachable host **and to a reachable, working server** - the
same server the realm used successfully seconds later. The condition that was
missing is not in the request at all: the bootstrap `admin` user has **no email
address**, and the endpoint mails the test to the caller. Giving `admin` an
email turned the reachable case into **204 with `Cache-Control: no-cache`** and
left the unreachable case and `{}` at 500. So a default 26.7.1 answers 500 to
every input, and a probe that stopped there would have been measuring itself.

Four operations whose measured answers are decided by whether an SMTP server
accepts a connection. Gloak has no mail transport, `internal/httpx` is not this
branch's, and `CGO_ENABLED=0 go test ./...` may not touch a network. Left, with
the four states recorded so the cut that builds the transport does not have to
re-measure them.

**`POST /users/{id}/impersonation`** - 200,
`{"redirect":"http://localhost:8174/realms/master/account","sameRealm":true}`,
`Cache-Control: no-cache`, and **two `Set-Cookie`s**: `KEYCLOAK_IDENTITY`
carrying a `Serialized-ID` JWT with `sid` and `state_checker`, and
`KEYCLOAK_SESSION`. An unknown user is `404 {"error":"User not found"}`.

And it **ends the calling administrator's own session**: the access token that
made the call answered 401 on the very next request, where an ordinary write
made with a sibling token left it at 200 and the 404 path left it at 200 too.

That is F148's shape and F148's answer applies. The cookie pair is written by
`setLoginCookies` in `internal/oidc/loginactions.go` and the identity token by
`internal/token`; producing them from `internal/admin` is the second copy F148
exists to prevent. Left on the boundary.

**`GET .../test-nodes-available`** answers `{}` unless the client has an
`adminUrl` **and** a registered node - either alone gives `{}`. With both it
answers `{"failedRequests":["http://127.0.0.1:9/admin"]}`, because it performs
an outbound push to each node and reports which succeeded. Two conditions and an
outbound signed request; the `{}` alone is not a contract worth pinning.

**`GET .../installation/providers/{providerId}`** is one operation with
**eleven** bodies. `GET /admin/serverinfo` names them:
`docker-v2-compose-yaml`, `docker-v2-registry-config-file`,
`docker-v2-variable-override`, `keycloak-oidc-jboss-subsystem`,
`keycloak-oidc-jboss-subsystem-cli`, `keycloak-oidc-keycloak-json`,
`keycloak-saml`, `keycloak-saml-subsystem`, `keycloak-saml-subsystem-cli`,
`mod-auth-mellon`, `saml-sp-descriptor`. All eleven answer 200. Nine are
`text/plain`; **`docker-v2-compose-yaml` and `mod-auth-mellon` are
`application/zip`**. Five are SAML, which this project has no path for - the
same reason `generate-example-saml-response` is Pending - and no golden in this
harness holds a ZIP. An unknown provider is `404 {"error":"Unknown Provider"}`.

**`POST .../registration-access-token`** answers 200 with the full client
representation carrying a freshly minted `registrationAccessToken`
(`typ: RegistrationAccessToken`, `exp: 0`, HS512), which `GET /clients/{uuid}`
never carries. `internal/token.IssueRegistration` already mints exactly that
token. What it cannot do from here is make it work: which jti is current for a
client lives in `internal/oidc`'s in-memory `registrationStore`, whose own doc
comment says the honest place is a column on `model.Client` and that
`internal/model` and `internal/store` were owned elsewhere when it was written.
They are owned here - but `internal/oidc` is not, so a token minted in
`internal/admin` is a token `internal/oidc` refuses. Left, and the follow-up now
names the two packages that have to move together.

**`partial-export`** is the realm representation plus twelve keys and nothing
else: every one of the 106 keys `GET /admin/realms/{realm}` returns comes back
with an identical value, and it adds `authenticationFlows`, `authenticatorConfig`,
`clientScopes`, `components`, `defaultDefaultClientScopes`,
`defaultOptionalClientScopes`, `identityProviderMappers`, `identityProviders`,
`keycloakVersion`, `localizationTexts`, `requiredActions` and `scopeMappings`.
40 576 bytes on a default master, 55 185 with `exportClients=true&exportGroupsAndRoles=true`,
which adds `clients`, `clientScopeMappings`, `groups` and `roles`. It is sent
`Transfer-Encoding: chunked` with **`application/json` and no charset**.

**`partialImport`** answers `200 {"overwritten":0,"added":0,"skipped":0,"results":[]}`
to `{}` and `{"overwritten":0,"added":1,"skipped":0,"results":[{"action":"ADDED","resourceType":"REALM_ROLE","resourceName":"pi-role-1","id":"…"}]}`
to a one-role body. The empty case is 52 bytes; the general case is a realm
importer over roles, clients, groups, users and identity providers. Both left:
the export is a second serialisation of four families' representations and the
import is a second writer for five.

## 3. What gets built

Six changes, in dependency order. Each lands as its own commit.

### 3.1 `internal/model` and `internal/store` - migration `0034`

`0034_federated_identity_and_nodes.sql`, in **both**
`internal/store/sqlite/migrations/` and `internal/store/postgres/migrations/`
(the last existing is `0030`; `0034` is reserved for this branch):

```sql
CREATE TABLE federated_identity (
    realm_id          TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    identity_provider TEXT NOT NULL,
    external_user_id  TEXT NOT NULL,
    external_username TEXT NOT NULL,
    seq               INTEGER NOT NULL,
    PRIMARY KEY (realm_id, user_id, identity_provider)
);
CREATE TABLE client_node (
    realm_id      TEXT NOT NULL,
    client_uuid   TEXT NOT NULL,
    node          TEXT NOT NULL,
    registered_at INTEGER NOT NULL,
    PRIMARY KEY (realm_id, client_uuid, node)
);
```

`seq` exists because the listing's order is insertion order, measured, and
neither alias nor external id reproduces it.

New model types `model.FederatedIdentity` and the `RegisteredNodes` field on
`model.Client`; new interface methods on `store.UserRepo`
(`ListFederatedIdentities`, `LinkFederatedIdentity`, `UnlinkFederatedIdentity`)
and `store.ClientRepo` (`RegisterNode`, `UnregisterNode`, `ListNodes`),
implemented in **both** drivers and covered in `storetest/conformance.go`.

### 3.2 `internal/admin/federatedidentity.go`

Three handlers on `guardUserSubject`, `userReadRoles` for the read and
`userWriteRoles` for the two writes. The listing filters to the realm's
registered identity provider aliases - which is the finding, and the file says
so.

### 3.3 `internal/admin/userprofile.go`

`GET /users/profile` reads the realm's `declarative-user-profile` component and
writes its `kc.user.profile.config` as a `json.RawMessage`; a realm with no such
component gets the built-in default, held as one constant with the created-realm
body. `GET /users/{id}/unmanagedAttributes` reads
`unmanagedAttributePolicy` out of that same config and answers `{}` unless it is
present, the user's attributes when it is.
`GET /users/{id}/configured-user-storage-credential-types` answers `[]` with the
reason in the doc comment.

A new role-set variable for the profile read's five roles, because no existing
one is that union.

### 3.4 `internal/admin/clientnodes.go`

`POST .../nodes` and `DELETE .../nodes/{node}` behind the existing client guard
at `manage-clients`, plus `registeredNodes` on `clientRepresentation` with
`omitempty` so it is absent rather than `{}`.

### 3.5 `internal/admin/router.go`

Eleven registrations, and `users-management-permissions` on `guardRealmFeature`
with `writeFeatureNotEnabled` - the two-line change, next to `client-types`.

### 3.6 `internal/admin/realmconfig.go` (existing file)

`GET /credential-registrators`, one constant, `realmConfigReadRoles`.

## 4. Conformance

New cases appended at the very end of `catalog_admin.go`, new fixtures appended
at the very end of `fixture.go`'s map and after its last helper, goldens under
`testdata/golden/admin/`. Every `Implemented` case gets a golden recorded from
the reference container by `make record`; no golden is hand-written and none is
re-recorded to make a failure go away.

The two left-behind families that are worth a `Pending` case with a reason -
`impersonation` and `registration-access-token` - get one, so the reason lives
where the next reader is looking.

No new file is added to `internal/conformance`'s harness. The count in section 1
is checked by the coverage meter that already exists rather than by a test
written to agree with a table.

## 5. Parity

| chapter | before | after |
|---|---|---|
| `admin/users` | 20 / 34 | 26 / 34 |
| `admin/clients` | 28 / 35 | 30 / 35 |
| `admin/realms-admin` | 39 / 45 | 42 / 45 |
| total | 483 / 541 | 494 / 541 |
