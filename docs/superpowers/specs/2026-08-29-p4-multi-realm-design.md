# Multi-realm: P4

Date: 2026-08-29
Status: accepted

## 1. What this is

The sub-project that makes Gloak serve more than one realm. The roadmap allots
it "Realms Admin 45, Key 1", written before anyone counted.

The count is right. The allocation behind it is not what it looks like.

Counted against
`internal/conformance/testdata/openapi/keycloak-26.7.1.json`, the `Realms Admin`
tag holds exactly 45 operations and the `Key` tag exactly 1. But only **16 of
the 46 are P4's to build**. The other 30 are counted here because the
description tags them here, while the behaviour behind them belongs to six other
sub-projects. Section 2 works that out per operation, because the roadmap says
so only for export, import and events, and the rest of the split has never been
written down.

Everything from section 4 on is measured against a live
`quay.io/keycloak/keycloak:26.7.1 start-dev` on 2026-08-29, on port 8084, with
every transcript printed from the same argv that was executed.

## 2. The split, per operation

| Operation | Built by | Why |
|---|---|---|
| `GET /admin/realms` | **P4** | the realm as a resource |
| `POST /admin/realms` | **P4** | |
| `GET /admin/realms/{realm}` | **P4** | |
| `PUT /admin/realms/{realm}` | **P4** | |
| `DELETE /admin/realms/{realm}` | **P4** | |
| `GET /admin/realms/{realm}/keys` (`Key`) | **P4** | the realm's key set; four keys, not two |
| `GET /admin/realms/{realm}/default-groups` | **P4** | realm-level default, needs P2's groups |
| `PUT`/`DELETE .../default-groups/{groupId}` | **P4** | |
| `GET /admin/realms/{realm}/group-by-path/{path}` | **P4** | a `Groups` read tagged `Realms Admin` |
| `GET`/`PUT .../client-policies/policies` | **P4** | see below |
| `GET`/`PUT .../client-policies/profiles` | **P4** | see below |
| `GET`/`PUT .../client-types` | **P4** | see below |
| `GET .../default-default-client-scopes` | P5 | client scopes |
| `PUT`/`DELETE .../default-default-client-scopes/{clientScopeId}` | P5 | |
| `GET .../default-optional-client-scopes` | P5 | |
| `PUT`/`DELETE .../default-optional-client-scopes/{clientScopeId}` | P5 | |
| `POST .../client-description-converter` | P5 | client registration |
| `GET .../credential-registrators` | P8 | the authentication engine's credential providers |
| `GET .../client-session-stats` | P6 | sessions |
| `POST .../logout-all` | P6 | |
| `POST .../push-revocation` | P6 | |
| `DELETE .../sessions/{session}` | P6 | |
| `GET`/`PUT .../users-management-permissions` | P10 | fine-grained admin permissions, like the two `Groups` `management/permissions` operations P2 excluded |
| `GET .../localization` | P13 | i18n |
| `GET`/`DELETE`/`POST .../localization/{locale}` | P13 | |
| `GET`/`PUT`/`DELETE .../localization/{locale}/{key}` | P13 | |
| `GET`/`DELETE .../events` | P14 | the roadmap says so |
| `GET`/`PUT .../events/config` | P14 | |
| `GET`/`DELETE .../admin-events` | P14 | |
| `POST .../partial-export` | P14 | |
| `POST .../partialImport` | P14 | |
| `POST .../testSMTPConnection` | P14 | SMTP |

5 + 1 + 4 + 6 = **16 for P4**; 6 + 1 = 7 for P5, 1 for P8, 4 for P6, 2 for P10,
7 for P13, 9 for P14. 16 + 30 = 46.

**Two rows in that table are this document's judgement and not the roadmap's.**
Client policies, client profiles and client types are realm-level configuration
served off the realm resource, and no sub-project in the roadmap claims them.
They are put in P4 because that is where the state lives, not because anything
in section 4 of the roadmap says so. If P5 wants them when it gets there, moving
them costs a line in this table and nothing else.

`credential-registrators` is the other judgement call: it lists the credential
provider types the realm can register, which is the authentication engine's
inventory, so it is P8's even though it is read through the realm.

## 3. Three cuts, in dependency order

**Cut A, the realm as a resource - 5 operations.** `GET`/`POST /admin/realms`
and `GET`/`PUT`/`DELETE /admin/realms/{realm}`, plus whatever a new realm has to
be bootstrapped with. Nothing else in P4 can start without it, and it is where
the work is: `internal/bootstrap` creates `master` and nothing else today, the
representation is 104 keys, and section 7's admin containers do not exist in the
model at all.

**Cut B, the realm's keys - 1 operation.** `GET /admin/realms/{realm}/keys`. A
fresh realm carries **four** keys where Gloak models two, so this is a key
manager change and not a handler.

**Cut C, the realm-level defaults - 10 operations.** Default groups, group by
path, client policies, client profiles, client types. Each is a small read/write
pair over state the realm row already holds once Cut A exists.

The order is forced: B and C both address a realm that Cut A has to be able to
create.

## 4. The representation, and there are five of them

Recorded 2026-08-29 from `POST /admin/realms -d '{"realm":"p4a"}'` followed by
`GET /admin/realms/p4a`. The key order is part of the contract.

### 4.1 The full read - 104 keys

`Content-Type: application/json;charset=UTF-8`, `Cache-Control: no-cache`, and
the five security headers.

```json
{"id":"eb495f2c-32b0-4648-baa9-2f080981ee27","realm":"p4a","notBefore":0,"defaultSignatureAlgorithm":"RS256","revokeRefreshToken":false,"refreshTokenMaxReuse":0,"accessTokenLifespan":300,"accessTokenLifespanForImplicitFlow":900,"ssoSessionIdleTimeout":1800,"ssoSessionMaxLifespan":36000,"ssoSessionIdleTimeoutRememberMe":0,"ssoSessionMaxLifespanRememberMe":0,"offlineSessionIdleTimeout":2592000,"offlineSessionMaxLifespanEnabled":false,"offlineSessionMaxLifespan":5184000,"clientSessionIdleTimeout":0,"clientSessionMaxLifespan":0,"clientOfflineSessionIdleTimeout":0,"clientOfflineSessionMaxLifespan":0,"accessCodeLifespan":60,"accessCodeLifespanUserAction":300,"accessCodeLifespanLogin":1800,"actionTokenGeneratedByAdminLifespan":43200,"actionTokenGeneratedByUserLifespan":300,"oauth2DeviceCodeLifespan":600,"oauth2DevicePollingInterval":5,"enabled":false,"sslRequired":"external","registrationAllowed":false,"registrationEmailAsUsername":false,"rememberMe":false,"verifyEmail":false,"loginWithEmailAllowed":true,"duplicateEmailsAllowed":false,"resetPasswordAllowed":false,"editUsernameAllowed":false,"bruteForceProtected":false,"permanentLockout":false,"maxTemporaryLockouts":0,"bruteForceStrategy":"MULTIPLE","maxFailureWaitSeconds":900,"minimumQuickLoginWaitSeconds":60,"waitIncrementSeconds":60,"quickLoginCheckMilliSeconds":1000,"maxDeltaTimeSeconds":43200,"failureFactor":30,"maxSecondaryAuthFailures":0,"defaultRole":{"id":"145503e4-0d25-4145-a2f9-b4e9a59c1783","name":"default-roles-p4a","description":"${role_default-roles}","composite":true,"clientRole":false,"containerId":"eb495f2c-32b0-4648-baa9-2f080981ee27"},"requiredCredentials":["password"],"otpPolicyType":"totp","otpPolicyAlgorithm":"HmacSHA1","otpPolicyInitialCounter":0,"otpPolicyDigits":6,"otpPolicyLookAheadWindow":1,"otpPolicyPeriod":30,"otpPolicyCodeReusable":false,"otpSupportedApplications":["totpAppFreeOTPName","totpAppGoogleName","totpAppMicrosoftAuthenticatorName"],"webAuthnPolicyRpEntityName":"keycloak","webAuthnPolicySignatureAlgorithms":["ES256","RS256"],"webAuthnPolicyRpId":"","webAuthnPolicyAttestationConveyancePreference":"not specified","webAuthnPolicyAuthenticatorAttachment":"not specified","webAuthnPolicyRequireResidentKey":"not specified","webAuthnPolicyResidentKey":"not specified","webAuthnPolicyUserVerificationRequirement":"not specified","webAuthnPolicyCreateTimeout":0,"webAuthnPolicyAvoidSameAuthenticatorRegister":false,"webAuthnPolicyAcceptableAaguids":[],"webAuthnPolicyExtraOrigins":[],"webAuthnPolicyPasswordlessRpEntityName":"keycloak","webAuthnPolicyPasswordlessSignatureAlgorithms":["ES256","RS256"],"webAuthnPolicyPasswordlessRpId":"","webAuthnPolicyPasswordlessAttestationConveyancePreference":"not specified","webAuthnPolicyPasswordlessAuthenticatorAttachment":"not specified","webAuthnPolicyPasswordlessRequireResidentKey":"not specified","webAuthnPolicyPasswordlessResidentKey":"required","webAuthnPolicyPasswordlessUserVerificationRequirement":"required","webAuthnPolicyPasswordlessCreateTimeout":0,"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister":false,"webAuthnPolicyPasswordlessAcceptableAaguids":[],"webAuthnPolicyPasswordlessExtraOrigins":[],"browserSecurityHeaders":{"contentSecurityPolicyReportOnly":"","xContentTypeOptions":"nosniff","referrerPolicy":"no-referrer","xRobotsTag":"none","xFrameOptions":"SAMEORIGIN","contentSecurityPolicy":"frame-src 'self'; frame-ancestors 'self'; object-src 'none';","strictTransportSecurity":"max-age=31536000; includeSubDomains"},"smtpServer":{},"eventsEnabled":false,"eventsListeners":["jboss-logging"],"enabledEventTypes":[],"adminEventsEnabled":false,"adminEventsDetailsEnabled":false,"internationalizationEnabled":false,"browserFlow":"browser","registrationFlow":"registration","directGrantFlow":"direct grant","resetCredentialsFlow":"reset credentials","clientAuthenticationFlow":"clients","dockerAuthenticationFlow":"docker auth","firstBrokerLoginFlow":"first broker login","attributes":{"cibaBackchannelTokenDeliveryMode":"poll","cibaExpiresIn":"120","cibaAuthRequestedUserHint":"login_hint","oauth2DeviceCodeLifespan":"600","oauth2DevicePollingInterval":"5","parRequestUriLifespan":"60","cibaInterval":"5","realmReusableOtpCode":"false"},"userManagedAccessAllowed":false,"organizationsEnabled":false,"verifiableCredentialsEnabled":false,"adminPermissionsEnabled":false,"scimApiEnabled":false,"clientProfiles":{"profiles":[]},"clientPolicies":{"policies":[]}}
```

`master` is the same 104 keys plus `displayName` and `displayNameHtml`, inserted
after `realm`, and differs in one value: `accessTokenLifespan` is **60** where a
created realm's is **300**. Gloak's `internal/bootstrap` already pins master's
60; a created realm must not inherit it.

`master`'s `attributes` has **six** keys and `p4a`'s has **eight**: a created
realm carries `oauth2DeviceCodeLifespan` and `oauth2DevicePollingInterval` as
string attributes as well as as top-level integers, and master does not.
Duplicated state that disagrees between two realms of the same version, and it
is observable.

### 4.2 The single read has three shapes, decided by the caller

Measured on `p4e`, one caller per role, a fresh token minted immediately before
every call. A caller without `view-realm` on that realm's container gets a
**shorter body**, not a refusal.

```json
view-realm | manage-realm | realm-admin
{...the 104 keys above...}

view-users | manage-users
{"realm":"p4e","displayName":"Realm E","displayNameHtml":"<b>E</b>","registrationEmailAsUsername":false,"bruteForceProtected":false,"supportedLocales":[],"organizationsEnabled":false}

the other sixteen admin roles
{"realm":"p4e","displayName":"Realm E","displayNameHtml":"<b>E</b>","bruteForceProtected":false,"supportedLocales":[],"organizationsEnabled":false}
```

All three carry `Content-Type: application/json;charset=UTF-8` and
`Cache-Control: no-cache`. `displayName` and `displayNameHtml` are present only
when set, in all three.

**`supportedLocales` appears in the two short shapes and not in the long one.**
The full 104-key body has no `supportedLocales` key at all when
`internationalizationEnabled` is false; the short bodies emit `[]`. A shared
serialiser with `omitempty` produces neither correctly.

The five-key shape differs from the four-key one by exactly
`registrationEmailAsUsername`, and only the two users-family roles earn it.

### 4.3 The listing has two more shapes

`GET /admin/realms` returns an **array of full representations** by default -
`briefRepresentation` defaults to false here, the opposite of the role listings.

```
?briefRepresentation=true
[{"id":"...","realm":"p4b","enabled":true},
 {"id":"...","realm":"master","displayName":"Keycloak","displayNameHtml":"<div class=\"kc-logo-text\"><span>Keycloak</span></div>","enabled":true}]
```

A caller without `view-realm` gets a **one-key** entry:

```
[{"realm":"p4e"}]
```

and `briefRepresentation` does nothing to it - absent and `true` gave
byte-identical bodies. So one parameter, three answers, which is the third time
this API has done that; `briefRepresentation` on a role mapping was the second.

The listing is `transfer-encoding: chunked`, `Content-Type:
application/json;charset=UTF-8`, `Cache-Control: no-cache`.

## 5. What a created realm is bootstrapped with

`internal/bootstrap` creates these for `master` today and for nothing else. A
created realm gets its own set, and it is **not** the same set.

**Six clients**: `account`, `account-console`, `admin-cli`, `broker`,
`realm-management`, `security-admin-console`. Five of the six are master's; the
sixth is `realm-management` where master has `master-realm`.

**Three realm roles**, not five:

```
default-roles-p4a  ${role_default-roles}      composite
offline_access     ${role_offline-access}
uma_authorization  ${role_uma_authorization}
```

`admin` and `create-realm` exist in `master` alone.

**`default-roles-p4a`** is composite over `offline_access`, `uma_authorization`
and the `account` client's `manage-account` and `view-profile` - the same four
master's is.

**`realm-management` owns 22 roles**, where `master-realm` owns 21. The extra
one is `realm-admin`, composite over the other 21. `view-clients`,
`view-users` and `view-organizations` carry the same composites they do in
master.

**No users.** A created realm has none, so there is no administrator inside it
until somebody makes one.

**Four keys**, where Gloak models two:

```
RSA / RS256    SIG   with a self-signed certificate whose CN is the realm name
RSA / RSA-OAEP ENC   with its own certificate
OCT / HS512    SIG
OCT / AES      ENC
```

**And a seventh client, in `master`.** Creating `p4a` creates a client
`p4a-realm` in the **master** realm, bearer-only, named `p4a Realm`, owning the
**21** admin roles - no `realm-admin`. Its `defaultClientScopes` and
`optionalClientScopes` are `[]`, where `master-realm`'s carry the usual six and
five.

**And it edits master's `admin` role.** The realm role `admin` in `master` gains
all 21 roles of the new container as composites: 22 composites on a fresh
install, 43 after one realm is created, 127 after five. Deleting the realm
removes the client and takes the 21 composites back out again - 127 down to 106,
measured on the same container.

That last one is the finding that costs the most. `internal/bootstrap`'s
boundary in AGENTS.md says it "must not modify objects that already exist", and
creating a realm modifies `master`'s `admin` role. The boundary has to move or
the work has to move out of `bootstrap`; section 9 says which.

## 6. Twelve behaviours that look like bugs and are not

Each is measured, and each would be tidied up by a careful implementer.

**A created realm is disabled.** `POST /admin/realms -d '{"realm":"p4a"}'`
answers 201 and the realm comes back `"enabled":false`. The `enabled` field has
no default; a body that does not say so creates a realm nobody can log into.

**`PUT` merges, and it can rename the realm.** A body of `{}` answers 204 and
changes nothing. A body naming only `enabled` leaves a previously set
`displayName` in place. A `null` is ignored where an empty string is written -
`{"displayName":null}` left `Set` in place and `{"displayName":""}` produced
`"displayName":""` in the body. And `PUT /admin/realms/p4a -d '{"realm":"p4z"}'`
answers 204 and **renames the realm**, keeping its id: `GET /admin/realms/p4a`
is then 404 and `GET /admin/realms/p4z` is 200. So the path segment and the
body's `realm` are not required to agree, and when they disagree the body wins.
This is the opposite of `PUT` on a role, which replaces, and the same as `PUT`
on a client or a user, which merges - and neither of those can rename through a
`PUT`. A user's username explicitly cannot. Renaming onto a taken name is 409
`{"errorMessage":"Realm with same name exists"}`, which is **not** the wording
`POST` uses for the same collision.

**`attributes` is the one field `PUT` replaces**, and it is not replaced
cleanly. A realm created with `{"a":"1","b":"2"}` carried those two plus the
eight defaults. `PUT {"attributes":{"c":"3"}}` left `c` and the seven derived
policy attributes and dropped `a`, `b` **and `realmReusableOtpCode`** - so the
result is neither what was sent nor what was there. Serving a plain map merge or
a plain map replace both diverge.

**`PUT` and `POST` answer the same malformed body in two different error
families.** On one resource:

```
POST /admin/realms  -d 'nope'  -> 400 {"errorMessage":"unable to read contents from stream"}
PUT  /admin/realms/x -d 'nope' -> 400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
```

and with no body at all, `POST` is a 400 and `PUT` is a **500**
`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`.
Four shapes for two verbs of one resource.

**An unrecognised field is a 400 carrying a Jackson message with a line and
column in it.**

```
PUT /admin/realms/x -d '{"nosuchfield":true}'
400 {"error":"Invalid json representation for RealmRepresentation. Unrecognized field \"nosuchfield\" at line 1 column 20."}
```

The column number is a function of the request body, so this is the first
measured admin error whose text a client can move by reformatting its JSON.

**`POST` with no `Content-Type` is a 415**, not a 400:
`{"error":"The content-type header value did not match the value in @Consumes"}`.

**The realm listing is not sorted.** Ten realms came back
`probe-new-3, p4id, p4off, p4c, p4e, p4put, master, p4rich, p4a, p4d` - neither
alphabetical nor creation order - and identically on a second call. Like the
role listings, so the cases need `Case.Unordered`.

**`POST` honours an `id` in the body.** `{"id":"1111...","realm":"p4id"}` creates
a realm with that exact id. The `Location` header still names the realm, not the
id: `http://localhost:8084/admin/realms/p4id`.

**`POST`'s `attributes` merge with the defaults rather than replacing them.** A
create carrying `{"attributes":{"custom":"yes"}}` comes back with the eight
default attribute keys **and** `custom`.

**The single read answers a weaker caller with a shorter body, not a 403.** Two
short shapes, section 4.2. An `available`-style retreat that P2 already met on
the role mappings; here it is the primary read of the resource.

**`impersonation` is the one admin role that closes the realm read.** Twenty of
the 21 open it - `create-client`, `query-groups`, `view-events`, everything -
and `impersonation` answers 403, the same as a caller holding no admin role at
all. There is no rule behind that which the name predicts; only the sweep says
so.

**`DELETE /admin/realms/master` is a 400, not a 403 or a 409.**
`{"errorMessage":"Can't remove master realm"}`, with an apostrophe and no full
stop.

**A disabled realm still serves `GET /realms/{realm}`** on the protocol side,
200 with its public key. `enabled:false` does not take the realm off the
network.

**`POST` and `PATCH` on the same path answer different statuses, and it is not
the rule F31 wrote down.** On `/admin/realms/{realm}`, `POST` answers 404
`{"error":"HTTP 404 Not Found"}` and `PATCH` answers 405
`{"error":"HTTP 405 Method Not Allowed"}`. On `/admin/realms`, **`DELETE`
answers 405** - and F31 recorded `DELETE` answering 404 on the role-mapping
paths. So "the verb decides" is refuted by one request. Neither the path nor the
verb explains all four; see section 10.

## 7. The guards, and master is the special case

One caller per role, a fresh token minted immediately before every call, against
a realm `p4d` created for the sweep. The container is `realm-management` for a
token issued by `p4d` and `{realm}-realm` in `master` for a token issued by
`master`.

| role | `GET /realms/{r}` | listing entry | `PUT` | `DELETE` |
|---|---|---|---|---|
| `view-realm` | 200 full | full | 403 | - |
| `manage-realm` | 200 full | full | **204** | **204** |
| `realm-admin` | 200 full | full | **204** | 204 |
| `view-users` | 200 five-key | `{"realm":...}` | 403 | - |
| `manage-users` | 200 five-key | `{"realm":...}` | 403 | - |
| `create-client` | 200 four-key | `{"realm":...}` | 403 | - |
| `manage-authorization` | 200 four-key | `{"realm":...}` | 403 | - |
| `manage-clients` | 200 four-key | `{"realm":...}` | 403 | - |
| `manage-events` | 200 four-key | `{"realm":...}` | 403 | - |
| `manage-identity-providers` | 200 four-key | `{"realm":...}` | 403 | - |
| `manage-organizations` | 200 four-key | `{"realm":...}` | 403 | - |
| `query-clients` | 200 four-key | `{"realm":...}` | 403 | - |
| `query-groups` | 200 four-key | `{"realm":...}` | 403 | - |
| `query-organizations` | 200 four-key | `{"realm":...}` | 403 | - |
| `query-realms` | 200 four-key | `{"realm":...}` | 403 | - |
| `query-users` | 200 four-key | `{"realm":...}` | 403 | - |
| `view-authorization` | 200 four-key | `{"realm":...}` | 403 | - |
| `view-clients` | 200 four-key | `{"realm":...}` | 403 | - |
| `view-events` | 200 four-key | `{"realm":...}` | 403 | - |
| `view-identity-providers` | 200 four-key | `{"realm":...}` | 403 | - |
| `view-organizations` | 200 four-key | `{"realm":...}` | 403 | - |
| **`impersonation`** | **403** | **403** | 403 | - |
| no admin role | 403 | 403 | 403 | - |

`POST /admin/realms` is different again: it takes the **realm role
`create-realm`** in `master`, and nothing else. `manage-realm` is 403 on it,
`realm-admin` is 403 on it, and a `create-realm` holder is 403 on the realm
**listing** while getting 200 on the single read - so the collection's two verbs
disagree about who may use them, in both directions.

### 7.1 Do a caller's rights in one realm reach another? Yes, once, and only
downwards

This is the question the sub-project turns on, so it was measured four ways.

**From master, the reduced read reaches every realm.** A master caller holding
`view-users` on `master-realm` and nothing else reads `p4e` with 200 and the
four-key body. So does one holding only the realm role `create-realm`. The
listing does **not**: the same caller sees `[{"realm":"master"}]` and `p4e` is
absent from it.

**From master, nothing else reaches.** That caller gets 403 on
`/admin/realms/p4e/users`, `/clients` and `/roles`, and 200 on
`/admin/realms/master/users`.

**The mirror holds.** A master caller holding `view-users` on **`p4e-realm`**
gets 200 on `/admin/realms/p4e/users`, 403 on `/admin/realms/master/users`, and
`[{"realm":"p4e"}]` from the listing.

**Upwards, nothing reaches at all.** A caller inside `p4e` holding
`realm-admin` - the strongest role that realm has - gets **403** on
`/admin/realms/master` and on `/admin/realms/p4a`. Not a reduced body: a
refusal.

So the rule is: **every route resolves the caller's rights against exactly one
container - `{realm}-realm` in `master` for a master-issued token,
`realm-management` in the realm itself for a realm-issued one - and the single
realm read is the one place a master caller's rights leak sideways, and only in
its shortest form.**

The admin token carries none of this. `iss` is the issuing realm's, `aud` is
absent and `resource_access` is empty, because `admin-cli` is a lightweight
client. The roles are resolved from storage at request time, which is what
`internal/roles` already does.

### 7.2 The ordering: the realm comes first, before anybody is judged

Measured on seven callers including one holding no admin role at all:

```
GET|PUT|DELETE /admin/realms/nosuchrealm  ->  404 {"error":"Realm not found."}
```

Every caller, every verb. A realm that **does** exist and the caller may not see
answers 403. So the resource is resolved before the authorization question, the
same order `guardGroup` and `guardByRoleContainer` already record, and the
opposite of the users family's coarse gate. It does leak which realm names
exist to an authenticated caller with no rights at all.

`Realm not found.` keeps its full stop, as AGENTS.md records, and the protocol
side keeps its own spelling `Realm does not exist` without one.

## 8. The error shapes, and there are two families again

```
POST   /admin/realms, duplicate          -> 409 {"errorMessage":"Realm p4a already exists"}
POST   /admin/realms, {"realm":"master"} -> 409 {"errorMessage":"Realm master already exists"}
POST   /admin/realms, {}                 -> 400 {"errorMessage":"Realm name cannot be empty"}
POST   /admin/realms, no body            -> 400 {"errorMessage":"unable to read contents from stream"}
POST   /admin/realms, not JSON           -> 400 {"errorMessage":"unable to read contents from stream"}
POST   /admin/realms, no Content-Type    -> 415 {"error":"The content-type header value did not match the value in @Consumes"}
PUT    /admin/realms/{r}, not JSON       -> 400 {"error":"invalid_request","error_description":"Cannot parse the JSON"}
PUT    /admin/realms/{r}, no body        -> 500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
PUT    /admin/realms/{r}, unknown field  -> 400 {"error":"Invalid json representation for RealmRepresentation. Unrecognized field \"nosuchfield\" at line 1 column 20."}
PUT    /admin/realms/{r}, name taken     -> 409 {"errorMessage":"Realm with same name exists"}
GET|PUT|DELETE /admin/realms/{gone}      -> 404 {"error":"Realm not found."}
DELETE /admin/realms/master              -> 400 {"errorMessage":"Can't remove master realm"}
any route, no or bad token               -> 401 {"error":"HTTP 401 Unauthorized"}
any route, wrong role                    -> 403 {"error":"HTTP 403 Forbidden"}
POST   /admin/realms/{realm}             -> 404 {"error":"HTTP 404 Not Found"}
PATCH  /admin/realms/{realm}             -> 405 {"error":"HTTP 405 Method Not Allowed"}
PUT|DELETE /admin/realms                 -> 405 {"error":"HTTP 405 Method Not Allowed"}
```

The four `errorMessage` bodies are `POST`'s two 409s, its 400s and the master
delete; every other one uses `error` or the RFC 6749 shape. Same resource,
**three** families, where clients, users and groups have two. None of the
`errorMessage` bodies ends in a full stop and `Realm not found.` does.

**`POST`'s malformed body and `PUT`'s are different errors.** `unable to read
contents from stream` on `POST` is a fourth spelling of "cannot parse the JSON":
`POST /users` says `invalid_request` with `Cannot parse the JSON`, the ten
role-array endpoints say `unknown_error` with the same description, `PUT
/admin/realms/{r}` says `invalid_request` with `Cannot parse the JSON` - and
`POST /admin/realms` says none of them. A shared decoder gets three of the four
wrong.

The 201 carries `Location: {issuer}/admin/realms/{realm}`, an empty body and
`content-length: 0`. The 204s from `PUT` carry the five security headers
including `X-Frame-Options`, because the request declared `application/json`;
the 204 from `DELETE` carries neither it nor `Cache-Control`, because a `DELETE`
sends no `Content-Type`. That is `httpx.WriteNoContent`'s existing rule and this
sub-project does not change it.

## 9. What has to change inside Gloak

**`internal/bootstrap` becomes realm-parameterised, and its boundary moves.**
`EnsureMaster` becomes two things: the master-only part (the `admin` and
`create-realm` realm roles, the `master-realm` container, the administrator
account) and a `CreateRealm` that both it and the Admin API call. The AGENTS.md
boundary "must not modify objects that already exist" is contradicted by the
measured behaviour in section 5 - creating a realm edits master's `admin` role -
so the boundary line has to be rewritten rather than worked around, and the
rewrite must say which object may be modified and why.

**The admin role container stops being a constant, and this is the dangerous
one.** `adminRoleContainer = "master-realm"` becomes a function of the realm:
`realm-management` inside a non-master realm, `{realm}-realm` in master. Both
exist for one realm at once and they hold different role sets - 22 and 21.

`internal/admin/roles.go`'s `ownedByRealmOwnClient` already says so in a comment
written before this cut: it tests `realm.Name + "-realm"` and warns that "when
Realms Admin lands, every admin role outside master would silently answer false
here and become grantable to anyone." That is F32's escalation reappearing by a
different route, and it is not hypothetical - the predicate is what
`adminRoleNames` reduces the caller's own roles with, so a `realm-management`
role answering false makes the caller's rights invisible to every guard **and**
makes those roles handable out by anybody. The same test is in
`representation.go`'s `clientAccessFor`. Both move in this cut or neither does.

**The guard resolves rights against a container chosen by the token's realm, not
by the route's.** `resolveCaller` today reads the caller out of the realm named
in the path. It has to read it out of the realm that **issued the token** and
then look up the container for the realm named in the path. That is the single
largest change in the package and it touches every existing admin route, which
is why Cut A has to prove it against the whole existing conformance suite rather
than only the new cases.

**Realm keys become four per realm.** `internal/keys` mints RS256 and HS512
today. `GET /admin/realms/{realm}/keys` needs RSA-OAEP and AES as well, each
with its own kid, and the two RSA keys each with a self-signed certificate whose
CN is the realm name. That is Cut B, and Cut A must not invent them.

**The conformance fixtures assume `master`.** Every existing case is against
`master` and many carry `PristineRealm: true`. A cut that creates a second realm
inside a shared server has to prove it does not perturb them.

## 10. What this document does not decide

**Whether the realm row stores the 104 fields or a JSON blob.** Nothing
observable depends on it. The plan takes the decision; the argument is that a
column per field is 104 columns across two drivers for state P4 does not
interpret, against a blob that cannot be queried. The measured contract is the
same either way.

**How master's `admin` composite is kept in step.** Section 5 measured that it
gains 21 composites per realm created and loses them on delete. Whether Gloak
stores those rows or derives them at read time is undecided, and the observable
that would settle it - what `GET /admin/realms/master/roles/admin/composites`
answers - is a `Roles` operation P2 already serves, so the choice is
constrained by an existing golden and not free.

**The 405/404 rule.** Section 6's last entry shows F31's "the verb decides" is
wrong: `DELETE` answers 404 on a role-mapping path and 405 on `/admin/realms`.
What the rule actually is remains unmeasured. Gloak answers 404 everywhere
today; this document adds a second counter-example and does not fix it. It
belongs in F31.

**Which sub-project owns client policies, client profiles and client types.**
Section 2 assigns them to P4 and says it is a judgement.

**Everything a realm's 104 fields mean.** Cut A serves them at their measured
defaults and lets `PUT` change them. Whether `bruteForceProtected` does anything
is P8's question, whether `smtpServer` does anything is P14's, and whether
`otpPolicyType` does anything is P8's. Serving a field is not implementing it,
and this document does not claim otherwise.

**Whether a created realm's `VERIFY_PROFILE` required action is reproduced.** It
is not measured as part of P4 and it bit the measurement: a user created in a
new realm with no email, first name or last name cannot obtain a token at all -
`{"error":"invalid_grant","error_description":"Account is not fully set up"}` -
where the same user in `master` can. Every P4 probe therefore creates callers
with a complete profile. Whether Gloak reproduces that refusal is P8's, and
until it does, Gloak is measurably more permissive than Keycloak on one path.
