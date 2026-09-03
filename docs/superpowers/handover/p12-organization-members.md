# P12 second cut: an organization's members, invitations and identity providers

Branch `feat/p12-organization-members`. Measured against a live Keycloak 26.7.1
on 2026-09-02 and 2026-09-03, container `kc-org` on `:8160`, started
`quay.io/keycloak/keycloak:26.7.1 start-dev` with no feature flags and removed
afterwards.

**Organizations were turned on through the API**, not through a container flag:
`POST /admin/realms` with `{"realm":"gloak-org-probe","enabled":true}`, then a
`GET` of the realm representation, `organizationsEnabled` set to `true`, and a
`PUT` back. Master's own flag was never touched, and the destructive half - the
role sweep, the SMTP configuration, the user-profile edits - all ran inside the
created realm.

Two things were needed to measure this tag at all and neither is a container
flag:

- **A mail sink.** Both invite endpoints send an e-mail and a realm with no
  `smtpServer` answers 500, so the invitation family cannot be seen. A
  thirty-line SMTP server on the host, reached from the container at
  `host.docker.internal:2525`, made the whole family visible. §1.6 is what it
  showed.
- **A socket.** Python's `urllib` adds `Content-Type:
  application/x-www-form-urlencoded` to any POST carrying data that does not
  already name one. Every "no Content-Type" probe in the first half of this cut
  measured a header it had set itself, and the rule that came out was backwards.
  See §1.9 - it is the most expensive mistake in this cut and it was caught by
  the recorder, not by a person.

---

## 1. Measurements

### 1.1 What a member is, and what the create takes

**A member is a user, addressed by the user's own id.** There is no membership
id and no second identity: `POST .../members` carrying a user id answers 201
with a `Location` ending in **that same id**, the single read addresses the user
by it, the representation's `id` is the user's, and `DELETE /users/{id}` makes
the member vanish. That makes it the sixteenth create measured for AGENTS.md's
`Location` bullet and the **fifth whose tail the caller chose**, which is a new
kind: the other four are names, this one is an id the caller sent in the body.

**The body is the user id as raw bytes and it is not JSON.** Measured over ten
bodies:

```
"2a04b3cf-…"           201   a JSON string
2a04b3cf-…             201   no quotes at all - not valid JSON
"2a04b3cf-…            201   one leading quote
2a04b3cf-…"            201   one trailing quote
  2a04b3cf-…           201   surrounding spaces, and tabs likewise
2a04b3cf-…\n           201   a trailing newline
2a04b3c"f-…            404   a quote in the middle
""2a04b3cf-…""         404   two quotes at each end
'2a04b3cf-…'           404   single quotes
["2a04b3cf-…"]         404   a JSON array of one
{"id":"2a04b3cf-…"}    404   a UserRepresentation
"gloak-probe-user-x"   404   the username instead of the id
```

The rule those twelve agree on: **trim whitespace, then strip at most one `"`
from each end**. `""x""` failing is what says "at most one"; the mid-string quote
failing is what says "at the ends". `json.Unmarshal` into a string is right on
the first row and wrong on the four below it that succeed.

That decides the schema: one table, `(organization_id, user_id)`, no id of its
own, no created date - the representation's `createdTimestamp` is the **user's**.

### 1.2 One user now serialises five ways

AGENTS.md records three. The member family adds two more:

```
GET .../members                 id username [firstName] [lastName] [email]
                                emailVerified [attributes] enabled
                                createdTimestamp membershipType
GET .../members?brief=false     … the same … totp disableableCredentialTypes
GET .../members/{member-id}     requiredActions notBefore membershipType
```

The single read is **byte-identical** to a `briefRepresentation=false` listing
entry, checked as bytes. Neither carries the `access` block, and neither carries
the `federatedIdentities` key `GET /users/{id}` has. `briefRepresentation`
defaults to **true** on the listing and is **ignored** by the single read -
which is the organization pair's rule one path segment up, reproduced.

### 1.3 The member listing pages by default, and its `search` is a third rule

**No other listing in this API bounds itself when asked for nothing.**

```
no parameters      10 rows of 12       max defaults to 10, first to 0
max=100            12
max=-1             12                  a negative bound means no bound
first=-1           10                  …and first falls back to 0
max=0              0
max=abc            404 {"error":"HTTP 404 Not Found"}
```

`search` matches `username`, `firstName`, `lastName` and `email` as a
**case-insensitive substring**, and not the id. The pair that separates it from
the user listing was issued on one container against one realm:

```
GET /organizations/{org}/members?search=lm-03   matched gloak-probe-lm-03
GET /users?search=lm-03                          []
```

So the user listing's `search` is a prefix (`term` becomes `term%`) and this one
is an infix (`%term%`). `*` is the wildcard and becomes `%`; `%` and `_` are
literals; and **`"quotes"` do not mean equality here**, where they do on the
user listing - `search="gloak-probe-lm-03"` answered `[]`.

`exact=true` compares the whole value against each of the same four fields, and
`exact=bogus` behaves as `false`. `membershipType` filters and an unknown value
is a **500** `unknown_error` - Jackson refusing to bind the enum, the same shape
the invitation `status` parameter has.

**`GET .../members/count` reads none of them.** `?search=lm-03` and
`?membershipType=MANAGED` both answered `12` on a twelve-member organization
whose listing answered one row and none. The organization count one path segment
up honours its own `search`, so the two counts on this resource disagree about
whether a count is filtered.

The listing is **sorted by username**, measured on a set whose username order
and e-mail order deliberately disagree, and reproducibly so.

### 1.4 The two `.../organizations` reads are twins that disagree twice

Both serve the **brief organization shape** and honour `briefRepresentation`
(false adds `attributes`, in `javamap.KeyOrder`'s order). For a member their
bodies are byte-identical. They differ in two places:

```
                                                    a non-member   an unknown id
/organizations/{org}/members/{id}/organizations      404            404
/organizations/members/{id}/organizations            200 []         404
```

and in their guards (§1.5). Their order is **not** explained: four organizations
came back `mm, zz, aa, fin` on four consecutive reads - neither insertion, nor
name, nor organization id, nor the reverse of any of them. Reproducible within
one container and explained by nothing.

### 1.5 The guards are conjunctions, and there are five of them

Measured with a token minted per caller, one user per role set, in the created
realm, against every route. `mr` is `manage-realm`, `vo`/`mo`/`qo` the
organization roles, `vu`/`mu`/`qu` the user roles, `vip`/`mip` the identity
provider pair.

```
GET  members, members/count            (vo|mo|mr) AND (vu|mu|qu)
GET  members/{id}, /groups, /organizations
                                       (vo|mo|mr) AND (vu|mu)
GET  organizations/members/{id}/organizations
                                       (vo|mo|mr|qo) AND (vu|mu)
POST members, DELETE members/{id}      (mo|mr)     AND mu
invite-user, invite-existing-user      (mo|mr)     AND mu
GET/DELETE/resend invitations, GET invitations
                                       (mo|mr)                  no user role
GET  identity-providers ×3             (vo|mo|mr) AND (vip|mip)
POST/DELETE identity-providers         (mo|mr)     AND mip
```

Four of those are findings rather than bookkeeping:

- **No single role opens any of the nineteen routes.** `manage-organizations`
  alone is 403 on every member route; so is `manage-users` alone. This is the
  second endpoint family in the API to need a conjunction, after
  `/roles/{name}/users`, and the first where the conjunction is the rule for a
  whole tag rather than for one route among four that look identical.
- **`query-users` opens the listing and the count and nothing else**, which is
  `GET /users`' role set against `GET /users/{id}`'s, one tag away.
- **`query-organizations` opens the top-level `.../organizations` read and not
  its org-scoped twin.** Two routes serving byte-identical bodies, two guards.
- **The invitation reads refuse the view role.** `view-organizations` is 403 on
  `GET .../invitations` and `manage-organizations` alone is 200. AGENTS.md
  records exactly two reads in the whole API that need a manage role; this adds
  two more.

`view-realm` reaches nothing in this tag. The order is uniform and matches the
first cut: authenticate, realm, roles, `organizationsEnabled`, organization. On
an org id that resolves to nothing a full administrator gets
`404 {"errorMessage":"Organization not found."}` and a caller holding no role
gets 403, on all eighteen org-scoped routes; with the flag off every route
including the top-level one answers the not-enabled 404.

### 1.6 The invitation family, seen populated

On a default container **no invitation can exist**: both invite endpoints send
an e-mail and a realm with no `smtpServer` answers
`500 {"errorMessage":"Failed to send invite email"}` - the contract, the same
shape as `VERIFY_EMAIL`'s 500 and CIBA's 503. A realm whose configured server
cannot be reached answers the same 500.

With a mail sink the container could reach, the family is:

```json
{"id":"98a93ddd-…","organizationId":"1e5a152b-…","email":"newone@inv.example.com",
 "firstName":"New","lastName":"One","sentDate":1788420203,"expiresAt":1788463403,
 "status":"PENDING","inviteLink":"http://…"}
```

- **`sentDate` and `expiresAt` are seconds**, where a user's `createdTimestamp`
  is milliseconds. `expiresAt - sentDate` is 43200.
- **The `id` is the invite token's `jti`.** The token is HS512, `typ` is
  `ORGIVT`, and it carries `eml`, `reduri` and `org_id`.
- **The `inviteLink` has two shapes and the *user* decides which.** An e-mail no
  user holds gets
  `/protocol/openid-connect/registrations?response_type=code&client_id=account&token=…`;
  one an existing user holds gets `/login-actions/action-token?key=…`, whose
  token carries a `sub`. `invite-existing-user` always produces the second.
- **A resend is not a resend.** It answers 204 and the invitation it names is
  **gone**: the old id 404s, one row for that e-mail remains, and it carries a
  new id, a new `sentDate`, a new `expiresAt` and a new link. A fresh token is a
  fresh row, because the id is the token's `jti`.
- **The listing sorts by the invitation id**, a random UUID - `mid, beta, alpha,
  zeta` from an insertion order of `zeta, alpha, mid, beta`, matching a sort by
  id exactly. An earlier reading of "sorted by e-mail" fitted the first sample
  and was refuted by the second, which is AGENTS.md's "two recordings agreeing is
  never evidence of stability" happening again.
- **The listing has no default bound**: thirteen invitations came back to a
  request with no parameters, where the member listing beside it caps at ten.
- Its filters are **exact**: `email=aaa` finds nothing where
  `email=aaa@ord.example.com` finds the row, and `firstName=Ne` finds nothing
  where `firstName=New` does. `search` is an infix over e-mail, first name and
  last name. That inverts the user listing, where the named filters are
  substrings and `search` is a prefix.
- `status=bogus` is a 500 `unknown_error`.
- **The two invite 204s carry `Content-Security-Policy`**, `frame-src 'self';
  frame-ancestors 'self'; object-src 'none';` - the realm's own
  `browserSecurityHeaders` on an **Admin API** response. Their 400s, 409s and
  500s carry none. AGENTS.md records that header on the page path and on
  revocation; this is a third place.

### 1.7 The two invite endpoints disagree about everything

```
invite-user            no/empty email   400 {"errorMessage":"Email is required to invite a member"}
                       a member's email 409 {"errorMessage":"User already a member of the organization"}
                       already invited  409 {"errorMessage":"User already has a pending invitation"}
                       otherwise        500 Failed to send invite email
invite-existing-user   no/empty id      400 {"error":"To invite a member you need to provide the user id"}
                       unknown id       400 {"errorMessage":"User does not exist"}
                       no e-mail on it  400 {"errorMessage":"User does not have an email address"}
                       already invited  409 {"error":"conflict","error_description":"Duplicate resource error"}
                       otherwise        500 Failed to send invite email
```

Three of those are findings:

- **The missing required field is the bare-`error` family on one and the
  `errorMessage` family on the other**, one path segment apart.
- **`invite-existing-user` does not check membership.** Inviting a user who is
  already a member answered 204 and made a second invitation, where
  `invite-user` refuses the same person's e-mail with a 409.
- **The duplicate invitation has two entirely different 409 bodies.** One is a
  sentence; the other is `Duplicate resource error` - and **that one sends none
  of the five security headers** while the three sibling 409s in this family
  send all five. Another data point for AGENTS.md's unexplained fifth exception,
  and it agrees with what that bullet already says: the header set follows
  whatever produced the response.

And the member add's own duplicate is a **third** sentence for the same
condition: `User is already a member of the organization.` - with a full stop
and "is already", where `invite-user`'s has neither.

### 1.8 An organization's identity providers are a column, not a join table

`POST /organizations/{org}/identity-providers` answers **204 with no
`Location`** - where `POST .../members` in the same family answers 201 with one -
and the **realm's own** read of that provider starts carrying
`"organizationId"`. The delete drops the key and leaves the provider. So the
association is one nullable column and the organization routes are a filter over
it; the bodies they serve are the identity provider chapter's, unchanged.

`organizationId` sits between `firstBrokerLoginFlowAlias` and `config`, and
`briefRepresentation=true` drops it - which makes it a **ninth** thing that
parameter drops, where AGENTS.md's bullet lists eight.

Five operations, five sentences, and no two of the pairs agree:

```
GET    .../{alias}           404 "Identity provider not associated with the organization"
GET    .../{alias}/groups    404  the same sentence
DELETE .../{alias}           404 "Identity provider not found with the given alias"
POST   unknown alias         400  that same second sentence, as a 400
POST   already on this org   409 "Identity provider already associated to the organization"
POST   on another org        400 "Identity provider already associated with a different organization"
POST   empty body            400  the unknown-alias sentence
```

**The read and the delete answer the same missing association with two different
sentences**, and the 409 and the second 400 differ by one preposition - *to*
against *with*. One helper for the family gets at least two of the six wrong.

`GET .../{alias}/groups` is `[]` on every provider, for F120's reason.

### 1.9 The Content-Type rule, and how this cut got it wrong

**Measured at socket level**, because nothing else can see it:

```
POST .../members              absent 201   application/json 201   text/plain 415
                              application/x-www-form-urlencoded 415   application/xml 415
                              Content-Type: (empty value)       500 unknown_error
POST .../identity-providers   absent 204   application/json 204   text/plain 415
POST /organizations           absent 201
PUT  /organizations/{id}      absent 204
POST .../members/invite-user  absent 400 "Email is required" - the form is not read
                              application/json 400 - likewise
                              application/x-www-form-urlencoded 500 Failed to send
```

So **an absent `Content-Type` is accepted** on the four JSON writes, which is
exactly the rule `requireJSONBody`'s doc comment already records for the scope
mappings; and the two invite endpoints do not enforce one at all - without the
form Content-Type the body is simply not read, so they answer about the field
they are then missing and can never answer 415.

**This cut recorded the opposite rule first, and shipped it into a handler and a
test before the recorder caught it.** Python's `urllib` adds
`Content-Type: application/x-www-form-urlencoded` to any POST carrying data that
does not already name one, so every "no Content-Type" probe measured the 415 of
a header it had set itself. The recorder builds its requests by hand, recorded a
409 where the probe had recorded a 415, and `TestConformance` failed on the
mismatch. **Fixed on this branch**: the extra helper is gone and the two
handlers use `requireJSONBody`.

The consequence beyond this cut is in §3, under F149.

The **empty-value** `Content-Type: ` is a third answer, `500 unknown_error`, and
is not reproduced - it would mean reading `r.Header["Content-Type"]` rather than
`Get`, in a helper shared with a family where nothing measured it.

### 1.10 Wrong verbs on this tag are a real 405

```
PUT, PATCH  /organizations                       405 {"error":"HTTP 405 Method Not Allowed"}
PATCH, POST /organizations/{id}                  405
PUT, PATCH  /organizations/{id}/members          405
POST        /organizations/{id}/members/{id}     404 {"error":"HTTP 404 Not Found"}
DELETE      /organizations/{id}/members          404
PUT, PATCH  /organizations/{id}/invitations      405
POST        /organizations/{id}/invitations      404
PUT, PATCH  /organizations/{id}/identity-providers 405
PATCH, PUT  /organizations/count                 404 {"errorMessage":"Organization not found."}
```

That is the role-mapping paths' split - `PUT`/`PATCH` 405, `POST`/`DELETE` 404 -
on a seventh family, and it reaches the **first cut's own six routes** as well.
Gloak answers 404 to all of them through `WithKeycloakFallbacks` and **nothing
was changed on the strength of it**, which is what AGENTS.md's F31 bullet asks
for. The `/organizations/count` row is a routing quirk worth keeping: for every
verb but `GET`, `count` is matched by the `{org-id}` template.

### 1.11 F120: the hidden root group, identified

`POST /organizations/{org}/groups` answers **201 with the group in the body**,
`application/json` with no charset - `POST /groups/{id}/children`'s shape - and
the group carries a `parentId` naming an id the representation never shows. This
cut found what it is:

```
GET /organizations/{org}/groups/{parentId}
  {"id":"6002e2b2-…","name":"3f349df3-…","path":"/3f349df3-…",
   "subGroups":[],"attributes":{},"realmRoles":[],"clientRoles":{}}
```

**The hidden root group's `name` and `path` are the organization's own id.** It
is one group per organization, created with it, and:

- `GET /groups` and `GET /groups/count` do **not** see it or its children - a
  realm with an organization group answered `[]` and `{"count":0}`.
- `GET /groups/{parentId}` on the realm group family answers
  **`400 {"errorMessage":"Cannot manage organization related group via non
  Organization API."}`** - a new sentence and a new 400 on the group family.
- A member is **not** in it: `GET .../members/{id}/groups` is `[]` for a member
  of an organization that has a group.

That is the whole of what F120 was waiting on. The eleven group operations and
their eleven role-mapping siblings remain out of scope for this cut.

### 1.12 Cascades and smaller things

```
DELETE /users/{id}                removes the membership; the organization survives
DELETE /organizations/{id}        removes the memberships; the users survive
DELETE .../members/{id}           removes the membership; the **user** survives
DELETE /identity-provider/instances/{alias}   removes it from the organization listing
a user of another realm           404 on POST .../members and on the top-level read
a non-member and an unknown id    the same generic 404 on all four member routes
GET .../invitations               200 [] with **no Cache-Control**, where every
                                  other read in the tag carries no-cache
```

The member routes are a **sixth producer** of `{"error":"HTTP 404 Not Found"}`,
after an unmatched path, a wrong verb, a switched-off resource, an unparseable
integer bound and the authorization resource family - and the second that is an
ordinary missing row.

### 1.13 A users-family finding this cut did not go looking for

**`briefRepresentation=true` on the user listing drops `attributes` as well**,
which makes it five fields and not the four `admin/users/list-brief`'s comment
records - but **which** attributes it drops is decided by the realm's user
profile, not by the parameter:

```
master, admin, is_temporary_admin (undeclared)   brief KEEPS attributes
a created realm, a declared attribute            brief DROPS attributes
```

Both with `unmanagedAttributePolicy` unset, which is what `POST /admin/realms`
produces. The committed golden holds the first row, so Gloak is right on the
only user it can serve with attributes; a declared attribute is unreachable
because Gloak has no user profile endpoint. **Not fixed** - it is the users
chapter's, no golden can reach the second row, and the member family reuses
`userRepresentationOf` unchanged for exactly that reason.

### 1.14 The mutation that survived

Seventeen mutations, one each, every one confirming the **named** test fails.
Sixteen were killed. The survivor:

```
sqlite Members()  ORDER BY u.username  ->  ORDER BY u.email
```

`TestConformance/organization_members_are_users,_ordered_by_username,_and_cascade_both_ways`
passed with it. The subtest created three users named `gloak-probe-zzz`,
`gloak-probe-aaa`, `gloak-probe-mmm` and gave each the e-mail
`name + "@members.example.com"` - so the two orders were the same string doing
two jobs, and no order was asserted at all. That is exactly the hole AGENTS.md
records swallowing four survivors in three cuts.

**Fixed on this branch.** The e-mails now sort the other way round
(`zzz -> aaa@`, `aaa -> zzz@`), the subtest asserts the first row's e-mail as
well as its username, and the mutation is killed on both drivers. The
conformance golden `admin/organizations/members-list` had the separation from the
start - `gloak-probe-zebra` carries `aaa@…` and `gloak-probe-aardvark` carries
`zzz@…` - so the behaviour was pinned; what was missing was the store's own
guard, which is the half a driver can get wrong on its own.

---

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

- **A member is a user, and `POST .../members` takes its id as raw bytes.** The
  body is not JSON: a bare uuid, one with a single leading quote, one with a
  single trailing quote and one wrapped in spaces are all 201, while `""x""`, a
  quote in the middle, `'x'`, `["x"]` and `{"id":"x"}` are all 404. The rule is
  trim, then strip at most one `"` from each end. `json.Unmarshal` into a string
  is right on the quoted form and wrong on four of the others, and it is the
  obvious implementation. The 201's `Location` ends in the id the **caller
  sent**, which makes it the fifth create in this API whose tail the caller
  chose and the only one where the caller chose an id rather than a name.

- **One user serialises five ways, not three.** The three this file already
  records, plus an organization member's two: nine keys ending in
  `membershipType` from the listing, and thirteen from
  `?briefRepresentation=false` and from the single read, which are byte-identical
  to each other. Neither carries the `access` block, and neither carries
  `federatedIdentities`. A shared serialiser would be wrong three ways.

- **The member listing is the only listing in this API that pages when asked for
  nothing.** `max` defaults to 10 and `first` to 0: twelve members answered ten
  rows to a request with no parameters. A negative bound means no bound. The
  role listings need `search` or both bounds, the group listing pages on either,
  the user listing returns everything, and the **invitation** listing next door
  returns everything too - so one tag holds two of the five rules.

- **`search` has a third rule and the member listing is where it is.** Against a
  member named `gloak-probe-lm-03`, `search=lm-03` matches on
  `/organizations/{org}/members` and answers `[]` on `/users` - measured side by
  side on one realm. The user listing's is a prefix (`term%`), this one is an
  infix (`%term%`), and the role listing's `*` is a literal where both of these
  treat it as a wildcard. `"quotes"` mean equality on the user listing and
  nothing here. The **invitation** listing inverts the user listing instead: its
  named filters are exact and its `search` is an infix.

- **The member count reads none of the member listing's parameters**, where the
  organization count one path segment up honours its own `search`. `?search=` and
  `?membershipType=` both answered 12 on an organization whose listing answered
  one row and none. Passing the query through "for consistency" is the change
  that breaks it.

- **Nineteen routes need a role from each of two families, and no single role
  opens any of them.** `manage-organizations` alone is 403 on every member route
  and so is `manage-users` alone. There are five conjunctions, not one:
  `query-users` opens the member listing and count and nothing else,
  `query-organizations` opens the top-level `.../organizations` read and not its
  org-scoped twin, the member writes need `manage-users` where the reads take
  the view role, the identity provider family takes the identity provider pair
  instead of the user pair, and **the four invitation routes take
  `manage-organizations` or `manage-realm` alone - no second family at all**.
  That last one puts two more reads in this API's very short list of reads that
  refuse the view role.

- **Two routes serve byte-identical bodies and have different guards and
  different 404s.** `GET /organizations/{org}/members/{id}/organizations` is a
  404 for a user of the realm who is not a member of that organization;
  `GET /organizations/members/{id}/organizations` answers 200 and `[]` for the
  same user, and takes `query-organizations` where the other does not. Only an
  unknown user id is a 404 on both.

- **The invitation family's 500 is the contract.** Both invite endpoints send an
  e-mail, so a realm with no `smtpServer` - master's and every realm
  `POST /admin/realms` creates - answers
  `500 {"errorMessage":"Failed to send invite email"}` to every well-formed
  request, and no invitation can exist. The listing is `[]` and the three `{id}`
  routes are `404 {"errorMessage":"Invitation not found"}`, which is a
  twenty-fifth spelling of not-found. It is `VERIFY_EMAIL`'s and CIBA's
  situation: the failure is the observable behaviour, not a gap.

- **Two sibling invite endpoints disagree about the error family, about
  membership and about their own 409.** A missing required field is
  `{"error":"To invite a member you need to provide the user id"}` on
  `invite-existing-user` and
  `{"errorMessage":"Email is required to invite a member"}` on `invite-user`.
  `invite-user` refuses a member's e-mail with a 409; `invite-existing-user`
  invites a member happily, 204 and a second invitation row. And a duplicate
  invitation is `{"errorMessage":"User already has a pending invitation"}` on one
  and `{"error":"conflict","error_description":"Duplicate resource error"}` on
  the other - one condition, two endpoints, two entirely different 409 bodies,
  and the second sends **none** of the five security headers where the first
  sends all five.

- **An organization's identity providers are a column on the provider.**
  Associating one through `POST /organizations/{org}/identity-providers` - a 204
  with no `Location`, where the member add beside it is a 201 with one - makes
  the **realm's** own `GET /identity-provider/instances/{alias}` start carrying
  `"organizationId"`, and the delete drops the key and leaves the provider. So
  one provider reaches at most one organization, and a second organization
  claiming it is a 400. `briefRepresentation=true` drops `organizationId`, which
  makes nine things that parameter drops rather than eight.

- **`organizationId` on a broker create is not a 400 for every value.** This file
  and `internal/admin` both said it was, from a probe set taken on `master`,
  where organizations are switched off and no organization can exist - so every
  value the probe could try resolved to nothing. In a realm with the flag on, a
  **real** organization id is a 201 and the provider is associated with it, and a
  `PUT` naming one does the same. So there are three routes that write the
  association, not one. `""`, a non-uuid and a uuid that resolves to nothing are
  still the 400, with one sentence for all three.

- **The organization tag answers a wrong verb with a real 405.** `PUT` and
  `PATCH` on any of its collections answer
  `{"error":"HTTP 405 Method Not Allowed"}`, and `POST` on an item and `DELETE`
  on a collection answer the generic 404 - the role-mapping paths' split on a
  seventh family, and it reaches the six routes the first cut serves as well.
  `PATCH /organizations/count` is a third answer,
  `404 {"errorMessage":"Organization not found."}`, because `count` is matched by
  the `{org-id}` template for every verb but `GET`.

- **An absent `Content-Type` is accepted on this API's JSON writes, and the probe
  that says otherwise is measuring itself.** Python's `urllib` adds
  `application/x-www-form-urlencoded` to any POST carrying data that does not
  already name one, so a "no Content-Type" probe written with it measures the 415
  of a header it set. Measured at socket level, `POST .../members`,
  `POST .../identity-providers`, `POST /organizations` and
  `PUT /organizations/{id}` all accept an absent one and answer 415 to
  `text/plain`, `application/x-www-form-urlencoded` and `application/xml`; a
  **present but empty** one is a third answer, `500 unknown_error`. The two
  invite endpoints cannot answer 415 at all - without the form Content-Type the
  body is not read and they answer about the field they are then missing.

- **A group under an organization is invisible to the group family, and its
  parent is the organization's id.** `GET /organizations/{org}/groups/{parentId}`
  reads the hidden root group F120 is blocked on: its `name` and its `path` are
  the **organization's own id**. `GET /groups` and `GET /groups/count` do not see
  it or its children, and `GET /groups/{parentId}` answers
  `400 {"errorMessage":"Cannot manage organization related group via non
  Organization API."}`.

---

## 3. Follow-up dispositions

### F120 - the organization group family is blocked on a hidden root group

**Unblocked, not built.** The blocker is answered: the `parentId` names a group
whose `name` and `path` are the organization's own id, readable through
`GET /organizations/{org-id}/groups/{group-id}` and refused by the realm's own
group routes with a new 400. §1.11 has the bytes. The eleven group operations
and the eleven role-mapping ones remain unserved and remain F120's; what has
changed is that the next cut needs no container to start.

Two things it will want that this cut also measured: the create's 201 carries the
group **in the body** with `application/json` and **no charset**, which is
`POST /groups/{id}/children`'s shape; and a member of the organization is not a
member of its root group.

### F121 - the `Workflows` tag needs a YAML writer

**Untouched.** Nothing in this cut goes near it, and the entry's own reason -
that it is a decision about `internal/httpx` before it is nine handlers - is
unchanged. Re-confirmed only that the tag is not gated by `organizationsEnabled`.

### F95 - a client's `attributes` is serialised from a Go map

**Untouched, and the entry's count is now higher.** This cut adds no ordered-map
serialiser: an organization's attributes go through the existing
`organizationAttributes`, and the member representation carries the user's
attributes through `userRepresentationOf`, which is a Go map and would sort - but
**no fixture in this project can give a member an attribute**, because a created
realm's user profile refuses undeclared ones and Gloak has no profile endpoint.
So F95's blast radius is unchanged and the member family cannot widen it.

§1.13 is adjacent and separate: `briefRepresentation` on the *user* listing drops
`attributes`, and which attributes it drops depends on the user profile. That is
a users-chapter finding, not F95's.

### F149 - `requireJSONBody` accepts an absent `Content-Type` and Keycloak answers 415

**Its premise is false on the four endpoints this cut measured, and the reason is
the probe.** Measured at socket level on 2026-09-03: `POST .../members`,
`POST .../identity-providers`, `POST /organizations` and `PUT /organizations/{id}`
all **accept** an absent `Content-Type`. The entry says the 415 was measured on
nine endpoints across four chapters; every one of those measurements needs
re-taking with a client that does not add the header, because the obvious tool
does. See §1.9.

What is real and stays: a **wrong** Content-Type is a 415 with that body, and
`requireJSONBody` already answers it. What this cut adds to the entry is the
method - **build the request by hand** - and one endpoint where the answer is a
third thing: a present-but-empty `Content-Type` is a `500 unknown_error`.

This cut did not edit the follow-ups list. F149 needs its first paragraph
rewritten before anybody acts on it.

---

## 4. Parity before and after

```
                     before      after
admin/organizations   6 / 36     24 / 36
total                380 / 540   398 / 540
```

Eighteen of the tag's nineteen remaining non-group operations. The nineteenth is
`GET /admin/realms/{realm}/organizations/members/{member-id}/organizations`, and
it is unserved for a routing reason rather than a Keycloak one: it and
`GET /organizations/{orgID}/members/{memberID}` are both four segments, they
overlap on exactly one concrete path -
`/organizations/members/members/organizations` - and neither matches a strict
subset of the other, so `net/http`'s `ServeMux` calls them conflicting and panics
at registration. Registering the overlap as a third, fully literal pattern does
**not** resolve it; `conflictsWith` is pairwise, checked against Go 1.26.6 rather
than inferred from the documentation, which reads as though it might.

The two ways out both cost more than the route is worth. A dispatcher on
`organizations/{a}/{b}/{c}` would swallow every four-segment path under the tag
that Gloak does not serve - the eleven F120 group routes among them - and those
answer the unmatched-path 404 **with none of the five security headers**, which
only `WithKeycloakFallbacks` can produce. Dropping the org-scoped read instead
loses the route that matters more.

Keycloak's answers to the overlap are measured, so the next cut needs no
container:

```
/organizations/members/members/organizations  404 {"error":"HTTP 404 Not Found"}
/organizations/members/members                404 {"errorMessage":"Organization not found."}
```

The first is the top-level route reading `members` as a user id that resolves to
nothing; the second is the org-scoped route reading it as an organization id. So
JAX-RS prefers the literal segment on the four-segment shape and the wildcard on
the three-segment one. The route's guard is measured too (§1.5) and its handler
body is written - `writeMemberOrganizations` serves the org-scoped twin - so what
is missing is a way to register it.

The eleven remaining operations after that are the group family's, F120's.
