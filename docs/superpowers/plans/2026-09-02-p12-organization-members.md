# P12 second cut: an organization's members, invitations and identity providers

Measured against a live Keycloak 26.7.1 on 2026-09-02, container `kc-org` on
`:8160`, started `quay.io/keycloak/keycloak:26.7.1 start-dev` with no feature
flags. Organizations were turned on **through the API**: `POST /admin/realms`
with `{"realm":"gloak-org-probe","enabled":true}`, then `GET` the realm
representation, set `organizationsEnabled` to `true`, and `PUT` it back. The
container flag was not used and master's own flag was never touched.

The destructive half - the role sweep, the SMTP configuration, the user-profile
edits - all ran inside `gloak-org-probe`, a created realm, for the reason
AGENTS.md gives about `POST /components` on master.

## 0. What a member actually is

**A member is a user, addressed by the user's own id.** There is no membership
id and no second identity. Three measurements say so and no probe disagrees:

```
POST /organizations/{org}/members   body: 2a04b3cf-38cc-4bc9-836b-c018f9b30229
  -> 201, Location .../organizations/{org}/members/2a04b3cf-…-c018f9b30229
GET  /organizations/{org}/members/2a04b3cf-…       -> 200, "id" is that value
DELETE /users/{that id}  -> the member vanishes from the listing
```

The `Location` tail is the id the **caller sent in the body**, not a
server-minted one, which makes this a sixteenth create for AGENTS.md's
`Location` bullet and the fifth whose tail the caller chose.

**`POST .../members` accepts the user id as the raw request body, and it is not
JSON.** Measured over eight bodies:

```
"2a04b3cf-…"        201     a JSON string
2a04b3cf-…          201     no quotes at all - not valid JSON
"2a04b3cf-…         201     one leading quote
2a04b3cf-…"         201     one trailing quote
  2a04b3cf-…        201     leading and trailing spaces
\t2a04b3cf-…\t      201     tabs
2a04b3c"f-…         404     a quote in the middle
""2a04b3cf-…""      404     two quotes each end
'2a04b3cf-…'        404     single quotes
["2a04b3cf-…"]      404     a JSON array of one
{"id":"2a04b3cf-…"} 404     a UserRepresentation
"gloak-probe-user-three" 404 the username instead of the id
```

So the rule is: **trim whitespace, then strip at most one `"` from each end**,
and resolve what is left as a user id. `""x""` failing is what says "at most
one"; the mid-string quote failing is what says "at the ends". A handler that
decodes the body as JSON is right on the first row and wrong on four of the
others.

**That decides the schema: one table, not two.** A membership is a pair
`(organization_id, user_id)` with no identity of its own, no created date on the
wire and no representation. `membershipType` is the only member-only field and
it was `UNMANAGED` on every member this cut could create - a managed member is
one the organization itself provisioned through an identity provider or a
completed invitation, and neither is reachable in this container regime.

## 1. Scope: nineteen operations, not seventeen

The brief says `members 8, identity-providers 5, invitations 4`. The description
enumerates **ten** member operations, so the tag's remainder is nineteen. Counted
from the list below rather than incremented:

```
members
  1  GET    /organizations/{org-id}/members
  2  POST   /organizations/{org-id}/members
  3  GET    /organizations/{org-id}/members/count
  4  POST   /organizations/{org-id}/members/invite-existing-user
  5  POST   /organizations/{org-id}/members/invite-user
  6  GET    /organizations/{org-id}/members/{member-id}
  7  DELETE /organizations/{org-id}/members/{member-id}
  8  GET    /organizations/{org-id}/members/{member-id}/groups
  9  GET    /organizations/{org-id}/members/{member-id}/organizations
 10  GET    /organizations/members/{member-id}/organizations
identity-providers
 11  GET    /organizations/{org-id}/identity-providers
 12  POST   /organizations/{org-id}/identity-providers
 13  GET    /organizations/{org-id}/identity-providers/{alias}
 14  DELETE /organizations/{org-id}/identity-providers/{alias}
 15  GET    /organizations/{org-id}/identity-providers/{alias}/groups
invitations
 16  GET    /organizations/{org-id}/invitations
 17  GET    /organizations/{org-id}/invitations/{id}
 18  DELETE /organizations/{org-id}/invitations/{id}
 19  POST   /organizations/{org-id}/invitations/{id}/resend
```

The two the brief's count leaves out are the invite endpoints, which are the two
that are **not** JSON: both consume `application/x-www-form-urlencoded`.

The chapter's denominator is 36 and six are served, so this cut takes
`admin/organizations` from 6/36 to 25/36. The eleven that remain are the group
family, F120's, and they stay out - see §7 for what this cut measured about the
hidden root group anyway.

## 2. The two member shapes

```
brief  id username [firstName] [lastName] [email] emailVerified [attributes]
       enabled createdTimestamp membershipType
full   … the same … totp disableableCredentialTypes requiredActions notBefore
       membershipType
```

`briefRepresentation` defaults to **true** on the listing and is **ignored** by
the single read, exactly as on the organization pair one path segment up. The
single read's body is byte-identical to a `briefRepresentation=false` listing
entry - checked as bytes, not by eye.

The shape is `userRepresentation` with `membershipType` appended and **no
`access` block and no `federatedIdentities`**, where `GET /users/{id}` carries
both. That is a fourth and fifth serialisation of one user, after the three
AGENTS.md records.

Implementation: embed Gloak's existing `userRepresentation` and add
`MembershipType` after it, which is exactly the field order `encoding/json`
emits for an embedded struct. `userRepresentationOf(u, brief)` is reused
unchanged - see §8 for the one thing that decides that and why it is not a
divergence.

## 3. The member listing pages by default, and its `search` is a third rule

```
no parameters      10 rows of 12          max defaults to 10, first to 0
max=100            12
max=-1             12                     a negative bound means no bound
first=-1           10                     …and first falls back to 0
max=0              0
max=abc            404 {"error":"HTTP 404 Not Found"}
```

**No other listing in this API bounds itself when asked for nothing.** The role
listings need `search` or both bounds, the group listing pages on either, the
user listing returns everything. This one always pages.

`search` matches `username`, `firstName`, `lastName` and `email` as a
**case-insensitive substring**, and not the id:

```
search=lm-03      matched gloak-probe-lm-03   on /organizations/{org}/members
search=lm-03      []                          on /users, same realm, same needle
```

That pair was issued on one container minutes apart and is the whole finding:
the user listing's `search` is a prefix (`term` becomes `term%`) and this one is
an infix (`%term%`). `*` is the wildcard and becomes `%`; `%` and `_` are
literals (`%lph%` and `_lpha` both find nothing where `*lph*` and `lph` find the
row); `"quotes"` do **not** mean equality here, where they do on the user
listing.

`exact=true` compares the whole value against each of the same four fields.
`exact=bogus` behaves as `false`.

`membershipType` filters, and an unknown value is a **500** `unknown_error` -
Jackson refusing to bind the enum, the same shape as the invitation `status`
parameter.

**`GET .../members/count` reads none of them.** `?search=lm-03` and
`?membershipType=MANAGED` both answered `12` on a twelve-member organization
whose listing answered one row and none. The organization count next door
honours its `search`; this one does not.

The listing is **sorted by username** - three members added `zzz, aaa, mmm` came
back `aaa, mmm, zzz`, reproducibly, and the set was chosen so that username
order and email order disagree.

## 4. The two `.../organizations` reads are twins that disagree twice

Both serve the **brief organization shape**, both honour `briefRepresentation`
(false adds `attributes`, in `javamap.KeyOrder`'s order), and for a member their
bodies are byte-identical. They differ in two places:

```
                                        non-member      unknown user id
/organizations/{org}/members/{id}/organizations   404   404
/organizations/members/{id}/organizations         200 []  404
```

and in their guards - see §6. So the org-scoped one asserts membership of the
organization in its own path and the top-level one does not.

Their order is **not** explained: four organizations came back
`mm, zz, aa, fin` on four consecutive reads - neither insertion, nor name, nor
organization id, nor reverse of any of them. Reproducible within one container
and explained by nothing, so the cases carry `Unordered`.

## 5. Identity providers are a column, not a join table

`POST /organizations/{org}/identity-providers` with the alias in the body
answers **204** - not the member add's 201, and with **no `Location`** - and the
**realm's own** provider representation gains an `organizationId` key:

```
GET /identity-provider/instances/{alias}   before  … "config":{…},"types":[…]
                                            after  … "organizationId":"{org}", …
GET /organizations/{org}/identity-providers/{alias}   byte-identical to that
```

Deleting the association drops the key again and leaves the provider. So the
storage is one nullable column on `identity_provider` and the organization
routes are a filter over it, and the representation needs one new
`omitempty` field rather than a serialiser of its own.

Its errors are five sentences over five operations, and no two of the pairs
agree:

```
GET    .../{alias}           404 {"errorMessage":"Identity provider not associated with the organization"}
GET    .../{alias}/groups    404  the same sentence
DELETE .../{alias}           404 {"errorMessage":"Identity provider not found with the given alias"}
POST   with an unknown alias 400  that same second sentence, as a 400
POST   with an alias already on this organization
                             409 {"errorMessage":"Identity provider already associated to the organization"}
POST   with an alias on another organization
                             400 {"errorMessage":"Identity provider already associated with a different organization"}
POST   with an empty body    400  the unknown-alias sentence
POST   with no Content-Type  415 {"error":"The content-type header value did not match the value in @Consumes"}
```

The read and the delete answer the **same missing association** with two
different sentences, and the 409 and the 400 differ by one preposition - *to*
against *with*. One helper for the family gets at least two of the six wrong.

`GET .../{alias}/groups` is `[]` on every provider, because organization groups
are F120's and Gloak has none.

## 6. The guards are conjunctions, and three of them are different conjunctions

Measured with a token minted per caller, one user per role set, in the created
realm, against every route in the family. `mr` is `manage-realm`.

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

Four things in that table are findings rather than bookkeeping:

- **No single role opens a member route.** `manage-organizations` alone is 403
  on every one of them; so is `manage-users` alone. This is the second endpoint
  family in the API needing a conjunction, after `/roles/{name}/users`, and the
  first where the conjunction is the rule for a whole tag rather than for one
  route among four that look identical.
- **`query-users` opens the listing and the count and nothing else**, which is
  `GET /users`' role set against `GET /users/{id}`'s, reproduced one tag away.
- **`query-organizations` opens the top-level `.../organizations` read and not
  its org-scoped twin.** Two routes serving byte-identical bodies, two guards.
- **The invitation family refuses the view role.** `view-organizations` is 403
  on `GET .../invitations` and `manage-organizations` alone is 200. That is a
  **read that needs a manage role**, of which AGENTS.md records exactly two in
  the whole API; this adds two more (the listing and the single read).

Order is uniform and matches the first cut: authenticate, resolve the realm,
check the roles, check `organizationsEnabled`, resolve the organization. On an
org id that resolves to nothing a full administrator gets
`404 {"errorMessage":"Organization not found."}` and a caller holding no role
gets `403 {"error":"HTTP 403 Forbidden"}`, on all eighteen org-scoped routes.
With the flag off every route including the top-level one answers
`404 {"errorMessage":"Organizations not enabled for this realm."}`.

## 7. Invitations: four operations whose create is a 500 by construction

`invite-user` and `invite-existing-user` send an e-mail, and a realm with no
`smtpServer` answers **`500 {"errorMessage":"Failed to send invite email"}`**.
That is the contract, the same shape as `VERIFY_EMAIL`'s 500 and CIBA's 503, and
it is what a default 26.7.1 answers to every well-formed request. So on a
default container **no invitation can be created**, the listing is always `[]`
and the three `{id}` routes always answer
`404 {"errorMessage":"Invitation not found"}` - the twenty-fifth spelling of
not-found in this API.

This cut measured the family anyway, by pointing the realm's `smtpServer` at a
throwaway SMTP sink on the host (`host.docker.internal:2525`), because a family
nobody has seen populated is a family nobody can implement responsibly. What it
found is in the handover; what matters for the code is that the invitation rows
are unreachable without a mailer, so **this cut adds no invitation table**.

The reachable half is the validation, and it is where the family is strange:

```
invite-user            no/empty email  400 {"errorMessage":"Email is required to invite a member"}
                       a member's email 409 {"errorMessage":"User already a member of the organization"}
                       pending invite   409 {"errorMessage":"User already has a pending invitation"}
                       otherwise        500 Failed to send invite email
invite-existing-user   no/empty id      400 {"error":"To invite a member you need to provide the user id"}
                       unknown id       400 {"errorMessage":"User does not exist"}
                       no email on user 400 {"errorMessage":"User does not have an email address"}
                       pending invite   409 {"error":"conflict","error_description":"Duplicate resource error"}
                       otherwise        500 Failed to send invite email
```

Two sibling endpoints, and: one reports a missing required field in the `error`
family and the other in the `errorMessage` family; one refuses a member and the
other invites one happily (204, a second invitation row); and their duplicate
invitations answer **two entirely different 409 bodies**, one of them the
`Duplicate resource error` this project has a computed tally for.

The two 409s are unreachable in Gloak - no invitation can exist - and are
recorded rather than served, with a comment saying which line would produce them
when a mailer lands.

Neither invite endpoint enforces a `Content-Type`: `invite-user` with none at
all is a **204** where `POST .../members` with none is a 415. That is a direct
F149 data point on one family.

## 8. Two things that look like divergences and are not

**`userRepresentationOf(u, brief)` is reused unchanged, including its
`attributes` handling.** Keycloak's brief shape drops `attributes` for an
attribute the realm's user profile *declares* and keeps it for one the profile
does not know about - master's `is_temporary_admin` survives
`briefRepresentation=true` (which is what `admin/users/list-brief`'s committed
golden holds) while a declared `gloakprobe` does not, both with
`unmanagedAttributePolicy` unset. Gloak has no user profile and no admin API
route that writes an undeclared attribute, so the only user it can serve with
attributes is the bootstrapped administrator, whose attribute is of the kind
Keycloak keeps. Reusing the helper is therefore right on every input Gloak can
produce. The split is a users-family finding and goes in the handover.

**A wrong verb on these paths is a real 405.** `PUT` and `PATCH` on any of the
collections answer `{"error":"HTTP 405 Method Not Allowed"}`, `POST` on an item
and `DELETE` on a collection answer the generic 404 - the role-mapping paths'
split, on a seventh family. Gloak answers 404 to all of them through
`WithKeycloakFallbacks` and **nothing is changed on the strength of it**, which
is what AGENTS.md's F31 bullet asks for. `PATCH /organizations/count` answers
`404 {"errorMessage":"Organization not found."}` instead, because the `{org-id}`
template matches `count` for every verb but `GET`.

## 9. The work

### 9.1 `internal/model`

- `OrganizationMember{OrganizationID, UserID}` is not needed as a wire type; the
  membership is a `(org, user)` pair the store exposes as `[]*model.User` and
  `[]*model.Organization`. Add nothing to `model` for it.
- `model.IdentityProvider` gains `OrganizationID string`.

### 9.2 `internal/store` - migration `0025_organization_member.sql`

```sql
CREATE TABLE organization_member (
    organization_id TEXT NOT NULL REFERENCES organization (id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES user_account (id) ON DELETE CASCADE,
    PRIMARY KEY (organization_id, user_id)
);
ALTER TABLE identity_provider ADD COLUMN organization_id TEXT;
```

Both cascades are measured: deleting the user removed the member, deleting the
organization emptied the member's organization list. `organization_id` on
`identity_provider` is nullable and carries no foreign key for the reason
`organization_domain` has no `realm_id` - the association is realm-scoped
through two tables that must not be able to disagree; the handler resolves the
organization first.

`OrganizationRepo` gains five methods, `IdentityProviderRepo` two:

```go
AddMember(ctx, orgID, userID string) error          // ErrConflict on a repeat
RemoveMember(ctx, orgID, userID string) error       // ErrNotFound when absent
IsMember(ctx, orgID, userID string) (bool, error)
Members(ctx, orgID string) ([]*model.User, error)   // ordered by username
MemberOf(ctx, realmID, userID string) ([]*model.Organization, error)

ListByOrganization(ctx, realmID, orgID string) ([]*model.IdentityProvider, error)
SetOrganization(ctx, realmID, alias, orgID string) error
```

Both drivers, and `internal/store/storetest/conformance.go` grows subtests for
all seven so `go test -tags docker ./internal/store/postgres/ -v` has something
to print.

### 9.3 `internal/admin`

New file `organizationmembers.go`:

- `organizationMemberRepresentation` embedding `userRepresentation`
- `listOrganizationMembers`, `countOrganizationMembers`, `readOrganizationMember`,
  `addOrganizationMember`, `removeOrganizationMember`,
  `listOrganizationMemberGroups`, `listOrganizationMemberOrganizations`,
  `listMemberOrganizations` (the top-level one)
- `inviteUser`, `inviteExistingUser`
- `organizationMemberID` - the body reader of §0, trim then one quote each end

New file `organizationidps.go` and `organizationinvitations.go`.

`router.go` gains eighteen `mux.HandleFunc` registrations under `guardOrganization`
plus one under a new `guardOrganizationsAny` for the top-level members route, and
five new role-set variables. The guards are conjunctions, so `guardAny` is not
enough: a small `guardAll(orgRoles, userRoles, …)` wrapper, written once and
used by the four shapes in §6's table.

`requireJSONBody` is used on `POST .../members` and
`POST .../identity-providers` (both measured 415 with no `Content-Type`) and
**not** on the two invite endpoints (measured 204 with none). F149 is not
touched.

### 9.4 `internal/conformance`

Cases appended at the very end of `adminCases`; fixtures appended at the very
end of the map and after the last helper. Roughly thirty cases covering: the two
member shapes, the default bound, the substring `search` against the user
listing's prefix, `exact`, `membershipType`, the unfiltered count, the body
shapes of the member add, the 409, the 404s, the two `.../organizations` twins
and their disagreement, the identity provider association and its six error
sentences, the empty invitation listing and its three 404s, and the invite
validation ladder including the two error families.

`Unordered` goes on the two `.../organizations` reads and nowhere else;
`Volatile` on `*/createdTimestamp` and `*/id`; `VolatileTailHeaders` on the
member add's `Location`.

## 10. Order of work

1. Commit this plan.
2. Migration and both drivers, with `storetest` subtests. Run the Postgres suite.
3. `internal/admin`, one family at a time, each with package tests.
4. `make record`, then `make test`, `make lint`.
5. Mutation-test every claim, one mutation each, confirming the *named* test
   fails.
6. Handover, then the pull request.
