# P2, second cut: roles and role mappings on a user

Date: 2026-08-23
Sub-project: P2, second of three cuts
Predecessor: `2026-08-22-p2-admin-api-core-design.md`

## 1. What this is

The `Roles`, `Roles (by ID)`, `Role Mapper` and `Client Role Mappings` OpenAPI
tags, as far as they concern a **user**. Groups get the third cut.

P2's first cut ended by saying the remaining five tags "get a second spec once
this cut is serving and the shape of the work is known from having done it".
It is, and it is.

The four tags hold 71 operations. This spec takes **43**:

| Block | Operations |
|---|---|
| `Roles` - realm roles and client roles, CRUD and composites | 24 |
| `Roles (by ID)` | 8 |
| `Role Mapper` - the user half | 6 |
| `Client Role Mappings` - the user half | 5 |

### 1.1 Why 43 and not 71

The same rule the first cut used: a tag names the resource an operation hangs
off, not the sub-project that builds it.

The other 28 divide three ways:

| Owner | Operations | What they are |
|---|---|---|
| **P2's third cut** - groups | 11 | the group halves of `Role Mapper` (6) and `Client Role Mappings` (5) - every `groups/{group-id}/role-mappings/...` path |
| **organizations, unscheduled** | 11 | every `organizations/{org-id}/groups/{group-id}/role-mappings/...` path |
| **P10 authz services** | 6 | `management/permissions`, `GET` and `PUT`, on realm roles, client roles and roles-by-id |

`/roles/{name}/groups` and its client-role twin are the awkward pair. They are
group listings sitting in the `Roles` tag, so they are counted in the 24 here
and **served as `[]` from the first day** - which is what a realm with no groups
answers anyway, measured. When the third cut lands they start returning rows and
need no new route.

### 1.2 Why this cut and not groups first

Two things are blocked on it and nothing is blocked on groups.

- **F17.** The listings are gated where Keycloak filters. Both halves need a
  caller holding a narrow role, and building one through the API needs role
  assignment - which is `Role Mapper`. Today `internal/admin`'s own tests reach
  that state by writing to the store directly, so no conformance case can cover
  it.
- **`oidc/introspection/active-access-token`.** It has been `Pending` since P1
  because no fixture can put the introspecting client inside an access token's
  audience. F18 measured what would: a role on that client, assigned to the
  user. `POST /users/{id}/role-mappings/clients/{uuid}` is that operation.

## 2. The model already exists

This is the unusual part of this cut, and it is why it is worth doing now
rather than later. `internal/store`'s `RoleRepo` was built for bootstrap in the
foundation slice and extended for F18:

```go
Create, ByID, ByName, ListRealmRoles, ListClientRoles,
AddComposite, ListComposites,
AssignToUser, RemoveFromUser, ListUserRoles
```

`internal/roles.Effective` already walks composites transitively, and both
`internal/admin` and `internal/oidc` authorise and issue tokens with it.

What is missing is small and known:

| Need | Why it is not there |
|---|---|
| `Update(ctx, *model.Role)` | nothing has ever changed a role |
| `Delete(ctx, realmID, id)` | nothing has ever removed one |
| `RemoveComposite(ctx, roleID, childID)` | bootstrap only ever adds |
| `ListUsersWithRole(ctx, realmID, roleID)` | `/roles/{name}/users` |
| `model.Role.Attributes map[string][]string` | measured, stored, and round-trips - one migration |

Five additions and one migration, against the first cut's eleven repository
methods and three migrations. The endpoints are the work here, not the model.

## 3. Representations: two shapes, and the flag that picks them is inverted

Measured, and recorded in the "Roles" section of
`2026-08-18-keycloak-26.7.1-observed.md`.

A **listing** carries six keys, a **single read** seven:

```
id, name, description, composite, clientRole, containerId [, attributes]
```

The trap is that `briefRepresentation` **defaults to true** here and to false
on the user listing. The same query parameter, two endpoints, opposite
defaults. `internal/admin`'s user code reads `== "true"`; the role code has to
read `!= "false"`, and a shared helper would get one of them wrong.

Three more measured details the implementation cannot guess:

- `description` is **absent** when unset, not `""`.
- `containerId` is the realm's **UUID** for a realm role and the client's UUID
  for a client role - not the realm name.
- role `attributes` are **stored**, where a user's are dropped. Gloak drops user
  attributes on purpose, with a comment saying so; copying that here would be
  wrong.

## 4. `PUT` replaces here and merges next door

The first cut established that `PUT /clients/{uuid}` and `PUT /users/{id}`
unmarshal the request body **over** the current representation, so an omitted
field keeps its value. `PUT` on a role does not: a body carrying only `name`
clears an existing `description`. Measured directly.

It also **renames**: the id survives, the old path 404s. A user's username, by
contrast, is immutable through its own `PUT`.

So `internal/admin` will now hold both semantics, three files apart. Whatever
implements this has to say so at both call sites, because the natural instinct
on reading `updateClient` is to copy it.

## 5. Authorization: two different rules in one cut

| Operations | Read | Write |
|---|---|---|
| realm roles | `view-realm` | `manage-realm` |
| client roles | `view-clients` | `manage-clients` |
| `roles-by-id` | **the role's container decides** | same |
| user role mappings | `view-users` | `manage-users` |

Two of these do not fit the guard wrappers the first cut built.
`guard(role, next)` and `guardAny(roles, next)` decide from the route alone.

- **`roles-by-id`** decides from the data: the same path needs `view-clients`
  for a client role and `view-realm` for a realm role, so the role has to be
  loaded before the caller is judged. The 404 for a missing role must still come
  out ahead of any 403, or the endpoint becomes a probe for which role ids
  exist.
- **role mappings** are guarded by the **subject**, not the role. Assigning a
  `master-realm` role to a user needs `manage-users`; a caller holding
  `manage-realm` and nothing else is refused. This is the natural mistake to
  make in the other direction.

One further measured rule, which looks like a bug and is not:
**`POST /clients/{master-realm uuid}/roles` is 403 for a full administrator.**
The realm's own client takes no new roles from anybody.

## 6. Harness: root-level arrays cannot be sorted, and these need to be

Measured across three container starts: **the realm role listing comes back in
a different order every time.** Three runs gave three orders, and the client
role listing moves too. It is a Java set, like `scopes_supported`, the token
response's `scope` and the JWKS `keys` array before it.

Every listing in this cut is affected, and every one of them is a **bare array
at the root of the body** - `GET /roles`, `GET /clients/{uuid}/roles`, every
composite listing, every `available`/`composite` listing.

`Case.Unordered` cannot reach them. `matchesAny` in `internal/conformance/normalize.go`
opens with

```go
if len(path) == 0 {
    return false
}
```

so the root value never matches a pattern. Every array sorted so far has been
nested under a key. This is a harness task and it comes first: without it, not
one listing in this cut can be an `Implemented` case, and the whole cut would
ship behind `Recorded`.

The fix is a path spelling for the root - `"."` or the empty pattern - decided
where the walk starts rather than by special-casing each pass, since
`Normalize`, `SortUnordered`, `SortUnorderedKeys` and `SortUnorderedWords` all
share `editor.value`.

## 7. What this cut will get wrong on purpose

- **`/roles/{name}/groups` answers `[]`.** Correct today, and correct until the
  third cut, because the realm has no groups. It is listed here so that nobody
  later reads the empty array as a stub.
- **`management/permissions` is not routed at all**, so it falls through to the
  measured 404 for an unmatched path. That is what P10 will replace.
- **F17 is not closed by this cut, only unblocked by it.** Filtering the client
  and user listings by the caller's own view permission is its own change, and
  it now becomes reachable as a conformance case rather than only as a unit
  test.

## 8. Scope

In: the 43 operations of section 1, the five repository methods and one
migration of section 2, the harness fix of section 6.

Out:

- groups, and the 17 operations section 1.1 assigns to the third cut
- `management/permissions`, which is P10
- the organizations paths, which have no sub-project yet
- role attributes as anything other than an opaque map. Keycloak gives some of
  them meaning; nothing here reads one.
- realms other than `master`, which is P4

## 9. What this document deliberately does not decide

**How many plans this becomes.** 43 operations is nearly twice the first cut's
24, and the first cut took 18 tasks. The natural seam is between the roles
themselves and the mappings on a user, and the harness fix has to come before
either. Whoever writes the plan decides whether that is one document or two;
what must not happen is a plan that starts implementing listings before the
root-array fix is in, because every one of them would be unverifiable.

**Whether `internal/admin` splits.** It is five files today and this cut adds
roles, roles-by-id and role mappings. That is a judgement to make while
writing the code, against files that exist, not here.
