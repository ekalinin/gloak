# The `Clients` singles and three lone operations

Eight operations: the five the `Clients` tag has left, and one each from
`Client Registration Policy`, `Identity Providers` and `Organizations`.

## 0. The list, recomputed

The brief's list was checked against the vendored description rather than taken
on trust, and by a method that evaluates Go values instead of reading Go source:
a throwaway test in `internal/conformance` that walks
`testdata/openapi/keycloak-26.7.1.json` and joins it against the **`Operation`
fields of the assembled `Catalog`**, so a case whose path is written
`"a" + "b"` is compared as `ab`. The tag filter reported 30 of the `Clients`
tag's 35 operations served and named the same five the brief does; the
whole-surface run named the same three lone ones. 413 operations in the
document, 31 not claimed by any case, and the eight below are eight of those 31.

The probe has a control built into its own output: it prints a status per
operation and printed three different ones, so it is not a function that returns
the same answer for every input.

## 1. One row per operation

| operation | what it needs | this cut |
|---|---|---|
| `GET /clients/{uuid}/test-nodes-available` | a client with an `adminUrl`; Gloak's `model.Client` has none | **takes** the reachable case, `{}`, on `push-revocation`'s precedent |
| `GET /client-registration-policy/providers` | the realm's client scope names and a fixed provider set | **takes** |
| `GET /organizations/members/{member-id}/organizations` | a route registration `ServeMux` refuses | **takes** - F153's catch-all reading holds, and is measured below |
| `GET /clients/{uuid}/installation/providers/{providerId}` | eleven renderers, five of them SAML | **leaves** - three legs, §4 |
| `POST /identity-provider/import-config` | an outbound HTTP fetch from `internal/admin` | **leaves** - its 200 is unreachable for a golden in both directions, §4 |
| `POST /clients/{uuid}/registration-access-token` | `internal/oidc`'s `registrationStore` | **leaves** - F148, unchanged, already `Pending` with this reason |
| `GET .../evaluate-scopes/generate-example-userinfo` | `userinfoDocument` in `internal/oidc` | **leaves** - reason re-checked and not expired |
| `GET .../evaluate-scopes/generate-example-saml-response` | a SAML issuance path, and a mask no harness here has | **leaves** - reason re-checked and not expired |

**Does the catch-all reading hold for F153's route?** Yes, and it is measured
rather than argued. F153's remaining question was whether
`/organizations/{a}/{b}/{c}` answers with the five security headers when `{b}`
is not a locator that resolves. Every four-segment `GET` under `/organizations`
that was sent answered **404 with all five headers**, on both bodies:

```
/organizations/{a resolvable org}/bogus/thing   404 {"error":"HTTP 404 Not Found"}          five headers
/organizations/nosuchorg/bogus/thing            404 {"errorMessage":"Organization not found."} five headers
/organizations/{org}/bogus                      404 {"error":"HTTP 404 Not Found"}          five headers
/organizations/{org}/bogus/thing/more           404 {"error":"HTTP 404 Not Found"}          five headers
/organizations/members/bogus/x                  404 {"errorMessage":"Organization not found."} five headers
```

So a wildcard dispatcher swallows nothing that wants the header-less
unmatched-path 404, and for these paths it is **more** faithful than the
fallback, exactly as F153's 2026-09-03 note predicted for the group family. The
header-less 404 belongs to a path that matches no route at the server root;
everything under `/admin/realms/{realm}/` reaches the filter chain, and
`/admin/realms/{realm}/nosuchcollection/x/y/z` was measured carrying all five
too.

## 2. What is built

### 2.1 `GET /clients/{uuid}/test-nodes-available`

**The written rule is wrong and this cut corrects it.** `clientnodes.go` and
`docs/superpowers/handover/scattered-remainder.md` both record a *two*-condition
rule - "`{}` unless the client has an `adminUrl` **and** at least one registered
node - either alone gives `{}`". Re-measured on 2026-09-06 in all four cells:

```
no adminUrl, no node        {}
no adminUrl, one node       {}
adminUrl,    no node        {"failedRequests":["http://10.255.255.1:9/adm"]}
adminUrl,    one node n1    {"failedRequests":["http://n1:9/adm"]}
```

It is **one** condition - a non-empty effective `adminUrl` - and the nodes decide
the *contents* rather than whether the endpoint answers. Each registered node
contributes the adminUrl with its **host replaced by the node's name**, scheme,
port and path kept. `rootUrl` is resolved into a relative `adminUrl` first, and
an `adminUrl` that is the empty string is the `{}` case even with a node
registered.

Gloak's `model.Client` carries no `adminUrl`; `sessions.go` records the same
about `logout-all`'s success list and `push-revocation`'s. So the reachable
answer is `{}` on every client Gloak can serve, and the handler is `{}` with the
rule above written over it - `pushRealmRevocation`'s precedent, applied on the
strength of a measurement rather than by analogy.

Guard, measured one role at a time over nineteen single `master-realm` roles
plus a caller holding nothing, with `GET /clients` as a control that differs in
both directions: `manage-clients` alone is 200, `view-clients` is 403, and the
order is realm, caller, the coarse `clientsReadRoles` gate, the client, then
`manage-clients` - `guardClientSubject`, unchanged, the combinator its two node
siblings already use.

### 2.2 `GET /client-registration-policy/providers`

Eight providers, 4427 bytes on master, `application/json;charset=UTF-8` with
`Cache-Control: no-cache` and all five security headers. The provider order and
the 39-name `allowed-protocol-mapper-types` option list are **identical between
master and a created realm**; the 16-name `allowed-client-scopes` option list is
**not**, so that one list gets `Case.Unordered` and its neighbour deliberately
does not.

The option list is the realm's client scope names plus the literal `openid`, and
it tracks the realm: creating a client scope made it appear.

Guard: `view-realm` or `manage-realm`, and **every clients role is 403** -
including `view-clients` and `manage-clients` on an endpoint the description
tags `Client Registration Policy`.

### 2.3 `GET /organizations/members/{member-id}/organizations`

The body is **byte-identical** to its org-scoped twin
`GET /organizations/{orgID}/members/{memberID}/organizations`, compared with
`cmp` on a member of two organizations. `briefRepresentation` is the only
parameter that does anything; `search`, `first`, `max` and `exact` are ignored,
measured with `search=nomatch` still answering both organizations.

Guard: `organizationsListReadRoles` **and** `organizationMemberReadRoles` - the
conjunction its twin has, on the coarse half that **includes
`query-organizations`**. That is what separates the two routes:
`query-organizations` + `view-users` is 200 here and 403 on the twin.

Registration, because `ServeMux` refuses the pattern:

- a `GET` catch-all `.../organizations/{a}/{b}/{c}`, which is a strict superset
  of every four-segment pattern the family registers and therefore conflicts
  with none of them;
- three fully literal `GET` twins - `members/members/organizations`,
  `members/groups/organizations`, `members/identity-providers/organizations` -
  because those three paths are claimed by a more specific existing pattern, and
  Keycloak answers all three from the top-level route;
- **not** a third literal pattern to break the original conflict: that was
  re-checked against Go 1.26.6 and still panics, because the conflict check is
  pairwise. F153 was right.

The catch-all's own 404s are the two measured bodies, guarded as measured: the
coarse gate is `organizationsListReadRoles`, the organization is resolved next
(404 to a `query-organizations` caller for an id that resolves to nothing), and
`organizationReadRoles` is checked last (403 to that same caller for one that
resolves).

## 3. What is not built, and why

### `GET /clients/{uuid}/installation/providers/{providerId}` - three legs

1. **Three of the eleven bodies cannot be pinned by a golden.**
   `docker-v2-compose-yaml` and `mod-auth-mellon` answer `application/zip`,
   which F161 answered and `RefuseNonTextBody` now enforces. `saml-sp-descriptor`
   is `text/plain` and carries an `ID="ID_<uuid>"` minted per request; the four
   body masks address a JSON document and the two HTML masks address HTML, so
   nothing in this harness reaches a value inside a text body.
2. **Five of the eleven are SAML adapter configuration.** This project has no
   SAML path, which is the standing reason `generate-example-saml-response` is
   `Pending`; writing five SAML templates for a server that cannot speak SAML is
   F38's "machinery with no consumer".
3. **Two fields of the one body that looks easiest are decided by client
   attributes Gloak does not model.** `keycloak-oidc-keycloak-json` carries
   `verify-token-audience` and `use-resource-role-mappings` on `account` and
   neither on a client created through `POST /clients`.

Everything measured about the operation is in the handover, including the
finding that **`application/zip` omits `X-Frame-Options`** and carries the other
four - the media type the security-header bullet says nobody has measured.

### `POST /identity-provider/import-config` - the 200 is unreachable for a golden

Measured, and the first probe measured itself: from outside the container every
input answered 500, because `localhost:8179` is not reachable *from* the
container. Pointed at the container's own view of itself it answers 200 with a
ten-key config map.

```
reachable discovery document        200 {"userInfoUrl":…,"useJwksUrl":"true"}   ten keys
unreachable host                    500 {"error":"unknown_error",…}
file:///etc/passwd                  500 the same
a URL that is not a URL             500 the same
an unknown providerId               500 the same
no fromUrl, or no providerId        400 {"error":"HTTP 400 Bad Request"}
```

**What it does when the fetch fails**: `500 unknown_error` with
`For more on this error consult the server log.`, plain `application/json`, no
`Cache-Control`. **What it does with a URL pointing at the host**: it fetches it.
There is no loopback guard - the container fetched its own
`http://localhost:8080/realms/master/.well-known/openid-configuration` and
answered with it - so the operation is an authenticated outbound fetch of an
operator-supplied URL, and that is the contract rather than a defect.

The boundary is not the SSRF shape, it is that the 200 cannot be recorded or
verified. The recorder would need the reference container to reach a URL, and the
verifier serves through `httptest.ResponseRecorder` in a suite that must never
need the network. So the only cases a golden could hold are the 400 and the 500,
neither of which may name `Operation` - `Case.Operation` means "demonstrates the
operation is **served**" - and the handler would move parity by zero while being
compared by nothing.

### The three already-`Pending` ones

`registration-access-token`'s reason names `internal/oidc`'s `registrationStore`
and says the move needs one cut holding both that package and `internal/store`.
This cut owns `internal/store` and not `internal/oidc`, which is the same half it
had before, so the reason has not expired. The same is true of
`generate-example-userinfo`, whose one truth is `userinfoDocument` in
`internal/oidc`, and of `generate-example-saml-response`. None is re-litigated.

## 4. Order of work

1. This plan, committed first, so the mutation pass has a clean tree to revert to.
2. `internal/admin/clientregistrationpolicy.go` and the `test-nodes-available`
   handler in `clientnodes.go`, with their unit tests.
3. The organization route: the catch-all, the three literal twins, the
   registration test that no pattern steals the shape.
4. Catalogue cases, inserted immediately after the last `admin/workflows` case;
   fixtures inserted immediately after the `oidcCore` block; `make record`
   against the reference container; goldens committed unedited.
5. The mutation pass - a different mutation per claim, the named test confirmed
   failing, each revert checked with `git diff`.
6. `docs/superpowers/handover/clients-singles.md`, then the pull request.

## 5. Parity

```
chapter                            before   after
admin/clients                       30/35   31/35
admin/client-registration-policy     0/1     1/1
admin/organizations                 35/36   36/36
total                             512/541  515/541
```

Two chapters go to complete.
