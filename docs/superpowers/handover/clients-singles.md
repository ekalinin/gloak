# The `Clients` singles and three lone operations

Eight operations: the five the `Clients` tag had left, and one each from
`Client Registration Policy`, `Identity Providers` and `Organizations`. Three
are built, five are left with a measured reason each. The plan is
`docs/superpowers/plans/2026-09-06-clients-singles.md`, whose first section is
one row per operation.

The list was recomputed rather than inherited, by a method that evaluates Go
values instead of reading Go source: a throwaway test in `internal/conformance`
joining the vendored description's `paths` against the assembled `Catalog`'s
`Operation` fields, so a case whose path is written `"a" + "b"` compares as
`ab`. It reported 30 of the `Clients` tag's 35 operations served and named the
same five the brief did; the whole-surface run named 31 unclaimed operations in
all and the same three lone ones. The probe printed three different statuses,
so it is not a function returning one answer.

Everything below was measured against `quay.io/keycloak/keycloak:26.7.1` on
:8179, whose `GET /admin/serverinfo` reported `26.7.1` before anything was
believed.

## 1. Measurements

### 1.1 `test-nodes-available` is one condition, not two, and the rule already written down was wrong

`internal/admin/clientnodes.go` and §2 of
`docs/superpowers/handover/scattered-remainder.md` both recorded, from
2026-09-05:

> It answers `{}` unless the client has an `adminUrl` **and** at least one
> registered node - either alone gives `{}`.

Re-measured 2026-09-06 across all four cells, with the nodes registered through
the sibling write:

```
no adminUrl, no node        {}
no adminUrl, one node       {}
adminUrl,    no node        {"failedRequests":["http://10.255.255.1:9/adm"]}
adminUrl,    one node n1    {"failedRequests":["http://n1:9/adm"]}
```

**The `adminUrl` alone is enough.** The cell that was wrong is the third one -
the one where the endpoint answers something without a node - and the reason the
first reading is plausible is that the *fourth* cell looks like the interesting
one and both readings agree there.

What the nodes do is decide the **contents**. Each registered node contributes
the adminUrl with its **host replaced by the node's name**, keeping the scheme,
the port and the path:

```
adminUrl https://app.example.org/callback, nodes zzz aaa mmm
  -> ["https://aaa/callback","https://mmm/callback","https://zzz/callback"]
rootUrl http://root.example.org + adminUrl /rel, node nr1
  -> ["http://nr1/rel"]
adminUrl "" , node ne1
  -> {}
```

So `rootUrl` is resolved into a relative `adminUrl` first, and an `adminUrl`
that is the **empty string** is the `{}` case even with a node registered -
which is what makes the condition "a non-empty effective adminUrl" rather than
"an adminUrl key".

**`failedRequests` is not the map's order.** `registeredNodes` serialises
`{kn1, kn2}` as `kn2, kn1` - the sized Java map, which
`javamap.SizedKeyOrder` places - and `failedRequests` for the same client in the
same response family answers `kn1, kn2`. Two orders out of one map. Sorted fits
both measured sets and insertion order fits neither: `zzz, aaa, mmm` inserted in
that order came back `aaa, mmm, zzz`.

Guard, one role at a time over nineteen single `master-realm` admin roles plus a
caller holding nothing, with `GET /clients` as a control known to differ:
`manage-clients` alone is 200 and **`view-clients` is 403**. The resolution
order is the two node writes': realm, caller, a coarse `clientsReadRoles` gate,
the client, then the route's own role - so `view-clients` and `query-clients`
both see `Could not find client` for a UUID that resolves to nothing and 403 for
one that resolves.

Headers: `application/json;charset=UTF-8`, all five security headers, and
**`Cache-Control: no-cache`** - where `POST .../push-revocation` writes the same
`{}` from the same Java type one path segment away and carries none.

Wrong verbs: `POST`, `PUT` and `DELETE` answer `404 {"error":"HTTP 404 Not
Found"}` and **`PATCH` answers a real 405**. One path, five verbs, two answers,
and it is PATCH alone - the protocol mappers' shape met on a second family.

### 1.2 `client-registration-policy/providers` is eight providers and one variable list

4427 bytes on a default master, `application/json;charset=UTF-8`,
`Cache-Control: no-cache`, all five security headers. Two reads of one realm are
byte-identical.

The eight ids come back in this order on master **and** on a realm created
through `POST /admin/realms`:

```
allowed-client-templates, registration-web-origins, client-disabled, scope,
max-clients, allowed-protocol-mappers, trusted-hosts, consent-required
```

So does `allowed-protocol-mappers`' 39-name option list, name for name. Neither
is masked.

**`allowed-client-scopes`' option list is the one thing that moves**, and it
moves two ways:

- it is the realm's own client scope names **plus the literal `openid`**, which
  is not a client scope - the realm's `GET /client-scopes` returns fifteen and
  the option list offers sixteen. Creating a client scope makes its name appear;
  measured with the mapper list read in the same two requests as a control that
  did not move.
- master and a created realm answered the **same sixteen names in different
  orders**. The names cannot explain that, so it is ordered by something
  per-realm - the scopes' ids are the obvious candidate and were not chased.
  This is the case's one `Unordered`.

Guard: `view-realm` or `manage-realm`, and **every clients role is 403**. Swept
one role at a time over nineteen single roles plus a caller holding nothing,
with `GET /clients` as a control that differs in **both** directions:

```
                  GET /clients   this listing
view-realm             403            200
manage-realm           403            200
view-clients           200            403
manage-clients         200            403
query-clients          200            403
fourteen others        403            403
```

The four wrong verbs answer a **real 405** on all four.

### 1.3 F153's route, and the question the entry left open

`GET /organizations/members/{member-id}/organizations` answers a body **byte
identical** to its org-scoped twin, compared with `cmp` on a member of two
organizations. The two differ in what precedes the body: this route has no
organization in its path and answers 200 and `[]` for a user of the realm who
belongs to none, where the twin answers 404 for the same user.

**`briefRepresentation` is the only parameter it reads.** `search`, `first`,
`max` and `exact` do nothing at all - `search=nomatch` still answered both
organizations - so this is a fourth shape beside the three paging rules
AGENTS.md records, and the shape is that there is no paging.

An unknown member id, and one that is not a UUID, both answer
`404 {"error":"HTTP 404 Not Found"}`.

Guard, one pair at a time:

```
                                     top-level   org-scoped
view-organizations   + view-users        200         200
manage-organizations + view-users        200         200
manage-realm         + view-users        200         200
query-organizations  + view-users        200         403
view-organizations   + query-users       403         403
view-organizations   + view-realm        403         403
view-organizations   alone               403         403
view-users           alone               403         403
```

Both need a conjunction and the coarse halves differ by exactly
`query-organizations`. A single-role sweep says nothing here: the only single
role that opens either route is the composite `realm-admin`, so a sweep that
stopped at single roles would have reported "no role opens it" for both and
missed the difference entirely.

**The routing.** The pattern this path wants conflicts with **three** of the
family's registered routes, not one:

```
{orgID}/members/{memberID}              /organizations/members/members/organizations
{orgID}/groups/{groupID}                /organizations/members/groups/organizations
{orgID}/identity-providers/{idpAlias}   /organizations/members/identity-providers/organizations
```

Neither side of any pair is a strict subset of the other. A third, fully literal
pattern does **not** break the tie - re-checked against Go 1.26.6 rather than
inherited, because `net/http`'s conflict check is pairwise. F153 was right about
that.

Keycloak answers **all three of those paths, and `members/count/organizations`
beside them**, `404 {"error":"HTTP 404 Not Found"}` - the top-level route
reading the middle segment as a member id that resolves to nothing. So JAX-RS
gives the literal `members` the win over the `{orgID}` wildcard on the whole
four-segment shape, not only on the one path F153 measured.

**F153's remaining question is answered and the answer is favourable.** The entry
said a wildcard dispatcher would swallow paths that "answer the unmatched-path
404 with none of the five security headers", and asked whether that held for
`/organizations/{a}/{b}/{c}` where `{b}` is not a locator that resolves. It does
not. Every four-segment `GET` under `/organizations` answered with **all five**:

```
{a resolvable org}/bogus/thing   404 {"error":"HTTP 404 Not Found"}
nosuchorg/bogus/thing            404 {"errorMessage":"Organization not found."}
{org}/bogus                      404 {"error":"HTTP 404 Not Found"}
{org}/bogus/thing/more           404 {"error":"HTTP 404 Not Found"}
members/bogus/x                  404 {"errorMessage":"Organization not found."}
{org}/groups/nosuchgroup         404 {"errorMessage":"Group does not exist"}
```

and so did `/admin/realms/{realm}/nosuchcollection/x/y/z`, which is the control:
the header-less 404 belongs to a path that matches nothing at the **server**
root, and everything under `/admin/realms/{realm}/` reaches the filter chain.

Gloak served all of those as `{"error":"Unable to find matching target resource
method"}` with **none** of the five, which `WithKeycloakFallbacks`' own doc
comment describes. So the dispatcher is more faithful than the fallback here,
not less - which is what F153's 2026-09-03 note found for the group family, met
on the shape it said was still open.

The guard on those 404s is measured and is **neither** of the family's two
combinators: the coarse gate is `organizationsListReadRoles`, the organization
is resolved next, and `organizationReadRoles` is checked last.
`query-organizations` gets 404 for an organization that does not exist and 403
for one that does, where `guardOrganizationAnd` would answer 403 to both.

**The verbs.** The dispatcher is `GET`-only, and the reason is in the
measurement:

```
                                  GET   POST  PUT   DELETE  PATCH
{resolvable org}/bogus/thing      404   405   404   404     405
nosuchorg/bogus/thing             404   404   404   404     404
members/{uuid}/organizations      200   404   404   404     404   (all four "Organization not found.")
```

`POST` and `PATCH` on a resolvable organization answer a **real 405**, and
reproducing a 405 is F31's standing question rather than this cut's. A
method-less dispatcher would have had to answer them.

### 1.4 `installation/providers/{providerId}` - measured, not built

All eleven answer 200 with `Cache-Control: no-cache`. Nine are `text/plain`;
`docker-v2-compose-yaml` and `mod-auth-mellon` are `application/zip`. An unknown
provider is `404 {"error":"Unknown Provider"}`. `view-clients` and
`manage-clients` read it, `query-clients` is 403 - which confirms
scattered-remainder's claim that this endpoint and `test-nodes-available` sit
next to each other and disagree about the view role.

**`application/zip` omits `X-Frame-Options` and carries the other four**, which
is the media type AGENTS.md's header bullet says nobody has measured. Both zip
responses do, and so do all nine `text/plain` ones. That is one more media type
on the `X-Frame-Options`-alone side of the split and none on the other.

The bodies vary with the client in ways that are bounded but real, measured
across a public client, a confidential one, a bearer-only one and a SAML one:

```
keycloak-oidc-keycloak-json
  bearer-only    inserts "bearer-only": true after "realm"
  public         inserts "public-client": true after "resource"
  confidential   inserts "credentials": {"secret": ...} after "resource"
  account only   carries "verify-token-audience" and "use-resource-role-mappings"
keycloak-saml
  entityID is the client's resolved baseUrl, or "SPECIFY YOUR entityID!"
docker-v2-*
  a double slash: http://host//realms/master/protocol/docker-v2/auth
saml-sp-descriptor
  ID="ID_<uuid>", minted per request, inside a text/plain body
```

### 1.5 `import-config`, and the probe that measured itself

The first probe reported `500` for **every** input including a URL that
obviously works - and the missing condition was not in the request. From outside
the container, `http://localhost:8179/...` is not reachable *by* the container.
Pointed at the container's own view of itself it answers 200. That is the
`testSMTPConnection` shape from the previous cut, met again by a different
route.

```
reachable OIDC discovery       200 ten keys, application/json;charset=UTF-8, no Cache-Control
providerId oidc / keycloak-oidc  byte-identical to each other
reachable SAML descriptor      200 seventeen keys, signingCertificate among them
unreachable host               500 {"error":"unknown_error","error_description":"For more on this error consult the server log."}
file:///etc/passwd             500 the same
a string that is not a URL     500 the same
an unknown providerId          500 the same
no fromUrl, or no providerId   400 {"error":"HTTP 400 Bad Request"}
```

**What it does when the fetch fails**: the 500 above, plain `application/json`,
no `Cache-Control`, and the same body for a bad URL, a bad scheme and an unknown
provider - four causes, one answer. **What it does with a URL pointing at the
host**: it fetches it. There is no loopback guard; the container fetched its own
`localhost:8080` discovery document and answered with it.

## 2. Entries for AGENTS.md's "Things that look like bugs and are not"

Written in that file's voice, for whoever folds them in.

- **`GET .../clients/{uuid}/test-nodes-available` needs one condition, not two,
  and the node names are substituted into the host.** It answers `{}` exactly
  when the client's effective `adminUrl` is empty, and this file said "an
  `adminUrl` **and** at least one registered node" until 2026-09-06. A client
  with an `adminUrl` and **no** node answers
  `{"failedRequests":["<the adminUrl>"]}`; with nodes it answers one URL per
  node, the adminUrl with its **host replaced by the node's name** and the
  scheme, port and path kept, so `https://app.example.org/callback` with a node
  `aaa` answers `https://aaa/callback`. `rootUrl` is resolved into a relative
  `adminUrl` first and an `adminUrl` that is the **empty string** is the `{}`
  case even with a node registered. The wrong cell was the one where the
  endpoint answers *without* a node, which is exactly the cell a two-condition
  reading has no reason to send.

- **One map, two orders, one response family.** `registeredNodes` serialises
  `{kn1, kn2}` as `kn2, kn1` - the sized Java HashMap - and
  `test-nodes-available`'s `failedRequests` answers `kn1, kn2` for the same
  client. Sorted fits both measured sets of `failedRequests` and insertion order
  fits neither. Reusing the map's own ordering for the array is the obvious
  saving and it is wrong.

- **`GET .../test-nodes-available` carries `Cache-Control: no-cache` and
  `POST .../push-revocation` carries none.** Same `{}`, same Java type, same
  tag, one path segment apart. That is the third pair inside the client family
  after the node write and the node delete, and it is the cheapest counterexample
  yet to any rule about `Cache-Control` stated over the verb, the status or the
  body.

- **`test-nodes-available` answers `PATCH` a real 405 and the other three verbs
  a 404.** One path, five verbs, two answers, and the odd one is PATCH - which
  is the protocol mappers' split met on a second family. Gloak sends 404 to all
  four. See F31.

- **`GET /client-registration-policy/providers` is authorised out of the realm
  pair, and every clients role is 403 on it.** `view-clients`,
  `manage-clients` and `query-clients` are all refused a listing whose one
  variable option list is made of the realm's client scope names, and
  `view-realm`/`manage-realm` read it - measured with `GET /clients` alongside,
  which differs in both directions. That is the third time the description's tag
  has failed to predict the guard, after the client-scope family's `Realms
  Admin` routes taking the clients set, and it is the first time a
  client-shaped tag has taken the realm set.

- **The client-registration-policy listing's option list is the realm's client
  scopes plus a name that is not one.** A default realm has fifteen client
  scopes and `allowed-client-scopes` offers sixteen values; the extra is the
  literal `openid`, which `GET /client-scopes` does not carry. The list follows
  the realm - creating a client scope makes it appear - and its **order is not
  reproducible across realms**: master and a realm created through
  `POST /admin/realms` answered the same sixteen names in different orders, so
  nothing about the names explains it. The 39-name mapper list beside it and the
  eight provider ids came back in the same order on both realms and are asserted
  whole; one list of three varies, and it is the only one masked.

- **`defaultValue` on a `"type":"boolean"` property is a JSON boolean on one
  provider and a JSON string on another.** `allow-default-scopes` sends `true`
  and `trusted-hosts`' two flags send `"true"`, in the same body, on the same
  declared type. Normalising either is the tidy-up that changes a byte.

- **JAX-RS gives the literal `members` the win over the `{orgID}` wildcard on
  the whole four-segment shape.**
  `/organizations/members/{anything}/organizations` reaches the top-level member
  route, so `members/members/organizations`, `members/groups/organizations`,
  `members/identity-providers/organizations` and `members/count/organizations`
  all answer `404 {"error":"HTTP 404 Not Found"}` - the top-level route reading
  the middle segment as a member id that resolves to nothing - and not
  `Organization not found.`, which is what an organization called `members`
  would answer. Go's `ServeMux` gives the win to the *more specific* pattern
  instead, which is the opposite, and is why the route needs one wildcard plus
  three literals rather than one pattern.

- **A four-segment path under `/organizations` gets all five security headers,
  and which 404 body it gets is decided by the first segment.** A resolvable
  organization with a sub-resource that does not exist answers
  `{"error":"HTTP 404 Not Found"}`; an organization id that resolves to nothing
  answers `{"errorMessage":"Organization not found."}`. Both carry the five
  headers, because both reach the filter chain through the realm - the
  header-less 404 belongs to a path that matches nothing at the server root.
  Answering these out of the unmatched-path fallback is what Gloak did until
  2026-09-06 and it was wrong on the body and on all five headers.

- **`GET /organizations/members/{member-id}/organizations` reads no parameter
  but `briefRepresentation`.** `search`, `first`, `max` and `exact` are all
  ignored - `search=nomatch` answers every one of the member's organizations -
  where the organization listing one path segment up reads its own `search`.
  That is a fourth answer beside the three paging rules this file records, and
  it is "no paging at all".

- **The top-level member route and its org-scoped twin serve byte-identical
  bodies and have different guards.** Both need a conjunction; the coarse half
  differs by exactly `query-organizations`, which opens the top-level route with
  a user-read role and is 403 on the twin. Neither is opened by any single admin
  role, so a single-role sweep reports "nothing opens either" and misses the
  difference - it takes a pair sweep to see it.

- **`POST /identity-provider/import-config` fetches whatever URL it is given,
  including one pointing at the server itself.** There is no loopback guard: a
  Keycloak asked for its own `http://localhost:8080/realms/master/.well-known/openid-configuration`
  fetches it and answers 200 with the config map built from it. Every failure -
  an unreachable host, a `file://` URL, a string that is not a URL, an unknown
  `providerId` - is the same `500 unknown_error`, and a missing `fromUrl` or
  `providerId` is `400 {"error":"HTTP 400 Bad Request"}`. Four causes, one
  answer, and the 200 needs a network the test suite may not have.

- **`application/zip` omits `X-Frame-Options` and carries the other four.**
  Measured on `GET .../installation/providers/docker-v2-compose-yaml` and
  `.../mod-auth-mellon`, the tag's two binary bodies. That is a fourth media
  type on the `X-Frame-Options`-alone side, after `text/plain`,
  `application/octet-stream` and a `Content-Type`-less 204, and it is one the
  header bullet named as unmeasured. No golden can hold it - see F161 - so the
  measurement lives here.

## 3. Follow-up dispositions

### F153 - closed, and the half that was still open is measured false

The entry's objection to a wildcard dispatcher was that it would swallow paths
whose 404 only `WithKeycloakFallbacks` can produce. §1.3 sends the request the
2026-09-03 note asked for and the answer is that **every** four-segment `GET`
under `/organizations` carries all five security headers, including the ones
where the second segment is not a locator that resolves. So the dispatcher is
more faithful than the fallback for this whole shape, and Gloak's answers for
six such paths moved from a header-less 404 with the wrong body to Keycloak's
own.

Two things in the entry survive unchanged and are worth keeping:

- **a third literal pattern does not break the conflict.** Re-checked against Go
  1.26.6 rather than inherited: `net/http`'s conflict check is pairwise.
- **the conflict is real and the panic is at registration.** What the entry did
  not have is that it is three conflicts rather than one, and that Keycloak
  resolves all three the same way - toward the top-level route, which is why the
  three literals point there.

The dispatcher is `GET`-only because `POST` and `PATCH` on those paths answer a
real 405, and F31 is where that question lives.

### F161 - unchanged, and its answer is what keeps one operation out of this cut

`installation/providers/{providerId}` is eleven bodies and **three of them
cannot be pinned by a golden**: two are `application/zip`, which
`RefuseNonTextBody` refuses at the moment of recording, and `saml-sp-descriptor`
is `text/plain` carrying an `ID="ID_<uuid>"` minted per request. That third one
is worth adding to the entry: F161 is written about binary bodies, and the
harness has the same gap one step in - **the four body masks address a JSON
document and the two HTML masks address HTML, so no mask reaches a value inside
a `text/plain` body.** Nothing was built for it, because a mask with one
consumer is F38's shape and the operation is declined on two other grounds
anyway.

### F148 - unchanged, and its three refusals were re-checked rather than assumed

All three of the operations this cut was told not to re-litigate rest on
`internal/oidc`, which this branch may not touch:

- `registration-access-token`'s minted token is only usable if
  `internal/oidc`'s in-memory `registrationStore` recognises its `jti`. The
  entry says the move needs one cut holding both that package and
  `internal/store`. This cut owns `internal/store` and not `internal/oidc`,
  which is the same half the previous cut had, so the reason has not expired.
- `generate-example-userinfo` rests on `userinfoDocument` in
  `internal/oidc/userinfo.go`. Same boundary, same answer.
- `generate-example-saml-response` needs a SAML issuance path and a mask that
  can reach inside a JSON string. Neither is closer.

What this cut adds to the entry is a **fourth** shape of refusal that is not
about a package boundary at all. `POST /identity-provider/import-config` could
be written in `internal/admin` today - it needs an `http.Client` and nothing
else - and it is declined because **its 200 is unreachable for the harness in
both directions**: the recorder would need the reference container to reach a
URL, and the verifier serves through `httptest.ResponseRecorder` in a suite that
must never need the network. The only cases a golden could hold are the 400 and
the 500, and neither may name `Operation`, so the handler would move parity by
zero while being compared by nothing. F148 is about where a value is built; this
is about whether the value can be measured, and the two are different questions
that produce the same `Pending`.

### F157 - untouched, checked rather than assumed

`attack-detection` stores nothing because nothing counts a failed
authentication. None of the three operations built here authenticates anybody or
counts anything: `test-nodes-available` reads a field that does not exist, the
registration-policy listing reads client scope names, and the member route reads
a membership table. No writer was added to that record and nothing closes.

It is named for a second reason, which is that its shape is the one §1.1 reuses.
`test-nodes-available` answers `{}` because `model.Client` has no `adminUrl`,
the way attack-detection answers the zero record because nothing counts a
failure. In both cases **adding the column would be a claim about the model that
is not true** until the thing that writes it exists - here the outbound push,
which Keycloak's answer depends on: it reports a node as failed *because the
push to it failed*, so a handler that listed the nodes without asking them would
be inventing an answer rather than measuring one. No `adminUrl` was added.

### F95 - untouched, and one measurement is relevant to it

The client's `attributes` is still a Go map. `test-nodes-available`'s
`failedRequests` is a **second** ordering out of `registeredNodes`, and it is
not `javamap`'s: sorted, where the map is `SizedKeyOrder`'s. When F95's move
lands and takes `registeredNodes` with it, the array beside it must not inherit
the map's ordering.

## 4. Parity before and after

```
chapter                            before   after
admin/clients                       30/35   31/35
admin/client-registration-policy     0/1     1/1
admin/organizations                 35/36   36/36
total                             512/541  515/541
```

Measured against `74db295`, which is where this branch was cut. **Two chapters
go to complete**: `Client Registration Policy` was a whole tag of one operation
and `Organizations` had one left.

The three left in `admin/clients` are the two `evaluate-scopes` generators and
`registration-access-token`, all three `Pending` with their reasons in the
catalogue, plus `installation/providers/{providerId}`, which is now `Pending`
nowhere and declined in the plan - it has no case, because a case with no
fixture is inventory and the reason is better written where a reader will find
it. `identity-provider/import-config` is the same.

## 5. The mutation pass

Fourteen mutations, one per claim, each reverted and each revert checked. The
harness refuses to run on a dirty tree, refuses a mutation that changes no byte,
refuses one that does not compile, and **reads `go test`'s exit code before it
looks at the log**. It was given a control known **not** to differ - a
comment-only edit - before anything else, and that one survived, so the harness
was not reporting KILLED for everything.

| # | mutation | test | result |
|---|---|---|---|
| 00 | a comment only | the registration policy tests | SURVIVED, as required |
| 01 | `test-nodes-available` loses its `Cache-Control` | `TestTestNodesAvailableCarriesCacheControlAndPushRevocationDoesNot` | killed |
| 02 | the read takes `clientsReadRoles` | `TestTestNodesAvailableIsTheThirdRouteOnTheClientSubjectGuard` | killed |
| 03 | the scope fill reaches every option list | `TestAllowedClientScopesFollowsTheRealm` | killed |
| 04 | `openid` is dropped | `TestAllowedClientScopesCarriesOpenIDWhichIsNotAClientScope` | killed |
| 05 | the fill writes through the shared providers | `TestTheRegistrationPolicyListingLeavesTheEmbeddedProvidersAlone` | **survived**, then killed |
| 06 | the policy listing takes the clients pair | `TestTheRegistrationPolicyListingIsTheRealmPairAndNotTheClientsPair` | killed |
| 07 | the three literal patterns go | `TestTheTopLevelMemberOrganizationsRouteIsRegistered` | killed |
| 08 | the fine role precedes the organization | `TestTheFourSegmentDispatcherAnswersBothMeasured404s` | killed |
| 09 | the coarse gate loses `query-organizations` | `TestTheTopLevelMemberOrganizationsGuardIsNotItsTwins` | killed |
| 10 | the top-level route reads `search` | `TestTheTopLevelMemberOrganizationsRouteIgnoresEveryParameterButBrief` | killed |
| 11 | one 404 body for both dispatcher cases | golden `admin/organizations/four-segment-unknown-organization` | killed |
| 12 | the top-level route answers about another user | `TestTheTopLevelMemberOrganizationsRouteMatchesItsTwinByte` | killed |
| 13 | the option list's `Unordered` goes | golden `admin/client-registration-policy/providers` | killed |

**Mutation 05 survived, and the reason is that no serial caller can see it.**
The eight providers are decoded once into a package-level slice and every
request fills the option list before writing its body, so a handler writing
through the shared backing array serves the right answer to every request in
sequence and is wrong only when two realms are in flight at once. The test
written the obvious way - two realms, read each twice, check neither has the
other's scopes - passes under the mutation, because each read refills before it
serves.

The test now asserts the **invariant** instead: `loadClientRegistrationPolicies`
is read directly and its first property's options must still be nil after a
request has been served, with the served list checked non-empty in between so
the assertion cannot pass because the fill never ran. That is deterministic, and
it killed the mutation on the re-run. It is the same failure the previous cut
recorded for mutation 10 - an assertion whose two sides come from one place -
reached from the other side: an assertion about a symptom that the code under
test destroys before anyone can look.

**Mutation 13 killed for a reason the case comment did not originally give**, and
the comment now says both. The `Unordered` was added because Keycloak's order is
not reproducible across realms; it is *also* load-bearing because Gloak appends
`openid` after the store's own ordering, so removing it fails the golden on this
container rather than failing `TestNoMaskIsInertOnItsGolden`. The mask does real
work either way; a comment naming only one of its two jobs is the sentence the
next cut half-believes.

Two cells were **left unmeasured on purpose** and no mutation was written for
either:

- **the non-empty `test-nodes-available` body.** Gloak has no `adminUrl`, so
  every input reaches the `{}` branch, and a mutation that broke the other
  branch would survive because the branch does not exist. Building it means
  building the outbound push, which is §3's F157 note.
- **`failedRequests`' order.** It is sorted on both measured sets and there is
  no code here that produces it, so there is nothing to mutate. The measurement
  is in §1.1 for whoever adds the field.

## 6. What is not here

- **No store interface method and no migration.** The registration policy
  listing reads through `ClientScopeRepo.ListByRealm` and the member route
  through `OrganizationRepo.MemberOf`, both of which existed, so `0038_*` was
  never written and neither driver changed.
- **No fixture.** All seven cases reuse `admin-token`, `client-node-bare`,
  `client-node-registered` and `org-member-one`, so `internal/conformance/fixture.go`
  is untouched.
- **One recorder artefact, reverted rather than committed.** `make record`
  rewrote `admin/realms-admin/partial-export-clients.http`, whose body is the
  whole realm representation and whose every difference is a per-container
  UUID - the realm's id, `defaultRole`'s id and the rest. It is a `Recorded`
  case, so nothing compares it and the churn is invisible in CI; it is the same
  shape as the artefact the previous cut recorded for
  `evaluate-scope-mappings-not-granted`. It was reverted and the suite passed
  against the committed bytes afterwards.
- **`installation/providers/{providerId}` and `import-config` have no case at
  all**, deliberately: a case with no fixture is inventory, and the reasons for
  both are three and two lines respectively in the plan rather than one line in
  a `Reason`.
