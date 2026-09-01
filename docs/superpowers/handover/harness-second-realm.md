# F142: a second realm in the conformance harness

Branch `feat/harness-second-realm`. Everything measured below was taken against a
live Keycloak 26.7.1 on 2026-09-01 - container `kc-realm2`, port 8155,
`start-dev`, bootstrap admin `admin/admin`, removed afterwards - or read off this
repository's own catalogue and goldens. The plan is at
`docs/superpowers/plans/2026-09-01-harness-second-realm.md`.

## 1. Measurements

### 1.1 F142's premise is false, and the count is what says so

F142 says "every case in `internal/conformance` is recorded and replayed against
`master`". Counted from the catalogue rather than estimated:

```
cases in the catalogue                                     592
cases whose path names a realm that is not master           66
of those, Implemented                                       65
distinct non-master realm segments                          34
```

The second realm has been in the harness since P4. `realmFixture(name)` creates
one through `POST /admin/realms`, five fixtures call it, `createdKeys` in the
pollution guard already carries `"realm"`, and `admin/realms-admin/list` is
already `PristineRealm` so a new realm on the shared container cannot pollute it.
**Nothing had to be built for a case to run against a second realm.**

What is true is narrower and is the thing worth writing down:

```
goldens whose *response* (headers and body, not the request-line comment)
carries the realm name the case addressed                   60
  of those, addressed at master                             58
  of those, addressed at a realm the case's fixture made     2
```

The two are `admin/organizations/create`, whose `Location` is built from
`rc.realm.Name`, and `admin/realms-admin/read`, whose body's `realm` and
`defaultRole.name` are. Both already fail on a hard-coded `master`, and nobody
had noticed that they do.

### 1.2 Twenty derivation sites, eighteen blind, one pinned elsewhere

A **derivation site** is a place in served code where the realm name of the
request becomes a response byte. Counted from the list, not incremented:

| # | site | what it produces | asserted against |
|---|---|---|---|
| 1 | `admin/clients.go:154` | `POST /clients` `Location` | master only |
| 2 | `admin/users.go:278` | `POST /users` `Location` | master only |
| 3 | `admin/groups.go:386` | `POST /groups` `Location` | master only |
| 4 | `admin/groups.go:409` | `POST /groups/{id}/children` `Location` | master only |
| 5 | `admin/roles.go:254` | `POST /roles` `Location` | master only |
| 6 | `admin/roles.go:482` | `POST /clients/{u}/roles` `Location` | master only |
| 7 | `admin/identityproviders.go:437` | `POST .../instances` `Location` | master only |
| 8 | `admin/organizations.go:360` | `POST /organizations` `Location` | **a created realm** |
| 9 | `admin/realms.go:449`,`:456` | `GET /admin/realms/{r}` body | **a created realm** |
| 10 | `admin/representation.go:123` | a client's `access` block, via `isAdminContainerName` | master only |
| 11 | `oidc/discovery.go:165` | every URL in the discovery document | **now a created realm** |
| 12 | `oidc/router.go:351`,`:354` | `GET /realms/{r}` body | **now a created realm** |
| 13 | `httpx/theme.go:141` | the restart URL on every theme page | master only; **pinned by a package test** |
| 14 | `oidc/deviceverify.go:74` | the device page's form `action` | master only |
| 15 | `oidc/device.go:167` | `verification_uri`, `verification_uri_complete` | master only |
| 16 | `oidc/introspect.go:54` | the introspection body's `iss` | master only, and see below |
| 17 | `oidc/registration.go:863` | `Location` and `registration_client_uri` | master only |
| 18 | `httpx/errors.go:696` | `WWW-Authenticate: Bearer realm="..."` | **now a created realm** |
| 19 | `oidc/authorize.go:616` | the `iss` in `/auth`'s error redirect | master only |
| 20 | `admin/clientscopes.go:205`, `admin/protocolmappers.go:264` | `Location`, from `r.URL.Path` | **cannot be hard-coded** |

Before this cut: **eighteen of twenty asserted against master alone, and exactly
one of the eighteen pinned by a package test** - site 13, by
`internal/httpx`'s `TestThemeErrorPageCarriesTheChrome`, which F142's own cut
added. `internal/oidc`'s tests call `bootstrap.EnsureMaster` and nothing else, so
the whole protocol side had no second-realm coverage of any kind.

Site 16 is a special case worth not miscounting: `realmIssuer` there is the
issuer the introspection endpoint **parses** with as well as the one it echoes,
so a hard-coded `master` breaks master too. It is self-pinning rather than blind.

A further set of sites is asserted by **no** golden at all and is outside this
count: `realmCookiePath` (every `Set-Cookie` in the browser flow is masked
whole), `realmIssuer` inside the tokens (opaque), the login form's `action`,
the required-action and consent redirects, `roles.go:454`'s `<realm>-realm`
refusal, `adminRealmOf`, `AssignDefaults`, and the rename cascade.

### 1.3 A created realm's discovery document is master's with the name swapped

Measured on one container, master against a realm made by
`POST /admin/realms {"realm":"gloak-probe-r2","enabled":true}`: the two documents
are **byte-identical after substituting the realm name**, all thirty-odd URLs
included, with exactly one difference - `scopes_supported`, a Java set whose
iteration order differs between the two realms and which the master case already
declares `Unordered`.

`GET /realms/{r}` is the same story: `realm`, `token-service` and
`account-service` follow the name, `tokens-not-before` does not, and `public_key`
is the realm's own key.

### 1.4 The theme error page carries three realm-derived values, not one

This is the measurement that would not have been made any other way. The 400 page
served for an unknown `client_id`, master against a created realm, differs in
three places and only one of them is the restart URL F142 went looking for:

```
-    <title>Sign in to gloak-probe-second</title>
+    <title>Sign in to Keycloak</title>
-              class="pf-v5-c-brand">gloak-probe-second</div>
+              class="pf-v5-c-brand"><div class="kc-logo-text"><span>Keycloak</span></div></div>
```

The `<title>` and the header brand are the realm's `displayName` and
`displayNameHtml`. A realm created through `POST /admin/realms` carries neither,
so Keycloak falls back to the realm **name** in both places - and the
`<div class="kc-logo-text"><span>` wrapper is `displayNameHtml`'s markup, so it
disappears with it rather than wrapping the name. `internal/httpx/theme.go`
serves master's two values as constants, which is right on master and wrong
everywhere else.

So the page's chrome is a **third** thing that follows the realm, after the
restart URL's path and after the `client_id` parameter inside it that
AGENTS.md already records. A test asserting only that `/realms/master/` is
absent - which is what the package test does - passes a page that says
"Sign in to Keycloak" to every realm on the server.

### 1.5 Creating a realm before the token cases moves a token golden

`make record` with the new fixture in `oidcCore` moved exactly one committed
golden: `oidc/introspection/active-refresh-token`. Its `aud` gained
`gloak-probe-second-realm` and its `resource_access` gained that client with all
21 admin roles.

The reason is not the fixture: **that body enumerates a realm-wide set and
nothing had said so.** `aud` and `resource_access` name every admin container the
subject holds roles on, and the bootstrapped administrator holds `create-realm`,
so every realm any fixture creates adds a key to this body. The golden was clean
only because every realm-creating fixture in the catalogue lived in `adminCases`
and therefore ran after it in catalogue order. Ordering cannot carry that, which
is what `PristineRealm`'s own doc comment says.

Two further things about it are worth having written down:

- **`TestNoGoldenHoldsAnObjectItDidNotCreate` did not see it.** The realm arrives
  in this body as the derived client name `gloak-probe-second-realm` - a key of
  `resource_access` and an element of `aud` - and that guard looks for
  `"realm":"<name>"`. `TestConformance` caught it one step later, which is the
  step the ratchet exists to precede.
- The case now carries `PristineRealm: true`, and re-recording it with the flag
  reproduced the committed bytes **byte for byte**. So `make record` on this
  branch now adds four goldens and moves none.

### 1.6 Three mutations survive, measured rather than inferred

With `master` hard-coded into `registrationURI`, the device grant's
`verification_uri` and `/auth`'s error-redirect `iss` - all three at once -
`go test ./internal/conformance ./internal/oidc ./internal/httpx` is green.
Sites 15, 17 and 19 are unpinned by anything in this repository, and that is a
measurement rather than a reading of the table above.

## 2. Entries for AGENTS.md

Written in that file's voice, for whoever folds this in. The first belongs under
"Things that look like bugs and are not"; the second is about the harness and
belongs beside the mask and pollution bullets.

> - **A theme page names the realm three times and only one of them is the
>   restart URL.** The `<title>` is `Sign in to <displayName>` and the header
>   brand is `<displayNameHtml>`, and a realm created through
>   `POST /admin/realms` has neither - so Keycloak falls back to the realm
>   **name** in both, and the `<div class="kc-logo-text"><span>` wrapper the
>   `displayNameHtml` carries disappears with it rather than wrapping the name.
>   Master's two values are `Keycloak` and that wrapper, which is why serving
>   them as constants looks right: it is right on the one realm every conformance
>   case addressed. Measured 2026-09-01 on the 400 page for an unknown
>   `client_id`, master against a created realm, byte for byte.
>
> - **The catalogue could not tell a realm-derived value from the literal
>   `master`, and the fix was cases rather than machinery.** Sixty goldens carry
>   the realm name of their request in the response and fifty-eight of them
>   address master, so a handler answering with the literal compared equal to one
>   deriving it - F142, found by a mutation on the theme page's restart URL that
>   passed all 352 served cases. What F142 costed as "a second realm in the
>   harness" was **already built**: `realmFixture` has created realms through the
>   API since P4 and sixty-six cases address one. The blind spot was that all
>   sixty-six were on the Admin API. `Case.SecondRealm` marks a case that
>   re-measures a covered behaviour against another realm; it is kept out of the
>   parity denominator, because a protocol chapter counts cases and counting a
>   re-measurement would report diligence as coverage. **Twenty derivation sites
>   exist and eighteen were master-only; four are pinned now and three of the
>   rest are measured survivors** - `registrationURI`, the device grant's
>   `verification_uri` and `/auth`'s error-redirect `iss` all take a hard-coded
>   `master` with the whole tree green.
>
> - **A refresh token's introspection body enumerates a realm-wide set.** `aud`
>   and `resource_access` name every admin container the subject holds roles on,
>   and the bootstrapped administrator holds `create-realm`, so **every realm any
>   fixture creates adds a key**. `oidc/introspection/active-refresh-token` was
>   clean for a month only because every realm-creating fixture happened to live
>   in `adminCases` and run after it. It carries `PristineRealm` now. The
>   pollution guard did not see it: the realm arrives as the derived client name
>   `<realm>-realm`, a key of `resource_access` and an element of `aud`, where
>   the guard looks for `"realm":"<name>"`.

## 3. Follow-up dispositions

### F142 - closed for four sites, open as a class, and its premise corrected

**The entry's opening sentence should be corrected before anything else**: "every
case in `internal/conformance` is recorded and replayed against `master`" has
been false since P4, and it is the reason the entry costed neither of its two
routes. The counts in §1.1 are what it should say instead.

**Closed here:** sites 11, 12 and 18 - the discovery document, the realm info
body and the bearer challenge - each by an `Implemented` case whose golden
addresses `gloak-probe-second`. Each was mutation-tested: hard-coding `master`
fails the second-realm case and leaves its master sibling and the package's own
tests green.

**Recorded here:** site 13's page, as
`oidc/authorization/second-realm-error-page`, which is `Recorded` rather than
`Implemented` because of §1.4. When somebody makes the theme follow the realm's
display name, that case will start matching its golden and `TestConformance` will
say so and demand promotion. That is the alarm working, not a failure.

**Still open, and this is what the entry should stay open for:** sites 1-7, 10,
14, 15, 17 and 19. Three of them are measured survivors (§1.6). The entry's
general form is right and should be kept: any value a handler derives from the
realm name is unpinned unless a second-realm case or a package test says
otherwise. What it should no longer say is that the harness cannot express one.

### F53 - followed, not overturned

F53 decided `PristineRealm` "stays a declaration and the sweep that checks it is
a person reading the catalogue", after a derived check was tried and declined on
two measurements.

`Case.SecondRealm` follows that decision. It cannot be derived from the path
either: `oidc/discovery/unknown-realm` addresses `nosuchrealm` and *is* a
distinct documented behaviour that belongs in the denominator, while a
second-realm re-measurement is the same behaviour twice and does not. A rule
reading "the path does not say master" cannot tell those apart.

Where it goes further is that the declaration is falsifiable, and both halves are
checked: `TestSecondRealmCasesAddressARealmTheyCreate` requires the realm to be
one the case's **own** fixture creates - the verifier runs that fixture and
nothing else - and `TestSecondRealmGoldenPinsItsRealmName` requires the golden's
response to carry that name and never `master`. A second-realm case whose golden
pins nothing realm-derived is the harness equivalent of a mask that changes
nothing, and it fails.

**F53 also gains a fourth instance and should record it.** Its own text says "the
sweep was complete and a one-off sweep cannot hold. Every cut that adds a fixture
writing to a realm-wide set can add another, and one did immediately." Another
has: `oidc/introspection/active-refresh-token`, §1.5. It is the first one on the
**protocol** side, and the first the ratchet could not see, because the object
reaches the body under a derived name rather than under its creation key.

Widening the guard to also match a created realm's `<realm>-realm` admin
container was considered and deliberately not done here: it is a change to a
guard every golden in the repository passes, and it belongs in a cut that can
afford to read whatever it turns up rather than in one closing F142.

### F72 - untouched

No parked golden was touched. `oidc/authorization/prompt-create` is still the
only entry in `parkedGoldens` and `TestNoPendingGoldenIsCompared`'s "parked == 0"
guard is still one promotion away from firing.

## 4. Parity

**352 of 535 before and after. No case moved.**

The four new cases are excluded from the meter by `countsTowardsParity`, because
a protocol chapter's denominator is the catalogue's own case count and a
second-realm case is the same behaviour as its master sibling. Without the
exclusion the total would read 355 of 539, and three of those three would be
Gloak reading as serving more behaviours than it does.

`TestSecondRealmCasesAreOutsideTheParityDenominator` reads the meter's own report
rather than the predicate, so dropping the exclusion from the tally fails rather
than quietly inflating the number - confirmed by mutation.

## 5. What the next cut should do, and where

### 5.1 Package tests this cut may not write

Named per package and per claim, as asked. None of these is speculative: each is
a site from §1.2 with no second-realm coverage.

**`internal/httpx`** - one test, two claims:

- `WriteThemeErrorPage` renders the realm's `displayName` in the `<title>` and
  its `displayNameHtml` in the header brand, falling back to the realm **name**
  when the realm has neither, and dropping the `kc-logo-text` wrapper with it.
  `ThemeChrome` has no field for either today, so this is an interface change and
  not only a test. §1.4 has the measured bytes.
- `TestThemeErrorPageCarriesTheChrome`'s doc comment says "Every conformance case
  in this repository runs against master". That was already false when it was
  written and is now false twice over. It is one sentence to correct, and it is
  the sentence F142 was written from.

**`internal/oidc`** - four claims, none of which any test in that package can see
today, because every test there builds a handler with `bootstrap.EnsureMaster`
and no second realm:

- `registrationURI` names the realm of the request, in the `Location` of a
  registration create and in `registration_client_uri` on all four registration
  reads and writes. **Measured survivor.**
- the device authorization response's `verification_uri` and
  `verification_uri_complete` name the realm of the request. **Measured
  survivor.**
- `/auth`'s error redirect carries `iss=<issuer>/realms/<the request's realm>`.
  **Measured survivor.**
- the device verification page's form `action` is `/realms/<realm>/device`, and
  is relative - AGENTS.md already records that it is not the arrival path, which
  is a second thing about it that only a second realm can distinguish.

**`internal/admin`** - one test would cover seven sites at once.
`crossrealm_test.go` already builds a second realm through
`bootstrap.CreateRealm`, so the claim is one table: a create's `Location` names
the realm the request addressed, over `POST /clients`, `/users`, `/groups`,
`/groups/{id}/children`, `/roles`, `/clients/{uuid}/roles` and
`.../identity-provider/instances`. Site 10 - a client's `access` block, decided
by `isAdminContainerName` - belongs in the same file and is a separate claim,
because on a realm that is not master the admin container is `realm-management`
rather than `<realm>-realm`.

### 5.2 Second-realm cases the harness can now take

Each is a fixture line and a case. The two that need a client inside the second
realm are the reason they are not in this cut: `browserRedirectURI`'s fixture
family is written against master and generalising it is a cut of its own.

- `oidc/certs/second-realm` - pins nothing realm-derived on its own (every value
  is masked) and should **not** be added for its own sake. Listed so the next
  person does not add it thinking it does.
- `oidc/device/second-realm-verification-page` - site 14, needs no client.
- `oidc/device/second-realm-authorization-request` - site 15, needs a client in
  the second realm.
- `oidc/registration/second-realm-create` - site 17, needs an initial access
  token in the second realm.
- `oidc/authorization/second-realm-error-redirect` - site 19, needs a client with
  a registered redirect URI in the second realm.

## 6. What surprised me

The finding I did not expect was that F142's own premise was wrong, and that the
route it costed as expensive had been sitting in `fixture.go` since P4 with
sixty-six cases using it. The count in §1.1 was the whole decision: an estimate
would have said "the catalogue is master-only" because that is what the entry
says, and the entry says it because nobody had counted.

The second was §1.4. The brief warned that a second realm answers differently for
reasons that have nothing to do with the value being chased, and that telling
those apart is the work - and that is exactly what happened, except that the
unrelated difference turned out to be a divergence worth more than the thing I
went looking for.
