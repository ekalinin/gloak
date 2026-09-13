# The mapper-types golden, and the third party inside it

F230. `admin/identity-providers/mapper-types-unsupported` claimed a 500 and moved
on one of four `make record` runs. The previous cut took ten direct draws across
three containers, one of them cold, got a 200 every time, and concluded **the
golden is wrong**.

**The golden was right, and so were the ten draws.** They were measuring
different things, and neither of them was measuring Keycloak. `GET
.../mapper-types` instantiates the identity provider, and
`linkedin-openid-connect`'s factory fetches a well-known document **from
`www.linkedin.com`** while it does so. The status is therefore whatever the
recording host's egress to a third party happens to be: a 500 where the fetch
fails, a 200 with six mapper types where it succeeds. Nothing in the catalogue,
the fixtures or the `internalId` space was involved.

So of the four hypotheses the brief put, it is the fourth. The first is the
closest of the three named - the 500 is real and reproducible and the ten draws
missed the condition - but the condition is not "something in the fixture
ordering"; it is a TCP handshake to a host neither this repository nor Keycloak
controls.

Everything below was measured on **2026-09-13** against
`quay.io/keycloak/keycloak:26.7.1`, from `main` at `9ad6fd6`.

## 1. The measurement that decided it

### 1.1 The first draw already refuted the previous cut

Container A, created with `docker run` thirty seconds earlier, bootstrap
completed, nothing else on it. The fixture's own body, then the case's own
request:

```
POST   /admin/realms/master/identity-provider/instances
       {"alias":"gloak-probe-mt-broker-li",
        "internalId":"1de07000-0000-4000-8000-000000000022",
        "providerId":"linkedin-openid-connect"}        -> 201
GET    .../instances/gloak-probe-mt-broker-li/mapper-types -> 500   (x3)
```

Three draws, one cold container, the request the first thing to touch the
provider - which is the previous cut's own description of the draw it trusted
most, and it answers the opposite way. At that point the honest reading is not
"the golden is right after all"; it is that **the count on either side is worth
nothing** and something decides this that nobody has named.

### 1.2 The server log names it in one line

```
RuntimeException: Error calling the OIDC LinkedIn well-known address.
  at LinkedInOIDCIdentityProviderFactory.getWellKnownMetadata(…:107)
  at LinkedInOIDCIdentityProviderFactory.create(…:73)
  at IdentityProviderResource.createIdentityProviderInstance(…:251)
  at IdentityProviderResource.getMapperTypes(…:269)
Caused by: javax.net.ssl.SSLHandshakeException: Remote host terminated the handshake
Caused by: java.io.EOFException: SSL peer shut down incorrectly
```

`getMapperTypes` **constructs the provider** before it can answer, so whatever
the factory does on construction decides the status. LinkedIn's fetches
`https://www.linkedin.com/oauth/.well-known/openid-configuration`.

This machine cannot complete that handshake from inside Docker and can complete
it from the host, which is the whole of the disagreement:

```
macOS host, curl                          200
macOS host, openssl s_client              handshake ok, verify 0
colima VM, curl                           timeout after 20s
container, busybox wget                   handshake terminated
container, https://example.com            OK
container, https://quay.io                OK
```

Both sides resolve `www.linkedin.com` to the same two Cloudflare addresses, so it
is not DNS, and general TLS egress from a container works - it is this one host.
**That is an accident of this machine and it is the point.** The golden records
whatever the recording host's egress was on the day, and a golden in this
repository is read as a statement about Keycloak.

### 1.3 The mechanism, measured on both sides without leaving the container

A stack trace is an argument, not a measurement, and the 200 half still had to be
drawn. LinkedIn's URL is hard-coded, so it cannot be pointed anywhere. **`openshift-v4`'s
can**: it reads its metadata URL out of `baseUrl`. So the same provider, the same
endpoint and the same container answer both ways, with the fetch as the only
difference:

```
openshift-v4, no config                      500   Target host is not specified
openshift-v4, baseUrl = the container itself 200   4068 bytes, six mapper types
openshift-v4, baseUrl = 127.0.0.1:9          500
```

The reachable `baseUrl` is this Keycloak's own
`/realms/master/.well-known/oauth-authorization-server`, which carries the
`authorization_endpoint` and `token_endpoint` the provider needs. Nothing left
the container.

So the rule is: **the status of this route is decided by whether the provider's
factory can complete its metadata fetch**, and the body is a 500 on any failure.
Six mapper types is the same number the previous cut saw for
`linkedin-openid-connect`, which is the last corroboration needed - its ten 200s
were ten successful fetches, not ten measurements of Keycloak.

### 1.4 Why one of the two providers is stable and the other is not

```
linkedin-openid-connect   URL hard-coded to www.linkedin.com   needs egress
openshift-v4              URL from baseUrl, absent on a bare create   opens no socket
```

`openshift-v4`'s failure is Apache HttpClient's route planner refusing a request
with no target: `ProtocolException: Target host is not specified`, thrown before
a socket exists. That is why it answered the 500 on every draw the previous cut
took and on every draw taken here - **it cannot be moved by the network, because
it never reaches it.**

### 1.5 The 500 is a property of the instance, not of the provider id

This is the part that outlives F230. `openshift-v4` with a `baseUrl` that
resolves answers **200 with six mapper types**, one of which is
`openshift-v4-user-attribute-mapper`:

```
hardcoded-user-session-attribute-idp-mapper
oidc-hardcoded-role-idp-mapper
openshift-v4-user-attribute-mapper
oidc-hardcoded-group-idp-mapper
hardcoded-attribute-idp-mapper
oidc-username-idp-mapper
```

Keycloak therefore **has** a mapper set for `openshift-v4`; it simply cannot
build the provider that would be asked for it. AGENTS.md says these two providers
"are exactly the two the catalogue has no mapper set for", and
`internal/model/providercatalogue.go` repeats it as the reason one branch is
enough. The branch really is enough for Gloak, and the **reason** is wrong: the
two ids are the two whose construction performs I/O. Section 7 is how that
should be folded.

Gloak answers the 500 for both ids whatever the config says, so a caller who
configures a `baseUrl` gets a 500 from Gloak and a 200 from Keycloak. That is a
real divergence, it is newly measured, and nothing in the tree asserts either
way: **F232**.

## 2. Containers

**Two containers, both genuinely fresh, plus the recorder's own.**

| container | how | what it answered |
|---|---|---|
| A | `docker run`, cold, bootstrap 30s before the first request | linkedin 500 x3, openshift bare 500 x3, openshift with `baseUrl` 200 x2, openshift dead `baseUrl` 500, oidc 200/10 types, the collision probes |
| B | `docker run`, cold, independent | linkedin 500, openshift bare 500 |
| recorder | `make record`, its own shared container plus one per `PristineRealm` case | section 4 |

Both A and B were created by `docker run`, not restarted - the distinction
AGENTS.md asks for. The previous cut's "three containers, including a cold one"
cannot be checked from here, and after section 1 it does not need to be: on a
host whose egress works, all ten of its draws are the expected answer.

`oidc` answering 200 with **8255** bytes on container A is the cross-check that
the probe was measuring the same thing the committed goldens hold - that is the
byte count P9's handover records for `oidc`'s mapper types.

## 3. The `internalId` collision sweep

The brief asked how far it reaches. **It reaches no case today, and what holds it
off is a flag set on an unrelated case for an unrelated reason.**

### 3.1 What a collision actually does

Measured, because the consequence decides whether this matters. On container A,
with `…020` already held by `gloak-probe-mt-broker-oidc`:

```
POST .../instances {"alias":"gloak-probe-idps-strand","internalId":"…020",…}
  -> 409 {"errorMessage":"Identity Provider gloak-probe-idps-strand already exists"}
GET  .../instances/gloak-probe-idps-strand   -> 404 {"error":"HTTP 404 Not Found"}
```

Three things, each worse than the last. The check is on the **internalId**; the
message names the **alias that does not exist**; and `idempotentCreate` accepts
409, so the fixture step **passes**. A case whose fixture silently created
nothing addresses a 404.

The recorder's order was measured too, since the alias-clearing `PUT` might have
freed the id. It does not - create, strand, then the colliding create is still a
409 and the second alias still 404s.

### 3.2 Every fixture-minted provider id in the tree

`1de07000-0000-4000-8000-0000000000XX`, from the four helpers and the literals.
**This is the tree as found**, before section 4.2 moved three of them; the sweep
was done on `main` at `9ad6fd6`:

| id | minted by | alias |
|---|---|---|
| `…001` | `idp-full` | `gloak-probe-idp-full` |
| `…002` | `idp-minimal` **and** `idp-taken` | `gloak-probe-idp-min` on both |
| `…010` `…011` `…012` | `idp-listing` | `gloak-probe-idp-zzz/mmm/aaa` |
| `…020` `…021` | `idp-stranded` | `gloak-probe-idps-strand/zzz` |
| `…020` `…021` `…022` | `idp-mt-oidc` / `idp-mt-saml` / `idp-mt-linkedin` | `gloak-probe-mt-broker-oidc/saml/li` |
| `…030`-`…037` | the eight `idp-mapper-*` | `gloak-probe-map-broker-*` |
| `…0c1`-`…0c4` | the four `org-broker*` | `gloak-probe-org-idp`, one per realm |

Two further creates name no `internalId` at all - `identityProviderStep`, used by
two fixtures, and the account chapter's pair in `fixture_account.go` - so they
take a server-minted UUID and cannot collide with this space. The mapper ids
`…041`-`…048` and the authz groups are separate id spaces on the same prefix.

**Three duplicates, and exactly one reaches a case - as a harmless one:**

- **`…002`, `idp-minimal` and `idp-taken`.** One id and **one alias**: the bodies
  are the same constant. Whichever runs second gets the 409 and the resource the
  case wants is there either way. Harmless by construction, and it is the reason
  the ratchet in section 5 keys on the alias rather than on the id alone.
- **`…020`, `idp-stranded` and `idp-mt-oidc`.** Two different aliases.
- **`…021`, `idp-stranded` and `idp-mt-saml`.** Two different aliases.

The last two are live collisions and they have never fired, because
`admin/identity-providers/update-strands-the-row` is **`PristineRealm: true`** and
lands on a container of its own. That flag is set because the case enumerates the
realm - F40's reason, nothing to do with ids. Clear it, or add one non-pristine
case naming `idp-stranded`, and `mapper-types` and `mapper-types-saml` become
404s with no fixture reporting a failure.

So the answer to "how many cases does it reach" is **zero, held at zero by
accident**. That is a result, and it is the one that needed the sweep: the
mechanism the previous cut named is real, it is not F230's cause, and it was one
flag away from being a worse bug than F230.

### 3.3 It was never F230's mechanism anyway

Two independent reasons, either sufficient: `idp-mt-linkedin` mints `…022`, which
nothing else in the tree mints; and a collision produces a **404**, not the 500
the golden holds. Hypothesis 2 is refuted on measurement rather than on argument.

## 4. What changed

### 4.1 The case asks the provider whose 500 needs no network

`admin/identity-providers/mapper-types-unsupported` now names `openshift-v4`.
Same status, same body, same headers, same case id, same subject - "an instance
whose mapper types cannot be listed" - and no third party in the loop. The
fixture `idp-mt-linkedin` becomes `idp-mt-openshift`, alias
`gloak-probe-mt-broker-os`; it had one consumer.

The case's comment carries the measurement: that the route instantiates the
provider, that LinkedIn's 500 is the host's egress and `openshift-v4`'s is
thrown before a socket, and that the status follows the instance rather than the
provider id.

**`linkedin-openid-connect` is not replaced by a second case.** Its answer cannot
be recorded reproducibly anywhere, which is F113's rule arriving from a new
direction: that rule is about a body carrying per-request values, and this is a
**status** carrying the recording host's network. F233.

### 4.2 The two colliding ids move

`idp-mt-oidc` and `idp-mt-saml` go to `…050` and `…051`, and
`idp-mt-openshift` to `…052`. The stranded fixture keeps `…020`/`…021` because
**its ids are the ones a golden asserts** - `update-strands-the-row` holds both -
so moving that side would move committed bytes for a fixture hygiene fix. `…05X`
is clear of the strand loop's growth path as well as its two current values: that
loop is `'0'+i`, so a third entry would take `…022`.

### 4.3 The ratchet

`TestNoTwoFixturesMintOneIdentityProviderID` walks `Fixtures`, picks out every
`POST` whose path ends `/identity-provider/instances`, and fails when one
`internalId` is minted for more than one alias. It reported both live collisions
when it was written and passes now. The `…002` pair passes it, because one id for
one alias is the case that cannot hurt.

Keyed on the alias rather than the id because a test that reported `idp-minimal`
and `idp-taken` would be a test people learn to ignore.

## 5. The mutation pass

Eight mutations, **one survivor, fixed and now killed**. The tree was committed
and clean before each one, the revert is on a `trap … EXIT` rather than the
happy path so it runs through a panic or a timeout kill, the diff is checked
non-empty before the tests run, and `git status --porcelain` is checked after
every revert. `internal/conformance` is the only package this cut touches and it
runs whole; the `-run` filter appears only where the claim is that a **named**
test fails.

| | mutation | outcome |
|---|---|---|
| M1 | `idp-mt-oidc`'s internalId back to `…020` | killed, `TestNoTwoFixturesMintOneIdentityProviderID` |
| M2 | `idp-mt-saml`'s internalId back to `…021` | killed, same test |
| M3 | the fixture's alias is not the one the case asks | killed, `TestConformance/admin/identity-providers/mapper-types-unsupported` |
| M4 | the fixture's `providerId` back to `linkedin-openid-connect` | **survived the whole package** |
| M5 | `jsonStringField` finds nothing | killed, the vacuity guard |
| M6 | M4 again, against the ratchet M4 earned | killed, `TestNoMapperTypesCaseAsksAProviderThatFetchesOnConstruction` |
| M7 | the case's own path back to the old alias | killed, `TestConformance/…/mapper-types-unsupported` |
| M8 | the sweep's path suffix gains a trailing slash | killed, the vacuity guard |

None of the eight is a text-only edit, which is the F208 trap: M1, M2 and M8
change bytes that decide a match, M3 and M7 change a route, M4 and M6 change
which provider is built, and M5 inverts a condition.

M5 and M8 are the pair AGENTS.md distinguishes, and they are on the **guard**
rather than on the rule: both make the sweep match nothing, which is "the
function fails" and not "the function is wrong consistently". They are worth
running exactly because the failure they model is silent - a sweep matching
nothing passes. The rule itself is tested by M1, M2, M3, M4, M6 and M7.

### 5.1 The survivor, and what an implementation satisfying it looks like

M4 changed one literal: `idp-mt-openshift`'s body from
`"providerId":"openshift-v4"` to `"providerId":"linkedin-openid-connect"`,
leaving the alias and the internalId alone. The whole package passed in 320
seconds.

It passes because **Gloak answers the 500 for both ids whatever the config
says** - one branch, the catalogue's missing entry, section 1.5 - so the fixture
builds a LinkedIn broker under the openshift alias, the verifier asks for it, and
the bytes compare equal.

An implementation satisfying the mutated tree is **exactly the tree before this
cut**, with the fixture renamed. Every symptom returns: `make record` on a
connected host rewrites the golden to a 200, a reader sees a golden move for no
reason in the diff, and the next cut re-derives section 1 from scratch. The
suite could not tell the difference, and neither could a reviewer reading the
diff, because the only thing that separates the two providers is a measurement
that lived in a handover.

So the ratchet carries the measurement rather than the literal:
`identityProvidersFetchingOnConstruction` is the set of provider ids whose
factory fetches while the provider is built, and
`TestNoMapperTypesCaseAsksAProviderThatFetchesOnConstruction` fails when a
`mapper-types` case's fixture names one. M6 is the same mutation against it, and
it is killed.

This is F208's disposition applied as the SAML cut wrote it: **before filing a
null edit under F208, check whether its nullity is an invariant nobody wrote
down.** It was, the ratchet is cheap, and it is the only thing in the tree that
would stop this happening a third time.

## 6. Parity

```
before   598 of 644 enumerated behaviours served; 2 chapters not enumerated
after    598 of 644 enumerated behaviours served; 2 chapters not enumerated
```

**The meter does not move, and it should not.** The case stays `Implemented`,
because Gloak serves those bytes and a live Keycloak 26.7.1 answers them - the
change is which provider can be relied on to produce them. Nothing was demoted to
`Recorded` and nothing needed to be.

The re-record is the evidence rather than the argument. A full `make record`,
803 seconds, exit 0, moved **one line in one golden**:

```
-# GET …/identity-provider/instances/gloak-probe-mt-broker-li/mapper-types
+# GET …/identity-provider/instances/gloak-probe-mt-broker-os/mapper-types
```

The status line, the `Content-Length` mask, `Content-Type`, the four security
headers, `X-Frame-Options` and the body are byte-identical. So the contract is
unchanged and is now reproducible on a host with no route to LinkedIn - which is
the only thing this cut set out to do to it.

That run is also the third and fourth independent measurement of the 500: the
recorder builds its own containers, one shared and one per asserted
`PristineRealm` case, and forty such cases are declared.

## 7. What belongs in AGENTS.md

Phrased as it would be folded, into the identity-provider bullets beside the
per-provider catalogue.

- **`GET .../identity-provider/instances/{alias}/mapper-types` instantiates the
  provider, so a factory that does I/O on construction decides the status.** Two
  of the seventeen answer a 500 and **the two 500s do not have one cause**.
  `openshift-v4` reads its metadata URL out of `baseUrl`, which a bare create
  does not carry, and Apache's route planner refuses with `Target host is not
  specified` before a socket exists - reproducible on an air-gapped host, on
  every draw anyone has taken. `linkedin-openid-connect`'s URL is **hard-coded to
  `https://www.linkedin.com/oauth/.well-known/openid-configuration`**, so its
  answer is the recording host's egress to a third party: 500 where the fetch
  fails, measured three times on a cold container and once on a second, and 200
  with six mapper types where it succeeds, which is what ten draws on a
  better-connected host saw. `admin/identity-providers/mapper-types-unsupported`
  asks `openshift-v4` for that reason and must not be pointed back.
- **The 500 is a property of the instance, not of the provider id.** The same
  `openshift-v4` alias given a `baseUrl` that resolves answers 200 with six
  mapper types, one of them `openshift-v4-user-attribute-mapper`. So the sentence
  "they are exactly the two the catalogue has no mapper set for" is true of
  **Gloak's** catalogue and false of Keycloak's, and the claim in
  `internal/model/providercatalogue.go` that the two conditions are one set is a
  correct statement about the code resting on a wrong statement about Keycloak.
  Gloak answers the 500 unconditionally: F232.
- **An identity provider's `internalId` is global, and a duplicate create is a
  409 naming the alias that does not exist.** `idempotentCreate` accepts it, so
  the fixture passes and the case addressing the losing alias gets a 404. The
  alias-clearing `PUT` does not free the id.
  `TestNoTwoFixturesMintOneIdentityProviderID` is the ratchet, and it is keyed on
  one id for one alias rather than on uniqueness, because `idp-minimal` and
  `idp-taken` share both on purpose.
- **A golden whose value depends on reaching a host on the public internet is
  not a contract**, however many times it has been drawn. This is F113's rule on
  a new axis: that one is about a body carrying per-request values, this one is
  about a **status** carrying the recording host's network. Both are cases
  `make record` cannot settle.
- **F179's rule needs its sample-size half removed.** "A recording that
  disagrees with a golden is not evidence that the golden was wrong" is right,
  and "telling them apart needs a third draw" is not - ten draws on one side and
  four on the other did not tell them apart, and reading one stack trace did.
  **A disagreement is settled by a mechanism or it is not settled.**

## 8. Follow-ups

### F232: Gloak's mapper-types 500 is unconditional where Keycloak's is not

Measured in section 1.5. Keycloak answers `openshift-v4` with 200 and six mapper
types once `baseUrl` resolves, and with a 500 otherwise; Gloak answers 500 for
`openshift-v4` and `linkedin-openid-connect` whatever the config holds. Nothing
in the tree asserts either direction, and the six types are recorded in section
1.5 rather than in a golden.

Not fixed here, for two reasons. It needs the six type definitions in full, not
their ids, and the serving path would have to make a decision Gloak has no
machinery for - **Keycloak's answer depends on an outbound fetch**, which Gloak
must not make. The honest shape is probably that Gloak serves the 500 and the
divergence is recorded as deliberate, which is a decision rather than a patch.
What to measure first: whether `linkedin-openid-connect` offers the same six, on
a host that can reach LinkedIn.

### F233: a case whose status depends on the public internet has no disposition

`linkedin-openid-connect`'s `mapper-types` cannot be recorded reproducibly, and
the catalogue's vocabulary has no word for that. `Pending` is for a body nothing
can reproduce, and the reason is F113. This is a status nothing can reproduce,
and the cause is outside the machine.

It matters beyond this one cell: **nothing stops the next such case**. A
`Pending` case is declared in `parkedGoldens` with a reason; there is no
equivalent declaration for "this value is a function of the recording host", and
the only thing that caught this one was a golden moving between runs and two cuts
reading it opposite ways.

### F234: the fixture id spaces share one prefix and nothing enumerates them

`1de07000-0000-4000-8000-0000000000XX` carries identity providers, identity
provider mappers, authz policies, resources and scopes, and the organization
brokers, in overlapping suffix ranges kept apart by convention and comments. The
new ratchet covers one of those families. The others have the same shape -
global id spaces, `idempotentCreate` over the top - and the sweep in section 3
was hand-done because nothing enumerates them.

What to do first is the cheap half: generalise
`TestNoTwoFixturesMintOneIdentityProviderID` over the families whose creates
carry a literal id, and report how many duplicates exist before deciding whether
any of them can fire.

### F235: `make record` has no way to report that a golden moved for an external reason

F230 took three cuts: one recorded the flap and reverted it, one drew ten times
and concluded the golden was wrong, and this one found the cause. Every one of
them read the same diff. F166 records the same shape for a different cause - "a
recurring hand-revert is a defect report that nobody has anywhere to file" - and
the remedy it found was per-case (`PristineRealm`).

The general question is whether `make record` can say **which** goldens moved
against what they held, in a form that survives the revert, so the second cut
starts from the first's diff instead of re-deriving it. Nothing is proposed here;
the observation is that two cuts spent a session each on one cell and the
information that would have saved the second was in the first's working tree.
