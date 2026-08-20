# Gloak: design of the documentation conformance harness

Date: 2026-08-20
Status: accepted

## 1. What this is

A regression suite whose case list is derived from the Keycloak documentation and
whose expected values are recorded from a live Keycloak 26.7.1.

The request came as "regression tests that fully replicate the documentation". Taken
literally that conflicts with the rule this project is built on, so the design splits
the two sources rather than choosing between them:

- **Documentation supplies the inventory.** Which endpoints exist, which grants they
  accept, which parameters they read, which error conditions are named. This is what
  the docs are reliable for.
- **A running Keycloak supplies the values.** Status codes, header spellings, JSON
  key order, error strings, byte-for-byte bodies. AGENTS.md: *observable values are
  measured, never remembered*, and *do not infer them from the documentation*.

Nothing in the harness asserts a value that came out of a document.

## 2. Scope

### 2.1 In scope for the project as a whole

The client-observable contract: the OIDC and OAuth2 protocol endpoints, the Admin
REST API, and the parts of the Server Administration Guide that are reachable
through those APIs.

### 2.2 Out of scope, permanently

Configuration, All configuration options, Operator, High Availability, Upgrading, and
the Server Developer Guide. README states that configuration is deliberately not part
of the contract - Gloak uses `GLOAK_*` rather than `KC_*` - and the Operator and HA
guides describe the Java distribution, which does not exist here.

Adapters and client libraries (JavaScript, Node.js, mod_auth_openidc, mod_auth_mellon,
admin client, authorization client, policy enforcer) are documented but are clients of
the contract, not the contract itself.

### 2.3 Decomposition

The client-observable contract is too large for a single spec: the Admin REST API
alone is 273 paths and 413 operations. It is split into three slices, each with its
own spec and plan:

1. **The harness** - this document. The `Case` type, the catalogue, the recorder, the
   verifier, the coverage report, and the OIDC inventory.
2. **The OIDC catalogue** - filling in the pending OIDC cases as the protocol lands.
3. **The Admin REST API catalogue** - generated from the 26.7.1 OpenAPI document
   rather than written by hand.

## 3. Documentation sources and their version

The documentation index currently serves **26.7.2**, while the project pins
**26.7.1**. Version-pinned URLs were checked and behave differently per guide:

| Source | Version-pinned URL | Status |
|---|---|---|
| Server Administration | `https://www.keycloak.org/docs/26.7.1/server_admin/index.html` | 200 |
| Admin REST API (OpenAPI) | `https://www.keycloak.org/docs-api/26.7.1/rest-api/openapi.json` | 200, 273 paths, 413 operations |
| Securing Applications | `https://www.keycloak.org/docs/26.7.1/securing_apps/` | **404** |

The Securing Applications guide moved to `/securing-apps/*` and exists only as
latest. Its pages therefore cannot be cited at 26.7.1.

This is tolerable because of the split in section 1. A drifting document can only
move the *inventory*, never a value, and inventory changes are reviewed by a human
when the catalogue is edited. Each case records the URL and the date it was read, so
drift is visible rather than silent.

## 4. Package layout

A new test-only package. Production code must not import it.

```
internal/conformance/
  case.go                  # Case, Status, Doc, Request
  catalog.go               # var Catalog []Case, assembled from the per-chapter files
  catalog_oidc.go          # the inventory from /securing-apps/oidc-layers
  normalize.go             # in-place byte rewriting of volatile values
  golden.go                # reading and writing testdata/golden/<id>.http
  server.go                # building the Gloak handler under test
  conformance_test.go      # the offline verifier
  coverage_test.go         # the coverage report
  normalize_test.go        # the harness's own tests
  record_test.go           # //go:build docker - the recorder
  testdata/golden/*.http
```

AGENTS.md's boundary table gains a row:

| Package | Owns | Must not |
|---|---|---|
| `internal/conformance` | the documentation-derived catalogue and golden comparison | be imported by production code, or know about SQL or handler internals; it sees only an `http.Handler` |

## 5. The `Case` type

```go
type Status int

const (
	Implemented Status = iota // Gloak serves this today
	Pending                   // documented, not implemented yet
)

type Doc struct {
	URL       string // the page the behaviour was read from
	Section   string // the heading within it
	Retrieved string // YYYY-MM-DD the page was read
}

type Request struct {
	Method  string
	Path    string // literal, including the realm name
	Query   map[string]string
	Headers map[string]string
	Form    map[string]string // application/x-www-form-urlencoded
	Body    []byte            // used when Form is empty
}

type Case struct {
	ID      string // stable slug, also the golden filename
	Doc     Doc
	Status  Status
	Reason  string // why it is Pending; required when Status is Pending
	Fixture string // named setup applied before the request

	Request       Request
	AssertHeaders []string // response headers compared exactly
	Volatile      []string // JSON paths whose values are replaced before comparison
}
```

The status line is always compared; `AssertHeaders` governs headers only.

`Volatile` paths are slash-separated from the document root, with array elements
addressed by index and `*` matching every element: `access_token`,
`keys/*/x5c`, `token_endpoint_auth_methods_supported/0`. This is RFC 6901 syntax
restricted to the subset the catalogue needs, plus the `*` wildcard.

`ID` is a path-like slug: `oidc/token/password-grant-admin-cli`. It is the golden
filename, so it must be stable; renaming one is renaming a file.

`Volatile` is what makes the approach possible at all. A token response carries a
fresh `access_token`, `expires_in` and `session_state` on every run, but the field
set and their order are exactly the contract being copied. Volatile paths have their
values replaced and their **presence and position still asserted**.

`Fixture` has one value in this slice, `bootstrap`, and one implementation: a fresh
store with `EnsureMaster` applied. It is a seam, not machinery - without it the
second slice rewrites the type - but it gains no second implementation here.

An **empty** `Fixture` means the case needs setup that does not exist yet: a
confidential client, a second user, a completed browser login. The recorder skips
those rather than failing on them, and the coverage report counts them separately as
inventory only. This is how most of the pending OIDC inventory enters the catalogue
without blocking on fixtures that belong to the next slice.

## 6. The golden file

`testdata/golden/<ID>.http`, a raw capture:

```
# GET /realms/master/.well-known/openid-configuration
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Type: application/json
Referrer-Policy: no-referrer

{"issuer":"{{issuer}}/realms/master",...}
```

Every response header is written; only those in `AssertHeaders` are compared. The
file stays a faithful slice of the wire, which matters because the recorder's diff is
reviewed by a person, while `Date` and `Content-Length` do not make the suite flicker.

**Both bodies and headers are stored already normalised** - that is, after both
passes of section 7, not verbatim. Storing raw values would make every `make record`
produce a diff on every volatile field, and a recorder whose output always churns is
a recorder whose diff nobody reads. Headers whose values change per response, `Date`
and `Content-Length`, keep their names and get `{{volatile}}` for a value, so a header
disappearing is still visible.

Everything not normalised is verbatim, including whitespace and the absence of a
trailing newline. The existing capture in
`internal/oidc/testdata/discovery-26.7.1.json` confirms what that means in practice:
Keycloak emits compact JSON on one line with no trailing newline.

## 7. Comparison

Two passes, applied identically to the golden body and to Gloak's response, then a
byte-for-byte comparison of the results.

**Pass 1, issuer.** Every absolute URL in every body carries the base URL of the
server that produced it: the reference container answers on `http://localhost:18091`
per the recipe in AGENTS.md, the test server on `http://localhost:8080`. Both are
replaced with `{{issuer}}`.

The recorder applies this pass before writing the golden, so the file on disk already
holds `{{issuer}}` and re-running the pass over it at verify time is a no-op. The
verifier still runs it over both sides, because a substitution that is idempotent
everywhere is easier to reason about than one that is conditional.

**Pass 2, volatile values.** Declared paths have their values replaced with a
placeholder that carries the original JSON type, so a string becoming a number is
still caught.

### 7.1 The rewriting must not re-marshal

Normalisation edits byte ranges in place. It does not unmarshal and re-marshal.

Marshalling through `map[string]any` sorts keys alphabetically. That is the exact
failure AGENTS.md warns about, and here it would erase the single property the suite
exists to check.

The implementation walks `json.Decoder` tokens while tracking the current path. For
each value it calls `dec.Decode(&raw)` into a `json.RawMessage` and then
`dec.InputOffset()`. Because `Decode` stops on the value's final byte and `raw` holds
that value verbatim, the value occupies `[offset-len(raw), offset)`. Only that range
is spliced. Every other byte - key order, spacing, the missing trailing newline -
survives untouched, so the final comparison is honestly byte-for-byte.

## 8. The verifier

For each case in the catalogue, one subtest:

| `Status` | Golden present | Behaviour |
|---|---|---|
| `Implemented` | yes | compare; fail on any difference |
| `Implemented` | **no** | **fail**: shipped without a measured contract |
| `Pending` | yes | skip; the bytes are already the specification for the unwritten feature |
| `Pending` | no | skip; counted in the report as inventory only |

The second row is the point of the design. It turns AGENTS.md's central rule into
something the build enforces rather than something a reviewer has to remember. Two
endpoints violate it today (follow-up F3); after this slice they cannot.

The third row is why the recorder records pending cases too. Recording the token
endpoint's response before the token endpoint is written means the bytes to aim for
already exist when someone starts writing it.

The verifier runs offline against an in-process handler. It needs no Docker and no
network, so it belongs in `make test`.

## 9. The recorder

`record_test.go`, behind `//go:build docker`, run deliberately and never as part of
`make test`.

It starts `quay.io/keycloak/keycloak:26.7.1` with `start-dev` and
`KC_BOOTSTRAP_ADMIN_USERNAME=admin` / `KC_BOOTSTRAP_ADMIN_PASSWORD=admin`, matching
the observed spec, waits for `/realms/master`, runs every catalogue case against it,
and writes the goldens. testcontainers is already a dependency.

The recorder rewrites checked-in files, so its diff is reviewed by a person before it
is committed. Cases with an empty `Fixture` are skipped and counted; a case that
names a fixture the recorder cannot build is an error, not a quiet skip.

## 10. The coverage report

`coverage_test.go` always passes and prints a table: per chapter, implemented against
total, then the pending IDs with their documentation references. Exposed as
`make conformance`.

It prints rather than writing a checked-in file. A generated file in the tree drifts
from the tests that generate it, which is the failure mode this whole design is
trying to avoid.

## 11. The harness's own tests

A harness that proves nothing passes quietly, so it is tested directly:

- the normaliser preserves key order while substituting a value
- nested and array paths resolve correctly
- a type change at a volatile path is still caught
- the absence of a trailing newline survives normalisation
- **negative test**: a body with two top-level keys transposed must fail comparison

## 12. Contents of this slice

### 12.1 Implemented cases

Eight, all recorded and all green when the slice lands:

| ID | Request |
|---|---|
| `oidc/discovery/master` | `GET /realms/master/.well-known/openid-configuration` |
| `oidc/discovery/unknown-realm` | same, unknown realm |
| `oidc/certs/master` | `GET /realms/master/protocol/openid-connect/certs` |
| `oidc/certs/unknown-realm` | same, unknown realm |
| `realm/info/master` | `GET /realms/master` |
| `realm/info/unknown-realm` | same, unknown realm |
| `http/unknown-path` | `GET /nosuchpath` |
| `http/method-not-allowed` | `POST` to the discovery path |

The last two bodies are recorded in the follow-ups document as chosen rather than
measured. This slice measures them.

### 12.2 The OIDC inventory, pending

From `https://www.keycloak.org/securing-apps/oidc-layers`, which names eleven
endpoints and six grants. Grouped by endpoint:

- **authorization** - code flow, PKCE `S256` and `plain`, implicit, `response_mode`
  variants, `prompt`, and the error paths for `redirect_uri` and `client_id`
- **token** - authorization code, implicit, resource owner password credentials,
  client credentials, device code, CIBA, plus token exchange, the JWT authorization
  grant and DPoP; and the measured error shapes, including an unknown client
  returning `invalid_client` where a wrong secret returns `unauthorized_client`
- **userinfo** - `GET` and `POST`, and the bad-token case: 401, `text/plain`, empty
  body, error in `WWW-Authenticate`
- **logout** - RP-initiated with and without `id_token_hint`, back-channel,
  front-channel, `post_logout_redirect_uri` validation
- **introspection** - active access token, active refresh token, inactive token,
  unauthenticated client
- **revocation** - refresh token, access token, unknown token, wrong client
- **device authorization** - the device code request and the polling responses,
  `authorization_pending`, `slow_down`, `expired_token`, `access_denied`
- **backchannel authentication** - the `auth_req_id` request and its polling
- **dynamic client registration** - create, read, update, delete, initial access
  token, registration access token

Roughly 60 to 65 entries. The exact number is settled when the catalogue is written;
this estimate comes from the endpoint and grant lists on that page.

### 12.3 Fixes required to land green

Recording will expose the divergences follow-up F3 already predicted:

- JWKS gains `x5c`, `x5t` and `x5t#S256`, which means `internal/keys` must generate a
  self-signed certificate for the realm key. This is real work, not a string edit.
- **JWKS stops being marshalled by go-jose.** `certs` currently hands
  `jose.JSONWebKeySet` straight to `httpx.WriteJSON`, so the key order is go-jose's
  `rawJSONWebKey`: `use, kty, kid, alg, n, e, x5c, x5t, x5t#S256`. That is a
  third-party struct with a third-party order, which is the same failure AGENTS.md
  describes for `map[string]any`. The endpoint needs a Gloak-owned struct whose fields
  are declared in the order the recorded golden shows.
- realm-info field set and order.
- `Cache-Control` and CORS headers on all three shipped endpoints.
- The 404 and 405 fallback bodies.

`docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md` gains sections for
`/protocol/openid-connect/certs` and `GET /realms/{realm}`, closing F3.

### 12.4 Deliverables

1. `internal/conformance`: `case.go`, `catalog.go`, `catalog_oidc.go`,
   `normalize.go`, `golden.go`, `server.go`
2. the recorder behind `-tags docker`
3. the offline verifier and the coverage report
4. the harness's own tests, including the negative one
5. recorded goldens for the eight implemented cases
6. the fixes in 12.3
7. the two new sections in the observed spec
8. `make conformance` and `make record`; the boundary row in AGENTS.md; a README
   section on the record-and-review workflow

### 12.5 Not in this slice

The Admin REST API catalogue, SAML, Authorization Services, the adapters and client
libraries, and everything in section 2.2.

## 13. Risks

**The fixes in 12.3 may be larger than they look.** Certificate generation for the
realm key is the one to watch. If it grows past this slice it becomes its own branch,
and the affected cases stay red in the meantime rather than being marked `Pending` -
marking them would defeat section 8.

**The pending inventory can rot.** An entry nobody ever turns into a passing test is
a comment with a build cost. The coverage report is the mitigation: the count is
printed on every run, so a number that never moves is visible.

**Recording is a privileged operation.** It rewrites the expected values wholesale. A
careless `make record` followed by an unreviewed commit would pin a regression as the
new contract. The mitigation is procedural, and it belongs in README: the recorder's
diff is read before it is committed.
