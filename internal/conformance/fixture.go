package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Step is one request run before a case's own, whose response contributes
// values the case can refer to. Steps are never recorded as goldens: only the
// case's own response is. Recording them would commit a live token to the
// repository.
type Step struct {
	Request Request
	// Capture maps a variable name to a slash-separated path into the step's
	// JSON response body. "access_token" is the common one.
	Capture map[string]string
	// CaptureHeader maps a variable name to a response header. The admin API
	// answers a create with 201, an empty body and the new object's URL in
	// Location, so there is nothing for Capture to read; this is how a case
	// gets hold of an identifier the server minted.
	//
	// A value that parses as a URL yields its final path segment, since that
	// is what a case substitutes into a path and the base URL differs between
	// the recorder and the verifier. Anything else is captured whole.
	CaptureHeader map[string]string
	// CaptureForm reads values out of the first HTML form in the step's
	// response. It maps a variable name to what to take: "action" for the
	// form's action URL, or "input:<name>" for one input's value.
	//
	// The login page is why it exists. Its form's action carries five query
	// parameters - session_code, execution, client_id, tab_id and client_data -
	// every one of them minted per request, so the credential POST cannot be
	// written as a literal. See the "The login page, and the five parameters
	// its form carries" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	//
	// "action" is captured **relative to the base URL**, so it drops straight
	// into a following step's Path. buildRequest appends Query only when Query
	// is non-empty, so an action carrying its own query string works there
	// unchanged.
	//
	// "input:" is supported although the measured login needs none of it: the
	// form's three inputs are username, password and a value-less hidden
	// credentialId. It is here so the next flow with a valued hidden field does
	// not need a second mechanism.
	CaptureForm map[string]string
	// CaptureQuery maps a variable name to a query parameter of the Location
	// header. CaptureHeader cannot do this: it yields a URL's last path
	// segment, which is what a 201's Location carries and is useless for the
	// authorization redirect, whose code, state, session_state and iss are all
	// in the query.
	//
	// The fragment is deliberately not read. response_mode=fragment puts the
	// same parameters there, but the case that measures it records the
	// redirect rather than capturing out of it, and supporting what no case
	// uses is a guess about the next cut.
	CaptureQuery map[string]string
	// ExpectStatus is the set of status codes this step accepts. Empty means
	// **any 2xx**, which is what almost every step wants.
	//
	// It exists because a fixture step that fails used to be silent: RunFixture
	// read resp.StatusCode only to decorate a capture-failure message, so a
	// refused setup request left the fixture running to completion, the case's
	// own request went to a server in the wrong state, and `make record` wrote
	// that response as the contract and reported PASS. Follow-up F34 has the
	// realised symptom - nineteen goldens recorded, every subtest passing, and
	// every one of them describing a subject holding no roles.
	//
	// The default cannot simply be "2xx" with no way out: the recorder shares
	// one container, so a fixture more than one case names runs its creates more
	// than once and every run after the first answers 409. Those creates say so
	// with idempotentCreate, which turns each of the comments that documented
	// that 409 into something checked.
	ExpectStatus []int
	// Mutates says a step that captures nothing is here for its effect on the
	// server rather than for its response.
	//
	// TestFixturesAreWellFormed rejects a GET that captures nothing as dead
	// weight, and that rule rests on "a GET does not change server state" -
	// which is true of every step in the catalogue except one. **GET /logout
	// with a valid id_token_hint ends the session**, measured: the refresh
	// token that worked before it answers "Session not active" after. So
	// logout-hint-spent's third step is a GET that captures nothing, changes
	// everything, and is the whole point of the fixture.
	//
	// It is a declaration rather than a path list because the next endpoint
	// whose GET writes should have to say so too, and because a list of paths
	// in a test is a second place the catalogue's shape is written down.
	Mutates bool
}

// idempotentCreate is the ExpectStatus of a create whose repeat is harmless:
// the object is already there, the fixture looks its id up rather than reading
// Location, and the state the case needs is reached either way.
//
// The creates that do **not** carry it are the ones that capture from Location -
// see clientFixtureBody - where a 409 leaves nothing to capture and the failure
// must be loud.
var idempotentCreate = []int{http.StatusCreated, http.StatusConflict}

// Fixture is the setup a case runs against: a named server-side starting
// state, plus the steps that lead from it to the state the case measures.
type Fixture struct {
	// State names the starting point. "bootstrap" is a fresh master realm,
	// and is the only one today.
	State string
	Steps []Step
	// Delay is waited out after the last step and before the case's own
	// request. It exists for one measured behaviour: a token that has to be
	// expired when the case asks about it.
	//
	// Nothing else in the harness sleeps, and this should stay the exception.
	// It is here because the alternative was not available: a client attribute
	// can shorten an access token's life to one second, but "-1" was measured
	// falling back to 36000 rather than producing a token born expired, and
	// "0" produced expires_in 0 with a token the server still accepted. So the
	// only way to reach an expired token is to wait for one.
	Delay time.Duration
}

// Fixtures is every setup a case may name. One declaration, executed twice:
// by the recorder against the reference container and by the verifier against
// the in-process handler. Two declarations would compare responses obtained
// in different ways, which is the one thing this suite cannot afford.
var Fixtures = map[string]Fixture{
	"bootstrap": {State: "bootstrap"},

	// admin-token holds an access token and a refresh token for the
	// bootstrapped administrator, obtained the way kcadm.sh obtains one: the
	// password grant on admin-cli.
	//
	// Note that admin-cli is a lightweight client, so the access token this
	// yields carries no sub, aud or realm_access - see the "Lightweight
	// access tokens" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	"admin-token": {
		State: "bootstrap",
		Steps: []Step{{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  "admin-cli",
					"username":   "admin",
					"password":   "admin",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		}},
	},

	// admin-token-openid is admin-token with the openid scope requested.
	//
	// The two differ in exactly one way and it is not cosmetic: a token
	// obtained without openid is refused by the userinfo endpoint, measured
	// as 403 with WWW-Authenticate carrying error="insufficient_scope" and
	// error_description="Missing openid scope". A case measuring what
	// userinfo returns for a valid token needs this fixture; a case
	// measuring the token endpoint's own response needs admin-token, whose
	// recorded scope is "email profile" precisely because it did not ask for
	// openid.
	"admin-token-openid": {
		State: "bootstrap",
		Steps: []Step{{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  "admin-cli",
					"username":   "admin",
					"password":   "admin",
					"scope":      "openid",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		}},
	},

	// admin-token-account-client is admin-token plus the internal UUID of the
	// bootstrapped `account` client, found by filtering the client list.
	//
	// The UUID cannot be a literal in a case: it is minted at bootstrap, so
	// the reference container's differs from Gloak's on every run. Looking it
	// up is what makes a case addressable by the UUID Keycloak's admin API
	// addresses clients by.
	"admin-token-account-client": {
		State: "bootstrap",
		Steps: []Step{
			{
				Request: Request{
					Method: http.MethodPost,
					Path:   "/realms/master/protocol/openid-connect/token",
					Form: map[string]string{
						"grant_type": "password",
						"client_id":  "admin-cli",
						"username":   "admin",
						"password":   "admin",
					},
				},
				Capture: map[string]string{"access_token": "access_token"},
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "account"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				// The filter matches exactly one client, so index 0 is not a
				// bet on list order.
				Capture: map[string]string{"client_uuid": "0/id"},
			},
		},
	},

	// admin-token-admin-user is admin-token plus the bootstrapped
	// administrator's own user ID, found by filtering the user list. Like the
	// client UUID it is minted at bootstrap, so it can never be a literal.
	"admin-token-admin-user": {
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/users",
					Query:   map[string]string{"username": "admin", "exact": "true"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				// exact=true matches one user, so index 0 is not a bet on
				// list order.
				Capture: map[string]string{"user_id": "0/id"},
			},
		},
	},

	// One fixture per case that needs a pre-created user, each with its own
	// username - the same uniqueness requirement clientFixture carries, for
	// the same reason.
	"admin-token-created-user":   userFixture("gloak-probe-user"),
	"admin-token-user-to-update": userFixture("gloak-probe-update-user"),
	"admin-token-user-to-delete": userFixture("gloak-probe-delete-user"),

	// A user that has been through a partial update, so a case can read back
	// what merging left behind.
	"admin-token-user-updated": updatedUserFixture(),

	// Users that already hold a password, for the credential cases. Each
	// creates its own user and captures the credential's server-minted id.
	"admin-token-user-with-password":           passwordFixture("gloak-probe-pw-user", false, ""),
	"admin-token-user-with-doomed-password":    passwordFixture("gloak-probe-pw-doomed", false, ""),
	"admin-token-user-with-labelled-password":  passwordFixture("gloak-probe-pw-labelled", false, "office laptop"),
	"admin-token-user-with-temporary-password": passwordFixture("gloak-probe-pw-temp", true, ""),

	// A user who logged in and was then logged out by an administrator, so a
	// case can ask what its refresh token answers afterwards.
	"logged-out-user": loggedOutUserFixture(),

	// One fixture per case that needs a pre-created client, each with its own
	// clientId - see clientFixture for why sharing one would break recording.
	"admin-token-client-to-update":    clientFixture("gloak-probe-update"),
	"admin-token-client-to-delete":    clientFixture("gloak-probe-delete"),
	"admin-token-client-to-duplicate": clientFixture("gloak-probe-duplicate"),
	"admin-token-client-to-read":      clientFixture("gloak-probe-read"),
	// A client carrying a description, which no bootstrapped client has and
	// which Gloak dropped entirely until kcadm.sh caught it.
	"admin-token-client-described": clientFixtureBody(
		`{"clientId":"gloak-probe-described","enabled":true,"name":"A name","description":"A description"}`),

	// The secret endpoints need a client that has a secret, which means one
	// created through the API: none of the six bootstrapped clients has one.
	"admin-token-client-secret":         clientFixture("gloak-probe-secret"),
	"admin-token-client-secret-rotate":  clientFixture("gloak-probe-rotate"),
	"admin-token-client-secret-rotated": clientFixture("gloak-probe-rotated"),
	"admin-token-client-secret-drop":    clientFixture("gloak-probe-drop"),

	"admin-token-client-service-account": clientFixtureBody(
		`{"clientId":"gloak-probe-service-account","enabled":true,"serviceAccountsEnabled":true}`),

	// The fixtures P1 could not write. Everything the six bodies in follow-up
	// F15 need is one confidential client with a known secret, which is what
	// Tasks 10 and 11 made reachable.
	//
	// gloak-confidential is shared by four cases, which is why
	// confidentialClientFixture looks its UUID up rather than reading Location
	// - see there.
	"confidential-user-token": confidentialClientFixture(
		"gloak-confidential",
		`{"clientId":"gloak-confidential","enabled":true,"directAccessGrantsEnabled":true}`,
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type":    "password",
					"client_id":     "gloak-confidential",
					"client_secret": "{{client_secret}}",
					"username":      "admin",
					"password":      "admin",
					"scope":         "openid",
				},
			},
			Capture: map[string]string{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
			},
		},
	),

	"confidential-service-account": confidentialClientFixture(
		"gloak-confidential-sa",
		`{"clientId":"gloak-confidential-sa","enabled":true,"serviceAccountsEnabled":true}`,
	),

	// The browser fixtures. Every one registers its own client, because the
	// six bootstrapped ones cannot serve these cases: security-admin-console
	// pins pkce.code.challenge.method to S256 and registers a host-relative
	// redirect pattern, admin-cli has the standard flow off, account and
	// account-console redirect only inside /realms/master/account/*, and
	// broker and master-realm are confidential. See browserRedirectURI.
	//
	// One fixture per case, and here that is not only the usual isolation rule:
	// a failed code exchange spends the code, so two cases sharing one login
	// would measure the second one's replay. See browserCodeFixture.
	"browser-client":      browserClientFixture("gloak-probe-browser", ""),
	"browser-login":       browserFormFixture("gloak-probe-browser", "", nil),
	"browser-login-s256":  browserFormFixture("gloak-probe-browser", "", pkceS256Query),
	"browser-login-plain": browserFormFixture("gloak-probe-browser", "", pkcePlainQuery),
	"browser-login-frag":  browserFormFixture("gloak-probe-browser", "", map[string]string{"response_mode": "fragment"}),
	"browser-login-form":  browserFormFixture("gloak-probe-browser", "", map[string]string{"response_mode": "form_post"}),
	// A login that has already completed, so the case's own request is the
	// **replay** of its credential POST.
	//
	// Its client is its own for the usual reason, and its jar is the point: the
	// successful login clears KC_RESTART with Max-Age=0, and `cookies` stores a
	// cleared cookie as an empty value and resends it - which is what a browser
	// that has not yet expired it does. Measured 2026-08-30 as a grid over the
	// three cookies, an **empty KC_RESTART counts as absent**, so this fixture
	// reaches the one branch of the three whose Location holds nothing
	// per-request and can therefore be asserted by value.
	"browser-login-expired": browserCodeFixture("gloak-probe-browser-expired", "", nil),

	"browser-code":          browserCodeFixture("gloak-probe-browser", "", nil),
	"browser-code-mismatch": browserCodeFixture("gloak-probe-browser", "", pkceS256Query),
	"browser-code-spent":    browserSpentCodeFixture("gloak-probe-browser", nil, nil),
	"browser-logged-in":     browserLogoutFixture(),

	// The logout fixtures. Every one of them signs its user in with a direct
	// grant rather than through the login form, because the logout endpoint's
	// answer is measured identical either way and only the direct grant can be
	// replayed against Gloak. See the block comment above logoutClientBody.
	//
	// One client per fixture, as everywhere else: the recorder shares one
	// container across the catalogue, and two fixtures creating one clientId
	// would make the second create a 409.
	"logout-hint":         logoutSessionFixture("gloak-probe-logout", logoutRedirectAttribute),
	"logout-hint-spent":   logoutSpentHintFixture(),
	"logout-client":       Fixture{State: "bootstrap", Steps: logoutClientSteps("gloak-probe-logout-client", logoutRedirectAttribute)},
	"logout-default-uris": logoutSessionFixture("gloak-probe-logout-default", ""),
	"logout-refresh":      logoutSessionFixture("gloak-probe-logout-refresh", logoutRedirectAttribute),
	"logout-mismatch":     logoutMismatchFixture(),
	"logout-confidential": logoutConfidentialFixture(),

	// access.token.lifespan is measured: "1" makes expires_in 1 and the token
	// verifiably expired a second later. The delay is what makes the case
	// deterministic rather than a race against the recorder's own latency.
	"confidential-expired-token": expiredTokenFixture(),

	// A realm role created through the API, for the cases that read one back.
	// Location names it by name rather than by id, so nothing needs capturing:
	// the case can address it by the name it asked for.
	"admin-token-realm-role": {
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-role","description":"a probe"}`),
			},
			ExpectStatus: idempotentCreate,
		}},
	},

	// One realm role per case that writes to it, each with its own name -
	// the same uniqueness clientFixture and userFixture carry, for the same
	// reason: sharing a name with a case that mutates it would make the
	// mutation visible to every other case addressing that name.
	"admin-token-role-to-update": realmRoleFixture("gloak-probe-role-update"),
	"admin-token-role-to-delete": realmRoleFixture("gloak-probe-role-delete"),

	// Three realm roles sharing one search prefix, for the cases that
	// exercise first and max on a narrowed listing.
	"admin-token-paged-roles":          pagedRolesFixture(),
	"admin-token-role-with-attributes": attributedRoleFixture(),

	// A client carrying one role, for the cases that read a client's own
	// roles back. Read-only cases only - see realmRoleFixture's doc for why a
	// case that writes needs its own name instead.
	"admin-token-client-role-container": clientRoleFixture("gloak-probe-role-client", "gloak-probe-client-role"),
	"admin-token-client-role-to-update": clientRoleFixture("gloak-probe-role-client-update", "gloak-probe-client-role-update"),
	"admin-token-client-role-to-delete": clientRoleFixture("gloak-probe-role-client-delete", "gloak-probe-client-role-delete"),

	// A client with no role of its own yet, for the case that creates one.
	"admin-token-role-create-container": clientFixture("gloak-probe-role-create-client"),

	// A realm role and a client role sharing one search prefix, for the case
	// that guards the realm listing against leaking a client role in.
	"admin-token-same-named-roles": sameNamedRolesFixture(),

	// A realm-role parent composite over one realm-family child and one
	// client-family child, everything linked. Backs every read on the realm
	// side of the composite endpoints, both by name and by id (roles-by-id
	// addresses the identical role through {{parent_id}}), and the write
	// endpoints too: POST .../composites is measured idempotent - "already a
	// child" answers 204, not 409 - so a case's own add repeats what this
	// fixture already did, and a case's own remove is undone the next time
	// this fixture runs, since its last step re-links both children before
	// every case that names it.
	"admin-token-composite-parent": compositeParentFixture(),

	// compositeParentFixture's mirror with a client role as the parent, for
	// the client side of the same endpoints.
	"admin-token-composite-parent-client": compositeParentClientFixture(),

	// The subject every mapping read is taken on: one user holding one realm
	// role and one role on each of two clients.
	"admin-token-mapping-subject": mappingSubjectFixture(),

	// A user holding nothing but the default-roles-master it is created with.
	// It backs the realm `available` read, which is the one case in this
	// family that enumerates the realm's own roles rather than one user's -
	// so its fixture must create no realm role of its own. See that case's
	// PristineRealm marking.
	"admin-token-mapping-bare-user": userFixture("gloak-probe-mapping-bare"),

	// One fixture per write pair, each with its own user, role and client -
	// the uniqueness realmRoleFixture's doc explains. Both end by assigning
	// the role, so the pair's `DELETE` has something to remove and its `POST`
	// repeats an assignment that is measured idempotent.
	"admin-token-mapping-realm-write":  mappingRealmWriteFixture(),
	"admin-token-mapping-client-write": mappingClientWriteFixture(),

	// The three callers that are **not** the bootstrapped administrator. Every
	// other fixture here authenticates as it, which is why no case in the
	// catalogue could assert a 403 until now - F37.
	"narrow-caller-manage-users":  callerFixture("gloak-probe-caller-manage-users", "manage-users"),
	"narrow-caller-view-users":    callerFixture("gloak-probe-caller-view-users", "view-users"),
	"narrow-caller-impostor":      impostorCallerFixture(),
	"narrow-caller-query-users":   callerFixture("gloak-probe-caller-query-users", "query-users"),
	"narrow-caller-query-clients": callerFixture("gloak-probe-caller-query-clients", "query-clients"),

	// The group tree. Each fixture owns its groups: the recorder shares one
	// container, so a case that renames or deletes must not be reading a group
	// another case is asserting on.
	"admin-token-group":        groupFixture("gloak-probe-group", "group_id"),
	"admin-token-group-update": groupFixture("gloak-probe-group-update", "group_id"),
	"admin-token-group-delete": groupFixture("gloak-probe-group-delete", "group_id"),
	"admin-token-group-tree":   groupTreeFixture(),
	"admin-token-group-search": groupSearchFixture(),
	"admin-token-group-member": groupMemberFixture(),

	// A group holding one realm role and one client role, for the eleven
	// mapping routes. Its own group and its own client, the uniqueness
	// realmRoleFixture's doc explains.
	"admin-token-group-mappings": groupMappingFixture(),

	// A realm of its own for each case that changes one, because the recorder
	// shares a container: an update and a delete on the same realm would make
	// the second depend on whether the first ran.
	"admin-token-realm":        realmFixture("gloak-probe-realm"),
	"admin-token-realm-update": realmFixture("gloak-probe-realm-update"),
	"admin-token-realm-delete": realmFixture("gloak-probe-realm-delete"),

	// P4's second cut. The default groups and the read by path live in a realm
	// of their own rather than in master, so master's own group goldens - which
	// are PristineRealm - stay untouched by them.
	"admin-token-default-groups":      defaultGroupsFixture(false),
	"admin-token-default-groups-full": defaultGroupsFixture(true),

	// The client-policy writes each get a realm too, for realmFixture's reason:
	// they replace the realm's whole profile set, so two cases sharing one
	// realm would make the second depend on whether the first ran.
	"admin-token-client-profiles":         realmFixture("gloak-probe-profiles"),
	"admin-token-client-profiles-written": clientProfilesFixture("gloak-probe-profiles-written"),
	"admin-token-client-policies-written": clientPoliciesFixture("gloak-probe-policies-written"),

	// P5's first cut. Every one of these creates its client scope with a
	// **fixed** id, which is measured to be honoured: POST /client-scopes with
	// `"id":"aaaa..."` in the body created a scope with exactly that id and put
	// it in Location, on Keycloak and on Gloak alike. That buys two things no
	// other family in this file has - the case's path can name the id
	// literally, so nothing has to be captured, and the golden's `id` is
	// reproducible, so nothing has to be masked. The repeat is a 409, which
	// idempotentCreate already tolerates.
	//
	// One fixture per case that mutates its scope, each with its own name and
	// id, for realmRoleFixture's reason.
	"admin-token-client-scope":           clientScopeFixture(probeScopeID, "gloak-probe-scope"),
	"admin-token-client-scope-update":    clientScopeFixture(probeScopeUpdateID, "gloak-probe-scope-update"),
	"admin-token-client-scope-delete":    clientScopeFixture(probeScopeDeleteID, "gloak-probe-scope-delete"),
	"admin-token-client-template-update": clientScopeFixture(probeTemplateUpdateID, "gloak-probe-template-update"),
	"admin-token-client-template-delete": clientScopeFixture(probeTemplateDeleteID, "gloak-probe-template-delete"),

	// The realm's two default sets. A PUT and a DELETE cannot share a scope:
	// the PUT is measured 409 on the repeat, so the case that deletes needs one
	// already in the set and the case that adds needs one in neither.
	"admin-token-realm-scope-add":      realmDefaultScopeFixture(probeRealmAddID, "gloak-probe-realm-add", false, true),
	"admin-token-realm-scope-drop":     realmDefaultScopeFixture(probeRealmDropID, "gloak-probe-realm-drop", true, true),
	"admin-token-realm-scope-add-opt":  realmDefaultScopeFixture(probeRealmAddOptID, "gloak-probe-realm-add-opt", false, false),
	"admin-token-realm-scope-drop-opt": realmDefaultScopeFixture(probeRealmDropOptID, "gloak-probe-realm-drop-opt", true, false),

	// A client's two sets. Same split, and each case gets its own client as
	// well as its own scope, because attaching to a shared client would make
	// the listing case depend on whether the attach case had run.
	"admin-token-client-scopes-read": clientScopeAttachFixture(
		probeScopeClientReadID, "gloak-probe-cs-read",
		probeAttachReadID, "gloak-probe-cs-read-scope", false, true),
	"admin-token-client-scope-attach": clientScopeAttachFixture(
		probeScopeClientAttachID, "gloak-probe-cs-attach",
		probeAttachID, "gloak-probe-cs-attach-scope", false, true),
	"admin-token-client-scope-detach": clientScopeAttachFixture(
		probeScopeClientDetachID, "gloak-probe-cs-detach",
		probeDetachID, "gloak-probe-cs-detach-scope", true, true),
	"admin-token-client-scope-attach-opt": clientScopeAttachFixture(
		probeScopeClientAttachOptID, "gloak-probe-cs-attach-opt",
		probeAttachOptID, "gloak-probe-cs-attach-opt-scope", false, false),
	"admin-token-client-scope-detach-opt": clientScopeAttachFixture(
		probeScopeClientDetachOptID, "gloak-probe-cs-detach-opt",
		probeDetachOptID, "gloak-probe-cs-detach-opt-scope", true, false),

	// A client scope that has been through a partial PUT, so a case can read
	// back what the PUT left alone. `admin-token-user-updated`'s shape, for
	// the same reason: a 204 says nothing about what it wrote.
	"admin-token-client-scope-merged": mergedClientScopeFixture(),

	"admin-token-client-named-scopes": namedScopesClientFixture(
		probeScopeClientNamedID, "gloak-probe-cs-named", "", "", false),
	"admin-token-client-saml-scope": namedScopesClientFixture(
		probeScopeClientSAMLID, "gloak-probe-cs-saml",
		probeSAMLScopeID, "gloak-probe-cs-saml-scope", true),

	// ---------------------------------------------------------------------
	// P5 cut B: protocol mappers. Appended here rather than filed beside the
	// client-scope fixtures above, because internal/conformance/fixture.go
	// belongs to another stream this session and the end of the map is the
	// one place two branches cannot both edit.
	//
	// Every mapper is created with a **fixed id**, which the body's id wins
	// over on every path that takes one: POST /client-scopes, POST /clients,
	// POST .../protocol-mappers/models and POST .../protocol-mappers/add-models
	// were each measured keeping the id they were handed. So no fixture has to
	// capture from Location, which is what makes them safe on the shared
	// container.
	//
	// The mapper configs are **measured to be order-stable**: their key order
	// as sent is the key order Keycloak serves them back in. That is not free -
	// a config is a Java map and a seven-key one comes back reordered - so each
	// of these was checked against the container before being written here, and
	// it is what lets these goldens assert config bytes with no UnorderedKeys
	// mask. See the plan's section 4.4.
	"admin-token-mapper-scope": mapperScopeFixture(
		probeMapperScopeID, "gloak-probe-pm-read", readMappers(probeMapperAID, probeMapperBID)),
	"admin-token-mapper-scope-create": mapperScopeFixture(
		probeMapperScopeCreateID, "gloak-probe-pm-create", ""),
	"admin-token-mapper-template-create": mapperScopeFixture(
		probeMapperTemplateCreateID, "gloak-probe-pm-tmpl-create", ""),
	"admin-token-mapper-scope-update": mapperScopeFixture(
		probeMapperScopeUpdateID, "gloak-probe-pm-update",
		oneMapper(probeMapperUpdateID, "gloak-probe-mapper-update", "gloak-before")),
	"admin-token-mapper-template-update": mapperScopeFixture(
		probeMapperTemplateUpdateID, "gloak-probe-pm-tmpl-update",
		oneMapper(probeMapperTmplUpdateID, "gloak-probe-mapper-update", "gloak-before")),
	"admin-token-mapper-scope-delete": mapperScopeFixture(
		probeMapperScopeDeleteID, "gloak-probe-pm-delete",
		oneMapper(probeMapperDeleteID, "gloak-probe-mapper-delete", "gloak-delete")),
	"admin-token-mapper-template-delete": mapperScopeFixture(
		probeMapperTemplateDeleteID, "gloak-probe-pm-tmpl-delete",
		oneMapper(probeMapperTmplDeleteID, "gloak-probe-mapper-delete", "gloak-delete")),
	"admin-token-mapper-scope-add": mapperScopeFixture(
		probeMapperScopeAddID, "gloak-probe-pm-add", ""),
	"admin-token-mapper-template-add": mapperScopeFixture(
		probeMapperTemplateAddID, "gloak-probe-pm-tmpl-add", ""),
	"admin-token-mapper-scope-dup": mapperScopeFixture(
		probeMapperScopeDupID, "gloak-probe-pm-dup",
		oneMapper(probeMapperDupID, "gloak-probe-mapper-dup", "gloak-dup")),

	"admin-token-mapper-client": mapperClientFixture(
		probeMapperClientID, "gloak-probe-pm-client",
		readMappers(probeMapperClientAID, probeMapperClientBID)),
	"admin-token-mapper-client-create": mapperClientFixture(
		probeMapperClientCreateID, "gloak-probe-pm-client-create", ""),
	"admin-token-mapper-client-update": mapperClientFixture(
		probeMapperClientUpdateID, "gloak-probe-pm-client-update",
		oneMapper(probeMapperClientUpdMapID, "gloak-probe-mapper-update", "gloak-before")),
	"admin-token-mapper-client-delete": mapperClientFixture(
		probeMapperClientDeleteID, "gloak-probe-pm-client-delete",
		oneMapper(probeMapperClientDelMapID, "gloak-probe-mapper-delete", "gloak-delete")),
	"admin-token-mapper-client-add": mapperClientFixture(
		probeMapperClientAddID, "gloak-probe-pm-client-add", ""),

	// The three fixtures whose point is what a 204 or a 409 cannot show.
	"admin-token-mapper-created":        createdMapperFixture(),
	"admin-token-mapper-updated":        updatedMapperFixture(),
	"admin-token-mapper-batch-conflict": batchConflictMapperFixture(),

	// ---------------------------------------------------------------------
	// P5 cut C: scope mappings. Appended at the very end for cut B's reason -
	// this file belongs to another stream this session and the end of the map
	// is the one place two branches cannot both edit.
	//
	// Every container carries a fixed id, which the body's id is measured to
	// win on for both `POST /client-scopes` and `POST /clients`, so no case has
	// to capture one. The **roles** are the exception: a role's id is minted by
	// the server whatever the body says - `POST .../roles` answers a `Location`
	// ending in the role's *name* - so each fixture reads its realm role back
	// to capture the id the realm write needs. The client write needs no id at
	// all: it resolves by name.
	"scope-mappings-scope":           scopeMappingScopeFixture(smScopeID, "gloak-probe-sm-read", smRoleClientID, "gloak-probe-sm-rc", true, true),
	"scope-mappings-scope-add":       scopeMappingScopeFixture(smScopeAddID, "gloak-probe-sm-add", smRoleClientAddID, "gloak-probe-sm-rc-add", false, false),
	"scope-mappings-scope-drop":      scopeMappingScopeFixture(smScopeDropID, "gloak-probe-sm-drop", smRoleClientDropID, "gloak-probe-sm-rc-drop", true, false),
	"scope-mappings-scope-add-role":  scopeMappingScopeFixture(smScopeAddRoleID, "gloak-probe-sm-add-role", smRoleClientAddRoleID, "gloak-probe-sm-rc-add-role", false, false),
	"scope-mappings-scope-drop-role": scopeMappingScopeFixture(smScopeDropRoleID, "gloak-probe-sm-drop-role", smRoleClientDropRoleID, "gloak-probe-sm-rc-drop-role", false, true),

	"scope-mappings-template-add":       scopeMappingScopeFixture(smTemplateAddID, "gloak-probe-sm-t-add", smRoleClientTAddID, "gloak-probe-sm-rc-t-add", false, false),
	"scope-mappings-template-drop":      scopeMappingScopeFixture(smTemplateDropID, "gloak-probe-sm-t-drop", smRoleClientTDropID, "gloak-probe-sm-rc-t-drop", true, false),
	"scope-mappings-template-add-role":  scopeMappingScopeFixture(smTemplateAddRoleID, "gloak-probe-sm-t-add-role", smRoleClientTAddRoleID, "gloak-probe-sm-rc-t-add-role", false, false),
	"scope-mappings-template-drop-role": scopeMappingScopeFixture(smTemplateDropRoleID, "gloak-probe-sm-t-drop-role", smRoleClientTDropRoleID, "gloak-probe-sm-rc-t-drop-role", false, true),

	"scope-mappings-client":           scopeMappingClientFixture(smOwnerID, "gloak-probe-sm-owner", smRoleClientOwnerID, "gloak-probe-sm-rc-owner", true, true),
	"scope-mappings-client-add":       scopeMappingClientFixture(smOwnerAddID, "gloak-probe-sm-owner-add", smRoleClientOAddID, "gloak-probe-sm-rc-o-add", false, false),
	"scope-mappings-client-drop":      scopeMappingClientFixture(smOwnerDropID, "gloak-probe-sm-owner-drop", smRoleClientODropID, "gloak-probe-sm-rc-o-drop", true, false),
	"scope-mappings-client-add-role":  scopeMappingClientFixture(smOwnerAddRoleID, "gloak-probe-sm-owner-add-role", smRoleClientOAddRoleID, "gloak-probe-sm-rc-o-add-role", false, false),
	"scope-mappings-client-drop-role": scopeMappingClientFixture(smOwnerDropRoleID, "gloak-probe-sm-owner-drop-role", smRoleClientODropRoleID, "gloak-probe-sm-rc-o-drop-role", false, true),

	// A client with fullScopeAllowed **set**, so its composite reads answer
	// every role in the realm rather than what it has mapped.
	"scope-mappings-full-scope": scopeMappingFullScopeFixture(),
	// A client scope with a **composite** realm role mapped, for the two reads
	// that disagree about it: composite expands it and available does not.
	"scope-mappings-composite": scopeMappingCompositeFixture(),
	// What a 204 cannot show: the realm write took a **client** role, by id,
	// with no name, and the combined read afterwards is where it landed.
	"scope-mappings-written": scopeMappingWrittenFixture(),
	// What a 403 cannot show: a batch of one allowed role and one refused one
	// wrote neither.
	"scope-mappings-batch-refused": scopeMappingBatchRefusedFixture(),

	// A caller holding manage-clients and nothing else, which is what makes the
	// per-role check visible: it may map a client role and not a realm one.
	"narrow-caller-manage-clients": callerFixture("gloak-probe-caller-manage-clients", "manage-clients"),
	// The same caller, with a scope and a realm role to aim at.
	"scope-mappings-narrow-caller": scopeMappingNarrowCallerFixture(),
}

// The fixed client-scope ids P5's fixtures create their scopes with. They are
// spelled here rather than inline so a case can name the same constant its
// fixture used, and so two fixtures cannot silently pick the same one.
const (
	probeScopeID          = "a5c09e00-0000-4000-8000-000000000001"
	probeScopeUpdateID    = "a5c09e00-0000-4000-8000-000000000002"
	probeScopeDeleteID    = "a5c09e00-0000-4000-8000-000000000003"
	probeTemplateUpdateID = "a5c09e00-0000-4000-8000-000000000004"
	probeTemplateDeleteID = "a5c09e00-0000-4000-8000-000000000005"
	probeRealmAddID       = "a5c09e00-0000-4000-8000-000000000006"
	probeRealmDropID      = "a5c09e00-0000-4000-8000-000000000007"
	probeRealmAddOptID    = "a5c09e00-0000-4000-8000-000000000008"
	probeRealmDropOptID   = "a5c09e00-0000-4000-8000-000000000009"
	probeAttachReadID     = "a5c09e00-0000-4000-8000-00000000000a"
	probeAttachID         = "a5c09e00-0000-4000-8000-00000000000b"
	probeDetachID         = "a5c09e00-0000-4000-8000-00000000000c"
	probeAttachOptID      = "a5c09e00-0000-4000-8000-00000000000d"
	probeDetachOptID      = "a5c09e00-0000-4000-8000-00000000000e"

	// The clients those last five hang their scopes on, fixed for the same
	// reason - see clientScopeAttachFixture.
	probeScopeClientReadID      = "c11e0000-0000-4000-8000-00000000000a"
	probeScopeClientAttachID    = "c11e0000-0000-4000-8000-00000000000b"
	probeScopeClientDetachID    = "c11e0000-0000-4000-8000-00000000000c"
	probeScopeClientAttachOptID = "c11e0000-0000-4000-8000-00000000000d"
	probeScopeClientDetachOptID = "c11e0000-0000-4000-8000-00000000000e"
	probeScopeClientNamedID     = "c11e0000-0000-4000-8000-00000000000f"
	probeScopeClientSAMLID      = "c11e0000-0000-4000-8000-000000000010"
	probeSAMLScopeID            = "a5c09e00-0000-4000-8000-00000000000f"
	probeScopeMergedID          = "a5c09e00-0000-4000-8000-000000000010"
)

// clientScopeFixture creates one client scope in master with a fixed id.
//
// `protocol` is not optional on the way in: a create without it is a measured
// 400 "Unexpected protocol", so a fixture that omitted it would fail rather
// than create anything.
func clientScopeFixture(id, name string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), clientScopeStep(id, name)},
	}
}

func clientScopeStep(id, name string) Step {
	return protocolScopeStep(id, name, "openid-connect")
}

// mergedClientScopeFixture creates a scope carrying a description and two
// attributes and then PUTs a body naming only its `name`.
//
// The case that reads it afterwards is what says the PUT **merged**: a client
// scope keeps the description and the attributes the body did not mention,
// where a role updated the same way loses its description. The update case's
// own 204 cannot see that, and a mutation replacing the merge with a
// replacement survived every other case in this cut.
func mergedClientScopeFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/client-scopes",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body: []byte(`{"id":"` + probeScopeMergedID +
						`","name":"gloak-probe-scope-merged","description":"before",` +
						`"protocol":"openid-connect","attributes":` +
						`{"include.in.token.scope":"true","display.on.consent.screen":"false"}}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodPut,
					Path:    "/admin/realms/master/client-scopes/" + probeScopeMergedID,
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-scope-merged"}`),
				},
			},
		},
	}
}

func protocolScopeStep(id, name, protocol string) Step {
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"id":"` + id + `","name":"` + name +
				`","protocol":"` + protocol + `"}`),
		},
		ExpectStatus: idempotentCreate,
	}
}

// namedScopesClientFixture is a client that names its own client scopes, plus a
// **saml** scope, optionally already offered to it.
//
// It exists for the two rules nothing else in this catalogue can see. Naming
// either list suppresses inheritance on **both**, so a client naming only
// `defaultClientScopes` has an empty optional list rather than the realm's
// five; and attaching a scope whose protocol is not the client's answers 204
// and attaches nothing. Both were measured, both were guessed wrong first, and
// a mutation of each survived every other case in this cut.
func namedScopesClientFixture(clientUUID, clientID, scopeID, scopeName string,
	offerSAML bool) Fixture {
	body := `{"id":"` + clientUUID + `","clientId":"` + clientID +
		`","enabled":true,"defaultClientScopes":["email"]}`
	f := Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(body),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
	if !offerSAML {
		return f
	}
	f.Steps = append(f.Steps,
		protocolScopeStep(scopeID, scopeName, "saml"),
		Step{
			Request: Request{
				Method: http.MethodPut,
				Path: "/admin/realms/master/clients/" + clientUUID +
					"/default-client-scopes/" + scopeID,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
		})
	return f
}

// realmDefaultScopeFixture creates a client scope and, when added is true, puts
// it into one of master's two default sets.
//
// It writes to **master's** realm-wide sets, which is why the two listing cases
// that read them are PristineRealm.
func realmDefaultScopeFixture(id, name string, added, defaultScope bool) Fixture {
	f := clientScopeFixture(id, name)
	if !added {
		return f
	}
	list := "default-default-client-scopes"
	if !defaultScope {
		list = "default-optional-client-scopes"
	}
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/" + list + "/" + id,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// The repeat is a measured 409, and the recorder runs a fixture once
		// per case naming it.
		ExpectStatus: []int{http.StatusNoContent, http.StatusConflict},
	})
	return f
}

// clientScopeAttachFixture is a client of its own plus a client scope of its
// own, optionally already attached to it.
//
// The **client** carries a fixed id here where clientFixture captures one from
// Location, and that is not a preference: `admin-token-client-scopes-read` is
// named by three cases, the recorder runs a fixture once per case against one
// shared container, and the second create answers 409 with no Location to
// capture. Measured on both sides: POST /clients honours an `id` in the body,
// so the id is known before the request rather than after it and the repeat is
// a tolerated 409. It is the same reason confidentialClientFixture looks its
// UUID up, reached by the cheaper route.
func clientScopeAttachFixture(clientUUID, clientID, scopeID, scopeName string,
	attached, defaultScope bool) Fixture {
	f := Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"id":"` + clientUUID + `","clientId":"` + clientID + `","enabled":true}`),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
	f.Steps = append(f.Steps, clientScopeStep(scopeID, scopeName))
	if !attached {
		return f
	}
	list := "default-client-scopes"
	if !defaultScope {
		list = "optional-client-scopes"
	}
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/" + clientUUID + "/" + list +
				"/" + scopeID,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
	})
	return f
}

// realmFixture creates one realm through POST /admin/realms and captures its
// name, which is what every route below addresses it by.
//
// A second State was the other option and it is the wrong one: every other
// resource in this file is built through Steps against the API, and a State
// that seeded a realm behind the API's back would be seeding it differently
// from the way a caller does.
//
// The name is a literal rather than a capture. Unlike a client or a group, a
// realm is addressed by the name the caller chose and not by a server-minted
// id, so there is nothing to look up.
func realmFixture(name string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"realm":"` + name + `","enabled":true}`),
				},
				ExpectStatus: idempotentCreate,
			},
		},
	}
}

// defaultGroupsFixture builds a realm with a parent group, a child of it, and
// - when populated - both of them made default groups.
//
// **The realm is its own rather than master.** The default-groups listing and
// the read by path are realm-wide reads, and master's group goldens are
// PristineRealm: adding a group to master to measure these would show up in
// them. A realm created for the purpose cannot collide with anything.
//
// The two variants share one realm name each so the populated one is not
// affected by the empty one having run.
func defaultGroupsFixture(populated bool) Fixture {
	name := "gloak-probe-dg"
	if populated {
		name = "gloak-probe-dg-full"
	}
	f := realmFixture(name)
	f.Steps = append(f.Steps, groupInRealmSteps(name, "gloak-probe-dg-top", "", "dg_top")...)
	f.Steps = append(f.Steps, groupInRealmSteps(name, "gloak-probe-dg-child", "{{dg_top}}", "dg_child")...)
	if !populated {
		return f
	}
	for _, id := range []string{"{{dg_top}}", "{{dg_child}}"} {
		f.Steps = append(f.Steps, Step{
			Request: Request{
				Method:  http.MethodPut,
				Path:    "/admin/realms/" + name + "/default-groups/" + id,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
		})
	}
	return f
}

// groupInRealmSteps creates one group in the named realm and captures its id.
// parentID empty makes it top-level; otherwise it is created as that group's
// child.
//
// The id is read back with a second request rather than out of the create's
// Location or body, which both carry it: a create the recorder runs twice
// answers 409 the second time, and then there is nothing to capture from.
// groupFixture and groupTreeFixture take the same shape for the same reason.
func groupInRealmSteps(realm, name, parentID, idVar string) []Step {
	create, read := "/admin/realms/"+realm+"/groups", "/admin/realms/"+realm+"/groups"
	query := map[string]string{"search": name}
	if parentID != "" {
		create = "/admin/realms/" + realm + "/groups/" + parentID + "/children"
		read = create
		query = nil
	}
	return []Step{
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    create,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + name + `"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    read,
				Query:   query,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			// The realm holds this one group at this level, so index 0 is not
			// a bet on list order.
			Capture: map[string]string{idVar: "0/id"},
		},
	}
}

// clientProfilesFixture is a realm with one client profile written into it,
// for the read that has something to read.
func clientProfilesFixture(name string) Fixture {
	f := realmFixture(name)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/" + name + "/client-policies/profiles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"profiles":[{"name":"gloak-probe-profile","description":"a probe",` +
				`"executors":[{"executor":"secure-session","configuration":{}}]}]}`),
		},
	})
	return f
}

// clientPoliciesFixture is clientProfilesFixture plus a policy naming that
// profile, which is the only cross-reference a policy body has.
func clientPoliciesFixture(name string) Fixture {
	f := clientProfilesFixture(name)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/" + name + "/client-policies/policies",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"policies":[{"name":"gloak-probe-policy","description":"a probe",` +
				`"enabled":true,"conditions":[{"condition":"any-client","configuration":{}}],` +
				`"profiles":["gloak-probe-profile"]}]}`),
		},
	})
	return f
}

func groupMappingFixture() Fixture {
	f := groupFixture("gloak-probe-group-mapped", "group_id")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-group-realm-role"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/gloak-probe-group-realm-role",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"realm_role_id": "id"},
		},
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body: []byte(`[{"id":"{{realm_role_id}}",` +
					`"name":"gloak-probe-group-realm-role"}]`),
			},
		},
	)
	f.Steps = append(f.Steps, clientWithRoleSteps("gloak-probe-group-map-client", "client_uuid",
		`{"name":"gloak-probe-group-client-role"}`,
		"gloak-probe-group-client-role", "client_role_id")...)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`[{"id":"{{client_role_id}}",` +
				`"name":"gloak-probe-group-client-role"}]`),
		},
	})
	return f
}

// groupMemberFixture puts one user in one group, which cut B's membership write
// made possible. Cut A's members case ran on an empty group because this could
// not be built; its comment said so and that reason expires here.
func groupMemberFixture() Fixture {
	f := userFixture("gloak-probe-group-member")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/groups",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-group-members"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/groups",
				Query:   map[string]string{"search": "gloak-probe-group-members"},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"group_id": "0/id"},
		},
		Step{
			Request: Request{
				Method:  http.MethodPut,
				Path:    "/admin/realms/master/users/{{user_id}}/groups/{{group_id}}",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
		},
	)
	return f
}

// groupFixture creates one top-level group and captures its id.
//
// The id cannot be a literal in a case: it is minted by the server, so the
// reference container's differs from Gloak's on every run. The listing is
// filtered by name to find it, the way the client fixtures do.
func groupFixture(name, idVar string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/groups",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"` + name + `"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/groups",
					Query:   map[string]string{"search": name},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				// The search matches this name and no other, so index 0 is not
				// a bet on list order.
				Capture: map[string]string{idVar: "0/id"},
			},
		},
	}
}

// groupTreeFixture is a parent with one child, for the children pair and for
// the single read's subGroupCount.
func groupTreeFixture() Fixture {
	f := groupFixture("gloak-probe-group-tree", "group_id")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/groups/{{group_id}}/children",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-group-child"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/groups/{{group_id}}/children",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"child_id": "0/id"},
		},
	)
	return f
}

// groupSearchFixture is the shape the search rule needs: two top-level groups
// whose names both match, and a child of the second that matches as well and
// sorts **before** either of them.
//
// That ordering is the whole point. The page is taken from the matches, so
// max=1 returns the child's top-level ancestor rather than the first row.
func groupSearchFixture() Fixture {
	f := Fixture{State: "bootstrap", Steps: []Step{adminTokenStep()}}
	create := func(path, body string) Step {
		return Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    path,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(body),
			},
			ExpectStatus: idempotentCreate,
		}
	}
	f.Steps = append(f.Steps,
		create("/admin/realms/master/groups", `{"name":"gloak-srch-one"}`),
		create("/admin/realms/master/groups", `{"name":"zz-gloak-srch"}`),
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/groups",
				Query:   map[string]string{"search": "zz-gloak-srch"},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"group_id": "0/id"},
		},
		create("/admin/realms/master/groups/{{group_id}}/children", `{"name":"aa-gloak-srch-kid"}`),
	)
	return f
}

// callerFixture is a caller that is not the administrator: a user created and
// given a password through the API, assigned the named admin roles from the
// realm's own `master-realm` client, and then password-granted on admin-cli.
// Its access token is `caller_token`, so a case picks the caller it means by
// which of the two tokens it sends.
//
// **The roles come from `master-realm` by container, not by name**, which is
// the same distinction F32 turned out to be about: a fixture that minted a role
// of its own named `manage-users` would be building the impostor rather than
// the caller.
//
// The token is minted **after** the assignments. Both servers resolve a
// caller's roles from the session on every request rather than from the token -
// there is nothing in an admin-cli token to authorise against, see
// internal/admin's package comment - so the order is not load-bearing, and it
// is this way round because a fixture that reads as though it were is a fixture
// somebody will later reorder.
//
// It also captures `admin_client_uuid` and `realm_role_admin_id`, which the
// cases need to name a role the caller may not be given.
func callerFixture(username string, roles ...string) Fixture {
	f := passwordFixture(username, false, "")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients",
				Query:   map[string]string{"clientId": "master-realm"},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"admin_client_uuid": "0/id"},
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/admin",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"realm_role_admin_id": "id"},
		},
	)
	for i, role := range roles {
		v := "caller_role_" + strconv.Itoa(i)
		f.Steps = append(f.Steps,
			Step{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients/{{admin_client_uuid}}/roles/" + role,
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{v: "id"},
			},
			assignClientRoleStep("{{admin_client_uuid}}", "{{"+v+"}}", role),
		)
	}
	f.Steps = append(f.Steps, callerTokenStep(username))
	return f
}

// callerTokenStep password-grants the fixture's own user on admin-cli and
// captures its access token. Separate from callerFixture because a fixture that
// goes on assigning roles has to mint again afterwards to read as though the
// token carried them.
func callerTokenStep(username string) Step {
	return Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   username,
				"password":   "s3cret",
			},
		},
		Capture: map[string]string{"caller_token": "access_token"},
	}
}

// impostorCallerFixture is F32's caller: one holding a perfectly ordinary
// client role that happens to be **named** manage-realm, and no admin role that
// opens the realm-role routes.
//
// manage-clients and manage-users are what it takes to mint such a role and
// hand it to somebody, which is why the caller holds them - it is a narrow
// admin widening itself, not an anonymous path. Neither of the two opens
// POST /roles, which is what makes the case that uses this a test of the name
// and not of the caller being weak.
//
// The impostor is minted by the administrator rather than by the caller. Who
// mints it is not what the case is about, and doing it here keeps the fixture
// to the steps whose failure would matter.
func impostorCallerFixture() Fixture {
	f := callerFixture("gloak-probe-caller-impostor", "manage-clients", "manage-users")
	f.Steps = append(f.Steps, clientWithRoleSteps("gloak-probe-impostor-client",
		"impostor_client_uuid", `{"name":"manage-realm"}`, "manage-realm", "impostor_role_id")...)
	f.Steps = append(f.Steps,
		assignClientRoleStep("{{impostor_client_uuid}}", "{{impostor_role_id}}", "manage-realm"),
		callerTokenStep("gloak-probe-caller-impostor"))
	return f
}

// mappingSubjectFixture builds the subject the mapping reads are taken on: one
// user holding one realm role and one role on each of two clients, plus a
// second role on the first client left unassigned so `available` has something
// to offer.
//
// The realm role and the assigned client role carry an attribute value, which
// is what makes the two `.../composite` reads' briefRepresentation measurable -
// they are the only two of the six reads that honour it.
//
// **The two clientIds must not share a Java HashMap bucket.** The combined view
// keys `clientMappings` in bucket order and Gloak reproduces it with
// internal/javamap, which is exact only while every key has a bucket to
// itself: colliding keys chain in insertion order, which nothing observable
// reports. At capacity 16 `gloak-probe-mapping-side` is bucket 1 and
// `gloak-probe-mapping-app` is bucket 4. The pair is also discriminating -
// bucket order puts `side` first, where sorting and insertion order both put
// `app` first - so the case would fail rather than pass by accident if the
// endpoint stopped using javamap.
//
// Every create is looked up rather than trusted from Location, for the reason
// confidentialClientFixture gives: several cases name this fixture, so the
// recorder runs its creates several times against one container and every run
// after the first answers 409 with no Location.
//
// **The assignment bodies carry the role's name as well as its id**, and that
// is not decoration: measured 2026-08-27, a mapping write resolves the entry by
// **name** and then requires the id to name the same role, so an id-only body
// answers 404 whatever the id is. See "A mapping write resolves the role by
// name, and the id has to agree" in
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md, and follow-up
// F33 for the Gloak side.
func mappingSubjectFixture() Fixture {
	f := userFixture("gloak-probe-mapping-user")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-mapping-realm","attributes":{"probe":["v1","v2"]}}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/gloak-probe-mapping-realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"realm_role_id": "id"},
		},
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-mapping-realm"}]`),
			},
		},
	)
	f.Steps = append(f.Steps, clientWithRoleSteps("gloak-probe-mapping-app", "client_uuid",
		`{"name":"gloak-probe-mapping-app-role","attributes":{"probe":["v1","v2"]}}`,
		"gloak-probe-mapping-app-role", "app_role_id")...)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body:    []byte(`{"name":"gloak-probe-mapping-app-free"}`),
		},
		ExpectStatus: idempotentCreate,
	})
	f.Steps = append(f.Steps, clientWithRoleSteps("gloak-probe-mapping-side", "side_client_uuid",
		`{"name":"gloak-probe-mapping-side-role"}`,
		"gloak-probe-mapping-side-role", "side_role_id")...)
	f.Steps = append(f.Steps,
		assignClientRoleStep("{{client_uuid}}", "{{app_role_id}}", "gloak-probe-mapping-app-role"),
		assignClientRoleStep("{{side_client_uuid}}", "{{side_role_id}}", "gloak-probe-mapping-side-role"),
	)
	return f
}

// mappingRealmWriteFixture is the realm write pair's subject: its own user, its
// own realm role, and the role already assigned.
//
// Already assigned, because the pair shares one fixture. `POST` on a role the
// user already holds is measured 204 rather than 409, so the assign case
// repeats what this did; and the remove case's deletion is undone the next
// time the fixture runs, since its last step re-assigns before every case that
// names it. That is compositeParentFixture's arrangement, for the same reason.
func mappingRealmWriteFixture() Fixture {
	f := userFixture("gloak-probe-mapping-realm-write")
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-mapping-write-realm-role"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/gloak-probe-mapping-write-realm-role",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"realm_role_id": "id"},
		},
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-mapping-write-realm-role"}]`),
			},
		},
	)
	return f
}

// mappingClientWriteFixture is mappingRealmWriteFixture's mirror for the client
// write pair, with the role on a client of its own.
func mappingClientWriteFixture() Fixture {
	f := userFixture("gloak-probe-mapping-client-write")
	f.Steps = append(f.Steps, clientWithRoleSteps("gloak-probe-mapping-write-client", "client_uuid",
		`{"name":"gloak-probe-mapping-write-client-role"}`,
		"gloak-probe-mapping-write-client-role", "client_role_id")...)
	f.Steps = append(f.Steps, assignClientRoleStep("{{client_uuid}}", "{{client_role_id}}",
		"gloak-probe-mapping-write-client-role"))
	return f
}

// clientWithRoleSteps creates one client and one role on it, capturing the
// client's UUID under uuidVar and the role's id under roleVar. The mapping
// fixtures need both ids, unlike clientRoleFixture next door which addresses
// its role by name and so captures only the client.
func clientWithRoleSteps(clientID, uuidVar, roleBody, roleName, roleVar string) []Step {
	return []Step{
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"clientId":"` + clientID + `","enabled":true}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients",
				Query:   map[string]string{"clientId": clientID},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{uuidVar: "0/id"},
		},
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients/{{" + uuidVar + "}}/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(roleBody),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients/{{" + uuidVar + "}}/roles/" + roleName,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{roleVar: "id"},
		},
	}
}

// assignClientRoleStep gives the fixture's user one client role. The endpoint
// it uses is one of the eleven under test, which is the arrangement
// compositeParentFixture already takes: there is no other way to reach the
// state, and a case whose own endpoint cannot serve its setup fails loudly.
//
// roleName goes into the body beside the id because the write resolves by name;
// see mappingSubjectFixture.
func assignClientRoleStep(uuidRef, roleRef, roleName string) Step {
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/" + uuidRef,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body:    []byte(`[{"id":"` + roleRef + `","name":"` + roleName + `"}]`),
		},
	}
}

// realmRoleFixture creates one realm role and nothing else. Unlike
// clientFixture and userFixture, nothing needs to be captured: a role's
// Location names it by name, not by a server-minted id, so a case addresses
// the name it asked for directly.
func realmRoleFixture(name string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + name + `"}`),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
}

// pagedRolesFixture creates three realm roles sharing one search prefix, so a
// listing can be narrowed to a set of known size before first and max are
// applied to it.
//
// Narrowing first is what makes most of the goldens recordable. A page taken
// out of the whole realm is generally a subset chosen by Keycloak's own role
// order, which AGENTS.md records as differing between container starts, and
// Case.Unordered cannot repair a difference in membership - only in order.
// admin/roles/list-realm-page-no-search is the one case that does take a page
// out of the whole realm; its comment says what makes that particular page
// safe.
//
// **The three are created c, b, a, so creation order is not alphabetical
// order.** Created a, b, c they agreed by accident, and a case over them could
// not tell Keycloak's page selection from Gloak's own sort by name - the two
// produced the same answer whatever the endpoint did. Measured 2026-08-26,
// Keycloak sorts by name on every path that pages, so a fixture whose creation
// order matches that sort is a fixture that cannot detect the difference.
func pagedRolesFixture() Fixture {
	steps := []Step{adminTokenStep()}
	for _, suffix := range []string{"c", "b", "a"} {
		steps = append(steps, Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-page-` + suffix + `"}`),
			},
			ExpectStatus: idempotentCreate,
		})
	}
	return Fixture{State: "bootstrap", Steps: steps}
}

// attributedRoleFixture creates one realm role carrying attributes, so the
// listing's briefRepresentation can be measured against something that has
// something to hide. Exactly one role matches the search prefix, so the
// resulting body is a one-element array and the realm's unstable role order
// cannot reach it.
func attributedRoleFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"gloak-probe-attrs","attributes":{"attribute1":["value1","value2"]}}`),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
}

// clientRoleFixture creates one client and one role on it, addressed by name
// like realmRoleFixture - only the client's own UUID needs capturing, since
// the admin API addresses a client by id but a role on it by name.
//
// The client is looked up rather than trusted from Location, unlike plain
// clientFixture: this fixture backs four read-only cases (list, read, users,
// groups), so the recorder runs its creates four times against the shared
// container, and every run after the first answers 409 with no Location -
// the same reason confidentialClientFixture gives.
func clientRoleFixture(clientID, roleName string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"` + clientID + `","enabled":true}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": clientID},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"client_uuid": "0/id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"` + roleName + `"}`),
				},
				ExpectStatus: idempotentCreate,
			},
		},
	}
}

// sameNamedRolesFixture creates a realm role and a client role sharing one
// search prefix, so a listing narrowed by that prefix has something to leak.
//
// Mined from RealmRolesSearchTest.testSearchForRealmRoles, upstream's guard on
// issue #9587: the realm listing must never return a role whose clientRole is
// true, however the search is spelled.
func sameNamedRolesFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-shared-realm"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"gloak-probe-shared-client"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "gloak-probe-shared-client"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"client_uuid": "0/id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-shared-on-client"}`),
				},
				ExpectStatus: idempotentCreate,
			},
		},
	}
}

// compositeParentFixture creates a realm role, a realm-family child role, a
// client, and a client-family child role on that client, then links both
// children onto the realm role - so a case can read the composite back
// filtered and unfiltered, or write to the same link, addressing the parent
// either by name or (through parent_id) by id.
//
// Every create is looked up rather than trusted from Location, for the
// reason confidentialClientFixture gives: the recorder shares one container,
// so a fixture more than one case names runs its creates more than once, and
// a repeat create answers 409 with nothing useful in Location. A role's
// lookup is a read by name, since that survives a 409 just as well as a 201.
func compositeParentFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-parent"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/roles/gloak-probe-composite-parent",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"parent_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-child-realm"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/roles/gloak-probe-composite-child-realm",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"child_realm_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"gloak-probe-composite-client","enabled":true}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "gloak-probe-composite-client"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"client_uuid": "0/id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-child-client"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-child-client",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"child_client_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles/gloak-probe-composite-parent/composites",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`[{"id":"{{child_realm_id}}"},{"id":"{{child_client_id}}"}]`),
				},
			},
		},
	}
}

// compositeParentClientFixture is compositeParentFixture's mirror with a
// client role as the parent instead of a realm role, so the client side of
// the composite endpoints has something real to read and write too. The
// parent and both children sit on the same client, which is enough to
// exercise the composites/clients filter - it only checks the child's own
// container, not whether that happens to be the parent's container as well.
func compositeParentClientFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"gloak-probe-composite-client-parent","enabled":true}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "gloak-probe-composite-client-parent"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"client_uuid": "0/id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-client-role-parent"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"parent_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-client-parent-child-realm"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/roles/gloak-probe-composite-client-parent-child-realm",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"child_realm_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"name":"gloak-probe-composite-client-parent-child-client"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-parent-child-client",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"child_client_id": "id"},
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`[{"id":"{{child_realm_id}}"},{"id":"{{child_client_id}}"}]`),
				},
			},
		},
	}
}

// confidentialClientFixture creates a confidential client, then captures its
// UUID and the secret the server generated for it.
//
// It finds the UUID by filtering the client list rather than by reading
// Location, and that is the difference from clientFixture. A fixture named by
// more than one case runs once per case against the recorder's single shared
// container, so the second create answers 409 with no Location at all. A
// lookup finds the client either way, which makes the whole fixture idempotent
// and therefore shareable. The create's own response is not captured from, so
// its 409 passes harmlessly; if it failed for any other reason the lookup
// returns an empty array and the capture fails loudly.
func confidentialClientFixture(clientID, body string, extra ...Step) Fixture {
	steps := []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(body),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients",
				Query:   map[string]string{"clientId": clientID},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"client_uuid": "0/id"},
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"client_secret": "value"},
		},
	}
	return Fixture{State: "bootstrap", Steps: append(steps, extra...)}
}

// browserRedirectURI is what the browser fixtures register as their client's
// only redirect pattern, and what every P3 case sends as redirect_uri.
//
// It never has to resolve. TestRecordGoldens sets CheckRedirect to
// ErrUseLastResponse and the verifier reads a ResponseRecorder, so nothing on
// either side ever follows it. What matters is only that Keycloak accepts it,
// which it does because the fixture registered it.
//
// Registering one is not a convenience. security-admin-console, which every
// oidc/authorization case named until now, carries the host-relative pattern
// "/admin/master/console/*", resolved against whatever host and port the
// request arrived on - so no absolute literal in a Case can match a container
// whose port testcontainers assigns at run time. Four cases carried a comment
// saying so and stayed unrecordable. See the "The bootstrapped clients cannot
// serve most of the cases that name them" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
const browserRedirectURI = "http://localhost:9999/callback"

// pkceVerifier and pkceChallengeS256 are RFC 7636 appendix B's pair, which is
// where the challenge already in this catalogue came from. Keeping the
// published pair means the relationship between the two literals is checkable
// against the RFC rather than against a comment.
const (
	pkceVerifier      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pkceChallengeS256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	// plain means challenge and verifier are the same string. It is 43
	// characters because that is RFC 7636's minimum; the literal this replaced
	// was 41.
	pkceVerifierPlain = "gloak-probe-plain-code-verifier-0123456789A"
)

// logoutRedirectAttribute registers a post-logout redirect explicitly.
//
// It is **not** a separate registration that a client must have before it can
// redirect. Measured 2026-08-29 across five clients differing only in this
// attribute: absent, "" and "+" all fall back to the client's own redirectUris,
// "-" refuses every target including its own redirectUris, and anything else is
// a "##"-separated pattern list that replaces redirectUris rather than adding
// to it. So a client with no attribute at all redirects to its registered
// redirect_uri, which is what `logout-default-uris` exists to pin - and it
// falsifies the sentence this constant's comment carried until now.
//
// It is still set here, because a case measuring the explicit branch and a case
// measuring the fallback have to be two clients or neither is measured.
const logoutRedirectAttribute = `,"attributes":{"post.logout.redirect.uris":"` + browserRedirectURI + `"}`

var (
	pkceS256Query = map[string]string{
		"code_challenge":        pkceChallengeS256,
		"code_challenge_method": "S256",
	}
	pkcePlainQuery = map[string]string{
		"code_challenge":        pkceVerifierPlain,
		"code_challenge_method": "plain",
	}
)

// browserClientBody is a public client with the standard flow on and
// browserRedirectURI registered. attributes is spliced in as given, so a
// caller can pin a PKCE method.
func browserClientBody(clientID, attributes string) string {
	return `{"clientId":"` + clientID + `","enabled":true,"publicClient":true,` +
		`"standardFlowEnabled":true,"redirectUris":["` + browserRedirectURI + `"]` +
		attributes + `}`
}

// browserClientSteps creates the client a browser case logs in at.
//
// The create is idempotent because the recorder shares one container across
// the whole catalogue and a fixture named by more than one case runs its
// create once per case. Nothing is captured from it, so the repeat's 409
// passes harmlessly.
func browserClientSteps(clientID, attributes string) []Step {
	return []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(browserClientBody(clientID, attributes)),
			},
			ExpectStatus: idempotentCreate,
		},
	}
}

// browserClientFixture is the client and nothing else, for a case whose own
// request is the one to GET /auth.
func browserClientFixture(clientID, attributes string) Fixture {
	return Fixture{State: "bootstrap", Steps: browserClientSteps(clientID, attributes)}
}

// authorizeStep opens the authorization endpoint and captures the login form's
// action URL, which is the whole reason this cut exists: the action carries
// session_code, execution, client_id, tab_id and client_data, all minted per
// request, so the credential POST cannot be a literal.
//
// The step insists on a 200. A rejected authorization request answers a 302
// with no body, and CaptureForm would then fail on the missing form - but one
// request later, with a message about HTML rather than about the rejection.
// Saying 200 here puts the failure where it happened.
func authorizeStep(clientID string, extra map[string]string) Step {
	query := map[string]string{
		"response_type": "code",
		"client_id":     clientID,
		"redirect_uri":  browserRedirectURI,
		"scope":         "openid",
		"state":         "xyz123",
	}
	for k, v := range extra {
		query[k] = v
	}
	return Step{
		Request:      Request{Method: http.MethodGet, Path: "/realms/master/protocol/openid-connect/auth", Query: query},
		ExpectStatus: []int{http.StatusOK},
		CaptureForm:  map[string]string{"login_action": "action"},
	}
}

// loginStep posts the credentials to the captured action.
//
// The three form fields are the three the measured page carries and no more:
// username, password, and a hidden credentialId with no value. Everything
// volatile is in the action's query, which is why nothing here is captured
// from the page's inputs.
func loginStep() Step {
	return Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		// The successful login is a redirect, not a 2xx.
		ExpectStatus: []int{http.StatusFound},
		CaptureQuery: map[string]string{
			"code":          "code",
			"session_state": "session_state",
		},
	}
}

// browserFormFixture stops at the login page, so the case's own request is the
// credential POST and its own response is the redirect carrying the code.
func browserFormFixture(clientID, attributes string, authQuery map[string]string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: append(browserClientSteps(clientID, attributes), authorizeStep(clientID, authQuery)),
	}
}

// browserCodeFixture runs the whole login, so the case's own request is the
// code exchange at the token endpoint.
//
// Each case that redeems a code needs its own fixture, and that is not the
// uniqueness rule clientFixture follows for its own reason - it is measured. A
// failed exchange spends the code: a wrong code_verifier answers "PKCE
// verification failed: Code mismatch" and the immediate retry answers "Code
// not valid". Two cases sharing one login would measure the second one's
// replay.
func browserCodeFixture(clientID, attributes string, authQuery map[string]string) Fixture {
	steps := append(browserClientSteps(clientID, attributes), authorizeStep(clientID, authQuery))
	return Fixture{State: "bootstrap", Steps: append(steps, loginStep())}
}

// browserSpentCodeFixture is browserCodeFixture with the code already redeemed
// once, so the case's own request is the replay.
func browserSpentCodeFixture(clientID string, authQuery, exchange map[string]string) Fixture {
	f := browserCodeFixture(clientID, "", authQuery)
	form := map[string]string{
		"grant_type":   "authorization_code",
		"client_id":    clientID,
		"redirect_uri": browserRedirectURI,
		"code":         "{{code}}",
	}
	for k, v := range exchange {
		form[k] = v
	}
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form:   form,
		},
	})
	return f
}

// browserLogoutFixture logs a user in and exchanges the code, so the case's
// own request is the logout carrying a real id_token_hint.
//
// Its client is its own, because it needs post.logout.redirect.uris and
// nothing else in the catalogue does. Sharing gloak-probe-browser would mean
// every browser case's client silently gained a logout redirect, and a case
// asserting the refusal of one would then measure the wrong thing.
func browserLogoutFixture() Fixture {
	const clientID = "gloak-probe-browser-logout"
	steps := append(browserClientSteps(clientID, logoutRedirectAttribute),
		authorizeStep(clientID, nil), loginStep())
	return Fixture{State: "bootstrap", Steps: append(steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    clientID,
				"redirect_uri": browserRedirectURI,
				"code":         "{{code}}",
			},
		},
		Capture: map[string]string{"id_token": "id_token"},
	})}
}

// --- The logout fixtures ---
//
// Every one of them mints its session with a **direct grant** rather than a
// browser login, and that is a measurement rather than a convenience.
//
// Measured 2026-08-29, the logout endpoint's 302 is byte-identical whether the
// id_token_hint came from a browser login or from a password grant with no
// cookie jar at all: same Location, same Cache-Control: no-cache, the same four
// security headers with X-Frame-Options and Content-Security-Policy absent. The
// only difference is two cookies - a browser session's KEYCLOAK_IDENTITY and
// KEYCLOAK_SESSION are cleared with Max-Age=0, and there is nothing to clear
// when none were sent - and Set-Cookie is masked as volatile on these cases and
// asserted by none of them.
//
// What that buys is that the fixtures **run against Gloak**. browserLogoutFixture
// drives Keycloak's login form, which Gloak does not serve until P13, so a case
// naming it can never be promoted past Recorded however well the endpoint
// works. See docs/superpowers/plans/2026-08-29-p6-logout.md section 1.

// logoutClientBody is a public client that can both log a user in directly and
// accept them back afterwards. attributes is spliced in as given so a caller
// can register post-logout targets or deliberately register none.
func logoutClientBody(clientID, attributes string) string {
	return `{"clientId":"` + clientID + `","enabled":true,"publicClient":true,` +
		`"standardFlowEnabled":true,"directAccessGrantsEnabled":true,` +
		`"redirectUris":["` + browserRedirectURI + `"]` + attributes + `}`
}

// logoutClientSteps creates that client. Idempotent for the same reason
// browserClientSteps is: the recorder shares one container across the whole
// catalogue and nothing is captured from the create.
func logoutClientSteps(clientID, attributes string) []Step {
	return []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(logoutClientBody(clientID, attributes)),
			},
			ExpectStatus: idempotentCreate,
		},
	}
}

// logoutGrantStep signs a user in at one of those clients and keeps both the ID
// token and the refresh token, because the two logout families want different
// ones: the browser family sends the ID token as id_token_hint, and the POST
// family sends the refresh token.
//
// scope=openid is what makes the response carry an id_token at all.
func logoutGrantStep(clientID string) Step {
	return Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  clientID,
				"username":   "admin",
				"password":   "admin",
				"scope":      "openid",
			},
		},
		Capture: map[string]string{"id_token": "id_token", "refresh_token": "refresh_token"},
	}
}

// logoutSessionFixture is the common shape: one client, one session on it.
func logoutSessionFixture(clientID, attributes string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: append(logoutClientSteps(clientID, attributes), logoutGrantStep(clientID)),
	}
}

// logoutSpentHintFixture logs the session out once already, so the case's own
// request is the **second** logout with a hint whose session is gone.
//
// Measured: that answers the same 302, not an error. A session that is already
// ended is a logout that has already succeeded, which is the opposite of how
// the token endpoint treats a spent authorization code.
func logoutSpentHintFixture() Fixture {
	const clientID = "gloak-probe-logout-spent"
	f := logoutSessionFixture(clientID, logoutRedirectAttribute)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "{{id_token}}",
				"post_logout_redirect_uri": browserRedirectURI,
			},
		},
		ExpectStatus: []int{http.StatusFound},
		Mutates:      true,
	})
	return f
}

// logoutMismatchFixture creates a second client that holds no session, so the
// case can authenticate as one client while presenting the other's refresh
// token. Both are public, so nothing but the token differs - the same
// correction the token endpoint's "another client's code" case needed.
func logoutMismatchFixture() Fixture {
	f := logoutSessionFixture("gloak-probe-logout-owner", logoutRedirectAttribute)
	f.Steps = append(f.Steps, logoutClientSteps("gloak-probe-logout-other", "")[1])
	return f
}

// logoutConfidentialFixture is the same session on a client that must
// authenticate, for the 401 a confidential client gets when it sends no secret.
// The secret is captured but the case deliberately does not send it.
func logoutConfidentialFixture() Fixture {
	const clientID = "gloak-probe-logout-confidential"
	return confidentialClientFixture(clientID,
		`{"clientId":"`+clientID+`","enabled":true,"directAccessGrantsEnabled":true,`+
			`"redirectUris":["`+browserRedirectURI+`"],`+
			`"attributes":{"post.logout.redirect.uris":"`+browserRedirectURI+`"}}`,
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type":    "password",
					"client_id":     clientID,
					"client_secret": "{{client_secret}}",
					"username":      "admin",
					"password":      "admin",
					"scope":         "openid",
				},
			},
			Capture: map[string]string{"refresh_token": "refresh_token"},
		},
	)
}

// expiredTokenFixture obtains an access token that is already expired when the
// case asks about it.
//
// The client carries access.token.lifespan "1", measured to make expires_in 1,
// and the fixture then waits two seconds. See Fixture.Delay for why waiting is
// the only route: neither "0" nor "-1" produces a token born expired.
func expiredTokenFixture() Fixture {
	f := confidentialClientFixture(
		"gloak-confidential-expiring",
		`{"clientId":"gloak-confidential-expiring","enabled":true,"directAccessGrantsEnabled":true,`+
			`"attributes":{"access.token.lifespan":"1"}}`,
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type":    "password",
					"client_id":     "gloak-confidential-expiring",
					"client_secret": "{{client_secret}}",
					"username":      "admin",
					"password":      "admin",
					"scope":         "openid",
				},
			},
			Capture: map[string]string{"access_token": "access_token"},
		},
	)
	f.Delay = 2 * time.Second
	return f
}

// adminTokenStep is the first step of every admin fixture: the password grant
// on admin-cli, the way kcadm.sh authenticates.
func adminTokenStep() Step {
	return Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "admin",
				"password":   "admin",
			},
		},
		Capture: map[string]string{"access_token": "access_token"},
	}
}

// clientFixture builds a fixture that obtains an admin token and creates one
// client, capturing its server-minted UUID from Location.
//
// **Each caller must pass a clientId no other fixture uses.** The recorder runs
// every case against a single container, so state accumulates across cases: two
// fixtures creating the same clientId would make the second one's create fail
// with a conflict, and the capture would then read a Location that is not
// there. The verifier does not have this problem - it builds a fresh
// bootstrapped store per case - which is exactly why the asymmetry is easy to
// miss and worth stating here.
func clientFixture(clientID string) Fixture {
	return clientFixtureBody(`{"clientId":"` + clientID + `","enabled":true}`)
}

// clientFixtureBody is clientFixture with the creation body spelled out, for a
// client that needs more than a clientId - service accounts switched on, say.
// The clientId inside the body carries the same uniqueness requirement.
func clientFixtureBody(body string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(body),
				},
				CaptureHeader: map[string]string{"client_uuid": "Location"},
			},
		},
	}
}

// userFixture creates one user and captures its server-minted ID.
//
// It looks the ID up by username rather than reading Location, for the reason
// confidentialClientFixture spells out: the recorder shares one container, so
// a fixture named by two cases runs twice and the second create answers 409
// with no Location. The lookup finds the user either way.
//
// The user carries a first and last name because the cases that read it back
// need something for a partial update to leave alone.
func userFixture(username string) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{
			adminTokenStep(),
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/users",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body: []byte(`{"username":"` + username + `","enabled":true,` +
						`"firstName":"Ada","lastName":"Lovelace","email":"` + username + `@example.com"}`),
				},
				ExpectStatus: idempotentCreate,
			},
			{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/users",
					Query:   map[string]string{"username": username, "exact": "true"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"user_id": "0/id"},
			},
		},
	}
}

// updatedUserFixture creates a user and then sends a partial update, so the
// case that follows can read back what merging did.
func updatedUserFixture() Fixture {
	f := userFixture("gloak-probe-merged-user")
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body:    []byte(`{"firstName":"Grace"}`),
		},
	})
	return f
}

// passwordFixture creates a user, sets a password on it and captures the
// credential's server-minted id.
//
// temporary drives the reset's temporary flag, which is what adds
// UPDATE_PASSWORD to the user's requiredActions. A non-empty label adds a
// userLabel step, so a case can read one back.
func passwordFixture(username string, temporary bool, label string) Fixture {
	f := userFixture(username)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/users/{{user_id}}/reset-password",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"type":"password","value":"s3cret","temporary":` +
				strconv.FormatBool(temporary) + `}`),
		},
	}, Step{
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// A user reaches this fixture with exactly one credential, so index 0
		// is not a bet on list order.
		Capture: map[string]string{"credential_id": "0/id"},
	})
	if label != "" {
		f.Steps = append(f.Steps, Step{
			Request: Request{
				Method:  http.MethodPut,
				Path:    "/admin/realms/master/users/{{user_id}}/credentials/{{credential_id}}/userLabel",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "text/plain"},
				Body:    []byte(label),
			},
		})
	}
	return f
}

// loggedOutUserFixture gives a user a password, logs it in, and then ends the
// session through POST /users/{id}/logout.
//
// The refresh token it captures is the interesting part: a token that verifies
// and whose session is gone answers a different message from a token that was
// never valid.
func loggedOutUserFixture() Fixture {
	f := passwordFixture("gloak-probe-logged-out", false, "")
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "gloak-probe-logged-out",
				"password":   "s3cret",
			},
		},
		Capture: map[string]string{"user_refresh_token": "refresh_token"},
	}, Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/logout",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
	})
	return f
}

// Do performs one request. The recorder's implementation talks to the
// reference container over HTTP; the verifier's serves the in-process handler
// through httptest. Both return the response with its body still readable.
type Do func(*http.Request) (*http.Response, error)

// cookies is what a fixture's steps share so that a login is a session rather
// than a sequence of strangers. Name to value, resent on every step.
//
// It lives here, inside RunFixture, and not on the recorder's http.Client.
// The recorder would get a jar free from http.Client.Jar and the verifier -
// which calls ServeHTTP into an httptest.ResponseRecorder - would get nothing,
// so the two sides would obtain their responses in different ways. That is the
// one thing this suite cannot afford; see the Fixtures doc comment.
//
// It is deliberately **not** a cookie jar's semantics. net/http/cookiejar
// needs a *url.URL per call and a public-suffix list to behave, and the
// fixtures address one host and no case tests scoping - so Path, Domain,
// Secure and Max-Age are all ignored. A cookie cleared with Max-Age=0 and an
// empty value is stored and resent as an empty value, which is what a browser
// that has not yet expired it would send, and what Keycloak accepts: the
// measured login clears KC_RESTART exactly that way.
type cookies map[string]string

// store folds a response's Set-Cookie headers in, keeping the last value for a
// name a response repeats.
func (c cookies) store(h http.Header) {
	for _, raw := range h.Values("Set-Cookie") {
		name, value, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		// Only the value, up to the first attribute separator. Keycloak spells
		// its attributes with no space after the semicolon, so cutting on ";"
		// rather than "; " is what reads AUTH_SESSION_ID=x;Version=1 correctly.
		value, _, _ = strings.Cut(value, ";")
		c[strings.TrimSpace(name)] = value
	}
}

// send puts every stored cookie on a request, in name order so that a golden
// recorded from one run is reproducible by the next.
//
// It writes the Cookie header itself rather than calling
// http.Request.AddCookie. AddCookie sanitises the value, and sanitising drops
// the double quotes Keycloak wraps KC_AUTH_SESSION_HASH's value in - so the
// cookie sent back would not be the cookie received. This project's rule is
// byte for byte wherever a client can observe it, and a request header is
// observable.
func (c cookies) send(r *http.Request) {
	if len(c) == 0 {
		return
	}
	names := make([]string, 0, len(c))
	for name := range c {
		names = append(names, name)
	}
	slices.Sort(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+c[name])
	}
	r.Header.Set("Cookie", strings.Join(pairs, "; "))
}

// Session is what a fixture leaves behind: the values its steps captured, and
// the cookies they collected.
//
// The cookies are here rather than staying inside RunFixture because the
// case's own request is not one of the fixture's steps - it is built and sent
// by the recorder and by the verifier themselves - and a credential POST that
// arrives without the authentication session the login page opened is refused
// with a 400 theme page. That was measured, by recording one.
type Session struct {
	Vars    map[string]string
	Cookies map[string]string
}

// Apply puts the session's cookies on a request. It is what a fixture's last
// step and the case's own request have in common.
func (s *Session) Apply(r *http.Request) {
	if s == nil {
		return
	}
	cookies(s.Cookies).send(r)
}

// RunFixture is Run for the callers that need only the captured values.
func RunFixture(f Fixture, base string, do Do) (map[string]string, error) {
	s, err := Run(f, base, do)
	if err != nil {
		return nil, err
	}
	return s.Vars, nil
}

// Run executes a fixture's steps in order against do, threading the values
// each step captures into the requests that follow, and returns everything
// captured along with the cookies collected on the way.
//
// A step whose response lacks a captured path is an error, not an empty
// string. Substituting an empty token would record whatever Keycloak answers
// for a blank credential: a real response to a request nobody meant to make,
// and one that would look like a measured contract afterwards.
//
// A step whose **status** is not the one it expects is an error too, and that
// is checked before anything is captured: see Step.ExpectStatus and F34.
func Run(f Fixture, base string, do Do) (*Session, error) {
	vars := map[string]string{}
	jar := cookies{}
	for i, s := range f.Steps {
		req, err := buildRequest(base, Expand(s.Request, vars))
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: build request: %w", i, err)
		}
		jar.send(req)
		resp, err := do(req)
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: %w", i, err)
		}
		jar.store(resp.Header)
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: read body: %w", i, err)
		}
		if !acceptedStatus(s.ExpectStatus, resp.StatusCode) {
			return nil, fmt.Errorf("fixture step %d: %s %s: want %s, got %d: %s",
				i, s.Request.Method, s.Request.Path, wantedStatus(s.ExpectStatus), resp.StatusCode, body)
		}
		for name, path := range s.Capture {
			value, err := captureFrom(body, path)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d, body %s)",
					i, name, err, resp.StatusCode, body)
			}
			vars[name] = value
		}
		for name, header := range s.CaptureHeader {
			value, err := captureFromHeader(resp.Header, header)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d)",
					i, name, err, resp.StatusCode)
			}
			vars[name] = value
		}
		for name, what := range s.CaptureForm {
			value, err := captureFromForm(body, what, base)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d)",
					i, name, err, resp.StatusCode)
			}
			vars[name] = value
		}
		for name, param := range s.CaptureQuery {
			value, err := captureFromQuery(resp.Header, param)
			if err != nil {
				return nil, fmt.Errorf("fixture step %d: capture %q: %w (status %d)",
					i, name, err, resp.StatusCode)
			}
			vars[name] = value
		}
	}
	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	return &Session{Vars: vars, Cookies: jar}, nil
}

// acceptedStatus applies a step's ExpectStatus: the listed codes, or any 2xx
// when the step lists none.
func acceptedStatus(expect []int, got int) bool {
	if len(expect) == 0 {
		return got >= 200 && got < 300
	}
	return slices.Contains(expect, got)
}

// wantedStatus spells an ExpectStatus for the failure message. The symptom of a
// silent step appears one request later at the earliest, so the message has to
// carry enough to find the step without re-running anything.
func wantedStatus(expect []int) string {
	if len(expect) == 0 {
		return "2xx"
	}
	out := make([]string, 0, len(expect))
	for _, c := range expect {
		out = append(out, strconv.Itoa(c))
	}
	return strings.Join(out, " or ")
}

// captureFrom pulls one value out of a JSON body by slash-separated path.
//
// A numeric segment indexes an array, matching the path syntax Normalize
// already uses. That is what lets a fixture read an identifier out of a
// filtered list - "0/id" from GET /clients?clientId=account - without the
// endpoint that creates one existing yet.
//
// Unlike the golden comparison passes this unmarshals rather than splicing
// bytes: a captured value is fed back into a request, never written to a
// golden, so key order does not matter here.
func captureFrom(body []byte, path string) (string, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("response is not JSON: %w", err)
	}
	cur := doc
	for seg := range strings.SplitSeq(path, "/") {
		next, err := step(cur, seg)
		if err != nil {
			return "", fmt.Errorf("path %q: %w", path, err)
		}
		cur = next
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("path %q: value is %T, not a string", path, cur)
	}
	return s, nil
}

// step descends one path segment into an object key or an array index.
func step(cur any, seg string) (any, error) {
	switch parent := cur.(type) {
	case map[string]any:
		v, ok := parent[seg]
		if !ok {
			return nil, fmt.Errorf("no key %q", seg)
		}
		return v, nil
	case []any:
		i, err := strconv.Atoi(seg)
		if err != nil {
			return nil, fmt.Errorf("%q is not an array index", seg)
		}
		if i < 0 || i >= len(parent) {
			return nil, fmt.Errorf("index %d is out of range, the array holds %d", i, len(parent))
		}
		return parent[i], nil
	default:
		return nil, fmt.Errorf("%q is not reachable, parent is %T", seg, cur)
	}
}

// captureFromHeader pulls one value out of a response header.
//
// An absent header is an error rather than an empty string, for the same
// reason a missing body capture is: substituting nothing would turn
// ".../clients/{{client_uuid}}" into ".../clients/" and record whatever that
// answers as though somebody had meant to ask for it.
//
// A value that parses as an absolute URL yields its last path segment. That is
// what Location carries and what a case needs, and taking it here rather than
// in every case keeps the base URL - which differs between the recorder and
// the verifier - out of the catalogue.
func captureFromHeader(h http.Header, name string) (string, error) {
	value := h.Get(name)
	if value == "" {
		return "", fmt.Errorf("response has no %s header", name)
	}
	if u, err := url.Parse(value); err == nil && u.IsAbs() {
		if segment := path.Base(u.Path); segment != "." && segment != "/" {
			return segment, nil
		}
	}
	return value, nil
}

// captureFromForm pulls one value out of the first HTML form in a body. what
// is "action" or "input:<name>"; see Step.CaptureForm.
//
// It tokenises rather than matching a regular expression. A regular expression
// over HTML is the classic mistake, and the login form's action is exactly the
// shape that breaks one: it holds five query parameters whose values are
// base64 and can contain any of the characters a naive pattern would use as a
// delimiter, and the whole attribute arrives HTML-escaped, with &amp; between
// the parameters.
func captureFromForm(body []byte, what, base string) (string, error) {
	action, inputs, err := parseFirstForm(body)
	if err != nil {
		return "", err
	}
	if what == "action" {
		// Relative to base, so it can be a following step's Path. The recorder
		// and the verifier answer on different hosts, so an absolute action
		// would send the next step to the wrong server.
		return strings.TrimPrefix(action, base), nil
	}
	name, ok := strings.CutPrefix(what, "input:")
	if !ok {
		return "", fmt.Errorf("%q is not \"action\" or \"input:<name>\"", what)
	}
	value, ok := inputs[name]
	if !ok {
		return "", fmt.Errorf("the form has no input named %q", name)
	}
	return value, nil
}

// parseFirstForm returns the first form's action and its inputs by name.
//
// An absent form is an error rather than an empty action, for the reason
// captureFrom and captureFromHeader already give: substituting nothing would
// send the next step to the base URL and record whatever that answers as
// though somebody had meant to ask for it. On this endpoint the empty action
// is not hypothetical - a rejected authorization request answers a 302 with no
// body at all, and that is the failure this turns into a message.
func parseFirstForm(body []byte) (string, map[string]string, error) {
	z := html.NewTokenizer(bytes.NewReader(body))
	inForm := false
	action := ""
	inputs := map[string]string{}
	for {
		switch z.Next() {
		case html.ErrorToken:
			if !inForm {
				return "", nil, fmt.Errorf("the response has no <form> (%d bytes)", len(body))
			}
			// A form left unclosed at end of input is still a form. Returning
			// what was collected beats failing on a page's stray markup.
			return action, inputs, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "form":
				if inForm {
					continue // a nested form; the first one is the one asked for
				}
				inForm = true
				action = attr(z, "action")
			case "input":
				if inForm {
					if n := attr(z, "name"); n != "" {
						inputs[n] = attr(z, "value")
					}
				}
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "form" && inForm {
				return action, inputs, nil
			}
		}
	}
}

// attr reads one attribute off the tokenizer's current tag. The tokenizer
// unescapes attribute values, so the login form's action comes back with real
// ampersands between its five query parameters rather than &amp;.
func attr(z *html.Tokenizer, want string) string {
	for {
		key, value, more := z.TagAttr()
		if string(key) == want {
			return string(value)
		}
		if !more {
			return ""
		}
	}
}

// captureFromQuery pulls one query parameter out of the Location header.
//
// An absent header or an absent parameter is an error and not an empty string,
// the same rule the other captures follow. A case whose code came back empty
// would exchange nothing at the token endpoint and record the refusal as the
// authorization code grant's contract.
func captureFromQuery(h http.Header, param string) (string, error) {
	location := h.Get("Location")
	if location == "" {
		return "", fmt.Errorf("response has no Location header")
	}
	u, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("Location %q is not a URL: %w", location, err)
	}
	values, ok := u.Query()[param]
	if !ok || len(values) == 0 {
		return "", fmt.Errorf("Location %q has no %q parameter", location, param)
	}
	return values[0], nil
}

// Expand substitutes {{name}} references in a request's path, query, headers,
// form values and body with captured variables. A reference with no matching
// variable is left alone, so a typo shows up in the recorded request rather
// than silently becoming an empty string.
//
// The path is substituted because the admin API addresses objects by UUID
// there - /admin/realms/{realm}/clients/{uuid} - and that UUID is minted by
// the server, so it can never be a literal in a case. Leaving the path out
// was P1's shape, where every captured value went into a header or a form,
// and it recorded a 404 as the contract for the first case that needed it.
//
// It copies every map it touches. One Case is expanded twice - once by the
// recorder with the container's values, once by the verifier with Gloak's -
// so writing through to the catalogue's own maps would let the first run
// poison the second.
func Expand(r Request, vars map[string]string) Request {
	out := r
	out.Path = expandString(r.Path, vars)
	out.Query = expandMap(r.Query, vars)
	out.Headers = expandMap(r.Headers, vars)
	out.Form = expandMap(r.Form, vars)
	if len(r.Body) > 0 {
		out.Body = []byte(expandString(string(r.Body), vars))
	}
	return out
}

func expandString(s string, vars map[string]string) string {
	for name, value := range vars {
		s = strings.ReplaceAll(s, "{{"+name+"}}", value)
	}
	return s
}

func expandMap(in, vars map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = expandString(v, vars)
	}
	return out
}

// ReplaceCaptured masks captured values wherever they appear in a recorded
// response, using the same {{name}} spelling the request used to refer to
// them.
//
// Without it a golden for an endpoint that echoes its input - introspection
// is the obvious one - would hold a live token, and would therefore differ
// from itself on every recording. That is the churn four goldens already
// have, and it is what stops a `make record` diff from being read.
//
// An empty value is skipped: strings.ReplaceAll with an empty old string
// inserts the replacement between every byte of the input.
func ReplaceCaptured(raw []byte, vars map[string]string) []byte {
	for name, value := range vars {
		if value == "" {
			continue
		}
		raw = []byte(strings.ReplaceAll(string(raw), value, "{{"+name+"}}"))
	}
	return raw
}

// ---------------------------------------------------------------------------
// P5 cut B: protocol mappers.
//
// These sit after the last existing helper for the reason the fixtures do: the
// file belongs to another stream this session, and the end of it is the one
// place two branches cannot both edit.
// ---------------------------------------------------------------------------

// The fixed ids the protocol-mapper fixtures use. Scopes continue the
// a5c09e00 series the client-scope cut started, clients the c11e0000 one, and
// the mappers get a series of their own so a case can never name a mapper id
// where a scope id was meant.
const (
	probeMapperScopeID          = "a5c09e00-0000-4000-8000-000000000011"
	probeMapperScopeCreateID    = "a5c09e00-0000-4000-8000-000000000012"
	probeMapperTemplateCreateID = "a5c09e00-0000-4000-8000-000000000013"
	probeMapperScopeUpdateID    = "a5c09e00-0000-4000-8000-000000000014"
	probeMapperTemplateUpdateID = "a5c09e00-0000-4000-8000-000000000015"
	probeMapperScopeDeleteID    = "a5c09e00-0000-4000-8000-000000000016"
	probeMapperTemplateDeleteID = "a5c09e00-0000-4000-8000-000000000017"
	probeMapperScopeAddID       = "a5c09e00-0000-4000-8000-000000000018"
	probeMapperTemplateAddID    = "a5c09e00-0000-4000-8000-000000000019"
	probeMapperScopeDupID       = "a5c09e00-0000-4000-8000-00000000001a"
	probeMapperScopeCreatedID   = "a5c09e00-0000-4000-8000-00000000001b"
	probeMapperScopeUpdatedID   = "a5c09e00-0000-4000-8000-00000000001c"
	probeMapperScopeBatchID     = "a5c09e00-0000-4000-8000-00000000001d"

	probeMapperClientID       = "c11e0000-0000-4000-8000-000000000011"
	probeMapperClientCreateID = "c11e0000-0000-4000-8000-000000000012"
	probeMapperClientUpdateID = "c11e0000-0000-4000-8000-000000000013"
	probeMapperClientDeleteID = "c11e0000-0000-4000-8000-000000000014"
	probeMapperClientAddID    = "c11e0000-0000-4000-8000-000000000015"

	// **A mapper id is unique across the whole realm, not within its
	// container.** Measured: a second client scope created with a mapper id
	// already in use answers 409 `Duplicate resource error` and is not
	// created, and a client created the same way answers
	// `Client <id> already exists` - a message about the client, for a
	// conflict on the mapper's id. So no two fixtures may share one, and the
	// first draft of these did: three fixtures reused one mapper id, three
	// scopes were silently never created, and idempotentCreate swallowed the
	// 409 that said so.
	probeMapperAID            = "9a99e400-0000-4000-8000-000000000001"
	probeMapperBID            = "9a99e400-0000-4000-8000-000000000002"
	probeMapperClientAID      = "9a99e400-0000-4000-8000-000000000003"
	probeMapperClientBID      = "9a99e400-0000-4000-8000-000000000004"
	probeMapperUpdateID       = "9a99e400-0000-4000-8000-000000000005"
	probeMapperTmplUpdateID   = "9a99e400-0000-4000-8000-000000000006"
	probeMapperClientUpdMapID = "9a99e400-0000-4000-8000-000000000007"
	probeMapperDeleteID       = "9a99e400-0000-4000-8000-000000000008"
	probeMapperTmplDeleteID   = "9a99e400-0000-4000-8000-000000000009"
	probeMapperClientDelMapID = "9a99e400-0000-4000-8000-00000000000a"
	probeMapperDupID          = "9a99e400-0000-4000-8000-00000000000b"
	probeMapperCreatedID      = "9a99e400-0000-4000-8000-00000000000c"
	probeMapperBatchID        = "9a99e400-0000-4000-8000-00000000000d"
	probeMapperUpdatedID      = "9a99e400-0000-4000-8000-00000000000e"
	probeMapperBatchDupID     = "9a99e400-0000-4000-8000-00000000000f"
)

// The mapper bodies the fixtures embed, spelled once so a case can quote the
// same configs its fixture sent.
//
// probeReadMappers holds one of each protocol, because the
// `protocol/{protocol}` route filters on the **mapper's** own protocol and a
// scope holding only OIDC mappers cannot tell that route apart from `models`.
// The saml one also carries a `saml-*` provider, which is one of the fifteen
// that do **not** gain a mirrored config key.
func readMappers(idA, idB string) string {
	return `{"id":"` + idA + `","name":"gloak-probe-mapper-a",` +
		`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
		`"config":{"claim.name":"gloak-a","user.attribute":"gloak"}},` +
		`{"id":"` + idB + `","name":"gloak-probe-mapper-b",` +
		`"protocol":"saml","protocolMapper":"saml-user-property-mapper",` +
		`"config":{"attribute.name":"gloak-b"}}`
}

// oneMapper is the body of a single mapper, spelled once so a fixture and the
// case that reads it cannot disagree about the config.
func oneMapper(id, name, claim string) string {
	return `{"id":"` + id + `","name":"` + name + `",` +
		`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
		`"config":{"claim.name":"` + claim + `"}}`
}

// mapperScopeFixture creates one client scope carrying the mappers it is
// given, in a single POST.
//
// One request rather than a create followed by N mapper POSTs, because
// `POST /client-scopes` was measured accepting `protocolMappers` **and keeping
// the ids inside them** - which is not true of its PUT, and is the reason a
// scope's mappers can be set up without capturing anything.
func mapperScopeFixture(id, name, mappers string) Fixture {
	body := `{"id":"` + id + `","name":"` + name + `","protocol":"openid-connect"`
	if mappers != "" {
		body += `,"protocolMappers":[` + mappers + `]`
	}
	body += `}`
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/client-scopes",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(body),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
}

// mapperClientFixture is mapperScopeFixture over a client. `POST /clients`
// takes `protocolMappers` the same way and keeps their ids too.
//
// The client names one of its scope lists so it inherits nothing: a client
// created bare picks up the realm's six defaults and five optionals, and none
// of that is what these cases are about. Naming **either** list suppresses
// inheritance on both - the rule the client-scope cut measured - so one empty
// list is enough.
func mapperClientFixture(uuid, clientID, mappers string) Fixture {
	body := `{"id":"` + uuid + `","clientId":"` + clientID + `","defaultClientScopes":[]`
	if mappers != "" {
		body += `,"protocolMappers":[` + mappers + `]`
	}
	body += `}`
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), {
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(body),
			},
			ExpectStatus: idempotentCreate,
		}},
	}
}

// createdMapperFixture creates two mappers through the dedicated routes so a
// case can read back what a 201 and a 204 do not show: the config keys the
// server added for itself, an empty-valued key it dropped, and
// `consentRequired` coming back **false** for a body that sent `true`.
//
// The first asks for `id.token.claim` and `access.token.claim` and gets
// `introspection.token.claim` and `userinfo.token.claim` appended, because
// `oidc-usermodel-attribute-mapper` is one of the twenty providers that
// mirror both. The second uses `oidc-audience-resolve-mapper`, which mirrors
// **only** the first - so a case reading the pair fails if the rule is
// implemented as one flag rather than two, and fails again if it is
// implemented as "every oidc-* provider".
func createdMapperFixture() Fixture {
	f := mapperScopeFixture(probeMapperScopeCreatedID, "gloak-probe-pm-created", "")
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + probeMapperScopeCreatedID + "/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
			},
			Body: []byte(`{"id":"` + probeMapperCreatedID + `","name":"gloak-probe-mapper-created",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"consentRequired":true,` +
				`"config":{"id.token.claim":"true","access.token.claim":"true","empty":""}}`),
		},
		ExpectStatus: idempotentCreate,
	}, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + probeMapperScopeCreatedID + "/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
			},
			// **Both** sources, not just `access.token.claim`. The first draft
			// sent only that one and two mutations survived: with no
			// `id.token.claim` to mirror, "userinfo follows introspection" and
			// "every oidc-* provider mirrors both" produce exactly the bytes
			// the measured rule produces. Sending both sources is what makes
			// the missing `userinfo.token.claim` visible.
			Body: []byte(`[{"id":"` + probeMapperBatchID + `","name":"gloak-probe-mapper-added",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-audience-resolve-mapper",` +
				`"config":{"id.token.claim":"true","access.token.claim":"true"}}]`),
		},
		ExpectStatus: []int{http.StatusNoContent, http.StatusConflict},
	})
	return f
}

// updatedMapperFixture PUTs over a mapper and exists for the three fields the
// PUT throws away.
//
// The body renames the mapper, moves it to `saml` and sets
// `consentRequired: true`; measured, none of the three lands. Only
// `protocolMapper` and `config` are written, and the config is **replaced**
// rather than merged. The PUT's own 204 says none of that, which is why this
// is a fixture and a read rather than an assertion on the write.
func updatedMapperFixture() Fixture {
	f := mapperScopeFixture(probeMapperScopeUpdatedID, "gloak-probe-pm-updated",
		`{"id":"`+probeMapperUpdatedID+`","name":"gloak-probe-mapper-updated",`+
			`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",`+
			`"config":{"claim.name":"gloak-before","user.attribute":"gloak"}}`)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/client-scopes/" + probeMapperScopeUpdatedID +
				"/protocol-mappers/models/" + probeMapperUpdatedID,
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
			},
			Body: []byte(`{"id":"` + probeMapperUpdatedID + `","name":"gloak-probe-mapper-renamed",` +
				`"protocol":"saml","protocolMapper":"oidc-audience-resolve-mapper",` +
				`"consentRequired":true,"config":{"access.token.claim":"true"}}`),
		},
	})
	return f
}

// batchConflictMapperFixture sends an add-models array whose **second** entry
// duplicates a name the scope already holds, and exists so a case can read the
// listing afterwards.
//
// The point is that the **first** entry is not there. The batch validates
// before it applies, exactly as a composite batch does, and its 409 alone
// cannot tell a rejected batch from a half-applied one.
func batchConflictMapperFixture() Fixture {
	f := mapperScopeFixture(probeMapperScopeBatchID, "gloak-probe-pm-batch",
		oneMapper(probeMapperBatchDupID, "gloak-probe-mapper-dup", "gloak-dup"))
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + probeMapperScopeBatchID + "/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-mapper-first","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{}},` +
				`{"name":"gloak-probe-mapper-dup","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{}}]`),
		},
		ExpectStatus: []int{http.StatusConflict},
	})
	return f
}

// ---------------------------------------------------------------------------
// P5 cut C: scope mappings.
//
// These sit after the last existing helper for the reason the fixtures do: the
// file belongs to another stream this session, and the end of it is the one
// place two branches cannot both edit.
// ---------------------------------------------------------------------------

// The fixed ids the scope-mapping fixtures use. Client scopes continue the
// a5c09e00 series and clients the c11e0000 one, both from the 0x21 block so
// they cannot collide with cut A's or cut B's.
const (
	smScopeID         = "a5c09e00-0000-4000-8000-000000000021"
	smScopeAddID      = "a5c09e00-0000-4000-8000-000000000022"
	smScopeDropID     = "a5c09e00-0000-4000-8000-000000000023"
	smScopeAddRoleID  = "a5c09e00-0000-4000-8000-000000000024"
	smScopeDropRoleID = "a5c09e00-0000-4000-8000-000000000025"

	smTemplateAddID      = "a5c09e00-0000-4000-8000-000000000026"
	smTemplateDropID     = "a5c09e00-0000-4000-8000-000000000027"
	smTemplateAddRoleID  = "a5c09e00-0000-4000-8000-000000000028"
	smTemplateDropRoleID = "a5c09e00-0000-4000-8000-000000000029"

	smCompositeScopeID = "a5c09e00-0000-4000-8000-00000000002a"
	smWrittenScopeID   = "a5c09e00-0000-4000-8000-00000000002b"
	smBatchScopeID     = "a5c09e00-0000-4000-8000-00000000002c"
	smNarrowScopeID    = "a5c09e00-0000-4000-8000-00000000002d"

	// The container clients - the thing whose scope mappings are read.
	smOwnerID         = "c11e0000-0000-4000-8000-000000000021"
	smOwnerAddID      = "c11e0000-0000-4000-8000-000000000022"
	smOwnerDropID     = "c11e0000-0000-4000-8000-000000000023"
	smOwnerAddRoleID  = "c11e0000-0000-4000-8000-000000000024"
	smOwnerDropRoleID = "c11e0000-0000-4000-8000-000000000025"
	smFullScopeID     = "c11e0000-0000-4000-8000-000000000026"

	// The role clients - the client whose roles are mapped. A second client
	// rather than the container itself, because **a client's own roles are in
	// its own scope** without ever being mapped: pointing the two at one client
	// would make every `available` read on this family answer `[]` for a reason
	// that has nothing to do with the mapping under test.
	smRoleClientID          = "c11e0000-0000-4000-8000-000000000031"
	smRoleClientAddID       = "c11e0000-0000-4000-8000-000000000032"
	smRoleClientDropID      = "c11e0000-0000-4000-8000-000000000033"
	smRoleClientAddRoleID   = "c11e0000-0000-4000-8000-000000000034"
	smRoleClientDropRoleID  = "c11e0000-0000-4000-8000-000000000035"
	smRoleClientTAddID      = "c11e0000-0000-4000-8000-000000000036"
	smRoleClientTDropID     = "c11e0000-0000-4000-8000-000000000037"
	smRoleClientTAddRoleID  = "c11e0000-0000-4000-8000-000000000038"
	smRoleClientTDropRoleID = "c11e0000-0000-4000-8000-000000000039"
	smRoleClientOwnerID     = "c11e0000-0000-4000-8000-00000000003a"
	smRoleClientOAddID      = "c11e0000-0000-4000-8000-00000000003b"
	smRoleClientODropID     = "c11e0000-0000-4000-8000-00000000003c"
	smRoleClientOAddRoleID  = "c11e0000-0000-4000-8000-00000000003d"
	smRoleClientODropRoleID = "c11e0000-0000-4000-8000-00000000003e"
	smRoleClientWrittenID   = "c11e0000-0000-4000-8000-00000000003f"
	smRoleClientBatchID     = "c11e0000-0000-4000-8000-000000000040"

	// One realm role name for every fixture in this family. A realm role is
	// realm-wide, so a second name would only add rows to the two
	// `realm/available` goldens without adding an assertion; every fixture
	// creates it idempotently and the scope mappings themselves are per
	// container, so sharing it cannot make two fixtures interfere.
	smRealmRole = "gloak-probe-sm-realm-role"
	// The composite realm role, which only one fixture needs.
	smCompositeRole = "gloak-probe-sm-composite"
	// Two roles per role client: one the fixture may map and one it never
	// does, so `available` has something to answer.
	smClientRole = "gloak-probe-sm-client-role"
	smSpareRole  = "gloak-probe-sm-client-spare"
)

// scopeMappingRoleSteps creates the realm role and the role client this family
// maps, captures the realm role's id, and optionally maps either.
//
// The realm role's id is read back rather than declared: `POST .../roles`
// answers a `Location` ending in the role's **name**, so nothing about a role
// create lets a fixture choose its id - which is the difference between this
// family's setup and cut A's and cut B's.
func scopeMappingRoleSteps(prefix, roleClientUUID, roleClientID string, mapRealm, mapClient bool) []Step {
	steps := []Step{
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + smRealmRole + `"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/" + smRealmRole,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"sm_realm_role_id": "id"},
		},
		{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/clients",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				// defaultClientScopes suppresses inheritance on **both** lists,
				// measured, which keeps this client out of the client-scope
				// goldens' way.
				Body: []byte(`{"id":"` + roleClientUUID + `","clientId":"` + roleClientID +
					`","defaultClientScopes":[]}`),
			},
			ExpectStatus: idempotentCreate,
		},
	}
	for _, name := range []string{smClientRole, smSpareRole} {
		steps = append(steps, Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/clients/" + roleClientUUID + "/roles",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`{"name":"` + name + `"}`),
			},
			ExpectStatus: idempotentCreate,
		})
	}
	if mapRealm {
		steps = append(steps, Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   prefix + "/scope-mappings/realm",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
			},
		})
	}
	if mapClient {
		steps = append(steps, Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   prefix + "/scope-mappings/clients/" + roleClientUUID,
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				// **By name, with no id.** The client write resolves by name
				// and ignores the id; the realm write above does the opposite.
				Body: []byte(`[{"name":"` + smClientRole + `"}]`),
			},
		})
	}
	return steps
}

// scopeMappingScopeFixture is the client-scope container: a scope, a role
// client with two roles, a realm role, and whichever mappings the case needs.
func scopeMappingScopeFixture(scopeID, scopeName, roleClientUUID, roleClientID string, mapRealm, mapClient bool) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: append([]Step{adminTokenStep(), clientScopeStep(scopeID, scopeName)},
			scopeMappingRoleSteps("/admin/realms/master/client-scopes/"+scopeID,
				roleClientUUID, roleClientID, mapRealm, mapClient)...),
	}
}

// scopeMappingClientFixture is the same over a client container.
//
// **fullScopeAllowed is off**, which is the whole reason the container's
// mappings are observable: a client with the flag set has every role in scope
// already, so its `composite` reads answer the realm rather than what it
// mapped. Four of the six bootstrapped clients have it off and two have it on,
// and scope-mappings-full-scope is the other side of that.
func scopeMappingClientFixture(ownerUUID, ownerID, roleClientUUID, roleClientID string, mapRealm, mapClient bool) Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: append([]Step{adminTokenStep(), scopeMappingOwnerStep(ownerUUID, ownerID, false)},
			scopeMappingRoleSteps("/admin/realms/master/clients/"+ownerUUID,
				roleClientUUID, roleClientID, mapRealm, mapClient)...),
	}
}

func scopeMappingOwnerStep(uuid, clientID string, fullScope bool) Step {
	full := "false"
	if fullScope {
		full = "true"
	}
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/clients",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"id":"` + uuid + `","clientId":"` + clientID +
				`","fullScopeAllowed":` + full + `,"defaultClientScopes":[]}`),
		},
		ExpectStatus: idempotentCreate,
	}
}

// scopeMappingFullScopeFixture creates a client with fullScopeAllowed set and
// **maps nothing**, so the case reading its composite is reading the flag
// rather than a mapping.
func scopeMappingFullScopeFixture() Fixture {
	return Fixture{
		State: "bootstrap",
		Steps: []Step{adminTokenStep(), scopeMappingOwnerStep(smFullScopeID, "gloak-probe-sm-full", true)},
	}
}

// scopeMappingCompositeFixture maps a **composite** realm role and nothing
// else, which is what makes `composite` and `available` disagree: the child is
// in the expansion and still in the available list, because available
// subtracts what is mapped **directly**.
func scopeMappingCompositeFixture() Fixture {
	f := scopeMappingScopeFixture(smCompositeScopeID, "gloak-probe-sm-comp",
		smRoleClientID, "gloak-probe-sm-rc", false, false)
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + smCompositeRole + `"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/" + smCompositeRole,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"sm_composite_role_id": "id"},
		},
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/roles-by-id/{{sm_composite_role_id}}/composites",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`[{"id":"{{sm_realm_role_id}}","name":"` + smRealmRole + `"}]`),
			},
		},
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/client-scopes/" + smCompositeScopeID + "/scope-mappings/realm",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`[{"id":"{{sm_composite_role_id}}"}]`),
			},
		},
	)
	return f
}

// scopeMappingWrittenFixture posts a **client** role to
// `.../scope-mappings/realm` by id, with no name at all, so the case that reads
// the combined view afterwards is what says where it landed.
//
// The write's own 204 says nothing. Three implementations answer it: one that
// refuses a client role on the realm path, one that stores it under the realm
// half, and the measured one that stores it under the client's. Only this read
// tells them apart.
func scopeMappingWrittenFixture() Fixture {
	f := scopeMappingScopeFixture(smWrittenScopeID, "gloak-probe-sm-written",
		smRoleClientWrittenID, "gloak-probe-sm-rc-written", false, false)
	f.Steps = append(f.Steps,
		Step{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients/" + smRoleClientWrittenID + "/roles/" + smClientRole,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"sm_client_role_id": "id"},
		},
		Step{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/client-scopes/" + smWrittenScopeID + "/scope-mappings/realm",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`[{"id":"{{sm_client_role_id}}"}]`),
			},
		},
	)
	return f
}

// scopeMappingBatchRefusedFixture sends a batch of one role the caller may map
// and one it may not, as a manage-clients caller, so the case reading the
// container afterwards can say **neither** was written.
//
// The 403 alone cannot tell a rejected batch from a half-applied one, which is
// the same thing the protocol mappers' add-models conflict case pins.
func scopeMappingBatchRefusedFixture() Fixture {
	f := scopeMappingScopeFixture(smBatchScopeID, "gloak-probe-sm-batch",
		smRoleClientBatchID, "gloak-probe-sm-rc-batch", false, false)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/" + smRoleClientBatchID + "/roles/" + smClientRole,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		Capture: map[string]string{"sm_client_role_id": "id"},
	})
	f.Steps = append(f.Steps, scopeMappingCallerSteps("gloak-probe-caller-sm-batch")...)
	f.Steps = append(f.Steps, Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + smBatchScopeID + "/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{caller_token}}", "Content-Type": "application/json",
			},
			// The allowed one **first**. A loop that applied as it validated
			// would write it and then refuse, which is exactly what the case
			// reading the container afterwards rules out.
			Body: []byte(`[{"id":"{{sm_client_role_id}}"},{"id":"{{sm_realm_role_id}}"}]`),
		},
		ExpectStatus: []int{http.StatusForbidden},
	})
	return f
}

// scopeMappingNarrowCallerFixture is a scope, a realm role and a
// manage-clients caller in one fixture, for the cases that need all three.
func scopeMappingNarrowCallerFixture() Fixture {
	f := scopeMappingScopeFixture(smNarrowScopeID, "gloak-probe-sm-narrow",
		smRoleClientID, "gloak-probe-sm-rc", false, false)
	f.Steps = append(f.Steps, scopeMappingCallerSteps("gloak-probe-caller-sm-narrow")...)
	return f
}

// scopeMappingCallerSteps adds a user holding manage-clients and nothing else,
// and captures its token as {{caller_token}}.
//
// callerFixture next door builds the whole fixture rather than a step list, and
// these cases need the caller **and** a container, so the steps are rebuilt
// here.
//
// The password arrives through `PUT .../reset-password` rather than an inline
// `credentials` array on the create, which is passwordFixture's shape and is
// **not** cosmetic: the inline array works on Keycloak and Gloak ignores it, so
// a fixture written the short way records against the reference container and
// then fails to log in against the handler. Found by writing it the short way.
func scopeMappingCallerSteps(username string) []Step {
	return []Step{
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/users",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"username":"` + username + `","enabled":true}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/users",
				Query:   map[string]string{"username": username, "exact": "true"},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"caller_user_id": "0/id"},
		},
		{
			Request: Request{
				Method:  http.MethodPut,
				Path:    "/admin/realms/master/users/{{caller_user_id}}/reset-password",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"type":"password","value":"probe-pass","temporary":false}`),
			},
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients",
				Query:   map[string]string{"clientId": "master-realm"},
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"admin_client_uuid": "0/id"},
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/clients/{{admin_client_uuid}}/roles/manage-clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"caller_role_id": "id"},
		},
		{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/admin/realms/master/users/{{caller_user_id}}/role-mappings/clients/{{admin_client_uuid}}",
				Headers: map[string]string{
					"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json",
				},
				Body: []byte(`[{"id":"{{caller_role_id}}","name":"manage-clients"}]`),
			},
		},
		{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password", "client_id": "admin-cli",
					"username": username, "password": "probe-pass",
				},
			},
			Capture: map[string]string{"caller_token": "access_token"},
		},
	}
}
