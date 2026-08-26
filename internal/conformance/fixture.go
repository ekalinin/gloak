package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
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
}

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
			},
			{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/clients",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`{"clientId":"gloak-probe-shared-client"}`),
				},
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

// RunFixture executes a fixture's steps in order against do, threading the
// values each step captures into the requests that follow, and returns
// everything captured.
//
// A step whose response lacks a captured path is an error, not an empty
// string. Substituting an empty token would record whatever Keycloak answers
// for a blank credential: a real response to a request nobody meant to make,
// and one that would look like a measured contract afterwards.
func RunFixture(f Fixture, base string, do Do) (map[string]string, error) {
	vars := map[string]string{}
	for i, s := range f.Steps {
		req, err := buildRequest(base, Expand(s.Request, vars))
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: build request: %w", i, err)
		}
		resp, err := do(req)
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: %w", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("fixture step %d: read body: %w", i, err)
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
	}
	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	return vars, nil
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
