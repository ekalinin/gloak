package conformance

import (
	"net/http"
	"strconv"
)

// The account API's fixtures.
//
// They live in a file of their own and their entries in Fixtures do not,
// because the map is one literal. Everything a reader needs about them is
// here.
//
// The account API is the third API on this server and the first whose caller
// is an ordinary user rather than an administrator, so none of the token steps
// in fixture.go can be reused: every one of them mints the bootstrapped
// administrator's token, and the account API's gate is a question about the
// **subject's** roles on the realm's `account` client.

// accountProbePassword is what every account fixture's user logs in with. One
// constant for requiredActionPassword's reason - a case reading a literal the
// fixture did not write is how a login stops working when only one of the two
// is edited - and a second constant rather than that one because these users
// are created by a different body.
const accountProbePassword = "gloak-probe-account-pw"

// accountProbeUser is the ordinary user most account cases speak as: created
// with nothing but a username and a password, which is enough in **master**
// and would not be in a created realm - a password grant there needs an email,
// a firstName and a lastName, which is why accountBrokerFixture's user carries
// all three and this one carries none.
const accountProbeUser = "gloak-probe-account-user"

// accountBrokerRealm is the realm accountBrokerFixture builds. The brokers live
// there rather than in master because four identity providers in master would
// appear in every golden that enumerates the realm's own.
const accountBrokerRealm = "gloak-probe-account-brokers"

// accountUserBody is a user created with an inline credential, the shortest
// route from nothing to a user who can complete a password grant. profile adds
// the three fields a created realm insists on and master does not ask for.
func accountUserBody(username string, profile bool) string {
	body := `{"username":"` + username + `","enabled":true,`
	if profile {
		body += `"email":"` + username + `@example.com","firstName":"Ada","lastName":"Lovelace",`
	}
	return body + `"credentials":[{"type":"password","value":"` + accountProbePassword +
		`","temporary":false}]}`
}

// accountLoginStep is the password grant that turns a created user into the
// bearer token an account case sends, on admin-cli in the named realm.
//
// **admin-cli is a measurement here rather than a convenience.** It is the one
// bootstrapped client with direct grants, and it is also a lightweight client
// whose access token carries no `aud` claim at all - and the account API
// accepts it. accountScopeFilteredFixture yields a token that also carries no
// `aud` and is refused. The two together are what say the audience gate reads
// the token's granted roles rather than the claim, so the catalogue needs both
// and neither is redundant.
//
// It captures **user_token** rather than access_token on purpose: every one of
// these fixtures already holds an administrator's access_token from the steps
// that created the user, and a case sending the wrong one of the two would be
// a silent 200 measuring the administrator's own account.
func accountLoginStep(realm, username string) Step {
	return Step{
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/" + realm + "/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   username,
				"password":   accountProbePassword,
			},
		},
		Capture: map[string]string{"user_token": "access_token"},
	}
}

// accountCreateUserStep creates one account-API user in master, idempotently.
func accountCreateUserStep(username string) Step {
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body:    []byte(accountUserBody(username, false)),
		},
		ExpectStatus: idempotentCreate,
	}
}

// accountUserIDStep captures the created user's id by looking it up rather
// than reading Location, so a fixture more than one case names still reaches
// the state it promises when its create answers 409.
func accountUserIDStep(username string) Step {
	return Step{
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"username": username, "exact": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		Capture: map[string]string{"user_id": "0/id"},
	}
}

// accountUserFixture is the plain case: a user carrying the realm's default
// roles, which reach three of the eight account roles through
// default-roles-master's composite closure, and its token.
func accountUserFixture(username string) Fixture {
	return Fixture{State: "bootstrap", Steps: []Step{
		adminTokenStep(),
		accountCreateUserStep(username),
		accountLoginStep("master", username),
	}}
}

// accountRoleFixture is accountUserFixture with the realm's default roles
// **taken away** and at most one account role put back.
//
// It is what makes the account API's guard testable at all. Every account role
// an ordinary user has arrives through one composite - default-roles-master
// over manage-account, manage-account-links and view-profile - so a catalogue
// built on users created the ordinary way holds exactly one caller shape, and
// a guard that admitted every authenticated subject would pass all of it. That
// is AGENTS.md's "a set of assertions an incorrect implementation satisfies
// entirely", and this fixture is the answer to it.
//
// role empty strips and puts nothing back, which is the audience gate's own
// input: a subject holding no account role at all is 401 rather than 403.
func accountRoleFixture(username, role string) Fixture {
	steps := []Step{
		adminTokenStep(),
		accountCreateUserStep(username),
		accountUserIDStep(username),
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/default-roles-master",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"default_roles_id": "id"},
		},
		{
			// Both keys are sent: the id is what the write reads and the name
			// is what a reader of the fixture needs to see.
			Request: Request{
				Method:  http.MethodDelete,
				Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`[{"id":"{{default_roles_id}}","name":"default-roles-master"}]`),
			},
		},
	}
	if role != "" {
		steps = append(steps,
			Step{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients",
					Query:   map[string]string{"clientId": "account"},
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"account_uuid": "0/id"},
			},
			Step{
				Request: Request{
					Method:  http.MethodGet,
					Path:    "/admin/realms/master/clients/{{account_uuid}}/roles/" + role,
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
				},
				Capture: map[string]string{"account_role_id": "id"},
			},
			Step{
				Request: Request{
					Method:  http.MethodPost,
					Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{account_uuid}}",
					Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
					Body:    []byte(`[{"id":"{{account_role_id}}","name":"` + role + `"}]`),
				},
			},
		)
	}
	return Fixture{State: "bootstrap", Steps: append(steps, accountLoginStep("master", username))}
}

// accountCollidingRoleName is the account role name the collision fixture puts
// on a **realm** role. It is deliberately not a gloak-probe- name, because a
// name the account API would not recognise measures nothing, and it is declared
// in namedOutsideTheConvention with the window argument that makes it safe.
const accountCollidingRoleName = "view-profile"

// accountRealmRoleCollisionFixture gives a user a **realm** role named after an
// account role, and no account role at all.
//
// It is internal/admin's F32 asked of this API before the answer can be got
// wrong here: a caller who can create a role can name it anything, so a gate
// that asked "does this subject hold a role called view-profile" would hand the
// whole account API to whoever minted one. Keycloak refuses it - measured,
// **401**, on all three of /groups, /linked-accounts and /supportedLocales -
// and accountGrants reduces by container for exactly this reason.
//
// It exists because the mutation that drops the container test **survived**
// every other case in the chapter: no other fixture's user holds a role whose
// name collides with an account role, so widening the grants to any container
// changed no byte of any golden.
func accountRealmRoleCollisionFixture() Fixture {
	const username = "gloak-probe-account-collide"
	return Fixture{State: "bootstrap", Steps: []Step{
		adminTokenStep(),
		accountCreateUserStep(username),
		accountUserIDStep(username),
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/default-roles-master",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"default_roles_id": "id"},
		},
		{
			Request: Request{
				Method:  http.MethodDelete,
				Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`[{"id":"{{default_roles_id}}","name":"default-roles-master"}]`),
			},
		},
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/roles",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + accountCollidingRoleName + `"}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodGet,
				Path:    "/admin/realms/master/roles/" + accountCollidingRoleName,
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			},
			Capture: map[string]string{"colliding_role_id": "id"},
		},
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body: []byte(`[{"id":"{{colliding_role_id}}","name":"` +
					accountCollidingRoleName + `"}]`),
			},
		},
		accountLoginStep("master", username),
	}}
}

// accountDisabledUserFixture logs a user in and **then** disables it, so the
// case's own request carries a token that verifies, names a live session and
// belongs to an account nobody may use any more.
//
// The order is the fixture: disabling first would make the password grant fail
// and there would be no token to send. It exists because the mutation that
// removes the `!user.Enabled` check survived the whole chapter - every other
// case's user is enabled throughout - and Keycloak answers this 401.
func accountDisabledUserFixture() Fixture {
	const username = "gloak-probe-account-disabled"
	return Fixture{State: "bootstrap", Steps: []Step{
		adminTokenStep(),
		accountCreateUserStep(username),
		accountUserIDStep(username),
		accountLoginStep("master", username),
		{
			Request: Request{
				Method:  http.MethodPut,
				Path:    "/admin/realms/master/users/{{user_id}}",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"enabled":false}`),
			},
		},
	}}
}

// accountGroupFixture puts one user in one group and logs it in. child asks for
// the group to be a **child** of a group the user is not in, which is the input
// that separates the two readings of "the groups I am in".
//
// Its group create reads Location rather than searching, so each of these is
// named by exactly one case: `search` on the group listing returns a matching
// descendant nested inside its top-level ancestor, so a lookup by name cannot
// address the child at all.
func accountGroupFixture(username string, child bool) Fixture {
	steps := []Step{
		adminTokenStep(),
		accountCreateUserStep(username),
		accountUserIDStep(username),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/groups",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + username + `-group"}`),
			},
			CaptureHeader: map[string]string{"group_id": "Location"},
		},
	}
	if child {
		steps = append(steps, Step{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/groups/{{group_id}}/children",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body:    []byte(`{"name":"` + username + `-child"}`),
			},
			// The child create's Location is /groups/<child uuid> and **not**
			// under /children, which is measured and which is what lets one
			// capture name serve both shapes of this fixture.
			CaptureHeader: map[string]string{"group_id": "Location"},
		})
	}
	steps = append(steps, Step{
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/users/{{user_id}}/groups/{{group_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
	})
	return Fixture{State: "bootstrap", Steps: append(steps, accountLoginStep("master", username))}
}

// accountUnlistedBrokerStep registers one of the two provider types the
// linked-accounts listing leaves out even when the provider is enabled.
//
// It exists because the mutation that deletes the unlistedProviderIDs filter
// **survived the whole chapter**: every provider the broker fixture created was
// one the listing shows, so removing the filter changed no byte of any golden.
// That is AGENTS.md's "a set of inputs an incorrect implementation satisfies
// entirely", and two rows are the answer to it - one per entry in the table, so
// that deleting either entry alone is caught rather than only deleting both.
//
// Both are measured creatable and measured absent: `POST` answers 201, the
// realm's own identity provider listing shows all three, and this listing shows
// only the `oidc` one. `jwt-authorization-grant` needs an `issuer` or the create
// is a 400 `Issuer is required`, which is why the config is a parameter here and
// fixed in accountBrokerStep.
func accountUnlistedBrokerStep(alias, providerID, config string) Step {
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/" + accountBrokerRealm + "/identity-provider/instances",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body: []byte(`{"alias":"` + alias + `","providerId":"` + providerID +
				`","enabled":true,"config":{` + config + `}}`),
		},
		ExpectStatus: idempotentCreate,
	}
}

// accountBrokerStep registers one identity provider in accountBrokerRealm.
func accountBrokerStep(alias, providerID, displayName string, enabled bool) Step {
	body := `{"alias":"` + alias + `","providerId":"` + providerID + `","enabled":` +
		strconv.FormatBool(enabled) + `,`
	if displayName != "" {
		body += `"displayName":"` + displayName + `",`
	}
	// The two `clientId`s here are the broker's credentials **at the remote
	// provider** and create no object on this server at all - but
	// TestEveryCreatedObjectCarriesTheProbePrefix reads one object per JSON
	// object and cannot tell the two meanings of the key apart. Naming them
	// inside the convention is a smaller answer than an exemption, and it costs
	// nothing: no golden holds an identity provider's config.
	body += `"config":{"clientId":"gloak-probe-broker-client","clientSecret":"gloak-probe-broker-secret",` +
		`"authorizationUrl":"http://localhost:1/auth","tokenUrl":"http://localhost:1/token"}}`
	return Step{
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/" + accountBrokerRealm + "/identity-provider/instances",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
			Body:    []byte(body),
		},
		ExpectStatus: idempotentCreate,
	}
}

// accountBrokerFixture is a realm holding four identity providers chosen so
// that no wrong implementation of the linked-accounts listing passes:
//
//	zzz-probe-broker    oidc, displayName "AAA First"  sorts last by alias and
//	                                                   first by display name
//	gloak-probe-social  google                         the social flag, true
//	gloak-probe-oidc    oidc, no displayName           the alias fallback
//	gloak-probe-off     oidc, disabled                 absent from the listing
//
//	gloak-probe-k8s       kubernetes               enabled and never listed
//	gloak-probe-jwt-grant jwt-authorization-grant  enabled and never listed
//
// A listing sorted by display name puts the first row last, one that omits an
// empty display name loses a key on the third, one that reads `social` off
// anything but the provider id gets the second wrong, one that does not filter
// on `enabled` gains a fourth row, and one that drops unlistedProviderIDs gains
// two more. Six providers, six separate refutations, one body.
//
// The last two were added on 2026-09-08 because the mutation deleting the
// unlisted filter survived without them, and there is one per entry in that
// table so that deleting either entry alone is caught. They contribute **no
// row** to the golden, which is exactly what they are there to assert.
//
// **They are behind a flag because their create is not idempotent and the
// others are.** A second POST creating `kubernetes` under a name the realm
// already holds answers `400 {"errorMessage":"Issuer URL already used for IDP
// '<alias>'"}` rather than the 409 every other create here answers: a
// kubernetes provider's issuer is a server-filled constant,
// `https://kubernetes.default.svc.cluster.local`, and the **issuer-uniqueness
// check runs before the alias check**, so the repeat collides with itself.
//
// Widening the step's ExpectStatus to accept 400 was the smaller diff and is
// the wrong one: `Issuer is required` is a 400 too, so a step that accepted it
// would pass while creating nothing, and the mutation these two rows exist to
// kill would survive again with the fixture looking green. Instead the pair
// lives in a fixture named by **exactly one case**, so it is created once and
// the 400 is never reached. If a second case ever names it, that case's own
// recording is where this comment will be needed.
func accountBrokerFixture(unlisted bool) Fixture {
	const username = "gloak-probe-account-broker-user"
	steps := []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				// The four locales are **deliberately unsorted and the flag is
				// deliberately off**. GET .../account/supportedLocales answers
				// this list in stored order whether internationalizationEnabled
				// is set or not, measured both ways, so a realm carrying
				// `de, en, fr` with the flag on could not tell a sorted answer
				// from a stored one and a realm with the flag off could not tell
				// a gated answer from an ungated one. This body separates both.
				Body: []byte(`{"realm":"` + accountBrokerRealm + `","enabled":true,` +
					`"internationalizationEnabled":false,` +
					`"supportedLocales":["zz","de","en","fr"]}`),
			},
			ExpectStatus: idempotentCreate,
		},
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/" + accountBrokerRealm + "/users",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				// The three profile fields are not decoration: a password grant
				// in a realm created through POST /admin/realms is refused
				// `Account is not fully set up` without them, and the refusal
				// names neither the realm nor the profile.
				Body: []byte(accountUserBody(username, true)),
			},
			ExpectStatus: idempotentCreate,
		},
		accountBrokerStep("zzz-probe-broker", "oidc", "AAA First", true),
		accountBrokerStep("gloak-probe-social", "google", "", true),
		accountBrokerStep("gloak-probe-oidc", "oidc", "", true),
		accountBrokerStep("gloak-probe-off", "oidc", "", false),
	}
	if unlisted {
		// The two the listing omits although they are enabled. They add no row
		// to the golden - that is the measurement - and they are what makes the
		// omission falsifiable.
		steps = append(steps,
			accountUnlistedBrokerStep("gloak-probe-k8s", "kubernetes", ""),
			accountUnlistedBrokerStep("gloak-probe-jwt-grant", "jwt-authorization-grant",
				`"issuer":"http://localhost:1/"`),
		)
	}
	return Fixture{State: "bootstrap", Steps: append(steps, accountLoginStep(accountBrokerRealm, username))}
}

// accountScopeFilteredFixture logs a fully-privileged user in through a client
// whose fullScopeAllowed is off and which has no scope mappings, so the account
// roles the user really holds are filtered out of the token's scope.
//
// It is the second half of the pair accountLoginStep describes. The token it
// yields carries **no `aud` claim**, exactly like admin-cli's, and is refused
// where admin-cli's is accepted - so no implementation that inspects the claim
// can tell them apart, and one that inspects the granted roles gets both right.
func accountScopeFilteredFixture() Fixture {
	return accountNarrowClientFixture("gloak-probe-account-narrow", "")
}

// accountScopeFilteredLightweightFixture is the same client with
// client.use.lightweight.access.token.enabled, and it is **the pair that says
// this gate cannot be reading a claim**.
//
// admin-cli is lightweight and has fullScopeAllowed on; this client is
// lightweight and has it off. Their access tokens carry the identical eight
// keys - exp, iat, jti, iss, typ, azp, sid, scope - with no aud, no
// realm_access and no resource_access between them, so there is no byte in
// either token an implementation could read to tell them apart. Measured
// 2026-09-08 on a live 26.7.1 with one user holding every account role through
// default-roles: **200 for the one with the flag on, 401 for the one with it
// off.**
//
// The chapter's existing pair - admin-cli accepted, gloak-probe-account-narrow
// refused - is one measurement short of this. Those two clients also differ in
// the lightweight attribute, so a gate reading `aud` could have been right
// about the second and wrong about the first for a reason nothing separated.
// This one holds every other variable still.
func accountScopeFilteredLightweightFixture() Fixture {
	return accountNarrowClientFixture("gloak-probe-account-narrow-lw",
		`,"attributes":{"client.use.lightweight.access.token.enabled":"true"}`)
}

// accountNarrowClientFixture is what the two share: a fully-privileged user
// logged in through a client with fullScopeAllowed off and no scope mappings,
// so the account roles the user really holds are filtered out of the token's
// scope. `extra` is spliced into the client's create body.
func accountNarrowClientFixture(clientID, extra string) Fixture {
	username := clientID + "-user"
	return Fixture{State: "bootstrap", Steps: []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body: []byte(`{"clientId":"` + clientID + `","enabled":true,"publicClient":true,` +
					`"standardFlowEnabled":false,"directAccessGrantsEnabled":true,` +
					`"fullScopeAllowed":false` + extra + `}`),
			},
			ExpectStatus: idempotentCreate,
		},
		accountCreateUserStep(username),
		{
			Request: Request{
				Method: http.MethodPost,
				Path:   "/realms/master/protocol/openid-connect/token",
				Form: map[string]string{
					"grant_type": "password",
					"client_id":  clientID,
					"username":   username,
					"password":   accountProbePassword,
				},
			},
			Capture: map[string]string{"user_token": "access_token"},
		},
	}}
}
