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

// accountBrokerStep registers one identity provider in accountBrokerRealm.
func accountBrokerStep(alias, providerID, displayName string, enabled bool) Step {
	body := `{"alias":"` + alias + `","providerId":"` + providerID + `","enabled":` +
		strconv.FormatBool(enabled) + `,`
	if displayName != "" {
		body += `"displayName":"` + displayName + `",`
	}
	body += `"config":{"clientId":"gloak-probe","clientSecret":"gloak-probe",` +
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
// A listing sorted by display name puts the first row last, one that omits an
// empty display name loses a key on the third, one that reads `social` off
// anything but the provider id gets the second wrong, and one that does not
// filter on `enabled` gains a fourth row. Four providers, four separate
// refutations, one body.
func accountBrokerFixture() Fixture {
	const username = "gloak-probe-account-broker-user"
	return Fixture{State: "bootstrap", Steps: []Step{
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
		accountLoginStep(accountBrokerRealm, username),
	}}
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
	const clientID = "gloak-probe-account-narrow"
	const username = "gloak-probe-account-narrow-user"
	return Fixture{State: "bootstrap", Steps: []Step{
		adminTokenStep(),
		{
			Request: Request{
				Method:  http.MethodPost,
				Path:    "/admin/realms/master/clients",
				Headers: map[string]string{"Authorization": "Bearer {{access_token}}", "Content-Type": "application/json"},
				Body: []byte(`{"clientId":"` + clientID + `","enabled":true,"publicClient":true,` +
					`"standardFlowEnabled":false,"directAccessGrantsEnabled":true,"fullScopeAllowed":false}`),
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
