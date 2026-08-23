package conformance

import "net/http"

// adminCases is the Admin REST API surface. Unlike the protocol chapters, its
// denominator comes from Keycloak's own OpenAPI description rather than from
// this list, so every case here names the operation it exercises - see
// Case.Operation and TestAdminCasesNameARealOperation.
//
// Several cases may exercise one operation: a success, a 404, a 403. The
// coverage report counts distinct operations, so writing more of them raises
// confidence without inflating the meter.
var adminCases = []Case{
	// --- Authentication ---
	// Measured 2026-08-22, recorded in the "Admin API rejection shapes"
	// section of docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	//
	// These are a different family from the protocol side's. The admin API
	// answers shape 2 with the generic HTTP-status body and carries no
	// WWW-Authenticate at all, where userinfo carries its whole error in that
	// header. Assuming the two matched would have been wrong in every detail.
	{
		ID: "admin/users/list-unauthenticated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: these pin a rejection, not that the listing works. The
		// success path is a stub until the representation is recorded, and an
		// operation nobody serves must not count towards parity.
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/master/users",
		},
		AssertHeaders: []string{"Content-Type"},
		// Pinned as absent because the protocol side's 401 does carry it, and
		// an implementation that reused userinfo's rejection would send one
		// here too.
		AssertAbsentHeaders: []string{"WWW-Authenticate"},
	},
	{
		// Measured to be byte-identical to the case above. Keycloak does not
		// distinguish "no credentials" from "bad credentials" on this API,
		// unlike userinfo, which does. Kept as its own case precisely because
		// the two being identical is the finding.
		ID: "admin/users/list-garbage-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: these pin a rejection, not that the listing works. The
		// success path is a stub until the representation is recorded, and an
		// operation nobody serves must not count towards parity.
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Headers: map[string]string{"Authorization": "Bearer not-a-token"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"WWW-Authenticate"},
	},
	// --- Clients ---
	{
		ID: "admin/clients/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get clients belonging to the realm",
			Retrieved: "2026-08-22",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/master/clients",
			// Filtered to one client on purpose. Two of the six bootstrapped
			// clients carry protocolMappers, whose model is P5, so the
			// unfiltered list cannot be reproduced yet - see
			// admin/clients/list-all below. The filter is the same operation
			// and is how a caller finds a client's server-minted UUID.
			Query:   map[string]string{"clientId": "account"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		// The internal UUID is minted at bootstrap, so it differs between the
		// reference container and Gloak on every run. The field's presence and
		// position stay asserted.
		// The two scope-name lists come back in different orders on different
		// container starts - measured across two independent recordings, where
		// profile/roles and organization/offline_access swapped. Same family as
		// scopes_supported and the token response's scope: a Java set with no
		// fixed iteration order. Membership stays asserted.
		Unordered: []string{"*/defaultClientScopes", "*/optionalClientScopes"},
		Volatile:  []string{"*/id"},
		// See Case.UnorderedKeys: attributes is a Java Map serialised in hash
		// order, which Go cannot reproduce without emulating java.util.HashMap.
		UnorderedKeys: []string{"*/attributes"},
	},
	{
		// The unfiltered list, which cannot pass yet: account-console and
		// security-admin-console carry protocolMappers, and protocol mappers
		// are P5. Recorded so the contract is in the repository and so the
		// moment P5 makes it reproducible, the Recorded alarm says so.
		ID: "admin/clients/list-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get clients belonging to the realm",
			Retrieved: "2026-08-22",
		},
		Status: Recorded,
		Reason: "two bootstrapped clients carry protocolMappers, which is P5",
		// No Operation: admin/clients/list already claims this one.
		//
		// The one case in the catalogue that enumerates the realm, so it has
		// to be recorded before any fixture creates a client. See
		// Case.PristineRealm.
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		Unordered:     []string{"*/defaultClientScopes", "*/optionalClientScopes"},
		Volatile:      []string{"*/id", "*/protocolMappers/*/id"},
		UnorderedKeys: []string{"*/attributes"},
	},
	{
		ID: "admin/clients/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get representation of the client",
			Retrieved: "2026-08-22",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}",
		Fixture:   "admin-token-account-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		Unordered:     []string{"defaultClientScopes", "optionalClientScopes"},
		Volatile:      []string{"id"},
		UnorderedKeys: []string{"attributes"},
	},
	{
		ID: "admin/clients/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get representation of the client",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that reading works.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	{
		ID: "admin/clients/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: create a new client",
			Retrieved: "2026-08-22",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"clientId":"gloak-probe-create","enabled":true}`),
		},
		// Measured: 201 with an empty body, no Content-Type, and the new
		// object's absolute URL in Location. The UUID in it is minted per
		// request, so the value is masked while its presence stays asserted.
		AssertHeaders:       []string{"Location"},
		VolatileHeaders:     []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/clients/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: create a new client, conflicting clientId",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that create works.
		Fixture: "admin-token-client-to-duplicate",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"clientId":"gloak-probe-duplicate","enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/clients/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: update the client",
			Retrieved: "2026-08-22",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}",
		Fixture:   "admin-token-client-to-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"clientId":"gloak-probe-update","enabled":false,"description":"renamed"}`),
		},
	},
	{
		ID: "admin/clients/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: delete the client",
			Retrieved: "2026-08-22",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}",
		Fixture:   "admin-token-client-to-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
	},
	{
		ID: "admin/clients/delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: delete the client",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that delete works.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Client secrets ---
	{
		ID: "admin/clients/secret-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the client secret",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/client-secret",
		Fixture:   "admin-token-client-secret",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// Cache-Control is asserted because the POST on this same path was
		// measured without one. The pair is the finding, so each has to pin
		// its own half.
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"value"},
	},
	{
		// A client with no secret. Every one of the six bootstrapped clients
		// is like this, so the empty answer is the common case rather than an
		// edge, and it is a 200 with the key absent rather than a 404.
		ID: "admin/clients/secret-read-none",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the client secret, client without one",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/clients/secret-read already claims it.
		Fixture: "admin-token-account-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/clients/secret-regenerate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: generate a new secret for the client",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/client-secret",
		Fixture:   "admin-token-client-secret-rotate",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		// The half of the finding that only an absence can pin: the GET beside
		// this one carries Cache-Control and this does not.
		AssertAbsentHeaders: []string{"Cache-Control"},
		Volatile:            []string{"value"},
	},
	{
		// The rotated secret is a constant 404 on this distribution:
		// CLIENT_SECRET_ROTATION is a disabled preview feature and
		// secret-rotation is not a registered executor, so nothing can ever
		// put a client into the other state. The 404 is the contract.
		ID: "admin/clients/secret-rotated-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the rotated client secret",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/client-secret/rotated",
		Fixture:   "admin-token-client-secret-rotated",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret/rotated",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/clients/secret-rotated-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: invalidate the rotated secret for the client",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/client-secret/rotated",
		Fixture:   "admin-token-client-secret-drop",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/client-secret/rotated",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// One of the four security headers is asserted present so that the two
		// asserted absent read as omissions rather than as "this response
		// carries no headers".
		AssertHeaders: []string{"X-Content-Type-Options"},
		// X-Frame-Options is the third exception to the five, and this 204 is
		// one of four DELETEs measured omitting it. Cache-Control separates it
		// from the client delete, which does send one.
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},
	{
		ID: "admin/clients/secret-unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the client secret, unknown client",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that reading works.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/client-secret",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- The service account user ---
	{
		ID: "admin/clients/service-account-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get a user dedicated to the service account",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/service-account-user",
		Fixture:   "admin-token-client-service-account",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/service-account-user",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The account is minted per run, so both its id and the millisecond it
		// was created differ between the container and Gloak. The absence of
		// an access block - which the same user carries through GET /users -
		// stays asserted, because that is the finding here.
		Volatile: []string{"id", "createdTimestamp"},
	},
	{
		ID: "admin/clients/service-account-user-disabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get a user dedicated to the service account, client without one",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. It is a 400 rather than the 404 an
		// unknown client gets, and the message names the clientId in single
		// quotes rather than the UUID the request used.
		Fixture: "admin-token-account-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/service-account-user",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Reading back a client created through the API, which is the only way
		// to see a representation carrying a secret. It cannot pass yet:
		// Keycloak fills the two client-scope name lists from the realm's
		// defaults on create, and Gloak leaves them empty because the realm
		// does not model a default set - that is P5. Recorded so the shape is
		// in the repository and the alarm fires when P5 makes it reproducible.
		ID: "admin/clients/read-created",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get representation of a client created through the API",
			Retrieved: "2026-08-23",
		},
		Status: Recorded,
		Reason: "a created client inherits the realm's default client scopes, which is P5",
		// No Operation: admin/clients/read already claims it.
		Fixture: "admin-token-client-to-read",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"defaultClientScopes", "optionalClientScopes"},
		Volatile:      []string{"id", "secret", "attributes/client.secret.creation.time"},
		UnorderedKeys: []string{"attributes"},
	},

	{
		// The 403 shape is measured - see "Admin API rejection shapes" in
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md, taken
		// from a live caller holding view-users and nothing else - and it is
		// served and covered by TestCallerWithoutTheRoleIsForbidden in
		// internal/admin, which builds that caller through the store.
		//
		// It cannot be a conformance case yet. A fixture runs the same
		// requests against the reference container and against Gloak, so
		// reaching a narrow-role caller needs Gloak to serve user creation
		// (this cut, later) *and* role assignment, which is the Role Mapper
		// tag and therefore P2's second cut. There is no way to seed the
		// container except through its API.
		ID: "admin/users/list-without-view-users",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, caller lacking view-users",
			Retrieved: "2026-08-22",
		},
		Status:  Pending,
		Reason:  "the fixture needs role assignment, which is P2's second cut",
		Fixture: "",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Headers: map[string]string{"Authorization": "Bearer REPLACE-WITH-A-NARROW-ROLE-TOKEN"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Reported under admin/users rather than admin/realms-admin: the
		// chapter is taken from the case ID and has to match the chapter whose
		// denominator the named operation belongs to, or a Users operation
		// would count towards the Realms Admin row.
		ID: "admin/users/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, unknown realm",
			Retrieved: "2026-08-22",
		},
		Status: Implemented,
		// No Operation: these pin a rejection, not that the listing works. The
		// success path is a stub until the representation is recorded, and an
		// operation nobody serves must not count towards parity.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/nosuchrealm/users",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
}
