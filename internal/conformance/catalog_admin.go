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
		// A client with a name and a description, which the six bootstrapped
		// clients between them do not have. Gloak had no description field at
		// all until kcadm.sh set one and the read-back lost it - the first
		// thing the external oracle found. Measured position: between name and
		// rootUrl.
		//
		// Recorded rather than served, for the same reason
		// admin/clients/read-created is: a created client inherits the realm's
		// default client scopes, which is P5. See follow-up F16.
		ID: "admin/clients/read-described",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get representation of a client with a description",
			Retrieved: "2026-08-23",
		},
		Status:  Recorded,
		Reason:  "a created client inherits the realm's default client scopes, which is P5",
		Fixture: "admin-token-client-described",
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

	// --- Users ---
	{
		ID: "admin/users/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users",
		// The realm holds one user at this point, the bootstrapped
		// administrator, and every other fixture creates more - so this
		// enumerates the realm and has to record first. See
		// Case.PristineRealm.
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// id and createdTimestamp are minted at bootstrap.
		Volatile: []string{"*/id", "*/createdTimestamp"},
	},
	{
		// The same listing narrowed by username, which is what makes the case
		// reproducible once other fixtures have added users. It is also how
		// the field set is pinned against the read below: the two differ, and
		// only in access.
		ID: "admin/users/list-by-username",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, filtered by username",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"username": "admin"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdTimestamp"},
	},
	{
		// briefRepresentation drops four fields - totp,
		// disableableCredentialTypes, requiredActions and notBefore - and
		// keeps access. Their natural values are false, [], [] and 0, so
		// nothing but a recording distinguishes "dropped" from "empty".
		ID: "admin/users/list-brief",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, briefRepresentation",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/master/users",
			Query: map[string]string{
				"username":            "admin",
				"briefRepresentation": "true",
			},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdTimestamp"},
	},
	{
		// search is the loose filter: a case-insensitive substring across
		// username, firstName, lastName and email, where username= matches
		// only its own field.
		ID: "admin/users/list-by-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, search",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"search": "ADMI"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdTimestamp"},
	},
	{
		// A filter matching nothing is 200 and an empty array, not a 404.
		ID: "admin/users/list-no-match",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, filter matching nothing",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"username": "nosuchuser"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A bare JSON number, not an object.
		ID: "admin/users/count",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get the number of users",
			Retrieved: "2026-08-23",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/users/count",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/users/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get representation of the user",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}",
		Fixture:   "admin-token-admin-user",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "createdTimestamp"},
	},
	{
		ID: "admin/users/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get representation of the user, unknown id",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. The message is "User not found", where a
		// missing client says "Could not find client" and a missing realm
		// "Realm not found." - three endpoints, three spellings.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	{
		// search is a prefix, not a substring - which is what this case is
		// here to pin, because Task 13 shipped it as a substring on the
		// strength of four measurements that were all prefixes by accident.
		// "user" is inside "full-user" and finds nothing.
		ID: "admin/users/list-search-is-a-prefix",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, search matching mid-string",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token-created-user",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"search": "loak-probe"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The same term with wildcards does match, which is what makes the
		// case above a statement about prefixes rather than about the term.
		//
		// The term is narrowed to this fixture's own email address. A broader
		// one matched a *different* fixture's user the moment one was added
		// whose username shared the prefix, and the golden recorded both.
		ID: "admin/users/list-search-wildcard",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, search with a wildcard",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/list already claims it.
		Fixture: "admin-token-created-user",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"search": "*probe-user@example*"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdTimestamp"},
	},
	{
		ID: "admin/users/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"username":"gloak-probe-create","enabled":true}`),
		},
		// Unlike the client create, which sends no Content-Length at all, this
		// 201 sends content-length: 0. Both send no Content-Type.
		AssertHeaders:       []string{"Location"},
		VolatileHeaders:     []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, duplicate username",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. The message names no username, unlike
		// the client conflict's "Client <id> already exists".
		Fixture: "admin-token-created-user",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"username":"gloak-probe-user","enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/create-without-username",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, no username",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. errorMessage, where a malformed body on
		// the same endpoint answers the OAuth shape - two error families on
		// one route.
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/create-malformed",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, malformed body",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{not json`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A body of exactly "null" answers 500, where a body that is merely
		// malformed answers 400. Keycloak's defect, reproduced - see
		// decodeInto. An empty body does the same, but the recorder cannot
		// send one: Request.Body is used only when non-empty.
		ID: "admin/users/create-null-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, null body",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`null`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// An unrecognised field is a 400 carrying Jackson's own message, with
		// the offending name and the line and column it sat at. Recorded
		// rather than served: Go's decoder reports the field name and no
		// position, and reconstructing Jackson's column - which points past
		// the *value*, not the name - is a lot of fragile arithmetic for one
		// error string.
		ID: "admin/users/create-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, unrecognised field",
			Retrieved: "2026-08-23",
		},
		Status:  Recorded,
		Reason:  "the message carries Jackson's line and column, which Go's decoder does not report",
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"username":"gloak-probe-unknown","nosuchfield":1}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/users/{user-id}",
		Fixture:   "admin-token-user-to-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"firstName":"Grace"}`),
		},
	},
	{
		// The body merged: firstName changed and lastName survived, from a
		// request that named only the first. This is the case that would
		// catch a wholesale replace.
		ID: "admin/users/update-merges",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user, reading back a partial update",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/read already claims this one.
		Fixture: "admin-token-user-updated",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "createdTimestamp"},
	},
	{
		ID: "admin/users/update-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user, unknown id",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"firstName":"x"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: delete the user",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/users/{user-id}",
		Fixture:   "admin-token-user-to-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: delete the user, unknown id",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/users/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Credentials ---
	{
		ID: "admin/users/credentials-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get the credentials, user with none",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/credentials",
		Fixture:   "admin-token-created-user",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The body carries no hash and no salt. credentialData is a JSON
		// **string**, not a nested object, describing how the secret was
		// hashed - which is why the golden shows it escaped.
		ID: "admin/users/credentials-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get the credentials",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/credentials-empty already claims it.
		Fixture: "admin-token-user-with-password",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		ID: "admin/users/reset-password",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: set up a new password",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/users/{user-id}/reset-password",
		Fixture:   "admin-token-created-user",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}/reset-password",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"type":"password","value":"s3cret","temporary":false}`),
		},
		// A JSON request body, so this 204 does carry X-Frame-Options - see
		// httpx.WriteNoContent.
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/reset-password-no-value",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: set up a new password, no value",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. It is the bare-prose shape, a third
		// error family on the user endpoints after errorMessage and OAuth.
		Fixture: "admin-token-created-user",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}/reset-password",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"type":"password"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// temporary true adds UPDATE_PASSWORD to the user's requiredActions,
		// which is the only observable difference the flag makes.
		ID: "admin/users/reset-password-temporary",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: set up a new password, temporary",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: admin/users/read already claims the read this uses.
		Fixture: "admin-token-user-with-temporary-password",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "createdTimestamp"},
	},
	{
		// A text/plain body, so this 204 omits X-Frame-Options. Sending JSON
		// to it answers 415 instead.
		ID: "admin/users/credential-label",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update a credential label",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/userLabel",
		Fixture:   "admin-token-user-with-password",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}/credentials/{{credential_id}}/userLabel",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "text/plain",
			},
			Body: []byte(`my password`),
		},
		AssertHeaders:       []string{"X-Content-Type-Options"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// The label read back, sitting between type and createdDate.
		ID: "admin/users/credential-label-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get the credentials, labelled",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-user-with-labelled-password",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		ID: "admin/users/credential-move-to-first",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: move a credential to first in the list",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/moveToFirst",
		Fixture:   "admin-token-user-with-password",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials/{{credential_id}}/moveToFirst",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"X-Content-Type-Options"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// Moving a credential after a target that does not exist is still a
		// 204: only the credential being moved is checked.
		ID: "admin/users/credential-move-after",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: move a credential after another",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users/{user-id}/credentials/{credentialId}/moveAfter/{newPreviousCredentialId}",
		Fixture:   "admin-token-user-with-password",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials/{{credential_id}}/moveAfter/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"X-Content-Type-Options"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/credential-move-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: move a credential, unknown credential",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-created-user",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials/00000000-0000-0000-0000-000000000000/moveToFirst",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/users/credential-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove a credential",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/users/{user-id}/credentials/{credentialId}",
		Fixture:   "admin-token-user-with-doomed-password",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials/{{credential_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/credential-delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove a credential, unknown id",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-created-user",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Measured: 204 for any list, including ["password"], and nothing
		// observable changes. On a bootstrapped realm no credential type
		// declares itself disableable, so the endpoint does nothing - and
		// that is the contract, not a gap.
		ID: "admin/users/disable-credential-types",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: disable credential types",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/users/{user-id}/disable-credential-types",
		Fixture:   "admin-token-user-with-password",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}/disable-credential-types",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`["otp"]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},

	{
		ID: "admin/users/logout",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove all user sessions",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users/{user-id}/logout",
		Fixture:   "admin-token-created-user",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/logout",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// No Content-Type on the request, so no X-Frame-Options on the 204 -
		// the eighth confirmation of that rule and the first on a POST.
		AssertHeaders:       []string{"X-Content-Type-Options"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},
	{
		// Idempotent: the user in this fixture has no session at all, and the
		// answer is still 204 rather than a 404.
		ID: "admin/users/logout-without-a-session",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove all user sessions, user already logged out",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-user-to-update",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/{{user_id}}/logout",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"X-Content-Type-Options"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/logout-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove all user sessions, unknown id",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/master/users/00000000-0000-0000-0000-000000000000/logout",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
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

	// --- Roles ---
	{
		ID: "admin/roles/list-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm or client",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles",
		// The realm's five roles and nothing else, so it has to run before any
		// fixture has created one. See Case.PristineRealm.
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The order is a Java set's and was measured differing on three
		// consecutive container starts. "." is the document root - this is the
		// case Task 1 exists for.
		Unordered: []string{"."},
		Volatile:  []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-page-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, max=0; mined from RealmRolesSearchTest.testSearchForRoles",
			Retrieved: "2026-08-25",
		},
		Status: Implemented,
		// No Operation: GET /admin/realms/{realm}/roles is already claimed by
		// admin/roles/list-realm, and an operation is counted once.
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-page", "max": "0"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-page-past-end",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, first past the end of the match set; mined from RealmRolesSearchTest.testSearchForRoles",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-page", "first": "3"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// Recordable because Task 2 measured this exact page -
		// search=gloak-probe-page&first=1&max=1 - reproducible in both
		// membership and order across two separate container starts.
		//
		// **This page cannot tell a sort by name from any other order.** The
		// middle of three is the middle whichever way the three are arranged,
		// so the assertion holds under Keycloak's measured sort by name and
		// under the creation order this fixture used to hand it as well.
		// pagedRolesFixture now creates c, b, a rather than a, b, c, which
		// removes the accidental agreement but does not make *this* query
		// discriminating - only a page that is not symmetric about the middle
		// would be. admin/roles/list-realm-page-no-search below is the case
		// that actually pins the sort.
		ID: "admin/roles/list-realm-page-first",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, one role taken out of the middle of the match set; mined from RealmRolesSearchTest.testSearchForRoles",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-page", "first": "1", "max": "1"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// **The only case guarding the gate that decides whether a role
		// listing pages at all**, and the reason it exists is that the gate
		// was got wrong once. Every other paging case sends search=, so all
		// six of them passed while first=1&max=5 with no search returned the
		// entire realm.
		//
		// Measured 2026-08-26: the listing pages when search is non-empty *or*
		// when first and max are both present, and the paged path is sorted by
		// name. This sends no search at all, so it is the second condition on
		// its own. Without it the response would be every realm role.
		//
		// **Why a page of the whole realm is recordable here when Case.
		// PristineRealm exists precisely because it usually is not.** The
		// recorder shares one container and state accumulates in catalogue
		// order, so an unfiltered listing normally picks up whatever earlier
		// fixtures created. This page cannot: the paged path is sorted by
		// name, and every realm role any fixture creates is named
		// "gloak-probe-...", which sorts after "default-roles-master" and so
		// can never enter or displace the window at indices 1 and 2. Those two
		// slots hold create-realm and default-roles-master whatever else the
		// realm accumulated, which is also why this case needs no
		// PristineRealm marking and adds no ordering constraint. A future
		// fixture creating a realm role sorting before "default-roles-master"
		// would break that, and would break this case loudly rather than
		// silently.
		//
		// No Unordered: the paged path was measured sorted and stable, unlike
		// the plain listing, so order is worth asserting here. It is what
		// distinguishes a real page from two roles picked out of the unstable
		// set.
		ID: "admin/roles/list-realm-page-no-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, first and max with no search term; mined from RealmRolesSearchTest.testPaginationRoles",
			Retrieved: "2026-08-26",
		},
		Status: Implemented,
		// No Operation: GET /admin/realms/{realm}/roles is already claimed by
		// admin/roles/list-realm, and an operation is counted once.
		Fixture: "admin-token-paged-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"first": "1", "max": "2"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-brief",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, briefRepresentation=true over a role with attributes; mined from RealmRolesSearchTest.getRolesWithBriefRepresentation",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-role-with-attributes",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-attrs", "briefRepresentation": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/list-realm-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, briefRepresentation=false over a role with attributes; mined from RealmRolesSearchTest.getRolesWithFullRepresentation",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-role-with-attributes",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-attrs", "briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
		// attributes is a Java Map in hash order and Go sorts map keys. This is
		// the suite's one documented retreat from byte-exactness; see the
		// UnorderedKeys note in case.go.
		UnorderedKeys: []string{"*/attributes"},
	},
	{
		ID: "admin/roles/list-realm-search-excludes-client-roles",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm, search matching a client role too; mined from RealmRolesSearchTest.testSearchForRealmRoles, upstream issue #9587",
			Retrieved: "2026-08-25",
		},
		Status:  Implemented,
		Fixture: "admin-token-same-named-roles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles",
			Query:   map[string]string{"search": "gloak-probe-shared"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/read-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get a role by name",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/admin",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "containerId"},
	},
	{
		// A role created through the API, read back by the name it was given -
		// the round trip Location alone cannot prove.
		ID: "admin/roles/read-created",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get a role by name",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-realm-role",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/gloak-probe-role",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"id", "containerId"},
	},
	{
		ID: "admin/roles/not-found",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get a role by name",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/no-such-role",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: create a new role for the realm or client",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/roles",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-role-create","description":"a probe"}`),
		},
		// Measured: 201, empty body, Location naming the role by name rather
		// than by id. Still masked - see clientFixture's Location for why: the
		// recorder and the verifier serve from different hosts, and only the
		// body passes through ReplaceIssuer, not a header compared raw.
		AssertHeaders:       []string{"Location"},
		VolatileHeaders:     []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: create a new role, conflicting name",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that create works.
		Fixture: "admin-token-realm-role",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-role"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: create a new role, no name",
			Retrieved: "2026-08-23",
		},
		Status: Implemented,
		// No Operation: a rejection. Lowercase "role has no name", where the
		// 404 two cases up is sentence case and the 409 above is a third shape
		// again - three error families on one endpoint.
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"description":"no name"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: update a role by name",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/roles/{role-name}",
		Fixture:   "admin-token-role-to-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/roles/gloak-probe-role-update",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-role-update","description":"renamed"}`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options - see
		// httpx.WriteNoContent.
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: delete a role by name",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/roles/{role-name}",
		Fixture:   "admin-token-role-to-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/roles/gloak-probe-role-delete",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// Direct holders only - the administrator holds admin directly. See
		// "/roles/{name}/users is direct holders only" in the observed doc.
		ID: "admin/roles/users",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the users that have the specified role name",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/users",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/admin/users",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdTimestamp"},
	},
	{
		// Always [] - the realm has no groups until P2's third cut. See
		// roleGroups in internal/admin/roles.go.
		ID: "admin/roles/groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the groups that have the specified role name",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/groups",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/admin/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/roles/composites-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get composites of the role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/gloak-probe-composite-parent/composites",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// Two children, realm and client family mixed - order not measured
		// stable, same family as the plain listing above.
		Unordered: []string{"."},
		Volatile:  []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-realm-filter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get realm-level roles of the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/composites/realm",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/gloak-probe-composite-parent/composites/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-clients-filter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get client-level roles for the client that are in the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/composites/clients/{targetClientUuid}",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles/gloak-probe-composite-parent/composites/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: add a composite to the role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles/gloak-probe-composite-parent/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			// Already a child by the time this runs - the fixture links it.
			// Measured idempotent: 204, not 409. See compositeParentFixture.
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles/composites-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: remove roles from the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/roles/gloak-probe-composite-parent/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},

	// --- Client roles ---
	{
		ID: "admin/roles/list-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get all roles for the realm or client, client roles",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles",
		Fixture:   "admin-token-client-role-container",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/read-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get a role by name, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}",
		Fixture:   "admin-token-client-role-container",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-client-role",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "containerId"},
	},
	{
		ID: "admin/roles/create-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: create a new role for the realm or client, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/roles",
		Fixture:   "admin-token-role-create-container",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/roles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-client-role-created"}`),
		},
		AssertHeaders:       []string{"Location"},
		VolatileHeaders:     []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/update-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: update a role by name, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}",
		Fixture:   "admin-token-client-role-to-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-client-role-update",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-client-role-update","description":"renamed"}`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles/delete-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: delete a role by name, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}",
		Fixture:   "admin-token-client-role-to-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-client-role-delete",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles/users-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the users that have the specified role name, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/users",
		Fixture:   "admin-token-client-role-container",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-client-role/users",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/roles/groups-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the groups that have the specified role name, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/groups",
		Fixture:   "admin-token-client-role-container",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-client-role/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/roles/composites-list-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get composites of the role, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-realm-filter-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get realm-level roles of the role's composite, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites/realm",
		Fixture:   "admin-token-composite-parent-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-clients-filter-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get client-level roles for the client that are in the role's composite, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites/clients/{targetClientUuid}",
		Fixture:   "admin-token-composite-parent-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles/composites-add-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: add a composite to the role, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles/composites-remove-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: remove roles from the role's composite, client role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/composites",
		Fixture:   "admin-token-composite-parent-client",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-composite-client-role-parent/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},

	// --- Roles by id ---
	{
		ID: "admin/roles-by-id/not-found",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): get a specific role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles-by-id/{role-id}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The successful read the case above's 404 does not demonstrate: the
		// full seven-key representation, addressed by id.
		ID: "admin/roles-by-id/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): get a specific role's representation",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/{{parent_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "containerId"},
	},
	{
		ID: "admin/roles-by-id/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): update the role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/roles-by-id/{role-id}",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/roles-by-id/{{parent_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			// Same name, so this stays a no-op on content: other cases share
			// this fixture's parent and must still see it unchanged. See
			// compositeParentFixture.
			Body: []byte(`{"name":"gloak-probe-composite-parent"}`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles-by-id/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): delete the role",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/roles-by-id/{role-id}",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/roles-by-id/{{parent_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles-by-id/composites-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): get role's children",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles-by-id/{role-id}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/{{parent_id}}/composites",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles-by-id/composites-realm-filter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): get realm-level roles that are in the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles-by-id/{role-id}/composites/realm",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/{{parent_id}}/composites/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles-by-id/composites-clients-filter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): get client-level roles for the client that are in the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles-by-id/{role-id}/composites/clients/{clientUuid}",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/{{parent_id}}/composites/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/roles-by-id/composites-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): make the role a composite role by associating some child roles",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/roles-by-id/{role-id}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles-by-id/{{parent_id}}/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/roles-by-id/composites-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): remove a set of roles from the role's composite",
			Retrieved: "2026-08-23",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/roles-by-id/{role-id}/composites",
		Fixture:   "admin-token-composite-parent",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/roles-by-id/{{parent_id}}/composites",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{child_realm_id}}"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
}
