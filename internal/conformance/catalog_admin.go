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
		// The clients-family mirror of admin/users/list-without-view-users:
		// query-clients is admitted and shown nothing. Measured 2026-08-28,
		// unfiltered so that "nothing" is the caller's doing and not a
		// clientId parameter's.
		//
		// This route took view-clients alone until that sweep, so it refused
		// this caller **and** manage-clients, which Keycloak serves in full -
		// wrong in both directions at once. F17.
		ID: "admin/clients/list-to-a-query-clients-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get clients belonging to the realm, caller holding query-clients",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-clients",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
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
		// The retreat on a **client's** attributes is no longer about the
		// order being unknown, and F90 is what measured the difference.
		// javamap.KeyOrder reproduces every attribute key set a default 26.7.1
		// puts on a client - five of them, no bucket collision anywhere in the
		// set, pinned by TestKeyOrderReproducesAClientsAttributes. What still
		// cannot reproduce it is Gloak: model.Client.Attributes is a Go map and
		// encoding/json sorts it, so `account` serves
		// `post.logout.redirect.uris, realm_client` where Keycloak serves them
		// the other way round. Dropping the mask today fails this case rather
		// than tightening it. The mask comes off when internal/admin serialises
		// the map through javamap.KeyOrder - see follow-up F92, and the four
		// sibling cases below that carry the same mask for the same reason.
		UnorderedKeys: []string{"*/attributes"},
	},
	{
		// The unfiltered list. Its Reason said "protocolMappers, which is P5"
		// until 2026-08-30, and P5 landed: the mappers are stored and served,
		// and re-serving this case shows only three differences left, none of
		// which is a missing mapper.
		//
		// Two are `master-realm`, which Gloak's bootstrap creates without the
		// display name Keycloak gives it and without either client-scope list.
		// The third is `account-console`'s `audience resolve`, which Keycloak
		// serves as `"config":{}` from this route and populated from the
		// dedicated mapper route - the "one mapper serialises two ways" bullet
		// in AGENTS.md - where Gloak serves it populated from both. See F93.
		//
		// A stale Reason is what sends the next reader past work that is
		// already possible, so it names the three rather than the phase.
		ID: "admin/clients/list-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get clients belonging to the realm",
			Retrieved: "2026-08-22",
		},
		Status: Recorded,
		Reason: "master-realm is bootstrapped with no name and neither client-scope list, " +
			"and account-console's audience resolve serves a populated config where this route " +
			"measures an empty one",
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
		// The client-attributes retreat, for the reason admin/clients/list
		// gives above: reproducible by javamap.KeyOrder, not by a Go map.
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
		// The same retreat on the same two keys - see admin/clients/list.
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
		// object's absolute URL in Location. Only the UUID at the end of it is
		// minted per request, so only that segment is masked - the scheme, the
		// host and `/admin/realms/master/clients` are compared. See F46.
		AssertHeaders:       []string{"Location"},
		VolatileTailHeaders: []string{"Location"},
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
		Status: Implemented,
		// No Operation: admin/clients/read already claims it.
		Fixture: "admin-token-client-to-read",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"defaultClientScopes", "optionalClientScopes"},
		Volatile:      []string{"secret", "attributes/client.secret.creation.time"},
		// A created client's two attributes come back
		// `realm_client, client.secret.creation.time`, which javamap.KeyOrder
		// reproduces and a Go map sorts the other way - see admin/clients/list.
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
		Status:  Implemented,
		Fixture: "admin-token-client-described",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"defaultClientScopes", "optionalClientScopes"},
		Volatile:      []string{"secret", "attributes/client.secret.creation.time"},
		// A created client's two attributes come back
		// `realm_client, client.secret.creation.time`, which javamap.KeyOrder
		// reproduces and a Go map sorts the other way - see admin/clients/list.
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
		Volatile:      []string{"createdTimestamp"},
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
		Volatile:      []string{"*/createdTimestamp"},
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
		VolatileTailHeaders: []string{"Location"},
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
		Volatile:      []string{"createdTimestamp"},
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
		Volatile:      []string{"*/createdDate"},
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
		Volatile:      []string{"createdTimestamp"},
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
		Volatile:      []string{"*/createdDate"},
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
		// A caller holding query-users and nothing else: 200 and an empty
		// array, not 403. The route admits it and the **body** is what
		// narrows - measured 2026-08-28 on one caller per role, alongside the
		// count next door, which the same caller gets in full.
		//
		// This was Pending from 2026-08-22 to 2026-08-28 behind two blockers,
		// and both are now gone: the harness had no non-admin caller (F37) and
		// the listing filter was neither measured nor built (F17). The second
		// is why it stayed Pending after the first was closed.
		ID: "admin/users/list-without-view-users",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get users, caller lacking view-users",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-users",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// F30, the sharpest cell of it: **query-users opens no single-user
		// route at all and still learns that the user does not exist.** The
		// same caller gets 403 from this path when the user is real, which
		// admin/users/read-to-a-query-users-caller records.
		//
		// So the guard is two stages with the subject resolved between them,
		// and this is the case that a single-stage guard cannot pass whichever
		// role it names: name query-users and the real-subject case breaks,
		// omit it and this one does.
		ID: "admin/users/read-missing-to-a-query-users-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get representation of the user, unknown id, caller holding query-users",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-users",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The other half of the pair above: the same caller, a subject that
		// exists, 403. Together they are what says the 404 is about the
		// subject and not about the caller.
		ID: "admin/users/read-to-a-query-users-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get representation of the user, caller holding query-users",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-users",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// F36's suspicion, settled: manage-users **may** read a user. It has
		// no composites at all - it is not composite over view-users - so
		// reading the admin roles by name predicts a caller that can delete a
		// user it cannot read. Keycloak does not do that, and Gloak did until
		// 2026-08-28.
		ID: "admin/users/read-to-a-manage-users-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get representation of the user, caller holding manage-users",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-manage-users",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
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
		//
		// **No Unordered**, and it carried one until the mask sweep. A window of
		// one row has no order to give up, so the mask changed no byte while
		// saying the paged path's order is unstable - which contradicts the case
		// below, where it is measured sorted and asserted. Two of the three other
		// paged cases said the same thing over an empty array.
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
		Volatile:      []string{"*/id", "*/containerId"},
		// **No UnorderedKeys.** It carried one until F90 measured what it was
		// masking: the fixture gives this role a single attribute, and a
		// one-key object has no order to give up. The mask was inert - the
		// golden's bytes are the same with it and without it - and an inert
		// retreat is worse than none, because it reads as though something was
		// measured and conceded. If a second attribute is ever added here, it
		// is measured then rather than pre-emptively excused now.
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
		// than by id - `.../roles/gloak-probe-role-create`, re-measured
		// 2026-08-29. Nothing in it is minted, so nothing is masked.
		//
		// It was masked, on the grounds that "only the body passes through
		// ReplaceIssuer, not a header compared raw". That stopped being true in
		// P3: diff runs ReplaceCaptured and ReplaceIssuer over the served
		// headers as well, and the comment that noticed says this family is
		// exactly where it went unseen, because every asserted Location was
		// also masked. See F46.
		AssertHeaders:       []string{"Location"},
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
		// F32's rule: the guard reads the role's **container**, so a caller
		// holding a perfectly ordinary client role that happens to be named
		// manage-realm is refused this route.
		//
		// The caller does hold manage-clients and manage-users, which is what
		// it takes to mint such a role and hand it out - a narrow admin
		// widening itself. Neither of those opens this route, and that is what
		// makes the case a test of the name rather than of a weak caller:
		// admin/roles/create next door is the same request as the
		// administrator, answering 201.
		ID: "admin/roles/create-refused-to-an-impostor-role",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: create a new role, a caller holding an ordinary role named manage-realm",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-impostor",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/roles",
			Headers: map[string]string{
				"Authorization": "Bearer {{caller_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-minted-by-an-impostor"}`),
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
		//
		// **PristineRealm although the body names one bootstrapped user.** The
		// body is every user in the realm holding a bootstrapped role, so it is
		// a function of the whole realm and not of this case's fixture. It is
		// clean today only because no fixture happens to assign admin; measured
		// 2026-08-29 on a live 26.7.1, granting the realm role to a created
		// user put that user in this body. See F53.
		ID: "admin/roles/users",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the users that have the specified role name",
			Retrieved: "2026-08-23",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/roles/{role-name}/users",
		PristineRealm: true,
		Fixture:       "admin-token",
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
		//
		// **PristineRealm for the same reason as the users sibling above.** []
		// is a statement about every group in the realm, and granting admin to
		// a created group put that group in this body when it was measured on
		// 2026-08-29. Eight fixtures create groups; none grants this role, and
		// nothing but the flag says so. See F53.
		ID: "admin/roles/groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: get the groups that have the specified role name",
			Retrieved: "2026-08-23",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/roles/{role-name}/groups",
		PristineRealm: true,
		Fixture:       "admin-token",
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
		Volatile:  []string{"*/containerId"},
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
		Volatile:      []string{"*/containerId"},
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
		Volatile:      []string{"*/id"},
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
		Volatile:      []string{"id"},
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
		// Measured 2026-08-29:
		// `.../clients/{{client_uuid}}/roles/gloak-probe-client-role-created`.
		// The UUID in the middle is the fixture's own capture, so
		// ReplaceCaptured rewrites it on both sides and the whole value is
		// comparable. Nothing is masked. See F46.
		AssertHeaders:       []string{"Location"},
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
		Volatile:      []string{"*/containerId"},
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
		Volatile:      []string{"*/containerId"},
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
		Volatile:      []string{"containerId"},
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
		Volatile:      []string{"*/containerId"},
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
		Volatile:      []string{"*/containerId"},
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

	// --- Role mappings on a user ---
	//
	// Measured in the "Role mappings on a user" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. This block
	// and the next record the eleven operations of the Role Mapper and Client
	// Role Mappings tags that act on a **user**; the group and organization
	// mirrors those two tags also carry are a later cut.
	{
		ID: "admin/role-mapper/list-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get realm-level role mappings",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings/realm",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// A bare array, like every listing in this family. "." is the document
		// root; see Case.Unordered.
		Unordered: []string{"."},
		Volatile:  []string{"*/id", "*/containerId"},
	},
	{
		// The same read with briefRepresentation=false, which this endpoint
		// **ignores**: the body is the six-key brief shape and carries no
		// attributes key, although the subject's realm role has real attribute
		// values. Only .../composite honours the parameter, and the three
		// siblings disagreeing is what this case pins - the obvious tidy-up is
		// to make them agree.
		ID: "admin/role-mapper/list-realm-ignores-brief",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get realm-level role mappings, briefRepresentation=false",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: the case above already claims this one.
		Fixture: "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// The transitive expansion, which is a different question from the
		// direct list above: the subject holds default-roles-master, so
		// offline_access and uma_authorization are here and are not there.
		ID: "admin/role-mapper/composite-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get effective realm-level role mappings",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings/realm/composite",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// The one read of the six that honours briefRepresentation. With it
		// false every element grows a seventh key, and the subject's own realm
		// role carries a real attribute value where the bootstrapped ones carry
		// {} - which is what tells "the key appeared" from "the values arrived".
		//
		// No UnorderedKeys: the attributes map has one key here, so there is no
		// key order to give up. The suite's single documented retreat from
		// byte-exactness stays single.
		ID: "admin/role-mapper/composite-realm-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get effective realm-level role mappings, briefRepresentation=false",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: admin/role-mapper/composite-realm already claims it.
		Fixture: "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm/composite",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// **The one case in this family that enumerates the realm**, so it has
		// to record before any fixture has created a realm role. See
		// Case.PristineRealm - and note that its own fixture creates a user and
		// no role, for the same reason.
		//
		// The subject holds only the default-roles-master it was created with,
		// so this is the other four bootstrapped realm roles. The caller is a
		// full administrator, which is what makes the list the plain complement:
		// the same read run by a manage-users caller loses admin and
		// create-realm, and by a view-users caller loses everything.
		ID: "admin/role-mapper/available-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get realm-level roles that can be mapped",
			Retrieved: "2026-08-27",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/users/{user-id}/role-mappings/realm/available",
		PristineRealm: true,
		Fixture:       "admin-token-mapping-bare-user",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// Already assigned by the time this runs - the fixture assigns it.
		// Measured idempotent: a role the user already holds is 204, not 409.
		// See mappingRealmWriteFixture.
		//
		// **The entry carries the role's name as well as its id, and both are
		// required.** Measured 2026-08-27: this write resolves the role by name
		// and then checks the id names the same one, so an id-only body is 404.
		// admin/role-mapper/assign-realm-id-only below records that.
		ID: "admin/role-mapper/assign-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings to the user",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users/{user-id}/role-mappings/realm",
		Fixture:   "admin-token-mapping-realm-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-mapping-write-realm-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options - see
		// httpx.WriteNoContent.
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/role-mapper/remove-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: delete realm-level role mappings",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/users/{user-id}/role-mappings/realm",
		Fixture:   "admin-token-mapping-realm-write",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-mapping-write-realm-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		// The same write with the name left out. Measured 2026-08-27 on all
		// four write routes: 404 `{"error":"Role not found"}`, whatever the id
		// is - the entry's id and name must resolve to the same role, so an
		// id-only entry resolves to nothing.
		//
		// It was Recorded until 2026-08-28: Gloak resolved by id alone and
		// answered 204. Nobody probed this shape before, because every measured
		// body in the observed document sent both keys, so "resolve by id" was
		// never falsified. F33, closed.
		ID: "admin/role-mapper/assign-realm-id-only",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings to the user, an entry carrying no name",
			Retrieved: "2026-08-27",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapping-realm-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The id-only case's sharper twin: **two real realm roles, one named
		// by each key.** Measured 2026-08-28 - 404, and Gloak answered 204,
		// writing the role the id named and ignoring the name entirely.
		//
		// This is the shape that says the rule is agreement rather than
		// tolerance. An id-only entry is also 404 under "resolve by name and
		// find nothing", which is why that case alone did not pin it.
		//
		// offline_access is a realm role of the master realm on both sides,
		// which is what lets this send a second real name without a second
		// fixture step.
		ID: "admin/role-mapper/assign-realm-name-disagrees",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings to the user, an entry whose id and name name different roles",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapping-realm-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}","name":"offline_access"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// F28's caller-relative rule, recorded rather than argued for the first
		// time. The caller holds manage-users, which opens this route - the
		// available read below is the control that says so - and is refused the
		// realm role admin, which it may not hand out.
		//
		// The subject is the caller itself. Nothing in the predicate looks at
		// the subject, measured on the sweep this came from, so a second user
		// would be a step whose failure could not change the answer.
		ID: "admin/role-mapper/assign-refused-to-a-manage-users-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings, a role the caller may not grant",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-manage-users",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{caller_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_admin_id}}","name":"admin"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The other half of the same rule: `available` is filtered by what the
		// caller may grant, not merely by what the subject lacks. A view-users
		// caller may read this list and assign none of it, so the body is `[]`
		// although the subject holds almost no realm role.
		//
		// This is the case that stops the read being scored on the
		// administrator's answer alone. An implementation that ignored the
		// caller entirely would pass every other case on this route.
		ID: "admin/role-mapper/available-to-a-view-users-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get available realm-level role mappings, a caller that may grant none of them",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-view-users",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The combined view, and the only body in this family that is not a
		// bare array. Two things are asserted here that no other case can:
		//
		// **clientMappings' key order.** It is a Java HashMap serialised in
		// bucket order, so gloak-probe-mapping-side (bucket 1) comes before
		// gloak-probe-mapping-app (bucket 4) although it sorts after it and was
		// assigned after it. Sorting the keys - which is what Go does to a map -
		// would get this backwards, and so would reproducing insertion order.
		// The two ids were chosen not to share a bucket; see
		// mappingSubjectFixture for why that matters.
		//
		// **That the view is the direct assignments, not the expansion.** The
		// subject holds default-roles-master, whose composite carries
		// offline_access and uma_authorization and two account client roles.
		// None of them is here.
		ID: "admin/role-mapper/all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get role mappings",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// Only the realm half is a list whose order is unstable. The client
		// half is an object, and its order is the contract this case exists for.
		Unordered: []string{"realmMappings"},
		// The client half's ids are all captured by the fixture, so they are
		// already masked as {{client_uuid}} and friends and stay readable -
		// which keeps "the entry's id is that client's UUID" asserted. The realm
		// half has no such handle on default-roles-master or on the realm
		// itself.
		Volatile: []string{"realmMappings/*/id", "realmMappings/*/containerId"},
	},
	{
		// A client role posted to the realm endpoint. It exists, and it is
		// refused with the same 404 an unknown id gets, because the check is
		// which container owns the role rather than whether one does.
		ID: "admin/role-mapper/assign-realm-client-role",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings to the user, a client role",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: a rejection, not a demonstration that the write works.
		Fixture: "admin-token-mapping-subject",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{app_role_id}}","name":"gloak-probe-mapping-app-role"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/role-mapper/unknown-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get role mappings, unknown user",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: a rejection.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/00000000-0000-0000-0000-000000000000/role-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Client role mappings on a user ---
	{
		ID: "admin/client-role-mappings/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get client-level role mappings for the user or group, and the app",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/client-role-mappings/composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get effective client-level role mappings",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}/composite",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The client mirror of admin/role-mapper/composite-realm-full: this is
		// the second of the six reads that honours briefRepresentation, and it
		// was measured on this route rather than inherited from the realm one.
		ID: "admin/client-role-mappings/composite-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get effective client-level role mappings, briefRepresentation=false",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: the case above already claims it.
		Fixture: "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}/composite",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The complement of the direct list, over one client's roles: the
		// fixture leaves gloak-probe-mapping-app-free unassigned so this has
		// something to offer. Read by a full administrator, which is what makes
		// it the plain complement - the list is also filtered by what the caller
		// may grant.
		ID: "admin/client-role-mappings/available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get available client-level roles that can be mapped to the user or group",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}/available",
		Fixture:   "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
	},
	{
		// Already assigned by the time this runs, exactly as on the realm
		// mirror, and measured idempotent on this route too. See
		// mappingClientWriteFixture. The name beside the id is required here as
		// well, measured on this route rather than inherited from the realm one.
		ID: "admin/client-role-mappings/assign",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: add client-level roles to the user or group role mapping",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-mapping-client-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}","name":"gloak-probe-mapping-write-client-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/client-role-mappings/remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: delete client-level roles from user or group role mapping",
			Retrieved: "2026-08-27",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/users/{user-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-mapping-client-write",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}","name":"gloak-probe-mapping-write-client-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		// admin/role-mapper/assign-realm-id-only's mirror, measured on this
		// route rather than inherited from it: the client pair answers the same
		// 404 for an entry carrying no name. Gloak answered 204 here too until
		// 2026-08-28. F33, closed.
		ID: "admin/client-role-mappings/assign-id-only",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: add client-level roles, an entry carrying no name",
			Retrieved: "2026-08-27",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapping-client-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// admin/role-mapper/assign-realm-name-disagrees' mirror, measured on
		// this route on 2026-08-28 rather than inherited from it.
		//
		// The name here is a **realm** role, so this pins two things at once:
		// the id and the name must agree, and the name is looked for in the
		// route's own container. An entry whose two keys agree on a role of
		// the wrong container is 404 as well, measured in both directions on
		// the same day - a client role through the realm route and a realm
		// role through the client route.
		ID: "admin/client-role-mappings/assign-name-disagrees",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: add client-level roles, an entry whose id and name name different roles",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapping-client-write",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/users/{{user_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}","name":"offline_access"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The ninth not-found spelling on this API, and **not** the "Could not
		// find client" that GET /clients/{uuid} answers for the very same
		// unknown UUID. The two were measured side by side, since reusing the
		// existing client resolver here was the obvious move.
		ID: "admin/client-role-mappings/unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get client-level role mappings, unknown client",
			Retrieved: "2026-08-27",
		},
		Status: Implemented,
		// No Operation: a rejection.
		Fixture: "admin-token-mapping-subject",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/role-mappings/clients/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	// ---- Groups, P2's third cut ----------------------------------------
	{
		// Top-level only. The count next door answers 2 for the same realm,
		// because it counts the whole tree - the two are measured disagreeing.
		//
		// briefRepresentation defaults to **true** here, which is the opposite
		// way from the user listing, so this body carries no attributes.
		ID: "admin/groups/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: get group hierarchy",
			Retrieved: "2026-08-28",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/groups",
		PristineRealm: true,
		Fixture:       "admin-token-group",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **201 with an empty body**, where POST .../children below answers 201
		// with the group in it. Two creates on one resource, disagreeing.
		ID: "admin/groups/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: create or add a top level realm group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/groups",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-group-created"}`),
		},
		// Only the minted UUID is masked, so the golden still says the new
		// group landed under `/admin/realms/master/groups`. See F46.
		VolatileTailHeaders: []string{"Location"},
		AssertHeaders:       []string{"Location"},
	},
	{
		// `{"count":n}`, an **object**, where GET /users/count next door is a
		// bare JSON number. The two counts do not agree about what a count is.
		//
		// **The number was masked and is measured again.** The count is over
		// the whole realm, and while the recorder shared one container any
		// fixture creating a group moved it - the first recording said 3 where
		// a pristine replay says 2, so the value was masked to `{{number}}`.
		// A PristineRealm case now gets a container of its own (F40), which
		// leaves bootstrap plus this fixture's parent and child: measured
		// 2026-08-29 on a live 26.7.1, a bootstrapped realm holds no groups
		// and this pair answers `{"count":2}`. The mask was the one place
		// F40's defect was papered over rather than fixed. See F47.
		//
		// The numeric rules the body cannot show - whole tree, top=true, top
		// ignored under search - stay pinned by
		// TestGroupCountIsTheTreeAndTopIsIgnoredUnderSearch.
		ID: "admin/groups/count",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: returns the groups counts",
			Retrieved: "2026-08-28",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/groups/count",
		PristineRealm: true,
		Fixture:       "admin-token-group-tree",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The single read carries three keys the listing does not - attributes,
		// realmRoles and clientRoles - and subGroupCount is 1 while subGroups
		// is still `[]`, which is the tree never being expanded.
		ID: "admin/groups/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: get group by id",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}",
		Fixture:   "admin-token-group-tree",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/groups/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: update group, ignores subgroups",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/groups/{group-id}",
		Fixture:   "admin-token-group-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/groups/{{group_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-group-update"}`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options - unlike the
		// delete below, whose request has none.
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		// The 204 omits X-Frame-Options, because the request carried no body,
		// and carries no Cache-Control either - where DELETE on a client does.
		ID: "admin/groups/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: deletes a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/groups/{group-id}",
		Fixture:   "admin-token-group-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/groups/{{group_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},
	{
		// Each row carries parentId **and** subGroupCount, where the create's
		// response one case down carries the first and not the second.
		ID: "admin/groups/children-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: return a paginated list of subgroups",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/children",
		Fixture:   "admin-token-group-tree",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/children",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **201 with the group in the body**, and the body is the one shape
		// carrying no subGroupCount. Both measured on this route rather than
		// shared with POST /groups, which they disagree with.
		ID: "admin/groups/children-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: set or create child",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/groups/{group-id}/children",
		Fixture:   "admin-token-group",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups/{{group_id}}/children",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-group-made-child"}`),
		},
		// **The Location is `/groups/<child uuid>`, not
		// `/groups/{{group_id}}/children/<child uuid>`** - measured 2026-08-29,
		// and the whole-header mask had been hiding it. A child is addressed
		// like any other group once it exists. See F46.
		VolatileTailHeaders: []string{"Location"},
		AssertHeaders:       []string{"Content-Type", "Cache-Control", "Location"},
		Volatile:            []string{"id"},
	},
	{
		// The user representation **without an access block**, where the user
		// listing next door carries a one-key one.
		//
		// This ran on an empty group through cut A, because the only way to
		// fill one is the membership write and that was cut B. It is filled
		// now, so the body is the representation rather than `[]`.
		ID: "admin/groups/members",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: get users in the group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/members",
		Fixture:   "admin-token-group-member",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/members",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		// **The search rule, and the case the whole cut turns on.** The matches
		// are aa-gloak-srch-kid (a child), gloak-srch-one and zz-gloak-srch;
		// max=1 takes the first by name, which is the child, so what comes back
		// is its top-level ancestor with it nested.
		//
		// This is the only case in the catalogue where subGroups is not `[]`.
		// The design document said it always was until this was measured.
		ID: "admin/groups/search-pages-the-matches",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: get group hierarchy, searched and paged",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-group-search",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups",
			Query:   map[string]string{"search": "gloak-srch", "max": "1"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"*/subGroups/*/id"},
	},
	{
		ID: "admin/groups/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: get group by id, unknown id",
			Retrieved: "2026-08-28",
		},
		Status: Implemented,
		// No Operation: a rejection. "Could not find group by id" is not the
		// membership route's "Group not found" - two spellings, measured.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The 409 for a duplicate at the top level, which ends in a full stop
		// and is **not** the sibling's wording one case down.
		ID: "admin/groups/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: create a top level group, duplicate name",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-group",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-group"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same condition one level down, and a different string for it.
		ID: "admin/groups/children-create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: set or create child, duplicate name",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-group-tree",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups/{{group_id}}/children",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-group-child"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Lowercase, no full stop, and the errorMessage shape - where the two
		// 404s on this resource use `error`. One resource, two error families.
		ID: "admin/groups/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: create a top level group, no name",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	// ---- a user's group membership, P2's third cut B --------------------
	{
		// The **fifth** group shape: no subGroupCount and no access, and
		// briefRepresentation=false gains the attributes trio without gaining
		// either. Reported under admin/users because the operation is tagged
		// Users, and the chapter has to match the tag whose denominator it
		// counts against.
		ID: "admin/users/groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: get the groups the user is a member of",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/groups",
		Fixture:   "admin-token-group-member",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// `{"count":n}`, an object - like the group count and unlike
		// GET /users/count, which is a bare number.
		ID: "admin/users/groups-count",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: returns the number of groups the user is a member of",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/users/{user-id}/groups/count",
		Fixture:   "admin-token-group-member",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/groups/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The fixture has already joined this group, so this is the **second**
		// join and it is measured 204 rather than 409.
		//
		// Cache-Control: no-cache and **no X-Frame-Options**, because the
		// request carries no body - where PUT /groups/{id} is the other way
		// round on both counts.
		ID: "admin/users/groups-join",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: add the user to the group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/users/{user-id}/groups/{groupId}",
		Fixture:   "admin-token-group-member",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/users/{{user_id}}/groups/{{group_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/users/groups-leave",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: remove the user from the group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/users/{user-id}/groups/{groupId}",
		Fixture:   "admin-token-group-member",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/users/{{user_id}}/groups/{{group_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// **"Group not found", not "Could not find group by id."** The Groups
		// routes spell the same condition the other way, measured on each. A
		// shared helper gets one of the two wrong.
		ID: "admin/users/groups-join-unknown-group",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: add the user to the group, unknown group",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token-admin-user",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/users/{{user_id}}/groups/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The subject wins.** Both ids are unknown and the answer is about
		// the user, which is what says the subject is resolved first.
		ID: "admin/users/groups-join-unknown-both",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: add the user to the group, neither exists",
			Retrieved: "2026-08-28",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/users/00000000-0000-0000-0000-000000000000" +
				"/groups/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	// ---- a group's role mappings, P2's third cut C ---------------------
	{
		ID: "admin/role-mapper/group-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get role mappings for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"realmMappings/*/containerId"},
	},
	{
		ID: "admin/role-mapper/group-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get realm-level role mappings for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/realm",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/role-mapper/group-realm-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get effective realm-level role mappings for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/realm/composite",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/role-mapper/group-realm-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: get realm-level roles that can be mapped to a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/realm/available",
		// Every realm role the group does not hold, so its body is a function
		// of the whole realm and not of this group: a shared-container
		// recording put thirteen other fixtures' probe roles in it where the
		// committed golden has the five Keycloak bootstraps. F40.
		PristineRealm: true,
		Fixture:       "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/client-role-mappings/group-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get client-level role mappings for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/client-role-mappings/group-client-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get effective client-level role mappings for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}/composite",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/client-role-mappings/group-client-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: get available client-level roles for a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}/available",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/role-mapper/group-realm-assign",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: add realm-level role mappings to a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/groups/{group-id}/role-mappings/realm",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups/{{group_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-group-realm-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/role-mapper/group-realm-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Role Mapper: delete realm-level role mappings from a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/groups/{group-id}/role-mappings/realm",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/groups/{{group_id}}/role-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{realm_role_id}}","name":"gloak-probe-group-realm-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/client-role-mappings/group-client-assign",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: add client-level roles to a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}","name":"gloak-probe-group-client-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/client-role-mappings/group-client-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Role Mappings: delete client-level roles from a group",
			Retrieved: "2026-08-28",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/groups/{group-id}/role-mappings/clients/{client-id}",
		Fixture:   "admin-token-group-mappings",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/groups/{{group_id}}/role-mappings/clients/{{client_uuid}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{client_role_id}}","name":"gloak-probe-group-client-role"}]`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	// ---- Realms Admin, P4's first cut ----------------------------------
	{
		// **PristineRealm, and it has to be.** The body is every realm that
		// exists, and the recorder shares one container - so this must record
		// before any fixture creates a second realm. The verifier builds a
		// fresh handler per case and would see master alone whatever the
		// order, which is the asymmetry that makes the ordering load-bearing
		// rather than tidy. TestPristineRealmGoldensAreNotPolluted is what
		// says it held.
		//
		// briefRepresentation defaults to **false** here, the opposite of the
		// role listings, so this is the full representation per realm.
		ID: "admin/realms-admin/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get accessible realms",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/defaultRole/id", "*/defaultRole/containerId"},
		// The realm's attributes are a Java map in hash order and javamap
		// cannot place them, which is a different reason from the one a
		// client's attributes have and was re-measured on 2026-08-30 rather
		// than inherited.
		//
		// master answers six keys here and a created realm eight, and in both
		// the leading run shares **one bucket**: cibaBackchannelTokenDeliveryMode,
		// cibaExpiresIn, cibaAuthRequestedUserHint - and oauth2DeviceCodeLifespan
		// too on the eight. javamap.KeyOrder breaks a chain alphabetically, so
		// it puts cibaAuthRequestedUserHint first and gets the first three
		// positions wrong; every position after them is right, which is what
		// says the bucket rule holds and only the tie-break does not. Keycloak
		// chains in insertion order and nothing observable says what that was.
		// TestKeyOrderCannotPlaceARealmsAttributes pins it.
		//
		// So this mask stays, and it stays for a reason rather than because
		// nobody looked. See F90.
		UnorderedKeys: []string{"*/attributes"},
	},
	{
		// 201 with an empty body, content-length 0, and the new realm's URL in
		// Location - addressed by the **name the caller chose**, not by a
		// server-minted id, which is what makes a realm unlike every other
		// resource on this API.
		ID: "admin/realms-admin/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: import a realm",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"realm":"gloak-probe-realm-created","enabled":true}`),
		},
		// **Nothing is masked**, because nothing here is minted:
		// `{{issuer}}/admin/realms/gloak-probe-realm-created`, measured
		// 2026-08-29. The mask carried the note that "the served side's headers
		// are not issuer-normalised by the differ today", and that was already
		// wrong when it was written - diff runs ReplaceCaptured and
		// ReplaceIssuer over the served headers, and says so in its own comment
		// two files away. A mask nobody could see through is where a claim like
		// that survives. See F46.
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "admin/realms-admin/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get the top-level representation of the realm",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}",
		Fixture:   "admin-token-realm",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"id", "defaultRole/id", "defaultRole/containerId"},
		// The realm's attributes are a Java map in hash order and javamap
		// cannot place them - see the listing above for which three positions
		// it gets wrong and why. This realm is a created one, so its map is
		// the eight-key shape.
		UnorderedKeys: []string{"attributes"},
	},
	{
		// The 204 carries X-Frame-Options because the request declared JSON -
		// where the delete below carries neither it nor Cache-Control, because
		// a DELETE sends no Content-Type. httpx.WriteNoContent's existing rule,
		// measured again on this pair rather than assumed.
		ID: "admin/realms-admin/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update the top-level information of the realm",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}",
		Fixture:   "admin-token-realm-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-realm-update",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"displayName":"Probed"}`),
		},
		AssertHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/realms-admin/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: delete the realm",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}",
		Fixture:   "admin-token-realm-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/gloak-probe-realm-delete",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},
	{
		// **"Realm not found." keeps its full stop**, where the protocol side
		// spells the same missing realm "Realm does not exist" without one.
		// And it is 404 to every caller, including one with no admin role: the
		// realm is resolved before anybody is judged.
		ID: "admin/realms-admin/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get the top-level representation, unknown realm",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// No Operation: a rejection, by the rule admin/users/unknown-realm states.
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-no-such-realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// errorMessage, and **no full stop** - where the 404 above has one.
		// Same resource, two error families, which is what clients and users
		// already do and what a shared helper would flatten.
		ID: "admin/realms-admin/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: import a realm, duplicate name",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"realm":"gloak-probe-realm","enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/realms-admin/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: import a realm, no name",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **400, not 403.** The master realm cannot be deleted at all, by
		// anybody, and the refusal is about the realm rather than the caller -
		// which is why it is the errorMessage family and not the generic 403.
		ID: "admin/realms-admin/delete-master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: delete the realm, master",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// -----------------------------------------------------------------------
	// P4's second cut: the remaining eleven operations of the Realms Admin tag
	// and the whole of the Key tag. Measured 2026-08-29 against a live 26.7.1.
	// -----------------------------------------------------------------------
	{
		// **Four keys, where the JWKS beside it publishes two.** The two OCT
		// entries carry a kid and nothing else; the two RSA ones carry the
		// public key, its certificate and the certificate's notAfter in
		// milliseconds.
		ID: "admin/key/realm-keys",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Key: get the keys of the realm",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/keys",
		Fixture:       "admin-token",
		PristineRealm: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/keys",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// Everything derived from the key material varies per container start,
		// and so does providerId, which is a component id Keycloak mints at
		// random. What this case pins is the field set, their order, the
		// algorithm metadata, and the key order of `active` - which is a Java
		// map javamap reproduces and not something Go's sorted map keys would.
		Volatile: []string{
			"active/*",
			"keys/*/providerId",
			"keys/*/kid",
			"keys/*/publicKey",
			"keys/*/certificate",
			"keys/*/validTo",
		},
		// The array is ordered by providerId, which the line above has just
		// masked, so its order is not reproducible - measured on two realms
		// whose algorithm orders differ. The JWKS case takes the same retreat
		// for the same reason.
		Unordered: []string{"keys"},
	},
	{
		ID: "admin/key/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Key: get the keys of the realm, unknown realm",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-no-such-realm/keys",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **PristineRealm, and the emptiness is why.** The body is the whole of
		// gloak-probe-dg's default-groups list, and
		// admin/realms-admin/default-group-add puts a group into that very list
		// three cases later. On a shared container this golden is [] only
		// because the catalogue happens to read before it writes - the exact
		// disease F40 realised, one realm along. See F53.
		ID: "admin/realms-admin/default-groups-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get a realm's default groups",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/default-groups",
		PristineRealm: true,
		Fixture:       "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-dg/default-groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The entry is the shape a user's group listing sends**: no
		// subGroupCount, no attributes, no access.
		ID: "admin/realms-admin/default-groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get a realm's default groups, populated",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-default-groups-full",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-dg-full/default-groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// No order reproduces both measurements: three groups added zzz, aaa,
		// mmm came back in that order, and a parent added before its child came
		// back after it.
		Unordered: []string{"."},
	},
	{
		// The 204 carries Cache-Control: no-cache and **no X-Frame-Options**,
		// because a PUT with no body declares no Content-Type. The client-policy
		// PUT further down is the other way round on both counts.
		ID: "admin/realms-admin/default-group-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a default group",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/default-groups/{groupId}",
		Fixture:   "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/gloak-probe-dg/default-groups/{{dg_top}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Type"},
	},
	{
		// Removing a group that is **not** a default group is a 204, not a 404.
		// This realm's fixture makes neither group a default one.
		ID: "admin/realms-admin/default-group-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: remove a default group",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/default-groups/{groupId}",
		Fixture:   "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/gloak-probe-dg/default-groups/{{dg_child}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Type"},
	},
	{
		// **"Group not found", not "Could not find group by id"** - the
		// membership routes' spelling for the same missing group.
		ID: "admin/realms-admin/default-group-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a default group, unknown group",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/gloak-probe-dg/default-groups/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The sixth shape of a group**: the single read minus its access
		// block, measured side by side on the same group.
		ID: "admin/realms-admin/group-by-path",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get a group by path",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/group-by-path/{path}",
		Fixture:   "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-dg/group-by-path/gloak-probe-dg-top",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A nested path walks the tree, and a leading slash is optional: this
		// one sends none and the group's own path comes back with one.
		ID: "admin/realms-admin/group-by-path-nested",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get a group by path, nested",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-dg/group-by-path/gloak-probe-dg-top/gloak-probe-dg-child",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A **twelfth** spelling of not-found on this API, and the third for a
		// group. It is answered before the caller is judged, so a caller
		// holding no admin role gets it too.
		ID: "admin/realms-admin/group-by-path-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get a group by path, no such path",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-default-groups",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-dg/group-by-path/gloak-probe-no-such-group",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **Not PristineRealm, and the reason is a fact rather than a
		// preference.** Four later cases PUT this realm's profiles and two more
		// PUT its policies, so the four reads on gloak-probe-profiles - this
		// one, its -global sibling and the two policy reads - are read-before-
		// write on a shared container. They survive because every one of those
		// writes writes the *empty* state: two send `{"profiles":[]}` or
		// `{"policies":[]}` and the rest are refused. Give any of those PUTs a
		// non-empty body and these four goldens become wrong, so change the
		// body and the flag together. Swept 2026-08-29; see F53.
		ID: "admin/realms-admin/client-profiles-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client profiles",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-policies/profiles",
		Fixture:   "admin-token-client-profiles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A profile written without a description comes back without the key,
		// which is what puts omitempty on that field and not on `executors`.
		ID: "admin/realms-admin/client-profiles",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client profiles, one written",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles-written",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-profiles-written/client-policies/profiles",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The ten built-in profiles, 9 KB of them, and the reason the constant
		// is recorded bytes rather than Go structs: several of the
		// configurations in here have keys that are not in alphabetical order,
		// and Go sorts a map's keys.
		ID: "admin/realms-admin/client-profiles-global",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client profiles, including the global ones",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Query:   map[string]string{"include-global-profiles": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The 204 carries no Cache-Control at all**, where the default-groups
		// PUT above carries no-cache. Two PUTs in one cut, opposite answers,
		// which is what "pinned per endpoint" means. It does carry
		// X-Frame-Options, because this request declares application/json.
		ID: "admin/realms-admin/client-profiles-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client profiles",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-policies/profiles",
		Fixture:   "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"profiles":[]}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		// **A body Keycloak cannot read is the RFC 6749 shape here** and the
		// errorMessage shape on POST /admin/realms. Two ways to send bad JSON
		// to one resource family, two error families.
		ID: "admin/realms-admin/client-profiles-malformed",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client profiles, malformed body",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`nope`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **An absent body is a 400 here and a 500 on PUT /admin/realms/{r}.**
		// Same verb, neighbouring routes, and a shared decoder gets one wrong.
		ID: "admin/realms-admin/client-profiles-no-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client profiles, no body",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Recorded rather than Implemented: reproducing this means reproducing
		// Jackson's parser positions - the column is a function of the request
		// body - and PUT /admin/realms/{realm} does not reproduce its own copy
		// of this error either. Gloak ignores the field and answers 204.
		ID: "admin/realms-admin/client-profiles-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client profiles, unrecognised field",
			Retrieved: "2026-08-29",
		},
		Status:  Recorded,
		Reason:  "the message carries a Jackson line and column computed from the request body; Gloak ignores unknown fields here, as PUT /admin/realms/{realm} does",
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/profiles",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"nosuchfield":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/realms-admin/client-policies-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client policies",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-policies/policies",
		Fixture:   "admin-token-client-profiles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-profiles/client-policies/policies",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/realms-admin/client-policies",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client policies, one written",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-policies-written",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-policies-written/client-policies/policies",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// 26.7.1 ships no global policies where it ships ten global profiles.
		// The key is still added by the parameter.
		ID: "admin/realms-admin/client-policies-global",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get client policies, including the global ones",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-profiles/client-policies/policies",
			Query:   map[string]string{"include-global-policies": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/realms-admin/client-policies-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client policies",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-policies/policies",
		Fixture:   "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/policies",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"policies":[]}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		// The one cross-reference a policy body has, and the one validation
		// this cut can perform out of the realm's own state.
		ID: "admin/realms-admin/client-policies-unknown-profile",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client policies, unknown profile",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-profiles",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-profiles/client-policies/policies",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"policies":[{"name":"gloak-probe-bad-policy","conditions":[],` +
				`"profiles":["gloak-probe-no-such-profile"]}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A 501 is this endpoint's whole contract on a default 26.7.1.**
		// CLIENT_TYPES is a disabled preview feature, the same situation as
		// GET .../client-secret/rotated's permanent 404, and like it this is
		// the operation served rather than a stub.
		ID: "admin/realms-admin/client-types",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: list client types",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-types",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-types",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/realms-admin/client-types-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: update client types",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-types",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/client-types",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"global-client-types":[],"realm-client-types":[]}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The realm is resolved before the feature check, which is itself
		// before the authorization check. This pins the first of the three.
		ID: "admin/realms-admin/client-types-unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: list client types, unknown realm",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-no-such-realm/client-types",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ---------------------------------------------------------------------
	// P5's first cut: client scopes, the realm's two default sets and a
	// client's two. See docs/superpowers/plans/2026-08-29-p5-client-scopes.md.
	//
	// `client-templates` is a deprecated path alias for `client-scopes`. The
	// vendored description counts its five operations separately, so they are
	// five cases here rather than a note, and each one is measured through the
	// alias rather than assumed from its sibling.
	// ---------------------------------------------------------------------
	{
		// PristineRealm because the body is every client scope in the realm.
		// Two later cases create one and one deletes one, and this case's
		// number is the whole point of it.
		//
		// Unordered at the root because the fifteen come back in a Java set's
		// order, and on each scope's protocolMappers for the same reason. The
		// ids are **not** masked: they are per-container UUIDs, so they are
		// Volatile, but the sort has to run on masked bytes to be stable -
		// which it does, Normalize before SortUnordered.
		ID: "admin/client-scopes/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get client scopes belonging to the realm",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/client-scopes",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// protocolMappers was masked whole until F59 was fixed, and that was a
		// limitation of Case.Unordered rather than a decision: sortArray decoded
		// the array it matched in one go, so a path matching the root consumed
		// the document and `*/protocolMappers` was never visited - silently. The
		// walk now runs deepest path first, so both are sorted and both are
		// asserted.
		//
		// Both orders need sorting and neither is contract. The scope order is a
		// Java set's, and the mapper order inside a scope is too - six of the
		// fifteen scopes came back with a different mapper order on two container
		// starts. Only the ids are masked: the scope's own, and each mapper's,
		// both per-container UUIDs. The sort has to run on masked bytes to be
		// stable, which it does - Normalize before SortUnordered.
		//
		// So the thirty-five bootstrapped protocol mappers are now under a
		// golden: their names, their protocolMapper types, their consentRequired
		// flags and every key of their config, in Keycloak's key order.
		// TestBootstrappedClientScopeMappers in internal/admin asserts one
		// scope's fourteen directly and keeps doing so; this is the other
		// thirty-four.
		Volatile:  []string{"*/id", "*/protocolMappers/*/id"},
		Unordered: []string{".", "*/protocolMappers"},
	},
	{
		// The alias serves the identical body. Measured, not assumed: this is
		// the same request through the other spelling and its golden is
		// recorded separately.
		ID: "admin/client-scopes/list-templates",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get client scopes belonging to the realm (client-templates)",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/client-templates",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// protocolMappers was masked whole until F59 was fixed, and that was a
		// limitation of Case.Unordered rather than a decision: sortArray decoded
		// the array it matched in one go, so a path matching the root consumed
		// the document and `*/protocolMappers` was never visited - silently. The
		// walk now runs deepest path first, so both are sorted and both are
		// asserted.
		//
		// Both orders need sorting and neither is contract. The scope order is a
		// Java set's, and the mapper order inside a scope is too - six of the
		// fifteen scopes came back with a different mapper order on two container
		// starts. Only the ids are masked: the scope's own, and each mapper's,
		// both per-container UUIDs. The sort has to run on masked bytes to be
		// stable, which it does - Normalize before SortUnordered.
		//
		// So the thirty-five bootstrapped protocol mappers are now under a
		// golden: their names, their protocolMapper types, their consentRequired
		// flags and every key of their config, in Keycloak's key order.
		// TestBootstrappedClientScopeMappers in internal/admin asserts one
		// scope's fourteen directly and keeps doing so; this is the other
		// thirty-four.
		Volatile:  []string{"*/id", "*/protocolMappers/*/id"},
		Unordered: []string{".", "*/protocolMappers"},
	},
	{
		// A created scope: five keys, no description and no protocolMappers,
		// and `attributes` present and empty. The id is the fixture's own
		// constant, so nothing here is Volatile.
		ID: "admin/client-scopes/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get representation of the client scope",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}",
		Fixture:   "admin-token-client-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/client-scopes/read-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get representation of the client scope (client-templates)",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}",
		Fixture:   "admin-token-client-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// 201, empty body, absolute Location - and **Cache-Control: no-cache**,
		// where POST /clients has none. Two creates on one API, one with the
		// header and one without.
		ID: "admin/client-scopes/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a new client scope",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-scopes",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"a5c09e00-0000-4000-8000-0000000000f1",` +
				`"name":"gloak-probe-scope-create","protocol":"openid-connect"}`),
		},
		AssertHeaders:       []string{"Cache-Control", "Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/client-scopes/create-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a new client scope (client-templates)",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-templates",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-templates",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"a5c09e00-0000-4000-8000-0000000000f2",` +
				`"name":"gloak-probe-template-create","protocol":"openid-connect"}`),
		},
		AssertHeaders:       []string{"Cache-Control", "Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// 204 with **no** Cache-Control, where the delete beside it carries
		// one. Pinned per endpoint, like every other Cache-Control here.
		ID: "admin/client-scopes/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: update the client scope",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-scopes/{client-scope-id}",
		Fixture:   "admin-token-client-scope-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000002",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-scope-updated","description":"after"}`),
		},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/client-scopes/update-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: update the client scope (client-templates)",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-templates/{client-scope-id}",
		Fixture:   "admin-token-client-template-update",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000004",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-template-updated"}`),
		},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		// The 204 carries Cache-Control where the update's does not, and no
		// X-Frame-Options because the request declared no Content-Type.
		ID: "admin/client-scopes/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: delete the client scope",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-scopes/{client-scope-id}",
		Fixture:   "admin-token-client-scope-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000003",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/client-scopes/delete-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: delete the client scope (client-templates)",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-templates/{client-scope-id}",
		Fixture:   "admin-token-client-template-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000005",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The 404 the /client-scopes/{id} routes answer, and it is not the one
		// the realm's and the client's default-scope routes answer for the
		// very same missing object. Both spellings are in this catalogue on
		// purpose.
		ID: "admin/client-scopes/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get a client scope that does not exist",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// A path segment that is not a UUID at all is the same 404, not a 400.
		ID: "admin/client-scopes/read-malformed-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: get a client scope by an id that is not a UUID",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/not-a-uuid",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// An absent protocol and an invalid one give the identical message.
		ID: "admin/client-scopes/create-without-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create with no protocol",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-scope-noproto"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A name that is present and empty is a 400 naming the empty string,
		// with the quotes escaped into the message.
		ID: "admin/client-scopes/create-empty-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create with an empty name",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"","protocol":"openid-connect"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A name that is **absent** is a 500, and it is checked before the
		// protocol - `{}` answers about the name where `{"name":"x"}` answers
		// about the protocol. Keycloak's own defect, reproduced.
		ID: "admin/client-scopes/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create with no name",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"protocol":"openid-connect"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The name conflicts whatever the protocol says: the same name under
		// the other protocol is still 409.
		ID: "admin/client-scopes/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a client scope whose name is taken",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-scope",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-scope","protocol":"saml"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// The realm's own two default sets. Tagged Realms Admin by the
	// description and guarded by the clients role family, which is why they
	// are built here and counted there.
	{
		// Nine on a pristine realm, not six: the three saml scopes are in it
		// and are filtered out only when an openid-connect client inherits.
		// The order is insertion order and it is reproducible - four
		// measurements across two container starts and two realms agreed - so
		// it is asserted rather than sorted away.
		ID: "admin/realms-admin/default-default-client-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get the realm's default default client scopes",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/default-default-client-scopes",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/default-default-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
	},
	{
		ID: "admin/realms-admin/default-optional-client-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: get the realm's default optional client scopes",
			Retrieved: "2026-08-29",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/default-optional-client-scopes",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/default-optional-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
	},
	{
		ID: "admin/realms-admin/default-default-client-scope-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a client scope to the realm's defaults",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/default-default-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-realm-scope-add",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/default-default-client-scopes/a5c09e00-0000-4000-8000-000000000006",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/realms-admin/default-default-client-scope-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: remove a client scope from the realm's defaults",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/default-default-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-realm-scope-drop",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/default-default-client-scopes/a5c09e00-0000-4000-8000-000000000007",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/realms-admin/default-optional-client-scope-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a client scope to the realm's optionals",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-realm-scope-add-opt",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/default-optional-client-scopes/a5c09e00-0000-4000-8000-000000000008",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/realms-admin/default-optional-client-scope-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: remove a client scope from the realm's optionals",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/default-optional-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-realm-scope-drop-opt",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/default-optional-client-scopes/a5c09e00-0000-4000-8000-000000000009",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The **second** PUT of one scope is a 409, where the client-level PUT
		// beside it is idempotent. The fixture has already added this one.
		ID: "admin/realms-admin/default-default-client-scope-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a client scope that is already a realm default",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-realm-scope-drop",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/default-default-client-scopes/a5c09e00-0000-4000-8000-000000000007",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The realm routes' 404 for a missing client scope is "Client scope
		// not found", where /client-scopes/{id} answers "Could not find client
		// scope" for the very same object.
		ID: "admin/realms-admin/default-default-client-scope-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Realms Admin: add a client scope that does not exist",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodPut,
			Path:    "/admin/realms/master/default-default-client-scopes/00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// A client's own two sets. Tagged Clients by the description; the
	// resource is a client scope, so P5 builds them.
	{
		// Two keys per entry, where the realm's listing carries three. The
		// order is a Java set's and is **not** reproducible - two clients
		// created minutes apart came back with roles and profile swapped - so
		// this one is sorted where the realm's is asserted in order.
		ID: "admin/clients/default-client-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the client's default client scopes",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/default-client-scopes",
		// PristineRealm because this body is a function of the realm's own
		// default sets at the moment the fixture created its client, and two
		// cases earlier in the catalogue add a scope to those sets. Recorded
		// against the shared container it came back with seven entries and
		// replayed against a fresh one with six. That is F40's shape on a body
		// that does not look realm-wide, which is exactly what follow-up F53
		// asks about.
		PristineRealm: true,
		Fixture:       "admin-token-client-scopes-read",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000a/default-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
		Unordered:     []string{"."},
	},
	{
		ID: "admin/clients/optional-client-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the client's optional client scopes",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes",
		// PristineRealm because this body is a function of the realm's own
		// default sets at the moment the fixture created its client, and two
		// cases earlier in the catalogue add a scope to those sets. Recorded
		// against the shared container it came back with seven entries and
		// replayed against a fresh one with six. That is F40's shape on a body
		// that does not look realm-wide, which is exactly what follow-up F53
		// asks about.
		PristineRealm: true,
		Fixture:       "admin-token-client-scopes-read",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000a/optional-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
		Unordered:     []string{"."},
	},
	{
		ID: "admin/clients/default-client-scope-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: add a default client scope to the client",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/default-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-client-scope-attach",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000b/default-client-scopes/" +
				"a5c09e00-0000-4000-8000-00000000000b",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/clients/default-client-scope-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: remove a default client scope from the client",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/default-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-client-scope-detach",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000c/default-client-scopes/" +
				"a5c09e00-0000-4000-8000-00000000000c",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/clients/optional-client-scope-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: add an optional client scope to the client",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-client-scope-attach-opt",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000d/optional-client-scopes/" +
				"a5c09e00-0000-4000-8000-00000000000d",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		ID: "admin/clients/optional-client-scope-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: remove an optional client scope from the client",
			Retrieved: "2026-08-29",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/optional-client-scopes/{clientScopeId}",
		Fixture:   "admin-token-client-scope-detach-opt",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000e/optional-client-scopes/" +
				"a5c09e00-0000-4000-8000-00000000000e",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The client is resolved before the caller's write role and the scope
		// after it, so an unknown client on this route is "Could not find
		// client" - the clients family's spelling, not either of the client
		// scope ones.
		ID: "admin/clients/default-client-scopes-unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: get the default client scopes of a client that does not exist",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/default-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// And a scope that does not exist on a client that does is the third
		// spelling again: "Client scope not found".
		ID: "admin/clients/default-client-scope-unknown-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: add a default client scope that does not exist",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-scopes-read",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000a/default-client-scopes/" +
				"00000000-0000-0000-0000-000000000000",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// `{}` is what says the **order** of the two checks. A body with no
		// name and no protocol answers about the name - the 500 - where
		// `{"name":"x"}` answers about the protocol. Without this case a
		// mutation that swaps the two survives every other case in this cut,
		// which is exactly what it did before this case was added.
		ID: "admin/client-scopes/create-empty-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create from an empty JSON object",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **Naming either list suppresses inheritance on both.** The fixture's
		// client names `defaultClientScopes` and says nothing about the
		// optional one, and its optional list is empty rather than the realm's
		// five. A per-list nil check gives the five, and nothing else in this
		// cut can tell the difference.
		ID: "admin/clients/optional-client-scopes-not-inherited",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: a client naming only its default scopes inherits no optional ones",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-named-scopes",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000000f/optional-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A protocol mismatch is a silent no-op.** The fixture PUT a saml
		// scope onto this openid-connect client and got 204; the list still
		// holds the one scope the client was created with. Asserting the 204
		// alone does not see it - the write answers 204 either way - so this
		// case reads the list afterwards.
		ID: "admin/clients/default-client-scopes-protocol-mismatch",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: a saml client scope offered to an openid-connect client",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-saml-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000010/default-client-scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id"},
	},
	{
		// **The PUT merged.** The fixture created this scope with a description
		// and two attributes and then sent a body naming only its `name`; both
		// survived. A role updated the same way loses its description, so
		// copying updateRealmRole's shape here is the mistake this case
		// catches - and the update case's own 204 cannot see it.
		ID: "admin/client-scopes/read-merged",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: read a client scope after a partial update",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "admin-token-client-scope-merged",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000010",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	// -----------------------------------------------------------------------
	// P5 cut B: protocol mappers. Twenty-one operations - three families of
	// seven over two containers - plus the behaviours their status codes
	// cannot show.
	//
	// Appended at the end of adminCases and nowhere else: another stream is
	// editing cases in the middle of this file, and the end is the one place
	// two branches cannot both edit.
	//
	// The `client-templates` spelling is measured **byte-identical** to
	// `client-scopes` on all seven, headers included, with the one exception
	// its parent family has: POST echoes the path it was called on into
	// Location. So the seven template cases exist to pin the aliasing, and the
	// only one of them that could ever differ is the create.
	// -----------------------------------------------------------------------
	{
		// Two mappers, one per protocol, and the array comes back in **no
		// reproducible order** - Keycloak's own order inside a container moved
		// between two container starts on six of the fifteen bootstrapped
		// scopes. Unordered names the root, which is where the array is.
		ID: "admin/protocol-mappers/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client scope's mappers",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
	},
	{
		ID: "admin/protocol-mappers/list-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client scope's mappers (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000011/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
	},
	{
		ID: "admin/protocol-mappers/list-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client's own mappers",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000011/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
	},
	{
		// Six keys in a fixed order, nothing omitempty, `config` present and
		// `consentRequired` always false.
		ID: "admin/protocol-mappers/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: one mapper of a client scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/read-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: one mapper of a client scope (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/read-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: one mapper of a client",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-client",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000011" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000004",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The filter is on the mapper's own `protocol`, not the container's.**
		// This scope is `openid-connect` and holds one `saml` mapper, so asking
		// for `saml` answers the one and asking for `openid-connect` answers
		// the other. A filter reading the scope's protocol would answer both
		// for one value and neither for the other, and this case is the pair
		// that says so - see by-protocol-empty below for the other half.
		ID: "admin/protocol-mappers/by-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client scope's mappers of one protocol",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/protocol/{protocol}",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/protocol/saml",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/by-protocol-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client scope's mappers of one protocol (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/protocol/{protocol}",
		Fixture:   "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/protocol/saml",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/by-protocol-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client's mappers of one protocol",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/protocol/{protocol}",
		Fixture:   "admin-token-mapper-client",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000011" +
				"/protocol-mappers/protocol/openid-connect",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **An unknown protocol is 200 and `[]`, not a 400.** The segment is
		// never validated against anything; it is compared to what each mapper
		// stored, and a mapper's own `protocol` is not validated either - a
		// create with `"protocol":"bogus"` is a 201.
		ID: "admin/protocol-mappers/by-protocol-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: an unknown protocol answers an empty array",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/protocol/gloak-no-such-protocol",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// 201, `Cache-Control: no-cache`, an absolute Location ending in the
		// id **the body asked for**, and **no Content-Type at all**.
		ID: "admin/protocol-mappers/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add a mapper to a client scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-scope-create",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000012" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-0000000000f1",` +
				`"name":"gloak-probe-mapper-new","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-new"}}`),
		},
		AssertHeaders:       []string{"Cache-Control", "Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// **The alias echoes its own path.** This is the one operation of the
		// seven where the two spellings are distinguishable in a response:
		// Location comes back under /client-templates. Building it from a
		// constant rather than from r.URL.Path sends a caller of the
		// deprecated path to the other one, and only this case can tell.
		ID: "admin/protocol-mappers/create-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add a mapper to a client scope (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-template-create",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000013" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-0000000000f2",` +
				`"name":"gloak-probe-mapper-tmpl","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-tmpl"}}`),
		},
		AssertHeaders:       []string{"Cache-Control", "Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/protocol-mappers/create-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add a mapper to a client",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models",
		Fixture:   "admin-token-mapper-client-create",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000012" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-0000000000f3",` +
				`"name":"gloak-probe-mapper-cl","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-cl"}}`),
		},
		AssertHeaders:       []string{"Cache-Control", "Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// 204 **with** Cache-Control, unlike PUT /client-scopes/{id} next door,
		// which carries none. Pinned per endpoint, as every Cache-Control on
		// this API is.
		ID: "admin/protocol-mappers/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: update a client scope's mapper",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-scope-update",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000014" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000005",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-000000000005",` +
				`"name":"gloak-probe-mapper-update","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-after"}}`),
		},
		AssertHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/update-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: update a client scope's mapper (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-template-update",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000015" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000006",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-000000000006",` +
				`"name":"gloak-probe-mapper-update","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-after"}}`),
		},
		AssertHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/protocol-mappers/update-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: update a client's mapper",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-client-update",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000013" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000007",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9a99e400-0000-4000-8000-000000000007",` +
				`"name":"gloak-probe-mapper-update","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper",` +
				`"config":{"claim.name":"gloak-after"}}`),
		},
		AssertHeaders: []string{"Cache-Control"},
	},
	{
		// 204 with Cache-Control and **no X-Frame-Options**: the delete sends
		// no Content-Type, and that is what decides the header - the rule
		// httpx.WriteNoContent carries.
		ID: "admin/protocol-mappers/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: delete a client scope's mapper",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-scope-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000016" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000008",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/protocol-mappers/delete-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: delete a client scope's mapper (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-template-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000017" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-000000000009",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "admin/protocol-mappers/delete-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: delete a client's mapper",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/models/{id}",
		Fixture:   "admin-token-mapper-client-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000014" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-00000000000a",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// **204, not 201, and no Location** - where the single create beside it
		// is 201 with one. Same resource, same verb, one path segment apart.
		ID: "admin/protocol-mappers/add-models",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add several mappers to a client scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-scopes/{client-scope-id}/protocol-mappers/add-models",
		Fixture:   "admin-token-mapper-scope-add",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000018" +
				"/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"9a99e400-0000-4000-8000-0000000000f4",` +
				`"name":"gloak-probe-mapper-batch-a","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{"claim.name":"a"}},` +
				`{"id":"9a99e400-0000-4000-8000-0000000000f5",` +
				`"name":"gloak-probe-mapper-batch-b","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{"claim.name":"b"}}]`),
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		ID: "admin/protocol-mappers/add-models-template",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add several mappers to a client scope (client-templates)",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-templates/{client-scope-id}/protocol-mappers/add-models",
		Fixture:   "admin-token-mapper-template-add",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000019" +
				"/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"9a99e400-0000-4000-8000-0000000000f6",` +
				`"name":"gloak-probe-mapper-batch-c","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{"claim.name":"c"}}]`),
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		ID: "admin/protocol-mappers/add-models-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add several mappers to a client",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/protocol-mappers/add-models",
		Fixture:   "admin-token-mapper-client-add",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000015" +
				"/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"9a99e400-0000-4000-8000-0000000000f7",` +
				`"name":"gloak-probe-mapper-batch-d","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{"claim.name":"d"}}]`),
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		// **A fifteenth spelling of not-found.** `Model not found` names
		// neither the resource nor the key it was looked up by, and it is the
		// answer for a path segment that is not a UUID as well as for one that
		// is and is unknown.
		ID: "admin/protocol-mappers/read-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a mapper id that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-0000000000ff",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The container's own 404, which is the parent family's string and not
		// this one's: `Could not find client scope`.
		ID: "admin/protocol-mappers/read-unknown-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client scope that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-0000000000fe" +
				"/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// And the client family's, which is a third string again for the same
		// missing container: `Could not find client`.
		ID: "admin/protocol-mappers/read-unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a client that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-0000000000fe" +
				"/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **A 404 on a create.** The `protocolMapper` is looked up in the
		// server's provider registry and the answer is about the lookup, not
		// about the request - and it is checked **first**, before the name and
		// before the protocol, which is why an empty body answers this rather
		// than answering about the name.
		ID: "admin/protocol-mappers/create-unknown-provider",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a protocolMapper no provider is registered for",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-mapper-bad","protocol":"openid-connect",` +
				`"protocolMapper":"gloak-no-such-provider"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The same 404 for an **empty body object**, which is what says the
		// provider check runs before everything else. `{}` answers about the
		// provider where `POST /client-scopes` answers about the name.
		ID: "admin/protocol-mappers/create-empty-object",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: an empty object answers about the provider",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The one response on this family that carries none of the five
		// security headers.** A body with a valid provider and no `name` is a
		// 409 about a duplicate that does not exist, and it never reaches
		// Keycloak's filter chain - where the other 409 on the same route
		// carries all five. AssertAbsentHeaders is the whole point of the case;
		// the body alone would pass with the headers wrongly present.
		ID: "admin/protocol-mappers/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a body with no name",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Cache-Control", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
	},
	{
		// An absent **protocol** is the same 409 as an absent name, and the
		// same missing headers. Two required fields, one message about neither
		// of them.
		ID: "admin/protocol-mappers/create-without-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a body with no protocol",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-mapper-noproto",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Cache-Control", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
	},
	{
		// The **other** 409, in the errorMessage shape and with all five
		// security headers. Two conflicts on one route, two shapes, two header
		// sets.
		ID: "admin/protocol-mappers/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a name the container already holds",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope-dup",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000001a" +
				"/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-mapper-dup","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{}}`),
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// A **third** conflict spelling, on the batch route:
		// `Protocol mapper name must be unique per protocol`, in the OAuth
		// shape where the single create's is the errorMessage one.
		ID: "admin/protocol-mappers/add-models-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a batch naming a name already held",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope-dup",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000001a" +
				"/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-mapper-dup","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper","config":{}}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **What the 201 cannot show.** The fixture created one mapper asking
		// for `id.token.claim` and `access.token.claim` and a key whose value
		// was `""`, with `consentRequired: true`; and a second, through
		// add-models, on a provider that mirrors only one of the two.
		//
		// So this body carries four assertions no status code does: the empty
		// key is gone, both mirrors were appended to the first, **only
		// `introspection.token.claim`** was appended to the second, and
		// `consentRequired` is false on both.
		//
		// A mirroring rule written as one flag, or as "every oidc-* provider",
		// passes every other case in this cut and fails here. **It did not,
		// until the fixture's second mapper was given `id.token.claim` as
		// well**: with no source key to mirror, both mutations produce exactly
		// the right bytes, and both survived. Two survivors, one fixture line.
		ID: "admin/protocol-mappers/read-created",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a created mapper's config after the server filled it in",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-created",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000001b" +
				"/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
	},
	{
		// **What the 204 cannot show.** The fixture's PUT renamed the mapper,
		// moved it to `saml` and set `consentRequired: true`; this body says
		// the name, the protocol and the flag are all unchanged and only
		// `protocolMapper` and `config` moved - and that the config was
		// **replaced**, since `user.attribute` is gone rather than merged
		// through.
		//
		// Writing the whole representation back is the obvious implementation.
		// It passes the update case's own 204 and fails here.
		ID: "admin/protocol-mappers/read-updated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a mapper after a PUT",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-updated",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000001c" +
				"/protocol-mappers/models/9a99e400-0000-4000-8000-00000000000e",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **What the 409 cannot show.** The fixture's add-models array named a
		// fresh mapper first and a duplicate second. This listing holds the
		// one mapper the scope started with and **not** the fresh one, which is
		// what says the batch validates before it applies.
		//
		// An implementation that writes as it goes answers the same 409 and
		// leaves an extra row. Only this case sees it.
		ID: "admin/protocol-mappers/list-after-batch-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a rejected batch writes nothing",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-batch-conflict",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000001d" +
				"/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`query-clients` is refused here and served one level up.** On
		// `GET /client-scopes` it is admitted and answered `200 []` - the
		// client listing's shape, and one of the three places this API answers
		// a weaker caller with a shorter list. On every protocol-mapper route
		// it is a flat 403. So the coarse gate on this family is two roles,
		// not the parent's three, and widening it to clientsReadRoles for
		// symmetry is the tidy-up that breaks it.
		//
		// The scope id names nothing on purpose: the gate runs **before** the
		// container is resolved, so this caller gets 403 rather than the 404 a
		// view-clients caller gets for the same path. That is the second thing
		// the case pins, and it is why it needs no scope fixture.
		//
		// Added after a mutation survived: swapping clientScopeMapperReadRoles
		// for clientsReadRoles passed every other case in this cut.
		ID: "admin/protocol-mappers/list-to-a-query-clients-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a caller holding query-clients",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-clients",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-0000000000fd" +
				"/protocol-mappers/models",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The batch route checks the provider too, and answers the same 404 the
		// single create does. Added after a mutation survived: deleting the
		// provider check from addProtocolMappers passed every other case in
		// this cut, because every other batch body names a registered one.
		ID: "admin/protocol-mappers/add-models-unknown-provider",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: a batch naming a provider that is not registered",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-mapper-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000011" +
				"/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-mapper-batch-bad","protocol":"openid-connect",` +
				`"protocolMapper":"gloak-no-such-provider"}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	// ---------------------------------------------------------------------
	// P5 cut C: scope mappings. Thirty-three operations, eleven behaviours,
	// three path spellings.
	//
	// The eleven under a client scope come first, then the eleven the
	// `client-templates` alias serves - which are measured **byte-identical**,
	// headers included, with none of the one exception the parent family and the
	// protocol mappers each had, because nothing on this tag mints a `Location`
	// for the two spellings to disagree about. The alias reads share the parent's
	// fixture and container for exactly that reason; the alias writes get their
	// own, because a write cannot be recorded twice against one container and
	// mean the same thing.
	//
	// Appended at the very end of the slice, as cut B's were.
	// ---------------------------------------------------------------------
	{
		ID: "admin/scope-mappings/all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the combined view of a container's scope mappings",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The role ids are minted by the server: a role create answers a
		// Location ending in the role's **name**, so nothing lets a fixture
		// choose one. The clientMappings key, its `id` and the mappings'
		// containerId are the fixture's own fixed client UUID and stay
		// asserted.
		Volatile: []string{"realmMappings/*/containerId", "clientMappings/*/mappings/*/id"},
	},
	{
		ID: "admin/scope-mappings/realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/realm-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm/available",
		PristineRealm: true,
		Fixture:       "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/realm-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the effective realm-level roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm/composite",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/add-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add realm-level roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-scope-add",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000022/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/remove-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove realm-level roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-scope-drop",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000023/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/client-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}/available",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/client-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's effective roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}/composite",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/add-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add one client's roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-scope-add-role",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000024/scope-mappings/clients/c11e0000-0000-4000-8000-000000000034",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/remove-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove one client's roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-scopes/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-scope-drop-role",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000025/scope-mappings/clients/c11e0000-0000-4000-8000-000000000035",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},

	{
		ID: "admin/scope-mappings/template-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the combined view of a container's scope mappings",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The role ids are minted by the server: a role create answers a
		// Location ending in the role's **name**, so nothing lets a fixture
		// choose one. The clientMappings key, its `id` and the mappings'
		// containerId are the fixture's own fixed client UUID and stay
		// asserted.
		Volatile: []string{"realmMappings/*/containerId", "clientMappings/*/mappings/*/id"},
	},
	{
		ID: "admin/scope-mappings/template-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-realm-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm/available",
		PristineRealm: true,
		Fixture:       "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-realm-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the effective realm-level roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm/composite",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-add-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add realm-level roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-template-add",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000026/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/template-remove-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove realm-level roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/realm",
		Fixture:   "scope-mappings-template-drop",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000027/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/template-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-client-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}/available",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-client-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's effective roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}/composite",
		Fixture:   "scope-mappings-scope",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-000000000031/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/template-add-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add one client's roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-template-add-role",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000028/scope-mappings/clients/c11e0000-0000-4000-8000-000000000038",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/template-remove-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove one client's roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/client-templates/{client-scope-id}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-template-drop-role",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/client-templates/a5c09e00-0000-4000-8000-000000000029/scope-mappings/clients/c11e0000-0000-4000-8000-000000000039",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},

	{
		ID: "admin/scope-mappings/owner-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the combined view of a container's scope mappings",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The role ids are minted by the server: a role create answers a
		// Location ending in the role's **name**, so nothing lets a fixture
		// choose one. The clientMappings key, its `id` and the mappings'
		// containerId are the fixture's own fixed client UUID and stay
		// asserted.
		Volatile: []string{"realmMappings/*/containerId", "clientMappings/*/mappings/*/id"},
	},
	{
		ID: "admin/scope-mappings/owner-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-realm-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the realm-level roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm/available",
		PristineRealm: true,
		Fixture:       "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-realm-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get the effective realm-level roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm/composite",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-add-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add realm-level roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm",
		Fixture:   "scope-mappings-client-add",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000022/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/owner-remove-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove realm-level roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/realm",
		Fixture:   "scope-mappings-client-drop",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000023/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/owner-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles in a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003a",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-client-available",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's roles that can be added",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}/available",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003a/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-client-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: get one client's effective roles",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}/composite",
		Fixture:   "scope-mappings-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000021/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003a/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		ID: "admin/scope-mappings/owner-add-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: add one client's roles to a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-client-add-role",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000024/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003d",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		ID: "admin/scope-mappings/owner-remove-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: remove one client's roles from a container's scope",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/scope-mappings/clients/{client}",
		Fixture:   "scope-mappings-client-drop-role",
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000025/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003e",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-client-role"}]`),
		},
		// A JSON request body, so this 204 carries X-Frame-Options. It carries
		// **no Cache-Control at all**, where the client-scope DELETE one level
		// up does - pinned per endpoint, like every other Cache-Control here.
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},

	{
		// **`composite` expands what is mapped and `available` does not.** The
		// fixture maps one composite realm role and nothing else; this body
		// holds it **and its child**, which was never mapped.
		//
		// An implementation that answered the direct list here passes
		// admin/scope-mappings/realm-composite, whose container has a
		// non-composite role mapped and where the two lists coincide.
		ID: "admin/scope-mappings/composite-expands-a-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a composite role in scope puts its children in scope",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-composite",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002a" +
				"/scope-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/containerId"},
	},
	{
		// The other half of the same measurement: the child that
		// admin/scope-mappings/composite-expands-a-composite finds **in** the
		// composite is still **in** this available list, because available
		// subtracts what is mapped directly rather than what is in scope.
		//
		// Computing available from the composite is the obvious tidy-up - the
		// two reads look like complements - and it is what this case rules out.
		ID: "admin/scope-mappings/available-keeps-a-reachable-child",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: available is the complement of the direct list",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "scope-mappings-composite",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002a" +
				"/scope-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// **`briefRepresentation` is honoured by `.../composite` alone**, which
		// is the user role-mapping family's rule confirmed on a new family - the
		// first time one of this API's parameter rules has generalised rather
		// than inverted. `false` grows an `attributes` key; the six other reads
		// on this family ignore the parameter entirely.
		//
		// Plumbing the parameter through all seven is the tidy-up that breaks
		// the six.
		ID: "admin/scope-mappings/composite-brief-false",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the effective realm-level roles, briefRepresentation=false",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm/composite",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/containerId"},
	},
	{
		// **`fullScopeAllowed` is a third input to `composite`, and only a
		// client has it.** The fixture's client maps nothing at all and this
		// body is **every realm role in the realm** - which is why the case is
		// PristineRealm.
		//
		// An implementation that computed composite from the mappings alone
		// answers `[]` here and passes every other case in this cut, because
		// every other container is a client scope or a client with the flag
		// off. Two of the six bootstrapped clients carry it, so this is not a
		// corner.
		ID: "admin/scope-mappings/full-scope-composite",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a fullScopeAllowed client has every role in scope",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "scope-mappings-full-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000026" +
				"/scope-mappings/realm/composite",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Unordered:     []string{"."},
		Volatile:      []string{"*/id", "*/containerId"},
	},
	{
		// **What the write's 204 cannot show.** The fixture posted a **client**
		// role to `.../scope-mappings/realm`, by id, with no `name` at all, and
		// got 204. This body says where it went: under `clientMappings`, not
		// under `realmMappings` and not nowhere.
		//
		// So the `realm` path segment is a precondition on nothing - the write
		// resolves by id, realm-wide, and stores the role under its own
		// container. Three implementations answer that 204 and only this read
		// tells them apart. Adding a `role.ClientID == ""` check to make the
		// write agree with its own path is the tidy-up this case refuses.
		ID: "admin/scope-mappings/realm-write-lands-under-its-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the realm write takes a client role and files it correctly",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-written",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002b" +
				"/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The realm write resolves by `id` and the client write by `name`.**
		// This is the realm write with a real role's **name** and no id: a
		// **500**, Keycloak's own defect, because the lookup is by id and a null
		// one reaches the store.
		//
		// The client write's mirror image is
		// admin/scope-mappings/client-write-without-a-name. One decoder that
		// accepted an entry when *either* key matched passes every happy path in
		// this cut and gets both of these wrong.
		ID: "admin/scope-mappings/realm-write-without-an-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the realm write with a name and no id",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"name":"gloak-probe-sm-realm-role"}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The other half: the client write with a real role's **id** and no
		// name is a 404, where the realm write with an id alone is a 204.
		ID: "admin/scope-mappings/client-write-without-a-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the client write with an id and no name",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-written",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002b" +
				"/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003f",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_client_role_id}}"}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// A role id that resolves to nothing: 404 `Role not found`, the same
		// spelling the user role-mapping writes answer and **not** the four
		// other not-found strings this API has for a role.
		ID: "admin/scope-mappings/unknown-role",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a role id that resolves to nothing",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"99999999-9999-4999-8999-999999999999"}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// An unknown container: `Could not find client scope`, the spelling
		// `/client-scopes/{id}` uses and not the `Client scope not found` the
		// two default-scope families answer for the same missing object.
		ID: "admin/scope-mappings/unknown-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a client scope that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-0000000000fe" +
				"/scope-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// An unknown `{client}` segment answers **`Could not find client`**,
		// where the role-mapping family's identical-looking segment answers
		// `Client not found`. Same missing client, two routes, two strings -
		// which is why mappingClientFromPath is not reused here.
		ID: "admin/scope-mappings/unknown-role-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a role container that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/clients/c11e0000-0000-4000-8000-0000000000fe",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The per-role check is the composite-write rule, not the
		// caller-relative one.** A `manage-clients` caller - which passes both
		// the coarse gate and the fine write check - is **403** mapping an
		// ordinary realm role that is not an admin role at all.
		//
		// mayGrantRole, the predicate the user and group families use, allows
		// this: the role is not one of the realm's admin roles, so nothing about
		// the caller's own rights is even consulted. Reusing it here is the
		// obvious move and this case is what refuses it.
		ID: "admin/scope-mappings/refused-realm-role",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a manage-clients caller mapping a realm role",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-narrow-caller",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002d" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{caller_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"{{sm_realm_role_id}}"}]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **`available` runs the write's predicate, so a weaker caller gets a
		// shorter list rather than a refusal.** The same `manage-clients` caller
		// that is 403 writing a realm role reads this list as `[]`, where a
		// caller holding `manage-realm` too sees every realm role in the realm.
		//
		// Fourth instance of "200 with a shorter list to a weaker caller" on
		// this API, and the one that says the set a caller may write is exactly
		// the set its own available read shows it.
		ID: "admin/scope-mappings/available-to-a-manage-clients-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: available to a caller that may map nothing in it",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-narrow-caller",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002d" +
				"/scope-mappings/realm/available",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **What the 403 cannot show.** The fixture's batch named a client role
		// this caller may map **first** and a realm role it may not second, and
		// got 403. This body says the first one was not written either.
		//
		// A loop that applied as it validated answers the same 403 and leaves a
		// row behind. Only this read sees it, and the array order is
		// load-bearing: with the refused entry first, a half-applying loop would
		// have written nothing and passed.
		ID: "admin/scope-mappings/refused-batch-writes-nothing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a batch validates before it applies",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-batch-refused",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-00000000002c" +
				"/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **415, and this family is where it became reachable.** These are the
		// first routes in Gloak whose `DELETE` carries a body, and a body needs
		// a Content-Type that whatever HTTP library the caller uses will pick
		// for itself.
		//
		// Measured on both verbs: `application/json` and **no Content-Type at
		// all** are accepted, and anything else is this 415. The absent case is
		// not an artefact - it was measured separately from a suppressed-header
		// probe that first looked like it.
		ID: "admin/scope-mappings/unsupported-media-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a write whose Content-Type is not JSON",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "text/plain",
			},
			Body: []byte(`[]`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The parse code follows the body's shape, not the endpoint.** An
		// object sent to an array endpoint is `unknown_error`; the truncated
		// array these routes actually want is `invalid_request`, which
		// decodeRoleList next door would answer `unknown_error` to.
		//
		// This is the second family to use cut B's shape classifier, and the
		// case that says it is in the path.
		ID: "admin/scope-mappings/wrong-shape-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: an object body on an array endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The truncated **array** - the shape these endpoints want - answers the
		// other code. The pair is what says the rule is the body's and not the
		// route's.
		ID: "admin/scope-mappings/truncated-array-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a truncated array body",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-scope",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-000000000021" +
				"/scope-mappings/realm",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **`query-clients` is admitted by the gate and refused after the
		// container**, which is why a scope that does not exist answers it
		// **404** and a scope that does answers 403. Asking only what it gets on
		// a scope that exists cannot tell the two arrangements apart, and this
		// project shipped the wrong one on the strength of exactly that on the
		// protocol-mapper family a day earlier.
		//
		// The scope id names nothing on purpose.
		ID: "admin/scope-mappings/to-a-query-clients-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a caller holding query-clients",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "narrow-caller-query-clients",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/client-scopes/a5c09e00-0000-4000-8000-0000000000fd" +
				"/scope-mappings/realm",
			Headers: map[string]string{"Authorization": "Bearer {{caller_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The combined view is the direct list, not the composite one, and not
		// the direct-scope set either.** The same client whose
		// `.../realm/composite` answers every realm role in the realm answers
		// `{}` here, because it has mapped nothing - **and it owns a role**,
		// which its `available` and `composite` reads would count and this one
		// measurably does not.
		//
		// The owned role is what makes this case bite. Without it the fixture's
		// client has nothing to distinguish `sc.mappings()` from the wider set,
		// and a mutation building this body out of the latter **survived** -
		// on every other container in this cut the two coincide.
		ID: "admin/scope-mappings/full-scope-all",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: the combined view of a fullScopeAllowed client",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-full-scope",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-000000000026" +
				"/scope-mappings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A client's own roles are in its own scope**, without ever being
		// mapped. The fixture's client has `fullScopeAllowed` off and maps
		// nothing of its own, and this read - its own roles against its own
		// scope - answers `[]` rather than the two roles it owns.
		//
		// An implementation whose available read subtracts only the mappings
		// answers both roles here and passes every other case in this cut,
		// because every other available read points at a *different* client.
		ID: "admin/scope-mappings/a-clients-own-roles-are-in-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Scope Mappings: a client's own roles need no mapping",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "scope-mappings-client",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/c11e0000-0000-4000-8000-00000000003a" +
				"/scope-mappings/clients/c11e0000-0000-4000-8000-00000000003a/available",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},

	// --- F84: the credentials array POST /users and PUT /users/{id} carry ---
	//
	// None of these claims an Operation. All three routes they touch are
	// claimed already; what they add is the part of those routes' contract that
	// was being served wrong.
	{
		// **The case F84 says no case for POST /users would have found.** The
		// create answers 201 with an empty body whether the array was honoured
		// or dropped, so the assertion is split: the fixture logs in as the
		// user - a step that simply fails when the password was not stored -
		// and this reads the credential the array produced.
		ID: "admin/users/inline-credential",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user with an inline credentials array",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		// **type is ignored and userLabel is dropped**, both in one body. The
		// entry asked for an `otp` labelled "office laptop"; the credential is
		// a `password` with no userLabel key, and the fixture's grant says the
		// value really is the password.
		//
		// The type half is reset-password's measured behaviour arriving on a
		// second route; the label half is not - reset-password *clears* a
		// label, and this never reads one.
		ID: "admin/users/inline-credential-ignores-type-and-label",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, inline credential of another type",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-otp",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		// Two entries, one credential. The fixture already proved which value
		// survived - the second grants and the first is refused - and this is
		// the other half: the listing has one row, not two.
		ID: "admin/users/inline-credential-twice",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, two inline credentials",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-twice",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		// **An empty value is a 201 and a credential that describes no hash.**
		// Three keys where every other credential has four or five: there is no
		// credentialData at all. Keycloak's own defect - the password grant
		// against this user is a 500 - and reproduced as far as the admin API
		// reaches.
		ID: "admin/users/inline-credential-empty-value",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, inline credential with an empty value",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-empty-value",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		// temporary true puts UPDATE_PASSWORD on the user, the way it does
		// through reset-password. What it does **not** do is the mirror image:
		// a later non-temporary inline credential leaves the action in place,
		// where reset-password with temporary false removes it. Only the add is
		// asserted here; the difference is written up in AGENTS.md.
		ID: "admin/users/inline-credential-temporary",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, temporary inline credential",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-temporary",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
	},
	{
		// **temporary is a disjunction over the array, not last-wins.** The
		// second entry says false and the user still carries UPDATE_PASSWORD.
		// Applying the entries in order with the last flag winning is the
		// obvious implementation, passes admin/users/inline-credential-temporary
		// beside it, and fails here.
		ID: "admin/users/inline-credential-temporary-then-not",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, temporary then permanent inline credentials",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-temporary-then-not",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
	},
	{
		// **The inline array only ever adds the required action.** A
		// non-temporary credential put over a user that has UPDATE_PASSWORD
		// leaves it there, where reset-password with temporary false takes it
		// away. Reusing resetPassword's withAction call is one line and it is
		// wrong here and nowhere else.
		ID: "admin/users/inline-credential-keeps-temporary",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user, permanent inline credential over a temporary one",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-keeps-temporary",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
	},
	{
		// The same array on PUT /users/{id}. F84 was filed against the create
		// and is a defect on both routes, so the update has its own fixture,
		// its own grant and its own golden rather than being assumed from the
		// create's.
		ID: "admin/users/update-inline-credential",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user with an inline credentials array",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-update",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users/{{user_id}}/credentials",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/createdDate"},
	},
	{
		// **An entry with no value is a 500 and the user is rolled back.** The
		// user this body names does not exist afterwards, which is what the
		// next case reads.
		//
		// It is the third answer this API gives to a missing password:
		// reset-password says 400 "No password provided", the update route says
		// 400 "Could not update user!", and the create says this.
		ID: "admin/users/create-credential-without-value",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, inline credential with no value",
			Retrieved: "2026-08-30",
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
			Body: []byte(`{"username":"gloak-probe-novalue","enabled":true,` +
				`"credentials":[{"type":"password"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The rollback, read back. Without it the 500 above is satisfied by a
		// handler that creates the user and then fails, which is what a
		// first attempt at this actually did.
		//
		// The rejected create is in the **fixture**, not in the case before
		// this one. Reading it out of catalogue order would make the golden
		// hold only while that order holds - and worse, it would pass for the
		// wrong reason under the verifier, which serves each case from a
		// handler that has seen nothing but this case's own fixture and would
		// answer `[]` whether or not anything had ever been rolled back.
		ID: "admin/users/create-credential-without-value-rolled-back",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, inline credential with no value, rolled back",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "inline-credential-rollback",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/users",
			Query:   map[string]string{"username": "gloak-probe-rollback", "exact": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The update route's answer to the body the create answers 500: 400,
		// and the errorMessage shape rather than the OAuth one. Two routes on
		// one resource, one bad body, two families - the fifth time this API has
		// punished a decoder shared by a pair.
		ID: "admin/users/update-credential-without-value",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user, inline credential with no value",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-created-user",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"credentials":[{"type":"password"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same body the create answers 500. This is the boundary probe for
		// the shared decoder: admin/users/create-null-body pins the 500 and
		// this pins that the PUT does **not** answer it, which is the half a
		// decoder written once gets wrong.
		ID: "admin/users/update-null-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: update the user, null body",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token-created-user",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/users/{{user_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`null`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A binding failure is unknown_error where a syntax failure is
		// invalid_request.** admin/users/create-malformed sends a truncated
		// object and gets invalid_request; this sends a well-formed object
		// whose credentials key holds a string and gets the other code.
		//
		// Every earlier probe of this endpoint sent a truncated document, which
		// is why invalid_request looked like the answer to "malformed body". It
		// is the answer to "malformed JSON", and this is the body that tells
		// them apart.
		ID: "admin/users/create-credentials-wrong-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, credentials of the wrong JSON type",
			Retrieved: "2026-08-30",
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
			Body: []byte(`{"username":"gloak-probe-badcreds","credentials":"nonsense"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same rule reached through a body that names no credential at all,
		// so the code cannot be read as something the credentials key does.
		ID: "admin/users/create-enabled-wrong-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, enabled of the wrong JSON type",
			Retrieved: "2026-08-30",
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
			Body: []byte(`{"username":"gloak-probe-badenabled","enabled":"yes"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A body whose first token is not `{` at all. Same code as the two
		// above and a different reason for it, which is why all three are here:
		// wrong shape and wrong type share an answer that a truncated object
		// does not.
		ID: "admin/users/create-array-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: create a new user, array body",
			Retrieved: "2026-08-30",
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
			Body: []byte(`[`),
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- F78: a protocol mapper id is unique across the server ---
	//
	// Five routes enforce it and they answer with two bodies, and which body a
	// caller gets is decided by the route **and** by where the colliding mapper
	// is. The follow-up said the location alone decides; the four cells below
	// are what says otherwise, and the two add-models rows are the pair that
	// does it. None of these claims an Operation - every route is claimed.
	{
		// An id the container it is aimed at already holds. This one route
		// answers it with the name conflict, for a request whose name is free.
		ID: "admin/protocol-mappers/duplicate-id-same-container",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: create a mapper, id already in this container",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78HolderScopeID + "/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"` + f78HeldMapperID + `","name":"gloak-probe-f78-free",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same id, aimed at a container that does not hold it. Same route,
		// same status, a different body - which is the half of the follow-up's
		// claim that survived.
		ID: "admin/protocol-mappers/duplicate-id-other-container",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: create a mapper, id held by another container",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-second",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78SecondScopeID + "/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"` + f78HeldMapperID + `","name":"gloak-probe-f78-free",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The cell that refutes "the location decides".** Same container,
		// same id, the batch route - and the generic duplicate, where the
		// single create beside it answers its own name conflict. An
		// implementation that shared one predicate between the two routes
		// passes the three other cells and fails this one.
		ID: "admin/protocol-mappers/add-models-duplicate-id-same-container",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add mappers, id already in this container",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78HolderScopeID + "/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"` + f78HeldMapperID + `","name":"gloak-probe-f78-free",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The fourth cell, which is the third's twin. Two cells of one route
		// answering identically is what a 2x2 is for; without it the batch
		// route's answer could still be read as "the location decides, and this
		// route's local answer happens to be the generic one".
		ID: "admin/protocol-mappers/add-models-duplicate-id-other-container",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add mappers, id held by another container",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-second",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78SecondScopeID + "/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"` + f78HeldMapperID + `","name":"gloak-probe-f78-free",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A body wrong in both ways at once, and the name answers.** The id
		// belongs to another container and the name belongs to this one; the
		// reply is the name conflict, so the id check runs last on this route.
		// Both cells of this route already share that message, which is why the
		// order between them needs a body that reaches only one of the two.
		ID: "admin/protocol-mappers/duplicate-id-and-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: create a mapper, id held elsewhere and name held here",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-second",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78SecondScopeID + "/protocol-mappers/models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"` + f78HeldMapperID + `","name":"` + f78TakenMapperName + `",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same adjacency on the batch route, where the two answers really
		// are different bodies: the name conflict is `Protocol mapper name must
		// be unique per protocol` and the id conflict is `Duplicate resource
		// error`. Swapping the two checks is invisible on the route above and
		// visible here.
		ID: "admin/protocol-mappers/add-models-duplicate-id-and-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: add mappers, id held elsewhere and name held here",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-second",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes/" + f78SecondScopeID + "/protocol-mappers/add-models",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`[{"id":"` + f78HeldMapperID + `","name":"` + f78TakenMapperName + `",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}]`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A create whose nested mapper carries an id another container holds.
		ID: "admin/client-scopes/create-duplicate-mapper-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a client scope, mapper id already in use",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-f78-collide","protocol":"openid-connect",` +
				`"protocolMappers":[` + f78HeldMapper + `]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The refused create left nothing behind. Without this the 409 above is
		// satisfied by a handler that writes the scope and then reports the
		// conflict - which, with no transaction in the store, is exactly the
		// shape the fix has.
		ID: "admin/client-scopes/create-duplicate-mapper-id-rolled-back",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a client scope, mapper id already in use, rolled back",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-rollback",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/client-scopes/" + f78RollbackID,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **Two mappers in one body sharing an id**, which the route answers
		// with its own conflict - the same message a taken name gets, for a
		// name nobody has taken.
		ID: "admin/client-scopes/create-duplicate-mapper-id-in-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a client scope, two mappers sharing an id",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-f78-dupbody","protocol":"openid-connect",` +
				`"protocolMappers":[{"id":"` + f78BodyMapperID + `","name":"gloak-probe-f78-a",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"},` +
				`{"id":"` + f78BodyMapperID + `","name":"gloak-probe-f78-b",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The client create's two cells, the same pair over the other kind of
		// container. Its local message names the clientId where the scope's
		// names the scope.
		ID: "admin/clients/create-duplicate-mapper-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: create a client, mapper id already in use",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"clientId":"gloak-probe-f78-collide-client","enabled":true,` +
				`"protocolMappers":[` + f78HeldMapper + `]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/clients/create-duplicate-mapper-id-in-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: create a client, two mappers sharing an id",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"clientId":"gloak-probe-f78-dupbody-client","enabled":true,` +
				`"protocolMappers":[{"id":"` + f78BodyMapperID + `","name":"gloak-probe-f78-a",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"},` +
				`{"id":"` + f78BodyMapperID + `","name":"gloak-probe-f78-b",` +
				`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The route the follow-up's correction turns on.** The colliding
		// mapper is in another *realm* and the create is still a 409, so the
		// uniqueness is server-wide. A realm-wide index answers this one 201
		// and passes every other case in this family.
		ID: "admin/client-scopes/create-duplicate-mapper-id-across-realms",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Client Scopes: create a client scope in another realm, mapper id already in use",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-f78-realm/client-scopes",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-f78-cross","protocol":"openid-connect",` +
				`"protocolMappers":[` + f78HeldMapper + `]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The fifth route. An id another container holds is the generic 409
		// here as everywhere else.
		ID: "admin/clients/update-duplicate-mapper-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: update a client, mapper id already in use",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-client",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/" + f78ClientID,
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"protocolMappers":[` + f78HeldMapper + `]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A sixth body, and it is not a 409 at all.** Two entries sharing an
		// id on the update route answer 400 `invalid_input`, naming the second
		// mapper. Five routes, three local messages and two statuses.
		ID: "admin/clients/update-duplicate-mapper-id-in-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: update a client, two mappers sharing an id",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-id-holder-client",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/" + f78ClientID,
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"protocolMappers":[{"id":"` + f78PutBodyID + `",` +
				`"name":"gloak-probe-f78-a","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper"},` +
				`{"id":"` + f78PutBodyID + `",` +
				`"name":"gloak-probe-f78-b","protocol":"openid-connect",` +
				`"protocolMapper":"oidc-usermodel-attribute-mapper"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The update matches by name and keeps the id it already had.** The
		// fixture's PUT sent the same name under a different id; the mapper
		// read back carries the id the create gave it, with the provider and
		// the config the PUT sent.
		//
		// This is what makes the route's uniqueness check land only on the add
		// path: without it, a client's own representation put straight back
		// would be a 400.
		//
		// It reads the mapper through its own route rather than reading the
		// client, and that is not a preference. The client representation
		// carries `defaultClientScopes`, which the shared container's earlier
		// cases have added realm defaults to and the verifier's fresh handler
		// has not - so the golden would hold three scopes this fixture never
		// made and fail for a reason that has nothing to do with the mapper.
		// Addressing the mapper by the id the create gave it is also a stronger
		// assertion: a wholesale replace answers this request 404.
		ID: "admin/clients/update-mapper-keeps-its-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: update a client, a mapper matched by name",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-renamed-by-put",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/" + f78RenamedID +
				"/protocol-mappers/models/" + f78KeptMapperID,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},

	// --- F89: the count SizedKeyOrder needs ---
	//
	// Neither of these carries UnorderedKeys. The point of both is the key
	// order inside `config`, so sorting it away would leave the case asserting
	// nothing it was written for.
	{
		// **The case that makes F89 observable.** Four config keys grown to six
		// by the provider's two mirrors: the map is built for four and
		// serialised at six, and the three candidate orders - no ordering,
		// ordering at six, ordering at four - are three different bodies.
		//
		// Every other mapper in this catalogue uses a key set whose hash order
		// happens to be its insertion order, which is why the lost count broke
		// nothing that anything could see.
		ID: "admin/protocol-mappers/config-key-order-grown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: the config key order of a mapper the create grew",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-config-order",
		Request: Request{
			Method:  http.MethodGet,
			Path:    f89MapperPath + "/" + f89GrownID,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The same rule with the count out of the way: a provider that mirrors
		// nothing, so the map is built for three and serialised at three. It
		// still comes back in an order the request did not write, which is what
		// separates "the count is wrong" from "there is no ordering at all".
		ID: "admin/protocol-mappers/config-key-order",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Protocol Mappers: the config key order of a mapper the create left alone",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "mapper-config-order",
		Request: Request{
			Method:  http.MethodGet,
			Path:    f89MapperPath + "/" + f89UngrownID,
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},

	// --- P8's first cut: the SPI registry and the required actions ---
	//
	// Eighteen operations of the Authentication Management tag's thirty-nine.
	// The other twenty-one are the flow model - flows, executions and the
	// shared authenticator config - and are deliberately not here: Gloak walks
	// a hard-coded browser flow, so serving the routes that edit a stored one
	// would move state nothing consumes. See
	// docs/superpowers/plans/2026-08-30-p8-authentication.md.
	//
	// Nothing in this block writes to **master**. The two pristine listings
	// below enumerate the realm's required actions, and every write case works
	// in a realm of its own for that reason.
	{
		// 42 entries, and every byte of them is measured. The three keys come
		// back `displayName, description, id` because Keycloak builds this
		// entry as a Java map and serialises it in bucket order -
		// javamap.KeyOrder places it exactly, which is why the struct's field
		// order is explained rather than merely copied.
		ID: "admin/authentication-management/authenticator-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the authenticator provider registry",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/authenticator-providers",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/authenticator-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The one registry with a fourth key, and the fourth key comes
		// **first**: `supportsSecret, displayName, description, id`. That is
		// what a fourth key does to a HashMap's bucket order and has nothing to
		// do with its meaning.
		ID: "admin/authentication-management/client-authenticator-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the client authenticator registry",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/client-authenticator-providers",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/client-authenticator-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/authentication-management/form-action-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the form action registry",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/form-action-providers",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/form-action-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// One entry, and the only registry whose id `config-description` does
		// **not** resolve: `config-description/registration-page-form` is a 404
		// where the other 52 ids are 200.
		ID: "admin/authentication-management/form-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the form provider registry",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/form-providers",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/form-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **Not a list**, whatever its siblings look like: an object keyed by
		// client-authenticator id whose key order is the listing's.
		//
		// This case is the one that pins the finding a byte comparison caught
		// and a reader would not have: `federated-jwt` answers `"properties":[]`
		// from `config-description/federated-jwt` and **two** properties here.
		// Four of the five client authenticators have the two lists equal,
		// which is exactly why one list looked like enough.
		ID: "admin/authentication-management/per-client-config-description",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the per-client config description",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/per-client-config-description",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/per-client-config-description",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A provider with no config at all: `properties` is `[]` rather than
		// absent, on 32 of the 52.
		ID: "admin/authentication-management/config-description",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: an authenticator's config description",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/config-description/{providerId}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/config-description/auth-cookie",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A property carrying `defaultValue` and `options`, which is what says
		// the three optional members of the property struct are in the right
		// places. No Operation: the case above already claims this one.
		ID: "admin/authentication-management/config-description-with-options",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: a config description carrying options",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/config-description/idp-review-profile",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The **sixteenth** spelling of not-found on this API, and the first of
		// three the Authentication Management tag adds.
		ID: "admin/authentication-management/config-description-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: an unknown authenticator provider",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/config-description/gloak-probe-nope",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// PristineRealm: the body is the realm's whole set of required actions,
		// so anything another case registered or renamed would land in it.
		//
		// Fourteen rows in priority order. Three carry `enabled:false` and none
		// carries `defaultAction:true`, which is what a default install has.
		ID: "admin/authentication-management/required-actions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the registered required actions",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/authentication/required-actions",
		Fixture:       "admin-token",
		PristineRealm: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// `[]` on a pristine realm, and **not** a constant: it is `[]` because
		// all fourteen providers are registered, and a delete puts one in it.
		// The case below reads the populated shape from a realm of its own.
		ID: "admin/authentication-management/unregistered-required-actions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the unregistered required actions",
			Retrieved: "2026-08-30",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/authentication/unregistered-required-actions",
		Fixture:       "admin-token",
		PristineRealm: true,
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/unregistered-required-actions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// Seven keys in the measured order.
		ID: "admin/authentication-management/required-action",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: one required action",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/required-actions/{alias}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// `Failed to find required action` with **no** full stop. The DELETE
		// case below is the same missing row with one, and that pair is the
		// whole point of having both.
		ID: "admin/authentication-management/required-action-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: reading a required action that is not there",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/gloak-probe-nope",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// `Failed to find required action.` **with** the full stop, for the
		// identical missing alias the case above reads. One resource, one key,
		// two sentences, and the verb is what picks.
		ID: "admin/authentication-management/required-action-delete-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: deleting a required action that is not there",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/authentication/required-actions/gloak-probe-nope",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// `{"config":{}}`, a one-key wrapper rather than the map itself.
		ID: "admin/authentication-management/required-action-config",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: a required action's config",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP/config",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// `{"properties":[...]}` and nothing else - **not** the four-key shape
		// `config-description/{providerId}` serves. Two endpoints on one tag
		// whose paths differ by a segment and whose bodies share one key.
		//
		// Its `max_auth_age` carries `"defaultValue":300` on a property whose
		// `"type"` is `"String"`: a number on a string property, which is why
		// the field is `any`.
		ID: "admin/authentication-management/required-action-config-description",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: a required action's config description",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/authentication/required-actions/{alias}/config-description",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP/config-description",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **400, not 404**, for a row that exists. `delete_account` is the one
		// required action of the fourteen that is not configurable, and the
		// `/config` sub-resource answers about configurability rather than
		// about the row.
		ID: "admin/authentication-management/required-action-config-not-configurable",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the config of an action that has none",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/delete_account/config",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The same row through the neighbouring route answers **404** with a
		// third sentence. One alias, two sub-resources, two statuses.
		ID: "admin/authentication-management/required-action-config-description-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the config description of an action that has none",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/authentication/required-actions/delete_account/config-description",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The strict decoder, which is the first one measured in this API.
		// Every other endpoint here ignores a field it does not know; this one
		// names the Java class, the field, the line and the column.
		//
		// The body is chosen so the column is not the body's length: the
		// unknown key is **first**, so a reader can see that the number tracks
		// the offending field rather than the end of the request.
		ID: "admin/authentication-management/required-action-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: an unrecognised field on the representation",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"zz":1,"alias":"CONFIGURE_TOTP"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The config route's own decoder, which is strict too and names a
		// different class. Sent to master because a 400 changes nothing.
		ID: "admin/authentication-management/required-action-config-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: an unrecognised field on the config",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/authentication/required-actions/CONFIGURE_TOTP/config",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"x","config":{}}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The 204 that has **no Cache-Control**. Its DELETE sibling is the only
		// other operation on the tag without one; the four remaining writes all
		// carry `no-cache`. It does carry X-Frame-Options, because the request
		// declared an application/* Content-Type.
		ID: "admin/authentication-management/required-action-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: update a required action",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/authentication/required-actions/{alias}",
		Fixture:   "auth-actions",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-auth-put/authentication/required-actions/TERMS_AND_CONDITIONS",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"TERMS_AND_CONDITIONS","name":"Terms and Conditions",` +
				`"providerId":"TERMS_AND_CONDITIONS","enabled":true,"defaultAction":true,` +
				`"priority":20,"config":{}}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The rename, read back. The body's alias won and the body's
		// providerId - `gloak-probe-ignored` - did not: the row still says
		// `UPDATE_PROFILE`. Writing the representation back wholesale is the
		// obvious implementation and this golden is what refuses it.
		ID: "admin/authentication-management/required-action-renamed",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: a required action the body renamed",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "auth-action-renamed",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-auth-renamed/authentication/" +
				"required-actions/gloak-probe-renamed-action",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The orphan a PUT with `{}` leaves: still in the listing, with **no
		// `alias` key at all** and no `name`, `enabled` false and priority 0,
		// which sorts it first. Keycloak's own defect, reproduced.
		//
		// It also pins the pair of emptiness rules: `alias` disappears when
		// empty and `name` would not have, which is why one is a string with
		// omitempty and the other a pointer.
		ID: "admin/authentication-management/required-action-orphaned",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the row a PUT with an empty body leaves",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "auth-action-orphan",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-auth-orphan/authentication/required-actions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The 204 with **no Cache-Control and no X-Frame-Options**: no
		// Cache-Control because this verb and its PUT sibling are the pair that
		// omit it, and no X-Frame-Options because a DELETE with no body
		// declares no Content-Type. Two different rules, one response.
		ID: "admin/authentication-management/required-action-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: unregister a required action",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/authentication/required-actions/{alias}",
		Fixture:   "auth-actions-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/gloak-probe-auth-del/authentication/required-actions/idp_link",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		// The unregistered listing with something in it, which a pristine realm
		// cannot show. Two keys per entry, and the `name` is the **provider's**
		// display name rather than the deleted row's.
		ID: "admin/authentication-management/unregistered-after-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the unregistered listing after a delete",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "auth-action-unregistered",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-auth-unreg/authentication/" +
				"unregistered-required-actions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// Registering a provider that is already registered: **409 in the RFC
		// 6749 shape**, not the errorMessage one the conflicts elsewhere on
		// this API use.
		//
		// It is a POST whose body carries no `name`, which keeps it out of the
		// pollution guard's creation set - and it is also the shape that
		// produces the six-key representation, so the body is doing two jobs.
		ID: "admin/authentication-management/register-required-action-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: registering an action that is registered",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/authentication/register-required-action",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"providerId":"CONFIGURE_TOTP"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// A providerId that names nothing: 400, and its own sentence again.
		ID: "admin/authentication-management/register-required-action-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: registering a provider that does not exist",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/authentication/register-required-action",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"providerId":"gloak-probe-nope"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The successful registration, in a realm whose idp_link was
		// unregistered by its fixture. 204 with Cache-Control, unlike the two
		// /required-actions/{alias} verbs.
		ID: "admin/authentication-management/register-required-action",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: register a required action",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/authentication/register-required-action",
		Fixture:   "auth-action-to-register",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-auth-reg/authentication/" +
				"register-required-action",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"providerId":"idp_link"}`),
		},
		AssertHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		ID: "admin/authentication-management/raise-priority",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: raise a required action's priority",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/authentication/required-actions/{alias}/raise-priority",
		Fixture:   "auth-actions-raise",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-auth-raise/authentication/" +
				"required-actions/UPDATE_PASSWORD/raise-priority",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		ID: "admin/authentication-management/lower-priority",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: lower a required action's priority",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/authentication/required-actions/{alias}/lower-priority",
		Fixture:   "auth-actions-lower",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-auth-lower/authentication/" +
				"required-actions/UPDATE_PASSWORD/lower-priority",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		// The **effect** of raise-priority, which its 204 cannot show: the two
		// rows have exchanged priority values. UPDATE_PASSWORD was 57 and
		// CONFIGURE_TOTP 54, and they are now 54 and 57. A decrement would have
		// produced 56, so the two hypotheses differ in this body.
		ID: "admin/authentication-management/priority-exchanged",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the listing after a raise",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "auth-action-raised",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-auth-raised/authentication/required-actions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/authentication-management/required-action-config-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: write a required action's config",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		Fixture:   "auth-actions-config",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/gloak-probe-auth-cfg/authentication/" +
				"required-actions/CONFIGURE_TOTP/config",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"config":{"max_auth_age":"600"}}`),
		},
		AssertHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		// The config write **filters**: its fixture sent a declared key and an
		// undeclared one, and only the declared one is here. The
		// representation's own PUT writes the same field and does not filter,
		// which is a rule no single golden can hold and which
		// TestTheTwoConfigWritersDisagreeAboutUnknownKeys pins.
		ID: "admin/authentication-management/required-action-config-filtered",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: the config write drops undeclared keys",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "auth-action-config-filtered",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-auth-cfgf/authentication/" +
				"required-actions/CONFIGURE_TOTP/config",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The delete leaves `{"config":{}}` rather than removing the key, which
		// the case above's sibling read is what would show. Its 204 carries
		// Cache-Control and **no** X-Frame-Options: a DELETE with no body.
		ID: "admin/authentication-management/required-action-config-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authentication Management: clear a required action's config",
			Retrieved: "2026-08-30",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/authentication/required-actions/{alias}/config",
		Fixture:   "auth-actions-config-del",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/gloak-probe-auth-cfgd/authentication/" +
				"required-actions/CONFIGURE_TOTP/config",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},

	// ---------------------------------------------------------------------
	// Organizations. P12's first cut: the organization as a resource, and the
	// realm-level gate that governs all forty-seven paths under
	// /admin/realms/{realm}/organizations.
	// ---------------------------------------------------------------------
	{
		// **The contract of a realm that has not turned organizations on**,
		// which is every realm on a default 26.7.1 - master's and every one
		// POST /admin/realms creates.
		//
		// It is a 404 with an errorMessage, and it is **not** client-types'
		// 501: ORGANIZATION is `"type":"DEFAULT","enabled":true` in
		// GET /admin/serverinfo and is absent from
		// profileInfo.disabledFeatures, where CLIENT_TYPES is. The feature is
		// on; the realm's flag is off. And unlike client-types the check runs
		// **after** the caller's roles, which is what admin's own
		// TestOrganizationsAreRefusedUntilTheRealmSaysSo pins and no golden
		// can, since a golden has one caller.
		ID: "admin/organizations/not-enabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a realm with organizationsEnabled false",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm-off",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-off/organizations",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/organizations/list-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: return a paginated list of organizations",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations",
		Fixture:   "org-realm",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-empty/organizations",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The bare number**, where GET /groups/count next door is
		// `{"count":2}` and GET /users/count is a bare number too. Three counts
		// on this API and two shapes; this one sides with the users one.
		ID: "admin/organizations/count-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: return the number of organizations",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/count",
		Fixture:   "org-realm",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-empty/organizations/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The 201 carries a Location ending in a server-minted UUID and **no
		// Content-Type at all** - content-length is 0. It is the eighth create
		// measured for this and the fifth whose Location ends in an id, which
		// is why VolatileTailHeaders is right for it.
		ID: "admin/organizations/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create a new organization",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations",
		Fixture:   "org-realm-new",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mk/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-created"}`),
		},
		AssertHeaders:       []string{"Location", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control"},
		VolatileTailHeaders: []string{"Location"},
	},
	{
		// The listing's **brief** shape, which is its default: no `attributes`,
		// and `domains` present because this organization has one.
		ID: "admin/organizations/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the listing's default shape",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one/organizations",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// briefRepresentation=false adds `attributes` and nothing else, and the
		// two attribute keys come back **z before k** - a Java HashMap's bucket
		// order, which javamap.KeyOrder places exactly. That is why this body
		// is asserted as bytes with no UnorderedKeys retreat, where the five
		// client cases still need one (F95).
		ID: "admin/organizations/list-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the listing under briefRepresentation=false",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one/organizations",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: return a specific organization",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}",
		Fixture:   "org-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one/organizations/{{org_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The single read ignores briefRepresentation.** Its sibling listing
		// honours it, and this body is byte-identical to admin/organizations/read
		// above - which is the assertion: the same golden bytes under a
		// parameter that moves the neighbouring route.
		ID: "admin/organizations/read-brief-ignored",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: briefRepresentation does nothing to the single read",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one/organizations/{{org_id}}",
			Query:   map[string]string{"briefRepresentation": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/count",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the count of a realm holding one",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one/organizations/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: an organization that does not exist",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-empty/organizations/gloak-probe-nosuch",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// An **empty** name is a null name here. A client scope's absent name is
		// a 500 and its empty one a 400 naming the empty string; this endpoint
		// gives both the same 400.
		ID: "admin/organizations/create-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create with no name",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-empty/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":""}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The first of the pair that differs **only in a full stop**. Its alias
		// sibling is the next case, and the two are deliberately adjacent so a
		// reader sees the difference rather than being told about it.
		ID: "admin/organizations/create-duplicate-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create with a name already taken",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-taken",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-dup/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-named"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The second of the pair: **no full stop**, and "A organization" is
		// Keycloak's grammar in both.
		ID: "admin/organizations/create-duplicate-alias",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create with an alias already taken",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-taken",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-dup/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-fresh","alias":"gloak-probe-org-alias"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A duplicate **domain** is a 400 where a duplicate name is a 409, so
		// the conflict status on this resource is per field. The message names
		// the other organization and the realm, which is why the store resolves
		// the row rather than answering a boolean.
		ID: "admin/organizations/create-duplicate-domain",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create with a domain another organization holds",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-taken",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-dup/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-fresh2","domains":[{"name":"gloak-probe-domain.example.com"}]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A name that cannot become an alias: the **errorMessage** family, with
		// the prefix that says the name is being used as one.
		ID: "admin/organizations/create-name-not-an-alias",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a name the alias rules refuse",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-empty/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-bad/org"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The **same** validation reaching the wire in the other error family.
		// An explicit alias answers `{"error":"Character '/' not allowed."}` -
		// the `error` key, and no prefix - where the case above answers
		// `errorMessage` with one. One check, two shapes, decided by which
		// field carried the value.
		ID: "admin/organizations/create-bad-alias",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: an alias the alias rules refuse",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-empty/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-ok","alias":"gloak-probe/alias"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The create is a **strict** decoder. The two Authentication Management
		// PUTs were the first measured in this API; these are the third and
		// fourth, so "the two required-action PUTs" is no longer the list.
		ID: "admin/organizations/create-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: create with an undeclared field",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-realm",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-empty/organizations",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-x","bogusField":"x"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// An absent alias means "derive it from the name", not "leave it
		// alone", so a read-modify-write that drops the key fails on every
		// organization whose alias is not its name.
		ID: "admin/organizations/update-alias-refused",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a PUT that would move the alias",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-org-put/organizations/{{org_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-named"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A PUT with no name is a 409 about a name it does not have.** The
		// missing name falls back to the alias, which then collides with the
		// organization's own row. The create answers the same missing name with
		// a 400. Keycloak's own defect, reproduced.
		ID: "admin/organizations/update-without-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a PUT carrying no name",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-org-put/organizations/{{org_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-org-alias"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The 204 carries X-Frame-Options - the request declared
		// application/json - and **no Cache-Control**, where four of the five
		// measured deletes elsewhere carry one. Pinned per endpoint.
		ID: "admin/organizations/update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: update an organization",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/organizations/{org-id}",
		Fixture:   "org-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/gloak-probe-org-put/organizations/{{org_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-org-renamed","alias":"gloak-probe-org-alias"}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// What the 204 above cannot show: the rename landed, `description`,
		// `redirectUrl` and `domains` are gone because the body did not carry
		// them, and **`attributes` survived** although it did not carry those
		// either. One field on this body merges where the rest replace.
		ID: "admin/organizations/update-replaced",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the read after a PUT",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "org-updated",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-upd/organizations/{{org_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The 204 of a request that sends no Content-Type: **no
		// X-Frame-Options**, and no Cache-Control either.
		ID: "admin/organizations/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: delete an organization",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/organizations/{org-id}",
		Fixture:   "org-realm-del",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/gloak-probe-org-rm/organizations/{{org_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},

	// ---- P10 first cut: authorization services ----------------------------
	//
	// Appended at the very end of the slice. Every value below was measured
	// against a live 26.7.1 on 2026-08-31; the plan carries the sweeps.
	{
		ID: "admin/authz-resource-server/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resource server",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server",
		Fixture:   "authz-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// **The absence is the assertion.** This read and settings beside it
		// send no Cache-Control where every sub-resource read on the family
		// sends no-cache, so "the authz family caches nothing" is a claim two
		// routes falsify. Without this line the golden would pass whether the
		// header were emitted or not.
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The body's id and clientId are **both** the client UUID and name is
		// the clientId string, so ReplaceCaptured rewrites two of the three and
		// the third is asserted literally. That is what pins the confusion: a
		// serialiser filling clientId from model.Client.ClientID would put
		// `gloak-probe-authz-upd` where {{client_uuid}} is and the golden would
		// not match.
		ID: "admin/authz-resource-server/read-updated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a PUT naming decisionStrategy alone",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "authz-client-updated",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// The fixture's PUT sent decisionStrategy and nothing else. This body
		// is what the other two fields became: **ENFORCING and true**, the
		// representation's own initialisers, not what was stored and not the
		// zero values. Only `decisionStrategy` differs from the plain read
		// eight lines up, and that difference is the whole measurement.
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/authz-resource-server/settings",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the settings export",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/settings",
		Fixture:   "authz-client-settings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/settings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// A different body from the read two cases up: no id, no clientId, no
		// name. On a resource server holding nothing that is the whole
		// difference, which is why this case and that one are worth having side
		// by side - one shared serialiser would make them equal.
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/authz-resource-server/policy-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the policy provider catalogue",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/providers",
		Fixture:   "authz-client-policy",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy/providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// **No Unordered.** The ten entries come back in a Java map's order,
		// javamap.SizedKeyOrder reproduces it, and sorting the array would
		// throw away the one thing this golden is for. It is also where the two
		// absentees are pinned: `uma` is a registered policy provider and is
		// not here, and `js` is absent because SCRIPTS is disabled.
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// Byte-identical to the case above, and that is the assertion. A
		// permission catalogue filtered to the two providers whose group is
		// "Permission" is the obvious implementation and it would fail here and
		// nowhere else.
		ID: "admin/authz-resource-server/permission-providers",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the permission provider catalogue",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/providers",
		Fixture:   "authz-client-perm",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission/providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/authz-resource-server/put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: updating the resource server",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server",
		Fixture:   "authz-client-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"allowRemoteResourceManagement":false,"policyEnforcementMode":"PERMISSIVE","decisionStrategy":"AFFIRMATIVE"}`),
		},
		// The 204 carries X-Frame-Options because the request declared a JSON
		// Content-Type, and no Cache-Control - which is the per-endpoint pin,
		// not the method's.
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **A body with no decisionStrategy is a 409**, whatever else it holds.
		// The body here carries a name on purpose: `{}` would pass a handler
		// that refused an absent *name*, and `{"name":"x"}` is the probe that
		// tells the two rules apart. That was the first reading of this
		// endpoint and it was wrong.
		//
		// The 409 also **drops the five security headers**, which the strict
		// 400 and the bad-enum 400 on this same route do not.
		ID: "admin/authz-resource-server/put-no-decision-strategy",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a write with no decisionStrategy",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "authz-client-conflict",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-authz-conflict"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Referrer-Policy"},
	},
	{
		// The gate. A client without authorizationServicesEnabled answers this
		// on every path under authz/resource-server, and the body is
		// `{"error":"HTTP 404 Not Found"}` - **not** any of the twenty-one
		// spellings of not-found, and not `Could not find client`, which the
		// same route answers for a client that does not exist at all.
		ID: "admin/authz-resource-server/not-enabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a client without the flag",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "authz-client-off",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The twelve management/permissions operations, one case per ordering
		// rather than one per route: what varies between them is where the 501
		// sits. The roles route never looks its role up...
		ID: "admin/roles/management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles/{role-name}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodGet,
			// A role name that does not exist, deliberately: the 501 runs
			// before the lookup, so this asserts the ordering and the body at
			// once. A real role name would pass a handler that resolved first.
			Path:    "/admin/realms/master/roles/gloak-probe-no-such-role/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// ...and neither does the by-id route, on an id that resolves to
		// nothing.
		ID: "admin/roles-by-id/management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/roles-by-id/{role-id}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/roles-by-id/00000000-0000-0000-0000-000000000000/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The group route **does** resolve first, so this one names a group
		// that exists. Its sibling below names one that does not and gets a 404
		// instead - the pair is the ordering, and either alone would pass a
		// handler with the other ordering.
		ID: "admin/groups/management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/groups/{group-id}/management/permissions",
		Fixture:   "authz-mgmt-group",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/{{group_id}}/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/groups/management-permissions-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: management permissions resolve the group before refusing",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/groups/00000000-0000-0000-0000-000000000000/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The clients pair resolves the client first, so this asserts the 501
		// on a client that exists...
		ID: "admin/clients/management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/management/permissions",
		Fixture:   "authz-mgmt-client",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// ...and this one the 404 on a client that does not, which is the other
		// half of the same ordering. It is `Could not find client`, the clients
		// family's spelling, and not the gate's `HTTP 404 Not Found`.
		ID: "admin/clients/management-permissions-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: management permissions resolve the client before refusing",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The client's *role* route resolves the client and **not** the role,
		// so this names a real client and a role that does not exist. It is the
		// two-fault case the ordering needs: breaking one parameter at a time
		// would not tell this route from the group one.
		ID: "admin/roles/client-management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: a client role's management permissions",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/management/permissions",
		Fixture:   "authz-mgmt-client-role",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-no-such-role/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The identity-provider pair never looks its alias up, which is why
		// this case can exist at all: Gloak serves no identity providers, and
		// this refusal is two of that chapter's seventeen operations without
		// one.
		ID: "admin/identity-providers/management-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-no-such-idp/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// The second verb of each of the six management/permissions paths.
	//
	// They are separate cases rather than a note on the six above because the
	// parity meter counts operations and PUT is one, and because **the verb
	// really could decide something here**: it does on
	// `/required-actions/{alias}`, where GET and DELETE answer a missing alias
	// with two spellings of one sentence. Measured on all twelve: it does not.
	{
		ID: "admin/roles/management-permissions-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: setting management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/roles/{role-name}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/roles/gloak-probe-no-such-role/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles-by-id/management-permissions-get",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles (by ID): reading management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/roles-by-id/{role-id}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/roles-by-id/00000000-0000-0000-0000-000000000000/management/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/groups/management-permissions-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Groups: setting management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/groups/{group-id}/management/permissions",
		Fixture:   "authz-mgmt-group",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/groups/{{group_id}}/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/clients/management-permissions-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Clients: setting management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/management/permissions",
		Fixture:   "authz-mgmt-client-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/roles/client-management-permissions-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Roles: setting a client role's management permissions",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/roles/{role-name}/management/permissions",
		Fixture:   "authz-mgmt-client-role-put",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/roles/gloak-probe-no-such-role/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "admin/identity-providers/management-permissions-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: setting management permissions, ADMIN_FINE_GRAINED_AUTHZ disabled",
			Retrieved: "2026-08-31",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/identity-provider/instances/{alias}/management/permissions",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/identity-provider/instances/gloak-probe-no-such-idp/management/permissions",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"enabled":true}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// ---- P10 second cut: the authorization-services scope family ----------
	//
	// Appended at the very end of the slice. Every value below was measured
	// against a live 26.7.1 on 2026-09-01, container kc-authzb on port 8141;
	// docs/superpowers/plans/2026-08-31-p10-authz-cut-b.md carries the sweeps.
	//
	// Eight operations, eighteen cases. The extra ten are the pairs: two orders
	// of one scope set, two meanings of `name`, two 409s that disagree about
	// the security headers, and two empty-bodied 404s that disagree about
	// X-Frame-Options. Each of those pairs is a rule that a single case would
	// record as a body and prove nothing about.
	{
		// **Sorted by name, byte-wise.** The fixture creates them zulu,
		// yankee, xray, whiskey, Zebra, and this golden holds
		// Zebra, whiskey, xray, yankee, zulu - a case-folded sort would put
		// Zebra fourth, and the settings case eight rows down holds the same
		// five in creation order. The two goldens together are the assertion;
		// either alone is a body.
		ID: "admin/authz-resource-server/scope-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the scope listing",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope",
		Fixture:   "authz-scope-list",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// **No Unordered.** The order is the measurement.
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// `?name=` is a **case-insensitive substring** and `?max=` pages on its
		// own. `Zebra` in the answer is what says the filter folds case where
		// the sort beside it does not, and the search case four rows down sends
		// the same spelling to the other `name` and gets a 204.
		ID: "admin/authz-resource-server/scope-list-filtered",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the scope listing's name filter and paging",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-filter",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope",
			Query:   map[string]string{"name": "ZE", "max": "1"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A bound that does not parse is a 404**, and the body is the one
		// AGENTS.md attributes to an unmatched path, a wrong verb and a
		// switched-off resource. This is the fourth producer: a route the
		// caller may use, on a resource server that exists, refused because an
		// integer parameter could not bind. Measured on this listing and on
		// GET /roles, /users, /groups and /clients alike.
		ID: "admin/authz-resource-server/scope-list-bad-bound",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a scope listing bound that does not parse",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-bound",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope",
			Query:   map[string]string{"first": "abc"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The create's 201 is the request echoed, not a read.** The body
		// carries `policies` and `resources` back, and no other view of the
		// same scope has either key - the read case below is the control. The
		// field order is measured from a create that sent all six in reverse:
		// id, name, iconUri, policies, resources, displayName.
		//
		// **No Location**, which is what AssertAbsentHeaders pins. Four of the
		// admin creates end their Location in the new object's id and three do
		// not; this one has none at all.
		ID: "admin/authz-resource-server/scope-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a scope",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope",
		Fixture:   "authz-scope-create",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"resources":[],"policies":[],"displayName":"Created",` +
				`"iconUri":"http://example.test/i.png","name":"gloak-probe-created",` +
				`"id":"5c0be000-0000-4000-8000-0000000000e1"}`),
		},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		// **This 409 carries all five security headers and the PUT's carries
		// none**, on identical bodies one path segment apart. AGENTS.md's fifth
		// security-header exception says a 409 `Duplicate resource error` sends
		// none of the five; this case and admin/authz-resource-server/
		// scope-put-conflict are the pair that refutes it, and the repository's
		// own admin/realms-admin/default-default-client-scope-duplicate golden
		// had already been carrying all five since P5.
		//
		// The body is `{"iconUri":...}` rather than `{}` on purpose: it carries
		// a field, so a handler that refused an *empty body* would pass `{}`
		// and fail here. Only an absent `name` is the 409 - `{"name":""}` is a
		// 201.
		ID: "admin/authz-resource-server/scope-create-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a scope with no name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-conflict",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"iconUri":"http://example.test/i.png"}`),
		},
		AssertHeaders: []string{
			"Content-Type", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
	},
	{
		ID: "admin/authz-resource-server/scope-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: reading one scope",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}",
		Fixture:   "authz-scope-read",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-000000003001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The absence of a spelling, not one of the twenty-one.** No body, no
		// Content-Type, Content-Length 0 - and `Cache-Control: no-cache`, which
		// the PUT's and the DELETE's 404 on this same path do not send.
		//
		// **X-Frame-Options is absent because the request declared no
		// Content-Type.** The case below sends the identical request with
		// `application/json` and gets it. AGENTS.md records that rule for a 204
		// and names httpx.WriteNoContent as the one place that decides it;
		// these two cases say the rule is about the empty body rather than the
		// status.
		ID: "admin/authz-resource-server/scope-read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a scope that does not exist",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-missing",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-0000000000ff",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The same 404 with one header added to the **request**. It is the
		// distinguishing probe for the case above, and without it that golden
		// would record an omission with no reason attached.
		ID: "admin/authz-resource-server/scope-read-missing-json",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the empty 404 with a JSON Content-Type",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-missing-json",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-0000000000ff",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
		},
		AssertHeaders:       []string{"Cache-Control", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// **200 with a bare object**, not an array of one. And the match is
		// exact and case-sensitive, which the listing's `name` is not: the
		// filtered listing case above finds `Zebra` from `ZE`.
		ID: "admin/authz-resource-server/scope-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the scope search",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/search",
		Fixture:   "authz-scope-search",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/search",
			Query:   map[string]string{"name": "gloak-probe-solo"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A miss is a **204**, and the name sent here differs from the seeded
		// one only in case. That is what makes the search case-sensitive rather
		// than merely exact, and no other body can say it.
		ID: "admin/authz-resource-server/scope-search-miss",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the scope search is case-sensitive",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-search-miss",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/search",
			Query:   map[string]string{"name": "GLOAK-PROBE-SOLO"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// An absent or empty `name` is a **400 with an empty body**, which is
		// its own shape on an API with four error bodies: it has none of them.
		ID: "admin/authz-resource-server/scope-search-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the scope search with no name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-search-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/search",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// 204, and **no Cache-Control** - the eighth measured response where
		// that header is pinned per endpoint rather than per method.
		// X-Frame-Options is here because the request declares JSON.
		ID: "admin/authz-resource-server/scope-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: updating a scope",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}",
		Fixture:   "authz-scope-put",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-000000007001",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-renamed"}`),
		},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// What the 204 above cannot show: **the PUT replaces**. The fixture's
		// scope was created with an iconUri and a displayName and the PUT named
		// only its name; this body has neither. A merge - which is what a
		// client and a user PUT do - would have kept both.
		ID: "admin/authz-resource-server/scope-put-replaced",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a scope PUT replaces rather than merging",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-put-replaced",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-000000008001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The other half of the 409 pair. Same body shape as the create's
		// conflict case, same request Content-Type, one path segment away -
		// and **none of the five security headers**. Both causes of this 409
		// agree with each other, so it is decided per verb on this endpoint.
		ID: "admin/authz-resource-server/scope-put-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: updating a scope with no name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-put-conflict",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-000000009001",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"iconUri":"http://example.test/i.png"}`),
		},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
	},
	{
		// A successful delete: 204, **no Cache-Control**, and no
		// X-Frame-Options because a DELETE with no body declares no
		// Content-Type.
		ID: "admin/authz-resource-server/scope-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: deleting a scope",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}",
		Fixture:   "authz-scope-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-00000000a001",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		// The delete's 404 sends **no Cache-Control** where the read's sends
		// no-cache. Two 404s on one path differing in one header, and here the
		// method is what decides it - which is the opposite of what the
		// Cache-Control bullet concludes about the six measured deletes, where
		// every generalisation over the method has failed.
		ID: "admin/authz-resource-server/scope-delete-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: deleting a scope that does not exist",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-missing-del",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-0000000000ff",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control", "X-Frame-Options"},
	},
	{
		// `[]`, and it is the measured answer rather than a stub for exactly as
		// long as Gloak has no permissions: there is no route that creates one.
		// The half a case can see move is the 404 for a scope that does not
		// exist, which the scope-read-missing case above records.
		ID: "admin/authz-resource-server/scope-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a scope's permissions",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}/permissions",
		Fixture:   "authz-scope-permissions",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-00000000b001/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/authz-resource-server/scope-resources",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a scope's resources",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/scope/{scope-id}/resources",
		Fixture:   "authz-scope-resources",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/scope/" +
				"5c0be000-0000-4000-8000-00000000c001/resources",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The settings export's scopes come back in creation order**, where
		// the listing eighteen rows up sorts the same five by name. The fixture
		// creates them zulu, yankee, xray, whiskey, Zebra and this golden holds
		// exactly that, entry by entry stripped of its id and keeping nothing
		// else - the first cut recorded this order as "neither name order nor
		// insertion order and not pinned".
		//
		// The `admin/authz-resource-server/settings` case above stays: it is
		// the same body on an **empty** resource server, where the two reads of
		// a resource server differ only in three leading keys. This one is the
		// only case in the catalogue that can see the two orders disagree.
		ID: "admin/authz-resource-server/settings-with-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the settings export with scopes in it",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-settings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/settings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},

	// P9: identity providers and components. See
	// docs/superpowers/plans/2026-09-01-p9-identity-providers.md.
	{
		// **The representation's field rules are not uniform and this body is
		// where they are asserted together.** The create sent fifteen fields
		// and the read answers thirteen: `updateProfileFirstLoginMode` and
		// `postBrokerLoginFlowAlias` are accepted and never echoed. The six
		// tri-state flags are all `true` here and all absent in the minimal
		// case below, which is the pair that says absent is not false.
		//
		// **`clientSecret` comes back as ten asterisks**, so a caller cannot
		// round-trip a provider through a GET and a PUT without losing it.
		//
		// The config's key order is javamap.SizedKeyOrder's, which is the
		// **other** constructor from the component listing four cases down.
		// Nothing masks it.
		ID: "admin/identity-providers/read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: get one identity provider instance",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}",
		Fixture:   "idp-full",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-idp-full",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The other end of the pair. Alias and providerId and nothing else:
		// `config` is `{}` rather than absent, `enabled` is `true` rather than
		// omitted, and the six flags are gone.
		ID: "admin/identity-providers/read-minimal",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: an instance created from alias and providerId alone",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "idp-minimal",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-idp-min",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **Sorted by alias**, and the fixture creates them zzz, mmm, aaa so
		// that the golden asserts the sort rather than the insertion order.
		// No Unordered mask: this order is reproducible and asserting it is the
		// point.
		//
		// **PristineRealm**, because the body is the realm's whole set of
		// providers and the recorder shares one container: without it this
		// golden holds whatever the fixtures of the cases beside it created,
		// which is what the first recording of it did.
		ID: "admin/identity-providers/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: list the instances",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/identity-provider/instances",
		PristineRealm: true,
		Fixture:       "idp-listing",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`briefRepresentation=true` answers a six-key shape**, not the full
		// one minus a field: it drops the six tri-state flags,
		// `firstBrokerLoginFlowAlias` and `types`, and **empties `config`**
		// while keeping the key. The default on this listing is false - the
		// third default this one parameter has in this API.
		//
		// The first reading of it was "it drops types", from probes on
		// providers that carried neither a config nor a flag. **This golden is
		// what refuted it**: the fixture's providers carry both, and the
		// recording sent the request no hand probe had.
		ID: "admin/identity-providers/list-brief",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: the listing under briefRepresentation",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "idp-listing",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances",
			Query:   map[string]string{"briefRepresentation": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`search` is a prefix with an implied trailing wildcard**, so
		// `gloak-probe-idp-m` finds `gloak-probe-idp-mmm` and nothing else. It
		// is the same rule the user listing follows and **not** the role
		// listing's, where `*` is a literal - measured on one container with
		// one value.
		ID: "admin/identity-providers/list-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: the listing under search",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "idp-listing",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances",
			Query:   map[string]string{"search": "gloak-probe-idp-m"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A malformed integer bound is a 404**, and it is the generic
		// `{"error":"HTTP 404 Not Found"}` rather than anything about the
		// route. `/components` next door answers the same parameter with a 200
		// and the whole listing, which is why the two families do not share a
		// bound parser. See F134.
		ID: "admin/identity-providers/list-bad-bound",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: the listing with an unparseable first",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances",
			Query:   map[string]string{"first": "abc"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **An alias that does not exist is the generic 404**, not a spelling
		// of not-found. This family adds none, where the Component family two
		// cases down adds two.
		ID: "admin/identity-providers/read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: an alias that resolves to nothing",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-no-such-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The create's Location ends in the alias**, a name tail rather than
		// a uuid one, which is why this case is **not** in
		// Case.VolatileTailHeaders: the tail is what the request chose and is
		// asserted. The 201 carries no Content-Type at all.
		ID: "admin/identity-providers/create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: create an instance",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/identity-provider/instances",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-idp-create","providerId":"github",` +
				`"config":{"clientId":"gloak-probe-cid","clientSecret":"gloak-probe-secret"}}`),
		},
		AssertHeaders:       []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A duplicate alias is a 409 naming it**, in the errorMessage family.
		ID: "admin/identity-providers/create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: create an instance whose alias is taken",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "idp-taken",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-idp-min","providerId":"oidc"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **A body with no alias is `path is null`**, which is Keycloak's own
		// message and is about a path rather than about the field the request
		// is missing.
		ID: "admin/identity-providers/create-no-alias",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: create an instance with no alias",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"providerId":"oidc"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **An unregistered providerId names itself in the message**, and an
		// absent one produces the same sentence with `null` in it - one check
		// with one spelling rather than a presence test and a membership test.
		ID: "admin/identity-providers/create-bad-provider",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: create an instance naming a provider that is not registered",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-idp-bad","providerId":"nonesuch"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The sixth strict decoder**, and it reports a line and column. The
		// claim that client registration is the only endpoint that does is
		// wrong four ways over: the two required-action PUTs, the two
		// organization writes, this pair and `POST /components` all do.
		ID: "admin/identity-providers/create-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: create an instance with a field the server does not know",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-idp-strict","providerId":"oidc","zzz":1}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The strict decode runs before the path's alias is resolved**: an
		// unknown field on an alias that does not exist answers the 400 and not
		// the 404. That is the required-action PUT's order and the opposite of
		// the organization PUT's, and it is the request that tells the two
		// apart - a clean body on the same alias is the 404.
		ID: "admin/identity-providers/update-decodes-first",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: update an unknown alias with an unknown field",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/identity-provider/instances/{alias}",
		Fixture:   "admin-token",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/identity-provider/instances/gloak-probe-no-such-idp",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"x","providerId":"oidc","zzz":1}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **Keycloak's own defect, reproduced.** The fixture PUTs a body with
		// no `alias` and gets a 204; this listing is what that 204 cannot show.
		// The row keeps its internalId, loses its `alias` key outright and
		// sorts first, and nothing can address it again.
		//
		// Refusing an absent alias is the tidy-up that turns a measured 204
		// into a 400, which is why this case exists rather than a test alone.
		ID: "admin/identity-providers/update-strands-the-row",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: the listing after a PUT whose body has no alias",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "idp-stranded",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A rename is refused**, where the absent alias above is not. Two
		// halves of one sentence, one request each.
		ID: "admin/identity-providers/update-rename",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: update an instance, changing its alias",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "idp-minimal",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/admin/realms/master/identity-provider/instances/gloak-probe-idp-min",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"alias":"gloak-probe-idp-other","providerId":"oidc"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The delete is not idempotent**: the second is the generic 404. The
		// 204 carries `Cache-Control: no-cache` and no `X-Frame-Options`, the
		// request having sent no Content-Type.
		ID: "admin/identity-providers/delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: delete an instance",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/identity-provider/instances/{alias}",
		Fixture:   "idp-minimal",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-idp-min",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **The export of anything but a SAML provider is a bodyless 204**, no
		// Content-Type at all. A SAML provider answers `application/xml` with a
		// freshly minted `ID_<uuid>` in it on every request, which is why that
		// half is not here: a page carrying a per-request value cannot be
		// asserted.
		ID: "admin/identity-providers/export",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: export an instance's public broker configuration",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/export",
		Fixture:   "idp-minimal",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-idp-min/export",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// **The body is the bare JSON `false`**, on every provider type. It
		// reports whether anything was reloaded, and nothing is: no provider on
		// a default container has a JWKS Keycloak has cached.
		//
		// It is also the one read on this family that refuses the view role -
		// see the router.
		ID: "admin/identity-providers/reload-keys",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: reload an instance's keys",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/reload-keys",
		Fixture:   "idp-minimal",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-idp-min/reload-keys",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A fresh realm's components are fifteen on master**, and the listing
		// is neither empty nor about user federation: four key providers, ten
		// client-registration policies, and the declarative user profile.
		//
		// Two masks, neither inert, both measured on two realms of one
		// container:
		//
		//   - the **row order** has none. Two realms created minutes apart
		//     returned the same fourteen rows in two entirely different orders,
		//     matching neither insertion, name, id nor provider.
		//   - `allowed-protocol-mapper-types` holds eight names in two
		//     different orders on those same two realms.
		//
		// The ids and the parentId are per-realm UUIDs and are Volatile. The
		// **key order inside each config is not masked**: it is
		// javamap.KeyOrder's and it is asserted, which is the other of
		// Keycloak's two HashMap constructors from the identity provider config
		// eleven cases up.
		ID: "admin/component/list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Component: list a realm's components",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		Operation:     "GET /admin/realms/{realm}/components",
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/components",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/parentId"},
		Unordered:     []string{".", "*/config/allowed-protocol-mapper-types"},
	},
	{
		// The same listing narrowed to the four key providers, which is what
		// `GET /admin/realms/{realm}/keys` is a view over and Gloak's is not -
		// see AGENTS.md's note that Gloak derives that endpoint's `providerId`
		// from the kid by a fixed hash.
		//
		// **A `type` that matches nothing is `[]` and not a 404**, which is why
		// the filters run over rows rather than resolving anything.
		ID: "admin/component/list-by-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Component: list a realm's components filtered by provider type",
			Retrieved: "2026-09-01",
		},
		Status:        Implemented,
		PristineRealm: true,
		Fixture:       "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/components",
			Query:   map[string]string{"type": "org.keycloak.keys.KeyProvider"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/id", "*/parentId"},
		Unordered:     []string{"."},
	},
	{
		// **`Could not find component` is a spelling of not-found this API did
		// not have**, and it is in the bare-`error` family. The realm's own id
		// answers it too: components are parented on the realm and the realm is
		// not one.
		ID: "admin/component/read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Component: an id that resolves to nothing",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/components/{id}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/components/gloak-probe-no-such-component",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},

	// ---- P10 third cut: the authorization-services resource family --------
	//
	// Appended at the very end of the slice. Every value below was measured
	// against a live 26.7.1 on 2026-09-01, container kc-authz on port 8154;
	// docs/superpowers/plans/2026-09-01-p10-authz-resources.md carries the
	// sweeps.
	//
	// Nine operations. The extra cases are the pairs, and each pair is a rule
	// that one case would record as a body and prove nothing about: two orders
	// of one resource set, two meanings of `name`, two 409s that disagree about
	// both the body and the security headers, two empty-body refusals that
	// disagree about the status, and two 404s one path segment apart that
	// disagree about everything.
	{
		// **Sorted by name, byte-wise.** The fixture creates them zulu,
		// yankee, xray, Zebra and this golden holds Zebra, xray, yankee, zulu -
		// a case-folded sort would put Zebra third. The settings case further
		// down holds the same four in creation order, and the two goldens
		// together are the assertion; either alone is a body.
		ID: "admin/authz-resource-server/resource-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resource listing",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource",
		Fixture:   "authz-res-list",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// **No Unordered.** The order is the measurement, and so is every
		// `owner` block in it - the id is the client's UUID and the name is its
		// clientId string, which is the inversion this family's representation
		// records.
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// Four filters in one request, which is how the golden says they are
		// **ANDed** rather than that each works alone. `?name=` is a
		// case-insensitive substring where the sort beside it is byte-wise, so
		// `ZE` finds `gloak-probe-Zebra`; `?max=` pages on its own.
		ID: "admin/authz-resource-server/resource-list-filtered",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resource listing's filters",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-filter",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Query: map[string]string{
				"name": "ZE", "max": "1", "owner": "gloak-probe-authz-rs-filt", "deep": "true",
			},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`?deep=false` drops two keys, not one**: `attributes` and `scopes`.
		// The fixture's resource carries both, and the read case below is the
		// control that shows what the same row looks like with them.
		ID: "admin/authz-resource-server/resource-list-shallow",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resource listing under deep=false",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-deep",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Query:   map[string]string{"deep": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`matchingUri` is a best match, not a filter.** The fixture
		// registers `/gloak-probe/deep/*` and `/gloak-probe/deep/a/b`, and this
		// request asks for a path only the wildcard covers. The pair that makes
		// it an assertion is that the *exact* registration wins `/deep/a/b`,
		// which the package's own test sends - a golden can only hold one
		// request.
		ID: "admin/authz-resource-server/resource-list-matching-uri",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resource listing's matchingUri",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-uri",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Query:   map[string]string{"uri": "/gloak-probe/deep/x/y", "matchingUri": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A bound that does not parse is a 404**, and this is the sixth
		// listing measured answering it. See the scope family's case of the
		// same name for the four producers of that body.
		ID: "admin/authz-resource-server/resource-list-bad-bound",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource listing bound that does not parse",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-bound",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Query:   map[string]string{"max": "abc"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The create's 201 is a read of what was written**, which is the
		// opposite of the scope create beside it: the body names its scope by
		// **name** and the answer carries that scope's minted id, so it cannot
		// be the request echoed.
		//
		// **No Location**, which is what AssertAbsentHeaders pins, and
		// `Cache-Control: no-cache`, which the PUT and the DELETE on the same
		// resource do not send.
		ID: "admin/authz-resource-server/resource-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a resource",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource",
		Fixture:   "authz-res-create",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"_id":"5e50a5ce-0000-4000-8000-00000000f401",` +
				`"name":"gloak-probe-created","displayName":"Created","type":"urn:gloak:c",` +
				`"icon_uri":"http://example.test/c.png","ownerManagedAccess":true,` +
				`"uris":["/z","/a","/m"],"attributes":{"k2":["b"],"k1":["a"]},` +
				`"scopes":[{"name":"gloak-probe-alpha"}]}`),
		},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		// **A create with no name is `Duplicate resource error`** - the same
		// answer the resource-server PUT and the scope create give a body that
		// is missing their own gate - and it carries the five security headers,
		// where the PUT's 409 two cases down carries none.
		ID: "admin/authz-resource-server/resource-create-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource create with no name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-noname",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"displayName":"gloak-probe-nameless"}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **A create with a taken name names it**, and it is the only refusal
		// in the whole authorization-services surface that repeats its input
		// back. The PUT answering the same condition says `Duplicate resource
		// error` instead - one condition, two verbs, two bodies.
		ID: "admin/authz-resource-server/resource-create-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource create with a taken name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-conflict",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/resource",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-solo"}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The full representation, and the golden is the field order: `_id`
		// sits between `attributes` and `uris`, which is where no other
		// representation in this API puts an id. `uris` comes back
		// `/a, /z, /m` from a request that sent `/z, /a, /m`, and `attributes`
		// comes back `k1` before `k2` from a request that sent `k2` first -
		// both HashSet and HashMap bucket orders, both collision-free by
		// construction.
		ID: "admin/authz-resource-server/resource-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: reading one resource",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}",
		Fixture:   "authz-res-read",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000f601",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The read's 404 is the generic JSON body with no Cache-Control.**
		// The scope family's single read answers the same condition with an
		// empty body **and** a Cache-Control, so the two families invert each
		// other on both halves - and the sub-route case below inverts this one
		// again, one path segment lower.
		//
		// It is a fifth producer of `{"error":"HTTP 404 Not Found"}`, after an
		// unmatched path, a wrong verb, a switched-off resource and an
		// unparseable bound, and the first that is an ordinary missing row.
		ID: "admin/authz-resource-server/resource-read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource id that resolves to nothing",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-missing",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/gloak-probe-no-such-resource",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// And the same missing resource one path segment lower answers an
		// **empty body with a Cache-Control** - no `Content-Type` and, because
		// the body is empty, no `X-Frame-Options`. Two 404s on one resource,
		// and the path segment is what decides.
		ID: "admin/authz-resource-server/resource-scopes-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource sub-route on an id that resolves to nothing",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-missing-sub",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/gloak-probe-no-such-resource/scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The search's hit: a **bare object**, not an array, and the match is
		// exact and case-sensitive where the listing's `name` is a
		// case-insensitive substring. Two parameters of one name on one family,
		// two meanings - the scope family's rule, re-measured here rather than
		// inherited.
		ID: "admin/authz-resource-server/resource-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: searching a resource by exact name",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/search",
		Fixture:   "authz-res-search",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/search",
			Query:   map[string]string{"name": "gloak-probe-solo"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The same name in the wrong case is a **204**, which is what says the
		// search does not fold where the listing does.
		ID: "admin/authz-resource-server/resource-search-miss",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource search that matches nothing",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-search-miss",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/search",
			Query:   map[string]string{"name": "GLOAK-PROBE-SOLO"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// An absent or empty `name` is a **400 with an empty body**, which is
		// the third of the search's three answers and the one a handler written
		// as "look it up and 404" would never produce.
		ID: "admin/authz-resource-server/resource-search-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource search with no name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-search-empty",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/search",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The PUT's 204: **no Cache-Control**, no body, and `X-Frame-Options`
		// because the request declared `application/json` - the empty-body rule
		// AGENTS.md records, holding on a third family.
		ID: "admin/authz-resource-server/resource-put",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: updating a resource",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}",
		Fixture:   "authz-res-put",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000fa01",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-full"}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type"},
	},
	{
		// What the 204 cannot show. The fixture has already sent that same PUT,
		// so this golden is the resource afterwards: `displayName`, `type`,
		// `icon_uri` and `scopes` gone, `uris` back to `[]`,
		// `ownerManagedAccess` back to false - and **`attributes` exactly as
		// they were**, which is the one field a replace does not replace.
		ID: "admin/authz-resource-server/resource-put-replaced",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: what a resource PUT replaces and what it keeps",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-put-replaced",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000fb01",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The update's 409 is `Duplicate resource error` and carries none of
		// the five security headers**, where the create's names the resource
		// and carries all five. The two cases above and this one are the
		// assertion; any one of them alone is a body.
		ID: "admin/authz-resource-server/resource-put-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource PUT onto a taken name",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-put-conflict",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000fc01",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-yankee"}`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Cache-Control"},
	},
	{
		// The delete's 204: **no Cache-Control**, a ninth measured delete, and
		// no `X-Frame-Options` because a delete sends no `Content-Type`.
		ID: "admin/authz-resource-server/resource-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: deleting a resource",
			Retrieved: "2026-09-01",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/resource/{resource-id}",
		Fixture:   "authz-res-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000fd01",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Cache-Control", "Content-Type", "X-Frame-Options"},
	},
	{
		// The delete's 404 is the read's, not the sub-routes': a JSON body and
		// no Cache-Control. The scope family's delete answers an empty body
		// with no Cache-Control, so these two deletes agree on the header and
		// disagree on the body.
		ID: "admin/authz-resource-server/resource-delete-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: deleting a resource that does not exist",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-missing-del",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/gloak-probe-no-such-resource",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The attribute map on its own, in the same order the representation
		// puts it in - which is what says the sub-route and the read share a
		// serialiser rather than each sorting.
		ID: "admin/authz-resource-server/resource-attributes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource's attributes",
			Retrieved: "2026-09-01",
		},
		Status: Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/" +
			"resource/{resource-id}/attributes",
		Fixture: "authz-res-attributes",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000fe01/attributes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`[]` is the store's truth rather than a stub**, for exactly as long
		// as Gloak has no permissions: on a live server this lists every
		// permission naming the resource and every scope permission naming a
		// scope it carries. The half of this route that is real behaviour today
		// is its 404, which the sub-route case above holds.
		ID: "admin/authz-resource-server/resource-permissions",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource's permissions",
			Retrieved: "2026-09-01",
		},
		Status: Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/" +
			"resource/{resource-id}/permissions",
		Fixture: "authz-res-permissions",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000ff01/permissions",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The third of three shapes a scope takes inside a resource**:
		// `{id, name}` here, `{id, name, iconUri}` inline in the resource, and
		// `{name}` in the settings export. The fixture's scope carries both an
		// iconUri and a displayName, so this golden and the read's are what say
		// which key each view drops.
		ID: "admin/authz-resource-server/resource-scopes",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a resource's scopes",
			Retrieved: "2026-09-01",
		},
		Status: Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/" +
			"resource/{resource-id}/scopes",
		Fixture: "authz-res-scopes",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"resource/5e50a5ce-0000-4000-8000-00000000e001/scopes",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The settings export carries resources**, which it did not before
		// this cut - not because Keycloak changed but because no fixture had a
		// resource to put in it, so the only value the key had ever taken was
		// `[]`. They come back in **creation order** where the listing sorts,
		// and each is the representation minus `_id` and `owner` with every
		// inline scope reduced to its name.
		ID: "admin/authz-resource-server/settings-with-resources",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the settings export with resources in it",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-res-settings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/settings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The scope-side read that stopped answering `[]` when this cut landed,
		// and which the second cut's comment said would. Its entry is two keys
		// with the **name first** - the only body in this API shaped that way -
		// and the rows come back in creation order, which the fixture's
		// out-of-name-order creates are what make an assertion.
		ID: "admin/authz-resource-server/scope-resources-populated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the resources naming a scope",
			Retrieved: "2026-09-01",
		},
		Status:  Implemented,
		Fixture: "authz-scope-resources-full",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"scope/5c0be000-0000-4000-8000-00000000e2e0/resources",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},

	// ---- P10 fourth cut: policy, permission and import ---------------------
	//
	// Appended at the very end of adminCases.
	{
		// **Sorted by name, byte-wise**, and the fixture creates them zulu,
		// yankee, xray, Zebra so this golden holding Zebra first is the
		// assertion - a case-folded sort would put it third.
		//
		// Two more measurements ride on the same body. `zulu` is a `role`
		// policy created with no config and answers `config:{"roles":"[]"}`,
		// which is the provider's own key added on the way in - its own 201
		// said `{}`. And `xray`'s config went in `{nbf, hour}` and comes back
		// **`{hour, nbf}`**, which is `javamap.SizedKeyOrder`; `javamap.KeyOrder`
		// returns the other order and is what this golden refuses.
		ID: "admin/authz-resource-server/policy-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the policy listing",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy",
		Fixture:   "authz-pol-list",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// Three filters in one request, which is how the golden says they are
		// **ANDed** rather than that each works alone.
		//
		// **`?type=` is a case-insensitive substring**, which `ti` is what
		// says: it finds `time` and nothing else. §1.9 of the third cut's
		// handover records this filter as exact and is wrong. `?name=` folds
		// case too, where the sort beside it does not.
		ID: "admin/authz-resource-server/policy-list-filtered",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the policy listing's filters",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-filter",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Query:  map[string]string{"type": "TI", "name": "XRA", "max": "5"},
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`?permission=true` keeps three of the nine types** - `resource`,
		// `scope` and `uma` - and this golden holds `yankee` and `Zebra` out of
		// the fixture's four. The `permission-list` case below asks the
		// `/permission` path for the same two rows and gets them in the typed
		// shape, and the pair is what separates the filter from the
		// serialisation.
		ID: "admin/authz-resource-server/policy-list-permission-true",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the policy listing filtered to permissions",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-permission",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Query:   map[string]string{"permission": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A bound that does not parse is a 404**, and this is the seventh
		// listing measured answering it. See the scope family's case of the
		// same name for the producers of that body.
		ID: "admin/authz-resource-server/policy-list-bad-bound",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a policy listing bound that does not parse",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-bound",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Query:   map[string]string{"first": "abc"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The create's 201 is the request echoed**, which is the opposite of
		// the resource create two path segments away. Three halves of this
		// golden say so: the `config` comes back exactly as it was sent where
		// the listing's version of the same row has the provider's `roles` key
		// added; `owner` and `resourceType` are echoed and no read serves
		// either; and the three association arrays are echoed as **resolved
		// ids** where the request named the scope and the resource by name.
		//
		// **No Location**, which is what AssertAbsentHeaders pins, and
		// `Cache-Control: no-cache`.
		ID: "admin/authz-resource-server/policy-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a policy",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy",
		Fixture:   "authz-pol-create",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9011ce00-0000-4000-8000-000000001599",` +
				`"name":"gloak-probe-created","description":"D","type":"uma",` +
				`"logic":"NEGATIVE","decisionStrategy":"AFFIRMATIVE","owner":"echoed",` +
				`"resourceType":"urn:gloak:echoed",` +
				`"scopes":["gloak-probe-pscope"],"policies":[],` +
				`"config":{"zzz":"1"}}`),
		},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		// **A duplicate name is the only 409 in this API that puts prose in
		// `error` and a category in `error_description`** - every other shape
		// on this surface is the other way round. It is also the second refusal
		// in the family that names what it refused, after the resource create's.
		//
		// **It carries all five security headers**, which AssertHeaders pins,
		// where the `PUT` onto the same taken name carries none. That pair is
		// F147's probe on a third family and it is recorded in the handover;
		// nothing here writes a rule about it.
		ID: "admin/authz-resource-server/policy-create-conflict",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a policy with a taken name",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-conflict",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-solo","type":"role"}`),
		},
		AssertHeaders: []string{
			"Content-Type", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
	},
	{
		// **A policy needs a name and a type, and missing either is this 409.**
		// This body carries a type and no name, which is the half §1.9 of the
		// third cut's handover and AGENTS.md both miss - they say `type` is the
		// gate, from a probe that only ever left the type out.
		ID: "admin/authz-resource-server/policy-create-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a policy with no name",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-noname",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"type":"role"}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **The accepted type set is not `GET .../policy/providers`' catalogue.**
		// `user` is in that catalogue, is offered to every caller who reads it,
		// and answers this 500 - so a validator built from the constant this
		// repository already ships would admit it and then fail.
		ID: "admin/authz-resource-server/policy-create-unknown-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a policy of a type the server refuses",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-badtype",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-usertype","type":"user"}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **`{"error":"unknown_error"}` with no `error_description` at all** -
		// an error shape this API has not been measured producing anywhere
		// else, and it belongs to the body's own `scopes` array alone. The same
		// unknown name inside `config.scopes` answers the ordinary consult-log
		// 500 instead, which is why the two do not share a resolver.
		//
		// It also pins the order: this body carries no `type` either, and the
		// scope resolution answers ahead of the presence check.
		ID: "admin/authz-resource-server/policy-create-unknown-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a policy naming a scope that does not exist",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-badscope",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-badscope","scopes":["gloak-probe-nothing"]}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The scope and resource searches' shape on a third family: an exact,
		// case-sensitive name and a **bare object** rather than an array.
		ID: "admin/authz-resource-server/policy-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: searching for a policy by name",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/search",
		Fixture:   "authz-pol-search",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy/search",
			Query:   map[string]string{"name": "gloak-probe-solo"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The match is case-sensitive and exact**, which this uppercase
		// request is what says: the fixture holds `gloak-probe-solo` and this
		// asks for it in capitals and gets the 204.
		ID: "admin/authz-resource-server/policy-search-miss",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a policy search that matches nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-search-miss",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy/search",
			Query:   map[string]string{"name": "GLOAK-PROBE-SOLO"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// An absent `name` is a **400 with an empty body**, and it carries the
		// `Cache-Control` the 200 does. The empty body is why X-Frame-Options
		// is absent - AGENTS.md's third security-header exception.
		ID: "admin/authz-resource-server/policy-search-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a policy search with no name",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-search-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/policy/search",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **The same two rows as `policy-list-permission-true`, one key apart.**
		// That pair is the probe that separates the filter from the
		// serialisation, and it is why both cases exist rather than one.
		//
		// Two of the eight typed shapes are in this body: `yankee` carries
		// `resourceType`, projected from `config.defaultResourceType` and
		// placed **after** `decisionStrategy`; `Zebra` carries `scopes`, placed
		// **between `type` and `logic`** because it is a base-class field where
		// the rest are the subclass's. Neither row carries a `config` key at
		// all.
		ID: "admin/authz-resource-server/permission-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the permission listing",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission",
		Fixture:   "authz-perm-list",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`POST .../permission` does not restrict the type.** This body says
		// `role`, which the listing beside it hides, and the answer is a 201 -
		// so the two creates really are one handler and only the reads split.
		// The row it makes is on `GET .../policy` and not on
		// `GET .../permission`.
		ID: "admin/authz-resource-server/permission-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: creating a permission",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission",
		Fixture:   "authz-perm-create",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"9011ce00-0000-4000-8000-000000001e99",` +
				`"name":"gloak-probe-permcreated","type":"role",` +
				`"resources":["gloak-probe-presource"],"policies":["gloak-probe-solo"]}`),
		},
		AssertHeaders:       []string{"Content-Type", "Cache-Control"},
		AssertAbsentHeaders: []string{"Location"},
	},
	{
		// **The search is not filtered by family.** This asks the
		// `/permission` spelling for a `role` policy and gets it, in the typed
		// shape - which makes this operation the only one in the description
		// that shows the typed representation of the six types
		// `GET .../permission` hides.
		//
		// The `roles: []` in it is the projection of the provider's own added
		// config key, and it is the empty case on purpose: a populated one
		// would hold a bootstrap-minted role id and would have to be masked.
		ID: "admin/authz-resource-server/permission-search-role",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a role policy through the permission search",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/search",
		Fixture:   "authz-perm-search-role",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission/search",
			Query:   map[string]string{"name": "gloak-probe-roled"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`targetContextAttributes` is emitted whether the config carries it
		// or not**, defaulting to false, where `roles` is emitted only because
		// the role provider writes the key. Two types, two reasons a field is
		// always there, and this fixture's config names neither.
		ID: "admin/authz-resource-server/permission-search-regex",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a regex policy's typed representation",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-perm-search-regex",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission/search",
			Query:   map[string]string{"name": "gloak-probe-regexed"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The whole twelve-field time table, in the order it was measured
		// coming back - and **two of the twelve are renamed on the way out**:
		// `config.nbf` is `notBefore` and `config.noa` is `notOnOrAfter`. The
		// generic view of the same row, which the listing case holds, serves
		// the config's own spellings.
		ID: "admin/authz-resource-server/permission-search-time",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a time policy's typed representation",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-perm-search-time",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission/search",
			Query:   map[string]string{"name": "gloak-probe-timed"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The permission search's miss, which is the policy search's: 204, an
		// empty body and the `Cache-Control` the 200 sends.
		ID: "admin/authz-resource-server/permission-search-miss",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: a permission search that matches nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-perm-search-miss",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/permission/search",
			Query:   map[string]string{"name": "gloak-probe-nothing"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **204 with no `Cache-Control`**, and it carries `X-Frame-Options`
		// because the request declared an `application/*` Content-Type -
		// AGENTS.md's third security-header exception, on a route that had not
		// been measured for it.
		ID: "admin/authz-resource-server/import",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: importing a resource server's settings",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/import",
		Fixture:   "authz-import",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/import",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **`import` is strict where `POST .../policy` beside it is not.** The
		// same unknown field is this 400 here and a 500 there, on one resource
		// server - which makes this the ninth strict endpoint and the first
		// whose immediate neighbour disagrees with it.
		ID: "admin/authz-resource-server/import-unknown-field",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: importing a body carrying an unknown field",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-import-strict",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/import",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"zzz":1}`),
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// What the import's 204 cannot show, read afterwards. Three measured
		// behaviours in one body:
		//
		//   - the three settings are **reset to the representation's own
		//     initialisers and then overwritten** by what the body named, which
		//     is `PUT .../authz/resource-server`'s rule;
		//   - **nothing is deleted** - `gloak-probe-pscope`,
		//     `gloak-probe-presource` and `gloak-probe-solo` are all still
		//     there and none was mentioned;
		//   - **a name the import already holds is merged into rather than
		//     replaced** - `gloak-probe-solo` arrived as a `regex` body and is
		//     still a `role` policy, with the imported `pattern` beside the
		//     `roles` its own provider wrote.
		ID: "admin/authz-resource-server/import-applied",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the settings after an import",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-import-applied",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/settings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The settings export carries policies**, which it did not before this
		// cut - not because Keycloak changed but because no fixture had a policy
		// to put in it, so the only value the key had ever taken was `[]`. That
		// is the second time this one struct has held such a key, one cut after
		// `resources`.
		//
		// **Its partition is not `GET .../permission`'s.** The fixture
		// interleaves the two families and this golden holds the `resource` and
		// `scope` rows last with `uma` among the policies, where the listing
		// counts `uma` as a permission. Two notions of "permission" one path
		// segment apart.
		//
		// **And its config is the live config denormalised.** `mike` reads back
		// `config:{}` from the listing and exports
		// `{"applyPolicies":["gloak-probe-alpha"]}`, synthesised from the
		// association by name; `bravo` and `delta` do the same for `resources`
		// and `scopes`. The id and the owner are dropped from every entry.
		ID: "admin/authz-resource-server/settings-with-policies",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: the settings export with policies in it",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "authz-pol-settings",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/settings",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **Measured and not served**, which is what `Recorded` is for.
		//
		// `userId` is this endpoint's gate: a body without one is this
		// consult-log 500, and a body with one runs the whole authorization
		// engine and answers 200 with a **full RPT** inside it - an access
		// token carrying `exp`, `iat`, `jti` and `sid`, a `realm_access`, a
		// `resource_access` and an `authorization.permissions` claim, beside a
		// `results` array holding every resource, its scopes, each permission
		// that applies, each of that permission's associated policies and their
		// individual PERMIT/DENY, and the allowed and denied scope sets.
		//
		// Two things put that outside this branch. The engine is nine policy
		// evaluators, decision-strategy aggregation and logic inversion, none
		// of which any other route on this surface needs. And the RPT is an
		// access token's claim set, which lives in `internal/token` - a package
		// this branch may not modify, and reproducing its claim set in
		// `internal/admin` would be the second-truth the boundary table exists
		// to prevent. See the handover.
		ID: "admin/authz-resource-server/policy-evaluate-no-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: evaluating with no subject",
			Retrieved: "2026-09-02",
		},
		Status: Recorded,
		Reason: "The 200 beside this 500 runs the authorization engine and mints an RPT, " +
			"which needs internal/token. Measured in full in " +
			"docs/superpowers/handover/p10-authz-policies.md.",
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/policy/evaluate",
		Fixture:   "authz-pol-evaluate",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"policy/evaluate",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The permission spelling of the same operation, and it answers
		// identically - measured side by side, on the gate and on the 200
		// alike. See the case above for why neither is served.
		ID: "admin/authz-resource-server/permission-evaluate-no-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Authorization services: evaluating a permission with no subject",
			Retrieved: "2026-09-02",
		},
		Status: Recorded,
		Reason: "The 200 beside this 500 runs the authorization engine and mints an RPT, " +
			"which needs internal/token. Measured in full in " +
			"docs/superpowers/handover/p10-authz-policies.md.",
		Operation: "POST /admin/realms/{realm}/clients/{client-uuid}/authz/resource-server/permission/evaluate",
		Fixture:   "authz-perm-evaluate",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/clients/{{client_uuid}}/authz/resource-server/" +
				"permission/evaluate",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// P9's second cut: the per-provider property catalogue and the mapper
	// family. See docs/superpowers/plans/2026-09-02-p9-provider-catalogue.md.
	{
		// **The catalogue's small end.** Eleven of the seventeen registered
		// providers declare no properties at all and `oidc` is one of them, so
		// this endpoint serves a provider's *extra* configuration rather than
		// its whole surface - which is worth a golden precisely because the
		// name says otherwise and an `oidc` broker plainly has a `clientId`.
		//
		// `helpText` is `""` and `configMetadata` is `[]` on all seventeen.
		ID: "admin/identity-providers/provider-info",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: get one provider's configuration properties",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/providers/{provider_id}",
		Fixture:   "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/providers/oidc",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The catalogue's big end, and the one entry where **one field carries
		// two JSON types**: `githubJsonFormat`'s default is the literal `false`
		// and `jwtAuthorizationGrantMaxAllowedAssertionExpiration`'s is the
		// string `"3600"`, both on providers this endpoint serves. A `string`
		// field loses the first and a `bool` loses the second, which is why the
		// catalogue holds an `any` and why this golden is worth its case.
		//
		// `google` is the biggest of the seventeen at 2386 bytes and six
		// properties.
		ID: "admin/identity-providers/provider-info-properties",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: a provider that declares properties",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/providers/google",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **An unregistered provider id is a 400 here and a 404 one path
		// segment away.** The instance routes answer an alias that does not
		// exist with the generic `HTTP 404 Not Found`; this route answers the
		// generic **400**. Two neighbouring families, one unknown name, two
		// statuses.
		ID: "admin/identity-providers/provider-info-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: an unregistered provider id",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/providers/gloak-probe-nosuch",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A Java map keyed on the mapper id, and its order is stored rather
		// than computed.** All thirteen measured key sets are bucket-monotone
		// at capacity 16; javamap.KeyOrder places eight of them and the five it
		// misses hold six colliding pairs, which is that package's documented
		// tie-break gap. Nothing is masked here - the order was byte-identical
		// across two container starts, so it is a constant of the version.
		//
		// The set is per provider and this is the ten an `oidc` broker offers.
		ID: "admin/identity-providers/mapper-types",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: the mapper types one instance offers",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/mapper-types",
		Fixture:   "idp-mt-oidc",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-mt-broker-oidc/mapper-types",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The biggest body in this half of the catalogue, 10212 bytes, and the
		// one that carries the two things the serialiser could get wrong and
		// nothing else would notice: an `options` array, and a helpText holding
		// `ATTRIBUTE.<NAME>`. Keycloak escapes none of `<`, `>` and `&`, and a
		// custom MarshalJSON cannot inherit the encoder's SetEscapeHTML(false),
		// so this golden is what pins marshalOrderedValue.
		//
		// A `saml` broker swaps six of the ten for SAML spellings, which is
		// also what says the set follows the provider rather than the route.
		ID: "admin/identity-providers/mapper-types-saml",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: a SAML instance's mapper types",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mt-saml",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-mt-broker-saml/mapper-types",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **Two of the seventeen answer this route with a 500**, on an instance
		// that was created without complaint and reads back normally through
		// every other route in the family - `linkedin-openid-connect` and
		// `openshift-v4`. Reproduced rather than smoothed into an empty map,
		// because what a caller gets is the 500.
		ID: "admin/identity-providers/mapper-types-unsupported",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: an instance whose mapper types cannot be listed",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mt-linkedin",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/master/identity-provider/instances/gloak-probe-mt-broker-li/mapper-types",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **The config is not filtered and the mapper type is not validated.**
		// `gloak-probe-undeclared` is not a property of
		// `oidc-user-attribute-idp-mapper` and it comes back; a create naming a
		// mapper type that does not exist is a 201. `POST /components` one
		// chapter away does the opposite on both counts, which is what makes
		// this golden the pair to `admin/component/list`.
		//
		// The four config keys are placed by javamap.SizedKeyOrder - the same
		// constructor the parent provider's config uses and the other one from
		// a component's. Nothing masks the order.
		ID: "admin/identity-providers/mappers-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: get one mapper",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}",
		Fixture:   "idp-mapper-one",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-one/mappers/1de07000-0000-4000-8000-000000000041",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The listing's order is masked, and this golden is exactly why the
		// mask is not something to argue away.** Five mappers created
		// `zzz, mmm, aaa, qqq, bbb` came back `bbb, zzz, qqq, mmm, aaa`, twice
		// on one container: it is a Java collection over the **mapper id**, and
		// an id is a minted UUID on any run that does not name one.
		//
		// The recorded body below happens to be in creation order, because this
		// fixture names its ids and names them ascending. That coincidence is a
		// fact about the ids chosen here and not about the endpoint, so the mask
		// stays - taking it off would turn "these three ids sort this way" into
		// a claim that Keycloak preserves creation order, which the five-mapper
		// probe measures as false.
		//
		// It is also the only route of the five that reads the path's alias:
		// the three that name a mapper id resolve it realm-wide.
		ID: "admin/identity-providers/mappers-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: list one instance's mappers",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
		Fixture:   "idp-mapper-listing",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-list/mappers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		Unordered:     []string{"."},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **A 201 with a Location and no Content-Type at all**, content-length
		// zero. The tail is the mapper's id, and the fixture names it, so
		// nothing here is masked - the body's `id` winning on this create is
		// the fifth endpoint in this API with that rule and this header is
		// where it is asserted.
		ID: "admin/identity-providers/mappers-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: add a mapper to an instance",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/identity-provider/instances/{alias}/mappers",
		Fixture:   "idp-mapper-create",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-new/mappers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"1de07000-0000-4000-8000-000000000046",` +
				`"name":"gloak-probe-mapper-fresh",` +
				`"identityProviderAlias":"gloak-probe-map-broker-new",` +
				`"identityProviderMapper":"oidc-hardcoded-role-idp-mapper",` +
				`"config":{"role":"offline_access","syncMode":"INHERIT"}}`),
		},
		AssertHeaders:       []string{"Location"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		// **A body with no name answers the duplicate-resource 409**, which is
		// the policy family's answer to the same omission and the third family
		// in this API to give it. Nothing is duplicated - the broker holds no
		// mappers at all.
		//
		// **It is a sixteenth golden for the security-header split**, and one of
		// the sharper ones: it sends **none** of the five, while the duplicate
		// 400 below and the empty-body 500 beside it - same route, same verb,
		// same `Content-Type` - send all five. Three failures of one endpoint,
		// two header sets, and nothing about the request or the response tells
		// them apart. See F147, which says exactly that and is not being
		// explained here either.
		ID: "admin/identity-providers/mappers-create-no-name",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: adding a mapper with no name",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mapper-noname",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-non/mappers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"identityProviderAlias":"gloak-probe-map-broker-non",` +
				`"identityProviderMapper":"oidc-username-idp-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **A name the alias already holds is a 400, not a 409**, and the
		// sentence names the provider's `providerId` where the route carries
		// its alias. So the two ways a name can fail on this endpoint are two
		// different statuses and neither is the one the rest of the API uses
		// for a duplicate.
		ID: "admin/identity-providers/mappers-create-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: adding a mapper whose name is taken",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mapper-taken",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-dup/mappers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"name":"gloak-probe-mapper-taken",` +
				`"identityProviderAlias":"gloak-probe-map-broker-dup",` +
				`"identityProviderMapper":"oidc-username-idp-mapper"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **An empty body is a 500** where a merely malformed one is a 400 -
		// the same defect `POST /users` has, on a different endpoint, and
		// reproduced for the same reason.
		ID: "admin/identity-providers/mappers-create-empty-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: adding a mapper with no body",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mapper-empty",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-emp/mappers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(``),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A 204 with `Cache-Control: no-cache`, and the update **replaces**:
		// this body names one config key on a mapper holding four, and the read
		// afterwards is one key. `PUT /components/{id}` one chapter away merges
		// and cannot clear a config at all, so the two neighbouring updates are
		// opposite on the same verb.
		//
		// The request declares JSON, so the 204 carries `X-Frame-Options` -
		// which is the rule AGENTS.md records about the request's Content-Type
		// rather than about the method.
		ID: "admin/identity-providers/mappers-update",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: update one mapper",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "PUT /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}",
		Fixture:   "idp-mapper-update",
		Request: Request{
			Method: http.MethodPut,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-upd/mappers/1de07000-0000-4000-8000-000000000047",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"id":"1de07000-0000-4000-8000-000000000047",` +
				`"name":"gloak-probe-mapper-target",` +
				`"identityProviderAlias":"gloak-probe-map-broker-upd",` +
				`"identityProviderMapper":"oidc-user-attribute-idp-mapper",` +
				`"config":{"claim":"gloak-probe-replaced"}}`),
		},
		AssertHeaders: []string{"Cache-Control", "X-Frame-Options"},
	},
	{
		// The delete's 204 carries `Cache-Control: no-cache` and **no**
		// `X-Frame-Options`, because the request declares no Content-Type -
		// which is what decides that header on a 204, per AGENTS.md, and which
		// this case and the update above assert as a pair.
		ID: "admin/identity-providers/mappers-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: delete one mapper",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/identity-provider/instances/{alias}/mappers/{id}",
		Fixture:   "idp-mapper-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-del/mappers/1de07000-0000-4000-8000-000000000048",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Cache-Control"},
		AssertAbsentHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **`Model not found` is a new spelling of not-found**, and it is in the
		// bare-`error` family. The provider family around it answers an unknown
		// alias with the generic `HTTP 404 Not Found`, so one chapter now has
		// both - and the Component chapter beside it has two more of its own.
		ID: "admin/identity-providers/mappers-read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: a mapper id that resolves to nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "idp-mapper-create",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/identity-provider/instances/" +
				"gloak-probe-map-broker-new/mappers/1de07000-0000-4000-8000-0000000000ff",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	// ---- P12 second cut: an organization's members, invitations and identity
	// providers. Appended at the very end of adminCases and nowhere else.
	// Everything below was measured 2026-09-02 against a live 26.7.1.
	{
		// **The listing pages by default**, which no other listing in this API
		// does: `max` is 10 and `first` is 0 when the request says nothing. That
		// is not visible in this golden - three members fit inside ten - and it
		// is `TestTheMemberListingPagesByDefault` that pins it. What this golden
		// holds is the **order** and the brief shape: three members whose
		// usernames and e-mails sort in opposite directions come back by
		// username, so a handler sorting by e-mail or returning insertion order
		// produces different bytes.
		//
		// The brief shape is nine keys and ends in `membershipType`, which is a
		// fourth serialisation of one user in this API.
		ID: "admin/organizations/members-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: return a paginated list of organization members",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/members",
		Fixture:   "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		// briefRepresentation=false adds exactly four keys - totp,
		// disableableCredentialTypes, requiredActions and notBefore - **before**
		// membershipType rather than after it, which is what says the member
		// shape is a user representation with one field appended and not a
		// shape of its own.
		ID: "admin/organizations/members-list-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member listing under briefRepresentation=false",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		// **search is a case-insensitive substring here and a prefix on the user
		// listing**, measured side by side with this very needle: `armot` is
		// inside `gloak-probe-marmot` and is not a prefix of it, and
		// `GET /users?search=armot` answers `[]` on the same realm.
		ID: "admin/organizations/members-search",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member listing's search",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Query:   map[string]string{"search": "armot"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		// The control for the case above, on the same realm and with the same
		// needle. **This is the pair**: one body holds a row and the other is
		// empty, and nothing but the route differs.
		ID: "admin/organizations/members-search-control",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Users: the user listing's search is a prefix",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/users",
			Query:   map[string]string{"search": "armot"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// exact narrows search to the whole value of one of the same four
		// fields - here the last name, which no other seed carries.
		ID: "admin/organizations/members-search-exact",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member listing's exact",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Query: map[string]string{
				"search": "Alpha", "exact": "true", "briefRepresentation": "false",
			},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		// membershipType is the one member-only field, and UNMANAGED is the only
		// value this project can produce - MANAGED belongs to a user the
		// organization provisioned itself, which needs a mail sender.
		ID: "admin/organizations/members-membership-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member listing's membershipType",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Query:   map[string]string{"membershipType": "MANAGED"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The bounds. `first=2` skips two of the three, which is what says the
		// listing pages from an offset rather than only capping.
		ID: "admin/organizations/members-paged",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member listing's first and max",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members",
			Query:   map[string]string{"first": "2", "max": "5"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"*/createdTimestamp"},
	},
	{
		ID: "admin/organizations/members-list-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: an organization with no members",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The count reads none of the listing's parameters.** This request
		// carries the search that answers one row next door and the count still
		// answers three. The organization count one path segment up honours its
		// own search, so the two disagree.
		ID: "admin/organizations/members-count",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the number of members in an organization",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/members/count",
		Fixture:   "org-members",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem/organizations/{{org_id}}/members/count",
			Query:   map[string]string{"search": "armot", "membershipType": "MANAGED"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/members-count-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the member count of an empty organization",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members/count",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The full shape, and it is byte-identical to an entry of the listing
		// under briefRepresentation=false. Neither carries the `access` block
		// `GET /users/{id}` has, nor its `federatedIdentities`.
		ID: "admin/organizations/members-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: return the member with the specified id",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/members/{member-id}",
		Fixture:   "org-member-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}/members/{{member_1}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
	},
	{
		// **The single read ignores briefRepresentation**, exactly as the
		// organization single read one path segment up does. This body is the
		// one above, byte for byte, under a parameter that moves the listing.
		ID: "admin/organizations/members-read-brief-ignored",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: briefRepresentation does nothing to the single member read",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-member-one",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}/members/{{member_1}}",
			Query:   map[string]string{"briefRepresentation": "true"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		Volatile:      []string{"createdTimestamp"},
	},
	{
		// **A user who exists and is not a member is the generic 404**, the same
		// bytes a member id that resolves to nothing gets. So the member routes
		// join the four producers of that body this document already records,
		// and nothing on the wire tells the two cases apart.
		ID: "admin/organizations/members-read-not-a-member",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a member id that is a user of the realm and not a member",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members/{{stranger_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The 201's Location ends in the id the caller sent**, not a
		// server-minted one, which makes this the fifth create in this API whose
		// tail the caller chose - and the reason VolatileTailHeaders is wrong
		// for it: once ReplaceCaptured has run there is nothing minted left in
		// the header, so it is asserted whole.
		//
		// The body it sends is the bare user id and **not JSON**; see
		// `TestTheMemberAddReadsARawUserIDRatherThanJSON` for the ten bodies
		// that pin the rule, which no single golden can.
		ID: "admin/organizations/members-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: add the user with the specified id as a member",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations/{org-id}/members",
		Fixture:   "org-member-add",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mem-add/organizations/{{org_id}}/members",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{{stranger_id}}`),
		},
		AssertHeaders:       []string{"Location", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A user id that resolves to nothing, on the write. It is the generic
		// 404 rather than any of the twenty-five spellings.
		ID: "admin/organizations/members-add-unknown-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: adding a member id that resolves to nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`"11111111-2222-3333-4444-555555555555"`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The duplicate sentence has a full stop and reads "is already a
		// member"**, where invite-user's 409 for the same condition has neither.
		// One family, one condition, two sentences.
		ID: "admin/organizations/members-add-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: adding a user who is already a member",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-member-taken",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mem-dup/organizations/{{org_id}}/members",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{{member_1}}`),
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **An absent Content-Type is accepted**, and this 409 is what says so:
		// the request reached the duplicate check rather than being refused
		// ahead of it. A wrong one - `text/plain`,
		// `application/x-www-form-urlencoded`, `application/xml` - is a 415,
		// which is `requireJSONBody`'s existing rule.
		//
		// **F149's premise is false here**, and the way this cut found out is
		// worth keeping: the probe that "sent no Content-Type" was Python's
		// urllib, which adds `application/x-www-form-urlencoded` to any POST
		// carrying data that does not already name one, so it measured the 415
		// of a header it had set itself. The recorder builds its requests by
		// hand, recorded this 409, and a socket-level re-measurement settled it.
		ID: "admin/organizations/members-add-no-content-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: adding a member with no Content-Type",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-member-taken",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/admin/realms/gloak-probe-org-mem-dup/organizations/{{org_id}}/members",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
			Body:    []byte(`{{member_1}}`),
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The 204 carries neither Cache-Control nor X-Frame-Options: the request
		// sends no Content-Type, which is what decides the second, and this
		// endpoint is one of those that send no Cache-Control on a 204 at all.
		ID: "admin/organizations/members-remove",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: remove the user with the specified id from the organization",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/organizations/{org-id}/members/{member-id}",
		Fixture:   "org-member-delete",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/admin/realms/gloak-probe-org-mem-del/organizations/{{org_id}}/members/{{member_1}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control", "X-Frame-Options"},
	},
	{
		// **The member's organization groups are always empty**, and that is the
		// contract rather than a stub: the groups it answers are the
		// organization's own, which are F120's eleven blocked operations, and a
		// live 26.7.1 answers `[]` too until somebody creates one.
		ID: "admin/organizations/members-groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the organization group memberships of a member",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/members/{member-id}/groups",
		Fixture:   "org-member-one",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}" +
				"/members/{{member_1}}/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The **brief organization shape**, which is the listing's default one
		// path segment up: no attributes, and no domains because this
		// organization has none.
		ID: "admin/organizations/members-organizations",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the organizations associated with a member",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/members/{member-id}/organizations",
		Fixture:   "org-member-one",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}" +
				"/members/{{member_1}}/organizations",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// briefRepresentation=false adds `attributes` and nothing else - the
		// same one key it adds to the organization listing, and the reason this
		// route is not a fourth organization shape.
		ID: "admin/organizations/members-organizations-full",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: a member's organizations under briefRepresentation=false",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-member-one",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}" +
				"/members/{{member_1}}/organizations",
			Query:   map[string]string{"briefRepresentation": "false"},
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The invitation listing carries no Cache-Control**, where every other
		// read in this tag carries `no-cache`. One endpoint of nine, pinned per
		// endpoint the way Cache-Control on a 204 already is - which is why this
		// case names it in AssertAbsentHeaders rather than leaving it out.
		//
		// It is `[]` on every realm this project can build, and that is the
		// contract: both invite endpoints need a mail sender, so no invitation
		// can exist. See internal/admin/organizationinvitations.go.
		ID: "admin/organizations/invitations-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: get invitations for the organization",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/invitations",
		Fixture:   "org-empty",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/invitations",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// `Invitation not found` - the twenty-fifth spelling of not-found, with
		// no full stop where `Organization not found.` one path segment up has
		// one.
		ID: "admin/organizations/invitations-read-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: get invitation by ID",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/invitations/{id}",
		Fixture:   "org-empty",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}" +
				"/invitations/gloak-probe-no-such-invitation",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/organizations/invitations-delete-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: delete an invitation",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/organizations/{org-id}/invitations/{id}",
		Fixture:   "org-empty",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}" +
				"/invitations/gloak-probe-no-such-invitation",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **A resend is not a resend**, measured against a family populated
		// through a throwaway SMTP sink: it answers 204 and the invitation it
		// names is gone, replaced by one with a new id, a new sentDate and a new
		// link. None of that is reachable here, so what this golden holds is the
		// 404 - which is what every default container answers.
		ID: "admin/organizations/invitations-resend-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: resend an invitation",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations/{org-id}/invitations/{id}/resend",
		Fixture:   "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}" +
				"/invitations/gloak-probe-no-such-invitation/resend",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The 500 is the contract.** Both invite endpoints send an e-mail, and
		// a realm with no smtpServer - master's and every realm
		// POST /admin/realms creates - answers this for every well-formed
		// request. It is the same shape as VERIFY_EMAIL's 500 and CIBA's 503.
		ID: "admin/organizations/invite-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: invite a user by e-mail address",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations/{org-id}/members/invite-user",
		Fixture:   "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members/invite-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"email": "gloak-probe-invitee@gloak-probe-members.example.com"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The missing required field is the errorMessage family here** and the
		// bare-`error` family on invite-existing-user one path segment away.
		ID: "admin/organizations/invite-user-no-email",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: inviting with no e-mail address",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}/members/invite-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"firstName": "gloak-probe-nobody"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The 409 for a member's e-mail: **no full stop and "already a
		// member"**, where POST .../members answers the same condition with a
		// full stop and "is already a member".
		ID: "admin/organizations/invite-user-already-a-member",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: inviting the e-mail address of a member",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-member-one",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}" +
				"/members/invite-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"email": "solo@gloak-probe-members.example.com"},
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The bare-`error` family for a missing required field**, which is the
		// half of this pair that surprises: its sibling above answers the same
		// kind of failure with `errorMessage`.
		ID: "admin/organizations/invite-existing-user-no-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: inviting an existing user with no id",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}" +
				"/members/invite-existing-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"nothing": "gloak-probe-nothing"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "admin/organizations/invite-existing-user-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: inviting an existing user id that resolves to nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-empty",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-org-mem-nil/organizations/{{org_id}}" +
				"/members/invite-existing-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"id": "11111111-2222-3333-4444-555555555555"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **It does not check membership.** The person invite-user refuses with
		// a 409 reaches the mail sender here, which is what makes the two
		// endpoints two endpoints.
		ID: "admin/organizations/invite-existing-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: invite an existing user by id",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations/{org-id}/members/invite-existing-user",
		Fixture:   "org-member-one",
		Request: Request{
			Method: http.MethodPost,
			Path: "/admin/realms/gloak-probe-org-one-mem/organizations/{{org_id}}" +
				"/members/invite-existing-user",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/x-www-form-urlencoded",
			},
			Form: map[string]string{"id": "{{member_1}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The organization's identity providers, and the body is the identity
		// provider chapter's own - `organizationId` and all. That is the
		// finding: the association is a **column on the provider**, so this
		// listing serves rows the realm's own listing serves too.
		ID: "admin/organizations/identity-providers-list",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: all identity providers associated with the organization",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/identity-providers",
		Fixture:   "org-broker",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-brk/organizations/{{org_id}}/identity-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/identity-providers-list-empty",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: an organization with no identity providers",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker-loose",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-brk-new/organizations/{{org_id}}/identity-providers",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "admin/organizations/identity-providers-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: the identity provider with the specified alias",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}",
		Fixture:   "org-broker",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-brk/organizations/{{org_id}}" +
				"/identity-providers/gloak-probe-org-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The realm's own read of the same provider, which is where the
		// `organizationId` key turns up. **Two chapters, one row**: this is what
		// says the association is a column rather than a join table.
		ID: "admin/organizations/identity-providers-realm-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Identity Providers: a provider associated with an organization",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/admin/realms/gloak-probe-org-brk/identity-provider/instances/gloak-probe-org-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// **The read's 404 is not the delete's.** The same missing association
		// answers `Identity provider not associated with the organization` here
		// and `Identity provider not found with the given alias` from the
		// delete, measured on one alias in one session.
		ID: "admin/organizations/identity-providers-read-unassociated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: an alias not associated with the organization",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker-loose",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-brk-new/organizations/{{org_id}}" +
				"/identity-providers/gloak-probe-org-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The other sentence, from the delete, on the same missing association.
		ID: "admin/organizations/identity-providers-delete-unassociated",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: removing an alias not associated with the organization",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker-loose",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/gloak-probe-org-brk-new/organizations/{{org_id}}" +
				"/identity-providers/gloak-probe-org-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The association is a 204 with no Location**, where the member add in
		// the same family is a 201 with one. Two adds on one resource, two
		// statuses.
		ID: "admin/organizations/identity-providers-add",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: add the identity provider with the specified id",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "POST /admin/realms/{realm}/organizations/{org-id}/identity-providers",
		Fixture:   "org-broker-add",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-brk-add/organizations/{{org_id}}/identity-providers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`"gloak-probe-org-idp"`),
		},
		AssertHeaders:       []string{"X-Frame-Options"},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control", "Location"},
	},
	{
		// An alias that resolves to nothing is a **400** carrying the delete's
		// sentence - one set of words reaching the wire under two statuses.
		ID: "admin/organizations/identity-providers-add-unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: associating an alias that resolves to nothing",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker-loose",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-brk-new/organizations/{{org_id}}/identity-providers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`"gloak-probe-no-such-broker"`),
		},
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// The 409 whose sentence differs from the 400 beside it by one
		// preposition - `to` against `with`.
		ID: "admin/organizations/identity-providers-add-duplicate",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: associating an alias the organization already holds",
			Retrieved: "2026-09-02",
		},
		Status:  Implemented,
		Fixture: "org-broker",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/admin/realms/gloak-probe-org-brk/organizations/{{org_id}}/identity-providers",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`"gloak-probe-org-idp"`),
		},
		AssertHeaders:       []string{"Content-Type", "X-Frame-Options"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **Always an empty array**, for the member-groups case's reason: the
		// groups it answers are the organization's own, which are F120's.
		ID: "admin/organizations/identity-providers-groups",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: organization groups for the identity provider",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "GET /admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}/groups",
		Fixture:   "org-broker",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/gloak-probe-org-brk/organizations/{{org_id}}" +
				"/identity-providers/gloak-probe-org-idp/groups",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The 204 that ends the family, and the one operation whose effect is
		// visible two chapters away: after it the realm's own read of that
		// provider stops carrying `organizationId`.
		ID: "admin/organizations/identity-providers-delete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Organizations: remove the identity provider from the organization",
			Retrieved: "2026-09-02",
		},
		Status:    Implemented,
		Operation: "DELETE /admin/realms/{realm}/organizations/{org-id}/identity-providers/{alias}",
		Fixture:   "org-broker-delete",
		Request: Request{
			Method: http.MethodDelete,
			Path: "/admin/realms/gloak-probe-org-brk-del/organizations/{{org_id}}" +
				"/identity-providers/gloak-probe-org-idp",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertAbsentHeaders: []string{"Content-Type", "Cache-Control", "X-Frame-Options"},
	},
}
