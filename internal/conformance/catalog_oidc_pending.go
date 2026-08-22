package conformance

import "net/http"

// oidcPending is the documented OIDC surface Gloak does not serve yet. Each
// entry is one behaviour named at https://www.keycloak.org/securing-apps/oidc-layers.
// Recording a pending case is deliberate: the bytes become the specification
// for the feature before anybody starts writing it.
//
// Fixture is "bootstrap" only where a freshly bootstrapped Keycloak can serve
// the request unaided - mostly the error cases. Everything needing a
// confidential client with a known secret, a second user, a completed
// browser login, or a previously issued token gets Fixture: "" so the
// recorder skips it; the bootstrap fixture has no way to hand a case a token
// it did not itself request, since a Case's Request is a literal, not a
// chained sequence of calls.
var oidcPending = []Case{
	// --- Authorization endpoint ---
	// admin-cli has standard flow disabled (see the observed spec's
	// "Bootstrap of the master realm" table), so every case below uses
	// security-admin-console, which is public with standard flow enabled.
	{
		ID: "oidc/authorization/code-flow-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: authorization code grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the redirect back
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/pkce-s256",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, S256 challenge method",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the redirect back
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type":         "code",
				"client_id":             "security-admin-console",
				"redirect_uri":          "http://localhost:8080/admin/master/console/",
				"scope":                 "openid",
				"state":                 "xyz123",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "S256",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/pkce-plain",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, plain challenge method",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the redirect back
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type":         "code",
				"client_id":             "security-admin-console",
				"redirect_uri":          "http://localhost:8080/admin/master/console/",
				"scope":                 "openid",
				"state":                 "xyz123",
				"code_challenge":        "plainverifier1234567890123456789012345678",
				"code_challenge_method": "plain",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/implicit-flow",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: implicit",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the redirect back
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "id_token token",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid",
				"state":         "xyz123",
				"nonce":         "abc123",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/response-mode-fragment",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: response_mode=fragment",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the redirect back
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"response_mode": "fragment",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/response-mode-form-post",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: response_mode=form_post",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "", // needs a completed browser login to observe the auto-submitted form
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"response_mode": "form_post",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/authorization/prompt-none-no-session",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: prompt=none",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the authorization endpoint is not implemented",
		// Measured: recording this with Fixture: "bootstrap" produced the
		// same "Invalid parameter: redirect_uri" page as invalid-redirect-uri
		// below, not a login_required response. A Case's redirect_uri is a
		// literal chosen when this file was written, and Keycloak's
		// security-admin-console redirect pattern only validates against the
		// exact host:port the recorder's container answers on at run time,
		// which is assigned by testcontainers and unknowable in advance.
		// There is no literal that reaches the intended behaviour.
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid",
				"state":         "xyz123",
				"prompt":        "none",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/authorization/invalid-redirect-uri",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: redirect URI validation",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "security-admin-console",
				"redirect_uri":  "https://evil.example/callback",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/authorization/unknown-client-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: client validation",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "nosuchclient",
				"redirect_uri":  "https://client.example.com/callback",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/authorization/missing-response-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: request validation",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the authorization endpoint is not implemented",
		// Measured: recording this with Fixture: "bootstrap" produced the
		// same "Invalid parameter: redirect_uri" page as invalid-redirect-uri
		// above; redirect_uri validation runs before response_type
		// validation, and no literal redirect_uri matches the recorder's
		// container at run time (see prompt-none-no-session above).
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"client_id":    "security-admin-console",
				"redirect_uri": "http://localhost:8080/admin/master/console/",
				"scope":        "openid",
				"state":        "xyz123",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/authorization/unsupported-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: scope validation",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the authorization endpoint is not implemented",
		// Measured: same "Invalid parameter: redirect_uri" outcome as the
		// two cases above, for the same reason.
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"scope":         "openid nosuchscope",
				"state":         "xyz123",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Token endpoint ---
	// expires_in and refresh_expires_in are not in these cases' Volatile
	// lists. They are configured token lifespans (60 and 1800 for master;
	// see the "Token endpoint response" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md), not
	// per-request randomness - but that is measured for exactly one of the
	// eight token-issuing cases this affects, not for all eight.
	//
	// oidc/token/password-grant-admin-cli, the only one with a bootstrap
	// fixture today, was recorded twice against independent fresh containers
	// (2026-08-20) and returned identical expires_in/refresh_expires_in both
	// times - the only field that changed between the two runs was scope's
	// word order, already tracked below. That is a measurement.
	//
	// The other seven - oidc/token/authorization-code-grant,
	// refresh-token-grant, client-credentials-grant, device-code-grant,
	// ciba-grant, dpop-bound-token, and oidc/ciba/poll-complete further down
	// this file - have no golden at all; none of them can be recorded yet.
	// Unmasking expires_in/refresh_expires_in for those seven is an
	// inference from the one measured case, not a measurement of its own: it
	// assumes they share the master realm's token endpoint closely enough to
	// behave the same way. The direction is safe - removing a path from
	// Volatile writes no value anywhere, and a wrong inference fails loudly
	// the moment a case gains a fixture and gets recorded - but it is an
	// inference, not the measurement this project's rule asks for. Confirm
	// each one when it gains a fixture.
	//
	// oidc/token/refresh-token-grant is the weakest member of the seven:
	// refresh_expires_in on a *refresh* response is bounded by the
	// remaining SSO session lifetime, not purely by the configured
	// refresh-token lifespan, so "configured lifespan, not randomness" is
	// least obviously safe there. That is a flag for whoever measures it,
	// not a measurement.
	//
	// session_state stays masked in all eight: it is a fresh UUID per
	// response, unlike the two duration fields.
	{
		ID: "oidc/token/password-grant-admin-cli",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: Resource Owner Password Credentials grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
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
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
		// The scope field's word order (e.g. "profile email" vs "email
		// profile") is not stable across container starts - see the
		// "scopes_supported order" finding in
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md,
		// same underlying cause (a Java set with no fixed iteration order),
		// just surfacing inside a space-separated string here instead of a
		// JSON array.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/token/unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: client authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "nosuchclient",
				"username":   "admin",
				"password":   "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/authorization-code-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: authorization code",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs an authorization code from a completed browser login
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    "security-admin-console",
				"redirect_uri": "http://localhost:8080/admin/master/console/",
				"code":         "REPLACE-WITH-A-REAL-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
	},
	{
		ID: "oidc/token/refresh-token-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: refresh_token grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     "admin-cli",
				"refresh_token": "{{refresh_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
		// See password-grant-admin-cli for why scope's word order is not
		// stable across container starts.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/token/client-credentials-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client credentials",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a confidential client with a service account, which no bootstrapped client has
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     "gloak-service-client",
				"client_secret": "REPLACE-WITH-A-REAL-SECRET",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"access_token"},
	},
	{
		ID: "oidc/token/device-code-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a device_code from a completed device authorization request
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "REPLACE-WITH-A-REAL-DEVICE-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
	},
	{
		ID: "oidc/token/ciba-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs an auth_req_id from a completed CIBA authentication request
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "admin-cli",
				"auth_req_id": "REPLACE-WITH-A-REAL-AUTH-REQ-ID",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
	},
	{
		ID: "oidc/token/token-exchange",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: token exchange",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // token exchange needs a previously issued token and is a feature that must be explicitly enabled
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"client_id":          "admin-cli",
				"subject_token":      "REPLACE-WITH-A-REAL-TOKEN",
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/jwt-authorization-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: JWT bearer authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a client configured to trust a signed JWT assertion, which no bootstrapped client has
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
				"client_id":  "admin-cli",
				"assertion":  "REPLACE-WITH-A-REAL-SIGNED-JWT",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/dpop-bound-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: DPoP-bound tokens",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a client configured to require DPoP, which no bootstrapped client has, and a proof JWT bound to the request
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Headers: map[string]string{
				"DPoP": "REPLACE-WITH-A-REAL-DPOP-PROOF",
			},
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "admin",
				"password":   "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
	},
	{
		ID: "oidc/token/wrong-password",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: Resource Owner Password Credentials grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "admin",
				"password":   "wrong-password",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/wrong-client-secret",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: client authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "password",
				"client_id":     "broker",
				"client_secret": "wrong-secret",
				"username":      "admin",
				"password":      "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/missing-grant-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: request validation",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"client_id": "admin-cli",
				"username":  "admin",
				"password":  "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/unknown-grant-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: request validation",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "nosuchgrant",
				"client_id":  "admin-cli",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/replayed-code",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: authorization code reuse",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a real authorization code from a completed browser login, used twice
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    "security-admin-console",
				"redirect_uri": "http://localhost:8080/admin/master/console/",
				"code":         "REPLACE-WITH-AN-ALREADY-CONSUMED-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/invalid-refresh-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: refresh_token grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     "admin-cli",
				"refresh_token": "not-a-refresh-token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/token/pkce-verifier-mismatch",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, S256 challenge method",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the token endpoint is not implemented",
		Fixture: "", // needs a real code from a PKCE-initiated browser login, exchanged with the wrong verifier
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "authorization_code",
				"client_id":     "security-admin-console",
				"redirect_uri":  "http://localhost:8080/admin/master/console/",
				"code":          "REPLACE-WITH-A-REAL-PKCE-CODE",
				"code_verifier": "the-wrong-verifier-0123456789012345678901",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Userinfo endpoint ---
	{
		ID: "oidc/userinfo/invalid-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer not-a-token"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
		// Measured: userinfo is the second exception to the five security
		// headers reaching every response - it sends four of them and omits
		// X-Frame-Options, on every status measured so far. Pinned as an
		// absent header because AssertHeaders can only ever check a header
		// that is named, so nothing else would catch an implementation that
		// started sending it everywhere "for consistency".
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "oidc/userinfo/get-with-valid-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "userinfo is not implemented",
		// Measured 2026-08-21: no bootstrapped client can produce a token
		// this endpoint accepts. admin-cli is the only one of the six with
		// direct access grants enabled, and it carries
		// client.use.lightweight.access.token.enabled = true, which userinfo
		// rejects outright - 401 with error="invalid_token" and
		// error_description="Lightweight access token not allowed for
		// userinfo endpoint", regardless of the scope requested. Reaching
		// the success body needs either a completed browser login or a
		// client created through the admin API. See lightweight-token below,
		// which pins the refusal that was measured instead.
		Fixture: "",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer REPLACE-WITH-A-NON-LIGHTWEIGHT-ACCESS-TOKEN"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// Measured while recording get-with-valid-token: userinfo refuses a
		// lightweight access token whatever its scope, and the refusal is
		// not the same shape as the invalid-token one - the status is 401
		// either way, but the error code and description differ.
		ID: "oidc/userinfo/lightweight-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-21",
		},
		Status:  Implemented,
		Fixture: "admin-token-openid",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
		// Measured: userinfo is the second exception to the five security
		// headers reaching every response - it sends four of them and omits
		// X-Frame-Options, on every status measured so far. Pinned as an
		// absent header because AssertHeaders can only ever check a header
		// that is named, so nothing else would catch an implementation that
		// started sending it everywhere "for consistency".
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		// Measured while recording get-with-valid-token against the
		// admin-token fixture, which asks for no scope: userinfo refuses a
		// token that lacks openid, with a shape that is neither the success
		// body nor the invalid-token rejection. Kept as a case of its own
		// rather than discarded, since the bytes are already measured.
		ID: "oidc/userinfo/token-without-openid-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-21",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
		// Measured: userinfo is the second exception to the five security
		// headers reaching every response - it sends four of them and omits
		// X-Frame-Options, on every status measured so far. Pinned as an
		// absent header because AssertHeaders can only ever check a header
		// that is named, so nothing else would catch an implementation that
		// started sending it everywhere "for consistency".
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "oidc/userinfo/post-with-valid-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "userinfo is not implemented",
		// Blocked by the same measured refusal as get-with-valid-token
		// above: the only bootstrapped client with direct access grants
		// issues lightweight tokens, which userinfo does not accept.
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/userinfo",
			Form: map[string]string{
				"access_token": "REPLACE-WITH-A-NON-LIGHTWEIGHT-ACCESS-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/userinfo/expired-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "userinfo is not implemented",
		Fixture: "", // needs a real access token allowed to expire, which a bootstrap fixture cannot wait out
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer REPLACE-WITH-A-REAL-EXPIRED-ACCESS-TOKEN"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
	},
	{
		ID: "oidc/userinfo/missing-authorization-header",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/userinfo",
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
		// Measured: userinfo is the second exception to the five security
		// headers reaching every response - it sends four of them and omits
		// X-Frame-Options, on every status measured so far. Pinned as an
		// absent header because AssertHeaders can only ever check a header
		// that is named, so nothing else would catch an implementation that
		// started sending it everywhere "for consistency".
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},

	// --- Logout endpoint ---
	{
		ID: "oidc/logout/rp-initiated-with-id-token-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the logout endpoint is not implemented",
		Fixture: "", // needs a real id_token from a completed browser login
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "REPLACE-WITH-A-REAL-ID-TOKEN",
				"post_logout_redirect_uri": "http://localhost:8080/admin/master/console/",
				"state":                    "xyz123",
			},
		},
		AssertHeaders: []string{"Location"},
	},
	{
		ID: "oidc/logout/rp-initiated-without-id-token-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the logout endpoint is not implemented",
		// Measured: recording this with Fixture: "bootstrap" produced the
		// same "Invalid redirect uri" page as invalid-post-logout-redirect-uri
		// below, for the same reason as the authorization-endpoint cases
		// above - no literal post_logout_redirect_uri matches the recorder's
		// container at run time.
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":                "security-admin-console",
				"post_logout_redirect_uri": "http://localhost:8080/admin/master/console/",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/logout/invalid-post-logout-redirect-uri",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: redirect URI validation",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the logout endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":                "security-admin-console",
				"post_logout_redirect_uri": "https://evil.example/callback",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/logout/backchannel",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: backchannel logout",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the logout endpoint is not implemented",
		Fixture: "", // needs a client with a registered backchannel logout URL and an active session; Keycloak calls the client, the client does not call this
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":     "gloak-backchannel-client",
				"id_token_hint": "REPLACE-WITH-A-REAL-ID-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/logout/frontchannel",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: frontchannel logout",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the logout endpoint is not implemented",
		Fixture: "", // needs a client with a registered frontchannel logout URL and an active session
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":     "gloak-frontchannel-client",
				"id_token_hint": "REPLACE-WITH-A-REAL-ID-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Introspection endpoint ---
	{
		ID: "oidc/introspection/active-access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the introspection endpoint is not implemented",
		// A live access token is now obtainable - the admin-token fixture
		// has one - but that is not what blocks this case. Introspecting
		// with client_id "admin-cli" was measured returning 403
		// {"error":"invalid_request","error_description":"Client not
		// allowed."}: admin-cli is public, and Keycloak refuses
		// introspection to public clients outright, so the response never
		// reaches the shape this case names. See inactive-token below, where
		// that was measured. Getting there needs a confidential client with
		// a known secret, which arrives with client management.
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id": "admin-cli",
				"token":     "REPLACE-WITH-A-REAL-ACCESS-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/introspection/active-refresh-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the introspection endpoint is not implemented",
		// Blocked by the same measured refusal as active-access-token above:
		// admin-cli is public and Keycloak does not let public clients
		// introspect. A confidential client is what unblocks it, not a
		// token.
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":       "admin-cli",
				"token":           "REPLACE-WITH-A-REAL-REFRESH-TOKEN",
				"token_type_hint": "refresh_token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/introspection/inactive-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the introspection endpoint is not implemented",
		// Measured: recording this with Fixture: "bootstrap" and client_id:
		// "admin-cli" returned 403 {"error":"invalid_request",
		// "error_description":"Client not allowed."} - admin-cli is public
		// and Keycloak refuses introspection to public clients outright, so
		// the response never reaches the {"active":false} shape this case
		// names. Getting there needs a confidential client with a known
		// secret, which no bootstrapped client has (see wrong-client-secret
		// above for why broker's real secret is unknown).
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id": "admin-cli",
				"token":     "not-a-token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/introspection/unauthenticated-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the introspection endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"token": "not-a-token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Token revocation endpoint ---
	{
		ID: "oidc/revocation/refresh-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the token revocation endpoint is not implemented",
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/revoke",
			Form: map[string]string{
				"client_id": "admin-cli",
				"token":     "{{refresh_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/revocation/access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the token revocation endpoint is not implemented",
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/revoke",
			Form: map[string]string{
				"client_id":       "admin-cli",
				"token":           "{{access_token}}",
				"token_type_hint": "access_token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/revocation/unknown-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the token revocation endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/revoke",
			Form: map[string]string{
				"client_id": "admin-cli",
				"token":     "not-a-token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/revocation/wrong-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint: client authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the token revocation endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/revoke",
			Form: map[string]string{
				"client_id":     "broker",
				"client_secret": "wrong-secret",
				"token":         "not-a-token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Device authorization endpoint ---
	{
		ID: "oidc/device/authorization-request",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the device authorization endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/auth/device",
			Form: map[string]string{
				"client_id": "admin-cli",
				"scope":     "openid",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"device_code", "user_code", "verification_uri",
			"verification_uri_complete", "expires_in", "interval",
		},
	},
	{
		ID: "oidc/device/poll-authorization-pending",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the device authorization endpoint is not implemented",
		Fixture: "", // needs a real device_code that has not yet been authorized by a user
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "REPLACE-WITH-A-REAL-PENDING-DEVICE-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/poll-slow-down",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the device authorization endpoint is not implemented",
		Fixture: "", // needs a real device_code polled faster than the returned interval
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "REPLACE-WITH-A-REAL-DEVICE-CODE-POLLED-TOO-FAST",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/poll-expired-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the device authorization endpoint is not implemented",
		Fixture: "", // needs a real device_code left to expire, which a bootstrap fixture cannot wait out
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "REPLACE-WITH-A-REAL-EXPIRED-DEVICE-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/poll-access-denied",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the device authorization endpoint is not implemented",
		Fixture: "", // needs a real device_code that a second user denied via the browser
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "REPLACE-WITH-A-REAL-DENIED-DEVICE-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Backchannel authentication endpoint (CIBA) ---
	{
		ID: "oidc/ciba/authentication-request",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the backchannel authentication endpoint is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id":       "admin-cli",
				"scope":           "openid",
				"login_hint":      "admin",
				"binding_message": "gloak-probe",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"auth_req_id", "expires_in", "interval"},
	},
	{
		ID: "oidc/ciba/poll-pending",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the backchannel authentication endpoint is not implemented",
		Fixture: "", // needs a real auth_req_id that a second user has not yet approved
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "admin-cli",
				"auth_req_id": "REPLACE-WITH-A-REAL-PENDING-AUTH-REQ-ID",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/ciba/poll-complete",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "the backchannel authentication endpoint is not implemented",
		Fixture: "", // needs a real auth_req_id that a second user has approved
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "admin-cli",
				"auth_req_id": "REPLACE-WITH-A-REAL-APPROVED-AUTH-REQ-ID",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
	},

	// --- Dynamic client registration ---
	{
		ID: "oidc/registration/create-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "", // needs an initial access token, which the bootstrap fixture has no admin API access to mint
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Authorization": "Bearer REPLACE-WITH-A-REAL-INITIAL-ACCESS-TOKEN",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe","redirect_uris":["http://localhost:8080/admin/master/console/"]}`),
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri", "client_id_issued_at", "client_secret_expires_at"},
	},
	{
		ID: "oidc/registration/read-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "", // needs a client created via registration and its registration access token
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/clients-registrations/openid-connect/gloak-probe",
			Headers: map[string]string{
				"Authorization": "Bearer REPLACE-WITH-A-REAL-REGISTRATION-ACCESS-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri", "client_id_issued_at", "client_secret_expires_at"},
	},
	{
		ID: "oidc/registration/update-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "", // needs a client created via registration and its registration access token
		Request: Request{
			Method: http.MethodPut,
			Path:   "/realms/master/clients-registrations/openid-connect/gloak-probe",
			Headers: map[string]string{
				"Authorization": "Bearer REPLACE-WITH-A-REAL-REGISTRATION-ACCESS-TOKEN",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_id":"gloak-probe","client_name":"gloak-probe-renamed","redirect_uris":["http://localhost:8080/admin/master/console/"]}`),
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri", "client_id_issued_at", "client_secret_expires_at"},
	},
	{
		ID: "oidc/registration/delete-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "", // needs a client created via registration and its registration access token
		Request: Request{
			Method: http.MethodDelete,
			Path:   "/realms/master/clients-registrations/openid-connect/gloak-probe",
			Headers: map[string]string{
				"Authorization": "Bearer REPLACE-WITH-A-REAL-REGISTRATION-ACCESS-TOKEN",
			},
		},
	},
	{
		ID: "oidc/registration/without-initial-access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: anonymous registration",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe","redirect_uris":["http://localhost:8080/admin/master/console/"]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/with-registration-access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: authenticating subsequent requests",
			Retrieved: "2026-08-20",
		},
		Status:  Pending,
		Reason:  "dynamic client registration is not implemented",
		Fixture: "", // needs the per-client registration access token issued at creation time
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/clients-registrations/openid-connect/gloak-probe",
			Headers: map[string]string{
				"Authorization": "Bearer REPLACE-WITH-A-REAL-REGISTRATION-ACCESS-TOKEN",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"client_id", "client_secret", "registration_access_token", "registration_client_uri", "client_id_issued_at", "client_secret_expires_at"},
	},
}
