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
	//
	// These cases named security-admin-console until 2026-08-29, on the
	// reasoning that it is the one bootstrapped public client with the standard
	// flow enabled. It is, and it cannot serve nine of them. It pins
	// pkce.code.challenge.method to S256, so a request carrying no
	// code_challenge_method is refused with "Missing parameter:
	// code_challenge_method" before anything else is looked at; and its
	// redirectUris is the host-relative "/admin/master/console/*", resolved
	// against whatever host and port the request arrived on, so no absolute
	// literal here can match the recorder's run-time port. Four of the cases
	// carried a comment about the second half of that and none about the first.
	//
	// They now register their own client instead. See browserRedirectURI in
	// fixture.go, and the "The bootstrapped clients cannot serve most of the
	// cases that name them" section of
	// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
	//
	// The success redirects mask their whole Location. It carries a code and a
	// session_state minted by the case's own request, which no fixture can
	// capture and mask by name, so the alternative was a golden that churns on
	// every recording. What that costs is the query key order - measured as
	// state, session_state, iss, code - and it is a real loss, recorded as a
	// follow-up rather than hidden here. The **error** redirects are not masked:
	// after ReplaceIssuer they hold nothing per-request, so their error code,
	// description and key order are all pinned exactly.
	{
		ID: "oidc/authorization/code-flow-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: authorization code grant",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "browser-login",
		// The fixture stops at the login page, so the case's own request is
		// the credential POST and its own response is the redirect carrying
		// the code. {{login_action}} is the form's action, captured from the
		// page: it holds session_code, execution, client_id, tab_id and
		// client_data, all minted per request.
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		AssertHeaders: []string{"Location", "Cache-Control"},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/pkce-s256",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, S256 challenge method",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "browser-login-s256",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		AssertHeaders: []string{"Location", "Cache-Control"},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/pkce-plain",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, plain challenge method",
			Retrieved: "2026-08-20",
		},
		Status: Recorded,
		Reason: "the authorization endpoint is not implemented",
		// Measured: a client with no pkce.code.challenge.method accepts either
		// method. This case was impossible against security-admin-console,
		// which pins S256 and answers "code challenge method is not matching
		// the configured one" to plain - not a mismeasurement but an
		// unreachable case.
		Fixture: "browser-login-plain",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		AssertHeaders: []string{"Location", "Cache-Control"},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/implicit-flow",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: implicit",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the implicit flow is out of P3's scope",
		// Measured 2026-08-29 on a client with the implicit flow disabled,
		// which is the default: 302 with the error in the **fragment**, not
		// the query, without any response_mode being asked for - the default
		// response mode follows the response type. A case for that belongs
		// with whichever sub-project builds the implicit flow, and writing one
		// here would claim surface P3 is not building.
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "id_token token",
				"client_id":     "gloak-probe-browser",
				"redirect_uri":  "http://localhost:9999/callback",
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
		Status:  Recorded,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "browser-login-frag",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		AssertHeaders: []string{"Location", "Cache-Control"},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/response-mode-form-post",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: response_mode=form_post",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the harness cannot mask a per-request value inside an HTML body",
		// Measured 2026-08-29 and recorded in the observed spec: form_post
		// answers **200** with an auto-submitting form, not a redirect, and
		// its Content-Type is text/html with no charset where the login page's
		// is text/html;charset=utf-8. The parameter order inside the form is
		// code, iss, state, session_state, which is not the query redirect's
		// state, session_state, iss, code.
		//
		// It is Pending rather than Recorded because the golden cannot be
		// written yet. The body carries a live code, session_state, tab_id and
		// client_data, all minted by this request. Case.Volatile addresses
		// paths into a JSON document and there is no equivalent for HTML, so
		// the golden would churn on every recording and could never match a
		// served implementation. The mechanism is the next cut's; inventing it
		// here to land one case is how a harness grows a feature nothing
		// needs twice.
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		AssertHeaders:   []string{"Content-Type", "Cache-Control"},
		VolatileHeaders: []string{"Set-Cookie"},
	},
	{
		ID: "oidc/authorization/prompt-none-no-session",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: prompt=none",
			Retrieved: "2026-08-20",
		},
		Status: Recorded,
		Reason: "the authorization endpoint is not implemented",
		// This case recorded the "Invalid parameter: redirect_uri" page until
		// 2026-08-29, and its old comment concluded there was no literal that
		// could reach the intended behaviour. There is: a client the fixture
		// registers with an absolute pattern. Nothing follows the redirect, so
		// the URI never has to resolve.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "gloak-probe-browser",
				"redirect_uri":  "http://localhost:9999/callback",
				"scope":         "openid",
				"state":         "xyz123",
				"prompt":        "none",
			},
		},
		AssertHeaders: []string{"Location", "Cache-Control"},
		// AUTH_SESSION_ID and KC_AUTH_SESSION_HASH are minted per request. The
		// attributes on them are contract and are recorded in the observed
		// spec rather than here; nothing asserts this header either way, and
		// left unmasked it churns the golden on every recording.
		VolatileHeaders: []string{"Set-Cookie"},
		// Measured: this redirect is the one response in the whole browser
		// flow that omits X-Frame-Options, and it omits Content-Security-Policy
		// with it. login-actions' own error redirect, to the same URI with the
		// same status, carries both. Pinned as absent because AssertHeaders can
		// only check a header that is named.
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/authorization/invalid-redirect-uri",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: redirect URI validation",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the login theme is P13, and this response is a theme page",
		// Measured 2026-08-29: 400, text/html;charset=utf-8, no Cache-Control
		// at all, and 3618 bytes of the keycloak.v2 theme whose
		// /resources/<hash>/ segment is regenerated per container start. Two
		// recordings from one container are byte-identical and two containers
		// are not, so the golden already in the repository churns on every
		// re-record. That is the churn the P3 design defers to P13, now
		// measured rather than assumed.
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
		Reason:  "the login theme is P13, and this response is a theme page",
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
		Status: Recorded,
		Reason: "the authorization endpoint is not implemented",
		// The old comment here was right that redirect_uri validation runs
		// first and wrong that nothing could get past it. Once the redirect
		// URI validates, the rejection is a redirect rather than a page, which
		// is the split the P3 design's section 4 is about.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"client_id":    "gloak-probe-browser",
				"redirect_uri": "http://localhost:9999/callback",
				"scope":        "openid",
				"state":        "xyz123",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/authorization/unsupported-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: scope validation",
			Retrieved: "2026-08-20",
		},
		Status:  Recorded,
		Reason:  "the authorization endpoint is not implemented",
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "gloak-probe-browser",
				"redirect_uri":  "http://localhost:9999/callback",
				"scope":         "openid nosuchscope",
				"state":         "xyz123",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
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
		Status:  Recorded,
		Reason:  "the token endpoint does not serve the authorization_code grant",
		Fixture: "browser-code",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    "gloak-probe-browser",
				"redirect_uri": "http://localhost:9999/callback",
				"code":         "{{code}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Pragma"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
		// See password-grant-admin-cli for why scope's word order is not
		// stable across container starts.
		UnorderedWords: []string{"scope"},
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
		Status: Implemented,
		// Measured 2026-08-23: this grant's body is three keys short of the
		// password grant's. No refresh_token, no session_state and no
		// id_token, but refresh_expires_in is present and 0 - so the two
		// absences are absences and the third is a zero, which no amount of
		// reasoning from the password grant would have produced.
		Fixture: "confidential-service-account",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     "gloak-confidential-sa",
				"client_secret": "{{client_secret}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"access_token"},
		// See password-grant-admin-cli for why scope's word order is not
		// stable across container starts.
		UnorderedWords: []string{"scope"},
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
		Status: Recorded,
		Reason: "the token endpoint does not serve the authorization_code grant",
		// The fixture redeems the code once, so this request is the replay.
		Fixture: "browser-code-spent",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    "gloak-probe-browser",
				"redirect_uri": "http://localhost:9999/callback",
				"code":         "{{code}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Pragma"},
	},
	{
		// A refresh token that verifies and whose session an administrator
		// ended. Measured 2026-08-23: "Session not active", where a garbage
		// token gets "Invalid refresh token" - two causes, two messages, one
		// status. A revocation produces the same message, so P1's assertion
		// that revocation gave the other one was a guess and is corrected.
		ID: "oidc/token/refresh-after-logout",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: refresh_token grant, session ended",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "logged-out-user",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":    "refresh_token",
				"client_id":     "admin-cli",
				"refresh_token": "{{user_refresh_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A token that never was one. The neighbouring case,
		// refresh-after-logout, uses a token that verifies and whose session
		// has been ended - and gets a different message for the same status.
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
		Status: Recorded,
		Reason: "the token endpoint does not serve the authorization_code grant",
		// The login is its own, not shared with authorization-code-grant.
		// Measured 2026-08-29: a failed exchange spends the code, so a second
		// case reusing this login would measure "Code not valid" instead of
		// the PKCE failure.
		Fixture: "browser-code-mismatch",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":   "authorization_code",
				"client_id":    "gloak-probe-browser",
				"redirect_uri": "http://localhost:9999/callback",
				"code":         "{{code}}",
				// 43 characters, RFC 7636's minimum, and not the verifier
				// whose challenge the fixture sent.
				"code_verifier": "gloak-probe-wrong-code-verifier-0123456789A",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Pragma"},
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
		Status: Implemented,
		// Unblocked 2026-08-23 by client management: a client created through
		// the admin API carries no lightweight-token attribute, so its access
		// tokens are the full set userinfo accepts. The refusal measured in
		// its place on 2026-08-21 is kept as lightweight-token below.
		Fixture: "confidential-user-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		// Cache-Control is asserted because this response sends it **twice** -
		// no-store and then no-cache - where the four rejections send only
		// no-store. Both values are compared; see the header folding in
		// conformance_test.go.
		//
		// X-Frame-Options is asserted because, unlike the four rejections,
		// this response carries it. That is what stops the four-of-five rule
		// being applied to the endpoint as a whole.
		AssertHeaders: []string{"Content-Type", "Cache-Control", "X-Frame-Options"},
		// sub is the administrator's user ID, minted at bootstrap, so it
		// differs between the reference container and Gloak on every run.
		Volatile: []string{"sub"},
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
		Status: Implemented,
		// The token arrives in the form rather than in a header, and the
		// response was measured byte-identical to the GET's - same body, same
		// doubled Cache-Control, same five security headers.
		Fixture: "confidential-user-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/userinfo",
			Form: map[string]string{
				"access_token": "{{access_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "X-Frame-Options"},
		Volatile:      []string{"sub"},
	},
	{
		ID: "oidc/userinfo/expired-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Implemented,
		// The fixture shortens the client's access token to one second
		// through the access.token.lifespan attribute and then waits two.
		// Three routes to a token born expired were tried and measured
		// first: "0" yields expires_in 0 with a token the server still
		// accepts, "-1" falls back to 36000 rather than to the realm's 60,
		// and there is no other knob. Waiting is the only one that works,
		// which is why Fixture.Delay exists and why it has one user.
		Fixture: "confidential-expired-token",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/protocol/openid-connect/userinfo",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "WWW-Authenticate"},
		// A rejection, so back to four of the five security headers.
		AssertAbsentHeaders: []string{"X-Frame-Options"},
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
		Status:  Recorded,
		Reason:  "the logout endpoint is not implemented",
		Fixture: "browser-logged-in",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "{{id_token}}",
				"post_logout_redirect_uri": "http://localhost:9999/callback",
				"state":                    "xyz123",
			},
		},
		// Measured 2026-08-29: the redirect carries **state and nothing
		// else**. No iss, where the authorization endpoint's redirect carries
		// one, so this Location holds nothing per-request and is asserted
		// exactly rather than masked. Cache-Control is no-cache here and
		// "no-store, must-revalidate, max-age=0" at /auth.
		AssertHeaders: []string{"Location", "Cache-Control"},
		// A fresh AUTH_SESSION_ID, plus KEYCLOAK_IDENTITY and KEYCLOAK_SESSION
		// cleared with Max-Age=0. Per-request, so masked.
		VolatileHeaders: []string{"Set-Cookie"},
		// The same omission the authorization endpoint's redirect has. The
		// two endpoints that redirect a browser to a client's registered URI
		// both drop these two; login-actions, redirecting to the very same
		// URI, does not.
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/logout/rp-initiated-without-id-token-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		Reason: "the login theme is P13, and this response is a theme page",
		// Measured 2026-08-29, and it is not the redirect this case was
		// written to expect. Without an id_token_hint the logout endpoint
		// serves the theme's "Logging out" confirmation page - 200,
		// text/html;charset=utf-8, "Do you want to log out?" - whatever the
		// post_logout_redirect_uri is and whether or not it validates. So
		// AssertHeaders naming Location was asserting a header that does not
		// exist on this response, and the earlier comment's diagnosis, that
		// the run-time port was to blame, was measuring the wrong thing.
		//
		// It is a theme page, so it moves to P13 with the other three. P3's
		// share of oidc/logout is one case, not two.
		Fixture: "",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":                "gloak-probe-browser-logout",
				"post_logout_redirect_uri": "http://localhost:9999/callback",
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
		Status: Pending,
		Reason: "the login theme is P13, and this response is a theme page",
		// Measured 2026-08-29: 400, text/html;charset=utf-8, the theme's error
		// page with the instruction "Invalid redirect uri". Same per-container
		// resource hash as the authorization endpoint's two, same deferral.
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
		Reason: "no fixture can put the introspecting client in an access token's audience",
		// The confidential client that P1's note was waiting for now exists,
		// and it is still not enough. Measured 2026-08-23: introspecting a
		// freshly minted, unexpired access token answers 200
		// {"active":false}, and the server log gives the reason - `reason=
		// "Client 'gloak-confidential' is not in the token audience"`. An
		// access token's aud holds the clients the *user* has roles on, never
		// the issuing client, so a client cannot introspect its own token.
		//
		// Reaching an active body therefore needs the caller inside that aud,
		// which needs either a role on the caller assigned to the user - the
		// Role Mapper tag, P2's second cut - or an audience protocol mapper,
		// which is P5. Recording it now would put {"active":false} in a file
		// named active-access-token, which is worse than leaving it Pending.
		//
		// The refusal itself is measured and recorded, as
		// access-token-outside-audience below.
		Fixture: "",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":     "gloak-confidential",
				"client_secret": "REPLACE-WITH-A-REAL-SECRET",
				"token":         "REPLACE-WITH-AN-ACCESS-TOKEN-NAMING-THIS-CLIENT-IN-AUD",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The refusal measured while trying to record active-access-token.
		// Recorded until F18: Gloak's access tokens named their own client in
		// aud, so this answered active where Keycloak answers inactive.
		ID: "oidc/introspection/access-token-outside-audience",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint: caller outside the token audience",
			Retrieved: "2026-08-23",
		},
		Status:  Implemented,
		Fixture: "confidential-user-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":     "gloak-confidential",
				"client_secret": "{{client_secret}}",
				"token":         "{{access_token}}",
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
		Status: Implemented,
		// A refresh token introspects active where an access token does not:
		// the audience check that refuses the access token is not applied
		// here. Measured 2026-08-23.
		//
		// The body is not RFC 7662's small set. It is the *access* token's
		// claim set rebuilt from the refresh token - realm_access,
		// resource_access, acr, preferred_username and all - with client_id,
		// username, token_type and active appended. It was Recorded until F18
		// resolved roles at issuance, and the alarm that says so is what
		// promoted it.
		Fixture: "confidential-user-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":       "gloak-confidential",
				"client_secret":   "{{client_secret}}",
				"token":           "{{refresh_token}}",
				"token_type_hint": "refresh_token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile:      []string{"exp", "iat", "jti", "sub", "sid"},
		// Java sets again: the two role lists and aud have no fixed order.
		Unordered: []string{"aud", "realm_access/roles", "resource_access/*/roles"},
		// scope is a space-separated list from the same kind of set.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/introspection/inactive-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Introspection endpoint",
			Retrieved: "2026-08-20",
		},
		Status: Implemented,
		// Unblocked by client management. The earlier attempt used admin-cli
		// and never got past the public-client refusal - 403 {"error":
		// "invalid_request","error_description":"Client not allowed."} - so
		// the {"active":false} shape this case names was never reached. A
		// confidential client reaches it.
		Fixture: "confidential-user-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token/introspect",
			Form: map[string]string{
				"client_id":     "gloak-confidential",
				"client_secret": "{{client_secret}}",
				"token":         "not-a-token",
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
		Status:  Implemented,
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
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/revoke",
			Form: map[string]string{
				"client_id": "admin-cli",
				"token":     "{{refresh_token}}",
			},
		},
		// Measured: the revocation success carries no Content-Type at all -
		// its body is empty - and is the only response recorded so far
		// carrying Content-Security-Policy. Asserting Content-Type here would
		// fail on "asserted but absent from the golden", which says nothing
		// about the implementation; the pair below pins what was measured.
		AssertHeaders:       []string{"Content-Security-Policy"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/revocation/access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
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
		// Same measured shape as refresh-token above.
		AssertHeaders:       []string{"Content-Security-Policy"},
		AssertAbsentHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/revocation/unknown-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token revocation endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
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
		Status:  Implemented,
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
