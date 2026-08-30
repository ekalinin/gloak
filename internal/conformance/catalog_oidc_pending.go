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
		Status:  Implemented,
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
		// The header set is asserted, not only the two values P3 could reach.
		// X-Frame-Options and Content-Security-Policy are the point: this
		// endpoint's 302 carries both where GET /auth's 302, to the very same
		// URI with the very same status, carries neither. That difference is
		// the one a reader comparing the two endpoints most easily assumes
		// away, and until now no case asserted it. The goldens already held
		// these values, so nothing was re-recorded to claim them.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy",
			"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Robots-Tag", "Set-Cookie",
		},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole - so both are asserted on presence.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/pkce-s256",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, S256 challenge method",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
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
		// The header set is asserted, not only the two values P3 could reach.
		// X-Frame-Options and Content-Security-Policy are the point: this
		// endpoint's 302 carries both where GET /auth's 302, to the very same
		// URI with the very same status, carries neither. That difference is
		// the one a reader comparing the two endpoints most easily assumes
		// away, and until now no case asserted it. The goldens already held
		// these values, so nothing was re-recorded to claim them.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy",
			"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Robots-Tag", "Set-Cookie",
		},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole - so both are asserted on presence.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/pkce-plain",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, plain challenge method",
			Retrieved: "2026-08-20",
		},
		Status: Implemented,
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
		// The header set is asserted, not only the two values P3 could reach.
		// X-Frame-Options and Content-Security-Policy are the point: this
		// endpoint's 302 carries both where GET /auth's 302, to the very same
		// URI with the very same status, carries neither. That difference is
		// the one a reader comparing the two endpoints most easily assumes
		// away, and until now no case asserted it. The goldens already held
		// these values, so nothing was re-recorded to claim them.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy",
			"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Robots-Tag", "Set-Cookie",
		},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole - so both are asserted on presence.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		// The replay of a credential POST, and the one response in this flow
		// whose Location can be asserted **by value**.
		//
		// Every other case here masks its Location whole, because a success
		// carries a code and a session_state this request minted. This one
		// carries `error`, `error_description`, `state` and `iss` and nothing
		// else, so its key order and both its strings are pinned exactly - and
		// they are the strings a browser meets whenever it uses its back button
		// after signing in.
		//
		// Measured 2026-08-30 as a grid over the three cookies. Which of three
		// answers a replay gets depends on the cookies alone: KC_RESTART
		// present restarts, KEYCLOAK_IDENTITY alone answers this, and neither
		// answers a 400 page. The fixture reaches this branch because the login
		// itself clears KC_RESTART.
		ID: "oidc/authorization/replayed-session-code",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authentication: replaying a spent session code",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "browser-login-expired",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "admin",
				"password":     "admin",
				"credentialId": "",
			},
		},
		// Location is asserted by value, which nothing else in this family can
		// do. Set-Cookie is not asserted at all: measured, this branch sets
		// none, and AssertAbsentHeaders says so rather than leaving it to the
		// golden nobody compares.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy", "X-Frame-Options",
		},
		AssertAbsentHeaders: []string{"Set-Cookie"},
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
		Status:  Implemented,
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
		// The header set is asserted, not only the two values P3 could reach.
		// X-Frame-Options and Content-Security-Policy are the point: this
		// endpoint's 302 carries both where GET /auth's 302, to the very same
		// URI with the very same status, carries neither. That difference is
		// the one a reader comparing the two endpoints most easily assumes
		// away, and until now no case asserted it. The goldens already held
		// these values, so nothing was re-recorded to claim them.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy",
			"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Robots-Tag", "Set-Cookie",
		},
		// Location carries a code and a session_state minted by this request;
		// Set-Cookie carries KEYCLOAK_IDENTITY and KEYCLOAK_SESSION, equally
		// per-request. Neither can be captured by a fixture and masked by
		// name, so both are masked whole - so both are asserted on presence.
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
	// this file - had no golden at all when this was written; none of them
	// could be recorded yet. Unmasking expires_in/refresh_expires_in for those
	// seven was an inference from the one measured case, not a measurement of
	// its own: it assumed they share the master realm's token endpoint closely
	// enough to behave the same way. The direction is safe - removing a path
	// from Volatile writes no value anywhere, and a wrong inference fails
	// loudly the moment a case gains a fixture and gets recorded - but it is an
	// inference, not the measurement this project's rule asks for. Confirm
	// each one when it gains a fixture.
	//
	// **Three of the seven have been confirmed since.**
	// oidc/token/authorization-code-grant, client-credentials-grant and
	// refresh-token-grant all carry recorded goldens now, with expires_in 60
	// and refresh_expires_in 1800 asserted rather than masked, so the
	// inference held everywhere it has been tested - including on the refresh
	// response the paragraph below calls the weakest. Four remain inferred.
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
		Status:  Implemented,
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
		Status: Pending,
		// **This reason said "the token endpoint is not implemented" until
		// 2026-08-30, and that had been false since P1.** The token endpoint
		// has served four grants for days and now dispatches this one too;
		// what is missing is an *approved* device code, which needs the
		// verification and consent pages. Same reason as
		// oidc/device/poll-access-denied, and the client_id was admin-cli,
		// which has the grant disabled and so could never have reached this
		// body at all.
		Reason:  "a completed device authorization needs the device verification and consent pages, which are not implemented",
		Fixture: "", // needs a device_code a user approved through the browser
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device",
				"device_code": "REPLACE-WITH-A-REAL-APPROVED-DEVICE-CODE",
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
		Status: Pending,
		// The same correction: the token endpoint is implemented and dispatches
		// this grant. What is missing is an auth_req_id, and a default 26.7.1
		// mints none - see the CIBA block further down. The client_id was
		// admin-cli, which has the CIBA grant disabled and so could never have
		// reached this body either.
		Reason:  "a default 26.7.1 has no CIBA authentication channel, so no auth_req_id can be obtained to redeem",
		Fixture: "", // needs an auth_req_id, which needs an external authentication channel endpoint
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "gloak-probe-ciba",
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
		Reason:  "the token-exchange grant is not implemented",
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
		Reason:  "the jwt-bearer grant is not implemented",
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
		Reason:  "DPoP is not implemented",
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
		// The authorization endpoint's `duplicated parameter` has a sibling
		// here, measured 2026-08-30, and two things about it are this
		// endpoint's own.
		//
		// It reads the **body** and not the query: `zz` twice on the query of
		// an otherwise valid password grant is a 200, one in each is a 200, and
		// both in the body is this 400. And it runs **after** client
		// authentication, where /auth's runs seventh - `zz` twice with an
		// unknown client_id is the 401 and `zz` twice with a valid client and a
		// wrong password is this. It is not this grant's either: `grant_type`
		// twice answers the same way, and so does `zz` twice on an
		// authorization_code request.
		//
		// The request is spelled with Body rather than Form because Form is a
		// Go map and cannot say a key twice - the same thing RawQuery exists
		// for on the query side. The Content-Type has to be set by hand for the
		// same reason: buildRequest only sets it for a Form.
		ID: "oidc/token/duplicated-parameter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: request validation",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/protocol/openid-connect/token",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte("grant_type=password&client_id=admin-cli&username=admin&password=admin&zz=1&zz=2"),
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Pragma"},
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
		Status: Implemented,
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
		Status: Implemented,
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
		Status: Implemented,
		// The fixture moved from browser-logged-in to logout-hint on 2026-08-29,
		// and the case measures the same response.
		//
		// browser-logged-in drives Keycloak's login form, which Gloak does not
		// serve until P13, so this case could never run against Gloak however
		// well the endpoint worked - it would sit at Recorded with the endpoint
		// finished. Measured on one container: a direct grant's id_token_hint
		// with no cookie jar at all produces a byte-identical 302, differing
		// only in the two cookie clears a browser session would have had, which
		// this case masks as volatile and does not assert.
		Fixture: "logout-hint",
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
		Status: Implemented,
		// **This case is back to the redirect it was originally written to
		// expect, and the reading that moved it to P13 was wrong.**
		//
		// Measured 2026-08-29 on one container, the same request with and
		// without a cookie jar:
		//
		//	with a live browser session   200, the theme's "Logging out" page
		//	with no session at all        302 to the registered target
		//
		// The confirmation page is what a logout serves when it has a session
		// to end and no authority to end it without asking. The measurement
		// that produced "logout without an id_token_hint does not redirect"
		// was taken through a jar and read the session for the parameter. This
		// case sends no cookies, so it is the second row.
		//
		// It has its own client rather than sharing logout-hint's, because it
		// is the one case that must NOT have a session on the client it names:
		// a client carrying one would answer the page here and the case would
		// stop measuring what it says it measures.
		Fixture: "logout-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"client_id":                "gloak-probe-logout-client",
				"post_logout_redirect_uri": "http://localhost:9999/callback",
				"state":                    "xyz123",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		VolatileHeaders:     []string{"Set-Cookie"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/logout/post-logout-uri-defaults-to-redirect-uris",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: redirect URI validation",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The client this fixture creates registers **no**
		// post.logout.redirect.uris at all, and its redirectUris entry still
		// validates. That falsifies "a client whose redirect_uri validates at
		// the authorization endpoint is still refused at the logout endpoint
		// until it is set": the attribute is a filter over redirectUris, not a
		// separate registration.
		//
		// Measured across five values - absent, "", "+", "-" and a
		// "##"-separated list. The first three fall back to redirectUris, "-"
		// refuses everything including its own redirectUris, and a list
		// replaces redirectUris rather than adding to it. This case pins the
		// first row and internal/oidc's own tests pin the other four, because
		// four more goldens would each cost a container-shared client to say
		// one thing.
		Fixture: "logout-default-uris",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "{{id_token}}",
				"post_logout_redirect_uri": "http://localhost:9999/callback",
			},
		},
		// No state was sent, so the Location is the bare target - which is the
		// other half of "state and nothing else": there is no iss to leave
		// behind either.
		AssertHeaders:       []string{"Location", "Cache-Control"},
		VolatileHeaders:     []string{"Set-Cookie"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/logout/spent-id-token-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The fixture already logged this session out once, so the case's own
		// request presents an id_token_hint whose session is gone.
		//
		// Measured: the same 302, not an error. That is the opposite of the
		// authorization code, where a second attempt answers "Code not valid" -
		// and it is why the endpoint cannot be written to resolve the session
		// before deciding. A client asked for the session to end and it has
		// ended.
		Fixture: "logout-hint-spent",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "{{id_token}}",
				"post_logout_redirect_uri": "http://localhost:9999/callback",
				"state":                    "again",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		VolatileHeaders:     []string{"Set-Cookie"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/logout/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The realm is resolved before anything else, and its rejection is the
		// only one on this endpoint that is JSON rather than a page. Measured
		// with a request that is wrong in two further ways - an unusable
		// id_token_hint and an unregistered target - and it still answers about
		// the realm.
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-no-such-realm/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "not-a-jwt",
				"post_logout_redirect_uri": "https://evil.example/cb",
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
		// page with the instruction "Invalid redirect uri", and
		// **Cache-Control: no-cache** - which the authorization endpoint's
		// otherwise identical page family does not send. The envelope is served
		// now; the body carries the same per-container resource hash as the
		// authorization endpoint's two, so the golden stays deferred.
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
		ID: "oidc/logout/invalid-id-token-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: redirect URI validation",
			Retrieved: "2026-08-29",
		},
		Status: Pending,
		Reason: "the login theme is P13, and this response is a theme page",
		// The third instruction the 400 page carries, and the branch that
		// decides the rejection order: an unusable id_token_hint is answered
		// **before** the redirect URI is looked at, so a request wrong in both
		// ways answers about the hint. Measured on five hints - rubbish, an
		// access token, a refresh token, a rewritten signature and another
		// realm's token - all answering "Invalid parameter: id_token_hint".
		//
		// Its envelope is served; only the prose is P13's, and Gloak's
		// placeholder body cannot carry three different instructions. That is
		// why the branch is guarded by internal/oidc's own tests as well.
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Query: map[string]string{
				"id_token_hint":            "not-a-jwt",
				"post_logout_redirect_uri": "https://evil.example/callback",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Logout endpoint, the POST family ---
	//
	// A POST carrying a refresh_token is a different endpoint wearing the same
	// path: it authenticates the client, answers JSON rather than pages, and
	// ignores any post_logout_redirect_uri it was given. Measured 2026-08-29,
	// the refresh_token is what decides - a POST without one answers the GET
	// families, and a POST carrying both a refresh_token and an id_token_hint
	// answers 204.
	{
		ID: "oidc/logout/post-refresh-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "logout-refresh",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Form: map[string]string{
				"client_id":     "gloak-probe-logout-refresh",
				"refresh_token": "{{refresh_token}}",
			},
		},
		// 204, an empty body, Cache-Control: no-cache, and a
		// Content-Security-Policy - the second protocol response measured
		// carrying that header, beside revocation's success. X-Frame-Options is
		// asserted because this is a 204 whose request declared
		// application/x-www-form-urlencoded, which is the side of
		// WriteNoContent's measured rule that sends it.
		AssertHeaders: []string{"Cache-Control", "Content-Security-Policy", "X-Frame-Options"},
	},
	{
		ID: "oidc/logout/post-invalid-refresh-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status:  Implemented,
		Fixture: "logout-refresh",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Form: map[string]string{
				"client_id":     "gloak-probe-logout-refresh",
				"refresh_token": "not-a-jwt",
			},
		},
		// {"error":"invalid_grant","error_description":"Invalid refresh token"},
		// and **no Cache-Control at all** where the 204 beside it sends
		// no-cache. Measured on an access token and an ID token in the
		// refresh_token's place too, which answer the same body - so the token
		// type is asserted rather than the shape.
		AssertHeaders:       []string{"Content-Type"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "oidc/logout/post-client-mismatch",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// Two **public** clients, so nothing but the token differs. The token
		// endpoint's equivalent case had to be redone for exactly this reason:
		// its first attempt used a confidential client and measured client
		// authentication rather than the token.
		//
		// The description is a spelling nothing else in this project carries.
		Fixture: "logout-mismatch",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Form: map[string]string{
				"client_id":     "gloak-probe-logout-other",
				"refresh_token": "{{refresh_token}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/logout/post-missing-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// A refresh_token with nothing naming a client is 401 invalid_client,
		// where a confidential client sending no secret is 401
		// unauthorized_client. That is the split AGENTS.md records for the token
		// endpoint, holding on a fourth endpoint - and the pair is only a pair
		// because post-confidential-no-secret sits beside this case.
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Form:   map[string]string{"refresh_token": "not-a-jwt"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/logout/post-confidential-no-secret",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Logout endpoint: RP-initiated logout",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The fixture holds this client's secret and the case deliberately does
		// not send it. Measured: 401 unauthorized_client, and the same request
		// carrying the secret answers 204 - so the refusal is about the
		// credential rather than about the token.
		//
		// The GET family does not authenticate the client at all: the same
		// confidential client redirects with an id_token_hint and no secret.
		Fixture: "logout-confidential",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/logout",
			Form: map[string]string{
				"client_id":     "gloak-probe-logout-confidential",
				"refresh_token": "{{refresh_token}}",
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
		Status: Pending,
		// The endpoint is implemented as of 2026-08-29; what this case waits
		// for is not the endpoint. Back-channel logout is Keycloak making an
		// outbound HTTP call to the client's registered
		// backchannel.logout.url, carrying a signed logout token. The harness
		// records one request and one response and can observe neither the
		// call nor its token, so there is nothing here for a golden to hold.
		Reason:  "the harness cannot observe Keycloak calling out to a client",
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
		Status: Pending,
		// Same correction as its back-channel sibling: the endpoint exists, and
		// front-channel logout is an HTML page carrying an iframe per client
		// session, which is both a theme page (P13) and a call out to the
		// client (unobservable here).
		Reason:  "the response is a theme page carrying per-client iframes, and the calls it makes are unobservable",
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
	//
	// **Five of these cases named admin-cli on the bootstrap fixture until
	// 2026-08-30, and so measured a refusal rather than the grant.** The device
	// grant is off on every client of a default 26.7.1 - all six bootstrapped
	// ones - which the parked golden for authorization-request said in as many
	// words. They now create a client carrying
	// oauth2.device.authorization.grant.enabled, which is what the endpoint
	// needs and what nothing in the catalogue had.
	//
	// The refusal is not lost: it is oidc/device/grant-disabled below, which
	// inherited the request the five used to share.
	{
		ID: "oidc/device/authorization-request",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "device-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/auth/device",
			Form: map[string]string{
				"client_id": "gloak-probe-device",
				"scope":     "openid",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
		// The device endpoint's success is the one response in this chapter
		// that carries a Cache-Control, and it carries no Pragma. The token
		// endpoint beside it carries both on every response including its
		// rejections, so neither absence is a default.
		AssertAbsentHeaders: []string{"Pragma"},
		// Three values, not the six this case masked while it was Pending.
		// verification_uri is {{issuer}}/realms/master/device, and expires_in
		// and interval are the realm's measured 600 and 5 - configuration
		// rather than randomness, and asserting them is most of the point of
		// the case.
		Volatile: []string{"device_code", "user_code", "verification_uri_complete"},
	},
	{
		// The refusal the five cases above used to measure between them, kept
		// as a case of its own so that promoting them cost no coverage.
		ID: "oidc/device/grant-disabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
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
		// No rejection on this endpoint carries a Cache-Control, where its own
		// 200 does. That is the opposite way round from the token endpoint and
		// is the reason both headers are pinned on both cases.
		AssertAbsentHeaders: []string{"Cache-Control", "Pragma"},
	},
	{
		// invalid_grant here and invalid_request at the token endpoint, for the
		// identical description. Two endpoints in one flow, one container.
		ID: "oidc/device/duplicated-parameter",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "device-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/auth/device",
			// **Request.Form cannot say "the same key twice"** - it is a
			// map[string]string, the same limitation F48 solved for the query
			// with RawQuery and did not solve for the body. Body plus an
			// explicit Content-Type is the way to express it: buildRequest uses
			// Body only when Form is empty, and only sets the form Content-Type
			// when Form is not.
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte("client_id=gloak-probe-device&zz=1&zz=2"),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// unauthorized_client, one code away from the invalid_client an unknown
		// client gets for the identical description.
		ID: "oidc/device/confidential-no-secret",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint: client authentication",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "device-confidential",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/auth/device",
			Form: map[string]string{
				"client_id": "gloak-probe-device-confidential",
				"scope":     "openid",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization endpoint: client authentication",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/auth/device",
			Form: map[string]string{
				"client_id": "gloak-probe-no-such-client",
				"scope":     "openid",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/poll-authorization-pending",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "device-pending",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device-pending",
				"device_code": "{{device_code}}",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Pragma"},
	},
	{
		// The fixture polls once; this is the second poll, inside the interval.
		ID: "oidc/device/poll-slow-down",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "device-polled",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device-polled",
				"device_code": "{{device_code}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// oauth2.device.code.lifespan is "1" on this fixture's client and the
		// fixture waits two seconds, which is how an expiry is reached without
		// moving the realm's oauth2DeviceCodeLifespan for every case recorded
		// after it.
		ID: "oidc/device/poll-expired-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "device-expired",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device-expired",
				"device_code": "{{device_code}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/device/poll-unknown-device-code",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "device-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device",
				"device_code": "gloak-probe-not-a-device-code",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// invalid_request, where an empty device_code= reaches the lookup and
		// answers invalid_grant "Device code not valid" instead.
		ID: "oidc/device/poll-missing-device-code",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "device-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":  "gloak-probe-device",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The same condition oidc/device/grant-disabled measures at the other
		// endpoint, with a different code **and** a different description.
		// Keeping both is what says the two are not one string.
		ID: "oidc/device/poll-grant-disabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: device authorization grant",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "admin-cli",
				"device_code": "gloak-probe-not-a-device-code",
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
		Status: Pending,
		// The reason is the browser half, not the grant. Reaching a denied
		// device code means the verification page at /realms/{realm}/device,
		// the OAUTH_GRANT consent page and POST /login-actions/consent, none
		// of which Gloak serves - they are keycloak.v2 Freemarker pages, the
		// same family as the four parked login-theme goldens.
		Reason:  "a denied device code needs the device verification and consent pages, which are not implemented",
		Fixture: "", // needs a device code a user denied through the browser
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device",
				"device_code": "REPLACE-WITH-A-REAL-DENIED-DEVICE-CODE",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},

	// --- Backchannel authentication endpoint (CIBA) ---
	//
	// **CIBA cannot complete on a default Keycloak 26.7.1, and the two poll
	// cases below are Pending because of that rather than because Gloak has
	// not got round to them.** Measured 2026-08-30: a client carrying
	// oidc.ciba.grant.enabled sending a well-formed authentication request
	// answers 503 server_error "Failed to send authentication request",
	// because the default ciba-http-auth-channel provider needs an external
	// HTTP endpoint that start-dev does not configure. So there is no
	// auth_req_id a default container could ever hand a fixture.
	//
	// That makes the 503 a contract rather than a gap - the same shape as
	// client-types answering 501 and .../client-secret/rotated answering a
	// permanent 404 - and it is what oidc/ciba/channel-unavailable records.
	{
		ID: "oidc/ciba/authentication-request",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
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
		// 401 where the device endpoint beside it answers 400 for the
		// equivalent refusal, which is what the parked golden was kept for and
		// is now a contract.
		AssertAbsentHeaders: []string{"Cache-Control", "Pragma"},
	},
	{
		// The 503 a fully valid request gets. Every check in front of it has to
		// pass to reach it, so this case is also what pins the order.
		ID: "oidc/ciba/channel-unavailable",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id":  "gloak-probe-ciba",
				"scope":      "openid",
				"login_hint": "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// "missing parameter : scope" - lower case, with a space on **both**
		// sides of the colon, where every other missing-parameter description
		// on the protocol side is "Missing parameter: x". The CIBA grant one
		// endpoint away uses that ordinary spelling, which is why both are
		// cases.
		ID: "oidc/ciba/missing-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id":  "gloak-probe-ciba",
				"login_hint": "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// **login_hint is checked before scope**, which a request missing one
		// of them cannot say. This case and missing-scope above send the other
		// parameter; oidc/ciba/missing-both sends neither and is what decides
		// the adjacency.
		ID: "oidc/ciba/missing-login-hint",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id": "gloak-probe-ciba",
				"scope":     "openid",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/ciba/missing-both-parameters",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form:   map[string]string{"client_id": "gloak-probe-ciba"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// A present-but-empty login_hint and one naming nobody are one answer,
		// so this is the value check rather than the presence check above it.
		// invalid_request with a lower-case underscored description, unlike
		// everything else on this endpoint.
		ID: "oidc/ciba/invalid-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id":  "gloak-probe-ciba",
				"scope":      "openid",
				"login_hint": "gloak-probe-no-such-user",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// The description echoes the raw scope parameter, the way /auth's does.
		// It is the last check before the channel, and it runs **after** the
		// login_hint's lookup, which is what oidc/ciba/invalid-user's sibling
		// probe in internal/oidc's own tests pins.
		ID: "oidc/ciba/invalid-scope",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Backchannel authentication endpoint",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/ext/ciba/auth",
			Form: map[string]string{
				"client_id":  "gloak-probe-ciba",
				"scope":      "gloak-probe-bogus-scope",
				"login_hint": "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		// 400 for the string the backchannel endpoint answers 401 for. One
		// description, two statuses - the mirror image of the device grant's
		// pair, which shares neither.
		ID: "oidc/ciba/poll-grant-disabled",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "admin-cli",
				"auth_req_id": "gloak-probe-not-an-auth-req-id",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/ciba/poll-invalid-auth-req-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "gloak-probe-ciba",
				"auth_req_id": "gloak-probe-not-an-auth-req-id",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/ciba/poll-missing-auth-req-id",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "ciba-client",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "urn:openid:params:grant-type:ciba",
				"client_id":  "gloak-probe-ciba",
			},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/ciba/poll-pending",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		// Not "not implemented". A default 26.7.1 has no configured
		// authentication channel, so it mints no auth_req_id at all - see the
		// block comment above oidc/ciba/authentication-request. Nothing in this
		// project's container regime can record this case, and saying "not
		// implemented" would read as a to-do somebody could close.
		Reason:  "a default 26.7.1 has no CIBA authentication channel, so no auth_req_id can be obtained to poll with",
		Fixture: "", // needs an auth_req_id, which needs an external authentication channel endpoint
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "gloak-probe-ciba",
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
		Reason:  "a default 26.7.1 has no CIBA authentication channel, so no auth_req_id can be obtained to approve",
		Fixture: "", // needs an auth_req_id a second user approved, which needs that channel
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:openid:params:grant-type:ciba",
				"client_id":   "gloak-probe-ciba",
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
