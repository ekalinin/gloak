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
	// --- Single sign-on: a browser that is already logged in ---
	//
	// Measured 2026-08-30 against a live 26.7.1, container kc-browser on 8112.
	// The three cases below are the ones whose bodies are **empty**, which is
	// what lets them be Implemented at all: everything else this cut serves is a
	// keycloak.v2 Freemarker page and is Recorded instead.
	{
		ID: "oidc/authorization/sso-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: an already-authenticated browser",
			Retrieved: "2026-08-30",
		},
		Status: Implemented,
		// browser-code runs a whole login and leaves the jar signed in, so the
		// case's own request is the **second** authorization request. It does
		// not redeem the code the fixture minted, which is why it can share a
		// fixture with the cases that do: the rule that a redemption needs its
		// own login is about the code being spent, and nothing here spends one.
		Fixture: "browser-code",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "code",
				"client_id":     "gloak-probe-browser",
				"redirect_uri":  "http://localhost:9999/callback",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		// The two absences are the assertion. This 302 omits X-Frame-Options
		// and Content-Security-Policy where POST /login-actions/authenticate's
		// 302, to the same URI with the same status, carries both - so the pair
		// is asserted absent here and present there, and a change that made
		// either endpoint agree with the other breaks one of the two.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Referrer-Policy",
			"Strict-Transport-Security", "X-Content-Type-Options", "X-Robots-Tag",
			"Set-Cookie",
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
		// Location carries a code and the session_state; Set-Cookie carries five
		// cookies, four of them per-request. Both are masked whole and so are
		// asserted on presence - which is the same retreat every case in this
		// family makes, and the reason internal/oidc's own tests are what pin
		// the session being **reused** rather than minted.
		VolatileHeaders: []string{"Location", "Set-Cookie"},
	},
	{
		ID: "oidc/authorization/prompt-none-login-required",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: prompt=none with no session",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
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
		// Location is asserted **by value**: with nobody signed in there is no
		// code and no session_state in it, so error, state and iss and their
		// order are all pinned. Set-Cookie is not: measured, this branch sets
		// AUTH_SESSION_ID and KC_AUTH_SESSION_HASH and **no KC_RESTART**, and
		// the two it does set are per-request.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Referrer-Policy",
			"Strict-Transport-Security", "X-Content-Type-Options", "X-Robots-Tag",
			"Set-Cookie",
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
		VolatileHeaders:     []string{"Set-Cookie"},
	},
	{
		ID: "oidc/device/verification-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization grant: the verification URI",
			Retrieved: "2026-08-30",
		},
		Status: Implemented,
		// device-pending mints a code and captures its user_code, which is the
		// only identifier this side of the flow sees.
		Fixture: "device-pending",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/device",
			Query:  map[string]string{"user_code": "{{user_code}}"},
		},
		// The 302 to /login-actions/authenticate, carrying a freshly minted
		// tab_id - so Location is masked - and the same header set /auth's own
		// redirect carries, X-Frame-Options and Content-Security-Policy absent.
		AssertHeaders: []string{
			"Location", "Cache-Control", "Referrer-Policy",
			"Strict-Transport-Security", "X-Content-Type-Options", "X-Robots-Tag",
			"Set-Cookie",
		},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
		VolatileHeaders:     []string{"Location", "Set-Cookie"},
	},

	// --- The login theme's pages ---
	//
	// **All four are compared contracts as of 2026-09-03**, and it took two
	// mechanisms rather than one. ReplaceThemeResource made three of them
	// comparable in 2026-09-01 by rewriting the one installation-wide value the
	// markup carries, the /resources/<version>/ segment. prompt-create needed
	// the other one: it is rendered from inside the authentication flow, so it
	// carries a tab_id and an authentication session hash that its **own**
	// request mints, and Case.VolatileHTMLQuery and Case.VolatileHTMLCall are
	// what mask those two without giving up the markup around them. What each
	// case pins is in its own comment.
	//
	// That segment is **minted with the database**, not per container start,
	// which is what every comment in this file said until it was restarted six
	// times and measured. It changes nothing here, because `make record` starts
	// a fresh container each run.
	{
		ID: "oidc/device/verification-page",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization grant: the verification page",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/device",
		},
		// **GET here is not a wrong method**, which is what this case exists to
		// record: Gloak answered it 404 until this cut.
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
	},
	{
		ID: "oidc/device/status-page",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization grant: the status page",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/device/status",
		},
		// It carries **no Cache-Control at all**, which is the one thing on this
		// page worth pinning and the only page in the flow that does not.
		AssertHeaders:       []string{"Content-Type", "Content-Language"},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		ID: "oidc/authorization/prompt-create",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: prompt=create on a realm with registration off",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
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
				"prompt":        "create",
			},
		},
		// **This page carries a Cache-Control and max-age-invalid's does not**,
		// which is the pair that refutes AGENTS.md's "GET /auth's page family
		// sends none at all". The two are recorded side by side so that the
		// difference is a diff away rather than a memory.
		//
		// **Set-Cookie is asserted and masked**, which the other three pages in
		// this block need neither of: this is the one that opens an
		// authentication session, so it sets AUTH_SESSION_ID and
		// KC_AUTH_SESSION_HASH where max-age-invalid beside it sets none at all
		// and says so with AssertAbsentHeaders. Both values are minted per
		// request, so the golden churned on every re-record until this was
		// declared - the disease F23 and F69 are about, arriving on this case
		// the moment it stopped being parked and started being re-recorded.
		AssertHeaders:   []string{"Content-Type", "Cache-Control", "Content-Language", "Set-Cookie"},
		VolatileHeaders: []string{"Set-Cookie"},
		// The two values this page mints for itself, and the reason it was
		// parked from 2026-08-30 until 2026-09-03. Measured by issuing the
		// request twice against one container: these two move and nothing else
		// does - client_data is a base64 of the request's own parameters and
		// came back identical both times.
		//
		// Masking them is not the same as giving up the page. The tab_id goes
		// out of one query and the restart URL's realm, path, client_id,
		// client_data, skip_logout and their order all stay compared; the
		// checkAuthSession argument goes and its import, its indentation, its
		// parentheses and the block's place between the two <script>s beside it
		// all stay compared. That is 5389 bytes of markup asserted to hide 75.
		VolatileHTMLQuery: []string{"tab_id"},
		VolatileHTMLCall:  []string{"checkAuthSession"},
	},
	{
		// The first of F146's nine placeholder pages to become a contract, and
		// the second consumer of F38's mechanism.
		//
		// **Its tab_id is not masked and that is the finding**, not an
		// oversight. F146 recorded that all nine pages carry a tab_id minted by
		// the request that renders them and concluded that no golden could hold
		// any of them. The tab here is minted by the fixture's own GET /auth, so
		// the fixture captures it and ReplaceCaptured has always reached it -
		// the golden asserts *which tab* rather than giving the value up. What
		// genuinely could not be masked is the KC_AUTH_SESSION_HASH, which
		// arrives only inside a Set-Cookie and which nothing here can capture
		// out of one.
		//
		// What this case pins beyond the mask: **three URLs to two endpoints
		// that agree on nothing**. The head's restart URL ends
		// skip_logout=true, the body's loginRestartLink is the same path ending
		// skip_logout=false, and its loginContinueLink is absolute and puts
		// execution first. And the <SCRIPT> history.replaceState block, which
		// is emitted exactly when the request's session code was still
		// spendable and whose URL is rebuilt rather than echoed - this request
		// sends execution=gloak-probe-not-an-execution and the page answers
		// with the realm's real one.
		ID: "oidc/authorization/session-code-wrong-execution",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authentication: a valid session code with a wrong execution",
			Retrieved: "2026-09-03",
		},
		Status:  Implemented,
		Fixture: "browser-page-expired",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/login-actions/authenticate",
			Query: map[string]string{
				"session_code": "{{session_code}}",
				"execution":    "gloak-probe-not-an-execution",
				"client_id":    "gloak-probe-browser",
				"tab_id":       "{{tab_id}}",
				"client_data":  browserClientData,
			},
		},
		// A **200**, which is the thing about this branch most likely to be
		// implemented as a 400: the request named an execution that does not
		// exist and the answer is a page, not a rejection. It sets no cookies,
		// where the login page beside it sets three.
		AssertHeaders: []string{
			"Content-Type", "Cache-Control", "Content-Language",
			"Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
		},
		AssertAbsentHeaders: []string{"Set-Cookie"},
		VolatileHTMLCall:    []string{"checkAuthSession"},
	},
	{
		ID: "oidc/authorization/max-age-invalid",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: a non-numeric max_age",
			Retrieved: "2026-08-30",
		},
		Status:  Implemented,
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
				"max_age":       "abc",
			},
		},
		// The other half of that pair: **no Cache-Control at all**, and no
		// cookies either, where prompt=create's page sets two. Both absences are
		// asserted rather than left to a golden nobody compares.
		AssertHeaders:       []string{"Content-Type", "Content-Language"},
		AssertAbsentHeaders: []string{"Cache-Control", "Set-Cookie"},
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
		Reason: "Gloak answers this request the 400 page: form_post is in responseModes and not in " +
			"servableResponseModes, so the transport does not exist. That is F51. The harness's own " +
			"blocker is gone - this Reason said 'the harness cannot mask a per-request value inside an " +
			"HTML body' until 2026-09-03, and the tab_id in the history.replaceState URL is exactly " +
			"Case.VolatileHTMLQuery's shape now. What is still missing on the mask side is an INPUT " +
			"VALUE frame for the form's own code and session_state, which no case in the catalogue " +
			"consumes yet",
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
		Status: Implemented,
		// Measured 2026-08-29: 400, text/html;charset=utf-8, no Cache-Control
		// at all, and the keycloak.v2 error page whose /resources/<version>/
		// segment is the one value in it that belongs to the installation. Two
		// recordings from one container are byte-identical and two containers
		// are not - re-measured 2026-09-01, and the variable is the **database**
		// rather than the container start: six restarts of one container gave
		// one value and eight fresh databases gave eight. ReplaceThemeResource
		// is what makes the two sides comparable, and this case is the first
		// consumer it ever had.
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
		Status:  Implemented,
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

	// --- The /login-actions family's error page: F109's twelve call sites ---
	//
	// Twelve sites across three files reach one page, and until 2026-09-02 no
	// golden compared any of them. What made these four possible is a
	// measurement rather than a mechanism: **this page carries nothing
	// per-request.** Its restart URL is `?client_id=<id>&skip_logout=true` and
	// no more - no tab_id, no session_code, no checkAuthSession hash - where the
	// nine theme pages still serving a placeholder body carry all three between
	// them. So the same page that could not be pinned inside the flow is a
	// contract outside it.
	//
	// All four send **no cookies**, which is what reaches three of the twelve
	// branches from a fixture that only creates a client. The fourth, "a real
	// client that is not the tab's", needs a live tab and is pinned by
	// internal/oidc's TestLoginActionErrorPageNamesTheRequestsClient instead.
	{
		ID: "oidc/authorization/login-actions-invalid-client-data",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Login actions: client_data",
			Retrieved: "2026-09-02",
		},
		Status: Implemented,
		// Measured 2026-09-02: 400, the keycloak.v2 login-error page,
		// "Invalid Request", and Cache-Control: no-store, must-revalidate,
		// max-age=0 - the third of the three values this one page has across
		// four endpoints. client_data is checked before the cookies, which is
		// why a request carrying none still gets this sentence rather than the
		// restart one.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/login-actions/authenticate",
			Query: map[string]string{
				"client_id":   "gloak-probe-browser",
				"tab_id":      "zz",
				"client_data": "!!!!",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
	},
	{
		ID: "oidc/authorization/login-actions-restart-cookie-missing",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Login actions: the restart cookie",
			Retrieved: "2026-09-02",
		},
		Status: Implemented,
		// The long sentence, and the chrome that names the request's client.
		// Its pair is login-actions-unknown-client below: same sentence, same
		// endpoint, and a chrome that names nothing - which is what says the
		// chrome follows the client that resolved rather than the request that
		// asked.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/login-actions/authenticate",
			Query: map[string]string{
				"client_id":   "gloak-probe-browser",
				"tab_id":      "zz",
				"client_data": "e30",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
	},
	{
		ID: "oidc/authorization/login-actions-unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Login actions: client validation",
			Retrieved: "2026-09-02",
		},
		Status: Implemented,
		// **An unknown client_id never reaches the client check here**: the
		// authentication session is judged first, so the answer is about the
		// cookie and the page names no client at all. Measured beside the case
		// above, which differs only in the client_id being real. GET /auth
		// splits the same four client failures into three sentences; this
		// family reports none of them.
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/login-actions/authenticate",
			Query: map[string]string{
				"client_id":   "nosuchclient",
				"tab_id":      "zz",
				"client_data": "e30",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
	},
	{
		ID: "oidc/authorization/login-actions-unparseable-body",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Login actions: request body",
			Retrieved: "2026-09-02",
		},
		Status: Implemented,
		// **Not the page family at all.** A body carrying a bad percent escape
		// answers 500 with application/json and the identical 94 bytes POST
		// /auth and POST /logout answer, and the decode runs ahead of every
		// check the endpoint makes - bad client_data, absent cookies and an
		// unknown client all lose to it, and only the realm beats it. Gloak
		// answered the 400 page on three of those four rows until 2026-09-02,
		// because its ParseForm sat four levels down.
		Fixture: "bootstrap",
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/login-actions/authenticate",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    []byte("a=1&%zz=2"),
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "oidc/authorization/required-action-invalid-client-data",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Login actions: required action, client_data",
			Retrieved: "2026-09-02",
		},
		Status: Implemented,
		// The sibling endpoint answering the identical page, which is the claim
		// F109's twelve sites rest on: three files, one writer, one answer. It
		// is not a re-measurement of the case above - a different handler
		// decides it, and the two were separately capable of disagreeing, the
		// way /auth and /logout do about an empty client_id.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/login-actions/required-action",
			Query: map[string]string{
				"client_id":   "gloak-probe-browser",
				"tab_id":      "zz",
				"client_data": "!!!!",
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
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
		Status: Implemented,
		// **Two stale Reasons in a row on this one case.** It said "the token
		// endpoint is not implemented" until 2026-08-30, which had been false
		// since P1; the correction then said a completed device authorization
		// "needs the device verification and consent pages, which are not
		// implemented", and those landed in the cut that filed it. The
		// device-approved fixture is device-denied with one form field removed.
		Fixture: "device-approved",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device-approved",
				"device_code": "{{device_code}}",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		Volatile: []string{
			"access_token", "refresh_token", "id_token", "session_state",
		},
		// See password-grant-admin-cli for why scope's word order is not stable
		// across container starts.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/token/ciba-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Grant types: client initiated backchannel authentication",
			Retrieved: "2026-08-20",
		},
		Status: Pending,
		// The one of the five that is still unreachable, and it is the only one
		// whose Reason survived this cut unchanged. The token endpoint
		// dispatches the grant; what is missing is an auth_req_id, and a default
		// 26.7.1 mints none - see the CIBA block further down.
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
		Status: Implemented,
		// The Fixture comment here read "token exchange needs a previously
		// issued token and is a feature that must be explicitly enabled", and
		// the second half was about the wrong feature. `GET /admin/serverinfo`
		// on 26.7.1 reports `TOKEN_EXCHANGE` and `TOKEN_EXCHANGE_DELEGATION` as
		// disabled previews and **`TOKEN_EXCHANGE_STANDARD_V2` as `DEFAULT` and
		// enabled**. The disabled one is the legacy exchange; this grant type
		// reaches the standard one, and its gate is a client attribute.
		Fixture: "token-exchange",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
				"client_id":          "gloak-probe-exchange",
				"client_secret":      "{{client_secret}}",
				"subject_token":      "{{subject_token}}",
				"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
			},
		},
		AssertHeaders: []string{"Content-Type"},
		// Eight keys, not nine: no refresh_token and no id_token even though the
		// subject token was granted openid, `refresh_expires_in` 0 rather than
		// absent, and an `issued_token_type` after `scope` that no other grant
		// emits. session_state is the **subject's** session rather than a new
		// one, which is why it is masked here and not compared to anything.
		Volatile:       []string{"access_token", "session_state"},
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/token/jwt-authorization-grant",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: JWT bearer authorization grant",
			Retrieved: "2026-08-20",
		},
		Status: Implemented,
		// Reachable exactly as it was already written, and nobody had sent it.
		// A literal placeholder assertion on admin-cli answers the second rung
		// of a six-rung ladder, `The provided assertion is not a valid JWT`, and
		// never reaches the public-client check behind it.
		//
		// **The happy path is out of reach on any default container**, not only
		// on this one: the grant needs an identity provider whose issuer matches
		// the assertion's, and creating one is
		// POST /admin/realms/{r}/identity-provider/instances. So the six
		// refusals are the whole of this grant here, the same shape as CIBA's
		// 503, and the last of them is a contract rather than a stub.
		Fixture: "bootstrap",
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
		Status: Pending,
		// **"DPoP is not implemented" was true of Gloak and wrong about why this
		// case is Pending.** DPoP is a `DEFAULT` feature on 26.7.1 and the grant
		// works: a proof signed ES256 answers 200 with `token_type: DPoP` and a
		// `cnf.jkt` on the access *and* refresh tokens. What cannot be expressed
		// is the request, for two independent measured reasons - a proof carries
		// an `iat` and is refused outside a window of tens of seconds, and its
		// `jti` is single-use, so a literal could not be recorded and replayed
		// even seconds later. The harness is the limit, not the container.
		Reason:  "a DPoP proof carries a per-request iat and a single-use jti, so no literal proof can be recorded and replayed",
		Fixture: "", // needs a proof JWT minted per request, which no Case.Request can express
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
		ID: "oidc/token/dpop-header-invalid",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: DPoP-bound tokens",
			Retrieved: "2026-08-31",
		},
		// Recorded rather than Pending: this half of DPoP **is** expressible as
		// a literal, and measuring it costs nothing while leaving the contract
		// in the repository for whoever implements the rest.
		//
		// It is also the surprising half. The client is `admin-cli`, which
		// carries no `dpop.bound.access.tokens` attribute at all, and the header
		// is still validated - so DPoP verification is **opportunistic**, not
		// switched on per client. Gloak ignores the header and answers 200 with
		// tokens, which is the divergence this case names.
		Status:  Recorded,
		Reason:  "DPoP is not implemented; Gloak ignores the header and issues an unbound token",
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Headers: map[string]string{
				"DPoP": "not-a-proof",
			},
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "admin",
				"password":   "admin",
			},
		},
		AssertHeaders: []string{"Content-Type"},
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
		// **The token endpoint refuses an account that has not done what an
		// administrator told it to.** A temporary password is the ordinary way
		// to arrive here: the inline `credentials` entry that creates this
		// fixture's user carries `temporary: true`, which puts UPDATE_PASSWORD
		// on the representation, and this is what the direct grant then answers.
		//
		// It sits beside oidc/token/wrong-password on purpose. The two are the
		// pair that says the check runs **after** the password: the same user
		// with a wrong password answers "Invalid user credentials" and would go
		// on doing so if this check were moved in front of the credential, which
		// is where a reader would put it and where it would be an
		// account-enumeration oracle.
		ID: "oidc/token/required-action-pending",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: Resource Owner Password Credentials grant",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "temporary-password",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "gloak-probe-temp-password",
				"password":   requiredActionPassword,
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// A disabled user is its **own** description, and it is not the one
		// Gloak served until 2026-08-31: `enabled` was checked before the
		// password and answered "Invalid user credentials". Measured, the right
		// password answers "Account disabled" and the wrong one answers
		// "Invalid user credentials", so the check is after the credential here
		// too - and this case and oidc/token/wrong-password together are what
		// say so.
		ID: "oidc/token/disabled-user",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Token endpoint: Resource Owner Password Credentials grant",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "disabled-user",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type": "password",
				"client_id":  "admin-cli",
				"username":   "gloak-probe-disabled-user",
				"password":   requiredActionPassword,
			},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The browser half of the same rule: a user carrying UPDATE_PASSWORD is
		// answered a **302 to /login-actions/required-action** rather than one
		// carrying a code.
		//
		// Its header set is asserted rather than only its status, because the
		// point of the case is that this is the *login action's* redirect and
		// not the authorization endpoint's: it carries Content-Security-Policy
		// and X-Frame-Options where GET /auth's 302, to a different URI with the
		// same status, carries neither.
		//
		// **Set-Cookie is deliberately not in the list**, although its absence
		// is the most interesting thing about this response: the redirect to an
		// action sets no cookies at all, where the credential POST that ends in
		// a code sets three. The harness refuses a header that is asserted and
		// absent from the golden - "header Set-Cookie is asserted but absent
		// from the golden" - so a case cannot pin an absence, and
		// internal/oidc's TestATemporaryPasswordIsActuallyTemporary counts the
		// Set-Cookie headers instead.
		//
		// Location is masked whole because it carries a per-request tab_id, the
		// same reason oidc/authorization/code-flow-redirect masks its own.
		ID: "oidc/authorization/required-action-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: required action at login",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "browser-required-action",
		Request: Request{
			Method: http.MethodPost,
			Path:   "{{login_action}}",
			Form: map[string]string{
				"username":     "gloak-probe-reqaction-user",
				"password":     requiredActionPassword,
				"credentialId": "",
			},
		},
		AssertHeaders: []string{
			"Location", "Cache-Control", "Content-Security-Policy",
			"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security",
			"X-Content-Type-Options", "X-Robots-Tag",
		},
		VolatileHeaders: []string{"Location"},
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
		Status: Implemented,
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
		Status: Implemented,
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
		// **Measured 2026-08-31 and implemented; what cannot be held here is
		// the golden, not the behaviour.** See
		// docs/superpowers/plans/2026-08-31-p6-channel-logout.md, which records
		// how an outbound call is measured at all: a listener in a second
		// container on the same bridge, because a colima host is not
		// addressable from inside the reference container.
		//
		// The response this case would record is the ordinary logout - a 302 or
		// a page, already covered by five sibling cases and byte-identical
		// whether the client was called, answered 500 or does not exist. What
		// this case is about is a **request Keycloak makes**, and a Case holds
		// one request and one response with no side for a second socket. Three
		// things would have to exist first: an address the recorder's container
		// and the verifier's in-process handler can both reach, substituted the
		// way {{id_token}} is; a golden shape that can hold an outbound request
		// rather than a response; and something in the harness that says the
		// call is synchronous, which it is - a hanging client blocks the logout
		// for about five seconds, twice measured.
		//
		// What is asserted instead, in internal/oidc's own tests against an
		// httptest.NewServer, so `go test` needs no Docker and no network:
		//
		//	POST <backchannel.logout.url>, application/x-www-form-urlencoded,
		//	body logout_token=<jwt> and nothing else
		//	header {"alg":"RS256","typ":"logout+jwt","kid":<the realm's RSA kid>}
		//	claims exp, iat, jti, iss, aud, sub, typ:"Logout", [sid,] events
		//	events {"http://schemas.openid.net/event/backchannel-logout":{}}
		//	exp - iat = 120
		//
		// Four measurements a reader would get wrong: sid appears **only** when
		// backchannel.logout.session.required is "true" and an absent attribute
		// behaves as "false"; one POST goes to **every** client session in the
		// user session, including the client that asked; a failing client
		// changes nothing and is not retried; and `POST .../logout-all` and
		// `POST /revoke` end sessions and call **nobody**, so hanging the
		// notification off session removal fires on two paths Keycloak does
		// not.
		Reason:  "the harness holds one request and one response, and this is a request Keycloak makes",
		Fixture: "", // deliberately none: a Pending case's fixture never runs, and this one would need a listener the harness has no way to start
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
		// **The old reason was wrong in its second half, and that half was the
		// interesting one.** Front-channel logout makes no outbound call at
		// all: Keycloak answers the browser with a page and the *browser*
		// fetches the iframes. So this response is exactly the shape the
		// harness records, and what keeps it Pending is only its body - the
		// same "the login theme is P13" the five sibling page cases carry.
		//
		// Measured 2026-08-31, and it is the seventh response shape of this
		// endpoint rather than a variant of one of the six:
		//
		//	200, text/html;charset=utf-8, Cache-Control: no-cache
		//	data-page-id="login-frontchannel-logout", title "Logging out"
		//	Content-Security-Policy: frame-src 'self' <host> ; frame-ancestors 'self'; object-src 'none';
		//
		// **It takes the 302's inputs and answers 200** - a valid
		// id_token_hint, a registered post_logout_redirect_uri and a state -
		// and it replaces the "You are logged out" page too when there is no
		// target. Its title is the *confirmation* page's, so the title cannot
		// tell the two apart; the Content-Security-Policy can, and it is the
		// one theme page whose policy is computed. One host:port per client,
		// **not de-duplicated**, with a space before the semicolon.
		//
		// A client reaches it only with `frontchannelLogout: true` **and** a
		// `frontchannel.logout.url`; either alone still answers the 302. And
		// `frontchannel.logout.session.required` defaults to **true** when
		// absent, which is the opposite of its back-channel namesake - what it
		// decides is whether the iframe's src gains ?sid=&iss=, and that is in
		// the body, which is why it is P13's and not this cut's.
		//
		// The envelope is served now. internal/oidc's own tests are what assert
		// it, because Gloak's placeholder body cannot carry the iframes and this
		// golden would not compare equal until it can.
		Reason:  "the login theme is P13, and this response is a theme page",
		Fixture: "", // deliberately none while the case is Pending: a Pending case's fixture never runs, and a promoted one needs P13 first
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
		//
		// **It enumerates a realm-wide set and nobody had noticed**, which is
		// F53's question answered by example for the third time. `aud` and
		// `resource_access` name every admin container the subject holds roles
		// on, and the bootstrapped administrator holds `create-realm`, so
		// **every realm any fixture creates adds a key to this body** - the
		// realm's own `<name>-realm` client, with all 21 roles under it. The
		// golden was clean only because every realm-creating fixture in the
		// catalogue lived in adminCases and ran after it; the first one added
		// ahead of it, in 2026-09-01's second-realm cut, moved this golden and
		// nothing else.
		//
		// Ordering cannot carry that, which is exactly what PristineRealm's own
		// doc comment says. TestNoGoldenHoldsAnObjectItDidNotCreate did **not**
		// see it either: the realm arrives here as the derived client name
		// `gloak-probe-second-realm`, a key of `resource_access` and an element
		// of `aud`, and that guard looks for `"realm":"<name>"`. TestConformance
		// caught it one step later, which is the step the ratchet exists to
		// precede.
		PristineRealm: true,
		Fixture:       "confidential-user-token",
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
		// **Promoted from Pending on 2026-08-30.** Its reason was the browser
		// half - the verification page, the OAUTH_GRANT consent page and
		// POST /login-actions/consent - and all three are now served, so a
		// fixture can reach a denied device code by cancelling one. See
		// deviceDeniedFixture, which is the only fixture in the file that walks
		// two endpoints' worth of pages.
		//
		// It never carried a golden, so nothing had to leave parkedGoldens.
		Status:  Implemented,
		Fixture: "device-denied",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/protocol/openid-connect/token",
			Form: map[string]string{
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
				"client_id":   "gloak-probe-device-denied",
				"device_code": "{{device_code}}",
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
	//
	// All six of these were Pending with the Reason "dynamic client
	// registration is not implemented" and a Fixture comment saying the five
	// non-anonymous ones needed "an initial access token, which the bootstrap
	// fixture has no admin API access to mint".
	//
	// **They never needed one.** Measured 2026-08-31: an ordinary
	// administrator's access token registers a client, and the registration
	// access token it mints carries the same `registration_auth:"authenticated"`
	// an initial access token's does. So the five run on fixtures built out of
	// the admin token this catalogue has had since P1, and
	// POST /admin/realms/{r}/clients-initial-access is not on the path at all.
	//
	// Two of the six used to be the same request. `read-client` now reads with
	// the **administrator's** token and `with-registration-access-token` with
	// the client's own, which is measured to produce two different bodies: the
	// token-holder's carries `registration_access_token` and the
	// administrator's does not.
	{
		ID: "oidc/registration/create-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe-create","redirect_uris":["http://localhost:9999/callback"]}`),
		},
		// Location is asserted rather than merely present: it is the one
		// response on the protocol side that carries one, and everything before
		// the minted UUID is contract. This is the **eighth** create measured
		// for the "a create's Location ends in the new object's id" rule and the
		// fifth that ends in a UUID.
		AssertHeaders:       []string{"Content-Type", "Location"},
		VolatileTailHeaders: []string{"Location"},
		// Five values, and no more. client_secret_expires_at is a constant 0 and
		// was on this list; masking it would have asserted its type and nothing
		// else, which is the inert mask F46 is about.
		Volatile: []string{
			"client_id", "client_secret", "registration_access_token",
			"registration_client_uri", "client_id_issued_at",
		},
		// The client's optional scope list is not stable across container
		// starts, measured twice on this very case: one recording answered
		// `address phone offline_access organization microprofile-jwt` and a
		// hand probe minutes earlier answered the same five words with
		// `organization` and `offline_access` the other way round. Same rule as
		// oidc/token/password-grant-admin-cli.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/registration/read-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "registration-created",
		// The **administrator's** read, which is the shape without
		// registration_access_token. Its sibling below is the same route read
		// with the client's own token, which carries it.
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/clients-registrations/openid-connect/{{registered_client_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		// The client's optional scope list is not stable across container
		// starts, measured twice on this very case: one recording answered
		// `address phone offline_access organization microprofile-jwt` and a
		// hand probe minutes earlier answered the same five words with
		// `organization` and `offline_access` the other way round. Same rule as
		// oidc/token/password-grant-admin-cli.
		UnorderedWords: []string{"scope"},
		// Nothing is masked. The client id, the secret and the registration
		// token are all captured by the fixture, so ReplaceCaptured rewrites
		// them - inside registration_client_uri too, which therefore stays
		// asserted apart from the id. client_id_issued_at is absent on a read,
		// which is itself part of what this golden pins.
	},
	{
		ID: "oidc/registration/with-registration-access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: authenticating subsequent requests",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "registration-created",
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/clients-registrations/openid-connect/{{registered_client_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{registration_access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		// The client's optional scope list is not stable across container
		// starts, measured twice on this very case: one recording answered
		// `address phone offline_access organization microprofile-jwt` and a
		// hand probe minutes earlier answered the same five words with
		// `organization` and `offline_access` the other way round. Same rule as
		// oidc/token/password-grant-admin-cli.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/registration/update-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "registration-updated",
		Request: Request{
			Method: http.MethodPut,
			Path:   "/realms/master/clients-registrations/openid-connect/{{registered_client_id}}",
			Headers: map[string]string{
				"Authorization": "Bearer {{registration_access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_id":"{{registered_client_id}}","client_name":"gloak-probe-registered-renamed",` +
				`"redirect_uris":["http://localhost:9999/callback"]}`),
		},
		AssertHeaders: []string{"Content-Type"},
		// One mask, and it is the one the update earns: **the PUT rotates the
		// registration access token**, so the value in this body is a new one
		// the fixture never saw and the one it presented is dead. A GET does
		// not rotate it, which is why the two reads above mask nothing.
		Volatile: []string{"registration_access_token"},
		// The client's optional scope list is not stable across container
		// starts, measured twice on this very case: one recording answered
		// `address phone offline_access organization microprofile-jwt` and a
		// hand probe minutes earlier answered the same five words with
		// `organization` and `offline_access` the other way round. Same rule as
		// oidc/token/password-grant-admin-cli.
		UnorderedWords: []string{"scope"},
	},
	{
		ID: "oidc/registration/delete-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "registration-deleted",
		Request: Request{
			Method:  http.MethodDelete,
			Path:    "/realms/master/clients-registrations/openid-connect/{{registered_client_id}}",
			Headers: map[string]string{"Authorization": "Bearer {{registration_access_token}}"},
		},
		// The 204 sends four of the five security headers. That is the
		// Content-Type rule rather than a rule about deletes: this request
		// declares none, so X-Frame-Options is omitted. Pinned as a negative,
		// because AssertHeaders can never catch a header that should be absent.
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Type", "Cache-Control"},
	},
	{
		ID: "oidc/registration/without-initial-access-token",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: anonymous registration",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe","redirect_uris":["http://localhost:9999/callback"]}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/forbidden-caller",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: anonymous registration",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		// The **second** 403 this endpoint has, and the pair is the point: a
		// caller presenting no bearer token at all gets the Trusted Hosts
		// sentence above, and one presenting a valid access token without the
		// role gets `Forbidden`. admin-cli's own token is the cheapest way to
		// reach it - it authenticates and it is not the administrator's, so it
		// holds no create-client.
		//
		// It is the refresh token that is sent, not the access token, because
		// the administrator's access token *does* open this endpoint. The
		// refresh token authenticates as the wrong kind and answers a third
		// body again.
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Authorization": "Bearer {{refresh_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe-forbidden"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/failed-decode",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: authenticating subsequent requests",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// A bearer that does not verify. The description is measured to be
		// wider than it reads - a **well-formed JWT with a wrong signature**
		// answers it too - so "decode" here means "verify".
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Authorization": "Bearer not-a-token",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_name":"gloak-probe-decode"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/client-identifier-included",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		// A create naming its own client_id is refused, which is why every
		// registered client is addressed by a UUID and why the three cases
		// above capture one rather than spelling it.
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{
				"Authorization": "Bearer {{access_token}}",
				"Content-Type":  "application/json",
			},
			Body: []byte(`{"client_id":"gloak-probe-named","client_name":"gloak-probe-named"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/unsupported-media-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// **No Authorization header**, and the answer is about the
		// Content-Type. That is what says the body is examined before the
		// caller is, which is the opposite order to every other guarded route
		// in this project.
		//
		// The header has to be sent and has to be wrong. An **absent**
		// Content-Type is accepted here, measured - the request then falls
		// through to the anonymous 403 - so a case that simply omitted it would
		// be a second copy of without-initial-access-token rather than a
		// measurement of the 415. text/plain is one of the three values
		// measured to be refused.
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{"Content-Type": "text/plain"},
			Body:    []byte(`{"client_name":"gloak-probe-media"}`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/malformed-json",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// The other half of the same order: no credentials, unparseable body,
		// and the answer is about the JSON. On the protocol side the shape is
		// the RFC 6749 one, where the Admin API's four spellings of this are
		// split between `unknown_error`, `invalid_request`,
		// `HTTP 400 Bad Request` and `unable to read contents from stream`.
		Request: Request{
			Method:  http.MethodPost,
			Path:    "/realms/master/clients-registrations/openid-connect",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte(`{`),
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/unknown-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: authenticating subsequent requests",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		// `Client not found` is the Admin API's spelling (2) of twenty-one, and
		// here it arrives in the RFC 6749 shape with an `invalid_request` code
		// rather than as an `errorMessage`. Same sentence, different envelope,
		// different surface.
		//
		// It is a 404 **only because the caller holds a role**: the same request
		// with no bearer is a 401, and with a bearer holding nothing a 403.
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/clients-registrations/openid-connect/gloak-probe-absent",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/unauthenticated-read",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration: authenticating subsequent requests",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		// The item path's answer to no credentials, and it is **not** the
		// collection's. A create with no bearer is told about the Trusted Hosts
		// policy; a read is told it is not authorised, and a PUT or a DELETE is
		// told the same thing in a different sentence. Three bodies for one
		// condition, split by route and then by verb.
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/clients-registrations/openid-connect/admin-cli",
		},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/registration/bootstrapped-client",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Dynamic client registration",
			Retrieved: "2026-08-31",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		// **The read is not limited to registered clients.** admin-cli comes
		// back in the OIDC shape, and it is the client that says
		// token_endpoint_auth_method follows clientAuthenticatorType rather than
		// publicClient: admin-cli is public, reads back `client_secret_basic`,
		// carries `client_secret_expires_at` and carries no `client_secret`.
		// Its client_name is the theme message key, echoed raw.
		Request: Request{
			Method:  http.MethodGet,
			Path:    "/realms/master/clients-registrations/openid-connect/admin-cli",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type"},
		// The client's optional scope list is one of the two whose order was
		// measured to move between container starts. See
		// oidc/token/password-grant-admin-cli.
		UnorderedWords: []string{"scope"},
	},
}
