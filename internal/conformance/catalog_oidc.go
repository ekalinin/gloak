package conformance

import "net/http"

// oidcCore holds the OIDC protocol endpoints named at
// https://www.keycloak.org/securing-apps/oidc-layers.
var oidcCore = []Case{
	{
		ID: "oidc/discovery/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master/.well-known/openid-configuration"},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// scopes_supported is a Java set whose iteration order is fixed at
		// container startup but differs between starts; see
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
		Unordered: []string{"scopes_supported"},
	},
	{
		ID: "oidc/discovery/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/.well-known/openid-configuration"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "oidc/certs/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master/protocol/openid-connect/certs"},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// The realm key is generated per process, so everything derived from
		// it varies. The field set, their order, and the algorithm metadata
		// are what this case pins.
		Volatile: []string{
			"keys/*/kid",
			"keys/*/n",
			"keys/*/x5c",
			"keys/*/x5t",
			"keys/*/x5t#S256",
		},
		// The keys array's element order is not stable across container
		// starts; see the "Certificate endpoint" section of
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
		Unordered: []string{"keys"},
	},
	{
		ID: "oidc/certs/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/protocol/openid-connect/certs"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "realm/info/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/index.html",
			Section:   "Realm public information endpoint used by adapters",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master"},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		Volatile: []string{"public_key"},
	},
	{
		ID: "realm/info/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/index.html",
			Section:   "Realm public information endpoint used by adapters",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/nosuchrealm"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	// --- Authorization endpoint, the rejections that never reach a login form ---
	//
	// Every one of these registers its own client through the browser-client
	// fixture. The six bootstrapped ones cannot serve them:
	// security-admin-console pins pkce.code.challenge.method to S256 and
	// registers the host-relative "/admin/master/console/*", admin-cli has the
	// standard flow off, account and account-console redirect only inside
	// /realms/master/account/*, and broker and master-realm are confidential.
	// See browserRedirectURI in fixture.go.
	//
	// None is masked. After ReplaceIssuer an error redirect holds nothing
	// per-request, so the error code, the description and the query key order -
	// measured as error, error_description, state, iss - are all compared byte
	// for byte. That is the whole contract of the family and it is why these
	// were worth serving before the success path.
	//
	// All of them pin X-Frame-Options and Content-Security-Policy **absent**.
	// GET /auth's redirect back to the client is the one response in the browser
	// flow that omits them, and AssertHeaders can only check a header that is
	// named, so the negative needs its own field.
	{
		ID: "oidc/authorization/missing-response-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: request validation",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
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
		ID: "oidc/authorization/unsupported-response-type",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: request validation",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The sibling above sends no response_type and this one sends an
		// unusable value, and they are two different answers: a missing one is
		// invalid_request with a description, an unusable one is
		// unsupported_response_type with **no error_description key at all**.
		// One case cannot pin both.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type": "foo",
				"client_id":     "gloak-probe-browser",
				"redirect_uri":  "http://localhost:9999/callback",
				"scope":         "openid",
				"state":         "xyz123",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/authorization/invalid-response-mode",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: response_mode validation",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// response_mode has a validity check of its own, and it sits between
		// the response type and the flow check: a bogus mode with
		// response_type=foo answers about the response type, and with
		// response_type=token about the mode. Measured 2026-08-29.
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
				"response_mode": "bogus",
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
		Status:  Implemented,
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
	{
		ID: "oidc/authorization/pkce-missing-challenge",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, request validation",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The first of the three PKCE checks, and the one whose position is
		// the surprise: a code_challenge_method with no code_challenge answers
		// about the **challenge**, whatever the method is - see the sibling
		// below, which needs a challenge present to be reachable at all.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type":         "code",
				"client_id":             "gloak-probe-browser",
				"redirect_uri":          "http://localhost:9999/callback",
				"scope":                 "openid",
				"state":                 "xyz123",
				"code_challenge_method": "S256",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/authorization/pkce-invalid-challenge-method",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: PKCE, request validation",
			Retrieved: "2026-08-29",
		},
		Status: Implemented,
		// The challenge is RFC 7636 appendix B's, the same literal the fixtures
		// use, and it is here only to get past the check above.
		Fixture: "browser-client",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/auth",
			Query: map[string]string{
				"response_type":         "code",
				"client_id":             "gloak-probe-browser",
				"redirect_uri":          "http://localhost:9999/callback",
				"scope":                 "openid",
				"state":                 "xyz123",
				"code_challenge":        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				"code_challenge_method": "bogus",
			},
		},
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
	{
		ID: "oidc/authorization/prompt-none-no-session",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: prompt=none",
			Retrieved: "2026-08-20",
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
		AssertHeaders: []string{"Location", "Cache-Control"},
		// This is the only rejection in the family that sets cookies:
		// prompt=none is checked after the authentication session exists, so
		// AUTH_SESSION_ID and KC_AUTH_SESSION_HASH are already minted. Their
		// attributes are contract and are recorded in the observed spec rather
		// than here; left unmasked they churn the golden on every recording.
		// Gloak has no session and sends none, which is why Set-Cookie is not
		// in AssertHeaders.
		VolatileHeaders:     []string{"Set-Cookie"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},

	{
		ID: "http/fallback/unknown-path",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: paths outside the endpoint set",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/nosuchpath"},
		// A path matching no route never reaches the filter chain that adds
		// the five security headers on every other response; see the
		// "Fallback responses" section of
		// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// F177. **Exactly one trailing slash is stripped, ahead of the route
		// table and across the whole server.** This is the cell the follow-up
		// named, and it is the positive control the two refusals below need: a
		// server that answered every slashed path a 404 satisfies both of them
		// and fails here.
		//
		// It duplicates oidc/certs/master's body on purpose. The behaviour
		// being pinned is the routing rule, and the only way a golden can say
		// "the slashed path reached this endpoint" is to hold what that
		// endpoint answers.
		ID: "http/fallback/trailing-slash-protocol",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a path with one trailing slash",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/certs/",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		Volatile: []string{
			"keys/*/kid",
			"keys/*/n",
			"keys/*/x5c",
			"keys/*/x5t",
			"keys/*/x5t#S256",
		},
		Unordered: []string{"keys"},
	},
	{
		// F177's second question: **the rule reaches the Admin API.** That is
		// what makes it one strip ahead of the mux rather than a route per
		// protocol endpoint, and it is why this cut's change is in
		// WithKeycloakFallbacks and not in the protocol router.
		//
		// The endpoint is chosen for two properties this case rests on. Its
		// body is a pure function of nothing - a user id resolving to nothing
		// answers the same seven-key zero record a real user gets, which is
		// admin/attack-detection/brute-force-status-unknown-user's finding - so
		// the golden cannot drift with the container's state. And it carries
		// the Admin API's `;charset=UTF-8`, where the protocol side sends a
		// bare `application/json`, so the Content-Type alone says which of the
		// two surfaces served it.
		ID: "http/fallback/trailing-slash-admin",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs-api/26.7.1/rest-api/",
			Section:   "Attack Detection: a path with one trailing slash",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "admin-token",
		Request: Request{
			Method: http.MethodGet,
			Path: "/admin/realms/master/attack-detection/brute-force/users/" +
				"gloak-probe-no-such-user/",
			Headers: map[string]string{"Authorization": "Bearer {{access_token}}"},
		},
		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		// The half of F177's rule that says it is a **strip** and not a route.
		// The unmatched-path 404 answers a slashed path exactly as it answers
		// the bare one, headers included - so nothing downstream of the strip
		// has to know the slash was there, and the two measured fallback
		// bodies stay two.
		//
		// It keeps the absent-header declaration its unslashed sibling carries
		// rather than deferring to it: the interesting claim is that a request
		// which was rewritten before routing still misses the filter chain.
		ID: "http/fallback/trailing-slash-unknown-path",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: an unmatched path with a trailing slash",
			Retrieved: "2026-09-07",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/nosuchpath/"},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// The boundary of F177's rule, and the case that kills the
		// implementation the three above would all pass: **a second trailing
		// slash is not a second strip.** A path carrying a doubled slash, a
		// "." segment or a ".." segment never reaches a route at all.
		//
		// Three things here are measured and none of them is what a reader
		// guesses. It is a **400**, not a 404. Its Content-Type spells the
		// parameter `application/json; charset=UTF-8`, **with a space**, which
		// is a third spelling in this server - the Admin API writes
		// `application/json;charset=UTF-8` and the protocol side a bare
		// `application/json`. And it carries **none** of the five security
		// headers, which is the "never reached the filter chain" exception met
		// on a request that is refused rather than unrouted.
		//
		// Measured with raw sockets and `curl --path-as-is` on 2026-09-07,
		// because curl normalises a path before sending it and a probe written
		// without that flag measures curl. This closes F11.
		ID: "http/fallback/path-not-normalized",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a path that is not normalized",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/certs//",
		},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Cache-Control",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		ID: "http/fallback/method-not-allowed",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodPost, Path: "/realms/master/.well-known/openid-configuration"},
		// A known path hit with the wrong method still reaches the filter
		// chain a matched resource sits behind, so the five security headers
		// are present, unlike the unmatched-path case above.
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	// --- The realm resource dispatcher, F184 ---
	//
	// Everything under `/realms/{realm}` that no route serves reaches
	// Keycloak's filter chain through the realm resource's own locator, so it
	// carries all five security headers where the unmatched-path body carries
	// none. That is F153's shape a fourth time, after `/organizations`, the
	// group tree and `/account`, and it is answered once here rather than a
	// fourth time per family.
	//
	// Six cases because the dispatcher has four decisions in it and two of them
	// are about where it may **not** reach:
	// the sentence itself, the depth, the realm before anything else, the realm
	// before the *method*, `/realms` staying off the route table, and the
	// protocol dispatcher keeping its own sentence inside the tree.
	{
		// The shape F184 leads with. The path is a segment no Keycloak
		// resource has ever had, so the case cannot start passing because
		// somebody built the endpoint it names.
		ID: "http/fallback/realm-resource",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a realm resource no route serves",
			Retrieved: "2026-09-09",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master/nosuchthing"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// Measured with no Cache-Control at all, which is the protocol side's
		// rule for a refusal and not something the body says.
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **Depth changes nothing**, measured at one, two and six segments.
		// It is a case rather than a line in a comment because it is the
		// difference between one {rest...} pattern and a pattern per depth,
		// and a dispatcher built on a single wildcard segment passes the case
		// above and fails this one.
		ID: "http/fallback/realm-resource-deep",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a deep realm resource no route serves",
			Retrieved: "2026-09-09",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master/nosuchthing/deeper"},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The realm is resolved first, so the same path under a realm that
		// does not exist answers about the realm. A dispatcher that wrote its
		// sentence without a lookup passes both cases above and fails here -
		// and it is right on every probe that gets *one* thing wrong, which is
		// every probe a reader writes.
		ID: "http/fallback/realm-resource-unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: an unserved resource of a realm that does not exist",
			Retrieved: "2026-09-09",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/nosuchthing"},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// **The realm is resolved before the method is dispatched**, which is
		// stronger than "the realm is resolved first" and is the cell that
		// decides the dispatcher's patterns carry no method. This path *is*
		// served by this router, with GET; POST to it under a realm that does
		// not exist answers about the realm and not the wrong-method 404 its
		// sibling above answers on master.
		//
		// A catch-all registered `GET /realms/{realm}/{rest...}` passes every
		// other case in this group and fails this one, because the request
		// would fall through to WithKeycloakFallbacks, which holds no store
		// and cannot resolve a realm.
		ID: "http/fallback/method-not-allowed-unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a wrong method under a realm that does not exist",
			Retrieved: "2026-09-09",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodPost,
			Path:   "/realms/nosuchrealm/.well-known/openid-configuration",
		},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The realm root itself with a method nothing serves. On master this
		// is a real 405 - F31's standing divergence, and not this cut's - but
		// under a realm that does not exist it is the realm sentence, so the
		// cell is reproducible and worth holding.
		//
		// It is also the case that pins the **bare** `/realms/{realm}` pattern.
		// Registering only `/realms/{realm}/{rest...}` makes Go's ServeMux add
		// an implicit redirect at the subtree root, and this request then
		// answers a 307 to `/realms/nosuchrealm/` with net/http's own body -
		// with a non-empty pattern, so WithKeycloakFallbacks hands it over
		// rather than catching it. That is §3.1's 301 hazard and F153's shape,
		// met by running the route table rather than reading the documentation.
		ID: "http/fallback/realm-root-unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: a wrong method on the root of a realm that does not exist",
			Retrieved: "2026-09-09",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodPost, Path: "/realms/nosuchrealm"},
		AssertHeaders: []string{"Content-Type", "X-Frame-Options"},
	},
	{
		// The constraint on where the dispatcher may sit, and the only
		// measured place in this server where a **shorter** path is less
		// reachable than a longer one: `/realms` falls off the route table
		// entirely while everything below it carries all five headers.
		//
		// A catch-all one segment higher - `/realms/{rest...}`, or a
		// `/realms/` subtree - serves this path and passes every other case in
		// the group. The absent headers are the whole assertion, so they are
		// declared: AssertHeaders can only check a header that is named.
		ID: "http/fallback/realms-collection",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: the realms collection itself",
			Retrieved: "2026-09-09",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms"},
		AssertHeaders: []string{"Content-Type"},
		AssertAbsentHeaders: []string{
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	// --- The protocol dispatcher, F178 ---
	//
	// `/realms/{realm}/protocol/{name}` is decided by Keycloak's **protocol
	// map** rather than by its route table, which is why none of these four
	// can be produced by a fallback: an unmatched path answers
	// `Unable to find matching target resource method` with none of the five
	// security headers, and every cell here carries all five.
	//
	// Four cases because the dispatcher has three decisions in it and each of
	// them is one probe away from an implementation that looks right - the
	// realm before the protocol, a registered protocol stopping the dispatch,
	// and the bare `/protocol` segment not being a protocol name. Sent as GET
	// only: `Protocol not found` was measured byte-identical on GET, POST,
	// PUT, DELETE, OPTIONS and HEAD, and a golden per verb would report one
	// behaviour six times. internal/oidc's TestProtocolNotFoundAnswersEveryVerb
	// carries that half.
	{
		// The sentence itself, on the shape the follow-up leads with.
		ID: "oidc/protocol/unknown",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: an unregistered login protocol",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master/protocol/nosuchproto"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		AssertAbsentHeaders: []string{"Cache-Control"},
	},
	{
		// **The discriminating case.** A dispatcher that answered
		// `Protocol not found` for everything under `/protocol/` passes the
		// case above and fails here: a path under a protocol Keycloak *has*
		// registered answers the router's own generic 404 instead, so the map
		// is load-bearing.
		//
		// It is the OIDC half of saml/endpoint/unknown-subpath, kept because
		// the two protocols are the two entries in that map and a fold or a
		// typo in either would show on one of them alone.
		ID: "oidc/protocol/unknown-under-registered",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: an unserved path under a registered protocol",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/master/protocol/openid-connect/nosuchsub",
		},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// The bare segment. **`/protocol` is not a protocol**: it answers
		// `HTTP 404 Not Found` where a one-character name answers
		// `Protocol not found`, so the empty name is a third answer rather
		// than the unregistered case with nothing in it.
		ID: "oidc/protocol/bare",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: the bare protocol segment",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/master/protocol"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},
	{
		// The order. An unknown realm answers about the **realm** even when
		// the protocol is unknown too, so a dispatcher reading its map first
		// is wrong on every request that gets both wrong - and right on every
		// request that gets only one wrong, which is every probe a reader
		// writes first.
		ID: "oidc/protocol/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: an unregistered protocol in a realm that does not exist",
			Retrieved: "2026-09-07",
		},
		Status:  Implemented,
		Fixture: "bootstrap",
		Request: Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/protocol/nosuchproto"},
		AssertHeaders: []string{
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
	},

	// --- The same behaviours, measured against a realm that is not master ---
	//
	// Every case above spells master into its path, and fifty-eight of the
	// sixty goldens that carry a realm name in their *response* do too, so a
	// handler answering with the literal compares equal to one deriving it from
	// the request. That is F142, found by a mutation that hard-coded master into
	// the theme page's restart URL and passed the whole tree.
	//
	// These four address a realm their fixture created. Nothing here needed
	// building: realmFixture has made realms through POST /admin/realms since
	// P4, and ReplaceIssuer rewrites the base URL and not the realm segment, so
	// the name stays asserted in the golden. See Case.SecondRealm for what the
	// flag does and for why it is a declaration rather than something read off
	// the path.
	//
	// All four measured on 2026-09-01 against a live 26.7.1 on port 8155, with
	// the realm created through the API rather than bootstrapped - which is not
	// the same thing as master under another name, and one of the four proves
	// it.
	{
		ID: "oidc/discovery/second-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: well-known configuration endpoint",
			Retrieved: "2026-08-20",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-second/.well-known/openid-configuration",
		},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// Measured: a created realm's document is byte-identical to master's
		// with the realm name swapped, every one of the thirty-odd URLs
		// included - and differs in exactly one thing, which is the same thing
		// the master case already masks. scopes_supported is a Java set whose
		// iteration order is fixed at startup, and the two realms' orders
		// disagree on one container.
		Unordered: []string{"scopes_supported"},
	},
	{
		ID: "realm/info/second-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/docs/26.7.1/server_admin/index.html",
			Section:   "Realm public information endpoint used by adapters",
			Retrieved: "2026-08-20",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm",
		Request:     Request{Method: http.MethodGet, Path: "/realms/gloak-probe-second"},
		AssertHeaders: []string{
			"Cache-Control",
			"Content-Type",
			"Referrer-Policy",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-Frame-Options",
			"X-Robots-Tag",
		},
		// Three of the five keys follow the realm - realm, token-service and
		// account-service - and tokens-not-before does not. public_key is the
		// realm's own key rather than master's, which is what makes this case
		// worth having beside the sibling above: the body proves the realm was
		// resolved and not assumed.
		Volatile: []string{"public_key"},
	},
	{
		ID: "oidc/userinfo/second-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Userinfo endpoint",
			Retrieved: "2026-08-20",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-second/protocol/openid-connect/userinfo",
		},
		// WWW-Authenticate is the point: the challenge carries
		// realm="gloak-probe-second", and httpx.WriteBearerChallenge is the one
		// place that decides it. The master sibling asserts the same header and
		// cannot tell a derived value from the literal.
		AssertHeaders:       []string{"Content-Type", "WWW-Authenticate"},
		AssertAbsentHeaders: []string{"X-Frame-Options"},
	},
	{
		ID: "oidc/authorization/second-realm-error-page",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: client validation",
			Retrieved: "2026-08-20",
		},
		Status: Implemented,
		// The page carries **three** realm-derived values, not the one F142
		// went looking for. The restart URL's path is the third; the first two
		// are the <title> and the header brand:
		//
		//	<title>Sign in to gloak-probe-second</title>
		//	class="pf-v5-c-brand">gloak-probe-second</div>
		//
		// They are the realm's displayName and displayNameHtml, and a realm
		// created through POST /admin/realms carries neither. The
		// kc-logo-text wrapper master's brand has is displayNameHtml's own
		// markup, so it disappears with the value rather than wrapping the
		// name.
		//
		// **This case was Recorded until 2026-09-02 and its promotion is the
		// alarm working.** internal/httpx served master's two values as
		// constants, which is right on the one realm every conformance case
		// used to address; when the theme was made to follow the realm this
		// case started matching its golden and TestConformance said so. The
		// fallback the constants hid is one `if` deeper than it looks - the
		// brand falls back to displayName and only then to the realm name -
		// and that `if` is measured in internal/httpx's own tests, because a
		// realm carrying neither value cannot show it.
		SecondRealm: true,
		Fixture:     "second-realm",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/gloak-probe-second/protocol/openid-connect/auth",
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

	// --- The three sites the cut before this one measured and left open ---
	//
	// Sites 14, 15 and 19 of the derivation table in
	// docs/superpowers/handover/harness-second-realm.md §1.2. Three of them
	// were **measured survivors**: hard-coding master into registrationURI,
	// into the device grant's verification_uri and into /auth's error-redirect
	// iss left `go test ./internal/conformance ./internal/oidc
	// ./internal/httpx` green, all three at once, on 2026-09-01.
	//
	// Two of the three are closed here **and** in internal/oidc's
	// crossrealm_test.go, per site. The third, registrationURI, has no case:
	// measured 2026-09-02 with a control, a second realm's registration
	// endpoint refuses master's own administrator with the same
	// `401 invalid_token / Failed decode token` a garbage bearer gets, and the
	// two credentials that do open it are an initial access token - an Admin
	// API route Gloak does not serve - and a registration access token, which
	// needs a client that is already registered. That site is a package test
	// and its comment says so.
	//
	// oidc/certs/second-realm is deliberately **not** here. Every value in that
	// response is masked, so it would pin nothing realm-derived and would be
	// the harness equivalent of a mask that changes nothing.
	{
		ID: "oidc/device/second-realm-verification-page",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Device authorization grant: the verification page",
			Retrieved: "2026-09-02",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/" + secondRealmName + "/device",
		},
		// The form's action is `/realms/<realm>/device`, relative and not the
		// path the request arrived on - and on master those are three spellings
		// of one string, which is why the sentence above serveDeviceCodePage
		// claimed the opposite for a month without any test disagreeing.
		//
		// The page carries the chrome too, so this golden pins the title and
		// the brand a second time. That is not redundant with the error page
		// beside it: they are two body templates sharing one head.
		AssertHeaders: []string{"Content-Type", "Cache-Control", "Content-Language"},
	},
	// **oidc/device/second-realm-authorization-request is not here, and the
	// reason is a mask rather than a measurement.** §5.2 of the handover names
	// it and the fixture for it was written; the response was recorded and the
	// realm is in it, on `verification_uri`. What stops it is
	// `verification_uri_complete`, which is that URL plus `?user_code=` plus a
	// code minted per request: masking it whole is the mask
	// `prefixMasksLeftInPlace` already records as a finding on the master
	// sibling - `{{issuer}}` and more, thrown away to hide eight characters -
	// and a second instance of a known-too-wide mask is not worth a second
	// entry in a list of findings. Case has no body-side equivalent of
	// VolatileTailHeaders, which is F107's "a mechanism and not an edit".
	//
	// Site 15 is closed by internal/oidc's
	// TestDeviceAuthorizationNamesTheRequestsRealm instead, which asserts both
	// URLs whole and needs no mask at all. The case belongs here the day that
	// mechanism exists.
	{
		ID: "oidc/authorization/second-realm-error-redirect",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Authorization endpoint: request validation",
			Retrieved: "2026-09-02",
		},
		Status:      Implemented,
		SecondRealm: true,
		Fixture:     "second-realm-browser",
		Request: Request{
			Method: http.MethodGet,
			Path:   "/realms/" + secondRealmName + "/protocol/openid-connect/auth",
			Query: map[string]string{
				"client_id":    "gloak-probe-second-browser",
				"redirect_uri": browserRedirectURI,
				"scope":        "openid",
				"state":        "xyz123",
			},
		},
		// The iss is the only one of the four query keys a second realm can
		// tell apart - error, error_description and state are the same bytes
		// whatever realm asked - and ReplaceIssuer rewrites the base URL and
		// not the realm segment, so it stays asserted whole.
		AssertHeaders:       []string{"Location", "Cache-Control"},
		AssertAbsentHeaders: []string{"X-Frame-Options", "Content-Security-Policy"},
	},
}
