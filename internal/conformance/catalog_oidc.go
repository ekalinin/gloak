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
}
