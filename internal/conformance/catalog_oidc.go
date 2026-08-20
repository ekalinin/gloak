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
}
