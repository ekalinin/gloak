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
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master/.well-known/openid-configuration"},
		AssertHeaders: []string{"Content-Type"},
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
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/.well-known/openid-configuration"},
		AssertHeaders: []string{"Content-Type"},
	},
	{
		ID: "oidc/certs/master",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/master/protocol/openid-connect/certs"},
		AssertHeaders: []string{"Content-Type"},
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
	},
	{
		ID: "oidc/certs/unknown-realm",
		Doc: Doc{
			URL:       "https://www.keycloak.org/securing-apps/oidc-layers",
			Section:   "Keycloak server OIDC endpoints: certificate endpoint",
			Retrieved: "2026-08-20",
		},
		Status:        Implemented,
		Fixture:       "bootstrap",
		Request:       Request{Method: http.MethodGet, Path: "/realms/nosuchrealm/protocol/openid-connect/certs"},
		AssertHeaders: []string{"Content-Type"},
	},
}
