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
}
