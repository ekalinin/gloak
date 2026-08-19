package oidc

// discoveryDoc builds the OpenID Connect discovery document served at
// /realms/{realm}/.well-known/openid-configuration.
//
// The endpoint URLs are derived from issuerBase and realm at request time.
// The algorithm and capability arrays are fixed values transcribed from a
// live Keycloak 26.7.1 instance, captured in
// internal/oidc/testdata/discovery-26.7.1.json (56 top-level keys); see
// TestDiscoveryKeySetMatchesKeycloak, which pins every key that capture
// emits.
func discoveryDoc(issuerBase, realm string) map[string]any {
	realmBase := issuerBase + "/realms/" + realm
	protoBase := realmBase + "/protocol/openid-connect"

	tokenEndpoint := protoBase + "/token"
	revocationEndpoint := protoBase + "/revoke"
	introspectionEndpoint := protoBase + "/token/introspect"
	deviceAuthorizationEndpoint := protoBase + "/auth/device"
	registrationEndpoint := realmBase + "/clients-registrations/openid-connect"
	userinfoEndpoint := protoBase + "/userinfo"
	pushedAuthorizationRequestEndpoint := protoBase + "/ext/par/request"
	backchannelAuthenticationEndpoint := protoBase + "/ext/ciba/auth"

	signingAlgs := []string{
		"PS384", "RS384", "EdDSA", "ES384", "HS256", "HS512", "ES256",
		"RS256", "HS384", "ES512", "PS256", "PS512", "RS512",
	}
	encryptionAlgs := []string{
		"ECDH-ES+A256KW", "ECDH-ES+A192KW", "ECDH-ES+A128KW",
		"RSA-OAEP", "RSA-OAEP-256", "RSA1_5", "ECDH-ES",
	}
	encryptionEncs := []string{
		"A256GCM", "A192GCM", "A128GCM",
		"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
	}
	clientAuthMethods := []string{
		"private_key_jwt", "client_secret_basic", "client_secret_post",
		"tls_client_auth", "client_secret_jwt",
	}

	return map[string]any{
		"issuer":                                realmBase,
		"authorization_endpoint":                protoBase + "/auth",
		"token_endpoint":                        tokenEndpoint,
		"introspection_endpoint":                introspectionEndpoint,
		"userinfo_endpoint":                     userinfoEndpoint,
		"end_session_endpoint":                  protoBase + "/logout",
		"frontchannel_logout_session_supported": true,
		"frontchannel_logout_supported":         true,
		"jwks_uri":                              protoBase + "/certs",
		"check_session_iframe":                  protoBase + "/login-status-iframe.html",
		"grant_types_supported": []string{
			"authorization_code", "client_credentials", "implicit", "password",
			"refresh_token", "urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:uma-ticket",
			"urn:openid:params:grant-type:ciba",
		},
		"acr_values_supported": []string{"0", "1"},
		"response_types_supported": []string{
			"code", "none", "id_token", "token", "id_token token",
			"code id_token", "code token", "code id_token token",
		},
		"subject_types_supported":                        []string{"public", "pairwise"},
		"prompt_values_supported":                        []string{"none", "login", "consent"},
		"id_token_signing_alg_values_supported":          signingAlgs,
		"id_token_encryption_alg_values_supported":       encryptionAlgs,
		"id_token_encryption_enc_values_supported":       encryptionEncs,
		"userinfo_signing_alg_values_supported":          append(append([]string{}, signingAlgs...), "none"),
		"userinfo_encryption_alg_values_supported":       encryptionAlgs,
		"userinfo_encryption_enc_values_supported":       encryptionEncs,
		"request_object_signing_alg_values_supported":    append(append([]string{}, signingAlgs...), "none"),
		"request_object_encryption_alg_values_supported": encryptionAlgs,
		"request_object_encryption_enc_values_supported": encryptionEncs,
		"response_modes_supported": []string{
			"query", "fragment", "form_post", "query.jwt", "fragment.jwt",
			"form_post.jwt", "jwt",
		},
		"registration_endpoint":                                    registrationEndpoint,
		"token_endpoint_auth_methods_supported":                    clientAuthMethods,
		"token_endpoint_auth_signing_alg_values_supported":         signingAlgs,
		"introspection_endpoint_auth_methods_supported":            clientAuthMethods,
		"introspection_endpoint_auth_signing_alg_values_supported": signingAlgs,
		"authorization_signing_alg_values_supported":               signingAlgs,
		"authorization_encryption_alg_values_supported":            encryptionAlgs,
		"authorization_encryption_enc_values_supported":            encryptionEncs,
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "name",
			"given_name", "family_name", "preferred_username", "email",
			"acr", "azp", "nonce",
		},
		"claim_types_supported":      []string{"normal"},
		"claims_parameter_supported": true,
		"scopes_supported": []string{
			"openid", "phone", "offline_access", "profile", "basic", "email",
			"web-origins", "acr", "organization", "microprofile-jwt", "roles",
			"address", "service_account",
		},
		"request_parameter_supported":                true,
		"request_uri_parameter_supported":            true,
		"require_request_uri_registration":           true,
		"code_challenge_methods_supported":           []string{"plain", "S256"},
		"tls_client_certificate_bound_access_tokens": true,
		"dpop_signing_alg_values_supported": []string{
			"PS384", "RS384", "EdDSA", "ES384", "ES256", "RS256", "ES512",
			"PS256", "PS512", "RS512",
		},
		"revocation_endpoint":                                   revocationEndpoint,
		"revocation_endpoint_auth_methods_supported":            clientAuthMethods,
		"revocation_endpoint_auth_signing_alg_values_supported": signingAlgs,
		"backchannel_logout_supported":                          true,
		"backchannel_logout_session_supported":                  true,
		"device_authorization_endpoint":                         deviceAuthorizationEndpoint,
		"backchannel_token_delivery_modes_supported":            []string{"poll", "ping"},
		"backchannel_authentication_endpoint":                   backchannelAuthenticationEndpoint,
		"backchannel_authentication_request_signing_alg_values_supported": []string{
			"PS384", "RS384", "EdDSA", "ES384", "ES256", "RS256", "ES512",
			"PS256", "PS512", "RS512",
		},
		"require_pushed_authorization_requests": false,
		"pushed_authorization_request_endpoint": pushedAuthorizationRequestEndpoint,
		"mtls_endpoint_aliases": map[string]string{
			"token_endpoint":                        tokenEndpoint,
			"revocation_endpoint":                   revocationEndpoint,
			"introspection_endpoint":                introspectionEndpoint,
			"device_authorization_endpoint":         deviceAuthorizationEndpoint,
			"registration_endpoint":                 registrationEndpoint,
			"userinfo_endpoint":                     userinfoEndpoint,
			"pushed_authorization_request_endpoint": pushedAuthorizationRequestEndpoint,
			"backchannel_authentication_endpoint":   backchannelAuthenticationEndpoint,
		},
		"authorization_response_iss_parameter_supported": true,
	}
}
