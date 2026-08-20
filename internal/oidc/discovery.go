package oidc

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"math/big"

	"github.com/ekalinin/gloak/internal/keys"
)

// jwksDocument is the JWKS as Keycloak orders it. Field order is taken from
// internal/conformance/testdata/golden/oidc/certs/master.http; go-jose's own
// marshalling uses a different order, which is why the set is not handed to
// httpx.WriteJSON directly.
type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kid     string   `json:"kid"`
	Kty     string   `json:"kty"`
	Alg     string   `json:"alg"`
	Use     string   `json:"use"`
	X5c     []string `json:"x5c"`
	X5t     string   `json:"x5t"`
	X5tS256 string   `json:"x5t#S256"`
	N       string   `json:"n"`
	E       string   `json:"e"`
}

// jwksFor builds the published key set from a realm's signing material.
func jwksFor(k *keys.RealmKeys) jwksDocument {
	set := k.JWKS()
	pub := set.Keys[0].Key.(*rsa.PublicKey)
	der := k.CertificateDER()
	sha1Sum := sha1.Sum(der)
	sha256Sum := sha256.Sum256(der)
	enc := base64.RawURLEncoding
	return jwksDocument{Keys: []jwksKey{{
		Kid:     set.Keys[0].KeyID,
		Kty:     "RSA",
		Alg:     set.Keys[0].Algorithm,
		Use:     set.Keys[0].Use,
		X5c:     []string{base64.StdEncoding.EncodeToString(der)},
		X5t:     enc.EncodeToString(sha1Sum[:]),
		X5tS256: enc.EncodeToString(sha256Sum[:]),
		N:       enc.EncodeToString(pub.N.Bytes()),
		E:       enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// mtlsEndpointAliases mirrors Keycloak's nested mtls_endpoint_aliases
// object. Field order matches the order captured in
// internal/oidc/testdata/discovery-26.7.1.json.
type mtlsEndpointAliases struct {
	TokenEndpoint                      string `json:"token_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
	RegistrationEndpoint               string `json:"registration_endpoint"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
}

// discoveryDocument is the OpenID Connect discovery document served at
// /realms/{realm}/.well-known/openid-configuration.
//
// Field order is declared exactly as Keycloak 26.7.1 emits it, transcribed
// key-by-key from internal/oidc/testdata/discovery-26.7.1.json (56
// top-level keys). Go marshals struct fields in declaration order, unlike
// map keys, which are sorted alphabetically; that ordering is part of the
// byte-exact contract, so it must never be reshuffled for readability.
// TestDiscoveryKeyOrderMatchesKeycloak pins this against the captured file.
type discoveryDocument struct {
	Issuer                                                    string              `json:"issuer"`
	AuthorizationEndpoint                                     string              `json:"authorization_endpoint"`
	TokenEndpoint                                             string              `json:"token_endpoint"`
	IntrospectionEndpoint                                     string              `json:"introspection_endpoint"`
	UserinfoEndpoint                                          string              `json:"userinfo_endpoint"`
	EndSessionEndpoint                                        string              `json:"end_session_endpoint"`
	FrontchannelLogoutSessionSupported                        bool                `json:"frontchannel_logout_session_supported"`
	FrontchannelLogoutSupported                               bool                `json:"frontchannel_logout_supported"`
	JwksURI                                                   string              `json:"jwks_uri"`
	CheckSessionIframe                                        string              `json:"check_session_iframe"`
	GrantTypesSupported                                       []string            `json:"grant_types_supported"`
	AcrValuesSupported                                        []string            `json:"acr_values_supported"`
	ResponseTypesSupported                                    []string            `json:"response_types_supported"`
	SubjectTypesSupported                                     []string            `json:"subject_types_supported"`
	PromptValuesSupported                                     []string            `json:"prompt_values_supported"`
	IDTokenSigningAlgValuesSupported                          []string            `json:"id_token_signing_alg_values_supported"`
	IDTokenEncryptionAlgValuesSupported                       []string            `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported                       []string            `json:"id_token_encryption_enc_values_supported"`
	UserinfoSigningAlgValuesSupported                         []string            `json:"userinfo_signing_alg_values_supported"`
	UserinfoEncryptionAlgValuesSupported                      []string            `json:"userinfo_encryption_alg_values_supported"`
	UserinfoEncryptionEncValuesSupported                      []string            `json:"userinfo_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported                    []string            `json:"request_object_signing_alg_values_supported"`
	RequestObjectEncryptionAlgValuesSupported                 []string            `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported                 []string            `json:"request_object_encryption_enc_values_supported"`
	ResponseModesSupported                                    []string            `json:"response_modes_supported"`
	RegistrationEndpoint                                      string              `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported                         []string            `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported                []string            `json:"token_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpointAuthMethodsSupported                 []string            `json:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported        []string            `json:"introspection_endpoint_auth_signing_alg_values_supported"`
	AuthorizationSigningAlgValuesSupported                    []string            `json:"authorization_signing_alg_values_supported"`
	AuthorizationEncryptionAlgValuesSupported                 []string            `json:"authorization_encryption_alg_values_supported"`
	AuthorizationEncryptionEncValuesSupported                 []string            `json:"authorization_encryption_enc_values_supported"`
	ClaimsSupported                                           []string            `json:"claims_supported"`
	ClaimTypesSupported                                       []string            `json:"claim_types_supported"`
	ClaimsParameterSupported                                  bool                `json:"claims_parameter_supported"`
	ScopesSupported                                           []string            `json:"scopes_supported"`
	RequestParameterSupported                                 bool                `json:"request_parameter_supported"`
	RequestURIParameterSupported                              bool                `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration                             bool                `json:"require_request_uri_registration"`
	CodeChallengeMethodsSupported                             []string            `json:"code_challenge_methods_supported"`
	TLSClientCertificateBoundAccessTokens                     bool                `json:"tls_client_certificate_bound_access_tokens"`
	DpopSigningAlgValuesSupported                             []string            `json:"dpop_signing_alg_values_supported"`
	RevocationEndpoint                                        string              `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported                    []string            `json:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported           []string            `json:"revocation_endpoint_auth_signing_alg_values_supported"`
	BackchannelLogoutSupported                                bool                `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported                         bool                `json:"backchannel_logout_session_supported"`
	DeviceAuthorizationEndpoint                               string              `json:"device_authorization_endpoint"`
	BackchannelTokenDeliveryModesSupported                    []string            `json:"backchannel_token_delivery_modes_supported"`
	BackchannelAuthenticationEndpoint                         string              `json:"backchannel_authentication_endpoint"`
	BackchannelAuthenticationRequestSigningAlgValuesSupported []string            `json:"backchannel_authentication_request_signing_alg_values_supported"`
	RequirePushedAuthorizationRequests                        bool                `json:"require_pushed_authorization_requests"`
	PushedAuthorizationRequestEndpoint                        string              `json:"pushed_authorization_request_endpoint"`
	MtlsEndpointAliases                                       mtlsEndpointAliases `json:"mtls_endpoint_aliases"`
	AuthorizationResponseIssParameterSupported                bool                `json:"authorization_response_iss_parameter_supported"`
}

// discoveryDoc builds the OpenID Connect discovery document served at
// /realms/{realm}/.well-known/openid-configuration.
//
// The endpoint URLs are derived from issuerBase and realm at request time.
// The algorithm and capability arrays are fixed values transcribed from a
// live Keycloak 26.7.1 instance, captured in
// internal/oidc/testdata/discovery-26.7.1.json (56 top-level keys); see
// TestDiscoveryKeySetMatchesKeycloak and TestDiscoveryKeyOrderMatchesKeycloak.
func discoveryDoc(issuerBase, realm string) discoveryDocument {
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

	return discoveryDocument{
		Issuer:                             realmBase,
		AuthorizationEndpoint:              protoBase + "/auth",
		TokenEndpoint:                      tokenEndpoint,
		IntrospectionEndpoint:              introspectionEndpoint,
		UserinfoEndpoint:                   userinfoEndpoint,
		EndSessionEndpoint:                 protoBase + "/logout",
		FrontchannelLogoutSessionSupported: true,
		FrontchannelLogoutSupported:        true,
		JwksURI:                            protoBase + "/certs",
		CheckSessionIframe:                 protoBase + "/login-status-iframe.html",
		GrantTypesSupported: []string{
			"authorization_code", "client_credentials", "implicit", "password",
			"refresh_token", "urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:uma-ticket",
			"urn:openid:params:grant-type:ciba",
		},
		AcrValuesSupported: []string{"0", "1"},
		ResponseTypesSupported: []string{
			"code", "none", "id_token", "token", "id_token token",
			"code id_token", "code token", "code id_token token",
		},
		SubjectTypesSupported:                     []string{"public", "pairwise"},
		PromptValuesSupported:                     []string{"none", "login", "consent"},
		IDTokenSigningAlgValuesSupported:          signingAlgs,
		IDTokenEncryptionAlgValuesSupported:       encryptionAlgs,
		IDTokenEncryptionEncValuesSupported:       encryptionEncs,
		UserinfoSigningAlgValuesSupported:         append(append([]string{}, signingAlgs...), "none"),
		UserinfoEncryptionAlgValuesSupported:      encryptionAlgs,
		UserinfoEncryptionEncValuesSupported:      encryptionEncs,
		RequestObjectSigningAlgValuesSupported:    append(append([]string{}, signingAlgs...), "none"),
		RequestObjectEncryptionAlgValuesSupported: encryptionAlgs,
		RequestObjectEncryptionEncValuesSupported: encryptionEncs,
		ResponseModesSupported: []string{
			"query", "fragment", "form_post", "query.jwt", "fragment.jwt",
			"form_post.jwt", "jwt",
		},
		RegistrationEndpoint:                               registrationEndpoint,
		TokenEndpointAuthMethodsSupported:                  clientAuthMethods,
		TokenEndpointAuthSigningAlgValuesSupported:         signingAlgs,
		IntrospectionEndpointAuthMethodsSupported:          clientAuthMethods,
		IntrospectionEndpointAuthSigningAlgValuesSupported: signingAlgs,
		AuthorizationSigningAlgValuesSupported:             signingAlgs,
		AuthorizationEncryptionAlgValuesSupported:          encryptionAlgs,
		AuthorizationEncryptionEncValuesSupported:          encryptionEncs,
		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "name",
			"given_name", "family_name", "preferred_username", "email",
			"acr", "azp", "nonce",
		},
		ClaimTypesSupported:      []string{"normal"},
		ClaimsParameterSupported: true,
		ScopesSupported: []string{
			"openid", "phone", "offline_access", "profile", "basic", "email",
			"web-origins", "acr", "organization", "microprofile-jwt", "roles",
			"address", "service_account",
		},
		RequestParameterSupported:             true,
		RequestURIParameterSupported:          true,
		RequireRequestURIRegistration:         true,
		CodeChallengeMethodsSupported:         []string{"plain", "S256"},
		TLSClientCertificateBoundAccessTokens: true,
		DpopSigningAlgValuesSupported: []string{
			"PS384", "RS384", "EdDSA", "ES384", "ES256", "RS256", "ES512",
			"PS256", "PS512", "RS512",
		},
		RevocationEndpoint:                              revocationEndpoint,
		RevocationEndpointAuthMethodsSupported:          clientAuthMethods,
		RevocationEndpointAuthSigningAlgValuesSupported: signingAlgs,
		BackchannelLogoutSupported:                      true,
		BackchannelLogoutSessionSupported:               true,
		DeviceAuthorizationEndpoint:                     deviceAuthorizationEndpoint,
		BackchannelTokenDeliveryModesSupported:          []string{"poll", "ping"},
		BackchannelAuthenticationEndpoint:               backchannelAuthenticationEndpoint,
		BackchannelAuthenticationRequestSigningAlgValuesSupported: []string{
			"PS384", "RS384", "EdDSA", "ES384", "ES256", "RS256", "ES512",
			"PS256", "PS512", "RS512",
		},
		RequirePushedAuthorizationRequests: false,
		PushedAuthorizationRequestEndpoint: pushedAuthorizationRequestEndpoint,
		MtlsEndpointAliases: mtlsEndpointAliases{
			TokenEndpoint:                      tokenEndpoint,
			RevocationEndpoint:                 revocationEndpoint,
			IntrospectionEndpoint:              introspectionEndpoint,
			DeviceAuthorizationEndpoint:        deviceAuthorizationEndpoint,
			RegistrationEndpoint:               registrationEndpoint,
			UserinfoEndpoint:                   userinfoEndpoint,
			PushedAuthorizationRequestEndpoint: pushedAuthorizationRequestEndpoint,
			BackchannelAuthenticationEndpoint:  backchannelAuthenticationEndpoint,
		},
		AuthorizationResponseIssParameterSupported: true,
	}
}
