package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
)

// POST /admin/realms/{realm}/client-description-converter, measured against a
// live 26.7.1 on 2026-09-03.
//
// **The Content-Type is not read at all.** The same OIDC body converts under
// `application/json`, `text/plain`, `application/xml` and with no Content-Type
// header; the SAML body does too. What decides is the body's own shape, which
// is why nothing here looks at the header. The route's guard is
// **manage-clients**, not the realm pair the description's `Realms Admin` tag
// would suggest - see the registration in router.go.

// convertClientDescription serves the route.
//
// The order is: the caller (in the guard), then the shape test, then the
// decode. Measured: a caller holding nothing gets 403 for a body that would
// have been a 400.
func (h *handler) convertClientDescription(w http.ResponseWriter, r *http.Request, _ *reqContext) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if !looksLikeOIDCClientDescription(body) {
		httpx.WriteMessageError(w, http.StatusBadRequest, "Unsupported format")
		return
	}

	var in oidcClientDescription
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		// **A body that passes the shape test and then will not decode is a
		// 500, not a 400**, and so is an unrecognised field. That is the
		// fifteenth strict decoder on this API and the first that answers 500;
		// the other fourteen all answer 400. `{"x":"redirect_uris"}` is what
		// makes it visible, because the shape test is a string test.
		httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
			"Cannot parse the JSON")
		return
	}

	out, ok := convertOIDCClientDescription(&in)
	if !ok {
		// An unregistered token_endpoint_auth_method, measured: a 500 with the
		// same body as the decode failure.
		writeConverterServerError(w)
		return
	}
	// **No Cache-Control**, measured: this 200 carries the charset every admin
	// 2xx with a body carries and nothing else, where writeAdminJSON adds
	// `no-cache`.
	httpx.WriteJSONCharset(w, http.StatusOK, out)
}

// looksLikeOIDCClientDescription is Keycloak's own predicate, and it is a
// **string** test rather than a parse.
//
// The trimmed body must start with `{`, end with `}` and contain
// `redirect_uris` anywhere at all: `{"x":"redirect_uris"}` passes it and then
// fails to decode, which is a 500 rather than the 400 an unrecognised shape
// gets. `{"client_id":"x"}`, `redirect_uris` without braces, `["redirect_uris"]`
// and an empty body are all `400 {"error":"Unsupported format"}`.
//
// The SAML branch is deliberately absent: Keycloak converts a SAML
// EntityDescriptor here too, and Gloak does not - see the Recorded conformance
// case and the follow-up.
func looksLikeOIDCClientDescription(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) >= 2 &&
		trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' &&
		bytes.Contains(trimmed, []byte("redirect_uris"))
}

// oidcClientDescription is Keycloak's OIDCClientRepresentation.
//
// **Every field name it accepts is declared, including the ones this cut does
// not map**, because the decode is strict: a name that is not here is a 500,
// and Keycloak accepts all forty-eight. All forty-eight were sent in one body
// and answered 200, so the list is measured rather than copied out of a
// specification.
//
// The unmapped block below is a declared gap, not an oversight: the golden of
// `admin/realms-admin/client-description-converter-every-field` records what
// Keycloak answers for all of them and is `Recorded` for exactly that reason.
type oidcClientDescription struct {
	ClientID                          *string   `json:"client_id"`
	ClientName                        *string   `json:"client_name"`
	ClientURI                         *string   `json:"client_uri"`
	LogoURI                           *string   `json:"logo_uri"`
	RedirectURIs                      *[]string `json:"redirect_uris"`
	ResponseTypes                     *[]string `json:"response_types"`
	GrantTypes                        *[]string `json:"grant_types"`
	TokenEndpointAuthMethod           *string   `json:"token_endpoint_auth_method"`
	JWKSURI                           *string   `json:"jwks_uri"`
	Scope                             *string   `json:"scope"`
	FrontchannelLogoutURI             *string   `json:"frontchannel_logout_uri"`
	FrontchannelLogoutSessionRequired *bool     `json:"frontchannel_logout_session_required"`
	BackchannelLogoutURI              *string   `json:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired  *bool     `json:"backchannel_logout_session_required"`
	PostLogoutRedirectURIs            *[]string `json:"post_logout_redirect_uris"`
	DefaultACRValues                  *[]string `json:"default_acr_values"`

	// Declared so the strict decode accepts them, and not mapped. Their
	// measured effect is in the Recorded golden named above.
	ApplicationType                            json.RawMessage `json:"application_type"`
	Contacts                                   json.RawMessage `json:"contacts"`
	PolicyURI                                  json.RawMessage `json:"policy_uri"`
	TOSURI                                     json.RawMessage `json:"tos_uri"`
	JWKS                                       json.RawMessage `json:"jwks"`
	SectorIdentifierURI                        json.RawMessage `json:"sector_identifier_uri"`
	SubjectType                                json.RawMessage `json:"subject_type"`
	IDTokenSignedResponseAlg                   json.RawMessage `json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg                json.RawMessage `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc                json.RawMessage `json:"id_token_encrypted_response_enc"`
	UserinfoSignedResponseAlg                  json.RawMessage `json:"userinfo_signed_response_alg"`
	UserinfoEncryptedResponseAlg               json.RawMessage `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc               json.RawMessage `json:"userinfo_encrypted_response_enc"`
	RequestObjectSigningAlg                    json.RawMessage `json:"request_object_signing_alg"`
	RequestObjectEncryptionAlg                 json.RawMessage `json:"request_object_encryption_alg"`
	RequestObjectEncryptionEnc                 json.RawMessage `json:"request_object_encryption_enc"`
	TokenEndpointAuthSigningAlg                json.RawMessage `json:"token_endpoint_auth_signing_alg"`
	DefaultMaxAge                              json.RawMessage `json:"default_max_age"`
	RequireAuthTime                            json.RawMessage `json:"require_auth_time"`
	InitiateLoginURI                           json.RawMessage `json:"initiate_login_uri"`
	RequestURIs                                json.RawMessage `json:"request_uris"`
	SoftwareID                                 json.RawMessage `json:"software_id"`
	SoftwareVersion                            json.RawMessage `json:"software_version"`
	SoftwareStatement                          json.RawMessage `json:"software_statement"`
	TLSClientCertificateBoundAccessTokens      json.RawMessage `json:"tls_client_certificate_bound_access_tokens"`
	TLSClientAuthSubjectDN                     json.RawMessage `json:"tls_client_auth_subject_dn"`
	AuthorizationSignedResponseAlg             json.RawMessage `json:"authorization_signed_response_alg"`
	AuthorizationEncryptedResponseAlg          json.RawMessage `json:"authorization_encrypted_response_alg"`
	AuthorizationEncryptedResponseEnc          json.RawMessage `json:"authorization_encrypted_response_enc"`
	BackchannelTokenDeliveryMode               json.RawMessage `json:"backchannel_token_delivery_mode"`
	BackchannelClientNotificationEndpoint      json.RawMessage `json:"backchannel_client_notification_endpoint"`
	BackchannelAuthenticationRequestSigningAlg json.RawMessage `json:"backchannel_authentication_request_signing_alg"`
	RequirePushedAuthorizationRequests         json.RawMessage `json:"require_pushed_authorization_requests"`
	DPoPBoundAccessTokens                      json.RawMessage `json:"dpop_bound_access_tokens"`
	ClientSecret                               json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt                      json.RawMessage `json:"client_secret_expires_at"`
	ClientIDIssuedAt                           json.RawMessage `json:"client_id_issued_at"`
	RegistrationAccessToken                    json.RawMessage `json:"registration_access_token"`
	RegistrationClientURI                      json.RawMessage `json:"registration_client_uri"`
}

// convertedClient is what the route answers, with the keys in the measured
// order.
//
// Three of them are pointers because their **presence** is what a body decides:
// `redirect_uris:null` drops redirectUris where `[]` sends `[]`, `client_name:""`
// sends `"name":""`, and the two service-account flags appear only when the body
// names `grant_types` at all - even as an empty array.
type convertedClient struct {
	ClientID                     *string             `json:"clientId,omitempty"`
	Name                         *string             `json:"name,omitempty"`
	BaseURL                      *string             `json:"baseUrl,omitempty"`
	ClientAuthenticatorType      string              `json:"clientAuthenticatorType"`
	RedirectURIs                 *[]string           `json:"redirectUris,omitempty"`
	StandardFlowEnabled          bool                `json:"standardFlowEnabled"`
	ImplicitFlowEnabled          bool                `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled    bool                `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled       *bool               `json:"serviceAccountsEnabled,omitempty"`
	AuthorizationServicesEnabled *bool               `json:"authorizationServicesEnabled,omitempty"`
	PublicClient                 bool                `json:"publicClient"`
	FrontchannelLogout           bool                `json:"frontchannelLogout"`
	Protocol                     string              `json:"protocol"`
	Attributes                   convertedAttributes `json:"attributes"`
	OptionalClientScopes         *[]string           `json:"optionalClientScopes,omitempty"`
}

// convertedAttributes is the client's attributes in Keycloak's Java map order.
//
// **javamap.KeyOrder is right for the small sets and wrong for the middling
// ones, and that is measured rather than assumed.** The capacity Keycloak's map
// ends up at is not a function of its key set: three keys came back at 16, six
// and eight at 32, eighteen and forty-one at 32. KeyOrder gives 16 up to twelve
// entries, so it agrees on every set of four or fewer and on every set of
// thirteen or more, and disagrees in between - which is exactly the range a
// body naming `grant_types` or `jwks_uri` lands in.
//
// No javamap function can be handed the right table, because the number that
// decides it is how many entries Keycloak's own construction sequence put in
// before it dropped some, and nothing on the wire says what that was. The
// conformance cases that assert bytes use the shapes KeyOrder places; the ones
// it does not are Recorded. See the follow-up.
type convertedAttributes []convertedAttribute

type convertedAttribute struct{ name, value string }

func (a convertedAttributes) MarshalJSON() ([]byte, error) {
	byName := make(map[string]string, len(a))
	keys := make([]string, 0, len(a))
	for _, e := range a {
		byName[e.name] = e.value
		keys = append(keys, e.name)
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range javamap.KeyOrder(keys) {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := marshalOrderedValue(key)
		if err != nil {
			return nil, err
		}
		value, err := marshalOrderedValue(byName[key])
		if err != nil {
			return nil, err
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// convertOIDCClientDescription is the mapping. It reports false for an input
// Keycloak answers with a 500.
func convertOIDCClientDescription(in *oidcClientDescription) (*convertedClient, bool) {
	out := &convertedClient{
		ClientID:     in.ClientID,
		Name:         in.ClientName,
		BaseURL:      in.ClientURI,
		RedirectURIs: in.RedirectURIs,
		Protocol:     "openid-connect",
	}

	authenticator, public, allowedMethod, ok := clientAuthenticator(in.TokenEndpointAuthMethod)
	if !ok {
		return nil, false
	}
	out.ClientAuthenticatorType = authenticator
	out.PublicClient = public

	out.StandardFlowEnabled, out.ImplicitFlowEnabled = convertedFlows(in)
	if in.GrantTypes != nil {
		gt := *in.GrantTypes
		out.DirectAccessGrantsEnabled = slices.Contains(gt, "password")
		out.ServiceAccountsEnabled = ptr(slices.Contains(gt, "client_credentials"))
		// authorizationServicesEnabled appears with the flag above and was
		// false on every measured body, including one naming every grant type
		// Keycloak knows. Nothing in an OIDC description turns it on.
		out.AuthorizationServicesEnabled = ptr(false)
	}
	out.FrontchannelLogout = in.FrontchannelLogoutURI != nil

	attrs := convertedAttributes{}
	add := func(name, value string) { attrs = append(attrs, convertedAttribute{name, value}) }
	if allowedMethod != "" {
		add("client.secret.authentication.allowed.method", allowedMethod)
	}
	if in.LogoURI != nil {
		add("logoUri", *in.LogoURI)
	}
	if in.FrontchannelLogoutURI != nil {
		add("frontchannel.logout.url", *in.FrontchannelLogoutURI)
	}
	if in.BackchannelLogoutURI != nil {
		add("backchannel.logout.url", *in.BackchannelLogoutURI)
	}
	if in.PostLogoutRedirectURIs != nil {
		add("post.logout.redirect.uris", strings.Join(*in.PostLogoutRedirectURIs, "##"))
	}
	if in.DefaultACRValues != nil {
		add("default.acr.values", strings.Join(*in.DefaultACRValues, "##"))
	}
	if in.JWKSURI != nil {
		add("use.jwks.url", "true")
		add("use.jwks.string", "false")
		add("jwks.url", *in.JWKSURI)
	}
	if in.GrantTypes != nil {
		gt := *in.GrantTypes
		add("standard.token.exchange.enabled",
			boolText(slices.Contains(gt, "urn:ietf:params:oauth:grant-type:token-exchange")))
		add("oauth2.jwt.authorization.grant.enabled",
			boolText(slices.Contains(gt, "urn:ietf:params:oauth:grant-type:jwt-bearer")))
		add("oauth2.device.authorization.grant.enabled",
			boolText(slices.Contains(gt, "urn:ietf:params:oauth:grant-type:device_code")))
		add("use.refresh.tokens", boolText(slices.Contains(gt, "refresh_token")))
		add("oidc.ciba.grant.enabled",
			boolText(slices.Contains(gt, "urn:openid:params:grant-type:ciba")))
	}
	// **backchannel.logout.session.required defaults to `true` here**, which is
	// the opposite of the default the same attribute has on a client the admin
	// API creates. Measured: an OIDC body naming nothing produces "true" and one
	// naming it `false` produces "false".
	add("backchannel.logout.session.required", boolTextDefault(in.BackchannelLogoutSessionRequired, true))
	add("frontchannel.logout.session.required", boolTextDefault(in.FrontchannelLogoutSessionRequired, false))
	add("backchannel.logout.revoke.offline.tokens", "false")
	out.Attributes = attrs

	if in.Scope != nil {
		out.OptionalClientScopes = ptr(splitScope(*in.Scope))
	}
	return out, true
}

// convertedFlows is the standard and implicit flags.
//
// **Two inputs decide them and neither wins outright.** Measured, with the
// left column the whole request:
//
//	response_types absent, [], ["none"], ["code"]     standard, no implicit
//	response_types ["token"], ["id_token"]            implicit, no standard
//	response_types ["id_token token"]                 implicit, no standard
//	response_types ["code","token"]                   both
//	grant_types []                                    the response_types answer
//	grant_types ["authorization_code"]                standard
//	grant_types ["password"], ["refresh_token"]       neither
//	grant_types ["authorization_code","implicit"]     both
//	grant_types ["bogus"]                             neither
//	grant_types ["client_credentials"] + rt ["token"] implicit, no standard
//
// So a **non-empty** grant_types decides the standard flow, an empty one hands
// the question back to response_types, and the implicit flow is the union of
// the two. The last row is what says the union is real: grant_types alone would
// have answered no implicit flow there.
func convertedFlows(in *oidcClientDescription) (standard, implicit bool) {
	var rt []string
	if in.ResponseTypes != nil {
		rt = *in.ResponseTypes
	}
	for _, t := range rt {
		for _, word := range strings.Fields(t) {
			if word == "token" || word == "id_token" {
				implicit = true
			}
		}
	}
	if in.GrantTypes != nil && len(*in.GrantTypes) > 0 {
		gt := *in.GrantTypes
		return slices.Contains(gt, "authorization_code"), implicit || slices.Contains(gt, "implicit")
	}
	// Without a grant_types the standard flow survives unless the request asked
	// for an implicit one and no code: `["none"]` and `[]` both answer standard.
	return slices.Contains(rt, "code") || !implicit, implicit
}

// clientAuthenticator maps token_endpoint_auth_method onto the three fields it
// decides. An unregistered value is Keycloak's own 500.
//
// Measured one value at a time:
//
//	absent                 client-secret     confidential   no attribute
//	client_secret_basic    client-secret     confidential   the attribute
//	client_secret_post     client-secret     confidential   the attribute
//	client_secret_jwt      client-secret-jwt confidential   no attribute
//	private_key_jwt        client-jwt        confidential   no attribute
//	tls_client_auth        client-x509       confidential   no attribute
//	none                   none              public         no attribute
func clientAuthenticator(method *string) (authenticator string, public bool, allowedMethod string, ok bool) {
	if method == nil {
		return "client-secret", false, "", true
	}
	switch *method {
	case "client_secret_basic", "client_secret_post":
		return "client-secret", false, *method, true
	case "client_secret_jwt":
		return "client-secret-jwt", false, "", true
	case "private_key_jwt":
		return "client-jwt", false, "", true
	case "tls_client_auth":
		return "client-x509", false, "", true
	case "none":
		return "none", true, "", true
	}
	return "", false, "", false
}

// splitScope is Java's String.split(" ") with the empty string special-cased.
//
// Measured: `""` answers `[]` and `"a  b "` answers `["a","","b"]` - the inner
// empty survives and the trailing one does not, which is exactly what
// String.split does, and the empty input is the one case it disagrees with.
func splitScope(scope string) []string {
	if scope == "" {
		return []string{}
	}
	parts := strings.Split(scope, " ")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func boolTextDefault(b *bool, fallback bool) string {
	if b == nil {
		return boolText(fallback)
	}
	return boolText(*b)
}

// writeConverterServerError is the 500 an unregistered
// token_endpoint_auth_method answers.
//
// **The endpoint has two 500 bodies and they are not interchangeable**: a body
// that will not decode says `Cannot parse the JSON` and this one says
// `For more on this error consult the server log.` Both measured on the same
// route minutes apart.
func writeConverterServerError(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}
