package admin

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

const converterPath = "/admin/realms/master/client-description-converter"

// TestClientDescriptionConverterReproducesMeasuredBodies asserts the response
// **byte for byte** for every input whose attributes javamap.KeyOrder places.
//
// Every want below was read off a live 26.7.1 on 2026-09-03, one input field at
// a time so that no two rules could be confused for one.
func TestClientDescriptionConverterReproducesMeasuredBodies(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct{ name, body, want string }{
		{
			"the smallest body that converts",
			`{"redirect_uris":["https://e.com/cb"]}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"client_id, client_name and client_uri become three different keys",
			`{"client_id":"cdc-one","client_name":"Rich Name","client_uri":"https://home.example.com","redirect_uris":["https://e.com/cb"]}`,
			`{"clientId":"cdc-one","name":"Rich Name","baseUrl":"https://home.example.com",` +
				`"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			// logo_uri is the one URI field that becomes an attribute rather
			// than a top-level key, and its attribute name is camelCase where
			// every other one is dotted.
			"logo_uri lands in attributes",
			`{"logo_uri":"https://l","redirect_uris":["https://e.com/cb"]}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false","logoUri":"https://l",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"token_endpoint_auth_method none makes the client public",
			`{"client_id":"pub","redirect_uris":["https://e.com/cb"],"token_endpoint_auth_method":"none"}`,
			`{"clientId":"pub","clientAuthenticatorType":"none","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":true,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"client_secret_post keeps client-secret and adds an attribute",
			`{"redirect_uris":["https://e.com/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"client.secret.authentication.allowed.method":"client_secret_post",` +
				`"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"response_types token turns the standard flow off",
			`{"redirect_uris":["https://e.com/cb"],"response_types":["token"]}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":false,"implicitFlowEnabled":true,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			// `none` is a response type that turns neither flow on, and the
			// standard flow survives it. `["code","token"]` turns both on.
			"response_types none leaves the standard flow alone",
			`{"redirect_uris":["https://e.com/cb"],"response_types":["none"]}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"scope becomes optionalClientScopes, split the way Java splits it",
			`{"redirect_uris":["https://e.com/cb"],"scope":"a  b "}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"},` +
				`"optionalClientScopes":["a","","b"]}`,
		},
		{
			// An empty scope is the one input String.split disagrees with:
			// Java answers [""] and Keycloak answers [].
			"an empty scope is an empty array",
			`{"redirect_uris":["https://e.com/cb"],"scope":""}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"},` +
				`"optionalClientScopes":[]}`,
		},
		{
			// redirect_uris:null drops the key where [] sends [], which is why
			// the field is a pointer.
			"a null redirect_uris drops the key",
			`{"redirect_uris":null}`,
			`{"clientAuthenticatorType":"client-secret",` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"an empty client_name is a present empty name",
			`{"redirect_uris":["https://e.com/cb"],"client_name":""}`,
			`{"name":"","clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"frontchannel_logout_uri turns frontchannelLogout on",
			`{"redirect_uris":["https://e.com/cb"],"frontchannel_logout_uri":"https://fc"}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":true,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.url":"https://fc",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
		{
			"default_acr_values are joined with ## too",
			`{"redirect_uris":["https://e.com/cb"],"default_acr_values":["1","2"]}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"true",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false",` +
				`"default.acr.values":"1##2"}}`,
		},
		{
			"backchannel_logout_session_required defaults to true and is read when given",
			`{"redirect_uris":["https://e.com/cb"],"backchannel_logout_session_required":false}`,
			`{"clientAuthenticatorType":"client-secret","redirectUris":["https://e.com/cb"],` +
				`"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,` +
				`"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect",` +
				`"attributes":{"backchannel.logout.session.required":"false",` +
				`"frontchannel.logout.session.required":"false",` +
				`"backchannel.logout.revoke.offline.tokens":"false"}}`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := send(t, h, http.MethodPost, converterPath, admin, c.body)
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if got := w.Body.String(); got != c.want {
				t.Errorf("\n got %s\nwant %s", got, c.want)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json;charset=UTF-8" {
				t.Errorf("Content-Type %q", ct)
			}
			if cc := w.Header().Get("Cache-Control"); cc != "" {
				t.Errorf("Cache-Control %q, want none", cc)
			}
		})
	}
}

// TestClientDescriptionConverterCollidingChains covers the two measured bodies
// whose attribute order Gloak does **not** reproduce, and says why.
//
// Both add an attribute that shares a bucket with one of the three every body
// carries - `backchannel.logout.url` with `backchannel.logout.session.required`
// and `post.logout.redirect.uris` with `frontchannel.logout.session.required`,
// at capacity 16 and at 32 alike. Keycloak chains a collision in **insertion**
// order and javamap.KeyOrder breaks it alphabetically, which is that function's
// documented limit rather than anything about this endpoint. Keycloak put the
// added key first in both, and alphabetically it sorts second in both.
//
// So the values and the membership are asserted here and the order is not, and
// the two orders are written down so the divergence is a recorded fact rather
// than an absence.
func TestClientDescriptionConverterCollidingChains(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		name, body string
		want       map[string]string
		keycloak   []string
	}{
		{
			"backchannel_logout_uri collides with backchannel.logout.session.required",
			`{"redirect_uris":["https://e.com/cb"],"backchannel_logout_uri":"https://bc"}`,
			map[string]string{
				"backchannel.logout.url":                   "https://bc",
				"backchannel.logout.session.required":      "true",
				"frontchannel.logout.session.required":     "false",
				"backchannel.logout.revoke.offline.tokens": "false",
			},
			[]string{
				"backchannel.logout.url",
				"backchannel.logout.session.required",
				"frontchannel.logout.session.required",
				"backchannel.logout.revoke.offline.tokens",
			},
		},
		{
			"post_logout_redirect_uris collides with frontchannel.logout.session.required",
			`{"redirect_uris":["https://e.com/cb"],"post_logout_redirect_uris":["https://a","https://b"]}`,
			map[string]string{
				"backchannel.logout.session.required":      "true",
				"post.logout.redirect.uris":                "https://a##https://b",
				"frontchannel.logout.session.required":     "false",
				"backchannel.logout.revoke.offline.tokens": "false",
			},
			[]string{
				"backchannel.logout.session.required",
				"post.logout.redirect.uris",
				"frontchannel.logout.session.required",
				"backchannel.logout.revoke.offline.tokens",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := send(t, h, http.MethodPost, converterPath, admin, c.body)
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			var got struct {
				Attributes map[string]string `json:"attributes"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got.Attributes) != len(c.want) {
				t.Errorf("%d attributes, want %d", len(got.Attributes), len(c.want))
			}
			for name, value := range c.want {
				if got.Attributes[name] != value {
					t.Errorf("%s = %q, want %q", name, got.Attributes[name], value)
				}
			}
			// The order Keycloak sent, kept here as the record. If a later cut
			// makes Gloak place a colliding chain, this is the assertion to
			// turn back on.
			if len(c.keycloak) != len(c.want) {
				t.Errorf("the recorded order names %d keys and the body has %d",
					len(c.keycloak), len(c.want))
			}
		})
	}
}

// TestClientDescriptionConverterFlagRules walks the ten measured combinations
// of grant_types and response_types.
//
// The **last** row is the one that earns the table: grant_types alone would
// answer no implicit flow there, and response_types alone would answer a
// standard one, so the pair is neither field's rule.
func TestClientDescriptionConverterFlagRules(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	cases := []struct {
		name                          string
		body                          string
		standard, implicit, direct    bool
		serviceAccounts, hasGrantKeys bool
	}{
		{"no grant_types and no response_types", `{"redirect_uris":[]}`, true, false, false, false, false},
		{"response_types []", `{"redirect_uris":[],"response_types":[]}`, true, false, false, false, false},
		{"response_types id_token token", `{"redirect_uris":[],"response_types":["id_token token"]}`, false, true, false, false, false},
		{"response_types code and token", `{"redirect_uris":[],"response_types":["code","token"]}`, true, true, false, false, false},
		{"grant_types []", `{"redirect_uris":[],"grant_types":[]}`, true, false, false, false, true},
		{"grant_types authorization_code", `{"redirect_uris":[],"grant_types":["authorization_code"]}`, true, false, false, false, true},
		{"grant_types password", `{"redirect_uris":[],"grant_types":["password"]}`, false, false, true, false, true},
		{"grant_types authorization_code and implicit", `{"redirect_uris":[],"grant_types":["authorization_code","implicit"]}`, true, true, false, false, true},
		{"grant_types bogus", `{"redirect_uris":[],"grant_types":["bogus"]}`, false, false, false, false, true},
		{"grant_types client_credentials with response_types token", `{"redirect_uris":[],"grant_types":["client_credentials"],"response_types":["token"]}`, false, true, false, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := send(t, h, http.MethodPost, converterPath, admin, c.body)
			if w.Code != http.StatusOK {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			var got map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("parse: %v", err)
			}
			for key, want := range map[string]bool{
				"standardFlowEnabled":       c.standard,
				"implicitFlowEnabled":       c.implicit,
				"directAccessGrantsEnabled": c.direct,
			} {
				if got[key] != want {
					t.Errorf("%s = %v, want %v", key, got[key], want)
				}
			}
			_, hasServiceAccounts := got["serviceAccountsEnabled"]
			_, hasAuthzServices := got["authorizationServicesEnabled"]
			if hasServiceAccounts != c.hasGrantKeys || hasAuthzServices != c.hasGrantKeys {
				t.Errorf("serviceAccountsEnabled present=%v, authorizationServicesEnabled present=%v; want %v",
					hasServiceAccounts, hasAuthzServices, c.hasGrantKeys)
			}
			if c.hasGrantKeys && got["serviceAccountsEnabled"] != c.serviceAccounts {
				t.Errorf("serviceAccountsEnabled = %v, want %v", got["serviceAccountsEnabled"], c.serviceAccounts)
			}
		})
	}
}

// TestClientDescriptionConverterGrantTypeAttributes asserts the five extra
// attributes a grant_types body carries, by membership and value.
//
// **It does not assert their order, and that is the divergence this cut
// ships.** Keycloak's map holds these eight at capacity 32 and javamap.KeyOrder
// gives 16 for eight entries, so Gloak serves them in a different order. The
// capacity is not a function of the key set - three keys came back at 16 and
// six, eight and eighteen at 32 - so no javamap function can be handed the
// right table. See the follow-up, and
// admin/realms-admin/client-description-converter-grant-types, which is
// Recorded for exactly this.
func TestClientDescriptionConverterGrantTypeAttributes(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	w := send(t, h, http.MethodPost, converterPath, admin,
		`{"redirect_uris":["https://e.com/cb"],"grant_types":`+
			`["refresh_token","urn:ietf:params:oauth:grant-type:device_code"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var got struct {
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]string{
		"standard.token.exchange.enabled":           "false",
		"oauth2.jwt.authorization.grant.enabled":    "false",
		"frontchannel.logout.session.required":      "false",
		"oauth2.device.authorization.grant.enabled": "true",
		"backchannel.logout.revoke.offline.tokens":  "false",
		"use.refresh.tokens":                        "true",
		"oidc.ciba.grant.enabled":                   "false",
		"backchannel.logout.session.required":       "true",
	}
	if len(got.Attributes) != len(want) {
		t.Errorf("%d attributes, want %d: %v", len(got.Attributes), len(want), got.Attributes)
	}
	for name, value := range want {
		if got.Attributes[name] != value {
			t.Errorf("%s = %q, want %q", name, got.Attributes[name], value)
		}
	}
}

// TestClientDescriptionConverterRefusals pins the shape test and the two 500s.
//
// The three rows that matter are the last three: a body that passes the string
// test and then fails to parse is a 500 and not the 400 an unrecognised shape
// gets, an unknown field is the same 500, and an unregistered
// token_endpoint_auth_method is a 500 with a **different** body.
func TestClientDescriptionConverterRefusals(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	unsupported := `{"error":"Unsupported format"}`
	for _, body := range []string{
		``,
		`{"client_id":"cdc-min"}`,
		`redirect_uris`,
		`["redirect_uris"]`,
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`,
	} {
		w := send(t, h, http.MethodPost, converterPath, admin, body)
		if w.Code != http.StatusBadRequest || w.Body.String() != unsupported {
			t.Errorf("body %q: %d %s", body, w.Code, w.Body)
		}
	}

	// Whitespace is trimmed before the braces are looked at.
	if w := send(t, h, http.MethodPost, converterPath, admin,
		"  {\"redirect_uris\":[\"https://e.com/cb\"]}  "); w.Code != http.StatusOK {
		t.Errorf("a padded body: %d %s", w.Code, w.Body)
	}

	cannotParse := `{"error":"unknown_error","error_description":"Cannot parse the JSON"}`
	for _, body := range []string{`{"x":"redirect_uris"}`, `{"redirect_uris":[],"nosuchfield":"x"}`} {
		w := send(t, h, http.MethodPost, converterPath, admin, body)
		if w.Code != http.StatusInternalServerError || w.Body.String() != cannotParse {
			t.Errorf("body %q: %d %s", body, w.Code, w.Body)
		}
	}

	w := send(t, h, http.MethodPost, converterPath, admin,
		`{"redirect_uris":[],"token_endpoint_auth_method":"bogus"}`)
	if w.Code != http.StatusInternalServerError ||
		w.Body.String() != `{"error":"unknown_error","error_description":"For more on this error consult the server log."}` {
		t.Errorf("an unregistered auth method: %d %s", w.Code, w.Body)
	}
}

// TestClientDescriptionConverterAcceptsEveryMeasuredFieldName sends the whole
// accepted set in one body, and one name beside it that is **not** accepted.
//
// `software_statement` is RFC 7591's and is the obvious next name to declare;
// Keycloak's representation has no such field and answers it the strict
// decoder's 500. It is here because declaring it would have made Gloak accept a
// body Keycloak refuses, and nothing but sending it says so.
func TestClientDescriptionConverterAcceptsEveryMeasuredFieldName(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	const every = `{"redirect_uris":["https://e.com/cb"],"response_types":["code"],` +
		`"grant_types":["authorization_code"],"application_type":"web","contacts":["a@b.c"],` +
		`"client_name":"n","logo_uri":"https://l","client_uri":"https://u",` +
		`"policy_uri":"https://p","tos_uri":"https://t","jwks_uri":"https://j",` +
		`"jwks":{"keys":[]},"sector_identifier_uri":"https://s","subject_type":"public",` +
		`"id_token_signed_response_alg":"RS256","id_token_encrypted_response_alg":"RSA-OAEP",` +
		`"id_token_encrypted_response_enc":"A128CBC-HS256","userinfo_signed_response_alg":"RS256",` +
		`"userinfo_encrypted_response_alg":"RSA-OAEP","userinfo_encrypted_response_enc":"A128CBC-HS256",` +
		`"request_object_signing_alg":"RS256","request_object_encryption_alg":"RSA-OAEP",` +
		`"request_object_encryption_enc":"A128CBC-HS256","token_endpoint_auth_method":"client_secret_basic",` +
		`"token_endpoint_auth_signing_alg":"RS256","default_max_age":60,"require_auth_time":true,` +
		`"default_acr_values":["1"],"initiate_login_uri":"https://i","request_uris":["https://r"],` +
		`"client_id":"gloak-probe-every","software_id":"sw","software_version":"1",` +
		`"tls_client_certificate_bound_access_tokens":true,"tls_client_auth_subject_dn":"CN=x",` +
		`"backchannel_logout_uri":"https://bc","backchannel_logout_session_required":true,` +
		`"frontchannel_logout_uri":"https://fc","frontchannel_logout_session_required":true,` +
		`"post_logout_redirect_uris":["https://pl"],"authorization_signed_response_alg":"RS256",` +
		`"authorization_encrypted_response_alg":"RSA-OAEP",` +
		`"authorization_encrypted_response_enc":"A128CBC-HS256",` +
		`"backchannel_token_delivery_mode":"poll",` +
		`"backchannel_client_notification_endpoint":"https://bn",` +
		`"backchannel_authentication_request_signing_alg":"RS256",` +
		`"require_pushed_authorization_requests":true,"dpop_bound_access_tokens":true,` +
		`"client_secret":"s","client_secret_expires_at":0,"client_id_issued_at":0,` +
		`"registration_access_token":"t","registration_client_uri":"https://r","scope":"openid"}`

	if w := send(t, h, http.MethodPost, converterPath, admin, every); w.Code != http.StatusOK {
		t.Errorf("the whole accepted field set: %d %s", w.Code, w.Body)
	}
	w := send(t, h, http.MethodPost, converterPath, admin,
		`{"redirect_uris":["https://e.com/cb"],"software_statement":"s"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("software_statement: %d %s, want 500", w.Code, w.Body)
	}
}

// TestClientDescriptionConverterIgnoresTheContentType is a measurement a
// reviewer would otherwise assume the other way: the route's @Consumes covers
// three media types and none of them decides anything.
func TestClientDescriptionConverterIgnoresTheContentType(t *testing.T) {
	h, _, _ := newServer(t)
	admin := adminToken(t, h)

	var bodies []string
	for _, ct := range []string{"application/json", "text/plain", "application/xml", ""} {
		w := sendTyped(t, h, http.MethodPost, converterPath, admin, ct,
			`{"redirect_uris":["https://e.com/cb"]}`)
		if w.Code != http.StatusOK {
			t.Fatalf("Content-Type %q: %d %s", ct, w.Code, w.Body)
		}
		bodies = append(bodies, w.Body.String())
	}
	for _, body := range bodies[1:] {
		if body != bodies[0] {
			t.Errorf("the Content-Type moved the answer:\n%s\n%s", bodies[0], body)
		}
	}
}

// TestClientDescriptionConverterTakesManageClients is the guard, and it is not
// the one the description's tag predicts.
func TestClientDescriptionConverterTakesManageClients(t *testing.T) {
	h, s, realm := newServer(t)
	body := `{"redirect_uris":["https://e.com/cb"]}`

	if w := send(t, h, http.MethodPost, converterPath,
		tokenForRole(t, h, s, realm, "manage-clients"), body); w.Code != http.StatusOK {
		t.Errorf("manage-clients: %d %s", w.Code, w.Body)
	}
	viewClients := tokenForRole(t, h, s, realm, "view-clients")
	for role, token := range map[string]string{
		"manage-realm":  tokenForRole(t, h, s, realm, "manage-realm"),
		"view-realm":    tokenForRole(t, h, s, realm, "view-realm"),
		"view-clients":  viewClients,
		"create-client": tokenForRole(t, h, s, realm, "create-client"),
	} {
		if w := send(t, h, http.MethodPost, converterPath, token, body); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s, want 403", role, w.Code, w.Body)
		}
	}

	// The caller is judged before the body, so a refused caller never sees the
	// 400 a bad body would have earned.
	if w := send(t, h, http.MethodPost, converterPath, viewClients, `garbage`); w.Code != http.StatusForbidden {
		t.Errorf("a bad body from a refused caller: %d %s", w.Code, w.Body)
	}
}

// TestConvertedAttributesUseKeyOrder is the unit-level half: the marshaller
// places its keys with javamap rather than sorting them, which encoding/json
// would do to a Go map.
func TestConvertedAttributesUseKeyOrder(t *testing.T) {
	attrs := convertedAttributes{
		{"backchannel.logout.session.required", "true"},
		{"frontchannel.logout.session.required", "false"},
		{"backchannel.logout.revoke.offline.tokens", "false"},
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"backchannel.logout.session.required":"true",` +
		`"frontchannel.logout.session.required":"false",` +
		`"backchannel.logout.revoke.offline.tokens":"false"}`
	if string(raw) != want {
		t.Errorf("\n got %s\nwant %s", raw, want)
	}
	// Sorting is what a Go map would do and it is a different answer, which is
	// what makes the assertion above about javamap rather than about luck.
	names := []string{
		"backchannel.logout.session.required",
		"frontchannel.logout.session.required",
		"backchannel.logout.revoke.offline.tokens",
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	if slices.Equal(sorted, names) {
		t.Error("the measured order is alphabetical, so this vector proves nothing")
	}
}
