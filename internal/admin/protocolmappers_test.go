package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/model"
)

// TestBootstrappedClientMappers asserts the two protocol mappers a
// bootstrapped realm's **clients** carry, for the reason
// TestBootstrappedClientScopeMappers asserts a scope's: no golden can.
//
// The client representation's UUID is minted at bootstrap, so no conformance
// case can name one of these clients in a path, and the one case that
// enumerates the realm - `admin/clients/list-all` - is `Recorded` and skipped.
// So these two mappers, added on 2026-08-30, would otherwise be guarded by
// nothing at all.
//
// **Four of the six clients carry none.** That is asserted here too, because
// `protocolMappers` is absent rather than empty on the representation, and a
// bootstrap that gave every client an empty slice would serve `[]` on four
// bodies that have no such key.
//
// The values are the measurement, from
// GET /admin/realms/master/clients/{uuid}/protocol-mappers/models on a live
// Keycloak 26.7.1 on 2026-08-30, config key order included.
func TestBootstrappedClientMappers(t *testing.T) {
	_, s, realm := newServer(t)
	ctx := context.Background()

	for _, clientID := range []string{"account", "admin-cli", "broker", "master-realm"} {
		c, err := s.Clients().ByClientID(ctx, realm.ID, clientID)
		if err != nil {
			t.Fatalf("ByClientID(%s): %v", clientID, err)
		}
		if len(c.ProtocolMappers) != 0 {
			t.Errorf("%s has %d protocol mappers, want none", clientID, len(c.ProtocolMappers))
		}
	}

	for _, tc := range []struct {
		clientID     string
		name         string
		kind         string
		configKeys   []string
		configValues []string
	}{
		{
			clientID: "account-console",
			name:     "audience resolve",
			kind:     "oidc-audience-resolve-mapper",
			// Two keys, not seven, because oidc-audience-resolve-mapper is one
			// of the two OIDC providers that mirror `access.token.claim` into
			// `introspection.token.claim` and do **not** mirror
			// `id.token.claim` into `userinfo.token.claim`.
			configKeys:   []string{"introspection.token.claim", "access.token.claim"},
			configValues: []string{"true", "true"},
		},
		{
			clientID: "security-admin-console",
			name:     "locale",
			kind:     "oidc-usermodel-attribute-mapper",
			configKeys: []string{
				"introspection.token.claim", "userinfo.token.claim", "user.attribute",
				"id.token.claim", "access.token.claim", "claim.name", "jsonType.label",
			},
			configValues: []string{"true", "true", "locale", "true", "true", "locale", "String"},
		},
	} {
		c, err := s.Clients().ByClientID(ctx, realm.ID, tc.clientID)
		if err != nil {
			t.Fatalf("ByClientID(%s): %v", tc.clientID, err)
		}
		if len(c.ProtocolMappers) != 1 {
			t.Fatalf("%s has %d protocol mappers, want 1", tc.clientID, len(c.ProtocolMappers))
		}
		m := c.ProtocolMappers[0]
		if m.Name != tc.name || m.Protocol != "openid-connect" ||
			m.ProtocolMapper != tc.kind || m.ConsentRequired {
			t.Errorf("%s mapper = %+v", tc.clientID, m)
		}
		var keys, values []string
		for _, p := range m.Config {
			keys = append(keys, p.Key)
			values = append(values, p.Value)
		}
		// The key **order** is asserted, not only membership: it is Keycloak's
		// own Java map order and model.StringMap is what carries it.
		if !slices.Equal(keys, tc.configKeys) {
			t.Errorf("%s config keys:\n got %v\nwant %v", tc.clientID, keys, tc.configKeys)
		}
		if !slices.Equal(values, tc.configValues) {
			t.Errorf("%s config values:\n got %v\nwant %v", tc.clientID, values, tc.configValues)
		}
	}
}

// TestProtocolMapperConfigMirroring pins the two config keys a create fills in
// for itself, per provider.
//
// The rule is not "every oidc-* provider gets both": measured across all 39
// registered providers, twenty of the twenty-four OIDC ones do,
// oidc-allowed-origins-mapper and oidc-audience-resolve-mapper mirror only
// into `introspection.token.claim`, oidc-nonce-backwards-compatible-mapper and
// oidc-organization-membership-mapper mirror neither, and all fourteen `saml-*`
// providers and docker-v2-allow-all-mapper mirror neither.
//
// And it follows the **provider**, not the mapper's own `protocol`: the last
// two cases below are the pair that says so, and a prefix test on the provider
// id passes the first three and fails the fifth.
func TestProtocolMapperConfigMirroring(t *testing.T) {
	name, protocol := "m", "openid-connect"
	for _, tc := range []struct {
		what     string
		provider string
		protocol string
		in       model.StringMap
		want     model.StringMap
	}{
		{
			what: "both mirrors", provider: "oidc-usermodel-attribute-mapper",
			in: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
			},
			want: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
				{Key: "introspection.token.claim", Value: "true"},
				{Key: "userinfo.token.claim", Value: "true"},
			},
		},
		{
			// The mirrored value is the **source's**, not a constant "true".
			what: "false is mirrored too", provider: "oidc-usermodel-attribute-mapper",
			in: model.StringMap{{Key: "access.token.claim", Value: "false"}},
			want: model.StringMap{
				{Key: "access.token.claim", Value: "false"},
				{Key: "introspection.token.claim", Value: "false"},
			},
		},
		{
			what: "an explicit mirror is left alone", provider: "oidc-usermodel-attribute-mapper",
			in: model.StringMap{
				{Key: "access.token.claim", Value: "true"},
				{Key: "introspection.token.claim", Value: "false"},
			},
			want: model.StringMap{
				{Key: "access.token.claim", Value: "true"},
				{Key: "introspection.token.claim", Value: "false"},
			},
		},
		{
			what: "introspection only", provider: "oidc-audience-resolve-mapper",
			in: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
			},
			want: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
				{Key: "introspection.token.claim", Value: "true"},
			},
		},
		{
			what: "neither, on an oidc- provider", provider: "oidc-nonce-backwards-compatible-mapper",
			in: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
			},
			want: model.StringMap{
				{Key: "id.token.claim", Value: "true"},
				{Key: "access.token.claim", Value: "true"},
			},
		},
		{
			// An OIDC provider declared saml: the mirrors still apply.
			what:     "the provider decides, not the protocol (oidc under saml)",
			provider: "oidc-usermodel-attribute-mapper", protocol: "saml",
			in: model.StringMap{{Key: "access.token.claim", Value: "true"}},
			want: model.StringMap{
				{Key: "access.token.claim", Value: "true"},
				{Key: "introspection.token.claim", Value: "true"},
			},
		},
		{
			// And a saml provider declared openid-connect: they still do not.
			what:     "the provider decides, not the protocol (saml under oidc)",
			provider: "saml-user-property-mapper",
			in:       model.StringMap{{Key: "access.token.claim", Value: "true"}},
			want:     model.StringMap{{Key: "access.token.claim", Value: "true"}},
		},
		{
			// An empty value is dropped **before** the mirroring reads it, so
			// this produces neither the key nor its mirror.
			what:     "an empty value is dropped, and takes its mirror with it",
			provider: "oidc-usermodel-attribute-mapper",
			in: model.StringMap{
				{Key: "access.token.claim", Value: ""},
				{Key: "claim.name", Value: "x"},
			},
			want: model.StringMap{{Key: "claim.name", Value: "x"}},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			p := tc.protocol
			if p == "" {
				p = protocol
			}
			got := mapperConfig(protocolMapperRequest{
				Name: &name, Protocol: &p, ProtocolMapper: tc.provider, Config: tc.in,
			})
			if len(got) != len(tc.want) {
				t.Fatalf("config = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("config = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestProtocolMapperProviderTable pins the shape of the measured table itself.
//
// It is the membership test behind `ProtocolMapper provider not found` as well
// as the source of the two mirroring flags, so a row deleted to "simplify" the
// mirroring would silently turn a 404 into a 201.
func TestProtocolMapperProviderTable(t *testing.T) {
	if got := len(protocolMapperProviders); got != 39 {
		t.Errorf("provider table has %d entries, want the 39 GET /admin/serverinfo reports", got)
	}
	var both, introspectionOnly, neither int
	for id, p := range protocolMapperProviders {
		switch {
		case p.Introspection && p.Userinfo:
			both++
		case p.Introspection:
			introspectionOnly++
			if id != "oidc-allowed-origins-mapper" && id != "oidc-audience-resolve-mapper" {
				t.Errorf("%s mirrors introspection only; only two providers do", id)
			}
		case p.Userinfo:
			t.Errorf("%s mirrors userinfo without introspection; no provider does", id)
		default:
			neither++
		}
	}
	if both != 20 || introspectionOnly != 2 || neither != 17 {
		t.Errorf("provider table = %d both, %d introspection-only, %d neither; want 20, 2, 17",
			both, introspectionOnly, neither)
	}
}

// TestUpdateWritesTheMapperTheBodyNamesNotThePath pins the strangest thing
// measured on this family.
//
// `PUT .../protocol-mappers/models/{id}` resolves the mapper it writes from the
// **body's** `id`, not the path's. A PUT addressed to one mapper and carrying
// another's id answers 204 and changes the other one. Keycloak's
// `ClientScopeAdapter` looks the entity up by the model's id, and the path
// segment only decides whether the request is a 404 at all.
//
// It was measured and written into updateProtocolMapper's doc comment and
// nothing tested it: swapping the second lookup to the path's id left the whole
// suite green, because every other case sends a body whose id agrees with its
// path. This is the case where the two disagree, which is the only place the
// difference is observable.
func TestUpdateWritesTheMapperTheBodyNamesNotThePath(t *testing.T) {
	h, _, _ := newServer(t)
	token := tokenFor(t, h, "admin", "admin")

	scope := `{"id":"11111111-1111-1111-1111-111111111111","name":"gloak-probe-pm-swap",` +
		`"protocol":"openid-connect","protocolMappers":[` +
		`{"id":"aaaaaaaa-1111-1111-1111-111111111111","name":"a",` +
		`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
		`"config":{"claim.name":"before-a"}},` +
		`{"id":"bbbbbbbb-2222-2222-2222-222222222222","name":"b",` +
		`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
		`"config":{"claim.name":"before-b"}}]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/realms/master/client-scopes",
		strings.NewReader(scope))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create scope: %d %s", w.Code, w.Body)
	}

	// Addressed to a, carrying b's id.
	body := `{"id":"bbbbbbbb-2222-2222-2222-222222222222","name":"b",` +
		`"protocol":"openid-connect","protocolMapper":"oidc-usermodel-attribute-mapper",` +
		`"config":{"claim.name":"after-b"}}`
	req = httptest.NewRequest(http.MethodPut,
		"/admin/realms/master/client-scopes/11111111-1111-1111-1111-111111111111"+
			"/protocol-mappers/models/aaaaaaaa-1111-1111-1111-111111111111",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}

	w = get(t, h, "/admin/realms/master/client-scopes/11111111-1111-1111-1111-111111111111"+
		"/protocol-mappers/models", token)
	var got []struct {
		Name   string            `json:"name"`
		Config map[string]string `json:"config"`
	}
	if err := decodeJSON(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("parse listing: %v: %s", err, w.Body)
	}
	claims := map[string]string{}
	for _, m := range got {
		claims[m.Name] = m.Config["claim.name"]
	}
	if claims["b"] != "after-b" {
		t.Errorf("b's claim.name = %q, want %q - the body named b and b is what must move",
			claims["b"], "after-b")
	}
	if claims["a"] != "before-a" {
		t.Errorf("a's claim.name = %q, want %q - a was only the path, and the path does not decide",
			claims["a"], "before-a")
	}
}
