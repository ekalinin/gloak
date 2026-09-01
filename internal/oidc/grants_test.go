package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/bootstrap"
	"github.com/ekalinin/gloak/internal/keys"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
	"github.com/ekalinin/gloak/internal/store/sqlite"
)

// The token exchange and JWT bearer grants' tests are here for the reason the
// device grant's are: **what was measured is a ladder**, and a golden holds one
// rung. Every adjacency below was fixed by sending a request wrong in two ways
// at once, and the catalogue's two cases break exactly one thing each.

const tokenPath = "/realms/master/protocol/openid-connect/token"

// grantServer is a bootstrapped master with the clients each ladder needs,
// spelled the way the live probes spelled them.
func grantServer(t *testing.T) (http.Handler, store.Store, *model.Realm) {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "gloak.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := bootstrap.EnsureMaster(ctx, s, "admin", "admin"); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	realm, err := s.Realms().ByName(ctx, "master")
	if err != nil {
		t.Fatalf("ByName: %v", err)
	}
	clients := []*model.Client{
		// The exchange client: confidential, direct grants on so a subject
		// token can be obtained, and the attribute that opens the grant.
		{ClientID: "tx-on", Enabled: true, Secret: "s3cret", DirectAccessGrantsEnabled: true,
			Attributes: map[string]string{attrExchangeGrant: "true"}},
		// The same client with the attribute off, so the first rung is
		// reachable on a client that is otherwise identical.
		{ClientID: "tx-off", Enabled: true, Secret: "s3cret", DirectAccessGrantsEnabled: true},
		// A confidential client with the JWT bearer grant on, and one without,
		// so rungs 4 and 6 differ in the attribute alone.
		{ClientID: "jb-on", Enabled: true, Secret: "s3cret",
			Attributes: map[string]string{attrJWTBearerGrant: "true"}},
		{ClientID: "jb-off", Enabled: true, Secret: "s3cret"},
		{ClientID: "jb-public", Enabled: true, PublicClient: true,
			Attributes: map[string]string{attrJWTBearerGrant: "true"}},
	}
	for _, c := range clients {
		c.ID = model.NewID()
		c.RealmID = realm.ID
		c.Protocol = "openid-connect"
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.ClientID, err)
		}
	}
	mux := http.NewServeMux()
	Register(mux, s, keys.NewManager(s), "http://localhost:8080")
	return WithKeycloakFallbacks(mux), s, realm
}

// subjectToken is an access token for the exchange client, obtained the way the
// conformance fixture obtains one.
func subjectToken(t *testing.T, h http.Handler, clientID string) string {
	t.Helper()
	w := postForm(t, h, tokenPath, url.Values{
		"grant_type": {"password"}, "client_id": {clientID}, "client_secret": {"s3cret"},
		"username": {"admin"}, "password": {"admin"}, "scope": {"openid"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("subject token: want 200, got %d: %s", w.Code, w.Body)
	}
	var body tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return body.AccessToken
}

func exchangeForm(clientID, subject string) url.Values {
	return url.Values{
		"grant_type": {grantTokenExchange}, "client_id": {clientID}, "client_secret": {"s3cret"},
		"subject_token":      {subject},
		"subject_token_type": {tokenTypeAccess},
	}
}

// TestTokenExchangeAnswersEightKeysNotNine is the shape that made a separate
// response struct necessary: no refresh_token, no id_token even though the
// subject token was granted openid, refresh_expires_in 0, and issued_token_type
// after scope.
func TestTokenExchangeAnswersEightKeysNotNine(t *testing.T) {
	h, _, _ := grantServer(t)
	subject := subjectToken(t, h, "tx-on")
	w := postForm(t, h, tokenPath, exchangeForm("tx-on", subject))
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: want 200, got %d: %s", w.Code, w.Body)
	}
	want := []string{
		"access_token", "expires_in", "refresh_expires_in", "token_type",
		"not-before-policy", "session_state", "scope", "issued_token_type",
	}
	got := jsonKeyOrder(t, w.Body.Bytes())
	if !equalStrings(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	var body exchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body.IssuedTokenType != tokenTypeAccess {
		t.Errorf("issued_token_type: got %q", body.IssuedTokenType)
	}
	if body.RefreshExpiresIn != 0 {
		t.Errorf("refresh_expires_in must be 0, got %d", body.RefreshExpiresIn)
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type: got %q", body.TokenType)
	}
	// The absence of an id_token is asserted over the raw body rather than by
	// the struct, and that is a mutation's doing: setting IncludeIDToken true in
	// tokenExchangeGrant survived, because exchangeResponse has no such field
	// and the token it minted was simply dropped. The mutation is equivalent -
	// nothing observable moves - and this is what would catch the field being
	// added. See the mutation section of
	// docs/superpowers/handover/p7-registration.md.
	for _, absent := range []string{"id_token", "refresh_token"} {
		if strings.Contains(w.Body.String(), absent) {
			t.Errorf("the exchange body must not carry %s", absent)
		}
	}
}

// TestTheExchangedTokenKeepsTheSubjectsSession is the claim a response-shape
// test cannot make: session_state is the **subject's**, not a new one, so
// nothing about the exchange starts a session.
func TestTheExchangedTokenKeepsTheSubjectsSession(t *testing.T) {
	h, _, _ := grantServer(t)
	w := postForm(t, h, tokenPath, url.Values{
		"grant_type": {"password"}, "client_id": {"tx-on"}, "client_secret": {"s3cret"},
		"username": {"admin"}, "password": {"admin"}, "scope": {"openid"},
	})
	var first tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatalf("parse: %v", err)
	}
	x := postForm(t, h, tokenPath, exchangeForm("tx-on", first.AccessToken))
	if x.Code != http.StatusOK {
		t.Fatalf("exchange: want 200, got %d: %s", x.Code, x.Body)
	}
	var exchanged exchangeResponse
	if err := json.Unmarshal(x.Body.Bytes(), &exchanged); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if exchanged.SessionState != first.SessionState {
		t.Errorf("session_state: want the subject's %q, got %q",
			first.SessionState, exchanged.SessionState)
	}
	// The scope comes from the subject token, not from the request, which no
	// request in this test names.
	if exchanged.Scope != first.Scope {
		t.Errorf("scope: want the subject's %q, got %q", first.Scope, exchanged.Scope)
	}
}

// TestTokenExchangeRefusesInTheMeasuredOrder drives each adjacency with a
// request wrong in two ways, so the order is fixed rather than the list.
func TestTokenExchangeRefusesInTheMeasuredOrder(t *testing.T) {
	h, _, _ := grantServer(t)
	subject := subjectToken(t, h, "tx-on")

	for _, tc := range []struct {
		name string
		form url.Values
		desc string
	}{
		{
			// The attribute is checked before the parameters: a client with it
			// off sending nothing else answers about the client.
			"the attribute outranks a missing subject_token",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-off"},
				"client_secret": {"s3cret"}},
			descExchangeDisabled,
		},
		{
			// subject_token before subject_token_type: a request missing both
			// answers about the token.
			"subject_token outranks subject_token_type",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}},
			descExchangeMissingSubject,
		},
		{
			"a missing subject_token_type, with a good subject_token",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}, "subject_token": {subject}},
			descExchangeMissingType,
		},
		{
			// The type is judged before the token is verified: a garbage
			// subject with a wrong type answers about the type.
			"the type outranks the token's validity",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}, "subject_token": {"garbage"},
				"subject_token_type": {tokenTypeRefresh}},
			descExchangeAccessOnly,
		},
		{
			// And the requested type outranks it too.
			"requested_token_type outranks the token's validity",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}, "subject_token": {"garbage"},
				"subject_token_type": {tokenTypeAccess}, "requested_token_type": {tokenTypeRefresh}},
			descExchangeRequestedType,
		},
		{
			"an unverifiable subject_token",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}, "subject_token": {"garbage"},
				"subject_token_type": {tokenTypeAccess}},
			descExchangeInvalidToken,
		},
		{
			// An empty subject_token= reaches the verification rather than the
			// presence check, which is why the handler reads PostForm's key.
			"an empty subject_token is a value, not an absence",
			url.Values{"grant_type": {grantTokenExchange}, "client_id": {"tx-on"},
				"client_secret": {"s3cret"}, "subject_token": {""},
				"subject_token_type": {tokenTypeAccess}},
			descExchangeInvalidToken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postForm(t, h, tokenPath, tc.form)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body)
			}
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("parse: %v", err)
			}
			// Every rung is invalid_request, where the neighbouring grants use
			// invalid_grant for most of theirs.
			if body.Error != authErrInvalidRequest {
				t.Errorf("code: want invalid_request, got %q", body.Error)
			}
			if body.Description != tc.desc {
				t.Errorf("want %q, got %q", tc.desc, body.Description)
			}
		})
	}
}

// assertion builds a three-part JWT whose payload is the given JSON. Nothing
// signs it: the endpoint's "is this a valid JWT" predicate is measured to be
// structural.
func assertion(payload string) string {
	b := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return b(`{"alg":"RS256","typ":"JWT"}`) + "." + b(payload) + ".c2ln"
}

// TestJWTBearerRefusesInTheMeasuredOrder is the six-rung ladder, and three of
// its rungs are only visible from a request wrong in two ways.
func TestJWTBearerRefusesInTheMeasuredOrder(t *testing.T) {
	h, _, _ := grantServer(t)
	good := assertion(`{"iss":"https://issuer.example.com","sub":"s"}`)
	noIss := assertion(`{}`)

	for _, tc := range []struct {
		name string
		form url.Values
		desc string
	}{
		{
			"an absent assertion",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-on"},
				"client_secret": {"s3cret"}},
			descMissingAssertion,
		},
		{
			// An empty assertion= is a value: it reaches the parse.
			"an empty assertion is a value, not an absence",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-on"},
				"client_secret": {"s3cret"}, "assertion": {""}},
			descAssertionNotAJWT,
		},
		{
			// The parse outranks the public-client check: a public client
			// sending rubbish is told about the assertion.
			"the parse outranks the public client check",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-public"},
				"assertion": {"a.b.c"}},
			descAssertionNotAJWT,
		},
		{
			// And the public-client check outranks the iss claim.
			"a public client outranks a missing iss",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-public"},
				"assertion": {noIss}},
			descPublicClientGrant,
		},
		{
			// So does the attribute.
			"the attribute outranks a missing iss",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-off"},
				"client_secret": {"s3cret"}, "assertion": {noIss}},
			descJWTGrantDisabled,
		},
		{
			"a missing iss on a client that may use the grant",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-on"},
				"client_secret": {"s3cret"}, "assertion": {noIss}},
			descAssertionMissingIS,
		},
		{
			// The rung a mutation found: the first sweep of this ladder always
			// sent sub beside iss, so an assertion carrying only iss had never
			// been issued.
			"a missing sub, with an iss that names nothing",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-on"},
				"client_secret": {"s3cret"},
				"assertion":     {assertion(`{"iss":"https://issuer.example.com"}`)}},
			descAssertionMissingSub,
		},
		{
			// The end of the road on any default deployment.
			"an iss and a sub naming no identity provider",
			url.Values{"grant_type": {grantJWTBearer}, "client_id": {"jb-on"},
				"client_secret": {"s3cret"}, "assertion": {good}},
			descNoIdentityProvider,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postForm(t, h, tokenPath, tc.form)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body)
			}
			var body struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if body.Error != "invalid_grant" {
				t.Errorf("code: want invalid_grant, got %q", body.Error)
			}
			if body.Description != tc.desc {
				t.Errorf("want %q, got %q", tc.desc, body.Description)
			}
		})
	}
}

// TestMissingParameterAssertionHasNoSpace is one byte and it is the contract.
// Every other missing-parameter description on this endpoint is
// `Missing parameter: x`, and CIBA's one endpoint away is
// `missing parameter : login_hint` with a space on both sides.
func TestMissingParameterAssertionHasNoSpace(t *testing.T) {
	if strings.Contains(descMissingAssertion, ": ") {
		t.Errorf("%q gained a space after the colon", descMissingAssertion)
	}
	if descMissingAssertion != "Missing parameter:assertion" {
		t.Errorf("got %q", descMissingAssertion)
	}
}

// TestTheAssertionPredicateIsStructural pins what "a valid JWT" means here.
//
// **This test passed a mutation of the very rule it was written to establish.**
// Its first version listed five refused assertions and every one of them was
// refused for its *payload* - `a.b.c`'s `b` is not JSON, and so on - so a
// mutation that accepted a two-part assertion changed none of them. Reading the
// hole led to a probe that had never been sent, and the probe said the
// implementation was wrong: **two parts are accepted**, and only the part count
// outside two-or-three is refused. Every row below is now a live measurement.
func TestTheAssertionPredicateIsStructural(t *testing.T) {
	b := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	header := b(`{"alg":"RS256","typ":"JWT"}`)
	payload := b(`{"iss":"https://issuer.example.com","sub":"s"}`)

	for _, tc := range []struct {
		name     string
		raw      string
		accepted bool
	}{
		{"one part", payload, false},
		// The row a "exactly three parts" check gets wrong, and the row the
		// first version of this test could not see.
		{"two parts", header + "." + payload, true},
		{"three parts", header + "." + payload + ".sig", true},
		{"three parts, an empty signature", header + "." + payload + ".", true},
		{"four parts", header + "." + payload + ".sig.extra", false},
		{"five parts", header + "." + payload + ".a.b.c", false},
		{"an empty header", "." + payload, false},
		{"an empty payload", header + ".", false},
		{"a payload that is not base64url", header + ".!!!!", false},
		{"a payload that is a JSON array", header + "." + b(`[1,2]`), false},
		{"a.b.c", "a.b.c", false},
		{"two parts, neither JSON", "aGVsbG8.d29ybGQ", false},
		{"the empty string", "", false},
		{"no dots at all", "not-a-jwt", false},
	} {
		if _, ok := assertionClaims(tc.raw); ok != tc.accepted {
			t.Errorf("%s: want accepted=%v, got %v", tc.name, tc.accepted, ok)
		}
	}

	// An expired assertion still parses: expiry is not checked in front of the
	// identity provider lookup, measured.
	expired := assertion(`{"iss":"https://issuer.example.com","sub":"s","exp":1}`)
	claims, ok := assertionClaims(expired)
	if !ok || claims.Iss != "https://issuer.example.com" {
		t.Errorf("an expired assertion must still parse, got ok=%v iss=%q", ok, claims.Iss)
	}
}

// TestTheTwoNewGrantsAreDispatched proves the grant types reach their handlers
// rather than the endpoint's "Unsupported grant_type", which is what an
// unlisted grant type answers.
func TestTheTwoNewGrantsAreDispatched(t *testing.T) {
	h, _, _ := grantServer(t)
	for _, grant := range []string{grantTokenExchange, grantJWTBearer} {
		w := postForm(t, h, tokenPath, url.Values{
			"grant_type": {grant}, "client_id": {"jb-off"}, "client_secret": {"s3cret"},
		})
		if strings.Contains(w.Body.String(), "Unsupported grant_type") {
			t.Errorf("%s is not dispatched: %s", grant, w.Body)
		}
	}
}
