package oidc

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ekalinin/gloak/internal/model"
)

// The SAML ladder's unit tests.
//
// Most of what this endpoint does is pinned by goldens, which is where a
// measured contract belongs. Three things are not, and they are what this file
// is for:
//
//   - **the rung the chapter's goldens could not reach until 2026-09-18.** A
//     request that passes every check is answered with the login page, and the
//     page carries a per-request tab_id, a session_code and a session hash.
//     saml/endpoint/login-page is a golden now - the three mask frames reach all
//     three values - but the guard below is kept and sharpened rather than
//     deleted: it is the one assertion that fails first if the ladder ever
//     starts refusing what it should serve, and it does not depend on the
//     recorder. Without it, a handler that refused **every** assertion consumer
//     URL would satisfy every rejection in the chapter, which is the exact shape
//     AGENTS.md names as a set of assertions an incorrect implementation
//     satisfies entirely.
//   - **the two header sets and the three client_data shapes.** One golden sees
//     one side of each, so the pairs are held here where both sides are in one
//     assertion.
//   - **the ninth rung's refusal.** finishFlow must not mint an authorization
//     code for a SAML tab, and no golden can send a request that gets that far.
//   - **the signature verifier against a key generated here**, so that "it
//     verifies" is checked against a second key and not only against the one
//     pinned literal the catalogue carries.
//   - **the parser's refusals**, where one sentence - `Invalid Request` - is the
//     answer to eight different malformed inputs and a golden cannot say which
//     of them a handler stopped reading at.

// samlProbeRequest builds an AuthnRequest the way a service provider would.
func samlProbeRequest(kind, issuer, destination, acs string) string {
	dest, consumer := "", ""
	if destination != "" {
		dest = ` Destination="` + destination + `"`
	}
	if acs != "" {
		consumer = ` AssertionConsumerServiceURL="` + acs + `"`
	}
	return `<samlp:` + kind + ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
		` ID="ID_gloak_test" Version="2.0" IssueInstant="2026-09-11T12:00:00Z"` +
		dest + consumer + `><saml:Issuer>` + issuer + `</saml:Issuer></samlp:` + kind + `>`
}

// samlDeflate is the HTTP-Redirect binding's encoding: raw DEFLATE, base64.
func samlDeflate(t *testing.T, doc string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write([]byte(doc)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// samlProbeClient stores a SAML client and hands it back.
func samlProbeClient(t *testing.T, h *handler, realm *model.Realm, c *model.Client) *model.Client {
	t.Helper()
	c.RealmID = realm.ID
	if c.ID == "" {
		sum := sha256.Sum256([]byte(c.ClientID))
		hexID := hex.EncodeToString(sum[:16])
		c.ID = hexID[0:8] + "-" + hexID[8:12] + "-4" + hexID[13:16] + "-8" +
			hexID[17:20] + "-" + hexID[20:32]
	}
	if c.Protocol == "" {
		c.Protocol = protocolSAML
	}
	if err := h.store.Clients().Create(context.Background(), c); err != nil {
		t.Fatalf("create client %q: %v", c.ClientID, err)
	}
	return c
}

// samlGet sends a redirect-binding request and returns the recorder.
func samlGet(t *testing.T, h *handler, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/realms/master/protocol/saml?"+rawQuery, nil)
	req.SetPathValue("realm", "master")
	w := httptest.NewRecorder()
	h.samlEndpoint(w, req)
	return w
}

var samlInstruction = regexp.MustCompile(`<p class="instruction">(.*?)</p>`)

// samlAnswer is the one thing a rejection has that another does not.
func samlAnswer(t *testing.T, w *httptest.ResponseRecorder) (int, string) {
	t.Helper()
	m := samlInstruction.FindStringSubmatch(w.Body.String())
	if m == nil {
		return w.Code, ""
	}
	return w.Code, m[1]
}

// TestSAMLEndpointDoesNotRefuseARequestItCannotServe is the test the catalogue
// could not be until 2026-09-18, and is still the one that fails first.
//
// Every SAML case in the catalogue was a rejection, so a handler that answered
// `Invalid redirect uri` to **every** request would pass all of them. The
// request below passes every rung - an unsigned client that requires no
// signature, no Destination, and an assertion consumer URL the client's
// redirectUris cover - and Keycloak answers it 200 with the login page.
//
// **It now answers 200 with the login page**, where it answered the protocol
// dispatcher's 404 from 2026-09-11 until this cut. The assertion kept below is
// the one that was always the point: whatever this endpoint answers here, it
// must not be one of the ladder's sentences.
func TestSAMLEndpointDoesNotRefuseARequestItCannotServe(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{"saml.client.signature": "false"},
	})

	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	w := samlGet(t, h, url.Values{"SAMLRequest": {samlDeflate(t, message)}}.Encode())
	status, instruction := samlAnswer(t, w)

	if instruction != "" {
		t.Fatalf("a request that passes every rung was refused with %q", instruction)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want the login page's 200", status)
	}
	if !strings.Contains(w.Body.String(), `id="kc-form-login"`) {
		t.Fatalf("the answer is a 200 carrying no login form:\n%s", w.Body.String())
	}
}

// TestSAMLLoginPageSendsNoneOfTheSixAndTheIdPInitiatedOneSendsThemAll is the
// header split, held where a golden can see only one side of it at a time.
//
// Measured 2026-09-18: `/realms/{realm}/protocol/saml`'s login page carries a
// Cache-Control, a Content-Language and a Content-Type and nothing else; the
// IdP-initiated route one path segment down answers the same body with all five
// security headers and a Content-Security-Policy. Until this cut the exception
// was measured on six 400 pages alone, so a reader could take it for a property
// of that template rather than of the route.
func TestSAMLLoginPageSendsNoneOfTheSixAndTheIdPInitiatedOneSendsThemAll(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{
			"saml.client.signature":            "false",
			"saml.force.post.binding":          "true",
			"saml_idp_initiated_sso_url_name":  "sp-sso",
			"saml_assertion_consumer_url_post": "http://localhost:9999/acs",
		},
	})
	six := []string{
		"Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
	}

	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	endpoint := samlGet(t, h, url.Values{"SAMLRequest": {samlDeflate(t, message)}}.Encode())
	if endpoint.Code != http.StatusOK {
		t.Fatalf("the endpoint's login page is %d, want 200", endpoint.Code)
	}
	for _, name := range six {
		if got := endpoint.Header().Get(name); got != "" {
			t.Errorf("the endpoint's login page sends %s = %q and must send none of the six", name, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/realms/master/protocol/saml/clients/sp-sso", nil)
	req.SetPathValue("realm", "master")
	req.SetPathValue("name", "sp-sso")
	idp := httptest.NewRecorder()
	h.samlIdPInitiated(idp, req)
	if idp.Code != http.StatusOK {
		t.Fatalf("the IdP-initiated login page is %d, want 200", idp.Code)
	}
	for _, name := range six {
		if idp.Header().Get(name) == "" {
			t.Errorf("the IdP-initiated login page omits %s and must send all six", name)
		}
	}
}

// TestSAMLLoginPageCarriesTheMeasuredClientData holds the three shapes
// client_data has, which is the whole of what the authentication session a SAML
// request opens makes observable.
//
// Measured 2026-09-18, base64url of:
//
//	/protocol/saml, RelayState=gloak-relay  {"ru":<ACS>,"rt":<the ID>,"rm":"post","st":"gloak-relay"}
//	the same, RelayState= or absent         {"ru":<ACS>,"rt":<the ID>,"rm":"post"}
//	.../clients/{name}                      {"ru":<ACS>,"rm":"post"}
//
// **`rt` is a response type on OIDC and a request id here**, and on the
// IdP-initiated route it is absent rather than empty - there is no request to
// have one. **An empty RelayState is absent** where /auth's `state=` is present
// and empty, which is the third time these two endpoints have disagreed about
// emptiness in one parameter.
func TestSAMLLoginPageCarriesTheMeasuredClientData(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{
			"saml.client.signature":            "false",
			"saml.force.post.binding":          "true",
			"saml_idp_initiated_sso_url_name":  "sp-sso",
			"saml_assertion_consumer_url_post": "http://localhost:9999/acs-post",
		},
	})
	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	deflated := samlDeflate(t, message)

	for _, tc := range []struct {
		name  string
		query url.Values
		want  string
	}{
		{"a relay state", url.Values{"SAMLRequest": {deflated}, "RelayState": {"gloak-relay"}},
			`{"ru":"http://localhost:9999/acs","rt":"ID_gloak_test","rm":"post","st":"gloak-relay"}`},
		{"an empty relay state", url.Values{"SAMLRequest": {deflated}, "RelayState": {""}},
			`{"ru":"http://localhost:9999/acs","rt":"ID_gloak_test","rm":"post"}`},
		{"no relay state", url.Values{"SAMLRequest": {deflated}},
			`{"ru":"http://localhost:9999/acs","rt":"ID_gloak_test","rm":"post"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := samlClientDataOf(t, samlGet(t, h, tc.query.Encode()).Body.String())
			if got != tc.want {
				t.Errorf("client_data = %s\n           want %s", got, tc.want)
			}
		})
	}

	t.Run("the IdP-initiated route carries no rt", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/realms/master/protocol/saml/clients/sp-sso", nil)
		req.SetPathValue("realm", "master")
		req.SetPathValue("name", "sp-sso")
		w := httptest.NewRecorder()
		h.samlIdPInitiated(w, req)
		const want = `{"ru":"http://localhost:9999/acs-post","rm":"post"}`
		if got := samlClientDataOf(t, w.Body.String()); got != want {
			t.Errorf("client_data = %s\n           want %s", got, want)
		}
	})
}

// TestSAMLPostBindingReadsItsRelayStateFromTheForm is the first of the two
// tests this cut's mutation pass asked for, and it exists because **no golden
// can see inside saml/endpoint/post-binding-login-redirect's Location**.
//
// That header carries a freshly minted tab_id, so the case masks it whole, and
// with it go the client_id, the tab_id and the client_data. A mutation reading
// the POST binding's RelayState out of the **query** instead of the form
// therefore survived the entire tree: the 302's status, its Cache-Control and
// all six absent headers are unchanged, and the one thing that moved was inside
// the masked value.
//
// The request below sends **both** spellings with different values, which is
// sharper than sending only the form's: it fails for a handler reading the
// query, and it fails for one calling r.FormValue, which merges the two and
// would take whichever net/http happens to prefer. readSAMLRequest takes the
// same care with SAMLRequest for the same reason.
func TestSAMLPostBindingReadsItsRelayStateFromTheForm(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{
			"saml.client.signature":   "false",
			"saml.force.post.binding": "true",
		},
	})
	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(message))},
		"RelayState":  {"from-the-form"},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/realms/master/protocol/saml?RelayState=from-the-query",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("realm", "master")
	w := httptest.NewRecorder()
	h.samlEndpoint(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	const want = `{"ru":"http://localhost:9999/acs","rt":"ID_gloak_test","rm":"post","st":"from-the-form"}`
	if got := samlClientDataOf(t, w.Header().Get("Location")); got != want {
		t.Errorf("client_data = %s\n           want %s", got, want)
	}
}

// TestSAMLLoginSurvivesARestart is the second, and it covers the one path in
// this flow that rebuilds a tab from something other than the request.
//
// KC_RESTART is what a browser holds when its authentication session has gone,
// and writeRestartRedirect builds a **new** tab out of the record it names. A
// mutation dropping the two SAML fields from that record survived the whole
// tree: every golden here is a first request, so nothing in the catalogue ever
// restarts a SAML login, and the rebuilt tab silently became an OIDC one whose
// client_data says `"rt":"code"` for a login that never asked for a code.
//
// The assertion is the restart 302's own client_data, read out of the header
// rather than off the record, for samlClientDataOf's reason.
func TestSAMLLoginSurvivesARestart(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{
			"saml.client.signature":   "false",
			"saml.force.post.binding": "true",
		},
	})
	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	first := samlGet(t, h, url.Values{
		"SAMLRequest": {samlDeflate(t, message)},
		"RelayState":  {"gloak-relay"},
	}.Encode())
	if first.Code != http.StatusOK {
		t.Fatalf("the login page is %d, want 200", first.Code)
	}
	restart := ""
	for _, raw := range first.Header().Values("Set-Cookie") {
		if name, value, ok := strings.Cut(raw, "="); ok && name == restartCookie {
			restart, _, _ = strings.Cut(value, ";")
		}
	}
	if restart == "" {
		t.Fatalf("the login page set no %s cookie", restartCookie)
	}

	// No AUTH_SESSION_ID: the browser's authentication session is gone and the
	// restart cookie is all it has, which is the branch writeUnusableSession
	// takes to writeRestartRedirect.
	req := httptest.NewRequest(http.MethodGet,
		"/realms/master/login-actions/authenticate?client_id=sp&tab_id=gone&session_code=gone", nil)
	req.Header.Set("Cookie", restartCookie+"="+restart)
	req.SetPathValue("realm", "master")
	w := httptest.NewRecorder()
	h.loginActions(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("the restart is %d, want 302", w.Code)
	}
	const want = `{"ru":"http://localhost:9999/acs","rt":"ID_gloak_test","rm":"post","st":"gloak-relay"}`
	if got := samlClientDataOf(t, w.Header().Get("Location")); got != want {
		t.Errorf("the restarted tab's client_data = %s\n                              want %s", got, want)
	}
}

var samlClientDataPattern = regexp.MustCompile(`client_data=([A-Za-z0-9_-]+)`)

// samlClientDataOf decodes the first client_data out of a page.
//
// It reads the page rather than calling authTab.clientData, which is the rule
// this project has earned twice: a guard written from the value the thing under
// test was built from cannot catch that thing being built wrong.
func samlClientDataOf(t *testing.T, body string) string {
	t.Helper()
	m := samlClientDataPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no client_data in the body:\n%s", body)
	}
	raw, err := base64.RawURLEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("client_data %q does not decode: %v", m[1], err)
	}
	return string(raw)
}

// TestSAMLResponseBindingIsTheMeasuredGrid holds client_data's `rm`, which is
// the one thing about the SAML session that F228 asked to be measured before
// anything was built on it.
//
// Measured 2026-09-18 on one container, eight cells of a 2x4:
//
//	saml.force.post.binding "true"   ProtocolBinding absent / any of three   post
//	otherwise                        absent                                   get
//	otherwise                        HTTP-Redirect                            get
//	otherwise                        HTTP-POST                                post
//	otherwise                        HTTP-Artifact                            get
//
// **HTTP-Artifact is the cell a reader gets wrong**: the descriptor advertises
// an artifact binding, the request names it, and the answer is the default
// rather than a third value. And the attribute's own comparison is the exact
// string "true", case-sensitively, swept across the same nine values
// saml.client.signature was.
func TestSAMLResponseBindingIsTheMeasuredGrid(t *testing.T) {
	const (
		redirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
		artifactBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	)
	for _, tc := range []struct {
		force   string
		binding string
		want    string
	}{
		{"true", "", "post"},
		{"true", redirectBinding, "post"},
		{"true", samlHTTPPOSTBinding, "post"},
		{"true", artifactBinding, "post"},
		{"false", "", "get"},
		{"false", redirectBinding, "get"},
		{"false", samlHTTPPOSTBinding, "post"},
		{"false", artifactBinding, "get"},
		// The nine spellings of the attribute, all but one of them off.
		{"TRUE", "", "get"},
		{"True", "", "get"},
		{" true", "", "get"},
		{"", "", "get"},
		{"0", "", "get"},
		{"no", "", "get"},
	} {
		client := &model.Client{Attributes: map[string]string{"saml.force.post.binding": tc.force}}
		if got := samlResponseBinding(client, tc.binding); got != tc.want {
			t.Errorf("force=%q binding=%q -> %q, want %q", tc.force, tc.binding, got, tc.want)
		}
	}
	// The attribute absent entirely, which is not the same input as "".
	if got := samlResponseBinding(&model.Client{}, ""); got != "get" {
		t.Errorf("the attribute absent -> %q, want %q", got, "get")
	}
}

// TestSAMLLoginDoesNotEndInAnAuthorizationCode is the ninth rung's guard, and
// it is the one assertion in this file that is about a response Gloak refuses
// to invent.
//
// A SAML tab carries a redirect URI and a state, so every line of the OIDC
// ending runs on it to completion: completeLogin would mint an authorization
// code and send a SAML service provider `?code=…&state=…` at its assertion
// consumer URL. Nothing measures that, no SAML client would understand it, and
// it is a worse divergence than answering nothing. See completeSAMLLogin.
func TestSAMLLoginDoesNotEndInAnAuthorizationCode(t *testing.T) {
	h, _, realm := newHandler(t)
	_ = realm
	w := httptest.NewRecorder()
	if err := h.finishFlow(w, httptest.NewRequest(http.MethodGet, "/", nil), nil, nil, nil,
		&authTab{SAMLBinding: "post", RedirectURI: "http://localhost:9999/acs", State: "r"},
		nil, nil); err != nil {
		t.Fatalf("finishFlow: %v", err)
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the dispatcher's 404", w.Code)
	}
	if strings.Contains(w.Header().Get("Location"), "code=") {
		t.Fatalf("a SAML login ended in an authorization code: %q", w.Header().Get("Location"))
	}
}

// TestSAMLEndpointWalksTheLadderInTheMeasuredOrder pins the two rungs the first
// cut's five-deep ladder had no room for, and their **position**.
//
// Both inputs name an `openid-connect` client, so a ladder ordered client,
// protocol, signature answers `Wrong client protocol.` to both. Measured on a
// live 26.7.1 on 2026-09-11: it answers neither.
func TestSAMLEndpointWalksTheLadderInTheMeasuredOrder(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "off", Enabled: false, Protocol: "openid-connect",
	})
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "bearer", Enabled: true, Protocol: "openid-connect", BearerOnly: true,
	})
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "oidc", Enabled: true, Protocol: "openid-connect",
	})

	for _, tc := range []struct{ issuer, want string }{
		{"off", pageLoginRequesterNotEnabled},
		{"bearer", pageBearerOnly},
		{"oidc", pageWrongClientProtocol},
	} {
		message := samlProbeRequest("AuthnRequest", tc.issuer, "", "")
		_, instruction := samlAnswer(t, samlGet(t, h,
			url.Values{"SAMLRequest": {samlDeflate(t, message)}}.Encode()))
		if instruction != tc.want {
			t.Errorf("issuer %q answered %q, want %q", tc.issuer, instruction, tc.want)
		}
	}
}

// TestSAMLDestinationIsRequiredOnlyWhenTheRequestIsSigned is the measurement
// that made this whole chapter reachable from a catalogue, written down as a
// test because no single golden can hold both halves of it.
//
// Measured 2026-09-11, and it inverts what the first cut recorded: an
// AuthnRequest with **no Destination** reaches the login page, and only a
// request carrying a `Signature` parameter is required to have one.
func TestSAMLDestinationIsRequiredOnlyWhenTheRequestIsSigned(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{"saml.client.signature": "false"},
	})
	const acs = "http://localhost:9999/acs"

	unsigned := url.Values{"SAMLRequest": {samlDeflate(t,
		samlProbeRequest("AuthnRequest", "sp", "", acs))}}.Encode()
	if status, instruction := samlAnswer(t, samlGet(t, h, unsigned)); instruction != "" {
		t.Errorf("unsigned with no Destination: %d %q, want no refusal", status, instruction)
	}

	// The same message with a Signature parameter that is never verified,
	// because this client does not require one. Measured: the Destination is
	// demanded anyway, so the parameter decides and the flag does not.
	withSignature := unsigned + "&SigAlg=" + url.QueryEscape(samlSHA256SigAlg) +
		"&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("junk")))
	if _, instruction := samlAnswer(t, samlGet(t, h, withSignature)); instruction != pageInvalidRequest {
		t.Errorf("signed with no Destination: %q, want %q", instruction, pageInvalidRequest)
	}

	// And a Destination naming this server exactly is accepted with the
	// signature parameter present.
	signedWithDestination := url.Values{"SAMLRequest": {samlDeflate(t,
		samlProbeRequest("AuthnRequest", "sp",
			"http://localhost:8080/realms/master/protocol/saml", acs))}}.Encode() +
		"&SigAlg=" + url.QueryEscape(samlSHA256SigAlg) +
		"&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("junk")))
	if status, instruction := samlAnswer(t, samlGet(t, h, signedWithDestination)); instruction != "" {
		t.Errorf("signed with the right Destination: %d %q, want no refusal", status, instruction)
	}
}

const samlSHA256SigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// TestRedirectSignatureVerifies is the verifier's positive control against a key
// this test generates, rather than against the one literal the catalogue pins.
//
// A verifier that refuses everything is the failure this whole file guards, and
// it passes every rejection case there is. **Disabling verifyRedirectSignature's
// final comparison is caught here and by
// saml/endpoint/redirect-binding-signature-accepted, and by nothing else.**
func TestRedirectSignatureVerifies(t *testing.T) {
	client, key := samlSigningClient(t)
	message := samlDeflate(t, samlProbeRequest("AuthnRequest", "sp", "", ""))
	signedInput := "SAMLRequest=" + url.QueryEscape(message) +
		"&SigAlg=" + url.QueryEscape(samlSHA256SigAlg)
	query := signedInput + "&Signature=" + url.QueryEscape(samlSign(t, key, signedInput))

	if !verifyRedirectSignature(client, query) {
		t.Fatal("a correctly signed request was refused")
	}

	// The same signature over a different message, which is the half a
	// "signature present" check would pass.
	other := samlDeflate(t, samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:1/x"))
	tampered := "SAMLRequest=" + url.QueryEscape(other) +
		"&SigAlg=" + url.QueryEscape(samlSHA256SigAlg) +
		"&Signature=" + url.QueryEscape(samlSign(t, key, signedInput))
	if verifyRedirectSignature(client, tampered) {
		t.Fatal("a signature over a different message was accepted")
	}

	// **The escaping is not normalised, in both directions.** The signed bytes
	// are the query as sent, so a RelayState spelled with `%20` verifies against
	// a signature made over `%20` and the same query with `+` does not - measured
	// on a live 26.7.1 on 2026-09-11, and it is the input a mutation pass needed:
	// a verifier that decoded the parameters and re-encoded them with
	// url.QueryEscape would write `+` for both and get the first wrong.
	//
	// The accepting half is a golden as well -
	// saml/endpoint/redirect-binding-signature-over-a-relay-state - and the
	// refusing half is only here, because its answer is byte-identical to the
	// tampered case's.
	escaped := "SAMLRequest=" + url.QueryEscape(message) +
		"&RelayState=gloak%20relay%20state" +
		"&SigAlg=" + url.QueryEscape(samlSHA256SigAlg)
	if !verifyRedirectSignature(client, escaped+"&Signature="+
		url.QueryEscape(samlSign(t, key, escaped))) {
		t.Error("a RelayState spelled with %20 and signed over %20 was refused")
	}
	if verifyRedirectSignature(client,
		strings.ReplaceAll(escaped, "%20", "+")+"&Signature="+
			url.QueryEscape(samlSign(t, key, escaped))) {
		t.Error("a RelayState respelled with + was accepted against the %20 signature")
	}
}

// TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs pins the set, which is
// **three and not the four SAML defines**.
//
// Measured 2026-09-11 by signing one message with each digest and sending it to
// a live 26.7.1: sha1, sha256 and sha512 are accepted and **rsa-sha384 is
// refused**, with a correct URI, a correct digest and the same certificate the
// sha256 request verified against. Writing the table from the specification is
// what gives an implementation that accepts a signature Keycloak refuses.
func TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs(t *testing.T) {
	client, key := samlSigningClient(t)
	message := samlDeflate(t, samlProbeRequest("AuthnRequest", "sp", "", ""))

	for _, tc := range []struct {
		alg    string
		digest crypto.Hash
		want   bool
	}{
		{"http://www.w3.org/2000/09/xmldsig#rsa-sha1", crypto.SHA1, true},
		{samlSHA256SigAlg, crypto.SHA256, true},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", crypto.SHA512, true},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", crypto.SHA384, false},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", crypto.SHA224, false},
	} {
		signedInput := "SAMLRequest=" + url.QueryEscape(message) +
			"&SigAlg=" + url.QueryEscape(tc.alg)
		hasher := tc.digest.New()
		hasher.Write([]byte(signedInput))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, tc.digest, hasher.Sum(nil))
		if err != nil {
			t.Fatalf("sign with %v: %v", tc.digest, err)
		}
		query := signedInput + "&Signature=" +
			url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
		if got := verifyRedirectSignature(client, query); got != tc.want {
			t.Errorf("%s: verified = %v, want %v", tc.alg, got, tc.want)
		}
	}
}

// TestSigAlgHashesAndNewSigAlgHashAgree makes the two halves of the SigAlg gate
// one claim instead of two.
//
// **It exists because a mutation that added rsa-sha384 to `sigAlgHashes` alone
// survived the whole tree, and correctly so**: newSigAlgHash's switch does not
// know that digest, so it hands back nil and verifyRedirectSignature refuses the
// request anyway. The edit changed text and not behaviour, which is F208's shape
// - it passes every empty-diff guard a harness can have and then passes the
// tests, and lands in a report in the same column as a real finding.
//
// The ratchet is cheap and it is the only thing that can catch that edit: a
// digest named in the map must be one this build can hash with, and a digest
// this build can hash with must be one the map names. With both directions
// asserted, adding to either list alone fails and adding to both is a real
// mutation that TestRedirectSignatureAcceptsExactlyTheMeasuredSigAlgs kills.
func TestSigAlgHashesAndNewSigAlgHashAgree(t *testing.T) {
	named := map[crypto.Hash]bool{}
	for alg, digest := range sigAlgHashes {
		if newSigAlgHash(digest) == nil {
			t.Errorf("%s names %v and newSigAlgHash cannot build it", alg, digest)
		}
		named[digest] = true
	}
	// The other direction. Every digest newSigAlgHash answers must be one the
	// map names, or the switch is advertising a capability no SigAlg reaches.
	for _, digest := range []crypto.Hash{
		crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
	} {
		if newSigAlgHash(digest) != nil && !named[digest] {
			t.Errorf("newSigAlgHash builds %v and no SigAlg in sigAlgHashes names it", digest)
		}
	}
	if len(sigAlgHashes) != 3 {
		t.Errorf("sigAlgHashes holds %d entries; three were measured accepted, "+
			"and rsa-sha384 was measured refused", len(sigAlgHashes))
	}
}

// TestClientRequiresSignatureComparesTheExactString pins the case-sensitive
// equality.
//
// Measured 2026-09-11, one value at a time on one container: only the exact
// string "true" is on. `strconv.ParseBool` is the obvious implementation and it
// is wrong on "TRUE", which Java's own `Boolean.parseBoolean` would also read as
// true - so this is a place where copying the upstream idiom is wrong too.
func TestClientRequiresSignatureComparesTheExactString(t *testing.T) {
	for value, want := range map[string]bool{
		"true": true, "TRUE": false, "True": false, " true": false,
		"false": false, "": false, "0": false, "no": false, "1": false,
	} {
		client := &model.Client{Attributes: map[string]string{"saml.client.signature": value}}
		if got := clientRequiresSignature(client); got != want {
			t.Errorf("saml.client.signature = %q: %v, want %v", value, got, want)
		}
	}
	if clientRequiresSignature(&model.Client{}) {
		t.Error("a client with no attributes requires a signature")
	}
}

// samlSigningClient is a client whose registered certificate carries the public
// half of a key this test holds.
func samlSigningClient(t *testing.T) (*model.Client, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return &model.Client{
		ClientID: "sp", Enabled: true, Protocol: protocolSAML,
		Attributes: map[string]string{
			"saml.client.signature":     "true",
			"saml.signing.certificate":  base64.StdEncoding.EncodeToString(der),
			"saml.signature.algorithm":  "RSA_SHA256",
			"saml.server.signature":     "true",
			"saml_name_id_format":       "username",
			"saml_force_name_id_format": "false",
		},
	}, key
}

func samlSign(t *testing.T, key *rsa.PrivateKey, signedInput string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(signedInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

// TestParseSAMLMessageRefusesWhatKeycloakRefuses is the eight-input sweep behind
// one sentence.
//
// `Invalid Request` is the answer to every one of these, so no golden can say
// which check a handler stopped at, and a parser that dropped any single rule
// would still pass every case in the chapter. Every row was measured on a live
// 26.7.1 on 2026-09-11.
func TestParseSAMLMessageRefusesWhatKeycloakRefuses(t *testing.T) {
	const protocol = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
	const rest = ` ID="a" Version="2.0" IssueInstant="2026-09-11T12:00:00Z"`
	for name, doc := range map[string]string{
		"not XML at all":  `not xml`,
		"no namespace":    `<AuthnRequest` + rest + `><Issuer>sp</Issuer></AuthnRequest>`,
		"wrong namespace": `<p:AuthnRequest xmlns:p="urn:example:x"` + rest + `><Issuer>sp</Issuer></p:AuthnRequest>`,
		"lower-case root": `<samlp:authnrequest ` + protocol + rest + `><Issuer>sp</Issuer></samlp:authnrequest>`,
		"unknown root":    `<samlp:Response ` + protocol + rest + `><Issuer>sp</Issuer></samlp:Response>`,
		"no ID":           `<samlp:AuthnRequest ` + protocol + ` Version="2.0" IssueInstant="x"><Issuer>sp</Issuer></samlp:AuthnRequest>`,
		"version 1.0":     `<samlp:AuthnRequest ` + protocol + ` ID="a" Version="1.0" IssueInstant="x"><Issuer>sp</Issuer></samlp:AuthnRequest>`,
		"no IssueInstant": `<samlp:AuthnRequest ` + protocol + ` ID="a" Version="2.0"><Issuer>sp</Issuer></samlp:AuthnRequest>`,
		"no Issuer":       `<samlp:AuthnRequest ` + protocol + rest + `></samlp:AuthnRequest>`,
		"empty Issuer":    `<samlp:AuthnRequest ` + protocol + rest + `><Issuer></Issuer></samlp:AuthnRequest>`,
		"nested Issuer":   `<samlp:AuthnRequest ` + protocol + rest + `><Extensions><Issuer>sp</Issuer></Extensions></samlp:AuthnRequest>`,
	} {
		if _, ok := parseSAMLMessage([]byte(doc)); ok {
			t.Errorf("%s: parsed, want refused", name)
		}
	}
}

// TestParseSAMLMessageAcceptsWhatKeycloakAccepts is the other half, and its
// last row is the one nobody would guess.
//
// The Issuer's namespace is ignored - the assertion namespace, a default xmlns
// and no namespace at all all resolve - and **the last Issuer wins**: a message
// naming one client and then another is served from the second. That is JAXB
// overwriting a field it has already set, and an implementation reading the
// first Issuer is right on every well-formed message and wrong on that one.
func TestParseSAMLMessageAcceptsWhatKeycloakAccepts(t *testing.T) {
	const protocol = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
	const rest = ` ID="a" Version="2.0" IssueInstant="2026-09-11T12:00:00Z"`
	for name, tc := range map[string]struct{ doc, issuer string }{
		"prefixed protocol namespace": {
			`<samlp:AuthnRequest ` + protocol + rest + `><Issuer>sp</Issuer></samlp:AuthnRequest>`, "sp"},
		"default protocol namespace": {
			`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"` + rest +
				`><Issuer>sp</Issuer></AuthnRequest>`, "sp"},
		"Issuer in the assertion namespace": {
			`<samlp:AuthnRequest ` + protocol + ` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"` +
				rest + `><saml:Issuer>sp</saml:Issuer></samlp:AuthnRequest>`, "sp"},
		"the last Issuer wins": {
			`<samlp:AuthnRequest ` + protocol + rest +
				`><Issuer>first</Issuer><Issuer>second</Issuer></samlp:AuthnRequest>`, "second"},
	} {
		message, ok := parseSAMLMessage([]byte(tc.doc))
		if !ok {
			t.Errorf("%s: refused, want parsed", name)
			continue
		}
		if message.Issuer != tc.issuer {
			t.Errorf("%s: issuer = %q, want %q", name, message.Issuer, tc.issuer)
		}
	}
}

// TestSAMLAssertionConsumerURLCrossesItsTwoSources is the cell a reader would
// get wrong, and it is measured.
//
// A named AssertionConsumerServiceURL is checked against the client's
// **redirectUris**; an absent one falls back to the client's
// saml_assertion_consumer_url_post attribute and is **not** checked against
// redirectUris at all. So a client whose only ACS is that attribute, sent a
// message naming that same URL, is refused - the two halves do not compose.
func TestSAMLAssertionConsumerURLCrossesItsTwoSources(t *testing.T) {
	attributeOnly := &model.Client{
		Attributes: map[string]string{
			"saml_assertion_consumer_url_post": "http://localhost:8888/post"},
	}
	if got := samlAssertionConsumerURL(attributeOnly, nil); got != "http://localhost:8888/post" {
		t.Errorf("no message: %q, want the attribute", got)
	}
	named := &samlMessage{ACSURL: "http://localhost:8888/post"}
	if got := samlAssertionConsumerURL(attributeOnly, named); got != "" {
		t.Errorf("the attribute's own URL named in the message resolved to %q, want refused", got)
	}

	registered := &model.Client{RedirectURIs: []string{"http://localhost:9999/*"}}
	if got := samlAssertionConsumerURL(registered,
		&samlMessage{ACSURL: "http://localhost:9999/acs"}); got != "http://localhost:9999/acs" {
		t.Errorf("a registered ACS resolved to %q", got)
	}
	if got := samlAssertionConsumerURL(registered, &samlMessage{}); got != "" {
		t.Errorf("a client with no ACS attribute resolved to %q, want refused", got)
	}
}

// TestSAMLPagesSendTheirMeasuredHeaderSets pins the split between the two
// routes, which is the sharpest instance of the rule AGENTS.md records as
// having been wrong six times.
//
// The endpoint's page sends **none** of the five security headers and no
// Content-Security-Policy; the IdP-initiated route's, one path segment down,
// sends all six. Both are 400s from the same template on one container.
//
// The goldens carry this too. It is a test as well because the goldens carry it
// only for the rungs that have a case, and this asserts it of the writer.
func TestSAMLPagesSendTheirMeasuredHeaderSets(t *testing.T) {
	h, _, realm := newHandler(t)

	endpoint := samlGet(t, h, "SAMLRequest=")
	for _, header := range []string{
		"Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
	} {
		if got := endpoint.Header().Get(header); got != "" {
			t.Errorf("/protocol/saml sent %s: %q", header, got)
		}
	}
	if got := endpoint.Header().Get("Cache-Control"); got != samlPageCacheStore {
		t.Errorf("GET Cache-Control = %q, want %q", got, samlPageCacheStore)
	}

	post := httptest.NewRequest(http.MethodPost, "/realms/master/protocol/saml",
		strings.NewReader(""))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.SetPathValue("realm", "master")
	postRecorder := httptest.NewRecorder()
	h.samlEndpoint(postRecorder, post)
	if got := postRecorder.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("POST Cache-Control = %q, want no-cache", got)
	}

	idp := httptest.NewRequest(http.MethodGet, "/realms/master/protocol/saml/clients/nothing", nil)
	idp.SetPathValue("realm", "master")
	idp.SetPathValue("name", "nothing")
	idpRecorder := httptest.NewRecorder()
	h.samlIdPInitiated(idpRecorder, idp)
	for _, header := range []string{
		"Content-Security-Policy", "Referrer-Policy", "Strict-Transport-Security",
		"X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
	} {
		if idpRecorder.Header().Get(header) == "" {
			t.Errorf("/protocol/saml/clients/{name} sent no %s", header)
		}
	}
	_ = realm
}
