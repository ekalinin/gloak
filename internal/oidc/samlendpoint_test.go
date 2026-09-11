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
//   - **the rung above the last golden.** A request that passes every check is
//     answered by Keycloak with a login page, which carries a per-request tab_id
//     and therefore cannot be a golden (F113). Gloak answers the protocol
//     dispatcher's 404 there. Without a test, a handler that refused **every**
//     assertion consumer URL would satisfy every case in the chapter - all of
//     which are rejections - which is the exact shape AGENTS.md names as a set
//     of assertions an incorrect implementation satisfies entirely.
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
// cannot be.
//
// Every SAML case in the catalogue is a rejection, so a handler that answered
// `Invalid redirect uri` to **every** request would pass all of them. The
// request below passes every rung - an unsigned client that requires no
// signature, no Destination, and an assertion consumer URL the client's
// redirectUris cover - and Keycloak answers it 200 with the login page.
//
// Gloak has no assertion builder, so what it must not do is send one of the
// ladder's sentences. It answers the protocol dispatcher's 404 instead, which
// is what it answered before the ladder existed: the divergence stays on the one
// behaviour that is not built.
func TestSAMLEndpointDoesNotRefuseARequestItCannotServe(t *testing.T) {
	h, _, realm := newHandler(t)
	samlProbeClient(t, h, realm, &model.Client{
		ClientID: "sp", Enabled: true, RedirectURIs: []string{"http://localhost:9999/*"},
		Attributes: map[string]string{"saml.client.signature": "false"},
	})

	message := samlProbeRequest("AuthnRequest", "sp", "", "http://localhost:9999/acs")
	status, instruction := samlAnswer(t, samlGet(t, h,
		url.Values{"SAMLRequest": {samlDeflate(t, message)}}.Encode()))

	if instruction != "" {
		t.Fatalf("a request that passes every rung was refused with %q", instruction)
	}
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want the dispatcher's 404", status)
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
