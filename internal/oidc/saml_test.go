package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/keys"
)

// descriptorKeys is a realm key set for the builder to render. Generate mints a
// fresh RSA key and a self-signed certificate for it, which is what a realm
// holds, so nothing here is a stub.
func descriptorKeys(t *testing.T) *keys.RealmKeys {
	t.Helper()
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
	return k
}

// TestEncodingXMLCannotEmitTheDescriptor is the measurement AGENTS.md's rule
// about dependencies demands before a hand-written emitter is allowed to exist,
// applied to the standard library rather than to a module: prove with bytes
// that the obvious tool cannot do the job.
//
// It is the argument internal/httpx/yaml.go makes for SnakeYAML, one format
// across. The claim is not that `encoding/xml` is bad; it is that the two
// spellings the descriptor depends on are not reachable through it.
//
// Two failures, both on the same marshalled output:
//
//   - **the prefix.** Keycloak binds `md:` to the metadata namespace on the
//     root and writes `<md:IDPSSODescriptor>` and `<md:NameIDFormat>`.
//     `encoding/xml` has no way to say "use this prefix": it re-declares the
//     namespace as a default `xmlns` on each element that names one, so the
//     same tree comes out `<IDPSSODescriptor xmlns="...">`. Every element in
//     the document is affected.
//   - **the double declaration.** The root carries `xmlns` and `xmlns:md`
//     bound to one URI, and the default one is used by nothing. There is no
//     struct tag that produces a namespace declaration nothing uses.
//
// If a future Go release makes either reachable, this test fails and the
// emitter can go. That is the point of writing the refutation down as a test
// rather than as a paragraph.
func TestEncodingXMLCannotEmitTheDescriptor(t *testing.T) {
	type idpDescriptor struct {
		XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
		WantSigned bool     `xml:"WantAuthnRequestsSigned,attr"`
		Formats    []string `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	}
	type entityDescriptor struct {
		XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		EntityID string   `xml:"entityID,attr"`
		IDP      idpDescriptor
	}

	out, err := xml.Marshal(entityDescriptor{
		EntityID: "http://localhost:8080/realms/master",
		IDP: idpDescriptor{
			WantSigned: true,
			Formats:    nameIDFormats[:1],
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)

	if strings.Contains(got, "<md:IDPSSODescriptor") {
		t.Errorf("encoding/xml emitted a prefixed element, so the emitter in saml.go "+
			"can be replaced by it: %s", got)
	}
	if strings.Contains(got, `xmlns:md="`+samlMetadataNS+`"`) {
		t.Errorf("encoding/xml declared the md prefix, so the emitter in saml.go "+
			"can be replaced by it: %s", got)
	}
	// The positive half: it really does re-declare the namespace inline, which
	// is the byte-level difference, not merely a missing feature.
	if !strings.Contains(got, `<IDPSSODescriptor xmlns="`+samlMetadataNS+`"`) {
		t.Fatalf("encoding/xml no longer re-declares the namespace inline; "+
			"re-measure this refutation rather than trusting it: %s", got)
	}
}

// TestDescriptorCarriesTheLayoutRulesThatLookWrong names the six spellings a
// reader would tidy, so that a failure says which rule broke rather than
// dumping 3422 bytes.
//
// **The golden is the bytewise contract and this test is not.** It is seven
// substring checks and four structural ones, so it pins the presence of each
// rule and not the document - and the gap is real rather than theoretical:
// making the two binding lists identical leaves every assertion here passing,
// because nothing below mentions the sign-on list's order. What catches that is
// TestTheTwoBindingListsDisagree beside it and
// TestConformance/saml/descriptor/master above both, which compares every byte
// outside the two masked element texts.
//
// The name said "IsBytewise" until a review's mutation showed it was not. In a
// repository whose recurring failure is a sentence that reads as coverage, a
// test name promising a byte comparison it does not make is the same failure
// one layer down - and the comment on the sibling test already said so, calling
// this shape "no assertion over membership, and no count". Only the name
// disagreed.
func TestDescriptorCarriesTheLayoutRulesThatLookWrong(t *testing.T) {
	k := descriptorKeys(t)
	got := string(samlDescriptor("http://localhost:8080/realms/master", k))

	for _, want := range []string{
		// Two prefixes for one namespace on the root, the default used by
		// nothing.
		`<md:EntityDescriptor xmlns="` + samlMetadataNS + `" xmlns:md="` + samlMetadataNS + `"`,
		// The assertion namespace is declared and no element is in it.
		` xmlns:saml="` + samlAssertionNS + `"`,
		` entityID="http://localhost:8080/realms/master">`,
		`<md:IDPSSODescriptor WantAuthnRequestsSigned="true"`,
		`<ds:KeyName>` + k.RSAKeyID + `</ds:KeyName>`,
		`<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(k.CertificateDER()) + `</ds:X509Certificate>`,
		// The one service carrying an index, and the one Location that is not
		// the bare endpoint.
		`Location="http://localhost:8080/realms/master/protocol/saml/resolve" index="0">` +
			`</md:ArtifactResolutionService>`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor is missing %q", want)
		}
	}

	// No prologue and no trailing newline. Both were measured; both are the
	// kind of thing a builder grows by accident.
	if strings.HasPrefix(got, "<?xml") {
		t.Error("descriptor carries an XML declaration; Keycloak sends none")
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("descriptor ends in a newline; Keycloak sends none")
	}
	// Empty elements are spelled long, never self-closed.
	if strings.Contains(got, "/>") {
		t.Error("descriptor self-closes an element; Keycloak spells every one <md:X></md:X>")
	}
}

// TestTheCertificateIsStandardBase64OfTheDER closes the one hole the conformance
// golden cannot see.
//
// `saml/descriptor/master` masks <ds:X509Certificate>, because the certificate is
// minted with the database - so **the golden asserts that the element is there
// and says nothing about what is in it**. Switch the emitter to base64url, or to
// PEM with its armour, or to the encryption key's certificate instead of the
// signing one, and the golden still matches. That is the honest cost of the mask
// and this is where it is paid back.
//
// The check does not repeat the emitter's expression, which is what makes it a
// second opinion rather than a copy: it decodes the element's text with the
// standard alphabet and requires the bytes to be the realm's signing DER. A
// base64url emitter fails at the decode on any key whose DER produces a `+` or a
// `/`, and at the comparison on the rest.
func TestTheCertificateIsStandardBase64OfTheDER(t *testing.T) {
	k := descriptorKeys(t)
	got := string(samlDescriptor("http://localhost:8080/realms/master", k))

	const open, shut = "<ds:X509Certificate>", "</ds:X509Certificate>"
	i := strings.Index(got, open)
	j := strings.Index(got, shut)
	if i < 0 || j < i {
		t.Fatal("the descriptor carries no X509Certificate element")
	}
	text := got[i+len(open) : j]

	der, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		t.Fatalf("the certificate is not standard base64: %v", err)
	}
	if !bytes.Equal(der, k.CertificateDER()) {
		t.Fatalf("the certificate is %d bytes and the realm's signing DER is %d",
			len(der), len(k.CertificateDER()))
	}
	// No PEM armour and no line breaks: Keycloak sends one unbroken run.
	if strings.ContainsAny(text, "\n\r -") {
		t.Errorf("the certificate carries whitespace or PEM armour: %.40q", text)
	}

	// The same for the key id, which is masked for the same reason and is the
	// JWKS's kid rather than anything computed here.
	const kOpen, kShut = "<ds:KeyName>", "</ds:KeyName>"
	a := strings.Index(got, kOpen)
	b := strings.Index(got, kShut)
	if a < 0 || b < a {
		t.Fatal("the descriptor carries no KeyName element")
	}
	if name := got[a+len(kOpen) : b]; name != k.RSAKeyID {
		t.Errorf("KeyName is %q, want the realm's RSA kid %q", name, k.RSAKeyID)
	}
}

// TestTheTwoBindingListsDisagree is the assertion the descriptor's own bytes
// invite somebody to remove.
//
// SingleLogoutService is POST, Redirect, Artifact, SOAP and SingleSignOnService
// is POST, Redirect, SOAP, Artifact. The two lists hold the same four URIs and
// differ only in the last two, so a builder that shares one list is right on
// three of four entries in both places and wrong on two - which no assertion
// over membership, and no count, would catch.
func TestTheTwoBindingListsDisagree(t *testing.T) {
	if len(singleLogoutBindings) != len(singleSignOnBindings) {
		t.Fatal("the two binding lists no longer hold the same number of entries")
	}
	same := true
	for i := range singleLogoutBindings {
		if singleLogoutBindings[i] != singleSignOnBindings[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("the two binding lists are now identical, so one of them is wrong: " +
			"logout is POST, Redirect, Artifact, SOAP and sign-on is POST, Redirect, SOAP, Artifact")
	}

	// And the disagreement is where it was measured, in the last two entries.
	got := samlDescriptor("http://localhost:8080/realms/master", descriptorKeys(t))
	slo := strings.Index(string(got), "<md:SingleLogoutService")
	sso := strings.Index(string(got), "<md:SingleSignOnService")
	if slo < 0 || sso < 0 || slo > sso {
		t.Fatal("the logout bindings no longer come before the sign-on ones")
	}
	// The NameIDFormats sit between the two lists, which is the ordering a
	// reader would not guess and a grouped builder would lose.
	formats := strings.Index(string(got), "<md:NameIDFormat>")
	if formats < slo || formats > sso {
		t.Error("the NameIDFormats are no longer between the two service lists")
	}
}
