package oidc

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keys"
)

// The SAML IdP metadata descriptor.
//
// Every byte below was measured against a live Keycloak 26.7.1 on 2026-09-07,
// `GET /realms/master/protocol/saml/descriptor`, and the recorded contract is
// internal/conformance/testdata/golden/saml/descriptor/master.http.
//
// **The document is a pure function of the realm and its signing key.** Five
// requests to one container answered byte-identical bodies; two containers from
// one image differed in exactly two places, the <ds:KeyName> and the
// <ds:X509Certificate>, both derived from the RSA key that is minted with the
// database. It carries **no ID attribute and no timestamp**, which is what
// separates it from the two other XML bodies this server has: the identity
// provider export's `ID="ID_<uuid>"` and the artifact resolution response's
// `ID` plus `IssueInstant`, both minted per request. That is why this one can
// be a golden and those cannot.
//
// The layout is Keycloak's and several parts of it look wrong and are not:
//
//   - the root declares **two prefixes for one namespace**, a default `xmlns`
//     and `xmlns:md`, both the metadata URI, and then uses `md:` throughout.
//     The default declaration is never used by any element.
//   - it declares `xmlns:saml`, the assertion namespace, and **no element in
//     the document is in it**.
//   - every empty element is spelled `<md:X></md:X>` and never `<md:X/>`.
//   - there is no XML declaration, no `<?xml ... ?>` prologue and no trailing
//     newline.
//   - the four `SingleLogoutService` bindings come before the NameIDFormats and
//     the four `SingleSignOnService` bindings come after them, and the two
//     lists are **not** in the same order: SLO is POST, Redirect, Artifact,
//     SOAP and SSO is POST, Redirect, SOAP, Artifact. A shared binding list
//     would be right on one of them.
//
// Tidying any of those breaks the one thing this project exists to do.

// SAML binding and name identifier format URIs, in the order the descriptor
// emits them. They are two lists rather than one because the two services
// disagree about the order of SOAP and Artifact - measured, not assumed.
const (
	samlMetadataNS  = "urn:oasis:names:tc:SAML:2.0:metadata"
	samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	xmlDSigNS       = "http://www.w3.org/2000/09/xmldsig#"

	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	bindingSOAP     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// singleLogoutBindings and singleSignOnBindings are the two orders, kept apart
// on purpose. See the block above: SOAP and Artifact swap between them.
var (
	singleLogoutBindings = []string{bindingPOST, bindingRedirect, bindingArtifact, bindingSOAP}
	singleSignOnBindings = []string{bindingPOST, bindingRedirect, bindingSOAP, bindingArtifact}

	nameIDFormats = []string{
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	}
)

// samlDescriptor renders the IdP metadata for one realm.
//
// realmBase is the realm's own base URL - `<issuer>/realms/<name>` - which is
// both the entityID and the prefix of every Location in the document. Measured:
// the entityID is the realm URL with no trailing segment, the artifact
// resolution service points at `/protocol/saml/resolve`, and all eight other
// service Locations point at `/protocol/saml` itself.
func samlDescriptor(realmBase string, k *keys.RealmKeys) []byte {
	var b strings.Builder
	b.WriteString(`<md:EntityDescriptor xmlns="` + samlMetadataNS + `"`)
	b.WriteString(` xmlns:md="` + samlMetadataNS + `"`)
	b.WriteString(` xmlns:saml="` + samlAssertionNS + `"`)
	b.WriteString(` xmlns:ds="` + xmlDSigNS + `"`)
	b.WriteString(` entityID="` + realmBase + `">`)

	b.WriteString(`<md:IDPSSODescriptor WantAuthnRequestsSigned="true"`)
	b.WriteString(` protocolSupportEnumeration="` + samlProtocolNS + `">`)

	// The key block. KeyName is the realm's RSA kid, the same value the JWKS
	// publishes; X509Certificate is the DER in standard base64 with no PEM
	// armour and no line breaks, which is what the JWKS x5c entry carries too.
	b.WriteString(`<md:KeyDescriptor use="signing"><ds:KeyInfo>`)
	b.WriteString(`<ds:KeyName>` + k.RSAKeyID + `</ds:KeyName>`)
	b.WriteString(`<ds:X509Data><ds:X509Certificate>`)
	b.WriteString(base64.StdEncoding.EncodeToString(k.CertificateDER()))
	b.WriteString(`</ds:X509Certificate></ds:X509Data>`)
	b.WriteString(`</ds:KeyInfo></md:KeyDescriptor>`)

	// The one service with an index, and the one whose Location is not the
	// bare SAML endpoint.
	b.WriteString(`<md:ArtifactResolutionService Binding="` + bindingSOAP + `"`)
	b.WriteString(` Location="` + realmBase + `/protocol/saml/resolve" index="0">`)
	b.WriteString(`</md:ArtifactResolutionService>`)

	endpoint := realmBase + "/protocol/saml"
	for _, binding := range singleLogoutBindings {
		b.WriteString(`<md:SingleLogoutService Binding="` + binding + `"`)
		b.WriteString(` Location="` + endpoint + `"></md:SingleLogoutService>`)
	}
	for _, format := range nameIDFormats {
		b.WriteString(`<md:NameIDFormat>` + format + `</md:NameIDFormat>`)
	}
	for _, binding := range singleSignOnBindings {
		b.WriteString(`<md:SingleSignOnService Binding="` + binding + `"`)
		b.WriteString(` Location="` + endpoint + `"></md:SingleSignOnService>`)
	}

	b.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
	return []byte(b.String())
}

// samlDescriptorEndpoint serves GET /realms/{realm}/protocol/saml/descriptor.
//
// Cache-Control is `no-cache`, which is the certs endpoint's value and not the
// discovery document's longer one - pinned per endpoint, as AGENTS.md records.
// The realm 404 comes from resolveRealm and is the protocol side's
// `Realm does not exist`, measured on this path as on every other under
// /realms/.
func (h *handler) samlDescriptorEndpoint(w http.ResponseWriter, r *http.Request) {
	realm := h.resolveRealm(w, r)
	if realm == nil {
		return
	}
	k := h.realmKeys(w, r, realm)
	if k == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	httpx.WriteXML(w, http.StatusOK, samlDescriptor(h.issuerBase+"/realms/"+realm.Name, k))
}
