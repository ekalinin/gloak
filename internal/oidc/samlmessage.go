package oidc

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"strings"
)

// Reading a SAML message off the wire, for the two bindings
// /realms/{realm}/protocol/saml serves.
//
// Every rule below was measured against a live Keycloak 26.7.1 on 2026-09-11,
// one input at a time, by sending the message and reading which of the
// endpoint's sentences came back. The endpoint answers `Invalid Request` to
// every message it cannot read **and** to every readable message whose Issuer
// names no client, which is the reason each rule needed its own probe: the
// answer alone never says which check refused.
//
// # The two bindings differ in exactly the compression
//
//	HTTP-Redirect   SAMLRequest= base64( raw DEFLATE( xml ) )   in the query
//	HTTP-POST       SAMLRequest= base64( xml )                  in the form
//
// and each rejects the other's spelling into `Invalid Request`, measured in both
// directions. The DEFLATE is raw - RFC 1951, no zlib header - which is what
// compress/flate reads.
//
// # SAMLRequest wins over SAMLResponse
//
// Measured: a `SAMLResponse` carrying an AuthnRequest is `Invalid Request`
// whatever is in it, and a request carrying **both** parameters is served from
// the `SAMLRequest`. So this reader takes SAMLRequest alone; a lone
// SAMLResponse is a message this endpoint does not read, not a message it reads
// and refuses.
//
// # What the parser requires, each cell measured
//
//	root in the SAML protocol namespace     required - a default xmlns works,
//	                                        no namespace at all is Invalid Request,
//	                                        and so is any other namespace
//	root local name AuthnRequest            case-sensitive: `authnrequest` is refused
//	ID attribute                            required
//	Version="2.0"                           required: "1.0" is refused
//	IssueInstant                            required
//	Issuer a **direct child**               one nested inside <Extensions> is refused
//	Issuer's namespace                      ignored: the assertion namespace, a
//	                                        default xmlns and no namespace at all
//	                                        all resolve
//	two Issuers                             **the last one wins** - a message
//	                                        naming `account` then a SAML client is
//	                                        served from the SAML client
//
// The last row is the one worth keeping. It is JAXB overwriting a field it has
// already set, and an implementation reading the first Issuer is right on every
// well-formed message and wrong on that one - which is why it is a case rather
// than a sentence here.

// The SAML 2.0 namespaces this reader compares against. samlProtocolNS is
// declared in saml.go, beside the descriptor that emits it.
const samlRequestVersion = "2.0"

// samlMessageKind is the root element's local name, which is what decides
// whether the endpoint is being asked for single sign-on or single logout.
type samlMessageKind string

const (
	samlAuthnRequest  samlMessageKind = "AuthnRequest"
	samlLogoutRequest samlMessageKind = "LogoutRequest"
)

// samlMessage is the part of a SAML request the ladder in samlendpoint.go
// reads. Nothing else in the document is looked at, and that is measured
// rather than a simplification: ProtocolBinding="…SOAP" and ForceAuthn="true"
// both reach the login page unchanged.
type samlMessage struct {
	Kind   samlMessageKind
	ID     string
	Issuer string
	// Destination and HasDestination are separate because **an absent
	// Destination is accepted and a present wrong one is not**. Measured
	// 2026-09-11: an AuthnRequest with no Destination attribute, and one with
	// Destination="", both reach the login page on a server whose own URL they
	// do not name, where a Destination naming the wrong port is
	// `Invalid Request`. That single cell is what makes a literal AuthnRequest
	// sendable from a fixture at all - see F175 - and the first cut had it the
	// other way round.
	Destination    string
	HasDestination bool
	// ACSURL is the request's AssertionConsumerServiceURL, empty when the
	// message names none. An absent one is not a refusal: the client's
	// saml_assertion_consumer_url_post attribute answers for it.
	ACSURL string
}

// decodeSAMLRedirect decodes the HTTP-Redirect binding's SAMLRequest parameter:
// base64, then raw DEFLATE.
func decodeSAMLRedirect(param string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, false
	}
	// The limit is what stops a small parameter inflating without bound. It is
	// generous against every measured message - the longest AuthnRequest in this
	// project is under 500 bytes - and it is a guard rather than a contract, so
	// no measurement fixes it.
	xmlBytes, err := io.ReadAll(io.LimitReader(flate.NewReader(strings.NewReader(string(raw))), 1<<20))
	if err != nil {
		return nil, false
	}
	return xmlBytes, true
}

// decodeSAMLPost decodes the HTTP-POST binding's SAMLRequest parameter: base64
// of the XML, with no compression.
func decodeSAMLPost(param string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// parseSAMLMessage reads the document, reporting false for every shape the
// endpoint answers `Invalid Request` to.
//
// It walks the token stream rather than unmarshalling into a struct, for two
// reasons that are both measured requirements. The Issuer must be a **direct
// child** - encoding/xml's `xml:"Issuer"` would find one nested inside
// <Extensions>, which Keycloak refuses - and the root's namespace has to be
// compared while its local name is compared case-sensitively, which a struct
// tag spells but cannot report on separately.
func parseSAMLMessage(doc []byte) (*samlMessage, bool) {
	decoder := xml.NewDecoder(strings.NewReader(string(doc)))
	root, err := nextStartElement(decoder)
	if err != nil {
		return nil, false
	}
	if root.Name.Space != samlProtocolNS {
		return nil, false
	}
	msg := &samlMessage{Kind: samlMessageKind(root.Name.Local)}
	if msg.Kind != samlAuthnRequest && msg.Kind != samlLogoutRequest {
		return nil, false
	}
	var version, issueInstant string
	for _, attr := range root.Attr {
		switch attr.Name.Local {
		case "ID":
			msg.ID = attr.Value
		case "Version":
			version = attr.Value
		case "IssueInstant":
			issueInstant = attr.Value
		case "Destination":
			msg.Destination, msg.HasDestination = attr.Value, true
		case "AssertionConsumerServiceURL":
			msg.ACSURL = attr.Value
		}
	}
	if msg.ID == "" || version != samlRequestVersion || issueInstant == "" {
		return nil, false
	}
	if !readIssuer(decoder, msg) {
		return nil, false
	}
	if msg.Issuer == "" {
		return nil, false
	}
	return msg, true
}

// readIssuer takes the Issuer out of the root's direct children.
//
// **The last one wins**, measured: a message carrying <Issuer>account</Issuer>
// and then <Issuer>a-saml-client</Issuer> is served from the second. Every
// child that is not an Issuer is skipped whole, which is what keeps a nested
// one from being found.
func readIssuer(decoder *xml.Decoder, msg *samlMessage) bool {
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "Issuer" {
			if err := decoder.Skip(); err != nil {
				return false
			}
			continue
		}
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return false
		}
		msg.Issuer = strings.TrimSpace(text)
	}
}

// nextStartElement returns the document's first element, skipping the prologue
// and any comment or whitespace in front of it.
func nextStartElement(decoder *xml.Decoder) (xml.StartElement, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start, nil
		}
	}
}
