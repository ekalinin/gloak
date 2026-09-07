package httpx

import "net/http"

// This file is the third body format Gloak writes, and it is here rather than
// in internal/oidc for the reason WriteJSON's doc comment gives: this package
// owns every response body, so the byte-exactness guarantee cannot drift
// between call sites. See AGENTS.md's boundary table.
//
// It takes bytes rather than a value, where WriteJSON and WriteYAML take one,
// and that is measured rather than a shortcut. `encoding/xml` cannot emit the
// document this serves - see TestEncodingXMLCannotEmitTheDescriptor in
// internal/oidc, which runs the marshaller and compares. Three things it gets
// wrong on the SAML metadata Keycloak sends:
//
//   - it has no way to declare two prefixes for one namespace URI, and the
//     descriptor declares `xmlns` and `xmlns:md` both bound to the metadata
//     namespace on the root element;
//   - it re-declares a namespace on every element that names one instead of
//     using a prefix bound above, so `<md:NameIDFormat>` comes out
//     `<NameIDFormat xmlns="...">`;
//   - it writes an element with no content as `<a></a>`, which happens to
//     agree here, but it cannot be asked for the prefix spelling that would
//     make the agreement mean anything.
//
// So the descriptor is emitted as bytes by its own builder, which is
// internal/httpx/yaml.go's situation one file across, and this function is the
// writer rather than the marshaller.
//
// **The media type is not shared with the other XML response on this surface.**
// GET /realms/{realm}/protocol/saml/descriptor answers
// `application/xml;charset=UTF-8` and carries all five security headers;
// POST /realms/{realm}/protocol/saml/resolve answers `text/xml` and omits
// X-Frame-Options, measured on one container on 2026-09-07. Two XML media types
// one path segment apart, opposite answers to the header rule AGENTS.md records
// - which is why this writer names its type rather than assuming "XML".

// WriteXML writes an already-rendered XML document with the media type
// Keycloak's SAML descriptor answers, `application/xml;charset=UTF-8`.
//
// It deletes nothing. The five security headers arrive from the router's
// SetSecurityHeaders and the descriptor carries all five, unlike YAML,
// text/plain and the keystore downloads, which each delete X-Frame-Options.
// Cache-Control is the caller's, because it is pinned per endpoint.
func WriteXML(w http.ResponseWriter, status int, body []byte) {
	suppressDate(w)
	w.Header().Set("Content-Type", "application/xml;charset=UTF-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
