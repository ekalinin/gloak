package admin

import (
	"bytes"
	"encoding/json"
)

// marshalOrderedValue marshals one value of an ordered JSON object without
// escaping `<`, `>` and `&`.
//
// **A custom MarshalJSON cannot inherit the encoder's SetEscapeHTML(false).**
// `internal/httpx` turns HTML escaping off for every response body, because
// Keycloak does not escape those three characters; but a type with its own
// MarshalJSON is asked for bytes, and whatever `json.Marshal` produced inside
// it has already been escaped. The outer encoder then only *compacts* what it
// was handed, so `<` survives to the wire.
//
// It is reachable and both halves were measured on 2026-09-02. An identity
// provider created with `{"config":{"note":"a<b>c&d"}}` reads back from
// Keycloak as `"a<b>c&d"`; `identityProviderConfig` marshalled the same entry
// with all three characters escaped to their six-character `\u00xx` spelling,
// and a plain struct written through the same response writer came out right -
// which is what says the fault is the custom marshaller and not
// `internal/httpx`.
//
// The mapper family this cut adds carries the same caller-supplied values, and
// its **catalogue** carries angle brackets in a helpText no caller can avoid:
// `saml-username-idp-mapper` says `ATTRIBUTE.<NAME>`. So the catalogue could
// not have been served byte-exactly without this, which is how a divergence
// that had been shipped since P9's first cut came to be noticed.
//
// Every ordered-object marshaller in this package goes through here for that
// reason. There are four: an identity provider's config, a component's config,
// an identity provider mapper's config and the mapper-type catalogue.
func marshalOrderedValue(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode appends a newline; an object member may not carry one.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
