package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is one of the three SigAlg values measured accepted; see sigAlgHashes.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"net/url"
	"strings"

	"github.com/ekalinin/gloak/internal/model"
)

// Verifying the HTTP-Redirect binding's signature.
//
// # Why this exists rather than a flag
//
// Every client `POST /admin/realms/{realm}/clients` creates with
// `{"protocol":"saml"}` carries `saml.client.signature: "true"` among the
// fourteen attributes it generates, so the **default** SAML client requires a
// signature and an unsigned AuthnRequest from one answers `Invalid requester`.
// A handler that answered that sentence whenever the flag is on would be right
// on every unsigned message and wrong on the only message a correctly
// configured client ever sends - which is what the first cut of this chapter
// refused to ship, and what this file is here to avoid.
//
// The positive control is measured and it is in the catalogue rather than only
// in a unit test: `saml/endpoint/redirect-binding-signature-accepted` sends a
// genuinely signed AuthnRequest from a client whose key the fixture pins, and
// the answer moves one rung up the ladder to `Invalid redirect uri`. A verifier
// that refused everything would answer `Invalid requester` there.
//
// # What was measured, on 2026-09-11, against a live 26.7.1
//
// A request signed with the client's own generated private key, over the
// canonical string below, with `SigAlg` = rsa-sha256:
//
//	no RelayState                        accepted - answered the next rung
//	RelayState present and signed        accepted
//	Signature over a **different** message  refused, `Invalid requester`
//	SigAlg and Signature both junk       refused
//	SigAlg alone, Signature alone        refused
//	neither parameter                    refused
//
// So the check is real and this is what it checks.
//
// # The canonical string
//
// The bytes signed are the **raw query parameters as they were sent**, joined
// with `&` in a fixed order - SAMLRequest (or SAMLResponse), RelayState if it
// is there, SigAlg - and never a re-encoding of the decoded values. Re-encoding
// is the implementation that works until a client percent-encodes a character
// this server would not have, which is every client that writes `+` for a
// space; the probe that measured this endpoint did exactly that and passed.
//
// # What this file cannot do, and says so
//
// **The HTTP-POST binding's signature is an enveloped XML one**, over a
// canonicalised document, and nothing in the standard library canonicalises
// XML. So a POST-binding message from a client requiring a signature is not
// verified here and not refused here either: samlendpoint.go stops and lets the
// request fall through to the protocol dispatcher's 404, which is the answer
// Gloak gave that whole endpoint before this cut. Answering `Invalid requester`
// instead would be the exact mistake the paragraph above describes, one binding
// across. See follow-up F229.

// sigAlgHashes is the accepted set of RSA SigAlg URIs, and it is **three, not
// four**.
//
// Each of these was measured accepting a real signature made with that digest,
// on one container on 2026-09-11, over one message, from a client whose
// certificate the probe installed:
//
//	http://www.w3.org/2000/09/xmldsig#rsa-sha1          accepted
//	http://www.w3.org/2001/04/xmldsig-more#rsa-sha256   accepted
//	http://www.w3.org/2001/04/xmldsig-more#rsa-sha512   accepted
//	http://www.w3.org/2001/04/xmldsig-more#rsa-sha384   **refused**
//	http://www.w3.org/2001/04/xmldsig-more#rsa-sha224   refused
//
// **rsa-sha384 is the one that looks like a bug and is not.** The URI is
// correct, the digest is correct, the signature verifies against the same
// certificate the sha256 request used, and Keycloak answers `Invalid requester`.
// Setting the client's own `saml.signature.algorithm` to `RSA_SHA512` changes
// nothing about it either way, so the accepted set is a property of the server
// and not of the client. Writing the table from SAML's own list of four - which
// is what a reader would do - gives an implementation that accepts one signature
// Keycloak refuses.
//
// A `SigAlg` naming sha256 with a sha512 signature under it is refused too, so
// the URI decides the digest rather than being advisory.
//
// **This map is half the gate and newSigAlgHash's switch is the other half**,
// and the asymmetry is worth naming because a mutation pass walked into it:
// adding rsa-sha384 *here* alone changes nothing observable, because the switch
// then hands back a nil hash and the request is refused anyway. That is a
// textual edit with no behaviour behind it - F208's shape - and it passed every
// test in the tree. TestSigAlgHashesAndNewSigAlgHashAgree is the ratchet that
// makes the two lists one claim, so the same edit now fails.
var sigAlgHashes = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":        crypto.SHA1,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": crypto.SHA512,
}

// newSigAlgHash is crypto.Hash.New without the import of every digest into the
// call site. crypto.Hash.New panics for a hash whose package is not linked in,
// so the three packages are imported above and this switch is what links them.
//
// It is deliberately a switch over the three and not `h.New()`, so that a
// SigAlg naming a digest this build does not link cannot panic a request.
func newSigAlgHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New() //nolint:gosec // See sigAlgHashes.
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA512:
		return sha512.New()
	}
	return nil
}

// clientRequiresSignature reports whether the client's saml.client.signature
// attribute is on.
//
// **The comparison is against the exact string "true" and is case-sensitive.**
// Measured 2026-09-11, one value at a time on one container: "false", "", the
// attribute absent, "FALSE", "0", "no", " true", "TRUE" and "True" are all
// **off**, and only "true" is on. So it is `"true".equals(value)` in Keycloak
// and not a boolean parse - `Boolean.parseBoolean("TRUE")` is true in Java, and
// an implementation reaching for strconv.ParseBool here is wrong on exactly
// that input.
func clientRequiresSignature(client *model.Client) bool {
	return client.Attributes["saml.client.signature"] == "true"
}

// verifyRedirectSignature checks the signature on an HTTP-Redirect binding
// request, reporting false for every reason the endpoint answers
// `Invalid requester`.
//
// rawQuery is the request's untouched RawQuery, because the signed bytes are
// the parameters as they arrived. See the canonical string above.
func verifyRedirectSignature(client *model.Client, rawQuery string) bool {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	sigAlg, signature := values.Get("SigAlg"), values.Get("Signature")
	if sigAlg == "" || signature == "" {
		return false
	}
	digest, ok := sigAlgHashes[sigAlg]
	if !ok {
		return false
	}
	signed, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	key := clientSigningKey(client)
	if key == nil {
		return false
	}
	hasher := newSigAlgHash(digest)
	if hasher == nil {
		return false
	}
	hasher.Write([]byte(redirectSignedString(rawQuery)))
	return rsa.VerifyPKCS1v15(key, digest, hasher.Sum(nil), signed) == nil
}

// redirectSignedString rebuilds the bytes the client signed out of the raw
// query, in SAML's fixed order and with each parameter's value exactly as it
// was sent.
func redirectSignedString(rawQuery string) string {
	raw := rawQueryParts(rawQuery)
	parts := make([]string, 0, 3)
	for _, name := range []string{"SAMLRequest", "SAMLResponse", "RelayState", "SigAlg"} {
		if part, ok := raw[name]; ok {
			parts = append(parts, name+"="+part)
		}
	}
	return strings.Join(parts, "&")
}

// rawQueryParts splits a raw query into its parameters **without decoding
// them**, keeping the first spelling of a repeated name.
func rawQueryParts(rawQuery string) map[string]string {
	parts := map[string]string{}
	for rawQuery != "" {
		var pair string
		pair, rawQuery, _ = strings.Cut(rawQuery, "&")
		name, value, _ := strings.Cut(pair, "=")
		if _, seen := parts[name]; !seen {
			parts[name] = value
		}
	}
	return parts
}

// clientSigningKey is the RSA public key a SAML client's registered certificate
// carries, and nil when the client has none this server can read.
//
// The attribute is `saml.signing.certificate`: the DER of an X.509 certificate
// in **standard** base64 with no PEM armour and no line breaks, which is the
// spelling the descriptor's <ds:X509Certificate> uses for the server's own.
func clientSigningKey(client *model.Client) *rsa.PublicKey {
	encoded := client.Attributes["saml.signing.certificate"]
	if encoded == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return key
}
