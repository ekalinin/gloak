package oidc

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/httpx"
)

// DPoP - RFC 9449, Demonstrating Proof of Possession - binds a token to the
// key that asked for it. Everything in this file was measured against a live
// Keycloak 26.7.1 on 2026-09-06, one malformation per request.
//
// # The header decides, not the client
//
// `admin-cli` carries no dpop.bound.access.tokens attribute and a proof sent to
// it still binds the tokens, so verification is **opportunistic**: a request
// carrying the header is verified whatever the client says. The attribute makes
// the header *mandatory* rather than switching verification on, and a request
// with no header to a client that carries it is descDPoPMissing.
//
// **A header present and empty is not a header absent.** `DPoP:` with an empty
// value - or one holding only spaces, which HTTP trims to the same thing -
// answers descDPoPMissing on a client that does not require DPoP at all, where
// no header at all answers 200 with an ordinary Bearer token. Measured by
// sending the bytes explicitly: curl drops a header written `-H "Name:  "`
// rather than sending an empty one, and the 200 that spelling produced was
// curl's answer and not Keycloak's.
const dpopHeader = "DPoP"

// dpopProofType is the required JOSE header typ. Compared exactly: DPOP+JWT
// answers the same refusal as JWT.
const dpopProofType = "dpop+jwt"

// The measured refusals, all 400 with invalid_request on the token endpoint.
//
// **The order they are checked in is measured too**, by nine proofs each wrong
// in two ways: typ, then alg, then the jwk, then the signature, then the
// mandatory claims, then htu, then htm, then iat, then jti. Two of those are
// not where a reader would put them - a proof with a broken signature and a
// wrong htm answers about the signature, and **htu is compared before htm**, so
// a proof wrong about both answers about the URL. Reordering either changes the
// answer to a request that is wrong in two ways.
const (
	descDPoPMissing        = "DPoP proof is missing"
	descDPoPHeaderFailure  = "DPoP header verification failure"
	descDPoPNoJWK          = "No JWK in DPoP header"
	descDPoPMissingClaims  = "DPoP mandatory claims are missing"
	descDPoPURLMismatch    = "DPoP HTTP URL mismatch"
	descDPoPMethodMismatch = "DPoP HTTP method mismatch"
	descDPoPNotActive      = "DPoP proof is not active"
	descDPoPReplayed       = "DPoP proof has already been used"
	// descDPoPConfirmationMismatch is the refresh grant's, and it is
	// invalid_grant where every other sentence here is invalid_request.
	descDPoPConfirmationMismatch = "DPoP confirmation doesn't match DPoP proof"
	// The two verification failures are different sentences and both name a
	// Java class. A signature that does not verify is the first; a proof whose
	// alg names a curve the key does not have - ES384 over a P-256 key - is the
	// second, and it comes out of a different layer of Keycloak.
	descDPoPBadSignature = "DPoP verification failure: " +
		"org.keycloak.exceptions.TokenSignatureInvalidException: Invalid token signature"
	descDPoPSigningFailed = "DPoP verification failure: " +
		"org.keycloak.common.VerificationException: Signing failed"
)

// descDPoPWrongType spells the typ refusal. An **absent** typ interpolates the
// literal word "null" and an empty one interpolates nothing, both measured, so
// the missing case is not the empty case written twice.
func descDPoPWrongType(typ string, present bool) string {
	if !present {
		typ = "null"
	}
	return "Invalid or missing type in DPoP header: " + typ
}

// descDPoPUnsupportedAlg is an alg outside the ten the discovery document
// advertises. `none` and `HS256` are both measured here rather than at the
// signature check.
func descDPoPUnsupportedAlg(alg string) string {
	return "Unsupported DPoP algorithm: " + alg
}

// descDPoPKeyType is a supported alg over a key of the wrong kind - RS256 or
// EdDSA over an EC key, both measured. It names the algorithm twice, which is
// Keycloak's sentence and not a mistake here.
func descDPoPKeyType(alg, kty string) string {
	return fmt.Sprintf("Key with algorithm %s and type %s is incorrect for provider algorithm %s",
		alg, kty, alg)
}

// dpopAlgorithms is the set the discovery document advertises, and the set this
// check accepts. Anything else is descDPoPUnsupportedAlg, which is why `none`
// never reaches a verifier.
var dpopAlgorithms = map[string]string{
	"PS384": "RSA", "RS384": "RSA", "EdDSA": "OKP", "ES384": "EC", "ES256": "EC",
	"RS256": "RSA", "ES512": "EC", "PS256": "RSA", "PS512": "RSA", "RS512": "RSA",
}

// dpopCurves is the curve each EC algorithm requires. A P-256 key under ES384
// is descDPoPSigningFailed rather than a bad signature, measured.
var dpopCurves = map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}

// The iat window, measured at one second's resolution against a container whose
// clock agreed with the host's to the second: a proof is accepted for
// iat in [now-25, now+15] and refused either side.
//
// It is two constants rather than one because the window is asymmetric, and
// 10 + 15 is what puts its edges where they were measured.
//
// **Its lowest second is a 500 on Keycloak and a 200 here.** At exactly now-25
// the proof passes this window and dies where the jti is stored, which is what
// a cache entry whose remaining life computes to zero does. Reproducing a
// server error for one second of a forty-second window is the tidy-up this
// project files rather than builds; see
// docs/superpowers/handover/ciba-dpop.md.
const (
	dpopProofLifetime = 10 * time.Second
	dpopClockSkew     = 15 * time.Second
)

// dpopProof is a verified proof: the thumbprint the tokens will carry, and
// nothing else the caller needs.
type dpopProof struct {
	Thumbprint string
}

// dpopError is one refusal, carrying the code as well as the sentence because
// the refresh grant's mismatch is invalid_grant where the rest are
// invalid_request.
type dpopError struct {
	code        string
	description string
}

func (e *dpopError) write(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusBadRequest, e.code, e.description)
}

func dpopRefusal(description string) *dpopError {
	return &dpopError{code: authErrInvalidRequest, description: description}
}

// proofStore is the single-use jti cache.
//
// In memory, and for the same reason as the authentication session, the
// authorization code and the device store: Keycloak keeps it in Infinispan
// rather than in its schema, so a table here would be a divergence rather than
// a copy. It costs the same thing they cost - this cut is single-process, and a
// restart forgets which proofs have been spent. See F75.
type proofStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newProofStore() *proofStore {
	return &proofStore{seen: map[string]time.Time{}}
}

// use records a jti and reports whether it had already been used. Entries are
// dropped once no proof carrying them could still be inside the iat window,
// which is what stops the map growing without bound.
func (s *proofStore) use(jti string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, at := range s.seen {
		if now.Sub(at) > dpopProofLifetime+dpopClockSkew {
			delete(s.seen, id)
		}
	}
	if _, ok := s.seen[jti]; ok {
		return true
	}
	s.seen[jti] = now
	return false
}

// dpopClaims is the proof's payload. All four are mandatory and any one absent
// answers the same descDPoPMissingClaims, so they are pointers only where zero
// is a legitimate value.
type dpopClaims struct {
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat *int64 `json:"iat"`
	Jti string `json:"jti"`
}

// dpopHeaderFields is the JOSE header, read before anything is verified because
// the first three checks are about it. jwk stays raw so that kty and crv can be
// read for the two messages that name them.
type dpopHeaderFields struct {
	Typ *string         `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}

// verifyDPoP applies the measured ladder to one request's DPoP header and
// returns the thumbprint its tokens should carry.
//
// A nil proof and a nil error is the ordinary case: no header, a client that
// does not require one, and an unbound Bearer token.
//
// url is the absolute URL the request arrived at, built from the issuer base
// rather than from the Host header so that the recorder and the verifier - one
// behind a container's mapped port, one in process - compare the same string.
func (h *handler) verifyDPoP(r *http.Request, required bool, url string) (*dpopProof, *dpopError) {
	raw, present := r.Header[http.CanonicalHeaderKey(dpopHeader)]
	value := ""
	if present && len(raw) > 0 {
		value = raw[0]
	}
	// A header the request repeats is one Go joins with a comma on the way in
	// and Keycloak refuses as unparseable; either way it is not a proof.
	if present && len(raw) > 1 {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	if strings.TrimSpace(value) == "" {
		if present || required {
			return nil, dpopRefusal(descDPoPMissing)
		}
		return nil, nil
	}
	return h.verifyDPoPProof(value, r.Method, url)
}

// verifyDPoPProof is verifyDPoP once the header is known to hold something.
func (h *handler) verifyDPoPProof(value, method, url string) (*dpopProof, *dpopError) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	var hdr dpopHeaderFields
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}

	if hdr.Typ == nil || *hdr.Typ != dpopProofType {
		spelled := ""
		if hdr.Typ != nil {
			spelled = *hdr.Typ
		}
		return nil, dpopRefusal(descDPoPWrongType(spelled, hdr.Typ != nil))
	}
	wantType, ok := dpopAlgorithms[hdr.Alg]
	if !ok {
		return nil, dpopRefusal(descDPoPUnsupportedAlg(hdr.Alg))
	}
	if len(hdr.JWK) == 0 {
		return nil, dpopRefusal(descDPoPNoJWK)
	}
	var described struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
	}
	if err := json.Unmarshal(hdr.JWK, &described); err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	if described.Kty != wantType {
		return nil, dpopRefusal(descDPoPKeyType(hdr.Alg, described.Kty))
	}
	if want, ok := dpopCurves[hdr.Alg]; ok && described.Crv != want {
		return nil, dpopRefusal(descDPoPSigningFailed)
	}

	key := &jose.JSONWebKey{}
	if err := key.UnmarshalJSON(hdr.JWK); err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	jws, err := jose.ParseSigned(value, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(hdr.Alg)})
	if err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, dpopRefusal(descDPoPBadSignature)
	}

	var claims dpopClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		// Unmeasured: a payload that is not an object never got past
		// Keycloak's own parse in any probe. The header family is the closest
		// measured answer and is what a caller sees here.
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	if claims.Htm == "" || claims.Htu == "" || claims.Iat == nil || claims.Jti == "" {
		return nil, dpopRefusal(descDPoPMissingClaims)
	}
	// The query is cut before the comparison and the comparison is exact
	// otherwise: a proof whose htu carries ?x=1 is accepted where one naming
	// another path or another host is not.
	if trimQuery(claims.Htu) != url {
		return nil, dpopRefusal(descDPoPURLMismatch)
	}
	if claims.Htm != method {
		return nil, dpopRefusal(descDPoPMethodMismatch)
	}
	now := time.Now()
	iat := time.Unix(*claims.Iat, 0)
	if iat.Before(now.Add(-dpopProofLifetime - dpopClockSkew)) || iat.After(now.Add(dpopClockSkew)) {
		return nil, dpopRefusal(descDPoPNotActive)
	}
	if h.proofs.use(claims.Jti, now) {
		return nil, dpopRefusal(descDPoPReplayed)
	}

	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, dpopRefusal(descDPoPHeaderFailure)
	}
	return &dpopProof{Thumbprint: base64.RawURLEncoding.EncodeToString(sum)}, nil
}

// trimQuery drops a URL's query and fragment, which is what the htu comparison
// is measured to do.
func trimQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// requiresDPoP is the client attribute that makes the header mandatory. It does
// **not** switch verification on: a client without it still has its proof
// verified when it sends one.
func requiresDPoP(attributes map[string]string) bool {
	return attributes[attrDPoPBound] == "true"
}

// dpopThumbprint is what the token issuance is given: the proof's thumbprint,
// or empty when there was none.
func dpopThumbprint(p *dpopProof) string {
	if p == nil {
		return ""
	}
	return p.Thumbprint
}

// tokenTypeFor is the token response's token_type. It follows the request's
// proof, not the client's attribute.
func tokenTypeFor(jkt string) string {
	if jkt == "" {
		return "Bearer"
	}
	return dpopHeader
}
