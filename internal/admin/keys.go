package admin

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/javamap"
)

// GET /admin/realms/{realm}/keys - the whole of the OpenAPI description's `Key`
// tag. See the "Realm keys" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md.

// keysMetadata is the body: the active kid per algorithm, then every key.
type keysMetadata struct {
	Active activeKeys    `json:"active"`
	Keys   []keyMetadata `json:"keys"`
}

// keyMetadata is one key. The field order is transcribed from a recorded
// response and is the contract.
//
// **Three fields are absent on an OCT key and present on an RSA one**, so all
// three carry omitempty and ValidTo is a pointer: its measured value is a large
// positive number on the two RSA keys and the key is simply missing on the two
// OCT ones, which a plain int64 with omitempty could express only by accident.
type keyMetadata struct {
	ProviderID       string `json:"providerId"`
	ProviderPriority int    `json:"providerPriority"`
	KID              string `json:"kid"`
	Status           string `json:"status"`
	Type             string `json:"type"`
	Algorithm        string `json:"algorithm"`
	PublicKey        string `json:"publicKey,omitempty"`
	Certificate      string `json:"certificate,omitempty"`
	Use              string `json:"use"`
	ValidTo          *int64 `json:"validTo,omitempty"`
}

// activeKeys is the `active` object: algorithm name to kid.
//
// It is a slice with its own marshaller rather than a map for the reason
// clientMappings is: Keycloak builds it from a Java Map and Go sorts a map's
// keys. Measured on master and on a created realm, both answered
// `RSA-OAEP, HS512, RS256, AES` - which is what javamap.KeyOrder returns for
// those four names, and the first of its five confirmed vectors with no bucket
// collision in it.
type activeKeys []activeKey

type activeKey struct {
	Algorithm string
	KID       string
}

func (a activeKeys) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, entry := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		key, err := json.Marshal(entry.Algorithm)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		value, err := json.Marshal(entry.KID)
		if err != nil {
			return nil, err
		}
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// The four constants the listing repeats on every key. Every measured entry on
// both realms carried priority 100 and status ACTIVE; nothing in Gloak can make
// a key inactive, because nothing rotates one.
const (
	keyProviderPriority = 100
	keyStatusActive     = "ACTIVE"
	keyTypeRSA          = "RSA"
	keyTypeOCT          = "OCT"
)

// **`use` is upper case here and lower case in the JWKS.** SIG and ENC on this
// endpoint, sig and enc at /realms/{realm}/protocol/openid-connect/certs, for
// the same two keys. One constant shared between them would be wrong on one.
const (
	keyUseSig = "SIG"
	keyUseEnc = "ENC"
)

// readKeys serves GET /admin/realms/{realm}/keys.
//
// Four keys, where the JWKS beside it publishes two: the HMAC key that signs
// refresh tokens and the AES key appear here as bare kids, with no material.
func (h *handler) readKeys(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	k, err := h.keys.ForRealm(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	entries := []keyMetadata{
		rsaKeyMetadata(k.RSAKeyID, "RS256", keyUseSig, k.SigningPublicKey(), k.CertificateDER()),
		rsaKeyMetadata(k.EncKeyID, "RSA-OAEP", keyUseEnc, k.EncryptionPublicKey(), k.EncCertificateDER()),
		octKeyMetadata(k.HMACKeyID, "HS512", keyUseSig),
		octKeyMetadata(k.AESKeyID, "AES", keyUseEnc),
	}
	// **Ordered by providerId**, which is what the two recorded responses show:
	// master came back 501bb07d, c64d81a4, c801ee0a, cdaa5860 and a created
	// realm 3a8bb3b7, 5ab0fbec, bf17f8cb, df836b05, both ascending, and their
	// algorithm orders differ. So the order is a function of a value that is
	// random per key, and the conformance case compares this array unordered.
	slices.SortFunc(entries, func(a, b keyMetadata) int {
		return bytes.Compare([]byte(a.ProviderID), []byte(b.ProviderID))
	})

	active := make(activeKeys, 0, len(entries))
	names := make([]string, 0, len(entries))
	byName := make(map[string]string, len(entries))
	for _, e := range entries {
		names = append(names, e.Algorithm)
		byName[e.Algorithm] = e.KID
	}
	for _, name := range javamap.KeyOrder(names) {
		active = append(active, activeKey{Algorithm: name, KID: byName[name]})
	}

	writeAdminJSON(w, keysMetadata{Active: active, Keys: entries})
}

func rsaKeyMetadata(kid, algorithm, use string, pub *rsa.PublicKey, certDER []byte) keyMetadata {
	m := keyMetadata{
		ProviderID:       providerIDOf(kid),
		ProviderPriority: keyProviderPriority,
		KID:              kid,
		Status:           keyStatusActive,
		Type:             keyTypeRSA,
		Algorithm:        algorithm,
		Use:              use,
	}
	if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
		m.PublicKey = base64.StdEncoding.EncodeToString(der)
	}
	m.Certificate = base64.StdEncoding.EncodeToString(certDER)
	// validTo is the certificate's notAfter in milliseconds. Reading it off the
	// certificate rather than recomputing the validity window is what keeps the
	// two from drifting: internal/keys decides how long a key lives.
	if cert, err := x509.ParseCertificate(certDER); err == nil {
		millis := cert.NotAfter.UnixMilli()
		m.ValidTo = &millis
	}
	return m
}

func octKeyMetadata(kid, algorithm, use string) keyMetadata {
	return keyMetadata{
		ProviderID:       providerIDOf(kid),
		ProviderPriority: keyProviderPriority,
		KID:              kid,
		Status:           keyStatusActive,
		Type:             keyTypeOCT,
		Algorithm:        algorithm,
		Use:              use,
	}
}

// providerIDOf is the `providerId` of the key whose kid is given.
//
// In Keycloak this is the id of the key *provider component*, a separate object
// with its own row - which is why it is a different UUID from the kid on every
// measured key. Gloak models no components, and it does not need to: each of
// the four keys comes from exactly one provider, so here the key and its
// provider are the same object.
//
// It is therefore derived from the kid rather than stored. Deriving keeps it
// stable across restarts without a column for a concept nothing else in the
// model has, and keeps it distinct from the kid, which is the one thing about
// it a client can observe. The conformance case masks the value, so what is
// being preserved here is the shape and the distinctness, not the bytes.
func providerIDOf(kid string) string {
	sum := sha256.Sum256([]byte("gloak:key-provider:" + kid))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
