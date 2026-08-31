// Package keys manages a realm's signing material. It is deliberately separate
// from token issuance: Keycloak signs access and ID tokens RS256 but refresh
// tokens HS512, so a realm holds more than one key even before rotation and
// multiple active JWKS entries arrive.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/model"
)

type RealmKeys struct {
	RSAKeyID  string
	EncKeyID  string
	HMACKeyID string
	AESKeyID  string

	rsaKey     *rsa.PrivateKey
	certDER    []byte
	encKey     *rsa.PrivateKey
	encCertDER []byte
	hmacKey    []byte
	aesKey     []byte
}

// aesSecretSize is the AES key's length in bytes, matching Keycloak's
// aes-generated provider default of 128 bits.
//
// **It is not observable.** The secret is published by no endpoint - the key
// appears in GET /admin/realms/{realm}/keys as type OCT with a kid and nothing
// else - so this is Keycloak's default rather than a measured contract, and it
// is written down as such.
const aesSecretSize = 16

// Generate creates a realm's four keys: an RSA key for RS256 signing, a second
// RSA key for RSA-OAEP encryption, a secret for HS512, and an AES secret. Each
// RSA key gets a self-signed certificate, because Keycloak publishes one in
// the JWKS as x5c with its two thumbprints, so the key alone is not enough.
// subjectCN is the realm name, which is what appears in both published
// certificates' subject.
//
// The encryption key is published but never used by Gloak itself: a live
// master realm's JWKS carries it, so a JWKS without it differs from Keycloak's
// on the one endpoint whose whole purpose is to be read by other software.
//
// **The AES key is used by nothing at all**, here or in the JWKS. It exists
// because GET /admin/realms/{realm}/keys was measured serving four keys on
// both master and a created realm, and a realm serving three differs from
// Keycloak on that endpoint.
func Generate(subjectCN string) (*RealmKeys, error) {
	rsaKey, certDER, err := generateRSAWithCertificate(subjectCN)
	if err != nil {
		return nil, err
	}
	encKey, encCertDER, err := generateRSAWithCertificate(subjectCN)
	if err != nil {
		return nil, err
	}
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("keys: generate hmac: %w", err)
	}
	aesKey, err := generateAES()
	if err != nil {
		return nil, err
	}
	return &RealmKeys{
		// **The two RSA kids are derived from the key and the two OCT ones are
		// not.** See KeyID.
		RSAKeyID:   KeyID(&rsaKey.PublicKey),
		EncKeyID:   KeyID(&encKey.PublicKey),
		HMACKeyID:  model.NewID(),
		AESKeyID:   model.NewID(),
		rsaKey:     rsaKey,
		certDER:    certDER,
		encKey:     encKey,
		encCertDER: encCertDER,
		hmacKey:    hmacKey,
		aesKey:     aesKey,
	}, nil
}

// KeyID is the kid Keycloak publishes for an RSA key: the base64url SHA-256
// digest of the DER-encoded SubjectPublicKeyInfo, unpadded.
//
// Measured 2026-08-29: the digest of master's recorded publicKey reproduces
// its recorded kid byte for byte, on both the RS256 and the RSA-OAEP key.
// **It is not the RFC 7638 JWK thumbprint**, which was computed first over the
// same key and gives a different value - so the obvious guess is the wrong
// one, and keys_test.go carries the measured pair as a vector.
//
// The two OCT keys are UUIDs instead, measured on the same response, which is
// why this takes an *rsa.PublicKey rather than a Key: there is no "the kid
// rule" to share between them.
func KeyID(pub *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// Unreachable for an RSA key: MarshalPKIXPublicKey only fails on a key
		// type it does not know. Falling back to a fresh id keeps a realm
		// serviceable rather than failing a bootstrap over an impossibility.
		return model.NewID()
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func generateAES() ([]byte, error) {
	key := make([]byte, aesSecretSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("keys: generate aes: %w", err)
	}
	return key, nil
}

func generateRSAWithCertificate(subjectCN string) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: generate rsa: %w", err)
	}
	certDER, err := selfSign(key, subjectCN)
	if err != nil {
		return nil, nil, err
	}
	return key, certDER, nil
}

// selfSign issues the certificate Keycloak publishes alongside a realm key.
// The validity window matches what a live Keycloak 26.7.1 was observed to
// issue: roughly ten years starting at generation time, not the Unix epoch.
// See the "Certificate endpoint" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. Nothing
// validates this chain; it is published for clients that pin x5c.
func selfSign(key *rsa.PrivateKey, subjectCN string) ([]byte, error) {
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subjectCN},
		NotBefore:    now,
		NotAfter:     now.AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("keys: self-sign: %w", err)
	}
	return der, nil
}

// CertificateDER is the signing key's certificate, published as x5c on the
// sig entry and hashed into its x5t and x5t#S256.
func (k *RealmKeys) CertificateDER() []byte { return k.certDER }

// SigningPublicKey is the RS256 public key, used to verify a token this realm
// issued. The private half never leaves this package.
func (k *RealmKeys) SigningPublicKey() *rsa.PublicKey { return &k.rsaKey.PublicKey }

// EncCertificateDER is the same for the encryption key's enc entry.
func (k *RealmKeys) EncCertificateDER() []byte { return k.encCertDER }

// EncryptionPublicKey is the RSA-OAEP public key. The Admin API's key listing
// publishes it beside the signing one; nothing in Gloak encrypts with it.
func (k *RealmKeys) EncryptionPublicKey() *rsa.PublicKey { return &k.encKey.PublicKey }

// HMACSecret is the HS512 secret, needed to verify a refresh token this realm
// issued. It is deliberately absent from JWKS and from every response body:
// handing it out would hand out the ability to mint refresh tokens. See
// internal/keys' row in AGENTS.md's boundary table.
func (k *RealmKeys) HMACSecret() []byte { return k.hmacKey }

// JWKS returns the public key set served at
// /realms/{realm}/protocol/openid-connect/certs. A live master realm publishes
// two keys - RS256/sig and RSA-OAEP/enc - measured in the "Certificate
// endpoint" section of
// docs/superpowers/specs/2026-08-18-keycloak-26.7.1-observed.md. The HMAC key
// is never published: it signs refresh tokens, which clients treat as opaque.
func (k *RealmKeys) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{
			Key:       k.rsaKey.Public(),
			KeyID:     k.RSAKeyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
		{
			Key:       k.encKey.Public(),
			KeyID:     k.EncKeyID,
			Algorithm: string(jose.RSA_OAEP),
			Use:       "enc",
		},
	}}
}

// RSASigner signs access and ID tokens.
func (k *RealmKeys) RSASigner() (jose.Signer, error) {
	return k.RSASignerTyped("JWT")
}

// RSASignerTyped is RSASigner with the JOSE header's typ chosen by the caller.
//
// It exists because the back-channel logout token is the one RS256 token
// Keycloak signs whose header says something other than "JWT": measured
// 2026-08-31, `{"alg":"RS256","typ" : "logout+jwt","kid" : ...}`, over a
// payload whose own typ claim says "Logout". Two spellings of the token's kind
// in one token, so the header's cannot be derived from the payload's.
func (k *RealmKeys) RSASignerTyped(typ string) (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k.rsaKey},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", k.RSAKeyID),
	)
}

// HMACSigner signs refresh tokens.
func (k *RealmKeys) HMACSigner() (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS512, Key: k.hmacKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.HMACKeyID),
	)
}
