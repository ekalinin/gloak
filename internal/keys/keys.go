// Package keys manages a realm's signing material. It is deliberately separate
// from token issuance: Keycloak signs access and ID tokens RS256 but refresh
// tokens HS512, so a realm holds more than one key even before rotation and
// multiple active JWKS entries arrive.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/model"
)

type RealmKeys struct {
	RSAKeyID  string
	HMACKeyID string

	rsaKey  *rsa.PrivateKey
	certDER []byte
	hmacKey []byte
}

// Generate creates a fresh RSA key for RS256, a self-signed certificate over
// it, and a fresh secret for HS512. Keycloak publishes the certificate in the
// JWKS as x5c with its two thumbprints, so the key alone is not enough.
// subjectCN is the realm name, which is what appears in the published
// certificate's subject.
func Generate(subjectCN string) (*RealmKeys, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keys: generate rsa: %w", err)
	}
	certDER, err := selfSign(rsaKey, subjectCN)
	if err != nil {
		return nil, err
	}
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("keys: generate hmac: %w", err)
	}
	return &RealmKeys{
		RSAKeyID:  model.NewID(),
		HMACKeyID: model.NewID(),
		rsaKey:    rsaKey,
		certDER:   certDER,
		hmacKey:   hmacKey,
	}, nil
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

// CertificateDER is the realm certificate, published as x5c and hashed into
// x5t and x5t#S256.
func (k *RealmKeys) CertificateDER() []byte { return k.certDER }

// JWKS returns the public key set served at
// /realms/{realm}/protocol/openid-connect/certs. The HMAC key is never
// published: it signs refresh tokens, which clients treat as opaque.
func (k *RealmKeys) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       k.rsaKey.Public(),
		KeyID:     k.RSAKeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
}

// RSASigner signs access and ID tokens.
func (k *RealmKeys) RSASigner() (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: k.rsaKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.RSAKeyID),
	)
}

// HMACSigner signs refresh tokens.
func (k *RealmKeys) HMACSigner() (jose.Signer, error) {
	return jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS512, Key: k.hmacKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.HMACKeyID),
	)
}
