// Package keys manages a realm's signing material. It is deliberately separate
// from token issuance: Keycloak signs access and ID tokens RS256 but refresh
// tokens HS512, so a realm holds more than one key even before rotation and
// multiple active JWKS entries arrive.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/model"
)

type RealmKeys struct {
	RSAKeyID  string
	HMACKeyID string

	rsaKey  *rsa.PrivateKey
	hmacKey []byte
}

// Generate creates a fresh RSA key for RS256 and a fresh secret for HS512.
func Generate() (*RealmKeys, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keys: generate rsa: %w", err)
	}
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("keys: generate hmac: %w", err)
	}
	return &RealmKeys{
		RSAKeyID:  model.NewID(),
		HMACKeyID: model.NewID(),
		rsaKey:    rsaKey,
		hmacKey:   hmacKey,
	}, nil
}

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
