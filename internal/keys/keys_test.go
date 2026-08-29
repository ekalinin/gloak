package keys_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
)

func TestGenerateProducesFourDistinctKeyIDs(t *testing.T) {
	k, err := keys.Generate("master")

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ids := map[string]string{
		"rsa": k.RSAKeyID, "enc": k.EncKeyID, "hmac": k.HMACKeyID, "aes": k.AESKeyID,
	}
	seen := make(map[string]string, len(ids))
	for name, id := range ids {
		if id == "" {
			t.Fatalf("%s key ID is empty", name)
		}
		if other, dup := seen[id]; dup {
			t.Fatalf("%s and %s share the key ID %q", other, name, id)
		}
		seen[id] = name
	}
}

// TestKeyIDReproducesTheMeasuredKid is the vector, and both halves of it come
// off one recorded response.
//
// publicKey and kid below are master's RS256 entry from
// GET /admin/realms/master/keys on a live Keycloak 26.7.1, recorded
// 2026-08-29. The digest of the first has to be the second, which is what says
// the rule is base64url(sha256(SubjectPublicKeyInfo)) and not something that
// merely produces a 43-character string.
//
// The RFC 7638 JWK thumbprint was computed over this same key first, because
// it is the obvious guess, and gives RI0Cq8BR5aI1Km8s8ioVX63uTGMEWZOCfyf1NN6jy7I.
func TestKeyIDReproducesTheMeasuredKid(t *testing.T) {
	const (
		publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZf5VMa5NxHtHj7d7n5p6bMbsiQwg6FEW75o9QhDIGPJAXP3TUOuKyy65Ww+wHLWiF8rzj2XbZO9coUBu5wD8KTjm2/KKgne2pVcEk4XRFEcLrlrZmqmIybXDfUREbWrpVBRB1F1R6R3G89swrw7Gm10CS4qOsg/RLAD0QAVp/86LatxutvHsCGS62EK9uBoruylAdMUKk7DvLyMw2TPCd6Lc8EXkz13zNgzf+8aL/m7t7eYA4nKAgMPoG86jT7b23KvECYw0Q1yYGBcCiarHDLEkFogIejZGw7KT6+FHS7fCKsKbAPZ+wIvLcoYtEvvgasV3DRXtvuYynWm00665wIDAQAB"
		kid       = "Q80zap21IG6Jjn3zecYt3iXqDNthWiPlL4dNVvQGkyw"
	)
	der, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("decode the recorded public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("want an RSA public key, got %T", parsed)
	}

	if got := keys.KeyID(pub); got != kid {
		t.Fatalf("want the measured kid %q, got %q", kid, got)
	}
}

// TestGeneratedRSAKidsAreDerivedFromTheirKeys pins the other half: the two RSA
// key IDs are not fresh UUIDs but the digest of the key they name, so a set
// read back from storage and one generated from the same key agree.
func TestGeneratedRSAKidsAreDerivedFromTheirKeys(t *testing.T) {
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if got := keys.KeyID(k.SigningPublicKey()); got != k.RSAKeyID {
		t.Errorf("signing kid %q is not the digest of its key (%q)", k.RSAKeyID, got)
	}
	if got := keys.KeyID(k.EncryptionPublicKey()); got != k.EncKeyID {
		t.Errorf("encryption kid %q is not the digest of its key (%q)", k.EncKeyID, got)
	}
}

func TestJWKSExposesOnlyThePublicRSAKeys(t *testing.T) {
	// Two published keys, measured: RS256/sig and RSA-OAEP/enc. The HMAC key
	// signs refresh tokens, which are opaque to clients; publishing it would
	// hand out the ability to mint them.
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	set := k.JWKS()

	if len(set.Keys) != 2 {
		t.Fatalf("want exactly two published keys, got %d", len(set.Keys))
	}
	if set.Keys[0].KeyID != k.RSAKeyID {
		t.Fatalf("want signing key ID %q, got %q", k.RSAKeyID, set.Keys[0].KeyID)
	}
	if set.Keys[1].KeyID != k.EncKeyID {
		t.Fatalf("want encryption key ID %q, got %q", k.EncKeyID, set.Keys[1].KeyID)
	}
	for _, jwk := range set.Keys {
		if !jwk.IsPublic() {
			t.Fatalf("key %q is private in the JWKS", jwk.KeyID)
		}
		if jwk.KeyID == k.HMACKeyID {
			t.Fatal("the HMAC key is published")
		}
	}
	if set.Keys[0].Algorithm != "RS256" || set.Keys[0].Use != "sig" {
		t.Fatalf("want RS256/sig, got %s/%s", set.Keys[0].Algorithm, set.Keys[0].Use)
	}
	if set.Keys[1].Algorithm != "RSA-OAEP" || set.Keys[1].Use != "enc" {
		t.Fatalf("want RSA-OAEP/enc, got %s/%s", set.Keys[1].Algorithm, set.Keys[1].Use)
	}
}

func TestCertificateDERMatchesTheJWKSPublicKey(t *testing.T) {
	// Keycloak publishes a certificate over the same RSA key it publishes in
	// the JWKS. A certificate over a different key would still parse and
	// still satisfy the field-set/order assertions, so this checks the one
	// thing those cannot: that x5c actually attests the published key.
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cert, err := x509.ParseCertificate(k.CertificateDER())
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "master" {
		t.Fatalf("want subject CN %q, got %q", "master", cert.Subject.CommonName)
	}

	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("want an RSA public key in the certificate, got %T", cert.PublicKey)
	}
	jwkPub, ok := k.JWKS().Keys[0].Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("want an RSA public key in the JWKS, got %T", k.JWKS().Keys[0].Key)
	}
	if !certPub.Equal(jwkPub) {
		t.Fatal("want the certificate's public key to match the JWKS entry's")
	}
}

func TestSignersUseTheExpectedAlgorithms(t *testing.T) {
	// Signing and reading the JWS header back is what catches the mistake that
	// matters here: the two signers swapped, so refresh tokens end up RS256 and
	// access tokens HS512.
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cases := []struct {
		name    string
		signer  func() (jose.Signer, error)
		wantAlg string
		wantKid string
	}{
		{"access and ID tokens", k.RSASigner, "RS256", k.RSAKeyID},
		{"refresh tokens", k.HMACSigner, "HS512", k.HMACKeyID},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := tc.signer()
			if err != nil {
				t.Fatalf("signer: %v", err)
			}

			jws, err := signer.Sign([]byte(`{"sub":"probe"}`))
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			serialised, err := jws.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			parsed, err := jose.ParseSigned(serialised,
				[]jose.SignatureAlgorithm{jose.RS256, jose.HS512})
			if err != nil {
				t.Fatalf("ParseSigned: %v", err)
			}

			hdr := parsed.Signatures[0].Header
			if string(hdr.Algorithm) != tc.wantAlg {
				t.Errorf("want alg %s, got %s", tc.wantAlg, hdr.Algorithm)
			}
			if hdr.KeyID != tc.wantKid {
				t.Errorf("want kid %s, got %s", tc.wantKid, hdr.KeyID)
			}
		})
	}
}
