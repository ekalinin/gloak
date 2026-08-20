package keys_test

import (
	"crypto/rsa"
	"crypto/x509"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ekalinin/gloak/internal/keys"
)

func TestGenerateProducesBothKeys(t *testing.T) {
	k, err := keys.Generate("master")

	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k.RSAKeyID == "" || k.HMACKeyID == "" {
		t.Fatalf("want both key IDs set, got rsa=%q hmac=%q", k.RSAKeyID, k.HMACKeyID)
	}
	if k.RSAKeyID == k.HMACKeyID {
		t.Fatal("want distinct key IDs for the RSA and HMAC keys")
	}
}

func TestJWKSExposesOnlyThePublicRSAKey(t *testing.T) {
	// The HMAC key signs refresh tokens, which are opaque to clients. Publishing
	// it would hand out the ability to mint refresh tokens.
	k, err := keys.Generate("master")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	set := k.JWKS()

	if len(set.Keys) != 1 {
		t.Fatalf("want exactly one published key, got %d", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.KeyID != k.RSAKeyID {
		t.Fatalf("want key ID %q, got %q", k.RSAKeyID, jwk.KeyID)
	}
	if !jwk.IsPublic() {
		t.Fatal("want a public key in the JWKS, got a private one")
	}
	if jwk.Algorithm != "RS256" || jwk.Use != "sig" {
		t.Fatalf("want RS256/sig, got %s/%s", jwk.Algorithm, jwk.Use)
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
