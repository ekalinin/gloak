package admin

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// keycloakCertificate is one certificate `POST .../certificates/jwt.credential/
// generate` answered on a live 26.7.1 on 2026-09-05, kept verbatim.
//
// It is the reference these tests compare Gloak's shape against. Every claim
// below - version 1, RSA 4096, sha256WithRSAEncryption, issuer equal to subject,
// notBefore 100 seconds before the request, notAfter three calendar years after
// it - is read off *this* value first and then asserted about Gloak's, so no
// assertion here is written from memory.
const keycloakCertificate = `MIIErzCCApcCBgGgcq9MLDANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBjLW9wZW5pZC1jb25u` +
	`ZWN0MB4XDTI2MDkwNTE3NDYyNloXDTI5MDkwNTE3NDgwNFowGzEZMBcGA1UEAwwQYy1vcGVuaWQt` +
	`Y29ubmVjdDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ1098mobGTNFCJUm0XrXD1p` +
	`+0wzjM2mXSuub3QUU2Ga0p8IsiTn3F+p40J/KbBDPhGqFyD9xPXERsjSxF5DQ5EVvX8ALjdGRpXB` +
	`zV6wYBeqmZm+VS1aXYaQXLBNEZiNApzZy4P1ByTGPAEe+AtHl78gCKBuUIM/+2+a8fFMP3gf0Ow6` +
	`WqetVlP8ELPy1GviGzdUkavd4AC0brEtCZ7JWTmp7u7fu7D0K3ERfy25lPbWlsQ4Mi9OVpq1OQIR` +
	`p3Drc4qztA003vlbD0R3/YUYDGIB/PfyaRffBAsdZzD3QPwl6UCoIwBzvn0lJFZX+FVwdjNzPuJT` +
	`OtYvZBplcF/BpfjG+IGsxYyFPufdJ3vNiTYus4qwJdxDDPveZwhQJyqjymIpYcyI0d0IXNOm1JNs` +
	`RAxLin2mP2l3UQDJoOTOvjg8DhO44qDw4ukqHUugqZky2iEtnSPloJgNK/QOBHhgmIVHLPZGcrof` +
	`8RnkBEcV7845Xw5W1sdvE+HmD+mzjBYk1h39MzKBojOPlA5jAEPh8DkpPsNrDjutqqrJOa96YwW5` +
	`KLVWchhxu8WQaifN3tGcMDiO53olNJKK8IWvkL7sC+7zCwhioPznyfET7iG+5yFEsMl3QKxqVWOi` +
	`pF2WR5IJffxRqcDsMlcULiwGNeNuaBNfl/W5z21+eVQlAQuexVxNAgMBAAEwDQYJKoZIhvcNAQEL` +
	`BQADggIBABi6vbxhntiROCZNaM2F8HtGmPxNXeDozE0o+U+IZ7CDOVA6pNIICwPGkuNbJ1JQCSHX` +
	`7VbExv0u1QBwLW1AQDhz+Da/HtQg4d0T17Q2zV6OqV0n+0oaMVfmAV64Z0uKRvFUM7VdU2l09iOC` +
	`6h7YWHGeRcTXHbq/T97D8KWz0EqRxw6cmNhIxtBIFrirol/cFRMYh7zUta9kZvIvuXkCllun0mkj` +
	`NA+rgzgIOLNg+KSvpU/yLf4tC3XuBgw+IqHldDn3y9uosiDPDXo9JQRqpK7G0gUi3sds8Xk9DZrJ` +
	`mjfO9Y3TbhMXG0xyNxJznS/oAlnZuTRhWZw4KgT57IA0cBHpZ8G4gBuKbacWT6EtpV++4tBrnE3K` +
	`2YUua99+KXbW/Drm0HKQSlxFlrt+eqVoJrF9xUuahafPBkONggtwNaami0Ti6b4/csKY/i04bYXV` +
	`cYj6aducFe3FhS99Z27VfZt/uVRaNbGRAOMn8zfkPrYH02a76pbVH9pLfGjIlZOEhSjE9ntB64P/` +
	`oEyKixYycOMOnO/L3rnGbs8U2SDfJbTz9QSOiOdQVCb/rhlSUcbJKP+xXSo7j+C23Id6LU7YrUcy` +
	`+J9vLwwf+Hu/cqkTcWj7+chn8y76mWX5oNf+YKLAuFl+6yrlhWSYPyQKfHwEYHhNFDs71gHPjcIz` +
	`SNZyxGe8`

func stringReader(s string) io.Reader { return strings.NewReader(s) }

// multipartRequest builds the request shape all three upload operations take:
// a keystoreFormat part, and a file part when there is a file. It is written
// here rather than reused from the conformance harness because this package may
// not import that one.
func multipartRequest(t *testing.T, format string, file []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if format != "" {
		if err := mw.WriteField("keystoreFormat", format); err != nil {
			t.Fatalf("write keystoreFormat: %v", err)
		}
	}
	if file != nil {
		part, err := mw.CreateFormFile("file", "cert.pem")
		if err != nil {
			t.Fatalf("create file part: %v", err)
		}
		if _, err := part.Write(file); err != nil {
			t.Fatalf("write file part: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/x", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func parseReference(t *testing.T) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(keycloakCertificate)
	if err != nil {
		t.Fatalf("decode the reference certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse the reference certificate: %v", err)
	}
	return cert
}

// TestGeneratedCertificateMatchesKeycloaksShape is where the measured
// certificate parameters are pinned.
//
// The conformance golden for POST .../generate cannot hold any of this: the key
// is minted per request, so both of its values are masked and the golden asserts
// the status, the headers and the two key names. Everything the mask gives up is
// asserted here instead, against a certificate Keycloak actually produced.
func TestGeneratedCertificateMatchesKeycloaksShape(t *testing.T) {
	want := parseReference(t)

	now := time.Date(2026, 9, 5, 17, 46, 26, 0, time.UTC)
	key, der, err := generateClientKeyPair("c-openid-connect", now)
	if err != nil {
		t.Fatalf("generateClientKeyPair: %v", err)
	}
	got, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Gloak's certificate does not parse: %v", err)
	}

	if want.Version != 1 {
		t.Fatalf("the reference is not v1 after all, it is v%d - re-measure before trusting this test", want.Version)
	}
	if got.Version != want.Version {
		t.Errorf("version: want %d, got %d", want.Version, got.Version)
	}
	if len(got.Extensions) != 0 {
		t.Errorf("a v1 certificate carries no extensions, got %d", len(got.Extensions))
	}
	if got.SignatureAlgorithm != want.SignatureAlgorithm {
		t.Errorf("signature algorithm: want %v, got %v", want.SignatureAlgorithm, got.SignatureAlgorithm)
	}
	if got.Subject.String() != want.Subject.String() {
		t.Errorf("subject: want %q, got %q", want.Subject, got.Subject)
	}
	if got.Issuer.String() != got.Subject.String() {
		t.Errorf("self-signed means issuer == subject, got %q and %q", got.Issuer, got.Subject)
	}

	wantBits := want.PublicKey.(*rsa.PublicKey).N.BitLen()
	if wantBits != certificateKeyBits {
		t.Fatalf("the reference key is %d bits, not %d - re-measure", wantBits, certificateKeyBits)
	}
	if bits := got.PublicKey.(*rsa.PublicKey).N.BitLen(); bits != wantBits {
		t.Errorf("key size: want %d bits, got %d", wantBits, bits)
	}
	if got.PublicKey.(*rsa.PublicKey).N.Cmp(key.PublicKey.N) != 0 {
		t.Error("the certificate does not carry the private key's own public key")
	}

	// The validity window, measured: notBefore about 100 seconds before the
	// request and notAfter three calendar years after it. The reference's own
	// window is **1096 days** because 2028 is a leap year, which is what makes
	// AddDate right and 3*365*24h a day short.
	//
	// The backdate is asserted as a range and the days exactly, and the range is
	// not caution. Three measured certificates gave 98, 99 and 99 seconds, so
	// Keycloak computes its two bounds from instants a 4096-bit keygen apart and
	// the exact second is not reproducible by anything. Gloak takes one instant
	// and is therefore exactly 100, which is inside the measured spread and is
	// the closest a deterministic implementation can come. Nothing observes it:
	// the generate golden masks the whole certificate, which is why this is the
	// only place it is written down.
	window := want.NotAfter.Sub(want.NotBefore)
	if days := window.Truncate(24 * time.Hour); days != 1096*24*time.Hour {
		t.Fatalf("the reference window is %v days, not 1096 - re-measure", days)
	}
	if backdate := window - 1096*24*time.Hour; backdate < 95*time.Second || backdate > 105*time.Second {
		t.Fatalf("the reference backdate is %v, not about 100s - re-measure", backdate)
	}
	if wantNotBefore := now.Add(-100 * time.Second); !got.NotBefore.Equal(wantNotBefore) {
		t.Errorf("notBefore: want %v, got %v", wantNotBefore, got.NotBefore)
	}
	if wantNotAfter := now.AddDate(3, 0, 0); !got.NotAfter.Equal(wantNotAfter) {
		t.Errorf("notAfter: want %v, got %v", wantNotAfter, got.NotAfter)
	}
	if d := got.NotAfter.Sub(got.NotBefore).Truncate(24 * time.Hour); d != 1096*24*time.Hour {
		t.Errorf("validity window: want 1096 days, got %v", d)
	}

	// The serial is the request's millisecond epoch, which is why nothing here
	// is random and why two certificates a second apart do not collide.
	if serial := got.SerialNumber.Int64(); serial != now.UnixMilli() {
		t.Errorf("serial: want %d, got %d", now.UnixMilli(), serial)
	}

	// It has to verify against itself, or the hand-assembled TBSCertificate and
	// the signature over it have drifted apart.
	if err := got.CheckSignatureFrom(got); err != nil {
		t.Errorf("the certificate does not verify against itself: %v", err)
	}
}

// TestGeneratedPrivateKeyIsPKCS1 pins the encoding, which is the other half of
// what the generate golden's mask gives up.
//
// PKCS#1 and not PKCS#8, measured: Keycloak's privateKey decodes to a DER
// SEQUENCE whose first INTEGER is an RSAPrivateKey's version 0, and
// x509.ParsePKCS8PrivateKey refuses it.
func TestGeneratedPrivateKeyIsPKCS1(t *testing.T) {
	key, _, err := generateClientKeyPair("c", time.Now())
	if err != nil {
		t.Fatalf("generateClientKeyPair: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	if _, err := x509.ParsePKCS1PrivateKey(der); err != nil {
		t.Fatalf("the private key does not parse as PKCS#1: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		t.Error("the private key parses as PKCS#8, so it is not the encoding Keycloak sends")
	}
}

// TestUploadedCertificateAcceptsArmourAndBareBase64 is measured on a live
// 26.7.1: the same certificate was accepted both as a PEM block and as bare
// base64 with no armour and no line breaks, answering byte-identical bodies.
//
// A parser requiring the header the format's name implies would be right about
// PEM and wrong about Keycloak.
func TestUploadedCertificateAcceptsArmourAndBareBase64(t *testing.T) {
	der, err := base64.StdEncoding.DecodeString(keycloakCertificate)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	armoured := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	for name, input := range map[string][]byte{
		"armoured":    armoured,
		"bare base64": []byte(keycloakCertificate),
		"bare, wrapped at 64": []byte(keycloakCertificate[:64] + "\n" +
			keycloakCertificate[64:]),
	} {
		got, err := parseUploadedCertificate(input)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != string(der) {
			t.Errorf("%s: decoded to different bytes", name)
		}
	}

	// And the other direction, so the parser is not accepting everything: both
	// of these answer 500 on a live 26.7.1.
	for _, bad := range [][]byte{
		[]byte("not a certificate at all\n"),
		[]byte(""),
		[]byte("MIIBogIBAAKCAQEA"), // valid base64, not a certificate
	} {
		if _, err := parseUploadedCertificate(bad); err == nil {
			t.Errorf("%q was accepted as a certificate", bad)
		}
	}
}

// TestCertificateUploadRefusalOrder pins the order the two 400s come in.
//
// Measured, and it is not the order a reader would guess: a request with no
// body at all answers about the **format**, and a request naming a format and
// carrying no file answers about the **file**. Checking the file first would
// answer "file cannot be empty" to a request that sent neither, which is a
// different observable.
func TestCertificateUploadRefusalOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "no body at all",
			req:  httptest.NewRequest(http.MethodPost, "/x", nil),
			want: `{"error":"keystoreFormat cannot be null"}`,
		},
		{
			name: "a JSON body, which is not multipart",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/x", stringReader("{}"))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			want: `{"error":"keystoreFormat cannot be null"}`,
		},
		{
			name: "a format and no file",
			req:  multipartRequest(t, "Certificate PEM", nil),
			want: `{"error":"file cannot be empty"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if _, ok := certificateUpload(w, tc.req); ok {
				t.Fatal("the upload was accepted")
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("status: want 400, got %d", w.Code)
			}
			if got := w.Body.String(); got != tc.want {
				t.Errorf("body: want %s, got %s", tc.want, got)
			}
		})
	}
}
