package admin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/model"
)

// certificateRepresentation is Keycloak's CertificateRepresentation as the
// client-attribute-certificate endpoints emit it.
//
// Every field is omitempty and that is measured rather than tidy. One struct
// serialises four different shapes on a live 26.7.1, 2026-09-05:
//
//	GET .../certificates/{attr}                  {}                       (nothing stored)
//	GET .../certificates/{attr}                  {privateKey,certificate}
//	POST .../generate                            {privateKey,certificate}
//	POST .../upload-certificate                  {certificate}
//	POST /identity-provider/upload-certificate    {publicKey,certificate}
//
// So an absent value is absent and not "", which is the rule AGENTS.md already
// records for four token claims - and the empty object is a **200**, not a 404,
// on a client that has never generated a key and on an {attr} naming nothing.
//
// The field order is the emitted key order and is fixed by the struct rather
// than by a map: privateKey, publicKey, certificate. The two measured
// two-key shapes agree with it.
type certificateRepresentation struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// The two client attributes the chapter reads and writes. Measured: a generate
// on {attr} "jwt.credential" leaves exactly `jwt.credential.private.key` and
// `jwt.credential.certificate` on the client, and nothing else.
//
// {attr} is a free-form prefix rather than an enum. `my.prefix` was measured
// working and storing `my.prefix.private.key`, which is why nothing here
// validates it.
const (
	certPrivateKeySuffix  = ".private.key"
	certCertificateSuffix = ".certificate"
)

// certificateKeyBits is the RSA modulus size Keycloak generates here.
//
// **4096, not 2048**, measured 2026-09-05 by parsing what POST .../generate
// answered. It is deliberately not shared with internal/keys, whose realm keys
// are 2048: two different sizes for two different jobs, and a shared constant
// would be wrong on one of them.
const certificateKeyBits = 4096

// certificateBackdate is how far before the request a generated certificate's
// notBefore is placed. The validity itself is three **calendar** years, added
// with AddDate rather than as a duration: the measured window spanned 1096 days
// because 2028 is a leap year, and 3*365*24h would be a day short of it.
//
// Measured on two clean samples taken 2026-09-05 with the request time recorded
// alongside: notBefore came back 99.7 and 99.5 seconds *before* the request, and
// notAfter exactly three years after it. Nobody knows why Keycloak backdates it;
// it is reproduced rather than tidied away.
const certificateBackdate = 100 * time.Second

// readClientCertificate serves
// GET /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}.
//
// Measured: 200 with Cache-Control: no-cache, and view-clients is enough - the
// same rule the client-secret read follows. An {attr} that names nothing is
// 200 {} rather than a 404, on a client that has other attributes as well.
func (h *handler) readClientCertificate(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	writeAdminJSON(w, certificateOf(client, r.PathValue("attr")))
}

// certificateOf reads the two attributes {attr} names off a client.
func certificateOf(client *model.Client, attr string) certificateRepresentation {
	return certificateRepresentation{
		PrivateKey:  client.Attributes[attr+certPrivateKeySuffix],
		Certificate: client.Attributes[attr+certCertificateSuffix],
	}
}

// generateClientCertificate serves POST .../certificates/{attr}/generate.
//
// Measured: 200 with Cache-Control: no-cache, manage-clients required, and the
// response is the new key pair - which is also what the GET beside it answers
// afterwards, byte for byte, because both read the same two attributes.
//
// The response is minted per request in full, so its golden masks both values
// and asserts the status, every header, the two key names and their order. That
// is the whole-Location retreat's shape at body scale and it is named here
// rather than left to be discovered: what the golden cannot assert about the
// key is asserted by this package's own tests instead.
func (h *handler) generateClientCertificate(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	key, certDER, err := generateClientKeyPair(client.ClientID, time.Now())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	attr := r.PathValue("attr")
	if client.Attributes == nil {
		client.Attributes = map[string]string{}
	}
	// PKCS#1, not PKCS#8: measured by parsing what Keycloak answered, whose
	// first INTEGER is the version 0 of an RSAPrivateKey rather than a
	// PrivateKeyInfo's algorithm identifier.
	client.Attributes[attr+certPrivateKeySuffix] =
		base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key))
	client.Attributes[attr+certCertificateSuffix] = base64.StdEncoding.EncodeToString(certDER)
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeAdminJSON(w, certificateOf(client, attr))
}

// uploadClientCertificate serves POST .../certificates/{attr}/upload-certificate.
//
// Measured, and three of the four are Keycloak's own defects reproduced:
//
//   - 200 with the uploaded certificate re-encoded, and **no Cache-Control** -
//     which is what separates the three uploads from the four other operations
//     in this family.
//   - **The private key is deleted.** A client carrying both came back with
//     `{certificate}` alone afterwards, and its representation carried only
//     `jwt.credential.certificate`. Uploading a certificate is not a partial
//     update of the pair.
//   - A keystoreFormat other than "Certificate PEM" is a **500**, not a 400 or a
//     415. So is a body that will not parse as a certificate.
//   - A missing file part is `400 {"error":"file cannot be empty"}` and a
//     missing keystoreFormat is `400 {"error":"keystoreFormat cannot be null"}`,
//     with the format checked first.
func (h *handler) uploadClientCertificate(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	file, ok := certificateUpload(w, r)
	if !ok {
		return
	}
	certDER, err := parseUploadedCertificate(file)
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}
	attr := r.PathValue("attr")
	if client.Attributes == nil {
		client.Attributes = map[string]string{}
	}
	delete(client.Attributes, attr+certPrivateKeySuffix)
	client.Attributes[attr+certCertificateSuffix] = base64.StdEncoding.EncodeToString(certDER)
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, certificateOf(client, attr))
}

// uploadIdentityProviderCertificate serves
// POST /admin/realms/{realm}/identity-provider/upload-certificate.
//
// It is tagged Client Attribute Certificate and it is **not** a client route,
// and its guard follows the path rather than the tag: measured 2026-09-05,
// manage-identity-providers opens it and manage-clients is refused, where
// manage-clients opens every other operation in the tag. That is the fourth
// time the description's tag has failed to predict the guard - and it needs the
// *manage* role where six sibling reads under identity-provider take the view
// role, which is the shape AGENTS.md already records for reload-keys.
//
// It writes nothing. The 200 is the uploaded certificate's public key and the
// certificate itself, which is the whole of what it does.
func (h *handler) uploadIdentityProviderCertificate(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	file, ok := certificateUpload(w, r)
	if !ok {
		return
	}
	certDER, err := parseUploadedCertificate(file)
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}
	pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, certificateRepresentation{
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Certificate: base64.StdEncoding.EncodeToString(certDER),
	})
}

// certificateUploadMaxBytes bounds what ParseMultipartForm buffers in memory.
// A certificate is a couple of kilobytes; this is generous and still bounded.
const certificateUploadMaxBytes = 1 << 20

// certificateUpload reads the two multipart parts every upload in this family
// takes, writing the measured refusal and reporting false when it cannot.
//
// The order is measured and is not the order a reader would guess: a request
// with **no body at all** answers about the format, a request naming a format
// and carrying no file answers about the file, and a format that is not
// "Certificate PEM" is only rejected afterwards - as a 500, by the caller. So
// presence of the format comes first, presence of the file second, and the
// format's *value* last.
//
// A body that is not multipart at all - `application/json`, `{}` - answers the
// same "keystoreFormat cannot be null" 400 as no body, which is what lets this
// ignore ParseMultipartForm's error and fall through to the same refusal.
func certificateUpload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	_ = r.ParseMultipartForm(certificateUploadMaxBytes)
	if r.FormValue("keystoreFormat") == "" {
		httpx.WriteMessageError(w, http.StatusBadRequest, "keystoreFormat cannot be null")
		return nil, false
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		httpx.WriteMessageError(w, http.StatusBadRequest, "file cannot be empty")
		return nil, false
	}
	defer func() { _ = file.Close() }()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(body) < certificateUploadMaxBytes {
		n, err := file.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	if len(body) == 0 {
		httpx.WriteMessageError(w, http.StatusBadRequest, "file cannot be empty")
		return nil, false
	}
	return body, true
}

// writeCertificateUploadFailure is what every way of handing these endpoints
// something they cannot read answers.
//
// It is a 500 and that is Keycloak's, measured on four inputs: a keystoreFormat
// of "JKS", of "Public Key PEM" and of "bogus", and a file that is not a
// certificate. Answering 400 here would be the better HTTP and an observable
// difference, which is the one thing this project cannot afford. It is the same
// body deleteRotatedSecretRejection sends for the same reason.
func writeCertificateUploadFailure(w http.ResponseWriter) {
	httpx.WriteOAuthError(w, http.StatusInternalServerError, "unknown_error",
		"For more on this error consult the server log.")
}

// parseUploadedCertificate turns the uploaded file into certificate DER.
//
// **The armour is optional**, measured: the same certificate was accepted both
// as a `-----BEGIN CERTIFICATE-----` block and as bare base64 with no armour and
// no line breaks, answering byte-identical bodies. So this decodes a PEM block
// when there is one and base64 with the whitespace removed when there is not,
// rather than requiring the header a reader would expect from the format's name.
func parseUploadedCertificate(file []byte) ([]byte, error) {
	if block, _ := pem.Decode(file); block != nil {
		return validCertificateDER(block.Bytes)
	}
	bare := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, string(file))
	der, err := base64.StdEncoding.DecodeString(bare)
	if err != nil {
		return nil, err
	}
	return validCertificateDER(der)
}

func validCertificateDER(der []byte) ([]byte, error) {
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	return der, nil
}

// generateClientKeyPair mints what POST .../generate answers.
//
// Every parameter is measured from a live 26.7.1 on 2026-09-05 by parsing the
// certificate it returned, never written from memory:
//
//	RSA 4096                    Public-Key: (4096 bit)
//	X.509 **version 1**         Version: 1 (0x0), and no extensions
//	serial                      the request's millisecond epoch
//	sha256WithRSAEncryption
//	issuer == subject == CN=<the client's clientId>
//	notBefore                   the request, less 100 seconds
//	notAfter                    the request, plus three years
//
// **Version 1 is why this does not use x509.CreateCertificate.** Go's builder
// emits a v3 TBSCertificate unconditionally, so reproducing Keycloak's v1 means
// assembling the SEQUENCE here. The difference is client-observable: the
// certificate this returns is the one a relying party parses.
func generateClientKeyPair(clientID string, now time.Time) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, certificateKeyBits)
	if err != nil {
		return nil, nil, err
	}
	der, err := selfSignedV1(key, clientID, now)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// v1TBSCertificate is RFC 5280's TBSCertificate with the [0] version field
// **left out**, which is what makes it a v1 certificate: the field is
// DEFAULT v1, and a v1 certificate omits it rather than encoding a zero.
type v1TBSCertificate struct {
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           v1Validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
}

type v1Validity struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

type v1Certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// oidSHA256WithRSA is 1.2.840.113549.1.1.11.
var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

func selfSignedV1(key *rsa.PrivateKey, commonName string, now time.Time) ([]byte, error) {
	name := pkix.Name{CommonName: commonName}.ToRDNSequence()
	nameDER, err := asn1.Marshal(name)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	// asn1.NULL parameters, which is what an RSA AlgorithmIdentifier carries and
	// what Keycloak's certificate was measured holding.
	alg := pkix.AlgorithmIdentifier{
		Algorithm:  oidSHA256WithRSA,
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	}
	tbs := v1TBSCertificate{
		// The serial is the request's epoch in milliseconds, which is why two
		// certificates minted a second apart do not collide and why nothing here
		// is random.
		SerialNumber:       big.NewInt(now.UnixMilli()),
		SignatureAlgorithm: alg,
		Issuer:             asn1.RawValue{FullBytes: nameDER},
		Validity: v1Validity{
			NotBefore: now.Add(-certificateBackdate).UTC(),
			NotAfter:  now.AddDate(3, 0, 0).UTC(),
		},
		Subject:   asn1.RawValue{FullBytes: nameDER},
		PublicKey: asn1.RawValue{FullBytes: pubDER},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	signature, err := signTBS(key, tbsDER)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(v1Certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: alg,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

// signTBS signs the encoded TBSCertificate the way sha256WithRSAEncryption
// says to: PKCS#1 v1.5 over a SHA-256 digest.
func signTBS(key *rsa.PrivateKey, tbsDER []byte) ([]byte, error) {
	digest := sha256.Sum256(tbsDER)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
}
