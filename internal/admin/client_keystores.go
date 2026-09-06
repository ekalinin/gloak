package admin

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ekalinin/gloak/internal/httpx"
	"github.com/ekalinin/gloak/internal/keystore"
	"github.com/ekalinin/gloak/internal/model"
)

// The three keystore operations of the Client Attribute Certificate tag:
// download, generate-and-download and upload. Everything in this file was
// measured against a live Keycloak 26.7.1 on 2026-09-06; see
// docs/superpowers/handover/certificate-remainder.md.
//
// # The two downloads are served and counted by nothing
//
// Their body is a keystore, and a keystore is different bytes on every request
// - twelve requests gave twelve bodies for each of six combinations - so no
// golden can hold one and `internal/conformance`'s RefuseNonTextBody says so
// where it can fail. A case without a golden cannot be Implemented and an
// operation without an Implemented case does not move the parity meter. That is
// the honest state rather than a defect: what **is** stable about these two
// responses is the status, the media type, the four security headers and the
// two headers that are absent, and TestKeystoreDownloadHeaders asserts every
// one of those here, which is the same bargain `generate` already makes.
//
// # BCFKS is the one divergence in this file
//
// Keycloak accepts three formats and this serves two. The third is
// BouncyCastle's FIPS keystore, whose payload is AES-256-CCM keyed by
// PBKDF2-HMAC-SHA512 inside a schema published nowhere but BouncyCastle's own
// source, and Go has no CCM. Gloak answers the 500 it answers for a lower-case
// format rather than editing the 406's body, which is a measured contract that
// lists BCFKS as supported.

// keystoreRequest is the JSON body the two downloads take.
//
// Every field is a pointer because **absent and empty are different answers**,
// measured on all four:
//
//	format absent or null       500 unknown_error
//	keyAlias absent             the alias is the client's clientId
//	keyAlias empty              the alias is the empty string, and the store holds it
//	keyPassword empty           accepted, and protects the key with ""
//	storePassword absent/null   400 password-missing
//
// A struct of plain strings collapses the first two rows of each pair.
type keystoreRequest struct {
	Format        *string `json:"format"`
	KeyAlias      *string `json:"keyAlias"`
	KeyPassword   *string `json:"keyPassword"`
	StorePassword *string `json:"storePassword"`
}

// The three formats the endpoints name, spelled as the 406 spells them.
const (
	keystoreFormatJKS    = "JKS"
	keystoreFormatPKCS12 = "PKCS12"
	keystoreFormatBCFKS  = "BCFKS"
)

// keystoreFormatsRefusal is the 406's body, byte for byte.
//
// **The order is Keycloak's and it is stable**: ten requests on one container
// and one more after a restart all answered `[PKCS12, JKS, BCFKS]`. It is not
// alphabetical and it is not the order this file declares the constants in,
// which is why it is written out rather than joined from a slice.
//
// The comparison is **case-sensitive**: `jks` is a 500 rather than a 406, which
// is how the first probe of this chapter came to report one answer for four
// different inputs.
const keystoreFormatsRefusal = "Not supported keystore format. " +
	"Supported keystore formats: [PKCS12, JKS, BCFKS]"

// downloadClientKeystore serves
// POST /admin/realms/{realm}/clients/{client-uuid}/certificates/{attr}/download.
//
// It writes nothing - measured, the stored pair is unchanged afterwards - which
// is why its guard is the **view** role where its generate-and-download sibling
// takes the manage one. It is the first POST in this API measured opened by a
// read role, and the split inside the pair is whether the operation writes
// rather than the verb.
func (h *handler) downloadClientKeystore(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	req, ok := decodeKeystoreRequest(w, r)
	if !ok {
		return
	}
	format, ok := keystoreFormatOf(w, req)
	if !ok {
		return
	}
	pair := certificateOf(client, r.PathValue("attr"))
	// **The certificate decides, not the key.** A client holding a certificate
	// and no private key - which is what upload-certificate and
	// generate-and-download both leave behind - answers 200 with a store of two
	// trusted certificates. A client holding neither answers this 404, and the
	// spelling is a thirty-sixth for AGENTS.md's list.
	if pair.Certificate == "" {
		httpx.WriteMessageError(w, http.StatusNotFound, "keypair not generated for client")
		return
	}
	if !requireKeystorePasswords(w, req, pair.PrivateKey != "", "download") {
		return
	}
	h.writeKeystore(w, r, rc, client, pair, format, req)
}

// generateAndDownloadClientKeystore serves .../generate-and-download.
//
// **It deletes the private key.** Measured twice: after it, the client's
// attributes hold `<attr>.certificate` and no `<attr>.private.key`, and the GET
// beside it answers `{certificate}` alone - while the keystore the caller is
// handed holds the key. The server generates a pair, gives the whole of it
// away, and keeps only the certificate. An implementation that stored the pair
// would pass every other case in this chapter.
//
// Both passwords are always required here, where download requires the key
// password only when there is a key, because this always mints one. The
// descriptions differ from download's by their last three words and are
// measured, not composed.
func (h *handler) generateAndDownloadClientKeystore(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	req, ok := decodeKeystoreRequest(w, r)
	if !ok {
		return
	}
	format, ok := keystoreFormatOf(w, req)
	if !ok {
		return
	}
	if !requireKeystorePasswords(w, req, true, "generation and download") {
		return
	}
	key, certDER, err := generateClientKeyPair(client.ClientID, time.Now())
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	pair := storedKeyPair(key, certDER)

	attr := r.PathValue("attr")
	if client.Attributes == nil {
		client.Attributes = map[string]string{}
	}
	delete(client.Attributes, attr+certPrivateKeySuffix)
	client.Attributes[attr+certCertificateSuffix] = pair.Certificate
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	h.writeKeystore(w, r, rc, client, pair, format, req)
}

// uploadClientKeystore serves .../upload.
//
// **It needs the whole keystore, the private key included.** The measurement
// that settles it: a JKS Keycloak itself produced came back as the byte
// identical PKCS#1 base64 that the generate had answered for that client, and
// the pair is then stored. There is no smaller job here than a reader - see
// internal/keystore, which is written rather than taken because the obvious
// dependency cannot read the bytes this endpoint receives.
//
// The refusals are measured and their order is measured with them, each pair
// decided by a request wrong in exactly two ways beside a control wrong in one:
//
//	unknown client                     404 Could not find client
//	keystoreFormat absent              400 keystoreFormat cannot be null
//	no file part                       400 file cannot be empty
//	keyAlias absent                    500 unknown_error - before the store is read
//	Certificate PEM, Public Key PEM    500 unknown_error
//	a file that is not its format      400 error loading keystore
//	JKS, wrong storePassword           400 Password verification failed
//	PKCS12, wrong storePassword        400 PKCS12 key store mac invalid
//	PKCS12, no storePassword           400 error loading keystore
//	an alias the store does not hold   400 certificate-not-found
//
// **A wrong key password is not a refusal.** On a JKS it answers 200 with the
// certificate alone and the key silently dropped, measured on a wrong password
// and an absent one; on a PKCS12 the key password is not used at all, because
// that format's key bag opens with the store password.
func (h *handler) uploadClientKeystore(w http.ResponseWriter, r *http.Request, rc *reqContext) {
	client, ok := h.clientFromPath(w, r, rc)
	if !ok {
		return
	}
	file, ok := keystoreUpload(w, r)
	if !ok {
		return
	}
	// The alias is read before the file is, which is the measured order: a
	// request with no keyAlias and a file that is not a keystore answers about
	// the alias.
	alias := r.FormValue("keyAlias")
	if _, present := r.Form["keyAlias"]; !present {
		writeCertificateUploadFailure(w)
		return
	}
	store, err := readUploadedKeystore(file, r.FormValue("keystoreFormat"), r.FormValue("storePassword"))
	if err != nil {
		writeKeystoreReadFailure(w, err, r.FormValue("keystoreFormat"))
		return
	}
	entry, found := store.Lookup(alias)
	if !found {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "certificate-not-found",
			"Certificate or key with given alias not found in the keystore")
		return
	}
	pair, err := keystoreEntryAsStored(entry, r.FormValue("keyPassword"))
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}

	attr := r.PathValue("attr")
	if client.Attributes == nil {
		client.Attributes = map[string]string{}
	}
	if pair.PrivateKey == "" {
		delete(client.Attributes, attr+certPrivateKeySuffix)
	} else {
		client.Attributes[attr+certPrivateKeySuffix] = pair.PrivateKey
	}
	client.Attributes[attr+certCertificateSuffix] = pair.Certificate
	if err := h.store.Clients().Update(r.Context(), client); err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	httpx.WriteJSONCharset(w, http.StatusOK, certificateOf(client, attr))
}

// decodeKeystoreRequest reads the two downloads' JSON body.
//
// Three refusals, all measured, and the third is not the one
// writeCannotParseJSON makes:
//
//	a Content-Type that is not application/json or */*, and an absent one
//	                              415 The content-type header value did not match the value in @Consumes
//	`{`                           400 invalid_request / Cannot parse the JSON
//	`[]`, `"x"`                   400 unknown_error   / Cannot parse the JSON
//
// So the code separates **syntax from binding** here - a body that is not JSON
// at all against one that is JSON of the wrong shape - which is what F163
// settled on `partialImport` and is a third family measured agreeing with it.
// writeCannotParseJSON splits on a leading `[` instead and is right on `[]` and
// wrong on `"x"`, so it is not reused: a rule about a code four families produce
// should not be rewritten from a fifth, and neither should a fifth borrow it.
//
// An **empty** body is not handled here at all. It answers 500 unknown_error
// with the consult-the-log description, which is the same answer an absent
// `format` gets, so it falls through to keystoreFormatOf rather than being
// caught twice.
func decodeKeystoreRequest(w http.ResponseWriter, r *http.Request) (keystoreRequest, bool) {
	var req keystoreRequest
	if !requireKeystoreJSONBody(w, r) {
		return req, false
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return req, false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return req, true
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		code := "unknown_error"
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			code = "invalid_request"
		}
		httpx.WriteOAuthError(w, http.StatusBadRequest, code, "Cannot parse the JSON")
		return req, false
	}
	return req, true
}

// requireKeystoreJSONBody is the media-type check the two downloads make.
//
// It is **not** requireJSONBody, which accepts an absent Content-Type: measured
// on this route, a request with no Content-Type at all is a 415 where the same
// body with `application/json` is served. `*/*` is accepted, the spelling folds
// case, and the parameters are ignored - `application/json; charset=UTF-8` with
// a space is served where `text/json` is refused.
func requireKeystoreJSONBody(w http.ResponseWriter, r *http.Request) bool {
	media := strings.ToLower(strings.TrimSpace(
		strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if media == "application/json" || media == "*/*" {
		return true
	}
	httpx.WriteMessageError(w, http.StatusUnsupportedMediaType,
		"The content-type header value did not match the value in @Consumes")
	return false
}

// keystoreFormatOf resolves the requested format, or writes the refusal.
//
// The 406 comes **before** everything else the body says and before the state
// of the client: a request with a bogus format and no store password answers
// about the format, and so does one against a client with no key pair at all.
//
// **There are two checks and they disagree about case.** Measured over fifteen
// spellings:
//
//	JKS, PKCS12, BCFKS                 200
//	jks, Jks, jKs, pkcs12, bcfks       500 unknown_error
//	bogus, BOGUS, "", " JKS", "JKS "   406
//	absent or null                     500 unknown_error
//
// So the membership test that produces the 406 **folds case**, and the code
// after it does not: a lower-case spelling of a real format passes the first
// and fails the second. Nothing is trimmed either, so a leading space makes a
// real format unrecognised. That pair of facts is what makes `jks` and `bogus`
// two different answers, and it is why this is two switches rather than one -
// a single case-sensitive membership test answers 406 for `jks`, which was the
// first version of this function and is wrong.
func keystoreFormatOf(w http.ResponseWriter, req keystoreRequest) (string, bool) {
	if req.Format == nil {
		writeCertificateUploadFailure(w)
		return "", false
	}
	switch strings.ToUpper(*req.Format) {
	case keystoreFormatJKS, keystoreFormatPKCS12, keystoreFormatBCFKS:
	default:
		httpx.WriteMessageError(w, http.StatusNotAcceptable, keystoreFormatsRefusal)
		return "", false
	}
	switch *req.Format {
	case keystoreFormatJKS, keystoreFormatPKCS12:
		return *req.Format, true
	}
	// Everything left is either a real format spelled in the wrong case, or
	// BCFKS - which is **the divergence**. See this file's opening comment:
	// Keycloak answers a keystore for BCFKS and Gloak cannot write one, so it
	// answers the 500 this route already produces for `jks` rather than editing
	// the 406's body, which is a measured contract listing BCFKS as supported.
	writeCertificateUploadFailure(w)
	return "", false
}

// requireKeystorePasswords writes the measured `password-missing` refusals.
//
// Two things about it are Keycloak's own and are reproduced rather than tidied.
// The description says **`jks`** whatever format was asked for, measured on all
// three; and the key password is checked **before** the store password, so a
// request sending neither answers about the key.
//
// hasKey is what makes the key password conditional, and it is the endpoint's
// rule rather than a convenience: a client holding a certificate and no private
// key is served without a key password, and the same request against a client
// holding a pair is a 400. Measured on both, on a client made cert-only through
// upload-certificate rather than by editing its attributes - a PUT on a client
// merges, so the obvious way of arranging that state does not arrange it.
func requireKeystorePasswords(w http.ResponseWriter, req keystoreRequest, hasKey bool, operation string) bool {
	if hasKey && req.KeyPassword == nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "password-missing",
			"Need to specify a key password for jks "+operation)
		return false
	}
	if req.StorePassword == nil {
		httpx.WriteOAuthError(w, http.StatusBadRequest, "password-missing",
			"Need to specify a store password for jks "+operation)
		return false
	}
	return true
}

// writeKeystore builds the keystore and hands it over.
//
// **It holds two entries, not one**: the client's pair under the caller's alias
// and **the realm's own certificate under the realm's name** as a trusted
// certificate - `master` in master and `certprobe` in a realm called certprobe,
// measured on both. A store holding only the client's pair would be a keystore
// a client could use and not the one Keycloak sends.
func (h *handler) writeKeystore(w http.ResponseWriter, r *http.Request, rc *reqContext,
	client *model.Client, pair certificateRepresentation, format string, req keystoreRequest) {

	// An absent alias is the clientId and an empty one is the empty string,
	// which the store then really holds under that name.
	alias := client.ClientID
	if req.KeyAlias != nil {
		alias = *req.KeyAlias
	}
	// An alias equal to the realm's is a 500 on Keycloak - the two entries
	// collide - and it is reproduced rather than resolved, because resolving it
	// would put a store on the wire that Keycloak never sends.
	if alias == rc.realm.Name {
		writeCertificateUploadFailure(w)
		return
	}
	keys, err := h.keys.ForRealm(r.Context(), rc.realm)
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	entry, err := keystoreEntryOf(alias, pair)
	if err != nil {
		writeCertificateUploadFailure(w)
		return
	}
	now := time.Now()
	entry.CreatedAt = now
	store := &keystore.Store{Entries: []keystore.Entry{entry, {
		Alias:     rc.realm.Name,
		CreatedAt: now,
		Chain:     [][]byte{keys.CertificateDER()},
	}}}

	var body []byte
	if format == keystoreFormatPKCS12 {
		body, err = keystore.WritePKCS12(store, deref(req.StorePassword))
	} else {
		body, err = keystore.WriteJKS(store, deref(req.StorePassword), deref(req.KeyPassword))
	}
	if err != nil {
		httpx.WriteMessageError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	writeKeystoreDownload(w, body)
}

// keystoreEntryOf turns the two stored attributes into one keystore entry.
//
// A client with a private key becomes a key entry whose chain is its own
// certificate; a client with the certificate alone becomes a **trusted
// certificate entry** under the same alias, which is what a store downloaded
// after an upload-certificate was measured holding - two trusted certificates
// and no key entry at all.
func keystoreEntryOf(alias string, pair certificateRepresentation) (keystore.Entry, error) {
	certDER, err := base64.StdEncoding.DecodeString(pair.Certificate)
	if err != nil {
		return keystore.Entry{}, err
	}
	entry := keystore.Entry{Alias: alias, Chain: [][]byte{certDER}}
	if pair.PrivateKey == "" {
		return entry, nil
	}
	pkcs1, err := base64.StdEncoding.DecodeString(pair.PrivateKey)
	if err != nil {
		return keystore.Entry{}, err
	}
	// The attribute holds PKCS#1, which is what the API answers; a keystore
	// holds PKCS#8. See storedKeyPair for where the first of those is measured.
	key, err := x509.ParsePKCS1PrivateKey(pkcs1)
	if err != nil {
		return keystore.Entry{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return keystore.Entry{}, err
	}
	entry.PrivateKey = pkcs8
	return entry, nil
}

// keystoreEntryAsStored is keystoreEntryOf's inverse: what upload writes onto
// the client, in the encodings the two attributes hold.
//
// The key password reaches only the JKS half, because a PKCS12's key bag is
// already open by the time the store is read - the two formats protect a key
// with different passwords and internal/keystore says which in its types. A key
// that will not unlock is **not** an error: the certificate is kept and the key
// dropped, which is the 200 Keycloak answers for a wrong key password.
func keystoreEntryAsStored(e keystore.Entry, keyPassword string) (certificateRepresentation, error) {
	certDER, ok := e.Certificate()
	if !ok {
		return certificateRepresentation{}, errors.New("admin: the keystore entry carries no certificate")
	}
	out := certificateRepresentation{Certificate: base64.StdEncoding.EncodeToString(certDER)}

	pkcs8 := e.PrivateKey
	if pkcs8 == nil && e.ProtectedKey != nil {
		unlocked, err := keystore.UnlockJKSKey(e.ProtectedKey, keyPassword)
		if err != nil {
			return out, nil
		}
		pkcs8 = unlocked
	}
	if pkcs8 == nil {
		return out, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return out, nil
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		// Every key this chapter mints is RSA, and what a non-RSA one is
		// stored as has not been measured. Keeping the certificate and dropping
		// the key is the same retreat a key that will not unlock makes.
		return out, nil
	}
	out.PrivateKey = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(rsaKey))
	return out, nil
}

// readUploadedKeystore parses what the caller sent, in the format it declared.
func readUploadedKeystore(file []byte, format, storePassword string) (*keystore.Store, error) {
	switch format {
	case keystoreFormatJKS:
		return keystore.ReadJKS(file, storePassword)
	case keystoreFormatPKCS12:
		return keystore.ReadPKCS12(file, storePassword)
	case "Certificate PEM", "Public Key PEM":
		// Measured: this endpoint answers 500 for the two formats its
		// upload-certificate sibling takes, rather than the 400 an unreadable
		// keystore gets. It is a different refusal for a different mistake.
		return nil, errKeystoreWrongFamily
	}
	// **An unrecognised format here is not the download's 406.** Measured:
	// `bogus` and `jks` both answer `400 error loading keystore` on this route,
	// where the same spellings on the download answer 406 and 500. One tag, two
	// families, three answers for an unknown format.
	return nil, keystore.ErrMalformed
}

var errKeystoreWrongFamily = errors.New("admin: that format belongs to upload-certificate")

// writeKeystoreReadFailure is the measured refusal for each way a keystore
// cannot be read, and the two formats do not answer the same one.
func writeKeystoreReadFailure(w http.ResponseWriter, err error, format string) {
	switch {
	case errors.Is(err, errKeystoreWrongFamily):
		writeCertificateUploadFailure(w)
	case errors.Is(err, keystore.ErrPasswordVerification) && format == keystoreFormatPKCS12:
		httpx.WriteMessageError(w, http.StatusBadRequest, "PKCS12 key store mac invalid")
	case errors.Is(err, keystore.ErrPasswordVerification):
		httpx.WriteMessageError(w, http.StatusBadRequest, "Password verification failed")
	default:
		httpx.WriteMessageError(w, http.StatusBadRequest, "error loading keystore")
	}
}

// writeKeystoreDownload writes the one binary response in this API.
//
// Measured on both downloads, and every line of it:
//
//	200
//	Content-Type: application/octet-stream
//	Cache-Control: no-cache
//	Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Robots-Tag
//	no X-Frame-Options
//	no Content-Disposition at all
//
// The missing X-Frame-Options is the media type's rule rather than the route's -
// five JSON responses on this same resource carry all five - which is the shape
// httpx.WriteYAML already records for `application/yaml`. The header is deleted
// rather than never set because the router sets all five before the mux runs.
//
// **This belongs in internal/httpx beside WriteYAML** and is here because the
// branch that wrote it does not own that package. It is the position
// writeEmptyStatus was in until F133 moved it, and the move is a rename.
func writeKeystoreDownload(w http.ResponseWriter, body []byte) {
	// Keycloak sends no Date and Go's net/http adds one. httpx.suppressDate is
	// unexported, so this is the one line of it that lives outside that package
	// - see the note above.
	w.Header()["Date"] = nil
	w.Header().Del("X-Frame-Options")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
