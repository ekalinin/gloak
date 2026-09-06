package admin

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ekalinin/gloak/internal/keystore"
	"github.com/ekalinin/gloak/internal/model"
	"github.com/ekalinin/gloak/internal/store"
)

// The three keystore operations, measured against a live Keycloak 26.7.1 on
// 2026-09-06. What is asserted here and nowhere else is the two downloads'
// whole contract: their response is a binary keystore, so no golden can hold
// one - see internal/conformance's RefuseNonTextBody - and this file is where
// the status, the media type, the headers and the store's own shape are pinned
// instead. That is the same bargain admin/client-attribute-certificate/generate
// already makes for its masked key.

const (
	keystoreAlias   = "gloak-alias"
	keystoreKeyPW   = "gloak-key-password"
	keystoreStorePW = "gloak-store-password"
)

// keystoreClient creates a client and gives it a key pair through the generate
// endpoint, which is the state a download reads.
func keystoreClient(t *testing.T, h http.Handler, s store.Store, realm *model.Realm,
	clientID, token string) *model.Client {
	t.Helper()
	c := createStoredClient(t, s, realm, &model.Client{ClientID: clientID, Enabled: true, Protocol: "openid-connect"})
	w := do(t, h, http.MethodPost,
		"/admin/realms/master/clients/"+c.ID+"/certificates/jwt.credential/generate", token)
	if w.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", w.Code, w.Body)
	}
	return c
}

func keystoreBody(format, alias string, keyPassword, storePassword *string) string {
	body := map[string]any{"format": format}
	if alias != "" {
		body["keyAlias"] = alias
	}
	if keyPassword != nil {
		body["keyPassword"] = *keyPassword
	}
	if storePassword != nil {
		body["storePassword"] = *storePassword
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func str(s string) *string { return &s }

// post sends a JSON body, which is what the two downloads take and what `do`
// cannot express.
func post(t *testing.T, h http.Handler, path, token, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func download(t *testing.T, h http.Handler, c *model.Client, token, op, body string) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, h, "/admin/realms/master/clients/"+c.ID+"/certificates/jwt.credential/"+op,
		token, "application/json", body)
}

// TestKeystoreDownloadHeaders is **the answer to what a case over a binary
// response could assert**, made a test rather than a golden.
//
// Measured on both binary operations, against five application/json responses
// on the same resource in the same session that carry all five security
// headers:
//
//	200, application/octet-stream, Cache-Control: no-cache
//	Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Robots-Tag
//	no X-Frame-Options, no Content-Disposition at all
//
// It cannot live in a golden because `RefuseNonTextBody` refuses to record a
// keystore, and a golden that held only headers would assert nothing about the
// body while moving the parity meter by two. So the operations stay uncounted
// and their headers are checked here.
func TestKeystoreDownloadHeaders(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-headers", token)

	for _, op := range []string{"download", "generate-and-download"} {
		t.Run(op, func(t *testing.T) {
			w := download(t, h, c, token, op,
				keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d %s", w.Code, w.Body)
			}
			if got := w.Header().Get("Content-Type"); got != "application/octet-stream" {
				t.Errorf("Content-Type: want application/octet-stream, got %q", got)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-cache" {
				t.Errorf("Cache-Control: want no-cache, got %q", got)
			}
			for _, name := range []string{
				"Referrer-Policy", "Strict-Transport-Security",
				"X-Content-Type-Options", "X-Robots-Tag",
			} {
				if w.Header().Get(name) == "" {
					t.Errorf("%s is absent; application/octet-stream carries four of the five", name)
				}
			}
			// The two absences are the measurement, and the second is the one a
			// reader expects to be there: Keycloak sends no Content-Disposition
			// on either download, so nothing names the file.
			if got, ok := w.Header()["X-Frame-Options"]; ok {
				t.Errorf("X-Frame-Options: want absent on application/octet-stream, got %q", got)
			}
			if got, ok := w.Header()["Content-Disposition"]; ok {
				t.Errorf("Content-Disposition: want absent, got %q", got)
			}
			// The value, not the key: suppressing Date is `w.Header()["Date"] =
			// nil`, which leaves the key present with nothing under it, so a
			// presence check here passes on a handler that never suppressed it.
			if got := w.Header()["Date"]; len(got) != 0 {
				t.Errorf("Keycloak sends no Date header on any response, got %q", got)
			}
		})
	}
}

// The store holds **two** entries: the client's pair under the caller's alias
// and the realm's own certificate under the realm's name, as a trusted
// certificate. Measured on master and on a realm called certprobe, which is why
// the alias is the realm's name rather than a constant.
func TestTheDownloadedKeystoreCarriesTheRealmCertificate(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-realm-cert", token)

	w := download(t, h, c, token, "download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if w.Code != http.StatusOK {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	ks, err := keystore.ReadJKS(w.Body.Bytes(), keystoreStorePW)
	if err != nil {
		t.Fatalf("the download is not a readable JKS: %v", err)
	}
	if len(ks.Entries) != 2 {
		t.Fatalf("want two entries, got %d", len(ks.Entries))
	}
	mine, ok := ks.Lookup(keystoreAlias)
	if !ok {
		t.Fatal("the client's own entry is missing")
	}
	if mine.ProtectedKey == nil {
		t.Error("the client's entry carries no key, so this is not a key entry")
	}
	realmEntry, ok := ks.Lookup(realm.Name)
	if !ok {
		t.Fatalf("no entry named %q, which is the realm's name", realm.Name)
	}
	if realmEntry.ProtectedKey != nil {
		t.Error("the realm's certificate is a trusted certificate entry and carries no key")
	}
	// The store the caller gets must really hold the client's key, or the
	// download hands over something the client cannot use.
	stored := certificateOf(mustReadClient(t, s, realm, c.ID), "jwt.credential")
	pkcs8, err := keystore.UnlockJKSKey(mine.ProtectedKey, keystoreKeyPW)
	if err != nil {
		t.Fatalf("the key in the store does not open with the key password: %v", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		t.Fatalf("the key in the store is not PKCS#8: %v", err)
	}
	got := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)))
	if got != stored.PrivateKey {
		t.Error("the key in the store is not the client's stored key")
	}
}

// **generate-and-download deletes the private key.** Measured twice: after it
// the client's attributes hold the certificate alone, while the keystore the
// caller was handed holds the key. An implementation that stored the pair would
// pass every other case in this chapter, which is why this is asserted on the
// store rather than on the response.
func TestGenerateAndDownloadKeepsOnlyTheCertificate(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-gd", token)
	before := certificateOf(mustReadClient(t, s, realm, c.ID), "jwt.credential")

	w := download(t, h, c, token, "generate-and-download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if w.Code != http.StatusOK {
		t.Fatalf("generate-and-download: %d %s", w.Code, w.Body)
	}
	after := mustReadClient(t, s, realm, c.ID)
	if _, ok := after.Attributes["jwt.credential.private.key"]; ok {
		t.Error("the private key is still on the client; generate-and-download deletes it")
	}
	pair := certificateOf(after, "jwt.credential")
	if pair.Certificate == "" {
		t.Fatal("the certificate was deleted too; only the key is")
	}
	if pair.Certificate == before.Certificate {
		t.Error("the certificate did not change, so nothing was generated")
	}
	// The key it gave away is in the store even though it kept none of it.
	ks, err := keystore.ReadJKS(w.Body.Bytes(), keystoreStorePW)
	if err != nil {
		t.Fatalf("the download is not a readable JKS: %v", err)
	}
	if e, ok := ks.Lookup(keystoreAlias); !ok || e.ProtectedKey == nil {
		t.Error("the caller was not given the key that was just deleted")
	}
}

// download writes nothing, which is why its guard is the view role.
func TestDownloadLeavesTheStoredPairAlone(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-readonly", token)
	before := certificateOf(mustReadClient(t, s, realm, c.ID), "jwt.credential")

	if w := download(t, h, c, token, "download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW))); w.Code != http.StatusOK {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	after := certificateOf(mustReadClient(t, s, realm, c.ID), "jwt.credential")
	if after.PrivateKey != before.PrivateKey || after.Certificate != before.Certificate {
		t.Error("the download changed the stored pair")
	}
}

// TestKeystoreDownloadRefusalOrder is the measured order, each row a request
// wrong in exactly two ways beside the control that is wrong in one.
//
// Without the controls this table cannot say which check answered: two rows
// that both answer 406 prove the format check ran and say nothing about what
// would have happened otherwise.
func TestKeystoreDownloadRefusalOrder(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	withKey := keystoreClient(t, h, s, realm, "keystore-order", token)
	empty := createStoredClient(t, s, realm,
		&model.Client{ClientID: "keystore-order-empty", Enabled: true, Protocol: "openid-connect"})

	for _, tc := range []struct {
		name        string
		client      *model.Client
		contentType string
		body        string
		status      int
		want        string
	}{
		{"the control, all four fields", withKey, "application/json",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 200, ""},
		{"a Content-Type that is not JSON", withKey, "application/x-www-form-urlencoded",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 415,
			`{"error":"The content-type header value did not match the value in @Consumes"}`},
		{"no Content-Type at all", withKey, "",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 415,
			`{"error":"The content-type header value did not match the value in @Consumes"}`},
		{"*/* is accepted", withKey, "*/*",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 200, ""},
		{"a charset parameter is ignored", withKey, "application/json; charset=UTF-8",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 200, ""},
		// The syntax-against-binding split, which is F163's rule and is not the
		// leading-bracket one writeCannotParseJSON makes.
		{"a body that is not JSON", withKey, "application/json", "{", 400,
			`{"error":"invalid_request","error_description":"Cannot parse the JSON"}`},
		{"JSON of the wrong shape", withKey, "application/json", "[]", 400,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"a JSON string", withKey, "application/json", `"x"`, 400,
			`{"error":"unknown_error","error_description":"Cannot parse the JSON"}`},
		{"an empty body", withKey, "application/json", "", 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"no format", withKey, "application/json",
			`{"keyAlias":"a","keyPassword":"k","storePassword":"s"}`, 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"an unknown format", withKey, "application/json",
			keystoreBody("bogus", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 406,
			`{"error":"Not supported keystore format. Supported keystore formats: [PKCS12, JKS, BCFKS]"}`},
		// **The 406's membership test folds case and everything after it does
		// not**, measured over fifteen spellings: a lower-case real format is a
		// 500 and an unknown one is a 406. The three rows below are what say so;
		// with only the `bogus` row above them, one case-sensitive membership
		// test would pass.
		{"a real format in the wrong case", withKey, "application/json",
			keystoreBody("jks", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"and it is not only JKS", withKey, "application/json",
			keystoreBody("pkcs12", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"nothing is trimmed", withKey, "application/json",
			keystoreBody(" JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 406,
			`{"error":"Not supported keystore format. Supported keystore formats: [PKCS12, JKS, BCFKS]"}`},
		{"an empty format is a 406 where an absent one is a 500", withKey, "application/json",
			`{"format":"","keyAlias":"a","keyPassword":"k","storePassword":"s"}`, 406,
			`{"error":"Not supported keystore format. Supported keystore formats: [PKCS12, JKS, BCFKS]"}`},
		// The format is decided before the client's state and before the
		// passwords, and each of these has its control two rows below.
		{"an unknown format on a client with no pair", empty, "application/json",
			keystoreBody("bogus", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 406,
			`{"error":"Not supported keystore format. Supported keystore formats: [PKCS12, JKS, BCFKS]"}`},
		{"an unknown format and no store password", withKey, "application/json",
			keystoreBody("bogus", keystoreAlias, str(keystoreKeyPW), nil), 406,
			`{"error":"Not supported keystore format. Supported keystore formats: [PKCS12, JKS, BCFKS]"}`},
		{"a client with no pair", empty, "application/json",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)), 404,
			`{"error":"keypair not generated for client"}`},
		{"a client with no pair and no store password", empty, "application/json",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), nil), 404,
			`{"error":"keypair not generated for client"}`},
		{"no key password", withKey, "application/json",
			keystoreBody("JKS", keystoreAlias, nil, str(keystoreStorePW)), 400,
			`{"error":"password-missing","error_description":"Need to specify a key password for jks download"}`},
		{"no store password", withKey, "application/json",
			keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), nil), 400,
			`{"error":"password-missing","error_description":"Need to specify a store password for jks download"}`},
		{"neither password answers about the key", withKey, "application/json",
			keystoreBody("JKS", keystoreAlias, nil, nil), 400,
			`{"error":"password-missing","error_description":"Need to specify a key password for jks download"}`},
		// The description says jks for every format. Keycloak's own defect.
		{"the description says jks for PKCS12 too", withKey, "application/json",
			keystoreBody("PKCS12", keystoreAlias, str(keystoreKeyPW), nil), 400,
			`{"error":"password-missing","error_description":"Need to specify a store password for jks download"}`},
		{"an alias equal to the realm's name", withKey, "application/json",
			keystoreBody("JKS", realm.Name, str(keystoreKeyPW), str(keystoreStorePW)), 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := post(t, h, "/admin/realms/master/clients/"+tc.client.ID+
				"/certificates/jwt.credential/download", token, tc.contentType, tc.body)
			if w.Code != tc.status {
				t.Fatalf("status: want %d, got %d %s", tc.status, w.Code, w.Body)
			}
			if tc.want != "" && w.Body.String() != tc.want {
				t.Errorf("body:\nwant %s\ngot  %s", tc.want, w.Body)
			}
		})
	}
}

// generate-and-download requires **both** passwords always, because it always
// mints a key, and its descriptions end differently. Two operations, one
// sentence template, and reusing download's would be wrong on three words.
func TestGenerateAndDownloadAlwaysNeedsBothPasswords(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	empty := createStoredClient(t, s, realm,
		&model.Client{ClientID: "keystore-gd-empty", Enabled: true, Protocol: "openid-connect"})

	w := download(t, h, empty, token, "generate-and-download",
		keystoreBody("JKS", keystoreAlias, nil, str(keystoreStorePW)))
	if want := `{"error":"password-missing","error_description":` +
		`"Need to specify a key password for jks generation and download"}`; w.Body.String() != want {
		t.Errorf("body:\nwant %s\ngot  %s", want, w.Body)
	}
	w = download(t, h, empty, token, "generate-and-download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), nil))
	if want := `{"error":"password-missing","error_description":` +
		`"Need to specify a store password for jks generation and download"}`; w.Body.String() != want {
		t.Errorf("body:\nwant %s\ngot  %s", want, w.Body)
	}
	// And it serves a client that has never generated anything, where download
	// answers 404 for the same client. That is the pair's other difference.
	if w := download(t, h, empty, token, "generate-and-download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW))); w.Code != http.StatusOK {
		t.Fatalf("generate-and-download on an empty client: %d %s", w.Code, w.Body)
	}
}

// The key password is required **exactly when a private key is stored**, which
// is a two-condition rule and needs the second state to be real. The cert-only
// client is made through upload-certificate, which deletes the key, rather than
// by editing attributes - a PUT on a client merges, so the obvious way of
// arranging this state does not arrange it.
func TestTheKeyPasswordIsRequiredOnlyWhenThereIsAKey(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-certonly", token)

	pair := certificateOf(mustReadClient(t, s, realm, c.ID), "jwt.credential")
	uploadCertificate(t, h, c, token, pair.Certificate)
	after := mustReadClient(t, s, realm, c.ID)
	if _, ok := after.Attributes["jwt.credential.private.key"]; ok {
		t.Fatal("the fixture did not reach a certificate-only client, so this test asserts nothing")
	}

	w := download(t, h, c, token, "download",
		keystoreBody("JKS", keystoreAlias, nil, str(keystoreStorePW)))
	if w.Code != http.StatusOK {
		t.Fatalf("a certificate-only client needs no key password: %d %s", w.Code, w.Body)
	}
	// And the entry it produces is a trusted certificate rather than a key
	// entry, which is what a store downloaded in that state was measured
	// holding: two trusted certificates and no key at all.
	ks, err := keystore.ReadJKS(w.Body.Bytes(), keystoreStorePW)
	if err != nil {
		t.Fatalf("the download is not a readable JKS: %v", err)
	}
	if e, _ := ks.Lookup(keystoreAlias); e.ProtectedKey != nil {
		t.Error("a client with no key produced a key entry")
	}
	// The store password is still required, which is what says the two are
	// separate rules rather than one.
	if w := download(t, h, c, token, "download",
		keystoreBody("JKS", keystoreAlias, nil, nil)); w.Code != http.StatusBadRequest {
		t.Errorf("the store password is required whatever the client holds: %d %s", w.Code, w.Body)
	}
}

// An absent keyAlias is the clientId and an empty one is the empty string. Two
// rows, because a single test sending neither cannot tell them apart.
func TestTheKeyAliasDefaultsToTheClientID(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-alias", token)

	w := download(t, h, c, token, "download",
		`{"format":"JKS","keyPassword":"k","storePassword":"s"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("no keyAlias: %d %s", w.Code, w.Body)
	}
	ks, err := keystore.ReadJKS(w.Body.Bytes(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.Lookup(c.ClientID); !ok {
		t.Errorf("an absent alias is the clientId %q; the store holds %v", c.ClientID, keystoreAliasesOf(ks))
	}

	w = download(t, h, c, token, "download",
		`{"format":"JKS","keyAlias":"","keyPassword":"k","storePassword":"s"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty keyAlias: %d %s", w.Code, w.Body)
	}
	ks, err = keystore.ReadJKS(w.Body.Bytes(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ks.Lookup(""); !ok {
		t.Errorf("an empty alias is the empty string; the store holds %v", keystoreAliasesOf(ks))
	}
}

// **BCFKS is this cut's one divergence and it is stated where it can fail.**
// Keycloak answers a keystore; Gloak cannot write one, because the format's
// payload is AES-256-CCM and Go has no CCM. The 406's body is left alone
// because it is a measured contract that lists BCFKS as supported, so the
// refusal is the 500 this route already produces for a lower-case format.
//
// If this ever starts answering 200, the divergence is closed and the entry in
// docs/superpowers/handover/certificate-remainder.md should go with it.
func TestBCFKSIsRefusedAndTheRefusalListsItAnyway(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-bcfks", token)

	w := download(t, h, c, token, "download",
		keystoreBody("BCFKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want the 500 divergence, got %d %s", w.Code, w.Body)
	}
	// The 406's body still names BCFKS, because that is what Keycloak sends and
	// a golden holds it.
	w = download(t, h, c, token, "download",
		keystoreBody("bogus", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if !strings.Contains(w.Body.String(), "BCFKS") {
		t.Errorf("the 406 must list BCFKS whatever Gloak can write: %s", w.Body)
	}
}

// The round trip: what download produces, upload reads back into the same pair.
// It runs over both formats because their key protection differs - a JKS key
// opens with the key password and a PKCS12 key with the store password - and a
// test using one password for both could not tell.
func TestKeystoreRoundTrip(t *testing.T) {
	for _, format := range []string{"JKS", "PKCS12"} {
		t.Run(format, func(t *testing.T) {
			h, s, realm := newServer(t)
			token := tokenFor(t, h, "admin", "admin")
			from := keystoreClient(t, h, s, realm, "keystore-rt-from-"+format, token)
			want := certificateOf(mustReadClient(t, s, realm, from.ID), "jwt.credential")

			w := download(t, h, from, token, "download",
				keystoreBody(format, keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
			if w.Code != http.StatusOK {
				t.Fatalf("download: %d %s", w.Code, w.Body)
			}

			to := createStoredClient(t, s, realm,
				&model.Client{ClientID: "keystore-rt-to-" + format, Enabled: true, Protocol: "openid-connect"})
			up := uploadKeystore(t, h, to, token, map[string]string{
				"keystoreFormat": format, "keyAlias": keystoreAlias,
				"keyPassword": keystoreKeyPW, "storePassword": keystoreStorePW,
			}, w.Body.Bytes())
			if up.Code != http.StatusOK {
				t.Fatalf("upload: %d %s", up.Code, up.Body)
			}
			var got certificateRepresentation
			if err := json.Unmarshal(up.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.PrivateKey != want.PrivateKey {
				t.Error("the private key did not survive the round trip")
			}
			if got.Certificate != want.Certificate {
				t.Error("the certificate did not survive the round trip")
			}
			// And it is stored, not merely echoed.
			stored := certificateOf(mustReadClient(t, s, realm, to.ID), "jwt.credential")
			if stored.PrivateKey != want.PrivateKey || stored.Certificate != want.Certificate {
				t.Error("upload answered the pair without storing it")
			}
			// The response carries the JSON headers, not the download's.
			if ct := up.Header().Get("Content-Type"); ct != "application/json;charset=UTF-8" {
				t.Errorf("Content-Type: want application/json;charset=UTF-8, got %q", ct)
			}
			if got, ok := up.Header()["Cache-Control"]; ok {
				t.Errorf("the three uploads send no Cache-Control, got %q", got)
			}
		})
	}
}

// **A wrong key password is not a refusal on a JKS**: 200, with the certificate
// alone and the key dropped. On a PKCS12 the key password is not used at all,
// so the same request answers the whole pair. One field, two formats, two
// answers - which is why this runs both and compares them.
func TestAWrongKeyPasswordDropsTheKeyOnJKSAndIsIgnoredOnPKCS12(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	from := keystoreClient(t, h, s, realm, "keystore-wrongkey", token)
	want := certificateOf(mustReadClient(t, s, realm, from.ID), "jwt.credential")

	for _, tc := range []struct {
		format  string
		wantKey bool
	}{
		{"JKS", false},
		{"PKCS12", true},
	} {
		t.Run(tc.format, func(t *testing.T) {
			w := download(t, h, from, token, "download",
				keystoreBody(tc.format, keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
			if w.Code != http.StatusOK {
				t.Fatalf("download: %d %s", w.Code, w.Body)
			}
			to := createStoredClient(t, s, realm, &model.Client{
				ClientID: "keystore-wrongkey-" + tc.format, Enabled: true, Protocol: "openid-connect"})
			up := uploadKeystore(t, h, to, token, map[string]string{
				"keystoreFormat": tc.format, "keyAlias": keystoreAlias,
				"keyPassword": "not the key password", "storePassword": keystoreStorePW,
			}, w.Body.Bytes())
			if up.Code != http.StatusOK {
				t.Fatalf("a wrong key password is not a refusal: %d %s", up.Code, up.Body)
			}
			var got certificateRepresentation
			if err := json.Unmarshal(up.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Certificate != want.Certificate {
				t.Error("the certificate is kept whatever the key password says")
			}
			if tc.wantKey && got.PrivateKey != want.PrivateKey {
				t.Error("a PKCS12 key bag opens with the store password, so the key password cannot lose it")
			}
			if !tc.wantKey && got.PrivateKey != "" {
				t.Error("a JKS key that will not unlock is dropped, not returned")
			}
		})
	}
}

// TestKeystoreUploadRefusalOrder is upload's measured order, each row wrong in
// exactly two ways beside a control wrong in one.
func TestKeystoreUploadRefusalOrder(t *testing.T) {
	h, s, realm := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	from := keystoreClient(t, h, s, realm, "keystore-upload-order", token)
	w := download(t, h, from, token, "download",
		keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if w.Code != http.StatusOK {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	jks := w.Body.Bytes()
	w = download(t, h, from, token, "download",
		keystoreBody("PKCS12", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW)))
	if w.Code != http.StatusOK {
		t.Fatalf("download: %d %s", w.Code, w.Body)
	}
	p12 := w.Body.Bytes()

	good := map[string]string{
		"keystoreFormat": "JKS", "keyAlias": keystoreAlias,
		"keyPassword": keystoreKeyPW, "storePassword": keystoreStorePW,
	}
	without := func(key string) map[string]string {
		out := map[string]string{}
		for k, v := range good {
			if k != key {
				out[k] = v
			}
		}
		return out
	}
	with := func(key, value string) map[string]string {
		out := map[string]string{}
		for k, v := range good {
			out[k] = v
		}
		out[key] = value
		return out
	}

	to := createStoredClient(t, s, realm,
		&model.Client{ClientID: "keystore-upload-target", Enabled: true, Protocol: "openid-connect"})
	for _, tc := range []struct {
		name   string
		fields map[string]string
		file   []byte
		status int
		want   string
	}{
		{"the control", good, jks, 200, ""},
		{"no keystoreFormat", without("keystoreFormat"), jks, 400,
			`{"error":"keystoreFormat cannot be null"}`},
		{"no keystoreFormat and rubbish for a file", without("keystoreFormat"), []byte("rubbish"), 400,
			`{"error":"keystoreFormat cannot be null"}`},
		{"no file part", good, nil, 400, `{"error":"file cannot be empty"}`},
		{"no keyAlias", without("keyAlias"), jks, 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"no keyAlias and rubbish for a file", without("keyAlias"), []byte("rubbish"), 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"a certificate format", with("keystoreFormat", "Certificate PEM"), jks, 500,
			`{"error":"unknown_error","error_description":"For more on this error consult the server log."}`},
		{"an unknown format", with("keystoreFormat", "bogus"), jks, 400,
			`{"error":"error loading keystore"}`},
		{"the format is case-sensitive here too", with("keystoreFormat", "jks"), jks, 400,
			`{"error":"error loading keystore"}`},
		{"a PKCS12 declared JKS is not a keystore this reads", with("keystoreFormat", "PKCS12"), jks, 400,
			`{"error":"error loading keystore"}`},
		{"a JKS with the wrong store password", with("storePassword", "wrong"), jks, 400,
			`{"error":"Password verification failed"}`},
		{"an alias the store does not hold", with("keyAlias", "nope"), jks, 400,
			`{"error":"certificate-not-found","error_description":` +
				`"Certificate or key with given alias not found in the keystore"}`},
		{"a wrong password beats a wrong alias", func() map[string]string {
			out := with("keyAlias", "nope")
			out["storePassword"] = "wrong"
			return out
		}(), jks, 400, `{"error":"Password verification failed"}`},
		{"a JKS with no store password skips the check", func() map[string]string {
			out := without("storePassword")
			out["keyAlias"] = "nope"
			return out
		}(), jks, 400, `{"error":"certificate-not-found","error_description":` +
			`"Certificate or key with given alias not found in the keystore"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := uploadKeystore(t, h, to, token, tc.fields, tc.file)
			if w.Code != tc.status {
				t.Fatalf("status: want %d, got %d %s", tc.status, w.Code, w.Body)
			}
			if tc.want != "" && w.Body.String() != tc.want {
				t.Errorf("body:\nwant %s\ngot  %s", tc.want, w.Body)
			}
		})
	}

	// The two formats spell a wrong store password differently, which is what
	// makes them two rules rather than one.
	w = uploadKeystore(t, h, to, token, map[string]string{
		"keystoreFormat": "PKCS12", "keyAlias": keystoreAlias,
		"keyPassword": keystoreKeyPW, "storePassword": "wrong",
	}, p12)
	if want := `{"error":"PKCS12 key store mac invalid"}`; w.Body.String() != want {
		t.Errorf("PKCS12's wrong password:\nwant %s\ngot  %s", want, w.Body)
	}
}

// The guards, one role at a time, with POST /clients as a control known to
// differ. **download is opened by view-clients and its sibling is not**, which
// is the finding: the verb does not decide, whether the operation writes does.
func TestKeystoreGuards(t *testing.T) {
	h, s, realm := newServer(t)
	admin := tokenFor(t, h, "admin", "admin")
	c := keystoreClient(t, h, s, realm, "keystore-guards", admin)
	body := keystoreBody("JKS", keystoreAlias, str(keystoreKeyPW), str(keystoreStorePW))

	for _, tc := range []struct {
		role                          string
		download, generateAndDownload int
		upload, control               int
	}{
		{"view-clients", 200, 403, 403, 403},
		{"manage-clients", 200, 200, 400, 201},
		{"view-realm", 403, 403, 403, 403},
		{"query-clients", 403, 403, 403, 403},
	} {
		t.Run(tc.role, func(t *testing.T) {
			token := tokenForRole(t, h, s, realm, tc.role)
			if w := download(t, h, c, token, "download", body); w.Code != tc.download {
				t.Errorf("download: want %d, got %d %s", tc.download, w.Code, w.Body)
			}
			if w := download(t, h, c, token, "generate-and-download", body); w.Code != tc.generateAndDownload {
				t.Errorf("generate-and-download: want %d, got %d %s", tc.generateAndDownload, w.Code, w.Body)
			}
			// The upload is sent without a file, so a caller that gets past the
			// guard lands on the measured 400 rather than needing a keystore.
			if w := uploadKeystore(t, h, c, token, map[string]string{
				"keystoreFormat": "JKS", "keyAlias": keystoreAlias,
			}, nil); w.Code != tc.upload {
				t.Errorf("upload: want %d, got %d %s", tc.upload, w.Code, w.Body)
			}
			// The control. Without it a sweep answering 403 to everything would
			// look like a measurement.
			w := post(t, h, "/admin/realms/master/clients", token, "application/json",
				`{"clientId":"control-`+tc.role+`"}`)
			if w.Code != tc.control {
				t.Errorf("the control POST /clients: want %d, got %d %s", tc.control, w.Code, w.Body)
			}
		})
	}
}

// An unknown client is 404 before the body is looked at, on all three.
func TestKeystoreOperationsResolveTheClientFirst(t *testing.T) {
	h, _, _ := newServer(t)
	token := tokenFor(t, h, "admin", "admin")
	gone := "/admin/realms/master/clients/00000000-0000-0000-0000-000000000000/certificates/jwt.credential/"
	for _, op := range []string{"download", "generate-and-download"} {
		// The body is unparseable, so a handler that read it first would answer
		// the decoder's 400.
		w := post(t, h, gone+op, token, "text/plain", "{")
		if w.Code != http.StatusNotFound || w.Body.String() != `{"error":"Could not find client"}` {
			t.Errorf("%s: want the client 404, got %d %s", op, w.Code, w.Body)
		}
	}
	w := uploadKeystore(t, h, &model.Client{ID: "00000000-0000-0000-0000-000000000000"}, token,
		map[string]string{}, nil)
	if w.Code != http.StatusNotFound || w.Body.String() != `{"error":"Could not find client"}` {
		t.Errorf("upload: want the client 404, got %d %s", w.Code, w.Body)
	}
}

// uploadKeystore sends the multipart request .../upload takes. A nil file means
// no file part at all, which is a different request from an empty one.
func uploadKeystore(t *testing.T, h http.Handler, c *model.Client, token string,
	fields map[string]string, file []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if file != nil {
		part, err := mw.CreateFormFile("file", "store.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/realms/master/clients/"+c.ID+"/certificates/jwt.credential/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// uploadCertificate drives the sibling operation, which deletes the private
// key. It is how a certificate-only client is arranged.
func uploadCertificate(t *testing.T, h http.Handler, c *model.Client, token, certificateBase64 string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("keystoreFormat", "Certificate PEM"); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormFile("file", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(certificateBase64)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/realms/master/clients/"+c.ID+"/certificates/jwt.credential/upload-certificate", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload-certificate: %d %s", w.Code, w.Body)
	}
}

func mustReadClient(t *testing.T, s store.Store, realm *model.Realm, id string) *model.Client {
	t.Helper()
	c, err := s.Clients().ByID(context.Background(), realm.ID, id)
	if err != nil {
		t.Fatalf("Clients().ByID: %v", err)
	}
	return c
}

func keystoreAliasesOf(s *keystore.Store) []string {
	out := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		out = append(out, e.Alias)
	}
	return out
}
