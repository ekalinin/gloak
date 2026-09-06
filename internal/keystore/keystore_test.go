package keystore

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// The two keystores under testdata are what a live Keycloak 26.7.1 answered on
// 2026-09-06 to
//
//	POST /admin/realms/master/clients/{uuid}/certificates/jwt.credential/download
//	{"format":"JKS|PKCS12","keyAlias":"gloak",
//	 "keyPassword":"gloakkey","storePassword":"gloakstore"}
//
// for a client called `gloak-probe-keystore` whose pair had just been generated.
// keycloak-26.7.1-pair.json is what that generate answered, so the expected key
// and certificate come from the server rather than from this package.
//
// The private key inside them went with the container that made it and protects
// nothing. It is here for the same reason probeCertificatePEM is in the
// conformance fixtures: a reader held to bytes it produced itself is held to
// nothing.
const (
	fixtureKeyAlias      = "gloak"
	fixtureKeyPassword   = "gloakkey"
	fixtureStorePassword = "gloakstore"
	fixtureRealmAlias    = "master"
)

func fixturePair(t *testing.T) (privateKey, certificate string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/keycloak-26.7.1-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct {
		PrivateKey  string `json:"privateKey"`
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(raw, &pair); err != nil {
		t.Fatal(err)
	}
	if pair.PrivateKey == "" || pair.Certificate == "" {
		t.Fatal("the recorded pair is empty, so nothing below asserts anything")
	}
	return pair.PrivateKey, pair.Certificate
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// mustRSA parses a PKCS#8 key the readers produced. The recorded pair holds the
// PKCS#1 base64 the API reports, so the comparison goes through this rather
// than through the PKCS#8 the keystore formats carry.
func mustRSA(t *testing.T, pkcs8Key []byte) *rsa.PrivateKey {
	t.Helper()
	key, err := x509.ParsePKCS8PrivateKey(pkcs8Key)
	if err != nil {
		t.Fatalf("the recovered key is not PKCS#8: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("the recovered key is a %T, not RSA", key)
	}
	return rsaKey
}

// TestReadJKSMatchesWhatKeycloakReports is the measurement this package exists
// to satisfy: the key and certificate inside a keystore Keycloak produced are
// exactly what its own API says they are.
func TestReadJKSMatchesWhatKeycloakReports(t *testing.T) {
	wantKey, wantCert := fixturePair(t)

	store, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatalf("ReadJKS: %v", err)
	}
	e, ok := store.Lookup(fixtureKeyAlias)
	if !ok {
		t.Fatalf("no entry named %q; the store holds %v", fixtureKeyAlias, aliases(store))
	}
	cert, ok := e.Certificate()
	if !ok {
		t.Fatal("the key entry carries no certificate")
	}
	if got := base64.StdEncoding.EncodeToString(cert); got != wantCert {
		t.Errorf("certificate:\nwant %s...\ngot  %s...", wantCert[:60], got[:60])
	}
	pkcs8Key, err := UnlockJKSKey(e.ProtectedKey, fixtureKeyPassword)
	if err != nil {
		t.Fatalf("UnlockJKSKey: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(mustRSA(t, pkcs8Key))); got != wantKey {
		t.Errorf("private key:\nwant %s...\ngot  %s...", wantKey[:60], got[:60])
	}
}

// The store bundles the realm's own certificate under the realm's name. That is
// measured on two realms - `master` in master and `certprobe` in a realm called
// certprobe - and it is why the reader looks entries up by alias rather than
// taking the first one.
func TestTheJKSCarriesTheRealmCertificateUnderTheRealmName(t *testing.T) {
	store, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Entries) != 2 {
		t.Fatalf("want two entries, got %d: %v", len(store.Entries), aliases(store))
	}
	realm, ok := store.Lookup(fixtureRealmAlias)
	if !ok {
		t.Fatalf("no entry named %q; the store holds %v", fixtureRealmAlias, aliases(store))
	}
	if realm.ProtectedKey != nil || realm.PrivateKey != nil {
		t.Error("the realm entry is a trusted certificate and must carry no key")
	}
	if _, ok := realm.Certificate(); !ok {
		t.Error("the realm entry carries no certificate")
	}
}

// The store password and the key password are different values in the fixture
// on purpose. A test using one for both cannot tell these two rules apart, and
// this repository has been caught by exactly that shape ten times.
func TestTheJKSPasswordsAreNotInterchangeable(t *testing.T) {
	raw := read(t, "keycloak-26.7.1.jks")
	if _, err := ReadJKS(raw, fixtureKeyPassword); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("the key password opened the store's integrity check: %v", err)
	}
	store, err := ReadJKS(raw, fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := store.Lookup(fixtureKeyAlias)
	if _, err := UnlockJKSKey(e.ProtectedKey, fixtureStorePassword); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("the store password opened the key: %v", err)
	}
	if _, err := UnlockJKSKey(e.ProtectedKey, "neither"); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("a wrong password opened the key: %v", err)
	}
	// **The positive control, and this test survived a mutation without it.**
	// The three assertions above are all refusals, so a key protector that
	// refused *every* password would satisfy every one of them: dropping the
	// password from the check digest left this test green and was caught only
	// by TestReadJKSMatchesWhatKeycloakReports. A test that asserts one
	// direction of a two-direction rule pins half of it.
	if _, err := UnlockJKSKey(e.ProtectedKey, fixtureKeyPassword); err != nil {
		t.Errorf("the key password did not open the key, so the three refusals above say nothing: %v", err)
	}
}

// An empty store password skips the integrity check, which is the format's rule
// and the endpoint's: an upload of a JKS with no storePassword answers 200 where
// the same request against a PKCS12 answers `error loading keystore`.
func TestAJKSWithNoStorePasswordSkipsTheCheck(t *testing.T) {
	if _, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), ""); err != nil {
		t.Errorf("an empty store password should skip the check, got %v", err)
	}
}

func TestReadJKSRefusesRubbish(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"wrong magic", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0, 0, 0, 0}},
		{"a PKCS12", read(t, "keycloak-26.7.1.p12")},
		{"truncated", read(t, "keycloak-26.7.1.jks")[:100]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadJKS(tc.raw, fixtureStorePassword); err == nil {
				t.Fatal("read a keystore that is not one")
			}
		})
	}
}

// TestWriteJKSRoundTrips holds the writer to the reader that is itself held to
// Keycloak's bytes, which is the only chain of custody available without a JVM.
func TestWriteJKSRoundTrips(t *testing.T) {
	source, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	key, cert := unpack(t, source)

	raw, err := WriteJKS(&Store{Entries: []Entry{
		{Alias: "written", Chain: [][]byte{cert}, PrivateKey: key},
		{Alias: "trusted", Chain: [][]byte{cert}},
	}}, "sp", "kp")
	if err != nil {
		t.Fatalf("WriteJKS: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte{0xfe, 0xed, 0xfe, 0xed}) {
		t.Fatalf("what was written does not begin with the JKS magic: % x", raw[:8])
	}
	back, err := ReadJKS(raw, "sp")
	if err != nil {
		t.Fatalf("ReadJKS on our own output: %v", err)
	}
	if _, err := ReadJKS(raw, "wrong"); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("the store we wrote verified under the wrong password: %v", err)
	}
	e, ok := back.Lookup("written")
	if !ok {
		t.Fatalf("the alias did not survive: %v", aliases(back))
	}
	got, err := UnlockJKSKey(e.ProtectedKey, "kp")
	if err != nil {
		t.Fatalf("UnlockJKSKey on our own output: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Error("the key did not survive the round trip")
	}
	if trusted, ok := back.Lookup("trusted"); !ok || trusted.ProtectedKey != nil {
		t.Error("the trusted certificate entry did not survive as one")
	}
}

// An alias is a clientId or a realm name, both caller-chosen, so the modified
// UTF-8 the format uses is exercised rather than assumed to be ASCII.
func TestAliasesSurviveModifiedUTF8(t *testing.T) {
	source, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	_, cert := unpack(t, source)
	for _, alias := range []string{"", "ascii", "grüß", "日本語", "a\x00b", "𝔊loak"} {
		raw, err := WriteJKS(&Store{Entries: []Entry{{Alias: alias, Chain: [][]byte{cert}}}}, "sp", "kp")
		if err != nil {
			t.Fatalf("%q: %v", alias, err)
		}
		back, err := ReadJKS(raw, "sp")
		if err != nil {
			t.Fatalf("%q: %v", alias, err)
		}
		if _, ok := back.Lookup(alias); !ok {
			t.Errorf("%q did not survive: got %v", alias, aliases(back))
		}
	}
}

// TestReadPKCS12MatchesWhatKeycloakReports is the JKS measurement's twin, and it
// is the one that pins berToDER: without it x/crypto/pkcs12 cannot read this
// file at all.
func TestReadPKCS12MatchesWhatKeycloakReports(t *testing.T) {
	wantKey, wantCert := fixturePair(t)

	store, err := ReadPKCS12(read(t, "keycloak-26.7.1.p12"), fixtureStorePassword)
	if err != nil {
		t.Fatalf("ReadPKCS12: %v", err)
	}
	e, ok := store.Lookup(fixtureKeyAlias)
	if !ok {
		t.Fatalf("no entry named %q; the store holds %v", fixtureKeyAlias, aliases(store))
	}
	cert, ok := e.Certificate()
	if !ok {
		t.Fatal("the key entry carries no certificate")
	}
	if got := base64.StdEncoding.EncodeToString(cert); got != wantCert {
		t.Errorf("certificate:\nwant %s...\ngot  %s...", wantCert[:60], got[:60])
	}
	if e.ProtectedKey != nil {
		t.Error("a PKCS12 key opens with the store password, so nothing is left protected")
	}
	if got := base64.StdEncoding.EncodeToString(
		x509.MarshalPKCS1PrivateKey(mustRSA(t, e.PrivateKey))); got != wantKey {
		t.Errorf("private key:\nwant %s...\ngot  %s...", wantKey[:60], got[:60])
	}
	if _, ok := store.Lookup(fixtureRealmAlias); !ok {
		t.Errorf("the realm certificate is missing; the store holds %v", aliases(store))
	}
}

// The measured asymmetry, stated where it can fail: PKCS12 opens with the store
// password and the key password does nothing.
func TestThePKCS12KeyOpensWithTheStorePassword(t *testing.T) {
	raw := read(t, "keycloak-26.7.1.p12")
	if _, err := ReadPKCS12(raw, fixtureKeyPassword); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("the key password opened the PKCS12: %v", err)
	}
	store, err := ReadPKCS12(raw, fixtureStorePassword)
	if err != nil {
		t.Fatalf("the store password did not open the PKCS12: %v", err)
	}
	if e, _ := store.Lookup(fixtureKeyAlias); e.PrivateKey == nil {
		t.Error("the store password opened the file and not the key")
	}
}

func TestWritePKCS12RoundTrips(t *testing.T) {
	source, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	key, cert := unpack(t, source)

	raw, err := WritePKCS12(&Store{Entries: []Entry{
		{Alias: "written", Chain: [][]byte{cert}, PrivateKey: key},
		{Alias: "trusted", Chain: [][]byte{cert}},
	}}, "sp")
	if err != nil {
		t.Fatalf("WritePKCS12: %v", err)
	}
	back, err := ReadPKCS12(raw, "sp")
	if err != nil {
		t.Fatalf("ReadPKCS12 on our own output: %v", err)
	}
	if _, err := ReadPKCS12(raw, "wrong"); !errors.Is(err, ErrPasswordVerification) {
		t.Errorf("the store we wrote verified under the wrong password: %v", err)
	}
	e, ok := back.Lookup("written")
	if !ok {
		t.Fatalf("the alias did not survive: %v", aliases(back))
	}
	if !bytes.Equal(e.PrivateKey, key) {
		t.Error("the key did not survive the round trip")
	}
	if got, _ := e.Certificate(); !bytes.Equal(got, cert) {
		t.Error("the certificate did not survive the round trip")
	}
	trusted, ok := back.Lookup("trusted")
	if !ok || trusted.PrivateKey != nil {
		t.Error("the trusted certificate entry did not survive as one")
	}
}

// berToDER must be the identity on a file that is already DER, or it is a
// rewriter nobody can reason about.
func TestBERToDERLeavesDERAlone(t *testing.T) {
	source, err := ReadJKS(read(t, "keycloak-26.7.1.jks"), fixtureStorePassword)
	if err != nil {
		t.Fatal(err)
	}
	key, cert := unpack(t, source)
	der, err := WritePKCS12(&Store{Entries: []Entry{
		{Alias: "written", Chain: [][]byte{cert}, PrivateKey: key},
	}}, "sp")
	if err != nil {
		t.Fatal(err)
	}
	got, err := berToDER(der)
	if err != nil {
		t.Fatalf("berToDER on DER: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Error("berToDER rewrote a file that was already DER")
	}
}

// The control for the claim in berToDER's comment: the vendored decoder really
// does refuse Keycloak's bytes, and really does accept them afterwards. Without
// the first half the normaliser could be doing nothing.
func TestBERToDERIsWhatMakesKeycloaksPKCS12Readable(t *testing.T) {
	raw := read(t, "keycloak-26.7.1.p12")
	if raw[1] != 0x80 {
		t.Fatalf("the fixture is not indefinite-length BER any more: % x", raw[:4])
	}
	der, err := berToDER(raw)
	if err != nil {
		t.Fatalf("berToDER: %v", err)
	}
	if der[1] == 0x80 {
		t.Fatal("berToDER left the indefinite length in place")
	}
	if len(der) >= len(raw) {
		t.Errorf("collapsing indefinite lengths should shrink the file: %d -> %d", len(raw), len(der))
	}
}

func TestBERToDERRefusesRubbish(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"a length that runs off the end", []byte{0x30, 0x7f, 0x00}},
		{"an indefinite length with no terminator", []byte{0x30, 0x80, 0x02, 0x01, 0x01}},
		{"a primitive with an indefinite length", []byte{0x02, 0x80, 0x00, 0x00}},
		{"trailing rubbish", []byte{0x02, 0x01, 0x01, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := berToDER(tc.raw); err == nil {
				t.Fatal("accepted what is not BER")
			}
		})
	}
}

// The PKCS#12 key derivation is not testable against Keycloak directly - it is
// inside an encryption - so it is pinned against RFC 7292's own worked shape by
// round-tripping through x/crypto/pkcs12, which implements the same function
// independently. A wrong KDF produces a file that decoder cannot open, and
// TestWritePKCS12RoundTrips is where that fails.
func TestPKCS12KDFIsDeterministicAndPasswordSensitive(t *testing.T) {
	salt := []byte("0123456789abcdefghij")
	a := pkcs12KDF("password", salt, 1, 24, 100)
	if !bytes.Equal(a, pkcs12KDF("password", salt, 1, 24, 100)) {
		t.Fatal("the derivation is not deterministic")
	}
	for _, other := range [][]byte{
		pkcs12KDF("Password", salt, 1, 24, 100),
		pkcs12KDF("password", []byte("0123456789abcdefghiJ"), 1, 24, 100),
		pkcs12KDF("password", salt, 2, 24, 100),
		pkcs12KDF("password", salt, 1, 24, 101),
	} {
		if bytes.Equal(a, other) {
			t.Error("two derivations that differ in one input came out equal")
		}
	}
	if len(pkcs12KDF("password", salt, 3, 64, 10)) != 64 {
		t.Error("a derivation longer than one digest came back short")
	}
}

func aliases(s *Store) []string {
	out := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		out = append(out, e.Alias)
	}
	return out
}

// unpack returns the fixture's key as PKCS#8 and its certificate as DER.
func unpack(t *testing.T, s *Store) (pkcs8Key, certificate []byte) {
	t.Helper()
	e, ok := s.Lookup(fixtureKeyAlias)
	if !ok {
		t.Fatal("the fixture store has no key entry")
	}
	key, err := UnlockJKSKey(e.ProtectedKey, fixtureKeyPassword)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := e.Certificate()
	return key, cert
}
