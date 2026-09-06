// Package keystore reads and writes the two Java keystore formats the client
// attribute certificate endpoints exchange.
//
// It exists because `POST .../certificates/{attr}/upload` hands the server a
// keystore and expects the private key **inside** it back, decrypted -
// measured 2026-09-06 against a live 26.7.1, which answered the byte-identical
// PKCS#1 base64 that `POST .../generate` had produced for the same client. The
// hope that the endpoint stored only a certificate, which would have made a
// purpose-built extractor smaller than a reader, is refuted by that
// measurement. There is no smaller job here.
//
// # Why this is written rather than taken
//
// Go has no JKS reader anywhere in its standard distribution, and the obvious
// dependency for the other half does not work. **Keycloak writes its PKCS12
// with BouncyCastle**, which emits indefinite-length BER with the content
// octets in a *constructed* OCTET STRING chunked at 1000 bytes. Measured on the
// exact bytes the endpoint receives:
//
//	encoding/asn1 on the raw file  asn1: syntax error: indefinite length found (not DER)
//	pkcs12.Decode(storepw)         pkcs12: error reading P12 data: ... indefinite length found
//	pkcs12.ToPEM(storepw)          n=0, the same error
//
// Every Go PKCS12 reader is built on `encoding/asn1`, so a dependency does not
// close the gap - the newer software.sslmate.com/src/go-pkcs12 reads DER
// through the same package and fails on the same byte. What closes it is
// [berToDER], and behind that this package uses golang.org/x/crypto/pkcs12,
// which is already a direct dependency of this module. **No new dependency was
// taken**, and the reason is a measurement rather than taste.
//
// # BCFKS is not here
//
// The third format the endpoints accept is BouncyCastle's FIPS keystore. Its
// payload is AES-256-CCM (2.16.840.1.101.3.4.1.47, 12-byte nonce, 8-byte ICV)
// keyed by PBKDF2-HMAC-SHA512 at 51200 iterations, inside an ObjectStore schema
// published nowhere but BouncyCastle's own source. Go's standard library and
// x/crypto have no CCM. Hand-rolling an AEAD to reach a format no golden can
// cover is machinery with a security risk and no consumer; it is filed instead.
//
// # What the two formats protect with which password
//
// They do not agree, and a test using one password for both cannot tell them
// apart. Measured on a store downloaded with two different values on purpose:
//
//	JKS      the key by keyPassword     the store MAC by storePassword
//	PKCS12   the key by storePassword   the MAC by storePassword; keyPassword unused
//
// That is why [Entry] carries a JKS key still protected and a PKCS12 key
// already recovered, in two separate fields, rather than one field and a
// comment.
package keystore

import (
	"crypto/x509"
	"errors"
	"time"
)

// Entry is one keystore entry.
//
// Java has two entry kinds and this models both: a private key entry carries a
// certificate chain and a key, a trusted certificate entry carries one
// certificate and no key. Which one it is, is whether the key fields are set.
type Entry struct {
	// Alias is the entry's name inside the store. Keycloak uses the caller's
	// keyAlias for the client's own pair and **the realm's name** for the
	// realm certificate it bundles alongside - measured `master` in master and
	// `certprobe` in a realm called certprobe.
	Alias string

	// CreatedAt is the entry's timestamp. JKS stores it; PKCS12 has no place
	// for one, so a store read back from PKCS12 has the zero time.
	CreatedAt time.Time

	// Chain is the entry's certificates in DER, leaf first. A trusted
	// certificate entry has exactly one.
	Chain [][]byte

	// PrivateKey is a PKCS#8 key the reader has already recovered, or that the
	// writer is to protect. The PKCS12 reader fills it, because that format's
	// key bag opens with the store password and there is nothing left to
	// unlock.
	PrivateKey []byte

	// ProtectedKey is a JKS key entry's EncryptedPrivateKeyInfo, still sealed.
	// It is separate from PrivateKey because recovering it needs a password
	// this package is not given at read time, and because **a wrong key
	// password is not an error on this endpoint**: Keycloak answers 200 with
	// the certificate alone and drops the key. A reader that failed the whole
	// read would answer 400 where Keycloak answers 200.
	ProtectedKey []byte
}

// Certificate returns the entry's leaf certificate in DER, and whether it has
// one.
func (e Entry) Certificate() ([]byte, bool) {
	if len(e.Chain) == 0 {
		return nil, false
	}
	return e.Chain[0], true
}

// Store is a keystore's entries in the order the file holds them.
//
// Order is not contract: Java enumerates aliases out of a HashMap, so the same
// two entries came back certificate-first in one download and key-first in the
// next, decided by the aliases' hash codes. Nothing here depends on it and
// nothing should.
type Store struct {
	Entries []Entry
}

// Lookup returns the entry with the given alias.
//
// The empty alias is a real alias rather than a wildcard: `keyAlias: ""` on a
// download produced a store whose key entry is named with the empty string,
// measured, and the upload beside it answers `certificate-not-found` for it -
// because the *download* wrote the empty name into a store that also holds the
// realm's, and the *upload* looks for it in a store that does not.
func (s *Store) Lookup(alias string) (Entry, bool) {
	for _, e := range s.Entries {
		if e.Alias == alias {
			return e, true
		}
	}
	return Entry{}, false
}

// ErrPasswordVerification is what a store whose integrity check does not match
// the password answers. The two formats spell their refusals differently on the
// wire - "Password verification failed" for JKS and "PKCS12 key store mac
// invalid" for PKCS12 - so the caller distinguishes them by which reader it
// called rather than by unwrapping this.
var ErrPasswordVerification = errors.New("keystore: password verification failed")

// ErrMalformed is what a file that is not the format it was declared to be
// answers. Keycloak's wire spelling is `error loading keystore`.
var ErrMalformed = errors.New("keystore: cannot read the keystore")

// pkcs8 re-encodes whatever DER form a key arrived in as a PKCS#8
// PrivateKeyInfo, which is what [Entry.PrivateKey] holds.
//
// The three forms are met in practice: JKS holds PKCS#8 already, and
// x/crypto/pkcs12's ToPEM re-marshals an RSA key as PKCS#1 and an EC key as
// SEC1 before handing it over. Sniffing by parse rather than by tag is what
// keeps this from being a guess about which library did what.
func pkcs8(der []byte) ([]byte, error) {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return der, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return x509.MarshalPKCS8PrivateKey(key)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, ErrMalformed
	}
	return x509.MarshalPKCS8PrivateKey(key)
}
