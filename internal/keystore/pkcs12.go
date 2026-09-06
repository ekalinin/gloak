package keystore

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf16"

	"crypto/x509/pkix"

	"golang.org/x/crypto/pkcs12"
)

// The OIDs a PKCS12 keystore is built from. Each was read off the file
// Keycloak produced rather than copied from a list, and the two PBE algorithms
// are the ones BouncyCastle chose there: 3DES for the key bag and 40-bit RC2
// for the certificates, both at 51200 iterations, with a SHA-1 MAC at 102400.
var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidCertBag                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidPKCS8ShroudedKeyBag      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidX509Certificate          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidSHA1                     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidPBEWithSHAAnd3DESCBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
)

// pkcs12Iterations is what this package writes.
//
// It is Keycloak's own number for the key bag, measured on the store it
// produced: `pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 51200`. The MAC there
// is 102400 and this writes 51200 for both; the difference is invisible - no
// golden holds these bytes and no reader cares - and one constant is one thing
// to get wrong instead of two.
const pkcs12Iterations = 51200

// ReadPKCS12 parses a PKCS12 keystore.
//
// The raw file is normalised from BER to DER first, because Keycloak's is BER
// and nothing in Go reads that. See [berToDER], which is the whole reason this
// is written rather than delegated.
//
// **Both the MAC and the key bag open with storePassword**, which is not what
// the endpoint's field names suggest. Measured on a store downloaded with
// `keyPassword=keypw, storePassword=storepw` - two different values on purpose:
// `openssl pkcs12 -passin pass:storepw` opens the shrouded key bag, and the
// upload endpoint answers the private key for a **wrong** keyPassword and for an
// absent one alike. So the entries come back with PrivateKey already filled and
// ProtectedKey empty, which is the opposite of ReadJKS.
func ReadPKCS12(raw []byte, storePassword string) (*Store, error) {
	der, err := resignPKCS12(raw, storePassword)
	if err != nil {
		return nil, err
	}
	blocks, err := pkcs12.ToPEM(der, storePassword)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, ErrPasswordVerification
		}
		return nil, ErrMalformed
	}

	// Bags are grouped by friendlyName, which is what a Java alias is stored
	// as. A key bag and the certificate it belongs to carry the same one; the
	// realm certificate Keycloak bundles alongside carries its own and no key.
	store := &Store{}
	index := map[string]int{}
	at := func(alias string) *Entry {
		if i, ok := index[alias]; ok {
			return &store.Entries[i]
		}
		index[alias] = len(store.Entries)
		store.Entries = append(store.Entries, Entry{Alias: alias})
		return &store.Entries[len(store.Entries)-1]
	}
	for _, b := range blocks {
		e := at(b.Headers["friendlyName"])
		switch b.Type {
		case "CERTIFICATE":
			e.Chain = append(e.Chain, b.Bytes)
		case "PRIVATE KEY":
			// ToPEM re-marshals: PKCS#1 for RSA, SEC1 for EC. Entry.PrivateKey
			// is PKCS#8 whichever reader filled it.
			key, err := pkcs8(b.Bytes)
			if err != nil {
				return nil, err
			}
			e.PrivateKey = key
		}
	}
	return store, nil
}

// WritePKCS12 encodes a store, sealing every key with storePassword.
//
// It seals with the **store** password rather than the key password on purpose:
// that is what Keycloak's own file does, measured, and it is what makes a
// download from Gloak uploadable to Gloak and to Keycloak alike. A writer that
// used the key password would produce a store this package could not read back
// and that the endpoint would answer `{certificate}` for.
//
// What it does not reproduce is the encoding. Keycloak streams indefinite-length
// BER through BouncyCastle and encrypts the certificate bags with 40-bit RC2;
// this writes definite-length DER and leaves the certificates in a plain `data`
// ContentInfo. Both are legal PKCS12 that Java, OpenSSL and this package read,
// **and no golden holds either**, so the difference is invisible to everything
// that compares. RC2 is not in Go's standard library and adding a broken cipher
// to match bytes nobody compares would be the wrong trade twice over.
func WritePKCS12(s *Store, storePassword string) ([]byte, error) {
	var keyBags, certBags []asn1.RawValue
	for _, e := range s.Entries {
		var localKeyID []byte
		if e.PrivateKey != nil {
			// The identifier is what links a key bag to its certificate; Java
			// needs the pair to agree or the entry reads back as two.
			if leaf, ok := e.Certificate(); ok {
				sum := sha1.Sum(leaf)
				localKeyID = sum[:]
			}
			sealed, err := sealPKCS12Key(e.PrivateKey, storePassword)
			if err != nil {
				return nil, err
			}
			bag, err := pkcs12Bag(oidPKCS8ShroudedKeyBag, sealed, e.Alias, localKeyID)
			if err != nil {
				return nil, err
			}
			keyBags = append(keyBags, bag)
		}
		for i, cert := range e.Chain {
			// CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
			certID, err := asn1.Marshal(oidX509Certificate)
			if err != nil {
				return nil, err
			}
			value := berEncode(0x30, append(certID, berEncode(0xa0, berEncode(0x04, cert))...))
			// Only the leaf carries the key identifier; a chain's issuers are
			// not the entry's own certificate.
			id := localKeyID
			if i > 0 {
				id = nil
			}
			bag, err := pkcs12Bag(oidCertBag, value, e.Alias, id)
			if err != nil {
				return nil, err
			}
			certBags = append(certBags, bag)
		}
	}

	// **Two ContentInfos, and the count is not cosmetic.** Keycloak's own file
	// holds a `data` one with the key bags and an `encryptedData` one with the
	// certificates, and the decoder behind ReadPKCS12 refuses anything else -
	// "expected exactly two items in the authenticated safe". A single
	// ContentInfo would produce a store this package writes and cannot read.
	keySafe, err := asn1.Marshal(keyBags)
	if err != nil {
		return nil, err
	}
	certSafe, err := asn1.Marshal(certBags)
	if err != nil {
		return nil, err
	}
	encryptedCerts, err := encryptPKCS12Safe(certSafe, storePassword)
	if err != nil {
		return nil, err
	}
	authenticatedSafe, err := asn1.Marshal([]contentInfo{{
		ContentType: oidDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: berEncode(0x04, keySafe)},
	}, {
		ContentType: oidEncryptedDataContentType,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: encryptedCerts},
	}})
	if err != nil {
		return nil, err
	}

	macSalt := make([]byte, sha1.Size)
	if _, err := io.ReadFull(rand.Reader, macSalt); err != nil {
		return nil, err
	}
	macKey := pkcs12KDF(storePassword, macSalt, 3, sha1.Size, pkcs12Iterations)
	mac := hmac.New(sha1.New, macKey)
	mac.Write(authenticatedSafe)

	return asn1.Marshal(struct {
		Version  int
		AuthSafe contentInfo
		MacData  macData
	}{
		Version: 3,
		AuthSafe: contentInfo{
			ContentType: oidDataContentType,
			Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
				Bytes: berEncode(0x04, authenticatedSafe)},
		},
		MacData: macData{
			Mac: digestInfo{
				Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.NullRawValue},
				Digest:    mac.Sum(nil),
			},
			MacSalt:    macSalt,
			Iterations: pkcs12Iterations,
		},
	})
}

// resignPKCS12 turns a keystore as it arrived into DER a Go reader will accept,
// after checking the password against the file's own integrity check.
//
// **The re-signing is forced by the normalisation and is the subtle part.** A
// PKCS12's MAC covers the AuthenticatedSafe's content octets, and this cut
// rewrites those from BER to DER, so the recorded digest cannot match the bytes
// the decoder is handed. Verifying the recorded digest against the **original**
// content and then recomputing one over the rewritten content keeps the
// password check exactly where the format put it - a wrong storePassword is
// still a MAC failure, which is the 400 the endpoint answers - while giving the
// decoder something it can read. Silently letting the decoder's own check pass
// on a recomputed MAC and nothing else would make a wrong password come back as
// an unreadable key bag instead, which is a different status.
func resignPKCS12(raw []byte, password string) ([]byte, error) {
	outer, err := berToDER(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	var pfx pfxPDU
	if rest, err := asn1.Unmarshal(outer, &pfx); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if pfx.Version != 3 || !pfx.AuthSafe.ContentType.Equal(oidDataContentType) {
		return nil, ErrMalformed
	}
	// Only SHA-1 is recognised, because it is what Keycloak's writer uses and
	// what the decoder behind this can read. A keystore MAC'd with SHA-256 -
	// a modern keytool's default - is an unreadable keystore rather than a
	// wrong password, and answering ErrMalformed is what says so.
	if !pfx.MacData.Mac.Algorithm.Algorithm.Equal(oidSHA1) {
		return nil, ErrMalformed
	}
	if pfx.MacData.Iterations < 1 || pfx.MacData.Iterations > pkcs12MaxIterations {
		return nil, ErrMalformed
	}

	var authenticatedSafe []byte
	if rest, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedSafe); err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !pkcs12MacEquals(pfx.MacData, authenticatedSafe, password) {
		return nil, ErrPasswordVerification
	}

	// The one nested structure the schema names: the AuthenticatedSafe inside
	// the content octets, which Keycloak writes with indefinite lengths of its
	// own.
	normalised, err := berToDER(authenticatedSafe)
	if err != nil {
		return nil, ErrMalformed
	}
	pfx.AuthSafe.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: berEncode(0x04, normalised)}
	mac := hmac.New(sha1.New, pkcs12KDF(password, pfx.MacData.MacSalt, 3, sha1.Size, pfx.MacData.Iterations))
	mac.Write(normalised)
	pfx.MacData.Mac.Digest = mac.Sum(nil)
	return asn1.Marshal(pfx)
}

// pkcs12MaxIterations bounds what an uploaded file can make this compute. The
// derivation is a SHA-1 chain, so the count is a caller-supplied loop bound.
const pkcs12MaxIterations = 1 << 20

func pkcs12MacEquals(m macData, message []byte, password string) bool {
	mac := hmac.New(sha1.New, pkcs12KDF(password, m.MacSalt, 3, sha1.Size, m.Iterations))
	mac.Write(message)
	return hmac.Equal(m.Mac.Digest, mac.Sum(nil))
}

type pfxPDU struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

// pkcs12Bag wraps a bag value with the two attributes an alias needs:
//
//	SafeBag ::= SEQUENCE { bagId OID, bagValue [0] EXPLICIT ANY,
//	                       bagAttributes SET OF Attribute OPTIONAL }
//
// The tags are laid out with berEncode rather than with struct tags because
// encoding/asn1 **silently drops an explicit tag** on an asn1.RawValue that
// carries FullBytes: makeField returns the bytes verbatim before it looks at
// the parameters. A bag written that way loses its [0] and reads back as
// nothing, which is how this was found.
//
// friendlyName is a BMPString, which encoding/asn1 cannot marshal at all, so it
// is laid out here too: UTF-16 big-endian with no terminator, inside tag 0x1e.
func pkcs12Bag(id asn1.ObjectIdentifier, value []byte, alias string, localKeyID []byte) (asn1.RawValue, error) {
	bagID, err := asn1.Marshal(id)
	if err != nil {
		return asn1.RawValue{}, err
	}
	name, err := pkcs12Attribute(oidFriendlyName, berEncode(0x1e, utf16BigEndian(alias)))
	if err != nil {
		return asn1.RawValue{}, err
	}
	attributes := name
	if localKeyID != nil {
		keyID, err := pkcs12Attribute(oidLocalKeyID, berEncode(0x04, localKeyID))
		if err != nil {
			return asn1.RawValue{}, err
		}
		attributes = append(attributes, keyID...)
	}
	body := append([]byte{}, bagID...)
	body = append(body, berEncode(0xa0, value)...)
	body = append(body, berEncode(0x31, attributes)...)
	return asn1.RawValue{FullBytes: berEncode(0x30, body)}, nil
}

// pkcs12Attribute is SEQUENCE { attrId OID, attrValues SET OF ANY }.
func pkcs12Attribute(id asn1.ObjectIdentifier, value []byte) ([]byte, error) {
	attrID, err := asn1.Marshal(id)
	if err != nil {
		return nil, err
	}
	return berEncode(0x30, append(attrID, berEncode(0x31, value)...)), nil
}

// encryptPKCS12Safe wraps the certificate bags in the encryptedData ContentInfo
// the format's second half is, encrypted with the same 3DES algorithm the key
// bag uses.
//
// Keycloak encrypts this half with 40-bit RC2, which Go does not implement and
// which is not worth adding: a broken cipher is a poor thing to write to match
// bytes nothing compares. The algorithm identifier is what a reader dispatches
// on, so a store written this way opens everywhere one written the other way
// does.
func encryptPKCS12Safe(safeContents []byte, password string) ([]byte, error) {
	salt := make([]byte, sha1.Size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	sealed, err := tripleDESCBC(pkcs7Pad(safeContents, des.BlockSize), password, salt)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbeParams{Salt: salt, Iterations: pkcs12Iterations})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedData{
		Version: 0,
		EncryptedContentInfo: encryptedContentInfo{
			ContentType: oidDataContentType,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidPBEWithSHAAnd3DESCBC,
				Parameters: asn1.RawValue{FullBytes: params},
			},
			EncryptedContent: sealed,
		},
	})
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

// tripleDESCBC encrypts under the key and IV RFC 7292's derivation gives for
// this password and salt.
func tripleDESCBC(padded []byte, password string, salt []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(pkcs12KDF(password, salt, 1, 24, pkcs12Iterations))
	if err != nil {
		return nil, err
	}
	iv := pkcs12KDF(password, salt, 2, des.BlockSize, pkcs12Iterations)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return out, nil
}

// sealPKCS12Key encrypts a PKCS#8 key into a pkcs8ShroudedKeyBag value with
// pbeWithSHAAnd3-KeyTripleDES-CBC, which is the algorithm Keycloak's own store
// uses and one x/crypto/pkcs12 can read - so what this writes, ReadPKCS12 reads.
func sealPKCS12Key(pkcs8Key []byte, password string) ([]byte, error) {
	salt := make([]byte, sha1.Size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	sealed, err := tripleDESCBC(pkcs7Pad(pkcs8Key, des.BlockSize), password, salt)
	if err != nil {
		return nil, err
	}
	params, err := asn1.Marshal(pbeParams{Salt: salt, Iterations: pkcs12Iterations})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithSHAAnd3DESCBC,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		Data: sealed,
	})
}

func pkcs7Pad(b []byte, size int) []byte {
	n := size - len(b)%size
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs12KDF is RFC 7292 appendix B.2 over SHA-1.
//
// id is 1 for an encryption key, 2 for an IV and 3 for a MAC key. The password
// is a BMPString **with** its terminating NUL, which is the one place this
// differs from javaPasswordBytes - and the reason the two are separate
// functions rather than one with a flag.
func pkcs12KDF(password string, salt []byte, id byte, size, iterations int) []byte {
	const u, v = sha1.Size, sha1.BlockSize
	pw := utf16BigEndian(password)
	pw = append(pw, 0, 0)

	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	fill := func(src []byte) []byte {
		if len(src) == 0 {
			return nil
		}
		n := ((len(src) + v - 1) / v) * v
		out := make([]byte, n)
		for i := range out {
			out[i] = src[i%len(src)]
		}
		return out
	}
	I := append(fill(salt), fill(pw)...)

	out := make([]byte, 0, size)
	for len(out) < size {
		h := sha1.New()
		h.Write(D)
		h.Write(I)
		A := h.Sum(nil)
		for i := 1; i < iterations; i++ {
			h.Reset()
			h.Write(A)
			A = h.Sum(nil)
		}
		out = append(out, A...)
		if len(out) >= size {
			break
		}
		// I_j = (I_j + B + 1) mod 2^v for every v-byte block, where B is A
		// repeated to v bytes. Done big-endian with a carry, which is what
		// "mod 2^v" means over a byte slice.
		B := make([]byte, v)
		for i := range B {
			B[i] = A[i%u]
		}
		for j := 0; j < len(I); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(I[j+k]) + int(B[k]) + carry
				I[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// utf16BigEndian is a string as a BMPString's content octets.
func utf16BigEndian(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2*i:], u)
	}
	return out
}
