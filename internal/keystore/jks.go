package keystore

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf16"

	"crypto/x509/pkix"
)

// The JKS file layout, read off a keystore Keycloak produced on 2026-09-06 and
// confirmed by recomputing the trailing digest, which matched:
//
//	uint32   0xfeedfeed
//	uint32   version, 2
//	uint32   entry count
//	entry*   uint32 tag, UTF alias, int64 milliseconds
//	           tag 1: uint32 len, EncryptedPrivateKeyInfo, uint32 chain len,
//	                  then per certificate UTF type, uint32 len, DER
//	           tag 2: UTF type, uint32 len, DER
//	[20]byte SHA-1 store check
//
// Nothing here is written from memory: every field was located by reading the
// file and every length printed, so a wrong guess would have produced a
// nonsensical length rather than a plausible answer.
const (
	jksMagic          uint32 = 0xfeedfeed
	jksVersion        uint32 = 2
	jksTagPrivateKey  uint32 = 1
	jksTagTrustedCert uint32 = 2
	jksCertType              = "X.509"
)

// jksSalt is the phrase SunJCE mixes into the store's integrity digest.
//
// It is not decoration and it is not a constant anybody may tidy: the digest is
// SHA1(password ‖ "Mighty Aphrodite" ‖ everything before it), and this
// repository's copy was confirmed against a real keystore rather than copied
// out of an article - the recomputed digest matched byte for byte, and both a
// wrong password and the store's own key password produced a mismatch.
var jksSalt = []byte("Mighty Aphrodite")

// jksKeyProtectorOID is 1.3.6.1.4.1.42.2.17.1.1, SunJCE's proprietary key
// protector, and it is the only algorithm a JKS key entry is ever sealed with.
// The AlgorithmIdentifier carries **no parameters at all**, measured: the
// encoded sequence is 12 bytes and holds nothing but the OID.
var jksKeyProtectorOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}

// encryptedPrivateKeyInfo is RFC 5208's, with pkix.AlgorithmIdentifier's
// optional Parameters left unset so that nothing is emitted for them.
type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// ReadJKS parses a JKS and verifies its integrity against storePassword.
//
// **An empty store password skips the check**, which is the format's own rule
// and is measured on the endpoint: `POST .../upload` of a JKS with no
// storePassword field at all answers 200, where the same request against a
// PKCS12 answers `error loading keystore`. Two formats, one missing field, two
// answers.
//
// The key entries come back still sealed, in Entry.ProtectedKey. See
// [UnlockJKSKey] for why that is a separate step.
func ReadJKS(raw []byte, storePassword string) (*Store, error) {
	r := &reader{b: raw}
	if r.u32() != jksMagic {
		return nil, ErrMalformed
	}
	if v := r.u32(); v != jksVersion {
		return nil, fmt.Errorf("%w: unsupported JKS version %d", ErrMalformed, v)
	}
	count := r.u32()
	// A corrupt count must not make this allocate the whole address space; a
	// keystore has a handful of entries and each costs at least a dozen bytes.
	if int(count) > len(raw)/12 {
		return nil, ErrMalformed
	}
	store := &Store{}
	for i := uint32(0); i < count; i++ {
		e := Entry{}
		tag := r.u32()
		e.Alias = r.utf()
		e.CreatedAt = time.UnixMilli(r.i64()).UTC()
		switch tag {
		case jksTagPrivateKey:
			e.ProtectedKey = r.blob()
			chain := r.u32()
			if int(chain) > len(raw)/8 {
				return nil, ErrMalformed
			}
			for j := uint32(0); j < chain; j++ {
				if r.utf() != jksCertType {
					return nil, ErrMalformed
				}
				e.Chain = append(e.Chain, r.blob())
			}
		case jksTagTrustedCert:
			if r.utf() != jksCertType {
				return nil, ErrMalformed
			}
			e.Chain = [][]byte{r.blob()}
		default:
			return nil, ErrMalformed
		}
		if r.err != nil {
			return nil, ErrMalformed
		}
		store.Entries = append(store.Entries, e)
	}
	if r.err != nil || len(raw)-r.at != sha1.Size {
		return nil, ErrMalformed
	}
	// The check is over everything before the digest, so the offset the reader
	// stopped at is what is hashed - not a recomputed length.
	if storePassword != "" {
		want := jksStoreDigest(raw[:r.at], storePassword)
		if subtle.ConstantTimeCompare(want, raw[r.at:]) != 1 {
			return nil, ErrPasswordVerification
		}
	}
	return store, nil
}

// WriteJKS encodes a store, sealing every key entry with keyPassword and
// signing the whole file with storePassword.
func WriteJKS(s *Store, storePassword, keyPassword string) ([]byte, error) {
	var b bytes.Buffer
	w := &writer{b: &b}
	w.u32(jksMagic)
	w.u32(jksVersion)
	w.u32(uint32(len(s.Entries)))
	for _, e := range s.Entries {
		if e.PrivateKey == nil && e.ProtectedKey == nil {
			if len(e.Chain) != 1 {
				return nil, errors.New("keystore: a trusted certificate entry holds exactly one certificate")
			}
			w.u32(jksTagTrustedCert)
			w.utf(e.Alias)
			w.i64(e.CreatedAt.UnixMilli())
			w.utf(jksCertType)
			w.blob(e.Chain[0])
			continue
		}
		sealed := e.ProtectedKey
		if sealed == nil {
			var err error
			if sealed, err = sealJKSKey(e.PrivateKey, keyPassword); err != nil {
				return nil, err
			}
		}
		w.u32(jksTagPrivateKey)
		w.utf(e.Alias)
		w.i64(e.CreatedAt.UnixMilli())
		w.blob(sealed)
		w.u32(uint32(len(e.Chain)))
		for _, cert := range e.Chain {
			w.utf(jksCertType)
			w.blob(cert)
		}
	}
	if w.err != nil {
		return nil, w.err
	}
	return append(b.Bytes(), jksStoreDigest(b.Bytes(), storePassword)...), nil
}

// jksStoreDigest is SHA1(password ‖ "Mighty Aphrodite" ‖ content).
func jksStoreDigest(content []byte, password string) []byte {
	h := sha1.New()
	h.Write(javaPasswordBytes(password))
	h.Write(jksSalt)
	h.Write(content)
	return h.Sum(nil)
}

// UnlockJKSKey recovers a PKCS#8 key from a JKS key entry.
//
// SunJCE's KeyProtector is a SHA-1 keystream XOR rather than a cipher. The
// sealed blob is
//
//	salt[20] ‖ (key XOR keystream) ‖ SHA1(password ‖ key)[20]
//
// where the keystream is SHA1(password ‖ previous), starting from the salt.
// The construction was confirmed against a keystore 26.7.1 produced: the check
// digest matched, the PKCS#8 inside decoded, and the PKCS#1 within it is byte
// identical to what `GET .../certificates/{attr}` reports for that client. The
// controls failed as they must - the store password and a wrong password both
// mismatched.
//
// It is a separate call rather than part of ReadJKS because **a wrong key
// password is not an error on this endpoint**: `POST .../upload` answers 200
// with the certificate alone, measured on an absent password and on a wrong
// one. A reader that failed the read would answer 400 where Keycloak answers
// 200.
func UnlockJKSKey(sealed []byte, password string) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(sealed, &epki)
	if err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	if !epki.Algorithm.Algorithm.Equal(jksKeyProtectorOID) {
		return nil, fmt.Errorf("%w: key sealed with %v rather than SunJCE's key protector",
			ErrMalformed, epki.Algorithm.Algorithm)
	}
	blob := epki.Data
	if len(blob) < 2*sha1.Size {
		return nil, ErrMalformed
	}
	salt := blob[:sha1.Size]
	check := blob[len(blob)-sha1.Size:]
	sealedKey := blob[sha1.Size : len(blob)-sha1.Size]

	pw := javaPasswordBytes(password)
	plain := make([]byte, len(sealedKey))
	previous := salt
	for off := 0; off < len(sealedKey); off += sha1.Size {
		h := sha1.New()
		h.Write(pw)
		h.Write(previous)
		digest := h.Sum(nil)
		previous = digest
		for i := 0; i < sha1.Size && off+i < len(sealedKey); i++ {
			plain[off+i] = sealedKey[off+i] ^ digest[i]
		}
	}
	h := sha1.New()
	h.Write(pw)
	h.Write(plain)
	if subtle.ConstantTimeCompare(h.Sum(nil), check) != 1 {
		return nil, ErrPasswordVerification
	}
	return plain, nil
}

// sealJKSKey is UnlockJKSKey's inverse, over a fresh random salt.
func sealJKSKey(pkcs8Key []byte, password string) ([]byte, error) {
	salt := make([]byte, sha1.Size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	pw := javaPasswordBytes(password)
	sealed := make([]byte, len(pkcs8Key))
	previous := salt
	for off := 0; off < len(pkcs8Key); off += sha1.Size {
		h := sha1.New()
		h.Write(pw)
		h.Write(previous)
		digest := h.Sum(nil)
		previous = digest
		for i := 0; i < sha1.Size && off+i < len(pkcs8Key); i++ {
			sealed[off+i] = pkcs8Key[off+i] ^ digest[i]
		}
	}
	h := sha1.New()
	h.Write(pw)
	h.Write(pkcs8Key)

	blob := make([]byte, 0, len(salt)+len(sealed)+sha1.Size)
	blob = append(blob, salt...)
	blob = append(blob, sealed...)
	blob = append(blob, h.Sum(nil)...)
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: jksKeyProtectorOID},
		Data:      blob,
	})
}

// javaPasswordBytes is a password as Java hands it to a MessageDigest here:
// each UTF-16 code unit big-endian, with **no terminator**.
//
// PKCS12's key derivation uses the same encoding *with* a terminating NUL, so
// the two are deliberately separate functions - sharing one and adding a flag
// is how a caller ends up passing the wrong one.
func javaPasswordBytes(password string) []byte {
	units := utf16.Encode([]rune(password))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// reader reads the big-endian shapes java.io.DataInputStream writes, recording
// the first failure and answering zeroes afterwards so that a truncated file
// produces one error rather than a panic at whichever field ran off the end.
type reader struct {
	b   []byte
	at  int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.at+n > len(r.b) {
		r.err = ErrMalformed
		return nil
	}
	out := r.b[r.at : r.at+n]
	r.at += n
	return out
}

func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *reader) i64() int64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}

// blob is a uint32 length followed by that many bytes.
func (r *reader) blob() []byte {
	n := r.u32()
	if int(n) > len(r.b) {
		r.err = ErrMalformed
		return nil
	}
	return r.take(int(n))
}

// utf is java.io.DataInput's modified UTF-8: a uint16 byte count, then the
// string with U+0000 written as C0 80 and characters outside the BMP written as
// a surrogate pair of three-byte sequences.
func (r *reader) utf() string {
	n := r.take(2)
	if n == nil {
		return ""
	}
	raw := r.take(int(binary.BigEndian.Uint16(n)))
	if raw == nil {
		return ""
	}
	return decodeModifiedUTF8(raw)
}

type writer struct {
	b   *bytes.Buffer
	err error
}

func (w *writer) u32(v uint32) {
	_ = binary.Write(w.b, binary.BigEndian, v)
}

func (w *writer) i64(v int64) {
	_ = binary.Write(w.b, binary.BigEndian, v)
}

func (w *writer) blob(v []byte) {
	w.u32(uint32(len(v)))
	w.b.Write(v)
}

func (w *writer) utf(s string) {
	encoded := encodeModifiedUTF8(s)
	if len(encoded) > 0xffff {
		w.err = errors.New("keystore: alias is longer than a Java UTF field can hold")
		return
	}
	_ = binary.Write(w.b, binary.BigEndian, uint16(len(encoded)))
	w.b.Write(encoded)
}

// encodeModifiedUTF8 and decodeModifiedUTF8 implement the two places Java's
// encoding differs from Go's: U+0000 is two bytes rather than one, and a
// character outside the BMP is its surrogate pair rather than a four-byte
// sequence.
//
// They are here rather than approximated by a plain string cast because an
// alias is a clientId or a realm name, both caller-chosen, and a keystore whose
// alias is written one way and read another is a bug nobody would find from the
// endpoint.
func encodeModifiedUTF8(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, u := range utf16.Encode([]rune(s)) {
		switch {
		case u >= 0x0001 && u <= 0x007f:
			out = append(out, byte(u))
		case u == 0 || u <= 0x07ff:
			out = append(out, byte(0xc0|(u>>6)), byte(0x80|(u&0x3f)))
		default:
			out = append(out, byte(0xe0|(u>>12)), byte(0x80|((u>>6)&0x3f)), byte(0x80|(u&0x3f)))
		}
	}
	return out
}

func decodeModifiedUTF8(b []byte) string {
	units := make([]uint16, 0, len(b))
	for i := 0; i < len(b); {
		switch c := b[i]; {
		case c < 0x80:
			units = append(units, uint16(c))
			i++
		case c&0xe0 == 0xc0 && i+1 < len(b):
			units = append(units, uint16(c&0x1f)<<6|uint16(b[i+1]&0x3f))
			i += 2
		case c&0xf0 == 0xe0 && i+2 < len(b):
			units = append(units, uint16(c&0x0f)<<12|uint16(b[i+1]&0x3f)<<6|uint16(b[i+2]&0x3f))
			i += 3
		default:
			// Nothing else is legal modified UTF-8. Java throws here; an alias
			// is not worth failing a whole read for, so the byte is taken as
			// itself and the caller's Lookup simply will not match.
			units = append(units, uint16(c))
			i++
		}
	}
	return string(utf16.Decode(units))
}
