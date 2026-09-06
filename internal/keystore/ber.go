package keystore

import (
	"encoding/binary"
	"errors"
)

// berToDER rewrites BER into DER, which is what every Go ASN.1 reader needs and
// what Keycloak does not send.
//
// **This function is the whole reason a PKCS12 dependency would not have
// helped.** Keycloak writes its keystores with BouncyCastle, and BouncyCastle's
// PKCS12 writer streams: the outer SEQUENCE, the ContentInfo's [0] and the
// OCTET STRING inside it all carry the indefinite length 0x80 terminated by an
// end-of-contents pair, and the content octets are a *constructed* OCTET STRING
// whose children are 1000-byte chunks. Measured on the exact bytes
// `POST .../certificates/{attr}/download` returns, 2026-09-06:
//
//	SEQ INDEF
//	  INT 3
//	  SEQ INDEF
//	    OID 1.2.840.113549.1.7.1 data
//	    [0] INDEF
//	      OCTSTR INDEF
//	        OCTSTR 1000, OCTSTR 1000, OCTSTR 1000, OCTSTR 1000, OCTSTR 747
//
// encoding/asn1 answers `indefinite length found (not DER)` on the first byte
// of that and so, therefore, does everything built on it.
//
// Three rewrites and no more, because a fourth would be a guess about a shape
// nothing here has met:
//
//   - an indefinite length becomes the definite length of the children that
//     preceded its end-of-contents pair;
//   - a constructed OCTET STRING, tag 0x24, becomes a primitive one holding its
//     children's contents joined - always, because a constructed OCTET STRING is
//     never valid DER whatever its length says;
//   - an **indefinite-length constructed context tag** whose children are all
//     primitive OCTET STRINGs becomes a primitive value with the same tag
//     number, holding those contents joined. That is an implicitly tagged
//     string written in chunks, and `encryptedContentInfo.encryptedContent` is
//     the one field in a PKCS12 that arrives that way.
//
// **The third rule is where BER is genuinely ambiguous and the indefinite length
// is what resolves it.** `A0 80 { 04 ... } 00 00` could be an implicitly tagged
// chunked OCTET STRING or an explicit [0] holding one primitive OCTET STRING,
// and nothing in the encoding says which without a schema. The rule above reads
// it as the first, and the reason that is safe is that a writer which knew the
// length would have emitted a definite one - which this leaves alone. Measured
// on the file: every explicit [0] in it holds a **constructed** OCTET STRING,
// `A0 80 24 80 ...`, so the two shapes really are distinguishable in what
// Keycloak sends.
//
// **"Context tag" is load-bearing and nothing in a keystore proves it.** Drop
// the class test and the rule reads "any indefinite constructed node whose
// children are all OCTET STRINGs", which collapses a BER
// `SEQUENCE OF OCTET STRING` - `30 80 04 .. 04 .. 00 00` - into `10 ..`, a
// primitive universal SEQUENCE, which is not a legal tag at all and has lost
// both of its values. That shape is reachable: a PKCS12 attribute's
// `attrValues SET OF ANY` around a `localKeyId` is `31 { 04 .. }`, and a writer
// that streamed it would send `31 80 04 .. 00 00`. Keycloak's writer sends it
// definite, so **no keystore in this repository distinguishes the two
// readings** and the guard could be deleted with every corpus test still green
// - measured, by deleting it.
// TestBERToDERJoinsChunksOnlyUnderAContextTag is a hand-built byte slice rather
// than a keystore for exactly that reason.
//
// A primitive value is copied byte for byte and a definite length is re-encoded
// minimally, so a file that is already DER comes back **identical**, which is
// what TestBERToDERLeavesDERAlone pins. That property matters: it means the
// normaliser cannot quietly change a store that never needed it.
func berToDER(raw []byte) ([]byte, error) {
	out, rest, err := berValue(raw, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errBER
	}
	return out, nil
}

var errBER = errors.New("keystore: cannot read the ASN.1 encoding")

// berMaxDepth bounds the nesting this will follow.
//
// The input is an uploaded file, so it is an attacker's to shape, and every
// level of nesting here is a stack frame. A PKCS12 is about eight deep; sixty
// four is generous and finite, where "as deep as the file allows" is half a
// megabyte of frames for a one megabyte upload.
const berMaxDepth = 64

// berValue rewrites one TLV and returns it with whatever followed it.
func berValue(b []byte, depth int) (value, rest []byte, err error) {
	if depth > berMaxDepth {
		return nil, nil, errBER
	}
	tag, header, content, rest, indefinite, err := berRead(b)
	if err != nil {
		return nil, nil, err
	}
	constructed := tag&0x20 != 0
	if !constructed {
		if indefinite {
			// A primitive value cannot have an indefinite length; the encoding
			// has no way to say where it ends.
			return nil, nil, errBER
		}
		return b[:len(header)+len(content)], rest, nil
	}

	// allOctetStrings is read off the children **as they arrived**, not as they
	// come out. A constructed OCTET STRING is rewritten into a primitive one
	// above, so asking the rewritten child would see 0x04 where the file said
	// 0x24 - and 0x24 is exactly the shape that says this tag is explicit.
	// Getting that backwards turns the ContentInfo's [0] into a primitive and
	// loses the whole AuthenticatedSafe, which is how it was found.
	var children []byte
	allOctetStrings := len(content) > 0
	for len(content) > 0 {
		childTag := content[0]
		var child []byte
		child, content, err = berValue(content, depth+1)
		if err != nil {
			return nil, nil, err
		}
		if childTag != 0x04 {
			allOctetStrings = false
		}
		children = append(children, child...)
	}

	// A constructed OCTET STRING is a chunked one whatever its length says, so
	// this rewrite does not wait for an indefinite length.
	if tag == 0x24 {
		joined, err := berJoinOctetStrings(children)
		if err != nil {
			return nil, nil, err
		}
		// The joined content is **not** normalised here, and that is deliberate.
		// An OCTET STRING's content is opaque - a PKCS12 carries an encrypted
		// bag in one and a whole AuthenticatedSafe in the next - and a rewriter
		// that guessed which was which would corrupt the one it guessed wrong.
		// ReadPKCS12 normalises the one nested structure this format has, where
		// the schema says it is a structure.
		return berEncode(0x04, joined), rest, nil
	}
	// An implicitly tagged string written in chunks. See the ambiguity this
	// resolves, and what resolves it, in berToDER's comment.
	//
	// `tag&0xc0 == 0x80` is the context-specific class and it is not
	// defensiveness: without it a BER `SEQUENCE OF OCTET STRING` is rewritten
	// into a primitive universal SEQUENCE and loses its contents. No keystore
	// here distinguishes the two, so the vector that does is hand-built - see
	// TestBERToDERJoinsChunksOnlyUnderAContextTag.
	if indefinite && tag&0xc0 == 0x80 && allOctetStrings {
		joined, err := berJoinOctetStrings(children)
		if err != nil {
			return nil, nil, err
		}
		return berEncode(tag&^0x20, joined), rest, nil
	}
	return berEncode(tag, children), rest, nil
}

// berRead splits one TLV. For an indefinite length it also consumes the
// end-of-contents pair, so content is what lay between.
func berRead(b []byte) (tag byte, header, content, rest []byte, indefinite bool, err error) {
	if len(b) < 2 {
		return 0, nil, nil, nil, false, errBER
	}
	tag = b[0]
	// The high-tag-number form is not rewritten. Nothing in a keystore uses it,
	// and a rewrite of a shape nobody has produced is a guess.
	if tag&0x1f == 0x1f {
		return 0, nil, nil, nil, false, errBER
	}
	i := 1
	length := int(b[i])
	i++
	switch {
	case length == 0x80:
		end, err := berEndOfContents(b[i:])
		if err != nil {
			return 0, nil, nil, nil, false, err
		}
		return tag, b[:i], b[i : i+end], b[i+end+2:], true, nil
	case length&0x80 != 0:
		n := length & 0x7f
		if n > 4 || i+n > len(b) {
			return 0, nil, nil, nil, false, errBER
		}
		length = 0
		for _, c := range b[i : i+n] {
			length = length<<8 | int(c)
		}
		i += n
	}
	if length < 0 || i+length > len(b) {
		return 0, nil, nil, nil, false, errBER
	}
	return tag, b[:i], b[i : i+length], b[i+length:], false, nil
}

// berEndOfContents returns how far the indefinite-length content runs, by
// walking the values inside it until the 00 00 pair. Scanning for the two bytes
// instead would find them inside any nested value that happens to hold them.
func berEndOfContents(b []byte) (int, error) {
	at := 0
	for {
		if at+2 > len(b) {
			return 0, errBER
		}
		if b[at] == 0 && b[at+1] == 0 {
			return at, nil
		}
		_, header, content, _, indefinite, err := berRead(b[at:])
		if err != nil {
			return 0, err
		}
		at += len(header) + len(content)
		if indefinite {
			at += 2
		}
	}
}

// berJoinOctetStrings concatenates the contents of a run of primitive OCTET
// STRINGs. The children have already been normalised, so each is definite.
func berJoinOctetStrings(children []byte) ([]byte, error) {
	var joined []byte
	for len(children) > 0 {
		tag, header, content, rest, _, err := berRead(children)
		if err != nil {
			return nil, err
		}
		if tag != 0x04 {
			return nil, errBER
		}
		_ = header
		joined = append(joined, content...)
		children = rest
	}
	return joined, nil
}

// berEncode writes a definite-length TLV.
func berEncode(tag byte, content []byte) []byte {
	n := len(content)
	var header []byte
	switch {
	case n < 0x80:
		header = []byte{tag, byte(n)}
	case n < 1<<8:
		header = []byte{tag, 0x81, byte(n)}
	case n < 1<<16:
		header = []byte{tag, 0x82, 0, 0}
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	case n < 1<<24:
		header = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		header = []byte{tag, 0x84, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(header[2:], uint32(n))
	}
	return append(header, content...)
}
