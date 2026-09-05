package conformance

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// goldenDir is where recorded responses live, relative to the package.
const goldenDir = "testdata/golden"

// volatilePlaceholder replaces the value of a header that changes per
// response. The header keeps its name, so a header disappearing is still
// visible in the diff.
const volatilePlaceholder = "{{volatile}}"

// uuidTailPlaceholder replaces the last path segment of a header whose value
// is a URL ending in a server-minted id. Everything before it stays in the
// golden and stays compared. See Case.VolatileTailHeaders.
const uuidTailPlaceholder = "{{uuid}}"

// uuidPattern is the canonical 8-4-4-4-12 spelling, lower case, which is how
// every measured admin Location spells the id it ends in.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// MaskURLTail replaces the final path segment of a URL with
// uuidTailPlaceholder, and reports whether it could.
//
// It refuses rather than masking when the tail is not a UUID, and the refusal
// is the point. Three of the seven admin creates end their Location in a name
// the request chose - the role name, the realm name - and masking those would
// throw away a measurement while looking like it had checked one, which is the
// failure Normalize's doc comment names. A case whose tail is not minted
// should assert its Location whole instead of declaring it here.
//
// It lives beside recordedHeaders rather than in the recorder because the
// recorder is behind the docker build tag, and both sides of the comparison
// have to mask identically or the golden and the response can never agree.
func MaskURLTail(value string) (string, bool) {
	cut := strings.LastIndex(value, "/")
	if cut < 0 {
		return "", false
	}
	if !uuidPattern.MatchString(value[cut+1:]) {
		return "", false
	}
	return value[:cut+1] + uuidTailPlaceholder, true
}

// VolatileHeaders change on every response and would otherwise make every
// `make record` produce a diff, which is how a recorder's output stops being
// read.
var VolatileHeaders = []string{"Date", "Content-Length"}

// Header is one response header. Headers are stored as an ordered slice
// rather than an http.Header because a map loses the order a diff reads by.
type Header struct {
	Name  string
	Value string
}

// Golden is a recorded response.
type Golden struct {
	RequestLine string
	Status      int
	Headers     []Header
	Body        []byte
}

// FormatGolden renders a Golden as the .http file that gets committed:
// the request as a comment, the status line, every header, a blank line,
// then the body with nothing appended after it.
func FormatGolden(g Golden) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n", g.RequestLine)
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\n", g.Status, http.StatusText(g.Status))
	for _, h := range g.Headers {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	b.WriteByte('\n')
	b.Write(g.Body)
	return b.Bytes()
}

// ParseGolden reads back what FormatGolden wrote.
func ParseGolden(raw []byte) (Golden, error) {
	head, body, found := bytes.Cut(raw, []byte("\n\n"))
	if !found {
		return Golden{}, fmt.Errorf("conformance: golden has no blank line separating head from body")
	}
	lines := strings.Split(string(head), "\n")
	if len(lines) < 2 {
		return Golden{}, fmt.Errorf("conformance: golden needs a request comment and a status line")
	}
	if !strings.HasPrefix(lines[0], "# ") {
		return Golden{}, fmt.Errorf("conformance: golden must open with a request comment")
	}
	g := Golden{RequestLine: strings.TrimPrefix(lines[0], "# "), Body: body}

	fields := strings.Fields(lines[1])
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return Golden{}, fmt.Errorf("conformance: %q is not a status line", lines[1])
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return Golden{}, fmt.Errorf("conformance: status code in %q: %w", lines[1], err)
	}
	g.Status = status

	for _, line := range lines[2:] {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			return Golden{}, fmt.Errorf("conformance: %q is not a header", line)
		}
		g.Headers = append(g.Headers, Header{Name: name, Value: value})
	}
	return g, nil
}

// recordedHeaders sorts headers by name so a re-record produces no spurious
// diff, and blanks the values that change per response. Captured values are
// masked here too: a token can arrive in a header as easily as in a body.
//
// Three masks apply. The package-level VolatileHeaders covers every case;
// c.VolatileHeaders covers the ones this case knows about; and
// c.VolatileTailHeaders masks the last path segment alone, which is how the
// admin API's per-request Location keeps everything before its UUID.
//
// It returns an error when a tail cannot be masked. A recorder that quietly
// wrote a live UUID into a golden would produce churn on every run and a
// contract nobody can read, so this is loud at the moment of recording rather
// than a surprise in the diff.
//
// It lives here rather than beside the recorder that calls it because the
// recorder is behind the docker build tag, and logic nothing can test without
// Docker is logic nothing tests.
func recordedHeaders(h http.Header, base string, c Case, vars map[string]string) ([]Header, error) {
	volatile := make(map[string]bool, len(VolatileHeaders)+len(c.VolatileHeaders))
	for _, name := range VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}
	for _, name := range c.VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}
	tail := make(map[string]bool, len(c.VolatileTailHeaders))
	for _, name := range c.VolatileTailHeaders {
		tail[http.CanonicalHeaderKey(name)] = true
	}

	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Header, 0, len(names))
	for _, name := range names {
		canonical := http.CanonicalHeaderKey(name)
		// Every value, not just the first. userinfo's 200 sends Cache-Control
		// twice - no-store, then no-cache - and recording one of them would
		// commit a contract Keycloak does not have.
		for _, value := range h.Values(name) {
			switch {
			case volatile[canonical]:
				value = volatilePlaceholder
			case tail[canonical]:
				value = string(ReplaceIssuer(ReplaceCaptured([]byte(value), vars), base))
				masked, ok := MaskURLTail(value)
				if !ok {
					return nil, fmt.Errorf("conformance: %s declares %s a volatile tail, "+
						"but %q does not end in a UUID - assert it whole instead", c.ID, name, value)
				}
				value = masked
			default:
				value = string(ReplaceIssuer(ReplaceCaptured([]byte(value), vars), base))
			}
			out = append(out, Header{Name: name, Value: value})
		}
	}
	return out, nil
}

// RefuseNonTextBody reports why body may not be written to a golden, and nil
// when it may.
//
// **This is F161's answer, stated where it can fail.** The question that entry
// asks is what a golden over a binary body would assert, and the measured answer
// is nothing. `POST .../certificates/{attr}/download` and its
// `generate-and-download` sibling answer a JKS, PKCS12 or BCFKS keystore, and on
// 2026-09-05 twelve requests for each of the six combinations produced twelve
// distinct bodies every time: the store is re-encrypted under a fresh salt even
// when the key inside it has not moved. The length does not survive either -
// generate-and-download's JKS came back 4412, 4413, 4414 and 4415 bytes, and
// download's is stable only until the key is regenerated, which is what a
// fixture does on every recording. So a golden holding those bytes fails on the
// next run of the recorder that wrote it.
//
// F113's rule already covers the case and was written for a different one: a
// response carrying a per-request value cannot be Recorded, whatever else is
// true of it, because Recorded is a promise the recorder has to be able to keep.
// This is that rule made checkable one layer down, over the bytes rather than
// over the status.
//
// The second reason needs no measurement. A golden is read in a diff before a
// `make record` is committed - that reading is the last thing standing between
// a wrong contract and the repository - and a keystore is not something anybody
// reads. One cut has already had a re-record move five files in chapters it
// never touched, and it was caught by reading them.
//
// It is deliberately **not** a mask and not an escape hatch. A case whose
// response is binary carries no golden and is therefore not Implemented, which
// is the honest state: the operation is counted as unserved rather than served
// behind an assertion about a length. Reopening this means building the decoded
// projection F161 calls shape 2, and the argument against that is in
// docs/superpowers/plans/2026-09-04-f161-binary-goldens.md section 2 - it costs a
// JKS reader Go does not have, to assert a key that GET .../certificates/{attr}
// already pins byte for byte.
//
// "Text" is valid UTF-8 with no control byte other than tab, newline and
// carriage return. All 872 golden bodies committed on 2026-09-05 pass, so the
// rule was measured against the tree before it was written rather than after.
func RefuseNonTextBody(body []byte) error {
	if !utf8.Valid(body) {
		return fmt.Errorf("conformance: body is not valid UTF-8, so it is a binary body; " +
			"a golden holding one asserts nothing - see RefuseNonTextBody")
	}
	for i, b := range body {
		if b >= 0x20 && b != 0x7f {
			continue
		}
		if b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return fmt.Errorf("conformance: body carries control byte %#02x at offset %d, "+
			"so it is a binary body; a golden holding one asserts nothing - "+
			"see RefuseNonTextBody", b, i)
	}
	return nil
}

// GoldenPath turns a case ID into a file path under dir. IDs are validated as
// slug paths by TestCatalogIsWellFormed, so no segment can escape dir.
func GoldenPath(dir, id string) string {
	return filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(id)+".http")
}
