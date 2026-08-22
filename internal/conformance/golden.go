package conformance

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// goldenDir is where recorded responses live, relative to the package.
const goldenDir = "testdata/golden"

// volatilePlaceholder replaces the value of a header that changes per
// response. The header keeps its name, so a header disappearing is still
// visible in the diff.
const volatilePlaceholder = "{{volatile}}"

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
// Two masks apply. The package-level VolatileHeaders covers every case;
// c.VolatileHeaders covers the ones this case knows about, which is how the
// admin API's per-request Location gets masked without masking Location
// everywhere.
//
// It lives here rather than beside the recorder that calls it because the
// recorder is behind the docker build tag, and logic nothing can test without
// Docker is logic nothing tests.
func recordedHeaders(h http.Header, base string, c Case, vars map[string]string) []Header {
	volatile := make(map[string]bool, len(VolatileHeaders)+len(c.VolatileHeaders))
	for _, name := range VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}
	for _, name := range c.VolatileHeaders {
		volatile[http.CanonicalHeaderKey(name)] = true
	}

	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Header, 0, len(names))
	for _, name := range names {
		value := h.Get(name)
		if volatile[http.CanonicalHeaderKey(name)] {
			value = volatilePlaceholder
		} else {
			value = string(ReplaceIssuer(ReplaceCaptured([]byte(value), vars), base))
		}
		out = append(out, Header{Name: name, Value: value})
	}
	return out
}

// GoldenPath turns a case ID into a file path under dir. IDs are validated as
// slug paths by TestCatalogIsWellFormed, so no segment can escape dir.
func GoldenPath(dir, id string) string {
	return filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(id)+".http")
}
