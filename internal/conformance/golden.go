package conformance

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
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

// GoldenPath turns a case ID into a file path under dir. IDs are validated as
// slug paths by TestCatalogIsWellFormed, so no segment can escape dir.
func GoldenPath(dir, id string) string {
	return filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(id)+".http")
}
