package parity

import (
	"regexp"
	"strings"
)

// decreaseLine matches the escape hatch a pull request body may carry: a line
// that, ignoring leading and trailing whitespace, reads "Parity-decrease:"
// followed by the reason, case-insensitive. Only a line where that is the
// whole prefix counts:
//
//   - "Parity-decrease: moved behind P4" matches, anywhere in the body,
//     indented or not, case-insensitive, CRLF or LF.
//   - "some text Parity-decrease: reason" does not match: the marker must
//     start the line, not appear mid-sentence.
//   - "This does not need a Parity-decrease: label" does not match, for the
//     same reason.
//   - "- Parity-decrease: reason" does not match either: a markdown list
//     marker is not whitespace, so it counts as text before the marker the
//     same way prose does. This is a deliberate choice, not an oversight -
//     the escape hatch takes a plain line, and widening the accepted forms
//     to cover list markers is left undone until it is asked for.
//
// When a body carries more than one such line, only the first is used.
var decreaseLine = regexp.MustCompile(`(?mi)^\s*Parity-decrease:\s*(.+?)\s*$`)

// DecreaseReason extracts the reason from a pull request body's
// Parity-decrease line, or returns the empty string when there is none. See
// decreaseLine for the accepted and rejected forms.
func DecreaseReason(prBody string) string {
	m := decreaseLine.FindStringSubmatch(prBody)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}
