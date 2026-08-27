package parity

import (
	"fmt"
	"strings"
)

// Marker leads every comment this renders, so the workflow can find the one it
// posted before and update it rather than appending a second.
const Marker = "<!-- gloak-parity -->"

// Render turns a diff into the comment body. decreaseReason is the text of the
// pull request's Parity-decrease line, empty when there is none.
func Render(d Diff, decreaseReason string) string {
	var b strings.Builder
	b.WriteString(Marker)
	b.WriteString("\n\n")

	switch {
	case d.Delta() == 0:
		fmt.Fprintf(&b, "Parity: %d of %d, no change.\n", d.AfterServed, d.Documented)
	default:
		fmt.Fprintf(&b, "Parity: %d -> %d of %d (%+d)\n",
			d.BeforeServed, d.AfterServed, d.Documented, d.Delta())
	}

	if len(d.Moved) > 0 {
		b.WriteString("\n```\n")
		fmt.Fprintf(&b, "%-30s  %6s  %5s  %5s\n", "chapter", "before", "after", "delta")
		for _, m := range d.Moved {
			fmt.Fprintf(&b, "%-30s  %6d  %5d  %+5d\n",
				m.Name, m.Before, m.After, m.After-m.Before)
		}
		b.WriteString("```\n")
	}

	if len(d.Appeared) > 0 {
		fmt.Fprintf(&b, "\nNew chapters: %s\n", strings.Join(d.Appeared, ", "))
	}
	if len(d.Disappeared) > 0 {
		fmt.Fprintf(&b, "\nChapters gone: %s\n", strings.Join(d.Disappeared, ", "))
	}

	if d.Decreased() {
		if decreaseReason != "" {
			fmt.Fprintf(&b, "\nThe total fell, and the pull request gives a reason:\n\n> %s\n",
				decreaseReason)
		} else {
			b.WriteString("\nThe total fell and no reason was given. " +
				"Add a `Parity-decrease: <reason>` line to the description.\n")
		}
	}

	return b.String()
}
