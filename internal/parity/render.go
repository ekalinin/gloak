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
	case d.Delta() != 0:
		fmt.Fprintf(&b, "Parity: %d -> %d of %d (%+d)\n",
			d.BeforeServed, d.AfterServed, d.Documented, d.Delta())
	case len(d.Moved) == 0:
		fmt.Fprintf(&b, "Parity: %d of %d, no change.\n", d.AfterServed, d.Documented)
	default:
		// The total is flat and chapters moved. "no change" would contradict
		// the table printed below it, which is a comment saying two things at
		// once and nothing that resolves them.
		fmt.Fprintf(&b, "Parity: %d of %d, total unchanged.\n", d.AfterServed, d.Documented)
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

	// Why the total did not move, when the reason is that nothing which moved
	// counts towards it. Without this the reader is left to reconcile a flat
	// total against a table of work on their own.
	if d.Delta() == 0 && d.MovedOutsideTheTotal() {
		b.WriteString("\nEvery chapter above is unenumerated: nobody has counted its " +
			"surface, so it has no denominator and the meter leaves it out of the " +
			"total. The total is flat because the work landed where it is not " +
			"counted, not because nothing was served.\n")
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
