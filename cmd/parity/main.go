// Command parity compares two conformance reports and prints the pull request
// comment. It exits non-zero when the total served count fell and the pull
// request body carries no Parity-decrease line.
//
// It holds no logic of its own: the format, the comparison and the rendering
// are in internal/parity, which is tested.
package main

import (
	"fmt"
	"os"

	"github.com/ekalinin/gloak/internal/parity"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: parity <before.tsv> <after.tsv>")
		os.Exit(2)
	}

	before, err := read(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	after, err := read(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	reason := parity.DecreaseReason(os.Getenv("PR_BODY"))

	d := parity.Compare(before, after)
	fmt.Print(parity.Render(d, reason))

	if d.Decreased() && reason == "" {
		fmt.Fprintf(os.Stderr, "parity: total fell from %d to %d and no Parity-decrease reason was given\n",
			d.BeforeServed, d.AfterServed)
		os.Exit(1)
	}
}

func read(path string) (parity.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return parity.Report{}, fmt.Errorf("parity: %w", err)
	}
	defer f.Close()
	return parity.Parse(f)
}
