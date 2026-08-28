// Package parity compares two parity reports written by the conformance
// meter and renders the difference.
//
// It does not import internal/conformance. The report format is the interface
// between the two, which keeps the meter's test-only boundary intact and makes
// the comparison testable without a catalogue.
package parity

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Chapter is one row of a report.
type Chapter struct {
	// Name is the chapter slug the meter groups cases under, such as
	// "admin/roles". It is unique within a report.
	Name string
	// Served is what the meter counts as served for this chapter: distinct
	// operations for a chapter with an OpenAPI tag, and Implemented cases for
	// one counted from the catalogue. The two are not interchangeable, which
	// is why nothing here recomputes either.
	Served int
	// Recorded is the count of cases whose bytes are measured and committed
	// but which nothing serves yet. It is reported, never gated: a case moving
	// from Recorded to Implemented shows up in Served.
	Recorded int
	// Documented is the chapter's denominator, from Keycloak's own API
	// description where there is one and from the catalogue otherwise.
	Documented int
	// Enumerated is false for a chapter whose surface nobody has counted.
	// Documented is 0 for those, and they are excluded from the total.
	Enumerated bool
}

// Report is one run of the meter.
type Report struct {
	Chapters []Chapter
	// Served and Documented are the totals the meter prints, not a sum of
	// the rows: an unenumerated chapter contributes to neither.
	Served       int
	Documented   int
	Unenumerated int
}

const header = "chapter\tserved\trecorded\tdocumented\tenumerated"

// Parse reads a report. Every malformed shape is an error rather than a zero
// value, because a zero report is indistinguishable from a real one that
// happens to serve nothing.
func Parse(r io.Reader) (Report, error) {
	var out Report
	sc := bufio.NewScanner(r)

	if !sc.Scan() {
		return Report{}, fmt.Errorf("parity: empty report")
	}
	if line := sc.Text(); line != header {
		return Report{}, fmt.Errorf("parity: want header %q, got %q", header, line)
	}

	seenTotal := false
	seen := map[string]bool{}
	for sc.Scan() {
		// The total row is the last row the meter writes. Anything after it
		// means the file is not a report the meter produced, and continuing
		// would let a second total overwrite the first, or a trailing chapter
		// row join a tally it was never counted in.
		if seenTotal {
			return Report{}, fmt.Errorf("parity: row after the total row: %q", sc.Text())
		}
		fields := strings.Split(sc.Text(), "\t")
		if fields[0] == "total" {
			if len(fields) != 4 {
				return Report{}, fmt.Errorf("parity: total row has %d fields, want 4", len(fields))
			}
			var err error
			if out.Served, err = strconv.Atoi(fields[1]); err != nil {
				return Report{}, fmt.Errorf("parity: total served: %w", err)
			}
			if out.Documented, err = strconv.Atoi(fields[2]); err != nil {
				return Report{}, fmt.Errorf("parity: total documented: %w", err)
			}
			if out.Unenumerated, err = strconv.Atoi(fields[3]); err != nil {
				return Report{}, fmt.Errorf("parity: total unenumerated: %w", err)
			}
			seenTotal = true
			continue
		}
		if len(fields) != 5 {
			return Report{}, fmt.Errorf("parity: chapter %q has %d fields, want 5", fields[0], len(fields))
		}
		ch := Chapter{Name: fields[0]}
		// Compare keys chapters by name, so a repeated name makes it disagree
		// with itself: the map keeps the last row while the loop sees both, and
		// Compare(r, r) reports a move that never happened. conformance.Chapters
		// is a hand-maintained slice, so a duplicated entry is a plausible typo.
		if seen[ch.Name] {
			return Report{}, fmt.Errorf("parity: chapter %q appears twice", ch.Name)
		}
		seen[ch.Name] = true
		var err error
		if ch.Served, err = strconv.Atoi(fields[1]); err != nil {
			return Report{}, fmt.Errorf("parity: %s served: %w", ch.Name, err)
		}
		if ch.Recorded, err = strconv.Atoi(fields[2]); err != nil {
			return Report{}, fmt.Errorf("parity: %s recorded: %w", ch.Name, err)
		}
		if ch.Documented, err = strconv.Atoi(fields[3]); err != nil {
			return Report{}, fmt.Errorf("parity: %s documented: %w", ch.Name, err)
		}
		if ch.Enumerated, err = strconv.ParseBool(fields[4]); err != nil {
			return Report{}, fmt.Errorf("parity: %s enumerated: %w", ch.Name, err)
		}
		out.Chapters = append(out.Chapters, ch)
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("parity: read report: %w", err)
	}
	if len(out.Chapters) == 0 {
		return Report{}, fmt.Errorf("parity: report has no chapters")
	}
	if !seenTotal {
		return Report{}, fmt.Errorf("parity: report has no total row")
	}
	return out, nil
}
