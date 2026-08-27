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
	Name       string
	Served     int
	Recorded   int
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
	for sc.Scan() {
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
