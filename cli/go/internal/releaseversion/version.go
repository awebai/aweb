// Package releaseversion compares aweb's Python rcN and npm -rc.N releases.
package releaseversion

import (
	"regexp"
	"strconv"
	"strings"
)

var spelling = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(?:(?:rc|-rc\.)([1-9][0-9]*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

type release struct {
	parts []uint64
	rc    uint64 // Zero denotes a final release.
}

func parse(raw string) (release, bool) {
	match := spelling.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return release{}, false
	}
	out := release{}
	for _, part := range strings.Split(match[1], ".") {
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return release{}, false
		}
		out.parts = append(out.parts, number)
	}
	if match[2] != "" {
		number, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			return release{}, false
		}
		out.rc = number
	}
	return out, true
}

// Compare returns -1, 0 or 1 for a < b, a == b or a > b. RC serials sort
// numerically below their matching final; build metadata does not affect order.
// The bool is false if either input is outside the supported release spellings.
func Compare(a, b string) (int, bool) {
	left, ok := parse(a)
	if !ok {
		return 0, false
	}
	right, ok := parse(b)
	if !ok {
		return 0, false
	}
	n := len(left.parts)
	if len(right.parts) > n {
		n = len(right.parts)
	}
	for i := 0; i < n; i++ {
		var x, y uint64
		if i < len(left.parts) {
			x = left.parts[i]
		}
		if i < len(right.parts) {
			y = right.parts[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	if left.rc == right.rc {
		return 0, true
	}
	if left.rc == 0 {
		return 1, true
	}
	if right.rc == 0 || left.rc < right.rc {
		return -1, true
	}
	return 1, true
}
