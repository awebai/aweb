package main

import (
	"strconv"
	"strings"
)

// terminalValue is one response member that goes only to the controlling
// terminal, under the concrete pointer it was found at.
type terminalValue struct {
	Pointer string
	Value   any
}

// takeTerminalOutput finds every member of response that a terminal_output
// pointer matches (RFC 6901, with a "*" segment matching every index of an
// array) and returns them with a copy of response that no longer has them.
// response itself is not changed.
func takeTerminalOutput(response any, pointers []string) ([]terminalValue, any) {
	rest := deepCopyJSON(response)
	var taken []terminalValue
	for _, pointer := range pointers {
		segments := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
		for i := range segments {
			segments[i] = strings.ReplaceAll(strings.ReplaceAll(segments[i], "~1", "/"), "~0", "~")
		}
		taken = takeAt(rest, segments, "", taken)
	}
	return taken, rest
}

func takeAt(node any, segments []string, at string, taken []terminalValue) []terminalValue {
	if len(segments) == 0 {
		return taken
	}
	head, last := segments[0], len(segments) == 1
	switch v := node.(type) {
	case map[string]any:
		child, ok := v[head]
		if !ok {
			return taken
		}
		here := at + "/" + escapePointerSegment(head)
		if last {
			delete(v, head)
			return append(taken, terminalValue{Pointer: here, Value: child})
		}
		return takeAt(child, segments[1:], here, taken)
	case []any:
		for i := range v {
			if head != "*" && head != strconv.Itoa(i) {
				continue
			}
			here := at + "/" + strconv.Itoa(i)
			if last {
				// An array element is never removed, so indexes stay stable.
				taken = append(taken, terminalValue{Pointer: here, Value: v[i]})
				v[i] = nil
				continue
			}
			taken = takeAt(v[i], segments[1:], here, taken)
		}
	}
	return taken
}

func escapePointerSegment(segment string) string {
	return strings.ReplaceAll(strings.ReplaceAll(segment, "~", "~0"), "/", "~1")
}

func deepCopyJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = deepCopyJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = deepCopyJSON(item)
		}
		return out
	default:
		return v
	}
}
