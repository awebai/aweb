package agentdocs

import "strings"

const (
	MarkerStart = "<!-- AWEB:START -->"
	MarkerEnd   = "<!-- AWEB:END -->"
)

// Render returns the complete marker-delimited team coordination block.
func Render(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return MarkerStart + "\n" + MarkerEnd + "\n"
	}
	return MarkerStart + "\n" + body + "\n" + MarkerEnd + "\n"
}

// Remove removes the first complete marker-delimited coordination block.
func Remove(content string) string {
	start := strings.Index(content, MarkerStart)
	end := strings.Index(content, MarkerEnd)
	if start == -1 || end == -1 || end < start {
		return content
	}
	end += len(MarkerEnd)
	before := strings.TrimRight(content[:start], "\n")
	after := strings.TrimLeft(content[end:], "\n")
	switch {
	case before == "":
		return after
	case after == "":
		return before
	default:
		return before + "\n\n" + after
	}
}

// RemoveAll removes every complete marker-delimited coordination block.
func RemoveAll(content string) string {
	for {
		updated := Remove(content)
		if updated == content {
			return content
		}
		content = updated
	}
}

// HasSingleMarkedBlock reports whether content contains exactly one complete
// coordination-owned region.
func HasSingleMarkedBlock(content string) bool {
	return strings.Count(content, MarkerStart) == 1 &&
		strings.Count(content, MarkerEnd) == 1 &&
		strings.Index(content, MarkerStart) < strings.Index(content, MarkerEnd)
}

// PreserveMarkedBlock carries the existing coordination-owned region into newly
// generated profile content. An unmarked document remains unmarked.
func PreserveMarkedBlock(existing, generated string) string {
	start := strings.Index(existing, MarkerStart)
	if start == -1 {
		return generated
	}
	endOffset := strings.Index(existing[start+len(MarkerStart):], MarkerEnd)
	if endOffset == -1 {
		return generated
	}
	end := start + len(MarkerStart) + endOffset + len(MarkerEnd)
	block := existing[start:end]
	base := strings.TrimRight(generated, "\n")
	if base == "" {
		return block + "\n"
	}
	return base + "\n\n" + block + "\n"
}
