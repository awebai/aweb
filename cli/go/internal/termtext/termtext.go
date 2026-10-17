// Package termtext escapes text from a server or a sender before aw prints it
// to a terminal.
package termtext

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line makes a one-line field from a server or a sender safe to print
// to a terminal: names, addresses, subjects. A verified sender is not a trusted
// one. Every rune that can drive the terminal (C0, DEL and C1 controls) or
// disguise text (line and paragraph separators, bidi controls, zero-width
// characters) is written as a visible escape such as \x1b or \u202e, so the
// reader sees what was sent. ZWNJ, ZWJ and the tag block are kept: names and
// emoji need them.
func Line(s string) string {
	return escapeTerminalRunes(s, false)
}

// Body is Line for message bodies and other multi-line text:
// line feeds and tabs are kept, every other rune Line escapes is
// escaped.
func Body(s string) string {
	return escapeTerminalRunes(s, true)
}

// Fprintln prints one formatted line whose values may come from a
// server or a sender, escaped as Line escapes a field.
func Fprintln(w io.Writer, format string, args ...any) {
	fmt.Fprintln(w, Line(fmt.Sprintf(format, args...)))
}

func escapeTerminalRunes(s string, keepLayout bool) string {
	if !containsTerminalUnsafe(s, keepLayout) {
		return s
	}
	var out strings.Builder
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && width == 1:
			// An invalid byte, such as a lone 0x9b (the 8-bit CSI), is
			// written as the byte it was.
			fmt.Fprintf(&out, `\x%02x`, s[i])
		case !terminalUnsafeRune(r, keepLayout):
			out.WriteString(s[i : i+width])
		case r < 0x80:
			fmt.Fprintf(&out, `\x%02x`, r)
		default:
			fmt.Fprintf(&out, `\u%04x`, r)
		}
		i += width
	}
	return out.String()
}

func containsTerminalUnsafe(s string, keepLayout bool) bool {
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && width == 1) || terminalUnsafeRune(r, keepLayout) {
			return true
		}
		i += width
	}
	return false
}

func terminalUnsafeRune(r rune, keepLayout bool) bool {
	if keepLayout && (r == '\n' || r == '\t') {
		return false
	}
	if unicode.Is(unicode.Cc, r) {
		return true
	}
	switch r {
	case 0x2028, 0x2029, // line and paragraph separators
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embeddings and overrides
		0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
		0x200e, 0x200f, 0x061c, // bidi marks
		0x200b, 0x2060, 0xfeff: // zero-width space, word joiner, BOM
		return true
	}
	return false
}
