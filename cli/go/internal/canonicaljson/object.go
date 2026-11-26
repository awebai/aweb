package canonicaljson

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// EscapeString returns JSON string contents using the released Unicode rule
// (docs/signature-primitives.md, Encoding compatibility). Only infallible memory
// writes occur here; I/O destinations belong to the caller.
func EscapeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// Object serializes the closed scalar maps built by legacy wire families. It
// preserves their handling of invalid UTF-8 as replacement runes. Arbitrary
// caller-supplied JSON uses Marshal or Strict instead.
func Object(fields map[string]any) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteByte('"')
		out.WriteString(EscapeString(key))
		out.WriteString(`":`)
		switch v := fields[key].(type) {
		case string:
			out.WriteByte('"')
			out.WriteString(EscapeString(v))
			out.WriteByte('"')
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case int:
			out.WriteString(strconv.Itoa(v))
		case int64:
			out.WriteString(strconv.FormatInt(v, 10))
		case nil:
			out.WriteString("null")
		default:
			panic(fmt.Sprintf("unsupported protocol field %T", v))
		}
	}
	out.WriteByte('}')
	return out.String()
}
