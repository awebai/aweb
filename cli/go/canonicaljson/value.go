// Package canonicaljson owns serialization for signed artifacts. Profiles keep
// released digest bytes and validation grammars explicit; callers own fields.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"strings"
)

func Marshal(v any) (string, error) {
	escaped, err := MarshalDigest(v)
	if err != nil {
		return "", err
	}
	return RawLineSeparators(escaped), nil
}

func MarshalDigest(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	// json.Encoder.Encode always appends a trailing newline; strip it so
	// the returned string is a single canonical JSON value.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return string(out), nil
}

const (
	escapedLineSeparator      = "\\u2028"
	escapedParagraphSeparator = "\\u2029"
)

func RawLineSeparators(encoded string) string {
	if !strings.Contains(encoded, escapedLineSeparator) && !strings.Contains(encoded, escapedParagraphSeparator) {
		return encoded
	}
	var out strings.Builder
	out.Grow(len(encoded))
	for i := 0; i < len(encoded); {
		switch {
		case encoded[i] != '\\' || i+1 >= len(encoded):
			out.WriteByte(encoded[i])
			i++
		case strings.HasPrefix(encoded[i:], escapedLineSeparator):
			out.WriteRune(0x2028)
			i += len(escapedLineSeparator)
		case strings.HasPrefix(encoded[i:], escapedParagraphSeparator):
			out.WriteRune(0x2029)
			i += len(escapedParagraphSeparator)
		default:
			out.WriteString(encoded[i : i+2])
			i += 2
		}
	}
	return out.String()
}
