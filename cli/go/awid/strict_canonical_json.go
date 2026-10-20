package awid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

var canonicalIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// StrictCanonicalJSON encodes a JSON value as the page and task contracts
// define canonical JSON: keys sorted by code point, no insignificant
// whitespace, UTF-8 with only the quotation mark, reverse solidus and C0
// controls escaped (as Python's json.dumps with ensure_ascii=False), and safe
// integers only. It refuses floats, integers beyond 2^53-1, number forms that
// are not plain integers, invalid UTF-8 and non-JSON types. Unlike
// encoding/json it leaves U+2028 and U+2029 unescaped, so its bytes equal the
// Python side's. AWID signing keeps its own serialization (CanonicalJSONValue).
func StrictCanonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeStrictCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeStrictCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		return writeStrictString(out, v)
	case json.Number:
		text := string(v)
		if !canonicalIntegerPattern.MatchString(text) {
			return fmt.Errorf("number %q has no canonical form", text)
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return fmt.Errorf("number %q is outside the safe range", text)
		}
		return writeSafeInteger(out, n)
	case int:
		return writeSafeInteger(out, int64(v))
	case int64:
		return writeSafeInteger(out, v)
	case int32:
		return writeSafeInteger(out, int64(v))
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if !utf8.ValidString(key) {
				return fmt.Errorf("object key is not valid UTF-8")
			}
			keys = append(keys, key)
		}
		// Byte order of valid UTF-8 is code point order, which is Python's.
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeStrictString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeStrictCanonical(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeStrictCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		return fmt.Errorf("%T has no canonical form", value)
	}
	return nil
}

func writeSafeInteger(out *bytes.Buffer, n int64) error {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return fmt.Errorf("integer %d is outside the safe range", n)
	}
	out.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func writeStrictString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	out.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\f':
			out.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(out, `\u%04x`, r)
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
	return nil
}
