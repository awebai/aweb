// Package hookevent signs and verifies aw-hooks events: the aweb.hook-event/1
// envelope and the hook-delivery request credential that carries it.
//
// docs/hook-events.md is the contract, and the public hook vectors pin the
// bytes.
package hookevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
)

// MaxSafeInteger is the largest integer every consumer reads exactly.
const MaxSafeInteger = 1<<53 - 1

// Error is a refusal with a stable code, so every consumer reports the same
// fault for the same input.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func refuse(code, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Code returns the refusal code of err, or "" when err is not a refusal.
func Code(err error) string {
	var refusal *Error
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

var integerText = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ParseStrict reads one JSON value. Objects become map[string]any, arrays
// []any, numbers int64. It refuses duplicate keys, floats, integers outside
// the safe range, null, strings with a character outside printable ASCII, and
// trailing data.
func ParseStrict(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, refuse("invalid_json", "trailing data")
	}
	return value, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, refuse("invalid_json", "%v", err)
	}
	return parseToken(dec, token)
}

func parseToken(dec *json.Decoder, token json.Token) (any, error) {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, refuse("invalid_json", "%v", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, refuse("invalid_json", "object key is not a string")
				}
				if err := checkASCII(key); err != nil {
					return nil, err
				}
				if _, exists := object[key]; exists {
					return nil, refuse("duplicate_key", "%s", key)
				}
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, refuse("invalid_json", "%v", err)
			}
			return object, nil
		case '[':
			list := []any{}
			for dec.More() {
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, refuse("invalid_json", "%v", err)
			}
			return list, nil
		}
		return nil, refuse("invalid_json", "unexpected %v", t)
	case json.Number:
		text := t.String()
		if !integerText.MatchString(text) {
			return nil, refuse("float_value", "%s", text)
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n > MaxSafeInteger || n < -MaxSafeInteger {
			return nil, refuse("invalid_value", "integer outside the safe range: %s", text)
		}
		return n, nil
	case string:
		if err := checkASCII(t); err != nil {
			return nil, err
		}
		return t, nil
	case bool:
		return t, nil
	case nil:
		return nil, refuse("null_value", "null is never a value")
	}
	return nil, refuse("invalid_json", "unexpected token %v", token)
}

func checkASCII(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return refuse("string_not_ascii", "character 0x%02x", s[i])
		}
	}
	return nil
}

// Canonical encodes a value as canonical JSON: object keys sorted, no
// insignificant whitespace, strings of printable ASCII with only `"` and `\`
// escaped, integers in the safe range, and no floats or null. Python's
// json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
// produces the same bytes for every value this accepts.
func Canonical(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, key); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []string:
		items := make([]any, len(v))
		for i, item := range v {
			items[i] = item
		}
		return writeCanonical(buf, items)
	case string:
		return writeString(buf, v)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int:
		return writeCanonical(buf, int64(v))
	case int64:
		if v > MaxSafeInteger || v < -MaxSafeInteger {
			return refuse("invalid_value", "integer outside the safe range: %d", v)
		}
		buf.WriteString(strconv.FormatInt(v, 10))
	case nil:
		return refuse("null_value", "null is never a value")
	default:
		return refuse("invalid_value", "unsupported value %T", value)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	if err := checkASCII(s); err != nil {
		return err
	}
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			buf.WriteByte('\\')
		}
		buf.WriteByte(s[i])
	}
	buf.WriteByte('"')
	return nil
}

// parseCanonicalObject parses data strictly and requires it to be a JSON
// object whose canonical encoding is exactly data.
func parseCanonicalObject(data []byte) (map[string]any, error) {
	value, err := ParseStrict(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, refuse("invalid_value", "not a JSON object")
	}
	canonical, err := Canonical(object)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, refuse("not_canonical", "bytes are not the canonical encoding")
	}
	return object, nil
}
