// Package strictjson reads and writes the strict canonical JSON that aweb's
// domain-separated signatures cover: hook events, hook deliveries and owner
// acts. Every value it accepts encodes to the same bytes in Go and in
// Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
package strictjson

import (
	"bytes"
	"encoding/base64"
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

// MaxDepth bounds how deeply objects and arrays may nest. Strict JSON is
// parsed before any signature is checked, so unauthenticated input must not
// drive unbounded recursion.
const MaxDepth = 8

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

// Refuse returns a refusal with a stable code.
func Refuse(code, format string, args ...any) error {
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
// the safe range, null, strings with a character outside printable ASCII,
// nesting deeper than MaxDepth, and trailing data.
func ParseStrict(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, Refuse("invalid_json", "trailing data")
	}
	return value, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, Refuse("invalid_json", "%v", err)
	}
	return parseToken(dec, token, depth)
}

func parseToken(dec *json.Decoder, token json.Token, depth int) (any, error) {
	switch t := token.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, Refuse("too_deep", "nesting deeper than %d", MaxDepth)
		}
		switch t {
		case '{':
			object := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, Refuse("invalid_json", "%v", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, Refuse("invalid_json", "object key is not a string")
				}
				if err := checkASCII(key); err != nil {
					return nil, err
				}
				if _, exists := object[key]; exists {
					return nil, Refuse("duplicate_key", "%s", key)
				}
				value, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if _, err := dec.Token(); err != nil {
				return nil, Refuse("invalid_json", "%v", err)
			}
			return object, nil
		case '[':
			list := []any{}
			for dec.More() {
				value, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, value)
			}
			if _, err := dec.Token(); err != nil {
				return nil, Refuse("invalid_json", "%v", err)
			}
			return list, nil
		}
		return nil, Refuse("invalid_json", "unexpected %v", t)
	case json.Number:
		text := t.String()
		if !integerText.MatchString(text) {
			return nil, Refuse("float_value", "%s", text)
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n > MaxSafeInteger || n < -MaxSafeInteger {
			return nil, Refuse("invalid_value", "integer outside the safe range: %s", text)
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
		return nil, Refuse("null_value", "null is never a value")
	}
	return nil, Refuse("invalid_json", "unexpected token %v", token)
}

func checkASCII(s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return Refuse("string_not_ascii", "character 0x%02x", s[i])
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
			return Refuse("invalid_value", "integer outside the safe range: %d", v)
		}
		buf.WriteString(strconv.FormatInt(v, 10))
	case nil:
		return Refuse("null_value", "null is never a value")
	default:
		return Refuse("invalid_value", "unsupported value %T", value)
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

// ParseCanonicalObject parses data strictly and requires it to be a JSON
// object whose canonical encoding is exactly data.
func ParseCanonicalObject(data []byte) (map[string]any, error) {
	value, err := ParseStrict(data)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, Refuse("invalid_value", "not a JSON object")
	}
	canonical, err := Canonical(object)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, Refuse("not_canonical", "bytes are not the canonical encoding")
	}
	return object, nil
}

// SignatureLength is the length of an Ed25519 signature in unpadded standard
// base64.
const SignatureLength = 86

// DecodeSignature accepts exactly one spelling of a 64-byte Ed25519
// signature: 86 characters of the standard base64 alphabet, no padding, and
// zero trailing bits.
func DecodeSignature(signature string) ([]byte, error) {
	if len(signature) != SignatureLength {
		return nil, Refuse("signature_encoding", "a signature is %d characters", SignatureLength)
	}
	sig, err := base64.RawStdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != 64 {
		return nil, Refuse("signature_encoding", "not unpadded standard base64 with zero trailing bits")
	}
	return sig, nil
}

// DecodeBase64URL accepts exactly one spelling: the URL alphabet, no padding,
// zero trailing bits.
func DecodeBase64URL(text, what string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, Refuse("invalid_value", "%s is not strict unpadded base64url", what)
	}
	return data, nil
}
