// Package strictjson reads and writes the strict canonical JSON that aweb's
// domain-separated signatures cover: hook events, hook deliveries and owner
// acts. Every value it accepts encodes to the same bytes in Go and in
// Python's json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/awebai/aw/canonicaljson"
	"github.com/awebai/aw/signaturewire"
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
	normalized, err := canonicalValue(value)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Strict(normalized)
}

// EqualValues compares owner-act values under the same ASCII/no-null profile
// as Canonical, delegating comparison to the shared canonical owner.
func EqualValues(input canonicaljson.Comparison) (bool, error) {
	expected, err := canonicalValue(input.Expected)
	if err != nil {
		return false, err
	}
	actual, err := canonicalValue(input.Actual)
	if err != nil {
		return false, err
	}
	return canonicaljson.EqualValues(canonicaljson.Comparison{Expected: expected, Actual: actual})
}

// Validation is this family's ASCII/no-null policy; serialization is shared.
func canonicalValue(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if err := checkASCII(key); err != nil {
				return nil, err
			}
			checked, err := canonicalValue(item)
			if err != nil {
				return nil, err
			}
			out[key] = checked
		}
		return out, nil
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			checked, err := canonicalValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = checked
		}
		return out, nil
	case []string:
		out := make([]any, len(v))
		for i, item := range v {
			checked, err := canonicalValue(item)
			if err != nil {
				return nil, err
			}
			out[i] = checked
		}
		return out, nil
	case string:
		if err := checkASCII(v); err != nil {
			return nil, err
		}
		return v, nil
	case bool:
		return v, nil
	case int:
		return canonicalValue(int64(v))
	case int64:
		if v > MaxSafeInteger || v < -MaxSafeInteger {
			return nil, Refuse("invalid_value", "integer outside the safe range: %d", v)
		}
		return v, nil
	case nil:
		return nil, Refuse("null_value", "null is never a value")
	default:
		return nil, Refuse("invalid_value", "unsupported value %T", value)
	}
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
	sig, err := signaturewire.DecodeStdStrict(signature)
	if err != nil || len(sig) != 64 {
		return nil, Refuse("signature_encoding", "not unpadded standard base64 with zero trailing bits")
	}
	return sig, nil
}

// DecodeBase64URL accepts exactly one spelling: the URL alphabet, no padding,
// zero trailing bits.
func DecodeBase64URL(text, what string) ([]byte, error) {
	data, err := signaturewire.DecodeURLStrict(text)
	if err != nil {
		return nil, Refuse("invalid_value", "%s is not strict unpadded base64url", what)
	}
	return data, nil
}
