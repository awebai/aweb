package canonicaljson

import (
	"bytes"
	"fmt"
)

// Comparison names the two values whose canonical encodings must agree.
type Comparison struct {
	Expected any
	Actual   any
}

// EqualValues implements the safe-integer UTF-8 comparison used by signed
// artifacts (docs/human-channels-contract-v1.md:27-31). A failure to encode
// either value is an error, including when both values fail to encode.
func EqualValues(input Comparison) (bool, error) {
	expected, err := Strict(input.Expected)
	if err != nil {
		return false, fmt.Errorf("encode expected canonical value: %w", err)
	}
	actual, err := Strict(input.Actual)
	if err != nil {
		return false, fmt.Errorf("encode actual canonical value: %w", err)
	}
	return bytes.Equal(expected, actual), nil
}
