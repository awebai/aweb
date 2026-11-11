package main

import (
	"strings"
	"testing"
)

func TestFormatJSONOutputKeepsIntegerDigitsAbove2To53(t *testing.T) {
	out := formatJSONOutput(map[string]any{
		"alias":    "alice",
		"sequence": int64(9007199254740993),
		"largest":  uint64(18446744073709551615),
		"nested":   []any{map[string]any{"id": int64(-9223372036854775807)}},
	})

	for _, want := range []string{
		`"sequence": 9007199254740993`,
		`"largest": 18446744073709551615`,
		`"id": -9223372036854775807`,
		`"name": "alice"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s:\n%s", want, out)
		}
	}
}
