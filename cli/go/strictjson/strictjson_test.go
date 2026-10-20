package strictjson

import "testing"

func TestCanonicalSortsKeysAndEscapesOnlyQuoteAndBackslash(t *testing.T) {
	got, err := Canonical(map[string]any{
		"b": []any{"x", int64(2), true},
		"a": `say "hi" \ <&>/`,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":"say \"hi\" \\ <&>/","b":["x",2,true]}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestCanonicalRefusesWhatNoConsumerReadsAlike(t *testing.T) {
	for name, value := range map[string]any{
		"non-ascii":     "café",
		"control":       "a\nb",
		"float":         1.5,
		"null":          nil,
		"unsafe-int":    int64(MaxSafeInteger + 1),
		"nested-unsafe": map[string]any{"n": int64(-MaxSafeInteger - 1)},
	} {
		if _, err := Canonical(value); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseStrictRefusals(t *testing.T) {
	for input, code := range map[string]string{
		`{"a":1,"a":2}`:            "duplicate_key",
		`{"a":1.0}`:                "float_value",
		`{"a":1e3}`:                "float_value",
		`{"a":null}`:               "null_value",
		"{\"a\":\"caf\\u00e9\"}":   "string_not_ascii",
		`{"a":9007199254740992}`:   "invalid_value",
		`{"a":1} {}`:               "invalid_json",
		`{"a":`:                    "invalid_json",
		"{\"a\":\"line\\nbreak\"}": "string_not_ascii",
	} {
		_, err := ParseStrict([]byte(input))
		if Code(err) != code {
			t.Errorf("%s: got %v, want %s", input, err, code)
		}
	}
}

func TestParseCanonicalObjectRequiresExactBytes(t *testing.T) {
	if _, err := ParseCanonicalObject([]byte(`{"a":1,"b":2}`)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{`{"b":2,"a":1}`, `{"a": 1}`, "{\"a\":\"\\u0041\"}"} {
		if _, err := ParseCanonicalObject([]byte(input)); Code(err) != "not_canonical" {
			t.Errorf("%s: got %v, want not_canonical", input, err)
		}
	}
}
