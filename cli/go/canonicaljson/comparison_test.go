package canonicaljson

import "testing"

func TestCanonicalEqualityRefusesAnUnencodableValueOnEitherSide(t *testing.T) {
	valid := map[string]any{"name": "portable", "count": int64(1)}
	invalid := map[string]any{"count": float64(1)}
	cases := []struct {
		name  string
		input Comparison
	}{
		{"expected", Comparison{Expected: invalid, Actual: valid}},
		{"actual", Comparison{Expected: valid, Actual: invalid}},
		{"both", Comparison{Expected: invalid, Actual: invalid}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			equal, err := EqualValues(tc.input)
			if err == nil || equal {
				t.Fatalf("unencodable values compared as equal=%v, err=%v", equal, err)
			}
		})
	}
	equal, err := EqualValues(Comparison{Expected: valid, Actual: map[string]any{"count": int64(1), "name": "portable"}})
	if err != nil || !equal {
		t.Fatalf("key order changed equality: equal=%v, err=%v", equal, err)
	}
	equal, err = EqualValues(Comparison{Expected: valid, Actual: map[string]any{"count": int64(2), "name": "portable"}})
	if err != nil || equal {
		t.Fatalf("different values compared as equal=%v, err=%v", equal, err)
	}
}
