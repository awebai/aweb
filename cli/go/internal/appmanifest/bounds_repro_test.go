package appmanifest

import "testing"

func TestDecodeSingleJSON(t *testing.T) {
	type doc struct {
		A int `json:"a"`
	}
	var d doc
	if err := DecodeSingleJSON([]byte(`{"a":1}`), &d); err != nil || d.A != 1 {
		t.Fatalf("single object: d=%+v err=%v", d, err)
	}
	if err := DecodeSingleJSON([]byte("  {\"a\":1}  \n\t"), &d); err != nil {
		t.Fatalf("whitespace-wrapped single object rejected: %v", err)
	}
	for _, in := range []string{`{"a":1}{"a":2}`, `{"a":1} garbage`, `{"a":1} 2`, `{"a":1}[]`} {
		if err := DecodeSingleJSON([]byte(in), &d); err == nil {
			t.Errorf("DecodeSingleJSON(%q) accepted trailing data", in)
		}
	}
}

func TestDecodeSingleJSONStrictRejectsUnknownFields(t *testing.T) {
	type tool struct {
		Auth string `json:"auth"`
	}
	var tl tool
	// A misspelled security-sensitive field must fail closed, not default.
	if err := DecodeSingleJSONStrict([]byte(`{"auht":"none"}`), &tl); err == nil {
		t.Fatal("strict decode accepted an unknown (misspelled) field")
	}
	// Lenient decode ignores unknown fields.
	if err := DecodeSingleJSON([]byte(`{"auht":"none"}`), &tl); err != nil {
		t.Fatalf("lenient decode rejected unknown field: %v", err)
	}
	// Strict decode accepts the correctly-spelled field.
	if err := DecodeSingleJSONStrict([]byte(`{"auth":"none"}`), &tl); err != nil || tl.Auth != "none" {
		t.Fatalf("strict decode of known field: tl=%+v err=%v", tl, err)
	}
}

// aajc.4 repro: json-mode --body-file parsing (the naapp dispatch surface)
// decodes a single JSON document but does not require EOF, so a valid object
// followed by a second object or garbage is silently accepted (only the first
// object is used). It must reject trailing data and still accept a
// whitespace-only suffix.
func TestJSONModeRawBodyRejectsTrailingData_Repro(t *testing.T) {
	rejects := []string{
		`{"a":1} {"b":2}`,
		`{"a":1} garbage`,
		`{"a":1}{"b":2}`,
		`{"a":1}` + "\n" + `["not","an","object"]`,
	}
	for _, in := range rejects {
		if _, err := jsonModeRawBodyObject([]byte(in)); err == nil {
			t.Errorf("jsonModeRawBodyObject(%q) accepted trailing data; want error", in)
		}
	}

	accepts := []string{
		`{"a":1}`,
		`  {"a":1}  ` + "\n\t",
		`{}`,
	}
	for _, in := range accepts {
		if _, err := jsonModeRawBodyObject([]byte(in)); err != nil {
			t.Errorf("jsonModeRawBodyObject(%q) rejected a valid single object: %v", in, err)
		}
	}
}
