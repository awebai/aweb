package termtext

import "testing"

func TestLineEscapesEveryRuneThatCanDriveOrDisguiseATerminal(t *testing.T) {
	cases := map[string]string{
		"\x1b[31mred":       `\x1b[31mred`,
		"bell\a":            `bell\x07`,
		"nul\x00":           `nul\x00`,
		"del\x7f":           `del\x7f`,
		"c1\u0085\u009b":    `c1\u0085\u009b`,
		"line\nbreak":       `line\x0abreak`,
		"carriage\rreturn":  `carriage\x0dreturn`,
		"tab\there":         `tab\x09here`,
		"sep\u2028\u2029":   `sep\u2028\u2029`,
		"bidi\u202a\u202e":  `bidi\u202a\u202e`,
		"iso\u2066\u2069":   `iso\u2066\u2069`,
		"marks\u200e\u200f": `marks\u200e\u200f`,
		"arabic\u061c":      `arabic\u061c`,
		"zw\u200b\u2060":    `zw\u200b\u2060`,
		"bom\ufeff":         `bom\ufeff`,
	}
	for in, want := range cases {
		if got := Line(in); got != want {
			t.Errorf("Line(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLineKeepsTextNamesAndEmojiNeed(t *testing.T) {
	for _, in := range []string{
		"alice",
		"Zo\u00eb O'Brien",
		"\u0645\u0644\u0641",
		"\u0928\u092e\u0938\u094d\u0924\u0947",
		"\U0001f469\u200d\U0001f4bb",
		"\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
		"\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f",
		`already \x1b literal`,
	} {
		if got := Line(in); got != in {
			t.Errorf("Line(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestBodyKeepsLineBreaksAndTabsAndEscapesTheRest(t *testing.T) {
	in := "line one\n\tindented\x1b]0;title\a\r\u202eevil"
	want := "line one\n\tindented\\x1b]0;title\\x07\\x0d\\u202eevil"
	if got := Body(in); got != want {
		t.Fatalf("Body(%q) = %q, want %q", in, got, want)
	}
}
