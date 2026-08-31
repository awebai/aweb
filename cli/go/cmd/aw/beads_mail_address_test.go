package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBeadsMailMap(t *testing.T, dir, content string) string {
	t.Helper()
	beadsDir := filepath.Join(dir, ".beads")
	if err := os.MkdirAll(beadsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(beadsDir, beadsMailMapFileName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const beadsMailMapFixture = `# beads-style local names -> aweb addresses
[addresses]
"mayor/" = "acme.aweb.ai/mayor"
worker = "acme.aweb.ai/worker"
"crow" = "did:aw:zcrow123"
`

func TestBeadsMailRecipientResolutionOrder(t *testing.T) {
	dir := t.TempDir()
	writeBeadsMailMap(t, dir, beadsMailMapFixture)
	m, err := loadBeadsMailAddressMap(dir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		input  string
		kind   string
		value  string
		mapped bool
	}{
		{"mayor/", "address", "acme.aweb.ai/mayor", true},
		{"worker", "address", "acme.aweb.ai/worker", true},
		{"crow", "did", "did:aw:zcrow123", true},
		{"did:aw:zother", "did", "did:aw:zother", false},
		{"acme.com/reviewer", "address", "acme.com/reviewer", false},
		{"@handle/agent", "address", "handle.aweb.ai/agent", false},
		{"teammate", "alias", "teammate", false},
	}
	for _, tc := range cases {
		got, err := resolveBeadsMailRecipient(m, tc.input)
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.input, err)
			continue
		}
		if got.Kind != tc.kind || got.Value != tc.value || got.Mapped != tc.mapped {
			t.Errorf("%q: got %+v want kind=%s value=%s mapped=%v", tc.input, got, tc.kind, tc.value, tc.mapped)
		}
	}
}

func TestBeadsMailRecipientErrors(t *testing.T) {
	dir := t.TempDir()
	mapPath := writeBeadsMailMap(t, dir, beadsMailMapFixture)
	m, err := loadBeadsMailAddressMap(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Unmapped rig-style name: the error is the product surface — it names
	// the file and shows the exact line to add (design record §5).
	_, err = resolveBeadsMailRecipient(m, "sheriff/")
	if err == nil {
		t.Fatal("unmapped rig name resolved")
	}
	for _, want := range []string{"sheriff/", mapPath, "[addresses]", "domain/name or did:aw:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("unmapped-name error missing %q:\n%s", want, err)
		}
	}

	if _, err := resolveBeadsMailRecipient(m, "list:oncall"); err == nil || !strings.Contains(err.Error(), "mailing lists") {
		t.Errorf("list: target error=%v", err)
	}

	// Email-style input never routes as an alias; the alias step excludes @
	// (design record §5) so a typo'd email gets the map guidance.
	if _, err := resolveBeadsMailRecipient(m, "alice@acme.com"); err == nil || !strings.Contains(err.Error(), "not mapped to an aweb address") {
		t.Errorf("email-style target error=%v", err)
	}

	// Malformed address-shaped input never rides through to the server as a
	// raw "address" (review probe findings, 2026-08-31): every one of these
	// gets the map guidance instead of Kind=address.
	for _, malformed := range []string{
		"alice@acme.com/reviewer", // embedded @ in the domain part
		"@.acme/reviewer",         // malformed hosted shorthand, left unnormalized
		"@ac..me/reviewer",        // double dot
		"./x",                     // dot-only domain
		"a/b/c",                   // rig-style path, unmapped
		"a.com\n/x",               // control characters never pass as address
		"a.com\x1b[31m/x",         // ANSI escape injection
		"plain\x1bname",           // control char excluded from the alias step too
	} {
		_, err := resolveBeadsMailRecipient(m, malformed)
		if err == nil || !strings.Contains(err.Error(), "not mapped to an aweb address") {
			t.Errorf("%q: error=%v", malformed, err)
		}
	}

	if _, err := resolveBeadsMailRecipient(m, "  "); err == nil {
		t.Error("blank recipient resolved")
	}
}

func TestBeadsMailMapParsingRejectsWhatItCannotHold(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		fragment string
	}{
		{"unknown table", "[addresses]\n\"a/\" = \"x.com/a\"\n[routes]\n", "unsupported table"},
		{"entry before table", "\"a/\" = \"x.com/a\"\n", "before any table"},
		{"unknown settings key", "[settings]\n\"colour\" = \"blue\"\n", "unknown setting"},
		{"bad dual-write value", "[settings]\ndual-write = \"maybe\"\n", "must be \"on\" or \"off\""},
		{"unquoted value", "[addresses]\na = x.com/a\n", "quoted string"},
		{"unterminated quote", "[addresses]\n\"a = \"x.com/a\"\n", "quoted"},
		{"backslash", "[addresses]\n\"a\\\" = \"x.com/a\"\n", "backslash"},
		{"duplicate key", "[addresses]\n\"a/\" = \"x.com/a\"\n\"a/\" = \"x.com/b\"\n", "duplicate"},
		{"email-style value", "[addresses]\n\"a/\" = \"alice@acme.com\"\n", "not an aweb address"},
		{"bare local value", "[addresses]\n\"a/\" = \"bob\"\n", "not an aweb address"},
		{"double-dot domain value", "[addresses]\n\"a/\" = \"x..com/a\"\n", "not an aweb address"},
		{"duplicate addresses table", "[addresses]\n\"a/\" = \"x.com/a\"\n[addresses]\n\"b/\" = \"x.com/b\"\n", "duplicate [addresses]"},
		{"padded quoted key", "[addresses]\n\" a/ \" = \"x.com/a\"\n", "whitespace inside quotes"},
		{"padded quoted value", "[addresses]\n\"a/\" = \" x.com/a\"\n", "whitespace inside quotes"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		path := writeBeadsMailMap(t, dir, tc.content)
		_, err := loadBeadsMailAddressMap(dir)
		if err == nil {
			t.Errorf("%s: parsed", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.fragment) {
			t.Errorf("%s: error missing %q: %v", tc.name, tc.fragment, err)
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("%s: error does not name the file: %v", tc.name, err)
		}
	}
}

func TestBeadsMailMapDiscovery(t *testing.T) {
	// Upward walk: map in an ancestor's .beads is found from a subdirectory.
	root := t.TempDir()
	writeBeadsMailMap(t, root, beadsMailMapFixture)
	nested := filepath.Join(root, "sub", "deeper")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	m, err := loadBeadsMailAddressMap(nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.entries["mayor/"]; !ok {
		t.Error("upward walk did not find the map")
	}

	// BEADS_DIR naming a directory with no map file: empty map, no error.
	bare := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bare, ".beads"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEADS_DIR", filepath.Join(bare, ".beads"))
	if m, err := loadBeadsMailAddressMap(nested); err != nil || len(m.entries) != 0 {
		t.Errorf("BEADS_DIR without map: entries=%v err=%v", m.entries, err)
	}

	// BEADS_DIR wins over the walk, matching bd's own resolution.
	other := t.TempDir()
	otherPath := writeBeadsMailMap(t, other, "[addresses]\n\"boss/\" = \"other.com/boss\"\n")
	t.Setenv("BEADS_DIR", filepath.Dir(otherPath))
	m, err = loadBeadsMailAddressMap(nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.entries["boss/"]; !ok || len(m.entries) != 1 {
		t.Errorf("BEADS_DIR not honored: %+v", m.entries)
	}

	// No .beads anywhere: empty map, no error; bare names still resolve as
	// aliases and only rig-style names error, with the default path named.
	t.Setenv("BEADS_DIR", "")
	lone := t.TempDir()
	m, err = loadBeadsMailAddressMap(lone)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.entries) != 0 {
		t.Errorf("expected empty map, got %+v", m.entries)
	}
	if _, err := resolveBeadsMailRecipient(m, "mayor/"); err == nil || !strings.Contains(err.Error(), filepath.Join(".beads", beadsMailMapFileName)) {
		t.Errorf("mapless rig-name error=%v", err)
	}
}

func TestBeadsMailDisplayAndDisclosure(t *testing.T) {
	dir := t.TempDir()
	writeBeadsMailMap(t, dir, beadsMailMapFixture)
	m, err := loadBeadsMailAddressMap(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := beadsMailDisplayName(m, "acme.aweb.ai/mayor"); got != "mayor/" {
		t.Errorf("reverse display got %q", got)
	}
	if got := beadsMailDisplayName(m, "unknown.com/x"); got != "" {
		t.Errorf("reverse display of unmapped got %q", got)
	}

	// Tie-break: two keys mapping to one value — lexically first wins.
	tie := beadsMailAddressMap{entries: map[string]string{
		"zeta/":  "x.com/one",
		"alpha/": "x.com/one",
	}}
	if got := beadsMailDisplayName(tie, "x.com/one"); got != "alpha/" {
		t.Errorf("tie-break got %q", got)
	}

	// A map key may itself look like a DID or a list: target; step 1 wins
	// over steps 2 and 3 structurally.
	shadow := beadsMailAddressMap{entries: map[string]string{
		"did:aw:zshadow": "x.com/mapped",
		"list:oncall":    "x.com/oncall",
	}}
	for input, want := range map[string]string{"did:aw:zshadow": "x.com/mapped", "list:oncall": "x.com/oncall"} {
		got, err := resolveBeadsMailRecipient(shadow, input)
		if err != nil || got.Value != want || !got.Mapped {
			t.Errorf("map-first for %q: got %+v err=%v", input, got, err)
		}
	}

	// Disclosure output neutralizes control characters even if a target were
	// constructed outside validation.
	hostile := beadsMailTarget{Kind: "address", Value: "x.com/a\x1b[31m", Input: "evil/\n"}
	if note := beadsMailResolutionNote(hostile); strings.ContainsAny(note, "\x1b\n") {
		t.Errorf("disclosure not sanitized: %q", note)
	}

	mapped, err := resolveBeadsMailRecipient(m, "mayor/")
	if err != nil {
		t.Fatal(err)
	}
	if note := beadsMailResolutionNote(mapped); note != "to mayor/ -> acme.aweb.ai/mayor" {
		t.Errorf("disclosure note %q", note)
	}
	direct, err := resolveBeadsMailRecipient(m, "acme.com/reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if note := beadsMailResolutionNote(direct); note != "to acme.com/reviewer" {
		t.Errorf("passthrough note %q", note)
	}
}
