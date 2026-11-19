package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hookJSONCorpusCase struct {
	Name string
	JSON []byte
}

func hookRoundTripCorpus(events []string) []hookJSONCorpusCase {
	payloads := []string{`900719925474099312345678901234567890`, `"\u0041\uD83D\uDE00\/\\\""`, `{"nested":[{},[],{"empty":{}}],"exponent":1.234567890123456789e+99}`}
	var cases []hookJSONCorpusCase
	for spaceIndex, space := range []string{"", " ", "\t", "\r\n  "} {
		for valueIndex, payload := range payloads {
			for groupIndex, group := range []string{"", `{"matcher":"Read","hooks":[{"type":"command","command":"echo keep"}],"extra":{"nested":[{}]}}`} {
				var members []string
				for _, event := range events {
					members = append(members, fmt.Sprintf(`%q@ws@:@ws@[@ws@%s@ws@]`, event, group))
				}
				raw := `{@ws@"value"@ws@:@ws@` + payload + `,@ws@"hooks"@ws@:@ws@{@ws@` + strings.Join(members, ",@ws@") + `@ws@}@ws@}@ws@`
				cases = append(cases, hookJSONCorpusCase{Name: fmt.Sprintf("space%d/value%d/groups%d", spaceIndex, valueIndex, groupIndex), JSON: []byte(strings.ReplaceAll(raw, "@ws@", space))})
			}
		}
	}
	return cases
}

// docs/runtime-hook-configuration.md:3-8: every pre-existing byte survives a round trip.
func TestClaudeHookRoundTripPreservesCorpusBytes(t *testing.T) {
	for _, tc := range hookRoundTripCorpus([]string{"PostToolUse"}) {
		t.Run(tc.Name, func(t *testing.T) {
			if !json.Valid(tc.JSON) {
				t.Fatalf("invalid corpus: %s", tc.JSON)
			}
			if _, err := parseHookJSON(tc.JSON); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			path := writeNotifySettings(t, root, string(tc.JSON))
			result := SetupClaudeHooks(root, skipHookConfirmation)
			if result.Error != nil {
				t.Fatal(result.Error)
			}
			resultCleanup := CleanupClaudeNotifyHook(root)
			if resultCleanup.Error != nil || resultCleanup.Removed != 1 {
				t.Fatalf("remove: %+v", resultCleanup)
			}
			if got := readInstallFile(t, path); !bytes.Equal(got, tc.JSON) {
				t.Fatalf("outside aw's handler changed\noriginal: %q\nrestored: %q", tc.JSON, got)
			}
		})
	}
}

func TestCodexHookRoundTripPreservesCorpusBytes(t *testing.T) {
	events := []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "PermissionRequest", "Stop", "Interrupt", "SessionEnd"}
	for _, tc := range hookRoundTripCorpus(events) {
		t.Run(tc.Name, func(t *testing.T) {
			if !json.Valid(tc.JSON) {
				t.Fatalf("invalid corpus: %s", tc.JSON)
			}
			if _, err := parseHookJSON(tc.JSON); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(path, tc.JSON, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := changeCodexActivityHooks(dir, installActivityHook); err != nil {
				t.Fatal(err)
			}
			if _, err := changeCodexActivityHooks(dir, removeActivityHook); err != nil {
				t.Fatal(err)
			}
			if got := readInstallFile(t, path); !bytes.Equal(got, tc.JSON) {
				t.Fatalf("outside aw's handlers changed\noriginal: %q\nrestored: %q", tc.JSON, got)
			}
		})
	}
}

type hookRefusalCase struct {
	Name   string
	JSON   string
	Repair string
}

var hookRefusalCases = []hookRefusalCase{
	{Name: "invalid JSON", JSON: `{"hooks":`, Repair: "Fix the JSON syntax"},
	{Name: "duplicate key", JSON: `{"hooks":{},"\u0068ooks":{}}`, Repair: "Remove the duplicate JSON key"},
	{Name: "hooks not object", JSON: `{"hooks":[]}`, Repair: "Set hooks to a JSON object"},
}

func TestHookJSONRefusalsNameFileAndSpecificRepair(t *testing.T) {
	for _, tc := range hookRefusalCases {
		t.Run(tc.Name, func(t *testing.T) {
			root := t.TempDir()
			path := writeNotifySettings(t, root, tc.JSON)
			assertHookRepair(t, SetupClaudeHooks(root, skipHookConfirmation).Error, hookRepairExpectation{Path: path, Repair: tc.Repair})
			assertHookRepair(t, CleanupClaudeNotifyHook(root).Error, hookRepairExpectation{Path: path, Repair: tc.Repair})
			if got := readInstallFile(t, path); string(got) != tc.JSON {
				t.Fatal("changed refused Claude settings")
			}
			codex := t.TempDir()
			path = filepath.Join(codex, "hooks.json")
			if err := os.WriteFile(path, []byte(tc.JSON), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, operation := range []activityHookOperation{installActivityHook, removeActivityHook} {
				_, err := changeCodexActivityHooks(codex, operation)
				assertHookRepair(t, err, hookRepairExpectation{Path: path, Repair: tc.Repair})
			}
			if got := readInstallFile(t, path); string(got) != tc.JSON {
				t.Fatal("changed refused Codex settings")
			}
		})
	}
}

type hookRepairExpectation struct {
	Path   string
	Repair string
}

func assertHookRepair(t *testing.T, err error, expected hookRepairExpectation) {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, part := range []string{expected.Path, expected.Repair, "Save the file and retry the command."} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("missing %q: %v", part, err)
		}
	}
}
