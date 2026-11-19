package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			assertHookRepair(t, SetupClaudeHooks(root, skipHookConfirmation).Error, path, tc.Repair)
			assertHookRepair(t, CleanupClaudeNotifyHook(root).Error, path, tc.Repair)
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
				assertHookRepair(t, err, path, tc.Repair)
			}
			if got := readInstallFile(t, path); string(got) != tc.JSON {
				t.Fatal("changed refused Codex settings")
			}
		})
	}
}
func assertHookRepair(t *testing.T, err error, path, repair string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, part := range []string{path, repair, "Save the file and retry the command."} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("missing %q: %v", part, err)
		}
	}
}

// Unit/process fixture: real CLI and local files; native service qualification is in the full gate.
func TestInitHookRefusalContinuesOtherActions(t *testing.T) {
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/instructions/active" {
			if err := json.NewEncoder(w).Encode(map[string]any{"document": map[string]any{"body_md": "Instructions survive a hook refusal."}}); err != nil {
				t.Error(err)
			}
			return
		}
		if r.URL.Path == "/v1/agents/heartbeat" {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected request %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, binary)
	for _, tc := range hookRefusalCases {
		t.Run(tc.Name, func(t *testing.T) {
			root := t.TempDir()
			writeTestConfig(t, root, server.URL)
			path := writeNotifySettings(t, root, tc.JSON)
			command := exec.CommandContext(ctx, binary, "init", "--inject-docs", "--setup-hooks")
			command.Dir = root
			command.Env = append(testCommandEnv(root), "AWEB_IDENTITY_HOME=", "AWEB_API_KEY=", "AW_NO_UPDATE_CHECK=1")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("init stopped on optional hook refusal: %v\n%s", err, output)
			}
			for _, part := range []string{"hook: not installed", path, tc.Repair} {
				if !bytes.Contains(output, []byte(part)) {
					t.Fatalf("missing %q: %s", part, output)
				}
			}
			if got := readInstallFile(t, path); string(got) != tc.JSON {
				t.Fatal("changed refused settings")
			}
			if docs := readInstallFile(t, filepath.Join(root, "AGENTS.md")); !bytes.Contains(docs, []byte("Instructions survive a hook refusal.")) {
				t.Fatal("other init action did not complete")
			}
		})
	}
}
