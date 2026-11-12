package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// installSecretsActionsApp installs, under a fresh AW_HOME, the corpus's
// session_actions_of_secrets owner_acts as the app "secrets".
func installSecretsActionsApp(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/owner-act-delivery-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		ManifestCases []struct {
			Name      string          `json:"name"`
			AppOrigin string          `json:"app_origin"`
			OwnerActs json.RawMessage `json:"owner_acts"`
		} `json:"manifest_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.ManifestCases {
		if tc.Name != "session_actions_of_secrets" {
			continue
		}
		manifest, _ := json.Marshal(map[string]any{
			"manifest_version": 3,
			"app":              map[string]any{"id": "secrets", "version": "1.0.0", "origin": tc.AppOrigin},
			"tools":            []any{},
			"owner_acts":       tc.OwnerActs,
		})
		home := t.TempDir()
		t.Setenv("AW_HOME", home)
		dir := filepath.Join(home, "plugins", "secrets")
		_ = os.MkdirAll(dir, 0o700)
		_ = os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600)
		provenance, _ := json.Marshal(pluginProvenance{AppName: "secrets", AppID: "secrets", Origin: tc.AppOrigin, Digest: "sha256:pinned"})
		_ = os.WriteFile(filepath.Join(dir, "provenance.json"), provenance, 0o600)
		return
	}
	t.Fatal("no session_actions_of_secrets case")
}

func runAppHumanForTest(t *testing.T, args ...string) error {
	t.Helper()
	clearAgentMarkers(t)
	return runAppHuman(appHumanCmd, args)
}

func TestAnUndeclaredSessionActionIsUnknown(t *testing.T) {
	installSecretsActionsApp(t)
	if err := runAppHumanForTest(t, "secrets", "rotate-everything"); errorCodeOf(err) != "session_action_unknown" {
		t.Fatalf("err %v", err)
	}
}

func TestAProtectedFieldHasNoFlag(t *testing.T) {
	installSecretsActionsApp(t)
	old := terminalAttached
	terminalAttached = func() bool { return true }
	t.Cleanup(func() { terminalAttached = old })
	err := runAppHumanForTest(t, "secrets", "onepassword-token", "--value", "typed-on-the-command-line")
	if errorCodeOf(err) != "protected_input_unavailable" {
		t.Fatalf("err %v", err)
	}
}

func TestAProtectedFieldRefusesInsideAnAgentRuntime(t *testing.T) {
	installSecretsActionsApp(t)
	clearAgentMarkers(t)
	t.Setenv("CLAUDECODE", "1")
	if err := runAppHuman(appHumanCmd, []string{"secrets", "onepassword-token"}); errorCodeOf(err) != "protected_input_unavailable" {
		t.Fatalf("err %v", err)
	}
}

func TestATerminalOutputRefusesInsideAnAgentRuntime(t *testing.T) {
	installSecretsActionsApp(t)
	clearAgentMarkers(t)
	t.Setenv("CODEX_THREAD_ID", "1")
	err := runAppHuman(appHumanCmd, []string{"secrets", "confirm", "--change-id", "c-1"})
	if errorCodeOf(err) != "protected_output_unavailable" {
		t.Fatalf("err %v", err)
	}
}

func TestTheInstallationIsNotAFlag(t *testing.T) {
	installSecretsActionsApp(t)
	err := runAppHumanForTest(t, "secrets", "change-set", "--installation_id", "x", "--change_id", "c")
	if errorCodeOf(err) != "installation_id_not_a_flag" {
		t.Fatalf("err %v", err)
	}
}

func TestGlobalFlagsAreTakenFromAnywhere(t *testing.T) {
	oldJSON, oldHuman, oldDomain := jsonFlag, humanFlag, humanDomainFlag
	t.Cleanup(func() { jsonFlag, humanFlag, humanDomainFlag = oldJSON, oldHuman, oldDomain })
	rest, err := takeGlobalFlags([]string{"secrets", "--json", "change-set", "--human=did:aw:x", "--change_id", "c", "--human-domain", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !jsonFlag || humanFlag != "did:aw:x" || humanDomainFlag != "example.com" {
		t.Fatalf("json %v human %q domain %q", jsonFlag, humanFlag, humanDomainFlag)
	}
	want := []string{"secrets", "change-set", "--change_id", "c"}
	if len(rest) != len(want) {
		t.Fatalf("rest %v", rest)
	}
	for i := range want {
		if rest[i] != want[i] {
			t.Fatalf("rest %v", rest)
		}
	}
}
