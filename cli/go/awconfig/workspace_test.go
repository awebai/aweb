package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWorktreeWorkspaceFromReadsLegacyRoleKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
workspace_id: ws-1
alias: alice
role: reviewer
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	state, err := LoadWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if state.RoleName != "reviewer" {
		t.Fatalf("role_name=%q", state.RoleName)
	}
	if state.Role != "reviewer" {
		t.Fatalf("role=%q", state.Role)
	}
}

func TestSaveWorktreeWorkspaceToWritesCanonicalRoleNameKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := SaveWorktreeWorkspaceTo(path, &WorktreeWorkspace{
		WorkspaceID: "ws-1",
		Alias:       "alice",
		Role:        "developer",
	}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workspace: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "role_name: developer") {
		t.Fatalf("workspace yaml missing role_name:\n%s", text)
	}
	if strings.Contains(text, "\nrole:") {
		t.Fatalf("workspace yaml still wrote legacy role key:\n%s", text)
	}
}
