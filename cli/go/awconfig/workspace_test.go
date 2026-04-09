package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadWorktreeWorkspaceFromRejectsLegacyRoleKey(t *testing.T) {
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

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected legacy role key to fail")
	}
	if !strings.Contains(err.Error(), legacyWorkspaceRemovedFieldsErrorPrefix) {
		t.Fatalf("unexpected error: %v", err)
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

func TestSaveWorktreeWorkspaceToWrites0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := SaveWorktreeWorkspaceTo(path, &WorktreeWorkspace{
		AwebURL:     "https://app.aweb.ai",
		TeamAddress: "acme.com/backend",
		WorkspaceID: "ws-1",
	}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat workspace: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o want %#o", got, 0o600)
	}
}

func TestLoadWorktreeWorkspaceFromRejectsLegacyServerURLOnly(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
server_url: https://coord.example
team_address: acme.com/default
workspace_id: ws-1
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected legacy workspace load to fail")
	}
	if !strings.Contains(err.Error(), legacyWorkspaceFormatError) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadWorktreeWorkspaceFromRejectsRemovedIdentityAndProjectFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
team_address: acme.com/backend
identity_handle: alice
did: did:key:z6MkWorkspace
stable_id: did:aw:workspace
signing_key: .aw/signing.key
custody: self
lifetime: persistent
project_slug: acme
workspace_id: ws-1
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected removed workspace fields to fail")
	}
	for _, field := range []string{"identity_handle", "did", "stable_id", "signing_key", "custody", "lifetime", "project_slug"} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing field %q in error: %v", field, err)
		}
	}
}

func TestLoadWorktreeWorkspaceFromRejectsLegacyAPIKeyAuth(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
api_key: aw_sk_test
workspace_id: ws-1
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected api_key workspace load to fail")
	}
	if !strings.Contains(err.Error(), legacyWorkspaceAPIKeyError) {
		t.Fatalf("unexpected error: %v", err)
	}
}
