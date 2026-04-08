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

func TestLoadWorktreeWorkspaceFromIgnoresIdentityFieldsWhenIdentityExists(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "workspace.yaml"), []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
team_address: acme.com/backend
identity_handle: alice
did: did:key:z6MkWorkspace
stable_id: did:aw:workspace
signing_key: .aw/signing.key
custody: self
lifetime: persistent
workspace_id: ws-1
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(awDir, "identity.yaml"), &WorktreeIdentity{
		DID:       "did:key:z6MkIdentity",
		StableID:  "did:aw:identity",
		Custody:   "self",
		Lifetime:  "persistent",
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	state, err := LoadWorktreeWorkspaceFrom(filepath.Join(awDir, "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if state.DID != "" || state.StableID != "" || state.SigningKey != "" || state.Custody != "" || state.Lifetime != "" {
		t.Fatalf("workspace identity fields were not scrubbed: %#v", state)
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

func TestScrubWorkspaceIdentityFieldsReturnsStatErrors(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	workspacePath := filepath.Join(awDir, "workspace.yaml")
	state := &WorktreeWorkspace{
		DID:        "did:key:z6MkWorkspace",
		StableID:   "did:aw:workspace",
		SigningKey: ".aw/signing.key",
		Custody:    "self",
		Lifetime:   "persistent",
	}

	if err := os.Chmod(awDir, 0o000); err != nil {
		t.Fatalf("chmod .aw: %v", err)
	}
	defer func() {
		_ = os.Chmod(awDir, 0o755)
	}()

	err := scrubWorkspaceIdentityFields(workspacePath, state, false)
	if err == nil {
		t.Fatal("expected stat error")
	}
	if !strings.Contains(err.Error(), "stat ") {
		t.Fatalf("unexpected error: %v", err)
	}
}
