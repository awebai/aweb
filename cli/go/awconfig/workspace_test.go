package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func canonicalWorkspaceState() *WorktreeWorkspace {
	return &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		APIKey:     "aw_sk_workspace",
		ActiveTeam: "backend:acme.com",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			RoleName:    "developer",
			WorkspaceID: "ws-1",
			CertPath:    TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	}
}

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
	if err := SaveWorktreeWorkspaceTo(path, canonicalWorkspaceState()); err != nil {
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
	if err := SaveWorktreeWorkspaceTo(path, canonicalWorkspaceState()); err != nil {
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
team_id: default:acme.com
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

func TestLoadWorktreeWorkspaceFromRejectsLegacySingleTeamShape(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
team_id: backend:acme.com
alias: alice
workspace_id: ws-1
role_name: developer
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected legacy single-team workspace load to fail")
	}
	if !strings.Contains(err.Error(), legacyWorkspaceSingleTeamError) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadWorktreeWorkspaceFromRejectsRemovedIdentityAndProjectFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
identity_handle: alice
did: did:key:z6MkWorkspace
stable_id: did:aw:workspace
signing_key: .aw/signing.key
custody: self
lifetime: persistent
project_slug: acme
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    workspace_id: ws-1
    cert_path: team-certs/backend__acme.com.pem
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

func TestLoadWorktreeWorkspaceFromRejectsRemovedRegistryAndHostedURLFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
awid_url: https://registry.example
cloud_url: https://hosted.example
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    workspace_id: ws-1
    cert_path: team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected removed workspace fields to fail")
	}
	for _, field := range []string{"awid_url", "cloud_url"} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing field %q in error: %v", field, err)
		}
	}
}

func TestLoadWorktreeWorkspaceFromAcceptsWorkspaceAPIKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
api_key: removed-token
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    workspace_id: ws-1
    cert_path: team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	workspace, err := LoadWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspace.APIKey != "removed-token" {
		t.Fatalf("api_key=%q", workspace.APIKey)
	}
}

func TestLoadWorktreeWorkspaceFromRejectsUnsupportedFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    workspace_id: ws-1
    cert_path: team-certs/backend__acme.com.pem
future_key: value
weird_mode: true
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected unsupported workspace fields to fail")
	}
	if !strings.Contains(err.Error(), workspaceUnsupportedFieldsErrorPrefix) {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, field := range []string{"future_key", "weird_mode"} {
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("missing field %q in error: %v", field, err)
		}
	}
}

func TestLoadWorktreeWorkspaceFromRejectsLegacyTeamAddressKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
team_address: acme.com/backend
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    workspace_id: ws-1
    cert_path: team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected legacy team_address workspace load to fail")
	}
	if !strings.Contains(err.Error(), legacyWorkspaceTeamAddressError) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadWorktreeWorkspaceFromRejectsEmptyMemberships(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "workspace.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(`
aweb_url: https://app.aweb.ai
active_team: backend:acme.com
memberships: []
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write workspace: %v", err)
	}

	_, err := LoadWorktreeWorkspaceFrom(path)
	if err == nil {
		t.Fatal("expected empty memberships to fail")
	}
	if !strings.Contains(err.Error(), "at least one membership") {
		t.Fatalf("unexpected error: %v", err)
	}
}
