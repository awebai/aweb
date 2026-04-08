package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func testCommandEnv(home string) []string {
	mirrorLegacyKnownAgentsFixture(home)
	return append(os.Environ(),
		"HOME="+home,
		"AW_CONFIG_PATH=",
	)
}

func testCommandEnvWithAuth(home, baseURL, apiKey string) []string {
	env := testCommandEnv(home)
	if baseURL != "" {
		env = append(env, "AWEB_URL="+baseURL)
	}
	if apiKey != "" {
		env = append(env, "AWEB_API_KEY="+apiKey)
	}
	return env
}

func writeWorkspaceBindingForTest(t *testing.T, workingDir string, state awconfig.WorktreeWorkspace) string {
	t.Helper()
	path := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := awconfig.SaveWorktreeWorkspaceTo(path, &state); err != nil {
		t.Fatalf("write workspace binding: %v", err)
	}
	return path
}

func writeContextForTest(t *testing.T, workingDir string, ctx awconfig.WorktreeContext) string {
	t.Helper()
	path := filepath.Join(workingDir, ".aw", "context")
	if err := awconfig.SaveWorktreeContextTo(path, &ctx); err != nil {
		t.Fatalf("write worktree context: %v", err)
	}
	return path
}

func writeIdentityForTest(t *testing.T, workingDir string, state awconfig.WorktreeIdentity) string {
	t.Helper()
	path := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	if err := awconfig.SaveWorktreeIdentityTo(path, &state); err != nil {
		t.Fatalf("write worktree identity: %v", err)
	}
	return path
}

func defaultWorkspaceBinding(serverURL string) awconfig.WorktreeWorkspace {
	return awconfig.WorktreeWorkspace{
		AwebURL:        serverURL,
		APIKey:         "aw_sk_test",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		WorkspaceID:    "workspace-1",
		ProjectSlug:    "demo",
	}
}

func writeDefaultWorkspaceBindingForTest(t *testing.T, workingDir, serverURL string) string {
	t.Helper()
	return writeWorkspaceBindingForTest(t, workingDir, defaultWorkspaceBinding(serverURL))
}

type testSelectionFixture struct {
	AwebURL        string
	APIKey         string
	IdentityID     string
	IdentityHandle string
	NamespaceSlug  string
	ProjectSlug    string
	WorkspaceID    string
	DID            string
	StableID       string
	Address        string
	Custody        string
	Lifetime       string
	SigningKey     ed25519.PrivateKey
	CreatedAt      string
}

func writeSelectionFixtureForTest(t *testing.T, workingDir string, fixture testSelectionFixture) {
	t.Helper()
	workspace := awconfig.WorktreeWorkspace{
		AwebURL:        fixture.AwebURL,
		APIKey:         fixture.APIKey,
		IdentityID:     fixture.IdentityID,
		IdentityHandle: fixture.IdentityHandle,
		NamespaceSlug:  fixture.NamespaceSlug,
		ProjectSlug:    fixture.ProjectSlug,
		WorkspaceID:    fixture.WorkspaceID,
	}
	if workspace.WorkspaceID == "" {
		workspace.WorkspaceID = fixture.IdentityID
	}
	if workspace.ProjectSlug == "" {
		workspace.ProjectSlug = fixture.NamespaceSlug
	}
	writeWorkspaceBindingForTest(t, workingDir, workspace)

	if fixture.DID == "" && fixture.StableID == "" && fixture.Custody == "" && fixture.Lifetime == "" && fixture.Address == "" {
		return
	}

	createdAt := fixture.CreatedAt
	if createdAt == "" {
		createdAt = "2026-04-04T00:00:00Z"
	}
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:       fixture.DID,
		StableID:  fixture.StableID,
		Address:   fixture.Address,
		Custody:   fixture.Custody,
		Lifetime:  fixture.Lifetime,
		CreatedAt: createdAt,
	})

	if fixture.SigningKey != nil {
		if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), fixture.SigningKey); err != nil {
			t.Fatalf("write signing key: %v", err)
		}
	}
}

func mirrorLegacyKnownAgentsFixture(workingDir string) {
	sourcePath := filepath.Join(workingDir, "known_agents.yaml")
	if _, err := os.Stat(sourcePath); err != nil {
		return
	}
	targetPath, err := awconfig.DefaultKnownAgentsPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(targetPath), 0o700)
	_ = os.WriteFile(targetPath, data, 0o600)
}
