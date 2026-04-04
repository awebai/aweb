package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
)

func testCommandEnv(home string) []string {
	mirrorLegacyConfigFixture(home)
	mirrorLegacyKnownAgentsFixture(home)
	baseURL, apiKey := legacyEnvOverrides(home)
	return append(os.Environ(),
		"HOME="+home,
		"AW_CONFIG_PATH=",
		"AWEB_URL="+baseURL,
		"AWEB_API_KEY="+apiKey,
	)
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
		ServerURL:      serverURL,
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

type legacyTestConfig struct {
	Servers        map[string]legacyTestServer  `yaml:"servers"`
	Accounts       map[string]legacyTestAccount `yaml:"accounts"`
	DefaultAccount string                       `yaml:"default_account"`
}

type legacyTestServer struct {
	URL string `yaml:"url"`
}

type legacyTestAccount struct {
	Server         string `yaml:"server"`
	APIKey         string `yaml:"api_key"`
	IdentityID     string `yaml:"identity_id"`
	IdentityHandle string `yaml:"identity_handle"`
	NamespaceSlug  string `yaml:"namespace_slug"`
	DID            string `yaml:"did"`
	StableID       string `yaml:"stable_id"`
	SigningKey     string `yaml:"signing_key"`
	Custody        string `yaml:"custody"`
	Lifetime       string `yaml:"lifetime"`
	ProjectSlug    string `yaml:"project_slug"`
	WorkspaceID    string `yaml:"workspace_id"`
}

func mirrorLegacyConfigFixture(workingDir string) {
	cfgPath := filepath.Join(workingDir, "config.yaml")
	if _, err := os.Stat(cfgPath); err != nil {
		return
	}

	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}

	var cfg legacyTestConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return
	}

	accountName := cfg.DefaultAccount
	if accountName == "" {
		for name := range cfg.Accounts {
			accountName = name
			break
		}
	}
	acct, ok := cfg.Accounts[accountName]
	if !ok {
		return
	}
	serverURL := acct.Server
	if srv, ok := cfg.Servers[acct.Server]; ok && srv.URL != "" {
		serverURL = srv.URL
	}

	ws := awconfig.WorktreeWorkspace{
		ServerURL:      serverURL,
		APIKey:         acct.APIKey,
		IdentityID:     acct.IdentityID,
		IdentityHandle: acct.IdentityHandle,
		NamespaceSlug:  acct.NamespaceSlug,
		DID:            acct.DID,
		StableID:       acct.StableID,
		SigningKey:     acct.SigningKey,
		Custody:        acct.Custody,
		Lifetime:       acct.Lifetime,
		WorkspaceID:    acct.WorkspaceID,
		ProjectSlug:    acct.ProjectSlug,
	}
	if ws.WorkspaceID == "" {
		ws.WorkspaceID = acct.IdentityID
	}
	if ws.ProjectSlug == "" {
		ws.ProjectSlug = acct.NamespaceSlug
	}
	if existing, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath); err == nil {
		if existing.ServerURL == "" {
			existing.ServerURL = ws.ServerURL
		}
		if existing.APIKey == "" {
			existing.APIKey = ws.APIKey
		}
		if existing.IdentityID == "" {
			existing.IdentityID = ws.IdentityID
		}
		if existing.IdentityHandle == "" {
			existing.IdentityHandle = ws.IdentityHandle
		}
		if existing.NamespaceSlug == "" {
			existing.NamespaceSlug = ws.NamespaceSlug
		}
		if existing.WorkspaceID == "" {
			existing.WorkspaceID = ws.WorkspaceID
		}
		if existing.ProjectSlug == "" {
			existing.ProjectSlug = ws.ProjectSlug
		}
		if existing.SigningKey == "" {
			existing.SigningKey = ws.SigningKey
		}
		if existing.Custody == "" {
			existing.Custody = ws.Custody
		}
		if existing.Lifetime == "" {
			existing.Lifetime = ws.Lifetime
		}
		ws = *existing
	}
	_ = awconfig.SaveWorktreeWorkspaceTo(workspacePath, &ws)

	if acct.DID == "" && acct.StableID == "" && acct.Custody == "" && acct.Lifetime == "" {
		return
	}

	identity := awconfig.WorktreeIdentity{
		DID:       acct.DID,
		StableID:  acct.StableID,
		Custody:   acct.Custody,
		Lifetime:  acct.Lifetime,
		CreatedAt: "2026-04-04T00:00:00Z",
	}
	_ = awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()), &identity)

	if acct.Custody == "self" {
		targetPath := awconfig.WorktreeSigningKeyPath(workingDir)
		if _, err := os.Stat(targetPath); err == nil {
			return
		}
		sourcePath := acct.SigningKey
		if sourcePath == "" {
			sourcePath = ws.SigningKey
		}
		if sourcePath == "" {
			return
		}
		keyData, err := os.ReadFile(sourcePath)
		if err != nil {
			return
		}
		_ = os.MkdirAll(filepath.Dir(targetPath), 0o700)
		_ = os.WriteFile(targetPath, keyData, 0o600)
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

func legacyEnvOverrides(workingDir string) (string, string) {
	cfgPath := filepath.Join(workingDir, "config.yaml")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", ""
	}

	var cfg legacyTestConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", ""
	}

	accountName := cfg.DefaultAccount
	if accountName == "" {
		for name := range cfg.Accounts {
			accountName = name
			break
		}
	}
	acct, ok := cfg.Accounts[accountName]
	if !ok {
		return "", ""
	}
	baseURL := acct.Server
	if srv, ok := cfg.Servers[acct.Server]; ok && srv.URL != "" {
		baseURL = srv.URL
	}
	return baseURL, acct.APIKey
}
