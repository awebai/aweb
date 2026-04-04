package awconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestResolveExplicitAccountWins(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"aweb": {URL: "http://localhost:8000"},
		},
		Accounts: map[string]Account{
			"a": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_a"}},
			"b": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_b"}},
		},
		DefaultAccount: "a",
	}

	sel, err := Resolve(global, ResolveOptions{AccountName: "b"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "b" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.APIKey != "aw_sk_b" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
	if sel.BaseURL != "http://localhost:8000" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
}

func TestResolveServerUsesContextServerAccounts(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"local": {URL: "http://localhost:8000"},
			"aweb":  {URL: "https://app.aweb.ai"},
		},
		Accounts: map[string]Account{
			"wt-local": {Account: awid.Account{Server: "local", APIKey: "aw_sk_local"}},
			"wt-aweb":  {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_aweb"}},
		},
		DefaultAccount: "wt-aweb",
	}
	ctx := &WorktreeContext{
		DefaultAccount: "wt-aweb",
		ServerAccounts: map[string]string{
			"aweb": "wt-aweb",
		},
	}

	sel, err := Resolve(global, ResolveOptions{ServerName: "aweb", Context: ctx})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "wt-aweb" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
}

func TestResolvePrefersClientDefaultAccountInContext(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"local": {URL: "http://localhost:8000"},
			"aweb":  {URL: "https://app.aweb.ai"},
		},
		Accounts: map[string]Account{
			"acct-local": {Account: awid.Account{Server: "local", APIKey: "aw_sk_local"}},
			"acct-aweb":  {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_aweb"}},
		},
		DefaultAccount: "acct-aweb",
	}
	ctx := &WorktreeContext{
		DefaultAccount: "acct-aweb",
		ServerAccounts: map[string]string{},
		ClientDefaultAccounts: map[string]string{
			"aw": "acct-aweb",
		},
	}

	sel, err := Resolve(global, ResolveOptions{ClientName: "aw", Context: ctx})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "acct-aweb" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
}

func TestResolvePrefersClientDefaultAccountInGlobalConfig(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"local": {URL: "http://localhost:8000"},
			"aweb":  {URL: "https://app.aweb.ai"},
		},
		Accounts: map[string]Account{
			"acct-local": {Account: awid.Account{Server: "local", APIKey: "aw_sk_local"}},
			"acct-aweb":  {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_aweb"}},
		},
		DefaultAccount: "acct-aweb",
		ClientDefaultAccounts: map[string]string{
			"aw": "acct-aweb",
		},
	}

	sel, err := Resolve(global, ResolveOptions{ClientName: "aw"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "acct-aweb" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
}

func TestResolveEnvOverrides(t *testing.T) {
	t.Setenv("AWEB_URL", "http://example.com")
	t.Setenv("AWEB_API_KEY", "aw_sk_env")
	t.Setenv("AWEB_ACCOUNT", "")

	global := &GlobalConfig{
		Accounts: map[string]Account{
			"a": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_a"}},
		},
		DefaultAccount: "a",
	}

	sel, err := Resolve(global, ResolveOptions{AllowEnvOverrides: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.BaseURL != "http://example.com" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
	if sel.APIKey != "aw_sk_env" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
}

func TestResolveEnvAccount(t *testing.T) {
	t.Setenv("AWEB_ACCOUNT", "b")
	t.Setenv("AWEB_URL", "")
	t.Setenv("AWEB_API_KEY", "")

	global := &GlobalConfig{
		Servers: map[string]Server{
			"aweb": {URL: "http://localhost:8000"},
		},
		Accounts: map[string]Account{
			"a": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_a"}},
			"b": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_b"}},
		},
		DefaultAccount: "a",
	}

	sel, err := Resolve(global, ResolveOptions{AllowEnvOverrides: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "b" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.APIKey != "aw_sk_b" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
}

func TestValidateBaseURL(t *testing.T) {
	t.Parallel()

	if err := ValidateBaseURL(""); err == nil {
		t.Fatalf("expected error")
	}
	if err := ValidateBaseURL("localhost:8000"); err == nil {
		t.Fatalf("expected error")
	}
	if err := ValidateBaseURL("http://localhost:8000"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveMissingDefaults(t *testing.T) {
	t.Parallel()

	if _, err := Resolve(&GlobalConfig{}, ResolveOptions{}); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := Resolve(&GlobalConfig{}, ResolveOptions{AllowEnvOverrides: true}); err == nil {
		// Even with env overrides allowed, empty env should error.
		t.Fatalf("expected error")
	}
	if os.Getenv("AWEB_URL") != "" || os.Getenv("AWEB_API_KEY") != "" {
		t.Fatalf("test expects no env")
	}
}

func TestResolveEnvOnlyNoAccount(t *testing.T) {
	// Not parallel: t.Setenv mutates process env, would race with TestResolveMissingDefaults.
	t.Setenv("AWEB_URL", "http://example.com")
	t.Setenv("AWEB_API_KEY", "aw_sk_env")
	t.Setenv("AWEB_ACCOUNT", "")
	t.Setenv("AWEB_SERVER", "")

	// No accounts configured at all — env vars alone should suffice.
	sel, err := Resolve(&GlobalConfig{}, ResolveOptions{AllowEnvOverrides: true})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.BaseURL != "http://example.com" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
	if sel.APIKey != "aw_sk_env" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
}

func TestResolveAccountByAgentAlias(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"prod": {URL: "https://app.aweb.ai"},
		},
		Accounts: map[string]Account{
			"acct-prod__default__alice": {Account: awid.Account{Server: "prod", APIKey: "aw_sk_alice", IdentityHandle: "alice"}},
			"acct-prod__default__bob":   {Account: awid.Account{Server: "prod", APIKey: "aw_sk_bob", IdentityHandle: "bob"}},
		},
		DefaultAccount: "acct-prod__default__alice",
	}

	// "bob" doesn't match any config key, but matches agent_alias on one account.
	sel, err := Resolve(global, ResolveOptions{AccountName: "bob"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "acct-prod__default__bob" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.APIKey != "aw_sk_bob" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
}

func TestResolveStableID(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"aweb": {URL: "http://localhost:8000"},
		},
		Accounts: map[string]Account{
			"a": {Account: awid.Account{Server: "aweb", APIKey: "aw_sk_a", StableID: "did:aw:abc123"}},
		},
		DefaultAccount: "a",
	}

	sel, err := Resolve(global, ResolveOptions{AccountName: "a"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.StableID != "did:aw:abc123" {
		t.Fatalf("StableID=%q, want %q", sel.StableID, "did:aw:abc123")
	}
}

func TestResolveAccountByAgentAliasAmbiguous(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"prod":    {URL: "https://app.aweb.ai"},
			"staging": {URL: "https://staging.aweb.ai"},
		},
		Accounts: map[string]Account{
			"acct-prod":    {Account: awid.Account{Server: "prod", APIKey: "aw_sk_1", IdentityHandle: "alice"}},
			"acct-staging": {Account: awid.Account{Server: "staging", APIKey: "aw_sk_2", IdentityHandle: "alice"}},
		},
		DefaultAccount: "acct-prod",
	}

	// "alice" matches two accounts — should error, not silently pick one.
	_, err := Resolve(global, ResolveOptions{AccountName: "alice"})
	if err == nil {
		t.Fatalf("expected error for ambiguous alias")
	}
}

func TestResolvePrefersWorkspaceBindingOverContextDefaults(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := SaveWorktreeWorkspaceTo(filepath.Join(awDir, "workspace.yaml"), &WorktreeWorkspace{
		ServerURL:      "https://app.aweb.ai",
		APIKey:         "aw_sk_workspace",
		IdentityID:     "ws-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
		DID:            "did:key:z6MkWorkspace",
		StableID:       "did:aw:workspace",
		SigningKey:     ".aw/signing.key",
		Custody:        "self",
		Lifetime:       "persistent",
	}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}
	if err := SaveWorktreeContextTo(filepath.Join(awDir, "context"), &WorktreeContext{
		DefaultAccount: "acct-global",
		ServerAccounts: map[string]string{"prod": "acct-global"},
	}); err != nil {
		t.Fatalf("save context: %v", err)
	}

	global := &GlobalConfig{
		Servers: map[string]Server{
			"prod": {URL: "https://staging.aweb.ai"},
		},
		Accounts: map[string]Account{
			"acct-global": {Account: awid.Account{
				Server:         "prod",
				APIKey:         "aw_sk_global",
				IdentityID:     "global-1",
				IdentityHandle: "bob",
			}},
		},
		DefaultAccount: "acct-global",
	}

	sel, err := Resolve(global, ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sel.AccountName != "" {
		t.Fatalf("account=%q", sel.AccountName)
	}
	if sel.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("baseURL=%q", sel.BaseURL)
	}
	if sel.APIKey != "aw_sk_workspace" {
		t.Fatalf("apiKey=%q", sel.APIKey)
	}
	if sel.IdentityHandle != "alice" {
		t.Fatalf("identity_handle=%q", sel.IdentityHandle)
	}
	if sel.StableID != "did:aw:workspace" {
		t.Fatalf("stable_id=%q", sel.StableID)
	}
}
