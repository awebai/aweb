package awconfig

import (
	"os"
	"testing"
)

func TestResolveExplicitAccountWins(t *testing.T) {
	t.Parallel()

	global := &GlobalConfig{
		Servers: map[string]Server{
			"beadhub": {URL: "http://localhost:8000"},
		},
		Accounts: map[string]Account{
			"a": {Server: "beadhub", APIKey: "aw_sk_a"},
			"b": {Server: "beadhub", APIKey: "aw_sk_b"},
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
			"beadhub": {URL: "http://localhost:8000"},
			"aweb":    {URL: "https://app.aweb.ai"},
		},
		Accounts: map[string]Account{
			"wt-bh":   {Server: "beadhub", APIKey: "aw_sk_bh"},
			"wt-aweb": {Server: "aweb", APIKey: "aw_sk_aweb"},
		},
		DefaultAccount: "wt-bh",
	}
	ctx := &WorktreeContext{
		DefaultAccount: "wt-bh",
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

func TestResolveEnvOverrides(t *testing.T) {
	t.Setenv("AWEB_URL", "http://example.com")
	t.Setenv("AWEB_API_KEY", "aw_sk_env")
	t.Setenv("AWEB_ACCOUNT", "")

	global := &GlobalConfig{
		Accounts: map[string]Account{
			"a": {Server: "beadhub", APIKey: "aw_sk_a"},
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
			"beadhub": {URL: "http://localhost:8000"},
		},
		Accounts: map[string]Account{
			"a": {Server: "beadhub", APIKey: "aw_sk_a"},
			"b": {Server: "beadhub", APIKey: "aw_sk_b"},
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
