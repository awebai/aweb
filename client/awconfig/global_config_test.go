package awconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGlobalFromMissingFileReturnsEmpty(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	cfg, err := LoadGlobalFrom(path)
	if err != nil {
		t.Fatalf("LoadGlobalFrom: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected cfg")
	}
	if cfg.Servers == nil || cfg.Accounts == nil {
		t.Fatalf("expected maps initialized")
	}
}

func TestSaveGlobalToWrites0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "nested", "config.yaml")

	cfg := &GlobalConfig{
		Servers: map[string]Server{
			"localhost:8000": {},
		},
		Accounts: map[string]Account{
			"alice": {
				Server: "localhost:8000",
				APIKey: "aw_sk_test",
			},
		},
		DefaultAccount: "alice",
	}
	if err := cfg.SaveGlobalTo(path); err != nil {
		t.Fatalf("SaveGlobalTo: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%o, want 600", got)
	}
}

func TestUpdateGlobalAtMergesAccounts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")

	if err := UpdateGlobalAt(path, func(cfg *GlobalConfig) error {
		cfg.Accounts["a"] = Account{Server: "localhost:8000", APIKey: "aw_sk_a"}
		cfg.DefaultAccount = "a"
		return nil
	}); err != nil {
		t.Fatalf("UpdateGlobalAt #1: %v", err)
	}

	if err := UpdateGlobalAt(path, func(cfg *GlobalConfig) error {
		cfg.Accounts["b"] = Account{Server: "localhost:8000", APIKey: "aw_sk_b"}
		return nil
	}); err != nil {
		t.Fatalf("UpdateGlobalAt #2: %v", err)
	}

	cfg, err := LoadGlobalFrom(path)
	if err != nil {
		t.Fatalf("LoadGlobalFrom: %v", err)
	}
	if _, ok := cfg.Accounts["a"]; !ok {
		t.Fatalf("missing account a")
	}
	if _, ok := cfg.Accounts["b"]; !ok {
		t.Fatalf("missing account b")
	}
}
