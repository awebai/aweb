package main

import (
	"github.com/awebai/aw/awconfig"
	"os"
	"path/filepath"
	"testing"
)

func TestAPIKeyRecoveryFileOperationsRequireAnExplicitHome(t *testing.T) {
	absent := awconfig.IdentityHome{}
	if err := saveAPIKeyPartialInit(absent, &apiKeyPartialInitState{Version: 1}); err == nil {
		t.Fatal("save selected a home")
	}
	if err := removeAPIKeyPartialInit(absent); err == nil {
		t.Fatal("remove selected a home")
	}
	if _, err := quarantineAPIKeyPartialInit(absent); err == nil {
		t.Fatal("quarantine selected a home")
	}
	if _, err := snapshotAwTree(absent); err == nil {
		t.Fatal("snapshot selected a home")
	}
	if err := rollbackAwTree(absent, nil); err == nil {
		t.Fatal("rollback selected a home")
	}
}

func TestAPIKeyRollbackPreservesRecoveryInTheSelectedHome(t *testing.T) {
	home := awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "selected")}
	state := &apiKeyPartialInitState{Version: 1, Name: "retained"}
	if err := saveAPIKeyPartialInit(home, state); err != nil {
		t.Fatal(err)
	}
	snapshot, err := snapshotAwTree(home)
	if err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(home.Root, "new", "certificate")
	if err := os.MkdirAll(filepath.Dir(created), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("new installation"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := rollbackAwTree(home, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(created)); !os.IsNotExist(err) {
		t.Fatalf("installation remains: %v", err)
	}
	retained, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(home))
	if err != nil || retained == nil || retained.Name != state.Name {
		t.Fatalf("retained state lost: %v", err)
	}
}
