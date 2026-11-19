//go:build !windows

package awconfig

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorityKeyIOPreservesOperatorManagedParentPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(home, ".awid")); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := SaveTeamKey("example.com", "team", key); err != nil {
		t.Fatal(err)
	}
	team, err := LoadTeamKey("example.com", "team")
	if err != nil || !team.Equal(key) {
		t.Fatalf("operator-managed team key: %v", err)
	}
	if err := SaveControllerKey("example.com", key); err != nil {
		t.Fatal(err)
	}
	controller, err := LoadControllerKey("example.com")
	if err != nil || !controller.Equal(key) {
		t.Fatalf("operator-managed controller key: %v", err)
	}
}
