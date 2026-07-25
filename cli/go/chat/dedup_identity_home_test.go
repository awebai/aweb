package chat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestDeliveredIDCachesRemainIndependentOfExternalIdentityHome(t *testing.T) {
	root := t.TempDir()
	principal := filepath.Join(root, "principal")
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, dir := range []string{principal, first, second} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(awconfig.IdentityHomeEnv, principal)
	if err := SaveDeliveredIDsForDir(first, []string{"first-message"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveDeliveredIDsForDir(second, []string{"second-message"}); err != nil {
		t.Fatal(err)
	}
	firstIDs, err := LoadDeliveredIDsForDir(first)
	if err != nil {
		t.Fatal(err)
	}
	secondIDs, err := LoadDeliveredIDsForDir(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := firstIDs["second-message"]; ok {
		t.Fatal("first instance cache contains second instance delivery")
	}
	if _, ok := secondIDs["first-message"]; ok {
		t.Fatal("second instance cache contains first instance delivery")
	}
	if _, err := os.Stat(filepath.Join(principal, DeliveredIDsFileName)); !os.IsNotExist(err) {
		t.Fatalf("identity home received instance delivery cache: %v", err)
	}
}
