package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneCreationReadFailureKeepsItsRecoveryHome(t *testing.T) {
	for _, condition := range []string{"absent", "malformed", "unreadable"} {
		t.Run(condition, func(t *testing.T) {
			home := t.TempDir()
			identityPath := filepath.Join(home, "identity.yaml")
			path := standaloneCreateRecoveryPath(identityPath)
			switch condition {
			case "malformed":
				if err := os.WriteFile(path, []byte("{incomplete"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			prepared, err := loadStandaloneCreateRecovery(standaloneCreateResume{IdentityPath: identityPath, SigningKeyPath: filepath.Join(home, "signing.key"), WorkspacePath: filepath.Join(home, "workspace.yaml"), Name: "retained", Domain: "example.com"})
			if condition == "absent" {
				if err != nil || prepared != nil {
					t.Fatalf("absent attempt was treated as retained: %v", err)
				}
				return
			}
			if err == nil || prepared != nil || !retainUnfinishedProvisioningIdentity(err) {
				t.Fatalf("unreadable retained operation could be deleted by its caller: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("inspection discarded the original recovery: %v", err)
			}
		})
	}
}
