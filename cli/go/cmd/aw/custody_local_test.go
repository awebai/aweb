package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestCustodyLocalFallbackRefusals(t *testing.T) {
	for _, scenario := range []string{"malformed-identity", "external-home", "global-certificate", "key-mismatch", "missing-certificate"} {
		t.Run(scenario, func(t *testing.T) {
			resetGrantCommandGlobals(t)
			root := t.TempDir()
			t.Chdir(root)
			setGrantTestEnv(t, root)
			pub, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			did := awid.ComputeDIDKey(pub)
			writeLocalTeamSignedRequestWorkspaceForTest(t, root, "http://127.0.0.1:1", "backend:demo", "resident", did, key)
			home, err := awconfig.ResolveIdentityHome(root, "")
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "malformed-identity":
				if err := os.WriteFile(filepath.Join(home.Root, "identity.yaml"), []byte("[invalid yaml"), 0600); err != nil {
					t.Fatal(err)
				}
			case "external-home":
				home = awconfig.IdentityHome{Root: t.TempDir(), Source: awconfig.IdentityHomeFlag}
			case "global-certificate":
				writeGlobalTeamSignedRequestWorkspaceForTest(t, root, "http://127.0.0.1:1", "backend:demo", "resident", did, awid.ComputeStableID(pub), "demo/resident", key)
				if err := os.Remove(filepath.Join(home.Root, "identity.yaml")); err != nil {
					t.Fatal(err)
				}
			case "key-mismatch":
				_, other, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), other); err != nil {
					t.Fatal(err)
				}
			case "missing-certificate":
				if err := os.Remove(awconfig.TeamCertificatePath(root, "backend:demo")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := newCustodyService(home); err == nil {
				t.Fatalf("accepted %s", scenario)
			}
		})
	}
}
