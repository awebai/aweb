package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcceptanceMintedKeyMarkerRejectsMalformedState(t *testing.T) {
	for _, name := range []string{"directory", "malformed"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "pending-hosted-accept")
			if name == "directory" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("unrelated state\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := statHostedAcceptPendingMarker(path, filepath.Join(home, "signing.key")); err == nil {
				t.Fatal("malformed marker was accepted as fresh-key provenance")
			}
		})
	}
}
