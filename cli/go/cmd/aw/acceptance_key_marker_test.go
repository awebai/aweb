package main

import (
	"github.com/awebai/aw/awconfig"
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
			if err := (acceptanceMintedKey{Home: awconfig.IdentityHome{Root: home}}).require(); err == nil {
				t.Fatal("malformed marker was accepted as fresh-key provenance")
			}
		})
	}
}

func TestAcceptanceMintedKeyMarkerUsesOnlyItsNamedHome(t *testing.T) {
	home := t.TempDir()
	marker := acceptanceMintedKey{Home: awconfig.IdentityHome{Root: home}}
	if found, err := marker.present(); err != nil || found {
		t.Fatalf("absent marker: present=%v err=%v", found, err)
	}
	if err := marker.save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, acceptanceKeyMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "pending hosted accept\n" {
		t.Fatalf("released marker bytes changed: %q", raw)
	}
	info, err := os.Stat(filepath.Join(home, acceptanceKeyMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode=%v", info.Mode())
	}
	if err := marker.require(); err != nil {
		t.Fatal(err)
	}
	if err := marker.remove(); err != nil {
		t.Fatal(err)
	}
	if err := marker.remove(); err != nil {
		t.Fatal(err)
	}
	if found, err := marker.present(); err != nil || found {
		t.Fatalf("removed marker: present=%v err=%v", found, err)
	}
	if err := (acceptanceMintedKey{}).save(); err == nil {
		t.Fatal("unnamed home accepted")
	}
}
