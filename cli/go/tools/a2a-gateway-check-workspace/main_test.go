package main

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestWriteWorkspaceCreatesUsableSyntheticIdentity(t *testing.T) {
	root := t.TempDir()
	if err := writeWorkspace(root, "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}

	workspace, teams, loadedRoot, err := awconfig.LoadWorkspaceAndTeamState(root)
	if err != nil {
		t.Fatal(err)
	}
	if loadedRoot != root {
		t.Fatalf("loaded root=%q, want %q", loadedRoot, root)
	}
	if workspace.AwebURL != "http://127.0.0.1:1" {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
	if len(workspace.Memberships) != 1 || len(teams.Memberships) != 1 {
		t.Fatalf("memberships workspace=%d teams=%d", len(workspace.Memberships), len(teams.Memberships))
	}

	membership := teams.Memberships[0]
	cert, err := awid.LoadTeamCertificate(filepath.Join(root, ".aw", filepath.FromSlash(membership.CertPath)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != cert.MemberDIDKey {
		t.Fatalf("signing key did:key=%q, certificate=%q", got, cert.MemberDIDKey)
	}
}

func TestWriteWorkspaceRefusesNonEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	if err := writeWorkspace(root, "http://127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := writeWorkspace(root, "http://127.0.0.1:1"); err == nil {
		t.Fatal("expected non-empty output directory to be rejected")
	}
}
