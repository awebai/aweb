package awconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestResolvePrefersIdentityAddressForPersistentBYOD(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:     "https://app.aweb.ai",
		TeamAddress: "myteam.aweb.ai/backend",
		Alias:       "support",
		WorkspaceID: "agent-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:       "did:key:z6MkBYOD",
		StableID:  "did:aw:byod-support",
		Address:   "acme.com/support",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WorktreeSigningKeyPath(tmp), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Address != "acme.com/support" {
		t.Fatalf("address=%q want %q", sel.Address, "acme.com/support")
	}
	if sel.NamespaceSlug != "myteam.aweb.ai" {
		t.Fatalf("namespace_slug=%q", sel.NamespaceSlug)
	}
}

func TestResolveDerivesWorkspaceIdentityFromCanonicalBinding(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:     "https://app.aweb.ai",
		TeamAddress: "acme.com/backend",
		Alias:       "alice",
		WorkspaceID: "workspace-1",
	}); err != nil {
		t.Fatal(err)
	}

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.IdentityHandle != "alice" {
		t.Fatalf("identity_handle=%q", sel.IdentityHandle)
	}
	if sel.IdentityID != "workspace-1" {
		t.Fatalf("identity_id=%q", sel.IdentityID)
	}
	if sel.NamespaceSlug != "acme.com" {
		t.Fatalf("namespace_slug=%q", sel.NamespaceSlug)
	}
	if sel.DefaultProject != "" {
		t.Fatalf("default_project=%q", sel.DefaultProject)
	}
}
