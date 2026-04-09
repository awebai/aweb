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
	if sel.Domain != "myteam.aweb.ai" {
		t.Fatalf("domain=%q", sel.Domain)
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
	if sel.Alias != "alice" {
		t.Fatalf("alias=%q", sel.Alias)
	}
	if sel.WorkspaceID != "workspace-1" {
		t.Fatalf("workspace_id=%q", sel.WorkspaceID)
	}
	if sel.Domain != "acme.com" {
		t.Fatalf("domain=%q", sel.Domain)
	}
}
