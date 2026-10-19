package main

import (
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestInboxIndexesStayWithSelectedPrincipal(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "checkout")
	a := &awconfig.Selection{WorkingDir: cwd, IdentityHome: filepath.Join(root, "principal-a"), WorkspacePath: filepath.Join(root, "principal-a", "workspace.yaml"), ExternalIdentityHome: true}
	b := &awconfig.Selection{WorkingDir: cwd, IdentityHome: filepath.Join(root, "principal-b"), WorkspacePath: filepath.Join(root, "principal-b", "workspace.yaml"), ExternalIdentityHome: true}
	saveBeadsMailInboxState(a, []string{"a-message"})
	saveBeadsMailInboxState(b, []string{"b-message"})
	for _, tc := range []struct {
		sel  *awconfig.Selection
		want string
	}{{a, "a-message"}, {b, "b-message"}} {
		got, err := resolveBeadsMailMessageRef(tc.sel, "1")
		if err != nil || got != tc.want {
			t.Fatalf("inbox index crossed identity boundary: got %q err %v want %q", got, err, tc.want)
		}
	}
}
