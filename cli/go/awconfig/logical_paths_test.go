package awconfig

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIdentityHomePathSlashContract(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}
	for _, input := range []string{"identity.yaml", "team-certs/default__acme.aweb.ai.pem", "encryption-keys/sha256-abc.x25519.key", " team-certs/team.pem "} {
		t.Run(input, func(t *testing.T) {
			got, err := IdentityHomePath(home, input)
			want := filepath.Join(root, filepath.FromSlash(strings.TrimSpace(input)))
			if err != nil || got != want {
				t.Fatalf("path(%q)=%q, %v; want %q", input, got, err, want)
			}
		})
	}
	unsafe := []string{"", " ", "/tmp/key", `team-certs\acme.pem`, `\tmp\key`, `\\server\share\key`, "../key", "a/../../" + filepath.Base(root) + "/inner.key"}
	if runtime.GOOS == "windows" {
		unsafe = append(unsafe, "C:/tmp/key", "C:key")
	}
	for _, input := range unsafe {
		t.Run("reject/"+input, func(t *testing.T) {
			if got, err := IdentityHomePath(home, input); err == nil || got != "" {
				t.Fatalf("unsafe path(%q)=%q, %v", input, got, err)
			}
		})
	}
}

// These are stored logical paths, regardless of the OS that writes them. The
// exact slash literals also exercise the actual Windows helpers in native CI.
func TestLogicalRelativePathsUseForwardSlashes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}
	cases := []struct{ name, got, want string }{
		{"context", DefaultWorktreeContextRelativePath(), ".aw/context"},
		{"encryption-state", DefaultWorktreeEncryptionStateRelativePath(), ".aw/encryption.yaml"},
		{"encryption-directory", DefaultWorktreeEncryptionKeysRelativeDir(), ".aw/encryption-keys"},
		{"encryption-private-key", WorktreeEncryptionPrivateKeyRelativePath("sha256:abc"), ".aw/encryption-keys/sha256-abc.x25519.key"},
		{"encryption-assertion", WorktreeEncryptionAssertionRelativePath("sha256:abc"), ".aw/encryption-keys/sha256-abc.assertion.json"},
		{"identity", DefaultWorktreeIdentityRelativePath(), ".aw/identity.yaml"},
		{"signing-key", DefaultWorktreeSigningKeyRelativePath(), ".aw/signing.key"},
		{"team-state", DefaultTeamStateRelativePath(), ".aw/teams.yaml"},
		{"workspace", DefaultWorktreeWorkspaceRelativePath(), ".aw/workspace.yaml"},
		{"certificate", TeamCertificateRelativePath("default:acme.aweb.ai"), "team-certs/default__acme.aweb.ai.pem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("logical path=%q, want %q", tc.got, tc.want)
			}
			got, err := IdentityHomeStoredPath(home, tc.got)
			want := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(tc.want, ".aw/")))
			if err != nil || got != want {
				t.Errorf("stored path=%q, %v; want %q", got, err, want)
			}
		})
	}
}
