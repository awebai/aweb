package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIdentityHomePrecedenceAndDefault(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(root, "explicit")
	environment := filepath.Join(root, "environment")
	for _, path := range []string{explicit, environment} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(IdentityHomeEnv, environment)

	home, err := ResolveIdentityHome(root, explicit)
	if err != nil || home.Root != explicit || home.Source != IdentityHomeFlag {
		t.Fatalf("explicit home=%#v err=%v", home, err)
	}
	home, err = ResolveIdentityHome(root, "")
	if err != nil || home.Root != environment || home.Source != IdentityHomeEnvVar {
		t.Fatalf("environment home=%#v err=%v", home, err)
	}
	t.Setenv(IdentityHomeEnv, "")
	home, err = ResolveIdentityHome(root, "")
	if err != nil || home.Root != filepath.Join(root, ".aw") || home.Source != IdentityHomeDefault {
		t.Fatalf("default home=%#v err=%v", home, err)
	}
}

func TestResolveIdentityHomeRejectsRelativeAndSymlinkedRoots(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveIdentityHome(root, "relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative flag error=%v", err)
	}
	t.Setenv(IdentityHomeEnv, "relative")
	if _, err := ResolveIdentityHome(root, ""); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative env error=%v", err)
	}
	t.Setenv(IdentityHomeEnv, "")
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveIdentityHome(root, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink error=%v", err)
	}
}

func TestWorktreePathAPIsHonorExplicitDirectoryDespiteAwIdentityHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	instance := filepath.Join(root, "instance")
	principal := filepath.Join(root, "principal")
	t.Setenv(IdentityHomeEnv, principal)
	paths := map[string]string{
		"identity":    WorktreeIdentityPath(instance),
		"signing":     WorktreeSigningKeyPath(instance),
		"workspace":   WorktreeWorkspacePath(instance),
		"teams":       TeamStatePath(instance),
		"certificate": TeamCertificatePath(instance, "team:example.test"),
		"encryption":  WorktreeEncryptionStatePath(instance),
		"keys":        WorktreeEncryptionKeysDir(instance),
		"context":     WorktreeContextPath(instance),
	}
	wantRoot := filepath.Join(instance, ".aw")
	for name, path := range paths {
		rel, err := filepath.Rel(wantRoot, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Errorf("%s path %q ignored explicit worktree root %q", name, path, wantRoot)
		}
		if strings.HasPrefix(path, principal) {
			t.Errorf("%s path was ambiently redirected into %q", name, principal)
		}
	}
}

// An upward-traversing path is refused for traversing, not merely for landing
// outside the root. This one rejoins INSIDE the root, so a containment check
// that only compares the joined path against the root accepts it: relative to
// the root the result is plainly "inner.key". Only a check on the relative path
// itself catches it, which is what keeps this from being restated as one.
func TestIdentityHomePathRejectsUpwardTraversalThatRejoinsInsideRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}
	traversing := filepath.Join("a", "..", "..", filepath.Base(root), "inner.key")

	// The fixture reaches the traversal check rather than being turned away
	// earlier: the same target named without traversal is accepted.
	if _, err := IdentityHomePath(home, "inner.key"); err != nil {
		t.Fatalf("plain target rejected before the traversal check could be reached: %v", err)
	}
	got, err := IdentityHomePath(home, traversing)
	if err == nil {
		t.Fatalf("upward-traversing path %q accepted, resolved to %q", traversing, got)
	}
	if !strings.Contains(err.Error(), "escapes identity home") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

func TestIdentityHomeStoredPathSupportsKnownLegacyPrefixAndRejectsEscapes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}
	got, err := IdentityHomeStoredPath(home, ".aw/encryption-keys/archive.x25519.key")
	if err != nil || got != filepath.Join(root, "encryption-keys", "archive.x25519.key") {
		t.Fatalf("legacy path=%q err=%v", got, err)
	}
	for _, unsafe := range []string{"/tmp/key", "../key", "encryption-keys\\..\\key"} {
		if _, err := IdentityHomeStoredPath(home, unsafe); err == nil {
			t.Fatalf("unsafe path %q accepted", unsafe)
		}
	}
	keyDir := filepath.Join(root, "encryption-keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(keyDir, "linked.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := IdentityHomeStoredPath(home, "encryption-keys/linked.key"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("linked credential error=%v", err)
	}
}

// The containment check must run on the value that is ultimately opened. The
// identity-home prefix is stripped first, so an upward walk hidden behind that
// prefix has to be rejected on the stripped value, not the original.
func TestIdentityHomeStoredPathRejectsEscapeBehindIdentityHomePrefix(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}

	for _, unsafe := range []string{
		".aw/../key",
		".aw/../../key",
		".aw/team-certs/../../../key",
	} {
		got, err := IdentityHomeStoredPath(home, unsafe)
		if err == nil {
			t.Fatalf("stored path %q accepted, resolved to %q", unsafe, got)
		}
		if !strings.Contains(err.Error(), "escapes identity home") {
			t.Fatalf("stored path %q error=%q want it to name the escape", unsafe, err)
		}
	}

	// The prefixed and plain forms designate the same file, which is why the
	// default and identity-home branches may share this resolution.
	prefixed, err := IdentityHomeStoredPath(home, ".aw/team-certs/team.pem")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := IdentityHomeStoredPath(home, "team-certs/team.pem")
	if err != nil {
		t.Fatal(err)
	}
	if prefixed != plain {
		t.Fatalf("prefixed=%q plain=%q want the same path", prefixed, plain)
	}
}

// A stored path of nothing but the identity-home prefix designates no file.
// It is rejected rather than resolved to the identity home itself.
func TestIdentityHomeStoredPathRejectsBareIdentityHomePrefix(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := IdentityHome{Root: root, Source: IdentityHomeFlag}
	got, err := IdentityHomeStoredPath(home, ".aw/")
	if err == nil {
		t.Fatalf("bare prefix accepted, resolved to %q", got)
	}
	if !strings.Contains(err.Error(), "must be a relative forward-slash path") {
		t.Fatalf("error=%q want it to name the unusable path", err)
	}
}
