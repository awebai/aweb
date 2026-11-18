//go:build !windows

package custodypath

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// shortCanonicalDir is a private directory whose path fits a Unix socket
// (104 bytes on macOS) whatever TMPDIR is, with no symlinked component: prepareAt
// refuses a symlinked parent, and macOS's /tmp and /var are symlinks.
func shortCanonicalDir(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "cp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPrivateRuntimeDirectory(t *testing.T) {
	for _, scenario := range []string{"new", "unsafe-mode", "symlink-dir", "symlink-socket", "regular-file", "socket"} {
		t.Run(scenario, func(t *testing.T) {
			base := shortCanonicalDir(t)
			dir := filepath.Join(base, "runtime")
			socket := filepath.Join(dir, "c.sock")
			if scenario == "symlink-dir" {
				if err := os.Symlink(base, dir); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "new":
					if err := os.Remove(dir); err != nil {
						t.Fatal(err)
					}
				case "unsafe-mode":
					if err := os.Chmod(dir, 0755); err != nil {
						t.Fatal(err)
					}
				case "symlink-socket":
					if err := os.Symlink(filepath.Join(base, "target"), socket); err != nil {
						t.Fatal(err)
					}
				case "regular-file":
					if err := os.WriteFile(socket, []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				case "socket":
					ln, err := net.Listen("unix", socket)
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					if err := os.Chmod(socket, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := prepareAt(dir, socket)
			valid := scenario == "new" || scenario == "socket"
			if (err == nil) != valid {
				t.Fatalf("prepare %s: %v", scenario, err)
			}
			if valid {
				if err := checkAt(dir, socket); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRuntimeRejectsRealForeignOwner(t *testing.T) {
	// A normal gate user can inspect the root-owned filesystem root. Root uses
	// its own disposable directory, changing only that directory's ownership.
	dir := string(os.PathSeparator)
	if os.Geteuid() == 0 {
		dir = t.TempDir()
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		defer os.Chown(dir, 0, 0)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == uint32(os.Geteuid()) {
		t.Fatal("foreign-owner fixture is not owned by another uid")
	}
	if err := ownerOnly(info); err == nil || err.Error() != "custody path is not owned by the current user" {
		t.Fatalf("real foreign owner was not refused for ownership: %v", err)
	}
}
