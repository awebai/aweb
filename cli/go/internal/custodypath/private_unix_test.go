//go:build !windows

package custodypath

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateRuntimeDirectory(t *testing.T) {
	for _, scenario := range []string{"new", "unsafe-mode", "symlink-dir", "symlink-socket", "regular-file", "socket"} {
		t.Run(scenario, func(t *testing.T) {
			base := t.TempDir()
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

type foreignOwnerInfo struct{ os.FileInfo }

func (f foreignOwnerInfo) Sys() any { return &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)} }
func TestRuntimeRejectsRealForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to assign a distinct uid; exercised in the Linux test container")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	defer os.Chown(dir, 0, 0)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerOnly(info); err == nil {
		t.Fatal("real foreign owner accepted")
	}
}

func TestRuntimeRejectsForeignOwner(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerOnly(foreignOwnerInfo{info}); err == nil {
		t.Fatal("foreign owner accepted")
	}
}
